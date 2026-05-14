//! lattica-listener — FEC assembler + UDP daemon.
//!
//! The assembler is transport-agnostic: feed it raw shred bytes via `ingest()`,
//! it groups them by `(slot, fec_set_index)` and emits events as state changes.
//! When 32 shreds with a matching Merkle root arrive, it triggers RS reconstruction
//! and emits a `Reconstructed` event with the recovered 64-shred set and a DAS
//! confidence score.

use lattica_reedsol::{reconstruct, SHREDS_PER_FEC};
use lattica_shred::{
    fec_set::ERASURE_SHARD_SIZE, parse_shred, verify_shred, ShredKind, SIZE_OF_SIGNATURE,
    MERKLE_HASH_PREFIX_NODE, SIZE_OF_PROOF_ENTRY,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub mod leader;
pub mod udp;

pub use leader::{LeaderResolver, StaticLeader, HeliusLeaderResolver};

/// Number of data shreds required to reconstruct a block.
pub const DATA_SHREDS_THRESHOLD: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FecKey {
    pub slot: u64,
    pub fec_set_index: u32,
}

#[derive(Clone, Debug)]
pub enum FecEvent {
    /// First shred arrived for this FEC set; merkle root and leader sig captured.
    Started {
        key: FecKey,
        merkle_root: [u8; 32],
    },
    /// A new shred was accepted into the set.
    ShredAccepted {
        key: FecKey,
        shreds_present: usize,
        erasure_shard_index: usize,
    },
    /// 32+ shreds arrived; reconstruction succeeded.
    Reconstructed {
        key: FecKey,
        merkle_root: [u8; 32],
        /// Probability (0..=1) that a withholding adversary would have been undetected
        /// given the number of distinct shreds we observed before reconstruction.
        das_confidence: f64,
    },
    /// All FEC sets in the slot have been reconstructed AND a shred carrying
    /// `LAST_SHRED_IN_SLOT` has been seen. The slot can now be served as a
    /// single attestation.
    SlotFinalized {
        slot: u64,
        /// FEC roots in `fec_set_index` order.
        fec_roots: Vec<[u8; 32]>,
        /// Merkle root over all `fec_roots` using the same domain-separated SHA-256
        /// ladder as individual shred Merkle trees. A 2-KiB witness commits to the
        /// entire slot.
        slot_root: [u8; 32],
        /// Total distinct shreds observed across all FEC sets in the slot.
        total_shreds_observed: usize,
        /// Aggregate DAS confidence: 1 − ∏ᵢ (1 − cᵢ), the probability that *some*
        /// FEC set caught the adversary if any did. (Independent samples per set.)
        slot_das_confidence: f64,
    },
    /// Shred rejected (sig mismatch, root mismatch, etc.).
    Rejected {
        reason: String,
    },
}

#[derive(Default)]
struct FecState {
    merkle_root: Option<[u8; 32]>,
    leader_sig: Option<[u8; 64]>,
    /// indexed by erasure_shard_index ∈ [0, 64)
    shards: Vec<Option<Vec<u8>>>,
    distinct_seen: usize,
    reconstructed: bool,
    /// per-set DAS confidence as of reconstruction time
    das_confidence_at_reconstruct: f64,
}

impl FecState {
    fn new() -> Self {
        Self {
            shards: (0..SHREDS_PER_FEC).map(|_| None).collect(),
            ..Default::default()
        }
    }
}

/// Slot-level state: tracks which FEC sets we've seen for this slot and whether
/// the leader's LAST_SHRED_IN_SLOT marker has arrived.
#[derive(Default)]
struct SlotState {
    /// `fec_set_index` of every FEC set we've seen at least one shred for.
    seen_fec_indices: std::collections::BTreeSet<u32>,
    /// `fec_set_index` of every FEC set we've fully reconstructed.
    reconstructed_fec_indices: std::collections::BTreeSet<u32>,
    /// True once a data shred with `LAST_SHRED_IN_SLOT` was accepted.
    last_shred_seen: bool,
    /// `fec_set_index` of the FEC set carrying the LAST_IN_SLOT marker.
    /// Used to know which FEC index range is "complete" for the slot.
    last_fec_set_index: Option<u32>,
    /// True once we emitted a SlotFinalized event for this slot.
    finalized: bool,
}

pub struct FecAssembler {
    resolver: Box<dyn LeaderResolver>,
    states: HashMap<FecKey, FecState>,
    slots: HashMap<u64, SlotState>,
}

impl FecAssembler {
    /// Construct with a single static leader (convenience for tests / fixtures).
    pub fn new(leader_pubkey: [u8; 32]) -> Self {
        Self::with_resolver(Box::new(StaticLeader(leader_pubkey)))
    }

    /// Construct with a custom leader resolver (e.g. Helius-backed).
    pub fn with_resolver(resolver: Box<dyn LeaderResolver>) -> Self {
        Self {
            resolver,
            states: HashMap::new(),
            slots: HashMap::new(),
        }
    }

    /// Feed a raw shred. Returns the sequence of events caused by this ingest.
    pub fn ingest(&mut self, raw: &[u8]) -> Vec<FecEvent> {
        let mut events = Vec::new();
        // Parse first to obtain the slot, then look up the proper leader for that slot.
        let parsed_for_slot = match parse_shred(raw) {
            Ok(p) => p,
            Err(e) => {
                events.push(FecEvent::Rejected { reason: format!("parse: {e}") });
                return events;
            }
        };
        let Some(leader_pubkey) = self.resolver.leader_for_slot(parsed_for_slot.header.slot)
        else {
            events.push(FecEvent::Rejected {
                reason: format!("no leader for slot {}", parsed_for_slot.header.slot),
            });
            return events;
        };
        let v = match verify_shred(raw, &leader_pubkey) {
            Ok(v) => v,
            Err(e) => {
                events.push(FecEvent::Rejected { reason: format!("verify: {e}") });
                return events;
            }
        };
        let key = FecKey { slot: v.slot, fec_set_index: v.fec_set_index };
        let state = self.states.entry(key.clone()).or_insert_with(FecState::new);

        // Slot-level bookkeeping: every shred (even rejected duplicates / already-
        // reconstructed sets) updates "have we seen this fec_set_index" and the
        // last-shred-in-slot marker. Without this we'd miss the LAST_IN_SLOT bit
        // if it arrives after the FEC set is already reconstructed.
        let slot_state = self.slots.entry(v.slot).or_default();
        slot_state.seen_fec_indices.insert(v.fec_set_index);
        if v.is_last_in_slot() {
            slot_state.last_shred_seen = true;
            // The last_fec_set_index is the index of the FEC set carrying the marker.
            // Track the maximum because two shreds in the same set may arrive out of
            // order; the marker can only live on the data-complete shred of the
            // final FEC set.
            slot_state.last_fec_set_index = Some(
                slot_state.last_fec_set_index.map_or(v.fec_set_index, |x| x.max(v.fec_set_index)),
            );
        }

        if state.reconstructed {
            // Even though this FEC set is already done, the *slot* may still
            // need finalization — fall through to the slot-finalization check
            // at the end.
            if let Some(ev) = self.try_finalize_slot(v.slot) {
                events.push(ev);
            }
            return events;
        }

        // 2. confirm merkle root consistency for the set
        match state.merkle_root {
            None => {
                state.merkle_root = Some(v.merkle_root);
                events.push(FecEvent::Started { key: key.clone(), merkle_root: v.merkle_root });
            }
            Some(existing) if existing != v.merkle_root => {
                events.push(FecEvent::Rejected {
                    reason: "merkle root diverges within FEC set (leader equivocation?)".into(),
                });
                return events;
            }
            _ => {}
        }

        // 3. extract erasure shard bytes and store (reuse parse from step 1)
        let parsed = parsed_for_slot;
        let shard_start = SIZE_OF_SIGNATURE;
        let shard_end = match v.kind {
            ShredKind::Data => shard_start + ERASURE_SHARD_SIZE,
            ShredKind::Code => {
                // For code shreds, the erasure region starts at offset 89, not 64.
                // Common length is identical (987 bytes).
                89 + ERASURE_SHARD_SIZE
            }
        };
        let shard_offset = match v.kind {
            ShredKind::Data => SIZE_OF_SIGNATURE,
            ShredKind::Code => 89,
        };
        let shard_bytes = raw[shard_offset..shard_offset + ERASURE_SHARD_SIZE].to_vec();
        let _ = (shard_start, shard_end);

        let idx = parsed.erasure_shard_index;
        if idx >= SHREDS_PER_FEC {
            events.push(FecEvent::Rejected {
                reason: format!("erasure_shard_index out of range: {idx}"),
            });
            return events;
        }
        if state.shards[idx].is_some() {
            return events; // duplicate
        }
        state.shards[idx] = Some(shard_bytes);
        state.distinct_seen += 1;
        events.push(FecEvent::ShredAccepted {
            key: key.clone(),
            shreds_present: state.distinct_seen,
            erasure_shard_index: idx,
        });

        // 4. attempt reconstruction once we have 32 shards.
        if state.distinct_seen >= DATA_SHREDS_THRESHOLD && !state.reconstructed {
            let mut shards: [Option<Vec<u8>>; SHREDS_PER_FEC] = std::array::from_fn(|i| state.shards[i].clone());
            match reconstruct(&mut shards) {
                Ok(()) => {
                    state.reconstructed = true;
                    // Sampling argument: with N distinct shreds out of 64, probability
                    // that a withholding adversary publishing only 31 shreds remains
                    // undetected is C(31, N) / C(64, N).
                    let das = das_confidence(state.distinct_seen);
                    state.das_confidence_at_reconstruct = das;
                    events.push(FecEvent::Reconstructed {
                        key: key.clone(),
                        merkle_root: state.merkle_root.unwrap(),
                        das_confidence: das,
                    });

                    // Mark this fec_set_index as reconstructed in the slot state.
                    // Then check whether the entire slot is now complete.
                    let slot_state = self.slots.entry(v.slot).or_default();
                    slot_state.reconstructed_fec_indices.insert(v.fec_set_index);
                    if let Some(ev) = self.try_finalize_slot(v.slot) {
                        events.push(ev);
                    }
                }
                Err(e) => {
                    events.push(FecEvent::Rejected { reason: format!("rs reconstruct: {e}") });
                }
            }
        }
        events
    }

    /// Returns `Some(SlotFinalized)` exactly once, the first time the slot
    /// satisfies both conditions:
    ///   1. We've seen a shred with `LAST_SHRED_IN_SLOT`, AND
    ///   2. Every `fec_set_index` we've ever seen for this slot (up to and
    ///      including `last_fec_set_index`) has been reconstructed.
    ///
    /// Note: Solana fec_set_index values are *non-contiguous* — for a 32-data-
    /// shred FEC set, they're the starting shred index (0, 32, 64, …), not a
    /// dense 0,1,2,… enumeration. We therefore iterate `seen_fec_indices` (a
    /// BTreeSet of the actual indices observed) rather than a numeric range.
    fn try_finalize_slot(&mut self, slot: u64) -> Option<FecEvent> {
        let slot_state = self.slots.get_mut(&slot)?;
        if slot_state.finalized {
            return None;
        }
        if !slot_state.last_shred_seen {
            return None;
        }
        let last_idx = slot_state.last_fec_set_index?;

        // Snapshot the indices we need to check & report (BTreeSet iterates ascending).
        let indices_to_check: Vec<u32> = slot_state
            .seen_fec_indices
            .iter()
            .copied()
            .filter(|i| *i <= last_idx)
            .collect();

        for i in &indices_to_check {
            if !slot_state.reconstructed_fec_indices.contains(i) {
                return None;
            }
        }
        // Sanity: the FEC set that carries the LAST_IN_SLOT marker must itself
        // appear in seen_fec_indices (it was inserted when its first shred
        // arrived). If somehow it's not, we don't finalize.
        if !slot_state.seen_fec_indices.contains(&last_idx) {
            return None;
        }
        slot_state.finalized = true;

        // Collect per-set roots in fec_set_index order, plus aggregate stats.
        let mut fec_roots: Vec<[u8; 32]> = Vec::with_capacity(indices_to_check.len());
        let mut total_shreds = 0usize;
        let mut undetect = 1.0f64;
        for i in &indices_to_check {
            let key = FecKey { slot, fec_set_index: *i };
            let st = self.states.get(&key)?;
            fec_roots.push(st.merkle_root?);
            total_shreds += st.distinct_seen;
            // Aggregate "P[adversary undetected]" across independent sets:
            // 1 - confidence_i = P[set i didn't catch them]; product over sets.
            undetect *= 1.0 - st.das_confidence_at_reconstruct;
        }
        let slot_root = aggregate_root(&fec_roots);

        Some(FecEvent::SlotFinalized {
            slot,
            fec_roots,
            slot_root,
            total_shreds_observed: total_shreds,
            slot_das_confidence: 1.0 - undetect,
        })
    }
}

/// Hashes a list of FEC roots into a single slot root using the same
/// domain-separated SHA-256 ladder as Solana's intra-shred Merkle tree
/// (CT-style with 20-byte truncation). Last odd node duplicates itself.
fn aggregate_root(roots: &[[u8; 32]]) -> [u8; 32] {
    if roots.is_empty() {
        return [0u8; 32];
    }
    let mut layer: Vec<[u8; 32]> = roots.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for chunk in layer.chunks(2) {
            let a = &chunk[0];
            let b = if chunk.len() == 2 { &chunk[1] } else { &chunk[0] };
            let mut h = Sha256::new();
            h.update(MERKLE_HASH_PREFIX_NODE);
            h.update(&a[..SIZE_OF_PROOF_ENTRY]);
            h.update(&b[..SIZE_OF_PROOF_ENTRY]);
            next.push(<[u8; 32]>::from(h.finalize()));
        }
        layer = next;
    }
    layer[0]
}

/// DAS sampling confidence.
///
/// Returns the probability that a withholding adversary (who has only 31 shreds
/// available across the network — one shy of the reconstruction threshold) would
/// have produced the observed `n` distinct shreds purely by chance.
///
/// Concretely: 1 - C(31, n) / C(64, n) — the probability we got "lucky" with all
/// good shreds. Higher is better. With n=32 the adversary is detected with certainty.
pub fn das_confidence(n: usize) -> f64 {
    if n >= DATA_SHREDS_THRESHOLD {
        return 1.0;
    }
    // Compute C(31, n) / C(64, n) without overflow using log-gamma free identity:
    //   C(31, n) / C(64, n) = prod_{k=0..n-1} (31 - k) / (64 - k)
    let mut ratio: f64 = 1.0;
    for k in 0..n {
        ratio *= (31.0 - k as f64) / (64.0 - k as f64);
    }
    1.0 - ratio
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use lattica_shred::fec_set::{build_fec_set, FecSetParams};

    fn build_test_set(payload_len: usize) -> (Vec<Vec<u8>>, [u8; 32], [u8; 32]) {
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let leader_pk = signing.verifying_key().to_bytes();
        let payload: Vec<u8> = (0..(payload_len / 4) as u32).flat_map(|i| i.to_le_bytes()).collect();
        let params = FecSetParams {
            slot: 1_111,
            fec_set_index: 0,
            version: 1,
            parent_offset: 1,
            flags: 0,
            chained_root: [0u8; 32],
            signing_key: &signing,
        };
        let fec = build_fec_set(&payload, params).unwrap();
        (fec.shreds, fec.merkle_root, leader_pk)
    }

    #[test]
    fn assembler_recovers_from_32_data_shreds_only() {
        let (shreds, root, leader_pk) = build_test_set(8_000);
        let mut asm = FecAssembler::new(leader_pk);

        let mut reconstructed = false;
        for i in 0..32 {
            for ev in asm.ingest(&shreds[i]) {
                if let FecEvent::Reconstructed { merkle_root, das_confidence, .. } = ev {
                    assert_eq!(merkle_root, root);
                    assert!(das_confidence >= 1.0);
                    reconstructed = true;
                }
            }
        }
        assert!(reconstructed, "should have reconstructed at 32 shreds");
    }

    #[test]
    fn assembler_recovers_from_mixed_data_and_coding() {
        let (shreds, root, leader_pk) = build_test_set(8_000);
        let mut asm = FecAssembler::new(leader_pk);

        // Drop the first 16 data shreds; feed remaining data (16..32) plus 16 coding shreds.
        let mut order: Vec<usize> = Vec::new();
        order.extend(16..32);
        order.extend(32..48);

        let mut reconstructed = false;
        for i in order {
            for ev in asm.ingest(&shreds[i]) {
                if let FecEvent::Reconstructed { merkle_root, .. } = ev {
                    assert_eq!(merkle_root, root);
                    reconstructed = true;
                }
            }
        }
        assert!(reconstructed, "should have reconstructed with mixed shreds");
    }

    #[test]
    fn assembler_rejects_wrong_leader() {
        let (shreds, _root, _leader_pk) = build_test_set(2_000);
        // Use a DIFFERENT leader pubkey.
        let wrong_pk: [u8; 32] = SigningKey::from_bytes(&[1u8; 32]).verifying_key().to_bytes();
        let mut asm = FecAssembler::new(wrong_pk);
        let events = asm.ingest(&shreds[0]);
        assert!(events.iter().any(|e| matches!(e, FecEvent::Rejected { .. })));
    }

    /// Negative test: with only 31 shreds delivered (one shy of threshold), the
    /// assembler must NOT emit a Reconstructed event, and DAS confidence must be < 1.
    #[test]
    fn assembler_does_not_reconstruct_at_31() {
        let (shreds, _root, leader_pk) = build_test_set(4_000);
        let mut asm = FecAssembler::new(leader_pk);
        let mut reconstructed = false;
        for i in 0..31 {
            for ev in asm.ingest(&shreds[i]) {
                if matches!(ev, FecEvent::Reconstructed { .. }) {
                    reconstructed = true;
                }
            }
        }
        assert!(!reconstructed, "should not have reconstructed with only 31 shreds");
        // das_confidence(31) is mathematically 1 - 1/C(64,31) ≈ 1 - 3.3e-18,
        // which f64 cannot distinguish from 1.0 — but das_confidence(8), say, must
        // be strictly < 1, so use a sample point well within f64 precision.
        assert!(das_confidence(8) < 1.0);
    }

    #[test]
    fn das_confidence_table() {
        assert!((das_confidence(0) - 0.0).abs() < 1e-12);
        // n=20 should be very close to 1.
        assert!(das_confidence(20) > 0.999_99);
        // n=32 is full certainty.
        assert_eq!(das_confidence(32), 1.0);
        // n=10 still leaves meaningful adversary room.
        let c10 = das_confidence(10);
        assert!(c10 > 0.99 && c10 < 1.0);
    }

    // -------------------------------------------------------------------------
    // Slot finalization (Phase 3) — multi-FEC-set + LAST_SHRED_IN_SLOT detection
    // -------------------------------------------------------------------------

    /// Build a FEC set at a specific slot/index with optional LAST_IN_SLOT bit set
    /// on every data shred. (DATA_COMPLETE on every data shred is fine for tests
    /// — the assembler only ever reads the bit OR'd into any one shred it accepts.)
    fn build_set_at(
        signing: &SigningKey,
        slot: u64,
        fec_set_index: u32,
        payload_len: usize,
        last_in_slot: bool,
    ) -> (Vec<Vec<u8>>, [u8; 32]) {
        use lattica_shred::{SHRED_FLAG_DATA_COMPLETE, SHRED_FLAG_LAST_IN_SLOT};
        let payload: Vec<u8> = (0..(payload_len / 4) as u32)
            .flat_map(|i| i.to_le_bytes())
            .collect();
        let flags = if last_in_slot {
            SHRED_FLAG_DATA_COMPLETE | SHRED_FLAG_LAST_IN_SLOT
        } else {
            0
        };
        let params = FecSetParams {
            slot,
            fec_set_index,
            version: 1,
            parent_offset: 1,
            flags,
            chained_root: [0u8; 32],
            signing_key: signing,
        };
        let fec = build_fec_set(&payload, params).unwrap();
        (fec.shreds, fec.merkle_root)
    }

    fn collect_slot_finalized(events: &[FecEvent]) -> Option<&FecEvent> {
        events.iter().find(|e| matches!(e, FecEvent::SlotFinalized { .. }))
    }

    #[test]
    fn slot_finalizes_when_all_sets_done_and_last_seen() {
        let signing = SigningKey::from_bytes(&[5u8; 32]);
        let leader_pk = signing.verifying_key().to_bytes();
        let (set0, root0) = build_set_at(&signing, 222, 0, 4_000, false);
        let (set1, root1) = build_set_at(&signing, 222, 32, 4_000, true); // last in slot

        let mut asm = FecAssembler::new(leader_pk);
        let mut all_events = Vec::new();
        for raw in set0.iter().take(32).chain(set1.iter().take(32)) {
            all_events.extend(asm.ingest(raw));
        }

        let final_ev = collect_slot_finalized(&all_events)
            .expect("SlotFinalized must fire once both sets are done and LAST_IN_SLOT is seen");
        match final_ev {
            FecEvent::SlotFinalized { slot, fec_roots, slot_root, total_shreds_observed, slot_das_confidence } => {
                assert_eq!(*slot, 222);
                assert_eq!(fec_roots.len(), 2);
                assert_eq!(fec_roots[0], root0);
                assert_eq!(fec_roots[1], root1);
                assert_eq!(*total_shreds_observed, 64);
                assert!(*slot_das_confidence > 0.999_999);
                let recomputed = aggregate_root(&[root0, root1]);
                assert_eq!(*slot_root, recomputed, "slot_root must equal aggregate_root over fec_roots");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn slot_does_not_finalize_without_last_marker() {
        // Both FEC sets fully reconstructed but neither carries LAST_IN_SLOT.
        // SlotFinalized must NOT fire — we don't yet know how many sets the slot has.
        let signing = SigningKey::from_bytes(&[6u8; 32]);
        let leader_pk = signing.verifying_key().to_bytes();
        let (set0, _) = build_set_at(&signing, 333, 0, 2_000, false);
        let (set1, _) = build_set_at(&signing, 333, 32, 2_000, false);

        let mut asm = FecAssembler::new(leader_pk);
        let mut all_events = Vec::new();
        for raw in set0.iter().take(32).chain(set1.iter().take(32)) {
            all_events.extend(asm.ingest(raw));
        }
        assert!(collect_slot_finalized(&all_events).is_none(),
            "no LAST_IN_SLOT seen → slot must remain open");
    }

    #[test]
    fn slot_does_not_finalize_when_a_set_is_incomplete() {
        // LAST_IN_SLOT seen, fec_set_index=0 fully reconstructed,
        // but fec_set_index=32 (the LAST one) only has 31 shreds → can't reconstruct.
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let leader_pk = signing.verifying_key().to_bytes();
        let (set0, _) = build_set_at(&signing, 444, 0, 2_000, false);
        let (set1, _) = build_set_at(&signing, 444, 32, 2_000, true);

        let mut asm = FecAssembler::new(leader_pk);
        let mut all_events = Vec::new();
        for raw in set0.iter().take(32) {
            all_events.extend(asm.ingest(raw));
        }
        for raw in set1.iter().take(31) {
            all_events.extend(asm.ingest(raw));
        }
        assert!(collect_slot_finalized(&all_events).is_none(),
            "fec_set 32 is missing 1 shred → slot is not finalizable yet");
    }

    #[test]
    fn slot_finalizes_idempotently() {
        // Once SlotFinalized has fired for a slot, further shreds for that slot
        // (even valid ones) must not produce another SlotFinalized.
        let signing = SigningKey::from_bytes(&[8u8; 32]);
        let leader_pk = signing.verifying_key().to_bytes();
        let (set0, _) = build_set_at(&signing, 555, 0, 2_000, true);

        let mut asm = FecAssembler::new(leader_pk);
        let mut all_events = Vec::new();
        for raw in set0.iter() {
            all_events.extend(asm.ingest(raw));
        }
        let n_finalized = all_events.iter()
            .filter(|e| matches!(e, FecEvent::SlotFinalized { .. }))
            .count();
        assert_eq!(n_finalized, 1, "SlotFinalized must fire exactly once per slot");
    }
}

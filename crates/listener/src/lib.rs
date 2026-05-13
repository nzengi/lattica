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
};
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
}

impl FecState {
    fn new() -> Self {
        Self {
            shards: (0..SHREDS_PER_FEC).map(|_| None).collect(),
            ..Default::default()
        }
    }
}

pub struct FecAssembler {
    resolver: Box<dyn LeaderResolver>,
    states: HashMap<FecKey, FecState>,
}

impl FecAssembler {
    /// Construct with a single static leader (convenience for tests / fixtures).
    pub fn new(leader_pubkey: [u8; 32]) -> Self {
        Self::with_resolver(Box::new(StaticLeader(leader_pubkey)))
    }

    /// Construct with a custom leader resolver (e.g. Helius-backed).
    pub fn with_resolver(resolver: Box<dyn LeaderResolver>) -> Self {
        Self { resolver, states: HashMap::new() }
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

        if state.reconstructed {
            return events; // we're done with this set
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
                    events.push(FecEvent::Reconstructed {
                        key,
                        merkle_root: state.merkle_root.unwrap(),
                        das_confidence: das,
                    });
                }
                Err(e) => {
                    events.push(FecEvent::Rejected { reason: format!("rs reconstruct: {e}") });
                }
            }
        }
        events
    }
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
}

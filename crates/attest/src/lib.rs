//! lattica-attest — Phase 3 attestation packet + verifier.
//!
//! An `Attestation` is what a single listener publishes for a slot:
//! `(slot, fec_set_index, leader_pubkey, fec_merkle_root, leader_sig, Δ_lthash)`.
//! The leader signature commits the listener to the FEC content; the Δ_lthash
//! commits to every account modification in the slot (this listener's view).
//!
//! A `SlotVerifier` consumer takes:
//!   1. an Attestation (specifically its `delta_lthash`), AND
//!   2. the complete set of (old, new) account state transitions claimed for
//!      that slot,
//! and decides whether the two are consistent. The verifier is *all-or-
//! nothing*: it succeeds only when the claimed transition set, summed
//! homomorphically, equals the attested delta. Subset proofs are Phase 3.4.

use lattica_lthash::{hash_account, AccountForHash, LtHash, N_LIMBS};
use serde::{Deserialize, Serialize};

// --------------------------------------------------------------------------
// Attestation packet
// --------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attestation {
    pub slot: u64,
    pub fec_set_index: u32,
    pub leader_pubkey: [u8; 32],
    pub fec_merkle_root: [u8; 32],
    /// 64-byte Ed25519 signature over fec_merkle_root. Stored as Vec to dodge
    /// serde's lack of derive for arrays > 32 without extra deps.
    pub leader_sig: Vec<u8>,
    /// Per-slot Δ_lthash limbs (1024 × u16 = 2 KiB).
    pub delta_lthash: Vec<u16>,
}

impl Attestation {
    pub fn from_delta(
        slot: u64,
        fec_set_index: u32,
        leader_pubkey: [u8; 32],
        fec_merkle_root: [u8; 32],
        leader_sig: [u8; 64],
        delta: &LtHash,
    ) -> Self {
        assert_eq!(delta.0.len(), N_LIMBS);
        Self {
            slot,
            fec_set_index,
            leader_pubkey,
            fec_merkle_root,
            leader_sig: leader_sig.to_vec(),
            delta_lthash: delta.0.to_vec(),
        }
    }

    /// Reconstruct the LtHash from the serialized limbs. Returns `None` on
    /// length mismatch — refuse to verify a malformed attestation.
    pub fn delta_as_lthash(&self) -> Option<LtHash> {
        if self.delta_lthash.len() != N_LIMBS {
            return None;
        }
        let mut limbs = [0u16; N_LIMBS];
        limbs.copy_from_slice(&self.delta_lthash);
        Some(LtHash(limbs))
    }
}

// --------------------------------------------------------------------------
// Slot verifier
// --------------------------------------------------------------------------

/// A single account state transition claimed for the slot.
///
/// Either side may be `None`:
///   * `(None, Some(_))` — account was *created* in this slot.
///   * `(Some(_), None)` — account was *closed* in this slot (lamports → 0).
/// `(None, None)` is invalid and rejected by `verify_slot_delta`.
#[derive(Clone, Debug)]
pub struct AccountTransition<'a> {
    pub old: Option<AccountForHash<'a>>,
    pub new: Option<AccountForHash<'a>>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum VerifyError {
    /// One of the transitions had `old=None` AND `new=None`.
    EmptyTransition,
    /// The attestation's `delta_lthash` has the wrong limb count.
    MalformedDelta,
    /// The recomputed Δ does not match the attested one. The verifier carries
    /// the 32-byte checksum of both for downstream debugging.
    DeltaMismatch {
        attested: [u8; 32],
        recomputed: [u8; 32],
    },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyTransition => write!(f, "transition has neither old nor new state"),
            Self::MalformedDelta => write!(f, "attestation delta_lthash limb count != 1024"),
            Self::DeltaMismatch { attested, recomputed } => write!(
                f,
                "delta mismatch: attested={} recomputed={}",
                hex::encode(attested),
                hex::encode(recomputed),
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

/// All-or-nothing verifier.
///
/// Recomputes Σ (h(new) − h(old)) over the supplied transitions and checks
/// it matches the attested delta limb-for-limb. Returns `Ok(())` on success.
///
/// This is *complete*: the caller must supply every modified account for the
/// slot. Missing any transition causes a mismatch. Adding a transition that
/// wasn't actually in the slot also causes a mismatch.
pub fn verify_slot_delta(
    attestation: &Attestation,
    transitions: &[AccountTransition<'_>],
) -> Result<(), VerifyError> {
    let attested = attestation
        .delta_as_lthash()
        .ok_or(VerifyError::MalformedDelta)?;

    let mut recomputed = LtHash::identity();
    for t in transitions {
        match (&t.old, &t.new) {
            (None, None) => return Err(VerifyError::EmptyTransition),
            (Some(o), Some(n)) => {
                recomputed.mix_out(&hash_account(o));
                recomputed.mix_in(&hash_account(n));
            }
            (Some(o), None) => recomputed.mix_out(&hash_account(o)),
            (None, Some(n)) => recomputed.mix_in(&hash_account(n)),
        }
    }

    if recomputed.0 == attested.0 {
        Ok(())
    } else {
        Err(VerifyError::DeltaMismatch {
            attested: attested.checksum(),
            recomputed: recomputed.checksum(),
        })
    }
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use lattica_lthash::SlotDelta;

    fn acct<'a>(seed: u8, data: &'a [u8]) -> AccountForHash<'a> {
        AccountForHash {
            lamports: 1_000_000 + seed as u64,
            data,
            executable: false,
            owner: [seed; 32],
            pubkey: [seed.wrapping_add(1); 32],
        }
    }

    /// Build an Attestation whose `delta_lthash` is correctly populated from
    /// the given transitions. Other fields are dummy.
    fn synthetic_attestation_for(transitions: &[(Option<&AccountForHash<'_>>, Option<&AccountForHash<'_>>)]) -> Attestation {
        let mut sd = SlotDelta::new();
        for (o, n) in transitions {
            sd.mix(*o, *n);
        }
        Attestation::from_delta(
            42,
            0,
            [0xaa; 32],
            [0xbb; 32],
            [0xcc; 64],
            &sd.delta,
        )
    }

    #[test]
    fn happy_path_complete_set_verifies() {
        let a_old = acct(1, b"old-a");
        let a_new = acct(1, b"new-a");
        let b_old = acct(2, b"old-b");
        let b_new = acct(2, b"new-b");

        let attestation = synthetic_attestation_for(&[
            (Some(&a_old), Some(&a_new)),
            (Some(&b_old), Some(&b_new)),
        ]);

        let transitions = vec![
            AccountTransition { old: Some(a_old.clone()), new: Some(a_new.clone()) },
            AccountTransition { old: Some(b_old.clone()), new: Some(b_new.clone()) },
        ];
        verify_slot_delta(&attestation, &transitions).expect("complete set must verify");
    }

    #[test]
    fn single_flipped_byte_fails() {
        // Attestation built from a_new = "new-a"; verifier supplied a_new = "new-A"
        let a_old = acct(1, b"old-a");
        let a_new_real = acct(1, b"new-a");
        let a_new_tampered = acct(1, b"new-A");

        let attestation = synthetic_attestation_for(&[
            (Some(&a_old), Some(&a_new_real)),
        ]);

        let transitions = vec![
            AccountTransition {
                old: Some(a_old.clone()),
                new: Some(a_new_tampered.clone()),
            },
        ];
        let result = verify_slot_delta(&attestation, &transitions);
        assert!(matches!(result, Err(VerifyError::DeltaMismatch { .. })));
    }

    #[test]
    fn spurious_extra_transition_fails() {
        // Attestation covers ONE account change; verifier claims TWO.
        let a_old = acct(1, b"old-a");
        let a_new = acct(1, b"new-a");
        let spurious_old = acct(99, b"phantom-old");
        let spurious_new = acct(99, b"phantom-new");

        let attestation = synthetic_attestation_for(&[
            (Some(&a_old), Some(&a_new)),
        ]);

        let transitions = vec![
            AccountTransition { old: Some(a_old.clone()), new: Some(a_new.clone()) },
            AccountTransition {
                old: Some(spurious_old.clone()),
                new: Some(spurious_new.clone()),
            },
        ];
        let result = verify_slot_delta(&attestation, &transitions);
        assert!(matches!(result, Err(VerifyError::DeltaMismatch { .. })));
    }

    #[test]
    fn missing_transition_fails() {
        // Attestation covers TWO accounts; verifier supplies only one.
        let a_old = acct(1, b"old-a");
        let a_new = acct(1, b"new-a");
        let b_old = acct(2, b"old-b");
        let b_new = acct(2, b"new-b");

        let attestation = synthetic_attestation_for(&[
            (Some(&a_old), Some(&a_new)),
            (Some(&b_old), Some(&b_new)),
        ]);

        let transitions = vec![
            AccountTransition { old: Some(a_old.clone()), new: Some(a_new.clone()) },
        ];
        let result = verify_slot_delta(&attestation, &transitions);
        assert!(matches!(result, Err(VerifyError::DeltaMismatch { .. })));
    }

    #[test]
    fn account_creation_and_closure_verify() {
        // Mixed slot: one account created (None → Some), one closed (Some → None).
        let created = acct(5, b"hello-world");
        let closed = acct(6, b"goodbye");

        let attestation = synthetic_attestation_for(&[
            (None, Some(&created)),
            (Some(&closed), None),
        ]);

        let transitions = vec![
            AccountTransition { old: None, new: Some(created.clone()) },
            AccountTransition { old: Some(closed.clone()), new: None },
        ];
        verify_slot_delta(&attestation, &transitions).expect("create+close must verify");
    }

    #[test]
    fn empty_transition_rejected() {
        let attestation = synthetic_attestation_for(&[]);
        let transitions = vec![AccountTransition { old: None, new: None }];
        let result = verify_slot_delta(&attestation, &transitions);
        assert_eq!(result, Err(VerifyError::EmptyTransition));
    }

    #[test]
    fn empty_slot_verifies() {
        // No modifications at all → delta is identity. Verifier with no
        // transitions must also produce identity.
        let attestation = synthetic_attestation_for(&[]);
        verify_slot_delta(&attestation, &[]).expect("empty slot delta = identity");
    }

    #[test]
    fn malformed_delta_rejected() {
        let mut attestation = synthetic_attestation_for(&[]);
        attestation.delta_lthash.truncate(N_LIMBS / 2);
        let result = verify_slot_delta(&attestation, &[]);
        assert_eq!(result, Err(VerifyError::MalformedDelta));
    }
}

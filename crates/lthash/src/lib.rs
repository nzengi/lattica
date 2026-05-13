//! lattica-lthash — Solana's homomorphic accounts hash, vendored.
//!
//! Construction (matches firedancer/src/ballet/lthash and agave/lattice-hash):
//!   - codomain: (Z / 2^16)^1024, i.e. 1024 limbs of u16
//!   - per-element hash: Blake3-XOF on the canonical account byte string → 2048 bytes → 1024 u16
//!   - group op: elementwise wrapping_add (mod 2^16); inverse: wrapping_sub
//!
//! Per-account input (canonical order, agave/accounts-db/src/accounts_db.rs:4482-4506):
//!   lamports (8 LE) || data (var) || executable (1) || owner (32) || pubkey (32)
//!
//! The identity element is the zero vector. A "tombstone" account (deleted /
//! lamports==0) hashes to the zero vector by convention.

use blake3::Hasher;

pub const N_LIMBS: usize = 1024;
pub const BYTES_PER_HASH: usize = N_LIMBS * 2; // 2048

/// A point in the (Z/2^16)^1024 additive group.
#[derive(Clone, Copy)]
pub struct LtHash(pub [u16; N_LIMBS]);

impl LtHash {
    pub const fn identity() -> Self {
        LtHash([0u16; N_LIMBS])
    }

    /// Add another LtHash into self (group operation).
    pub fn mix_in(&mut self, other: &LtHash) {
        for i in 0..N_LIMBS {
            self.0[i] = self.0[i].wrapping_add(other.0[i]);
        }
    }

    /// Subtract another LtHash from self.
    pub fn mix_out(&mut self, other: &LtHash) {
        for i in 0..N_LIMBS {
            self.0[i] = self.0[i].wrapping_sub(other.0[i]);
        }
    }

    /// Reduce to a 32-byte gossip-compatible commitment (Blake3 of the 2048-byte vector).
    pub fn checksum(&self) -> [u8; 32] {
        let mut bytes = [0u8; BYTES_PER_HASH];
        for (i, limb) in self.0.iter().enumerate() {
            bytes[2 * i..2 * i + 2].copy_from_slice(&limb.to_le_bytes());
        }
        *blake3::hash(&bytes).as_bytes()
    }

    /// Equality (constant-time-ish; identity check).
    pub fn is_identity(&self) -> bool {
        self.0.iter().all(|&x| x == 0)
    }
}

impl Default for LtHash {
    fn default() -> Self {
        Self::identity()
    }
}

/// A minimal, canonical account view sufficient for LtHash computation.
#[derive(Clone, Debug)]
pub struct AccountForHash<'a> {
    pub lamports: u64,
    pub data: &'a [u8],
    pub executable: bool,
    pub owner: [u8; 32],
    pub pubkey: [u8; 32],
}

/// Hash a single account into a 1024-limb LtHash vector.
/// Returns identity for tombstone (lamports == 0).
pub fn hash_account(acct: &AccountForHash<'_>) -> LtHash {
    if acct.lamports == 0 {
        return LtHash::identity();
    }
    let mut h = Hasher::new();
    h.update(&acct.lamports.to_le_bytes());
    h.update(acct.data);
    h.update(&[acct.executable as u8]);
    h.update(&acct.owner);
    h.update(&acct.pubkey);
    let mut xof = h.finalize_xof();
    let mut bytes = [0u8; BYTES_PER_HASH];
    xof.fill(&mut bytes);
    let mut limbs = [0u16; N_LIMBS];
    for i in 0..N_LIMBS {
        limbs[i] = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]);
    }
    LtHash(limbs)
}

/// Per-slot delta builder: caller feeds (old_account_state, new_account_state) pairs
/// across all accounts modified in a slot; resulting delta is the LtHash element such that
/// new_state_lthash = old_state_lthash + delta.
#[derive(Clone, Default)]
pub struct SlotDelta {
    pub delta: LtHash,
}

impl SlotDelta {
    pub fn new() -> Self { Self::default() }

    pub fn mix(&mut self, old: Option<&AccountForHash<'_>>, new: Option<&AccountForHash<'_>>) {
        if let Some(o) = old {
            let h = hash_account(o);
            self.delta.mix_out(&h);
        }
        if let Some(n) = new {
            let h = hash_account(n);
            self.delta.mix_in(&h);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_account(seed: u8, data: &[u8]) -> AccountForHash<'_> {
        AccountForHash {
            lamports: 1_000_000 + seed as u64,
            data,
            executable: false,
            owner: [seed; 32],
            pubkey: [seed.wrapping_add(1); 32],
        }
    }

    /// Core property: adding then removing the same account yields identity.
    #[test]
    fn mix_in_then_mix_out_is_identity() {
        let mut h = LtHash::identity();
        let a = dummy_account(7, b"hello");
        let ha = hash_account(&a);
        h.mix_in(&ha);
        h.mix_out(&ha);
        assert!(h.is_identity());
    }

    /// Homomorphism: hash({a,b}) = hash(a) + hash(b).
    #[test]
    fn additive_homomorphism() {
        let a = dummy_account(1, b"alpha");
        let b = dummy_account(2, b"beta");
        let mut sum = hash_account(&a);
        sum.mix_in(&hash_account(&b));
        // Reverse order should match.
        let mut rev = hash_account(&b);
        rev.mix_in(&hash_account(&a));
        assert_eq!(sum.0, rev.0);
    }

    /// Slot delta correctness: applying delta on top of "before" lthash yields "after".
    #[test]
    fn slot_delta_reconstructs_after_state() {
        let a_old = dummy_account(3, b"old-a");
        let a_new = dummy_account(3, b"new-a");
        let b_old = dummy_account(4, b"old-b");
        let b_new = dummy_account(4, b"new-b");

        let mut before = LtHash::identity();
        before.mix_in(&hash_account(&a_old));
        before.mix_in(&hash_account(&b_old));

        let mut delta = SlotDelta::new();
        delta.mix(Some(&a_old), Some(&a_new));
        delta.mix(Some(&b_old), Some(&b_new));

        let mut after_via_delta = before;
        after_via_delta.mix_in(&delta.delta);

        let mut after_direct = LtHash::identity();
        after_direct.mix_in(&hash_account(&a_new));
        after_direct.mix_in(&hash_account(&b_new));

        assert_eq!(after_via_delta.0, after_direct.0);
    }

    /// Tombstone: an account with lamports == 0 contributes identity.
    #[test]
    fn tombstone_is_identity() {
        let t = AccountForHash {
            lamports: 0,
            data: b"",
            executable: false,
            owner: [0; 32],
            pubkey: [0; 32],
        };
        assert!(hash_account(&t).is_identity());
    }
}

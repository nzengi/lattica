//! lattica-attest — attestation packet for the LATTICA aggregation gossip layer (Phase 3).
//!
//! Each listener publishes one Attestation per FEC set it fully reconstructed:
//!   (slot, fec_set_index, leader_pubkey, fec_merkle_root, leader_sig, Δ_lthash, sampled shreds)
//!
//! Phase 1: just the struct shape; libp2p wiring lives in Phase 3.

use lattica_lthash::{LtHash, N_LIMBS};
use serde::{Deserialize, Serialize};

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
}

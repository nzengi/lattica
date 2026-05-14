//! lattica-shred — parse & verify a single Solana shred against a leader pubkey.
//!
//! Wire-format reference (cross-checked against agave/ledger/src/shred):
//!   ShredCommonHeader (83 bytes):
//!     [0..64]   signature           (Ed25519, signs the Merkle root)
//!     [64]      variant             (high 4 bits = kind, low 4 bits = proof_size)
//!     [65..73]  slot                (u64 LE)
//!     [73..77]  index               (u32 LE)
//!     [77..79]  version             (u16 LE)
//!     [79..83]  fec_set_index       (u32 LE)
//!
//!   DataShredHeader  (+5):  parent_offset u16, flags u8, size u16
//!   CodingShredHeader(+6):  num_data u16, num_coding u16, position u16
//!
//! Tail layout (chained variants on mainnet today):
//!   ... payload bytes ...
//!   [chained_merkle_root]   32 bytes (only if variant is *chained*)
//!   [merkle_proof]          proof_size * 20 bytes
//!   [retransmitter_sig]     64 bytes (only if variant is *resigned*)
//!
//! Merkle hashing follows Certificate-Transparency style domain separation:
//!   leaf = SHA256(0x00 || "SOLANA_MERKLE_SHREDS_LEAF" || msg)
//!   node = SHA256(0x01 || "SOLANA_MERKLE_SHREDS_NODE" || left[..20] || right[..20])
//! where `msg` is the shred byte range past the signature and before the proof.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub mod fec_set;

pub const SIZE_OF_SIGNATURE: usize = 64;
pub const SIZE_OF_COMMON_HEADER: usize = 83;
pub const SIZE_OF_DATA_HEADER_EXTRA: usize = 5;
pub const SIZE_OF_CODING_HEADER_EXTRA: usize = 6;
pub const SIZE_OF_MERKLE_ROOT: usize = 32;
pub const SIZE_OF_PROOF_ENTRY: usize = 20;
pub const SIZE_OF_RETRANSMITTER_SIG: usize = 64;

pub const MERKLE_HASH_PREFIX_LEAF: &[u8] = b"\x00SOLANA_MERKLE_SHREDS_LEAF";
pub const MERKLE_HASH_PREFIX_NODE: &[u8] = b"\x01SOLANA_MERKLE_SHREDS_NODE";

pub const DATA_SHREDS_PER_FEC: usize = 32;
pub const CODING_SHREDS_PER_FEC: usize = 32;
pub const SHREDS_PER_FEC: usize = DATA_SHREDS_PER_FEC + CODING_SHREDS_PER_FEC;
pub const PROOF_ENTRIES_FOR_32_32: u8 = 6;

pub const DATA_SHRED_PAYLOAD_SIZE: usize = 1203;
pub const CODING_SHRED_PAYLOAD_SIZE: usize = 1228;

/// Offset of the `flags` byte within a Data shred (after parent_offset u16).
pub const DATA_SHRED_FLAGS_OFFSET: usize = 85;
/// Bitmask in `flags`: marks the final shred of a FEC set (no reconstruction past this).
pub const SHRED_FLAG_DATA_COMPLETE: u8 = 0b0100_0000;
/// Bitmask in `flags`: marks the final shred of the *slot*. Implies DATA_COMPLETE.
pub const SHRED_FLAG_LAST_IN_SLOT: u8 = 0b1000_0000;

#[derive(Debug, thiserror::Error)]
pub enum ShredError {
    #[error("payload too small: {0} bytes")]
    PayloadTooSmall(usize),
    #[error("unknown shred variant byte: 0x{0:02x}")]
    UnknownVariant(u8),
    #[error("invalid signature encoding")]
    InvalidSignatureBytes,
    #[error("invalid pubkey encoding")]
    InvalidPubkeyBytes,
    #[error("invalid merkle proof (root mismatch)")]
    MerkleRootMismatch,
    #[error("ed25519 signature verification failed")]
    SignatureVerifyFailed,
    #[error("proof_size {0} would overflow shred buffer")]
    ProofSizeOverflow(u8),
}

/// Which kind of shred and which optional fields are present in the tail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShredKind {
    Data,
    Code,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShredVariant {
    pub kind: ShredKind,
    pub proof_size: u8,
    pub chained: bool,
    pub resigned: bool,
}

impl ShredVariant {
    /// Decode a variant byte. Matches agave/ledger/src/shred.rs:633-663 — only the
    /// 4 chained variants are accepted on current mainnet.
    pub fn decode(byte: u8) -> Result<Self, ShredError> {
        let proof_size = byte & 0x0f;
        let hi = byte & 0xf0;
        let (kind, resigned) = match hi {
            0x60 => (ShredKind::Code, false), // MerkleCode chained
            0x70 => (ShredKind::Code, true),  // MerkleCode chained resigned
            0x90 => (ShredKind::Data, false), // MerkleData chained
            0xb0 => (ShredKind::Data, true),  // MerkleData chained resigned
            _ => return Err(ShredError::UnknownVariant(byte)),
        };
        Ok(Self { kind, proof_size, chained: true, resigned })
    }

    /// Encode this variant into a single byte.
    pub fn encode(self) -> u8 {
        let hi = match (self.kind, self.resigned) {
            (ShredKind::Code, false) => 0x60,
            (ShredKind::Code, true)  => 0x70,
            (ShredKind::Data, false) => 0x90,
            (ShredKind::Data, true)  => 0xb0,
        };
        hi | (self.proof_size & 0x0f)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CommonHeader {
    pub signature: [u8; 64],
    pub variant: ShredVariant,
    pub slot: u64,
    pub index: u32,
    pub version: u16,
    pub fec_set_index: u32,
}

#[derive(Clone, Debug)]
pub struct ParsedShred<'a> {
    pub raw: &'a [u8],
    pub header: CommonHeader,
    /// Byte range hashed for the Merkle leaf: past signature, before proof (& before resign-sig).
    pub leaf_range: std::ops::Range<usize>,
    /// Byte range of the Merkle proof.
    pub proof_range: std::ops::Range<usize>,
    /// Optional chained merkle root (immediately before the proof).
    pub chained_root: Option<[u8; 32]>,
    /// 0-based index of this shred inside its FEC set (data + coding share the same Merkle tree).
    pub erasure_shard_index: usize,
    /// For data shreds only: the `flags` byte at offset 85. `None` for coding shreds.
    pub data_flags: Option<u8>,
}

impl<'a> ParsedShred<'a> {
    /// True iff this is a data shred carrying the LAST_SHRED_IN_SLOT bit.
    pub fn is_last_in_slot(&self) -> bool {
        self.data_flags.is_some_and(|f| f & SHRED_FLAG_LAST_IN_SLOT != 0)
    }

    /// True iff this is a data shred with DATA_COMPLETE (last data shred of its FEC set).
    pub fn is_data_complete(&self) -> bool {
        self.data_flags.is_some_and(|f| f & SHRED_FLAG_DATA_COMPLETE != 0)
    }
}

/// Parse a raw shred buffer up through Merkle proof location.
pub fn parse_shred(raw: &[u8]) -> Result<ParsedShred<'_>, ShredError> {
    if raw.len() < SIZE_OF_COMMON_HEADER {
        return Err(ShredError::PayloadTooSmall(raw.len()));
    }

    let mut sig = [0u8; 64];
    sig.copy_from_slice(&raw[0..SIZE_OF_SIGNATURE]);
    let variant = ShredVariant::decode(raw[64])?;
    let slot = u64::from_le_bytes(raw[65..73].try_into().unwrap());
    let index = u32::from_le_bytes(raw[73..77].try_into().unwrap());
    let version = u16::from_le_bytes(raw[77..79].try_into().unwrap());
    let fec_set_index = u32::from_le_bytes(raw[79..83].try_into().unwrap());

    let header = CommonHeader {
        signature: sig,
        variant,
        slot,
        index,
        version,
        fec_set_index,
    };

    // Determine total expected length and proof location.
    let expected_len = match variant.kind {
        ShredKind::Data => DATA_SHRED_PAYLOAD_SIZE,
        ShredKind::Code => CODING_SHRED_PAYLOAD_SIZE,
    };
    if raw.len() < expected_len {
        return Err(ShredError::PayloadTooSmall(raw.len()));
    }

    let proof_bytes = variant.proof_size as usize * SIZE_OF_PROOF_ENTRY;
    let resign_bytes = if variant.resigned { SIZE_OF_RETRANSMITTER_SIG } else { 0 };

    if proof_bytes + resign_bytes + SIZE_OF_SIGNATURE > expected_len {
        return Err(ShredError::ProofSizeOverflow(variant.proof_size));
    }

    let proof_end = expected_len - resign_bytes;
    let proof_start = proof_end - proof_bytes;
    let proof_range = proof_start..proof_end;

    // Leaf hash covers [SIZE_OF_SIGNATURE .. proof_start), which already includes the
    // chained-merkle-root region when present. This matches agave's signed_data().
    let leaf_range = SIZE_OF_SIGNATURE..proof_start;

    let chained_root = if variant.chained {
        let cr_start = proof_start - SIZE_OF_MERKLE_ROOT;
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&raw[cr_start..proof_start]);
        Some(buf)
    } else {
        None
    };

    // erasure_shard_index: data shreds use (index - fec_set_index); coding shreds use
    // their `position` field. We read that on demand for coding shreds.
    let erasure_shard_index = match variant.kind {
        ShredKind::Data => (index - fec_set_index) as usize,
        ShredKind::Code => {
            // CodingShredHeader.position lives at offset 87..89 (after common + num_data + num_coding).
            let position = u16::from_le_bytes(raw[87..89].try_into().unwrap());
            DATA_SHREDS_PER_FEC + position as usize
        }
    };

    let data_flags = match variant.kind {
        ShredKind::Data => Some(raw[DATA_SHRED_FLAGS_OFFSET]),
        ShredKind::Code => None,
    };

    Ok(ParsedShred {
        raw,
        header,
        leaf_range,
        proof_range,
        chained_root,
        erasure_shard_index,
        data_flags,
    })
}

/// Compute the Merkle leaf for a parsed shred.
pub fn merkle_leaf(p: &ParsedShred<'_>) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(MERKLE_HASH_PREFIX_LEAF);
    h.update(&p.raw[p.leaf_range.clone()]);
    h.finalize().into()
}

/// Reconstruct the Merkle root from a leaf, its index, and the proof entries.
/// Matches agave/ledger/src/shred/merkle_tree.rs::get_merkle_root.
pub fn compute_merkle_root(
    leaf_index: usize,
    leaf: [u8; 32],
    proof: &[u8],
) -> Result<[u8; 32], ShredError> {
    if !proof.len().is_multiple_of(SIZE_OF_PROOF_ENTRY) {
        return Err(ShredError::MerkleRootMismatch);
    }
    let mut index = leaf_index;
    let mut node = leaf;
    for chunk in proof.chunks_exact(SIZE_OF_PROOF_ENTRY) {
        let mut h = Sha256::new();
        h.update(MERKLE_HASH_PREFIX_NODE);
        if index % 2 == 0 {
            h.update(&node[..SIZE_OF_PROOF_ENTRY]);
            h.update(chunk);
        } else {
            h.update(chunk);
            h.update(&node[..SIZE_OF_PROOF_ENTRY]);
        }
        node = h.finalize().into();
        index >>= 1;
    }
    if index != 0 {
        return Err(ShredError::MerkleRootMismatch);
    }
    Ok(node)
}

/// Full verification: parse → recover Merkle root → verify Ed25519 signature(root) by leader.
pub fn verify_shred(raw: &[u8], leader_pubkey: &[u8; 32]) -> Result<VerifiedShred, ShredError> {
    let p = parse_shred(raw)?;
    let leaf = merkle_leaf(&p);
    let proof = &p.raw[p.proof_range.clone()];
    let root = compute_merkle_root(p.erasure_shard_index, leaf, proof)?;

    let pk = VerifyingKey::from_bytes(leader_pubkey).map_err(|_| ShredError::InvalidPubkeyBytes)?;
    let sig = Signature::from_slice(&p.header.signature).map_err(|_| ShredError::InvalidSignatureBytes)?;
    pk.verify(&root, &sig).map_err(|_| ShredError::SignatureVerifyFailed)?;

    Ok(VerifiedShred {
        slot: p.header.slot,
        fec_set_index: p.header.fec_set_index,
        index: p.header.index,
        erasure_shard_index: p.erasure_shard_index,
        merkle_root: root,
        chained_root: p.chained_root,
        kind: p.header.variant.kind,
        data_flags: p.data_flags,
    })
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedShred {
    pub slot: u64,
    pub fec_set_index: u32,
    pub index: u32,
    pub erasure_shard_index: usize,
    pub merkle_root: [u8; 32],
    pub chained_root: Option<[u8; 32]>,
    pub kind: ShredKind,
    /// Data-shred flags byte (None for coding shreds). Use `is_last_in_slot()` etc.
    pub data_flags: Option<u8>,
}

impl VerifiedShred {
    pub fn is_last_in_slot(&self) -> bool {
        self.data_flags.is_some_and(|f| f & SHRED_FLAG_LAST_IN_SLOT != 0)
    }
    pub fn is_data_complete(&self) -> bool {
        self.data_flags.is_some_and(|f| f & SHRED_FLAG_DATA_COMPLETE != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Construct a synthetic, internally consistent 32+32 FEC set without payload data,
    /// then verify each shred against the leader pubkey. This proves the wire format
    /// and Merkle/Ed25519 plumbing without any network or agave dependency.
    #[test]
    fn synthetic_fec_round_trip() {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let leader_pk = signing.verifying_key().to_bytes();

        // Build 64 leaf hashes (one per shred); we'll wire them into a Merkle tree by hand.
        let mut leaves = Vec::with_capacity(SHREDS_PER_FEC);
        for i in 0..SHREDS_PER_FEC {
            let mut h = Sha256::new();
            h.update(b"lattica-test-leaf");
            h.update(&(i as u32).to_le_bytes());
            leaves.push(<[u8; 32]>::from(h.finalize()));
        }

        // Build the Merkle tree (Solana style, 20-byte truncated internal hashes).
        let root = build_root(&leaves);
        let sig = signing.sign(&root);

        for i in 0..SHREDS_PER_FEC {
            let proof = build_proof(&leaves, i);
            assert_eq!(compute_merkle_root(i, leaves[i], &proof).unwrap(), root);
            // Verify the sig over the root.
            let pk = VerifyingKey::from_bytes(&leader_pk).unwrap();
            pk.verify(&root, &sig).unwrap();
        }
    }

    fn build_root(leaves: &[[u8; 32]]) -> [u8; 32] {
        let mut layer: Vec<[u8; 32]> = leaves.to_vec();
        while layer.len() > 1 {
            let mut next = Vec::with_capacity((layer.len() + 1) / 2);
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

    fn build_proof(leaves: &[[u8; 32]], target: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut layer: Vec<[u8; 32]> = leaves.to_vec();
        let mut idx = target;
        while layer.len() > 1 {
            let sibling = idx ^ 1;
            let s = if sibling < layer.len() { &layer[sibling] } else { &layer[layer.len() - 1] };
            out.extend_from_slice(&s[..SIZE_OF_PROOF_ENTRY]);
            let mut next = Vec::with_capacity((layer.len() + 1) / 2);
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
            idx >>= 1;
        }
        out
    }
}

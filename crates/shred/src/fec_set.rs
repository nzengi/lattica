//! lattica-shred::fec_set — byte-level constructor for a (32 data + 32 coding) FEC set.
//!
//! Produces 64 fully-valid raw shred byte buffers that round-trip through `verify_shred`.
//! Uses chained-MerkleData (0x9?) and chained-MerkleCode (0x6?) with proof_size = 6
//! and no retransmitter sig — the dominant on-mainnet pattern.
//!
//! Layout reference: agave/ledger/src/shred/merkle.rs:44-69 (data shred),
//! :58-69 (coding shred). Erasure shard region is [64..1051) for data and
//! [89..1076) for coding; both are 987 bytes — equal for RS encoding.

use crate::{
    CODING_SHRED_PAYLOAD_SIZE, CODING_SHREDS_PER_FEC, DATA_SHRED_PAYLOAD_SIZE,
    DATA_SHREDS_PER_FEC, MERKLE_HASH_PREFIX_LEAF, MERKLE_HASH_PREFIX_NODE,
    PROOF_ENTRIES_FOR_32_32, SIZE_OF_MERKLE_ROOT, SIZE_OF_PROOF_ENTRY, SIZE_OF_SIGNATURE,
    ShredError, ShredKind, ShredVariant, SHREDS_PER_FEC,
};
use ed25519_dalek::{Signer, SigningKey};
use reed_solomon_erasure::galois_8::ReedSolomon;
use sha2::{Digest, Sha256};

/// Common erasure-shard size for the standard 32+32 batch with proof_size=6, chained, no resign.
pub const ERASURE_SHARD_SIZE: usize = 987;

/// Data shred layout offsets.
mod data_off {
    pub const SIG: usize = 0;
    pub const VARIANT: usize = 64;
    pub const SLOT: usize = 65;
    pub const INDEX: usize = 73;
    pub const VERSION: usize = 77;
    pub const FEC_SET_INDEX: usize = 79;
    pub const PARENT_OFFSET: usize = 83;
    pub const FLAGS: usize = 85;
    pub const SIZE_FIELD: usize = 86;
    pub const DATA_BUF: usize = 88;        // through 1051 (963 bytes)
    pub const DATA_BUF_END: usize = 1051;
    pub const CHAINED_ROOT: usize = 1051;  // 32 bytes
    pub const PROOF: usize = 1083;          // 120 bytes
    pub const TOTAL: usize = 1203;
}

/// Coding shred layout offsets.
mod code_off {
    pub const SIG: usize = 0;
    pub const VARIANT: usize = 64;
    pub const SLOT: usize = 65;
    pub const INDEX: usize = 73;
    pub const VERSION: usize = 77;
    pub const FEC_SET_INDEX: usize = 79;
    pub const NUM_DATA: usize = 83;
    pub const NUM_CODING: usize = 85;
    pub const POSITION: usize = 87;
    pub const ERASURE_BUF: usize = 89;      // through 1076 (987 bytes)
    pub const ERASURE_BUF_END: usize = 1076;
    pub const CHAINED_ROOT: usize = 1076;   // 32 bytes
    pub const PROOF: usize = 1108;           // 120 bytes
    pub const TOTAL: usize = 1228;
}

#[derive(Clone, Copy, Debug)]
pub struct FecSetParams<'a> {
    pub slot: u64,
    pub fec_set_index: u32,
    pub version: u16,
    pub parent_offset: u16,
    pub flags: u8,
    /// Merkle root of the *previous* FEC set in this slot, or 32 zero bytes for the first.
    pub chained_root: [u8; 32],
    pub signing_key: &'a SigningKey,
}

/// A constructed FEC set: 64 fully-valid shred byte buffers (32 data, then 32 coding).
pub struct FecSet {
    pub shreds: Vec<Vec<u8>>,
    pub merkle_root: [u8; 32],
    pub leader_pubkey: [u8; 32],
    pub signature: [u8; 64],
}

/// Build a FEC set carrying `payload` bytes.
/// `payload` is split across 32 data shreds; up to `DATA_SHREDS_PER_FEC * 963` bytes are accepted.
pub fn build_fec_set(payload: &[u8], params: FecSetParams<'_>) -> Result<FecSet, ShredError> {
    const DATA_CAPACITY_PER_SHRED: usize = data_off::DATA_BUF_END - data_off::DATA_BUF; // 963
    let max_payload = DATA_CAPACITY_PER_SHRED * DATA_SHREDS_PER_FEC;
    if payload.len() > max_payload {
        return Err(ShredError::PayloadTooSmall(payload.len())); // overload error meaning here
    }

    let data_variant = ShredVariant {
        kind: ShredKind::Data,
        proof_size: PROOF_ENTRIES_FOR_32_32,
        chained: true,
        resigned: false,
    };
    let code_variant = ShredVariant {
        kind: ShredKind::Code,
        proof_size: PROOF_ENTRIES_FOR_32_32,
        chained: true,
        resigned: false,
    };

    // Pre-allocate all 64 shred buffers.
    let mut shreds: Vec<Vec<u8>> = Vec::with_capacity(SHREDS_PER_FEC);
    for _ in 0..DATA_SHREDS_PER_FEC { shreds.push(vec![0u8; DATA_SHRED_PAYLOAD_SIZE]); }
    for _ in 0..CODING_SHREDS_PER_FEC { shreds.push(vec![0u8; CODING_SHRED_PAYLOAD_SIZE]); }

    // Fill headers + data buffer for the 32 data shreds.
    for i in 0..DATA_SHREDS_PER_FEC {
        let buf = &mut shreds[i];
        buf[data_off::VARIANT] = data_variant.encode();
        buf[data_off::SLOT..data_off::SLOT + 8].copy_from_slice(&params.slot.to_le_bytes());
        let index = params.fec_set_index + i as u32;
        buf[data_off::INDEX..data_off::INDEX + 4].copy_from_slice(&index.to_le_bytes());
        buf[data_off::VERSION..data_off::VERSION + 2].copy_from_slice(&params.version.to_le_bytes());
        buf[data_off::FEC_SET_INDEX..data_off::FEC_SET_INDEX + 4]
            .copy_from_slice(&params.fec_set_index.to_le_bytes());
        buf[data_off::PARENT_OFFSET..data_off::PARENT_OFFSET + 2]
            .copy_from_slice(&params.parent_offset.to_le_bytes());
        buf[data_off::FLAGS] = params.flags;

        // Slice of payload for this shred.
        let off = i * DATA_CAPACITY_PER_SHRED;
        let end = (off + DATA_CAPACITY_PER_SHRED).min(payload.len());
        let slice = if off < payload.len() { &payload[off..end] } else { &[] };
        buf[data_off::DATA_BUF..data_off::DATA_BUF + slice.len()].copy_from_slice(slice);

        // size = bytes used in the data region (header + this slice).
        let size = (data_off::DATA_BUF + slice.len()) as u16;
        buf[data_off::SIZE_FIELD..data_off::SIZE_FIELD + 2].copy_from_slice(&size.to_le_bytes());

        buf[data_off::CHAINED_ROOT..data_off::CHAINED_ROOT + 32]
            .copy_from_slice(&params.chained_root);
    }

    // Fill headers for the 32 coding shreds; erasure region will be populated by RS encode.
    for j in 0..CODING_SHREDS_PER_FEC {
        let i = DATA_SHREDS_PER_FEC + j;
        let buf = &mut shreds[i];
        buf[code_off::VARIANT] = code_variant.encode();
        buf[code_off::SLOT..code_off::SLOT + 8].copy_from_slice(&params.slot.to_le_bytes());
        // Coding shred index in the slot mirrors the data-shred index space; common convention
        // is to assign coding indices starting at fec_set_index (parallel ordering). agave allows
        // this convention. See merkle.rs:266-269 (first_coding_index = index - position).
        let index = params.fec_set_index + j as u32;
        buf[code_off::INDEX..code_off::INDEX + 4].copy_from_slice(&index.to_le_bytes());
        buf[code_off::VERSION..code_off::VERSION + 2].copy_from_slice(&params.version.to_le_bytes());
        buf[code_off::FEC_SET_INDEX..code_off::FEC_SET_INDEX + 4]
            .copy_from_slice(&params.fec_set_index.to_le_bytes());
        buf[code_off::NUM_DATA..code_off::NUM_DATA + 2]
            .copy_from_slice(&(DATA_SHREDS_PER_FEC as u16).to_le_bytes());
        buf[code_off::NUM_CODING..code_off::NUM_CODING + 2]
            .copy_from_slice(&(CODING_SHREDS_PER_FEC as u16).to_le_bytes());
        buf[code_off::POSITION..code_off::POSITION + 2].copy_from_slice(&(j as u16).to_le_bytes());
        buf[code_off::CHAINED_ROOT..code_off::CHAINED_ROOT + 32]
            .copy_from_slice(&params.chained_root);
    }

    // Reed-Solomon encode: input is the 32 × 987-byte erasure regions of the data shreds;
    // output is 32 × 987-byte parity shards written into the coding shreds' erasure regions.
    {
        let mut data_shards: Vec<Vec<u8>> = Vec::with_capacity(DATA_SHREDS_PER_FEC);
        for i in 0..DATA_SHREDS_PER_FEC {
            data_shards.push(shreds[i][SIZE_OF_SIGNATURE..SIZE_OF_SIGNATURE + ERASURE_SHARD_SIZE].to_vec());
        }
        let mut parity_shards: Vec<Vec<u8>> = (0..CODING_SHREDS_PER_FEC)
            .map(|_| vec![0u8; ERASURE_SHARD_SIZE])
            .collect();
        let rs = ReedSolomon::new(DATA_SHREDS_PER_FEC, CODING_SHREDS_PER_FEC)
            .map_err(|_| ShredError::ProofSizeOverflow(0))?;
        rs.encode_sep(&data_shards, &mut parity_shards)
            .map_err(|_| ShredError::ProofSizeOverflow(0))?;
        for (j, parity) in parity_shards.into_iter().enumerate() {
            let i = DATA_SHREDS_PER_FEC + j;
            shreds[i][code_off::ERASURE_BUF..code_off::ERASURE_BUF_END].copy_from_slice(&parity);
        }
    }

    // Compute leaves (one per shred). Leaf = SHA256(LEAF_PREFIX || bytes[64..proof_start]).
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(SHREDS_PER_FEC);
    for i in 0..SHREDS_PER_FEC {
        let buf = &shreds[i];
        let proof_start = if i < DATA_SHREDS_PER_FEC { data_off::PROOF } else { code_off::PROOF };
        let mut h = Sha256::new();
        h.update(MERKLE_HASH_PREFIX_LEAF);
        h.update(&buf[SIZE_OF_SIGNATURE..proof_start]);
        leaves.push(h.finalize().into());
    }

    // Build Merkle tree, collect root + proofs.
    let merkle_tree = build_tree(&leaves);
    let merkle_root = merkle_tree.root;

    // Write proofs into each shred.
    for i in 0..SHREDS_PER_FEC {
        let proof = merkle_proof(&merkle_tree, i);
        let buf = &mut shreds[i];
        let (proof_start, proof_end) = if i < DATA_SHREDS_PER_FEC {
            (data_off::PROOF, data_off::PROOF + (PROOF_ENTRIES_FOR_32_32 as usize) * SIZE_OF_PROOF_ENTRY)
        } else {
            (code_off::PROOF, code_off::PROOF + (PROOF_ENTRIES_FOR_32_32 as usize) * SIZE_OF_PROOF_ENTRY)
        };
        buf[proof_start..proof_end].copy_from_slice(&proof);
    }

    // Sign the root and write into every shred's signature field.
    let signature = params.signing_key.sign(&merkle_root);
    let sig_bytes = signature.to_bytes();
    for buf in shreds.iter_mut() {
        buf[..SIZE_OF_SIGNATURE].copy_from_slice(&sig_bytes);
    }

    let leader_pubkey = params.signing_key.verifying_key().to_bytes();

    Ok(FecSet {
        shreds,
        merkle_root,
        leader_pubkey,
        signature: sig_bytes,
    })
}

struct Tree {
    /// Per-level nodes, level 0 = leaves.
    levels: Vec<Vec<[u8; 32]>>,
    root: [u8; 32],
}

fn build_tree(leaves: &[[u8; 32]]) -> Tree {
    let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
    levels.push(leaves.to_vec());
    while levels.last().unwrap().len() > 1 {
        let last = levels.last().unwrap();
        let mut next: Vec<[u8; 32]> = Vec::with_capacity((last.len() + 1) / 2);
        for chunk in last.chunks(2) {
            let a = &chunk[0];
            let b = if chunk.len() == 2 { &chunk[1] } else { &chunk[0] };
            let mut h = Sha256::new();
            h.update(MERKLE_HASH_PREFIX_NODE);
            h.update(&a[..SIZE_OF_PROOF_ENTRY]);
            h.update(&b[..SIZE_OF_PROOF_ENTRY]);
            next.push(h.finalize().into());
        }
        levels.push(next);
    }
    let root = levels.last().unwrap()[0];
    Tree { levels, root }
}

fn merkle_proof(tree: &Tree, mut index: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for level in &tree.levels {
        if level.len() <= 1 {
            break;
        }
        let sibling = index ^ 1;
        let s = if sibling < level.len() { &level[sibling] } else { &level[level.len() - 1] };
        out.extend_from_slice(&s[..SIZE_OF_PROOF_ENTRY]);
        index >>= 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_shred, verify_shred};

    #[test]
    fn fec_set_round_trips_through_verify_shred() {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let leader_pk = signing.verifying_key().to_bytes();
        // ~16 KiB of test payload, below the 32 * 963 = 30816 cap.
        let payload: Vec<u8> = (0..4_000u32).flat_map(|i| i.to_le_bytes()).collect();

        let params = FecSetParams {
            slot: 12_345_678,
            fec_set_index: 0,
            version: 5,
            parent_offset: 1,
            flags: 0b0100_0000, // DATA_COMPLETE
            chained_root: [0u8; 32],
            signing_key: &signing,
        };

        let fec = build_fec_set(&payload, params).unwrap();
        assert_eq!(fec.shreds.len(), SHREDS_PER_FEC);

        // Every shred must pass full verify_shred against the leader pubkey.
        for (i, raw) in fec.shreds.iter().enumerate() {
            let parsed = parse_shred(raw)
                .unwrap_or_else(|e| panic!("parse failed at shred {i}: {e:?}"));
            assert_eq!(parsed.header.slot, params.slot);
            assert_eq!(parsed.header.fec_set_index, params.fec_set_index);

            let v = verify_shred(raw, &leader_pk)
                .unwrap_or_else(|e| panic!("verify failed at shred {i}: {e:?}"));
            assert_eq!(v.merkle_root, fec.merkle_root, "merkle root mismatch at shred {i}");
        }
    }

    #[test]
    fn data_and_coding_erasure_regions_have_equal_size() {
        assert_eq!(
            data_off::DATA_BUF_END - SIZE_OF_SIGNATURE,
            ERASURE_SHARD_SIZE
        );
        assert_eq!(
            code_off::ERASURE_BUF_END - code_off::ERASURE_BUF,
            ERASURE_SHARD_SIZE
        );
    }
}

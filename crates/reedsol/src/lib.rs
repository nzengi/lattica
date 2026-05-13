//! lattica-reedsol — reconstruct a Solana FEC set (32 data + 32 coding) from any 32 shreds.
//!
//! Solana erases over GF(2^8) with `reed-solomon-erasure`. The erasure region
//! of each shred is the byte slice past the signature; for a (data, coding) batch
//! the data and coding erasure shards must share a common shard size, which is
//! determined by the coding-shred layout.

use reed_solomon_erasure::galois_8::ReedSolomon;

pub const DATA_SHREDS_PER_FEC: usize = 32;
pub const CODING_SHREDS_PER_FEC: usize = 32;
pub const SHREDS_PER_FEC: usize = DATA_SHREDS_PER_FEC + CODING_SHREDS_PER_FEC;

#[derive(Debug, thiserror::Error)]
pub enum ReedSolError {
    #[error("reed-solomon: {0}")]
    Inner(#[from] reed_solomon_erasure::Error),
    #[error("not enough shards present: have {0}, need at least {1}")]
    InsufficientShards(usize, usize),
    #[error("shard length mismatch: expected {0}, got {1}")]
    ShardLenMismatch(usize, usize),
}

/// Reconstruct missing shards in a (32, 32) erasure batch.
///
/// `shards[i]` is `Some(bytes)` if the i-th erasure shard is present, else `None`.
/// `i` in `[0, 32)` is a data shard; `i` in `[32, 64)` is a coding shard.
/// On success, all 64 entries are populated.
pub fn reconstruct(
    shards: &mut [Option<Vec<u8>>; SHREDS_PER_FEC],
) -> Result<(), ReedSolError> {
    let r = ReedSolomon::new(DATA_SHREDS_PER_FEC, CODING_SHREDS_PER_FEC)?;
    r.reconstruct(shards.as_mut_slice())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rs_round_trip_recovers_from_any_32() {
        let shard_size = 1024usize;
        let mut originals: Vec<Vec<u8>> = (0..DATA_SHREDS_PER_FEC)
            .map(|i| {
                let mut v = vec![0u8; shard_size];
                for (j, b) in v.iter_mut().enumerate() {
                    *b = ((i * 31 + j) & 0xff) as u8;
                }
                v
            })
            .collect();
        // Append empty parity slots.
        for _ in 0..CODING_SHREDS_PER_FEC {
            originals.push(vec![0u8; shard_size]);
        }
        let r = ReedSolomon::new(DATA_SHREDS_PER_FEC, CODING_SHREDS_PER_FEC).unwrap();
        let (data, parity) = originals.split_at_mut(DATA_SHREDS_PER_FEC);
        r.encode_sep(data, parity).unwrap();

        // Drop 32 arbitrary shards (e.g. data shreds 0..16 and coding 0..16).
        let mut shards: [Option<Vec<u8>>; SHREDS_PER_FEC] = std::array::from_fn(|_| None);
        for (i, s) in originals.iter().enumerate() {
            shards[i] = Some(s.clone());
        }
        for i in 0..16 { shards[i] = None; }
        for i in DATA_SHREDS_PER_FEC..DATA_SHREDS_PER_FEC + 16 { shards[i] = None; }

        reconstruct(&mut shards).unwrap();

        for (i, (orig, recovered)) in originals.iter().zip(shards.iter()).enumerate() {
            assert_eq!(orig, recovered.as_ref().unwrap(), "shard {} mismatch", i);
        }
    }
}

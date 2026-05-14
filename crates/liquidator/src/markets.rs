//! Per-program market cache: maps `market_index -> (pubkey, oracle)` for every
//! perp and spot market. Populated once at startup via raw RPC fetches; the
//! resulting lookups are pure and cheap.
//!
//! Uses drift-rs struct decoders only (no FFI / no subscribe path).

use anyhow::{Context, Result};
use anchor_lang::AccountDeserialize;
use drift_rs::{
    constants::PROGRAM_ID,
    types::accounts::{PerpMarket, SpotMarket},
};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy)]
pub struct MarketInfo {
    pub pubkey: Pubkey,
    pub oracle: Pubkey,
}

pub struct Markets {
    perps: HashMap<u16, MarketInfo>,
    spots: HashMap<u16, MarketInfo>,
}

impl Markets {
    /// Fetches all perp + spot markets up to `max_perp` / `max_spot`. Stops
    /// scanning each list when the first non-existent account is encountered.
    /// As of 2026-05, mainnet has 50 perp markets and ~30 spot markets, so 64
    /// is a safe upper bound for both.
    pub async fn load(rpc: &RpcClient) -> Result<Self> {
        let perps = scan_markets::<PerpMarket, _>(rpc, b"perp_market", 64, |m| MarketInfo {
            pubkey: derive_pda(b"perp_market", m.market_index),
            oracle: m.amm.oracle,
        })
        .await
        .context("scan perp markets")?;

        let spots = scan_markets::<SpotMarket, _>(rpc, b"spot_market", 64, |m| MarketInfo {
            pubkey: derive_pda(b"spot_market", m.market_index),
            oracle: m.oracle,
        })
        .await
        .context("scan spot markets")?;

        tracing::info!("markets loaded: {} perps, {} spots", perps.len(), spots.len());
        Ok(Self { perps, spots })
    }

    pub fn perp(&self, index: u16) -> MarketInfo {
        *self
            .perps
            .get(&index)
            .unwrap_or_else(|| panic!("perp market {index} not in cache"))
    }
    pub fn spot(&self, index: u16) -> MarketInfo {
        *self
            .spots
            .get(&index)
            .unwrap_or_else(|| panic!("spot market {index} not in cache"))
    }
}

fn derive_pda(seed: &[u8], market_index: u16) -> Pubkey {
    Pubkey::find_program_address(&[seed, &market_index.to_le_bytes()], &PROGRAM_ID).0
}

/// Walks market_index = 0..max, decoding each account via `T::try_deserialize`.
/// Stops at the first index that returns "account does not exist" — Drift
/// market indices are dense, so this gives us the live count without needing
/// to read the State account.
async fn scan_markets<T, F>(
    rpc: &RpcClient,
    seed: &[u8],
    max: u16,
    extract: F,
) -> Result<HashMap<u16, MarketInfo>>
where
    T: AccountDeserialize,
    F: Fn(&T) -> MarketInfo,
{
    let mut out = HashMap::with_capacity(max as usize);
    for i in 0..max {
        let pda = derive_pda(seed, i);
        match rpc.get_account(&pda).await {
            Ok(acct) => {
                let mut data = acct.data.as_slice();
                let market = T::try_deserialize(&mut data)
                    .with_context(|| format!("decode market index {i}"))?;
                out.insert(i, extract(&market));
            }
            Err(_) => break, // sparse beyond this index — stop
        }
    }
    Ok(out)
}

//! probe — direct-RPC validation that we can decode Drift account types
//! without going through drift-rs's broken FFI subscribe/build paths.
//!
//! If this works for PerpMarket and SpotMarket, we have a path to manually
//! constructing liquidation ixs (bypassing the alpha-SDK margin path entirely).

use anyhow::{Context, Result, anyhow};
use anchor_lang::AccountDeserialize;
use drift_rs::{
    constants::PROGRAM_ID,
    types::accounts::{PerpMarket, SpotMarket},
};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};
use std::env;
use tracing::{info, warn};

pub async fn run() -> Result<()> {
    let rpc_url = env_rpc_url()?;
    let rpc = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    // Derive PerpMarket PDA for market_index 0 (SOL-PERP).
    // PDA: seeds = ["perp_market", market_index_le.to_le_bytes()], program = PROGRAM_ID.
    let market_index: u16 = 0;
    let perp_pda = derive_perp_market_pda(market_index);
    info!("PerpMarket[{market_index}] PDA = {perp_pda}");

    let acct = rpc.get_account(&perp_pda).await.context("fetch perp market")?;
    info!("perp_market account len = {} bytes, owner = {}", acct.data.len(), acct.owner);

    let mut data = acct.data.as_slice();
    let perp = PerpMarket::try_deserialize(&mut data).context("decode PerpMarket")?;
    let name = std::str::from_utf8(&perp.name).unwrap_or("?").trim_end_matches('\0').trim();
    info!("  market_index   = {}", perp.market_index);
    info!("  name           = {}", name);
    info!("  status         = {:?}", perp.status);
    info!("  oracle pubkey  = {}", perp.amm.oracle);
    info!("  oracle source  = {:?}", perp.amm.oracle_source);
    info!("  base precision = {}", perp.amm.order_step_size);

    // Same for SOL/USDC spot (market_index 1 is typically SOL spot; 0 is USDC).
    for spot_idx in [0u16, 1] {
        let spot_pda = derive_spot_market_pda(spot_idx);
        let acct = rpc.get_account(&spot_pda).await.context("fetch spot market")?;
        let mut data = acct.data.as_slice();
        let spot = SpotMarket::try_deserialize(&mut data).context("decode SpotMarket")?;
        let name = std::str::from_utf8(&spot.name).unwrap_or("?").trim_end_matches('\0').trim();
        info!("SpotMarket[{spot_idx}] name={} oracle={} mint={}",
            name, spot.oracle, spot.mint);
    }

    warn!("PROBE OK — drift-rs struct definitions decode mainnet bytes correctly.");
    warn!("the broken FFI was in subscribe/builder paths, not in struct decoders.");
    warn!("path forward: bypass drift-rs subscribe layer; do raw-RPC fetches ourselves.");

    Ok(())
}

fn derive_perp_market_pda(market_index: u16) -> Pubkey {
    let (pda, _bump) = Pubkey::find_program_address(
        &[b"perp_market", &market_index.to_le_bytes()],
        &PROGRAM_ID,
    );
    pda
}

fn derive_spot_market_pda(market_index: u16) -> Pubkey {
    let (pda, _bump) = Pubkey::find_program_address(
        &[b"spot_market", &market_index.to_le_bytes()],
        &PROGRAM_ID,
    );
    pda
}

fn env_rpc_url() -> Result<String> {
    if let Ok(v) = env::var("HELIUS_RPC_URL") { return Ok(v); }
    for p in [".env", "../.env", "../../.env"] {
        if let Ok(contents) = std::fs::read_to_string(p) {
            for line in contents.lines() {
                if let Some(rest) = line.trim().strip_prefix("HELIUS_RPC_URL=") {
                    return Ok(rest.trim().to_string());
                }
            }
        }
    }
    Err(anyhow!("HELIUS_RPC_URL not set"))
}

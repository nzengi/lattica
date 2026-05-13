//! Paper-trade scanner — v0.1.
//!
//! Connects DriftClient to mainnet, subscribes to all perp/spot markets and oracles,
//! enumerates ~30 perp market accounts, prints status + oracle prices. This first
//! iteration validates: FFI linkage, mainnet connectivity, drift-rs API surface.

use anyhow::{Context as _, Result, anyhow};
use std::env;
use tracing::{info, warn};

use drift_rs::{DriftClient, Wallet, Context as DriftContext, types::MarketId};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;

pub async fn run() -> Result<()> {
    let rpc_url = env_rpc_url()?;
    info!("paper-trade mode — RPC {}", redact_url(&rpc_url));

    let rpc = RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());

    // Read-only wallet — drift-rs requires a wallet for client construction,
    // but we never sign in paper mode.
    let wallet = Wallet::read_only(Pubkey::new_unique());

    info!("connecting DriftClient to mainnet…");
    let client = DriftClient::new(DriftContext::MainNet, rpc, wallet)
        .await
        .context("DriftClient::new failed (check libdrift_ffi_sys is linked)")?;

    info!("subscribing to all markets + oracles (cache prime)…");
    client.subscribe_all_markets().await.context("subscribe_all_markets")?;
    client.subscribe_all_oracles().await.context("subscribe_all_oracles")?;
    // Give the WebSocket-fed oracle map time to receive the first batch of price
    // updates before we read; otherwise oracle_price returns the default-initialized 1.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Enumerate perp markets 0..50; print whichever ones exist.
    info!("enumerating perp markets:");
    let mut found = 0u16;
    for i in 0u16..50 {
        match client.get_perp_market_account(i).await {
            Ok(m) => {
                found += 1;
                let price = client
                    .oracle_price(MarketId::perp(m.market_index))
                    .await
                    .ok();
                let price_str = price
                    .map(|p| format!("{:.6}", p as f64 / 1e6))
                    .unwrap_or_else(|| "<no oracle>".to_string());
                let name = std::str::from_utf8(&m.name)
                    .unwrap_or("?")
                    .trim_end_matches(char::from(0))
                    .trim();
                info!(
                    "  perp[{:>2}] {:<14} status={:?} price={}",
                    m.market_index, name, m.status, price_str
                );
            }
            Err(_) => continue,
        }
    }
    info!("perp markets found: {found}");

    warn!("v0.1 paper-trade is done — connection verified.");
    warn!("next iterations:");
    warn!("  v0.2 — getProgramAccounts for all Drift User accounts; rank by health");
    warn!("  v0.3 — simulate liquidation tx via rpc.simulateTransaction");
    warn!("  v0.4 — Jito bundle submission on live mainnet");

    Ok(())
}

fn env_rpc_url() -> Result<String> {
    if let Ok(v) = env::var("HELIUS_RPC_URL") {
        return Ok(v);
    }
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

fn redact_url(url: &str) -> String {
    if let Some(idx) = url.find("api-key=") {
        let mut s = url[..idx + 8].to_string();
        s.push_str("***");
        return s;
    }
    url.to_string()
}

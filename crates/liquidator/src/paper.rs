//! Paper-trade scanner — v0.2.
//!
//! Connects DriftClient to mainnet, primes market+oracle subscriptions, then runs
//! the User-account scanner to identify liquidation candidates. PRINTS the top
//! ~20 unhealthy users; no tx signing, no Jito submission.

use anyhow::{Context as _, Result, anyhow};
use std::env;
use std::sync::Arc;
use tracing::{info, warn};

use drift_rs::{Context as DriftContext, DriftClient, Wallet};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;

use crate::scanner::{ScanScope, scan_users};

pub async fn run() -> Result<()> {
    let rpc_url = env_rpc_url()?;
    info!("paper-trade v0.2 — RPC {}", redact_url(&rpc_url));

    let rpc_for_client = RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());
    // Independent client for getProgramAccounts (drift-rs consumes the one passed in).
    let rpc_for_gpa = Arc::new(RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed()));

    let wallet = Wallet::read_only(Pubkey::new_unique());

    info!("connecting DriftClient to mainnet…");
    let client = DriftClient::new(DriftContext::MainNet, rpc_for_client, wallet)
        .await
        .context("DriftClient::new failed (check libdrift_ffi_sys is linked)")?;

    info!("subscribing to all markets + oracles…");
    client.subscribe_all_markets().await.context("subscribe_all_markets")?;
    client.subscribe_all_oracles().await.context("subscribe_all_oracles")?;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // First pass: only users with open orders — much smaller subset, fast RPC.
    let scope = std::env::args().nth(2).unwrap_or_else(|| "orders".into());
    let scan_scope = match scope.as_str() {
        "all" => ScanScope::AllNonIdle,
        _ => ScanScope::UsersWithOrders,
    };

    let candidates = scan_users(&client, &rpc_for_gpa, scan_scope, 20)
        .await
        .context("scan_users")?;

    // v0.2 status: User account decoder works (1425 active mainnet users decoded);
    // margin calc via drift-rs alpha SDK is unreliable (bytemuck panics on stale
    // market data layouts inside the FFI). Show the user-discovery results;
    // exact margin calc is deferred to v0.3 (alternative: simulate liquidation
    // tx, let the Drift program return error if user is solvent).
    info!("user-discovery scan results (margin calc STUBBED — see roadmap):");
    info!(
        "  {:<44} {:>4} {:>4}",
        "user-pda (base58)", "perp", "spot"
    );
    let mut sorted = candidates.clone();
    sorted.sort_by_key(|c| std::cmp::Reverse(c.n_perp_positions + c.n_spot_positions));
    let total_positions: usize = sorted.iter().map(|c| c.n_perp_positions + c.n_spot_positions).sum();
    for c in sorted.iter().take(20) {
        info!(
            "  {} {:>4} {:>4}",
            c.pubkey, c.n_perp_positions, c.n_spot_positions
        );
    }
    info!("summary: {} users with open orders; {} total positions across top 20",
        candidates.len(), total_positions);

    warn!("v0.2 done — user discovery + position decoding works on mainnet.");
    warn!("known limit: drift-rs alpha.14 margin FFI panics on current mainnet market layouts.");
    warn!("v0.3 plan: pivot to liquidatePerp simulation — let Drift program decide solvency.");

    Ok(())
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

fn redact_url(url: &str) -> String {
    if let Some(idx) = url.find("api-key=") {
        let mut s = url[..idx + 8].to_string();
        s.push_str("***");
        return s;
    }
    url.to_string()
}

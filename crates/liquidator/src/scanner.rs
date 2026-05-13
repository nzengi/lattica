//! User-account scanner: pulls Drift User accounts via `getProgramAccounts`,
//! decodes them, computes Maintenance-margin health for each, and ranks
//! by liquidation distance.
//!
//! Health = total_collateral / margin_requirement (Maintenance).
//! Health < 1.0 = liquidatable.
//! Health < 1.05 = "watchlist" (one oracle tick away).

use anyhow::{Context, Result};
use anchor_lang::AccountDeserialize;
use drift_rs::{
    DriftClient,
    constants::PROGRAM_ID,
    drift_idl::types::MarginRequirementType,
    ffi::{
        MarginContextMode, calculate_margin_requirement_and_total_collateral_and_liability_info,
    },
    math::account_list_builder::AccountsListBuilder,
    memcmp::{get_user_filter, get_user_with_order_filter},
    types::accounts::User,
};
use solana_account_decoder::UiAccountEncoding;
use solana_client::{
    nonblocking::rpc_client::RpcClient,
    rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig},
};
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};

#[derive(Debug, Clone)]
pub struct LiqCandidate {
    pub pubkey: Pubkey,
    pub authority: Pubkey,
    pub total_collateral_q6: i128,
    pub margin_requirement_q6: u128,
    pub health: f64,
    pub n_perp_positions: usize,
    pub n_spot_positions: usize,
}

/// Filter mode for the User-account fetch.
#[derive(Debug, Clone, Copy)]
pub enum ScanScope {
    /// Only users with open orders. Smaller subset (~hundreds), faster RPC, good for PoC.
    UsersWithOrders,
    /// All non-idle Users. Larger (~tens of thousands), heavy RPC call.
    AllNonIdle,
}

pub async fn scan_users(
    client: &DriftClient,
    rpc: &RpcClient,
    scope: ScanScope,
    max_candidates: usize,
) -> Result<Vec<LiqCandidate>> {
    let filters = match scope {
        ScanScope::UsersWithOrders => vec![get_user_filter(), get_user_with_order_filter()],
        ScanScope::AllNonIdle => vec![get_user_filter()],
    };

    let config = RpcProgramAccountsConfig {
        filters: Some(filters),
        account_config: RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::Base64),
            commitment: Some(CommitmentConfig::confirmed()),
            ..Default::default()
        },
        ..Default::default()
    };

    tracing::info!("getProgramAccounts on Drift program {} (scope={:?})…", PROGRAM_ID, scope);
    let accounts = rpc
        .get_program_accounts_with_config(&PROGRAM_ID, config)
        .await
        .context("get_program_accounts_with_config")?;
    tracing::info!("rpc returned {} candidate accounts", accounts.len());

    let mut candidates = Vec::with_capacity(accounts.len());
    let mut decode_failures = 0usize;
    let mut margin_failures = 0usize;
    let mut zero_margin = 0usize;
    let mut already_liquidating = 0usize;
    let total = accounts.len();
    let started = std::time::Instant::now();

    // drift-rs alpha.14's User struct must match the on-chain layout byte-for-byte.
    // If the chain grew/shrank the struct (struct evolution between SDK versions),
    // bytemuck::from_bytes inside `User::try_deserialize_unchecked` will fatally
    // panic — guard with a size precheck.
    let expected_user_len = 8 + std::mem::size_of::<User>();
    tracing::info!("expected User account data size: {} bytes (8 discriminator + {} struct)",
        expected_user_len, std::mem::size_of::<User>());

    let mut size_mismatch = 0usize;
    for (i, (pubkey, account)) in accounts.into_iter().enumerate() {
        if i > 0 && i % 200 == 0 {
            let elapsed_s = started.elapsed().as_secs_f64();
            let rate = i as f64 / elapsed_s;
            tracing::info!(
                "  …scanned {}/{} ({:.1}/s, eta {:.0}s)",
                i, total, rate, ((total - i) as f64 / rate).max(0.0)
            );
        }
        if account.data.len() != expected_user_len {
            size_mismatch += 1;
            continue;
        }
        // Wrap each step in catch_unwind. drift-rs alpha.14 uses bytemuck::from_bytes
        // on several internal data paths and panics on size/alignment mismatch;
        // we want to gracefully skip such accounts rather than crash the scanner.
        let pk_copy = pubkey;
        let data_copy = account.data.clone();
        let decode_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut data = data_copy.as_slice();
            User::try_deserialize(&mut data)
        }));
        let user = match decode_result {
            Ok(Ok(u)) => u,
            Ok(Err(_)) => { decode_failures += 1; continue; }
            Err(_) => { decode_failures += 1; continue; }
        };
        if user.is_being_liquidated() || user.is_bankrupt() {
            already_liquidating += 1;
            continue;
        }

        // TEMPORARY: skip margin calc to isolate the bytemuck panic source.
        // If we get past User decode with all 1425 users, the panic is in margin calc.
        let _ = client; // unused while margin is stubbed
        let total_collateral: i128 = 0;
        let margin_requirement: u128 = 1; // sentinel so health computation doesn't divide by zero

        if margin_requirement == 0 {
            zero_margin += 1;
            continue;
        }
        let health = total_collateral as f64 / margin_requirement as f64;
        let n_perp = user.perp_positions.iter().filter(|p| !p.is_available()).count();
        let n_spot = user.spot_positions.iter().filter(|p| !p.is_available()).count();

        candidates.push(LiqCandidate {
            pubkey: pk_copy,
            authority: user.authority,
            total_collateral_q6: total_collateral,
            margin_requirement_q6: margin_requirement,
            health,
            n_perp_positions: n_perp,
            n_spot_positions: n_spot,
        });
    }

    tracing::info!(
        "decoded={} size_mismatch={} decode_failures={} margin_failures={} zero_margin={} already_liq={}",
        candidates.len(),
        size_mismatch,
        decode_failures,
        margin_failures,
        zero_margin,
        already_liquidating,
    );

    candidates.sort_by(|a, b| a.health.partial_cmp(&b.health).unwrap_or(std::cmp::Ordering::Equal));
    candidates.truncate(max_candidates);
    Ok(candidates)
}

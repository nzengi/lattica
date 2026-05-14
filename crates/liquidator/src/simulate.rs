//! `simulate` mode — picks a single mainnet candidate, builds a manual
//! `liquidate_perp` ix, sends it to `simulateTransaction` (no signing, no
//! submit), prints the program logs.
//!
//! Goal: prove that the manually-built ix is structurally correct. A healthy
//! user should produce the Drift program error
//! `SufficientCollateral` (or similar) — that's the success signal: the
//! program parsed our accounts + args, ran margin math, and rejected because
//! the user is solvent. Any earlier error (account not found, deserialization
//! failure, custom anchor error) means we got the layout wrong.

use anyhow::{Context, Result, anyhow};
use anchor_lang::AccountDeserialize;
use drift_rs::{constants::PROGRAM_ID, types::accounts::User};
use solana_account_decoder::UiAccountEncoding;
use solana_client::{
    nonblocking::rpc_client::RpcClient,
    rpc_config::{RpcAccountInfoConfig, RpcProgramAccountsConfig, RpcSimulateTransactionConfig},
};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    hash::Hash,
    message::{Message, VersionedMessage},
    pubkey::Pubkey,
    transaction::VersionedTransaction,
};
use std::env;
use tracing::{info, warn};

use crate::ix::{build_liquidate_perp_ix, user_pda, user_stats_pda};
use crate::markets::Markets;

pub async fn run() -> Result<()> {
    let rpc_url = env_rpc_url()?;
    let rpc = RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());

    info!("loading market cache from mainnet…");
    let markets = Markets::load(&rpc).await.context("load markets")?;

    info!("scanning Drift program for User accounts with open perp positions…");
    let candidate = pick_candidate_with_perp_position(&rpc).await?;
    let market_index = candidate
        .data
        .perp_positions
        .iter()
        .find(|p| !p.is_available())
        .map(|p| p.market_index)
        .ok_or_else(|| anyhow!("candidate has no perp positions"))?;

    info!(
        "candidate user = {}, authority = {}, target market_index = {}",
        candidate.pubkey, candidate.data.authority, market_index
    );

    // For SIMULATION ONLY: use the candidate's own authority as the "liquidator"
    // — sigVerify=false on simulate means no real signature is needed. This
    // lets us test ix structure without depositing USDC for a real liquidator
    // account. In v0.5 we'll swap in our own funded Drift sub-account.
    let liquidator_authority = candidate.data.authority;
    let liquidator_user = user_pda(&liquidator_authority, candidate.data.sub_account_id);
    info!(
        "(simulation) using liquidatee's own authority as liquidator: stats={}",
        user_stats_pda(&liquidator_authority)
    );

    let ix = build_liquidate_perp_ix(
        liquidator_authority,
        liquidator_user,
        &candidate.data, // re-using same User as both sides for sim
        candidate.pubkey,
        &candidate.data,
        market_index,
        u64::MAX, // no cap — let program decide
        None,     // no limit price
        &markets,
    );
    info!("built liquidate_perp ix: {} accounts, {} bytes data",
        ix.accounts.len(), ix.data.len());
    info!("ix.program_id = {}", ix.program_id);
    info!("ix.data hex   = {}", hex::encode(&ix.data));
    for (i, m) in ix.accounts.iter().enumerate() {
        info!("  acct[{:>2}] {}  signer={} writable={}", i, m.pubkey, m.is_signer, m.is_writable);
    }

    // Wrap into a legacy Message + VersionedTransaction (no LUT for sim).
    let msg = Message::new(&[ix], Some(&liquidator_authority));
    let mut tx = VersionedTransaction {
        signatures: vec![Default::default(); msg.header.num_required_signatures as usize],
        message: VersionedMessage::Legacy(msg),
    };
    // Fill in a recent blockhash — sim with replaceRecentBlockhash also handles it,
    // but having one set up front avoids surprises with serialization.
    let blockhash = rpc.get_latest_blockhash().await.context("blockhash")?;
    set_blockhash(&mut tx, blockhash);

    info!("simulating against mainnet (sigVerify=false, replaceRecentBlockhash=true)…");
    let sim = rpc
        .simulate_transaction_with_config(
            &tx,
            RpcSimulateTransactionConfig {
                sig_verify: false,
                replace_recent_blockhash: true,
                commitment: Some(CommitmentConfig::confirmed()),
                encoding: None,
                accounts: None,
                min_context_slot: None,
                inner_instructions: false,
            },
        )
        .await
        .context("simulate_transaction")?;

    info!("--- simulation result ---");
    if let Some(err) = &sim.value.err {
        info!("err = {:?}", err);
    } else {
        info!("err = None (would have succeeded)");
    }
    if let Some(units) = sim.value.units_consumed {
        info!("compute units consumed = {}", units);
    }
    if let Some(logs) = &sim.value.logs {
        info!("logs ({} lines):", logs.len());
        for l in logs {
            info!("  {}", l);
        }
    } else {
        warn!("no logs returned");
    }

    interpret(&sim.value);
    Ok(())
}

fn interpret(value: &solana_client::rpc_response::RpcSimulateTransactionResult) {
    let logs = value.logs.as_deref().unwrap_or(&[]);
    let success_signals = [
        "SufficientCollateral",
        "UserHasInvalidLiquidation",
        "UserNotBeingLiquidated",
        "InvalidLiquidation",
    ];
    let layout_signals = [
        "AccountDidNotDeserialize",
        "ConstraintSeeds",
        "AccountNotEnoughKeys",
        "AccountOwnedByWrongProgram",
        "InvalidProgramId",
        "instruction modified data of an account it does not own",
    ];
    let mut hit_success = false;
    let mut hit_layout = false;
    for line in logs {
        if success_signals.iter().any(|s| line.contains(s)) {
            hit_success = true;
        }
        if layout_signals.iter().any(|s| line.contains(s)) {
            hit_layout = true;
        }
    }
    if hit_success {
        warn!("✅ ix structure is correct — Drift program ran margin math and rejected on solvency");
    } else if hit_layout {
        warn!("❌ account layout is wrong — fix the ix builder before continuing");
    } else if value.err.is_none() {
        warn!("⚠️  simulation succeeded with no error — unexpected; user may actually be liquidatable");
    } else {
        warn!("⚠️  unrecognized error pattern — inspect logs above");
    }
}

fn set_blockhash(tx: &mut VersionedTransaction, hash: Hash) {
    match &mut tx.message {
        VersionedMessage::Legacy(m) => m.recent_blockhash = hash,
        VersionedMessage::V0(m) => m.recent_blockhash = hash,
    }
}

#[allow(unused)]
struct Candidate {
    pubkey: Pubkey,
    data: User,
}

/// Lightweight version of scanner — picks the FIRST decoded User with at
/// least one open perp position. We don't need the lowest-health user for an
/// ix-shape probe; any active user exercises the same code path.
async fn pick_candidate_with_perp_position(rpc: &RpcClient) -> Result<Candidate> {
    use drift_rs::memcmp::{get_user_filter, get_user_with_order_filter};
    let config = RpcProgramAccountsConfig {
        filters: Some(vec![get_user_filter(), get_user_with_order_filter()]),
        account_config: RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::Base64),
            commitment: Some(CommitmentConfig::confirmed()),
            ..Default::default()
        },
        ..Default::default()
    };
    let accounts = rpc
        .get_program_accounts_with_config(&PROGRAM_ID, config)
        .await
        .context("get_program_accounts")?;
    info!("scanning {} candidate user accounts for an open perp position…", accounts.len());

    let expected = 8 + std::mem::size_of::<User>();
    for (pk, acct) in accounts {
        if acct.data.len() != expected {
            continue;
        }
        let decode = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut data = acct.data.as_slice();
            User::try_deserialize(&mut data)
        }));
        let user = match decode {
            Ok(Ok(u)) => u,
            _ => continue,
        };
        if user.is_being_liquidated() || user.is_bankrupt() {
            continue;
        }
        let has_perp = user.perp_positions.iter().any(|p| !p.is_available());
        if has_perp {
            return Ok(Candidate { pubkey: pk, data: user });
        }
    }
    Err(anyhow!("no candidate with an open perp position found"))
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


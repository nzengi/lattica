//! `disc-probe` mode — sends *minimal* simulate-only transactions with several
//! candidate discriminators against the live Drift program. Lets us isolate
//! whether the discriminator scheme is wrong (every disc fails the same way)
//! vs. our specific ix construction (different errors per disc).
//!
//! Each probe sends just the 8-byte discriminator with NO args and the Drift
//! state PDA as the only account. Shape is intentionally invalid — we want
//! the program to *recognize* the disc and fail at account validation, not
//! at the dispatcher's fallback arm.

use anyhow::{Context, Result, anyhow};
use drift_rs::constants::PROGRAM_ID;
use solana_client::{
    nonblocking::rpc_client::RpcClient, rpc_config::RpcSimulateTransactionConfig,
};
use solana_sdk::{
    commitment_config::CommitmentConfig,
    hash::Hash,
    instruction::{AccountMeta, Instruction},
    message::{Message, VersionedMessage},
    pubkey::Pubkey,
    transaction::VersionedTransaction,
};
use std::env;
use tracing::{info, warn};

use crate::ix::state_pda;

pub async fn run() -> Result<()> {
    let rpc_url = env_rpc_url()?;
    let rpc = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    // Anchor sighashes for several known Drift ixs (alpha.14 IDL).
    // Computed: sha256("global:<name>")[..8].
    let probes: &[(&str, [u8; 8])] = &[
        // The one we've been trying:
        ("liquidate_perp", [75, 35, 119, 247, 191, 18, 139, 2]),
        // A simple, well-tested user ix:
        ("initialize_user", [0x6f, 0x11, 0xb9, 0xfa, 0x3c, 0x7a, 0x26, 0xfe]),
        // A pure read-only ix (no state mutation):
        ("update_user_idle", [0xfd, 0x85, 0x43, 0x16, 0x67, 0xa1, 0x14, 0x64]),
        // Garbage — should always hit fallback:
        ("garbage_baseline", [0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef]),
    ];

    let blockhash = rpc.get_latest_blockhash().await.context("blockhash")?;
    let dummy_payer = Pubkey::new_unique();

    for (name, disc) in probes {
        let result = probe_one(&rpc, *disc, dummy_payer, blockhash).await;
        match result {
            Ok(summary) => info!("[{:>20}] disc={}  →  {}", name, hex::encode(disc), summary),
            Err(e) => warn!("[{:>20}] error: {e:#}", name),
        }
    }

    Ok(())
}

async fn probe_one(
    rpc: &RpcClient,
    disc: [u8; 8],
    payer: Pubkey,
    blockhash: Hash,
) -> Result<String> {
    let ix = Instruction {
        program_id: PROGRAM_ID,
        // One readonly account (state PDA) — won't satisfy the ix's account
        // requirements but will let the dispatcher reach the handler if the
        // disc is recognized. Anchor will then fail at account validation
        // with a DIFFERENT error than InstructionFallbackNotFound.
        accounts: vec![AccountMeta::new_readonly(state_pda(), false)],
        data: disc.to_vec(),
    };

    let msg = Message::new(&[ix], Some(&payer));
    let mut tx = VersionedTransaction {
        signatures: vec![Default::default(); msg.header.num_required_signatures as usize],
        message: VersionedMessage::Legacy(msg),
    };
    if let VersionedMessage::Legacy(m) = &mut tx.message {
        m.recent_blockhash = blockhash;
    }

    let sim = rpc
        .simulate_transaction_with_config(
            &tx,
            RpcSimulateTransactionConfig {
                sig_verify: false,
                replace_recent_blockhash: true,
                commitment: Some(CommitmentConfig::confirmed()),
                ..Default::default()
            },
        )
        .await
        .context("simulate")?;

    let logs = sim.value.logs.unwrap_or_default();
    // Pick the most-informative log line: the one that mentions an Anchor error
    // code, an account constraint violation, or a custom error.
    let summary = logs
        .iter()
        .find(|l| {
            l.contains("AnchorError")
                || l.contains("Constraint")
                || l.contains("AccountNot")
                || l.contains("AccountOwnedByWrong")
        })
        .cloned()
        .unwrap_or_else(|| {
            // No Anchor error → look for the program's exit error code instead.
            logs.iter()
                .rev()
                .find(|l| l.contains("custom program error"))
                .cloned()
                .unwrap_or_else(|| format!("err={:?}", sim.value.err))
        });
    Ok(summary)
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

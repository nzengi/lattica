//! lattica-liq — Drift v2 liquidation bot.
//!
//! Modes:
//!   paper        v0.1  scan Drift Users, decode positions, no signing
//!   probe        v0.2  direct-RPC PerpMarket / SpotMarket decode probe
//!   simulate     v0.3  build LiquidatePerp ix manually + simulate (BLOCKED — see disc-probe)
//!   disc-probe   v0.3  send candidate discriminators against the live program;
//!                      every standard Anchor sha256("global:<name>")[:8] returns
//!                      InstructionFallbackNotFound — on-chain dispatcher diverges
//!                      from public IDL. See memory/project_drift_dispatcher.md.
//!   idl-dump     v0.3  fetch + decompress on-chain Anchor IDL for diff.

use anyhow::Result;

mod disc_probe;
mod idl_dump;
mod ix;
mod markets;
mod paper;
mod probe;
mod scanner;
mod simulate;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lattica_liq=info,drift_rs=warn".into()),
        )
        .init();

    let mode = std::env::args().nth(1).unwrap_or_else(|| "paper".to_string());
    match mode.as_str() {
        "paper" => paper::run().await,
        "probe" => probe::run().await,
        "simulate" => simulate::run().await,
        "idl-dump" => idl_dump::run().await,
        "disc-probe" => disc_probe::run().await,
        other => {
            eprintln!("unknown mode: {other}. supported: paper | probe | simulate | idl-dump | disc-probe");
            Ok(())
        }
    }
}

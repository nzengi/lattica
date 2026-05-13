//! lattica-liq — Drift v2 liquidation bot.
//!
//! Phases of this binary:
//!   v0.1  PAPER MODE   — connect to mainnet, scan Drift User accounts, compute
//!                        margin/health, identify liquidatable candidates, PRINT
//!                        what would happen. No tx signing, no Jito submission.
//!   v0.2  ARMED        — same scanning + actually build liquidation ixs + simulate
//!                        them locally (rpc.simulateTransaction). Still no submit.
//!   v0.3  LIVE MAINNET — submit via Jito bundle with tip; rotate $300 collateral.

use anyhow::Result;

mod paper;
mod scanner;

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
        other => {
            eprintln!("unknown mode: {other}. supported: paper");
            Ok(())
        }
    }
}

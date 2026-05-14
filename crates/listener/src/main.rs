//! lattica-listen — daemon that ingests Solana shreds on a UDP port and emits FEC events.
//!
//! Usage:
//!   lattica-listen <bind-addr> static:<leader-pubkey-base58>
//!   lattica-listen <bind-addr> helius:<rpc-url>
//!
//! Examples:
//!   lattica-listen 0.0.0.0:9999 static:EnaT...
//!   lattica-listen 0.0.0.0:9999 'helius:https://mainnet.helius-rpc.com/?api-key=...'

use lattica_listener::{
    udp::run_listener_with_resolver, FecEvent, HeliusLeaderResolver, LeaderResolver, StaticLeader,
};
use std::{env, net::SocketAddr, process::ExitCode};

fn pubkey_from_b58(s: &str) -> Option<[u8; 32]> {
    let v = bs58::decode(s).into_vec().ok()?;
    if v.len() != 32 { return None; }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Some(out)
}

fn parse_resolver(spec: &str) -> Option<Box<dyn LeaderResolver>> {
    if let Some(pk_str) = spec.strip_prefix("static:") {
        let pk = pubkey_from_b58(pk_str)?;
        Some(Box::new(StaticLeader(pk)))
    } else if let Some(url) = spec.strip_prefix("helius:") {
        Some(Box::new(HeliusLeaderResolver::new(url.to_string())))
    } else if spec.len() == 44 && bs58::decode(spec).into_vec().is_ok() {
        // bare base58 pubkey — treat as static
        let pk = pubkey_from_b58(spec)?;
        Some(Box::new(StaticLeader(pk)))
    } else {
        None
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage:
  lattica-listen <bind-addr> static:<leader-pubkey-base58>
  lattica-listen <bind-addr> helius:<rpc-url>
  lattica-listen <bind-addr> <leader-pubkey-base58>   # shorthand for static:"
    );
    ExitCode::FAILURE
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return usage();
    }
    let addr: SocketAddr = match args[1].parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("invalid bind addr: {e}");
            return ExitCode::FAILURE;
        }
    };
    let Some(resolver) = parse_resolver(&args[2]) else {
        eprintln!("invalid resolver spec");
        return usage();
    };

    eprintln!("[lattica-listen] binding {addr}, resolver = {}", &args[2]);
    let (mut rx, _handle) = match run_listener_with_resolver(addr, resolver).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("bind failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    while let Some(ev) = rx.recv().await {
        match ev {
            FecEvent::Started { key, merkle_root } => {
                println!("[start] slot={} fec_set={} root={}",
                    key.slot, key.fec_set_index, hex::encode(merkle_root));
            }
            FecEvent::ShredAccepted { key, shreds_present, erasure_shard_index } => {
                println!("[shred] slot={} fec_set={} have={}/64 idx={}",
                    key.slot, key.fec_set_index, shreds_present, erasure_shard_index);
            }
            FecEvent::Reconstructed { key, merkle_root, das_confidence } => {
                println!("[done!] slot={} fec_set={} root={} das_conf={:.6}",
                    key.slot, key.fec_set_index, hex::encode(merkle_root), das_confidence);
            }
            FecEvent::SlotFinalized { slot, fec_roots, slot_root, total_shreds_observed, slot_das_confidence } => {
                println!(
                    "[SLOT!] slot={} n_fec_sets={} shreds_observed={} slot_das_conf={:.9} slot_root={}",
                    slot, fec_roots.len(), total_shreds_observed, slot_das_confidence,
                    hex::encode(slot_root),
                );
            }
            FecEvent::Rejected { reason } => {
                eprintln!("[rej] {reason}");
            }
        }
    }
    ExitCode::SUCCESS
}

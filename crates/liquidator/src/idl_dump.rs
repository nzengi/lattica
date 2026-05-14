//! `idl-dump` mode — fetches the Drift program's on-chain Anchor IDL,
//! decompresses it, and writes it to /tmp/drift_onchain.json. Lets us compare
//! the LIVE program's ix discriminators against what drift-rs alpha.14 has
//! hard-coded — useful when simulate keeps returning `InstructionFallbackNotFound`.

use anyhow::{Context, Result, anyhow};
use drift_rs::constants::PROGRAM_ID;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey};
use std::env;
use std::io::Read;
use tracing::info;

pub async fn run() -> Result<()> {
    let rpc_url = env_rpc_url()?;
    let rpc = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    // Anchor IDL account derivation:
    //   base = find_program_address(&[], program_id).0
    //   idl  = create_with_seed(base, "anchor:idl", program_id)
    let (base, _bump) = Pubkey::find_program_address(&[], &PROGRAM_ID);
    let idl_account = Pubkey::create_with_seed(&base, "anchor:idl", &PROGRAM_ID)
        .map_err(|e| anyhow!("create_with_seed: {e}"))?;
    info!("anchor idl account = {idl_account}");

    let acct = rpc
        .get_account(&idl_account)
        .await
        .context("fetch idl account")?;
    info!("idl account size = {} bytes, owner = {}", acct.data.len(), acct.owner);

    // Layout: 8 disc + 32 authority + 4 data_len(LE) + zlib-deflated IDL JSON
    if acct.data.len() < 44 {
        return Err(anyhow!("idl account too small: {} bytes", acct.data.len()));
    }
    let data_len = u32::from_le_bytes(acct.data[40..44].try_into().unwrap()) as usize;
    info!("compressed idl payload = {} bytes", data_len);
    let payload = &acct.data[44..44 + data_len];

    let mut decoder = flate2::read::ZlibDecoder::new(payload);
    let mut json_bytes = Vec::with_capacity(data_len * 4);
    decoder
        .read_to_end(&mut json_bytes)
        .context("zlib decompress idl")?;
    info!("decompressed idl = {} bytes", json_bytes.len());

    std::fs::write("/tmp/drift_onchain.json", &json_bytes)?;
    info!("wrote /tmp/drift_onchain.json");

    // Quick check: locate liquidatePerp ix and print its on-chain discriminator
    // (computed by sha256("global:<name_snake_case>") per Anchor convention).
    let s = std::str::from_utf8(&json_bytes).unwrap_or("");
    if let Some(idx) = s.find(r#""name": "liquidatePerp""#).or_else(|| s.find(r#""name":"liquidatePerp""#)) {
        info!("on-chain idl contains liquidatePerp at offset {idx}");
        let snippet_end = (idx + 600).min(s.len());
        info!("snippet: {}", &s[idx..snippet_end]);
    } else {
        info!("on-chain idl does NOT contain `liquidatePerp` — search for similar names…");
        for name in ["liquidate", "Liquidate"] {
            if let Some(i) = s.find(name) {
                info!("found `{}` at offset {}: {}", name, i, &s[i..(i + 80).min(s.len())]);
            }
        }
    }

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

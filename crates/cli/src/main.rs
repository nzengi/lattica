//! lattica — demo CLI.
//!
//! Subcommands:
//!   hash-account <pubkey>            Pull mainnet account via Helius JSON-RPC,
//!                                    compute LtHash, print 32-byte checksum + first limbs.
//!   verify-shred <shred.hex> <pk>    Parse a shred (hex file) and verify against a leader pubkey (base58).
//!   slot                             Print current mainnet slot.
//!
//! Env: HELIUS_RPC_URL  (or pass --url <…>)

use base64::Engine;
use ed25519_dalek::SigningKey;
use lattica_attest::{AccountTransition, Attestation, verify_slot_delta, VerifyError};
use lattica_listener::{FecAssembler, FecEvent, das_confidence};
use lattica_lthash::{AccountForHash, LtHash, SlotDelta, hash_account};
use lattica_shred::{
    fec_set::{FecSetParams, build_fec_set},
    verify_shred,
};
use serde_json::json;
use std::{env, fs, process::ExitCode};

fn env_url() -> String {
    if let Ok(v) = env::var("HELIUS_RPC_URL") {
        return v;
    }
    // Fallback: read from .env in cwd
    if let Ok(contents) = fs::read_to_string(".env").or_else(|_| fs::read_to_string("../.env")) {
        for line in contents.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("HELIUS_RPC_URL=") {
                return rest.trim().to_string();
            }
        }
    }
    eprintln!("error: HELIUS_RPC_URL not set (env or .env file)");
    std::process::exit(2);
}

fn rpc(url: &str, method: &str, params: serde_json::Value) -> serde_json::Value {
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    });
    let resp: serde_json::Value = ureq::post(url)
        .set("Content-Type", "application/json")
        .send_json(body)
        .expect("rpc transport")
        .into_json()
        .expect("rpc parse");
    if let Some(err) = resp.get("error") {
        eprintln!("rpc error: {err}");
        std::process::exit(3);
    }
    resp["result"].clone()
}

fn pubkey_from_b58(s: &str) -> [u8; 32] {
    let v = bs58::decode(s).into_vec().expect("invalid base58");
    assert_eq!(v.len(), 32, "pubkey must be 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

fn cmd_slot() -> ExitCode {
    let url = env_url();
    let v = rpc(&url, "getSlot", json!([]));
    println!("mainnet slot: {}", v);
    ExitCode::SUCCESS
}

fn cmd_leaders(start_str: &str, count_str: &str) -> ExitCode {
    let url = env_url();
    let start: u64 = match start_str.parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("invalid start slot: {e}");
            return ExitCode::FAILURE;
        }
    };
    let count: u64 = match count_str.parse() {
        Ok(v) if (1..=5000).contains(&v) => v,
        _ => {
            eprintln!("count must be 1..=5000");
            return ExitCode::FAILURE;
        }
    };
    let v = rpc(&url, "getSlotLeaders", json!([start, count]));
    let arr = v.as_array().expect("result not array");
    let mut prev: Option<&str> = None;
    let mut run_start = start;
    for (i, leader) in arr.iter().enumerate() {
        let s = leader.as_str().unwrap();
        if Some(s) != prev {
            if let Some(p) = prev {
                println!("  slot {}..{} → {}", run_start, start + i as u64 - 1, p);
            }
            prev = Some(s);
            run_start = start + i as u64;
        }
    }
    if let Some(p) = prev {
        println!("  slot {}..{} → {}", run_start, start + arr.len() as u64 - 1, p);
    }
    ExitCode::SUCCESS
}

/// Snapshot of a Solana account at the slot the RPC server returned it for.
struct AccountSnapshot {
    slot: u64,
    lamports: u64,
    data: Vec<u8>,
    executable: bool,
    owner: [u8; 32],
    pubkey: [u8; 32],
}

impl AccountSnapshot {
    fn as_for_hash(&self) -> AccountForHash<'_> {
        AccountForHash {
            lamports: self.lamports,
            data: &self.data,
            executable: self.executable,
            owner: self.owner,
            pubkey: self.pubkey,
        }
    }
}

/// Fetch a single account via Helius `getAccountInfo` with `commitment=confirmed`
/// and return its state PLUS the RPC's reported context slot. Returns Err on
/// missing account.
fn fetch_snapshot(url: &str, pubkey_str: &str) -> Result<AccountSnapshot, String> {
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "getAccountInfo",
        "params": [pubkey_str, { "encoding": "base64", "commitment": "confirmed" }],
    });
    let resp: serde_json::Value = ureq::post(url)
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(|e| format!("rpc transport: {e}"))?
        .into_json()
        .map_err(|e| format!("rpc parse: {e}"))?;
    if let Some(err) = resp.get("error") {
        return Err(format!("rpc error: {err}"));
    }
    let result = &resp["result"];
    let slot = result["context"]["slot"].as_u64().ok_or("missing context.slot")?;
    let value = &result["value"];
    if value.is_null() {
        return Err(format!("account not found: {pubkey_str}"));
    }
    let lamports = value["lamports"].as_u64().ok_or("missing lamports")?;
    let owner_b58 = value["owner"].as_str().ok_or("missing owner")?;
    let executable = value["executable"].as_bool().ok_or("missing executable")?;
    let data_arr = value["data"].as_array().ok_or("data not array")?;
    let data_b64 = data_arr[0].as_str().ok_or("data[0] not str")?;
    let data = base64::engine::general_purpose::STANDARD
        .decode(data_b64)
        .map_err(|e| format!("data base64: {e}"))?;
    Ok(AccountSnapshot {
        slot,
        lamports,
        data,
        executable,
        owner: pubkey_from_b58(owner_b58),
        pubkey: pubkey_from_b58(pubkey_str),
    })
}

fn fetch_current_slot(url: &str) -> Result<u64, String> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "getSlot",
        "params": [{"commitment": "confirmed"}]});
    let resp: serde_json::Value = ureq::post(url)
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(|e| format!("rpc: {e}"))?
        .into_json()
        .map_err(|e| format!("rpc: {e}"))?;
    resp["result"].as_u64().ok_or_else(|| "missing slot".to_string())
}

fn cmd_hash_account(pubkey_str: &str) -> ExitCode {
    let url = env_url();
    let result = rpc(
        &url,
        "getAccountInfo",
        json!([pubkey_str, { "encoding": "base64", "commitment": "finalized" }]),
    );
    let value = &result["value"];
    if value.is_null() {
        eprintln!("account not found: {pubkey_str}");
        return ExitCode::FAILURE;
    }
    let lamports = value["lamports"].as_u64().expect("lamports");
    let owner_b58 = value["owner"].as_str().expect("owner");
    let executable = value["executable"].as_bool().expect("executable");
    let data_arr = value["data"].as_array().expect("data");
    let data_b64 = data_arr[0].as_str().expect("data[0]");
    let data = base64::engine::general_purpose::STANDARD
        .decode(data_b64)
        .expect("data base64");

    let owner = pubkey_from_b58(owner_b58);
    let pubkey = pubkey_from_b58(pubkey_str);

    let acct = AccountForHash {
        lamports,
        data: &data,
        executable,
        owner,
        pubkey,
    };

    let h: LtHash = hash_account(&acct);
    let checksum = h.checksum();

    println!("pubkey:       {pubkey_str}");
    println!("owner:        {owner_b58}");
    println!("lamports:     {lamports}");
    println!("executable:   {executable}");
    println!("data size:    {} bytes", data.len());
    println!("lthash[0..8]: {:?}", &h.0[..8]);
    println!("checksum:     {}", hex::encode(checksum));

    // Demo: homomorphism — adding then removing this account yields identity.
    let mut h2 = LtHash::identity();
    h2.mix_in(&h);
    h2.mix_out(&h);
    assert!(h2.is_identity(), "lthash homomorphism broke");
    println!("homomorphism: OK (mix_in(a) + mix_out(a) == identity)");

    ExitCode::SUCCESS
}

fn cmd_verify_shred(shred_path: &str, leader_b58: &str) -> ExitCode {
    let bytes = fs::read(shred_path).expect("read shred file");
    // Tolerate both raw bytes and hex-encoded files.
    let raw: Vec<u8> = if bytes.iter().all(|b| b.is_ascii_hexdigit() || b.is_ascii_whitespace()) {
        let cleaned: String = bytes.iter().filter(|b| !b.is_ascii_whitespace()).map(|b| *b as char).collect();
        hex::decode(cleaned).expect("hex decode")
    } else {
        bytes
    };
    let leader = pubkey_from_b58(leader_b58);
    match verify_shred(&raw, &leader) {
        Ok(v) => {
            println!("slot:          {}", v.slot);
            println!("fec_set_index: {}", v.fec_set_index);
            println!("shred index:   {}", v.index);
            println!("erasure idx:   {}", v.erasure_shard_index);
            println!("kind:          {:?}", v.kind);
            println!("merkle_root:   {}", hex::encode(v.merkle_root));
            if let Some(cr) = v.chained_root {
                println!("chained_root:  {}", hex::encode(cr));
            }
            println!("sig:           OK");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("verify failed: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Generate a fresh ed25519 keypair, save in Solana's standard 64-byte JSON-array
/// format (32-byte seed concatenated with 32-byte public key), print base58 pubkey.
fn cmd_keygen(out_path: Option<&str>) -> ExitCode {
    let mut seed = [0u8; 32];
    if let Err(e) = getrandom::getrandom(&mut seed) {
        eprintln!("getrandom failed: {e}");
        return ExitCode::FAILURE;
    }
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let pubkey = signing.verifying_key().to_bytes();

    // Solana keypair file: [seed_byte_0..seed_byte_31, pub_byte_0..pub_byte_31]
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(&seed);
    combined.extend_from_slice(&pubkey);
    let json = serde_json::to_string(&combined).unwrap();

    // Default path: ~/.config/solana/lattica.json
    let default_path = match env::var("HOME") {
        Ok(home) => format!("{home}/.config/solana/lattica.json"),
        Err(_) => "lattica.json".to_string(),
    };
    let path = out_path.unwrap_or(&default_path);

    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Err(e) = fs::write(path, &json) {
        eprintln!("write failed at {path}: {e}");
        return ExitCode::FAILURE;
    }
    // chmod 600 so it isn't world-readable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }

    println!("pubkey:  {}", bs58::encode(&pubkey).into_string());
    println!("path:    {path}");
    println!("note:    file is mode 0600; do not share.");
    println!();
    println!("use this pubkey for:");
    println!("  - Jito ShredStream sign-up (https://docs.jito.wtf/lowlatencytxnfeed/)");
    println!("  - mainnet auth challenge signing (no SOL balance required for ShredStream)");
    ExitCode::SUCCESS
}

fn fmt_prob(p: f64) -> String {
    if p == 0.0 { "0".to_string() }
    else if p >= 1e-3 { format!("{:.6}", p) }
    else { format!("{:.3e}", p) }
}

fn cmd_das_demo(n_str: &str) -> ExitCode {
    let n: usize = match n_str.parse() {
        Ok(v) if v <= 64 => v,
        _ => {
            eprintln!("n must be 0..=64");
            return ExitCode::FAILURE;
        }
    };
    let signing = SigningKey::from_bytes(&[0x4c; 32]);
    let leader_pk = signing.verifying_key().to_bytes();
    let payload: Vec<u8> = (0..4_000u32).flat_map(|i| i.to_le_bytes()).collect();
    let fec = build_fec_set(
        &payload,
        FecSetParams {
            slot: 999_999,
            fec_set_index: 0,
            version: 1,
            parent_offset: 1,
            flags: 0b0100_0000,
            chained_root: [0u8; 32],
            signing_key: &signing,
        },
    )
    .expect("build_fec_set");

    let leader_b58 = bs58::encode(&leader_pk).into_string();
    println!("constructed FEC: 64 shreds, payload={}B, leader={}", payload.len(), leader_b58);
    println!("merkle_root: {}", hex::encode(fec.merkle_root));
    println!();
    println!("simulating delivery of {n} of 64 shreds (withholding = {})...", 64 - n);
    println!("a priori DAS confidence at n={n} (random multi-listener sampling): {}",
        fmt_prob(das_confidence(n)));
    println!();

    let mut asm = FecAssembler::new(leader_pk);
    let mut reconstructed = false;
    for i in 0..n {
        for ev in asm.ingest(&fec.shreds[i]) {
            match ev {
                FecEvent::Started { key, .. } => {
                    println!("  [start ] slot={} fec_set={}", key.slot, key.fec_set_index);
                }
                FecEvent::ShredAccepted { shreds_present, erasure_shard_index, .. } => {
                    println!("  [shred ] have={}/64 erasure_idx={}", shreds_present, erasure_shard_index);
                }
                FecEvent::Reconstructed { merkle_root, das_confidence, .. } => {
                    reconstructed = true;
                    println!(
                        "  [DONE  ] reconstructed; root={} das_conf={:.6}",
                        hex::encode(merkle_root), das_confidence
                    );
                }
                FecEvent::SlotFinalized { .. } => {
                    // Single-FEC demo without LAST_IN_SLOT flag — won't fire here.
                }
                FecEvent::Rejected { reason } => {
                    println!("  [reject] {reason}");
                }
            }
        }
    }
    println!();
    if reconstructed {
        println!("verdict: block recovered with cryptographic certainty.");
    } else {
        println!(
            "verdict: NOT recovered. P[adversary undetected | random sampling] = {}",
            fmt_prob(1.0 - das_confidence(n))
        );
    }
    ExitCode::SUCCESS
}

fn cmd_slot_demo() -> ExitCode {
    // Builds a synthetic 2-FEC-set slot and walks it through the assembler so
    // you can see the SlotFinalized event with aggregate slot_root.
    //
    // Slot 0xdead0042 carries 2 FEC sets:
    //   set @ fec_set_index=0  — 32 data + 32 coding shreds, no flags
    //   set @ fec_set_index=32 — 32 data + 32 coding shreds, LAST_IN_SLOT on the data shreds
    //
    // We deliver all 64 shreds of each set and expect exactly one SlotFinalized.
    use lattica_shred::{SHRED_FLAG_DATA_COMPLETE, SHRED_FLAG_LAST_IN_SLOT};
    let signing = SigningKey::from_bytes(&[0x5a; 32]);
    let leader_pk = signing.verifying_key().to_bytes();
    let payload: Vec<u8> = (0..3_000u32).flat_map(|i| i.to_le_bytes()).collect();
    let slot: u64 = 0xdead_0042;

    let mk_set = |idx: u32, last: bool| -> Vec<Vec<u8>> {
        let flags = if last {
            SHRED_FLAG_DATA_COMPLETE | SHRED_FLAG_LAST_IN_SLOT
        } else {
            0
        };
        build_fec_set(
            &payload,
            FecSetParams {
                slot,
                fec_set_index: idx,
                version: 1,
                parent_offset: 1,
                flags,
                chained_root: [0u8; 32],
                signing_key: &signing,
            },
        )
        .expect("build_fec_set")
        .shreds
    };

    let set_a = mk_set(0, false);
    let set_b = mk_set(32, true);
    println!("constructed 2-FEC-set slot {slot}:");
    println!("  set A: fec_set_index=0,  flags=0       (32 + 32 shreds)");
    println!("  set B: fec_set_index=32, flags=0xc0    (DATA_COMPLETE | LAST_IN_SLOT)");
    println!();

    let mut asm = FecAssembler::new(leader_pk);
    let mut finalized_seen = 0usize;
    for (label, set) in [("A", &set_a), ("B", &set_b)] {
        println!("delivering set {label} (32 data shreds)…");
        for raw in set.iter().take(32) {
            for ev in asm.ingest(raw) {
                match ev {
                    FecEvent::Reconstructed { key, das_confidence, .. } => {
                        println!(
                            "  [done  ] fec_set={} reconstructed das_conf={:.6}",
                            key.fec_set_index, das_confidence
                        );
                    }
                    FecEvent::SlotFinalized {
                        slot,
                        fec_roots,
                        slot_root,
                        total_shreds_observed,
                        slot_das_confidence,
                    } => {
                        finalized_seen += 1;
                        println!();
                        println!("[SLOT FINALIZED] slot={slot}");
                        println!("  n_fec_sets         = {}", fec_roots.len());
                        println!("  total_shreds       = {total_shreds_observed}");
                        println!("  slot_das_conf      = {}", fmt_prob(slot_das_confidence));
                        println!("  slot_root          = {}", hex::encode(slot_root));
                        for (i, r) in fec_roots.iter().enumerate() {
                            println!("    fec_roots[{i}]       = {}", hex::encode(r));
                        }
                    }
                    FecEvent::Rejected { reason } => {
                        println!("  [reject] {reason}");
                    }
                    _ => {}
                }
            }
        }
    }

    println!();
    if finalized_seen == 1 {
        println!("verdict: 2-FEC slot finalized into a single 32-byte slot_root.");
        println!("         Phase 3 milestone — multi-FEC + LAST_IN_SLOT detection works.");
        ExitCode::SUCCESS
    } else {
        eprintln!("expected exactly 1 SlotFinalized event, got {finalized_seen}");
        ExitCode::FAILURE
    }
}

fn cmd_verify_slot(mode: &str) -> ExitCode {
    // Two scenarios:
    //   `ok`       — verifier supplies the same accounts the attestation was built from
    //   `tamper`   — verifier flips one byte on one account's "new" state
    //
    // In both cases we build a synthetic 3-account slot, produce an Attestation
    // covering it, then call verify_slot_delta against the chosen scenario.
    let a_old = AccountForHash {
        lamports: 1_000_000, data: b"alice-old", executable: false,
        owner: [1; 32], pubkey: [11; 32],
    };
    let a_new = AccountForHash {
        lamports: 1_000_500, data: b"alice-new", executable: false,
        owner: [1; 32], pubkey: [11; 32],
    };
    let b_old = AccountForHash {
        lamports: 2_000_000, data: b"bob-old", executable: false,
        owner: [2; 32], pubkey: [22; 32],
    };
    let b_new = AccountForHash {
        lamports: 2_000_500, data: b"bob-new", executable: false,
        owner: [2; 32], pubkey: [22; 32],
    };
    let created = AccountForHash {
        lamports: 5_000_000, data: b"newly-created", executable: false,
        owner: [3; 32], pubkey: [33; 32],
    };

    // Build the on-chain "truth": Σ (h(new) − h(old)) over the actual modifications.
    let mut sd = SlotDelta::new();
    sd.mix(Some(&a_old), Some(&a_new));
    sd.mix(Some(&b_old), Some(&b_new));
    sd.mix(None, Some(&created));

    let leader_pk = SigningKey::from_bytes(&[0x21; 32]).verifying_key().to_bytes();
    let attestation = Attestation::from_delta(
        0x1234_5678, // slot
        0,
        leader_pk,
        [0xab; 32],
        [0xcd; 64],
        &sd.delta,
    );

    println!("constructed attestation for slot {} with 3 account transitions:", attestation.slot);
    println!("  - alice    : modified (lamports + data)");
    println!("  - bob      : modified (lamports + data)");
    println!("  - created  : initialized (None → Some)");
    println!("  delta checksum: {}", hex::encode(sd.delta.checksum()));
    println!();

    let transitions: Vec<AccountTransition<'_>> = match mode {
        "ok" => {
            println!("verifier mode: ok  — supplying the *true* transition set");
            vec![
                AccountTransition { old: Some(a_old), new: Some(a_new) },
                AccountTransition { old: Some(b_old), new: Some(b_new) },
                AccountTransition { old: None, new: Some(created) },
            ]
        }
        "tamper" => {
            println!("verifier mode: tamper — flipping bob's new-state data ('bob-new' → 'BOB-new')");
            let b_new_tampered = AccountForHash {
                lamports: 2_000_500, data: b"BOB-new", executable: false,
                owner: [2; 32], pubkey: [22; 32],
            };
            vec![
                AccountTransition { old: Some(a_old), new: Some(a_new) },
                AccountTransition { old: Some(b_old), new: Some(b_new_tampered) },
                AccountTransition { old: None, new: Some(created) },
            ]
        }
        _ => {
            eprintln!("mode must be 'ok' or 'tamper'");
            return ExitCode::FAILURE;
        }
    };
    println!();

    match verify_slot_delta(&attestation, &transitions) {
        Ok(()) => {
            println!("✓ VERIFIED — recomputed Δ matches the attestation.");
            println!("  All claimed transitions are consistent with the slot's published delta.");
            ExitCode::SUCCESS
        }
        Err(VerifyError::DeltaMismatch { attested, recomputed }) => {
            println!("✗ MISMATCH — recomputed Δ diverges from the attestation.");
            println!("  attested   = {}", hex::encode(attested));
            println!("  recomputed = {}", hex::encode(recomputed));
            println!();
            println!("  This is the cryptographic core: a single bit changed in any of");
            println!("  the account state transitions makes the recomputed sum land in a");
            println!("  different point of (Z/2^16)^1024 — collision-resistant under Blake3.");
            // exit nonzero so scripts can detect mismatch
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("verify error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_rpc_attest(pubkey_str: &str, wait_slots_str: &str) -> ExitCode {
    let wait_slots: u64 = match wait_slots_str.parse() {
        Ok(v) if v >= 1 => v,
        _ => {
            eprintln!("wait_slots must be ≥ 1");
            return ExitCode::FAILURE;
        }
    };
    let url = env_url();
    println!("===  LATTICA real-mainnet attestation  ===");
    println!("pubkey      : {pubkey_str}");
    println!("wait slots  : {wait_slots} (~{}s on mainnet at 400ms/slot)", wait_slots * 400 / 1000);
    println!();

    // ── Snapshot 1 ───────────────────────────────────────────────────────────
    println!("[1/4] fetching snapshot at current slot via Helius getAccountInfo…");
    let snap_old = match fetch_snapshot(&url, pubkey_str) {
        Ok(s) => s,
        Err(e) => { eprintln!("fetch failed: {e}"); return ExitCode::FAILURE; }
    };
    let h_old = hash_account(&snap_old.as_for_hash());
    println!("    slot          = {}", snap_old.slot);
    println!("    lamports      = {}", snap_old.lamports);
    println!("    data size     = {} bytes", snap_old.data.len());
    println!("    lthash chksum = {}", hex::encode(h_old.checksum()));
    println!();

    // ── Wait for `wait_slots` to elapse ──────────────────────────────────────
    println!("[2/4] polling getSlot until current ≥ {} + {}…", snap_old.slot, wait_slots);
    let target_slot = snap_old.slot + wait_slots;
    loop {
        match fetch_current_slot(&url) {
            Ok(s) if s >= target_slot => {
                println!("    reached slot {s}");
                break;
            }
            Ok(s) => {
                print!("\r    at slot {s} (need {target_slot}, +{} more)…    ",
                    target_slot.saturating_sub(s));
                use std::io::Write;
                let _ = std::io::stdout().flush();
                std::thread::sleep(std::time::Duration::from_millis(800));
            }
            Err(e) => {
                eprintln!("\nslot poll failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    println!();

    // ── Snapshot 2 ───────────────────────────────────────────────────────────
    println!("[3/4] fetching snapshot at new slot…");
    let snap_new = match fetch_snapshot(&url, pubkey_str) {
        Ok(s) => s,
        Err(e) => { eprintln!("fetch failed: {e}"); return ExitCode::FAILURE; }
    };
    let h_new = hash_account(&snap_new.as_for_hash());
    println!("    slot          = {}", snap_new.slot);
    println!("    lamports      = {}", snap_new.lamports);
    println!("    data size     = {} bytes", snap_new.data.len());
    println!("    lthash chksum = {}", hex::encode(h_new.checksum()));
    println!();

    // ── Build the real Δ_lthash and an Attestation ───────────────────────────
    let mut sd = SlotDelta::new();
    sd.mix(Some(&snap_old.as_for_hash()), Some(&snap_new.as_for_hash()));
    let changed = !sd.delta.is_identity();
    println!("[4/4] computing Δ = h(new) − h(old)…");
    println!("    Δ checksum    = {}", hex::encode(sd.delta.checksum()));
    println!("    account changed between slots: {changed}");
    println!();

    // The attestation. In production the leader_sig + fec_merkle_root come
    // from a reassembled FEC set; here we synthesize them since we're
    // asserting only the LtHash arm of the protocol.
    let leader_pk = SigningKey::from_bytes(&[0; 32]).verifying_key().to_bytes();
    let attestation = Attestation::from_delta(
        snap_new.slot,
        0,
        leader_pk,
        [0; 32],
        [0; 64],
        &sd.delta,
    );

    // ── verify_slot_delta against the real transition ────────────────────────
    println!("=== verifier (ok mode) ===");
    let txs = vec![AccountTransition {
        old: Some(snap_old.as_for_hash()),
        new: Some(snap_new.as_for_hash()),
    }];
    match verify_slot_delta(&attestation, &txs) {
        Ok(()) => println!("✓ VERIFIED — recomputed Δ matches the attestation."),
        Err(e) => {
            eprintln!("UNEXPECTED MISMATCH on truthful run: {e}");
            return ExitCode::FAILURE;
        }
    }
    println!();

    // Tamper case: flip the first byte of new-state data.
    if snap_new.data.is_empty() {
        println!("(account has no data; skipping tamper case)");
        return ExitCode::SUCCESS;
    }
    let mut tampered_data = snap_new.data.clone();
    tampered_data[0] ^= 0x01;
    let tampered = AccountForHash {
        lamports: snap_new.lamports,
        data: &tampered_data,
        executable: snap_new.executable,
        owner: snap_new.owner,
        pubkey: snap_new.pubkey,
    };
    println!("=== verifier (tamper mode — flipped data[0]) ===");
    let txs_tamper = vec![AccountTransition {
        old: Some(snap_old.as_for_hash()),
        new: Some(tampered),
    }];
    match verify_slot_delta(&attestation, &txs_tamper) {
        Ok(()) => {
            println!("UNEXPECTED ok on tampered run — verifier broken?");
            ExitCode::FAILURE
        }
        Err(VerifyError::DeltaMismatch { attested, recomputed }) => {
            println!("✓ MISMATCH caught:");
            println!("    attested   = {}", hex::encode(attested));
            println!("    recomputed = {}", hex::encode(recomputed));
            println!();
            println!("✓ end-to-end LATTICA pipeline working on REAL mainnet data:");
            println!("  RPC fetch → LtHash on real bytes → attestation → verifier ✓/✗");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("unexpected error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage:
  lattica slot
  lattica hash-account <pubkey-base58>
  lattica verify-shred <path-to-shred-bytes-or-hex> <leader-pubkey-base58>
  lattica das-demo <n>          # construct synthetic FEC, deliver n of 64 shreds, show DAS outcome
  lattica slot-demo             # build 2 FEC sets, finalize the slot, print slot_root (Phase 3.1)
  lattica verify-slot <mode>    # all-or-nothing LtHash slot verifier; mode = ok | tamper  (Phase 3.3)
  lattica rpc-attest <pubkey> <wait-slots>
                                # fetch a real mainnet account at slot S0 and S0+wait_slots,
                                # compute the real Δ_lthash, run verify_slot_delta against it.
                                # Demonstrates the entire LATTICA pipeline on REAL mainnet data.
  lattica keygen [path]         # generate Solana-format keypair (default ~/.config/solana/lattica.json)
  lattica leaders <start> <n>   # print mainnet leaders for n consecutive slots starting at <start>"
    );
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return usage();
    }
    match args[1].as_str() {
        "slot" => cmd_slot(),
        "hash-account" if args.len() == 3 => cmd_hash_account(&args[2]),
        "verify-shred" if args.len() == 4 => cmd_verify_shred(&args[2], &args[3]),
        "das-demo" if args.len() == 3 => cmd_das_demo(&args[2]),
        "slot-demo" => cmd_slot_demo(),
        "verify-slot" if args.len() == 3 => cmd_verify_slot(&args[2]),
        "rpc-attest" if args.len() == 4 => cmd_rpc_attest(&args[2], &args[3]),
        "keygen" => cmd_keygen(args.get(2).map(String::as_str)),
        "leaders" if args.len() == 4 => cmd_leaders(&args[2], &args[3]),
        _ => usage(),
    }
}

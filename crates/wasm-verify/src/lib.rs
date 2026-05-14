//! lattica-wasm-verify — browser/Node bindings for the all-or-nothing slot
//! verifier. Compiles to a ~50 KB WASM module that takes a serialized
//! `Attestation` and a serialized list of `(old, new)` account state
//! transitions, returns `Ok` or a structured mismatch error.
//!
//! Build via `wasm-pack build crates/wasm-verify --target web` (or `--target
//! nodejs`). The resulting `pkg/` directory exposes `verifySlotDelta(att, txs)`.
//!
//! Wire types (JS-side):
//!
//! ```ts
//! type Account = {
//!   lamports: number | bigint;
//!   data: Uint8Array;
//!   executable: boolean;
//!   owner: Uint8Array;  // 32 bytes
//!   pubkey: Uint8Array; // 32 bytes
//! };
//! type Transition = { old: Account | null; new: Account | null };
//! type Attestation = {
//!   slot: bigint;
//!   fec_set_index: number;
//!   leader_pubkey: Uint8Array;   // 32
//!   fec_merkle_root: Uint8Array; // 32
//!   leader_sig: Uint8Array;      // 64
//!   delta_lthash: Uint16Array;   // 1024
//! };
//! ```

use lattica_attest::{verify_slot_delta, AccountTransition, Attestation, VerifyError};
use lattica_lthash::AccountForHash;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

#[derive(Deserialize)]
struct JsAccount {
    #[serde(with = "lamports_serde")]
    lamports: u64,
    data: Vec<u8>,
    executable: bool,
    owner: Vec<u8>,
    pubkey: Vec<u8>,
}

#[derive(Deserialize)]
struct JsTransition {
    #[serde(rename = "old")]
    old: Option<JsAccount>,
    #[serde(rename = "new")]
    new_: Option<JsAccount>,
}

// JS Number can't safely represent u64; accept either Number (for small
// fixtures) or BigInt (for production lamport amounts). serde-wasm-bindgen
// surfaces both as serde_json::Value-ish types, so manual coercion.
mod lamports_serde {
    use serde::{Deserialize, Deserializer};
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        // Accept either a numeric literal or a string-encoded bigint.
        let v = serde_json::Value::deserialize(d)?;
        match v {
            serde_json::Value::Number(n) => n.as_u64().ok_or_else(|| {
                serde::de::Error::custom("lamports number out of u64 range")
            }),
            serde_json::Value::String(s) => s
                .parse::<u64>()
                .map_err(|_| serde::de::Error::custom("lamports string not u64")),
            _ => Err(serde::de::Error::custom("lamports must be number or string")),
        }
    }
}

fn account_for_hash(a: &JsAccount) -> Result<AccountForHash<'_>, String> {
    if a.owner.len() != 32 {
        return Err(format!("owner must be 32 bytes, got {}", a.owner.len()));
    }
    if a.pubkey.len() != 32 {
        return Err(format!("pubkey must be 32 bytes, got {}", a.pubkey.len()));
    }
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&a.owner);
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&a.pubkey);
    Ok(AccountForHash {
        lamports: a.lamports,
        data: &a.data,
        executable: a.executable,
        owner,
        pubkey,
    })
}

/// Verify an attestation against a claimed transition set.
///
/// Returns:
///   * `null` on success.
///   * A string on failure (`"mismatch: <attested_hex> != <recomputed_hex>"`,
///     `"malformed_delta"`, `"empty_transition"`, or a parsing error).
///
/// Designed to be the *only* public API surface. Browser code that receives
/// an attestation over the wire calls this with the rebuilt transition set.
#[wasm_bindgen(js_name = verifySlotDelta)]
pub fn verify_slot_delta_js(
    attestation: JsValue,
    transitions: JsValue,
) -> Result<JsValue, JsValue> {
    let attestation: Attestation = serde_wasm_bindgen::from_value(attestation)
        .map_err(|e| JsValue::from_str(&format!("attestation parse: {e}")))?;
    let js_transitions: Vec<JsTransition> = serde_wasm_bindgen::from_value(transitions)
        .map_err(|e| JsValue::from_str(&format!("transitions parse: {e}")))?;

    // Convert JsTransition → AccountTransition while keeping the JsAccount
    // backing storage alive for the duration of the verify call.
    let backing: Vec<(Option<JsAccount>, Option<JsAccount>)> = js_transitions
        .into_iter()
        .map(|t| (t.old, t.new_))
        .collect();

    let mut transitions = Vec::with_capacity(backing.len());
    for (old, new) in backing.iter() {
        let old_h = match old {
            Some(a) => Some(account_for_hash(a).map_err(|e| JsValue::from_str(&e))?),
            None => None,
        };
        let new_h = match new {
            Some(a) => Some(account_for_hash(a).map_err(|e| JsValue::from_str(&e))?),
            None => None,
        };
        transitions.push(AccountTransition { old: old_h, new: new_h });
    }

    match verify_slot_delta(&attestation, &transitions) {
        Ok(()) => Ok(JsValue::NULL),
        Err(VerifyError::EmptyTransition) => Err(JsValue::from_str("empty_transition")),
        Err(VerifyError::MalformedDelta) => Err(JsValue::from_str("malformed_delta")),
        Err(VerifyError::DeltaMismatch { attested, recomputed }) => Err(JsValue::from_str(
            &format!("mismatch: {} != {}", hex::encode(attested), hex::encode(recomputed)),
        )),
    }
}

/// Tiny smoke export so the wasm pkg ships with at least one verifiable
/// constant — useful for "did wasm load correctly" health checks in JS.
#[wasm_bindgen(js_name = lthashLimbCount)]
pub fn lthash_limb_count() -> u32 {
    lattica_lthash::N_LIMBS as u32
}

// Keep `backing` referenced in transitions; clippy would otherwise drop it.
#[allow(dead_code)]
fn _ensure_backing_lifetime() {}

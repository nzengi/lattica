//! Leader resolver — given a slot, returns the leader's 32-byte pubkey.
//!
//! `StaticLeader` is for tests / single-leader fixtures.
//! `HeliusLeaderResolver` queries `getSlotLeaders` against any Solana JSON-RPC endpoint
//! (Helius mainnet by default) and caches per-slot results.

use serde_json::{Value, json};
use std::sync::{Mutex, RwLock};
use std::collections::HashMap;

/// Trait: lookup the 32-byte leader pubkey for a given slot. None = unknown.
pub trait LeaderResolver: Send + Sync {
    fn leader_for_slot(&self, slot: u64) -> Option<[u8; 32]>;
}

/// Static single-leader resolver. Useful for synthetic FEC tests where every
/// shred is signed by the same key.
pub struct StaticLeader(pub [u8; 32]);

impl LeaderResolver for StaticLeader {
    fn leader_for_slot(&self, _slot: u64) -> Option<[u8; 32]> {
        Some(self.0)
    }
}

/// Helius-backed (or any JSON-RPC) resolver. Caches leaders in fixed-size windows.
/// On miss, fetches a batch of `BATCH_SIZE` consecutive leaders.
pub struct HeliusLeaderResolver {
    url: String,
    /// slot -> leader pubkey bytes
    cache: RwLock<HashMap<u64, [u8; 32]>>,
    /// guards in-flight batch fetches to avoid stampedes
    inflight: Mutex<()>,
}

impl HeliusLeaderResolver {
    pub const BATCH_SIZE: u64 = 1000;
    pub const MAX_CACHE_ENTRIES: usize = 100_000;

    pub fn new(url: String) -> Self {
        Self {
            url,
            cache: RwLock::new(HashMap::new()),
            inflight: Mutex::new(()),
        }
    }

    fn fetch_window(&self, start: u64, count: u64) -> Result<Vec<[u8; 32]>, String> {
        let body = json!({
            "jsonrpc": "2.0", "id": 1,
            "method": "getSlotLeaders",
            "params": [start, count],
        });
        let resp: Value = ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .send_json(body)
            .map_err(|e| format!("rpc transport: {e}"))?
            .into_json()
            .map_err(|e| format!("rpc parse: {e}"))?;
        if let Some(err) = resp.get("error") {
            return Err(format!("rpc error: {err}"));
        }
        let arr = resp["result"]
            .as_array()
            .ok_or_else(|| "result is not array".to_string())?;
        let mut out = Vec::with_capacity(arr.len());
        for v in arr {
            let s = v.as_str().ok_or_else(|| "leader not string".to_string())?;
            let bytes = bs58::decode(s).into_vec().map_err(|e| format!("base58: {e}"))?;
            if bytes.len() != 32 {
                return Err("leader pubkey not 32 bytes".to_string());
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&bytes);
            out.push(pk);
        }
        Ok(out)
    }

    fn fill_window(&self, start: u64) -> Result<(), String> {
        let leaders = self.fetch_window(start, Self::BATCH_SIZE)?;
        let mut cache = self.cache.write().map_err(|_| "cache poisoned".to_string())?;
        for (i, pk) in leaders.into_iter().enumerate() {
            cache.insert(start + i as u64, pk);
        }
        // Coarse cache eviction: drop oldest if too big.
        if cache.len() > Self::MAX_CACHE_ENTRIES {
            let drop_n = cache.len() - Self::MAX_CACHE_ENTRIES;
            let mut keys: Vec<u64> = cache.keys().copied().collect();
            keys.sort();
            for k in keys.into_iter().take(drop_n) {
                cache.remove(&k);
            }
        }
        Ok(())
    }
}

impl LeaderResolver for HeliusLeaderResolver {
    fn leader_for_slot(&self, slot: u64) -> Option<[u8; 32]> {
        if let Some(pk) = self.cache.read().ok().and_then(|c| c.get(&slot).copied()) {
            return Some(pk);
        }
        // Miss — fetch a window starting at this slot.
        let _g = self.inflight.lock().ok()?;
        // Re-check after taking the lock; another thread may have filled it.
        if let Some(pk) = self.cache.read().ok().and_then(|c| c.get(&slot).copied()) {
            return Some(pk);
        }
        if let Err(e) = self.fill_window(slot) {
            eprintln!("[leader] fill_window({slot}) failed: {e}");
            return None;
        }
        self.cache.read().ok().and_then(|c| c.get(&slot).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_leader_resolves() {
        let pk = [0x11u8; 32];
        let r = StaticLeader(pk);
        assert_eq!(r.leader_for_slot(0), Some(pk));
        assert_eq!(r.leader_for_slot(u64::MAX), Some(pk));
    }
}

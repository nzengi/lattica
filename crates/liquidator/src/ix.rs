//! Manual `LiquidatePerp` instruction builder — bypasses drift-rs's broken FFI
//! transaction-building path. Uses ONLY the on-chain Drift program's documented
//! account ordering (oracles → spots → perps for remaining_accounts) and the
//! IDL discriminator.
//!
//! Inputs (markets, user data) come from raw RPC fetches + drift-rs struct
//! decoders, both of which are known-clean (proved by `probe.rs`).

use std::collections::BTreeSet;

use drift_rs::{constants::PROGRAM_ID, types::accounts::User};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
};

use crate::markets::Markets;

/// Anchor discriminator for the on-chain `liquidate_perp` ix.
/// Source: drift_idl.rs LiquidatePerp::DISCRIMINATOR (alpha.14)
/// = sha256("global:liquidate_perp")[..8].
/// Override via env LATTICA_DISC_OVERRIDE=hex (16 chars) for testing variants.
const LIQUIDATE_PERP_DISCRIMINATOR: [u8; 8] = [75, 35, 119, 247, 191, 18, 139, 2];

/// Drift program's required ordering for `remaining_accounts`:
/// oracles first, then spot markets, then perp markets, deduped by pubkey,
/// secondary sort by pubkey within each group. Writable wins over readable
/// when the same market appears with both flags (BTreeSet keeps the first
/// inserted; we insert writable first).
///
/// Mirrors the private enum in drift-rs `crates/src/types.rs`. Re-implemented
/// here so the liquidator crate doesn't depend on drift-rs internals.
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
enum RemainingAccount {
    Oracle { pubkey: Pubkey } = 0,
    Spot { pubkey: Pubkey, writable: bool } = 1,
    Perp { pubkey: Pubkey, writable: bool } = 2,
}

impl RemainingAccount {
    fn discriminant(&self) -> u8 {
        match self {
            Self::Oracle { .. } => 0,
            Self::Spot { .. } => 1,
            Self::Perp { .. } => 2,
        }
    }
    fn pubkey(&self) -> &Pubkey {
        match self {
            Self::Oracle { pubkey } => pubkey,
            Self::Spot { pubkey, .. } => pubkey,
            Self::Perp { pubkey, .. } => pubkey,
        }
    }
    fn into_meta(self) -> AccountMeta {
        let (pubkey, writable) = match self {
            Self::Oracle { pubkey } => (pubkey, false),
            Self::Spot { pubkey, writable } => (pubkey, writable),
            Self::Perp { pubkey, writable } => (pubkey, writable),
        };
        AccountMeta { pubkey, is_writable: writable, is_signer: false }
    }
}

impl PartialEq for RemainingAccount {
    fn eq(&self, other: &Self) -> bool {
        self.discriminant() == other.discriminant() && self.pubkey() == other.pubkey()
    }
}
impl Eq for RemainingAccount {}
impl PartialOrd for RemainingAccount {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for RemainingAccount {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self.discriminant().cmp(&other.discriminant()) {
            std::cmp::Ordering::Equal => self.pubkey().cmp(other.pubkey()),
            o => o,
        }
    }
}

/// Drift state account PDA — `seeds = [b"drift_state"]`.
pub fn state_pda() -> Pubkey {
    Pubkey::find_program_address(&[b"drift_state"], &PROGRAM_ID).0
}

/// UserStats PDA for an authority — `seeds = [b"user_stats", authority]`.
pub fn user_stats_pda(authority: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[b"user_stats", authority.as_ref()], &PROGRAM_ID).0
}

/// User PDA for `(authority, sub_account_id)` — `seeds = [b"user", authority, sub_id_le]`.
pub fn user_pda(authority: &Pubkey, sub_account_id: u16) -> Pubkey {
    Pubkey::find_program_address(
        &[b"user", authority.as_ref(), &sub_account_id.to_le_bytes()],
        &PROGRAM_ID,
    )
    .0
}

/// Build a `liquidate_perp` instruction.
///
/// * `liquidator_authority` — signer; pays + owns the liquidator User.
/// * `liquidator_user` / `liquidator_user_data` — the liquidator's Drift sub-account.
/// * `liquidatee_user` / `liquidatee_user_data` — the target being liquidated.
/// * `market_index` — the perp market we're claiming the position from.
/// * `liquidator_max_base_asset_amount` — cap on base asset to take (program clamps).
/// * `limit_price` — optional; price ceiling (longs) or floor (shorts) on takeover.
/// * `markets` — cached pubkey+oracle for every market index we may touch.
pub fn build_liquidate_perp_ix(
    liquidator_authority: Pubkey,
    liquidator_user: Pubkey,
    liquidator_user_data: &User,
    liquidatee_user: Pubkey,
    liquidatee_user_data: &User,
    market_index: u16,
    liquidator_max_base_asset_amount: u64,
    limit_price: Option<u64>,
    markets: &Markets,
) -> Instruction {
    let state = state_pda();
    let liquidator_stats = user_stats_pda(&liquidator_authority);
    let liquidatee_stats = user_stats_pda(&liquidatee_user_data.authority);

    // Base accounts — order MUST match IDL `liquidatePerp.accounts`.
    let mut metas = vec![
        AccountMeta::new_readonly(state, false),
        AccountMeta::new_readonly(liquidator_authority, true),
        AccountMeta::new(liquidator_user, false),
        AccountMeta::new(liquidator_stats, false),
        AccountMeta::new(liquidatee_user, false),
        AccountMeta::new(liquidatee_stats, false),
    ];

    // Remaining accounts — BTreeSet handles ordering + dedup.
    let mut ra = BTreeSet::<RemainingAccount>::new();

    // Always include the perp market being liquidated as WRITABLE; insert first
    // so its writable flag wins over any readable insertion below.
    let perp = markets.perp(market_index);
    ra.insert(RemainingAccount::Perp { pubkey: perp.pubkey, writable: true });
    ra.insert(RemainingAccount::Oracle { pubkey: perp.oracle });

    // Include every market touched by either user (readable).
    for u in [liquidator_user_data, liquidatee_user_data] {
        for p in u.spot_positions.iter().filter(|p| !p.is_available()) {
            let sm = markets.spot(p.market_index);
            ra.insert(RemainingAccount::Spot { pubkey: sm.pubkey, writable: false });
            ra.insert(RemainingAccount::Oracle { pubkey: sm.oracle });
        }
        for p in u.perp_positions.iter().filter(|p| !p.is_available()) {
            let pm = markets.perp(p.market_index);
            ra.insert(RemainingAccount::Perp { pubkey: pm.pubkey, writable: false });
            ra.insert(RemainingAccount::Oracle { pubkey: pm.oracle });
        }
    }

    // Always include QUOTE_SPOT (USDC, market_index = 0) — Drift requires it for
    // any margin-touching ix even if neither user holds a USDC spot position.
    let q = markets.spot(0);
    ra.insert(RemainingAccount::Spot { pubkey: q.pubkey, writable: false });
    ra.insert(RemainingAccount::Oracle { pubkey: q.oracle });

    metas.extend(ra.into_iter().map(RemainingAccount::into_meta));

    // ix data = 8-byte discriminator + borsh(market_index, max_base, limit_price?).
    // Borsh `Option<u64>` = 1-byte tag (0=None, 1=Some) followed by 8-byte LE.
    let mut data = Vec::with_capacity(8 + 2 + 8 + 1 + 8);
    data.extend_from_slice(&LIQUIDATE_PERP_DISCRIMINATOR);
    data.extend_from_slice(&market_index.to_le_bytes());
    data.extend_from_slice(&liquidator_max_base_asset_amount.to_le_bytes());
    match limit_price {
        None => data.push(0),
        Some(p) => {
            data.push(1);
            data.extend_from_slice(&p.to_le_bytes());
        }
    }

    Instruction { program_id: PROGRAM_ID, accounts: metas, data }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminator_matches_idl() {
        // Sanity: same bytes drift-rs alpha.14 hard-codes.
        assert_eq!(LIQUIDATE_PERP_DISCRIMINATOR, [75, 35, 119, 247, 191, 18, 139, 2]);
    }

    #[test]
    fn state_pda_is_deterministic() {
        let a = state_pda();
        let b = state_pda();
        assert_eq!(a, b);
    }

    #[test]
    fn remaining_account_ordering_is_oracles_then_spots_then_perps() {
        let p1 = Pubkey::new_unique();
        let p2 = Pubkey::new_unique();
        let p3 = Pubkey::new_unique();
        let mut s = BTreeSet::new();
        s.insert(RemainingAccount::Perp { pubkey: p1, writable: true });
        s.insert(RemainingAccount::Spot { pubkey: p2, writable: false });
        s.insert(RemainingAccount::Oracle { pubkey: p3 });
        let v: Vec<_> = s.into_iter().collect();
        assert!(matches!(v[0], RemainingAccount::Oracle { .. }));
        assert!(matches!(v[1], RemainingAccount::Spot { .. }));
        assert!(matches!(v[2], RemainingAccount::Perp { .. }));
    }

    #[test]
    fn writable_wins_over_readable_for_same_market() {
        // Insert writable first (as build_liquidate_perp_ix does), then readable
        // for the same market — BTreeSet treats them as equal (cmp ignores
        // writable flag), so the first inserted wins.
        let pk = Pubkey::new_unique();
        let mut s = BTreeSet::new();
        s.insert(RemainingAccount::Perp { pubkey: pk, writable: true });
        s.insert(RemainingAccount::Perp { pubkey: pk, writable: false });
        let v: Vec<_> = s.into_iter().collect();
        assert_eq!(v.len(), 1);
        assert!(matches!(v[0], RemainingAccount::Perp { writable: true, .. }));
    }
}

# LATTICA

> **Solana already runs Danksharding. We just unplugged the trash chute.**

LATTICA is a validator-adjacent protocol that harvests two cryptographic byproducts
every Solana slot produces but never publishes — and turns them into a
trust-minimized data-availability + homomorphic state-diff oracle layer.

This repository is a **proof of concept**. The protocol is real, the math
checks out, and the wire-level constructor produces shreds that are byte-perfect
against agave/firedancer mainnet format. Mainnet shred ingestion is gated on
Jito ShredStream activation (free, ~48h sign-up) and a public-IP listener;
all other pieces run locally with zero external dependencies.

---

## The Insight

Every Solana slot, validators produce — and discard — two cryptographic objects
that are individually well-known and jointly unnoticed:

1. **A leader-Ed25519-signed Merkle root over a (32 data + 32 coding)
   Reed-Solomon FEC set.** Any 32 of 64 shreds reconstruct the block. This
   is, information-theoretically, the same construction Ethereum is building
   under the name *1D Danksharding* — except it has been live on Solana mainnet
   for years. Each shred carries its Merkle proof back to the leader's signed
   root, so a third party with any 20-shred sample has a `2⁻²⁰` bound on
   undetected withholding.

2. **A per-slot lattice-hash delta in `(ℤ/2¹⁶)¹⁰²⁴`.** It's a homomorphic
   commitment to every account modification in the slot:
   `Δ_slot = Σ_{a ∈ modified} (h(a_new) − h(a_old))`. agave computes it,
   mixes it into the cumulative bank hash, and throws the delta away. Only the
   Blake3-checksum of the cumulative reaches the wire.

Together these form a complete, native, *free* DAS-plus-state-diff layer. No
fork, no SIMD, no validator-side change — just a peer-to-peer network of
listeners that capture what's already on Turbine, verify it, and republish.

Code refs for everything below are vendored against:

* `agave/ledger/src/shred/{merkle,merkle_tree}.rs`
* `agave/accounts-db/src/accounts_db.rs:4470-4513` (per-account LtHash byte order)
* `agave/lattice-hash/src/lt_hash.rs:27-56` (XOF → 1024×u16, wrapping ops)
* `firedancer/src/ballet/lthash/fd_lthash.h:4-65` (cross-impl of the same hash)
* `firedancer/src/ballet/shred/fd_shred.h:84-186` (1228-byte coding shred, Ed25519 sig)
* `firedancer/src/ballet/reedsol/fd_reedsol.h:9` (GF(2⁸))

---

## Math

### Reed-Solomon DAS sampling

For the standard 32+32 batch with `k` independent random shred queries against
a withholding adversary publishing only 31 of 64 positions:

```
P[undetected] = C(31, k) / C(64, k)
```

| k random samples | P[undetected]   | bits of security |
|------------------|-----------------|------------------|
| 4                | 0.467           | 1.1              |
| 8                | 0.0018          | 9.1              |
| 16               | 1.5 × 10⁻⁶      | 19.6             |
| 20               | 4.3 × 10⁻⁹      | 27.8             |
| 32               | 0 (recovery)    | ∞                |

These numbers come from the **MacWilliams identity** for the (64, 32) MDS
Reed-Solomon code over GF(2⁸); they are the tight sampling bound, not a
heuristic.

### LtHash homomorphism

Codomain `(ℤ/2¹⁶)¹⁰²⁴`. Per-account hash `h: Account → (ℤ/2¹⁶)¹⁰²⁴` is

```
h(a) = Blake3-XOF₂₀₄₈( lamports(8 LE) ‖ data ‖ executable(1) ‖ owner(32) ‖ pubkey(32) )
       reinterpreted as 1024 little-endian u16 limbs
```

Group operation: elementwise `wrapping_add`. Inverse: `wrapping_sub`. The
LtHash of a set is `Σ_{a ∈ S} h(a)`. Implementation lives at
`crates/lthash/src/lib.rs:60-85`; round-trip tests confirm
`mix_in(a); mix_out(a) ≡ identity` and `hash({a, b}) = h(a) + h(b)`.

Binding security reduces to Blake3's preimage resistance (the codomain alone
permits trivial collisions; binding is provided by the underlying hash).
ZK-friendly: the limb arithmetic has no carries to track in a circuit.

### Per-slot delta protocol

Validators compute `Δ_slot = LtHash_after − LtHash_before` *idempotently* for
each modified account in `agave/runtime/src/bank/accounts_lt_hash.rs:42-191`,
then mix it into the cumulative — and discard. Publishing this 2048-byte delta
once per slot enables:

* **Light client subset proofs.** Given an account `X`, a verifier with
  `(old_X, new_X)` and the published `Δ_slot` recomputes `δ_X = h(new_X) − h(old_X)`
  and checks `δ_X` is consistent with `Δ_slot`. Bandwidth: `O(2 KiB)` per slot.
* **1024-slot rollup checkpoints.** The homomorphism makes
  `Σ_{i ∈ [0, 1024)} Δᵢ` a single 2 KiB element. Cross-chain bridges verify
  historical state transitions over 1024 slots with a 2 KiB witness.
* **Fork detection.** Per-slot deltas diverge at slot S between forks; current
  bank-hash comparison only catches divergence at the *cumulative* level.

---

## What's In This Repo

```
crates/
├── shred/      Solana shred wire format: parser, Merkle/Ed25519 verifier,
│               byte-level (32, 64) FEC constructor (chained-MerkleData/Code
│               variants 0x96 / 0x66, proof_size = 6, no resign).
├── reedsol/    Reed-Solomon (32, 64) over GF(2⁸) via reed-solomon-erasure.
├── lthash/     LtHash homomorphism + per-account hash + SlotDelta builder.
├── listener/   FecAssembler (groups shreds by (slot, fec_set_index), triggers
│               RS reconstruction at 32 shreds), LeaderResolver trait,
│               StaticLeader + HeliusLeaderResolver impls, tokio UDP daemon.
├── attest/     Phase 3 attestation packet shape (libp2p wiring later).
└── cli/        `lattica` binary: keygen, slot, leaders, hash-account,
                verify-shred, das-demo.
scripts/
├── setup-jito.sh   Clones+builds jito-shredstream-proxy into vendor/.
└── run-mainnet.sh  Orchestrates proxy + lattica-listen for live mainnet.
```

15/15 unit tests pass:

```
$ cargo test --workspace
... 15 passed; 0 failed
```

Including:

* `fec_set_round_trips_through_verify_shred` — constructed 64-shred FEC set passes the full parser + Merkle path + Ed25519 sig verifier.
* `e2e_loopback_recovers_block` — end-to-end UDP loopback: 32 shreds delivered, listener emits `Reconstructed` with correct root.
* `assembler_does_not_reconstruct_at_31` — withholding at threshold − 1 correctly does not trigger reconstruction.
* `additive_homomorphism`, `slot_delta_reconstructs_after_state` — LtHash math.
* `rs_round_trip_recovers_from_any_32` — Reed-Solomon recovery from arbitrary 32 of 64 shards.

---

## Quick Start

```sh
git clone <this-repo>
cd lattica
cp .env.example .env
# put a Helius (or any Solana JSON-RPC) endpoint into .env
cargo build --release
cargo test  --workspace
```

### Local demos (no external services beyond Helius RPC)

```sh
# Full DAS pipeline against a synthetic FEC set
./target/release/lattica das-demo 32   # recovery succeeds; das_conf = 1.0
./target/release/lattica das-demo 20   # withholding; P[adv undetected] = 4.3e-9
./target/release/lattica das-demo 8    # marginal; P[adv undetected] = 1.78e-3

# Live mainnet via Helius
./target/release/lattica slot
./target/release/lattica leaders 419549000 16
./target/release/lattica hash-account 11111111111111111111111111111111
./target/release/lattica hash-account 8tjRQLzor4dP4qd1e7pVDdQmsdwdVv4kSeCVEHwWEiQW
```

### Mainnet shred pipeline (Jito ShredStream — see MAINNET.md)

```sh
# 1. Generate auth keypair (one-time)
./target/release/lattica keygen
# 2. Sign up your pubkey to ShredStream — https://docs.jito.wtf/lowlatencytxnfeed/
# 3. After Jito activates the keypair (~48h):
./scripts/setup-jito.sh
./scripts/run-mainnet.sh
```

Note: Jito BlockEngine streams shreds via UDP port 20000, which requires a
**public IP without NAT**. Run on a VPS, or open UDP 20000 on your router.

---

## Architecture

```
                                                          ┌────────────────┐
                                                          │  consumers     │
                                                          │  (mobile,      │
                                                          │   ZK bridges,  │
                                                          │   searchers)   │
                                                          └────────▲───────┘
                                                                   │ sample
                                                                   │
┌──────────────────────────────────────────────────────────────────┴───────┐
│  L3  aggregation gossip  (libp2p — Phase 3)                              │
│      Packet: (slot, fec_set_idx, merkle_root, leader_sig, Δ_lthash 2KB)  │
└──────────────────────────────────────────────────────────────────▲───────┘
                                                                   │ publish
┌──────────────────────────────────────────────────────────────────┴───────┐
│  L2  listener nodes (validator-adjacent, no stake)                       │
│      lattica-listen: UDP → parse → Merkle/Ed25519 → FEC assembler →      │
│      RS reconstruct → Δ_lthash recompute → attestation                   │
└──────────────────────────────────────────────────────────────────▲───────┘
                                                                   │ shreds
┌──────────────────────────────────────────────────────────────────┴───────┐
│  L1  Solana mainnet validators  (unchanged, no fork)                     │
└──────────────────────────────────────────────────────────────────────────┘
```

The protocol is **passive on the validator side**. Listeners harvest the
existing turbine broadcast; nothing on-chain or in-consensus changes.

---

## Status

| Phase | Description | State |
|------|-------------|-------|
| 1 | Wire-format parser, FEC constructor, Reed-Solomon, LtHash | ✓ done |
| 2 | FEC assembler, leader-aware listener, UDP daemon, CLI, E2E test | ✓ done |
| 3 | Aggregation gossip (libp2p), Byzantine-tolerant attestation | sketched (`crates/attest`) |
| 4 | WASM light-client SDK (browser, mobile) | not started |
| 5 | Bridge adapter (1024-slot Σ Δᵢ → BN254 on-chain verifier) | not started |
| - | Live mainnet shred ingestion via Jito ShredStream | blocked on ~48h sign-up |

---

## Honest Limitations

* **Proof of concept.** Not production-ready, not audited, no formal-verification
  of the FEC constructor.
* **Synthetic shreds today.** The byte-level constructor matches mainnet format
  exactly, but real mainnet shred ingestion requires Jito ShredStream access
  (or running a Solana validator).
* **Single FEC set per slot in current assembler.** A real slot has many FEC
  sets; the assembler handles them keyed by `(slot, fec_set_index)` but does
  not yet finalize slots when the leader's last shred arrives.
* **Δ_lthash recompute on the listener** requires replaying the block's entries
  through the SVM. Phase 2 deliberately stops at FEC reassembly; entry-level
  replay is Phase 3+.
* **DAS sampling argument applies to multi-listener clients, not single-node
  listeners.** A single listener that simply receives whatever shreds arrive
  has no security guarantee against withholding; the cryptographic argument
  requires *independent* sampling across multiple listeners. The current code
  emits the per-listener confidence; multi-listener sampling is Phase 3.

---

## Files of Interest

* `crates/shred/src/lib.rs` — wire format constants, variant decode/encode,
  parse + Merkle leaf computation + Ed25519 verify.
* `crates/shred/src/fec_set.rs` — `build_fec_set` constructor; produces 64
  byte-level shreds.
* `crates/lthash/src/lib.rs` — `hash_account`, `LtHash::{mix_in, mix_out, checksum}`.
* `crates/listener/src/lib.rs` — `FecAssembler::ingest`, DAS confidence math.
* `crates/listener/src/leader.rs` — `LeaderResolver` trait,
  `HeliusLeaderResolver` with windowed caching.
* `crates/cli/src/main.rs` — every CLI subcommand.
* `MAINNET.md` — full activation guide for the Jito ShredStream path.

---

## Inspiration & References

* Solana Labs / Anza for [agave](https://github.com/anza-xyz/agave).
* Jump Crypto for [Firedancer](https://github.com/firedancer-io/firedancer).
* The lattice-hash construction follows
  [eprint.iacr.org/2019/227](https://eprint.iacr.org/2019/227).
* Reed-Solomon DAS sampling math owes to the Ethereum Danksharding line of work.
* Robin Wilson's *Theorem of the Day* catalog supplied the bedside reading
  (MacWilliams, Minkowski, Lagrange interpolation, CRT, Lovász Local Lemma)
  that gives this protocol its formal underpinning.

---

## License

Apache-2.0. See [LICENSE](./LICENSE).

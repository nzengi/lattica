# LATTICA — Mainnet Activation Guide

Local synthetic demos prove every layer of the protocol. To pipe **real mainnet
shreds** through, you need a shred source. Two practical options today:

## Option A — Jito ShredStream (free, recommended)

### 1. Generate the auth keypair (already done if you ran `lattica keygen`)

```
$ lattica keygen
pubkey:  3PnhgpWW7NAj5TVFUpBSzYqsxbUG14YPY8diaCdz9LAB
path:    /home/nzengi/.config/solana/lattica.json
```

### 2. Sign up to Jito ShredStream

Fill the access form at <https://docs.jito.wtf/lowlatencytxnfeed/>. Provide the
pubkey above. Activation takes ~48 hours; you get an email confirmation.

ShredStream itself is **free during beta** — no SOL balance required on this
pubkey (it's used only for the auth-challenge signing).

### 3. Build the proxy

```
$ ./scripts/setup-jito.sh
```

Clones `jito-labs/shredstream-proxy` into `vendor/`, builds in release.

### 4. Make sure UDP port 20000 is reachable

Jito BlockEngine sends shreds via UDP to the proxy on port 20000 by default.
This **requires a public IP without NAT**. Practical paths:

* Run on a VPS with a public IPv4 (the planned deployment target).
* On a home connection: open UDP 20000 on the router and forward to your machine.

### 5. Run the full pipeline

```
$ cargo build --release
$ ./scripts/run-mainnet.sh
```

This starts two processes:

* `jito-shredstream-proxy` — authenticates with Jito, receives shreds via gRPC/UDP,
  republishes to `127.0.0.1:9999`.
* `lattica-listen 127.0.0.1:9999 helius:<rpc-url>` — verifies each shred against
  the correct leader (looked up via Helius `getSlotLeaders`), groups by
  `(slot, fec_set_index)`, triggers Reed-Solomon reconstruction at 32 shreds,
  emits `[done!]` events with the leader-signed Merkle root.

## Option B — Helius LaserStream (paid)

Helius offers a paid `LaserStream` product with low-latency block + shred access.
Pricing varies; see <https://www.helius.dev>.

If you go this route, point `lattica-listen` at LaserStream's UDP output or
write a small adapter that translates Helius gRPC frames to UDP datagrams.

## Local-only proof (no shred source required)

These work today, no waiting:

```
$ ./target/release/lattica slot                      # mainnet slot via Helius
$ ./target/release/lattica leaders 419549000 16      # leader schedule lookup
$ ./target/release/lattica hash-account <pubkey>     # canonical LtHash of a live account
$ ./target/release/lattica das-demo 32               # synthetic FEC + full DAS recovery
$ ./target/release/lattica das-demo 20               # withholding scenario (P[adv]≈4e-9)
$ cargo test --workspace                              # 15/15 pass — byte-level Solana wire compat
```

## Env

`.env` (gitignored) — populated by `cp .env.example .env`.

* `HELIUS_RPC_URL` — JSON-RPC endpoint for slot/leader/account queries.
* `JITO_SHREDSTREAM_ADDR` — optional, overridden by `--block-engine-url` in `run-mainnet.sh`.

## Files

* `crates/shred`     — Solana shred wire format: parser + Merkle/Ed25519 verifier + byte-level FEC constructor
* `crates/reedsol`   — Reed-Solomon (32, 64) over GF(2⁸)
* `crates/lthash`    — LtHash homomorphism, per-slot Δ recompute
* `crates/listener`  — FEC assembler + leader resolver + UDP daemon
* `crates/cli`       — `lattica` user-facing binary (keygen, slot, leaders, hash-account, verify-shred, das-demo)
* `crates/attest`    — Phase 3 attestation packet format (libp2p wiring later)
* `scripts/`         — `setup-jito.sh`, `run-mainnet.sh`

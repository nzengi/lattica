# lattica-liquidator

Drift Protocol v2 liquidation bot, built on top of [drift-rs](https://github.com/drift-labs/drift-rs).

## Why Drift, why now

- Solana's largest perp DEX → constant funding-rate-driven liquidations
- Lower "liquidator network" competition than Solend/MarginFi
- Public liquidator program with documented [Anchor IDL](https://github.com/drift-labs/protocol-v2)
- Capital-efficient: liquidator's $$ rotates per fill (you don't take risk)

## Status

* **v0.1 (current)** — paper mode: connect to mainnet, subscribe to all markets + oracles, enumerate 50 perp markets, identify Active vs Settlement vs Delisted. Validates FFI linkage and SDK surface.
* **v0.2 (next)** — `getProgramAccounts` for all Drift User accounts; per-user margin/health calc; rank by liquidation distance.
* **v0.3** — build liquidation ix; simulate via `rpc.simulateTransaction`.
* **v0.4** — Jito bundle submission live on mainnet with our $300 collateral rotating.

## Required: libdrift_ffi_sys

drift-rs links a C ABI to the on-chain Drift program crate via `libdrift_ffi_sys`,
which must be built with **Rust 1.76.0 exactly** (later versions break i128 C ABI
for Drift's account layouts). One-time setup:

```sh
git clone --depth 1 https://github.com/drift-labs/drift-ffi-sys vendor/drift-ffi-sys
cd vendor/drift-ffi-sys
rustup install 1.76.0
cargo +1.76.0 build --release
```

The resulting `vendor/drift-ffi-sys/target/release/libdrift_ffi_sys.so` is then
pointed to via two env vars:

```sh
export CARGO_DRIFT_FFI_PATH=/path/to/vendor/drift-ffi-sys/target/release
export LD_LIBRARY_PATH=$CARGO_DRIFT_FFI_PATH
```

## Run paper mode

```sh
cargo build -p lattica-liquidator
LD_LIBRARY_PATH=$LATTICA_ROOT/vendor/drift-ffi-sys/target/release \
  cargo run -p lattica-liquidator -- paper
```

Sample output:

```
INFO connecting DriftClient to mainnet…
INFO enumerating perp markets:
INFO   perp[ 0] SOL-PERP       status=Active
INFO   perp[ 1] BTC-PERP       status=Active
INFO   perp[ 2] ETH-PERP       status=Active
INFO   perp[ 7] DOGE-PERP      status=Active
INFO   perp[24] JUP-PERP       status=Active
INFO   perp[30] DRIFT-PERP     status=Active
INFO perp markets found: 50
```

## Risk & capital

This is a **proof of concept under active development**. Do not point at mainnet
without paper-trading a strategy for at least a week first. Initial deployment
capital: $300 USDC, rotating per-fill.

The bot's risk model: it never takes directional exposure. A liquidation fills
the bot with collateral (the liquidatee's margin); the bot's outstanding capital
is one liquidation worth of USDC.

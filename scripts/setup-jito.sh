#!/usr/bin/env bash
# Clones and builds jito-shredstream-proxy into ./vendor/.
# Idempotent: skips work if already built.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$ROOT/vendor"
PROXY_DIR="$VENDOR/shredstream-proxy"

mkdir -p "$VENDOR"

if [[ -d "$PROXY_DIR/.git" ]]; then
  echo "[setup-jito] vendor exists — pulling latest"
  (cd "$PROXY_DIR" && git pull --ff-only)
else
  echo "[setup-jito] cloning jito-labs/shredstream-proxy"
  git clone --depth 1 https://github.com/jito-labs/shredstream-proxy "$PROXY_DIR"
fi

(cd "$PROXY_DIR" && cargo build --release)
PROXY_BIN="$PROXY_DIR/target/release/jito-shredstream-proxy"
if [[ ! -x "$PROXY_BIN" ]]; then
  echo "[setup-jito] build did not produce expected binary at $PROXY_BIN"
  exit 1
fi

echo "[setup-jito] ok — $PROXY_BIN"

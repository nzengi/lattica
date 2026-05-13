#!/usr/bin/env bash
# Orchestrates a full LATTICA mainnet run:
#   1. starts jito-shredstream-proxy (translates Jito gRPC → local UDP)
#   2. starts lattica-listen (consumes UDP, parses shreds, verifies, reconstructs blocks)
#
# Prereqs:
#   * scripts/setup-jito.sh has been run (clones + builds the proxy)
#   * ~/.config/solana/lattica.json exists (run `lattica keygen`)
#   * The pubkey is signed up to Jito ShredStream (https://docs.jito.wtf/lowlatencytxnfeed/)
#   * .env contains HELIUS_RPC_URL
#   * UDP port 20000 is reachable from the public internet (or you are on a VPS with public IP)
#
# Exit Ctrl-C kills both processes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROXY_BIN="$ROOT/vendor/shredstream-proxy/target/release/jito-shredstream-proxy"
LISTEN_BIN="$ROOT/target/release/lattica-listen"

# Settings — override via env.
: "${KEYPAIR:=$HOME/.config/solana/lattica.json}"
: "${BLOCK_ENGINE_URL:=https://mainnet.block-engine.jito.wtf}"
: "${DESIRED_REGIONS:=amsterdam,ny}"
: "${DEST:=127.0.0.1:9999}"
: "${SRC_BIND_PORT:=20000}"

if [[ ! -x "$PROXY_BIN" ]]; then
  echo "[run-mainnet] proxy not built — run scripts/setup-jito.sh first" >&2
  exit 1
fi
if [[ ! -x "$LISTEN_BIN" ]]; then
  echo "[run-mainnet] lattica-listen not built — run \`cargo build --release\` first" >&2
  exit 1
fi
if [[ ! -f "$KEYPAIR" ]]; then
  echo "[run-mainnet] missing keypair $KEYPAIR — run \`lattica keygen\` first" >&2
  exit 1
fi

# Load HELIUS_RPC_URL.
if [[ -f "$ROOT/.env" ]]; then
  # shellcheck disable=SC1091
  set -a; source "$ROOT/.env"; set +a
fi
: "${HELIUS_RPC_URL:?HELIUS_RPC_URL not set (see .env.example)}"

cleanup() {
  echo "[run-mainnet] shutting down…"
  kill -- -$$ 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "[run-mainnet] starting jito proxy → UDP $DEST"
"$PROXY_BIN" \
  --block-engine-url "$BLOCK_ENGINE_URL" \
  --auth-keypair "$KEYPAIR" \
  --desired-regions "$DESIRED_REGIONS" \
  --dest-ip-ports "$DEST" \
  --src-bind-port "$SRC_BIND_PORT" &
PROXY_PID=$!

sleep 2
echo "[run-mainnet] starting lattica-listen on $DEST with helius resolver"
"$LISTEN_BIN" "$DEST" "helius:$HELIUS_RPC_URL" &
LISTEN_PID=$!

wait "$LISTEN_PID" "$PROXY_PID"

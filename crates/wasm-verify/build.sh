#!/usr/bin/env bash
# Builds the wasm-verify pkg for both `web` and `nodejs` targets and stages
# the artifacts next to the demo files so they're immediately runnable.
#
# Output:
#   crates/wasm-verify/demo/web/   ← drop-in for static-server (open index.html)
#   crates/wasm-verify/demo/node/  ← `node demo/node/node-smoketest.cjs`

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$SCRIPT_DIR"

echo "[build.sh] building web target…"
wasm-pack build --target web --out-dir "$ROOT/wasm-pkg" >/dev/null
echo "[build.sh] building nodejs target…"
wasm-pack build --target nodejs --out-dir "$ROOT/wasm-pkg-node" >/dev/null

# Stage web bundle next to index.html
mkdir -p demo/web demo/node
cp "$ROOT/wasm-pkg/lattica_wasm_verify.js" \
   "$ROOT/wasm-pkg/lattica_wasm_verify_bg.wasm" \
   "$ROOT/wasm-pkg/lattica_wasm_verify.d.ts" \
   demo/web/
cp demo/index.html demo/web/

# Stage node bundle
cp "$ROOT/wasm-pkg-node/lattica_wasm_verify.js" \
   "$ROOT/wasm-pkg-node/lattica_wasm_verify_bg.wasm" \
   "$ROOT/wasm-pkg-node/package.json" \
   demo/node/
cp demo/node-smoketest.cjs demo/node/

WASM_KB=$(stat -c %s demo/web/lattica_wasm_verify_bg.wasm)
WASM_KB=$(awk "BEGIN { printf \"%.1f\", $WASM_KB / 1024 }")
echo "[build.sh] done."
echo "  web demo  : crates/wasm-verify/demo/web/index.html  (open in browser)"
echo "  node demo : node crates/wasm-verify/demo/node/node-smoketest.cjs"
echo "  wasm size : ${WASM_KB} KiB"

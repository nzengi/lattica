// LATTICA — Node.js wasm verifier smoke test.
//
// Loads the wasm-pkg, runs verifySlotDelta in three modes:
//   1. self-cancelling (old == new): Σ = 0, attestation Δ = 0       → ✓
//   2. tampered (old != new vs Δ=0):                                  → ✗ mismatch
//   3. malformed Δ (limb count != 1024):                              → ✗ malformed
//
// Run:  node wasm-pkg-node/demo.cjs

const path = require('path');
const wasm = require(path.join(__dirname, 'lattica_wasm_verify.js'));

const fillByte = (b, n) => new Uint8Array(n).fill(b);
const strBytes = (s) => new TextEncoder().encode(s);
const acct = (seed, data, lamports) => ({
  lamports,
  data: strBytes(data),
  executable: false,
  owner: fillByte(seed, 32),
  pubkey: fillByte(seed * 11, 32),
});

const a_old = acct(1, 'alice-old', 1_000_000);
const a_new = acct(1, 'alice-new', 1_000_500);

const zeroAtt = (limbs = 1024) => ({
  slot: 0x12345678,
  fec_set_index: 0,
  leader_pubkey: fillByte(0xaa, 32),
  fec_merkle_root: fillByte(0xbb, 32),
  leader_sig: Array.from(fillByte(0xcc, 64)),
  delta_lthash: Array(limbs).fill(0),
});

let pass = 0;
let fail = 0;

function check(label, fn, expectMismatch) {
  const t0 = process.hrtime.bigint();
  let result;
  try {
    result = fn();
    const dtMs = Number(process.hrtime.bigint() - t0) / 1e6;
    if (expectMismatch) {
      console.log(`  ✗ FAIL ${label} — expected mismatch, got Ok in ${dtMs.toFixed(2)} ms`);
      fail += 1;
    } else {
      console.log(`  ✓ ${label} — verified in ${dtMs.toFixed(2)} ms`);
      pass += 1;
    }
  } catch (e) {
    const dtMs = Number(process.hrtime.bigint() - t0) / 1e6;
    if (expectMismatch) {
      console.log(`  ✓ ${label} — caught: ${e} (${dtMs.toFixed(2)} ms)`);
      pass += 1;
    } else {
      console.log(`  ✗ FAIL ${label} — unexpected error: ${e}`);
      fail += 1;
    }
  }
}

console.log(`LATTICA wasm verifier (limbs = ${wasm.lthashLimbCount()})`);
console.log();

check(
  'self-cancelling (old == new) against Δ=0',
  () => wasm.verifySlotDelta(zeroAtt(), [{ old: a_old, new: a_old }]),
  false,
);

check(
  'tampered (old != new) against Δ=0',
  () => wasm.verifySlotDelta(zeroAtt(), [{ old: a_old, new: a_new }]),
  true,
);

check(
  'malformed Δ (512 limbs instead of 1024)',
  () => wasm.verifySlotDelta(zeroAtt(512), []),
  true,
);

check(
  'empty slot (no transitions, Δ=0)',
  () => wasm.verifySlotDelta(zeroAtt(), []),
  false,
);

console.log();
if (fail === 0) {
  console.log(`ALL OK — ${pass} checks passed`);
  process.exit(0);
} else {
  console.log(`FAILURES: ${fail} of ${pass + fail} checks failed`);
  process.exit(1);
}

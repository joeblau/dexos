// Node PoC: assert the compiled wasm binding reproduces the pinned conformance
// vectors bit-for-bit. Every check compares wasm output against
// `conformance/vectors.json` — the single cross-language source of truth. No
// value is recomputed in JS; the wasm module (thin shim over dexos-sdk-core) is
// the sole producer under test.
//
// Run (from repo root, after `wasm-pack build ... --target nodejs`):
//   node bindings/wasm/tests/poc.test.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import * as wasm from "../pkg/nodejs/dexos_sdk_wasm.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../../..");
const vectors = JSON.parse(
  readFileSync(resolve(repoRoot, "conformance/vectors.json"), "utf8"),
);

let failures = 0;
function check(name, got, want) {
  if (got === want) {
    console.log(`ok   ${name}`);
  } else {
    failures += 1;
    console.error(`FAIL ${name}\n       got:  ${got}\n       want: ${want}`);
  }
}

const toHex = (u8) => Buffer.from(u8).toString("hex");
const fromHex = (h) => new Uint8Array(Buffer.from(h, "hex"));

// --- LOGIC #1: framed GetMarket request (types + codec + framing) ------------
{
  const v = vectors.encode_get_market_request;
  const out = wasm.encode_get_market_request(
    BigInt(v.input.request_id), // u64 -> BigInt
    v.input.market_id, // u32 -> number
  );
  check("encode_get_market_request.frame_hex", toHex(out), v.frame_hex);
}

// --- LOGIC #2: deterministic ed25519 signature (crypto) ----------------------
{
  const v = vectors.ed25519_sign;
  const seed = fromHex(v.input.seed_hex);
  const msg = new TextEncoder().encode(v.input.msg_utf8);
  const sig = wasm.ed25519_sign(seed, msg);
  check("ed25519_sign.sig_hex", toHex(sig), v.sig_hex);
}

// --- LOGIC #3: the load-bearing control-signing SSoT surface -----------------
{
  const v = vectors.signed_submit_order;
  const seed = fromHex(vectors.seed_hex);
  const signed = wasm.sign_submit_order(
    seed,
    BigInt(v.input.client_id),
    BigInt(v.input.nonce),
  );
  check("sign_submit_order.preimage_hex", toHex(signed.preimage), v.preimage_hex);
  check("sign_submit_order.signature_hex", toHex(signed.signature), v.signature_hex);
  check(
    "sign_submit_order.command_hash_hex",
    toHex(signed.command_hash),
    v.command_hash_hex,
  );
  check(
    "sign_submit_order.framed_request_hex",
    toHex(signed.framed_request),
    v.framed_request_hex,
  );
}

// --- The single money converter: raw <-> canonical fixed-6dp decimal ---------
{
  const v = vectors.amount_pin;
  check("amount_to_decimal(raw)->decimal", wasm.amount_to_decimal(v.raw), v.decimal);
  check("amount_from_decimal(decimal)->raw", wasm.amount_from_decimal(v.decimal), v.raw);
}

// --- decode_response is wired to the core's total frame decoder ---------------
// No happy-path response vector is pinned, so assert the negative contract: a
// *request* frame (msg_type=1) must be rejected by decode_response (expects
// msg_type=2). This proves the export links real framing, not a stub.
{
  const requestFrame = fromHex(vectors.encode_get_market_request.frame_hex);
  let threw = false;
  try {
    wasm.decode_response(requestFrame);
  } catch {
    threw = true;
  }
  check("decode_response(request_frame) rejects", threw, true);
}

if (failures > 0) {
  console.error(`\n${failures} check(s) FAILED`);
  process.exit(1);
}
console.log("\nOK — all wasm outputs are byte-identical to conformance/vectors.json");

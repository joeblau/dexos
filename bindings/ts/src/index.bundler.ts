// Bundler entry (webpack / vite / rollup with wasm support): re-exports the
// compiled wasm surface (bundler target — the bundler wires up wasm loading via
// the `_bg.js` glue, so no explicit init is needed) plus the pure-TS helpers.

export {
  encode_get_market_request,
  ed25519_sign,
  sign_submit_order,
  amount_to_decimal,
  amount_from_decimal,
  decode_response,
  SignedSubmit,
} from "../wasm/bundler/dexos_sdk_wasm.js";

export * from "./amount.js";
export * from "./transport.js";
export type * from "./wire.js";

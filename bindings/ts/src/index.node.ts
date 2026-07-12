// Node.js entry: re-exports the compiled wasm surface (nodejs target — a
// synchronous CommonJS module that loads the `.wasm` at require time) plus the
// pure-TS helpers. The wasm module is the sole producer of wire bytes; nothing
// here re-implements protocol logic.

export {
  encode_get_market_request,
  ed25519_sign,
  sign_submit_order,
  amount_to_decimal,
  amount_from_decimal,
  decode_response,
  SignedSubmit,
} from "../wasm/nodejs/dexos_sdk_wasm.js";

export * from "./amount.js";
export * from "./transport.js";
export type * from "./wire.js";

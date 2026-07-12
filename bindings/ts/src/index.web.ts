// Browser entry: re-exports the compiled wasm surface (web target — an ESM
// module that must be initialized before use) plus the pure-TS helpers. Call
// `init(wasmUrl)` once before invoking any wasm-backed function.

import __wbg_init, { initSync } from "../wasm/web/dexos_sdk_wasm.js";
import type { InitInput, InitOutput, SyncInitInput } from "../wasm/web/dexos_sdk_wasm.js";

export {
  encode_get_market_request,
  ed25519_sign,
  sign_submit_order,
  amount_to_decimal,
  amount_from_decimal,
  decode_response,
  SignedSubmit,
} from "../wasm/web/dexos_sdk_wasm.js";

export * from "./amount.js";
export * from "./transport.js";
export type * from "./wire.js";

/**
 * Load and instantiate the wasm module. Pass the URL (or fetched bytes) of
 * `dexos_sdk_wasm_bg.wasm`. Must resolve before any wasm-backed export is used.
 */
export async function init(
  input?: InitInput | Promise<InitInput>,
): Promise<InitOutput> {
  return __wbg_init(input === undefined ? undefined : { module_or_path: input });
}

/** Synchronous instantiation from already-fetched wasm bytes or a Module. */
export function initFromBytes(input: SyncInitInput): InitOutput {
  return initSync({ module: input });
}

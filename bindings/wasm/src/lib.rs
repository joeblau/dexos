#![allow(unsafe_code)] // wasm-bindgen macro expansion; this crate is a thin FFI shim only.
//! `dexos-sdk-wasm` — the npm/wasm binding for the DexOS client SDK.
//!
//! Every function here is a THIN `#[wasm_bindgen]` wrapper over
//! [`dexos_sdk_core`]. No wire logic (framing, postcard, ed25519, hashing) lives
//! in this crate — it only marshals arguments and moves bytes:
//!
//! * `u64` correlation ids / nonces cross as JS `BigInt` (wasm-bindgen default).
//! * byte buffers cross as `Uint8Array` (`Vec<u8>` / `&[u8]`).
//! * `i128` money never crosses; it is carried as the canonical fixed-6dp
//!   decimal string produced by the single [`convert`] converter, paired with
//!   its base-10 raw integer string.
//! * a decoded [`dexos_sdk_core::RpcResponse`] crosses as a plain JS object via
//!   `serde-wasm-bindgen`.
//!
//! `conformance/vectors.json` pins the byte-exact outputs; `tests/poc.test.mjs`
//! asserts this compiled module reproduces them bit-for-bit.

use dexos_sdk_core::{convert, decode_response as core_decode_response, poc, Amount};
use wasm_bindgen::prelude::*;

/// LOGIC #1 — deterministic framed `GetMarket` request. Delegates entirely to
/// the core's single source of truth; the wasm crate never re-implements
/// framing. Returns the raw frame bytes as a `Uint8Array`.
///
/// Golden: `encode_get_market_request(1n, 42)` ==
/// `05de010007010001000000000000000300000001032a`.
#[wasm_bindgen]
pub fn encode_get_market_request(request_id: u64, market_id: u32) -> Vec<u8> {
    poc::encode_get_market_request(request_id, market_id)
}

/// LOGIC #2 — deterministic ed25519 signature over `msg` with the key derived
/// from a 32-byte `seed`. Returns the 64-byte signature as a `Uint8Array`.
#[wasm_bindgen]
pub fn ed25519_sign(seed: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsError> {
    let seed = convert::bytes32(seed).map_err(JsError::new)?;
    Ok(poc::ed25519_sign(&seed, msg).to_vec())
}

/// The SSoT control-signing outputs crossing into JS. Each field is a
/// `Uint8Array`; `getter_with_clone` hands JS an owned copy per read.
#[wasm_bindgen(getter_with_clone)]
pub struct SignedSubmit {
    /// `"dexos.rpc.control.v1"` ++ postcard(signing payload).
    pub preimage: Vec<u8>,
    /// ed25519 signature over `preimage` (64 bytes).
    pub signature: Vec<u8>,
    /// Domain-tagged canonical hash of the lowered `Command` (32 bytes).
    pub command_hash: Vec<u8>,
    /// The full framed `RpcRequest` for the signed `SubmitOrder`.
    pub framed_request: Vec<u8>,
}

/// LOGIC #3 (the load-bearing SSoT surface) — the control-signing preimage,
/// signature, `command_hash`, and framed request for the canonical
/// `SubmitOrder`. Every binding must reproduce these bytes exactly.
#[wasm_bindgen]
pub fn sign_submit_order(seed: &[u8], client_id: u64, nonce: u64) -> Result<SignedSubmit, JsError> {
    let seed = convert::bytes32(seed).map_err(JsError::new)?;
    let signed = poc::sign_submit_order(&seed, client_id, nonce);
    Ok(SignedSubmit {
        preimage: signed.preimage,
        signature: signed.signature,
        command_hash: signed.command_hash,
        framed_request: signed.framed_request,
    })
}

/// Canonicalize a base-10 raw [`Amount`] integer string into the fixed-6dp
/// decimal string that carries money across the FFI boundary. `"1000000"` ->
/// `"1.000000"`. The raw form is a string because `i128` has no JS number.
#[wasm_bindgen]
pub fn amount_to_decimal(raw: &str) -> Result<String, JsError> {
    let raw: i128 = raw
        .parse()
        .map_err(|_| JsError::new("amount raw must be a base-10 i128 integer"))?;
    Ok(convert::amount_to_decimal(Amount::from_raw(raw)))
}

/// Parse a fixed-6dp decimal string back to the raw [`Amount`] integer, returned
/// as a base-10 string. `"1.000000"` -> `"1000000"`. Inverse of
/// [`amount_to_decimal`]; both route through the single core converter.
#[wasm_bindgen]
pub fn amount_from_decimal(decimal: &str) -> Result<String, JsError> {
    let amount = convert::amount_from_decimal(decimal).map_err(JsError::new)?;
    Ok(amount.raw().to_string())
}

/// Decode a framed `RpcResponse` into a plain JS object via `serde-wasm-bindgen`
/// (128-bit money fields cross as `BigInt`). Throws on a non-response frame or
/// undecodable bytes. The wasm crate performs no framing itself — it forwards to
/// the core's total decode path.
#[wasm_bindgen]
pub fn decode_response(bytes: &[u8]) -> Result<JsValue, JsError> {
    let response = core_decode_response(bytes).map_err(|e| JsError::new(&e.to_string()))?;
    let serializer =
        serde_wasm_bindgen::Serializer::new().serialize_large_number_types_as_bigints(true);
    serde::Serialize::serialize(&response, &serializer).map_err(|e| JsError::new(&e.to_string()))
}

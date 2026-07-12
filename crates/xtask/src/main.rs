//! `xtask` — conformance-vector generator for the DexOS client SDKs.
//!
//! `xtask gen-vectors` reuses the SSoT logic in `dexos-sdk-core` (it never
//! re-derives any wire logic) and writes the committed golden corpus to the
//! workspace-root `conformance/` directory:
//!   * `vectors.json` — the full cross-language corpus (frame hex, signing
//!     preimage, signature, command hash, signed round-trip, money pin, and a
//!     wire-struct map);
//!   * `submit_order_params.hex` / `command_place_order.hex` — the struct golden
//!     bytes consumed by `dexos-sdk-core`'s `abi_freeze` tests via `include_str!`.
//!
//! Paths are resolved from `CARGO_MANIFEST_DIR`, never the CWD, so the output is
//! stable regardless of where cargo is invoked.

use std::path::PathBuf;

use dexos_sdk_core::codec::encode;
use dexos_sdk_core::{poc, Amount, CancelAllParams, PageParams};
use dexos_sdk_core::{AccountId, MarketId};

/// The workspace root: `crates/xtask` -> `../..`. Never CWD-relative.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root must resolve")
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("gen-vectors") => gen_vectors(),
        Some("bump") => {
            eprintln!(
                "`xtask bump` is a Phase 4 concern (rename + version rewrite); not yet wired"
            );
            std::process::exit(2);
        }
        other => {
            eprintln!("usage: xtask [gen-vectors|bump <ver>], got {other:?}");
            std::process::exit(2);
        }
    }
}

fn gen_vectors() {
    let root = workspace_root();
    let dir = root.join("conformance");
    std::fs::create_dir_all(&dir).expect("create conformance dir");

    let seed = [7u8; 32];
    let signed = poc::sign_submit_order(&seed, 1, 1);
    let params = poc::golden_submit_params();
    let submit_params_hex = hex::encode(encode(&params).expect("encode SubmitOrderParams"));
    let command_hex = hex::encode(encode(&params.to_command()).expect("encode Command"));
    let amount_postcard_hex =
        hex::encode(encode(&Amount::from_raw(1_000_000)).expect("encode Amount"));

    // A small wire-struct hex map. Later TS/py stages extend this into a
    // deep-equal gate; Stage A pins the encodings so any postcard drift is
    // caught cross-language.
    let cancel_all = CancelAllParams {
        account: AccountId::new(1),
        market: Some(MarketId::new(42)),
    };
    let wire_structs = serde_json::json!({
        "SubmitOrderParams": { "hex": submit_params_hex },
        "Command_PlaceOrder": { "hex": command_hex },
        "PageParams_default": { "hex": hex::encode(encode(&PageParams::default()).unwrap()) },
        "CancelAllParams": { "hex": hex::encode(encode(&cancel_all).unwrap()) },
    });

    let vectors = serde_json::json!({
        "schema": 2,
        "seed_hex": hex::encode(seed),
        "encode_get_market_request": {
            "input": { "request_id": 1, "market_id": 42 },
            "frame_hex": hex::encode(poc::encode_get_market_request(1, 42)),
        },
        "ed25519_sign": {
            "input": { "seed_hex": hex::encode(seed), "msg_utf8": "dexos" },
            "sig_hex": hex::encode(poc::ed25519_sign(&seed, b"dexos")),
        },
        "signed_submit_order": {
            "input": { "client_id": 1, "nonce": 1 },
            "preimage_hex": hex::encode(&signed.preimage),
            "signature_hex": hex::encode(&signed.signature),
            "command_hash_hex": hex::encode(&signed.command_hash),
            "framed_request_hex": hex::encode(&signed.framed_request),
        },
        "amount_pin": {
            "raw": "1000000",
            "decimal": "1.000000",
            "postcard_hex": amount_postcard_hex,
        },
        "wire_structs": wire_structs,
    });

    let json = serde_json::to_string_pretty(&vectors).expect("serialize vectors") + "\n";
    std::fs::write(dir.join("vectors.json"), json).expect("write vectors.json");

    // abi_freeze golden .hex files (consumed via include_str!).
    std::fs::write(
        dir.join("submit_order_params.hex"),
        format!("{submit_params_hex}\n"),
    )
    .expect("write submit_order_params.hex");
    std::fs::write(
        dir.join("command_place_order.hex"),
        format!("{command_hex}\n"),
    )
    .expect("write command_place_order.hex");

    let readme = concat!(
        "# conformance\n\n",
        "Cross-language golden vectors for the DexOS client SDKs. All files here\n",
        "are **generated** by `cargo run -p dexos-xtask -- gen-vectors` from the\n",
        "single source of truth in `crates/sdk-core` and are **committed** so CI\n",
        "can `git diff --exit-code` them after regeneration. Never hand-edit.\n\n",
        "## Files\n\n",
        "- `vectors.json` — the full corpus (framed `GetMarket`, ed25519 signature,\n",
        "  the control-signing preimage + signature + command hash + framed signed\n",
        "  `SubmitOrder`, the fixed-6dp money pin, and a wire-struct hex map). Every\n",
        "  binding (wasm/npm, pyo3/pip, native rust) asserts bit-identity against it.\n",
        "- `submit_order_params.hex` / `command_place_order.hex` — postcard golden\n",
        "  bytes pinned by `crates/sdk-core`'s `abi_freeze` tests.\n",
    );
    std::fs::write(dir.join("README.md"), readme).expect("write conformance README");

    println!(
        "wrote {} (+ submit_order_params.hex, command_place_order.hex, README.md)",
        dir.join("vectors.json").display()
    );
}

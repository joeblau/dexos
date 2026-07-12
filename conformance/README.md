# conformance

Cross-language golden vectors for the DexOS client SDKs. All files here
are **generated** by `cargo run -p dexos-xtask -- gen-vectors` from the
single source of truth in `crates/sdk-core` and are **committed** so CI
can `git diff --exit-code` them after regeneration. Never hand-edit.

## Files

- `vectors.json` — the full corpus (framed `GetMarket`, ed25519 signature,
  the control-signing preimage + signature + command hash + framed signed
  `SubmitOrder`, the fixed-6dp money pin, and a wire-struct hex map). Every
  binding (wasm/npm, pyo3/pip, native rust) asserts bit-identity against it.
- `submit_order_params.hex` / `command_place_order.hex` — postcard golden
  bytes pinned by `crates/sdk-core`'s `abi_freeze` tests.

# DexOS Client SDK

One pure-Rust core. Thin clients in every language. Byte-identical on the wire.

The DexOS SDK lets applications talk to a node in Rust, TypeScript/JavaScript
(browser + Node), and Python. Every language package is a **thin shim**: it
marshals arguments and moves bytes. It does **not** re-implement cryptography,
`postcard` encoding, or frame construction. All of that logic lives once, in the
pure Rust core, and is compiled into each binding.

## Why one core

The wire protocol is unforgiving: `postcard` encodes enum variants and struct
fields **positionally**, control commands are signed over a domain-separated
preimage, and money is fixed-point (`i128`, six decimal places). If two
languages disagree about any of that by a single byte, a signature fails to
verify or an order is silently mis-encoded.

Rather than re-derive that logic per language (and drift), the SDK compiles
**one** implementation — `crates/sdk-core` (`dexos-sdk-core`) — into every
target:

| Layer                | Crate / package        | Role                                                        |
|----------------------|------------------------|-------------------------------------------------------------|
| Source of truth      | `dexos-sdk-core`       | Pure, transport-free, `#![forbid(unsafe_code)]`, wasm-safe. Types, signing, encode/decode. |
| Native Rust client   | `dexos-sdk`            | `dexos-sdk-core` + a tokio/rustls TLS 1.3 transport.        |
| wasm / npm           | `bindings/wasm` → `@dexos/sdk` | `#[wasm_bindgen]` wrappers over the core.           |
| Python / PyPI        | `bindings/py` → `dexos`| pyo3 (abi3) wrappers over the core.                         |
| TypeScript           | `bindings/ts` → `@dexos/sdk`   | Ergonomic TS over the compiled wasm core.           |

The bindings share the exact same compiled bytes. They cannot drift because they
are the same code.

### What crosses the language boundary

Some Rust types have no faithful representation in JS/Python. The core defines
**one** audited converter for each (`crates/sdk-core/src/convert.rs`), and every
binding calls it:

- `Amount` (`i128`, 6 dp) crosses as a canonical fixed-6-dp **decimal string**
  (`"1.500000"`, never a JS `number`). i128 has no wasm-bindgen support.
- Scaled `i64`/`u64` fields cross as **bigint** in TS, never `number`.
- Fixed byte arrays (`[u8; 32]` seeds, `[u8; 64]` signatures) cross as byte
  slices and are validated back to arrays on the way in.

## Install

No crates.io / npm / PyPI publish yet — Phase 4 flips `publish = true`. Today the
packages are consumed directly from the repository (the "git-tag bridge").

```sh
# Rust (native client)
cargo add dexos-sdk --git https://github.com/joeblau/dexos
# core only (no transport), e.g. to bring your own executor:
cargo add dexos-sdk-core --git https://github.com/joeblau/dexos

# TypeScript / JavaScript (browser, Node, or bundler)
npm i @dexos/sdk

# Python (3.9+)
pip install dexos
```

## Use

```rust
// Rust — native TLS 1.3 client
use dexos_sdk::Dexos;
let info = Dexos::connect("127.0.0.1:8080".parse()?, "node.example.com");
```

```ts
// TypeScript — same bytes, in the browser or Node
import { encode_get_market_request, sign_submit_order } from "@dexos/sdk";
const frame = encode_get_market_request(1n, 42);
```

```python
# Python
import dexos
frame  = dexos.encode_get_market_request(1, 42)
signed = dexos.sign_submit_order(bytes([7]) * 32, client_id=1, nonce=1)
```

## Build from source

All Rust/wasm/maturin commands need the **rustup** toolchain (pinned 1.92.0),
which — unlike a Homebrew cargo — has the `wasm32` std and honors
`rust-toolchain.toml`. Prefix with `PATH="$HOME/.cargo/bin:$PATH"` if a Homebrew
cargo is first on your `PATH`.

```sh
# Rust core + native client
cargo build -p dexos-sdk-core -p dexos-sdk --locked
cargo test  -p dexos-sdk-core --locked          # unit + ABI-freeze tests

# wasm / npm (needs the wasm32 target + wasm-pack)
wasm-pack build bindings/wasm --target nodejs --out-dir pkg/nodejs

# Python wheel (needs maturin; pyo3 abi3-py39)
maturin develop -m bindings/py/Cargo.toml

# TypeScript (builds all three wasm targets, then tsc)
npm --prefix bindings/ts ci
npm --prefix bindings/ts run codegen:wasm
npm --prefix bindings/ts run build
```

The two public crates advertise `rust-version = "1.82"` (wider consumer reach
than the engine's 1.92); the `msrv` CI job proves that floor.

## The conformance guarantee

The core is the source of truth, and CI enforces that every binding reproduces
its bytes exactly.

1. **Rust pins the truth.** `crates/sdk-core` carries ABI-freeze tests that pin
   `postcard` enum variant **order** (e.g. `RpcMethod`, `RpcError::NonceReused`
   last, `RpcOk::CommandAck` last) and per-wire-struct **golden bytes**, so a
   field reorder is caught rather than silently accepted. `poc.rs` pins the
   control-signing preimage (`dexos.rpc.control.v1` ++ postcard), the ed25519
   signature, the `command_hash`, and the full framed request.

2. **A committed corpus.** `cargo run -p dexos-xtask -- gen-vectors` writes
   `conformance/vectors.json` (plus the golden `.hex` files) from the Rust core.
   These are committed and diff-gated — regenerating must produce byte-identical
   output or CI fails.

   Hand-verified golden: `encode_get_market_request(1, 42)` ==
   `05de010007010001000000000000000300000001032a`.

3. **Every binding is checked against it.** `.github/workflows/sdk-ci.yml`:
   - `conformance` — core tests pass, then `gen-vectors` + `git diff --exit-code`.
   - `msrv` — the public crates build on 1.82.0.
   - `wasm` — node PoC + headless-browser tests assert bit-identity; also asserts
     `getrandom` 0.1 never enters the wasm cdylib graph.
   - `python` — regenerate + diff-gate the `.pyi` stub, build the wheel, `pytest`.
   - `ts` — build + lint (bans JS `number` for money) + `vitest` (frame
     bit-identity and wire `deepEqual` against `vectors.json`).

Committed source-of-truth artifacts (never hand-edited, regenerated by the
core): `conformance/vectors.json`, `conformance/*.hex`,
`bindings/py/python/dexos/_core.pyi`, `bindings/ts/src/wire.ts`.

## Scope

In scope now (Phases 0–3): the core, the native Rust client, and the wasm/npm,
Python, and TypeScript bindings — no crates.io/npm/PyPI publish (git-tag bridge),
no gateway or streaming. A browser edge gateway (`bin/dexos-gateway`) and a
`Subscribe` streaming wire method are later phases; `SubscriptionClient` is
present but gated `Unsupported` until then.

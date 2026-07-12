# DexOS — Decentralized Market Operating System

A pre-production, globally-distributed **exchange-kernel research project** in Rust. Not a
general-purpose blockchain — a purpose-built market network optimized for
deterministic execution, low latency, continuous sequencing, quorum-signed
checkpoints, self-custodied stablecoin collateral, and permissionless sponsored
markets (perpetuals, prediction, decision, scalar, and custom payout markets).

> **Status:** `marketd` is a composition skeleton, not production exchange
> software. It must not custody real assets or accept public trading traffic.
> See [the security status](docs/SECURITY.md) for current limitations.

## Design in one paragraph

Execution is separated from finality. A single-writer-per-shard deterministic
state machine executes a canonical command stream over continuous sequence
numbers, keeping canonical hot state in memory and persisting through an
append-only command log plus periodic snapshots. Periodically the network
produces quorum-signed checkpoints (HotStuff-style BFT). Everything in the
deterministic core is fixed-point integer arithmetic — no floating point, no
allocation on the hot path, no locks in matching, no database in the execution
path.

## Workspace

```
crates/
  types            fixed-point scalars, compact IDs, domain enums, decimal
  crypto           hashing, incremental Merkle, ed25519/secp256k1/EIP-1271, quorum/threshold
  codec            compact binary wire format (postcard) + priority Frame envelope
  orderbook        native CLOB (price-time, O(1) cancel, slab) + conditional engine
  risk             fixed-point margin/risk engine (perp + payout-vector)
  state-tree       incremental state commitments and roots
  execution        deterministic engine: ledger, sessions, deposits/withdrawals, order routing
  storage          append-only command log, snapshots, deterministic replay
  discovery        signed peer records, peer + market discovery, reputation
  network          async Transport (in-process + TCP), priority classes, backpressure
  consensus        BFT sequencing, quorum certificates, checkpoints, witnesses
  proto            transport-free RPC wire/protocol types (wasm-safe, no async)
  rpc              public binary RPC server + streaming subscription API
  client           native typed RPC client (proto + rpc round-trip, ed25519 signing)
  light-client     verified checkpoint sync + Merkle proofs (read-only)
  markets          registry, lifecycle, sponsor staking, payout, perp funding, resolution
  prediction-markets  binary / multi-outcome / scalar / dead-heat settlement
  decision-markets    action-contingent markets, time-weighted decision price
  oracle           threshold-signed price aggregation + health state machine
  custody          wallet binding + threshold custody signer subsystem
  chain-adapter[-evm|-svm]  external-chain observation trait + mock adapters
  observability    lock-free metrics, latency histograms, trace ids
  simd             runtime-dispatched kernels (scalar reference + vectorized, bit-identical)
  simulation       deterministic network + consensus simulator & fault injection
  benchmarks       purpose-built latency/throughput harness
  loadgen          distributed load generator engine
  node             composition root (config, roles, lifecycle) — owns the async runtime
bin/
  marketd          the node binary (run/benchmark/replay/inspect/keygen/snapshot/verify)
  market-loadgen   the load generator binary
  dexos            command-line RPC client (queries + signed control methods)
ui/                Dioxus 0.7 frontends (built separately from the engine — see Run)
  shared           renderer-agnostic components + view models (dexos-ui, wasm-safe)
  web              browser (wasm) app (dexos-web)
  desktop          native desktop app (dexos-desktop, links client directly)
  mobile           iOS / Android app (dexos-mobile, links client directly)
```

**Strict dependency direction.** The deterministic execution core
(`types`, `execution`, `orderbook`, `risk`, `state-tree`) links **no** async
runtime, networking, RPC, or storage engine. Enforced fail-closed in CI by
`scripts/check-core-deps.sh`, which checks each core crate's full
normal-dependency closure against the explicit allowlist in
`scripts/core-deps-allowlist.txt` — any crate not on the list fails the
gate — alongside `scripts/check-no-float.sh` and `scripts/check-unsafe.sh`.

## Toolchain

Rust is pinned to a single channel (currently **1.92.0**):
[`rust-toolchain.toml`](rust-toolchain.toml) and the workspace `rust-version`
are kept equal. There is no multi-MSRV CI matrix. See
[docs/TOOLCHAIN.md](docs/TOOLCHAIN.md) for the full policy (including the
optional macOS portability job).

## Setup

First-time setup on a fresh machine — installs the pinned toolchain and wasm
target, the per-OS system libraries the desktop/mobile frontends need, the
Dioxus CLI, and downloads the whole crate graph:

```sh
./bootstrap.sh                 # engine + frontends (Linux / macOS / Windows via Git Bash)
./bootstrap.sh --no-frontend   # engine only (no wasm target, GUI libs, or dx)
./bootstrap.sh --dev           # also install CI dev tools (cargo-deny, cargo-llvm-cov)
```

It is idempotent and detects the OS/distro (apt, dnf, pacman, zypper, or macOS
Xcode CLT). See `./bootstrap.sh --help` for all flags.

## Build & test

```sh
cargo build --workspace --locked
cargo fmt --all --check
cargo test  --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
./scripts/check-no-float.sh && ./scripts/check-core-deps.sh && ./scripts/check-unsafe.sh
```

Or run every PR-blocking CI gate in one shot (fmt, clippy, tests, docs, core
guards, state-root agreement — add `--full` for the determinism suite):

```sh
./scripts/preflight.sh
```

## Run

`marketd` is a workspace binary — build it first, then run it from
`target/release/`. It is **not** installed on your `PATH` by default.

```sh
cargo build --release --bin marketd     # produces target/release/marketd

./target/release/marketd run --config config/dev.toml            # full node
./target/release/marketd run --light --config config/light.toml  # read-only light node
./target/release/marketd run --role validator --role sequencer   # multiple roles
cargo run --release --bin marketd --features dev-tools -- benchmark --suite all --output results.json
./target/release/marketd replay --snapshot <path> --log <path>
./target/release/marketd verify  --snapshot <path>
./target/release/marketd keygen
```

Prefer a bare `marketd`? Install it onto your `PATH` (`~/.cargo/bin`):

```sh
cargo install --path bin/marketd
marketd run --config config/dev.toml
```

`marketd run` starts the node, prints its startup manifest (including the
selected SIMD backend), binds optional `/metrics` + `/livez` + `/readyz` when
`[observability].metrics_listen` is set, and idles until it receives SIGINT or
SIGTERM. Shutdown runs flush hooks, drains bounded queues under
`performance.drain_timeout_ms` (default 30s), and exits nonzero on drain
timeout or critical-task failure.

### Operator commands (real vs planned)

| Command | Status |
|---------|--------|
| `run` | **Real** — composition root lifecycle, metrics/probes, graceful drain |
| `keygen` | **Real** — OS CSPRNG ed25519 identity seed |
| `benchmark` | **Real** when built with `--features dev-tools` |
| `replay` / `inspect` / `verify` | **Real** — durable WAL / snapshot integrity (storage) |
| `snapshot` | **Fail closed** — engine serialize not wired; exits nonzero |

Release builds use `panic = "abort"`.

### Client (`dexos`)

`dexos` drives the full system over the node's RPC socket — 18 read-only queries
and 10 signed control methods, one subcommand per RPC method.

```sh
cargo build --release --bin dexos

./target/release/dexos --target 127.0.0.1:8080 get-market --market 1
marketd keygen --output trader.seed
./target/release/dexos --key trader.seed --nonce 0 \
  create-market --creator 1 --market-type perpetual --symbol BTC-PERP --outcomes 1
```

It targets a plaintext listener today (TLS client + `marketd run` binding are
planned). See [the CLI reference](docs/CLI.md) for the full command table,
signing model, and status.

### Frontends (web · desktop · mobile)

The `ui/*` crates are [Dioxus 0.7](https://dioxuslabs.com) apps and are **not**
built by the engine's default `cargo build` — they need a wasm target (web) or
platform system libraries (desktop/mobile), so they are compiled explicitly. The
shared `dexos-ui` crate holds renderer-agnostic components; `dexos-web` is the
browser build; `dexos-desktop` / `dexos-mobile` link the native `client` crate
and talk to a node directly.

**Prerequisites** — the Dioxus CLI (its binary is `dx`) plus the wasm target for
web builds:

```sh
cargo install dioxus-cli --locked        # provides `dx` (match the pinned Dioxus 0.7.x)
rustup target add wasm32-unknown-unknown  # for the web build
dx --version                              # must print "dioxus 0.7.x"
```

> **`dx` name collision.** Deno also ships a `dx` (`deno x`). If `dx --version`
> doesn't say `dioxus`, another `dx` shadows it on `PATH` — put `~/.cargo/bin`
> first by adding `export PATH="$HOME/.cargo/bin:$PATH"` to your shell rc (after
> any `brew shellenv` line) and opening a new shell, or invoke it directly as
> `~/.cargo/bin/dx …`.

**Web app** (`dexos-web`) — served as wasm via the Dioxus dev server:

```sh
dx serve --package dexos-web --platform web
# opens http://localhost:8080 by default; pass `--port 8081` to avoid clashing
# with the node's default RPC port (127.0.0.1:8080).
```

**Desktop app** (`dexos-desktop`) — a native webview window. Runs with plain
cargo (no `dx` needed) or under `dx serve` for hot-reload:

```sh
cargo run -p dexos-desktop                       # or: dx serve --package dexos-desktop --platform desktop
DEXOS_NODE_ADDR=127.0.0.1:8080 cargo run -p dexos-desktop   # point at a node
```

**Mobile app** (`dexos-mobile`) — iOS / Android via `dx` (requires the platform
SDK/simulator):

```sh
dx serve --package dexos-mobile --platform ios      # or --platform android
```

> **Status.** The frontends are **scaffolds**. `dexos-web` currently renders the
> markets view's empty state; live data will arrive through Dioxus server
> functions that call `client` server-side (not yet wired). `dexos-desktop` /
> `dexos-mobile` already link `client` and query `get_markets` from
> `DEXOS_NODE_ADDR` (default `127.0.0.1:8080`), degrading to an empty table on
> error. Note that `marketd run` does **not** yet bind the RPC listener
> ([TODO #418](crates/node/src/config.rs)), so there is no live node↔UI data path
> today — point the apps at a process that serves the RPC directly (a dev harness
> or test server) until the node's listener lands.

## Demo scripts

```sh
./scripts/demo-local.sh              # three full nodes + one light node (US/EU/Japan configs)
./scripts/demo-failover.sh           # kill the leader, continue, verify
./scripts/benchmark-single-market.sh # single-market throughput/latency report
./scripts/verify-state-roots.sh      # cross-node deterministic state-root check
```

## Engineering standards

Stable Rust; `unsafe_code = "deny"` by default (narrow, documented exceptions in
isolated perf modules only); fixed-point integers in all deterministic paths; no
silent integer truncation (`cast_possible_truncation` is a hard clippy error); no
panics on untrusted input (typed `thiserror` errors everywhere); bounded queues;
no benchmark claims without reproducible scripts.

See [architecture](docs/ARCHITECTURE.md), [security status](docs/SECURITY.md),
[build features](docs/FEATURES.md), [performance profiling](docs/PERFORMANCE.md),
and the [`dexos` CLI reference](docs/CLI.md).

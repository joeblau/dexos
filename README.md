# DexOS — Decentralized Market Operating System

A production-oriented, globally-distributed **exchange kernel** in Rust. Not a
general-purpose blockchain — a purpose-built market network optimized for
deterministic execution, low latency, continuous sequencing, quorum-signed
checkpoints, self-custodied stablecoin collateral, and permissionless sponsored
markets (perpetuals, prediction, decision, scalar, and custom payout markets).

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
  rpc              public binary RPC + streaming subscription API
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
```

**Strict dependency direction.** The deterministic execution core
(`types`, `execution`, `orderbook`, `risk`, `state-tree`) links **no** async
runtime, networking, RPC, or storage engine. Enforced in CI by
`scripts/check-core-deps.sh`, `scripts/check-no-float.sh`, and
`scripts/check-unsafe.sh`.

## Build & test

```sh
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets -- -D warnings
./scripts/check-no-float.sh && ./scripts/check-core-deps.sh && ./scripts/check-unsafe.sh
```

## Run

```sh
marketd run --config config/dev.toml            # full node
marketd run --light --config config/light.toml  # read-only light node
marketd run --role validator --role sequencer   # multiple roles
marketd benchmark --suite all --output results.json
marketd replay --snapshot <path> --log <path>
marketd verify  --snapshot <path>
marketd keygen
```

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

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/SECURITY.md](docs/SECURITY.md).

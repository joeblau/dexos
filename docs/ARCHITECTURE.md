# DexOS Architecture

DexOS is a distributed **exchange kernel**, not a general-purpose blockchain. It
begins from the question: *what is the minimum distributed, cryptographic, and
custody machinery required to make a Nasdaq-class exchange network globally
accessible, independently verifiable, and resistant to unilateral control?*

## Layering & dependency direction

```
                    ┌─────────────────────────────────────────┐
   edge (async)     │ node · rpc · light-client · network ·    │
                    │ discovery · loadgen · chain-adapter*      │
                    ├─────────────────────────────────────────┤
   coordination     │ consensus · storage · custody · oracle · │
   (sync/det.)      │ markets · prediction- · decision-markets │
                    ├─────────────────────────────────────────┤
   execution core   │ execution · orderbook · risk · state-tree│  ← no async / net /
   (deterministic)  │ crypto · codec · types                   │    rpc / storage-engine
                    └─────────────────────────────────────────┘
```

The **deterministic execution core** (`types`, `execution`, `orderbook`, `risk`,
`state-tree`) is integer-only and links no async runtime, networking, RPC, or
storage engine. This is enforced mechanically (`scripts/check-core-deps.sh`,
`scripts/check-no-float.sh`, `scripts/check-unsafe.sh`) and in CI.

## Separation of execution and finality

- **Execution** is a single-writer-per-shard deterministic state machine. It
  consumes a canonical `Command` stream indexed by continuous, monotonic
  `SequenceNumber`s and produces `ExecutionReceipt`s and an incremental state
  root. Identical command streams yield bit-identical state roots (verified by
  deterministic-replay tests).
- **Finality** is produced separately: witnesses certify executed sequence
  ranges, and a validator quorum finalizes periodic **checkpoints** via
  HotStuff-style quorum certificates. A command therefore moves through
  `ACCEPTED → EXECUTED → CERTIFIED → FINALIZED`.

This split means expensive BFT does not run on every low-level operation;
execution proceeds at memory speed while finality pipelines behind it.

## State commitments

`state-tree` maintains incremental per-account and per-market commitments and a
shard root (`root = hash_node(account_root, market_root)`), recomputing only the
O(log n) path touched by each update. `consensus` composes shard roots into a
checkpoint. Light clients verify balances/positions with Merkle proofs against a
finalized checkpoint root — never trusting a proxy.

## Consensus & checkpoints

`consensus` is a pure synchronous state machine (no async): continuous sequencing
with gap detection, deterministic round-robin leader selection, quorum-certificate
formation, pipelined execution/finalization, epoch and validator-set transitions,
and fork + double-sign/equivocation detection. `Checkpoint`s bind
`{previous_state_root, new_state_root, command_root, execution_root, oracle_root}`
under a quorum certificate and chain by ancestry.

The `BftEngine` runs in one of two explicit `ConsensusMode`s, and the distinction
is enforced in code, not just configuration:

- **`CrashTolerant` (demo).** Single-phase `Commit` certification with simple
  timeout view rotation. This is the mode the first demo runs across three
  regional nodes for crash-tolerant replication. It is **not** Byzantine-safe on
  its own and must not be relied on past crash faults; it needs no more than three
  nodes.
- **`ByzantineFaultTolerant` (production).** The full HotStuff/PBFT pipeline:
  chained `Prepare → PreCommit → Commit` quorum certificates, a high-QC / locking
  rule, `parent_hash` ancestry validation against the pipeline tip, refusal to
  certify a forked round, view changes that require a `TimeoutCertificate` (a
  quorum of signed timeouts — no replica can advance a view unilaterally), and a
  `finalize` that is refused until an execution commitment is certified by a
  quorum. Tolerating one Byzantine fault requires a `3f+1` set (**≥ 4
  validators**); the safety property (no two honest replicas finalize different
  blocks at a height under partitions and a Byzantine leader) is covered by the
  `consensus` unit tests and the `simulation` fault matrix.

## Networking

`network` provides an async `Transport` trait with an in-process transport (for
the deterministic simulator and tests) and a TCP transport (authenticated
handshake, length-prefixed `codec::Frame` framing). Traffic is divided into
priority classes **P0–P8** (consensus → risk-reducing → liquidation → new orders
→ receipts → oracle → checkpoints → market data → sync) with bounded per-class
queues and backpressure, so a market-data or state-sync burst can never starve
consensus or order traffic. QUIC and kernel-bypass (AF_XDP/DPDK) are future
adapters behind the same trait — normal optimized networking first, measured, then
optional.

## Markets

`markets` is a generic registry: every market is a `MarketDefinition` sponsored by
economic stake (a performance bond, not a listing fee), with a validated 12-state
lifecycle, multi-sponsor revenue sharing and governance, objective-fault slashing,
generic payout rules (vector/scalar/custom), value-conserving complete-set
mint/redeem, perpetual funding, and a resolution framework (evidence hashes,
challenge windows, threshold resolver committees) kept separate from the price
oracle. `prediction-markets` and `decision-markets` build market-type-specific
settlement (binary/multi-outcome/scalar/dead-heat; action-contingent with a
time-weighted decision price) on the shared primitives.

## Custody edge

The internal ledger is stablecoin-denominated and chain-agnostic; external chains
only gate entry/exit. `custody` binds EVM/SVM wallets (EIP-712, EIP-1271, Solana
ed25519), issues scoped session keys, and runs a threshold signer subsystem that
**independently** verifies a finalized withdrawal certificate before signing —
consensus authorizes, custody attests, and the ledger reserves/debits *before* any
external transaction is signed. `chain-adapter` defines the observation trait and
certificate types; the `-evm`/`-svm` crates are deterministic mock chains for the
first release, with production-oriented interfaces.

## Threading model

Async lives only at the edge (`node` owns the tokio runtime): peer connections,
RPC, discovery, state sync, chain observers. The deterministic hot paths
(matching, risk, oracle aggregation, consensus vote processing, journal writing)
run on pinned dedicated threads with bounded SPSC/MPSC ingress queues — arbitrary
task scheduling never controls execution latency.

## Observability & performance

`observability` provides lock-free atomic counters, integer-bucketed latency
histograms, and queue-depth/drop gauges that stay off the hot path. `benchmarks`
is a purpose-built harness reporting p50/p90/p95/p99/p99.9, throughput, and
allocations/op with machine-readable export. `simd` provides runtime-dispatched
kernels whose vectorized paths are bit-identical to the scalar reference.
`simulation` is a deterministic discrete-event network+consensus simulator with
fault injection (delay/reorder/drop/dup/crash/Byzantine/clock-drift) used for
soak and fault testing; the same seed reproduces byte-identical runs.

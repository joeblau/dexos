# 20M composed validator performance gate

The headline target is not a sum of component benchmarks. It is the minimum of
unique accepted, executed, and Minimmit-finalized order commands divided by the
synchronized steady-state interval. New, cancel, and replace commands count once;
retries, duplicates, rejected inputs, and consensus messages do not count.

The immutable workload is
`crates/benchmarks/workloads/global-20m-v1.toml`. A qualifying campaign uses real
London, New York, and Tokyo load agents and validators over the intended
DoubleZero interfaces, offers exactly 24M commands/s at the pinned regional
shares, warms up for at least 60 seconds, and records exactly 600 seconds of
steady state in each of three consecutive runs.

Each run JSON must deserialize as `benchmarks::ComposedRun`. It includes the exact
command and workload hash; complete raw one-second samples and their digest; build,
host, OS, NIC, and topology fingerprints; evidence for every signed-RPC through
Minimmit-checkpoint stage; reconciled counters; backlog drain; coordinated-
omission-safe receipt/finality latency; and aggregate, regional, node, and shard
throughput.

Validate three ordered artifacts with:

```sh
cargo run -p benchmarks --bin composed-gate -- \
  --manifest crates/benchmarks/workloads/global-20m-v1.toml \
  --run artifacts/run-1.json \
  --run artifacts/run-2.json \
  --run artifacts/run-3.json \
  --output artifacts/gate.json
```

The command exits nonzero on missing or unreachable targets, fewer than three
runs, insufficient duration or samples, incompatible provenance, any missing
production stage, counter mismatch, sequence gaps, NIC drops, unexplained loss,
positive finality-backlog slope, failure to drain within two checkpoint intervals,
or throughput below 20M effective finalized orders/s. Component microbenchmarks
remain available through `marketd benchmark`, but are component evidence only.

`crates/benchmarks/artifacts/20m/baseline-unoptimized-v1.json` records revision
`61cc7e6` honestly as FAIL because that baseline lacked the production composed
route. The current tree has the packed socket, durable execution, bounded Minimmit
driver, and checkpoint-bound asynchronous socket receipt delivery as a tested
composition, but the Phase-0 `Node::run` startup path does not instantiate that
stack and no external three-region campaign has run. The baseline does not
substitute fixed simulated costs for those missing components. The component socket
also has a shared-WAL multi-session core: explicit fixed-batch sequence stripes wait
for the exact next global range, retain at most the current frame per connection,
reject stale/unregistered lanes, and recover the same state root in journal order.
The checked-in machine evaluation is
`crates/benchmarks/artifacts/20m/baseline-unoptimized-v1-evaluation.json`. Reproduce
its explicit failure with:

```sh
cargo run -p benchmarks --bin composed-gate --locked -- \
  --manifest crates/benchmarks/workloads/global-20m-v1.toml \
  --run crates/benchmarks/artifacts/20m/baseline-unoptimized-v1.json \
  --output crates/benchmarks/artifacts/20m/baseline-unoptimized-v1-evaluation.json
```

The nonzero exit is required: the evaluation names the unavailable target,
missing raw intervals/finality route, incomplete topology scopes, and zero
effective finalized throughput instead of converting component rates into a
baseline validator result.

## Local component evidence (not the headline gate)

The following July 12–13, 2026 development measurements were taken on macOS
aarch64 with the counting allocator enabled from a dirty working tree. They are
useful regression evidence only: there is no complete socket → journal →
execution → Minimmit route, and the isolated WAL row deliberately disables
`fdatasync`. There is no three-region traffic. The Minimmit signer-weight kernel
has an ARM64 manual-counter capture below, but no component result may be
presented as effective global orders/s.

| Component suite | Variant | p50 | p99 | allocations/op |
| --- | --- | ---: | ---: | ---: |
| `Engine::execute` mark-price command | original deep-clone transaction | 52.958 us | 64.166 us | 35 |
| complete `Engine::execute` resting order | COW + book handoff | 22.958 us | 34.000 us | 35.006 |
| complete `Engine::execute` resting order | bounded in-place common-order journal | 8.334 us | 11.458 us | 0 |
| SPSC ingress → shard owner → SPSC effect | bounded in-place journal | 8.875 us | 11.542 us | 0 |
| durable WAL append, 64-byte payload, sync disabled | reusable frame + allocation-free chain hash | 5.500 us | 15.750 us | 0 |
| packed encode, 128 records | scalar | 1.125 us | 1.459 us | 0 |
| packed encode, 128 records | NEON | 0.583 us | 0.750 us | 0 |
| packed decode, 128 records | scalar | 1.417 us | 1.792 us | 0 |
| packed decode, 128 records | NEON | 1.209 us | 1.458 us | 0 |
| LZ4 encode + decode, 32 records | runtime SIMD + slicing-by-8 CRC | 4.291 us | 5.417 us | 0 |
| LZ4 encode + decode, 64 records | runtime SIMD + slicing-by-8 CRC | 8.375 us | 10.834 us | 0 |
| LZ4 encode + decode, 128 records | runtime SIMD + slicing-by-8 CRC | 16.084 us | 20.500 us | 0 |
| LZ4 encode, 32 records | scalar | 2.541 us | 3.167 us | 0 |
| LZ4 encode, 32 records | NEON candidate | 2.542 us | 3.167 us | 0 |
| LZ4 decode + CRC + record validation, 32 records | scalar | 2.292 us | 2.542 us | 0 |
| LZ4 decode + CRC + record validation, 32 records | NEON | 1.833 us | 2.375 us | 0 |
| LZ4 decode + CRC + record validation, 64 records | scalar | 4.292 us | 5.542 us | 0 |
| LZ4 decode + CRC + record validation, 64 records | NEON | 3.542 us | 4.625 us | 0 |
| LZ4 decode + CRC + record validation, 128 records | scalar | 8.500 us | 11.084 us | 0 |
| LZ4 decode + CRC + record validation, 128 records | NEON | 7.042 us | 9.125 us | 0 |
| trusted-context batch decode/admission, 128 records | fused NEON decode + SPSC | 7.917 us | 10.417 us | 0 |
| signed batch verify + replay + decode/admission, 128 records | Ed25519 + fused NEON + SPSC | 41.333 us | 53.875 us | 0 |
| market pre-trade depth summary, 128 fills | full-width scalar reference | 0.792-0.833 us | 1.041-1.084 us | 0 |
| market pre-trade depth summary, 128 fills | NEON fixed-point product blocks | 0.791-0.833 us | 1.041-1.042 us | 0 |
| Minimmit notarize/nullify/execution digests | fixed-stack scalar, n=16 label | 0.958 us | 1.250 us | 0 |
| Minimmit vote admission mix | 3 valid + 1 invalid Ed25519, n=16 | 85.792 us | 109.500 us | 0 |
| Minimmit M certificate verification | notarization + nullification, 7 signers each | 399.500 us | 437.458 us | 0 |
| Minimmit L certificate verification | ordering + execution, 13 signers each | 737.291 us | 789.958 us | 0 |
| Minimmit invalid certificate attribution | first invalid signer index, n=16 | 67.458 us | 79.083 us | 0 |
| Minimmit M + L certificate assembly | fixed-stack bitmap/dedup + inline owned QCs, n=16 | 0.209 us | 0.250 us | 0 |
| Minimmit QC signer-weight sum, 256 dense n=16 bitmaps | checked scalar reference | 0.750-0.834 us | 1.000-1.083 us | 0 |
| Minimmit QC signer-weight sum, 256 dense n=16 bitmaps | NEON selection + widened reduction | 0.334-0.375 us | 0.459 us | 0 |

The packed-wire 32/64-record SIMD candidates remain separately qualified; the
corrected seven-lane 128-record kernel is substantially faster. LZ4 decode
runtime-selects checked NEON/AVX2/AVX-512
literal/match copy kernels at every batch size; on this corpus NEON reduces
receive-path p50 by 17-20% on the corrected record corpus. The fixed-table SIMD
encoder is retained for differential coverage at 32 records but is tied with
its scalar reference; 64/128 encoder candidates dispatch to `lz4_flex` scalar
because their added match probing regressed the full path. Slicing-by-8 IEEE CRC removes
the former byte-at-a-time CRC bottleneck. Payload/input sizes are pinned at
531/1696 B (31.3%), 988/3392 B (29.1%), and 1927/6768 B (28.5%) for 32/64/128.
NEON disassembly for the wire and LZ4 kernels contains explicit vector
load/store and equality reductions; x86 cross-compilation contains AVX2
`vmovups ... ymm0` and AVX-512 `vmovups ... zmm0` lanes.

The production market-order pre-trade summary now retains ordered maker
decisions in an eight-lane fixed stack batch and vectorizes only independent
`price × fill quantity` products. FIFO traversal, quantity clamps, STP,
directed rounding, checked accumulation, and stateful mutation remain scalar.
Four alternating-order paired Apple M3 Max runs of 20,000 samples each reported
1.15-2.41% total-time improvement; every deterministic 95% paired-bootstrap
interval for mean scalar-minus-NEON latency was positive (6-21 ns across the
four runs), with zero allocations on both paths. Release disassembly contains
the expected `umull.2d` NEON instructions. The compact evidence is
`crates/benchmarks/artifacts/20m/matching-plan-neon-apple-arm64-v1.json`, and
the runner emits every raw pair. A pinned Rust 1.92 x86_64-apple-darwin Rosetta
lane also passed all 74 execution, 64 order-book, and 49 SIMD tests, covering
receipts, typed errors, fills, outcomes, roots, rounding boundaries, STP, and
tails. Rosetta exposed no AVX2/AVX-512 backend, so this is cross-architecture
replay evidence rather than x86 SIMD or performance qualification. Bare-metal
x86 AVX2/AVX-512 runtime results and paired cycles/branch/cache counters remain
required before issue #572 can close.

The same pinned x86_64 Rust 1.92 lane also passed all 20 codec, 154 network,
105 node-unit, and five node-integration tests as x86_64 Mach-O binaries. That
corpus covers the packed golden digest, 32/64/128 batch envelopes, TCP/QUIC
transport invariants, durable execution/recovery, receipts, checkpoint-bound
finality, and striped global ordering. The exact command and limitations are in
`crates/benchmarks/artifacts/20m/packed-x86_64-rosetta-determinism-v1.json`.
Because runtime detection selected scalar under Rosetta, this strengthens #569
cross-architecture compatibility but does not satisfy #570/#571 bare-metal x86
SIMD or performance gates.

The Minimmit matrix covers n=6/11/16 in the benchmark registry. Accepted vote
and certificate verification is allocation-free and uses pre-parsed committee
keys; detailed failure returns the first invalid bitmap index in deterministic
ascending order. The production certificate path now isolates its independent
16-bit signer-weight reduction after ordered signature validation and dispatches
it to checked NEON/AVX2/AVX-512 kernels. Signature verification, error ordering,
M/L threshold selection, and reactor transitions remain scalar. Four paired
Apple M3 Max runs over dense weighted n=16 L-certificate bitmaps improved the
pure reduction by 54.99-56.46%; every 95% bootstrap interval was positive, and
both paths allocated zero bytes. Disassembly contains NEON `cmeq`, `uaddlp`,
`uadalp`, and `addp`; pinned x86 cross-assembly contains AVX2 `vpcmpeqd` /
`vpmovzxdq` / `vpaddq` and masked AVX-512 `vmovdqu32` plus `vpaddq`. The
all-bitmap differential corpus covers every 16-bit value at lengths 0 through
16, wide-weight scalar fallback, M/L results, and bad-signer error precedence.
The compact evidence is
`crates/benchmarks/artifacts/20m/minimmit-weight-neon-apple-arm64-v1.json`.
This qualifies the ARM64 pure kernel, not end-to-end QC verification: Ed25519
still dominates at 399-737 us, and bare-metal x86 runtime plus x86 cycles/
branch/cache counters remain required before issue #573 can close. Owned
certificate assembly stores its bounded signature set inline and remains
zero-allocation.

An equal-work Apple M3 Max counter capture ran 2,000,000,000 reductions per path
with the same `7,835,625,000,000` checksum. Xcode 27 `xctrace` sampled EL0
manual counters every 1 ms and attributed 5,262 scalar and 2,564 NEON
running-thread samples. The totals below are the observed samples only; they are
not extrapolated across unsampled intervals. The exact archived event set and
commands are in the compact artifact and
`crates/benchmarks/artifacts/20m/minimmit-weight-xctrace-m3-options.json`.

| ARM64 counter | Scalar observed | NEON observed | Reduction |
| --- | ---: | ---: | ---: |
| cycles | 19,717,509,772 | 9,237,635,773 | 53.15% |
| instructions | 152,358,449,083 | 61,421,358,642 | 59.69% |
| retired branches | 17,553,345,486 | 1,981,535,169 | 88.71% |
| branch mispredictions | 123,349,571 | 29,613 | 99.98% |
| L1D load misses | 14,650,649 | 53,240 | 99.64% |
| L1D store misses | 1,362,708 | 20,421 | 98.50% |

Normalized for sampled work, branch mispredictions fell from 7,027.13 to 14.94
per million retired branches. L1D load/store misses fell from 96.16/8.94 to
0.87/0.33 per million instructions. These are pure-kernel ARM64 counters, not
composed validator or multi-region evidence.

The fused admission suite consumes an already-authenticated connection context,
decompresses, checks CRC, materializes typed records once, lowers all engine
commands, and atomically publishes them to the SPSC ring. Its 7.917 us p50 is
about 16.2 million admitted records/s for one local producer. The production
wrapper verifies the signed `DXOB` binding and strict replay state before this
boundary. Its separate Apple M3 Max component artifact reports 41.333 us p50,
45.417 us p95, 3,058,688 records/s, and zero measured allocations for that full
receive-side wrapper. Both rows exclude the
socket, execution, durability, consensus, and finality; only the second row
includes outer-signature verification. Neither row is the ≥20M global
acceptance result.

Reproduce the registered measurements with, for example:

```sh
cargo run --release -p marketd --features dev-tools -- \
  benchmark --suite shard-worker-order --output shard-worker-order.json
cargo run --release -p marketd --features dev-tools -- \
  benchmark --suite packed-batch-admit-128 --output packed-batch-admit-128.json
cargo run --release -p marketd --features dev-tools -- \
  benchmark --suite packed-encode-dispatched-128 --output packed-encode-dispatched-128.json
cargo run --release -p marketd --features dev-tools -- \
  benchmark --suite order-batch-lz4-128 --output order-batch-lz4-128.json
cargo run --release -p marketd --features dev-tools -- \
  benchmark --suite order-batch-lz4-decode-dispatched-128 \
  --output order-batch-lz4-decode-dispatched-128.json
cargo run --release -p benchmarks --bin matching-paired -- \
  --iterations 20000 --warmup 2000 --bootstrap-resamples 5000 \
  --output matching-paired.json
```

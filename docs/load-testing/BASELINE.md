# Load-generator development baseline

This is a development diagnostic, not a 20M qualification result and not a validator
capacity result.

| Field | Value |
| --- | --- |
| Date | 2026-07-12 America/Los_Angeles |
| Source commit | `61cc7e6f392198e9e122807c5a87f53e7eff191f` plus this worktree's uncommitted loadgen changes |
| Host | Apple M3 Max, arm64 |
| OS | Darwin 27.0.0 |
| Rust | rustc 1.96.1, LLVM 22.1.8 |
| Profile | workspace `bench` (inherits release, LTO thin, one codegen unit) |

Command:

```sh
./scripts/check-loadgen-hot-path.sh
```

Observed result:

```text
hot_path operations=1000000 scheduled_operations=1000000 elapsed_ns=10819059208 operations_per_second=92429 encoded_bytes=141345971 bytes_per_operation_milli=141345 allocations=0 allocations_per_operation_millionths=0 arch=aarch64 os=macos logical_cpus=16
report_snapshots=100 snapshot_allocations=100 allocations_per_snapshot=1
```

The loop performs open-loop scheduling, deterministic workload generation, real
per-command Ed25519 signing, production RPC lowering/framing into fixed buffers, and
the same global, action, interval, and endpoint histogram recording used by the live
runtime. It encoded 141,345,971 bytes (141.345 bytes/action on average).
It proves the instrumented steady path made zero allocator calls on this run. It also
identifies per-command signing as a material CPU budget: extrapolating this
single-core microbenchmark directly would require roughly 217 equivalent cores for
20M operations/s before network and scheduling overhead. That extrapolation is only a
capacity-planning warning; the distributed five-minute campaign is the authoritative
measurement.

Histogram storage is allocated once at recorder construction. The benchmark also
reports that off-hot-path cost separately as `snapshot_allocations`; one fixed bucket
block per constructed snapshot recorder is expected, while `allocations=0` remains
the per-action gate.

The process smokes separately proved exact socket/sink reconciliation at small scale:

- local: 1,000 offered and socket-written production frames;
- distributed: three authenticated agents, 1,200 aggregate socket-written frames,
  exact three-agent controller merge, and 1,200 independently received sink frames;
- endpoint failover: future work moved to a healthy same-region sink with exact
  per-endpoint counter and histogram attribution;
- signals: real SIGINT and SIGTERM both produced bounded, reconciled interrupted
  reports and the required nonzero automation status;
- TLS integration: TLS 1.3 with required client certificate, 25/25 accepted frames;
- sink metrics: independently mergeable processing-latency buckets with zero
  overflow, saturation, or merge errors;
- allocation benchmark: zero measured allocations after warm-up.

No checked-in artifact claims that this macOS development host reached the epic's
20M/s for five minutes. The Linux multi-host campaign remains mandatory.

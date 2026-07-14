# 20M distributed load-generator contract

This document is the normative measurement contract for the live `market-loadgen`
runtime. The deterministic simulator remains useful for planning and tests, but its
planned counts and modelled latency are never performance evidence. The legacy
blocking measured runner is also disqualified: it serializes a request behind its
receipt, uses a private 17-byte protocol, and historically capped a run at 200,000
requests.

## Claims and accounting

The generator-capacity headline is the number of complete, production-format trading
requests handed to real sockets during synchronized steady-state intervals. A
qualifying reference-sink campaign sustains at least 20,000,000 socket-written
operations/s for 300 seconds after a 30-second warm-up on multiple generator hosts.
Reference-sink capacity is never described as validator capacity.

A validator campaign reports acknowledged and accepted rates separately. The 20M
validator program in `PERFORMANCE_20M.md` additionally requires executed and
Minimmit-finalized reconciliation and its longer 60-second warm-up / 600-second
steady-state phases.

Each offered operation advances monotonically through zero or more intermediate
counters and exactly one terminal counter:

```text
offered
  |-- locally-dropped
  `-- generated
        |-- protocol-failed
        `-- queued
              |-- transport-failed
              `-- socket-written
                    |-- timed-out
                    `-- acknowledged
                          |-- accepted
                          `-- rejected
```

Consequently, after drain:

```text
offered = accepted + rejected + timed-out + transport-failed
        + protocol-failed + locally-dropped
acknowledged = accepted + rejected
socket-written = acknowledged + timed-out
```

Failures after a complete socket write are timeouts; connection or partial-write
failures before that boundary are transport failures. Encoding, signing, invalid
local state, and preflight failures are protocol failures. Queue/correlation capacity
exhaustion and missed open-loop deadlines are locally dropped and retain a typed
reason. Retries are new offered attempts with new request IDs but preserve the
original logical-operation identity, so retries cannot inflate unique validator
throughput.

## Time and phases

The controller chooses a future UTC start time and sends it with a monotonic phase
schedule. Agents record clock method, measured offset, and uncertainty, but queue and
request latency always use one host's monotonic clock; no latency subtracts clocks
from different machines.

The standard generator qualification phases are:

| Phase | Duration | Included in headline |
| --- | ---: | --- |
| preflight | bounded by operator timeout | no |
| warm-up | 30 seconds | no |
| steady | 300 seconds | yes |
| drain | until every written request is terminal | no |
| cool-down | 10 seconds | no |

The validator campaign overrides warm-up and steady duration to 60 and 600 seconds.
One-second intervals are half-open `[start_ns, end_ns)`. An operation belongs to the
offered interval containing its scheduled deadline and to the written/terminal
interval containing the corresponding local monotonic timestamp.

Open-loop pacing never converts lag into an unbounded catch-up burst. At most one
configured burst quantum may be recovered; older missed deadlines become typed local
drops. Backpressure is bounded and visible. A healthy qualification run requires
every steady interval to reach at least 98% of its assigned socket-written rate, no
unexplained counter loss, zero histogram overflow, zero sequence/identity collision,
and fewer than 0.01% unexpected terminal failures. The final drain must conserve all
offered operations.

## Components and isolation

- The local runner uses the same agent engine as distributed mode but embeds its
  controller and does not open a control listener.
- An agent validates its host, source addresses, targets, keys, fixed capacities, and
  clock status before accepting a plan. It owns generation and target connections.
- The controller authenticates agents, allocates disjoint client/nonce/request/RNG
  namespaces, schedules phases, receives off-path interval deltas, and merges raw
  histogram buckets. It never proxies order traffic.
- The generic validator baseline uses signed `proto::RpcMethod::{SubmitOrder,
  CancelOrder, ReplaceOrder}` and correlated `RpcResponse` frames. The optimized
  path signs one canonical `DXOB` wrapper for each 32-128 record batch and consumes
  correlated `DXBR` admission, execution, and finality receipts.
- Every optimized connection consumes an explicit server-issued lease. Lease files
  contain destination/session/account/client identity, nonce and sequence starts,
  plus `batch_sequence_stride` and `command_sequence_stride`; signing seed bytes
  remain in the separate key file. Strides are global controller outputs, not
  recomputed from an agent's local subset. Multi-connection lanes must cover a
  fixed-batch stripe exactly; collisions, missing/inconsistent stripes, or duplicate
  identities fail preflight.
- `market-loadgen --measured --packed-leases leases.json` selects the optimized
  path. `--target-profile component --packed-completion executed` is development
  evidence only. A `validator` profile requires TLS 1.3 and defaults to
  `--packed-completion finalized`; missing Minimmit checkpoint receipts fail closed.
  Plaintext is restricted to the explicit component/development posture.
- The reference sink parses the same production frames and is prominently labelled;
  it may skip business execution only for generator-capacity qualification.

Missing, late, disconnected, saturated, or failed agents make an aggregate run fail.
An agent identity epoch and assignment digest are single-use; reconnection cannot
reissue a client/nonce partition from an already-started run.

## Reference topology

The checked-in target topology is three Linux x86_64 generator hosts (London, New
York, Tokyo), each with at least 32 dedicated physical cores, 128 GiB RAM, one 100
GbE NIC, local NUMA allocation, performance governor, synchronized clocks, and at
least two explicitly configured source IPs. The campaign uses at least 10,000 total
persistent connections, split approximately equally across regions and weighted
explicit endpoints. RSS queues, IRQ affinity, source IPs, MTU, offloads, socket
buffers, file-descriptor limits, CPU pinning, kernel, NIC driver/firmware, and exact
binary provenance are artifacts, not inferred defaults.

The reference sink is a separate multi-host tier with enough independently measured
receive capacity to leave at least 20% headroom above offered load. Generator and sink
counters reconcile. A separate run targets the real validator cluster and reports
its achieved written, acknowledged, accepted, executed, and finalized throughput
without borrowing the sink result.

## Artifact rules

Agents emit raw one-second counter deltas and compatible histogram buckets. The
controller sums counters and buckets; it never averages percentiles. Every artifact
records scenario hash, seed, run/assignment digest, commit and dirty state, Rust/LLVM,
binary flags, host/CPU/NUMA/kernel/governor, NIC/driver/firmware/offloads/MTU, source
IPs, endpoints, connection count, clock method/offset/uncertainty, interval boundaries,
queue high-water marks, RSS, scheduler lag, reconnects, and metric saturation.

Any missing interval, incompatible histogram schema, counter overflow, agent failure,
provenance mismatch, or failure to conserve counters is an explicit FAIL.

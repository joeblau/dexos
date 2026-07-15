# DexOS load-testing architecture and measurement contract

Status: accepted design for `market-loadgen-campaign` 20M qualification
Scope: local runner, distributed controller/agents, validator adapter, and reference sink

## Claims and target modes

`market-loadgen-campaign` has three deliberately distinct data-plane modes:

| Mode | Target | Permitted claim |
| --- | --- | --- |
| `simulate` | no socket | deterministic planning and test coverage only |
| `sink` | protocol-conformant test sink | generator/socket capacity only |
| `validator` | DexOS RPC listener | validator acknowledged and accepted capacity |

Simulated, scheduled, or generated counts do not prove network capacity. The legacy
blocking measured runner is request/receipt serialized and capped at 200,000 requests;
its results cannot satisfy the 20M gate. A sink result is always labelled
`reference-sink` and can never be emitted or interpreted as a validator result.

The epic gate is at least **20,000,000 complete production-protocol trading request
frames handed to sockets per second**, sustained during every one-second interval of
a five-minute steady-state phase after a 30-second warm-up, aggregated across more
than one generator host. Validator `acknowledged` and `accepted` rates are reported
separately and are never inferred from sink capacity.

## Phase and timestamp boundaries

A run has four ordered phases. Configuration and preflight occur before them.

1. **Warm-up** establishes connections, primes worker-local state, and permits code,
   allocator, route, ARP/NDP, and TLS caches to settle. Warm-up is reported but is not
   included in qualification gates.
2. **Steady state** is the only qualification interval. The open-loop schedule begins
   at the published monotonic phase boundary. Interval `n` is the half-open range
   `[steady_start + n seconds, steady_start + (n + 1) seconds)`.
3. **Drain** stops offering new operations and allows queued and in-flight operations
   to reach terminal outcomes until the queue is empty or the configured deadline.
4. **Cool-down** takes final snapshots and reconciles independently counted artifacts.

Each operation carries timestamps from a single worker-local monotonic clock:

- `scheduled_at`: ideal open-loop deadline;
- `generated_at`: a complete valid logical operation exists;
- `queued_at`: the encoded request becomes eligible for a connection;
- `write_started_at`: the first byte is submitted to the async writer;
- `socket_written_at`: the final byte of the frame is accepted by the socket API;
- `acknowledged_at`: a correlated complete response frame is decoded.

Queue delay is `write_started_at - scheduled_at`. Request-to-ack latency is
`acknowledged_at - socket_written_at`; end-to-end offered-to-ack latency is also
reported as `acknowledged_at - scheduled_at`. Durations use integer nanoseconds.
Cross-host wall clocks are provenance only and are never subtracted for per-request
latency. Percentiles use nearest-rank values over mergeable histogram buckets.

## Counter definitions and conservation

- **offered**: an open-loop deadline fell inside the measured interval;
- **generated**: a valid new/cancel/replace operation was produced;
- **queued**: an encoded request entered a bounded connection queue;
- **socket-written**: every byte of a complete real RPC request frame was handed to
  the socket API;
- **acknowledged**: a matching response was decoded before its deadline;
- **accepted**: the acknowledgement contains a successful `CommandAck`;
- **rejected**: the acknowledgement contains a typed protocol/application rejection;
- **timed-out**: no matching acknowledgement arrived before the deadline;
- **transport-failed**: DNS, bind, connect, TLS, write, read, close, or reconnect failed;
- **protocol-failed**: framing, correlation, or response decoding failed;
- **locally-dropped**: generation, encoding, correlation, or connection queues were
  full, or the overload policy intentionally discarded the action.

Every offered operation reaches exactly one pre-write outcome:

```text
offered = socket-written + locally-dropped + generator-failed + transport-failed-before-write
```

Every socket-written operation reaches exactly one terminal outcome by the end of
drain:

```text
socket-written = accepted + rejected + timed-out
               + transport-failed-after-write + protocol-failed
```

`acknowledged = accepted + rejected`. A transport failure is classified before or
after write, never both. Retry attempts have attempt counters, but the logical
operation remains in exactly one terminal bucket. Duplicate responses, late responses,
counter overflow, histogram saturation, and unclassified remainders make the run fail.

## Pacing, overload, and reconnect rules

Workers use an open-loop integer schedule derived from the scenario rate. Scheduler
lag increments `missed_deadlines` and `rate_debt_ns`. A worker may catch up by at most
the configured burst quantum; it must not turn accumulated lag into an unbounded
burst. After that quantum, overdue operations become `locally-dropped` with reason
`scheduler-overload`.

Request and byte queues, correlation tables, live-order pools, and histograms have
fixed configured capacities. Full structures never grow in the timed path. When an
established route fails, the connection closes the old endpoint's counter/histogram
segment, accounts every in-flight and already-offered operation there, and tries
startup-resolved same-region alternatives before retrying the failed route. Only
future work moves; identity partitions and in-flight work never migrate. The search
is bounded by the configured endpoints and reconnect-attempt ceiling, with
exponential backoff and deterministic jitter. Reconnecting never reuses a
`(client_id, nonce)` pair for a new logical operation.

## Components and trust boundaries

- The **local runner** resolves one plan, performs preflight, and invokes the same
  agent engine in-process without a control-plane listener.
- An **agent** owns data-plane workers, source addresses, connections, credentials,
  nonce/RNG namespaces, local monotonic latency, and raw interval deltas.
- The **controller** authenticates agents, validates advertised topology, assigns
  disjoint partitions, chooses a future start, monitors heartbeats, and merges raw
  counters and histogram buckets. Trading traffic never traverses the controller.
- The **validator adapter** signs `proto::RpcMethod::{SubmitOrder, CancelOrder,
  ReplaceOrder}`, correlates real `RpcResponse`s, and updates bounded live-order state
  only from accepted acknowledgements.
- The **reference sink** parses the same request frames, independently counts input,
  and optionally returns conformant or deliberately faulty responses. It is test-only.

Control access is authenticated. Agents allow-list target endpoints from their local
configuration; a controller cannot direct traffic elsewhere. Signing material is read
by agents and is never sent to the controller or included in resolved plans/reports.

## Reference topology and qualification thresholds

The checked-in reference scenario is `config/loadgen/reference-20m.toml`. The minimum
topology is eight Linux generator hosts and two independently instrumented sink hosts:

- generator: 48 physical cores, 64 GiB RAM, one 25 GbE NIC, RSS/RPS configured,
  Rust release build with LTO, CPU frequency governor fixed to performance;
- sink: sufficient cores and aggregate NIC bandwidth to keep receive saturation below
  80%; each sink publishes independent receive/response counters;
- kernel: monotonic clock, synchronized wall-clock provenance, `nofile` and conntrack
  limits above the planned sockets, widened ephemeral port range, and NIC/socket
  buffers recorded in artifacts;
- at least 10,000 persistent connections, distributed across at least four source IPs,
  two logical regions, and two weighted sink endpoints;
- exact operation sizes and encoded byte rates are captured in the final artifact.

Eight 48-core generators provide 384 physical cores. The checked-in Apple M3 Max
diagnostic requires roughly 217 equivalent cores for 20M signed actions/s and 260 for
the 24M offered-rate headroom before networking and runtime overhead; four 32-core
hosts would therefore be an unsupported reference claim. The campaign still measures
actual hosts rather than treating this extrapolation as evidence.

Qualification fails if any steady one-second interval is below 20M socket-written/s,
if unexpected terminal failures exceed 0.01% in any interval, if scheduler overload or
metrics loss is nonzero, if generator/sink written-received reconciliation differs by
more than in-flight operations at an interval boundary or by any operation after drain,
if RSS/queues grow without a configured bound, or if a required agent is late/missing.
Expected reject/fault campaigns use separate thresholds and cannot qualify healthy mode.

The campaign stores scenario, resolved redacted plan, commit, Rust/compiler and binary
flags, host CPU/RAM/NIC/kernel settings, connection/source-IP layout, per-second JSONL,
final reports from every process, profiles, and the reconciliation result. A separate
validator campaign records written/acknowledged/accepted throughput, p99 latency, and
bottlenecks without applying the sink-capacity claim to the validator.

One-second connection-local deltas travel through a bounded off-hot-path channel.
Endpoint failover closes an exact partial segment before changing routes, and only a
complete all-connection aggregate is emitted; queue overflow or a missing contributor
is metric loss and makes qualification fail. Every interval carries raw global and
per-action histograms plus exact region/endpoint segments. Distributed agents stream
these aggregates to the controller, which rejects duplicates, retains the agent
dimension, and requires the stream to match the final agent report. Latency recorders
remain connection-local and fixed capacity; every per-second and final percentile is
derived from raw bucket merges rather than percentile averaging.

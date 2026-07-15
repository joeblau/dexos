# Market load-generator operator guide

`market-loadgen-campaign` has three explicit modes: deterministic simulation, a test-only
reference sink, and a real DexOS validator/gateway target. Read
[`ARCHITECTURE.md`](ARCHITECTURE.md) before interpreting results. Sink throughput is
generator capacity; it is never a validator-capacity claim.

The checked-in development measurement and its limitations are recorded in
[`BASELINE.md`](BASELINE.md).
The issue-by-issue implementation/evidence status is recorded in
[`ACCEPTANCE.md`](ACCEPTANCE.md).

## Build, validate, and simulate

Build the release binary and resolve a plan without opening target sockets:

```sh
cargo build --release --locked -p market-loadgen
target/release/market-loadgen-campaign \
  --scenario config/loadgen/reference-20m.toml \
  --dry-run controller --target-kind sink
```

The resolved TOML redacts control tokens and signing-key paths. Simulation remains
available for deterministic workload tests:

```sh
target/release/market-loadgen-campaign \
  --orders-per-second 100000 --duration 30s simulate
```

Simulation opens no data-plane socket and cannot qualify throughput.

## Local reference-sink run

Terminal 1:

```sh
target/release/market-loadgen-campaign reference-sink --listen 127.0.0.1:9900
```

Terminal 2:

```sh
target/release/market-loadgen-campaign \
  --scenario config/loadgen/local-sink.toml \
  local --target-kind sink
```

The sink independently parses and verifies the same signed `SubmitOrder`,
`CancelOrder`, and `ReplaceOrder` frames used by validator mode. Exercise bounded
fault paths with `--fault no-ack`, `batched-ack`, `delayed-ack`, `reject`, `drop`,
`corrupt-response`, `throttle`, or `disconnect`. Fault runs are expected to fail the
healthy scenario gate unless their thresholds are intentionally changed.

The checked-in 20M profile uses TLS endpoints, so each capacity sink must use its
TLS 1.3 listener (add `--client-ca-file` to require mTLS):

```sh
market-loadgen reference-sink \
  --listen 0.0.0.0:9443 \
  --tls-cert-file secrets/sink-chain.pem \
  --tls-key-file secrets/sink-key.pem \
  --client-ca-file secrets/loadgen-client-ca.pem
```

The certificate SAN must match the corresponding endpoint `tls.server_name`; agents
must receive the matching CA and, for mTLS, client certificate/key references.

Run both checked-in CI smokes with:

```sh
./scripts/loadgen-smoke.sh
./scripts/loadgen-distributed-smoke.sh
./scripts/loadgen-signal-smoke.sh
```

Linux root/network-namespace hosts can run the gated 10,000-connection IPv4/IPv6
source-sharding integration test:

```sh
sudo ./scripts/test-loadgen-10k-connections-linux.sh
```

## Local validator run

Edit `config/loadgen/local-validator.toml` with the validator RPC endpoint, real
market IDs, a funded account ID, and local signing-key/TLS files. Then run:

```sh
target/release/market-loadgen-campaign \
  --scenario config/loadgen/local-validator.toml \
  --dry-run local --target-kind validator

target/release/market-loadgen-campaign \
  --scenario config/loadgen/local-validator.toml \
  local --target-kind validator
```

TLS mode is TLS 1.3 only. `ca_file` supplies the trust root; setting both
`client_cert_file` and `client_key_file` enables mTLS. The signing seed must be 32 raw
bytes or 64 hexadecimal characters. Secrets are loaded by the generator process and
are not serialized into plans, reports, or controller messages.

Validator mode requires the production RPC listener and trade-control path to be
enabled. A successful validator report distinguishes socket-written, acknowledged,
accepted, rejected, and failure counts; it does not infer acceptance from writes.
Dedicated test clusters may start from
`config/loadgen/node-rpc-reference-profile.toml`, whose explicit connection,
per-source, in-flight, and TLS limits are intentionally unsuitable for an exposed
production node without a separate security review.

## Distributed smoke and production layout

Create a control token of at least 16 bytes outside version control:

```sh
install -d -m 700 secrets
umask 077
printf '%s\n' 'replace-with-a-random-control-secret' > secrets/loadgen-smoke.token
```

Start the reference sink, then the controller, then all three agents (one command per
terminal or host):

```sh
target/release/market-loadgen-campaign reference-sink --listen 127.0.0.1:9900

target/release/market-loadgen-campaign \
  --scenario config/loadgen/distributed-controller-smoke.toml \
  controller --target-kind sink

target/release/market-loadgen-campaign \
  --scenario config/loadgen/distributed-agent-a-smoke.toml \
  agent --controller 127.0.0.1:9910 --target-kind sink

target/release/market-loadgen-campaign \
  --scenario config/loadgen/distributed-agent-b-smoke.toml \
  agent --controller 127.0.0.1:9910 --target-kind sink

target/release/market-loadgen-campaign \
  --scenario config/loadgen/distributed-agent-c-smoke.toml \
  agent --controller 127.0.0.1:9910 --target-kind sink
```

For production, give each generator host its own agent scenario containing only its
local source addresses, credentials, capacity, and target allow-list. The controller
scenario owns the aggregate rate and connection count. Agents connect outbound to the
controller; trading traffic goes directly from each agent to its allow-listed target.
The controller rejects unexpected/duplicate identities, invalid challenge proofs,
insufficient advertised capacity, late starts, heartbeat loss, partial reports, raw
histogram inconsistencies, and aggregate counter-conservation failures.

## Artifacts and qualification

Every live CLI run writes beneath `output.directory`:

- `resolved-plan.toml` with secret references redacted;
- `intervals.jsonl` with exact one-second counters plus p50/p95/p99/p99.9 globally,
  by action, and by region/endpoint;
- `histograms.json` with raw mergeable queue-delay and request-to-ack buckets;
- `final.json` with conserved aggregate counters and latency percentiles;
- `provenance.json` with commit, Rust compiler, host, role, and timestamp.

During steady state, local mode emits each aggregate one-second counter snapshot as
soon as every configured connection contributes. Agents stream the same snapshots
over the authenticated control connection; controllers validate them against each
agent's final report, retain each stream under
`controller/agents/<agent-id>/intervals.jsonl`, and print agent-labelled live rows. A full snapshot channel,
missing contributor, duplicate interval, or streamed/final mismatch increments metric
loss or fails the run. Interval streams and final JSON include p50/p95/p99/p99.9 for
queue and request-to-ack latency globally, by action, agent, and region/endpoint;
`histograms.json` retains final raw compatible buckets. Percentiles are always
recomputed from merged raw buckets.

Each independently collected reference-sink final JSON also includes its configured
fault mode, whether signature validation was enabled, raw mergeable
`processing_latency` buckets (complete frame read through the configured response or
fault action), and explicit histogram merge/overflow/saturation fields. The
qualification verifier requires healthy immediate-ack mode, signature validation, a
sample for every received frame, and zero sink metric errors.

Agent artifacts use `agent-<id>/`; controller artifacts use `controller/`. A run fails
if artifact creation fails. The 20M gate requires every one-second steady interval—not
the five-minute average—to contain at least 20,000,000 complete socket-written frames,
with zero metric loss and all configured failure/latency gates satisfied.

The reference campaign helper deliberately requires one controller and at least eight
generator hosts and will not manufacture a result:

```sh
./scripts/qualify-loadgen-20m.sh controller-host \
  gen-west-1 gen-west-2 gen-west-3 gen-west-4 \
  gen-east-1 gen-east-2 gen-east-3 gen-east-4
```

Its default is a provenance-only preparation pass. After staging per-host release
binaries/configs and starting independently instrumented sinks, set `EXECUTE=1` plus
`REMOTE_BINARY`, `REMOTE_CONFIG_DIR`, `REMOTE_ARTIFACT_DIR`,
`REMOTE_SINK_ARTIFACT_DIR`, `CONTROLLER_ADDRESS`, and a comma-separated `SINK_HOSTS`
list containing at least two hosts. The helper inventories and collects from the
controller, all generators, and every sink host. Once the artifacts are collected,
make the colon-separated sink finals explicit and run the fail-closed verifier:

```sh
SINK_FINALS=artifacts/sink-a.json:artifacts/sink-b.json \
  ./scripts/verify-loadgen-qualification.sh artifacts/loadgen/reference-20m-run
```

Use `config/loadgen/reference-20m.toml` as the reviewed reference, replacing the
documentation-only TEST-NET addresses, DNS names, and secret paths. Archive agent,
controller, and independently instrumented sink artifacts together. Run a separate
validator campaign and label its acknowledged/accepted capacity independently.

## Host preparation and troubleshooting

Record all tuning in campaign artifacts. At minimum, raise `nofile` above planned
sockets, confirm the ephemeral-port range, configure NIC RSS/RPS queues and interrupt
affinity, pin generator workers to physical cores, use the performance CPU governor,
and verify source IPv4/IPv6 addresses are locally assigned. Keep sink receive
saturation below 80% so the generator—not the test sink—is measured.

On each Linux generator and sink, attach the checked-in bounded profiler after the
process starts (the default 360 seconds covers warm-up plus steady state):

```sh
./scripts/profile-loadgen-process.sh "$(pgrep -n market-loadgen)" artifacts/profile-agent-a 360
```

It records `perf stat` when available, RSS/high-water/threads/FD samples, socket
summary, kernel network counters, and before/after NIC and memory snapshots. Combine
those files with the runtime's scheduler debt, bounded queue/in-flight configuration,
metric-overflow fields, and the zero-allocation benchmark output.

Common preflight failures are intentionally fatal:

- DNS or address-family mismatch: every endpoint must resolve and match its source IP;
- source bind failure: assign the address locally before starting the agent;
- TLS identity/CA/mTLS failure: fix files and server name; plaintext fallback is not
  attempted;
- insufficient connections/capacity: correct the local agent topology or controller
  partition instead of silently oversubscribing;
- rate debt/local drops: increase connections/in-flight depth or reduce offered load;
- missing heartbeat/late start: fix control reachability and clock provenance, then
  restart the entire run with a new run ID;
- conservation or sink reconciliation mismatch: treat the run as invalid and retain
  all fault artifacts for diagnosis.

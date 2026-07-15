# Load-generator acceptance ledger

This ledger maps epic #552 and tasks #553–#565 to checked-in evidence. It is
deliberately fail-closed: implementation readiness is distinct from a measured 20M
qualification.

| Issue | Implemented evidence | Remaining external evidence |
| --- | --- | --- |
| #553 architecture/contract | `ARCHITECTURE.md`; exact conservation and interval-gate tests | none |
| #554 scenario/CLI | schema-v2 validation, redacted dry-run, complete examples and CLI parsing/round-trip tests | real endpoint/account values |
| #555 production RPC | signed production request types, in-place codec, correlated out-of-order responses, live owned-order state, all-action round-trip through the production `rpc` server/backend, TLS 1.3/mTLS integration, and authentication-failing warm-up | composed-node authorization campaign |
| #556 metrics | fixed mergeable histograms; exact typed counters and rejection reasons; bounded one-second raw-histogram streams split by action, agent, region, and endpoint; overflow gates | campaign artifacts at target scale |
| #557 workload | deterministic fixed-point regimes, BBO/order distributions, bounded replay, stateful cancel/replace, one-million-action ratio test | none |
| #558 async runtime | Tokio persistent pools, fixed worker shards, bounded pipeline/slots, partial I/O, timeout, reconnect, out-of-order ack, and drain tests | 10,000 live sockets on Linux reference hosts |
| #559 topology | explicit IPv4/IPv6 source binding, DNS/source preflight, exact weighted connection/rate partition, bounded live same-region failover with exact endpoint attribution, 10,000-assignment test, Linux namespace script | execute namespace and 10,000-socket tests on Linux root host |
| #560 hot path | in-place signing/framing, open-loop deadline pacing, fixed buffers, CPU affinity, allocation benchmark | release profiles at target scale |
| #561 reference sink | production framing/signatures, plaintext and TLS 1.3/mTLS listeners, independent counters, raw mergeable processing-latency histogram with overflow/saturation gates, deterministic fault matrix, bounded malformed input | prove sink headroom and collect independent multi-host counters |
| #562 local runner | warm-up/steady/drain/cooldown, process-level SIGINT/SIGTERM cooperative-drain smoke, thresholds, artifacts, multi-endpoint/market/action test | optional real-validator local run |
| #563 distributed runner | authenticated challenge, allow-list, heartbeat/state machine, synchronized partitions, streamed raw intervals, exact merge, three-agent network and process smokes | multi-host deployment |
| #564 qualification | launch/collection/profiling/verifier scripts and reference scenario | **not complete:** 30s warm-up + 300 one-second intervals at 20M socket-written/s, independent sink reconciliation, Linux profiles, and separate real-validator campaign |
| #565 operations guide | local/validator/three-agent/reference commands, tuning, safety, troubleshooting, CI smokes | none |

The development baseline in `BASELINE.md` is not qualification evidence. Only
`verify-loadgen-qualification.sh` with independently collected sink finals can emit a
20M pass marker, and it rejects non-release, short, partial, simulated, or
non-reconciled artifacts.

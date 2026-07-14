# London / New York / Tokyo DoubleZero campaign

This directory pins the intended six-validator, three-load-agent lab shape for
issue #576. It is a deployment contract, not proof that the campaign ran. The
committed composed gate remains FAIL until three real 60 s warm-up + 600 s
steady runs reconcile through execution and Minimmit finality.

DoubleZero must run directly on each Linux x86_64 validator host, with a public
IP and no NAT. The current operator guide uses GRE, BGP over the `doublezero0`
interface, `doublezero status`, and `doublezero latency`; see the
[Malbec Labs setup guide](https://docs.malbeclabs.com/setup/). Do not install or
change DoubleZero packages as part of a benchmark run. Network onboarding,
identity files, tenant authorization, and secrets are operator-owned and stay
outside this repository.

## Fixed topology

[`topology.toml`](topology.toml) defines two validators in each of London, New
York, and Tokyo, Minimmit `n=6, f=1, M=3, L=5`, 256 logical shards, equal regional
load, 100 Gbit/s provenance, a two-NUMA host profile, NIC queues/offloads, kernel
buffers, clocks, and the exact campaign phases. Replace tokens in
[`validator.toml.example`](validator.toml.example) on each host; never commit the
rendered configs or validator keys.

Before starting a node, set the actual provisioned peer IPs and run:

```sh
export DZ_PEERS=198.51.100.10,198.51.100.11
sudo --preserve-env=DZ_PEERS ./deploy/doublezero/preflight.sh
ip -s -j link show dev doublezero0 > artifacts/preflight-interface.json
doublezero latency > artifacts/preflight-doublezero-latency.txt
```

The example IPs above are documentation addresses and must be replaced. The
route check fails if any intended peer silently uses another interface. Redact
public keys or addresses required by the operator policy before publishing an
artifact; never redact counters, timestamps, route device names, or versions.

## Campaign state machine

1. **Smoke:** validate configs, six-member committee commitments, root agreement,
   signed RPC, one M certificate, one L certificate, and an execution-final
   checkpoint at a negligible rate. Snapshot `ip -s`, `ethtool -S`, `ss -ti`,
   queue, journal, receipt, and finality counters before and after.
2. **Ramp:** increase offered load in 10% steps, holding each for 30 s. Stop on a
   sequence gap, root divergence, NIC error/drop, generator saturation,
   unexplained reconciliation loss, or positive finality-backlog slope.
3. **Steady:** after at least 60 s warm-up, collect exactly 600 one-second
   intervals at 24M offered operations/s, approximately one third per region.
   Run this three consecutive times with identical fingerprints.
4. **Drain:** stop ingress, retain validators for at least two checkpoint
   intervals, and require accepted = executed = receipted = finalized.
5. **Fault:** outside the three headline runs, repeat smoke/ramp while killing a
   validator, severing one regional link, and restarting from durable state.
   Require the documented Minimmit M/L behavior and identical finalized roots.

`market-loadgen --measured` now uses uncapped signed production RPC over
persistent Tokio connections with bounded pipelining. It requires TLS 1.3 for a
`validator` target, supports optional mTLS and explicit source-IP binding, and
reports offered/generated/socket-written/acknowledged/terminal counters
separately. The deleted private 17-byte protocol is not callable.

The controller partitions rate, connections, client IDs, nonce namespaces, RNG
streams, regions, and explicit endpoints deterministically, then HMAC-authenticates
each single-use assignment. Prepare an out-of-band 32-byte-or-longer control key,
set the controller plan's start at least five seconds in the future, and emit the
three envelopes:

```sh
cargo run --release -p market-loadgen -- controller \
  --plan artifacts/controller-plan.json \
  --agents artifacts/agents.json \
  --control-key-file /run/secrets/dexos-load-control.key \
  --output artifacts/assignments.json
```

On each load host, copy the same assignment artifact and invoke the matching
agent identity. The agent authenticates its envelope, rejects a stale steady
start, derives only its assigned identity namespace, waits for the synchronized
steady phase, and sends order traffic directly to its assigned validators:

```sh
cargo run --release -p market-loadgen -- agent \
  --assignment artifacts/assignments.json \
  --agent-id lon-load-0 \
  --control-key-file /run/secrets/dexos-load-control.key \
  --scenario deploy/doublezero/loadgen-scenario.toml \
  --signing-key-file /run/secrets/dexos-load-session.seed \
  --account-id 1001 \
  --target-profile validator \
  --packed-leases /run/secrets/lon-packed-leases.json \
  --packed-batch-size 128 \
  --packed-completion finalized \
  --source-ip 192.0.2.10 \
  --tls-server-name rpc.dexos.internal \
  --ca-cert /run/secrets/dexos-rpc-ca.pem \
  > artifacts/london-agent.json
```

The packed lease file is a JSON array with one server-issued lease per assigned
connection. Each entry supplies `endpoint`, `destination`, `session_ref`,
`account_id`, `client_id`, `nonce_base`, `first_batch_sequence`,
`first_command_sequence`, `batch_sequence_stride`, and
`command_sequence_stride`; optional `source_ip` and `max_live_orders` fields
override their defaults. For a multi-connection agent, the server must issue
globally striped sequence leases and every endpoint must appear in the
authenticated assignment. Keep the file secret even though the signing seed is
stored separately.

The same binary can launch a protocol-conformant reference sink. Its JSON is
permanently labelled `reference-sink` and is valid only for generator headroom:

```sh
cargo run --release -p market-loadgen -- reference-sink \
  --listen 0.0.0.0:9100 --max-connections 16384
```

Before a campaign, verify the installed binary surfaces:

```sh
market-loadgen --help | grep -E 'controller|agent'
market-loadgen controller --help
market-loadgen agent --help
```

If any check fails, stop. Simulation output and reference-sink capacity cannot
be submitted as validator or composed-path throughput. The current agent runs
the assigned warm-up and synchronized steady phases; controller-side live
heartbeat/report collection and the external host campaign still remain
required before a three-region result can pass.

## Required evidence

For every host and one-second interval collect interface L2 bytes/packets,
errors/drops, queue occupancy, retransmits, compression and batch distributions,
offered/generated/socket-written/acknowledged/accepted/rejected/timeout/failure
counts, regional receipt latency, finality latency/backlog, M/L certificate
counts, execution-final checkpoints, and shard roots. Record git/Cargo/toolchain,
kernel/microcode/NUMA/governor/affinity, NIC driver/firmware/offloads/MTU, exact
commands, and raw artifact SHA-256 values.

Start from [`composed-evidence.template.json`](composed-evidence.template.json),
but do not submit the template values. Set the authenticated assignment `run_id`,
full provenance, production-route evidence references, backlog observations, and
canonical ownership totals. `per_node` means the one canonical validator owner
attributed to each command, not the sum of replicated execution on all six
validators. Populate `per_shard` with exactly 256 uniquely named scopes. For
offered, accepted, executed, and finalized independently, node and shard totals
must each conserve the three regional agent totals.

Each agent HMAC-binds the exact report digest to its original authenticated
assignment envelope. Build each run artifact from the three agent stdout files,
the same out-of-band control key, and the operator evidence. The key is read
locally and is never copied into either artifact. The command verifies every
assignment and report tag, writes a deterministic raw input artifact, hashes it,
and refuses to emit a run if any second, lifecycle counter, histogram count,
region, node, or shard is missing or inconsistent:

```sh
cargo run --release -p benchmarks --bin composed-build -- \
  --manifest crates/benchmarks/workloads/global-20m-v1.toml \
  --agent artifacts/london-agent.json \
  --agent artifacts/new-york-agent.json \
  --agent artifacts/tokyo-agent.json \
  --control-key-file /run/secrets/dexos-load-control.key \
  --evidence artifacts/run-1-evidence.json \
  --raw-output artifacts/run-1-raw.json \
  --output artifacts/run-1.json
```

A structurally complete run is still written when its measured throughput is
below 20M/s; it is labelled `FAIL` rather than discarded. Missing or internally
inconsistent evidence produces no composed run. The campaign gate below owns
the final nonzero exit status for a failed three-run qualification.

Evaluate three completed run JSON files only with:

```sh
cargo run --release -p benchmarks --bin composed-gate -- \
  --manifest crates/benchmarks/workloads/global-20m-v1.toml \
  --run artifacts/run-1.json \
  --run artifacts/run-2.json \
  --run artifacts/run-3.json \
  --output artifacts/gate.json
```

Any missing scope, fewer than six manifest validators, fewer than 256 unique
shards, or regional/node/shard totals that do not conserve the global finalized
count now fails the gate.

# DexOS production-readiness review

> Review date: 2026-07-14
> Reviewed branch: `minimmit/step-2-phase-1-wire-types-digests-codec` after integration with `main`
> Verdict: **RELEASE BLOCKED — not suitable for real funds or public trading**
> Canonical composition blocker: [#312](https://github.com/joeblau/dexos/issues/312)

## Executive summary

DexOS now has substantial, tested implementations for deterministic execution,
authenticated networking, Minimmit consensus, packed order ingress, durable
packed batches, checkpoint verification, SDKs, release artifacts, and process
operations. The production-readiness issues from the 2026-07-11 audit have
largely been implemented and closed; the previous version of this document was
therefore no longer an accurate description of the repository.

The remaining release blocker is composition. `marketd run` starts supervised
placeholder role queues and observability, but it does not instantiate the
implemented data-plane, storage, execution, peer, or consensus components. A
host can install and supervise this binary, but it cannot yet operate a
restart-safe validator or exchange.

The bare-metal scripts deliberately expose that boundary:

- smoke operation requires `DEXOS_ACKNOWLEDGE_SKELETON=1`;
- `/readyz` means process bootstrap readiness, not exchange readiness;
- `bare-metal-verify --production-gate` fails intentionally;
- the example configuration prohibits public traffic and real assets.

## Current evidence

The integrated branch is checked with the repository-pinned toolchain and the
same engine exclusions as CI:

| Check | Result |
|---|---|
| `cargo fmt --all --check` | Pass |
| workspace Clippy with `-D warnings` | Pass |
| workspace unit and integration tests | Pass |
| Rust, TypeScript, and Python SDK tests | Pass |
| deterministic-core no-float, dependency, and unsafe guards | Pass |
| bare-metal script syntax and staged install checks | Pass |

These checks establish component correctness and packaging consistency. They do
not establish a composed validator, crash-safe consensus participation, or
real-funds safety.

## Supported release boundary

The current bare-metal bundle supports only a pre-production process smoke
deployment:

1. verify a pinned release digest;
2. install an immutable release and atomically select it;
3. validate host, configuration, ownership, and permission invariants;
4. run `marketd` under a hardened systemd unit;
5. exercise metrics, `/livez`, `/readyz`, graceful stop, upgrade, rollback, and
   uninstall workflows.

It does **not** support validator, sequencer, custody, public RPC, or trading
operation. See [the bare-metal runbook](runbooks/BARE_METAL.md) for the exact
operator procedure and guardrails.

## Remaining production blockers

| ID | Missing composition | Release impact | Required proof |
|---|---|---|---|
| BM-001 | Startup composition | `marketd run` never constructs `PackedValidatorCore`, `PackedServer`, `TcpTransport`, `ConsensusDriver`, or `execution::Engine`. | Readiness stays false until recovery, listeners, execution, and consensus are operational. |
| BM-002 | Identity and genesis | Config has no local validator identity, nonzero network ID, signed genesis manifest, consensus safety-state path, or authenticated bootstrap peer descriptors. | Every node proves one identity and one genesis/network before admitting or voting. |
| BM-003 | Session leases | Packed sessions require pre-resolved authority and sequence leases, but no authoritative lease registry or signed startup manifest exists. | Restart reconstructs non-overlapping leases without inventing authority or reusing sequence numbers. |
| BM-004 | Permissioned peer mesh | The transport exists, but there is no allowlisted accept/dial manager, reconnect loop, duplicate-session policy, consensus fanout, or connectivity readiness. | Multi-node tests prove authenticated membership, reconnect, bounded failure, and protocol progress. |
| BM-005 | Block payload path | Consensus proposals commit a payload root, but no builder, durable payload store, or follower synchronization protocol supplies the commands to execute. | Every validator executes the identical available payload for every certified block. |
| BM-006 | Consensus driver contract | Proposal effects omit the current epoch/view; commit effects omit the certified state root/certificate; slash evidence is not surfaced. | Driver events carry all signing/finality evidence and a supervised loop persists or gossips every safety-relevant effect. |
| BM-007 | Checkpoint construction | Packed execution does not retain the canonical command/result hash streams required to build checkpoints. | Finalized checkpoints are built from the exact executed range and verified end to end. |
| BM-008 | Authoritative recovery | Packed recovery assumes an already-correct engine prefix; Minimmit safety state and execution snapshots are not durable. A fresh restart could sign conflicting votes. | `kill -9` recovery restores identical state, locks, proofs, leases, payloads, checkpoints, and resumes without double-signing. |
| BM-009 | End-to-end operations | Current verification proves process health only. | A real signed order is durably admitted, sequenced, executed, finalized, queried, then recovered identically after crash and failover. |

## Implementation order

1. Extend configuration with identity, genesis/network, authenticated peers,
   safety-state, snapshot, packed TLS, and signed session-manifest inputs.
2. Add authoritative execution and consensus persistence before enabling votes.
3. Correct the node driver event contract and implement the durable block
   payload/checkpoint path.
4. Compose a permissioned peer manager, packed/RPC listeners, execution,
   Minimmit, checkpoint finality, and critical-task supervision in `marketd`.
5. Make readiness depend on recovered storage, bound listeners, identity,
   required peers, and consensus/execution health.
6. Replace the intentional production-gate failure with end-to-end crash,
   restart, and multi-node failover assertions only after those paths exist.

The smallest useful intermediate milestone is a TLS-only, single-node durable
packed execution mode that emits `Admitted` and `Executed` receipts. It must be
named and documented as an execution service—not a validator or finalized
exchange—and must refuse validator, sequencer, custody, public-asset, and
finality claims.

## Performance work

The open 20M operations/s load and performance campaigns
([#552](https://github.com/joeblau/dexos/issues/552) and
[#567](https://github.com/joeblau/dexos/issues/567)) remain separate from this
review. Their code may improve components, but no throughput result can satisfy
BM-001 through BM-009 or permit production deployment.

## Required external assurance

Even after the composition gate passes, real-funds launch still requires an
independent cryptographic/protocol review, application-security assessment,
chain-specific finality validation, operational game days, and benchmark/fault
campaigns on the supported bare-metal topology. Component tests and internal
simulation are prerequisites, not substitutes, for those reviews.

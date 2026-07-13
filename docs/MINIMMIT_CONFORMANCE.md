# Minimmit conformance status

## Decision

A Quint model and trace-replay harness are explicitly deferred. The roadmap
referenced `pipeline/minimmit/quint/`, but no model or owned specification
toolchain exists there. Creating a nominal model without an owner would add a
second, unmaintained protocol description rather than an independent oracle.

## Interim conformance oracle

Until a formal model is funded, the shipped protocol is gated by three layers:

1. `crypto::quorum::tests::honest_intersection_holds_over_random_sized_committees`
   checks the `W ≥ 5B+1`, `M=2B+1`, `L=W-B` honest-intersection invariant over
   randomized weighted committees.
2. The `consensus::minimmit` unit tests exercise R1–R7, parent validity,
   M-versus-L formation, non-slashable R6, mandatory execution L-certificates,
   epoch rotation, admission bounds, and deterministic `step` replay.
3. `simulation::minimmit_tests::{s1_*,s2_*,s3_*,s4_*}` and the liveness tests
   cover honest agreement, Byzantine equivocation, invalid signatures,
   equivocating/crashed leaders, partition healing, R7 re-dissemination,
   execution finality, epoch changes, and bit-identical replay.

CI runs these through `cargo test --workspace --locked` and the dedicated
`consensus simulation proof` job. This is an implementation-derived oracle, not
a substitute for an independently reviewed formal specification.

## Revisit trigger

The deferral expires before any of the following is merged:

- raising `MAX_VALIDATORS` or changing the signer bitmap width;
- replacing ed25519 certificates with BLS aggregation;
- changing `M`, `L`, `select_parent`, `valid_parent`, R6, or execution-finality
  semantics;
- launching a production network that will custody real value.

At that point an owner must create `pipeline/minimmit/quint/`, model views,
notarize/nullify, both thresholds, parent selection/validation, ordering
finality, and execution certification, then replay generated traces through
`MinimmitReplica::step`. The harness should follow the repository's
`crates/chain-adapter/src/conformance.rs` lineage: shared abstract traces,
adapter-driven execution, and explicit state/effect equivalence assertions.

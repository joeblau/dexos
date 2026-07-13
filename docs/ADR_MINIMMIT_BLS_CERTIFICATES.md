# ADR: Minimmit BLS certificate seam

Status: deferred, demand-gated design. No BLS dependency or runtime path is
introduced by this ADR.

## Context

Minimmit currently aliases `Certificate` to the repository's ed25519
`QuorumCertificate`: a message digest, signer bitmap, and one 64-byte signature
per signer. `MinimmitCommittee::assemble` and `verify` are the production
construction and verification boundary. The reactor asks that boundary to
assemble or verify at `ThresholdKind::Advance` (M) or `ThresholdKind::Finalize`
(L); protocol rules do not implement signature aggregation themselves.

## Deferred design

A BLS backend would replace the alias with a certificate carrying the signed
message, an aggregate signature (approximately 96 bytes for a BLS12-381 G2
signature), and the signer/weight evidence needed to prove the M or L bar. The
crypto crate would own key validation, proof-of-possession or an equivalent
rogue-key defense, deterministic aggregation, subgroup checks, and batch-safe
verification. `MinimmitCommittee::{assemble,verify}` would select the threshold
and backend. Wire fixtures and committee tests would change; R1–R7,
`MinimmitReplica::step`, parent rules, and the finality ladder would not.

Before implementation, direct ed25519 certificate field construction in test
fixtures must be replaced by committee-backed helpers. The wire version and
domain separation must be bumped as a coordinated hard fork. Mixed certificate
backends in one epoch are forbidden.

## Validator-cap prerequisites

The shipped certificate has a `u16` bitmap and therefore a 16-validator cap.
Raising it to 64 requires, at minimum, a `u64` or bounded multiword bitmap,
updated canonical encoding, codec/version negotiation, admission and allocation
bounds, cross-architecture golden vectors, revised sizing/config checks, and a
coordinated wire upgrade. Raising it beyond 64 requires either a wider bounded
signer representation or a BLS certificate with an accountable signer/weight
commitment; BLS aggregation alone does not remove membership and rogue-key
requirements.

Any cap raise or BLS adoption also activates the formal-conformance trigger in
[`MINIMMIT_CONFORMANCE.md`](MINIMMIT_CONFORMANCE.md). Until demand justifies that
work, the linear ed25519 path remains the only supported backend.

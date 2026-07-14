# Minimmit hard-fork migration

The Minimmit release is consensus- and wire-incompatible with earlier nodes.
It changes committee sizing to `n ≥ 5f+1` (minimum six for `f=1`), adds explicit
validator weights, uses distinct `M=2f+1` and `L=n-f` thresholds, standardizes
validator indices as `u16`, and replaces the old message family with `Propose`,
`Notarize`, `Nullify`, `Notarization`, `Nullification`, and `ExecAttest`.

Rust source consumers that construct `QuorumCertificate` directly must also
migrate the public `signatures` field from `Vec<[u8; 64]>` to the bounded
`crypto::QuorumSignatures` container (for example, with
`signatures.into_iter().collect()`). Its serde sequence representation and the
v2 packed QC bytes are unchanged; this is a source-API break that removes the
certificate hot-path heap allocation, not another wire-version change.

This cannot be deployed as a rolling upgrade. Operators must agree on the last
old checkpoint, stop every validator, install an identical six-or-more-member
validator descriptor and `delta_ms`, deploy the same Minimmit build, verify the
L-set commitment out of band, and restart from the coordinated epoch boundary.
Mixed-version peers must remain disconnected. Before enabling traffic, confirm
that all nodes report the same epoch, canonical L commitment, checkpoint root,
and finalized height.

There is no live production network today, so this runbook records the required
coordination contract rather than an active-network ceremony.

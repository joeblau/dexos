# DexOS security status

DexOS is pre-production research software. It has not completed an independent
security audit and must not custody real assets or accept public trading traffic.
The production-readiness backlog is tracked in GitHub; passing CI is not a claim
of production safety.

## Implemented controls

- Workspace Rust code denies unsafe code by default; CI checks the deterministic
  core for floating-point operations and forbidden dependency directions.
- Binary decoders use bounded lengths and typed errors. Cryptographic operations
  use maintained RustCrypto implementations.
- Mock EVM/SVM adapters and benchmark/load-generator dependencies are excluded
  from the default `marketd` feature set.
- CI dependencies are immutable-SHA pinned and workflow tokens are read-only.
- **secp256k1 low-S (EIP-2)**: EVM signatures are normalized on sign and high-S
  encodings are rejected on verify (malleability-resistant replay caches).
- **EIP-712 typed data**: domain separators bind `name`, `version`, `chainId`,
  and `verifyingContract`; digests use the standard
  `keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ structHash)` prehash.
- **Custody authorize/settle**: threshold signing requires a verified wallet or
  session authorization; settle requires a matching pending id/amount and a
  non-trivial finality attestation that meets chain policy confirmations.
- **Light-client validator sets**: only weak-subjectivity bootstrap installs the
  first set free; later epochs require a quorum certificate from the prior set.
- **Consensus equivocation**: double-sign and proposal forks halt the offender's
  QC weight, record serializable slash evidence, and refuse certification for
  forked rounds.

## Wallet / EIP-1271 trust model (honest)

EIP-1271 support is an **offline owner-key model**:

1. The smart-wallet **contract address** is bound into the proof and must equal
   the claimed wallet address.
2. Verification checks that a designated **owner secp256k1 key** produced a
   valid low-S signature over the message (or EIP-712 digest).

DexOS does **not** currently call the on-chain `isValidSignature(bytes32,bytes)`
entry point. Wallets that authorize via passkeys, modules, or multi-sig without
publishing an owner key are **not** fully supported. Production deployments that
require true contract-defined validation must add a chain-adapter
`isValidSignature` check before treating an EIP-1271 proof as final.

## Known limitations

- `marketd run` is a composition skeleton; durable execution, production RPC,
  consensus, recovery, and full custody integration remain incomplete.
- On-chain EIP-1271 (`isValidSignature`) is not yet invoked; see trust model above.
- Settlement finality proofs are verified against policy fields; full
  header-chain re-verification lives in `chain-adapter` and must be composed by
  the node.
- Constant-time behavior has not been independently verified. We rely on the
  guarantees of upstream cryptographic libraries only where documented by them.
- Graceful shutdown drains current in-memory queues but is not yet a durable,
  crash-safe operational lifecycle.

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in a public issue. Use GitHub's
private vulnerability reporting for this repository. Include affected commit,
reproduction steps, impact, and any suggested mitigation. Maintainers will
acknowledge a report within five business days and coordinate disclosure after a
fix. There is currently no bug-bounty program or guaranteed response SLA.

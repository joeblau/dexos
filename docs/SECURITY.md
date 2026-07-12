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

## Known limitations

- `marketd run` is a composition skeleton; durable execution, production RPC,
  consensus, recovery, and custody integration are incomplete.
- EIP-712/EIP-1271 wallet support, full external-chain verification, independent
  custody operation, and end-to-end withdrawal authorization are not complete.
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

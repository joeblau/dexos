# DexOS Security Boundaries

Security is structural: narrow, typed interfaces between subsystems, and every
externally-supplied byte treated as untrusted.

## Trust boundaries

| Boundary | Guarantee |
|---|---|
| networking ↔ decoding | `codec` decoders are total; malformed/truncated bytes return a typed `CodecError`, never a panic or unchecked allocation. |
| decoding ↔ command validation | commands are validated (structure, signatures, nonces) before execution. |
| validation ↔ deterministic execution | the engine only sees validated, sequenced commands; every handler returns a typed `ExecutionError`. |
| consensus ↔ custody | consensus *authorizes* a finalized withdrawal; custody signers *independently verify* the certificate before signing. Validators ≠ custody signers. |
| consensus ↔ chain adapters | chain adapters observe/attest deposits; the replicated ledger reserves/debits **before** any external transaction is signed. |
| full nodes ↔ light nodes | light nodes verify quorum signatures + Merkle proofs and expose an explicit `Verified`/`Unverified` status — never a trusted proxy. |
| sponsors ↔ protocol governance | sponsor rights are bounded by protocol constraints; slashing only on objectively-measurable faults. |
| oracle producers ↔ aggregation | observations are individually signed; aggregation applies staleness/venue/outlier filters + threshold signatures. |
| resolvers ↔ settlement | resolution requires a threshold committee quorum over immutable rules with evidence hashes and a challenge window. |

## Untrusted-input handling

- **No panics on untrusted input.** Every decoder and command handler returns a
  `Result` with a typed error. Enforced by pervasive `never_panics_on_arbitrary_bytes`
  tests (deterministic LCG-driven fuzzing) across `codec`, `types::decimal`,
  `crypto`, `storage`, `consensus`, `rpc`, `light-client`, custody, chain adapters,
  and every market crate.
- **No silent integer truncation.** `cast_possible_truncation` is a hard clippy
  error workspace-wide; narrowing conversions use `TryFrom` and return errors.
- **No floating point in deterministic paths.** Enforced by `check-no-float.sh`
  over the core crates. Fixed-point arithmetic defines scale, overflow, rounding,
  and saturation explicitly per operation.
- **Bounded allocation.** Length prefixes are validated against remaining input
  before allocation; payout vectors, validator sets, and frames have documented
  maximums.

## Cryptography

- ed25519 (node identity, oracle, custody, quorum, Solana), secp256k1/EIP-712
  (EVM), EIP-1271 (smart wallets). Verification is total and constant-time via the
  underlying libraries; scalar reference implementations are the bit-exact target
  for SIMD kernels.
- Quorum/threshold certificates verify signed weight against a threshold and
  reject unknown/duplicate signers and tampered messages.

## Unsafe policy

`unsafe_code = "deny"` workspace-wide. The only sanctioned exception is a narrow,
documented, per-item opt-in inside an isolated performance module (`simd`), each
`unsafe` block carrying a `// SAFETY:` invariant and covered by an equivalence
test. `check-unsafe.sh` additionally forbids any unannotated `unsafe` in the
deterministic core.

## Reporting

This is a research/reference implementation. Report issues via the repository
tracker. Do not place third-party RPC providers in the trading path; nodes connect
directly to the nearest exchange node for authentication, orders, and market data.

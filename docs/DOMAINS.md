# Domain separation catalog

All cryptographic domain tags live in [`crates/crypto/src/domain.rs`](../crates/crypto/src/domain.rs)
and are mixed with payload bytes via `crypto::hash_domain` (length-prefixed SHA-256).

**Rule:** never invent a second spelling of the same purpose (`DEXOS/…`,
`dexos.custody.…`, ad-hoc keccak-only prefixes). Add a constant to the registry
instead.

## Withdrawal family

| Domain constant | Tag | Used by |
|-----------------|-----|---------|
| `DOMAIN_WITHDRAWAL_ID` | `dexos:custody:withdrawal-id:v1` | `custody::WithdrawalRequest::id`, `chain_adapter::WithdrawalRequest::id` |
| `DOMAIN_WITHDRAWAL_AUTH` | `dexos:custody:withdrawal-auth:v1` | `custody::withdrawal_authorization_digest` (checkpoint inclusion) |
| `DOMAIN_WITHDRAWAL_CERT` | `dexos:custody:withdrawal-cert:v1` | `chain_adapter::WithdrawalCertificate` (observer settlement) |
| `DOMAIN_DEPOSIT` | `dexos:custody:deposit:v1` | `chain_adapter` deposit certificates |

Two **types** of certificate remain (authorization vs on-chain settlement) but
they share one **namespace** for ids and digests so they cannot be confused at
the domain layer.

## Other tags

Merkle/state/oracle/command domains also live in the same registry (`DOMAIN_LEAF`,
`DOMAIN_NODE`, …). See `crypto::domain::ALL_DOMAINS` for the full list.

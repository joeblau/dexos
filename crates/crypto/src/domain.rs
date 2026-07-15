//! Canonical domain-separation tags for DexOS commitments and wire digests.
//!
//! # Convention
//!
//! All tags use the form `dexos:<subsystem>:<purpose>:vN` and are mixed with
//! payload bytes exclusively through [`crate::hash_domain`] (length-prefixed
//! SHA-256). Callers must **not** invent parallel tags (e.g. `DEXOS/...` or
//! dotted `dexos.custody...` forms) — a dual scheme is how withdrawal
//! certificates previously diverged between crates.
//!
//! # Withdrawal lifecycle (two artifacts, one domain family)
//!
//! | Stage | Type (crate) | Domain |
//! |-------|--------------|--------|
//! | User / ledger withdrawal id | `custody::WithdrawalId`, `chain_adapter::WithdrawalId` | [`DOMAIN_WITHDRAWAL_ID`] |
//! | Consensus authorization digest (checkpoint inclusion) | `custody::withdrawal_authorization_digest` | [`DOMAIN_WITHDRAWAL_AUTH`] |
//! | On-chain settlement certificate (observers) | `chain_adapter::WithdrawalCertificate` | [`DOMAIN_WITHDRAWAL_CERT`] |
//!
//! Both `custody` and `chain-adapter` re-export these constants; there is a
//! single source of truth here.

// ---- merkle / state (also defined as aliases in `hash` for historic paths) ----

/// Merkle leaf payload.
pub const DOMAIN_LEAF: &[u8] = b"dexos:leaf:v1";
/// Merkle internal node.
pub const DOMAIN_NODE: &[u8] = b"dexos:node:v1";
/// Per-account commitment.
pub const DOMAIN_ACCOUNT: &[u8] = b"dexos:account:v1";
/// Per-market commitment.
pub const DOMAIN_MARKET: &[u8] = b"dexos:market:v1";
/// Sequenced command.
pub const DOMAIN_COMMAND: &[u8] = b"dexos:command:v1";
/// Execution receipt.
pub const DOMAIN_EXECUTION: &[u8] = b"dexos:execution:v1";
/// Canonical execution-ledger transition state.
pub const DOMAIN_EXECUTION_LEDGER_STATE: &[u8] = b"dexos:execution:ledger-state:v1";
/// Canonical execution-layer session authorization and replay state.
pub const DOMAIN_EXECUTION_SESSION_STATE: &[u8] = b"dexos:execution:session-state:v1";
/// Canonical order-book transition state (price levels, FIFO priority, and
/// future-behavior caches).
pub const DOMAIN_ORDERBOOK_STATE: &[u8] = b"dexos:orderbook:state:v3";
/// Canonical stored risk-engine transition state.
pub const DOMAIN_RISK_STATE: &[u8] = b"dexos:risk:state:v1";
/// Oracle observation / certificate body.
pub const DOMAIN_ORACLE: &[u8] = b"dexos:oracle:v1";
/// Canonical validator-set commitment.
pub const DOMAIN_VALIDATOR_SET: &[u8] = b"dexos:validator-set:v1";
/// Decision-market action/outcome confirmation.
pub const DOMAIN_DECISION: &[u8] = b"dexos:decision:v1";

// ---- custody / chain-adapter withdrawal family ----

/// Deterministic withdrawal request id (user + ledger).
///
/// Preimage is the canonical request body (account, chain, destination, amount,
/// nonce, …). Both `custody` and `chain-adapter` derive ids with this tag.
pub const DOMAIN_WITHDRAWAL_ID: &[u8] = b"dexos:custody:withdrawal-id:v1";

/// Consensus authorization digest committed under a finalizing checkpoint.
///
/// Binds the full request, confirmations, and ledger reservation fields so a
/// quorum over an unrelated checkpoint cannot authorize a different withdrawal.
pub const DOMAIN_WITHDRAWAL_AUTH: &[u8] = b"dexos:custody:withdrawal-auth:v1";

/// Observer settlement certificate body (destination-chain finality attestation).
pub const DOMAIN_WITHDRAWAL_CERT: &[u8] = b"dexos:custody:withdrawal-cert:v1";

/// Deposit observation / certificate body (entry path).
pub const DOMAIN_DEPOSIT: &[u8] = b"dexos:custody:deposit:v1";

/// Quorum-signed validator-set transition (light-client / consensus epoch change).
///
/// Preimage binds `(old_epoch, new_epoch, new_set_commitment)` so a committee can
/// only install a successor set that the prior committee certified.
pub const DOMAIN_VALIDATOR_SET_TRANSITION: &[u8] = b"dexos:validator-set-transition:v1";

/// Every registered domain tag (for docs, fuzzing, and "no dual scheme" tests).
pub const ALL_DOMAINS: &[&[u8]] = &[
    DOMAIN_LEAF,
    DOMAIN_NODE,
    DOMAIN_ACCOUNT,
    DOMAIN_MARKET,
    DOMAIN_COMMAND,
    DOMAIN_EXECUTION,
    DOMAIN_EXECUTION_LEDGER_STATE,
    DOMAIN_EXECUTION_SESSION_STATE,
    DOMAIN_ORDERBOOK_STATE,
    DOMAIN_RISK_STATE,
    DOMAIN_ORACLE,
    DOMAIN_VALIDATOR_SET,
    DOMAIN_DECISION,
    DOMAIN_WITHDRAWAL_ID,
    DOMAIN_WITHDRAWAL_AUTH,
    DOMAIN_WITHDRAWAL_CERT,
    DOMAIN_DEPOSIT,
    DOMAIN_VALIDATOR_SET_TRANSITION,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_domain;
    use std::collections::HashSet;

    #[test]
    fn all_domain_tags_are_unique() {
        let mut seen = HashSet::new();
        for d in ALL_DOMAINS {
            assert!(
                seen.insert(*d),
                "duplicate domain tag: {:?}",
                std::str::from_utf8(d)
            );
        }
    }

    #[test]
    fn withdrawal_family_is_domain_separated() {
        let body = b"same-preimage";
        let id = hash_domain(DOMAIN_WITHDRAWAL_ID, body);
        let auth = hash_domain(DOMAIN_WITHDRAWAL_AUTH, body);
        let cert = hash_domain(DOMAIN_WITHDRAWAL_CERT, body);
        assert_ne!(id, auth);
        assert_ne!(auth, cert);
        assert_ne!(id, cert);
    }

    #[test]
    fn tags_follow_dexos_colon_convention() {
        for d in ALL_DOMAINS {
            let s = std::str::from_utf8(d).unwrap();
            assert!(
                s.starts_with("dexos:"),
                "tag {s:?} must use dexos:<subsystem>:… form"
            );
            assert!(
                !s.contains('/'),
                "tag {s:?} must not use legacy DEXOS/ slash form"
            );
            assert!(
                !s.contains('.'),
                "tag {s:?} must not use legacy dotted dexos.custody form"
            );
        }
    }
}

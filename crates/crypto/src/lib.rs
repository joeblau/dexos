//! `crypto` — deterministic hashing, Merkle commitments, multi-scheme signature
//! verification, and quorum/threshold certificates for the DexOS kernel.
//!
//! Pure and deterministic: no async runtime, no networking, no storage, no float.
//! The scalar implementations here are the canonical bit-exact target for the
//! future SIMD kernels in the `simd` epic.

pub mod domain;
pub mod hash;
pub mod merkle;
pub mod quorum;
pub mod signature;

pub use domain::{
    ALL_DOMAINS, DOMAIN_ACCOUNT, DOMAIN_COMMAND, DOMAIN_DECISION, DOMAIN_DEPOSIT, DOMAIN_EXECUTION,
    DOMAIN_EXECUTION_LEDGER_STATE, DOMAIN_EXECUTION_REPLAY_STATE, DOMAIN_EXECUTION_SESSION_STATE,
    DOMAIN_EXECUTION_STATE, DOMAIN_LEAF, DOMAIN_MARKET, DOMAIN_NODE, DOMAIN_ORACLE,
    DOMAIN_ORDERBOOK_STATE, DOMAIN_RISK_STATE, DOMAIN_VALIDATOR_SET,
    DOMAIN_VALIDATOR_SET_TRANSITION, DOMAIN_WITHDRAWAL_AUTH, DOMAIN_WITHDRAWAL_CERT,
    DOMAIN_WITHDRAWAL_ID,
};
pub use hash::{hash_domain, hash_domain_parts, hash_leaf, hash_node, keccak256};
pub use merkle::{merkle_root, verify_proof, MerkleError, MerkleTree};
pub use quorum::{
    minimmit_thresholds, minimmit_unit_byzantine_bound, require_minimmit_sizing, QuorumCertificate,
    QuorumError, QuorumSignatures, ThresholdSigners, Validator, ValidatorSet, MAX_VALIDATORS,
    QC_PACKED_HEADER_LEN, QC_WIRE_VERSION, VALIDATOR_SET_VERSION,
};
#[allow(deprecated)]
pub use signature::batch_verify_ed25519;
pub use signature::{
    eip712_digest, eip712_domain_separator, eip712_hash_struct, is_low_s_secp256k1, verify_ed25519,
    verify_ed25519_all, verify_eip1271, verify_eip1271_prehash, verify_eip712,
    verify_secp256k1_evm, verify_secp256k1_prehash, CachedEd25519Key, CryptoError, Eip712Domain,
    EvmKeyPair, KeyPair,
};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "crypto";

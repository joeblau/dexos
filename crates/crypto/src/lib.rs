//! `crypto` — deterministic hashing, Merkle commitments, multi-scheme signature
//! verification, and quorum/threshold certificates for the DexOS kernel.
//!
//! Pure and deterministic: no async runtime, no networking, no storage, no float.
//! The scalar implementations here are the canonical bit-exact target for the
//! future SIMD kernels in the `simd` epic.

pub mod hash;
pub mod merkle;
pub mod quorum;
pub mod signature;

pub use hash::{
    hash_domain, hash_leaf, hash_node, keccak256, DOMAIN_ACCOUNT, DOMAIN_COMMAND, DOMAIN_EXECUTION,
    DOMAIN_LEAF, DOMAIN_MARKET, DOMAIN_NODE, DOMAIN_ORACLE,
};
pub use merkle::{merkle_root, verify_proof, MerkleError, MerkleTree};
pub use quorum::{QuorumCertificate, QuorumError, ThresholdSigners, Validator, ValidatorSet};
pub use signature::{
    batch_verify_ed25519, verify_ed25519, verify_eip1271, verify_secp256k1_evm, CryptoError,
    EvmKeyPair, KeyPair,
};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "crypto";

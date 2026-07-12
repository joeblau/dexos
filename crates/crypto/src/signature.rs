//! Multi-scheme signature verification and deterministic key generation.
//!
//! - **ed25519** — node identity, oracle, custody, quorum, and Solana (SVM) wallets.
//! - **secp256k1 / EIP-712** — EVM wallets: ECDSA over a keccak-256 message digest.
//! - **EIP-1271** — smart-wallet authorization modeled as the owner secp256k1 key.
//!
//! Verification is total: malformed keys/signatures return a typed [`CryptoError`],
//! never a panic. Scalar reference; SIMD batch kernels must match bit-for-bit.

use ed25519_dalek::{
    Signature as EdSignature, Signer, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey,
};
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{
    Signature as K256Signature, SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey,
};

use crate::hash::keccak256;

/// A signature-verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// The public key bytes were malformed.
    #[error("malformed public key")]
    MalformedKey,
    /// The signature bytes were malformed.
    #[error("malformed signature")]
    MalformedSignature,
    /// The signature did not verify against the key and message.
    #[error("invalid signature")]
    InvalidSignature,
}

/// An ed25519 keypair (node identity, oracle, custody, quorum).
#[derive(Debug, Clone)]
pub struct KeyPair {
    signing: EdSigningKey,
}

impl KeyPair {
    /// Deterministically derive a keypair from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: EdSigningKey::from_bytes(seed),
        }
    }

    /// The 32-byte public key.
    pub fn public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Sign a message, returning the 64-byte signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

/// Verify an ed25519 signature.
pub fn verify_ed25519(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let vk = EdVerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::MalformedKey)?;
    let sig = EdSignature::from_bytes(signature);
    vk.verify_strict(message, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Verify N ed25519 signatures. Results are bit-identical to calling
/// [`verify_ed25519`] sequentially over the same inputs.
///
/// This is a sequential multi-verify helper (not a cryptographic batch
/// verification algorithm with shared random linear combination). The name
/// reflects that semantics; prefer it over the deprecated
/// [`batch_verify_ed25519`] alias.
pub fn verify_ed25519_all(items: &[([u8; 32], Vec<u8>, [u8; 64])]) -> Vec<bool> {
    items
        .iter()
        .map(|(pk, msg, sig)| verify_ed25519(pk, msg, sig).is_ok())
        .collect()
}

/// Deprecated alias for [`verify_ed25519_all`].
///
/// Kept so existing call sites continue to compile; the name `batch_verify`
/// overstated the algorithm (it is sequential, not a true batch proof).
#[deprecated(note = "renamed to verify_ed25519_all — sequential multi-verify, not crypto batch")]
pub fn batch_verify_ed25519(items: &[([u8; 32], Vec<u8>, [u8; 64])]) -> Vec<bool> {
    verify_ed25519_all(items)
}

/// An EVM (secp256k1) keypair for EIP-712-style signing over keccak-256 digests.
#[derive(Debug, Clone)]
pub struct EvmKeyPair {
    signing: K256SigningKey,
}

impl EvmKeyPair {
    /// Derive from a 32-byte seed (the scalar). Errors if the scalar is invalid.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, CryptoError> {
        Ok(Self {
            signing: K256SigningKey::from_slice(seed).map_err(|_| CryptoError::MalformedKey)?,
        })
    }

    /// The SEC1-encoded (compressed) public key bytes.
    pub fn public_sec1(&self) -> Vec<u8> {
        self.signing.verifying_key().to_sec1_bytes().to_vec()
    }

    /// Sign the keccak-256 digest of `message`.
    pub fn sign_evm(&self, message: &[u8]) -> Result<[u8; 64], CryptoError> {
        let digest = keccak256(message);
        let sig: K256Signature = self
            .signing
            .sign_prehash(digest.as_slice())
            .map_err(|_| CryptoError::InvalidSignature)?;
        let bytes = sig.to_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

/// Verify a secp256k1/EIP-712 signature: ECDSA over `keccak256(message)`.
pub fn verify_secp256k1_evm(
    public_key_sec1: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let vk = K256VerifyingKey::from_sec1_bytes(public_key_sec1)
        .map_err(|_| CryptoError::MalformedKey)?;
    let sig = K256Signature::from_slice(signature).map_err(|_| CryptoError::MalformedSignature)?;
    let digest = keccak256(message);
    vk.verify_prehash(digest.as_slice(), &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Verify an EIP-1271 smart-wallet signature. Models the wallet's authorization
/// as its owner secp256k1 key signing the message digest.
pub fn verify_eip1271(
    owner_public_key_sec1: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    verify_secp256k1_evm(owner_public_key_sec1, message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_known_answer_valid_and_tampered() {
        let kp = KeyPair::from_seed(&[7u8; 32]);
        let pk = kp.public();
        let msg = b"authorize session";
        let sig = kp.sign(msg);
        assert!(verify_ed25519(&pk, msg, &sig).is_ok());
        assert_eq!(
            verify_ed25519(&pk, b"different", &sig),
            Err(CryptoError::InvalidSignature)
        );
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(verify_ed25519(&pk, msg, &bad).is_err());
    }

    #[test]
    fn secp256k1_evm_known_answer_valid_and_tampered() {
        let kp = EvmKeyPair::from_seed(&[9u8; 32]).unwrap();
        let pk = kp.public_sec1();
        let msg = b"withdraw 100 usdc";
        let sig = kp.sign_evm(msg).unwrap();
        assert!(verify_secp256k1_evm(&pk, msg, &sig).is_ok());
        assert!(verify_secp256k1_evm(&pk, b"withdraw 200 usdc", &sig).is_err());
        // EIP-1271 delegates to the owner key.
        assert!(verify_eip1271(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn wrong_message_never_verifies_property() {
        let kp = KeyPair::from_seed(&[3u8; 32]);
        let pk = kp.public();
        let mut state = 1u64;
        for _ in 0..2000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let m = state.to_le_bytes();
            let sig = kp.sign(&m);
            assert!(verify_ed25519(&pk, &m, &sig).is_ok());
            let mut m2 = m;
            m2[0] ^= 1;
            assert!(verify_ed25519(&pk, &m2, &sig).is_err());
        }
    }

    #[test]
    fn batch_matches_sequential() {
        let kp = KeyPair::from_seed(&[1u8; 32]);
        let pk = kp.public();
        let mut items = Vec::new();
        for i in 0..64u8 {
            let msg = vec![i; 16];
            let sig = kp.sign(&msg);
            items.push((pk, msg, sig));
        }
        // Corrupt a few.
        items[5].2[0] ^= 1;
        items[40].0[0] ^= 1;
        let batch = verify_ed25519_all(&items);
        let seq: Vec<bool> = items
            .iter()
            .map(|(p, m, s)| verify_ed25519(p, m, s).is_ok())
            .collect();
        assert_eq!(batch, seq);
        assert!(!batch[5] && !batch[40] && batch[0]);
        #[allow(deprecated)]
        {
            assert_eq!(batch_verify_ed25519(&items), batch);
        }
    }

    #[test]
    fn verification_never_panics_on_garbage() {
        let mut state = 0xfeedu64;
        for _ in 0..10_000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let mut pk = [0u8; 32];
            let mut sig = [0u8; 64];
            pk[0] = state.to_le_bytes()[0];
            sig[0] = state.to_le_bytes()[1];
            let _ = verify_ed25519(&pk, b"m", &sig);
            let _ = verify_secp256k1_evm(&pk, b"m", &sig);
        }
    }
}

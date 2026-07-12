//! Multi-scheme signature verification and deterministic key generation.
//!
//! - **ed25519** — node identity, oracle, custody, quorum, and Solana (SVM) wallets.
//! - **secp256k1 / EIP-712** — EVM wallets: ECDSA over a 32-byte digest, with
//!   EIP-2 low-S enforcement and wallet-compatible EIP-712 typed-data digests.
//! - **EIP-1271** — smart-wallet authorization modeled as the **owner**
//!   secp256k1 key, bound to a contract address (offline trust model; see
//!   [`verify_eip1271`]).
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
    /// The secp256k1 signature used a high-S value (EIP-2 / malleability).
    #[error("high-S secp256k1 signature rejected")]
    HighS,
    /// EIP-1271 binding failed: contract address does not match the claimed wallet.
    #[error("EIP-1271 contract address mismatch")]
    ContractAddressMismatch,
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

/// Cached ed25519 verifying key for a fixed committee member.
///
/// Parsing a public key once and reusing the verifier across many votes avoids
/// repeated SEC1/ed25519 decompress work during QC formation hot paths.
#[derive(Debug, Clone)]
pub struct CachedEd25519Key {
    bytes: [u8; 32],
    verifying: EdVerifyingKey,
}

impl CachedEd25519Key {
    /// Parse and cache a verifying key. Errors if the bytes are not a valid key.
    pub fn parse(public_key: &[u8; 32]) -> Result<Self, CryptoError> {
        let verifying =
            EdVerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::MalformedKey)?;
        Ok(Self {
            bytes: *public_key,
            verifying,
        })
    }

    /// The original 32-byte public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Verify a signature over `message` with the cached key.
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> Result<(), CryptoError> {
        let sig = EdSignature::from_bytes(signature);
        self.verifying
            .verify_strict(message, &sig)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

// ---------------------------------------------------------------------------
// secp256k1 / EIP-712 / EIP-1271
// ---------------------------------------------------------------------------

/// Enforce EIP-2 low-S: reject malleable high-S signatures.
fn require_low_s(sig: &K256Signature) -> Result<(), CryptoError> {
    // `normalize_s` returns `Some` only when S was high; `None` means already low.
    if sig.normalize_s().is_some() {
        return Err(CryptoError::HighS);
    }
    Ok(())
}

/// Normalize a signature to low-S form (EIP-2). Always returns a low-S signature.
fn normalize_low_s(sig: K256Signature) -> K256Signature {
    sig.normalize_s().unwrap_or(sig)
}

/// Convert a k256 signature to a fixed 64-byte `r || s` encoding.
fn sig_to_bytes(sig: &K256Signature) -> [u8; 64] {
    let bytes = sig.to_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    out
}

/// An EVM (secp256k1) keypair for EIP-712-style signing over digests.
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

    /// Sign the keccak-256 digest of `message`, producing a low-S signature.
    pub fn sign_evm(&self, message: &[u8]) -> Result<[u8; 64], CryptoError> {
        let digest = keccak256(message);
        self.sign_prehash(&digest)
    }

    /// Sign a pre-hashed 32-byte digest (EIP-712 final digest), low-S normalized.
    pub fn sign_prehash(&self, digest: &[u8; 32]) -> Result<[u8; 64], CryptoError> {
        let sig: K256Signature = self
            .signing
            .sign_prehash(digest.as_slice())
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(sig_to_bytes(&normalize_low_s(sig)))
    }

    /// Sign an EIP-712 typed-data digest (domain separator + struct hash).
    pub fn sign_eip712(
        &self,
        domain: &Eip712Domain,
        struct_hash: &[u8; 32],
    ) -> Result<[u8; 64], CryptoError> {
        let digest = eip712_digest(domain, struct_hash);
        self.sign_prehash(&digest)
    }
}

/// Verify a secp256k1 signature over `keccak256(message)`.
///
/// High-S signatures are rejected ([`CryptoError::HighS`]).
pub fn verify_secp256k1_evm(
    public_key_sec1: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let digest = keccak256(message);
    verify_secp256k1_prehash(public_key_sec1, &digest, signature)
}

/// Verify a secp256k1 signature over a 32-byte prehash (EIP-712 final digest).
///
/// High-S signatures are rejected ([`CryptoError::HighS`]).
pub fn verify_secp256k1_prehash(
    public_key_sec1: &[u8],
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let vk = K256VerifyingKey::from_sec1_bytes(public_key_sec1)
        .map_err(|_| CryptoError::MalformedKey)?;
    let sig = K256Signature::from_slice(signature).map_err(|_| CryptoError::MalformedSignature)?;
    require_low_s(&sig)?;
    vk.verify_prehash(digest.as_slice(), &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Whether `signature` is a well-formed low-S secp256k1 signature encoding.
#[must_use]
pub fn is_low_s_secp256k1(signature: &[u8]) -> bool {
    match K256Signature::from_slice(signature) {
        Ok(sig) => sig.normalize_s().is_none(),
        Err(_) => false,
    }
}

// ---- EIP-712 typed data ---------------------------------------------------

/// EIP-712 domain parameters used to form the domain separator.
///
/// Compatible with wallet UI typed-data prompts: `name`, `version`, `chainId`,
/// and `verifyingContract` match the fields wallets display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eip712Domain {
    /// Human-readable signing domain name (e.g. `"DexOS Custody"`).
    pub name: String,
    /// Domain version string (e.g. `"1"`).
    pub version: String,
    /// EVM chain id.
    pub chain_id: u64,
    /// Contract address that will consume the signature (20 bytes).
    pub verifying_contract: [u8; 20],
}

/// Type hash for `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)`.
fn eip712_domain_type_hash() -> [u8; 32] {
    keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    )
}

/// Encode a `uint256` as a 32-byte big-endian word (ABI word).
fn abi_u256_from_u64(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// Encode an `address` as a 32-byte left-padded word.
fn abi_address(addr: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(addr);
    out
}

/// Compute the EIP-712 domain separator for `domain`.
///
/// `domainSeparator = keccak256(typeHash ‖ keccak(name) ‖ keccak(version) ‖ chainId ‖ verifyingContract)`
#[must_use]
pub fn eip712_domain_separator(domain: &Eip712Domain) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 * 5);
    buf.extend_from_slice(&eip712_domain_type_hash());
    buf.extend_from_slice(&keccak256(domain.name.as_bytes()));
    buf.extend_from_slice(&keccak256(domain.version.as_bytes()));
    buf.extend_from_slice(&abi_u256_from_u64(domain.chain_id));
    buf.extend_from_slice(&abi_address(&domain.verifying_contract));
    keccak256(&buf)
}

/// Final EIP-712 digest: `keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ structHash)`.
///
/// This is the value wallets sign and the prehash used by
/// [`EvmKeyPair::sign_prehash`] / [`verify_secp256k1_prehash`].
#[must_use]
pub fn eip712_digest(domain: &Eip712Domain, struct_hash: &[u8; 32]) -> [u8; 32] {
    let domain_sep = eip712_domain_separator(domain);
    let mut buf = [0u8; 66];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(&domain_sep);
    buf[34..66].copy_from_slice(struct_hash);
    keccak256(&buf)
}

/// Hash an EIP-712 struct: `keccak256(typeHash ‖ encodeData...)`.
///
/// `encoded_fields` must already be the ABI-encoded field payload (32-byte words
/// for static types; `keccak256` of dynamic contents for dynamic types).
#[must_use]
pub fn eip712_hash_struct(type_hash: &[u8; 32], encoded_fields: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(32 + encoded_fields.len());
    buf.extend_from_slice(type_hash);
    buf.extend_from_slice(encoded_fields);
    keccak256(&buf)
}

/// Verify an EIP-712 signature over `(domain, struct_hash)`.
pub fn verify_eip712(
    public_key_sec1: &[u8],
    domain: &Eip712Domain,
    struct_hash: &[u8; 32],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let digest = eip712_digest(domain, struct_hash);
    verify_secp256k1_prehash(public_key_sec1, &digest, signature)
}

/// Verify an EIP-1271 smart-wallet signature (offline owner-key model).
///
/// # Trust model
///
/// DexOS does **not** invoke the on-chain `isValidSignature(bytes32,bytes)` entry
/// point. This verifier:
///
/// 1. Requires `contract_address` to equal the claimed smart-wallet address
///    (binding the contract identity into the proof), and
/// 2. Checks that `owner_public_key_sec1` produced a valid **low-S** secp256k1
///    signature over `keccak256(message)`.
///
/// Production deployments that need true contract-defined validation (passkeys,
/// multi-sig modules, session keys inside the wallet) MUST perform an on-chain
/// or chain-adapter `isValidSignature` check; this function is the offline
/// owner-key approximation used when the wallet publishes a designated owner
/// key. See `docs/SECURITY.md`.
pub fn verify_eip1271(
    contract_address: &[u8; 20],
    claimed_wallet_address: &[u8; 20],
    owner_public_key_sec1: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    if contract_address != claimed_wallet_address {
        return Err(CryptoError::ContractAddressMismatch);
    }
    verify_secp256k1_evm(owner_public_key_sec1, message, signature)
}

/// Verify EIP-1271 over a pre-hashed EIP-712 digest (offline owner-key model).
///
/// Same trust model as [`verify_eip1271`], but the signature is over `digest`
/// directly (the EIP-712 final digest).
pub fn verify_eip1271_prehash(
    contract_address: &[u8; 20],
    claimed_wallet_address: &[u8; 20],
    owner_public_key_sec1: &[u8],
    digest: &[u8; 32],
    signature: &[u8],
) -> Result<(), CryptoError> {
    if contract_address != claimed_wallet_address {
        return Err(CryptoError::ContractAddressMismatch);
    }
    verify_secp256k1_prehash(owner_public_key_sec1, digest, signature)
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
        assert!(is_low_s_secp256k1(&sig));
    }

    #[test]
    fn high_s_signatures_are_rejected() {
        let kp = EvmKeyPair::from_seed(&[9u8; 32]).unwrap();
        let pk = kp.public_sec1();
        let msg = b"malleability probe";
        let sig = kp.sign_evm(msg).unwrap();
        assert!(is_low_s_secp256k1(&sig));

        // Flip to high-S by replacing S with n - S (secp256k1 group order).
        // n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        let mut high = sig;
        // Parse s from the high half and complement against n.
        let sig_obj = K256Signature::from_slice(&sig).unwrap();
        let high_obj = {
            // Force a high-S encoding: take normalize_s inverse by using the
            // fact that if sig is low, the other representative is high.
            // We construct it by negating S through the public API: re-sign is
            // low; instead mutate S bytes to n-S via known order.
            let n: [u8; 32] = [
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
                0xD0, 0x36, 0x41, 0x41,
            ];
            let s = &sig[32..];
            let mut new_s = [0u8; 32];
            let mut borrow = 0u16;
            for i in (0..32).rev() {
                let diff = u16::from(n[i])
                    .wrapping_sub(u16::from(s[i]))
                    .wrapping_sub(borrow);
                new_s[i] = diff as u8;
                borrow = if diff > 0xff { 1 } else { 0 };
            }
            high[32..].copy_from_slice(&new_s);
            let _ = sig_obj;
            high
        };
        assert!(!is_low_s_secp256k1(&high_obj));
        assert_eq!(
            verify_secp256k1_evm(&pk, msg, &high_obj),
            Err(CryptoError::HighS)
        );
    }

    #[test]
    fn eip712_domain_separator_is_stable_and_binds_fields() {
        let domain = Eip712Domain {
            name: "DexOS Custody".into(),
            version: "1".into(),
            chain_id: 1,
            verifying_contract: [0xAB; 20],
        };
        let a = eip712_domain_separator(&domain);
        let b = eip712_domain_separator(&domain);
        assert_eq!(a, b);

        let mut other = domain.clone();
        other.chain_id = 2;
        assert_ne!(a, eip712_domain_separator(&other));

        let mut other = domain.clone();
        other.verifying_contract[0] ^= 1;
        assert_ne!(a, eip712_domain_separator(&other));

        let mut other = domain;
        other.name = "Other".into();
        assert_ne!(a, eip712_domain_separator(&other));
    }

    #[test]
    fn eip712_sign_verify_roundtrip() {
        let kp = EvmKeyPair::from_seed(&[11u8; 32]).unwrap();
        let pk = kp.public_sec1();
        let domain = Eip712Domain {
            name: "DexOS".into(),
            version: "1".into(),
            chain_id: 8453,
            verifying_contract: [0x11; 20],
        };
        let type_hash = keccak256(b"Bind(uint32 account,uint64 nonce)");
        let mut fields = [0u8; 64];
        fields[28..32].copy_from_slice(&1u32.to_be_bytes());
        fields[56..64].copy_from_slice(&7u64.to_be_bytes());
        let struct_hash = eip712_hash_struct(&type_hash, &fields);
        let sig = kp.sign_eip712(&domain, &struct_hash).unwrap();
        assert!(verify_eip712(&pk, &domain, &struct_hash, &sig).is_ok());
        // Wrong struct fails.
        let mut bad_fields = fields;
        bad_fields[63] ^= 1;
        let bad_struct = eip712_hash_struct(&type_hash, &bad_fields);
        assert!(verify_eip712(&pk, &domain, &bad_struct, &sig).is_err());
    }

    #[test]
    fn eip1271_binds_contract_address_to_owner() {
        let kp = EvmKeyPair::from_seed(&[5u8; 32]).unwrap();
        let pk = kp.public_sec1();
        let msg = b"bind smart wallet";
        let sig = kp.sign_evm(msg).unwrap();
        let contract = [0xCA; 20];
        assert!(verify_eip1271(&contract, &contract, &pk, msg, &sig).is_ok());
        let other = [0x00; 20];
        assert_eq!(
            verify_eip1271(&contract, &other, &pk, msg, &sig),
            Err(CryptoError::ContractAddressMismatch)
        );
    }

    #[test]
    fn cached_ed25519_matches_scalar() {
        let kp = KeyPair::from_seed(&[3u8; 32]);
        let pk = kp.public();
        let cached = CachedEd25519Key::parse(&pk).unwrap();
        let msg = b"vote digest";
        let sig = kp.sign(msg);
        assert!(cached.verify(msg, &sig).is_ok());
        assert_eq!(
            cached.verify(b"other", &sig),
            Err(CryptoError::InvalidSignature)
        );
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

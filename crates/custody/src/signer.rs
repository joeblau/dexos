//! The custody signing boundary: production HSM/KMS backends and a feature-gated
//! deterministic software simulator.
//!
//! [`Signer`] is the per-key interface the custody controller aggregates into a
//! [`QuorumCertificate`]. The **only** always-compiled implementation is
//! [`HsmSigner`], which holds no private key material: it pins a key's public
//! half plus an opaque [`KeyHandle`] and delegates every signature to an
//! [`HsmBackend`] (AWS KMS, Cloud HSM, or a PKCS#11 token). Seed / private-key
//! material never enters the node process.
//!
//! # Integrating a real HSM / KMS
//!
//! Implement [`HsmBackend`] in the node's I/O layer (which may be async / do
//! network I/O — this deterministic crate deliberately cannot) and hand the
//! controller an `Arc<dyn HsmBackend>`:
//!
//! - **AWS KMS** — map [`KeyHandle`] to a key ARN / id. `public_key` calls
//!   `GetPublicKey`; `sign` calls `Sign` with `MessageType=DIGEST` and an
//!   ed25519 signing algorithm, returning the 64-byte signature. IAM policy,
//!   grants, and CloudTrail provide authorize / audit separation.
//! - **Cloud HSM (CloudHSM / Cloud KMS HSM)** — same shape over the vendor SDK;
//!   the handle is the HSM key label. Keys are generated **inside** the HSM in a
//!   key ceremony and are non-extractable.
//! - **PKCS#11 token** — the handle encodes `(slot, CKA_LABEL)`. `public_key`
//!   reads `CKA_EC_POINT`; `sign` runs `C_SignInit`/`C_Sign` with
//!   `CKM_EDDSA` against the private-key object. Dual control is enforced by the
//!   token's login policy (e.g. m-of-n `C_Login`).
//!
//! Rotation ships **public keys and handles only** (see
//! [`crate::controller::ControlCommand`]); a live signer is reconstituted by
//! [binding][HsmSigner::bind_attested] the handle through the backend and
//! checking the HSM-reported key equals the ceremony-published one. A raw seed is
//! never accepted on the control plane.
//!
//! `SoftSigner` and `MockHsm` are compiled only under the `mock-signers`
//! feature (and the crate's own tests). They are the deterministic replay /
//! simulation backend and are **never** linked into a production build, which
//! depends on this crate without that feature.

use std::sync::Arc;

use crypto::{QuorumCertificate, QuorumSignatures, Validator, ValidatorSet};
use types::Hash;

use crate::error::CustodyError;

#[cfg(any(feature = "mock-signers", test))]
use crypto::KeyPair;
#[cfg(any(feature = "mock-signers", test))]
use std::collections::BTreeMap;

/// The custody signing boundary: one signing key, held in an HSM in production.
///
/// Implementations must be deterministic for a given key and message so that the
/// software simulator and a real HSM produce byte-identical certificates in the
/// test / replay harness.
pub trait Signer {
    /// The signer's 32-byte ed25519 public key.
    fn public_key(&self) -> [u8; 32];

    /// Sign a 32-byte message hash, returning a 64-byte signature.
    fn sign(&self, message: &Hash) -> Result<[u8; 64], CustodyError>;
}

/// An opaque reference naming a key inside an HSM / KMS / PKCS#11 token.
///
/// The bytes are backend-defined — a KMS key ARN, an HSM key label, or an
/// encoded `(slot, CKA_LABEL)` — and are treated as an opaque identifier
/// everywhere in this crate. A handle is *not* secret; it carries no key
/// material and is safe to ship on the control plane.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyHandle(Box<[u8]>);

impl KeyHandle {
    /// A handle from a UTF-8 label (KMS ARN / HSM key label).
    #[must_use]
    pub fn from_label(label: &str) -> Self {
        Self(label.as_bytes().into())
    }

    /// A handle from raw backend-defined bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.into())
    }

    /// The opaque handle bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for KeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Render printable labels readably; fall back to a length for binary
        // handles. Never prints key material (handles carry none).
        match std::str::from_utf8(&self.0) {
            Ok(s) => write!(f, "KeyHandle({s:?})"),
            Err(_) => write!(f, "KeyHandle(<{} bytes>)", self.0.len()),
        }
    }
}

/// The private-key custodian: an external HSM / KMS / PKCS#11 token.
///
/// This is the trust boundary. The private key is generated inside the token in
/// an offline key ceremony and is non-extractable; the node process holds only a
/// [`KeyHandle`] and can ask the backend to sign. Implementations live in the
/// node's I/O layer — see the [module docs][self] for AWS KMS, Cloud HSM, and
/// PKCS#11 integration recipes.
///
/// Implementations must be `Send + Sync` (the handle is shared across the node)
/// and deterministic for a provisioned key and message.
pub trait HsmBackend: std::fmt::Debug + Send + Sync {
    /// The 32-byte ed25519 public key provisioned for `handle`.
    ///
    /// Returns [`CustodyError::UnknownKeyHandle`] if no key is provisioned.
    fn public_key(&self, handle: &KeyHandle) -> Result<[u8; 32], CustodyError>;

    /// Sign a 32-byte message with the private key behind `handle`.
    ///
    /// Returns [`CustodyError::UnknownKeyHandle`] if no key is provisioned.
    fn sign(&self, handle: &KeyHandle, message: &Hash) -> Result<[u8; 64], CustodyError>;
}

/// A production custody signer bound to one HSM-resident key.
///
/// Holds only the key's public half and an opaque [`KeyHandle`]; every signature
/// is delegated to the [`HsmBackend`], so no seed or private key ever lives in
/// process memory. Constructed via [`bind`](HsmSigner::bind) /
/// [`bind_attested`](HsmSigner::bind_attested) — there is no seed constructor.
#[derive(Clone)]
pub struct HsmSigner {
    backend: Arc<dyn HsmBackend>,
    handle: KeyHandle,
    public_key: [u8; 32],
}

impl std::fmt::Debug for HsmSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HsmSigner")
            .field("handle", &self.handle)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl HsmSigner {
    /// Bind to an HSM-resident key, fetching and pinning its public key.
    ///
    /// Returns [`CustodyError::UnknownKeyHandle`] if the backend has no key for
    /// `handle`.
    pub fn bind(backend: Arc<dyn HsmBackend>, handle: KeyHandle) -> Result<Self, CustodyError> {
        let public_key = backend.public_key(&handle)?;
        Ok(Self {
            backend,
            handle,
            public_key,
        })
    }

    /// Bind and attest: bind the key, then fail unless the HSM-reported public
    /// key equals `expected`.
    ///
    /// This is the rotation-time check: `expected` is the public key published by
    /// the offline key ceremony, so a control-plane operator cannot swap in a key
    /// they secretly control. Returns [`CustodyError::KeyAttestationFailed`] on
    /// mismatch.
    pub fn bind_attested(
        backend: Arc<dyn HsmBackend>,
        handle: KeyHandle,
        expected: [u8; 32],
    ) -> Result<Self, CustodyError> {
        let signer = Self::bind(backend, handle)?;
        if signer.public_key != expected {
            return Err(CustodyError::KeyAttestationFailed);
        }
        Ok(signer)
    }

    /// The opaque handle this signer is bound to.
    #[must_use]
    pub fn handle(&self) -> &KeyHandle {
        &self.handle
    }
}

impl Signer for HsmSigner {
    fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    fn sign(&self, message: &Hash) -> Result<[u8; 64], CustodyError> {
        self.backend.sign(&self.handle, message)
    }
}

/// The public identity of a rotation participant: an [`HsmBackend`] key handle
/// and the ceremony-published public key used to attest it.
///
/// Carries **no** seed or private key — this is exactly what a rotation control
/// command is permitted to ship.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRef {
    /// The opaque handle naming the key inside the HSM / KMS.
    pub handle: KeyHandle,
    /// The 32-byte ed25519 public key published by the key ceremony.
    pub public_key: [u8; 32],
}

impl KeyRef {
    /// A key reference from a handle and its published public key.
    #[must_use]
    pub fn new(handle: KeyHandle, public_key: [u8; 32]) -> Self {
        Self { handle, public_key }
    }
}

/// Largest supported signer set (bounded by the 16-bit quorum bitmap).
pub const MAX_SIGNERS: usize = 16;

/// A `t`-of-`n` threshold signer set at a given rotation epoch.
///
/// Aggregates individual [`Signer`] shares over a message into a
/// [`QuorumCertificate`] verifiable by [`validator_set`]. Any `t` distinct valid
/// shares verify; any `t-1` do not. Foreign / out-of-range / duplicate share
/// indices are ignored, never panicking.
///
/// [`validator_set`]: SignerSet::validator_set
#[derive(Debug, Clone)]
pub struct SignerSet<S: Signer> {
    signers: Vec<S>,
    threshold: u64,
    epoch: u64,
}

impl<S: Signer> SignerSet<S> {
    /// Build a set of `signers` with weight `threshold` at rotation `epoch`.
    ///
    /// Returns [`CustodyError::InvalidThreshold`] if `threshold == 0`,
    /// `threshold > n`, `n == 0`, or `n > MAX_SIGNERS` — never panics.
    pub fn new(signers: Vec<S>, threshold: u64, epoch: u64) -> Result<Self, CustodyError> {
        let n = signers.len();
        if n == 0 || n > MAX_SIGNERS {
            return Err(CustodyError::InvalidThreshold);
        }
        let n_u64 = u64::try_from(n).map_err(|_| CustodyError::InvalidThreshold)?;
        if threshold == 0 || threshold > n_u64 {
            return Err(CustodyError::InvalidThreshold);
        }
        Ok(Self {
            signers,
            threshold,
            epoch,
        })
    }

    /// The required signing threshold (`t`).
    pub fn threshold(&self) -> u64 {
        self.threshold
    }

    /// The number of signers (`n`).
    pub fn n(&self) -> usize {
        self.signers.len()
    }

    /// The rotation epoch this set is authoritative for.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The verifying validator set (unit weight each, threshold `t`).
    pub fn validator_set(&self) -> ValidatorSet {
        let validators = self
            .signers
            .iter()
            .map(|s| Validator {
                public_key: s.public_key(),
                weight: 1,
            })
            .collect();
        ValidatorSet::with_threshold(validators, self.threshold)
    }

    /// Aggregate shares from `indices` over `message` into a certificate.
    ///
    /// Indices are deduplicated, applied in ascending order, and those outside
    /// the set are skipped. The returned certificate verifies under
    /// [`validator_set`](SignerSet::validator_set) iff at least `threshold`
    /// distinct in-range signers participated.
    pub fn sign(
        &self,
        message: Hash,
        indices: &[usize],
    ) -> Result<QuorumCertificate, CustodyError> {
        let mut idx: Vec<usize> = indices
            .iter()
            .copied()
            .filter(|&i| i < self.signers.len() && i < MAX_SIGNERS)
            .collect();
        idx.sort_unstable();
        idx.dedup();

        let mut signer_bitmap = 0u16;
        let mut signatures = QuorumSignatures::new();
        for &i in &idx {
            signer_bitmap |= 1u16 << i;
            signatures
                .try_push(self.signers[i].sign(&message)?)
                .map_err(|_| CustodyError::InvalidThreshold)?;
        }
        Ok(QuorumCertificate {
            message,
            signer_bitmap,
            signatures,
        })
    }
}

// -------------------------------------------------------------------------
// Test / dev only: the deterministic software simulator. Never compiled into a
// production build (the node depends on `custody` without `mock-signers`), so a
// release binary is structurally incapable of constructing a signer from a raw
// seed.
// -------------------------------------------------------------------------

/// A deterministic software signer (the simulator's per-key element).
///
/// Test / dev only: available solely under the `mock-signers` feature. A
/// production build cannot construct one, and therefore cannot turn a raw seed
/// into a custody signer.
#[cfg(any(feature = "mock-signers", test))]
#[derive(Debug, Clone)]
pub struct SoftSigner {
    keypair: KeyPair,
}

#[cfg(any(feature = "mock-signers", test))]
impl SoftSigner {
    /// Derive a software signer from a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            keypair: KeyPair::from_seed(seed),
        }
    }
}

#[cfg(any(feature = "mock-signers", test))]
impl Signer for SoftSigner {
    fn public_key(&self) -> [u8; 32] {
        self.keypair.public()
    }

    fn sign(&self, message: &Hash) -> Result<[u8; 64], CustodyError> {
        Ok(self.keypair.sign(message.as_bytes()))
    }
}

#[cfg(any(feature = "mock-signers", test))]
impl SignerSet<SoftSigner> {
    /// Convenience: build a software simulator set from seeds.
    ///
    /// Test / dev only (`mock-signers`). Production signer sets are built from
    /// [`HsmSigner::bind`] over an [`HsmBackend`].
    pub fn from_seeds(
        seeds: &[[u8; 32]],
        threshold: u64,
        epoch: u64,
    ) -> Result<Self, CustodyError> {
        let signers = seeds.iter().map(SoftSigner::from_seed).collect();
        Self::new(signers, threshold, epoch)
    }
}

/// A deterministic in-memory [`HsmBackend`] standing in for a real token.
///
/// Test / dev only (`mock-signers`). Keys are `provision`ed up front (modeling
/// an offline key ceremony that generates keys inside the token) and then the
/// backend is shared read-only. Signatures are byte-identical to a
/// `SoftSigner` over the same seed, so the same replay harness drives the mock
/// and, one day, a real HSM.
#[cfg(any(feature = "mock-signers", test))]
#[derive(Debug, Clone, Default)]
pub struct MockHsm {
    keys: BTreeMap<Box<[u8]>, KeyPair>,
}

#[cfg(any(feature = "mock-signers", test))]
impl MockHsm {
    /// An empty token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Provision a key from a seed (models a key ceremony), returning its public
    /// key so the caller can publish it as attestation material.
    pub fn provision(&mut self, handle: &KeyHandle, seed: &[u8; 32]) -> [u8; 32] {
        let keypair = KeyPair::from_seed(seed);
        let public_key = keypair.public();
        self.keys.insert(handle.as_bytes().into(), keypair);
        public_key
    }
}

#[cfg(any(feature = "mock-signers", test))]
impl HsmBackend for MockHsm {
    fn public_key(&self, handle: &KeyHandle) -> Result<[u8; 32], CustodyError> {
        self.keys
            .get(handle.as_bytes())
            .map(KeyPair::public)
            .ok_or(CustodyError::UnknownKeyHandle)
    }

    fn sign(&self, handle: &KeyHandle, message: &Hash) -> Result<[u8; 64], CustodyError> {
        let keypair = self
            .keys
            .get(handle.as_bytes())
            .ok_or(CustodyError::UnknownKeyHandle)?;
        Ok(keypair.sign(message.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeds(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| [u8::try_from(i).unwrap() + 1; 32]).collect()
    }

    // Provision `seeds` into a fresh mock token and return the shared backend
    // plus the published key references (handle + public key).
    fn provision(seeds: &[[u8; 32]]) -> (Arc<MockHsm>, Vec<KeyRef>) {
        let mut hsm = MockHsm::new();
        let refs = seeds
            .iter()
            .enumerate()
            .map(|(i, seed)| {
                let handle = KeyHandle::from_label(&format!("key-{i}"));
                let public_key = hsm.provision(&handle, seed);
                KeyRef::new(handle, public_key)
            })
            .collect();
        (Arc::new(hsm), refs)
    }

    // Build an HSM-backed signer set from the mock token.
    fn hsm_set(
        seeds: &[[u8; 32]],
        threshold: u64,
        epoch: u64,
    ) -> (Arc<MockHsm>, SignerSet<HsmSigner>) {
        let (backend, refs) = provision(seeds);
        let signers = refs
            .into_iter()
            .map(|r| HsmSigner::bind_attested(backend.clone(), r.handle, r.public_key).unwrap())
            .collect();
        (
            backend.clone(),
            SignerSet::new(signers, threshold, epoch).unwrap(),
        )
    }

    #[test]
    fn new_rejects_bad_threshold_and_size() {
        assert_eq!(
            SignerSet::from_seeds(&seeds(4), 0, 0).unwrap_err(),
            CustodyError::InvalidThreshold
        );
        assert_eq!(
            SignerSet::from_seeds(&seeds(4), 5, 0).unwrap_err(),
            CustodyError::InvalidThreshold
        );
        assert_eq!(
            SignerSet::from_seeds(&[], 1, 0).unwrap_err(),
            CustodyError::InvalidThreshold
        );
        assert!(SignerSet::from_seeds(&seeds(4), 3, 0).is_ok());
    }

    #[test]
    fn t_of_n_verifies_and_t_minus_1_does_not() {
        let set = SignerSet::from_seeds(&seeds(5), 3, 0).unwrap();
        let vs = set.validator_set();
        let msg = Hash::from_bytes([7u8; 32]);

        assert!(vs.verify(&set.sign(msg, &[0, 1, 2]).unwrap()).is_ok());
        assert!(vs.verify(&set.sign(msg, &[1, 3, 4]).unwrap()).is_ok());
        // t-1 = 2 shares never verifies.
        assert!(vs.verify(&set.sign(msg, &[0, 1]).unwrap()).is_err());
        // Duplicate / foreign indices are ignored (dedup to 2 distinct).
        assert!(vs.verify(&set.sign(msg, &[0, 0, 1, 99]).unwrap()).is_err());
    }

    #[test]
    fn hsm_backend_signatures_equal_software_simulator() {
        // The HSM boundary is faithful: an HsmSigner over a provisioned key and a
        // SoftSigner over the same seed produce byte-identical aggregate
        // certificates, so the replay harness is agnostic to the backend.
        let soft = SignerSet::from_seeds(&seeds(4), 3, 0).unwrap();
        let (_hsm, hard) = hsm_set(&seeds(4), 3, 0);
        let msg = Hash::from_bytes([3u8; 32]);
        assert_eq!(
            soft.validator_set().total_weight(),
            hard.validator_set().total_weight()
        );
        assert_eq!(
            soft.sign(msg, &[0, 1, 2]).unwrap(),
            hard.sign(msg, &[0, 1, 2]).unwrap()
        );
    }

    #[test]
    fn hsm_signer_holds_no_seed_and_signs_via_backend() {
        let (_backend, set) = hsm_set(&seeds(3), 2, 0);
        let vs = set.validator_set();
        let msg = Hash::from_bytes([9u8; 32]);
        assert!(vs.verify(&set.sign(msg, &[0, 1]).unwrap()).is_ok());
    }

    #[test]
    fn bind_rejects_unknown_handle() {
        let (backend, _refs) = provision(&seeds(1));
        let err = HsmSigner::bind(backend, KeyHandle::from_label("absent")).unwrap_err();
        assert_eq!(err, CustodyError::UnknownKeyHandle);
    }

    #[test]
    fn attestation_rejects_wrong_public_key() {
        let (backend, refs) = provision(&seeds(2));
        // Attesting handle 0 against handle 1's public key must fail: a control
        // operator cannot bind a key whose published identity they do not hold.
        let wrong = refs[1].public_key;
        let err = HsmSigner::bind_attested(backend, refs[0].handle.clone(), wrong).unwrap_err();
        assert_eq!(err, CustodyError::KeyAttestationFailed);
    }

    #[test]
    fn deterministic_across_runs() {
        let a = SignerSet::from_seeds(&seeds(4), 3, 0).unwrap();
        let b = SignerSet::from_seeds(&seeds(4), 3, 0).unwrap();
        let msg = Hash::from_bytes([1u8; 32]);
        assert_eq!(
            a.sign(msg, &[0, 1, 2]).unwrap(),
            b.sign(msg, &[0, 1, 2]).unwrap()
        );
    }
}

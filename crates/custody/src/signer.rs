//! The production HSM signer boundary and a deterministic software simulator.
//!
//! [`Signer`] is the per-key interface a production hardware security module
//! implements. [`SoftSigner`] is a deterministic software key implementing it
//! (the simulator), and [`HsmSigner`] is an interchangeable stub with identical
//! semantics. [`SignerSet`] aggregates `t`-of-`n` shares from any `Signer` into
//! a verifiable [`QuorumCertificate`].

use crypto::{KeyPair, QuorumCertificate, Validator, ValidatorSet};
use types::Hash;

use crate::error::CustodyError;

/// The custody signing boundary: one signing key, held in an HSM in production.
///
/// Implementations must be deterministic for a given key and message so that the
/// software simulator and a real HSM produce byte-identical certificates in the
/// test/replay harness.
pub trait Signer {
    /// The signer's 32-byte ed25519 public key.
    fn public_key(&self) -> [u8; 32];

    /// Sign a 32-byte message hash, returning a 64-byte signature.
    fn sign(&self, message: &Hash) -> Result<[u8; 64], CustodyError>;
}

/// A deterministic software signer (the simulator's per-key element).
#[derive(Debug, Clone)]
pub struct SoftSigner {
    keypair: KeyPair,
}

impl SoftSigner {
    /// Derive a software signer from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            keypair: KeyPair::from_seed(seed),
        }
    }
}

impl Signer for SoftSigner {
    fn public_key(&self) -> [u8; 32] {
        self.keypair.public()
    }

    fn sign(&self, message: &Hash) -> Result<[u8; 64], CustodyError> {
        Ok(self.keypair.sign(message.as_bytes()))
    }
}

/// A stub standing in for a hardware HSM signer. Deterministic and behaviourally
/// identical to [`SoftSigner`]; present so tests can prove the two are
/// interchangeable behind [`Signer`] with identical authorization semantics.
#[derive(Debug, Clone)]
pub struct HsmSigner {
    keypair: KeyPair,
}

impl HsmSigner {
    /// Attach to an HSM slot modeled by a 32-byte seed.
    pub fn attach(seed: &[u8; 32]) -> Self {
        Self {
            keypair: KeyPair::from_seed(seed),
        }
    }
}

impl Signer for HsmSigner {
    fn public_key(&self) -> [u8; 32] {
        self.keypair.public()
    }

    fn sign(&self, message: &Hash) -> Result<[u8; 64], CustodyError> {
        Ok(self.keypair.sign(message.as_bytes()))
    }
}

/// Largest supported signer set (bounded by the 64-bit quorum bitmap).
pub const MAX_SIGNERS: usize = 64;

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

        let mut signer_bitmap = 0u64;
        let mut signatures = Vec::with_capacity(idx.len());
        for &i in &idx {
            signer_bitmap |= 1u64 << i;
            signatures.push(self.signers[i].sign(&message)?);
        }
        Ok(QuorumCertificate {
            message,
            signer_bitmap,
            signatures,
        })
    }
}

impl SignerSet<SoftSigner> {
    /// Convenience: build a software simulator set from seeds.
    pub fn from_seeds(
        seeds: &[[u8; 32]],
        threshold: u64,
        epoch: u64,
    ) -> Result<Self, CustodyError> {
        let signers = seeds.iter().map(SoftSigner::from_seed).collect();
        Self::new(signers, threshold, epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeds(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| [u8::try_from(i).unwrap() + 1; 32]).collect()
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
    fn soft_and_hsm_are_interchangeable() {
        let soft =
            SignerSet::new(seeds(4).iter().map(SoftSigner::from_seed).collect(), 3, 0).unwrap();
        let hsm = SignerSet::new(seeds(4).iter().map(HsmSigner::attach).collect(), 3, 0).unwrap();
        let msg = Hash::from_bytes([3u8; 32]);
        // Identical public keys and identical aggregate certificates.
        assert_eq!(
            soft.validator_set().total_weight(),
            hsm.validator_set().total_weight()
        );
        assert_eq!(
            soft.sign(msg, &[0, 1, 2]).unwrap(),
            hsm.sign(msg, &[0, 1, 2]).unwrap()
        );
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

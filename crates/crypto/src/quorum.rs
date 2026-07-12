//! Validator sets, quorum certificates, and a deterministic threshold-signer
//! simulator (ed25519). Production HSM signers implement the same interface.

use serde::{Deserialize, Serialize};

use crate::signature::{verify_ed25519, KeyPair};
use types::Hash;

/// Maximum number of validators in a [`ValidatorSet`].
///
/// Bound by the 64-bit `signer_bitmap` of a [`QuorumCertificate`]: bit `i`
/// names validator index `i`, so more than 64 members cannot be represented.
/// Consensus committees share this operational ceiling (see
/// `consensus::MAX_VALIDATORS`).
pub const MAX_VALIDATORS: usize = 64;

/// A quorum / threshold verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum QuorumError {
    /// A set bit refers to a validator index outside the set.
    #[error("unknown signer index")]
    UnknownSigner,
    /// The number of signatures does not match the number of set bits.
    #[error("signature count does not match signer bitmap")]
    MalformedCertificate,
    /// A member signature failed to verify.
    #[error("invalid member signature")]
    InvalidSignature,
    /// Signed weight did not reach the threshold.
    #[error("signed weight {signed} below threshold {threshold}")]
    BelowThreshold {
        /// Weight that actually signed.
        signed: u64,
        /// Required threshold.
        threshold: u64,
    },
    /// Summing validator weights overflowed `u64` (weights must use checked
    /// arithmetic; saturating sums would silently under-count the threshold).
    #[error("validator weight sum overflowed")]
    WeightOverflow,
    /// The validator set is empty, exceeds [`MAX_VALIDATORS`], or has an
    /// invalid threshold.
    #[error("invalid validator set")]
    InvalidSet,
}

/// A weighted validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    /// ed25519 public key.
    pub public_key: [u8; 32],
    /// Voting weight.
    pub weight: u64,
}

/// A validator set with a fixed weight threshold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
    total_weight: u64,
    threshold: u64,
}

impl ValidatorSet {
    /// Build a BFT set with a `2f+1`-style threshold: `floor(2*total/3)+1`.
    ///
    /// # Panics
    ///
    /// Panics if the set is invalid (empty, `> MAX_VALIDATORS`, or weight
    /// overflow). Prefer [`Self::try_new_bft`] on untrusted input.
    pub fn new_bft(validators: Vec<Validator>) -> Self {
        Self::try_new_bft(validators).expect("invalid BFT validator set")
    }

    /// Fallible BFT constructor: rejects empty sets, sets larger than
    /// [`MAX_VALIDATORS`], and weight sums that overflow `u64`.
    pub fn try_new_bft(validators: Vec<Validator>) -> Result<Self, QuorumError> {
        let total = sum_weights(&validators)?;
        if validators.is_empty() || validators.len() > MAX_VALIDATORS {
            return Err(QuorumError::InvalidSet);
        }
        let threshold = (2 * total) / 3 + 1;
        Ok(Self {
            validators,
            total_weight: total,
            threshold,
        })
    }

    /// Build a set with an explicit weight threshold (e.g. crash-tolerant `f+1`).
    ///
    /// # Panics
    ///
    /// Panics if the set is invalid. Prefer [`Self::try_with_threshold`].
    pub fn with_threshold(validators: Vec<Validator>, threshold: u64) -> Self {
        Self::try_with_threshold(validators, threshold).expect("invalid validator set")
    }

    /// Fallible explicit-threshold constructor.
    ///
    /// Rejects empty sets, sets larger than [`MAX_VALIDATORS`], weight overflow,
    /// and a zero threshold.
    pub fn try_with_threshold(
        validators: Vec<Validator>,
        threshold: u64,
    ) -> Result<Self, QuorumError> {
        if validators.is_empty() || validators.len() > MAX_VALIDATORS || threshold == 0 {
            return Err(QuorumError::InvalidSet);
        }
        let total = sum_weights(&validators)?;
        Ok(Self {
            validators,
            total_weight: total,
            threshold,
        })
    }

    /// Total voting weight.
    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    /// Required threshold weight.
    pub fn threshold(&self) -> u64 {
        self.threshold
    }

    /// Number of validators.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Verify a quorum certificate over its message. Rejects unknown signers,
    /// malformed certificates, bad signatures, and below-threshold weight.
    pub fn verify(&self, qc: &QuorumCertificate) -> Result<(), QuorumError> {
        let set_bits = qc.signer_bitmap.count_ones() as usize;
        if set_bits != qc.signatures.len() {
            return Err(QuorumError::MalformedCertificate);
        }
        let mut signed_weight: u64 = 0;
        let mut sig_index = 0usize;
        for bit in 0..u64::BITS {
            if qc.signer_bitmap & (1u64 << bit) == 0 {
                continue;
            }
            let validator = self
                .validators
                .get(bit as usize)
                .ok_or(QuorumError::UnknownSigner)?;
            let signature = &qc.signatures[sig_index];
            sig_index += 1;
            verify_ed25519(&validator.public_key, qc.message.as_bytes(), signature)
                .map_err(|_| QuorumError::InvalidSignature)?;
            signed_weight = signed_weight
                .checked_add(validator.weight)
                .ok_or(QuorumError::WeightOverflow)?;
        }
        if signed_weight < self.threshold {
            return Err(QuorumError::BelowThreshold {
                signed: signed_weight,
                threshold: self.threshold,
            });
        }
        Ok(())
    }
}

fn sum_weights(validators: &[Validator]) -> Result<u64, QuorumError> {
    let mut total: u64 = 0;
    for v in validators {
        total = total
            .checked_add(v.weight)
            .ok_or(QuorumError::WeightOverflow)?;
    }
    Ok(total)
}

/// A quorum certificate: signatures over `message` from the validators named in
/// `signer_bitmap` (bit `i` == validator `i`), in ascending index order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// The message that was signed (typically a checkpoint or block hash).
    pub message: Hash,
    /// Bitmap of participating validator indices.
    pub signer_bitmap: u64,
    /// Member signatures, aligned to the set bits in ascending order.
    #[serde(with = "sig_vec")]
    pub signatures: Vec<[u8; 64]>,
}

/// serde adapter for `Vec<[u8; 64]>` (serde has no built-in impl past 32 bytes).
mod sig_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &[[u8; 64]], s: S) -> Result<S::Ok, S::Error> {
        let as_slices: Vec<&[u8]> = v.iter().map(|a| a.as_slice()).collect();
        as_slices.serialize(s)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 64]>, D::Error> {
        let vecs: Vec<Vec<u8>> = Vec::deserialize(d)?;
        vecs.into_iter()
            .map(|v| {
                <[u8; 64]>::try_from(v.as_slice())
                    .map_err(|_| serde::de::Error::custom("signature must be 64 bytes"))
            })
            .collect()
    }
}

/// A deterministic k-of-n threshold signer simulator (software; the production
/// signer interface is separate). Each signer is an ed25519 keypair.
#[derive(Debug, Clone)]
pub struct ThresholdSigners {
    signers: Vec<KeyPair>,
    threshold: u64,
}

impl ThresholdSigners {
    /// Build `n` deterministic signers from seeds, with threshold `k`.
    pub fn from_seeds(seeds: &[[u8; 32]], k: u64) -> Self {
        Self {
            signers: seeds.iter().map(KeyPair::from_seed).collect(),
            threshold: k,
        }
    }

    /// The validator set (unit weight each) with threshold `k`.
    pub fn validator_set(&self) -> ValidatorSet {
        let validators = self
            .signers
            .iter()
            .map(|kp| Validator {
                public_key: kp.public(),
                weight: 1,
            })
            .collect();
        ValidatorSet::with_threshold(validators, self.threshold)
    }

    /// Produce a certificate over `message` from the given signer indices
    /// (deduplicated and applied in ascending order).
    pub fn sign(&self, message: Hash, mut indices: Vec<usize>) -> QuorumCertificate {
        indices.sort_unstable();
        indices.dedup();
        let mut bitmap = 0u64;
        let mut signatures = Vec::new();
        for &i in &indices {
            if i >= self.signers.len() || i >= MAX_VALIDATORS {
                continue;
            }
            bitmap |= 1u64 << i;
            signatures.push(self.signers[i].sign(message.as_bytes()));
        }
        QuorumCertificate {
            message,
            signer_bitmap: bitmap,
            signatures,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signers(n: usize, k: u64) -> ThresholdSigners {
        let seeds: Vec<[u8; 32]> = (0..n).map(|i| [u8::try_from(i).unwrap(); 32]).collect();
        ThresholdSigners::from_seeds(&seeds, k)
    }

    #[test]
    fn quorum_verifies_iff_threshold_met() {
        let ts = signers(4, 3); // 3-of-4
        let set = ts.validator_set();
        let msg = Hash::from_bytes([42u8; 32]);

        // 3 signers -> verifies.
        let qc = ts.sign(msg, vec![0, 1, 2]);
        assert!(set.verify(&qc).is_ok());

        // 2 signers -> below threshold.
        let qc2 = ts.sign(msg, vec![0, 1]);
        assert!(matches!(
            set.verify(&qc2),
            Err(QuorumError::BelowThreshold { .. })
        ));
    }

    #[test]
    fn rejects_malformed_and_unknown_and_tampered() {
        let ts = signers(4, 3);
        let set = ts.validator_set();
        let msg = Hash::from_bytes([1u8; 32]);

        // Signature count mismatch.
        let mut qc = ts.sign(msg, vec![0, 1, 2]);
        qc.signatures.pop();
        assert_eq!(set.verify(&qc), Err(QuorumError::MalformedCertificate));

        // Unknown signer bit (index 10 in a 4-validator set).
        let mut qc = ts.sign(msg, vec![0, 1, 2]);
        qc.signer_bitmap |= 1 << 10;
        qc.signatures.push([0u8; 64]);
        assert_eq!(set.verify(&qc), Err(QuorumError::UnknownSigner));

        // Tampered message vs signatures.
        let mut qc = ts.sign(msg, vec![0, 1, 2]);
        qc.message = Hash::from_bytes([2u8; 32]);
        assert_eq!(set.verify(&qc), Err(QuorumError::InvalidSignature));
    }

    #[test]
    fn any_k_of_n_subset_reconstructs() {
        let ts = signers(5, 3);
        let set = ts.validator_set();
        let msg = Hash::from_bytes([7u8; 32]);
        for subset in [vec![0, 1, 2], vec![2, 3, 4], vec![0, 2, 4], vec![1, 3, 4]] {
            assert!(set.verify(&ts.sign(msg, subset)).is_ok());
        }
        // Fewer than k fails.
        assert!(set.verify(&ts.sign(msg, vec![0, 4])).is_err());
    }

    #[test]
    fn try_new_bft_rejects_empty_oversized_and_weight_overflow() {
        assert_eq!(
            ValidatorSet::try_new_bft(vec![]),
            Err(QuorumError::InvalidSet)
        );
        let too_many: Vec<Validator> = (0..=MAX_VALIDATORS)
            .map(|i| Validator {
                public_key: [u8::try_from(i.min(255)).unwrap_or(0); 32],
                weight: 1,
            })
            .collect();
        assert_eq!(
            ValidatorSet::try_new_bft(too_many),
            Err(QuorumError::InvalidSet)
        );
        let overflow = vec![
            Validator {
                public_key: [1u8; 32],
                weight: u64::MAX,
            },
            Validator {
                public_key: [2u8; 32],
                weight: 1,
            },
        ];
        assert_eq!(
            ValidatorSet::try_new_bft(overflow),
            Err(QuorumError::WeightOverflow)
        );
    }

    #[test]
    fn try_with_threshold_rejects_zero_threshold() {
        let v = vec![Validator {
            public_key: [1u8; 32],
            weight: 1,
        }];
        assert_eq!(
            ValidatorSet::try_with_threshold(v, 0),
            Err(QuorumError::InvalidSet)
        );
    }
}

//! Validator sets, quorum certificates, and a deterministic threshold-signer
//! simulator (ed25519). Production HSM signers implement the same interface.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::hash::{hash_domain, DOMAIN_VALIDATOR_SET};
use crate::signature::{verify_ed25519, KeyPair};
use types::Hash;

/// Maximum number of validators in a [`ValidatorSet`].
///
/// Bound by the 64-bit `signer_bitmap` of a [`QuorumCertificate`]: bit `i`
/// names validator index `i`, so more than 64 members cannot be represented.
/// Consensus committees share this operational ceiling (see
/// `consensus::MAX_VALIDATORS`).
pub const MAX_VALIDATORS: usize = 64;

/// Version tag of the canonical validator-set encoding used by
/// [`ValidatorSet::commitment`]. Bumping it changes every commitment, so it is
/// bound into the hashed preimage and must move whenever the encoding changes.
pub const VALIDATOR_SET_VERSION: u16 = 1;

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
    /// The validator set is empty or exceeds [`MAX_VALIDATORS`].
    #[error("invalid validator set")]
    InvalidSet,
    /// Two members share a public key; one signer could otherwise be counted
    /// more than once toward the threshold.
    #[error("duplicate validator public key")]
    DuplicateValidator,
    /// A member has zero voting weight, which cannot contribute to any quorum
    /// and inflates the apparent membership count.
    #[error("validator has zero weight")]
    ZeroWeight,
    /// The threshold is zero or exceeds the total weight, so it can never (or
    /// only trivially) be met.
    #[error("threshold {threshold} outside 1..={total}")]
    ThresholdOutOfRange {
        /// The rejected threshold.
        threshold: u64,
        /// Total voting weight it was checked against.
        total: u64,
    },
}

/// A weighted validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    /// ed25519 public key.
    pub public_key: [u8; 32],
    /// Voting weight.
    pub weight: u64,
}

/// A validated validator set with a fixed weight threshold.
///
/// Every constructor is fallible and enforces the same canonical invariants:
/// nonempty membership no larger than [`MAX_VALIDATORS`], unique public keys,
/// strictly positive weights, an overflow-checked total, and a threshold in
/// `1..=total`. These invariants hold for the lifetime of the value, so quorum
/// verification never has to re-check them.
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

    /// Fallible canonical BFT constructor.
    ///
    /// Rejects empty sets, sets larger than [`MAX_VALIDATORS`], duplicate public
    /// keys, zero-weight members, and weight sums that overflow `u64`. The
    /// threshold is the strictly-greater-than-two-thirds quorum
    /// `floor(2*total/3) + 1`, computed without the `2*total` product so debug
    /// and release builds behave identically (no overflow panic, no wraparound).
    pub fn try_new_bft(validators: Vec<Validator>) -> Result<Self, QuorumError> {
        let total = validate_membership(&validators)?;
        let threshold = bft_threshold(total);
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

    /// Fallible canonical explicit-threshold constructor.
    ///
    /// Rejects empty sets, sets larger than [`MAX_VALIDATORS`], duplicate public
    /// keys, zero-weight members, weight overflow, and any threshold outside
    /// `1..=total`.
    pub fn try_with_threshold(
        validators: Vec<Validator>,
        threshold: u64,
    ) -> Result<Self, QuorumError> {
        let total = validate_membership(&validators)?;
        if threshold == 0 || threshold > total {
            return Err(QuorumError::ThresholdOutOfRange { threshold, total });
        }
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

    /// A canonical, versioned commitment to this set's membership and threshold.
    ///
    /// The preimage is domain-separated ([`DOMAIN_VALIDATOR_SET`]), carries
    /// [`VALIDATOR_SET_VERSION`], and lists members sorted by public key. Because
    /// members are canonically ordered and duplicates are rejected at
    /// construction, two sets built from the same members in any input order
    /// commit to the same hash, while any change to a key, weight, threshold, or
    /// membership changes it.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        let mut ordered: Vec<&Validator> = self.validators.iter().collect();
        ordered.sort_unstable_by(|a, b| a.public_key.cmp(&b.public_key));

        let mut buf = Vec::with_capacity(2 + 8 + 8 + 4 + ordered.len() * (32 + 8));
        buf.extend_from_slice(&VALIDATOR_SET_VERSION.to_le_bytes());
        buf.extend_from_slice(&self.threshold.to_le_bytes());
        buf.extend_from_slice(&self.total_weight.to_le_bytes());
        // Length-prefix the membership so it can never be confused with a
        // different set whose trailing bytes happen to align.
        let count = u32::try_from(ordered.len()).unwrap_or(u32::MAX);
        buf.extend_from_slice(&count.to_le_bytes());
        for v in ordered {
            buf.extend_from_slice(&v.public_key);
            buf.extend_from_slice(&v.weight.to_le_bytes());
        }
        hash_domain(DOMAIN_VALIDATOR_SET, &buf)
    }
}

/// The strictly-greater-than-two-thirds BFT quorum `floor(2*total/3) + 1`.
///
/// Computed without forming the `2 * total` product (which overflows `u64` for
/// `total > u64::MAX / 2`): with `total = 3*q + r` and `r in {0,1,2}`,
/// `floor(2*total/3) = 2*q + floor(2*r/3)`. Every intermediate fits in `u64`
/// (`2*q <= 2*(u64::MAX/3) < u64::MAX`), so the result is identical in debug and
/// release and never panics. For any `total >= 1` the result lies in `1..=total`
/// and satisfies `3 * threshold > 2 * total`.
const fn bft_threshold(total: u64) -> u64 {
    let q = total / 3;
    let r = total % 3;
    // `2*q` and the `<= 1` correction cannot overflow; see the doc comment.
    2 * q + (2 * r) / 3 + 1
}

/// Validate canonical membership and return the overflow-checked total weight.
///
/// Enforces nonempty membership no larger than [`MAX_VALIDATORS`], unique public
/// keys, strictly positive weights, and a `u64`-checked weight sum.
fn validate_membership(validators: &[Validator]) -> Result<u64, QuorumError> {
    if validators.is_empty() || validators.len() > MAX_VALIDATORS {
        return Err(QuorumError::InvalidSet);
    }
    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut total: u64 = 0;
    for v in validators {
        if v.weight == 0 {
            return Err(QuorumError::ZeroWeight);
        }
        if !seen.insert(v.public_key) {
            return Err(QuorumError::DuplicateValidator);
        }
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
    fn try_with_threshold_rejects_zero_and_over_total() {
        let v = vec![
            Validator {
                public_key: [1u8; 32],
                weight: 2,
            },
            Validator {
                public_key: [2u8; 32],
                weight: 3,
            },
        ];
        // total == 5.
        assert_eq!(
            ValidatorSet::try_with_threshold(v.clone(), 0),
            Err(QuorumError::ThresholdOutOfRange {
                threshold: 0,
                total: 5
            })
        );
        assert_eq!(
            ValidatorSet::try_with_threshold(v.clone(), 6),
            Err(QuorumError::ThresholdOutOfRange {
                threshold: 6,
                total: 5
            })
        );
        // Boundaries 1 and total both accepted.
        assert!(ValidatorSet::try_with_threshold(v.clone(), 1).is_ok());
        assert!(ValidatorSet::try_with_threshold(v, 5).is_ok());
    }

    #[test]
    fn rejects_duplicate_keys_and_zero_weights() {
        let dup = vec![
            Validator {
                public_key: [7u8; 32],
                weight: 1,
            },
            Validator {
                public_key: [7u8; 32],
                weight: 1,
            },
        ];
        assert_eq!(
            ValidatorSet::try_new_bft(dup.clone()),
            Err(QuorumError::DuplicateValidator)
        );
        assert_eq!(
            ValidatorSet::try_with_threshold(dup, 1),
            Err(QuorumError::DuplicateValidator)
        );

        let zero = vec![
            Validator {
                public_key: [1u8; 32],
                weight: 1,
            },
            Validator {
                public_key: [2u8; 32],
                weight: 0,
            },
        ];
        assert_eq!(
            ValidatorSet::try_new_bft(zero.clone()),
            Err(QuorumError::ZeroWeight)
        );
        assert_eq!(
            ValidatorSet::try_with_threshold(zero, 1),
            Err(QuorumError::ZeroWeight)
        );
    }

    /// `floor(2*total/3) + 1` reference over `u128`, immune to `u64` overflow.
    fn bft_threshold_reference(total: u64) -> u64 {
        let t = u128::from(total);
        u64::try_from((2 * t) / 3 + 1).expect("BFT threshold always fits in u64")
    }

    #[test]
    fn bft_threshold_matches_reference_and_is_overflow_safe() {
        // A deterministic splitmix64 walk plus exact overflow boundaries. Every
        // sample must reproduce the u128 reference and never panic.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut totals: Vec<u64> = vec![
            1,
            2,
            3,
            4,
            5,
            6,
            u64::MAX,
            u64::MAX - 1,
            u64::MAX - 2,
            u64::MAX / 2,
            u64::MAX / 2 + 1,
            u64::MAX / 3,
            u64::MAX / 3 + 1,
            (u64::MAX / 3) * 3,
        ];
        for _ in 0..20_000 {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            totals.push((z ^ (z >> 31)).max(1));
        }
        for total in totals {
            assert_eq!(
                bft_threshold(total),
                bft_threshold_reference(total),
                "threshold mismatch for total {total}"
            );
        }
    }

    #[test]
    fn bft_threshold_strictly_exceeds_two_thirds() {
        // Property: for every valid total, 3*threshold > 2*total (strict), and
        // threshold stays within 1..=total. Checked over u128 so the comparison
        // itself cannot overflow.
        let mut state: u64 = 0x0123_4567_89AB_CDEF;
        let mut totals: Vec<u64> = vec![1, 2, 3, 4, 5, u64::MAX, u64::MAX - 1, u64::MAX / 3];
        for _ in 0..50_000 {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            totals.push((z ^ (z >> 31)).max(1));
        }
        for total in totals {
            let threshold = bft_threshold(total);
            assert!(threshold >= 1, "threshold underflow for total {total}");
            assert!(threshold <= total, "threshold exceeds total {total}");
            assert!(
                3 * u128::from(threshold) > 2 * u128::from(total),
                "threshold not strictly above two-thirds for total {total}"
            );
            // One short of the threshold must be at or below two-thirds.
            assert!(
                3 * u128::from(threshold - 1) <= 2 * u128::from(total),
                "threshold not minimal for total {total}"
            );
        }
    }

    #[test]
    fn try_new_bft_threshold_within_bounds_for_weighted_sets() {
        // A weighted set whose total nears the overflow boundary still yields a
        // valid, in-range threshold (release and debug behave identically).
        let set = ValidatorSet::try_new_bft(vec![
            Validator {
                public_key: [1u8; 32],
                weight: u64::MAX - 10,
            },
            Validator {
                public_key: [2u8; 32],
                weight: 10,
            },
        ])
        .expect("near-max weighted BFT set is valid");
        assert_eq!(set.total_weight(), u64::MAX);
        assert_eq!(set.threshold(), bft_threshold_reference(u64::MAX));
        assert!(set.threshold() >= 1 && set.threshold() <= set.total_weight());
    }

    #[test]
    fn commitment_is_invariant_to_input_ordering() {
        let a = Validator {
            public_key: [3u8; 32],
            weight: 5,
        };
        let b = Validator {
            public_key: [1u8; 32],
            weight: 7,
        };
        let c = Validator {
            public_key: [2u8; 32],
            weight: 9,
        };
        let forward =
            ValidatorSet::try_with_threshold(vec![a.clone(), b.clone(), c.clone()], 12).unwrap();
        let shuffled = ValidatorSet::try_with_threshold(vec![c, a, b], 12).unwrap();
        // Same members, weights, and threshold in a different input order ->
        // identical canonical commitment.
        assert_eq!(forward.commitment(), shuffled.commitment());
    }

    #[test]
    fn commitment_binds_membership_weight_and_threshold() {
        let base = ValidatorSet::try_with_threshold(
            vec![
                Validator {
                    public_key: [1u8; 32],
                    weight: 3,
                },
                Validator {
                    public_key: [2u8; 32],
                    weight: 4,
                },
            ],
            5,
        )
        .unwrap();
        let base_commit = base.commitment();

        // Different threshold.
        let other_threshold = ValidatorSet::try_with_threshold(
            vec![
                Validator {
                    public_key: [1u8; 32],
                    weight: 3,
                },
                Validator {
                    public_key: [2u8; 32],
                    weight: 4,
                },
            ],
            6,
        )
        .unwrap();
        assert_ne!(base_commit, other_threshold.commitment());

        // Different weight.
        let other_weight = ValidatorSet::try_with_threshold(
            vec![
                Validator {
                    public_key: [1u8; 32],
                    weight: 3,
                },
                Validator {
                    public_key: [2u8; 32],
                    weight: 5,
                },
            ],
            5,
        )
        .unwrap();
        assert_ne!(base_commit, other_weight.commitment());

        // Different membership (a key changes).
        let other_member = ValidatorSet::try_with_threshold(
            vec![
                Validator {
                    public_key: [1u8; 32],
                    weight: 3,
                },
                Validator {
                    public_key: [9u8; 32],
                    weight: 4,
                },
            ],
            5,
        )
        .unwrap();
        assert_ne!(base_commit, other_member.commitment());
    }
}

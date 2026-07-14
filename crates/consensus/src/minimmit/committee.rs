//! The Minimmit dual-threshold committee: one validated membership exposing
//! both the advance (`M = 2B + 1`) and finalize (`L = W − B`) verification
//! sets, plus the [`Certificate`] assembly / verification seam.
//!
//! An M-certificate and an L-certificate are the **same**
//! [`crypto::QuorumCertificate`] verified
//! against two [`ValidatorSet`]s that differ only in threshold — zero new
//! crypto primitives. The BLS drop-in seam is the [`Certificate`] alias held
//! behind [`MinimmitCommittee::assemble`] / [`MinimmitCommittee::verify`]:
//! swapping the certificate backend is a crypto + committee change, never a
//! consensus-logic change (§4.5, §13.2).

use crypto::{
    minimmit_thresholds, minimmit_unit_byzantine_bound, require_minimmit_sizing, CachedEd25519Key,
    QuorumCertificate, QuorumError, QuorumSignatures, Validator, ValidatorSet,
};
use types::Hash;

use crate::vote::{VoteError, MAX_VALIDATORS};

/// The certificate type Minimmit notarizations / nullifications carry.
///
/// Today this is exactly [`crypto::QuorumCertificate`] (ed25519 signatures +
/// `u16` signer bitmap, linear size). It is deliberately referenced only
/// through this alias and assembled / verified behind [`MinimmitCommittee`]
/// so a future constant-size BLS certificate can drop in without touching the
/// replica's rules (`docs/CONSENSUS_MINIMMIT.md` §13.2).
// SEAM: docs/ADR_MINIMMIT_BLS_CERTIFICATES.md defines the demand-gated BLS swap.
pub type Certificate = QuorumCertificate;

/// Which of the two Minimmit verification bars a certificate is checked
/// against ([`MinimmitCommittee::verify`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThresholdKind {
    /// The advance threshold `M = 2B + 1`: an M-certificate (notarization or
    /// nullification) advances the view.
    Advance,
    /// The finalize threshold `L = W − B`: an L-notarization finalizes the
    /// block and its ancestors; the execution certificate also verifies here.
    Finalize,
}

/// Detailed, deterministic Minimmit certificate verification failure.
///
/// Unlike the compatibility [`QuorumError`] surface, signer-specific failures
/// retain the exact committee index. This is the scalar conformance oracle for
/// optimized batch kernels: a failed batch must attribute the same first bad
/// signer in ascending bitmap order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MinimmitCertificateError {
    #[error("signature count does not match signer bitmap")]
    MalformedCertificate,
    #[error("unknown signer index {index}")]
    UnknownSigner { index: u16 },
    #[error("invalid signature at signer index {index}")]
    InvalidSignature { index: u16 },
    #[error("validator weight sum overflowed")]
    WeightOverflow,
    #[error("signed weight {signed} below threshold {threshold}")]
    BelowThreshold { signed: u64, threshold: u64 },
}

impl From<MinimmitCertificateError> for QuorumError {
    fn from(error: MinimmitCertificateError) -> Self {
        match error {
            MinimmitCertificateError::MalformedCertificate => Self::MalformedCertificate,
            MinimmitCertificateError::UnknownSigner { .. } => Self::UnknownSigner,
            MinimmitCertificateError::InvalidSignature { .. } => Self::InvalidSignature,
            MinimmitCertificateError::WeightOverflow => Self::WeightOverflow,
            MinimmitCertificateError::BelowThreshold { signed, threshold } => {
                Self::BelowThreshold { signed, threshold }
            }
        }
    }
}

/// The validators of one epoch exposing **both** Minimmit thresholds over a
/// single validated membership.
///
/// One member `Vec<Validator>` is validated once (canonical-membership
/// invariants of [`ValidatorSet`] plus the `W >= 5B + 1` / `M < L` sizing
/// guard) and wrapped into two [`ValidatorSet`] handles that share the same
/// membership in the same canonical order (signer bitmaps line up):
///
/// - `advance_set` — threshold `M = 2B + 1` (form a certificate ⇒ advance),
/// - `finalize_set` — threshold `L = W − B` (finalize).
///
/// **Canonical-set rule:** [`ValidatorSet::commitment`] binds the threshold,
/// so the two sets hash differently. The [`Self::finalize_set`] (`L`) is the
/// single canonical set for every commitment (checkpoints, epoch transitions,
/// light-client verification) — never feed the M-set into a commitment.
///
/// Validator indices are `u16`, matching the Minimmit wire standard and the
/// 16-bit certificate signer bitmap.
#[derive(Debug, Clone)]
pub struct MinimmitCommittee {
    epoch: u64,
    byzantine_weight: u64,
    /// Threshold `M`; same membership and order as `finalize_set`.
    advance_set: ValidatorSet,
    /// Threshold `L`; the canonical set for commitments.
    finalize_set: ValidatorSet,
    /// Pre-parsed verifying keys aligned with the canonical membership order.
    cached_keys: Vec<CachedEd25519Key>,
    /// Fixed lanes for the common `u32`-bounded weighted committee. `None`
    /// retains the full-width scalar path for unusually large validator weights.
    weight_lanes: Option<[u32; MAX_VALIDATORS]>,
    /// Unit committees use one scalar popcount, which is faster than either a
    /// branch loop or a vector gather at the bounded 16-member envelope.
    unit_weights: bool,
    /// Non-consensus runtime implementation choice for the pure weight sum.
    quorum_backend: simd::Backend,
}

impl MinimmitCommittee {
    /// Build a Minimmit committee for `epoch` sized against an explicit
    /// Byzantine **weight** bound `B` (weighted-correct; for the common
    /// unit-weight committee use [`Self::new_unit`]).
    ///
    /// Never panics on untrusted input. Rejects, in order:
    ///
    /// - an empty membership ([`VoteError::EmptyCommittee`]),
    /// - more than [`MAX_VALIDATORS`] members
    ///   ([`VoteError::TooManyValidators`]),
    /// - noncanonical membership — duplicate public keys, zero weights, weight
    ///   overflow, or unparseable ed25519 keys
    ///   ([`VoteError::InvalidValidatorSet`]),
    /// - fault-model violations — `W < 5B + 1` or a collapsed `M >= L`
    ///   separation ([`VoteError::InsufficientSizing`]).
    pub fn new(
        epoch: u64,
        validators: Vec<Validator>,
        byzantine_weight: u64,
    ) -> Result<Self, VoteError> {
        if validators.is_empty() {
            return Err(VoteError::EmptyCommittee);
        }
        if validators.len() > MAX_VALIDATORS {
            return Err(VoteError::TooManyValidators);
        }
        // Validate the membership once (threshold 1 is always in range for a
        // canonical set) so membership errors surface before sizing errors,
        // and take the overflow-checked total from it.
        let membership = ValidatorSet::try_with_threshold(validators.clone(), 1)
            .map_err(|_| VoteError::InvalidValidatorSet)?;
        let total_weight = membership.total_weight();
        require_minimmit_sizing(total_weight, byzantine_weight).map_err(|_| {
            VoteError::InsufficientSizing {
                total_weight,
                byzantine_weight,
            }
        })?;
        // Cannot fail after the sizing guard; propagate defensively.
        let (advance, finalize) =
            minimmit_thresholds(total_weight, byzantine_weight).map_err(|_| {
                VoteError::InsufficientSizing {
                    total_weight,
                    byzantine_weight,
                }
            })?;
        let advance_set = ValidatorSet::try_with_threshold(validators.clone(), advance)
            .map_err(|_| VoteError::InvalidValidatorSet)?;
        let finalize_set = ValidatorSet::try_with_threshold(validators, finalize)
            .map_err(|_| VoteError::InvalidValidatorSet)?;
        let mut cached_keys = Vec::with_capacity(finalize_set.len());
        let mut weight_lanes = [0u32; MAX_VALIDATORS];
        let mut weights_fit_u32 = true;
        let mut unit_weights = true;
        for (index, v) in finalize_set.validators().iter().enumerate() {
            cached_keys.push(
                CachedEd25519Key::parse(&v.public_key)
                    .map_err(|_| VoteError::InvalidValidatorSet)?,
            );
            match u32::try_from(v.weight) {
                Ok(weight) => weight_lanes[index] = weight,
                Err(_) => weights_fit_u32 = false,
            }
            unit_weights &= v.weight == 1;
        }
        Ok(Self {
            epoch,
            byzantine_weight,
            advance_set,
            finalize_set,
            cached_keys,
            weight_lanes: weights_fit_u32.then_some(weight_lanes),
            unit_weights,
            quorum_backend: simd::detect(),
        })
    }

    /// Unit-weight convenience: derive the Byzantine bound `f = ⌊(n−1)/5⌋`
    /// (the committee's capacity, the greatest `f` with `n >= 5f + 1`) from
    /// the member count and delegate to [`Self::new`].
    ///
    /// Every member must carry weight exactly `1` — deriving `f` from a count
    /// is meaningless for weighted memberships, which must size against an
    /// explicit Byzantine weight via [`Self::new`]. Non-unit weights are
    /// rejected with [`VoteError::InvalidValidatorSet`]. Note `n = 2..=5`
    /// derives `f = 0` — a demo-only committee with no Byzantine tolerance
    /// (`M = 1`, `L = n`).
    pub fn new_unit(epoch: u64, validators: Vec<Validator>) -> Result<Self, VoteError> {
        if validators.iter().any(|v| v.weight != 1) {
            return Err(VoteError::InvalidValidatorSet);
        }
        let n = u64::try_from(validators.len()).unwrap_or(u64::MAX);
        Self::new(epoch, validators, minimmit_unit_byzantine_bound(n))
    }

    /// The committee epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Number of validators.
    #[must_use]
    pub fn len(&self) -> usize {
        self.finalize_set.len()
    }

    /// Canonical committee commitment for checkpoints and epoch transitions.
    ///
    /// This always binds the L threshold. The M-set commitment is intentionally
    /// available only through the explicitly named [`Self::advance_set`].
    #[must_use]
    pub fn canonical_commitment(&self) -> Hash {
        self.finalize_set.commitment()
    }

    /// Whether the committee is empty (never true post-construction).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.finalize_set.is_empty()
    }

    /// Total voting weight `W`.
    #[must_use]
    pub fn total_weight(&self) -> u64 {
        self.finalize_set.total_weight()
    }

    /// The Byzantine weight bound `B` this committee was sized against.
    #[must_use]
    pub fn byzantine_weight(&self) -> u64 {
        self.byzantine_weight
    }

    /// The advance threshold `M = 2B + 1`.
    #[must_use]
    pub fn advance_threshold(&self) -> u64 {
        self.advance_set.threshold()
    }

    /// The finalize threshold `L = W − B`.
    #[must_use]
    pub fn finalize_threshold(&self) -> u64 {
        self.finalize_set.threshold()
    }

    /// The [`ValidatorSet`] verifying at the advance threshold `M`.
    #[must_use]
    pub fn advance_set(&self) -> &ValidatorSet {
        &self.advance_set
    }

    /// The [`ValidatorSet`] verifying at the finalize threshold `L`.
    ///
    /// This is the **single canonical set** for every commitment (checkpoint,
    /// epoch transition, light-client verification): commitments bind the
    /// threshold, so the M-set hashes differently and must never feed one.
    #[must_use]
    pub fn finalize_set(&self) -> &ValidatorSet {
        &self.finalize_set
    }

    /// The validators in canonical membership order (bit `i` of a
    /// [`Certificate`] signer bitmap names `validators()[i]`).
    #[must_use]
    pub fn validators(&self) -> &[Validator] {
        self.finalize_set.validators()
    }

    /// Public key of validator `index`, if present.
    #[must_use]
    pub fn public_key(&self, index: u16) -> Option<[u8; 32]> {
        self.validators()
            .get(usize::from(index))
            .map(|v| v.public_key)
    }

    /// Cached verifying key of validator `index`, if present.
    #[must_use]
    pub fn cached_key(&self, index: u16) -> Option<&CachedEd25519Key> {
        self.cached_keys.get(usize::from(index))
    }

    /// Voting weight of validator `index`, if present.
    #[must_use]
    pub fn weight(&self, index: u16) -> Option<u64> {
        self.validators().get(usize::from(index)).map(|v| v.weight)
    }

    /// Deterministic round-robin leader: `(epoch + view) mod n`
    /// (`docs/CONSENSUS_MINIMMIT.md` §6.1).
    #[must_use]
    pub fn leader(&self, view: u64) -> u16 {
        let n = u64::try_from(self.len()).unwrap_or(1).max(1);
        let idx = self.epoch.wrapping_add(view) % n;
        // `idx < n <= MAX_VALIDATORS = 16` always fits in u16.
        u16::try_from(idx).unwrap_or(0)
    }

    /// Assemble a [`Certificate`] over `message` from `(validator_index,
    /// signature)` pairs — the certificate-construction half of the BLS seam.
    ///
    /// Signers are deduplicated by index (first occurrence wins) and packed in
    /// ascending index order, the canonical bitmap alignment. Signatures are
    /// **not** cryptographically verified here: admission (the vote tallies)
    /// verifies each signature exactly once, and [`Self::verify`] re-checks an
    /// assembled or received certificate end-to-end. No threshold is enforced
    /// at assembly — the same call site assembles M-certs and L-certs and
    /// checks the bar it needs via [`Self::verify`].
    ///
    /// # Errors
    ///
    /// [`VoteError::ForeignSigner`] if any index is outside the committee.
    pub fn assemble(
        &self,
        message: Hash,
        signers: &[(u16, [u8; 64])],
    ) -> Result<Certificate, VoteError> {
        let mut by_index = [None; MAX_VALIDATORS];
        for &(index, signature) in signers {
            if usize::from(index) >= self.len() {
                return Err(VoteError::ForeignSigner(u32::from(index)));
            }
            let slot = &mut by_index[usize::from(index)];
            if slot.is_none() {
                *slot = Some(signature);
            }
        }
        let mut signer_bitmap: u16 = 0;
        let mut signatures = QuorumSignatures::new();
        for (index, signature) in by_index.into_iter().take(self.len()).enumerate() {
            if let Some(signature) = signature {
                signer_bitmap |= 1u16 << u16::try_from(index).unwrap_or(0);
                signatures
                    .try_push(signature)
                    .map_err(|_| VoteError::TooManyValidators)?;
            }
        }
        Ok(Certificate {
            message,
            signer_bitmap,
            signatures,
        })
    }

    /// Verify a [`Certificate`] at one of the two Minimmit bars — the
    /// certificate-verification half of the BLS seam.
    ///
    /// Routes to the [`Self::advance_set`] (`M`) or [`Self::finalize_set`]
    /// (`L`) and re-verifies every signature plus the signed-weight threshold.
    /// The caller owns the digest-equality check (`cert.message` must equal
    /// the recomputed notarize / nullify digest —
    /// [`Notarization::verify`](super::Notarization::verify) /
    /// [`Nullification::verify`](super::Nullification::verify) layer it on
    /// top, #519).
    ///
    /// # Errors
    ///
    /// Any [`QuorumError`] from [`ValidatorSet::verify`]: unknown signer,
    /// malformed certificate, invalid signature, or below-threshold weight.
    pub fn verify(&self, cert: &Certificate, kind: ThresholdKind) -> Result<(), QuorumError> {
        self.verify_detailed(cert, kind).map_err(Into::into)
    }

    /// Verify with cached committee keys and preserve deterministic bad-signer
    /// attribution. This hot path performs no heap allocation.
    pub fn verify_detailed(
        &self,
        cert: &Certificate,
        kind: ThresholdKind,
    ) -> Result<(), MinimmitCertificateError> {
        self.verify_detailed_with_backend(cert, kind, self.quorum_backend)
    }

    /// Qualification entry point using an explicit weight-reduction backend.
    ///
    /// Signature checks and deterministic bad-signer attribution are identical
    /// to [`Self::verify_detailed`]. An unavailable architecture tag executes
    /// the checked scalar weight oracle; production construction caches the
    /// runnable backend returned by [`simd::detect`].
    pub fn verify_detailed_with_backend(
        &self,
        cert: &Certificate,
        kind: ThresholdKind,
        backend: simd::Backend,
    ) -> Result<(), MinimmitCertificateError> {
        if cert.signer_count() != cert.signatures.len() {
            return Err(MinimmitCertificateError::MalformedCertificate);
        }
        let threshold = match kind {
            ThresholdKind::Advance => self.advance_threshold(),
            ThresholdKind::Finalize => self.finalize_threshold(),
        };
        let mut signature_index = 0usize;
        for index in 0..u16::BITS {
            if cert.signer_bitmap & (1u16 << index) == 0 {
                continue;
            }
            let validator_index = u16::try_from(index).unwrap_or(u16::MAX);
            self.validators().get(usize::from(validator_index)).ok_or(
                MinimmitCertificateError::UnknownSigner {
                    index: validator_index,
                },
            )?;
            let signature = cert
                .signatures
                .get(signature_index)
                .ok_or(MinimmitCertificateError::MalformedCertificate)?;
            signature_index += 1;
            self.cached_keys[usize::from(validator_index)]
                .verify(cert.message.as_bytes(), signature)
                .map_err(|_| MinimmitCertificateError::InvalidSignature {
                    index: validator_index,
                })?;
        }
        // Weight accumulation is independent only after all ordered signature
        // checks have succeeded. Keeping it here preserves the scalar oracle's
        // exact malformed/unknown/invalid error precedence.
        let signed_weight = self.selected_weight(cert.signer_bitmap, backend)?;
        if signed_weight < threshold {
            return Err(MinimmitCertificateError::BelowThreshold {
                signed: signed_weight,
                threshold,
            });
        }
        Ok(())
    }

    fn selected_weight(
        &self,
        signer_bitmap: u16,
        backend: simd::Backend,
    ) -> Result<u64, MinimmitCertificateError> {
        if self.unit_weights {
            return Ok(u64::from(signer_bitmap.count_ones()));
        }
        if let Some(weights) = &self.weight_lanes {
            return simd::selected_weight(backend, signer_bitmap, weights, self.len()).ok_or_else(
                || MinimmitCertificateError::UnknownSigner {
                    index: first_unknown_signer(signer_bitmap, self.len()),
                },
            );
        }

        let mut signed_weight = 0u64;
        for (index, validator) in self.validators().iter().enumerate() {
            if signer_bitmap & (1u16 << index) != 0 {
                signed_weight = signed_weight
                    .checked_add(validator.weight)
                    .ok_or(MinimmitCertificateError::WeightOverflow)?;
            }
        }
        Ok(signed_weight)
    }
}

fn first_unknown_signer(signer_bitmap: u16, committee_len: usize) -> u16 {
    let valid_mask = if committee_len >= MAX_VALIDATORS {
        u16::MAX
    } else {
        (1u16 << committee_len) - 1
    };
    u16::try_from((signer_bitmap & !valid_mask).trailing_zeros()).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::KeyPair;

    /// Deterministic keypairs; seed `i + 1` so no all-zero seed is used.
    fn keypairs(n: usize) -> Vec<KeyPair> {
        (0..n)
            .map(|i| KeyPair::from_seed(&[u8::try_from(i).unwrap() + 1; 32]))
            .collect()
    }

    fn validators(keys: &[KeyPair], weights: &[u64]) -> Vec<Validator> {
        assert_eq!(keys.len(), weights.len());
        keys.iter()
            .zip(weights)
            .map(|(kp, &weight)| Validator {
                public_key: kp.public(),
                weight,
            })
            .collect()
    }

    fn unit_validators(keys: &[KeyPair]) -> Vec<Validator> {
        validators(keys, &vec![1u64; keys.len()])
    }

    /// Sign `message` with the keypairs at `indices`, as `(index, sig)` pairs.
    fn sign_all(keys: &[KeyPair], message: Hash, indices: &[u16]) -> Vec<(u16, [u8; 64])> {
        indices
            .iter()
            .map(|&i| (i, keys[usize::from(i)].sign(message.as_bytes())))
            .collect()
    }

    #[test]
    fn rejects_undersized_and_builds_at_5f_plus_1() {
        // f = 1 needs n >= 6: n = 3, 4, 5 rejected with the sizing error.
        for n in [3usize, 4, 5] {
            let keys = keypairs(n);
            assert_eq!(
                MinimmitCommittee::new(0, unit_validators(&keys), 1).unwrap_err(),
                VoteError::InsufficientSizing {
                    total_weight: u64::try_from(n).unwrap(),
                    byzantine_weight: 1,
                },
                "n={n} at f=1 must be rejected"
            );
        }
        // n = 6 at f = 1 builds: M = 3, L = 5, shared membership.
        let keys = keypairs(6);
        let committee = MinimmitCommittee::new(7, unit_validators(&keys), 1).unwrap();
        assert_eq!(committee.epoch(), 7);
        assert_eq!(committee.len(), 6);
        assert!(!committee.is_empty());
        assert_eq!(committee.total_weight(), 6);
        assert_eq!(committee.byzantine_weight(), 1);
        assert_eq!(committee.advance_threshold(), 3);
        assert_eq!(committee.finalize_threshold(), 5);
        assert_eq!(
            committee.advance_set().validators(),
            committee.finalize_set().validators(),
            "both sets share one canonical membership"
        );
        assert_ne!(
            committee.advance_set().commitment(),
            committee.finalize_set().commitment(),
            "commitments bind the threshold; only the L-set is canonical"
        );
        // Accessors line up with the canonical order.
        assert_eq!(committee.public_key(0), Some(keys[0].public()));
        assert_eq!(committee.weight(5), Some(1));
        assert_eq!(committee.public_key(6), None);
        assert_eq!(committee.weight(6), None);
        assert!(committee.cached_key(5).is_some());
        assert!(committee.cached_key(6).is_none());
    }

    #[test]
    fn constructor_rejects_noncanonical_membership() {
        assert_eq!(
            MinimmitCommittee::new(0, vec![], 1).unwrap_err(),
            VoteError::EmptyCommittee
        );

        let too_many = keypairs(MAX_VALIDATORS + 1);
        assert_eq!(
            MinimmitCommittee::new(0, unit_validators(&too_many), 3).unwrap_err(),
            VoteError::TooManyValidators
        );

        // Duplicate public key: membership error wins over sizing.
        let keys = keypairs(6);
        let mut dup = unit_validators(&keys);
        dup[1].public_key = dup[0].public_key;
        assert_eq!(
            MinimmitCommittee::new(0, dup, 1).unwrap_err(),
            VoteError::InvalidValidatorSet
        );

        // Zero-weight member.
        let mut zero = unit_validators(&keys);
        zero[2].weight = 0;
        assert_eq!(
            MinimmitCommittee::new(0, zero, 1).unwrap_err(),
            VoteError::InvalidValidatorSet
        );

        // Byzantine bound beyond capacity: n = 16 tolerates f <= 3.
        let sixteen = keypairs(16);
        assert_eq!(
            MinimmitCommittee::new(0, unit_validators(&sixteen), 4).unwrap_err(),
            VoteError::InsufficientSizing {
                total_weight: 16,
                byzantine_weight: 4,
            }
        );
    }

    #[test]
    fn one_signer_set_verifies_at_m_and_at_l() {
        // n = 6, f = 1: M = 3, L = 5. The SAME signer set forms certificates
        // checked against advance_set at M and finalize_set at L.
        let keys = keypairs(6);
        let committee = MinimmitCommittee::new(0, unit_validators(&keys), 1).unwrap();
        let msg = Hash::from_bytes([0xABu8; 32]);

        // An M-quorum: passes the advance bar, fails the finalize bar.
        let m_cert = committee
            .assemble(msg, &sign_all(&keys, msg, &[1, 3, 5]))
            .unwrap();
        assert_eq!(committee.verify(&m_cert, ThresholdKind::Advance), Ok(()));
        assert_eq!(
            committee.verify(&m_cert, ThresholdKind::Finalize),
            Err(QuorumError::BelowThreshold {
                signed: 3,
                threshold: 5,
            }),
            "verify(cert, L) must route to the finalize set"
        );
        // The raw sets agree with the routed verification.
        assert!(committee.advance_set().verify(&m_cert).is_ok());
        assert!(committee.finalize_set().verify(&m_cert).is_err());

        // An L-quorum passes both bars (an L-quorum is an M-quorum).
        let l_cert = committee
            .assemble(msg, &sign_all(&keys, msg, &[0, 1, 2, 3, 4]))
            .unwrap();
        assert_eq!(committee.verify(&l_cert, ThresholdKind::Advance), Ok(()));
        assert_eq!(committee.verify(&l_cert, ThresholdKind::Finalize), Ok(()));
        assert!(committee.advance_set().verify(&l_cert).is_ok());
        assert!(committee.finalize_set().verify(&l_cert).is_ok());

        // Below M fails both.
        let sub_m = committee
            .assemble(msg, &sign_all(&keys, msg, &[2, 4]))
            .unwrap();
        assert_eq!(
            committee.verify(&sub_m, ThresholdKind::Advance),
            Err(QuorumError::BelowThreshold {
                signed: 2,
                threshold: 3,
            }),
            "verify(cert, M) must route to the advance set"
        );
        assert!(committee.verify(&sub_m, ThresholdKind::Finalize).is_err());
    }

    #[test]
    fn detailed_verification_attributes_the_first_invalid_signer() {
        let keys = keypairs(11);
        let committee = MinimmitCommittee::new_unit(4, unit_validators(&keys)).unwrap();
        let msg = Hash::from_bytes([0xC7; 32]);
        let mut cert = committee
            .assemble(msg, &sign_all(&keys, msg, &[0, 2, 4, 6, 8, 10]))
            .unwrap();
        cert.signatures[1][7] ^= 0x80;
        cert.signatures[4][9] ^= 0x40;

        assert_eq!(
            committee.verify_detailed(&cert, ThresholdKind::Advance),
            Err(MinimmitCertificateError::InvalidSignature { index: 2 })
        );
        assert_eq!(
            committee.verify(&cert, ThresholdKind::Advance),
            Err(QuorumError::InvalidSignature),
            "the compatibility surface must retain its established error"
        );
    }

    #[test]
    fn scalar_and_simd_weight_paths_preserve_qc_results_and_error_precedence() {
        let keys = keypairs(16);
        let weights = [
            1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597,
        ];
        let committee = MinimmitCommittee::new(12, validators(&keys, &weights), 500).unwrap();
        let msg = Hash::from_bytes([0xD4; 32]);
        let cert = committee
            .assemble(msg, &sign_all(&keys, msg, &[0, 2, 4, 6, 8, 10, 12, 14, 15]))
            .unwrap();
        for kind in [ThresholdKind::Advance, ThresholdKind::Finalize] {
            let scalar = committee.verify_detailed_with_backend(&cert, kind, simd::Backend::Scalar);
            for backend in [
                simd::Backend::Avx2,
                simd::Backend::Avx512,
                simd::Backend::Neon,
            ] {
                assert_eq!(
                    committee.verify_detailed_with_backend(&cert, kind, backend),
                    scalar,
                    "backend={backend:?} kind={kind:?}"
                );
            }
        }

        let short_keys = keypairs(6);
        let short = MinimmitCommittee::new_unit(1, unit_validators(&short_keys)).unwrap();
        let mut invalid_before_unknown = short
            .assemble(msg, &sign_all(&short_keys, msg, &[0, 1, 2]))
            .unwrap();
        invalid_before_unknown.signatures[0][0] ^= 0x80;
        invalid_before_unknown.signer_bitmap |= 1 << 8;
        invalid_before_unknown
            .signatures
            .try_push(short_keys[0].sign(msg.as_bytes()))
            .unwrap();
        for backend in [
            simd::Backend::Scalar,
            simd::Backend::Avx2,
            simd::Backend::Avx512,
            simd::Backend::Neon,
        ] {
            assert_eq!(
                short.verify_detailed_with_backend(
                    &invalid_before_unknown,
                    ThresholdKind::Advance,
                    backend,
                ),
                Err(MinimmitCertificateError::InvalidSignature { index: 0 }),
                "an earlier invalid signature must win over a later unknown signer"
            );
        }
    }

    #[test]
    fn weights_wider_than_u32_keep_the_full_width_scalar_fallback() {
        let keys = keypairs(6);
        let weights = [u64::from(u32::MAX) + 1, 1, 1, 1, 1, 1];
        let committee = MinimmitCommittee::new(2, validators(&keys, &weights), 1).unwrap();
        let msg = Hash::from_bytes([0xE5; 32]);
        let cert = committee
            .assemble(msg, &sign_all(&keys, msg, &[0, 1, 2, 3, 4]))
            .unwrap();
        for backend in [
            simd::Backend::Scalar,
            simd::Backend::Avx2,
            simd::Backend::Avx512,
            simd::Backend::Neon,
        ] {
            assert_eq!(
                committee.verify_detailed_with_backend(&cert, ThresholdKind::Finalize, backend,),
                Ok(())
            );
        }
    }

    #[test]
    fn weighted_committee_computes_m_and_l_over_weights() {
        // W = 101, B = 20 (exactly 5B + 1): M = 2B+1 = 41, L = W−B = 81.
        let keys = keypairs(6);
        let members = validators(&keys, &[30, 25, 20, 15, 6, 5]);
        let committee = MinimmitCommittee::new(3, members, 20).unwrap();
        assert_eq!(committee.total_weight(), 101);
        assert_eq!(committee.byzantine_weight(), 20);
        assert_eq!(committee.advance_threshold(), 41);
        assert_eq!(committee.finalize_threshold(), 81);
        assert_eq!(committee.weight(0), Some(30));
        assert_eq!(committee.weight(5), Some(5));

        let msg = Hash::from_bytes([0x11u8; 32]);
        // Indices {0, 1} carry weight 55: >= M, < L.
        let m_cert = committee
            .assemble(msg, &sign_all(&keys, msg, &[0, 1]))
            .unwrap();
        assert_eq!(committee.verify(&m_cert, ThresholdKind::Advance), Ok(()));
        assert_eq!(
            committee.verify(&m_cert, ThresholdKind::Finalize),
            Err(QuorumError::BelowThreshold {
                signed: 55,
                threshold: 81,
            })
        );
        // Indices {0, 1, 2, 3} carry weight 90 >= L.
        let l_cert = committee
            .assemble(msg, &sign_all(&keys, msg, &[0, 1, 2, 3]))
            .unwrap();
        assert_eq!(committee.verify(&l_cert, ThresholdKind::Advance), Ok(()));
        assert_eq!(committee.verify(&l_cert, ThresholdKind::Finalize), Ok(()));

        // B = 21 exceeds what W = 101 tolerates.
        let members = validators(&keys, &[30, 25, 20, 15, 6, 5]);
        assert_eq!(
            MinimmitCommittee::new(3, members, 21).unwrap_err(),
            VoteError::InsufficientSizing {
                total_weight: 101,
                byzantine_weight: 21,
            }
        );
    }

    #[test]
    fn unit_convenience_derives_capacity_f() {
        // n = 6 derives f = 1 (M = 3, L = 5).
        let committee = MinimmitCommittee::new_unit(0, unit_validators(&keypairs(6))).unwrap();
        assert_eq!(committee.byzantine_weight(), 1);
        assert_eq!(committee.advance_threshold(), 3);
        assert_eq!(committee.finalize_threshold(), 5);

        // n = 16 (the cap) derives f = 3 (M = 7, L = 13).
        let committee = MinimmitCommittee::new_unit(9, unit_validators(&keypairs(16))).unwrap();
        assert_eq!(committee.byzantine_weight(), 3);
        assert_eq!(committee.advance_threshold(), 7);
        assert_eq!(committee.finalize_threshold(), 13);

        // n = 5 derives f = 0: demo-only, no Byzantine tolerance (M=1, L=n).
        let committee = MinimmitCommittee::new_unit(0, unit_validators(&keypairs(5))).unwrap();
        assert_eq!(committee.byzantine_weight(), 0);
        assert_eq!(committee.advance_threshold(), 1);
        assert_eq!(committee.finalize_threshold(), 5);

        // Non-unit weights must size explicitly through `new`.
        let keys = keypairs(6);
        let weighted = validators(&keys, &[2, 1, 1, 1, 1, 1]);
        assert_eq!(
            MinimmitCommittee::new_unit(0, weighted).unwrap_err(),
            VoteError::InvalidValidatorSet
        );
    }

    #[test]
    fn leader_is_epoch_mixed_round_robin() {
        let keys = keypairs(6);
        // Epoch 7 over n = 6: leader(v) = (7 + v) mod 6, NOT bare v mod 6.
        let committee = MinimmitCommittee::new(7, unit_validators(&keys), 1).unwrap();
        assert_eq!(committee.leader(0), 1);
        assert_eq!(committee.leader(4), 5);
        assert_eq!(committee.leader(5), 0);
        assert_ne!(
            committee.leader(0),
            0,
            "bare v mod n would pick 0 at view 0; epoch-mixing must not"
        );
        // Full rotation: every validator leads exactly once per n views.
        let mut seen: Vec<u16> = (0..6).map(|v| committee.leader(v)).collect();
        seen.sort_unstable();
        assert_eq!(seen, vec![0, 1, 2, 3, 4, 5]);
        // epoch + view wraps without panicking.
        let committee = MinimmitCommittee::new(u64::MAX, unit_validators(&keys), 1).unwrap();
        assert_eq!(committee.leader(1), 0); // u64::MAX + 1 wraps to 0
    }

    #[test]
    fn assemble_dedups_orders_and_rejects_foreign_signers() {
        let keys = keypairs(6);
        let committee = MinimmitCommittee::new(0, unit_validators(&keys), 1).unwrap();
        let msg = Hash::from_bytes([0x42u8; 32]);

        // Scrambled input with a duplicate index: packed ascending, deduped.
        let sig0 = keys[0].sign(msg.as_bytes());
        let sig3 = keys[3].sign(msg.as_bytes());
        let sig5 = keys[5].sign(msg.as_bytes());
        let cert = committee
            .assemble(msg, &[(3, sig3), (0, sig0), (3, sig3), (5, sig5)])
            .unwrap();
        assert_eq!(cert.signer_bitmap, 0b10_1001);
        assert_eq!(cert.signatures.as_slice(), [sig0, sig3, sig5]);
        // Ascending packing is proven end-to-end: misaligned signatures would
        // fail verification against the bitmap-named keys.
        assert_eq!(committee.verify(&cert, ThresholdKind::Advance), Ok(()));

        // Foreign index: outside the 6-member committee.
        assert_eq!(
            committee.assemble(msg, &[(6, sig0)]),
            Err(VoteError::ForeignSigner(6))
        );

        // A signature claiming the wrong index assembles (assembly does not
        // verify) but never survives `verify`.
        let forged = committee
            .assemble(
                msg,
                &[
                    (0, sig3),
                    (1, keys[1].sign(msg.as_bytes())),
                    (2, keys[2].sign(msg.as_bytes())),
                ],
            )
            .unwrap();
        assert_eq!(
            committee.verify(&forged, ThresholdKind::Advance),
            Err(QuorumError::InvalidSignature)
        );
    }
}

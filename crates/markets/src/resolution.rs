//! The resolution framework: an immutable, versioned resolution *policy*
//! (committee keys/threshold, challenge window, rules commitment, round,
//! deployment, and expiry), evidence-bound resolution certificates whose signed
//! digest is bound to that policy, and staked challenge windows with an explicit
//! propose -> challenge -> adjudicate -> finalize progression.
//!
//! # Why the policy is the source of truth
//! Verification inputs are derived *exclusively* from a market's committed
//! [`ResolutionPolicy`] (see [`crate::registry`]). A certificate carries a
//! [`ResolutionPolicy::commitment`] and a round; verification recomputes the
//! expected commitment/round from stored state and rejects anything that does
//! not match, so a caller can never substitute a different committee, rules,
//! deployment, or round to finalize a payout. Rotation is an explicit versioned
//! transition ([`ResolutionPolicy::rotate`]) that strictly advances the round
//! and cannot rewrite a past one.
//!
//! # Separation from the price oracle
//! Nothing here shares a type with the perpetual price-oracle path. The
//! resolution committee is a [`crypto::ValidatorSet`] over a
//! **resolution-specific hash domain** ([`RESOLUTION_DOMAIN`]); price marks come
//! from [`crate::perpetual`] and never touch these types. The compile-time
//! separation is asserted by a test.

use crypto::{hash_domain, QuorumCertificate, ValidatorSet};
use serde::{Deserialize, Serialize};
use types::{Amount, Hash, MarketId, PayoutVector, SequenceNumber};

use crate::error::ResolutionError;

/// Hash domain for resolution messages. Deliberately distinct from the price
/// oracle's `crypto::DOMAIN_ORACLE`.
pub const RESOLUTION_DOMAIN: &[u8] = b"DEXOS/RESOLUTION/v1";

/// Hash domain for the canonical [`ResolutionPolicy`] commitment. Distinct from
/// [`RESOLUTION_DOMAIN`] so a policy digest can never be confused with a signed
/// resolution message.
pub const RESOLUTION_POLICY_DOMAIN: &[u8] = b"DEXOS/RESOLUTION/POLICY/v1";

/// Upper bound on the number of pending challenges a single resolution round may
/// hold. Bounds allocation on adversarial challenge floods.
pub const MAX_CHALLENGES: usize = 64;

/// The transition a certificate authorizes. Bound into the signed digest so a
/// proposal certificate can never be replayed to adjudicate a dispute (or vice
/// versa): the two phases produce different messages under the same committee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionPhase {
    /// Opens the challenge window with a proposed outcome.
    Propose,
    /// Deterministically settles a challenged round with a final outcome.
    Adjudicate,
}

impl ResolutionPhase {
    /// The single-byte canonical tag folded into the signed digest.
    #[must_use]
    const fn tag(self) -> u8 {
        match self {
            ResolutionPhase::Propose => 0,
            ResolutionPhase::Adjudicate => 1,
        }
    }
}

/// The canonical message a resolution committee signs.
///
/// The digest binds the market, the committed policy ([`ResolutionPolicy::commitment`]),
/// the resolution round, the challenge deadline, the phase, the certified payout
/// vector, and the evidence hash. Because every one of these is folded in, a
/// valid quorum over one (policy, round, deadline, outcome, phase) tuple cannot
/// be replayed to certify a different one.
#[must_use]
pub fn resolution_message(
    market_id: MarketId,
    policy_commitment: Hash,
    round: u64,
    challenge_deadline: SequenceNumber,
    phase: ResolutionPhase,
    payout: &PayoutVector,
    evidence_hash: Hash,
) -> Hash {
    let mut buf = Vec::with_capacity(4 + 32 + 8 + 8 + 1 + payout.len() * 16 + 32);
    buf.extend_from_slice(&market_id.get().to_le_bytes());
    buf.extend_from_slice(policy_commitment.as_bytes());
    buf.extend_from_slice(&round.to_le_bytes());
    buf.extend_from_slice(&challenge_deadline.get().to_le_bytes());
    buf.push(phase.tag());
    for v in payout.values() {
        buf.extend_from_slice(&v.raw().to_le_bytes());
    }
    buf.extend_from_slice(evidence_hash.as_bytes());
    hash_domain(RESOLUTION_DOMAIN, &buf)
}

/// An immutable, versioned resolution policy for a market.
///
/// Bound to a market by [`crate::MarketRegistry::commit_resolution_policy`] and
/// only ever replaced by an explicit [`ResolutionPolicy::rotate`], which strictly
/// advances the version and round. The [`ResolutionPolicy::commitment`] over all
/// fields is what a [`ResolutionCertificate`] must name, so a certificate is
/// cryptographically bound to the exact committee, rules, deployment, round, and
/// challenge window the market committed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionPolicy {
    version: u32,
    round: u64,
    deployment: u64,
    committee: ValidatorSet,
    challenge_window: u64,
    rules_hash: Hash,
    expiry: SequenceNumber,
}

impl ResolutionPolicy {
    /// Construct a policy.
    ///
    /// * `version` — policy generation, advanced by [`Self::rotate`].
    /// * `round` — the resolution round this policy governs.
    /// * `deployment` — the deployment/network the policy is valid on.
    /// * `committee` — the threshold committee whose quorum certifies outcomes.
    /// * `challenge_window` — the minimum challenge window, in sequence ticks.
    /// * `rules_hash` — commitment to the off-chain resolution rules text.
    /// * `expiry` — the first sequence at which the policy may no longer propose.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: u32,
        round: u64,
        deployment: u64,
        committee: ValidatorSet,
        challenge_window: u64,
        rules_hash: Hash,
        expiry: SequenceNumber,
    ) -> Self {
        Self {
            version,
            round,
            deployment,
            committee,
            challenge_window,
            rules_hash,
            expiry,
        }
    }

    /// The policy generation.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The resolution round this policy governs.
    #[must_use]
    pub fn round(&self) -> u64 {
        self.round
    }

    /// The deployment/network the policy is valid on.
    #[must_use]
    pub fn deployment(&self) -> u64 {
        self.deployment
    }

    /// The resolution committee validator set.
    #[must_use]
    pub fn committee(&self) -> &ValidatorSet {
        &self.committee
    }

    /// The minimum challenge-window length in sequence ticks.
    #[must_use]
    pub fn challenge_window(&self) -> u64 {
        self.challenge_window
    }

    /// The immutable rules-text commitment.
    #[must_use]
    pub fn rules_hash(&self) -> Hash {
        self.rules_hash
    }

    /// The first sequence at which the policy may no longer propose.
    #[must_use]
    pub fn expiry(&self) -> SequenceNumber {
        self.expiry
    }

    /// A canonical, domain-separated commitment over every policy field.
    ///
    /// Two policies commit to the same hash iff they agree on version, round,
    /// deployment, committee (by [`ValidatorSet::commitment`]), challenge window,
    /// rules hash, and expiry; any change moves the commitment.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        let committee = self.committee.commitment();
        let mut buf = Vec::with_capacity(4 + 8 + 8 + 32 + 8 + 32 + 8);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.round.to_le_bytes());
        buf.extend_from_slice(&self.deployment.to_le_bytes());
        buf.extend_from_slice(committee.as_bytes());
        buf.extend_from_slice(&self.challenge_window.to_le_bytes());
        buf.extend_from_slice(self.rules_hash.as_bytes());
        buf.extend_from_slice(&self.expiry.get().to_le_bytes());
        hash_domain(RESOLUTION_POLICY_DOMAIN, &buf)
    }

    /// Rotate to a successor policy: the version and round both strictly advance
    /// (a rotation can never re-open or rewrite a past round), the deployment is
    /// preserved, and the committee, challenge window, rules commitment, and
    /// expiry are replaced.
    #[must_use]
    pub fn rotate(
        &self,
        committee: ValidatorSet,
        challenge_window: u64,
        rules_hash: Hash,
        expiry: SequenceNumber,
    ) -> Self {
        Self {
            version: self.version.saturating_add(1),
            round: self.round.saturating_add(1),
            deployment: self.deployment,
            committee,
            challenge_window,
            rules_hash,
            expiry,
        }
    }
}

/// A threshold-committee resolution certificate binding a market to a payout
/// vector, the committed policy, a round, a challenge deadline, and a phase, with
/// an evidence hash and a quorum of resolver signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionCertificate {
    /// The market being resolved.
    pub market_id: MarketId,
    /// The committed policy commitment this certificate is bound to.
    pub policy_commitment: Hash,
    /// The resolution round.
    pub round: u64,
    /// The challenge deadline the committee attests to; finalization is
    /// impossible before it.
    pub challenge_deadline: SequenceNumber,
    /// Which transition the certificate authorizes.
    pub phase: ResolutionPhase,
    /// The certified payout vector.
    pub payout: PayoutVector,
    /// Hash of the supporting evidence.
    pub evidence_hash: Hash,
    /// The committee quorum certificate over [`resolution_message`].
    pub quorum: QuorumCertificate,
}

impl ResolutionCertificate {
    /// Assemble a certificate. Callers supply a quorum produced over
    /// [`resolution_message`] for these fields.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: MarketId,
        policy_commitment: Hash,
        round: u64,
        challenge_deadline: SequenceNumber,
        phase: ResolutionPhase,
        payout: PayoutVector,
        evidence_hash: Hash,
        quorum: QuorumCertificate,
    ) -> Self {
        Self {
            market_id,
            policy_commitment,
            round,
            challenge_deadline,
            phase,
            payout,
            evidence_hash,
            quorum,
        }
    }

    /// Verify this certificate against the market's committed `policy` for
    /// `expected_market` with `expected_outcomes` outcomes.
    ///
    /// The verification inputs come exclusively from `policy`: a caller cannot
    /// supply a different committee or rule. Checks, in order: market id match,
    /// the certificate names this exact policy commitment, the round matches the
    /// policy round, payout length match, payout value conservation, the quorum's
    /// message binds this policy/round/deadline/phase/outcome/evidence, and the
    /// committee quorum verifies to threshold. Every failure is a typed
    /// [`ResolutionError`]; never panics.
    ///
    /// # Errors
    /// [`ResolutionError::MarketIdMismatch`], [`ResolutionError::PolicyMismatch`],
    /// [`ResolutionError::RoundMismatch`],
    /// [`ResolutionError::PayoutLengthMismatch`],
    /// [`ResolutionError::Vector`] (non-conserving payout),
    /// [`ResolutionError::ForgedMessage`], or [`ResolutionError::Quorum`].
    pub fn verify(
        &self,
        policy: &ResolutionPolicy,
        expected_market: MarketId,
        expected_outcomes: usize,
    ) -> Result<(), ResolutionError> {
        if self.market_id != expected_market {
            return Err(ResolutionError::MarketIdMismatch);
        }
        // Bind to the committed policy: any noncommitted committee, rules,
        // deployment, challenge window, or version changes the commitment.
        if self.policy_commitment != policy.commitment() {
            return Err(ResolutionError::PolicyMismatch);
        }
        if self.round != policy.round {
            return Err(ResolutionError::RoundMismatch);
        }
        if self.payout.len() != expected_outcomes {
            return Err(ResolutionError::PayoutLengthMismatch);
        }
        // Revalidate at the certificate boundary: a decoded certificate bypasses
        // the payout constructors, so re-assert non-negative, unit-sum values
        // before a quorum can bind them into settlement.
        self.payout.validate_conserving()?;
        let expected = resolution_message(
            self.market_id,
            self.policy_commitment,
            self.round,
            self.challenge_deadline,
            self.phase,
            &self.payout,
            self.evidence_hash,
        );
        if self.quorum.message != expected {
            return Err(ResolutionError::ForgedMessage);
        }
        policy.committee.verify(&self.quorum)?;
        Ok(())
    }
}

/// A staked challenge window opened when a market enters `PendingResolution`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeWindow {
    /// The sequence at which the window opened.
    pub opened_at: SequenceNumber,
    /// The window length in sequence ticks.
    pub duration: u64,
}

impl ChallengeWindow {
    /// Open a window at `opened_at` for `duration` ticks.
    #[must_use]
    pub fn open(opened_at: SequenceNumber, duration: u64) -> Self {
        Self {
            opened_at,
            duration,
        }
    }

    /// The first sequence at which the window is closed (saturating).
    #[must_use]
    pub fn deadline(&self) -> u64 {
        self.opened_at.get().saturating_add(self.duration)
    }

    /// Whether the window is still open at `now` (challenges accepted).
    #[must_use]
    pub fn is_open(&self, now: SequenceNumber) -> bool {
        now.get() < self.deadline()
    }

    /// Whether the window has expired at `now` (eligible for auto-finalization).
    #[must_use]
    pub fn is_expired(&self, now: SequenceNumber) -> bool {
        !self.is_open(now)
    }
}

/// A staked challenge against a pending resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    /// The account posting the challenge.
    pub challenger: types::AccountId,
    /// The bond staked, forfeited on a failed challenge.
    pub bond: Amount,
    /// Hash of the challenger's counter-evidence.
    pub evidence_hash: Hash,
    /// The sequence at which the challenge was submitted.
    pub submitted_at: SequenceNumber,
}

/// A bounded queue of pending challenges. Rejects growth past `cap` with a
/// typed error rather than allocating unboundedly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeBook {
    pending: Vec<Challenge>,
    cap: usize,
}

impl ChallengeBook {
    /// A new challenge book holding at most `cap` challenges.
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            pending: Vec::new(),
            cap,
        }
    }

    /// Number of pending challenges.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether there are no pending challenges.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// The pending challenges.
    #[must_use]
    pub fn pending(&self) -> &[Challenge] {
        &self.pending
    }

    /// Push a challenge onto the book. The caller is responsible for checking
    /// the window is still open (via [`ChallengeWindow::is_open`]) first.
    ///
    /// # Errors
    /// [`ResolutionError::ChallengeQueueFull`] when the book is at capacity.
    pub fn submit(&mut self, challenge: Challenge) -> Result<(), ResolutionError> {
        if self.pending.len() >= self.cap {
            return Err(ResolutionError::ChallengeQueueFull);
        }
        self.pending.push(challenge);
        Ok(())
    }

    /// Total bonds currently staked in the book (saturating).
    #[must_use]
    pub fn total_bonds(&self) -> Amount {
        self.pending
            .iter()
            .fold(Amount::ZERO, |acc, c| acc.saturating_add(c.bond))
    }

    /// Clear the book (on finalization), returning the drained challenges.
    pub fn drain(&mut self) -> Vec<Challenge> {
        std::mem::take(&mut self.pending)
    }
}

/// External resolution source. Implementors bridge an off-chain resolver (a
/// UMA-style optimistic oracle, a sports-data feed, etc.) into a payout vector.
/// Kept a trait so the registry depends only on the abstraction.
pub trait ResolutionAdapter {
    /// Fetch a proposed outcome for `market_id`, if the adapter has one.
    fn fetch_outcome(&self, market_id: MarketId) -> Option<PayoutVector>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::ThresholdSigners;

    fn committee(n: usize, k: u64) -> ThresholdSigners {
        let seeds: Vec<[u8; 32]> = (0..n).map(|i| [u8::try_from(i).unwrap(); 32]).collect();
        ThresholdSigners::from_seeds(&seeds, k)
    }

    fn payout() -> PayoutVector {
        PayoutVector::new(vec![Amount::ONE, Amount::ZERO]).unwrap()
    }

    fn policy(ts: &ThresholdSigners) -> ResolutionPolicy {
        ResolutionPolicy::new(
            1,
            0,
            42,
            ts.validator_set(),
            100,
            Hash::ZERO,
            SequenceNumber::new(1_000_000),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn make_cert(
        ts: &ThresholdSigners,
        market: MarketId,
        policy_commitment: Hash,
        round: u64,
        deadline: SequenceNumber,
        phase: ResolutionPhase,
        pv: PayoutVector,
        evidence: Hash,
        signers: Vec<usize>,
    ) -> ResolutionCertificate {
        let msg = resolution_message(
            market,
            policy_commitment,
            round,
            deadline,
            phase,
            &pv,
            evidence,
        );
        let qc = ts.sign(msg, signers);
        ResolutionCertificate::new(
            market,
            policy_commitment,
            round,
            deadline,
            phase,
            pv,
            evidence,
            qc,
        )
    }

    #[test]
    fn valid_k_of_n_certificate_verifies() {
        let ts = committee(4, 3);
        let p = policy(&ts);
        let market = MarketId::new(7);
        let ev = Hash::from_bytes([9u8; 32]);
        let cert = make_cert(
            &ts,
            market,
            p.commitment(),
            0,
            SequenceNumber::new(150),
            ResolutionPhase::Propose,
            payout(),
            ev,
            vec![0, 1, 2],
        );
        assert!(cert.verify(&p, market, 2).is_ok());
    }

    #[test]
    fn rejects_shortfall_wrong_market_and_bad_length() {
        let ts = committee(4, 3);
        let p = policy(&ts);
        let market = MarketId::new(7);
        let ev = Hash::from_bytes([9u8; 32]);
        let d = SequenceNumber::new(150);

        // Quorum shortfall (only 2 of 3).
        let short = make_cert(
            &ts,
            market,
            p.commitment(),
            0,
            d,
            ResolutionPhase::Propose,
            payout(),
            ev,
            vec![0, 1],
        );
        assert!(matches!(
            short.verify(&p, market, 2),
            Err(ResolutionError::Quorum(_))
        ));

        // Wrong market id.
        let cert = make_cert(
            &ts,
            market,
            p.commitment(),
            0,
            d,
            ResolutionPhase::Propose,
            payout(),
            ev,
            vec![0, 1, 2],
        );
        assert_eq!(
            cert.verify(&p, MarketId::new(8), 2),
            Err(ResolutionError::MarketIdMismatch)
        );

        // Mismatched payout length.
        assert_eq!(
            cert.verify(&p, market, 3),
            Err(ResolutionError::PayoutLengthMismatch)
        );
    }

    #[test]
    fn rejects_noncommitted_policy_round_and_committee() {
        let ts = committee(4, 3);
        let p = policy(&ts);
        let market = MarketId::new(7);
        let ev = Hash::from_bytes([9u8; 32]);
        let d = SequenceNumber::new(150);

        // A certificate whose committee genuinely signed, but under a DIFFERENT
        // policy commitment (e.g. a different deployment) is rejected: the market
        // only trusts its stored policy.
        let other = ResolutionPolicy::new(
            1,
            0,
            99, // different deployment
            ts.validator_set(),
            100,
            Hash::ZERO,
            SequenceNumber::new(1_000_000),
        );
        let wrong_policy = make_cert(
            &ts,
            market,
            other.commitment(),
            0,
            d,
            ResolutionPhase::Propose,
            payout(),
            ev,
            vec![0, 1, 2],
        );
        assert_eq!(
            wrong_policy.verify(&p, market, 2),
            Err(ResolutionError::PolicyMismatch)
        );

        // A certificate for a round the policy does not govern is rejected.
        let wrong_round = make_cert(
            &ts,
            market,
            p.commitment(),
            1,
            d,
            ResolutionPhase::Propose,
            payout(),
            ev,
            vec![0, 1, 2],
        );
        assert_eq!(
            wrong_round.verify(&p, market, 2),
            Err(ResolutionError::RoundMismatch)
        );

        // A certificate naming the correct policy commitment but signed by a
        // DIFFERENT committee fails the committee quorum check: verification uses
        // the stored committee, never a caller-supplied one.
        let other_committee =
            ThresholdSigners::from_seeds(&[[100u8; 32], [101u8; 32], [102u8; 32], [103u8; 32]], 3);
        let msg = resolution_message(
            market,
            p.commitment(),
            0,
            d,
            ResolutionPhase::Propose,
            &payout(),
            ev,
        );
        let qc = other_committee.sign(msg, vec![0, 1, 2]);
        let impostor = ResolutionCertificate::new(
            market,
            p.commitment(),
            0,
            d,
            ResolutionPhase::Propose,
            payout(),
            ev,
            qc,
        );
        assert!(matches!(
            impostor.verify(&p, market, 2),
            Err(ResolutionError::Quorum(_))
        ));
    }

    #[test]
    fn rejects_forged_message_tampered_outcome_and_wrong_phase() {
        let ts = committee(4, 3);
        let p = policy(&ts);
        let market = MarketId::new(7);
        let ev = Hash::from_bytes([9u8; 32]);
        let d = SequenceNumber::new(150);

        // Sign one outcome, then swap the payout: message no longer binds.
        let mut cert = make_cert(
            &ts,
            market,
            p.commitment(),
            0,
            d,
            ResolutionPhase::Propose,
            payout(),
            ev,
            vec![0, 1, 2],
        );
        cert.payout = PayoutVector::new(vec![Amount::ZERO, Amount::ONE]).unwrap();
        assert_eq!(
            cert.verify(&p, market, 2),
            Err(ResolutionError::ForgedMessage)
        );

        // A proposal certificate cannot be replayed as an adjudication: swapping
        // the declared phase breaks the digest binding.
        let mut phase_swap = make_cert(
            &ts,
            market,
            p.commitment(),
            0,
            d,
            ResolutionPhase::Propose,
            payout(),
            ev,
            vec![0, 1, 2],
        );
        phase_swap.phase = ResolutionPhase::Adjudicate;
        assert_eq!(
            phase_swap.verify(&p, market, 2),
            Err(ResolutionError::ForgedMessage)
        );
    }

    #[test]
    fn rejects_non_conserving_certified_payout() {
        let ts = committee(4, 3);
        let p = policy(&ts);
        let market = MarketId::new(7);
        let ev = Hash::from_bytes([9u8; 32]);
        let d = SequenceNumber::new(150);

        // Over-allocated payout (sums to 2.0) is rejected before the quorum check,
        // even though the quorum genuinely signs this message.
        let over = PayoutVector::new(vec![Amount::ONE, Amount::ONE]).unwrap();
        let cert = make_cert(
            &ts,
            market,
            p.commitment(),
            0,
            d,
            ResolutionPhase::Propose,
            over,
            ev,
            vec![0, 1, 2],
        );
        assert_eq!(
            cert.verify(&p, market, 2),
            Err(ResolutionError::Vector(
                types::PayoutVectorError::OverAllocated
            ))
        );

        // Zero-sum payout likewise rejected.
        let zero = PayoutVector::new(vec![Amount::ZERO, Amount::ZERO]).unwrap();
        let cert_zero = make_cert(
            &ts,
            market,
            p.commitment(),
            0,
            d,
            ResolutionPhase::Propose,
            zero,
            ev,
            vec![0, 1, 2],
        );
        assert_eq!(
            cert_zero.verify(&p, market, 2),
            Err(ResolutionError::Vector(types::PayoutVectorError::ZeroSum))
        );
    }

    #[test]
    fn policy_commitment_binds_every_field_and_rotation_advances() {
        let ts = committee(4, 3);
        let base = policy(&ts);
        let base_commit = base.commitment();

        // Deterministic.
        assert_eq!(base_commit, base.commitment());

        // Each field moves the commitment.
        let mut changed = base.clone();
        changed.deployment = 43;
        assert_ne!(base_commit, changed.commitment());
        let mut changed = base.clone();
        changed.round = 1;
        assert_ne!(base_commit, changed.commitment());
        let mut changed = base.clone();
        changed.challenge_window = 101;
        assert_ne!(base_commit, changed.commitment());
        let mut changed = base.clone();
        changed.rules_hash = Hash::from_bytes([1u8; 32]);
        assert_ne!(base_commit, changed.commitment());
        let mut changed = base.clone();
        changed.expiry = SequenceNumber::new(1_000_001);
        assert_ne!(base_commit, changed.commitment());

        // A different committee moves the commitment.
        let other = ThresholdSigners::from_seeds(&[[9u8; 32], [8u8; 32], [7u8; 32]], 2);
        let mut changed = base.clone();
        changed.committee = other.validator_set();
        assert_ne!(base_commit, changed.commitment());

        // Rotation strictly advances version and round, preserves deployment,
        // and produces a distinct commitment.
        let rotated = base.rotate(
            ts.validator_set(),
            200,
            Hash::from_bytes([5u8; 32]),
            base.expiry(),
        );
        assert_eq!(rotated.version(), base.version() + 1);
        assert_eq!(rotated.round(), base.round() + 1);
        assert_eq!(rotated.deployment(), base.deployment());
        assert_ne!(base_commit, rotated.commitment());
    }

    #[test]
    fn certificate_from_pre_rotation_policy_is_rejected_after_rotation() {
        let ts = committee(4, 3);
        let old = policy(&ts);
        let market = MarketId::new(7);
        let ev = Hash::from_bytes([9u8; 32]);
        let d = SequenceNumber::new(150);
        let cert = make_cert(
            &ts,
            market,
            old.commitment(),
            0,
            d,
            ResolutionPhase::Propose,
            payout(),
            ev,
            vec![0, 1, 2],
        );
        // Valid under the old policy...
        assert!(cert.verify(&old, market, 2).is_ok());
        // ...but rejected once the policy rotates (new commitment AND new round).
        let new = old.rotate(ts.validator_set(), 100, Hash::ZERO, old.expiry());
        assert_eq!(
            cert.verify(&new, market, 2),
            Err(ResolutionError::PolicyMismatch)
        );
    }

    #[test]
    fn verification_invariant_under_signer_subset_permutation() {
        let ts = committee(5, 3);
        let p = policy(&ts);
        let market = MarketId::new(1);
        let ev = Hash::from_bytes([1u8; 32]);
        let d = SequenceNumber::new(150);
        for subset in [vec![0, 1, 2], vec![2, 3, 4], vec![0, 2, 4], vec![1, 3, 4]] {
            let cert = make_cert(
                &ts,
                market,
                p.commitment(),
                0,
                d,
                ResolutionPhase::Propose,
                payout(),
                ev,
                subset,
            );
            // Deterministic across repeated verification.
            assert!(cert.verify(&p, market, 2).is_ok());
            assert!(cert.verify(&p, market, 2).is_ok());
        }
    }

    #[test]
    fn challenge_window_and_bounded_book() {
        let w = ChallengeWindow::open(SequenceNumber::new(100), 50);
        assert_eq!(w.deadline(), 150);
        assert!(w.is_open(SequenceNumber::new(149)));
        assert!(w.is_expired(SequenceNumber::new(150)));

        let mut book = ChallengeBook::new(2);
        let c = Challenge {
            challenger: types::AccountId::new(1),
            bond: Amount::from_raw(1_000_000),
            evidence_hash: Hash::ZERO,
            submitted_at: SequenceNumber::new(101),
        };
        book.submit(c).unwrap();
        book.submit(c).unwrap();
        assert_eq!(
            book.submit(c).unwrap_err(),
            ResolutionError::ChallengeQueueFull
        );
        assert_eq!(book.total_bonds(), Amount::from_raw(2_000_000));
        assert_eq!(book.drain().len(), 2);
        assert!(book.is_empty());
    }

    // Deterministic LCG.
    struct Lcg(u64);
    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
    }

    #[test]
    fn never_panics_decoding_arbitrary_certificate_bytes() {
        let mut r = Lcg(0xDEAD_10CC);
        for _ in 0..20_000 {
            let len = usize::try_from(r.next_u64() % 128).unwrap();
            let bytes: Vec<u8> = (0..len)
                .map(|_| u8::try_from(r.next_u64() % 256).unwrap())
                .collect();
            // Decoding must never panic and, if it decodes, verification is total.
            if let Ok(cert) = postcard::from_bytes::<ResolutionCertificate>(&bytes) {
                let ts = committee(4, 3);
                let p = policy(&ts);
                let _ = cert.verify(&p, MarketId::new(0), cert.payout.len());
            }
            let _ = postcard::from_bytes::<ChallengeBook>(&bytes);
            let _ = postcard::from_bytes::<ResolutionPolicy>(&bytes);
        }
    }

    #[test]
    fn resolution_message_binds_each_input() {
        let m = MarketId::new(3);
        let pv = payout();
        let ev = Hash::from_bytes([5u8; 32]);
        let pc = Hash::from_bytes([6u8; 32]);
        let d = SequenceNumber::new(150);
        let base = resolution_message(m, pc, 0, d, ResolutionPhase::Propose, &pv, ev);
        // Deterministic.
        assert_eq!(
            base,
            resolution_message(m, pc, 0, d, ResolutionPhase::Propose, &pv, ev)
        );
        // Each input changes the digest.
        assert_ne!(
            base,
            resolution_message(
                MarketId::new(4),
                pc,
                0,
                d,
                ResolutionPhase::Propose,
                &pv,
                ev
            )
        );
        assert_ne!(
            base,
            resolution_message(
                m,
                Hash::from_bytes([7u8; 32]),
                0,
                d,
                ResolutionPhase::Propose,
                &pv,
                ev
            )
        );
        assert_ne!(
            base,
            resolution_message(m, pc, 1, d, ResolutionPhase::Propose, &pv, ev)
        );
        assert_ne!(
            base,
            resolution_message(
                m,
                pc,
                0,
                SequenceNumber::new(151),
                ResolutionPhase::Propose,
                &pv,
                ev
            )
        );
        assert_ne!(
            base,
            resolution_message(m, pc, 0, d, ResolutionPhase::Adjudicate, &pv, ev)
        );
        let pv2 = PayoutVector::new(vec![Amount::ZERO, Amount::ONE]).unwrap();
        assert_ne!(
            base,
            resolution_message(m, pc, 0, d, ResolutionPhase::Propose, &pv2, ev)
        );
        assert_ne!(
            base,
            resolution_message(
                m,
                pc,
                0,
                d,
                ResolutionPhase::Propose,
                &pv,
                Hash::from_bytes([1u8; 32])
            )
        );
    }
}

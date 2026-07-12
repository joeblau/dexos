//! The resolution framework: an immutable rule, evidence-bound resolution
//! certificates, a threshold resolution committee, staked challenge windows,
//! and an external-adapter hook.
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

/// The canonical message a resolution committee signs: a binding over the
/// market, the certified payout vector, and the evidence hash.
///
/// Because the outcome and evidence are folded into the signed digest, a valid
/// quorum over one outcome cannot be replayed to certify a different one.
#[must_use]
pub fn resolution_message(market_id: MarketId, payout: &PayoutVector, evidence_hash: Hash) -> Hash {
    let mut buf = Vec::with_capacity(4 + payout.len() * 16 + 32);
    buf.extend_from_slice(&market_id.get().to_le_bytes());
    for v in payout.values() {
        buf.extend_from_slice(&v.raw().to_le_bytes());
    }
    buf.extend_from_slice(evidence_hash.as_bytes());
    hash_domain(RESOLUTION_DOMAIN, &buf)
}

/// An immutable resolution rule for a market: the committee, the challenge
/// window length, and a commitment to the off-chain resolution rules text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionRule {
    committee: ValidatorSet,
    challenge_window: u64,
    rules_hash: Hash,
}

impl ResolutionRule {
    /// Construct an immutable rule.
    #[must_use]
    pub fn new(committee: ValidatorSet, challenge_window: u64, rules_hash: Hash) -> Self {
        Self {
            committee,
            challenge_window,
            rules_hash,
        }
    }

    /// The resolution committee validator set.
    #[must_use]
    pub fn committee(&self) -> &ValidatorSet {
        &self.committee
    }

    /// The challenge-window length in sequence ticks.
    #[must_use]
    pub fn challenge_window(&self) -> u64 {
        self.challenge_window
    }

    /// The immutable rules-text commitment.
    #[must_use]
    pub fn rules_hash(&self) -> Hash {
        self.rules_hash
    }
}

/// A threshold-committee resolution certificate binding a market to a payout
/// vector, with an evidence hash and a quorum of resolver signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionCertificate {
    /// The market being resolved.
    pub market_id: MarketId,
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
    pub fn new(
        market_id: MarketId,
        payout: PayoutVector,
        evidence_hash: Hash,
        quorum: QuorumCertificate,
    ) -> Self {
        Self {
            market_id,
            payout,
            evidence_hash,
            quorum,
        }
    }

    /// Verify this certificate against `rule` for `expected_market` with
    /// `expected_outcomes` outcomes.
    ///
    /// Checks, in order: market id match, payout length match, payout value
    /// conservation, the quorum's message binds this outcome/evidence, and the
    /// committee quorum verifies to threshold. Every failure is a typed
    /// [`ResolutionError`]; never panics.
    ///
    /// # Errors
    /// [`ResolutionError::MarketIdMismatch`],
    /// [`ResolutionError::PayoutLengthMismatch`],
    /// [`ResolutionError::Vector`] (non-conserving payout),
    /// [`ResolutionError::ForgedMessage`], or [`ResolutionError::Quorum`].
    pub fn verify(
        &self,
        rule: &ResolutionRule,
        expected_market: MarketId,
        expected_outcomes: usize,
    ) -> Result<(), ResolutionError> {
        if self.market_id != expected_market {
            return Err(ResolutionError::MarketIdMismatch);
        }
        if self.payout.len() != expected_outcomes {
            return Err(ResolutionError::PayoutLengthMismatch);
        }
        // Revalidate at the certificate boundary: a decoded certificate bypasses
        // the payout constructors, so re-assert non-negative, unit-sum values
        // before a quorum can bind them into settlement.
        self.payout.validate_conserving()?;
        let expected = resolution_message(self.market_id, &self.payout, self.evidence_hash);
        if self.quorum.message != expected {
            return Err(ResolutionError::ForgedMessage);
        }
        rule.committee.verify(&self.quorum)?;
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

    fn make_cert(
        ts: &ThresholdSigners,
        market: MarketId,
        pv: PayoutVector,
        evidence: Hash,
        signers: Vec<usize>,
    ) -> ResolutionCertificate {
        let msg = resolution_message(market, &pv, evidence);
        let qc = ts.sign(msg, signers);
        ResolutionCertificate::new(market, pv, evidence, qc)
    }

    #[test]
    fn valid_k_of_n_certificate_verifies() {
        let ts = committee(4, 3);
        let rule = ResolutionRule::new(ts.validator_set(), 100, Hash::ZERO);
        let market = MarketId::new(7);
        let ev = Hash::from_bytes([9u8; 32]);
        let cert = make_cert(&ts, market, payout(), ev, vec![0, 1, 2]);
        assert!(cert.verify(&rule, market, 2).is_ok());
    }

    #[test]
    fn rejects_shortfall_wrong_market_and_bad_length() {
        let ts = committee(4, 3);
        let rule = ResolutionRule::new(ts.validator_set(), 100, Hash::ZERO);
        let market = MarketId::new(7);
        let ev = Hash::from_bytes([9u8; 32]);

        // Quorum shortfall (only 2 of 3).
        let short = make_cert(&ts, market, payout(), ev, vec![0, 1]);
        assert!(matches!(
            short.verify(&rule, market, 2),
            Err(ResolutionError::Quorum(_))
        ));

        // Wrong market id.
        let cert = make_cert(&ts, market, payout(), ev, vec![0, 1, 2]);
        assert_eq!(
            cert.verify(&rule, MarketId::new(8), 2),
            Err(ResolutionError::MarketIdMismatch)
        );

        // Mismatched payout length.
        assert_eq!(
            cert.verify(&rule, market, 3),
            Err(ResolutionError::PayoutLengthMismatch)
        );
    }

    #[test]
    fn rejects_forged_message_and_tampered_outcome() {
        let ts = committee(4, 3);
        let rule = ResolutionRule::new(ts.validator_set(), 100, Hash::ZERO);
        let market = MarketId::new(7);
        let ev = Hash::from_bytes([9u8; 32]);
        // Sign one outcome, then swap the payout: message no longer binds.
        let mut cert = make_cert(&ts, market, payout(), ev, vec![0, 1, 2]);
        cert.payout = PayoutVector::new(vec![Amount::ZERO, Amount::ONE]).unwrap();
        assert_eq!(
            cert.verify(&rule, market, 2),
            Err(ResolutionError::ForgedMessage)
        );
    }

    #[test]
    fn rejects_non_conserving_certified_payout() {
        let ts = committee(4, 3);
        let rule = ResolutionRule::new(ts.validator_set(), 100, Hash::ZERO);
        let market = MarketId::new(7);
        let ev = Hash::from_bytes([9u8; 32]);

        // Over-allocated payout (sums to 2.0) is rejected before the quorum check,
        // even though the quorum genuinely signs this message.
        let over = PayoutVector::new(vec![Amount::ONE, Amount::ONE]).unwrap();
        let cert = make_cert(&ts, market, over, ev, vec![0, 1, 2]);
        assert_eq!(
            cert.verify(&rule, market, 2),
            Err(ResolutionError::Vector(
                types::PayoutVectorError::OverAllocated
            ))
        );

        // Zero-sum payout likewise rejected.
        let zero = PayoutVector::new(vec![Amount::ZERO, Amount::ZERO]).unwrap();
        let cert_zero = make_cert(&ts, market, zero, ev, vec![0, 1, 2]);
        assert_eq!(
            cert_zero.verify(&rule, market, 2),
            Err(ResolutionError::Vector(types::PayoutVectorError::ZeroSum))
        );
    }

    #[test]
    fn verification_invariant_under_signer_subset_permutation() {
        let ts = committee(5, 3);
        let rule = ResolutionRule::new(ts.validator_set(), 100, Hash::ZERO);
        let market = MarketId::new(1);
        let ev = Hash::from_bytes([1u8; 32]);
        for subset in [vec![0, 1, 2], vec![2, 3, 4], vec![0, 2, 4], vec![1, 3, 4]] {
            let cert = make_cert(&ts, market, payout(), ev, subset);
            // Deterministic across repeated verification.
            assert!(cert.verify(&rule, market, 2).is_ok());
            assert!(cert.verify(&rule, market, 2).is_ok());
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
                let rule = ResolutionRule::new(ts.validator_set(), 10, Hash::ZERO);
                let _ = cert.verify(&rule, MarketId::new(0), cert.payout.len());
            }
            let _ = postcard::from_bytes::<ChallengeBook>(&bytes);
            let _ = postcard::from_bytes::<ResolutionRule>(&bytes);
        }
    }

    #[test]
    fn resolution_message_is_deterministic() {
        let m = MarketId::new(3);
        let pv = payout();
        let ev = Hash::from_bytes([5u8; 32]);
        assert_eq!(
            resolution_message(m, &pv, ev),
            resolution_message(m, &pv, ev)
        );
        // A different outcome yields a different message.
        let pv2 = PayoutVector::new(vec![Amount::ZERO, Amount::ONE]).unwrap();
        assert_ne!(
            resolution_message(m, &pv, ev),
            resolution_message(m, &pv2, ev)
        );
    }
}

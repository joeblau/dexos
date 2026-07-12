//! Decision-rule evaluation, action selection, and signed confirmations.
//!
//! Expected utility for an action is `Σ_o P(o) · utility(o)`, where the outcome
//! "probability" `P(o)` is the time-weighted decision [`Price`] of that outcome's
//! share (scale `1e6`, `1.0 == 1_000_000`) reinterpreted as a [`Ratio`]. The
//! price vector is first validated as a probability vector (see
//! [`validate_probability_vector`]): every entry must lie in `[0, 1]` and the
//! entries must sum to one unit within a per-outcome tolerance. Selection is
//! deterministic: ties break to the lowest action index.
//!
//! A [`DecisionConfirmation`] externally confirms a selected action or a resolved
//! outcome. It is a domain-separated payload (bound to a market, network, round,
//! kind, and index) plus a threshold [`QuorumCertificate`] from the market's
//! committed authority set. Verification recomputes the digest (rejecting tamper)
//! and checks the quorum reaches threshold weight against the committed keys
//! (rejecting unsigned and wrong-authority confirmations).

use crypto::{hash_domain, QuorumCertificate, ThresholdSigners, ValidatorSet, DOMAIN_DECISION};
use types::{Amount, Hash, MarketId, Price, Ratio, SequenceNumber};

use crate::definition::{DecisionRule, UtilityFunction};
use crate::error::DecisionMarketError;
use crate::instrument::ActionId;

/// Per-outcome tolerance (in `Ratio` micro-units) applied to the probability-sum
/// normalization check. Each decision price is an independently truncated
/// fixed-point TWAP that can lose up to one micro-unit, so a genuine unit-sum
/// distribution over `n` outcomes can read as low as `1.0 - n` micro-units. The
/// accepted band is therefore `RATIO_SCALE ± n · PROBABILITY_SUM_TOLERANCE_PER_OUTCOME`.
pub const PROBABILITY_SUM_TOLERANCE_PER_OUTCOME: i64 = 1;

/// The result of evaluating the decision rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionOutcome {
    /// The chosen action.
    pub action: ActionId,
    /// Its time-weighted expected utility.
    pub expected_utility: Amount,
}

/// Validate that `prices` is a bounded, normalized probability vector.
///
/// Documented normalization rule: every entry must lie in `[0, 1]` (raw in
/// `0..=RATIO_SCALE`) and the entries must sum to exactly one unit
/// (`RATIO_SCALE`) within a tolerance of
/// [`PROBABILITY_SUM_TOLERANCE_PER_OUTCOME`] micro-units per outcome. The
/// tolerance absorbs the round-toward-zero truncation dust of independent
/// fixed-point TWAPs. Returns a typed error, never panics.
pub fn validate_probability_vector(prices: &[Price]) -> Result<(), DecisionMarketError> {
    let scale = i128::from(types::RATIO_SCALE);
    let mut sum: i128 = 0;
    for price in prices {
        let raw = i128::from(price.raw());
        if !(0..=scale).contains(&raw) {
            return Err(DecisionMarketError::ProbabilityOutOfRange);
        }
        sum = sum
            .checked_add(raw)
            .ok_or(DecisionMarketError::Truncation)?;
    }
    let n = i128::try_from(prices.len()).map_err(|_| DecisionMarketError::Truncation)?;
    let tolerance = n
        .checked_mul(i128::from(PROBABILITY_SUM_TOLERANCE_PER_OUTCOME))
        .ok_or(DecisionMarketError::Truncation)?;
    if (sum - scale).abs() > tolerance {
        return Err(DecisionMarketError::UnnormalizedProbabilities);
    }
    Ok(())
}

/// Compute the time-weighted expected utility for a single action given its
/// per-outcome decision prices. `prices.len()` must equal `utils.len()`, and the
/// prices must form a valid probability vector (see
/// [`validate_probability_vector`]).
pub fn expected_utility(
    prices: &[Price],
    utils: &UtilityFunction,
) -> Result<Amount, DecisionMarketError> {
    if prices.len() != utils.len() {
        return Err(DecisionMarketError::UtilityLengthMismatch {
            expected: utils.len(),
            got: prices.len(),
        });
    }
    validate_probability_vector(prices)?;
    let mut sum = Amount::ZERO;
    for (price, utility) in prices.iter().zip(utils.values().iter()) {
        // Price and Ratio share the 1e6 scale; reinterpret the price as a
        // probability weight and multiply the utility (rounds toward zero).
        let weight = Ratio::from_raw(price.raw());
        let term = utility.mul_ratio(weight)?;
        sum = sum.checked_add(term)?;
    }
    Ok(sum)
}

/// Select the winning action from every action's per-outcome decision prices.
///
/// `per_action_prices[a]` is action `a`'s decision-price vector. Every vector
/// must be a valid probability vector. Selection is deterministic and ties break
/// to the lowest action index.
pub fn select_action(
    rule: DecisionRule,
    per_action_prices: &[Vec<Price>],
    utils: &UtilityFunction,
) -> Result<SelectionOutcome, DecisionMarketError> {
    if per_action_prices.is_empty() {
        return Err(DecisionMarketError::NoActions);
    }
    let mut best: Option<SelectionOutcome> = None;
    for (idx, prices) in per_action_prices.iter().enumerate() {
        let eu = expected_utility(prices, utils)?;
        let action = ActionId::from_index(idx)?;
        let candidate = SelectionOutcome {
            action,
            expected_utility: eu,
        };
        best = Some(match best {
            None => candidate,
            Some(current) => {
                let take = match rule {
                    DecisionRule::MaximizeExpectedUtility => eu > current.expected_utility,
                    DecisionRule::MinimizeExpectedUtility => eu < current.expected_utility,
                };
                // Strict comparison keeps the earlier (lower-index) action on ties.
                if take {
                    candidate
                } else {
                    current
                }
            }
        });
    }
    best.ok_or(DecisionMarketError::NoActions)
}

/// What a [`DecisionConfirmation`] authorizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationKind {
    /// Confirms the selected action (`index` is an action index).
    Action,
    /// Confirms the resolved outcome (`index` is an outcome index).
    Outcome,
}

impl ConfirmationKind {
    /// Stable single-byte tag bound into the signed digest.
    #[inline]
    const fn tag(self) -> u8 {
        match self {
            ConfirmationKind::Action => 0,
            ConfirmationKind::Outcome => 1,
        }
    }
}

/// The signed payload of a decision confirmation.
///
/// The digest bound by the threshold signature commits to the market, network,
/// round, kind, and index, so a confirmation cannot be replayed against another
/// market, network, round, or transition kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmationPayload {
    /// The market this confirmation is bound to.
    pub market_id: MarketId,
    /// The network this confirmation is bound to.
    pub network_id: u64,
    /// A strictly-monotonic round guarding against replay.
    pub round: SequenceNumber,
    /// Whether this confirms an action or an outcome.
    pub kind: ConfirmationKind,
    /// The action index (for [`ConfirmationKind::Action`]) or outcome index (for
    /// [`ConfirmationKind::Outcome`]).
    pub index: u16,
}

impl ConfirmationPayload {
    /// Build an action confirmation payload.
    #[inline]
    pub const fn action(
        market_id: MarketId,
        network_id: u64,
        round: SequenceNumber,
        action: u16,
    ) -> Self {
        Self {
            market_id,
            network_id,
            round,
            kind: ConfirmationKind::Action,
            index: action,
        }
    }

    /// Build an outcome confirmation payload.
    #[inline]
    pub const fn outcome(
        market_id: MarketId,
        network_id: u64,
        round: SequenceNumber,
        outcome: u16,
    ) -> Self {
        Self {
            market_id,
            network_id,
            round,
            kind: ConfirmationKind::Outcome,
            index: outcome,
        }
    }

    /// Domain-separated 32-byte digest bound by the threshold signature. Fixed
    /// little-endian layout; deterministic across machines.
    pub fn digest(&self) -> Hash {
        let mut buf = Vec::with_capacity(4 + 8 + 8 + 1 + 2);
        buf.extend_from_slice(&self.market_id.get().to_le_bytes());
        buf.extend_from_slice(&self.network_id.to_le_bytes());
        buf.extend_from_slice(&self.round.get().to_le_bytes());
        buf.push(self.kind.tag());
        buf.extend_from_slice(&self.index.to_le_bytes());
        hash_domain(DOMAIN_DECISION, &buf)
    }
}

/// A threshold-signed, domain-bound confirmation of a selected action or a
/// resolved outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionConfirmation {
    /// The signed payload.
    pub payload: ConfirmationPayload,
    /// Quorum certificate over `payload.digest()`.
    pub quorum: QuorumCertificate,
}

impl DecisionConfirmation {
    /// Form a confirmation by threshold-signing `payload` with `signers` at the
    /// given signer indices. The quorum message is bound to the payload digest.
    pub fn form(
        payload: ConfirmationPayload,
        signers: &ThresholdSigners,
        indices: Vec<usize>,
    ) -> DecisionConfirmation {
        let quorum = signers.sign(payload.digest(), indices);
        DecisionConfirmation { payload, quorum }
    }

    /// Verify the certificate against `set`: the quorum message must equal the
    /// recomputed payload digest (rejecting tampered payloads) and the quorum
    /// must reach threshold weight with valid member signatures (rejecting
    /// unsigned, sub-threshold, and wrong-authority confirmations). Never panics.
    pub fn verify(&self, set: &ValidatorSet) -> Result<(), DecisionMarketError> {
        if self.quorum.message != self.payload.digest() {
            return Err(DecisionMarketError::ConfirmationDigestMismatch);
        }
        set.verify(&self.quorum)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn util(vals: &[i128]) -> UtilityFunction {
        UtilityFunction::new(vals.iter().map(|v| Amount::from_raw(*v)).collect()).unwrap()
    }

    fn signers(n: usize, k: u64) -> ThresholdSigners {
        let seeds: Vec<[u8; 32]> = (0..n).map(|i| [u8::try_from(i).unwrap(); 32]).collect();
        ThresholdSigners::from_seeds(&seeds, k)
    }

    #[test]
    fn expected_utility_is_probability_weighted_sum() {
        // P(up)=0.6, P(down)=0.4; utility up=10.0, down=0.0 -> 6.0
        let prices = [Price::from_raw(600_000), Price::from_raw(400_000)];
        let eu = expected_utility(&prices, &util(&[10_000_000, 0])).unwrap();
        assert_eq!(eu, Amount::from_raw(6_000_000));
    }

    #[test]
    fn probability_vector_bounds_and_normalization_enforced() {
        // Out-of-range entry (> 1.0).
        assert_eq!(
            validate_probability_vector(&[Price::from_raw(1_500_000), Price::from_raw(0)]),
            Err(DecisionMarketError::ProbabilityOutOfRange)
        );
        // Negative entry.
        assert_eq!(
            validate_probability_vector(&[Price::from_raw(-1), Price::from_raw(1_000_001)]),
            Err(DecisionMarketError::ProbabilityOutOfRange)
        );
        // Unnormalized (sum 1.2).
        assert_eq!(
            validate_probability_vector(&[Price::from_raw(600_000), Price::from_raw(600_000)]),
            Err(DecisionMarketError::UnnormalizedProbabilities)
        );
        // Unnormalized (sum 0.2).
        assert_eq!(
            validate_probability_vector(&[Price::from_raw(100_000), Price::from_raw(100_000)]),
            Err(DecisionMarketError::UnnormalizedProbabilities)
        );
        // Exact unit sum accepted.
        assert!(
            validate_probability_vector(&[Price::from_raw(700_000), Price::from_raw(300_000)])
                .is_ok()
        );
        // Within per-outcome truncation tolerance (two outcomes -> ±2 micro).
        assert!(
            validate_probability_vector(&[Price::from_raw(500_000), Price::from_raw(499_999)])
                .is_ok()
        );
        // Just outside tolerance rejected.
        assert_eq!(
            validate_probability_vector(&[Price::from_raw(500_000), Price::from_raw(499_997)]),
            Err(DecisionMarketError::UnnormalizedProbabilities)
        );
    }

    #[test]
    fn expected_utility_rejects_unnormalized_prices() {
        assert_eq!(
            expected_utility(
                &[Price::from_raw(100_000), Price::from_raw(100_000)],
                &util(&[10_000_000, 0])
            ),
            Err(DecisionMarketError::UnnormalizedProbabilities)
        );
    }

    #[test]
    fn selection_picks_max_expected_utility() {
        // Action 0: P(up)=0.2 -> EU 2.0 ; Action 1: P(up)=0.8 -> EU 8.0
        let prices = vec![
            vec![Price::from_raw(200_000), Price::from_raw(800_000)],
            vec![Price::from_raw(800_000), Price::from_raw(200_000)],
        ];
        let u = util(&[10_000_000, 0]);
        let out = select_action(DecisionRule::MaximizeExpectedUtility, &prices, &u).unwrap();
        assert_eq!(out.action, ActionId::new(1));
        assert_eq!(out.expected_utility, Amount::from_raw(8_000_000));

        let out_min = select_action(DecisionRule::MinimizeExpectedUtility, &prices, &u).unwrap();
        assert_eq!(out_min.action, ActionId::new(0));
    }

    #[test]
    fn ties_break_to_lowest_index() {
        let prices = vec![
            vec![Price::from_raw(500_000), Price::from_raw(500_000)],
            vec![Price::from_raw(500_000), Price::from_raw(500_000)],
        ];
        let u = util(&[10_000_000, 0]);
        let out = select_action(DecisionRule::MaximizeExpectedUtility, &prices, &u).unwrap();
        assert_eq!(out.action, ActionId::new(0));
    }

    #[test]
    fn confirmation_forms_and_verifies_at_quorum() {
        let ts = signers(4, 3);
        let set = ts.validator_set();
        let payload = ConfirmationPayload::action(MarketId::new(5), 7, SequenceNumber::new(1), 1);
        let c = DecisionConfirmation::form(payload, &ts, vec![0, 1, 2]);
        assert!(c.verify(&set).is_ok());
    }

    #[test]
    fn unsigned_confirmation_rejected() {
        let ts = signers(4, 3);
        let set = ts.validator_set();
        let payload = ConfirmationPayload::action(MarketId::new(5), 7, SequenceNumber::new(1), 1);
        // No signers -> below threshold.
        let c = DecisionConfirmation::form(payload, &ts, vec![]);
        assert!(matches!(
            c.verify(&set),
            Err(DecisionMarketError::Quorum(_))
        ));
    }

    #[test]
    fn wrong_authority_confirmation_rejected() {
        let ts = signers(4, 3);
        let set = ts.validator_set();
        // A disjoint key set signs the same payload digest.
        let foreign_seeds: Vec<[u8; 32]> = (0..4)
            .map(|i| [u8::try_from(i).unwrap() + 100; 32])
            .collect();
        let foreign = ThresholdSigners::from_seeds(&foreign_seeds, 3);
        let payload = ConfirmationPayload::action(MarketId::new(5), 7, SequenceNumber::new(1), 1);
        let c = DecisionConfirmation::form(payload, &foreign, vec![0, 1, 2]);
        // The digest still matches the payload, but signatures are wrong-authority.
        assert_eq!(c.quorum.message, c.payload.digest());
        assert!(matches!(
            c.verify(&set),
            Err(DecisionMarketError::Quorum(_))
        ));
    }

    #[test]
    fn tampered_payload_rejected() {
        let ts = signers(4, 3);
        let set = ts.validator_set();
        let payload = ConfirmationPayload::action(MarketId::new(5), 7, SequenceNumber::new(1), 1);
        let mut c = DecisionConfirmation::form(payload, &ts, vec![0, 1, 2]);
        // Mutate the index after signing: the digest no longer matches.
        c.payload.index = 0;
        assert_eq!(
            c.verify(&set),
            Err(DecisionMarketError::ConfirmationDigestMismatch)
        );
    }

    #[test]
    fn action_and_outcome_digests_differ_for_same_index() {
        let a = ConfirmationPayload::action(MarketId::new(5), 7, SequenceNumber::new(1), 1);
        let o = ConfirmationPayload::outcome(MarketId::new(5), 7, SequenceNumber::new(1), 1);
        assert_ne!(a.digest(), o.digest());
    }

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
    }

    #[test]
    fn verification_never_panics_on_garbage_quorum() {
        let ts = signers(4, 3);
        let set = ts.validator_set();
        let mut r = Lcg(0x5EED);
        for _ in 0..5_000 {
            let payload = ConfirmationPayload::action(
                MarketId::new(u32::try_from(r.next() % 16).unwrap()),
                r.next(),
                SequenceNumber::new(r.next()),
                u16::try_from(r.next() % 8).unwrap(),
            );
            let mut sig = [0u8; 64];
            for b in sig.iter_mut() {
                *b = u8::try_from(r.next() & 0xff).unwrap();
            }
            let quorum = QuorumCertificate {
                message: payload.digest(),
                signer_bitmap: r.next(),
                signatures: vec![sig],
            };
            let c = DecisionConfirmation { payload, quorum };
            let _ = c.verify(&set);
        }
    }

    #[test]
    fn property_selection_is_deterministic() {
        let mut r = Lcg(0xABCDEF);
        let u = util(&[7_000_000, 3_000_000]);
        for _ in 0..3_000 {
            let n = usize::try_from(r.next() % 5).unwrap() + 1;
            let mut prices = Vec::with_capacity(n);
            for _ in 0..n {
                // Build a normalized two-outcome vector [p, 1 - p].
                let p = i64::try_from(r.next() % 1_000_001).unwrap();
                prices.push(vec![
                    Price::from_raw(p),
                    Price::from_raw(types::RATIO_SCALE - p),
                ]);
            }
            let first = select_action(DecisionRule::MaximizeExpectedUtility, &prices, &u);
            let again = select_action(DecisionRule::MaximizeExpectedUtility, &prices, &u);
            assert_eq!(first, again);
            assert!(first.is_ok());
        }
    }
}

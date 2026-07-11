//! Decision-rule evaluation and action selection.
//!
//! Expected utility for an action is `Σ_o P(o) · utility(o)`, where the
//! outcome "probability" `P(o)` is the time-weighted decision [`Price`] of that
//! outcome's share (scale `1e6`, `1.0 == 1_000_000`) reinterpreted as a
//! [`Ratio`]. Selection is deterministic: ties break to the lowest action index.
//!
//! An externally-confirmed selection carries a fixed-width payload that is
//! decoded panic-free and checked for replay via a monotonic sequence number.

use types::{Amount, Price, Ratio, SequenceNumber};

use crate::definition::{DecisionRule, UtilityFunction};
use crate::error::DecisionMarketError;
use crate::instrument::ActionId;

/// The result of evaluating the decision rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionOutcome {
    /// The chosen action.
    pub action: ActionId,
    /// Its time-weighted expected utility.
    pub expected_utility: Amount,
}

/// Compute the time-weighted expected utility for a single action given its
/// per-outcome decision prices. `prices.len()` must equal `utils.len()`.
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
/// `per_action_prices[a]` is action `a`'s decision-price vector. Selection is
/// deterministic and ties break to the lowest action index.
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

/// A fixed-width external confirmation of a selected action.
///
/// Wire layout (little-endian, exactly [`ExternalConfirmation::ENCODED_LEN`]
/// bytes): `action: u16 | sequence: u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalConfirmation {
    /// The externally-confirmed action.
    pub action: ActionId,
    /// A strictly-monotonic sequence guarding against replay.
    pub sequence: SequenceNumber,
}

impl ExternalConfirmation {
    /// The exact encoded byte length.
    pub const ENCODED_LEN: usize = 10;

    /// Build a confirmation.
    #[inline]
    pub const fn new(action: ActionId, sequence: SequenceNumber) -> Self {
        Self { action, sequence }
    }

    /// Encode to the fixed-width wire form.
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0..2].copy_from_slice(&self.action.get().to_le_bytes());
        out[2..10].copy_from_slice(&self.sequence.get().to_le_bytes());
        out
    }

    /// Decode from bytes, rejecting any wrong-length payload. Never panics.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecisionMarketError> {
        if bytes.len() != Self::ENCODED_LEN {
            return Err(DecisionMarketError::MalformedConfirmation);
        }
        let action_bytes = <[u8; 2]>::try_from(&bytes[0..2])
            .map_err(|_| DecisionMarketError::MalformedConfirmation)?;
        let seq_bytes = <[u8; 8]>::try_from(&bytes[2..10])
            .map_err(|_| DecisionMarketError::MalformedConfirmation)?;
        Ok(Self {
            action: ActionId::new(u16::from_le_bytes(action_bytes)),
            sequence: SequenceNumber::new(u64::from_le_bytes(seq_bytes)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn util(vals: &[i128]) -> UtilityFunction {
        UtilityFunction::new(vals.iter().map(|v| Amount::from_raw(*v)).collect()).unwrap()
    }

    #[test]
    fn expected_utility_is_probability_weighted_sum() {
        // P(up)=0.6, P(down)=0.4; utility up=10.0, down=0.0 -> 6.0
        let prices = [Price::from_raw(600_000), Price::from_raw(400_000)];
        let eu = expected_utility(&prices, &util(&[10_000_000, 0])).unwrap();
        assert_eq!(eu, Amount::from_raw(6_000_000));
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
    fn confirmation_round_trips_and_rejects_bad_length() {
        let c = ExternalConfirmation::new(ActionId::new(3), SequenceNumber::new(42));
        let bytes = c.encode();
        assert_eq!(ExternalConfirmation::decode(&bytes).unwrap(), c);
        assert_eq!(
            ExternalConfirmation::decode(&bytes[..9]),
            Err(DecisionMarketError::MalformedConfirmation)
        );
        assert_eq!(
            ExternalConfirmation::decode(&[]),
            Err(DecisionMarketError::MalformedConfirmation)
        );
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
    fn confirmation_decode_never_panics_on_arbitrary_bytes() {
        let mut r = Lcg(0x5EED);
        for _ in 0..20_000 {
            let len = usize::try_from(r.next() % 16).unwrap();
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                bytes.push(u8::try_from(r.next() & 0xff).unwrap());
            }
            let _ = ExternalConfirmation::decode(&bytes);
        }
    }

    #[test]
    fn property_selection_is_deterministic() {
        let mut r = Lcg(0xABCDEF);
        let u = util(&[7_000_000, 3_000_000, 1_000_000]);
        for _ in 0..3_000 {
            let n = usize::try_from(r.next() % 5).unwrap() + 1;
            let mut prices = Vec::with_capacity(n);
            for _ in 0..n {
                let a = i64::try_from(r.next() % 1_000_001).unwrap();
                let b = i64::try_from(r.next() % 1_000_001).unwrap();
                let c = i64::try_from(r.next() % 1_000_001).unwrap();
                prices.push(vec![
                    Price::from_raw(a),
                    Price::from_raw(b),
                    Price::from_raw(c),
                ]);
            }
            let first = select_action(DecisionRule::MaximizeExpectedUtility, &prices, &u);
            let again = select_action(DecisionRule::MaximizeExpectedUtility, &prices, &u);
            assert_eq!(first, again);
        }
    }
}

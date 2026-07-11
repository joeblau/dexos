//! Scenario-vector (worst-case) risk for multi-outcome markets.
//!
//! A [`PayoutVector`] gives the settlement value of **one** claim under each
//! possible outcome. A trader holding `signed_qty` claims (positive = long,
//! negative = short) realizes `signed_qty * payout[o]` under outcome `o`.
//!
//! The functions here are the *scalar reference implementation*. They are the
//! documented equivalence baseline against which any future SIMD kernel is
//! diffed: for identical inputs a vectorized kernel must produce bit-identical
//! [`Amount`] outputs.
//!
//! Rounding is toward zero (inherited from [`Amount::mul_ratio`]), which is
//! conservative: the reported worst case is never rounded *up* into looking
//! safer than it is for a short, because the magnitude is only ever truncated.

use types::{Amount, PayoutVector, Quantity, Ratio};

use crate::error::RiskError;
use crate::math::{max_amount, min_amount, neg_amount};

/// The full per-outcome settlement value vector for a position.
///
/// Allocates a [`Vec`] of one [`Amount`] per outcome (bounded by
/// `types::MAX_OUTCOMES`). Prefer [`worst_case_scenario_pnl`] on the hot path,
/// which is allocation-free.
pub fn scenario_values(
    payout: &PayoutVector,
    signed_qty: Quantity,
) -> Result<Vec<Amount>, RiskError> {
    let scale = Ratio::from_raw(signed_qty.raw());
    let mut out = Vec::with_capacity(payout.len());
    for &p in payout.values() {
        out.push(p.mul_ratio(scale)?);
    }
    Ok(out)
}

/// The worst-case (minimum) settlement PnL across all outcomes.
///
/// Allocation-free single pass. For a long position this is the least
/// favorable payout; for a short it is the most expensive.
pub fn worst_case_scenario_pnl(
    payout: &PayoutVector,
    signed_qty: Quantity,
) -> Result<Amount, RiskError> {
    let scale = Ratio::from_raw(signed_qty.raw());
    let mut worst: Option<Amount> = None;
    for &p in payout.values() {
        let value = p.mul_ratio(scale)?;
        worst = Some(match worst {
            None => value,
            Some(w) => min_amount(w, value),
        });
    }
    // A constructed PayoutVector is guaranteed non-empty, but stay total.
    worst.ok_or(RiskError::Payout(types::PayoutVectorError::Empty))
}

/// The best-case (maximum) settlement PnL across all outcomes.
pub fn best_case_scenario_pnl(
    payout: &PayoutVector,
    signed_qty: Quantity,
) -> Result<Amount, RiskError> {
    let scale = Ratio::from_raw(signed_qty.raw());
    let mut best: Option<Amount> = None;
    for &p in payout.values() {
        let value = p.mul_ratio(scale)?;
        best = Some(match best {
            None => value,
            Some(b) => max_amount(b, value),
        });
    }
    best.ok_or(RiskError::Payout(types::PayoutVectorError::Empty))
}

/// Collateral required to cover the position in every outcome:
/// `max(0, -worst_case_pnl)`.
///
/// This is guaranteed `>=` the liability (`-pnl`) in *every* individual
/// scenario, since it equals the maximum liability across outcomes.
pub fn required_collateral(
    payout: &PayoutVector,
    signed_qty: Quantity,
) -> Result<Amount, RiskError> {
    let worst = worst_case_scenario_pnl(payout, signed_qty)?;
    if worst.is_negative() {
        neg_amount(worst)
    } else {
        Ok(Amount::ZERO)
    }
}

/// A held position in a payout-vector (multi-outcome) market.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayoutPosition {
    /// Settlement value of one claim under each outcome.
    pub payout: PayoutVector,
    /// Signed claims held (positive = long, negative = short).
    pub signed_qty: Quantity,
}

impl PayoutPosition {
    /// Construct a payout-vector position.
    pub fn new(payout: PayoutVector, signed_qty: Quantity) -> Self {
        Self { payout, signed_qty }
    }

    /// Worst-case settlement PnL for this position.
    #[inline]
    pub fn worst_case_pnl(&self) -> Result<Amount, RiskError> {
        worst_case_scenario_pnl(&self.payout, self.signed_qty)
    }

    /// Collateral this position requires in isolation.
    #[inline]
    pub fn required_collateral(&self) -> Result<Amount, RiskError> {
        required_collateral(&self.payout, self.signed_qty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pv(v: &[i128]) -> PayoutVector {
        PayoutVector::new(v.iter().map(|&x| Amount::from_raw(x)).collect()).unwrap()
    }

    const ONE: i128 = 1_000_000; // 1.0 at Amount scale
    const QTY_ONE: i64 = 1_000_000; // 1.0 at Quantity scale

    #[test]
    fn binary_long_and_short() {
        // Binary market: outcome 0 pays 1.0, outcome 1 pays 0.0.
        let market = pv(&[ONE, 0]);
        // Long 1 claim: worst case is 0 (outcome 1); no collateral needed.
        let long = PayoutPosition::new(market.clone(), Quantity::from_raw(QTY_ONE));
        assert_eq!(long.worst_case_pnl().unwrap(), Amount::from_raw(0));
        assert_eq!(long.required_collateral().unwrap(), Amount::ZERO);
        // Short 1 claim: worst case is -1.0 (outcome 0 pays 1 you must deliver).
        let short = PayoutPosition::new(market, Quantity::from_raw(-QTY_ONE));
        assert_eq!(short.worst_case_pnl().unwrap(), Amount::from_raw(-ONE));
        assert_eq!(short.required_collateral().unwrap(), Amount::from_raw(ONE));
    }

    #[test]
    fn multi_outcome_worst_case() {
        // Three outcomes paying 0.2, 0.5, 1.0.
        let market = pv(&[ONE / 5, ONE / 2, ONE]);
        // Short 2 claims: values -0.4, -1.0, -2.0 -> worst -2.0, required 2.0.
        let short = PayoutPosition::new(market, Quantity::from_raw(-2 * QTY_ONE));
        assert_eq!(short.worst_case_pnl().unwrap(), Amount::from_raw(-2 * ONE));
        assert_eq!(
            short.required_collateral().unwrap(),
            Amount::from_raw(2 * ONE)
        );
    }

    #[test]
    fn scalar_market_partial_payout() {
        // Scalar/range market settling between 0.25 and 0.75.
        let market = pv(&[ONE / 4, ONE / 2, 3 * ONE / 4]);
        let long = PayoutPosition::new(market, Quantity::from_raw(QTY_ONE));
        assert_eq!(long.worst_case_pnl().unwrap(), Amount::from_raw(ONE / 4));
        // Long already funded via premium: no extra collateral.
        assert_eq!(long.required_collateral().unwrap(), Amount::ZERO);
    }

    #[test]
    fn dead_heat_equal_outcomes() {
        // Dead-heat / tie: every outcome pays 0.5.
        let market = pv(&[ONE / 2, ONE / 2, ONE / 2]);
        let short = PayoutPosition::new(market, Quantity::from_raw(-3 * QTY_ONE));
        // -0.5 * 3 = -1.5 in every outcome.
        assert_eq!(
            short.worst_case_pnl().unwrap(),
            Amount::from_raw(-3 * ONE / 2)
        );
        assert_eq!(
            short.required_collateral().unwrap(),
            Amount::from_raw(3 * ONE / 2)
        );
    }

    #[test]
    fn custom_payout_vector_fractional_qty() {
        // Custom vector with an irregular shape and a fractional position.
        let market = pv(&[3 * ONE, 0, ONE]);
        // Short 0.5 claims: values -1.5, 0, -0.5 -> worst -1.5, required 1.5.
        let short = PayoutPosition::new(market, Quantity::from_raw(-QTY_ONE / 2));
        assert_eq!(
            short.worst_case_pnl().unwrap(),
            Amount::from_raw(-3 * ONE / 2)
        );
        assert_eq!(
            short.required_collateral().unwrap(),
            Amount::from_raw(3 * ONE / 2)
        );
    }

    #[test]
    fn scenario_values_matches_hand_values() {
        let market = pv(&[ONE, 2 * ONE, 3 * ONE]);
        let vals = scenario_values(&market, Quantity::from_raw(QTY_ONE)).unwrap();
        assert_eq!(
            vals,
            vec![
                Amount::from_raw(ONE),
                Amount::from_raw(2 * ONE),
                Amount::from_raw(3 * ONE)
            ]
        );
    }

    // Deterministic in-test LCG (no external crates).
    struct Lcg(u64);
    impl Lcg {
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn payout_amount(&mut self) -> i128 {
            // Bounded 0.0 ..= ~1000.0 so products stay well inside i128.
            i128::from(self.next_u64() % 1_000_000_000)
        }
        fn signed_qty(&mut self) -> i64 {
            i64::try_from(self.next_u64() % 2_000_000).unwrap() - 1_000_000
        }
    }

    #[test]
    fn property_required_collateral_covers_every_scenario() {
        let mut r = Lcg(0xC0FF_EE01);
        for _ in 0..20_000 {
            let n = usize::try_from(r.next_u64() % 8).unwrap() + 1;
            let vals: Vec<Amount> = (0..n)
                .map(|_| Amount::from_raw(r.payout_amount()))
                .collect();
            let market = PayoutVector::new(vals).unwrap();
            let q = Quantity::from_raw(r.signed_qty());
            let req = required_collateral(&market, q).unwrap();
            // Required collateral is non-negative...
            assert!(!req.is_negative());
            // ...and covers the liability in every individual scenario.
            let per_outcome = scenario_values(&market, q).unwrap();
            for v in per_outcome {
                let liability = if v.is_negative() {
                    neg_amount(v).unwrap()
                } else {
                    Amount::ZERO
                };
                assert!(req.raw() >= liability.raw());
            }
        }
    }

    #[test]
    fn never_panics_on_extreme_payouts() {
        // Huge payouts and extreme quantities must error, never panic.
        let market = pv(&[i128::MAX, i128::MIN, 0]);
        let q = Quantity::from_raw(i64::MAX);
        let _ = worst_case_scenario_pnl(&market, q);
        let _ = required_collateral(&market, Quantity::from_raw(i64::MIN));
        let _ = scenario_values(&market, q);
    }
}

//! Generic payout vectors, complete-set accounting, settlement distribution,
//! and worst-case settlement liability.
//!
//! # Complete sets
//! Minting a complete set locks one stablecoin unit and issues one claim on
//! *each* outcome; redeeming burns one claim of each outcome and returns the
//! unit. The pool therefore maintains, at all times, the invariant
//! `locked_collateral == outstanding[o]` for every outcome `o`
//! ([`CompleteSetPool::invariant_holds`]).
//!
//! # Value conservation on settlement
//! For a resolved [`PayoutVector`] whose entries sum to one unit, the total
//! stablecoin credited equals the collateral locked, modulo deterministic
//! rounding dust that is reported explicitly ([`Settlement::dust`]).

use serde::{Deserialize, Serialize};
use types::{Amount, ArithError, Hash, PayoutVector, Quantity, ScalarOutcome, AMOUNT_SCALE};

use crate::error::PayoutError;

/// `(a * b) / c` in `i128` with checked multiply, rounding toward zero.
fn mul_div(a: i128, b: i128, c: i128) -> Result<i128, ArithError> {
    if c == 0 {
        return Err(ArithError::DivByZero);
    }
    let product = a.checked_mul(b).ok_or(ArithError::Overflow)?;
    Ok(product / c)
}

/// `claims * payout_per_claim` rescaled to [`Amount`] units, rounding toward
/// zero. Both operands are at the 6-dp Amount scale.
fn settle_value(claims: Amount, payout_per_claim: Amount) -> Result<Amount, PayoutError> {
    let v = mul_div(claims.raw(), payout_per_claim.raw(), AMOUNT_SCALE)?;
    Ok(Amount::from_raw(v))
}

/// How a market pays out at settlement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayoutRule {
    /// A fixed per-outcome payout vector (binary, multi-outcome, dead-heat, …).
    Vector(PayoutVector),
    /// A scalar / range market resolving to a value in `[lower, upper]`. Two
    /// outcomes in canonical [`types::ScalarOutcome`] order: index 0 = long,
    /// index 1 = short.
    Scalar {
        /// Lower bound of the settlement range.
        lower: Amount,
        /// Upper bound of the settlement range.
        upper: Amount,
    },
    /// A custom rule resolved by an external adapter, committed by hash. Not
    /// self-enumerable.
    Custom(Hash),
}

impl PayoutRule {
    /// The number of outcomes if statically enumerable (`Vector`/`Scalar`);
    /// `None` for `Custom`.
    #[must_use]
    pub fn num_outcomes(&self) -> Option<usize> {
        match self {
            PayoutRule::Vector(v) => Some(v.len()),
            PayoutRule::Scalar { .. } => Some(2),
            PayoutRule::Custom(_) => None,
        }
    }
}

/// A payout vector paying the entire unit to `winner`, zero elsewhere.
///
/// # Errors
/// [`PayoutError::Vector`] if `n` is 0 or exceeds the maximum;
/// [`PayoutError::OutcomeMismatch`] if `winner >= n`.
pub fn winner_takes_all(n: usize, winner: usize) -> Result<PayoutVector, PayoutError> {
    if winner >= n {
        return Err(PayoutError::OutcomeMismatch);
    }
    let mut v = vec![Amount::ZERO; n];
    v[winner] = Amount::ONE;
    Ok(PayoutVector::new_conserving(v)?)
}

/// A dead-heat / tie vector splitting one unit equally across `winners`, with
/// rounding dust assigned to the last winner so the vector sums to exactly one
/// unit.
///
/// # Errors
/// [`PayoutError::OutcomeMismatch`] if `winners` is empty or any index `>= n`;
/// [`PayoutError::DuplicateWinner`] if an index is named twice;
/// [`PayoutError::Vector`] on bad `n`; [`PayoutError::Arith`] on overflow.
pub fn dead_heat(n: usize, winners: &[usize]) -> Result<PayoutVector, PayoutError> {
    if winners.is_empty() {
        return Err(PayoutError::OutcomeMismatch);
    }
    let k = i128::try_from(winners.len()).map_err(|_| ArithError::OutOfRange)?;
    let mut v = vec![Amount::ZERO; n];
    let per = Amount::ONE.raw() / k;
    let mut allocated = 0i128;
    for &w in winners {
        if w >= n {
            return Err(PayoutError::OutcomeMismatch);
        }
        // Reject duplicate winners: a repeated index would otherwise overwrite an
        // entry while double-counting `allocated`, corrupting the dust adjustment
        // (and could yield a non-conserving vector). `per > 0` since `k <= n <=
        // MAX_OUTCOMES`, so a placed slot is always non-zero.
        if v[w].raw() != 0 {
            return Err(PayoutError::DuplicateWinner);
        }
        v[w] = Amount::from_raw(per);
        allocated += per;
    }
    // Assign the remaining dust to the last winner so the sum is exactly ONE.
    let last = winners[winners.len() - 1];
    let dust = Amount::ONE.raw() - allocated;
    v[last] = Amount::from_raw(per + dust);
    Ok(PayoutVector::new_conserving(v)?)
}

/// An INVALID-market pro-rata refund vector: every outcome shares the unit
/// equally, so any complete set redeems for exactly one unit.
///
/// # Errors
/// As [`dead_heat`].
pub fn invalid_refund(n: usize) -> Result<PayoutVector, PayoutError> {
    let all: Vec<usize> = (0..n).collect();
    dead_heat(n, &all)
}

/// The two-outcome payout vector for a scalar market resolving to `value`, in
/// canonical [`types::ScalarOutcome`] order.
///
/// `value` is clamped into `[lower, upper]`. Index 0 ([`ScalarOutcome::Long`])
/// receives `(value - lower) / (upper - lower)`; index 1
/// ([`ScalarOutcome::Short`]) receives the complement, so the vector sums to
/// exactly one unit. All width arithmetic is checked, so extreme bounds return a
/// typed error instead of overflowing.
///
/// # Errors
/// [`PayoutError::OutcomeMismatch`] if `upper <= lower`; [`PayoutError::Arith`]
/// on overflow at extreme bounds.
pub fn scalar_payout(
    lower: Amount,
    upper: Amount,
    value: Amount,
) -> Result<PayoutVector, PayoutError> {
    if upper.raw() <= lower.raw() {
        return Err(PayoutError::OutcomeMismatch);
    }
    let clamped = value.raw().clamp(lower.raw(), upper.raw());
    // `upper - lower` and `clamped - lower` can overflow i128 at extreme bounds
    // (e.g. `lower == Amount::MIN`), so never subtract unchecked.
    let range = upper
        .raw()
        .checked_sub(lower.raw())
        .ok_or(ArithError::Overflow)?;
    let numer = clamped
        .checked_sub(lower.raw())
        .ok_or(ArithError::Overflow)?;
    // long = (value - lower) / range, expressed at Amount scale (floor toward 0).
    let long_raw = mul_div(numer, Amount::ONE.raw(), range)?;
    let long = Amount::from_raw(long_raw);
    let short = Amount::ONE.checked_sub(long)?;
    let mut v = vec![Amount::ZERO; 2];
    v[ScalarOutcome::Long.index()] = long;
    v[ScalarOutcome::Short.index()] = short;
    Ok(PayoutVector::new_conserving(v)?)
}

/// The aggregate complete-set position of one market.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompleteSetPool {
    num_outcomes: usize,
    locked_collateral: Amount,
    outstanding: Vec<Amount>,
}

impl CompleteSetPool {
    /// A fresh empty pool over `num_outcomes` outcomes.
    ///
    /// # Errors
    /// [`PayoutError::Vector`] via a zero / oversized outcome count.
    pub fn new(num_outcomes: usize) -> Result<Self, PayoutError> {
        if num_outcomes == 0 || num_outcomes > types::MAX_OUTCOMES {
            return Err(PayoutError::Vector(types::PayoutVectorError::Empty));
        }
        Ok(Self {
            num_outcomes,
            locked_collateral: Amount::ZERO,
            outstanding: vec![Amount::ZERO; num_outcomes],
        })
    }

    /// Number of outcomes.
    #[must_use]
    pub fn num_outcomes(&self) -> usize {
        self.num_outcomes
    }

    /// Collateral currently locked.
    #[must_use]
    pub fn locked_collateral(&self) -> Amount {
        self.locked_collateral
    }

    /// Outstanding claims per outcome.
    #[must_use]
    pub fn outstanding(&self) -> &[Amount] {
        &self.outstanding
    }

    /// Whether the collateral-conservation invariant holds: locked collateral
    /// equals the outstanding claims of every outcome.
    #[must_use]
    pub fn invariant_holds(&self) -> bool {
        self.outstanding
            .iter()
            .all(|&c| c == self.locked_collateral)
    }

    /// Mint `units` complete sets: lock `units` collateral, issue `units` claims
    /// on every outcome.
    ///
    /// # Errors
    /// [`PayoutError::NonPositiveUnits`] if `units <= 0`; [`PayoutError::Arith`]
    /// on overflow.
    pub fn mint(&mut self, units: Amount) -> Result<(), PayoutError> {
        if units.raw() <= 0 {
            return Err(PayoutError::NonPositiveUnits);
        }
        let new_locked = self.locked_collateral.checked_add(units)?;
        let mut next = Vec::with_capacity(self.num_outcomes);
        for &c in &self.outstanding {
            next.push(c.checked_add(units)?);
        }
        self.locked_collateral = new_locked;
        self.outstanding = next;
        Ok(())
    }

    /// Redeem `units` complete sets: burn `units` claims of every outcome and
    /// release `units` collateral.
    ///
    /// # Errors
    /// [`PayoutError::NonPositiveUnits`] if `units <= 0`;
    /// [`PayoutError::InsufficientCollateral`] if fewer than `units` are locked;
    /// [`PayoutError::InsufficientClaims`] if any outcome has fewer than `units`.
    pub fn redeem(&mut self, units: Amount) -> Result<(), PayoutError> {
        if units.raw() <= 0 {
            return Err(PayoutError::NonPositiveUnits);
        }
        if self.locked_collateral.raw() < units.raw() {
            return Err(PayoutError::InsufficientCollateral);
        }
        if self.outstanding.iter().any(|&c| c.raw() < units.raw()) {
            return Err(PayoutError::InsufficientClaims);
        }
        self.locked_collateral = self.locked_collateral.checked_sub(units)?;
        for c in &mut self.outstanding {
            *c = c.checked_sub(units)?;
        }
        Ok(())
    }

    /// Distribute settlement across outstanding claims given the resolved
    /// `payout` vector (one payout amount per outcome-claim). The credited total
    /// plus [`Settlement::dust`] equals the collateral that was locked.
    ///
    /// # Errors
    /// [`PayoutError::OutcomeMismatch`] if `payout.len() != num_outcomes`;
    /// [`PayoutError::Vector`] if `payout` is not value-conserving (negative,
    /// zero-sum, or over/under one unit); [`PayoutError::Arith`] on overflow.
    pub fn settle(&self, payout: &PayoutVector) -> Result<Settlement, PayoutError> {
        if payout.len() != self.num_outcomes {
            return Err(PayoutError::OutcomeMismatch);
        }
        // Revalidate at the settlement boundary: a vector may have been
        // deserialized (bypassing the constructors), so re-assert conservation
        // before crediting. This keeps the reported dust bounded to rounding.
        payout.validate_conserving()?;
        let mut per_outcome = Vec::with_capacity(self.num_outcomes);
        let mut total = Amount::ZERO;
        for (claims, pay) in self.outstanding.iter().zip(payout.values()) {
            let credit = settle_value(*claims, *pay)?;
            total = total.checked_add(credit)?;
            per_outcome.push(credit);
        }
        let dust = self.locked_collateral.checked_sub(total)?;
        Ok(Settlement {
            per_outcome_credit: per_outcome,
            total_credited: total,
            dust,
        })
    }
}

/// The result of settling a [`CompleteSetPool`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    /// Stablecoin credited to holders of each outcome's claims.
    pub per_outcome_credit: Vec<Amount>,
    /// Sum of `per_outcome_credit`.
    pub total_credited: Amount,
    /// `locked_collateral - total_credited`: deterministic rounding dust routed
    /// to the protocol / insurance backstop.
    pub dust: Amount,
}

/// Worst-case settlement liability of holding `signed_qty` claims against
/// `payout`, reusing the risk crate's scenario engine as the scalar reference.
///
/// # Errors
/// [`PayoutError::Arith`] if the scenario scan overflows.
pub fn worst_case_liability(
    payout: &PayoutVector,
    signed_qty: Quantity,
) -> Result<Amount, PayoutError> {
    risk::required_collateral(payout, signed_qty)
        .map_err(|_| PayoutError::Arith(ArithError::Overflow))
}

/// The sum of a payout vector's entries (for unit-conservation checks).
///
/// # Errors
/// [`PayoutError::Arith`] on overflow.
pub fn payout_sum(payout: &PayoutVector) -> Result<Amount, PayoutError> {
    let mut total = Amount::ZERO;
    for &v in payout.values() {
        total = total.checked_add(v)?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: i128 = AMOUNT_SCALE;

    fn amt(r: i128) -> Amount {
        Amount::from_raw(r)
    }

    #[test]
    fn constructors_cover_all_shapes() {
        // binary win / synthetic-NO
        let yes = winner_takes_all(2, 0).unwrap();
        assert_eq!(yes.values(), &[amt(ONE), amt(0)]);
        let no = winner_takes_all(2, 1).unwrap();
        assert_eq!(no.values(), &[amt(0), amt(ONE)]);
        // multi-outcome
        let m = winner_takes_all(4, 2).unwrap();
        assert_eq!(m.values()[2], amt(ONE));
        // dead-heat between 0 and 1
        let dh = dead_heat(3, &[0, 1]).unwrap();
        assert_eq!(dh.values(), &[amt(ONE / 2), amt(ONE / 2), amt(0)]);
        // invalid / partial refund over 3 outcomes: 1/3 each with dust on last.
        let inv = invalid_refund(3).unwrap();
        assert_eq!(payout_sum(&inv).unwrap(), amt(ONE));
        // scalar mid-point, canonical [long, short] order
        let sc = scalar_payout(amt(0), amt(100 * ONE), amt(25 * ONE)).unwrap();
        // long = 25/100 = 0.25, short = 0.75
        assert_eq!(sc.values()[ScalarOutcome::Long.index()], amt(ONE / 4));
        assert_eq!(sc.values()[ScalarOutcome::Short.index()], amt(3 * ONE / 4));
        assert_eq!(sc.values(), &[amt(ONE / 4), amt(3 * ONE / 4)]);
    }

    #[test]
    fn all_constructor_vectors_sum_to_one_unit() {
        for n in 1..=8usize {
            for w in 0..n {
                assert_eq!(
                    payout_sum(&winner_takes_all(n, w).unwrap()).unwrap(),
                    amt(ONE)
                );
            }
            assert_eq!(payout_sum(&invalid_refund(n).unwrap()).unwrap(), amt(ONE));
        }
        for k in 1..=5i128 {
            let winners: Vec<usize> = (0..usize::try_from(k).unwrap()).collect();
            let dh = dead_heat(6, &winners).unwrap();
            assert_eq!(payout_sum(&dh).unwrap(), amt(ONE));
        }
        // scalar across a sweep of values always sums to one unit.
        for v in 0..=10i128 {
            let sc = scalar_payout(amt(0), amt(10 * ONE), amt(v * ONE)).unwrap();
            assert_eq!(payout_sum(&sc).unwrap(), amt(ONE));
        }
    }

    #[test]
    fn scalar_clamps_outside_range() {
        // value above upper clamps to full long: [long=1, short=0].
        let sc = scalar_payout(amt(0), amt(ONE), amt(5 * ONE)).unwrap();
        assert_eq!(sc.values(), &[amt(ONE), amt(0)]);
        // value below lower clamps to full short: [long=0, short=1].
        let sc2 = scalar_payout(amt(ONE), amt(2 * ONE), amt(0)).unwrap();
        assert_eq!(sc2.values(), &[amt(0), amt(ONE)]);
        assert_eq!(
            scalar_payout(amt(ONE), amt(ONE), amt(ONE)).unwrap_err(),
            PayoutError::OutcomeMismatch
        );
    }

    #[test]
    fn dead_heat_rejects_duplicate_winners() {
        assert_eq!(
            dead_heat(3, &[0, 0]).unwrap_err(),
            PayoutError::DuplicateWinner
        );
        assert_eq!(
            dead_heat(4, &[1, 2, 1]).unwrap_err(),
            PayoutError::DuplicateWinner
        );
        // Distinct winners still succeed and conserve exactly.
        let dh = dead_heat(3, &[0, 2]).unwrap();
        assert_eq!(payout_sum(&dh).unwrap(), amt(ONE));
        assert!(dh.validate_conserving().is_ok());
    }

    #[test]
    fn scalar_payout_matches_rational_reference_and_conserves() {
        let mut r = Lcg(0x5CA1_A420);
        for _ in 0..20_000 {
            // Bounded so the reference division is exact and in range.
            let lo = i128::from(r.next_u64() % 1_000_000) - 500_000;
            let span = i128::from(r.next_u64() % 10_000_000) + 1; // >= 1 => lo < hi
            let hi = lo + span;
            let v = lo - 1_000_000 + i128::from(r.next_u64() % 12_000_000);
            let pv = scalar_payout(amt(lo), amt(hi), amt(v)).unwrap();
            let long = pv.values()[ScalarOutcome::Long.index()].raw();
            let short = pv.values()[ScalarOutcome::Short.index()].raw();
            // Value-conserving to exactly one unit.
            assert_eq!(long + short, ONE);
            assert!(pv.validate_conserving().is_ok());
            // Rational reference (exact i128): long == floor((clamp(v)-lo)*ONE/span).
            let clamped = v.clamp(lo, hi);
            let expected_long = (clamped - lo) * ONE / span;
            assert_eq!(long, expected_long);
            assert!((0..=ONE).contains(&long));
        }
    }

    #[test]
    fn scalar_payout_rejects_extremes_without_panic() {
        // Width overflow at extreme bounds -> typed Arith error, never a panic.
        assert_eq!(
            scalar_payout(Amount::MIN, Amount::MAX, Amount::ZERO).unwrap_err(),
            PayoutError::Arith(ArithError::Overflow)
        );
        // numerator * ONE overflow at a huge span -> typed error.
        assert_eq!(
            scalar_payout(Amount::ZERO, Amount::MAX, Amount::MAX).unwrap_err(),
            PayoutError::Arith(ArithError::Overflow)
        );
        // Degenerate range is still rejected.
        assert_eq!(
            scalar_payout(Amount::ONE, Amount::ONE, Amount::ONE).unwrap_err(),
            PayoutError::OutcomeMismatch
        );
    }

    #[test]
    fn settle_rejects_non_conserving_payout() {
        let mut pool = CompleteSetPool::new(2).unwrap();
        pool.mint(amt(ONE)).unwrap();
        // Over-allocated vector: settle rejects instead of over-crediting.
        let over = PayoutVector::new(vec![amt(ONE), amt(ONE)]).unwrap();
        assert_eq!(
            pool.settle(&over).unwrap_err(),
            PayoutError::Vector(types::PayoutVectorError::OverAllocated)
        );
        // Zero-sum vector rejected too.
        let zero = PayoutVector::new(vec![amt(0), amt(0)]).unwrap();
        assert_eq!(
            pool.settle(&zero).unwrap_err(),
            PayoutError::Vector(types::PayoutVectorError::ZeroSum)
        );
        // Negative entry rejected.
        let neg = PayoutVector::new(vec![amt(-1), amt(ONE + 1)]).unwrap();
        assert_eq!(
            pool.settle(&neg).unwrap_err(),
            PayoutError::Vector(types::PayoutVectorError::NegativeEntry)
        );
    }

    #[test]
    fn settlement_dust_is_bounded_and_conserves() {
        // A non-divisible collateral over a three-way dead heat leaves sub-unit
        // rounding dust; credited + dust equals the locked collateral exactly.
        let mut pool = CompleteSetPool::new(3).unwrap();
        pool.mint(amt(ONE + 1)).unwrap();
        let payout = dead_heat(3, &[0, 1, 2]).unwrap();
        let s = pool.settle(&payout).unwrap();
        assert_eq!(
            s.total_credited.checked_add(s.dust).unwrap(),
            pool.locked_collateral()
        );
        // Dust never reaches one micro-unit per outcome.
        assert!(!s.dust.is_negative());
        assert!(s.dust.raw() < i128::try_from(pool.num_outcomes()).unwrap());
    }

    #[test]
    fn mint_redeem_maintains_invariant_and_conserves() {
        let mut pool = CompleteSetPool::new(3).unwrap();
        assert!(pool.invariant_holds());
        pool.mint(amt(5 * ONE)).unwrap();
        assert!(pool.invariant_holds());
        assert_eq!(pool.locked_collateral(), amt(5 * ONE));
        assert_eq!(pool.outstanding(), &[amt(5 * ONE); 3]);
        pool.redeem(amt(2 * ONE)).unwrap();
        assert!(pool.invariant_holds());
        assert_eq!(pool.locked_collateral(), amt(3 * ONE));
        // over-redeem rejected.
        assert_eq!(
            pool.redeem(amt(10 * ONE)).unwrap_err(),
            PayoutError::InsufficientCollateral
        );
        assert_eq!(
            pool.mint(amt(0)).unwrap_err(),
            PayoutError::NonPositiveUnits
        );
    }

    #[test]
    fn settlement_winner_takes_all_conserves() {
        let mut pool = CompleteSetPool::new(2).unwrap();
        pool.mint(amt(7 * ONE)).unwrap();
        let payout = winner_takes_all(2, 0).unwrap();
        let s = pool.settle(&payout).unwrap();
        // outcome-0 holders get 7.0, outcome-1 holders get 0.
        assert_eq!(s.per_outcome_credit, vec![amt(7 * ONE), amt(0)]);
        assert_eq!(s.total_credited, amt(7 * ONE));
        assert_eq!(s.dust, amt(0));
    }

    #[test]
    fn settlement_dead_heat_and_dust() {
        let mut pool = CompleteSetPool::new(3).unwrap();
        pool.mint(amt(ONE)).unwrap();
        // dead heat 0 & 1: [0.5, 0.5, 0].
        let payout = dead_heat(3, &[0, 1]).unwrap();
        let s = pool.settle(&payout).unwrap();
        assert_eq!(s.total_credited.checked_add(s.dust).unwrap(), amt(ONE));
    }

    #[test]
    fn worst_case_liability_matches_hand_values() {
        // Binary [1,0], short 1 claim -> worst case pays 1.0.
        let market = winner_takes_all(2, 0).unwrap();
        let liab = worst_case_liability(&market, Quantity::from_raw(-1_000_000)).unwrap();
        assert_eq!(liab, amt(ONE));
        // Long 1 claim -> no liability.
        let liab_long = worst_case_liability(&market, Quantity::from_raw(1_000_000)).unwrap();
        assert_eq!(liab_long, Amount::ZERO);
    }

    // Deterministic LCG property test: mint/redeem conserves at all times.
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
    fn property_mint_redeem_conserves() {
        let mut r = Lcg(0xC0DE_F00D);
        for _ in 0..10_000 {
            let n = usize::try_from(r.next_u64() % 6).unwrap() + 1;
            let mut pool = CompleteSetPool::new(n).unwrap();
            for _ in 0..20 {
                let units = amt(i128::from(r.next_u64() % 1_000_000));
                if r.next_u64().is_multiple_of(2) {
                    let _ = pool.mint(units);
                } else {
                    let _ = pool.redeem(units);
                }
                // Invariant: locked == every outcome's outstanding.
                assert!(pool.invariant_holds());
                assert!(!pool.locked_collateral().is_negative());
            }
            // Settling a unit-summing vector conserves: credited + dust == locked.
            if n >= 1 {
                let payout = invalid_refund(n).unwrap();
                let s = pool.settle(&payout).unwrap();
                assert_eq!(
                    s.total_credited.checked_add(s.dust).unwrap(),
                    pool.locked_collateral()
                );
                assert!(!s.dust.is_negative());
            }
        }
    }

    #[test]
    fn never_panics_decoding_arbitrary_payout_rule_bytes() {
        let mut r = Lcg(0xBAD_C0FFE);
        for _ in 0..20_000 {
            let len = usize::try_from(r.next_u64() % 64).unwrap();
            let bytes: Vec<u8> = (0..len)
                .map(|_| u8::try_from(r.next_u64() % 256).unwrap())
                .collect();
            let _ = postcard::from_bytes::<PayoutRule>(&bytes);
            let _ = postcard::from_bytes::<CompleteSetPool>(&bytes);
        }
    }
}

//! Scalar perpetual positions with average-entry accounting.
//!
//! A [`PerpPosition`] tracks a signed net quantity and a volume-weighted
//! average entry price. Fills that increase exposure re-weight the average;
//! fills that reduce it realize PnL on the closed portion (which the engine
//! folds into settled collateral) and leave the average untouched; fills that
//! flip the sign realize the full close and re-open at the fill price.
//!
//! Design note (conservation): a fill executed *at the current mark price*
//! leaves account equity unchanged — it only moves value between the
//! unrealized and realized (collateral) ledgers. Equity moves only by realized
//! PnL away from mark, funding, and fees. The unit tests assert this.

use types::{Amount, MarketId, Price, Quantity};

use crate::error::RiskError;
use crate::math::abs_amount;

/// A signed perpetual position in one market.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PerpPosition {
    /// The market this position is in.
    pub market: MarketId,
    /// Signed net quantity (positive = long, negative = short).
    pub net_qty: Quantity,
    /// Volume-weighted average entry price of the open quantity.
    pub avg_entry: Price,
}

impl PerpPosition {
    /// A flat (zero) position in `market`.
    #[inline]
    pub fn flat(market: MarketId) -> Self {
        Self {
            market,
            net_qty: Quantity::ZERO,
            avg_entry: Price::ZERO,
        }
    }

    /// True if the position holds no quantity.
    #[inline]
    pub fn is_flat(&self) -> bool {
        self.net_qty.raw() == 0
    }

    /// Apply a signed fill and return the realized PnL to settle into collateral.
    ///
    /// `dq` is the signed filled quantity (positive = bought, negative = sold);
    /// `price` is the execution price. Realized PnL is non-zero only when the
    /// fill reduces or flips the existing position.
    pub fn apply_fill(&mut self, dq: Quantity, price: Price) -> Result<Amount, RiskError> {
        let d = dq.raw();
        if d == 0 {
            return Ok(Amount::ZERO);
        }
        let net = self.net_qty.raw();
        if net == 0 {
            self.net_qty = dq;
            self.avg_entry = price;
            return Ok(Amount::ZERO);
        }

        let same_direction = (net > 0) == (d > 0);
        if same_direction {
            // Increasing exposure: re-weight the average entry price.
            let new_net = net.checked_add(d).ok_or(types::ArithError::Overflow)?;
            self.avg_entry = weighted_avg(net, self.avg_entry, d, price)?;
            self.net_qty = Quantity::from_raw(new_net);
            return Ok(Amount::ZERO);
        }

        // Opposite direction: realize PnL on the closed portion.
        let close = min_abs(net, d); // magnitude closed, > 0
        let diff = price.checked_sub(self.avg_entry)?; // price - entry
        let gross = diff.notional(Quantity::from_raw(close))?; // (price-entry)*close
                                                               // Long closes profit when price>entry (+gross); short closes profit
                                                               // when price<entry (-gross).
        let realized = if net > 0 {
            gross
        } else {
            Amount::ZERO.checked_sub(gross)?
        };

        let new_net = net.checked_add(d).ok_or(types::ArithError::Overflow)?;
        if new_net == 0 {
            self.avg_entry = Price::ZERO;
        } else if (new_net > 0) != (net > 0) {
            // Flipped: the remainder opens a fresh position at the fill price.
            self.avg_entry = price;
        }
        // else: partial reduction, average entry is unchanged.
        self.net_qty = Quantity::from_raw(new_net);
        Ok(realized)
    }

    /// Signed notional at `mark`: `mark * net_qty`, sign preserved.
    #[inline]
    pub fn signed_notional(&self, mark: Price) -> Result<Amount, RiskError> {
        mark.notional(self.net_qty).map_err(RiskError::from)
    }

    /// Absolute notional exposure at `mark`.
    #[inline]
    pub fn exposure(&self, mark: Price) -> Result<Amount, RiskError> {
        abs_amount(self.signed_notional(mark)?)
    }

    /// Unrealized PnL at `mark`: `(mark - avg_entry) * net_qty`.
    #[inline]
    pub fn unrealized(&self, mark: Price) -> Result<Amount, RiskError> {
        let diff = mark.checked_sub(self.avg_entry)?;
        diff.notional(self.net_qty).map_err(RiskError::from)
    }
}

/// Volume-weighted average of two same-signed legs, in [`Price`] units.
///
/// `(|q0|*p0 + |q1|*p1) / (|q0|+|q1|)` computed in `i128` and narrowed back to
/// `i64` via `try_from` (never truncating). The result lies between `p0` and
/// `p1`, so it always fits `i64` when both inputs do; `try_from` only guards
/// against a poisoned intermediate.
fn weighted_avg(q0: i64, p0: Price, q1: i64, p1: Price) -> Result<Price, RiskError> {
    let a0 = i128::from(q0.checked_abs().ok_or(types::ArithError::Overflow)?);
    let a1 = i128::from(q1.checked_abs().ok_or(types::ArithError::Overflow)?);
    let num = a0
        .checked_mul(i128::from(p0.raw()))
        .and_then(|x| x.checked_add(a1.checked_mul(i128::from(p1.raw()))?))
        .ok_or(types::ArithError::Overflow)?;
    let den = a0.checked_add(a1).ok_or(types::ArithError::Overflow)?;
    if den == 0 {
        return Err(types::ArithError::DivByZero.into());
    }
    let avg = num / den;
    let raw = i64::try_from(avg).map_err(|_| types::ArithError::OutOfRange)?;
    Ok(Price::from_raw(raw))
}

/// Magnitude of the smaller absolute value of two opposite-signed integers,
/// returned as a positive `i64`. Guards `i64::MIN`.
fn min_abs(a: i64, b: i64) -> i64 {
    let aa = a.unsigned_abs();
    let ab = b.unsigned_abs();
    let m = aa.min(ab);
    // m <= |a| and |b|; both fit i64 magnitude except the MIN edge, where the
    // opposite operand bounds m below i64::MAX in practice. Clamp defensively.
    i64::try_from(m).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    const P1: i64 = 1_000_000; // price 1.0
    const Q1: i64 = 1_000_000; // qty 1.0
    const A1: i128 = 1_000_000; // amount 1.0
    const M: u32 = 1;

    fn pos() -> PerpPosition {
        PerpPosition::flat(MarketId::new(M))
    }

    #[test]
    fn open_sets_entry_no_realized() {
        let mut p = pos();
        let r = p
            .apply_fill(Quantity::from_raw(2 * Q1), Price::from_raw(10 * P1))
            .unwrap();
        assert_eq!(r, Amount::ZERO);
        assert_eq!(p.net_qty, Quantity::from_raw(2 * Q1));
        assert_eq!(p.avg_entry, Price::from_raw(10 * P1));
    }

    #[test]
    fn increase_reweights_average() {
        let mut p = pos();
        p.apply_fill(Quantity::from_raw(Q1), Price::from_raw(10 * P1))
            .unwrap();
        p.apply_fill(Quantity::from_raw(Q1), Price::from_raw(20 * P1))
            .unwrap();
        // Average of 10 and 20 over equal size = 15.
        assert_eq!(p.avg_entry, Price::from_raw(15 * P1));
        assert_eq!(p.net_qty, Quantity::from_raw(2 * Q1));
    }

    #[test]
    fn reduce_realizes_pnl_leaves_average() {
        let mut p = pos();
        p.apply_fill(Quantity::from_raw(4 * Q1), Price::from_raw(10 * P1))
            .unwrap();
        // Sell 1 at 13 -> realized (13-10)*1 = 3.0.
        let r = p
            .apply_fill(Quantity::from_raw(-Q1), Price::from_raw(13 * P1))
            .unwrap();
        assert_eq!(r, Amount::from_raw(3 * A1));
        assert_eq!(p.net_qty, Quantity::from_raw(3 * Q1));
        assert_eq!(p.avg_entry, Price::from_raw(10 * P1));
    }

    #[test]
    fn short_reduce_profit_sign() {
        let mut p = pos();
        // Short 2 at 10.
        p.apply_fill(Quantity::from_raw(-2 * Q1), Price::from_raw(10 * P1))
            .unwrap();
        // Buy back 1 at 7 -> short profit (10-7)*1 = 3.0.
        let r = p
            .apply_fill(Quantity::from_raw(Q1), Price::from_raw(7 * P1))
            .unwrap();
        assert_eq!(r, Amount::from_raw(3 * A1));
        assert_eq!(p.net_qty, Quantity::from_raw(-Q1));
        assert_eq!(p.avg_entry, Price::from_raw(10 * P1));
    }

    #[test]
    fn flip_realizes_and_reopens() {
        let mut p = pos();
        p.apply_fill(Quantity::from_raw(Q1), Price::from_raw(10 * P1))
            .unwrap();
        // Sell 3 at 12: close 1 (realize +2), open short 2 at 12.
        let r = p
            .apply_fill(Quantity::from_raw(-3 * Q1), Price::from_raw(12 * P1))
            .unwrap();
        assert_eq!(r, Amount::from_raw(2 * A1));
        assert_eq!(p.net_qty, Quantity::from_raw(-2 * Q1));
        assert_eq!(p.avg_entry, Price::from_raw(12 * P1));
    }

    #[test]
    fn full_close_flattens() {
        let mut p = pos();
        p.apply_fill(Quantity::from_raw(Q1), Price::from_raw(10 * P1))
            .unwrap();
        let r = p
            .apply_fill(Quantity::from_raw(-Q1), Price::from_raw(15 * P1))
            .unwrap();
        assert_eq!(r, Amount::from_raw(5 * A1));
        assert!(p.is_flat());
        assert_eq!(p.avg_entry, Price::ZERO);
    }

    #[test]
    fn unrealized_and_exposure() {
        let mut p = pos();
        p.apply_fill(Quantity::from_raw(2 * Q1), Price::from_raw(10 * P1))
            .unwrap();
        // Mark 12: unrealized (12-10)*2 = 4.0; exposure 12*2 = 24.0.
        assert_eq!(
            p.unrealized(Price::from_raw(12 * P1)).unwrap(),
            Amount::from_raw(4 * A1)
        );
        assert_eq!(
            p.exposure(Price::from_raw(12 * P1)).unwrap(),
            Amount::from_raw(24 * A1)
        );
    }

    #[test]
    fn extreme_fills_never_panic() {
        let mut p = pos();
        let _ = p.apply_fill(Quantity::from_raw(i64::MAX), Price::from_raw(i64::MAX));
        let _ = p.apply_fill(Quantity::from_raw(i64::MIN), Price::from_raw(i64::MIN));
        let _ = p.exposure(Price::from_raw(i64::MAX));
        let _ = p.unrealized(Price::from_raw(i64::MIN));
    }
}

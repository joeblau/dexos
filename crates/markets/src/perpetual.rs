//! Perpetual-market mechanics: deterministic mark price, signed funding
//! application, and realized-PnL settlement.
//!
//! All arithmetic is fixed-point and saturating/checked; no path panics or uses
//! floating point. Funding is *conservative*: the payment a long makes is the
//! payment a short receives, so a balanced book (`sum(signed_qty) == 0`) nets to
//! zero within rounding.

use orderbook::OrderBook;
use serde::{Deserialize, Serialize};
use types::{Amount, ArithError, MarketId, OracleHealth, Price, Quantity, Ratio};

use crate::error::PerpError;

/// A funding tick for one perpetual market.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundingUpdate {
    /// The market this update applies to.
    pub market_id: MarketId,
    /// The signed funding rate for the interval (positive = longs pay shorts).
    pub funding_rate: Ratio,
    /// The mark price at which the funding notional is measured.
    pub mark_price: Price,
}

impl FundingUpdate {
    /// Construct a funding update.
    #[must_use]
    pub fn new(market_id: MarketId, funding_rate: Ratio, mark_price: Price) -> Self {
        Self {
            market_id,
            funding_rate,
            mark_price,
        }
    }
}

/// The signed funding payment for a position: `mark * signed_qty * rate`,
/// rounded toward zero. Positive means the position *pays* this amount.
///
/// A long (`signed_qty > 0`) pays a positive amount when `rate > 0`; a short
/// (`signed_qty < 0`) yields a negative amount (i.e. receives funding).
///
/// # Errors
/// [`PerpError::Arith`] on overflow.
pub fn funding_payment(
    mark: Price,
    signed_qty: Quantity,
    rate: Ratio,
) -> Result<Amount, PerpError> {
    let notional = mark.notional(signed_qty)?;
    Ok(notional.mul_ratio(rate)?)
}

/// Apply funding to an account `balance` holding `signed_qty` at `mark`.
///
/// Returns the new balance: `balance - funding_payment`. Longs are debited and
/// shorts credited when the rate is positive, and vice-versa.
///
/// # Errors
/// [`PerpError::Arith`] on overflow.
pub fn apply_funding(
    balance: Amount,
    mark: Price,
    signed_qty: Quantity,
    rate: Ratio,
) -> Result<Amount, PerpError> {
    let pay = funding_payment(mark, signed_qty, rate)?;
    Ok(balance.checked_sub(pay)?)
}

/// Realized PnL of closing `signed_qty` opened at `entry` against `exit`:
/// `(exit - entry) * signed_qty`, rounded toward zero.
///
/// # Errors
/// [`PerpError::Arith`] on overflow.
pub fn realized_pnl(entry: Price, exit: Price, signed_qty: Quantity) -> Result<Amount, PerpError> {
    let delta = exit.checked_sub(entry)?;
    Ok(delta.notional(signed_qty)?)
}

/// The mid price of a book, if it has both a best bid and a best ask.
///
/// Computed in `i128` and narrowed with a checked conversion so it never
/// truncates.
#[must_use]
pub fn book_mid(book: &OrderBook) -> Option<Price> {
    match (book.best_bid(), book.best_ask()) {
        (Some(bid), Some(ask)) => {
            let sum = i128::from(bid.raw()) + i128::from(ask.raw());
            i64::try_from(sum / 2).ok().map(Price::from_raw)
        }
        _ => None,
    }
}

/// Derive a deterministic mark price from the oracle index, an optional book
/// mid, and oracle health.
///
/// * `Normal`: average of index and book mid when a mid exists, else the index.
/// * `Degraded` / `Stale`: the index alone (ignore a possibly-toxic book).
/// * `Halted`: no mark is produced.
///
/// The output is a pure function of its inputs, giving a bit-stable scalar
/// reference.
///
/// # Errors
/// [`PerpError::OracleHalted`] when `health` is `Halted`; [`PerpError::Arith`]
/// on overflow.
pub fn derive_mark(
    index: Price,
    mid: Option<Price>,
    health: OracleHealth,
) -> Result<Price, PerpError> {
    match health {
        OracleHealth::Halted => Err(PerpError::OracleHalted),
        OracleHealth::Normal => match mid {
            Some(m) => {
                let sum = i128::from(index.raw()) + i128::from(m.raw());
                let raw = i64::try_from(sum / 2).map_err(|_| ArithError::OutOfRange)?;
                Ok(Price::from_raw(raw))
            }
            None => Ok(index),
        },
        OracleHealth::Degraded | OracleHealth::Stale => Ok(index),
    }
}

/// Minimal perpetual-market state carried by the registry: the last mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PerpMarketState {
    /// The most recently derived mark price (`ZERO` until first set).
    pub mark_price: Price,
    /// The most recently applied funding rate.
    pub last_funding_rate: Ratio,
}

impl PerpMarketState {
    /// Update the mark from an index/book/health observation.
    ///
    /// # Errors
    /// As [`derive_mark`].
    pub fn update_mark(
        &mut self,
        index: Price,
        mid: Option<Price>,
        health: OracleHealth,
    ) -> Result<Price, PerpError> {
        let mark = derive_mark(index, mid, health)?;
        self.mark_price = mark;
        Ok(mark)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orderbook::{BookConfig, NewOrder};
    use types::{OrderId, OrderType, Side, TimeInForce};

    const P1: i64 = 1_000_000; // 1.0 price
    const Q1: i64 = 1_000_000; // 1.0 qty

    #[test]
    fn funding_sign_and_magnitude() {
        let mark = Price::from_raw(100 * P1); // 100.0
        let rate = Ratio::from_bps(100).unwrap(); // 1%
                                                  // Long 2 units: notional 200, funding 1% = 2.0 paid (positive).
        let long = funding_payment(mark, Quantity::from_raw(2 * Q1), rate).unwrap();
        assert_eq!(long, Amount::from_raw(2_000_000));
        // Short 2 units: receives (negative payment).
        let short = funding_payment(mark, Quantity::from_raw(-2 * Q1), rate).unwrap();
        assert_eq!(short, Amount::from_raw(-2_000_000));
        // Applying to balances: long debited, short credited.
        let long_bal = apply_funding(
            Amount::from_raw(10_000_000),
            mark,
            Quantity::from_raw(2 * Q1),
            rate,
        )
        .unwrap();
        assert_eq!(long_bal, Amount::from_raw(8_000_000));
        let short_bal = apply_funding(
            Amount::from_raw(10_000_000),
            mark,
            Quantity::from_raw(-2 * Q1),
            rate,
        )
        .unwrap();
        assert_eq!(short_bal, Amount::from_raw(12_000_000));
    }

    #[test]
    fn funding_conserves_on_balanced_book() {
        let mark = Price::from_raw(50 * P1);
        let rate = Ratio::from_bps(37).unwrap();
        // Three longs +1,+2,+3 and matching shorts -2,-4.
        let longs: [i64; 3] = [1, 2, 3];
        let shorts: [i64; 2] = [-2, -4];
        let mut net = Amount::ZERO;
        for q in longs {
            net = net
                .checked_add(funding_payment(mark, Quantity::from_raw(q * Q1), rate).unwrap())
                .unwrap();
        }
        for q in shorts {
            net = net
                .checked_add(funding_payment(mark, Quantity::from_raw(q * Q1), rate).unwrap())
                .unwrap();
        }
        // sum(qty) = 6 - 6 = 0 so total funding nets to exactly zero.
        assert_eq!(net, Amount::ZERO);
    }

    #[test]
    fn realized_pnl_directions() {
        // Long 1 from 100 to 110 -> +10.
        assert_eq!(
            realized_pnl(
                Price::from_raw(100 * P1),
                Price::from_raw(110 * P1),
                Quantity::from_raw(Q1)
            )
            .unwrap(),
            Amount::from_raw(10_000_000)
        );
        // Short 1 from 100 to 110 -> -10.
        assert_eq!(
            realized_pnl(
                Price::from_raw(100 * P1),
                Price::from_raw(110 * P1),
                Quantity::from_raw(-Q1)
            )
            .unwrap(),
            Amount::from_raw(-10_000_000)
        );
    }

    #[test]
    fn mark_price_health_transitions() {
        let index = Price::from_raw(100 * P1);
        let mid = Some(Price::from_raw(102 * P1));
        // Normal with a mid -> average 101.
        assert_eq!(
            derive_mark(index, mid, OracleHealth::Normal).unwrap(),
            Price::from_raw(101 * P1)
        );
        // Normal without a mid -> index.
        assert_eq!(
            derive_mark(index, None, OracleHealth::Normal).unwrap(),
            index
        );
        // Degraded / Stale -> index regardless of mid.
        assert_eq!(
            derive_mark(index, mid, OracleHealth::Degraded).unwrap(),
            index
        );
        assert_eq!(derive_mark(index, mid, OracleHealth::Stale).unwrap(), index);
        // Halted -> error, no panic.
        assert_eq!(
            derive_mark(index, mid, OracleHealth::Halted).unwrap_err(),
            PerpError::OracleHalted
        );
    }

    #[test]
    fn book_mid_from_orderbook() {
        let mut book = OrderBook::new(BookConfig::default());
        assert_eq!(book_mid(&book), None);
        book.submit(NewOrder {
            order_id: OrderId::new(1),
            account: types::AccountId::new(1),
            side: Side::Bid,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price::from_raw(99 * P1),
            quantity: Quantity::from_raw(Q1),
            client_id: 0,
            reduce_only: false,
        })
        .unwrap();
        book.submit(NewOrder {
            order_id: OrderId::new(2),
            account: types::AccountId::new(2),
            side: Side::Ask,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price::from_raw(101 * P1),
            quantity: Quantity::from_raw(Q1),
            client_id: 0,
            reduce_only: false,
        })
        .unwrap();
        assert_eq!(book_mid(&book), Some(Price::from_raw(100 * P1)));
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
        fn small_i64(&mut self) -> i64 {
            i64::try_from(self.next_u64() % 2_000_000).unwrap() - 1_000_000
        }
    }

    #[test]
    fn property_funding_never_panics_and_nets_to_zero_when_balanced() {
        let mut r = Lcg(0xFEED_BEEF);
        for _ in 0..10_000 {
            let mark = Price::from_raw(r.small_i64());
            let rate = Ratio::from_raw(r.small_i64());
            let q = Quantity::from_raw(r.small_i64());
            // opposite positions cancel by construction.
            let a = funding_payment(mark, q, rate);
            let b = funding_payment(mark, Quantity::from_raw(-q.raw()), rate);
            if let (Ok(a), Ok(b)) = (a, b) {
                // a + b should be 0 when both computed (rounding is symmetric
                // toward zero for exact negation).
                assert_eq!(a.checked_add(b).unwrap(), Amount::ZERO);
            }
        }
    }

    #[test]
    fn never_panics_decoding_arbitrary_funding_bytes() {
        let mut r = Lcg(0x0BAD_F00D);
        for _ in 0..20_000 {
            let len = usize::try_from(r.next_u64() % 40).unwrap();
            let bytes: Vec<u8> = (0..len)
                .map(|_| u8::try_from(r.next_u64() % 256).unwrap())
                .collect();
            let _ = postcard::from_bytes::<FundingUpdate>(&bytes);
            let _ = postcard::from_bytes::<PerpMarketState>(&bytes);
        }
    }
}

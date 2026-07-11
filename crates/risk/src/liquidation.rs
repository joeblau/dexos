//! Liquidation queue, insurance fund, and socialized-loss fallback.
//!
//! When an account is liquidated its positions are closed at mark and its final
//! equity computed. A non-negative result is solvent. A negative result is a
//! shortfall, covered in strict priority order:
//!
//! 1. the account's own remaining collateral (already reflected in equity),
//! 2. the **insurance fund**,
//! 3. **socialized loss** — the explicit final fallback, drawn only after the
//!    insurance fund is exhausted.
//!
//! Total system value (collateral + insurance fund - socialized loss) is
//! conserved to the unit across this process.

use types::{AccountId, Amount};

use crate::error::RiskError;
use crate::math::min_amount;

/// A pooled insurance fund that absorbs liquidation shortfalls before any loss
/// is socialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InsuranceFund {
    balance: Amount,
}

impl InsuranceFund {
    /// A fund seeded with `initial` collateral.
    #[inline]
    pub fn new(initial: Amount) -> Self {
        Self { balance: initial }
    }

    /// Current balance.
    #[inline]
    pub fn balance(&self) -> Amount {
        self.balance
    }

    /// Add collateral to the fund (e.g. liquidation fees or top-ups).
    #[inline]
    pub fn deposit(&mut self, amount: Amount) -> Result<(), RiskError> {
        self.balance = self.balance.checked_add(amount)?;
        Ok(())
    }

    /// Draw up to `shortfall` from the fund. Returns `(drawn, remaining_uncovered)`
    /// where `drawn + remaining_uncovered == shortfall`. `remaining_uncovered`
    /// is the amount that must be socialized.
    pub fn cover(&mut self, shortfall: Amount) -> Result<(Amount, Amount), RiskError> {
        if shortfall.is_negative() {
            return Err(RiskError::NegativeAmount);
        }
        let drawn = min_amount(self.balance, shortfall);
        self.balance = self.balance.checked_sub(drawn)?;
        let uncovered = shortfall.checked_sub(drawn)?;
        Ok((drawn, uncovered))
    }
}

/// The disposition of a single liquidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiquidationOutcome {
    /// The account that was liquidated.
    pub account: AccountId,
    /// Final equity at liquidation (negative implies a shortfall).
    pub final_equity: Amount,
    /// Amount drawn from the insurance fund to cover a shortfall.
    pub insurance_drawn: Amount,
    /// Amount that had to be socialized after the fund was exhausted.
    pub socialized_loss: Amount,
    /// Collateral returned to a solvent liquidated account.
    pub returned_collateral: Amount,
}

impl LiquidationOutcome {
    /// True if any loss had to be socialized.
    #[inline]
    pub fn had_socialized_loss(&self) -> bool {
        self.socialized_loss.raw() > 0
    }
}

/// A FIFO liquidation queue. Distressed accounts are enqueued once and drained
/// in insertion order by the engine.
#[derive(Debug, Clone, Default)]
pub struct LiquidationQueue {
    queue: Vec<AccountId>,
}

impl LiquidationQueue {
    /// An empty queue.
    #[inline]
    pub fn new() -> Self {
        Self { queue: Vec::new() }
    }

    /// Enqueue an account if it is not already queued (idempotent).
    pub fn enqueue(&mut self, account: AccountId) {
        if !self.queue.contains(&account) {
            self.queue.push(account);
        }
    }

    /// Pop the next account to liquidate (FIFO).
    pub fn pop(&mut self) -> Option<AccountId> {
        if self.queue.is_empty() {
            None
        } else {
            Some(self.queue.remove(0))
        }
    }

    /// Number of queued accounts.
    #[inline]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// True if nothing is queued.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// A snapshot of the queued accounts in order.
    #[inline]
    pub fn as_slice(&self) -> &[AccountId] {
        &self.queue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A1: i128 = 1_000_000;

    #[test]
    fn fund_covers_within_balance() {
        let mut f = InsuranceFund::new(Amount::from_raw(10 * A1));
        let (drawn, uncovered) = f.cover(Amount::from_raw(4 * A1)).unwrap();
        assert_eq!(drawn, Amount::from_raw(4 * A1));
        assert_eq!(uncovered, Amount::ZERO);
        assert_eq!(f.balance(), Amount::from_raw(6 * A1));
    }

    #[test]
    fn fund_exhausts_then_socializes() {
        let mut f = InsuranceFund::new(Amount::from_raw(3 * A1));
        let (drawn, uncovered) = f.cover(Amount::from_raw(5 * A1)).unwrap();
        assert_eq!(drawn, Amount::from_raw(3 * A1));
        assert_eq!(uncovered, Amount::from_raw(2 * A1));
        assert_eq!(f.balance(), Amount::ZERO);
    }

    #[test]
    fn cover_rejects_negative() {
        let mut f = InsuranceFund::new(Amount::from_raw(A1));
        assert_eq!(
            f.cover(Amount::from_raw(-1)),
            Err(RiskError::NegativeAmount)
        );
    }

    #[test]
    fn queue_is_fifo_and_dedups() {
        let mut q = LiquidationQueue::new();
        q.enqueue(AccountId::new(1));
        q.enqueue(AccountId::new(2));
        q.enqueue(AccountId::new(1)); // dup ignored
        assert_eq!(q.len(), 2);
        assert_eq!(q.pop(), Some(AccountId::new(1)));
        assert_eq!(q.pop(), Some(AccountId::new(2)));
        assert_eq!(q.pop(), None);
    }
}

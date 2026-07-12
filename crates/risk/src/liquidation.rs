//! Liquidation queue, insurance fund, socialized-loss fallback, and the
//! auto-deleverage (ADL) transfer record.
//!
//! When an account is liquidated the pipeline runs, in strict order:
//!
//! 1. **auto-deleverage** — the account's open perp positions are closed at the
//!    mark, transferring the opposite exposure to solvent counterparties ranked
//!    deterministically (most-profitable first, ties broken by account index).
//!    Closing at the mark is value-neutral, so ADL never moves system value.
//! 2. the account's own remaining collateral absorbs the loss first (it is
//!    already reflected in the post-ADL equity),
//! 3. the **insurance fund** covers any shortfall,
//! 4. **socialized loss** — the explicit final fallback, a pro-rata haircut of
//!    solvent accounts' collateral, drawn only after the insurance fund is
//!    exhausted.
//!
//! Total system value (Σ open equity + insurance fund) is conserved to the unit
//! across the whole pipeline: the bankrupt account's negative equity is exactly
//! matched by the insurance draw plus the solvent-collateral haircut.

use std::collections::{HashSet, VecDeque};

use types::{AccountId, Amount, MarketId, Price, Quantity};

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

/// One auto-deleverage transfer: a counterparty position reduced at the mark to
/// absorb part of the liquidated account's opposite exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdlFill {
    /// The solvent account whose position was reduced.
    pub counterparty: AccountId,
    /// The market the transfer occurred in.
    pub market: MarketId,
    /// Absolute quantity transferred (always positive).
    pub quantity: Quantity,
    /// The mark price the transfer executed at.
    pub price: Price,
}

/// The disposition of a single liquidation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiquidationOutcome {
    /// The account that was liquidated.
    pub account: AccountId,
    /// Final equity after auto-deleverage (negative implies a shortfall).
    pub final_equity: Amount,
    /// Amount drawn from the insurance fund to cover a shortfall.
    pub insurance_drawn: Amount,
    /// Shortfall left uncovered after the insurance fund was exhausted (the
    /// amount that had to be socialized).
    pub socialized_loss: Amount,
    /// Portion of `socialized_loss` actually charged to solvent accounts. Equals
    /// `socialized_loss` whenever solvent collateral was sufficient; a smaller
    /// value indicates residual bad debt no solvent account could absorb.
    pub socialized_charged: Amount,
    /// Collateral returned to a solvent liquidated account.
    pub returned_collateral: Amount,
    /// The auto-deleverage transfers, in deterministic ranking order.
    pub adl_fills: Vec<AdlFill>,
    /// Per-account socialization debits, in ascending account order.
    pub haircuts: Vec<(AccountId, Amount)>,
}

impl LiquidationOutcome {
    /// True if any loss had to be socialized.
    #[inline]
    pub fn had_socialized_loss(&self) -> bool {
        self.socialized_loss.raw() > 0
    }
}

/// A FIFO liquidation queue with O(1) membership and pop-front.
///
/// Distressed accounts are enqueued once (deduplicated through the membership
/// set) and drained in insertion order by the engine. Backed by a [`VecDeque`]
/// for O(1) `pop`-front and a [`HashSet`] for O(1) `contains`.
#[derive(Debug, Clone, Default)]
pub struct LiquidationQueue {
    queue: VecDeque<AccountId>,
    present: HashSet<AccountId>,
}

impl LiquidationQueue {
    /// An empty queue.
    #[inline]
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            present: HashSet::new(),
        }
    }

    /// Enqueue an account if it is not already queued (idempotent, O(1)).
    pub fn enqueue(&mut self, account: AccountId) {
        if self.present.insert(account) {
            self.queue.push_back(account);
        }
    }

    /// Pop the next account to liquidate (FIFO, O(1)).
    pub fn pop(&mut self) -> Option<AccountId> {
        let account = self.queue.pop_front()?;
        self.present.remove(&account);
        Some(account)
    }

    /// Remove a specific account from the queue if present, returning whether it
    /// was queued. Used to drop an account once it has been liquidated.
    pub fn remove(&mut self, account: AccountId) -> bool {
        if self.present.remove(&account) {
            if let Some(pos) = self.queue.iter().position(|&a| a == account) {
                self.queue.remove(pos);
            }
            true
        } else {
            false
        }
    }

    /// True if `account` is currently queued (O(1)).
    #[inline]
    pub fn contains(&self, account: AccountId) -> bool {
        self.present.contains(&account)
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
        assert!(q.contains(AccountId::new(1)));
        assert_eq!(q.pop(), Some(AccountId::new(1)));
        assert!(!q.contains(AccountId::new(1)));
        assert_eq!(q.pop(), Some(AccountId::new(2)));
        assert_eq!(q.pop(), None);
    }

    #[test]
    fn queue_remove_targets_specific_account() {
        let mut q = LiquidationQueue::new();
        q.enqueue(AccountId::new(1));
        q.enqueue(AccountId::new(2));
        q.enqueue(AccountId::new(3));
        // Remove the middle account; the rest keep FIFO order and re-enqueue is
        // allowed after removal.
        assert!(q.remove(AccountId::new(2)));
        assert!(!q.remove(AccountId::new(2))); // idempotent
        assert!(!q.contains(AccountId::new(2)));
        assert_eq!(q.len(), 2);
        q.enqueue(AccountId::new(2)); // goes to the back
        assert_eq!(q.pop(), Some(AccountId::new(1)));
        assert_eq!(q.pop(), Some(AccountId::new(3)));
        assert_eq!(q.pop(), Some(AccountId::new(2)));
        assert_eq!(q.pop(), None);
    }
}

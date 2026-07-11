//! Complete-set collateral ledger and settlement math.
//!
//! Minting a complete set locks `amount` of collateral and issues `amount` of a
//! YES claim for *every* outcome. Redeeming burns one claim of every outcome to
//! unlock collateral. The core invariant, maintained by construction:
//!
//! > for each outcome `i`, `sum over holders of holding[i] == locked collateral`.
//!
//! Settlement uses that invariant to distribute the locked collateral exactly:
//! a fraction vector summing to 1.0 credits each holder `sum_i holding_i * f_i`,
//! and the sub-micro-unit floor remainders are redistributed by largest remainder
//! so the credited total equals the locked collateral to the micro-unit.

use std::collections::BTreeMap;

use types::{AccountId, Amount, Ratio, RATIO_SCALE};

use crate::outcome::OutcomeSet;
use crate::settlement::{Resolution, SettlementError};

/// Complete-set mint/redeem failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CompleteSetError {
    /// A non-positive amount was minted or redeemed.
    #[error("mint/redeem amount must be positive")]
    NonPositiveAmount,
    /// The holder does not hold one claim of every outcome at the redeem amount.
    #[error("redeem requires one claim of every outcome; no partial unlock")]
    InsufficientClaims,
    /// A fixed-point operation overflowed.
    #[error("complete-set arithmetic overflow")]
    Overflow,
}

/// A ledger of outstanding YES claims per outcome per holder, plus the locked
/// collateral backing them. Positions are indexed by outcome *position*
/// (`0..outcomes.len()`), matching the settlement fraction vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimBook {
    n: usize,
    holdings: BTreeMap<AccountId, Vec<Amount>>,
    locked: Amount,
}

impl ClaimBook {
    /// An empty book over an `n`-outcome market.
    pub fn new(outcomes: &OutcomeSet) -> Self {
        Self {
            n: outcomes.len(),
            holdings: BTreeMap::new(),
            locked: Amount::ZERO,
        }
    }

    /// The number of outcomes.
    #[inline]
    pub fn outcome_count(&self) -> usize {
        self.n
    }

    /// The total locked collateral.
    #[inline]
    pub fn locked_collateral(&self) -> Amount {
        self.locked
    }

    /// A holder's YES-claim balance for outcome position `i` (zero if none).
    pub fn balance(&self, holder: AccountId, i: usize) -> Amount {
        self.holdings
            .get(&holder)
            .and_then(|v| v.get(i))
            .copied()
            .unwrap_or(Amount::ZERO)
    }

    /// Total outstanding YES claims of outcome position `i` across all holders.
    /// Equals the locked collateral by the complete-set invariant.
    pub fn outstanding(&self, i: usize) -> Amount {
        let mut total = Amount::ZERO;
        for v in self.holdings.values() {
            if let Some(a) = v.get(i) {
                total = total.saturating_add(*a);
            }
        }
        total
    }

    /// Mint a complete set: lock `amount` collateral and issue `amount` of every
    /// outcome's YES claim to `holder`.
    pub fn mint(&mut self, holder: AccountId, amount: Amount) -> Result<(), CompleteSetError> {
        if amount.raw() <= 0 {
            return Err(CompleteSetError::NonPositiveAmount);
        }
        let new_locked = self
            .locked
            .checked_add(amount)
            .map_err(|_| CompleteSetError::Overflow)?;
        let n = self.n;
        let entry = self
            .holdings
            .entry(holder)
            .or_insert_with(|| vec![Amount::ZERO; n]);
        // Pre-check every slot so a failure leaves the ledger unchanged.
        let mut next = Vec::with_capacity(self.n);
        for slot in entry.iter() {
            next.push(
                slot.checked_add(amount)
                    .map_err(|_| CompleteSetError::Overflow)?,
            );
        }
        *entry = next;
        self.locked = new_locked;
        Ok(())
    }

    /// Redeem a complete set: burn `amount` of *every* outcome's YES claim from
    /// `holder` and unlock `amount` collateral. Errors (with no state change) if
    /// the holder lacks one claim of any outcome — there is no partial unlock.
    pub fn redeem(&mut self, holder: AccountId, amount: Amount) -> Result<(), CompleteSetError> {
        if amount.raw() <= 0 {
            return Err(CompleteSetError::NonPositiveAmount);
        }
        let entry = self
            .holdings
            .get(&holder)
            .ok_or(CompleteSetError::InsufficientClaims)?;
        for slot in entry {
            if slot.raw() < amount.raw() {
                return Err(CompleteSetError::InsufficientClaims);
            }
        }
        let new_locked = self
            .locked
            .checked_sub(amount)
            .map_err(|_| CompleteSetError::Overflow)?;
        // Safe to mutate now: every slot has been verified >= amount.
        let entry = self
            .holdings
            .get_mut(&holder)
            .ok_or(CompleteSetError::InsufficientClaims)?;
        for slot in entry.iter_mut() {
            *slot = slot
                .checked_sub(amount)
                .map_err(|_| CompleteSetError::Overflow)?;
        }
        self.locked = new_locked;
        Ok(())
    }

    /// Transfer `amount` of outcome position `i`'s YES claim from `from` to `to`.
    ///
    /// This models secondary trading of individual claims. It moves claims within
    /// a single outcome, so per-outcome outstanding totals — and thus the
    /// complete-set invariant — are preserved. Errors (with no state change) if
    /// `from` lacks the balance or `i` is out of range.
    pub fn transfer(
        &mut self,
        from: AccountId,
        to: AccountId,
        i: usize,
        amount: Amount,
    ) -> Result<(), CompleteSetError> {
        if amount.raw() <= 0 {
            return Err(CompleteSetError::NonPositiveAmount);
        }
        if i >= self.n {
            return Err(CompleteSetError::InsufficientClaims);
        }
        let from_bal = self.balance(from, i);
        if from_bal.raw() < amount.raw() {
            return Err(CompleteSetError::InsufficientClaims);
        }
        // A self-transfer is a validated no-op. Writing `from` and `to` slots
        // separately when they alias the same account would let the second write
        // clobber the first, destroying `amount` claims and breaking the
        // complete-set invariant.
        if from == to {
            return Ok(());
        }
        let to_bal = self.balance(to, i);
        let new_to = to_bal
            .checked_add(amount)
            .map_err(|_| CompleteSetError::Overflow)?;
        let new_from = from_bal
            .checked_sub(amount)
            .map_err(|_| CompleteSetError::Overflow)?;
        // Both slots validated; commit.
        let n = self.n;
        self.holdings
            .entry(to)
            .or_insert_with(|| vec![Amount::ZERO; n])[i] = new_to;
        self.holdings
            .entry(from)
            .or_insert_with(|| vec![Amount::ZERO; n])[i] = new_from;
        Ok(())
    }

    /// Settle every holder against a normalized fraction vector (raw sum must be
    /// `RATIO_SCALE`). Returns a value-conserving [`Settlement`].
    pub fn settle_fractions(&self, normalized: &[Ratio]) -> Result<Settlement, SettlementError> {
        if normalized.len() != self.n {
            return Err(SettlementError::Dimension);
        }
        let mut sum: i128 = 0;
        for f in normalized {
            if f.raw() < 0 {
                return Err(SettlementError::NegativeFraction);
            }
            sum = sum
                .checked_add(i128::from(f.raw()))
                .ok_or(SettlementError::Overflow)?;
        }
        if sum != i128::from(RATIO_SCALE) {
            // Only fully-normalized vectors conserve collateral exactly.
            return Err(SettlementError::NotConserved);
        }
        let scale = i128::from(RATIO_SCALE);

        // (holder, floor credit, fractional remainder in [0, RATIO_SCALE)).
        let mut rows: Vec<(AccountId, i128, i128)> = Vec::with_capacity(self.holdings.len());
        let mut total_floor: i128 = 0;
        for (acct, holdings) in &self.holdings {
            let mut numer: i128 = 0;
            for (i, h) in holdings.iter().enumerate() {
                let f = i128::from(normalized[i].raw());
                let term = h.raw().checked_mul(f).ok_or(SettlementError::Overflow)?;
                numer = numer.checked_add(term).ok_or(SettlementError::Overflow)?;
            }
            let floor = numer.div_euclid(scale);
            let rem = numer.rem_euclid(scale);
            total_floor = total_floor
                .checked_add(floor)
                .ok_or(SettlementError::Overflow)?;
            rows.push((*acct, floor, rem));
        }

        // The invariant makes the ideal total exactly the locked collateral, so
        // the leftover is a small non-negative count of micro-units.
        let leftover = self
            .locked
            .raw()
            .checked_sub(total_floor)
            .ok_or(SettlementError::Overflow)?;
        if leftover < 0 {
            return Err(SettlementError::NotConserved);
        }
        let leftover_usize =
            usize::try_from(leftover).map_err(|_| SettlementError::NotConserved)?;
        if leftover_usize > rows.len() {
            // More leftover than holders can only mean a broken invariant.
            return Err(SettlementError::NotConserved);
        }

        // Largest-remainder allocation: sort by remainder desc, then holder asc.
        let mut order: Vec<usize> = (0..rows.len()).collect();
        order.sort_by(|&a, &b| {
            rows[b]
                .2
                .cmp(&rows[a].2)
                .then_with(|| rows[a].0.get().cmp(&rows[b].0.get()))
        });
        for &row_idx in order.iter().take(leftover_usize) {
            rows[row_idx].1 += 1;
        }

        let mut credits: BTreeMap<AccountId, Amount> = BTreeMap::new();
        let mut total_credited: i128 = 0;
        for (acct, credit, _) in rows {
            total_credited = total_credited
                .checked_add(credit)
                .ok_or(SettlementError::Overflow)?;
            credits.insert(acct, Amount::from_raw(credit));
        }

        Ok(Settlement {
            credits,
            total_credited: Amount::from_raw(total_credited),
            locked: self.locked,
        })
    }

    /// Settle against a [`Resolution`], mapping it through `outcomes`.
    pub fn settle(
        &self,
        outcomes: &OutcomeSet,
        resolution: &Resolution,
    ) -> Result<Settlement, SettlementError> {
        let fractions = resolution.to_fractions(outcomes)?;
        self.settle_fractions(&fractions)
    }
}

/// The result of settling a [`ClaimBook`]: per-holder credits plus conservation
/// totals. `total_credited == locked` for any well-formed book.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    credits: BTreeMap<AccountId, Amount>,
    total_credited: Amount,
    locked: Amount,
}

impl Settlement {
    /// Per-holder credit map (deterministic order).
    #[inline]
    pub fn credits(&self) -> &BTreeMap<AccountId, Amount> {
        &self.credits
    }

    /// A single holder's credit (zero if absent).
    pub fn credit_of(&self, holder: AccountId) -> Amount {
        self.credits.get(&holder).copied().unwrap_or(Amount::ZERO)
    }

    /// The sum of all credits.
    #[inline]
    pub fn total_credited(&self) -> Amount {
        self.total_credited
    }

    /// The collateral that was locked at settlement time.
    #[inline]
    pub fn locked(&self) -> Amount {
        self.locked
    }

    /// Whether the settlement conserved collateral exactly.
    #[inline]
    pub fn is_conserved(&self) -> bool {
        self.total_credited == self.locked
    }
}

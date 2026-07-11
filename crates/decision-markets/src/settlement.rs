//! Settlement records for a resolved (or voided) decision market.

use std::collections::BTreeMap;

use types::{AccountId, Amount};

use crate::instrument::ActionId;

/// The computed payout of every `(action, account)` position after settlement.
///
/// Total collateral in is conserved: [`Settlement::total_paid`] equals the sum
/// of collateral held across all contingent markets, with zero rounding leakage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    payouts: BTreeMap<(ActionId, AccountId), Amount>,
    total_paid: Amount,
}

impl Settlement {
    pub(crate) fn new(
        payouts: BTreeMap<(ActionId, AccountId), Amount>,
        total_paid: Amount,
    ) -> Self {
        Self {
            payouts,
            total_paid,
        }
    }

    /// The payout for a single position (zero if absent).
    #[inline]
    pub fn payout(&self, action: ActionId, account: AccountId) -> Amount {
        self.payouts
            .get(&(action, account))
            .copied()
            .unwrap_or(Amount::ZERO)
    }

    /// Total collateral distributed by this settlement.
    #[inline]
    pub fn total_paid(&self) -> Amount {
        self.total_paid
    }

    /// Iterate over every `(action, account) -> payout` entry in deterministic
    /// (sorted) order.
    pub fn entries(&self) -> impl Iterator<Item = (&(ActionId, AccountId), &Amount)> {
        self.payouts.iter()
    }

    /// The number of payout entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.payouts.len()
    }

    /// Whether there are no payout entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.payouts.is_empty()
    }
}

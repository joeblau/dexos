//! Per-market configuration blocks embedded in a [`crate::MarketDefinition`].
//!
//! The **price oracle** ([`OracleConfig`]) and the **resolution oracle**
//! ([`ResolverConfig`]) are deliberately distinct types with no shared fields,
//! keeping the two trust domains conceptually and structurally separate.

use serde::{Deserialize, Serialize};
use types::{Amount, Ratio};

use crate::error::PayoutError;

/// Maximum basis points (100%).
pub const MAX_BPS: u16 = 10_000;

/// Trading-fee schedule in basis points.
///
/// Fees are charged on notional. The `protocol_bps` slice is the protocol's cut
/// of the accrued fee pool; the remainder is distributed to sponsors by their
/// [`crate::SponsorShare::revenue_share_bps`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSchedule {
    /// Maker fee, basis points of notional.
    pub maker_bps: u16,
    /// Taker fee, basis points of notional.
    pub taker_bps: u16,
    /// Protocol's cut of accrued fees, basis points (0..=10_000).
    pub protocol_bps: u16,
}

impl FeeSchedule {
    /// Construct, returning `None` if any field exceeds [`MAX_BPS`].
    #[must_use]
    pub fn new(maker_bps: u16, taker_bps: u16, protocol_bps: u16) -> Option<Self> {
        if maker_bps > MAX_BPS || taker_bps > MAX_BPS || protocol_bps > MAX_BPS {
            return None;
        }
        Some(Self {
            maker_bps,
            taker_bps,
            protocol_bps,
        })
    }

    /// The fee charged on `notional` for a taker (or maker) fill.
    ///
    /// Rounds toward zero (inherited from [`Amount::mul_ratio`]). Negative
    /// notionals are treated by magnitude by the caller; this multiplies the
    /// supplied `notional` directly.
    ///
    /// # Errors
    /// [`PayoutError::Arith`] on fixed-point overflow.
    pub fn accrue(&self, notional: Amount, taker: bool) -> Result<Amount, PayoutError> {
        let bps = if taker {
            self.taker_bps
        } else {
            self.maker_bps
        };
        let ratio = Ratio::from_bps(i64::from(bps))?;
        Ok(notional.mul_ratio(ratio)?)
    }

    /// The protocol's cut of an already-accrued `fee` pool. Rounds toward zero.
    ///
    /// # Errors
    /// [`PayoutError::Arith`] on fixed-point overflow.
    pub fn protocol_cut(&self, fee: Amount) -> Result<Amount, PayoutError> {
        let ratio = Ratio::from_bps(i64::from(self.protocol_bps))?;
        Ok(fee.mul_ratio(ratio)?)
    }
}

/// Price-oracle configuration (index price feed). Distinct from the resolution
/// oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleConfig {
    /// Opaque identifier of the index price source.
    pub index_source: u32,
    /// Maximum staleness, in sequence ticks, before the feed is `Stale`.
    pub max_staleness: u64,
    /// Deviation tolerance (ratio) between book mid and index before clamping.
    pub deviation_bound: Ratio,
}

impl OracleConfig {
    /// A permissive default price-oracle config.
    #[must_use]
    pub fn new(index_source: u32, max_staleness: u64, deviation_bound: Ratio) -> Self {
        Self {
            index_source,
            max_staleness,
            deviation_bound,
        }
    }
}

/// Resolution-oracle configuration: the committee threshold and challenge
/// window. The actual committee keys live in
/// [`crate::resolution::ResolutionRule`], which is referenced by `rules_hash`
/// so the definition stays copyable and hashable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolverConfig {
    /// Number of resolvers in the committee.
    pub committee_size: u16,
    /// Weight threshold required to certify an outcome.
    pub threshold: u64,
    /// Challenge window length, in sequence ticks.
    pub challenge_window: u64,
    /// Bond a challenger must post, refunded on a successful challenge.
    pub challenge_bond: Amount,
}

impl ResolverConfig {
    /// Construct a resolver config.
    #[must_use]
    pub fn new(
        committee_size: u16,
        threshold: u64,
        challenge_window: u64,
        challenge_bond: Amount,
    ) -> Self {
        Self {
            committee_size,
            threshold,
            challenge_window,
            challenge_bond,
        }
    }
}

/// Lifecycle-automation configuration: thresholds that drive the
/// `Bootstrapping -> Open` and `Open -> Closed` transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleConfig {
    /// Bootstrapped collateral required before the market may open.
    pub bootstrap_liquidity_threshold: Amount,
    /// Sequence tick at which trading closes (`Open -> Closed`).
    pub trading_close_seq: u64,
}

impl LifecycleConfig {
    /// Construct a lifecycle config.
    #[must_use]
    pub fn new(bootstrap_liquidity_threshold: Amount, trading_close_seq: u64) -> Self {
        Self {
            bootstrap_liquidity_threshold,
            trading_close_seq,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_schedule_bounds_and_accrual() {
        assert!(FeeSchedule::new(10_001, 0, 0).is_none());
        let fs = FeeSchedule::new(10, 20, 3_000).unwrap();
        // 20 bps of 1_000.0 notional = 2.0.
        let notional = Amount::from_raw(1_000_000_000);
        assert_eq!(
            fs.accrue(notional, true).unwrap(),
            Amount::from_raw(2_000_000)
        );
        // 10 bps maker = 1.0.
        assert_eq!(
            fs.accrue(notional, false).unwrap(),
            Amount::from_raw(1_000_000)
        );
        // protocol 30% of an accrued 2.0 fee = 0.6.
        assert_eq!(
            fs.protocol_cut(Amount::from_raw(2_000_000)).unwrap(),
            Amount::from_raw(600_000)
        );
    }
}

//! Sponsorship: multi-sponsor stake accounting, revenue-share distribution,
//! transferable ownership, and slashing restricted to *objectively measurable*
//! failures.
//!
//! # Value conservation
//! Stake in equals stake out: [`SponsorSet::add_sponsor`] credits exactly the
//! posted stake, [`SponsorSet::remove_sponsor`] returns exactly that sponsor's
//! remaining stake, and [`SponsorSet::slash`] moves exactly the slashed amount
//! to the caller (destined for the insurance backstop). No path creates or
//! destroys value.
//!
//! # Objective faults only
//! [`SlashableFault`] enumerates the *only* conditions that may reduce stake.
//! Subjective performance (slow quotes, thin books that still meet obligation,
//! unpopular markets) can never trigger a slash — there is no variant for it.

use serde::{Deserialize, Serialize};
use types::{Amount, Ratio, SponsorId};

use crate::config::MAX_BPS;
use crate::error::SponsorError;

/// One sponsor's stake, revenue entitlement, and governance weight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorShare {
    /// The sponsor's identity.
    pub sponsor_id: SponsorId,
    /// Posted collateral stake (non-negative by invariant).
    pub stake: Amount,
    /// Share of the sponsor fee pool, in basis points.
    pub revenue_share_bps: u16,
    /// Governance voting weight.
    pub governance_weight: u64,
}

impl SponsorShare {
    /// Construct a sponsor share.
    #[must_use]
    pub fn new(
        sponsor_id: SponsorId,
        stake: Amount,
        revenue_share_bps: u16,
        governance_weight: u64,
    ) -> Self {
        Self {
            sponsor_id,
            stake,
            revenue_share_bps,
            governance_weight,
        }
    }
}

/// A set of sponsors backing one market, with a single current owner.
///
/// Invariants (checked by every mutator):
/// * `sum(revenue_share_bps) <= 10_000`.
/// * every `stake >= 0`.
/// * `sponsor_id`s are unique.
/// * the set is never empty.
/// * `owner` is always a member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorSet {
    shares: Vec<SponsorShare>,
    owner: SponsorId,
}

impl SponsorSet {
    /// Create a set from a single founding sponsor, who becomes the owner.
    ///
    /// # Errors
    /// [`SponsorError::RevenueShareExceeded`] if the founder's bps exceed 10_000,
    /// or [`SponsorError::Arith`] if the stake is negative.
    pub fn new(founder: SponsorShare) -> Result<Self, SponsorError> {
        if founder.revenue_share_bps > MAX_BPS {
            return Err(SponsorError::RevenueShareExceeded);
        }
        if founder.stake.is_negative() {
            return Err(SponsorError::Arith(types::ArithError::OutOfRange));
        }
        Ok(Self {
            owner: founder.sponsor_id,
            shares: vec![founder],
        })
    }

    /// The current owner id.
    #[must_use]
    pub fn owner(&self) -> SponsorId {
        self.owner
    }

    /// Number of sponsors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shares.len()
    }

    /// Whether the set has no sponsors (never true once constructed).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    /// All sponsor shares, in insertion order.
    #[must_use]
    pub fn shares(&self) -> &[SponsorShare] {
        &self.shares
    }

    /// Look up one sponsor's share.
    #[must_use]
    pub fn share(&self, sponsor_id: SponsorId) -> Option<&SponsorShare> {
        self.shares.iter().find(|s| s.sponsor_id == sponsor_id)
    }

    /// Aggregate stake across all sponsors (saturating; stays non-negative).
    #[must_use]
    pub fn total_stake(&self) -> Amount {
        self.shares
            .iter()
            .fold(Amount::ZERO, |acc, s| acc.saturating_add(s.stake))
    }

    /// Aggregate revenue-share basis points. Widened to `u32` so the `<=10_000`
    /// invariant is checked without truncation.
    #[must_use]
    pub fn total_revenue_bps(&self) -> u32 {
        self.shares
            .iter()
            .map(|s| u32::from(s.revenue_share_bps))
            .sum()
    }

    /// Aggregate governance weight (saturating).
    #[must_use]
    pub fn total_governance_weight(&self) -> u64 {
        self.shares
            .iter()
            .fold(0u64, |acc, s| acc.saturating_add(s.governance_weight))
    }

    /// Admit an additional sponsor.
    ///
    /// # Errors
    /// * [`SponsorError::DuplicateSponsor`] if the id is already present.
    /// * [`SponsorError::RevenueShareExceeded`] if the new aggregate bps > 10_000.
    /// * [`SponsorError::Arith`] if the stake is negative.
    pub fn add_sponsor(&mut self, share: SponsorShare) -> Result<(), SponsorError> {
        if share.stake.is_negative() {
            return Err(SponsorError::Arith(types::ArithError::OutOfRange));
        }
        if self.share(share.sponsor_id).is_some() {
            return Err(SponsorError::DuplicateSponsor);
        }
        let projected = self.total_revenue_bps() + u32::from(share.revenue_share_bps);
        if projected > u32::from(MAX_BPS) {
            return Err(SponsorError::RevenueShareExceeded);
        }
        self.shares.push(share);
        Ok(())
    }

    /// Add stake to an existing sponsor. Returns the sponsor's new stake.
    ///
    /// # Errors
    /// [`SponsorError::UnknownSponsor`] or [`SponsorError::Arith`] on overflow /
    /// negative amount.
    pub fn add_stake(
        &mut self,
        sponsor_id: SponsorId,
        amount: Amount,
    ) -> Result<Amount, SponsorError> {
        if amount.is_negative() {
            return Err(SponsorError::Arith(types::ArithError::OutOfRange));
        }
        let share = self
            .shares
            .iter_mut()
            .find(|s| s.sponsor_id == sponsor_id)
            .ok_or(SponsorError::UnknownSponsor)?;
        share.stake = share.stake.checked_add(amount)?;
        Ok(share.stake)
    }

    /// Remove a sponsor, returning the stake to refund to the ledger.
    ///
    /// `min_required` is the market's stake requirement, and `enforce` is true
    /// when the market is past `Draft` (so the requirement must still hold after
    /// removal). Removal is rejected if it would empty the set or remove the
    /// owner.
    ///
    /// # Errors
    /// [`SponsorError::UnknownSponsor`], [`SponsorError::WouldEmptySet`],
    /// [`SponsorError::NotOwner`] (attempt to remove the owner), or
    /// [`SponsorError::StakeRequirementBreach`].
    pub fn remove_sponsor(
        &mut self,
        sponsor_id: SponsorId,
        min_required: Amount,
        enforce: bool,
    ) -> Result<Amount, SponsorError> {
        if self.shares.len() == 1 {
            return Err(SponsorError::WouldEmptySet);
        }
        if sponsor_id == self.owner {
            // Ownership must be transferred before the owner can exit.
            return Err(SponsorError::NotOwner);
        }
        let idx = self
            .shares
            .iter()
            .position(|s| s.sponsor_id == sponsor_id)
            .ok_or(SponsorError::UnknownSponsor)?;
        let refunded = self.shares[idx].stake;
        if enforce {
            let remaining = self.total_stake().saturating_sub(refunded);
            if remaining.raw() < min_required.raw() {
                return Err(SponsorError::StakeRequirementBreach);
            }
        }
        self.shares.remove(idx);
        Ok(refunded)
    }

    /// Transfer ownership to another existing sponsor.
    ///
    /// # Errors
    /// [`SponsorError::NotOwner`] if `current` is not the owner, or
    /// [`SponsorError::UnknownSponsor`] if `next` is not a member.
    pub fn transfer_ownership(
        &mut self,
        current: SponsorId,
        next: SponsorId,
    ) -> Result<(), SponsorError> {
        if current != self.owner {
            return Err(SponsorError::NotOwner);
        }
        if self.share(next).is_none() {
            return Err(SponsorError::UnknownSponsor);
        }
        self.owner = next;
        Ok(())
    }

    /// Distribute an accrued sponsor fee `pool` across sponsors by bps.
    ///
    /// Returns `(payouts, remainder)` where `payouts[i]` corresponds to
    /// `shares()[i]`. Each payout is `pool * bps / 10_000` rounded toward zero;
    /// the deterministic `remainder` (rounding dust plus any unallocated bps)
    /// is `pool - sum(payouts)` and is conventionally credited to the owner.
    ///
    /// Conservation: `sum(payouts) + remainder == pool` exactly.
    ///
    /// # Errors
    /// [`SponsorError::Arith`] on overflow.
    pub fn distribute_revenue(
        &self,
        pool: Amount,
    ) -> Result<(Vec<(SponsorId, Amount)>, Amount), SponsorError> {
        let mut payouts = Vec::with_capacity(self.shares.len());
        let mut allocated = Amount::ZERO;
        for share in &self.shares {
            let ratio = Ratio::from_bps(i64::from(share.revenue_share_bps))?;
            let cut = pool.mul_ratio(ratio)?;
            allocated = allocated.checked_add(cut)?;
            payouts.push((share.sponsor_id, cut));
        }
        let remainder = pool.checked_sub(allocated)?;
        Ok((payouts, remainder))
    }
}

/// The closed set of *objectively measurable* sponsor failures. There is no
/// variant for subjective performance; slashing is impossible without one of
/// these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashableFault {
    /// The published market config was invalid / self-contradictory.
    InvalidConfig,
    /// The sponsor's oracle commitment was broken (feed absent vs commitment).
    BrokenOracleCommitment,
    /// A committed quoting obligation was measurably missed.
    QuotingObligationMiss,
    /// A resolution the sponsor certified was proven fraudulent.
    FraudulentResolution,
    /// The sponsor double-signed conflicting messages.
    DoubleSign,
    /// The sponsor abandoned the market (measurable prolonged absence).
    Abandonment,
}

impl SlashableFault {
    /// The slash penalty, in basis points of the sponsor's stake, for this
    /// fault. These are fixed, published constants (no discretion).
    #[must_use]
    pub const fn penalty_bps(self) -> u16 {
        match self {
            SlashableFault::InvalidConfig => 2_000,
            SlashableFault::BrokenOracleCommitment => 3_000,
            SlashableFault::QuotingObligationMiss => 1_000,
            SlashableFault::FraudulentResolution => 10_000,
            SlashableFault::DoubleSign => 10_000,
            SlashableFault::Abandonment => 5_000,
        }
    }
}

impl SponsorSet {
    /// Slash a sponsor for an objective `fault`, reducing its stake by the
    /// fault's penalty bps and returning the slashed amount (to be credited to
    /// the insurance backstop by the caller).
    ///
    /// Only [`SlashableFault`] variants can reach here; there is no way to slash
    /// for subjective reasons. Value is conserved: the sponsor's stake drops by
    /// exactly the returned amount.
    ///
    /// # Errors
    /// [`SponsorError::UnknownSponsor`] or [`SponsorError::Arith`].
    pub fn slash(
        &mut self,
        sponsor_id: SponsorId,
        fault: SlashableFault,
    ) -> Result<Amount, SponsorError> {
        let share = self
            .shares
            .iter_mut()
            .find(|s| s.sponsor_id == sponsor_id)
            .ok_or(SponsorError::UnknownSponsor)?;
        let ratio = Ratio::from_bps(i64::from(fault.penalty_bps()))?;
        let mut slashed = share.stake.mul_ratio(ratio)?;
        // Never slash more than the sponsor holds.
        if slashed.raw() > share.stake.raw() {
            slashed = share.stake;
        }
        share.stake = share.stake.checked_sub(slashed)?;
        Ok(slashed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(n: u32) -> SponsorId {
        SponsorId::new(n)
    }

    fn founder() -> SponsorShare {
        SponsorShare::new(sid(1), Amount::from_raw(1_000_000), 6_000, 100)
    }

    #[test]
    fn multi_sponsor_stake_and_governance_totals() {
        let mut set = SponsorSet::new(founder()).unwrap();
        set.add_sponsor(SponsorShare::new(
            sid(2),
            Amount::from_raw(500_000),
            3_000,
            50,
        ))
        .unwrap();
        assert_eq!(set.total_stake(), Amount::from_raw(1_500_000));
        assert_eq!(set.total_revenue_bps(), 9_000);
        assert_eq!(set.total_governance_weight(), 150);
    }

    #[test]
    fn revenue_share_bps_bound_enforced() {
        let mut set = SponsorSet::new(founder()).unwrap();
        // founder is 6000; +5000 would be 11000 > 10000.
        let err = set
            .add_sponsor(SponsorShare::new(sid(2), Amount::ZERO, 5_000, 0))
            .unwrap_err();
        assert_eq!(err, SponsorError::RevenueShareExceeded);
        // +4000 is exactly 10000, allowed.
        assert!(set
            .add_sponsor(SponsorShare::new(sid(2), Amount::ZERO, 4_000, 0))
            .is_ok());
    }

    #[test]
    fn revenue_distribution_sums_exactly() {
        let mut set = SponsorSet::new(founder()).unwrap();
        set.add_sponsor(SponsorShare::new(sid(2), Amount::ZERO, 4_000, 0))
            .unwrap();
        let pool = Amount::from_raw(1_000_000); // 1.0
        let (payouts, remainder) = set.distribute_revenue(pool).unwrap();
        // 60% and 40% of 1.0.
        assert_eq!(payouts[0].1, Amount::from_raw(600_000));
        assert_eq!(payouts[1].1, Amount::from_raw(400_000));
        assert_eq!(remainder, Amount::ZERO);
        let sum = payouts
            .iter()
            .fold(Amount::ZERO, |a, p| a.checked_add(p.1).unwrap());
        assert_eq!(sum.checked_add(remainder).unwrap(), pool);
    }

    #[test]
    fn remainder_captures_rounding_and_unallocated_bps() {
        // Only 50% allocated; remainder holds the other half plus any dust.
        let set = SponsorSet::new(SponsorShare::new(sid(1), Amount::ZERO, 5_000, 0)).unwrap();
        let pool = Amount::from_raw(1_000_001); // odd micro-unit
        let (payouts, remainder) = set.distribute_revenue(pool).unwrap();
        let sum = payouts
            .iter()
            .fold(Amount::ZERO, |a, p| a.checked_add(p.1).unwrap());
        assert_eq!(sum.checked_add(remainder).unwrap(), pool);
        // 50% of 1_000_001 rounds toward zero to 500_000.
        assert_eq!(payouts[0].1, Amount::from_raw(500_000));
        assert_eq!(remainder, Amount::from_raw(500_001));
    }

    #[test]
    fn ownership_transfer_and_removal_rules() {
        let mut set = SponsorSet::new(founder()).unwrap();
        set.add_sponsor(SponsorShare::new(
            sid(2),
            Amount::from_raw(500_000),
            1_000,
            10,
        ))
        .unwrap();
        // Cannot remove the owner directly.
        assert_eq!(
            set.remove_sponsor(sid(1), Amount::ZERO, false).unwrap_err(),
            SponsorError::NotOwner
        );
        // Transfer then remove old owner.
        set.transfer_ownership(sid(1), sid(2)).unwrap();
        let refunded = set.remove_sponsor(sid(1), Amount::ZERO, false).unwrap();
        assert_eq!(refunded, Amount::from_raw(1_000_000));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn removal_respects_stake_requirement_when_active() {
        let mut set = SponsorSet::new(founder()).unwrap();
        set.add_sponsor(SponsorShare::new(
            sid(2),
            Amount::from_raw(500_000),
            1_000,
            10,
        ))
        .unwrap();
        set.transfer_ownership(sid(1), sid(2)).unwrap();
        // Requirement 1.2; removing sid(1) (1.0) leaves 0.5 < 1.2 -> breach.
        let req = Amount::from_raw(1_200_000);
        assert_eq!(
            set.remove_sponsor(sid(1), req, true).unwrap_err(),
            SponsorError::StakeRequirementBreach
        );
    }

    #[test]
    fn slash_only_reduces_by_penalty_and_conserves() {
        let mut set = SponsorSet::new(founder()).unwrap();
        let before = set.share(sid(1)).unwrap().stake;
        // InvalidConfig = 2000 bps = 20% of 1.0 = 0.2.
        let slashed = set.slash(sid(1), SlashableFault::InvalidConfig).unwrap();
        assert_eq!(slashed, Amount::from_raw(200_000));
        let after = set.share(sid(1)).unwrap().stake;
        assert_eq!(before.checked_sub(after).unwrap(), slashed);
        // Fraud / double-sign are total (100%).
        let mut set2 = SponsorSet::new(founder()).unwrap();
        let all = set2
            .slash(sid(1), SlashableFault::FraudulentResolution)
            .unwrap();
        assert_eq!(all, before);
        assert_eq!(set2.share(sid(1)).unwrap().stake, Amount::ZERO);
    }

    // Deterministic LCG property test: revenue distribution always conserves.
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
    fn property_distribution_conserves_over_random_sets() {
        let mut r = Lcg(0x5EED_1234);
        for _ in 0..20_000 {
            let n = usize::try_from(r.next_u64() % 6).unwrap() + 1;
            let mut remaining_bps = 10_000u32;
            let founder_bps = u16::try_from(r.next_u64() % u64::from(remaining_bps + 1)).unwrap();
            remaining_bps -= u32::from(founder_bps);
            let mut set = SponsorSet::new(SponsorShare::new(
                sid(0),
                Amount::from_raw(i128::from(r.next_u64() % 1_000_000)),
                founder_bps,
                r.next_u64() % 1000,
            ))
            .unwrap();
            for i in 1..n {
                if remaining_bps == 0 {
                    break;
                }
                let bps = u16::try_from(r.next_u64() % u64::from(remaining_bps + 1)).unwrap();
                remaining_bps -= u32::from(bps);
                // add_sponsor may still succeed; ignore duplicate-free ids.
                let _ = set.add_sponsor(SponsorShare::new(
                    sid(u32::try_from(i).unwrap()),
                    Amount::from_raw(i128::from(r.next_u64() % 1_000_000)),
                    bps,
                    r.next_u64() % 1000,
                ));
            }
            assert!(set.total_revenue_bps() <= u32::from(MAX_BPS));
            let pool = Amount::from_raw(i128::from(r.next_u64() % 1_000_000_000));
            let (payouts, remainder) = set.distribute_revenue(pool).unwrap();
            let sum = payouts
                .iter()
                .fold(Amount::ZERO, |a, p| a.checked_add(p.1).unwrap());
            assert_eq!(sum.checked_add(remainder).unwrap(), pool);
            assert!(!remainder.is_negative());
        }
    }
}

//! The market registry: the canonical [`MarketDefinition`] record, a uniqueness-
//! enforcing [`MarketRegistry`], the validated lifecycle command handlers, and a
//! deterministic state-root commitment.
//!
//! Every mutating handler drives the lifecycle through
//! [`crate::lifecycle::advance`], emitting exactly one sequenced
//! [`LifecycleEvent`] per committed transition. Two independent replays of the
//! same command sequence produce a bit-identical [`MarketRegistry::state_root`].

use std::collections::{BTreeMap, BTreeSet};

use crypto::{hash_domain, DOMAIN_MARKET};
use risk::RiskConfig;
use serde::{Deserialize, Serialize};
use types::{
    Amount, Hash, MarketId, MarketLifecycle, MarketType, OracleHealth, PayoutVector, Price,
    SequenceNumber, SponsorId,
};

use crate::config::{FeeSchedule, LifecycleConfig, OracleConfig, ResolverConfig, MAX_BPS};
use crate::error::{MarketError, PayoutError, ResolutionError};
use crate::lifecycle;
use crate::payout::{invalid_refund, CompleteSetPool, PayoutRule, Settlement};
use crate::perpetual::PerpMarketState;
use crate::resolution::{ResolutionCertificate, ResolutionRule};
use crate::sponsor::{SlashableFault, SponsorSet};

/// The immutable-once-created definition of a market.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketDefinition {
    /// Unique market identifier.
    pub market_id: MarketId,
    /// The market kind (payout/risk semantics).
    pub market_type: MarketType,
    /// The backing sponsors.
    pub sponsor_set: SponsorSet,
    /// Opaque collateral-asset identifier.
    pub collateral_asset: u32,
    /// Minimum aggregate sponsor stake required to advance past `Draft`.
    pub stake_requirement: Amount,
    /// Trading-fee schedule.
    pub fee_schedule: FeeSchedule,
    /// Price-oracle configuration (distinct from resolution).
    pub oracle_config: OracleConfig,
    /// Resolution-oracle configuration (distinct from price).
    pub resolver_config: ResolverConfig,
    /// Risk / margin parameters.
    pub risk_config: RiskConfig,
    /// Lifecycle-automation thresholds.
    pub lifecycle_config: LifecycleConfig,
    /// How the market pays out at settlement.
    pub payout_rule: PayoutRule,
    /// Commitment to off-chain metadata.
    pub metadata_hash: Hash,
}

impl MarketDefinition {
    /// The number of settlement outcomes, if the payout rule is enumerable.
    #[must_use]
    pub fn num_outcomes(&self) -> Option<usize> {
        self.payout_rule.num_outcomes()
    }
}

/// A sequenced lifecycle-transition event emitted on every committed transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleEvent {
    /// Monotonic event sequence number.
    pub sequence: SequenceNumber,
    /// The market that transitioned.
    pub market_id: MarketId,
    /// The prior state.
    pub from: MarketLifecycle,
    /// The new state.
    pub to: MarketLifecycle,
}

/// The internal per-market registry record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct MarketRecord {
    definition: MarketDefinition,
    lifecycle: MarketLifecycle,
    bootstrapped: Amount,
    pool: Option<CompleteSetPool>,
    perp: PerpMarketState,
    resolution: Option<PayoutVector>,
    settled: bool,
}

/// A replayable market command over the lifecycle-management subset. Resolution
/// and settlement, which carry certificates/rules, are applied via dedicated
/// [`MarketRegistry`] methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketCommand {
    /// Create a new market in `Draft`.
    CreateMarket(Box<MarketDefinition>),
    /// Post sponsor stake; auto-advances `Draft -> Staked` at the requirement.
    StakeMarket {
        /// Target market.
        market_id: MarketId,
        /// Sponsor posting stake.
        sponsor_id: SponsorId,
        /// Amount posted.
        amount: Amount,
    },
    /// Advance `Staked -> Bootstrapping`.
    ActivateMarket(MarketId),
    /// Add bootstrap liquidity; auto-advances `Bootstrapping -> Open`.
    AddBootstrapLiquidity {
        /// Target market.
        market_id: MarketId,
        /// Liquidity added.
        amount: Amount,
    },
    /// Halt an `Open`/`Bootstrapping` market.
    HaltMarket(MarketId),
    /// Resume a `Halted` market to `Open`.
    ResumeMarket(MarketId),
    /// Close trading at sequence `now` (`Open -> Closed`).
    CloseMarket {
        /// Target market.
        market_id: MarketId,
        /// Current sequence tick.
        now: u64,
    },
    /// Advance `Closed -> PendingResolution`.
    BeginResolution(MarketId),
    /// Mint `units` complete sets (market must be `Open`).
    MintCompleteSet {
        /// Target market.
        market_id: MarketId,
        /// Complete sets to mint.
        units: Amount,
    },
    /// Redeem `units` complete sets (market must be `Open`).
    RedeemCompleteSet {
        /// Target market.
        market_id: MarketId,
        /// Complete sets to redeem.
        units: Amount,
    },
    /// Archive a `Settled`/`Halted` market.
    ArchiveMarket(MarketId),
}

/// The market registry.
#[derive(Debug, Clone, Default)]
pub struct MarketRegistry {
    markets: BTreeMap<MarketId, MarketRecord>,
    events: Vec<LifecycleEvent>,
    next_seq: SequenceNumber,
    applied_evidence: BTreeSet<Hash>,
    insurance: Amount,
}

impl MarketRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ---- discovery / query ------------------------------------------------

    /// All market ids, ascending.
    #[must_use]
    pub fn get_markets(&self) -> Vec<MarketId> {
        self.markets.keys().copied().collect()
    }

    /// The definition of one market.
    #[must_use]
    pub fn get_market(&self, market_id: MarketId) -> Option<&MarketDefinition> {
        self.markets.get(&market_id).map(|r| &r.definition)
    }

    /// The lifecycle status of one market.
    #[must_use]
    pub fn get_market_status(&self, market_id: MarketId) -> Option<MarketLifecycle> {
        self.markets.get(&market_id).map(|r| r.lifecycle)
    }

    /// Number of markets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.markets.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.markets.is_empty()
    }

    /// The lifecycle event stream committed so far.
    #[must_use]
    pub fn events(&self) -> &[LifecycleEvent] {
        &self.events
    }

    /// The insurance / backstop balance accumulated from slashing and dust.
    #[must_use]
    pub fn insurance(&self) -> Amount {
        self.insurance
    }

    // ---- lifecycle handlers ----------------------------------------------

    /// Create a market in `Draft`, enforcing id uniqueness and config bounds.
    ///
    /// # Errors
    /// [`MarketError::DuplicateMarket`], or [`MarketError::ParameterOutOfRange`]
    /// on an invalid fee schedule or negative stake requirement.
    pub fn create_market(&mut self, definition: MarketDefinition) -> Result<(), MarketError> {
        if self.markets.contains_key(&definition.market_id) {
            return Err(MarketError::DuplicateMarket);
        }
        if definition.fee_schedule.maker_bps > MAX_BPS
            || definition.fee_schedule.taker_bps > MAX_BPS
            || definition.fee_schedule.protocol_bps > MAX_BPS
            || definition.stake_requirement.is_negative()
        {
            return Err(MarketError::ParameterOutOfRange);
        }
        let pool = definition
            .payout_rule
            .num_outcomes()
            .map(CompleteSetPool::new)
            .transpose()?;
        let record = MarketRecord {
            definition,
            lifecycle: MarketLifecycle::Draft,
            bootstrapped: Amount::ZERO,
            pool,
            perp: PerpMarketState::default(),
            resolution: None,
            settled: false,
        };
        self.markets.insert(record.definition.market_id, record);
        Ok(())
    }

    /// Commit a validated lifecycle transition, emitting one sequenced event.
    fn transition(&mut self, market_id: MarketId, to: MarketLifecycle) -> Result<(), MarketError> {
        let record = self
            .markets
            .get_mut(&market_id)
            .ok_or(MarketError::UnknownMarket)?;
        let from = record.lifecycle;
        let next = lifecycle::advance(from, to)?;
        record.lifecycle = next;
        let seq = self.next_seq;
        self.events.push(LifecycleEvent {
            sequence: seq,
            market_id,
            from,
            to: next,
        });
        self.next_seq = SequenceNumber::new(seq.get().saturating_add(1));
        Ok(())
    }

    fn record(&self, market_id: MarketId) -> Result<&MarketRecord, MarketError> {
        self.markets
            .get(&market_id)
            .ok_or(MarketError::UnknownMarket)
    }

    fn record_mut(&mut self, market_id: MarketId) -> Result<&mut MarketRecord, MarketError> {
        self.markets
            .get_mut(&market_id)
            .ok_or(MarketError::UnknownMarket)
    }

    /// Post sponsor stake. Auto-advances `Draft -> Staked` once the aggregate
    /// stake reaches the requirement.
    ///
    /// # Errors
    /// [`MarketError::UnknownMarket`], or a wrapped [`crate::SponsorError`].
    pub fn stake_market(
        &mut self,
        market_id: MarketId,
        sponsor_id: SponsorId,
        amount: Amount,
    ) -> Result<Amount, MarketError> {
        let record = self.record_mut(market_id)?;
        let new_stake = record
            .definition
            .sponsor_set
            .add_stake(sponsor_id, amount)?;
        let met = record.definition.sponsor_set.total_stake().raw()
            >= record.definition.stake_requirement.raw();
        let is_draft = record.lifecycle == MarketLifecycle::Draft;
        if met && is_draft {
            self.transition(market_id, MarketLifecycle::Staked)?;
        }
        Ok(new_stake)
    }

    /// Advance `Staked -> Bootstrapping`.
    ///
    /// # Errors
    /// [`MarketError::UnknownMarket`] or [`MarketError::Lifecycle`].
    pub fn activate_market(&mut self, market_id: MarketId) -> Result<(), MarketError> {
        self.transition(market_id, MarketLifecycle::Bootstrapping)
    }

    /// Add bootstrap liquidity. Auto-advances `Bootstrapping -> Open` once the
    /// configured threshold is met.
    ///
    /// # Errors
    /// [`MarketError::UnknownMarket`], [`MarketError::WrongLifecycleState`], or
    /// arithmetic overflow.
    pub fn add_bootstrap_liquidity(
        &mut self,
        market_id: MarketId,
        amount: Amount,
    ) -> Result<(), MarketError> {
        let record = self.record_mut(market_id)?;
        if record.lifecycle != MarketLifecycle::Bootstrapping {
            return Err(MarketError::WrongLifecycleState);
        }
        record.bootstrapped = record.bootstrapped.checked_add(amount)?;
        let met = record.bootstrapped.raw()
            >= record
                .definition
                .lifecycle_config
                .bootstrap_liquidity_threshold
                .raw();
        if met {
            self.transition(market_id, MarketLifecycle::Open)?;
        }
        Ok(())
    }

    /// Halt an `Open` or `Bootstrapping` market.
    ///
    /// # Errors
    /// [`MarketError::Lifecycle`] if not haltable.
    pub fn halt_market(&mut self, market_id: MarketId) -> Result<(), MarketError> {
        self.transition(market_id, MarketLifecycle::Halted)
    }

    /// Resume a `Halted` market to `Open`.
    ///
    /// # Errors
    /// [`MarketError::Lifecycle`] if not resumable.
    pub fn resume_market(&mut self, market_id: MarketId) -> Result<(), MarketError> {
        self.transition(market_id, MarketLifecycle::Open)
    }

    /// Close trading (`Open -> Closed`) once `now` reaches the configured close
    /// tick.
    ///
    /// # Errors
    /// [`MarketError::ParameterOutOfRange`] if `now` is before the close tick;
    /// [`MarketError::Lifecycle`] if not `Open`.
    pub fn close_market(&mut self, market_id: MarketId, now: u64) -> Result<(), MarketError> {
        let record = self.record(market_id)?;
        if now < record.definition.lifecycle_config.trading_close_seq {
            return Err(MarketError::ParameterOutOfRange);
        }
        self.transition(market_id, MarketLifecycle::Closed)
    }

    /// Advance `Closed -> PendingResolution`.
    ///
    /// # Errors
    /// [`MarketError::Lifecycle`] if not `Closed`.
    pub fn begin_resolution(&mut self, market_id: MarketId) -> Result<(), MarketError> {
        self.transition(market_id, MarketLifecycle::PendingResolution)
    }

    /// Archive a `Settled` (or abandoned `Halted`) market.
    ///
    /// # Errors
    /// [`MarketError::Lifecycle`] if not archivable.
    pub fn archive_market(&mut self, market_id: MarketId) -> Result<(), MarketError> {
        self.transition(market_id, MarketLifecycle::Archived)
    }

    /// Update mutable parameters (fee schedule, metadata) while in `Draft` or
    /// `Staked`.
    ///
    /// # Errors
    /// [`MarketError::WrongLifecycleState`] if past `Staked`;
    /// [`MarketError::ParameterOutOfRange`] on an invalid fee schedule.
    pub fn update_parameters(
        &mut self,
        market_id: MarketId,
        fee_schedule: FeeSchedule,
        metadata_hash: Hash,
    ) -> Result<(), MarketError> {
        if fee_schedule.maker_bps > MAX_BPS
            || fee_schedule.taker_bps > MAX_BPS
            || fee_schedule.protocol_bps > MAX_BPS
        {
            return Err(MarketError::ParameterOutOfRange);
        }
        let record = self.record_mut(market_id)?;
        if !matches!(
            record.lifecycle,
            MarketLifecycle::Draft | MarketLifecycle::Staked
        ) {
            return Err(MarketError::WrongLifecycleState);
        }
        record.definition.fee_schedule = fee_schedule;
        record.definition.metadata_hash = metadata_hash;
        Ok(())
    }

    // ---- complete sets ----------------------------------------------------

    /// Mint `units` complete sets. Requires an `Open` market with an enumerable
    /// payout rule.
    ///
    /// # Errors
    /// [`MarketError::WrongLifecycleState`] if not `Open`; [`MarketError::Payout`]
    /// for a non-enumerable rule or a bad unit count.
    pub fn mint_complete_set(
        &mut self,
        market_id: MarketId,
        units: Amount,
    ) -> Result<(), MarketError> {
        let record = self.record_mut(market_id)?;
        if record.lifecycle != MarketLifecycle::Open {
            return Err(MarketError::WrongLifecycleState);
        }
        let pool = record.pool.as_mut().ok_or(PayoutError::NonEnumerable)?;
        pool.mint(units)?;
        Ok(())
    }

    /// Redeem `units` complete sets. Requires an `Open` market.
    ///
    /// # Errors
    /// As [`MarketRegistry::mint_complete_set`], plus insufficient-balance
    /// payout errors.
    pub fn redeem_complete_set(
        &mut self,
        market_id: MarketId,
        units: Amount,
    ) -> Result<(), MarketError> {
        let record = self.record_mut(market_id)?;
        if record.lifecycle != MarketLifecycle::Open {
            return Err(MarketError::WrongLifecycleState);
        }
        let pool = record.pool.as_mut().ok_or(PayoutError::NonEnumerable)?;
        pool.redeem(units)?;
        Ok(())
    }

    // ---- resolution & settlement -----------------------------------------

    /// Resolve a `PendingResolution`/`Disputed` market with a verified committee
    /// certificate. Records the certified outcome and advances to `Resolved`.
    ///
    /// # Errors
    /// [`MarketError::WrongLifecycleState`], or [`MarketError::Resolution`] if
    /// the certificate fails verification.
    pub fn resolve_market(
        &mut self,
        market_id: MarketId,
        certificate: &ResolutionCertificate,
        rule: &ResolutionRule,
    ) -> Result<(), MarketError> {
        let record = self.record(market_id)?;
        if !matches!(
            record.lifecycle,
            MarketLifecycle::PendingResolution | MarketLifecycle::Disputed
        ) {
            return Err(MarketError::WrongLifecycleState);
        }
        let expected = record
            .definition
            .num_outcomes()
            .ok_or(PayoutError::NonEnumerable)?;
        certificate.verify(rule, market_id, expected)?;
        let outcome = certificate.payout.clone();
        let record = self.record_mut(market_id)?;
        record.resolution = Some(outcome);
        self.transition(market_id, MarketLifecycle::Resolved)
    }

    /// Mark a `PendingResolution`/`Disputed` market INVALID, recording a
    /// pro-rata refund vector, and advance to `Invalid`.
    ///
    /// # Errors
    /// [`MarketError::WrongLifecycleState`] or [`MarketError::Payout`].
    pub fn invalidate_market(&mut self, market_id: MarketId) -> Result<(), MarketError> {
        let record = self.record(market_id)?;
        if !matches!(
            record.lifecycle,
            MarketLifecycle::PendingResolution | MarketLifecycle::Disputed
        ) {
            return Err(MarketError::WrongLifecycleState);
        }
        let n = record
            .definition
            .num_outcomes()
            .ok_or(PayoutError::NonEnumerable)?;
        let refund = invalid_refund(n)?;
        let record = self.record_mut(market_id)?;
        record.resolution = Some(refund);
        self.transition(market_id, MarketLifecycle::Invalid)
    }

    /// Open a staked challenge, moving `PendingResolution -> Disputed`.
    ///
    /// # Errors
    /// [`MarketError::Lifecycle`] if not `PendingResolution`.
    pub fn dispute_market(&mut self, market_id: MarketId) -> Result<(), MarketError> {
        self.transition(market_id, MarketLifecycle::Disputed)
    }

    /// Settle a `Resolved`/`Invalid` market, distributing collateral across
    /// outstanding claims and routing dust to the insurance backstop.
    ///
    /// Idempotent: re-invoking after settlement recomputes the same
    /// [`Settlement`] without mutating state.
    ///
    /// # Errors
    /// [`MarketError::WrongLifecycleState`] if not settleable;
    /// [`MarketError::Payout`] if no resolution outcome / non-enumerable pool.
    pub fn settle_market(&mut self, market_id: MarketId) -> Result<Settlement, MarketError> {
        let record = self.record(market_id)?;
        // Idempotent no-op once settled.
        if record.settled {
            return self.compute_settlement(market_id);
        }
        if !matches!(
            record.lifecycle,
            MarketLifecycle::Resolved | MarketLifecycle::Invalid
        ) {
            return Err(MarketError::WrongLifecycleState);
        }
        let settlement = self.compute_settlement(market_id)?;
        let dust = settlement.dust;
        self.transition(market_id, MarketLifecycle::Settled)?;
        let record = self.record_mut(market_id)?;
        record.settled = true;
        self.insurance = self.insurance.checked_add(dust)?;
        Ok(settlement)
    }

    /// Compute (without mutating) the settlement of a resolved market.
    fn compute_settlement(&self, market_id: MarketId) -> Result<Settlement, MarketError> {
        let record = self.record(market_id)?;
        let payout = record
            .resolution
            .as_ref()
            .ok_or(PayoutError::OutcomeMismatch)?;
        let pool = record.pool.as_ref().ok_or(PayoutError::NonEnumerable)?;
        Ok(pool.settle(payout)?)
    }

    // ---- perpetual mark ---------------------------------------------------

    /// Update a perpetual market's mark from an index/book/health observation.
    ///
    /// # Errors
    /// [`MarketError::UnknownMarket`] or [`MarketError::Perp`] (e.g. halted
    /// oracle).
    pub fn update_mark(
        &mut self,
        market_id: MarketId,
        index: Price,
        mid: Option<Price>,
        health: OracleHealth,
    ) -> Result<Price, MarketError> {
        let record = self.record_mut(market_id)?;
        let mark = record.perp.update_mark(index, mid, health)?;
        Ok(mark)
    }

    /// The last mark price recorded for a market.
    #[must_use]
    pub fn mark_price(&self, market_id: MarketId) -> Option<Price> {
        self.markets.get(&market_id).map(|r| r.perp.mark_price)
    }

    // ---- slashing ---------------------------------------------------------

    /// Slash a sponsor for an objective `fault`, crediting the slashed stake to
    /// the insurance backstop. `evidence_hash` deduplicates: a record already
    /// applied cannot double-slash. If aggregate stake falls below the
    /// requirement on an active market, it deterministically transitions to
    /// `Halted`.
    ///
    /// # Errors
    /// [`MarketError::Resolution`] with `DuplicateEvidence`,
    /// [`MarketError::Sponsor`], or [`MarketError::UnknownMarket`].
    pub fn slash_sponsor(
        &mut self,
        market_id: MarketId,
        sponsor_id: SponsorId,
        fault: SlashableFault,
        evidence_hash: Hash,
    ) -> Result<Amount, MarketError> {
        if self.applied_evidence.contains(&evidence_hash) {
            return Err(MarketError::Resolution(ResolutionError::DuplicateEvidence));
        }
        let record = self.record_mut(market_id)?;
        let slashed = record.definition.sponsor_set.slash(sponsor_id, fault)?;
        let below = record.definition.sponsor_set.total_stake().raw()
            < record.definition.stake_requirement.raw();
        let current = record.lifecycle;
        self.applied_evidence.insert(evidence_hash);
        self.insurance = self.insurance.checked_add(slashed)?;
        if below && lifecycle::is_legal_transition(current, MarketLifecycle::Halted) {
            self.transition(market_id, MarketLifecycle::Halted)?;
        }
        Ok(slashed)
    }

    // ---- command replay ---------------------------------------------------

    /// Apply one replayable [`MarketCommand`].
    ///
    /// # Errors
    /// The command's underlying handler error.
    pub fn apply(&mut self, command: MarketCommand) -> Result<(), MarketError> {
        match command {
            MarketCommand::CreateMarket(def) => self.create_market(*def),
            MarketCommand::StakeMarket {
                market_id,
                sponsor_id,
                amount,
            } => self.stake_market(market_id, sponsor_id, amount).map(|_| ()),
            MarketCommand::ActivateMarket(id) => self.activate_market(id),
            MarketCommand::AddBootstrapLiquidity { market_id, amount } => {
                self.add_bootstrap_liquidity(market_id, amount)
            }
            MarketCommand::HaltMarket(id) => self.halt_market(id),
            MarketCommand::ResumeMarket(id) => self.resume_market(id),
            MarketCommand::CloseMarket { market_id, now } => self.close_market(market_id, now),
            MarketCommand::BeginResolution(id) => self.begin_resolution(id),
            MarketCommand::MintCompleteSet { market_id, units } => {
                self.mint_complete_set(market_id, units)
            }
            MarketCommand::RedeemCompleteSet { market_id, units } => {
                self.redeem_complete_set(market_id, units)
            }
            MarketCommand::ArchiveMarket(id) => self.archive_market(id),
        }
    }

    // ---- commitment -------------------------------------------------------

    /// A deterministic 32-byte commitment over the full registry state. Bit-
    /// identical for equal state across independent replays.
    #[must_use]
    pub fn state_root(&self) -> Hash {
        let snapshot = (
            &self.markets,
            self.next_seq.get(),
            self.insurance,
            &self.applied_evidence,
        );
        match postcard::to_allocvec(&snapshot) {
            Ok(bytes) => hash_domain(DOMAIN_MARKET, &bytes),
            Err(_) => Hash::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payout::winner_takes_all;
    use crate::resolution::resolution_message;
    use crate::sponsor::SponsorShare;
    use crypto::ThresholdSigners;
    use types::Ratio;

    fn risk_cfg() -> RiskConfig {
        RiskConfig::new(
            Ratio::from_bps(1000).unwrap(),
            Ratio::from_bps(500).unwrap(),
            Ratio::from_raw(10_000_000),
        )
        .unwrap()
    }

    fn definition(id: u32) -> MarketDefinition {
        let founder = SponsorShare::new(SponsorId::new(1), Amount::ZERO, 6_000, 100);
        MarketDefinition {
            market_id: MarketId::new(id),
            market_type: MarketType::BinaryPrediction,
            sponsor_set: SponsorSet::new(founder).unwrap(),
            collateral_asset: 1,
            stake_requirement: Amount::from_raw(1_000_000),
            fee_schedule: FeeSchedule::new(10, 20, 3_000).unwrap(),
            oracle_config: OracleConfig::new(0, 100, Ratio::from_bps(100).unwrap()),
            resolver_config: ResolverConfig::new(4, 3, 50, Amount::from_raw(1_000_000)),
            risk_config: risk_cfg(),
            lifecycle_config: LifecycleConfig::new(Amount::from_raw(5_000_000), 1_000),
            payout_rule: PayoutRule::Vector(winner_takes_all(2, 0).unwrap()),
            metadata_hash: Hash::ZERO,
        }
    }

    fn drive_to_open(reg: &mut MarketRegistry, id: u32) {
        let m = MarketId::new(id);
        reg.stake_market(m, SponsorId::new(1), Amount::from_raw(1_000_000))
            .unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Staked));
        reg.activate_market(m).unwrap();
        reg.add_bootstrap_liquidity(m, Amount::from_raw(5_000_000))
            .unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Open));
    }

    #[test]
    fn create_enforces_uniqueness_and_queries() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        assert_eq!(
            reg.create_market(definition(1)).unwrap_err(),
            MarketError::DuplicateMarket
        );
        assert_eq!(reg.get_markets(), vec![MarketId::new(1)]);
        assert!(reg.get_market(MarketId::new(1)).is_some());
        assert_eq!(
            reg.get_market_status(MarketId::new(1)),
            Some(MarketLifecycle::Draft)
        );
        assert_eq!(reg.get_market(MarketId::new(2)), None);
    }

    #[test]
    fn full_lifecycle_advance_and_events() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        drive_to_open(&mut reg, 1);
        let m = MarketId::new(1);
        // Bootstrapping stays until threshold; here it opened at exactly 5.0.
        reg.close_market(m, 1_000).unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Closed));
        reg.begin_resolution(m).unwrap();
        // Every committed transition emitted exactly one sequenced event.
        let seqs: Vec<u64> = reg.events().iter().map(|e| e.sequence.get()).collect();
        let expected: Vec<u64> = (0..seqs.len()).map(|i| u64::try_from(i).unwrap()).collect();
        assert_eq!(seqs, expected);
        // Draft->Staked, Staked->Bootstrapping, Bootstrapping->Open,
        // Open->Closed, Closed->PendingResolution == 5 events.
        assert_eq!(reg.events().len(), 5);
    }

    #[test]
    fn illegal_transitions_rejected() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let m = MarketId::new(1);
        // Cannot open from Draft.
        assert!(matches!(
            reg.resume_market(m),
            Err(MarketError::Lifecycle(_))
        ));
        // Cannot close before trading-close tick.
        drive_to_open(&mut reg, 1);
        assert_eq!(
            reg.close_market(m, 999).unwrap_err(),
            MarketError::ParameterOutOfRange
        );
    }

    #[test]
    fn bootstrapping_holds_until_threshold() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let m = MarketId::new(1);
        reg.stake_market(m, SponsorId::new(1), Amount::from_raw(1_000_000))
            .unwrap();
        reg.activate_market(m).unwrap();
        // Below the 5.0 threshold stays in Bootstrapping and rejects minting.
        reg.add_bootstrap_liquidity(m, Amount::from_raw(1_000_000))
            .unwrap();
        assert_eq!(
            reg.get_market_status(m),
            Some(MarketLifecycle::Bootstrapping)
        );
        assert_eq!(
            reg.mint_complete_set(m, Amount::from_raw(1_000_000))
                .unwrap_err(),
            MarketError::WrongLifecycleState
        );
        // Crossing the threshold opens it.
        reg.add_bootstrap_liquidity(m, Amount::from_raw(4_000_000))
            .unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Open));
    }

    #[test]
    fn update_parameters_bounds_and_state() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let m = MarketId::new(1);
        // Out-of-range bps rejected (constructor guards, so build raw).
        let bad = FeeSchedule {
            maker_bps: 10_001,
            taker_bps: 0,
            protocol_bps: 0,
        };
        assert_eq!(
            reg.update_parameters(m, bad, Hash::ZERO).unwrap_err(),
            MarketError::ParameterOutOfRange
        );
        let ok = FeeSchedule::new(5, 5, 1000).unwrap();
        reg.update_parameters(m, ok, Hash::from_bytes([1u8; 32]))
            .unwrap();
        assert_eq!(reg.get_market(m).unwrap().fee_schedule, ok);
        // Not allowed once past Staked.
        drive_to_open(&mut reg, 1);
        assert_eq!(
            reg.update_parameters(m, ok, Hash::ZERO).unwrap_err(),
            MarketError::WrongLifecycleState
        );
    }

    #[test]
    fn resolve_and_settle_conserve_and_are_idempotent() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let m = MarketId::new(1);
        drive_to_open(&mut reg, 1);
        reg.mint_complete_set(m, Amount::from_raw(3_000_000))
            .unwrap();
        reg.close_market(m, 1_000).unwrap();
        reg.begin_resolution(m).unwrap();

        // Build a committee certificate for outcome 0 (pays 1.0).
        let ts = ThresholdSigners::from_seeds(&[[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]], 3);
        let rule = ResolutionRule::new(ts.validator_set(), 50, Hash::ZERO);
        let payout = winner_takes_all(2, 0).unwrap();
        let ev = Hash::from_bytes([7u8; 32]);
        let msg = resolution_message(m, &payout, ev);
        let qc = ts.sign(msg, vec![0, 1, 2]);
        let cert = ResolutionCertificate::new(m, payout, ev, qc);
        reg.resolve_market(m, &cert, &rule).unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Resolved));

        let s1 = reg.settle_market(m).unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Settled));
        // 3 complete sets, outcome 0 pays 1.0 each -> 3.0 credited, no dust.
        assert_eq!(s1.total_credited, Amount::from_raw(3_000_000));
        assert_eq!(s1.dust, Amount::ZERO);
        // Idempotent re-settle: same result, still Settled.
        let s2 = reg.settle_market(m).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Settled));
    }

    #[test]
    fn cannot_settle_without_resolution() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let m = MarketId::new(1);
        drive_to_open(&mut reg, 1);
        reg.close_market(m, 1_000).unwrap();
        reg.begin_resolution(m).unwrap();
        // No verified certificate yet -> cannot reach Settled.
        assert!(matches!(
            reg.settle_market(m),
            Err(MarketError::WrongLifecycleState)
        ));
    }

    #[test]
    fn slash_only_objective_and_halts_below_requirement() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let m = MarketId::new(1);
        drive_to_open(&mut reg, 1);
        let insurance_before = reg.insurance();
        // Fraud is a total slash: drops stake to 0 < requirement -> Halted.
        let ev = Hash::from_bytes([1u8; 32]);
        let slashed = reg
            .slash_sponsor(
                m,
                SponsorId::new(1),
                SlashableFault::FraudulentResolution,
                ev,
            )
            .unwrap();
        assert_eq!(slashed, Amount::from_raw(1_000_000));
        assert_eq!(
            reg.insurance(),
            insurance_before.checked_add(slashed).unwrap()
        );
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Halted));
        // Replayed evidence cannot double-slash.
        assert_eq!(
            reg.slash_sponsor(
                m,
                SponsorId::new(1),
                SlashableFault::FraudulentResolution,
                ev
            )
            .unwrap_err(),
            MarketError::Resolution(ResolutionError::DuplicateEvidence)
        );
    }

    #[test]
    fn deterministic_replay_yields_identical_state_root() {
        fn build() -> Hash {
            let mut reg = MarketRegistry::new();
            let cmds = command_log();
            for c in cmds {
                // Some commands intentionally may fail (idempotent replay); ignore.
                let _ = reg.apply(c);
            }
            reg.state_root()
        }
        assert_eq!(build(), build());
    }

    fn command_log() -> Vec<MarketCommand> {
        let m = MarketId::new(1);
        vec![
            MarketCommand::CreateMarket(Box::new(definition(1))),
            MarketCommand::StakeMarket {
                market_id: m,
                sponsor_id: SponsorId::new(1),
                amount: Amount::from_raw(1_000_000),
            },
            MarketCommand::ActivateMarket(m),
            MarketCommand::AddBootstrapLiquidity {
                market_id: m,
                amount: Amount::from_raw(5_000_000),
            },
            MarketCommand::MintCompleteSet {
                market_id: m,
                units: Amount::from_raw(2_000_000),
            },
            MarketCommand::RedeemCompleteSet {
                market_id: m,
                units: Amount::from_raw(1_000_000),
            },
            MarketCommand::CloseMarket {
                market_id: m,
                now: 1_000,
            },
            MarketCommand::BeginResolution(m),
        ]
    }

    #[test]
    fn state_root_changes_with_state() {
        let mut reg = MarketRegistry::new();
        let empty = reg.state_root();
        reg.create_market(definition(1)).unwrap();
        assert_ne!(empty, reg.state_root());
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
    }

    #[test]
    fn property_random_command_streams_never_panic_and_replay() {
        for seed in [1u64, 2, 3, 42, 12345] {
            let mut r = Lcg(seed);
            let mut a = MarketRegistry::new();
            let mut b = MarketRegistry::new();
            let mut log = Vec::new();
            for _ in 0..60 {
                let m = MarketId::new(u32::try_from(r.next_u64() % 3).unwrap());
                let cmd = match r.next_u64() % 8 {
                    0 => MarketCommand::CreateMarket(Box::new(definition(m.get()))),
                    1 => MarketCommand::StakeMarket {
                        market_id: m,
                        sponsor_id: SponsorId::new(1),
                        amount: Amount::from_raw(i128::from(r.next_u64() % 3_000_000)),
                    },
                    2 => MarketCommand::ActivateMarket(m),
                    3 => MarketCommand::AddBootstrapLiquidity {
                        market_id: m,
                        amount: Amount::from_raw(i128::from(r.next_u64() % 6_000_000)),
                    },
                    4 => MarketCommand::HaltMarket(m),
                    5 => MarketCommand::ResumeMarket(m),
                    6 => MarketCommand::MintCompleteSet {
                        market_id: m,
                        units: Amount::from_raw(i128::from(r.next_u64() % 2_000_000)),
                    },
                    _ => MarketCommand::CloseMarket {
                        market_id: m,
                        now: r.next_u64() % 2_000,
                    },
                };
                log.push(cmd);
            }
            for c in &log {
                let _ = a.apply(c.clone());
            }
            for c in &log {
                let _ = b.apply(c.clone());
            }
            assert_eq!(a.state_root(), b.state_root());
        }
    }

    #[test]
    fn never_panics_decoding_arbitrary_definition_and_command_bytes() {
        let mut r = Lcg(0xF00D_BABE);
        for _ in 0..20_000 {
            let len = usize::try_from(r.next_u64() % 256).unwrap();
            let bytes: Vec<u8> = (0..len)
                .map(|_| u8::try_from(r.next_u64() % 256).unwrap())
                .collect();
            let _ = postcard::from_bytes::<MarketDefinition>(&bytes);
            let _ = postcard::from_bytes::<MarketCommand>(&bytes);
            let _ = postcard::from_bytes::<LifecycleEvent>(&bytes);
        }
    }

    #[test]
    fn codec_roundtrip_all_market_types() {
        for market_type in [
            MarketType::Perpetual,
            MarketType::BinaryPrediction,
            MarketType::MultiOutcomePrediction,
            MarketType::Decision,
            MarketType::Sports,
            MarketType::Scalar,
            MarketType::CustomPayoutVector,
        ] {
            let mut def = definition(9);
            def.market_type = market_type;
            let bytes = postcard::to_allocvec(&def).unwrap();
            let decoded: MarketDefinition = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(def, decoded);
            // Bit-identical re-encode.
            assert_eq!(bytes, postcard::to_allocvec(&decoded).unwrap());
        }
    }

    #[test]
    fn codec_roundtrip_varied_sponsor_set_sizes() {
        for n in 1..=8u32 {
            let mut def = definition(1);
            let mut set =
                SponsorSet::new(SponsorShare::new(SponsorId::new(0), Amount::ZERO, 0, 0)).unwrap();
            for i in 1..n {
                set.add_sponsor(SponsorShare::new(
                    SponsorId::new(i),
                    Amount::ZERO,
                    0,
                    u64::from(i),
                ))
                .unwrap();
            }
            def.sponsor_set = set;
            let bytes = postcard::to_allocvec(&def).unwrap();
            let decoded: MarketDefinition = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(def, decoded);
        }
    }
}

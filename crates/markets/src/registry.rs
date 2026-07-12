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
    AccountId, Amount, Hash, MarketId, MarketLifecycle, MarketType, OracleHealth, PayoutVector,
    Price, SequenceNumber, SponsorId,
};

use crate::config::{FeeSchedule, LifecycleConfig, OracleConfig, ResolverConfig, MAX_BPS};
use crate::error::{EscrowError, MarketError, PayoutError, ResolutionError};
use crate::escrow::EscrowLedger;
use crate::lifecycle::{self, HaltReason, HaltState};
use crate::payout::{invalid_refund, CompleteSetPool, PayoutRule, Settlement};
use crate::perpetual::PerpMarketState;
use crate::resolution::{
    Challenge, ChallengeBook, ResolutionCertificate, ResolutionPhase, ResolutionPolicy,
    MAX_CHALLENGES,
};
use crate::sponsor::{AppliedSlash, SlashEvidence, SlashVerifyContext, SponsorSet};

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

/// The per-round resolution progress bound to a market: the committee's proposed
/// (and, once a dispute is adjudicated, final) outcome, the committee-attested
/// challenge deadline, the staked challenge book, and whether adjudication has
/// run. Persisted in the record so every verification input is derived from
/// stored state, never a caller argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ResolutionRoundState {
    /// The round this progress belongs to (must equal the committed policy round).
    round: u64,
    /// The committee-attested first sequence at which finalization is permitted.
    deadline: SequenceNumber,
    /// The proposed outcome; overwritten by the adjudicated outcome on dispute.
    payout: PayoutVector,
    /// The proposal's evidence commitment.
    evidence_hash: Hash,
    /// Staked challenges against the proposal.
    challenges: ChallengeBook,
    /// Whether a challenged round has been deterministically adjudicated.
    adjudicated: bool,
}

/// The internal per-market registry record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MarketRecord {
    definition: MarketDefinition,
    lifecycle: MarketLifecycle,
    bootstrapped: Amount,
    pool: Option<CompleteSetPool>,
    perp: PerpMarketState,
    resolution: Option<PayoutVector>,
    settled: bool,
    /// The immutable, versioned resolution policy this market committed to.
    policy: Option<ResolutionPolicy>,
    /// Progress of the current resolution round, once a proposal is made.
    round_state: Option<ResolutionRoundState>,
    /// Active halt metadata (reason + prior state), present only while Halted.
    halt: Option<HaltState>,
    /// Latest observed price-oracle health for resume gates.
    oracle_health: OracleHealth,
    /// Resting order count reported by the execution layer (liability for archive).
    open_orders: u64,
    /// Outstanding withdrawal claims / locked user collateral units.
    locked_user_collateral: Amount,
}

/// A replayable market command over the lifecycle-management subset. Resolution
/// and settlement, which carry certificates/rules, are applied via dedicated
/// [`MarketRegistry`] methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketCommand {
    /// Credit a deposit into a funding account's available balance. The only
    /// way value enters the market escrow ledger.
    Deposit {
        /// Account to credit.
        account: AccountId,
        /// Amount deposited.
        amount: Amount,
    },
    /// Create a new market in `Draft`.
    CreateMarket(Box<MarketDefinition>),
    /// Post sponsor stake from a funding account; auto-advances
    /// `Draft -> Staked` at the requirement.
    StakeMarket {
        /// Target market.
        market_id: MarketId,
        /// Sponsor posting stake.
        sponsor_id: SponsorId,
        /// Funding account debited for the stake.
        funding_account: AccountId,
        /// Amount posted.
        amount: Amount,
    },
    /// Advance `Staked -> Bootstrapping`.
    ActivateMarket(MarketId),
    /// Add bootstrap liquidity from a funding account; auto-advances
    /// `Bootstrapping -> Open`.
    AddBootstrapLiquidity {
        /// Target market.
        market_id: MarketId,
        /// Funding account debited for the liquidity.
        funding_account: AccountId,
        /// Liquidity added.
        amount: Amount,
    },
    /// Halt an `Open`/`Bootstrapping` market with a typed reason.
    HaltMarket {
        /// Target market.
        market_id: MarketId,
        /// Why the market is halted.
        reason: HaltReason,
    },
    /// Resume a `Halted` market to its prior phase after prerequisite checks.
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
    /// Mint `units` complete sets against locked collateral (market must be
    /// `Open`).
    MintCompleteSet {
        /// Target market.
        market_id: MarketId,
        /// Funding account debited for the collateral.
        funding_account: AccountId,
        /// Complete sets to mint.
        units: Amount,
    },
    /// Redeem `units` complete sets, returning collateral (market must be
    /// `Open`).
    RedeemCompleteSet {
        /// Target market.
        market_id: MarketId,
        /// Account credited with the released collateral.
        recipient: AccountId,
        /// Complete sets to redeem.
        units: Amount,
    },
    /// Archive a `Settled`/`Halted` market.
    ArchiveMarket(MarketId),
}

/// The market registry.
///
/// Every unit of economic value it reports — sponsor stake, bootstrap
/// liquidity, complete-set collateral, insurance, protocol, and dust — is
/// backed one-for-one by the canonical [`EscrowLedger`]. The registry never
/// accepts caller-constructed funded state; totals are derived from committed
/// escrow ([`MarketRegistry::reconciles`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MarketRegistry {
    markets: BTreeMap<MarketId, MarketRecord>,
    events: Vec<LifecycleEvent>,
    next_seq: SequenceNumber,
    /// Domain-bound evidence ids already applied (replay protection).
    applied_evidence: BTreeSet<Hash>,
    /// Portable audit log of verified, applied slashes.
    slash_log: Vec<AppliedSlash>,
    ledger: EscrowLedger,
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

    /// The insurance / backstop balance accumulated from slashing.
    #[must_use]
    pub fn insurance(&self) -> Amount {
        self.ledger.insurance()
    }

    /// The settlement-payable protocol balance.
    #[must_use]
    pub fn protocol(&self) -> Amount {
        self.ledger.protocol()
    }

    /// The accumulated settlement rounding-dust balance.
    #[must_use]
    pub fn dust(&self) -> Amount {
        self.ledger.dust()
    }

    /// The canonical escrow ledger backing every reported total.
    #[must_use]
    pub fn ledger(&self) -> &EscrowLedger {
        &self.ledger
    }

    /// Available (spendable) balance of a funding account.
    ///
    /// # Errors
    /// [`MarketError::Escrow`] if the account was never funded.
    pub fn available(&self, account: AccountId) -> Result<Amount, MarketError> {
        Ok(self.ledger.available(account)?)
    }

    /// Credit a deposit into a funding account. The sole entry point for value
    /// into the market escrow ledger.
    ///
    /// # Errors
    /// [`MarketError::Escrow`] on a negative amount or overflow.
    pub fn deposit(&mut self, account: AccountId, amount: Amount) -> Result<(), MarketError> {
        self.ledger.deposit(account, amount)?;
        Ok(())
    }

    /// Whether every registry total reconciles to committed escrow and the
    /// ledger's global conservation invariant holds. True after every command,
    /// snapshot restore, and settlement.
    #[must_use]
    pub fn reconciles(&self) -> bool {
        if !self.ledger.conservation_holds() {
            return false;
        }
        for (id, record) in &self.markets {
            if self.ledger.sponsor_stake_total(*id) != record.definition.sponsor_set.total_stake() {
                return false;
            }
            if self.ledger.bootstrap(*id) != record.bootstrapped {
                return false;
            }
            // A settled market's collateral has been drained from escrow into
            // the protocol/dust accounts, while the pool retains its historical
            // locked figure for idempotent re-settlement.
            let expected = if record.settled {
                Amount::ZERO
            } else {
                record
                    .pool
                    .as_ref()
                    .map_or(Amount::ZERO, CompleteSetPool::locked_collateral)
            };
            if self.ledger.complete_set(*id) != expected {
                return false;
            }
        }
        true
    }

    /// Serialize the full registry (markets, events, evidence, escrow) into a
    /// canonical snapshot.
    ///
    /// # Errors
    /// [`MarketError::Escrow`] if encoding fails.
    pub fn snapshot(&self) -> Result<Vec<u8>, MarketError> {
        postcard::to_allocvec(self).map_err(|_| MarketError::Escrow(EscrowError::Reconciliation))
    }

    /// Restore a registry from a [`MarketRegistry::snapshot`].
    ///
    /// # Errors
    /// [`MarketError::Escrow`] if the bytes do not decode.
    pub fn restore(bytes: &[u8]) -> Result<Self, MarketError> {
        postcard::from_bytes(bytes).map_err(|_| MarketError::Escrow(EscrowError::Reconciliation))
    }

    // ---- lifecycle handlers ----------------------------------------------

    /// Create a market in `Draft`, enforcing id uniqueness and config bounds.
    ///
    /// The definition may not carry pre-funded sponsor stake: all stake must be
    /// posted through [`MarketRegistry::stake_market`], which debits the
    /// canonical ledger. A founding set with any non-zero stake is rejected.
    ///
    /// # Errors
    /// [`MarketError::DuplicateMarket`]; [`MarketError::ParameterOutOfRange`] on
    /// an invalid fee schedule or negative stake requirement; or
    /// [`MarketError::Escrow`] with [`EscrowError::PrefundedStake`] if any
    /// sponsor arrives already funded.
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
        if definition
            .sponsor_set
            .shares()
            .iter()
            .any(|s| s.stake != Amount::ZERO)
        {
            return Err(MarketError::Escrow(EscrowError::PrefundedStake));
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
            policy: None,
            round_state: None,
            halt: None,
            oracle_health: OracleHealth::Halted,
            open_orders: 0,
            locked_user_collateral: Amount::ZERO,
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

    /// Post sponsor stake, locking `amount` of `funding_account`'s available
    /// balance into the sponsor's stake escrow. Auto-advances `Draft -> Staked`
    /// once the aggregate stake reaches the requirement.
    ///
    /// The stake fails outright if the funding account cannot cover it; no
    /// counter is ever incremented against value that does not exist.
    ///
    /// # Errors
    /// [`MarketError::UnknownMarket`], a wrapped [`crate::SponsorError`], or
    /// [`MarketError::Escrow`] if the funding account lacks the balance.
    pub fn stake_market(
        &mut self,
        market_id: MarketId,
        sponsor_id: SponsorId,
        funding_account: AccountId,
        amount: Amount,
    ) -> Result<Amount, MarketError> {
        let record = self.record_mut(market_id)?;
        // Reject unknown sponsors before touching the ledger.
        if record.definition.sponsor_set.share(sponsor_id).is_none() {
            return Err(MarketError::Sponsor(crate::SponsorError::UnknownSponsor));
        }
        // Lock funds first: an unfunded stake fails here, leaving the sponsor
        // set untouched. The escrow mirrors the sponsor stake exactly, so the
        // subsequent `add_stake` cannot diverge or overflow.
        self.ledger
            .lock_sponsor_stake(market_id, sponsor_id, funding_account, amount)?;
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

    /// Admit an additional sponsor to a market with zero initial stake; stake is
    /// posted afterwards via [`MarketRegistry::stake_market`].
    ///
    /// # Errors
    /// [`MarketError::UnknownMarket`], a wrapped [`crate::SponsorError`], or
    /// [`MarketError::Escrow`] with [`EscrowError::PrefundedStake`] if `share`
    /// carries stake.
    pub fn add_sponsor(
        &mut self,
        market_id: MarketId,
        share: crate::SponsorShare,
    ) -> Result<(), MarketError> {
        if share.stake != Amount::ZERO {
            return Err(MarketError::Escrow(EscrowError::PrefundedStake));
        }
        let record = self.record_mut(market_id)?;
        record.definition.sponsor_set.add_sponsor(share)?;
        Ok(())
    }

    /// Remove a sponsor, refunding its escrowed stake to `refund_account`.
    /// Moves existing escrow; never mints value.
    ///
    /// # Errors
    /// [`MarketError::UnknownMarket`], a wrapped [`crate::SponsorError`]
    /// (owner / empty-set / requirement breach), or [`MarketError::Escrow`].
    pub fn remove_sponsor(
        &mut self,
        market_id: MarketId,
        sponsor_id: SponsorId,
        refund_account: AccountId,
    ) -> Result<Amount, MarketError> {
        let record = self.record(market_id)?;
        let enforce = record.lifecycle != MarketLifecycle::Draft;
        let min_required = record.definition.stake_requirement;
        let record = self.record_mut(market_id)?;
        let refunded =
            record
                .definition
                .sponsor_set
                .remove_sponsor(sponsor_id, min_required, enforce)?;
        self.ledger
            .release_sponsor_stake(market_id, sponsor_id, refund_account, refunded)?;
        Ok(refunded)
    }

    /// Advance `Staked -> Bootstrapping`.
    ///
    /// # Errors
    /// [`MarketError::UnknownMarket`] or [`MarketError::Lifecycle`].
    pub fn activate_market(&mut self, market_id: MarketId) -> Result<(), MarketError> {
        self.transition(market_id, MarketLifecycle::Bootstrapping)
    }

    /// Add bootstrap liquidity, locking `amount` of `funding_account`'s
    /// available balance into the market's bootstrap escrow. Auto-advances
    /// `Bootstrapping -> Open` once the configured threshold is met.
    ///
    /// # Errors
    /// [`MarketError::UnknownMarket`], [`MarketError::WrongLifecycleState`],
    /// [`MarketError::Escrow`] if the funding account lacks the balance, or
    /// arithmetic overflow.
    pub fn add_bootstrap_liquidity(
        &mut self,
        market_id: MarketId,
        funding_account: AccountId,
        amount: Amount,
    ) -> Result<(), MarketError> {
        let record = self.record(market_id)?;
        if record.lifecycle != MarketLifecycle::Bootstrapping {
            return Err(MarketError::WrongLifecycleState);
        }
        self.ledger
            .lock_bootstrap(market_id, funding_account, amount)?;
        let record = self.record_mut(market_id)?;
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

    /// Halt an `Open` or `Bootstrapping` market with a typed reason. Persists
    /// the prior lifecycle so resume cannot skip bootstrapping.
    ///
    /// # Errors
    /// [`MarketError::Lifecycle`] if not haltable.
    pub fn halt_market(
        &mut self,
        market_id: MarketId,
        reason: HaltReason,
    ) -> Result<(), MarketError> {
        let record = self.record(market_id)?;
        let prior = record.lifecycle;
        if !matches!(
            prior,
            MarketLifecycle::Open | MarketLifecycle::Bootstrapping
        ) {
            return Err(MarketError::Lifecycle(crate::LifecycleError::IllegalTransition {
                from: prior,
                to: MarketLifecycle::Halted,
            }));
        }
        self.transition(market_id, MarketLifecycle::Halted)?;
        let record = self.record_mut(market_id)?;
        record.halt = Some(HaltState::new(reason, prior));
        Ok(())
    }

    /// Resume a `Halted` market to its prior phase after revalidating stake,
    /// bootstrap liquidity, and oracle health. Never opens a market that was
    /// halted during bootstrapping.
    ///
    /// # Errors
    /// [`MarketError::ResumePrerequisites`], [`MarketError::OracleUnhealthy`],
    /// or [`MarketError::Lifecycle`].
    pub fn resume_market(&mut self, market_id: MarketId) -> Result<(), MarketError> {
        let record = self.record(market_id)?;
        if record.lifecycle != MarketLifecycle::Halted {
            return Err(MarketError::Lifecycle(crate::LifecycleError::IllegalTransition {
                from: record.lifecycle,
                to: MarketLifecycle::Open,
            }));
        }
        let halt = record.halt.ok_or(MarketError::ResumePrerequisites)?;
        let target = halt.resume_target().ok_or(MarketError::ResumePrerequisites)?;

        // Stake must still meet the requirement.
        let stake_ok = record.definition.sponsor_set.total_stake().raw()
            >= record.definition.stake_requirement.raw();
        if !stake_ok {
            return Err(MarketError::ResumePrerequisites);
        }
        // Resuming to Open requires bootstrap threshold and a usable oracle.
        if target == MarketLifecycle::Open {
            let boot_ok = record.bootstrapped.raw()
                >= record
                    .definition
                    .lifecycle_config
                    .bootstrap_liquidity_threshold
                    .raw();
            if !boot_ok {
                return Err(MarketError::ResumePrerequisites);
            }
            if matches!(
                record.oracle_health,
                OracleHealth::Halted | OracleHealth::Stale
            ) {
                return Err(MarketError::OracleUnhealthy);
            }
            // Oracle-unhealthy halt cannot clear while still unhealthy.
            if halt.reason == HaltReason::OracleUnhealthy
                && record.oracle_health != OracleHealth::Normal
                && record.oracle_health != OracleHealth::Degraded
            {
                return Err(MarketError::OracleUnhealthy);
            }
        }
        self.transition(market_id, target)?;
        let record = self.record_mut(market_id)?;
        record.halt = None;
        Ok(())
    }

    /// Update the observed price-oracle health for resume / trading gates.
    pub fn set_oracle_health(
        &mut self,
        market_id: MarketId,
        health: OracleHealth,
    ) -> Result<(), MarketError> {
        let record = self.record_mut(market_id)?;
        record.oracle_health = health;
        Ok(())
    }

    /// Report resting order count (from the execution book) for archive gates.
    pub fn set_open_orders(
        &mut self,
        market_id: MarketId,
        open_orders: u64,
    ) -> Result<(), MarketError> {
        let record = self.record_mut(market_id)?;
        record.open_orders = open_orders;
        Ok(())
    }

    /// Report locked user collateral outstanding against this market.
    pub fn set_locked_user_collateral(
        &mut self,
        market_id: MarketId,
        amount: Amount,
    ) -> Result<(), MarketError> {
        if amount.is_negative() {
            return Err(MarketError::ParameterOutOfRange);
        }
        let record = self.record_mut(market_id)?;
        record.locked_user_collateral = amount;
        Ok(())
    }

    /// Apply a sequenced perpetual funding epoch exactly once.
    pub fn apply_funding_epoch(
        &mut self,
        market_id: MarketId,
        epoch: u64,
        rate: types::Ratio,
        mark: Price,
    ) -> Result<crate::FundingEpochReceipt, MarketError> {
        let record = self.record_mut(market_id)?;
        Ok(record.perp.apply_funding_epoch(epoch, rate, mark)?)
    }

    /// The halt state of a market, if currently halted.
    #[must_use]
    pub fn halt_state(&self, market_id: MarketId) -> Option<HaltState> {
        self.markets.get(&market_id).and_then(|r| r.halt)
    }

    /// Observed oracle health for a market.
    #[must_use]
    pub fn oracle_health(&self, market_id: MarketId) -> Option<OracleHealth> {
        self.markets.get(&market_id).map(|r| r.oracle_health)
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

    /// Archive a `Settled` (or abandoned `Halted`) market only when liabilities
    /// are zero: no open orders, no complete-set claims, no locked user
    /// collateral, no open disputes, and escrow is fully released (or the
    /// market completed a forced invalid/refund settlement).
    ///
    /// # Errors
    /// [`MarketError::ArchiveLiabilities`] or [`MarketError::Lifecycle`].
    pub fn archive_market(&mut self, market_id: MarketId) -> Result<(), MarketError> {
        let record = self.record(market_id)?;
        if record.open_orders != 0 {
            return Err(MarketError::ArchiveLiabilities);
        }
        if record.locked_user_collateral.raw() != 0 {
            return Err(MarketError::ArchiveLiabilities);
        }
        if let Some(pool) = &record.pool {
            if pool.outstanding().iter().any(|a| a.raw() != 0) {
                return Err(MarketError::ArchiveLiabilities);
            }
        }
        // Open dispute / unresolved challenge blocks archive.
        if let Some(rs) = &record.round_state {
            if !rs.challenges.is_empty() && !rs.adjudicated {
                return Err(MarketError::ArchiveLiabilities);
            }
        }
        if record.lifecycle == MarketLifecycle::Halted {
            // Abandoned halt: require no sponsor stake still locked and no
            // bootstrap escrow (forced clear). Settled path uses Settled state.
            let stake = record.definition.sponsor_set.total_stake();
            if stake.raw() != 0 || record.bootstrapped.raw() != 0 {
                return Err(MarketError::ArchiveLiabilities);
            }
        }
        self.transition(market_id, MarketLifecycle::Archived)?;
        let record = self.record_mut(market_id)?;
        record.halt = None;
        Ok(())
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

    /// Mint `units` complete sets, locking `units` of `funding_account`'s
    /// available balance as collateral. Requires an `Open` market with an
    /// enumerable payout rule.
    ///
    /// # Errors
    /// [`MarketError::WrongLifecycleState`] if not `Open`; [`MarketError::Payout`]
    /// for a non-enumerable rule or a non-positive unit count;
    /// [`MarketError::Escrow`] if the funding account lacks the collateral.
    pub fn mint_complete_set(
        &mut self,
        market_id: MarketId,
        funding_account: AccountId,
        units: Amount,
    ) -> Result<(), MarketError> {
        let record = self.record(market_id)?;
        if record.lifecycle != MarketLifecycle::Open {
            return Err(MarketError::WrongLifecycleState);
        }
        if record.pool.is_none() {
            return Err(MarketError::Payout(PayoutError::NonEnumerable));
        }
        // Reject a non-positive count before locking; the escrow lock must
        // mirror exactly the collateral the pool commits.
        if units.raw() <= 0 {
            return Err(MarketError::Payout(PayoutError::NonPositiveUnits));
        }
        self.ledger
            .lock_complete_set(market_id, funding_account, units)?;
        let record = self.record_mut(market_id)?;
        let pool = record.pool.as_mut().ok_or(PayoutError::NonEnumerable)?;
        pool.mint(units)?;
        Ok(())
    }

    /// Redeem `units` complete sets, releasing the collateral to `recipient`.
    /// Requires an `Open` market.
    ///
    /// # Errors
    /// As [`MarketRegistry::mint_complete_set`], plus insufficient-claim /
    /// insufficient-collateral payout errors. Escrow is only moved once the
    /// pool has accepted the burn, so a rejected redeem never touches balances.
    pub fn redeem_complete_set(
        &mut self,
        market_id: MarketId,
        recipient: AccountId,
        units: Amount,
    ) -> Result<(), MarketError> {
        let record = self.record_mut(market_id)?;
        if record.lifecycle != MarketLifecycle::Open {
            return Err(MarketError::WrongLifecycleState);
        }
        let pool = record.pool.as_mut().ok_or(PayoutError::NonEnumerable)?;
        pool.redeem(units)?;
        self.ledger
            .release_complete_set(market_id, recipient, units)?;
        Ok(())
    }

    // ---- resolution & settlement -----------------------------------------

    /// Commit the immutable, versioned [`ResolutionPolicy`] a market resolves
    /// under. The committed policy is the *sole* source of truth for later
    /// certificate verification; a caller can never supply a rule or committee at
    /// resolution time.
    ///
    /// Allowed once, before the resolution round begins (any state up to and
    /// including `PendingResolution`, before a proposal exists). Replacing a
    /// committed policy is only possible via the explicit
    /// [`MarketRegistry::rotate_resolution_policy`] transition.
    ///
    /// # Errors
    /// [`MarketError::UnknownMarket`]; [`MarketError::WrongLifecycleState`] once
    /// resolution is under way or the market is terminal; or
    /// [`MarketError::Resolution`] with
    /// [`ResolutionError::PolicyAlreadyCommitted`].
    pub fn commit_resolution_policy(
        &mut self,
        market_id: MarketId,
        policy: ResolutionPolicy,
    ) -> Result<(), MarketError> {
        let record = self.record_mut(market_id)?;
        if record.policy.is_some() {
            return Err(MarketError::Resolution(
                ResolutionError::PolicyAlreadyCommitted,
            ));
        }
        if !Self::policy_mutable(record.lifecycle) {
            return Err(MarketError::WrongLifecycleState);
        }
        record.policy = Some(policy);
        Ok(())
    }

    /// Rotate the committed resolution policy to an explicit successor generation.
    ///
    /// The successor's version and round strictly advance
    /// ([`ResolutionPolicy::rotate`]), so a rotation can never rewrite or re-open
    /// a past round. Any in-flight proposal for the old round is discarded and a
    /// fresh proposal is required. Permitted only before finalization and never
    /// while a dispute is open.
    ///
    /// # Errors
    /// [`MarketError::UnknownMarket`]; [`MarketError::WrongLifecycleState`] once
    /// the market is disputed/resolved/settled/archived; or
    /// [`MarketError::Resolution`] with [`ResolutionError::PolicyNotCommitted`].
    pub fn rotate_resolution_policy(
        &mut self,
        market_id: MarketId,
        committee: crypto::ValidatorSet,
        challenge_window: u64,
        rules_hash: Hash,
        expiry: SequenceNumber,
    ) -> Result<(), MarketError> {
        let record = self.record_mut(market_id)?;
        if !Self::policy_mutable(record.lifecycle) {
            return Err(MarketError::WrongLifecycleState);
        }
        let current = record
            .policy
            .as_ref()
            .ok_or(ResolutionError::PolicyNotCommitted)?;
        let rotated = current.rotate(committee, challenge_window, rules_hash, expiry);
        record.policy = Some(rotated);
        // A rotation opens a new round; discard any stale in-flight proposal so
        // it cannot be finalized against the successor policy.
        record.round_state = None;
        Ok(())
    }

    /// States in which the committed policy may still be set or rotated: before
    /// resolution is under way and never once a dispute is open or the market is
    /// terminal.
    fn policy_mutable(lifecycle: MarketLifecycle) -> bool {
        matches!(
            lifecycle,
            MarketLifecycle::Draft
                | MarketLifecycle::Staked
                | MarketLifecycle::Bootstrapping
                | MarketLifecycle::Open
                | MarketLifecycle::Halted
                | MarketLifecycle::Closed
                | MarketLifecycle::PendingResolution
        )
    }

    /// Propose a committee-certified outcome, opening the challenge window.
    ///
    /// The certificate is verified against the market's *committed* policy and
    /// round via [`ResolutionCertificate::verify`]; no caller-supplied rule is
    /// accepted. The committee-attested `challenge_deadline` must grant at least
    /// the committed challenge window measured from `now`, and finalization is
    /// impossible before it. The market stays `PendingResolution` while the
    /// window is open.
    ///
    /// # Errors
    /// [`MarketError::WrongLifecycleState`] if not `PendingResolution`, or
    /// [`MarketError::Resolution`] for a missing/expired policy, a wrong phase, an
    /// existing proposal, a too-short deadline, or a certificate that fails
    /// verification.
    pub fn propose_resolution(
        &mut self,
        market_id: MarketId,
        certificate: &ResolutionCertificate,
        now: SequenceNumber,
    ) -> Result<(), MarketError> {
        let record = self.record(market_id)?;
        if record.lifecycle != MarketLifecycle::PendingResolution {
            return Err(MarketError::WrongLifecycleState);
        }
        if record.round_state.is_some() {
            return Err(MarketError::Resolution(ResolutionError::ProposalExists));
        }
        let policy = record
            .policy
            .as_ref()
            .ok_or(ResolutionError::PolicyNotCommitted)?;
        if now.get() >= policy.expiry().get() {
            return Err(MarketError::Resolution(ResolutionError::PolicyExpired));
        }
        if certificate.phase != ResolutionPhase::Propose {
            return Err(MarketError::Resolution(ResolutionError::PhaseMismatch));
        }
        let expected = record
            .definition
            .num_outcomes()
            .ok_or(PayoutError::NonEnumerable)?;
        certificate.verify(policy, market_id, expected)?;
        // The committee must grant at least the committed window from now.
        let earliest = now
            .get()
            .checked_add(policy.challenge_window())
            .ok_or(ResolutionError::WindowTooShort)?;
        if certificate.challenge_deadline.get() < earliest {
            return Err(MarketError::Resolution(ResolutionError::WindowTooShort));
        }
        let round = policy.round();
        let deadline = certificate.challenge_deadline;
        let payout = certificate.payout.clone();
        let evidence_hash = certificate.evidence_hash;
        let record = self.record_mut(market_id)?;
        record.round_state = Some(ResolutionRoundState {
            round,
            deadline,
            payout,
            evidence_hash,
            challenges: ChallengeBook::new(MAX_CHALLENGES),
            adjudicated: false,
        });
        Ok(())
    }

    /// Submit a staked challenge against the pending proposal, moving the market
    /// to `Disputed`. Accepted only while the committee-attested challenge window
    /// is open; an open challenge blocks finalization until deterministic
    /// adjudication.
    ///
    /// # Errors
    /// [`MarketError::WrongLifecycleState`]; or [`MarketError::Resolution`] with
    /// [`ResolutionError::NoProposal`], [`ResolutionError::WindowClosed`], or
    /// [`ResolutionError::ChallengeQueueFull`].
    pub fn submit_challenge(
        &mut self,
        market_id: MarketId,
        challenger: AccountId,
        bond: Amount,
        evidence_hash: Hash,
        now: SequenceNumber,
    ) -> Result<(), MarketError> {
        let record = self.record_mut(market_id)?;
        if !matches!(
            record.lifecycle,
            MarketLifecycle::PendingResolution | MarketLifecycle::Disputed
        ) {
            return Err(MarketError::WrongLifecycleState);
        }
        let round_state = record
            .round_state
            .as_mut()
            .ok_or(ResolutionError::NoProposal)?;
        if now.get() >= round_state.deadline.get() {
            return Err(MarketError::Resolution(ResolutionError::WindowClosed));
        }
        round_state.challenges.submit(Challenge {
            challenger,
            bond,
            evidence_hash,
            submitted_at: now,
        })?;
        let was_pending = record.lifecycle == MarketLifecycle::PendingResolution;
        if was_pending {
            self.transition(market_id, MarketLifecycle::Disputed)?;
        }
        Ok(())
    }

    /// Deterministically adjudicate a disputed round with a committee
    /// adjudication certificate, recording the final outcome and clearing the
    /// challenge book. Permitted only after the challenge window closes and bound
    /// to that exact window; the certificate is verified against the committed
    /// policy just like a proposal.
    ///
    /// # Errors
    /// [`MarketError::WrongLifecycleState`] if not `Disputed`; or
    /// [`MarketError::Resolution`] for a missing policy/proposal, a still-open
    /// window, a wrong phase/round, or a certificate that fails verification.
    pub fn adjudicate_resolution(
        &mut self,
        market_id: MarketId,
        certificate: &ResolutionCertificate,
        now: SequenceNumber,
    ) -> Result<(), MarketError> {
        let record = self.record(market_id)?;
        if record.lifecycle != MarketLifecycle::Disputed {
            return Err(MarketError::WrongLifecycleState);
        }
        let policy = record
            .policy
            .as_ref()
            .ok_or(ResolutionError::PolicyNotCommitted)?;
        let round_state = record
            .round_state
            .as_ref()
            .ok_or(ResolutionError::NoProposal)?;
        if now.get() < round_state.deadline.get() {
            return Err(MarketError::Resolution(ResolutionError::WindowOpen));
        }
        if certificate.phase != ResolutionPhase::Adjudicate {
            return Err(MarketError::Resolution(ResolutionError::PhaseMismatch));
        }
        // Bind the adjudication certificate to this exact round's window.
        if certificate.challenge_deadline != round_state.deadline {
            return Err(MarketError::Resolution(ResolutionError::RoundMismatch));
        }
        let expected = record
            .definition
            .num_outcomes()
            .ok_or(PayoutError::NonEnumerable)?;
        certificate.verify(policy, market_id, expected)?;
        let payout = certificate.payout.clone();
        let record = self.record_mut(market_id)?;
        let round_state = record
            .round_state
            .as_mut()
            .ok_or(ResolutionError::NoProposal)?;
        round_state.payout = payout;
        round_state.adjudicated = true;
        let _ = round_state.challenges.drain();
        Ok(())
    }

    /// Finalize a resolution once its challenge window has closed, committing the
    /// outcome bound into stored round state and advancing to `Resolved`.
    ///
    /// Takes no certificate or rule: the outcome is exactly the one the committee
    /// certified (and, on a dispute, that adjudication settled). Finalization
    /// before the committed deadline is impossible, and a disputed round cannot
    /// finalize until it is adjudicated.
    ///
    /// # Errors
    /// [`MarketError::WrongLifecycleState`]; or [`MarketError::Resolution`] with
    /// [`ResolutionError::NoProposal`], [`ResolutionError::WindowOpen`], or
    /// [`ResolutionError::UnresolvedChallenge`].
    pub fn finalize_resolution(
        &mut self,
        market_id: MarketId,
        now: SequenceNumber,
    ) -> Result<(), MarketError> {
        let record = self.record(market_id)?;
        let round_state = record
            .round_state
            .as_ref()
            .ok_or(ResolutionError::NoProposal)?;
        if now.get() < round_state.deadline.get() {
            return Err(MarketError::Resolution(ResolutionError::WindowOpen));
        }
        match record.lifecycle {
            MarketLifecycle::PendingResolution => {}
            MarketLifecycle::Disputed => {
                if !round_state.adjudicated {
                    return Err(MarketError::Resolution(
                        ResolutionError::UnresolvedChallenge,
                    ));
                }
            }
            _ => return Err(MarketError::WrongLifecycleState),
        }
        let outcome = round_state.payout.clone();
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

    /// Settle a `Resolved`/`Invalid` market: drain the complete-set collateral
    /// escrow, routing the credited total to the protocol settlement-payable
    /// account and the rounding dust to the dust account.
    ///
    /// Idempotent: re-invoking after settlement recomputes the same
    /// [`Settlement`] without mutating state or the ledger.
    ///
    /// # Errors
    /// [`MarketError::WrongLifecycleState`] if not settleable;
    /// [`MarketError::Payout`] if no resolution outcome / non-enumerable pool;
    /// [`MarketError::Escrow`] if the escrow fails to reconcile.
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
        // Move existing collateral escrow into protocol/dust before committing
        // the transition; a reconciliation failure aborts without side effects.
        self.ledger
            .settle_complete_set(market_id, settlement.total_credited, settlement.dust)?;
        self.transition(market_id, MarketLifecycle::Settled)?;
        let record = self.record_mut(market_id)?;
        record.settled = true;
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

    /// Slash a sponsor only after objective [`SlashEvidence`] verifies.
    ///
    /// Order of effects (same transaction):
    /// 1. Verify typed evidence (signatures, domain binding, fault predicates).
    /// 2. Reject replays via the domain-bound [`SlashEvidence::evidence_id`].
    /// 3. Reduce sponsor stake, debit escrow into insurance, then mark the
    ///    evidence applied and append a portable audit record.
    ///
    /// Invalid evidence leaves stake, insurance, lifecycle, and replay state
    /// unchanged. If aggregate stake falls below the requirement on an active
    /// market, it deterministically transitions to `Halted`.
    ///
    /// # Errors
    /// [`MarketError::Sponsor`] (including evidence failures),
    /// [`MarketError::Resolution`] with `DuplicateEvidence`,
    /// [`MarketError::UnknownMarket`], or escrow errors.
    pub fn slash_sponsor(
        &mut self,
        market_id: MarketId,
        sponsor_id: SponsorId,
        evidence: &SlashEvidence,
    ) -> Result<Amount, MarketError> {
        // Fraud-against-state needs the market's finalized payout commitment.
        let finalized = self
            .markets
            .get(&market_id)
            .and_then(|r| r.resolution.as_ref())
            .map(finalized_payout_commitment);
        let ctx = SlashVerifyContext {
            finalized_payout_hash: finalized,
        };

        // 1. Verify first — no stake, escrow, or replay mutation on failure.
        evidence.verify(market_id, sponsor_id, ctx)?;

        let evidence_id = evidence.evidence_id(market_id, sponsor_id);
        // 2. Replay check before any economic move.
        if self.applied_evidence.contains(&evidence_id) {
            return Err(MarketError::Resolution(ResolutionError::DuplicateEvidence));
        }

        let fault = evidence.fault();
        let deployment = evidence.deployment();
        let epoch = evidence.epoch();

        // Ensure the sponsor is present and escrow can cover the penalty before
        // mutating either side (keeps ledger + sponsor set locked together).
        let record = self
            .markets
            .get(&market_id)
            .ok_or(MarketError::UnknownMarket)?;
        let stake = record
            .definition
            .sponsor_set
            .share(sponsor_id)
            .ok_or(MarketError::Sponsor(crate::error::SponsorError::UnknownSponsor))?
            .stake;
        // Preview the penalty without mutating, using the same bps math as slash.
        let ratio = types::Ratio::from_bps(i64::from(fault.penalty_bps()))?;
        let mut expected = stake.mul_ratio(ratio)?;
        if expected.raw() > stake.raw() {
            expected = stake;
        }
        let escrowed = self.ledger.sponsor_stake(market_id, sponsor_id);
        if escrowed.raw() < expected.raw() {
            // Should be unreachable when reconciles() holds; refuse rather than
            // partially apply.
            return Err(MarketError::Escrow(EscrowError::InsufficientEscrow));
        }

        // 3. Apply stake reduction, then escrow debit, then mark replay.
        let record = self.record_mut(market_id)?;
        let slashed = record.definition.sponsor_set.slash(sponsor_id, fault)?;
        debug_assert_eq!(slashed, expected);
        let below = record.definition.sponsor_set.total_stake().raw()
            < record.definition.stake_requirement.raw();
        let current = record.lifecycle;

        self.ledger
            .slash_sponsor_stake(market_id, sponsor_id, slashed)?;

        // Mark replay + audit only after both economic mutations succeeded.
        self.applied_evidence.insert(evidence_id);
        self.slash_log.push(AppliedSlash {
            evidence_id,
            market_id,
            sponsor_id,
            fault,
            deployment,
            epoch,
            amount: slashed,
        });

        if below && lifecycle::is_legal_transition(current, MarketLifecycle::Halted) {
            self.transition(market_id, MarketLifecycle::Halted)?;
        }
        Ok(slashed)
    }

    /// Portable audit log of verified, applied sponsor slashes.
    #[must_use]
    pub fn slash_log(&self) -> &[AppliedSlash] {
        &self.slash_log
    }

    /// Whether a domain-bound evidence id has already been applied.
    #[must_use]
    pub fn evidence_applied(&self, evidence_id: Hash) -> bool {
        self.applied_evidence.contains(&evidence_id)
    }

    // ---- command replay ---------------------------------------------------

    /// Apply one replayable [`MarketCommand`].
    ///
    /// # Errors
    /// The command's underlying handler error.
    pub fn apply(&mut self, command: MarketCommand) -> Result<(), MarketError> {
        match command {
            MarketCommand::Deposit { account, amount } => self.deposit(account, amount),
            MarketCommand::CreateMarket(def) => self.create_market(*def),
            MarketCommand::StakeMarket {
                market_id,
                sponsor_id,
                funding_account,
                amount,
            } => self
                .stake_market(market_id, sponsor_id, funding_account, amount)
                .map(|_| ()),
            MarketCommand::ActivateMarket(id) => self.activate_market(id),
            MarketCommand::AddBootstrapLiquidity {
                market_id,
                funding_account,
                amount,
            } => self.add_bootstrap_liquidity(market_id, funding_account, amount),
            MarketCommand::HaltMarket { market_id, reason } => {
                self.halt_market(market_id, reason)
            }
            MarketCommand::ResumeMarket(id) => self.resume_market(id),
            MarketCommand::CloseMarket { market_id, now } => self.close_market(market_id, now),
            MarketCommand::BeginResolution(id) => self.begin_resolution(id),
            MarketCommand::MintCompleteSet {
                market_id,
                funding_account,
                units,
            } => self.mint_complete_set(market_id, funding_account, units),
            MarketCommand::RedeemCompleteSet {
                market_id,
                recipient,
                units,
            } => self.redeem_complete_set(market_id, recipient, units),
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
            &self.ledger,
            &self.applied_evidence,
            &self.slash_log,
        );
        match postcard::to_allocvec(&snapshot) {
            Ok(bytes) => hash_domain(DOMAIN_MARKET, &bytes),
            Err(_) => Hash::ZERO,
        }
    }
}

/// Canonical commitment over a finalized payout vector for fraud evidence.
fn finalized_payout_commitment(payout: &PayoutVector) -> Hash {
    let mut buf = Vec::with_capacity(payout.len() * 16);
    for v in payout.values() {
        buf.extend_from_slice(&v.raw().to_le_bytes());
    }
    hash_domain(crate::sponsor::SPONSOR_MESSAGE_DOMAIN, &buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payout::winner_takes_all;
    use crate::resolution::resolution_message;
    use crate::sponsor::{
        config_payload_hash, resolution_payload_hash, sponsor_msg_kind, SignedSponsorMessage,
        SponsorShare,
    };
    use crypto::{KeyPair, ThresholdSigners};
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

    fn acct(n: u32) -> AccountId {
        AccountId::new(n)
    }

    /// The shared funding account used by the lifecycle helpers.
    const TREASURY: u32 = 100;

    /// Fund the treasury, stake to `Staked`, activate, and bootstrap to `Open`,
    /// leaving every reported total reconciled to committed escrow.
    fn drive_to_open(reg: &mut MarketRegistry, id: u32) {
        let m = MarketId::new(id);
        let t = acct(TREASURY);
        reg.deposit(t, Amount::from_raw(100_000_000)).unwrap();
        reg.stake_market(m, SponsorId::new(1), t, Amount::from_raw(1_000_000))
            .unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Staked));
        reg.activate_market(m).unwrap();
        reg.add_bootstrap_liquidity(m, t, Amount::from_raw(5_000_000))
            .unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Open));
        assert!(reg.reconciles());
    }

    /// The standard 3-of-4 resolution committee used by the resolution tests.
    fn resolution_committee() -> ThresholdSigners {
        ThresholdSigners::from_seeds(&[[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]], 3)
    }

    /// A committed policy on deployment 7, round 0, with a 50-tick challenge
    /// window and a far expiry.
    fn test_policy(ts: &ThresholdSigners) -> ResolutionPolicy {
        ResolutionPolicy::new(
            1,
            0,
            7,
            ts.validator_set(),
            50,
            Hash::ZERO,
            SequenceNumber::new(1_000_000),
        )
    }

    /// Build a committee certificate bound to `policy` for `phase`/`deadline`.
    fn make_cert(
        ts: &ThresholdSigners,
        m: MarketId,
        policy: &ResolutionPolicy,
        deadline: SequenceNumber,
        phase: ResolutionPhase,
        payout: PayoutVector,
        ev: Hash,
    ) -> ResolutionCertificate {
        let msg = resolution_message(
            m,
            policy.commitment(),
            policy.round(),
            deadline,
            phase,
            &payout,
            ev,
        );
        let qc = ts.sign(msg, vec![0, 1, 2]);
        ResolutionCertificate::new(
            m,
            policy.commitment(),
            policy.round(),
            deadline,
            phase,
            payout,
            ev,
            qc,
        )
    }

    /// Drive a fresh market with `collateral` minted to `Closed -> PendingResolution`
    /// and commit `policy`, ready for a proposal.
    fn drive_to_pending(
        reg: &mut MarketRegistry,
        id: u32,
        collateral: Amount,
        policy: ResolutionPolicy,
    ) -> MarketId {
        let m = MarketId::new(id);
        drive_to_open(reg, id);
        reg.mint_complete_set(m, acct(TREASURY), collateral)
            .unwrap();
        reg.close_market(m, 1_000).unwrap();
        reg.begin_resolution(m).unwrap();
        reg.commit_resolution_policy(m, policy).unwrap();
        m
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
        let t = acct(TREASURY);
        reg.deposit(t, Amount::from_raw(10_000_000)).unwrap();
        reg.stake_market(m, SponsorId::new(1), t, Amount::from_raw(1_000_000))
            .unwrap();
        reg.activate_market(m).unwrap();
        // Below the 5.0 threshold stays in Bootstrapping and rejects minting.
        reg.add_bootstrap_liquidity(m, t, Amount::from_raw(1_000_000))
            .unwrap();
        assert_eq!(
            reg.get_market_status(m),
            Some(MarketLifecycle::Bootstrapping)
        );
        assert_eq!(
            reg.mint_complete_set(m, t, Amount::from_raw(1_000_000))
                .unwrap_err(),
            MarketError::WrongLifecycleState
        );
        // Crossing the threshold opens it.
        reg.add_bootstrap_liquidity(m, t, Amount::from_raw(4_000_000))
            .unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Open));
        assert!(reg.reconciles());
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
        let ts = resolution_committee();
        let policy = test_policy(&ts);
        let m = drive_to_pending(&mut reg, 1, Amount::from_raw(3_000_000), policy.clone());

        // Propose a committee-certified outcome (outcome 0 pays 1.0) under the
        // committed policy, opening the challenge window.
        let payout = winner_takes_all(2, 0).unwrap();
        let ev = Hash::from_bytes([7u8; 32]);
        let now = SequenceNumber::new(100);
        let deadline = SequenceNumber::new(150);
        let cert = make_cert(
            &ts,
            m,
            &policy,
            deadline,
            ResolutionPhase::Propose,
            payout,
            ev,
        );
        reg.propose_resolution(m, &cert, now).unwrap();
        // The market stays pending until the committee-attested window closes.
        assert_eq!(
            reg.get_market_status(m),
            Some(MarketLifecycle::PendingResolution)
        );
        // Finalizing before the committed deadline is impossible.
        assert_eq!(
            reg.finalize_resolution(m, SequenceNumber::new(149))
                .unwrap_err(),
            MarketError::Resolution(ResolutionError::WindowOpen)
        );
        reg.finalize_resolution(m, deadline).unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Resolved));

        // Escrow before settlement holds exactly the minted collateral.
        assert_eq!(reg.ledger().complete_set(m), Amount::from_raw(3_000_000));
        let s1 = reg.settle_market(m).unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Settled));
        // 3 complete sets, outcome 0 pays 1.0 each -> 3.0 credited, no dust.
        assert_eq!(s1.total_credited, Amount::from_raw(3_000_000));
        assert_eq!(s1.dust, Amount::ZERO);
        // Settlement moved the collateral escrow into the protocol account; the
        // dust account stayed empty; nothing was created.
        assert_eq!(reg.ledger().complete_set(m), Amount::ZERO);
        assert_eq!(reg.protocol(), Amount::from_raw(3_000_000));
        assert_eq!(reg.dust(), Amount::ZERO);
        assert!(reg.reconciles());
        // Idempotent re-settle: same result, still Settled, ledger untouched.
        let s2 = reg.settle_market(m).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Settled));
        assert_eq!(reg.protocol(), Amount::from_raw(3_000_000));
        assert!(reg.reconciles());
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
    fn propose_binds_stored_committee_market_and_window() {
        // Criteria: a certificate under a noncommitted committee/market is
        // rejected, and a caller cannot substitute a rule — verification always
        // uses the market's stored policy.
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let ts = resolution_committee();
        let policy = test_policy(&ts);
        let m = drive_to_pending(&mut reg, 1, Amount::from_raw(3_000_000), policy.clone());
        let payout = winner_takes_all(2, 0).unwrap();
        let ev = Hash::from_bytes([7u8; 32]);
        let now = SequenceNumber::new(100);
        let deadline = SequenceNumber::new(150);

        // A certificate the market's committee never signed (a different, caller
        // "supplied" committee) names the correct policy commitment but fails the
        // stored committee's quorum check.
        let impostor =
            ThresholdSigners::from_seeds(&[[9u8; 32], [8u8; 32], [7u8; 32], [6u8; 32]], 3);
        let forged = make_cert(
            &impostor,
            m,
            &policy,
            deadline,
            ResolutionPhase::Propose,
            payout.clone(),
            ev,
        );
        assert!(matches!(
            reg.propose_resolution(m, &forged, now),
            Err(MarketError::Resolution(ResolutionError::Quorum(_)))
        ));

        // A certificate naming a different market is rejected.
        let wrong_market = make_cert(
            &ts,
            MarketId::new(999),
            &policy,
            deadline,
            ResolutionPhase::Propose,
            payout.clone(),
            ev,
        );
        assert_eq!(
            reg.propose_resolution(m, &wrong_market, now).unwrap_err(),
            MarketError::Resolution(ResolutionError::MarketIdMismatch)
        );

        // A deadline shorter than the committed 50-tick window is rejected.
        let short = make_cert(
            &ts,
            m,
            &policy,
            SequenceNumber::new(149),
            ResolutionPhase::Propose,
            payout.clone(),
            ev,
        );
        assert_eq!(
            reg.propose_resolution(m, &short, now).unwrap_err(),
            MarketError::Resolution(ResolutionError::WindowTooShort)
        );

        // None of the rejected attempts recorded a proposal; a valid one still works.
        let good = make_cert(
            &ts,
            m,
            &policy,
            deadline,
            ResolutionPhase::Propose,
            payout,
            ev,
        );
        reg.propose_resolution(m, &good, now).unwrap();
        assert_eq!(
            reg.get_market_status(m),
            Some(MarketLifecycle::PendingResolution)
        );
    }

    #[test]
    fn open_challenge_blocks_finalization_until_adjudication() {
        // Criterion: an open challenge blocks finalization until deterministic
        // adjudication.
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let ts = resolution_committee();
        let policy = test_policy(&ts);
        let m = drive_to_pending(&mut reg, 1, Amount::from_raw(3_000_000), policy.clone());
        let ev = Hash::from_bytes([7u8; 32]);
        let now = SequenceNumber::new(100);
        let deadline = SequenceNumber::new(150);

        // Propose outcome 0.
        let cert = make_cert(
            &ts,
            m,
            &policy,
            deadline,
            ResolutionPhase::Propose,
            winner_takes_all(2, 0).unwrap(),
            ev,
        );
        reg.propose_resolution(m, &cert, now).unwrap();

        // A challenge inside the window moves the market to Disputed.
        reg.submit_challenge(
            m,
            acct(500),
            Amount::from_raw(1_000_000),
            Hash::from_bytes([2u8; 32]),
            SequenceNumber::new(120),
        )
        .unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Disputed));

        // Challenges after the window closes are rejected.
        assert_eq!(
            reg.submit_challenge(
                m,
                acct(501),
                Amount::from_raw(1),
                Hash::ZERO,
                SequenceNumber::new(151),
            )
            .unwrap_err(),
            MarketError::Resolution(ResolutionError::WindowClosed)
        );

        // Finalization is blocked while the challenge is unresolved.
        assert_eq!(
            reg.finalize_resolution(m, deadline).unwrap_err(),
            MarketError::Resolution(ResolutionError::UnresolvedChallenge)
        );

        // Adjudication before the window closes is refused.
        let adj = make_cert(
            &ts,
            m,
            &policy,
            deadline,
            ResolutionPhase::Adjudicate,
            winner_takes_all(2, 1).unwrap(),
            Hash::from_bytes([3u8; 32]),
        );
        assert_eq!(
            reg.adjudicate_resolution(m, &adj, SequenceNumber::new(149))
                .unwrap_err(),
            MarketError::Resolution(ResolutionError::WindowOpen)
        );

        // Deterministic adjudication flips the outcome to 1 and clears the book.
        reg.adjudicate_resolution(m, &adj, deadline).unwrap();
        reg.finalize_resolution(m, deadline).unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Resolved));

        // Settlement pays the adjudicated outcome; value is conserved.
        let s = reg.settle_market(m).unwrap();
        assert_eq!(s.total_credited, Amount::from_raw(3_000_000));
        assert!(reg.reconciles());
    }

    #[test]
    fn rotation_advances_round_and_rejects_stale_certificate() {
        // Criterion: rotation requires an explicit version transition and cannot
        // rewrite past rounds; certificates for the pre-rotation round are
        // rejected.
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let m = MarketId::new(1);
        let ts = resolution_committee();
        let policy = test_policy(&ts);
        drive_to_open(&mut reg, 1);
        reg.commit_resolution_policy(m, policy.clone()).unwrap();

        // A proposal certificate bound to the ORIGINAL policy (version 1, round 0).
        let payout = winner_takes_all(2, 0).unwrap();
        let ev = Hash::from_bytes([7u8; 32]);
        let deadline = SequenceNumber::new(200);
        let stale = make_cert(
            &ts,
            m,
            &policy,
            deadline,
            ResolutionPhase::Propose,
            payout.clone(),
            ev,
        );

        // Rotate to a new committee: version and round both strictly advance.
        let ts2 =
            ThresholdSigners::from_seeds(&[[10u8; 32], [11u8; 32], [12u8; 32], [13u8; 32]], 3);
        let expiry = SequenceNumber::new(1_000_000);
        reg.rotate_resolution_policy(
            m,
            ts2.validator_set(),
            50,
            Hash::from_bytes([1u8; 32]),
            expiry,
        )
        .unwrap();
        let rotated = policy.rotate(ts2.validator_set(), 50, Hash::from_bytes([1u8; 32]), expiry);
        assert_eq!(rotated.version(), 2);
        assert_eq!(rotated.round(), 1);

        // Move to pending and try the stale certificate: rejected (old commitment).
        reg.mint_complete_set(m, acct(TREASURY), Amount::from_raw(3_000_000))
            .unwrap();
        reg.close_market(m, 1_000).unwrap();
        reg.begin_resolution(m).unwrap();
        assert_eq!(
            reg.propose_resolution(m, &stale, SequenceNumber::new(100))
                .unwrap_err(),
            MarketError::Resolution(ResolutionError::PolicyMismatch)
        );

        // A certificate under the rotated policy (round 1, new committee) works.
        let good = make_cert(
            &ts2,
            m,
            &rotated,
            deadline,
            ResolutionPhase::Propose,
            payout,
            ev,
        );
        reg.propose_resolution(m, &good, SequenceNumber::new(100))
            .unwrap();
        reg.finalize_resolution(m, deadline).unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Resolved));
    }

    #[test]
    fn resolution_policy_lifecycle_guards() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let m = MarketId::new(1);
        let ts = resolution_committee();
        let policy = test_policy(&ts);

        // Commit is once-only.
        reg.commit_resolution_policy(m, policy.clone()).unwrap();
        assert_eq!(
            reg.commit_resolution_policy(m, policy.clone()).unwrap_err(),
            MarketError::Resolution(ResolutionError::PolicyAlreadyCommitted)
        );

        // Rotating a market with no committed policy is refused.
        reg.create_market(definition(2)).unwrap();
        assert_eq!(
            reg.rotate_resolution_policy(
                MarketId::new(2),
                ts.validator_set(),
                50,
                Hash::ZERO,
                SequenceNumber::new(10),
            )
            .unwrap_err(),
            MarketError::Resolution(ResolutionError::PolicyNotCommitted)
        );

        // Proposing with no committed policy is refused.
        let m3 = MarketId::new(3);
        reg.create_market(definition(3)).unwrap();
        drive_to_open(&mut reg, 3);
        reg.mint_complete_set(m3, acct(TREASURY), Amount::from_raw(1_000_000))
            .unwrap();
        reg.close_market(m3, 1_000).unwrap();
        reg.begin_resolution(m3).unwrap();
        let cert = make_cert(
            &ts,
            m3,
            &policy,
            SequenceNumber::new(150),
            ResolutionPhase::Propose,
            winner_takes_all(2, 0).unwrap(),
            Hash::ZERO,
        );
        assert_eq!(
            reg.propose_resolution(m3, &cert, SequenceNumber::new(100))
                .unwrap_err(),
            MarketError::Resolution(ResolutionError::PolicyNotCommitted)
        );

        // An expired policy cannot open a resolution.
        let expired = ResolutionPolicy::new(
            1,
            0,
            7,
            ts.validator_set(),
            50,
            Hash::ZERO,
            SequenceNumber::new(100),
        );
        reg.create_market(definition(4)).unwrap();
        let m4 = drive_to_pending(&mut reg, 4, Amount::from_raw(1_000_000), expired.clone());
        let cert4 = make_cert(
            &ts,
            m4,
            &expired,
            SequenceNumber::new(300),
            ResolutionPhase::Propose,
            winner_takes_all(2, 0).unwrap(),
            Hash::ZERO,
        );
        assert_eq!(
            reg.propose_resolution(m4, &cert4, SequenceNumber::new(200))
                .unwrap_err(),
            MarketError::Resolution(ResolutionError::PolicyExpired)
        );
    }

    fn sponsor_key() -> KeyPair {
        KeyPair::from_seed(&[0x51u8; 32])
    }

    fn double_sign_evidence(
        key: &KeyPair,
        market: MarketId,
        sponsor: SponsorId,
        deployment: u64,
        epoch: u64,
        a: u8,
        b: u8,
    ) -> SlashEvidence {
        let first = SignedSponsorMessage::sign(
            key,
            deployment,
            market,
            sponsor,
            epoch,
            sponsor_msg_kind::GENERIC,
            Hash::from_bytes([a; 32]),
        );
        let second = SignedSponsorMessage::sign(
            key,
            deployment,
            market,
            sponsor,
            epoch,
            sponsor_msg_kind::GENERIC,
            Hash::from_bytes([b; 32]),
        );
        SlashEvidence::DoubleSign {
            deployment,
            epoch,
            first,
            second,
        }
    }

    fn fraud_conflicting_evidence(
        key: &KeyPair,
        market: MarketId,
        sponsor: SponsorId,
        deployment: u64,
        epoch: u64,
    ) -> SlashEvidence {
        let claim = SignedSponsorMessage::sign(
            key,
            deployment,
            market,
            sponsor,
            epoch,
            sponsor_msg_kind::RESOLUTION,
            resolution_payload_hash(Hash::from_bytes([1u8; 32])),
        );
        let other = SignedSponsorMessage::sign(
            key,
            deployment,
            market,
            sponsor,
            epoch,
            sponsor_msg_kind::RESOLUTION,
            resolution_payload_hash(Hash::from_bytes([2u8; 32])),
        );
        SlashEvidence::FraudulentResolution {
            deployment,
            epoch,
            claim,
            conflicting_claim: Some(other),
            finalized_payout_hash: None,
        }
    }

    fn invalid_config_evidence(
        key: &KeyPair,
        market: MarketId,
        sponsor: SponsorId,
        deployment: u64,
        epoch: u64,
        revenue_bps: u32,
        sponsor_count: u32,
    ) -> SlashEvidence {
        let attestation = SignedSponsorMessage::sign(
            key,
            deployment,
            market,
            sponsor,
            epoch,
            sponsor_msg_kind::CONFIG,
            config_payload_hash(revenue_bps, sponsor_count),
        );
        SlashEvidence::InvalidConfig {
            deployment,
            epoch,
            attestation,
            revenue_bps,
            sponsor_count,
        }
    }

    #[test]
    fn slash_only_objective_and_halts_below_requirement() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let m = MarketId::new(1);
        let sponsor = SponsorId::new(1);
        drive_to_open(&mut reg, 1);
        let insurance_before = reg.insurance();
        let key = sponsor_key();
        // Fraud is a total slash: drops stake to 0 < requirement -> Halted.
        let evidence = fraud_conflicting_evidence(&key, m, sponsor, 1, 7);
        let slashed = reg.slash_sponsor(m, sponsor, &evidence).unwrap();
        assert_eq!(slashed, Amount::from_raw(1_000_000));
        assert_eq!(
            reg.insurance(),
            insurance_before.checked_add(slashed).unwrap()
        );
        // The slash moved escrow, not minted value: the sponsor's stake escrow
        // is now empty and the ledger still reconciles.
        assert_eq!(reg.ledger().sponsor_stake(m, sponsor), Amount::ZERO);
        assert!(reg.reconciles());
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Halted));
        assert_eq!(reg.slash_log().len(), 1);
        // Replayed evidence cannot double-slash.
        assert_eq!(
            reg.slash_sponsor(m, sponsor, &evidence).unwrap_err(),
            MarketError::Resolution(ResolutionError::DuplicateEvidence)
        );
    }

    #[test]
    fn valid_double_sign_slashes_once_and_invalid_leaves_state() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let m = MarketId::new(1);
        let sponsor = SponsorId::new(1);
        drive_to_open(&mut reg, 1);
        let key = sponsor_key();
        let root_before = reg.state_root();
        let stake_before = reg.ledger().sponsor_stake(m, sponsor);
        let insurance_before = reg.insurance();
        let lifecycle_before = reg.get_market_status(m);

        // Random / nonconflicting messages cannot slash.
        let nonconflict = double_sign_evidence(&key, m, sponsor, 1, 1, 5, 5);
        assert!(reg.slash_sponsor(m, sponsor, &nonconflict).is_err());
        // Wrong market binding.
        let wrong_market = double_sign_evidence(&key, MarketId::new(99), sponsor, 1, 1, 1, 2);
        assert!(reg.slash_sponsor(m, sponsor, &wrong_market).is_err());
        // State fully unchanged after invalid attempts.
        assert_eq!(reg.state_root(), root_before);
        assert_eq!(reg.ledger().sponsor_stake(m, sponsor), stake_before);
        assert_eq!(reg.insurance(), insurance_before);
        assert_eq!(reg.get_market_status(m), lifecycle_before);
        assert!(reg.slash_log().is_empty());
        assert!(!reg.evidence_applied(nonconflict.evidence_id(m, sponsor)));

        // Valid double-sign: total slash, escrow moves, exactly once.
        let evidence = double_sign_evidence(&key, m, sponsor, 1, 1, 1, 2);
        let slashed = reg.slash_sponsor(m, sponsor, &evidence).unwrap();
        assert_eq!(slashed, stake_before);
        assert_eq!(reg.ledger().sponsor_stake(m, sponsor), Amount::ZERO);
        assert_eq!(
            reg.insurance(),
            insurance_before.checked_add(slashed).unwrap()
        );
        assert!(reg.evidence_applied(evidence.evidence_id(m, sponsor)));
        assert_eq!(
            reg.slash_sponsor(m, sponsor, &evidence).unwrap_err(),
            MarketError::Resolution(ResolutionError::DuplicateEvidence)
        );
        // Same signed payloads under another deployment/epoch are distinct ids
        // but still fail domain checks if rebound — construct peer market replay.
        let mut reg2 = MarketRegistry::new();
        reg2.create_market(definition(2)).unwrap();
        drive_to_open(&mut reg2, 2);
        let m2 = MarketId::new(2);
        // Evidence bound to market 1 cannot slash market 2.
        assert!(reg2.slash_sponsor(m2, sponsor, &evidence).is_err());
        assert_eq!(
            reg2.ledger().sponsor_stake(m2, sponsor),
            Amount::from_raw(1_000_000)
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
        let t = acct(TREASURY);
        vec![
            MarketCommand::Deposit {
                account: t,
                amount: Amount::from_raw(100_000_000),
            },
            MarketCommand::CreateMarket(Box::new(definition(1))),
            MarketCommand::StakeMarket {
                market_id: m,
                sponsor_id: SponsorId::new(1),
                funding_account: t,
                amount: Amount::from_raw(1_000_000),
            },
            MarketCommand::ActivateMarket(m),
            MarketCommand::AddBootstrapLiquidity {
                market_id: m,
                funding_account: t,
                amount: Amount::from_raw(5_000_000),
            },
            MarketCommand::MintCompleteSet {
                market_id: m,
                funding_account: t,
                units: Amount::from_raw(2_000_000),
            },
            MarketCommand::RedeemCompleteSet {
                market_id: m,
                recipient: t,
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
                let account = acct(u32::try_from(r.next_u64() % 3).unwrap() + 200);
                let cmd = match r.next_u64() % 9 {
                    0 => MarketCommand::CreateMarket(Box::new(definition(m.get()))),
                    1 => MarketCommand::StakeMarket {
                        market_id: m,
                        sponsor_id: SponsorId::new(1),
                        funding_account: account,
                        amount: Amount::from_raw(i128::from(r.next_u64() % 3_000_000)),
                    },
                    2 => MarketCommand::ActivateMarket(m),
                    3 => MarketCommand::AddBootstrapLiquidity {
                        market_id: m,
                        funding_account: account,
                        amount: Amount::from_raw(i128::from(r.next_u64() % 6_000_000)),
                    },
                    4 => MarketCommand::HaltMarket {
                        market_id: m,
                        reason: crate::HaltReason::Admin,
                    },
                    5 => MarketCommand::ResumeMarket(m),
                    6 => MarketCommand::MintCompleteSet {
                        market_id: m,
                        funding_account: account,
                        units: Amount::from_raw(i128::from(r.next_u64() % 2_000_000)),
                    },
                    7 => MarketCommand::Deposit {
                        account,
                        amount: Amount::from_raw(i128::from(r.next_u64() % 8_000_000)),
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
                // The ledger reconciles to registry totals after every command,
                // whether it committed or was rejected.
                assert!(a.reconciles());
            }
            for c in &log {
                let _ = b.apply(c.clone());
            }
            assert_eq!(a.state_root(), b.state_root());
        }
    }

    #[test]
    fn create_rejects_prefunded_sponsor_stake() {
        let mut reg = MarketRegistry::new();
        let mut def = definition(1);
        // A founder arriving already funded is caller-constructed state -> reject.
        def.sponsor_set = SponsorSet::new(SponsorShare::new(
            SponsorId::new(1),
            Amount::from_raw(1),
            0,
            0,
        ))
        .unwrap();
        assert_eq!(
            reg.create_market(def).unwrap_err(),
            MarketError::Escrow(EscrowError::PrefundedStake)
        );
        // Admitting a pre-funded sponsor is likewise refused.
        reg.create_market(definition(2)).unwrap();
        assert_eq!(
            reg.add_sponsor(
                MarketId::new(2),
                SponsorShare::new(SponsorId::new(9), Amount::from_raw(5), 0, 0)
            )
            .unwrap_err(),
            MarketError::Escrow(EscrowError::PrefundedStake)
        );
    }

    #[test]
    fn stake_bootstrap_mint_fail_without_available_balance() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let m = MarketId::new(1);
        let t = acct(TREASURY);
        // An unfunded (never-seen) account cannot stake.
        assert!(matches!(
            reg.stake_market(m, SponsorId::new(1), t, Amount::from_raw(1)),
            Err(MarketError::Escrow(EscrowError::UnknownAccount))
        ));
        // Fund 0.5 but try to stake 1.0 -> InsufficientAvailable, no mutation.
        reg.deposit(t, Amount::from_raw(500_000)).unwrap();
        assert!(matches!(
            reg.stake_market(m, SponsorId::new(1), t, Amount::from_raw(1_000_000)),
            Err(MarketError::Escrow(
                EscrowError::InsufficientAvailable { .. }
            ))
        ));
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Draft));
        assert_eq!(
            reg.get_market(m).unwrap().sponsor_set.total_stake(),
            Amount::ZERO
        );
        assert!(reg.reconciles());

        // Stake within balance; requirement (1.0) not yet met -> still Draft.
        reg.stake_market(m, SponsorId::new(1), t, Amount::from_raw(500_000))
            .unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Draft));
        reg.deposit(t, Amount::from_raw(500_000)).unwrap();
        reg.stake_market(m, SponsorId::new(1), t, Amount::from_raw(500_000))
            .unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Staked));

        reg.activate_market(m).unwrap();
        // Bootstrap with no available funds fails.
        assert!(matches!(
            reg.add_bootstrap_liquidity(m, t, Amount::from_raw(5_000_000)),
            Err(MarketError::Escrow(
                EscrowError::InsufficientAvailable { .. }
            ))
        ));
        assert_eq!(
            reg.get_market_status(m),
            Some(MarketLifecycle::Bootstrapping)
        );
        assert!(reg.reconciles());

        reg.deposit(t, Amount::from_raw(5_000_000)).unwrap();
        reg.add_bootstrap_liquidity(m, t, Amount::from_raw(5_000_000))
            .unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Open));
        // Minting with a drained account fails; the pool never grows.
        assert!(matches!(
            reg.mint_complete_set(m, t, Amount::from_raw(1_000_000)),
            Err(MarketError::Escrow(
                EscrowError::InsufficientAvailable { .. }
            ))
        ));
        assert_eq!(reg.ledger().complete_set(m), Amount::ZERO);
        assert!(reg.reconciles());
    }

    #[test]
    fn operations_lock_exactly_reported_collateral() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let m = MarketId::new(1);
        let t = acct(TREASURY);
        reg.deposit(t, Amount::from_raw(100_000_000)).unwrap();
        let start = reg.available(t).unwrap();

        reg.stake_market(m, SponsorId::new(1), t, Amount::from_raw(1_000_000))
            .unwrap();
        assert_eq!(
            reg.ledger().sponsor_stake(m, SponsorId::new(1)),
            Amount::from_raw(1_000_000)
        );
        assert_eq!(
            reg.ledger().sponsor_stake_total(m),
            reg.get_market(m).unwrap().sponsor_set.total_stake()
        );

        reg.activate_market(m).unwrap();
        reg.add_bootstrap_liquidity(m, t, Amount::from_raw(5_000_000))
            .unwrap();
        assert_eq!(reg.ledger().bootstrap(m), Amount::from_raw(5_000_000));

        reg.mint_complete_set(m, t, Amount::from_raw(4_000_000))
            .unwrap();
        assert_eq!(reg.ledger().complete_set(m), Amount::from_raw(4_000_000));

        // Exactly the reported collateral left the funding account.
        let locked = Amount::from_raw(1_000_000 + 5_000_000 + 4_000_000);
        assert_eq!(
            reg.available(t).unwrap(),
            start.checked_sub(locked).unwrap()
        );
        assert!(reg.reconciles());
    }

    #[test]
    fn redeem_and_remove_move_existing_escrow_not_value() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let m = MarketId::new(1);
        let t = acct(TREASURY);
        // A second sponsor so the removable one is not the owner-founder.
        reg.add_sponsor(
            m,
            SponsorShare::new(SponsorId::new(2), Amount::ZERO, 1_000, 10),
        )
        .unwrap();
        drive_to_open(&mut reg, 1);
        let supply = reg.ledger().total_supply();

        // Stake sponsor 2, then remove it: escrow refunds to a fresh account.
        reg.stake_market(m, SponsorId::new(2), t, Amount::from_raw(2_000_000))
            .unwrap();
        assert_eq!(
            reg.ledger().sponsor_stake(m, SponsorId::new(2)),
            Amount::from_raw(2_000_000)
        );
        let refund = acct(300);
        let refunded = reg.remove_sponsor(m, SponsorId::new(2), refund).unwrap();
        assert_eq!(refunded, Amount::from_raw(2_000_000));
        assert_eq!(reg.available(refund).unwrap(), Amount::from_raw(2_000_000));
        assert_eq!(
            reg.ledger().sponsor_stake(m, SponsorId::new(2)),
            Amount::ZERO
        );
        assert!(reg
            .get_market(m)
            .unwrap()
            .sponsor_set
            .share(SponsorId::new(2))
            .is_none());

        // Mint then redeem: the released collateral returns to the recipient.
        reg.mint_complete_set(m, t, Amount::from_raw(3_000_000))
            .unwrap();
        let before = reg.available(t).unwrap();
        reg.redeem_complete_set(m, t, Amount::from_raw(1_000_000))
            .unwrap();
        assert_eq!(
            reg.available(t).unwrap(),
            before.checked_add(Amount::from_raw(1_000_000)).unwrap()
        );
        assert_eq!(reg.ledger().complete_set(m), Amount::from_raw(2_000_000));

        // Every move above was a transfer; total supply is unchanged.
        assert_eq!(reg.ledger().total_supply(), supply);
        assert!(reg.reconciles());
    }

    #[test]
    fn snapshot_restore_reconciles_and_preserves_state_root() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let m = MarketId::new(1);
        drive_to_open(&mut reg, 1);
        reg.mint_complete_set(m, acct(TREASURY), Amount::from_raw(2_000_000))
            .unwrap();
        let root = reg.state_root();

        let bytes = reg.snapshot().unwrap();
        let restored = MarketRegistry::restore(&bytes).unwrap();
        assert!(restored.reconciles());
        assert_eq!(restored.state_root(), root);
        assert_eq!(
            restored.ledger().complete_set(m),
            Amount::from_raw(2_000_000)
        );
    }

    #[test]
    fn conservation_spans_protocol_sponsor_insurance_and_dust() {
        let mut reg = MarketRegistry::new();
        // A 3-outcome market whose invalid refund leaves rounding dust, with a
        // stake requirement low enough that a partial slash keeps it Open.
        let mut def = definition(1);
        def.payout_rule = PayoutRule::Vector(winner_takes_all(3, 0).unwrap());
        def.stake_requirement = Amount::from_raw(1_000_000);
        reg.create_market(def).unwrap();
        let m = MarketId::new(1);
        let t = acct(TREASURY);
        reg.deposit(t, Amount::from_raw(100_000_000)).unwrap();

        reg.stake_market(m, SponsorId::new(1), t, Amount::from_raw(2_000_000))
            .unwrap();
        reg.activate_market(m).unwrap();
        reg.add_bootstrap_liquidity(m, t, Amount::from_raw(5_000_000))
            .unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Open));

        // Partial slash (20% of 2.0 = 0.4) funds insurance; 1.6 >= 1.0 so the
        // market stays Open. Invalid-config evidence uses an over-bps attestation.
        let key = sponsor_key();
        let evidence =
            invalid_config_evidence(&key, m, SponsorId::new(1), 1, 3, 12_000, 1);
        let slashed = reg
            .slash_sponsor(m, SponsorId::new(1), &evidence)
            .unwrap();
        assert_eq!(slashed, Amount::from_raw(400_000));
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Open));

        // An odd collateral over three outcomes yields sub-unit settlement dust.
        reg.mint_complete_set(m, t, Amount::from_raw(1_000_001))
            .unwrap();
        reg.close_market(m, 1_000).unwrap();
        reg.begin_resolution(m).unwrap();
        reg.invalidate_market(m).unwrap();
        let s = reg.settle_market(m).unwrap();
        assert_eq!(s.dust, Amount::from_raw(1));

        // All four conservation accounts carry value simultaneously.
        assert!(reg.ledger().sponsor_stake(m, SponsorId::new(1)).raw() > 0);
        assert!(reg.insurance().raw() > 0);
        assert!(reg.protocol().raw() > 0);
        assert!(reg.dust().raw() > 0);
        assert!(reg.ledger().conservation_holds());
        assert!(reg.reconciles());
        // Supply never moved: only the single 100.0 deposit ever entered.
        assert_eq!(reg.ledger().total_supply(), Amount::from_raw(100_000_000));
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

    #[test]
    fn halt_resume_cannot_bypass_bootstrapping() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let m = MarketId::new(1);
        let t = acct(TREASURY);
        reg.deposit(t, Amount::from_raw(10_000_000)).unwrap();
        reg.stake_market(m, SponsorId::new(1), t, Amount::from_raw(1_000_000))
            .unwrap();
        reg.activate_market(m).unwrap();
        // Still bootstrapping.
        reg.halt_market(m, crate::HaltReason::BootstrapFailed).unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Halted));
        assert_eq!(
            reg.halt_state(m).unwrap().prior,
            MarketLifecycle::Bootstrapping
        );
        // Resume returns to Bootstrapping, not Open.
        reg.resume_market(m).unwrap();
        assert_eq!(
            reg.get_market_status(m),
            Some(MarketLifecycle::Bootstrapping)
        );
        // Open still requires bootstrap threshold.
        assert_eq!(
            reg.mint_complete_set(m, t, Amount::from_raw(1_000_000))
                .unwrap_err(),
            MarketError::WrongLifecycleState
        );
    }

    #[test]
    fn resume_rejects_unhealthy_oracle_and_understake() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        drive_to_open(&mut reg, 1);
        let m = MarketId::new(1);
        reg.set_oracle_health(m, OracleHealth::Normal).unwrap();
        reg.halt_market(m, crate::HaltReason::OracleUnhealthy).unwrap();
        // Oracle still stale -> cannot resume new risk.
        reg.set_oracle_health(m, OracleHealth::Stale).unwrap();
        assert_eq!(
            reg.resume_market(m).unwrap_err(),
            MarketError::OracleUnhealthy
        );
        reg.set_oracle_health(m, OracleHealth::Normal).unwrap();
        reg.resume_market(m).unwrap();
        assert_eq!(reg.get_market_status(m), Some(MarketLifecycle::Open));
    }

    #[test]
    fn archive_rejects_outstanding_liabilities() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        drive_to_open(&mut reg, 1);
        let m = MarketId::new(1);
        reg.halt_market(m, crate::HaltReason::Admin).unwrap();
        // Stake / bootstrap still locked.
        assert_eq!(
            reg.archive_market(m).unwrap_err(),
            MarketError::ArchiveLiabilities
        );
        reg.set_open_orders(m, 3).unwrap();
        // Even with orders reported, still blocked.
        assert_eq!(
            reg.archive_market(m).unwrap_err(),
            MarketError::ArchiveLiabilities
        );
    }

    #[test]
    fn funding_epoch_once_via_registry() {
        let mut reg = MarketRegistry::new();
        reg.create_market(definition(1)).unwrap();
        let m = MarketId::new(1);
        let rate = types::Ratio::from_bps(5).unwrap();
        let mark = Price::from_raw(1_000_000);
        reg.apply_funding_epoch(m, 1, rate, mark).unwrap();
        assert_eq!(
            reg.apply_funding_epoch(m, 1, rate, mark).unwrap_err(),
            MarketError::Perp(crate::PerpError::DuplicateEpoch { last: 1, got: 1 })
        );
    }
}

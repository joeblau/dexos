//! The runtime decision-market state machine.
//!
//! One [`ContingentMarket`] is spawned per action. Collateral enters only by
//! minting complete sets (one share of every outcome) and leaves only by
//! redeeming complete sets or at settlement, so the collateral ledger is exact.
//! Trading transfers shares between accounts without moving collateral.
//!
//! Determinism: all per-account state lives in ordered [`BTreeMap`]s, and
//! [`DecisionMarket::state_root`] hashes the canonical serialization so a replay
//! of the same command sequence yields an identical root.

use std::collections::BTreeMap;

use types::domain::Hash;
use types::{AccountId, Amount, Price, Quantity, Ratio, SequenceNumber};

use crate::definition::{DecisionMarketDefinition, UnselectedActionPolicy};
use crate::error::DecisionMarketError;
use crate::instrument::{ActionId, InstrumentId, OutcomeId};
use crate::lifecycle::DecisionPhase;
use crate::selection::{select_action, ExternalConfirmation, SelectionOutcome};
use crate::settlement::Settlement;
use crate::twap::TwapAccumulator;

/// Minimum-liquidity and concentration guards for a valid decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionGuards {
    /// Minimum collateral each contingent market must hold to be decided.
    pub min_liquidity: Amount,
    /// Maximum share of a single market a single account may hold (`0..=1.0`).
    pub max_concentration: Ratio,
}

impl DecisionGuards {
    /// Construct guards.
    #[inline]
    pub const fn new(min_liquidity: Amount, max_concentration: Ratio) -> Self {
        Self {
            min_liquidity,
            max_concentration,
        }
    }
}

/// One account's holdings within a single contingent market.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AccountPosition {
    /// Shares held per outcome index.
    shares: Vec<Quantity>,
    /// Net collateral this account deposited (mint minus redeem).
    deposited: Amount,
}

impl AccountPosition {
    fn new(num_outcomes: usize) -> Self {
        Self {
            shares: vec![Quantity::ZERO; num_outcomes],
            deposited: Amount::ZERO,
        }
    }

    fn total_shares(&self) -> Result<i128, DecisionMarketError> {
        let mut sum: i128 = 0;
        for s in &self.shares {
            sum = sum
                .checked_add(i128::from(s.raw()))
                .ok_or(DecisionMarketError::Truncation)?;
        }
        Ok(sum)
    }
}

/// A single action-contingent market over the shared outcome set.
#[derive(Debug, Clone)]
struct ContingentMarket {
    total_sets: Quantity,
    positions: BTreeMap<AccountId, AccountPosition>,
    twaps: Vec<TwapAccumulator>,
}

impl ContingentMarket {
    fn new(num_outcomes: usize, window: crate::twap::TimeWindow) -> Self {
        Self {
            total_sets: Quantity::ZERO,
            positions: BTreeMap::new(),
            twaps: vec![TwapAccumulator::new(window); num_outcomes],
        }
    }

    fn total_collateral(&self) -> Result<Amount, DecisionMarketError> {
        let mut sum = Amount::ZERO;
        for pos in self.positions.values() {
            sum = sum.checked_add(pos.deposited)?;
        }
        Ok(sum)
    }
}

/// A live decision market walking the [`DecisionPhase`] lifecycle.
#[derive(Debug, Clone)]
pub struct DecisionMarket {
    definition: DecisionMarketDefinition,
    phase: DecisionPhase,
    num_outcomes: usize,
    markets: Vec<ContingentMarket>,
    selected: Option<ActionId>,
    resolved_outcome: Option<OutcomeId>,
    ext_sequence: SequenceNumber,
}

impl DecisionMarket {
    /// Create a market in [`DecisionPhase::Draft`] from a validated definition.
    pub fn new(definition: DecisionMarketDefinition) -> Result<Self, DecisionMarketError> {
        definition.validate()?;
        let num_outcomes = definition.num_outcomes();
        let window = definition.selection_window;
        let markets = (0..definition.num_actions())
            .map(|_| ContingentMarket::new(num_outcomes, window))
            .collect();
        Ok(Self {
            definition,
            phase: DecisionPhase::Draft,
            num_outcomes,
            markets,
            selected: None,
            resolved_outcome: None,
            ext_sequence: SequenceNumber::ZERO,
        })
    }

    /// The immutable definition.
    #[inline]
    pub fn definition(&self) -> &DecisionMarketDefinition {
        &self.definition
    }

    /// The current lifecycle phase.
    #[inline]
    pub fn phase(&self) -> DecisionPhase {
        self.phase
    }

    /// The selected action, if any.
    #[inline]
    pub fn selected_action(&self) -> Option<ActionId> {
        self.selected
    }

    /// The resolved outcome, if any.
    #[inline]
    pub fn resolved_outcome(&self) -> Option<OutcomeId> {
        self.resolved_outcome
    }

    /// The flat instrument id for an `(action, outcome)` pair.
    pub fn instrument(
        &self,
        action: ActionId,
        outcome: OutcomeId,
    ) -> Result<InstrumentId, DecisionMarketError> {
        let n = u16::try_from(self.num_outcomes).map_err(|_| DecisionMarketError::Truncation)?;
        crate::instrument::instrument_id(action, outcome, n)
    }

    // --- lifecycle transitions -------------------------------------------------

    fn set_phase(&mut self, to: DecisionPhase) -> Result<(), DecisionMarketError> {
        self.phase = self.phase.transition(to)?;
        Ok(())
    }

    /// `Draft -> Trading`: open the market for minting and trading.
    pub fn open_trading(&mut self) -> Result<(), DecisionMarketError> {
        self.set_phase(DecisionPhase::Trading)
    }

    /// `Trading -> DecisionLocked`: freeze trading before the decision.
    pub fn lock_decision(&mut self) -> Result<(), DecisionMarketError> {
        self.set_phase(DecisionPhase::DecisionLocked)
    }

    /// `ActionSelected -> Evaluating`.
    pub fn begin_evaluation(&mut self) -> Result<(), DecisionMarketError> {
        self.set_phase(DecisionPhase::Evaluating)
    }

    /// `Evaluating -> Resolved`: record the realized outcome for the selected
    /// action's contingent market.
    pub fn resolve(&mut self, outcome: OutcomeId) -> Result<(), DecisionMarketError> {
        if outcome.index()? >= self.num_outcomes {
            return Err(DecisionMarketError::UnknownOutcome);
        }
        self.set_phase(DecisionPhase::Resolved)?;
        self.resolved_outcome = Some(outcome);
        Ok(())
    }

    // --- trading ---------------------------------------------------------------

    fn require_trading(&self) -> Result<(), DecisionMarketError> {
        if self.phase == DecisionPhase::Trading {
            Ok(())
        } else {
            Err(DecisionMarketError::WrongPhase { phase: self.phase })
        }
    }

    fn market_mut(
        &mut self,
        action: ActionId,
    ) -> Result<&mut ContingentMarket, DecisionMarketError> {
        let idx = action.index()?;
        self.markets
            .get_mut(idx)
            .ok_or(DecisionMarketError::UnknownAction)
    }

    fn market_ref(&self, action: ActionId) -> Result<&ContingentMarket, DecisionMarketError> {
        let idx = action.index()?;
        self.markets
            .get(idx)
            .ok_or(DecisionMarketError::UnknownAction)
    }

    /// Collateral value of `n` complete sets at the definition's par value.
    fn set_value(&self, n: Quantity) -> Result<Amount, DecisionMarketError> {
        let ratio = Ratio::from_raw(n.raw());
        Ok(self.definition.collateral_per_set.mul_ratio(ratio)?)
    }

    /// Mint `n` complete sets of `action` for `account`, depositing collateral
    /// and crediting `n` shares of every outcome.
    pub fn mint(
        &mut self,
        action: ActionId,
        account: AccountId,
        n: Quantity,
    ) -> Result<(), DecisionMarketError> {
        self.require_trading()?;
        if n.raw() <= 0 {
            return Err(DecisionMarketError::NonPositiveSize);
        }
        let value = self.set_value(n)?;
        let num_outcomes = self.num_outcomes;
        let market = self.market_mut(action)?;
        let pos = market
            .positions
            .entry(account)
            .or_insert_with(|| AccountPosition::new(num_outcomes));
        let mut updated = pos.shares.clone();
        for s in &mut updated {
            *s = s.checked_add(n)?;
        }
        pos.shares = updated;
        pos.deposited = pos.deposited.checked_add(value)?;
        market.total_sets = market.total_sets.checked_add(n)?;
        Ok(())
    }

    /// Redeem `n` complete sets of `action` held by `account`, returning
    /// collateral and burning `n` shares of every outcome.
    pub fn redeem(
        &mut self,
        action: ActionId,
        account: AccountId,
        n: Quantity,
    ) -> Result<(), DecisionMarketError> {
        self.require_trading()?;
        if n.raw() <= 0 {
            return Err(DecisionMarketError::NonPositiveSize);
        }
        let value = self.set_value(n)?;
        let market = self.market_mut(action)?;
        let pos = market
            .positions
            .get_mut(&account)
            .ok_or(DecisionMarketError::InsufficientShares)?;
        if pos.shares.iter().any(|s| s.raw() < n.raw()) {
            return Err(DecisionMarketError::InsufficientShares);
        }
        for s in &mut pos.shares {
            *s = s.checked_sub(n)?;
        }
        pos.deposited = pos.deposited.checked_sub(value)?;
        market.total_sets = market.total_sets.checked_sub(n)?;
        Ok(())
    }

    /// Transfer `qty` shares of one `outcome` in `action` from `from` to `to`.
    /// Collateral is unchanged (a secondary-market trade).
    pub fn transfer(
        &mut self,
        action: ActionId,
        outcome: OutcomeId,
        from: AccountId,
        to: AccountId,
        qty: Quantity,
    ) -> Result<(), DecisionMarketError> {
        self.require_trading()?;
        if qty.raw() <= 0 {
            return Err(DecisionMarketError::NonPositiveSize);
        }
        let o = outcome.index()?;
        if o >= self.num_outcomes {
            return Err(DecisionMarketError::UnknownOutcome);
        }
        let num_outcomes = self.num_outcomes;
        let market = self.market_mut(action)?;
        let sender = market
            .positions
            .get_mut(&from)
            .ok_or(DecisionMarketError::InsufficientShares)?;
        let sender_share = sender.shares.get(o).copied().unwrap_or(Quantity::ZERO);
        if sender_share.raw() < qty.raw() {
            return Err(DecisionMarketError::InsufficientShares);
        }
        sender.shares[o] = sender_share.checked_sub(qty)?;
        let receiver = market
            .positions
            .entry(to)
            .or_insert_with(|| AccountPosition::new(num_outcomes));
        receiver.shares[o] = receiver
            .shares
            .get(o)
            .copied()
            .unwrap_or(Quantity::ZERO)
            .checked_add(qty)?;
        Ok(())
    }

    /// Observe a decision-price tick for `(action, outcome)` during trading.
    pub fn observe_price(
        &mut self,
        action: ActionId,
        outcome: OutcomeId,
        ts: u64,
        price: Price,
    ) -> Result<(), DecisionMarketError> {
        self.require_trading()?;
        let o = outcome.index()?;
        let market = self.market_mut(action)?;
        let acc = market
            .twaps
            .get_mut(o)
            .ok_or(DecisionMarketError::UnknownOutcome)?;
        acc.observe(ts, price)
    }

    // --- risk queries ----------------------------------------------------------

    /// Worst-case collateral liability of a contingent market: the maximum payout
    /// over every outcome scenario. Because exactly one outcome pays par per set,
    /// this equals the market's total collateral.
    pub fn worst_case_liability(&self, action: ActionId) -> Result<Amount, DecisionMarketError> {
        self.market_ref(action)?.total_collateral()
    }

    /// The per-outcome scenario liability vector for a contingent market.
    pub fn scenario_liabilities(
        &self,
        action: ActionId,
    ) -> Result<Vec<Amount>, DecisionMarketError> {
        let total = self.market_ref(action)?.total_collateral()?;
        Ok(vec![total; self.num_outcomes])
    }

    /// The time-weighted decision-price vector for a contingent market.
    pub fn decision_prices(&self, action: ActionId) -> Result<Vec<Price>, DecisionMarketError> {
        let market = self.market_ref(action)?;
        market.twaps.iter().map(|t| t.finalize()).collect()
    }

    // --- guards & selection ----------------------------------------------------

    fn check_guards(&self, guards: DecisionGuards) -> Result<(), DecisionMarketError> {
        for market in &self.markets {
            let total = market.total_collateral()?;
            if total.raw() < guards.min_liquidity.raw() {
                return Err(DecisionMarketError::LiquidityTooThin);
            }
            let mut total_shares: i128 = 0;
            let mut max_account: i128 = 0;
            for pos in market.positions.values() {
                let acc_total = pos.total_shares()?;
                total_shares = total_shares
                    .checked_add(acc_total)
                    .ok_or(DecisionMarketError::Truncation)?;
                if acc_total > max_account {
                    max_account = acc_total;
                }
            }
            if total_shares > 0 {
                // max_account / total_shares > max_concentration  <=>
                // max_account * RATIO_SCALE > total_shares * max_concentration
                let lhs = max_account
                    .checked_mul(i128::from(types::RATIO_SCALE))
                    .ok_or(DecisionMarketError::Truncation)?;
                let rhs = total_shares
                    .checked_mul(i128::from(guards.max_concentration.raw()))
                    .ok_or(DecisionMarketError::Truncation)?;
                if lhs > rhs {
                    return Err(DecisionMarketError::ConcentrationExceeded);
                }
            }
        }
        Ok(())
    }

    fn per_action_prices(&self) -> Result<Vec<Vec<Price>>, DecisionMarketError> {
        (0..self.markets.len())
            .map(|i| {
                let action = ActionId::from_index(i)?;
                self.decision_prices(action)
            })
            .collect()
    }

    /// Automatically select the action maximizing time-weighted expected utility.
    ///
    /// Requires [`DecisionPhase::DecisionLocked`]. If the liquidity or
    /// concentration guards fail, the market transitions to
    /// [`DecisionPhase::Invalid`] (the deterministic void path) and an error is
    /// returned.
    pub fn select_auto(
        &mut self,
        guards: DecisionGuards,
    ) -> Result<SelectionOutcome, DecisionMarketError> {
        if self.phase != DecisionPhase::DecisionLocked {
            return Err(DecisionMarketError::WrongPhase { phase: self.phase });
        }
        if let Err(e) = self.check_guards(guards) {
            self.phase = DecisionPhase::Invalid;
            return Err(e);
        }
        let prices = self.per_action_prices()?;
        let outcome = select_action(
            self.definition.decision_rule,
            &prices,
            &self.definition.utility_function,
        )?;
        self.selected = Some(outcome.action);
        self.set_phase(DecisionPhase::ActionSelected)?;
        Ok(outcome)
    }

    /// Select the action from an externally-confirmed payload.
    ///
    /// The payload is decoded panic-free; the action must be in range and the
    /// sequence must strictly exceed the last accepted one (replay guard). Guards
    /// are still enforced (a failure voids the market).
    pub fn select_confirmed(
        &mut self,
        payload: &[u8],
        guards: DecisionGuards,
    ) -> Result<ActionId, DecisionMarketError> {
        if self.phase != DecisionPhase::DecisionLocked {
            return Err(DecisionMarketError::WrongPhase { phase: self.phase });
        }
        let confirmation = ExternalConfirmation::decode(payload)?;
        if confirmation.action.index()? >= self.markets.len() {
            return Err(DecisionMarketError::UnknownAction);
        }
        if confirmation.sequence.get() <= self.ext_sequence.get() {
            return Err(DecisionMarketError::StaleConfirmation);
        }
        if let Err(e) = self.check_guards(guards) {
            self.phase = DecisionPhase::Invalid;
            return Err(e);
        }
        self.ext_sequence = confirmation.sequence;
        self.selected = Some(confirmation.action);
        self.set_phase(DecisionPhase::ActionSelected)?;
        Ok(confirmation.action)
    }

    // --- settlement ------------------------------------------------------------

    /// Settle the market: pay out the chosen action by its resolved outcome and
    /// settle every unchosen action per the counterfactual policy. If the market
    /// is [`DecisionPhase::Invalid`], every action is settled per the policy.
    ///
    /// Total collateral is conserved exactly (zero rounding leakage).
    pub fn settle(&mut self) -> Result<Settlement, DecisionMarketError> {
        match self.phase {
            DecisionPhase::Resolved => self.settle_resolved(),
            DecisionPhase::Invalid => self.settle_all_unselected(),
            other => Err(DecisionMarketError::WrongPhase { phase: other }),
        }
    }

    fn settle_resolved(&mut self) -> Result<Settlement, DecisionMarketError> {
        let selected = self.selected.ok_or(DecisionMarketError::NotSelected)?;
        let outcome = self
            .resolved_outcome
            .ok_or(DecisionMarketError::NotResolved)?;
        let winner = outcome.index()?;
        let policy = self.definition.unselected_action_policy;
        let mut payouts: BTreeMap<(ActionId, AccountId), Amount> = BTreeMap::new();
        let mut total = Amount::ZERO;
        for (idx, market) in self.markets.iter().enumerate() {
            let action = ActionId::from_index(idx)?;
            let market_total = market.total_collateral()?;
            let entries = if action == selected {
                Self::distribute(market, market_total, |pos| {
                    i128::from(pos.shares.get(winner).copied().unwrap_or(Quantity::ZERO).raw())
                })?
            } else {
                Self::settle_unselected(market, market_total, policy)?
            };
            for (acct, amount) in entries {
                total = total.checked_add(amount)?;
                payouts.insert((action, acct), amount);
            }
        }
        self.set_phase(DecisionPhase::Settled)?;
        Ok(Settlement::new(payouts, total))
    }

    fn settle_all_unselected(&mut self) -> Result<Settlement, DecisionMarketError> {
        let policy = self.definition.unselected_action_policy;
        let mut payouts: BTreeMap<(ActionId, AccountId), Amount> = BTreeMap::new();
        let mut total = Amount::ZERO;
        for (idx, market) in self.markets.iter().enumerate() {
            let action = ActionId::from_index(idx)?;
            let market_total = market.total_collateral()?;
            let entries = Self::settle_unselected(market, market_total, policy)?;
            for (acct, amount) in entries {
                total = total.checked_add(amount)?;
                payouts.insert((action, acct), amount);
            }
        }
        self.set_phase(DecisionPhase::Settled)?;
        Ok(Settlement::new(payouts, total))
    }

    fn settle_unselected(
        market: &ContingentMarket,
        market_total: Amount,
        policy: UnselectedActionPolicy,
    ) -> Result<Vec<(AccountId, Amount)>, DecisionMarketError> {
        match policy {
            // Refund each depositor exactly what they contributed. Sum == total.
            UnselectedActionPolicy::Refund => Ok(market
                .positions
                .iter()
                .map(|(acct, pos)| (*acct, pos.deposited))
                .collect()),
            // Void: complete sets redeem at par to current holders, pro-rata by
            // total shares held.
            UnselectedActionPolicy::Void => {
                Self::distribute(market, market_total, |pos| {
                    pos.total_shares().unwrap_or(0)
                })
            }
        }
    }

    /// Distribute `total` across accounts proportional to a non-negative integer
    /// weight, using cumulative flooring so the payouts sum to `total` exactly
    /// (deterministic, zero rounding leakage).
    fn distribute(
        market: &ContingentMarket,
        total: Amount,
        weight_of: impl Fn(&AccountPosition) -> i128,
    ) -> Result<Vec<(AccountId, Amount)>, DecisionMarketError> {
        let mut weights: Vec<(AccountId, i128)> = Vec::with_capacity(market.positions.len());
        let mut total_weight: i128 = 0;
        for (acct, pos) in &market.positions {
            let w = weight_of(pos);
            total_weight = total_weight
                .checked_add(w)
                .ok_or(DecisionMarketError::Truncation)?;
            weights.push((*acct, w));
        }
        let mut out = Vec::with_capacity(weights.len());
        if total_weight == 0 {
            for (acct, _) in weights {
                out.push((acct, Amount::ZERO));
            }
            return Ok(out);
        }
        let total_raw = total.raw();
        let mut cum_weight: i128 = 0;
        let mut distributed: i128 = 0;
        for (acct, w) in weights {
            cum_weight = cum_weight
                .checked_add(w)
                .ok_or(DecisionMarketError::Truncation)?;
            let scaled = total_raw
                .checked_mul(cum_weight)
                .ok_or(DecisionMarketError::Truncation)?;
            let target = scaled / total_weight;
            let pay = target
                .checked_sub(distributed)
                .ok_or(DecisionMarketError::Truncation)?;
            distributed = target;
            out.push((acct, Amount::from_raw(pay)));
        }
        Ok(out)
    }

    // --- deterministic commitment ---------------------------------------------

    /// A deterministic 32-byte commitment to the full market state. Identical
    /// command sequences produce identical roots (used to prove replay
    /// determinism).
    pub fn state_root(&self) -> Hash {
        let mut buf: Vec<u8> = Vec::new();
        buf.push(self.phase.discriminant());
        buf.extend_from_slice(&self.ext_sequence.get().to_le_bytes());
        match self.selected {
            None => buf.push(0),
            Some(a) => {
                buf.push(1);
                buf.extend_from_slice(&a.get().to_le_bytes());
            }
        }
        match self.resolved_outcome {
            None => buf.push(0),
            Some(o) => {
                buf.push(1);
                buf.extend_from_slice(&o.get().to_le_bytes());
            }
        }
        for market in &self.markets {
            buf.extend_from_slice(&market.total_sets.raw().to_le_bytes());
            for twap in &market.twaps {
                let root = twap.finalize().map(|p| p.raw()).unwrap_or(i64::MIN);
                buf.extend_from_slice(&root.to_le_bytes());
            }
            for (acct, pos) in &market.positions {
                buf.extend_from_slice(&acct.get().to_le_bytes());
                buf.extend_from_slice(&pos.deposited.raw().to_le_bytes());
                for s in &pos.shares {
                    buf.extend_from_slice(&s.raw().to_le_bytes());
                }
            }
            // Delimiter so variable-length position lists cannot alias.
            buf.extend_from_slice(&[0xff; 4]);
        }
        crypto::hash_domain(crypto::DOMAIN_MARKET, &buf)
    }
}

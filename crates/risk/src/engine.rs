//! The risk engine: Structure-of-Arrays cached account state, incremental
//! margin updates, isolated/cross margin, pre-trade checks, and liquidation.
//!
//! # Layout
//!
//! Account risk state is stored Structure-of-Arrays: each cached scalar
//! (`collateral`, `equity`, `exposure`, `initial_margin`, `maintenance_margin`)
//! lives in its own contiguous [`Vec`] indexed by the account's slab index. The
//! hot liquidation scan reads only the `equity` and `maintenance_margin`
//! columns, so it streams two dense arrays rather than chasing per-account
//! objects.
//!
//! # Incremental updates
//!
//! Mutations touch exactly one account and call [`RiskEngine::recompute`] for
//! that index, which folds its (already-allocated) position vector into the
//! cached columns. On the steady-state path (a fill against an already-open
//! market position) no heap allocation occurs. [`RiskEngine::recompute_all`]
//! performs the same per-account computation for every account; the two are
//! definitionally equal, which the tests assert.
//!
//! # Determinism
//!
//! All arithmetic is integer fixed-point and total. [`RiskEngine::state_root`]
//! is an order-independent-free FNV-1a fingerprint over the SoA columns; a
//! replayed command stream reproduces a bit-identical root.

use types::{AccountId, Amount, MarketId, PayoutVector, Price, Quantity};

use crate::config::{MarginMode, OrderPriority, RiskConfig};
use crate::error::RiskError;
use crate::liquidation::{InsuranceFund, LiquidationOutcome, LiquidationQueue};
use crate::math::{abs_amount, neg_amount};
use crate::position::PerpPosition;
use crate::scenario::PayoutPosition;

/// Fixed-point risk & margin engine for scalar perp and payout-vector exposure.
#[derive(Debug, Clone)]
pub struct RiskEngine {
    config: RiskConfig,

    // --- Structure-of-Arrays account state (indexed by account slab index) ---
    used: Vec<bool>,
    open: Vec<bool>,
    margin_mode: Vec<MarginMode>,
    collateral: Vec<Amount>,
    perp: Vec<Vec<PerpPosition>>,
    payout: Vec<Vec<PayoutPosition>>,

    // Cached, recomputed incrementally on every mutation.
    cached_equity: Vec<Amount>,
    cached_exposure: Vec<Amount>,
    // Worst-case scenario collateral demanded by the payout-vector book: the
    // net liability across every multi-outcome position if each settles at its
    // least favorable outcome. Folded into both `cached_im` and `cached_mm`.
    cached_scenario: Vec<Amount>,
    cached_im: Vec<Amount>,
    cached_mm: Vec<Amount>,

    // --- market state (indexed by market slab index) ---
    marks: Vec<Option<Price>>,
    risk_group: Vec<Option<u32>>,
    market_limit: Vec<Option<Amount>>,

    // --- global risk state ---
    portfolio_limit: Option<Amount>,
    insurance: InsuranceFund,
    liq_queue: LiquidationQueue,
    socialized_total: Amount,
}

impl RiskEngine {
    /// A fresh engine with the given static risk parameters and an empty
    /// insurance fund.
    pub fn new(config: RiskConfig) -> Self {
        Self {
            config,
            used: Vec::new(),
            open: Vec::new(),
            margin_mode: Vec::new(),
            collateral: Vec::new(),
            perp: Vec::new(),
            payout: Vec::new(),
            cached_equity: Vec::new(),
            cached_exposure: Vec::new(),
            cached_scenario: Vec::new(),
            cached_im: Vec::new(),
            cached_mm: Vec::new(),
            marks: Vec::new(),
            risk_group: Vec::new(),
            market_limit: Vec::new(),
            portfolio_limit: None,
            insurance: InsuranceFund::default(),
            liq_queue: LiquidationQueue::new(),
            socialized_total: Amount::ZERO,
        }
    }

    /// The active risk configuration.
    #[inline]
    pub fn config(&self) -> RiskConfig {
        self.config
    }

    // ----------------------------------------------------------------- accounts

    /// Open an account with `collateral` starting balance (isolated margin).
    pub fn open_account(
        &mut self,
        account: AccountId,
        collateral: Amount,
    ) -> Result<(), RiskError> {
        if collateral.is_negative() {
            return Err(RiskError::NegativeAmount);
        }
        let i = account.index()?;
        self.grow_accounts(i);
        if self.used[i] {
            return Err(RiskError::AccountExists);
        }
        self.used[i] = true;
        self.open[i] = true;
        self.margin_mode[i] = MarginMode::Isolated;
        self.collateral[i] = collateral;
        self.perp[i].clear();
        self.payout[i].clear();
        self.recompute(i)
    }

    /// Set an account's margin mode (isolated vs cross).
    pub fn set_margin_mode(
        &mut self,
        account: AccountId,
        mode: MarginMode,
    ) -> Result<(), RiskError> {
        let i = self.active_index(account)?;
        self.margin_mode[i] = mode;
        self.recompute(i)
    }

    /// Credit (deposit) collateral into an account.
    pub fn credit_collateral(
        &mut self,
        account: AccountId,
        amount: Amount,
    ) -> Result<(), RiskError> {
        if amount.is_negative() {
            return Err(RiskError::NegativeAmount);
        }
        let i = self.active_index(account)?;
        self.collateral[i] = self.collateral[i].checked_add(amount)?;
        self.recompute(i)
    }

    /// Debit (withdraw) collateral, refusing to drop the account below its
    /// initial-margin requirement.
    pub fn debit_collateral(
        &mut self,
        account: AccountId,
        amount: Amount,
    ) -> Result<(), RiskError> {
        if amount.is_negative() {
            return Err(RiskError::NegativeAmount);
        }
        let i = self.active_index(account)?;
        let free = self.cached_equity[i].checked_sub(self.cached_im[i])?;
        if amount.raw() > free.raw() {
            return Err(RiskError::InsufficientCollateral);
        }
        self.collateral[i] = self.collateral[i].checked_sub(amount)?;
        self.recompute(i)
    }

    /// Apply signed funding to an account's collateral (positive = received).
    pub fn apply_funding(&mut self, account: AccountId, amount: Amount) -> Result<(), RiskError> {
        let i = self.active_index(account)?;
        self.collateral[i] = self.collateral[i].checked_add(amount)?;
        self.recompute(i)
    }

    /// Charge a non-negative fee against an account's collateral (may push it
    /// negative, making it liquidatable).
    pub fn apply_fee(&mut self, account: AccountId, fee: Amount) -> Result<(), RiskError> {
        if fee.is_negative() {
            return Err(RiskError::NegativeAmount);
        }
        let i = self.active_index(account)?;
        self.collateral[i] = self.collateral[i].checked_sub(fee)?;
        self.recompute(i)
    }

    // ------------------------------------------------------------------- market

    /// Set (or update) a market's mark price and refresh every account.
    pub fn set_mark_price(&mut self, market: MarketId, price: Price) -> Result<(), RiskError> {
        let mi = market.index()?;
        self.grow_market(mi);
        self.marks[mi] = Some(price);
        self.recompute_all()
    }

    /// Assign a market to a cross-margin risk group (default group == market id).
    pub fn set_risk_group(&mut self, market: MarketId, group: u32) -> Result<(), RiskError> {
        let mi = market.index()?;
        self.grow_market(mi);
        self.risk_group[mi] = Some(group);
        self.recompute_all()
    }

    /// Set a per-market notional cap.
    pub fn set_market_limit(&mut self, market: MarketId, cap: Amount) -> Result<(), RiskError> {
        if cap.is_negative() {
            return Err(RiskError::NegativeAmount);
        }
        let mi = market.index()?;
        self.grow_market(mi);
        self.market_limit[mi] = Some(cap);
        Ok(())
    }

    /// Set the portfolio-wide notional cap.
    pub fn set_portfolio_limit(&mut self, cap: Amount) -> Result<(), RiskError> {
        if cap.is_negative() {
            return Err(RiskError::NegativeAmount);
        }
        self.portfolio_limit = Some(cap);
        Ok(())
    }

    // -------------------------------------------------------------------- fills

    /// Apply a signed fill to an account's position in `market`, folding any
    /// realized PnL into collateral and refreshing the cached risk columns.
    pub fn apply_fill(
        &mut self,
        account: AccountId,
        market: MarketId,
        signed_qty: Quantity,
        price: Price,
    ) -> Result<(), RiskError> {
        let i = self.active_index(account)?;
        let pos_idx = self.position_slot(i, market);
        let realized = self.perp[i][pos_idx].apply_fill(signed_qty, price)?;
        self.collateral[i] = self.collateral[i].checked_add(realized)?;
        // Drop a flattened position to keep scans tight (only when at the end).
        if self.perp[i][pos_idx].is_flat() && pos_idx + 1 == self.perp[i].len() {
            self.perp[i].pop();
        }
        self.recompute(i)
    }

    /// Add a payout-vector (multi-outcome) position to an account.
    ///
    /// The position is admitted only if, once its worst-case scenario liability
    /// is folded into the account's requirement, the account still meets initial
    /// margin. A short multi-outcome claim posted without collateral to cover its
    /// worst outcome is rejected with [`RiskError::InsufficientMargin`] and no
    /// position is recorded. Every payout mutation recomputes the cached columns
    /// so equity, IM, MM, and the liquidation scan reflect the new book.
    pub fn open_payout_position(
        &mut self,
        account: AccountId,
        payout: PayoutVector,
        signed_qty: Quantity,
    ) -> Result<(), RiskError> {
        let i = self.active_index(account)?;
        self.payout[i].push(PayoutPosition::new(payout, signed_qty));
        self.recompute(i)?;
        let required = self.cached_im[i];
        let available = self.cached_equity[i];
        if available.raw() < required.raw() {
            // Roll the book back to its pre-trade state; the account cannot
            // collateralize this position's worst-case liability.
            self.payout[i].pop();
            self.recompute(i)?;
            return Err(RiskError::InsufficientMargin {
                required,
                available,
            });
        }
        Ok(())
    }

    // --------------------------------------------------------------- pre-trade

    /// Allocation-free pre-trade risk check against the portfolio.
    ///
    /// A reduce-only order is admitted iff the account currently has exposure to
    /// reduce. An exposure-increasing order is admitted iff, after adding
    /// `notional`, the account still meets initial margin — which includes the
    /// worst-case scenario collateral its payout-vector book demands — stays
    /// within `max_leverage`, and respects the portfolio cap. The account is
    /// never admitted below maintenance margin as a consequence, since initial
    /// margin dominates maintenance margin.
    pub fn check_order(
        &self,
        account: AccountId,
        notional: Amount,
        reduce_only: bool,
    ) -> Result<(), RiskError> {
        let i = self.active_index(account)?;
        if notional.is_negative() {
            return Err(RiskError::NegativeAmount);
        }
        if reduce_only {
            if self.cached_exposure[i].raw() > 0 {
                return Ok(());
            }
            return Err(RiskError::NothingToReduce);
        }
        let projected = self.cached_exposure[i].checked_add(notional)?;
        if let Some(cap) = self.portfolio_limit {
            if projected.raw() > cap.raw() {
                return Err(RiskError::PortfolioLimitExceeded);
            }
        }
        // Initial margin on the projected perp notional plus the worst-case
        // scenario collateral the existing payout-vector book already reserves.
        let required = projected
            .mul_ratio(self.config.initial_margin)?
            .checked_add(self.cached_scenario[i])?;
        let available = self.cached_equity[i];
        if available.raw() < required.raw() {
            return Err(RiskError::InsufficientMargin {
                required,
                available,
            });
        }
        let max_notional = available.mul_ratio(self.config.max_leverage)?;
        if projected.raw() > max_notional.raw() {
            return Err(RiskError::LeverageExceeded);
        }
        Ok(())
    }

    /// Pre-trade check that additionally enforces a single market's notional cap.
    pub fn check_order_in_market(
        &self,
        account: AccountId,
        market: MarketId,
        notional: Amount,
        reduce_only: bool,
    ) -> Result<(), RiskError> {
        let i = self.active_index(account)?;
        if !reduce_only {
            if let Some(cap) = self.market_limit_for(market) {
                let current = self.market_exposure(i, market)?;
                let projected = current.checked_add(notional)?;
                if projected.raw() > cap.raw() {
                    return Err(RiskError::MarketLimitExceeded);
                }
            }
        }
        self.check_order(account, notional, reduce_only)
    }

    /// Execution priority hint: risk-reducing for reduce-only orders or
    /// distressed accounts, otherwise normal.
    pub fn order_priority(
        &self,
        account: AccountId,
        reduce_only: bool,
    ) -> Result<OrderPriority, RiskError> {
        let i = self.active_index(account)?;
        if reduce_only || self.cached_equity[i].raw() <= self.cached_mm[i].raw() {
            Ok(OrderPriority::RiskReducing)
        } else {
            Ok(OrderPriority::Normal)
        }
    }

    // ---------------------------------------------------------------- readouts

    /// Cached account equity (collateral + unrealized PnL at mark).
    pub fn equity(&self, account: AccountId) -> Result<Amount, RiskError> {
        Ok(self.cached_equity[self.read_index(account)?])
    }

    /// Cached initial-margin requirement.
    pub fn initial_margin(&self, account: AccountId) -> Result<Amount, RiskError> {
        Ok(self.cached_im[self.read_index(account)?])
    }

    /// Cached maintenance-margin requirement (== liquidation threshold).
    pub fn maintenance_margin(&self, account: AccountId) -> Result<Amount, RiskError> {
        Ok(self.cached_mm[self.read_index(account)?])
    }

    /// Cached absolute notional exposure.
    pub fn exposure(&self, account: AccountId) -> Result<Amount, RiskError> {
        Ok(self.cached_exposure[self.read_index(account)?])
    }

    /// Cached worst-case scenario collateral demanded by the payout-vector book.
    /// Included in both the initial- and maintenance-margin requirements.
    pub fn scenario_margin(&self, account: AccountId) -> Result<Amount, RiskError> {
        Ok(self.cached_scenario[self.read_index(account)?])
    }

    /// The maintenance-margin liquidation threshold for an account.
    pub fn liquidation_threshold(&self, account: AccountId) -> Result<Amount, RiskError> {
        self.maintenance_margin(account)
    }

    /// Free collateral withdrawable without breaching initial margin.
    pub fn free_collateral(&self, account: AccountId) -> Result<Amount, RiskError> {
        let i = self.read_index(account)?;
        self.cached_equity[i]
            .checked_sub(self.cached_im[i])
            .map_err(RiskError::from)
    }

    /// Current collateral balance.
    pub fn collateral(&self, account: AccountId) -> Result<Amount, RiskError> {
        Ok(self.collateral[self.read_index(account)?])
    }

    /// Worst-case equity across all payout-vector outcomes, holding perp
    /// positions at mark. This is the required-collateral basis for
    /// multi-outcome exposure.
    pub fn worst_case_equity(&self, account: AccountId) -> Result<Amount, RiskError> {
        let i = self.read_index(account)?;
        let mut wc = self.collateral[i];
        for pos in &self.perp[i] {
            let mark = self.mark_for(pos.market).unwrap_or(pos.avg_entry);
            wc = wc.checked_add(pos.unrealized(mark)?)?;
        }
        for pp in &self.payout[i] {
            wc = wc.checked_add(pp.worst_case_pnl()?)?;
        }
        Ok(wc)
    }

    /// Collateral required so the account is solvent in every scenario:
    /// `max(0, -(worst_case_equity - collateral))`.
    pub fn required_scenario_collateral(&self, account: AccountId) -> Result<Amount, RiskError> {
        let i = self.read_index(account)?;
        let wce = self.worst_case_equity(account)?;
        let scenario = wce.checked_sub(self.collateral[i])?;
        if scenario.is_negative() {
            neg_amount(scenario)
        } else {
            Ok(Amount::ZERO)
        }
    }

    // ------------------------------------------------------------- liquidation

    /// Accounts strictly below maintenance margin, in ascending index order.
    pub fn liquidation_candidates(&self) -> Vec<AccountId> {
        let mut out = Vec::new();
        for i in 0..self.used.len() {
            if self.open[i] && self.cached_equity[i].raw() < self.cached_mm[i].raw() {
                if let Ok(id) = AccountId::from_index(i) {
                    out.push(id);
                }
            }
        }
        out
    }

    /// Push all current candidates onto the liquidation queue; returns the count
    /// newly considered.
    pub fn enqueue_liquidations(&mut self) -> usize {
        let candidates = self.liquidation_candidates();
        let n = candidates.len();
        for id in candidates {
            self.liq_queue.enqueue(id);
        }
        n
    }

    /// Pop the next queued account to liquidate.
    pub fn next_liquidation(&mut self) -> Option<AccountId> {
        self.liq_queue.pop()
    }

    /// Number of accounts waiting in the liquidation queue.
    pub fn liquidation_queue_len(&self) -> usize {
        self.liq_queue.len()
    }

    /// Liquidate an account: close its book at mark, then cover any shortfall
    /// from the insurance fund first and socialize only the uncovered
    /// remainder. Solvent accounts have their residual equity returned.
    pub fn liquidate(&mut self, account: AccountId) -> Result<LiquidationOutcome, RiskError> {
        let i = self.active_index(account)?;
        let final_equity = self.cached_equity[i];

        let (insurance_drawn, socialized_loss, returned_collateral) = if final_equity.is_negative()
        {
            let shortfall = neg_amount(final_equity)?;
            let (drawn, uncovered) = self.insurance.cover(shortfall)?;
            self.socialized_total = self.socialized_total.checked_add(uncovered)?;
            (drawn, uncovered, Amount::ZERO)
        } else {
            (Amount::ZERO, Amount::ZERO, final_equity)
        };

        // Bankrupt / close the account and clear its book.
        self.perp[i].clear();
        self.payout[i].clear();
        self.collateral[i] = Amount::ZERO;
        self.open[i] = false;
        self.recompute(i)?;

        Ok(LiquidationOutcome {
            account,
            final_equity,
            insurance_drawn,
            socialized_loss,
            returned_collateral,
        })
    }

    /// Current insurance-fund balance.
    #[inline]
    pub fn insurance_fund(&self) -> Amount {
        self.insurance.balance()
    }

    /// Seed / top up the insurance fund.
    pub fn fund_insurance(&mut self, amount: Amount) -> Result<(), RiskError> {
        if amount.is_negative() {
            return Err(RiskError::NegativeAmount);
        }
        self.insurance.deposit(amount)
    }

    /// Total loss socialized to date.
    #[inline]
    pub fn socialized_loss(&self) -> Amount {
        self.socialized_total
    }

    // ------------------------------------------------------------ maintenance

    /// Recompute every account's cached columns from scratch. Definitionally
    /// equal to the incremental path; used after bulk changes and in tests.
    pub fn recompute_all(&mut self) -> Result<(), RiskError> {
        // Recompute every slot (unused slots are empty and fold to zero, so the
        // pass is idempotent). The loop body indexes no single slice, avoiding a
        // needless-range-loop rewrite that the `&mut self` borrow would forbid.
        let n = self.used.len();
        for i in 0..n {
            self.recompute(i)?;
        }
        Ok(())
    }

    /// Number of account slots ever opened.
    #[inline]
    pub fn account_count(&self) -> usize {
        self.used.iter().filter(|&&u| u).count()
    }

    /// Deterministic order-sensitive fingerprint of all cached risk state.
    /// Replaying an identical command stream yields an identical root.
    pub fn state_root(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for i in 0..self.used.len() {
            fnv(&mut h, i128::from(u8::from(self.open[i])));
            fnv(&mut h, self.collateral[i].raw());
            fnv(&mut h, self.cached_equity[i].raw());
            fnv(&mut h, self.cached_exposure[i].raw());
            fnv(&mut h, self.cached_im[i].raw());
            fnv(&mut h, self.cached_mm[i].raw());
        }
        fnv(&mut h, self.insurance_fund().raw());
        fnv(&mut h, self.socialized_total.raw());
        h
    }

    // --------------------------------------------------------------- internals

    fn recompute(&mut self, i: usize) -> Result<(), RiskError> {
        let (equity, exposure, scenario) = self.compute(i)?;
        self.cached_equity[i] = equity;
        self.cached_exposure[i] = exposure;
        self.cached_scenario[i] = scenario;
        // Perp margin is a fraction of notional; payout margin is the full
        // worst-case scenario liability (settlement is certain to realize some
        // outcome, so no volatility haircut applies). Both requirements add.
        self.cached_im[i] = exposure
            .mul_ratio(self.config.initial_margin)?
            .checked_add(scenario)?;
        self.cached_mm[i] = exposure
            .mul_ratio(self.config.maintenance_margin)?
            .checked_add(scenario)?;
        Ok(())
    }

    /// Compute `(equity, perp_exposure, scenario_collateral)` for one account.
    ///
    /// `scenario_collateral` is `max(0, -Σ worst_case_pnl)` over the payout-vector
    /// book: the collateral floor at which the book stays solvent if every
    /// multi-outcome position settles at its least favorable outcome. Summing the
    /// per-position worst cases is the exact portfolio worst case for independent
    /// markets and conservative otherwise.
    fn compute(&self, i: usize) -> Result<(Amount, Amount, Amount), RiskError> {
        let mut equity = self.collateral[i];
        for pos in &self.perp[i] {
            let mark = self.mark_for(pos.market).unwrap_or(pos.avg_entry);
            equity = equity.checked_add(pos.unrealized(mark)?)?;
        }
        let exposure = match self.margin_mode[i] {
            MarginMode::Isolated => {
                let mut e = Amount::ZERO;
                for pos in &self.perp[i] {
                    let mark = self.mark_for(pos.market).unwrap_or(pos.avg_entry);
                    e = e.checked_add(pos.exposure(mark)?)?;
                }
                e
            }
            MarginMode::Cross => self.cross_exposure(i)?,
        };
        let mut payout_worst = Amount::ZERO;
        for pp in &self.payout[i] {
            payout_worst = payout_worst.checked_add(pp.worst_case_pnl()?)?;
        }
        let scenario = if payout_worst.is_negative() {
            neg_amount(payout_worst)?
        } else {
            Amount::ZERO
        };
        Ok((equity, exposure, scenario))
    }

    /// Cross exposure: sum over risk groups of the absolute *net* signed
    /// notional. Allocates a small accumulator bounded by the account's open
    /// markets.
    fn cross_exposure(&self, i: usize) -> Result<Amount, RiskError> {
        let mut groups: Vec<(u32, Amount)> = Vec::new();
        for pos in &self.perp[i] {
            let mark = self.mark_for(pos.market).unwrap_or(pos.avg_entry);
            let sn = pos.signed_notional(mark)?;
            let g = self.group_of(pos.market);
            match groups.iter_mut().find(|(gg, _)| *gg == g) {
                Some(entry) => entry.1 = entry.1.checked_add(sn)?,
                None => groups.push((g, sn)),
            }
        }
        let mut e = Amount::ZERO;
        for (_, sn) in &groups {
            e = e.checked_add(abs_amount(*sn)?)?;
        }
        Ok(e)
    }

    fn market_exposure(&self, i: usize, market: MarketId) -> Result<Amount, RiskError> {
        for pos in &self.perp[i] {
            if pos.market == market {
                let mark = self.mark_for(market).unwrap_or(pos.avg_entry);
                return pos.exposure(mark);
            }
        }
        Ok(Amount::ZERO)
    }

    fn position_slot(&mut self, i: usize, market: MarketId) -> usize {
        if let Some(idx) = self.perp[i].iter().position(|p| p.market == market) {
            idx
        } else {
            self.perp[i].push(PerpPosition::flat(market));
            self.perp[i].len() - 1
        }
    }

    fn mark_for(&self, market: MarketId) -> Option<Price> {
        let mi = market.index().ok()?;
        self.marks.get(mi).copied().flatten()
    }

    fn group_of(&self, market: MarketId) -> u32 {
        market
            .index()
            .ok()
            .and_then(|mi| self.risk_group.get(mi).copied().flatten())
            .unwrap_or_else(|| market.get())
    }

    fn market_limit_for(&self, market: MarketId) -> Option<Amount> {
        let mi = market.index().ok()?;
        self.market_limit.get(mi).copied().flatten()
    }

    /// Index of an account that must be active (open) for mutation/checks.
    fn active_index(&self, account: AccountId) -> Result<usize, RiskError> {
        let i = account.index()?;
        match self.used.get(i) {
            Some(true) if self.open[i] => Ok(i),
            Some(true) => Err(RiskError::AccountClosed),
            _ => Err(RiskError::UnknownAccount),
        }
    }

    /// Index of an account that has been opened (may be closed) for reads.
    fn read_index(&self, account: AccountId) -> Result<usize, RiskError> {
        let i = account.index()?;
        match self.used.get(i) {
            Some(true) => Ok(i),
            _ => Err(RiskError::UnknownAccount),
        }
    }

    fn grow_accounts(&mut self, i: usize) {
        if i >= self.used.len() {
            let n = i + 1;
            self.used.resize(n, false);
            self.open.resize(n, false);
            self.margin_mode.resize(n, MarginMode::Isolated);
            self.collateral.resize(n, Amount::ZERO);
            self.perp.resize(n, Vec::new());
            self.payout.resize(n, Vec::new());
            self.cached_equity.resize(n, Amount::ZERO);
            self.cached_exposure.resize(n, Amount::ZERO);
            self.cached_scenario.resize(n, Amount::ZERO);
            self.cached_im.resize(n, Amount::ZERO);
            self.cached_mm.resize(n, Amount::ZERO);
        }
    }

    fn grow_market(&mut self, mi: usize) {
        if mi >= self.marks.len() {
            let n = mi + 1;
            self.marks.resize(n, None);
            self.risk_group.resize(n, None);
            self.market_limit.resize(n, None);
        }
    }
}

/// FNV-1a fold of one `i128` (little-endian) into a running hash.
#[inline]
fn fnv(hash: &mut u64, value: i128) {
    for b in value.to_le_bytes() {
        *hash ^= u64::from(b);
        *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::Ratio;

    const P: i64 = 1_000_000; // price 1.0
    const Q: i64 = 1_000_000; // qty 1.0
    const A: i128 = 1_000_000; // amount 1.0

    fn amt(units: i128) -> Amount {
        Amount::from_raw(units * A)
    }
    fn price(units: i64) -> Price {
        Price::from_raw(units * P)
    }
    fn qty(units: i64) -> Quantity {
        Quantity::from_raw(units * Q)
    }

    // initial 10%, maintenance 5%, max leverage 20x.
    fn cfg() -> RiskConfig {
        RiskConfig::new(
            Ratio::from_raw(100_000),
            Ratio::from_raw(50_000),
            Ratio::from_raw(20_000_000),
        )
        .unwrap()
    }

    fn engine() -> RiskEngine {
        RiskEngine::new(cfg())
    }

    fn acct(n: u32) -> AccountId {
        AccountId::new(n)
    }
    fn mkt(n: u32) -> MarketId {
        MarketId::new(n)
    }
    /// A payout vector from raw `Amount` units (already at the 6-dp scale).
    fn pv(raw: &[i128]) -> PayoutVector {
        PayoutVector::new(raw.iter().map(|&x| Amount::from_raw(x)).collect()).unwrap()
    }

    #[test]
    fn margin_math_on_known_values() {
        let mut e = engine();
        e.open_account(acct(1), amt(1_000)).unwrap();
        e.set_mark_price(mkt(1), price(100)).unwrap();
        // Buy 5 @ 100 -> exposure 500, equity still 1000 (fill at mark).
        e.apply_fill(acct(1), mkt(1), qty(5), price(100)).unwrap();
        assert_eq!(e.exposure(acct(1)).unwrap(), amt(500));
        assert_eq!(e.equity(acct(1)).unwrap(), amt(1_000));
        // IM 10% of 500 = 50; MM 5% = 25.
        assert_eq!(e.initial_margin(acct(1)).unwrap(), amt(50));
        assert_eq!(e.maintenance_margin(acct(1)).unwrap(), amt(25));
        // Mark rises to 110 -> unrealized (110-100)*5 = 50, equity 1050.
        e.set_mark_price(mkt(1), price(110)).unwrap();
        assert_eq!(e.equity(acct(1)).unwrap(), amt(1_050));
        assert_eq!(e.exposure(acct(1)).unwrap(), amt(550));
    }

    #[test]
    fn conservation_fill_at_mark_and_fee() {
        let mut e = engine();
        e.open_account(acct(1), amt(1_000)).unwrap();
        e.set_mark_price(mkt(1), price(100)).unwrap();
        e.apply_fill(acct(1), mkt(1), qty(3), price(100)).unwrap();
        let before = e.equity(acct(1)).unwrap();
        // Reduce at mark: equity unchanged (value only moves ledger to ledger).
        e.apply_fill(acct(1), mkt(1), qty(-1), price(100)).unwrap();
        assert_eq!(e.equity(acct(1)).unwrap(), before);
        // Fee reduces equity by exactly the fee.
        e.apply_fee(acct(1), amt(7)).unwrap();
        assert_eq!(
            e.equity(acct(1)).unwrap(),
            before.checked_sub(amt(7)).unwrap()
        );
    }

    #[test]
    fn healthy_passes_undermargined_rejected() {
        let mut e = engine();
        e.open_account(acct(1), amt(100)).unwrap();
        e.set_mark_price(mkt(1), price(100)).unwrap();
        // Adding 500 notional needs IM 50 <= equity 100: OK.
        assert!(e.check_order(acct(1), amt(500), false).is_ok());
        // Adding 2000 notional needs IM 200 > equity 100: rejected.
        assert!(matches!(
            e.check_order(acct(1), amt(2_000), false),
            Err(RiskError::InsufficientMargin { .. })
        ));
    }

    #[test]
    fn reduce_only_admitted_iff_exposure() {
        let mut e = engine();
        e.open_account(acct(1), amt(100)).unwrap();
        e.set_mark_price(mkt(1), price(100)).unwrap();
        // No position: reduce-only has nothing to reduce.
        assert_eq!(
            e.check_order(acct(1), amt(10), true),
            Err(RiskError::NothingToReduce)
        );
        e.apply_fill(acct(1), mkt(1), qty(5), price(100)).unwrap();
        // Now there is exposure: reduce-only is admitted.
        assert!(e.check_order(acct(1), amt(10), true).is_ok());
    }

    #[test]
    fn leverage_cap_rejects() {
        // 1x max leverage engine.
        let mut e = RiskEngine::new(
            RiskConfig::new(
                Ratio::from_raw(100_000),
                Ratio::from_raw(50_000),
                Ratio::from_raw(1_000_000),
            )
            .unwrap(),
        );
        e.open_account(acct(1), amt(100)).unwrap();
        e.set_mark_price(mkt(1), price(100)).unwrap();
        // 100 notional == 1x equity: OK. 101 exceeds leverage.
        assert!(e.check_order(acct(1), amt(100), false).is_ok());
        assert_eq!(
            e.check_order(acct(1), amt(101), false),
            Err(RiskError::LeverageExceeded)
        );
    }

    #[test]
    fn portfolio_and_market_limits() {
        let mut e = engine();
        e.open_account(acct(1), amt(10_000)).unwrap();
        e.set_mark_price(mkt(1), price(100)).unwrap();
        e.set_portfolio_limit(amt(1_000)).unwrap();
        e.set_market_limit(mkt(1), amt(300)).unwrap();
        assert_eq!(
            e.check_order(acct(1), amt(1_500), false),
            Err(RiskError::PortfolioLimitExceeded)
        );
        assert_eq!(
            e.check_order_in_market(acct(1), mkt(1), amt(400), false),
            Err(RiskError::MarketLimitExceeded)
        );
        // Within both caps.
        assert!(e
            .check_order_in_market(acct(1), mkt(1), amt(200), false)
            .is_ok());
    }

    #[test]
    fn liquidation_candidates_flag_below_maintenance() {
        let mut e = engine();
        e.open_account(acct(1), amt(30)).unwrap();
        e.set_mark_price(mkt(1), price(100)).unwrap();
        // Exposure 500 -> MM 25. Equity 30 > 25: healthy.
        e.apply_fill(acct(1), mkt(1), qty(5), price(100)).unwrap();
        assert!(e.liquidation_candidates().is_empty());
        // Mark drops to 98 -> unrealized (98-100)*5 = -10, equity 20 < MM 24.5.
        e.set_mark_price(mkt(1), price(98)).unwrap();
        assert_eq!(e.liquidation_candidates(), vec![acct(1)]);
    }

    #[test]
    fn isolated_vs_cross_hedged_and_unhedged() {
        // Two markets in the SAME risk group, opposite positions.
        let mut e = engine();
        e.open_account(acct(1), amt(1_000)).unwrap();
        e.set_risk_group(mkt(1), 7).unwrap();
        e.set_risk_group(mkt(2), 7).unwrap();
        e.set_mark_price(mkt(1), price(100)).unwrap();
        e.set_mark_price(mkt(2), price(100)).unwrap();
        e.apply_fill(acct(1), mkt(1), qty(5), price(100)).unwrap(); // long 500
        e.apply_fill(acct(1), mkt(2), qty(-3), price(100)).unwrap(); // short 300

        let isolated = e.exposure(acct(1)).unwrap(); // 500 + 300 = 800
        assert_eq!(isolated, amt(800));

        e.set_margin_mode(acct(1), MarginMode::Cross).unwrap();
        let cross = e.exposure(acct(1)).unwrap(); // |500 - 300| = 200
        assert_eq!(cross, amt(200));
        assert!(cross.raw() <= isolated.raw());

        // Non-offsetting: both long -> cross == isolated.
        let mut e2 = engine();
        e2.open_account(acct(2), amt(1_000)).unwrap();
        e2.set_risk_group(mkt(1), 7).unwrap();
        e2.set_risk_group(mkt(2), 7).unwrap();
        e2.set_mark_price(mkt(1), price(100)).unwrap();
        e2.set_mark_price(mkt(2), price(100)).unwrap();
        e2.apply_fill(acct(2), mkt(1), qty(5), price(100)).unwrap();
        e2.apply_fill(acct(2), mkt(2), qty(3), price(100)).unwrap();
        let iso = e2.exposure(acct(2)).unwrap();
        e2.set_margin_mode(acct(2), MarginMode::Cross).unwrap();
        assert_eq!(e2.exposure(acct(2)).unwrap(), iso);
    }

    #[test]
    fn worst_case_payout_collateral() {
        let mut e = engine();
        e.open_account(acct(1), amt(2)).unwrap();
        // Short 1 binary claim paying [1.0, 0.0]: worst case -1.0.
        let market = PayoutVector::new(vec![Amount::from_raw(A), Amount::ZERO]).unwrap();
        e.open_payout_position(acct(1), market, qty(-1)).unwrap();
        // Worst-case equity: collateral 2 + (-1) = 1.
        assert_eq!(e.worst_case_equity(acct(1)).unwrap(), amt(1));
        // Required scenario collateral to cover the short = 1.
        assert_eq!(e.required_scenario_collateral(acct(1)).unwrap(), amt(1));
    }

    #[test]
    fn liquidation_solvent_returns_equity() {
        let mut e = engine();
        e.fund_insurance(amt(100)).unwrap();
        e.open_account(acct(1), amt(50)).unwrap();
        e.set_mark_price(mkt(1), price(100)).unwrap();
        e.apply_fill(acct(1), mkt(1), qty(5), price(100)).unwrap();
        let outcome = e.liquidate(acct(1)).unwrap();
        assert_eq!(outcome.final_equity, amt(50));
        assert_eq!(outcome.returned_collateral, amt(50));
        assert_eq!(outcome.socialized_loss, Amount::ZERO);
        assert_eq!(e.insurance_fund(), amt(100));
    }

    #[test]
    fn liquidation_shortfall_within_insurance() {
        let mut e = engine();
        e.fund_insurance(amt(100)).unwrap();
        e.open_account(acct(1), amt(10)).unwrap();
        e.set_mark_price(mkt(1), price(100)).unwrap();
        e.apply_fill(acct(1), mkt(1), qty(5), price(100)).unwrap();
        // Crash mark to 96 -> unrealized -20, equity -10 (bankrupt).
        e.set_mark_price(mkt(1), price(96)).unwrap();
        assert_eq!(e.equity(acct(1)).unwrap(), amt(-10));
        let outcome = e.liquidate(acct(1)).unwrap();
        assert_eq!(outcome.insurance_drawn, amt(10));
        assert_eq!(outcome.socialized_loss, Amount::ZERO);
        assert_eq!(e.insurance_fund(), amt(90));
        assert!(!outcome.had_socialized_loss());
    }

    #[test]
    fn liquidation_socialized_when_insurance_short() {
        let mut e = engine();
        e.fund_insurance(amt(4)).unwrap();
        e.open_account(acct(1), amt(10)).unwrap();
        e.set_mark_price(mkt(1), price(100)).unwrap();
        e.apply_fill(acct(1), mkt(1), qty(5), price(100)).unwrap();
        // equity -10 shortfall; insurance only 4 -> socialize 6.
        e.set_mark_price(mkt(1), price(96)).unwrap();
        let outcome = e.liquidate(acct(1)).unwrap();
        assert_eq!(outcome.insurance_drawn, amt(4));
        assert_eq!(outcome.socialized_loss, amt(6));
        assert_eq!(e.insurance_fund(), Amount::ZERO);
        assert_eq!(e.socialized_loss(), amt(6));
        // Insurance was fully drawn BEFORE socializing: drawn + socialized == shortfall.
        assert_eq!(
            outcome
                .insurance_drawn
                .checked_add(outcome.socialized_loss)
                .unwrap(),
            amt(10)
        );
    }

    #[test]
    fn incremental_equals_batch_recompute() {
        let mut e = engine();
        for a in 1..=5u32 {
            e.open_account(acct(a), amt(1_000)).unwrap();
        }
        e.set_mark_price(mkt(1), price(100)).unwrap();
        e.set_mark_price(mkt(2), price(50)).unwrap();
        for a in 1..=5u32 {
            let s = i64::from(a);
            e.apply_fill(acct(a), mkt(1), qty(s), price(100)).unwrap();
            e.apply_fill(acct(a), mkt(2), qty(-s), price(50)).unwrap();
        }
        let incremental = e.state_root();
        e.recompute_all().unwrap();
        assert_eq!(e.state_root(), incremental);
    }

    // Deterministic in-test LCG (no external crates).
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn range(&mut self, lo: i64, hi: i64) -> i64 {
            let span = u64::try_from(hi - lo).unwrap() + 1;
            lo + i64::try_from(self.next() % span).unwrap()
        }
    }

    fn build_engine_from_seed(seed: u64) -> RiskEngine {
        let mut e = engine();
        let mut r = Lcg(seed);
        for a in 1..=6u32 {
            e.open_account(acct(a), amt(10_000)).unwrap();
        }
        e.set_mark_price(mkt(1), price(100)).unwrap();
        e.set_mark_price(mkt(2), price(200)).unwrap();
        for _ in 0..400 {
            let a = u32::try_from(r.range(1, 6)).unwrap();
            let m = u32::try_from(r.range(1, 2)).unwrap();
            let q = r.range(-5, 5);
            let px = r.range(90, 210);
            // Fills must not panic; overflow-safe ops may legitimately error.
            let _ = e.apply_fill(
                acct(a),
                mkt(m),
                Quantity::from_raw(q * Q),
                Price::from_raw(px * P),
            );
        }
        e
    }

    #[test]
    fn property_random_fills_preserve_invariants() {
        let mut e = build_engine_from_seed(0xABCD_1234);
        // Invariant 1: cached equity == collateral + sum of unrealized PnL.
        // Invariant 2: incremental caches == full batch recompute.
        let before = e.state_root();
        e.recompute_all().unwrap();
        assert_eq!(e.state_root(), before);

        for a in 1..=6u32 {
            let i = acct(a).index().unwrap();
            let mut expected = e.collateral[i];
            for pos in &e.perp[i] {
                let mark = e.mark_for(pos.market).unwrap_or(pos.avg_entry);
                expected = expected.checked_add(pos.unrealized(mark).unwrap()).unwrap();
            }
            assert_eq!(e.equity(acct(a)).unwrap(), expected);
            // Maintenance margin never exceeds initial margin.
            assert!(
                e.maintenance_margin(acct(a)).unwrap().raw()
                    <= e.initial_margin(acct(a)).unwrap().raw()
            );
        }
    }

    #[test]
    fn deterministic_replay_same_state_root() {
        let a = build_engine_from_seed(0x5151_5151);
        let b = build_engine_from_seed(0x5151_5151);
        assert_eq!(a.state_root(), b.state_root());
    }

    #[test]
    fn check_order_never_panics_on_arbitrary_input() {
        let mut e = engine();
        e.open_account(acct(1), amt(100)).unwrap();
        e.set_mark_price(mkt(1), price(100)).unwrap();
        let mut r = Lcg(0xDEAD_0001);
        for _ in 0..50_000 {
            let notional =
                Amount::from_raw(i128::from(r.next()).wrapping_mul(i128::from(r.next())));
            let reduce = r.next().is_multiple_of(2);
            let _ = e.check_order(acct(1), notional, reduce);
            let _ = e.check_order(acct(999), notional, reduce); // unknown account
            let q = Quantity::from_raw(r.range(-1_000_000, 1_000_000));
            let px = Price::from_raw(r.range(1, 1_000_000));
            let _ = e.apply_fill(acct(1), mkt(1), q, px);
            let _ = e.liquidation_candidates();
            let _ = e.worst_case_equity(acct(1));
        }
    }

    // ----------------------------------------------------- payout-vector margin

    #[test]
    fn opening_short_payout_without_collateral_fails() {
        let mut e = engine();
        e.open_account(acct(1), amt(0)).unwrap();
        // Short one binary claim paying [1.0, 0.0]: worst case is a 1.0
        // liability, but the account posts no collateral.
        let market = pv(&[A, 0]);
        assert!(matches!(
            e.open_payout_position(acct(1), market.clone(), qty(-1)),
            Err(RiskError::InsufficientMargin { .. })
        ));
        // The rejected position left no trace: no scenario liability recorded.
        assert_eq!(e.scenario_margin(acct(1)).unwrap(), Amount::ZERO);
        assert_eq!(e.initial_margin(acct(1)).unwrap(), Amount::ZERO);
        assert_eq!(e.worst_case_equity(acct(1)).unwrap(), amt(0));
        // Once collateral covers the worst case, the same order is admitted.
        e.credit_collateral(acct(1), amt(1)).unwrap();
        assert!(e.open_payout_position(acct(1), market, qty(-1)).is_ok());
        assert_eq!(e.scenario_margin(acct(1)).unwrap(), amt(1));
        assert_eq!(e.initial_margin(acct(1)).unwrap(), amt(1));
        assert_eq!(e.maintenance_margin(acct(1)).unwrap(), amt(1));
    }

    #[test]
    fn opening_long_payout_needs_no_collateral() {
        let mut e = engine();
        e.open_account(acct(1), amt(0)).unwrap();
        // A long binary claim can never owe: worst case is 0, so it is admitted
        // with no collateral and demands no scenario margin.
        let market = pv(&[A, 0]);
        assert!(e.open_payout_position(acct(1), market, qty(1)).is_ok());
        assert_eq!(e.scenario_margin(acct(1)).unwrap(), Amount::ZERO);
        assert_eq!(e.initial_margin(acct(1)).unwrap(), Amount::ZERO);
    }

    #[test]
    fn liquidation_candidates_include_underwater_payout() {
        let mut e = engine();
        e.open_account(acct(1), amt(2)).unwrap();
        // Short one binary claim: scenario liability 1.0, margin 1.0.
        let market = pv(&[A, 0]);
        e.open_payout_position(acct(1), market, qty(-1)).unwrap();
        assert_eq!(e.maintenance_margin(acct(1)).unwrap(), amt(1));
        // Equity 2 > MM 1: healthy, not a candidate.
        assert!(e.liquidation_candidates().is_empty());
        // A fee eats collateral down to 0.5, below the payout book's 1.0 floor.
        e.apply_fee(acct(1), Amount::from_raw(3 * A / 2)).unwrap();
        assert_eq!(e.equity(acct(1)).unwrap(), Amount::from_raw(A / 2));
        // Worst-case equity is now negative: the payout book is underwater.
        assert_eq!(
            e.worst_case_equity(acct(1)).unwrap(),
            Amount::from_raw(-A / 2)
        );
        assert_eq!(e.liquidation_candidates(), vec![acct(1)]);
        assert_eq!(e.enqueue_liquidations(), 1);
    }

    #[test]
    fn golden_margin_binary_multi_scalar() {
        // Golden vectors: for a pure payout book the margin equals the worst-case
        // scenario liability (no perp exposure, so no volatility haircut).

        // Binary short [1.0, 0.0], qty -1 -> worst -1.0.
        let mut e = engine();
        e.open_account(acct(1), amt(10)).unwrap();
        e.open_payout_position(acct(1), pv(&[A, 0]), qty(-1))
            .unwrap();
        assert_eq!(e.scenario_margin(acct(1)).unwrap(), amt(1));
        assert_eq!(e.initial_margin(acct(1)).unwrap(), amt(1));
        assert_eq!(e.maintenance_margin(acct(1)).unwrap(), amt(1));

        // Multi-outcome short [0.2, 0.5, 1.0], qty -2 -> worst -2.0.
        let mut e = engine();
        e.open_account(acct(1), amt(10)).unwrap();
        e.open_payout_position(acct(1), pv(&[A / 5, A / 2, A]), qty(-2))
            .unwrap();
        assert_eq!(e.scenario_margin(acct(1)).unwrap(), amt(2));
        assert_eq!(e.initial_margin(acct(1)).unwrap(), amt(2));
        assert_eq!(e.maintenance_margin(acct(1)).unwrap(), amt(2));

        // Scalar/range short [0.25, 0.5, 0.75], qty -1 -> worst -0.75.
        let mut e = engine();
        e.open_account(acct(1), amt(10)).unwrap();
        e.open_payout_position(acct(1), pv(&[A / 4, A / 2, 3 * A / 4]), qty(-1))
            .unwrap();
        assert_eq!(
            e.scenario_margin(acct(1)).unwrap(),
            Amount::from_raw(3 * A / 4)
        );
        assert_eq!(
            e.initial_margin(acct(1)).unwrap(),
            Amount::from_raw(3 * A / 4)
        );
        assert_eq!(
            e.maintenance_margin(acct(1)).unwrap(),
            Amount::from_raw(3 * A / 4)
        );

        // Scalar long [0.25, 0.5, 0.75], qty 1 -> worst +0.25: no margin.
        let mut e = engine();
        e.open_account(acct(1), amt(10)).unwrap();
        e.open_payout_position(acct(1), pv(&[A / 4, A / 2, 3 * A / 4]), qty(1))
            .unwrap();
        assert_eq!(e.scenario_margin(acct(1)).unwrap(), Amount::ZERO);
        assert_eq!(e.initial_margin(acct(1)).unwrap(), Amount::ZERO);
    }

    #[test]
    fn mixed_perp_and_payout_margin_adds() {
        // Perp margin (fraction of notional) and payout margin (worst-case
        // liability) sum into the same requirement.
        let mut e = engine();
        e.open_account(acct(1), amt(1_000)).unwrap();
        e.set_mark_price(mkt(1), price(100)).unwrap();
        e.apply_fill(acct(1), mkt(1), qty(5), price(100)).unwrap(); // exposure 500
        e.open_payout_position(acct(1), pv(&[A, 0]), qty(-1))
            .unwrap(); // scenario 1
        assert_eq!(e.exposure(acct(1)).unwrap(), amt(500));
        assert_eq!(e.scenario_margin(acct(1)).unwrap(), amt(1));
        // IM = 10% * 500 + 1 = 51; MM = 5% * 500 + 1 = 26.
        assert_eq!(e.initial_margin(acct(1)).unwrap(), amt(51));
        assert_eq!(e.maintenance_margin(acct(1)).unwrap(), amt(26));
    }

    #[test]
    fn check_order_enforces_scenario_collateral() {
        // With a payout book reserving collateral, a new perp order must clear
        // perp initial margin *plus* the reserved scenario collateral.
        let mut e = engine();
        e.open_account(acct(1), amt(100)).unwrap();
        e.set_mark_price(mkt(1), price(100)).unwrap();
        // Short 50 binary claims: scenario liability 50, admitted (100 >= 50).
        e.open_payout_position(acct(1), pv(&[A, 0]), qty(-50))
            .unwrap();
        assert_eq!(e.scenario_margin(acct(1)).unwrap(), amt(50));
        // Notional 500 -> perp IM 50 + scenario 50 = 100 == equity 100: OK.
        assert!(e.check_order(acct(1), amt(500), false).is_ok());
        // Notional 501 -> 50.1 + 50 = 100.1 > 100: rejected on scenario reserve.
        assert!(matches!(
            e.check_order(acct(1), amt(501), false),
            Err(RiskError::InsufficientMargin { .. })
        ));
    }

    #[test]
    fn payout_mutation_recomputes_incrementally() {
        // Every payout mutation refreshes the cached columns: the incremental
        // path matches a from-scratch batch recompute.
        let mut e = engine();
        e.open_account(acct(1), amt(100)).unwrap();
        e.set_mark_price(mkt(1), price(100)).unwrap();
        e.apply_fill(acct(1), mkt(1), qty(3), price(100)).unwrap();
        e.open_payout_position(acct(1), pv(&[A / 5, A / 2, A]), qty(-2))
            .unwrap();
        let incremental = e.state_root();
        e.recompute_all().unwrap();
        assert_eq!(e.state_root(), incremental);
    }
}

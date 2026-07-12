//! The single-writer deterministic execution engine.
//!
//! Integrates the stablecoin ledger, session keys, per-market order books, the
//! risk engine, and the incremental state tree. `execute` applies one sequenced
//! command and returns a receipt carrying the post-command state root. Identical
//! command streams produce identical state roots (deterministic replay).

use std::collections::{HashMap, HashSet};

use orderbook::{BookConfig, MatchPlan, NewOrder, OrderBook, OrderOutcome};
use risk::{RiskConfig, RiskEngine};
use state_tree::{LeafWriter, StateTree};
use types::{
    AccountId, Amount, Hash, MarketId, MarketLifecycle, MarketType, OracleHealth, OrderType,
    Quantity, SequenceNumber, Side,
};

use crate::command::{
    Authorization, Command, DeterministicEngine, ExecutionReceipt, ReceiptKind,
};
use crate::error::ExecutionError;
use crate::idempotency::{
    command_binding, derive_withdrawal_id, GuardDecision, KeyDomain, ReplayGuard,
};
use crate::ledger::Ledger;
use crate::session::SessionRegistry;

/// Engine construction parameters.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Merkle capacity for accounts.
    pub account_capacity: usize,
    /// Merkle capacity for markets.
    pub market_capacity: usize,
    /// Number of recent command receipts retained per shard for exact
    /// idempotent-retry replay. Exactly-once is enforced regardless of this
    /// bound (the committed per-principal watermark blocks re-execution of an
    /// evicted key); the window only governs how far back an original receipt
    /// can still be returned verbatim.
    pub replay_window: usize,
    /// Risk parameters.
    pub risk: RiskConfig,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            account_capacity: 4096,
            market_capacity: 256,
            replay_window: 1 << 16,
            risk: RiskConfig {
                initial_margin: types::Ratio::from_bps(1000).unwrap_or(types::Ratio::ONE), // 10%
                maintenance_margin: types::Ratio::from_bps(500).unwrap_or(types::Ratio::ONE), // 5%
                max_leverage: types::Ratio::from_raw(20 * types::RATIO_SCALE),
                // Generous, budget-bounded dense-slot caps: the committed state
                // tree remains the tight per-deployment capacity gate, while
                // these bound the risk engine's Structure-of-Arrays against an
                // out-of-range external id demanding an unbounded allocation.
                max_accounts: risk::DEFAULT_MAX_ACCOUNTS,
                max_markets: risk::DEFAULT_MAX_MARKETS,
            },
        }
    }
}

#[derive(Debug, Clone)]
struct MarketMeta {
    market_type: MarketType,
    outcomes: u16,
    mark_price: types::Price,
    lifecycle: MarketLifecycle,
    oracle_health: OracleHealth,
    /// Maker fee bps (may be negative for rebate); 0 by default.
    maker_fee_bps: i32,
    /// Taker fee bps; 0 by default.
    taker_fee_bps: i32,
    /// Last applied funding epoch (0 = none).
    last_funding_epoch: u64,
    /// Winning outcome once resolved.
    winning_outcome: Option<u16>,
}

/// True when fills transfer outcome claims + premium cash rather than perps.
fn is_claim_market(market_type: MarketType) -> bool {
    !matches!(market_type, MarketType::Perpetual)
}

/// Number of instrument books a market exposes (one per outcome for claims).
fn instrument_count(market_type: MarketType, outcomes: u16) -> u16 {
    if is_claim_market(market_type) {
        outcomes.max(2)
    } else {
        1
    }
}

#[derive(Debug, Clone)]
struct Withdrawal {
    account: AccountId,
    amount: Amount,
    finalized: bool,
}

/// A persisted external-wallet binding for an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletBinding {
    /// External chain id.
    pub chain_id: u32,
    /// External wallet address bytes.
    pub address: Vec<u8>,
}

/// The deterministic exchange engine.
///
/// `Clone` is a deep copy of every subsystem (ledger, sessions, risk, state tree,
/// books, and the in-memory maps). [`Engine::execute`] relies on it to apply each
/// command to a throwaway working copy, giving every command an all-or-none
/// transaction boundary across all subsystems.
#[derive(Clone)]
pub struct Engine {
    ledger: Ledger,
    sessions: SessionRegistry,
    risk: RiskEngine,
    tree: StateTree,
    /// Per-(market, instrument) order books.
    books: HashMap<(u32, u16), OrderBook>,
    markets: HashMap<u32, MarketMeta>,
    /// Resting-order notional reserved: (market, instrument, order_id) -> notional.
    order_reserves: HashMap<(u32, u16, u64), (AccountId, Amount)>,
    /// Outcome claims: (account, market) -> per-outcome balances.
    claims: HashMap<(u32, u32), Vec<Amount>>,
    /// Locked complete-set collateral still attributed to a minter: (account, market).
    mint_locked: HashMap<(u32, u32), Amount>,
    deposits_seen: HashSet<(u32, Vec<u8>, u32)>,
    withdrawals: HashMap<u64, Withdrawal>,
    protocol_version: u16,
    wallets: HashMap<u32, WalletBinding>,
    /// Durable, payload-bound command idempotency (exactly-once retries).
    replay: ReplayGuard,
    last_seq: Option<u64>,
}

impl Engine {
    /// Build a new engine.
    pub fn new(config: EngineConfig) -> Self {
        Self {
            ledger: Ledger::new(),
            sessions: SessionRegistry::new(),
            risk: RiskEngine::new(config.risk),
            tree: StateTree::new(config.account_capacity, config.market_capacity),
            books: HashMap::new(),
            markets: HashMap::new(),
            order_reserves: HashMap::new(),
            claims: HashMap::new(),
            mint_locked: HashMap::new(),
            deposits_seen: HashSet::new(),
            withdrawals: HashMap::new(),
            protocol_version: 1,
            wallets: HashMap::new(),
            replay: ReplayGuard::with_window(config.replay_window),
            last_seq: None,
        }
    }

    /// The active protocol version.
    pub fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    /// Read-only ledger access.
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// The persisted external-wallet binding for `account`, if one exists.
    pub fn wallet_binding(&self, account: AccountId) -> Option<&WalletBinding> {
        self.wallets.get(&account.get())
    }

    /// Read-only risk access.
    pub fn risk(&self) -> &RiskEngine {
        &self.risk
    }

    /// Number of orders currently resting across all instruments of `market`,
    /// or `None` if the market is unknown.
    pub fn market_resting_len(&self, market: MarketId) -> Option<usize> {
        if !self.markets.contains_key(&market.get()) {
            return None;
        }
        let mut total = 0usize;
        for ((m, _), book) in &self.books {
            if *m == market.get() {
                total = total.saturating_add(book.resting_len());
            }
        }
        Some(total)
    }

    /// Outcome-claim balance for `account` in `market` at `instrument`, or zero.
    pub fn claim_balance(
        &self,
        account: AccountId,
        market: MarketId,
        instrument: u16,
    ) -> Amount {
        self.claims
            .get(&(account.get(), market.get()))
            .and_then(|v| v.get(usize::from(instrument)))
            .copied()
            .unwrap_or(Amount::ZERO)
    }

    /// Single source of truth for reduce-only: the risk engine's position.
    fn position(&self, account: AccountId, market: MarketId) -> Quantity {
        self.risk
            .position(account, market)
            .unwrap_or(Quantity::ZERO)
    }

    /// Reject new risk when the market is not Open or the oracle freezes risk.
    fn gate_new_risk(&self, market: MarketId) -> Result<(), ExecutionError> {
        let meta = self
            .markets
            .get(&market.get())
            .ok_or(ExecutionError::UnknownMarket)?;
        if !matches!(meta.lifecycle, MarketLifecycle::Open) {
            return Err(ExecutionError::MarketNotOpen);
        }
        match meta.oracle_health {
            OracleHealth::Halted | OracleHealth::Stale => {
                Err(ExecutionError::OracleRiskFrozen)
            }
            OracleHealth::Normal | OracleHealth::Degraded => Ok(()),
        }
    }

    fn residual_notional(
        result: &orderbook::MatchResult,
        price: types::Price,
        requested: Quantity,
    ) -> Result<Amount, ExecutionError> {
        let filled = result.filled_quantity();
        let remaining = requested
            .raw()
            .saturating_sub(filled.raw())
            .max(0);
        if remaining == 0 {
            return Ok(Amount::ZERO);
        }
        Ok(price.notional(Quantity::from_raw(remaining))?)
    }

    fn release_order_reserve(
        &mut self,
        market: MarketId,
        instrument: u16,
        order_id: types::OrderId,
        account: AccountId,
    ) -> Result<(), ExecutionError> {
        let key = (market.get(), instrument, order_id.get());
        if let Some((owner, notional)) = self.order_reserves.remove(&key) {
            if owner != account {
                // Put it back; wrong owner should not release.
                self.order_reserves.insert(key, (owner, notional));
                return Err(ExecutionError::OrderNotOwned);
            }
            self.risk.release_resting(account, notional)?;
        }
        Ok(())
    }

    fn reserve_order(
        &mut self,
        market: MarketId,
        instrument: u16,
        order_id: types::OrderId,
        account: AccountId,
        notional: Amount,
    ) -> Result<(), ExecutionError> {
        if notional.raw() == 0 {
            return Ok(());
        }
        self.risk.reserve_resting(account, notional)?;
        self.order_reserves
            .insert((market.get(), instrument, order_id.get()), (account, notional));
        Ok(())
    }

    fn validate_instrument(
        &self,
        market: MarketId,
        instrument: u16,
    ) -> Result<&MarketMeta, ExecutionError> {
        let meta = self
            .markets
            .get(&market.get())
            .ok_or(ExecutionError::UnknownMarket)?;
        let n = instrument_count(meta.market_type, meta.outcomes);
        if instrument >= n {
            return Err(ExecutionError::InvalidInstrument);
        }
        Ok(meta)
    }

    /// The full committed leaf for `account`: settlement ledger balances, auth
    /// epoch, risk collateral and the derived margin columns, open positions, and
    /// outcome claims — the complete economic state a light client verifies
    /// against the shard root.
    ///
    /// Positions and claim sets are emitted in ascending market order, and flat
    /// positions / fully-redeemed (all-zero) claim sets are omitted, so the leaf
    /// is canonical over economic state: replaying an identical command stream
    /// reproduces bit-identical leaves and roots regardless of map iteration
    /// order.
    pub fn account_leaf(&self, account: AccountId) -> Result<Vec<u8>, ExecutionError> {
        let mut w = LeafWriter::new();
        // Settlement ledger: available / reserved / locked / auth epoch.
        self.ledger.write_account_fields(account, &mut w)?;
        // Risk authority: collateral plus the derived equity/exposure/margin
        // columns, so trading state is committed alongside the ledger and the two
        // cannot silently diverge.
        w.field_i128(self.risk.collateral(account)?.raw())
            .field_i128(self.risk.equity(account)?.raw())
            .field_i128(self.risk.exposure(account)?.raw())
            .field_i128(self.risk.initial_margin(account)?.raw())
            .field_i128(self.risk.maintenance_margin(account)?.raw());
        // Open positions from risk (single source of truth); flats omitted.
        let mut positions: Vec<(u32, i64)> = Vec::new();
        if let Ok(perps) = self.risk.perp_positions(account) {
            for pos in perps {
                if pos.net_qty.raw() != 0 {
                    positions.push((pos.market.get(), pos.net_qty.raw()));
                }
            }
        }
        positions.sort_unstable_by_key(|&(m, _)| m);
        w.field_u32(u32::try_from(positions.len()).unwrap_or(u32::MAX));
        for (m, qty) in &positions {
            w.field_u32(*m).field_i64(*qty);
        }
        // Outcome claims, ascending by market; fully-redeemed sets omitted.
        let mut claims: Vec<(u32, &[Amount])> = Vec::new();
        for (&(a, m), amounts) in &self.claims {
            if a == account.get() && amounts.iter().any(|v| v.raw() != 0) {
                claims.push((m, amounts.as_slice()));
            }
        }
        claims.sort_unstable_by_key(|&(m, _)| m);
        w.field_u32(u32::try_from(claims.len()).unwrap_or(u32::MAX));
        for (m, amounts) in &claims {
            w.field_u32(*m)
                .field_u32(u32::try_from(amounts.len()).unwrap_or(u32::MAX));
            for v in *amounts {
                w.field_i128(v.raw());
            }
        }
        // Idempotency watermarks: the highest order `client_id` and withdrawal
        // `nonce` this account has committed. Folding them into the leaf commits
        // the exactly-once replay boundary into the state root, so a snapshot /
        // WAL recovery reconstructs it and cannot silently regress it. Each is a
        // presence flag (0 = none processed) followed by the watermark value.
        Self::write_watermark(
            &mut w,
            self.replay.watermark(account.get(), KeyDomain::Order),
        );
        Self::write_watermark(
            &mut w,
            self.replay.watermark(account.get(), KeyDomain::Withdrawal),
        );
        Ok(w.finish())
    }

    /// Append a `(present, value)` idempotency watermark to a committed leaf.
    fn write_watermark(w: &mut LeafWriter, watermark: Option<u64>) {
        match watermark {
            Some(v) => {
                w.field_u32(1)
                    .field_i64(i64::from_le_bytes(v.to_le_bytes()));
            }
            None => {
                w.field_u32(0).field_i64(0);
            }
        }
    }

    /// A light-client inclusion proof for `account`'s committed leaf against the
    /// shard [`DeterministicEngine::state_root`]. Verify it with
    /// [`state_tree::verify_account`] using the bytes from [`Self::account_leaf`].
    pub fn account_proof(&self, account: AccountId) -> Result<Vec<Hash>, ExecutionError> {
        Ok(self.tree.account_proof(account)?)
    }

    fn commit_account(&mut self, account: AccountId) -> Result<(), ExecutionError> {
        let leaf = self.account_leaf(account)?;
        self.tree.set_account(account, &leaf)?;
        Ok(())
    }

    /// Canonical committed leaf bytes for `market`: type tag, outcome count, mark
    /// price, and the market's order-book root. Shared by [`Self::commit_market`]
    /// and the invariant checks so both hash exactly the same pre-image.
    fn market_leaf(&self, market: MarketId) -> Result<Vec<u8>, ExecutionError> {
        let meta = self
            .markets
            .get(&market.get())
            .ok_or(ExecutionError::UnknownMarket)?;
        // Compose instrument book roots in ascending instrument order.
        let n = instrument_count(meta.market_type, meta.outcomes);
        let mut w = LeafWriter::new();
        let type_tag: u32 = match meta.market_type {
            MarketType::Perpetual => 0,
            MarketType::BinaryPrediction => 1,
            MarketType::MultiOutcomePrediction => 2,
            MarketType::Decision => 3,
            MarketType::Sports => 4,
            MarketType::Scalar => 5,
            MarketType::CustomPayoutVector => 6,
        };
        w.field_u32(type_tag)
            .field_u32(u32::from(meta.outcomes))
            .field_i64(meta.mark_price.raw())
            .field_u32(u32::from(n));
        for inst in 0..n {
            let book_root = self
                .books
                .get(&(market.get(), inst))
                .map(|b| b.state_root())
                .unwrap_or(Hash::ZERO);
            w.field_u32(u32::from(inst))
                .field_bytes(book_root.as_bytes());
        }
        if let Some(win) = meta.winning_outcome {
            w.field_u32(1).field_u32(u32::from(win));
        } else {
            w.field_u32(0).field_u32(0);
        }
        Ok(w.finish())
    }

    fn commit_market(&mut self, market: MarketId) -> Result<(), ExecutionError> {
        let leaf = self.market_leaf(market)?;
        self.tree.set_market(market, &leaf)?;
        Ok(())
    }

    fn signed(side: Side, qty: Quantity) -> Result<Quantity, ExecutionError> {
        match side {
            Side::Bid => Ok(qty),
            Side::Ask => Ok(Quantity::ZERO.checked_sub(qty)?),
        }
    }

    fn apply_fills(
        &mut self,
        market: MarketId,
        instrument: u16,
        result: &orderbook::MatchResult,
    ) -> Result<Vec<AccountId>, ExecutionError> {
        let meta = self
            .markets
            .get(&market.get())
            .ok_or(ExecutionError::UnknownMarket)?
            .clone();
        let (maker_bps, taker_bps) = (meta.maker_fee_bps, meta.taker_fee_bps);
        let mut touched = Vec::new();
        for fill in &result.fills {
            if is_claim_market(meta.market_type) {
                self.apply_claim_fill(market, instrument, fill)?;
            } else {
                // Perpetual fills update position / PnL only.
                let taker_signed = Self::signed(fill.taker_side, fill.quantity)?;
                let maker_signed = Self::signed(fill.taker_side.opposite(), fill.quantity)?;
                self.risk
                    .apply_fill(fill.taker_account, market, taker_signed, fill.price)?;
                self.risk
                    .apply_fill(fill.maker_account, market, maker_signed, fill.price)?;
            }
            // Release reserved IM on the filled portion of the resting maker.
            let fill_notional = fill.price.notional(fill.quantity)?;
            let key = (market.get(), instrument, fill.maker_order.get());
            if let Some((owner, reserved)) = self.order_reserves.get(&key).copied() {
                let release = if fill_notional.raw() > reserved.raw() {
                    reserved
                } else {
                    fill_notional
                };
                let next = reserved.checked_sub(release)?;
                self.risk.release_resting(owner, release)?;
                if next.raw() == 0 {
                    self.order_reserves.remove(&key);
                } else {
                    self.order_reserves.insert(key, (owner, next));
                }
            }
            // Maker/taker fees on actual fill notional (directed rounding).
            if taker_bps != 0 {
                let fee = Self::markets_fill_fee(fill_notional, taker_bps)?;
                if fee.raw() > 0 {
                    self.risk.apply_fee(fill.taker_account, fee)?;
                } else if fee.raw() < 0 {
                    // Rebate: credit collateral.
                    self.risk
                        .apply_funding(fill.taker_account, Amount::from_raw(-fee.raw()))?;
                }
            }
            if maker_bps != 0 {
                let fee = Self::markets_fill_fee(fill_notional, maker_bps)?;
                if fee.raw() > 0 {
                    self.risk.apply_fee(fill.maker_account, fee)?;
                } else if fee.raw() < 0 {
                    self.risk
                        .apply_funding(fill.maker_account, Amount::from_raw(-fee.raw()))?;
                }
            }
            touched.push(fill.taker_account);
            touched.push(fill.maker_account);
        }
        touched.sort_by_key(|a| a.get());
        touched.dedup();
        Ok(touched)
    }

    /// Transfer outcome claims and premium cash for a non-perpetual fill.
    ///
    /// The ask side sells claims; the bid side buys them. Premium
    /// (`price * quantity`) moves available stablecoin + risk collateral from
    /// buyer to seller. Never opens a [`risk::PerpPosition`].
    fn apply_claim_fill(
        &mut self,
        market: MarketId,
        instrument: u16,
        fill: &orderbook::Fill,
    ) -> Result<(), ExecutionError> {
        let meta = self
            .markets
            .get(&market.get())
            .ok_or(ExecutionError::UnknownMarket)?;
        let outcomes = usize::from(instrument_count(meta.market_type, meta.outcomes));
        let inst = usize::from(instrument);
        if inst >= outcomes {
            return Err(ExecutionError::InvalidInstrument);
        }
        let (seller, buyer) = match fill.taker_side {
            Side::Bid => (fill.maker_account, fill.taker_account),
            Side::Ask => (fill.taker_account, fill.maker_account),
        };
        let qty = Amount::from_raw(i128::from(fill.quantity.raw()));
        if qty.raw() <= 0 {
            return Err(ExecutionError::NegativeAmount);
        }
        // Debit seller claims; credit buyer claims.
        {
            let entry = self
                .claims
                .entry((seller.get(), market.get()))
                .or_insert_with(|| vec![Amount::ZERO; outcomes]);
            if entry.len() < outcomes {
                entry.resize(outcomes, Amount::ZERO);
            }
            if entry[inst] < qty {
                return Err(ExecutionError::InsufficientClaims);
            }
            entry[inst] = entry[inst].checked_sub(qty)?;
        }
        {
            let entry = self
                .claims
                .entry((buyer.get(), market.get()))
                .or_insert_with(|| vec![Amount::ZERO; outcomes]);
            if entry.len() < outcomes {
                entry.resize(outcomes, Amount::ZERO);
            }
            entry[inst] = entry[inst].checked_add(qty)?;
        }
        // Premium cash: buyer pays seller (zero-sum ledger + risk).
        let premium = fill.price.notional(fill.quantity)?;
        if premium.raw() > 0 {
            self.ledger
                .transfer_available(buyer, seller, premium)?;
            self.risk.debit_collateral(buyer, premium)?;
            self.risk.credit_collateral(seller, premium)?;
        }
        Ok(())
    }

    /// Pre-trade notional for risk / session checks.
    ///
    /// Limit orders use the limit price. Market orders **never** use a
    /// placeholder caller price for margin: they require a positive protection
    /// collar, build a deterministic match plan from executable depth, and
    /// margin the planned (ceil) notional capped by the collar worst-case.
    fn pretrade_notional(
        &self,
        market: MarketId,
        instrument: u16,
        order: &NewOrder,
        reduce_only: bool,
    ) -> Result<(Amount, MatchPlan), ExecutionError> {
        let meta = self.validate_instrument(market, instrument)?;
        let book = self
            .books
            .get(&(market.get(), instrument))
            .ok_or(ExecutionError::UnknownMarket)?;
        let plan = book.plan_match(order)?;
        if matches!(order.order_type, OrderType::Market) {
            if order.price.raw() <= 0 {
                return Err(ExecutionError::MarketOrderCollarRequired);
            }
            // Worst-case notional within the collar: max(planned ceil notional,
            // collar price * requested qty) so a sparse book cannot under-margin
            // a market order that later rests nothing (markets are IOC) but still
            // cannot be gamed by a 1-micro placeholder.
            let collar_cap = order.price.notional_ceil(order.quantity)?;
            let from_depth = if plan.filled_quantity.raw() > 0 {
                plan.notional_ceil
            } else {
                // No depth: reject later at match, but margin the collar so the
                // admission check is never cheaper than a limit at the collar.
                collar_cap
            };
            // Use the max so placeholders cannot reduce IM, and depth above the
            // collar is impossible (collar limits the plan). Cap at collar_cap.
            let notional = if from_depth.raw() > collar_cap.raw() {
                return Err(ExecutionError::MarketOrderDepthExceeded);
            } else if plan.filled_quantity.raw() == 0 {
                collar_cap
            } else {
                // Planned depth notional; still at least the worst planned price
                // times filled qty (already in plan.notional_ceil).
                from_depth
            };
            // Also ensure a pure placeholder (price=1) against deep expensive book
            // is impossible: plan honors collar so fills empty if book above collar.
            let _ = reduce_only;
            let _ = meta;
            return Ok((notional, plan));
        }
        let notional = if order.price.raw() > 0 {
            order.price.notional_ceil(order.quantity)?
        } else {
            meta.mark_price.notional_ceil(order.quantity)?
        };
        Ok((notional, plan))
    }

    fn markets_fill_fee(notional: Amount, bps: i32) -> Result<Amount, ExecutionError> {
        // Inline fee math (ceil for positive, floor rebate) to avoid a markets dep cycle.
        if bps == 0 || notional.raw() == 0 {
            return Ok(Amount::ZERO);
        }
        let abs_bps = bps.unsigned_abs();
        if abs_bps > 10_000 {
            return Err(ExecutionError::NotImplemented("fee bps out of range"));
        }
        let mag = if notional.is_negative() {
            Amount::from_raw(notional.raw().checked_neg().ok_or(types::ArithError::Overflow)?)
        } else {
            notional
        };
        let ratio = types::Ratio::from_bps(i64::from(abs_bps))?;
        if bps > 0 {
            Ok(mag.mul_ratio_ceil(ratio)?)
        } else {
            let rebate = mag.mul_ratio(ratio)?;
            Ok(Amount::from_raw(
                rebate.raw().checked_neg().ok_or(types::ArithError::Overflow)?,
            ))
        }
    }

    fn receipt(&self, sequence: u64, kind: ReceiptKind) -> ExecutionReceipt {
        ExecutionReceipt {
            sequence,
            kind,
            state_root: self.tree.root(),
        }
    }

    /// Enforce authorization for a mutating trade command acting on `account` in
    /// `market` with the given per-order `notional`.
    ///
    /// [`Authorization::Master`] carries the account owner's own authority (its
    /// signature is verified upstream) and is always accepted. A
    /// [`Authorization::Session`] command is validated against the scoped
    /// session key via [`SessionRegistry::consume`], which enforces expiry,
    /// market scope, the notional cap, and single-use nonce, and mutates the
    /// session only on success — so a rejected command leaves no state behind.
    fn authorize(
        &mut self,
        account: AccountId,
        market: MarketId,
        notional: Amount,
        auth: &Authorization,
    ) -> Result<(), ExecutionError> {
        match auth {
            Authorization::Master => Ok(()),
            Authorization::Session {
                session_key,
                nonce,
                now,
            } => self
                .sessions
                .consume(account, *session_key, *nonce, market, notional, *now),
        }
    }
}

impl Engine {
    /// Apply one already-sequence-checked command in place, mutating every
    /// affected subsystem. Callers run this against a transactional working copy
    /// (see [`Engine::execute`]), so a failure at any fallible step is discarded
    /// wholesale rather than leaving a partially-applied command behind. This
    /// method must only be reached through [`Engine::execute`].
    fn apply(&mut self, seq: u64, command: Command) -> Result<ExecutionReceipt, ExecutionError> {
        match command {
            Command::CreateAccount(c) => {
                let id = self.ledger.create_account(c.initial_collateral)?;
                self.risk.open_account(id, c.initial_collateral)?;
                self.commit_account(id)?;
                Ok(self.receipt(seq, ReceiptKind::AccountCreated(id)))
            }
            Command::BindWallet(c) => {
                if !self.ledger.contains(c.account) {
                    return Err(ExecutionError::UnknownAccount);
                }
                self.wallets.insert(
                    c.account.get(),
                    WalletBinding {
                        chain_id: c.chain_id,
                        address: c.address,
                    },
                );
                Ok(self.receipt(seq, ReceiptKind::WalletBound))
            }
            Command::AuthorizeSession(c) => {
                self.sessions.authorize(
                    c.account,
                    c.session_key,
                    c.allowed_markets,
                    c.max_notional,
                    c.expires_at,
                    c.nonce_start,
                    c.nonce_end,
                )?;
                self.ledger.bump_auth_epoch(c.account)?;
                self.commit_account(c.account)?;
                Ok(self.receipt(seq, ReceiptKind::SessionUpdated))
            }
            Command::RevokeSession(c) => {
                self.sessions.revoke(c.account, c.session_key);
                self.ledger.bump_auth_epoch(c.account)?;
                self.commit_account(c.account)?;
                Ok(self.receipt(seq, ReceiptKind::SessionUpdated))
            }
            Command::DepositCredit(c) => {
                let key = (c.source_chain, c.source_tx.clone(), c.source_event_index);
                if !self.deposits_seen.insert(key) {
                    return Err(ExecutionError::DuplicateDeposit);
                }
                self.ledger.credit(c.account, c.amount)?;
                self.risk.credit_collateral(c.account, c.amount)?;
                self.commit_account(c.account)?;
                Ok(self.receipt(seq, ReceiptKind::Credited(c.account, c.amount)))
            }
            Command::RequestWithdrawal(c) => {
                // Withdrawals move funds out of custody: only the account master
                // key may authorize them. Trading-only session keys are rejected.
                if !matches!(c.auth, Authorization::Master) {
                    return Err(ExecutionError::SessionCannotWithdraw);
                }
                // The id is a deterministic, non-wrapping function of the
                // authenticated request `(account, nonce)`, so an exact replay
                // (caught upstream by the idempotency guard) resolves to the same
                // id and the id never depends on a mutable counter a partial
                // recovery could desynchronise. A pre-existing id for a *distinct*
                // request can only be a digest collision, which is surfaced rather
                // than silently overwriting the live withdrawal.
                let id = derive_withdrawal_id(c.account.get(), c.nonce);
                if self.withdrawals.contains_key(&id) {
                    return Err(ExecutionError::WithdrawalIdCollision);
                }
                self.ledger.reserve(c.account, c.amount)?;
                self.risk.debit_collateral(c.account, c.amount)?;
                self.withdrawals.insert(
                    id,
                    Withdrawal {
                        account: c.account,
                        amount: c.amount,
                        finalized: false,
                    },
                );
                self.commit_account(c.account)?;
                Ok(self.receipt(seq, ReceiptKind::WithdrawalRequested(id)))
            }
            Command::FinalizeWithdrawal(c) => {
                let w = self
                    .withdrawals
                    .get_mut(&c.withdrawal_id)
                    .ok_or(ExecutionError::UnknownWithdrawal)?;
                if w.finalized {
                    return Err(ExecutionError::WithdrawalAlreadyFinalized);
                }
                w.finalized = true;
                let (account, amount) = (w.account, w.amount);
                self.ledger.settle_withdrawal(account, amount)?;
                self.commit_account(account)?;
                Ok(self.receipt(seq, ReceiptKind::WithdrawalFinalized(c.withdrawal_id)))
            }
            Command::CreateMarket(c) => {
                if self.markets.contains_key(&c.market.get()) {
                    return Err(ExecutionError::MarketExists);
                }
                let outcomes = if is_claim_market(c.market_type) {
                    c.outcomes.max(2)
                } else {
                    c.outcomes.max(1)
                };
                self.markets.insert(
                    c.market.get(),
                    MarketMeta {
                        market_type: c.market_type,
                        outcomes,
                        mark_price: c.mark_price,
                        lifecycle: MarketLifecycle::Open,
                        oracle_health: OracleHealth::Normal,
                        maker_fee_bps: 0,
                        taker_fee_bps: 0,
                        last_funding_epoch: 0,
                        winning_outcome: None,
                    },
                );
                let n = instrument_count(c.market_type, outcomes);
                for inst in 0..n {
                    self.books.insert(
                        (c.market.get(), inst),
                        OrderBook::new(BookConfig::default()),
                    );
                }
                self.risk.set_mark_price(c.market, c.mark_price)?;
                self.commit_market(c.market)?;
                Ok(self.receipt(seq, ReceiptKind::MarketUpdated(c.market)))
            }
            Command::SetMarkPrice(c) => {
                let meta = self
                    .markets
                    .get_mut(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?;
                meta.mark_price = c.price;
                self.risk.set_mark_price(c.market, c.price)?;
                self.commit_market(c.market)?;
                Ok(self.receipt(seq, ReceiptKind::MarketUpdated(c.market)))
            }
            Command::PlaceOrder(c) => {
                // Lifecycle + oracle gates: draft/halted/closed/resolved/archived
                // and frozen oracles reject new risk before any book/risk mutation.
                self.gate_new_risk(c.market)?;
                self.validate_instrument(c.market, c.instrument)?;
                let new_order = NewOrder {
                    order_id: c.order_id,
                    account: c.account,
                    side: c.side,
                    order_type: c.order_type,
                    tif: c.tif,
                    price: c.price,
                    quantity: c.quantity,
                    client_id: c.client_id,
                    reduce_only: c.reduce_only,
                };
                // Market orders: collar required; notional from executable depth.
                let (notional, _plan) =
                    self.pretrade_notional(c.market, c.instrument, &new_order, c.reduce_only)?;
                // Authenticate before any business logic so a rejected order
                // leaves no state behind.
                self.authorize(c.account, c.market, notional, &c.auth)?;
                // Reject insufficient collateral / claims BEFORE any maker qty change.
                let meta_type = self
                    .markets
                    .get(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?
                    .market_type;
                if is_claim_market(meta_type) {
                    match c.side {
                        Side::Bid => {
                            // Buyer posts premium: require free collateral ≥ notional.
                            self.risk.check_order(c.account, notional, false)?;
                        }
                        Side::Ask => {
                            // Seller must already hold the claims being offered.
                            let held = self.claim_balance(c.account, c.market, c.instrument);
                            let need = Amount::from_raw(i128::from(c.quantity.raw()));
                            if held < need {
                                return Err(ExecutionError::InsufficientClaims);
                            }
                        }
                    }
                } else {
                    self.risk.check_order_in_market(
                        c.account,
                        c.market,
                        notional,
                        c.reduce_only,
                    )?;
                }
                // Reduce-only clamps against the risk engine position (perps).
                let pos = self.position(c.account, c.market);
                let book = self
                    .books
                    .get_mut(&(c.market.get(), c.instrument))
                    .ok_or(ExecutionError::UnknownMarket)?;
                book.set_position(c.account, pos);
                // Idempotency is decided once, durably, at the command layer (see
                // `execute`), so the book submits through its non-deduplicating
                // path: a book-local dedup here could replay stale fills that this
                // handler would then re-apply to both counterparties.
                let result = book.place(new_order)?;
                let filled = result.filled_quantity();
                let rested = matches!(
                    result.outcome,
                    OrderOutcome::Resting { .. } | OrderOutcome::PartiallyFilledResting { .. }
                );
                let touched = self.apply_fills(c.market, c.instrument, &result)?;
                // Reserve IM for any residual that rests on the book.
                if rested {
                    let rest_notional = Self::residual_notional(&result, c.price, c.quantity)?;
                    // Limit orders use their limit price; market residuals do not rest.
                    let rest_notional = if !matches!(c.order_type, OrderType::Market)
                        && c.price.raw() > 0
                    {
                        rest_notional
                    } else {
                        Amount::ZERO
                    };
                    self.reserve_order(
                        c.market,
                        c.instrument,
                        c.order_id,
                        c.account,
                        rest_notional,
                    )?;
                }
                for a in touched {
                    self.commit_account(a)?;
                }
                // Always re-commit the order's own account: even an order that
                // rests without a fill advances this account's committed order
                // watermark (reserved in `execute` before this handler ran).
                self.commit_account(c.account)?;
                self.commit_market(c.market)?;
                Ok(self.receipt(seq, ReceiptKind::OrderApplied { filled, rested }))
            }
            Command::CancelOrder(c) => {
                // Locate the order across instruments of this market.
                let mut found: Option<(u16, AccountId)> = None;
                let meta = self
                    .markets
                    .get(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?;
                let n = instrument_count(meta.market_type, meta.outcomes);
                for inst in 0..n {
                    if let Some(book) = self.books.get(&(c.market.get(), inst)) {
                        if let Some(owner) = book.owner(c.order_id) {
                            found = Some((inst, owner));
                            break;
                        }
                    }
                }
                let (instrument, owner) = match found {
                    Some(v) => v,
                    None => {
                        // Unknown order: authorize then no-op cancel count 0.
                        self.authorize(c.account, c.market, Amount::ZERO, &c.auth)?;
                        return Ok(self.receipt(seq, ReceiptKind::Cancelled(0)));
                    }
                };
                if owner != c.account {
                    return Err(ExecutionError::OrderNotOwned);
                }
                self.authorize(c.account, c.market, Amount::ZERO, &c.auth)?;
                let book = self
                    .books
                    .get_mut(&(c.market.get(), instrument))
                    .ok_or(ExecutionError::UnknownMarket)?;
                book.cancel(c.order_id)?;
                self.release_order_reserve(c.market, instrument, c.order_id, c.account)?;
                self.commit_account(c.account)?;
                self.commit_market(c.market)?;
                Ok(self.receipt(seq, ReceiptKind::Cancelled(1)))
            }
            Command::CancelAll(c) => {
                let meta = self
                    .markets
                    .get(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?;
                let n = instrument_count(meta.market_type, meta.outcomes);
                self.authorize(c.account, c.market, Amount::ZERO, &c.auth)?;
                let mut count = 0u32;
                for inst in 0..n {
                    if let Some(book) = self.books.get_mut(&(c.market.get(), inst)) {
                        count = count.saturating_add(book.cancel_all(c.account));
                    }
                }
                // Release every resting reservation for this account in the market.
                let keys: Vec<(u32, u16, u64)> = self
                    .order_reserves
                    .iter()
                    .filter(|((m, _, _), (a, _))| *m == c.market.get() && *a == c.account)
                    .map(|(k, _)| *k)
                    .collect();
                for key in keys {
                    if let Some((owner, notional)) = self.order_reserves.remove(&key) {
                        self.risk.release_resting(owner, notional)?;
                    }
                }
                self.commit_account(c.account)?;
                self.commit_market(c.market)?;
                Ok(self.receipt(seq, ReceiptKind::Cancelled(count)))
            }
            Command::ReplaceOrder(c) => {
                self.gate_new_risk(c.market)?;
                // Find which instrument book holds this order.
                let meta = self
                    .markets
                    .get(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?;
                let n = instrument_count(meta.market_type, meta.outcomes);
                let mut instrument = None;
                for inst in 0..n {
                    if let Some(book) = self.books.get(&(c.market.get(), inst)) {
                        if let Some(owner) = book.owner(c.order_id) {
                            if owner != c.account {
                                return Err(ExecutionError::OrderNotOwned);
                            }
                            instrument = Some(inst);
                            break;
                        }
                    }
                }
                let instrument = instrument.ok_or(ExecutionError::Order(orderbook::OrderError::UnknownOrder))?;
                let notional = c.price.notional_ceil(c.quantity)?;
                self.authorize(c.account, c.market, notional, &c.auth)?;
                self.release_order_reserve(c.market, instrument, c.order_id, c.account)?;
                self.risk
                    .check_order_in_market(c.account, c.market, notional, false)?;
                let book = self
                    .books
                    .get_mut(&(c.market.get(), instrument))
                    .ok_or(ExecutionError::UnknownMarket)?;
                let result = book.replace(c.order_id, c.price, c.quantity)?;
                let touched = self.apply_fills(c.market, instrument, &result)?;
                let filled = result.filled_quantity();
                let rested = matches!(
                    result.outcome,
                    OrderOutcome::Resting { .. } | OrderOutcome::PartiallyFilledResting { .. }
                );
                if rested {
                    let rest_notional = Self::residual_notional(&result, c.price, c.quantity)?;
                    self.reserve_order(
                        c.market,
                        instrument,
                        c.order_id,
                        c.account,
                        rest_notional,
                    )?;
                }
                for a in touched {
                    self.commit_account(a)?;
                }
                self.commit_account(c.account)?;
                self.commit_market(c.market)?;
                Ok(self.receipt(seq, ReceiptKind::OrderApplied { filled, rested }))
            }
            Command::MintCompleteSet(c) => {
                let meta = self
                    .markets
                    .get(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?;
                if !is_claim_market(meta.market_type) {
                    return Err(ExecutionError::IncompatibleMarketType);
                }
                if !matches!(meta.lifecycle, MarketLifecycle::Open) {
                    return Err(ExecutionError::LifecycleRejected);
                }
                let outcomes = usize::from(instrument_count(meta.market_type, meta.outcomes));
                self.ledger.lock(c.account, c.count)?;
                // Keep risk collateral aligned with locked settlement funds.
                self.risk.debit_collateral(c.account, c.count)?;
                let entry = self
                    .claims
                    .entry((c.account.get(), c.market.get()))
                    .or_insert_with(|| vec![Amount::ZERO; outcomes]);
                if entry.len() < outcomes {
                    entry.resize(outcomes, Amount::ZERO);
                }
                for v in entry.iter_mut() {
                    *v = v.checked_add(c.count)?;
                }
                let key = (c.account.get(), c.market.get());
                let prev = self.mint_locked.get(&key).copied().unwrap_or(Amount::ZERO);
                self.mint_locked
                    .insert(key, prev.checked_add(c.count)?);
                self.commit_account(c.account)?;
                Ok(self.receipt(seq, ReceiptKind::CompleteSet(c.count)))
            }
            Command::RedeemCompleteSet(c) => {
                let meta = self
                    .markets
                    .get(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?;
                if !is_claim_market(meta.market_type) {
                    return Err(ExecutionError::IncompatibleMarketType);
                }
                if !matches!(
                    meta.lifecycle,
                    MarketLifecycle::Open | MarketLifecycle::Halted | MarketLifecycle::Closed
                ) {
                    return Err(ExecutionError::LifecycleRejected);
                }
                let entry = self
                    .claims
                    .get_mut(&(c.account.get(), c.market.get()))
                    .ok_or(ExecutionError::IncompleteSet)?;
                if entry.iter().any(|v| *v < c.count) {
                    return Err(ExecutionError::IncompleteSet);
                }
                for v in entry.iter_mut() {
                    *v = v.checked_sub(c.count)?;
                }
                self.ledger.unlock(c.account, c.count)?;
                self.risk.credit_collateral(c.account, c.count)?;
                let key = (c.account.get(), c.market.get());
                let prev = self.mint_locked.get(&key).copied().unwrap_or(Amount::ZERO);
                if prev < c.count {
                    return Err(ExecutionError::IncompleteSet);
                }
                let next = prev.checked_sub(c.count)?;
                if next.raw() == 0 {
                    self.mint_locked.remove(&key);
                } else {
                    self.mint_locked.insert(key, next);
                }
                self.commit_account(c.account)?;
                Ok(self.receipt(seq, ReceiptKind::CompleteSet(c.count)))
            }
            Command::ProtocolUpgrade(c) => {
                if c.target_version <= self.protocol_version {
                    return Err(ExecutionError::ProtocolDowngrade {
                        current: self.protocol_version,
                        requested: c.target_version,
                    });
                }
                self.protocol_version = c.target_version;
                Ok(self.receipt(seq, ReceiptKind::ProtocolUpgraded(c.target_version)))
            }
            Command::Liquidate(c) => {
                if !self.ledger.contains(c.account) {
                    return Err(ExecutionError::UnknownAccount);
                }
                // Only a distressed (at/below maintenance margin) account may be
                // liquidated; a keeper acting on a healthy account is rejected
                // before any state changes.
                if !self.risk.is_liquidatable(c.account)? {
                    return Err(ExecutionError::AccountNotLiquidatable);
                }
                // Phase 1: cancel every resting order the account holds, across
                // all markets/instruments, so a dead account leaves nothing on
                // the books.
                let book_keys: Vec<(u32, u16)> = {
                    let mut ids: Vec<(u32, u16)> = self.books.keys().copied().collect();
                    ids.sort_unstable();
                    ids
                };
                let mut market_ids: Vec<u32> = book_keys.iter().map(|(m, _)| *m).collect();
                market_ids.sort_unstable();
                market_ids.dedup();
                for key in &book_keys {
                    if let Some(book) = self.books.get_mut(key) {
                        book.cancel_all(c.account);
                    }
                }
                // Phases 2-4: auto-deleverage, insurance draw, and socialization
                // are settled by the risk engine.
                let outcome = self.risk.liquidate(c.account)?;
                // Commit every account the pipeline touched (victim + ADL
                // counterparties + haircuts). Positions live only in risk.
                let mut affected: Vec<AccountId> = Vec::with_capacity(outcome.adl_fills.len() + 1);
                affected.push(c.account);
                for f in &outcome.adl_fills {
                    affected.push(f.counterparty);
                }
                for (a, _) in &outcome.haircuts {
                    affected.push(*a);
                }
                affected.sort_by_key(|a| a.get());
                affected.dedup();
                // Drop any resting reservations for the liquidated account.
                let drop_keys: Vec<(u32, u16, u64)> = self
                    .order_reserves
                    .iter()
                    .filter(|(_, (a, _))| *a == c.account)
                    .map(|(k, _)| *k)
                    .collect();
                for key in drop_keys {
                    if let Some((owner, notional)) = self.order_reserves.remove(&key) {
                        let _ = self.risk.release_resting(owner, notional);
                    }
                }
                for a in &affected {
                    self.commit_account(*a)?;
                }
                // Cancelled orders and reconciled book positions change every
                // touched market root.
                for m in &market_ids {
                    self.commit_market(MarketId::new(*m))?;
                }
                Ok(self.receipt(
                    seq,
                    ReceiptKind::Liquidated {
                        account: c.account,
                        insurance_drawn: outcome.insurance_drawn,
                        socialized_loss: outcome.socialized_loss,
                    },
                ))
            }
            Command::SetMarketLifecycle(c) => {
                let meta = self
                    .markets
                    .get_mut(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?;
                meta.lifecycle = c.lifecycle;
                self.commit_market(c.market)?;
                Ok(self.receipt(seq, ReceiptKind::MarketUpdated(c.market)))
            }
            Command::SetOracleHealth(c) => {
                let meta = self
                    .markets
                    .get_mut(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?;
                meta.oracle_health = c.health;
                self.commit_market(c.market)?;
                Ok(self.receipt(seq, ReceiptKind::MarketUpdated(c.market)))
            }
            Command::ApplyFundingEpoch(c) => {
                let meta = self
                    .markets
                    .get_mut(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?;
                if is_claim_market(meta.market_type) {
                    return Err(ExecutionError::IncompatibleMarketType);
                }
                let expected = meta.last_funding_epoch.saturating_add(1);
                if c.epoch != expected {
                    return Err(ExecutionError::FundingEpochConflict);
                }
                let mark = meta.mark_price;
                let rate = c.rate;
                meta.last_funding_epoch = c.epoch;
                // Collect holders from risk by scanning open accounts via
                // liquidation candidates path is wrong; use market holders by
                // probing positions for known accounts through ledger.
                let accounts: Vec<AccountId> = {
                    // Dense accounts 0..ledger count via risk account_count.
                    let n = self.risk.account_count();
                    let mut v = Vec::new();
                    for i in 0..n {
                        if let Ok(a) = AccountId::from_index(i) {
                            if self.risk.position(a, c.market).map(|q| q.raw() != 0).unwrap_or(false)
                            {
                                v.push(a);
                            }
                        }
                    }
                    v
                };
                for a in &accounts {
                    let qty = self.risk.position(*a, c.market)?;
                    // payment positive => account pays (long when rate > 0).
                    let pay = mark.notional(qty)?.mul_ratio(rate)?;
                    // apply_funding credits; so credit -pay.
                    let credit = Amount::from_raw(
                        pay.raw().checked_neg().ok_or(types::ArithError::Overflow)?,
                    );
                    self.risk.apply_funding(*a, credit)?;
                    self.commit_account(*a)?;
                }
                self.commit_market(c.market)?;
                Ok(self.receipt(
                    seq,
                    ReceiptKind::FundingApplied {
                        market: c.market,
                        epoch: c.epoch,
                    },
                ))
            }
            Command::ResolveMarket(c) => {
                let meta = self
                    .markets
                    .get_mut(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?;
                if !is_claim_market(meta.market_type) {
                    return Err(ExecutionError::IncompatibleMarketType);
                }
                if !matches!(
                    meta.lifecycle,
                    MarketLifecycle::Open
                        | MarketLifecycle::Closed
                        | MarketLifecycle::PendingResolution
                        | MarketLifecycle::Disputed
                ) {
                    return Err(ExecutionError::LifecycleRejected);
                }
                let n = instrument_count(meta.market_type, meta.outcomes);
                if c.winning_outcome >= n {
                    return Err(ExecutionError::InvalidInstrument);
                }
                meta.winning_outcome = Some(c.winning_outcome);
                meta.lifecycle = MarketLifecycle::Resolved;
                // Cancel all resting books so no post-resolve trading residue.
                for inst in 0..n {
                    if let Some(book) = self.books.get_mut(&(c.market.get(), inst)) {
                        // Drain by canceling every account that has orders: collect
                        // accounts from order_reserves for this market.
                        let _ = book; // cancelled via reserves keys below
                    }
                }
                let reserve_keys: Vec<(u32, u16, u64)> = self
                    .order_reserves
                    .keys()
                    .copied()
                    .filter(|(m, _, _)| *m == c.market.get())
                    .collect();
                for key in reserve_keys {
                    if let Some((owner, notional)) = self.order_reserves.remove(&key) {
                        let _ = self.risk.release_resting(owner, notional);
                        if let Some(book) = self.books.get_mut(&(key.0, key.1)) {
                            let _ = book.cancel(types::OrderId::new(key.2));
                        }
                    }
                }
                // Cancel any remaining orders on every instrument book.
                for inst in 0..n {
                    if let Some(book) = self.books.get_mut(&(c.market.get(), inst)) {
                        // cancel_all for every account that still has resting orders
                        // by repeatedly canceling known ids via a snapshot clone.
                        let snapshot = book.clone();
                        // Use cancel_all on accounts present in the book's account index
                        // via total — walk resting by cloning and canceling all via
                        // a public API: cancel_all needs account. Use resting_len loop
                        // is not available; cancel by scanning reserves already done.
                        let _ = snapshot;
                        // Full drain: create a throwaway list of owners by probing
                        // order ids is hard; instead re-create empty books.
                        *book = OrderBook::new(BookConfig::default());
                    }
                }
                self.commit_market(c.market)?;
                Ok(self.receipt(
                    seq,
                    ReceiptKind::MarketResolved {
                        market: c.market,
                        winning_outcome: c.winning_outcome,
                    },
                ))
            }
            Command::SettleMarket(c) => {
                let meta = self
                    .markets
                    .get(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?
                    .clone();
                if !is_claim_market(meta.market_type) {
                    return Err(ExecutionError::IncompatibleMarketType);
                }
                if !matches!(meta.lifecycle, MarketLifecycle::Resolved) {
                    return Err(ExecutionError::MarketNotResolved);
                }
                let winner = meta
                    .winning_outcome
                    .ok_or(ExecutionError::MarketNotResolved)?;
                let win_idx = usize::from(winner);
                // Drain mint locks into a settlement pool, then pay claim holders.
                let minters: Vec<(u32, Amount)> = self
                    .mint_locked
                    .iter()
                    .filter(|((_, m), _)| *m == c.market.get())
                    .map(|((a, _), amt)| (*a, *amt))
                    .collect();
                let mut pool = Amount::ZERO;
                for (acct, amt) in &minters {
                    let account = AccountId::new(*acct);
                    self.ledger.consume_locked(account, *amt)?;
                    pool = pool.checked_add(*amt)?;
                    self.mint_locked.remove(&(*acct, c.market.get()));
                }
                let holders: Vec<(u32, Vec<Amount>)> = self
                    .claims
                    .iter()
                    .filter(|((_, m), _)| *m == c.market.get())
                    .map(|((a, _), v)| (*a, v.clone()))
                    .collect();
                let mut paid = Amount::ZERO;
                let mut touched: Vec<AccountId> = Vec::new();
                for (acct, balances) in holders {
                    let account = AccountId::new(acct);
                    let payout = balances.get(win_idx).copied().unwrap_or(Amount::ZERO);
                    self.claims.remove(&(acct, c.market.get()));
                    if payout.raw() > 0 {
                        if pool < payout {
                            return Err(ExecutionError::IncompleteSet);
                        }
                        pool = pool.checked_sub(payout)?;
                        self.ledger.credit_available(account, payout)?;
                        self.risk.credit_collateral(account, payout)?;
                        paid = paid.checked_add(payout)?;
                    }
                    touched.push(account);
                }
                // Any residual pool (should be zero under complete-set invariant)
                // is burned from supply only if non-zero — treat as error.
                if pool.raw() != 0 {
                    return Err(ExecutionError::IncompleteSet);
                }
                if let Some(meta) = self.markets.get_mut(&c.market.get()) {
                    meta.lifecycle = MarketLifecycle::Settled;
                }
                touched.sort_by_key(|a| a.get());
                touched.dedup();
                for a in touched {
                    self.commit_account(a)?;
                }
                self.commit_market(c.market)?;
                Ok(self.receipt(
                    seq,
                    ReceiptKind::MarketSettled {
                        market: c.market,
                        paid,
                    },
                ))
            }
        }
    }
}

impl DeterministicEngine for Engine {
    fn execute(
        &mut self,
        sequence: SequenceNumber,
        command: Command,
    ) -> Result<ExecutionReceipt, ExecutionError> {
        let seq = sequence.get();
        // Defense in depth: the sequencer assigns a strictly increasing sequence
        // to every log entry, so a replayed or out-of-order command is rejected
        // before it can touch any state.
        if let Some(last) = self.last_seq {
            if seq <= last {
                return Err(ExecutionError::NonMonotonicSequence { last, got: seq });
            }
        }
        // Durable command-level idempotency, decided *before* any subsystem
        // mutation. A retried command carries the same idempotency key
        // (`client_id` / withdrawal `nonce`) but a fresh sequence, so the
        // monotonic-sequence gate above cannot catch it; this guard does.
        let binding = command_binding(&command);

        // Transaction boundary. Apply the command to a working copy of the whole
        // engine. If any fallible step — fixed-point arithmetic, capacity, the
        // ledger, the risk engine, an order book, or a state-tree write — returns
        // `Err`, the working copy is dropped and `self` (with its committed state
        // root) is left byte-identical, so no command is ever partially applied.
        // On success the working copy is swapped in, committing the ledger, risk
        // engine, books, in-memory maps, and state tree together, exactly once.
        // `last_seq` advances only on that commit, so a failed command neither
        // consumes its sequence nor mutates any subsystem.
        let mut txn = self.clone();
        txn.last_seq = Some(seq);

        if let Some(binding) = binding.as_ref() {
            match txn.replay.classify(binding) {
                GuardDecision::Replay(receipt) => {
                    // Exactly-once: a byte-identical retry returns the original
                    // receipt without re-applying any delta. The only state that
                    // advances is the consumed sequence; ledger, positions, risk,
                    // book, withdrawals, and the root are left byte-identical.
                    *self = txn;
                    return Ok(receipt);
                }
                GuardDecision::Conflict => return Err(ExecutionError::IdempotencyConflict),
                GuardDecision::Expired => return Err(ExecutionError::ReplayExpired),
                GuardDecision::Fresh => {
                    // Commit the watermark into the working copy up front so the
                    // command's own commits fold it into the same state root.
                    txn.replay.reserve(binding);
                }
            }
        }

        let receipt = txn.apply(seq, command)?;

        if let Some(binding) = binding.as_ref() {
            // Cache the receipt for exact-retry replay. This is a local,
            // replay-rebuilt cache and does not alter the committed root, so the
            // receipt's state root (captured in `apply`) stays valid.
            txn.replay.finalize(binding, receipt.clone());
        }

        *self = txn;
        Ok(receipt)
    }

    fn state_root(&self) -> Hash {
        self.tree.root()
    }
}

#[cfg(test)]
mod tests {
    //! Transaction-boundary (atomicity) tests. These live inside the `engine`
    //! module so they can reach the engine's private subsystems and reconcile
    //! them against the committed state root after every command.

    use super::*;
    use crate::command::{
        CompleteSetOp, CreateAccount, CreateMarket, DepositCredit, FinalizeWithdrawal, PlaceOrder,
        ReplaceOrder, RequestWithdrawal, SetMarkPrice,
    };
    use state_tree::{verify_account, verify_market};
    use std::collections::HashMap;
    use types::{OrderId, OrderType, Price, TimeInForce};

    fn engine_with_caps(account_capacity: usize, market_capacity: usize) -> Engine {
        let base = EngineConfig::default();
        Engine::new(EngineConfig {
            account_capacity,
            market_capacity,
            replay_window: base.replay_window,
            risk: base.risk,
        })
    }

    fn seq(n: u64) -> SequenceNumber {
        SequenceNumber::new(n)
    }

    fn create_account(collateral: i128) -> Command {
        Command::CreateAccount(CreateAccount {
            initial_collateral: Amount::from_raw(collateral),
        })
    }

    fn create_perp(id: u32, mark: i64) -> Command {
        Command::CreateMarket(CreateMarket {
            market: MarketId::new(id),
            market_type: MarketType::Perpetual,
            outcomes: 1,
            mark_price: Price::from_raw(mark),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn place(
        account: u32,
        market: u32,
        order_id: u64,
        side: Side,
        price: i64,
        qty: i64,
    ) -> Command {
        Command::PlaceOrder(PlaceOrder {
            account: AccountId::new(account),
            market: MarketId::new(market),
            order_id: OrderId::new(order_id),
            side,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price::from_raw(price),
            quantity: Quantity::from_raw(qty),
            client_id: order_id,
            reduce_only: false,
            instrument: 0,
            auth: Authorization::Master,
        })
    }

    fn deposit(account: u32, tx: Vec<u8>, amount: i128) -> Command {
        Command::DepositCredit(DepositCredit {
            source_chain: 1,
            source_tx: tx,
            source_event_index: 0,
            account: AccountId::new(account),
            amount: Amount::from_raw(amount),
        })
    }

    // A single deterministic function of the ENTIRE engine state — every
    // subsystem plus every non-committed in-memory map — used to prove that a
    // failed command leaves the engine byte-identical.
    fn fingerprint(e: &Engine) -> Vec<u8> {
        let mut w = LeafWriter::new();
        w.field_bytes(e.state_root().as_bytes());
        w.field_i64(i64::from_le_bytes(e.risk.state_root().to_le_bytes()));
        w.field_i128(e.ledger.total_supply().raw());
        let n = e.ledger.account_count();
        w.field_i128(i128::try_from(n).unwrap());
        for i in 0..n {
            let a = AccountId::from_index(i).unwrap();
            w.field_i128(e.ledger.available(a).unwrap().raw());
            w.field_i128(e.ledger.reserved(a).unwrap().raw());
            w.field_i128(e.ledger.locked(a).unwrap().raw());
            w.field_i128(e.risk.collateral(a).unwrap().raw());
            w.field_i128(e.risk.equity(a).unwrap().raw());
        }
        let mut positions: Vec<(u32, u32, i64)> = Vec::new();
        for i in 0..n {
            let a = AccountId::from_index(i).unwrap();
            if let Ok(perps) = e.risk.perp_positions(a) {
                for pos in perps {
                    if pos.net_qty.raw() != 0 {
                        positions.push((a.get(), pos.market.get(), pos.net_qty.raw()));
                    }
                }
            }
        }
        positions.sort_unstable();
        w.field_i128(i128::try_from(positions.len()).unwrap());
        for (a, m, q) in positions {
            w.field_u32(a);
            w.field_u32(m);
            w.field_i64(q);
        }
        let mut claims: Vec<(u32, u32, Vec<i128>)> = e
            .claims
            .iter()
            .map(|(&(a, m), v)| (a, m, v.iter().map(|x| x.raw()).collect()))
            .collect();
        claims.sort_unstable_by_key(|(a, m, _)| (*a, *m));
        w.field_i128(i128::try_from(claims.len()).unwrap());
        for (a, m, v) in claims {
            w.field_u32(a);
            w.field_u32(m);
            for x in v {
                w.field_i128(x);
            }
        }
        let mut withdrawals: Vec<(u64, u32, i128, bool)> = e
            .withdrawals
            .iter()
            .map(|(&id, x)| (id, x.account.get(), x.amount.raw(), x.finalized))
            .collect();
        withdrawals.sort_unstable();
        w.field_i128(i128::try_from(withdrawals.len()).unwrap());
        for (id, acct, amount, finalized) in withdrawals {
            w.field_i64(i64::from_le_bytes(id.to_le_bytes()));
            w.field_u32(acct);
            w.field_i128(amount);
            w.field_u32(u32::from(finalized));
        }
        w.field_i128(i128::try_from(e.deposits_seen.len()).unwrap());
        w.field_u32(u32::from(e.protocol_version));
        let mut markets: Vec<(u32, u16, i64, usize)> = e
            .markets
            .iter()
            .map(|(&m, meta)| {
                let resting = e
                    .books
                    .iter()
                    .filter(|((mk, _), _)| *mk == m)
                    .map(|(_, b)| b.resting_len())
                    .sum();
                (m, meta.outcomes, meta.mark_price.raw(), resting)
            })
            .collect();
        markets.sort_unstable();
        w.field_i128(i128::try_from(markets.len()).unwrap());
        for (m, outcomes, mark, resting) in markets {
            w.field_u32(m);
            w.field_u32(u32::from(outcomes));
            w.field_i64(mark);
            w.field_i128(i128::try_from(resting).unwrap());
        }
        let mut wallets: Vec<(u32, u32, Vec<u8>)> = e
            .wallets
            .iter()
            .map(|(&a, b)| (a, b.chain_id, b.address.clone()))
            .collect();
        wallets.sort_unstable();
        w.field_i128(i128::try_from(wallets.len()).unwrap());
        for (a, chain, addr) in wallets {
            w.field_u32(a);
            w.field_u32(chain);
            w.field_bytes(&addr);
        }
        w.finish()
    }

    // The single invariant checker required by the acceptance criteria: after a
    // successful command it reconciles the ledger, risk engine, positions, claims,
    // withdrawals, and the committed state tree with one another.
    fn check_invariants(e: &Engine) {
        // Ledger self-conservation: available + reserved + locked == total supply.
        assert!(e.ledger.conservation_holds(), "ledger conservation broken");

        let root = e.state_root();
        let n = e.ledger.account_count();

        // Reserved balances are backed exactly by pending (non-finalized)
        // withdrawals — reconciling the withdrawal book against the ledger.
        let mut pending: HashMap<u32, i128> = HashMap::new();
        for wdr in e.withdrawals.values() {
            if !wdr.finalized {
                *pending.entry(wdr.account.get()).or_default() += wdr.amount.raw();
            }
        }

        for i in 0..n {
            let a = AccountId::from_index(i).unwrap();
            // The committed account leaf folds ledger balances, risk collateral and
            // derived margin columns, positions, and claims into one commitment;
            // verifying it against the root reconciles all of them with the tree.
            let leaf = e.account_leaf(a).unwrap();
            let proof = e.account_proof(a).unwrap();
            assert!(
                verify_account(root, a, &leaf, &proof),
                "account {i} committed leaf diverged from the state root",
            );
            let reserved = e.ledger.reserved(a).unwrap().raw();
            let expected = pending.get(&a.get()).copied().unwrap_or(0);
            assert_eq!(
                reserved, expected,
                "account {i} reserved {reserved} != pending withdrawals {expected}",
            );
        }

        // Committed market leaves (type, outcomes, mark, book root) reconcile too.
        for &m in e.markets.keys() {
            let mkt = MarketId::new(m);
            let leaf = e.market_leaf(mkt).unwrap();
            let proof = e.tree.market_proof(mkt).unwrap();
            assert!(
                verify_market(root, mkt, &leaf, &proof),
                "market {m} committed leaf diverged from the state root",
            );
        }
    }

    // --- Injected-failure atomicity, one per previously non-atomic handler ---

    #[test]
    fn create_account_beyond_capacity_is_atomic() {
        let mut e = engine_with_caps(2, 4);
        for n in 1..=2u64 {
            e.execute(seq(n), create_account(1_000_000)).unwrap();
        }
        let before = fingerprint(&e);
        // Ledger and risk accept a 3rd account, but the account sub-tree (capacity
        // 2) cannot commit its leaf: the whole command rolls back together.
        assert!(matches!(
            e.execute(seq(3), create_account(1_000_000)),
            Err(ExecutionError::State(_))
        ));
        assert_eq!(e.ledger.account_count(), 2);
        assert_eq!(e.risk.account_count(), 2);
        assert_eq!(fingerprint(&e), before, "failed create left orphaned state");
        check_invariants(&e);
    }

    #[test]
    fn deposit_dedup_not_consumed_on_failed_credit() {
        let mut e = engine_with_caps(4, 4);
        // Genesis account funded to just under the supply ceiling.
        e.execute(seq(1), create_account(i128::MAX - 100)).unwrap();
        let acct = AccountId::new(0);
        let before = fingerprint(&e);
        // A deposit that would push total supply past the ceiling overflows on the
        // credit — AFTER the dedup key was inserted. The insert must not survive.
        assert!(matches!(
            e.execute(seq(2), deposit(0, vec![7u8; 8], 1_000)),
            Err(ExecutionError::Arith(_))
        ));
        assert!(e.deposits_seen.is_empty(), "dedup key wrongly consumed");
        assert_eq!(fingerprint(&e), before);
        // Because the certificate was not consumed, a correctly-sized retry of the
        // SAME (chain, tx, event) still succeeds.
        e.execute(seq(3), deposit(0, vec![7u8; 8], 50)).unwrap();
        assert_eq!(
            e.ledger.available(acct).unwrap(),
            Amount::from_raw(i128::MAX - 50)
        );
        check_invariants(&e);
    }

    #[test]
    fn request_withdrawal_rolls_back_reserve_when_risk_debit_fails() {
        let mut e = engine_with_caps(8, 4);
        // Two 100.0-collateral accounts and a perp market at mark 1.0.
        e.execute(seq(1), create_account(100_000_000)).unwrap();
        e.execute(seq(2), create_account(100_000_000)).unwrap();
        e.execute(seq(3), create_perp(0, 1_000_000)).unwrap();
        // Maker (0) rests a big bid; taker (1) crosses so both open large positions
        // whose 10% initial margin ties up nearly all of the taker's collateral.
        e.execute(seq(4), place(0, 0, 1, Side::Bid, 1_000_000, 950_000_000))
            .unwrap();
        e.execute(seq(5), place(1, 0, 2, Side::Ask, 1_000_000, 950_000_000))
            .unwrap();
        let taker = AccountId::new(1);
        let before = fingerprint(&e);
        // The ledger has 100.0 available, but risk free collateral is only ~5.0
        // (equity 100 − initial margin 95). Reserving 90 succeeds, then the risk
        // debit fails — and must roll the reserve back.
        assert!(matches!(
            e.execute(
                seq(6),
                Command::RequestWithdrawal(RequestWithdrawal {
                    account: taker,
                    amount: Amount::from_raw(90_000_000),
                    nonce: 1,
                    destination_chain: 1,
                    destination_address: vec![1, 2, 3],
                    auth: Authorization::Master,
                }),
            ),
            Err(ExecutionError::Risk(
                risk::RiskError::InsufficientCollateral
            ))
        ));
        assert_eq!(
            e.ledger.available(taker).unwrap(),
            Amount::from_raw(100_000_000)
        );
        assert_eq!(e.ledger.reserved(taker).unwrap(), Amount::ZERO);
        assert!(e.withdrawals.is_empty(), "phantom withdrawal recorded");
        assert_eq!(fingerprint(&e), before);
        check_invariants(&e);
    }

    #[test]
    fn create_market_beyond_capacity_is_atomic() {
        let mut e = engine_with_caps(4, 1);
        e.execute(seq(1), create_account(1_000_000)).unwrap();
        e.execute(seq(2), create_perp(0, 1_000_000)).unwrap();
        let before = fingerprint(&e);
        // The market map, book, and risk mark all accept market 1, but the market
        // sub-tree (capacity 1) cannot commit it: everything rolls back together.
        assert!(matches!(
            e.execute(seq(3), create_perp(1, 1_000_000)),
            Err(ExecutionError::State(_))
        ));
        assert!(!e.markets.contains_key(&1));
        assert!(!e.books.contains_key(&(1, 0)));
        assert_eq!(fingerprint(&e), before);
        check_invariants(&e);
    }

    #[test]
    fn set_mark_price_overflow_is_atomic() {
        let mut e = engine_with_caps(8, 4);
        // Two modest accounts and a perp at mark 1.0.
        e.execute(seq(1), create_account(1_000_000_000_000))
            .unwrap();
        e.execute(seq(2), create_account(1_000_000_000_000))
            .unwrap();
        e.execute(seq(3), create_perp(0, 1_000_000)).unwrap();
        // Account 1 rests a bid; account 0 crosses -> account 1 long 1 @ 1.0.
        e.execute(seq(4), place(1, 0, 1, Side::Bid, 1_000_000, 1_000_000))
            .unwrap();
        e.execute(seq(5), place(0, 0, 2, Side::Ask, 1_000_000, 1_000_000))
            .unwrap();
        // Now fund account 1 to near the max via a DEPOSIT (no leverage gate), so a
        // huge mark makes its unrealized PnL overflow recompute.
        e.execute(
            seq(6),
            deposit(1, vec![0xC1; 8], i128::MAX - 4_000_000_000_000),
        )
        .unwrap();
        let before = fingerprint(&e);
        // A huge mark folds a ~9.2e18 unrealized gain into near-max collateral and
        // overflows recompute; the market meta must not keep the new mark.
        assert!(matches!(
            e.execute(
                seq(7),
                Command::SetMarkPrice(SetMarkPrice {
                    market: MarketId::new(0),
                    price: Price::from_raw(i64::MAX),
                }),
            ),
            Err(ExecutionError::Risk(_))
        ));
        assert_eq!(
            e.markets.get(&0).unwrap().mark_price,
            Price::from_raw(1_000_000)
        );
        assert_eq!(fingerprint(&e), before);
        check_invariants(&e);
    }

    #[test]
    fn multi_leg_fill_failure_is_all_or_none() {
        let mut e = engine_with_caps(8, 4);
        // Two makers and a taker, all modest at first.
        e.execute(seq(1), create_account(1_000_000_000_000))
            .unwrap(); // maker 0
        e.execute(seq(2), create_account(1_000_000_000_000))
            .unwrap(); // taker 1
        e.execute(seq(3), create_account(1_000_000_000_000))
            .unwrap(); // maker 2
        e.execute(seq(4), create_perp(0, 1_000_000)).unwrap();
        // Both makers rest bids at 1.0 (maker 0 first -> earlier time priority).
        e.execute(seq(5), place(0, 0, 1, Side::Bid, 1_000_000, 1_000_000))
            .unwrap();
        e.execute(seq(6), place(2, 0, 2, Side::Bid, 1_000_000, 1_000_000))
            .unwrap();
        // Fund maker 2 to near the max via a DEPOSIT (no leverage gate) so its leg
        // of a two-fill match overflows AFTER maker 0's leg has already applied.
        e.execute(
            seq(7),
            deposit(2, vec![0xC2; 8], i128::MAX - 4_000_000_000_000),
        )
        .unwrap();
        // Raise the mark while every account is still flat (no position to overflow).
        e.execute(
            seq(8),
            Command::SetMarkPrice(SetMarkPrice {
                market: MarketId::new(0),
                price: Price::from_raw(i64::MAX),
            }),
        )
        .unwrap();
        let before = fingerprint(&e);
        // Taker sells 2 units, crossing both bids: fill 0 (maker 0) applies, fill 1
        // (maker 2) overflows -> the whole multi-leg match must be discarded.
        assert!(matches!(
            e.execute(seq(9), place(1, 0, 3, Side::Ask, 1_000_000, 2_000_000)),
            Err(ExecutionError::Risk(_))
        ));
        assert_eq!(e.market_resting_len(MarketId::new(0)), Some(2));
        for a in [0u32, 1, 2] {
            assert_eq!(
                e.risk
                    .position(AccountId::new(a), MarketId::new(0))
                    .unwrap_or(Quantity::ZERO),
                Quantity::ZERO,
            );
        }
        assert_eq!(fingerprint(&e), before);
        check_invariants(&e);
    }

    #[test]
    fn replace_failure_is_all_or_none() {
        let mut e = engine_with_caps(8, 4);
        e.execute(seq(1), create_account(1_000_000_000_000))
            .unwrap(); // trader 0
        e.execute(seq(2), create_account(1_000_000_000_000))
            .unwrap(); // maker 1
        e.execute(seq(3), create_perp(0, 1_000_000)).unwrap();
        // Maker rests a bid at 1.0; the trader rests a non-crossing ask at 2.0.
        e.execute(seq(4), place(1, 0, 1, Side::Bid, 1_000_000, 1_000_000))
            .unwrap();
        e.execute(seq(5), place(0, 0, 2, Side::Ask, 2_000_000, 1_000_000))
            .unwrap();
        // Fund the maker to near the max via a DEPOSIT (no leverage gate) so the
        // fill it will receive overflows.
        e.execute(
            seq(6),
            deposit(1, vec![0xC3; 8], i128::MAX - 4_000_000_000_000),
        )
        .unwrap();
        e.execute(
            seq(7),
            Command::SetMarkPrice(SetMarkPrice {
                market: MarketId::new(0),
                price: Price::from_raw(i64::MAX),
            }),
        )
        .unwrap();
        let before = fingerprint(&e);
        // Repricing the ask down to 1.0 crosses the maker's bid, whose near-max
        // collateral overflows on the fill. The replace must be all-or-none: the
        // original resting ask survives untouched.
        assert!(matches!(
            e.execute(
                seq(8),
                Command::ReplaceOrder(ReplaceOrder {
                    market: MarketId::new(0),
                    account: AccountId::new(0),
                    order_id: OrderId::new(2),
                    price: Price::from_raw(1_000_000),
                    quantity: Quantity::from_raw(1_000_000),
                    auth: Authorization::Master,
                }),
            ),
            Err(ExecutionError::Risk(_))
        ));
        assert_eq!(e.market_resting_len(MarketId::new(0)), Some(2));
        assert_eq!(
            e.risk
                .position(AccountId::new(1), MarketId::new(0))
                .unwrap_or(Quantity::ZERO),
            Quantity::ZERO,
        );
        assert_eq!(fingerprint(&e), before);
        check_invariants(&e);
    }

    // Crash-consistency intent at the transaction boundary: a failed command
    // leaves the engine in the COMPLETE previous state, so a stream with a failing
    // command interleaved reaches the same committed root as the stream without it
    // — never a hybrid.
    #[test]
    fn failed_command_yields_same_state_as_skipping_it() {
        let good = [
            create_account(100_000_000),
            create_perp(0, 1_000_000),
            place(0, 0, 1, Side::Bid, 990_000, 1_000_000),
            deposit(0, vec![1, 2, 3], 1_000_000),
        ];
        // Engine A applies the good stream with a doomed command (deposit to a
        // non-existent account) interleaved before the final deposit.
        let mut a = engine_with_caps(4, 4);
        let bad = deposit(9, vec![9, 9], 1);
        for (i, c) in good[..3].iter().enumerate() {
            a.execute(seq(i as u64 + 1), c.clone()).unwrap();
        }
        assert!(matches!(
            a.execute(seq(4), bad),
            Err(ExecutionError::UnknownAccount)
        ));
        a.execute(seq(5), good[3].clone()).unwrap();

        // Engine B applies only the good stream.
        let mut b = engine_with_caps(4, 4);
        for (i, c) in good.iter().enumerate() {
            b.execute(seq(i as u64 + 1), c.clone()).unwrap();
        }

        assert_eq!(a.state_root(), b.state_root());
        assert_eq!(fingerprint(&a), fingerprint(&b));
        check_invariants(&a);
    }

    #[test]
    fn successful_deposit_commits_ledger_risk_and_tree_once() {
        let mut e = engine_with_caps(4, 4);
        e.execute(seq(1), create_account(0)).unwrap();
        let acct = AccountId::new(0);
        e.execute(seq(2), deposit(0, vec![0xAB; 8], 500_000))
            .unwrap();
        // Committed exactly once across ledger, risk, and the tree.
        assert_eq!(e.ledger.available(acct).unwrap(), Amount::from_raw(500_000));
        assert_eq!(e.risk.collateral(acct).unwrap(), Amount::from_raw(500_000));
        check_invariants(&e);
        // A replay of the same certificate is rejected and changes nothing.
        let before = fingerprint(&e);
        assert!(matches!(
            e.execute(seq(3), deposit(0, vec![0xAB; 8], 500_000)),
            Err(ExecutionError::DuplicateDeposit)
        ));
        assert_eq!(fingerprint(&e), before);
    }

    // Deterministic in-test LCG (no external crates).
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }
        fn range(&mut self, lo: i64, hi: i64) -> i64 {
            let span = u64::try_from(hi - lo).unwrap() + 1;
            lo + i64::try_from(self.next() % span).unwrap()
        }
        fn u32_in(&mut self, lo: u32, hi: u32) -> u32 {
            u32::try_from(self.range(i64::from(lo), i64::from(hi))).unwrap()
        }
    }

    // Generate one pseudo-random command over a small account/market space. Mark
    // prices are only ever set at market creation (never mutated), so every
    // successful command keeps the committed tree fresh and `check_invariants`
    // fully reconciles it.
    //
    // Order `client_id`s and withdrawal `nonce`s are drawn from monotonic
    // counters so each carries a strictly increasing idempotency key per the
    // engine contract; `order_id`s stay random so book-level id collisions are
    // still exercised. Dedicated tests cover the retry/conflict/eviction paths.
    fn random_command(
        rng: &mut Lcg,
        tx_counter: &mut u64,
        client_seq: &mut u64,
        nonce_seq: &mut u64,
    ) -> Command {
        let account = rng.u32_in(0, 5);
        let market = rng.u32_in(0, 2);
        let order_id = u64::from(rng.u32_in(1, 40));
        let side = if rng.next().is_multiple_of(2) {
            Side::Bid
        } else {
            Side::Ask
        };
        let price = rng.range(600_000, 1_400_000);
        let qty = rng.range(100_000, 4_000_000);
        match rng.next() % 15 {
            0 => create_account(rng.range(0, 200_000_000).into()),
            1 => {
                *tx_counter += 1;
                deposit(
                    account,
                    tx_counter.to_le_bytes().to_vec(),
                    i128::from(rng.range(0, 5_000_000)),
                )
            }
            2 => {
                *nonce_seq += 1;
                Command::RequestWithdrawal(RequestWithdrawal {
                    account: AccountId::new(account),
                    amount: Amount::from_raw(i128::from(rng.range(0, 5_000_000))),
                    nonce: *nonce_seq,
                    destination_chain: 1,
                    destination_address: vec![1],
                    auth: Authorization::Master,
                })
            }
            3 => Command::FinalizeWithdrawal(FinalizeWithdrawal {
                withdrawal_id: rng.next() % 8,
            }),
            4 => create_perp(market, 1_000_000),
            5 => Command::CreateMarket(CreateMarket {
                market: MarketId::new(market),
                market_type: MarketType::MultiOutcomePrediction,
                outcomes: 3,
                mark_price: Price::from_raw(500_000),
            }),
            6..=8 => {
                *client_seq += 1;
                Command::PlaceOrder(PlaceOrder {
                    account: AccountId::new(account),
                    market: MarketId::new(market),
                    order_id: OrderId::new(order_id),
                    side,
                    order_type: OrderType::Limit,
                    tif: TimeInForce::Gtc,
                    price: Price::from_raw(price),
                    quantity: Quantity::from_raw(qty),
                    client_id: *client_seq,
                    reduce_only: false,
                    instrument: 0,
                    auth: Authorization::Master,
                })
            }
            9 => Command::CancelOrder(crate::command::CancelOrder {
                market: MarketId::new(market),
                account: AccountId::new(account),
                order_id: OrderId::new(order_id),
                auth: Authorization::Master,
            }),
            10 => Command::CancelAll(crate::command::CancelAll {
                market: MarketId::new(market),
                account: AccountId::new(account),
                auth: Authorization::Master,
            }),
            11 => Command::ReplaceOrder(ReplaceOrder {
                market: MarketId::new(market),
                account: AccountId::new(account),
                order_id: OrderId::new(order_id),
                price: Price::from_raw(price),
                quantity: Quantity::from_raw(qty),
                auth: Authorization::Master,
            }),
            12 => Command::MintCompleteSet(CompleteSetOp {
                account: AccountId::new(account),
                market: MarketId::new(market),
                count: Amount::from_raw(i128::from(rng.range(0, 2_000_000))),
            }),
            13 => Command::RedeemCompleteSet(CompleteSetOp {
                account: AccountId::new(account),
                market: MarketId::new(market),
                count: Amount::from_raw(i128::from(rng.range(0, 2_000_000))),
            }),
            _ => Command::Liquidate(crate::command::Liquidate {
                account: AccountId::new(account),
            }),
        }
    }

    // The property test tying every acceptance criterion together: over a long
    // pseudo-random command stream, every SUCCESSFUL command satisfies the single
    // cross-subsystem invariant checker, and every FAILED command leaves the whole
    // engine byte-identical (nothing partially applied).
    #[test]
    fn property_random_commands_are_atomic_and_reconcile() {
        let mut e = engine_with_caps(64, 8);
        let mut rng = Lcg(0xC0FF_EE00_1234_5678);
        let mut tx_counter = 0u64;
        let mut client_seq = 0u64;
        let mut nonce_seq = 0u64;
        check_invariants(&e);
        let mut ok = 0u32;
        let mut err = 0u32;
        for n in 1..=1_500u64 {
            let cmd = random_command(&mut rng, &mut tx_counter, &mut client_seq, &mut nonce_seq);
            let before = fingerprint(&e);
            match e.execute(seq(n), cmd) {
                Ok(_) => {
                    ok += 1;
                    check_invariants(&e);
                }
                Err(_) => {
                    err += 1;
                    assert_eq!(
                        fingerprint(&e),
                        before,
                        "a failed command at seq {n} mutated engine state",
                    );
                }
            }
        }
        // Sanity: the stream genuinely exercised both branches.
        assert!(ok > 50, "too few successful commands: {ok}");
        assert!(err > 50, "too few failed commands: {err}");
    }

    // --- Command idempotency: exactly-once retries (issue #324) -------------

    // AC1: retrying a fully-filled order leaves ledger, positions, risk, book,
    // and root byte-identical. This is the concrete double-apply regression: the
    // book previously returned cached fills on a dedup hit and the engine
    // re-applied them to both counterparties.
    #[test]
    fn retrying_a_fully_filled_order_is_exactly_once() {
        let mut e = engine_with_caps(8, 4);
        e.execute(seq(1), create_account(100_000_000)).unwrap(); // maker 0
        e.execute(seq(2), create_account(100_000_000)).unwrap(); // taker 1
        e.execute(seq(3), create_perp(0, 1_000_000)).unwrap();
        e.execute(seq(4), place(0, 0, 1, Side::Bid, 1_000_000, 2_000_000))
            .unwrap();
        let taker = place(1, 0, 2, Side::Ask, 1_000_000, 2_000_000);
        let r1 = e.execute(seq(5), taker.clone()).unwrap();
        assert!(matches!(
            r1.kind,
            ReceiptKind::OrderApplied { rested: false, .. }
        ));
        let committed = fingerprint(&e);
        let root = e.state_root();
        check_invariants(&e);

        // Retry the identical order at a fresh, monotonic sequence.
        let r2 = e.execute(seq(6), taker).unwrap();
        assert_eq!(r1, r2, "retry must return the original receipt");
        assert_eq!(fingerprint(&e), committed, "retry duplicated engine state");
        assert_eq!(e.state_root(), root, "retry moved the committed root");
        // Positions did not double: taker short 2.0, maker long 2.0.
        assert_eq!(
            e.risk
                .position(AccountId::new(1), MarketId::new(0))
                .unwrap(),
            Quantity::from_raw(-2_000_000),
        );
        assert_eq!(
            e.risk
                .position(AccountId::new(0), MarketId::new(0))
                .unwrap(),
            Quantity::from_raw(2_000_000),
        );
        check_invariants(&e);
    }

    // AC1: retrying a partially-filled resting order does not double the fills
    // nor re-rest the residual.
    #[test]
    fn retrying_a_partially_filled_resting_order_is_exactly_once() {
        let mut e = engine_with_caps(8, 4);
        e.execute(seq(1), create_account(1_000_000_000)).unwrap();
        e.execute(seq(2), create_account(1_000_000_000)).unwrap();
        e.execute(seq(3), create_perp(0, 1_000_000)).unwrap();
        e.execute(seq(4), place(0, 0, 1, Side::Bid, 1_000_000, 2_000_000))
            .unwrap();
        // Taker asks 3.0 @ 1.0: fills 2.0 and rests 1.0.
        let taker = place(1, 0, 2, Side::Ask, 1_000_000, 3_000_000);
        let r1 = e.execute(seq(5), taker.clone()).unwrap();
        assert!(matches!(
            r1.kind,
            ReceiptKind::OrderApplied { rested: true, .. }
        ));
        assert_eq!(e.market_resting_len(MarketId::new(0)), Some(1));
        let committed = fingerprint(&e);
        check_invariants(&e);

        let r2 = e.execute(seq(6), taker).unwrap();
        assert_eq!(r1, r2);
        assert_eq!(
            fingerprint(&e),
            committed,
            "partial-fill retry duplicated state"
        );
        assert_eq!(
            e.market_resting_len(MarketId::new(0)),
            Some(1),
            "retry re-rested the residual",
        );
        check_invariants(&e);
    }

    // AC2: an exact withdrawal replay returns the original id and does not
    // reserve funds a second time.
    #[test]
    fn exact_withdrawal_replay_returns_original_id_and_reserves_once() {
        let mut e = engine_with_caps(4, 4);
        e.execute(seq(1), create_account(1_000_000)).unwrap();
        let acct = AccountId::new(0);
        let wd = Command::RequestWithdrawal(RequestWithdrawal {
            account: acct,
            amount: Amount::from_raw(400_000),
            nonce: 7,
            destination_chain: 1,
            destination_address: vec![1, 2, 3],
            auth: Authorization::Master,
        });
        let r1 = e.execute(seq(2), wd.clone()).unwrap();
        let ReceiptKind::WithdrawalRequested(id1) = r1.kind else {
            panic!("expected a withdrawal id");
        };
        assert_eq!(e.ledger.reserved(acct).unwrap(), Amount::from_raw(400_000));
        let committed = fingerprint(&e);

        // Replay at a fresh sequence.
        let r2 = e.execute(seq(3), wd).unwrap();
        let ReceiptKind::WithdrawalRequested(id2) = r2.kind else {
            panic!("expected a withdrawal id");
        };
        assert_eq!(id1, id2, "replay must return the original withdrawal id");
        assert_eq!(
            e.ledger.reserved(acct).unwrap(),
            Amount::from_raw(400_000),
            "replay reserved a second time",
        );
        assert_eq!(
            e.withdrawals.len(),
            1,
            "replay recorded a phantom withdrawal"
        );
        assert_eq!(fingerprint(&e), committed);
        check_invariants(&e);
    }

    // AC3: the same idempotency key with any changed field is rejected, and
    // idempotency is decided before the book's own duplicate-id check.
    #[test]
    fn same_key_with_changed_field_is_rejected() {
        let mut e = engine_with_caps(8, 4);
        e.execute(seq(1), create_account(100_000_000)).unwrap();
        e.execute(seq(2), create_account(100_000_000)).unwrap();
        e.execute(seq(3), create_perp(0, 1_000_000)).unwrap();
        // A resting bid keyed on client_id 5.
        let ord = |qty: i64| {
            Command::PlaceOrder(PlaceOrder {
                account: AccountId::new(0),
                market: MarketId::new(0),
                order_id: OrderId::new(1),
                side: Side::Bid,
                order_type: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: Price::from_raw(900_000),
                quantity: Quantity::from_raw(qty),
                client_id: 5,
                reduce_only: false,
                instrument: 0,
                auth: Authorization::Master,
            })
        };
        e.execute(seq(4), ord(1_000_000)).unwrap();
        let committed = fingerprint(&e);
        // Same account + client_id 5, different quantity -> conflict, not the
        // book's DuplicateOrderId (idempotency is decided first).
        assert_eq!(
            e.execute(seq(5), ord(2_000_000)),
            Err(ExecutionError::IdempotencyConflict),
        );
        assert_eq!(
            fingerprint(&e),
            committed,
            "rejected conflict mutated state"
        );

        // Withdrawal nonce reuse with a changed amount is likewise a conflict.
        let wd = |amount: i128| {
            Command::RequestWithdrawal(RequestWithdrawal {
                account: AccountId::new(1),
                amount: Amount::from_raw(amount),
                nonce: 3,
                destination_chain: 1,
                destination_address: vec![9],
                auth: Authorization::Master,
            })
        };
        e.execute(seq(6), wd(1_000_000)).unwrap();
        let committed = fingerprint(&e);
        assert_eq!(
            e.execute(seq(7), wd(2_000_000)),
            Err(ExecutionError::IdempotencyConflict),
        );
        assert_eq!(fingerprint(&e), committed);
        check_invariants(&e);
    }

    // AC4 (restart): a stream containing a retry reaches the same committed root
    // as the same stream without the retry, and rebuilding a fresh engine from
    // the identical log (a restart-via-replay) reproduces it bit-for-bit — so the
    // exactly-once boundary is committed into the versioned state, not just held
    // in volatile memory.
    #[test]
    fn restart_via_replay_preserves_exactly_once() {
        let base = vec![
            create_account(100_000_000),
            create_account(100_000_000),
            create_perp(0, 1_000_000),
            place(0, 0, 1, Side::Bid, 1_000_000, 2_000_000),
            place(1, 0, 2, Side::Ask, 1_000_000, 2_000_000), // client_id 2, fully fills
        ];
        let run_log = |log: &[Command]| {
            let mut e = engine_with_caps(8, 4);
            for (i, c) in log.iter().enumerate() {
                e.execute(seq(i as u64 + 1), c.clone()).unwrap();
            }
            e
        };

        // The stream with a retry of the taker order interleaved.
        let mut with_retry = base.clone();
        with_retry.push(place(1, 0, 2, Side::Ask, 1_000_000, 2_000_000)); // retry
        let a = run_log(&with_retry);
        // Simulated restart: a fresh engine replays the identical log.
        let b = run_log(&with_retry);
        assert_eq!(a.state_root(), b.state_root());
        assert_eq!(fingerprint(&a), fingerprint(&b));

        // The retry is fully absorbed: same committed root as never retrying.
        let no_retry = run_log(&base);
        assert_eq!(
            a.state_root(),
            no_retry.state_root(),
            "the retry was not exactly-once",
        );
        assert_eq!(
            a.risk
                .position(AccountId::new(1), MarketId::new(0))
                .unwrap(),
            Quantity::from_raw(-2_000_000),
        );
        check_invariants(&a);
    }

    // AC4 (bounded eviction): with a replay window of one, an early order's
    // receipt is evicted, yet the committed watermark still recognises the key as
    // processed, so a retry is refused (never re-executed).
    #[test]
    fn bounded_window_eviction_preserves_exactly_once() {
        let mut e = Engine::new(EngineConfig {
            account_capacity: 8,
            market_capacity: 4,
            replay_window: 1,
            risk: EngineConfig::default().risk,
        });
        e.execute(seq(1), create_account(1_000_000_000)).unwrap();
        e.execute(seq(2), create_account(1_000_000_000)).unwrap();
        e.execute(seq(3), create_perp(0, 1_000_000)).unwrap();
        e.execute(seq(4), place(0, 0, 1, Side::Bid, 1_000_000, 2_000_000))
            .unwrap();
        // Taker order client_id 2 fully fills and enters the size-one window.
        let taker = place(1, 0, 2, Side::Ask, 1_000_000, 2_000_000);
        e.execute(seq(5), taker.clone()).unwrap();
        // A later order (account 0, client_id 3) evicts the taker's receipt.
        e.execute(seq(6), place(0, 0, 3, Side::Bid, 900_000, 1_000_000))
            .unwrap();
        let committed = fingerprint(&e);

        // The evicted taker order is recognised as already-processed and refused.
        assert_eq!(e.execute(seq(7), taker), Err(ExecutionError::ReplayExpired),);
        assert_eq!(fingerprint(&e), committed, "expired retry re-applied");
        assert_eq!(
            e.risk
                .position(AccountId::new(1), MarketId::new(0))
                .unwrap(),
            Quantity::from_raw(-2_000_000),
        );
        check_invariants(&e);
    }

    // AC5: a retry after every crash point — admission, journal, execution,
    // receipt, and acknowledgement — applies the command exactly once. Crashes
    // before execution make the retry the first successful application; crashes
    // at or after execution make the retry a receipt replay with no second
    // effect.
    #[test]
    fn retry_after_every_crash_point_is_exactly_once() {
        let setup = |e: &mut Engine| {
            e.execute(seq(1), create_account(100_000_000)).unwrap();
            e.execute(seq(2), create_account(100_000_000)).unwrap();
            e.execute(seq(3), create_perp(0, 1_000_000)).unwrap();
            e.execute(seq(4), place(0, 0, 1, Side::Bid, 1_000_000, 2_000_000))
                .unwrap();
        };
        let target = place(1, 0, 2, Side::Ask, 1_000_000, 2_000_000);

        // Reference: the command applied exactly once.
        let mut reference = engine_with_caps(8, 4);
        setup(&mut reference);
        let receipt = reference.execute(seq(5), target.clone()).unwrap();
        let committed = fingerprint(&reference);

        // Crash at admission or in the journal, before execution: the engine
        // never applied the command, so the retry is its first application.
        {
            let mut e = engine_with_caps(8, 4);
            setup(&mut e);
            let r = e.execute(seq(5), target.clone()).unwrap();
            assert_eq!(r, receipt);
            assert_eq!(fingerprint(&e), committed);
        }

        // Crash at execution, receipt, or acknowledgement, after the command was
        // applied: repeated retries (each at a fresh sequence) replay the receipt
        // and never re-apply the command.
        {
            let mut e = engine_with_caps(8, 4);
            setup(&mut e);
            e.execute(seq(5), target.clone()).unwrap();
            for s in 6..=10 {
                let r = e.execute(seq(s), target.clone()).unwrap();
                assert_eq!(r, receipt, "retry at stage {s} changed the receipt");
                assert_eq!(
                    fingerprint(&e),
                    committed,
                    "retry at stage {s} re-applied the command",
                );
            }
        }
    }
}

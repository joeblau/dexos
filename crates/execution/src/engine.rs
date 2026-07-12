//! The single-writer deterministic execution engine.
//!
//! Integrates the stablecoin ledger, session keys, per-market order books, the
//! risk engine, and the incremental state tree. `execute` applies one sequenced
//! command and returns a receipt carrying the post-command state root. Identical
//! command streams produce identical state roots (deterministic replay).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use orderbook::{BookConfig, NewOrder, OrderBook, OrderOutcome};
use risk::{RiskConfig, RiskEngine};
use state_tree::{LeafWriter, StateTree};
use types::{
    AccountId, Amount, Hash, MarketId, MarketLifecycle, MarketType, OracleHealth, OrderType,
    Quantity, SequenceNumber, Side,
};

use crate::command::{Authorization, Command, DeterministicEngine, ExecutionReceipt, ReceiptKind};
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

/// Book-order coordinates: `(market, instrument, order_id)`.
type OrderKey = (u32, u16, u64);

/// Notional reserved for one resting perp order, plus the resting quantity it
/// was computed from.
///
/// Invariant: `reserved == limit_price.notional(qty_remaining)` (toward-zero),
/// where the limit price is the maker's resting price — the price every fill
/// against this maker executes at. Releases telescope against that identity:
/// each fill releases `reserved - price.notional(new_qty)` rather than the
/// floor of its own fill notional, so the sum of releases over the order's
/// lifetime equals the reserved amount bit-exactly. Summing per-fill floors
/// instead (`floor(a) + floor(b) <= floor(a + b)`) can strand up to one
/// micro-unit per fill in `reserved_resting` forever once the maker leaves
/// the book (#408).
#[derive(Debug, Clone, Copy)]
struct OrderReserve {
    /// Owning account.
    account: AccountId,
    /// Notional currently reserved in [`RiskEngine::reserve_resting`].
    reserved: Amount,
    /// Resting quantity the reserve was computed from.
    qty_remaining: Quantity,
}

/// Add `amount` into a committed escrow column entry (creating it if absent).
fn column_add<K: Ord>(
    column: &mut BTreeMap<K, Amount>,
    key: K,
    amount: Amount,
) -> Result<(), ExecutionError> {
    if amount.raw() < 0 {
        return Err(ExecutionError::NegativeAmount);
    }
    if amount.raw() == 0 {
        return Ok(());
    }
    let entry = column.entry(key).or_insert(Amount::ZERO);
    *entry = entry.checked_add(amount)?;
    Ok(())
}

/// Subtract `amount` from a committed escrow column entry, removing the entry
/// when it reaches zero so leaves stay canonical. A shortfall or missing entry
/// is an escrow accounting inconsistency (typed, never a panic).
fn column_sub<K: Ord + Copy>(
    column: &mut BTreeMap<K, Amount>,
    key: K,
    amount: Amount,
) -> Result<(), ExecutionError> {
    if amount.raw() < 0 {
        return Err(ExecutionError::NegativeAmount);
    }
    if amount.raw() == 0 {
        return Ok(());
    }
    let current = column
        .get(&key)
        .copied()
        .ok_or(ExecutionError::EscrowInconsistency)?;
    if current < amount {
        return Err(ExecutionError::EscrowInconsistency);
    }
    let next = current.checked_sub(amount)?;
    if next.raw() == 0 {
        column.remove(&key);
    } else {
        column.insert(key, next);
    }
    Ok(())
}

/// Escrow backing one resting claim-market order.
///
/// A resting bid moves its promised premium out of the ledger's `available`
/// partition (and out of risk collateral) when it rests; a resting ask moves
/// the offered claims out of the live claim balance. Fills draw down this
/// record, so a resting maker can never be left unbacked, and every cancel /
/// expiry / replace / liquidation / resolve path releases the exact remainder.
#[derive(Debug, Clone, Copy)]
struct ClaimOrderEscrow {
    /// Owning account.
    account: AccountId,
    /// Side of the resting order (bid escrows premium; ask escrows claims).
    side: Side,
    /// Remaining escrowed premium (bids; zero for asks).
    premium: Amount,
    /// Remaining escrowed claim quantity (asks; zero for bids).
    claims: Amount,
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
    /// Resting-order notional reserved, keyed by book-order coordinates. Each
    /// record carries the resting quantity its reserve was computed from so
    /// fill-by-fill releases telescope to exactly the reserved amount (see
    /// [`OrderReserve`]).
    order_reserves: HashMap<OrderKey, OrderReserve>,
    /// Outcome claims: account -> market -> per-outcome balances. Live
    /// (spendable) claims only; claims backing resting asks are moved into
    /// `ask_claims_escrow` while the order rests. Keyed by account first so
    /// [`Self::account_leaf`] folds one account's claims without scanning
    /// every other account's entries (#404); the inner `BTreeMap` iterates
    /// markets in ascending key order — exactly the committed leaf's
    /// serialization order, so no per-leaf sort is needed.
    claims: HashMap<u32, BTreeMap<u32, Vec<Amount>>>,
    /// Committed reserved-premium column for resting claim-market bids, keyed
    /// `(account, market)`. The cash itself sits in the ledger's `escrowed`
    /// partition; this column is the per-market breakdown folded into the
    /// account leaf (deterministic: BTreeMap iterates in key order).
    bid_premium_escrow: BTreeMap<(u32, u32), Amount>,
    /// Committed reserved-claims column for resting claim-market asks, keyed
    /// `(account, market, instrument)`; folded into the account leaf.
    ask_claims_escrow: BTreeMap<(u32, u32, u16), Amount>,
    /// Per-resting-order escrow records for exact release on fill drawdown,
    /// cancel, cancel-all, replace, expiry, liquidation, and resolve.
    claim_escrows: HashMap<OrderKey, ClaimOrderEscrow>,
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
            bid_premium_escrow: BTreeMap::new(),
            ask_claims_escrow: BTreeMap::new(),
            claim_escrows: HashMap::new(),
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

    /// Live (un-escrowed) outcome-claim balance for `account` in `market` at
    /// `instrument`, or zero. Claims backing resting asks are excluded: they sit
    /// in the committed reserved-claims column until the ask fills or releases.
    pub fn claim_balance(&self, account: AccountId, market: MarketId, instrument: u16) -> Amount {
        self.claims
            .get(&account.get())
            .and_then(|markets| markets.get(&market.get()))
            .and_then(|v| v.get(usize::from(instrument)))
            .copied()
            .unwrap_or(Amount::ZERO)
    }

    /// Premium escrowed by `account`'s resting claim-market bids in `market`.
    pub fn premium_escrowed(&self, account: AccountId, market: MarketId) -> Amount {
        self.bid_premium_escrow
            .get(&(account.get(), market.get()))
            .copied()
            .unwrap_or(Amount::ZERO)
    }

    /// Claims escrowed by `account`'s resting asks in `market` at `instrument`.
    pub fn claims_escrowed(&self, account: AccountId, market: MarketId, instrument: u16) -> Amount {
        self.ask_claims_escrow
            .get(&(account.get(), market.get(), instrument))
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
            OracleHealth::Halted | OracleHealth::Stale => Err(ExecutionError::OracleRiskFrozen),
            OracleHealth::Normal | OracleHealth::Degraded => Ok(()),
        }
    }

    /// Reserve basis for the residual of a just-matched order: the resting
    /// quantity (`requested - filled`) and its limit-price notional (toward
    /// zero). Both are returned together so the stored [`OrderReserve`] holds
    /// exactly the quantity its reserved amount was computed from.
    fn residual_notional(
        result: &orderbook::MatchResult,
        price: types::Price,
        requested: Quantity,
    ) -> Result<(Amount, Quantity), ExecutionError> {
        let filled = result.filled_quantity();
        let remaining = requested.raw().saturating_sub(filled.raw()).max(0);
        if remaining == 0 {
            return Ok((Amount::ZERO, Quantity::ZERO));
        }
        let qty = Quantity::from_raw(remaining);
        Ok((price.notional(qty)?, qty))
    }

    fn release_order_reserve(
        &mut self,
        market: MarketId,
        instrument: u16,
        order_id: types::OrderId,
        account: AccountId,
    ) -> Result<(), ExecutionError> {
        let key = (market.get(), instrument, order_id.get());
        if let Some(rec) = self.order_reserves.remove(&key) {
            if rec.account != account {
                // Put it back; wrong owner should not release.
                self.order_reserves.insert(key, rec);
                return Err(ExecutionError::OrderNotOwned);
            }
            // Release the CURRENT reserved amount (already telescoped down by
            // any prior fills), never a recomputation from scratch.
            self.risk.release_resting(account, rec.reserved)?;
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
        qty_remaining: Quantity,
    ) -> Result<(), ExecutionError> {
        if notional.raw() == 0 {
            return Ok(());
        }
        self.risk.reserve_resting(account, notional)?;
        self.order_reserves.insert(
            (market.get(), instrument, order_id.get()),
            OrderReserve {
                account,
                reserved: notional,
                qty_remaining,
            },
        );
        Ok(())
    }

    /// Escrow the resting residual of a claim-market order.
    ///
    /// Bids move the residual premium (`price * remaining`, floor — exactly what
    /// maker-price fills will draw) out of ledger `available` and risk
    /// collateral into the committed reserved-premium column. Asks move
    /// `remaining` claims out of the live claim balance into the committed
    /// reserved-claims column, so a second ask over the same claims fails closed
    /// at placement and `RedeemCompleteSet` cannot strip a resting ask's
    /// backing. Fails typed (rolling the whole command back) when the residual
    /// is not fully fundable.
    fn escrow_claim_resting(
        &mut self,
        key: OrderKey,
        account: AccountId,
        side: Side,
        price: types::Price,
        remaining: Quantity,
    ) -> Result<(), ExecutionError> {
        if remaining.raw() <= 0 {
            return Ok(());
        }
        let (market, instrument, _) = key;
        let mut record = ClaimOrderEscrow {
            account,
            side,
            premium: Amount::ZERO,
            claims: Amount::ZERO,
        };
        match side {
            Side::Bid => {
                let premium = price.notional(remaining)?;
                if premium.raw() > 0 {
                    // Fail-closed: both the settlement ledger and risk
                    // collateral must fund the promised premium at rest.
                    self.ledger.escrow(account, premium)?;
                    self.risk.debit_collateral(account, premium)?;
                    column_add(
                        &mut self.bid_premium_escrow,
                        (account.get(), market),
                        premium,
                    )?;
                }
                record.premium = premium;
            }
            Side::Ask => {
                let need = Amount::from_raw(i128::from(remaining.raw()));
                let entry = self
                    .claims
                    .get_mut(&account.get())
                    .and_then(|markets| markets.get_mut(&market))
                    .ok_or(ExecutionError::InsufficientClaims)?;
                let inst = usize::from(instrument);
                let held = entry.get(inst).copied().unwrap_or(Amount::ZERO);
                if held < need {
                    return Err(ExecutionError::InsufficientClaims);
                }
                entry[inst] = held.checked_sub(need)?;
                column_add(
                    &mut self.ask_claims_escrow,
                    (account.get(), market, instrument),
                    need,
                )?;
                record.claims = need;
            }
        }
        self.claim_escrows.insert(key, record);
        Ok(())
    }

    /// Release whatever escrow remains for one claim-market order back to its
    /// owner: bid premium returns to ledger `available` + risk collateral;
    /// ask claims return to the live claim balance. A missing record is a
    /// no-op (perp orders, already-drained fills). Returns the owner released.
    fn release_claim_escrow(
        &mut self,
        key: OrderKey,
        expected_owner: Option<AccountId>,
    ) -> Result<Option<AccountId>, ExecutionError> {
        let Some(record) = self.claim_escrows.get(&key).copied() else {
            return Ok(None);
        };
        if let Some(owner) = expected_owner {
            if record.account != owner {
                return Err(ExecutionError::OrderNotOwned);
            }
        }
        let (market, instrument, _) = key;
        match record.side {
            Side::Bid => {
                if record.premium.raw() > 0 {
                    column_sub(
                        &mut self.bid_premium_escrow,
                        (record.account.get(), market),
                        record.premium,
                    )?;
                    self.ledger.release_escrow(record.account, record.premium)?;
                    self.risk
                        .credit_collateral(record.account, record.premium)?;
                }
            }
            Side::Ask => {
                if record.claims.raw() > 0 {
                    column_sub(
                        &mut self.ask_claims_escrow,
                        (record.account.get(), market, instrument),
                        record.claims,
                    )?;
                    let meta = self
                        .markets
                        .get(&market)
                        .ok_or(ExecutionError::UnknownMarket)?;
                    let outcomes = usize::from(instrument_count(meta.market_type, meta.outcomes));
                    let entry = self
                        .claims
                        .entry(record.account.get())
                        .or_default()
                        .entry(market)
                        .or_insert_with(|| vec![Amount::ZERO; outcomes]);
                    if entry.len() < outcomes {
                        entry.resize(outcomes, Amount::ZERO);
                    }
                    let inst = usize::from(instrument);
                    if inst >= entry.len() {
                        return Err(ExecutionError::EscrowInconsistency);
                    }
                    entry[inst] = entry[inst].checked_add(record.claims)?;
                }
            }
        }
        self.claim_escrows.remove(&key);
        Ok(Some(record.account))
    }

    /// Draw `premium` for a fill against a resting bid's escrow record and the
    /// committed reserved-premium column. Backed by the escrow-at-rest bound
    /// (per-fill floor notionals at the maker price never exceed the escrowed
    /// floor notional), so a shortfall is an accounting inconsistency.
    fn draw_bid_escrow(
        &mut self,
        key: OrderKey,
        buyer: AccountId,
        premium: Amount,
    ) -> Result<(), ExecutionError> {
        if premium.raw() == 0 {
            return Ok(());
        }
        let record = self
            .claim_escrows
            .get_mut(&key)
            .ok_or(ExecutionError::EscrowInconsistency)?;
        if record.account != buyer || !matches!(record.side, Side::Bid) || record.premium < premium
        {
            return Err(ExecutionError::EscrowInconsistency);
        }
        record.premium = record.premium.checked_sub(premium)?;
        column_sub(&mut self.bid_premium_escrow, (buyer.get(), key.0), premium)
    }

    /// Draw `qty` claims for a fill against a resting ask's escrow record and
    /// the committed reserved-claims column. Claims escrow is exact-integer, so
    /// a shortfall is an accounting inconsistency.
    fn draw_ask_escrow(
        &mut self,
        key: OrderKey,
        seller: AccountId,
        qty: Amount,
    ) -> Result<(), ExecutionError> {
        if qty.raw() == 0 {
            return Ok(());
        }
        let record = self
            .claim_escrows
            .get_mut(&key)
            .ok_or(ExecutionError::EscrowInconsistency)?;
        if record.account != seller || !matches!(record.side, Side::Ask) || record.claims < qty {
            return Err(ExecutionError::EscrowInconsistency);
        }
        record.claims = record.claims.checked_sub(qty)?;
        column_sub(
            &mut self.ask_claims_escrow,
            (seller.get(), key.0, key.1),
            qty,
        )
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
    /// epoch, risk collateral and the derived margin columns, open positions,
    /// outcome claims, and the resting-order escrow columns (reserved premium
    /// per market, reserved claims per market/instrument) — the complete
    /// economic state a light client verifies against the shard root.
    ///
    /// Positions, claim sets, and escrow entries are emitted in ascending
    /// market (and instrument) order, and flat positions / fully-redeemed
    /// (all-zero) claim sets / zero escrows are omitted, so the leaf is
    /// canonical over economic state: replaying an identical command stream
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
        // Claims are keyed by account first, so only this account's entries are
        // walked (no global scan, #404); the inner `BTreeMap` iterates markets
        // in ascending key order — byte-identical to the explicit
        // sort-by-market this serialization previously performed.
        let claims: Vec<(u32, &[Amount])> = self
            .claims
            .get(&account.get())
            .map(|markets| {
                markets
                    .iter()
                    .filter(|(_, amounts)| amounts.iter().any(|v| v.raw() != 0))
                    .map(|(&m, amounts)| (m, amounts.as_slice()))
                    .collect()
            })
            .unwrap_or_default();
        w.field_u32(u32::try_from(claims.len()).unwrap_or(u32::MAX));
        for (m, amounts) in &claims {
            w.field_u32(*m)
                .field_u32(u32::try_from(amounts.len()).unwrap_or(u32::MAX));
            for v in *amounts {
                w.field_i128(v.raw());
            }
        }
        // Reserved-premium column (resting claim-market bids), ascending by
        // market with zero entries omitted; then the reserved-claims column
        // (resting asks), ascending by (market, instrument). Both are
        // integer-only, fixed-order, sorted-key serializations (BTreeMap range
        // iteration), so identical command streams commit bit-identical leaves
        // on every architecture.
        let a = account.get();
        let premium: Vec<(u32, i128)> = self
            .bid_premium_escrow
            .range((a, u32::MIN)..=(a, u32::MAX))
            .filter(|(_, v)| v.raw() != 0)
            .map(|(&(_, m), v)| (m, v.raw()))
            .collect();
        w.field_u32(u32::try_from(premium.len()).unwrap_or(u32::MAX));
        for (m, v) in &premium {
            w.field_u32(*m).field_i128(*v);
        }
        let reserved_claims: Vec<(u32, u16, i128)> = self
            .ask_claims_escrow
            .range((a, u32::MIN, u16::MIN)..=(a, u32::MAX, u16::MAX))
            .filter(|(_, v)| v.raw() != 0)
            .map(|(&(_, m, i), v)| (m, i, v.raw()))
            .collect();
        w.field_u32(u32::try_from(reserved_claims.len()).unwrap_or(u32::MAX));
        for (m, inst, v) in &reserved_claims {
            w.field_u32(*m).field_u32(u32::from(*inst)).field_i128(*v);
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
            // The release telescopes: recompute the reserve the residual still
            // needs (`fill.price` IS the maker's limit price — the same basis
            // the reservation was floored on) and release the difference, so
            // Σ releases over the maker's lifetime equals the reserved amount
            // bit-exactly. Releasing per-fill floors instead under-releases
            // (floor(a) + floor(b) <= floor(a + b)) and, once the maker fully
            // fills off the book, the dust would stay reserved forever (#408).
            let fill_notional = fill.price.notional(fill.quantity)?;
            let key = (market.get(), instrument, fill.maker_order.get());
            if let Some(rec) = self.order_reserves.get(&key).copied() {
                let new_qty = rec.qty_remaining.saturating_sub(fill.quantity);
                let new_reserve = fill.price.notional(new_qty)?;
                // Non-negative: notional is monotone in quantity at a fixed
                // price; a shortfall (never expected) fails typed in
                // `release_resting`, rolling the whole command back.
                let release = rec.reserved.checked_sub(new_reserve)?;
                self.risk.release_resting(rec.account, release)?;
                if new_qty.raw() == 0 {
                    self.order_reserves.remove(&key);
                } else {
                    self.order_reserves.insert(
                        key,
                        OrderReserve {
                            account: rec.account,
                            reserved: new_reserve,
                            qty_remaining: new_qty,
                        },
                    );
                }
            }
            // When this fill fully consumed the resting maker (it no longer
            // rests on the already-updated book), release any residual claim
            // escrow — floor-rounding premium dust for bids, exact zero for
            // asks — back to the maker so nothing leaks.
            let maker_consumed = self
                .books
                .get(&(market.get(), instrument))
                .map(|b| !b.contains(fill.maker_order))
                .unwrap_or(true);
            if maker_consumed {
                self.release_claim_escrow(key, None)?;
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
    /// (`price * quantity`) moves stablecoin + risk collateral from buyer to
    /// seller. Never opens a [`risk::PerpPosition`].
    ///
    /// The resting maker's side settles from its escrow taken at rest — a
    /// maker ask's claims come out of the reserved-claims column and a maker
    /// bid's premium out of the reserved-premium column — so a fill can never
    /// fail on the maker and leave a poisoned, unbacked order resting. Only the
    /// taker's own leg (live claims / available cash) can reject, which rolls
    /// back only the taker's own command.
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
        let maker_is_seller = matches!(fill.taker_side, Side::Bid);
        let (seller, buyer) = match fill.taker_side {
            Side::Bid => (fill.maker_account, fill.taker_account),
            Side::Ask => (fill.taker_account, fill.maker_account),
        };
        let maker_key: OrderKey = (market.get(), instrument, fill.maker_order.get());
        let qty = Amount::from_raw(i128::from(fill.quantity.raw()));
        if qty.raw() <= 0 {
            return Err(ExecutionError::NegativeAmount);
        }
        // Debit seller claims: from the maker's escrow when the resting ask
        // sells (escrowed at rest, so this cannot fail on the maker), from the
        // live balance when the taker sells (checked at placement; a failure
        // rejects only the taker's own command).
        if maker_is_seller {
            self.draw_ask_escrow(maker_key, seller, qty)?;
        } else {
            let entry = self
                .claims
                .entry(seller.get())
                .or_default()
                .entry(market.get())
                .or_insert_with(|| vec![Amount::ZERO; outcomes]);
            if entry.len() < outcomes {
                entry.resize(outcomes, Amount::ZERO);
            }
            if entry[inst] < qty {
                return Err(ExecutionError::InsufficientClaims);
            }
            entry[inst] = entry[inst].checked_sub(qty)?;
        }
        // Credit buyer claims (always live).
        {
            let entry = self
                .claims
                .entry(buyer.get())
                .or_default()
                .entry(market.get())
                .or_insert_with(|| vec![Amount::ZERO; outcomes]);
            if entry.len() < outcomes {
                entry.resize(outcomes, Amount::ZERO);
            }
            entry[inst] = entry[inst].checked_add(qty)?;
        }
        // Premium cash: buyer pays seller (zero-sum ledger + risk). A resting
        // maker bid settles from its premium escrow — the cash left `available`
        // and risk collateral when the bid rested — so the maker leg cannot
        // fail; a taker bid pays from live available cash.
        let premium = fill.price.notional(fill.quantity)?;
        if premium.raw() > 0 {
            if maker_is_seller {
                self.ledger.transfer_available(buyer, seller, premium)?;
                self.risk.debit_collateral(buyer, premium)?;
            } else {
                self.draw_bid_escrow(maker_key, buyer, premium)?;
                self.ledger.settle_escrow(buyer, seller, premium)?;
            }
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
        _reduce_only: bool,
    ) -> Result<Amount, ExecutionError> {
        self.validate_instrument(market, instrument)?;
        let book = self
            .books
            .get(&(market.get(), instrument))
            .ok_or(ExecutionError::UnknownMarket)?;

        // `plan_match` is a full dry-run of matching against current depth. Its
        // result is only needed to margin market orders from executable depth, so
        // a resting limit — the most common command — no longer pays that O(levels)
        // walk and allocation for a value it would discard. The quantity/price
        // rejections `plan_match` performed *before* `authorize` are replicated
        // here so the pre-authorize ordering and the exact typed errors are
        // preserved.
        if order.quantity.raw() <= 0 {
            return Err(orderbook::OrderError::NonPositiveQuantity.into());
        }

        if matches!(order.order_type, OrderType::Market) {
            if order.price.raw() <= 0 {
                return Err(ExecutionError::MarketOrderCollarRequired);
            }
            // Worst-case notional within the collar: max(planned ceil notional,
            // collar price * requested qty) so a sparse book cannot under-margin
            // a market order that later rests nothing (markets are IOC) but still
            // cannot be gamed by a 1-micro placeholder.
            let plan = book.plan_match(order)?;
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
            return Ok(notional);
        }

        // Limit orders margin at their limit price, which must be positive — the
        // same fail-closed check `plan_match` applied to non-market orders. The
        // former mark-price fallback was dead under that gate and is intentionally
        // gone: reaching it would silently loosen validation for a `price <= 0`
        // limit.
        if order.price.raw() <= 0 {
            return Err(orderbook::OrderError::NonPositivePrice.into());
        }
        let notional = order.price.notional_ceil(order.quantity)?;
        Ok(notional)
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
            Amount::from_raw(
                notional
                    .raw()
                    .checked_neg()
                    .ok_or(types::ArithError::Overflow)?,
            )
        } else {
            notional
        };
        let ratio = types::Ratio::from_bps(i64::from(abs_bps))?;
        if bps > 0 {
            Ok(mag.mul_ratio_ceil(ratio)?)
        } else {
            let rebate = mag.mul_ratio(ratio)?;
            Ok(Amount::from_raw(
                rebate
                    .raw()
                    .checked_neg()
                    .ok_or(types::ArithError::Overflow)?,
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
                // set_mark_price recomputes every holder's equity/IM/MM, and those
                // values fold into the committed account leaf (see account_leaf).
                // Re-commit each holder's leaf so the state root matches live
                // account state — otherwise verify_account fails after a mark move.
                // Mirrors ApplyFundingEpoch. Collect first to avoid the
                // &self.risk / &mut self borrow conflict, and commit in ascending
                // index order for determinism. This stays inside the working-copy
                // transaction, so a commit failure rolls the whole command back.
                let holders: Vec<AccountId> = {
                    let n = self.risk.account_count();
                    let mut v = Vec::new();
                    for i in 0..n {
                        if let Ok(a) = AccountId::from_index(i) {
                            if self
                                .risk
                                .position(a, c.market)
                                .map(|q| q.raw() != 0)
                                .unwrap_or(false)
                            {
                                v.push(a);
                            }
                        }
                    }
                    v
                };
                for a in &holders {
                    self.commit_account(*a)?;
                }
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
                // Market orders margin from executable depth; limit orders use
                // their limit price. See `pretrade_notional`.
                let notional =
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
                            // Seller must already hold the claims being offered
                            // in the LIVE (un-escrowed) pool: claims backing
                            // already-resting asks were moved into the
                            // reserved-claims column at rest, so a second ask
                            // over the same claims fails closed here.
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
                // Escrow (claims) or reserve IM (perps) for any residual that
                // rests on the book.
                if rested {
                    let remaining = match result.outcome {
                        OrderOutcome::Resting { remaining }
                        | OrderOutcome::PartiallyFilledResting { remaining } => remaining,
                        _ => Quantity::ZERO,
                    };
                    if is_claim_market(meta_type) {
                        // Escrow-at-rest: physically move the promised premium
                        // (bid) or claims (ask) out of the spendable pools so a
                        // resting maker can never be crossed unbacked. A second
                        // ask over the same claims — or a bid promising cash
                        // `available` does not hold — fails closed right here.
                        self.escrow_claim_resting(
                            (c.market.get(), c.instrument, c.order_id.get()),
                            c.account,
                            c.side,
                            c.price,
                            remaining,
                        )?;
                    } else {
                        let (rest_notional, rest_qty) =
                            Self::residual_notional(&result, c.price, c.quantity)?;
                        // Limit orders use their limit price; market residuals
                        // do not rest.
                        let (rest_notional, rest_qty) =
                            if !matches!(c.order_type, OrderType::Market) && c.price.raw() > 0 {
                                (rest_notional, rest_qty)
                            } else {
                                (Amount::ZERO, Quantity::ZERO)
                            };
                        self.reserve_order(
                            c.market,
                            c.instrument,
                            c.order_id,
                            c.account,
                            rest_notional,
                            rest_qty,
                        )?;
                    }
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
                // Claim markets: restore the exact escrowed premium / claims.
                self.release_claim_escrow(
                    (c.market.get(), instrument, c.order_id.get()),
                    Some(c.account),
                )?;
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
                let keys: Vec<OrderKey> = self
                    .order_reserves
                    .iter()
                    .filter(|((m, _, _), rec)| *m == c.market.get() && rec.account == c.account)
                    .map(|(k, _)| *k)
                    .collect();
                for key in keys {
                    if let Some(rec) = self.order_reserves.remove(&key) {
                        self.risk.release_resting(rec.account, rec.reserved)?;
                    }
                }
                // Release every claim escrow this account holds in the market,
                // in sorted key order for cross-architecture determinism.
                let mut escrow_keys: Vec<OrderKey> = self
                    .claim_escrows
                    .iter()
                    .filter(|(k, rec)| k.0 == c.market.get() && rec.account == c.account)
                    .map(|(k, _)| *k)
                    .collect();
                escrow_keys.sort_unstable();
                for key in escrow_keys {
                    self.release_claim_escrow(key, Some(c.account))?;
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
                let meta_type = meta.market_type;
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
                let instrument =
                    instrument.ok_or(ExecutionError::Order(orderbook::OrderError::UnknownOrder))?;
                let notional = c.price.notional_ceil(c.quantity)?;
                self.authorize(c.account, c.market, notional, &c.auth)?;
                self.release_order_reserve(c.market, instrument, c.order_id, c.account)?;
                let order_key: OrderKey = (c.market.get(), instrument, c.order_id.get());
                // Claim markets: release the old order's escrow first (a
                // repriced order re-escrows at its new terms below), then apply
                // the same admission checks as placement — bids need free
                // collateral for the new notional, asks need the full new
                // quantity held in the live claim pool.
                let claim_side = if is_claim_market(meta_type) {
                    let side = self
                        .claim_escrows
                        .get(&order_key)
                        .map(|r| r.side)
                        .ok_or(ExecutionError::EscrowInconsistency)?;
                    self.release_claim_escrow(order_key, Some(c.account))?;
                    match side {
                        Side::Bid => self.risk.check_order(c.account, notional, false)?,
                        Side::Ask => {
                            let held = self.claim_balance(c.account, c.market, instrument);
                            let need = Amount::from_raw(i128::from(c.quantity.raw()));
                            if held < need {
                                return Err(ExecutionError::InsufficientClaims);
                            }
                        }
                    }
                    Some(side)
                } else {
                    self.risk
                        .check_order_in_market(c.account, c.market, notional, false)?;
                    None
                };
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
                    let remaining = match result.outcome {
                        OrderOutcome::Resting { remaining }
                        | OrderOutcome::PartiallyFilledResting { remaining } => remaining,
                        _ => Quantity::ZERO,
                    };
                    if let Some(side) = claim_side {
                        self.escrow_claim_resting(order_key, c.account, side, c.price, remaining)?;
                    } else {
                        let (rest_notional, rest_qty) =
                            Self::residual_notional(&result, c.price, c.quantity)?;
                        self.reserve_order(
                            c.market,
                            instrument,
                            c.order_id,
                            c.account,
                            rest_notional,
                            rest_qty,
                        )?;
                    }
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
                    .entry(c.account.get())
                    .or_default()
                    .entry(c.market.get())
                    .or_insert_with(|| vec![Amount::ZERO; outcomes]);
                if entry.len() < outcomes {
                    entry.resize(outcomes, Amount::ZERO);
                }
                for v in entry.iter_mut() {
                    *v = v.checked_add(c.count)?;
                }
                let key = (c.account.get(), c.market.get());
                let prev = self.mint_locked.get(&key).copied().unwrap_or(Amount::ZERO);
                self.mint_locked.insert(key, prev.checked_add(c.count)?);
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
                    .get_mut(&c.account.get())
                    .and_then(|markets| markets.get_mut(&c.market.get()))
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
                // Markets whose book state actually changed: `cancel_all`
                // removed at least one resting order there. Only these need a
                // market-leaf re-commit below — for every other market the
                // rebuilt leaf would be byte-identical to the one already in
                // the tree (same book roots, same meta), so re-hashing its
                // Merkle path is a pure no-op on the state root (#431).
                // `BTreeSet` iterates in ascending market id — the same
                // deterministic order the previous commit-every-market loop
                // produced with sort + dedup.
                let mut touched_markets: BTreeSet<u32> = BTreeSet::new();
                for key in &book_keys {
                    if let Some(book) = self.books.get_mut(key) {
                        if book.cancel_all(c.account) > 0 {
                            touched_markets.insert(key.0);
                        }
                    }
                }
                // Release the account's claim-market escrows for the orders
                // just cancelled — BEFORE risk settlement closes the risk
                // account, so the escrowed premium flows back into collateral
                // and participates in the liquidation instead of leaking.
                // Sorted key order keeps release deterministic.
                let mut escrow_keys: Vec<OrderKey> = self
                    .claim_escrows
                    .iter()
                    .filter(|(_, rec)| rec.account == c.account)
                    .map(|(k, _)| *k)
                    .collect();
                escrow_keys.sort_unstable();
                for key in escrow_keys {
                    self.release_claim_escrow(key, Some(c.account))?;
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
                let drop_keys: Vec<OrderKey> = self
                    .order_reserves
                    .iter()
                    .filter(|(_, rec)| rec.account == c.account)
                    .map(|(k, _)| *k)
                    .collect();
                for key in drop_keys {
                    if let Some(rec) = self.order_reserves.remove(&key) {
                        let _ = self.risk.release_resting(rec.account, rec.reserved);
                    }
                }
                for a in &affected {
                    self.commit_account(*a)?;
                }
                // Re-commit only the market leaves whose books changed. No
                // other effect of this handler reaches a market leaf: escrow
                // release, `risk.liquidate` (ADL fills, insurance draw,
                // socialization), and reservation drops mutate ledger / risk /
                // claim state, all of which lives in the account leaves
                // committed above; market meta (type, outcomes, mark price,
                // winning outcome) is untouched by liquidation.
                for m in &touched_markets {
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
                // Holders come from the risk engine's market -> accounts
                // reverse index: exactly the accounts with a non-zero position
                // in this market, in ascending account-index order — the same
                // set and sequence as the old dense 0..account_count() scan
                // filtered by non-zero position, so per-holder funding
                // accumulation, rounding, and commit order stay byte-identical
                // while the work scales with the market's holders instead of
                // accounts x positions (#430).
                let accounts: Vec<AccountId> = self.risk.market_holders(c.market)?;
                // Funding is a CLOSED transfer (#433). Per-account toward-zero
                // rounding of `notional * rate` is only symmetric when longs
                // and shorts mirror each other exactly; on a net-flat but
                // asymmetric book the truncated debits and credits diverge and
                // the difference leaks (or mints) collateral each epoch.
                // Policy, in the fixed ascending dense-index holder order:
                //   * payer   (truncated pay > 0): debit the obligation rounded
                //     UP — `mul_ratio_ceil`, the fixed.rs policy for
                //     non-negative obligations. The product `notional * rate`
                //     is strictly positive for a payer, so the toward-positive
                //     rounding is a ceiling on its magnitude.
                //   * receiver (truncated pay < 0): credit the truncated
                //     entitlement `|pay|` (the existing `mul_ratio` value).
                //   * residual `collected - distributed` (>= 0 by
                //     construction: payers round up, receivers round down) is
                //     routed to the insurance fund, so total collateral —
                //     accounts plus insurance — is conserved exactly.
                // Everything is integer-only over committed state (mark,
                // positions, rate) with checked accumulation, so identical
                // streams commit byte-identical roots on every architecture.
                let mut collected: i128 = 0;
                let mut distributed: i128 = 0;
                for a in &accounts {
                    let qty = self.risk.position(*a, c.market)?;
                    let notional = mark.notional(qty)?;
                    // Truncated payment classifies the holder: positive pays
                    // funding (long when rate > 0), negative receives it.
                    let pay = notional.mul_ratio(rate)?;
                    let delta = match pay.raw().cmp(&0) {
                        std::cmp::Ordering::Greater => {
                            let debit = notional.mul_ratio_ceil(rate)?;
                            collected = collected
                                .checked_add(debit.raw())
                                .ok_or(types::ArithError::Overflow)?;
                            Amount::from_raw(
                                debit
                                    .raw()
                                    .checked_neg()
                                    .ok_or(types::ArithError::Overflow)?,
                            )
                        }
                        std::cmp::Ordering::Less => {
                            let credit = Amount::from_raw(
                                pay.raw().checked_neg().ok_or(types::ArithError::Overflow)?,
                            );
                            distributed = distributed
                                .checked_add(credit.raw())
                                .ok_or(types::ArithError::Overflow)?;
                            credit
                        }
                        std::cmp::Ordering::Equal => Amount::ZERO,
                    };
                    self.risk.apply_funding(*a, delta)?;
                    self.commit_account(*a)?;
                }
                // Non-negative by construction; enforced fail-closed so a
                // violated assumption rolls the epoch back instead of drawing
                // the insurance fund down (fund_insurance rejects negatives).
                let residual = collected
                    .checked_sub(distributed)
                    .ok_or(types::ArithError::Overflow)?;
                if residual < 0 {
                    return Err(ExecutionError::NegativeFundingResidual);
                }
                if residual > 0 {
                    self.risk.fund_insurance(Amount::from_raw(residual))?;
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
                let reserve_keys: Vec<OrderKey> = self
                    .order_reserves
                    .keys()
                    .copied()
                    .filter(|(m, _, _)| *m == c.market.get())
                    .collect();
                for key in reserve_keys {
                    if let Some(rec) = self.order_reserves.remove(&key) {
                        let _ = self.risk.release_resting(rec.account, rec.reserved);
                        if let Some(book) = self.books.get_mut(&(key.0, key.1)) {
                            let _ = book.cancel(types::OrderId::new(key.2));
                        }
                    }
                }
                // Release every claim escrow in this market before settlement:
                // escrowed claims return to live balances (so SettleMarket pays
                // them) and escrowed premium returns to available. Sorted key
                // order for determinism; owners re-commit below so the state
                // root reflects the released balances.
                let mut escrow_keys: Vec<OrderKey> = self
                    .claim_escrows
                    .keys()
                    .copied()
                    .filter(|(m, _, _)| *m == c.market.get())
                    .collect();
                escrow_keys.sort_unstable();
                let mut released: Vec<AccountId> = Vec::new();
                for key in escrow_keys {
                    if let Some(owner) = self.release_claim_escrow(key, None)? {
                        released.push(owner);
                    }
                }
                released.sort_by_key(|a| a.get());
                released.dedup();
                for a in &released {
                    self.commit_account(*a)?;
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
                    .filter_map(|(&a, markets)| {
                        markets.get(&c.market.get()).map(|v| (a, v.clone()))
                    })
                    .collect();
                let mut paid = Amount::ZERO;
                let mut touched: Vec<AccountId> = Vec::new();
                for (acct, balances) in holders {
                    let account = AccountId::new(acct);
                    let payout = balances.get(win_idx).copied().unwrap_or(Amount::ZERO);
                    if let Some(markets) = self.claims.get_mut(&acct) {
                        markets.remove(&c.market.get());
                        if markets.is_empty() {
                            self.claims.remove(&acct);
                        }
                    }
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

        // Idempotency classification is non-mutating (`classify` takes `&self`),
        // so decide it *before* the transaction clone. The replay, conflict, and
        // expired outcomes touch no subsystem state, and cloning the whole engine
        // only to drop it (or, for a replay, only to advance `last_seq`) is pure
        // overhead — a multi-megabyte deep copy on the hot exactly-once path. This
        // is byte-identical to the previous clone-then-classify boundary: a Replay
        // advanced only `last_seq`; Conflict/Expired left `self` untouched.
        if let Some(binding) = binding.as_ref() {
            match self.replay.classify(binding) {
                GuardDecision::Replay(receipt) => {
                    // Exactly-once: a byte-identical retry returns the original
                    // receipt without re-applying any delta. The only state that
                    // advances is the consumed sequence; ledger, positions, risk,
                    // book, withdrawals, and the root are left byte-identical, so
                    // advance `last_seq` in place rather than cloning the engine.
                    self.last_seq = Some(seq);
                    return Ok(receipt);
                }
                GuardDecision::Conflict => return Err(ExecutionError::IdempotencyConflict),
                GuardDecision::Expired => return Err(ExecutionError::ReplayExpired),
                GuardDecision::Fresh => {}
            }
        }

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
            // Commit the watermark into the working copy up front so the command's
            // own commits fold it into the same state root.
            txn.replay.reserve(binding);
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
        ApplyFundingEpoch, CancelAll, CancelOrder, CompleteSetOp, CreateAccount, CreateMarket,
        DepositCredit, FinalizeWithdrawal, Liquidate, PlaceOrder, ReplaceOrder, RequestWithdrawal,
        ResolveMarket, SetMarkPrice, SettleMarket,
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

    /// A two-outcome prediction (claim) market.
    fn create_claim(id: u32) -> Command {
        Command::CreateMarket(CreateMarket {
            market: MarketId::new(id),
            market_type: MarketType::BinaryPrediction,
            outcomes: 2,
            mark_price: Price::from_raw(500_000),
        })
    }

    fn mint(account: u32, market: u32, count: i128) -> Command {
        Command::MintCompleteSet(CompleteSetOp {
            account: AccountId::new(account),
            market: MarketId::new(market),
            count: Amount::from_raw(count),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn place_at(
        account: u32,
        market: u32,
        order_id: u64,
        side: Side,
        price: i64,
        qty: i64,
        instrument: u16,
        tif: TimeInForce,
    ) -> Command {
        Command::PlaceOrder(PlaceOrder {
            account: AccountId::new(account),
            market: MarketId::new(market),
            order_id: OrderId::new(order_id),
            side,
            order_type: OrderType::Limit,
            tif,
            price: Price::from_raw(price),
            quantity: Quantity::from_raw(qty),
            client_id: order_id,
            reduce_only: false,
            instrument,
            auth: Authorization::Master,
        })
    }

    fn cancel(account: u32, market: u32, order_id: u64) -> Command {
        Command::CancelOrder(CancelOrder {
            market: MarketId::new(market),
            account: AccountId::new(account),
            order_id: OrderId::new(order_id),
            auth: Authorization::Master,
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
            w.field_i128(e.ledger.escrowed(a).unwrap().raw());
            w.field_i128(e.risk.collateral(a).unwrap().raw());
            w.field_i128(e.risk.equity(a).unwrap().raw());
        }
        // Claim-market escrow state: committed columns + per-order records.
        w.field_i128(i128::try_from(e.bid_premium_escrow.len()).unwrap());
        for (&(a, m), v) in &e.bid_premium_escrow {
            w.field_u32(a);
            w.field_u32(m);
            w.field_i128(v.raw());
        }
        w.field_i128(i128::try_from(e.ask_claims_escrow.len()).unwrap());
        for (&(a, m, inst), v) in &e.ask_claims_escrow {
            w.field_u32(a);
            w.field_u32(m);
            w.field_u32(u32::from(inst));
            w.field_i128(v.raw());
        }
        let mut escrow_records: Vec<(u32, u16, u64, u32, u32, i128, i128)> = e
            .claim_escrows
            .iter()
            .map(|(&(m, inst, oid), rec)| {
                let side_tag = match rec.side {
                    Side::Bid => 0u32,
                    Side::Ask => 1u32,
                };
                (
                    m,
                    inst,
                    oid,
                    rec.account.get(),
                    side_tag,
                    rec.premium.raw(),
                    rec.claims.raw(),
                )
            })
            .collect();
        escrow_records.sort_unstable();
        w.field_i128(i128::try_from(escrow_records.len()).unwrap());
        for (m, inst, oid, a, side_tag, premium, claims) in escrow_records {
            w.field_u32(m);
            w.field_u32(u32::from(inst));
            w.field_i64(i64::from_le_bytes(oid.to_le_bytes()));
            w.field_u32(a);
            w.field_u32(side_tag);
            w.field_i128(premium);
            w.field_i128(claims);
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
            .flat_map(|(&a, markets)| {
                markets
                    .iter()
                    .map(move |(&m, v)| (a, m, v.iter().map(|x| x.raw()).collect()))
            })
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

        // Claim-order escrow reconciliation: the ledger's escrowed partition is
        // exactly the sum of the committed per-market reserved-premium column,
        // and each committed column entry is exactly the sum of its live
        // per-order escrow records — so escrow can neither leak nor double-count
        // without failing here.
        let mut premium_by_account: HashMap<u32, i128> = HashMap::new();
        for (&(a, _m), v) in &e.bid_premium_escrow {
            *premium_by_account.entry(a).or_default() += v.raw();
        }
        for i in 0..n {
            let a = AccountId::from_index(i).unwrap();
            assert_eq!(
                e.ledger.escrowed(a).unwrap().raw(),
                premium_by_account.get(&a.get()).copied().unwrap_or(0),
                "account {i} ledger escrow diverged from the committed premium column",
            );
        }
        let mut premium_by_column: HashMap<(u32, u32), i128> = HashMap::new();
        let mut claims_by_column: HashMap<(u32, u32, u16), i128> = HashMap::new();
        for (&(m, inst, _oid), rec) in &e.claim_escrows {
            match rec.side {
                Side::Bid => {
                    *premium_by_column.entry((rec.account.get(), m)).or_default() +=
                        rec.premium.raw();
                }
                Side::Ask => {
                    *claims_by_column
                        .entry((rec.account.get(), m, inst))
                        .or_default() += rec.claims.raw();
                }
            }
        }
        premium_by_column.retain(|_, v| *v != 0);
        claims_by_column.retain(|_, v| *v != 0);
        let committed_premium: HashMap<(u32, u32), i128> = e
            .bid_premium_escrow
            .iter()
            .map(|(&k, v)| (k, v.raw()))
            .collect();
        let committed_claims: HashMap<(u32, u32, u16), i128> = e
            .ask_claims_escrow
            .iter()
            .map(|(&k, v)| (k, v.raw()))
            .collect();
        assert_eq!(
            committed_premium, premium_by_column,
            "committed premium column diverged from per-order escrow records",
        );
        assert_eq!(
            committed_claims, claims_by_column,
            "committed claims column diverged from per-order escrow records",
        );

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
    fn set_mark_price_recommits_holder_leaves() {
        // The committed account leaf folds risk equity/IM/MM, which recompute when
        // the mark moves. After opening a real perp position and moving the mark,
        // every holder's committed leaf must still verify against the state root —
        // otherwise SetMarkPrice leaves stale leaves and check_invariants (which
        // calls verify_account for every account) fails.
        let mut e = engine_with_caps(8, 4);
        e.execute(seq(1), create_account(1_000_000_000_000))
            .unwrap(); // maker 0
        e.execute(seq(2), create_account(1_000_000_000_000))
            .unwrap(); // taker 1
        e.execute(seq(3), create_perp(0, 1_000_000)).unwrap();
        // Maker rests a bid at 1.0; taker crosses with an ask -> both open a
        // non-zero perp position whose equity depends on the mark.
        e.execute(seq(4), place(0, 0, 1, Side::Bid, 1_000_000, 1_000_000))
            .unwrap();
        e.execute(seq(5), place(1, 0, 2, Side::Ask, 1_000_000, 1_000_000))
            .unwrap();
        for a in [0u32, 1] {
            assert_ne!(
                e.risk
                    .position(AccountId::new(a), MarketId::new(0))
                    .unwrap_or(Quantity::ZERO),
                Quantity::ZERO,
                "account {a} should hold a position",
            );
        }
        // Move the mark up 20%: both holders' equity/IM/MM change.
        e.execute(
            seq(6),
            Command::SetMarkPrice(SetMarkPrice {
                market: MarketId::new(0),
                price: Price::from_raw(1_200_000),
            }),
        )
        .unwrap();
        // Without re-committing holder leaves, verify_account fails here.
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

    // --- Claim-market escrow-at-rest (issue #398) ----------------------------
    //
    // A resting claim order must be BACKED: a bid escrows its promised premium
    // out of `available`, an ask escrows the offered claims out of the live
    // claim pool, both into committed columns that fold into the state root.
    // Every release path (fill drawdown, cancel, cancel-all, replace, TIF
    // expiry, liquidation, resolve) restores the exact reserved amount.

    // Reproduction 1: a seller holding 100 claims rests a 100-claim ask; the
    // escrow physically removes the claims, so a second 100-claim ask is
    // REJECTED at placement (fail-closed) and a taker crossing the first ask
    // can never fail on the maker.
    #[test]
    fn overcommitted_second_ask_rejected_and_resting_ask_always_fillable() {
        let mut e = engine_with_caps(8, 4);
        e.execute(seq(1), create_account(1_000_000_000)).unwrap(); // seller 0
        e.execute(seq(2), create_account(1_000_000_000)).unwrap(); // buyer 1
        e.execute(seq(3), create_claim(0)).unwrap();
        e.execute(seq(4), mint(0, 0, 100_000_000)).unwrap(); // 100.0 sets
        let (seller, buyer) = (AccountId::new(0), AccountId::new(1));
        let m = MarketId::new(0);

        // First 100-claim ask at best price rests; claims move into escrow.
        e.execute(seq(5), place(0, 0, 1, Side::Ask, 400_000, 100_000_000))
            .unwrap();
        assert_eq!(e.claim_balance(seller, m, 0), Amount::ZERO);
        assert_eq!(
            e.claims_escrowed(seller, m, 0),
            Amount::from_raw(100_000_000)
        );
        check_invariants(&e);

        // Second identical ask has no un-escrowed claims backing it: rejected
        // at placement, leaving nothing behind.
        let before = fingerprint(&e);
        assert_eq!(
            e.execute(seq(6), place(0, 0, 2, Side::Ask, 400_000, 100_000_000)),
            Err(ExecutionError::InsufficientClaims),
        );
        assert_eq!(fingerprint(&e), before, "rejected ask mutated state");
        assert_eq!(e.market_resting_len(m), Some(1));

        // The resting ask is drawn from escrow at fill: the taker command
        // succeeds even though the seller's LIVE balance is zero — the
        // poisoned-ask scenario is impossible.
        e.execute(seq(7), place(1, 0, 3, Side::Bid, 400_000, 100_000_000))
            .unwrap();
        assert_eq!(e.claim_balance(buyer, m, 0), Amount::from_raw(100_000_000));
        assert_eq!(e.claims_escrowed(seller, m, 0), Amount::ZERO);
        assert!(
            e.claim_escrows.is_empty(),
            "escrow record leaked after fill"
        );
        // Premium 0.4 * 100 = 40.0 paid to the seller.
        assert_eq!(
            e.ledger.available(seller).unwrap(),
            Amount::from_raw(1_000_000_000 - 100_000_000 + 40_000_000),
        );
        check_invariants(&e);
    }

    // Reproduction 2: a bid cannot rest promising premium `available` does not
    // hold — it is rejected at rest (fail-closed) — and a funded bid escrows
    // its premium into the committed column, from which fills settle without
    // touching `available` again.
    #[test]
    fn underfunded_bid_rejected_and_funded_bid_escrows_premium() {
        let mut e = engine_with_caps(8, 4);
        e.execute(seq(1), create_account(10_000_000)).unwrap(); // buyer 0: 10.0
        e.execute(seq(2), create_account(1_000_000_000)).unwrap(); // seller 1
        e.execute(seq(3), create_claim(0)).unwrap();
        let buyer = AccountId::new(0);
        let m = MarketId::new(0);

        // 30 @ 0.5 promises premium 15.0 > 10.0 available: rejected at rest.
        let before = fingerprint(&e);
        assert!(matches!(
            e.execute(seq(4), place(0, 0, 1, Side::Bid, 500_000, 30_000_000)),
            Err(ExecutionError::InsufficientAvailable { .. })
        ));
        assert_eq!(e.market_resting_len(m), Some(0), "unbacked bid rested");
        assert_eq!(fingerprint(&e), before);

        // A funded bid rests: premium 8.0 moves available -> escrow column.
        e.execute(seq(5), place(0, 0, 2, Side::Bid, 500_000, 16_000_000))
            .unwrap();
        assert_eq!(e.premium_escrowed(buyer, m), Amount::from_raw(8_000_000));
        assert_eq!(
            e.ledger.escrowed(buyer).unwrap(),
            Amount::from_raw(8_000_000)
        );
        assert_eq!(
            e.ledger.available(buyer).unwrap(),
            Amount::from_raw(2_000_000)
        );
        check_invariants(&e);

        // A further bid the remaining 2.0 cannot back is rejected fail-closed:
        // the point-in-time race of the original bug is gone because the first
        // bid's premium has physically left `available`.
        let before = fingerprint(&e);
        assert!(matches!(
            e.execute(seq(6), place(0, 0, 3, Side::Bid, 500_000, 10_000_000)),
            Err(ExecutionError::InsufficientAvailable { .. })
        ));
        assert_eq!(fingerprint(&e), before);

        // A seller crossing the resting bid settles from escrow: the maker leg
        // cannot fail and the buyer's available cash is untouched at fill.
        e.execute(seq(7), mint(1, 0, 16_000_000)).unwrap();
        e.execute(seq(8), place(1, 0, 4, Side::Ask, 500_000, 16_000_000))
            .unwrap();
        assert_eq!(e.premium_escrowed(buyer, m), Amount::ZERO);
        assert_eq!(e.ledger.escrowed(buyer).unwrap(), Amount::ZERO);
        assert_eq!(
            e.ledger.available(buyer).unwrap(),
            Amount::from_raw(2_000_000)
        );
        assert_eq!(e.claim_balance(buyer, m, 0), Amount::from_raw(16_000_000));
        assert!(e.claim_escrows.is_empty());
        check_invariants(&e);
    }

    // Release coverage: CancelOrder restores the reserved columns to zero and
    // the live claim balance / available cash exactly.
    #[test]
    fn cancel_restores_escrowed_claims_and_premium_exactly() {
        let mut e = engine_with_caps(8, 4);
        e.execute(seq(1), create_account(1_000_000_000)).unwrap(); // seller 0
        e.execute(seq(2), create_account(1_000_000_000)).unwrap(); // buyer 1
        e.execute(seq(3), create_claim(0)).unwrap();
        e.execute(seq(4), mint(0, 0, 50_000_000)).unwrap();
        let (seller, buyer) = (AccountId::new(0), AccountId::new(1));
        let m = MarketId::new(0);

        e.execute(seq(5), place(0, 0, 1, Side::Ask, 400_000, 50_000_000))
            .unwrap();
        e.execute(seq(6), place(1, 0, 2, Side::Bid, 300_000, 20_000_000))
            .unwrap(); // premium 6.0, no cross
        assert_eq!(
            e.claims_escrowed(seller, m, 0),
            Amount::from_raw(50_000_000)
        );
        assert_eq!(e.premium_escrowed(buyer, m), Amount::from_raw(6_000_000));
        check_invariants(&e);

        e.execute(seq(7), cancel(0, 0, 1)).unwrap();
        assert_eq!(e.claims_escrowed(seller, m, 0), Amount::ZERO);
        assert_eq!(e.claim_balance(seller, m, 0), Amount::from_raw(50_000_000));
        check_invariants(&e);

        e.execute(seq(8), cancel(1, 0, 2)).unwrap();
        assert_eq!(e.premium_escrowed(buyer, m), Amount::ZERO);
        assert_eq!(e.ledger.escrowed(buyer).unwrap(), Amount::ZERO);
        assert_eq!(
            e.ledger.available(buyer).unwrap(),
            Amount::from_raw(1_000_000_000),
        );
        assert_eq!(
            e.risk.collateral(buyer).unwrap(),
            Amount::from_raw(1_000_000_000),
        );
        assert!(e.claim_escrows.is_empty());
        check_invariants(&e);
    }

    // Release coverage: CancelAll releases every escrow the account holds in
    // the market — both instruments' claims and the bid premium — exactly.
    #[test]
    fn cancel_all_restores_escrows_exactly() {
        let mut e = engine_with_caps(8, 4);
        e.execute(seq(1), create_account(1_000_000_000)).unwrap();
        e.execute(seq(2), create_claim(0)).unwrap();
        e.execute(seq(3), mint(0, 0, 50_000_000)).unwrap();
        let a = AccountId::new(0);
        let m = MarketId::new(0);

        e.execute(
            seq(4),
            place_at(0, 0, 1, Side::Ask, 400_000, 30_000_000, 0, TimeInForce::Gtc),
        )
        .unwrap();
        e.execute(
            seq(5),
            place_at(0, 0, 2, Side::Ask, 400_000, 20_000_000, 1, TimeInForce::Gtc),
        )
        .unwrap();
        e.execute(
            seq(6),
            place_at(0, 0, 3, Side::Bid, 300_000, 10_000_000, 0, TimeInForce::Gtc),
        )
        .unwrap(); // premium 3.0
        assert_eq!(e.claims_escrowed(a, m, 0), Amount::from_raw(30_000_000));
        assert_eq!(e.claims_escrowed(a, m, 1), Amount::from_raw(20_000_000));
        assert_eq!(e.premium_escrowed(a, m), Amount::from_raw(3_000_000));
        check_invariants(&e);

        let r = e
            .execute(
                seq(7),
                Command::CancelAll(CancelAll {
                    market: m,
                    account: a,
                    auth: Authorization::Master,
                }),
            )
            .unwrap();
        assert!(matches!(r.kind, ReceiptKind::Cancelled(3)));
        assert_eq!(e.claims_escrowed(a, m, 0), Amount::ZERO);
        assert_eq!(e.claims_escrowed(a, m, 1), Amount::ZERO);
        assert_eq!(e.premium_escrowed(a, m), Amount::ZERO);
        assert_eq!(e.claim_balance(a, m, 0), Amount::from_raw(50_000_000));
        assert_eq!(e.claim_balance(a, m, 1), Amount::from_raw(50_000_000));
        assert_eq!(e.ledger.escrowed(a).unwrap(), Amount::ZERO);
        assert_eq!(
            e.ledger.available(a).unwrap(),
            Amount::from_raw(950_000_000), // 1000 - 50 locked by the mint
        );
        assert!(e.claim_escrows.is_empty());
        check_invariants(&e);
    }

    // Release coverage: ReplaceOrder releases the old escrow and re-escrows the
    // new residual exactly; growth the live pool cannot back is rejected
    // atomically (the original order and its escrow survive).
    #[test]
    fn replace_reescrows_exactly_and_rejects_unbacked_growth() {
        let mut e = engine_with_caps(8, 4);
        e.execute(seq(1), create_account(1_000_000_000)).unwrap(); // seller 0
        e.execute(seq(2), create_account(1_000_000_000)).unwrap(); // buyer 1
        e.execute(seq(3), create_claim(0)).unwrap();
        e.execute(seq(4), mint(0, 0, 100_000_000)).unwrap();
        let (seller, buyer) = (AccountId::new(0), AccountId::new(1));
        let m = MarketId::new(0);

        // Ask 100 @ 0.4 rests; replace down to 60 @ 0.5: exactly 60 stays
        // escrowed and 40 returns to the live pool.
        e.execute(seq(5), place(0, 0, 1, Side::Ask, 400_000, 100_000_000))
            .unwrap();
        e.execute(
            seq(6),
            Command::ReplaceOrder(ReplaceOrder {
                market: m,
                account: seller,
                order_id: OrderId::new(1),
                price: Price::from_raw(500_000),
                quantity: Quantity::from_raw(60_000_000),
                auth: Authorization::Master,
            }),
        )
        .unwrap();
        assert_eq!(
            e.claims_escrowed(seller, m, 0),
            Amount::from_raw(60_000_000)
        );
        assert_eq!(e.claim_balance(seller, m, 0), Amount::from_raw(40_000_000));
        check_invariants(&e);

        // Growing beyond the total holding (100) is rejected atomically.
        let before = fingerprint(&e);
        assert_eq!(
            e.execute(
                seq(7),
                Command::ReplaceOrder(ReplaceOrder {
                    market: m,
                    account: seller,
                    order_id: OrderId::new(1),
                    price: Price::from_raw(500_000),
                    quantity: Quantity::from_raw(150_000_000),
                    auth: Authorization::Master,
                }),
            ),
            Err(ExecutionError::InsufficientClaims),
        );
        assert_eq!(fingerprint(&e), before, "failed replace mutated escrow");
        assert_eq!(
            e.claims_escrowed(seller, m, 0),
            Amount::from_raw(60_000_000)
        );

        // Bid 20 @ 0.3 (premium 6.0) replaced to 30 @ 0.35 (premium 10.5):
        // the committed column tracks the new residual exactly.
        e.execute(seq(8), place(1, 0, 2, Side::Bid, 300_000, 20_000_000))
            .unwrap();
        assert_eq!(e.premium_escrowed(buyer, m), Amount::from_raw(6_000_000));
        e.execute(
            seq(9),
            Command::ReplaceOrder(ReplaceOrder {
                market: m,
                account: buyer,
                order_id: OrderId::new(2),
                price: Price::from_raw(350_000),
                quantity: Quantity::from_raw(30_000_000),
                auth: Authorization::Master,
            }),
        )
        .unwrap();
        assert_eq!(e.premium_escrowed(buyer, m), Amount::from_raw(10_500_000));
        assert_eq!(
            e.ledger.escrowed(buyer).unwrap(),
            Amount::from_raw(10_500_000)
        );
        assert_eq!(
            e.ledger.available(buyer).unwrap(),
            Amount::from_raw(1_000_000_000 - 10_500_000),
        );
        check_invariants(&e);
    }

    // Release coverage (TIF expiry): an IOC residual expires instead of
    // resting, so no escrow is ever taken for it, and a partially-filled
    // resting maker's escrow is drawn down exactly and fully released the
    // moment the order is consumed.
    #[test]
    fn ioc_residual_expiry_leaves_no_escrow() {
        let mut e = engine_with_caps(8, 4);
        e.execute(seq(1), create_account(1_000_000_000)).unwrap(); // seller 0
        e.execute(seq(2), create_account(1_000_000_000)).unwrap(); // buyer 1
        e.execute(seq(3), create_claim(0)).unwrap();
        e.execute(seq(4), mint(0, 0, 50_000_000)).unwrap();
        let (seller, buyer) = (AccountId::new(0), AccountId::new(1));
        let m = MarketId::new(0);

        // Resting ask 50 @ 0.4; buyer sends IOC bid 80 @ 0.4: 50 fills, the
        // 30 residual expires. No premium escrow may remain for the buyer.
        e.execute(seq(5), place(0, 0, 1, Side::Ask, 400_000, 50_000_000))
            .unwrap();
        e.execute(
            seq(6),
            place_at(1, 0, 2, Side::Bid, 400_000, 80_000_000, 0, TimeInForce::Ioc),
        )
        .unwrap();
        assert_eq!(e.premium_escrowed(buyer, m), Amount::ZERO);
        assert_eq!(e.ledger.escrowed(buyer).unwrap(), Amount::ZERO);
        assert_eq!(
            e.ledger.available(buyer).unwrap(),
            Amount::from_raw(1_000_000_000 - 20_000_000), // only the fill premium
        );
        assert_eq!(e.claim_balance(buyer, m, 0), Amount::from_raw(50_000_000));
        assert_eq!(e.claims_escrowed(seller, m, 0), Amount::ZERO);
        assert_eq!(e.market_resting_len(m), Some(0));
        assert!(e.claim_escrows.is_empty());
        check_invariants(&e);

        // Symmetric: a resting bid partially filled by an IOC ask. The maker
        // bid's escrow is drawn exactly; the taker ask's expired residual
        // escrows nothing and its claims stay live.
        e.execute(seq(7), mint(0, 0, 50_000_000)).unwrap();
        e.execute(
            seq(8),
            place_at(1, 0, 3, Side::Bid, 500_000, 20_000_000, 0, TimeInForce::Gtc),
        )
        .unwrap(); // premium 10.0 escrowed
        assert_eq!(e.premium_escrowed(buyer, m), Amount::from_raw(10_000_000));
        let buyer_available = e.ledger.available(buyer).unwrap();
        e.execute(
            seq(9),
            place_at(0, 0, 4, Side::Ask, 500_000, 50_000_000, 0, TimeInForce::Ioc),
        )
        .unwrap(); // fills 20, residual 30 expires
        assert_eq!(e.premium_escrowed(buyer, m), Amount::ZERO);
        assert_eq!(e.ledger.escrowed(buyer).unwrap(), Amount::ZERO);
        // The maker paid from escrow, not from available.
        assert_eq!(e.ledger.available(buyer).unwrap(), buyer_available);
        assert_eq!(e.claims_escrowed(seller, m, 0), Amount::ZERO);
        assert_eq!(e.claim_balance(seller, m, 0), Amount::from_raw(30_000_000));
        assert_eq!(e.claim_balance(buyer, m, 0), Amount::from_raw(70_000_000));
        assert!(e.claim_escrows.is_empty());
        check_invariants(&e);
    }

    // Release coverage: liquidation cancels the account's resting claim orders
    // and releases their escrows back (premium into collateral BEFORE risk
    // settlement, claims into the live pool) so nothing leaks when the risk
    // account closes.
    #[test]
    fn liquidation_releases_claim_escrows() {
        let mut e = engine_with_caps(8, 4);
        e.execute(seq(1), create_account(100_000_000)).unwrap(); // victim 0: 100.0
        e.execute(seq(2), create_account(10_000_000_000)).unwrap(); // cpty 1
        e.execute(seq(3), create_perp(0, 1_000_000)).unwrap();
        e.execute(seq(4), create_claim(1)).unwrap();
        let victim = AccountId::new(0);
        let m1 = MarketId::new(1);

        // Victim escrows claims (ask) and premium (bid) on the claim market.
        e.execute(seq(5), mint(0, 1, 50_000_000)).unwrap();
        e.execute(
            seq(6),
            place_at(0, 1, 1, Side::Ask, 500_000, 50_000_000, 0, TimeInForce::Gtc),
        )
        .unwrap();
        e.execute(
            seq(7),
            place_at(0, 1, 2, Side::Bid, 500_000, 10_000_000, 1, TimeInForce::Gtc),
        )
        .unwrap(); // premium 5.0
        assert_eq!(
            e.claims_escrowed(victim, m1, 0),
            Amount::from_raw(50_000_000)
        );
        assert_eq!(e.premium_escrowed(victim, m1), Amount::from_raw(5_000_000));
        check_invariants(&e);

        // Victim opens a 400.0 long at 1.0; the mark drops to 0.9 so equity
        // (45 - 40 = 5) falls below maintenance margin (18).
        e.execute(seq(8), place(1, 0, 3, Side::Ask, 1_000_000, 400_000_000))
            .unwrap();
        e.execute(seq(9), place(0, 0, 4, Side::Bid, 1_000_000, 400_000_000))
            .unwrap();
        e.execute(
            seq(10),
            Command::SetMarkPrice(SetMarkPrice {
                market: MarketId::new(0),
                price: Price::from_raw(900_000),
            }),
        )
        .unwrap();
        check_invariants(&e);

        e.execute(seq(11), Command::Liquidate(Liquidate { account: victim }))
            .unwrap();
        assert!(e.bid_premium_escrow.is_empty(), "premium escrow leaked");
        assert!(e.ask_claims_escrow.is_empty(), "claims escrow leaked");
        assert!(e.claim_escrows.is_empty(), "escrow records leaked");
        assert_eq!(e.ledger.escrowed(victim).unwrap(), Amount::ZERO);
        // Premium (5.0) returned to available; claims returned to the live pool.
        assert_eq!(
            e.ledger.available(victim).unwrap(),
            Amount::from_raw(50_000_000)
        );
        assert_eq!(e.claim_balance(victim, m1, 0), Amount::from_raw(50_000_000));
        assert_eq!(e.claim_balance(victim, m1, 1), Amount::from_raw(50_000_000));
        check_invariants(&e);
    }

    // #431: Liquidate re-commits only the market leaves whose books actually
    // changed (a cancel removed at least one resting order). With many markets
    // but victim orders resting in only a few, the post-liquidation root must
    // be bit-identical to the root produced by the pre-#431 behavior of
    // re-committing EVERY market leaf — skipped markets rebuild the exact
    // same leaf, so committing them is a no-op on the state root.
    #[test]
    fn liquidate_commits_only_touched_markets_bit_identically() {
        let mut e = engine_with_caps(4, 16);
        e.execute(seq(1), create_account(100_000_000)).unwrap(); // victim 0: 100.0
        e.execute(seq(2), create_account(10_000_000_000)).unwrap(); // cpty 1
        let victim = AccountId::new(0);
        for m in 0..12u32 {
            e.execute(seq(3 + u64::from(m)), create_perp(m, 1_000_000))
                .unwrap();
        }
        // Victim rests small non-crossing bids in ONLY markets 2 and 9.
        e.execute(seq(15), place(0, 2, 1, Side::Bid, 500_000, 10_000_000))
            .unwrap();
        e.execute(seq(16), place(0, 9, 2, Side::Bid, 500_000, 10_000_000))
            .unwrap();
        // The counterparty rests bids in markets 4 and 7, so untouched books
        // are non-empty (the skip must be per-account, not per-book-emptiness).
        e.execute(seq(17), place(1, 4, 3, Side::Bid, 500_000, 10_000_000))
            .unwrap();
        e.execute(seq(18), place(1, 7, 4, Side::Bid, 500_000, 10_000_000))
            .unwrap();
        // Victim opens a 400.0 long at 1.0 in market 0; the mark drops to
        // 0.75 so equity (100 - 100 = 0) falls below maintenance margin.
        e.execute(seq(19), place(1, 0, 5, Side::Ask, 1_000_000, 400_000_000))
            .unwrap();
        e.execute(seq(20), place(0, 0, 6, Side::Bid, 1_000_000, 400_000_000))
            .unwrap();
        e.execute(
            seq(21),
            Command::SetMarkPrice(SetMarkPrice {
                market: MarketId::new(0),
                price: Price::from_raw(750_000),
            }),
        )
        .unwrap();
        check_invariants(&e);

        e.execute(seq(22), Command::Liquidate(Liquidate { account: victim }))
            .unwrap();
        // The victim's resting orders are gone; bystander books are intact.
        assert_eq!(e.market_resting_len(MarketId::new(2)), Some(0));
        assert_eq!(e.market_resting_len(MarketId::new(9)), Some(0));
        assert_eq!(e.market_resting_len(MarketId::new(4)), Some(1));
        assert_eq!(e.market_resting_len(MarketId::new(7)), Some(1));
        // Every committed market leaf (including the ten skipped ones)
        // reconciles with the live books against the state root.
        check_invariants(&e);

        // Byte-identity with the pre-#431 behavior: force a re-commit of
        // EVERY market leaf and assert the root does not move — the markets
        // the handler skipped were provably unchanged.
        let root_after = e.state_root();
        let mut all_markets: Vec<u32> = e.markets.keys().copied().collect();
        all_markets.sort_unstable();
        assert_eq!(all_markets.len(), 12);
        for m in all_markets {
            e.commit_market(MarketId::new(m)).unwrap();
        }
        assert_eq!(
            e.state_root(),
            root_after,
            "committing all markets after Liquidate moved the root: a changed market was skipped",
        );
        check_invariants(&e);
    }

    // Release coverage: resolving a market releases every escrow in it —
    // escrowed claims return to live balances so SettleMarket's complete-set
    // pool reconciles exactly, and escrowed premium returns to available.
    #[test]
    fn resolve_releases_claim_escrows_before_settlement() {
        let mut e = engine_with_caps(8, 4);
        e.execute(seq(1), create_account(1_000_000_000)).unwrap(); // seller 0
        e.execute(seq(2), create_account(1_000_000_000)).unwrap(); // buyer 1
        e.execute(seq(3), create_claim(0)).unwrap();
        e.execute(seq(4), mint(0, 0, 100_000_000)).unwrap();
        let (seller, buyer) = (AccountId::new(0), AccountId::new(1));
        let m = MarketId::new(0);

        e.execute(seq(5), place(0, 0, 1, Side::Ask, 400_000, 60_000_000))
            .unwrap();
        e.execute(seq(6), place(1, 0, 2, Side::Bid, 300_000, 30_000_000))
            .unwrap(); // premium 9.0, no cross
        assert_eq!(
            e.claims_escrowed(seller, m, 0),
            Amount::from_raw(60_000_000)
        );
        assert_eq!(e.premium_escrowed(buyer, m), Amount::from_raw(9_000_000));
        check_invariants(&e);

        e.execute(
            seq(7),
            Command::ResolveMarket(ResolveMarket {
                market: m,
                winning_outcome: 0,
            }),
        )
        .unwrap();
        assert!(e.claim_escrows.is_empty());
        assert_eq!(e.claims_escrowed(seller, m, 0), Amount::ZERO);
        assert_eq!(e.premium_escrowed(buyer, m), Amount::ZERO);
        assert_eq!(e.claim_balance(seller, m, 0), Amount::from_raw(100_000_000));
        assert_eq!(
            e.ledger.available(buyer).unwrap(),
            Amount::from_raw(1_000_000_000),
        );
        check_invariants(&e);

        // Settlement pays the full winning holding from the mint-locked pool —
        // impossible if the resolve had left 60 claims stranded in escrow.
        e.execute(seq(8), Command::SettleMarket(SettleMarket { market: m }))
            .unwrap();
        assert_eq!(
            e.ledger.available(seller).unwrap(),
            Amount::from_raw(1_000_000_000),
        );
        assert_eq!(e.ledger.locked(seller).unwrap(), Amount::ZERO);
        check_invariants(&e);
    }

    // #408 repro: a perp maker rests 10 micro-lots at 0.333333, reserving
    // floor(333333 * 10 / 1e6) = 3 micro-units of notional. Ten one-lot fills
    // each floor to 0 fill notional, so summing per-fill floors releases 0 of
    // the 3 reserved; once the maker fully fills it leaves the book, no cancel
    // ever runs, and the 3 micro-units stay in `reserved_resting` forever.
    // The telescoping release must return the reservation to exactly zero and
    // drop the `order_reserves` record.
    #[test]
    fn full_fill_releases_floor_dust_reserve_exactly() {
        let mut e = engine_with_caps(8, 4);
        e.execute(seq(1), create_account(1_000_000_000)).unwrap(); // maker 0
        e.execute(seq(2), create_account(1_000_000_000)).unwrap(); // taker 1
        e.execute(seq(3), create_perp(0, 1_000_000)).unwrap();
        let maker = AccountId::new(0);

        // Maker bid: 10 micro-lots @ 0.333333 rests whole.
        e.execute(seq(4), place(0, 0, 1, Side::Bid, 333_333, 10))
            .unwrap();
        assert_eq!(
            e.risk.reserved_resting(maker).unwrap(),
            Amount::from_raw(3),
            "floor(333333 * 10 / 1e6) must reserve exactly 3",
        );
        assert!(e.order_reserves.contains_key(&(0, 0, 1)));

        // Ten one-lot taker asks fully consume the maker. Every per-fill
        // notional floors to zero — the leak scenario.
        for i in 0..10u64 {
            e.execute(seq(5 + i), place(1, 0, 2 + i, Side::Ask, 333_333, 1))
                .unwrap();
        }
        assert_eq!(
            e.risk.reserved_resting(maker).unwrap(),
            Amount::ZERO,
            "fully-filled maker stranded reserved notional (floor-sum leak)",
        );
        assert!(
            !e.order_reserves.contains_key(&(0, 0, 1)),
            "fully-filled maker left a dangling order_reserves record",
        );
        assert!(e.order_reserves.is_empty());
        check_invariants(&e);
    }

    // #408: partial fills draw the reservation down along the telescoped
    // schedule (reserved always equals the limit-price notional of the resting
    // residual), and a cancel then releases exactly the stored remainder — so
    // fills + cancel release precisely the original reserve, never less.
    #[test]
    fn partial_fills_then_cancel_release_original_reserve_exactly() {
        let mut e = engine_with_caps(8, 4);
        e.execute(seq(1), create_account(1_000_000_000)).unwrap(); // maker 0
        e.execute(seq(2), create_account(1_000_000_000)).unwrap(); // taker 1
        e.execute(seq(3), create_perp(0, 1_000_000)).unwrap();
        let maker = AccountId::new(0);

        e.execute(seq(4), place(0, 0, 1, Side::Bid, 333_333, 10))
            .unwrap();
        assert_eq!(e.risk.reserved_resting(maker).unwrap(), Amount::from_raw(3));

        // Three one-lot fills leave 7 resting: the reservation must telescope
        // to floor(333333 * 7 / 1e6) = 2 (per-fill floors would release 0 and
        // leave it stuck at 3).
        for i in 0..3u64 {
            e.execute(seq(5 + i), place(1, 0, 2 + i, Side::Ask, 333_333, 1))
                .unwrap();
        }
        assert_eq!(
            e.risk.reserved_resting(maker).unwrap(),
            Amount::from_raw(2),
            "reservation must track the residual's limit-price notional",
        );
        check_invariants(&e);

        // Cancel releases the CURRENT stored remainder (2), bringing the total
        // released across fills + cancel to exactly the original 3.
        e.execute(seq(8), cancel(0, 0, 1)).unwrap();
        assert_eq!(
            e.risk.reserved_resting(maker).unwrap(),
            Amount::ZERO,
            "fills + cancel must release exactly the original reserve",
        );
        assert!(e.order_reserves.is_empty());
        check_invariants(&e);
    }

    // #404 byte-identity golden: a multi-account, multi-market claim scenario
    // whose committed leaves and state root were captured from the pre-re-key
    // serialization (claims keyed `(account, market)` with an explicit
    // sort-by-market in `account_leaf`). The re-keyed layout
    // (account -> BTreeMap<market, _>) must reproduce these bytes exactly:
    // BTreeMap ascending-key iteration == the old sort by market.
    #[test]
    fn claims_rekey_keeps_leaf_bytes_and_root_golden_404() {
        let mut e = engine_with_caps(8, 4);
        e.execute(seq(1), create_account(1_000_000_000)).unwrap(); // 0
        e.execute(seq(2), create_account(1_000_000_000)).unwrap(); // 1
        e.execute(seq(3), create_account(1_000_000_000)).unwrap(); // 2

        // Claim markets created in non-ascending id order so map insertion
        // order differs from the committed (ascending-market) leaf order.
        e.execute(seq(4), create_claim(2)).unwrap();
        e.execute(seq(5), create_claim(0)).unwrap();
        e.execute(seq(6), create_claim(1)).unwrap();
        // Account 0 holds claims in all three markets, minted out of order.
        e.execute(seq(7), mint(0, 2, 40_000_000)).unwrap();
        e.execute(seq(8), mint(0, 0, 30_000_000)).unwrap();
        e.execute(seq(9), mint(0, 1, 20_000_000)).unwrap();
        // Account 1 holds claims in market 1 only.
        e.execute(seq(10), mint(1, 1, 10_000_000)).unwrap();
        // A resting ask escrows account 0's market-2 claims into the
        // reserved-claims column; a partial fill then moves 10.0 of them to
        // account 1 (exercising apply_claim_fill and the escrow draw).
        e.execute(
            seq(11),
            place_at(0, 2, 1, Side::Ask, 400_000, 25_000_000, 0, TimeInForce::Gtc),
        )
        .unwrap();
        e.execute(
            seq(12),
            place_at(1, 2, 2, Side::Bid, 400_000, 10_000_000, 0, TimeInForce::Gtc),
        )
        .unwrap();
        // A resting bid escrows account 1 premium in market 0.
        e.execute(
            seq(13),
            place_at(1, 0, 3, Side::Bid, 300_000, 5_000_000, 0, TimeInForce::Gtc),
        )
        .unwrap();
        // Account 2 mints then fully redeems: its all-zero claim set must be
        // omitted from the committed leaf exactly as before.
        e.execute(seq(14), mint(2, 0, 50_000_000)).unwrap();
        e.execute(
            seq(15),
            Command::RedeemCompleteSet(CompleteSetOp {
                account: AccountId::new(2),
                market: MarketId::new(0),
                count: Amount::from_raw(50_000_000),
            }),
        )
        .unwrap();

        // Every committed leaf must verify against the root, and the escrow
        // columns must reconcile with the per-order records.
        check_invariants(&e);

        // Account 0: claim groups for markets 0 (30/30), 1 (20/20), and
        // 2 (15 live / 40 — 25 escrowed by the ask, 10 of those sold), plus
        // the reserved-claims column entry (market 2, instrument 0, 15.0).
        assert_eq!(
            hex::encode(e.account_leaf(AccountId::new(0)).unwrap()),
            "010080887a360000000000000000000000000000000000000000000000000000\
             0000804a5d05000000000000000000000000000000000000000080887a360000\
             0000000000000000000080887a36000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000003000000000000000200000080c3c9010000\
             0000000000000000000080c3c901000000000000000000000000010000000200\
             0000002d3101000000000000000000000000002d310100000000000000000000\
             00000200000002000000c0e1e400000000000000000000000000005a62020000\
             0000000000000000000000000000010000000200000000000000c0e1e4000000\
             0000000000000000000001000000010000000000000000000000000000000000\
             0000",
        );
        // Account 1: claim groups for markets 1 (10/10) and 2 (10/0 — bought
        // from the fill), plus the reserved-premium column entry (market 0,
        // 1.5 escrowed by the resting bid).
        assert_eq!(
            hex::encode(e.account_leaf(AccountId::new(1)).unwrap()),
            "01002047ae3a0000000000000000000000000000000000000000000000000000\
             00008096980000000000000000000000000000000000000000002047ae3a0000\
             000000000000000000002047ae3a000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000020000000100000002000000809698000000\
             0000000000000000000080969800000000000000000000000000020000000200\
             0000809698000000000000000000000000000000000000000000000000000000\
             0000010000000000000060e31600000000000000000000000000000000000100\
             00000300000000000000000000000000000000000000",
        );
        // Account 2: fully-redeemed (all-zero) claim set is omitted — its leaf
        // carries zero claim groups, exactly as before the re-key.
        assert_eq!(
            hex::encode(e.account_leaf(AccountId::new(2)).unwrap()),
            "010000ca9a3b0000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000000000000000000000ca9a3b0000\
             0000000000000000000000ca9a3b000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000000000000000",
        );
        // The committed state root over the whole scenario is pinned too: any
        // leaf-byte drift anywhere moves it.
        assert_eq!(
            hex::encode(e.state_root().as_bytes()),
            "16873ec5c49c71a33f4efb6f8e73d1d714ed5a8dc34644d76efdb8b14bd60693",
        );
    }

    // #430 byte-identity golden: a multi-holder funding epoch driven by the
    // risk engine's market_holders reverse index must pay every holder — and
    // only the holders — exactly what the old dense 0..account_count() scan
    // paid, in the same ascending-account order, reproducing the state root
    // captured from the pre-#430 implementation.
    #[test]
    fn funding_epoch_multi_holder_matches_dense_scan_golden_430() {
        // Five accounts: three end holding distinct signed positions, one
        // opens a position and flattens it (leaves the holder index), one
        // never trades. All fills execute at the mark, so pre-funding
        // collateral is untouched and the funding deltas below are exact.
        let script: Vec<Command> = vec![
            create_account(100_000_000), // 0: ends long 4.5
            create_account(100_000_000), // 1: ends short 2.5
            create_account(100_000_000), // 2: ends short 2.0
            create_account(100_000_000), // 3: opens short 1.0, then flattens
            create_account(100_000_000), // 4: never trades
            create_perp(0, 1_000_000),
            // Account 0 rests a 3.5 bid; accounts 1 and 2 sell into it.
            place(0, 0, 1, Side::Bid, 1_000_000, 3_500_000),
            place(1, 0, 2, Side::Ask, 1_000_000, 1_500_000),
            place(2, 0, 3, Side::Ask, 1_000_000, 2_000_000),
            // Account 3 opens short 1.0 against account 0's fresh bid...
            place(0, 0, 4, Side::Bid, 1_000_000, 1_000_000),
            place(3, 0, 5, Side::Ask, 1_000_000, 1_000_000),
            // ...then buys it back from account 1, leaving itself flat.
            place(1, 0, 6, Side::Ask, 1_000_000, 1_000_000),
            place(3, 0, 7, Side::Bid, 1_000_000, 1_000_000),
        ];
        let run = |cmds: &[Command]| -> Engine {
            let mut e = engine_with_caps(8, 4);
            for (i, c) in cmds.iter().enumerate() {
                e.execute(seq(i as u64 + 1), c.clone()).unwrap();
            }
            e
        };
        let mut e = run(&script);
        for (a, q) in [
            (0u32, 4_500_000i64),
            (1, -2_500_000),
            (2, -2_000_000),
            (3, 0),
            (4, 0),
        ] {
            assert_eq!(
                e.risk
                    .position(AccountId::new(a), MarketId::new(0))
                    .unwrap(),
                Quantity::from_raw(q),
                "account {a} position",
            );
        }

        // Reference: the pre-#430 dense scan — probe every account in
        // ascending index order, and for each non-zero position debit
        // mark.notional(position) * rate — evaluated against live state
        // right before the epoch.
        let mark = Price::from_raw(1_000_000);
        let rate = types::Ratio::from_bps(100).unwrap(); // 1%
        let mut expected: Vec<(u32, Amount)> = Vec::new();
        for i in 0..e.risk.account_count() {
            let a = AccountId::from_index(i).unwrap();
            let q = e.risk.position(a, MarketId::new(0)).unwrap();
            let mut c = e.risk.collateral(a).unwrap();
            if q.raw() != 0 {
                let pay = mark.notional(q).unwrap().mul_ratio(rate).unwrap();
                c = c.checked_sub(pay).unwrap();
            }
            expected.push((a.get(), c));
        }

        let funding = Command::ApplyFundingEpoch(ApplyFundingEpoch {
            market: MarketId::new(0),
            epoch: 1,
            rate,
        });
        e.execute(seq(script.len() as u64 + 1), funding.clone())
            .unwrap();

        let got: Vec<(u32, Amount)> = (0..e.risk.account_count())
            .map(|i| {
                let a = AccountId::from_index(i).unwrap();
                (a.get(), e.risk.collateral(a).unwrap())
            })
            .collect();
        assert_eq!(got, expected, "funding must match the dense-scan reference");
        // Longs pay, shorts receive, the flattened and idle accounts move by
        // exactly nothing: 4.5 * 1% = 0.045; 2.5 * 1% = 0.025; 2 * 1% = 0.02.
        let collateral = |e: &Engine, a: u32| e.risk.collateral(AccountId::new(a)).unwrap().raw();
        assert_eq!(collateral(&e, 0), 100_000_000 - 45_000);
        assert_eq!(collateral(&e, 1), 100_000_000 + 25_000);
        assert_eq!(collateral(&e, 2), 100_000_000 + 20_000);
        assert_eq!(collateral(&e, 3), 100_000_000);
        assert_eq!(collateral(&e, 4), 100_000_000);
        check_invariants(&e);

        // Deterministic replay: an identical stream reproduces the root bit
        // for bit.
        let mut e2 = run(&script);
        e2.execute(seq(script.len() as u64 + 1), funding).unwrap();
        assert_eq!(e.state_root(), e2.state_root());

        // Golden root captured from the pre-#430 dense-scan implementation:
        // the reverse-index holder set must commit byte-identical state.
        // Unchanged by the #433 closed-transfer rounding fix: every payment in
        // this scenario is an exact micro-unit multiple (4.5/2.5/2.0 notional
        // at 1% has no fractional micro-unit), so ceil-for-payers equals the
        // old truncation, the residual is zero, and no insurance transfer
        // occurs — the committed bytes are identical.
        assert_eq!(
            hex::encode(e.state_root().as_bytes()),
            "9d8cc0493262dfa45301dad8a340af19148e53b9ba63437dea98bb630af61699",
        );
    }

    // #433 conservation: funding is a closed transfer. On a net-flat but
    // ASYMMETRIC book, per-account toward-zero rounding leaks dust — here the
    // old code debited the long trunc(2.25) = 2 while crediting the shorts
    // trunc(0.75) + trunc(1.5) = 0 + 1 = 1, destroying 1 micro-unit of
    // collateral per epoch. The fix debits payers with obligations rounded UP
    // (ceil(2.25) = 3), credits receivers their truncated entitlements
    // (0 + 1), and routes the non-negative residual (3 - 1 = 2) to the
    // insurance fund, so total collateral (accounts + insurance) is conserved
    // exactly. This test fails on the pre-#433 code (total drops by 1 and the
    // insurance fund stays empty).
    #[test]
    fn funding_epoch_conserves_collateral_with_insurance_residual_433() {
        // One long of 3 raw quantity units against shorts of 1 and 2, filled
        // at the mark (1.0), so pre-funding collateral is untouched. At mark
        // 1.0 the notionals are +3 / -1 / -2 micro-units; a 0.75 rate makes
        // every payment fractional: +2.25 / -0.75 / -1.5.
        let script: Vec<Command> = vec![
            create_account(100_000_000), // 0: long 3 raw
            create_account(100_000_000), // 1: short 1 raw
            create_account(100_000_000), // 2: short 2 raw
            create_perp(0, 1_000_000),
            place(0, 0, 1, Side::Bid, 1_000_000, 3),
            place(1, 0, 2, Side::Ask, 1_000_000, 1),
            place(2, 0, 3, Side::Ask, 1_000_000, 2),
        ];
        let run = |cmds: &[Command]| -> Engine {
            let mut e = engine_with_caps(8, 4);
            for (i, c) in cmds.iter().enumerate() {
                e.execute(seq(i as u64 + 1), c.clone()).unwrap();
            }
            e
        };
        let mut e = run(&script);
        let total = |e: &Engine| -> i128 {
            let mut sum = e.risk.insurance_fund().raw();
            for i in 0..e.risk.account_count() {
                let a = AccountId::from_index(i).unwrap();
                sum += e.risk.collateral(a).unwrap().raw();
            }
            sum
        };
        let before = total(&e);
        assert_eq!(before, 300_000_000);
        assert_eq!(e.risk.insurance_fund(), Amount::ZERO);

        let rate = types::Ratio::from_raw(750_000); // 0.75
        let funding = Command::ApplyFundingEpoch(ApplyFundingEpoch {
            market: MarketId::new(0),
            epoch: 1,
            rate,
        });
        e.execute(seq(script.len() as u64 + 1), funding.clone())
            .unwrap();

        // Payer: exact 2.25 rounds UP to 3 (collected). Receivers: truncated
        // entitlements 0 and 1 (distributed). Residual 3 - 1 = 2 >= 0 goes to
        // the insurance fund.
        let collateral = |e: &Engine, a: u32| e.risk.collateral(AccountId::new(a)).unwrap().raw();
        assert_eq!(collateral(&e, 0), 100_000_000 - 3);
        assert_eq!(collateral(&e, 1), 100_000_000);
        assert_eq!(collateral(&e, 2), 100_000_000 + 1);
        let collected: i128 = 3;
        let distributed: i128 = 1;
        let residual = e.risk.insurance_fund().raw();
        assert!(residual >= 0, "funding residual must be non-negative");
        assert_eq!(
            residual,
            collected - distributed,
            "insurance residual must be exactly collected - distributed",
        );
        // Exact conservation: accounts + insurance fund are unchanged in total.
        assert_eq!(
            total(&e),
            before,
            "funding must conserve total collateral (accounts + insurance)",
        );
        check_invariants(&e);

        // Deterministic replay: an identical stream reproduces the root bit
        // for bit.
        let mut e2 = run(&script);
        e2.execute(seq(script.len() as u64 + 1), funding).unwrap();
        assert_eq!(e.state_root(), e2.state_root());

        // Golden root pinned at #433 from the corrected closed-transfer
        // implementation (payers ceil, receivers trunc, residual to
        // insurance). This scenario's root DIFFERS from what the pre-#433
        // toward-zero code committed (the long's debit changed 2 -> 3): that
        // is the intended, documented bump. Any future drift in funding
        // rounding, holder order, or leaf bytes moves it.
        assert_eq!(
            hex::encode(e.state_root().as_bytes()),
            "bd242685452bf7f094658dd866e8a109354c5a118032ccafab65d2635489a6fc",
        );
    }
}

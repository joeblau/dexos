//! The single-writer deterministic execution engine.
//!
//! Integrates the stablecoin ledger, session keys, per-market order books, the
//! risk engine, and the incremental state tree. `execute` applies one sequenced
//! command and returns a receipt carrying the post-command state root. Identical
//! command streams produce identical state roots (deterministic replay).

use std::collections::{HashMap, HashSet};

use orderbook::{BookConfig, NewOrder, OrderBook, OrderOutcome};
use risk::{RiskConfig, RiskEngine};
use state_tree::{LeafWriter, StateTree};
use types::{AccountId, Amount, Hash, MarketId, MarketType, Quantity, SequenceNumber, Side};

use crate::command::{Authorization, Command, DeterministicEngine, ExecutionReceipt, ReceiptKind};
use crate::error::ExecutionError;
use crate::ledger::Ledger;
use crate::session::SessionRegistry;

/// Engine construction parameters.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Merkle capacity for accounts.
    pub account_capacity: usize,
    /// Merkle capacity for markets.
    pub market_capacity: usize,
    /// Risk parameters.
    pub risk: RiskConfig,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            account_capacity: 4096,
            market_capacity: 256,
            risk: RiskConfig {
                initial_margin: types::Ratio::from_bps(1000).unwrap_or(types::Ratio::ONE), // 10%
                maintenance_margin: types::Ratio::from_bps(500).unwrap_or(types::Ratio::ONE), // 5%
                max_leverage: types::Ratio::from_raw(20 * types::RATIO_SCALE),
            },
        }
    }
}

#[derive(Debug, Clone)]
struct MarketMeta {
    market_type: MarketType,
    outcomes: u16,
    mark_price: types::Price,
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
    books: HashMap<u32, OrderBook>,
    markets: HashMap<u32, MarketMeta>,
    positions: HashMap<(u32, u32), Quantity>,
    claims: HashMap<(u32, u32), Vec<Amount>>,
    deposits_seen: HashSet<(u32, Vec<u8>, u32)>,
    withdrawals: HashMap<u64, Withdrawal>,
    next_withdrawal_id: u64,
    protocol_version: u16,
    wallets: HashMap<u32, WalletBinding>,
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
            positions: HashMap::new(),
            claims: HashMap::new(),
            deposits_seen: HashSet::new(),
            withdrawals: HashMap::new(),
            next_withdrawal_id: 0,
            protocol_version: 1,
            wallets: HashMap::new(),
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

    /// Number of orders currently resting in `market`'s book, or `None` if the
    /// market is unknown. Used to observe that liquidation cancelled an account's
    /// resting orders.
    pub fn market_resting_len(&self, market: MarketId) -> Option<usize> {
        self.books.get(&market.get()).map(OrderBook::resting_len)
    }

    fn position(&self, account: AccountId, market: MarketId) -> Quantity {
        self.positions
            .get(&(account.get(), market.get()))
            .copied()
            .unwrap_or(Quantity::ZERO)
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
        // Open positions, ascending by market; flats omitted.
        let mut positions: Vec<(u32, i64)> = Vec::new();
        for (&(a, m), qty) in &self.positions {
            if a == account.get() && qty.raw() != 0 {
                positions.push((m, qty.raw()));
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
        Ok(w.finish())
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
        let book_root = self
            .books
            .get(&market.get())
            .map(|b| b.state_root())
            .unwrap_or(Hash::ZERO);
        let type_tag: u32 = match meta.market_type {
            MarketType::Perpetual => 0,
            MarketType::BinaryPrediction => 1,
            MarketType::MultiOutcomePrediction => 2,
            MarketType::Decision => 3,
            MarketType::Sports => 4,
            MarketType::Scalar => 5,
            MarketType::CustomPayoutVector => 6,
        };
        Ok(LeafWriter::new()
            .field_u32(type_tag)
            .field_u32(u32::from(meta.outcomes))
            .field_i64(meta.mark_price.raw())
            .field_bytes(book_root.as_bytes())
            .finish())
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
        result: &orderbook::MatchResult,
    ) -> Result<Vec<AccountId>, ExecutionError> {
        let mut touched = Vec::new();
        for fill in &result.fills {
            let taker_signed = Self::signed(fill.taker_side, fill.quantity)?;
            let maker_signed = Self::signed(fill.taker_side.opposite(), fill.quantity)?;
            self.risk
                .apply_fill(fill.taker_account, market, taker_signed, fill.price)?;
            self.risk
                .apply_fill(fill.maker_account, market, maker_signed, fill.price)?;
            self.bump_position(fill.taker_account, market, taker_signed)?;
            self.bump_position(fill.maker_account, market, maker_signed)?;
            touched.push(fill.taker_account);
            touched.push(fill.maker_account);
        }
        touched.sort_by_key(|a| a.get());
        touched.dedup();
        Ok(touched)
    }

    fn bump_position(
        &mut self,
        account: AccountId,
        market: MarketId,
        delta: Quantity,
    ) -> Result<(), ExecutionError> {
        let entry = self
            .positions
            .entry((account.get(), market.get()))
            .or_insert(Quantity::ZERO);
        *entry = entry.checked_add(delta)?;
        Ok(())
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
                self.ledger.reserve(c.account, c.amount)?;
                self.risk.debit_collateral(c.account, c.amount)?;
                let id = self.next_withdrawal_id;
                self.next_withdrawal_id = self.next_withdrawal_id.wrapping_add(1);
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
                self.markets.insert(
                    c.market.get(),
                    MarketMeta {
                        market_type: c.market_type,
                        outcomes: c.outcomes,
                        mark_price: c.mark_price,
                    },
                );
                self.books
                    .insert(c.market.get(), OrderBook::new(BookConfig::default()));
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
                let meta = self
                    .markets
                    .get(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?
                    .clone();
                let notional = if c.price.raw() > 0 {
                    c.price.notional(c.quantity)?
                } else {
                    meta.mark_price.notional(c.quantity)?
                };
                // Authenticate before any business logic so a rejected order
                // leaves no state behind.
                self.authorize(c.account, c.market, notional, &c.auth)?;
                self.risk
                    .check_order_in_market(c.account, c.market, notional, c.reduce_only)?;
                let pos = self.position(c.account, c.market);
                let book = self
                    .books
                    .get_mut(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?;
                book.set_position(c.account, pos);
                let result = book.submit(NewOrder {
                    order_id: c.order_id,
                    account: c.account,
                    side: c.side,
                    order_type: c.order_type,
                    tif: c.tif,
                    price: c.price,
                    quantity: c.quantity,
                    client_id: c.client_id,
                    reduce_only: c.reduce_only,
                })?;
                let filled = result.filled_quantity();
                let rested = matches!(
                    result.outcome,
                    OrderOutcome::Resting { .. } | OrderOutcome::PartiallyFilledResting { .. }
                );
                let touched = self.apply_fills(c.market, &result)?;
                for a in touched {
                    self.commit_account(a)?;
                }
                self.commit_market(c.market)?;
                Ok(self.receipt(seq, ReceiptKind::OrderApplied { filled, rested }))
            }
            Command::CancelOrder(c) => {
                let owner = self
                    .books
                    .get(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?
                    .owner(c.order_id);
                // Defense in depth: a caller may only cancel its own resting
                // orders.
                if matches!(owner, Some(o) if o != c.account) {
                    return Err(ExecutionError::OrderNotOwned);
                }
                // Cancellation carries no notional, but still requires an
                // in-scope, unexpired, non-replayed session (or the master key).
                self.authorize(c.account, c.market, Amount::ZERO, &c.auth)?;
                let book = self
                    .books
                    .get_mut(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?;
                let count = match book.cancel(c.order_id) {
                    Ok(()) => 1,
                    Err(orderbook::OrderError::UnknownOrder) => 0,
                    Err(e) => return Err(e.into()),
                };
                self.commit_market(c.market)?;
                Ok(self.receipt(seq, ReceiptKind::Cancelled(count)))
            }
            Command::CancelAll(c) => {
                // Ensure the market exists before authorizing.
                if !self.books.contains_key(&c.market.get()) {
                    return Err(ExecutionError::UnknownMarket);
                }
                self.authorize(c.account, c.market, Amount::ZERO, &c.auth)?;
                let book = self
                    .books
                    .get_mut(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?;
                let count = book.cancel_all(c.account);
                self.commit_market(c.market)?;
                Ok(self.receipt(seq, ReceiptKind::Cancelled(count)))
            }
            Command::ReplaceOrder(c) => {
                let owner = self
                    .books
                    .get(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?
                    .owner(c.order_id);
                // Defense in depth: a caller may only replace its own resting
                // orders.
                if matches!(owner, Some(o) if o != c.account) {
                    return Err(ExecutionError::OrderNotOwned);
                }
                // A replace re-establishes an order, so it is bounded by the
                // session's per-order notional cap like a fresh placement.
                let notional = c.price.notional(c.quantity)?;
                self.authorize(c.account, c.market, notional, &c.auth)?;
                let book = self
                    .books
                    .get_mut(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?;
                let result = book.replace(c.order_id, c.price, c.quantity)?;
                let touched = self.apply_fills(c.market, &result)?;
                for a in touched {
                    self.commit_account(a)?;
                }
                self.commit_market(c.market)?;
                let filled = result.filled_quantity();
                let rested = matches!(
                    result.outcome,
                    OrderOutcome::Resting { .. } | OrderOutcome::PartiallyFilledResting { .. }
                );
                Ok(self.receipt(seq, ReceiptKind::OrderApplied { filled, rested }))
            }
            Command::MintCompleteSet(c) => {
                let meta = self
                    .markets
                    .get(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?;
                let outcomes = usize::from(meta.outcomes.max(2));
                self.ledger.lock(c.account, c.count)?;
                let entry = self
                    .claims
                    .entry((c.account.get(), c.market.get()))
                    .or_insert_with(|| vec![Amount::ZERO; outcomes]);
                for v in entry.iter_mut() {
                    *v = v.checked_add(c.count)?;
                }
                self.commit_account(c.account)?;
                Ok(self.receipt(seq, ReceiptKind::CompleteSet(c.count)))
            }
            Command::RedeemCompleteSet(c) => {
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
                // all markets, so a dead account leaves nothing on the books.
                let market_ids: Vec<u32> = {
                    let mut ids: Vec<u32> = self.books.keys().copied().collect();
                    ids.sort_unstable();
                    ids
                };
                for m in &market_ids {
                    if let Some(book) = self.books.get_mut(m) {
                        book.cancel_all(c.account);
                    }
                }
                // Phases 2-4: auto-deleverage, insurance draw, and socialization
                // are settled by the risk engine.
                let outcome = self.risk.liquidate(c.account)?;
                // Reconcile the external position mirror for every account the
                // pipeline touched (the victim plus each ADL counterparty).
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
                for a in &affected {
                    for m in &market_ids {
                        let market = MarketId::new(*m);
                        let qty = self.risk.position(*a, market).unwrap_or(Quantity::ZERO);
                        let key = (a.get(), *m);
                        if qty.raw() == 0 {
                            self.positions.remove(&key);
                        } else {
                            self.positions.insert(key, qty);
                        }
                    }
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
        let receipt = txn.apply(seq, command)?;
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
        let mut positions: Vec<(u32, u32, i64)> = e
            .positions
            .iter()
            .map(|(&(a, m), q)| (a, m, q.raw()))
            .collect();
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
        w.field_i64(i64::from_le_bytes(e.next_withdrawal_id.to_le_bytes()));
        w.field_u32(u32::from(e.protocol_version));
        let mut markets: Vec<(u32, u16, i64, usize)> = e
            .markets
            .iter()
            .map(|(&m, meta)| {
                (
                    m,
                    meta.outcomes,
                    meta.mark_price.raw(),
                    e.books.get(&m).map(OrderBook::resting_len).unwrap_or(0),
                )
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

        // The external position mirror equals the risk engine's own positions.
        for (&(a, m), qty) in &e.positions {
            let risk_qty = e
                .risk
                .position(AccountId::new(a), MarketId::new(m))
                .unwrap_or(Quantity::ZERO);
            assert_eq!(
                risk_qty.raw(),
                qty.raw(),
                "position mirror mismatch for account {a} market {m}",
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
        assert!(!e.books.contains_key(&1));
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
        assert!(e.positions.is_empty(), "partial fill leaked a position");
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
    fn random_command(rng: &mut Lcg, tx_counter: &mut u64) -> Command {
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
            2 => Command::RequestWithdrawal(RequestWithdrawal {
                account: AccountId::new(account),
                amount: Amount::from_raw(i128::from(rng.range(0, 5_000_000))),
                nonce: 1,
                destination_chain: 1,
                destination_address: vec![1],
                auth: Authorization::Master,
            }),
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
            6..=8 => place(account, market, order_id, side, price, qty),
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
        check_invariants(&e);
        let mut ok = 0u32;
        let mut err = 0u32;
        for n in 1..=1_500u64 {
            let cmd = random_command(&mut rng, &mut tx_counter);
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
}

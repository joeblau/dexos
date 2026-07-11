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

use crate::command::{Command, DeterministicEngine, ExecutionReceipt, ReceiptKind};
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

/// The deterministic exchange engine.
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
        }
    }

    /// Read-only ledger access.
    pub fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    /// Read-only risk access.
    pub fn risk(&self) -> &RiskEngine {
        &self.risk
    }

    fn position(&self, account: AccountId, market: MarketId) -> Quantity {
        self.positions
            .get(&(account.get(), market.get()))
            .copied()
            .unwrap_or(Quantity::ZERO)
    }

    fn commit_account(&mut self, account: AccountId) -> Result<(), ExecutionError> {
        let leaf = self.ledger.account_leaf(account)?;
        self.tree.set_account(account, &leaf)?;
        Ok(())
    }

    fn commit_market(&mut self, market: MarketId) -> Result<(), ExecutionError> {
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
        let leaf = LeafWriter::new()
            .field_u32(type_tag)
            .field_u32(u32::from(meta.outcomes))
            .field_i64(meta.mark_price.raw())
            .field_bytes(book_root.as_bytes())
            .finish();
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
}

impl DeterministicEngine for Engine {
    fn execute(
        &mut self,
        sequence: SequenceNumber,
        command: Command,
    ) -> Result<ExecutionReceipt, ExecutionError> {
        let seq = sequence.get();
        match command {
            Command::CreateAccount(c) => {
                let id = self.ledger.create_account(c.initial_collateral)?;
                self.risk.open_account(id, c.initial_collateral)?;
                self.commit_account(id)?;
                Ok(self.receipt(seq, ReceiptKind::AccountCreated(id)))
            }
            Command::BindWallet(_c) => Ok(self.receipt(seq, ReceiptKind::WalletBound)),
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
                let book = self
                    .books
                    .get_mut(&c.market.get())
                    .ok_or(ExecutionError::UnknownMarket)?;
                let count = book.cancel_all(c.account);
                self.commit_market(c.market)?;
                Ok(self.receipt(seq, ReceiptKind::Cancelled(count)))
            }
            Command::ReplaceOrder(c) => {
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
        }
    }

    fn state_root(&self) -> Hash {
        self.tree.root()
    }
}

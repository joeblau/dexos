//! An in-memory [`RpcBackend`] for tests and local development.
//!
//! It is deterministic, enforces page bounds, dedupes commands by
//! `(client_id, nonce)` for exactly-once semantics, validates sessions, and can
//! simulate ingress backpressure. It maintains a real account Merkle tree so
//! [`RpcBackend::get_account_proof`] returns verifiable proofs.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use crypto::MerkleTree;
use types::{AccountId, Amount, Hash, MarketId, OrderId, Price, Quantity, SequenceNumber, Side};

use crate::backend::RpcBackend;
use crate::command::{
    AuthorizeSessionParams, BasketParams, BindWalletParams, CancelAllParams, CancelOrderParams,
    Command, CommandAck, ControlMeta, CreateMarketParams, ReplaceOrderParams,
    RequestWithdrawalParams, RevokeSessionParams, StakeMarketParams, SubmitOrderParams,
};
use crate::error::RpcError;
use crate::session::Session;
use crate::wire::{
    Account, AccountProof, Book, Checkpoint, DepositStatus, ExecutionReceipt, FinalityStatus,
    MarketDetail, MarketStatus, MarketSummary, NetworkStatus, NodeInfo, OracleStatus, Order,
    PageParams, PeerInfo, Position, RpcMode, Trade, VerificationStatus, WithdrawalStatus,
};

/// Registration of a session key bound to an account.
struct BoundSession {
    account: AccountId,
    session: Session,
}

struct Inner {
    node: NodeInfo,
    peers: Vec<PeerInfo>,
    markets: HashMap<MarketId, MarketDetail>,
    books: HashMap<MarketId, Book>,
    trades: HashMap<MarketId, Vec<Trade>>,
    market_status: HashMap<MarketId, MarketStatus>,
    oracle_status: HashMap<MarketId, OracleStatus>,
    checkpoints: HashMap<u64, Checkpoint>,
    latest_height: u64,
    accounts: HashMap<AccountId, Account>,
    positions: HashMap<(AccountId, MarketId), Position>,
    orders: HashMap<AccountId, Vec<Order>>,
    receipts: HashMap<Hash, ExecutionReceipt>,
    deposits: HashMap<Hash, DepositStatus>,
    withdrawals: HashMap<Hash, WithdrawalStatus>,
    network: NetworkStatus,
    sessions: HashMap<[u8; 32], BoundSession>,
    seen: HashMap<(u64, u64), CommandAck>,
    tree: MerkleTree,
    now: u64,
    next_order: u64,
    page_limit: u32,
    saturated: bool,
}

/// A configurable in-memory backend. Cheap to `clone` semantics are not needed;
/// wrap in an `Arc` to share across the async server.
pub struct StubBackend {
    inner: Mutex<Inner>,
}

impl StubBackend {
    /// A fresh backend in the given mode with a default page limit of 100 and an
    /// account tree sized for 1024 leaves.
    pub fn new(mode: RpcMode) -> Self {
        let node = NodeInfo {
            node_id: [0u8; 32],
            chain_id: 1,
            protocol_version: 1,
            mode,
            height: 0,
        };
        let network = NetworkStatus {
            peer_count: 0,
            height: 0,
            finalized_height: 0,
            syncing: false,
        };
        StubBackend {
            inner: Mutex::new(Inner {
                node,
                peers: Vec::new(),
                markets: HashMap::new(),
                books: HashMap::new(),
                trades: HashMap::new(),
                market_status: HashMap::new(),
                oracle_status: HashMap::new(),
                checkpoints: HashMap::new(),
                latest_height: 0,
                accounts: HashMap::new(),
                positions: HashMap::new(),
                orders: HashMap::new(),
                receipts: HashMap::new(),
                deposits: HashMap::new(),
                withdrawals: HashMap::new(),
                network,
                sessions: HashMap::new(),
                seen: HashMap::new(),
                tree: MerkleTree::new(1024),
                now: 0,
                next_order: 1,
                page_limit: 100,
                saturated: false,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Set the configured maximum page size for list queries.
    pub fn set_page_limit(&self, limit: u32) {
        self.lock().page_limit = limit.max(1);
    }

    /// Set the simulated wall-clock (unix millis) used for session expiry checks.
    pub fn set_now(&self, now: u64) {
        self.lock().now = now;
    }

    /// Toggle ingress saturation: while set, every control method returns
    /// [`RpcError::Backpressure`].
    pub fn set_saturated(&self, saturated: bool) {
        self.lock().saturated = saturated;
    }

    /// Insert / overwrite a market's metadata.
    pub fn insert_market(&self, detail: MarketDetail) {
        let mut g = self.lock();
        g.markets.insert(detail.summary.market_id, detail);
    }

    /// Insert / overwrite an order book.
    pub fn insert_book(&self, book: Book) {
        let mut g = self.lock();
        g.books.insert(book.market_id, book);
    }

    /// Insert / overwrite market status.
    pub fn insert_market_status(&self, status: MarketStatus) {
        let mut g = self.lock();
        g.market_status.insert(status.market_id, status);
    }

    /// Insert / overwrite oracle status.
    pub fn insert_oracle_status(&self, status: OracleStatus) {
        let mut g = self.lock();
        g.oracle_status.insert(status.market_id, status);
    }

    /// Append a trade print to a market's tape.
    pub fn push_trade(&self, trade: Trade) {
        let mut g = self.lock();
        g.trades.entry(trade.market_id).or_default().push(trade);
    }

    /// Insert / overwrite an account and commit its leaf to the account tree.
    pub fn insert_account(&self, account: Account) -> Result<(), RpcError> {
        let mut g = self.lock();
        let index = account
            .account_id
            .index()
            .map_err(|_| RpcError::InvalidRequest("account id out of range".into()))?;
        let leaf = account_leaf(&account);
        g.tree
            .set(index, leaf)
            .map_err(|_| RpcError::InvalidRequest("account index exceeds tree".into()))?;
        g.accounts.insert(account.account_id, account);
        Ok(())
    }

    /// Insert / overwrite a position.
    pub fn insert_position(&self, position: Position) {
        let mut g = self.lock();
        g.positions
            .insert((position.account_id, position.market_id), position);
    }

    /// Append an order to an account's list.
    pub fn push_order(&self, order: Order) {
        let mut g = self.lock();
        g.orders.entry(order.account_id).or_default().push(order);
    }

    /// Insert / overwrite an execution receipt.
    pub fn insert_receipt(&self, receipt: ExecutionReceipt) {
        let mut g = self.lock();
        g.receipts.insert(receipt.command_hash, receipt);
    }

    /// Insert / overwrite a deposit status.
    pub fn insert_deposit(&self, status: DepositStatus) {
        let mut g = self.lock();
        g.deposits.insert(status.tx_hash, status);
    }

    /// Insert / overwrite a withdrawal status.
    pub fn insert_withdrawal(&self, status: WithdrawalStatus) {
        let mut g = self.lock();
        g.withdrawals.insert(status.request_hash, status);
    }

    /// Register a session key bound to an account with a validated scope.
    pub fn register_session(&self, account: AccountId, session: Session) {
        let mut g = self.lock();
        g.sessions
            .insert(session.session_pubkey, BoundSession { account, session });
    }

    /// The current account-tree root, i.e. the latest checkpoint state root.
    pub fn state_root(&self) -> Hash {
        self.lock().tree.root()
    }

    /// Publish a checkpoint at the current tree root and mark it latest.
    pub fn commit_checkpoint(&self, height: u64, timestamp: u64) {
        let mut g = self.lock();
        let root = g.tree.root();
        let prev = g
            .checkpoints
            .get(&g.latest_height)
            .map_or(Hash::ZERO, |c| c.new_state_root);
        let cp = Checkpoint {
            height,
            new_state_root: root,
            prev_state_root: prev,
            timestamp,
            quorum_certificate: None,
        };
        g.checkpoints.insert(height, cp);
        g.latest_height = height;
        g.node.height = height;
    }
}

fn account_leaf(account: &Account) -> Hash {
    let encoded = codec::encode(account).unwrap_or_default();
    crypto::hash_domain(crypto::DOMAIN_ACCOUNT, &encoded)
}

fn command_hash(command: &Command) -> Hash {
    let encoded = codec::encode(command).unwrap_or_default();
    crypto::hash_domain(crypto::DOMAIN_COMMAND, &encoded)
}

fn clamp_page<T: Clone>(items: &[T], page: PageParams, limit: u32) -> Vec<T> {
    let effective = page.limit.min(limit);
    let start = usize::try_from(page.offset).unwrap_or(usize::MAX);
    let take = usize::try_from(effective).unwrap_or(0);
    items.iter().skip(start).take(take).cloned().collect()
}

impl StubBackend {
    /// Common control path: validate the session (if delegated), dedupe by
    /// `(client_id, nonce)`, and produce an ack. `order_id`/`market_id` decorate
    /// the ack when relevant.
    fn ingest(
        &self,
        meta: &ControlMeta,
        command: Command,
        order_id: Option<OrderId>,
        market_id: Option<MarketId>,
    ) -> Result<CommandAck, RpcError> {
        let mut g = self.lock();
        if g.saturated {
            return Err(RpcError::Backpressure);
        }
        // Exactly-once: a repeated (client_id, nonce) returns the stored ack.
        if let Some(existing) = g.seen.get(&(meta.client_id, meta.nonce)) {
            return Ok(existing.clone());
        }
        // Delegated session validation.
        if let Some(pk) = meta.session_pubkey {
            let now = g.now;
            let bound = g.sessions.get(&pk).ok_or(RpcError::Unauthorized)?;
            // A session is bound to exactly one account; reject commands that
            // act on any other account.
            if let Some(account) = command.account() {
                if account != bound.account {
                    return Err(RpcError::Unauthorized);
                }
            }
            bound.session.authorize(&command, now)?;
        }
        let ack = CommandAck {
            command_hash: command_hash(&command),
            finality: FinalityStatus::Accepted,
            order_id,
            market_id,
        };
        g.seen.insert((meta.client_id, meta.nonce), ack.clone());
        Ok(ack)
    }
}

impl RpcBackend for StubBackend {
    fn get_node_info(&self) -> Result<NodeInfo, RpcError> {
        Ok(self.lock().node.clone())
    }

    fn get_peers(&self) -> Result<Vec<PeerInfo>, RpcError> {
        Ok(self.lock().peers.clone())
    }

    fn get_markets(&self, page: PageParams) -> Result<Vec<MarketSummary>, RpcError> {
        let g = self.lock();
        let mut all: Vec<MarketSummary> = g.markets.values().map(|m| m.summary).collect();
        all.sort_by_key(|s| s.market_id.get());
        Ok(clamp_page(&all, page, g.page_limit))
    }

    fn get_market(&self, market: MarketId) -> Result<MarketDetail, RpcError> {
        self.lock()
            .markets
            .get(&market)
            .cloned()
            .ok_or(RpcError::NotFound)
    }

    fn get_market_book(&self, market: MarketId, depth: u32) -> Result<Book, RpcError> {
        let g = self.lock();
        let mut book = g.books.get(&market).cloned().ok_or(RpcError::NotFound)?;
        let d = usize::try_from(depth).unwrap_or(usize::MAX);
        book.bids.truncate(d);
        book.asks.truncate(d);
        Ok(book)
    }

    fn get_market_trades(
        &self,
        market: MarketId,
        page: PageParams,
    ) -> Result<Vec<Trade>, RpcError> {
        let g = self.lock();
        let all = g.trades.get(&market).ok_or(RpcError::NotFound)?;
        Ok(clamp_page(all, page, g.page_limit))
    }

    fn get_market_status(&self, market: MarketId) -> Result<MarketStatus, RpcError> {
        self.lock()
            .market_status
            .get(&market)
            .copied()
            .ok_or(RpcError::NotFound)
    }

    fn get_oracle_status(&self, market: MarketId) -> Result<OracleStatus, RpcError> {
        self.lock()
            .oracle_status
            .get(&market)
            .copied()
            .ok_or(RpcError::NotFound)
    }

    fn get_checkpoint(&self, height: u64) -> Result<Checkpoint, RpcError> {
        self.lock()
            .checkpoints
            .get(&height)
            .cloned()
            .ok_or(RpcError::NotFound)
    }

    fn get_latest_checkpoint(&self) -> Result<Checkpoint, RpcError> {
        let g = self.lock();
        g.checkpoints
            .get(&g.latest_height)
            .cloned()
            .ok_or(RpcError::NotFound)
    }

    fn get_account(&self, account: AccountId) -> Result<Account, RpcError> {
        self.lock()
            .accounts
            .get(&account)
            .copied()
            .ok_or(RpcError::NotFound)
    }

    fn get_account_proof(&self, account: AccountId) -> Result<AccountProof, RpcError> {
        let g = self.lock();
        let acct = g
            .accounts
            .get(&account)
            .copied()
            .ok_or(RpcError::NotFound)?;
        let index = account
            .index()
            .map_err(|_| RpcError::InvalidRequest("account id out of range".into()))?;
        let siblings = g.tree.proof(index).map_err(|_| RpcError::NotFound)?;
        let leaf = account_leaf(&acct);
        let state_root = g.tree.root();
        let leaf_index =
            u64::try_from(index).map_err(|_| RpcError::Internal("index overflow".into()))?;
        let mut proof = AccountProof {
            account_id: account,
            leaf,
            leaf_index,
            siblings,
            checkpoint_height: g.latest_height,
            state_root,
            verification_status: VerificationStatus::Unverified,
        };
        proof.verification_status = proof.verify_against(state_root);
        Ok(proof)
    }

    fn get_position(&self, account: AccountId, market: MarketId) -> Result<Position, RpcError> {
        self.lock()
            .positions
            .get(&(account, market))
            .copied()
            .ok_or(RpcError::NotFound)
    }

    fn get_orders(&self, account: AccountId, page: PageParams) -> Result<Vec<Order>, RpcError> {
        let g = self.lock();
        let all = g.orders.get(&account).ok_or(RpcError::NotFound)?;
        Ok(clamp_page(all, page, g.page_limit))
    }

    fn get_execution_receipt(&self, command_hash: Hash) -> Result<ExecutionReceipt, RpcError> {
        self.lock()
            .receipts
            .get(&command_hash)
            .cloned()
            .ok_or(RpcError::NotFound)
    }

    fn get_deposit_status(&self, tx_hash: Hash) -> Result<DepositStatus, RpcError> {
        self.lock()
            .deposits
            .get(&tx_hash)
            .copied()
            .ok_or(RpcError::NotFound)
    }

    fn get_withdrawal_status(&self, request_hash: Hash) -> Result<WithdrawalStatus, RpcError> {
        self.lock()
            .withdrawals
            .get(&request_hash)
            .copied()
            .ok_or(RpcError::NotFound)
    }

    fn get_network_status(&self) -> Result<NetworkStatus, RpcError> {
        Ok(self.lock().network)
    }

    fn submit_order(
        &self,
        meta: &ControlMeta,
        params: &SubmitOrderParams,
    ) -> Result<CommandAck, RpcError> {
        let order_id = {
            let mut g = self.lock();
            let id = g.next_order;
            g.next_order = g.next_order.saturating_add(1);
            OrderId::new(id)
        };
        self.ingest(
            meta,
            params.to_command(),
            Some(order_id),
            Some(params.market),
        )
    }

    fn cancel_order(
        &self,
        meta: &ControlMeta,
        params: &CancelOrderParams,
    ) -> Result<CommandAck, RpcError> {
        self.ingest(
            meta,
            params.to_command(),
            Some(params.order_id),
            Some(params.market),
        )
    }

    fn cancel_all(
        &self,
        meta: &ControlMeta,
        params: &CancelAllParams,
    ) -> Result<CommandAck, RpcError> {
        self.ingest(meta, params.to_command(), None, params.market)
    }

    fn replace_order(
        &self,
        meta: &ControlMeta,
        params: &ReplaceOrderParams,
    ) -> Result<CommandAck, RpcError> {
        self.ingest(
            meta,
            params.to_command(),
            Some(params.order_id),
            Some(params.market),
        )
    }

    fn submit_basket(
        &self,
        meta: &ControlMeta,
        params: &BasketParams,
    ) -> Result<CommandAck, RpcError> {
        self.ingest(meta, params.to_command(), None, None)
    }

    fn authorize_session(
        &self,
        meta: &ControlMeta,
        params: &AuthorizeSessionParams,
    ) -> Result<CommandAck, RpcError> {
        self.ingest(meta, params.to_command(), None, None)
    }

    fn revoke_session(
        &self,
        meta: &ControlMeta,
        params: &RevokeSessionParams,
    ) -> Result<CommandAck, RpcError> {
        self.ingest(meta, params.to_command(), None, None)
    }

    fn bind_wallet(
        &self,
        meta: &ControlMeta,
        params: &BindWalletParams,
    ) -> Result<CommandAck, RpcError> {
        self.ingest(meta, params.to_command(), None, None)
    }

    fn request_withdrawal(
        &self,
        meta: &ControlMeta,
        params: &RequestWithdrawalParams,
    ) -> Result<CommandAck, RpcError> {
        self.ingest(meta, params.to_command(), None, None)
    }

    fn create_market(
        &self,
        meta: &ControlMeta,
        params: &CreateMarketParams,
    ) -> Result<CommandAck, RpcError> {
        self.ingest(meta, params.to_command(), None, None)
    }

    fn stake_market(
        &self,
        meta: &ControlMeta,
        params: &StakeMarketParams,
    ) -> Result<CommandAck, RpcError> {
        self.ingest(meta, params.to_command(), None, Some(params.market))
    }
}

/// Build a minimal well-formed account for fixtures.
pub fn fixture_account(id: u32, balance: Amount) -> Account {
    Account {
        account_id: AccountId::new(id),
        balance,
        equity: balance,
        nonce: 0,
    }
}

/// Build a minimal one-level book for fixtures.
pub fn fixture_book(market: MarketId, bid: Price, ask: Price, qty: Quantity) -> Book {
    use crate::wire::BookLevel;
    Book {
        market_id: market,
        sequence: SequenceNumber::new(1),
        bids: vec![BookLevel {
            price: bid,
            quantity: qty,
        }],
        asks: vec![BookLevel {
            price: ask,
            quantity: qty,
        }],
    }
}

/// Build a fixture position.
pub fn fixture_position(account: u32, market: u32, size: Quantity) -> Position {
    Position {
        account_id: AccountId::new(account),
        market_id: MarketId::new(market),
        size,
        side: Side::Bid,
        entry_price: Price::ONE,
        unrealized_pnl: Amount::ZERO,
    }
}

/// The set of seen `(client_id, nonce)` pairs — exposed for idempotency tests.
impl StubBackend {
    /// Number of distinct commands ingested (deduped by client_id + nonce).
    pub fn ingested_count(&self) -> usize {
        self.lock().seen.len()
    }

    /// The set of seen idempotency keys.
    pub fn seen_keys(&self) -> HashSet<(u64, u64)> {
        self.lock().seen.keys().copied().collect()
    }
}

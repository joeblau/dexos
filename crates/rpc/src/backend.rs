//! The [`RpcBackend`] trait the node implements over the live engine, plus the
//! pure [`dispatch`] router that maps a decoded request to a backend call and
//! enforces read-only / light mode.

use types::{AccountId, Hash, MarketId};

use crate::command::{
    AuthorizeSessionParams, BasketParams, BindWalletParams, CancelAllParams, CancelOrderParams,
    CommandAck, ControlMeta, CreateMarketParams, ReplaceOrderParams, RequestWithdrawalParams,
    RevokeSessionParams, StakeMarketParams, SubmitOrderParams,
};
use crate::error::RpcError;
use crate::request::{RpcMethod, RpcRequest};
use crate::response::{RpcOk, RpcResponse};
use crate::wire::{
    Account, AccountProof, Book, Checkpoint, DepositStatus, ExecutionReceipt, MarketDetail,
    MarketStatus, MarketSummary, NetworkStatus, NodeInfo, OracleStatus, Order, PageParams,
    PeerInfo, Position, Trade, WithdrawalStatus,
};

/// The backend the node implements over its live engine. Object-safe: all
/// methods are synchronous with concrete parameters and returns, so a
/// `&dyn RpcBackend` can be dispatched over.
///
/// Query methods return typed values or [`RpcError::NotFound`]. Control methods
/// return a [`CommandAck`]; the backend is responsible for idempotency keyed on
/// the `(client_id, nonce)` in [`ControlMeta`] and for session validation.
pub trait RpcBackend: Send + Sync {
    // ---- queries ----
    /// Node identity and status.
    fn get_node_info(&self) -> Result<NodeInfo, RpcError>;
    /// Connected peers.
    fn get_peers(&self) -> Result<Vec<PeerInfo>, RpcError>;
    /// List markets (server clamps `page.limit`).
    fn get_markets(&self, page: PageParams) -> Result<Vec<MarketSummary>, RpcError>;
    /// One market's metadata.
    fn get_market(&self, market: MarketId) -> Result<MarketDetail, RpcError>;
    /// One market's order book to `depth` levels.
    fn get_market_book(&self, market: MarketId, depth: u32) -> Result<Book, RpcError>;
    /// Recent trades (server clamps `page.limit`).
    fn get_market_trades(&self, market: MarketId, page: PageParams)
        -> Result<Vec<Trade>, RpcError>;
    /// Live status for a market.
    fn get_market_status(&self, market: MarketId) -> Result<MarketStatus, RpcError>;
    /// Oracle status for a market.
    fn get_oracle_status(&self, market: MarketId) -> Result<OracleStatus, RpcError>;
    /// A checkpoint by height.
    fn get_checkpoint(&self, height: u64) -> Result<Checkpoint, RpcError>;
    /// The latest checkpoint.
    fn get_latest_checkpoint(&self) -> Result<Checkpoint, RpcError>;
    /// An account's state.
    fn get_account(&self, account: AccountId) -> Result<Account, RpcError>;
    /// A Merkle proof for an account. The response's `verification_status` must
    /// be populated.
    fn get_account_proof(&self, account: AccountId) -> Result<AccountProof, RpcError>;
    /// A position by account and market.
    fn get_position(&self, account: AccountId, market: MarketId) -> Result<Position, RpcError>;
    /// Orders for an account (server clamps `page.limit`).
    fn get_orders(&self, account: AccountId, page: PageParams) -> Result<Vec<Order>, RpcError>;
    /// An execution receipt by command hash.
    fn get_execution_receipt(&self, command_hash: Hash) -> Result<ExecutionReceipt, RpcError>;
    /// A deposit's status by tx hash.
    fn get_deposit_status(&self, tx_hash: Hash) -> Result<DepositStatus, RpcError>;
    /// A withdrawal's status by request hash.
    fn get_withdrawal_status(&self, request_hash: Hash) -> Result<WithdrawalStatus, RpcError>;
    /// Network / sync status.
    fn get_network_status(&self) -> Result<NetworkStatus, RpcError>;

    // ---- control ----
    /// Submit a new order.
    fn submit_order(
        &self,
        meta: &ControlMeta,
        params: &SubmitOrderParams,
    ) -> Result<CommandAck, RpcError>;
    /// Cancel an order.
    fn cancel_order(
        &self,
        meta: &ControlMeta,
        params: &CancelOrderParams,
    ) -> Result<CommandAck, RpcError>;
    /// Cancel all orders.
    fn cancel_all(
        &self,
        meta: &ControlMeta,
        params: &CancelAllParams,
    ) -> Result<CommandAck, RpcError>;
    /// Replace an order.
    fn replace_order(
        &self,
        meta: &ControlMeta,
        params: &ReplaceOrderParams,
    ) -> Result<CommandAck, RpcError>;
    /// Submit a basket.
    fn submit_basket(
        &self,
        meta: &ControlMeta,
        params: &BasketParams,
    ) -> Result<CommandAck, RpcError>;
    /// Authorize a session.
    fn authorize_session(
        &self,
        meta: &ControlMeta,
        params: &AuthorizeSessionParams,
    ) -> Result<CommandAck, RpcError>;
    /// Revoke a session.
    fn revoke_session(
        &self,
        meta: &ControlMeta,
        params: &RevokeSessionParams,
    ) -> Result<CommandAck, RpcError>;
    /// Bind a wallet.
    fn bind_wallet(
        &self,
        meta: &ControlMeta,
        params: &BindWalletParams,
    ) -> Result<CommandAck, RpcError>;
    /// Request a withdrawal.
    fn request_withdrawal(
        &self,
        meta: &ControlMeta,
        params: &RequestWithdrawalParams,
    ) -> Result<CommandAck, RpcError>;
    /// Create a market.
    fn create_market(
        &self,
        meta: &ControlMeta,
        params: &CreateMarketParams,
    ) -> Result<CommandAck, RpcError>;
    /// Stake a market.
    fn stake_market(
        &self,
        meta: &ControlMeta,
        params: &StakeMarketParams,
    ) -> Result<CommandAck, RpcError>;
}

use crate::wire::RpcMode;

/// Route a decoded request to the backend, echoing its `request_id`. Control
/// methods are rejected with [`RpcError::ReadOnly`] unless `mode` allows writes.
/// This function is pure and never panics.
pub fn dispatch(backend: &dyn RpcBackend, mode: RpcMode, request: RpcRequest) -> RpcResponse {
    let result = route(backend, mode, request.method);
    RpcResponse::new(request.request_id, result)
}

fn route(backend: &dyn RpcBackend, mode: RpcMode, method: RpcMethod) -> Result<RpcOk, RpcError> {
    // Reject writes up front on read-only / light nodes.
    if method.is_control() && !mode.allows_writes() {
        return Err(RpcError::ReadOnly);
    }
    match method {
        RpcMethod::GetNodeInfo => backend.get_node_info().map(RpcOk::NodeInfo),
        RpcMethod::GetPeers => backend.get_peers().map(RpcOk::Peers),
        RpcMethod::GetMarkets(page) => backend.get_markets(page).map(RpcOk::Markets),
        RpcMethod::GetMarket(m) => backend.get_market(m).map(RpcOk::Market),
        RpcMethod::GetMarketBook(m, depth) => {
            backend.get_market_book(m, depth).map(RpcOk::MarketBook)
        }
        RpcMethod::GetMarketTrades(m, page) => {
            backend.get_market_trades(m, page).map(RpcOk::MarketTrades)
        }
        RpcMethod::GetMarketStatus(m) => backend.get_market_status(m).map(RpcOk::MarketStatus),
        RpcMethod::GetOracleStatus(m) => backend.get_oracle_status(m).map(RpcOk::OracleStatus),
        RpcMethod::GetCheckpoint(h) => backend.get_checkpoint(h).map(RpcOk::Checkpoint),
        RpcMethod::GetLatestCheckpoint => backend.get_latest_checkpoint().map(RpcOk::Checkpoint),
        RpcMethod::GetAccount(a) => backend.get_account(a).map(RpcOk::Account),
        RpcMethod::GetAccountProof(a) => backend.get_account_proof(a).map(RpcOk::AccountProof),
        RpcMethod::GetPosition(a, m) => backend.get_position(a, m).map(RpcOk::Position),
        RpcMethod::GetOrders(a, page) => backend.get_orders(a, page).map(RpcOk::Orders),
        RpcMethod::GetExecutionReceipt(h) => backend
            .get_execution_receipt(h)
            .map(RpcOk::ExecutionReceipt),
        RpcMethod::GetDepositStatus(h) => backend.get_deposit_status(h).map(RpcOk::DepositStatus),
        RpcMethod::GetWithdrawalStatus(h) => backend
            .get_withdrawal_status(h)
            .map(RpcOk::WithdrawalStatus),
        RpcMethod::GetNetworkStatus => backend.get_network_status().map(RpcOk::NetworkStatus),

        RpcMethod::SubmitOrder(meta, p) => backend.submit_order(&meta, &p).map(RpcOk::CommandAck),
        RpcMethod::CancelOrder(meta, p) => backend.cancel_order(&meta, &p).map(RpcOk::CommandAck),
        RpcMethod::CancelAll(meta, p) => backend.cancel_all(&meta, &p).map(RpcOk::CommandAck),
        RpcMethod::ReplaceOrder(meta, p) => backend.replace_order(&meta, &p).map(RpcOk::CommandAck),
        RpcMethod::SubmitBasket(meta, p) => backend.submit_basket(&meta, &p).map(RpcOk::CommandAck),
        RpcMethod::AuthorizeSession(meta, p) => {
            backend.authorize_session(&meta, &p).map(RpcOk::CommandAck)
        }
        RpcMethod::RevokeSession(meta, p) => {
            backend.revoke_session(&meta, &p).map(RpcOk::CommandAck)
        }
        RpcMethod::BindWallet(meta, p) => backend.bind_wallet(&meta, &p).map(RpcOk::CommandAck),
        RpcMethod::RequestWithdrawal(meta, p) => {
            backend.request_withdrawal(&meta, &p).map(RpcOk::CommandAck)
        }
        RpcMethod::CreateMarket(meta, p) => backend.create_market(&meta, &p).map(RpcOk::CommandAck),
        RpcMethod::StakeMarket(meta, p) => backend.stake_market(&meta, &p).map(RpcOk::CommandAck),
    }
}

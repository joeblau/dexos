//! The RPC request envelope and method enum.

use serde::{Deserialize, Serialize};
use types::{AccountId, Hash, MarketId};

use crate::command::{
    AuthorizeSessionParams, BasketParams, BindWalletParams, CancelAllParams, CancelOrderParams,
    ControlMeta, CreateMarketParams, ReplaceOrderParams, RequestWithdrawalParams,
    RevokeSessionParams, StakeMarketParams, SubmitOrderParams,
};
use crate::wire::PageParams;

/// A correlated RPC request. `request_id` is echoed on the response so a client
/// can pipeline many in-flight requests over one connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcRequest {
    /// Client-chosen correlation id, echoed on the response.
    pub request_id: u64,
    /// The method and its parameters.
    pub method: RpcMethod,
}

impl RpcRequest {
    /// Construct a request with an explicit correlation id.
    pub fn new(request_id: u64, method: RpcMethod) -> Self {
        RpcRequest { request_id, method }
    }

    /// Whether this is a control (write) method.
    pub fn is_control(&self) -> bool {
        self.method.is_control()
    }
}

/// Every RPC method with its typed parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RpcMethod {
    // ---- read-only queries ----
    /// Node identity and status.
    GetNodeInfo,
    /// Connected peers.
    GetPeers,
    /// List markets.
    GetMarkets(PageParams),
    /// One market's metadata.
    GetMarket(MarketId),
    /// One market's order book to `depth` levels.
    GetMarketBook(MarketId, u32),
    /// Recent trades for a market.
    GetMarketTrades(MarketId, PageParams),
    /// Live status for a market.
    GetMarketStatus(MarketId),
    /// Oracle status for a market.
    GetOracleStatus(MarketId),
    /// A checkpoint by height.
    GetCheckpoint(u64),
    /// The latest checkpoint.
    GetLatestCheckpoint,
    /// An account's state.
    GetAccount(AccountId),
    /// A Merkle proof for an account against the latest checkpoint.
    GetAccountProof(AccountId),
    /// A position by account and market.
    GetPosition(AccountId, MarketId),
    /// Orders for an account.
    GetOrders(AccountId, PageParams),
    /// An execution receipt by command hash.
    GetExecutionReceipt(Hash),
    /// A deposit's status by tx hash.
    GetDepositStatus(Hash),
    /// A withdrawal's status by request hash.
    GetWithdrawalStatus(Hash),
    /// Network / sync status.
    GetNetworkStatus,

    // ---- control (write) methods ----
    /// Submit a new order.
    SubmitOrder(ControlMeta, SubmitOrderParams),
    /// Cancel an order.
    CancelOrder(ControlMeta, CancelOrderParams),
    /// Cancel all orders.
    CancelAll(ControlMeta, CancelAllParams),
    /// Replace an order.
    ReplaceOrder(ControlMeta, ReplaceOrderParams),
    /// Submit a basket of orders.
    SubmitBasket(ControlMeta, BasketParams),
    /// Authorize a session key.
    AuthorizeSession(ControlMeta, AuthorizeSessionParams),
    /// Revoke a session key.
    RevokeSession(ControlMeta, RevokeSessionParams),
    /// Bind an external wallet.
    BindWallet(ControlMeta, BindWalletParams),
    /// Request a withdrawal.
    RequestWithdrawal(ControlMeta, RequestWithdrawalParams),
    /// Create a market.
    CreateMarket(ControlMeta, CreateMarketParams),
    /// Stake a market.
    StakeMarket(ControlMeta, StakeMarketParams),
}

impl RpcMethod {
    /// Whether this method mutates state (and is therefore rejected on read-only
    /// and light nodes).
    pub fn is_control(&self) -> bool {
        matches!(
            self,
            RpcMethod::SubmitOrder(..)
                | RpcMethod::CancelOrder(..)
                | RpcMethod::CancelAll(..)
                | RpcMethod::ReplaceOrder(..)
                | RpcMethod::SubmitBasket(..)
                | RpcMethod::AuthorizeSession(..)
                | RpcMethod::RevokeSession(..)
                | RpcMethod::BindWallet(..)
                | RpcMethod::RequestWithdrawal(..)
                | RpcMethod::CreateMarket(..)
                | RpcMethod::StakeMarket(..)
        )
    }

    /// The canonical [`Command`](crate::command::Command) a control method lowers
    /// to, or `None` for read-only queries.
    pub fn to_command(&self) -> Option<crate::command::Command> {
        Some(match self {
            RpcMethod::SubmitOrder(_, p) => p.to_command(),
            RpcMethod::CancelOrder(_, p) => p.to_command(),
            RpcMethod::CancelAll(_, p) => p.to_command(),
            RpcMethod::ReplaceOrder(_, p) => p.to_command(),
            RpcMethod::SubmitBasket(_, p) => p.to_command(),
            RpcMethod::AuthorizeSession(_, p) => p.to_command(),
            RpcMethod::RevokeSession(_, p) => p.to_command(),
            RpcMethod::BindWallet(_, p) => p.to_command(),
            RpcMethod::RequestWithdrawal(_, p) => p.to_command(),
            RpcMethod::CreateMarket(_, p) => p.to_command(),
            RpcMethod::StakeMarket(_, p) => p.to_command(),
            _ => return None,
        })
    }

    /// The idempotency metadata for a control method, or `None` for a query.
    pub fn control_meta(&self) -> Option<ControlMeta> {
        Some(match self {
            RpcMethod::SubmitOrder(m, _)
            | RpcMethod::CancelOrder(m, _)
            | RpcMethod::CancelAll(m, _)
            | RpcMethod::ReplaceOrder(m, _)
            | RpcMethod::SubmitBasket(m, _)
            | RpcMethod::AuthorizeSession(m, _)
            | RpcMethod::RevokeSession(m, _)
            | RpcMethod::BindWallet(m, _)
            | RpcMethod::RequestWithdrawal(m, _)
            | RpcMethod::CreateMarket(m, _)
            | RpcMethod::StakeMarket(m, _) => *m,
            _ => return None,
        })
    }
}

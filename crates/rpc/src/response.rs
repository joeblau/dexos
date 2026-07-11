//! The RPC response envelope and success-payload enum.

use serde::{Deserialize, Serialize};

use crate::command::CommandAck;
use crate::error::RpcError;
use crate::wire::Order;
use crate::wire::{
    Account, AccountProof, Book, Checkpoint, DepositStatus, ExecutionReceipt, MarketDetail,
    MarketStatus, MarketSummary, NetworkStatus, NodeInfo, OracleStatus, PeerInfo, Position, Trade,
    WithdrawalStatus,
};

/// A correlated RPC response. `request_id` echoes the request it answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcResponse {
    /// Correlation id copied from the request.
    pub request_id: u64,
    /// The method outcome.
    pub result: RpcResult,
}

/// The outcome of a method: a typed success payload or a typed error.
pub type RpcResult = Result<RpcOk, RpcError>;

impl RpcResponse {
    /// Construct a response echoing `request_id`.
    pub fn new(request_id: u64, result: RpcResult) -> Self {
        RpcResponse { request_id, result }
    }
}

/// A successful method result. One variant per method return type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RpcOk {
    /// `get_node_info`.
    NodeInfo(NodeInfo),
    /// `get_peers`.
    Peers(Vec<PeerInfo>),
    /// `get_markets`.
    Markets(Vec<MarketSummary>),
    /// `get_market`.
    Market(MarketDetail),
    /// `get_market_book`.
    MarketBook(Book),
    /// `get_market_trades`.
    MarketTrades(Vec<Trade>),
    /// `get_market_status`.
    MarketStatus(MarketStatus),
    /// `get_oracle_status`.
    OracleStatus(OracleStatus),
    /// `get_checkpoint` / `get_latest_checkpoint`.
    Checkpoint(Checkpoint),
    /// `get_account`.
    Account(Account),
    /// `get_account_proof`.
    AccountProof(AccountProof),
    /// `get_position`.
    Position(Position),
    /// `get_orders`.
    Orders(Vec<Order>),
    /// `get_execution_receipt`.
    ExecutionReceipt(ExecutionReceipt),
    /// `get_deposit_status`.
    DepositStatus(DepositStatus),
    /// `get_withdrawal_status`.
    WithdrawalStatus(WithdrawalStatus),
    /// `get_network_status`.
    NetworkStatus(NetworkStatus),
    /// Any control method.
    CommandAck(CommandAck),
}

//! Hand-written request builders for all 18 read queries and 11 control writes.
//!
//! Bindings call these rather than constructing `RpcMethod` variants directly:
//! the tuple-variant enums (`RpcMethod`/`Command`) are never auto-mapped across
//! an FFI boundary, so a single audited constructor per method keeps every
//! language honest. Read builders are unsigned; control builders take a
//! [`ControlMeta`] produced by [`crate::Signer::sign`].

use proto::*;
use types::{AccountId, Hash, MarketId};

// ---- read-only queries (unsigned) : 18 total ----

/// Build `get_node_info`.
pub fn get_node_info(id: u64) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetNodeInfo)
}

/// Build `get_peers`.
pub fn get_peers(id: u64) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetPeers)
}

/// Build `get_markets`.
pub fn get_markets(id: u64, page: PageParams) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetMarkets(page))
}

/// Build `get_market`.
pub fn get_market(id: u64, m: MarketId) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetMarket(m))
}

/// Build `get_market_book` to `depth` levels.
pub fn get_market_book(id: u64, m: MarketId, depth: u32) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetMarketBook(m, depth))
}

/// Build `get_market_trades`.
pub fn get_market_trades(id: u64, m: MarketId, page: PageParams) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetMarketTrades(m, page))
}

/// Build `get_market_status`.
pub fn get_market_status(id: u64, m: MarketId) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetMarketStatus(m))
}

/// Build `get_oracle_status`.
pub fn get_oracle_status(id: u64, m: MarketId) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetOracleStatus(m))
}

/// Build `get_checkpoint` by height.
pub fn get_checkpoint(id: u64, height: u64) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetCheckpoint(height))
}

/// Build `get_latest_checkpoint`.
pub fn get_latest_checkpoint(id: u64) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetLatestCheckpoint)
}

/// Build `get_account`.
pub fn get_account(id: u64, a: AccountId) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetAccount(a))
}

/// Build `get_account_proof`.
pub fn get_account_proof(id: u64, a: AccountId) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetAccountProof(a))
}

/// Build `get_position`.
pub fn get_position(id: u64, a: AccountId, m: MarketId) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetPosition(a, m))
}

/// Build `get_orders`.
pub fn get_orders(id: u64, a: AccountId, page: PageParams) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetOrders(a, page))
}

/// Build `get_execution_receipt` by command hash.
pub fn get_execution_receipt(id: u64, h: Hash) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetExecutionReceipt(h))
}

/// Build `get_deposit_status` by tx hash.
pub fn get_deposit_status(id: u64, h: Hash) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetDepositStatus(h))
}

/// Build `get_withdrawal_status` by request hash.
pub fn get_withdrawal_status(id: u64, h: Hash) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetWithdrawalStatus(h))
}

/// Build `get_network_status`.
pub fn get_network_status(id: u64) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::GetNetworkStatus)
}

// ---- control (write) methods (signed) : 11 total ----

/// Build a signed `submit_order`.
pub fn submit_order(id: u64, meta: ControlMeta, p: SubmitOrderParams) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::SubmitOrder(meta, p))
}

/// Build a signed `cancel_order`.
pub fn cancel_order(id: u64, meta: ControlMeta, p: CancelOrderParams) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::CancelOrder(meta, p))
}

/// Build a signed `cancel_all`.
pub fn cancel_all(id: u64, meta: ControlMeta, p: CancelAllParams) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::CancelAll(meta, p))
}

/// Build a signed `replace_order`.
pub fn replace_order(id: u64, meta: ControlMeta, p: ReplaceOrderParams) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::ReplaceOrder(meta, p))
}

/// Build a signed `submit_basket`.
pub fn submit_basket(id: u64, meta: ControlMeta, p: BasketParams) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::SubmitBasket(meta, p))
}

/// Build a signed `authorize_session`.
pub fn authorize_session(id: u64, meta: ControlMeta, p: AuthorizeSessionParams) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::AuthorizeSession(meta, p))
}

/// Build a signed `revoke_session`.
pub fn revoke_session(id: u64, meta: ControlMeta, p: RevokeSessionParams) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::RevokeSession(meta, p))
}

/// Build a signed `bind_wallet`.
pub fn bind_wallet(id: u64, meta: ControlMeta, p: BindWalletParams) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::BindWallet(meta, p))
}

/// Build a signed `request_withdrawal`.
pub fn request_withdrawal(id: u64, meta: ControlMeta, p: RequestWithdrawalParams) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::RequestWithdrawal(meta, p))
}

/// Build a signed `create_market`.
pub fn create_market(id: u64, meta: ControlMeta, p: CreateMarketParams) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::CreateMarket(meta, p))
}

/// Build a signed `stake_market`.
pub fn stake_market(id: u64, meta: ControlMeta, p: StakeMarketParams) -> RpcRequest {
    RpcRequest::new(id, RpcMethod::StakeMarket(meta, p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_builders_set_request_id_and_method() {
        let r = get_market(9, MarketId::new(42));
        assert_eq!(r.request_id, 9);
        assert!(!r.is_control());
        assert!(matches!(r.method, RpcMethod::GetMarket(_)));
    }

    #[test]
    fn control_builders_are_control() {
        let meta = ControlMeta {
            client_id: 1,
            nonce: 1,
            session_pubkey: None,
            signer: [0u8; 32],
            signature: [0u8; 64],
        };
        let p = CancelAllParams {
            account: AccountId::new(1),
            market: None,
        };
        let r = cancel_all(3, meta, p);
        assert_eq!(r.request_id, 3);
        assert!(r.is_control());
    }
}

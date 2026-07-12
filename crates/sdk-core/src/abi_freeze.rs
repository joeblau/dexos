//! Wire-ABI freeze tests.
//!
//! postcard encodes an enum's *variant index* and a struct's fields
//! *positionally*, so both variant ORDER and struct field ORDER are load-bearing
//! wire contract. These tests pin:
//!   * every `RpcMethod` variant's encoded index (18 reads + 11 controls = 29),
//!     exhaustively (a compile error if a variant is added/removed, plus an
//!     encoded-index assertion catching reorders);
//!   * `RpcError::NonceReused` staying the final variant (idempotency-wire ABI);
//!   * `RpcOk::CommandAck` staying the final variant;
//!   * golden bytes for `SubmitOrderParams` and `Command::PlaceOrder`
//!     (regenerated + diff-gated by `xtask gen-vectors`).

use codec::encode;
use proto::{
    AuthorizeSessionParams, BasketParams, BindWalletParams, CancelAllParams, CancelOrderParams,
    Command, CommandAck, ControlMeta, CreateMarketParams, FinalityStatus, PageParams,
    ReplaceOrderParams, RequestWithdrawalParams, RevokeSessionParams, RpcError, RpcMethod, RpcOk,
    SessionScope, StakeMarketParams, SubmitOrderParams,
};
use types::{
    AccountId, Amount, Hash, MarketId, MarketType, OrderId, Price, Quantity, Ratio, SponsorId,
};

fn dummy_meta() -> ControlMeta {
    ControlMeta {
        client_id: 1,
        nonce: 1,
        session_pubkey: None,
        signer: [0u8; 32],
        signature: [0u8; 64],
    }
}

fn submit_params() -> SubmitOrderParams {
    crate::poc::golden_submit_params()
}

/// Expected postcard variant index of every `RpcMethod`. The match is
/// exhaustive with no wildcard, so adding or removing a variant fails to
/// compile here — forcing this freeze test to be updated deliberately.
fn method_index(m: &RpcMethod) -> u8 {
    match m {
        RpcMethod::GetNodeInfo => 0,
        RpcMethod::GetPeers => 1,
        RpcMethod::GetMarkets(_) => 2,
        RpcMethod::GetMarket(_) => 3,
        RpcMethod::GetMarketBook(_, _) => 4,
        RpcMethod::GetMarketTrades(_, _) => 5,
        RpcMethod::GetMarketStatus(_) => 6,
        RpcMethod::GetOracleStatus(_) => 7,
        RpcMethod::GetCheckpoint(_) => 8,
        RpcMethod::GetLatestCheckpoint => 9,
        RpcMethod::GetAccount(_) => 10,
        RpcMethod::GetAccountProof(_) => 11,
        RpcMethod::GetPosition(_, _) => 12,
        RpcMethod::GetOrders(_, _) => 13,
        RpcMethod::GetExecutionReceipt(_) => 14,
        RpcMethod::GetDepositStatus(_) => 15,
        RpcMethod::GetWithdrawalStatus(_) => 16,
        RpcMethod::GetNetworkStatus => 17,
        RpcMethod::SubmitOrder(_, _) => 18,
        RpcMethod::CancelOrder(_, _) => 19,
        RpcMethod::CancelAll(_, _) => 20,
        RpcMethod::ReplaceOrder(_, _) => 21,
        RpcMethod::SubmitBasket(_, _) => 22,
        RpcMethod::AuthorizeSession(_, _) => 23,
        RpcMethod::RevokeSession(_, _) => 24,
        RpcMethod::BindWallet(_, _) => 25,
        RpcMethod::RequestWithdrawal(_, _) => 26,
        RpcMethod::CreateMarket(_, _) => 27,
        RpcMethod::StakeMarket(_, _) => 28,
    }
}

/// One representative instance of every `RpcMethod` variant, in declaration
/// order, so each variant's encoded leading index byte can be checked.
fn all_methods() -> Vec<RpcMethod> {
    let a = AccountId::new(1);
    let m = MarketId::new(42);
    let meta = dummy_meta();
    let scope = SessionScope {
        markets: vec![],
        all_markets: false,
        max_notional: Amount::from_raw(0),
        max_leverage: Ratio::from_raw(0),
        allow_withdrawal: false,
        allow_session_admin: false,
        allow_market_create: false,
        expiry: 0,
    };
    vec![
        RpcMethod::GetNodeInfo,
        RpcMethod::GetPeers,
        RpcMethod::GetMarkets(PageParams::default()),
        RpcMethod::GetMarket(m),
        RpcMethod::GetMarketBook(m, 8),
        RpcMethod::GetMarketTrades(m, PageParams::default()),
        RpcMethod::GetMarketStatus(m),
        RpcMethod::GetOracleStatus(m),
        RpcMethod::GetCheckpoint(1),
        RpcMethod::GetLatestCheckpoint,
        RpcMethod::GetAccount(a),
        RpcMethod::GetAccountProof(a),
        RpcMethod::GetPosition(a, m),
        RpcMethod::GetOrders(a, PageParams::default()),
        RpcMethod::GetExecutionReceipt(Hash([0u8; 32])),
        RpcMethod::GetDepositStatus(Hash([0u8; 32])),
        RpcMethod::GetWithdrawalStatus(Hash([0u8; 32])),
        RpcMethod::GetNetworkStatus,
        RpcMethod::SubmitOrder(meta, submit_params()),
        RpcMethod::CancelOrder(
            meta,
            CancelOrderParams {
                account: a,
                market: m,
                order_id: OrderId::new(1),
            },
        ),
        RpcMethod::CancelAll(
            meta,
            CancelAllParams {
                account: a,
                market: None,
            },
        ),
        RpcMethod::ReplaceOrder(
            meta,
            ReplaceOrderParams {
                account: a,
                market: m,
                order_id: OrderId::new(1),
                new_price: Price::from_raw(1),
                new_quantity: Quantity::from_raw(1),
            },
        ),
        RpcMethod::SubmitBasket(
            meta,
            BasketParams {
                account: a,
                orders: vec![],
            },
        ),
        RpcMethod::AuthorizeSession(
            meta,
            AuthorizeSessionParams {
                account: a,
                session_pubkey: [0u8; 32],
                scope: scope.clone(),
            },
        ),
        RpcMethod::RevokeSession(
            meta,
            RevokeSessionParams {
                account: a,
                session_pubkey: [0u8; 32],
            },
        ),
        RpcMethod::BindWallet(
            meta,
            BindWalletParams {
                account: a,
                wallet: [0u8; 20],
                signature: vec![],
            },
        ),
        RpcMethod::RequestWithdrawal(
            meta,
            RequestWithdrawalParams {
                account: a,
                amount: Amount::from_raw(0),
                destination: [0u8; 20],
            },
        ),
        RpcMethod::CreateMarket(
            meta,
            CreateMarketParams {
                creator: a,
                market_type: MarketType::Perpetual,
                symbol: String::new(),
                outcomes: 1,
            },
        ),
        RpcMethod::StakeMarket(
            meta,
            StakeMarketParams {
                market: m,
                sponsor: SponsorId::new(1),
                amount: Amount::from_raw(0),
            },
        ),
    ]
}

#[test]
fn rpcmethod_variant_indices_frozen() {
    let methods = all_methods();
    // 18 reads + 11 controls.
    assert_eq!(methods.len(), 29, "RpcMethod variant count changed");
    for (i, method) in methods.iter().enumerate() {
        let idx = u8::try_from(i).unwrap();
        assert_eq!(
            method_index(method),
            idx,
            "declaration order vs method_index disagree at {i}"
        );
        let encoded = encode(method).unwrap();
        assert_eq!(
            encoded[0], idx,
            "postcard variant index for {method:?} drifted (got {}, want {idx})",
            encoded[0]
        );
    }
    // Spot pins from the cheatsheet.
    assert_eq!(encode(&RpcMethod::GetNodeInfo).unwrap(), vec![0]);
    assert_eq!(
        encode(&RpcMethod::GetMarket(MarketId::new(0))).unwrap(),
        vec![3, 0]
    );
}

#[test]
fn rpcerror_nonce_reused_stays_last() {
    // Full index pin: NotFound..NonceReused == 0..=14.
    let all = [
        RpcError::NotFound,
        RpcError::ReadOnly,
        RpcError::Backpressure,
        RpcError::MessageTooLarge,
        RpcError::InvalidRequest(String::new()),
        RpcError::Unauthorized,
        RpcError::InvalidSignature,
        RpcError::SessionExpired,
        RpcError::OutOfScope,
        RpcError::OverNotional,
        RpcError::OverLeverage,
        RpcError::Codec(String::new()),
        RpcError::UnknownMethod,
        RpcError::Internal(String::new()),
        RpcError::NonceReused,
    ];
    for (i, e) in all.iter().enumerate() {
        assert_eq!(encode(e).unwrap()[0], u8::try_from(i).unwrap());
    }
    // NonceReused is deliberately appended last: its index is the max.
    let nonce = encode(&RpcError::NonceReused).unwrap();
    let internal = encode(&RpcError::Internal(String::new())).unwrap();
    assert_eq!(nonce[0], 14);
    assert!(nonce[0] > internal[0]);
}

#[test]
fn rpcok_command_ack_stays_last() {
    // CommandAck is the final RpcOk variant (index 17) — appended so control
    // acks never shift the read variants' indices.
    let ack = RpcOk::CommandAck(CommandAck {
        command_hash: Hash([0u8; 32]),
        finality: FinalityStatus::Accepted,
        order_id: None,
        market_id: None,
    });
    assert_eq!(encode(&ack).unwrap()[0], 17);
}

#[test]
fn submit_order_params_field_order_frozen() {
    // Struct field order is load-bearing (postcard is positional). A field
    // reorder/insert changes these committed golden bytes and fails here.
    let hex = hex::encode(encode(&submit_params()).unwrap());
    let golden = include_str!("../../../conformance/submit_order_params.hex").trim();
    assert_eq!(hex, golden, "SubmitOrderParams wire layout drifted");
}

#[test]
fn command_place_order_field_order_frozen() {
    let cmd = submit_params().to_command();
    assert!(matches!(cmd, Command::PlaceOrder { .. }));
    let hex = hex::encode(encode(&cmd).unwrap());
    let golden = include_str!("../../../conformance/command_place_order.hex").trim();
    assert_eq!(hex, golden, "Command::PlaceOrder wire layout drifted");
}

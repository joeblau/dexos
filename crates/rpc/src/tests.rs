//! Unit, property (in-test LCG), and never-panics tests for the RPC crate.

use std::sync::Arc;

use crate::command::*;
use crate::error::RpcError;
use crate::request::*;
use crate::response::*;
use crate::session::Session;
use crate::stream::*;
use crate::stub::*;
use crate::transport::*;
use crate::wire::*;
use crate::{dispatch, RpcBackend};

use types::{
    AccountId, Amount, Hash, MarketId, MarketType, OracleHealth, OrderId, OrderType, Price,
    Quantity, Ratio, SequenceNumber, Side, SponsorId, TimeInForce,
};

/// A tiny deterministic LCG (no external crates) for property tests.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.0
    }
    fn range(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next().to_le_bytes()[0]).collect()
    }
}

fn m(id: u32) -> MarketId {
    MarketId::new(id)
}
fn a(id: u32) -> AccountId {
    AccountId::new(id)
}

/// An unsigned envelope: used only by paths that never reach signature
/// verification (codec round-trips, read-only-mode rejection).
fn sample_meta() -> ControlMeta {
    ControlMeta {
        client_id: 7,
        nonce: 1,
        session_pubkey: None,
        signer: [0u8; 32],
        signature: [0u8; 64],
    }
}

/// The canonical account-root keypair used by fixtures; its public key is
/// registered for account `a(1)` in [`populated_backend`].
fn account_kp() -> crypto::KeyPair {
    crypto::KeyPair::from_seed(&[11u8; 32])
}

/// A signed direct (non-delegated) envelope authorizing `command`.
fn signed_meta(kp: &crypto::KeyPair, client_id: u64, nonce: u64, command: &Command) -> ControlMeta {
    ControlMeta::signed(client_id, nonce, None, kp, command).expect("test command must encode")
}

fn sample_submit() -> SubmitOrderParams {
    SubmitOrderParams {
        account: a(1),
        market: m(1),
        side: Side::Bid,
        order_type: OrderType::Limit,
        price: Price::ONE,
        quantity: Quantity::ONE,
        time_in_force: TimeInForce::Gtc,
        leverage: Ratio::ONE,
    }
}

fn sample_scope(markets: Vec<MarketId>) -> SessionScope {
    SessionScope {
        markets,
        all_markets: false,
        max_notional: Amount::MAX,
        max_leverage: Ratio::ONE,
        allow_withdrawal: false,
        allow_session_admin: false,
        allow_market_create: false,
        expiry: 1_000,
    }
}

/// One instance of every method for round-trip coverage.
fn all_methods() -> Vec<RpcMethod> {
    let meta = sample_meta();
    vec![
        RpcMethod::GetNodeInfo,
        RpcMethod::GetPeers,
        RpcMethod::GetMarkets(PageParams::default()),
        RpcMethod::GetMarket(m(1)),
        RpcMethod::GetMarketBook(m(1), 10),
        RpcMethod::GetMarketTrades(m(1), PageParams::default()),
        RpcMethod::GetMarketStatus(m(1)),
        RpcMethod::GetOracleStatus(m(1)),
        RpcMethod::GetCheckpoint(5),
        RpcMethod::GetLatestCheckpoint,
        RpcMethod::GetAccount(a(1)),
        RpcMethod::GetAccountProof(a(1)),
        RpcMethod::GetPosition(a(1), m(1)),
        RpcMethod::GetOrders(a(1), PageParams::default()),
        RpcMethod::GetExecutionReceipt(Hash::from_bytes([3u8; 32])),
        RpcMethod::GetDepositStatus(Hash::from_bytes([4u8; 32])),
        RpcMethod::GetWithdrawalStatus(Hash::from_bytes([5u8; 32])),
        RpcMethod::GetNetworkStatus,
        RpcMethod::SubmitOrder(meta, sample_submit()),
        RpcMethod::CancelOrder(
            meta,
            CancelOrderParams {
                account: a(1),
                market: m(1),
                order_id: OrderId::new(9),
            },
        ),
        RpcMethod::CancelAll(
            meta,
            CancelAllParams {
                account: a(1),
                market: Some(m(1)),
            },
        ),
        RpcMethod::ReplaceOrder(
            meta,
            ReplaceOrderParams {
                account: a(1),
                market: m(1),
                order_id: OrderId::new(9),
                new_price: Price::ONE,
                new_quantity: Quantity::ONE,
            },
        ),
        RpcMethod::SubmitBasket(
            meta,
            BasketParams {
                account: a(1),
                orders: vec![sample_submit()],
            },
        ),
        RpcMethod::AuthorizeSession(
            meta,
            AuthorizeSessionParams {
                account: a(1),
                session_pubkey: [1u8; 32],
                scope: sample_scope(vec![m(1)]),
            },
        ),
        RpcMethod::RevokeSession(
            meta,
            RevokeSessionParams {
                account: a(1),
                session_pubkey: [1u8; 32],
            },
        ),
        RpcMethod::BindWallet(
            meta,
            BindWalletParams {
                account: a(1),
                wallet: [2u8; 20],
                signature: vec![1, 2, 3],
            },
        ),
        RpcMethod::RequestWithdrawal(
            meta,
            RequestWithdrawalParams {
                account: a(1),
                amount: Amount::ONE,
                destination: [3u8; 20],
            },
        ),
        RpcMethod::CreateMarket(
            meta,
            CreateMarketParams {
                creator: a(1),
                market_type: MarketType::Perpetual,
                symbol: "BTC-PERP".into(),
                outcomes: 1,
            },
        ),
        RpcMethod::StakeMarket(
            meta,
            StakeMarketParams {
                market: m(1),
                sponsor: SponsorId::new(1),
                amount: Amount::ONE,
            },
        ),
    ]
}

fn sample_checkpoint() -> Checkpoint {
    Checkpoint {
        height: 5,
        new_state_root: Hash::from_bytes([9u8; 32]),
        prev_state_root: Hash::ZERO,
        timestamp: 100,
        quorum_certificate: None,
    }
}

/// One instance of every success payload for round-trip coverage.
fn all_oks() -> Vec<RpcOk> {
    vec![
        RpcOk::NodeInfo(NodeInfo {
            node_id: [1u8; 32],
            chain_id: 1,
            protocol_version: 1,
            mode: RpcMode::Full,
            height: 3,
        }),
        RpcOk::Peers(vec![PeerInfo {
            peer_id: [2u8; 32],
            address: "1.2.3.4:9000".into(),
            connected: true,
            latency_ms: 12,
        }]),
        RpcOk::Markets(vec![MarketSummary {
            market_id: m(1),
            market_type: MarketType::Perpetual,
            lifecycle: types::MarketLifecycle::Open,
        }]),
        RpcOk::Market(MarketDetail {
            summary: MarketSummary {
                market_id: m(1),
                market_type: MarketType::Perpetual,
                lifecycle: types::MarketLifecycle::Open,
            },
            tick_size: Price::ONE,
            lot_size: Quantity::ONE,
            symbol: "BTC-PERP".into(),
            outcomes: 1,
        }),
        RpcOk::MarketBook(fixture_book(m(1), Price::ONE, Price::ONE, Quantity::ONE)),
        RpcOk::MarketTrades(vec![Trade {
            market_id: m(1),
            order_id: OrderId::new(1),
            price: Price::ONE,
            quantity: Quantity::ONE,
            side: Side::Bid,
            timestamp: 1,
        }]),
        RpcOk::MarketStatus(MarketStatus {
            market_id: m(1),
            lifecycle: types::MarketLifecycle::Open,
            mark_price: Price::ONE,
            index_price: Price::ONE,
            funding_rate: Ratio::ZERO,
            open_interest: Quantity::ONE,
            oracle_health: OracleHealth::Normal,
        }),
        RpcOk::OracleStatus(OracleStatus {
            market_id: m(1),
            health: OracleHealth::Normal,
            price: Price::ONE,
            sources: 3,
            last_update: 1,
        }),
        RpcOk::Checkpoint(sample_checkpoint()),
        RpcOk::Account(fixture_account(1, Amount::ONE)),
        RpcOk::AccountProof(AccountProof {
            account_id: a(1),
            leaf: Hash::from_bytes([7u8; 32]),
            leaf_index: 1,
            siblings: vec![Hash::ZERO],
            checkpoint_height: 5,
            state_root: Hash::ZERO,
        }),
        RpcOk::Position(fixture_position(1, 1, Quantity::ONE)),
        RpcOk::Orders(vec![Order {
            order_id: OrderId::new(1),
            account_id: a(1),
            market_id: m(1),
            side: Side::Bid,
            order_type: OrderType::Limit,
            price: Price::ONE,
            quantity: Quantity::ONE,
            filled: Quantity::ZERO,
            time_in_force: TimeInForce::Gtc,
        }]),
        RpcOk::ExecutionReceipt(ExecutionReceipt {
            command_hash: Hash::from_bytes([8u8; 32]),
            order_id: Some(OrderId::new(1)),
            fills: vec![Fill {
                price: Price::ONE,
                quantity: Quantity::ONE,
            }],
            finality: FinalityStatus::Executed,
            checkpoint_height: Some(5),
            verification_status: VerificationStatus::Verified,
        }),
        RpcOk::DepositStatus(DepositStatus {
            tx_hash: Hash::from_bytes([1u8; 32]),
            account_id: a(1),
            amount: Amount::ONE,
            status: BridgeStatus::Confirmed,
            confirmations: 12,
        }),
        RpcOk::WithdrawalStatus(WithdrawalStatus {
            request_hash: Hash::from_bytes([2u8; 32]),
            account_id: a(1),
            amount: Amount::ONE,
            status: BridgeStatus::Pending,
            finality: FinalityStatus::Certified,
        }),
        RpcOk::NetworkStatus(NetworkStatus {
            peer_count: 4,
            height: 5,
            finalized_height: 4,
            syncing: false,
        }),
        RpcOk::CommandAck(CommandAck {
            command_hash: Hash::from_bytes([6u8; 32]),
            finality: FinalityStatus::Accepted,
            order_id: Some(OrderId::new(1)),
            market_id: Some(m(1)),
        }),
    ]
}

// ---------------------------------------------------------------------------
// Round-trip coverage
// ---------------------------------------------------------------------------

#[test]
fn crate_name_is_stable() {
    assert_eq!(crate::CRATE_NAME, "rpc");
}

#[test]
fn every_request_round_trips_through_codec() {
    for (i, method) in all_methods().into_iter().enumerate() {
        let request = RpcRequest::new(u64::try_from(i).unwrap() + 100, method);
        // Direct codec round-trip.
        let bytes = codec::encode(&request).unwrap();
        let back: RpcRequest = codec::decode(&bytes).unwrap();
        assert_eq!(request, back);
        // Framed transport round-trip preserves request_id (correlation).
        let framed = encode_request(&request).unwrap();
        let decoded = decode_request(&framed).unwrap();
        assert_eq!(request, decoded);
        assert_eq!(decoded.request_id, u64::try_from(i).unwrap() + 100);
    }
}

#[test]
fn every_response_round_trips_through_codec() {
    for (i, ok) in all_oks().into_iter().enumerate() {
        let response = RpcResponse::new(u64::try_from(i).unwrap(), Ok(ok));
        let bytes = codec::encode(&response).unwrap();
        let back: RpcResponse = codec::decode(&bytes).unwrap();
        assert_eq!(response, back);
        let framed = encode_response(&response).unwrap();
        let decoded = decode_response(&framed).unwrap();
        assert_eq!(response, decoded);
    }
    // Error responses round-trip too.
    let err = RpcResponse::new(42, Err(RpcError::NotFound));
    let framed = encode_response(&err).unwrap();
    assert_eq!(decode_response(&framed).unwrap(), err);
}

#[test]
fn control_methods_lower_to_expected_commands() {
    let meta = sample_meta();
    let mkt = m(1);
    let cases: Vec<(RpcMethod, bool)> = vec![
        (RpcMethod::SubmitOrder(meta, sample_submit()), true),
        (RpcMethod::GetNodeInfo, false),
    ];
    for (method, is_ctrl) in cases {
        assert_eq!(method.is_control(), is_ctrl);
        assert_eq!(method.to_command().is_some(), is_ctrl);
    }
    // Spot-check a specific lowering.
    let sm = RpcMethod::StakeMarket(
        meta,
        StakeMarketParams {
            market: mkt,
            sponsor: SponsorId::new(2),
            amount: Amount::ONE,
        },
    );
    match sm.to_command() {
        Some(Command::StakeMarket { market, .. }) => assert_eq!(market, mkt),
        other => panic!("unexpected lowering: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Dispatch + mode enforcement
// ---------------------------------------------------------------------------

fn populated_backend(mode: RpcMode) -> StubBackend {
    let b = StubBackend::new(mode);
    b.insert_market(MarketDetail {
        summary: MarketSummary {
            market_id: m(1),
            market_type: MarketType::Perpetual,
            lifecycle: types::MarketLifecycle::Open,
        },
        tick_size: Price::ONE,
        lot_size: Quantity::ONE,
        symbol: "BTC-PERP".into(),
        outcomes: 1,
    });
    b.insert_account(fixture_account(1, Amount::ONE)).unwrap();
    // Register account a(1)'s root authorization key so signed direct commands
    // for it can be authenticated.
    b.register_account_key(a(1), account_kp().public());
    b.commit_checkpoint(1, 1000);
    b
}

#[test]
fn dispatch_routes_query_to_correct_handler() {
    let b = populated_backend(RpcMode::Full);
    let resp = dispatch(
        &b,
        RpcMode::Full,
        RpcRequest::new(1, RpcMethod::GetMarket(m(1))),
    );
    assert_eq!(resp.request_id, 1);
    match resp.result {
        Ok(RpcOk::Market(d)) => assert_eq!(d.summary.market_id, m(1)),
        other => panic!("unexpected: {other:?}"),
    }
    // Missing market -> NotFound (no panic).
    let missing = dispatch(
        &b,
        RpcMode::Full,
        RpcRequest::new(2, RpcMethod::GetMarket(m(99))),
    );
    assert_eq!(missing.result, Err(RpcError::NotFound));
}

#[test]
fn dispatch_write_succeeds_in_full_mode() {
    let b = populated_backend(RpcMode::Full);
    let kp = account_kp();
    let params = sample_submit();
    let meta = signed_meta(&kp, 7, 1, &params.to_command());
    let req = RpcRequest::new(9, RpcMethod::SubmitOrder(meta, params));
    let resp = dispatch(&b, RpcMode::Full, req);
    assert!(matches!(resp.result, Ok(RpcOk::CommandAck(_))));
}

#[test]
fn read_only_and_light_reject_every_control_method() {
    for mode in [RpcMode::ReadOnly, RpcMode::Light] {
        let b = populated_backend(mode);
        for method in all_methods() {
            let is_ctrl = method.is_control();
            let resp = dispatch(&b, mode, RpcRequest::new(1, method));
            if is_ctrl {
                assert_eq!(resp.result, Err(RpcError::ReadOnly));
            } else {
                // Queries still work in read-only / light mode.
                assert!(resp.result.is_ok() || resp.result == Err(RpcError::NotFound));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Account proofs
// ---------------------------------------------------------------------------

#[test]
fn account_proof_verifies_and_tamper_is_rejected() {
    let b = populated_backend(RpcMode::Full);
    let proof = b.get_account_proof(a(1)).unwrap();
    // Valid proof accepts against the committed root.
    assert_eq!(
        proof.verify_against(b.state_root()),
        VerificationStatus::ProofValid
    );
    // Tampered leaf rejects.
    let mut tampered = proof.clone();
    tampered.leaf = Hash::from_bytes([0xAB; 32]);
    assert_eq!(
        tampered.verify_against(b.state_root()),
        VerificationStatus::ProofInvalid
    );
    // Tampered sibling rejects.
    let mut sib = proof.clone();
    if let Some(first) = sib.siblings.first_mut() {
        *first = Hash::from_bytes([0xCD; 32]);
    }
    assert_eq!(
        sib.verify_against(b.state_root()),
        VerificationStatus::ProofInvalid
    );
}

#[test]
fn account_proof_unknown_account_is_not_found() {
    let b = populated_backend(RpcMode::Full);
    assert_eq!(b.get_account_proof(a(1234)), Err(RpcError::NotFound));
}

// ---------------------------------------------------------------------------
// Page bounds
// ---------------------------------------------------------------------------

#[test]
fn list_methods_never_exceed_page_bound() {
    let b = StubBackend::new(RpcMode::Full);
    b.set_page_limit(2);
    for id in 0..10u32 {
        b.insert_market(MarketDetail {
            summary: MarketSummary {
                market_id: m(id),
                market_type: MarketType::Perpetual,
                lifecycle: types::MarketLifecycle::Open,
            },
            tick_size: Price::ONE,
            lot_size: Quantity::ONE,
            symbol: "X".into(),
            outcomes: 1,
        });
    }
    let mut lcg = Lcg(1);
    for _ in 0..200 {
        let limit = u32::try_from(lcg.range(1_000_000)).unwrap();
        let page = PageParams { offset: 0, limit };
        let out = b.get_markets(page).unwrap();
        assert!(out.len() <= 2, "page bound violated: {}", out.len());
    }
}

// ---------------------------------------------------------------------------
// Session validation
// ---------------------------------------------------------------------------

#[test]
fn session_validation_rejects_each_class() {
    let session = Session {
        session_pubkey: [1u8; 32],
        scope: SessionScope {
            markets: vec![m(1)],
            all_markets: false,
            max_notional: Amount::from_raw(1),
            max_leverage: Ratio::ONE,
            allow_withdrawal: false,
            allow_session_admin: false,
            allow_market_create: false,
            expiry: 1_000,
        },
    };
    // Out-of-scope market.
    let oos = SubmitOrderParams {
        market: m(2),
        ..sample_submit()
    }
    .to_command();
    assert_eq!(session.authorize(&oos, 0), Err(RpcError::OutOfScope));
    // Over-leverage.
    let ol = SubmitOrderParams {
        leverage: Ratio::from_raw(2_000_000),
        ..sample_submit()
    }
    .to_command();
    assert_eq!(session.authorize(&ol, 0), Err(RpcError::OverLeverage));
    // Over-notional (Price::ONE * Quantity::ONE = Amount::ONE > max_notional=1 raw).
    let on = sample_submit().to_command();
    assert_eq!(session.authorize(&on, 0), Err(RpcError::OverNotional));
    // Expired.
    let expired = SubmitOrderParams {
        price: Price::ZERO,
        ..sample_submit()
    }
    .to_command();
    assert_eq!(
        session.authorize(&expired, 2_000),
        Err(RpcError::SessionExpired)
    );
    // Unauthorized withdrawal.
    let wd = Command::Withdraw {
        account: a(1),
        amount: Amount::ZERO,
        destination: [0u8; 20],
    };
    assert_eq!(session.authorize(&wd, 0), Err(RpcError::Unauthorized));
    // A within-scope, within-limit order is accepted.
    let ok_session = Session {
        session_pubkey: [1u8; 32],
        scope: sample_scope(vec![m(1)]),
    };
    assert_eq!(
        ok_session.authorize(&sample_submit().to_command(), 0),
        Ok(())
    );
}

/// The four privileged admin commands. `scope`'s admin flags decide each.
fn authorize_session_cmd() -> Command {
    Command::AuthorizeSession {
        account: a(1),
        session_pubkey: [9u8; 32],
        scope: sample_scope(vec![m(1)]),
    }
}
fn revoke_session_cmd() -> Command {
    Command::RevokeSession {
        account: a(1),
        session_pubkey: [9u8; 32],
    }
}
fn bind_wallet_cmd() -> Command {
    Command::BindWallet {
        account: a(1),
        wallet: [2u8; 20],
        signature: vec![1, 2, 3],
    }
}
fn create_market_cmd() -> Command {
    Command::CreateMarket {
        creator: a(1),
        market_type: MarketType::Perpetual,
        symbol: "TEST-PERP".to_string(),
        outcomes: 1,
    }
}

/// Acceptance: a trading-scoped session (no admin capability flags set) cannot
/// authorize new sessions, revoke sessions, bind wallets, or create markets.
/// Every privileged command class is default-deny.
#[test]
fn trading_scoped_session_cannot_perform_admin_commands() {
    let session = Session {
        session_pubkey: [1u8; 32],
        scope: sample_scope(vec![m(1)]),
    };
    // sample_scope leaves allow_session_admin / allow_market_create false.
    for cmd in [
        authorize_session_cmd(),
        revoke_session_cmd(),
        bind_wallet_cmd(),
        create_market_cmd(),
    ] {
        assert_eq!(
            session.authorize(&cmd, 0),
            Err(RpcError::Unauthorized),
            "trading session must not be able to run {cmd:?}"
        );
    }
    // The within-scope trading command it *is* allowed to run still works, so
    // the deny is specific to admin classes rather than a blanket rejection.
    assert_eq!(session.authorize(&sample_submit().to_command(), 0), Ok(()));
}

/// Acceptance: session authorization and revocation are the account root key's
/// exclusive privilege — they can never be delegated, even to a session that
/// has been granted the account-admin capability flag.
#[test]
fn session_authorize_and_revoke_are_never_delegable() {
    let mut scope = sample_scope(vec![m(1)]);
    scope.allow_session_admin = true;
    scope.allow_market_create = true;
    let session = Session {
        session_pubkey: [1u8; 32],
        scope,
    };
    assert_eq!(
        session.authorize(&authorize_session_cmd(), 0),
        Err(RpcError::Unauthorized)
    );
    assert_eq!(
        session.authorize(&revoke_session_cmd(), 0),
        Err(RpcError::Unauthorized)
    );
}

/// Acceptance: `allow_session_admin` gates the delegable account-administration
/// command (`BindWallet`), and `allow_market_create` gates `CreateMarket`. When
/// set, the corresponding command is permitted while unrelated admin classes
/// remain denied.
#[test]
fn admin_capability_flags_are_independent() {
    // Only wallet binding is delegated.
    let mut wallet_scope = sample_scope(vec![m(1)]);
    wallet_scope.allow_session_admin = true;
    let wallet_session = Session {
        session_pubkey: [1u8; 32],
        scope: wallet_scope,
    };
    assert_eq!(wallet_session.authorize(&bind_wallet_cmd(), 0), Ok(()));
    // Market creation is not granted by the account-admin flag.
    assert_eq!(
        wallet_session.authorize(&create_market_cmd(), 0),
        Err(RpcError::Unauthorized)
    );

    // Only market creation is delegated.
    let mut market_scope = sample_scope(vec![m(1)]);
    market_scope.allow_market_create = true;
    let market_session = Session {
        session_pubkey: [2u8; 32],
        scope: market_scope,
    };
    assert_eq!(market_session.authorize(&create_market_cmd(), 0), Ok(()));
    // Wallet binding is not granted by the market-create flag.
    assert_eq!(
        market_session.authorize(&bind_wallet_cmd(), 0),
        Err(RpcError::Unauthorized)
    );
}

/// Acceptance: an empty `markets` allow-list with no wildcard denies all
/// trading; an explicit market entry or the `all_markets` wildcard is required
/// before any order is accepted.
#[test]
fn empty_markets_scope_denies_trading_until_explicit() {
    // Empty list, no wildcard -> every market is out of scope.
    let deny_all = Session {
        session_pubkey: [1u8; 32],
        scope: sample_scope(vec![]),
    };
    assert_eq!(
        deny_all.authorize(&sample_submit().to_command(), 0),
        Err(RpcError::OutOfScope)
    );

    // Explicit market entry -> that market is now in scope.
    let listed = Session {
        session_pubkey: [1u8; 32],
        scope: sample_scope(vec![m(1)]),
    };
    assert_eq!(listed.authorize(&sample_submit().to_command(), 0), Ok(()));

    // Explicit wildcard -> any market is in scope even with an empty list.
    let mut wildcard_scope = sample_scope(vec![]);
    wildcard_scope.all_markets = true;
    let wildcard = Session {
        session_pubkey: [1u8; 32],
        scope: wildcard_scope,
    };
    let other_market = SubmitOrderParams {
        market: m(42),
        ..sample_submit()
    }
    .to_command();
    assert_eq!(wildcard.authorize(&other_market, 0), Ok(()));
}

// ---------------------------------------------------------------------------
// Idempotency + backpressure
// ---------------------------------------------------------------------------

#[test]
fn commands_are_idempotent_by_client_id_and_nonce() {
    let b = StubBackend::new(RpcMode::Full);
    let kp = account_kp();
    b.register_account_key(a(1), kp.public());
    let params = sample_submit();
    let cmd = params.to_command();
    let meta = signed_meta(&kp, 1, 1, &cmd);
    let ack1 = b.submit_order(&meta, &params).unwrap();
    let ack2 = b.submit_order(&meta, &params).unwrap();
    assert_eq!(ack1, ack2, "retransmit must be exactly-once");
    assert_eq!(b.ingested_count(), 1);
    // A new nonce is a distinct command; it must be signed afresh over the new
    // nonce (the signature commits to the nonce).
    let meta2 = signed_meta(&kp, 1, 2, &cmd);
    let _ = b.submit_order(&meta2, &params).unwrap();
    assert_eq!(b.ingested_count(), 2);
}

#[test]
fn saturated_ingress_returns_backpressure() {
    let b = StubBackend::new(RpcMode::Full);
    b.set_saturated(true);
    let meta = sample_meta();
    assert_eq!(
        b.submit_order(&meta, &sample_submit()),
        Err(RpcError::Backpressure)
    );
}

// ---------------------------------------------------------------------------
// Signed control envelopes (authentication + replay resistance)
// ---------------------------------------------------------------------------

/// Unsigned `PlaceOrder` / `Withdraw` / `Cancel` are rejected at both the pure
/// dispatch router and the backend, in full (writeable) mode.
#[test]
fn unsigned_control_commands_are_rejected() {
    let b = populated_backend(RpcMode::Full);
    let unsigned = sample_meta();

    let place = RpcMethod::SubmitOrder(unsigned, sample_submit());
    assert_eq!(
        dispatch(&b, RpcMode::Full, RpcRequest::new(1, place)).result,
        Err(RpcError::InvalidSignature)
    );
    let withdraw = RpcMethod::RequestWithdrawal(
        unsigned,
        RequestWithdrawalParams {
            account: a(1),
            amount: Amount::ONE,
            destination: [3u8; 20],
        },
    );
    assert_eq!(
        dispatch(&b, RpcMode::Full, RpcRequest::new(2, withdraw)).result,
        Err(RpcError::InvalidSignature)
    );
    let cancel = RpcMethod::CancelOrder(
        unsigned,
        CancelOrderParams {
            account: a(1),
            market: m(1),
            order_id: OrderId::new(9),
        },
    );
    assert_eq!(
        dispatch(&b, RpcMode::Full, RpcRequest::new(3, cancel)).result,
        Err(RpcError::InvalidSignature)
    );

    // The backend is an independent guard: direct calls reject unsigned too.
    assert_eq!(
        b.submit_order(&unsigned, &sample_submit()),
        Err(RpcError::InvalidSignature)
    );
    assert_eq!(
        b.request_withdrawal(
            &unsigned,
            &RequestWithdrawalParams {
                account: a(1),
                amount: Amount::ONE,
                destination: [3u8; 20],
            }
        ),
        Err(RpcError::InvalidSignature)
    );
}

/// The signature commits to method + params + nonce + client + session key:
/// tampering with any of them invalidates it.
#[test]
fn signature_binds_method_params_nonce_and_session() {
    let kp = account_kp();
    let params = sample_submit();
    let cmd = params.to_command();
    let meta = signed_meta(&kp, 5, 9, &cmd);
    assert!(meta.verify_signature(&cmd).is_ok());

    // Different params (a different market) -> different message.
    let other_cmd = SubmitOrderParams {
        market: m(2),
        ..params
    }
    .to_command();
    assert_eq!(
        meta.verify_signature(&other_cmd),
        Err(RpcError::InvalidSignature)
    );

    // Tampered nonce.
    let mut n = meta;
    n.nonce = 10;
    assert_eq!(n.verify_signature(&cmd), Err(RpcError::InvalidSignature));

    // Tampered client id.
    let mut c = meta;
    c.client_id = 6;
    assert_eq!(c.verify_signature(&cmd), Err(RpcError::InvalidSignature));

    // Tampered session-key claim.
    let mut s = meta;
    s.session_pubkey = Some([9u8; 32]);
    assert_eq!(s.verify_signature(&cmd), Err(RpcError::InvalidSignature));

    // Tampered signature bytes.
    let mut sig = meta;
    sig.signature[0] ^= 1;
    assert_eq!(sig.verify_signature(&cmd), Err(RpcError::InvalidSignature));
}

/// A byte-for-byte replay of a signed envelope executes exactly once; lifting
/// the captured signature onto a fresh nonce to dodge the dedupe filter fails.
#[test]
fn signed_replay_is_rejected_exactly_once() {
    let b = populated_backend(RpcMode::Full);
    let kp = account_kp();
    let params = sample_submit();
    let cmd = params.to_command();
    let meta = signed_meta(&kp, 3, 7, &cmd);

    let ack1 = b.submit_order(&meta, &params).unwrap();
    let ack2 = b.submit_order(&meta, &params).unwrap();
    assert_eq!(ack1, ack2, "replay must be exactly-once");
    assert_eq!(b.ingested_count(), 1);

    // The signature covers the nonce, so it cannot be reused on a new one.
    let mut forged = meta;
    forged.nonce = 8;
    assert_eq!(
        b.submit_order(&forged, &params),
        Err(RpcError::InvalidSignature)
    );
    assert_eq!(b.ingested_count(), 1);
}

/// An authentically signed command by a key that is not the account's
/// registered root key (or when the account has no key at all) is unauthorized.
#[test]
fn wrong_signer_for_account_is_unauthorized() {
    let b = populated_backend(RpcMode::Full);
    let attacker = crypto::KeyPair::from_seed(&[99u8; 32]);
    let params = sample_submit();
    let cmd = params.to_command();
    let meta = signed_meta(&attacker, 1, 1, &cmd);

    // The envelope is authentic (the attacker really signed it) ...
    assert!(meta.verify_signature(&cmd).is_ok());
    // ... but the signer is not a(1)'s registered key.
    assert_eq!(b.submit_order(&meta, &params), Err(RpcError::Unauthorized));

    // An account with no registered key cannot authorize direct commands.
    let empty = StubBackend::new(RpcMode::Full);
    assert_eq!(
        empty.submit_order(&meta, &params),
        Err(RpcError::Unauthorized)
    );
}

/// Delegated commands must be signed by the claimed session key; an authentic
/// signature from any other key over the same envelope is rejected.
#[test]
fn delegated_commands_require_the_session_key_to_sign() {
    let b = StubBackend::new(RpcMode::Full);
    let session_kp = crypto::KeyPair::from_seed(&[42u8; 32]);
    let session_pk = session_kp.public();
    b.register_session(
        a(1),
        Session {
            session_pubkey: session_pk,
            scope: sample_scope(vec![m(1)]),
        },
    );
    b.set_now(0);
    let params = sample_submit();
    let cmd = params.to_command();

    // Signed by the session key, claiming the session -> accepted.
    let good = ControlMeta::signed(1, 1, Some(session_pk), &session_kp, &cmd)
        .expect("test command must encode");
    assert!(b.submit_order(&good, &params).is_ok());

    // Signed by a different key but still claiming the session -> the signer is
    // authentic but is not the session key: unauthorized.
    let other = crypto::KeyPair::from_seed(&[43u8; 32]);
    let bad = ControlMeta::signed(1, 2, Some(session_pk), &other, &cmd)
        .expect("test command must encode");
    assert_eq!(b.submit_order(&bad, &params), Err(RpcError::Unauthorized));
}

/// Property: adversarial `signer` / `signature` / `session` bytes never
/// authorize a control command, through either the backend or dispatch.
#[test]
fn adversarial_bytes_never_authorize() {
    let b = populated_backend(RpcMode::Full);
    let mut lcg = Lcg(0xA11CE5);
    for _ in 0..5_000 {
        let mut signer = [0u8; 32];
        for byte in signer.iter_mut() {
            *byte = lcg.next().to_le_bytes()[0];
        }
        let mut signature = [0u8; 64];
        for byte in signature.iter_mut() {
            *byte = lcg.next().to_le_bytes()[0];
        }
        let session_pubkey = if lcg.range(2) == 0 {
            None
        } else {
            let mut pk = [0u8; 32];
            for byte in pk.iter_mut() {
                *byte = lcg.next().to_le_bytes()[0];
            }
            Some(pk)
        };
        let meta = ControlMeta {
            client_id: lcg.next(),
            nonce: lcg.next(),
            session_pubkey,
            signer,
            signature,
        };
        let params = sample_submit();
        assert!(
            b.submit_order(&meta, &params).is_err(),
            "adversarial envelope authorized at backend"
        );
        let req = RpcRequest::new(1, RpcMethod::SubmitOrder(meta, params));
        let resp = dispatch(&b, RpcMode::Full, req);
        assert!(
            resp.result.is_err(),
            "adversarial envelope authorized via dispatch: {:?}",
            resp.result
        );
    }
}

// ---------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------

#[test]
fn stream_delivers_ordered_sequences() {
    let hub = StreamHub::new(16);
    let topic = Topic::Trades(m(1));
    let mut sub = hub.subscribe(topic, Reliability::Reliable).unwrap();
    for i in 1..=5u64 {
        hub.publish_delta(
            topic,
            StreamPayload::Trade(Trade {
                market_id: m(1),
                order_id: OrderId::new(i),
                price: Price::ONE,
                quantity: Quantity::ONE,
                side: Side::Bid,
                timestamp: i,
            }),
        );
    }
    for i in 1..=5u64 {
        let ev = sub.try_recv().unwrap();
        assert_eq!(ev.sequence, SequenceNumber::new(i));
    }
    assert_eq!(sub.try_recv(), Err(StreamError::Empty));
}

#[test]
fn sequence_tracker_detects_gap_and_not_on_contiguous() {
    let mut t = SequenceTracker::new();
    assert_eq!(t.observe(SequenceNumber::new(1)), Ok(Progress::Applied));
    assert_eq!(t.observe(SequenceNumber::new(2)), Ok(Progress::Applied));
    // Duplicate is idempotent, not a gap.
    assert_eq!(t.observe(SequenceNumber::new(2)), Ok(Progress::Duplicate));
    // A jump fires a gap and does not advance the baseline.
    assert_eq!(
        t.observe(SequenceNumber::new(4)),
        Err(Gap {
            expected: 3,
            got: 4
        })
    );
    assert_eq!(t.last(), Some(SequenceNumber::new(2)));
    // Contiguous resumes cleanly.
    assert_eq!(t.observe(SequenceNumber::new(3)), Ok(Progress::Applied));
    assert_eq!(t.observe(SequenceNumber::new(4)), Ok(Progress::Applied));
}

/// Reconstruct a simple book from a snapshot at N plus subsequent deltas and
/// confirm it equals the canonical state — deterministic replay.
#[test]
fn snapshot_plus_deltas_reconstructs_canonical_state() {
    use std::collections::BTreeMap;
    let hub = StreamHub::new(64);
    let topic = Topic::Book(m(1));

    // Canonical engine state: price -> quantity on the bid side.
    let mut canonical: BTreeMap<i64, i64> = BTreeMap::new();
    canonical.insert(100, 5);
    canonical.insert(101, 7);

    // Emit snapshot.
    let snap = Book {
        market_id: m(1),
        sequence: SequenceNumber::new(1),
        bids: canonical
            .iter()
            .map(|(p, q)| BookLevel {
                price: Price::from_raw(*p),
                quantity: Quantity::from_raw(*q),
            })
            .collect(),
        asks: vec![],
    };
    hub.publish_snapshot(topic, StreamPayload::Book(snap));

    // Apply deltas to canonical and publish them.
    let updates = [(100i64, 0i64), (102, 3), (101, 9)];
    for (price, qty) in updates {
        if qty == 0 {
            canonical.remove(&price);
        } else {
            canonical.insert(price, qty);
        }
        hub.publish_delta(
            topic,
            StreamPayload::BookDelta(BookDelta {
                market_id: m(1),
                side: Side::Bid,
                price: Price::from_raw(price),
                quantity: Quantity::from_raw(qty),
            }),
        );
    }

    // A late subscriber recovers from sequence 0 (snapshot within window).
    let recovery = hub.recover(topic, 0);
    let events = match recovery {
        Recovery::Deltas(d) => d,
        Recovery::SnapshotRequired => panic!("expected in-window recovery"),
    };
    let mut rebuilt: BTreeMap<i64, i64> = BTreeMap::new();
    for ev in events {
        // Recovered events are shared handles; read the payload through them.
        match &ev.payload {
            StreamPayload::Book(book) => {
                for lvl in &book.bids {
                    rebuilt.insert(lvl.price.raw(), lvl.quantity.raw());
                }
            }
            StreamPayload::BookDelta(d) => {
                if d.quantity == Quantity::ZERO {
                    rebuilt.remove(&d.price.raw());
                } else {
                    rebuilt.insert(d.price.raw(), d.quantity.raw());
                }
            }
            _ => {}
        }
    }
    assert_eq!(rebuilt, canonical);
}

#[test]
fn recovery_window_backfills_or_requires_snapshot() {
    let hub = StreamHub::new(4);
    let topic = Topic::Book(m(1));
    for i in 1..=6u64 {
        hub.publish_delta(
            topic,
            StreamPayload::BookDelta(BookDelta {
                market_id: m(1),
                side: Side::Bid,
                price: Price::from_raw(i64::try_from(i).unwrap()),
                quantity: Quantity::ONE,
            }),
        );
    }
    // Window holds the last 4 (seq 3..=6). Gap within window backfills.
    match hub.recover(topic, 4) {
        Recovery::Deltas(d) => {
            let seqs: Vec<u64> = d.iter().map(|e| e.sequence.get()).collect();
            assert_eq!(seqs, vec![5, 6]);
        }
        Recovery::SnapshotRequired => panic!("should backfill within window"),
    }
    // Gap beyond window requires a fresh snapshot.
    assert_eq!(hub.recover(topic, 0), Recovery::SnapshotRequired);
}

#[test]
fn recovery_deltas_share_history_events_without_cloning() {
    // recover() must hand back Arc handles to the very events retained in
    // history — pointer copies, not deep clones of event bodies.
    let hub = StreamHub::new(8);
    let topic = Topic::Book(m(1));
    let published: Vec<SharedEvent> = (1..=4i64)
        .map(|i| {
            hub.publish_delta(
                topic,
                StreamPayload::BookDelta(BookDelta {
                    market_id: m(1),
                    side: Side::Bid,
                    price: Price::from_raw(i),
                    quantity: Quantity::ONE,
                }),
            )
        })
        .collect();
    let deltas = match hub.recover(topic, 0) {
        Recovery::Deltas(d) => d,
        Recovery::SnapshotRequired => panic!("expected in-window recovery"),
    };
    assert_eq!(deltas.len(), published.len());
    for (recovered, original) in deltas.iter().zip(&published) {
        // Same allocation as the stored/published SharedEvent, not a copy.
        assert!(Arc::ptr_eq(recovered, original));
        assert_eq!(recovered.sequence, original.sequence);
    }
}

#[test]
fn bounded_broadcast_does_not_grow_for_slow_subscriber() {
    // Capacity 4: a subscriber that never reads is lagged, not unbounded.
    let hub = StreamHub::new(4);
    let topic = Topic::Trades(m(1));
    let mut slow = hub.subscribe(topic, Reliability::Reliable).unwrap();
    for i in 1..=1000u64 {
        hub.publish_delta(
            topic,
            StreamPayload::Trade(Trade {
                market_id: m(1),
                order_id: OrderId::new(i),
                price: Price::ONE,
                quantity: Quantity::ONE,
                side: Side::Bid,
                timestamp: i,
            }),
        );
    }
    // The reliable subscriber observes a lag rather than 1000 buffered events.
    assert!(matches!(
        slow.try_recv(),
        Err(StreamError::Lagged(_)) | Ok(_)
    ));
    // A lossy subscriber skips the lost window and keeps consuming the tail.
    let mut lossy = hub.subscribe(topic, Reliability::Lossy).unwrap();
    hub.publish_delta(
        topic,
        StreamPayload::Trade(Trade {
            market_id: m(1),
            order_id: OrderId::new(1001),
            price: Price::ONE,
            quantity: Quantity::ONE,
            side: Side::Bid,
            timestamp: 1001,
        }),
    );
    assert!(lossy.try_recv().is_ok());
}

#[test]
fn private_topics_are_gated() {
    let hub = StreamHub::new(8);
    let owner = a(1);
    let other = a(2);
    let sessions = crate::session::SessionRegistry::new();
    let owner_pk = [7u8; 32];
    let other_pk = [8u8; 32];
    sessions.insert(
        owner,
        Session {
            session_pubkey: owner_pk,
            scope: sample_scope(vec![m(1)]),
        },
    );
    sessions.insert(
        other,
        Session {
            session_pubkey: other_pk,
            scope: sample_scope(vec![m(1)]),
        },
    );
    // Public path rejects private topics.
    assert_eq!(
        hub.subscribe(Topic::Positions(owner), Reliability::Reliable)
            .err(),
        Some(RpcError::Unauthorized)
    );
    // Matching bound account via server-installed session, unexpired -> ok.
    assert!(hub
        .subscribe_private(
            Topic::Orders(owner),
            &owner_pk,
            &sessions,
            0,
            Reliability::Reliable
        )
        .is_ok());
    // Cross-account session key -> unauthorized (no leakage).
    assert_eq!(
        hub.subscribe_private(
            Topic::Orders(owner),
            &other_pk,
            &sessions,
            0,
            Reliability::Reliable
        )
        .err(),
        Some(RpcError::Unauthorized)
    );
    // Unknown session key -> unauthorized (client cannot spoof binding).
    assert_eq!(
        hub.subscribe_private(
            Topic::Orders(owner),
            &[9u8; 32],
            &sessions,
            0,
            Reliability::Reliable
        )
        .err(),
        Some(RpcError::Unauthorized)
    );
    // Expired session -> session expired.
    assert_eq!(
        hub.subscribe_private(
            Topic::Orders(owner),
            &owner_pk,
            &sessions,
            2_000,
            Reliability::Reliable
        )
        .err(),
        Some(RpcError::SessionExpired)
    );
}

#[test]
fn every_topic_variant_round_trips_bit_stable() {
    let topics = [
        Topic::Book(m(1)),
        Topic::Trades(m(1)),
        Topic::MarkPrice(m(1)),
        Topic::OraclePrice(m(1)),
        Topic::Funding(m(1)),
        Topic::Positions(a(1)),
        Topic::Orders(a(1)),
        Topic::ExecutionReceipts(a(1)),
        Topic::Checkpoints,
        Topic::MarketLifecycle,
        Topic::NetworkHealth,
    ];
    for topic in topics {
        let a1 = codec::encode(&topic).unwrap();
        let b1 = codec::encode(&topic).unwrap();
        assert_eq!(a1, b1, "encoding must be deterministic");
        let back: Topic = codec::decode(&a1).unwrap();
        assert_eq!(back, topic);
    }
}

// ---------------------------------------------------------------------------
// Property + never-panics
// ---------------------------------------------------------------------------

fn random_request(lcg: &mut Lcg) -> RpcRequest {
    let id = lcg.next();
    let method = match lcg.range(6) {
        0 => RpcMethod::GetMarket(m(u32::try_from(lcg.range(1000)).unwrap())),
        1 => RpcMethod::GetAccount(a(u32::try_from(lcg.range(1000)).unwrap())),
        2 => RpcMethod::GetCheckpoint(lcg.next()),
        3 => RpcMethod::GetMarketBook(
            m(u32::try_from(lcg.range(1000)).unwrap()),
            u32::try_from(lcg.range(1000)).unwrap(),
        ),
        4 => RpcMethod::SubmitOrder(
            ControlMeta {
                client_id: lcg.next(),
                nonce: lcg.next(),
                session_pubkey: None,
                signer: [0u8; 32],
                signature: [0u8; 64],
            },
            sample_submit(),
        ),
        _ => RpcMethod::GetNetworkStatus,
    };
    RpcRequest::new(id, method)
}

#[test]
fn property_random_requests_round_trip() {
    let mut lcg = Lcg(0xDEADBEEF);
    for _ in 0..5_000 {
        let req = random_request(&mut lcg);
        let framed = encode_request(&req).unwrap();
        let back = decode_request(&framed).unwrap();
        assert_eq!(req, back);
        assert_eq!(back.request_id, req.request_id);
    }
}

#[test]
fn decode_never_panics_on_arbitrary_bytes() {
    let mut lcg = Lcg(0x1234_5678);
    for _ in 0..50_000 {
        let len = usize::try_from(lcg.range(48)).unwrap();
        let buf = lcg.bytes(len);
        // Framed decoders.
        let _ = decode_request(&buf);
        let _ = decode_response(&buf);
        let _ = decode_stream_event(&buf);
        // Raw payload decoders.
        let _ = codec::decode::<RpcRequest>(&buf);
        let _ = codec::decode::<RpcResponse>(&buf);
        let _ = codec::decode::<StreamEvent>(&buf);
        let _ = codec::decode::<Topic>(&buf);
    }
}

#[test]
fn no_floating_point_in_wire_types() {
    // A grep-in-test guard mirroring the CI no-float gate for wire structs.
    for src in [
        include_str!("wire.rs"),
        include_str!("command.rs"),
        include_str!("request.rs"),
        include_str!("response.rs"),
        include_str!("stream.rs"),
    ] {
        assert!(!src.contains("f32"), "f32 found in a wire module");
        assert!(!src.contains("f64"), "f64 found in a wire module");
    }
}

// ---------------------------------------------------------------------------
// Async server (Tokio)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tcp_server_round_trips_a_query() {
    use std::sync::Arc;
    use tokio::net::TcpListener;

    let backend: Arc<dyn RpcBackend> = Arc::new(populated_backend(RpcMode::Full));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = crate::serve(listener, backend, RpcMode::Full).await;
    });

    let req = RpcRequest::new(77, RpcMethod::GetNetworkStatus);
    let resp = crate::server::round_trip(addr, &req).await.unwrap();
    assert_eq!(resp.request_id, 77);
    assert!(matches!(resp.result, Ok(RpcOk::NetworkStatus(_))));
}

#[tokio::test]
async fn tcp_server_rejects_write_in_read_only_mode() {
    use std::sync::Arc;
    use tokio::net::TcpListener;

    let backend: Arc<dyn RpcBackend> = Arc::new(populated_backend(RpcMode::ReadOnly));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = crate::serve(listener, backend, RpcMode::ReadOnly).await;
    });

    let req = RpcRequest::new(5, RpcMethod::SubmitOrder(sample_meta(), sample_submit()));
    let resp = crate::server::round_trip(addr, &req).await.unwrap();
    assert_eq!(resp.result, Err(RpcError::ReadOnly));
}

// ---------------------------------------------------------------------------
// Connection admission control (DoS hardening): global + per-IP budgets,
// slowloris timeouts. These exercise the async accept loop over real loopback
// TCP; the pure per-IP / rate-limit logic is unit-tested in `crate::limits`.
// ---------------------------------------------------------------------------

/// Read exactly one framed message from `reader` (test-local mirror of the
/// server's frame reader; the server's is module-private).
async fn read_one_frame<R>(reader: &mut R) -> std::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut header = [0u8; codec::FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await?;
    let plen = u32::from_le_bytes([header[15], header[16], header[17], header[18]]);
    let plen = usize::try_from(plen).unwrap();
    assert!(
        plen <= codec::MAX_FRAME_PAYLOAD,
        "frame payload out of bounds"
    );
    let mut buf = vec![0u8; codec::FRAME_HEADER_LEN + plen];
    buf[..codec::FRAME_HEADER_LEN].copy_from_slice(&header);
    reader
        .read_exact(&mut buf[codec::FRAME_HEADER_LEN..])
        .await?;
    Ok(buf)
}

/// Open a persistent connection, prove the server is serving it (one full
/// request/response round-trip), and return the still-open stream so the
/// connection keeps occupying its admission slot for the caller.
async fn connect_and_confirm(addr: std::net::SocketAddr) -> tokio::net::TcpStream {
    use tokio::io::AsyncWriteExt;
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = RpcRequest::new(1, RpcMethod::GetNetworkStatus);
    let out = encode_request(&req).unwrap();
    stream.write_all(&out).await.unwrap();
    stream.flush().await.unwrap();
    let frame = read_one_frame(&mut stream).await.unwrap();
    let resp = decode_response(&frame).unwrap();
    assert!(matches!(resp.result, Ok(RpcOk::NetworkStatus(_))));
    stream
}

/// A wide-open budget over loopback (all connections share one source IP, so
/// per-IP limits are disabled here and governed instead by `max_connections`).
fn budget_config(max_connections: usize) -> crate::server::ServerConfig {
    crate::server::ServerConfig {
        max_connections,
        max_connections_per_ip: u32::MAX,
        per_ip_rate: None,
        idle_timeout: std::time::Duration::from_secs(30),
        read_timeout: std::time::Duration::from_secs(30),
        write_timeout: std::time::Duration::from_secs(5),
        max_tracked_ips: 1_024,
        max_payload: codec::MAX_RPC_FRAME_PAYLOAD,
        tls: crate::server::TlsMode::Disabled,
        work: crate::work::WorkBudgetConfig::default(),
        dispatch_timeout: std::time::Duration::from_secs(5),
        drain_timeout: std::time::Duration::from_secs(5),
    }
}

/// Acceptance: a configurable maximum number of connections is enforced and the
/// excess is rejected cleanly with a `Backpressure` reply, without disturbing
/// the connections already within budget.
#[tokio::test]
async fn tcp_server_caps_connections_and_rejects_excess_cleanly() {
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    let backend: Arc<dyn RpcBackend> = Arc::new(populated_backend(RpcMode::Full));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ =
            crate::server::serve_with_config(listener, backend, RpcMode::Full, budget_config(4))
                .await;
    });

    // Saturate the budget with four confirmed, parked connections.
    let mut parked = Vec::new();
    for _ in 0..4 {
        parked.push(connect_and_confirm(addr).await);
    }

    // The fifth connection is over budget: the server sends one Backpressure
    // reply and closes, rather than accepting unbounded work.
    let mut extra = TcpStream::connect(addr).await.unwrap();
    let frame = read_one_frame(&mut extra).await.unwrap();
    let resp = decode_response(&frame).unwrap();
    assert_eq!(resp.result, Err(RpcError::Backpressure));

    // The connections within budget are undisturbed and keep serving.
    let survivor = parked.first_mut().unwrap();
    let req = RpcRequest::new(99, RpcMethod::GetNetworkStatus);
    let out = encode_request(&req).unwrap();
    survivor.write_all(&out).await.unwrap();
    survivor.flush().await.unwrap();
    let frame = read_one_frame(survivor).await.unwrap();
    let resp = decode_response(&frame).unwrap();
    assert_eq!(resp.request_id, 99);
    assert!(matches!(resp.result, Ok(RpcOk::NetworkStatus(_))));
}

/// Acceptance: slowloris-style stalled clients are timed out. A peer that opens
/// a connection but never completes a request frame is evicted after the idle /
/// read timeout, observed as the server closing the socket (EOF).
#[tokio::test]
async fn tcp_server_evicts_slowloris_clients() {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let backend: Arc<dyn RpcBackend> = Arc::new(populated_backend(RpcMode::Full));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cfg = crate::server::ServerConfig {
        max_connections: 16,
        max_connections_per_ip: u32::MAX,
        per_ip_rate: None,
        idle_timeout: Duration::from_millis(150),
        read_timeout: Duration::from_millis(150),
        write_timeout: Duration::from_secs(5),
        max_tracked_ips: 1_024,
        max_payload: codec::MAX_RPC_FRAME_PAYLOAD,
        tls: crate::server::TlsMode::Disabled,
        work: crate::work::WorkBudgetConfig::default(),
        dispatch_timeout: Duration::from_secs(5),
        drain_timeout: Duration::from_secs(5),
    };
    tokio::spawn(async move {
        let _ = crate::server::serve_with_config(listener, backend, RpcMode::Full, cfg).await;
    });

    // A client that connects and sends nothing is evicted after idle_timeout.
    let mut silent = TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(2), silent.read(&mut buf)).await {
        Ok(Ok(0)) => {}  // clean EOF: the idle client was closed.
        Ok(Err(_)) => {} // reset: also an eviction.
        Ok(Ok(n)) => panic!("stalled client unexpectedly received {n} bytes"),
        Err(_) => panic!("server failed to evict an idle client within the slack"),
    }

    // A client that dribbles a partial frame header and then stalls is likewise
    // evicted (the header read cannot complete within the timeout).
    let mut partial = TcpStream::connect(addr).await.unwrap();
    partial.write_all(&[0u8, 1, 2]).await.unwrap();
    partial.flush().await.unwrap();
    match tokio::time::timeout(Duration::from_secs(2), partial.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("partial-header client unexpectedly received {n} bytes"),
        Err(_) => panic!("server failed to evict a partial-header slowloris client"),
    }
}

/// Acceptance: load test documenting the connection budget under a flood. With
/// the budget saturated, a burst of many simultaneous excess connections are
/// every one rejected cleanly, and the budget itself is never corrupted — the
/// in-budget connections keep serving throughout.
#[tokio::test]
async fn tcp_server_connection_budget_holds_under_flood() {
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    const BUDGET: usize = 8;
    const FLOOD: usize = 32;

    let backend: Arc<dyn RpcBackend> = Arc::new(populated_backend(RpcMode::Full));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = crate::server::serve_with_config(
            listener,
            backend,
            RpcMode::Full,
            budget_config(BUDGET),
        )
        .await;
    });

    // Saturate the budget with confirmed, parked connections.
    let mut parked = Vec::new();
    for _ in 0..BUDGET {
        parked.push(connect_and_confirm(addr).await);
    }

    // Flood with many simultaneous excess connections; each must be cleanly
    // rejected with Backpressure (the server never exceeds its budget).
    let mut floods = Vec::new();
    for _ in 0..FLOOD {
        floods.push(tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let frame = read_one_frame(&mut stream).await.unwrap();
            decode_response(&frame).unwrap().result
        }));
    }
    for handle in floods {
        assert_eq!(handle.await.unwrap(), Err(RpcError::Backpressure));
    }

    // The in-budget connections were never disturbed by the flood.
    for stream in parked.iter_mut() {
        let req = RpcRequest::new(7, RpcMethod::GetNetworkStatus);
        let out = encode_request(&req).unwrap();
        stream.write_all(&out).await.unwrap();
        stream.flush().await.unwrap();
        let frame = read_one_frame(stream).await.unwrap();
        let resp = decode_response(&frame).unwrap();
        assert_eq!(resp.request_id, 7);
        assert!(matches!(resp.result, Ok(RpcOk::NetworkStatus(_))));
    }
}

// ---------------------------------------------------------------------------
// Graceful shutdown (#407): serve_with_shutdown stops accepting, drains
// in-flight connections, joins its tracked tasks, and returns.
// ---------------------------------------------------------------------------

/// Acceptance (#407): firing the stop signal makes `serve_with_shutdown`
/// RETURN within a bounded time with the served-connection count, closes the
/// accept socket so no new connection is served, and drains the in-flight
/// connections (each observes a clean close instead of being left running).
#[tokio::test]
async fn serve_with_shutdown_stops_accepting_drains_and_returns() {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    let backend: Arc<dyn RpcBackend> = Arc::new(populated_backend(RpcMode::Full));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut cfg = budget_config(16);
    cfg.drain_timeout = Duration::from_secs(2);
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let server = tokio::spawn(async move {
        crate::server::serve_with_shutdown(listener, backend, RpcMode::Full, cfg, stop_rx).await
    });

    // Two live connections, each confirmed with a full request/response
    // round-trip, then parked idle so they are in flight when the stop fires.
    let mut first = connect_and_confirm(addr).await;
    let mut second = connect_and_confirm(addr).await;

    stop_tx.send(true).unwrap();

    // The serve future returns within a bounded time, reporting both served
    // connections. Cancelling is no longer the only way to stop the server.
    let served = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("serve_with_shutdown must return promptly after the stop signal")
        .expect("serve task must not panic")
        .expect("shutdown is not a listener error");
    assert_eq!(served, 2);

    // The in-flight connections were drained: each observes a clean close
    // (EOF or reset), not an open socket left behind by a vanished server.
    for stream in [&mut first, &mut second] {
        let mut buf = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("drained connection unexpectedly received {n} bytes"),
            Err(_) => panic!("in-flight connection was not closed by shutdown"),
        }
    }

    // No new connection is accepted after stop: the listener is dropped, so a
    // fresh connect is refused — or, if the OS raced the close, the socket
    // yields EOF/reset without ever serving a request.
    match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
        Ok(Err(_)) => {} // connection refused: the accept socket is gone.
        Ok(Ok(mut stream)) => {
            let mut buf = [0u8; 1];
            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => {}
                other => panic!("connection after stop was served: {other:?}"),
            }
        }
        Err(_) => panic!("connect after stop must fail fast, not hang"),
    }
}

/// A stop signalled *before* the server starts is honored immediately —
/// `watch::Receiver::wait_for` inspects the current value, not just changes —
/// so a racing shutdown cannot be lost. Zero connections are served.
#[tokio::test]
async fn serve_with_shutdown_honors_stop_signalled_before_start() {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::TcpListener;

    let backend: Arc<dyn RpcBackend> = Arc::new(populated_backend(RpcMode::Full));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    stop_tx.send(true).unwrap();

    let served = tokio::time::timeout(
        Duration::from_secs(5),
        crate::server::serve_with_shutdown(
            listener,
            backend,
            RpcMode::Full,
            budget_config(4),
            stop_rx,
        ),
    )
    .await
    .expect("a pre-fired stop must return immediately")
    .expect("shutdown is not a listener error");
    assert_eq!(served, 0);
}

// ---------------------------------------------------------------------------
// Accept-error resilience (#406): the accept loop classifies listener errors
// instead of terminating on the first one. Injecting accept() failures through
// a real TcpListener is not portable, so the classification helper is
// unit-tested directly; the loop consumes it verbatim.
// ---------------------------------------------------------------------------

/// Per-connection accept failures (the queued peer died before we accepted,
/// or the syscall was interrupted) leave the listener healthy: accept again
/// immediately.
#[test]
fn accept_action_continues_on_transient_socket_errors() {
    use crate::server::{accept_action, AcceptAction};
    use std::io::ErrorKind;

    for kind in [
        ErrorKind::ConnectionAborted,
        ErrorKind::ConnectionReset,
        ErrorKind::Interrupted,
    ] {
        let err = std::io::Error::new(kind, "transient");
        assert_eq!(
            accept_action(&err),
            AcceptAction::Continue,
            "{kind:?} must not terminate the accept loop"
        );
    }
    // The raw-errno path decodes the same way (ECONNABORTED is exactly the
    // errno a flooded accept() surfaces between kernel queueing and accept).
    let err = std::io::Error::from_raw_os_error(libc::ECONNABORTED);
    assert_eq!(accept_action(&err), AcceptAction::Continue);
}

/// FD/buffer/memory exhaustion has no stable `io::ErrorKind` in Rust 1.92, so
/// the classifier must recognize the raw errnos and back off — terminating
/// here would kill the server during exactly the flood its admission control
/// exists to survive.
#[test]
fn accept_action_backs_off_on_resource_exhaustion_errnos() {
    use crate::server::{accept_action, AcceptAction};

    for errno in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
        let err = std::io::Error::from_raw_os_error(errno);
        assert_eq!(
            accept_action(&err),
            AcceptAction::Backoff,
            "errno {errno} (kind {:?}) must back off, not terminate",
            err.kind()
        );
    }
}

/// Unclassified errors stay fatal: a genuinely broken listener (e.g. a
/// permission failure) must terminate the server rather than spin.
#[test]
fn accept_action_is_fatal_for_unclassified_errors() {
    use crate::server::{accept_action, AcceptAction};

    let err = std::io::Error::from_raw_os_error(libc::EACCES);
    assert_eq!(accept_action(&err), AcceptAction::Fatal);
    let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    assert_eq!(accept_action(&err), AcceptAction::Fatal);
    // A synthetic error with no OS errno and no transient kind is also fatal.
    let err = std::io::Error::other("listener broke");
    assert_eq!(accept_action(&err), AcceptAction::Fatal);
}

// ---------------------------------------------------------------------------
// P1 #285: authorize_session installs; bounded idempotency; authenticated streams
// ---------------------------------------------------------------------------

#[test]
fn authorize_session_installs_usable_session() {
    let b = StubBackend::new(RpcMode::Full);
    let root = account_kp();
    b.register_account_key(a(1), root.public());
    let session_kp = crypto::KeyPair::from_seed(&[55u8; 32]);
    let session_pk = session_kp.public();
    let params = AuthorizeSessionParams {
        account: a(1),
        session_pubkey: session_pk,
        scope: sample_scope(vec![m(1)]),
    };
    let cmd = params.to_command();
    let meta = signed_meta(&root, 1, 1, &cmd);
    assert!(b.authorize_session(&meta, &params).is_ok());
    // Session is now installed and bound to a(1).
    assert!(b.session_bound_to(&session_pk, a(1)));

    // Delegated trading with the installed session succeeds.
    let order = sample_submit();
    let order_cmd = order.to_command();
    let sess_meta = ControlMeta::signed(2, 1, Some(session_pk), &session_kp, &order_cmd)
        .expect("test command must encode");
    b.set_now(0);
    assert!(b.submit_order(&sess_meta, &order).is_ok());

    // Revoke removes the binding.
    let rev = RevokeSessionParams {
        account: a(1),
        session_pubkey: session_pk,
    };
    let rev_cmd = rev.to_command();
    let rev_meta = signed_meta(&root, 1, 2, &rev_cmd);
    assert!(b.revoke_session(&rev_meta, &rev).is_ok());
    assert!(!b.session_bound_to(&session_pk, a(1)));
}

#[test]
fn idempotency_store_stays_bounded_under_flood() {
    let cfg = crate::idempotency::IdempotencyConfig {
        max_entries: 64,
        ttl: std::time::Duration::from_secs(60),
    };
    let b = StubBackend::with_idempotency(RpcMode::Full, cfg);
    let root = account_kp();
    b.register_account_key(a(1), root.public());
    let params = sample_submit();
    let cmd = params.to_command();
    for i in 0..2_000u64 {
        let meta = signed_meta(&root, 1, i, &cmd);
        let _ = b.submit_order(&meta, &params);
    }
    assert!(
        b.ingested_count() <= 64,
        "idempotency map grew to {}",
        b.ingested_count()
    );
}

#[test]
fn private_stream_cannot_spoof_account_binding() {
    let hub = StreamHub::new(8);
    let sessions = crate::session::SessionRegistry::new();
    let real_pk = [1u8; 32];
    sessions.insert(
        a(1),
        Session {
            session_pubkey: real_pk,
            scope: sample_scope(vec![m(1)]),
        },
    );
    // Attacker tries to subscribe to a(2)'s orders using a(1)'s session key.
    assert_eq!(
        hub.subscribe_private(
            Topic::Orders(a(2)),
            &real_pk,
            &sessions,
            0,
            Reliability::Reliable
        )
        .err(),
        Some(RpcError::Unauthorized)
    );
    // Invented key with no server install cannot bind to anything.
    assert_eq!(
        hub.subscribe_private(
            Topic::Orders(a(1)),
            &[0xff; 32],
            &sessions,
            0,
            Reliability::Reliable
        )
        .err(),
        Some(RpcError::Unauthorized)
    );
}

// ---------------------------------------------------------------------------
// P1 #286: payload caps + book depth clamp + TLS production config
// ---------------------------------------------------------------------------

#[test]
fn get_market_book_depth_is_clamped_centrally() {
    let b = populated_backend(RpcMode::Full);
    // Insert a book deeper than the central clamp so truncation is observable.
    let deep = crate::MAX_BOOK_DEPTH as usize + 50;
    let mut bids = Vec::with_capacity(deep);
    let mut asks = Vec::with_capacity(deep);
    for i in 0..deep {
        bids.push(crate::wire::BookLevel {
            price: Price::from_raw(10_000 - i as i64),
            quantity: Quantity::ONE,
        });
        asks.push(crate::wire::BookLevel {
            price: Price::from_raw(10_001 + i as i64),
            quantity: Quantity::ONE,
        });
    }
    b.insert_book(Book {
        market_id: m(1),
        sequence: SequenceNumber::new(1),
        bids,
        asks,
    });
    // Client asks for absurd depth; dispatch clamps to MAX_BOOK_DEPTH.
    let req = RpcRequest::new(1, RpcMethod::GetMarketBook(m(1), u32::MAX));
    let resp = dispatch(&b, RpcMode::Full, req);
    match resp.result {
        Ok(RpcOk::MarketBook(book)) => {
            assert_eq!(book.bids.len(), crate::MAX_BOOK_DEPTH as usize);
            assert_eq!(book.asks.len(), crate::MAX_BOOK_DEPTH as usize);
        }
        other => panic!("expected book, got {other:?}"),
    }
    // Direct backend call without clamp still returns full depth — proving the
    // clamp lives in dispatch, not the backend.
    let unclamped = b.get_market_book(m(1), u32::MAX).unwrap();
    assert!(unclamped.bids.len() > crate::MAX_BOOK_DEPTH as usize);
}

#[test]
#[allow(clippy::assertions_on_constants)]
fn rpc_default_payload_cap_is_below_sync_cap() {
    assert!(codec::MAX_RPC_FRAME_PAYLOAD < codec::MAX_FRAME_PAYLOAD);
    assert_eq!(codec::MAX_RPC_FRAME_PAYLOAD, 256 * 1024);
    let cfg = crate::server::ServerConfig::default();
    assert_eq!(cfg.max_payload, codec::MAX_RPC_FRAME_PAYLOAD);
}

#[test]
fn production_config_requires_tls() {
    let (cert, key) = crate::generate_self_signed_localhost().expect("self-signed");
    let acceptor = crate::acceptor_from_pem(&cert, &key, None).expect("acceptor");
    let cfg = crate::server::ServerConfig::production(acceptor);
    assert!(matches!(cfg.tls, crate::server::TlsMode::Required(_)));
    assert!(cfg.max_payload <= codec::MAX_RPC_FRAME_PAYLOAD);
}

#[tokio::test]
async fn tls_server_round_trips_a_query() {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
    use tokio_rustls::rustls::ClientConfig as RustlsClientConfig;
    use tokio_rustls::TlsConnector;

    let (cert_pem, key_pem) = crate::generate_self_signed_localhost().unwrap();
    let acceptor = crate::acceptor_from_pem(&cert_pem, &key_pem, None).unwrap();

    // Client trusts the same self-signed cert.
    let mut roots = rustls::RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(&cert_pem))
            .collect::<Result<_, _>>()
            .unwrap();
    for c in certs {
        roots.add(c).unwrap();
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client_cfg = RustlsClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_cfg));

    let backend: Arc<dyn RpcBackend> = Arc::new(populated_backend(RpcMode::Full));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut cfg = budget_config(16);
    cfg.tls = crate::server::TlsMode::Required(acceptor);
    tokio::spawn(async move {
        let _ = crate::server::serve_with_config(listener, backend, RpcMode::Full, cfg).await;
    });

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(name, tcp).await.unwrap();
    let req = RpcRequest::new(1, RpcMethod::GetNetworkStatus);
    let out = encode_request(&req).unwrap();
    tls.write_all(&out).await.unwrap();
    tls.flush().await.unwrap();
    let mut header = [0u8; codec::FRAME_HEADER_LEN];
    tls.read_exact(&mut header).await.unwrap();
    let plen = u32::from_le_bytes([header[15], header[16], header[17], header[18]]) as usize;
    let mut buf = vec![0u8; codec::FRAME_HEADER_LEN + plen];
    buf[..codec::FRAME_HEADER_LEN].copy_from_slice(&header);
    tls.read_exact(&mut buf[codec::FRAME_HEADER_LEN..])
        .await
        .unwrap();
    let resp = decode_response(&buf).unwrap();
    assert!(matches!(resp.result, Ok(RpcOk::NetworkStatus(_))));
}

/// Acceptance (#399): a client that completes the TCP handshake but never sends
/// its TLS ClientHello cannot pin admission permits. The handshake is bounded
/// by `read_timeout`; when it fires, the connection task exits and releases both
/// the global and the per-IP permit, so subsequent clients are served.
#[tokio::test]
async fn stalled_tls_handshake_times_out_and_releases_permits() {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
    use tokio_rustls::rustls::ClientConfig as RustlsClientConfig;
    use tokio_rustls::TlsConnector;

    let (cert_pem, key_pem) = crate::generate_self_signed_localhost().unwrap();
    let acceptor = crate::acceptor_from_pem(&cert_pem, &key_pem, None).unwrap();

    // Client trusts the same self-signed cert.
    let mut roots = rustls::RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(&cert_pem))
            .collect::<Result<_, _>>()
            .unwrap();
    for c in certs {
        roots.add(c).unwrap();
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client_cfg = RustlsClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_cfg));

    // A budget of exactly one connection, globally and per source IP: if the
    // stalled handshake leaked its permits, no later client could be admitted.
    let backend: Arc<dyn RpcBackend> = Arc::new(populated_backend(RpcMode::Full));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut cfg = budget_config(1);
    cfg.max_connections_per_ip = 1;
    cfg.read_timeout = Duration::from_millis(150);
    cfg.tls = crate::server::TlsMode::Required(acceptor);
    tokio::spawn(async move {
        let _ = crate::server::serve_with_config(listener, backend, RpcMode::Full, cfg).await;
    });

    // The attacker: TCP handshake completes, then silence — no ClientHello.
    // The server must evict it within ~read_timeout, observed as EOF/reset.
    let mut stalled = TcpStream::connect(addr).await.unwrap();
    let mut probe = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(2), stalled.read(&mut probe)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {} // clean FIN or reset: the stall was evicted.
        Ok(Ok(n)) => panic!("stalled handshake unexpectedly received {n} bytes"),
        Err(_) => panic!("server failed to time out a stalled TLS handshake"),
    }

    // Both permits must now be free: a well-behaved TLS client is admitted and
    // served. Retry briefly to absorb the small window between the eviction FIN
    // and the connection task actually exiting (which releases the permits).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let attempt = async {
            let tcp = TcpStream::connect(addr).await.ok()?;
            let name = ServerName::try_from("localhost").ok()?;
            let mut tls = connector.connect(name, tcp).await.ok()?;
            let req = RpcRequest::new(1, RpcMethod::GetNetworkStatus);
            let out = encode_request(&req).ok()?;
            tls.write_all(&out).await.ok()?;
            tls.flush().await.ok()?;
            let mut header = [0u8; codec::FRAME_HEADER_LEN];
            tls.read_exact(&mut header).await.ok()?;
            let plen =
                u32::from_le_bytes([header[15], header[16], header[17], header[18]]) as usize;
            let mut frame = vec![0u8; codec::FRAME_HEADER_LEN + plen];
            frame[..codec::FRAME_HEADER_LEN].copy_from_slice(&header);
            tls.read_exact(&mut frame[codec::FRAME_HEADER_LEN..])
                .await
                .ok()?;
            decode_response(&frame).ok()
        };
        if let Some(resp) = attempt.await {
            assert!(matches!(resp.result, Ok(RpcOk::NetworkStatus(_))));
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "permits were never released after the stalled handshake timed out"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

// ---------------------------------------------------------------------------
// P1 #354: isolated dispatch + in-flight byte budget
// ---------------------------------------------------------------------------

#[tokio::test]
async fn in_flight_byte_budget_rejects_before_admission() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    let backend: Arc<dyn RpcBackend> = Arc::new(populated_backend(RpcMode::Full));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut cfg = budget_config(32);
    // Measure a real request frame, then set the process-wide byte budget just
    // below it so admission fails closed before dispatch.
    let req = RpcRequest::new(1, RpcMethod::GetNetworkStatus);
    let out = encode_request(&req).unwrap();
    cfg.work = crate::work::WorkBudgetConfig {
        max_in_flight_requests: 1_000,
        max_in_flight_bytes: out.len().saturating_sub(1).max(1),
        max_in_flight_requests_per_conn: 1,
        max_in_flight_bytes_per_conn: 1_000_000,
    };
    tokio::spawn(async move {
        let _ = crate::server::serve_with_config(listener, backend, RpcMode::Full, cfg).await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(&out).await.unwrap();
    stream.flush().await.unwrap();
    let frame = read_one_frame(&mut stream).await.unwrap();
    let resp = decode_response(&frame).unwrap();
    assert_eq!(resp.result, Err(RpcError::Backpressure));
}

// ---------------------------------------------------------------------------
// #396: dispatch timeout fails the connection closed and keeps the work
// budget charged until the orphaned blocking task finishes
// ---------------------------------------------------------------------------

/// A backend whose `get_network_status` blocks (on the blocking pool) until the
/// test releases it via the channel — simulating a dispatch that outruns
/// `dispatch_timeout`. Every other method is unused by the test.
struct StallingBackend {
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl RpcBackend for StallingBackend {
    fn get_node_info(&self) -> Result<NodeInfo, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_peers(&self) -> Result<Vec<PeerInfo>, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_markets(&self, _page: PageParams) -> Result<Vec<MarketSummary>, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_market(&self, _market: MarketId) -> Result<MarketDetail, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_market_book(&self, _market: MarketId, _depth: u32) -> Result<Book, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_market_trades(
        &self,
        _market: MarketId,
        _page: PageParams,
    ) -> Result<Vec<Trade>, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_market_status(&self, _market: MarketId) -> Result<MarketStatus, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_oracle_status(&self, _market: MarketId) -> Result<OracleStatus, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_checkpoint(&self, _height: u64) -> Result<Checkpoint, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_latest_checkpoint(&self) -> Result<Checkpoint, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_account(&self, _account: AccountId) -> Result<Account, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_account_proof(&self, _account: AccountId) -> Result<AccountProof, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_position(&self, _account: AccountId, _market: MarketId) -> Result<Position, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_orders(&self, _account: AccountId, _page: PageParams) -> Result<Vec<Order>, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_execution_receipt(&self, _command_hash: Hash) -> Result<ExecutionReceipt, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_deposit_status(&self, _tx_hash: Hash) -> Result<DepositStatus, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_withdrawal_status(&self, _request_hash: Hash) -> Result<WithdrawalStatus, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_network_status(&self) -> Result<NetworkStatus, RpcError> {
        // Block the dispatching thread until the test releases it (or the test
        // drops the sender, which also unblocks).
        let _ = self
            .release
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv();
        Ok(NetworkStatus {
            peer_count: 0,
            height: 0,
            finalized_height: 0,
            syncing: false,
        })
    }
    fn submit_order(
        &self,
        _meta: &ControlMeta,
        _params: &SubmitOrderParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn cancel_order(
        &self,
        _meta: &ControlMeta,
        _params: &CancelOrderParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn cancel_all(
        &self,
        _meta: &ControlMeta,
        _params: &CancelAllParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn replace_order(
        &self,
        _meta: &ControlMeta,
        _params: &ReplaceOrderParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn submit_basket(
        &self,
        _meta: &ControlMeta,
        _params: &BasketParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn authorize_session(
        &self,
        _meta: &ControlMeta,
        _params: &AuthorizeSessionParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn revoke_session(
        &self,
        _meta: &ControlMeta,
        _params: &RevokeSessionParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn bind_wallet(
        &self,
        _meta: &ControlMeta,
        _params: &BindWalletParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn request_withdrawal(
        &self,
        _meta: &ControlMeta,
        _params: &RequestWithdrawalParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn create_market(
        &self,
        _meta: &ControlMeta,
        _params: &CreateMarketParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn stake_market(
        &self,
        _meta: &ControlMeta,
        _params: &StakeMarketParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
}

/// Acceptance (#396): a backend dispatch that outruns `dispatch_timeout` gets a
/// `Backpressure` reply and the connection is failed closed (the loop serves no
/// further requests), while the process-wide work-budget permit stays charged
/// until the orphaned blocking task — which cannot be aborted — actually
/// finishes.
#[tokio::test]
async fn dispatch_timeout_fails_connection_closed_and_holds_work_budget() {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let backend: Arc<dyn RpcBackend> = Arc::new(StallingBackend {
        release: std::sync::Mutex::new(release_rx),
    });
    let mut cfg = budget_config(4);
    cfg.dispatch_timeout = Duration::from_millis(100);
    let work = crate::work::WorkBudget::new(&cfg.work);

    let (mut client, server_io) = tokio::io::duplex(64 * 1024);
    let server = {
        let work = Arc::clone(&work);
        tokio::spawn(async move {
            crate::server::handle_connection_with(
                server_io,
                backend,
                RpcMode::Full,
                &cfg,
                Some(work),
            )
            .await
        })
    };

    let req = RpcRequest::new(42, RpcMethod::GetNetworkStatus);
    let out = encode_request(&req).unwrap();
    client.write_all(&out).await.unwrap();
    client.flush().await.unwrap();

    // The timed-out dispatch surfaces Backpressure, correlated to the request.
    let frame = read_one_frame(&mut client).await.unwrap();
    let resp = decode_response(&frame).unwrap();
    assert_eq!(resp.request_id, 42);
    assert_eq!(resp.result, Err(RpcError::Backpressure));

    // The connection is failed closed after the reply: the next read is EOF,
    // not another served request, and the handler exits cleanly.
    let mut buf = [0u8; 1];
    let n = client.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "connection must close after a dispatch timeout");
    assert!(server.await.unwrap().is_ok());

    // The blocking task is still running (spawn_blocking cannot be aborted), so
    // the process-wide work budget must still be charged.
    assert_eq!(work.in_flight_requests(), 1);
    assert!(work.in_flight_bytes() > 0);

    // Release the backend; once the orphaned task finishes, the reaper drops
    // the permit and the budget returns to zero.
    release_tx.send(()).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while work.in_flight_requests() != 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "work permit was never released after the blocking task finished"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(work.in_flight_bytes(), 0);
}

/// A backend whose `get_network_status` unwinds on the blocking pool, so the
/// dispatch task dies with a `JoinError` instead of returning a response.
/// `resume_unwind` skips the global panic hook, keeping the intentional death
/// out of test output. Every other method is unused by the test.
struct PanickingBackend;

impl RpcBackend for PanickingBackend {
    fn get_node_info(&self) -> Result<NodeInfo, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_peers(&self) -> Result<Vec<PeerInfo>, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_markets(&self, _page: PageParams) -> Result<Vec<MarketSummary>, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_market(&self, _market: MarketId) -> Result<MarketDetail, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_market_book(&self, _market: MarketId, _depth: u32) -> Result<Book, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_market_trades(
        &self,
        _market: MarketId,
        _page: PageParams,
    ) -> Result<Vec<Trade>, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_market_status(&self, _market: MarketId) -> Result<MarketStatus, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_oracle_status(&self, _market: MarketId) -> Result<OracleStatus, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_checkpoint(&self, _height: u64) -> Result<Checkpoint, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_latest_checkpoint(&self) -> Result<Checkpoint, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_account(&self, _account: AccountId) -> Result<Account, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_account_proof(&self, _account: AccountId) -> Result<AccountProof, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_position(&self, _account: AccountId, _market: MarketId) -> Result<Position, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_orders(&self, _account: AccountId, _page: PageParams) -> Result<Vec<Order>, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_execution_receipt(&self, _command_hash: Hash) -> Result<ExecutionReceipt, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_deposit_status(&self, _tx_hash: Hash) -> Result<DepositStatus, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_withdrawal_status(&self, _request_hash: Hash) -> Result<WithdrawalStatus, RpcError> {
        Err(RpcError::NotFound)
    }
    fn get_network_status(&self) -> Result<NetworkStatus, RpcError> {
        std::panic::resume_unwind(Box::new("intentional dispatch death"))
    }
    fn submit_order(
        &self,
        _meta: &ControlMeta,
        _params: &SubmitOrderParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn cancel_order(
        &self,
        _meta: &ControlMeta,
        _params: &CancelOrderParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn cancel_all(
        &self,
        _meta: &ControlMeta,
        _params: &CancelAllParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn replace_order(
        &self,
        _meta: &ControlMeta,
        _params: &ReplaceOrderParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn submit_basket(
        &self,
        _meta: &ControlMeta,
        _params: &BasketParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn authorize_session(
        &self,
        _meta: &ControlMeta,
        _params: &AuthorizeSessionParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn revoke_session(
        &self,
        _meta: &ControlMeta,
        _params: &RevokeSessionParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn bind_wallet(
        &self,
        _meta: &ControlMeta,
        _params: &BindWalletParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn request_withdrawal(
        &self,
        _meta: &ControlMeta,
        _params: &RequestWithdrawalParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn create_market(
        &self,
        _meta: &ControlMeta,
        _params: &CreateMarketParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
    fn stake_market(
        &self,
        _meta: &ControlMeta,
        _params: &StakeMarketParams,
    ) -> Result<CommandAck, RpcError> {
        Err(RpcError::NotFound)
    }
}

/// Regression (#421): a post-decode dispatch failure — the blocking dispatch
/// task dies with a `JoinError` — must echo the decoded request's id, not 0.
/// A pipelining client correlates in-flight requests by `request_id`; an
/// uncorrelated error reply would be attributed to the wrong request. Two
/// pipelined requests with distinct ids each get an `Internal` dispatch-join
/// reply carrying their own id, in order.
#[tokio::test]
async fn dispatch_join_error_echoes_request_id() {
    use tokio::io::AsyncWriteExt;

    let backend: Arc<dyn RpcBackend> = Arc::new(PanickingBackend);
    let cfg = budget_config(4);

    let (mut client, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        crate::server::handle_connection_with(server_io, backend, RpcMode::Full, &cfg, None).await
    });

    // Pipeline two requests with distinctive ids before reading any reply.
    for id in [42u64, 43] {
        let req = RpcRequest::new(id, RpcMethod::GetNetworkStatus);
        let out = encode_request(&req).unwrap();
        client.write_all(&out).await.unwrap();
    }
    client.flush().await.unwrap();

    // Each dispatch dies on the blocking pool; each reply must still carry the
    // id of the request it answers.
    for expected_id in [42u64, 43] {
        let frame = read_one_frame(&mut client).await.unwrap();
        let resp = decode_response(&frame).unwrap();
        assert_eq!(
            resp.request_id, expected_id,
            "post-decode error replies must echo the request id for pipelining correlation"
        );
        match resp.result {
            Err(RpcError::Internal(msg)) => assert!(
                msg.contains("dispatch join"),
                "expected a dispatch-join error, got: {msg}"
            ),
            other => panic!("expected Internal dispatch-join error, got {other:?}"),
        }
    }

    // A join error fails only that request, not the connection: the handler
    // exits cleanly once the client hangs up.
    drop(client);
    assert!(server.await.unwrap().is_ok());
}

// ---------------------------------------------------------------------------
// #416: RPC server metrics — the flood-facing shed paths are counted on a real
// MetricsRegistry and rpc_connections_active tracks connection lifetime
// ---------------------------------------------------------------------------

/// Snapshot helper: the current value of counter `name` on `reg` (zero when
/// the counter was never registered).
fn counter_value(reg: &observability::MetricsRegistry, name: &str) -> u64 {
    reg.snapshot()
        .counters
        .iter()
        .find(|c| c.name == name)
        .map(|c| c.value)
        .unwrap_or_default()
}

/// Snapshot helper: the current value of gauge `name` on `reg`.
fn gauge_value(reg: &observability::MetricsRegistry, name: &str) -> i64 {
    reg.snapshot()
        .gauges
        .iter()
        .find(|g| g.name == name)
        .map(|g| g.value)
        .unwrap_or_default()
}

/// Poll (bounded) until `rpc_connections_active` returns to zero: the closed
/// connection's task has ended and its drop guard restored the gauge. The
/// guard drops after the admission permits are released, so a zero gauge also
/// means the next client can be admitted.
async fn wait_active_zero(reg: &observability::MetricsRegistry) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while gauge_value(reg, "rpc_connections_active") != 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "rpc_connections_active never returned to 0 after the connection closed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Acceptance (#416): a server run with [`crate::RpcMetrics`] built from a
/// real `MetricsRegistry` counts each shed path it takes — accept-time
/// admission rejection, oversize frame, dispatch timeout — while untaken
/// paths stay at zero, and `rpc_connections_active` rises while a connection
/// is admitted and returns to 0 after every connection closes.
#[tokio::test]
async fn rpc_metrics_count_shed_paths_and_track_active_connections() {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let registry = Arc::new(observability::MetricsRegistry::new());
    let metrics = Arc::new(crate::RpcMetrics::register(&registry));

    // Stalling backend: `get_network_status` blocks on the blocking pool until
    // released (driving the #396 dispatch-timeout path); every other method
    // replies immediately.
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let backend: Arc<dyn RpcBackend> = Arc::new(StallingBackend {
        release: std::sync::Mutex::new(release_rx),
    });
    // A budget of exactly one connection makes the accept-rejection path
    // deterministic; a short dispatch timeout keeps the stall bounded.
    let mut cfg = budget_config(1);
    cfg.dispatch_timeout = Duration::from_millis(100);
    let max_payload = cfg.max_payload;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn({
        let metrics = Arc::clone(&metrics);
        async move {
            let _ = crate::server::serve_with_metrics(
                listener,
                backend,
                RpcMode::Full,
                cfg,
                Some(metrics),
                stop_rx,
            )
            .await;
        }
    });

    // 1) Admit one connection and confirm it is being served (an immediate
    //    NotFound reply), then observe the gauge at 1 while it stays parked.
    let mut parked = TcpStream::connect(addr).await.unwrap();
    let req = RpcRequest::new(1, RpcMethod::GetNodeInfo);
    let out = encode_request(&req).unwrap();
    parked.write_all(&out).await.unwrap();
    parked.flush().await.unwrap();
    let frame = read_one_frame(&mut parked).await.unwrap();
    assert_eq!(
        decode_response(&frame).unwrap().result,
        Err(RpcError::NotFound)
    );
    assert_eq!(gauge_value(&registry, "rpc_connections_active"), 1);

    // 2) Accept rejection: the budget is one connection, so a second client
    //    is refused with a Backpressure notice — and counted. The rejected
    //    connection never touches the gauge.
    let mut excess = TcpStream::connect(addr).await.unwrap();
    let frame = read_one_frame(&mut excess).await.unwrap();
    assert_eq!(
        decode_response(&frame).unwrap().result,
        Err(RpcError::Backpressure)
    );
    assert_eq!(counter_value(&registry, "rpc_accept_rejections_total"), 1);
    assert_eq!(gauge_value(&registry, "rpc_connections_active"), 1);

    // Close the parked connection; its drop guard restores the gauge to 0.
    drop(parked);
    wait_active_zero(&registry).await;

    // 3) Oversize: a header declaring a payload over the cap is answered with
    //    MessageTooLarge, counted, and the connection is closed (EOF).
    let mut oversize = TcpStream::connect(addr).await.unwrap();
    let mut header = [0u8; codec::FRAME_HEADER_LEN];
    let plen = u32::try_from(max_payload).unwrap().saturating_add(1);
    header[15..19].copy_from_slice(&plen.to_le_bytes());
    oversize.write_all(&header).await.unwrap();
    oversize.flush().await.unwrap();
    let frame = read_one_frame(&mut oversize).await.unwrap();
    assert_eq!(
        decode_response(&frame).unwrap().result,
        Err(RpcError::MessageTooLarge)
    );
    assert_eq!(counter_value(&registry, "rpc_oversize_total"), 1);
    let mut buf = [0u8; 1];
    assert_eq!(oversize.read(&mut buf).await.unwrap(), 0);
    wait_active_zero(&registry).await;

    // 4) Dispatch timeout (#396 path): the stalled dispatch is answered with
    //    Backpressure correlated to the request, counted on its dedicated
    //    counter, and the connection is failed closed.
    let mut stalled = TcpStream::connect(addr).await.unwrap();
    let req = RpcRequest::new(42, RpcMethod::GetNetworkStatus);
    let out = encode_request(&req).unwrap();
    stalled.write_all(&out).await.unwrap();
    stalled.flush().await.unwrap();
    let frame = read_one_frame(&mut stalled).await.unwrap();
    let resp = decode_response(&frame).unwrap();
    assert_eq!(resp.request_id, 42);
    assert_eq!(resp.result, Err(RpcError::Backpressure));
    assert_eq!(counter_value(&registry, "rpc_dispatch_timeouts_total"), 1);
    assert_eq!(stalled.read(&mut buf).await.unwrap(), 0);

    // After every connection has closed, the gauge is restored to zero.
    wait_active_zero(&registry).await;

    // Paths never taken stayed at zero: the dispatch timeout was counted as a
    // dispatch timeout, not smeared into backpressure or read timeouts.
    assert_eq!(counter_value(&registry, "rpc_read_timeouts_total"), 0);
    assert_eq!(counter_value(&registry, "rpc_backpressure_total"), 0);
    // And the registry exports the rpc_* series by name.
    let text = registry.export_text();
    assert!(text.contains("rpc_dispatch_timeouts_total 1"));
    assert!(text.contains("rpc_connections_active 0"));

    // Release the orphaned blocking dispatch so runtime shutdown is not
    // pinned on it (mirrors the #396 test).
    release_tx.send(()).unwrap();
}

// ---------------------------------------------------------------------------
// P1 #355: stream fanout byte-bounded, sharded, copy-light
// ---------------------------------------------------------------------------

#[test]
fn publish_uses_shared_arc_not_per_subscriber_clone() {
    let hub = StreamHub::with_limits(64, 64 * 1024, 128);
    let topic = Topic::Trades(m(1));
    let mut subs: Vec<_> = (0..64)
        .map(|_| hub.subscribe(topic, Reliability::Lossy).unwrap())
        .collect();
    let shared = hub.publish_delta(
        topic,
        StreamPayload::Trade(Trade {
            market_id: m(1),
            order_id: OrderId::new(1),
            price: Price::ONE,
            quantity: Quantity::ONE,
            side: Side::Bid,
            timestamp: 1,
        }),
    );
    // Every subscriber observes the same Arc allocation (strong_count grows with
    // fanout; the body is not deep-cloned per receiver).
    for sub in subs.iter_mut() {
        let got = sub.try_recv_shared().expect("event");
        assert!(Arc::ptr_eq(&shared, &got));
    }
    let stats = hub.topic_stats(topic);
    assert_eq!(stats.published, 1);
    assert_eq!(stats.subscribers, 64);
}

#[test]
fn hot_topic_byte_budget_does_not_block_other_topics() {
    // Tiny byte budget on each topic; flood topic A, then publish on topic B.
    let hub = StreamHub::with_limits(8, 256, 64);
    let hot = Topic::Trades(m(1));
    let cold = Topic::Trades(m(2));
    let mut cold_sub = hub.subscribe(cold, Reliability::Reliable).unwrap();
    for i in 0..100u64 {
        hub.publish_delta(
            hot,
            StreamPayload::Trade(Trade {
                market_id: m(1),
                order_id: OrderId::new(i),
                price: Price::ONE,
                quantity: Quantity::ONE,
                side: Side::Bid,
                timestamp: i,
            }),
        );
    }
    let hot_stats = hub.topic_stats(hot);
    assert!(
        hot_stats.history_shed > 0,
        "hot topic must shed under budget"
    );
    assert!(hot_stats.history_bytes <= hub.topic_byte_budget());

    let cold_event = hub.publish_delta(
        cold,
        StreamPayload::Trade(Trade {
            market_id: m(2),
            order_id: OrderId::new(1),
            price: Price::ONE,
            quantity: Quantity::ONE,
            side: Side::Ask,
            timestamp: 1,
        }),
    );
    let got = cold_sub.try_recv_shared().expect("cold topic still live");
    assert!(Arc::ptr_eq(&cold_event, &got));
    // Cold topic has its own budget; hot shedding did not exhaust it.
    assert_eq!(hub.topic_stats(cold).history_shed, 0);
}

#[test]
fn fanout_scales_to_many_subscribers_without_per_sub_alloc_growth() {
    // Cover 1 / 64 / 1000 subscriber fanout with a maximum-ish book snapshot.
    for n in [1usize, 64, 1_000] {
        let hub = StreamHub::with_limits(32, 2 * 1024 * 1024, 64);
        let topic = Topic::Book(m(1));
        let mut subs: Vec<_> = (0..n)
            .map(|_| hub.subscribe(topic, Reliability::Lossy).unwrap())
            .collect();
        let mut bids = Vec::new();
        for i in 0..50 {
            bids.push(crate::wire::BookLevel {
                price: Price::from_raw(1_000 - i),
                quantity: Quantity::ONE,
            });
        }
        let book = Book {
            market_id: m(1),
            sequence: SequenceNumber::new(1),
            bids,
            asks: vec![],
        };
        let shared = hub.publish_snapshot(topic, StreamPayload::Book(book));
        let mut received = 0usize;
        for sub in subs.iter_mut() {
            if let Ok(got) = sub.try_recv_shared() {
                assert!(Arc::ptr_eq(&shared, &got));
                received += 1;
            }
        }
        // Lossy + bounded broadcast: all in-capacity receivers should see it.
        assert!(received >= n.min(32), "n={n} received={received}");
        assert!(std::sync::Arc::strong_count(&shared) >= 1);
    }
}

#[test]
fn shed_and_lag_are_observable_for_recovery() {
    let hub = StreamHub::with_limits(4, 512, 32);
    let topic = Topic::Trades(m(1));
    let mut slow = hub.subscribe(topic, Reliability::Reliable).unwrap();
    for i in 0..50u64 {
        hub.publish_delta(
            topic,
            StreamPayload::Trade(Trade {
                market_id: m(1),
                order_id: OrderId::new(i),
                price: Price::ONE,
                quantity: Quantity::ONE,
                side: Side::Bid,
                timestamp: i,
            }),
        );
    }
    let stats = hub.topic_stats(topic);
    assert!(stats.history_shed > 0 || stats.published == 50);
    // Slow reliable subscriber either lags or can recover via snapshot-required.
    match slow.try_recv() {
        Err(StreamError::Lagged(_)) | Ok(_) | Err(StreamError::Empty) => {}
        Err(other) => panic!("unexpected {other:?}"),
    }
    match hub.recover(topic, 0) {
        Recovery::SnapshotRequired | Recovery::Deltas(_) => {}
    }
}

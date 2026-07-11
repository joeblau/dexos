//! Unit, property (in-test LCG), and never-panics tests for the RPC crate.

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
    ControlMeta::signed(client_id, nonce, None, kp, command)
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
            verification_status: VerificationStatus::ProofValid,
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
    assert_eq!(proof.verification_status, VerificationStatus::ProofValid);
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
    let good = ControlMeta::signed(1, 1, Some(session_pk), &session_kp, &cmd);
    assert!(b.submit_order(&good, &params).is_ok());

    // Signed by a different key but still claiming the session -> the signer is
    // authentic but is not the session key: unauthorized.
    let other = crypto::KeyPair::from_seed(&[43u8; 32]);
    let bad = ControlMeta::signed(1, 2, Some(session_pk), &other, &cmd);
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
        match ev.payload {
            StreamPayload::Book(book) => {
                for lvl in book.bids {
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
    // Public path rejects private topics.
    assert_eq!(
        hub.subscribe(Topic::Positions(owner), Reliability::Reliable)
            .err(),
        Some(RpcError::Unauthorized)
    );
    // Matching bound account, unexpired -> ok.
    assert!(hub
        .subscribe_private(Topic::Orders(owner), owner, 1_000, 0, Reliability::Reliable)
        .is_ok());
    // Cross-account -> unauthorized (no leakage).
    assert_eq!(
        hub.subscribe_private(Topic::Orders(owner), other, 1_000, 0, Reliability::Reliable)
            .err(),
        Some(RpcError::Unauthorized)
    );
    // Expired -> session expired.
    assert_eq!(
        hub.subscribe_private(
            Topic::Orders(owner),
            owner,
            1_000,
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

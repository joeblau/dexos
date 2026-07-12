//! `execution` — the deterministic replicated execution engine.
//!
//! Single-writer per shard, integer-only, no async runtime, no networking, no
//! storage-engine dependency. Applies a canonical [`Command`] stream through the
//! [`DeterministicEngine`] trait, producing receipts and an incremental state root
//! that is bit-identical across deterministic replay.

pub mod command;
pub mod engine;
pub mod error;
pub mod ledger;
pub mod session;

pub use command::{
    Authorization, AuthorizeSession, BindWallet, CancelAll, CancelOrder, Command, CompleteSetOp,
    CreateAccount, CreateMarket, DepositCredit, DeterministicEngine, ExecutionReceipt,
    FinalizeWithdrawal, PlaceOrder, ProtocolUpgrade, ReceiptKind, ReplaceOrder, RequestWithdrawal,
    RevokeSession, SetMarkPrice, Timestamp,
};
pub use engine::{Engine, EngineConfig, WalletBinding};
pub use error::ExecutionError;
pub use ledger::Ledger;
pub use session::SessionRegistry;

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "execution";

#[cfg(test)]
mod tests {
    use super::*;
    use types::{
        AccountId, Amount, MarketId, MarketType, OrderId, OrderType, Price, Quantity,
        SequenceNumber, Side, TimeInForce,
    };

    fn engine() -> Engine {
        Engine::new(EngineConfig::default())
    }

    // A perp market at mark 1.0 with two 100.0-collateral accounts, then a
    // realized-PnL cycle followed by a withdrawal. Account 0 is the maker,
    // account 1 the taker. The taker opens a short at 1.0, buys 1 back at 1.1
    // (realizing a 0.1 loss into risk collateral only — the settlement ledger is
    // untouched by fills), then withdraws 10.0. This is the "withdraw after
    // trade" divergence scenario from the acceptance criteria.
    fn trade_and_withdraw_script() -> Vec<Command> {
        let market = MarketId::new(0);
        let (maker, taker) = (AccountId::new(0), AccountId::new(1));
        let order = |account, order_id, side, price, qty| {
            Command::PlaceOrder(PlaceOrder {
                account,
                market,
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
        };
        vec![
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(100_000_000),
            }),
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(100_000_000),
            }),
            Command::CreateMarket(CreateMarket {
                market,
                market_type: MarketType::Perpetual,
                outcomes: 1,
                mark_price: Price::from_raw(1_000_000),
            }),
            // Maker rests a bid; taker crosses -> maker long 2, taker short 2.
            order(maker, 1, Side::Bid, 1_000_000, 2_000_000),
            order(taker, 2, Side::Ask, 1_000_000, 2_000_000),
            // Maker rests an ask at 1.1; taker buys 1 back -> realizes PnL.
            order(maker, 3, Side::Ask, 1_100_000, 1_000_000),
            order(taker, 4, Side::Bid, 1_100_000, 1_000_000),
            // Taker withdraws 10.0 after the trade.
            Command::RequestWithdrawal(RequestWithdrawal {
                account: taker,
                amount: amt(10_000_000),
                nonce: 1,
                destination_chain: 1,
                destination_address: vec![1, 2, 3],
                auth: Authorization::Master,
            }),
        ]
    }

    // Build a fresh engine and apply `cmds`, panicking on any failure.
    fn apply_all(cmds: &[Command]) -> Engine {
        let mut e = engine();
        for (i, c) in cmds.iter().enumerate() {
            e.execute(seq(i as u64 + 1), c.clone()).expect("apply");
        }
        e
    }

    fn seq(n: u64) -> SequenceNumber {
        SequenceNumber::new(n)
    }

    fn amt(x: i128) -> Amount {
        Amount::from_raw(x)
    }

    // Apply a script of commands, returning the final state root.
    fn run(cmds: &[Command]) -> types::Hash {
        let mut e = engine();
        for (i, c) in cmds.iter().enumerate() {
            e.execute(seq(i as u64 + 1), c.clone()).expect("apply");
        }
        e.state_root()
    }

    #[test]
    fn account_creation_is_dense_and_deterministic() {
        let mut e = engine();
        let r0 = e
            .execute(
                seq(1),
                Command::CreateAccount(CreateAccount {
                    initial_collateral: amt(1_000_000),
                }),
            )
            .unwrap();
        let r1 = e
            .execute(
                seq(2),
                Command::CreateAccount(CreateAccount {
                    initial_collateral: amt(0),
                }),
            )
            .unwrap();
        assert_eq!(
            r0.kind,
            ReceiptKind::AccountCreated(types::AccountId::new(0))
        );
        assert_eq!(
            r1.kind,
            ReceiptKind::AccountCreated(types::AccountId::new(1))
        );
        assert!(e.ledger().conservation_holds());
        assert_eq!(e.ledger().total_supply(), amt(1_000_000));
    }

    #[test]
    fn deposit_is_idempotent_on_source_coordinates() {
        let mut e = engine();
        e.execute(
            seq(1),
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(0),
            }),
        )
        .unwrap();
        let acct = types::AccountId::new(0);
        let dep = Command::DepositCredit(DepositCredit {
            source_chain: 1,
            source_tx: vec![0xaa; 32],
            source_event_index: 0,
            account: acct,
            amount: amt(500_000),
        });
        e.execute(seq(2), dep.clone()).unwrap();
        assert_eq!(e.ledger().available(acct).unwrap(), amt(500_000));
        // Replay of the same certificate is rejected; balance unchanged.
        assert_eq!(
            e.execute(seq(3), dep),
            Err(ExecutionError::DuplicateDeposit)
        );
        assert_eq!(e.ledger().available(acct).unwrap(), amt(500_000));
        assert!(e.ledger().conservation_holds());
    }

    #[test]
    fn withdrawal_reserves_before_finalize_and_conserves() {
        let mut e = engine();
        e.execute(
            seq(1),
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(1_000_000),
            }),
        )
        .unwrap();
        let acct = types::AccountId::new(0);
        let r = e
            .execute(
                seq(2),
                Command::RequestWithdrawal(RequestWithdrawal {
                    account: acct,
                    amount: amt(400_000),
                    nonce: 1,
                    destination_chain: 1,
                    destination_address: vec![1, 2, 3],
                    auth: Authorization::Master,
                }),
            )
            .unwrap();
        let ReceiptKind::WithdrawalRequested(id) = r.kind else {
            panic!("expected withdrawal id")
        };
        // Funds reserved (removed from available) before custody signs.
        assert_eq!(e.ledger().available(acct).unwrap(), amt(600_000));
        assert_eq!(e.ledger().reserved(acct).unwrap(), amt(400_000));
        assert_eq!(e.ledger().total_supply(), amt(1_000_000));
        // Finalize removes the reserved funds from the system.
        e.execute(
            seq(3),
            Command::FinalizeWithdrawal(FinalizeWithdrawal { withdrawal_id: id }),
        )
        .unwrap();
        assert_eq!(e.ledger().reserved(acct).unwrap(), amt(0));
        assert_eq!(e.ledger().total_supply(), amt(600_000));
        assert!(e.ledger().conservation_holds());
        // Double-finalize rejected.
        assert_eq!(
            e.execute(
                seq(4),
                Command::FinalizeWithdrawal(FinalizeWithdrawal { withdrawal_id: id })
            ),
            Err(ExecutionError::WithdrawalAlreadyFinalized)
        );
    }

    #[test]
    fn complete_set_mint_redeem_conserves_supply() {
        let mut e = engine();
        e.execute(
            seq(1),
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(1_000_000),
            }),
        )
        .unwrap();
        e.execute(
            seq(2),
            Command::CreateMarket(CreateMarket {
                market: types::MarketId::new(0),
                market_type: MarketType::MultiOutcomePrediction,
                outcomes: 3,
                mark_price: Price::from_raw(500_000),
            }),
        )
        .unwrap();
        let acct = types::AccountId::new(0);
        // Mint 300k complete sets: locks stablecoin, credits claims across 3 outcomes.
        e.execute(
            seq(3),
            Command::MintCompleteSet(CompleteSetOp {
                account: acct,
                market: types::MarketId::new(0),
                count: amt(300_000),
            }),
        )
        .unwrap();
        assert_eq!(e.ledger().locked(acct).unwrap(), amt(300_000));
        assert_eq!(e.ledger().available(acct).unwrap(), amt(700_000));
        assert!(e.ledger().conservation_holds());
        // Redeem: burns claims, unlocks stablecoin.
        e.execute(
            seq(4),
            Command::RedeemCompleteSet(CompleteSetOp {
                account: acct,
                market: types::MarketId::new(0),
                count: amt(300_000),
            }),
        )
        .unwrap();
        assert_eq!(e.ledger().available(acct).unwrap(), amt(1_000_000));
        assert_eq!(e.ledger().locked(acct).unwrap(), amt(0));
        assert!(e.ledger().conservation_holds());
    }

    #[test]
    fn orders_match_across_accounts() {
        let mut e = engine();
        e.execute(
            seq(1),
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(100_000_000),
            }),
        )
        .unwrap();
        e.execute(
            seq(2),
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(100_000_000),
            }),
        )
        .unwrap();
        e.execute(
            seq(3),
            Command::CreateMarket(CreateMarket {
                market: types::MarketId::new(0),
                market_type: MarketType::Perpetual,
                outcomes: 1,
                mark_price: Price::from_raw(1_000_000),
            }),
        )
        .unwrap();
        let (maker, taker) = (types::AccountId::new(0), types::AccountId::new(1));
        // Maker rests a bid; taker crosses with an ask.
        e.execute(
            seq(4),
            Command::PlaceOrder(PlaceOrder {
                account: maker,
                market: types::MarketId::new(0),
                order_id: OrderId::new(1),
                side: Side::Bid,
                order_type: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: Price::from_raw(1_000_000),
                quantity: Quantity::from_raw(1_000_000),
                client_id: 1,
                reduce_only: false,
                auth: Authorization::Master,
            }),
        )
        .unwrap();
        let r = e
            .execute(
                seq(5),
                Command::PlaceOrder(PlaceOrder {
                    account: taker,
                    market: types::MarketId::new(0),
                    order_id: OrderId::new(2),
                    side: Side::Ask,
                    order_type: OrderType::Limit,
                    tif: TimeInForce::Gtc,
                    price: Price::from_raw(1_000_000),
                    quantity: Quantity::from_raw(1_000_000),
                    client_id: 2,
                    reduce_only: false,
                    auth: Authorization::Master,
                }),
            )
            .unwrap();
        assert_eq!(
            r.kind,
            ReceiptKind::OrderApplied {
                filled: Quantity::from_raw(1_000_000),
                rested: false
            }
        );
    }

    #[test]
    fn rejected_place_order_does_not_diverge_committed_state() {
        let mut e = engine();
        e.execute(
            seq(1),
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(100_000_000),
            }),
        )
        .unwrap();
        e.execute(
            seq(2),
            Command::CreateMarket(CreateMarket {
                market: types::MarketId::new(0),
                market_type: MarketType::Perpetual,
                outcomes: 1,
                mark_price: Price::from_raw(1_000_000),
            }),
        )
        .unwrap();
        let place = |order_id: u64, client_id: u64| {
            Command::PlaceOrder(PlaceOrder {
                account: types::AccountId::new(0),
                market: types::MarketId::new(0),
                order_id: OrderId::new(order_id),
                side: Side::Bid,
                order_type: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: Price::from_raw(1_000_000),
                quantity: Quantity::from_raw(1_000_000),
                client_id,
                reduce_only: false,
                auth: Authorization::Master,
            })
        };
        // First order rests and advances the committed state root.
        e.execute(seq(3), place(1, 1)).unwrap();
        let root_after_rest = e.state_root();
        // A colliding order id is rejected by the book. Because the book leaves
        // itself bit-identical on error, the engine commits nothing and the
        // state root is unchanged: book and risk/ledger cannot diverge.
        assert_eq!(
            e.execute(seq(4), place(1, 2)),
            Err(ExecutionError::Order(
                orderbook::OrderError::DuplicateOrderId
            ))
        );
        assert_eq!(e.state_root(), root_after_rest);
    }

    #[test]
    fn deterministic_replay_yields_identical_state_roots() {
        let script = vec![
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(50_000_000),
            }),
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(50_000_000),
            }),
            Command::CreateMarket(CreateMarket {
                market: types::MarketId::new(0),
                market_type: MarketType::Perpetual,
                outcomes: 1,
                mark_price: Price::from_raw(1_000_000),
            }),
            Command::PlaceOrder(PlaceOrder {
                account: types::AccountId::new(0),
                market: types::MarketId::new(0),
                order_id: OrderId::new(1),
                side: Side::Bid,
                order_type: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: Price::from_raw(990_000),
                quantity: Quantity::from_raw(2_000_000),
                client_id: 1,
                reduce_only: false,
                auth: Authorization::Master,
            }),
            Command::PlaceOrder(PlaceOrder {
                account: types::AccountId::new(1),
                market: types::MarketId::new(0),
                order_id: OrderId::new(2),
                side: Side::Ask,
                order_type: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: Price::from_raw(990_000),
                quantity: Quantity::from_raw(1_000_000),
                client_id: 2,
                reduce_only: false,
                auth: Authorization::Master,
            }),
            Command::DepositCredit(DepositCredit {
                source_chain: 1,
                source_tx: vec![1, 2, 3],
                source_event_index: 0,
                account: types::AccountId::new(0),
                amount: amt(1_000_000),
            }),
        ];
        let a = run(&script);
        let b = run(&script);
        assert_eq!(
            a, b,
            "identical command streams must yield identical state roots"
        );
        assert!(!a.is_zero());
    }

    #[test]
    fn unknown_account_and_market_are_typed_errors_not_panics() {
        let mut e = engine();
        assert_eq!(
            e.execute(
                seq(1),
                Command::DepositCredit(DepositCredit {
                    source_chain: 1,
                    source_tx: vec![],
                    source_event_index: 0,
                    account: types::AccountId::new(9),
                    amount: amt(1)
                })
            ),
            Err(ExecutionError::UnknownAccount)
        );
        assert_eq!(
            e.execute(
                seq(2),
                Command::SetMarkPrice(SetMarkPrice {
                    market: types::MarketId::new(9),
                    price: Price::from_raw(1)
                })
            ),
            Err(ExecutionError::UnknownMarket)
        );
    }

    // --- Unified committed economic state (positions + risk + ledger) ---

    // Acceptance criterion: a post-trade account leaf changes when the account's
    // position (and hence its risk state) changes.
    #[test]
    fn post_trade_account_leaf_and_root_change_with_position() {
        let mut e = engine();
        e.execute(
            seq(1),
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(100_000_000),
            }),
        )
        .unwrap();
        e.execute(
            seq(2),
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(100_000_000),
            }),
        )
        .unwrap();
        e.execute(
            seq(3),
            Command::CreateMarket(CreateMarket {
                market: MarketId::new(0),
                market_type: MarketType::Perpetual,
                outcomes: 1,
                mark_price: Price::from_raw(1_000_000),
            }),
        )
        .unwrap();
        let taker = AccountId::new(1);
        // Committed leaf and root before the taker holds any position.
        let leaf_before = e.account_leaf(taker).unwrap();
        let root_before = e.state_root();

        // Maker rests a bid; taker crosses with an ask -> both gain a position.
        e.execute(
            seq(4),
            Command::PlaceOrder(PlaceOrder {
                account: AccountId::new(0),
                market: MarketId::new(0),
                order_id: OrderId::new(1),
                side: Side::Bid,
                order_type: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: Price::from_raw(1_000_000),
                quantity: Quantity::from_raw(2_000_000),
                client_id: 1,
                reduce_only: false,
                auth: Authorization::Master,
            }),
        )
        .unwrap();
        e.execute(
            seq(5),
            Command::PlaceOrder(PlaceOrder {
                account: taker,
                market: MarketId::new(0),
                order_id: OrderId::new(2),
                side: Side::Ask,
                order_type: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: Price::from_raw(1_000_000),
                quantity: Quantity::from_raw(2_000_000),
                client_id: 2,
                reduce_only: false,
                auth: Authorization::Master,
            }),
        )
        .unwrap();

        let leaf_after = e.account_leaf(taker).unwrap();
        assert_ne!(
            leaf_before, leaf_after,
            "a new position must change the committed account leaf"
        );
        assert_ne!(
            root_before,
            e.state_root(),
            "a trade must change the committed state root"
        );
    }

    // Acceptance criterion: a light-client Merkle proof verifies trading balances
    // (position + risk + ledger) against the shard root.
    #[test]
    fn light_client_proof_verifies_trading_balances() {
        use state_tree::verify_account;
        let e = apply_all(&trade_and_withdraw_script());
        let taker = AccountId::new(1);

        let root = e.state_root();
        let leaf = e.account_leaf(taker).unwrap();
        let proof = e.account_proof(taker).unwrap();

        assert!(
            verify_account(root, taker, &leaf, &proof),
            "the committed trading leaf must verify against the shard root"
        );

        // Tampering any leaf byte (here the position/claim tail) breaks the proof.
        let mut tampered = leaf.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(
            !verify_account(root, taker, &tampered, &proof),
            "a tampered trading leaf must not verify"
        );
    }

    // Acceptance criterion: identical command streams (including fills, realized
    // PnL, and a withdrawal) produce identical full economic state roots.
    #[test]
    fn identical_streams_yield_identical_full_economic_roots() {
        let script = trade_and_withdraw_script();
        let a = run(&script);
        let b = run(&script);
        assert_eq!(
            a, b,
            "identical command streams must yield identical economic state roots"
        );
        assert!(!a.is_zero());

        // The trade genuinely moves the root: dropping the fills yields a
        // different root even though the ledger deposits are identical.
        let no_trade = vec![
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(100_000_000),
            }),
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(100_000_000),
            }),
            Command::CreateMarket(CreateMarket {
                market: MarketId::new(0),
                market_type: MarketType::Perpetual,
                outcomes: 1,
                mark_price: Price::from_raw(1_000_000),
            }),
        ];
        assert_ne!(
            a,
            run(&no_trade),
            "positions and risk state must be reflected in the economic root"
        );
    }

    // Acceptance criterion: no dual-ledger divergence under withdraw after trade.
    // The realized loss moves risk collateral but not the settlement ledger; the
    // committed leaf pins BOTH consistently, so a light client can never be shown
    // a balance that disagrees with the trading state.
    #[test]
    fn no_dual_ledger_divergence_under_withdraw_after_trade() {
        use state_tree::{verify_account, LeafReader};
        let script = trade_and_withdraw_script();
        let e = apply_all(&script);
        let taker = AccountId::new(1);

        // The committed leaf verifies against the shard root.
        let root = e.state_root();
        let leaf = e.account_leaf(taker).unwrap();
        let proof = e.account_proof(taker).unwrap();
        assert!(verify_account(root, taker, &leaf, &proof));

        // Decode the leaf prefix and confirm it is a single, consistent snapshot
        // of both ledgers rather than two divergent views.
        let mut r = LeafReader::new(&leaf).unwrap();
        let available = r.field_i128().unwrap();
        let reserved = r.field_i128().unwrap();
        let _locked = r.field_i128().unwrap();
        let _auth_epoch = r.field_i64().unwrap();
        let collateral = r.field_i128().unwrap();

        // Ledger: 100.0 - 10.0 reserved for withdrawal.
        assert_eq!(available, 90_000_000);
        assert_eq!(reserved, 10_000_000);
        assert_eq!(available, e.ledger().available(taker).unwrap().raw());
        assert_eq!(reserved, e.ledger().reserved(taker).unwrap().raw());

        // Risk collateral: 100.0 - 0.1 realized loss - 10.0 debited on withdrawal.
        assert_eq!(collateral, 89_900_000);
        assert_eq!(collateral, e.risk().collateral(taker).unwrap().raw());

        // The divergence between settlement (available) and risk (collateral) is
        // committed and verifiable — not hidden outside the root.
        assert_ne!(available, collateral);

        // Replay determinism holds across the full trade+withdraw stream.
        assert_eq!(run(&script), root);
    }

    // Recommendation: golden vector pinning the committed account leaf layout so
    // any silent field-layout drift is caught. A freshly created 5.0-collateral
    // account has no positions or claims and no mark price, so equity == 5.0 and
    // all margins are zero.
    #[test]
    fn account_leaf_layout_golden() {
        let mut e = engine();
        e.execute(
            seq(1),
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(5_000_000),
            }),
        )
        .unwrap();
        let leaf = e.account_leaf(AccountId::new(0)).unwrap();
        // version=1 | available 5.0 | reserved 0 | locked 0 | auth_epoch 0
        // | collateral 5.0 | equity 5.0 | exposure 0 | im 0 | mm 0
        // | position_count 0 | claim_group_count 0
        let expected = "0100\
                        404b4c00000000000000000000000000\
                        00000000000000000000000000000000\
                        00000000000000000000000000000000\
                        0000000000000000\
                        404b4c00000000000000000000000000\
                        404b4c00000000000000000000000000\
                        00000000000000000000000000000000\
                        00000000000000000000000000000000\
                        00000000000000000000000000000000\
                        00000000\
                        00000000";
        assert_eq!(hex::encode(&leaf), expected);
    }

    #[test]
    fn protocol_upgrade_is_monotonic() {
        use command::ProtocolUpgrade;
        let mut e = engine();
        assert_eq!(e.protocol_version(), 1);
        e.execute(
            seq(1),
            Command::ProtocolUpgrade(ProtocolUpgrade { target_version: 2 }),
        )
        .unwrap();
        assert_eq!(e.protocol_version(), 2);
        // Downgrade / same version is rejected.
        assert_eq!(
            e.execute(
                seq(2),
                Command::ProtocolUpgrade(ProtocolUpgrade { target_version: 2 })
            ),
            Err(ExecutionError::ProtocolDowngrade {
                current: 2,
                requested: 2
            })
        );
        assert_eq!(e.protocol_version(), 2);
    }

    // -------- Session-key authorization enforcement (issue #277) --------

    const SESSION_KEY: [u8; 32] = [7u8; 32];

    // A 100.0-collateral account, two perp markets (0 and 1) at mark 1.0, and a
    // session key for account 0 scoped to market 0 with a 2.0 per-order notional
    // cap, expiry 1000, and nonces 0..=10. Returns the engine and next sequence.
    fn session_fixture() -> (Engine, u64) {
        let mut e = engine();
        e.execute(
            seq(1),
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(100_000_000),
            }),
        )
        .unwrap();
        for (n, m) in [(2u64, 0u32), (3, 1)] {
            e.execute(
                seq(n),
                Command::CreateMarket(CreateMarket {
                    market: MarketId::new(m),
                    market_type: MarketType::Perpetual,
                    outcomes: 1,
                    mark_price: Price::from_raw(1_000_000),
                }),
            )
            .unwrap();
        }
        e.execute(
            seq(4),
            Command::AuthorizeSession(AuthorizeSession {
                account: AccountId::new(0),
                session_key: SESSION_KEY,
                allowed_markets: vec![MarketId::new(0)],
                max_notional: amt(2_000_000),
                expires_at: 1000,
                nonce_start: 0,
                nonce_end: 10,
            }),
        )
        .unwrap();
        (e, 5)
    }

    fn sess(nonce: u64, now: u64) -> Authorization {
        Authorization::Session {
            session_key: SESSION_KEY,
            nonce,
            now,
        }
    }

    // A resting bid on `market` (price 0.9, so it never crosses) for account 0.
    fn place_bid(market: u32, order_id: u64, qty: i64, auth: Authorization) -> Command {
        Command::PlaceOrder(PlaceOrder {
            account: AccountId::new(0),
            market: MarketId::new(market),
            order_id: OrderId::new(order_id),
            side: Side::Bid,
            order_type: OrderType::Limit,
            tif: TimeInForce::Gtc,
            price: Price::from_raw(900_000),
            quantity: Quantity::from_raw(qty),
            client_id: order_id,
            reduce_only: false,
            auth,
        })
    }

    // Acceptance criteria: a PlaceOrder must present a session that is known,
    // in-scope for the market, under the notional cap, unexpired, and whose
    // nonce has not been used — or the account master key.
    #[test]
    fn place_order_enforces_session_scope_expiry_notional_and_nonce() {
        let (mut e, mut n) = session_fixture();
        // A valid session order rests.
        let r = e
            .execute(seq(n), place_bid(0, 1, 1_000_000, sess(0, 500)))
            .unwrap();
        assert!(matches!(r.kind, ReceiptKind::OrderApplied { .. }));
        n += 1;
        // Replaying nonce 0 is rejected.
        assert_eq!(
            e.execute(seq(n), place_bid(0, 2, 1_000_000, sess(0, 500))),
            Err(ExecutionError::BadNonce)
        );
        n += 1;
        // An unknown session key is rejected.
        assert_eq!(
            e.execute(
                seq(n),
                place_bid(
                    0,
                    3,
                    1_000_000,
                    Authorization::Session {
                        session_key: [9u8; 32],
                        nonce: 1,
                        now: 500,
                    },
                ),
            ),
            Err(ExecutionError::UnknownSession)
        );
        n += 1;
        // Over the per-order notional cap (0.9 * 3.0 = 2.7 > 2.0).
        assert_eq!(
            e.execute(seq(n), place_bid(0, 4, 3_000_000, sess(1, 500))),
            Err(ExecutionError::NotionalExceeded)
        );
        n += 1;
        // A market outside the session scope.
        assert_eq!(
            e.execute(seq(n), place_bid(1, 5, 1_000_000, sess(2, 500))),
            Err(ExecutionError::MarketNotAuthorized)
        );
        n += 1;
        // After the session expiry.
        assert_eq!(
            e.execute(seq(n), place_bid(0, 6, 1_000_000, sess(3, 2000))),
            Err(ExecutionError::SessionExpired)
        );
        n += 1;
        // The master key is always accepted.
        let r = e
            .execute(seq(n), place_bid(0, 7, 1_000_000, Authorization::Master))
            .unwrap();
        assert!(matches!(r.kind, ReceiptKind::OrderApplied { .. }));
    }

    // Acceptance criterion (withdraw path): a scoped session key cannot move
    // funds out of custody; only the master key may withdraw.
    #[test]
    fn withdrawal_requires_master_key() {
        let (mut e, mut n) = session_fixture();
        let acct = AccountId::new(0);
        assert_eq!(
            e.execute(
                seq(n),
                Command::RequestWithdrawal(RequestWithdrawal {
                    account: acct,
                    amount: amt(1_000_000),
                    nonce: 1,
                    destination_chain: 1,
                    destination_address: vec![9, 9, 9],
                    auth: sess(0, 500),
                }),
            ),
            Err(ExecutionError::SessionCannotWithdraw)
        );
        // Nothing was reserved by the rejected session withdrawal.
        assert_eq!(e.ledger().reserved(acct).unwrap(), amt(0));
        n += 1;
        let r = e
            .execute(
                seq(n),
                Command::RequestWithdrawal(RequestWithdrawal {
                    account: acct,
                    amount: amt(1_000_000),
                    nonce: 1,
                    destination_chain: 1,
                    destination_address: vec![9, 9, 9],
                    auth: Authorization::Master,
                }),
            )
            .unwrap();
        assert!(matches!(r.kind, ReceiptKind::WithdrawalRequested(_)));
        assert_eq!(e.ledger().reserved(acct).unwrap(), amt(1_000_000));
    }

    // Cancel/replace enforce both ownership (defense in depth) and, when a
    // session key is used, the session's market scope and nonce.
    #[test]
    fn cancel_and_replace_enforce_ownership_and_session_scope() {
        let mut e = engine();
        let mut n = 1u64;
        for _ in 0..2 {
            e.execute(
                seq(n),
                Command::CreateAccount(CreateAccount {
                    initial_collateral: amt(100_000_000),
                }),
            )
            .unwrap();
            n += 1;
        }
        for m in [0u32, 1] {
            e.execute(
                seq(n),
                Command::CreateMarket(CreateMarket {
                    market: MarketId::new(m),
                    market_type: MarketType::Perpetual,
                    outcomes: 1,
                    mark_price: Price::from_raw(1_000_000),
                }),
            )
            .unwrap();
            n += 1;
        }
        for oid in [1u64, 2] {
            e.execute(seq(n), place_bid(0, oid, 1_000_000, Authorization::Master))
                .unwrap();
            n += 1;
        }
        // Account 1 may neither cancel nor replace account 0's order.
        assert_eq!(
            e.execute(
                seq(n),
                Command::CancelOrder(CancelOrder {
                    market: MarketId::new(0),
                    account: AccountId::new(1),
                    order_id: OrderId::new(1),
                    auth: Authorization::Master,
                }),
            ),
            Err(ExecutionError::OrderNotOwned)
        );
        n += 1;
        assert_eq!(
            e.execute(
                seq(n),
                Command::ReplaceOrder(ReplaceOrder {
                    market: MarketId::new(0),
                    account: AccountId::new(1),
                    order_id: OrderId::new(1),
                    price: Price::from_raw(800_000),
                    quantity: Quantity::from_raw(1_000_000),
                    auth: Authorization::Master,
                }),
            ),
            Err(ExecutionError::OrderNotOwned)
        );
        n += 1;
        // Authorize a market-0 session for account 0.
        e.execute(
            seq(n),
            Command::AuthorizeSession(AuthorizeSession {
                account: AccountId::new(0),
                session_key: SESSION_KEY,
                allowed_markets: vec![MarketId::new(0)],
                max_notional: amt(2_000_000),
                expires_at: 1000,
                nonce_start: 0,
                nonce_end: 10,
            }),
        )
        .unwrap();
        n += 1;
        // A market-0 session cannot act in market 1.
        assert_eq!(
            e.execute(
                seq(n),
                Command::CancelOrder(CancelOrder {
                    market: MarketId::new(1),
                    account: AccountId::new(0),
                    order_id: OrderId::new(99),
                    auth: sess(0, 500),
                }),
            ),
            Err(ExecutionError::MarketNotAuthorized)
        );
        n += 1;
        // The owner cancels its own order via the in-scope session (nonce 0).
        let r = e
            .execute(
                seq(n),
                Command::CancelOrder(CancelOrder {
                    market: MarketId::new(0),
                    account: AccountId::new(0),
                    order_id: OrderId::new(1),
                    auth: sess(0, 500),
                }),
            )
            .unwrap();
        assert_eq!(r.kind, ReceiptKind::Cancelled(1));
        n += 1;
        // Replaying that session nonce on a later cancel is rejected.
        assert_eq!(
            e.execute(
                seq(n),
                Command::CancelOrder(CancelOrder {
                    market: MarketId::new(0),
                    account: AccountId::new(0),
                    order_id: OrderId::new(2),
                    auth: sess(0, 500),
                }),
            ),
            Err(ExecutionError::BadNonce)
        );
    }

    // Defense in depth: the engine rejects a replayed or out-of-order sequence.
    #[test]
    fn non_monotonic_sequence_is_rejected() {
        let mut e = engine();
        e.execute(
            seq(5),
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(1_000_000),
            }),
        )
        .unwrap();
        assert_eq!(
            e.execute(
                seq(5),
                Command::CreateAccount(CreateAccount {
                    initial_collateral: amt(0),
                }),
            ),
            Err(ExecutionError::NonMonotonicSequence { last: 5, got: 5 })
        );
        assert_eq!(
            e.execute(
                seq(3),
                Command::CreateAccount(CreateAccount {
                    initial_collateral: amt(0),
                }),
            ),
            Err(ExecutionError::NonMonotonicSequence { last: 5, got: 3 })
        );
        // A strictly greater sequence advances.
        e.execute(
            seq(6),
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(0),
            }),
        )
        .unwrap();
    }

    // Recommendation: wallet bindings are persisted (no longer a no-op) and
    // validated against account existence.
    #[test]
    fn bind_wallet_persists_and_validates_account() {
        let mut e = engine();
        e.execute(
            seq(1),
            Command::CreateAccount(CreateAccount {
                initial_collateral: amt(0),
            }),
        )
        .unwrap();
        assert_eq!(
            e.execute(
                seq(2),
                Command::BindWallet(BindWallet {
                    account: AccountId::new(9),
                    chain_id: 1,
                    address: vec![0xaa; 20],
                }),
            ),
            Err(ExecutionError::UnknownAccount)
        );
        e.execute(
            seq(3),
            Command::BindWallet(BindWallet {
                account: AccountId::new(0),
                chain_id: 1,
                address: vec![0xaa; 20],
            }),
        )
        .unwrap();
        assert_eq!(
            e.wallet_binding(AccountId::new(0)),
            Some(&WalletBinding {
                chain_id: 1,
                address: vec![0xaa; 20],
            })
        );
        // Rebinding overwrites the prior binding.
        e.execute(
            seq(4),
            Command::BindWallet(BindWallet {
                account: AccountId::new(0),
                chain_id: 2,
                address: vec![0xbb; 20],
            }),
        )
        .unwrap();
        assert_eq!(
            e.wallet_binding(AccountId::new(0)).map(|b| b.chain_id),
            Some(2)
        );
    }
}

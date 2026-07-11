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
    AuthorizeSession, BindWallet, CancelAll, CancelOrder, Command, CompleteSetOp, CreateAccount,
    CreateMarket, DepositCredit, DeterministicEngine, ExecutionReceipt, FinalizeWithdrawal,
    PlaceOrder, ReceiptKind, ReplaceOrder, RequestWithdrawal, RevokeSession, SetMarkPrice,
    Timestamp,
};
pub use engine::{Engine, EngineConfig};
pub use error::ExecutionError;
pub use ledger::Ledger;
pub use session::SessionRegistry;

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "execution";

#[cfg(test)]
mod tests {
    use super::*;
    use types::{
        Amount, MarketType, OrderId, OrderType, Price, Quantity, SequenceNumber, Side, TimeInForce,
    };

    fn engine() -> Engine {
        Engine::new(EngineConfig::default())
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
}

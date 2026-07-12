//! `decision-markets` — action-contingent decision markets.
//!
//! A **decision market** lets a mechanism pick the action that maximizes (or
//! minimizes) a fixed, immutable utility function over uncertain outcomes. One
//! action-contingent market is spawned per candidate action; traders express
//! beliefs about each outcome *conditional on that action being taken*. The
//! system then selects the action with the best **time-weighted** expected
//! utility — never from the final tick alone — settles the chosen action by its
//! realized outcome, and unwinds the unchosen actions per a counterfactual
//! policy.
//!
//! Part of the DexOS deterministic execution core: `#![forbid(unsafe_code)]`, no
//! floating point (fixed-point integers from [`types`] only), no async/networking,
//! and every fallible operation returns a typed [`DecisionMarketError`] rather
//! than panicking on adversarial input.
//!
//! # Lifecycle
//!
//! `Draft → Trading → DecisionLocked → ActionSelected → Evaluating → Resolved →
//! Settled`, with a guarded `→ Invalid → Settled` void path. See
//! [`DecisionPhase`].
//!
//! # Modules
//!
//! - [`definition`]: the immutable [`DecisionMarketDefinition`] + panic-free codec.
//! - [`lifecycle`]: validated phase transitions.
//! - [`twap`]: allocation-free time-weighted decision-price accumulator.
//! - [`instrument`]: the bijective `(action, outcome) → instrument` mapping.
//! - [`selection`]: expected-utility evaluation and external confirmations.
//! - [`market`]: the runtime state machine (mint/redeem/trade, guards, settle).
//! - [`settlement`]: the conserved payout record.
#![forbid(unsafe_code)]

pub mod definition;
pub mod error;
pub mod instrument;
pub mod lifecycle;
pub mod market;
pub mod selection;
pub mod settlement;
pub mod twap;

pub use definition::{
    Action, DecisionGuards, DecisionMarketDefinition, DecisionRule, Outcome,
    UnselectedActionPolicy, UtilityFunction, MAX_ACTIONS, MAX_LABEL_BYTES, MAX_OUTCOMES,
};
pub use error::DecisionMarketError;
pub use instrument::{instrument_coords, instrument_id, ActionId, InstrumentId, OutcomeId};
pub use lifecycle::DecisionPhase;
pub use market::DecisionMarket;
pub use selection::{
    expected_utility, select_action, validate_probability_vector, ConfirmationKind,
    ConfirmationPayload, DecisionConfirmation, SelectionOutcome,
    PROBABILITY_SUM_TOLERANCE_PER_OUTCOME,
};
pub use settlement::Settlement;
pub use twap::{time_weighted_average, PriceTick, TimeWindow, TwapAccumulator};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "decision-markets";

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::ThresholdSigners;
    use types::{AccountId, Amount, MarketId, Price, Quantity, Ratio, SequenceNumber};

    const NETWORK_ID: u64 = 7;
    const MARKET_ID: MarketId = MarketId::new(5);

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "decision-markets");
    }

    fn authority() -> ThresholdSigners {
        // 3-of-4 deterministic authority set.
        let seeds: Vec<[u8; 32]> = (0..4).map(|i| [u8::try_from(i).unwrap(); 32]).collect();
        ThresholdSigners::from_seeds(&seeds, 3)
    }

    fn definition_full(
        policy: UnselectedActionPolicy,
        guards: DecisionGuards,
    ) -> DecisionMarketDefinition {
        DecisionMarketDefinition::new(
            vec![Action::new("ship"), Action::new("hold")],
            vec![Outcome::new("up"), Outcome::new("down")],
            UtilityFunction::new(vec![Amount::from_raw(10_000_000), Amount::ZERO]).unwrap(),
            DecisionRule::MaximizeExpectedUtility,
            TimeWindow::new(0, 100).unwrap(),
            TimeWindow::new(100, 200).unwrap(),
            policy,
            Amount::from_raw(1_000_000),
            MARKET_ID,
            NETWORK_ID,
            guards,
            Ratio::from_raw(500_000),
            authority().validator_set(),
        )
        .unwrap()
    }

    fn definition(policy: UnselectedActionPolicy) -> DecisionMarketDefinition {
        definition_full(policy, DecisionGuards::new(Amount::ZERO, Ratio::ONE))
    }

    /// Observe a constant `price` twice, covering the selection window with a
    /// real inter-tick interval (`[0, 60)`, 60% of the window).
    fn observe_covering(
        m: &mut DecisionMarket,
        action: ActionId,
        outcome: OutcomeId,
        price: Price,
    ) {
        m.observe_price(action, outcome, 0, price).unwrap();
        m.observe_price(action, outcome, 60, price).unwrap();
    }

    fn action_confirmation(round: u64, action: u16) -> DecisionConfirmation {
        let payload =
            ConfirmationPayload::action(MARKET_ID, NETWORK_ID, SequenceNumber::new(round), action);
        DecisionConfirmation::form(payload, &authority(), vec![0, 1, 2])
    }

    fn outcome_confirmation(round: u64, outcome: u16) -> DecisionConfirmation {
        let payload = ConfirmationPayload::outcome(
            MARKET_ID,
            NETWORK_ID,
            SequenceNumber::new(round),
            outcome,
        );
        DecisionConfirmation::form(payload, &authority(), vec![0, 1, 2])
    }

    #[test]
    fn mint_then_redeem_conserves_collateral() {
        let mut m = DecisionMarket::new(definition(UnselectedActionPolicy::Refund)).unwrap();
        m.open_trading().unwrap();
        let acct = AccountId::new(1);
        let action = ActionId::new(0);
        m.mint(action, acct, Quantity::from_raw(3_000_000)).unwrap();
        assert_eq!(
            m.worst_case_liability(action).unwrap(),
            Amount::from_raw(3_000_000)
        );
        m.redeem(action, acct, Quantity::from_raw(3_000_000))
            .unwrap();
        assert_eq!(m.worst_case_liability(action).unwrap(), Amount::ZERO);
    }

    #[test]
    fn worst_case_liability_matches_hand_fixture() {
        // par 1.0/set; mint 5 sets in action 0, 2 sets in action 1.
        let mut m = DecisionMarket::new(definition(UnselectedActionPolicy::Void)).unwrap();
        m.open_trading().unwrap();
        m.mint(
            ActionId::new(0),
            AccountId::new(1),
            Quantity::from_raw(5_000_000),
        )
        .unwrap();
        m.mint(
            ActionId::new(1),
            AccountId::new(2),
            Quantity::from_raw(2_000_000),
        )
        .unwrap();
        assert_eq!(
            m.worst_case_liability(ActionId::new(0)).unwrap(),
            Amount::from_raw(5_000_000)
        );
        assert_eq!(
            m.scenario_liabilities(ActionId::new(1)).unwrap(),
            vec![Amount::from_raw(2_000_000), Amount::from_raw(2_000_000)]
        );
    }

    #[test]
    fn thin_market_blocks_selection_and_voids() {
        // Guards committed in the definition (min liquidity 1e9).
        let guards = DecisionGuards::new(Amount::from_raw(1_000_000_000), Ratio::ONE);
        let mut m =
            DecisionMarket::new(definition_full(UnselectedActionPolicy::Refund, guards)).unwrap();
        m.open_trading().unwrap();
        // Only a tiny amount of liquidity.
        m.mint(ActionId::new(0), AccountId::new(1), Quantity::from_raw(1))
            .unwrap();
        m.observe_price(
            ActionId::new(0),
            OutcomeId::new(0),
            0,
            Price::from_raw(600_000),
        )
        .unwrap();
        m.lock_decision().unwrap();
        assert_eq!(
            m.select_auto(100),
            Err(DecisionMarketError::LiquidityTooThin)
        );
        assert_eq!(m.phase(), DecisionPhase::Invalid);
    }

    #[test]
    fn concentration_limit_blocks_selection() {
        // Committed concentration limit of 50%.
        let guards = DecisionGuards::new(Amount::ZERO, Ratio::from_raw(500_000));
        let mut m =
            DecisionMarket::new(definition_full(UnselectedActionPolicy::Refund, guards)).unwrap();
        m.open_trading().unwrap();
        // One account holds everything -> 100% concentration.
        m.mint(
            ActionId::new(0),
            AccountId::new(1),
            Quantity::from_raw(10_000_000),
        )
        .unwrap();
        m.mint(
            ActionId::new(1),
            AccountId::new(1),
            Quantity::from_raw(10_000_000),
        )
        .unwrap();
        m.lock_decision().unwrap();
        assert_eq!(
            m.select_auto(100),
            Err(DecisionMarketError::ConcentrationExceeded)
        );
        assert_eq!(m.phase(), DecisionPhase::Invalid);
    }

    #[test]
    fn insufficient_window_coverage_voids() {
        // A single (final) tick per outcome carries no time-weighting.
        let mut m = DecisionMarket::new(definition(UnselectedActionPolicy::Refund)).unwrap();
        m.open_trading().unwrap();
        m.mint(
            ActionId::new(0),
            AccountId::new(1),
            Quantity::from_raw(1_000_000),
        )
        .unwrap();
        m.mint(
            ActionId::new(1),
            AccountId::new(2),
            Quantity::from_raw(1_000_000),
        )
        .unwrap();
        // Exactly one observation per outcome -> zero observed coverage.
        for a in 0..2u16 {
            for o in 0..2u16 {
                m.observe_price(
                    ActionId::new(a),
                    OutcomeId::new(o),
                    90,
                    Price::from_raw(500_000),
                )
                .unwrap();
            }
        }
        m.lock_decision().unwrap();
        assert_eq!(
            m.select_auto(100),
            Err(DecisionMarketError::InsufficientWindowCoverage)
        );
        assert_eq!(m.phase(), DecisionPhase::Invalid);
    }

    #[test]
    fn selection_before_window_end_is_rejected() {
        let mut m = DecisionMarket::new(definition(UnselectedActionPolicy::Refund)).unwrap();
        m.open_trading().unwrap();
        m.mint(
            ActionId::new(0),
            AccountId::new(1),
            Quantity::from_raw(1_000_000),
        )
        .unwrap();
        m.mint(
            ActionId::new(1),
            AccountId::new(2),
            Quantity::from_raw(1_000_000),
        )
        .unwrap();
        observe_covering(
            &mut m,
            ActionId::new(0),
            OutcomeId::new(0),
            Price::from_raw(900_000),
        );
        observe_covering(
            &mut m,
            ActionId::new(0),
            OutcomeId::new(1),
            Price::from_raw(100_000),
        );
        observe_covering(
            &mut m,
            ActionId::new(1),
            OutcomeId::new(0),
            Price::from_raw(100_000),
        );
        observe_covering(
            &mut m,
            ActionId::new(1),
            OutcomeId::new(1),
            Price::from_raw(900_000),
        );
        m.lock_decision().unwrap();
        // Selection window is [0, 100); running before it elapses is rejected and
        // does not void the market.
        assert_eq!(
            m.select_auto(99),
            Err(DecisionMarketError::SelectionWindowNotElapsed)
        );
        assert_eq!(m.phase(), DecisionPhase::DecisionLocked);
        // At the window end it proceeds.
        assert_eq!(m.select_auto(100).unwrap().action, ActionId::new(0));
    }

    #[test]
    fn evaluation_before_window_open_is_rejected() {
        let mut m = DecisionMarket::new(definition(UnselectedActionPolicy::Refund)).unwrap();
        m.open_trading().unwrap();
        m.mint(
            ActionId::new(0),
            AccountId::new(1),
            Quantity::from_raw(1_000_000),
        )
        .unwrap();
        m.mint(
            ActionId::new(1),
            AccountId::new(2),
            Quantity::from_raw(1_000_000),
        )
        .unwrap();
        observe_covering(
            &mut m,
            ActionId::new(0),
            OutcomeId::new(0),
            Price::from_raw(900_000),
        );
        observe_covering(
            &mut m,
            ActionId::new(0),
            OutcomeId::new(1),
            Price::from_raw(100_000),
        );
        observe_covering(
            &mut m,
            ActionId::new(1),
            OutcomeId::new(0),
            Price::from_raw(100_000),
        );
        observe_covering(
            &mut m,
            ActionId::new(1),
            OutcomeId::new(1),
            Price::from_raw(900_000),
        );
        m.lock_decision().unwrap();
        m.select_auto(100).unwrap();
        // Evaluation window is [100, 200); begin_evaluation before it opens fails.
        // (100 is the window open, so 99 is before it; but selection already set
        // sequenced time to 100, so use a value below the window start.)
        assert_eq!(
            m.begin_evaluation(99),
            Err(DecisionMarketError::EvaluationWindowNotOpen)
        );
        assert_eq!(m.phase(), DecisionPhase::ActionSelected);
        m.begin_evaluation(120).unwrap();
        // Sequenced time cannot move backward.
        assert_eq!(
            m.resolve(110, &outcome_confirmation(1, 0)),
            Err(DecisionMarketError::NonMonotonicTime)
        );
    }

    /// Drive a full market to SETTLED, asserting collateral conservation and the
    /// correct chosen/unchosen payouts.
    #[test]
    fn end_to_end_refund_policy_conserves_and_pays_correctly() {
        let mut m = DecisionMarket::new(definition(UnselectedActionPolicy::Refund)).unwrap();
        m.open_trading().unwrap();
        // action 0: account 1 mints 4 sets; action 1: account 2 mints 6 sets.
        m.mint(
            ActionId::new(0),
            AccountId::new(1),
            Quantity::from_raw(4_000_000),
        )
        .unwrap();
        m.mint(
            ActionId::new(1),
            AccountId::new(2),
            Quantity::from_raw(6_000_000),
        )
        .unwrap();
        // Decision prices: action 0 favors outcome up (0.9), action 1 favors down.
        observe_covering(
            &mut m,
            ActionId::new(0),
            OutcomeId::new(0),
            Price::from_raw(900_000),
        );
        observe_covering(
            &mut m,
            ActionId::new(0),
            OutcomeId::new(1),
            Price::from_raw(100_000),
        );
        observe_covering(
            &mut m,
            ActionId::new(1),
            OutcomeId::new(0),
            Price::from_raw(100_000),
        );
        observe_covering(
            &mut m,
            ActionId::new(1),
            OutcomeId::new(1),
            Price::from_raw(900_000),
        );
        m.lock_decision().unwrap();
        let chosen = m.select_auto(100).unwrap();
        // Action 0 EU = 0.9 * 10 = 9.0 > Action 1 EU = 0.1 * 10 = 1.0.
        assert_eq!(chosen.action, ActionId::new(0));
        m.begin_evaluation(120).unwrap();
        // Outcome "up" wins, confirmed by a threshold-signed outcome confirmation.
        m.resolve(150, &outcome_confirmation(1, 0)).unwrap();
        let s = m.settle().unwrap();
        assert_eq!(m.phase(), DecisionPhase::Settled);
        // Chosen action 0: account 1 held 4 sets of the winning outcome -> 4.0.
        assert_eq!(
            s.payout(ActionId::new(0), AccountId::new(1)),
            Amount::from_raw(4_000_000)
        );
        // Unchosen action 1 refunds the depositor its 6.0 collateral.
        assert_eq!(
            s.payout(ActionId::new(1), AccountId::new(2)),
            Amount::from_raw(6_000_000)
        );
        // Total conserved: 4.0 + 6.0 = 10.0.
        assert_eq!(s.total_paid(), Amount::from_raw(10_000_000));
    }

    #[test]
    fn void_policy_pays_current_holders_and_conserves() {
        let mut m = DecisionMarket::new(definition(UnselectedActionPolicy::Void)).unwrap();
        m.open_trading().unwrap();
        // action 1 (unchosen): account 1 mints 2 sets then sells 2 "up" shares to account 2.
        m.mint(
            ActionId::new(1),
            AccountId::new(1),
            Quantity::from_raw(2_000_000),
        )
        .unwrap();
        m.transfer(
            ActionId::new(1),
            OutcomeId::new(0),
            AccountId::new(1),
            AccountId::new(2),
            Quantity::from_raw(2_000_000),
        )
        .unwrap();
        // action 0 (chosen) liquidity so it can win.
        m.mint(
            ActionId::new(0),
            AccountId::new(3),
            Quantity::from_raw(1_000_000),
        )
        .unwrap();
        // Normalized decision prices for every action, covering the window.
        observe_covering(
            &mut m,
            ActionId::new(0),
            OutcomeId::new(0),
            Price::from_raw(900_000),
        );
        observe_covering(
            &mut m,
            ActionId::new(0),
            OutcomeId::new(1),
            Price::from_raw(100_000),
        );
        observe_covering(
            &mut m,
            ActionId::new(1),
            OutcomeId::new(0),
            Price::from_raw(100_000),
        );
        observe_covering(
            &mut m,
            ActionId::new(1),
            OutcomeId::new(1),
            Price::from_raw(900_000),
        );
        m.lock_decision().unwrap();
        m.select_auto(100).unwrap();
        m.begin_evaluation(120).unwrap();
        m.resolve(150, &outcome_confirmation(1, 0)).unwrap();
        let s = m.settle().unwrap();
        // Action 1 total collateral 2.0, total shares: account1 has 2 (down), account2 has 2 (up).
        // Void distributes 2.0 pro-rata by total shares (2 vs 2) -> 1.0 each.
        assert_eq!(
            s.payout(ActionId::new(1), AccountId::new(1)),
            Amount::from_raw(1_000_000)
        );
        assert_eq!(
            s.payout(ActionId::new(1), AccountId::new(2)),
            Amount::from_raw(1_000_000)
        );
        // Grand total conserved: action0 1.0 + action1 2.0 = 3.0.
        assert_eq!(s.total_paid(), Amount::from_raw(3_000_000));
    }

    #[test]
    fn signed_confirmation_rejects_unsigned_wrong_market_authority_stale_and_cross_network() {
        let mut m = DecisionMarket::new(definition(UnselectedActionPolicy::Refund)).unwrap();
        m.open_trading().unwrap();
        m.mint(
            ActionId::new(0),
            AccountId::new(1),
            Quantity::from_raw(5_000_000),
        )
        .unwrap();
        m.mint(
            ActionId::new(1),
            AccountId::new(2),
            Quantity::from_raw(5_000_000),
        )
        .unwrap();
        m.lock_decision().unwrap();

        // Unsigned: a confirmation with no signers never reaches threshold.
        let unsigned = {
            let payload =
                ConfirmationPayload::action(MARKET_ID, NETWORK_ID, SequenceNumber::new(1), 1);
            DecisionConfirmation::form(payload, &authority(), vec![])
        };
        assert!(matches!(
            m.select_confirmed(100, &unsigned),
            Err(DecisionMarketError::Quorum(_))
        ));

        // Wrong market.
        let wrong_market = {
            let payload = ConfirmationPayload::action(
                MarketId::new(999),
                NETWORK_ID,
                SequenceNumber::new(1),
                1,
            );
            DecisionConfirmation::form(payload, &authority(), vec![0, 1, 2])
        };
        assert_eq!(
            m.select_confirmed(100, &wrong_market),
            Err(DecisionMarketError::WrongMarket)
        );

        // Cross-network.
        let wrong_network = {
            let payload = ConfirmationPayload::action(MARKET_ID, 999, SequenceNumber::new(1), 1);
            DecisionConfirmation::form(payload, &authority(), vec![0, 1, 2])
        };
        assert_eq!(
            m.select_confirmed(100, &wrong_network),
            Err(DecisionMarketError::WrongNetwork)
        );

        // Wrong authority: a disjoint key set signs an otherwise-valid payload.
        let wrong_authority = {
            let foreign_seeds: Vec<[u8; 32]> = (0..4)
                .map(|i| [u8::try_from(i).unwrap() + 100; 32])
                .collect();
            let foreign = ThresholdSigners::from_seeds(&foreign_seeds, 3);
            let payload =
                ConfirmationPayload::action(MARKET_ID, NETWORK_ID, SequenceNumber::new(1), 1);
            DecisionConfirmation::form(payload, &foreign, vec![0, 1, 2])
        };
        assert!(matches!(
            m.select_confirmed(100, &wrong_authority),
            Err(DecisionMarketError::Quorum(_))
        ));

        // Stale round (0 does not exceed the initial 0), even when validly signed.
        assert_eq!(
            m.select_confirmed(100, &action_confirmation(0, 1)),
            Err(DecisionMarketError::StaleConfirmation)
        );

        // Out-of-range action.
        assert_eq!(
            m.select_confirmed(100, &action_confirmation(1, 9)),
            Err(DecisionMarketError::UnknownAction)
        );

        // Wrong kind: an outcome confirmation cannot select an action.
        assert_eq!(
            m.select_confirmed(100, &outcome_confirmation(1, 1)),
            Err(DecisionMarketError::WrongConfirmationKind)
        );

        // Running before the selection window elapses is rejected.
        assert_eq!(
            m.select_confirmed(99, &action_confirmation(1, 1)),
            Err(DecisionMarketError::SelectionWindowNotElapsed)
        );

        // None of the rejections changed the phase.
        assert_eq!(m.phase(), DecisionPhase::DecisionLocked);

        // A valid confirmation selects the action and advances the round.
        assert_eq!(
            m.select_confirmed(100, &action_confirmation(1, 1)).unwrap(),
            ActionId::new(1)
        );
        assert_eq!(m.selected_action(), Some(ActionId::new(1)));
        assert_eq!(m.phase(), DecisionPhase::ActionSelected);
    }

    // Deterministic LCG property test: over randomized mint/transfer sets, both
    // settlement policies conserve collateral exactly, and replaying the same
    // command sequence yields an identical state root.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
    }

    fn run_scenario(seed: u64, policy: UnselectedActionPolicy) -> (Amount, types::domain::Hash) {
        let mut r = Lcg(seed);
        let mut m = DecisionMarket::new(definition(policy)).unwrap();
        m.open_trading().unwrap();
        let mut deposited = Amount::ZERO;
        for _ in 0..12 {
            let action = ActionId::new(u16::try_from(r.next() % 2).unwrap());
            let acct = AccountId::new(u32::try_from(r.next() % 4).unwrap() + 1);
            let sets = i64::try_from(r.next() % 5 + 1).unwrap() * 1_000_000;
            m.mint(action, acct, Quantity::from_raw(sets)).unwrap();
            deposited = deposited
                .checked_add(Amount::from_raw(i128::from(sets)))
                .unwrap();
        }
        // Some transfers (do not change collateral).
        for _ in 0..6 {
            let action = ActionId::new(u16::try_from(r.next() % 2).unwrap());
            let outcome = OutcomeId::new(u16::try_from(r.next() % 2).unwrap());
            let from = AccountId::new(u32::try_from(r.next() % 4).unwrap() + 1);
            let to = AccountId::new(u32::try_from(r.next() % 4).unwrap() + 1);
            let _ = m.transfer(action, outcome, from, to, Quantity::from_raw(500_000));
        }
        // Normalized decision prices covering the window so selection is
        // well-defined (0.5 / 0.5, observed inter-tick coverage 60%).
        for a in 0..2u16 {
            for o in 0..2u16 {
                observe_covering(
                    &mut m,
                    ActionId::new(a),
                    OutcomeId::new(o),
                    Price::from_raw(500_000),
                );
            }
        }
        m.lock_decision().unwrap();
        m.select_auto(100).unwrap();
        m.begin_evaluation(120).unwrap();
        let outcome = u16::try_from(r.next() % 2).unwrap();
        m.resolve(150, &outcome_confirmation(1, outcome)).unwrap();
        let root = m.state_root();
        let s = m.settle().unwrap();
        assert_eq!(s.total_paid(), deposited, "collateral must be conserved");
        (s.total_paid(), root)
    }

    #[test]
    fn property_conservation_and_deterministic_replay() {
        for seed in 0..200u64 {
            for policy in [UnselectedActionPolicy::Refund, UnselectedActionPolicy::Void] {
                let (total_a, root_a) = run_scenario(seed, policy);
                let (total_b, root_b) = run_scenario(seed, policy);
                // Deterministic replay: identical totals and state roots.
                assert_eq!(total_a, total_b);
                assert_eq!(root_a, root_b);
            }
        }
    }

    /// Guard: the deterministic decision-market modules contain no
    /// floating-point types. The needles are constructed at runtime so this file
    /// does not trip its own scan.
    #[test]
    fn no_floating_point_in_source() {
        let f = 'f';
        let needle32 = format!("{f}32");
        let needle64 = format!("{f}64");
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut checked = 0usize;
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            assert!(!src.contains(&needle32), "found {needle32} in {path:?}");
            assert!(!src.contains(&needle64), "found {needle64} in {path:?}");
            checked += 1;
        }
        assert!(checked >= 8, "expected to scan every module");
    }
}

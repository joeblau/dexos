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
    Action, DecisionMarketDefinition, DecisionRule, Outcome, UnselectedActionPolicy,
    UtilityFunction, MAX_ACTIONS, MAX_LABEL_BYTES, MAX_OUTCOMES,
};
pub use error::DecisionMarketError;
pub use instrument::{instrument_coords, instrument_id, ActionId, InstrumentId, OutcomeId};
pub use lifecycle::DecisionPhase;
pub use market::{DecisionGuards, DecisionMarket};
pub use selection::{expected_utility, select_action, ExternalConfirmation, SelectionOutcome};
pub use settlement::Settlement;
pub use twap::{time_weighted_average, PriceTick, TimeWindow, TwapAccumulator};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "decision-markets";

#[cfg(test)]
mod tests {
    use super::*;
    use types::{AccountId, Amount, Price, Quantity, Ratio};

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "decision-markets");
    }

    fn definition(policy: UnselectedActionPolicy) -> DecisionMarketDefinition {
        DecisionMarketDefinition::new(
            vec![Action::new("ship"), Action::new("hold")],
            vec![Outcome::new("up"), Outcome::new("down")],
            UtilityFunction::new(vec![Amount::from_raw(10_000_000), Amount::ZERO]).unwrap(),
            DecisionRule::MaximizeExpectedUtility,
            TimeWindow::new(0, 100).unwrap(),
            TimeWindow::new(100, 200).unwrap(),
            policy,
            Amount::from_raw(1_000_000),
        )
        .unwrap()
    }

    fn lenient_guards() -> DecisionGuards {
        DecisionGuards::new(Amount::ZERO, Ratio::ONE)
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
        m.mint(ActionId::new(0), AccountId::new(1), Quantity::from_raw(5_000_000))
            .unwrap();
        m.mint(ActionId::new(1), AccountId::new(2), Quantity::from_raw(2_000_000))
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
        let mut m = DecisionMarket::new(definition(UnselectedActionPolicy::Refund)).unwrap();
        m.open_trading().unwrap();
        // Only a tiny amount of liquidity.
        m.mint(ActionId::new(0), AccountId::new(1), Quantity::from_raw(1))
            .unwrap();
        m.observe_price(ActionId::new(0), OutcomeId::new(0), 0, Price::from_raw(600_000))
            .unwrap();
        m.lock_decision().unwrap();
        let guards = DecisionGuards::new(Amount::from_raw(1_000_000_000), Ratio::ONE);
        assert_eq!(
            m.select_auto(guards),
            Err(DecisionMarketError::LiquidityTooThin)
        );
        assert_eq!(m.phase(), DecisionPhase::Invalid);
    }

    #[test]
    fn concentration_limit_blocks_selection() {
        let mut m = DecisionMarket::new(definition(UnselectedActionPolicy::Refund)).unwrap();
        m.open_trading().unwrap();
        // One account holds everything -> 100% concentration.
        m.mint(ActionId::new(0), AccountId::new(1), Quantity::from_raw(10_000_000))
            .unwrap();
        m.mint(ActionId::new(1), AccountId::new(1), Quantity::from_raw(10_000_000))
            .unwrap();
        m.lock_decision().unwrap();
        // Limit 50%.
        let guards = DecisionGuards::new(Amount::ZERO, Ratio::from_raw(500_000));
        assert_eq!(
            m.select_auto(guards),
            Err(DecisionMarketError::ConcentrationExceeded)
        );
        assert_eq!(m.phase(), DecisionPhase::Invalid);
    }

    /// Drive a full market to SETTLED, asserting collateral conservation and the
    /// correct chosen/unchosen payouts.
    #[test]
    fn end_to_end_refund_policy_conserves_and_pays_correctly() {
        let mut m = DecisionMarket::new(definition(UnselectedActionPolicy::Refund)).unwrap();
        m.open_trading().unwrap();
        // action 0: account 1 mints 4 sets; action 1: account 2 mints 6 sets.
        m.mint(ActionId::new(0), AccountId::new(1), Quantity::from_raw(4_000_000))
            .unwrap();
        m.mint(ActionId::new(1), AccountId::new(2), Quantity::from_raw(6_000_000))
            .unwrap();
        // Decision prices: action 0 favors outcome up (0.9), action 1 favors down.
        m.observe_price(ActionId::new(0), OutcomeId::new(0), 0, Price::from_raw(900_000))
            .unwrap();
        m.observe_price(ActionId::new(0), OutcomeId::new(1), 0, Price::from_raw(100_000))
            .unwrap();
        m.observe_price(ActionId::new(1), OutcomeId::new(0), 0, Price::from_raw(100_000))
            .unwrap();
        m.observe_price(ActionId::new(1), OutcomeId::new(1), 0, Price::from_raw(900_000))
            .unwrap();
        m.lock_decision().unwrap();
        let chosen = m.select_auto(lenient_guards()).unwrap();
        // Action 0 EU = 0.9 * 10 = 9.0 > Action 1 EU = 0.1 * 10 = 1.0.
        assert_eq!(chosen.action, ActionId::new(0));
        m.begin_evaluation().unwrap();
        m.resolve(OutcomeId::new(0)).unwrap(); // outcome "up" wins
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
        m.mint(ActionId::new(1), AccountId::new(1), Quantity::from_raw(2_000_000))
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
        m.mint(ActionId::new(0), AccountId::new(3), Quantity::from_raw(1_000_000))
            .unwrap();
        m.observe_price(ActionId::new(0), OutcomeId::new(0), 0, Price::from_raw(900_000))
            .unwrap();
        m.observe_price(ActionId::new(0), OutcomeId::new(1), 0, Price::from_raw(100_000))
            .unwrap();
        m.observe_price(ActionId::new(1), OutcomeId::new(0), 0, Price::from_raw(100_000))
            .unwrap();
        m.observe_price(ActionId::new(1), OutcomeId::new(1), 0, Price::from_raw(100_000))
            .unwrap();
        m.lock_decision().unwrap();
        m.select_auto(lenient_guards()).unwrap();
        m.begin_evaluation().unwrap();
        m.resolve(OutcomeId::new(0)).unwrap();
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
    fn external_confirmation_rejects_replay_and_bad_action() {
        let mut m = DecisionMarket::new(definition(UnselectedActionPolicy::Refund)).unwrap();
        m.open_trading().unwrap();
        m.mint(ActionId::new(0), AccountId::new(1), Quantity::from_raw(5_000_000))
            .unwrap();
        m.mint(ActionId::new(1), AccountId::new(2), Quantity::from_raw(5_000_000))
            .unwrap();
        m.lock_decision().unwrap();
        // Out-of-range action.
        let bad = ExternalConfirmation::new(ActionId::new(9), types::SequenceNumber::new(1));
        assert_eq!(
            m.select_confirmed(&bad.encode(), lenient_guards()),
            Err(DecisionMarketError::UnknownAction)
        );
        // Stale sequence (0 does not exceed the initial 0).
        let stale = ExternalConfirmation::new(ActionId::new(1), types::SequenceNumber::new(0));
        assert_eq!(
            m.select_confirmed(&stale.encode(), lenient_guards()),
            Err(DecisionMarketError::StaleConfirmation)
        );
        // Valid confirmation.
        let good = ExternalConfirmation::new(ActionId::new(1), types::SequenceNumber::new(1));
        assert_eq!(
            m.select_confirmed(&good.encode(), lenient_guards()).unwrap(),
            ActionId::new(1)
        );
        assert_eq!(m.selected_action(), Some(ActionId::new(1)));
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
        // Prices so action selection is well-defined.
        for a in 0..2u16 {
            for o in 0..2u16 {
                m.observe_price(
                    ActionId::new(a),
                    OutcomeId::new(o),
                    0,
                    Price::from_raw(500_000),
                )
                .unwrap();
            }
        }
        m.lock_decision().unwrap();
        m.select_auto(lenient_guards()).unwrap();
        m.begin_evaluation().unwrap();
        m.resolve(OutcomeId::new(u16::try_from(r.next() % 2).unwrap()))
            .unwrap();
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

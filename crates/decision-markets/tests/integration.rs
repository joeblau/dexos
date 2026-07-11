//! End-to-end integration coverage for the decision-market crate.

use decision_markets::{
    Action, ActionId, DecisionGuards, DecisionMarket, DecisionMarketDefinition, DecisionPhase,
    DecisionRule, ExternalConfirmation, Outcome, OutcomeId, TimeWindow, UnselectedActionPolicy,
    UtilityFunction,
};
use types::{AccountId, Amount, MarketType, Price, Quantity, Ratio, SequenceNumber};

/// A minimal registry entry, standing in for the node's market registry, to show
/// a `MarketType::Decision` entry is constructible from a valid definition.
struct RegistryEntry {
    market_type: MarketType,
    num_actions: usize,
    num_outcomes: usize,
}

fn sample_definition() -> DecisionMarketDefinition {
    DecisionMarketDefinition::new(
        vec![
            Action::new("launch"),
            Action::new("delay"),
            Action::new("cancel"),
        ],
        vec![Outcome::new("success"), Outcome::new("failure")],
        UtilityFunction::new(vec![Amount::from_raw(100_000_000), Amount::ZERO]).unwrap(),
        DecisionRule::MaximizeExpectedUtility,
        TimeWindow::new(0, 1_000).unwrap(),
        TimeWindow::new(1_000, 2_000).unwrap(),
        UnselectedActionPolicy::Refund,
        Amount::from_raw(1_000_000),
    )
    .unwrap()
}

#[test]
fn decision_registry_entry_constructible_from_definition() {
    let def = sample_definition();
    let entry = RegistryEntry {
        market_type: def.market_type(),
        num_actions: def.num_actions(),
        num_outcomes: def.num_outcomes(),
    };
    assert_eq!(entry.market_type, MarketType::Decision);
    assert_eq!(entry.num_actions, 3);
    assert_eq!(entry.num_outcomes, 2);
}

#[test]
fn definition_survives_binary_round_trip() {
    let def = sample_definition();
    let bytes = def.encode().unwrap();
    assert_eq!(DecisionMarketDefinition::decode(&bytes).unwrap(), def);
}

#[test]
fn full_lifecycle_from_creation_to_settled_conserves_collateral() {
    let mut m = DecisionMarket::new(sample_definition()).unwrap();
    assert_eq!(m.phase(), DecisionPhase::Draft);
    m.open_trading().unwrap();

    // Fund each contingent market.
    m.mint(ActionId::new(0), AccountId::new(1), Quantity::from_raw(10_000_000))
        .unwrap();
    m.mint(ActionId::new(1), AccountId::new(2), Quantity::from_raw(5_000_000))
        .unwrap();
    m.mint(ActionId::new(2), AccountId::new(3), Quantity::from_raw(4_000_000))
        .unwrap();
    let funded = 10_000_000 + 5_000_000 + 4_000_000;

    // Time-weighted decision prices: launch is most likely to succeed.
    // A late spike on "delay" must NOT flip the selection (TWAP, not last tick).
    m.observe_price(ActionId::new(0), OutcomeId::new(0), 0, Price::from_raw(800_000))
        .unwrap();
    m.observe_price(ActionId::new(0), OutcomeId::new(1), 0, Price::from_raw(200_000))
        .unwrap();
    m.observe_price(ActionId::new(1), OutcomeId::new(0), 0, Price::from_raw(300_000))
        .unwrap();
    m.observe_price(ActionId::new(1), OutcomeId::new(1), 0, Price::from_raw(700_000))
        .unwrap();
    // Final-tick spike for delay->success at t=999 (1 unit of a 1000-unit window).
    m.observe_price(ActionId::new(1), OutcomeId::new(0), 999, Price::from_raw(1_000_000))
        .unwrap();
    m.observe_price(ActionId::new(2), OutcomeId::new(0), 0, Price::from_raw(100_000))
        .unwrap();
    m.observe_price(ActionId::new(2), OutcomeId::new(1), 0, Price::from_raw(900_000))
        .unwrap();

    m.lock_decision().unwrap();
    let guards = DecisionGuards::new(Amount::from_raw(1_000_000), Ratio::ONE);
    let chosen = m.select_auto(guards).unwrap();
    assert_eq!(chosen.action, ActionId::new(0), "launch should win on TWAP");

    m.begin_evaluation().unwrap();
    m.resolve(OutcomeId::new(0)).unwrap(); // success
    let settlement = m.settle().unwrap();
    assert_eq!(m.phase(), DecisionPhase::Settled);

    // Chosen action 0: account 1 held 10 winning shares -> 10.0.
    assert_eq!(
        settlement.payout(ActionId::new(0), AccountId::new(1)),
        Amount::from_raw(10_000_000)
    );
    // Unchosen actions refund depositors.
    assert_eq!(
        settlement.payout(ActionId::new(1), AccountId::new(2)),
        Amount::from_raw(5_000_000)
    );
    assert_eq!(
        settlement.payout(ActionId::new(2), AccountId::new(3)),
        Amount::from_raw(4_000_000)
    );
    // Collateral conserved end-to-end.
    assert_eq!(settlement.total_paid(), Amount::from_raw(funded));
}

#[test]
fn externally_confirmed_selection_end_to_end() {
    let mut m = DecisionMarket::new(sample_definition()).unwrap();
    m.open_trading().unwrap();
    for a in 0..3u16 {
        m.mint(
            ActionId::new(a),
            AccountId::new(u32::from(a) + 1),
            Quantity::from_raw(3_000_000),
        )
        .unwrap();
    }
    m.lock_decision().unwrap();
    let guards = DecisionGuards::new(Amount::ZERO, Ratio::ONE);
    // Confirm action 2 externally.
    let conf = ExternalConfirmation::new(ActionId::new(2), SequenceNumber::new(7));
    let chosen = m.select_confirmed(&conf.encode(), guards).unwrap();
    assert_eq!(chosen, ActionId::new(2));

    m.begin_evaluation().unwrap();
    m.resolve(OutcomeId::new(0)).unwrap();
    let s = m.settle().unwrap();
    // Chosen action 2: account 3 held 3 winning shares -> 3.0.
    assert_eq!(
        s.payout(ActionId::new(2), AccountId::new(3)),
        Amount::from_raw(3_000_000)
    );
    // 9.0 total conserved across the three funded markets.
    assert_eq!(s.total_paid(), Amount::from_raw(9_000_000));
}

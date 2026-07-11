// Unit + property tests for the conditional engine. Included into
// `conditional::tests`.

use super::*;
use types::{AccountId, OrderId, OrderType, Price, Quantity, Side, TimeInForce};

struct Lcg(u64);
impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

fn template(id: u64, side: Side, price: i64, qty: i64) -> PlaceTemplate {
    PlaceTemplate {
        order_id: OrderId::new(id),
        account: AccountId::new(1),
        side,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price::from_raw(price),
        quantity: Quantity::from_raw(qty),
        client_id: id,
        reduce_only: false,
    }
}

#[test]
fn trigger_fires_at_and_beyond_boundary() {
    let above = TriggerKind::Above(Price::from_raw(100));
    assert!(!above.fires(Price::from_raw(99)));
    assert!(above.fires(Price::from_raw(100))); // boundary inclusive
    assert!(above.fires(Price::from_raw(101)));

    let below = TriggerKind::Below(Price::from_raw(100));
    assert!(!below.fires(Price::from_raw(101)));
    assert!(below.fires(Price::from_raw(100)));
    assert!(below.fires(Price::from_raw(99)));
}

#[test]
fn stop_loss_and_take_profit_mapping() {
    // Protective sell (long): stop-loss fires on drop, take-profit on rise.
    assert_eq!(
        TriggerKind::stop_loss(Side::Ask, Price::from_raw(90)),
        TriggerKind::Below(Price::from_raw(90))
    );
    assert_eq!(
        TriggerKind::take_profit(Side::Ask, Price::from_raw(110)),
        TriggerKind::Above(Price::from_raw(110))
    );
}

#[test]
fn property_trigger_fires_iff_crossed() {
    let mut r = Lcg(0x9999);
    for _ in 0..100_000 {
        let threshold = i64::from_le_bytes(r.next_u64().to_le_bytes()) / 4;
        let price = i64::from_le_bytes(r.next_u64().to_le_bytes()) / 4;
        let above = TriggerKind::Above(Price::from_raw(threshold));
        let below = TriggerKind::Below(Price::from_raw(threshold));
        assert_eq!(above.fires(Price::from_raw(price)), price >= threshold);
        assert_eq!(below.fires(Price::from_raw(price)), price <= threshold);
    }
}

#[test]
fn simple_stop_emits_once_and_is_removed() {
    let mut e = ConditionalEngine::new(ConditionalConfig::default());
    e.add_stop(template(1, Side::Ask, 90, 5), TriggerKind::Below(Price::from_raw(90)))
        .unwrap();
    // Above threshold: nothing.
    assert!(e.on_mark_price(Price::from_raw(95)).is_empty());
    assert_eq!(e.pending_len(), 1);
    // Crosses: one place intent, entry removed.
    let intents = e.on_mark_price(Price::from_raw(90));
    assert_eq!(intents.len(), 1);
    assert!(matches!(intents[0], OrderIntent::Place { quantity, .. } if quantity == Quantity::from_raw(5)));
    assert_eq!(e.pending_len(), 0);
    // Duplicated fire produces nothing (idempotent).
    assert!(e.on_mark_price(Price::from_raw(85)).is_empty());
}

#[test]
fn property_trailing_ratchets_forward_and_matches_naive() {
    for (seed, dir) in [(1u64, TrailDirection::SellStop), (2, TrailDirection::BuyStop)] {
        let mut r = Lcg(0x5A5A ^ seed);
        let offset = 10i64;
        let reference = Price::from_raw(1_000);
        let mut trail = Trailing::new(dir, Price::from_raw(offset), reference);
        let mut naive_extremum = reference.raw();
        let mut last_threshold = trail.threshold().raw();
        for _ in 0..50_000 {
            let price = 500 + i64::try_from(r.below(1_000)).unwrap();
            trail.update(Price::from_raw(price));
            // Naive reference recomputation.
            match dir {
                TrailDirection::SellStop => {
                    if price > naive_extremum {
                        naive_extremum = price;
                    }
                    assert_eq!(trail.threshold().raw(), naive_extremum - offset);
                    // Threshold never moves backward.
                    assert!(trail.threshold().raw() >= last_threshold);
                }
                TrailDirection::BuyStop => {
                    if price < naive_extremum {
                        naive_extremum = price;
                    }
                    assert_eq!(trail.threshold().raw(), naive_extremum + offset);
                    assert!(trail.threshold().raw() <= last_threshold);
                }
            }
            last_threshold = trail.threshold().raw();
        }
    }
}

#[test]
fn trailing_stop_fires_after_reversal() {
    let mut e = ConditionalEngine::new(ConditionalConfig::default());
    e.add_trailing(
        template(1, Side::Ask, 0, 5),
        TrailDirection::SellStop,
        Price::from_raw(10),
        Price::from_raw(100),
    )
    .unwrap();
    // Price climbs: threshold ratchets up to 120-10=110, no fire.
    assert!(e.on_mark_price(Price::from_raw(120)).is_empty());
    // Small dip but above threshold (110): no fire.
    assert!(e.on_mark_price(Price::from_raw(112)).is_empty());
    // Drop to threshold: fires.
    let intents = e.on_mark_price(Price::from_raw(110));
    assert_eq!(intents.len(), 1);
    assert_eq!(e.pending_len(), 0);
}

#[test]
fn oco_cancels_sibling_exactly_once() {
    let mut e = ConditionalEngine::new(ConditionalConfig::default());
    let leg_a = OcoLeg {
        trigger: TriggerKind::Above(Price::from_raw(110)),
        place: Some(template(1, Side::Ask, 110, 5)),
        cancel_order_id: Some(OrderId::new(200)),
    };
    let leg_b = OcoLeg {
        trigger: TriggerKind::Below(Price::from_raw(90)),
        place: Some(template(2, Side::Bid, 90, 5)),
        cancel_order_id: Some(OrderId::new(100)),
    };
    e.add_oco(leg_a, leg_b).unwrap();
    // Neither crosses.
    assert!(e.on_mark_price(Price::from_raw(100)).is_empty());
    // Leg A fires: emit its place + cancel leg B's sibling order exactly once.
    let intents = e.on_mark_price(Price::from_raw(115));
    let cancels: Vec<_> = intents
        .iter()
        .filter(|i| matches!(i, OrderIntent::Cancel { .. }))
        .collect();
    assert_eq!(cancels.len(), 1);
    assert!(matches!(cancels[0], OrderIntent::Cancel { order_id } if *order_id == OrderId::new(200)));
    assert_eq!(e.pending_len(), 0);
    // Further crossings emit nothing (sibling not cancelled twice).
    assert!(e.on_mark_price(Price::from_raw(80)).is_empty());
    assert!(e.on_mark_price(Price::from_raw(120)).is_empty());
}

#[test]
fn twap_slices_sum_to_parent_exactly() {
    for (parent, slices) in [(10i64, 3u32), (12, 4), (7, 7), (100, 6), (1, 1)] {
        let mut e = ConditionalEngine::new(ConditionalConfig::default());
        e.add_twap(template(1, Side::Bid, 100, parent), slices).unwrap();
        let mut total = 0i64;
        let mut count = 0u32;
        // Drive one slice per tick.
        for tick in 0..slices {
            let intents = e.on_mark_price(Price::from_raw(100 + i64::from(tick)));
            assert_eq!(intents.len(), 1);
            if let OrderIntent::Place { quantity, .. } = intents[0] {
                total += quantity.raw();
                count += 1;
            }
        }
        assert_eq!(count, slices);
        assert_eq!(total, parent, "slices must sum to parent");
        assert_eq!(e.pending_len(), 0);
        // Exhausted TWAP emits nothing further.
        assert!(e.on_mark_price(Price::from_raw(200)).is_empty());
    }
}

#[test]
fn twap_child_ids_are_distinct_and_deterministic() {
    let mut e = ConditionalEngine::new(ConditionalConfig::default());
    e.add_twap(template(1000, Side::Bid, 100, 9), 3).unwrap();
    let mut ids = Vec::new();
    for t in 0..3 {
        let intents = e.on_mark_price(Price::from_raw(100 + i64::from(t)));
        if let OrderIntent::Place { order_id, client_id, .. } = intents[0] {
            ids.push((order_id, client_id));
        }
    }
    assert_eq!(
        ids,
        [
            (OrderId::new(1000), 1000u64),
            (OrderId::new(1001), 1001),
            (OrderId::new(1002), 1002),
        ]
    );
}

#[test]
fn deterministic_replay_yields_identical_intent_stream() {
    fn run() -> Vec<OrderIntent> {
        let mut e = ConditionalEngine::new(ConditionalConfig::default());
        e.add_stop(template(1, Side::Ask, 90, 5), TriggerKind::Below(Price::from_raw(90)))
            .unwrap();
        e.add_stop(template(2, Side::Bid, 110, 5), TriggerKind::Above(Price::from_raw(110)))
            .unwrap();
        e.add_twap(template(3, Side::Bid, 100, 8), 4).unwrap();
        e.add_trailing(
            template(4, Side::Ask, 0, 5),
            TrailDirection::SellStop,
            Price::from_raw(5),
            Price::from_raw(100),
        )
        .unwrap();
        let prices = [100, 105, 108, 111, 95, 90, 120, 88, 130];
        let mut out = Vec::new();
        for p in prices {
            e.evaluate_into(Price::from_raw(p), &mut out);
        }
        out
    }
    assert_eq!(run(), run());
}

#[test]
fn evaluate_into_reuses_buffer() {
    let mut e = ConditionalEngine::new(ConditionalConfig::default());
    e.add_stop(template(1, Side::Ask, 90, 5), TriggerKind::Below(Price::from_raw(90)))
        .unwrap();
    let mut buf = Vec::with_capacity(8);
    e.evaluate_into(Price::from_raw(95), &mut buf);
    assert!(buf.is_empty());
    e.evaluate_into(Price::from_raw(90), &mut buf);
    assert_eq!(buf.len(), 1);
}

#[test]
fn capacity_exhaustion_and_validation_errors() {
    let mut e = ConditionalEngine::new(ConditionalConfig { capacity: 1 });
    e.add_stop(template(1, Side::Ask, 90, 5), TriggerKind::Below(Price::from_raw(90)))
        .unwrap();
    assert_eq!(
        e.add_stop(template(2, Side::Ask, 90, 5), TriggerKind::Below(Price::from_raw(90))),
        Err(ConditionalError::CapacityExhausted)
    );
    let mut e = ConditionalEngine::new(ConditionalConfig::default());
    assert_eq!(
        e.add_twap(template(1, Side::Bid, 100, 10), 0),
        Err(ConditionalError::ZeroSlices)
    );
    assert_eq!(
        e.add_stop(template(1, Side::Bid, 100, 0), TriggerKind::Above(Price::from_raw(1))),
        Err(ConditionalError::NonPositiveQuantity)
    );
    assert_eq!(
        e.add_trailing(
            template(1, Side::Ask, 0, 5),
            TrailDirection::SellStop,
            Price::from_raw(0),
            Price::from_raw(100)
        ),
        Err(ConditionalError::NonPositiveOffset)
    );
}

#[test]
fn decode_roundtrips_valid_buffer() {
    let mut bytes = [0u8; ENCODED_CONDITIONAL_LEN];
    bytes[0] = 1; // Ask
    bytes[1] = 0; // Limit
    bytes[2] = 0; // Gtc
    bytes[3] = 1; // Below
    bytes[4..12].copy_from_slice(&100_000i64.to_le_bytes());
    bytes[12..20].copy_from_slice(&5_000i64.to_le_bytes());
    bytes[20..28].copy_from_slice(&90_000i64.to_le_bytes());
    bytes[28..36].copy_from_slice(&42u64.to_le_bytes());
    bytes[36] = 0; // reduce_only=false
    let decoded = decode_conditional(&bytes).unwrap();
    assert_eq!(decoded.place.side, Side::Ask);
    assert_eq!(decoded.place.quantity, Quantity::from_raw(5_000));
    assert_eq!(decoded.trigger, TriggerKind::Below(Price::from_raw(90_000)));
    assert_eq!(decoded.place.client_id, 42);
}

#[test]
fn decode_rejects_malformed_and_never_panics() {
    // Too short.
    assert_eq!(decode_conditional(&[]), Err(ConditionalError::Malformed));
    assert_eq!(decode_conditional(&[0u8; 10]), Err(ConditionalError::Malformed));
    // Bad enum tag.
    let mut bytes = [0u8; ENCODED_CONDITIONAL_LEN];
    bytes[12..20].copy_from_slice(&5i64.to_le_bytes());
    bytes[0] = 9; // invalid side
    assert_eq!(decode_conditional(&bytes), Err(ConditionalError::Malformed));

    // Arbitrary bytes must never panic.
    let mut r = Lcg(0xF00D);
    let mut buf = Vec::new();
    for _ in 0..50_000 {
        let len = usize::try_from(r.below(64)).unwrap();
        buf.clear();
        for _ in 0..len {
            buf.push(u8::try_from(r.next_u64() & 0xFF).unwrap());
        }
        let _ = decode_conditional(&buf);
    }
}

#[test]
fn decoded_conditional_drives_engine() {
    let mut bytes = [0u8; ENCODED_CONDITIONAL_LEN];
    bytes[0] = 1; // Ask
    bytes[3] = 1; // Below
    bytes[4..12].copy_from_slice(&90_000i64.to_le_bytes());
    bytes[12..20].copy_from_slice(&5_000i64.to_le_bytes());
    bytes[20..28].copy_from_slice(&90_000i64.to_le_bytes());
    let decoded = decode_conditional(&bytes).unwrap();
    let mut e = ConditionalEngine::new(ConditionalConfig::default());
    e.add_stop(decoded.place, decoded.trigger).unwrap();
    assert!(e.on_mark_price(Price::from_raw(95_000)).is_empty());
    assert_eq!(e.on_mark_price(Price::from_raw(90_000)).len(), 1);
}

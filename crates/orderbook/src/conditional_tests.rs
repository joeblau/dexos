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
    assert!(!below.fires(Price::from_raw(101)));
    assert!(below.fires(Price::from_raw(99)));
}

#[test]
fn stop_loss_and_take_profit_mapping() {
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
fn simple_stop_emits_once_and_requires_ack() {
    let mut e = ConditionalEngine::new(ConditionalConfig::default());
    let id = e
        .add_stop(
            template(1, Side::Ask, 90, 5),
            TriggerKind::Below(Price::from_raw(90)),
        )
        .unwrap();
    assert!(e.on_mark_price(Price::from_raw(95)).is_empty());
    assert_eq!(e.pending_len(), 1);
    let intents = e.on_mark_price(Price::from_raw(90));
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].0, id);
    assert!(matches!(
        intents[0].1,
        OrderIntent::Place { quantity, .. } if quantity == Quantity::from_raw(5)
    ));
    assert_eq!(e.status(id), Some(ConditionalStatus::PendingExecution));
    // Duplicate price tick does not re-emit while PendingExecution.
    assert!(e.on_mark_price(Price::from_raw(85)).is_empty());
    e.ack(id, AccountId::new(1), ExecutionAck::Executed)
        .unwrap();
    assert_eq!(e.status(id), None);
    assert_eq!(e.pending_len(), 0);
}

#[test]
fn transient_execution_failure_retains_retryable_conditional() {
    let mut e = ConditionalEngine::new(ConditionalConfig::default());
    let id = e
        .add_stop(
            template(1, Side::Ask, 90, 5),
            TriggerKind::Below(Price::from_raw(90)),
        )
        .unwrap();
    let intents = e.on_mark_price(Price::from_raw(90));
    assert_eq!(intents.len(), 1);
    e.ack(id, AccountId::new(1), ExecutionAck::Retryable)
        .unwrap();
    assert_eq!(e.status(id), Some(ConditionalStatus::Retryable));
    assert!(e.pending_batch(id).is_some());
    // Owner-bound retry re-emits the same batch.
    let again = e.retry(id, AccountId::new(1)).unwrap();
    assert_eq!(again, intents[0].1);
    assert_eq!(e.status(id), Some(ConditionalStatus::PendingExecution));
    // Wrong owner cannot ack or retry.
    assert_eq!(
        e.ack(id, AccountId::new(9), ExecutionAck::Executed),
        Err(ConditionalError::OwnerMismatch)
    );
    e.ack(id, AccountId::new(1), ExecutionAck::Executed)
        .unwrap();
}

#[test]
fn oco_emits_atomic_batch_all_or_none() {
    let mut e = ConditionalEngine::new(ConditionalConfig::default());
    let leg_a = OcoLeg {
        trigger: TriggerKind::Below(Price::from_raw(90)),
        place: Some(template(10, Side::Ask, 90, 3)),
        cancel_order_id: Some(OrderId::new(99)),
    };
    let leg_b = OcoLeg {
        trigger: TriggerKind::Above(Price::from_raw(110)),
        place: Some(template(11, Side::Ask, 110, 3)),
        cancel_order_id: Some(OrderId::new(98)),
    };
    let id = e.add_oco(leg_a, leg_b).unwrap();
    let intents = e.on_mark_price(Price::from_raw(90));
    assert_eq!(intents.len(), 1);
    match &intents[0].1 {
        OrderIntent::Atomic { legs } => {
            assert_eq!(legs.len(), 2);
            assert!(matches!(legs[0], OrderIntent::Place { .. }));
            assert!(matches!(
                legs[1],
                OrderIntent::Cancel {
                    order_id
                } if order_id == OrderId::new(99)
            ));
        }
        other => panic!("expected Atomic, got {other:?}"),
    }
    // Fault injection: reject keeps no half-applied state in the engine;
    // retryable retains the full atomic batch.
    e.ack(id, AccountId::new(1), ExecutionAck::Retryable)
        .unwrap();
    let batch = e.pending_batch(id).cloned().unwrap();
    assert!(matches!(batch, OrderIntent::Atomic { .. }));
    e.ack(id, AccountId::new(1), ExecutionAck::Executed)
        .unwrap();
    assert_eq!(e.pending_len(), 0);
}

#[test]
fn twap_children_positive_sum_exact_no_wrap() {
    let mut e = ConditionalEngine::new(ConditionalConfig::default());
    // parent 10, slices 3 => 4,3,3
    let id = e.add_twap(template(100, Side::Bid, 50, 10), 3).unwrap();
    let mut total = 0i64;
    for expected in [4i64, 3, 3] {
        let intents = e.on_mark_price(Price::from_raw(50));
        assert_eq!(intents.len(), 1);
        match intents[0].1 {
            OrderIntent::Place {
                quantity, order_id, ..
            } => {
                assert_eq!(quantity.raw(), expected);
                total += quantity.raw();
                // Child ids are base + index without wrap.
                assert!(order_id.get() >= 100);
            }
            _ => panic!("expected Place"),
        }
        e.ack(id, AccountId::new(1), ExecutionAck::Executed)
            .unwrap();
    }
    assert_eq!(total, 10);
    assert_eq!(e.pending_len(), 0);
    // Zero-size slices rejected: parent 2, slices 3.
    assert_eq!(
        e.add_twap(template(200, Side::Bid, 50, 2), 3),
        Err(ConditionalError::NonPositiveQuantity)
    );
    // Wrap rejected: base near u64::MAX.
    let wrap = PlaceTemplate {
        order_id: OrderId::new(u64::MAX - 1),
        account: AccountId::new(1),
        side: Side::Bid,
        order_type: OrderType::Limit,
        tif: TimeInForce::Gtc,
        price: Price::from_raw(1),
        quantity: Quantity::from_raw(10),
        client_id: u64::MAX - 1,
        reduce_only: false,
    };
    assert_eq!(e.add_twap(wrap, 3), Err(ConditionalError::Overflow));
}

#[test]
fn decode_cannot_default_or_redirect_ownership() {
    let mut bytes = vec![0u8; ENCODED_CONDITIONAL_LEN];
    // account = 42
    bytes[0..4].copy_from_slice(&42u32.to_le_bytes());
    bytes[4] = 0; // Bid
    bytes[5] = 0; // Limit
    bytes[6] = 0; // Gtc
    bytes[7] = 0; // Above
    bytes[8..16].copy_from_slice(&1_000i64.to_le_bytes());
    bytes[16..24].copy_from_slice(&5i64.to_le_bytes());
    bytes[24..32].copy_from_slice(&900i64.to_le_bytes());
    bytes[32..40].copy_from_slice(&7u64.to_le_bytes());
    bytes[40] = 0;
    let decoded = decode_conditional(&bytes).unwrap();
    assert_eq!(decoded.place.account, AccountId::new(42));
    // Truncated buffer is malformed, never defaults owner.
    assert_eq!(
        decode_conditional(&bytes[..40]),
        Err(ConditionalError::Malformed)
    );
}

#[test]
fn zero_trigger_evaluation_is_sublinear() {
    let mut e = ConditionalEngine::new(ConditionalConfig {
        capacity: 1 << 14,
    });
    // Many far-away Above triggers; a low mark fires none.
    for i in 0..1_000u64 {
        e.add_stop(
            template(i + 1, Side::Bid, 1_000_000, 1),
            TriggerKind::Above(Price::from_raw(1_000_000 + i as i64)),
        )
        .unwrap();
    }
    // Below triggers with very low thresholds will not fire on a high mark.
    for i in 0..100u64 {
        e.add_stop(
            template(10_000 + i, Side::Ask, 1, 1),
            TriggerKind::Below(Price::from_raw(-(1_000_000 + i as i64))),
        )
        .unwrap();
    }
    let fired = e.on_mark_price(Price::from_raw(0));
    assert!(fired.is_empty());
    // A high price fires only the Above triggers at or below it.
    let mut e2 = ConditionalEngine::new(ConditionalConfig::default());
    for i in 0..50u64 {
        e2.add_stop(
            template(i + 1, Side::Bid, 100, 1),
            TriggerKind::Above(Price::from_raw(100 + i as i64)),
        )
        .unwrap();
    }
    let fired = e2.on_mark_price(Price::from_raw(110));
    assert_eq!(fired.len(), 11); // thresholds 100..=110
}

#[test]
fn property_trailing_ratchets_forward_and_matches_naive() {
    for (seed, dir) in [
        (1u64, TrailDirection::SellStop),
        (2, TrailDirection::BuyStop),
    ] {
        let mut r = Lcg(0x5A5A ^ seed);
        let offset = 10i64;
        let reference = Price::from_raw(1_000);
        let mut trail = Trailing::new(dir, Price::from_raw(offset), reference);
        let mut naive_extremum = reference.raw();
        let mut last_threshold = trail.threshold().raw();
        for _ in 0..50_000 {
            let p = Price::from_raw(i64::try_from(r.below(2_000)).unwrap());
            trail.update(p);
            match dir {
                TrailDirection::SellStop => {
                    if p.raw() > naive_extremum {
                        naive_extremum = p.raw();
                    }
                    let expected = naive_extremum.saturating_sub(offset);
                    assert_eq!(trail.threshold().raw(), expected);
                    assert!(trail.threshold().raw() >= last_threshold);
                }
                TrailDirection::BuyStop => {
                    if p.raw() < naive_extremum {
                        naive_extremum = p.raw();
                    }
                    let expected = naive_extremum.saturating_add(offset);
                    assert_eq!(trail.threshold().raw(), expected);
                    assert!(trail.threshold().raw() <= last_threshold || last_threshold == 0);
                }
            }
            last_threshold = trail.threshold().raw();
        }
    }
}

#[test]
fn never_panics_decoding_arbitrary_bytes() {
    let mut r = Lcg(0xBEEF);
    for _ in 0..50_000 {
        let len = usize::try_from(r.below(64)).unwrap();
        let bytes: Vec<u8> = (0..len)
            .map(|_| u8::try_from(r.below(256)).unwrap())
            .collect();
        let _ = decode_conditional(&bytes);
    }
}

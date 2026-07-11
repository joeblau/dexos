// Unit + property tests for the order book. Included into `book::tests`.

use super::*;
use crate::order::{BookConfig, NewOrder, OrderOutcome, StpPolicy};
use types::{AccountId, OrderId, OrderType, Price, Quantity, Side, TimeInForce};

/// Small deterministic LCG so property tests are reproducible bit-for-bit.
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

fn cfg() -> BookConfig {
    BookConfig {
        capacity: 1024,
        stp: StpPolicy::CancelMaker,
        dedup_capacity: 256,
        max_basket_legs: 16,
    }
}

#[allow(clippy::too_many_arguments)]
fn order(
    id: u64,
    acct: u32,
    side: Side,
    ot: OrderType,
    tif: TimeInForce,
    price: i64,
    qty: i64,
    client: u64,
) -> NewOrder {
    NewOrder {
        order_id: OrderId::new(id),
        account: AccountId::new(acct),
        side,
        order_type: ot,
        tif,
        price: Price::from_raw(price),
        quantity: Quantity::from_raw(qty),
        client_id: client,
        reduce_only: false,
    }
}

fn limit(id: u64, acct: u32, side: Side, price: i64, qty: i64) -> NewOrder {
    order(id, acct, side, OrderType::Limit, TimeInForce::Gtc, price, qty, id)
}

#[test]
fn price_time_priority_matches_best_then_oldest() {
    let mut b = OrderBook::new(cfg());
    // Two asks at the same price; the older (id 1) must fill first.
    b.submit(limit(1, 1, Side::Ask, 100, 5)).unwrap();
    b.submit(limit(2, 2, Side::Ask, 100, 5)).unwrap();
    // A better-priced ask should be preferred over both.
    b.submit(limit(3, 3, Side::Ask, 99, 5)).unwrap();
    let res = b.submit(limit(4, 4, Side::Bid, 100, 8)).unwrap();
    assert_eq!(res.fills.len(), 2);
    // Best price first: id 3 @ 99, then oldest at 100: id 1.
    assert_eq!(res.fills[0].maker_order, OrderId::new(3));
    assert_eq!(res.fills[0].price, Price::from_raw(99));
    assert_eq!(res.fills[1].maker_order, OrderId::new(1));
    assert_eq!(res.fills[1].quantity, Quantity::from_raw(3));
    assert!(matches!(res.outcome, OrderOutcome::FullyFilled));
}

#[test]
fn o1_cancel_removes_only_target() {
    let mut b = OrderBook::new(cfg());
    b.submit(limit(1, 1, Side::Bid, 100, 5)).unwrap();
    b.submit(limit(2, 1, Side::Bid, 100, 5)).unwrap();
    b.submit(limit(3, 1, Side::Bid, 100, 5)).unwrap();
    assert_eq!(b.resting_len(), 3);
    b.cancel(OrderId::new(2)).unwrap();
    assert_eq!(b.resting_len(), 2);
    assert!(b.contains(OrderId::new(1)));
    assert!(!b.contains(OrderId::new(2)));
    assert!(b.contains(OrderId::new(3)));
    assert_eq!(b.cancel(OrderId::new(2)), Err(OrderError::UnknownOrder));
    // Remaining orders preserve FIFO order 1 then 3.
    let res = b.submit(limit(9, 2, Side::Ask, 100, 6)).unwrap();
    assert_eq!(res.fills[0].maker_order, OrderId::new(1));
    assert_eq!(res.fills[1].maker_order, OrderId::new(3));
}

#[test]
fn best_bid_ask_track_the_book() {
    let mut b = OrderBook::new(cfg());
    assert_eq!(b.best_bid(), None);
    assert_eq!(b.best_ask(), None);
    b.submit(limit(1, 1, Side::Bid, 100, 5)).unwrap();
    b.submit(limit(2, 1, Side::Bid, 101, 5)).unwrap();
    b.submit(limit(3, 2, Side::Ask, 110, 5)).unwrap();
    b.submit(limit(4, 2, Side::Ask, 108, 5)).unwrap();
    assert_eq!(b.best_bid(), Some(Price::from_raw(101)));
    assert_eq!(b.best_ask(), Some(Price::from_raw(108)));
}

#[test]
fn ioc_fills_available_and_cancels_residual() {
    let mut b = OrderBook::new(cfg());
    b.submit(limit(1, 1, Side::Ask, 100, 3)).unwrap();
    let res = b
        .submit(order(2, 2, Side::Bid, OrderType::Limit, TimeInForce::Ioc, 100, 10, 2))
        .unwrap();
    assert_eq!(res.filled_quantity(), Quantity::from_raw(3));
    assert!(matches!(
        res.outcome,
        OrderOutcome::PartiallyFilledCancelled { filled } if filled == Quantity::from_raw(3)
    ));
    // Nothing rested.
    assert_eq!(b.best_bid(), None);
    assert_eq!(b.resting_len(), 0);
}

#[test]
fn ioc_with_no_liquidity_is_rejected() {
    let mut b = OrderBook::new(cfg());
    let res = b
        .submit(order(1, 1, Side::Bid, OrderType::Limit, TimeInForce::Ioc, 100, 5, 1))
        .unwrap();
    assert!(matches!(res.outcome, OrderOutcome::Rejected));
    assert!(res.fills.is_empty());
}

#[test]
fn fok_rejects_partial_cross_and_leaves_book_untouched() {
    let mut b = OrderBook::new(cfg());
    b.submit(limit(1, 1, Side::Ask, 100, 3)).unwrap();
    let root_before = b.state_root();
    let res = b
        .submit(order(2, 2, Side::Bid, OrderType::Limit, TimeInForce::Fok, 100, 5, 2))
        .unwrap();
    assert!(matches!(res.outcome, OrderOutcome::Rejected));
    assert!(res.fills.is_empty());
    // Book unchanged.
    assert_eq!(b.state_root(), root_before);
    assert_eq!(b.level_quantity(Side::Ask, Price::from_raw(100)), Quantity::from_raw(3));
}

#[test]
fn fok_fully_fills_when_liquidity_suffices() {
    let mut b = OrderBook::new(cfg());
    b.submit(limit(1, 1, Side::Ask, 100, 3)).unwrap();
    b.submit(limit(2, 1, Side::Ask, 101, 3)).unwrap();
    let res = b
        .submit(order(3, 2, Side::Bid, OrderType::Limit, TimeInForce::Fok, 101, 5, 3))
        .unwrap();
    assert!(matches!(res.outcome, OrderOutcome::FullyFilled));
    assert_eq!(res.filled_quantity(), Quantity::from_raw(5));
}

#[test]
fn post_only_rejects_when_crossing_but_rests_otherwise() {
    let mut b = OrderBook::new(cfg());
    b.submit(limit(1, 1, Side::Ask, 100, 5)).unwrap();
    // Would cross -> rejected, no fills, nothing rests on bid side.
    let crossing = order(2, 2, Side::Bid, OrderType::PostOnly, TimeInForce::Gtc, 100, 5, 2);
    let res = b.submit(crossing).unwrap();
    assert!(matches!(res.outcome, OrderOutcome::Rejected));
    assert_eq!(b.best_bid(), None);
    // Non-crossing post-only rests.
    let resting = order(3, 2, Side::Bid, OrderType::PostOnly, TimeInForce::Gtc, 99, 5, 3);
    let res = b.submit(resting).unwrap();
    assert!(matches!(res.outcome, OrderOutcome::Resting { .. }));
    assert_eq!(b.best_bid(), Some(Price::from_raw(99)));
}

#[test]
fn market_order_exhausts_book_then_cancels_remainder() {
    let mut b = OrderBook::new(cfg());
    b.submit(limit(1, 1, Side::Ask, 100, 2)).unwrap();
    b.submit(limit(2, 1, Side::Ask, 101, 2)).unwrap();
    let res = b
        .submit(order(3, 2, Side::Bid, OrderType::Market, TimeInForce::Ioc, 0, 10, 3))
        .unwrap();
    assert_eq!(res.filled_quantity(), Quantity::from_raw(4));
    assert!(matches!(res.outcome, OrderOutcome::PartiallyFilledCancelled { .. }));
    assert_eq!(b.resting_len(), 0);
    // Empty-book market order is rejected.
    let res = b
        .submit(order(4, 2, Side::Bid, OrderType::Market, TimeInForce::Ioc, 0, 5, 4))
        .unwrap();
    assert!(matches!(res.outcome, OrderOutcome::Rejected));
}

#[test]
fn reduce_only_rejects_without_position_and_clamps_with_one() {
    let mut b = OrderBook::new(cfg());
    b.submit(limit(1, 1, Side::Bid, 100, 100)).unwrap();
    // Account 2 has no position: reduce-only sell rejected.
    let ro = NewOrder {
        reduce_only: true,
        ..order(2, 2, Side::Ask, OrderType::Limit, TimeInForce::Gtc, 100, 10, 2)
    };
    assert!(matches!(b.submit(ro).unwrap().outcome, OrderOutcome::Rejected));
    // Give account 2 a long of 3; reduce-only sell of 10 clamps to 3.
    b.set_position(AccountId::new(2), Quantity::from_raw(3));
    let ro = NewOrder {
        reduce_only: true,
        ..order(3, 2, Side::Ask, OrderType::Limit, TimeInForce::Gtc, 100, 10, 3)
    };
    let res = b.submit(ro).unwrap();
    assert_eq!(res.filled_quantity(), Quantity::from_raw(3));
    assert!(matches!(res.outcome, OrderOutcome::FullyFilled));
}

#[test]
fn self_trade_prevention_cancel_maker() {
    let mut b = OrderBook::new(cfg());
    b.submit(limit(1, 7, Side::Ask, 100, 5)).unwrap();
    // Same account crosses: maker cancelled, no self-fill; taker rests.
    let res = b.submit(limit(2, 7, Side::Bid, 100, 5)).unwrap();
    assert!(res.fills.is_empty());
    assert!(!b.contains(OrderId::new(1)));
    assert!(b.contains(OrderId::new(2)));
}

#[test]
fn self_trade_prevention_cancel_taker() {
    let mut c = cfg();
    c.stp = StpPolicy::CancelTaker;
    let mut b = OrderBook::new(c);
    b.submit(limit(1, 7, Side::Ask, 100, 5)).unwrap();
    let res = b.submit(limit(2, 7, Side::Bid, 100, 5)).unwrap();
    assert!(res.fills.is_empty());
    // Maker remains, taker cancelled (did not rest).
    assert!(b.contains(OrderId::new(1)));
    assert!(!b.contains(OrderId::new(2)));
}

#[test]
fn idempotent_duplicate_client_id_executes_once() {
    let mut b = OrderBook::new(cfg());
    b.submit(limit(1, 1, Side::Ask, 100, 5)).unwrap();
    let first = b.submit(limit(2, 2, Side::Bid, 100, 5)).unwrap();
    let root_after_first = b.state_root();
    // Resubmit the identical order (same account + client_id) several times.
    for _ in 0..5 {
        let again = b.submit(limit(2, 2, Side::Bid, 100, 5)).unwrap();
        assert_eq!(again, first);
        assert_eq!(b.state_root(), root_after_first);
    }
}

#[test]
fn cancel_all_removes_only_owner_orders_deterministically() {
    let mut b = OrderBook::new(cfg());
    b.submit(limit(1, 1, Side::Bid, 100, 5)).unwrap();
    b.submit(limit(2, 2, Side::Bid, 99, 5)).unwrap();
    b.submit(limit(3, 1, Side::Bid, 98, 5)).unwrap();
    b.submit(limit(4, 1, Side::Ask, 110, 5)).unwrap();
    let removed = b.cancel_all(AccountId::new(1));
    assert_eq!(removed, 3);
    assert!(!b.contains(OrderId::new(1)));
    assert!(b.contains(OrderId::new(2)));
    assert!(!b.contains(OrderId::new(3)));
    assert!(!b.contains(OrderId::new(4)));
    assert_eq!(b.cancel_all(AccountId::new(1)), 0);
}

#[test]
fn atomic_replace_failure_leaves_book_bit_identical() {
    let mut b = OrderBook::new(cfg());
    b.submit(limit(1, 1, Side::Bid, 100, 5)).unwrap();
    b.submit(limit(2, 2, Side::Ask, 110, 5)).unwrap();
    let root_before = b.state_root();
    // Invalid replacement (zero qty) must not touch the book.
    assert_eq!(
        b.replace(OrderId::new(1), Price::from_raw(101), Quantity::from_raw(0)),
        Err(OrderError::NonPositiveQuantity)
    );
    assert_eq!(b.state_root(), root_before);
    // Unknown order likewise.
    assert_eq!(
        b.replace(OrderId::new(999), Price::from_raw(101), Quantity::from_raw(5)),
        Err(OrderError::UnknownOrder)
    );
    assert_eq!(b.state_root(), root_before);
}

#[test]
fn replace_repositions_order() {
    let mut b = OrderBook::new(cfg());
    b.submit(limit(1, 1, Side::Bid, 100, 5)).unwrap();
    let res = b.replace(OrderId::new(1), Price::from_raw(105), Quantity::from_raw(8)).unwrap();
    assert!(matches!(res.outcome, OrderOutcome::Resting { remaining } if remaining == Quantity::from_raw(8)));
    assert_eq!(b.best_bid(), Some(Price::from_raw(105)));
    assert_eq!(b.level_quantity(Side::Bid, Price::from_raw(105)), Quantity::from_raw(8));
}

#[test]
fn basket_rejects_atomically_on_bad_leg() {
    let mut b = OrderBook::new(cfg());
    b.submit(limit(1, 1, Side::Bid, 100, 5)).unwrap();
    let root_before = b.state_root();
    // Second leg is invalid (zero qty) -> whole basket rejected, book unchanged.
    let legs = [
        limit(10, 2, Side::Ask, 110, 5),
        order(11, 2, Side::Ask, OrderType::Limit, TimeInForce::Gtc, 111, 0, 11),
    ];
    assert_eq!(b.submit_basket(&legs), Err(OrderError::NonPositiveQuantity));
    assert_eq!(b.state_root(), root_before);
    // Oversized basket rejected.
    let big: Vec<NewOrder> = (0..100).map(|i| limit(1000 + i, 3, Side::Ask, 200, 1)).collect();
    assert_eq!(b.submit_basket(&big), Err(OrderError::BasketTooLarge));
    assert_eq!(b.state_root(), root_before);
    // Valid basket applies.
    let ok = [limit(20, 4, Side::Ask, 120, 5), limit(21, 4, Side::Ask, 121, 5)];
    assert_eq!(b.submit_basket(&ok).unwrap().len(), 2);
    assert!(b.contains(OrderId::new(20)));
}

/// A non-crossing limit that cannot rest because the book is at capacity must
/// fail with a typed error and leave the book bit-identical: no fill occurred,
/// so nothing may be stranded behind the `Err`.
#[test]
fn capacity_exhausted_non_crossing_limit_leaves_book_bit_identical() {
    let mut b = OrderBook::new(BookConfig { capacity: 2, ..cfg() });
    b.submit(limit(1, 1, Side::Bid, 100, 5)).unwrap();
    b.submit(limit(2, 1, Side::Bid, 99, 5)).unwrap();
    assert_eq!(b.resting_len(), 2);
    let root_before = b.state_root();
    // Third resting order has nowhere to go: the slab is full and it does not
    // cross, so it cannot free a slot by matching.
    assert_eq!(
        b.submit(limit(3, 2, Side::Bid, 98, 5)),
        Err(OrderError::CapacityExhausted)
    );
    assert_eq!(b.state_root(), root_before);
    assert_eq!(b.resting_len(), 2);
    assert!(!b.contains(OrderId::new(3)));
}

/// A basket whose later leg exhausts capacity *after* an earlier leg has already
/// filled a resting maker must roll back completely: the consumed maker is
/// restored and no leg rests. This is the "capacity-exhausted after partial
/// fill" case.
#[test]
fn basket_capacity_exhaustion_after_partial_fill_rolls_back() {
    let mut b = OrderBook::new(BookConfig { capacity: 3, ..cfg() });
    // Two resting asks owned by account 1; one slot remains free.
    b.submit(limit(1, 1, Side::Ask, 100, 5)).unwrap();
    b.submit(limit(2, 1, Side::Ask, 101, 5)).unwrap();
    assert_eq!(b.resting_len(), 2);
    let root_before = b.state_root();

    let legs = [
        // Leg 1 crosses and partially consumes maker id 1 (fills 3, fully filled
        // so it does not rest): an irreversible fill.
        limit(10, 2, Side::Bid, 100, 3),
        // Leg 2 does not cross and rests, filling the book to capacity.
        limit(11, 2, Side::Bid, 95, 5),
        // Leg 3 does not cross and has nowhere to rest -> CapacityExhausted.
        limit(12, 2, Side::Bid, 94, 5),
    ];
    assert_eq!(
        b.submit_basket(&legs),
        Err(OrderError::CapacityExhausted)
    );

    // Whole basket rolled back: maker id 1 restored to its full size, no leg
    // rests, and the book hashes identically to before the basket.
    assert_eq!(b.state_root(), root_before);
    assert_eq!(b.resting_len(), 2);
    assert_eq!(
        b.level_quantity(Side::Ask, Price::from_raw(100)),
        Quantity::from_raw(5)
    );
    assert!(!b.contains(OrderId::new(10)));
    assert!(!b.contains(OrderId::new(11)));
    assert!(!b.contains(OrderId::new(12)));
}

/// Rollback is deterministic: replaying the identical pre-state and failing
/// basket yields the identical state root. Guards the replay path for
/// capacity-exhausted-after-partial-fill.
#[test]
fn basket_capacity_rollback_is_deterministic_on_replay() {
    fn run() -> types::Hash {
        let mut b = OrderBook::new(BookConfig { capacity: 3, ..cfg() });
        b.submit(limit(1, 1, Side::Ask, 100, 5)).unwrap();
        b.submit(limit(2, 1, Side::Ask, 101, 5)).unwrap();
        let legs = [
            limit(10, 2, Side::Bid, 100, 3),
            limit(11, 2, Side::Bid, 95, 5),
            limit(12, 2, Side::Bid, 94, 5),
        ];
        assert!(b.submit_basket(&legs).is_err());
        // A valid follow-up still applies normally after a rolled-back basket.
        b.submit(limit(20, 3, Side::Bid, 90, 1)).unwrap();
        b.state_root()
    }
    assert_eq!(run(), run());
}

/// Rollback must not over-reject: baskets whose legs all fully fill (needing no
/// resting slot) succeed even at full capacity. A naive free-slot pre-check
/// would wrongly reject these; speculative apply + rollback does not.
#[test]
fn basket_at_capacity_succeeds_when_all_legs_fully_fill() {
    let mut b = OrderBook::new(BookConfig { capacity: 1, ..cfg() });
    // Single resting maker fills the book to capacity.
    b.submit(limit(1, 1, Side::Ask, 100, 10)).unwrap();
    assert!(b.resting_len() == 1);
    // Both legs cross and fully fill against the maker; neither needs a slot.
    let legs = [limit(10, 2, Side::Bid, 100, 4), limit(11, 2, Side::Bid, 100, 3)];
    let out = b.submit_basket(&legs).unwrap();
    assert_eq!(out.len(), 2);
    assert!(matches!(out[0].outcome, OrderOutcome::FullyFilled));
    assert!(matches!(out[1].outcome, OrderOutcome::FullyFilled));
    // Maker reduced by 7, still resting the remainder.
    assert_eq!(
        b.level_quantity(Side::Ask, Price::from_raw(100)),
        Quantity::from_raw(3)
    );
}

/// Property: every `Err` returned by `submit` or `submit_basket` leaves the book
/// bit-identical to its pre-command state. Run against a deliberately small book
/// so capacity exhaustion is exercised constantly.
#[test]
fn property_err_leaves_book_bit_identical() {
    let mut r = Lcg(0xFACE_FEED);
    let mut b = OrderBook::new(BookConfig {
        capacity: 8,
        dedup_capacity: 64,
        max_basket_legs: 6,
        ..cfg()
    });
    let mut next_id = 1u64;
    for _ in 0..40_000 {
        // Occasionally clear the book so both full and non-full states recur.
        if r.below(40) == 0 {
            for a in 0..4 {
                b.cancel_all(AccountId::new(a));
            }
        }
        let root_before = b.state_root();
        if r.below(5) == 0 {
            // Basket of 1..=4 legs with unique, monotonic order ids.
            let n = 1 + r.below(4);
            let mut legs = Vec::new();
            for _ in 0..n {
                let side = if r.below(2) == 0 { Side::Bid } else { Side::Ask };
                let acct = u32::try_from(r.below(4)).unwrap();
                let price = 90 + i64::try_from(r.below(15)).unwrap();
                let qty = 1 + i64::try_from(r.below(5)).unwrap();
                legs.push(limit_acct(next_id, acct, side, price, qty));
                next_id += 1;
            }
            if b.submit_basket(&legs).is_err() {
                assert_eq!(
                    b.state_root(),
                    root_before,
                    "a rejected basket must leave the book bit-identical"
                );
            }
        } else {
            let side = if r.below(2) == 0 { Side::Bid } else { Side::Ask };
            let acct = u32::try_from(r.below(4)).unwrap();
            let price = 90 + i64::try_from(r.below(15)).unwrap();
            let qty = 1 + i64::try_from(r.below(5)).unwrap();
            let ot = match r.below(4) {
                0 => OrderType::Limit,
                1 => OrderType::Market,
                2 => OrderType::PostOnly,
                _ => OrderType::Limit,
            };
            let tif = match r.below(3) {
                0 => TimeInForce::Gtc,
                1 => TimeInForce::Ioc,
                _ => TimeInForce::Fok,
            };
            let ord = order(next_id, acct, side, ot, tif, price, qty, next_id);
            next_id += 1;
            if b.submit(ord).is_err() {
                assert_eq!(
                    b.state_root(),
                    root_before,
                    "a rejected submit must leave the book bit-identical"
                );
            }
        }
    }
}

#[test]
fn duplicate_order_id_and_bad_input_are_typed_errors() {
    let mut b = OrderBook::new(cfg());
    b.submit(limit(1, 1, Side::Bid, 100, 5)).unwrap();
    // Same order id, different client id -> collision error.
    let dup = order(1, 1, Side::Bid, OrderType::Limit, TimeInForce::Gtc, 100, 5, 999);
    assert_eq!(b.submit(dup), Err(OrderError::DuplicateOrderId));
    let zero_qty = order(2, 1, Side::Bid, OrderType::Limit, TimeInForce::Gtc, 100, 0, 2);
    assert_eq!(b.submit(zero_qty), Err(OrderError::NonPositiveQuantity));
    let bad_price = order(3, 1, Side::Bid, OrderType::Limit, TimeInForce::Gtc, -5, 5, 3);
    assert_eq!(b.submit(bad_price), Err(OrderError::NonPositivePrice));
}

#[test]
fn property_quantity_conservation_across_random_fills() {
    let mut r = Lcg(0xC0FFEE);
    let mut b = OrderBook::new(BookConfig { capacity: 32_768, dedup_capacity: 4096, ..cfg() });
    let mut next_id = 1u64;
    for _ in 0..20_000 {
        let side = if r.below(2) == 0 { Side::Bid } else { Side::Ask };
        // Unique account per order so self-trade prevention never fires here;
        // that would cancel a resting maker and is covered by other tests.
        let acct = u32::try_from(next_id).unwrap();
        let price = 90 + i64::try_from(r.below(20)).unwrap();
        let qty = 1 + i64::try_from(r.below(9)).unwrap();
        let ot = match r.below(4) {
            0 => OrderType::Limit,
            1 => OrderType::Limit,
            2 => OrderType::Market,
            _ => OrderType::PostOnly,
        };
        let tif = match r.below(3) {
            0 => TimeInForce::Gtc,
            1 => TimeInForce::Ioc,
            _ => TimeInForce::Fok,
        };
        let ord = order(next_id, acct, side, ot, tif, price, qty, next_id);
        next_id += 1;

        let before = b.total_resting_quantity().raw();
        let res = match b.submit(ord) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let after = b.total_resting_quantity().raw();
        let filled = res.filled_quantity().raw();
        let rested = match res.outcome {
            OrderOutcome::Resting { remaining } => remaining.raw(),
            OrderOutcome::PartiallyFilledResting { remaining } => remaining.raw(),
            _ => 0,
        };
        // Makers lost exactly `filled`; the taker's residual that rested added
        // `rested`. This is exact quantity conservation.
        assert_eq!(after, before - filled + rested);
        // Filled + reported residual never exceeds the submitted quantity.
        let submitted = ord.quantity.raw();
        let accounted = match res.outcome {
            OrderOutcome::FullyFilled => filled,
            OrderOutcome::Resting { remaining } => filled + remaining.raw(),
            OrderOutcome::PartiallyFilledResting { remaining } => filled + remaining.raw(),
            OrderOutcome::PartiallyFilledCancelled { filled: f } => f.raw(),
            OrderOutcome::Rejected => 0,
        };
        assert!(accounted <= submitted);
        if matches!(res.outcome, OrderOutcome::FullyFilled | OrderOutcome::Resting { .. } | OrderOutcome::PartiallyFilledResting { .. }) {
            assert_eq!(accounted, submitted);
        }
    }
}

#[test]
fn property_no_self_trade_under_any_policy() {
    for (seed, policy) in [
        (1u64, StpPolicy::CancelMaker),
        (2, StpPolicy::CancelTaker),
        (3, StpPolicy::CancelBoth),
    ] {
        let mut r = Lcg(0xABBA ^ seed);
        let mut b =
            OrderBook::new(BookConfig { capacity: 2048, stp: policy, dedup_capacity: 512, ..cfg() });
        let mut next_id = 1u64;
        for _ in 0..10_000 {
            let side = if r.below(2) == 0 { Side::Bid } else { Side::Ask };
            let acct = u32::try_from(r.below(4)).unwrap();
            let price = 95 + i64::try_from(r.below(10)).unwrap();
            let qty = 1 + i64::try_from(r.below(5)).unwrap();
            let ord = limit_acct(next_id, acct, side, price, qty);
            next_id += 1;
            // Periodically clear the book so capacity is never exhausted.
            if next_id.is_multiple_of(1000) {
                for a in 0..4 {
                    b.cancel_all(AccountId::new(a));
                }
            }
            let res = match b.submit(ord) {
                Ok(r) => r,
                Err(_) => continue,
            };
            for f in &res.fills {
                assert_ne!(f.maker_account, f.taker_account, "self-trade under {policy:?}");
            }
        }
    }
}

fn limit_acct(id: u64, acct: u32, side: Side, price: i64, qty: i64) -> NewOrder {
    order(id, acct, side, OrderType::Limit, TimeInForce::Gtc, price, qty, id)
}

#[test]
fn deterministic_replay_yields_identical_state_root() {
    fn run() -> types::Hash {
        let mut r = Lcg(0x1234_5678);
        let mut b = OrderBook::new(BookConfig { capacity: 4096, ..cfg() });
        let mut next_id = 1u64;
        for _ in 0..15_000 {
            let choice = r.below(5);
            if choice == 0 && next_id > 5 {
                let victim = OrderId::new(1 + r.below(next_id - 1));
                let _ = b.cancel(victim);
            } else if choice == 1 {
                let _ = b.cancel_all(AccountId::new(u32::try_from(r.below(6)).unwrap()));
            } else {
                let side = if r.below(2) == 0 { Side::Bid } else { Side::Ask };
                let acct = u32::try_from(r.below(6)).unwrap();
                let price = 90 + i64::try_from(r.below(20)).unwrap();
                let qty = 1 + i64::try_from(r.below(9)).unwrap();
                let _ = b.submit(limit_acct(next_id, acct, side, price, qty));
                next_id += 1;
            }
        }
        b.state_root()
    }
    assert_eq!(run(), run());
}

#[test]
fn never_panics_on_arbitrary_orders() {
    let mut r = Lcg(0xDEAD_BEEF);
    let mut b = OrderBook::new(BookConfig { capacity: 512, ..cfg() });
    for i in 0..50_000u64 {
        let side = if r.next_u64() & 1 == 0 { Side::Bid } else { Side::Ask };
        let ot = match r.below(4) {
            0 => OrderType::Limit,
            1 => OrderType::Market,
            2 => OrderType::PostOnly,
            _ => OrderType::ReduceOnly,
        };
        let tif = match r.below(3) {
            0 => TimeInForce::Gtc,
            1 => TimeInForce::Ioc,
            _ => TimeInForce::Fok,
        };
        let ord = NewOrder {
            order_id: OrderId::new(r.next_u64()),
            account: AccountId::new(u32::try_from(r.below(1 << 20)).unwrap()),
            side,
            order_type: ot,
            tif,
            price: Price::from_raw(i64::from_le_bytes(r.next_u64().to_le_bytes())),
            quantity: Quantity::from_raw(i64::from_le_bytes(r.next_u64().to_le_bytes())),
            client_id: r.next_u64(),
            reduce_only: r.next_u64() & 1 == 0,
        };
        // Occasionally stub a random position and issue cancels / replaces.
        if i % 7 == 0 {
            b.set_position(
                AccountId::new(u32::try_from(r.below(16)).unwrap()),
                Quantity::from_raw(i64::from_le_bytes(r.next_u64().to_le_bytes())),
            );
        }
        let _ = b.submit(ord);
        let _ = b.cancel(OrderId::new(r.next_u64()));
        let _ = b.replace(
            OrderId::new(r.next_u64()),
            Price::from_raw(i64::from_le_bytes(r.next_u64().to_le_bytes())),
            Quantity::from_raw(i64::from_le_bytes(r.next_u64().to_le_bytes())),
        );
        let _ = b.state_root();
    }
}

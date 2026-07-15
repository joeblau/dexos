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
        matching_backend: simd::Backend::Scalar,
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

fn codec_cfg() -> BookConfig {
    BookConfig {
        capacity: 12,
        stp: StpPolicy::CancelMaker,
        dedup_capacity: 8,
        max_basket_legs: 4,
        matching_backend: simd::Backend::Scalar,
    }
}

fn codec_fixture() -> OrderBook {
    let mut book = OrderBook::new(codec_cfg());
    book.submit(limit(1, 1, Side::Ask, 110, 3)).unwrap();
    book.submit(limit(2, 2, Side::Ask, 111, 4)).unwrap();
    book.submit(limit(3, 3, Side::Bid, 111, 5)).unwrap();
    book.place(limit(4, 4, Side::Bid, 100, 1)).unwrap();
    book.set_position(AccountId::new(7), Quantity::from_raw(3));
    book.set_position(AccountId::new(8), Quantity::from_raw(-2));
    book
}

fn canonical_bytes(book: &OrderBook) -> Vec<u8> {
    book.encode_state_v3_bounded(usize::MAX).unwrap()
}

fn assert_logically_identical(left: &OrderBook, right: &OrderBook) {
    assert_eq!(canonical_bytes(left), canonical_bytes(right));
    assert_eq!(left.state_root(), right.state_root());
    assert_eq!(left.state_root_full_rebuild(), right.state_root_full_rebuild());
    assert_eq!(left.transition_root_v3(), right.transition_root_v3());
    assert_eq!(left.best_bid(), right.best_bid());
    assert_eq!(left.best_ask(), right.best_ask());
    assert_eq!(left.resting_len(), right.resting_len());
    assert_eq!(left.total_resting_quantity(), right.total_resting_quantity());
}

fn overwrite_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn overwrite_i64(bytes: &mut [u8], offset: usize, value: i64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
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
fn resting_order_views_are_complete_sorted_and_root_neutral() {
    let mut b = OrderBook::new(cfg());
    b.place(limit(9, 2, Side::Ask, 110, 7)).unwrap();
    b.place(limit(3, 1, Side::Bid, 100, 5)).unwrap();
    let bytes = canonical_bytes(&b);
    let root = b.transition_root_v3();

    assert_eq!(
        b.resting_order(OrderId::new(9)),
        Some(crate::RestingOrder {
            order_id: OrderId::new(9),
            account: AccountId::new(2),
            side: Side::Ask,
            price: Price::from_raw(110),
            remaining: Quantity::from_raw(7),
        })
    );
    assert_eq!(b.resting_order(OrderId::new(99)), None);
    assert_eq!(
        b.resting_orders(),
        vec![
            crate::RestingOrder {
                order_id: OrderId::new(3),
                account: AccountId::new(1),
                side: Side::Bid,
                price: Price::from_raw(100),
                remaining: Quantity::from_raw(5),
            },
            crate::RestingOrder {
                order_id: OrderId::new(9),
                account: AccountId::new(2),
                side: Side::Ask,
                price: Price::from_raw(110),
                remaining: Quantity::from_raw(7),
            },
        ]
    );
    assert_eq!(canonical_bytes(&b), bytes);
    assert_eq!(b.transition_root_v3(), root);
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
fn level_aggregate_overflow_rejects_without_mutation() {
    let mut b = OrderBook::new(cfg());
    b.submit(limit(1, 1, Side::Bid, 100, i64::MAX)).unwrap();
    let root = b.state_root();
    assert_eq!(b.submit(limit(2, 2, Side::Bid, 100, 1)), Err(OrderError::Overflow));
    assert_eq!(b.state_root(), root);
    assert_eq!(b.level_quantity(Side::Bid, Price::from_raw(100)), Quantity::from_raw(i64::MAX));
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

/// Cloning the book preserves its eager capacity reservations (slab backing
/// storage, id index) in addition to logical state, so books produced by
/// `Clone` — the engine's per-command copy and the basket snapshot/restore
/// path — keep the documented warm-path no-allocation guarantee. A derived
/// clone would shrink the reservations to the current entry count.
#[test]
fn clone_and_basket_rollback_preserve_eager_reservations() {
    let config = cfg();
    let mut b = OrderBook::new(config);
    b.submit(limit(1, 1, Side::Bid, 1, i64::MAX)).unwrap();
    b.submit(limit(2, 2, Side::Ask, 1_000, 5)).unwrap();

    let cloned = b.clone();
    // Logical state is bit-identical...
    assert_eq!(cloned.state_root(), b.state_root());
    assert_eq!(cloned.resting_len(), b.resting_len());
    // ...and the eager reservations survive the clone.
    assert_eq!(cloned.slab.capacity(), config.capacity);
    assert!(cloned.id_index.capacity() >= config.capacity);

    // End-to-end through the production rollback path: a failing leg restores
    // the snapshot clone, which must carry the reservations too. Leg 11
    // overflows the price-1 bid level (the maker rests i64::MAX there),
    // erroring only after leg 10 already mutated the book.
    let legs = [limit(10, 3, Side::Bid, 2, 1), limit(11, 3, Side::Bid, 1, 1)];
    assert!(b.submit_basket(&legs).is_err());
    assert_eq!(b.resting_len(), 2);
    assert!(b.id_index.capacity() >= config.capacity);
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
    for next_id in 1u64..=20_000 {
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
        // Incremental root must equal the full-rebuild oracle after every op.
        assert_eq!(b.state_root(), b.state_root_full_rebuild());
    }
}

#[test]
fn incremental_root_matches_full_rebuild_after_every_op() {
    let mut b = OrderBook::new(cfg());
    let mut r = Lcg(0xB007_A11CE);
    for i in 0..2_000u64 {
        assert_eq!(
            b.state_root(),
            b.state_root_full_rebuild(),
            "divergence before op {i}"
        );
        match r.below(5) {
            0 | 1 => {
                let id = r.next_u64();
                let side = if r.next_u64() & 1 == 0 {
                    Side::Bid
                } else {
                    Side::Ask
                };
                let px = 50 + (r.below(50) as i64);
                let qty = 1 + (r.below(20) as i64);
                let _ = b.submit(limit(id, (u32::try_from(r.below(8)).unwrap()) + 1, side, px, qty));
            }
            2 => {
                let _ = b.cancel(OrderId::new(r.next_u64()));
            }
            3 => {
                let id = r.next_u64();
                let px = 50 + (r.below(50) as i64);
                let qty = 1 + (r.below(20) as i64);
                let _ = b.replace(OrderId::new(id), Price::from_raw(px), Quantity::from_raw(qty));
            }
            _ => {
                // Crossing market sweep against whatever rests.
                let id = r.next_u64();
                let side = if r.next_u64() & 1 == 0 {
                    Side::Bid
                } else {
                    Side::Ask
                };
                let collar = 100i64;
                let qty = 1 + (r.below(30) as i64);
                let _ = b.submit(order(
                    id,
                    (u32::try_from(r.below(8)).unwrap()) + 1,
                    side,
                    OrderType::Market,
                    TimeInForce::Ioc,
                    collar,
                    qty,
                    id,
                ));
            }
        }
        assert_eq!(
            b.state_root(),
            b.state_root_full_rebuild(),
            "divergence after op {i}"
        );
    }
}

#[test]
fn book_root_schema_golden_vector() {
    // Locks the fast unordered diagnostic schema v2: empty book and a single
    // resting bid. Authoritative callers use transition_root_v3 instead.
    let mut b = OrderBook::new(cfg());
    let empty = b.state_root();
    assert_eq!(empty, b.state_root_full_rebuild());
    // Known-answer: schema version prefix makes the empty root non-zero and
    // stable across rebuilds.
    assert!(!empty.is_zero());
    b.submit(limit(1, 1, Side::Bid, 100, 5)).unwrap();
    let root = b.state_root();
    assert_eq!(root, b.state_root_full_rebuild());
    assert_ne!(root, empty);
    // Cancel restores the empty root (XOR involution).
    b.cancel(OrderId::new(1)).unwrap();
    assert_eq!(b.state_root(), empty);
    assert_eq!(OrderBook::hot_path_hash_budget_bytes(), 48 + 33);
}

#[test]
fn transition_root_v3_binds_fifo_and_next_fill() {
    let first = limit(1, 1, Side::Ask, 100, 5);
    let second = limit(2, 2, Side::Ask, 100, 5);
    let mut a = OrderBook::new(cfg());
    let mut b = OrderBook::new(cfg());
    a.place(first).unwrap();
    a.place(second).unwrap();
    b.place(second).unwrap();
    b.place(first).unwrap();

    assert_eq!(
        a.state_root(),
        b.state_root(),
        "v2 demonstrates the unordered-multiset defect"
    );
    assert_ne!(a.transition_root_v3(), b.transition_root_v3());

    let taker = limit(3, 3, Side::Bid, 100, 1);
    let a_fill = a.place(taker).unwrap();
    let b_fill = b.place(taker).unwrap();
    assert_eq!(a_fill.fills[0].maker_order, OrderId::new(1));
    assert_eq!(b_fill.fills[0].maker_order, OrderId::new(2));
}

#[test]
#[should_panic(expected = "price-level FIFO backward link mismatch")]
fn transition_root_v3_rejects_corrupt_fifo_backward_link() {
    let mut book = OrderBook::new(cfg());
    book.place(limit(1, 1, Side::Ask, 100, 5)).unwrap();
    book.place(limit(2, 2, Side::Ask, 100, 5)).unwrap();
    let second_slot = book.id_index.get(&OrderId::new(2)).unwrap().slot;
    book.slab.get_mut(second_slot).unwrap().prev = crate::slab::NIL;

    let _ = book.transition_root_v3();
}

#[test]
#[should_panic(expected = "incremental order-leaf XOR must match the canonical live-order scan")]
fn transition_root_v3_rejects_corrupt_incremental_root_cache() {
    let mut book = OrderBook::new(cfg());
    book.place(limit(1, 1, Side::Ask, 100, 5)).unwrap();
    book.order_leaf_xor[0] ^= 1;

    let _ = book.transition_root_v3();
}

#[test]
#[should_panic(expected = "stored side-book role must match its engine field")]
fn transition_root_v3_rejects_corrupt_side_book_role() {
    let mut book = OrderBook::new(cfg());
    book.place(limit(1, 1, Side::Bid, 100, 5)).unwrap();
    book.bids.set_side_for_test(Side::Ask);

    let _ = book.transition_root_v3();
}

#[test]
fn transition_root_v3_binds_logical_config_and_positions() {
    let base = OrderBook::new(cfg());
    let root = base.transition_root_v3();

    for changed in [
        BookConfig {
            capacity: cfg().capacity + 1,
            ..cfg()
        },
        BookConfig {
            stp: StpPolicy::CancelTaker,
            ..cfg()
        },
        BookConfig {
            dedup_capacity: cfg().dedup_capacity + 1,
            ..cfg()
        },
        BookConfig {
            max_basket_legs: cfg().max_basket_legs + 1,
            ..cfg()
        },
    ] {
        assert_ne!(OrderBook::new(changed).transition_root_v3(), root);
    }

    let mut with_position = base.clone();
    with_position.set_position(AccountId::new(7), Quantity::from_raw(-9));
    assert_ne!(with_position.transition_root_v3(), root);
}

#[test]
fn transition_root_v3_is_hashmap_order_independent_but_dedup_fifo_sensitive() {
    let mut positions_ab = OrderBook::new(cfg());
    positions_ab.set_position(AccountId::new(1), Quantity::from_raw(10));
    positions_ab.set_position(AccountId::new(2), Quantity::from_raw(-20));
    let mut positions_ba = OrderBook::new(cfg());
    positions_ba.set_position(AccountId::new(2), Quantity::from_raw(-20));
    positions_ba.set_position(AccountId::new(1), Quantity::from_raw(10));
    assert_eq!(
        positions_ab.transition_root_v3(),
        positions_ba.transition_root_v3()
    );

    let rejected_a = order(
        11,
        1,
        Side::Bid,
        OrderType::Market,
        TimeInForce::Ioc,
        100,
        1,
        101,
    );
    let rejected_b = order(
        12,
        2,
        Side::Bid,
        OrderType::Market,
        TimeInForce::Ioc,
        100,
        1,
        102,
    );
    let mut dedup_ab = OrderBook::new(cfg());
    dedup_ab.submit(rejected_a).unwrap();
    dedup_ab.submit(rejected_b).unwrap();
    let mut dedup_ba = OrderBook::new(cfg());
    dedup_ba.submit(rejected_b).unwrap();
    dedup_ba.submit(rejected_a).unwrap();
    assert_eq!(dedup_ab.state_root(), dedup_ba.state_root());
    assert_ne!(
        dedup_ab.transition_root_v3(),
        dedup_ba.transition_root_v3(),
        "FIFO order controls which idempotency record is evicted next"
    );
}

#[test]
fn transition_root_v3_golden_vector() {
    let mut book = OrderBook::new(cfg());
    book.place(limit(1, 7, Side::Bid, 100, 5)).unwrap();
    book.place(limit(2, 8, Side::Ask, 110, 6)).unwrap();
    book.set_position(AccountId::new(7), Quantity::from_raw(3));
    let encoded = canonical_bytes(&book);
    assert_eq!(encoded.len(), 59 + 2 * 16 + 2 * 37 + 12);
    assert_eq!(
        crypto::hash_domain(crypto::DOMAIN_ORDERBOOK_STATE, &encoded),
        Hash::from_bytes([
            50, 182, 109, 6, 209, 245, 235, 7, 86, 25, 40, 230, 200, 166, 188, 217, 49, 9,
            158, 191, 57, 93, 101, 0, 190, 80, 254, 226, 143, 95, 183, 114,
        ])
    );
    assert_eq!(book.transition_root_v3(), crypto::hash_domain(crypto::DOMAIN_ORDERBOOK_STATE, &encoded));
}

#[test]
fn transition_root_v3_dedup_schema_golden_vector() {
    let mut book = OrderBook::new(cfg());
    book.place(limit(1, 7, Side::Ask, 100, 5)).unwrap();
    book.submit(limit(2, 8, Side::Bid, 100, 5)).unwrap();
    let encoded = canonical_bytes(&book);
    assert_eq!(encoded.len(), 59 + 29 + 41);
    assert_eq!(
        crypto::hash_domain(crypto::DOMAIN_ORDERBOOK_STATE, &encoded),
        Hash::from_bytes([
            185, 17, 219, 185, 165, 201, 13, 159, 104, 195, 106, 36, 58, 56, 128, 194, 227,
            130, 125, 1, 83, 22, 198, 252, 74, 108, 160, 76, 160, 100, 155, 76,
        ])
    );
    assert_eq!(book.transition_root_v3(), crypto::hash_domain(crypto::DOMAIN_ORDERBOOK_STATE, &encoded));
}

#[test]
fn state_v3_codec_round_trips_every_logical_field_and_keeps_backend_external() {
    let original = codec_fixture();
    let bytes = canonical_bytes(&original);
    assert_eq!(
        crypto::hash_domain(crypto::DOMAIN_ORDERBOOK_STATE, &bytes),
        original.transition_root_v3()
    );

    let decoded = OrderBook::decode_state_v3_bounded(
        &bytes,
        &BookStateLimits::default(),
        simd::Backend::Neon,
    )
    .unwrap();
    assert_eq!(decoded.config.matching_backend, simd::Backend::Neon);
    assert_logically_identical(&original, &decoded);

    let too_small = bytes.len() - 1;
    assert_eq!(
        original.encode_state_v3_bounded(too_small),
        Err(BookStateError::EncodedBytesLimit {
            actual: bytes.len(),
            max: too_small,
        })
    );
}

#[test]
fn state_v3_codec_rejects_every_truncation_and_any_suffix() {
    let bytes = canonical_bytes(&codec_fixture());
    for cut in 0..bytes.len() {
        assert!(
            OrderBook::decode_state_v3_bounded(
                &bytes[..cut],
                &BookStateLimits::default(),
                simd::Backend::Scalar,
            )
            .is_err(),
            "truncation at byte {cut} was accepted"
        );
    }

    let mut with_suffix = bytes;
    with_suffix.extend_from_slice(&[0xaa, 0xbb]);
    match OrderBook::decode_state_v3_bounded(
        &with_suffix,
        &BookStateLimits::default(),
        simd::Backend::Scalar,
    ) {
        Err(error) => assert_eq!(error, BookStateError::TrailingBytes { remaining: 2 }),
        Ok(_) => panic!("trailing bytes were accepted"),
    }
}

#[test]
fn state_v3_decoder_never_panics_on_arbitrary_bounded_bytes() {
    let mut random = Lcg(0xC0DE_CAFE_F00D_BAAD);
    let limits = BookStateLimits {
        max_encoded_bytes: 512,
        max_capacity: 64,
        max_dedup_capacity: 32,
        max_basket_legs: 16,
        max_price_levels: 64,
        max_resting_orders: 64,
        max_positions: 64,
        max_dedup_records: 32,
        max_fills_per_result: 32,
        max_total_fills: 64,
    };
    for _ in 0..10_000 {
        let len = usize::try_from(random.below(513)).unwrap();
        let mut bytes = vec![0u8; len];
        for chunk in bytes.chunks_mut(8) {
            let word = random.next_u64().to_le_bytes();
            let chunk_len = chunk.len();
            chunk.copy_from_slice(&word[..chunk_len]);
        }
        let _ = OrderBook::decode_state_v3_bounded(&bytes, &limits, simd::Backend::Scalar);
    }
}

#[test]
fn state_v3_codec_enforces_every_resource_limit_independently() {
    let bytes = canonical_bytes(&codec_fixture());
    let assert_resource = |limits: BookStateLimits, expected: &'static str| {
        assert!(matches!(
            OrderBook::decode_state_v3_bounded(&bytes, &limits, simd::Backend::Scalar),
            Err(BookStateError::ResourceLimit { resource, .. }) if resource == expected
        ));
    };

    let limits = BookStateLimits {
        max_encoded_bytes: bytes.len() - 1,
        ..BookStateLimits::default()
    };
    match OrderBook::decode_state_v3_bounded(&bytes, &limits, simd::Backend::Scalar) {
        Err(error) => assert_eq!(
            error,
            BookStateError::EncodedBytesLimit {
                actual: bytes.len(),
                max: bytes.len() - 1,
            }
        ),
        Ok(_) => panic!("oversized state was accepted"),
    }

    assert_resource(
        BookStateLimits {
            max_capacity: 11,
            ..BookStateLimits::default()
        },
        "capacity",
    );
    assert_resource(
        BookStateLimits {
            max_dedup_capacity: 7,
            ..BookStateLimits::default()
        },
        "dedup capacity",
    );
    assert_resource(
        BookStateLimits {
            max_basket_legs: 3,
            ..BookStateLimits::default()
        },
        "basket legs",
    );
    assert_resource(
        BookStateLimits {
            max_price_levels: 1,
            ..BookStateLimits::default()
        },
        "price levels",
    );
    assert_resource(
        BookStateLimits {
            max_resting_orders: 1,
            ..BookStateLimits::default()
        },
        "resting orders",
    );
    assert_resource(
        BookStateLimits {
            max_positions: 1,
            ..BookStateLimits::default()
        },
        "positions",
    );
    assert_resource(
        BookStateLimits {
            max_dedup_records: 2,
            ..BookStateLimits::default()
        },
        "dedup records",
    );
    assert_resource(
        BookStateLimits {
            max_fills_per_result: 1,
            ..BookStateLimits::default()
        },
        "fills per dedup result",
    );
    assert_resource(
        BookStateLimits {
            max_total_fills: 1,
            ..BookStateLimits::default()
        },
        "total cached fills",
    );
}

#[test]
fn state_v3_codec_rejects_hostile_declared_bounds_before_payload_allocation() {
    let empty = OrderBook::new(codec_cfg());
    let mut huge_capacity = canonical_bytes(&empty);
    overwrite_u64(&mut huge_capacity, 2, u64::MAX);
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &huge_capacity,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::ResourceLimit {
            resource: "capacity",
            actual: u64::MAX,
            ..
        })
    ));

    let mut huge_levels = canonical_bytes(&empty);
    overwrite_u64(&mut huge_levels, 27, u64::MAX);
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &huge_levels,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::ResourceLimit {
            resource: "price levels",
            actual: u64::MAX,
            ..
        })
    ));

    // One declared bid level with an independently hostile order count. The
    // record payload is intentionally absent: the count limit must win over
    // truncation without attempting a resting-order allocation.
    let mut huge_orders = canonical_bytes(&empty);
    overwrite_u64(&mut huge_orders, 27, 1);
    let mut level = Vec::new();
    level.extend_from_slice(&100i64.to_le_bytes());
    level.extend_from_slice(&u64::MAX.to_le_bytes());
    huge_orders.splice(35..35, level);
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &huge_orders,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::ResourceLimit {
            resource: "resting orders",
            actual: u64::MAX,
            ..
        })
    ));

    let permissive = BookStateLimits {
        max_capacity: usize::MAX,
        ..BookStateLimits::default()
    };
    overwrite_u64(&mut huge_capacity, 2, u64::from(u32::MAX) + 1);
    match OrderBook::decode_state_v3_bounded(
        &huge_capacity,
        &permissive,
        simd::Backend::Scalar,
    ) {
        Err(error) => assert_eq!(
            error,
            BookStateError::NativeWidth {
                field: "slab capacity",
                value: u64::from(u32::MAX) + 1,
            }
        ),
        Ok(_) => panic!("unrepresentable slab capacity was accepted"),
    }

    #[cfg(target_pointer_width = "64")]
    {
        let mut unencodable = OrderBook::new(codec_cfg());
        unencodable.config.capacity = usize::try_from(u64::from(u32::MAX) + 1).unwrap();
        assert_eq!(
            unencodable.encode_state_v3_bounded(usize::MAX),
            Err(BookStateError::NativeWidth {
                field: "slab capacity",
                value: u64::from(u32::MAX) + 1,
            })
        );
    }
}

#[test]
fn state_v3_codec_rejects_noncanonical_or_corrupt_resting_state() {
    let mut book = OrderBook::new(codec_cfg());
    book.place(limit(1, 1, Side::Bid, 99, 2)).unwrap();
    book.place(limit(2, 2, Side::Bid, 100, 3)).unwrap();
    book.place(limit(3, 3, Side::Ask, 110, 4)).unwrap();
    let bytes = canonical_bytes(&book);

    // Header is 27 bytes. Bid count is 8 bytes. The first level is
    // 16 + 37 bytes, so the second level price begins at byte 88.
    let mut noncanonical_levels = bytes.clone();
    overwrite_i64(&mut noncanonical_levels, 88, 99);
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &noncanonical_levels,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::NonCanonical { .. })
    ));

    let mut wrong_side = bytes.clone();
    wrong_side[63] = 1;
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &wrong_side,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::InvalidValue { .. })
    ));

    let mut wrong_price = bytes.clone();
    overwrite_i64(&mut wrong_price, 64, 98);
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &wrong_price,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::InvalidValue { .. })
    ));

    let mut zero_quantity = bytes.clone();
    overwrite_i64(&mut zero_quantity, 72, 0);
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &zero_quantity,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::InvalidValue { .. })
    ));

    // The second bid's node starts at byte 104; duplicate the first order id.
    let mut duplicate_order = bytes.clone();
    overwrite_u64(&mut duplicate_order, 104, 1);
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &duplicate_order,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::NonCanonical { .. })
    ));

    // Ask count begins after both bid levels at byte 141; ask price/node price
    // begin at 149/178. Lock the ask to the best bid.
    let mut locked_book = bytes;
    overwrite_i64(&mut locked_book, 149, 100);
    overwrite_i64(&mut locked_book, 178, 100);
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &locked_book,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::InvalidValue { .. })
    ));
}

#[test]
fn state_v3_codec_rejects_unknown_header_tags() {
    let bytes = canonical_bytes(&OrderBook::new(codec_cfg()));
    let mut version = bytes.clone();
    version[0..2].copy_from_slice(&4u16.to_le_bytes());
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &version,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::UnsupportedVersion {
            found: 4,
            expected: BOOK_TRANSITION_ROOT_SCHEMA_VERSION,
        })
    ));

    let mut stp = bytes;
    stp[10] = 3;
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &stp,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::InvalidTag {
            field: "self-trade prevention policy",
            value: 3,
        })
    ));
}

#[test]
fn state_v3_codec_rejects_noncanonical_positions_and_malformed_cached_results() {
    let mut positioned = OrderBook::new(codec_cfg());
    positioned.set_position(AccountId::new(1), Quantity::from_raw(2));
    positioned.set_position(AccountId::new(2), Quantity::from_raw(3));
    let mut positions = canonical_bytes(&positioned);
    positions[63..67].copy_from_slice(&1u32.to_le_bytes());
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &positions,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::NonCanonical { .. })
    ));

    let mut rejected_book = OrderBook::new(codec_cfg());
    rejected_book
        .submit(order(
            1,
            1,
            Side::Bid,
            OrderType::Market,
            TimeInForce::Ioc,
            100,
            1,
            10,
        ))
        .unwrap();
    let rejected = canonical_bytes(&rejected_book);
    // Empty state prefixes total 59 bytes, then account/client/fill-count. The
    // outcome tag and quantity are bytes 79 and 80..88.
    let mut unknown_outcome = rejected.clone();
    unknown_outcome[79] = 9;
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &unknown_outcome,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::InvalidTag {
            field: "order outcome",
            value: 9,
        })
    ));
    let mut impossible_outcome = rejected.clone();
    impossible_outcome[79] = 1;
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &impossible_outcome,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::InvalidValue { .. })
    ));
    let mut nonzero_rejection = rejected;
    overwrite_i64(&mut nonzero_rejection, 80, 1);
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &nonzero_rejection,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::InvalidValue { .. })
    ));

    let mut filled_book = OrderBook::new(codec_cfg());
    filled_book.place(limit(20, 2, Side::Ask, 100, 2)).unwrap();
    filled_book.submit(limit(21, 3, Side::Bid, 100, 2)).unwrap();
    let filled = canonical_bytes(&filled_book);
    // One fill starts at byte 79. Maker/taker accounts are at 95/99, price at
    // 103, quantity at 111, side at 119, outcome at 120.
    let mut self_trade = filled.clone();
    self_trade[95..99].copy_from_slice(&3u32.to_le_bytes());
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &self_trade,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::InvalidValue { .. })
    ));
    let mut zero_fill = filled.clone();
    overwrite_i64(&mut zero_fill, 111, 0);
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &zero_fill,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::InvalidValue { .. })
    ));
    let mut overflowing_partial = filled.clone();
    overflowing_partial[120] = 2;
    overwrite_i64(&mut overflowing_partial, 121, i64::MAX);
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &overflowing_partial,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::ArithmeticOverflow {
            field: "cached original quantity",
        })
    ));
    let mut wrong_dedup_owner = filled.clone();
    wrong_dedup_owner[99..103].copy_from_slice(&4u32.to_le_bytes());
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &wrong_dedup_owner,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::InvalidValue { .. })
    ));
    let mut unknown_side = filled;
    unknown_side[119] = 7;
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &unknown_side,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::InvalidTag {
            field: "side",
            value: 7,
        })
    ));

    let mut duplicate_keys_book = OrderBook::new(codec_cfg());
    for (id, account, client) in [(30, 5, 50), (31, 6, 51)] {
        duplicate_keys_book
            .submit(order(
                id,
                account,
                Side::Bid,
                OrderType::Market,
                TimeInForce::Ioc,
                100,
                1,
                client,
            ))
            .unwrap();
    }
    let mut duplicate_keys = canonical_bytes(&duplicate_keys_book);
    // Two no-fill records are 29 bytes each and begin at 59 and 88.
    duplicate_keys[88..92].copy_from_slice(&5u32.to_le_bytes());
    overwrite_u64(&mut duplicate_keys, 92, 50);
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &duplicate_keys,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::NonCanonical { .. })
    ));

    let mut two_fill_book = OrderBook::new(codec_cfg());
    two_fill_book.place(limit(40, 7, Side::Ask, 100, 1)).unwrap();
    two_fill_book.place(limit(41, 8, Side::Ask, 101, 1)).unwrap();
    two_fill_book.submit(limit(42, 9, Side::Bid, 101, 2)).unwrap();
    let mut duplicate_maker = canonical_bytes(&two_fill_book);
    // The sole record starts at 59. Its two 41-byte fills start at 79 and 120.
    let first_maker = duplicate_maker[79..87].to_vec();
    duplicate_maker[120..128].copy_from_slice(&first_maker);
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &duplicate_maker,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::InvalidValue { .. })
    ));
}

#[test]
fn state_v3_codec_round_trips_partial_outcomes_and_rejects_unreachable_boundaries() {
    let mut partial_resting = OrderBook::new(codec_cfg());
    partial_resting
        .place(limit(50, 1, Side::Ask, 100, 1))
        .unwrap();
    let resting_result = partial_resting
        .submit(limit(51, 2, Side::Bid, 100, 2))
        .unwrap();
    assert!(matches!(
        resting_result.outcome,
        OrderOutcome::PartiallyFilledResting { remaining }
            if remaining == Quantity::from_raw(1)
    ));
    let resting_bytes = canonical_bytes(&partial_resting);
    let restored = OrderBook::decode_state_v3_bounded(
        &resting_bytes,
        &BookStateLimits::default(),
        simd::Backend::Scalar,
    )
    .unwrap();
    assert_logically_identical(&partial_resting, &restored);

    let mut partial_cancelled = OrderBook::new(codec_cfg());
    partial_cancelled
        .place(limit(60, 3, Side::Ask, 100, 1))
        .unwrap();
    let cancelled_result = partial_cancelled
        .submit(order(
            61,
            4,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Ioc,
            100,
            2,
            61,
        ))
        .unwrap();
    assert!(matches!(
        cancelled_result.outcome,
        OrderOutcome::PartiallyFilledCancelled { filled }
            if filled == Quantity::from_raw(1)
    ));
    let cancelled_bytes = canonical_bytes(&partial_cancelled);
    assert_eq!(cancelled_bytes.len(), 59 + 29 + 41);
    assert_eq!(cancelled_bytes[120], 3);
    let restored = OrderBook::decode_state_v3_bounded(
        &cancelled_bytes,
        &BookStateLimits::default(),
        simd::Backend::Scalar,
    )
    .unwrap();
    assert_logically_identical(&partial_cancelled, &restored);

    let mut impossible_cancelled = cancelled_bytes;
    overwrite_i64(&mut impossible_cancelled, 111, i64::MAX);
    overwrite_i64(&mut impossible_cancelled, 121, i64::MAX);
    assert!(matches!(
        OrderBook::decode_state_v3_bounded(
            &impossible_cancelled,
            &BookStateLimits::default(),
            simd::Backend::Scalar,
        ),
        Err(BookStateError::InvalidValue { .. })
    ));
}

#[test]
fn state_v3_dense_restore_matches_fragmented_slab_through_long_continuation() {
    let config = BookConfig {
        capacity: 12,
        stp: StpPolicy::CancelMaker,
        dedup_capacity: 16,
        max_basket_legs: 4,
        matching_backend: simd::Backend::Scalar,
    };
    let mut fragmented = OrderBook::new(config);
    for resting in [
        limit(10, 1, Side::Bid, 100, 8),
        limit(11, 2, Side::Bid, 100, 7),
        limit(14, 9, Side::Bid, 100, 6),
        limit(12, 3, Side::Bid, 99, 6),
        limit(20, 4, Side::Ask, 110, 5),
        limit(21, 5, Side::Ask, 110, 9),
        limit(22, 6, Side::Ask, 111, 4),
    ] {
        fragmented.submit(resting).unwrap();
    }
    fragmented.cancel(OrderId::new(12)).unwrap();
    fragmented.cancel(OrderId::new(20)).unwrap();
    fragmented.submit(limit(23, 7, Side::Ask, 112, 3)).unwrap();
    fragmented.cancel(OrderId::new(10)).unwrap();
    fragmented.submit(limit(13, 8, Side::Bid, 98, 2)).unwrap();
    fragmented.cancel(OrderId::new(21)).unwrap();

    let fragmented_layout = fragmented.slab.representation_for_test();
    let bytes = canonical_bytes(&fragmented);
    let mut dense = OrderBook::decode_state_v3_bounded(
        &bytes,
        &BookStateLimits::default(),
        simd::Backend::Scalar,
    )
    .unwrap();
    assert_ne!(fragmented_layout, dense.slab.representation_for_test());
    assert_ne!(
        fragmented.id_index[&OrderId::new(22)].slot,
        dense.id_index[&OrderId::new(22)].slot
    );
    assert_logically_identical(&fragmented, &dense);

    // A canceled order's retained cache entry must replay without resurrecting
    // it or depending on its former slab slot.
    let replay = limit(12, 3, Side::Bid, 99, 6);
    assert_eq!(fragmented.submit(replay), dense.submit(replay));
    assert!(!fragmented.contains(OrderId::new(12)));
    assert!(!dense.contains(OrderId::new(12)));
    assert_logically_identical(&fragmented, &dense);

    // Fill id 11 completely, then partially reduce id 14 in-place.
    let taker = limit(100, 50, Side::Ask, 100, 10);
    assert_eq!(fragmented.plan_match(&taker), dense.plan_match(&taker));
    assert_eq!(
        fragmented.plan_match_summary_with_backend(&taker, simd::Backend::Scalar),
        dense.plan_match_summary_with_backend(&taker, simd::Backend::Scalar)
    );
    assert_eq!(
        fragmented.plan_match_summary_with_backend(&taker, simd::Backend::Avx2),
        dense.plan_match_summary_with_backend(&taker, simd::Backend::Avx2)
    );
    assert_eq!(fragmented.place(taker), dense.place(taker));
    assert_eq!(
        fragmented.level_quantity(Side::Bid, Price::from_raw(100)),
        Quantity::from_raw(3)
    );
    assert_logically_identical(&fragmented, &dense);

    // Replace removes the partially-filled node, consumes both asks, and rests
    // an identical residual even though each allocator chooses another slot.
    assert_eq!(
        fragmented.replace(OrderId::new(14), Price::from_raw(112), Quantity::from_raw(8)),
        dense.replace(OrderId::new(14), Price::from_raw(112), Quantity::from_raw(8))
    );
    assert_logically_identical(&fragmented, &dense);
    assert_eq!(
        fragmented.cancel(OrderId::new(13)),
        dense.cancel(OrderId::new(13))
    );
    assert_logically_identical(&fragmented, &dense);

    fragmented.set_position(AccountId::new(60), Quantity::from_raw(5));
    dense.set_position(AccountId::new(60), Quantity::from_raw(5));
    let reduce_only = NewOrder {
        reduce_only: true,
        ..limit(200, 60, Side::Ask, 120, 8)
    };
    assert_eq!(fragmented.place(reduce_only), dense.place(reduce_only));
    assert_logically_identical(&fragmented, &dense);

    for resting in [
        limit(201, 61, Side::Ask, 130, 1),
        limit(202, 61, Side::Ask, 130, 1),
    ] {
        assert_eq!(fragmented.place(resting), dense.place(resting));
    }
    assert_eq!(fragmented.cancel_all(AccountId::new(61)), 2);
    assert_eq!(dense.cancel_all(AccountId::new(61)), 2);
    assert_logically_identical(&fragmented, &dense);

    let dedup_order = order(
        210,
        70,
        Side::Bid,
        OrderType::Limit,
        TimeInForce::Gtc,
        80,
        1,
        777,
    );
    assert_eq!(fragmented.submit(dedup_order), dense.submit(dedup_order));
    let before_replay = canonical_bytes(&fragmented);
    assert_eq!(fragmented.submit(dedup_order), dense.submit(dedup_order));
    assert_eq!(canonical_bytes(&fragmented), before_replay);
    assert_logically_identical(&fragmented, &dense);

    // The other-account bid fills first; CancelMaker then removes the taker's
    // own bid before the residual ask rests.
    let stp = limit(211, 70, Side::Ask, 80, 2);
    assert_eq!(fragmented.place(stp), dense.place(stp));
    assert_logically_identical(&fragmented, &dense);

    for index in 0..9u64 {
        let resting = limit(
            300 + index,
            80 + u32::try_from(index).unwrap(),
            Side::Ask,
            140 + i64::try_from(index).unwrap(),
            1,
        );
        assert_eq!(fragmented.place(resting), dense.place(resting));
        assert_logically_identical(&fragmented, &dense);
    }
    assert_eq!(fragmented.resting_len(), 11);

    let basket = [
        limit(400, 100, Side::Ask, 160, 1),
        limit(401, 101, Side::Ask, 161, 1),
    ];
    let before_basket = canonical_bytes(&fragmented);
    assert_eq!(
        fragmented.submit_basket(&basket),
        Err(OrderError::CapacityExhausted)
    );
    assert_eq!(
        dense.submit_basket(&basket),
        Err(OrderError::CapacityExhausted)
    );
    assert_eq!(canonical_bytes(&fragmented), before_basket);
    assert_logically_identical(&fragmented, &dense);

    let final_slot = limit(402, 102, Side::Ask, 162, 1);
    assert_eq!(fragmented.place(final_slot), dense.place(final_slot));
    let overflow = limit(403, 103, Side::Ask, 163, 1);
    assert_eq!(
        fragmented.place(overflow),
        Err(OrderError::CapacityExhausted)
    );
    assert_eq!(dense.place(overflow), Err(OrderError::CapacityExhausted));
    assert_logically_identical(&fragmented, &dense);
    assert_eq!(
        fragmented.cancel(OrderId::new(402)),
        dense.cancel(OrderId::new(402))
    );

    assert_eq!(
        fragmented.cancel(OrderId::new(9999)),
        dense.cancel(OrderId::new(9999))
    );
    assert_eq!(
        fragmented.replace(OrderId::new(9999), Price::from_raw(1), Quantity::from_raw(1)),
        dense.replace(OrderId::new(9999), Price::from_raw(1), Quantity::from_raw(1))
    );
    let invalid_quantity = limit(500, 110, Side::Ask, 170, 0);
    assert_eq!(
        fragmented.place(invalid_quantity),
        dense.place(invalid_quantity)
    );
    let invalid_price = limit(501, 110, Side::Ask, 0, 1);
    assert_eq!(fragmented.place(invalid_price), dense.place(invalid_price));
    assert_logically_identical(&fragmented, &dense);

    let original_fragmented = canonical_bytes(&fragmented);
    let original_dense = canonical_bytes(&dense);
    let mut fragmented_clone = fragmented.clone();
    let mut dense_clone = dense.clone();
    assert_eq!(
        fragmented_clone.cancel(OrderId::new(300)),
        dense_clone.cancel(OrderId::new(300))
    );
    assert_eq!(
        fragmented_clone.place(limit(600, 120, Side::Bid, 70, 1)),
        dense_clone.place(limit(600, 120, Side::Bid, 70, 1))
    );
    assert_logically_identical(&fragmented_clone, &dense_clone);
    assert_eq!(canonical_bytes(&fragmented), original_fragmented);
    assert_eq!(canonical_bytes(&dense), original_dense);
}

#[test]
fn plan_match_follows_executable_depth_not_placeholder() {
    let mut b = OrderBook::new(cfg());
    // Deep ask book: 10 @ 100, 10 @ 110, 10 @ 120.
    b.submit(limit(1, 1, Side::Ask, 100, 10)).unwrap();
    b.submit(limit(2, 2, Side::Ask, 110, 10)).unwrap();
    b.submit(limit(3, 3, Side::Ask, 120, 10)).unwrap();
    // Market bid for 25 with collar 120: sweeps 10+10+5.
    let plan = b
        .plan_match(&order(
            9,
            9,
            Side::Bid,
            OrderType::Market,
            TimeInForce::Ioc,
            120,
            25,
            9,
        ))
        .unwrap();
    assert_eq!(plan.fills.len(), 3);
    assert_eq!(plan.filled_quantity, Quantity::from_raw(25));
    assert_eq!(plan.worst_price, Some(Price::from_raw(120)));
    // Notional = 10*100 + 10*110 + 5*120 = 1000+1100+600 = 2700 (raw scaled).
    let expected = Price::from_raw(100)
        .notional(Quantity::from_raw(10))
        .unwrap()
        .checked_add(Price::from_raw(110).notional(Quantity::from_raw(10)).unwrap())
        .unwrap()
        .checked_add(Price::from_raw(120).notional(Quantity::from_raw(5)).unwrap())
        .unwrap();
    assert_eq!(plan.notional, expected);
    // A 1-micro "placeholder" collar that still reports as Market must not
    // invent cheap depth: with collar 1 nothing crosses.
    let cheap = b
        .plan_match(&order(
            10,
            9,
            Side::Bid,
            OrderType::Market,
            TimeInForce::Ioc,
            1,
            25,
            10,
        ))
        .unwrap();
    assert!(cheap.fills.is_empty());
    assert_eq!(cheap.notional.raw(), 0);
    // Book untouched by planning.
    assert_eq!(b.resting_len(), 3);
}

#[test]
fn match_summary_is_exactly_equivalent_to_materialized_plan() {
    for taker_side in [Side::Bid, Side::Ask] {
        let maker_side = taker_side.opposite();
        let mut b = OrderBook::new(cfg());
        for (offset, (price, quantity)) in [(100, 7), (105, 11), (110, 13)].into_iter().enumerate()
        {
            b.submit(limit(
                u64::try_from(offset + 1).unwrap(),
                u32::try_from(offset + 1).unwrap(),
                maker_side,
                price,
                quantity,
            ))
            .unwrap();
        }
        let collar = match taker_side {
            Side::Bid => 110,
            Side::Ask => 100,
        };
        let taker = order(
            99,
            99,
            taker_side,
            OrderType::Market,
            TimeInForce::Ioc,
            collar,
            25,
            99,
        );
        let plan = b.plan_match(&taker).unwrap();
        let summary = b.plan_match_summary(&taker).unwrap();
        assert_eq!(summary.filled_quantity, plan.filled_quantity);
        assert_eq!(summary.worst_price, plan.worst_price);
        assert_eq!(summary.notional, plan.notional);
        assert_eq!(summary.notional_ceil, plan.notional_ceil);
        assert_eq!(b.resting_len(), 3);
    }
}

#[test]
fn scalar_and_simd_match_summaries_cover_stp_rounding_and_tail_lanes() {
    let backends = [
        simd::Backend::Scalar,
        simd::Backend::Avx2,
        simd::Backend::Avx512,
        simd::Backend::Neon,
    ];
    for policy in [
        StpPolicy::CancelMaker,
        StpPolicy::CancelTaker,
        StpPolicy::CancelBoth,
    ] {
        for taker_side in [Side::Bid, Side::Ask] {
            for maker_count in [0usize, 1, 3, 4, 7, 8, 9, 15, 16, 17] {
                let mut config = cfg();
                config.stp = policy;
                let mut book = OrderBook::new(config);
                for lane in 0..maker_count {
                    let lane_i64 = i64::try_from(lane).unwrap();
                    // Self-owned makers straddle vector blocks and exercise all
                    // three STP stop/skip behaviors without changing traversal.
                    let account = if lane == 2 || lane == 10 {
                        99
                    } else {
                        u32::try_from(lane + 1).unwrap()
                    };
                    book.submit(limit(
                        u64::try_from(lane + 1).unwrap(),
                        account,
                        taker_side.opposite(),
                        1_000_001 + lane_i64,
                        500_001 + lane_i64,
                    ))
                    .unwrap();
                }
                let collar = match taker_side {
                    Side::Bid => 1_000_001 + i64::try_from(maker_count).unwrap(),
                    Side::Ask => 1_000_001,
                };
                let taker = order(
                    50_000,
                    99,
                    taker_side,
                    OrderType::Market,
                    TimeInForce::Ioc,
                    collar,
                    i64::try_from(maker_count).unwrap() * 600_000 + 1,
                    50_000,
                );
                let scalar = book
                    .plan_match_summary_with_backend(&taker, simd::Backend::Scalar)
                    .unwrap();
                let plan = book.plan_match(&taker).unwrap();
                assert_eq!(scalar.filled_quantity, plan.filled_quantity);
                assert_eq!(scalar.worst_price, plan.worst_price);
                assert_eq!(scalar.notional, plan.notional);
                assert_eq!(scalar.notional_ceil, plan.notional_ceil);
                for backend in backends {
                    assert_eq!(
                        book.plan_match_summary_with_backend(&taker, backend),
                        Ok(scalar),
                        "policy={policy:?} side={taker_side:?} makers={maker_count} backend={backend:?}",
                    );
                }
                assert_eq!(book.resting_len(), maker_count);
            }
        }
    }
}

#[test]
fn scalar_and_simd_match_summaries_are_identical_over_randomized_books() {
    let mut random = Lcg(0x5725_7257_2572_5725);
    for case in 0..512u64 {
        let policy = match case % 3 {
            0 => StpPolicy::CancelMaker,
            1 => StpPolicy::CancelTaker,
            _ => StpPolicy::CancelBoth,
        };
        let taker_side = if case.is_multiple_of(2) {
            Side::Bid
        } else {
            Side::Ask
        };
        let mut config = cfg();
        config.stp = policy;
        let mut book = OrderBook::new(config);
        let maker_count = usize::try_from(random.below(33)).unwrap();
        for lane in 0..maker_count {
            let account = if random.below(7) == 0 {
                77
            } else {
                u32::try_from(lane + 1).unwrap()
            };
            let price = 900_000 + i64::try_from(random.below(200_001)).unwrap();
            let quantity = 1 + i64::try_from(random.below(4_000_000_000)).unwrap();
            book.submit(limit(
                case * 100 + u64::try_from(lane).unwrap() + 1,
                account,
                taker_side.opposite(),
                price,
                quantity,
            ))
            .unwrap();
        }
        let taker = order(
            9_000_000 + case,
            77,
            taker_side,
            OrderType::Market,
            TimeInForce::Ioc,
            match taker_side {
                Side::Bid => 1_100_000,
                Side::Ask => 900_000,
            },
            1 + i64::try_from(random.below(8_000_000_000)).unwrap(),
            9_000_000 + case,
        );
        let scalar = book.plan_match_summary_with_backend(&taker, simd::Backend::Scalar);
        for backend in [
            simd::Backend::Avx2,
            simd::Backend::Avx512,
            simd::Backend::Neon,
        ] {
            assert_eq!(
                book.plan_match_summary_with_backend(&taker, backend),
                scalar,
                "case={case} backend={backend:?}",
            );
        }
    }
}

#[test]
fn scalar_and_simd_planning_preserve_fills_outcomes_errors_and_roots() {
    let run = |backend: simd::Backend, policy: StpPolicy, taker_side: Side| {
        let mut config = cfg();
        config.stp = policy;
        config.matching_backend = backend;
        let mut book = OrderBook::new(config);
        for lane in 0..17u64 {
            book.submit(limit(
                lane + 1,
                if lane == 5 { 99 } else { u32::try_from(lane + 1).unwrap() },
                taker_side.opposite(),
                1_000_001 + i64::try_from(lane).unwrap(),
                500_001 + i64::try_from(lane).unwrap(),
            ))
            .unwrap();
        }
        let taker = order(
            90_000,
            99,
            taker_side,
            OrderType::Market,
            TimeInForce::Ioc,
            match taker_side {
                Side::Bid => 1_000_017,
                Side::Ask => 1_000_001,
            },
            7_000_007,
            90_000,
        );
        let summary = book.plan_match_summary(&taker);
        let result = book.submit(taker);
        let invalid = book.plan_match_summary(&order(
            90_001,
            100,
            taker_side,
            OrderType::Limit,
            TimeInForce::Gtc,
            0,
            1,
            90_001,
        ));
        (
            summary,
            result,
            invalid,
            book.state_root(),
            book.transition_root_v3(),
        )
    };

    for policy in [
        StpPolicy::CancelMaker,
        StpPolicy::CancelTaker,
        StpPolicy::CancelBoth,
    ] {
        for side in [Side::Bid, Side::Ask] {
            let scalar = run(simd::Backend::Scalar, policy, side);
            for backend in [
                simd::Backend::Avx2,
                simd::Backend::Avx512,
                simd::Backend::Neon,
            ] {
                assert_eq!(
                    run(backend, policy, side),
                    scalar,
                    "policy={policy:?} side={side:?} backend={backend:?}",
                );
            }
        }
    }
}

#[test]
fn cancel_maker_report_preserves_encounter_order_and_current_remaining() {
    let mut book = OrderBook::new(cfg());
    book.place(limit(1, 7, Side::Ask, 100, 5)).unwrap();
    // Leave the first self maker partially filled before the reported match.
    book.place(limit(2, 8, Side::Bid, 100, 2)).unwrap();
    book.place(limit(3, 9, Side::Ask, 100, 4)).unwrap();
    book.place(limit(4, 7, Side::Ask, 100, 6)).unwrap();

    let report = book
        .place_with_report(limit(5, 7, Side::Bid, 100, 5))
        .unwrap();

    assert_eq!(report.result.fills.len(), 1);
    assert_eq!(report.result.fills[0].maker_order, OrderId::new(3));
    assert_eq!(report.result.fills[0].quantity, Quantity::from_raw(4));
    assert_eq!(
        report
            .stp_cancelled
            .iter()
            .map(|cancel| (cancel.order_id.get(), cancel.remaining.raw()))
            .collect::<Vec<_>>(),
        vec![(1, 3), (4, 6)],
    );
    assert!(report.stp_cancelled.iter().all(|cancel| {
        cancel.account == AccountId::new(7)
            && cancel.side == Side::Ask
            && cancel.price == Price::from_raw(100)
    }));
}

#[test]
fn cancel_both_reports_maker_then_stops_taker() {
    let mut config = cfg();
    config.stp = StpPolicy::CancelBoth;
    let mut book = OrderBook::new(config);
    book.place(limit(1, 7, Side::Ask, 100, 3)).unwrap();

    let report = book
        .place_with_report(limit(2, 7, Side::Bid, 100, 2))
        .unwrap();

    assert!(report.result.fills.is_empty());
    assert!(matches!(report.result.outcome, OrderOutcome::Rejected));
    assert_eq!(report.stp_cancelled.len(), 1);
    assert_eq!(report.stp_cancelled[0].order_id, OrderId::new(1));
    assert_eq!(report.stp_cancelled[0].remaining, Quantity::from_raw(3));
    assert!(!book.contains(OrderId::new(1)));
    assert!(!book.contains(OrderId::new(2)));
}

#[test]
fn cancel_taker_emits_no_maker_cancellation() {
    let mut config = cfg();
    config.stp = StpPolicy::CancelTaker;
    let mut book = OrderBook::new(config);
    book.place(limit(1, 7, Side::Ask, 100, 3)).unwrap();

    let report = book
        .place_with_report(limit(2, 7, Side::Bid, 100, 2))
        .unwrap();

    assert!(report.result.fills.is_empty());
    assert!(report.stp_cancelled.is_empty());
    assert!(book.contains(OrderId::new(1)));
}

#[test]
fn replace_report_includes_self_maker_crossed_by_replacement() {
    let mut book = OrderBook::new(cfg());
    book.place(limit(1, 7, Side::Ask, 100, 3)).unwrap();
    book.place(limit(2, 7, Side::Bid, 90, 2)).unwrap();

    let report = book
        .replace_with_report(OrderId::new(2), Price::from_raw(100), Quantity::from_raw(2))
        .unwrap();

    assert_eq!(report.stp_cancelled.len(), 1);
    assert_eq!(report.stp_cancelled[0].order_id, OrderId::new(1));
    assert!(matches!(
        report.result.outcome,
        OrderOutcome::Resting { remaining } if remaining == Quantity::from_raw(2)
    ));
    assert!(book.contains(OrderId::new(2)));
}

#[test]
fn report_variants_preserve_legacy_results_v3_bytes_and_roots() {
    let mut legacy = OrderBook::new(cfg());
    legacy.place(limit(1, 7, Side::Ask, 100, 3)).unwrap();
    legacy.place(limit(2, 8, Side::Ask, 100, 2)).unwrap();
    let mut reported = legacy.clone();

    let incoming = limit(3, 7, Side::Bid, 100, 4);
    let legacy_result = legacy.place(incoming).unwrap();
    let report = reported.place_with_report(incoming).unwrap();
    assert_eq!(report.result, legacy_result);
    assert!(!report.stp_cancelled.is_empty());
    assert_eq!(canonical_bytes(&reported), canonical_bytes(&legacy));
    assert_eq!(reported.transition_root_v3(), legacy.transition_root_v3());

    legacy.place(limit(4, 7, Side::Ask, 110, 2)).unwrap();
    legacy.place(limit(5, 7, Side::Bid, 90, 2)).unwrap();
    reported.place(limit(4, 7, Side::Ask, 110, 2)).unwrap();
    reported.place(limit(5, 7, Side::Bid, 90, 2)).unwrap();
    let legacy_result = legacy
        .replace(OrderId::new(5), Price::from_raw(110), Quantity::from_raw(2))
        .unwrap();
    let report = reported
        .replace_with_report(OrderId::new(5), Price::from_raw(110), Quantity::from_raw(2))
        .unwrap();
    assert_eq!(report.result, legacy_result);
    assert!(!report.stp_cancelled.is_empty());
    assert_eq!(canonical_bytes(&reported), canonical_bytes(&legacy));
    assert_eq!(reported.transition_root_v3(), legacy.transition_root_v3());
}

#[test]
fn failed_residual_rest_still_reports_applied_stp_cancellation() {
    let mut book = OrderBook::new(cfg());
    let self_ask = limit(1, 7, Side::Ask, 100, 1);
    let full_bid = limit(2, 8, Side::Bid, 100, i64::MAX);
    // Build the narrow internal edge directly: a crossed self maker plus a
    // same-price bid level whose aggregate cannot accept another unit. Public
    // matching never creates a crossed book, but execute_with_report must still
    // preserve any cancellation it applies before a fallible residual rest.
    book.rest_order(&self_ask, self_ask.quantity).unwrap();
    book.rest_order(&full_bid, full_bid.quantity).unwrap();

    let report = book
        .place_with_report(limit(3, 7, Side::Bid, 100, 1))
        .unwrap();

    assert!(report.result.fills.is_empty());
    assert!(matches!(report.result.outcome, OrderOutcome::Rejected));
    assert_eq!(report.stp_cancelled.len(), 1);
    assert_eq!(report.stp_cancelled[0].order_id, OrderId::new(1));
    assert!(!book.contains(OrderId::new(1)));
    assert!(!book.contains(OrderId::new(3)));
    assert!(book.contains(OrderId::new(2)));
    assert_eq!(book.total_resting_quantity(), Quantity::from_raw(i64::MAX));
}

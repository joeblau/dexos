#![no_main]

use codec::{PackedOrder, PACKED_SUBMIT_LEN};
use libfuzzer_sys::fuzz_target;
use types::{AccountId, MarketId, OrderId, OrderType, Price, Quantity, Ratio, Side, TimeInForce};

fuzz_target!(|input: &[u8]| {
    // Arbitrary bytes must never panic. Any accepted prefix must also be
    // canonical when encoded again.
    if let Ok((view, consumed)) = PackedOrder::decode_ref(input) {
        assert_canonical(view.record(), &input[..consumed]);
    }

    // Always exercise the successful path as well. Derive all record kinds and
    // their boundary-shaped integer fields from the fuzzer input, encode into
    // caller-owned memory, then require a byte-identical borrowed round trip.
    let record = generated_record(input);
    let mut encoded = [0_u8; PACKED_SUBMIT_LEN];
    let written = record
        .encode_into(&mut encoded)
        .expect("generated packed order must encode");
    let (decoded, consumed) =
        PackedOrder::decode_ref(&encoded[..written]).expect("encoded packed order must decode");
    assert_eq!(consumed, written);
    assert_eq!(decoded.record(), record);
    assert_canonical(decoded.record(), decoded.raw());
});

fn assert_canonical(record: PackedOrder, expected: &[u8]) {
    // Every accepted byte prefix must be canonical: decoding and re-encoding
    // the validated view produces exactly the authenticated input bytes.
    let mut encoded = [0_u8; PACKED_SUBMIT_LEN];
    let written = record
        .encode_into(&mut encoded)
        .expect("a decoded packed order must always re-encode");
    assert_eq!(written, expected.len());
    assert_eq!(&encoded[..written], expected);
}

fn generated_record(input: &[u8]) -> PackedOrder {
    let session_ref = word(input, 1) as u32;
    let nonce = word(input, 9);
    let client_id = word(input, 17);
    let account = AccountId::new(word(input, 25) as u32);
    let market = MarketId::new(word(input, 33) as u32);
    match byte(input, 0) % 3 {
        0 => PackedOrder::Submit {
            session_ref,
            nonce,
            client_id,
            account,
            market,
            side: if byte(input, 41) & 1 == 0 {
                Side::Bid
            } else {
                Side::Ask
            },
            order_type: match byte(input, 42) % 4 {
                0 => OrderType::Limit,
                1 => OrderType::Market,
                2 => OrderType::PostOnly,
                _ => OrderType::ReduceOnly,
            },
            price: Price::from_raw(positive_i64(word(input, 43))),
            quantity: Quantity::from_raw(positive_i64(word(input, 51))),
            time_in_force: match byte(input, 59) % 3 {
                0 => TimeInForce::Gtc,
                1 => TimeInForce::Ioc,
                _ => TimeInForce::Fok,
            },
            leverage: Ratio::from_raw(positive_i64(word(input, 60))),
        },
        1 => PackedOrder::Cancel {
            session_ref,
            nonce,
            client_id,
            account,
            market,
            order_id: OrderId::new(word(input, 41) | 1),
        },
        _ => PackedOrder::Replace {
            session_ref,
            nonce,
            client_id,
            account,
            market,
            order_id: OrderId::new(word(input, 41) | 1),
            new_price: Price::from_raw(positive_i64(word(input, 49))),
            new_quantity: Quantity::from_raw(positive_i64(word(input, 57))),
        },
    }
}

fn word(input: &[u8], start: usize) -> u64 {
    let mut bytes = [0_u8; 8];
    for (offset, value) in bytes.iter_mut().enumerate() {
        *value = byte(input, start + offset);
    }
    u64::from_le_bytes(bytes)
}

fn byte(input: &[u8], index: usize) -> u8 {
    input.get(index).copied().unwrap_or(0)
}

fn positive_i64(value: u64) -> i64 {
    i64::try_from(value & (i64::MAX as u64))
        .unwrap_or(i64::MAX)
        .max(1)
}

use std::path::PathBuf;

use codec::{Frame, PackedOrder, TrafficClass};
use crypto::KeyPair;
use network::{
    decode_order_batch_receipt_frame, AuthenticatedOrderBatchCodec, OrderBatchCodec,
    MSG_TYPE_ORDER_BATCH,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use types::{AccountId, MarketId, OrderId};

fn vector() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdk/vectors/packed-v1.json");
    serde_json::from_slice(&std::fs::read(path).expect("read packed vector"))
        .expect("parse packed vector")
}

fn expected<'a>(vector: &'a Value, name: &str) -> &'a str {
    vector["expected"][name]
        .as_str()
        .unwrap_or_else(|| panic!("missing expected field {name}"))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

#[test]
fn rust_matches_the_cross_language_packed_v1_vector() {
    let vector = vector();
    let records = (0..32u64)
        .map(|index| PackedOrder::Cancel {
            session_ref: 7,
            nonce: index + 1,
            client_id: index + 100,
            account: AccountId::new(9),
            market: MarketId::new(2),
            order_id: OrderId::new(index + 1_000),
        })
        .collect::<Vec<_>>();
    let mut packed = Vec::with_capacity(32 * 40);
    for record in records {
        let start = packed.len();
        packed.resize(start + record.encoded_len(), 0);
        record
            .encode_into(&mut packed[start..])
            .expect("encode packed record");
    }
    assert_eq!(
        hex::encode(&packed[..40]),
        expected(&vector, "first_record_hex")
    );
    assert_eq!(sha256(&packed), expected(&vector, "packed_records_sha256"));

    let mut raw = vec![0u8; 20 + packed.len()];
    raw[0..2].copy_from_slice(&0xb417u16.to_le_bytes());
    raw[2] = 1;
    raw[3] = 1;
    raw[4] = 0;
    raw[5] = 32;
    raw[8..12].copy_from_slice(&u32::try_from(packed.len()).unwrap().to_le_bytes());
    raw[12..16].copy_from_slice(&u32::try_from(packed.len()).unwrap().to_le_bytes());
    raw[16..20].copy_from_slice(&crc32(&packed).to_le_bytes());
    raw[20..].copy_from_slice(&packed);
    assert_eq!(sha256(&raw), expected(&vector, "raw_order_batch_sha256"));

    let signer = KeyPair::from_seed(&[8; 32]);
    assert_eq!(
        hex::encode(signer.public()),
        expected(&vector, "public_key_hex")
    );
    let mut authenticated = vec![0u8; 100 + raw.len()];
    authenticated[0..4].copy_from_slice(b"DXOB");
    authenticated[4] = 1;
    authenticated[8..40].fill(3);
    authenticated[40..44].copy_from_slice(&7u32.to_le_bytes());
    authenticated[44..48].copy_from_slice(&9u32.to_le_bytes());
    authenticated[48..56].copy_from_slice(&4u64.to_le_bytes());
    authenticated[56..64].copy_from_slice(&100u64.to_le_bytes());
    authenticated[64..96].copy_from_slice(&signer.public());
    authenticated[96..100].copy_from_slice(&u32::try_from(raw.len()).unwrap().to_le_bytes());
    authenticated[100..].copy_from_slice(&raw);
    let signature = signer.sign(&authenticated);
    authenticated.extend_from_slice(&signature);
    assert_eq!(
        sha256(&authenticated),
        expected(&vector, "authenticated_batch_sha256")
    );
    let verified = AuthenticatedOrderBatchCodec::verify(&authenticated, &[3; 32])
        .expect("verify cross-language raw batch");
    let mut decoded = vec![0; 64 * 1024];
    let decoded = OrderBatchCodec::decode_into(verified.envelope, &mut decoded)
        .expect("decode cross-language raw batch");
    assert_eq!(decoded.records, packed);

    let frame = Frame {
        class: TrafficClass::NewOrder,
        msg_type: MSG_TYPE_ORDER_BATCH,
        sequence: 0,
        payload: authenticated,
    }
    .encode()
    .expect("encode transport frame");
    assert_eq!(
        sha256(&frame),
        expected(&vector, "order_batch_frame_sha256")
    );

    let receipt_frame = hex::decode(expected(&vector, "executed_receipt_frame_hex"))
        .expect("decode receipt vector");
    let (frame, consumed) = Frame::decode(&receipt_frame).expect("decode receipt frame");
    assert_eq!(consumed, receipt_frame.len());
    let receipt = decode_order_batch_receipt_frame(&frame).expect("decode receipt");
    assert_eq!(receipt.batch_sequence, 4);
    assert_eq!(receipt.first_sequence, 100);
    assert_eq!(receipt.executed, 31);
    assert_eq!(receipt.failed, 1);
}

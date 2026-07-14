use std::time::Duration;

use client::packed::{CompletionBoundary, PackedClient, PackedLease, PackedOrder, PackedTransport};
use codec::{Frame, FRAME_HEADER_LEN};
use network::{
    decode_authenticated_order_batch_frame_into, encode_order_batch_receipt_frame,
    AuthenticatedOrderBatchCodec, OrderBatchReceipt, OrderBatchReceiptStage,
    AUTHENTICATED_ORDER_BATCH_HEADER_LEN, MSG_TYPE_ORDER_BATCH,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use types::{AccountId, MarketId, OrderId};

fn records(nonce_base: u64) -> Vec<PackedOrder> {
    (0..32)
        .map(|index| PackedOrder::Cancel {
            session_ref: 7,
            nonce: nonce_base + index,
            client_id: 100,
            account: AccountId::new(9),
            market: MarketId::new(2),
            order_id: OrderId::new(1_000 + index),
        })
        .collect()
}

async fn read_batch<S>(stream: &mut S, expected_transport_sequence: u64) -> Frame
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; FRAME_HEADER_LEN];
    stream.read_exact(&mut header).await.unwrap();
    let payload_len = u32::from_le_bytes(header[15..19].try_into().unwrap()) as usize;
    let mut wire = vec![0; FRAME_HEADER_LEN + payload_len];
    wire[..FRAME_HEADER_LEN].copy_from_slice(&header);
    stream
        .read_exact(&mut wire[FRAME_HEADER_LEN..])
        .await
        .unwrap();
    let (frame, consumed) = Frame::decode(&wire).unwrap();
    assert_eq!(consumed, wire.len());
    assert_eq!(frame.sequence, expected_transport_sequence);
    assert_eq!(frame.msg_type, MSG_TYPE_ORDER_BATCH);
    frame
}

async fn write_receipt<S>(
    stream: &mut S,
    stage: OrderBatchReceiptStage,
    receipt_sequence: u64,
    batch_sequence: u64,
    first_sequence: u64,
) where
    S: AsyncWrite + Unpin,
{
    let (admitted, executed, finalized, failed, checkpoint) = match stage {
        OrderBatchReceiptStage::Admitted => (32, 0, 0, 0, None),
        OrderBatchReceiptStage::Executed => (32, 31, 0, 1, None),
        OrderBatchReceiptStage::Finalized => (32, 31, 31, 1, Some(44)),
        OrderBatchReceiptStage::Rejected => unreachable!(),
    };
    let frame = encode_order_batch_receipt_frame(
        &OrderBatchReceipt {
            stage,
            record_count: 32,
            admitted,
            executed,
            finalized,
            failed,
            rejection_code: 0,
            batch_sequence,
            first_sequence,
            checkpoint_height: checkpoint,
            observed_unix_ns: 123,
        },
        receipt_sequence,
    )
    .unwrap()
    .encode()
    .unwrap();
    stream.write_all(&frame).await.unwrap();
    stream.flush().await.unwrap();
}

async fn serve_two_batches<S>(mut stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    for ordinal in 0..2u64 {
        let frame = read_batch(&mut stream, ordinal).await;
        let inspected = network::inspect_authenticated_order_batch(&frame.payload).unwrap();
        assert_eq!(inspected.binding.batch_sequence, 4 + ordinal);
        assert_eq!(inspected.binding.first_sequence, 100 + ordinal * 32);
        assert_eq!(inspected.binding.session_ref, 7);
        assert_eq!(inspected.binding.account, AccountId::new(9));
        let verified = AuthenticatedOrderBatchCodec::verify(&frame.payload, &[3; 32]).unwrap();
        assert_eq!(
            verified.envelope,
            &frame.payload[AUTHENTICATED_ORDER_BATCH_HEADER_LEN..frame.payload.len() - 64]
        );
        let mut decoded = vec![0; 64 * 1024];
        let batch =
            decode_authenticated_order_batch_frame_into(&frame, &[3; 32], &mut decoded).unwrap();
        assert_eq!(batch.record_count, 32);

        let receipt_base = ordinal * 3;
        write_receipt(
            &mut stream,
            OrderBatchReceiptStage::Admitted,
            receipt_base,
            4 + ordinal,
            100 + ordinal * 32,
        )
        .await;
        write_receipt(
            &mut stream,
            OrderBatchReceiptStage::Executed,
            receipt_base + 1,
            4 + ordinal,
            100 + ordinal * 32,
        )
        .await;
        // The first call completes at execution. Its later finality receipt must
        // be drained before the second batch's receipts without mis-correlation.
        write_receipt(
            &mut stream,
            OrderBatchReceiptStage::Finalized,
            receipt_base + 2,
            4 + ordinal,
            100 + ordinal * 32,
        )
        .await;
    }
}

#[tokio::test]
async fn tls_client_connects_and_drains_late_finality_before_the_next_batch() {
    let (cert_pem, key_pem) = rpc::generate_self_signed_localhost().unwrap();
    let acceptor = rpc::acceptor_from_pem(&cert_pem, &key_pem, None).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        serve_two_batches(tls).await;
    });
    let lease = PackedLease {
        endpoint,
        source_ip: None,
        destination: [3; 32],
        session_ref: 7,
        account: AccountId::new(9),
        first_batch_sequence: 4,
        first_command_sequence: 100,
        batch_sequence_stride: 1,
        command_sequence_stride: 0,
    };
    let mut client = PackedClient::connect(
        lease,
        [8; 32],
        PackedTransport::Tls13 {
            server_name: "localhost".to_string(),
            ca_certificates_pem: cert_pem,
            client_identity: None,
        },
    )
    .await
    .unwrap();
    let first = client
        .send_batch(
            &records(1),
            CompletionBoundary::Executed,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(first.executed.executed, 31);
    assert!(first.finalized.is_none());
    let second = client
        .send_batch(
            &records(33),
            CompletionBoundary::Executed,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(second.batch_sequence, 5);
    assert_eq!(second.first_sequence, 132);
    assert_eq!(client.next_batch_sequence(), 6);
    assert_eq!(client.next_command_sequence(), 164);
    server.await.unwrap();
}

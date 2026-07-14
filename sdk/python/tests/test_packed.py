import hashlib
import json
import queue
import socket
import struct
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from dexos_sdk import (
    BatchBinding,
    CancelOrder,
    CompletionBoundary,
    DevPlaintext,
    Ed25519Signer,
    PackedClient,
    PackedLease,
    ProtocolError,
    decode_order_batch_receipt,
    decode_order_batch_receipt_frame,
    encode_authenticated_order_batch,
    encode_order_batch_frame,
    encode_packed_order,
    encode_raw_order_batch,
)
from dexos_sdk.packed import (
    MAX_PENDING_ORDER_BATCH_FINALITY,
    _remember_retired_execution,
)


def cancel(index: int) -> CancelOrder:
    return CancelOrder(
        session_ref=7,
        nonce=index + 1,
        client_id=index + 100,
        account=9,
        market=2,
        order_id=index + 1000,
    )


class PackedProtocolTests(unittest.TestCase):
    def test_full_finality_capacity_rejects_before_encoding_or_write(self) -> None:
        stream = Mock(spec=socket.socket)
        lease = PackedLease(
            host="127.0.0.1",
            port=1,
            destination=bytes([3]) * 32,
            session_ref=7,
            account=9,
            first_batch_sequence=4,
            first_command_sequence=100,
            batch_sequence_stride=1,
        )
        client = PackedClient(lease, Ed25519Signer(bytes([8]) * 32), stream)
        client._retired_executed = {
            (sequence, sequence + 1)
            for sequence in range(MAX_PENDING_ORDER_BATCH_FINALITY)
        }
        retained = set(client._retired_executed)

        with patch("dexos_sdk.packed.encode_authenticated_order_batch") as encode:
            with self.assertRaisesRegex(
                ProtocolError, "late-finality correlation capacity was exhausted"
            ):
                client.send_batch(
                    [cancel(index) for index in range(32)],
                    CompletionBoundary.EXECUTED,
                )
            encode.assert_not_called()

        stream.sendall.assert_not_called()
        self.assertEqual(client.next_batch_sequence, 4)
        self.assertEqual(client.next_command_sequence, 100)
        self.assertEqual(len(client._retired_executed), MAX_PENDING_ORDER_BATCH_FINALITY)
        self.assertEqual(client._retired_executed, retained)

    def test_finality_correlation_capacity_fails_without_evicting_evidence(self) -> None:
        retired: set[tuple[int, int]] = set()
        for sequence in range(MAX_PENDING_ORDER_BATCH_FINALITY):
            _remember_retired_execution(retired, (sequence, sequence + 1))
        retained = set(retired)

        with self.assertRaisesRegex(
            ProtocolError, "late-finality correlation capacity was exhausted"
        ):
            _remember_retired_execution(retired, ((1 << 64) - 1, (1 << 64) - 1))

        self.assertEqual(len(retired), MAX_PENDING_ORDER_BATCH_FINALITY)
        self.assertEqual(retired, retained)

    def test_packed_cancel_and_raw_batch_layout(self) -> None:
        record = encode_packed_order(cancel(0))
        self.assertEqual(
            record.hex(),
            "0102280007000000010000000000000064000000000000000900000002000000e803000000000000",
        )
        batch = encode_raw_order_batch([cancel(index) for index in range(32)])
        self.assertEqual(int.from_bytes(batch[0:2], "little"), 0xB417)
        self.assertEqual(batch[3], 1)
        self.assertEqual(batch[5], 32)
        self.assertEqual(int.from_bytes(batch[8:12], "little"), 1280)
        self.assertEqual(int.from_bytes(batch[12:16], "little"), 1280)

    def test_authenticated_batch_is_deterministic_for_a_seed(self) -> None:
        signer = Ed25519Signer(bytes([8]) * 32)
        encoded = encode_authenticated_order_batch(
            BatchBinding(bytes([3]) * 32, 7, 9, 4, 100),
            signer,
            [cancel(index) for index in range(32)],
        )
        self.assertEqual(
            signer.public_key.hex(),
            "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca",
        )
        self.assertEqual(encoded[:4], b"DXOB")
        self.assertEqual(int.from_bytes(encoded[96:100], "little"), 1300)
        self.assertEqual(len(encoded), 1464)

    def test_receipt_semantic_contradictions_fail_closed(self) -> None:
        receipt = bytearray(48)
        receipt[:4] = b"DXBR"
        receipt[4] = 1
        receipt[5] = 2
        receipt[6] = 32
        receipt[7] = 32
        receipt[8] = 31
        receipt[10] = 1
        self.assertEqual(decode_order_batch_receipt(bytes(receipt)).stage.value, "executed")
        receipt[9] = 1
        with self.assertRaises(ProtocolError):
            decode_order_batch_receipt(bytes(receipt))

    def test_matches_the_shared_packed_v1_golden_vector(self) -> None:
        vector_path = Path(__file__).parents[2] / "vectors" / "packed-v1.json"
        vector = json.loads(vector_path.read_text())
        expected = vector["expected"]
        records = [cancel(index) for index in range(32)]
        packed = b"".join(encode_packed_order(record) for record in records)
        raw = encode_raw_order_batch(records)
        signer = Ed25519Signer(bytes([8]) * 32)
        authenticated = encode_authenticated_order_batch(
            BatchBinding(bytes([3]) * 32, 7, 9, 4, 100), signer, records
        )
        digest = lambda value: hashlib.sha256(value).hexdigest()
        self.assertEqual(packed[:40].hex(), expected["first_record_hex"])
        self.assertEqual(digest(packed), expected["packed_records_sha256"])
        self.assertEqual(digest(raw), expected["raw_order_batch_sha256"])
        self.assertEqual(digest(authenticated), expected["authenticated_batch_sha256"])
        self.assertEqual(
            digest(encode_order_batch_frame(authenticated, 0)),
            expected["order_batch_frame_sha256"],
        )
        receipt = decode_order_batch_receipt_frame(
            bytes.fromhex(expected["executed_receipt_frame_hex"])
        )
        self.assertEqual(receipt.executed, 31)
        self.assertEqual(receipt.failed, 1)

    def test_packed_client_connects_signs_advances_and_reads_receipts(self) -> None:
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        peer_errors: queue.Queue[BaseException | None] = queue.Queue()

        def peer() -> None:
            try:
                stream, _ = listener.accept()
                with stream:
                    header = recv_exact(stream, 19)
                    self.assertEqual(int.from_bytes(header[0:2], "little"), 0xDE05)
                    self.assertEqual(int.from_bytes(header[7:15], "little"), 0)
                    payload = recv_exact(stream, int.from_bytes(header[15:19], "little"))
                    self.assertEqual(payload[:4], b"DXOB")
                    self.assertEqual(int.from_bytes(payload[40:44], "little"), 7)
                    self.assertEqual(int.from_bytes(payload[44:48], "little"), 9)
                    self.assertEqual(int.from_bytes(payload[48:56], "little"), 4)
                    self.assertEqual(int.from_bytes(payload[56:64], "little"), 100)
                    body_end = 100 + int.from_bytes(payload[96:100], "little")
                    Ed25519PublicKey.from_public_bytes(payload[64:96]).verify(
                        payload[body_end:], payload[:body_end]
                    )
                    stream.sendall(receipt_frame(1, 0) + receipt_frame(2, 1))
                peer_errors.put(None)
            except BaseException as error:
                peer_errors.put(error)

        thread = threading.Thread(target=peer, daemon=True)
        thread.start()
        lease = PackedLease(
            host="127.0.0.1",
            port=listener.getsockname()[1],
            destination=bytes([3]) * 32,
            session_ref=7,
            account=9,
            first_batch_sequence=4,
            first_command_sequence=100,
            batch_sequence_stride=1,
        )
        try:
            with PackedClient.connect(lease, bytes([8]) * 32, DevPlaintext()) as client:
                result = client.send_batch(
                    [cancel(index) for index in range(32)],
                    CompletionBoundary.EXECUTED,
                    2.0,
                )
                self.assertEqual(result.batch_sequence, 4)
                self.assertEqual(result.executed.executed, 31)
                self.assertEqual(result.executed.failed, 1)
                self.assertEqual(client.next_batch_sequence, 5)
                self.assertEqual(client.next_command_sequence, 132)
            thread.join(2.0)
            error = peer_errors.get(timeout=2.0)
            if error is not None:
                raise error
        finally:
            listener.close()


def recv_exact(stream: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = stream.recv(length - len(output))
        if not chunk:
            raise ConnectionError("peer closed early")
        output.extend(chunk)
    return bytes(output)


def receipt_frame(stage: int, sequence: int) -> bytes:
    receipt = bytearray(48)
    receipt[:4] = b"DXBR"
    receipt[4] = 1
    receipt[5] = stage
    receipt[6] = 32
    receipt[7] = 32
    if stage == 2:
        receipt[8] = 31
        receipt[10] = 1
    struct.pack_into("<QQQQ", receipt, 16, 4, 100, 0, 123)
    return struct.pack("<HHBHQI", 0xDE05, 1, 4, 0x0102, sequence, 48) + receipt


if __name__ == "__main__":
    unittest.main()

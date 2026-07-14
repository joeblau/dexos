"""Canonical v1 packed records, authenticated batches, and persistent transport."""

from __future__ import annotations

import binascii
import socket
import ssl
import struct
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Literal, Sequence, TypeAlias

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

FRAME_HEADER_LEN = 19
RECEIPT_LEN = 48
MSG_TYPE_ORDER_BATCH = 0x0101
MSG_TYPE_ORDER_BATCH_RECEIPT = 0x0102
TRAFFIC_NEW_ORDER = 3
TRAFFIC_EXECUTION_RECEIPT = 4
MAX_U64 = (1 << 64) - 1
MIN_I64 = -(1 << 63)
MAX_I64 = (1 << 63) - 1
MAX_PENDING_ORDER_BATCH_FINALITY = 65_536


class ProtocolError(Exception):
    """A local input or remote wire value violated the v1 protocol."""


class BatchRejectedError(ProtocolError):
    """The server atomically rejected a batch."""

    def __init__(self, rejection_code: int) -> None:
        self.rejection_code = rejection_code
        super().__init__(f"batch rejected with code {rejection_code}")


@dataclass(frozen=True, slots=True)
class SubmitOrder:
    session_ref: int
    nonce: int
    client_id: int
    account: int
    market: int
    side: Literal["bid", "ask"]
    order_type: Literal["limit", "market", "post-only", "reduce-only"]
    price: int
    quantity: int
    time_in_force: Literal["gtc", "ioc", "fok"]
    leverage: int


@dataclass(frozen=True, slots=True)
class CancelOrder:
    session_ref: int
    nonce: int
    client_id: int
    account: int
    market: int
    order_id: int


@dataclass(frozen=True, slots=True)
class ReplaceOrder:
    session_ref: int
    nonce: int
    client_id: int
    account: int
    market: int
    order_id: int
    new_price: int
    new_quantity: int


PackedOrder: TypeAlias = SubmitOrder | CancelOrder | ReplaceOrder


@dataclass(frozen=True, slots=True)
class PackedLease:
    host: str
    port: int
    destination: bytes
    session_ref: int
    account: int
    first_batch_sequence: int
    first_command_sequence: int
    batch_sequence_stride: int
    command_sequence_stride: int = 0
    source_address: str | None = None


@dataclass(frozen=True, slots=True)
class DevPlaintext:
    """Explicit development-only plaintext transport."""


@dataclass(frozen=True, slots=True)
class Tls13:
    server_hostname: str
    ca_file: str | None = None
    ca_data: str | bytes | None = None
    client_cert_file: str | None = None
    client_key_file: str | None = None


PackedTransport: TypeAlias = DevPlaintext | Tls13


class CompletionBoundary(str, Enum):
    EXECUTED = "executed"
    FINALIZED = "finalized"


class ReceiptStage(str, Enum):
    ADMITTED = "admitted"
    EXECUTED = "executed"
    FINALIZED = "finalized"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class OrderBatchReceipt:
    stage: ReceiptStage
    record_count: int
    admitted: int
    executed: int
    finalized: int
    failed: int
    rejection_code: int
    batch_sequence: int
    first_sequence: int
    checkpoint_height: int | None
    observed_unix_ns: int


@dataclass(frozen=True, slots=True)
class PackedBatchResult:
    batch_sequence: int
    first_sequence: int
    admitted: OrderBatchReceipt | None
    executed: OrderBatchReceipt
    finalized: OrderBatchReceipt | None


@dataclass(frozen=True, slots=True)
class BatchBinding:
    destination: bytes
    session_ref: int
    account: int
    batch_sequence: int
    first_sequence: int


class Ed25519Signer:
    """An Ed25519 key backed by a canonical 32-byte seed."""

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ProtocolError("signing seed must contain 32 bytes")
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key = self._key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


def encode_packed_order(order: PackedOrder) -> bytes:
    """Encode one canonical fixed-width submit, cancel, or replace record."""
    if isinstance(order, SubmitOrder):
        tag, length, flags = 1, 56, _submit_flags(order)
    elif isinstance(order, CancelOrder):
        tag, length, flags = 2, 40, 0
    elif isinstance(order, ReplaceOrder):
        tag, length, flags = 3, 56, 0
    else:
        raise ProtocolError("unknown packed order type")
    output = bytearray(length)
    struct.pack_into("<BBBBIQQII", output, 0, 1, tag, length, flags,
                     _u32(order.session_ref, "session_ref"),
                     _u64(order.nonce, "nonce"),
                     _u64(order.client_id, "client_id"),
                     _u32(order.account, "account"),
                     _u32(order.market, "market"))
    if isinstance(order, SubmitOrder):
        struct.pack_into("<qqq", output, 32,
                         _i64(order.price, "price"),
                         _i64(order.quantity, "quantity"),
                         _i64(order.leverage, "leverage"))
    elif isinstance(order, CancelOrder):
        struct.pack_into("<Q", output, 32, _u64(order.order_id, "order_id"))
    else:
        struct.pack_into("<Qqq", output, 32,
                         _u64(order.order_id, "order_id"),
                         _i64(order.new_price, "new_price"),
                         _i64(order.new_quantity, "new_quantity"))
    return bytes(output)


def encode_raw_order_batch(records: Sequence[PackedOrder]) -> bytes:
    """Encode the interoperable raw (uncompressed) v1 order-batch envelope."""
    _validate_batch(records)
    packed = b"".join(encode_packed_order(record) for record in records)
    header = bytearray(20)
    struct.pack_into("<HBBBB2xIII", header, 0, 0xB417, 1, 1, 0, len(records),
                     len(packed), len(packed), binascii.crc32(packed) & 0xFFFF_FFFF)
    return bytes(header) + packed


def encode_authenticated_order_batch(
    binding: BatchBinding,
    signer: Ed25519Signer,
    records: Sequence[PackedOrder],
) -> bytes:
    if len(binding.destination) != 32:
        raise ProtocolError("destination must contain 32 bytes")
    _validate_record_bindings(records, binding.session_ref, binding.account)
    inner = encode_raw_order_batch(records)
    body = bytearray(100 + len(inner))
    body[0:4] = b"DXOB"
    body[4] = 1
    body[8:40] = binding.destination
    struct.pack_into("<IIQQ", body, 40,
                     _u32(binding.session_ref, "session_ref"),
                     _u32(binding.account, "account"),
                     _u64(binding.batch_sequence, "batch_sequence"),
                     _u64(binding.first_sequence, "first_sequence"))
    body[64:96] = signer.public_key
    struct.pack_into("<I", body, 96, len(inner))
    body[100:] = inner
    return bytes(body) + signer.sign(bytes(body))


def encode_order_batch_frame(payload: bytes, sequence: int) -> bytes:
    return _encode_frame(TRAFFIC_NEW_ORDER, MSG_TYPE_ORDER_BATCH, sequence, payload)


def decode_order_batch_receipt_frame(frame: bytes) -> OrderBatchReceipt:
    if len(frame) < FRAME_HEADER_LEN:
        raise ProtocolError("truncated frame")
    traffic_class, message_type, _sequence, length = _decode_frame_header(frame[:FRAME_HEADER_LEN])
    if traffic_class != TRAFFIC_EXECUTION_RECEIPT:
        raise ProtocolError("receipt has the wrong traffic class")
    if message_type != MSG_TYPE_ORDER_BATCH_RECEIPT:
        raise ProtocolError("receipt has the wrong message type")
    if length != RECEIPT_LEN or len(frame) != FRAME_HEADER_LEN + length:
        raise ProtocolError("receipt frame length is invalid")
    return decode_order_batch_receipt(frame[FRAME_HEADER_LEN:])


def decode_order_batch_receipt(payload: bytes) -> OrderBatchReceipt:
    if len(payload) != RECEIPT_LEN:
        raise ProtocolError("receipt must contain 48 bytes")
    if payload[:4] != b"DXBR":
        raise ProtocolError("bad receipt magic")
    if payload[4] != 1:
        raise ProtocolError(f"unsupported receipt version {payload[4]}")
    stages = {1: ReceiptStage.ADMITTED, 2: ReceiptStage.EXECUTED,
              3: ReceiptStage.FINALIZED, 4: ReceiptStage.REJECTED}
    try:
        stage = stages[payload[5]]
    except KeyError as error:
        raise ProtocolError(f"unknown receipt stage {payload[5]}") from error
    flags = payload[11]
    if flags & ~1 or payload[14:16] != b"\x00\x00":
        raise ProtocolError("receipt reserved bits are nonzero")
    rejection_code = struct.unpack_from("<H", payload, 12)[0]
    batch_sequence, first_sequence, checkpoint, observed = struct.unpack_from("<QQQQ", payload, 16)
    receipt = OrderBatchReceipt(
        stage=stage,
        record_count=payload[6],
        admitted=payload[7],
        executed=payload[8],
        finalized=payload[9],
        failed=payload[10],
        rejection_code=rejection_code,
        batch_sequence=batch_sequence,
        first_sequence=first_sequence,
        checkpoint_height=checkpoint if flags == 1 else None,
        observed_unix_ns=observed,
    )
    _validate_receipt(receipt)
    return receipt


class PackedClient:
    """Serialized persistent TCP/TLS client for one server-issued lease."""

    def __init__(self, lease: PackedLease, signer: Ed25519Signer, stream: socket.socket) -> None:
        _validate_lease(lease)
        self._lease = lease
        self._signer = signer
        self.public_key = signer.public_key
        self._stream = stream
        self._next_transport_sequence = 0
        self._next_receipt_sequence = 0
        self._next_batch_sequence = lease.first_batch_sequence
        self._next_command_sequence = lease.first_command_sequence
        self._retired_executed: set[tuple[int, int]] = set()
        self._lock = threading.Lock()
        self._usable = True

    @classmethod
    def connect(
        cls,
        lease: PackedLease,
        signing_seed: bytes,
        transport: PackedTransport,
        connect_timeout: float = 10.0,
    ) -> PackedClient:
        _validate_lease(lease)
        source = (lease.source_address, 0) if lease.source_address is not None else None
        raw = socket.create_connection((lease.host, lease.port), connect_timeout, source)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if isinstance(transport, DevPlaintext):
            stream = raw
        else:
            context = ssl.create_default_context(cafile=transport.ca_file, cadata=transport.ca_data)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            context.set_alpn_protocols(["dexos-rpc/1"])
            if transport.client_cert_file is not None:
                context.load_cert_chain(transport.client_cert_file, transport.client_key_file)
            try:
                stream = context.wrap_socket(raw, server_hostname=transport.server_hostname)
            except BaseException:
                raw.close()
                raise
        return cls(lease, Ed25519Signer(signing_seed), stream)

    @property
    def next_batch_sequence(self) -> int:
        return self._next_batch_sequence

    @property
    def next_command_sequence(self) -> int:
        return self._next_command_sequence

    def close(self) -> None:
        self._stream.close()

    def __enter__(self) -> PackedClient:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def send_batch(
        self,
        records: Sequence[PackedOrder],
        completion: CompletionBoundary = CompletionBoundary.EXECUTED,
        receipt_timeout: float = 10.0,
    ) -> PackedBatchResult:
        if receipt_timeout <= 0:
            raise ProtocolError("receipt timeout must be positive")
        with self._lock:
            return self._send_batch_locked(records, completion, receipt_timeout)

    def _send_batch_locked(
        self,
        records: Sequence[PackedOrder],
        completion: CompletionBoundary,
        receipt_timeout: float,
    ) -> PackedBatchResult:
        if not self._usable:
            raise ProtocolError("connection is unusable after an ambiguous in-flight failure")
        if not isinstance(completion, CompletionBoundary):
            raise ProtocolError("completion must be a CompletionBoundary")
        if completion is CompletionBoundary.EXECUTED:
            _ensure_finality_correlation_capacity(self._retired_executed)
        _validate_record_bindings(records, self._lease.session_ref, self._lease.account)
        binding = BatchBinding(
            destination=self._lease.destination,
            session_ref=self._lease.session_ref,
            account=self._lease.account,
            batch_sequence=self._next_batch_sequence,
            first_sequence=self._next_command_sequence,
        )
        payload = encode_authenticated_order_batch(binding, self._signer, records)
        wire = encode_order_batch_frame(payload, self._next_transport_sequence)
        self._usable = False
        self._stream.sendall(wire)
        command_advance = (len(records) if self._lease.command_sequence_stride == 0
                           else self._lease.command_sequence_stride)
        if command_advance < len(records):
            raise ProtocolError("invalid command stride")
        self._next_transport_sequence = _checked_add(self._next_transport_sequence, 1, "transport sequence")
        self._next_batch_sequence = _checked_add(
            self._next_batch_sequence, self._lease.batch_sequence_stride, "batch sequence")
        self._next_command_sequence = _checked_add(
            self._next_command_sequence, command_advance, "command sequence")

        admitted: OrderBatchReceipt | None = None
        executed: OrderBatchReceipt | None = None
        self._stream.settimeout(receipt_timeout)
        while True:
            sequence, receipt = self._read_receipt()
            if sequence != self._next_receipt_sequence:
                raise ProtocolError(
                    f"receipt sequence mismatch: expected {self._next_receipt_sequence}, got {sequence}")
            self._next_receipt_sequence = _checked_add(
                self._next_receipt_sequence, 1, "receipt sequence")
            key = (receipt.batch_sequence, receipt.first_sequence)
            current = (binding.batch_sequence, binding.first_sequence)
            if key != current:
                if receipt.stage is ReceiptStage.FINALIZED and key in self._retired_executed:
                    self._retired_executed.remove(key)
                    continue
                raise ProtocolError(f"uncorrelated receipt {key[0]}:{key[1]}")
            if receipt.record_count != len(records):
                raise ProtocolError("receipt count mismatch")
            if receipt.stage is ReceiptStage.REJECTED:
                raise BatchRejectedError(receipt.rejection_code)
            if receipt.stage is ReceiptStage.ADMITTED:
                admitted = receipt
            elif receipt.stage is ReceiptStage.EXECUTED:
                executed = receipt
                if completion is CompletionBoundary.EXECUTED:
                    _remember_retired_execution(self._retired_executed, key)
                    self._usable = True
                    return PackedBatchResult(binding.batch_sequence, binding.first_sequence,
                                             admitted, receipt, None)
            elif receipt.stage is ReceiptStage.FINALIZED:
                if executed is None:
                    raise ProtocolError("finalized receipt preceded execution")
                self._usable = True
                return PackedBatchResult(binding.batch_sequence, binding.first_sequence,
                                         admitted, executed, receipt)

    def _read_receipt(self) -> tuple[int, OrderBatchReceipt]:
        header = _read_exact(self._stream, FRAME_HEADER_LEN)
        traffic_class, message_type, sequence, length = _decode_frame_header(header)
        if traffic_class != TRAFFIC_EXECUTION_RECEIPT or message_type != MSG_TYPE_ORDER_BATCH_RECEIPT:
            raise ProtocolError("frame is not a packed batch receipt")
        if length != RECEIPT_LEN:
            raise ProtocolError("receipt frame length is invalid")
        return sequence, decode_order_batch_receipt(_read_exact(self._stream, length))


def _submit_flags(order: SubmitOrder) -> int:
    try:
        side = {"bid": 0, "ask": 1}[order.side]
        order_type = {"limit": 0, "market": 1, "post-only": 2, "reduce-only": 3}[order.order_type]
        time_in_force = {"gtc": 0, "ioc": 1, "fok": 2}[order.time_in_force]
    except KeyError as error:
        raise ProtocolError(f"invalid submit enum: {error.args[0]}") from error
    return side | (order_type << 1) | (time_in_force << 3)


def _remember_retired_execution(
    retired: set[tuple[int, int]], key: tuple[int, int]
) -> None:
    _ensure_finality_correlation_capacity(retired)
    retired.add(key)


def _ensure_finality_correlation_capacity(retired: set[tuple[int, int]]) -> None:
    if len(retired) >= MAX_PENDING_ORDER_BATCH_FINALITY:
        raise ProtocolError("late-finality correlation capacity was exhausted")


def _validate_batch(records: Sequence[PackedOrder]) -> None:
    if not 32 <= len(records) <= 128:
        raise ProtocolError(f"batch size {len(records)} is outside 32..=128")


def _validate_record_bindings(records: Sequence[PackedOrder], session_ref: int, account: int) -> None:
    _validate_batch(records)
    if any(record.session_ref != session_ref or record.account != account for record in records):
        raise ProtocolError("record does not match the batch session/account binding")


def _validate_lease(lease: PackedLease) -> None:
    if len(lease.destination) != 32:
        raise ProtocolError("destination must contain 32 bytes")
    if not 1 <= lease.port <= 65535:
        raise ProtocolError("port is outside 1..=65535")
    _u32(lease.session_ref, "session_ref")
    _u32(lease.account, "account")
    _u64(lease.first_batch_sequence, "first_batch_sequence")
    _u64(lease.first_command_sequence, "first_command_sequence")
    if lease.batch_sequence_stride <= 0:
        raise ProtocolError("batch stride must be positive")
    if lease.command_sequence_stride < 0:
        raise ProtocolError("command stride cannot be negative")


def _validate_receipt(receipt: OrderBatchReceipt) -> None:
    count = receipt.record_count
    if not 32 <= count <= 128:
        raise ProtocolError("receipt record count is invalid")
    if (receipt.admitted > count or receipt.executed > receipt.admitted
            or receipt.finalized > receipt.executed or receipt.failed > receipt.admitted
            or receipt.executed + receipt.failed > receipt.admitted):
        raise ProtocolError("receipt counters do not conserve")
    no_checkpoint = receipt.checkpoint_height is None
    valid = (
        (receipt.stage is ReceiptStage.ADMITTED and receipt.admitted == count
         and receipt.executed == receipt.finalized == receipt.failed == 0
         and receipt.rejection_code == 0 and no_checkpoint)
        or (receipt.stage is ReceiptStage.EXECUTED and receipt.admitted == count
            and receipt.executed + receipt.failed == receipt.admitted
            and receipt.finalized == receipt.rejection_code == 0 and no_checkpoint)
        or (receipt.stage is ReceiptStage.FINALIZED and receipt.admitted == count
            and receipt.executed + receipt.failed == receipt.admitted
            and receipt.finalized == receipt.executed and receipt.rejection_code == 0
            and not no_checkpoint)
        or (receipt.stage is ReceiptStage.REJECTED and receipt.admitted == receipt.executed
            == receipt.finalized == receipt.failed == 0 and receipt.rejection_code != 0
            and no_checkpoint)
    )
    if not valid:
        raise ProtocolError("receipt contradicts its lifecycle stage")


def _encode_frame(traffic_class: int, message_type: int, sequence: int, payload: bytes) -> bytes:
    if len(payload) > 0xFFFF_FFFF:
        raise ProtocolError("frame payload is too large")
    return struct.pack("<HHBHQI", 0xDE05, 1, traffic_class, message_type,
                       _u64(sequence, "frame sequence"), len(payload)) + payload


def _decode_frame_header(header: bytes) -> tuple[int, int, int, int]:
    if len(header) != FRAME_HEADER_LEN:
        raise ProtocolError("frame header must contain 19 bytes")
    magic, version, traffic_class, message_type, sequence, length = struct.unpack("<HHBHQI", header)
    if magic != 0xDE05:
        raise ProtocolError("bad frame magic")
    if version != 1:
        raise ProtocolError("unsupported frame version")
    return traffic_class, message_type, sequence, length


def _read_exact(stream: socket.socket, length: int) -> bytes:
    output = bytearray(length)
    view = memoryview(output)
    offset = 0
    while offset < length:
        received = stream.recv_into(view[offset:])
        if received == 0:
            raise ConnectionError("socket closed before the frame completed")
        offset += received
    return bytes(output)


def _u32(value: int, name: str) -> int:
    if not 0 <= value <= 0xFFFF_FFFF:
        raise ProtocolError(f"{name} is outside unsigned 32-bit range")
    return value


def _u64(value: int, name: str) -> int:
    if not 0 <= value <= MAX_U64:
        raise ProtocolError(f"{name} is outside unsigned 64-bit range")
    return value


def _i64(value: int, name: str) -> int:
    if not MIN_I64 <= value <= MAX_I64:
        raise ProtocolError(f"{name} is outside signed 64-bit range")
    return value


def _checked_add(left: int, right: int, name: str) -> int:
    return _u64(left + right, name)

//! Canonical fixed-endian packed records for the new/cancel/replace hot path.

use types::{AccountId, MarketId, OrderId, OrderType, Price, Quantity, Ratio, Side, TimeInForce};

/// Initial packed-order wire version.
pub const PACKED_ORDER_VERSION: u8 = 1;
const TAG_SUBMIT: u8 = 1;
const TAG_CANCEL: u8 = 2;
const TAG_REPLACE: u8 = 3;
const HEADER_LEN: usize = 4;
/// Encoded submit contribution, including version/tag/length/session/replay fields.
pub const PACKED_SUBMIT_LEN: usize = 56;
/// Encoded cancel contribution, including version/tag/length/session/replay fields.
pub const PACKED_CANCEL_LEN: usize = 40;
/// Encoded replace contribution, including version/tag/length/session/replay fields.
pub const PACKED_REPLACE_LEN: usize = 56;
const BATCH_AUTH_DOMAIN: &[u8] = b"dexos.packed-order.batch.v1";
const BATCH_AUTH_FIXED_LEN: usize = BATCH_AUTH_DOMAIN.len() + 4 + 8 + 2 + 1 + 4;

/// A validated, allocation-free representation of one hot order command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackedOrder {
    Submit {
        session_ref: u32,
        nonce: u64,
        client_id: u64,
        account: AccountId,
        market: MarketId,
        side: Side,
        order_type: OrderType,
        price: Price,
        quantity: Quantity,
        time_in_force: TimeInForce,
        leverage: Ratio,
    },
    Cancel {
        session_ref: u32,
        nonce: u64,
        client_id: u64,
        account: AccountId,
        market: MarketId,
        order_id: OrderId,
    },
    Replace {
        session_ref: u32,
        nonce: u64,
        client_id: u64,
        account: AccountId,
        market: MarketId,
        order_id: OrderId,
        new_price: Price,
        new_quantity: Quantity,
    },
}

impl PackedOrder {
    /// Exact encoded contribution for this command.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        match self {
            Self::Submit { .. } => PACKED_SUBMIT_LEN,
            Self::Cancel { .. } => PACKED_CANCEL_LEN,
            Self::Replace { .. } => PACKED_REPLACE_LEN,
        }
    }

    /// Established session identity reference bound by the outer authenticated batch.
    #[must_use]
    pub const fn session_ref(self) -> u32 {
        match self {
            Self::Submit { session_ref, .. }
            | Self::Cancel { session_ref, .. }
            | Self::Replace { session_ref, .. } => session_ref,
        }
    }

    /// Monotonic replay/idempotency nonce.
    #[must_use]
    pub const fn nonce(self) -> u64 {
        match self {
            Self::Submit { nonce, .. }
            | Self::Cancel { nonce, .. }
            | Self::Replace { nonce, .. } => nonce,
        }
    }

    /// Stable client idempotency namespace from the signed control envelope.
    #[must_use]
    pub const fn client_id(self) -> u64 {
        match self {
            Self::Submit { client_id, .. }
            | Self::Cancel { client_id, .. }
            | Self::Replace { client_id, .. } => client_id,
        }
    }

    /// Account routed by this record.
    #[must_use]
    pub const fn account(self) -> AccountId {
        match self {
            Self::Submit { account, .. }
            | Self::Cancel { account, .. }
            | Self::Replace { account, .. } => account,
        }
    }

    /// Market routed by this record.
    #[must_use]
    pub const fn market(self) -> MarketId {
        match self {
            Self::Submit { market, .. }
            | Self::Cancel { market, .. }
            | Self::Replace { market, .. } => market,
        }
    }

    /// Encode into caller-owned memory. No allocation is performed.
    pub fn encode_into(self, out: &mut [u8]) -> Result<usize, PackedOrderError> {
        self.encode_with_backend(simd::Backend::Scalar, out)
    }

    /// Checked scalar reference encoder.
    pub fn encode_into_scalar(self, out: &mut [u8]) -> Result<usize, PackedOrderError> {
        self.encode_with_backend(simd::Backend::Scalar, out)
    }

    /// Encode with an explicitly selected, already-qualified backend.
    pub fn encode_with_backend(
        self,
        backend: simd::Backend,
        out: &mut [u8],
    ) -> Result<usize, PackedOrderError> {
        validate_values(self)?;
        let needed = self.encoded_len();
        if out.len() < needed {
            return Err(PackedOrderError::BufferTooSmall {
                needed,
                available: out.len(),
            });
        }
        let (tag, flags) = match self {
            Self::Submit {
                side,
                order_type,
                time_in_force,
                ..
            } => (
                TAG_SUBMIT,
                side_bits(side)
                    | (order_type_bits(order_type) << 1)
                    | (tif_bits(time_in_force) << 3),
            ),
            Self::Cancel { .. } => (TAG_CANCEL, 0),
            Self::Replace { .. } => (TAG_REPLACE, 0),
        };
        let mut header = [0u8; 8];
        header[0] = PACKED_ORDER_VERSION;
        header[1] = tag;
        header[2] = u8::try_from(needed).map_err(|_| PackedOrderError::LengthOutOfRange)?;
        header[3] = flags;
        header[4..].copy_from_slice(&self.session_ref().to_le_bytes());
        let common = u64::from(self.account().get()) | (u64::from(self.market().get()) << 32);
        let mut words = [0u64; 7];
        words[0] = u64::from_le_bytes(header);
        words[1] = self.nonce();
        words[2] = self.client_id();
        words[3] = common;
        match self {
            Self::Submit {
                account,
                market,
                price,
                quantity,
                leverage,
                ..
            } => {
                let _ = (account, market);
                words[4] = u64::from_le_bytes(price.raw().to_le_bytes());
                words[5] = u64::from_le_bytes(quantity.raw().to_le_bytes());
                words[6] = u64::from_le_bytes(leverage.raw().to_le_bytes());
            }
            Self::Cancel {
                account,
                market,
                order_id,
                ..
            } => {
                let _ = (account, market);
                words[4] = order_id.get();
            }
            Self::Replace {
                account,
                market,
                order_id,
                new_price,
                new_quantity,
                ..
            } => {
                let _ = (account, market);
                words[4] = order_id.get();
                words[5] = u64::from_le_bytes(new_price.raw().to_le_bytes());
                words[6] = u64::from_le_bytes(new_quantity.raw().to_le_bytes());
            }
        }
        let lanes = if needed == PACKED_CANCEL_LEN { 5 } else { 7 };
        if !simd::store_u64_le(backend, &words[..lanes], out) {
            return Err(PackedOrderError::BufferTooSmall {
                needed,
                available: out.len(),
            });
        }
        Ok(needed)
    }

    /// Strictly decode one record and borrow its exact canonical byte span.
    pub fn decode_ref(bytes: &[u8]) -> Result<(PackedOrderView<'_>, usize), PackedOrderError> {
        Self::decode_ref_with_backend(simd::Backend::Scalar, bytes)
    }

    /// Checked scalar reference decoder.
    pub fn decode_ref_scalar(
        bytes: &[u8],
    ) -> Result<(PackedOrderView<'_>, usize), PackedOrderError> {
        Self::decode_ref_with_backend(simd::Backend::Scalar, bytes)
    }

    /// Decode with an explicitly selected, already-qualified backend.
    pub fn decode_ref_with_backend(
        backend: simd::Backend,
        bytes: &[u8],
    ) -> Result<(PackedOrderView<'_>, usize), PackedOrderError> {
        if bytes.len() < HEADER_LEN {
            return Err(PackedOrderError::Truncated);
        }
        if bytes[0] != PACKED_ORDER_VERSION {
            return Err(PackedOrderError::UnsupportedVersion(bytes[0]));
        }
        let expected = match bytes[1] {
            TAG_SUBMIT => PACKED_SUBMIT_LEN,
            TAG_CANCEL => PACKED_CANCEL_LEN,
            TAG_REPLACE => PACKED_REPLACE_LEN,
            tag => return Err(PackedOrderError::UnknownTag(tag)),
        };
        let declared = usize::from(bytes[2]);
        if declared != expected {
            return Err(PackedOrderError::InvalidLength { expected, declared });
        }
        let raw = bytes.get(..expected).ok_or(PackedOrderError::Truncated)?;
        let lanes = if expected == PACKED_CANCEL_LEN { 5 } else { 7 };
        let mut words = [0u64; 7];
        if !simd::load_u64_le(backend, raw, &mut words[..lanes]) {
            return Err(PackedOrderError::Truncated);
        }
        let flags = raw[3];
        let session_ref = u32::try_from(words[0] >> 32).unwrap_or(u32::MAX);
        let nonce = words[1];
        let client_id = words[2];
        let account = AccountId::new(u32::try_from(words[3] & u64::from(u32::MAX)).unwrap_or(0));
        let market = MarketId::new(u32::try_from(words[3] >> 32).unwrap_or(u32::MAX));
        let record = match raw[1] {
            TAG_SUBMIT => {
                if flags & 0b1110_0000 != 0 {
                    return Err(PackedOrderError::ReservedBits(flags));
                }
                let side = decode_side(flags & 1)?;
                let order_type = decode_order_type((flags >> 1) & 0b11)?;
                let time_in_force = decode_tif((flags >> 3) & 0b11)?;
                Self::Submit {
                    session_ref,
                    nonce,
                    client_id,
                    account,
                    market,
                    side,
                    order_type,
                    price: Price::from_raw(i64::from_le_bytes(words[4].to_le_bytes())),
                    quantity: Quantity::from_raw(i64::from_le_bytes(words[5].to_le_bytes())),
                    time_in_force,
                    leverage: Ratio::from_raw(i64::from_le_bytes(words[6].to_le_bytes())),
                }
            }
            TAG_CANCEL => {
                if flags != 0 {
                    return Err(PackedOrderError::ReservedBits(flags));
                }
                Self::Cancel {
                    session_ref,
                    nonce,
                    client_id,
                    account,
                    market,
                    order_id: OrderId::new(words[4]),
                }
            }
            TAG_REPLACE => {
                if flags != 0 {
                    return Err(PackedOrderError::ReservedBits(flags));
                }
                Self::Replace {
                    session_ref,
                    nonce,
                    client_id,
                    account,
                    market,
                    order_id: OrderId::new(words[4]),
                    new_price: Price::from_raw(i64::from_le_bytes(words[5].to_le_bytes())),
                    new_quantity: Quantity::from_raw(i64::from_le_bytes(words[6].to_le_bytes())),
                }
            }
            _ => unreachable!("tag checked above"),
        };
        validate_values(record)?;
        Ok((PackedOrderView { raw, record }, expected))
    }
}

/// Encode a production-sized packed-order batch into caller-owned storage.
///
/// The record count is strictly 32..=128. No temporary `Vec` or per-record
/// scatter buffer is created; the selected backend writes each fixed-width
/// record directly into its final contiguous span.
pub fn encode_batch_with_backend(
    records: &[PackedOrder],
    backend: simd::Backend,
    out: &mut [u8],
) -> Result<usize, PackedOrderError> {
    if !(32..=128).contains(&records.len()) {
        return Err(PackedOrderError::BatchSizeOutOfRange(records.len()));
    }
    let needed = records.iter().try_fold(0usize, |total, record| {
        total
            .checked_add(record.encoded_len())
            .ok_or(PackedOrderError::LengthOutOfRange)
    })?;
    if out.len() < needed {
        return Err(PackedOrderError::BufferTooSmall {
            needed,
            available: out.len(),
        });
    }
    // On the committed Apple M-series baseline, vector setup is outside noise
    // only at 128 records; 32/64 were tied or slower. Keep those widths on the
    // scalar reference instead of shipping a regressing candidate.
    let backend = if records.len() == 128 {
        backend
    } else {
        simd::Backend::Scalar
    };
    let mut cursor = 0usize;
    for record in records {
        let written = record.encode_with_backend(backend, &mut out[cursor..needed])?;
        cursor += written;
    }
    Ok(cursor)
}

/// Runtime-dispatched form of [`encode_batch_with_backend`].
pub fn encode_batch_into(
    records: &[PackedOrder],
    out: &mut [u8],
) -> Result<usize, PackedOrderError> {
    encode_batch_with_backend(records, simd::detect(), out)
}

/// Decode exactly one production-sized batch into caller-owned record slots.
///
/// `out.len()` is the declared record count and must be 32..=128. Trailing
/// bytes are rejected so a caller cannot accidentally authenticate one prefix
/// while routing a different suffix.
pub fn decode_batch_with_backend(
    bytes: &[u8],
    backend: simd::Backend,
    out: &mut [PackedOrder],
) -> Result<usize, PackedOrderError> {
    if !(32..=128).contains(&out.len()) {
        return Err(PackedOrderError::BatchSizeOutOfRange(out.len()));
    }
    let backend = if out.len() == 128 {
        backend
    } else {
        simd::Backend::Scalar
    };
    let mut cursor = 0usize;
    for slot in out {
        let remaining = bytes.get(cursor..).ok_or(PackedOrderError::Truncated)?;
        let (view, consumed) = PackedOrder::decode_ref_with_backend(backend, remaining)?;
        *slot = view.record();
        cursor = cursor
            .checked_add(consumed)
            .ok_or(PackedOrderError::LengthOutOfRange)?;
    }
    if cursor != bytes.len() {
        return Err(PackedOrderError::TrailingBytes);
    }
    Ok(cursor)
}

/// Runtime-dispatched form of [`decode_batch_with_backend`].
pub fn decode_batch_into(bytes: &[u8], out: &mut [PackedOrder]) -> Result<usize, PackedOrderError> {
    decode_batch_with_backend(bytes, simd::detect(), out)
}

/// Validated typed record retaining a zero-copy view of its canonical bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedOrderView<'a> {
    raw: &'a [u8],
    record: PackedOrder,
}

impl<'a> PackedOrderView<'a> {
    #[must_use]
    pub const fn raw(self) -> &'a [u8] {
        self.raw
    }

    #[must_use]
    pub const fn record(self) -> PackedOrder {
        self.record
    }
}

/// Batch-layer fields that bind order, destination, replay domain, and ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedBatchBinding {
    pub session_ref: u32,
    pub batch_sequence: u64,
    pub target_shard: u16,
    pub record_count: u8,
}

/// Build the exact caller-owned preimage authenticated by the session/batch layer.
///
/// Every record is strictly decoded, must name the same established session, and
/// is covered in byte order. Reordering, detaching, redirecting to another shard,
/// changing the batch sequence, or replaying under another session changes the
/// authenticated bytes.
pub fn batch_auth_preimage_into(
    binding: PackedBatchBinding,
    encoded_records: &[u8],
    out: &mut [u8],
) -> Result<usize, PackedOrderError> {
    if !(1..=128).contains(&binding.record_count) {
        return Err(PackedOrderError::RecordCountOutOfRange(
            binding.record_count,
        ));
    }
    let mut cursor = 0usize;
    let mut count = 0u8;
    while cursor < encoded_records.len() {
        let (view, consumed) = PackedOrder::decode_ref(&encoded_records[cursor..])?;
        if view.record().session_ref() != binding.session_ref {
            return Err(PackedOrderError::SessionMismatch);
        }
        cursor = cursor
            .checked_add(consumed)
            .ok_or(PackedOrderError::LengthOutOfRange)?;
        count = count
            .checked_add(1)
            .ok_or(PackedOrderError::RecordCountOutOfRange(u8::MAX))?;
    }
    if count != binding.record_count {
        return Err(PackedOrderError::RecordCountMismatch {
            declared: binding.record_count,
            actual: count,
        });
    }
    let needed = BATCH_AUTH_FIXED_LEN
        .checked_add(encoded_records.len())
        .ok_or(PackedOrderError::LengthOutOfRange)?;
    if out.len() < needed {
        return Err(PackedOrderError::BufferTooSmall {
            needed,
            available: out.len(),
        });
    }
    let mut p = 0;
    out[p..p + BATCH_AUTH_DOMAIN.len()].copy_from_slice(BATCH_AUTH_DOMAIN);
    p += BATCH_AUTH_DOMAIN.len();
    put_u32(out, p, binding.session_ref);
    p += 4;
    put_u64(out, p, binding.batch_sequence);
    p += 8;
    put_u16(out, p, binding.target_shard);
    p += 2;
    out[p] = binding.record_count;
    p += 1;
    let records_len =
        u32::try_from(encoded_records.len()).map_err(|_| PackedOrderError::LengthOutOfRange)?;
    put_u32(out, p, records_len);
    p += 4;
    out[p..p + encoded_records.len()].copy_from_slice(encoded_records);
    Ok(needed)
}

/// Negotiate the sole supported version, failing instead of falling back silently.
pub fn negotiate_packed_order_version(peer_min: u8, peer_max: u8) -> Result<u8, PackedOrderError> {
    if peer_min <= PACKED_ORDER_VERSION && PACKED_ORDER_VERSION <= peer_max {
        Ok(PACKED_ORDER_VERSION)
    } else {
        Err(PackedOrderError::NoCommonVersion { peer_min, peer_max })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PackedOrderError {
    #[error("packed order is truncated")]
    Truncated,
    #[error("unsupported packed-order version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown packed-order tag {0}")]
    UnknownTag(u8),
    #[error("packed-order length is {declared}, expected {expected}")]
    InvalidLength { expected: usize, declared: usize },
    #[error("reserved packed-order flag bits are set: {0:#04x}")]
    ReservedBits(u8),
    #[error("invalid packed-order field: {0}")]
    InvalidValue(&'static str),
    #[error("output buffer has {available} bytes, needs {needed}")]
    BufferTooSmall { needed: usize, available: usize },
    #[error("packed-order length is out of range")]
    LengthOutOfRange,
    #[error("record count {0} is outside 1..=128")]
    RecordCountOutOfRange(u8),
    #[error("packed-order batch size {0} is outside 32..=128")]
    BatchSizeOutOfRange(usize),
    #[error("batch declares {declared} records but contains {actual}")]
    RecordCountMismatch { declared: u8, actual: u8 },
    #[error("record session does not match authenticated batch session")]
    SessionMismatch,
    #[error("no common packed-order version in peer range {peer_min}..={peer_max}")]
    NoCommonVersion { peer_min: u8, peer_max: u8 },
    #[error("trailing bytes after the declared packed-order batch")]
    TrailingBytes,
}

fn validate_values(record: PackedOrder) -> Result<(), PackedOrderError> {
    match record {
        PackedOrder::Submit {
            quantity,
            leverage,
            order_type,
            price,
            ..
        } => {
            if quantity.raw() <= 0 {
                return Err(PackedOrderError::InvalidValue("quantity must be positive"));
            }
            if leverage.raw() <= 0 {
                return Err(PackedOrderError::InvalidValue("leverage must be positive"));
            }
            if !matches!(order_type, OrderType::Market) && price.raw() <= 0 {
                return Err(PackedOrderError::InvalidValue(
                    "limit price must be positive",
                ));
            }
        }
        PackedOrder::Cancel { order_id, .. } | PackedOrder::Replace { order_id, .. }
            if order_id.get() == 0 =>
        {
            return Err(PackedOrderError::InvalidValue("order_id must be nonzero"));
        }
        PackedOrder::Replace {
            new_price,
            new_quantity,
            ..
        } if new_price.raw() <= 0 || new_quantity.raw() <= 0 => {
            return Err(PackedOrderError::InvalidValue(
                "replacement price and quantity must be positive",
            ));
        }
        _ => {}
    }
    Ok(())
}

const fn side_bits(side: Side) -> u8 {
    match side {
        Side::Bid => 0,
        Side::Ask => 1,
    }
}

const fn order_type_bits(kind: OrderType) -> u8 {
    match kind {
        OrderType::Limit => 0,
        OrderType::Market => 1,
        OrderType::PostOnly => 2,
        OrderType::ReduceOnly => 3,
    }
}

const fn tif_bits(tif: TimeInForce) -> u8 {
    match tif {
        TimeInForce::Gtc => 0,
        TimeInForce::Ioc => 1,
        TimeInForce::Fok => 2,
    }
}

fn decode_side(v: u8) -> Result<Side, PackedOrderError> {
    match v {
        0 => Ok(Side::Bid),
        1 => Ok(Side::Ask),
        _ => Err(PackedOrderError::InvalidValue("side")),
    }
}

fn decode_order_type(v: u8) -> Result<OrderType, PackedOrderError> {
    match v {
        0 => Ok(OrderType::Limit),
        1 => Ok(OrderType::Market),
        2 => Ok(OrderType::PostOnly),
        3 => Ok(OrderType::ReduceOnly),
        _ => Err(PackedOrderError::InvalidValue("order_type")),
    }
}

fn decode_tif(v: u8) -> Result<TimeInForce, PackedOrderError> {
    match v {
        0 => Ok(TimeInForce::Gtc),
        1 => Ok(TimeInForce::Ioc),
        2 => Ok(TimeInForce::Fok),
        _ => Err(PackedOrderError::InvalidValue("time_in_force")),
    }
}

fn put_u16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::KeyPair;
    use sha2::Digest;

    fn submit(session_ref: u32, nonce: u64) -> PackedOrder {
        PackedOrder::Submit {
            session_ref,
            nonce,
            client_id: nonce,
            account: AccountId::new(7),
            market: MarketId::new(9),
            side: Side::Ask,
            order_type: OrderType::PostOnly,
            price: Price::from_raw(12_345_678),
            quantity: Quantity::from_raw(9_876_543),
            time_in_force: TimeInForce::Gtc,
            leverage: Ratio::from_raw(2_000_000),
        }
    }

    fn encode(record: PackedOrder) -> Vec<u8> {
        let mut buf = vec![0u8; record.encoded_len()];
        let n = record.encode_into(&mut buf).unwrap();
        buf.truncate(n);
        buf
    }

    #[test]
    fn all_record_kinds_round_trip_and_borrow_input() {
        let records = [
            submit(3, 10),
            PackedOrder::Cancel {
                session_ref: 3,
                nonce: 11,
                client_id: 91,
                account: AccountId::new(7),
                market: MarketId::new(9),
                order_id: OrderId::new(55),
            },
            PackedOrder::Replace {
                session_ref: 3,
                nonce: 12,
                client_id: 92,
                account: AccountId::new(7),
                market: MarketId::new(9),
                order_id: OrderId::new(55),
                new_price: Price::from_raw(99),
                new_quantity: Quantity::from_raw(88),
            },
        ];
        for record in records {
            let bytes = encode(record);
            let (view, n) = PackedOrder::decode_ref(&bytes).unwrap();
            assert_eq!(n, bytes.len());
            assert_eq!(view.record(), record);
            assert!(std::ptr::eq(view.raw(), bytes.as_slice()));
        }
    }

    #[test]
    fn every_strict_truncation_is_rejected() {
        for record in [
            submit(1, 1),
            PackedOrder::Cancel {
                session_ref: 1,
                nonce: 2,
                client_id: 2,
                account: AccountId::new(1),
                market: MarketId::new(1),
                order_id: OrderId::new(1),
            },
            PackedOrder::Replace {
                session_ref: 1,
                nonce: 3,
                client_id: 3,
                account: AccountId::new(1),
                market: MarketId::new(1),
                order_id: OrderId::new(1),
                new_price: Price::from_raw(1),
                new_quantity: Quantity::from_raw(1),
            },
        ] {
            let bytes = encode(record);
            for end in 0..bytes.len() {
                assert_eq!(
                    PackedOrder::decode_ref(&bytes[..end]),
                    Err(PackedOrderError::Truncated),
                    "prefix {end}"
                );
            }
        }
    }

    #[test]
    fn maximum_integer_fields_round_trip_without_truncation() {
        let record = PackedOrder::Replace {
            session_ref: u32::MAX,
            nonce: u64::MAX,
            client_id: u64::MAX - 1,
            account: AccountId::new(u32::MAX),
            market: MarketId::new(u32::MAX),
            order_id: OrderId::new(u64::MAX),
            new_price: Price::from_raw(i64::MAX),
            new_quantity: Quantity::from_raw(i64::MAX),
        };
        let bytes = encode(record);
        let (decoded, consumed) = PackedOrder::decode_ref(&bytes).unwrap();
        assert_eq!(decoded.record(), record);
        assert_eq!(consumed, PACKED_REPLACE_LEN);
    }

    #[test]
    fn malformed_tags_lengths_flags_and_values_fail_typed() {
        let bytes = encode(submit(1, 1));
        let mut bad = bytes.clone();
        bad[0] = 2;
        assert_eq!(
            PackedOrder::decode_ref(&bad),
            Err(PackedOrderError::UnsupportedVersion(2))
        );
        bad = bytes.clone();
        bad[1] = 99;
        assert_eq!(
            PackedOrder::decode_ref(&bad),
            Err(PackedOrderError::UnknownTag(99))
        );
        bad = bytes.clone();
        bad[2] -= 1;
        assert!(matches!(
            PackedOrder::decode_ref(&bad),
            Err(PackedOrderError::InvalidLength { .. })
        ));
        bad = bytes.clone();
        bad[3] |= 0x80;
        assert!(matches!(
            PackedOrder::decode_ref(&bad),
            Err(PackedOrderError::ReservedBits(_))
        ));
        bad = bytes;
        bad[3] = (3 << 3) | (bad[3] & 0b111);
        assert_eq!(
            PackedOrder::decode_ref(&bad),
            Err(PackedOrderError::InvalidValue("time_in_force"))
        );
    }

    #[test]
    fn workload_mean_is_below_eighty_bytes_with_all_per_order_material() {
        let total = PACKED_SUBMIT_LEN * 7 + PACKED_CANCEL_LEN * 2 + PACKED_REPLACE_LEN;
        assert_eq!(total, 528);
        assert!(total < 80 * 10);
        assert_eq!(PACKED_SUBMIT_LEN, 56);
        assert_eq!(PACKED_CANCEL_LEN, 40);
        assert_eq!(PACKED_REPLACE_LEN, 56);
    }

    #[test]
    fn scalar_and_vector_batches_are_byte_and_error_identical() {
        for count in [32usize, 64, 128] {
            let records: Vec<PackedOrder> = (0..count)
                .map(|i| match i % 10 {
                    0..=6 => submit(7, u64::try_from(i + 1).unwrap()),
                    7..=8 => PackedOrder::Cancel {
                        session_ref: 7,
                        nonce: u64::try_from(i + 1).unwrap(),
                        client_id: u64::try_from(i + 101).unwrap(),
                        account: AccountId::new(7),
                        market: MarketId::new(9),
                        order_id: OrderId::new(u64::try_from(i + 1).unwrap()),
                    },
                    _ => PackedOrder::Replace {
                        session_ref: 7,
                        nonce: u64::try_from(i + 1).unwrap(),
                        client_id: u64::try_from(i + 101).unwrap(),
                        account: AccountId::new(7),
                        market: MarketId::new(9),
                        order_id: OrderId::new(u64::try_from(i + 1).unwrap()),
                        new_price: Price::from_raw(99),
                        new_quantity: Quantity::from_raw(88),
                    },
                })
                .collect();
            let mut scalar_storage = vec![0u8; count * PACKED_SUBMIT_LEN + 1];
            let scalar_len = encode_batch_with_backend(
                &records,
                simd::Backend::Scalar,
                &mut scalar_storage[1..],
            )
            .unwrap();
            for backend in [
                simd::Backend::Scalar,
                simd::Backend::Avx2,
                simd::Backend::Avx512,
                simd::Backend::Neon,
            ] {
                let mut encoded = vec![0u8; count * PACKED_SUBMIT_LEN + 1];
                let n = encode_batch_with_backend(&records, backend, &mut encoded[1..]).unwrap();
                assert_eq!(n, scalar_len);
                assert_eq!(&encoded[1..=n], &scalar_storage[1..=scalar_len]);

                let mut decoded = vec![submit(1, 1); count];
                assert_eq!(
                    decode_batch_with_backend(&encoded[1..=n], backend, &mut decoded),
                    Ok(n),
                );
                assert_eq!(decoded, records);

                let mut truncated = vec![submit(1, 1); count];
                assert_eq!(
                    decode_batch_with_backend(&encoded[1..n], backend, &mut truncated),
                    Err(PackedOrderError::Truncated),
                );
                let mut bad = encoded[1..=n].to_vec();
                bad[3] |= 0x80;
                let mut rejected = vec![submit(1, 1); count];
                assert!(matches!(
                    decode_batch_with_backend(&bad, backend, &mut rejected),
                    Err(PackedOrderError::ReservedBits(_))
                ));
            }
        }
    }

    #[test]
    fn batch_count_and_trailing_bytes_fail_closed() {
        let records = vec![submit(1, 1); 31];
        let mut bytes = vec![0u8; 32 * PACKED_SUBMIT_LEN + 1];
        assert_eq!(
            encode_batch_into(&records, &mut bytes),
            Err(PackedOrderError::BatchSizeOutOfRange(31))
        );
        let records = vec![submit(1, 1); 32];
        let n = encode_batch_into(&records, &mut bytes).unwrap();
        bytes[n] = 1;
        let mut decoded = vec![submit(1, 1); 32];
        assert_eq!(
            decode_batch_into(&bytes[..=n], &mut decoded),
            Err(PackedOrderError::TrailingBytes)
        );
    }

    #[test]
    fn packed_decode_never_panics_on_arbitrary_bytes() {
        let mut state = 0x5eed_cafe_d00d_f00du64;
        for len in 0..=256usize {
            let mut bytes = vec![0u8; len];
            for byte in &mut bytes {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *byte = state.to_le_bytes()[0];
            }
            for backend in [
                simd::Backend::Scalar,
                simd::Backend::Avx2,
                simd::Backend::Avx512,
                simd::Backend::Neon,
            ] {
                let _ = PackedOrder::decode_ref_with_backend(backend, &bytes);
            }
        }
    }

    #[test]
    fn golden_bytes_and_digest_are_stable() {
        let bytes = encode(submit(0x0102_0304, 0x0506_0708_090a_0b0c));
        assert_eq!(
            hex(&bytes),
            "01013805040302010c0b0a09080706050c0b0a090807060507000000090000004e61bc00000000003fb496000000000080841e0000000000"
        );
        let digest = sha2::Sha256::digest(&bytes);
        assert_eq!(
            hex(&digest),
            "92d538f543c319787c40a40e965d573705ef184c1472db03ec139080b57f8e55"
        );
    }

    #[test]
    fn batch_auth_binds_order_session_sequence_and_target() {
        let a = encode(submit(7, 1));
        let b = encode(submit(7, 2));
        let mut records = Vec::new();
        records.extend_from_slice(&a);
        records.extend_from_slice(&b);
        let binding = PackedBatchBinding {
            session_ref: 7,
            batch_sequence: 42,
            target_shard: 3,
            record_count: 2,
        };
        let mut preimage = vec![0u8; 256];
        let n = batch_auth_preimage_into(binding, &records, &mut preimage).unwrap();
        preimage.truncate(n);
        let kp = KeyPair::from_seed(&[9u8; 32]);
        let signature = kp.sign(&preimage);
        assert!(crypto::verify_ed25519(&kp.public(), &preimage, &signature).is_ok());

        let mut reordered = Vec::new();
        reordered.extend_from_slice(&b);
        reordered.extend_from_slice(&a);
        let mut changed = vec![0u8; 256];
        let m = batch_auth_preimage_into(binding, &reordered, &mut changed).unwrap();
        assert!(crypto::verify_ed25519(&kp.public(), &changed[..m], &signature).is_err());

        let redirected = PackedBatchBinding {
            target_shard: 4,
            ..binding
        };
        let m = batch_auth_preimage_into(redirected, &records, &mut changed).unwrap();
        assert!(crypto::verify_ed25519(&kp.public(), &changed[..m], &signature).is_err());

        let replayed = PackedBatchBinding {
            batch_sequence: binding.batch_sequence + 1,
            ..binding
        };
        let m = batch_auth_preimage_into(replayed, &records, &mut changed).unwrap();
        assert!(crypto::verify_ed25519(&kp.public(), &changed[..m], &signature).is_err());

        let rebound = PackedBatchBinding {
            session_ref: binding.session_ref + 1,
            ..binding
        };
        assert_eq!(
            batch_auth_preimage_into(rebound, &records, &mut changed),
            Err(PackedOrderError::SessionMismatch)
        );

        // Detaching either record makes the declared count disagree before an
        // authenticator can be checked; no valid prefix is partially admitted.
        assert_eq!(
            batch_auth_preimage_into(binding, &a, &mut changed),
            Err(PackedOrderError::RecordCountMismatch {
                declared: 2,
                actual: 1,
            })
        );
    }

    #[test]
    fn negotiation_and_session_mismatch_fail_closed() {
        assert_eq!(negotiate_packed_order_version(1, 1), Ok(1));
        assert!(negotiate_packed_order_version(2, 3).is_err());
        let bytes = encode(submit(8, 1));
        let mut out = [0u8; 128];
        assert_eq!(
            batch_auth_preimage_into(
                PackedBatchBinding {
                    session_ref: 7,
                    batch_sequence: 1,
                    target_shard: 0,
                    record_count: 1,
                },
                &bytes,
                &mut out,
            ),
            Err(PackedOrderError::SessionMismatch)
        );
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let _ = write!(out, "{byte:02x}");
        }
        out
    }
}

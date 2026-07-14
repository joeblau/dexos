//! Session-authenticated wrapper for packed/LZ4 order batches.
//!
//! The inner [`crate::OrderBatchCodec`] supplies bounded framing, compression,
//! integrity, and record validation. This outer wrapper amortizes one Ed25519
//! signature over the complete ordered batch while binding it to an established
//! session, account, destination, batch sequence, and canonical command sequence.

use crypto::{verify_ed25519, CryptoError, KeyPair};
use types::AccountId;

use crate::{
    DecodedOrderBatch, Frame, OrderBatchCodec, OrderBatchError, TrafficClass, ORDER_BATCH_MAX_WIRE,
};

const MAGIC: [u8; 4] = *b"DXOB";
/// Initial authenticated packed-batch wrapper version.
pub const AUTHENTICATED_ORDER_BATCH_VERSION: u8 = 1;
/// Signed bytes before the inner order-batch envelope.
pub const AUTHENTICATED_ORDER_BATCH_HEADER_LEN: usize = 100;
/// Fixed Ed25519 signature suffix.
pub const AUTHENTICATED_ORDER_BATCH_SIGNATURE_LEN: usize = 64;
/// Strict maximum authenticated wire length.
pub const AUTHENTICATED_ORDER_BATCH_MAX_WIRE: usize = AUTHENTICATED_ORDER_BATCH_HEADER_LEN
    + ORDER_BATCH_MAX_WIRE
    + AUTHENTICATED_ORDER_BATCH_SIGNATURE_LEN;

/// Fields cryptographically bound to every record in one packed batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderBatchBinding {
    /// Node/shard destination identity. Redirecting bytes changes the preimage.
    pub destination: [u8; 32],
    /// Connection-established session reference repeated by every packed record.
    pub session_ref: u32,
    /// Authorized account repeated by every packed record.
    pub account: AccountId,
    /// Strict per-session batch sequence used for replay/reorder rejection.
    pub batch_sequence: u64,
    /// Canonical sequencer number allocated to the first record.
    pub first_sequence: u64,
}

/// Reusable, bounded authenticated-batch encoder.
pub struct AuthenticatedOrderBatchCodec {
    inner: OrderBatchCodec,
    wire: Vec<u8>,
}

impl AuthenticatedOrderBatchCodec {
    /// Allocate the compression table and maximum wire buffer once at startup.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: OrderBatchCodec::new(),
            wire: vec![0; AUTHENTICATED_ORDER_BATCH_MAX_WIRE],
        }
    }

    /// Encode, compress, bind, and sign one complete record sequence.
    pub fn encode(
        &mut self,
        binding: OrderBatchBinding,
        signer: &KeyPair,
        record_count: u8,
        partial: bool,
        records: &[u8],
    ) -> Result<EncodedAuthenticatedOrderBatch<'_>, AuthenticatedOrderBatchError> {
        let inner = self.inner.encode(record_count, partial, records)?;
        let inner_len = inner.bytes.len();
        write_header(
            &mut self.wire[..AUTHENTICATED_ORDER_BATCH_HEADER_LEN],
            binding,
            signer.public(),
            inner_len,
        )?;
        let body_end = AUTHENTICATED_ORDER_BATCH_HEADER_LEN
            .checked_add(inner_len)
            .ok_or(AuthenticatedOrderBatchError::LengthOutOfRange)?;
        self.wire[AUTHENTICATED_ORDER_BATCH_HEADER_LEN..body_end].copy_from_slice(inner.bytes);
        let signature = signer.sign(&self.wire[..body_end]);
        let end = body_end
            .checked_add(AUTHENTICATED_ORDER_BATCH_SIGNATURE_LEN)
            .ok_or(AuthenticatedOrderBatchError::LengthOutOfRange)?;
        self.wire[body_end..end].copy_from_slice(&signature);
        Ok(EncodedAuthenticatedOrderBatch {
            bytes: &self.wire[..end],
            binding,
            signer: signer.public(),
            record_count,
            partial,
        })
    }

    /// Parse strict bounds and verify the outer signature and destination binding.
    pub fn verify<'a>(
        bytes: &'a [u8],
        expected_destination: &[u8; 32],
    ) -> Result<VerifiedAuthenticatedOrderBatch<'a>, AuthenticatedOrderBatchError> {
        let header = parse_header(bytes)?;
        if &header.binding.destination != expected_destination {
            return Err(AuthenticatedOrderBatchError::WrongDestination);
        }
        let body_end = AUTHENTICATED_ORDER_BATCH_HEADER_LEN
            .checked_add(header.inner_len)
            .ok_or(AuthenticatedOrderBatchError::LengthOutOfRange)?;
        let end = body_end
            .checked_add(AUTHENTICATED_ORDER_BATCH_SIGNATURE_LEN)
            .ok_or(AuthenticatedOrderBatchError::LengthOutOfRange)?;
        if end != bytes.len() {
            return Err(if end > bytes.len() {
                AuthenticatedOrderBatchError::Truncated
            } else {
                AuthenticatedOrderBatchError::TrailingBytes
            });
        }
        let signature: [u8; 64] = bytes[body_end..end]
            .try_into()
            .map_err(|_| AuthenticatedOrderBatchError::Truncated)?;
        verify_ed25519(&header.signer, &bytes[..body_end], &signature)
            .map_err(AuthenticatedOrderBatchError::Signature)?;
        Ok(VerifiedAuthenticatedOrderBatch {
            binding: header.binding,
            signer: header.signer,
            envelope: &bytes[AUTHENTICATED_ORDER_BATCH_HEADER_LEN..body_end],
        })
    }
}

/// Strictly parsed but not signature-verified routing fields.
///
/// Callers may use only `session_ref` to select a trusted session. Every field
/// remains untrusted until [`AuthenticatedOrderBatchCodec::verify`] succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedOrderBatchHeader {
    pub binding: OrderBatchBinding,
    pub signer: [u8; 32],
}

/// Inspect the bounded outer header and exact wrapper length without performing
/// signature verification. This is the fail-closed routing seam for a bounded
/// multi-session registry; selected sessions must still verify the full wrapper.
pub fn inspect_authenticated_order_batch(
    bytes: &[u8],
) -> Result<AuthenticatedOrderBatchHeader, AuthenticatedOrderBatchError> {
    let header = parse_header(bytes)?;
    let body_end = AUTHENTICATED_ORDER_BATCH_HEADER_LEN
        .checked_add(header.inner_len)
        .ok_or(AuthenticatedOrderBatchError::LengthOutOfRange)?;
    let end = body_end
        .checked_add(AUTHENTICATED_ORDER_BATCH_SIGNATURE_LEN)
        .ok_or(AuthenticatedOrderBatchError::LengthOutOfRange)?;
    if end != bytes.len() {
        return Err(if end > bytes.len() {
            AuthenticatedOrderBatchError::Truncated
        } else {
            AuthenticatedOrderBatchError::TrailingBytes
        });
    }
    Ok(AuthenticatedOrderBatchHeader {
        binding: header.binding,
        signer: header.signer,
    })
}

impl Default for AuthenticatedOrderBatchCodec {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify the transport lane and signed wrapper, then decode the inner records
/// into caller-owned bounded scratch.
pub fn decode_authenticated_order_batch_frame_into<'a>(
    frame: &'a Frame,
    expected_destination: &[u8; 32],
    output: &'a mut [u8],
) -> Result<DecodedOrderBatch<'a>, AuthenticatedOrderBatchFrameError> {
    if frame.class != TrafficClass::NewOrder {
        return Err(AuthenticatedOrderBatchFrameError::WrongTrafficClass);
    }
    if frame.msg_type != crate::MSG_TYPE_ORDER_BATCH {
        return Err(AuthenticatedOrderBatchFrameError::WrongMessageType);
    }
    let verified = AuthenticatedOrderBatchCodec::verify(&frame.payload, expected_destination)?;
    OrderBatchCodec::decode_into(verified.envelope, output).map_err(Into::into)
}

/// Borrowed encoded result backed by the reusable encoder buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedAuthenticatedOrderBatch<'a> {
    pub bytes: &'a [u8],
    pub binding: OrderBatchBinding,
    pub signer: [u8; 32],
    pub record_count: u8,
    pub partial: bool,
}

/// Signature-verified wrapper. The inner envelope remains borrowed and is decoded
/// exactly once by shard admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedAuthenticatedOrderBatch<'a> {
    pub binding: OrderBatchBinding,
    pub signer: [u8; 32],
    pub envelope: &'a [u8],
}

/// Strict single-session replay/sequence state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderBatchReplayGuard {
    next_batch_sequence: u64,
    next_first_sequence: u64,
    batch_sequence_stride: u64,
    command_sequence_stride: u64,
}

impl OrderBatchReplayGuard {
    #[must_use]
    pub const fn new(next_batch_sequence: u64, next_first_sequence: u64) -> Self {
        Self {
            next_batch_sequence,
            next_first_sequence,
            batch_sequence_stride: 1,
            command_sequence_stride: 0,
        }
    }

    /// Construct a striped replay domain. A zero command stride retains the
    /// legacy contiguous behavior (`record_count`). Otherwise
    /// `command_sequence_stride / batch_sequence_stride` defines the exact
    /// fixed record count for every batch in this replay domain.
    #[must_use]
    pub const fn with_strides(
        next_batch_sequence: u64,
        next_first_sequence: u64,
        batch_sequence_stride: u64,
        command_sequence_stride: u64,
    ) -> Self {
        Self {
            next_batch_sequence,
            next_first_sequence,
            batch_sequence_stride,
            command_sequence_stride,
        }
    }

    /// Check without consuming state. This permits an identical retry after bounded
    /// shard backpressure while still rejecting replay after successful admission.
    pub fn check(&self, binding: &OrderBatchBinding) -> Result<(), AuthenticatedOrderBatchError> {
        if binding.batch_sequence != self.next_batch_sequence {
            return Err(AuthenticatedOrderBatchError::BatchSequence {
                expected: self.next_batch_sequence,
                actual: binding.batch_sequence,
            });
        }
        if binding.first_sequence != self.next_first_sequence {
            return Err(AuthenticatedOrderBatchError::CommandSequence {
                expected: self.next_first_sequence,
                actual: binding.first_sequence,
            });
        }
        Ok(())
    }

    /// Check identity and both post-admission sequence advances before any command
    /// is published to a shard ring.
    pub fn check_admission(
        &self,
        binding: &OrderBatchBinding,
        record_count: u8,
    ) -> Result<(), AuthenticatedOrderBatchError> {
        self.check(binding)?;
        if self.batch_sequence_stride == 0 {
            return Err(AuthenticatedOrderBatchError::InvalidSequenceStride);
        }
        if self.command_sequence_stride != 0 {
            if !self
                .command_sequence_stride
                .is_multiple_of(self.batch_sequence_stride)
            {
                return Err(AuthenticatedOrderBatchError::InvalidSequenceStride);
            }
            let expected = self.command_sequence_stride / self.batch_sequence_stride;
            if expected == 0 || expected > 128 {
                return Err(AuthenticatedOrderBatchError::InvalidSequenceStride);
            }
            if u64::from(record_count) != expected {
                return Err(AuthenticatedOrderBatchError::BatchWidth {
                    expected,
                    actual: record_count,
                });
            }
        }
        self.next_batch_sequence
            .checked_add(self.batch_sequence_stride)
            .ok_or(AuthenticatedOrderBatchError::SequenceExhausted)?;
        self.next_first_sequence
            .checked_add(self.command_advance(record_count))
            .ok_or(AuthenticatedOrderBatchError::SequenceExhausted)?;
        Ok(())
    }

    /// Consume a verified and admitted batch exactly once.
    pub fn commit(
        &mut self,
        binding: &OrderBatchBinding,
        record_count: u8,
    ) -> Result<(), AuthenticatedOrderBatchError> {
        self.check_admission(binding, record_count)?;
        self.next_batch_sequence = self
            .next_batch_sequence
            .checked_add(self.batch_sequence_stride)
            .ok_or(AuthenticatedOrderBatchError::SequenceExhausted)?;
        self.next_first_sequence = self
            .next_first_sequence
            .checked_add(self.command_advance(record_count))
            .ok_or(AuthenticatedOrderBatchError::SequenceExhausted)?;
        Ok(())
    }

    const fn command_advance(&self, record_count: u8) -> u64 {
        if self.command_sequence_stride == 0 {
            record_count as u64
        } else {
            self.command_sequence_stride
        }
    }

    #[must_use]
    pub const fn next_batch_sequence(&self) -> u64 {
        self.next_batch_sequence
    }

    #[must_use]
    pub const fn next_first_sequence(&self) -> u64 {
        self.next_first_sequence
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    binding: OrderBatchBinding,
    signer: [u8; 32],
    inner_len: usize,
}

fn write_header(
    output: &mut [u8],
    binding: OrderBatchBinding,
    signer: [u8; 32],
    inner_len: usize,
) -> Result<(), AuthenticatedOrderBatchError> {
    let output = output
        .get_mut(..AUTHENTICATED_ORDER_BATCH_HEADER_LEN)
        .ok_or(AuthenticatedOrderBatchError::Truncated)?;
    if inner_len == 0 || inner_len > ORDER_BATCH_MAX_WIRE {
        return Err(AuthenticatedOrderBatchError::LengthOutOfRange);
    }
    output.fill(0);
    output[0..4].copy_from_slice(&MAGIC);
    output[4] = AUTHENTICATED_ORDER_BATCH_VERSION;
    output[8..40].copy_from_slice(&binding.destination);
    output[40..44].copy_from_slice(&binding.session_ref.to_le_bytes());
    output[44..48].copy_from_slice(&binding.account.get().to_le_bytes());
    output[48..56].copy_from_slice(&binding.batch_sequence.to_le_bytes());
    output[56..64].copy_from_slice(&binding.first_sequence.to_le_bytes());
    output[64..96].copy_from_slice(&signer);
    output[96..100].copy_from_slice(
        &u32::try_from(inner_len)
            .map_err(|_| AuthenticatedOrderBatchError::LengthOutOfRange)?
            .to_le_bytes(),
    );
    Ok(())
}

fn parse_header(bytes: &[u8]) -> Result<Header, AuthenticatedOrderBatchError> {
    let h = bytes
        .get(..AUTHENTICATED_ORDER_BATCH_HEADER_LEN)
        .ok_or(AuthenticatedOrderBatchError::Truncated)?;
    if h[0..4] != MAGIC {
        return Err(AuthenticatedOrderBatchError::BadMagic);
    }
    if h[4] != AUTHENTICATED_ORDER_BATCH_VERSION {
        return Err(AuthenticatedOrderBatchError::UnsupportedVersion(h[4]));
    }
    if h[5..8] != [0; 3] {
        return Err(AuthenticatedOrderBatchError::ReservedHeader);
    }
    let inner_len = u32::from_le_bytes(h[96..100].try_into().unwrap_or([0; 4])) as usize;
    if inner_len == 0 || inner_len > ORDER_BATCH_MAX_WIRE {
        return Err(AuthenticatedOrderBatchError::LengthOutOfRange);
    }
    Ok(Header {
        binding: OrderBatchBinding {
            destination: h[8..40].try_into().unwrap_or([0; 32]),
            session_ref: u32::from_le_bytes(h[40..44].try_into().unwrap_or([0; 4])),
            account: AccountId::new(u32::from_le_bytes(h[44..48].try_into().unwrap_or([0; 4]))),
            batch_sequence: u64::from_le_bytes(h[48..56].try_into().unwrap_or([0; 8])),
            first_sequence: u64::from_le_bytes(h[56..64].try_into().unwrap_or([0; 8])),
        },
        signer: h[64..96].try_into().unwrap_or([0; 32]),
        inner_len,
    })
}

/// Authenticated wrapper validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthenticatedOrderBatchError {
    #[error("invalid inner order batch: {0}")]
    Inner(#[from] OrderBatchError),
    #[error("authenticated order batch is truncated")]
    Truncated,
    #[error("bad authenticated order batch magic")]
    BadMagic,
    #[error("unsupported authenticated order batch version {0}")]
    UnsupportedVersion(u8),
    #[error("authenticated order batch reserved header bytes are nonzero")]
    ReservedHeader,
    #[error("authenticated order batch length is out of range")]
    LengthOutOfRange,
    #[error("authenticated order batch has trailing bytes")]
    TrailingBytes,
    #[error("authenticated order batch targets another destination")]
    WrongDestination,
    #[error("authenticated order batch signature failed: {0}")]
    Signature(CryptoError),
    #[error("batch sequence mismatch: expected {expected}, got {actual}")]
    BatchSequence { expected: u64, actual: u64 },
    #[error("command sequence mismatch: expected {expected}, got {actual}")]
    CommandSequence { expected: u64, actual: u64 },
    #[error("authenticated order batch sequence exhausted")]
    SequenceExhausted,
    #[error("authenticated order batch sequence stride is invalid")]
    InvalidSequenceStride,
    #[error("authenticated order batch width mismatch: expected {expected}, got {actual}")]
    BatchWidth { expected: u64, actual: u8 },
}

/// Failure across transport-lane, signature, and inner-envelope validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthenticatedOrderBatchFrameError {
    #[error("frame is not on the reliable new-order traffic class")]
    WrongTrafficClass,
    #[error("frame is not a packed-order batch message")]
    WrongMessageType,
    #[error(transparent)]
    Authentication(#[from] AuthenticatedOrderBatchError),
    #[error(transparent)]
    Inner(#[from] OrderBatchError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{encode_batch_into, PackedOrder, PACKED_SUBMIT_LEN};
    use types::{MarketId, OrderType, Price, Quantity, Ratio, Side, TimeInForce};

    fn records() -> Vec<PackedOrder> {
        (0..32)
            .map(|index| PackedOrder::Submit {
                session_ref: 7,
                nonce: index + 1,
                client_id: index + 100,
                account: AccountId::new(9),
                market: MarketId::new(2),
                side: Side::Bid,
                order_type: OrderType::Limit,
                price: Price::from_raw(10),
                quantity: Quantity::from_raw(20),
                time_in_force: TimeInForce::Gtc,
                leverage: Ratio::from_raw(1_000_000),
            })
            .collect()
    }

    fn binding(batch: u64, first: u64) -> OrderBatchBinding {
        OrderBatchBinding {
            destination: [3; 32],
            session_ref: 7,
            account: AccountId::new(9),
            batch_sequence: batch,
            first_sequence: first,
        }
    }

    #[test]
    fn signature_binds_body_identity_destination_and_order() {
        let records = records();
        let mut packed = vec![0; records.len() * PACKED_SUBMIT_LEN];
        let len = encode_batch_into(&records, &mut packed).unwrap();
        let signer = KeyPair::from_seed(&[8; 32]);
        let mut codec = AuthenticatedOrderBatchCodec::new();
        let encoded = codec
            .encode(binding(4, 100), &signer, 32, false, &packed[..len])
            .unwrap();
        let verified = AuthenticatedOrderBatchCodec::verify(encoded.bytes, &[3; 32]).unwrap();
        assert_eq!(verified.binding, binding(4, 100));
        assert_eq!(verified.signer, signer.public());

        let mut tampered = encoded.bytes.to_vec();
        tampered[AUTHENTICATED_ORDER_BATCH_HEADER_LEN + 3] ^= 1;
        assert!(matches!(
            AuthenticatedOrderBatchCodec::verify(&tampered, &[3; 32]),
            Err(AuthenticatedOrderBatchError::Signature(_))
        ));
        assert_eq!(
            AuthenticatedOrderBatchCodec::verify(encoded.bytes, &[4; 32]),
            Err(AuthenticatedOrderBatchError::WrongDestination)
        );
    }

    #[test]
    fn replay_guard_rejects_replay_reorder_and_sequence_gaps() {
        let mut guard = OrderBatchReplayGuard::new(4, 100);
        guard.check(&binding(4, 100)).unwrap();
        guard.commit(&binding(4, 100), 32).unwrap();
        assert_eq!(guard.next_batch_sequence(), 5);
        assert_eq!(guard.next_first_sequence(), 132);
        assert!(matches!(
            guard.check(&binding(4, 100)),
            Err(AuthenticatedOrderBatchError::BatchSequence { .. })
        ));
        assert!(matches!(
            guard.check(&binding(6, 132)),
            Err(AuthenticatedOrderBatchError::BatchSequence { .. })
        ));
        assert!(matches!(
            guard.check(&binding(5, 133)),
            Err(AuthenticatedOrderBatchError::CommandSequence { .. })
        ));
    }

    #[test]
    fn striped_replay_guard_advances_by_server_issued_strides() {
        let mut guard = OrderBatchReplayGuard::with_strides(4, 100, 3, 96);
        for actual in std::iter::once(31u8).chain(33..=64) {
            assert_eq!(
                guard.check_admission(&binding(4, 100), actual),
                Err(AuthenticatedOrderBatchError::BatchWidth {
                    expected: 32,
                    actual,
                })
            );
            assert_eq!(guard.next_batch_sequence(), 4);
            assert_eq!(guard.next_first_sequence(), 100);
        }
        guard.commit(&binding(4, 100), 32).unwrap();
        assert_eq!(guard.next_batch_sequence(), 7);
        assert_eq!(guard.next_first_sequence(), 196);
        guard.commit(&binding(7, 196), 32).unwrap();
        assert_eq!(guard.next_batch_sequence(), 10);
        assert_eq!(guard.next_first_sequence(), 292);

        let non_integral_stride = OrderBatchReplayGuard::with_strides(4, 100, 3, 95);
        assert_eq!(
            non_integral_stride.check_admission(&binding(4, 100), 32),
            Err(AuthenticatedOrderBatchError::InvalidSequenceStride)
        );

        // Zero remains the protocol's legacy contiguous mode. Validator packed
        // execution applies its stricter full-batch receipt policy separately.
        let dynamic = OrderBatchReplayGuard::new(4, 100);
        dynamic.check_admission(&binding(4, 100), 1).unwrap();
    }

    #[test]
    fn routing_header_is_bounded_but_remains_untrusted() {
        let records = records();
        let mut packed = vec![0; records.len() * PACKED_SUBMIT_LEN];
        let len = encode_batch_into(&records, &mut packed).unwrap();
        let signer = KeyPair::from_seed(&[8; 32]);
        let mut codec = AuthenticatedOrderBatchCodec::new();
        let bytes = codec
            .encode(binding(4, 100), &signer, 32, false, &packed[..len])
            .unwrap()
            .bytes
            .to_vec();
        let inspected = inspect_authenticated_order_batch(&bytes).unwrap();
        assert_eq!(inspected.binding, binding(4, 100));
        assert_eq!(inspected.signer, signer.public());
        assert_eq!(
            inspect_authenticated_order_batch(&bytes[..bytes.len() - 1]),
            Err(AuthenticatedOrderBatchError::Truncated)
        );
    }
}

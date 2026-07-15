//! Fixed-size correlated lifecycle receipts for authenticated packed batches.
//!
//! Authenticity comes from the established TLS/peer transport. The payload binds
//! all lifecycle counters to the exact batch and command-sequence range, while
//! strict stage invariants prevent partial or contradictory evidence from being
//! counted as admitted, executed, or finalized throughput.

use crate::{Frame, TrafficClass, MSG_TYPE_ORDER_BATCH_RECEIPT};

const MAGIC: [u8; 4] = *b"DXBR";
/// Initial packed-batch receipt version.
pub const ORDER_BATCH_RECEIPT_VERSION: u8 = 1;
/// Fixed v1 receipt payload length.
pub const ORDER_BATCH_RECEIPT_LEN: usize = 48;
/// Maximum executed receipts that may await a later finality receipt on one
/// packed client/server deployment.
///
/// The same bound caps server-side finality routes and client-side correlation
/// history. Keeping it in the wire-owning crate prevents either side from
/// silently evicting evidence that the other side may still validly deliver.
pub const MAX_PENDING_ORDER_BATCH_FINALITY: usize = 65_536;
const FLAG_CHECKPOINT: u8 = 1;

/// Highest lifecycle boundary evidenced by this cumulative receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OrderBatchReceiptStage {
    Admitted = 1,
    Executed = 2,
    Finalized = 3,
    Rejected = 4,
}

impl OrderBatchReceiptStage {
    fn from_u8(value: u8) -> Result<Self, OrderBatchReceiptError> {
        match value {
            1 => Ok(Self::Admitted),
            2 => Ok(Self::Executed),
            3 => Ok(Self::Finalized),
            4 => Ok(Self::Rejected),
            _ => Err(OrderBatchReceiptError::UnknownStage(value)),
        }
    }
}

/// Cumulative lifecycle evidence for one atomically admitted 32-128 record batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderBatchReceipt {
    pub stage: OrderBatchReceiptStage,
    pub record_count: u8,
    pub admitted: u8,
    /// Successfully executed commands.
    pub executed: u8,
    pub finalized: u8,
    /// Commands that reached execution but returned a terminal engine error.
    pub failed: u8,
    /// Nonzero typed reason only for an atomically rejected batch.
    pub rejection_code: u16,
    pub batch_sequence: u64,
    pub first_sequence: u64,
    /// Checkpoint containing every successfully executed command in this batch.
    pub checkpoint_height: Option<u64>,
    /// Target-observed wall-clock timestamp for cross-region latency attribution.
    pub observed_unix_ns: u64,
}

impl OrderBatchReceipt {
    /// Validate stage/count conservation and encode into caller-owned fixed memory.
    pub fn encode_into(&self, output: &mut [u8]) -> Result<(), OrderBatchReceiptError> {
        self.validate()?;
        let output = output
            .get_mut(..ORDER_BATCH_RECEIPT_LEN)
            .ok_or(OrderBatchReceiptError::Truncated)?;
        output.fill(0);
        output[0..4].copy_from_slice(&MAGIC);
        output[4] = ORDER_BATCH_RECEIPT_VERSION;
        output[5] = self.stage as u8;
        output[6] = self.record_count;
        output[7] = self.admitted;
        output[8] = self.executed;
        output[9] = self.finalized;
        output[10] = self.failed;
        if self.checkpoint_height.is_some() {
            output[11] = FLAG_CHECKPOINT;
        }
        output[12..14].copy_from_slice(&self.rejection_code.to_le_bytes());
        output[16..24].copy_from_slice(&self.batch_sequence.to_le_bytes());
        output[24..32].copy_from_slice(&self.first_sequence.to_le_bytes());
        output[32..40].copy_from_slice(&self.checkpoint_height.unwrap_or(0).to_le_bytes());
        output[40..48].copy_from_slice(&self.observed_unix_ns.to_le_bytes());
        Ok(())
    }

    /// Decode an exact v1 receipt and re-run every semantic invariant.
    pub fn decode(bytes: &[u8]) -> Result<Self, OrderBatchReceiptError> {
        if bytes.len() < ORDER_BATCH_RECEIPT_LEN {
            return Err(OrderBatchReceiptError::Truncated);
        }
        if bytes.len() > ORDER_BATCH_RECEIPT_LEN {
            return Err(OrderBatchReceiptError::TrailingBytes);
        }
        if bytes[0..4] != MAGIC {
            return Err(OrderBatchReceiptError::BadMagic);
        }
        if bytes[4] != ORDER_BATCH_RECEIPT_VERSION {
            return Err(OrderBatchReceiptError::UnsupportedVersion(bytes[4]));
        }
        if bytes[11] & !FLAG_CHECKPOINT != 0 || bytes[14..16] != [0; 2] {
            return Err(OrderBatchReceiptError::ReservedBits);
        }
        let has_checkpoint = bytes[11] & FLAG_CHECKPOINT != 0;
        let receipt = Self {
            stage: OrderBatchReceiptStage::from_u8(bytes[5])?,
            record_count: bytes[6],
            admitted: bytes[7],
            executed: bytes[8],
            finalized: bytes[9],
            failed: bytes[10],
            rejection_code: u16::from_le_bytes(bytes[12..14].try_into().unwrap_or([0; 2])),
            batch_sequence: u64::from_le_bytes(bytes[16..24].try_into().unwrap_or([0; 8])),
            first_sequence: u64::from_le_bytes(bytes[24..32].try_into().unwrap_or([0; 8])),
            checkpoint_height: has_checkpoint
                .then(|| u64::from_le_bytes(bytes[32..40].try_into().unwrap_or([0; 8]))),
            observed_unix_ns: u64::from_le_bytes(bytes[40..48].try_into().unwrap_or([0; 8])),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> Result<(), OrderBatchReceiptError> {
        if !(32..=128).contains(&self.record_count) {
            return Err(OrderBatchReceiptError::RecordCount(self.record_count));
        }
        if self.admitted > self.record_count
            || self.executed > self.admitted
            || self.finalized > self.executed
            || self.failed > self.admitted
            || u16::from(self.executed) + u16::from(self.failed) > u16::from(self.admitted)
        {
            return Err(OrderBatchReceiptError::CounterInvariant);
        }
        match self.stage {
            OrderBatchReceiptStage::Admitted
                if self.admitted == self.record_count
                    && self.executed == 0
                    && self.finalized == 0
                    && self.failed == 0
                    && self.rejection_code == 0
                    && self.checkpoint_height.is_none() => {}
            OrderBatchReceiptStage::Executed
                if self.admitted == self.record_count
                    && u16::from(self.executed) + u16::from(self.failed)
                        == u16::from(self.admitted)
                    && self.finalized == 0
                    && self.rejection_code == 0
                    && self.checkpoint_height.is_none() => {}
            OrderBatchReceiptStage::Finalized
                if self.admitted == self.record_count
                    && u16::from(self.executed) + u16::from(self.failed)
                        == u16::from(self.admitted)
                    && self.finalized == self.executed
                    && self.rejection_code == 0
                    && self.checkpoint_height.is_some() => {}
            OrderBatchReceiptStage::Rejected
                if self.admitted == 0
                    && self.executed == 0
                    && self.finalized == 0
                    && self.failed == 0
                    && self.rejection_code != 0
                    && self.checkpoint_height.is_none() => {}
            _ => return Err(OrderBatchReceiptError::StageInvariant),
        }
        Ok(())
    }
}

/// Encode a receipt in its exact execution-receipt transport lane.
pub fn encode_order_batch_receipt_frame(
    receipt: &OrderBatchReceipt,
    sequence: u64,
) -> Result<Frame, OrderBatchReceiptError> {
    let mut payload = vec![0; ORDER_BATCH_RECEIPT_LEN];
    receipt.encode_into(&mut payload)?;
    Ok(Frame {
        class: TrafficClass::ExecutionReceipt,
        msg_type: MSG_TYPE_ORDER_BATCH_RECEIPT,
        sequence,
        payload,
    })
}

/// Verify the receipt transport lane and decode the exact fixed payload.
pub fn decode_order_batch_receipt_frame(
    frame: &Frame,
) -> Result<OrderBatchReceipt, OrderBatchReceiptError> {
    if frame.class != TrafficClass::ExecutionReceipt {
        return Err(OrderBatchReceiptError::WrongTrafficClass);
    }
    if frame.msg_type != MSG_TYPE_ORDER_BATCH_RECEIPT {
        return Err(OrderBatchReceiptError::WrongMessageType);
    }
    OrderBatchReceipt::decode(&frame.payload)
}

/// Malformed, contradictory, or misrouted packed receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OrderBatchReceiptError {
    #[error("packed batch receipt is truncated")]
    Truncated,
    #[error("packed batch receipt has trailing bytes")]
    TrailingBytes,
    #[error("bad packed batch receipt magic")]
    BadMagic,
    #[error("unsupported packed batch receipt version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown packed batch receipt stage {0}")]
    UnknownStage(u8),
    #[error("packed batch receipt reserved bits are nonzero")]
    ReservedBits,
    #[error("packed batch receipt record count {0} is outside 32..=128")]
    RecordCount(u8),
    #[error("packed batch receipt counters do not conserve")]
    CounterInvariant,
    #[error("packed batch receipt contradicts its lifecycle stage")]
    StageInvariant,
    #[error("packed batch receipt is on the wrong traffic class")]
    WrongTrafficClass,
    #[error("packed batch receipt has the wrong message type")]
    WrongMessageType,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finalized() -> OrderBatchReceipt {
        OrderBatchReceipt {
            stage: OrderBatchReceiptStage::Finalized,
            record_count: 128,
            admitted: 128,
            executed: 127,
            finalized: 127,
            failed: 1,
            rejection_code: 0,
            batch_sequence: 9,
            first_sequence: 1_000,
            checkpoint_height: Some(44),
            observed_unix_ns: 55,
        }
    }

    #[test]
    fn fixed_receipt_round_trips_on_exact_lane() {
        let receipt = finalized();
        let frame = encode_order_batch_receipt_frame(&receipt, 3).unwrap();
        assert_eq!(frame.class, TrafficClass::ExecutionReceipt);
        assert_eq!(frame.msg_type, MSG_TYPE_ORDER_BATCH_RECEIPT);
        assert_eq!(frame.payload.len(), ORDER_BATCH_RECEIPT_LEN);
        assert_eq!(decode_order_batch_receipt_frame(&frame), Ok(receipt));
    }

    #[test]
    fn contradictory_stage_counts_and_reserved_bits_fail_closed() {
        let mut bytes = [0; ORDER_BATCH_RECEIPT_LEN];
        finalized().encode_into(&mut bytes).unwrap();
        bytes[9] = 128;
        assert_eq!(
            OrderBatchReceipt::decode(&bytes),
            Err(OrderBatchReceiptError::CounterInvariant)
        );
        finalized().encode_into(&mut bytes).unwrap();
        bytes[14] = 1;
        assert_eq!(
            OrderBatchReceipt::decode(&bytes),
            Err(OrderBatchReceiptError::ReservedBits)
        );
    }

    #[test]
    fn every_stage_has_strict_conservation_rules() {
        let admitted = OrderBatchReceipt {
            stage: OrderBatchReceiptStage::Admitted,
            record_count: 32,
            admitted: 32,
            executed: 0,
            finalized: 0,
            failed: 0,
            rejection_code: 0,
            batch_sequence: 1,
            first_sequence: 2,
            checkpoint_height: None,
            observed_unix_ns: 3,
        };
        let mut bytes = [0; ORDER_BATCH_RECEIPT_LEN];
        assert_eq!(admitted.encode_into(&mut bytes), Ok(()));
        assert_eq!(
            OrderBatchReceipt {
                stage: OrderBatchReceiptStage::Rejected,
                admitted: 0,
                rejection_code: 7,
                ..admitted
            }
            .encode_into(&mut bytes),
            Ok(())
        );
        assert_eq!(
            OrderBatchReceipt {
                stage: OrderBatchReceiptStage::Rejected,
                admitted: 0,
                rejection_code: 0,
                ..admitted
            }
            .encode_into(&mut bytes),
            Err(OrderBatchReceiptError::StageInvariant)
        );
    }
}

//! Bounded correlation from packed admission ranges to execution/finality receipts.

use std::collections::VecDeque;

use network::{OrderBatchReceipt, OrderBatchReceiptStage};

use crate::{PackedBatchAdmission, ShardEffect};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingRange {
    batch_sequence: u64,
    first_sequence: u64,
    record_count: u8,
    processed: u8,
    executed: u8,
    failed: u8,
}

/// Fully validated receipt-tracker mutation, retained across the durable/SPSC
/// admission boundary so no fallible tracker check remains after publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparedBatchReceiptAdmission {
    range: PendingRange,
    next_admission_sequence: u64,
}

impl PreparedBatchReceiptAdmission {
    #[must_use]
    pub(crate) const fn next_admission_sequence(self) -> u64 {
        self.next_admission_sequence
    }
}

/// Preallocated FIFO correlator for globally sequenced batch ranges.
pub struct BatchReceiptTracker {
    pending: VecDeque<PendingRange>,
    capacity: usize,
    next_admission_sequence: Option<u64>,
}

impl BatchReceiptTracker {
    /// Allocate the maximum admitted but incompletely executed batch count.
    pub fn new(capacity: usize) -> Result<Self, BatchReceiptTrackerError> {
        if capacity == 0 {
            return Err(BatchReceiptTrackerError::InvalidCapacity);
        }
        Ok(Self {
            pending: VecDeque::with_capacity(capacity),
            capacity,
            next_admission_sequence: None,
        })
    }

    /// Retain one authenticated admission range for shard-effect correlation.
    pub fn track_admission(
        &mut self,
        admission: PackedBatchAdmission,
    ) -> Result<(), BatchReceiptTrackerError> {
        let prepared = self.prepare_admission(admission)?;
        self.commit_admission(prepared);
        Ok(())
    }

    /// Validate every receipt-tracker constraint without mutating tracker state.
    /// The returned token can be committed only after the batch is durable and
    /// published to the shard owner.
    pub(crate) fn prepare_admission(
        &self,
        admission: PackedBatchAdmission,
    ) -> Result<PreparedBatchReceiptAdmission, BatchReceiptTrackerError> {
        let batch_sequence = admission
            .batch_sequence
            .ok_or(BatchReceiptTrackerError::UnauthenticatedAdmission)?;
        if self.pending.len() >= self.capacity {
            return Err(BatchReceiptTrackerError::Backpressure);
        }
        if !(32..=128).contains(&admission.record_count) {
            return Err(BatchReceiptTrackerError::InvalidAdmissionRange);
        }
        let next = admission
            .first_sequence
            .get()
            .checked_add(u64::from(admission.record_count))
            .ok_or(BatchReceiptTrackerError::SequenceExhausted)?;
        if admission.last_sequence.get() != next - 1 {
            return Err(BatchReceiptTrackerError::InvalidAdmissionRange);
        }
        if let Some(expected) = self.next_admission_sequence {
            if admission.first_sequence.get() != expected {
                return Err(BatchReceiptTrackerError::AdmissionGap {
                    expected,
                    actual: admission.first_sequence.get(),
                });
            }
        }
        Ok(PreparedBatchReceiptAdmission {
            range: PendingRange {
                batch_sequence,
                first_sequence: admission.first_sequence.get(),
                record_count: admission.record_count,
                processed: 0,
                executed: 0,
                failed: 0,
            },
            next_admission_sequence: next,
        })
    }

    /// Apply a token returned by [`Self::prepare_admission`]. Callers keep this
    /// crate-private so tracker state cannot change between prepare and commit.
    pub(crate) fn commit_admission(&mut self, prepared: PreparedBatchReceiptAdmission) {
        debug_assert!(self.pending.len() < self.capacity);
        self.pending.push_back(prepared.range);
        self.next_admission_sequence = Some(prepared.next_admission_sequence);
    }

    /// Consume one canonical shard effect. A receipt is emitted only once the
    /// complete front batch range has reached a terminal engine result.
    pub fn observe_effect(
        &mut self,
        effect: &ShardEffect,
        observed_unix_ns: u64,
    ) -> Result<Option<OrderBatchReceipt>, BatchReceiptTrackerError> {
        let range = self
            .pending
            .front_mut()
            .ok_or(BatchReceiptTrackerError::UnexpectedEffect(
                effect.sequence.get(),
            ))?;
        let expected = range
            .first_sequence
            .checked_add(u64::from(range.processed))
            .ok_or(BatchReceiptTrackerError::SequenceExhausted)?;
        if effect.sequence.get() != expected {
            return Err(BatchReceiptTrackerError::EffectGap {
                expected,
                actual: effect.sequence.get(),
            });
        }
        range.processed = range
            .processed
            .checked_add(1)
            .ok_or(BatchReceiptTrackerError::SequenceExhausted)?;
        if effect.result.is_ok() {
            range.executed = range
                .executed
                .checked_add(1)
                .ok_or(BatchReceiptTrackerError::SequenceExhausted)?;
        } else {
            range.failed = range
                .failed
                .checked_add(1)
                .ok_or(BatchReceiptTrackerError::SequenceExhausted)?;
        }
        if range.processed != range.record_count {
            return Ok(None);
        }
        let complete =
            self.pending
                .pop_front()
                .ok_or(BatchReceiptTrackerError::UnexpectedEffect(
                    effect.sequence.get(),
                ))?;
        Ok(Some(OrderBatchReceipt {
            stage: OrderBatchReceiptStage::Executed,
            record_count: complete.record_count,
            admitted: complete.record_count,
            executed: complete.executed,
            finalized: 0,
            failed: complete.failed,
            rejection_code: 0,
            batch_sequence: complete.batch_sequence,
            first_sequence: complete.first_sequence,
            checkpoint_height: None,
            observed_unix_ns,
        }))
    }

    #[must_use]
    pub fn pending_batches(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn available_capacity(&self) -> usize {
        self.capacity.saturating_sub(self.pending.len())
    }
}

/// Construct immediate admission evidence for an authenticated published range.
pub fn admission_receipt(
    admission: PackedBatchAdmission,
    observed_unix_ns: u64,
) -> Result<OrderBatchReceipt, BatchReceiptTrackerError> {
    Ok(OrderBatchReceipt {
        stage: OrderBatchReceiptStage::Admitted,
        record_count: admission.record_count,
        admitted: admission.record_count,
        executed: 0,
        finalized: 0,
        failed: 0,
        rejection_code: 0,
        batch_sequence: admission
            .batch_sequence
            .ok_or(BatchReceiptTrackerError::UnauthenticatedAdmission)?,
        first_sequence: admission.first_sequence.get(),
        checkpoint_height: None,
        observed_unix_ns,
    })
}

/// Promote complete execution evidence only after Minimmit supplies a checkpoint
/// containing the entire sequence range.
pub fn finalize_executed_receipt(
    executed: OrderBatchReceipt,
    checkpoint_height: u64,
    observed_unix_ns: u64,
) -> Result<OrderBatchReceipt, BatchReceiptTrackerError> {
    if executed.stage != OrderBatchReceiptStage::Executed {
        return Err(BatchReceiptTrackerError::WrongFinalitySource);
    }
    Ok(OrderBatchReceipt {
        stage: OrderBatchReceiptStage::Finalized,
        finalized: executed.executed,
        checkpoint_height: Some(checkpoint_height),
        observed_unix_ns,
        ..executed
    })
}

/// Batch-range correlation failure. Every variant invalidates composed evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BatchReceiptTrackerError {
    #[error("batch receipt tracker capacity must be nonzero")]
    InvalidCapacity,
    #[error("batch receipt tracker is full")]
    Backpressure,
    #[error("trusted-context admission cannot produce a production receipt")]
    UnauthenticatedAdmission,
    #[error("packed admission has an invalid count or last-sequence range")]
    InvalidAdmissionRange,
    #[error("batch receipt tracker sequence exhausted")]
    SequenceExhausted,
    #[error("admission sequence gap: expected {expected}, got {actual}")]
    AdmissionGap { expected: u64, actual: u64 },
    #[error("shard effect sequence gap: expected {expected}, got {actual}")]
    EffectGap { expected: u64, actual: u64 },
    #[error("unexpected shard effect sequence {0}")]
    UnexpectedEffect(u64),
    #[error("only a complete executed receipt can be finalized")]
    WrongFinalitySource,
}

#[cfg(test)]
mod tests {
    use super::*;
    use execution::{ExecutionReceipt, ReceiptKind};
    use types::{Hash, SequenceNumber};

    fn admission(batch_sequence: u64, first: u64, count: u8) -> PackedBatchAdmission {
        PackedBatchAdmission {
            batch_sequence: Some(batch_sequence),
            record_count: count,
            first_sequence: SequenceNumber::new(first),
            last_sequence: SequenceNumber::new(first + u64::from(count) - 1),
            decode_backend: simd::Backend::Scalar,
        }
    }

    fn effect(sequence: u64) -> ShardEffect {
        ShardEffect {
            sequence: SequenceNumber::new(sequence),
            result: Ok(ExecutionReceipt {
                sequence,
                kind: ReceiptKind::Cancelled(1),
                state_root: Hash::ZERO,
            }),
        }
    }

    #[test]
    fn complete_range_emits_executed_then_finalized_receipt() {
        let admitted = admission(5, 100, 32);
        assert_eq!(
            admission_receipt(admitted, 10).unwrap().stage,
            OrderBatchReceiptStage::Admitted
        );
        let mut tracker = BatchReceiptTracker::new(2).unwrap();
        tracker.track_admission(admitted).unwrap();
        for sequence in 100..131 {
            assert_eq!(tracker.observe_effect(&effect(sequence), 20).unwrap(), None);
        }
        let executed = tracker.observe_effect(&effect(131), 20).unwrap().unwrap();
        assert_eq!(executed.executed, 32);
        assert_eq!(executed.failed, 0);
        let finalized = finalize_executed_receipt(executed, 9, 30).unwrap();
        assert_eq!(finalized.stage, OrderBatchReceiptStage::Finalized);
        assert_eq!(finalized.finalized, 32);
        assert_eq!(finalized.checkpoint_height, Some(9));
    }

    #[test]
    fn gaps_untrusted_admissions_and_capacity_fail_closed() {
        let mut tracker = BatchReceiptTracker::new(1).unwrap();
        tracker.track_admission(admission(1, 10, 32)).unwrap();
        assert_eq!(
            tracker.track_admission(admission(2, 42, 32)),
            Err(BatchReceiptTrackerError::Backpressure)
        );
        assert_eq!(
            tracker.observe_effect(&effect(11), 0),
            Err(BatchReceiptTrackerError::EffectGap {
                expected: 10,
                actual: 11
            })
        );
        assert_eq!(
            admission_receipt(
                PackedBatchAdmission {
                    batch_sequence: None,
                    ..admission(1, 10, 32)
                },
                0
            ),
            Err(BatchReceiptTrackerError::UnauthenticatedAdmission)
        );
    }
}

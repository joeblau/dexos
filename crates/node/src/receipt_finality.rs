//! Fail-closed binding from executed packed ranges to Minimmit finality.

use std::collections::BTreeMap;

use consensus::{BlockHeader, CheckpointHeader};
use network::{OrderBatchReceipt, OrderBatchReceiptStage};
use types::Hash;

use crate::finalize_executed_receipt;

/// Ordering and execution finality emitted by the canonical Minimmit driver.
///
/// The node constructs this at the checkpoint boundary so receipt promotion
/// remains independent of the driver's internal event representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MinimmitFinalityEvent {
    ConsensusFinal {
        block: Hash,
        height: u64,
    },
    Finalized {
        block: Hash,
        height: u64,
        /// Minimmit's wire-level `execution_root`: the deterministic post-execution
        /// state root certified by the execution L-certificate.
        execution_root: Hash,
    },
}

#[derive(Debug)]
struct PendingCheckpoint {
    height: u64,
    checkpoint: CheckpointHeader,
    consensus_final: bool,
    /// The first observation time for matching execution finality. Keeping
    /// this stable makes retries produce byte-identical receipt evidence.
    finalized_observed_unix_ns: Option<u64>,
    receipts: Vec<OrderBatchReceipt>,
}

/// Bounded correlation between a committed checkpoint payload and batch receipts.
///
/// A receipt is promoted only when all three commitments agree:
///
/// 1. the Minimmit block hash identifies the registered block header;
/// 2. that header's `payload_root` is the canonical checkpoint-header hash; and
/// 3. the deterministic state root certified by the execution L-certificate
///    equals the checkpoint's `new_state_root`.
///
/// `CheckpointHeader::execution_root` is a separate Merkle commitment over
/// per-command execution-result hashes; Minimmit does not certify that value.
pub struct MinimmitReceiptBridge {
    checkpoint_capacity: usize,
    receipt_capacity: usize,
    receipt_count: usize,
    checkpoints: BTreeMap<Hash, PendingCheckpoint>,
    blocks_by_height: BTreeMap<u64, Hash>,
    /// Disjoint executed sequence ranges, keyed by their inclusive start.
    ranges: BTreeMap<u64, (u64, Hash)>,
}

impl MinimmitReceiptBridge {
    pub fn new(
        checkpoint_capacity: usize,
        receipt_capacity: usize,
    ) -> Result<Self, MinimmitReceiptBridgeError> {
        if checkpoint_capacity == 0 || receipt_capacity == 0 {
            return Err(MinimmitReceiptBridgeError::InvalidCapacity);
        }
        Ok(Self {
            checkpoint_capacity,
            receipt_capacity,
            receipt_count: 0,
            checkpoints: BTreeMap::new(),
            blocks_by_height: BTreeMap::new(),
            ranges: BTreeMap::new(),
        })
    }

    /// Register the exact checkpoint header before its block is proposed.
    pub fn register_checkpoint(
        &mut self,
        block: &BlockHeader,
        checkpoint: CheckpointHeader,
    ) -> Result<Hash, MinimmitReceiptBridgeError> {
        if checkpoint.last_sequence < checkpoint.first_sequence {
            return Err(MinimmitReceiptBridgeError::InvalidCheckpointRange);
        }
        if block.payload_root != checkpoint.hash() {
            return Err(MinimmitReceiptBridgeError::PayloadCommitmentMismatch);
        }
        let block_hash = block.hash();
        if self.checkpoints.contains_key(&block_hash) {
            return Err(MinimmitReceiptBridgeError::DuplicateCheckpoint);
        }
        if self.blocks_by_height.contains_key(&block.height) {
            return Err(MinimmitReceiptBridgeError::ConflictingHeight(block.height));
        }
        if self.checkpoints.len() >= self.checkpoint_capacity {
            return Err(MinimmitReceiptBridgeError::CheckpointBackpressure);
        }
        self.checkpoints.insert(
            block_hash,
            PendingCheckpoint {
                height: block.height,
                checkpoint,
                consensus_final: false,
                finalized_observed_unix_ns: None,
                receipts: Vec::new(),
            },
        );
        self.blocks_by_height.insert(block.height, block_hash);
        Ok(block_hash)
    }

    /// Bind one complete executed batch to a registered checkpoint range.
    pub fn bind_executed(
        &mut self,
        block_hash: Hash,
        receipt: OrderBatchReceipt,
    ) -> Result<(), MinimmitReceiptBridgeError> {
        self.bind_executed_batch(block_hash, &[receipt])
    }

    /// Atomically bind a set of complete executed batches to one checkpoint.
    /// Every capacity, range, and overlap check completes before bridge state
    /// changes, so callers may safely retry the entire set after any error.
    pub fn bind_executed_batch(
        &mut self,
        block_hash: Hash,
        receipts: &[OrderBatchReceipt],
    ) -> Result<(), MinimmitReceiptBridgeError> {
        if receipts.is_empty() {
            return Ok(());
        }
        let next_receipt_count = self
            .receipt_count
            .checked_add(receipts.len())
            .ok_or(MinimmitReceiptBridgeError::ReceiptBackpressure)?;
        if next_receipt_count > self.receipt_capacity {
            return Err(MinimmitReceiptBridgeError::ReceiptBackpressure);
        }
        let pending = self
            .checkpoints
            .get(&block_hash)
            .ok_or(MinimmitReceiptBridgeError::UnknownBlock(block_hash))?;
        if pending.consensus_final {
            return Err(MinimmitReceiptBridgeError::CheckpointAlreadyOrdered);
        }

        let mut candidate_ranges = Vec::with_capacity(receipts.len());
        for &receipt in receipts {
            validate_executed(receipt)?;
            let last = receipt
                .first_sequence
                .checked_add(u64::from(receipt.record_count) - 1)
                .ok_or(MinimmitReceiptBridgeError::SequenceExhausted)?;
            if receipt.first_sequence < pending.checkpoint.first_sequence
                || last > pending.checkpoint.last_sequence
            {
                return Err(MinimmitReceiptBridgeError::ReceiptOutsideCheckpoint);
            }
            if self.ranges.range(..=last).next_back().is_some_and(
                |(&first, &(existing_last, _))| {
                    first <= last && existing_last >= receipt.first_sequence
                },
            ) {
                return Err(MinimmitReceiptBridgeError::OverlappingReceiptRange);
            }
            candidate_ranges.push((receipt.first_sequence, last));
        }

        candidate_ranges.sort_unstable_by_key(|&(first, _)| first);
        if candidate_ranges
            .windows(2)
            .any(|ranges| ranges[0].1 >= ranges[1].0)
        {
            return Err(MinimmitReceiptBridgeError::OverlappingReceiptRange);
        }

        // All validation is complete. Obtain the only fallible mutable lookup
        // before changing either index, then commit both bounded collections.
        let pending = self
            .checkpoints
            .get_mut(&block_hash)
            .ok_or(MinimmitReceiptBridgeError::UnknownBlock(block_hash))?;
        pending.receipts.extend_from_slice(receipts);
        for &(first, last) in &candidate_ranges {
            self.ranges.insert(first, (last, block_hash));
        }
        self.receipt_count = next_receipt_count;
        Ok(())
    }

    /// Observe an ordered driver event. `ConsensusFinal` never promotes a
    /// receipt; only the matching execution-certified `Finalized` event does.
    pub fn observe_finality(
        &mut self,
        event: MinimmitFinalityEvent,
        observed_unix_ns: u64,
    ) -> Result<Vec<OrderBatchReceipt>, MinimmitReceiptBridgeError> {
        match event {
            MinimmitFinalityEvent::ConsensusFinal { block, height } => {
                let pending = self
                    .checkpoints
                    .get_mut(&block)
                    .ok_or(MinimmitReceiptBridgeError::UnknownBlock(block))?;
                if pending.height != height {
                    return Err(MinimmitReceiptBridgeError::HeightMismatch {
                        expected: pending.height,
                        actual: height,
                    });
                }
                pending.consensus_final = true;
                Ok(Vec::new())
            }
            MinimmitFinalityEvent::Finalized {
                block,
                height,
                execution_root: certified_state_root,
            } => {
                let pending = self
                    .checkpoints
                    .get_mut(&block)
                    .ok_or(MinimmitReceiptBridgeError::UnknownBlock(block))?;
                if pending.height != height {
                    return Err(MinimmitReceiptBridgeError::HeightMismatch {
                        expected: pending.height,
                        actual: height,
                    });
                }
                if !pending.consensus_final {
                    return Err(MinimmitReceiptBridgeError::MissingConsensusFinal);
                }
                if pending.checkpoint.new_state_root != certified_state_root {
                    return Err(MinimmitReceiptBridgeError::ExecutionCommitmentMismatch);
                }
                let finalized_observed_unix_ns = pending
                    .finalized_observed_unix_ns
                    .unwrap_or(observed_unix_ns);
                let mut finalized = Vec::with_capacity(pending.receipts.len());
                for &receipt in &pending.receipts {
                    finalized.push(finalize_executed_receipt(
                        receipt,
                        height,
                        finalized_observed_unix_ns,
                    )?);
                }
                pending.finalized_observed_unix_ns = Some(finalized_observed_unix_ns);

                // A checkpoint with no socket receipts has no delivery evidence
                // to retain. Complete it immediately after both finality gates.
                if finalized.is_empty() {
                    self.checkpoints.remove(&block);
                    self.blocks_by_height.remove(&height);
                }
                Ok(finalized)
            }
        }
    }

    /// Acknowledge one successfully delivered or explicitly accounted
    /// finalized receipt. Unacknowledged receipts remain available on a
    /// repeated matching `Finalized` observation.
    pub(crate) fn acknowledge_finalized(
        &mut self,
        block_hash: Hash,
        batch_sequence: u64,
        first_sequence: u64,
    ) -> Result<(), MinimmitReceiptBridgeError> {
        let (height, position) = {
            let pending = self
                .checkpoints
                .get(&block_hash)
                .ok_or(MinimmitReceiptBridgeError::UnknownBlock(block_hash))?;
            if pending.finalized_observed_unix_ns.is_none() {
                return Err(MinimmitReceiptBridgeError::MissingExecutionFinality);
            }
            let position = pending
                .receipts
                .iter()
                .position(|receipt| {
                    receipt.batch_sequence == batch_sequence
                        && receipt.first_sequence == first_sequence
                })
                .ok_or(MinimmitReceiptBridgeError::UnknownReceipt {
                    batch_sequence,
                    first_sequence,
                })?;
            (pending.height, position)
        };

        if self.receipt_count == 0
            || !self.ranges.contains_key(&first_sequence)
            || self
                .ranges
                .get(&first_sequence)
                .is_some_and(|&(_, indexed_block)| indexed_block != block_hash)
        {
            return Err(MinimmitReceiptBridgeError::CorruptReceiptIndex);
        }

        // This lookup precedes every mutation in the acknowledgement commit.
        let pending = self
            .checkpoints
            .get_mut(&block_hash)
            .ok_or(MinimmitReceiptBridgeError::UnknownBlock(block_hash))?;
        let receipt = pending.receipts.remove(position);
        let checkpoint_complete = pending.receipts.is_empty();
        self.ranges.remove(&receipt.first_sequence);
        self.receipt_count -= 1;

        if checkpoint_complete {
            self.checkpoints.remove(&block_hash);
            self.blocks_by_height.remove(&height);
        }
        Ok(())
    }

    #[must_use]
    pub fn pending_checkpoints(&self) -> usize {
        self.checkpoints.len()
    }

    #[must_use]
    pub fn pending_receipts(&self) -> usize {
        self.receipt_count
    }
}

fn validate_executed(receipt: OrderBatchReceipt) -> Result<(), MinimmitReceiptBridgeError> {
    let complete = (32..=128).contains(&receipt.record_count)
        && receipt.stage == OrderBatchReceiptStage::Executed
        && receipt.admitted == receipt.record_count
        && u16::from(receipt.executed) + u16::from(receipt.failed) == u16::from(receipt.admitted)
        && receipt.finalized == 0
        && receipt.rejection_code == 0
        && receipt.checkpoint_height.is_none();
    if complete {
        Ok(())
    } else {
        Err(MinimmitReceiptBridgeError::InvalidExecutedReceipt)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MinimmitReceiptBridgeError {
    #[error("Minimmit receipt bridge capacities must be nonzero")]
    InvalidCapacity,
    #[error("checkpoint sequence range is out of order")]
    InvalidCheckpointRange,
    #[error("block payload root does not commit to the checkpoint header")]
    PayloadCommitmentMismatch,
    #[error("checkpoint block is already registered")]
    DuplicateCheckpoint,
    #[error("a different checkpoint is already registered at height {0}")]
    ConflictingHeight(u64),
    #[error("checkpoint bridge is backpressured")]
    CheckpointBackpressure,
    #[error("receipt bridge is backpressured")]
    ReceiptBackpressure,
    #[error("unknown Minimmit block {0:?}")]
    UnknownBlock(Hash),
    #[error("only a complete executed receipt can be bound")]
    InvalidExecutedReceipt,
    #[error("receipt sequence range exhausted")]
    SequenceExhausted,
    #[error("receipt range is not fully contained by its checkpoint")]
    ReceiptOutsideCheckpoint,
    #[error("executed receipt range overlaps a previously bound range")]
    OverlappingReceiptRange,
    #[error("receipts cannot be added after ordering finality")]
    CheckpointAlreadyOrdered,
    #[error("finality height mismatch: expected {expected}, got {actual}")]
    HeightMismatch { expected: u64, actual: u64 },
    #[error("execution finality arrived before ordering finality")]
    MissingConsensusFinal,
    #[error("receipt acknowledgement arrived before execution finality")]
    MissingExecutionFinality,
    #[error(
        "checkpoint has no pending receipt for batch {batch_sequence} at sequence {first_sequence}"
    )]
    UnknownReceipt {
        batch_sequence: u64,
        first_sequence: u64,
    },
    #[error("receipt bridge indexes are internally inconsistent")]
    CorruptReceiptIndex,
    #[error(
        "execution-certified state root does not match the checkpoint's committed new state root"
    )]
    ExecutionCommitmentMismatch,
    #[error(transparent)]
    Receipt(#[from] crate::BatchReceiptTrackerError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::ShardId;

    fn h(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    fn checkpoint(first: u64, last: u64) -> CheckpointHeader {
        CheckpointHeader {
            epoch: 4,
            shard_id: ShardId::new(0),
            first_sequence: first,
            last_sequence: last,
            previous_state_root: h(1),
            new_state_root: h(2),
            command_root: h(3),
            execution_root: h(4),
            oracle_root: h(5),
            timestamp: 6,
        }
    }

    fn block(height: u64, checkpoint: &CheckpointHeader) -> BlockHeader {
        BlockHeader {
            height,
            parent_hash: h(9),
            payload_root: checkpoint.hash(),
        }
    }

    fn executed(batch: u64, first: u64, count: u8) -> OrderBatchReceipt {
        OrderBatchReceipt {
            stage: OrderBatchReceiptStage::Executed,
            record_count: count,
            admitted: count,
            executed: count,
            finalized: 0,
            failed: 0,
            rejection_code: 0,
            batch_sequence: batch,
            first_sequence: first,
            checkpoint_height: None,
            observed_unix_ns: 10,
        }
    }

    #[test]
    fn promotes_only_after_both_bound_finality_gates() {
        let checkpoint = checkpoint(100, 163);
        let block = block(7, &checkpoint);
        let hash = block.hash();
        let mut bridge = MinimmitReceiptBridge::new(2, 4).unwrap();
        bridge.register_checkpoint(&block, checkpoint).unwrap();
        bridge.bind_executed(hash, executed(1, 100, 32)).unwrap();
        assert!(bridge
            .observe_finality(
                MinimmitFinalityEvent::ConsensusFinal {
                    block: hash,
                    height: 7,
                },
                20,
            )
            .unwrap()
            .is_empty());
        let finalized = bridge
            .observe_finality(
                MinimmitFinalityEvent::Finalized {
                    block: hash,
                    height: 7,
                    execution_root: h(2),
                },
                30,
            )
            .unwrap();
        assert_eq!(finalized.len(), 1);
        assert_eq!(finalized[0].stage, OrderBatchReceiptStage::Finalized);
        assert_eq!(finalized[0].checkpoint_height, Some(7));
        assert_eq!(bridge.pending_checkpoints(), 1);
        assert_eq!(bridge.pending_receipts(), 1);
        let retried = bridge
            .observe_finality(
                MinimmitFinalityEvent::Finalized {
                    block: hash,
                    height: 7,
                    execution_root: h(2),
                },
                99,
            )
            .unwrap();
        assert_eq!(retried, finalized);
        assert_eq!(retried[0].observed_unix_ns, 30);
        bridge
            .acknowledge_finalized(
                hash,
                finalized[0].batch_sequence,
                finalized[0].first_sequence,
            )
            .unwrap();
        assert_eq!(bridge.pending_checkpoints(), 0);
        assert_eq!(bridge.pending_receipts(), 0);
    }

    #[test]
    fn forged_payload_and_wrong_certified_state_root_fail_closed() {
        let checkpoint = checkpoint(100, 131);
        let mut forged = block(7, &checkpoint);
        forged.payload_root = h(99);
        let mut bridge = MinimmitReceiptBridge::new(2, 4).unwrap();
        assert_eq!(
            bridge.register_checkpoint(&forged, checkpoint.clone()),
            Err(MinimmitReceiptBridgeError::PayloadCommitmentMismatch)
        );

        let block = block(7, &checkpoint);
        let hash = bridge.register_checkpoint(&block, checkpoint).unwrap();
        bridge.bind_executed(hash, executed(1, 100, 32)).unwrap();
        bridge
            .observe_finality(
                MinimmitFinalityEvent::ConsensusFinal {
                    block: hash,
                    height: 7,
                },
                20,
            )
            .unwrap();
        assert_eq!(
            bridge.observe_finality(
                MinimmitFinalityEvent::Finalized {
                    block: hash,
                    height: 7,
                    // This is the checkpoint's execution-result Merkle root, not
                    // the deterministic state root certified by Minimmit.
                    execution_root: h(4),
                },
                30,
            ),
            Err(MinimmitReceiptBridgeError::ExecutionCommitmentMismatch)
        );
        assert_eq!(bridge.pending_receipts(), 1);
    }

    #[test]
    fn ranges_are_contained_unique_and_bounded() {
        let checkpoint = checkpoint(100, 163);
        let block = block(7, &checkpoint);
        let mut bridge = MinimmitReceiptBridge::new(1, 1).unwrap();
        let hash = bridge.register_checkpoint(&block, checkpoint).unwrap();
        assert_eq!(
            bridge.bind_executed(hash, executed(1, 90, 32)),
            Err(MinimmitReceiptBridgeError::ReceiptOutsideCheckpoint)
        );
        bridge.bind_executed(hash, executed(1, 100, 32)).unwrap();
        assert_eq!(
            bridge.bind_executed(hash, executed(2, 120, 32)),
            Err(MinimmitReceiptBridgeError::ReceiptBackpressure)
        );
    }

    #[test]
    fn multi_receipt_binding_rolls_back_every_candidate_on_error() {
        let checkpoint = checkpoint(100, 227);
        let block = block(7, &checkpoint);
        let hash = block.hash();
        let mut bounded = MinimmitReceiptBridge::new(1, 1).unwrap();
        bounded
            .register_checkpoint(&block, checkpoint.clone())
            .unwrap();
        assert_eq!(
            bounded.bind_executed_batch(hash, &[executed(1, 100, 32), executed(2, 132, 32)]),
            Err(MinimmitReceiptBridgeError::ReceiptBackpressure)
        );
        assert_eq!(bounded.pending_receipts(), 0);
        assert!(bounded.ranges.is_empty());
        bounded.bind_executed(hash, executed(1, 100, 32)).unwrap();

        let mut overlapping = MinimmitReceiptBridge::new(1, 4).unwrap();
        overlapping.register_checkpoint(&block, checkpoint).unwrap();
        assert_eq!(
            overlapping.bind_executed_batch(hash, &[executed(1, 100, 32), executed(2, 120, 32)]),
            Err(MinimmitReceiptBridgeError::OverlappingReceiptRange)
        );
        assert_eq!(overlapping.pending_receipts(), 0);
        assert!(overlapping.ranges.is_empty());
    }
}

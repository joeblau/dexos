//! Composed durable packed admission, deterministic execution, and receipts.

use execution::Engine;
use network::OrderBatchReceipt;

use crate::{
    admission_receipt, shard_pipeline, AuthenticatedPackedBatchIngress,
    AuthenticatedPackedIngressError, BatchReceiptTracker, BatchReceiptTrackerError,
    DurablePackedBatchIngress, PackedBatchJournal, PackedBatchJournalError, PackedIngressError,
    PackedSession, RingError, ShardEgress, ShardIngress, ShardStep, ShardWorker,
};

/// Single-session validator slice with a real durable/execution/receipt path.
pub struct PackedValidatorCore {
    durable: DurablePackedBatchIngress,
    ingress: ShardIngress,
    worker: ShardWorker,
    egress: ShardEgress,
    receipts: BatchReceiptTracker,
}

impl PackedValidatorCore {
    /// Recover every verified journaled batch into `engine`, advance authenticated
    /// replay state, then accept new traffic. The engine must already contain the
    /// snapshot/genesis prefix immediately preceding `session.first_command_sequence`.
    pub fn recover(
        engine: Engine,
        session: PackedSession,
        journal: PackedBatchJournal,
        ingress_capacity: usize,
        egress_capacity: usize,
        receipt_capacity: usize,
    ) -> Result<Self, PackedValidatorCoreError> {
        if ingress_capacity < 128 || egress_capacity < 128 {
            return Err(PackedValidatorCoreError::CapacityBelowBatchMaximum);
        }
        let mut receipts = BatchReceiptTracker::new(receipt_capacity)?;
        let (mut ingress, mut worker, mut egress) =
            shard_pipeline(engine, ingress_capacity, egress_capacity)?;
        let mut authenticated = AuthenticatedPackedBatchIngress::new(session);
        journal.for_each_recovered(|record| {
            let (admitted, prepared) = authenticated
                .try_admit_after(
                    &mut ingress,
                    &record.payload,
                    record.timestamp,
                    |admission| receipts.prepare_admission(admission).map_err(Into::into),
                )
                .map_err(|error| PackedBatchJournalError::Recovery(error.to_string()))?;
            receipts.commit_admission(prepared);
            let mut completed = false;
            for _ in 0..admitted.record_count {
                if worker.step() != ShardStep::Processed {
                    return Err(PackedBatchJournalError::Recovery(
                        "recovery shard worker did not process a published command".into(),
                    ));
                }
                let effect = egress.try_recv().ok_or_else(|| {
                    PackedBatchJournalError::Recovery(
                        "recovery shard effect was not published".into(),
                    )
                })?;
                completed = receipts
                    .observe_effect(&effect, record.timestamp)
                    .map_err(|error| PackedBatchJournalError::Recovery(error.to_string()))?
                    .is_some();
            }
            if !completed {
                return Err(PackedBatchJournalError::Recovery(
                    "recovered packed batch did not complete its receipt range".into(),
                ));
            }
            Ok(())
        })?;
        Ok(Self {
            durable: DurablePackedBatchIngress::from_authenticated(authenticated, journal),
            ingress,
            worker,
            egress,
            receipts,
        })
    }

    /// Durably admit a complete batch and return immediate admission evidence.
    pub fn admit(
        &mut self,
        bytes: &[u8],
        sequencer_now: u64,
        observed_unix_ns: u64,
    ) -> Result<OrderBatchReceipt, PackedValidatorCoreError> {
        let receipts = &self.receipts;
        let (admitted, (tracker, receipt)) = self
            .durable
            .try_admit_after(&mut self.ingress, bytes, sequencer_now, |admission| {
                let tracker = receipts.prepare_admission(admission)?;
                let receipt = admission_receipt(admission, observed_unix_ns)?;
                Ok((tracker, receipt))
            })
            .map_err(map_admission_error)?;
        debug_assert_eq!(receipt.record_count, admitted.record_count);
        self.receipts.commit_admission(tracker);
        Ok(receipt)
    }

    /// Execute at most one command and emit a cumulative executed receipt only at
    /// the exact end of its authenticated batch range.
    pub fn step(
        &mut self,
        observed_unix_ns: u64,
    ) -> Result<Option<OrderBatchReceipt>, PackedValidatorCoreError> {
        match self.worker.step() {
            ShardStep::Idle => Ok(None),
            ShardStep::EgressBackpressure => Err(PackedValidatorCoreError::EgressBackpressure),
            ShardStep::Processed => {
                let effect = self
                    .egress
                    .try_recv()
                    .ok_or(PackedValidatorCoreError::MissingShardEffect)?;
                Ok(self.receipts.observe_effect(&effect, observed_unix_ns)?)
            }
        }
    }

    /// Drain execution until the next batch receipt is complete.
    pub fn drive_until_receipt(
        &mut self,
        observed_unix_ns: u64,
    ) -> Result<OrderBatchReceipt, PackedValidatorCoreError> {
        loop {
            if let Some(receipt) = self.step(observed_unix_ns)? {
                return Ok(receipt);
            }
            if self.receipts.pending_batches() == 0 {
                return Err(PackedValidatorCoreError::MissingShardEffect);
            }
        }
    }

    #[must_use]
    pub fn state_root(&self) -> types::Hash {
        self.worker.state_root()
    }

    pub fn sync(&mut self) -> Result<(), PackedValidatorCoreError> {
        self.durable.sync()?;
        Ok(())
    }
}

fn map_admission_error(error: AuthenticatedPackedIngressError) -> PackedValidatorCoreError {
    match error {
        AuthenticatedPackedIngressError::Admission(PackedIngressError::ReceiptPreflight(
            BatchReceiptTrackerError::Backpressure,
        )) => PackedValidatorCoreError::ReceiptBackpressure,
        AuthenticatedPackedIngressError::Admission(PackedIngressError::ReceiptPreflight(error)) => {
            PackedValidatorCoreError::Receipt(error)
        }
        error => PackedValidatorCoreError::Admission(error),
    }
}

/// Failure in the composed durable/execution/receipt slice.
#[derive(Debug, thiserror::Error)]
pub enum PackedValidatorCoreError {
    #[error("ingress and egress capacities must each hold a 128-record batch")]
    CapacityBelowBatchMaximum,
    #[error(transparent)]
    Ring(#[from] RingError),
    #[error(transparent)]
    Journal(#[from] PackedBatchJournalError),
    #[error(transparent)]
    Admission(#[from] AuthenticatedPackedIngressError),
    #[error(transparent)]
    Receipt(#[from] BatchReceiptTrackerError),
    #[error("batch receipt tracker is backpressured")]
    ReceiptBackpressure,
    #[error("shard execution egress is backpressured")]
    EgressBackpressure,
    #[error("published command produced no shard effect")]
    MissingShardEffect,
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::PackedOrder;
    use crypto::KeyPair;
    use execution::{CreateAccount, CreateMarket, DeterministicEngine, EngineConfig};
    use network::{AuthenticatedOrderBatchCodec, OrderBatchBinding, OrderBatchReceiptStage};
    use types::{
        AccountId, Amount, MarketId, MarketType, OrderType, Price, Quantity, Ratio, SequenceNumber,
        Side, TimeInForce, RATIO_SCALE,
    };

    fn temp_dir() -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "dexos-packed-core-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    fn genesis() -> Engine {
        let mut engine = Engine::new(EngineConfig::default());
        engine
            .execute(
                SequenceNumber::new(1),
                execution::Command::CreateAccount(CreateAccount {
                    initial_collateral: Amount::from_raw(1_000_000_000),
                }),
            )
            .unwrap();
        engine
            .execute(
                SequenceNumber::new(2),
                execution::Command::CreateMarket(CreateMarket {
                    market: MarketId::new(0),
                    market_type: MarketType::Perpetual,
                    outcomes: 1,
                    mark_price: Price::from_raw(1_000_000),
                }),
            )
            .unwrap();
        engine
    }

    fn session(signer: &KeyPair) -> PackedSession {
        PackedSession {
            destination: [5; 32],
            session_ref: 7,
            account: AccountId::new(0),
            signer: signer.public(),
            authority: crate::PackedAuthority::Master,
            first_batch_sequence: 11,
            first_command_sequence: SequenceNumber::new(3),
            batch_sequence_stride: 1,
            command_sequence_stride: 0,
        }
    }

    fn batch(signer: &KeyPair) -> Vec<u8> {
        batch_with(signer, 32, false, 11, 3)
    }

    fn batch_with(
        signer: &KeyPair,
        count: u8,
        partial: bool,
        batch_sequence: u64,
        first_sequence: u64,
    ) -> Vec<u8> {
        let records: Vec<_> = (0..u64::from(count))
            .map(|index| PackedOrder::Submit {
                session_ref: 7,
                nonce: 10 + index,
                client_id: 10 + index,
                account: AccountId::new(0),
                market: MarketId::new(0),
                side: Side::Bid,
                order_type: OrderType::Limit,
                price: Price::from_raw(1),
                quantity: Quantity::from_raw(1),
                time_in_force: TimeInForce::Gtc,
                leverage: Ratio::from_raw(RATIO_SCALE),
            })
            .collect();
        let mut packed = vec![0; records.len() * codec::PACKED_SUBMIT_LEN];
        let len = if partial {
            let mut at = 0;
            for &record in &records {
                at += record.encode_into(&mut packed[at..]).unwrap();
            }
            at
        } else {
            codec::encode_batch_into(&records, &mut packed).unwrap()
        };
        AuthenticatedOrderBatchCodec::new()
            .encode(
                OrderBatchBinding {
                    destination: [5; 32],
                    session_ref: 7,
                    account: AccountId::new(0),
                    batch_sequence,
                    first_sequence,
                },
                signer,
                count,
                partial,
                &packed[..len],
            )
            .unwrap()
            .bytes
            .to_vec()
    }

    #[test]
    fn durable_execution_receipts_recover_to_identical_state_root() {
        let dir = temp_dir();
        let signer = KeyPair::from_seed(&[7; 32]);
        let bytes = batch(&signer);
        let journal = PackedBatchJournal::open(&dir, 1024 * 1024).unwrap();
        let mut core =
            PackedValidatorCore::recover(genesis(), session(&signer), journal, 256, 256, 8)
                .unwrap();
        let admitted = core.admit(&bytes, 50, 60).unwrap();
        assert_eq!(admitted.stage, OrderBatchReceiptStage::Admitted);
        let executed = core.drive_until_receipt(70).unwrap();
        assert_eq!(executed.executed, 32);
        assert_eq!(executed.failed, 0);
        let finalized = crate::finalize_executed_receipt(executed, 9, 80).unwrap();
        assert_eq!(finalized.finalized, 32);
        let expected_root = core.state_root();
        core.sync().unwrap();
        drop(core);

        let journal = PackedBatchJournal::open(&dir, 1024 * 1024).unwrap();
        let recovered =
            PackedValidatorCore::recover(genesis(), session(&signer), journal, 256, 256, 8)
                .unwrap();
        assert_eq!(recovered.state_root(), expected_root);
        drop(recovered);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn partial_batch_fails_receipt_preflight_before_journal_replay_or_spsc() {
        let dir = temp_dir();
        let signer = KeyPair::from_seed(&[8; 32]);
        let partial = batch_with(&signer, 31, true, 11, 3);
        let valid = batch(&signer);
        let journal = PackedBatchJournal::open(&dir, 1024 * 1024).unwrap();
        let mut core =
            PackedValidatorCore::recover(genesis(), session(&signer), journal, 256, 256, 8)
                .unwrap();
        let root = core.state_root();

        assert!(matches!(
            core.admit(&partial, 50, 60),
            Err(PackedValidatorCoreError::Receipt(
                BatchReceiptTrackerError::InvalidAdmissionRange
            ))
        ));
        assert_eq!(core.durable.journal().len(), 0);
        assert_eq!(core.durable.next_batch_sequence(), 11);
        assert_eq!(core.durable.next_command_sequence(), SequenceNumber::new(3));
        assert_eq!(core.receipts.pending_batches(), 0);
        assert_eq!(core.ingress.available_capacity(), 256);
        assert_eq!(core.state_root(), root);
        assert!(core.step(61).unwrap().is_none());

        core.admit(&valid, 62, 63).unwrap();
        assert_eq!(core.durable.journal().len(), 1);
        assert_eq!(core.durable.next_batch_sequence(), 12);
        core.drive_until_receipt(64).unwrap();
        drop(core);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn receipt_gap_fails_before_second_journal_or_replay_advance() {
        let dir = temp_dir();
        let signer = KeyPair::from_seed(&[9; 32]);
        let mut striped = session(&signer);
        striped.batch_sequence_stride = 2;
        striped.command_sequence_stride = 64;
        let first = batch_with(&signer, 32, false, 11, 3);
        let gap = batch_with(&signer, 32, false, 13, 67);
        let journal = PackedBatchJournal::open(&dir, 1024 * 1024).unwrap();
        let mut core =
            PackedValidatorCore::recover(genesis(), striped, journal, 256, 256, 8).unwrap();

        core.admit(&first, 50, 60).unwrap();
        core.drive_until_receipt(61).unwrap();
        let root = core.state_root();
        assert_eq!(core.durable.journal().len(), 1);
        assert_eq!(core.durable.next_batch_sequence(), 13);
        assert_eq!(
            core.durable.next_command_sequence(),
            SequenceNumber::new(67)
        );

        for _ in 0..2 {
            assert!(matches!(
                core.admit(&gap, 62, 63),
                Err(PackedValidatorCoreError::Receipt(
                    BatchReceiptTrackerError::AdmissionGap {
                        expected: 35,
                        actual: 67
                    }
                ))
            ));
            assert_eq!(core.durable.journal().len(), 1);
            assert_eq!(core.durable.next_batch_sequence(), 13);
            assert_eq!(
                core.durable.next_command_sequence(),
                SequenceNumber::new(67)
            );
            assert_eq!(core.receipts.pending_batches(), 0);
            assert_eq!(core.ingress.available_capacity(), 256);
            assert_eq!(core.state_root(), root);
            assert!(core.step(64).unwrap().is_none());
        }

        drop(core);
        let _ = std::fs::remove_dir_all(dir);
    }
}

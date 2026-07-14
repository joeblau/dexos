//! Multi-session durable packed admission over one canonical shard sequence.

use std::collections::BTreeMap;

use execution::Engine;
use network::{inspect_authenticated_order_batch, OrderBatchReceipt};

use crate::{
    admission_receipt, shard_pipeline, AuthenticatedPackedBatchIngress,
    AuthenticatedPackedIngressError, BatchReceiptTracker, BatchReceiptTrackerError,
    PackedBatchJournal, PackedBatchJournalError, PackedIngressError, PackedSession, RingError,
    ShardEgress, ShardIngress, ShardStep, ShardWorker,
};

/// One global sequencer/execution owner with independent authenticated replay
/// domains for bounded striped client sessions.
pub struct MultiSessionPackedValidatorCore {
    journal: PackedBatchJournal,
    sessions: BTreeMap<u32, AuthenticatedPackedBatchIngress>,
    ingress: ShardIngress,
    worker: ShardWorker,
    egress: ShardEgress,
    receipts: BatchReceiptTracker,
    next_command_sequence: u64,
}

impl MultiSessionPackedValidatorCore {
    /// Recover globally ordered journal entries, then accept striped sessions.
    pub fn recover(
        engine: Engine,
        sessions: Vec<PackedSession>,
        journal: PackedBatchJournal,
        ingress_capacity: usize,
        egress_capacity: usize,
        receipt_capacity: usize,
    ) -> Result<Self, MultiSessionPackedValidatorCoreError> {
        if ingress_capacity < 128 || egress_capacity < 128 {
            return Err(MultiSessionPackedValidatorCoreError::CapacityBelowBatchMaximum);
        }
        if sessions.is_empty() {
            return Err(MultiSessionPackedValidatorCoreError::EmptySessions);
        }
        validate_striped_sessions(&sessions)?;
        let destination = sessions[0].destination;
        let mut next_command_sequence = u64::MAX;
        let mut authenticated = BTreeMap::new();
        for session in sessions {
            if session.destination != destination {
                return Err(MultiSessionPackedValidatorCoreError::MixedDestination);
            }
            next_command_sequence = next_command_sequence.min(session.first_command_sequence.get());
            if authenticated
                .insert(
                    session.session_ref,
                    AuthenticatedPackedBatchIngress::new(session),
                )
                .is_some()
            {
                return Err(MultiSessionPackedValidatorCoreError::DuplicateSession(
                    session.session_ref,
                ));
            }
        }

        let mut receipts = BatchReceiptTracker::new(receipt_capacity)?;
        let (mut ingress, mut worker, mut egress) =
            shard_pipeline(engine, ingress_capacity, egress_capacity)?;
        journal.for_each_recovered(|record| {
            let header = inspect_authenticated_order_batch(&record.payload)
                .map_err(|error| PackedBatchJournalError::Recovery(error.to_string()))?;
            if header.binding.first_sequence != next_command_sequence {
                return Err(PackedBatchJournalError::Recovery(format!(
                    "global command sequence mismatch: expected {next_command_sequence}, got {}",
                    header.binding.first_sequence
                )));
            }
            let session = authenticated
                .get_mut(&header.binding.session_ref)
                .ok_or_else(|| {
                    PackedBatchJournalError::Recovery(format!(
                        "unknown packed session {}",
                        header.binding.session_ref
                    ))
                })?;
            let (admitted, prepared) = session
                .try_admit_after(
                    &mut ingress,
                    &record.payload,
                    record.timestamp,
                    |admission| receipts.prepare_admission(admission).map_err(Into::into),
                )
                .map_err(|error| PackedBatchJournalError::Recovery(error.to_string()))?;
            let global_next = prepared.next_admission_sequence();
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
            next_command_sequence = global_next;
            Ok(())
        })?;

        Ok(Self {
            journal,
            sessions: authenticated,
            ingress,
            worker,
            egress,
            receipts,
            next_command_sequence,
        })
    }

    #[must_use]
    pub const fn next_command_sequence(&self) -> u64 {
        self.next_command_sequence
    }

    /// Inspect only enough untrusted header state to decide whether a socket
    /// should run now, wait for a lower striped batch, or fail as stale.
    pub fn readiness(
        &self,
        bytes: &[u8],
    ) -> Result<MultiSessionAdmissionReadiness, MultiSessionPackedValidatorCoreError> {
        let header = inspect_authenticated_order_batch(bytes)?;
        if !self.sessions.contains_key(&header.binding.session_ref) {
            return Err(MultiSessionPackedValidatorCoreError::UnknownSession(
                header.binding.session_ref,
            ));
        }
        Ok(
            match header
                .binding
                .first_sequence
                .cmp(&self.next_command_sequence)
            {
                std::cmp::Ordering::Equal => MultiSessionAdmissionReadiness::Ready,
                std::cmp::Ordering::Greater => MultiSessionAdmissionReadiness::Wait {
                    expected: self.next_command_sequence,
                    actual: header.binding.first_sequence,
                },
                std::cmp::Ordering::Less => MultiSessionAdmissionReadiness::Stale {
                    expected: self.next_command_sequence,
                    actual: header.binding.first_sequence,
                },
            },
        )
    }

    /// Durably admit only the exact next global batch.
    pub fn admit(
        &mut self,
        bytes: &[u8],
        sequencer_now: u64,
        observed_unix_ns: u64,
    ) -> Result<OrderBatchReceipt, MultiSessionPackedValidatorCoreError> {
        match self.readiness(bytes)? {
            MultiSessionAdmissionReadiness::Ready => {}
            MultiSessionAdmissionReadiness::Wait { expected, actual } => {
                return Err(MultiSessionPackedValidatorCoreError::NotReady { expected, actual });
            }
            MultiSessionAdmissionReadiness::Stale { expected, actual } => {
                return Err(MultiSessionPackedValidatorCoreError::Stale { expected, actual });
            }
        }
        let header = inspect_authenticated_order_batch(bytes)?;
        let authenticated = self.sessions.get_mut(&header.binding.session_ref).ok_or(
            MultiSessionPackedValidatorCoreError::UnknownSession(header.binding.session_ref),
        )?;
        let journal = &mut self.journal;
        let receipts = &self.receipts;
        let (admitted, (tracker, receipt, global_next)) = authenticated
            .try_admit_after(&mut self.ingress, bytes, sequencer_now, |admission| {
                let tracker = receipts.prepare_admission(admission)?;
                let receipt = admission_receipt(admission, observed_unix_ns)?;
                let global_next = tracker.next_admission_sequence();
                journal
                    .append_batch(bytes, sequencer_now)
                    .map(|_| ())
                    .map_err(|error| PackedIngressError::Durability(error.to_string()))?;
                Ok((tracker, receipt, global_next))
            })
            .map_err(map_admission_error)?;
        debug_assert_eq!(receipt.record_count, admitted.record_count);
        self.receipts.commit_admission(tracker);
        self.next_command_sequence = global_next;
        Ok(receipt)
    }

    pub fn step(
        &mut self,
        observed_unix_ns: u64,
    ) -> Result<Option<OrderBatchReceipt>, MultiSessionPackedValidatorCoreError> {
        match self.worker.step() {
            ShardStep::Idle => Ok(None),
            ShardStep::EgressBackpressure => {
                Err(MultiSessionPackedValidatorCoreError::EgressBackpressure)
            }
            ShardStep::Processed => {
                let effect = self
                    .egress
                    .try_recv()
                    .ok_or(MultiSessionPackedValidatorCoreError::MissingShardEffect)?;
                Ok(self.receipts.observe_effect(&effect, observed_unix_ns)?)
            }
        }
    }

    pub fn drive_until_receipt(
        &mut self,
        observed_unix_ns: u64,
    ) -> Result<OrderBatchReceipt, MultiSessionPackedValidatorCoreError> {
        loop {
            if let Some(receipt) = self.step(observed_unix_ns)? {
                return Ok(receipt);
            }
            if self.receipts.pending_batches() == 0 {
                return Err(MultiSessionPackedValidatorCoreError::MissingShardEffect);
            }
        }
    }

    #[must_use]
    pub fn state_root(&self) -> types::Hash {
        self.worker.state_root()
    }

    pub fn sync(&mut self) -> Result<(), MultiSessionPackedValidatorCoreError> {
        self.journal.sync()?;
        Ok(())
    }
}

fn map_admission_error(
    error: AuthenticatedPackedIngressError,
) -> MultiSessionPackedValidatorCoreError {
    match error {
        AuthenticatedPackedIngressError::Admission(PackedIngressError::ReceiptPreflight(
            BatchReceiptTrackerError::Backpressure,
        )) => MultiSessionPackedValidatorCoreError::ReceiptBackpressure,
        AuthenticatedPackedIngressError::Admission(PackedIngressError::ReceiptPreflight(error)) => {
            MultiSessionPackedValidatorCoreError::Receipt(error)
        }
        error => MultiSessionPackedValidatorCoreError::Admission(error),
    }
}

fn validate_striped_sessions(
    sessions: &[PackedSession],
) -> Result<(), MultiSessionPackedValidatorCoreError> {
    if sessions.len() == 1 {
        return if sessions[0].batch_sequence_stride == 0 {
            Err(MultiSessionPackedValidatorCoreError::InvalidSequenceStrides)
        } else {
            Ok(())
        };
    }
    let batch_stride = sessions[0].batch_sequence_stride;
    let command_stride = sessions[0].command_sequence_stride;
    if batch_stride != u64::try_from(sessions.len()).unwrap_or(u64::MAX)
        || command_stride == 0
        || !command_stride.is_multiple_of(batch_stride)
        || sessions.iter().any(|session| {
            session.batch_sequence_stride != batch_stride
                || session.command_sequence_stride != command_stride
        })
    {
        return Err(MultiSessionPackedValidatorCoreError::InvalidSequenceStrides);
    }
    let batch_width = command_stride / batch_stride;
    if !(32..=128).contains(&batch_width) {
        return Err(MultiSessionPackedValidatorCoreError::InvalidSequenceStrides);
    }
    let mut starts: Vec<_> = sessions
        .iter()
        .map(|session| {
            (
                session.first_batch_sequence,
                session.first_command_sequence.get(),
            )
        })
        .collect();
    starts.sort_unstable();
    let (batch_base, command_base) = starts[0];
    for (ordinal, (batch, command)) in starts.into_iter().enumerate() {
        let ordinal = u64::try_from(ordinal).unwrap_or(u64::MAX);
        let expected_batch = batch_base
            .checked_add(ordinal)
            .ok_or(MultiSessionPackedValidatorCoreError::SequenceExhausted)?;
        let expected_command = command_base
            .checked_add(
                ordinal
                    .checked_mul(batch_width)
                    .ok_or(MultiSessionPackedValidatorCoreError::SequenceExhausted)?,
            )
            .ok_or(MultiSessionPackedValidatorCoreError::SequenceExhausted)?;
        if batch != expected_batch || command != expected_command {
            return Err(MultiSessionPackedValidatorCoreError::UnstripedSessions);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiSessionAdmissionReadiness {
    Ready,
    Wait { expected: u64, actual: u64 },
    Stale { expected: u64, actual: u64 },
}

#[derive(Debug, thiserror::Error)]
pub enum MultiSessionPackedValidatorCoreError {
    #[error("ingress and egress capacities must each hold a 128-record batch")]
    CapacityBelowBatchMaximum,
    #[error("multi-session packed core requires at least one session")]
    EmptySessions,
    #[error("multi-session packed core sessions target different destinations")]
    MixedDestination,
    #[error("duplicate packed session reference {0}")]
    DuplicateSession(u32),
    #[error("multi-session packed sequence strides are invalid or incomplete")]
    InvalidSequenceStrides,
    #[error("multi-session packed starting sequences do not cover every stripe")]
    UnstripedSessions,
    #[error("unknown packed session reference {0}")]
    UnknownSession(u32),
    #[error("global packed sequence {actual} is waiting for {expected}")]
    NotReady { expected: u64, actual: u64 },
    #[error("global packed sequence {actual} is stale; next is {expected}")]
    Stale { expected: u64, actual: u64 },
    #[error("global packed command sequence exhausted")]
    SequenceExhausted,
    #[error(transparent)]
    Ring(#[from] RingError),
    #[error(transparent)]
    Journal(#[from] PackedBatchJournalError),
    #[error(transparent)]
    Admission(#[from] AuthenticatedPackedIngressError),
    #[error(transparent)]
    Authentication(#[from] network::AuthenticatedOrderBatchError),
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
    use network::{AuthenticatedOrderBatchCodec, OrderBatchBinding};
    use types::{
        AccountId, Amount, MarketId, MarketType, OrderType, Price, Quantity, Ratio, SequenceNumber,
        Side, TimeInForce, RATIO_SCALE,
    };

    fn temp_dir() -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "dexos-multi-packed-core-{}-{}",
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

    fn session(
        reference: u32,
        signer: &KeyPair,
        first_batch: u64,
        first_command: u64,
    ) -> PackedSession {
        PackedSession {
            destination: [5; 32],
            session_ref: reference,
            account: AccountId::new(0),
            signer: signer.public(),
            authority: crate::PackedAuthority::Master,
            first_batch_sequence: first_batch,
            first_command_sequence: SequenceNumber::new(first_command),
            batch_sequence_stride: 2,
            command_sequence_stride: 64,
        }
    }

    fn batch(
        reference: u32,
        signer: &KeyPair,
        batch_sequence: u64,
        first_sequence: u64,
        nonce_base: u64,
    ) -> Vec<u8> {
        batch_with_count(
            reference,
            signer,
            batch_sequence,
            first_sequence,
            nonce_base,
            32,
            false,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn batch_with_count(
        reference: u32,
        signer: &KeyPair,
        batch_sequence: u64,
        first_sequence: u64,
        nonce_base: u64,
        count: u8,
        partial: bool,
    ) -> Vec<u8> {
        let records: Vec<_> = (0..u64::from(count))
            .map(|index| PackedOrder::Submit {
                session_ref: reference,
                nonce: nonce_base + index,
                client_id: nonce_base + index,
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
                    session_ref: reference,
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
    fn striped_sessions_wait_execute_in_global_order_and_recover() {
        let dir = temp_dir();
        let first = KeyPair::from_seed(&[7; 32]);
        let second = KeyPair::from_seed(&[8; 32]);
        let sessions = vec![session(7, &first, 11, 3), session(8, &second, 12, 35)];
        let batches = [
            batch(7, &first, 11, 3, 100),
            batch(8, &second, 12, 35, 200),
            batch(7, &first, 13, 67, 300),
            batch(8, &second, 14, 99, 400),
        ];
        let journal = PackedBatchJournal::open(&dir, 1024 * 1024).unwrap();
        let mut core = MultiSessionPackedValidatorCore::recover(
            genesis(),
            sessions.clone(),
            journal,
            256,
            256,
            8,
        )
        .unwrap();
        assert_eq!(
            core.readiness(&batches[1]).unwrap(),
            MultiSessionAdmissionReadiness::Wait {
                expected: 3,
                actual: 35
            }
        );
        for (index, bytes) in batches.iter().enumerate() {
            let admitted = core.admit(bytes, 10, 11).unwrap();
            assert_eq!(
                admitted.first_sequence,
                3 + u64::try_from(index).unwrap() * 32
            );
            let executed = core.drive_until_receipt(12).unwrap();
            assert_eq!(executed.first_sequence, admitted.first_sequence);
        }
        assert_eq!(core.next_command_sequence(), 131);
        assert!(matches!(
            core.readiness(&batches[0]),
            Ok(MultiSessionAdmissionReadiness::Stale { .. })
        ));
        let root = core.state_root();
        core.sync().unwrap();
        drop(core);

        let journal = PackedBatchJournal::open(&dir, 1024 * 1024).unwrap();
        let recovered =
            MultiSessionPackedValidatorCore::recover(genesis(), sessions, journal, 256, 256, 8)
                .unwrap();
        assert_eq!(recovered.next_command_sequence(), 131);
        assert_eq!(recovered.state_root(), root);
        drop(recovered);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn invalid_stripe_widths_leave_journal_replay_and_global_readiness_unchanged() {
        let dir = temp_dir();
        let first = KeyPair::from_seed(&[9; 32]);
        let second = KeyPair::from_seed(&[10; 32]);
        let sessions = vec![session(7, &first, 11, 3), session(8, &second, 12, 35)];
        let valid = batch(7, &first, 11, 3, 100);
        let journal = PackedBatchJournal::open(&dir, 1024 * 1024).unwrap();
        let mut core =
            MultiSessionPackedValidatorCore::recover(genesis(), sessions, journal, 256, 256, 8)
                .unwrap();
        let root = core.state_root();

        assert_eq!(
            core.readiness(&valid).unwrap(),
            MultiSessionAdmissionReadiness::Ready
        );
        for (count, partial) in [(31u8, true), (33, false), (64, false)] {
            let invalid = batch_with_count(7, &first, 11, 3, 100, count, partial);
            assert_eq!(
                core.readiness(&invalid).unwrap(),
                MultiSessionAdmissionReadiness::Ready
            );
            assert!(matches!(
                core.admit(&invalid, 10, 11),
                Err(MultiSessionPackedValidatorCoreError::Admission(
                    AuthenticatedPackedIngressError::Authentication(
                        network::AuthenticatedOrderBatchError::BatchWidth {
                            expected: 32,
                            actual
                        }
                    )
                )) if actual == count
            ));
            assert_eq!(core.journal.len(), 0);
            assert_eq!(core.next_command_sequence(), 3);
            let replay = core.sessions.get(&7).unwrap();
            assert_eq!(replay.next_batch_sequence(), 11);
            assert_eq!(replay.next_command_sequence(), SequenceNumber::new(3));
            assert_eq!(core.receipts.pending_batches(), 0);
            assert_eq!(core.receipts.available_capacity(), 8);
            assert_eq!(core.ingress.available_capacity(), 256);
            assert_eq!(core.state_root(), root);
            assert!(core.step(12).unwrap().is_none());
            assert_eq!(
                core.readiness(&valid).unwrap(),
                MultiSessionAdmissionReadiness::Ready
            );
        }

        core.admit(&valid, 13, 14).unwrap();
        assert_eq!(core.journal.len(), 1);
        assert_eq!(core.next_command_sequence(), 35);
        core.drive_until_receipt(15).unwrap();
        drop(core);
        let _ = std::fs::remove_dir_all(dir);
    }
}

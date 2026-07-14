//! Durable authenticated packed admission before shard publication.

use std::path::Path;

use storage::{DurableConfig, DurableError, DurableLog, Record, SyncPolicy};

use crate::{
    AuthenticatedPackedBatchIngress, AuthenticatedPackedIngressError, PackedBatchAdmission,
    PackedIngressError, PackedSession, ShardIngress,
};

/// WAL discriminator for one exact authenticated `DXOB` batch.
pub const PACKED_BATCH_WAL_COMMAND_TYPE: u16 = 0x0101;

/// Append-only batch journal whose record sequence is a local journal ordinal.
/// The payload retains the canonical command range and replay bindings.
pub struct PackedBatchJournal {
    log: DurableLog,
    next_entry_sequence: u64,
}

impl PackedBatchJournal {
    /// Open/recover an always-synchronous production journal.
    pub fn open(
        dir: impl AsRef<Path>,
        segment_max_bytes: usize,
    ) -> Result<Self, PackedBatchJournalError> {
        let log = DurableLog::open(
            DurableConfig::new(dir.as_ref().to_path_buf())
                .with_sync(SyncPolicy::Always)
                .with_segment_max_bytes(segment_max_bytes),
        )?;
        let next_entry_sequence = match log.last_sequence() {
            Some(last) => last
                .checked_add(1)
                .ok_or(PackedBatchJournalError::SequenceExhausted)?,
            None => 0,
        };
        Ok(Self {
            log,
            next_entry_sequence,
        })
    }

    /// Append and `fdatasync` exact authenticated bytes before publication.
    pub fn append_batch(
        &mut self,
        authenticated_bytes: &[u8],
        sequencer_now: u64,
    ) -> Result<u64, PackedBatchJournalError> {
        let sequence = self.next_entry_sequence;
        let next = sequence
            .checked_add(1)
            .ok_or(PackedBatchJournalError::SequenceExhausted)?;
        self.log.append(
            sequence,
            sequencer_now,
            PACKED_BATCH_WAL_COMMAND_TYPE,
            authenticated_bytes,
        )?;
        self.next_entry_sequence = next;
        Ok(sequence)
    }

    /// Force the active segment to stable storage during post-drain shutdown.
    pub fn sync(&mut self) -> Result<(), PackedBatchJournalError> {
        self.log.sync()?;
        Ok(())
    }

    /// Visit verified recovered batch entries in journal order.
    pub fn for_each_recovered<F>(&self, mut visit: F) -> Result<(), PackedBatchJournalError>
    where
        F: FnMut(&Record) -> Result<(), PackedBatchJournalError>,
    {
        for record in self.log.iter() {
            let record = record?;
            if record.command_type != PACKED_BATCH_WAL_COMMAND_TYPE {
                return Err(PackedBatchJournalError::WrongCommandType(
                    record.command_type,
                ));
            }
            visit(&record)?;
        }
        Ok(())
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.log.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.log.is_empty()
    }

    #[must_use]
    pub const fn next_entry_sequence(&self) -> u64 {
        self.next_entry_sequence
    }
}

/// Authenticated admission composed with an always-sync journal.
pub struct DurablePackedBatchIngress {
    authenticated: AuthenticatedPackedBatchIngress,
    journal: PackedBatchJournal,
}

impl DurablePackedBatchIngress {
    #[must_use]
    pub fn new(session: PackedSession, journal: PackedBatchJournal) -> Self {
        Self {
            authenticated: AuthenticatedPackedBatchIngress::new(session),
            journal,
        }
    }

    #[must_use]
    pub fn from_authenticated(
        authenticated: AuthenticatedPackedBatchIngress,
        journal: PackedBatchJournal,
    ) -> Self {
        Self {
            authenticated,
            journal,
        }
    }

    /// Validate completely, append+sync, publish, then consume replay state.
    pub fn try_admit(
        &mut self,
        ingress: &mut ShardIngress,
        bytes: &[u8],
        sequencer_now: u64,
    ) -> Result<PackedBatchAdmission, AuthenticatedPackedIngressError> {
        self.try_admit_after(ingress, bytes, sequencer_now, |_| Ok(()))
            .map(|(admission, ())| admission)
    }

    /// Run a caller's non-mutating admission preflight before append+sync. A
    /// successful preflight is followed by the journal barrier, SPSC publication,
    /// and replay commit in that order; its output is returned only after all
    /// three commits succeed.
    pub fn try_admit_after<F, T>(
        &mut self,
        ingress: &mut ShardIngress,
        bytes: &[u8],
        sequencer_now: u64,
        before_journal: F,
    ) -> Result<(PackedBatchAdmission, T), AuthenticatedPackedIngressError>
    where
        F: FnOnce(PackedBatchAdmission) -> Result<T, PackedIngressError>,
    {
        let journal = &mut self.journal;
        self.authenticated
            .try_admit_after(ingress, bytes, sequencer_now, |admission| {
                let output = before_journal(admission)?;
                journal
                    .append_batch(bytes, sequencer_now)
                    .map(|_| ())
                    .map_err(|error| PackedIngressError::Durability(error.to_string()))?;
                Ok(output)
            })
    }

    #[must_use]
    pub const fn journal(&self) -> &PackedBatchJournal {
        &self.journal
    }

    #[must_use]
    pub const fn next_batch_sequence(&self) -> u64 {
        self.authenticated.next_batch_sequence()
    }

    #[must_use]
    pub const fn next_command_sequence(&self) -> types::SequenceNumber {
        self.authenticated.next_command_sequence()
    }

    pub fn sync(&mut self) -> Result<(), PackedBatchJournalError> {
        self.journal.sync()
    }
}

/// Durable packed-journal open, recovery, or append failure.
#[derive(Debug, thiserror::Error)]
pub enum PackedBatchJournalError {
    #[error(transparent)]
    Storage(#[from] DurableError),
    #[error("packed batch journal sequence exhausted")]
    SequenceExhausted,
    #[error("unexpected WAL command type {0} in packed batch journal")]
    WrongCommandType(u16),
    #[error("packed batch recovery failed: {0}")]
    Recovery(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::PackedOrder;
    use crypto::KeyPair;
    use execution::{CreateAccount, CreateMarket, DeterministicEngine, Engine, EngineConfig};
    use network::{AuthenticatedOrderBatchCodec, OrderBatchBinding};
    use types::{
        AccountId, Amount, MarketId, MarketType, OrderType, Price, Quantity, Ratio, SequenceNumber,
        Side, TimeInForce, RATIO_SCALE,
    };

    fn temp_dir() -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "dexos-durable-packed-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    fn engine() -> Engine {
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

    fn signed_batch(signer: &KeyPair) -> Vec<u8> {
        let records: Vec<_> = (0..32)
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
        let len = codec::encode_batch_into(&records, &mut packed).unwrap();
        AuthenticatedOrderBatchCodec::new()
            .encode(
                OrderBatchBinding {
                    destination: [5; 32],
                    session_ref: 7,
                    account: AccountId::new(0),
                    batch_sequence: 11,
                    first_sequence: 3,
                },
                signer,
                32,
                false,
                &packed[..len],
            )
            .unwrap()
            .bytes
            .to_vec()
    }

    #[test]
    fn synced_journal_precedes_publication_and_recovers_exact_bytes() {
        let dir = temp_dir();
        let signer = KeyPair::from_seed(&[4; 32]);
        let bytes = signed_batch(&signer);
        let session = PackedSession {
            destination: [5; 32],
            session_ref: 7,
            account: AccountId::new(0),
            signer: signer.public(),
            authority: crate::PackedAuthority::Master,
            first_batch_sequence: 11,
            first_command_sequence: SequenceNumber::new(3),
            batch_sequence_stride: 1,
            command_sequence_stride: 0,
        };
        let journal = PackedBatchJournal::open(&dir, 1024 * 1024).unwrap();
        let mut durable = DurablePackedBatchIngress::new(session, journal);
        let (mut ingress, mut worker, _) = crate::shard_pipeline(engine(), 64, 64).unwrap();

        let admitted = durable.try_admit(&mut ingress, &bytes, 99).unwrap();
        assert_eq!(admitted.batch_sequence, Some(11));
        assert_eq!(durable.journal().len(), 1);
        let mut recovered = 0;
        durable
            .journal()
            .for_each_recovered(|record| {
                assert_eq!(record.sequence, 0);
                assert_eq!(record.timestamp, 99);
                assert_eq!(record.payload, bytes);
                recovered += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(recovered, 1);
        assert_eq!(worker.step(), crate::ShardStep::Processed);
        assert!(durable.try_admit(&mut ingress, &bytes, 100).is_err());
        assert_eq!(durable.journal().len(), 1, "replay must not append twice");

        drop(durable);
        let reopened = PackedBatchJournal::open(&dir, 1024 * 1024).unwrap();
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened.next_entry_sequence(), 1);
        drop(reopened);
        let _ = std::fs::remove_dir_all(dir);
    }
}

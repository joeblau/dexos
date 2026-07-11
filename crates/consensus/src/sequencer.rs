//! Continuous, gap-free command sequencing for a single shard.
//!
//! The [`Sequencer`] assigns strictly monotonic [`SequenceNumber`]s to accepted
//! commands. Because numbers are handed out by appending, the local stream is
//! gap-free by construction; [`Sequencer::ingest`] additionally validates an
//! externally-numbered stream (replay / cross-node) and reports the first gap.
//!
//! Each command carries a [`CommandStatus`] that advances monotonically through
//! `Accepted -> Executed -> Certified -> Finalized`. Transitions never move
//! backwards; an attempt to do so is a typed error rather than a silent no-op.

use serde::{Deserialize, Serialize};

use crypto::merkle_root;
use types::{Hash, SequenceNumber, ShardId};

/// Lifecycle status of a sequenced command.
///
/// Ranks are total-ordered so a transition is valid iff it strictly increases
/// the rank (no backward moves, no repeats).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CommandStatus {
    /// Assigned a sequence number and admitted to the log.
    Accepted,
    /// Deterministically executed against state.
    Executed,
    /// Covered by a quorum certificate.
    Certified,
    /// Irreversibly committed.
    Finalized,
}

impl CommandStatus {
    /// Monotonic rank used to police forward-only transitions.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            CommandStatus::Accepted => 0,
            CommandStatus::Executed => 1,
            CommandStatus::Certified => 2,
            CommandStatus::Finalized => 3,
        }
    }
}

/// A sequencing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SequencerError {
    /// The `u64` sequence space is exhausted.
    #[error("sequence space exhausted")]
    Exhausted,
    /// An ingested sequence number skipped (or repeated) the expected value.
    #[error("sequence gap: expected {expected}, got {got}")]
    Gap {
        /// The next contiguous sequence the sequencer expected.
        expected: u64,
        /// The sequence that was actually presented.
        got: u64,
    },
    /// A referenced sequence number is not present in the log.
    #[error("unknown sequence {0}")]
    UnknownSequence(u64),
    /// A status transition did not strictly advance the lifecycle.
    #[error("invalid status transition for sequence {sequence}: {from:?} -> {to:?}")]
    InvalidTransition {
        /// The sequence whose transition was rejected.
        sequence: u64,
        /// Current status.
        from: CommandStatus,
        /// Requested status.
        to: CommandStatus,
    },
    /// A range was specified with `last < first`.
    #[error("range out of order: [{first}, {last}]")]
    RangeOutOfOrder {
        /// Requested range start.
        first: u64,
        /// Requested range end.
        last: u64,
    },
}

/// A single sequenced command record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRecord {
    /// The assigned sequence number.
    pub sequence: SequenceNumber,
    /// A commitment to the command payload.
    pub command_hash: Hash,
    /// Current lifecycle status.
    pub status: CommandStatus,
}

/// A per-shard continuous sequencer.
///
/// Records are stored densely so that index == sequence number; the log is
/// therefore gap-free by construction.
#[derive(Debug, Clone)]
pub struct Sequencer {
    shard_id: ShardId,
    records: Vec<CommandRecord>,
}

impl Sequencer {
    /// Create an empty sequencer for `shard_id`, starting at sequence zero.
    #[must_use]
    pub fn new(shard_id: ShardId) -> Self {
        Self {
            shard_id,
            records: Vec::new(),
        }
    }

    /// The shard this sequencer serves.
    #[must_use]
    pub fn shard_id(&self) -> ShardId {
        self.shard_id
    }

    /// Number of sequenced commands.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the log is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The next sequence number that will be assigned.
    ///
    /// Returns [`SequencerError::Exhausted`] if the space is full.
    pub fn next_sequence(&self) -> Result<SequenceNumber, SequencerError> {
        u64::try_from(self.records.len())
            .map(SequenceNumber::new)
            .map_err(|_| SequencerError::Exhausted)
    }

    /// Assign the next sequence number to `command_hash` and admit it as
    /// [`CommandStatus::Accepted`]. Deterministic: repeated identical call
    /// sequences produce identical numbering.
    pub fn accept(&mut self, command_hash: Hash) -> Result<SequenceNumber, SequencerError> {
        let seq = self.next_sequence()?;
        self.records.push(CommandRecord {
            sequence: seq,
            command_hash,
            status: CommandStatus::Accepted,
        });
        Ok(seq)
    }

    /// Ingest an externally-numbered command, enforcing contiguity.
    ///
    /// Returns [`SequencerError::Gap`] if `sequence` is not exactly the next
    /// expected value — this is how replayed / cross-node streams surface gaps
    /// and duplicates.
    pub fn ingest(
        &mut self,
        sequence: SequenceNumber,
        command_hash: Hash,
    ) -> Result<(), SequencerError> {
        let expected = self.next_sequence()?;
        if sequence != expected {
            return Err(SequencerError::Gap {
                expected: expected.get(),
                got: sequence.get(),
            });
        }
        self.records.push(CommandRecord {
            sequence,
            command_hash,
            status: CommandStatus::Accepted,
        });
        Ok(())
    }

    /// The record for `sequence`, if present.
    #[must_use]
    pub fn record(&self, sequence: SequenceNumber) -> Option<&CommandRecord> {
        let idx = usize::try_from(sequence.get()).ok()?;
        self.records.get(idx)
    }

    /// The status of `sequence`, if present.
    #[must_use]
    pub fn status(&self, sequence: SequenceNumber) -> Option<CommandStatus> {
        self.record(sequence).map(|r| r.status)
    }

    /// Advance `sequence` to `to`, requiring a strictly forward transition.
    pub fn advance(
        &mut self,
        sequence: SequenceNumber,
        to: CommandStatus,
    ) -> Result<(), SequencerError> {
        let idx = usize::try_from(sequence.get())
            .map_err(|_| SequencerError::UnknownSequence(sequence.get()))?;
        let record = self
            .records
            .get_mut(idx)
            .ok_or(SequencerError::UnknownSequence(sequence.get()))?;
        if to.rank() <= record.status.rank() {
            return Err(SequencerError::InvalidTransition {
                sequence: sequence.get(),
                from: record.status,
                to,
            });
        }
        record.status = to;
        Ok(())
    }

    /// Convenience: mark `sequence` executed.
    pub fn mark_executed(&mut self, sequence: SequenceNumber) -> Result<(), SequencerError> {
        self.advance(sequence, CommandStatus::Executed)
    }

    /// Convenience: mark `sequence` certified.
    pub fn mark_certified(&mut self, sequence: SequenceNumber) -> Result<(), SequencerError> {
        self.advance(sequence, CommandStatus::Certified)
    }

    /// Convenience: mark `sequence` finalized.
    pub fn mark_finalized(&mut self, sequence: SequenceNumber) -> Result<(), SequencerError> {
        self.advance(sequence, CommandStatus::Finalized)
    }

    /// Merkle root over the command hashes in the inclusive range
    /// `[first, last]`. Deterministic and gap-free over the covered range.
    pub fn command_root(
        &self,
        first: SequenceNumber,
        last: SequenceNumber,
    ) -> Result<Hash, SequencerError> {
        if last.get() < first.get() {
            return Err(SequencerError::RangeOutOfOrder {
                first: first.get(),
                last: last.get(),
            });
        }
        let mut leaves: Vec<Hash> = Vec::new();
        let mut cur = first.get();
        loop {
            let idx = usize::try_from(cur).map_err(|_| SequencerError::UnknownSequence(cur))?;
            let record = self
                .records
                .get(idx)
                .ok_or(SequencerError::UnknownSequence(cur))?;
            leaves.push(record.command_hash);
            if cur == last.get() {
                break;
            }
            cur = cur
                .checked_add(1)
                .ok_or(SequencerError::UnknownSequence(cur))?;
        }
        Ok(merkle_root(&leaves))
    }
}

/// Detect the first gap in an arbitrary (possibly cross-shard) list of sequence
/// numbers expected to be contiguous from `start`.
///
/// Returns `Some((expected, got))` at the first divergence, or `None` if the
/// list is strictly contiguous.
#[must_use]
pub fn detect_gap(start: SequenceNumber, seqs: &[SequenceNumber]) -> Option<(u64, u64)> {
    let mut expected = start.get();
    for s in seqs {
        if s.get() != expected {
            return Some((expected, s.get()));
        }
        expected = expected.wrapping_add(1);
    }
    None
}

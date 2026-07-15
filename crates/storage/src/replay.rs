//! Deterministic replay driver.
//!
//! [`replay`] feeds log records to a caller-supplied `apply` closure in strict
//! sequence order, starting immediately after an optional base snapshot. The
//! storage layer owns ordering, checksum verification, and gap/reorder
//! detection; the actual state transition (`apply`) belongs to the engine and is
//! injected by the caller, which keeps `storage` free of any engine dependency
//! and makes replay bit-for-bit reproducible.

use std::convert::Infallible;

use crate::log::{LogError, SegmentedLog};
use crate::record::Record;
use crate::snapshot::Snapshot;

/// Lossless replay failure that keeps source and application errors distinct.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplayError<S, A> {
    /// Reading, decoding, or sequence validation failed.
    #[error("replay source failed: {0}")]
    Source(#[source] S),
    /// The application rejected the record at `sequence`.
    #[error("replay application failed at sequence {sequence}: {error}")]
    Apply {
        /// Exact record sequence passed to the application.
        sequence: u64,
        /// Original application error, preserved without string erasure.
        error: A,
    },
}

/// Replay `log` into `apply`, resuming after `from_snapshot` if provided.
///
/// Records already covered by the snapshot (`sequence <= snapshot.last_sequence`)
/// are skipped. The first applied record must be exactly one past the snapshot
/// (or, with no snapshot, becomes the baseline); every subsequent record must be
/// strictly consecutive. A missing sequence yields [`LogError::SequenceGap`] and
/// a rewind yields [`LogError::OutOfOrder`] — in both cases nothing is applied
/// for the offending record.
///
/// Returns the highest sequence number applied (or the snapshot's sequence, or
/// `0`, if nothing was applied).
///
/// # Errors
/// Returns the first [`LogError`] from decoding, checksum verification, or
/// sequence continuity checking.
pub fn replay<F>(
    log: &SegmentedLog,
    from_snapshot: Option<&Snapshot>,
    mut apply: F,
) -> Result<u64, LogError>
where
    F: FnMut(Record),
{
    match try_replay(log, from_snapshot, |record| {
        apply(record);
        Ok::<(), Infallible>(())
    }) {
        Ok(sequence) => Ok(sequence),
        Err(ReplayError::Source(error)) => Err(error),
        Err(ReplayError::Apply { error, .. }) => match error {},
    }
}

/// Fallibly replay `log` into `apply`, resuming after `from_snapshot`.
///
/// Source failures and application failures remain distinct in
/// [`ReplayError`]. On an application failure, the offending sequence is
/// reported, no later record is visited, and replay bookkeeping advances only
/// after `apply` returns `Ok(())`.
///
/// The storage layer cannot roll back mutations performed inside `apply` before
/// it returns an error. Callers restoring authoritative state must therefore
/// make each injected transition atomic (or discard the in-memory state on any
/// failure).
///
/// # Errors
/// Returns the first [`LogError`] as [`ReplayError::Source`], or the exact
/// application error as [`ReplayError::Apply`].
pub fn try_replay<F, A>(
    log: &SegmentedLog,
    from_snapshot: Option<&Snapshot>,
    mut apply: F,
) -> Result<u64, ReplayError<LogError, A>>
where
    F: FnMut(Record) -> Result<(), A>,
{
    let base = from_snapshot.map(Snapshot::last_sequence);
    let mut last_applied = base;

    for item in log.iter() {
        let rec = item.map_err(ReplayError::Source)?;

        // Skip anything already captured by the snapshot.
        if let Some(b) = base {
            if rec.sequence <= b {
                continue;
            }
        }

        if let Some(previous) = last_applied {
            let Some(expected) = previous.checked_add(1) else {
                return Err(ReplayError::Source(LogError::OutOfOrder {
                    last: previous,
                    got: rec.sequence,
                }));
            };
            if rec.sequence != expected {
                return Err(ReplayError::Source(if rec.sequence > expected {
                    LogError::SequenceGap {
                        expected,
                        got: rec.sequence,
                    }
                } else {
                    LogError::OutOfOrder {
                        last: previous,
                        got: rec.sequence,
                    }
                }));
            }
        }

        let sequence = rec.sequence;
        apply(rec).map_err(|error| ReplayError::Apply { sequence, error })?;
        last_applied = Some(sequence);
    }

    Ok(last_applied.unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::Hash;

    fn build_log(seqs: &[u64]) -> SegmentedLog {
        let mut log = SegmentedLog::new(64);
        for &s in seqs {
            log.append(s, s, 1, format!("cmd{s}").as_bytes()).unwrap();
        }
        log
    }

    /// A trivial deterministic "engine": folds record bytes into a rolling root.
    fn fold_root(seqs: &[u64]) -> Hash {
        let log = build_log(seqs);
        let mut acc = Hash::ZERO;
        replay(&log, None, |rec| {
            let mut buf = acc.as_bytes().to_vec();
            buf.extend_from_slice(&rec.sequence.to_le_bytes());
            buf.extend_from_slice(&rec.payload);
            acc = crypto::hash_leaf(&buf);
        })
        .unwrap();
        acc
    }

    #[test]
    fn deterministic_replay_reproduces_root() {
        let a = fold_root(&[1, 2, 3, 4, 5]);
        let b = fold_root(&[1, 2, 3, 4, 5]);
        assert_eq!(a, b);
        // A different history yields a different root.
        assert_ne!(a, fold_root(&[1, 2, 3, 4]));
    }

    #[test]
    fn replay_resumes_after_snapshot() {
        let log = build_log(&[1, 2, 3, 4, 5]);
        let snap = Snapshot::new(Hash::from_bytes([9; 32]), 3, b"state-at-3".to_vec());
        let mut applied = Vec::new();
        let last = replay(&log, Some(&snap), |rec| applied.push(rec.sequence)).unwrap();
        assert_eq!(applied, vec![4, 5]);
        assert_eq!(last, 5);
    }

    #[test]
    fn replay_with_empty_tail_returns_snapshot_seq() {
        let log = build_log(&[1, 2, 3]);
        let snap = Snapshot::new(Hash::ZERO, 3, Vec::new());
        let last = replay(&log, Some(&snap), |_| {}).unwrap();
        assert_eq!(last, 3);
    }

    #[test]
    fn gap_is_rejected() {
        let log = build_log(&[1, 2, 4]); // missing 3
        let err = replay(&log, None, |_| {}).unwrap_err();
        assert!(matches!(
            err,
            LogError::SequenceGap {
                expected: 3,
                got: 4
            }
        ));
    }

    #[test]
    fn gap_after_snapshot_is_rejected() {
        let log = build_log(&[1, 2, 3, 5]); // missing 4
        let snap = Snapshot::new(Hash::ZERO, 3, Vec::new());
        let err = replay(&log, Some(&snap), |_| {}).unwrap_err();
        assert!(matches!(
            err,
            LogError::SequenceGap {
                expected: 4,
                got: 5
            }
        ));
    }

    #[test]
    fn fallible_replay_preserves_apply_error_and_stops() {
        let log = build_log(&[1, 2, 3, 4]);
        let mut applied = Vec::new();
        let error = try_replay(&log, None, |record| {
            if record.sequence == 3 {
                return Err("transition rejected");
            }
            applied.push(record.sequence);
            Ok(())
        })
        .unwrap_err();

        assert_eq!(
            error,
            ReplayError::Apply {
                sequence: 3,
                error: "transition rejected",
            }
        );
        assert_eq!(applied, vec![1, 2]);
    }

    #[test]
    fn fallible_replay_keeps_source_errors_distinct() {
        let log = build_log(&[1, 3]);
        let error = try_replay(&log, None, |_| Ok::<(), &str>(())).unwrap_err();
        assert_eq!(
            error,
            ReplayError::Source(LogError::SequenceGap {
                expected: 2,
                got: 3,
            })
        );
        assert!(std::error::Error::source(&error).is_some());
    }
}

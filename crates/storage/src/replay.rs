//! Deterministic replay driver.
//!
//! [`replay`] feeds log records to a caller-supplied `apply` closure in strict
//! sequence order, starting immediately after an optional base snapshot. The
//! storage layer owns ordering, checksum verification, and gap/reorder
//! detection; the actual state transition (`apply`) belongs to the engine and is
//! injected by the caller, which keeps `storage` free of any engine dependency
//! and makes replay bit-for-bit reproducible.

use crate::log::{LogError, SegmentedLog};
use crate::record::Record;
use crate::snapshot::Snapshot;

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
    let base = from_snapshot.map(Snapshot::last_sequence);
    // `expected` is the sequence the next applied record must carry, once known.
    let mut expected: Option<u64> = base.map(|b| b.saturating_add(1));
    let mut last_applied = base.unwrap_or(0);

    for item in log.iter() {
        let rec = item?;

        // Skip anything already captured by the snapshot.
        if let Some(b) = base {
            if rec.sequence <= b {
                continue;
            }
        }

        match expected {
            Some(exp) if rec.sequence != exp => {
                return Err(if rec.sequence > exp {
                    LogError::SequenceGap {
                        expected: exp,
                        got: rec.sequence,
                    }
                } else {
                    LogError::OutOfOrder {
                        last: exp.saturating_sub(1),
                        got: rec.sequence,
                    }
                });
            }
            Some(_) => {}
            None => {
                // No snapshot: the first record establishes the baseline.
            }
        }

        last_applied = rec.sequence;
        expected = rec.sequence.checked_add(1);
        apply(rec);
    }

    Ok(last_applied)
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
}

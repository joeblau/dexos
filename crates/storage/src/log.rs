//! A segmented, append-only command log held in memory.
//!
//! The log is a `Vec<Segment>`; each [`Segment`] is a contiguous byte buffer of
//! framed [`Record`]s. When appending a record would push the active segment
//! past its configured byte budget a new segment is started, but global
//! sequence numbers stay monotonic across the segment boundary.
//!
//! Reads re-decode and re-verify every record's checksum, so corruption on disk
//! (modelled here as a mutated byte buffer) is caught at read time and surfaced
//! as a typed [`LogError`] rather than silently applied.
//!
//! Find uses binary search over segment metadata plus a sparse per-segment
//! offset index; truncation drops/truncates only the removed suffix rather than
//! rebuilding the retained prefix. For OS-backed durability see
//! [`crate::DurableLog`].

use crate::limits::{DEFAULT_INDEX_STRIDE, DEFAULT_MAX_RECORD_BYTES};
use crate::record::{decode_ref_bounded, Record, RecordError, RecordRef, FRAME_OVERHEAD};

/// Default per-segment byte budget: 64 MiB.
pub const DEFAULT_SEGMENT_BYTES: usize = 64 * 1024 * 1024;

/// Number of bytes in one mebibyte, for the `*_mb` convenience constructors.
const BYTES_PER_MB: usize = 1024 * 1024;

/// Errors produced while appending to or reading back the log.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LogError {
    /// A record failed to encode or decode / verify.
    #[error("record error: {0}")]
    Record(#[from] RecordError),
    /// A sequence number was skipped (a record is missing).
    #[error("sequence gap: expected {expected}, found {got}")]
    SequenceGap {
        /// The sequence number that was expected next.
        expected: u64,
        /// The sequence number actually encountered.
        got: u64,
    },
    /// A record arrived with a sequence at or below the previous one.
    #[error("out-of-order sequence: last was {last}, got {got}")]
    OutOfOrder {
        /// The previously observed sequence number.
        last: u64,
        /// The offending sequence number.
        got: u64,
    },
    /// A lookup did not find the requested sequence number.
    #[error("sequence {0} not found in log")]
    NotFound(u64),
}

/// Sparse index: sequence at a byte offset within the segment.
#[derive(Debug, Clone, Copy)]
struct IndexPoint {
    sequence: u64,
    offset: usize,
}

/// A single append-only segment: a contiguous buffer of framed records.
#[derive(Debug, Clone, Default)]
pub struct Segment {
    /// Ordinal index of this segment within the log (0-based).
    index: u64,
    /// Sequence number of the first record in this segment.
    base_sequence: u64,
    /// Sequence number of the last record appended, if any.
    last_sequence: Option<u64>,
    /// Number of records in this segment.
    count: usize,
    /// Concatenated framed record bytes.
    bytes: Vec<u8>,
    /// Sparse (sequence, offset) points for bounded local find scans.
    index_points: Vec<IndexPoint>,
}

impl Segment {
    /// Stable, sortable file-style name for this segment.
    ///
    /// The name encodes the base sequence so segments sort in log order.
    #[must_use]
    pub fn name(&self) -> String {
        format!("seg-{:020}.log", self.base_sequence)
    }

    /// Ordinal index of this segment within the log.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Sequence number of the first record in this segment.
    #[must_use]
    pub const fn base_sequence(&self) -> u64 {
        self.base_sequence
    }

    /// Sequence number of the last record in this segment, if any.
    #[must_use]
    pub const fn last_sequence(&self) -> Option<u64> {
        self.last_sequence
    }

    /// Number of records in this segment.
    #[must_use]
    pub const fn record_count(&self) -> usize {
        self.count
    }

    /// Size of this segment's byte buffer.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the segment holds no records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Borrow the raw framed bytes (for inspection / archival).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// An in-memory segmented append-only log.
#[derive(Debug, Clone)]
pub struct SegmentedLog {
    segments: Vec<Segment>,
    segment_max_bytes: usize,
    max_record_bytes: usize,
    index_stride: usize,
    last_sequence: Option<u64>,
    total_records: usize,
}

impl Default for SegmentedLog {
    fn default() -> Self {
        Self::new(DEFAULT_SEGMENT_BYTES)
    }
}

impl SegmentedLog {
    /// Create an empty log whose segments roll over at `segment_max_bytes`.
    ///
    /// A value of zero is treated as "one record per segment" (each append that
    /// lands in a non-empty segment rotates), which keeps rotation well-defined.
    #[must_use]
    pub fn new(segment_max_bytes: usize) -> Self {
        Self {
            segments: Vec::new(),
            segment_max_bytes,
            max_record_bytes: DEFAULT_MAX_RECORD_BYTES,
            index_stride: DEFAULT_INDEX_STRIDE,
            last_sequence: None,
            total_records: 0,
        }
    }

    /// Create an empty log whose segments roll over at `mb` mebibytes.
    #[must_use]
    pub fn with_segment_size_mb(mb: usize) -> Self {
        Self::new(mb.saturating_mul(BYTES_PER_MB))
    }

    /// Override the maximum encoded record size accepted on append/decode.
    #[must_use]
    pub fn with_max_record_bytes(mut self, n: usize) -> Self {
        self.max_record_bytes = n.max(FRAME_OVERHEAD);
        self
    }

    /// Override the sparse index stride.
    #[must_use]
    pub fn with_index_stride(mut self, n: usize) -> Self {
        self.index_stride = n.max(1);
        self
    }

    /// Append a command to the log.
    ///
    /// The `payload` is stored opaquely. Sequence numbers must strictly
    /// increase; a duplicate or out-of-order sequence is rejected with
    /// [`LogError::OutOfOrder`]. Gaps (a jump greater than one) are permitted at
    /// append time and detected later by [`Self::verify`] / replay, which lets a
    /// caller reconstruct and diagnose a damaged log.
    ///
    /// # Errors
    /// Returns [`LogError::OutOfOrder`] on a non-increasing sequence, or a
    /// [`LogError::Record`] if the payload is too large to frame.
    pub fn append(
        &mut self,
        sequence: u64,
        timestamp: u64,
        command_type: u16,
        payload: &[u8],
    ) -> Result<(), LogError> {
        if let Some(last) = self.last_sequence {
            if sequence <= last {
                return Err(LogError::OutOfOrder {
                    last,
                    got: sequence,
                });
            }
        }

        let framed_len = Record::encoded_len(payload.len());
        if framed_len > self.max_record_bytes {
            return Err(LogError::Record(RecordError::ExceedsMax {
                declared: framed_len,
                max: self.max_record_bytes,
            }));
        }

        // Borrow the caller's payload directly: no owned Record, no payload
        // copy beyond the single copy into `framed`.
        let record_ref = RecordRef {
            protocol_version: crate::record::PROTOCOL_VERSION,
            sequence,
            timestamp,
            command_type,
            payload,
        };
        let mut framed = Vec::with_capacity(framed_len);
        record_ref.encode_into(&mut framed)?;

        let need_new_segment = match self.segments.last() {
            None => true,
            Some(seg) => {
                !seg.is_empty()
                    && seg.byte_len().saturating_add(framed.len()) > self.segment_max_bytes
            }
        };

        if need_new_segment {
            let index = u64::try_from(self.segments.len()).unwrap_or(u64::MAX);
            self.segments.push(Segment {
                index,
                base_sequence: sequence,
                last_sequence: None,
                count: 0,
                bytes: Vec::new(),
                index_points: Vec::new(),
            });
        }

        // Safe: we just ensured there is at least one segment.
        let stride = self.index_stride.max(1);
        let seg = self
            .segments
            .last_mut()
            .ok_or(LogError::NotFound(sequence))?;
        let offset = seg.bytes.len();
        seg.bytes.extend_from_slice(&framed);
        seg.count += 1;
        if seg.count == 1 {
            seg.base_sequence = sequence;
        }
        seg.last_sequence = Some(sequence);
        if seg.count == 1 || seg.count % stride == 1 {
            seg.index_points.push(IndexPoint { sequence, offset });
        }
        self.last_sequence = Some(sequence);
        self.total_records += 1;
        Ok(())
    }

    /// Total number of records across all segments.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.total_records
    }

    /// Whether the log holds no records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total_records == 0
    }

    /// The highest sequence number appended so far, if any.
    #[must_use]
    pub const fn last_sequence(&self) -> Option<u64> {
        self.last_sequence
    }

    /// Number of segments.
    #[must_use]
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Borrow the segments (for inspection / archival).
    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Iterate decoded records in append order.
    ///
    /// Each item is a per-record decode result: checksums are verified, so a
    /// corrupt record yields `Err(LogError::Record(..))`. Sequence continuity is
    /// **not** enforced here; use [`Self::verify`] or [`crate::replay`] for that.
    #[must_use]
    pub fn iter(&self) -> Records<'_> {
        Records {
            segments: &self.segments,
            max_record_bytes: self.max_record_bytes,
            seg_idx: 0,
            offset: 0,
            done: false,
        }
    }

    /// Verify the whole log: every checksum passes and sequence numbers are
    /// strictly consecutive (no gaps, no reordering).
    ///
    /// # Errors
    /// Returns the first [`LogError`] encountered.
    pub fn verify(&self) -> Result<(), LogError> {
        let mut expected: Option<u64> = None;
        for item in self.iter() {
            let rec = item?;
            if let Some(exp) = expected {
                if rec.sequence != exp {
                    return Err(gap_or_order(exp, rec.sequence));
                }
            }
            expected = rec.sequence.checked_add(1);
        }
        Ok(())
    }

    /// Find and decode the record with the given `sequence`.
    ///
    /// Uses binary search over segment `[base, last]` ranges, then a sparse
    /// offset index with a bounded local scan.
    ///
    /// # Errors
    /// Returns [`LogError::NotFound`] if no such record exists, or a
    /// [`LogError::Record`] if the matching record is corrupt.
    pub fn find(&self, sequence: u64) -> Result<Record, LogError> {
        let seg_idx = self
            .segment_index_for(sequence)
            .ok_or(LogError::NotFound(sequence))?;
        let seg = &self.segments[seg_idx];
        let mut off = sparse_seek(&seg.index_points, sequence).unwrap_or(0);
        while off < seg.bytes.len() {
            let (rref, consumed) = decode_ref_bounded(&seg.bytes[off..], self.max_record_bytes)?;
            if rref.sequence == sequence {
                return Ok(rref.to_owned());
            }
            if rref.sequence > sequence {
                break;
            }
            off += consumed;
        }
        Err(LogError::NotFound(sequence))
    }

    /// Truncate the log so that only records with `sequence <= keep_through`
    /// survive, discarding everything after it.
    ///
    /// Work scales with the removed suffix: later segments are dropped and the
    /// cut segment is byte-truncated at the record boundary. The retained prefix
    /// is not re-encoded.
    ///
    /// # Errors
    /// Returns a [`LogError`] if a surviving record fails to decode (the log was
    /// already corrupt before truncation).
    pub fn truncate_after(&mut self, keep_through: u64) -> Result<(), LogError> {
        while let Some(last) = self.segments.last() {
            if last.base_sequence > keep_through {
                self.total_records = self.total_records.saturating_sub(last.count);
                self.segments.pop();
                continue;
            }
            break;
        }

        if self.segments.is_empty() {
            self.last_sequence = None;
            return Ok(());
        }

        let seg = self.segments.last_mut().expect("non-empty");
        if seg.last_sequence.is_some_and(|ls| ls <= keep_through) {
            self.last_sequence = seg.last_sequence;
            return Ok(());
        }

        // Scan the cut segment only (suffix work relative to retained history).
        let mut off = 0usize;
        let mut kept = 0usize;
        let mut last_seq = None;
        let mut index_points = Vec::new();
        let stride = self.index_stride.max(1);
        let mut base = seg.base_sequence;
        let max = self.max_record_bytes;

        while off < seg.bytes.len() {
            let (rref, consumed) = decode_ref_bounded(&seg.bytes[off..], max)?;
            if rref.sequence > keep_through {
                break;
            }
            if kept == 0 {
                base = rref.sequence;
            }
            kept += 1;
            last_seq = Some(rref.sequence);
            if kept == 1 || kept % stride == 1 {
                index_points.push(IndexPoint {
                    sequence: rref.sequence,
                    offset: off,
                });
            }
            off += consumed;
        }

        let removed = seg.count.saturating_sub(kept);
        self.total_records = self.total_records.saturating_sub(removed);

        if kept == 0 {
            self.segments.pop();
            self.last_sequence = self.segments.last().and_then(|s| s.last_sequence);
            return Ok(());
        }

        seg.bytes.truncate(off);
        seg.count = kept;
        seg.last_sequence = last_seq;
        seg.base_sequence = base;
        seg.index_points = index_points;
        self.last_sequence = last_seq;
        Ok(())
    }

    fn segment_index_for(&self, sequence: u64) -> Option<usize> {
        let mut lo = 0usize;
        let mut hi = self.segments.len();
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let seg = &self.segments[mid];
            let last = seg.last_sequence.unwrap_or(seg.base_sequence);
            if sequence < seg.base_sequence {
                hi = mid;
            } else if sequence > last {
                lo = mid + 1;
            } else {
                return Some(mid);
            }
        }
        None
    }
}

fn sparse_seek(points: &[IndexPoint], sequence: u64) -> Option<usize> {
    if points.is_empty() {
        return Some(0);
    }
    let mut lo = 0usize;
    let mut hi = points.len();
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if points[mid].sequence <= sequence {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let idx = lo.saturating_sub(1);
    Some(points[idx].offset)
}

/// Classify a sequence mismatch as a forward gap or a backward reorder.
fn gap_or_order(expected: u64, got: u64) -> LogError {
    if got > expected {
        LogError::SequenceGap { expected, got }
    } else {
        LogError::OutOfOrder {
            last: expected.saturating_sub(1),
            got,
        }
    }
}

/// Iterator over decoded records across all segments, in append order.
///
/// Yields `Err` and then stops on the first structural or checksum failure.
pub struct Records<'a> {
    segments: &'a [Segment],
    max_record_bytes: usize,
    seg_idx: usize,
    offset: usize,
    done: bool,
}

impl Iterator for Records<'_> {
    type Item = Result<Record, LogError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            let seg = self.segments.get(self.seg_idx)?;
            if self.offset >= seg.byte_len() {
                self.seg_idx += 1;
                self.offset = 0;
                continue;
            }
            let rest = &seg.as_bytes()[self.offset..];
            return match decode_ref_bounded(rest, self.max_record_bytes) {
                Ok((rref, consumed)) => {
                    self.offset += consumed;
                    Some(Ok(rref.to_owned()))
                }
                Err(err) => {
                    self.done = true;
                    Some(Err(LogError::Record(err)))
                }
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drain(log: &SegmentedLog) -> Vec<Record> {
        log.iter().map(|r| r.unwrap()).collect()
    }

    #[test]
    fn append_and_iter_round_trip_in_order() {
        let mut log = SegmentedLog::default();
        for seq in 1..=5u64 {
            let payload = format!("cmd-{seq}");
            log.append(seq, seq * 10, 1, payload.as_bytes()).unwrap();
        }
        let recs = drain(&log);
        assert_eq!(recs.len(), 5);
        for (i, rec) in recs.iter().enumerate() {
            let expected_seq = u64::try_from(i).unwrap() + 1;
            assert_eq!(rec.sequence, expected_seq);
            assert_eq!(rec.payload, format!("cmd-{expected_seq}").into_bytes());
        }
        log.verify().unwrap();
    }

    #[test]
    fn borrowed_append_round_trips_payload_sequence_timestamp() {
        // Appends go through the borrowed RecordRef encode path; decoded
        // records must carry the same payload/sequence/timestamp as before,
        // including an empty payload.
        let mut log = SegmentedLog::default();
        log.append(1, 111, 7, b"").unwrap();
        log.append(2, 222, 9, b"borrowed-hot-path").unwrap();
        let recs = drain(&log);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].sequence, 1);
        assert_eq!(recs[0].timestamp, 111);
        assert_eq!(recs[0].command_type, 7);
        assert!(recs[0].payload.is_empty());
        assert_eq!(recs[1].sequence, 2);
        assert_eq!(recs[1].timestamp, 222);
        assert_eq!(recs[1].command_type, 9);
        assert_eq!(recs[1].payload, b"borrowed-hot-path");
        log.verify().unwrap();
    }

    #[test]
    fn out_of_order_append_rejected() {
        let mut log = SegmentedLog::default();
        log.append(5, 0, 1, b"a").unwrap();
        assert!(matches!(
            log.append(5, 0, 1, b"b"),
            Err(LogError::OutOfOrder { last: 5, got: 5 })
        ));
        assert!(matches!(
            log.append(3, 0, 1, b"c"),
            Err(LogError::OutOfOrder { last: 5, got: 3 })
        ));
    }

    #[test]
    fn segment_rotation_preserves_monotonicity() {
        // Tiny segment budget forces frequent rotation.
        let mut log = SegmentedLog::new(1);
        for seq in 1..=6u64 {
            log.append(seq, 0, 1, b"payload").unwrap();
        }
        // Each record lands in its own segment (budget of 1 byte).
        assert_eq!(log.segment_count(), 6);
        // Global sequence stays monotonic across segments.
        let recs = drain(&log);
        for pair in recs.windows(2) {
            assert!(pair[1].sequence > pair[0].sequence);
        }
        // Segment names sort in sequence order and base sequences ascend.
        let bases: Vec<u64> = log.segments().iter().map(Segment::base_sequence).collect();
        assert_eq!(bases, vec![1, 2, 3, 4, 5, 6]);
        log.verify().unwrap();
    }

    #[test]
    fn multiple_records_per_segment_then_rotate() {
        // Budget fits ~2 small records before rotating.
        let payload = b"pl";
        let one = Record::encoded_len(payload.len());
        let mut log = SegmentedLog::new(one * 2);
        for seq in 1..=5u64 {
            log.append(seq, 0, 1, payload).unwrap();
        }
        assert!(log.segment_count() >= 2);
        assert_eq!(log.len(), 5);
        log.verify().unwrap();
    }

    #[test]
    fn gap_detected_by_verify() {
        let mut log = SegmentedLog::default();
        log.append(1, 0, 1, b"a").unwrap();
        log.append(2, 0, 1, b"b").unwrap();
        // Skip 3.
        log.append(4, 0, 1, b"d").unwrap();
        match log.verify() {
            Err(LogError::SequenceGap {
                expected: 3,
                got: 4,
            }) => {}
            other => panic!("expected gap, got {other:?}"),
        }
    }

    #[test]
    fn corrupt_byte_fails_on_read_with_typed_error() {
        let mut log = SegmentedLog::default();
        log.append(1, 0, 1, b"hello-world").unwrap();
        // Corrupt a payload byte inside the (only) segment's buffer.
        let seg = &mut log.segments[0];
        let idx = seg.bytes.len() - 5;
        seg.bytes[idx] ^= 0xFF;
        let mut saw_error = false;
        for item in log.iter() {
            if let Err(LogError::Record(RecordError::ChecksumMismatch { .. })) = item {
                saw_error = true;
            }
        }
        assert!(saw_error);
        assert!(log.verify().is_err());
    }

    #[test]
    fn find_returns_record_or_not_found() {
        let mut log = SegmentedLog::default().with_index_stride(2);
        for seq in 1..=4u64 {
            log.append(seq, 0, 1, format!("v{seq}").as_bytes()).unwrap();
        }
        assert_eq!(log.find(3).unwrap().payload, b"v3");
        assert!(matches!(log.find(99), Err(LogError::NotFound(99))));
    }

    #[test]
    fn truncate_after_keeps_consistent_prefix() {
        let mut log = SegmentedLog::new(64);
        for seq in 1..=10u64 {
            log.append(seq, seq, 1, b"payload").unwrap();
        }
        // Simulate a torn write: append one more, then truncate it away.
        log.truncate_after(6).unwrap();
        assert_eq!(log.last_sequence(), Some(6));
        let recs = drain(&log);
        assert_eq!(recs.len(), 6);
        for (i, rec) in recs.iter().enumerate() {
            assert_eq!(rec.sequence, u64::try_from(i).unwrap() + 1);
        }
        // Prefix remains fully consistent and replayable.
        log.verify().unwrap();
    }

    #[test]
    fn truncate_after_beyond_end_is_noop() {
        let mut log = SegmentedLog::default();
        for seq in 1..=3u64 {
            log.append(seq, 0, 1, b"x").unwrap();
        }
        log.truncate_after(100).unwrap();
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn truncate_does_not_rebuild_prefix_bytes() {
        // After truncate, retained segment bytes are a prefix of the original
        // (suffix truncate), not a re-encoded copy with different layout.
        let mut log = SegmentedLog::new(4096).with_index_stride(1);
        for seq in 1..=8u64 {
            log.append(seq, 0, 1, format!("body-{seq}").as_bytes())
                .unwrap();
        }
        let prefix_before: Vec<u8> = {
            // Encode the first 5 records independently for comparison length.
            let mut tmp = SegmentedLog::new(4096);
            for seq in 1..=5u64 {
                tmp.append(seq, 0, 1, format!("body-{seq}").as_bytes())
                    .unwrap();
            }
            tmp.segments[0].bytes.clone()
        };
        log.truncate_after(5).unwrap();
        assert_eq!(log.segments[0].bytes, prefix_before);
    }

    #[test]
    fn max_record_bytes_gate() {
        let mut log = SegmentedLog::new(1024).with_max_record_bytes(40);
        let big = vec![0u8; 64];
        assert!(matches!(
            log.append(1, 0, 1, &big),
            Err(LogError::Record(RecordError::ExceedsMax { .. }))
        ));
    }
}

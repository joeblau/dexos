//! Fixed-capacity latency sampling and integer percentile aggregation.
//!
//! Latency samples are nanosecond integers. A [`SampleSet`] holds a bounded number
//! of them; once full it counts further samples as dropped rather than growing without
//! limit or silently discarding them unnoticed. Percentiles use the nearest-rank
//! method on a sorted copy, so results are deterministic and free of floating point.

use serde::{Deserialize, Serialize};

use crate::command::CommandKind;

/// Five-bit sub-bucket precision: 32 linear subdivisions per power-of-two range.
pub const HISTOGRAM_SUB_BUCKETS: usize = 32;
/// Full `u64` nanosecond range split into 64 exponents and 32 subdivisions.
pub const HISTOGRAM_BUCKETS: usize = 64 * HISTOGRAM_SUB_BUCKETS;

/// Terminal and intermediate operation counters for one metric dimension.
///
/// Fields are plain worker-local integers: updates allocate nothing and require no
/// mutex. Interval collection merges snapshots off the trading hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OutcomeCounters {
    pub offered: u64,
    pub generated: u64,
    pub queued: u64,
    pub socket_written: u64,
    pub acknowledged: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub timed_out: u64,
    pub generator_failed: u64,
    pub transport_failed_before_write: u64,
    pub transport_failed_after_write: u64,
    pub protocol_failed: u64,
    pub locally_dropped: u64,
    /// Saturating arithmetic occurred. Any nonzero value invalidates a run.
    pub overflow: u64,
}

impl OutcomeCounters {
    /// Merge another compatible counter set. Saturation is explicit and makes the
    /// resulting report fail conservation rather than silently wrapping.
    pub fn merge(&mut self, other: &Self) {
        macro_rules! add {
            ($field:ident) => {
                match self.$field.checked_add(other.$field) {
                    Some(value) => self.$field = value,
                    None => {
                        self.$field = u64::MAX;
                        self.overflow = self.overflow.saturating_add(1);
                    }
                }
            };
        }
        add!(offered);
        add!(generated);
        add!(queued);
        add!(socket_written);
        add!(acknowledged);
        add!(accepted);
        add!(rejected);
        add!(timed_out);
        add!(generator_failed);
        add!(transport_failed_before_write);
        add!(transport_failed_after_write);
        add!(protocol_failed);
        add!(locally_dropped);
        self.overflow = self.overflow.saturating_add(other.overflow);
    }

    /// Prove the measurement contract's pre-write, post-write, and acknowledgement
    /// equations. This is required before a report can pass.
    pub fn validate_conservation(&self) -> Result<(), ConservationError> {
        if self.overflow != 0 {
            return Err(ConservationError::CounterOverflow(self.overflow));
        }
        let pre_write = self
            .socket_written
            .checked_add(self.locally_dropped)
            .and_then(|v| v.checked_add(self.generator_failed))
            .and_then(|v| v.checked_add(self.transport_failed_before_write))
            .ok_or(ConservationError::CounterOverflow(1))?;
        if self.offered != pre_write {
            return Err(ConservationError::Offered {
                offered: self.offered,
                terminal: pre_write,
            });
        }
        let acknowledged = self
            .accepted
            .checked_add(self.rejected)
            .ok_or(ConservationError::CounterOverflow(1))?;
        if self.acknowledged != acknowledged {
            return Err(ConservationError::Acknowledged {
                acknowledged: self.acknowledged,
                terminal: acknowledged,
            });
        }
        let post_write = acknowledged
            .checked_add(self.timed_out)
            .and_then(|v| v.checked_add(self.transport_failed_after_write))
            .and_then(|v| v.checked_add(self.protocol_failed))
            .ok_or(ConservationError::CounterOverflow(1))?;
        if self.socket_written != post_write {
            return Err(ConservationError::Written {
                written: self.socket_written,
                terminal: post_write,
            });
        }
        if self.generated > self.offered || self.queued > self.generated {
            return Err(ConservationError::ImpossibleIntermediate {
                offered: self.offered,
                generated: self.generated,
                queued: self.queued,
            });
        }
        Ok(())
    }
}

/// A failed counter-conservation invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConservationError {
    #[error("counter overflow/saturation occurred {0} time(s)")]
    CounterOverflow(u64),
    #[error("offered counter mismatch: offered={offered}, pre-write outcomes={terminal}")]
    Offered { offered: u64, terminal: u64 },
    #[error(
        "acknowledged counter mismatch: acknowledged={acknowledged}, accepted+rejected={terminal}"
    )]
    Acknowledged { acknowledged: u64, terminal: u64 },
    #[error("socket-written counter mismatch: written={written}, terminal outcomes={terminal}")]
    Written { written: u64, terminal: u64 },
    #[error(
        "impossible intermediate counters: offered={offered}, generated={generated}, queued={queued}"
    )]
    ImpossibleIntermediate {
        offered: u64,
        generated: u64,
        queued: u64,
    },
}

/// Per-action counters. One instance can be owned by each worker/region/endpoint
/// dimension without adding a global lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ActionCounters {
    pub new_order: OutcomeCounters,
    pub cancel: OutcomeCounters,
    pub replace: OutcomeCounters,
}

/// Worker-local latency histograms split by trading action. Construction is a
/// startup cost; recording and merging retain the fixed-memory histogram contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionHistograms {
    pub new_order: LatencyHistogram,
    pub cancel: LatencyHistogram,
    pub replace: LatencyHistogram,
}

impl ActionHistograms {
    #[must_use]
    pub fn new(max_trackable_ns: u64) -> Self {
        Self {
            new_order: LatencyHistogram::new(max_trackable_ns),
            cancel: LatencyHistogram::new(max_trackable_ns),
            replace: LatencyHistogram::new(max_trackable_ns),
        }
    }

    pub fn for_kind_mut(&mut self, kind: CommandKind) -> &mut LatencyHistogram {
        match kind {
            CommandKind::NewOrder => &mut self.new_order,
            CommandKind::Cancel => &mut self.cancel,
            CommandKind::Replace => &mut self.replace,
        }
    }

    pub fn merge(&mut self, other: &Self) -> Result<(), HistogramMergeError> {
        self.new_order.merge(&other.new_order)?;
        self.cancel.merge(&other.cancel)?;
        self.replace.merge(&other.replace)
    }
}

impl ActionCounters {
    pub fn for_kind_mut(&mut self, kind: CommandKind) -> &mut OutcomeCounters {
        match kind {
            CommandKind::NewOrder => &mut self.new_order,
            CommandKind::Cancel => &mut self.cancel,
            CommandKind::Replace => &mut self.replace,
        }
    }

    #[must_use]
    pub fn total(&self) -> OutcomeCounters {
        let mut total = self.new_order;
        total.merge(&self.cancel);
        total.merge(&self.replace);
        total
    }
}

/// Fixed-memory, mergeable nanosecond histogram.
///
/// Values are placed into 32 sub-buckets per power-of-two range (about 3.125%
/// relative precision at ranges above 32ns). Recording touches only worker-local
/// integers and performs no allocation, I/O, locking, or sorting. Values above the
/// configured ceiling enter the ceiling bucket and increment `saturated`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatencyHistogram {
    max_trackable_ns: u64,
    buckets: Box<[u64; HISTOGRAM_BUCKETS]>,
    count: u64,
    max: u64,
    saturated: u64,
    overflow: u64,
}

impl LatencyHistogram {
    #[must_use]
    pub fn new(max_trackable_ns: u64) -> Self {
        Self {
            max_trackable_ns: max_trackable_ns.max(1),
            buckets: zeroed_histogram_buckets(),
            count: 0,
            max: 0,
            saturated: 0,
            overflow: 0,
        }
    }

    /// Record one latency. This method is allocation-free and non-blocking.
    pub fn record(&mut self, value_ns: u64) {
        self.max = self.max.max(value_ns);
        let tracked = value_ns.min(self.max_trackable_ns);
        if value_ns > self.max_trackable_ns {
            self.saturated = self.saturated.saturating_add(1);
        }
        let index = histogram_index(tracked);
        match self.buckets[index].checked_add(1) {
            Some(value) => self.buckets[index] = value,
            None => self.overflow = self.overflow.saturating_add(1),
        }
        match self.count.checked_add(1) {
            Some(value) => self.count = value,
            None => self.overflow = self.overflow.saturating_add(1),
        }
    }

    /// Merge raw buckets. Percentiles are deliberately computed only after merge.
    pub fn merge(&mut self, other: &Self) -> Result<(), HistogramMergeError> {
        if self.max_trackable_ns != other.max_trackable_ns {
            return Err(HistogramMergeError::IncompatibleRange {
                left: self.max_trackable_ns,
                right: other.max_trackable_ns,
            });
        }
        for (left, right) in self.buckets.iter_mut().zip(other.buckets.iter()) {
            match left.checked_add(*right) {
                Some(value) => *left = value,
                None => {
                    *left = u64::MAX;
                    self.overflow = self.overflow.saturating_add(1);
                }
            }
        }
        self.count = match self.count.checked_add(other.count) {
            Some(value) => value,
            None => {
                self.overflow = self.overflow.saturating_add(1);
                u64::MAX
            }
        };
        self.saturated = self.saturated.saturating_add(other.saturated);
        self.overflow = self.overflow.saturating_add(other.overflow);
        self.max = self.max.max(other.max);
        Ok(())
    }

    #[must_use]
    pub fn summary(&self) -> HistogramSummary {
        HistogramSummary {
            count: self.count,
            p50: self.value_at_permille(500),
            p95: self.value_at_permille(950),
            p99: self.value_at_permille(990),
            p999: self.value_at_permille(999),
            max: self.max,
            saturated: self.saturated,
            overflow: self.overflow,
        }
    }

    fn value_at_permille(&self, permille: u64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let rank = permille.saturating_mul(self.count).div_ceil(1000).max(1);
        let mut seen = 0u64;
        for (index, count) in self.buckets.iter().enumerate() {
            seen = seen.saturating_add(*count);
            if seen >= rank {
                return histogram_upper_bound(index).min(self.max_trackable_ns);
            }
        }
        self.max_trackable_ns
    }

    /// Raw compatible buckets for off-hot-path distributed transport/artifacts.
    #[must_use]
    pub fn raw_buckets(&self) -> &[u64; HISTOGRAM_BUCKETS] {
        self.buckets.as_ref()
    }

    /// Rehydrate raw agent buckets after bounded control-plane transport.
    pub fn from_raw_parts(
        max_trackable_ns: u64,
        buckets: &[u64],
        count: u64,
        max: u64,
        saturated: u64,
        overflow: u64,
    ) -> Result<Self, HistogramMergeError> {
        if buckets.len() != HISTOGRAM_BUCKETS {
            return Err(HistogramMergeError::InvalidBucketCount {
                expected: HISTOGRAM_BUCKETS,
                actual: buckets.len(),
            });
        }
        let mut raw = zeroed_histogram_buckets();
        raw.copy_from_slice(buckets);
        let bucket_count = raw.iter().try_fold(0u64, |sum, value| {
            sum.checked_add(*value)
                .ok_or(HistogramMergeError::BucketCountOverflow)
        })?;
        if bucket_count != count {
            return Err(HistogramMergeError::CountMismatch {
                declared: count,
                buckets: bucket_count,
            });
        }
        Ok(Self {
            max_trackable_ns: max_trackable_ns.max(1),
            buckets: raw,
            count,
            max,
            saturated,
            overflow,
        })
    }

    #[must_use]
    pub const fn max_trackable_ns(&self) -> u64 {
        self.max_trackable_ns
    }
}

fn zeroed_histogram_buckets() -> Box<[u64; HISTOGRAM_BUCKETS]> {
    match vec![0u64; HISTOGRAM_BUCKETS].into_boxed_slice().try_into() {
        Ok(buckets) => buckets,
        Err(_) => unreachable!("fixed histogram vector has the declared bucket length"),
    }
}

/// Human/report-facing histogram values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HistogramSummary {
    pub count: u64,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub p999: u64,
    pub max: u64,
    pub saturated: u64,
    pub overflow: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HistogramMergeError {
    #[error("incompatible histogram ranges: {left}ns versus {right}ns")]
    IncompatibleRange { left: u64, right: u64 },
    #[error("raw histogram has {actual} buckets; expected {expected}")]
    InvalidBucketCount { expected: usize, actual: usize },
    #[error("raw histogram bucket count overflow")]
    BucketCountOverflow,
    #[error("raw histogram count mismatch: declared={declared}, buckets={buckets}")]
    CountMismatch { declared: u64, buckets: u64 },
}

fn histogram_index(value: u64) -> usize {
    if value == 0 {
        return 0;
    }
    let exponent = 63usize.saturating_sub(value.leading_zeros() as usize);
    let base = 1u64 << exponent;
    let sub = if exponent < 5 {
        usize::try_from(value.saturating_sub(base)).unwrap_or(0)
    } else {
        usize::try_from((value - base) >> (exponent - 5)).unwrap_or(0)
    }
    .min(HISTOGRAM_SUB_BUCKETS - 1);
    exponent * HISTOGRAM_SUB_BUCKETS + sub
}

fn histogram_upper_bound(index: usize) -> u64 {
    let exponent = index / HISTOGRAM_SUB_BUCKETS;
    let sub = index % HISTOGRAM_SUB_BUCKETS;
    let base = 1u64 << exponent;
    if exponent < 5 {
        return base.saturating_add(u64::try_from(sub).unwrap_or(0));
    }
    let step = 1u64 << (exponent - 5);
    base.saturating_add(
        u64::try_from(sub + 1)
            .unwrap_or(u64::MAX)
            .saturating_mul(step),
    )
    .saturating_sub(1)
}

/// A fixed-capacity buffer of nanosecond latency samples.
#[derive(Debug, Clone)]
pub struct SampleSet {
    capacity: usize,
    samples: Vec<u64>,
    dropped: u64,
}

impl SampleSet {
    /// Create a sample set with the given fixed capacity (at least 1).
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            samples: Vec::with_capacity(capacity.min(4096)),
            dropped: 0,
        }
    }

    /// Record a sample. Returns `false` (and increments [`SampleSet::dropped`]) when
    /// the buffer is already at capacity.
    pub fn record(&mut self, value: u64) -> bool {
        if self.samples.len() >= self.capacity {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        self.samples.push(value);
        true
    }

    /// Number of stored samples.
    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Whether no samples are stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Number of samples dropped due to capacity.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Configured capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// The stored samples in insertion order (unsorted).
    #[must_use]
    pub fn as_slice(&self) -> &[u64] {
        &self.samples
    }

    /// Compute percentiles over the stored samples (sorts a local copy).
    #[must_use]
    pub fn percentiles(&self) -> Percentiles {
        let mut buf = self.samples.clone();
        Percentiles::from_unsorted(&mut buf)
    }
}

/// Standard latency percentiles in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Percentiles {
    /// Number of samples the percentiles summarise.
    pub count: u64,
    /// 50th percentile (median).
    pub p50: u64,
    /// 90th percentile.
    pub p90: u64,
    /// 95th percentile.
    pub p95: u64,
    /// 99th percentile.
    pub p99: u64,
    /// 99.9th percentile.
    pub p999: u64,
    /// Maximum observed sample.
    pub max: u64,
}

impl Percentiles {
    /// Compute percentiles from an unsorted slice (sorted in place).
    #[must_use]
    pub fn from_unsorted(samples: &mut [u64]) -> Self {
        samples.sort_unstable();
        Self::from_sorted(samples)
    }

    /// Compute percentiles from an already-sorted slice.
    #[must_use]
    pub fn from_sorted(sorted: &[u64]) -> Self {
        let count = u64::try_from(sorted.len()).unwrap_or(u64::MAX);
        Self {
            count,
            p50: percentile_permille(sorted, 500),
            p90: percentile_permille(sorted, 900),
            p95: percentile_permille(sorted, 950),
            p99: percentile_permille(sorted, 990),
            p999: percentile_permille(sorted, 999),
            max: sorted.last().copied().unwrap_or(0),
        }
    }
}

/// Nearest-rank percentile of a sorted slice. `permille` is the quantile in
/// thousandths (e.g. `950` = p95, `999` = p99.9). Returns `0` for an empty slice.
#[must_use]
pub fn percentile_permille(sorted: &[u64], permille: u32) -> u64 {
    let n = sorted.len();
    if n == 0 {
        return 0;
    }
    // rank = ceil(permille/1000 * n), clamped to [1, n]; index is rank-1.
    let n64 = u64::try_from(n).unwrap_or(u64::MAX);
    let numerator = u64::from(permille).saturating_mul(n64);
    let rank = numerator.div_ceil(1000).clamp(1, n64);
    let idx = usize::try_from(rank - 1).unwrap_or(n - 1).min(n - 1);
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_of_1_to_100() {
        // Samples 1..=100; nearest-rank puts p50=50, p90=90, p95=95, p99=99.
        let mut data: Vec<u64> = (1..=100).collect();
        let p = Percentiles::from_unsorted(&mut data);
        assert_eq!(p.count, 100);
        assert_eq!(p.p50, 50);
        assert_eq!(p.p90, 90);
        assert_eq!(p.p95, 95);
        assert_eq!(p.p99, 99);
        assert_eq!(p.max, 100);
    }

    #[test]
    fn p999_of_1000_samples() {
        let mut data: Vec<u64> = (1..=1000).collect();
        let p = Percentiles::from_unsorted(&mut data);
        // ceil(0.999*1000)=999 -> index 998 -> value 999.
        assert_eq!(p.p999, 999);
        assert_eq!(p.p50, 500);
    }

    #[test]
    fn single_sample() {
        let p = Percentiles::from_sorted(&[42]);
        assert_eq!(p.p50, 42);
        assert_eq!(p.p999, 42);
        assert_eq!(p.max, 42);
    }

    #[test]
    fn empty_is_all_zero() {
        let p = Percentiles::from_sorted(&[]);
        assert_eq!(p, Percentiles::default());
    }

    #[test]
    fn sample_set_counts_overflow() {
        let mut s = SampleSet::new(4);
        for i in 0..10 {
            let ok = s.record(i);
            assert_eq!(ok, i < 4);
        }
        assert_eq!(s.len(), 4);
        assert_eq!(s.dropped(), 6);
        assert_eq!(s.capacity(), 4);
    }

    #[test]
    fn zero_capacity_is_floored_to_one() {
        let mut s = SampleSet::new(0);
        assert!(s.record(1));
        assert!(!s.record(2));
        assert_eq!(s.dropped(), 1);
    }

    #[test]
    fn exact_counter_conservation_and_failures() {
        let valid = OutcomeCounters {
            offered: 100,
            generated: 98,
            queued: 96,
            socket_written: 90,
            acknowledged: 82,
            accepted: 80,
            rejected: 2,
            timed_out: 3,
            generator_failed: 2,
            transport_failed_before_write: 4,
            transport_failed_after_write: 4,
            protocol_failed: 1,
            locally_dropped: 4,
            overflow: 0,
        };
        valid.validate_conservation().unwrap();

        let mut invalid = valid;
        invalid.accepted += 1;
        assert!(matches!(
            invalid.validate_conservation(),
            Err(ConservationError::Acknowledged { .. })
        ));
        invalid = valid;
        invalid.locally_dropped += 1;
        assert!(matches!(
            invalid.validate_conservation(),
            Err(ConservationError::Offered { .. })
        ));
    }

    #[test]
    fn merged_histogram_matches_combined_known_samples() {
        let mut left = LatencyHistogram::new(1_000_000);
        let mut right = LatencyHistogram::new(1_000_000);
        let mut combined = LatencyHistogram::new(1_000_000);
        for value in 1..=1000 {
            if value & 1 == 0 {
                left.record(value);
            } else {
                right.record(value);
            }
            combined.record(value);
        }
        left.merge(&right).unwrap();
        assert_eq!(left, combined);
        let summary = left.summary();
        assert_eq!(summary.count, 1000);
        // Log buckets return conservative bucket upper bounds, within documented
        // 3.125% precision above 32ns.
        assert!((500..=516).contains(&summary.p50), "{}", summary.p50);
        assert!((950..=980).contains(&summary.p95), "{}", summary.p95);
        assert!((990..=1020).contains(&summary.p99), "{}", summary.p99);
        assert_eq!(summary.max, 1000);
        assert_eq!(summary.saturated, 0);
        assert_eq!(summary.overflow, 0);
    }

    #[test]
    fn histogram_saturation_is_explicit() {
        let mut histogram = LatencyHistogram::new(100);
        histogram.record(50);
        histogram.record(101);
        histogram.record(u64::MAX);
        let summary = histogram.summary();
        assert_eq!(summary.count, 3);
        assert_eq!(summary.max, u64::MAX);
        assert_eq!(summary.saturated, 2);
        assert_eq!(summary.overflow, 0);
    }

    #[test]
    fn incompatible_histograms_do_not_merge() {
        let mut left = LatencyHistogram::new(100);
        let right = LatencyHistogram::new(200);
        assert!(matches!(
            left.merge(&right),
            Err(HistogramMergeError::IncompatibleRange { .. })
        ));
    }

    #[test]
    fn per_action_counters_merge_without_losing_remainder() {
        let mut actions = ActionCounters::default();
        for (kind, offered) in [
            (CommandKind::NewOrder, 7),
            (CommandKind::Cancel, 2),
            (CommandKind::Replace, 1),
        ] {
            let counter = actions.for_kind_mut(kind);
            counter.offered = offered;
            counter.generated = offered;
            counter.queued = offered;
            counter.socket_written = offered;
            counter.acknowledged = offered;
            counter.accepted = offered;
        }
        let total = actions.total();
        assert_eq!(total.offered, 10);
        assert_eq!(total.accepted, 10);
        total.validate_conservation().unwrap();
    }
}

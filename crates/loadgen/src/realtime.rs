//! Allocation-free, mergeable live-run metrics.
//!
//! A [`WorkerMetrics`] instance is owned by exactly one load worker. Recording uses
//! plain integer increments and fixed arrays: it allocates nothing, takes no lock,
//! and performs no I/O. The owner snapshots once per interval outside its send loop;
//! controller-side aggregation merges the raw counters and histogram buckets rather
//! than averaging percentiles.

use serde::{Deserialize, Serialize};

/// Histogram schema identifier. Reports with different schemas must not be merged.
pub const HISTOGRAM_SCHEMA: &str = "dexos-log2-32-v1";
/// Thirty-two sub-buckets per power of two gives at most 3.125% bucket width.
const SUB_BUCKET_BITS: u32 = 5;
const SUB_BUCKETS: usize = 1 << SUB_BUCKET_BITS;
/// Bucket zero is exact zero; the remaining buckets cover every `u64` nanosecond.
pub const HISTOGRAM_BUCKETS: usize = 1 + 64 * SUB_BUCKETS;

/// Trading action dimension used by live metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ActionKind {
    /// Submit a new order.
    New = 0,
    /// Cancel a previously accepted live order.
    Cancel = 1,
    /// Replace a previously accepted live order.
    Replace = 2,
}

impl ActionKind {
    const ALL: [Self; 3] = [Self::New, Self::Cancel, Self::Replace];

    const fn index(self) -> usize {
        self as usize
    }
}

/// Monotonic operation counters for one action class and interval.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationCounters {
    /// Operations scheduled by the open-loop workload.
    pub offered: u64,
    /// Valid operations produced by a worker.
    pub generated: u64,
    /// Operations admitted to a bounded connection queue.
    pub queued: u64,
    /// Complete request frames handed to the socket.
    pub socket_written: u64,
    /// Responses correlated to written requests.
    pub acknowledged: u64,
    /// Successful protocol outcomes.
    pub accepted: u64,
    /// Explicit protocol rejections.
    pub rejected: u64,
    /// Written requests whose response deadline elapsed.
    pub timed_out: u64,
    /// Requests that failed before a complete socket write.
    pub transport_failed: u64,
    /// Generation, signing, encoding, or local protocol failures.
    pub protocol_failed: u64,
    /// Missed deadlines or bounded-capacity refusals before generation completes.
    pub locally_dropped: u64,
}

impl OperationCounters {
    /// Add another compatible counter delta, failing on integer overflow.
    pub fn checked_merge(&mut self, other: &Self) -> Result<(), MetricsError> {
        macro_rules! add {
            ($field:ident) => {
                self.$field = self
                    .$field
                    .checked_add(other.$field)
                    .ok_or(MetricsError::CounterOverflow)?;
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
        add!(transport_failed);
        add!(protocol_failed);
        add!(locally_dropped);
        Ok(())
    }

    /// Number of operations in exactly one terminal bucket.
    #[must_use]
    pub fn terminal_total(self) -> Option<u64> {
        self.accepted
            .checked_add(self.rejected)?
            .checked_add(self.timed_out)?
            .checked_add(self.transport_failed)?
            .checked_add(self.protocol_failed)?
            .checked_add(self.locally_dropped)
    }

    /// Validate all intermediate and terminal conservation invariants after drain.
    pub fn validate_drained(self) -> Result<(), MetricsError> {
        if self.acknowledged
            != self
                .accepted
                .checked_add(self.rejected)
                .ok_or(MetricsError::CounterOverflow)?
        {
            return Err(MetricsError::AcknowledgementMismatch);
        }
        if self.socket_written
            != self
                .acknowledged
                .checked_add(self.timed_out)
                .ok_or(MetricsError::CounterOverflow)?
        {
            return Err(MetricsError::WrittenMismatch);
        }
        if self.offered != self.terminal_total().ok_or(MetricsError::CounterOverflow)? {
            return Err(MetricsError::TerminalMismatch);
        }
        if self.generated > self.offered
            || self.queued > self.generated
            || self.socket_written > self.queued
        {
            return Err(MetricsError::ImpossibleProgression);
        }
        Ok(())
    }
}

/// Fixed-memory integer-nanosecond histogram, mergeable bucket-for-bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NanoHistogram {
    buckets: Vec<u64>,
    /// Total values recorded.
    pub count: u64,
    /// Exact maximum observed value.
    pub max: u64,
    /// Values not recorded because a counter would overflow.
    pub overflow: u64,
}

impl Default for NanoHistogram {
    fn default() -> Self {
        Self {
            // Allocated once when the worker is constructed, never while recording.
            buckets: vec![0; HISTOGRAM_BUCKETS],
            count: 0,
            max: 0,
            overflow: 0,
        }
    }
}

impl NanoHistogram {
    /// Record one nanosecond value without allocating or blocking.
    pub fn record(&mut self, value: u64) {
        self.record_n(value, 1);
    }

    /// Record `occurrences` identical observations in O(1), without allocating.
    /// Packed receipts use this to represent one latency observation per command
    /// while processing a single 32-128-record lifecycle receipt.
    pub fn record_n(&mut self, value: u64, occurrences: u64) {
        if occurrences == 0 {
            return;
        }
        let index = bucket_index(value);
        let Some(bucket) = self.buckets.get_mut(index) else {
            self.overflow = self.overflow.saturating_add(occurrences);
            return;
        };
        let Some(next_bucket) = bucket.checked_add(occurrences) else {
            self.overflow = self.overflow.saturating_add(occurrences);
            return;
        };
        let Some(next_count) = self.count.checked_add(occurrences) else {
            self.overflow = self.overflow.saturating_add(occurrences);
            return;
        };
        *bucket = next_bucket;
        self.count = next_count;
        self.max = self.max.max(value);
    }

    /// Merge compatible raw buckets, rejecting overflow or malformed shape.
    pub fn checked_merge(&mut self, other: &Self) -> Result<(), MetricsError> {
        if self.buckets.len() != HISTOGRAM_BUCKETS || other.buckets.len() != HISTOGRAM_BUCKETS {
            return Err(MetricsError::HistogramSchema);
        }
        for (dst, src) in self.buckets.iter_mut().zip(&other.buckets) {
            *dst = dst.checked_add(*src).ok_or(MetricsError::CounterOverflow)?;
        }
        self.count = self
            .count
            .checked_add(other.count)
            .ok_or(MetricsError::CounterOverflow)?;
        self.max = self.max.max(other.max);
        self.overflow = self
            .overflow
            .checked_add(other.overflow)
            .ok_or(MetricsError::CounterOverflow)?;
        Ok(())
    }

    /// Approximate percentile using the upper bound of its logarithmic bucket.
    #[must_use]
    pub fn percentile_permille(&self, permille: u16) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let p = u64::from(permille.min(1000));
        let rank = self.count.saturating_mul(p).saturating_add(999) / 1000;
        let target = rank.max(1);
        let mut cumulative = 0u64;
        for (index, count) in self.buckets.iter().copied().enumerate() {
            cumulative = cumulative.saturating_add(count);
            if cumulative >= target {
                return bucket_upper_bound(index).min(self.max);
            }
        }
        self.max
    }

    /// Expose buckets for machine-readable artifacts and exact controller merging.
    #[must_use]
    pub fn buckets(&self) -> &[u64] {
        &self.buckets
    }

    fn clear(&mut self) {
        self.buckets.fill(0);
        self.count = 0;
        self.max = 0;
        self.overflow = 0;
    }
}

/// Counters and latencies for one trading action.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionMetrics {
    /// Operation lifecycle counters.
    pub counters: OperationCounters,
    /// Scheduled-deadline to queue-admission latency.
    pub queue_delay_ns: NanoHistogram,
    /// Complete socket write to correlated acknowledgement latency.
    pub request_ack_ns: NanoHistogram,
}

impl ActionMetrics {
    fn checked_merge(&mut self, other: &Self) -> Result<(), MetricsError> {
        self.counters.checked_merge(&other.counters)?;
        self.queue_delay_ns.checked_merge(&other.queue_delay_ns)?;
        self.request_ack_ns.checked_merge(&other.request_ack_ns)?;
        Ok(())
    }

    fn clear(&mut self) {
        self.counters = OperationCounters::default();
        self.queue_delay_ns.clear();
        self.request_ack_ns.clear();
    }
}

/// One worker's current interval metrics.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WorkerMetrics {
    actions: [ActionMetrics; 3],
    /// Maximum scheduler lag in the interval.
    pub max_scheduler_lag_ns: u64,
    /// High-water mark for the worker's bounded send queue.
    pub queue_high_water: u64,
    /// Metrics events that could not be represented exactly.
    pub metric_overflow: u64,
}

impl WorkerMetrics {
    /// Mutable metrics for an action class. The caller is the sole worker owner.
    pub fn action_mut(&mut self, kind: ActionKind) -> &mut ActionMetrics {
        &mut self.actions[kind.index()]
    }

    /// Freeze the interval into an owned report and reset the reusable worker state.
    pub fn take_interval(
        &mut self,
        start_ns: u64,
        end_ns: u64,
    ) -> Result<IntervalMetrics, MetricsError> {
        if end_ns <= start_ns {
            return Err(MetricsError::InvalidInterval);
        }
        let mut actions = std::array::from_fn(|_| ActionMetrics::default());
        for kind in ActionKind::ALL {
            std::mem::swap(&mut actions[kind.index()], &mut self.actions[kind.index()]);
            self.actions[kind.index()].clear();
        }
        let interval = IntervalMetrics {
            histogram_schema: HISTOGRAM_SCHEMA.to_string(),
            start_ns,
            end_ns,
            actions,
            max_scheduler_lag_ns: std::mem::take(&mut self.max_scheduler_lag_ns),
            queue_high_water: std::mem::take(&mut self.queue_high_water),
            metric_overflow: std::mem::take(&mut self.metric_overflow),
        };
        Ok(interval)
    }
}

/// Mergeable one-second (or explicitly bounded) interval artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntervalMetrics {
    /// Exact raw-histogram schema.
    pub histogram_schema: String,
    /// Inclusive monotonic interval start.
    pub start_ns: u64,
    /// Exclusive monotonic interval end.
    pub end_ns: u64,
    /// New, cancel, and replace metrics in discriminant order.
    pub actions: [ActionMetrics; 3],
    /// Maximum scheduler lag reported by any merged worker.
    pub max_scheduler_lag_ns: u64,
    /// Maximum queue occupancy reported by any merged worker.
    pub queue_high_water: u64,
    /// Metrics events that overflowed or could not be represented.
    pub metric_overflow: u64,
}

impl IntervalMetrics {
    /// Merge a worker/agent delta for the exact same time interval.
    pub fn checked_merge(&mut self, other: &Self) -> Result<(), MetricsError> {
        if self.histogram_schema != HISTOGRAM_SCHEMA || other.histogram_schema != HISTOGRAM_SCHEMA {
            return Err(MetricsError::HistogramSchema);
        }
        if self.start_ns != other.start_ns || self.end_ns != other.end_ns {
            return Err(MetricsError::IntervalMismatch);
        }
        for kind in ActionKind::ALL {
            self.actions[kind.index()].checked_merge(&other.actions[kind.index()])?;
        }
        self.max_scheduler_lag_ns = self.max_scheduler_lag_ns.max(other.max_scheduler_lag_ns);
        self.queue_high_water = self.queue_high_water.max(other.queue_high_water);
        self.metric_overflow = self
            .metric_overflow
            .checked_add(other.metric_overflow)
            .ok_or(MetricsError::CounterOverflow)?;
        Ok(())
    }

    /// Accumulate raw metrics across different time intervals.
    ///
    /// Unlike [`Self::checked_merge`], this operation is for a final whole-run
    /// artifact rather than controller fan-in for one logical second. Histogram
    /// buckets and counters are still merged exactly; the resulting bounds span
    /// both inputs.
    pub fn checked_accumulate(&mut self, other: &Self) -> Result<(), MetricsError> {
        if self.histogram_schema != HISTOGRAM_SCHEMA || other.histogram_schema != HISTOGRAM_SCHEMA {
            return Err(MetricsError::HistogramSchema);
        }
        for kind in ActionKind::ALL {
            self.actions[kind.index()].checked_merge(&other.actions[kind.index()])?;
        }
        self.start_ns = self.start_ns.min(other.start_ns);
        self.end_ns = self.end_ns.max(other.end_ns);
        self.max_scheduler_lag_ns = self.max_scheduler_lag_ns.max(other.max_scheduler_lag_ns);
        self.queue_high_water = self.queue_high_water.max(other.queue_high_water);
        self.metric_overflow = self
            .metric_overflow
            .checked_add(other.metric_overflow)
            .ok_or(MetricsError::CounterOverflow)?;
        Ok(())
    }

    /// Sum action counters without assuming every lifecycle stage completes inside
    /// this one time bucket. Final whole-run conservation remains the caller's job.
    pub fn raw_counters(&self) -> Result<OperationCounters, MetricsError> {
        if self.histogram_schema != HISTOGRAM_SCHEMA {
            return Err(MetricsError::HistogramSchema);
        }
        if self.metric_overflow != 0
            || self
                .actions
                .iter()
                .any(|a| a.queue_delay_ns.overflow != 0 || a.request_ack_ns.overflow != 0)
        {
            return Err(MetricsError::MetricOverflow);
        }
        let mut total = OperationCounters::default();
        for action in &self.actions {
            total.checked_merge(&action.counters)?;
        }
        Ok(total)
    }

    /// Sum action counters and validate final conservation after drain.
    pub fn validate_drained(&self) -> Result<OperationCounters, MetricsError> {
        let total = self.raw_counters()?;
        for action in &self.actions {
            action.counters.validate_drained()?;
        }
        total.validate_drained()?;
        Ok(total)
    }
}

/// Fail-closed live-metrics validation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MetricsError {
    /// A counter could not be represented in `u64`.
    #[error("metrics counter overflow")]
    CounterOverflow,
    /// Offered operations do not equal terminal outcomes after drain.
    #[error("terminal counters do not conserve offered operations")]
    TerminalMismatch,
    /// Acknowledgements do not equal accepted plus rejected outcomes.
    #[error("acknowledged counters do not conserve terminal responses")]
    AcknowledgementMismatch,
    /// Socket writes do not equal acknowledged plus timed-out outcomes.
    #[error("socket-written counters do not conserve post-write outcomes")]
    WrittenMismatch,
    /// An intermediate counter exceeds its predecessor.
    #[error("operation counters contain an impossible progression")]
    ImpossibleProgression,
    /// Histogram buckets are absent or use an incompatible schema.
    #[error("histogram schema mismatch")]
    HistogramSchema,
    /// Metrics being merged cover different interval boundaries.
    #[error("interval boundaries do not match")]
    IntervalMismatch,
    /// Interval end was not strictly greater than its start.
    #[error("invalid interval boundaries")]
    InvalidInterval,
    /// A metric event or histogram bucket overflowed.
    #[error("metrics overflow is non-zero")]
    MetricOverflow,
}

fn bucket_index(value: u64) -> usize {
    if value == 0 {
        return 0;
    }
    let exponent = 63u32.saturating_sub(value.leading_zeros());
    let base = 1u64 << exponent;
    let delta = value - base;
    let sub = if exponent >= SUB_BUCKET_BITS {
        delta >> (exponent - SUB_BUCKET_BITS)
    } else {
        delta << (SUB_BUCKET_BITS - exponent)
    };
    1 + usize::try_from(exponent).unwrap_or(63) * SUB_BUCKETS
        + usize::try_from(sub.min((SUB_BUCKETS - 1) as u64)).unwrap_or(SUB_BUCKETS - 1)
}

fn bucket_upper_bound(index: usize) -> u64 {
    if index == 0 {
        return 0;
    }
    let offset = index - 1;
    let exponent = offset / SUB_BUCKETS;
    let sub = offset % SUB_BUCKETS;
    if exponent >= 63 {
        return u64::MAX;
    }
    let base = 1u128 << exponent;
    let numerator = u128::try_from(sub + 1).unwrap_or(SUB_BUCKETS as u128) * base;
    let width_end = numerator.div_ceil(SUB_BUCKETS as u128);
    u64::try_from(base + width_end - 1).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete(c: &mut OperationCounters, count: u64) {
        c.offered = count;
        c.generated = count;
        c.queued = count;
        c.socket_written = count;
        c.acknowledged = count;
        c.accepted = count;
    }

    #[test]
    fn every_u64_value_maps_inside_the_fixed_histogram() {
        for value in [
            0,
            1,
            2,
            31,
            32,
            33,
            1_000,
            1_000_000,
            u64::MAX - 1,
            u64::MAX,
        ] {
            assert!(bucket_index(value) < HISTOGRAM_BUCKETS, "{value}");
        }
    }

    #[test]
    fn histogram_percentiles_and_merge_use_raw_buckets() {
        let mut a = NanoHistogram::default();
        let mut b = NanoHistogram::default();
        for value in 1..=100 {
            if value <= 50 {
                a.record(value);
            } else {
                b.record(value);
            }
        }
        a.checked_merge(&b).unwrap();
        assert_eq!(a.count, 100);
        assert_eq!(a.max, 100);
        assert!((50..=52).contains(&a.percentile_permille(500)));
        assert!((99..=100).contains(&a.percentile_permille(990)));
        assert_eq!(a.percentile_permille(1000), 100);
        assert_eq!(a.overflow, 0);
    }

    #[test]
    fn weighted_histogram_observations_reconcile_without_expansion() {
        let mut histogram = NanoHistogram::default();
        histogram.record_n(42, 128);
        histogram.record_n(1_000, 32);
        histogram.record_n(7, 0);
        assert_eq!(histogram.count, 160);
        assert_eq!(histogram.max, 1_000);
        assert_eq!(histogram.percentile_permille(500), 42);
        assert_eq!(histogram.percentile_permille(900), 1_000);
        assert_eq!(histogram.overflow, 0);
    }

    #[test]
    fn terminal_conservation_fails_closed_by_boundary() {
        let mut counters = OperationCounters::default();
        complete(&mut counters, 10);
        assert!(counters.validate_drained().is_ok());

        let mut bad = counters;
        bad.acknowledged = 9;
        assert_eq!(
            bad.validate_drained(),
            Err(MetricsError::AcknowledgementMismatch)
        );
        let mut bad = counters;
        bad.socket_written = 9;
        assert_eq!(bad.validate_drained(), Err(MetricsError::WrittenMismatch));
        let mut bad = counters;
        bad.offered = 11;
        assert_eq!(bad.validate_drained(), Err(MetricsError::TerminalMismatch));
    }

    #[test]
    fn worker_intervals_merge_and_reset_without_percentile_averaging() {
        let mut left = WorkerMetrics::default();
        let mut right = WorkerMetrics::default();
        complete(&mut left.action_mut(ActionKind::New).counters, 6);
        complete(&mut right.action_mut(ActionKind::New).counters, 4);
        left.action_mut(ActionKind::New).request_ack_ns.record(10);
        right
            .action_mut(ActionKind::New)
            .request_ack_ns
            .record(1_000);
        left.queue_high_water = 7;
        right.queue_high_water = 9;

        let mut merged = left.take_interval(1_000, 2_000).unwrap();
        merged
            .checked_merge(&right.take_interval(1_000, 2_000).unwrap())
            .unwrap();
        let total = merged.validate_drained().unwrap();
        assert_eq!(total.offered, 10);
        assert_eq!(merged.queue_high_water, 9);
        assert_eq!(merged.actions[0].request_ack_ns.count, 2);
        assert_eq!(merged.actions[0].request_ack_ns.max, 1_000);

        let reset = left.take_interval(2_000, 3_000).unwrap();
        assert_eq!(reset.actions[0].counters, OperationCounters::default());
        assert_eq!(reset.actions[0].request_ack_ns.count, 0);
    }

    #[test]
    fn incompatible_intervals_and_schemas_do_not_merge() {
        let mut a = WorkerMetrics::default().take_interval(1, 2).unwrap();
        let b = WorkerMetrics::default().take_interval(2, 3).unwrap();
        assert_eq!(a.checked_merge(&b), Err(MetricsError::IntervalMismatch));
        let mut b = WorkerMetrics::default().take_interval(1, 2).unwrap();
        b.histogram_schema = "other".to_string();
        assert_eq!(a.checked_merge(&b), Err(MetricsError::HistogramSchema));
    }
}

//! A lock-free, allocation-free, integer-bucketed latency [`Histogram`] and a
//! set of [`Stage`]-keyed histograms for per-pipeline-stage latency.
//!
//! # Bucketing
//!
//! Buckets are power-of-two exponential: a recorded value `v` lands in the
//! bucket indexed by its bit length, `bucket = 64 - v.leading_zeros()`, clamped
//! to [`BUCKET_COUNT`]` - 1`. Bucket `k` (for `k >= 1`) covers the half-open
//! range `[2^(k-1), 2^k)`; bucket `0` holds only `v == 0`. The top bucket is
//! **saturating**: any oversized input lands there without overflow.
//!
//! Because the mapping is a `leading_zeros` plus a clamp, the record path uses
//! **no floating point and no division** — only integer ops on fixed-size
//! atomic arrays. This is what keeps recording off the p99 critical path.
//!
//! # Percentile error bound
//!
//! On read, a quantile is estimated as the **upper bound of the bucket** the
//! target rank falls in. Since bucket `k` spans `[2^(k-1), 2^k)`, the estimate
//! `q` satisfies `true <= q < 2 * true` for any non-saturated sample — i.e. the
//! documented relative error bound is a factor of two, always over-estimating.
//! In the saturating top bucket the estimate is a lower bound instead.

use core::sync::atomic::{AtomicU64, Ordering};

/// Number of exponential buckets. Bucket `k` covers `[2^(k-1), 2^k)`; the top
/// bucket (`k == BUCKET_COUNT - 1`) is saturating. With 41 buckets the largest
/// non-saturating value is `2^40 - 1` nanoseconds (~18 minutes).
pub const BUCKET_COUNT: usize = 41;

/// Upper bound (exclusive-ish representative) of bucket `k`, used as the
/// quantile estimate. Bucket `0` reports `0`; bucket `k` reports `2^k - 1`.
#[must_use]
pub fn bucket_upper_bound(k: usize) -> u64 {
    if k == 0 {
        0
    } else {
        // k <= BUCKET_COUNT - 1 == 40, so `1u64 << k` never overflows.
        (1u64 << k).saturating_sub(1)
    }
}

/// Maps a value to its bucket index via integer bit length, clamped to the top
/// (saturating) bucket. No floating point, no division.
#[must_use]
fn bucket_index(v: u64) -> usize {
    let bits = u64::BITS - v.leading_zeros();
    // `bits` is at most 64; the widening conversion cannot fail on any target,
    // but we avoid `as` and clamp to the saturating top bucket regardless.
    let idx = usize::try_from(bits).unwrap_or(BUCKET_COUNT - 1);
    idx.min(BUCKET_COUNT - 1)
}

/// Five conventionally reported latency quantiles, in the same integer units
/// that were recorded (typically nanoseconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Quantiles {
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
}

/// A fixed-bucket latency histogram. All fields are atomics; recording touches
/// four of them and never allocates.
#[derive(Debug)]
pub struct Histogram {
    buckets: [AtomicU64; BUCKET_COUNT],
    count: AtomicU64,
    sum: AtomicU64,
    max: AtomicU64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

impl Histogram {
    /// Creates an empty histogram. The bucket array is stack-initialized here;
    /// no allocation occurs on this path or on [`record`](Self::record).
    #[must_use]
    pub fn new() -> Self {
        Self {
            buckets: core::array::from_fn(|_| AtomicU64::new(0)),
            count: AtomicU64::new(0),
            sum: AtomicU64::new(0),
            max: AtomicU64::new(0),
        }
    }

    /// Records one observation of `v` (e.g. a latency in nanoseconds).
    ///
    /// Allocation-free and lock-free: it computes a bucket index with integer
    /// arithmetic and performs four relaxed atomic updates (bucket, count, sum,
    /// running max). Oversized inputs saturate into the top bucket.
    #[inline]
    pub fn record(&self, v: u64) {
        let idx = bucket_index(v);
        saturating_add(&self.buckets[idx], 1);
        saturating_add(&self.count, 1);
        saturating_add(&self.sum, v);
        self.max.fetch_max(v, Ordering::Relaxed);
    }

    /// Total number of recorded observations.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Sum of all recorded values (saturating on the record path via `u64`).
    #[must_use]
    pub fn sum(&self) -> u64 {
        self.sum.load(Ordering::Relaxed)
    }

    /// Largest single recorded value.
    #[must_use]
    pub fn max(&self) -> u64 {
        self.max.load(Ordering::Relaxed)
    }

    /// Snapshot of the raw per-bucket counts.
    #[must_use]
    pub fn bucket_counts(&self) -> [u64; BUCKET_COUNT] {
        core::array::from_fn(|i| self.buckets[i].load(Ordering::Relaxed))
    }

    /// Estimates the quantile for `q_permille` (0..=1000, e.g. `999` for
    /// p99.9). Returns the upper bound of the bucket holding the target rank;
    /// returns `0` for an empty histogram. See the module docs for the error
    /// bound. Read-only and off the hot path.
    #[must_use]
    pub fn quantile_permille(&self, q_permille: u32) -> u64 {
        let count = self.count.load(Ordering::Relaxed);
        if count == 0 {
            return 0;
        }
        let q = u128::from(q_permille.min(1000));
        // Ceil rank in 1..=count. Wide arithmetic avoids any overflow.
        let target = (u128::from(count) * q).div_ceil(1000).max(1);
        let mut cumulative: u128 = 0;
        for (k, bucket) in self.buckets.iter().enumerate() {
            cumulative += u128::from(bucket.load(Ordering::Relaxed));
            if cumulative >= target {
                return bucket_upper_bound(k);
            }
        }
        // All mass counted but target not reached (should not happen); fall back
        // to the observed maximum.
        self.max.load(Ordering::Relaxed)
    }

    /// The five conventionally reported quantiles in one read.
    #[must_use]
    pub fn quantiles(&self) -> Quantiles {
        Quantiles {
            p50: self.quantile_permille(500),
            p90: self.quantile_permille(900),
            p95: self.quantile_permille(950),
            p99: self.quantile_permille(990),
            p999: self.quantile_permille(999),
        }
    }
}

#[inline]
fn saturating_add(value: &AtomicU64, delta: u64) {
    let _ = value.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
        Some(old.saturating_add(delta))
    });
}

/// A stage of the command-processing pipeline, used to key per-stage latency
/// histograms. The set is fixed so the histogram array is fixed-size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    /// Frame received off the wire.
    Ingress,
    /// Decoded from bytes into a typed command.
    Decode,
    /// Signature / authorization verification.
    Verify,
    /// Risk / margin checks.
    Risk,
    /// Order-book matching.
    Match,
    /// Settlement / state application.
    Settle,
    /// Commit / checkpoint accounting.
    Commit,
    /// Receipt serialized and sent.
    Egress,
}

impl Stage {
    /// Number of distinct stages.
    pub const COUNT: usize = 8;

    /// All stages in index order.
    pub const ALL: [Stage; Self::COUNT] = [
        Stage::Ingress,
        Stage::Decode,
        Stage::Verify,
        Stage::Risk,
        Stage::Match,
        Stage::Settle,
        Stage::Commit,
        Stage::Egress,
    ];

    /// Stable array index for this stage.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Stage::Ingress => 0,
            Stage::Decode => 1,
            Stage::Verify => 2,
            Stage::Risk => 3,
            Stage::Match => 4,
            Stage::Settle => 5,
            Stage::Commit => 6,
            Stage::Egress => 7,
        }
    }

    /// Lower-case stable name, used when exporting.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Stage::Ingress => "ingress",
            Stage::Decode => "decode",
            Stage::Verify => "verify",
            Stage::Risk => "risk",
            Stage::Match => "match",
            Stage::Settle => "settle",
            Stage::Commit => "commit",
            Stage::Egress => "egress",
        }
    }
}

/// One shared [`Histogram`] per [`Stage`], for per-stage latency tracking.
/// Recording is a single array index plus a [`Histogram::record`] — still
/// allocation-free and lock-free. Holds `Arc` handles so the same histograms
/// can also live in a [`MetricsRegistry`] snapshot.
///
/// [`MetricsRegistry`]: crate::MetricsRegistry
#[derive(Debug, Clone)]
pub struct StageHistograms {
    stages: [std::sync::Arc<Histogram>; Stage::COUNT],
}

impl Default for StageHistograms {
    fn default() -> Self {
        Self::new()
    }
}

impl StageHistograms {
    /// Creates a per-stage histogram set backed by fresh, standalone
    /// histograms.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stages: core::array::from_fn(|_| std::sync::Arc::new(Histogram::new())),
        }
    }

    /// Builds a per-stage set from existing shared handles (used when the
    /// histograms are also registered in a registry). `handles[i]` is the
    /// histogram for the stage whose [`Stage::index`] is `i`.
    #[must_use]
    pub fn from_handles(handles: [std::sync::Arc<Histogram>; Stage::COUNT]) -> Self {
        Self { stages: handles }
    }

    /// Records `v` into the histogram for `stage`. Allocation-free, lock-free.
    #[inline]
    pub fn record(&self, stage: Stage, v: u64) {
        self.stages[stage.index()].record(v);
    }

    /// Borrows the histogram for a stage.
    #[must_use]
    pub fn histogram(&self, stage: Stage) -> &Histogram {
        &self.stages[stage.index()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_counters_and_sum_saturate() {
        let h = Histogram::new();
        h.count.store(u64::MAX, Ordering::Relaxed);
        h.sum.store(u64::MAX - 1, Ordering::Relaxed);
        h.buckets[0].store(u64::MAX, Ordering::Relaxed);
        h.record(7);
        assert_eq!(h.count(), u64::MAX);
        assert_eq!(h.sum(), u64::MAX);
        assert_eq!(h.bucket_counts()[3], 1);
    }

    #[test]
    fn bucket_index_is_bit_length() {
        assert_eq!(bucket_index(0), 0);
        assert_eq!(bucket_index(1), 1);
        assert_eq!(bucket_index(2), 2);
        assert_eq!(bucket_index(3), 2);
        assert_eq!(bucket_index(4), 3);
        assert_eq!(bucket_index(u64::MAX), BUCKET_COUNT - 1);
    }

    #[test]
    fn counts_and_sum_are_exact() {
        let h = Histogram::new();
        for v in [10u64, 20, 30, 40] {
            h.record(v);
        }
        assert_eq!(h.count(), 4);
        assert_eq!(h.sum(), 100);
        assert_eq!(h.max(), 40);
    }

    #[test]
    fn top_bucket_saturates_on_oversized_input() {
        let h = Histogram::new();
        h.record(u64::MAX);
        let counts = h.bucket_counts();
        assert_eq!(counts[BUCKET_COUNT - 1], 1);
        assert_eq!(h.count(), 1);
        // No panic / overflow, and the estimate is the top bound.
        assert_eq!(
            h.quantile_permille(500),
            bucket_upper_bound(BUCKET_COUNT - 1)
        );
    }

    #[test]
    fn quantile_within_factor_two_of_reference() {
        let h = Histogram::new();
        let mut sample: Vec<u64> = Vec::new();
        for i in 1..=1000u64 {
            let v = i * 7 + 3; // spread across many buckets
            h.record(v);
            sample.push(v);
        }
        sample.sort_unstable();

        for &(perm, _label) in &[
            (500u32, "p50"),
            (900, "p90"),
            (950, "p95"),
            (990, "p99"),
            (999, "p99.9"),
        ] {
            let est = h.quantile_permille(perm);
            // Reference: ceil-rank order statistic.
            let len = u64::try_from(sample.len()).unwrap();
            let rank = usize::try_from((u128::from(len) * u128::from(perm)).div_ceil(1000).max(1))
                .unwrap();
            let reference = sample[rank - 1];
            assert!(est >= reference, "perm {perm}: est {est} < ref {reference}");
            assert!(
                est <= reference.saturating_mul(2),
                "perm {perm}: est {est} > 2*ref {reference}"
            );
        }
    }

    #[test]
    fn per_stage_histograms_are_independent() {
        let s = StageHistograms::new();
        s.record(Stage::Match, 100);
        s.record(Stage::Match, 200);
        s.record(Stage::Verify, 50);
        assert_eq!(s.histogram(Stage::Match).count(), 2);
        assert_eq!(s.histogram(Stage::Verify).count(), 1);
        assert_eq!(s.histogram(Stage::Ingress).count(), 0);
    }

    #[test]
    fn empty_histogram_quantile_is_zero() {
        let h = Histogram::new();
        assert_eq!(h.quantile_permille(990), 0);
        assert_eq!(h.quantiles(), Quantiles::default());
    }
}

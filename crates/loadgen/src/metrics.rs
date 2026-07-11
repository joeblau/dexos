//! Fixed-capacity latency sampling and integer percentile aggregation.
//!
//! Latency samples are nanosecond integers. A [`SampleSet`] holds a bounded number
//! of them; once full it counts further samples as dropped rather than growing without
//! limit or silently discarding them unnoticed. Percentiles use the nearest-rank
//! method on a sorted copy, so results are deterministic and free of floating point.

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
}

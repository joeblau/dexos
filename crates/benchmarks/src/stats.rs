//! Latency statistics: integer-only percentile computation and the per-suite
//! result record.
//!
//! Percentiles use the **nearest-rank** method computed entirely in integer
//! arithmetic, so a query over an identical sample multiset is bit-identical
//! across runs and platforms (no floating point anywhere on this path). Inputs
//! are nanosecond durations.

/// Hardware performance-counter readings for one benchmark.
///
/// These require privileged `perf_event` access (Linux) and are **not** sampled
/// on this platform. Rather than fabricate or silently omit them, the fields are
/// carried explicitly as `None` with `supported == false`, so a consumer can
/// tell "unavailable here" apart from a genuine zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HwCounters {
    /// Whether hardware counters were captured for this run.
    pub supported: bool,
    /// Retired CPU cycles, if measured.
    pub cpu_cycles: Option<u64>,
    /// Last-level cache misses, if measured.
    pub cache_misses: Option<u64>,
    /// Mispredicted branches, if measured.
    pub branch_misses: Option<u64>,
}

impl HwCounters {
    /// The unsupported reading used on hosts without counter access.
    #[must_use]
    pub const fn unsupported() -> Self {
        HwCounters {
            supported: false,
            cpu_cycles: None,
            cache_misses: None,
            branch_misses: None,
        }
    }
}

/// The nearest-rank percentile of `sorted` (ascending) for the permille `q`
/// (e.g. `500` = p50, `999` = p99.9). Returns `0` for an empty slice.
///
/// Rank is `ceil(q * n / 1000)` clamped to `[1, n]`, and the selected value is
/// `sorted[rank - 1]`. All integer arithmetic — deterministic and float-free.
#[must_use]
pub fn percentile_permille(sorted: &[u64], q: u32) -> u64 {
    let n = sorted.len();
    if n == 0 {
        return 0;
    }
    let n_u128 = n as u128;
    // rank = ceil(q * n / 1000)
    let rank = (u128::from(q) * n_u128).div_ceil(1000);
    let rank = rank.clamp(1, n_u128);
    // rank in [1, n] so the index is in bounds.
    let idx = usize::try_from(rank - 1).unwrap_or(n - 1).min(n - 1);
    sorted[idx]
}

/// Integer operations-per-second from a sample count and total nanoseconds.
/// Returns `0` when `total_ns == 0` to stay total.
#[must_use]
pub fn ops_per_sec(ops: u64, total_ns: u64) -> u64 {
    if total_ns == 0 {
        return 0;
    }
    u64::try_from(u128::from(ops) * 1_000_000_000u128 / u128::from(total_ns)).unwrap_or(u64::MAX)
}

/// The measured result of one benchmark suite. Every field is an integer so the
/// serialized report is bit-stable for a given set of samples.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchStat {
    /// Suite name (spec-stable identifier).
    pub name: String,
    /// Number of timed iterations.
    pub iterations: u64,
    /// Sum of all iteration latencies, nanoseconds.
    pub total_ns: u64,
    /// Minimum iteration latency, nanoseconds.
    pub min_ns: u64,
    /// Median (p50) latency, nanoseconds.
    pub p50_ns: u64,
    /// p90 latency, nanoseconds.
    pub p90_ns: u64,
    /// p95 latency, nanoseconds.
    pub p95_ns: u64,
    /// p99 latency, nanoseconds.
    pub p99_ns: u64,
    /// p99.9 latency, nanoseconds.
    pub p999_ns: u64,
    /// Maximum iteration latency, nanoseconds.
    pub max_ns: u64,
    /// Throughput, operations per second.
    pub ops_per_sec: u64,
    /// Total allocations attributed to the timed closure.
    pub allocations: u64,
    /// Total bytes allocated by the timed closure.
    pub bytes_allocated: u64,
    /// Allocations per operation, scaled by 1000 (milli-allocations) so it stays
    /// an integer: `allocations * 1000 / iterations`.
    pub allocs_per_op_milli: u64,
    /// Whether allocation figures are real (`count-alloc` active) or unmeasured.
    pub alloc_measured: bool,
    /// Hardware performance counters (unsupported on this platform).
    pub counters: HwCounters,
}

impl BenchStat {
    /// Build a stat record from raw nanosecond samples and allocation totals.
    ///
    /// `samples` is consumed and sorted in place. An empty `samples` yields an
    /// all-zero record (used only in degenerate/`iterations == 0` cases).
    #[must_use]
    pub fn from_samples(
        name: impl Into<String>,
        mut samples: Vec<u64>,
        allocations: u64,
        bytes_allocated: u64,
        alloc_measured: bool,
    ) -> Self {
        samples.sort_unstable();
        let iterations = samples.len() as u64;
        let total_ns: u64 = samples.iter().copied().fold(0u64, u64::saturating_add);
        let allocs_per_op_milli = if iterations == 0 {
            0
        } else {
            u64::try_from(u128::from(allocations) * 1000u128 / u128::from(iterations))
                .unwrap_or(u64::MAX)
        };
        BenchStat {
            name: name.into(),
            iterations,
            total_ns,
            min_ns: samples.first().copied().unwrap_or(0),
            p50_ns: percentile_permille(&samples, 500),
            p90_ns: percentile_permille(&samples, 900),
            p95_ns: percentile_permille(&samples, 950),
            p99_ns: percentile_permille(&samples, 990),
            p999_ns: percentile_permille(&samples, 999),
            max_ns: samples.last().copied().unwrap_or(0),
            ops_per_sec: ops_per_sec(iterations, total_ns),
            allocations,
            bytes_allocated,
            allocs_per_op_milli,
            alloc_measured,
            counters: HwCounters::unsupported(),
        }
    }

    /// Percentiles are monotonically non-decreasing, as an ordering invariant.
    #[must_use]
    pub fn percentiles_monotonic(&self) -> bool {
        self.min_ns <= self.p50_ns
            && self.p50_ns <= self.p90_ns
            && self.p90_ns <= self.p95_ns
            && self.p95_ns <= self.p99_ns
            && self.p99_ns <= self.p999_ns
            && self.p999_ns <= self.max_ns
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Lcg;

    #[test]
    fn percentile_on_known_sample_set() {
        // 1..=100 sorted. Nearest-rank: rank = ceil(q*100/1000), value = rank.
        let samples: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile_permille(&samples, 500), 50); // ceil(50)  -> idx 49 -> 50
        assert_eq!(percentile_permille(&samples, 900), 90);
        assert_eq!(percentile_permille(&samples, 950), 95);
        assert_eq!(percentile_permille(&samples, 990), 99);
        assert_eq!(percentile_permille(&samples, 999), 100); // ceil(99.9) = 100
        assert_eq!(percentile_permille(&samples, 0), 1); // clamped to rank 1
        assert_eq!(percentile_permille(&samples, 1000), 100);
    }

    #[test]
    fn percentile_small_and_boundary() {
        assert_eq!(percentile_permille(&[], 500), 0);
        assert_eq!(percentile_permille(&[7], 500), 7);
        assert_eq!(percentile_permille(&[7], 999), 7);
        // Duplicates: all identical -> every percentile equal.
        let dup = vec![42u64; 50];
        assert_eq!(percentile_permille(&dup, 500), 42);
        assert_eq!(percentile_permille(&dup, 999), 42);
    }

    #[test]
    fn ten_element_hand_computed() {
        // 10 samples: ranks land on exact indices.
        let s: Vec<u64> = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        // p50: ceil(500*10/1000)=5 -> idx 4 -> 50
        assert_eq!(percentile_permille(&s, 500), 50);
        // p90: ceil(9)=9 -> idx 8 -> 90
        assert_eq!(percentile_permille(&s, 900), 90);
        // p99: ceil(9.9)=10 -> idx 9 -> 100
        assert_eq!(percentile_permille(&s, 990), 100);
    }

    #[test]
    fn ops_per_sec_is_integer_and_total() {
        assert_eq!(ops_per_sec(1000, 1_000_000_000), 1000);
        assert_eq!(ops_per_sec(1, 1_000_000), 1000);
        assert_eq!(ops_per_sec(5, 0), 0); // no division by zero
    }

    #[test]
    fn from_samples_monotonic_and_deterministic() {
        let build = || {
            let mut r = Lcg::new(0xABCD);
            let samples: Vec<u64> = (0..500).map(|_| r.next_u64() % 10_000).collect();
            BenchStat::from_samples("x", samples, 0, 0, true)
        };
        let a = build();
        let b = build();
        assert_eq!(a, b, "identical samples -> bit-identical stat");
        assert!(a.percentiles_monotonic());
        assert_eq!(a.iterations, 500);
    }

    #[test]
    fn property_percentiles_within_oracle_bound() {
        // Property: nearest-rank percentile equals the reference sorted-sample
        // oracle exactly, across randomized inputs.
        let mut r = Lcg::new(0x1234_5678);
        for _ in 0..200 {
            let n = 1 + r.upto(300);
            let mut samples: Vec<u64> = (0..n).map(|_| r.next_u64() % 1_000_000).collect();
            samples.sort_unstable();
            for &q in &[500u32, 900, 950, 990, 999] {
                let got = percentile_permille(&samples, q);
                let rank = ((u128::from(q) * (n as u128)).div_ceil(1000)).clamp(1, n as u128);
                let idx = usize::try_from(rank - 1).unwrap();
                assert_eq!(got, samples[idx]);
            }
        }
    }
}

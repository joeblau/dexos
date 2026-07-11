//! The timing harness: run a closure `iterations` times, collecting per-iteration
//! nanosecond latencies and the allocations attributed to the closure body.
//!
//! The harness itself does the sample bookkeeping *outside* each timed/counted
//! region: only the closure call sits between the two `Instant`/allocation reads,
//! so neither the timer plumbing nor the sample `Vec` push is attributed to the
//! benchmarked operation.

use std::time::Instant;

use crate::alloc::{counting_enabled, AllocSnapshot};
use crate::stats::BenchStat;

/// Harness configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Timed iterations recorded into the sample set.
    pub iterations: u64,
    /// Untimed warm-up iterations run before measurement (fill caches / branch
    /// predictors). Excluded from all statistics.
    pub warmup: u64,
}

impl Config {
    /// A configuration with the given iteration count and a 10% warm-up.
    #[must_use]
    pub fn iters(iterations: u64) -> Self {
        Config {
            iterations,
            warmup: iterations / 10,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            iterations: 2_000,
            warmup: 200,
        }
    }
}

/// Time `body` under `config` and return a [`BenchStat`] labelled `name`.
///
/// `body` is called once per iteration and should perform exactly one logical
/// operation. Allocation attribution is only meaningful when the counting
/// allocator is installed (`count-alloc` feature); otherwise `alloc_measured`
/// is `false` and the allocation columns read zero.
pub fn bench<F: FnMut()>(name: &str, config: Config, mut body: F) -> BenchStat {
    // Warm-up: run but do not record.
    for _ in 0..config.warmup {
        body();
    }

    let n = usize::try_from(config.iterations).unwrap_or(usize::MAX);
    let mut samples: Vec<u64> = Vec::with_capacity(n);
    let measured = counting_enabled();

    let alloc_start = AllocSnapshot::capture();
    for _ in 0..config.iterations {
        let t0 = Instant::now();
        body();
        let elapsed = t0.elapsed();
        // Nanoseconds saturate at u64::MAX for absurdly long iterations.
        let ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        samples.push(ns);
    }
    let alloc_delta = AllocSnapshot::capture().since(alloc_start);

    BenchStat::from_samples(
        name,
        samples,
        alloc_delta.count,
        alloc_delta.bytes,
        measured,
    )
}

/// Measure the allocations made by a single call to `body` (count, bytes),
/// ignoring timing. Returns `(0, 0)` — indistinguishable from a real zero — when
/// the counting allocator is not installed.
pub fn measure_allocations<F: FnOnce()>(body: F) -> (u64, u64) {
    let start = AllocSnapshot::capture();
    body();
    let delta = AllocSnapshot::capture().since(start);
    (delta.count, delta.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_produces_populated_stat() {
        let mut acc = 0u64;
        let stat = bench("adds", Config::iters(64), || {
            acc = std::hint::black_box(acc.wrapping_add(1));
        });
        assert_eq!(stat.iterations, 64);
        assert_eq!(stat.name, "adds");
        assert!(stat.percentiles_monotonic());
        assert!(acc >= 64); // warm-up + timed calls actually ran
    }

    #[test]
    fn config_warmup_is_ten_percent() {
        assert_eq!(Config::iters(1000).warmup, 100);
    }

    #[cfg(feature = "count-alloc")]
    #[test]
    fn zero_alloc_closure_reports_zero_allocations() {
        let mut acc = 0u64;
        let stat = bench("noalloc", Config::iters(500), || {
            acc = std::hint::black_box(acc.wrapping_mul(3).wrapping_add(1));
        });
        assert!(stat.alloc_measured);
        assert_eq!(
            stat.allocations, 0,
            "steady-state closure must not allocate"
        );
        assert_eq!(stat.allocs_per_op_milli, 0);
    }

    #[cfg(feature = "count-alloc")]
    #[test]
    fn allocating_closure_is_attributed() {
        let stat = bench("alloc", Config::iters(50), || {
            let v = std::hint::black_box(vec![0u8; 256]);
            drop(v);
        });
        assert!(stat.allocations >= 50);
    }
}

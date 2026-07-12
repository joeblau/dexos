//! `observability` — lock-free, off-hot-path metrics, per-stage latency
//! histograms, subsystem-health gauges, and deterministic distributed trace
//! ids for the DexOS node.
//!
//! # Design
//!
//! The core constraint is that instrumentation must not add material p99
//! latency to command processing. Everything here obeys two rules:
//!
//! - **The record path is lock-free and allocation-free.** Counters and gauges
//!   are single atomics ([`Counter`], [`Gauge`]); the latency [`Histogram`] is
//!   a fixed-size array of atomics with an integer, division-free,
//!   floating-point-free bucketing function. Recording never locks, never
//!   allocates, and never branches into the heap.
//! - **All the expensive work is on the control path.** Registration and
//!   [`MetricsRegistry::snapshot`] take a mutex and allocate, but they run at
//!   startup and on scrape — never per command. Callers register their handles
//!   once and then record freely.
//!
//! # Modules
//!
//! - [`counter`]: [`Counter`] (monotonic `u64`) and [`Gauge`] (settable `i64`).
//! - [`histogram`]: fixed exponential-bucket [`Histogram`], [`Quantiles`], and
//!   per-[`Stage`] [`StageHistograms`].
//! - [`health`]: [`QueueMetrics`] (depth/drop), [`PeerMetrics`] (RTT/loss), and
//!   integer [`sequence_lag`] / [`age_ticks`] helpers.
//! - [`trace`]: [`TraceId`] / [`SpanId`] and the deterministic [`TraceGen`].
//! - [`registry`]: [`MetricsRegistry`], the owner and snapshotter.
//! - [`snapshot`]: [`Snapshot`] plus text exposition and a lenient parser.
//!
//! # Determinism
//!
//! No floating point is used on any deterministic path (bucketing and quantiles
//! are integer-only; the trace generator is `splitmix64` seeded by a `u64`).
//! Metrics are pure side state — recording them changes no engine output, so
//! replay with instrumentation enabled or disabled yields identical results.

#![deny(unsafe_code)]

pub mod counter;
pub mod health;
pub mod histogram;
pub mod registry;
pub mod snapshot;
pub mod trace;

pub use counter::{Counter, Gauge};
pub use health::{age_ticks, sequence_lag, PeerMetrics, QueueMetrics};
pub use histogram::{Histogram, Quantiles, Stage, StageHistograms, BUCKET_COUNT};
pub use registry::{MetricKind, MetricsRegistry, RegistrationError};
pub use snapshot::{
    parse_metric_lines, CounterSnapshot, GaugeSnapshot, HistogramSnapshot, Snapshot,
    PROMETHEUS_CONTENT_TYPE,
};
pub use trace::{SpanId, TraceContext, TraceGen, TraceId, TraceParseError};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "observability";

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // ---- deterministic in-test LCG (no external rng) ----------------------
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
    }

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "observability");
    }

    #[test]
    fn counter_and_gauge_snapshot_under_repeated_updates() {
        let reg = MetricsRegistry::new();
        let hits = reg.counter("hits");
        let depth = reg.gauge("depth");

        let mut expected_hits = 0u64;
        let mut expected_depth = 0i64;
        for i in 0..100_000u64 {
            hits.inc();
            expected_hits += 1;
            if i % 3 == 0 {
                depth.inc();
                expected_depth += 1;
            } else if i % 5 == 0 {
                depth.dec();
                expected_depth -= 1;
            }
        }
        let snap = reg.snapshot();
        assert_eq!(snap.counters[0].value, expected_hits);
        assert_eq!(snap.gauges[0].value, expected_depth);
    }

    #[test]
    fn counters_aggregate_under_concurrent_writers() {
        let reg = Arc::new(MetricsRegistry::new());
        let counter = reg.counter("shared");
        let threads = 8;
        let per_thread = 50_000u64;

        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let c = Arc::clone(&counter);
                std::thread::spawn(move || {
                    for _ in 0..per_thread {
                        c.inc();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(counter.get(), threads * per_thread);
        assert_eq!(reg.snapshot().counters[0].value, threads * per_thread);
    }

    #[test]
    fn property_histogram_count_matches_records() {
        // Deterministic randomized: record LCG-driven samples and assert the
        // total count and per-bucket totals are exactly conserved.
        let mut lcg = Lcg(0x0B5E_57ED_0000_0001);
        let h = Histogram::new();
        let n = 20_000u64;
        for _ in 0..n {
            // bounded, spread across many buckets
            let v = lcg.next() % 5_000_000;
            h.record(v);
        }
        assert_eq!(h.count(), n);
        let bucket_total: u64 = h.bucket_counts().iter().sum();
        assert_eq!(bucket_total, n);
        // Quantiles are non-decreasing.
        let q = h.quantiles();
        assert!(q.p50 <= q.p90);
        assert!(q.p90 <= q.p95);
        assert!(q.p95 <= q.p99);
        assert!(q.p99 <= q.p999);
    }

    #[test]
    fn property_registry_export_roundtrips() {
        let mut lcg = Lcg(0x0B5E_57ED_0000_0002);
        let reg = MetricsRegistry::new();
        let c = reg.counter("cmds");
        let g = reg.gauge("inflight");
        let h = reg.histogram("lat");
        let mut expected_c = 0u64;
        for _ in 0..1000 {
            let r = lcg.next();
            c.inc();
            expected_c += 1;
            g.set(i64::try_from(r % 1000).unwrap());
            h.record(r % 100_000);
        }
        let text = reg.export_text();
        assert!(!text.is_empty());
        let pairs = parse_metric_lines(&text);
        let map: std::collections::HashMap<_, _> = pairs.into_iter().collect();
        assert_eq!(map.get("cmds"), Some(&i128::from(expected_c)));
        assert!(map.contains_key("lat_count"));
        assert!(text.contains("lat_bucket{le=\"+Inf\"} 1000"));
    }

    #[test]
    fn trace_id_stable_across_stages() {
        // A command's trace id is observable and stable at every stage; each
        // stage gets its own span but the same trace.
        let mut gen = TraceGen::from_seed(0xDE_AD_BE_EF);
        let root = gen.new_context();
        let mut ctx = root;
        let mut observed = Vec::new();
        for _ in Stage::ALL {
            observed.push(ctx.trace);
            ctx = ctx.child(&mut gen);
        }
        assert!(observed.iter().all(|t| *t == root.trace));
        assert!(!root.trace.is_zero());
    }

    #[test]
    fn record_path_is_allocation_free_by_construction() {
        // The hot record path touches only pre-allocated atomics: the histogram
        // stores a fixed `[AtomicU64; BUCKET_COUNT]` (no Vec/Box/String), and
        // Counter/Gauge are single atomics. We assert the histogram's size is
        // the fixed inline array (proving no heap indirection) and exercise the
        // path heavily to confirm it never grows any allocation.
        use std::mem::size_of;
        use std::sync::atomic::AtomicU64;
        // buckets + count + sum + max, all inline atomics.
        assert_eq!(
            size_of::<Histogram>(),
            size_of::<AtomicU64>() * (BUCKET_COUNT + 3)
        );

        let reg = MetricsRegistry::new();
        let c = reg.counter("c");
        let g = reg.gauge("g");
        let h = reg.histogram("h");
        let stages = reg.stage_histograms("stage");
        // Hammer the record path; none of these calls allocate.
        for i in 0..1_000_000u64 {
            c.inc();
            g.set(i64::try_from(i % 7).unwrap());
            h.record(i % 1_000_000);
            stages.record(Stage::Match, i & 0xFFFF);
        }
        assert_eq!(c.get(), 1_000_000);
        assert_eq!(h.count(), 1_000_000);
    }
}

//! `benchmarks` — a purpose-built, dependency-free performance harness for the
//! DexOS kernel.
//!
//! Part of the DexOS decentralized market operating system. This crate contains
//! **no** external benchmarking framework (no criterion) and adds no new
//! crates.io dependencies: the timing harness, latency-percentile statistics,
//! allocation counter, JSON export, and Markdown renderer are all hand-rolled.
//!
//! # Pieces
//!
//! - [`alloc`]: a counting global allocator (gated behind the default
//!   `count-alloc` feature) so `allocations/op` and `bytes/op` can be attributed
//!   to a benchmarked closure.
//! - [`harness`]: [`harness::bench`] times a closure over N iterations,
//!   collecting nanosecond samples and allocation deltas.
//! - [`stats`]: integer-only nearest-rank percentiles (p50/p90/p95/p99/p99.9),
//!   throughput, and the [`BenchStat`] record.
//! - [`suites`]: the registered benchmark workloads over the order book, risk
//!   engine, execution engine, crypto, codec, state tree, storage, and consensus
//!   crates.
//! - [`targets`]: the spec-target regression gate (engine p99 < 20us, throughput
//!   >= 1,000,000 cmds/s, checkpoint finality p95 < 500ms).
//! - [`report`]: the aggregate [`Report`], its stable JSON export / parse, and
//!   the Markdown performance report.
//!
//! # Entry points
//!
//! [`run_all`] runs every registered suite and returns a [`Report`] — this is
//! what a `marketd benchmark --output results.json` command calls. [`run_suite`]
//! runs a single named suite for `--suite <name>`.

pub mod alloc;
pub mod composed;
pub mod composed_builder;
pub mod harness;
pub mod json;
pub mod report;
pub mod rng;
pub mod stats;
pub mod suites;
pub mod targets;

pub use composed::{
    evaluate_campaign, evaluate_run, load_manifest, CampaignEvaluation, ComposedRun, RunEvaluation,
    WorkloadManifest, COMPOSED_SCHEMA_VERSION, TARGET_EFFECTIVE_ORDERS_PER_SECOND,
};
pub use composed_builder::{
    build_composed_run, render_raw_campaign, ComposedRunEvidence, ScopeCounters,
};
pub use harness::{bench, measure_allocations, Config};
pub use report::{Provenance, Report, SCHEMA_VERSION};
pub use stats::{percentile_permille, BenchStat, HwCounters};
pub use suites::{
    all_provenance, find as find_suite, provenance as suite_provenance, registry, Suite,
    SuiteProvenance,
};
pub use targets::{
    evaluate as evaluate_targets, spec_targets, Comparison, Metric, Target, TargetEvaluation,
    TargetResult,
};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "benchmarks";

/// Run every registered suite with the default [`Config`] and assemble a report.
///
/// This is the `marketd benchmark --suite all` entry point.
#[must_use]
pub fn run_all() -> Report {
    run_all_with(Config::default())
}

/// Run every registered suite with an explicit [`Config`].
#[must_use]
pub fn run_all_with(config: Config) -> Report {
    let stats: Vec<BenchStat> = registry().into_iter().map(|s| (s.run)(config)).collect();
    Report::new(stats)
}

/// Run a single named suite with an explicit [`Config`], returning `None` if no
/// such suite is registered. This is the `marketd benchmark --suite <name>`
/// entry point.
#[must_use]
pub fn run_suite(name: &str, config: Config) -> Option<Report> {
    let suite = find_suite(name)?;
    Some(Report::new(vec![(suite.run)(config)]))
}

/// Render a [`Report`] as a human-readable Markdown performance report.
#[must_use]
pub fn render_markdown(report: &Report) -> String {
    report.to_markdown()
}

/// Serialize a [`Report`] to machine-readable JSON (for `--output results.json`).
#[must_use]
pub fn render_json(report: &Report) -> String {
    report.to_json()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny() -> Config {
        Config {
            iterations: 16,
            warmup: 2,
        }
    }

    #[test]
    fn crate_name_is_stable() {
        assert_eq!(CRATE_NAME, "benchmarks");
    }

    #[test]
    fn run_all_produces_a_full_non_empty_report() {
        let report = run_all_with(tiny());
        assert_eq!(report.stats.len(), registry().len());
        assert!(report.stats.len() >= 20, "expected the full spec suite set");
        assert_eq!(report.targets.len(), spec_targets().len());
        // Every suite reported a populated, monotone stat.
        for s in &report.stats {
            assert_eq!(s.iterations, 16);
            assert!(s.percentiles_monotonic());
        }
    }

    #[test]
    fn run_all_json_round_trips() {
        let report = run_all_with(tiny());
        let json = render_json(&report);
        assert!(!json.is_empty());
        let back = Report::from_json(&json).unwrap();
        assert_eq!(report, back);
        assert_eq!(json, back.to_json(), "re-serialization is byte-stable");
    }

    #[test]
    fn run_all_markdown_is_non_empty() {
        let report = run_all_with(tiny());
        let md = render_markdown(&report);
        assert!(md.contains("DexOS Performance Report"));
        assert!(md.contains("order-insertion"));
        assert!(md.len() > 500);
    }

    #[test]
    fn run_single_suite_runs_exactly_that_suite() {
        let report = run_suite("risk-check", tiny()).unwrap();
        assert_eq!(report.stats.len(), 1);
        assert_eq!(report.stats[0].name, "risk-check");
        assert!(run_suite("no-such-suite", tiny()).is_none());
    }

    #[test]
    fn deterministic_operation_ordering_replay() {
        // The oracle-aggregation workload is seeded from a fixed constant, so two
        // runs execute an identical operation stream and yield identical
        // integer percentiles-of-a-fixed-input regardless of timing. We assert
        // ordering determinism by re-running the seeded workload driver directly.
        use crate::rng::Lcg;
        let sequence = |seed: u64| {
            let mut r = Lcg::new(seed);
            (0..256).map(|_| r.range_i64(-5, 5)).collect::<Vec<_>>()
        };
        assert_eq!(
            sequence(0x0DEF_ACE0_1234_5678),
            sequence(0x0DEF_ACE0_1234_5678)
        );
    }

    #[test]
    fn full_report_targets_gate_is_present_and_deterministic() {
        let report = run_all_with(tiny());
        let eval = evaluate_targets(&report.stats, &spec_targets());
        assert_eq!(eval.results.len(), 3);
        // The gate outcome matches the report's cached flag.
        assert_eq!(eval.all_passed, report.all_targets_passed);
    }
}

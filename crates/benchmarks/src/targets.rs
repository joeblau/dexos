//! Spec performance targets and the pass/fail regression gate.
//!
//! Evaluation is integer-only and deterministic: the same report model yields
//! identical [`TargetResult`]s on every run. A missing suite/metric is reported
//! as `missing == true` (and therefore not passing) rather than panicking.

use crate::stats::BenchStat;

/// Which comparison a target applies between the measured metric and threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    /// Measured value must be strictly less than the threshold (latency-style).
    LessThan,
    /// Measured value must be greater than or equal to the threshold
    /// (throughput-style).
    GreaterOrEqual,
}

impl Comparison {
    /// The canonical operator string, for reports.
    #[must_use]
    pub fn symbol(self) -> &'static str {
        match self {
            Comparison::LessThan => "<",
            Comparison::GreaterOrEqual => ">=",
        }
    }

    fn holds(self, measured: u64, threshold: u64) -> bool {
        match self {
            Comparison::LessThan => measured < threshold,
            Comparison::GreaterOrEqual => measured >= threshold,
        }
    }
}

/// The metric of a [`BenchStat`] a target reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metric {
    /// p95 latency, nanoseconds.
    P95Ns,
    /// p99 latency, nanoseconds.
    P99Ns,
    /// Throughput, operations per second.
    OpsPerSec,
}

impl Metric {
    /// The stable identifier used in serialized output.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Metric::P95Ns => "p95_ns",
            Metric::P99Ns => "p99_ns",
            Metric::OpsPerSec => "ops_per_sec",
        }
    }

    fn read(self, stat: &BenchStat) -> u64 {
        match self {
            Metric::P95Ns => stat.p95_ns,
            Metric::P99Ns => stat.p99_ns,
            Metric::OpsPerSec => stat.ops_per_sec,
        }
    }
}

/// One spec target: a metric of a named suite compared against a threshold.
#[derive(Debug, Clone, Copy)]
pub struct Target {
    /// Stable target id, cited in pass/fail output.
    pub id: &'static str,
    /// Human-readable spec citation.
    pub description: &'static str,
    /// The suite whose metric is evaluated.
    pub suite: &'static str,
    /// Which metric to read.
    pub metric: Metric,
    /// The comparison direction.
    pub comparison: Comparison,
    /// The threshold (nanoseconds or ops/sec).
    pub threshold: u64,
}

/// The outcome of evaluating one [`Target`] against a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetResult {
    /// The target's stable id.
    pub id: String,
    /// The spec citation.
    pub description: String,
    /// The evaluated suite name.
    pub suite: String,
    /// The metric identifier.
    pub metric: String,
    /// The comparison symbol (`<` or `>=`).
    pub comparison: String,
    /// The threshold value.
    pub threshold: u64,
    /// The measured value, or `None` if the suite/metric was absent.
    pub measured: Option<u64>,
    /// Whether the target was satisfied.
    pub passed: bool,
    /// Whether the required suite/metric was missing from the report.
    pub missing: bool,
}

/// The full gate outcome across all targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetEvaluation {
    /// Per-target results.
    pub results: Vec<TargetResult>,
    /// Whether every target passed (and none were missing).
    pub all_passed: bool,
}

impl TargetEvaluation {
    /// Exit code convention: `0` when all targets pass, `1` otherwise. Suitable
    /// for `std::process::exit` in the `marketd benchmark` gate.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        i32::from(!self.all_passed)
    }
}

/// The spec targets the DexOS performance suite gates against.
///
/// Numbers are the exact spec thresholds: engine-only p99 < 20 microseconds,
/// single-market throughput >= 1,000,000 commands/second, and checkpoint
/// finality p95 < 500 milliseconds.
#[must_use]
pub fn spec_targets() -> Vec<Target> {
    vec![
        Target {
            id: "engine-p99-20us",
            description: "engine-only order execution p99 < 20us",
            suite: "market-order-execution",
            metric: Metric::P99Ns,
            comparison: Comparison::LessThan,
            threshold: 20_000,
        },
        Target {
            id: "throughput-1m-cmds",
            description: "single-market order insertion >= 1,000,000 ops/s",
            suite: "order-insertion",
            metric: Metric::OpsPerSec,
            comparison: Comparison::GreaterOrEqual,
            threshold: 1_000_000,
        },
        Target {
            id: "checkpoint-finality-p95-500ms",
            description: "checkpoint construction/finality p95 < 500ms",
            suite: "checkpoint-construction",
            metric: Metric::P95Ns,
            comparison: Comparison::LessThan,
            threshold: 500_000_000,
        },
    ]
}

/// Evaluate `targets` against the measured `stats`.
#[must_use]
pub fn evaluate(stats: &[BenchStat], targets: &[Target]) -> TargetEvaluation {
    let mut results = Vec::with_capacity(targets.len());
    let mut all_passed = true;
    for t in targets {
        let stat = stats.iter().find(|s| s.name == t.suite);
        let (measured, passed, missing) = match stat {
            Some(s) => {
                let m = t.metric.read(s);
                (Some(m), t.comparison.holds(m, t.threshold), false)
            }
            None => (None, false, true),
        };
        if !passed {
            all_passed = false;
        }
        results.push(TargetResult {
            id: t.id.to_string(),
            description: t.description.to_string(),
            suite: t.suite.to_string(),
            metric: t.metric.id().to_string(),
            comparison: t.comparison.symbol().to_string(),
            threshold: t.threshold,
            measured,
            passed,
            missing,
        });
    }
    TargetEvaluation {
        results,
        all_passed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::{BenchStat, HwCounters};

    fn stat(name: &str, p95: u64, p99: u64, ops: u64) -> BenchStat {
        BenchStat {
            name: name.to_string(),
            iterations: 1,
            total_ns: 1,
            min_ns: 0,
            p50_ns: 0,
            p90_ns: 0,
            p95_ns: p95,
            p99_ns: p99,
            p999_ns: 0,
            max_ns: 0,
            ops_per_sec: ops,
            allocations: 0,
            bytes_allocated: 0,
            allocs_per_op_milli: 0,
            alloc_measured: true,
            counters: HwCounters::unsupported(),
        }
    }

    #[test]
    fn passes_just_under_and_fails_just_over_latency() {
        let t = Target {
            id: "engine",
            description: "d",
            suite: "s",
            metric: Metric::P99Ns,
            comparison: Comparison::LessThan,
            threshold: 20_000,
        };
        let under = evaluate(&[stat("s", 0, 19_999, 0)], &[t]);
        assert!(under.all_passed);
        assert_eq!(under.exit_code(), 0);
        let over = evaluate(&[stat("s", 0, 20_000, 0)], &[t]);
        assert!(!over.all_passed);
        assert_eq!(over.exit_code(), 1);
        assert_eq!(over.results[0].measured, Some(20_000));
    }

    #[test]
    fn passes_at_and_fails_below_throughput_boundary() {
        let t = Target {
            id: "tp",
            description: "d",
            suite: "s",
            metric: Metric::OpsPerSec,
            comparison: Comparison::GreaterOrEqual,
            threshold: 1_000_000,
        };
        assert!(evaluate(&[stat("s", 0, 0, 1_000_000)], &[t]).all_passed);
        assert!(!evaluate(&[stat("s", 0, 0, 999_999)], &[t]).all_passed);
    }

    #[test]
    fn missing_suite_is_reported_not_panicked() {
        let t = spec_targets();
        let eval = evaluate(&[], &t);
        assert!(!eval.all_passed);
        assert!(eval.results.iter().all(|r| r.missing && !r.passed));
        assert_eq!(eval.exit_code(), 1);
    }

    #[test]
    fn deterministic_across_runs() {
        let stats = vec![stat("market-order-execution", 5, 10, 2_000_000)];
        let a = evaluate(&stats, &spec_targets());
        let b = evaluate(&stats, &spec_targets());
        assert_eq!(a, b);
    }
}

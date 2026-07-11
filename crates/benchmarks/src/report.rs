//! The aggregate benchmark report: data model, machine-readable JSON export,
//! JSON round-trip parsing, and a human-readable Markdown renderer.

use std::fmt::Write as _;

use crate::json::{self, JsonError, JsonValue, JsonWriter, ObjectWriter};
use crate::stats::{BenchStat, HwCounters};
use crate::targets::{evaluate, spec_targets, TargetResult};

/// The JSON schema version. Bump on any breaking field change.
pub const SCHEMA_VERSION: u32 = 1;

/// Build/environment provenance recorded alongside the measurements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// The report schema version.
    pub schema_version: u32,
    /// The crate that produced the report.
    pub crate_name: String,
    /// The crate version.
    pub crate_version: String,
    /// Target operating system (`std::env::consts::OS`).
    pub host_os: String,
    /// Target architecture (`std::env::consts::ARCH`).
    pub host_arch: String,
    /// Whether allocation counting was active.
    pub alloc_counting: bool,
    /// Whether hardware performance counters were available.
    pub hw_counters_supported: bool,
}

impl Provenance {
    /// Capture provenance for the current build/host.
    #[must_use]
    pub fn capture() -> Self {
        Provenance {
            schema_version: SCHEMA_VERSION,
            crate_name: crate::CRATE_NAME.to_string(),
            crate_version: env!("CARGO_PKG_VERSION").to_string(),
            host_os: std::env::consts::OS.to_string(),
            host_arch: std::env::consts::ARCH.to_string(),
            alloc_counting: crate::alloc::counting_enabled(),
            // No `perf_event` sampling on this build; counters are unsupported.
            hw_counters_supported: false,
        }
    }
}

/// A full benchmark run: provenance, per-suite statistics, and the target gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Build/host provenance.
    pub provenance: Provenance,
    /// Per-suite measured statistics.
    pub stats: Vec<BenchStat>,
    /// Spec-target pass/fail results.
    pub targets: Vec<TargetResult>,
    /// Whether every spec target passed.
    pub all_targets_passed: bool,
}

impl Report {
    /// Assemble a report from measured stats, evaluating the spec targets.
    #[must_use]
    pub fn new(stats: Vec<BenchStat>) -> Self {
        let eval = evaluate(&stats, &spec_targets());
        Report {
            provenance: Provenance::capture(),
            stats,
            targets: eval.results,
            all_targets_passed: eval.all_passed,
        }
    }

    /// A stat by suite name.
    #[must_use]
    pub fn stat(&self, name: &str) -> Option<&BenchStat> {
        self.stats.iter().find(|s| s.name == name)
    }

    // ------------------------------------------------------------------ JSON

    /// Serialize to compact, stable JSON. A given [`Report`] value serializes to
    /// a byte-identical string on every run (keys emitted in a fixed order).
    #[must_use]
    pub fn to_json(&self) -> String {
        JsonWriter::new()
            .write_object(|o| {
                o.object_field("provenance", |po| self.write_provenance(po))
                    .array_field("stats", &self.stats, Self::write_stat)
                    .array_field("targets", &self.targets, Self::write_target)
                    .bool_field("all_targets_passed", self.all_targets_passed)
            })
            .into_string()
    }

    fn write_provenance(&self, o: ObjectWriter) -> ObjectWriter {
        let p = &self.provenance;
        o.int_field("schema_version", i128::from(p.schema_version))
            .str_field("crate_name", &p.crate_name)
            .str_field("crate_version", &p.crate_version)
            .str_field("host_os", &p.host_os)
            .str_field("host_arch", &p.host_arch)
            .bool_field("alloc_counting", p.alloc_counting)
            .bool_field("hw_counters_supported", p.hw_counters_supported)
    }

    fn write_stat(w: JsonWriter, s: &BenchStat) -> JsonWriter {
        w.write_object(|o| {
            o.str_field("name", &s.name)
                .int_field("iterations", i128::from(s.iterations))
                .int_field("total_ns", i128::from(s.total_ns))
                .int_field("min_ns", i128::from(s.min_ns))
                .int_field("p50_ns", i128::from(s.p50_ns))
                .int_field("p90_ns", i128::from(s.p90_ns))
                .int_field("p95_ns", i128::from(s.p95_ns))
                .int_field("p99_ns", i128::from(s.p99_ns))
                .int_field("p999_ns", i128::from(s.p999_ns))
                .int_field("max_ns", i128::from(s.max_ns))
                .int_field("ops_per_sec", i128::from(s.ops_per_sec))
                .int_field("allocations", i128::from(s.allocations))
                .int_field("bytes_allocated", i128::from(s.bytes_allocated))
                .int_field("allocs_per_op_milli", i128::from(s.allocs_per_op_milli))
                .bool_field("alloc_measured", s.alloc_measured)
                .object_field("counters", |co| {
                    co.bool_field("supported", s.counters.supported)
                        .opt_u64_field("cpu_cycles", s.counters.cpu_cycles)
                        .opt_u64_field("cache_misses", s.counters.cache_misses)
                        .opt_u64_field("branch_misses", s.counters.branch_misses)
                })
        })
    }

    fn write_target(w: JsonWriter, t: &TargetResult) -> JsonWriter {
        w.write_object(|o| {
            o.str_field("id", &t.id)
                .str_field("description", &t.description)
                .str_field("suite", &t.suite)
                .str_field("metric", &t.metric)
                .str_field("comparison", &t.comparison)
                .int_field("threshold", i128::from(t.threshold))
                .opt_u64_field("measured", t.measured)
                .bool_field("passed", t.passed)
                .bool_field("missing", t.missing)
        })
    }

    /// Parse a report back from its JSON form. Total on adversarial input:
    /// malformed bytes or schema violations return an error, never a panic.
    pub fn from_json(text: &str) -> Result<Report, JsonError> {
        let v = json::parse(text)?;
        let prov = v.field("provenance")?;
        let provenance = Provenance {
            schema_version: u32::try_from(prov.field("schema_version")?.as_u64()?)
                .map_err(|_| JsonError::Schema("schema_version overflow".into()))?,
            crate_name: prov.field("crate_name")?.as_str()?.to_string(),
            crate_version: prov.field("crate_version")?.as_str()?.to_string(),
            host_os: prov.field("host_os")?.as_str()?.to_string(),
            host_arch: prov.field("host_arch")?.as_str()?.to_string(),
            alloc_counting: prov.field("alloc_counting")?.as_bool()?,
            hw_counters_supported: prov.field("hw_counters_supported")?.as_bool()?,
        };

        let mut stats = Vec::new();
        for s in v.field("stats")?.as_array()? {
            stats.push(parse_stat(s)?);
        }
        let mut targets = Vec::new();
        for t in v.field("targets")?.as_array()? {
            targets.push(parse_target(t)?);
        }
        let all_targets_passed = v.field("all_targets_passed")?.as_bool()?;
        Ok(Report {
            provenance,
            stats,
            targets,
            all_targets_passed,
        })
    }

    // -------------------------------------------------------------- Markdown

    /// Render a human-readable Markdown performance report.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        let p = &self.provenance;
        let _ = writeln!(md, "# DexOS Performance Report\n");

        // Provenance block.
        let _ = writeln!(md, "## Provenance\n");
        let _ = writeln!(md, "- schema version: {}", p.schema_version);
        let _ = writeln!(md, "- crate: {} v{}", p.crate_name, p.crate_version);
        let _ = writeln!(md, "- host: {} / {}", p.host_os, p.host_arch);
        let _ = writeln!(
            md,
            "- allocation counting: {}",
            if p.alloc_counting {
                "enabled"
            } else {
                "disabled (allocation columns unmeasured)"
            }
        );
        let _ = writeln!(
            md,
            "- hardware counters: {}\n",
            if p.hw_counters_supported {
                "available"
            } else {
                "unavailable on this host"
            }
        );

        // Results table.
        let _ = writeln!(md, "## Benchmark suites ({})\n", self.stats.len());
        let _ = writeln!(
            md,
            "| suite | iters | p50 (ns) | p95 (ns) | p99 (ns) | p99.9 (ns) | ops/sec | allocs/op |"
        );
        let _ = writeln!(md, "|---|---:|---:|---:|---:|---:|---:|---:|");
        for s in &self.stats {
            let allocs_per_op = if s.alloc_measured {
                format!(
                    "{}.{:03}",
                    s.allocs_per_op_milli / 1000,
                    s.allocs_per_op_milli % 1000
                )
            } else {
                "n/a".to_string()
            };
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} | {} | {} | {} | {} |",
                s.name,
                s.iterations,
                s.p50_ns,
                s.p95_ns,
                s.p99_ns,
                s.p999_ns,
                s.ops_per_sec,
                allocs_per_op,
            );
        }

        // Target gate.
        let _ = writeln!(
            md,
            "\n## Spec target gate: {}\n",
            if self.all_targets_passed {
                "PASS"
            } else {
                "FAIL"
            }
        );
        let _ = writeln!(
            md,
            "| target | suite | metric | required | measured | result |"
        );
        let _ = writeln!(md, "|---|---|---|---|---:|---|");
        for t in &self.targets {
            let measured = match t.measured {
                Some(m) => m.to_string(),
                None => "missing".to_string(),
            };
            let result = if t.missing {
                "MISSING"
            } else if t.passed {
                "pass"
            } else {
                "FAIL"
            };
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} {} | {} | {} |",
                t.id, t.suite, t.metric, t.comparison, t.threshold, measured, result,
            );
        }
        md
    }
}

fn parse_counters(v: &JsonValue) -> Result<HwCounters, JsonError> {
    let opt = |k: &str| -> Result<Option<u64>, JsonError> {
        match v.field(k)? {
            JsonValue::Null => Ok(None),
            other => Ok(Some(other.as_u64()?)),
        }
    };
    Ok(HwCounters {
        supported: v.field("supported")?.as_bool()?,
        cpu_cycles: opt("cpu_cycles")?,
        cache_misses: opt("cache_misses")?,
        branch_misses: opt("branch_misses")?,
    })
}

fn parse_stat(v: &JsonValue) -> Result<BenchStat, JsonError> {
    Ok(BenchStat {
        name: v.field("name")?.as_str()?.to_string(),
        iterations: v.field("iterations")?.as_u64()?,
        total_ns: v.field("total_ns")?.as_u64()?,
        min_ns: v.field("min_ns")?.as_u64()?,
        p50_ns: v.field("p50_ns")?.as_u64()?,
        p90_ns: v.field("p90_ns")?.as_u64()?,
        p95_ns: v.field("p95_ns")?.as_u64()?,
        p99_ns: v.field("p99_ns")?.as_u64()?,
        p999_ns: v.field("p999_ns")?.as_u64()?,
        max_ns: v.field("max_ns")?.as_u64()?,
        ops_per_sec: v.field("ops_per_sec")?.as_u64()?,
        allocations: v.field("allocations")?.as_u64()?,
        bytes_allocated: v.field("bytes_allocated")?.as_u64()?,
        allocs_per_op_milli: v.field("allocs_per_op_milli")?.as_u64()?,
        alloc_measured: v.field("alloc_measured")?.as_bool()?,
        counters: parse_counters(v.field("counters")?)?,
    })
}

fn parse_target(v: &JsonValue) -> Result<TargetResult, JsonError> {
    let measured = match v.field("measured")? {
        JsonValue::Null => None,
        other => Some(other.as_u64()?),
    };
    Ok(TargetResult {
        id: v.field("id")?.as_str()?.to_string(),
        description: v.field("description")?.as_str()?.to_string(),
        suite: v.field("suite")?.as_str()?.to_string(),
        metric: v.field("metric")?.as_str()?.to_string(),
        comparison: v.field("comparison")?.as_str()?.to_string(),
        threshold: v.field("threshold")?.as_u64()?,
        measured,
        passed: v.field("passed")?.as_bool()?,
        missing: v.field("missing")?.as_bool()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::HwCounters;

    fn sample_stat(name: &str) -> BenchStat {
        BenchStat {
            name: name.to_string(),
            iterations: 100,
            total_ns: 100_000,
            min_ns: 500,
            p50_ns: 900,
            p90_ns: 1_200,
            p95_ns: 1_500,
            p99_ns: 1_900,
            p999_ns: 2_500,
            max_ns: 3_000,
            ops_per_sec: 1_100_000,
            allocations: 0,
            bytes_allocated: 0,
            allocs_per_op_milli: 0,
            alloc_measured: true,
            counters: HwCounters::unsupported(),
        }
    }

    fn sample_report() -> Report {
        Report::new(vec![
            sample_stat("order-insertion"),
            sample_stat("market-order-execution"),
            sample_stat("checkpoint-construction"),
        ])
    }

    #[test]
    fn json_round_trips_losslessly() {
        let r = sample_report();
        let text = r.to_json();
        let back = Report::from_json(&text).unwrap();
        assert_eq!(r, back);
        // Re-serializing the parsed model is byte-identical.
        assert_eq!(text, back.to_json());
    }

    #[test]
    fn json_is_stable_across_serializations() {
        let r = sample_report();
        assert_eq!(r.to_json(), r.to_json());
    }

    #[test]
    fn markdown_is_non_empty_and_lists_suites() {
        let r = sample_report();
        let md = r.to_markdown();
        assert!(md.contains("# DexOS Performance Report"));
        assert!(md.contains("order-insertion"));
        assert!(md.contains("Spec target gate"));
        assert!(md.len() > 200);
    }

    #[test]
    fn from_json_rejects_malformed_without_panic() {
        assert!(Report::from_json("not json").is_err());
        assert!(Report::from_json("{}").is_err());
        assert!(Report::from_json(r#"{"provenance":{}}"#).is_err());
        // Truncated but structurally-started.
        assert!(Report::from_json(r#"{"stats":["#).is_err());
    }

    #[test]
    fn all_targets_passed_reflected_in_report() {
        // order-insertion ops/sec 1.1M >= 1M, engine p99 1900 < 20000,
        // checkpoint p95 1500 < 500ms: all pass.
        let r = sample_report();
        assert!(r.all_targets_passed);
        assert_eq!(r.targets.len(), 3);
    }
}

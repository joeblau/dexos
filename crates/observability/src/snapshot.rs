//! Point-in-time [`Snapshot`] of every registered metric plus a machine-
//! readable text exposition (Prometheus-style) and a lenient parser.
//!
//! Snapshotting and exporting are **off the hot path**: they lock the registry,
//! allocate, and format. The record path never touches this module.

use crate::histogram::Quantiles;

/// One counter's exported value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterSnapshot {
    /// Registered metric name.
    pub name: String,
    /// Current value.
    pub value: u64,
}

/// One gauge's exported value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GaugeSnapshot {
    /// Registered metric name.
    pub name: String,
    /// Current value.
    pub value: i64,
}

/// One histogram's exported summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistogramSnapshot {
    /// Registered metric name.
    pub name: String,
    /// Total observations.
    pub count: u64,
    /// Sum of observed values.
    pub sum: u64,
    /// Largest observed value.
    pub max: u64,
    /// p50/p90/p95/p99/p99.9 estimates.
    pub quantiles: Quantiles,
}

/// A consistent-as-of-read snapshot of all metrics in a registry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// All counters, in registration order.
    pub counters: Vec<CounterSnapshot>,
    /// All gauges, in registration order.
    pub gauges: Vec<GaugeSnapshot>,
    /// All histograms, in registration order.
    pub histograms: Vec<HistogramSnapshot>,
}

impl Snapshot {
    /// Total number of exported metric families.
    #[must_use]
    pub fn len(&self) -> usize {
        self.counters.len() + self.gauges.len() + self.histograms.len()
    }

    /// True if nothing has been registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.counters.is_empty() && self.gauges.is_empty() && self.histograms.is_empty()
    }

    /// Renders a Prometheus-style text exposition. Every non-comment line is
    /// `key<space>value`, so it round-trips through [`parse_metric_lines`].
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for c in &self.counters {
            out.push_str("# TYPE ");
            out.push_str(&c.name);
            out.push_str(" counter\n");
            out.push_str(&c.name);
            out.push(' ');
            out.push_str(&c.value.to_string());
            out.push('\n');
        }
        for g in &self.gauges {
            out.push_str("# TYPE ");
            out.push_str(&g.name);
            out.push_str(" gauge\n");
            out.push_str(&g.name);
            out.push(' ');
            out.push_str(&g.value.to_string());
            out.push('\n');
        }
        for h in &self.histograms {
            out.push_str("# TYPE ");
            out.push_str(&h.name);
            out.push_str(" histogram\n");
            push_line(&mut out, &format!("{}_count", h.name), i128::from(h.count));
            push_line(&mut out, &format!("{}_sum", h.name), i128::from(h.sum));
            push_line(&mut out, &format!("{}_max", h.name), i128::from(h.max));
            push_line(
                &mut out,
                &format!("{}_p50", h.name),
                i128::from(h.quantiles.p50),
            );
            push_line(
                &mut out,
                &format!("{}_p90", h.name),
                i128::from(h.quantiles.p90),
            );
            push_line(
                &mut out,
                &format!("{}_p95", h.name),
                i128::from(h.quantiles.p95),
            );
            push_line(
                &mut out,
                &format!("{}_p99", h.name),
                i128::from(h.quantiles.p99),
            );
            push_line(
                &mut out,
                &format!("{}_p999", h.name),
                i128::from(h.quantiles.p999),
            );
        }
        out
    }
}

fn push_line(out: &mut String, key: &str, value: i128) {
    out.push_str(key);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

/// Parses a text exposition (as produced by [`Snapshot::to_text`]) into
/// `(key, value)` pairs, skipping blank lines and `#` comments.
///
/// Lenient and total: malformed value tokens are skipped rather than erroring,
/// so this never panics on arbitrary input. Intended for tests and simple
/// scrapers.
#[must_use]
pub fn parse_metric_lines(text: &str) -> Vec<(String, i128)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let Some(key) = parts.next() else { continue };
        let Some(value_str) = parts.next() else {
            continue;
        };
        if let Ok(value) = value_str.trim().parse::<i128>() {
            out.push((key.to_string(), value));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Snapshot {
        Snapshot {
            counters: vec![CounterSnapshot {
                name: "orders_total".to_string(),
                value: 42,
            }],
            gauges: vec![GaugeSnapshot {
                name: "queue_depth".to_string(),
                value: -3,
            }],
            histograms: vec![HistogramSnapshot {
                name: "match_latency_ns".to_string(),
                count: 10,
                sum: 1000,
                max: 300,
                quantiles: Quantiles {
                    p50: 100,
                    p90: 200,
                    p95: 250,
                    p99: 300,
                    p999: 300,
                },
            }],
        }
    }

    #[test]
    fn export_is_non_empty_and_parseable() {
        let text = sample().to_text();
        assert!(!text.is_empty());
        let pairs = parse_metric_lines(&text);
        let map: std::collections::HashMap<_, _> = pairs.into_iter().collect();
        assert_eq!(map.get("orders_total"), Some(&42));
        assert_eq!(map.get("queue_depth"), Some(&-3));
        assert_eq!(map.get("match_latency_ns_count"), Some(&10));
        assert_eq!(map.get("match_latency_ns_p99"), Some(&300));
    }

    #[test]
    fn parser_skips_comments_and_junk() {
        let text = "# comment\n\ngood 5\nbad notanumber\n";
        let pairs = parse_metric_lines(text);
        assert_eq!(pairs, vec![("good".to_string(), 5i128)]);
    }

    #[test]
    fn len_and_is_empty() {
        assert!(Snapshot::default().is_empty());
        assert_eq!(sample().len(), 3);
    }
}

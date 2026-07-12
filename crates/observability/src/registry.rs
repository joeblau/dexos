//! [`MetricsRegistry`] — the owner of every named counter, gauge, and
//! histogram, plus the [`snapshot`](MetricsRegistry::snapshot) that exports
//! them.
//!
//! # Hot path vs. control path
//!
//! Registration and snapshotting take a `Mutex` and may allocate, but they are
//! **control-path** operations done at startup / on scrape. The **hot path** is
//! only ever the atomic methods on the `Arc<Counter>` / `Arc<Gauge>` /
//! `Arc<Histogram>` handles the registry hands back — those never lock and
//! never allocate. Register your handles once, then record freely.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::counter::{Counter, Gauge};
use crate::health::{PeerMetrics, QueueMetrics};
use crate::histogram::{Histogram, Stage, StageHistograms};
use crate::snapshot::{CounterSnapshot, GaugeSnapshot, HistogramSnapshot, Snapshot};

/// Interior, mutex-guarded registry state. Kept separate so the public type can
/// stay `Clone`-free and obviously `Send + Sync`.
#[derive(Default)]
struct Inner {
    descriptors: BTreeMap<String, MetricKind>,
    counters: Vec<(String, Arc<Counter>)>,
    gauges: Vec<(String, Arc<Gauge>)>,
    histograms: Vec<(String, Arc<Histogram>)>,
}

/// Prometheus metric family type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    Counter,
    Gauge,
    Histogram,
}

/// Registration failure caused by reusing one name for another metric type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("metric '{name}' is already registered as {existing:?}, requested {requested:?}")]
pub struct RegistrationError {
    pub name: String,
    pub existing: MetricKind,
    pub requested: MetricKind,
}

/// Owns all metrics and produces snapshots. Share it behind an `Arc` across
/// subsystems; each subsystem registers the handles it needs once.
#[derive(Default)]
pub struct MetricsRegistry {
    inner: Mutex<Inner>,
}

impl MetricsRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers (or returns the existing) counter named `name`. Idempotent:
    /// registering the same name twice returns the same handle, so subsystems
    /// can look up shared counters without coordinating.
    #[must_use]
    pub fn counter(&self, name: &str) -> Arc<Counter> {
        self.try_counter(name).expect("metric name type conflict")
    }

    /// Fallible counter registration that reports cross-family conflicts.
    pub fn try_counter(&self, name: &str) -> Result<Arc<Counter>, RegistrationError> {
        let mut inner = lock(&self.inner);
        register(&mut inner, name, MetricKind::Counter)?;
        if let Some((_, existing)) = inner.counters.iter().find(|(n, _)| n.as_str() == name) {
            return Ok(Arc::clone(existing));
        }
        let handle = Arc::new(Counter::new());
        inner.counters.push((name.to_string(), Arc::clone(&handle)));
        Ok(handle)
    }

    /// Registers (or returns the existing) gauge named `name`. Idempotent.
    #[must_use]
    pub fn gauge(&self, name: &str) -> Arc<Gauge> {
        self.try_gauge(name).expect("metric name type conflict")
    }

    /// Fallible gauge registration that reports cross-family conflicts.
    pub fn try_gauge(&self, name: &str) -> Result<Arc<Gauge>, RegistrationError> {
        let mut inner = lock(&self.inner);
        register(&mut inner, name, MetricKind::Gauge)?;
        if let Some((_, existing)) = inner.gauges.iter().find(|(n, _)| n.as_str() == name) {
            return Ok(Arc::clone(existing));
        }
        let handle = Arc::new(Gauge::new());
        inner.gauges.push((name.to_string(), Arc::clone(&handle)));
        Ok(handle)
    }

    /// Registers (or returns the existing) histogram named `name`. Idempotent.
    #[must_use]
    pub fn histogram(&self, name: &str) -> Arc<Histogram> {
        self.try_histogram(name).expect("metric name type conflict")
    }

    /// Fallible histogram registration that reports cross-family conflicts.
    pub fn try_histogram(&self, name: &str) -> Result<Arc<Histogram>, RegistrationError> {
        let mut inner = lock(&self.inner);
        register(&mut inner, name, MetricKind::Histogram)?;
        if let Some((_, existing)) = inner.histograms.iter().find(|(n, _)| n.as_str() == name) {
            return Ok(Arc::clone(existing));
        }
        let handle = Arc::new(Histogram::new());
        inner
            .histograms
            .push((name.to_string(), Arc::clone(&handle)));
        Ok(handle)
    }

    /// Registers bounded-queue instrumentation: a `{name}_depth` gauge and a
    /// `{name}_dropped` counter, wrapped in [`QueueMetrics`].
    #[must_use]
    pub fn queue(&self, name: &str, capacity: u64) -> QueueMetrics {
        let depth = self.gauge(&format!("{name}_depth"));
        let dropped = self.counter(&format!("{name}_dropped"));
        QueueMetrics::new(depth, dropped, capacity)
    }

    /// Registers peer-link instrumentation: `{name}_rtt_us` and
    /// `{name}_loss_ppm` gauges, wrapped in [`PeerMetrics`].
    #[must_use]
    pub fn peer(&self, name: &str) -> PeerMetrics {
        let rtt = self.gauge(&format!("{name}_rtt_us"));
        let loss = self.gauge(&format!("{name}_loss_ppm"));
        PeerMetrics::new(rtt, loss)
    }

    /// Registers one histogram per [`Stage`] under `{prefix}_{stage}` and
    /// returns a [`StageHistograms`] bound to those handles. Recording through
    /// the returned handle updates the registered histograms.
    #[must_use]
    pub fn stage_histograms(&self, prefix: &str) -> StageHistograms {
        // Register (or fetch) one histogram per stage, then bind the returned
        // handle to those exact shared histograms so recording is visible in
        // the registry snapshot.
        let handles = core::array::from_fn(|i| {
            self.histogram(&format!("{prefix}_{}", Stage::ALL[i].as_str()))
        });
        StageHistograms::from_handles(handles)
    }

    /// Takes a consistent-as-of-read [`Snapshot`] of every registered metric.
    /// Off the hot path: locks once, reads each atomic, and allocates the
    /// result vectors.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let inner = lock(&self.inner);
        let counters = inner
            .counters
            .iter()
            .map(|(name, c)| CounterSnapshot {
                name: name.clone(),
                value: c.get(),
            })
            .collect();
        let gauges = inner
            .gauges
            .iter()
            .map(|(name, g)| GaugeSnapshot {
                name: name.clone(),
                value: g.get(),
            })
            .collect();
        let histograms = inner
            .histograms
            .iter()
            .map(|(name, h)| HistogramSnapshot {
                name: name.clone(),
                count: h.count(),
                sum: h.sum(),
                max: h.max(),
                buckets: h.bucket_counts(),
                quantiles: h.quantiles(),
            })
            .collect();
        Snapshot {
            counters,
            gauges,
            histograms,
        }
    }

    /// Renders the current metrics as a text exposition. Convenience for
    /// `self.snapshot().to_text()`.
    #[must_use]
    pub fn export_text(&self) -> String {
        self.snapshot().to_text()
    }
}

fn register(inner: &mut Inner, name: &str, requested: MetricKind) -> Result<(), RegistrationError> {
    if let Some(&existing) = inner.descriptors.get(name) {
        if existing != requested {
            return Err(RegistrationError {
                name: name.to_owned(),
                existing,
                requested,
            });
        }
    } else {
        inner.descriptors.insert(name.to_owned(), requested);
    }
    Ok(())
}

/// Recovers a poisoned lock rather than panicking: metric state is plain
/// integers with no cross-field invariant, so a poisoned guard is still safe to
/// use. Keeps the control path panic-free.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_is_idempotent() {
        let reg = MetricsRegistry::new();
        let a = reg.counter("hits");
        let b = reg.counter("hits");
        a.add(5);
        assert_eq!(b.get(), 5); // same underlying atomic
        assert_eq!(reg.snapshot().counters.len(), 1);
    }

    #[test]
    fn cross_family_reuse_is_typed_error() {
        let reg = MetricsRegistry::new();
        reg.try_counter("same").unwrap();
        assert_eq!(
            reg.try_gauge("same").unwrap_err(),
            RegistrationError {
                name: "same".into(),
                existing: MetricKind::Counter,
                requested: MetricKind::Gauge
            }
        );
    }

    #[test]
    fn snapshot_reflects_all_families() {
        let reg = MetricsRegistry::new();
        reg.counter("c").inc();
        reg.gauge("g").set(7);
        reg.histogram("h").record(123);
        let snap = reg.snapshot();
        assert_eq!(snap.counters.len(), 1);
        assert_eq!(snap.gauges.len(), 1);
        assert_eq!(snap.histograms.len(), 1);
        assert_eq!(snap.gauges[0].value, 7);
        assert_eq!(snap.histograms[0].count, 1);
    }

    #[test]
    fn queue_and_peer_register_expected_names() {
        let reg = MetricsRegistry::new();
        let q = reg.queue("inbound", 8);
        q.try_push();
        let p = reg.peer("validator3");
        p.set_rtt_us(900);
        let text = reg.export_text();
        assert!(text.contains("inbound_depth"));
        assert!(text.contains("inbound_dropped"));
        assert!(text.contains("validator3_rtt_us"));
        assert!(text.contains("validator3_loss_ppm"));
    }

    #[test]
    fn stage_histograms_registered_and_recording_is_visible() {
        let reg = MetricsRegistry::new();
        let stages = reg.stage_histograms("cmd");
        stages.record(Stage::Match, 500);
        stages.record(Stage::Match, 600);
        let snap = reg.snapshot();
        assert_eq!(snap.histograms.len(), Stage::COUNT);
        // Recording through the handle is visible in the registry snapshot.
        let matched = snap
            .histograms
            .iter()
            .find(|h| h.name == "cmd_match")
            .expect("cmd_match registered");
        assert_eq!(matched.count, 2);
    }
}

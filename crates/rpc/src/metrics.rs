//! [`RpcMetrics`] — pre-registered, lock-free handles for the RPC server's
//! flood-facing shed/error counters and its active-connections gauge.
//!
//! The RPC listener is the node's public, flood-facing surface: its
//! DoS-hardening paths (slowloris read timeouts, oversize frames, dispatch
//! timeouts, work-budget backpressure, accept-time admission rejections) are
//! exactly where brown-outs first become visible. Without counters on those
//! paths a degraded server sheds load silently.
//!
//! # Hot path vs. control path
//!
//! Registration ([`RpcMetrics::register`]) locks and allocates, but it runs
//! once at startup — never per request. Every recording method here is a
//! single relaxed atomic operation on a pre-registered [`Counter`] /
//! [`Gauge`] handle, mirroring the `observability` crate's design rules.
//!
//! # Optionality
//!
//! The server threads metrics as an `Option<Arc<RpcMetrics>>` defaulting to
//! `None`: existing call sites and tests that never build a
//! [`MetricsRegistry`] pay only an `Option` branch on the shed paths (the
//! happy path never touches metrics at all). [`RpcMetrics::disabled`] builds
//! detached handles (registered nowhere, exported nowhere) for callers that
//! want an always-present struct instead of an `Option`.

use std::sync::Arc;

use observability::{Counter, Gauge, MetricsRegistry};

/// Pre-registered metric handles for the RPC server.
///
/// Build once from a [`MetricsRegistry`] at startup with
/// [`register`](Self::register) and pass an `Arc` of it to
/// [`serve_with_metrics`](crate::server::serve_with_metrics); the registry
/// then exports the following under its snapshot / text exposition:
///
/// | metric | kind | incremented when |
/// |---|---|---|
/// | `rpc_read_timeouts_total` | counter | a client stalls past the idle/read timeout |
/// | `rpc_oversize_total` | counter | a frame declares a payload over the cap |
/// | `rpc_dispatch_timeouts_total` | counter | a backend dispatch outruns its wait budget |
/// | `rpc_backpressure_total` | counter | the in-flight work budget rejects a request |
/// | `rpc_accept_rejections_total` | counter | admission control rejects a connection at accept |
/// | `rpc_connections_active` | gauge | +1 on admitted connection, -1 when it ends |
#[derive(Debug, Default)]
pub struct RpcMetrics {
    read_timeouts: Arc<Counter>,
    oversize: Arc<Counter>,
    dispatch_timeouts: Arc<Counter>,
    backpressure: Arc<Counter>,
    accept_rejections: Arc<Counter>,
    connections_active: Arc<Gauge>,
}

impl RpcMetrics {
    /// Registers every RPC server metric on `registry` and returns the bound
    /// handles. Control path: call once at startup, then record freely.
    /// Idempotent — registering twice binds to the same underlying atomics.
    #[must_use]
    pub fn register(registry: &MetricsRegistry) -> Self {
        Self {
            read_timeouts: registry.counter("rpc_read_timeouts_total"),
            oversize: registry.counter("rpc_oversize_total"),
            dispatch_timeouts: registry.counter("rpc_dispatch_timeouts_total"),
            backpressure: registry.counter("rpc_backpressure_total"),
            accept_rejections: registry.counter("rpc_accept_rejections_total"),
            connections_active: registry.gauge("rpc_connections_active"),
        }
    }

    /// Detached handles bound to no registry: recording is a harmless atomic
    /// update that is never exported. For callers that want an
    /// always-present `RpcMetrics` instead of an `Option`.
    #[must_use]
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Records a client stalled past the idle/read timeout (slowloris
    /// eviction). Single relaxed atomic add.
    #[inline]
    pub fn record_read_timeout(&self) {
        self.read_timeouts.inc();
    }

    /// Records a frame whose declared payload exceeded the configured cap.
    /// Single relaxed atomic add.
    #[inline]
    pub fn record_oversize(&self) {
        self.oversize.inc();
    }

    /// Records a backend dispatch that outran the per-request wait budget
    /// (the connection is failed closed). Single relaxed atomic add.
    #[inline]
    pub fn record_dispatch_timeout(&self) {
        self.dispatch_timeouts.inc();
    }

    /// Records a request rejected by the in-flight work budget before
    /// dispatch. Single relaxed atomic add.
    #[inline]
    pub fn record_backpressure(&self) {
        self.backpressure.inc();
    }

    /// Records a connection rejected at accept time by the global or per-IP
    /// admission budget. Single relaxed atomic add.
    #[inline]
    pub fn record_accept_rejection(&self) {
        self.accept_rejections.inc();
    }

    /// Marks a connection admitted: increments `rpc_connections_active` and
    /// returns a guard that decrements it on drop. Tie the guard to the
    /// connection task so every exit path — clean close, timeout eviction,
    /// TLS handshake failure, even an abort at the drain deadline — restores
    /// the gauge.
    #[must_use]
    pub(crate) fn track_connection(&self) -> ActiveConnection {
        self.connections_active.inc();
        ActiveConnection(Arc::clone(&self.connections_active))
    }
}

/// RAII guard for one admitted connection's slot in the
/// `rpc_connections_active` gauge; decrements on drop.
#[derive(Debug)]
pub(crate) struct ActiveConnection(Arc<Gauge>);

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0.dec();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_binds_to_registry_and_is_idempotent() {
        let registry = MetricsRegistry::new();
        let a = RpcMetrics::register(&registry);
        let b = RpcMetrics::register(&registry);
        a.record_oversize();
        b.record_oversize();
        let snap = registry.snapshot();
        let oversize = snap
            .counters
            .iter()
            .find(|c| c.name == "rpc_oversize_total")
            .expect("registered");
        // Both instances share one underlying atomic.
        assert_eq!(oversize.value, 2);
        assert!(snap
            .gauges
            .iter()
            .any(|g| g.name == "rpc_connections_active"));
    }

    #[test]
    fn connection_guard_restores_gauge_on_drop() {
        let registry = MetricsRegistry::new();
        let metrics = RpcMetrics::register(&registry);
        let gauge = |reg: &MetricsRegistry| {
            reg.snapshot()
                .gauges
                .iter()
                .find(|g| g.name == "rpc_connections_active")
                .map(|g| g.value)
                .unwrap_or_default()
        };
        let first = metrics.track_connection();
        let second = metrics.track_connection();
        assert_eq!(gauge(&registry), 2);
        drop(first);
        assert_eq!(gauge(&registry), 1);
        drop(second);
        assert_eq!(gauge(&registry), 0);
    }

    #[test]
    fn disabled_metrics_record_without_a_registry() {
        // No registry anywhere: recording must be a harmless no-op-equivalent.
        let metrics = RpcMetrics::disabled();
        metrics.record_read_timeout();
        metrics.record_oversize();
        metrics.record_dispatch_timeout();
        metrics.record_backpressure();
        metrics.record_accept_rejection();
        let guard = metrics.track_connection();
        drop(guard);
    }
}

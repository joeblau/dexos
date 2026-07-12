//! `node` — the DexOS composition root.
//!
//! This crate wires configuration, role dispatch, and lifecycle together and owns
//! the async runtime. The deterministic execution core (`execution`, `orderbook`,
//! `risk`, `state-tree`, `types`) is deliberately runtime-free; async lives here at
//! the edge, per the async/threading model and the strict dependency direction.
//!
//! Subsystem seams are bounded channels only — never unbounded queues — so a slow
//! consumer applies backpressure instead of growing memory without limit.

pub mod config;
pub mod error;
pub mod metrics;
pub mod readiness;
pub mod shutdown;
pub mod supervisor;
pub mod threading;

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

pub use config::{
    ConfigError, ConfigOverrides, ConsensusSection, LogFormat, NetworkSection, NodeConfig,
    NodeSection, ObservabilitySection, PerformanceSection, Role, RpcSection, StorageSection,
};
pub use error::NodeError;
pub use observability::{MetricsRegistry, TraceGen, TraceId};
pub use readiness::Readiness;
pub use shutdown::{FlushHooks, DEFAULT_DRAIN_TIMEOUT};

/// Capacity of each subsystem ingress queue. Bounded by construction.
pub const INGRESS_CAPACITY: usize = 1024;

/// Deterministic-core and edge subsystems this node links, in dependency order.
/// Referencing each crate's identity here also proves the composition root links
/// the whole workspace.
pub const SUBSYSTEMS: &[&str] = &[
    types::CRATE_NAME,
    crypto::CRATE_NAME,
    codec::CRATE_NAME,
    state_tree::CRATE_NAME,
    orderbook::CRATE_NAME,
    risk::CRATE_NAME,
    execution::CRATE_NAME,
    oracle::CRATE_NAME,
    markets::CRATE_NAME,
    prediction_markets::CRATE_NAME,
    decision_markets::CRATE_NAME,
    custody::CRATE_NAME,
    chain_adapter::CRATE_NAME,
    chain_adapter_evm::CRATE_NAME,
    chain_adapter_svm::CRATE_NAME,
    storage::CRATE_NAME,
    consensus::CRATE_NAME,
    network::CRATE_NAME,
    discovery::CRATE_NAME,
    rpc::CRATE_NAME,
    light_client::CRATE_NAME,
    observability::CRATE_NAME,
    simd::CRATE_NAME,
    #[cfg(feature = "dev-tools")]
    loadgen::CRATE_NAME,
];

/// A unit of work handed to a role handler across a bounded seam.
///
/// A placeholder envelope for the Phase 0 skeleton — later phases replace the
/// payload with typed, decoded commands and market-data frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Monotonic sequence assigned at ingress.
    pub seq: u64,
}

/// Summary of a completed, graceful shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownReport {
    /// Total envelopes processed (including those drained after the stop signal).
    pub processed: u64,
    /// Number of role handlers that ran.
    pub handlers: usize,
}

/// A configured, not-yet-running node.
pub struct Node {
    config: NodeConfig,
    roles: Vec<Role>,
    ingress: Vec<(Role, mpsc::Sender<Envelope>)>,
    receivers: Vec<(Role, mpsc::Receiver<Envelope>)>,
    shutdown_tx: watch::Sender<bool>,
    flush_hooks: FlushHooks,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("config", &self.config)
            .field("roles", &self.roles)
            .field(
                "ingress_roles",
                &self.ingress.iter().map(|(r, _)| r).collect::<Vec<_>>(),
            )
            .field(
                "receiver_roles",
                &self.receivers.iter().map(|(r, _)| r).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl Node {
    /// Construct a node from validated configuration, allocating one bounded
    /// ingress seam per effective role.
    ///
    /// In light mode the effective role set excludes consensus-bearing roles; a
    /// light config that explicitly requests one is rejected by validation.
    /// Duplicate roles are rejected during validation so exactly one handler and
    /// ingress queue exists per role.
    pub fn new(config: NodeConfig) -> Result<Self, NodeError> {
        config.validate()?;
        let roles = config.effective_roles();
        let (shutdown_tx, _initial_rx) = watch::channel(false);
        let mut ingress = Vec::with_capacity(roles.len());
        let mut receivers = Vec::with_capacity(roles.len());
        for role in &roles {
            let (tx, rx) = mpsc::channel(INGRESS_CAPACITY);
            ingress.push((*role, tx));
            receivers.push((*role, rx));
        }
        let mut flush_hooks = FlushHooks::new();
        // Placeholder flush hooks for subsystems not yet fully wired. When the
        // durable journal / RPC server / peer mesh land they replace these with
        // real fsync / close / disconnect work. Empty success keeps the hook
        // path exercised on every shutdown.
        flush_hooks.push("journal", Box::new(|| Ok(())));
        flush_hooks.push("rpc", Box::new(|| Ok(())));
        flush_hooks.push("network", Box::new(|| Ok(())));

        Ok(Self {
            config,
            roles,
            ingress,
            receivers,
            shutdown_tx,
            flush_hooks,
        })
    }

    /// The configuration this node was built from.
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// The roles this node will actually run.
    pub fn roles(&self) -> &[Role] {
        &self.roles
    }

    /// A cloned ingress sender for the given role, if that role is active.
    ///
    /// At most one sender exists per role (duplicates rejected at validation).
    pub fn sender_for(&self, role: Role) -> Option<mpsc::Sender<Envelope>> {
        self.ingress
            .iter()
            .find(|(r, _)| *r == role)
            .map(|(_, tx)| tx.clone())
    }

    /// Register an additional shutdown flush hook (control path only).
    pub fn push_flush_hook(&mut self, name: &'static str, hook: shutdown::FlushHook) {
        self.flush_hooks.push(name, hook);
    }

    /// A node-info-style startup manifest, emitted once at startup (off any hot path).
    pub fn startup_summary(&self) -> String {
        let roles = if self.roles.is_empty() {
            "(none)".to_string()
        } else {
            self.roles
                .iter()
                .map(|r| r.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let simd_backend = simd::detect();
        format!(
            "dexos node '{}' region={} mode={} roles=[{}] rpc={} listen={} subsystems={} simd={} pin_threads={} drain_timeout_ms={}",
            self.config.node.name,
            self.config.node.region,
            if self.config.node.light {
                "light"
            } else {
                "full"
            },
            roles,
            self.config.rpc.listen,
            self.config.network.listen,
            SUBSYSTEMS.len(),
            simd_backend.name(),
            self.config.performance.pin_threads,
            if self.config.performance.drain_timeout_ms == 0 {
                DEFAULT_DRAIN_TIMEOUT.as_millis()
            } else {
                u128::from(self.config.performance.drain_timeout_ms)
            },
        )
    }

    /// Run until the supplied `shutdown` future resolves, then drain every bounded
    /// queue and stop all handlers gracefully under the configured deadline.
    pub async fn run_until<F>(mut self, shutdown: F) -> Result<ShutdownReport, NodeError>
    where
        F: Future<Output = ()>,
    {
        let identity = NodeIdentity {
            name: self.config.node.name.clone(),
            region: self.config.node.region.clone(),
            version: env!("CARGO_PKG_VERSION"),
        };
        init_tracing(self.config.observability.log_format, &identity);

        // Apply pin_threads before spawning hot-path work.
        threading::apply_startup_pinning(&self.config.performance)?;

        let simd_backend = simd::detect();
        tracing::info!(
            target: "node",
            simd_backend = simd_backend.name(),
            simd_available = simd_backend.is_available(),
            "selected SIMD backend"
        );

        let readiness = Readiness::new();

        // Process-wide metrics registry + optional Prometheus scrape listener.
        let metrics = Arc::new(MetricsRegistry::new());
        metrics.counter("node_starts_total").inc();
        let metrics_task = metrics::spawn_if_configured(
            &self.config.observability.metrics_listen,
            Arc::clone(&metrics),
            Arc::clone(&readiness),
        )
        .await?;

        // Root span carries node identity + a process-level TraceId so every
        // nested event on the hot path can correlate without custom scrapers.
        // Seeded from OS entropy (never a constant) so distinct processes mint
        // distinct trace-id streams; fixed seeds live only in tests/doc examples.
        let mut trace_gen = TraceGen::from_seed(process_trace_seed(&identity));
        let process_trace = trace_gen.new_trace();
        let root = tracing::info_span!(
            "node.run",
            node_name = %identity.name,
            node_region = %identity.region,
            node_version = identity.version,
            trace_id = %process_trace.to_hex(),
        );
        let _enter = root.enter();
        tracing::info!(target: "node", "{}", self.startup_summary());

        // Set once shutdown is intentional so handler completions are not
        // misclassified as unexpected exits.
        let shutting_down = Arc::new(AtomicBool::new(false));
        let (fail_tx, mut fail_rx) = mpsc::unbounded_channel::<NodeError>();

        let receivers = std::mem::take(&mut self.receivers);
        let mut handles: Vec<(String, JoinHandle<u64>)> = Vec::with_capacity(receivers.len());
        for (role, rx) in receivers {
            let stop = self.shutdown_tx.subscribe();
            let role_name = role.as_str().to_string();
            let shutting_down = Arc::clone(&shutting_down);
            let fail_tx = fail_tx.clone();
            let readiness_h = Arc::clone(&readiness);
            let name = role_name.clone();
            handles.push((
                role_name.clone(),
                tokio::spawn(async move {
                    // Nested spawn so panics become JoinError we can classify.
                    let join =
                        tokio::task::spawn(run_handler(rx, stop, name.clone(), process_trace))
                            .await;
                    match join {
                        Ok(processed) => {
                            if !shutting_down.load(Ordering::Acquire) {
                                readiness_h
                                    .mark_not_ready(format!("critical task '{name}' exited early"));
                                let _ = fail_tx.send(NodeError::CriticalTask {
                                    role: name,
                                    detail: "handler returned before shutdown".into(),
                                });
                            }
                            processed
                        }
                        Err(join_err) => {
                            let detail = join_err.to_string();
                            readiness_h.mark_not_ready(format!(
                                "critical task '{name}' panicked: {detail}"
                            ));
                            let _ = fail_tx.send(NodeError::CriticalTask { role: name, detail });
                            0
                        }
                    }
                }),
            ));
        }
        drop(fail_tx);

        // Bootstrap complete: metrics listener bound (if any), handlers spawned.
        readiness.mark_ready();
        metrics.gauge("node_ready").set(1);
        tracing::info!(target: "node", "readiness=true (bootstrap complete)");

        // Wait for external shutdown OR critical-task failure.
        let pending_error = tokio::select! {
            _ = shutdown => {
                tracing::info!(target: "node", "external shutdown requested");
                None
            }
            maybe = fail_rx.recv() => {
                match maybe {
                    Some(err) => {
                        tracing::error!(target: "node", error = %err, "critical subsystem failed");
                        Some(err)
                    }
                    None => None,
                }
            }
        };

        shutting_down.store(true, Ordering::Release);
        self.finish_shutdown(handles, metrics_task, readiness, metrics, pending_error)
            .await
    }

    async fn finish_shutdown(
        mut self,
        handles: Vec<(String, JoinHandle<u64>)>,
        metrics_task: Option<JoinHandle<()>>,
        readiness: Arc<Readiness>,
        metrics: Arc<MetricsRegistry>,
        pending_error: Option<NodeError>,
    ) -> Result<ShutdownReport, NodeError> {
        readiness.mark_not_ready("shutting down");
        metrics.gauge("node_ready").set(0);
        tracing::info!(
            target: "node",
            "shutdown requested; draining {} subsystem queue(s)",
            handles.len()
        );
        let _ = self.shutdown_tx.send(true);

        // Flush durable / network resources before joining handlers.
        if let Err(e) = self.flush_hooks.run_all() {
            if pending_error.is_none() {
                if let Some(task) = metrics_task {
                    task.abort();
                }
                readiness.mark_not_live();
                return Err(e);
            }
            tracing::error!(target: "node", error = %e, "flush failed during already-failed shutdown");
        }

        let deadline = shutdown::drain_timeout_from_ms(self.config.performance.drain_timeout_ms);
        let drain_result = shutdown::drain_handlers_abort_on_timeout(handles, deadline).await;

        if let Some(task) = metrics_task {
            task.abort();
        }
        readiness.mark_not_live();

        if let Some(err) = pending_error {
            return Err(err);
        }

        let (processed, handler_count) = drain_result?;
        tracing::info!(
            target: "node",
            "drained {} queued command(s) across {} subsystem(s)",
            processed,
            handler_count
        );
        Ok(ShutdownReport {
            processed,
            handlers: handler_count,
        })
    }

    /// Run until an OS interrupt (SIGINT/SIGTERM) is received.
    pub async fn run(self) -> Result<ShutdownReport, NodeError> {
        self.run_until(shutdown::wait_for_stop_signal()).await
    }

    /// Build a multi-threaded runtime here (owned at the edge) and run to completion.
    /// This is the synchronous entry point binaries call so the core stays runtime-free.
    pub fn run_blocking(config: NodeConfig) -> Result<ShutdownReport, NodeError> {
        let node = Node::new(config)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(NodeError::Runtime)?;
        runtime.block_on(node.run())
    }
}

/// Process identity fields attached to every structured log record.
#[derive(Debug, Clone)]
struct NodeIdentity {
    name: String,
    region: String,
    version: &'static str,
}

/// Derives the process-level trace seed from OS entropy.
///
/// A constant seed here would make every marketd process on every node,
/// region, and restart mint byte-identical trace ids (`TraceGen` is fully
/// deterministic given its seed), defeating cross-fleet correlation.
///
/// Fails OPEN: if OS entropy is unavailable we fall back to hashing node
/// identity, wall-clock time, and pid instead of aborting startup. Per the
/// `TraceGen` contract (`observability::trace` module docs), trace ids are
/// for correlation only — intentionally not cryptographic — so a weak,
/// non-cryptographic fallback seed is acceptable where blocking startup on
/// the entropy source is not. (Contrast with marketd key generation, which
/// must fail hard.)
fn process_trace_seed(identity: &NodeIdentity) -> u64 {
    let mut buf = [0u8; 8];
    match getrandom::getrandom(&mut buf) {
        Ok(()) => u64::from_le_bytes(buf),
        Err(err) => {
            tracing::warn!(
                target: "node",
                error = %err,
                "OS entropy unavailable; deriving trace seed from identity/time/pid"
            );
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            fallback_trace_seed(&identity.name, &identity.region, nanos, std::process::id())
        }
    }
}

/// Entropy-free fallback seed: hashes node identity plus wall-clock nanos and
/// pid so concurrent or restarted processes still diverge. Weak by design —
/// trace ids are correlation-only, not cryptographic (see the
/// `observability::trace` module docs).
fn fallback_trace_seed(name: &str, region: &str, epoch_nanos: u128, pid: u32) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    region.hash(&mut hasher);
    epoch_nanos.hash(&mut hasher);
    pid.hash(&mut hasher);
    hasher.finish()
}

/// One role handler: process ingress envelopes until the stop signal, then drain
/// whatever remains in the bounded queue. Returns the number processed.
async fn run_handler(
    mut rx: mpsc::Receiver<Envelope>,
    mut stop: watch::Receiver<bool>,
    role: String,
    process_trace: TraceId,
) -> u64 {
    let mut processed: u64 = 0;
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => {
                while rx.try_recv().is_ok() {
                    processed += 1;
                }
                break;
            }
            maybe = rx.recv() => {
                match maybe {
                    Some(envelope) => {
                        let span = tracing::info_span!(
                            "node.handler",
                            role = %role,
                            trace_id = %process_trace.to_hex(),
                            envelope.seq = envelope.seq,
                        );
                        let _g = span.enter();
                        tracing::trace!(target: "node", "envelope processed");
                        processed += 1;
                    }
                    None => break,
                }
            }
        }
    }
    processed
}

/// Initialize structured logging exactly once, outside any hot path.
fn init_tracing(format: LogFormat, identity: &NodeIdentity) {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use tracing_subscriber::EnvFilter;
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        match format {
            LogFormat::Json => {
                let _ = tracing_subscriber::fmt()
                    .json()
                    .with_env_filter(filter)
                    .with_current_span(true)
                    .with_span_list(true)
                    .try_init();
                tracing::info!(
                    target: "node",
                    node_name = %identity.name,
                    node_region = %identity.region,
                    node_version = identity.version,
                    log_format = "json",
                    "structured logging initialized"
                );
            }
            LogFormat::Text => {
                let _ = tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_target(false)
                    .try_init();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn cfg_with_roles(light: bool, roles: Vec<Role>) -> NodeConfig {
        let mut c = NodeConfig::default();
        c.node.name = "test".into();
        c.node.light = light;
        c.node.roles = roles;
        c.validate().unwrap();
        c
    }

    #[tokio::test]
    async fn lifecycle_drains_bounded_queue_on_shutdown() {
        let node = Node::new(cfg_with_roles(false, vec![Role::Gateway])).unwrap();
        let tx = node.sender_for(Role::Gateway).expect("gateway seam");
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();

        let handle = tokio::spawn(node.run_until(async move {
            let _ = stop_rx.await;
        }));

        const N: u64 = 500;
        for seq in 0..N {
            tx.send(Envelope { seq }).await.expect("enqueue");
        }
        stop_tx.send(()).unwrap();

        let report = handle.await.unwrap().expect("clean shutdown");
        assert_eq!(report.handlers, 1);
        assert_eq!(report.processed, N, "every queued command must be drained");
    }

    #[tokio::test]
    async fn immediate_shutdown_with_no_roles_is_clean() {
        let node = Node::new(cfg_with_roles(false, vec![])).unwrap();
        let report = node.run_until(async {}).await.unwrap();
        assert_eq!(report.handlers, 0);
        assert_eq!(report.processed, 0);
    }

    #[tokio::test]
    async fn light_mode_disables_consensus_roles() {
        let node = Node::new(cfg_with_roles(true, vec![Role::Gateway, Role::Observer])).unwrap();
        assert_eq!(node.roles(), &[Role::Gateway, Role::Observer]);

        let mut bad = NodeConfig::default();
        bad.node.light = true;
        bad.node.roles = vec![Role::Validator];
        assert!(matches!(Node::new(bad), Err(NodeError::Config(_))));
    }

    #[test]
    fn startup_summary_reports_mode_roles_and_simd() {
        let node = Node::new(cfg_with_roles(true, vec![Role::Gateway])).unwrap();
        let s = node.startup_summary();
        assert!(s.contains("mode=light"));
        assert!(s.contains("gateway"));
        assert!(s.contains(&format!("subsystems={}", SUBSYSTEMS.len())));
        assert!(s.contains("simd="), "{s}");
    }

    #[test]
    fn duplicate_roles_rejected_before_handlers_spawn() {
        let mut c = NodeConfig::default();
        c.node.roles = vec![Role::Gateway, Role::Gateway];
        let err = Node::new(c).unwrap_err();
        assert!(matches!(
            err,
            NodeError::Config(ConfigError::Validation(ref m)) if m.contains("duplicate")
        ));
    }

    #[tokio::test]
    async fn readiness_false_until_bootstrap_then_true() {
        let mut cfg = cfg_with_roles(false, vec![Role::Gateway]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        cfg.observability.metrics_listen = addr.to_string();

        let node = Node::new(cfg).unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(node.run_until(async move {
            let _ = stop_rx.await;
        }));

        let mut ready = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if let Ok(mut stream) = tokio::net::TcpStream::connect(addr).await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let _ = stream
                    .write_all(b"GET /readyz HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    .await;
                let mut buf = Vec::new();
                let _ = stream.read_to_end(&mut buf).await;
                let text = String::from_utf8_lossy(&buf);
                if text.contains("200 OK") && text.contains("ready") {
                    ready = true;
                    break;
                }
            }
        }
        assert!(ready, "readyz should become ready after bootstrap");

        {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(b"GET /livez HTTP/1.0\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            let text = String::from_utf8_lossy(&buf);
            assert!(text.contains("200 OK"), "{text}");
        }

        {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(b"GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n")
                .await
                .unwrap();
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            let text = String::from_utf8_lossy(&buf);
            assert!(text.contains("node_starts_total"), "{text}");
        }

        stop_tx.send(()).unwrap();
        handle.await.unwrap().unwrap();
    }

    #[test]
    fn exactly_one_ingress_per_role() {
        let node = Node::new(cfg_with_roles(
            false,
            vec![Role::Gateway, Role::Oracle, Role::Observer],
        ))
        .unwrap();
        assert_eq!(node.roles().len(), 3);
        assert!(node.sender_for(Role::Gateway).is_some());
        assert!(node.sender_for(Role::Oracle).is_some());
        assert!(node.sender_for(Role::Observer).is_some());
        assert!(node.sender_for(Role::Validator).is_none());
    }

    fn test_identity() -> NodeIdentity {
        NodeIdentity {
            name: "test".into(),
            region: "local".into(),
            version: "0.0.0",
        }
    }

    #[test]
    fn process_trace_seed_is_not_constant_across_invocations() {
        // Issue #419: a fixed seed made every process emit identical trace
        // ids. Two derivations for the same identity must differ, and the
        // resulting TraceGen streams must mint different trace ids.
        let identity = test_identity();
        let a = process_trace_seed(&identity);
        let b = process_trace_seed(&identity);
        assert_ne!(a, b, "process trace seed must not repeat across startups");

        let trace_a = TraceGen::from_seed(a).new_trace();
        let trace_b = TraceGen::from_seed(b).new_trace();
        assert_ne!(
            trace_a.to_hex(),
            trace_b.to_hex(),
            "distinct seeds must mint distinct process trace ids"
        );
    }

    #[test]
    fn fallback_trace_seed_is_deterministic_for_fixed_inputs() {
        let a = fallback_trace_seed("marketd-1", "us-east", 1_234_567_890, 42);
        let b = fallback_trace_seed("marketd-1", "us-east", 1_234_567_890, 42);
        assert_eq!(a, b, "fallback must be a pure function of its inputs");
    }

    #[test]
    fn fallback_trace_seed_incorporates_time_and_pid() {
        let base = fallback_trace_seed("marketd-1", "us-east", 1_234_567_890, 42);
        assert_ne!(
            base,
            fallback_trace_seed("marketd-1", "us-east", 1_234_567_891, 42),
            "clock nanos must perturb the fallback seed"
        );
        assert_ne!(
            base,
            fallback_trace_seed("marketd-1", "us-east", 1_234_567_890, 43),
            "pid must perturb the fallback seed"
        );
        assert_ne!(
            base,
            fallback_trace_seed("marketd-2", "eu-west", 1_234_567_890, 42),
            "node identity must perturb the fallback seed"
        );
    }
}

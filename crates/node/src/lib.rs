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
pub mod threading;

use std::future::Future;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

pub use config::{
    ConfigError, ConfigOverrides, ConsensusSection, NetworkSection, NodeConfig, NodeSection,
    PerformanceSection, Role, RpcSection, SimdMode, StorageSection,
};
pub use error::NodeError;

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
#[derive(Debug)]
pub struct Node {
    config: NodeConfig,
    roles: Vec<Role>,
    ingress: Vec<(Role, mpsc::Sender<Envelope>)>,
    receivers: Vec<(Role, mpsc::Receiver<Envelope>)>,
    shutdown_tx: watch::Sender<bool>,
}

impl Node {
    /// Construct a node from validated configuration, allocating one bounded
    /// ingress seam per effective role.
    ///
    /// In light mode the effective role set excludes consensus-bearing roles; a
    /// light config that explicitly requests one is rejected by validation.
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
        Ok(Self {
            config,
            roles,
            ingress,
            receivers,
            shutdown_tx,
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
    pub fn sender_for(&self, role: Role) -> Option<mpsc::Sender<Envelope>> {
        self.ingress
            .iter()
            .find(|(r, _)| *r == role)
            .map(|(_, tx)| tx.clone())
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
        format!(
            "dexos node '{}' region={} mode={} roles=[{}] rpc={} listen={} subsystems={}",
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
        )
    }

    /// Run until the supplied `shutdown` future resolves, then drain every bounded
    /// queue and stop all handlers gracefully.
    pub async fn run_until<F>(mut self, shutdown: F) -> Result<ShutdownReport, NodeError>
    where
        F: Future<Output = ()>,
    {
        init_tracing();
        tracing::info!(target: "node", "{}", self.startup_summary());

        let receivers = std::mem::take(&mut self.receivers);
        let mut handles: Vec<(String, JoinHandle<u64>)> = Vec::with_capacity(receivers.len());
        for (role, rx) in receivers {
            let stop = self.shutdown_tx.subscribe();
            handles.push((
                role.as_str().to_string(),
                tokio::spawn(run_handler(rx, stop)),
            ));
        }

        shutdown.await;
        tracing::info!(target: "node", "shutdown requested; draining {} subsystem queue(s)", handles.len());
        // Ignore the error when there are zero handlers (no receivers to notify).
        let _ = self.shutdown_tx.send(true);

        let handler_count = handles.len();
        let mut processed = 0u64;
        for (role, handle) in handles {
            let count = handle
                .await
                .map_err(|source| NodeError::Join { role, source })?;
            processed += count;
        }
        tracing::info!(target: "node", "drained {} queued command(s) across {} subsystem(s)", processed, handler_count);
        Ok(ShutdownReport {
            processed,
            handlers: handler_count,
        })
    }

    /// Run until an OS interrupt (SIGINT/SIGTERM via ctrl_c) is received.
    pub async fn run(self) -> Result<ShutdownReport, NodeError> {
        self.run_until(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
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

/// One role handler: process ingress envelopes until the stop signal, then drain
/// whatever remains in the bounded queue. Returns the number processed.
async fn run_handler(mut rx: mpsc::Receiver<Envelope>, mut stop: watch::Receiver<bool>) -> u64 {
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
                    Some(_envelope) => processed += 1,
                    None => break,
                }
            }
        }
    }
    processed
}

/// Initialize structured logging exactly once, outside any hot path.
fn init_tracing() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use tracing_subscriber::EnvFilter;
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .try_init();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Legal light roles run; a light config asking for validator is a construction error.
        let node = Node::new(cfg_with_roles(true, vec![Role::Gateway, Role::Observer])).unwrap();
        assert_eq!(node.roles(), &[Role::Gateway, Role::Observer]);

        let mut bad = NodeConfig::default();
        bad.node.light = true;
        bad.node.roles = vec![Role::Validator];
        assert!(matches!(Node::new(bad), Err(NodeError::Config(_))));
    }

    #[test]
    fn startup_summary_reports_mode_and_roles() {
        let node = Node::new(cfg_with_roles(true, vec![Role::Gateway])).unwrap();
        let s = node.startup_summary();
        assert!(s.contains("mode=light"));
        assert!(s.contains("gateway"));
        assert!(s.contains(&format!("subsystems={}", SUBSYSTEMS.len())));
    }
}

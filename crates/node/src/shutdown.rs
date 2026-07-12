//! Production shutdown: SIGTERM + SIGINT, drain deadline, and flush hooks.
//!
//! The composition root waits for a stop signal, broadcasts shutdown to every
//! subsystem, and runs registered flush hooks in two ordered phases around the
//! handler drain: PRE-drain hooks stop ingress (RPC listener close, peer
//! disconnect) before handlers empty their bounded queues, and POST-drain
//! hooks make state durable (journal fsync/close) only after every handler
//! has finished draining — so a command processed during the drain can never
//! land behind an already-completed journal flush (issue #436). A drain
//! deadline is enforced; an incomplete drain is reported as
//! [`crate::NodeError::DrainTimeout`].

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use crate::error::NodeError;

/// Default graceful drain window when config does not override it.
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// A flush hook invoked exactly once during shutdown, in one of two phases.
///
/// Hooks are control-path only and phase placement is the contract (see
/// [`FlushHooks`]): PRE-drain hooks stop ingress (RPC listener close, peer
/// intake stop) and run before handlers drain their bounded queues; POST-drain
/// hooks make state durable (journal fsync/close) and run only after every
/// handler has drained. They must be bounded and must not block the hot path
/// at registration time.
pub type FlushHook = Box<dyn FnOnce() -> Result<(), String> + Send>;

/// Registry of shutdown flush hooks, split into two `FnOnce`-drain phases.
///
/// Shutdown ordering contract (issue #436): signal shutdown → run PRE-drain
/// (ingress-stopping) hooks → drain every handler queue → run POST-drain
/// (durability) hooks. Each bucket is drained exactly once and cannot rerun.
/// A durability hook registered pre-drain would flush before drained commands
/// exist and lose them; an ingress-stopping hook registered post-drain would
/// keep accepting work while queues drain. Journal fsync/close MUST therefore
/// be registered via [`FlushHooks::push_post_drain`].
#[derive(Default)]
pub struct FlushHooks {
    pre_drain: Vec<(&'static str, FlushHook)>,
    post_drain: Vec<(&'static str, FlushHook)>,
}

impl FlushHooks {
    /// Empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pre_drain: Vec::new(),
            post_drain: Vec::new(),
        }
    }

    /// Register a named PRE-drain hook: ingress-stopping work only (e.g.
    /// `"rpc"` listener close, `"network"` peer intake stop). Runs before
    /// handlers drain their queues; MUST NOT perform durability work.
    pub fn push_pre_drain(&mut self, name: &'static str, hook: FlushHook) {
        self.pre_drain.push((name, hook));
    }

    /// Register a named POST-drain hook: durability work only (e.g.
    /// `"journal"` fsync/close). Runs after every handler has drained its
    /// bounded queue, so the flush covers commands processed during shutdown.
    pub fn push_post_drain(&mut self, name: &'static str, hook: FlushHook) {
        self.post_drain.push((name, hook));
    }

    /// Run every PRE-drain hook in registration order, draining the bucket.
    /// Collects failures without panicking.
    pub fn run_pre_drain(&mut self) -> Result<(), NodeError> {
        run_phase("pre-drain", &mut self.pre_drain)
    }

    /// Run every POST-drain hook in registration order, draining the bucket.
    /// Collects failures without panicking.
    pub fn run_post_drain(&mut self) -> Result<(), NodeError> {
        run_phase("post-drain", &mut self.post_drain)
    }
}

/// Run one phase's hooks in registration order, `FnOnce`-draining its bucket
/// and aggregating failures without panicking.
fn run_phase(
    phase: &'static str,
    hooks: &mut Vec<(&'static str, FlushHook)>,
) -> Result<(), NodeError> {
    let mut failures = Vec::new();
    for (name, hook) in hooks.drain(..) {
        if let Err(detail) = hook() {
            tracing::error!(target: "node", phase, hook = name, %detail, "flush hook failed");
            failures.push(format!("{name}: {detail}"));
        } else {
            tracing::info!(target: "node", phase, hook = name, "flush hook completed");
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(NodeError::Flush {
            detail: format!("{phase}: {}", failures.join("; ")),
        })
    }
}

/// Wait until SIGINT or SIGTERM (production stop signals).
///
/// On platforms without Unix signal support this falls back to Ctrl-C only.
pub async fn wait_for_stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!(
                    target: "node",
                    error = %err,
                    "failed to install SIGTERM handler; falling back to ctrl_c only"
                );
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(err) => {
                tracing::warn!(
                    target: "node",
                    error = %err,
                    "failed to install SIGINT handler; falling back to ctrl_c only"
                );
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!(target: "node", signal = "SIGTERM", "stop signal received");
            }
            _ = sigint.recv() => {
                tracing::info!(target: "node", signal = "SIGINT", "stop signal received");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!(target: "node", signal = "ctrl_c", "stop signal received");
    }
}

/// Resolve the drain timeout from an optional millisecond config value.
///
/// `0` means "use the default" (`DEFAULT_DRAIN_TIMEOUT`).
#[must_use]
pub fn drain_timeout_from_ms(ms: u64) -> Duration {
    if ms == 0 {
        DEFAULT_DRAIN_TIMEOUT
    } else {
        Duration::from_millis(ms)
    }
}

/// Production drain: join each handle under a shared deadline, aborting stragglers.
///
/// Returns `(processed_total, handler_count)` on success.
pub async fn drain_handlers_abort_on_timeout(
    handles: Vec<(String, tokio::task::JoinHandle<u64>)>,
    deadline: Duration,
) -> Result<(u64, usize), NodeError> {
    let total = handles.len();
    if total == 0 {
        return Ok((0, 0));
    }

    let deadline_ms = u64::try_from(deadline.as_millis()).unwrap_or(u64::MAX);
    let mut join_set: Vec<(String, tokio::task::JoinHandle<u64>)> = handles;
    let sleep = tokio::time::sleep(deadline);
    tokio::pin!(sleep);

    let mut processed = 0u64;
    let mut finished = 0usize;

    loop {
        if finished == total {
            return Ok((processed, total));
        }

        // Wait for any remaining handle, or the deadline.
        let select_future = std::future::poll_fn(|cx| {
            for (idx, (_role, handle)) in join_set.iter_mut().enumerate() {
                if let std::task::Poll::Ready(result) = Future::poll(std::pin::Pin::new(handle), cx)
                {
                    return std::task::Poll::Ready(Some((idx, result)));
                }
            }
            if join_set.is_empty() {
                return std::task::Poll::Ready(None);
            }
            std::task::Poll::Pending
        });
        tokio::pin!(select_future);

        tokio::select! {
            biased;
            _ = &mut sleep => {
                let outstanding = total - finished;
                for (_role, handle) in join_set.drain(..) {
                    handle.abort();
                }
                return Err(NodeError::DrainTimeout {
                    outstanding,
                    deadline_ms,
                });
            }
            maybe = &mut select_future => {
                match maybe {
                    Some((idx, result)) => {
                        let (role, _handle) = join_set.swap_remove(idx);
                        match result {
                            Ok(count) => {
                                processed += count;
                                finished += 1;
                            }
                            Err(source) => {
                                for (_r, h) in join_set.drain(..) {
                                    h.abort();
                                }
                                return Err(NodeError::Join { role, source });
                            }
                        }
                    }
                    None => {
                        return Ok((processed, total));
                    }
                }
            }
        }
    }
}

/// Shared stop flag for coordinating supervisor-triggered shutdown with signals.
#[derive(Debug)]
pub struct StopFlag {
    inner: tokio::sync::watch::Sender<bool>,
}

impl StopFlag {
    /// Create a new stop flag (initially not stopped).
    #[must_use]
    pub fn new() -> Arc<Self> {
        let (inner, _) = tokio::sync::watch::channel(false);
        Arc::new(Self { inner })
    }

    /// Request stop.
    pub fn request(&self) {
        let _ = self.inner.send(true);
    }

    /// Whether stop has already been requested.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        *self.inner.borrow()
    }

    /// Wait until stop is requested.
    pub async fn wait(&self) {
        let mut rx = self.inner.subscribe();
        if *rx.borrow() {
            return;
        }
        while rx.changed().await.is_ok() {
            if *rx.borrow() {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_timeout_zero_means_default() {
        assert_eq!(drain_timeout_from_ms(0), DEFAULT_DRAIN_TIMEOUT);
        assert_eq!(drain_timeout_from_ms(1500), Duration::from_millis(1500));
    }

    #[test]
    fn flush_hooks_collect_failures_per_phase() {
        let mut hooks = FlushHooks::new();
        hooks.push_pre_drain("ok", Box::new(|| Ok(())));
        hooks.push_pre_drain("bad", Box::new(|| Err("boom".into())));
        hooks.push_post_drain("journal", Box::new(|| Err("fsync failed".into())));

        let err = hooks.run_pre_drain().unwrap_err();
        assert!(
            matches!(err, NodeError::Flush { ref detail } if detail.contains("bad: boom")),
            "{err}"
        );

        // A pre-drain failure must not consume the post-drain bucket.
        let err = hooks.run_post_drain().unwrap_err();
        assert!(
            matches!(
                err,
                NodeError::Flush { ref detail } if detail.contains("journal: fsync failed")
            ),
            "{err}"
        );

        // FnOnce drain: each bucket runs exactly once; reruns are empty and Ok.
        assert!(hooks.run_pre_drain().is_ok());
        assert!(hooks.run_post_drain().is_ok());
    }

    #[tokio::test]
    async fn drain_completes_within_deadline() {
        let handles = vec![("gateway".to_string(), tokio::spawn(async { 7u64 }))];
        let (n, h) = drain_handlers_abort_on_timeout(handles, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(n, 7);
        assert_eq!(h, 1);
    }

    #[tokio::test]
    async fn drain_timeout_aborts_stragglers() {
        let handles = vec![(
            "stuck".to_string(),
            tokio::spawn(async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                1u64
            }),
        )];
        let err = drain_handlers_abort_on_timeout(handles, Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            NodeError::DrainTimeout { outstanding: 1, .. }
        ));
    }

    #[tokio::test]
    async fn stop_flag_wakes_waiters() {
        let flag = StopFlag::new();
        let f = Arc::clone(&flag);
        let h = tokio::spawn(async move {
            f.wait().await;
        });
        tokio::task::yield_now().await;
        flag.request();
        h.await.unwrap();
        assert!(flag.is_requested());
    }
}

//! Process readiness and liveness state for Kubernetes-style probes.
//!
//! - **Liveness** (`/livez`): process is up and the runtime is responsive.
//! - **Readiness** (`/readyz`): bootstrap finished and no critical subsystem has
//!   exited unexpectedly. Starts `false` and flips to `true` only after the
//!   composition root marks bootstrap complete.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Shared readiness/liveness state published to the scrape server and supervisor.
#[derive(Debug)]
pub struct Readiness {
    live: AtomicBool,
    ready: AtomicBool,
    /// Human-readable reason when not ready (last writer wins; control path only).
    reason: std::sync::Mutex<String>,
}

impl Readiness {
    /// Construct a new readiness handle. Live from birth; not ready until bootstrap.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            live: AtomicBool::new(true),
            ready: AtomicBool::new(false),
            reason: std::sync::Mutex::new("bootstrap incomplete".to_string()),
        })
    }

    /// Process liveness: true while the node considers itself alive.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }

    /// Readiness for traffic: true only after successful bootstrap and while
    /// every critical task is still running.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Last readiness failure reason (empty when ready).
    #[must_use]
    pub fn reason(&self) -> String {
        self.reason
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|_| "reason lock poisoned".to_string())
    }

    /// Mark bootstrap complete — readiness becomes true.
    pub fn mark_ready(&self) {
        if let Ok(mut g) = self.reason.lock() {
            g.clear();
        }
        self.ready.store(true, Ordering::Release);
    }

    /// Mark not ready with an operator-visible reason (critical task exit, etc.).
    pub fn mark_not_ready(&self, why: impl Into<String>) {
        let why = why.into();
        if let Ok(mut g) = self.reason.lock() {
            *g = why;
        }
        self.ready.store(false, Ordering::Release);
    }

    /// Clear liveness (process is shutting down or unrecoverable).
    pub fn mark_not_live(&self) {
        self.live.store(false, Ordering::Release);
        self.mark_not_ready("not live");
    }
}

impl Default for Readiness {
    fn default() -> Self {
        Self {
            live: AtomicBool::new(true),
            ready: AtomicBool::new(false),
            reason: std::sync::Mutex::new("bootstrap incomplete".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_live_but_not_ready() {
        let r = Readiness::new();
        assert!(r.is_live());
        assert!(!r.is_ready());
        assert!(r.reason().contains("bootstrap"));
    }

    #[test]
    fn mark_ready_clears_reason() {
        let r = Readiness::new();
        r.mark_ready();
        assert!(r.is_ready());
        assert!(r.reason().is_empty());
    }

    #[test]
    fn unexpected_exit_clears_ready() {
        let r = Readiness::new();
        r.mark_ready();
        r.mark_not_ready("handler validator exited");
        assert!(!r.is_ready());
        assert!(r.reason().contains("validator"));
    }
}

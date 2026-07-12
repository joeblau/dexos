//! Thread placement for the pinned hot-path threads (matching, risk, oracle
//! aggregation, consensus vote processing, journal writing).
//!
//! Real core pinning and NUMA placement use OS affinity APIs; to keep the node
//! free of platform crates in this release, this module provides the config-driven
//! policy, named-thread construction, and a busy-poll hint. A production backend
//! implements [`Affinity`] with `sched_setaffinity`/`thread_policy_set`.

use crate::config::PerformanceSection;

/// Placement policy resolved from the `[performance]` config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadPlacement {
    /// Whether hot-path threads should be pinned to dedicated cores.
    pub pin: bool,
    /// Whether ingress queues should be busy-polled (vs. parked).
    pub busy_poll: bool,
}

impl ThreadPlacement {
    /// Derive the placement policy from configuration.
    pub fn from_config(perf: &PerformanceSection) -> Self {
        Self {
            pin: perf.pin_threads,
            busy_poll: perf.busy_poll,
        }
    }
}

/// A core-affinity backend. The default [`NoopAffinity`] is a portable no-op; a
/// production build supplies an OS-specific implementation.
pub trait Affinity {
    /// Pin the current thread to `core`. Returns whether the pin was applied.
    fn pin_current(&self, core: usize) -> bool;
}

/// Portable no-op affinity backend (pinning is a hint here, applied by a
/// platform backend in production).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAffinity;

impl Affinity for NoopAffinity {
    fn pin_current(&self, _core: usize) -> bool {
        false
    }
}

/// Spawn a named hot-path thread, applying the placement policy via `affinity`.
/// Naming aids `perf`/flamegraph attribution off the hot path.
pub fn spawn_pinned<A, F>(
    name: &str,
    core: usize,
    placement: ThreadPlacement,
    affinity: A,
    body: F,
) -> std::io::Result<std::thread::JoinHandle<()>>
where
    A: Affinity + Send + 'static,
    F: FnOnce() + Send + 'static,
{
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            if placement.pin {
                let _ = affinity.pin_current(core);
            }
            body();
        })
}

/// A busy-poll hint for spinning a bounded number of times while draining a
/// low-latency queue before yielding. Never blocks.
#[inline]
pub fn spin_hint() {
    std::hint::spin_loop();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_from_config() {
        let perf = PerformanceSection {
            pin_threads: true,
            busy_poll: false,
        };
        let p = ThreadPlacement::from_config(&perf);
        assert!(p.pin && !p.busy_poll);
    }

    #[test]
    fn spawn_pinned_runs_body_and_names_thread() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let ran = Arc::new(AtomicBool::new(false));
        let r = ran.clone();
        let placement = ThreadPlacement {
            pin: true,
            busy_poll: true,
        };
        let h = spawn_pinned("dexos-test", 0, placement, NoopAffinity, move || {
            r.store(true, Ordering::SeqCst);
        })
        .unwrap();
        h.join().unwrap();
        assert!(ran.load(Ordering::SeqCst));
    }

    #[test]
    fn noop_affinity_reports_not_applied() {
        assert!(!NoopAffinity.pin_current(3));
        spin_hint();
    }
}

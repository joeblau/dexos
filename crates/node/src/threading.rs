//! Thread placement for the pinned hot-path threads (matching, risk, oracle
//! aggregation, consensus vote processing, journal writing).
//!
//! Real core pinning uses OS affinity APIs:
//! - Linux: `sched_setaffinity`
//! - macOS: `thread_policy_set(THREAD_AFFINITY_POLICY)` (best-effort hint)
//!
//! When `[performance].pin_threads = true` and the platform cannot pin, the
//! node fails closed at startup (or warns on macOS when the kernel rejects the
//! policy). A portable no-op backend remains available for tests.

use crate::config::PerformanceSection;
use crate::error::NodeError;

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

/// Whether this build/target supports real thread pinning.
#[must_use]
pub fn pinning_supported() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
}

/// A core-affinity backend.
pub trait Affinity: Send {
    /// Pin the current thread to `core`. Returns whether the pin was applied.
    fn pin_current(&self, core: usize) -> bool;
}

/// Portable no-op affinity backend (tests / unsupported targets).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAffinity;

impl Affinity for NoopAffinity {
    fn pin_current(&self, _core: usize) -> bool {
        false
    }
}

/// OS affinity backend (Linux `sched_setaffinity` / macOS thread policy).
#[derive(Debug, Default, Clone, Copy)]
pub struct OsAffinity;

impl Affinity for OsAffinity {
    fn pin_current(&self, core: usize) -> bool {
        pin_current_thread(core)
    }
}

/// Pin the calling thread to `core` using the host OS affinity API.
///
/// Returns `false` when the platform has no affinity API, the core index is
/// out of range, or the syscall fails (e.g. insufficient privilege).
#[must_use]
pub fn pin_current_thread(core: usize) -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::pin(core)
    }
    #[cfg(target_os = "macos")]
    {
        macos::pin(core)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = core;
        false
    }
}

/// Apply startup pinning policy.
///
/// When `pin_threads` is true:
/// - unsupported platforms → [`NodeError::PinningUnsupported`]
/// - Linux pin failure → error (fail closed)
/// - macOS pin failure → warning (affinity is a soft hint and often unavailable)
pub fn apply_startup_pinning(perf: &PerformanceSection) -> Result<(), NodeError> {
    if !perf.pin_threads {
        return Ok(());
    }
    if !pinning_supported() {
        return Err(NodeError::PinningUnsupported {
            detail: "performance.pin_threads=true but this platform has no affinity backend; \
                     set pin_threads=false or run on Linux/macOS"
                .into(),
        });
    }
    let ok = pin_current_thread(0);
    if ok {
        tracing::info!(
            target: "node",
            core = 0,
            "pinned startup thread (performance.pin_threads=true)"
        );
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        tracing::warn!(
            target: "node",
            "performance.pin_threads=true but macOS thread affinity policy was rejected; \
             continuing without a hard pin (macOS treats affinity as a soft hint)"
        );
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(NodeError::PinningUnsupported {
            detail: "performance.pin_threads=true but sched_setaffinity failed for core 0 \
                     (check privileges / CPU set size); set pin_threads=false to continue"
                .into(),
        })
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
    A: Affinity + 'static,
    F: FnOnce() + Send + 'static,
{
    let thread_name = name.to_string();
    let name_for_log = thread_name.clone();
    std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            if placement.pin {
                let applied = affinity.pin_current(core);
                if !applied {
                    tracing::warn!(
                        target: "node",
                        thread = %name_for_log,
                        core,
                        "requested pin_threads but affinity was not applied"
                    );
                }
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

#[cfg(target_os = "linux")]
mod linux {
    /// CPU_SET size used by glibc (1024 CPUs).
    const CPU_SETSIZE: usize = 1024;
    const BITS: usize = 64;
    const WORDS: usize = CPU_SETSIZE / BITS;

    #[repr(C)]
    struct CpuSet {
        bits: [u64; WORDS],
    }

    extern "C" {
        fn sched_setaffinity(pid: i32, cpusetsize: usize, mask: *const CpuSet) -> i32;
    }

    pub(super) fn pin(core: usize) -> bool {
        if core >= CPU_SETSIZE {
            return false;
        }
        let mut set = CpuSet {
            bits: [0u64; WORDS],
        };
        set.bits[core / BITS] |= 1u64 << (core % BITS);
        // SAFETY: mask points to a valid CpuSet of the size we pass; pid 0 = self.
        #[allow(unsafe_code)] // SAFETY: documented affinity call; isolated perf module
        let rc = unsafe { sched_setaffinity(0, std::mem::size_of::<CpuSet>(), &set) };
        rc == 0
    }
}

#[cfg(target_os = "macos")]
mod macos {
    type MachPort = u32;
    type ThreadPolicyFlavor = u32;
    type MachMsgTypeNumber = u32;
    type KernReturn = i32;

    const THREAD_AFFINITY_POLICY: ThreadPolicyFlavor = 4;
    const THREAD_AFFINITY_POLICY_COUNT: MachMsgTypeNumber = 1;

    extern "C" {
        fn mach_thread_self() -> MachPort;
        fn thread_policy_set(
            thread: MachPort,
            flavor: ThreadPolicyFlavor,
            policy_info: *const i32,
            count: MachMsgTypeNumber,
        ) -> KernReturn;
    }

    pub(super) fn pin(core: usize) -> bool {
        // Affinity tags are opaque; use core+1 so 0 (null policy) is never sent.
        let tag = i32::try_from(core.saturating_add(1)).unwrap_or(1);
        #[allow(unsafe_code)]
        // SAFETY: mach_thread_self returns the calling thread; policy_info points
        // to a single i32 for THREAD_AFFINITY_POLICY with count 1 (isolated perf module).
        let rc = unsafe {
            let thread = mach_thread_self();
            thread_policy_set(
                thread,
                THREAD_AFFINITY_POLICY,
                &tag as *const i32,
                THREAD_AFFINITY_POLICY_COUNT,
            )
        };
        rc == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placement_from_config() {
        let perf = PerformanceSection {
            pin_threads: true,
            busy_poll: false,
            drain_timeout_ms: 0,
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

    #[test]
    fn os_affinity_does_not_panic() {
        // May succeed or fail depending on privileges; must not panic.
        let _ = OsAffinity.pin_current(0);
        let _ = pin_current_thread(0);
    }

    #[test]
    fn apply_startup_pinning_noop_when_disabled() {
        let perf = PerformanceSection::default();
        apply_startup_pinning(&perf).unwrap();
    }
}

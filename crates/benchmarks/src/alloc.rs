//! A dependency-free counting global allocator.
//!
//! This is the crate's single, deliberately isolated `unsafe` module. It wraps
//! the platform [`System`] allocator and, on every successful allocation,
//! increments **thread-local** counters so a benchmark can attribute
//! `allocations/op` and `bytes/op` to the closure it brackets. Deallocation is
//! forwarded verbatim and never counted (we only measure allocation pressure).
//!
//! Counters are per-thread (not process-global) so that measurements taken on
//! the benchmarking thread are immune to allocations made by other threads —
//! including the parallel test runner. The thread-local cells are `const`-
//! initialized, so accessing them never allocates (no recursion into the
//! allocator) and they have no destructor (so `with` cannot panic during thread
//! teardown).
//!
//! The `#[global_allocator]` registration is gated behind the `count-alloc`
//! cargo feature (enabled by default). When the feature is off the counters are
//! never touched, [`counting_enabled`] returns `false`, and every measurement
//! reports zero — i.e. "unmeasured" rather than a fabricated number.
//!
//! # Safety
//!
//! The only `unsafe` here is the [`GlobalAlloc`] implementation, which forwards
//! the caller's `Layout`/pointer to [`System`] unchanged. The counter updates
//! are plain thread-local cell arithmetic with no bearing on memory safety.
//! Correctness of the forwarding is exercised by the module's own tests
//! (`counts_a_boxed_alloc`) and by the harness-level zero-allocation test.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static TL_COUNT: Cell<u64> = const { Cell::new(0) };
    static TL_BYTES: Cell<u64> = const { Cell::new(0) };
}

#[inline]
fn record_alloc(size: usize) {
    let bytes = u64::try_from(size).unwrap_or(u64::MAX);
    TL_COUNT.with(|c| c.set(c.get().wrapping_add(1)));
    TL_BYTES.with(|b| b.set(b.get().wrapping_add(bytes)));
}

/// A [`GlobalAlloc`] that forwards to [`System`] while tallying allocations.
pub struct CountingAllocator;

// SAFETY: every method forwards its arguments unchanged to the `System`
// allocator, which is itself a correct `GlobalAlloc`. The whole body of each
// `unsafe fn` is an unsafe context (edition 2021), and the `System` calls are
// the only unsafe operations; the extra work is limited to relaxed atomic
// counter arithmetic, which cannot affect the validity of the returned pointers
// or the soundness of deallocation.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            record_alloc(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            record_alloc(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }
}

#[cfg(feature = "count-alloc")]
#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// Whether the counting allocator is actually installed (the `count-alloc`
/// feature is enabled). When `false`, all counter reads are meaningless zeros.
#[must_use]
pub const fn counting_enabled() -> bool {
    cfg!(feature = "count-alloc")
}

/// A point-in-time reading of the global allocation counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocSnapshot {
    /// Total successful allocations observed so far.
    pub count: u64,
    /// Total bytes requested across those allocations.
    pub bytes: u64,
}

impl AllocSnapshot {
    /// Capture the calling thread's allocation counters.
    #[must_use]
    pub fn capture() -> Self {
        AllocSnapshot {
            count: TL_COUNT.with(|c| c.get()),
            bytes: TL_BYTES.with(|b| b.get()),
        }
    }

    /// The non-negative delta `self - earlier`, saturating at zero.
    #[must_use]
    pub fn since(self, earlier: AllocSnapshot) -> AllocSnapshot {
        AllocSnapshot {
            count: self.count.saturating_sub(earlier.count),
            bytes: self.bytes.saturating_sub(earlier.bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_delta_is_saturating() {
        let a = AllocSnapshot {
            count: 10,
            bytes: 100,
        };
        let b = AllocSnapshot {
            count: 4,
            bytes: 40,
        };
        assert_eq!(
            a.since(b),
            AllocSnapshot {
                count: 6,
                bytes: 60
            }
        );
        // Reversed order saturates rather than underflowing.
        assert_eq!(b.since(a), AllocSnapshot { count: 0, bytes: 0 });
    }

    #[cfg(feature = "count-alloc")]
    #[test]
    fn counts_a_boxed_alloc() {
        let before = AllocSnapshot::capture();
        // A heap allocation the compiler cannot elide.
        let boxed = std::hint::black_box(vec![0u8; 4096]);
        let after = AllocSnapshot::capture();
        assert!(after.since(before).count >= 1);
        assert!(after.since(before).bytes >= 4096);
        drop(boxed);
    }

    #[cfg(feature = "count-alloc")]
    #[test]
    fn no_alloc_region_counts_zero() {
        // Pre-touch so any lazy statics are already allocated.
        let _ = AllocSnapshot::capture();
        let before = AllocSnapshot::capture();
        let mut acc = 0u64;
        for i in 0..1000u64 {
            acc = acc.wrapping_add(i);
        }
        std::hint::black_box(acc);
        let after = AllocSnapshot::capture();
        assert_eq!(after.since(before).count, 0);
    }
}

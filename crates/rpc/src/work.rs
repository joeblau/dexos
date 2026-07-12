//! Process-wide and per-session in-flight work budgets for the RPC server.
//!
//! Synchronous backend dispatch is moved off the Tokio accept/IO workers via
//! `spawn_blocking`. While a request is in flight it holds:
//!
//! * a process-wide concurrent-request permit;
//! * a process-wide byte reservation for the request frame; and
//! * optional per-connection concurrent-request / byte ceilings.
//!
//! Exhausted budgets surface as [`crate::error::RpcError::Backpressure`] before
//! the command is committed to the backend, so healthy clients keep progressing
//! under a flood of large or slow requests.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Shared ceilings for in-flight RPC work.
#[derive(Debug, Clone)]
pub struct WorkBudgetConfig {
    /// Process-wide maximum concurrent dispatches (blocking-pool tasks).
    pub max_in_flight_requests: usize,
    /// Process-wide maximum bytes retained by in-flight request frames.
    pub max_in_flight_bytes: usize,
    /// Per-connection concurrent-dispatch ceiling.
    pub max_in_flight_requests_per_conn: usize,
    /// Per-connection in-flight request-frame byte ceiling.
    pub max_in_flight_bytes_per_conn: usize,
}

impl Default for WorkBudgetConfig {
    fn default() -> Self {
        Self {
            max_in_flight_requests: 1_024,
            max_in_flight_bytes: 64 * 1024 * 1024,
            max_in_flight_requests_per_conn: 1,
            max_in_flight_bytes_per_conn: 1024 * 1024,
        }
    }
}

/// Process-wide in-flight work tracker. Cheap to clone via [`Arc`].
#[derive(Debug)]
pub struct WorkBudget {
    max_requests: usize,
    max_bytes: usize,
    requests: AtomicUsize,
    bytes: AtomicUsize,
    high_water_requests: AtomicUsize,
    high_water_bytes: AtomicUsize,
}

impl WorkBudget {
    /// Build a budget from `config` (process-wide ceilings only; per-connection
    /// ceilings live on [`ConnBudget`]).
    pub fn new(config: &WorkBudgetConfig) -> Arc<Self> {
        Arc::new(Self {
            max_requests: config.max_in_flight_requests.max(1),
            max_bytes: config.max_in_flight_bytes.max(1),
            requests: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            high_water_requests: AtomicUsize::new(0),
            high_water_bytes: AtomicUsize::new(0),
        })
    }

    /// Current number of in-flight requests.
    pub fn in_flight_requests(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }

    /// Current bytes reserved by in-flight request frames.
    pub fn in_flight_bytes(&self) -> usize {
        self.bytes.load(Ordering::Relaxed)
    }

    /// High-water mark of concurrent in-flight requests.
    pub fn high_water_requests(&self) -> usize {
        self.high_water_requests.load(Ordering::Relaxed)
    }

    /// High-water mark of reserved in-flight bytes.
    pub fn high_water_bytes(&self) -> usize {
        self.high_water_bytes.load(Ordering::Relaxed)
    }

    /// Try to reserve one request of `bytes`. On failure neither counter is
    /// changed (atomic check-and-set loop).
    pub fn try_acquire(self: &Arc<Self>, bytes: usize) -> Option<WorkPermit> {
        // Requests first: a pure count check is cheaper and fails closed.
        loop {
            let cur = self.requests.load(Ordering::Relaxed);
            if cur >= self.max_requests {
                return None;
            }
            if self
                .requests
                .compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                bump_high_water(&self.high_water_requests, cur + 1);
                break;
            }
        }
        // Then bytes. Roll back the request slot on failure.
        loop {
            let cur = self.bytes.load(Ordering::Relaxed);
            if cur.saturating_add(bytes) > self.max_bytes {
                self.requests.fetch_sub(1, Ordering::AcqRel);
                return None;
            }
            if self
                .bytes
                .compare_exchange_weak(cur, cur + bytes, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                bump_high_water(&self.high_water_bytes, cur + bytes);
                return Some(WorkPermit {
                    budget: Arc::clone(self),
                    bytes,
                });
            }
        }
    }
}

/// RAII reservation against a [`WorkBudget`]. Releases on drop.
#[derive(Debug)]
pub struct WorkPermit {
    budget: Arc<WorkBudget>,
    bytes: usize,
}

impl Drop for WorkPermit {
    fn drop(&mut self) {
        self.budget.bytes.fetch_sub(self.bytes, Ordering::AcqRel);
        self.budget.requests.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Per-connection in-flight ceiling. Sequential RPC sessions typically hold at
/// most one request, but the counters still bound pipelined or buggy clients
/// if the accept path ever admits more than one in flight.
#[derive(Debug)]
pub struct ConnBudget {
    max_requests: usize,
    max_bytes: usize,
    requests: AtomicUsize,
    bytes: AtomicUsize,
}

impl ConnBudget {
    /// Build a per-connection budget from `config`.
    pub fn new(config: &WorkBudgetConfig) -> Self {
        Self {
            max_requests: config.max_in_flight_requests_per_conn.max(1),
            max_bytes: config.max_in_flight_bytes_per_conn.max(1),
            requests: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
        }
    }

    /// Try to reserve one request of `bytes` on this connection.
    pub fn try_acquire(&self, bytes: usize) -> Option<ConnPermit<'_>> {
        loop {
            let cur = self.requests.load(Ordering::Relaxed);
            if cur >= self.max_requests {
                return None;
            }
            if self
                .requests
                .compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
        }
        loop {
            let cur = self.bytes.load(Ordering::Relaxed);
            if cur.saturating_add(bytes) > self.max_bytes {
                self.requests.fetch_sub(1, Ordering::AcqRel);
                return None;
            }
            if self
                .bytes
                .compare_exchange_weak(cur, cur + bytes, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Some(ConnPermit {
                    budget: self,
                    bytes,
                });
            }
        }
    }
}

/// RAII reservation against a [`ConnBudget`].
#[derive(Debug)]
pub struct ConnPermit<'a> {
    budget: &'a ConnBudget,
    bytes: usize,
}

impl Drop for ConnPermit<'_> {
    fn drop(&mut self) {
        self.budget.bytes.fetch_sub(self.bytes, Ordering::AcqRel);
        self.budget.requests.fetch_sub(1, Ordering::AcqRel);
    }
}

fn bump_high_water(slot: &AtomicUsize, observed: usize) {
    let mut cur = slot.load(Ordering::Relaxed);
    while observed > cur {
        match slot.compare_exchange_weak(cur, observed, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => cur = actual,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_budget_caps_requests_and_bytes() {
        let cfg = WorkBudgetConfig {
            max_in_flight_requests: 2,
            max_in_flight_bytes: 100,
            max_in_flight_requests_per_conn: 8,
            max_in_flight_bytes_per_conn: 1_000,
        };
        let b = WorkBudget::new(&cfg);
        let p1 = b.try_acquire(40).expect("first");
        let p2 = b.try_acquire(40).expect("second");
        assert!(b.try_acquire(1).is_none(), "request ceiling");
        drop(p1);
        // 40 + 70 = 110 > 100 → byte ceiling.
        assert!(b.try_acquire(70).is_none(), "byte ceiling");
        let p3 = b.try_acquire(50).expect("after release fits");
        drop(p2);
        drop(p3);
        assert_eq!(b.in_flight_requests(), 0);
        assert_eq!(b.in_flight_bytes(), 0);
        assert_eq!(b.high_water_requests(), 2);
    }

    #[test]
    fn conn_budget_is_independent() {
        let cfg = WorkBudgetConfig {
            max_in_flight_requests: 100,
            max_in_flight_bytes: 1_000_000,
            max_in_flight_requests_per_conn: 1,
            max_in_flight_bytes_per_conn: 64,
        };
        let c = ConnBudget::new(&cfg);
        let p = c.try_acquire(32).expect("one");
        assert!(c.try_acquire(1).is_none());
        drop(p);
        assert!(c.try_acquire(64).is_some());
    }
}

//! Bounded, non-blocking ingress for checkpoint / market-data streams.
//!
//! Under a burst, a light node must *shed load* rather than block its network
//! task or grow memory. [`BoundedIngress`] wraps a bounded `tokio` channel:
//! [`BoundedIngress::offer`] never awaits — it enqueues if there is room and
//! otherwise drops the item and increments a counter. This gives counted
//! backpressure with a hard memory bound, satisfying the "drop, don't block"
//! requirement for subscriber fanout and checkpoint bursts.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;

/// The producer half of a bounded, drop-on-full ingress.
#[derive(Debug, Clone)]
pub struct BoundedIngress<T> {
    tx: mpsc::Sender<T>,
    capacity: usize,
    dropped: Arc<AtomicU64>,
}

/// The consumer half: a plain bounded receiver.
pub type Ingress<T> = mpsc::Receiver<T>;

impl<T> BoundedIngress<T> {
    /// Create a bounded ingress of `capacity` items and its receiver.
    #[must_use]
    pub fn new(capacity: usize) -> (Self, Ingress<T>) {
        let cap = capacity.max(1);
        let (tx, rx) = mpsc::channel(cap);
        (
            Self {
                tx,
                capacity: cap,
                dropped: Arc::new(AtomicU64::new(0)),
            },
            rx,
        )
    }

    /// Offer an item without blocking. Returns `true` if enqueued, or `false`
    /// (incrementing the drop counter) if the queue was full or closed.
    pub fn offer(&self, item: T) -> bool {
        match self.tx.try_send(item) {
            Ok(()) => true,
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Number of items dropped due to a full (or closed) queue.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// The configured queue capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

//! Async wrapper around the strict-priority scheduler.
//!
//! [`AsyncPriorityChannel`] adds `await`-able receive and a close signal on top
//! of [`PriorityScheduler`]. It is the reliable "wire" between two connection
//! endpoints: for the loopback transport a single channel is shared by both
//! sides (sender enqueues, receiver awaits); for the TCP transport a local
//! channel is drained by a writer task on the send side and filled by a reader
//! task on the receive side.
//!
//! Sends are non-blocking and return [`TransportError::Backpressure`] when a
//! class queue is full, so a slow consumer can never make a producer allocate
//! without bound.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use codec::Frame;
use tokio::sync::Notify;

use crate::error::TransportError;
use crate::scheduler::PriorityScheduler;

/// A shared, bounded, strict-priority async frame channel.
#[derive(Debug)]
pub(crate) struct AsyncPriorityChannel {
    inner: Mutex<PriorityScheduler>,
    notify: Notify,
    closed: AtomicBool,
}

impl AsyncPriorityChannel {
    /// Create a channel bounding each class to `capacity_per_class` frames.
    pub(crate) fn new(capacity_per_class: usize) -> Self {
        Self {
            inner: Mutex::new(PriorityScheduler::new(capacity_per_class)),
            notify: Notify::new(),
            closed: AtomicBool::new(false),
        }
    }

    /// Enqueue a frame; non-blocking. Errors with
    /// [`TransportError::Backpressure`] if the frame's class is at capacity, or
    /// [`TransportError::ConnectionClosed`] if the channel is closed.
    pub(crate) fn try_send(&self, frame: Frame) -> Result<(), TransportError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(TransportError::ConnectionClosed);
        }
        {
            let mut sched = self.inner.lock().expect("scheduler mutex poisoned");
            sched.enqueue(frame)?;
        }
        self.notify.notify_one();
        Ok(())
    }

    /// Await and remove the highest-priority frame. Returns `None` once the
    /// channel is closed and fully drained.
    pub(crate) async fn recv(&self) -> Option<Frame> {
        loop {
            // Register interest *before* checking so a concurrent `try_send`
            // that fires between the check and the await cannot be lost.
            let notified = self.notify.notified();
            {
                let mut sched = self.inner.lock().expect("scheduler mutex poisoned");
                if let Some(frame) = sched.dequeue() {
                    return Some(frame);
                }
                if self.closed.load(Ordering::Acquire) {
                    return None;
                }
            }
            notified.await;
        }
    }

    /// Signal closure and wake any waiters. Buffered frames remain drainable.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    /// Frames currently buffered across all classes (for backpressure tests).
    pub(crate) fn pending(&self) -> usize {
        self.inner.lock().expect("scheduler mutex poisoned").len()
    }
}

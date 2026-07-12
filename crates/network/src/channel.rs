//! Async wrapper around the strict-priority scheduler.
//!
//! [`AsyncPriorityChannel`] adds `await`-able receive and a close signal on top
//! of [`PriorityScheduler`]. It is the reliable "wire" between two connection
//! endpoints: for the loopback transport a single channel is shared by both
//! sides (sender enqueues, receiver awaits); for the TCP transport a local
//! channel is drained by a writer task on the send side and filled by a reader
//! task on the receive side.
//!
//! [`AsyncPriorityChannel::try_send`] is non-blocking and returns
//! [`TransportError::Backpressure`] when a class queue is full, so a caller that
//! can shed (the loopback producer, the datagram path) never makes a producer
//! allocate without bound. For the reliable inbound path — where a shed frame
//! would vanish silently after the sender already observed success on the wire —
//! [`AsyncPriorityChannel::send`] instead *awaits* queue space, so the reader
//! stalls (and, over TCP, closes the peer's window) rather than dropping a
//! reliable frame.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use codec::Frame;
use tokio::sync::Notify;

use crate::budget::ByteBudget;
use crate::error::TransportError;
use crate::scheduler::{frame_cost, PriorityScheduler};

/// A shared, bounded, strict-priority async frame channel.
#[derive(Debug)]
pub(crate) struct AsyncPriorityChannel {
    inner: Mutex<PriorityScheduler>,
    /// Wakes a blocked receiver when a frame is enqueued or the channel closes.
    notify: Notify,
    /// Wakes a blocked [`send`](Self::send) when a frame is dequeued (freeing a
    /// class slot) or the channel closes.
    space: Notify,
    closed: AtomicBool,
    /// Optional shared byte budget charged on [`try_send`](Self::try_send) and
    /// credited on [`recv`](Self::recv). Only ever attached to a channel filled
    /// via `try_send` (the outbound / loopback reliable paths); never to the
    /// `send`-awaiting inbound reliable path, so an exhausted budget sheds back
    /// to the *sender's* own flow control and never drops an inbound reliable
    /// frame the far side already observed as delivered.
    budget: Option<Arc<ByteBudget>>,
}

impl AsyncPriorityChannel {
    /// Create a channel bounding each class to `capacity_per_class` frames, with
    /// no per-class byte ceiling and no shared byte budget. Test-only shorthand
    /// for [`with_limits`](Self::with_limits) with no byte bound.
    #[cfg(test)]
    pub(crate) fn new(capacity_per_class: usize) -> Self {
        Self {
            inner: Mutex::new(PriorityScheduler::new(capacity_per_class)),
            notify: Notify::new(),
            space: Notify::new(),
            closed: AtomicBool::new(false),
            budget: None,
        }
    }

    /// Create a channel bounding each class to `capacity_per_class` frames and
    /// `capacity_bytes_per_class` retained bytes, optionally charging a shared
    /// [`ByteBudget`] on every enqueue.
    pub(crate) fn with_limits(
        capacity_per_class: usize,
        capacity_bytes_per_class: usize,
        budget: Option<Arc<ByteBudget>>,
    ) -> Self {
        Self {
            inner: Mutex::new(PriorityScheduler::with_byte_cap(
                capacity_per_class,
                capacity_bytes_per_class,
            )),
            notify: Notify::new(),
            space: Notify::new(),
            closed: AtomicBool::new(false),
            budget,
        }
    }

    /// Enqueue a frame; non-blocking. Errors with
    /// [`TransportError::Backpressure`] if the frame's class is at its frame or
    /// byte ceiling (or the shared byte budget is exhausted), or
    /// [`TransportError::ConnectionClosed`] if the channel is closed.
    pub(crate) fn try_send(&self, frame: Frame) -> Result<(), TransportError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(TransportError::ConnectionClosed);
        }
        let class = frame.class;
        let cost = frame_cost(&frame);
        // Reserve the shared budget *before* touching the queue; an exhausted
        // node-wide or per-peer budget sheds here rather than growing memory.
        if let Some(budget) = &self.budget {
            if !budget.try_reserve(cost) {
                return Err(TransportError::Backpressure { class });
            }
        }
        {
            let mut sched = self.inner.lock().expect("scheduler mutex poisoned");
            if let Err(err) = sched.enqueue(frame) {
                drop(sched);
                // The per-class queue rejected it: return the budget we reserved.
                if let Some(budget) = &self.budget {
                    budget.release(cost);
                }
                return Err(err);
            }
        }
        self.notify.notify_one();
        Ok(())
    }

    /// Enqueue a frame, **awaiting queue space** if the frame's class is full
    /// rather than shedding it. Errors with [`TransportError::ConnectionClosed`]
    /// if the channel is closed.
    ///
    /// This is the reliable inbound path: a full class parks the caller until a
    /// [`recv`](Self::recv) frees a slot, so the reader stops draining its
    /// socket and the peer's TCP window closes — the sender is throttled instead
    /// of a reliable frame being lost after the sender already saw it written.
    pub(crate) async fn send(&self, frame: Frame) -> Result<(), TransportError> {
        loop {
            // Register interest *before* checking so a `recv` (or `close`) that
            // frees space between the check and the await cannot be lost.
            let notified = self.space.notified();
            {
                if self.closed.load(Ordering::Acquire) {
                    return Err(TransportError::ConnectionClosed);
                }
                let mut sched = self.inner.lock().expect("scheduler mutex poisoned");
                if sched.has_capacity_for(&frame) {
                    // Capacity (frame count *and* bytes) is available, so this
                    // enqueue cannot backpressure. The never-shed inbound path is
                    // deliberately not gated on the shared byte budget: it parks
                    // on per-class byte space (bounding the peer) instead of
                    // shedding a frame the far side already saw as delivered.
                    sched.enqueue(frame)?;
                    drop(sched);
                    self.notify.notify_one();
                    return Ok(());
                }
            }
            notified.await;
        }
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
                    drop(sched);
                    // The frame's bytes are no longer retained: credit the shared
                    // budget so another peer / class can reserve the capacity.
                    if let Some(budget) = &self.budget {
                        budget.release(frame_cost(&frame));
                    }
                    // A class slot just freed up: wake a sender blocked in `send`.
                    self.space.notify_one();
                    return Some(frame);
                }
                if self.closed.load(Ordering::Acquire) {
                    return None;
                }
            }
            notified.await;
        }
    }

    /// Signal closure and wake any waiters (both receivers and blocked senders).
    /// Buffered frames remain drainable.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify.notify_waiters();
        self.space.notify_waiters();
    }

    /// Frames currently buffered across all classes (for backpressure tests).
    pub(crate) fn pending(&self) -> usize {
        self.inner.lock().expect("scheduler mutex poisoned").len()
    }

    /// Payload bytes currently buffered across all classes.
    pub(crate) fn queued_bytes(&self) -> usize {
        self.inner
            .lock()
            .expect("scheduler mutex poisoned")
            .queued_bytes()
    }

    /// High-water mark of [`queued_bytes`](Self::queued_bytes).
    pub(crate) fn queued_bytes_high_water(&self) -> usize {
        self.inner
            .lock()
            .expect("scheduler mutex poisoned")
            .queued_bytes_high_water()
    }

    /// Payload bytes currently buffered in a single class.
    pub(crate) fn class_bytes(&self, class: codec::TrafficClass) -> usize {
        self.inner
            .lock()
            .expect("scheduler mutex poisoned")
            .class_bytes(class)
    }
}

impl Drop for AsyncPriorityChannel {
    fn drop(&mut self) {
        // Frames still buffered when the channel is torn down will never be
        // dequeued, so credit their reservation back to the shared budget here —
        // otherwise a churn of connections would leak the node-wide budget.
        if let Some(budget) = &self.budget {
            let remaining = self.inner.lock().map(|s| s.queued_bytes()).unwrap_or(0);
            budget.release(remaining);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use codec::{Frame, TrafficClass};
    use tokio::time::timeout;

    use super::AsyncPriorityChannel;
    use crate::budget::ByteBudget;
    use crate::error::TransportError;

    fn frame(class: TrafficClass, sequence: u64) -> Frame {
        Frame {
            class,
            msg_type: 0,
            sequence,
            payload: Vec::new(),
        }
    }

    fn sized(class: TrafficClass, sequence: u64, bytes: usize) -> Frame {
        Frame {
            class,
            msg_type: 0,
            sequence,
            payload: vec![0u8; bytes],
        }
    }

    #[tokio::test]
    async fn async_send_blocks_until_space_then_wakes() {
        // Capacity of one frame per class: the second reliable send on the same
        // class has nowhere to go and must park rather than shed.
        let ch = Arc::new(AsyncPriorityChannel::new(1));
        ch.try_send(frame(TrafficClass::Consensus, 0)).unwrap();

        let sender_ch = ch.clone();
        let sender =
            tokio::spawn(async move { sender_ch.send(frame(TrafficClass::Consensus, 1)).await });

        // The send is genuinely blocked: no capacity, no shed.
        tokio::task::yield_now().await;
        assert!(
            !sender.is_finished(),
            "send must block while the class is full"
        );

        // Draining one frame frees the slot and must wake the blocked sender.
        assert_eq!(ch.recv().await.unwrap().sequence, 0);
        let res = timeout(Duration::from_secs(5), sender)
            .await
            .expect("blocked send should wake after a dequeue")
            .unwrap();
        assert!(res.is_ok(), "send completes once space frees up");

        // The previously-blocked frame is now buffered and delivered in order.
        assert_eq!(ch.recv().await.unwrap().sequence, 1);
    }

    #[tokio::test]
    async fn async_send_unblocks_on_close_without_shedding() {
        let ch = Arc::new(AsyncPriorityChannel::new(1));
        ch.try_send(frame(TrafficClass::Consensus, 0)).unwrap();

        let sender_ch = ch.clone();
        let sender =
            tokio::spawn(async move { sender_ch.send(frame(TrafficClass::Consensus, 1)).await });
        tokio::task::yield_now().await;
        assert!(!sender.is_finished());

        // Closing the channel wakes the blocked sender with a typed error — the
        // frame is reported as undeliverable, never silently dropped.
        ch.close();
        let res = timeout(Duration::from_secs(5), sender)
            .await
            .expect("close should wake a blocked send")
            .unwrap();
        assert!(matches!(res, Err(TransportError::ConnectionClosed)));
    }

    #[tokio::test]
    async fn shared_budget_backpressures_try_send_and_frees_on_recv() {
        // A shared node-wide budget of 250 bytes across a generous per-class
        // queue: enqueue is bounded by the *budget*, not the frame count.
        let budget = ByteBudget::root(250);
        let ch = Arc::new(AsyncPriorityChannel::with_limits(
            1024,
            usize::MAX,
            Some(budget.clone()),
        ));
        ch.try_send(sized(TrafficClass::MarketData, 0, 100))
            .unwrap();
        ch.try_send(sized(TrafficClass::MarketData, 1, 100))
            .unwrap();
        assert_eq!(budget.used(), 200);
        assert_eq!(ch.queued_bytes(), 200);
        // The third 100-byte frame would push the budget to 300 > 250: shed.
        let err = ch
            .try_send(sized(TrafficClass::MarketData, 2, 100))
            .unwrap_err();
        assert!(matches!(
            err,
            TransportError::Backpressure {
                class: TrafficClass::MarketData
            }
        ));
        // A failed reservation is fully rolled back — the budget is unchanged.
        assert_eq!(budget.used(), 200);

        // Draining a frame credits the shared budget so a new frame fits again.
        let got = ch.recv().await.unwrap();
        assert_eq!(got.payload.len(), 100);
        assert_eq!(budget.used(), 100);
        ch.try_send(sized(TrafficClass::MarketData, 3, 100))
            .unwrap();
        assert_eq!(budget.used(), 200);
        assert_eq!(ch.queued_bytes_high_water(), 200);
    }

    #[test]
    fn dropping_channel_returns_buffered_bytes_to_the_budget() {
        // Buffered-but-undrained frames must not leak the shared budget when the
        // channel is torn down (connection churn).
        let budget = ByteBudget::root(10_000);
        {
            let ch = AsyncPriorityChannel::with_limits(1024, usize::MAX, Some(budget.clone()));
            ch.try_send(sized(TrafficClass::Sync, 0, 400)).unwrap();
            ch.try_send(sized(TrafficClass::Sync, 1, 600)).unwrap();
            assert_eq!(budget.used(), 1000);
        }
        // The channel dropped with 1000 bytes still buffered: all credited back.
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test]
    async fn async_send_never_sheds_a_full_stream_of_frames() {
        // A tight capacity with a lagging receiver: every reliable frame must be
        // delivered exactly once, in order — none shed under backpressure.
        let ch = Arc::new(AsyncPriorityChannel::new(2));
        let n = 64u64;
        let producer = ch.clone();
        let writer = tokio::spawn(async move {
            for i in 0..n {
                producer
                    .send(frame(TrafficClass::NewOrder, i))
                    .await
                    .unwrap();
            }
        });
        for i in 0..n {
            let got = timeout(Duration::from_secs(5), ch.recv())
                .await
                .expect("receiver should not stall")
                .unwrap();
            assert_eq!(got.sequence, i, "frames delivered contiguously, none shed");
        }
        writer.await.unwrap();
    }
}

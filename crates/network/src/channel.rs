//! Async wrapper around the strict-priority scheduler.
//!
//! [`AsyncPriorityChannel`] adds `await`-able receive and a close signal on top
//! of [`PriorityScheduler`]. It is the reliable "wire" between two connection
//! endpoints: for the loopback transport a single channel is shared by both
//! sides (sender enqueues, receiver awaits); for the TCP transport a local
//! channel is drained by a writer task on the send side and filled by a reader
//! task on the receive side; for the QUIC transport nine per-class writer
//! tasks each drain exactly their own class via
//! [`AsyncPriorityChannel::recv_class`], so a class parked on stream
//! flow-control credit never head-of-line blocks another class.
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
#[cfg(any(feature = "quic", test))]
use std::sync::PoisonError;
use std::sync::{Arc, Mutex};

use codec::Frame;
#[cfg(any(feature = "quic", test))]
use codec::TrafficClass;
use tokio::sync::Notify;

use crate::budget::ByteBudget;
use crate::error::TransportError;
use crate::scheduler::{frame_cost, PriorityScheduler, NUM_CLASSES};

/// A shared, bounded, strict-priority async frame channel.
#[derive(Debug)]
pub(crate) struct AsyncPriorityChannel {
    inner: Mutex<PriorityScheduler>,
    /// Wakes a blocked receiver when a frame is enqueued or the channel closes.
    notify: Notify,
    /// One wakeup per class for class-scoped receivers
    /// ([`recv_class`](Self::recv_class)): an enqueue for class C notifies
    /// exactly the class-C waiter. A single shared `Notify` with `notify_one`
    /// would hand the wakeup to an arbitrary waiter — with nine per-class QUIC
    /// writer tasks parked, a Sync enqueue could wake the Consensus writer
    /// (which re-parks on its empty class) while the Sync writer sleeps
    /// forever: a lost wakeup. Per-class notifies make the wakeup target
    /// structurally unambiguous.
    class_notify: [Notify; NUM_CLASSES],
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
            class_notify: std::array::from_fn(|_| Notify::new()),
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
            class_notify: std::array::from_fn(|_| Notify::new()),
            space: Notify::new(),
            closed: AtomicBool::new(false),
            budget,
        }
    }

    /// Wake receivers after a frame landed in class `idx`: the global waiter
    /// ([`recv`](Self::recv)) and the class-scoped waiter
    /// ([`recv_class`](Self::recv_class)). A channel is only ever drained
    /// through one of the two APIs, and notifying both is harmless — `Notify`
    /// stores at most one permit, so the unused side never accumulates state.
    fn notify_frame_ready(&self, idx: usize) {
        self.notify.notify_one();
        if let Some(notify) = self.class_notify.get(idx) {
            notify.notify_one();
        }
    }

    /// Account for `frame` having left the queue: credit the shared byte budget
    /// and wake one parked [`send`](Self::send). Must be called **exactly once
    /// per dequeued frame**, at the moment it is removed from the scheduler, so
    /// the budget tracks live queued bytes with no double-release and no leak
    /// (the [`Drop`] impl then only credits frames still queued).
    fn on_dequeued(&self, frame: &Frame) {
        if let Some(budget) = &self.budget {
            budget.release(frame_cost(frame));
        }
        self.space.notify_one();
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
        let idx = usize::from(class.priority());
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
        self.notify_frame_ready(idx);
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
        let idx = usize::from(frame.class.priority());
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
                    self.notify_frame_ready(idx);
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
                    // budget and wake a sender blocked in `send`.
                    self.on_dequeued(&frame);
                    return Some(frame);
                }
                if self.closed.load(Ordering::Acquire) {
                    return None;
                }
            }
            notified.await;
        }
    }

    /// Await and remove the next frame of **one class**, in that class's FIFO
    /// order. Returns `None` once the channel is closed and that class is
    /// drained. Frames in other classes are never returned and never awaited
    /// on: a saturated (or entirely unconsumed) class cannot head-of-line
    /// block another class's receiver.
    ///
    /// This is the per-class QUIC writer path: each of the nine writer tasks
    /// pulls exactly its own class and cross-class precedence is expressed by
    /// independent QUIC stream priorities rather than a shared dequeue order.
    ///
    /// Wakeup correctness: the class-scoped `Notified` future is created
    /// *before* the queue is checked, so an enqueue that lands between the
    /// check and the await stores a permit that completes the pre-registered
    /// future immediately — a frame enqueued for class C therefore always
    /// wakes the class-C waiter, even under contention. [`close`](Self::close)
    /// uses `notify_waiters` on every class so shutdown wakes all writers.
    #[cfg(any(feature = "quic", test))]
    pub(crate) async fn recv_class(&self, class: TrafficClass) -> Option<Frame> {
        let idx = usize::from(class.priority());
        // `priority()` is 0..=8 for every valid class, so the slot exists; an
        // impossible index is treated defensively as a closed, empty class.
        let class_notify = self.class_notify.get(idx)?;
        loop {
            // Register interest *before* checking so a concurrent enqueue into
            // this class that fires between the check and the await cannot be
            // lost (the stored permit completes the pre-created future).
            let notified = class_notify.notified();
            {
                let mut sched = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
                if let Some(frame) = sched.dequeue_class(class) {
                    drop(sched);
                    // The frame's bytes are no longer retained: credit the shared
                    // budget and wake a sender blocked in `send`.
                    self.on_dequeued(&frame);
                    return Some(frame);
                }
                if self.closed.load(Ordering::Acquire) {
                    return None;
                }
            }
            notified.await;
        }
    }

    /// Remove the highest-priority frame without waiting.
    ///
    /// Writer tasks use this after their first awaited receive to coalesce the
    /// frames already queued into one socket write while preserving strict
    /// priority ordering.
    pub(crate) fn try_recv(&self) -> Option<Frame> {
        let mut sched = self.inner.lock().expect("scheduler mutex poisoned");
        let frame = sched.dequeue();
        drop(sched);
        if let Some(frame) = &frame {
            // Same dequeue-side accounting as `recv`: the frame left the queue,
            // so its budget reservation is credited here (and only here).
            self.on_dequeued(frame);
        }
        frame
    }

    /// Signal closure and wake **all** waiters — the global receiver, every
    /// class-scoped receiver, and blocked senders — so each of the per-class
    /// writer tasks can observe shutdown. Buffered frames remain drainable.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify.notify_waiters();
        for notify in &self.class_notify {
            notify.notify_waiters();
        }
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
    async fn recv_class_wakes_exactly_the_waiting_class() {
        // Two class-scoped waiters park on an empty channel. An enqueue for one
        // class must wake exactly that class's waiter; the other must stay
        // parked (a shared notify_one could have handed the wakeup to the
        // wrong waiter, which would re-park and strand the frame).
        let ch = Arc::new(AsyncPriorityChannel::new(4));
        let consensus_ch = ch.clone();
        let consensus =
            tokio::spawn(async move { consensus_ch.recv_class(TrafficClass::Consensus).await });
        let sync_ch = ch.clone();
        let sync = tokio::spawn(async move { sync_ch.recv_class(TrafficClass::Sync).await });
        tokio::task::yield_now().await;
        assert!(!consensus.is_finished());
        assert!(!sync.is_finished());

        // A Consensus enqueue wakes the Consensus waiter...
        ch.try_send(frame(TrafficClass::Consensus, 0)).unwrap();
        let got = timeout(Duration::from_secs(5), consensus)
            .await
            .expect("consensus waiter must wake on a consensus enqueue")
            .unwrap()
            .unwrap();
        assert_eq!(got.class, TrafficClass::Consensus);
        assert_eq!(got.sequence, 0);

        // ...while the Sync waiter stays parked: its class is still empty and
        // its wakeup was not consumed by the other class.
        tokio::task::yield_now().await;
        assert!(
            !sync.is_finished(),
            "sync waiter must not wake for consensus"
        );

        // A Sync enqueue then wakes the Sync waiter.
        ch.try_send(frame(TrafficClass::Sync, 7)).unwrap();
        let got = timeout(Duration::from_secs(5), sync)
            .await
            .expect("sync waiter must wake on a sync enqueue")
            .unwrap()
            .unwrap();
        assert_eq!(got.class, TrafficClass::Sync);
        assert_eq!(got.sequence, 7);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn recv_class_never_loses_a_wakeup_under_contention() {
        // A producer races frames into two classes through a tiny (4-frame)
        // per-class queue while two class-scoped consumers pull concurrently on
        // separate worker threads. Every frame must reach its own class's
        // consumer in FIFO order; a single lost wakeup parks a consumer forever
        // and trips the timeout.
        let ch = Arc::new(AsyncPriorityChannel::new(4));
        let n = 512u64;

        let consensus_ch = ch.clone();
        let consensus = tokio::spawn(async move {
            for expect in 0..n {
                let got = consensus_ch
                    .recv_class(TrafficClass::Consensus)
                    .await
                    .expect("channel must stay open while frames remain");
                assert_eq!(got.class, TrafficClass::Consensus);
                assert_eq!(got.sequence, expect, "consensus FIFO within class");
            }
        });
        let sync_ch = ch.clone();
        let sync = tokio::spawn(async move {
            for expect in 0..n {
                let got = sync_ch
                    .recv_class(TrafficClass::Sync)
                    .await
                    .expect("channel must stay open while frames remain");
                assert_eq!(got.class, TrafficClass::Sync);
                assert_eq!(got.sequence, expect, "sync FIFO within class");
            }
        });

        let producer_ch = ch.clone();
        let producer = tokio::spawn(async move {
            for seq in 0..n {
                for class in [TrafficClass::Consensus, TrafficClass::Sync] {
                    loop {
                        match producer_ch.try_send(frame(class, seq)) {
                            Ok(()) => break,
                            Err(TransportError::Backpressure { .. }) => {
                                tokio::task::yield_now().await;
                            }
                            Err(e) => panic!("unexpected send error: {e}"),
                        }
                    }
                }
            }
        });

        timeout(Duration::from_secs(30), async {
            producer.await.unwrap();
            consensus.await.unwrap();
            sync.await.unwrap();
        })
        .await
        .expect("a consumer parked forever: lost class wakeup");
        assert_eq!(ch.pending(), 0, "every frame delivered exactly once");
    }

    #[tokio::test]
    async fn full_class_never_blocks_another_class_receiver() {
        // Regression (#395): saturate Sync to its frame cap with *no* Sync
        // consumer at all. A Consensus frame enqueued afterwards must still be
        // received immediately by the Consensus class receiver — the parked
        // class cannot head-of-line block a different class.
        let ch = Arc::new(AsyncPriorityChannel::new(2));
        ch.try_send(frame(TrafficClass::Sync, 0)).unwrap();
        ch.try_send(frame(TrafficClass::Sync, 1)).unwrap();
        assert!(matches!(
            ch.try_send(frame(TrafficClass::Sync, 2)),
            Err(TransportError::Backpressure {
                class: TrafficClass::Sync
            })
        ));

        ch.try_send(frame(TrafficClass::Consensus, 0)).unwrap();
        let got = timeout(
            Duration::from_secs(5),
            ch.recv_class(TrafficClass::Consensus),
        )
        .await
        .expect("consensus receiver must not be blocked by a full sync class")
        .unwrap();
        assert_eq!(got.class, TrafficClass::Consensus);
        assert_eq!(got.sequence, 0);
        assert_eq!(ch.pending(), 2, "the sync backlog is untouched");
    }

    #[tokio::test]
    async fn close_wakes_every_class_waiter() {
        // Shutdown must wake all nine class-scoped waiters, not just one: a
        // notify_one-style close would leave eight writer tasks parked forever.
        let ch = Arc::new(AsyncPriorityChannel::new(4));
        let mut waiters = Vec::new();
        for class_byte in 0..u8::try_from(crate::scheduler::NUM_CLASSES).unwrap() {
            let class = TrafficClass::from_u8(class_byte).unwrap();
            let waiter_ch = ch.clone();
            waiters.push(tokio::spawn(
                async move { waiter_ch.recv_class(class).await },
            ));
        }
        tokio::task::yield_now().await;
        ch.close();
        for waiter in waiters {
            let got = timeout(Duration::from_secs(5), waiter)
                .await
                .expect("close must wake every class waiter")
                .unwrap();
            assert!(got.is_none(), "closed and drained class returns None");
        }
    }

    #[tokio::test]
    async fn recv_class_drains_buffered_frames_after_close() {
        // Close never sheds: frames already buffered stay drainable per class,
        // then the closed class reports end-of-stream.
        let ch = AsyncPriorityChannel::new(4);
        ch.try_send(frame(TrafficClass::Consensus, 0)).unwrap();
        ch.try_send(frame(TrafficClass::Consensus, 1)).unwrap();
        ch.close();
        assert_eq!(
            ch.recv_class(TrafficClass::Consensus)
                .await
                .unwrap()
                .sequence,
            0
        );
        assert_eq!(
            ch.recv_class(TrafficClass::Consensus)
                .await
                .unwrap()
                .sequence,
            1
        );
        assert!(ch.recv_class(TrafficClass::Consensus).await.is_none());
        assert!(ch.recv_class(TrafficClass::Sync).await.is_none());
    }

    #[tokio::test]
    async fn recv_class_releases_budget_exactly_once_per_frame() {
        let budget = ByteBudget::root(10_000);
        let ch = Arc::new(AsyncPriorityChannel::with_limits(
            16,
            usize::MAX,
            Some(budget.clone()),
        ));
        ch.try_send(sized(TrafficClass::Sync, 0, 400)).unwrap();
        ch.try_send(sized(TrafficClass::Consensus, 0, 300)).unwrap();
        assert_eq!(budget.used(), 700);

        // Each class-scoped dequeue credits exactly that frame's cost.
        let sync = ch.recv_class(TrafficClass::Sync).await.unwrap();
        assert_eq!(sync.payload.len(), 400);
        assert_eq!(budget.used(), 300);
        let consensus = ch.recv_class(TrafficClass::Consensus).await.unwrap();
        assert_eq!(consensus.payload.len(), 300);
        assert_eq!(budget.used(), 0);

        // Drop of the fully-drained channel must not re-credit frames the
        // class receivers already released (no double-release).
        assert!(budget.try_reserve(100));
        drop(ch);
        assert_eq!(budget.used(), 100, "drop double-released dequeued frames");
    }

    #[tokio::test]
    async fn recv_class_frees_space_for_a_blocked_send() {
        // A class-scoped dequeue must wake a sender parked in `send`, exactly
        // like the global `recv` does.
        let ch = Arc::new(AsyncPriorityChannel::new(1));
        ch.try_send(frame(TrafficClass::Sync, 0)).unwrap();

        let sender_ch = ch.clone();
        let sender =
            tokio::spawn(async move { sender_ch.send(frame(TrafficClass::Sync, 1)).await });
        tokio::task::yield_now().await;
        assert!(
            !sender.is_finished(),
            "send must park while the class is full"
        );

        assert_eq!(ch.recv_class(TrafficClass::Sync).await.unwrap().sequence, 0);
        let res = timeout(Duration::from_secs(5), sender)
            .await
            .expect("recv_class must wake the blocked send")
            .unwrap();
        assert!(res.is_ok());
        assert_eq!(ch.recv_class(TrafficClass::Sync).await.unwrap().sequence, 1);
    }

    #[test]
    fn try_recv_releases_budget_like_recv() {
        // The TCP writer drains coalesced batches via `try_recv`: every frame
        // that leaves the queue must credit the shared budget exactly like
        // `recv`, or budget capacity leaks for the connection's lifetime.
        let budget = ByteBudget::root(10_000);
        let ch = AsyncPriorityChannel::with_limits(16, usize::MAX, Some(budget.clone()));
        ch.try_send(sized(TrafficClass::MarketData, 0, 250))
            .unwrap();
        assert_eq!(budget.used(), 250);
        let got = ch.try_recv().unwrap();
        assert_eq!(got.payload.len(), 250);
        assert_eq!(
            budget.used(),
            0,
            "try_recv must credit the budget on dequeue"
        );
        assert!(ch.try_recv().is_none());
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

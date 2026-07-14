//! Lock-free, cache-separated single-shard owner pipeline.
//!
//! Each ingress producer owns one [`SpscProducer`]; a shard with multiple
//! network/admission producers gives each its own ring and polls them on the
//! pinned owner thread. This avoids a contended MPSC head while retaining exact
//! bounded backpressure. The owner alone mutates [`execution::Engine`].

use std::cell::{Cell, UnsafeCell};
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use execution::{Command, DeterministicEngine, Engine, ExecutionError, ExecutionReceipt};
use types::SequenceNumber;

/// Cache-line-separated atomic index. 128 bytes covers current x86 and
/// aarch64 destructive-interference widths and prevents producer/consumer
/// counters from sharing a line.
#[repr(align(128))]
struct CachePadded<T>(T);

struct Slot<T> {
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: a slot is written only by the sole producer before a Release tail
// publication and read only by the sole consumer after an Acquire tail load.
// The consumer publishes reuse through the head with the symmetric ordering.
#[allow(unsafe_code)]
unsafe impl<T: Send> Sync for Slot<T> {}

struct RingInner<T> {
    slots: Box<[Slot<T>]>,
    mask: usize,
    head: CachePadded<AtomicUsize>,
    tail: CachePadded<AtomicUsize>,
}

// SAFETY: ownership is split into exactly one non-Clone producer and one
// non-Clone consumer. Slot synchronization is described above.
#[allow(unsafe_code)]
unsafe impl<T: Send> Sync for RingInner<T> {}

impl<T> Drop for RingInner<T> {
    fn drop(&mut self) {
        let mut head = self.head.0.load(Ordering::Relaxed);
        let tail = self.tail.0.load(Ordering::Relaxed);
        while head != tail {
            let index = head & self.mask;
            // SAFETY: when the last Arc drops no endpoint can be active. Every
            // position in [head, tail) was initialized and not yet consumed.
            #[allow(unsafe_code)]
            unsafe {
                (*self.slots[index].value.get()).assume_init_drop();
            }
            head = head.wrapping_add(1);
        }
    }
}

/// Sole producer endpoint for a bounded lock-free ring.
pub struct SpscProducer<T> {
    inner: Arc<RingInner<T>>,
    /// `Cell` makes the endpoint `!Sync`, preventing shared concurrent calls,
    /// while remaining `Send` so ownership can move to its producer thread.
    _single_owner: PhantomData<Cell<()>>,
}

/// Sole consumer endpoint for a bounded lock-free ring.
pub struct SpscConsumer<T> {
    inner: Arc<RingInner<T>>,
    _single_owner: PhantomData<Cell<()>>,
}

/// Build a fixed-capacity power-of-two SPSC ring.
pub fn spsc_ring<T>(capacity: usize) -> Result<(SpscProducer<T>, SpscConsumer<T>), RingError> {
    if capacity < 2 || !capacity.is_power_of_two() {
        return Err(RingError::CapacityMustBePowerOfTwo);
    }
    let slots: Vec<Slot<T>> = (0..capacity)
        .map(|_| Slot {
            value: UnsafeCell::new(MaybeUninit::uninit()),
        })
        .collect();
    let inner = Arc::new(RingInner {
        slots: slots.into_boxed_slice(),
        mask: capacity - 1,
        head: CachePadded(AtomicUsize::new(0)),
        tail: CachePadded(AtomicUsize::new(0)),
    });
    Ok((
        SpscProducer {
            inner: Arc::clone(&inner),
            _single_owner: PhantomData,
        },
        SpscConsumer {
            inner,
            _single_owner: PhantomData,
        },
    ))
}

impl<T> SpscProducer<T> {
    /// Enqueue without blocking or allocation, returning ownership on fullness.
    pub fn try_push(&mut self, value: T) -> Result<(), T> {
        let tail = self.inner.tail.0.load(Ordering::Relaxed);
        let head = self.inner.head.0.load(Ordering::Acquire);
        if tail.wrapping_sub(head) == self.inner.slots.len() {
            return Err(value);
        }
        let index = tail & self.inner.mask;
        // SAFETY: only this producer writes the unpublished tail slot; fullness
        // proves the consumer has released it for reuse.
        #[allow(unsafe_code)]
        unsafe {
            (*self.inner.slots[index].value.get()).write(value);
        }
        self.inner
            .tail
            .0
            .store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Fixed ring capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.inner.slots.len()
    }

    /// Slots currently available to this sole producer.
    ///
    /// The consumer can only increase this value after the Acquire load. Once
    /// the producer observes room for an entire batch, its exclusive ownership
    /// of `tail` makes the subsequent batch of pushes an atomic admission
    /// decision: no competing producer can consume the reservation.
    #[must_use]
    pub fn available_capacity(&self) -> usize {
        let tail = self.inner.tail.0.load(Ordering::Relaxed);
        let head = self.inner.head.0.load(Ordering::Acquire);
        self.inner
            .slots
            .len()
            .saturating_sub(tail.wrapping_sub(head).min(self.inner.slots.len()))
    }
}

impl<T> SpscConsumer<T> {
    /// Dequeue without blocking or allocation.
    pub fn try_pop(&mut self) -> Option<T> {
        let head = self.inner.head.0.load(Ordering::Relaxed);
        let tail = self.inner.tail.0.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let index = head & self.inner.mask;
        // SAFETY: the Acquire observed the producer's initialized slot, and
        // this sole consumer reads it exactly once before publishing reuse.
        #[allow(unsafe_code)]
        let value = unsafe { (*self.inner.slots[index].value.get()).assume_init_read() };
        self.inner
            .head
            .0
            .store(head.wrapping_add(1), Ordering::Release);
        Some(value)
    }

    /// Current approximate occupancy. Exact for the SPSC owner pair at a
    /// quiescent observation; intended for off-thread metrics only.
    #[must_use]
    pub fn len(&self) -> usize {
        let head = self.inner.head.0.load(Ordering::Acquire);
        let tail = self.inner.tail.0.load(Ordering::Acquire);
        tail.wrapping_sub(head).min(self.inner.slots.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Invalid bounded-ring construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RingError {
    #[error("SPSC capacity must be a power of two and at least two")]
    CapacityMustBePowerOfTwo,
}

/// One canonically sequenced command handed to the shard owner.
pub struct ShardCommand {
    pub sequence: SequenceNumber,
    pub command: Command,
}

/// One execution result handed to receipt/consensus-effect processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardEffect {
    pub sequence: SequenceNumber,
    pub result: Result<ExecutionReceipt, ExecutionError>,
}

/// Producer-facing bounded shard ingress.
pub struct ShardIngress {
    producer: SpscProducer<ShardCommand>,
}

/// Build only the bounded command handoff, for a network producer that is
/// attached to an externally managed shard-owner poll loop.
pub fn shard_command_ring(
    capacity: usize,
) -> Result<(ShardIngress, SpscConsumer<ShardCommand>), RingError> {
    let (producer, consumer) = spsc_ring(capacity)?;
    Ok((ShardIngress { producer }, consumer))
}

impl ShardIngress {
    /// Submit or recover the command unchanged when the bounded ring is full.
    /// Returning the inline command is intentionally larger than Clippy's
    /// conventional error threshold: boxing it would allocate on backpressure.
    #[allow(clippy::result_large_err)]
    pub fn try_submit(&mut self, command: ShardCommand) -> Result<(), ShardCommand> {
        self.producer.try_push(command)
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.producer.capacity()
    }

    /// Current producer-visible capacity for atomic batch admission.
    #[must_use]
    pub fn available_capacity(&self) -> usize {
        self.producer.available_capacity()
    }
}

/// Consumer-facing bounded receipt/consensus-effect egress.
pub struct ShardEgress {
    consumer: SpscConsumer<ShardEffect>,
}

impl ShardEgress {
    pub fn try_recv(&mut self) -> Option<ShardEffect> {
        self.consumer.try_pop()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.consumer.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.consumer.is_empty()
    }
}

/// Owner-thread counters. Updated by one thread with ordinary integers; scrape
/// or aggregate only outside the measured loop.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ShardCounters {
    pub dequeued: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub egress_backpressure: u64,
}

/// Result of one non-blocking owner iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardStep {
    Idle,
    Processed,
    EgressBackpressure,
}

/// Single writer that owns all mutable deterministic shard state.
pub struct ShardWorker {
    engine: Engine,
    ingress: SpscConsumer<ShardCommand>,
    egress: SpscProducer<ShardEffect>,
    pending: Option<ShardEffect>,
    counters: ShardCounters,
}

/// Construct one shard-owner pipeline with independently bounded ingress and
/// egress. All storage is allocated here, before the worker starts.
pub fn shard_pipeline(
    engine: Engine,
    ingress_capacity: usize,
    egress_capacity: usize,
) -> Result<(ShardIngress, ShardWorker, ShardEgress), RingError> {
    let (ingress_tx, ingress_rx) = spsc_ring(ingress_capacity)?;
    let (egress_tx, egress_rx) = spsc_ring(egress_capacity)?;
    Ok((
        ShardIngress {
            producer: ingress_tx,
        },
        ShardWorker {
            engine,
            ingress: ingress_rx,
            egress: egress_tx,
            pending: None,
            counters: ShardCounters::default(),
        },
        ShardEgress {
            consumer: egress_rx,
        },
    ))
}

impl ShardWorker {
    /// Perform at most one dequeue/execute/enqueue transition.
    pub fn step(&mut self) -> ShardStep {
        if let Some(effect) = self.pending.take() {
            if let Err(effect) = self.egress.try_push(effect) {
                self.pending = Some(effect);
                self.counters.egress_backpressure =
                    self.counters.egress_backpressure.saturating_add(1);
                return ShardStep::EgressBackpressure;
            }
            return ShardStep::Processed;
        }
        let Some(item) = self.ingress.try_pop() else {
            return ShardStep::Idle;
        };
        self.counters.dequeued = self.counters.dequeued.saturating_add(1);
        let sequence = item.sequence;
        let result = self.engine.execute(sequence, item.command);
        if result.is_ok() {
            self.counters.accepted = self.counters.accepted.saturating_add(1);
        } else {
            self.counters.rejected = self.counters.rejected.saturating_add(1);
        }
        let effect = ShardEffect { sequence, result };
        if let Err(effect) = self.egress.try_push(effect) {
            self.pending = Some(effect);
            self.counters.egress_backpressure = self.counters.egress_backpressure.saturating_add(1);
            ShardStep::EgressBackpressure
        } else {
            ShardStep::Processed
        }
    }

    /// Run on the current (normally pinned) owner thread until `stop` is set.
    /// Busy-polling never parks or acquires a lock; the cooperative mode yields
    /// only when no work is ready.
    pub fn run_until(&mut self, stop: &AtomicBool, busy_poll: bool) {
        while !stop.load(Ordering::Acquire) {
            match self.step() {
                ShardStep::Idle | ShardStep::EgressBackpressure if busy_poll => {
                    std::hint::spin_loop();
                }
                ShardStep::Idle | ShardStep::EgressBackpressure => std::thread::yield_now(),
                ShardStep::Processed => {}
            }
        }
    }

    #[must_use]
    pub const fn counters(&self) -> ShardCounters {
        self.counters
    }

    #[must_use]
    pub fn state_root(&self) -> types::Hash {
        self.engine.state_root()
    }

    #[must_use]
    pub fn into_engine(self) -> Engine {
        self.engine
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use execution::{Authorization, CreateAccount, CreateMarket, EngineConfig, PlaceOrder};
    use types::{
        AccountId, Amount, MarketId, MarketType, OrderId, OrderType, Price, Quantity, Side,
        TimeInForce,
    };

    fn initialized_engine() -> Engine {
        let mut engine = Engine::new(EngineConfig::default());
        engine
            .execute(
                SequenceNumber::new(1),
                Command::CreateAccount(CreateAccount {
                    initial_collateral: Amount::from_raw(1_000_000_000),
                }),
            )
            .unwrap();
        engine
            .execute(
                SequenceNumber::new(2),
                Command::CreateMarket(CreateMarket {
                    market: MarketId::new(0),
                    market_type: MarketType::Perpetual,
                    outcomes: 1,
                    mark_price: Price::from_raw(1_000_000),
                }),
            )
            .unwrap();
        engine
    }

    fn order(sequence: u64) -> ShardCommand {
        ShardCommand {
            sequence: SequenceNumber::new(sequence),
            command: Command::PlaceOrder(PlaceOrder {
                account: AccountId::new(0),
                market: MarketId::new(0),
                order_id: OrderId::new(sequence),
                side: Side::Bid,
                order_type: OrderType::Limit,
                tif: TimeInForce::Gtc,
                price: Price::from_raw(1),
                quantity: Quantity::from_raw(1),
                client_id: sequence,
                reduce_only: false,
                instrument: 0,
                auth: Authorization::Master,
            }),
        }
    }

    #[test]
    fn ring_is_fifo_bounded_and_returns_unaccepted_suffix() {
        let (mut tx, mut rx) = spsc_ring(4).unwrap();
        for i in 0..4 {
            assert_eq!(tx.try_push(i), Ok(()));
        }
        assert_eq!(tx.try_push(4), Err(4));
        for i in 0..4 {
            assert_eq!(rx.try_pop(), Some(i));
        }
        assert_eq!(rx.try_pop(), None);
    }

    #[test]
    fn shard_owner_preserves_order_roots_and_exact_accounting() {
        let engine = initialized_engine();
        let (mut ingress, mut worker, mut egress) = shard_pipeline(engine, 8, 8).unwrap();
        for sequence in 3..=6 {
            ingress.try_submit(order(sequence)).ok().unwrap();
            assert_eq!(worker.step(), ShardStep::Processed);
            let effect = egress.try_recv().unwrap();
            assert_eq!(effect.sequence, SequenceNumber::new(sequence));
            assert!(effect.result.is_ok());
        }
        assert_eq!(
            worker.counters(),
            ShardCounters {
                dequeued: 4,
                accepted: 4,
                rejected: 0,
                egress_backpressure: 0,
            }
        );

        let mut direct = initialized_engine();
        for sequence in 3..=6 {
            let item = order(sequence);
            direct.execute(item.sequence, item.command).unwrap();
        }
        assert_eq!(worker.state_root(), direct.state_root());
    }

    #[test]
    fn egress_saturation_stops_dequeue_and_loses_nothing() {
        let engine = initialized_engine();
        let (mut ingress, mut worker, mut egress) = shard_pipeline(engine, 8, 2).unwrap();
        for sequence in 3..=5 {
            ingress.try_submit(order(sequence)).ok().unwrap();
        }
        assert_eq!(worker.step(), ShardStep::Processed);
        assert_eq!(worker.step(), ShardStep::Processed);
        assert_eq!(worker.step(), ShardStep::EgressBackpressure);
        assert_eq!(worker.counters().dequeued, 3);
        assert!(egress.try_recv().unwrap().result.is_ok());
        assert_eq!(worker.step(), ShardStep::Processed);
        assert!(egress.try_recv().unwrap().result.is_ok());
        assert!(egress.try_recv().unwrap().result.is_ok());
        assert!(egress.is_empty());
    }
}

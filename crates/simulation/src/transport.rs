//! Fault-injecting simulated transport.
//!
//! The transport turns a logical *send* between two nodes into zero or more
//! scheduled *deliveries*, applying — deterministically from a [`SimRng`] — the
//! fault modes required by the fault matrix: extra delay, jitter-driven
//! reordering, drops, duplication, per-node clock drift, and network
//! partitions. It also tracks message accounting so tests can assert the ledger
//! identity `sent == delivered_once + dropped` with duplicates counted
//! separately.
//!
//! A separate [`PriorityLink`] models a bandwidth-limited link that services
//! traffic strictly by [`TrafficClass`] priority, used to prove that consensus
//! (P0) traffic is not starved behind market-data (P7) traffic under load.

use std::collections::BinaryHeap;

use codec::TrafficClass;

use crate::rng::SimRng;
use crate::scheduler::Time;

/// Per-link fault configuration. All fields are integer-only (no floating
/// point) so behavior is bit-reproducible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkFaults {
    /// Fixed base one-way delay added to every delivery (ns).
    pub base_delay_ns: u64,
    /// Maximum uniform jitter added on top of the base delay (ns).
    pub jitter_ns: u64,
    /// Probability in per-mille that a message is dropped outright.
    pub drop_permille: u32,
    /// Probability in per-mille that a delivered message is also duplicated.
    pub dup_permille: u32,
    /// Maximum number of *extra* duplicate copies when duplication fires.
    pub max_dups: u32,
    /// Probability in per-mille that a message receives a large extra delay,
    /// which reorders it relative to its peers.
    pub reorder_permille: u32,
    /// Maximum extra delay applied when reordering fires (ns).
    pub reorder_spread_ns: u64,
}

impl LinkFaults {
    /// A perfect link: no delay, no loss, no duplication, no reordering.
    pub const PERFECT: LinkFaults = LinkFaults {
        base_delay_ns: 0,
        jitter_ns: 0,
        drop_permille: 0,
        dup_permille: 0,
        max_dups: 0,
        reorder_permille: 0,
        reorder_spread_ns: 0,
    };

    /// A well-behaved but latent link: small delay and jitter, no faults.
    #[must_use]
    pub fn latent(base_delay_ns: u64, jitter_ns: u64) -> Self {
        Self {
            base_delay_ns,
            jitter_ns,
            ..Self::PERFECT
        }
    }
}

/// Running message accounting for the transport.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TransportStats {
    /// Logical messages handed to the transport.
    pub sent: u64,
    /// Messages dropped (never delivered).
    pub dropped: u64,
    /// Distinct messages delivered at least once (the "primary" copy).
    pub delivered_once: u64,
    /// Extra duplicate copies delivered beyond the primary.
    pub duplicated: u64,
}

impl TransportStats {
    /// Total delivery events (primary copies plus duplicates).
    #[must_use]
    pub fn total_deliveries(&self) -> u64 {
        self.delivered_once + self.duplicated
    }

    /// The core ledger identity: every sent message is either dropped or
    /// delivered exactly once (before duplication).
    #[must_use]
    pub fn ledger_balances(&self) -> bool {
        self.sent == self.dropped + self.delivered_once
    }
}

/// The outcome of routing one logical message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Routing {
    /// The message was dropped (partition or loss).
    Dropped,
    /// The message is delivered at each of these absolute times. The first
    /// entry is the primary copy; any others are duplicates.
    Deliver(Vec<Time>),
}

/// The fault-injecting transport shared by all links in a run.
#[derive(Debug, Clone)]
pub struct Transport {
    faults: LinkFaults,
    /// Partition group id per node index; nodes in different groups cannot
    /// exchange messages. An empty vector means a single fully-connected group.
    groups: Vec<u32>,
    /// Additive per-node send skew (clock drift), ns.
    skew_ns: Vec<u64>,
    stats: TransportStats,
}

impl Transport {
    /// Create a transport with uniform link faults and no partition.
    #[must_use]
    pub fn new(faults: LinkFaults) -> Self {
        Self {
            faults,
            groups: Vec::new(),
            skew_ns: Vec::new(),
            stats: TransportStats::default(),
        }
    }

    /// The current statistics snapshot.
    #[must_use]
    pub fn stats(&self) -> TransportStats {
        self.stats
    }

    /// The active fault configuration.
    #[must_use]
    pub fn faults(&self) -> LinkFaults {
        self.faults
    }

    /// Install a partition: `groups[node] == group id`. Nodes in different
    /// groups are severed until [`Transport::heal`] is called.
    pub fn partition(&mut self, groups: Vec<u32>) {
        self.groups = groups;
    }

    /// Remove any partition, restoring full connectivity.
    pub fn heal(&mut self) {
        self.groups.clear();
    }

    /// Set per-node additive send skew (clock drift) in nanoseconds.
    pub fn set_skew(&mut self, skew_ns: Vec<u64>) {
        self.skew_ns = skew_ns;
    }

    /// Whether two nodes can currently reach each other.
    #[must_use]
    pub fn connected(&self, from: u32, to: u32) -> bool {
        if self.groups.is_empty() {
            return true;
        }
        match (
            self.groups.get(usize::try_from(from).unwrap_or(usize::MAX)),
            self.groups.get(usize::try_from(to).unwrap_or(usize::MAX)),
        ) {
            (Some(a), Some(b)) => a == b,
            // Nodes without an assigned group are treated as reachable.
            _ => true,
        }
    }

    fn skew_for(&self, node: u32) -> u64 {
        self.skew_ns
            .get(usize::try_from(node).unwrap_or(usize::MAX))
            .copied()
            .unwrap_or(0)
    }

    /// Route one logical message from `from` to `to`, deciding its fate from
    /// `rng`. `now` is the current logical time. Delivery to self is always
    /// reliable and immediate (a node never drops its own message), which keeps
    /// self-vote accounting exact.
    pub fn route(&mut self, from: u32, to: u32, now: Time, rng: &mut SimRng) -> Routing {
        self.stats.sent += 1;

        if from == to {
            self.stats.delivered_once += 1;
            return Routing::Deliver(vec![now]);
        }

        if !self.connected(from, to) {
            self.stats.dropped += 1;
            return Routing::Dropped;
        }

        if rng.chance_permille(self.faults.drop_permille) {
            self.stats.dropped += 1;
            return Routing::Dropped;
        }

        // Primary delivery time = now + base + jitter + optional reorder spread
        // + sender clock skew.
        let jitter = if self.faults.jitter_ns == 0 {
            0
        } else {
            rng.below(self.faults.jitter_ns + 1)
        };
        let reorder = if rng.chance_permille(self.faults.reorder_permille)
            && self.faults.reorder_spread_ns > 0
        {
            rng.below(self.faults.reorder_spread_ns + 1)
        } else {
            0
        };
        let primary = now
            .saturating_add(self.faults.base_delay_ns)
            .saturating_add(jitter)
            .saturating_add(reorder)
            .saturating_add(self.skew_for(from));

        let mut times = vec![primary];
        self.stats.delivered_once += 1;

        if self.faults.max_dups > 0 && rng.chance_permille(self.faults.dup_permille) {
            let extra = rng.below(u64::from(self.faults.max_dups)) + 1;
            for _ in 0..extra {
                let dup_jitter = if self.faults.jitter_ns == 0 {
                    0
                } else {
                    rng.below(self.faults.jitter_ns + 1)
                };
                times.push(primary.saturating_add(dup_jitter));
                self.stats.duplicated += 1;
            }
        }

        Routing::Deliver(times)
    }
}

/// A single item queued on a bandwidth-limited priority link.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PriorityItem<T> {
    priority: u8,
    seq: u64,
    payload: T,
}

impl<T: Eq> Ord for PriorityItem<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Min-heap on (priority, seq): lower priority number = higher urgency
        // and is served first; FIFO within a priority via `seq`.
        other
            .priority
            .cmp(&self.priority)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}
impl<T: Eq> PartialOrd for PriorityItem<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A bounded, priority-ordered outbound link.
///
/// Under a per-step service budget, higher-priority traffic (lower
/// [`TrafficClass`] value) is always dequeued first, so P0 consensus traffic is
/// never starved behind a P7 market-data backlog. The queue is bounded: once it
/// reaches `capacity`, the lowest-priority item is evicted rather than growing
/// without bound.
#[derive(Debug)]
pub struct PriorityLink<T: Eq> {
    heap: BinaryHeap<PriorityItem<T>>,
    seq: u64,
    capacity: usize,
    evicted: u64,
}

impl<T: Eq> PriorityLink<T> {
    /// Create a link whose backlog is bounded to `capacity` items.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            heap: BinaryHeap::new(),
            seq: 0,
            capacity: capacity.max(1),
            evicted: 0,
        }
    }

    /// Current backlog depth.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.heap.len()
    }

    /// Number of items evicted due to the capacity bound.
    #[must_use]
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Enqueue an item at the priority of its traffic class.
    pub fn enqueue(&mut self, class: TrafficClass, payload: T) {
        let seq = self.seq;
        self.seq += 1;
        self.heap.push(PriorityItem {
            priority: class.priority(),
            seq,
            payload,
        });
        // Enforce the bound: if we overflowed, drop the least urgent item.
        if self.heap.len() > self.capacity {
            self.evict_lowest_priority();
        }
    }

    /// Dequeue up to `budget` items in strict priority order.
    pub fn drain(&mut self, budget: usize) -> Vec<T> {
        let mut out = Vec::new();
        for _ in 0..budget {
            match self.heap.pop() {
                Some(item) => out.push(item.payload),
                None => break,
            }
        }
        out
    }

    /// Dequeue the single most-urgent item, if any.
    pub fn pop(&mut self) -> Option<T> {
        self.heap.pop().map(|i| i.payload)
    }

    fn evict_lowest_priority(&mut self) {
        // Drain, drop the lowest-priority (largest priority number, then newest
        // seq), and re-insert the rest. Bounded work, no unbounded growth.
        let mut items: Vec<PriorityItem<T>> = self.heap.drain().collect();
        if items.is_empty() {
            return;
        }
        let mut worst = 0usize;
        for i in 1..items.len() {
            let cur = &items[i];
            let cand = &items[worst];
            if cur.priority > cand.priority || (cur.priority == cand.priority && cur.seq > cand.seq)
            {
                worst = i;
            }
        }
        items.swap_remove(worst);
        self.evicted += 1;
        for item in items {
            self.heap.push(item);
        }
    }
}

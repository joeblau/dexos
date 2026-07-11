//! The multi-node cluster orchestrator.
//!
//! A [`Cluster`] wires N [`Node`]s to a fault-injecting [`Transport`] and a
//! deterministic [`Scheduler`], then runs a [`SimConfig`] scenario to
//! completion. Every source of nondeterminism is the seeded [`SimRng`], and
//! every dispatched event is folded into a rolling trace digest, so re-running
//! the same config reproduces a byte-identical trace and byte-identical final
//! per-node state roots.
//!
//! Consensus is driven sequentially, height by height: the view leader
//! proposes, replicas vote, and a height advances only once every honest
//! surviving node has finalized it. View-change timeouts provide leader
//! failover; periodic retransmission provides liveness under loss and across a
//! healed partition.

use std::collections::BTreeMap;

use consensus::CheckpointHeader;
use crypto::{hash_leaf, hash_node, Validator};
use types::Hash;

use crate::node::{Behavior, Envelope, Node, NodeId, Outgoing, Payload, Target};
use crate::oracle::{Divergence, StateRootOracle};
use crate::rng::SimRng;
use crate::scheduler::{Scheduler, Time};
use crate::transport::{LinkFaults, Transport, TransportStats};

/// A fatal configuration error (never a panic path).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SimError {
    /// The committee could not be constructed (empty or too large).
    #[error("invalid committee: {0}")]
    Committee(String),
}

/// A scheduled cluster event.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SimEvent {
    ProposeKick { height: u64, view: u64 },
    // Boxed: an `Envelope` carries a `Proposal`, keeping the other (tiny)
    // variants from bloating the whole enum.
    Deliver { env: Box<Envelope> },
    Timeout { height: u64, view: u64 },
    Retransmit { height: u64 },
    Crash { node: NodeId },
    Restart { node: NodeId },
    Heal,
}

/// A full scenario description.
#[derive(Debug, Clone)]
pub struct SimConfig {
    /// Number of nodes / validators.
    pub num_nodes: u32,
    /// Number of consensus heights to drive.
    pub heights: u64,
    /// Master seed for all randomness.
    pub seed: u64,
    /// Per-link fault configuration.
    pub faults: LinkFaults,
    /// View-change timeout in logical ns.
    pub round_timeout_ns: u64,
    /// Retransmission interval in logical ns.
    pub retransmit_interval_ns: u64,
    /// Gap between finalizing a height and kicking the next.
    pub height_gap_ns: u64,
    /// Hard cap on logical time; the run stops past it.
    pub max_time_ns: u64,
    /// Hard cap on dispatched events (belt-and-suspenders termination).
    pub max_steps: u64,
    /// Non-honest node behaviors.
    pub behaviors: Vec<(NodeId, Behavior)>,
    /// Crash events: `(node, at_time)`.
    pub crashes: Vec<(NodeId, Time)>,
    /// Restart events: `(node, at_time)`.
    pub restarts: Vec<(NodeId, Time)>,
    /// Optional partition group assignment (one entry per node).
    pub partition: Option<Vec<u32>>,
    /// Optional time to heal the partition.
    pub heal_time_ns: Option<Time>,
    /// Per-node additive send skew (clock drift), ns.
    pub clock_skews: Vec<(NodeId, u64)>,
}

impl SimConfig {
    /// A clean scenario: `n` honest nodes, `heights` heights, small latency.
    #[must_use]
    pub fn clean(num_nodes: u32, heights: u64, seed: u64) -> Self {
        Self {
            num_nodes,
            heights,
            seed,
            faults: LinkFaults::latent(1_000, 500),
            // Timeout is deliberately far larger than the retransmit interval:
            // transient loss is repaired by retransmission long before a view
            // change would fire, so only a genuinely silent leader triggers
            // failover.
            round_timeout_ns: 5_000_000,
            retransmit_interval_ns: 200_000,
            height_gap_ns: 10_000,
            max_time_ns: 60_000_000_000,
            max_steps: 5_000_000,
            behaviors: Vec::new(),
            crashes: Vec::new(),
            restarts: Vec::new(),
            partition: None,
            heal_time_ns: None,
            clock_skews: Vec::new(),
        }
    }

    fn max_views(&self) -> u64 {
        u64::from(self.num_nodes).saturating_mul(3).max(3)
    }
}

/// The outcome of a run.
#[derive(Debug, Clone)]
pub struct SimResult {
    /// Rolling digest over every dispatched event.
    pub trace_digest: Hash,
    /// Finalized state root of each honest surviving node.
    pub survivor_roots: Vec<(NodeId, Hash)>,
    /// Finalized-height count of each honest surviving node.
    pub survivor_finalized: Vec<(NodeId, u64)>,
    /// Checkpoint headers of each honest surviving node.
    pub survivor_checkpoints: Vec<(NodeId, Vec<CheckpointHeader>)>,
    /// Maximum forks detected by any node.
    pub forks_detected: u64,
    /// Maximum vote equivocations detected by any node.
    pub equivocations_detected: u64,
    /// Measured logical failover time, if any height needed a view change.
    pub failover_time_ns: Option<u64>,
    /// Per-height finality latency in logical ns.
    pub finality_latencies_ns: Vec<u64>,
    /// Number of heights that reached honest-wide finality.
    pub heights_completed: u64,
    /// Number of events dispatched.
    pub steps: u64,
    /// Final transport accounting.
    pub transport: TransportStats,
}

impl SimResult {
    /// Assert that every honest surviving node agrees on the finalized root.
    ///
    /// # Errors
    /// Returns a [`Divergence`] if the survivors disagree or none survived.
    pub fn agree(&self) -> Result<Hash, Divergence> {
        StateRootOracle::agree(&self.survivor_roots)
    }

    /// Whether every honest surviving node finalized all `heights`.
    #[must_use]
    pub fn all_finalized(&self, heights: u64) -> bool {
        !self.survivor_finalized.is_empty()
            && self.survivor_finalized.iter().all(|&(_, c)| c >= heights)
    }

    /// Integer p95 of finality latency (no floating point).
    #[must_use]
    pub fn p95_finality_ns(&self) -> Option<u64> {
        percentile(&self.finality_latencies_ns, 95)
    }
}

/// Deterministic integer percentile: `pct` in `[0, 100]`.
#[must_use]
pub fn percentile(samples: &[u64], pct: u64) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    // rank = ceil(pct/100 * n) - 1, clamped to [0, n-1].
    let rank = pct
        .saturating_mul(u64::try_from(n).unwrap_or(u64::MAX))
        .div_ceil(100)
        .max(1)
        - 1;
    let idx = usize::try_from(rank).unwrap_or(n - 1).min(n - 1);
    Some(sorted[idx])
}

/// The cluster runtime.
pub struct Cluster {
    config: SimConfig,
    rng: SimRng,
    scheduler: Scheduler<SimEvent>,
    transport: Transport,
    nodes: Vec<Node>,
    honest: Vec<bool>,
    // Per-height bookkeeping (indexed by height; index 0 unused).
    propose_time: Vec<u64>,
    done: Vec<bool>,
    needed_failover: Vec<bool>,
    active_height: u64,
    // Results-in-progress.
    trace_state: Hash,
    finality_latencies: Vec<u64>,
    failover_time: Option<u64>,
    heights_completed: u64,
}

fn idx(id: NodeId) -> usize {
    usize::try_from(id).unwrap_or(usize::MAX)
}

/// Height/index conversion for the per-height bookkeeping vectors.
fn hidx(height: u64) -> usize {
    usize::try_from(height).unwrap_or(usize::MAX)
}

impl Cluster {
    /// Run a scenario to completion and return its result.
    ///
    /// # Errors
    /// Returns [`SimError`] only if the committee is malformed.
    pub fn run(config: SimConfig) -> Result<SimResult, SimError> {
        let mut cluster = Self::build(config)?;
        cluster.drive();
        Ok(cluster.gather())
    }

    fn build(config: SimConfig) -> Result<Self, SimError> {
        let n = config.num_nodes;
        let mut behavior_map: BTreeMap<NodeId, Behavior> = BTreeMap::new();
        for &(id, b) in &config.behaviors {
            behavior_map.insert(id, b);
        }

        // Deterministic keys + validators.
        let mut validators = Vec::new();
        let mut seeds = Vec::new();
        for i in 0..n {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&i.to_le_bytes());
            let kp = crypto::KeyPair::from_seed(&seed);
            validators.push(Validator {
                public_key: kp.public(),
                weight: 1,
            });
            seeds.push(seed);
        }
        let committee = consensus::Committee::new_bft(0, validators)
            .map_err(|e| SimError::Committee(format!("{e:?}")))?;

        let mut nodes = Vec::new();
        let mut honest = Vec::new();
        for i in 0..n {
            let behavior = behavior_map.get(&i).copied().unwrap_or(Behavior::Honest);
            honest.push(behavior == Behavior::Honest);
            nodes.push(Node::new(i, &seeds[idx(i)], committee.clone(), behavior));
        }

        let mut transport = Transport::new(config.faults);
        if let Some(groups) = &config.partition {
            transport.partition(groups.clone());
        }
        let mut skews = vec![0u64; idx(n)];
        for &(id, s) in &config.clock_skews {
            if let Some(slot) = skews.get_mut(idx(id)) {
                *slot = s;
            }
        }
        transport.set_skew(skews);

        let hlen = usize::try_from(config.heights.saturating_add(1)).unwrap_or(usize::MAX);
        Ok(Self {
            rng: SimRng::new(config.seed),
            scheduler: Scheduler::new(),
            transport,
            nodes,
            honest,
            propose_time: vec![0; hlen],
            done: vec![false; hlen],
            needed_failover: vec![false; hlen],
            active_height: 1,
            trace_state: Hash::ZERO,
            finality_latencies: Vec::new(),
            failover_time: None,
            heights_completed: 0,
            config,
        })
    }

    fn drive(&mut self) {
        // Seed lifecycle events.
        for (node, at) in self.config.crashes.clone() {
            self.scheduler.schedule_at(at, SimEvent::Crash { node });
        }
        for (node, at) in self.config.restarts.clone() {
            self.scheduler.schedule_at(at, SimEvent::Restart { node });
        }
        if let Some(at) = self.config.heal_time_ns {
            self.scheduler.schedule_at(at, SimEvent::Heal);
        }
        if self.config.heights >= 1 {
            self.start_height(1, 0);
        }

        let max_time = self.config.max_time_ns;
        let max_steps = self.config.max_steps;
        let mut steps: u64 = 0;
        while let Some(d) = self.scheduler.pop() {
            if d.time > max_time {
                break;
            }
            steps += 1;
            self.absorb_trace(d.time, d.tie_break, &d.event);
            self.dispatch(d.time, d.event);
            if steps >= max_steps {
                break;
            }
        }
    }

    fn start_height(&mut self, height: u64, at: Time) {
        if height > self.config.heights {
            return;
        }
        self.scheduler
            .schedule_at(at, SimEvent::ProposeKick { height, view: 0 });
        self.scheduler.schedule_at(
            at.saturating_add(self.config.round_timeout_ns),
            SimEvent::Timeout { height, view: 0 },
        );
        self.scheduler.schedule_at(
            at.saturating_add(self.config.retransmit_interval_ns),
            SimEvent::Retransmit { height },
        );
    }

    fn dispatch(&mut self, now: Time, event: SimEvent) {
        match event {
            SimEvent::ProposeKick { height, view } => self.on_propose_kick(height, view, now),
            SimEvent::Deliver { env } => self.on_deliver(env, now),
            SimEvent::Timeout { height, view } => self.on_timeout(height, view, now),
            SimEvent::Retransmit { height } => self.on_retransmit(height, now),
            SimEvent::Crash { node } => {
                if let Some(n) = self.nodes.get_mut(idx(node)) {
                    n.crash();
                }
                self.check_and_advance(now);
            }
            SimEvent::Restart { node } => {
                let snapshot = self.survivor_snapshot(node);
                if let Some(n) = self.nodes.get_mut(idx(node)) {
                    n.restart_and_sync(&snapshot);
                }
                self.check_and_advance(now);
            }
            SimEvent::Heal => self.transport.heal(),
        }
    }

    fn on_propose_kick(&mut self, height: u64, view: u64, now: Time) {
        let hi = hidx(height);
        if height > self.config.heights || self.done.get(hi).copied().unwrap_or(true) {
            return;
        }
        if view == 0 {
            if let Some(slot) = self.propose_time.get_mut(hi) {
                if *slot == 0 {
                    *slot = now;
                }
            }
        } else if let Some(slot) = self.needed_failover.get_mut(hi) {
            *slot = true;
        }
        let leader = self.leader_for(view);
        let out = self
            .nodes
            .get_mut(idx(leader))
            .map(|n| n.propose(height, view))
            .unwrap_or_default();
        self.route_all(leader, out, now);
        self.check_and_advance(now);
    }

    fn leader_for(&self, view: u64) -> NodeId {
        self.nodes
            .first()
            .map(|n| n_committee_leader(n, view))
            .unwrap_or(0)
    }

    fn on_deliver(&mut self, env: Box<Envelope>, now: Time) {
        let to = env.to;
        let out = self
            .nodes
            .get_mut(idx(to))
            .map(|n| n.handle(&env, now))
            .unwrap_or_default();
        self.route_all(to, out, now);
        self.check_and_advance(now);
    }

    fn on_timeout(&mut self, height: u64, view: u64, now: Time) {
        let hi = hidx(height);
        if height > self.config.heights || self.done.get(hi).copied().unwrap_or(true) {
            return;
        }
        let next = view + 1;
        if next <= self.config.max_views() {
            self.scheduler
                .schedule_at(now, SimEvent::ProposeKick { height, view: next });
            self.scheduler.schedule_at(
                now.saturating_add(self.config.round_timeout_ns),
                SimEvent::Timeout { height, view: next },
            );
        }
    }

    fn on_retransmit(&mut self, height: u64, now: Time) {
        let hi = hidx(height);
        if height > self.config.heights
            || self.done.get(hi).copied().unwrap_or(true)
            || now >= self.config.max_time_ns
        {
            return;
        }
        // Collect each node's gossip first (mutable borrow of `nodes`), then
        // route (mutable borrow of `self`) — avoids overlapping borrows.
        let batch: Vec<(NodeId, Vec<Outgoing>)> = self
            .nodes
            .iter_mut()
            .map(|node| (node.id(), node.retransmit(height)))
            .collect();
        for (from, out) in batch {
            if !out.is_empty() {
                self.route_all(from, out, now);
            }
        }
        self.scheduler.schedule_at(
            now.saturating_add(self.config.retransmit_interval_ns),
            SimEvent::Retransmit { height },
        );
        self.check_and_advance(now);
    }

    fn route_all(&mut self, from: NodeId, out: Vec<Outgoing>, now: Time) {
        for o in out {
            match o.target {
                Target::Broadcast => {
                    let n = u32::try_from(self.nodes.len()).unwrap_or(u32::MAX);
                    for to in 0..n {
                        self.route_one(from, to, o.payload.clone(), now);
                    }
                }
                Target::To(to) => self.route_one(from, to, o.payload.clone(), now),
            }
        }
    }

    fn route_one(&mut self, from: NodeId, to: NodeId, payload: Payload, now: Time) {
        match self.transport.route(from, to, now, &mut self.rng) {
            crate::transport::Routing::Dropped => {}
            crate::transport::Routing::Deliver(times) => {
                for t in times {
                    let env = Box::new(Envelope {
                        from,
                        to,
                        payload: payload.clone(),
                    });
                    self.scheduler.schedule_at(t, SimEvent::Deliver { env });
                }
            }
        }
    }

    /// Advance to the next height once the current one is honest-wide final.
    fn check_and_advance(&mut self, now: Time) {
        let h = self.active_height;
        if h == 0 || h > self.config.heights {
            return;
        }
        let hi = hidx(h);
        if self.done.get(hi).copied().unwrap_or(true) {
            return;
        }
        if !self.height_complete(h) {
            return;
        }
        if let Some(slot) = self.done.get_mut(hi) {
            *slot = true;
        }
        self.heights_completed += 1;
        let started = self.propose_time.get(hi).copied().unwrap_or(now);
        let latency = now.saturating_sub(started);
        self.finality_latencies.push(latency);
        if self.needed_failover.get(hi).copied().unwrap_or(false) && self.failover_time.is_none() {
            self.failover_time = Some(latency);
        }
        self.active_height = h + 1;
        if h < self.config.heights {
            let at = now.saturating_add(self.config.height_gap_ns);
            self.start_height(h + 1, at);
        }
    }

    fn height_complete(&self, height: u64) -> bool {
        let mut any = false;
        for (i, node) in self.nodes.iter().enumerate() {
            if !self.honest.get(i).copied().unwrap_or(false) {
                continue;
            }
            if node.is_crashed() {
                continue;
            }
            any = true;
            if !node.has_finalized(height) {
                return false;
            }
        }
        any
    }

    fn survivor_snapshot(&self, exclude: NodeId) -> Vec<(u64, Hash, u64)> {
        for (i, node) in self.nodes.iter().enumerate() {
            if node.id() == exclude {
                continue;
            }
            if self.honest.get(i).copied().unwrap_or(false) && !node.is_crashed() {
                return node.durable_snapshot();
            }
        }
        Vec::new()
    }

    fn absorb_trace(&mut self, time: Time, tie: u64, event: &SimEvent) {
        let (tag, a, b, digest): (u8, u64, u64, [u8; 32]) = match event {
            SimEvent::ProposeKick { height, view } => (1, *height, *view, [0u8; 32]),
            SimEvent::Deliver { env } => {
                let d = match &env.payload {
                    Payload::Proposal(p) => *p.digest().as_bytes(),
                    Payload::Vote(v) => *v.digest().as_bytes(),
                };
                (2, u64::from(env.from), u64::from(env.to), d)
            }
            SimEvent::Timeout { height, view } => (3, *height, *view, [0u8; 32]),
            SimEvent::Retransmit { height } => (4, *height, 0, [0u8; 32]),
            SimEvent::Crash { node } => (5, u64::from(*node), 0, [0u8; 32]),
            SimEvent::Restart { node } => (6, u64::from(*node), 0, [0u8; 32]),
            SimEvent::Heal => (7, 0, 0, [0u8; 32]),
        };
        let mut buf = Vec::with_capacity(8 + 8 + 1 + 8 + 8 + 32);
        buf.extend_from_slice(&time.to_le_bytes());
        buf.extend_from_slice(&tie.to_le_bytes());
        buf.push(tag);
        buf.extend_from_slice(&a.to_le_bytes());
        buf.extend_from_slice(&b.to_le_bytes());
        buf.extend_from_slice(&digest);
        self.trace_state = hash_node(self.trace_state, hash_leaf(&buf));
    }

    fn gather(&self) -> SimResult {
        let mut survivor_roots = Vec::new();
        let mut survivor_finalized = Vec::new();
        let mut survivor_checkpoints = Vec::new();
        let mut forks = 0u64;
        let mut equivs = 0u64;
        for (i, node) in self.nodes.iter().enumerate() {
            forks = forks.max(u64::try_from(node.forks_detected()).unwrap_or(u64::MAX));
            equivs = equivs.max(u64::try_from(node.equivocations_detected()).unwrap_or(u64::MAX));
            if self.honest.get(i).copied().unwrap_or(false) && !node.is_crashed() {
                survivor_roots.push((node.id(), node.state_root()));
                survivor_finalized.push((node.id(), node.finalized_count()));
                survivor_checkpoints.push((node.id(), node.checkpoints().to_vec()));
            }
        }
        SimResult {
            trace_digest: self.trace_state,
            survivor_roots,
            survivor_finalized,
            survivor_checkpoints,
            forks_detected: forks,
            equivocations_detected: equivs,
            failover_time_ns: self.failover_time,
            finality_latencies_ns: self.finality_latencies.clone(),
            heights_completed: self.heights_completed,
            steps: self.scheduler.dispatched_count(),
            transport: self.transport.stats(),
        }
    }
}

fn n_committee_leader(node: &Node, view: u64) -> NodeId {
    node.leader_for_view(view)
}

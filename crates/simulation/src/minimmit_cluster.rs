//! Deterministic Minimmit cluster driver.

use std::collections::BTreeMap;

use consensus::CheckpointHeader;
use crypto::{hash_leaf, hash_node, Validator};
use types::Hash;

use crate::node::{Behavior, Envelope, Node, NodeAction, NodeId, Outgoing, Payload, Target};
use crate::oracle::{Divergence, StateRootOracle};
use crate::rng::SimRng;
use crate::scheduler::{Scheduler, Time};
use crate::transport::{LinkFaults, Routing, Transport, TransportStats};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SimError {
    #[error("invalid Minimmit committee: {0}")]
    Committee(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SimEvent {
    Deliver {
        env: Box<Envelope>,
    },
    Retry {
        from: NodeId,
        outgoing: Box<Outgoing>,
    },
    Timer {
        node: NodeId,
        view: u64,
    },
    Tick {
        node: NodeId,
    },
    Crash {
        node: NodeId,
    },
    Restart {
        node: NodeId,
    },
    Heal,
}

#[derive(Debug, Clone)]
pub struct SimConfig {
    pub num_nodes: u32,
    pub heights: u64,
    pub seed: u64,
    pub faults: LinkFaults,
    /// Minimmit's node-owned 2Δ timer in logical nanoseconds.
    pub round_timeout_ns: u64,
    /// Periodic R7 tick cadence.
    pub retransmit_interval_ns: u64,
    pub height_gap_ns: u64,
    pub max_time_ns: u64,
    pub max_steps: u64,
    pub behaviors: Vec<(NodeId, Behavior)>,
    pub crashes: Vec<(NodeId, Time)>,
    pub restarts: Vec<(NodeId, Time)>,
    pub partition: Option<Vec<u32>>,
    pub heal_time_ns: Option<Time>,
    pub clock_skews: Vec<(NodeId, u64)>,
}

impl SimConfig {
    #[must_use]
    pub fn clean(num_nodes: u32, heights: u64, seed: u64) -> Self {
        Self {
            num_nodes,
            heights,
            seed,
            faults: LinkFaults::latent(1_000, 250),
            round_timeout_ns: 2_000_000,
            retransmit_interval_ns: 200_000,
            height_gap_ns: 0,
            max_time_ns: 60_000_000_000,
            max_steps: 200_000,
            behaviors: Vec::new(),
            crashes: Vec::new(),
            restarts: Vec::new(),
            partition: None,
            heal_time_ns: None,
            clock_skews: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SimResult {
    pub trace_digest: Hash,
    pub survivor_roots: Vec<(NodeId, Hash)>,
    pub survivor_finalized: Vec<(NodeId, u64)>,
    pub survivor_checkpoints: Vec<(NodeId, Vec<CheckpointHeader>)>,
    pub forks_detected: u64,
    pub equivocations_detected: u64,
    pub failover_time_ns: Option<u64>,
    pub finality_latencies_ns: Vec<u64>,
    pub heights_completed: u64,
    pub steps: u64,
    pub transport: TransportStats,
}

impl SimResult {
    pub fn agree(&self) -> Result<Hash, Divergence> {
        StateRootOracle::agree(&self.survivor_roots)
    }

    #[must_use]
    pub fn all_finalized(&self, heights: u64) -> bool {
        !self.survivor_finalized.is_empty()
            && self
                .survivor_finalized
                .iter()
                .all(|&(_, count)| count >= heights)
    }

    #[must_use]
    pub fn p95_finality_ns(&self) -> Option<u64> {
        percentile(&self.finality_latencies_ns, 95)
    }
}

#[must_use]
pub fn percentile(samples: &[u64], pct: u64) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = pct
        .saturating_mul(u64::try_from(sorted.len()).unwrap_or(u64::MAX))
        .div_ceil(100)
        .max(1)
        - 1;
    sorted.get(usize::try_from(rank).ok()?).copied()
}

pub struct Cluster {
    config: SimConfig,
    rng: SimRng,
    scheduler: Scheduler<SimEvent>,
    transport: Transport,
    nodes: Vec<Node>,
    honest: Vec<bool>,
    trace_state: Hash,
    first_finalized_at: Vec<Option<u64>>,
    started_at: u64,
    failover: bool,
}

fn idx(id: NodeId) -> usize {
    usize::try_from(id).unwrap_or(usize::MAX)
}

impl Cluster {
    pub fn run(config: SimConfig) -> Result<SimResult, SimError> {
        let mut cluster = Self::build(config)?;
        cluster.drive();
        Ok(cluster.gather())
    }

    fn build(config: SimConfig) -> Result<Self, SimError> {
        if config.num_nodes < 6 || config.num_nodes > 16 {
            return Err(SimError::Committee(format!(
                "Minimmit requires 6..=16 validators, got {}",
                config.num_nodes
            )));
        }
        let mut behavior_map = BTreeMap::new();
        for &(node, behavior) in &config.behaviors {
            behavior_map.insert(node, behavior);
        }
        let mut validators = Vec::new();
        let mut seeds = Vec::new();
        for index in 0..config.num_nodes {
            let mut seed = [0u8; 32];
            seed[..4].copy_from_slice(&index.to_le_bytes());
            let keypair = crypto::KeyPair::from_seed(&seed);
            validators.push(Validator {
                public_key: keypair.public(),
                weight: 1,
            });
            seeds.push(seed);
        }
        let committee = consensus::MinimmitCommittee::new_unit(0, validators)
            .map_err(|error| SimError::Committee(error.to_string()))?;
        let genesis = Hash::ZERO;
        let mut nodes = Vec::new();
        let mut honest = Vec::new();
        let mut initial_actions = Vec::new();
        for index in 0..config.num_nodes {
            let behavior = behavior_map
                .get(&index)
                .copied()
                .unwrap_or(Behavior::Honest);
            honest.push(behavior == Behavior::Honest);
            let index16 = u16::try_from(index)
                .map_err(|_| SimError::Committee("validator index overflow".into()))?;
            let (node, actions) = Node::new(
                index16,
                &seeds[idx(index)],
                committee.clone(),
                behavior,
                genesis,
                config.heights,
            )
            .map_err(|error| SimError::Committee(error.to_string()))?;
            nodes.push(node);
            initial_actions.push((index, actions));
        }
        let mut transport = Transport::new(config.faults);
        if let Some(groups) = &config.partition {
            if groups.len() != idx(config.num_nodes) {
                return Err(SimError::Committee(
                    "partition size does not match committee".into(),
                ));
            }
            transport.partition(groups.clone());
        }
        let mut skew = vec![0; idx(config.num_nodes)];
        for &(node, value) in &config.clock_skews {
            if let Some(slot) = skew.get_mut(idx(node)) {
                *slot = value;
            }
        }
        transport.set_skew(skew);
        let mut cluster = Self {
            first_finalized_at: vec![None; usize::try_from(config.heights + 1).unwrap_or(0)],
            started_at: 0,
            failover: false,
            rng: SimRng::new(config.seed),
            scheduler: Scheduler::new(),
            transport,
            nodes,
            honest,
            trace_state: Hash::ZERO,
            config,
        };
        for (node, actions) in initial_actions {
            let crashes_at_boot = cluster
                .config
                .crashes
                .iter()
                .any(|&(crashed, at)| crashed == node && at == 0);
            if !crashes_at_boot {
                cluster.apply_actions(node, actions, 0);
            }
        }
        Ok(cluster)
    }

    fn drive(&mut self) {
        for (node, at) in self.config.crashes.clone() {
            self.scheduler.schedule_at(at, SimEvent::Crash { node });
        }
        for (node, at) in self.config.restarts.clone() {
            self.scheduler.schedule_at(at, SimEvent::Restart { node });
        }
        if let Some(at) = self.config.heal_time_ns {
            self.scheduler.schedule_at(at, SimEvent::Heal);
        }
        for node in 0..self.config.num_nodes {
            self.scheduler
                .schedule_at(self.config.retransmit_interval_ns, SimEvent::Tick { node });
        }
        let mut steps = 0u64;
        while let Some(dispatched) = self.scheduler.pop() {
            if dispatched.time > self.config.max_time_ns || steps >= self.config.max_steps {
                break;
            }
            steps += 1;
            self.absorb_trace(dispatched.time, dispatched.tie_break, &dispatched.event);
            self.dispatch(dispatched.time, dispatched.event);
            self.record_progress(dispatched.time);
            if self.all_honest_complete() {
                break;
            }
        }
    }

    fn dispatch(&mut self, now: u64, event: SimEvent) {
        match event {
            SimEvent::Deliver { env } => {
                let node = env.to;
                let actions = self
                    .nodes
                    .get_mut(idx(node))
                    .map(|target| target.handle(&env, now))
                    .unwrap_or_default();
                self.apply_actions(node, actions, now);
            }
            SimEvent::Retry { from, outgoing } => {
                self.route_without_retry(from, *outgoing, now);
            }
            SimEvent::Timer { node, view } => {
                self.failover = true;
                let actions = self
                    .nodes
                    .get_mut(idx(node))
                    .map(|target| target.timer_fired(view, now))
                    .unwrap_or_default();
                self.apply_actions(node, actions, now);
            }
            SimEvent::Tick { node } => {
                let actions = self
                    .nodes
                    .get_mut(idx(node))
                    .map(|target| target.tick(now))
                    .unwrap_or_default();
                self.apply_actions(node, actions, now);
                self.scheduler.schedule_at(
                    now.saturating_add(self.config.retransmit_interval_ns),
                    SimEvent::Tick { node },
                );
            }
            SimEvent::Crash { node } => {
                if let Some(target) = self.nodes.get_mut(idx(node)) {
                    target.crash();
                }
            }
            SimEvent::Restart { node } => {
                let snapshot = self.survivor_snapshot(node);
                if let Some(target) = self.nodes.get_mut(idx(node)) {
                    target.restart_and_sync(&snapshot);
                }
            }
            SimEvent::Heal => self.transport.heal(),
        }
    }

    fn apply_actions(&mut self, from: NodeId, actions: Vec<NodeAction>, now: u64) {
        for action in actions {
            match action {
                NodeAction::Send(outgoing) => self.route_outgoing(from, *outgoing, now),
                NodeAction::ArmTimer { view } => {
                    self.scheduler.schedule_at(
                        now.saturating_add(self.config.round_timeout_ns),
                        SimEvent::Timer { node: from, view },
                    );
                }
                NodeAction::CancelTimer { .. } => {
                    // Stale timer events are intentionally harmless reactor
                    // inputs, so the deterministic scheduler need not delete.
                }
            }
        }
    }

    fn route_outgoing(&mut self, from: NodeId, outgoing: Outgoing, now: u64) {
        self.scheduler.schedule_at(
            now.saturating_add(self.config.retransmit_interval_ns / 2),
            SimEvent::Retry {
                from,
                outgoing: Box::new(outgoing.clone()),
            },
        );
        self.route_without_retry(from, outgoing, now);
    }

    fn route_without_retry(&mut self, from: NodeId, outgoing: Outgoing, now: u64) {
        match outgoing.target {
            Target::Broadcast => {
                for to in 0..self.config.num_nodes {
                    self.route_one(from, to, outgoing.payload.clone(), now);
                }
            }
            Target::To(to) => self.route_one(from, to, outgoing.payload, now),
        }
    }

    fn route_one(&mut self, from: NodeId, to: NodeId, payload: Payload, now: u64) {
        if let Routing::Deliver(times) = self.transport.route(from, to, now, &mut self.rng) {
            for at in times {
                self.scheduler.schedule_at(
                    at,
                    SimEvent::Deliver {
                        env: Box::new(Envelope {
                            from,
                            to,
                            payload: payload.clone(),
                        }),
                    },
                );
            }
        }
    }

    fn record_progress(&mut self, now: u64) {
        for height in 1..=self.config.heights {
            let slot = usize::try_from(height).unwrap_or(usize::MAX);
            if self
                .first_finalized_at
                .get(slot)
                .is_some_and(Option::is_some)
            {
                continue;
            }
            if self.height_complete(height) {
                if let Some(value) = self.first_finalized_at.get_mut(slot) {
                    *value = Some(now);
                }
            }
        }
    }

    fn height_complete(&self, height: u64) -> bool {
        let mut any = false;
        for (index, node) in self.nodes.iter().enumerate() {
            if !self.honest.get(index).copied().unwrap_or(false) || node.is_crashed() {
                continue;
            }
            any = true;
            if !node.has_finalized(height) {
                return false;
            }
        }
        any
    }

    fn all_honest_complete(&self) -> bool {
        (1..=self.config.heights).all(|height| self.height_complete(height))
    }

    fn survivor_snapshot(&self, exclude: NodeId) -> Vec<(u64, Hash, u64)> {
        self.nodes
            .iter()
            .enumerate()
            .find(|(index, node)| {
                node.id() != exclude
                    && self.honest.get(*index).copied().unwrap_or(false)
                    && !node.is_crashed()
            })
            .map_or_else(Vec::new, |(_, node)| node.durable_snapshot())
    }

    fn absorb_trace(&mut self, time: u64, tie: u64, event: &SimEvent) {
        let (tag, a, b, digest) = match event {
            SimEvent::Deliver { env } => (
                1u8,
                u64::from(env.from),
                u64::from(env.to),
                env.payload.digest(),
            ),
            SimEvent::Retry { from, outgoing } => {
                (2, u64::from(*from), 0, outgoing.payload.digest())
            }
            SimEvent::Timer { node, view } => (3, u64::from(*node), *view, Hash::ZERO),
            SimEvent::Tick { node } => (4, u64::from(*node), 0, Hash::ZERO),
            SimEvent::Crash { node } => (5, u64::from(*node), 0, Hash::ZERO),
            SimEvent::Restart { node } => (6, u64::from(*node), 0, Hash::ZERO),
            SimEvent::Heal => (7, 0, 0, Hash::ZERO),
        };
        let mut bytes = Vec::with_capacity(57);
        bytes.extend_from_slice(&time.to_le_bytes());
        bytes.extend_from_slice(&tie.to_le_bytes());
        bytes.push(tag);
        bytes.extend_from_slice(&a.to_le_bytes());
        bytes.extend_from_slice(&b.to_le_bytes());
        bytes.extend_from_slice(digest.as_bytes());
        self.trace_state = hash_node(self.trace_state, hash_leaf(&bytes));
    }

    fn gather(&self) -> SimResult {
        let mut survivor_roots = Vec::new();
        let mut survivor_finalized = Vec::new();
        let mut survivor_checkpoints = Vec::new();
        let mut forks = 0u64;
        let mut equivocations = 0u64;
        for (index, node) in self.nodes.iter().enumerate() {
            forks = forks.max(u64::try_from(node.forks_detected()).unwrap_or(u64::MAX));
            equivocations =
                equivocations.max(u64::try_from(node.equivocations_detected()).unwrap_or(u64::MAX));
            if self.honest.get(index).copied().unwrap_or(false) && !node.is_crashed() {
                survivor_roots.push((node.id(), node.state_root()));
                survivor_finalized.push((node.id(), node.finalized_count()));
                survivor_checkpoints.push((node.id(), node.checkpoints().to_vec()));
            }
        }
        let latencies: Vec<u64> = self
            .first_finalized_at
            .iter()
            .skip(1)
            .filter_map(|value| value.map(|at| at.saturating_sub(self.started_at)))
            .collect();
        SimResult {
            trace_digest: self.trace_state,
            survivor_roots,
            survivor_finalized,
            survivor_checkpoints,
            forks_detected: forks,
            equivocations_detected: equivocations,
            failover_time_ns: self
                .failover
                .then(|| latencies.first().copied().unwrap_or(0)),
            finality_latencies_ns: latencies.clone(),
            heights_completed: u64::try_from(latencies.len()).unwrap_or(u64::MAX),
            steps: self.scheduler.dispatched_count(),
            transport: self.transport.stats(),
        }
    }
}

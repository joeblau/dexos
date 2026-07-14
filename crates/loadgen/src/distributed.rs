//! Deterministic distributed controller/agent planning and aggregation.
//!
//! This module contains no target data-plane I/O: agents connect directly to their
//! assigned validators or reference sinks. The controller allocates collision-free
//! namespaces, authenticates a single-use assignment, tracks heartbeats, and merges
//! compatible raw interval metrics. A missing or failed agent makes qualification
//! fail closed.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::realtime::{IntervalMetrics, MetricsError};

/// Default future-start lead time required for a distributed plan.
pub const MIN_START_LEAD_NS: u64 = 5_000_000_000;

/// Capacity and topology advertised by one validated agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDescriptor {
    /// Stable agent identity, unique within a plan.
    pub id: String,
    /// Region label used in reports and target policy.
    pub region: String,
    /// Maximum sustainable configured operation rate.
    pub max_rate: u64,
    /// Maximum persistent target connections.
    pub max_connections: u32,
    /// Explicit targets this agent permits the controller to assign.
    pub allowed_targets: Vec<String>,
    /// Monotonic controller-observed clock uncertainty in nanoseconds.
    pub clock_uncertainty_ns: u64,
}

impl AgentDescriptor {
    fn validate(&self) -> Result<(), DistributedError> {
        if self.id.is_empty() || self.region.is_empty() {
            return Err(DistributedError::InvalidAgent);
        }
        if self.max_rate == 0 || self.max_connections == 0 || self.allowed_targets.is_empty() {
            return Err(DistributedError::InvalidAgent);
        }
        if self.allowed_targets.iter().any(String::is_empty) {
            return Err(DistributedError::InvalidAgent);
        }
        Ok(())
    }
}

/// Synchronized run phases shared by every assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseSchedule {
    /// Warm-up interval, excluded from headline throughput.
    pub warmup_secs: u64,
    /// Steady interval included in headline throughput.
    pub steady_secs: u64,
    /// Maximum time to wait for all written requests to become terminal.
    pub drain_secs: u64,
    /// Cool-down interval after drain.
    pub cooldown_secs: u64,
}

impl Default for PhaseSchedule {
    fn default() -> Self {
        Self {
            warmup_secs: 30,
            steady_secs: 300,
            drain_secs: 30,
            cooldown_secs: 10,
        }
    }
}

impl PhaseSchedule {
    fn validate(self) -> Result<(), DistributedError> {
        if self.warmup_secs == 0 || self.steady_secs == 0 || self.drain_secs == 0 {
            return Err(DistributedError::InvalidSchedule);
        }
        Ok(())
    }
}

/// Controller input used to deterministically partition a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerPlan {
    /// Unique run identifier. Reusing it is rejected by each agent.
    pub run_id: u128,
    /// Future synchronized UTC start in Unix nanoseconds.
    pub start_unix_ns: u64,
    /// Total open-loop rate to partition exactly.
    pub total_rate: u64,
    /// Total connection count to partition exactly.
    pub total_connections: u32,
    /// First globally unique client identifier assigned to this run.
    pub client_id_base: u64,
    /// Deterministic workload seed.
    pub seed: u64,
    /// Shared phase durations.
    pub phases: PhaseSchedule,
    /// Weighted targets. A target may appear more than once to express weight.
    pub targets: Vec<String>,
}

/// Collision-free work allocated to one agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAssignment {
    /// Run identifier from the controller plan.
    pub run_id: u128,
    /// Agent that alone may consume this assignment.
    pub agent_id: String,
    /// Region copied from the agent descriptor.
    pub region: String,
    /// Future UTC start shared by every agent.
    pub start_unix_ns: u64,
    /// Assigned open-loop rate.
    pub rate: u64,
    /// Assigned persistent connection count.
    pub connections: u32,
    /// Inclusive first client identifier.
    pub client_id_start: u64,
    /// Exclusive client identifier end.
    pub client_id_end: u64,
    /// Upper 32-bit namespace reserved for this assignment's nonces.
    pub nonce_namespace: u32,
    /// Disjoint deterministic RNG stream seed.
    pub rng_seed: u64,
    /// Explicit target subset; never inferred from validator config.
    pub targets: Vec<String>,
    /// Synchronized phase durations.
    pub phases: PhaseSchedule,
    /// SHA-256 digest binding every assignment field.
    pub digest: [u8; 32],
}

impl AgentAssignment {
    /// Construct a nonce whose high half is unique to this assignment.
    #[must_use]
    pub const fn nonce(&self, local: u32) -> u64 {
        ((self.nonce_namespace as u64) << 32) | local as u64
    }

    /// Recompute and verify the assignment digest.
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        constant_time_eq(&self.digest, &assignment_digest(self))
    }
}

/// Deterministically partition the plan over sorted agents.
pub fn partition_plan(
    plan: &ControllerPlan,
    agents: &[AgentDescriptor],
    now_unix_ns: u64,
) -> Result<Vec<AgentAssignment>, DistributedError> {
    plan.phases.validate()?;
    if agents.is_empty()
        || plan.total_rate == 0
        || plan.total_connections == 0
        || plan.targets.is_empty()
        || plan.start_unix_ns < now_unix_ns.saturating_add(MIN_START_LEAD_NS)
    {
        return Err(DistributedError::InvalidPlan);
    }

    let mut ordered: Vec<&AgentDescriptor> = agents.iter().collect();
    ordered.sort_by(|a, b| a.id.cmp(&b.id));
    let mut ids = BTreeSet::new();
    for agent in &ordered {
        agent.validate()?;
        if !ids.insert(agent.id.as_str()) {
            return Err(DistributedError::DuplicateAgent);
        }
    }

    let count = u64::try_from(ordered.len()).map_err(|_| DistributedError::InvalidPlan)?;
    let base_rate = plan.total_rate / count;
    let rate_remainder = plan.total_rate % count;
    let count_u32 = u32::try_from(ordered.len()).map_err(|_| DistributedError::InvalidPlan)?;
    let base_connections = plan.total_connections / count_u32;
    let connection_remainder = plan.total_connections % count_u32;

    let mut next_client = plan.client_id_base;
    let mut assignments = Vec::with_capacity(ordered.len());
    for (index, agent) in ordered.into_iter().enumerate() {
        let index_u64 = u64::try_from(index).map_err(|_| DistributedError::InvalidPlan)?;
        let index_u32 = u32::try_from(index).map_err(|_| DistributedError::InvalidPlan)?;
        let rate = base_rate + u64::from(index_u64 < rate_remainder);
        let connections = base_connections + u32::from(index_u32 < connection_remainder);
        if rate > agent.max_rate || connections > agent.max_connections {
            return Err(DistributedError::InsufficientCapacity {
                agent_id: agent.id.clone(),
            });
        }
        let client_id_end = next_client
            .checked_add(u64::from(connections))
            .ok_or(DistributedError::IdentityOverflow)?;
        let targets: Vec<String> = plan
            .targets
            .iter()
            .filter(|target| agent.allowed_targets.contains(target))
            .cloned()
            .collect();
        if targets.is_empty() {
            return Err(DistributedError::TargetNotAllowed {
                agent_id: agent.id.clone(),
            });
        }
        let nonce_namespace = namespace32(plan.run_id, &agent.id, b"nonce");
        let rng_seed = namespace64(plan.run_id, &agent.id, plan.seed, b"rng");
        let mut assignment = AgentAssignment {
            run_id: plan.run_id,
            agent_id: agent.id.clone(),
            region: agent.region.clone(),
            start_unix_ns: plan.start_unix_ns,
            rate,
            connections,
            client_id_start: next_client,
            client_id_end,
            nonce_namespace,
            rng_seed,
            targets,
            phases: plan.phases,
            digest: [0; 32],
        };
        assignment.digest = assignment_digest(&assignment);
        assignments.push(assignment);
        next_client = client_id_end;
    }

    let assigned_rate = assignments.iter().try_fold(0u64, |sum, a| {
        sum.checked_add(a.rate)
            .ok_or(DistributedError::IdentityOverflow)
    })?;
    let assigned_connections = assignments.iter().try_fold(0u32, |sum, a| {
        sum.checked_add(a.connections)
            .ok_or(DistributedError::IdentityOverflow)
    })?;
    if assigned_rate != plan.total_rate || assigned_connections != plan.total_connections {
        return Err(DistributedError::PartitionMismatch);
    }
    Ok(assignments)
}

/// HMAC-SHA256 challenge/response for the control plane.
#[derive(Clone)]
pub struct ControlAuthenticator {
    key: Vec<u8>,
}

/// Authenticated assignment envelope transferred on the distributed control plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedAssignment {
    /// Digest-bound assignment.
    pub assignment: AgentAssignment,
    /// Fresh controller challenge; agents reject replayed assignment digests.
    pub challenge: [u8; 32],
    /// HMAC-SHA256 over agent/run/assignment/challenge.
    pub tag: [u8; 32],
}

impl AuthenticatedAssignment {
    /// Bind an assignment to a fresh challenge and control-plane key.
    #[must_use]
    pub fn new(
        assignment: AgentAssignment,
        challenge: [u8; 32],
        authenticator: &ControlAuthenticator,
    ) -> Self {
        let tag = authenticator.tag(
            &assignment.agent_id,
            assignment.run_id,
            &assignment.digest,
            &challenge,
        );
        Self {
            assignment,
            challenge,
            tag,
        }
    }

    /// Verify intended agent, digest, and HMAC before preflight or replay consumption.
    pub fn verify_for(
        &self,
        agent_id: &str,
        authenticator: &ControlAuthenticator,
    ) -> Result<(), DistributedError> {
        if self.assignment.agent_id != agent_id {
            return Err(DistributedError::UnknownAgent);
        }
        if !self.assignment.verify_digest() {
            return Err(DistributedError::AssignmentDigest);
        }
        if !authenticator.verify(
            agent_id,
            self.assignment.run_id,
            &self.assignment.digest,
            &self.challenge,
            &self.tag,
        ) {
            return Err(DistributedError::ControlAuthentication);
        }
        Ok(())
    }
}

impl ControlAuthenticator {
    /// Build an authenticator from a non-empty out-of-band secret.
    pub fn new(key: &[u8]) -> Result<Self, DistributedError> {
        if key.len() < 32 {
            return Err(DistributedError::WeakControlKey);
        }
        Ok(Self { key: key.to_vec() })
    }

    /// Authenticate an agent, run, assignment, and fresh challenge nonce.
    #[must_use]
    pub fn tag(
        &self,
        agent_id: &str,
        run_id: u128,
        assignment_digest: &[u8; 32],
        challenge: &[u8; 32],
    ) -> [u8; 32] {
        let mut message = Vec::with_capacity(agent_id.len() + 16 + 32 + 32);
        message.extend_from_slice(agent_id.as_bytes());
        message.extend_from_slice(&run_id.to_be_bytes());
        message.extend_from_slice(assignment_digest);
        message.extend_from_slice(challenge);
        hmac_sha256(&self.key, &message)
    }

    /// Constant-time verification of a control-plane tag.
    #[must_use]
    pub fn verify(
        &self,
        agent_id: &str,
        run_id: u128,
        assignment_digest: &[u8; 32],
        challenge: &[u8; 32],
        tag: &[u8; 32],
    ) -> bool {
        constant_time_eq(
            tag,
            &self.tag(agent_id, run_id, assignment_digest, challenge),
        )
    }

    /// Bind a completed report digest to the exact authenticated assignment.
    #[must_use]
    pub fn report_tag(&self, assignment: &AgentAssignment, report_sha256: &[u8; 32]) -> [u8; 32] {
        let mut message = Vec::with_capacity(
            b"dexos.loadgen.agent-report.v1".len() + assignment.agent_id.len() + 16 + 32 + 32,
        );
        message.extend_from_slice(b"dexos.loadgen.agent-report.v1");
        message.extend_from_slice(assignment.agent_id.as_bytes());
        message.extend_from_slice(&assignment.run_id.to_be_bytes());
        message.extend_from_slice(&assignment.digest);
        message.extend_from_slice(report_sha256);
        hmac_sha256(&self.key, &message)
    }

    /// Constant-time verification of a completed agent report tag.
    #[must_use]
    pub fn verify_report(
        &self,
        assignment: &AgentAssignment,
        report_sha256: &[u8; 32],
        tag: &[u8; 32],
    ) -> bool {
        constant_time_eq(tag, &self.report_tag(assignment, report_sha256))
    }
}

/// Single-use assignment guard persisted by an agent for its process lifetime.
#[derive(Debug, Default)]
pub struct AssignmentReplayGuard {
    consumed: BTreeSet<[u8; 32]>,
}

impl AssignmentReplayGuard {
    /// Mark a verified assignment consumed before its timed phase starts.
    pub fn consume(&mut self, assignment: &AgentAssignment) -> Result<(), DistributedError> {
        if !assignment.verify_digest() {
            return Err(DistributedError::AssignmentDigest);
        }
        if !self.consumed.insert(assignment.digest) {
            return Err(DistributedError::AssignmentReplay);
        }
        Ok(())
    }
}

/// Agent lifecycle visible to the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentState {
    /// Capacity advertised, assignment not yet accepted.
    Advertised,
    /// Assignment authenticated and preflight passed.
    Ready,
    /// Warm-up phase.
    Warmup,
    /// Headline steady phase.
    Steady,
    /// Waiting for every write to reach a terminal outcome.
    Draining,
    /// Final report received and conserved.
    Complete,
    /// Agent failed and invalidated the aggregate run.
    Failed,
}

/// Heartbeat sent independently from target order traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHeartbeat {
    /// Agent identity.
    pub agent_id: String,
    /// Run identity.
    pub run_id: u128,
    /// Agent lifecycle state.
    pub state: AgentState,
    /// Agent-local monotonic send time.
    pub monotonic_ns: u64,
    /// Agent-observed queue occupancy.
    pub queue_depth: u64,
    /// Whether any bounded capacity is saturated.
    pub saturated: bool,
}

#[derive(Debug, Clone)]
struct AgentProgress {
    assignment_digest: [u8; 32],
    assigned_rate: u64,
    last_heartbeat_controller_ns: u64,
    state: AgentState,
    saturated: bool,
    interval_ordinals: BTreeSet<u64>,
}

/// Fail-closed controller audit state for one distributed run.
#[derive(Debug)]
pub struct ControllerRun {
    run_id: u128,
    heartbeat_timeout_ns: u64,
    agents: BTreeMap<String, AgentProgress>,
    intervals: BTreeMap<u64, IntervalMetrics>,
}

impl ControllerRun {
    /// Register every assignment before agents are allowed to start.
    pub fn new(
        assignments: &[AgentAssignment],
        heartbeat_timeout_ns: u64,
    ) -> Result<Self, DistributedError> {
        let Some(first) = assignments.first() else {
            return Err(DistributedError::InvalidPlan);
        };
        if heartbeat_timeout_ns == 0 {
            return Err(DistributedError::InvalidPlan);
        }
        let mut agents = BTreeMap::new();
        for assignment in assignments {
            if assignment.run_id != first.run_id || !assignment.verify_digest() {
                return Err(DistributedError::AssignmentDigest);
            }
            let progress = AgentProgress {
                assignment_digest: assignment.digest,
                assigned_rate: assignment.rate,
                last_heartbeat_controller_ns: 0,
                state: AgentState::Advertised,
                saturated: false,
                interval_ordinals: BTreeSet::new(),
            };
            if agents
                .insert(assignment.agent_id.clone(), progress)
                .is_some()
            {
                return Err(DistributedError::DuplicateAgent);
            }
        }
        Ok(Self {
            run_id: first.run_id,
            heartbeat_timeout_ns,
            agents,
            intervals: BTreeMap::new(),
        })
    }

    /// Accept an authenticated heartbeat and advance only monotonic states.
    pub fn heartbeat(
        &mut self,
        heartbeat: &AgentHeartbeat,
        received_controller_ns: u64,
    ) -> Result<(), DistributedError> {
        if heartbeat.run_id != self.run_id {
            return Err(DistributedError::WrongRun);
        }
        let progress = self
            .agents
            .get_mut(&heartbeat.agent_id)
            .ok_or(DistributedError::UnknownAgent)?;
        if state_rank(heartbeat.state) < state_rank(progress.state) {
            return Err(DistributedError::StateRegression);
        }
        progress.state = heartbeat.state;
        progress.saturated |= heartbeat.saturated;
        progress.last_heartbeat_controller_ns = received_controller_ns;
        Ok(())
    }

    /// Merge one raw interval delta from an agent exactly once.
    pub fn interval(
        &mut self,
        agent_id: &str,
        ordinal: u64,
        mut metrics: IntervalMetrics,
    ) -> Result<(), DistributedError> {
        let progress = self
            .agents
            .get_mut(agent_id)
            .ok_or(DistributedError::UnknownAgent)?;
        if !progress.interval_ordinals.insert(ordinal) {
            return Err(DistributedError::DuplicateInterval);
        }
        // Agent-local monotonic boundaries cannot be subtracted across hosts. The
        // ordinal defines the controller's logical one-second merge interval.
        metrics.start_ns = ordinal.saturating_mul(1_000_000_000);
        metrics.end_ns = metrics.start_ns.saturating_add(1_000_000_000);
        let counters = metrics.raw_counters()?;
        if counters.offered != progress.assigned_rate {
            return Err(DistributedError::IntervalOfferedMismatch {
                agent_id: agent_id.to_string(),
                expected: progress.assigned_rate,
                actual: counters.offered,
            });
        }
        if u128::from(counters.socket_written).saturating_mul(100)
            < u128::from(progress.assigned_rate).saturating_mul(98)
        {
            return Err(DistributedError::IntervalUnderRate {
                agent_id: agent_id.to_string(),
                expected: progress.assigned_rate,
                actual: counters.socket_written,
            });
        }
        if let Some(aggregate) = self.intervals.get_mut(&ordinal) {
            aggregate.checked_merge(&metrics)?;
        } else {
            self.intervals.insert(ordinal, metrics);
        }
        Ok(())
    }

    /// Validate liveness at a controller-local monotonic instant.
    pub fn check_liveness(&self, controller_now_ns: u64) -> Result<(), DistributedError> {
        for (agent_id, progress) in &self.agents {
            if progress.state == AgentState::Failed {
                return Err(DistributedError::AgentFailed {
                    agent_id: agent_id.clone(),
                });
            }
            if progress.last_heartbeat_controller_ns == 0
                || controller_now_ns.saturating_sub(progress.last_heartbeat_controller_ns)
                    > self.heartbeat_timeout_ns
            {
                return Err(DistributedError::MissingHeartbeat {
                    agent_id: agent_id.clone(),
                });
            }
        }
        Ok(())
    }

    /// Final qualification audit. Every agent and interval must be present.
    pub fn finalize(
        &self,
        expected_steady_intervals: u64,
        controller_now_ns: u64,
    ) -> Result<(), DistributedError> {
        self.check_liveness(controller_now_ns)?;
        if expected_steady_intervals == 0 {
            return Err(DistributedError::MissingInterval);
        }
        for (agent_id, progress) in &self.agents {
            if progress.state != AgentState::Complete {
                return Err(DistributedError::AgentIncomplete {
                    agent_id: agent_id.clone(),
                });
            }
            if progress.saturated {
                return Err(DistributedError::AgentSaturated {
                    agent_id: agent_id.clone(),
                });
            }
            if progress.assignment_digest == [0; 32] {
                return Err(DistributedError::AssignmentDigest);
            }
            for ordinal in 0..expected_steady_intervals {
                if !progress.interval_ordinals.contains(&ordinal) {
                    return Err(DistributedError::MissingInterval);
                }
            }
        }
        for ordinal in 0..expected_steady_intervals {
            let interval = self
                .intervals
                .get(&ordinal)
                .ok_or(DistributedError::MissingInterval)?;
            if interval.metric_overflow != 0 {
                return Err(DistributedError::Metrics(MetricsError::MetricOverflow));
            }
        }
        Ok(())
    }

    /// Controller-side aggregate for a completed logical interval.
    #[must_use]
    pub fn aggregate_interval(&self, ordinal: u64) -> Option<&IntervalMetrics> {
        self.intervals.get(&ordinal)
    }
}

/// Typed distributed control-plane failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DistributedError {
    /// Plan fields are empty, zero, or start too soon.
    #[error("invalid distributed run plan")]
    InvalidPlan,
    /// An advertised agent is missing required capacity/topology.
    #[error("invalid agent descriptor")]
    InvalidAgent,
    /// Agent IDs must be unique.
    #[error("duplicate agent identity")]
    DuplicateAgent,
    /// An agent lacks its allocated rate or connection capacity.
    #[error("agent `{agent_id}` has insufficient advertised capacity")]
    InsufficientCapacity { agent_id: String },
    /// No assigned target is on this agent's allow-list.
    #[error("agent `{agent_id}` does not allow any requested target")]
    TargetNotAllowed { agent_id: String },
    /// Client or connection namespace overflow.
    #[error("identity namespace overflow")]
    IdentityOverflow,
    /// Exact total rate/connection partitioning failed.
    #[error("partition totals do not match the controller plan")]
    PartitionMismatch,
    /// Warm-up, steady, or drain duration is zero.
    #[error("invalid phase schedule")]
    InvalidSchedule,
    /// Control-plane shared key is too weak.
    #[error("control authentication key must contain at least 32 bytes")]
    WeakControlKey,
    /// Control-plane HMAC did not verify.
    #[error("control authentication failed")]
    ControlAuthentication,
    /// Assignment fields do not match their digest.
    #[error("assignment digest mismatch")]
    AssignmentDigest,
    /// Assignment was already consumed by this agent.
    #[error("assignment replay")]
    AssignmentReplay,
    /// Heartbeat references another run.
    #[error("heartbeat references the wrong run")]
    WrongRun,
    /// Agent was not registered in the plan.
    #[error("unknown agent")]
    UnknownAgent,
    /// Agent attempted to move to an earlier state.
    #[error("agent state regressed")]
    StateRegression,
    /// An interval ordinal was reported twice by one agent.
    #[error("duplicate agent interval")]
    DuplicateInterval,
    /// Heartbeat deadline was missed.
    #[error("agent `{agent_id}` missed its heartbeat deadline")]
    MissingHeartbeat { agent_id: String },
    /// Agent explicitly failed.
    #[error("agent `{agent_id}` failed")]
    AgentFailed { agent_id: String },
    /// Agent did not reach complete state.
    #[error("agent `{agent_id}` did not complete")]
    AgentIncomplete { agent_id: String },
    /// Agent saturated a bounded resource.
    #[error("agent `{agent_id}` saturated a bounded resource")]
    AgentSaturated { agent_id: String },
    /// Expected agent interval is absent.
    #[error("one or more agent intervals are missing")]
    MissingInterval,
    /// Scheduled operations for an agent interval do not equal its exact partition.
    #[error("agent `{agent_id}` interval offered mismatch: expected {expected}, got {actual}")]
    IntervalOfferedMismatch {
        agent_id: String,
        expected: u64,
        actual: u64,
    },
    /// One steady interval missed the normative 98% socket-written floor.
    #[error("agent `{agent_id}` interval under rate: expected {expected}, got {actual}")]
    IntervalUnderRate {
        agent_id: String,
        expected: u64,
        actual: u64,
    },
    /// Raw metrics could not be merged or qualified.
    #[error(transparent)]
    Metrics(#[from] MetricsError),
}

fn state_rank(state: AgentState) -> u8 {
    match state {
        AgentState::Advertised => 0,
        AgentState::Ready => 1,
        AgentState::Warmup => 2,
        AgentState::Steady => 3,
        AgentState::Draining => 4,
        AgentState::Complete | AgentState::Failed => 5,
    }
}

fn assignment_digest(assignment: &AgentAssignment) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"dexos.loadgen.assignment.v1");
    h.update(assignment.run_id.to_be_bytes());
    hash_string(&mut h, &assignment.agent_id);
    hash_string(&mut h, &assignment.region);
    h.update(assignment.start_unix_ns.to_be_bytes());
    h.update(assignment.rate.to_be_bytes());
    h.update(assignment.connections.to_be_bytes());
    h.update(assignment.client_id_start.to_be_bytes());
    h.update(assignment.client_id_end.to_be_bytes());
    h.update(assignment.nonce_namespace.to_be_bytes());
    h.update(assignment.rng_seed.to_be_bytes());
    for target in &assignment.targets {
        hash_string(&mut h, target);
    }
    h.update(assignment.phases.warmup_secs.to_be_bytes());
    h.update(assignment.phases.steady_secs.to_be_bytes());
    h.update(assignment.phases.drain_secs.to_be_bytes());
    h.update(assignment.phases.cooldown_secs.to_be_bytes());
    h.finalize().into()
}

fn namespace32(run_id: u128, agent_id: &str, domain: &[u8]) -> u32 {
    let digest = namespace_digest(run_id, agent_id, 0, domain);
    u32::from_be_bytes(digest[..4].try_into().unwrap_or([0; 4]))
}

fn namespace64(run_id: u128, agent_id: &str, seed: u64, domain: &[u8]) -> u64 {
    let digest = namespace_digest(run_id, agent_id, seed, domain);
    u64::from_be_bytes(digest[..8].try_into().unwrap_or([0; 8]))
}

fn namespace_digest(run_id: u128, agent_id: &str, seed: u64, domain: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"dexos.loadgen.namespace.v1");
    h.update(domain);
    h.update(run_id.to_be_bytes());
    h.update(seed.to_be_bytes());
    hash_string(&mut h, agent_id);
    h.finalize().into()
}

fn hash_string(h: &mut Sha256, value: &str) {
    h.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    h.update(value.as_bytes());
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for index in 0..32 {
        diff |= left[index] ^ right[index];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realtime::{ActionKind, WorkerMetrics};

    fn agents() -> Vec<AgentDescriptor> {
        ["tokyo", "london", "new-york"]
            .into_iter()
            .map(|id| AgentDescriptor {
                id: id.to_string(),
                region: id.to_string(),
                max_rate: 10_000_000,
                max_connections: 5_000,
                allowed_targets: vec!["validator-a:9000".to_string()],
                clock_uncertainty_ns: 500_000,
            })
            .collect()
    }

    fn plan() -> ControllerPlan {
        ControllerPlan {
            run_id: 77,
            start_unix_ns: MIN_START_LEAD_NS + 1,
            total_rate: 20_000_002,
            total_connections: 10_001,
            client_id_base: 1_000_000,
            seed: 9,
            phases: PhaseSchedule::default(),
            targets: vec!["validator-a:9000".to_string()],
        }
    }

    #[test]
    fn three_agents_partition_totals_and_namespaces_exactly() {
        let assignments = partition_plan(&plan(), &agents(), 0).unwrap();
        assert_eq!(assignments.len(), 3);
        assert_eq!(assignments.iter().map(|a| a.rate).sum::<u64>(), 20_000_002);
        assert_eq!(
            assignments.iter().map(|a| a.connections).sum::<u32>(),
            10_001
        );
        assert!(assignments.iter().all(AgentAssignment::verify_digest));
        for pair in assignments.windows(2) {
            assert_eq!(pair[0].client_id_end, pair[1].client_id_start);
            assert_ne!(pair[0].nonce_namespace, pair[1].nonce_namespace);
            assert_ne!(pair[0].rng_seed, pair[1].rng_seed);
            assert_eq!(pair[0].start_unix_ns, pair[1].start_unix_ns);
        }
    }

    #[test]
    fn partitions_are_stable_independent_of_advertisement_order() {
        let forward = partition_plan(&plan(), &agents(), 0).unwrap();
        let mut reversed_agents = agents();
        reversed_agents.reverse();
        let reversed = partition_plan(&plan(), &reversed_agents, 0).unwrap();
        assert_eq!(forward, reversed);
    }

    #[test]
    fn assignment_digest_authentication_and_replay_fail_closed() {
        let assignment = partition_plan(&plan(), &agents(), 0).unwrap().remove(0);
        let auth = ControlAuthenticator::new(&[7; 32]).unwrap();
        let challenge = [9; 32];
        let tag = auth.tag(
            &assignment.agent_id,
            assignment.run_id,
            &assignment.digest,
            &challenge,
        );
        assert!(auth.verify(
            &assignment.agent_id,
            assignment.run_id,
            &assignment.digest,
            &challenge,
            &tag
        ));
        assert!(!auth.verify(
            "other",
            assignment.run_id,
            &assignment.digest,
            &challenge,
            &tag
        ));
        let report_digest = [0xabu8; 32];
        let report_tag = auth.report_tag(&assignment, &report_digest);
        assert!(auth.verify_report(&assignment, &report_digest, &report_tag));
        let mut tampered_digest = report_digest;
        tampered_digest[0] ^= 1;
        assert!(!auth.verify_report(&assignment, &tampered_digest, &report_tag));
        let envelope = AuthenticatedAssignment::new(assignment.clone(), challenge, &auth);
        envelope.verify_for(&assignment.agent_id, &auth).unwrap();
        assert_eq!(
            envelope.verify_for("other", &auth),
            Err(DistributedError::UnknownAgent)
        );
        let mut replay = AssignmentReplayGuard::default();
        replay.consume(&assignment).unwrap();
        assert_eq!(
            replay.consume(&assignment),
            Err(DistributedError::AssignmentReplay)
        );
    }

    fn complete_interval(count: u64) -> IntervalMetrics {
        let mut worker = WorkerMetrics::default();
        let counters = &mut worker.action_mut(ActionKind::New).counters;
        counters.offered = count;
        counters.generated = count;
        counters.queued = count;
        counters.socket_written = count;
        counters.acknowledged = count;
        counters.accepted = count;
        worker.take_interval(10, 20).unwrap()
    }

    #[test]
    fn three_agent_controller_merges_once_and_requires_every_agent() {
        let assignments = partition_plan(&plan(), &agents(), 0).unwrap();
        let mut run = ControllerRun::new(&assignments, 10).unwrap();
        for assignment in &assignments {
            run.heartbeat(
                &AgentHeartbeat {
                    agent_id: assignment.agent_id.clone(),
                    run_id: assignment.run_id,
                    state: AgentState::Complete,
                    monotonic_ns: 5,
                    queue_depth: 0,
                    saturated: false,
                },
                5,
            )
            .unwrap();
            run.interval(&assignment.agent_id, 0, complete_interval(assignment.rate))
                .unwrap();
        }
        run.finalize(1, 10).unwrap();
        let total = run
            .aggregate_interval(0)
            .unwrap()
            .validate_drained()
            .unwrap();
        assert_eq!(total.accepted, plan().total_rate);
    }

    #[test]
    fn missing_failed_or_saturated_agent_invalidates_run() {
        let assignments = partition_plan(&plan(), &agents(), 0).unwrap();
        let missing = ControllerRun::new(&assignments, 10).unwrap();
        assert!(matches!(
            missing.finalize(1, 10),
            Err(DistributedError::MissingHeartbeat { .. })
        ));

        let mut failed = ControllerRun::new(&assignments, 10).unwrap();
        failed
            .heartbeat(
                &AgentHeartbeat {
                    agent_id: assignments[0].agent_id.clone(),
                    run_id: assignments[0].run_id,
                    state: AgentState::Failed,
                    monotonic_ns: 1,
                    queue_depth: 0,
                    saturated: false,
                },
                1,
            )
            .unwrap();
        assert!(matches!(
            failed.check_liveness(2),
            Err(DistributedError::AgentFailed { .. })
        ));

        let mut saturated = ControllerRun::new(&assignments, 10).unwrap();
        for assignment in &assignments {
            saturated
                .heartbeat(
                    &AgentHeartbeat {
                        agent_id: assignment.agent_id.clone(),
                        run_id: assignment.run_id,
                        state: AgentState::Complete,
                        monotonic_ns: 1,
                        queue_depth: 0,
                        saturated: assignment.agent_id == assignments[0].agent_id,
                    },
                    1,
                )
                .unwrap();
            saturated
                .interval(&assignment.agent_id, 0, complete_interval(assignment.rate))
                .unwrap();
        }
        assert!(matches!(
            saturated.finalize(1, 2),
            Err(DistributedError::AgentSaturated { .. })
        ));
    }

    #[test]
    fn interval_rate_and_offered_floors_fail_closed() {
        let assignments = partition_plan(&plan(), &agents(), 0).unwrap();
        let assignment = &assignments[0];
        let mut offered_bad = ControllerRun::new(&assignments, 10).unwrap();
        assert!(matches!(
            offered_bad.interval(
                &assignment.agent_id,
                0,
                complete_interval(assignment.rate - 1)
            ),
            Err(DistributedError::IntervalOfferedMismatch { .. })
        ));

        let mut worker = WorkerMetrics::default();
        let counters = &mut worker.action_mut(ActionKind::New).counters;
        counters.offered = assignment.rate;
        counters.generated = assignment.rate;
        counters.queued = assignment.rate;
        counters.socket_written = assignment.rate.saturating_mul(97) / 100;
        counters.transport_failed = assignment.rate - counters.socket_written;
        let interval = worker.take_interval(0, 1).unwrap();
        let mut under_rate = ControllerRun::new(&assignments, 10).unwrap();
        assert!(matches!(
            under_rate.interval(&assignment.agent_id, 0, interval),
            Err(DistributedError::IntervalUnderRate { .. })
        ));
    }
}

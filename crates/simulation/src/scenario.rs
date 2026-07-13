//! Pre-built fault scenarios for the soak / fault matrix.
//!
//! Every builder returns a [`SimConfig`] that [`crate::Cluster::run`] executes
//! deterministically from its seed. The scenarios cover the required matrix:
//! happy path, network partition + heal, leader failover, crash + restart
//! recovery, packet loss / duplication / reordering, Byzantine equivocation,
//! invalid signatures, leader equivocation, and clock drift — plus a combined,
//! length-parameterized soak.

use crate::cluster::SimConfig;
use crate::node::{Behavior, NodeId};
use crate::transport::LinkFaults;

/// N honest nodes on a low-latency link; the reference "everything works" run.
#[must_use]
pub fn happy_path(num_nodes: u32, heights: u64, seed: u64) -> SimConfig {
    SimConfig::clean(num_nodes, heights, seed)
}

/// A partition splitting the nodes into `groups`, healed at `heal_ns`. Because
/// the timeout is set beyond the heal time, reconvergence is by retransmission
/// alone (no spurious view change), and all nodes finalize the same blocks.
#[must_use]
pub fn partition_heal(
    num_nodes: u32,
    heights: u64,
    seed: u64,
    groups: Vec<u32>,
    heal_ns: u64,
) -> SimConfig {
    let mut cfg = SimConfig::clean(num_nodes, heights, seed);
    cfg.partition = Some(groups);
    cfg.heal_time_ns = Some(heal_ns);
    // Keep the timeout comfortably beyond the heal so no view change fires;
    // reconvergence after the heal is by retransmission alone.
    cfg.round_timeout_ns = heal_ns.saturating_mul(20).max(5_000_000);
    cfg
}

/// The current leader (node 0) crashes before proposing, forcing a view-change
/// failover to an honest leader. Node 0 stays down for the run.
#[must_use]
pub fn leader_failover(num_nodes: u32, heights: u64, seed: u64) -> SimConfig {
    let mut cfg = SimConfig::clean(num_nodes, heights, seed);
    cfg.crashes = vec![(0, 0)];
    cfg
}

/// A non-leader node crashes, then restarts and recovers via state sync to a
/// bit-identical root. `restart_ns` should be after the run's heights finalize.
#[must_use]
pub fn crash_restart(
    num_nodes: u32,
    heights: u64,
    seed: u64,
    victim: NodeId,
    crash_ns: u64,
    restart_ns: u64,
) -> SimConfig {
    let mut cfg = SimConfig::clean(num_nodes, heights, seed);
    cfg.crashes = vec![(victim, crash_ns)];
    cfg.restarts = vec![(victim, restart_ns)];
    cfg
}

/// Lossy link with drops, duplication, and reordering; liveness is preserved by
/// retransmission and idempotent vote handling.
#[must_use]
pub fn packet_loss(
    num_nodes: u32,
    heights: u64,
    seed: u64,
    drop_permille: u32,
    dup_permille: u32,
) -> SimConfig {
    let mut cfg = SimConfig::clean(num_nodes, heights, seed);
    cfg.faults = LinkFaults {
        base_delay_ns: 1_000,
        jitter_ns: 500,
        drop_permille,
        dup_permille,
        max_dups: 2,
        reorder_permille: 200,
        reorder_spread_ns: 3_000,
    };
    cfg
}

/// `f` Byzantine equivocating voters (the highest-indexed, non-leader nodes).
/// The Minimmit feature uses its required `5f+1` sizing; the legacy lane keeps
/// HotStuff's `3f+1` sizing.
#[must_use]
pub fn byzantine_equivocation(f: u32, heights: u64, seed: u64) -> SimConfig {
    #[cfg(feature = "minimmit")]
    let num_nodes = 5 * f + 1;
    #[cfg(not(feature = "minimmit"))]
    let num_nodes = 3 * f + 1;
    let mut cfg = SimConfig::clean(num_nodes, heights, seed);
    let mut behaviors = Vec::new();
    for k in 0..f {
        behaviors.push((num_nodes - 1 - k, Behavior::EquivocatingVoter));
    }
    cfg.behaviors = behaviors;
    cfg
}

/// `f` invalid-signing nodes in the engine's required committee size; their
/// votes are rejected and honest nodes still reach agreement without panicking.
#[must_use]
pub fn invalid_signatures(f: u32, heights: u64, seed: u64) -> SimConfig {
    #[cfg(feature = "minimmit")]
    let num_nodes = 5 * f + 1;
    #[cfg(not(feature = "minimmit"))]
    let num_nodes = 3 * f + 1;
    let mut cfg = SimConfig::clean(num_nodes, heights, seed);
    let mut behaviors = Vec::new();
    for k in 0..f {
        behaviors.push((num_nodes - 1 - k, Behavior::InvalidSigner));
    }
    cfg.behaviors = behaviors;
    cfg
}

/// The leader (node 0) equivocates, proposing two conflicting blocks. On a
/// jitter-free link the first block wins uniformly and the fork is detected,
/// while honest nodes still agree.
#[must_use]
pub fn equivocating_leader(num_nodes: u32, heights: u64, seed: u64) -> SimConfig {
    let mut cfg = SimConfig::clean(num_nodes, heights, seed);
    cfg.faults = LinkFaults::latent(1_000, 0);
    cfg.behaviors = vec![(0, Behavior::EquivocatingLeader)];
    cfg
}

/// Per-node clock drift (skew) that perturbs message timing but never the
/// finalized block sequence, so final roots stay bit-identical.
#[must_use]
pub fn clock_drift(num_nodes: u32, heights: u64, seed: u64) -> SimConfig {
    let mut cfg = SimConfig::clean(num_nodes, heights, seed);
    let mut skews = Vec::new();
    for i in 0..num_nodes {
        // Monotonically increasing per-node skew, in ns.
        skews.push((i, u64::from(i) * 250));
    }
    cfg.clock_skews = skews;
    cfg
}

/// A combined, length-parameterized soak: many heights under loss, a partition
/// that heals, a crash + restart, and clock drift — all deterministic. Use a
/// small `heights` in CI and a large one for an extended (virtual-time) soak.
#[must_use]
pub fn soak(num_nodes: u32, heights: u64, seed: u64) -> SimConfig {
    let mut cfg = SimConfig::clean(num_nodes, heights, seed);
    cfg.faults = LinkFaults {
        base_delay_ns: 1_000,
        jitter_ns: 500,
        drop_permille: 100,
        dup_permille: 100,
        max_dups: 2,
        reorder_permille: 150,
        reorder_spread_ns: 2_000,
    };
    // A brief partition early on, healed well before the timeout fires.
    if num_nodes >= 4 {
        let mut groups = vec![0u32; usize::try_from(num_nodes).unwrap_or(0)];
        for g in groups
            .iter_mut()
            .skip(usize::try_from(num_nodes / 2).unwrap_or(0))
        {
            *g = 1;
        }
        cfg.partition = Some(groups);
        cfg.heal_time_ns = Some(50_000);
        cfg.round_timeout_ns = 5_000_000;
    }
    // Clock drift on every node.
    let mut skews = Vec::new();
    for i in 0..num_nodes {
        skews.push((i, u64::from(i) * 100));
    }
    cfg.clock_skews = skews;
    cfg
}

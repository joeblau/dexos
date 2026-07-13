#![deny(unsafe_code)]
//! Deterministic discrete-event simulation for the Minimmit consensus engine.
//!
//! Logical time, seeded transport faults, partitions, crashes, Byzantine
//! behavior, and replay are modeled without threads or a wall clock. The
//! simulator drives the same clock-free [`consensus::MinimmitReplica`] used by
//! the node and asserts agreement only after the mandatory execution L-cert.

#[path = "minimmit_cluster.rs"]
pub mod cluster;
#[path = "minimmit_node.rs"]
pub mod node;
pub mod oracle;
pub mod rng;
pub mod scenario;
pub mod scheduler;
pub mod transport;

pub use cluster::{percentile, Cluster, SimConfig, SimError, SimResult};
pub use node::{
    byzantine_block, canonical_block, Behavior, Envelope, Node, NodeId, Outgoing, Payload, Target,
};
pub use oracle::{Divergence, StateRootOracle};
pub use rng::SimRng;
pub use scheduler::{Dispatched, Scheduler, Time};
pub use transport::{LinkFaults, PriorityLink, Routing, Transport, TransportStats};

/// Crate identity, used by the node composition root for a startup manifest.
pub const CRATE_NAME: &str = "simulation";

#[cfg(test)]
mod minimmit_tests;

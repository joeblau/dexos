//! Authorize traffic classes from authenticated peer role.
//!
//! Inbound peers control the on-wire `Frame.class` byte. Without an admission
//! check a non-validator can label bulk traffic P0 and displace consensus. This
//! module maps an authenticated [`PeerRole`] to the set of classes it may
//! submit and rejects mismatches before enqueue.

use codec::TrafficClass;

use crate::error::TransportError;

/// Authenticated role of a peer, derived from membership / committee registry —
/// never from a self-attested gossip claim alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum PeerRole {
    /// Full validator: may submit every traffic class including P0 consensus.
    Validator = 0,
    /// Sequencer / block producer: consensus + execution path.
    Sequencer = 1,
    /// Oracle feeder: oracle certificates and market data only.
    Oracle = 2,
    /// Gateway / client-facing node: orders and market data, never consensus.
    Gateway = 3,
    /// Observer / unknown: lowest privileges (market data + sync only).
    #[default]
    Observer = 4,
}

impl PeerRole {
    /// Whether this role may submit frames of `class`.
    #[must_use]
    pub fn permits(self, class: TrafficClass) -> bool {
        use PeerRole::*;
        use TrafficClass::*;
        match self {
            Validator => true,
            Sequencer => !matches!(class, OracleCert),
            Oracle => matches!(class, OracleCert | MarketData | Checkpoint | Sync),
            Gateway => matches!(
                class,
                RiskReducing
                    | Liquidation
                    | NewOrder
                    | ExecutionReceipt
                    | MarketData
                    | Checkpoint
                    | Sync
            ),
            Observer => matches!(class, MarketData | Sync | Checkpoint),
        }
    }

    /// Whether this role is a consensus-admitting peer (counts against the
    /// per-validator consensus permit budget).
    #[must_use]
    pub fn is_consensus_peer(self) -> bool {
        matches!(self, PeerRole::Validator | PeerRole::Sequencer)
    }
}

/// Reject `class` when `role` is not authorized to submit it.
pub fn authorize_class(role: PeerRole, class: TrafficClass) -> Result<(), TransportError> {
    if role.permits(class) {
        Ok(())
    } else {
        Err(TransportError::UnauthorizedClass { class, role })
    }
}

/// Per-validator consensus admission budget: one peer cannot consume every
/// consensus permit under a shared node budget.
#[derive(Debug)]
pub struct ConsensusPermits {
    /// Maximum outstanding P0 bytes reserved by one validator peer.
    per_peer_bytes: usize,
    /// Node-wide outstanding P0 bytes across all validators.
    node_bytes: usize,
    /// Currently reserved per peer (keyed by a dense index assigned at accept).
    // Simple fixed table: peer index -> reserved bytes. Callers map PeerId.
    reserved: std::collections::HashMap<[u8; 32], usize>,
    node_reserved: usize,
}

impl ConsensusPermits {
    /// Create a permit table with the given ceilings.
    pub fn new(per_peer_bytes: usize, node_bytes: usize) -> Self {
        Self {
            per_peer_bytes,
            node_bytes,
            reserved: std::collections::HashMap::new(),
            node_reserved: 0,
        }
    }

    /// Try to reserve `bytes` of consensus admission for `peer`.
    pub fn try_reserve(&mut self, peer: [u8; 32], bytes: usize) -> bool {
        let used = self.reserved.get(&peer).copied().unwrap_or(0);
        if used.saturating_add(bytes) > self.per_peer_bytes {
            return false;
        }
        if self.node_reserved.saturating_add(bytes) > self.node_bytes {
            return false;
        }
        self.reserved.insert(peer, used.saturating_add(bytes));
        self.node_reserved = self.node_reserved.saturating_add(bytes);
        true
    }

    /// Release a previous reservation.
    pub fn release(&mut self, peer: [u8; 32], bytes: usize) {
        if let Some(used) = self.reserved.get_mut(&peer) {
            *used = used.saturating_sub(bytes);
        }
        self.node_reserved = self.node_reserved.saturating_sub(bytes);
    }

    /// Bytes currently reserved by `peer`.
    pub fn peer_used(&self, peer: [u8; 32]) -> usize {
        self.reserved.get(&peer).copied().unwrap_or(0)
    }

    /// Node-wide reserved consensus bytes.
    pub fn node_used(&self) -> usize {
        self.node_reserved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_validator_cannot_submit_p0() {
        assert!(authorize_class(PeerRole::Gateway, TrafficClass::Consensus).is_err());
        assert!(authorize_class(PeerRole::Observer, TrafficClass::Consensus).is_err());
        assert!(authorize_class(PeerRole::Oracle, TrafficClass::Consensus).is_err());
        assert!(authorize_class(PeerRole::Validator, TrafficClass::Consensus).is_ok());
        assert!(authorize_class(PeerRole::Sequencer, TrafficClass::Consensus).is_ok());
    }

    #[test]
    fn gateway_may_submit_orders_not_oracle() {
        assert!(authorize_class(PeerRole::Gateway, TrafficClass::NewOrder).is_ok());
        assert!(authorize_class(PeerRole::Gateway, TrafficClass::OracleCert).is_err());
    }

    #[test]
    fn one_validator_cannot_consume_every_consensus_permit() {
        let mut permits = ConsensusPermits::new(100, 250);
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert!(permits.try_reserve(a, 100));
        // Peer A is at its per-peer ceiling.
        assert!(!permits.try_reserve(a, 1));
        // Peer B can still reserve under the node budget.
        assert!(permits.try_reserve(b, 100));
        // Node budget remaining 50: a third peer can take 50 but not 100.
        let c = [3u8; 32];
        assert!(!permits.try_reserve(c, 100));
        assert!(permits.try_reserve(c, 50));
        assert_eq!(permits.node_used(), 250);
        permits.release(a, 100);
        assert_eq!(permits.peer_used(a), 0);
        assert_eq!(permits.node_used(), 150);
    }
}

//! In-process loopback transport.
//!
//! Peers register on a shared [`LoopbackFabric`]; connecting wires two
//! [`Connection`] endpoints together with tokio channels — no sockets, no
//! serialization to a socket, fully deterministic. This backs the simulator and
//! the crate's own async tests. It exercises the exact same [`Connection`]
//! surface, priority scheduler, backpressure, and replay suppression as the TCP
//! transport.
//!
//! Admission is **bounded**: each listener's accept queue has a fixed capacity
//! ([`TransportConfig::accept_queue_capacity`], default
//! [`crate::DEFAULT_ACCEPT_QUEUE`]). Flooding `connect` past that capacity
//! returns [`TransportError::Backpressure`] instead of growing memory without
//! limit — matching production overload behaviour.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;

use crate::channel::AsyncPriorityChannel;
use crate::connection::{Connection, TransportConfig};
use crate::error::TransportError;
use crate::peer::{Peer, PeerId};
use crate::transport::Transport;
use codec::TrafficClass;

/// A shared switchboard through which loopback peers find one another.
///
/// Clone freely: all clones share one registry.
#[derive(Clone, Default)]
pub struct LoopbackFabric {
    registry: Arc<Mutex<HashMap<PeerId, mpsc::Sender<Connection>>>>,
}

impl LoopbackFabric {
    /// Create an empty fabric.
    pub fn new() -> Self {
        Self::default()
    }

    fn register(&self, id: PeerId, inbox: mpsc::Sender<Connection>) {
        self.registry
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, inbox);
    }

    fn inbox_for(&self, id: &PeerId) -> Option<mpsc::Sender<Connection>> {
        self.registry
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    fn deregister(&self, id: &PeerId) {
        self.registry
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id);
    }
}

/// Build the two crosswired endpoints of a loopback connection.
///
/// `a` is returned to the dialer; `b` is delivered to the listener's accept
/// queue. The reliable priority channel for `a -> b` is *shared* by both
/// endpoints (dialer's outbound == listener's inbound), which is what makes
/// priority ordering deterministic: everything enqueued before the peer starts
/// receiving is drained highest-priority-first.
fn make_pair(a: PeerId, b: PeerId, cfg: &TransportConfig) -> (Connection, Connection) {
    let chan_ab = Arc::new(AsyncPriorityChannel::new(cfg.queue_capacity));
    let chan_ba = Arc::new(AsyncPriorityChannel::new(cfg.queue_capacity));

    // A tokio bounded channel requires a non-zero buffer.
    let datagram_cap = cfg.datagram_capacity.max(1);
    let (dtx_ab, drx_ab) = mpsc::channel(datagram_cap);
    let (dtx_ba, drx_ba) = mpsc::channel(datagram_cap);

    let a_conn = Connection::new(
        b,
        chan_ab.clone(),
        chan_ba.clone(),
        dtx_ab,
        drx_ba,
        cfg,
        Vec::new(),
    );
    let b_conn = Connection::new(a, chan_ba, chan_ab, dtx_ba, drx_ab, cfg, Vec::new());
    (a_conn, b_conn)
}

/// A loopback transport bound to one [`PeerId`].
pub struct LoopbackTransport {
    id: PeerId,
    fabric: LoopbackFabric,
    incoming: AsyncMutex<mpsc::Receiver<Connection>>,
    cfg: TransportConfig,
}

impl LoopbackTransport {
    /// Register `id` on `fabric` and return its transport.
    pub fn new(fabric: LoopbackFabric, id: PeerId, cfg: TransportConfig) -> Self {
        let cap = cfg.accept_queue_capacity.max(1);
        let (tx, rx) = mpsc::channel(cap);
        fabric.register(id, tx);
        Self {
            id,
            fabric,
            incoming: AsyncMutex::new(rx),
            cfg,
        }
    }

    /// This transport's peer identity.
    pub fn id(&self) -> PeerId {
        self.id
    }

    /// A [`Peer`] descriptor addressing this transport over the fabric.
    pub fn as_peer(&self) -> Peer {
        Peer::loopback(self.id)
    }
}

impl Drop for LoopbackTransport {
    fn drop(&mut self) {
        self.fabric.deregister(&self.id);
    }
}

impl Transport for LoopbackTransport {
    async fn connect(&self, peer: &Peer) -> Result<Connection, TransportError> {
        let inbox = self
            .fabric
            .inbox_for(&peer.id)
            .ok_or(TransportError::PeerUnreachable)?;
        let (local, remote) = make_pair(self.id, peer.id, &self.cfg);
        match inbox.try_send(remote) {
            Ok(()) => Ok(local),
            Err(mpsc::error::TrySendError::Full(_)) => Err(TransportError::Backpressure {
                // Admission pressure is not class-specific; Sync is the lowest
                // priority traffic class and stands in for connection-level shed.
                class: TrafficClass::Sync,
            }),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(TransportError::PeerUnreachable),
        }
    }

    async fn accept(&self) -> Result<Connection, TransportError> {
        let mut rx = self.incoming.lock().await;
        rx.recv().await.ok_or(TransportError::ConnectionClosed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::DEFAULT_ACCEPT_QUEUE;
    use crate::replay::PeerDedup;
    use codec::TrafficClass;

    fn cfg() -> TransportConfig {
        TransportConfig::default()
    }

    async fn connected_pair(cfg: TransportConfig) -> (Connection, Connection) {
        let fabric = LoopbackFabric::new();
        let a = LoopbackTransport::new(fabric.clone(), PeerId::from([1u8; 32]), cfg);
        let b = LoopbackTransport::new(fabric, PeerId::from([2u8; 32]), cfg);
        let dialer = a.connect(&b.as_peer()).await.unwrap();
        let listener = b.accept().await.unwrap();
        // The connections own their channels independently of the transports,
        // which may now be dropped.
        (dialer, listener)
    }

    #[tokio::test]
    async fn reliable_message_round_trips() {
        let (a, b) = connected_pair(cfg()).await;
        a.send_priority(TrafficClass::NewOrder, b"order-1").unwrap();
        let got = b.recv().await.unwrap();
        assert_eq!(got.payload, b"order-1");
        assert_eq!(got.class, TrafficClass::NewOrder);
        assert_eq!(b.peer_id(), PeerId::from([1u8; 32]));
    }

    #[tokio::test]
    async fn datagram_round_trips() {
        let (a, b) = connected_pair(cfg()).await;
        a.send_datagram(b"tick").unwrap();
        let got = b.recv_datagram().await.unwrap();
        assert_eq!(got, b"tick");
    }

    #[tokio::test]
    async fn p0_delivered_before_p7_backlog() {
        let (a, b) = connected_pair(cfg()).await;
        // Enqueue a big P7 backlog, then a single P0 vote, all before `b` reads.
        for i in 0..200u32 {
            a.send_priority(TrafficClass::MarketData, &i.to_le_bytes())
                .unwrap();
        }
        a.send_priority(TrafficClass::Consensus, b"vote").unwrap();

        // The consensus vote jumps the entire market-data backlog.
        let first = b.recv().await.unwrap();
        assert_eq!(first.class, TrafficClass::Consensus);
        assert_eq!(first.payload, b"vote");
    }

    #[tokio::test]
    async fn full_bounded_queue_applies_backpressure() {
        let mut c = cfg();
        c.queue_capacity = 8;
        let (a, _b) = connected_pair(c).await;
        // Fill the P3 class to capacity...
        for _ in 0..8 {
            a.send_priority(TrafficClass::NewOrder, b"x").unwrap();
        }
        // ...the next send is rejected; the queue does not grow.
        let err = a.send_priority(TrafficClass::NewOrder, b"x").unwrap_err();
        assert!(matches!(
            err,
            TransportError::Backpressure {
                class: TrafficClass::NewOrder
            }
        ));
        assert_eq!(a.pending_outbound(), 8);
        // Higher priority is unaffected by the full low-priority class.
        a.send_priority(TrafficClass::Consensus, b"v").unwrap();
    }

    #[tokio::test]
    async fn duplicate_sequence_delivered_once_across_paths() {
        // Two independent connections model two network paths to the SAME
        // logical peer. Identical messages carry the same idempotency sequence;
        // a per-peer dedup table upstream must deliver exactly one.
        let fabric = LoopbackFabric::new();
        let peer_id = PeerId::from([2u8; 32]);
        let a = LoopbackTransport::new(fabric.clone(), PeerId::from([1u8; 32]), cfg());
        let b = LoopbackTransport::new(fabric, peer_id, cfg());

        let path1 = a.connect(&b.as_peer()).await.unwrap();
        let b1 = b.accept().await.unwrap();
        let path2 = a.connect(&b.as_peer()).await.unwrap();
        let b2 = b.accept().await.unwrap();

        // Same idempotency-tagged message sent over both paths.
        path1
            .send_typed(TrafficClass::RiskReducing, 5, b"cancel")
            .unwrap();
        path2
            .send_typed(TrafficClass::RiskReducing, 5, b"cancel")
            .unwrap();

        let f1 = b1.recv().await.unwrap();
        let f2 = b2.recv().await.unwrap();
        assert_eq!(f1.msg_type, 5);
        assert_eq!(f2.msg_type, 5);

        // Upstream de-duplication keyed on (peer, idempotency id).
        let mut dedup = PeerDedup::new(1024, 16);
        let d1 = dedup.accept(peer_id, u64::from(f1.msg_type)).unwrap();
        let d2 = dedup.accept(peer_id, u64::from(f2.msg_type)).unwrap();
        assert!(
            d1 ^ d2,
            "exactly one of the two paths is delivered upstream"
        );
    }

    #[tokio::test]
    async fn connect_to_unknown_peer_fails_without_panic() {
        let fabric = LoopbackFabric::new();
        let a = LoopbackTransport::new(fabric, PeerId::from([1u8; 32]), cfg());
        let err = a.connect(&Peer::loopback(PeerId::from([9u8; 32]))).await;
        assert!(matches!(err, Err(TransportError::PeerUnreachable)));
    }

    #[tokio::test]
    async fn connect_flood_applies_accept_queue_backpressure() {
        let mut c = cfg();
        c.accept_queue_capacity = 4;
        let fabric = LoopbackFabric::new();
        let a = LoopbackTransport::new(fabric.clone(), PeerId::from([1u8; 32]), c);
        // Listener that never drains its accept queue.
        let b = LoopbackTransport::new(fabric, PeerId::from([2u8; 32]), c);

        // Fill the accept queue to capacity.
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(a.connect(&b.as_peer()).await.unwrap());
        }
        // The next connect is rejected with Backpressure; the queue does not grow.
        let err = a.connect(&b.as_peer()).await.unwrap_err();
        assert!(
            matches!(
                err,
                TransportError::Backpressure {
                    class: TrafficClass::Sync
                }
            ),
            "expected Backpressure, got {err:?}"
        );
        // Keep `held` live so the sender side of the accept queue stays open.
        drop(held);
        assert_eq!(DEFAULT_ACCEPT_QUEUE, 64);
        assert_eq!(TransportConfig::default().accept_queue_capacity, 64);
    }

    #[tokio::test]
    async fn integrity_property_over_random_payloads() {
        // Deterministic LCG generates arbitrary payloads across random classes;
        // every message must round-trip byte-for-byte in priority order.
        let (a, b) = connected_pair(cfg()).await;
        let mut state: u64 = 0xA5A5_1234_9999_0001;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            state
        };

        // Send one message per class in ascending priority order so the receive
        // order is deterministic even though all are enqueued first.
        let classes = [
            TrafficClass::Consensus,
            TrafficClass::RiskReducing,
            TrafficClass::Liquidation,
            TrafficClass::NewOrder,
            TrafficClass::ExecutionReceipt,
            TrafficClass::OracleCert,
            TrafficClass::Checkpoint,
            TrafficClass::MarketData,
            TrafficClass::Sync,
        ];
        let mut sent = Vec::new();
        for class in classes {
            let len = usize::try_from(next() % 64).unwrap();
            let mut payload = Vec::with_capacity(len);
            for _ in 0..len {
                payload.push(next().to_le_bytes()[0]);
            }
            a.send_priority(class, &payload).unwrap();
            sent.push((class, payload));
        }
        for (class, payload) in sent {
            let got = b.recv().await.unwrap();
            assert_eq!(got.class, class);
            assert_eq!(got.payload, payload);
        }
    }
}

//! Stable disconnect classification and lock-free transport counters.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::TransportError;

/// Operator-facing reason classes for terminated peer connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DisconnectReason {
    /// The peer closed the stream or the connection ended normally.
    RemoteClose = 0,
    /// Authentication or handshake validation failed.
    Authentication = 1,
    /// A length, codec, replay, or encryption check rejected wire data.
    Protocol = 2,
    /// A bounded queue could not admit work.
    Backpressure = 3,
    /// An operating-system I/O failure terminated the connection.
    Io = 4,
}

/// Lock-free cumulative disconnect counters, suitable for metrics exporters.
#[derive(Debug, Default)]
pub struct DisconnectMetrics {
    counts: [AtomicU64; 5],
}

impl DisconnectMetrics {
    /// Record one terminated connection.
    pub fn record(&self, reason: DisconnectReason) {
        self.counts[reason as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Read the cumulative count for a reason.
    #[must_use]
    pub fn get(&self, reason: DisconnectReason) -> u64 {
        self.counts[reason as usize].load(Ordering::Relaxed)
    }
}

/// Classify a typed transport error into a stable, low-cardinality reason.
#[must_use]
pub fn classify_disconnect(error: &TransportError) -> DisconnectReason {
    match error {
        TransportError::AuthFailed
        | TransportError::HandshakeFailed
        | TransportError::HandshakeTimeout
        | TransportError::NotInMembership
        | TransportError::NetworkMismatch { .. }
        | TransportError::VersionMismatch { .. } => DisconnectReason::Authentication,
        TransportError::Backpressure { .. } => DisconnectReason::Backpressure,
        TransportError::ConnectionClosed | TransportError::IdleTimeout => {
            DisconnectReason::RemoteClose
        }
        TransportError::Io(_) | TransportError::PeerUnreachable | TransportError::NoAddress => {
            DisconnectReason::Io
        }
        _ => DisconnectReason::Protocol,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disconnect_reason_classes_cover_handshake_and_idle() {
        let m = DisconnectMetrics::default();
        m.record(DisconnectReason::Authentication);
        m.record(DisconnectReason::Io);
        m.record(DisconnectReason::Protocol);
        assert_eq!(m.get(DisconnectReason::Authentication), 1);
        assert_eq!(m.get(DisconnectReason::Io), 1);
        assert_eq!(
            classify_disconnect(&TransportError::HandshakeTimeout),
            DisconnectReason::Authentication
        );
        assert_eq!(
            classify_disconnect(&TransportError::IdleTimeout),
            DisconnectReason::RemoteClose
        );
        assert_eq!(
            classify_disconnect(&TransportError::NotInMembership),
            DisconnectReason::Authentication
        );
    }
}

//! Authenticated TCP transport.
//!
//! This is the "normal", optimized networking path (no kernel bypass): TCP with
//! length-prefixed [`codec::Frame`] framing and a mutually-authenticated
//! handshake over [`crypto::KeyPair`] ed25519 signatures.
//!
//! # Handshake
//!
//! The handshake is symmetric — both sides run [`mutual_handshake`]:
//!
//! 1. each side sends `public_key(32) || nonce(32)`;
//! 2. each side signs the *peer's* nonce, bound into a transcript
//!    `DOMAIN || peer_nonce || self_pub || peer_pub`, and sends the 64-byte
//!    signature;
//! 3. each side verifies the peer's signature over the transcript it expects,
//!    proving the peer holds the private key for its claimed public key.
//!
//! The dialer additionally checks the peer's public key equals the *expected*
//! [`PeerId`] from the [`Peer`] descriptor. A forged or mismatched identity, or
//! a malformed handshake, is rejected with [`TransportError::AuthFailed`] /
//! [`TransportError::HandshakeFailed`] — never a panic.
//!
//! After the handshake the stream is split: a writer task drains the outbound
//! strict-priority channel (and datagram channel) to the socket, and a reader
//! task frames inbound bytes and routes them to the inbound reliable / datagram
//! channels with the same bounded backpressure as the loopback transport.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use codec::Frame;
use crypto::KeyPair;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::channel::AsyncPriorityChannel;
use crate::connection::{Connection, TransportConfig, MSG_TYPE_DATAGRAM};
use crate::error::TransportError;
use crate::framing::{read_frame, write_frame};
use crate::peer::{Peer, PeerId};
use crate::transport::Transport;

/// Domain separation tag for handshake signatures.
const HS_DOMAIN: &[u8] = b"dexos-network-handshake-v1";

/// Monotonic counter mixed into handshake nonces for freshness.
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Derive a 32-byte handshake nonce from wall-clock time, a process counter, and
/// the local public key. Not a security-critical RNG, but unique per handshake;
/// a production deployment would seed this from an OS CSPRNG.
fn make_nonce(public_key: &[u8; 32]) -> [u8; 32] {
    let counter = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut buf = Vec::with_capacity(32 + 16 + 8);
    buf.extend_from_slice(public_key);
    buf.extend_from_slice(&now.to_le_bytes());
    buf.extend_from_slice(&counter.to_le_bytes());
    let digest: types::Hash = crypto::hash_leaf(&buf);
    *digest.as_bytes()
}

/// The signed handshake transcript.
fn transcript(challenge: &[u8; 32], signer_pub: &[u8; 32], verifier_pub: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(HS_DOMAIN.len() + 96);
    m.extend_from_slice(HS_DOMAIN);
    m.extend_from_slice(challenge);
    m.extend_from_slice(signer_pub);
    m.extend_from_slice(verifier_pub);
    m
}

/// Run the mutual authentication handshake over `stream`.
///
/// If `expected` is `Some`, the peer's authenticated identity must match it.
/// Returns the peer's verified [`PeerId`].
pub(crate) async fn mutual_handshake(
    stream: &mut TcpStream,
    keypair: &KeyPair,
    expected: Option<PeerId>,
) -> Result<PeerId, TransportError> {
    let our_pub = keypair.public();
    let our_nonce = make_nonce(&our_pub);

    // Phase 1: exchange (public key, nonce). Both sides write before reading;
    // 64 bytes fit the socket buffer, so there is no deadlock.
    stream.write_all(&our_pub).await?;
    stream.write_all(&our_nonce).await?;
    stream.flush().await?;

    let mut their_pub = [0u8; 32];
    let mut their_nonce = [0u8; 32];
    stream.read_exact(&mut their_pub).await?;
    stream.read_exact(&mut their_nonce).await?;

    // Phase 2: sign the peer's challenge, exchange signatures.
    let our_sig = keypair.sign(&transcript(&their_nonce, &our_pub, &their_pub));
    stream.write_all(&our_sig).await?;
    stream.flush().await?;

    let mut their_sig = [0u8; 64];
    stream.read_exact(&mut their_sig).await?;

    crypto::verify_ed25519(
        &their_pub,
        &transcript(&our_nonce, &their_pub, &our_pub),
        &their_sig,
    )
    .map_err(|_| TransportError::AuthFailed)?;

    if let Some(expected) = expected {
        if their_pub != *expected.as_bytes() {
            return Err(TransportError::AuthFailed);
        }
    }
    Ok(PeerId::from(their_pub))
}

/// Split an authenticated [`TcpStream`] into a [`Connection`] with a writer and
/// reader task.
fn spawn_connection(stream: TcpStream, peer: PeerId, cfg: &TransportConfig) -> Connection {
    let (mut read_half, mut write_half) = stream.into_split();

    let out_reliable = Arc::new(AsyncPriorityChannel::new(cfg.queue_capacity));
    let in_reliable = Arc::new(AsyncPriorityChannel::new(cfg.queue_capacity));
    // A tokio bounded channel requires a non-zero buffer.
    let datagram_cap = cfg.datagram_capacity.max(1);
    let (out_dtx, mut out_drx) = mpsc::channel::<Frame>(datagram_cap);
    let (in_dtx, in_drx) = mpsc::channel::<Frame>(datagram_cap);

    // Writer: strict priority wins over datagrams (biased select).
    let writer_out = out_reliable.clone();
    let writer = tokio::spawn(async move {
        let mut dgram_open = true;
        loop {
            tokio::select! {
                biased;
                reliable = writer_out.recv() => match reliable {
                    Some(frame) => {
                        if write_frame(&mut write_half, &frame).await.is_err() {
                            break;
                        }
                    }
                    None => break, // channel closed -> connection dropped
                },
                dgram = out_drx.recv(), if dgram_open => match dgram {
                    Some(frame) => {
                        if write_frame(&mut write_half, &frame).await.is_err() {
                            break;
                        }
                    }
                    None => dgram_open = false, // datagram sender gone
                },
            }
        }
    });

    // Reader: frame inbound bytes and route by the reserved datagram msg_type.
    let reader_in = in_reliable.clone();
    let max_payload = cfg.max_payload;
    let reader = tokio::spawn(async move {
        // Loop ends when read_frame returns Err (EOF or malformed framing).
        while let Ok(frame) = read_frame(&mut read_half, max_payload).await {
            if frame.msg_type == MSG_TYPE_DATAGRAM {
                // Best-effort: shed on backpressure or closed receiver.
                let _ = in_dtx.try_send(frame);
            } else {
                match reader_in.try_send(frame) {
                    Ok(()) => {}
                    Err(TransportError::Backpressure { .. }) => {
                        // Inbound reliable queue full: shed per policy
                        // rather than grow unbounded.
                    }
                    Err(_) => break,
                }
            }
        }
        reader_in.close();
    });

    Connection::new(
        peer,
        out_reliable,
        in_reliable,
        out_dtx,
        in_drx,
        cfg,
        vec![writer, reader],
    )
}

/// A TCP transport bound to a local address, with a fixed node identity.
pub struct TcpTransport {
    id: PeerId,
    keypair: Arc<KeyPair>,
    listener: TcpListener,
    cfg: TransportConfig,
}

impl TcpTransport {
    /// Bind a listener at `addr` (use port 0 for an ephemeral port) with the
    /// given node keypair and configuration.
    pub async fn bind(
        addr: SocketAddr,
        keypair: Arc<KeyPair>,
        cfg: TransportConfig,
    ) -> Result<Self, TransportError> {
        let listener = TcpListener::bind(addr).await?;
        let id = PeerId::from(keypair.public());
        Ok(Self {
            id,
            keypair,
            listener,
            cfg,
        })
    }

    /// This node's authenticated identity.
    pub fn id(&self) -> PeerId {
        self.id
    }

    /// The bound local address (resolves the ephemeral port after `bind`).
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.listener.local_addr()?)
    }
}

impl Transport for TcpTransport {
    async fn connect(&self, peer: &Peer) -> Result<Connection, TransportError> {
        let addr = peer.addr.ok_or(TransportError::NoAddress)?;
        let mut stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true).ok();
        let verified = mutual_handshake(&mut stream, &self.keypair, Some(peer.id)).await?;
        Ok(spawn_connection(stream, verified, &self.cfg))
    }

    async fn accept(&self) -> Result<Connection, TransportError> {
        let (mut stream, _remote) = self.listener.accept().await?;
        stream.set_nodelay(true).ok();
        let verified = mutual_handshake(&mut stream, &self.keypair, None).await?;
        Ok(spawn_connection(stream, verified, &self.cfg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::TrafficClass;

    fn cfg() -> TransportConfig {
        TransportConfig::default()
    }

    fn kp(seed: u8) -> Arc<KeyPair> {
        Arc::new(KeyPair::from_seed(&[seed; 32]))
    }

    async fn bound(seed: u8) -> Arc<TcpTransport> {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        Arc::new(TcpTransport::bind(addr, kp(seed), cfg()).await.unwrap())
    }

    #[tokio::test]
    async fn mutual_auth_handshake_and_framed_exchange() {
        let server = bound(1).await;
        let client = bound(2).await;
        let server_addr = server.local_addr().unwrap();
        let server_id = server.id();

        let acceptor = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await })
        };
        let client_conn = client
            .connect(&Peer::dial(server_id, server_addr))
            .await
            .unwrap();
        let server_conn = acceptor.await.unwrap().unwrap();

        // Identities were mutually authenticated.
        assert_eq!(client_conn.peer_id(), server_id);
        assert_eq!(server_conn.peer_id(), client.id());

        // Framed reliable exchange, both directions.
        client_conn
            .send_priority(TrafficClass::Consensus, b"ping")
            .unwrap();
        let got = server_conn.recv().await.unwrap();
        assert_eq!(got.payload, b"ping");
        assert_eq!(got.class, TrafficClass::Consensus);

        server_conn
            .send_priority(TrafficClass::ExecutionReceipt, b"pong")
            .unwrap();
        let back = client_conn.recv().await.unwrap();
        assert_eq!(back.payload, b"pong");
    }

    #[tokio::test]
    async fn datagram_path_round_trips_over_tcp() {
        let server = bound(3).await;
        let client = bound(4).await;
        let server_addr = server.local_addr().unwrap();
        let server_id = server.id();
        let acceptor = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await })
        };
        let client_conn = client
            .connect(&Peer::dial(server_id, server_addr))
            .await
            .unwrap();
        let server_conn = acceptor.await.unwrap().unwrap();

        client_conn.send_datagram(b"tick").unwrap();
        let got = server_conn.recv_datagram().await.unwrap();
        assert_eq!(got, b"tick");
    }

    #[tokio::test]
    async fn forged_identity_is_rejected_without_panic() {
        let server = bound(5).await;
        let client = bound(6).await;
        let server_addr = server.local_addr().unwrap();

        // Keep the server accepting so the handshake can proceed far enough for
        // the client to detect the identity mismatch.
        let acceptor = {
            let server = server.clone();
            tokio::spawn(async move {
                let _ = server.accept().await;
            })
        };

        // Dial the real server address but *expect* a different identity.
        let wrong_id = PeerId::from([0xAAu8; 32]);
        let result = client.connect(&Peer::dial(wrong_id, server_addr)).await;
        assert!(matches!(result, Err(TransportError::AuthFailed)));
        let _ = acceptor.await;
    }

    #[tokio::test]
    async fn connect_without_address_fails() {
        let client = bound(7).await;
        let result = client
            .connect(&Peer::loopback(PeerId::from([1u8; 32])))
            .await;
        assert!(matches!(result, Err(TransportError::NoAddress)));
    }
}

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
//! 1. each side sends `public_key(32) || nonce(32) || ephemeral_x25519_pub(32)`;
//! 2. each side signs the *peer's* nonce, bound into a transcript
//!    `DOMAIN || peer_nonce || self_pub || peer_pub || self_eph || peer_eph`,
//!    and sends the 64-byte signature;
//! 3. each side verifies the peer's signature over the transcript it expects,
//!    proving the peer holds the private key for its claimed public key **and**
//!    authenticating both ephemeral keys against a man-in-the-middle.
//!
//! The dialer additionally checks the peer's public key equals the *expected*
//! [`PeerId`] from the [`Peer`] descriptor. A forged or mismatched identity, or
//! a malformed handshake, is rejected with [`TransportError::AuthFailed`] /
//! [`TransportError::HandshakeFailed`] — never a panic.
//!
//! # Encryption
//!
//! The authenticated ephemeral X25519 keys complete an ECDH whose secret is fed
//! through HKDF-SHA256 into per-direction ChaCha20-Poly1305 keys (see
//! [`crate::session`]). After the handshake every application frame crosses the
//! wire as an AEAD record, so a passive observer or on-path middlebox sees only
//! ciphertext and length prefixes, and the ephemeral secret gives forward
//! secrecy. The frame `sequence` (and thus the replay window) lives inside the
//! encrypted plaintext and is recovered before replay checking.
//!
//! After the handshake the stream is split: a writer task seals the outbound
//! strict-priority channel (and datagram channel) to the socket, and a reader
//! task opens inbound records and routes them to the inbound reliable / datagram
//! channels with the same bounded backpressure as the loopback transport.

use std::net::SocketAddr;
use std::sync::Arc;

use codec::Frame;
use crypto::KeyPair;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::budget::ByteBudget;
use crate::channel::AsyncPriorityChannel;
use crate::connection::{Connection, TransportConfig, MSG_TYPE_DATAGRAM};
use crate::error::TransportError;
use crate::framing::{read_encrypted_frame, write_encrypted_frame};
use crate::peer::{Peer, PeerId};
use crate::session::{Ephemeral, Session, EPH_PUBLIC_LEN};
use crate::transport::Transport;

/// Domain separation tag for handshake signatures.
const HS_DOMAIN: &[u8] = b"dexos-network-handshake-v1";

/// Draw a fresh 32-byte handshake nonce from the OS CSPRNG.
///
/// The nonce guards handshake freshness and replay resistance, so it must be
/// unpredictable. It comes straight from the platform secure RNG (`getrandom`)
/// — the same source [`Ephemeral::generate`] uses for session keys — rather
/// than a wall-clock/counter mixer an on-path attacker could predict. If the OS
/// CSPRNG is unavailable we fail the handshake instead of proceeding with weak
/// randomness.
fn make_nonce() -> Result<[u8; 32], TransportError> {
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce).map_err(|_| TransportError::HandshakeFailed)?;
    Ok(nonce)
}

/// The signed handshake transcript.
///
/// Includes both parties' **ephemeral X25519 public keys** so the ed25519
/// signature authenticates the session-key material: a man-in-the-middle cannot
/// substitute its own ephemeral key without invalidating the signature.
fn transcript(
    challenge: &[u8; 32],
    signer_pub: &[u8; 32],
    verifier_pub: &[u8; 32],
    signer_eph: &[u8; EPH_PUBLIC_LEN],
    verifier_eph: &[u8; EPH_PUBLIC_LEN],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(HS_DOMAIN.len() + 160);
    m.extend_from_slice(HS_DOMAIN);
    m.extend_from_slice(challenge);
    m.extend_from_slice(signer_pub);
    m.extend_from_slice(verifier_pub);
    m.extend_from_slice(signer_eph);
    m.extend_from_slice(verifier_eph);
    m
}

/// Run the mutual authentication handshake over `stream`, and establish an
/// encrypted session.
///
/// If `expected` is `Some`, the peer's authenticated identity must match it.
/// Returns the peer's verified [`PeerId`] and the derived [`Session`] ciphers.
pub(crate) async fn mutual_handshake(
    stream: &mut TcpStream,
    keypair: &KeyPair,
    expected: Option<PeerId>,
    is_initiator: bool,
) -> Result<(PeerId, Session), TransportError> {
    let our_pub = keypair.public();
    let our_nonce = make_nonce()?;
    let ephemeral = Ephemeral::generate()?;
    let our_eph = ephemeral.public();

    // Phase 1: exchange (public key, nonce, ephemeral public key). Both sides
    // write before reading; 96 bytes fit the socket buffer, so no deadlock.
    stream.write_all(&our_pub).await?;
    stream.write_all(&our_nonce).await?;
    stream.write_all(&our_eph).await?;
    stream.flush().await?;

    let mut their_pub = [0u8; 32];
    let mut their_nonce = [0u8; 32];
    let mut their_eph = [0u8; EPH_PUBLIC_LEN];
    stream.read_exact(&mut their_pub).await?;
    stream.read_exact(&mut their_nonce).await?;
    stream.read_exact(&mut their_eph).await?;

    // Phase 2: sign the peer's challenge (binding both ephemeral keys), exchange
    // signatures.
    let our_sig = keypair.sign(&transcript(
        &their_nonce,
        &our_pub,
        &their_pub,
        &our_eph,
        &their_eph,
    ));
    stream.write_all(&our_sig).await?;
    stream.flush().await?;

    let mut their_sig = [0u8; 64];
    stream.read_exact(&mut their_sig).await?;

    crypto::verify_ed25519(
        &their_pub,
        &transcript(&our_nonce, &their_pub, &our_pub, &their_eph, &our_eph),
        &their_sig,
    )
    .map_err(|_| TransportError::AuthFailed)?;

    if let Some(expected) = expected {
        if their_pub != *expected.as_bytes() {
            return Err(TransportError::AuthFailed);
        }
    }

    // Both ephemeral keys are now authenticated; complete the ECDH and derive
    // the directional session ciphers.
    let session = ephemeral.into_session(
        is_initiator,
        &their_eph,
        &our_pub,
        &their_pub,
        &our_nonce,
        &their_nonce,
    );
    Ok((PeerId::from(their_pub), session))
}

/// Split an authenticated, encrypted [`TcpStream`] into a [`Connection`] with a
/// writer and reader task. Every frame is sealed/opened with the handshake
/// [`Session`] ciphers, so nothing but ciphertext and length prefixes crosses
/// the wire.
fn spawn_connection(
    stream: TcpStream,
    peer: PeerId,
    session: Session,
    cfg: &TransportConfig,
    node_budget: &Arc<ByteBudget>,
) -> Connection {
    let (mut read_half, mut write_half) = stream.into_split();
    let (mut sealer, mut opener) = session.split();

    // A per-peer child budget under the node-wide budget bounds this peer's
    // outbound reliable bytes and, together with the per-class byte caps on the
    // inbound queue, keeps one peer from consuming the whole process ceiling.
    // Only the outbound channel (filled via `try_send`) charges the budget; the
    // inbound channel is filled via the never-shed `send` path and is bounded by
    // its per-class byte caps instead, so a budget can never force a reliable
    // frame the far side already saw to be dropped.
    let peer_budget = ByteBudget::child(cfg.max_peer_bytes, node_budget.clone());
    let out_reliable = Arc::new(AsyncPriorityChannel::with_limits(
        cfg.queue_capacity,
        cfg.max_class_bytes,
        Some(peer_budget),
    ));
    let in_reliable = Arc::new(AsyncPriorityChannel::with_limits(
        cfg.queue_capacity,
        cfg.max_class_bytes,
        None,
    ));
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
                        if write_encrypted_frame(&mut write_half, &mut sealer, &frame)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    None => break, // channel closed -> connection dropped
                },
                dgram = out_drx.recv(), if dgram_open => match dgram {
                    Some(frame) => {
                        if write_encrypted_frame(&mut write_half, &mut sealer, &frame)
                            .await
                            .is_err()
                        {
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
    let datagram_max = cfg.datagram_max_bytes;
    let semantic_max = cfg.semantic_max;
    let reader = tokio::spawn(async move {
        // Loop ends when a record fails to read/open (EOF, malformed framing, or
        // AEAD authentication failure — any of which tears the link down).
        while let Ok(frame) = read_encrypted_frame(&mut read_half, &mut opener, max_payload).await {
            if frame.msg_type == MSG_TYPE_DATAGRAM {
                // Best-effort: drop an over-cap datagram before it is enqueued,
                // and shed on backpressure or a closed receiver.
                if frame.payload.len() <= datagram_max {
                    let _ = in_dtx.try_send(frame);
                }
            } else {
                // A reliable frame over its class's semantic ceiling is a
                // protocol violation (e.g. a peer trying to stuff a bulk payload
                // into the high-priority consensus class): reject it *before* it
                // is copied into the inbound queue by tearing the link down. This
                // never silently sheds an acknowledged frame — it fails loudly.
                let idx = usize::from(frame.class.priority());
                let cap = semantic_max.get(idx).copied().unwrap_or(max_payload);
                if frame.payload.len() > cap {
                    break;
                }
                if reader_in.send(frame).await.is_err() {
                    // Reliable frames are *never* shed: `send` awaits queue space,
                    // so a full inbound queue stops us draining the socket and
                    // closes the peer's TCP window instead of dropping a frame the
                    // sender already observed as delivered. An error means closed.
                    break;
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
    /// Node-wide reliable-byte budget shared by every accepted/dialed peer.
    node_budget: Arc<ByteBudget>,
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
            node_budget: ByteBudget::root(cfg.max_node_bytes),
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

    /// Node-wide reliable bytes currently retained across every peer.
    pub fn node_queued_bytes(&self) -> usize {
        self.node_budget.used()
    }

    /// High-water mark of [`node_queued_bytes`](Self::node_queued_bytes).
    pub fn node_queued_bytes_high_water(&self) -> usize {
        self.node_budget.high_water()
    }

    /// The node-wide reliable-byte ceiling.
    pub fn node_byte_limit(&self) -> usize {
        self.node_budget.limit()
    }
}

impl Transport for TcpTransport {
    async fn connect(&self, peer: &Peer) -> Result<Connection, TransportError> {
        let addr = peer.addr.ok_or(TransportError::NoAddress)?;
        let mut stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true).ok();
        let (verified, session) =
            mutual_handshake(&mut stream, &self.keypair, Some(peer.id), true).await?;
        Ok(spawn_connection(
            stream,
            verified,
            session,
            &self.cfg,
            &self.node_budget,
        ))
    }

    async fn accept(&self) -> Result<Connection, TransportError> {
        let (mut stream, _remote) = self.listener.accept().await?;
        stream.set_nodelay(true).ok();
        let (verified, session) = mutual_handshake(&mut stream, &self.keypair, None, false).await?;
        Ok(spawn_connection(
            stream,
            verified,
            session,
            &self.cfg,
            &self.node_budget,
        ))
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
    async fn slow_consumer_never_loses_reliable_frames() {
        use std::time::Duration;
        use tokio::time::timeout;

        // Tight per-class queues so the inbound reliable buffer fills quickly and
        // the reader must stall the peer's TCP window rather than shed frames.
        let mut c = cfg();
        c.queue_capacity = 4;
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = Arc::new(TcpTransport::bind(addr, kp(20), c).await.unwrap());
        let client = Arc::new(TcpTransport::bind(addr, kp(21), c).await.unwrap());
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

        const N: u64 = 300;
        // Producer: send N consensus frames, retrying (never dropping) on
        // backpressure — the sender always eventually succeeds for each frame.
        let sender = tokio::spawn(async move {
            for i in 0..N {
                loop {
                    match client_conn.send_priority(TrafficClass::Consensus, &i.to_le_bytes()) {
                        Ok(()) => break,
                        Err(TransportError::Backpressure { .. }) => tokio::task::yield_now().await,
                        Err(e) => return Err(e),
                    }
                }
            }
            // Keep the connection alive until the consumer has drained everything.
            Ok::<_, TransportError>(client_conn)
        });

        // Slow consumer: pause so the inbound buffer saturates and the reader has
        // to backpressure the wire, then drain everything and prove nothing was
        // lost — every consensus frame arrives exactly once, strictly in order.
        tokio::time::sleep(Duration::from_millis(50)).await;
        for i in 0..N {
            let frame = timeout(Duration::from_secs(10), server_conn.recv())
                .await
                .expect("slow consumer must not lose frames under backpressure")
                .expect("reliable frame delivered without gap");
            assert_eq!(frame.class, TrafficClass::Consensus);
            assert_eq!(
                frame.payload,
                i.to_le_bytes(),
                "consensus frame {i} lost or reordered"
            );
        }
        let _kept_alive = sender.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn inbound_over_semantic_ceiling_reliable_frame_tears_down_link() {
        use std::time::Duration;
        use tokio::time::timeout;

        // The server enforces a tight consensus-class ceiling; the client's looser
        // config lets it *send* an over-contract frame the server must reject.
        let mut server_cfg = cfg();
        server_cfg.semantic_max[usize::from(TrafficClass::Consensus.priority())] = 64;
        let mut client_cfg = cfg();
        client_cfg.semantic_max[usize::from(TrafficClass::Consensus.priority())] = 1024 * 1024;

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = Arc::new(TcpTransport::bind(addr, kp(30), server_cfg).await.unwrap());
        let client = Arc::new(TcpTransport::bind(addr, kp(31), client_cfg).await.unwrap());
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

        // A 500-byte consensus frame is within the client's ceiling but far over
        // the server's 64-byte ceiling: the server rejects it on receipt.
        client_conn
            .send_priority(TrafficClass::Consensus, &[7u8; 500])
            .unwrap();

        // The server never delivers the over-ceiling frame; it tears the link
        // down instead of copying a bulk payload into its high-priority queue.
        let closed = timeout(Duration::from_secs(10), server_conn.recv())
            .await
            .expect("server must react to the over-ceiling frame");
        assert!(matches!(closed, Err(TransportError::ConnectionClosed)));
    }

    #[tokio::test]
    async fn inbound_oversized_datagram_is_dropped_before_delivery() {
        use std::time::Duration;
        use tokio::time::timeout;

        let mut server_cfg = cfg();
        server_cfg.datagram_max_bytes = 16;
        let mut client_cfg = cfg();
        client_cfg.datagram_max_bytes = 1024;

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = Arc::new(TcpTransport::bind(addr, kp(32), server_cfg).await.unwrap());
        let client = Arc::new(TcpTransport::bind(addr, kp(33), client_cfg).await.unwrap());
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

        // The oversized datagram is dropped by the server's reader before it is
        // enqueued; the following in-cap datagram is delivered normally.
        client_conn.send_datagram(&[9u8; 600]).unwrap();
        client_conn.send_datagram(b"ok").unwrap();

        let got = timeout(Duration::from_secs(10), server_conn.recv_datagram())
            .await
            .expect("in-cap datagram must still be delivered")
            .unwrap();
        assert_eq!(got, b"ok", "only the in-cap datagram is delivered");
    }

    #[test]
    fn nonces_are_csprng_drawn_and_distinct() {
        // Fresh draws from the OS CSPRNG must differ and must not be all-zero,
        // proving the nonce is no longer a predictable time/counter derivation.
        let a = make_nonce().unwrap();
        let b = make_nonce().unwrap();
        assert_ne!(a, b, "two CSPRNG nonces collided");
        assert_ne!(a, [0u8; 32], "nonce was all zero");
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

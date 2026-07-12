//! Authenticated QUIC transport with independent per-class streams and real datagrams.
//!
//! # Why QUIC
//!
//! [`crate::TcpTransport`] multiplexes every traffic class (and the so-called
//! "datagram" path) over a single ordered TCP byte stream. A large P8 sync frame
//! therefore head-of-line blocks a newly arrived P0 consensus vote for the full
//! transmit time of the sync payload. QUIC eliminates that coupling:
//!
//! * each reliable [`TrafficClass`] owns an independent bidirectional stream;
//! * market-data datagrams use native QUIC DATAGRAM frames (RFC 9221), never the
//!   reliable stream scheduler;
//! * stream-level flow control is sized so sync credit cannot starve consensus.
//!
//! # Authentication
//!
//! QUIC/TLS provides the encrypted session (self-signed certs, custom verifiers
//! that accept the peer's presented cert without a public CA — standard for
//! permissioned P2P). Application identity is the same ed25519 mutual handshake
//! used by TCP ([`crate::tcp::mutual_handshake`]) on a dedicated control stream,
//! so network-id / wire-version / capability negotiation and PeerId binding stay
//! identical across transports.
//!
//! # TCP fallback
//!
//! When QUIC is not configured, operators may still use [`crate::TcpTransport`].
//! TCP keeps working but with **reduced guarantees**: all classes and datagrams
//! share one ordered stream, so large sync frames can delay consensus and the
//! datagram path is lossy only at the application queue — not on the wire.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use codec::{Frame, TrafficClass, FRAME_HEADER_LEN, MAX_FRAME_PAYLOAD};
use crypto::KeyPair;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ClientConfig, Connection as QuinnConnection, Endpoint, RecvStream, SendStream, ServerConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;

use crate::budget::ByteBudget;
use crate::channel::AsyncPriorityChannel;
use crate::connection::{ConnSlot, Connection, ConnectionOpts, TransportConfig, MSG_TYPE_DATAGRAM};
use crate::disconnect::{classify_disconnect, DisconnectMetrics, DisconnectReason};
use crate::error::TransportError;
use crate::peer::{Peer, PeerId};
use crate::replay::PeerDedup;
use crate::scheduler::NUM_CLASSES;
use crate::tcp::{mutual_handshake, Membership};
use crate::transport::Transport;

/// ALPN protocol identifier for DexOS peer QUIC sessions.
const ALPN_DEXOS: &[u8] = b"dexos/quic/1";

/// Server name presented during TLS (unused for identity; PeerId is application-bound).
const TLS_SERVER_NAME: &str = "dexos-peer";

/// Per-stream receive window for P0 consensus (bytes). Sized for a burst of votes.
const P0_STREAM_WINDOW: u32 = 4 * 1024 * 1024;
/// Per-stream receive window for mid-priority classes.
const MID_STREAM_WINDOW: u32 = 2 * 1024 * 1024;
/// Per-stream receive window for P8 sync — deliberately smaller than P0 so a
/// saturated historical-sync peer cannot monopolize connection-level credit.
const SYNC_STREAM_WINDOW: u32 = 512 * 1024;
/// Connection-level receive window: enough for P0+mid concurrent, not 9× sync.
const CONN_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
/// Max concurrent bidi streams: control + 9 classes.
const MAX_BIDI_STREAMS: u32 = 16;

/// Build a self-signed certificate + private key for the QUIC/TLS layer.
///
/// Identity binding is performed by the application handshake, not the cert
/// subject — these certs only satisfy rustls's requirement for a credential.
fn make_tls_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), TransportError> {
    let cert_key = rcgen::KeyPair::generate().map_err(|_| TransportError::HandshakeFailed)?;
    let mut params = rcgen::CertificateParams::new(vec!["dexos-peer".into()])
        .map_err(|_| TransportError::HandshakeFailed)?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "dexos-peer");
    let cert = params
        .self_signed(&cert_key)
        .map_err(|_| TransportError::HandshakeFailed)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert_key.serialize_der()));
    Ok((cert_der, key_der))
}

/// Skip webpki CA validation: peers are authenticated by the ed25519 handshake.
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Accept any client certificate (identity is bound by the application handshake).
#[derive(Debug)]
struct SkipClientVerification;

impl rustls::server::danger::ClientCertVerifier for SkipClientVerification {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.max_concurrent_bidi_streams(MAX_BIDI_STREAMS.into());
    // Connection window deliberately below 9 × sync so a single saturated sync
    // peer cannot exhaust credit that consensus needs.
    t.receive_window(quinn::VarInt::from_u32(CONN_RECEIVE_WINDOW));
    // Default stream window is mid-tier; per-stream we still rely on independent
    // streams for HOL isolation. Sync writers chunk aggressively (see writer).
    t.stream_receive_window(quinn::VarInt::from_u32(MID_STREAM_WINDOW));
    t.datagram_receive_buffer_size(Some(1024 * 1024));
    t.datagram_send_buffer_size(1024 * 1024);
    // Keep idle close aligned with TransportConfig defaults (set per-endpoint).
    t.max_idle_timeout(Some(Duration::from_secs(120).try_into().unwrap()));
    t.keep_alive_interval(Some(Duration::from_secs(15)));
    Arc::new(t)
}

fn make_server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, TransportError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::Io(e.to_string()))?
        .with_client_cert_verifier(Arc::new(SkipClientVerification))
        .with_single_cert(vec![cert], key)
        .map_err(|e| TransportError::Io(e.to_string()))?;
    tls.alpn_protocols = vec![ALPN_DEXOS.to_vec()];
    tls.max_early_data_size = 0; // no 0-RTT until anti-replay is fully wired
    let mut server = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls).map_err(|e| TransportError::Io(e.to_string()))?,
    ));
    server.transport_config(transport_config());
    Ok(server)
}

fn make_client_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<ClientConfig, TransportError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| TransportError::Io(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_client_auth_cert(vec![cert], key)
        .map_err(|e| TransportError::Io(e.to_string()))?;
    tls.alpn_protocols = vec![ALPN_DEXOS.to_vec()];
    tls.enable_sni = false;
    let mut client = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).map_err(|e| TransportError::Io(e.to_string()))?,
    ));
    client.transport_config(transport_config());
    Ok(client)
}

/// Write one self-delimiting [`Frame`] (header includes payload length).
async fn write_frame(send: &mut SendStream, frame: &Frame) -> Result<(), TransportError> {
    let bytes = frame.encode()?;
    send.write_all(&bytes).await.map_err(map_write_err)?;
    Ok(())
}

/// Read one self-delimiting [`Frame`] from a QUIC stream.
async fn read_frame(recv: &mut RecvStream, max_payload: usize) -> Result<Frame, TransportError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    recv.read_exact(&mut header).await.map_err(map_read_err)?;
    let plen = u32::from_le_bytes([header[15], header[16], header[17], header[18]]) as usize;
    let cap = max_payload.min(MAX_FRAME_PAYLOAD);
    if plen > cap {
        return Err(TransportError::MessageTooLarge);
    }
    let mut buf = vec![0u8; FRAME_HEADER_LEN + plen];
    buf[..FRAME_HEADER_LEN].copy_from_slice(&header);
    if plen > 0 {
        recv.read_exact(&mut buf[FRAME_HEADER_LEN..])
            .await
            .map_err(map_read_err)?;
    }
    let (frame, _) = Frame::decode_with_max(&buf, cap)?;
    Ok(frame)
}

fn map_write_err(e: quinn::WriteError) -> TransportError {
    match e {
        quinn::WriteError::ConnectionLost(_) | quinn::WriteError::ClosedStream => {
            TransportError::ConnectionClosed
        }
        other => TransportError::Io(other.to_string()),
    }
}

fn map_read_err(e: quinn::ReadExactError) -> TransportError {
    match e {
        quinn::ReadExactError::FinishedEarly(_) => TransportError::ConnectionClosed,
        quinn::ReadExactError::ReadError(re) => match re {
            quinn::ReadError::ConnectionLost(_) | quinn::ReadError::ClosedStream => {
                TransportError::ConnectionClosed
            }
            other => TransportError::Io(other.to_string()),
        },
    }
}

/// Per-class stream window hint used by writers when chunking large sync frames.
fn class_chunk_limit(class: TrafficClass) -> usize {
    match class {
        TrafficClass::Consensus => P0_STREAM_WINDOW as usize,
        TrafficClass::Sync => SYNC_STREAM_WINDOW as usize / 4, // small chunks yield often
        _ => MID_STREAM_WINDOW as usize / 2,
    }
}

/// Wire a fully-handshaked Quinn connection into the shared [`Connection`] surface.
#[allow(clippy::too_many_arguments)]
fn spawn_quic_connection(
    quinn_conn: QuinnConnection,
    peer: PeerId,
    cfg: &TransportConfig,
    node_budget: &Arc<ByteBudget>,
    disconnects: Arc<DisconnectMetrics>,
    opts: ConnectionOpts,
    class_sends: Vec<SendStream>,
    class_recvs: Vec<RecvStream>,
    enable_datagrams: bool,
) -> Connection {
    assert_eq!(class_sends.len(), NUM_CLASSES);
    assert_eq!(class_recvs.len(), NUM_CLASSES);

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
    let datagram_cap = cfg.datagram_capacity.max(1);
    let (out_dtx, mut out_drx) = mpsc::channel::<Frame>(datagram_cap);
    let (in_dtx, in_drx) = mpsc::channel::<Frame>(datagram_cap);

    let mut tasks = Vec::with_capacity(NUM_CLASSES * 2 + 3);

    let mut class_txs = Vec::with_capacity(NUM_CLASSES);
    let mut class_rxs = Vec::with_capacity(NUM_CLASSES);
    for _ in 0..NUM_CLASSES {
        let (tx, rx) = mpsc::channel::<Frame>(cfg.queue_capacity.max(1));
        class_txs.push(tx);
        class_rxs.push(rx);
    }

    let dispatcher_out = out_reliable.clone();
    let dispatcher_disconnects = disconnects.clone();
    let dispatcher = tokio::spawn(async move {
        loop {
            let Some(frame) = dispatcher_out.recv().await else {
                break;
            };
            let idx = usize::from(frame.class.priority());
            if let Some(tx) = class_txs.get(idx) {
                if tx.send(frame).await.is_err() {
                    dispatcher_disconnects.record(DisconnectReason::Io);
                    break;
                }
            }
        }
    });
    tasks.push(dispatcher);

    for (idx, (mut send, mut rx)) in class_sends.into_iter().zip(class_rxs).enumerate() {
        let class = TrafficClass::from_u8(u8::try_from(idx).unwrap_or(u8::MAX))
            .unwrap_or(TrafficClass::Sync);
        let chunk = class_chunk_limit(class);
        let writer_disconnects = disconnects.clone();
        let writer = tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                // Yield between large sync writes so the runtime can schedule P0.
                if frame.payload.len() > chunk {
                    tokio::task::yield_now().await;
                }
                if write_frame(&mut send, &frame).await.is_err() {
                    writer_disconnects.record(DisconnectReason::Io);
                    break;
                }
                if class == TrafficClass::Sync {
                    // Explicit yield after every sync frame so consensus writers
                    // and the QUIC stack can interleave P0 packets.
                    tokio::task::yield_now().await;
                }
            }
            let _ = send.finish();
        });
        tasks.push(writer);
    }

    let max_payload = cfg.max_payload;
    let semantic_max = cfg.semantic_max;
    for mut recv in class_recvs {
        let reader_in = in_reliable.clone();
        let reader_disconnects = disconnects.clone();
        let reader = tokio::spawn(async move {
            loop {
                let frame = match read_frame(&mut recv, max_payload).await {
                    Ok(f) => f,
                    Err(error) => {
                        reader_disconnects.record(classify_disconnect(&error));
                        break;
                    }
                };
                let idx = usize::from(frame.class.priority());
                let cap = semantic_max.get(idx).copied().unwrap_or(max_payload);
                if frame.payload.len() > cap {
                    reader_disconnects.record(DisconnectReason::Protocol);
                    break;
                }
                if reader_in.send(frame).await.is_err() {
                    break;
                }
            }
            reader_in.close();
        });
        tasks.push(reader);
    }

    // Datagram path — native QUIC DATAGRAM frames (not multiplexed on streams).
    if enable_datagrams {
        let dgram_conn = quinn_conn.clone();
        let dgram_disconnects = disconnects.clone();
        let dgram_writer = tokio::spawn(async move {
            while let Some(frame) = out_drx.recv().await {
                let Ok(bytes) = frame.encode() else {
                    continue;
                };
                // QUIC datagrams are unordered and unreliable; drop on full buffer.
                if let Err(e) = dgram_conn.send_datagram(Bytes::from(bytes)) {
                    match e {
                        quinn::SendDatagramError::UnsupportedByPeer
                        | quinn::SendDatagramError::Disabled => {
                            dgram_disconnects.record(DisconnectReason::Protocol);
                            break;
                        }
                        quinn::SendDatagramError::TooLarge => {
                            // Shed oversized datagram; do not tear down.
                            continue;
                        }
                        quinn::SendDatagramError::ConnectionLost(_) => {
                            dgram_disconnects.record(DisconnectReason::Io);
                            break;
                        }
                    }
                }
            }
        });
        tasks.push(dgram_writer);

        let dgram_conn = quinn_conn.clone();
        let dgram_max = cfg.datagram_max_bytes;
        let dgram_reader = tokio::spawn(async move {
            while let Ok(data) = dgram_conn.read_datagram().await {
                match Frame::decode_with_max(&data, dgram_max.max(FRAME_HEADER_LEN)) {
                    Ok((frame, _)) if frame.msg_type == MSG_TYPE_DATAGRAM => {
                        if frame.payload.len() <= dgram_max {
                            let _ = in_dtx.try_send(frame);
                        }
                    }
                    Ok((frame, _)) => {
                        // Unexpected reliable frame on datagram path — ignore.
                        let _ = frame;
                    }
                    Err(_) => {
                        // Malformed datagram: shed, never tear down reliable.
                    }
                }
            }
        });
        tasks.push(dgram_reader);
    } else {
        // Drain outbound datagram attempts so senders get Backpressure/Closed
        // rather than hanging if misconfigured.
        drop(out_drx);
        drop(in_dtx);
    }

    // Idle / connection-close watcher.
    let idle_out = out_reliable.clone();
    let idle_disconnects = disconnects.clone();
    let idle_conn = quinn_conn.clone();
    let idle = tokio::spawn(async move {
        let err = idle_conn.closed().await;
        let _ = err;
        idle_disconnects.record(DisconnectReason::RemoteClose);
        idle_out.close();
    });
    tasks.push(idle);

    Connection::new_with_opts(
        peer,
        out_reliable,
        in_reliable,
        out_dtx,
        in_drx,
        cfg,
        tasks,
        opts,
    )
}

/// Establish class streams after a successful control-stream handshake.
async fn open_class_streams_initiator(
    conn: &QuinnConnection,
) -> Result<(Vec<SendStream>, Vec<RecvStream>), TransportError> {
    let mut sends = Vec::with_capacity(NUM_CLASSES);
    let mut recvs = Vec::with_capacity(NUM_CLASSES);
    for class_id in 0..NUM_CLASSES {
        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        send.write_all(&[u8::try_from(class_id).unwrap_or(0)])
            .await
            .map_err(map_write_err)?;
        sends.push(send);
        recvs.push(recv);
    }
    Ok((sends, recvs))
}

async fn open_class_streams_responder(
    conn: &QuinnConnection,
) -> Result<(Vec<SendStream>, Vec<RecvStream>), TransportError> {
    let mut by_class: Vec<Option<(SendStream, RecvStream)>> =
        (0..NUM_CLASSES).map(|_| None).collect();
    for _ in 0..NUM_CLASSES {
        let (send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let mut id = [0u8; 1];
        recv.read_exact(&mut id).await.map_err(map_read_err)?;
        let class_id = id[0] as usize;
        if class_id >= NUM_CLASSES || by_class[class_id].is_some() {
            return Err(TransportError::HandshakeFailed);
        }
        by_class[class_id] = Some((send, recv));
    }
    let mut sends = Vec::with_capacity(NUM_CLASSES);
    let mut recvs = Vec::with_capacity(NUM_CLASSES);
    for slot in by_class {
        let (s, r) = slot.ok_or(TransportError::HandshakeFailed)?;
        sends.push(s);
        recvs.push(r);
    }
    Ok((sends, recvs))
}

/// A QUIC transport bound to a local UDP address, with fixed node identity.
pub struct QuicTransport {
    id: PeerId,
    keypair: Arc<KeyPair>,
    endpoint: Endpoint,
    cfg: TransportConfig,
    node_budget: Arc<ByteBudget>,
    disconnects: Arc<DisconnectMetrics>,
    membership: Arc<Mutex<Membership>>,
    peer_dedup: Arc<Mutex<PeerDedup>>,
    handshake_sem: Arc<Semaphore>,
    epoch_counter: AtomicU64,
    /// Live connection counts per peer (connection budget). Shared with the
    /// [`ConnSlot`] guards owned by live [`Connection`]s, which release their
    /// reservation on drop.
    conn_counts: Arc<Mutex<HashMap<PeerId, usize>>>,
    /// When false, datagram channels are not wired (fail-closed vs silent no-op).
    enable_datagrams: bool,
}

impl QuicTransport {
    /// Bind a QUIC endpoint at `addr` with open membership and datagrams enabled.
    pub async fn bind(
        addr: SocketAddr,
        keypair: Arc<KeyPair>,
        cfg: TransportConfig,
    ) -> Result<Self, TransportError> {
        Self::bind_with_options(addr, keypair, cfg, Membership::open(), true).await
    }

    /// Bind with explicit membership and datagram enablement.
    pub async fn bind_with_options(
        addr: SocketAddr,
        keypair: Arc<KeyPair>,
        cfg: TransportConfig,
        membership: Membership,
        enable_datagrams: bool,
    ) -> Result<Self, TransportError> {
        let (cert, key) = make_tls_cert()?;
        let server_config = make_server_config(cert.clone(), clone_private_key(&key))?;
        let mut endpoint =
            Endpoint::server(server_config, addr).map_err(|e| TransportError::Io(e.to_string()))?;
        let client_config = make_client_config(cert, key)?;
        endpoint.set_default_client_config(client_config);

        let id = PeerId::from(keypair.public());
        let max_hs = cfg.max_concurrent_handshakes.max(1);
        Ok(Self {
            id,
            keypair,
            endpoint,
            peer_dedup: Arc::new(Mutex::new(PeerDedup::with_max_jump(
                cfg.dedup_window,
                cfg.max_seq_jump,
                4096,
            ))),
            cfg,
            node_budget: ByteBudget::root(cfg.max_node_bytes),
            disconnects: Arc::new(DisconnectMetrics::default()),
            membership: Arc::new(Mutex::new(membership)),
            handshake_sem: Arc::new(Semaphore::new(max_hs)),
            epoch_counter: AtomicU64::new(1),
            conn_counts: Arc::new(Mutex::new(HashMap::new())),
            enable_datagrams,
        })
    }

    /// This node's authenticated identity.
    pub fn id(&self) -> PeerId {
        self.id
    }

    /// The bound local address.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint
            .local_addr()
            .map_err(|e| TransportError::Io(e.to_string()))
    }

    /// Shared cumulative disconnect counters.
    #[must_use]
    pub fn disconnect_metrics(&self) -> Arc<DisconnectMetrics> {
        self.disconnects.clone()
    }

    /// Whether native QUIC datagrams are enabled on this transport.
    pub fn datagrams_enabled(&self) -> bool {
        self.enable_datagrams
    }

    /// Replace membership allowlist.
    pub fn set_membership(&self, membership: Membership) {
        *self
            .membership
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = membership;
    }

    /// Reserve one connection slot for `peer` against the per-peer budget.
    ///
    /// Returns a [`ConnSlot`] guard that releases the reservation when dropped,
    /// so the budget tracks live connections rather than lifetime totals. A
    /// refused reservation never inserts an entry, keeping the map bounded.
    fn reserve_conn_slot(&self, peer: PeerId) -> Result<ConnSlot, TransportError> {
        let mut counts = self
            .conn_counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let count = counts.get(&peer).copied().unwrap_or(0);
        if count >= self.cfg.connection_budget_per_peer {
            return Err(TransportError::Backpressure {
                class: TrafficClass::Sync,
            });
        }
        counts.insert(peer, count + 1);
        drop(counts);
        Ok(ConnSlot::new(peer, self.conn_counts.clone()))
    }

    async fn finish_session(
        &self,
        quinn_conn: QuinnConnection,
        expected: Option<PeerId>,
        is_initiator: bool,
        local_epoch: u64,
    ) -> Result<Connection, TransportError> {
        let _permit = self
            .handshake_sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| TransportError::HandshakeFailed)?;

        let fut = async {
            // Control stream: mutual ed25519 handshake + negotiation.
            let (mut control_send, mut control_recv) = if is_initiator {
                quinn_conn
                    .open_bi()
                    .await
                    .map_err(|e| TransportError::Io(e.to_string()))?
            } else {
                quinn_conn
                    .accept_bi()
                    .await
                    .map_err(|e| TransportError::Io(e.to_string()))?
            };

            // Combined read/write surface for mutual_handshake.
            let mut control = ControlStream {
                send: control_send,
                recv: control_recv,
            };
            let (hs, session) = mutual_handshake(
                &mut control,
                &self.keypair,
                expected,
                is_initiator,
                &self.cfg,
                local_epoch,
            )
            .await?;
            // Keep control stream open but unused (or finish send half).
            let ControlStream { send, recv } = control;
            control_send = send;
            control_recv = recv;
            let _ = control_send.finish();
            drop(control_recv);
            let _ = session; // QUIC/TLS already encrypts; app AEAD unused on this path.

            let (sends, recvs) = if is_initiator {
                open_class_streams_initiator(&quinn_conn).await?
            } else {
                open_class_streams_responder(&quinn_conn).await?
            };

            Ok::<_, TransportError>((hs, sends, recvs))
        };

        let (hs, sends, recvs) = match timeout(self.cfg.handshake_timeout, fut).await {
            Ok(result) => result?,
            Err(_) => {
                self.disconnects.record(DisconnectReason::Authentication);
                return Err(TransportError::HandshakeTimeout);
            }
        };

        let role = {
            let m = self
                .membership
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            match m.role_of(&hs.peer) {
                Some(role) => role,
                None => {
                    // Permissioned membership: reject unknown peers on both sides.
                    self.disconnects.record(DisconnectReason::Authentication);
                    return Err(TransportError::NotInMembership);
                }
            }
        };

        let conn_slot = self.reserve_conn_slot(hs.peer)?;
        let opts = ConnectionOpts {
            epoch: hs.epoch,
            role,
            wire_version: hs.wire_version,
            capabilities: hs.capabilities,
            peer_dedup: Some(self.peer_dedup.clone()),
            conn_slot: Some(conn_slot),
        };

        Ok(spawn_quic_connection(
            quinn_conn,
            hs.peer,
            &self.cfg,
            &self.node_budget,
            self.disconnects.clone(),
            opts,
            sends,
            recvs,
            self.enable_datagrams,
        ))
    }
}

/// Thin AsyncRead+AsyncWrite adapter over a Quinn bi-stream pair for handshake I/O.
struct ControlStream {
    send: SendStream,
    recv: RecvStream,
}

impl tokio::io::AsyncRead for ControlStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Quinn RecvStream implements AsyncRead.
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for ControlStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match std::pin::Pin::new(&mut self.send).poll_write(cx, buf) {
            std::task::Poll::Ready(Ok(n)) => std::task::Poll::Ready(Ok(n)),
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(std::io::Error::other(e.to_string())))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match std::pin::Pin::new(&mut self.send).poll_flush(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(std::io::Error::other(e.to_string())))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match std::pin::Pin::new(&mut self.send).poll_shutdown(cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(e)) => {
                std::task::Poll::Ready(Err(std::io::Error::other(e.to_string())))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Clone a private key DER (not all `PrivateKeyDer` variants implement `Clone`).
fn clone_private_key(key: &PrivateKeyDer<'static>) -> PrivateKeyDer<'static> {
    match key {
        PrivateKeyDer::Pkcs8(k) => {
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(k.secret_pkcs8_der().to_vec()))
        }
        PrivateKeyDer::Sec1(k) => PrivateKeyDer::Sec1(rustls_pki_types::PrivateSec1KeyDer::from(
            k.secret_sec1_der().to_vec(),
        )),
        PrivateKeyDer::Pkcs1(k) => PrivateKeyDer::Pkcs1(
            rustls_pki_types::PrivatePkcs1KeyDer::from(k.secret_pkcs1_der().to_vec()),
        ),
        _ => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(Vec::<u8>::new())),
    }
}

impl Transport for QuicTransport {
    async fn connect(&self, peer: &Peer) -> Result<Connection, TransportError> {
        let addr = peer.addr.ok_or(TransportError::NoAddress)?;
        let connecting = self
            .endpoint
            .connect(addr, TLS_SERVER_NAME)
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let quinn_conn = timeout(self.cfg.handshake_timeout, connecting)
            .await
            .map_err(|_| TransportError::HandshakeTimeout)?
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let local_epoch = self.epoch_counter.fetch_add(1, Ordering::Relaxed);
        self.finish_session(quinn_conn, Some(peer.id), true, local_epoch)
            .await
    }

    async fn accept(&self) -> Result<Connection, TransportError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(TransportError::ConnectionClosed)?;
        let quinn_conn = timeout(self.cfg.handshake_timeout, incoming)
            .await
            .map_err(|_| TransportError::HandshakeTimeout)?
            .map_err(|e| TransportError::Io(e.to_string()))?;
        let local_epoch = self.epoch_counter.fetch_add(1, Ordering::Relaxed);
        self.finish_session(quinn_conn, None, false, local_epoch)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::class_auth::PeerRole;
    use std::time::Instant;
    use tokio::time::timeout as to;

    fn cfg() -> TransportConfig {
        TransportConfig::default()
    }

    fn kp(seed: u8) -> Arc<KeyPair> {
        Arc::new(KeyPair::from_seed(&[seed; 32]))
    }

    async fn bound(seed: u8) -> Arc<QuicTransport> {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        Arc::new(QuicTransport::bind(addr, kp(seed), cfg()).await.unwrap())
    }

    #[tokio::test]
    async fn conn_budget_releases_slots_when_guards_drop() {
        let t = bound(109).await;
        let peer = PeerId::from([42u8; 32]);
        let budget = t.cfg.connection_budget_per_peer;
        assert!(budget > 0);

        // The budget admits exactly `budget` live reservations.
        let mut slots = Vec::new();
        for _ in 0..budget {
            slots.push(t.reserve_conn_slot(peer).unwrap());
        }
        assert!(matches!(
            t.reserve_conn_slot(peer),
            Err(TransportError::Backpressure { .. })
        ));

        // Dropping one guard frees exactly one slot.
        drop(slots.pop());
        let refilled = t.reserve_conn_slot(peer).unwrap();
        assert!(matches!(
            t.reserve_conn_slot(peer),
            Err(TransportError::Backpressure { .. })
        ));

        // Releasing every slot removes the peer's entry entirely.
        drop(refilled);
        slots.clear();
        assert!(t
            .conn_counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty());
    }

    #[tokio::test]
    async fn mutual_auth_and_priority_exchange() {
        let server = bound(101).await;
        let client = bound(102).await;
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

        assert_eq!(client_conn.peer_id(), server_id);
        assert_eq!(server_conn.peer_id(), client.id());

        client_conn
            .send_priority(TrafficClass::Consensus, b"p0-vote")
            .unwrap();
        let got = to(Duration::from_secs(5), server_conn.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.payload, b"p0-vote");
        assert_eq!(got.class, TrafficClass::Consensus);

        server_conn
            .send_priority(TrafficClass::Sync, b"chunk")
            .unwrap();
        let back = to(Duration::from_secs(5), client_conn.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(back.payload, b"chunk");
        assert_eq!(back.class, TrafficClass::Sync);
    }

    #[tokio::test]
    async fn real_datagram_round_trip() {
        let server = bound(103).await;
        let client = bound(104).await;
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
        let got = to(Duration::from_secs(5), server_conn.recv_datagram())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, b"tick");
    }

    #[tokio::test]
    async fn saturating_sync_does_not_block_p0() {
        // Core HOL-isolation acceptance: a flood of max-ish sync frames must not
        // prevent a P0 consensus frame from arriving within a tight SLA.
        let mut c = cfg();
        c.queue_capacity = 256;
        c.max_class_bytes = 64 * 1024 * 1024;
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = Arc::new(QuicTransport::bind(addr, kp(110), c).await.unwrap());
        let client = Arc::new(QuicTransport::bind(addr, kp(111), c).await.unwrap());
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

        // Large sync payloads (256 KiB) — enough to HOL-block TCP for a long time
        // on a single stream, but independent QUIC streams must let P0 through.
        let sync_payload = vec![0xABu8; 256 * 1024];
        let p0_payload = b"CONSENSUS-VOTE";

        let client_for_sync = client_conn;
        let sync_flood = tokio::spawn(async move {
            for _ in 0..32 {
                loop {
                    match client_for_sync.send_priority(TrafficClass::Sync, &sync_payload) {
                        Ok(()) => break,
                        Err(TransportError::Backpressure { .. }) => {
                            tokio::task::yield_now().await;
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
            // Inject P0 after the flood is queued.
            let start = Instant::now();
            client_for_sync
                .send_priority(TrafficClass::Consensus, p0_payload)
                .unwrap();
            Ok::<_, TransportError>((client_for_sync, start))
        });

        // Receiver: wait specifically for the P0 frame; ignore sync as it arrives.
        let p0_deadline = Duration::from_millis(500);
        let started = Instant::now();
        let mut saw_p0 = false;
        while started.elapsed() < Duration::from_secs(10) {
            match to(Duration::from_millis(200), server_conn.recv()).await {
                Ok(Ok(frame)) if frame.class == TrafficClass::Consensus => {
                    assert_eq!(frame.payload, p0_payload);
                    saw_p0 = true;
                    break;
                }
                Ok(Ok(_)) => continue, // sync frame
                Ok(Err(e)) => panic!("recv failed: {e}"),
                Err(_) => continue,
            }
        }
        assert!(saw_p0, "P0 consensus must arrive despite sync saturation");
        let (_conn, p0_sent_at) = sync_flood.await.unwrap().unwrap();
        let p0_latency = p0_sent_at.elapsed();
        assert!(
            p0_latency < p0_deadline,
            "P0 latency {p0_latency:?} exceeded SLA {p0_deadline:?} under sync load"
        );
    }

    #[tokio::test]
    async fn datagram_loss_does_not_delay_reliable() {
        let server = bound(120).await;
        let client = bound(121).await;
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

        // Flood datagrams (may be shed) then send a reliable P0.
        for i in 0..64u32 {
            let _ = client_conn.send_datagram(&i.to_le_bytes());
        }
        client_conn
            .send_priority(TrafficClass::Consensus, b"after-dgrams")
            .unwrap();

        let start = Instant::now();
        let mut saw = false;
        while start.elapsed() < Duration::from_secs(5) {
            // Drain any datagrams without blocking reliable.
            while let Ok(Ok(_)) = to(Duration::from_millis(1), server_conn.recv_datagram()).await {}
            if let Ok(Ok(frame)) = to(Duration::from_millis(50), server_conn.recv()).await {
                if frame.class == TrafficClass::Consensus {
                    assert_eq!(frame.payload, b"after-dgrams");
                    saw = true;
                    break;
                }
            }
        }
        assert!(saw, "reliable P0 must not wait on datagram flood");
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "reliable delivery delayed by datagrams: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn forged_identity_rejected() {
        let server = bound(130).await;
        let client = bound(131).await;
        let server_addr = server.local_addr().unwrap();
        let acceptor = {
            let server = server.clone();
            tokio::spawn(async move {
                let _ = server.accept().await;
            })
        };
        let wrong = PeerId::from([0xAAu8; 32]);
        let result = client.connect(&Peer::dial(wrong, server_addr)).await;
        assert!(
            matches!(
                result,
                Err(TransportError::AuthFailed)
                    | Err(TransportError::HandshakeFailed)
                    | Err(TransportError::HandshakeTimeout)
                    | Err(TransportError::Io(_))
                    | Err(TransportError::ConnectionClosed)
            ),
            "forged identity must fail, got {result:?}"
        );
        let _ = acceptor.await;
    }

    #[tokio::test]
    async fn network_id_mismatch_rejected() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut server_cfg = cfg();
        server_cfg.network_id = 42;
        let mut client_cfg = cfg();
        client_cfg.network_id = 99;
        let server = Arc::new(
            QuicTransport::bind(addr, kp(140), server_cfg)
                .await
                .unwrap(),
        );
        let client = Arc::new(
            QuicTransport::bind(addr, kp(141), client_cfg)
                .await
                .unwrap(),
        );
        let server_addr = server.local_addr().unwrap();
        let server_id = server.id();
        let acceptor = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await })
        };
        let client_result = client.connect(&Peer::dial(server_id, server_addr)).await;
        let _ = acceptor.await;
        assert!(
            matches!(
                client_result,
                Err(TransportError::NetworkMismatch { .. })
                    | Err(TransportError::AuthFailed)
                    | Err(TransportError::Io(_))
                    | Err(TransportError::ConnectionClosed)
                    | Err(TransportError::HandshakeFailed)
            ),
            "expected network mismatch, got {client_result:?}"
        );
    }

    #[tokio::test]
    async fn membership_rejects_unknown_on_accept() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let allowed = PeerId::from(kp(99).public());
        let membership = Membership::allowlist([(allowed, PeerRole::Validator)]);
        let server = Arc::new(
            QuicTransport::bind_with_options(addr, kp(150), cfg(), membership, true)
                .await
                .unwrap(),
        );
        let client = Arc::new(QuicTransport::bind(addr, kp(151), cfg()).await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let server_id = server.id();
        let acceptor = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await })
        };
        let client_result = client.connect(&Peer::dial(server_id, server_addr)).await;
        let accept_result = acceptor.await.unwrap();
        assert!(
            matches!(accept_result, Err(TransportError::NotInMembership)) || client_result.is_err(),
            "unknown peer must be rejected: accept={accept_result:?} client={client_result:?}"
        );
    }
}

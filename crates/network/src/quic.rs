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
//! * every stream shares one **uniform** 2 MiB receive window — quinn's
//!   `TransportConfig` cannot size receive windows per stream — so cross-class
//!   precedence is enforced on the transmit side: each class stream carries a
//!   transmit priority (`SendStream::set_priority`, set at stream open) under
//!   which quinn drains Consensus first and Sync last when the path is
//!   congested, and sync writers additionally chunk and yield aggressively.
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
//! # Concurrent acceptance (#405)
//!
//! Like [`crate::TcpTransport`], inbound admission is pumped: an internal task
//! drains the endpoint's incoming queue continuously and runs each handshake
//! on its own task, gated non-blockingly by the handshake semaphore. On
//! exhaustion new attempts are refused immediately (fail-closed shed) instead
//! of stalling admission, so a slow or half-open peer never delays a
//! well-behaved peer's acceptance.
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
    ClientConfig, Connection as QuinnConnection, Endpoint, Incoming, RecvStream, SendStream,
    ServerConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::Mutex as AsyncMutex;
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

/// Chunking hint for P0 consensus writers (bytes). **Not** a receive window:
/// quinn's `TransportConfig` applies one uniform window to every stream (see
/// `MID_STREAM_WINDOW`); this value only tunes writer yielding via
/// `class_chunk_limit`.
const P0_STREAM_WINDOW: u32 = 4 * 1024 * 1024;
/// The uniform per-stream receive window `transport_config` applies to
/// **every** stream — quinn 0.11 cannot size receive windows per stream, so
/// there is no per-class receive-window isolation. Cross-class precedence
/// comes from per-stream transmit priorities (`class_stream_priority`) plus
/// writer chunking (`class_chunk_limit`).
const MID_STREAM_WINDOW: u32 = 2 * 1024 * 1024;
/// Chunking hint for P8 sync writers (bytes): sync frames are chunked to a
/// quarter of this so the sync writer yields often. **Not** a receive window
/// (see `MID_STREAM_WINDOW`).
const SYNC_STREAM_WINDOW: u32 = 512 * 1024;
/// Connection-level receive window: deliberately below 9 × the uniform stream
/// window, so the class streams can never all hold full credit at once, and
/// any single stream (sync included) holds at most `MID_STREAM_WINDOW` of it.
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
    // Connection window deliberately below 9 × the uniform stream window so the
    // class streams can never all hold full credit simultaneously; any single
    // stream (sync included) is capped at one stream window of it.
    t.receive_window(quinn::VarInt::from_u32(CONN_RECEIVE_WINDOW));
    // quinn sizes ONE uniform receive window for every stream — per-class
    // receive windows are not expressible in TransportConfig. Cross-class
    // precedence is enforced by transmit priorities set at stream open
    // (class_stream_priority) plus sync writer chunking (class_chunk_limit).
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

/// Transmit priority for the class stream carrying `class_id`.
///
/// quinn drains pending data from higher-priority streams first, so Consensus
/// (class 0) maps to the **largest** value and Sync (class `NUM_CLASSES - 1`)
/// to the smallest: strictly monotonic decreasing over the valid class range.
/// Total and panic-free — out-of-range ids saturate to the lowest priority.
fn class_stream_priority(class_id: usize) -> i32 {
    let inverted = NUM_CLASSES.saturating_sub(1).saturating_sub(class_id);
    i32::try_from(inverted).unwrap_or(0)
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

    // Per-connection datagram clamp (#415). A native QUIC DATAGRAM must fit
    // the path's max datagram frame size (~1200 bytes at handshake), which is
    // only known once the connection is established — far below the configured
    // `datagram_max_bytes` default (64 KiB). Clamp the payload ceiling for
    // *this connection* to what the path can actually carry (minus the frame
    // header the writer prepends), so `Connection::send_datagram` rejects an
    // uncarriable payload synchronously with `MessageTooLarge` instead of
    // accepting it and having the datagram writer silently shed it on the
    // wire. `None` (datagrams unsupported/disabled by the peer) clamps to 0,
    // making every datagram send fail typed — consistent with the writer's
    // fail-closed handling of `UnsupportedByPeer`/`Disabled`. The global
    // default is untouched; other transports (TCP multiplexes datagrams over
    // the reliable stream) keep the configured ceiling.
    let mut cfg = *cfg;
    cfg.datagram_max_bytes = cfg.datagram_max_bytes.min(
        quinn_conn
            .max_datagram_size()
            .unwrap_or(0)
            .saturating_sub(FRAME_HEADER_LEN),
    );

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

    // One writer task per class, each pulling **its own class** directly from
    // the shared strict-priority channel (`recv_class`). There is deliberately
    // no central dispatcher: a dispatcher forwarding into per-class relay
    // queues re-introduces cross-class head-of-line blocking the moment one
    // class's relay fills while its writer is parked on QUIC stream
    // flow-control credit — the dispatcher parks on that one full relay and
    // stops dispatching every other class, including P0 consensus (#395).
    // With per-class pulls, a parked Sync writer leaves frames queued in the
    // Sync class only; every other writer keeps draining independently, each
    // class stays FIFO, and cross-class precedence is expressed by the QUIC
    // transmit priorities already set (fail-closed) when the class streams
    // were opened — see class_stream_priority and open_class_streams_*.
    for (idx, mut send) in class_sends.into_iter().enumerate() {
        let class = TrafficClass::from_u8(u8::try_from(idx).unwrap_or(u8::MAX))
            .unwrap_or(TrafficClass::Sync);
        let chunk = class_chunk_limit(class);
        let writer_out = out_reliable.clone();
        let writer_disconnects = disconnects.clone();
        let writer = tokio::spawn(async move {
            while let Some(frame) = writer_out.recv_class(class).await {
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
                let encoded_len = bytes.len();
                // QUIC datagrams are unordered and unreliable; drop on full buffer.
                if let Err(e) = dgram_conn.send_datagram(Bytes::from(bytes)) {
                    match e {
                        quinn::SendDatagramError::UnsupportedByPeer
                        | quinn::SendDatagramError::Disabled => {
                            dgram_disconnects.record(DisconnectReason::Protocol);
                            break;
                        }
                        quinn::SendDatagramError::TooLarge => {
                            // Send-side clamping is the primary guard: the
                            // per-connection `datagram_max_bytes` clamp in
                            // `spawn_quic_connection` makes `send_datagram`
                            // reject anything the path could not carry at
                            // handshake time with `MessageTooLarge`. Reaching
                            // this arm therefore means the path MTU shrank
                            // after the clamp; datagrams are lossy by
                            // contract, so shed this one datagram — never
                            // tear down the whole connection for it.
                            tracing::debug!(
                                encoded_len,
                                max = ?dgram_conn.max_datagram_size(),
                                "QUIC datagram exceeded shrunken path max; shed"
                            );
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
        &cfg,
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
        // Higher classes drain first when the path is congested. Fail closed:
        // a stream that is already closed means the connection is unusable.
        send.set_priority(class_stream_priority(class_id))
            .map_err(|_closed| TransportError::ConnectionClosed)?;
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
    for (class_id, slot) in by_class.into_iter().enumerate() {
        let (s, r) = slot.ok_or(TransportError::HandshakeFailed)?;
        // Mirror the initiator: this side's transmit scheduling must also
        // drain higher classes first. Fail closed on an already-closed stream.
        s.set_priority(class_stream_priority(class_id))
            .map_err(|_closed| TransportError::ConnectionClosed)?;
        sends.push(s);
        recvs.push(r);
    }
    Ok((sends, recvs))
}

/// Shared state each accepted-connection handshake task needs. All fields are
/// cheap shared handles (or `Copy`), so per-connection clones are O(1).
#[derive(Clone)]
struct AcceptCtx {
    keypair: Arc<KeyPair>,
    cfg: TransportConfig,
    node_budget: Arc<ByteBudget>,
    disconnects: Arc<DisconnectMetrics>,
    membership: Arc<Mutex<Membership>>,
    peer_dedup: Arc<Mutex<PeerDedup>>,
    conn_counts: Arc<Mutex<HashMap<PeerId, usize>>>,
    epoch_counter: Arc<AtomicU64>,
    /// When false, datagram channels are not wired (fail-closed vs silent no-op).
    enable_datagrams: bool,
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
    /// Handshake concurrency limiter: awaited by dials, taken non-blockingly
    /// (fail-closed refusal) by the accept pump.
    handshake_sem: Arc<Semaphore>,
    /// Monotonic epoch counter for outbound sessions (shared with the pump).
    epoch_counter: Arc<AtomicU64>,
    /// Live connection counts per peer (connection budget). Shared with the
    /// [`ConnSlot`] guards owned by live [`Connection`]s, which release their
    /// reservation on drop.
    conn_counts: Arc<Mutex<HashMap<PeerId, usize>>>,
    /// When false, datagram channels are not wired (fail-closed vs silent no-op).
    enable_datagrams: bool,
    /// Completed handshake results fed by the accept pump (see [`accept_pump`]).
    accepted_rx: AsyncMutex<mpsc::Receiver<Result<Connection, TransportError>>>,
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
    ///
    /// Spawns the internal accept pump: inbound handshakes run concurrently
    /// (bounded by [`TransportConfig::max_concurrent_handshakes`]) and
    /// [`Transport::accept`] yields each result as it completes.
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
        let (accepted_tx, accepted_rx) = mpsc::channel(cfg.accept_queue_capacity.max(1));
        let transport = Self {
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
            epoch_counter: Arc::new(AtomicU64::new(1)),
            conn_counts: Arc::new(Mutex::new(HashMap::new())),
            enable_datagrams,
            accepted_rx: AsyncMutex::new(accepted_rx),
        };
        tokio::spawn(accept_pump(
            transport.endpoint.clone(),
            transport.handshake_sem.clone(),
            transport.accept_ctx(),
            accepted_tx,
        ));
        Ok(transport)
    }

    /// Assemble the shared state the accept pump's handshake tasks need.
    fn accept_ctx(&self) -> AcceptCtx {
        AcceptCtx {
            keypair: self.keypair.clone(),
            cfg: self.cfg,
            node_budget: self.node_budget.clone(),
            disconnects: self.disconnects.clone(),
            membership: self.membership.clone(),
            peer_dedup: self.peer_dedup.clone(),
            conn_counts: self.conn_counts.clone(),
            epoch_counter: self.epoch_counter.clone(),
            enable_datagrams: self.enable_datagrams,
        }
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
    /// Test-only surface over [`ConnSlot::reserve`]; production paths reserve
    /// through [`finish_session`], which shares the same counts map.
    #[cfg(test)]
    fn reserve_conn_slot(&self, peer: PeerId) -> Result<ConnSlot, TransportError> {
        ConnSlot::reserve(&self.conn_counts, self.cfg.connection_budget_per_peer, peer)
    }
}

/// Run the authenticated control-stream handshake on an established QUIC
/// connection, apply the membership check, reserve the connection slot
/// (post-handshake, so failed handshakes consume no slot), open the per-class
/// streams, and wire the finished [`Connection`].
///
/// Concurrency gating is the caller's job: dials await the handshake
/// semaphore, while the accept pump's tasks hold a `try_acquire`d permit.
async fn finish_session(
    ctx: &AcceptCtx,
    quinn_conn: QuinnConnection,
    expected: Option<PeerId>,
    is_initiator: bool,
    local_epoch: u64,
) -> Result<Connection, TransportError> {
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
            &ctx.keypair,
            expected,
            is_initiator,
            &ctx.cfg,
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

    let (hs, sends, recvs) = match timeout(ctx.cfg.handshake_timeout, fut).await {
        Ok(result) => result?,
        Err(_) => {
            ctx.disconnects.record(DisconnectReason::Authentication);
            return Err(TransportError::HandshakeTimeout);
        }
    };

    let role = {
        let m = ctx
            .membership
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match m.role_of(&hs.peer) {
            Some(role) => role,
            None => {
                // Permissioned membership: reject unknown peers on both sides.
                ctx.disconnects.record(DisconnectReason::Authentication);
                return Err(TransportError::NotInMembership);
            }
        }
    };

    let conn_slot = ConnSlot::reserve(
        &ctx.conn_counts,
        ctx.cfg.connection_budget_per_peer,
        hs.peer,
    )?;
    let opts = ConnectionOpts {
        epoch: hs.epoch,
        role,
        wire_version: hs.wire_version,
        capabilities: hs.capabilities,
        peer_dedup: Some(ctx.peer_dedup.clone()),
        conn_slot: Some(conn_slot),
    };

    Ok(spawn_quic_connection(
        quinn_conn,
        hs.peer,
        &ctx.cfg,
        &ctx.node_budget,
        ctx.disconnects.clone(),
        opts,
        sends,
        recvs,
        ctx.enable_datagrams,
    ))
}

/// Everything `accept` does after a raw incoming connection attempt is
/// admitted: the QUIC/TLS establishment and the full authenticated session
/// setup, each bounded by the handshake timeout. Runs on its own task so one
/// slow or half-open peer never delays another peer's admission.
async fn accept_one(incoming: Incoming, ctx: &AcceptCtx) -> Result<Connection, TransportError> {
    let quinn_conn = timeout(ctx.cfg.handshake_timeout, incoming)
        .await
        .map_err(|_| TransportError::HandshakeTimeout)?
        .map_err(|e| TransportError::Io(e.to_string()))?;
    let local_epoch = ctx.epoch_counter.fetch_add(1, Ordering::Relaxed);
    finish_session(ctx, quinn_conn, None, false, local_epoch).await
}

/// Accept pump: drains the endpoint's incoming queue independently of any
/// in-flight handshake (#405).
///
/// Each incoming connection attempt is gated by a **non-blocking**
/// `try_acquire_owned` on the handshake semaphore — on exhaustion it is
/// refused immediately (fail-closed shed, recorded as
/// [`DisconnectReason::Backpressure`]) so a saturated semaphore can never
/// stall admission — and each surviving attempt's handshake runs on its own
/// task holding the permit. Results (ready [`Connection`]s and per-connection
/// failures alike) are handed to [`QuicTransport::accept`] through a bounded
/// channel. The pump exits when the endpoint closes or the owning transport
/// (the channel receiver) is dropped.
async fn accept_pump(
    endpoint: Endpoint,
    handshake_sem: Arc<Semaphore>,
    ctx: AcceptCtx,
    results: mpsc::Sender<Result<Connection, TransportError>>,
) {
    loop {
        let incoming = tokio::select! {
            // The transport was dropped: stop pumping.
            () = results.closed() => return,
            incoming = endpoint.accept() => incoming,
        };
        // `None` means the endpoint is closed: no further connections will
        // arrive. Dropping the pump's sender lets pending `accept()` callers
        // observe `ConnectionClosed` once in-flight handshakes drain.
        let Some(incoming) = incoming else { return };
        // Fail-closed shed: never await the semaphore here — a half-open
        // flood pinning every permit must not stop admission draining.
        let Ok(permit) = handshake_sem.clone().try_acquire_owned() else {
            ctx.disconnects.record(DisconnectReason::Backpressure);
            incoming.refuse();
            continue;
        };
        let task_ctx = ctx.clone();
        let task_results = results.clone();
        tokio::spawn(async move {
            // The permit spans the handshake and the result handoff, bounding
            // concurrently pinned connections/tasks under a half-open flood.
            let _permit = permit;
            let result = accept_one(incoming, &task_ctx).await;
            let _ = task_results.send(result).await;
        });
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
        // Dialer-side handshake concurrency limit. Awaiting here (unlike the
        // accept pump's fail-closed try-acquire) only delays our own outbound
        // dial, never another peer's admission.
        let _permit = self
            .handshake_sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| TransportError::HandshakeFailed)?;
        finish_session(
            &self.accept_ctx(),
            quinn_conn,
            Some(peer.id),
            true,
            local_epoch,
        )
        .await
    }

    /// Yield the next completed inbound handshake result from the accept pump.
    ///
    /// Handshakes run concurrently on their own tasks (see `accept_pump`), so
    /// this never blocks on any single slow or half-open peer. Errors are
    /// per-connection: a failed handshake (timeout, membership rejection, ...)
    /// surfaces here exactly as it did when accept ran the handshake inline.
    async fn accept(&self) -> Result<Connection, TransportError> {
        match self.accepted_rx.lock().await.recv().await {
            Some(result) => result,
            // Pump gone (endpoint closed or transport shutting down).
            None => Err(TransportError::ConnectionClosed),
        }
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
    async fn datagram_over_path_max_rejected_synchronously_at_send() {
        // #415: the configured `datagram_max_bytes` default (64 KiB) is far
        // above what a QUIC DATAGRAM frame can carry (path MTU ~1200 bytes).
        // Before the per-connection clamp, send_datagram accepted such a
        // payload and the datagram writer silently shed it on the wire
        // (`SendDatagramError::TooLarge` -> continue). With the clamp, the
        // sender must learn immediately via a typed error.
        let server = bound(140).await;
        let client = bound(141).await;
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

        // 64 KiB was accepted (then dropped) before the fix; it must now be
        // rejected synchronously — not Ok, not silently shed.
        let oversized = vec![0u8; crate::connection::DEFAULT_DATAGRAM_MAX_BYTES];
        assert!(matches!(
            client_conn.send_datagram(&oversized),
            Err(TransportError::MessageTooLarge)
        ));

        // A payload the path can carry (well under the ~1200-byte QUIC
        // datagram floor, minus the frame header) still sends and arrives.
        let within = vec![7u8; 512];
        client_conn.send_datagram(&within).unwrap();
        let got = to(Duration::from_secs(5), server_conn.recv_datagram())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, within);
    }

    #[test]
    fn datagram_clamp_arithmetic_bounds_payload_to_path() {
        // The clamp applied per connection in `spawn_quic_connection`:
        // payload ceiling = min(configured, path_max - header). `None`
        // (datagrams unsupported) clamps to 0 so all sends fail typed.
        let clamp = |configured: usize, path_max: Option<usize>| -> usize {
            configured.min(path_max.unwrap_or(0).saturating_sub(FRAME_HEADER_LEN))
        };
        // Typical post-handshake path max: ceiling shrinks to fit the frame.
        assert_eq!(clamp(64 * 1024, Some(1200)), 1200 - FRAME_HEADER_LEN);
        // Configured below the path max: configured wins (no widening).
        assert_eq!(clamp(256, Some(1200)), 256);
        // Peer without datagram support: everything is rejected at send.
        assert_eq!(clamp(64 * 1024, None), 0);
        // Degenerate path max below the header never underflows.
        assert_eq!(clamp(64 * 1024, Some(FRAME_HEADER_LEN - 1)), 0);
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

    /// Regression for #395: saturate the Sync pipeline end to end — the server
    /// does not drain, so its Sync class fills, its Sync reader parks, QUIC
    /// stream flow-control credit exhausts, the client's Sync writer parks on
    /// `write_frame`, and the client's Sync class queue fills to backpressure.
    /// A P0 consensus frame enqueued at that point must still be dispatched
    /// onto its own stream and delivered. With the old single-dispatcher
    /// design the dispatcher parked forwarding Sync into its full relay queue
    /// and stopped dispatching every class, so the consensus frame never left
    /// the client's queue.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn parked_sync_class_does_not_block_consensus_dispatch() {
        let mut c = cfg();
        c.queue_capacity = 8;
        c.max_class_bytes = 64 * 1024 * 1024;
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = Arc::new(QuicTransport::bind(addr, kp(160), c).await.unwrap());
        let client = Arc::new(QuicTransport::bind(addr, kp(161), c).await.unwrap());
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

        // 256 KiB sync payloads: a handful exhaust the 2 MiB per-stream receive
        // window once the server-side reader is parked on its full Sync class.
        let sync_payload = vec![0x5Au8; 256 * 1024];
        let mut accepted = 0u32;
        let mut backpressured = false;
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(20) {
            match client_conn.send_priority(TrafficClass::Sync, &sync_payload) {
                Ok(()) => accepted += 1,
                Err(TransportError::Backpressure { .. }) => {
                    backpressured = true;
                    // Confirm the stall is sustained (the writer is parked on
                    // stream credit, not a transient scheduling hiccup): the
                    // class must still be full after a settle delay.
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    match client_conn.send_priority(TrafficClass::Sync, &sync_payload) {
                        Ok(()) => accepted += 1,
                        Err(TransportError::Backpressure { .. }) => break,
                        Err(e) => panic!("unexpected send error: {e}"),
                    }
                }
                Err(e) => panic!("unexpected send error: {e}"),
            }
        }
        assert!(
            backpressured,
            "sync pipeline must saturate for this regression ({accepted} accepted)"
        );
        assert!(
            client_conn.pending_outbound() > 0,
            "the sync class queue must still hold parked frames"
        );

        // The regression: with Sync fully parked, a P0 frame must still be
        // accepted (its class is empty) *and* dispatched onto its own stream.
        client_conn
            .send_priority(TrafficClass::Consensus, b"P0-VOTE-UNDER-SYNC-PARK")
            .unwrap();

        // The server has drained nothing; the consensus frame must arrive over
        // its independent stream while the sync stream stays parked.
        let deadline = Instant::now() + Duration::from_secs(5);
        while server_conn.inbound_class_bytes(TrafficClass::Consensus) == 0 {
            assert!(
                Instant::now() < deadline,
                "consensus frame never dispatched: cross-class head-of-line blocking"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Strict priority on the inbound queue then delivers the P0 frame
        // ahead of the entire queued sync backlog.
        let got = to(Duration::from_secs(5), server_conn.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.class, TrafficClass::Consensus);
        assert_eq!(got.payload, b"P0-VOTE-UNDER-SYNC-PARK");
    }

    /// Wakeup correctness: with all nine class writers parked on their empty
    /// classes, a frame enqueued for one specific class must wake exactly that
    /// class's writer and be delivered — for every class.
    #[tokio::test]
    async fn every_class_writer_wakes_for_its_own_class() {
        let server = bound(170).await;
        let client = bound(171).await;
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

        // Let every writer task reach its parked recv_class await first, so
        // each subsequent enqueue exercises a real wakeup (not a pre-check).
        tokio::time::sleep(Duration::from_millis(50)).await;

        for class_byte in 0..u8::try_from(NUM_CLASSES).unwrap() {
            let class = TrafficClass::from_u8(class_byte).unwrap();
            let payload = vec![class_byte; 8];
            client_conn.send_priority(class, &payload).unwrap();
            let got = to(Duration::from_secs(5), server_conn.recv())
                .await
                .unwrap_or_else(|_| panic!("writer for {class:?} never woke"))
                .unwrap();
            assert_eq!(got.class, class);
            assert_eq!(got.payload, payload);
        }
    }

    /// #414: the transmit-priority mapping must be strictly monotonic —
    /// Consensus (class 0) outranks every class down to Sync (class 8) — and
    /// total (panic-free) over any input.
    #[test]
    fn class_stream_priority_is_monotonic_consensus_first() {
        assert!(
            class_stream_priority(0) > class_stream_priority(NUM_CLASSES - 1),
            "Consensus must strictly outrank Sync"
        );
        for class_id in 1..NUM_CLASSES {
            assert!(
                class_stream_priority(class_id - 1) > class_stream_priority(class_id),
                "priority must strictly decrease from class {} to class {}",
                class_id - 1,
                class_id
            );
        }
        // Sync is the floor, and out-of-range ids saturate to that floor
        // instead of panicking.
        assert_eq!(class_stream_priority(NUM_CLASSES - 1), 0);
        assert_eq!(class_stream_priority(NUM_CLASSES), 0);
        assert_eq!(class_stream_priority(usize::MAX), 0);
    }

    /// A raw quinn server endpoint sharing the transport's TLS/transport
    /// config, without the accept pump (so tests can drive streams directly).
    fn raw_server_endpoint() -> Endpoint {
        let (cert, key) = make_tls_cert().unwrap();
        let server_config = make_server_config(cert, key).unwrap();
        Endpoint::server(server_config, "127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap()
    }

    /// #414: opening the class streams must apply the transmit priority on
    /// **both** sides — initiator and responder — with Consensus strictly
    /// above Sync, matching `class_stream_priority` exactly.
    #[tokio::test]
    async fn class_streams_carry_transmit_priorities_on_both_sides() {
        let server = raw_server_endpoint();
        let server_addr = server.local_addr().unwrap();
        let client = raw_client_endpoint();

        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let streams = open_class_streams_responder(&conn).await;
            (conn, streams)
        });
        let client_conn = client
            .connect(server_addr, TLS_SERVER_NAME)
            .unwrap()
            .await
            .unwrap();
        let (client_sends, _client_recvs) =
            open_class_streams_initiator(&client_conn).await.unwrap();
        let (_server_conn, server_streams) = server_task.await.unwrap();
        let (server_sends, _server_recvs) = server_streams.unwrap();

        for sends in [&client_sends, &server_sends] {
            assert_eq!(sends.len(), NUM_CLASSES);
            for (class_id, send) in sends.iter().enumerate() {
                assert_eq!(
                    send.priority().unwrap(),
                    class_stream_priority(class_id),
                    "class {class_id} stream must carry its mapped transmit priority"
                );
            }
            // The property that matters for #414: Consensus drains strictly
            // ahead of Sync when the path is congested.
            assert!(
                sends[0].priority().unwrap() > sends[NUM_CLASSES - 1].priority().unwrap(),
                "Consensus stream priority must strictly exceed Sync's"
            );
        }
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

    /// A raw quinn client endpoint that completes QUIC/TLS but never runs the
    /// authenticated application handshake — a half-open peer from the
    /// transport's point of view.
    fn raw_client_endpoint() -> Endpoint {
        let (cert, key) = make_tls_cert().unwrap();
        let mut endpoint = Endpoint::client("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
        endpoint.set_default_client_config(make_client_config(cert, key).unwrap());
        endpoint
    }

    /// Regression for #405: acceptance must be concurrent. A half-open peer
    /// that completes QUIC/TLS but never starts the control-stream handshake
    /// used to pin the (serialized) accept path for the full 5 s handshake
    /// timeout, stalling every other peer. With the accept pump, the
    /// well-behaved peer must be admitted while the half-open handshake is
    /// still pending.
    #[tokio::test]
    async fn half_open_peer_does_not_block_other_accepts() {
        let server = bound(180).await;
        let client = bound(181).await;
        let server_addr = server.local_addr().unwrap();
        let server_id = server.id();

        // Half-open peer: QUIC established, control stream never opened. Keep
        // the connection alive so its handshake task stays pending server-side.
        let half_open = raw_client_endpoint();
        let stalled = half_open
            .connect(server_addr, TLS_SERVER_NAME)
            .unwrap()
            .await
            .unwrap();
        // Let the pump admit the half-open attempt first, so its handshake is
        // already in flight when the well-behaved peer arrives.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let acceptor = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await })
        };
        // Both bounds are far below the 5 s handshake timeout that used to
        // serialize acceptance behind the half-open peer.
        let client_conn = to(
            Duration::from_secs(2),
            client.connect(&Peer::dial(server_id, server_addr)),
        )
        .await
        .expect("well-behaved connect must not wait behind a half-open peer")
        .unwrap();
        let server_conn = to(Duration::from_secs(2), acceptor)
            .await
            .expect("accept() must yield the ready peer while the half-open handshake is pending")
            .unwrap()
            .unwrap();

        assert_eq!(client_conn.peer_id(), server_id);
        assert_eq!(server_conn.peer_id(), client.id());
        drop(stalled);
    }

    /// Regression for #405 (fail-closed shed): when every handshake permit is
    /// pinned by half-open peers, excess incoming connections must be refused
    /// immediately — never parked behind the stalled handshakes — and
    /// acceptance must recover once the stalled handshakes time out and
    /// release their permits.
    #[tokio::test]
    async fn saturated_handshake_budget_refuses_excess_conns_without_stalling() {
        let mut c = cfg();
        c.max_concurrent_handshakes = 1;
        c.handshake_timeout = Duration::from_millis(400);
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = Arc::new(QuicTransport::bind(addr, kp(190), c).await.unwrap());
        let server_addr = server.local_addr().unwrap();

        // One half-open connection pins the only handshake permit. The permit
        // is taken at admission, before QUIC/TLS completes, so once this
        // connect resolves the budget is saturated.
        let raw = raw_client_endpoint();
        let _pinned = raw
            .connect(server_addr, TLS_SERVER_NAME)
            .unwrap()
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Budget exhausted: the next attempt is refused fail-closed. A prompt
        // (refused) resolution proves the pump kept draining incoming attempts
        // rather than stalling on the saturated semaphore.
        let refused = to(
            Duration::from_secs(2),
            raw.connect(server_addr, TLS_SERVER_NAME).unwrap(),
        )
        .await
        .expect("shed must be prompt — a saturated semaphore must not stall the accept pump");
        assert!(
            refused.is_err(),
            "excess connection must be refused, got a connection"
        );
        assert!(
            server
                .disconnect_metrics()
                .get(DisconnectReason::Backpressure)
                >= 1,
            "fail-closed shed must be recorded as a Backpressure disconnect"
        );

        // Once the pinned handshake times out and releases its permit, a
        // well-behaved peer is admitted again.
        let client = bound(191).await;
        let mut recovered = None;
        for _ in 0..8 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            match to(
                Duration::from_secs(2),
                client.connect(&Peer::dial(server.id(), server_addr)),
            )
            .await
            {
                Ok(Ok(conn)) => {
                    recovered = Some(conn);
                    break;
                }
                Ok(Err(_)) | Err(_) => continue,
            }
        }
        let conn =
            recovered.expect("acceptance must recover after the half-open handshake times out");
        assert_eq!(conn.peer_id(), server.id());
    }
}

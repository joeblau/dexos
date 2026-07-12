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
//! 1. each side sends
//!    `public_key(32) || nonce(32) || ephemeral_x25519_pub(32)
//!     || network_id(8) || min_ver(2) || max_ver(2) || capabilities(8)
//!     || epoch(8)`;
//! 2. each side signs the *peer's* nonce, bound into a transcript that also
//!    covers the network identity, version range, capabilities, epoch, and
//!    both ephemeral keys;
//! 3. each side verifies the peer's signature, negotiates the highest common
//!    wire version, intersects capability bits, and rejects network-id
//!    mismatches or empty version overlap with a typed pre-application error.
//!
//! The dialer additionally checks the peer's public key equals the *expected*
//! [`PeerId`]. When membership is configured, the accepter rejects unknown
//! peers.
//!
//! # Concurrent acceptance (#405)
//!
//! Inbound admission is pumped: an internal task drains the raw listener
//! backlog continuously and runs **each** handshake on its own task, bounded
//! by [`TransportConfig::handshake_timeout`]. The handshake concurrency
//! semaphore is taken *non-blockingly* at admission — when all permits are
//! pinned by in-flight (possibly half-open) handshakes, new sockets are shed
//! immediately (fail-closed, recorded as [`DisconnectReason::Backpressure`])
//! instead of stalling the pump. [`Transport::accept`] then simply yields the
//! next handshake result, so one slow or half-open peer can never delay a
//! well-behaved peer's acceptance, and half-open floods cannot pin FDs
//! indefinitely.
//!
//! # Encryption / keepalive / idle
//!
//! After the handshake the stream is encrypted (see [`crate::session`]), TCP
//! keepalive is enabled, and an application-level idle timeout tears down
//! silent peers. Reconnect helpers apply exponential backoff with full jitter.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use codec::Frame;
use crypto::KeyPair;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::{timeout, MissedTickBehavior};

use crate::budget::ByteBudget;
use crate::channel::AsyncPriorityChannel;
use crate::class_auth::PeerRole;
use crate::connection::{ConnSlot, Connection, ConnectionOpts, TransportConfig, MSG_TYPE_DATAGRAM};
use crate::disconnect::{classify_disconnect, DisconnectMetrics, DisconnectReason};
use crate::error::TransportError;
use crate::framing::{append_encrypted_record, read_encrypted_frame};
use crate::peer::{Peer, PeerId};
use crate::reconnect::ReconnectBackoff;
use crate::replay::PeerDedup;
use crate::session::{Ephemeral, Session, EPH_PUBLIC_LEN};
use crate::transport::Transport;

/// Domain separation tag for handshake signatures.
const HS_DOMAIN: &[u8] = b"dexos-network-handshake-v2";

/// Bytes exchanged in handshake phase-1 identity block (excluding key/nonce/eph).
/// network_id(8) + min_ver(2) + max_ver(2) + caps(8) + epoch(8) = 28.
const HS_META_LEN: usize = 28;

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

/// Membership allowlist: optional map from peer identity to authenticated role.
#[derive(Debug, Clone, Default)]
pub struct Membership {
    /// When `None`, any authenticated peer is admitted (open mode).
    /// When `Some`, only listed peers are accepted and carry the mapped role.
    peers: Option<HashMap<PeerId, PeerRole>>,
}

impl Membership {
    /// Open membership: any authenticated peer is admitted as [`PeerRole::Validator`]
    /// (full privileges — used by tests and single-tenant deployments).
    pub fn open() -> Self {
        Self { peers: None }
    }

    /// Permissioned membership from an explicit allowlist.
    pub fn allowlist(entries: impl IntoIterator<Item = (PeerId, PeerRole)>) -> Self {
        Self {
            peers: Some(entries.into_iter().collect()),
        }
    }

    /// Whether membership is in permissioned mode.
    pub fn is_permissioned(&self) -> bool {
        self.peers.is_some()
    }

    /// Look up a peer's role. In open mode every peer is a validator.
    pub fn role_of(&self, id: &PeerId) -> Option<PeerRole> {
        match &self.peers {
            None => Some(PeerRole::Validator),
            Some(map) => map.get(id).copied(),
        }
    }

    /// Insert or replace a peer (for dynamic membership updates).
    pub fn insert(&mut self, id: PeerId, role: PeerRole) {
        self.peers.get_or_insert_with(HashMap::new).insert(id, role);
    }
}

/// Result of a successful handshake negotiation.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HandshakeResult {
    pub peer: PeerId,
    pub wire_version: u16,
    pub capabilities: u64,
    pub epoch: u64,
}

/// The signed handshake transcript.
#[allow(clippy::too_many_arguments)] // mirrors fixed on-wire field order
fn transcript(
    challenge: &[u8; 32],
    signer_pub: &[u8; 32],
    verifier_pub: &[u8; 32],
    signer_eph: &[u8; EPH_PUBLIC_LEN],
    verifier_eph: &[u8; EPH_PUBLIC_LEN],
    network_id: u64,
    min_ver: u16,
    max_ver: u16,
    capabilities: u64,
    epoch: u64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(HS_DOMAIN.len() + 160 + HS_META_LEN);
    m.extend_from_slice(HS_DOMAIN);
    m.extend_from_slice(challenge);
    m.extend_from_slice(signer_pub);
    m.extend_from_slice(verifier_pub);
    m.extend_from_slice(signer_eph);
    m.extend_from_slice(verifier_eph);
    m.extend_from_slice(&network_id.to_le_bytes());
    m.extend_from_slice(&min_ver.to_le_bytes());
    m.extend_from_slice(&max_ver.to_le_bytes());
    m.extend_from_slice(&capabilities.to_le_bytes());
    m.extend_from_slice(&epoch.to_le_bytes());
    m
}

fn encode_meta(
    network_id: u64,
    min_ver: u16,
    max_ver: u16,
    caps: u64,
    epoch: u64,
) -> [u8; HS_META_LEN] {
    let mut out = [0u8; HS_META_LEN];
    out[0..8].copy_from_slice(&network_id.to_le_bytes());
    out[8..10].copy_from_slice(&min_ver.to_le_bytes());
    out[10..12].copy_from_slice(&max_ver.to_le_bytes());
    out[12..20].copy_from_slice(&caps.to_le_bytes());
    out[20..28].copy_from_slice(&epoch.to_le_bytes());
    out
}

fn decode_meta(bytes: &[u8; HS_META_LEN]) -> (u64, u16, u16, u64, u64) {
    let network_id = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let min_ver = u16::from_le_bytes(bytes[8..10].try_into().unwrap());
    let max_ver = u16::from_le_bytes(bytes[10..12].try_into().unwrap());
    let caps = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
    let epoch = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
    (network_id, min_ver, max_ver, caps, epoch)
}

/// Highest common version in the inclusive ranges, if any.
fn negotiate_version(
    local_min: u16,
    local_max: u16,
    remote_min: u16,
    remote_max: u16,
) -> Option<u16> {
    let lo = local_min.max(remote_min);
    let hi = local_max.min(remote_max);
    if lo <= hi {
        Some(hi)
    } else {
        None
    }
}

/// Enable TCP keepalive (+ TCP_KEEPALIVE idle/interval where the platform allows).
fn configure_socket(stream: &TcpStream, cfg: &TransportConfig) -> Result<(), TransportError> {
    stream.set_nodelay(true).ok();
    // socket2 for portable keepalive knobs. Convert via std stream reference.
    let sock_ref = socket2::SockRef::from(stream);
    sock_ref
        .set_keepalive(true)
        .map_err(|e| TransportError::Io(e.to_string()))?;
    let mut ka = socket2::TcpKeepalive::new();
    ka = ka.with_time(cfg.keepalive_time);
    #[cfg(not(target_os = "windows"))]
    {
        ka = ka.with_interval(cfg.keepalive_interval);
    }
    sock_ref
        .set_tcp_keepalive(&ka)
        .map_err(|e| TransportError::Io(e.to_string()))?;
    Ok(())
}

/// Run the mutual authentication + version/network negotiation handshake.
///
/// Stream-agnostic so both the TCP path and the QUIC control stream can share
/// the same identity-binding transcript (network id, wire version, capabilities,
/// epoch, ephemeral X25519 keys).
pub(crate) async fn mutual_handshake<S>(
    stream: &mut S,
    keypair: &KeyPair,
    expected: Option<PeerId>,
    is_initiator: bool,
    cfg: &TransportConfig,
    local_epoch: u64,
) -> Result<(HandshakeResult, Session), TransportError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let our_pub = keypair.public();
    let our_nonce = make_nonce()?;
    let ephemeral = Ephemeral::generate()?;
    let our_eph = ephemeral.public();
    let our_meta = encode_meta(
        cfg.network_id,
        cfg.min_wire_version,
        cfg.max_wire_version,
        cfg.capabilities,
        local_epoch,
    );

    // Phase 1: exchange identity + negotiation block. Both sides write first.
    stream.write_all(&our_pub).await?;
    stream.write_all(&our_nonce).await?;
    stream.write_all(&our_eph).await?;
    stream.write_all(&our_meta).await?;
    stream.flush().await?;

    let mut their_pub = [0u8; 32];
    let mut their_nonce = [0u8; 32];
    let mut their_eph = [0u8; EPH_PUBLIC_LEN];
    let mut their_meta = [0u8; HS_META_LEN];
    stream.read_exact(&mut their_pub).await?;
    stream.read_exact(&mut their_nonce).await?;
    stream.read_exact(&mut their_eph).await?;
    stream.read_exact(&mut their_meta).await?;

    let (their_net, their_min, their_max, their_caps, their_epoch) = decode_meta(&their_meta);

    // Network identity: non-zero local id requires an exact match. Zero means
    // "unspecified" and accepts any remote (including zero).
    if cfg.network_id != 0 && their_net != cfg.network_id {
        return Err(TransportError::NetworkMismatch {
            local: cfg.network_id,
            remote: their_net,
        });
    }

    let wire_version = negotiate_version(
        cfg.min_wire_version,
        cfg.max_wire_version,
        their_min,
        their_max,
    )
    .ok_or(TransportError::VersionMismatch {
        local_min: cfg.min_wire_version,
        local_max: cfg.max_wire_version,
        remote_min: their_min,
        remote_max: their_max,
    })?;

    let capabilities = cfg.capabilities & their_caps;
    // Connection epoch: initiator's epoch is authoritative so both sides agree.
    let epoch = if is_initiator {
        local_epoch
    } else {
        their_epoch
    };

    // Phase 2: sign the peer's challenge binding all negotiated material.
    let our_sig = keypair.sign(&transcript(
        &their_nonce,
        &our_pub,
        &their_pub,
        &our_eph,
        &their_eph,
        cfg.network_id,
        cfg.min_wire_version,
        cfg.max_wire_version,
        cfg.capabilities,
        local_epoch,
    ));
    stream.write_all(&our_sig).await?;
    stream.flush().await?;

    let mut their_sig = [0u8; 64];
    stream.read_exact(&mut their_sig).await?;

    crypto::verify_ed25519(
        &their_pub,
        &transcript(
            &our_nonce,
            &their_pub,
            &our_pub,
            &their_eph,
            &our_eph,
            their_net,
            their_min,
            their_max,
            their_caps,
            their_epoch,
        ),
        &their_sig,
    )
    .map_err(|_| TransportError::AuthFailed)?;

    if let Some(expected) = expected {
        if their_pub != *expected.as_bytes() {
            return Err(TransportError::AuthFailed);
        }
    }

    let session = ephemeral.into_session(
        is_initiator,
        &their_eph,
        &our_pub,
        &their_pub,
        &our_nonce,
        &their_nonce,
    );
    Ok((
        HandshakeResult {
            peer: PeerId::from(their_pub),
            wire_version,
            capabilities,
            epoch,
        },
        session,
    ))
}

fn spawn_connection(
    stream: TcpStream,
    peer: PeerId,
    session: Session,
    cfg: &TransportConfig,
    node_budget: &Arc<ByteBudget>,
    disconnects: Arc<DisconnectMetrics>,
    opts: ConnectionOpts,
) -> Connection {
    let (mut read_half, mut write_half) = stream.into_split();
    let (mut sealer, mut opener) = session.split();

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

    let idle_timeout = cfg.idle_timeout;
    let last_activity = Arc::new(Mutex::new(Instant::now()));

    let writer_out = out_reliable.clone();
    let writer_disconnects = disconnects.clone();
    let writer_activity = last_activity.clone();
    let writer = tokio::spawn(async move {
        const MAX_BATCH_FRAMES: usize = 64;
        const MAX_BATCH_BYTES: usize = 256 * 1024;
        let mut dgram_open = true;
        let mut output = Vec::with_capacity(16 * 1024);
        loop {
            let first = tokio::select! {
                biased;
                reliable = writer_out.recv() => reliable,
                dgram = out_drx.recv(), if dgram_open => match dgram {
                    Some(frame) => Some(frame),
                    None => { dgram_open = false; continue; }
                },
            };
            let Some(first) = first else { break };

            *writer_activity
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Instant::now();

            output.clear();
            // Seal every frame — datagrams included — exactly as stamped by the
            // sender. The receiver's replay/dedup windows key on the sender's
            // per-datagram sequence, so rewriting it here (as an earlier
            // batching pass did with `sequence: 0`) would make every datagram
            // after the first look like a replay and be silently dropped.
            // Coalescing still happens below: a bounded burst of queued frames
            // is drained into one write_all/flush pair.
            if append_encrypted_record(&mut output, &mut sealer, &first).is_err() {
                break;
            }

            for _ in 1..MAX_BATCH_FRAMES {
                if output.len() >= MAX_BATCH_BYTES {
                    break;
                }
                let next = writer_out.try_recv().or_else(|| out_drx.try_recv().ok());
                let Some(frame) = next else { break };
                if append_encrypted_record(&mut output, &mut sealer, &frame).is_err() {
                    return;
                }
            }
            if !output.is_empty()
                && (write_half.write_all(&output).await.is_err()
                    || write_half.flush().await.is_err())
            {
                writer_disconnects.record(DisconnectReason::Io);
                break;
            }
        }
    });

    let reader_in = in_reliable.clone();
    let max_payload = cfg.max_payload;
    let datagram_max = cfg.datagram_max_bytes;
    let semantic_max = cfg.semantic_max;
    let reader_disconnects = disconnects.clone();
    let reader_activity = last_activity.clone();
    let reader = tokio::spawn(async move {
        loop {
            let frame = match read_encrypted_frame(&mut read_half, &mut opener, max_payload).await {
                Ok(frame) => frame,
                Err(error) => {
                    reader_disconnects.record(classify_disconnect(&error));
                    break;
                }
            };
            *reader_activity
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Instant::now();
            if frame.msg_type == MSG_TYPE_DATAGRAM {
                if frame.payload.len() <= datagram_max {
                    let _ = in_dtx.try_send(frame);
                }
            } else {
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
        }
        reader_in.close();
    });

    // Idle-timeout watchdog: tear down when no authenticated traffic arrives.
    let idle_out = out_reliable.clone();
    let idle_disconnects = disconnects;
    let idle_activity = last_activity;
    let idle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let last = *idle_activity.lock().unwrap_or_else(PoisonError::into_inner);
            if last.elapsed() >= idle_timeout {
                idle_disconnects.record(DisconnectReason::RemoteClose);
                idle_out.close();
                break;
            }
        }
    });

    Connection::new_with_opts(
        peer,
        out_reliable,
        in_reliable,
        out_dtx,
        in_drx,
        cfg,
        vec![writer, reader, idle],
        opts,
    )
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
}

/// Everything `accept` does after the raw socket is admitted: the bounded
/// authenticated handshake, the membership check, the connection-slot
/// reservation (post-handshake, so failed handshakes consume no slot), and
/// wiring the finished [`Connection`]. Runs on its own task so one slow or
/// half-open peer never delays another peer's admission.
async fn accept_one(mut stream: TcpStream, ctx: &AcceptCtx) -> Result<Connection, TransportError> {
    configure_socket(&stream, &ctx.cfg)?;
    let local_epoch = ctx.epoch_counter.fetch_add(1, Ordering::Relaxed);
    let fut = mutual_handshake(
        &mut stream,
        &ctx.keypair,
        None,
        false,
        &ctx.cfg,
        local_epoch,
    );
    let (hs, session) = match timeout(ctx.cfg.handshake_timeout, fut).await {
        Ok(result) => result?,
        Err(_) => {
            ctx.disconnects.record(DisconnectReason::Authentication);
            return Err(TransportError::HandshakeTimeout);
        }
    };
    // Membership / allowlist check on accept.
    let role = {
        let m = ctx
            .membership
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match m.role_of(&hs.peer) {
            Some(role) => role,
            None => {
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
    Ok(spawn_connection(
        stream,
        hs.peer,
        session,
        &ctx.cfg,
        &ctx.node_budget,
        ctx.disconnects.clone(),
        opts,
    ))
}

/// Accept pump: drains the kernel backlog independently of any in-flight
/// handshake (#405).
///
/// Each admitted socket is gated by a **non-blocking** `try_acquire_owned` on
/// the handshake semaphore — on exhaustion the socket is dropped immediately
/// (fail-closed shed, recorded as [`DisconnectReason::Backpressure`]) so a
/// saturated semaphore can never stall draining the backlog — and each
/// surviving socket's handshake runs on its own task holding the permit.
/// Results (ready [`Connection`]s and per-connection failures alike) are
/// handed to [`TcpTransport::accept`] through a bounded channel. The pump
/// exits when the owning transport (the channel receiver) is dropped.
async fn accept_pump(
    listener: TcpListener,
    handshake_sem: Arc<Semaphore>,
    ctx: AcceptCtx,
    results: mpsc::Sender<Result<Connection, TransportError>>,
) {
    loop {
        let admitted = tokio::select! {
            // The transport was dropped: release the listener socket.
            () = results.closed() => return,
            admitted = listener.accept() => admitted,
        };
        let (stream, _remote) = match admitted {
            Ok(pair) => pair,
            Err(e) => {
                // Surface the listener failure to the caller. The bounded
                // channel also paces a persistent error to consumption rate.
                if results.send(Err(e.into())).await.is_err() {
                    return;
                }
                continue;
            }
        };
        // Fail-closed shed: never await the semaphore here — a half-open
        // flood pinning every permit must not stop the backlog from draining.
        let Ok(permit) = handshake_sem.clone().try_acquire_owned() else {
            ctx.disconnects.record(DisconnectReason::Backpressure);
            drop(stream);
            continue;
        };
        let task_ctx = ctx.clone();
        let task_results = results.clone();
        tokio::spawn(async move {
            // The permit spans the handshake and the result handoff, bounding
            // concurrently pinned FDs/tasks under a half-open flood.
            let _permit = permit;
            let result = accept_one(stream, &task_ctx).await;
            let _ = task_results.send(result).await;
        });
    }
}

/// A TCP transport bound to a local address, with a fixed node identity.
pub struct TcpTransport {
    id: PeerId,
    keypair: Arc<KeyPair>,
    /// Resolved listen address; the listener itself is owned by the accept pump.
    local_addr: SocketAddr,
    cfg: TransportConfig,
    node_budget: Arc<ByteBudget>,
    disconnects: Arc<DisconnectMetrics>,
    membership: Arc<Mutex<Membership>>,
    /// Shared multipath PeerDedup across all connections.
    peer_dedup: Arc<Mutex<PeerDedup>>,
    /// Handshake concurrency limiter: awaited by dials, taken non-blockingly
    /// (fail-closed shed) by the accept pump.
    handshake_sem: Arc<Semaphore>,
    /// Monotonic epoch counter for outbound sessions (shared with the pump).
    epoch_counter: Arc<AtomicU64>,
    /// Live connection counts per peer (connection budget). Shared with the
    /// [`ConnSlot`] guards owned by live [`Connection`]s, which release their
    /// reservation on drop.
    conn_counts: Arc<Mutex<HashMap<PeerId, usize>>>,
    /// Completed handshake results fed by the accept pump (see [`accept_pump`]).
    accepted_rx: AsyncMutex<mpsc::Receiver<Result<Connection, TransportError>>>,
}

impl TcpTransport {
    /// Bind a listener at `addr` with open membership.
    pub async fn bind(
        addr: SocketAddr,
        keypair: Arc<KeyPair>,
        cfg: TransportConfig,
    ) -> Result<Self, TransportError> {
        Self::bind_with_membership(addr, keypair, cfg, Membership::open()).await
    }

    /// Bind with an explicit membership allowlist.
    ///
    /// Spawns the internal accept pump: inbound handshakes run concurrently
    /// (bounded by [`TransportConfig::max_concurrent_handshakes`]) and
    /// [`Transport::accept`] yields each result as it completes.
    pub async fn bind_with_membership(
        addr: SocketAddr,
        keypair: Arc<KeyPair>,
        cfg: TransportConfig,
        membership: Membership,
    ) -> Result<Self, TransportError> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        let id = PeerId::from(keypair.public());
        let max_hs = cfg.max_concurrent_handshakes.max(1);
        let (accepted_tx, accepted_rx) = mpsc::channel(cfg.accept_queue_capacity.max(1));
        let transport = Self {
            id,
            keypair,
            local_addr,
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
            accepted_rx: AsyncMutex::new(accepted_rx),
        };
        tokio::spawn(accept_pump(
            listener,
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
        }
    }

    /// This node's authenticated identity.
    pub fn id(&self) -> PeerId {
        self.id
    }

    /// The bound local address (resolves the ephemeral port after `bind`).
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        Ok(self.local_addr)
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

    /// Shared cumulative disconnect counters for this transport.
    #[must_use]
    pub fn disconnect_metrics(&self) -> Arc<DisconnectMetrics> {
        self.disconnects.clone()
    }

    /// Replace the membership allowlist (permissioned mode).
    pub fn set_membership(&self, membership: Membership) {
        *self
            .membership
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = membership;
    }

    /// Shared multipath dedup table.
    pub fn peer_dedup(&self) -> Arc<Mutex<PeerDedup>> {
        self.peer_dedup.clone()
    }

    /// Dial with reconnect backoff under transient failure. Returns the first
    /// successful connection or the last error after `max_attempts`.
    pub async fn connect_with_backoff(
        &self,
        peer: &Peer,
        max_attempts: u32,
    ) -> Result<Connection, TransportError> {
        let mut backoff = ReconnectBackoff::new(self.cfg.reconnect);
        let mut last_err = TransportError::PeerUnreachable;
        for attempt in 0..max_attempts.max(1) {
            match self.connect(peer).await {
                Ok(c) => {
                    backoff.reset();
                    return Ok(c);
                }
                Err(e) => {
                    last_err = e;
                    if attempt + 1 >= max_attempts {
                        break;
                    }
                    let delay = backoff.next_delay_os_rng();
                    tokio::time::sleep(delay).await;
                }
            }
        }
        Err(last_err)
    }

    async fn handshake_gated(
        &self,
        stream: &mut TcpStream,
        expected: Option<PeerId>,
        is_initiator: bool,
        local_epoch: u64,
    ) -> Result<(HandshakeResult, Session), TransportError> {
        let _permit = self
            .handshake_sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| TransportError::HandshakeFailed)?;
        let fut = mutual_handshake(
            stream,
            &self.keypair,
            expected,
            is_initiator,
            &self.cfg,
            local_epoch,
        );
        match timeout(self.cfg.handshake_timeout, fut).await {
            Ok(result) => result,
            Err(_) => {
                self.disconnects.record(DisconnectReason::Authentication);
                Err(TransportError::HandshakeTimeout)
            }
        }
    }

    /// Reserve one connection slot for `peer` against the per-peer budget.
    ///
    /// Returns a [`ConnSlot`] guard that releases the reservation when dropped,
    /// so the budget tracks live connections rather than lifetime totals. A
    /// refused reservation never inserts an entry, keeping the map bounded.
    fn reserve_conn_slot(&self, peer: PeerId) -> Result<ConnSlot, TransportError> {
        ConnSlot::reserve(&self.conn_counts, self.cfg.connection_budget_per_peer, peer)
    }
}

impl Transport for TcpTransport {
    async fn connect(&self, peer: &Peer) -> Result<Connection, TransportError> {
        let addr = peer.addr.ok_or(TransportError::NoAddress)?;
        let mut stream = TcpStream::connect(addr).await?;
        configure_socket(&stream, &self.cfg)?;
        let local_epoch = self.epoch_counter.fetch_add(1, Ordering::Relaxed);
        let (hs, session) = self
            .handshake_gated(&mut stream, Some(peer.id), true, local_epoch)
            .await?;
        let conn_slot = self.reserve_conn_slot(hs.peer)?;
        let role = self
            .membership
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .role_of(&hs.peer)
            .unwrap_or(PeerRole::Validator);
        let opts = ConnectionOpts {
            epoch: hs.epoch,
            role,
            wire_version: hs.wire_version,
            capabilities: hs.capabilities,
            peer_dedup: Some(self.peer_dedup.clone()),
            conn_slot: Some(conn_slot),
        };
        Ok(spawn_connection(
            stream,
            hs.peer,
            session,
            &self.cfg,
            &self.node_budget,
            self.disconnects.clone(),
            opts,
        ))
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
            // Pump gone and channel drained: the transport is shutting down.
            None => Err(TransportError::ConnectionClosed),
        }
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

        assert_eq!(client_conn.peer_id(), server_id);
        assert_eq!(server_conn.peer_id(), client.id());
        assert_eq!(client_conn.wire_version(), 1);
        assert_eq!(server_conn.wire_version(), 1);

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
    async fn every_datagram_is_delivered_in_order_over_tcp() {
        use tokio::time::timeout as to;

        // Regression for issue #394: the TCP writer used to rewrite every
        // datagram's sequence to 0 while re-batching payloads, so the
        // receiver's replay window classified all but the first datagram as
        // replays and silently dropped them. With sender-stamped sequences
        // preserved on the wire, every datagram must arrive, in order.
        let server = bound(60).await;
        let client = bound(61).await;
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

        const N: u64 = 32;
        for i in 0..N {
            client_conn.send_datagram(&i.to_le_bytes()).unwrap();
        }
        for i in 0..N {
            let got = to(Duration::from_secs(10), server_conn.recv_datagram())
                .await
                .expect("every datagram must be delivered, not just the first")
                .unwrap();
            assert_eq!(got, i.to_le_bytes(), "datagram {i} arrives in order");
        }
    }

    #[tokio::test]
    async fn forged_identity_is_rejected_without_panic() {
        let server = bound(5).await;
        let client = bound(6).await;
        let server_addr = server.local_addr().unwrap();

        let acceptor = {
            let server = server.clone();
            tokio::spawn(async move {
                let _ = server.accept().await;
            })
        };

        let wrong_id = PeerId::from([0xAAu8; 32]);
        let result = client.connect(&Peer::dial(wrong_id, server_addr)).await;
        assert!(matches!(result, Err(TransportError::AuthFailed)));
        let _ = acceptor.await;
    }

    #[tokio::test]
    async fn membership_rejects_unknown_peer_on_accept() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        // Server only allows a specific peer (not the client).
        let allowed = PeerId::from(kp(99).public());
        let membership = Membership::allowlist([(allowed, PeerRole::Validator)]);
        let server = Arc::new(
            TcpTransport::bind_with_membership(addr, kp(10), cfg(), membership)
                .await
                .unwrap(),
        );
        let client = Arc::new(TcpTransport::bind(addr, kp(11), cfg()).await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let server_id = server.id();

        let acceptor = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await })
        };
        let client_result = client.connect(&Peer::dial(server_id, server_addr)).await;
        // Either side may surface the failure depending on who closes first.
        let accept_result = acceptor.await.unwrap();
        assert!(
            matches!(accept_result, Err(TransportError::NotInMembership)) || client_result.is_err(),
            "unknown peer must be rejected: accept={accept_result:?} client={client_result:?}"
        );
    }

    #[tokio::test]
    async fn wrong_network_id_fails_with_network_mismatch() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut server_cfg = cfg();
        server_cfg.network_id = 42;
        let mut client_cfg = cfg();
        client_cfg.network_id = 99;
        let server = Arc::new(TcpTransport::bind(addr, kp(12), server_cfg).await.unwrap());
        let client = Arc::new(TcpTransport::bind(addr, kp(13), client_cfg).await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let server_id = server.id();
        let acceptor = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await })
        };
        let client_result = client.connect(&Peer::dial(server_id, server_addr)).await;
        let _ = acceptor.await;
        assert!(
            matches!(client_result, Err(TransportError::NetworkMismatch { .. }))
                || matches!(client_result, Err(TransportError::AuthFailed))
                || matches!(client_result, Err(TransportError::Io(_))),
            "expected network mismatch, got {client_result:?}"
        );
        if let Err(TransportError::NetworkMismatch { local, remote }) = client_result {
            assert_eq!(local, 99);
            assert_eq!(remote, 42);
        }
    }

    #[tokio::test]
    async fn no_common_wire_version_fails_with_version_mismatch() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut server_cfg = cfg();
        server_cfg.min_wire_version = 3;
        server_cfg.max_wire_version = 4;
        let mut client_cfg = cfg();
        client_cfg.min_wire_version = 1;
        client_cfg.max_wire_version = 2;
        let server = Arc::new(TcpTransport::bind(addr, kp(14), server_cfg).await.unwrap());
        let client = Arc::new(TcpTransport::bind(addr, kp(15), client_cfg).await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let server_id = server.id();
        let acceptor = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await })
        };
        let client_result = client.connect(&Peer::dial(server_id, server_addr)).await;
        let _ = acceptor.await;
        assert!(
            matches!(client_result, Err(TransportError::VersionMismatch { .. }))
                || matches!(client_result, Err(TransportError::Io(_)))
                || matches!(client_result, Err(TransportError::AuthFailed)),
            "expected version mismatch, got {client_result:?}"
        );
    }

    #[tokio::test]
    async fn n_and_n_minus_1_negotiate_highest_common_version() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut server_cfg = cfg();
        server_cfg.min_wire_version = 1;
        server_cfg.max_wire_version = 2;
        let mut client_cfg = cfg();
        client_cfg.min_wire_version = 1;
        client_cfg.max_wire_version = 1;
        let server = Arc::new(TcpTransport::bind(addr, kp(16), server_cfg).await.unwrap());
        let client = Arc::new(TcpTransport::bind(addr, kp(17), client_cfg).await.unwrap());
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
        assert_eq!(client_conn.wire_version(), 1);
        assert_eq!(server_conn.wire_version(), 1);
    }

    #[tokio::test]
    async fn stalled_handshake_times_out() {
        use tokio::net::TcpListener as TokioListener;
        // A raw listener that accepts but never completes the handshake.
        let listener = TokioListener::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let _stall = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            // Hold the socket open without responding.
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let mut c = cfg();
        c.handshake_timeout = Duration::from_millis(200);
        let client = Arc::new(
            TcpTransport::bind("127.0.0.1:0".parse().unwrap(), kp(18), c)
                .await
                .unwrap(),
        );
        let result = client
            .connect(&Peer::dial(PeerId::from([1u8; 32]), addr))
            .await;
        assert!(
            matches!(result, Err(TransportError::HandshakeTimeout)),
            "expected HandshakeTimeout, got {result:?}"
        );
    }

    #[tokio::test]
    async fn slow_consumer_never_loses_reliable_frames() {
        use tokio::time::timeout as to;

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
            Ok::<_, TransportError>(client_conn)
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        for i in 0..N {
            let frame = to(Duration::from_secs(10), server_conn.recv())
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
        use tokio::time::timeout as to;

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

        client_conn
            .send_priority(TrafficClass::Consensus, &[7u8; 500])
            .unwrap();

        let closed = to(Duration::from_secs(10), server_conn.recv())
            .await
            .expect("server must react to the over-ceiling frame");
        assert!(matches!(closed, Err(TransportError::ConnectionClosed)));
    }

    #[tokio::test]
    async fn inbound_oversized_datagram_is_dropped_before_delivery() {
        use tokio::time::timeout as to;

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

        client_conn.send_datagram(&[9u8; 600]).unwrap();
        client_conn.send_datagram(b"ok").unwrap();

        let got = to(Duration::from_secs(10), server_conn.recv_datagram())
            .await
            .expect("in-cap datagram must still be delivered")
            .unwrap();
        assert_eq!(got, b"ok", "only the in-cap datagram is delivered");
    }

    #[test]
    fn nonces_are_csprng_drawn_and_distinct() {
        let a = make_nonce().unwrap();
        let b = make_nonce().unwrap();
        assert_ne!(a, b, "two CSPRNG nonces collided");
        assert_ne!(a, [0u8; 32], "nonce was all zero");
    }

    #[test]
    fn negotiate_version_picks_highest_common() {
        assert_eq!(negotiate_version(1, 3, 2, 4), Some(3));
        assert_eq!(negotiate_version(1, 1, 2, 2), None);
        assert_eq!(negotiate_version(1, 2, 1, 1), Some(1));
    }

    #[tokio::test]
    async fn connect_without_address_fails() {
        let client = bound(7).await;
        let result = client
            .connect(&Peer::loopback(PeerId::from([1u8; 32])))
            .await;
        assert!(matches!(result, Err(TransportError::NoAddress)));
    }

    #[tokio::test]
    async fn peer_dedup_rejects_multipath_dual_delivery() {
        // Two TCP paths to the same logical peer sharing the server's PeerDedup.
        let server = bound(40).await;
        let client = bound(41).await;
        let server_addr = server.local_addr().unwrap();
        let server_id = server.id();

        let s1 = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await })
        };
        let c1 = client
            .connect(&Peer::dial(server_id, server_addr))
            .await
            .unwrap();
        let b1 = s1.await.unwrap().unwrap();

        let s2 = {
            let server = server.clone();
            tokio::spawn(async move { server.accept().await })
        };
        let c2 = client
            .connect(&Peer::dial(server_id, server_addr))
            .await
            .unwrap();
        let b2 = s2.await.unwrap().unwrap();

        // Force the same (epoch, seq) into PeerDedup via the shared table.
        // Connections have independent epochs from the dialer; inject via the
        // shared table directly to prove dual delivery rejection.
        let peer = client.id();
        let epoch = c1.epoch();
        {
            let dedup = server.peer_dedup();
            let mut d = dedup.lock().unwrap();
            assert!(d
                .accept_class(peer, epoch, TrafficClass::Consensus, 0)
                .unwrap());
            assert!(!d
                .accept_class(peer, epoch, TrafficClass::Consensus, 0)
                .unwrap());
        }
        // Keep connections alive so the transport stays up for the assertion.
        let _ = (c1, c2, b1, b2);
    }

    #[tokio::test]
    async fn gateway_role_rejects_inbound_p0_on_recv() {
        use crate::channel::AsyncPriorityChannel;
        use crate::connection::ConnectionOpts;

        let out = Arc::new(AsyncPriorityChannel::new(16));
        let inbound = Arc::new(AsyncPriorityChannel::new(16));
        let (out_dtx, _out_drx) = mpsc::channel(4);
        let (_in_dtx, in_drx) = mpsc::channel(4);
        let conn = Connection::new_with_opts(
            PeerId::from([1u8; 32]),
            out,
            inbound.clone(),
            out_dtx,
            in_drx,
            &TransportConfig::default(),
            Vec::new(),
            ConnectionOpts {
                epoch: 1,
                role: PeerRole::Gateway,
                wire_version: 1,
                capabilities: 0,
                peer_dedup: None,
                conn_slot: None,
            },
        );
        inbound
            .try_send(Frame {
                class: TrafficClass::Consensus,
                msg_type: 0,
                sequence: 0,
                payload: b"vote".to_vec(),
            })
            .unwrap();
        let err = conn.recv().await.unwrap_err();
        assert!(matches!(
            err,
            TransportError::UnauthorizedClass {
                class: TrafficClass::Consensus,
                role: PeerRole::Gateway
            }
        ));
    }

    #[tokio::test]
    async fn conn_budget_releases_slots_when_guards_drop() {
        let t = bound(9).await;
        let peer = PeerId::from([42u8; 32]);
        let budget = t.cfg.connection_budget_per_peer;
        assert!(budget > 0);

        // (a) The budget admits exactly `budget` live reservations; the next
        // reserve is refused with Backpressure.
        let mut slots = Vec::new();
        for _ in 0..budget {
            slots.push(t.reserve_conn_slot(peer).unwrap());
        }
        assert!(matches!(
            t.reserve_conn_slot(peer),
            Err(TransportError::Backpressure { .. })
        ));

        // (b) Dropping one guard frees exactly one slot: a new reserve
        // succeeds again, and the budget is enforced once more after it.
        drop(slots.pop());
        let refilled = t.reserve_conn_slot(peer).unwrap();
        assert!(matches!(
            t.reserve_conn_slot(peer),
            Err(TransportError::Backpressure { .. })
        ));

        // (c) Releasing every slot removes the peer's entry entirely, so the
        // map stays bounded by peers with live connections.
        drop(refilled);
        slots.clear();
        assert!(t
            .conn_counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty());
    }

    #[test]
    fn membership_allowlist_contains_only_listed_peers() {
        let a = PeerId::from([1u8; 32]);
        let b = PeerId::from([2u8; 32]);
        let m = Membership::allowlist([(a, PeerRole::Validator)]);
        assert_eq!(m.role_of(&a), Some(PeerRole::Validator));
        assert_eq!(m.role_of(&b), None);
        let open = Membership::open();
        assert_eq!(open.role_of(&b), Some(PeerRole::Validator));
    }

    /// Regression for #405: acceptance must be concurrent. A half-open client
    /// that completes the TCP connect but never sends a handshake byte used to
    /// pin the (serialized) accept path for the full 5 s handshake timeout,
    /// stalling every other peer. With the accept pump, the well-behaved peer
    /// must be admitted while the half-open handshake is still pending.
    #[tokio::test]
    async fn half_open_peer_does_not_block_other_accepts() {
        use tokio::time::timeout as to;

        let server = bound(70).await;
        let client = bound(71).await;
        let server_addr = server.local_addr().unwrap();
        let server_id = server.id();

        // Half-open peer: raw TCP connect, then silence. Keep the socket open
        // for the whole test so its handshake task stays pending server-side.
        let stalled = TcpStream::connect(server_addr).await.unwrap();
        // Let the pump admit the half-open socket first, so its handshake is
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
    /// pinned by half-open peers, excess sockets must be admitted from the
    /// kernel backlog and dropped immediately — never left pending behind the
    /// stalled handshakes — and acceptance must recover once the stalled
    /// handshakes time out and release their permits.
    #[tokio::test]
    async fn saturated_handshake_budget_sheds_excess_sockets_without_stalling() {
        use tokio::time::timeout as to;

        let mut c = cfg();
        c.max_concurrent_handshakes = 2;
        c.handshake_timeout = Duration::from_millis(400);
        let server = Arc::new(
            TcpTransport::bind("127.0.0.1:0".parse().unwrap(), kp(72), c)
                .await
                .unwrap(),
        );
        let server_addr = server.local_addr().unwrap();

        // Two half-open sockets pin both handshake permits.
        let _pinned_a = TcpStream::connect(server_addr).await.unwrap();
        let _pinned_b = TcpStream::connect(server_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Budget exhausted: the next socket is shed fail-closed. Observing EOF
        // proves the pump kept draining the backlog (accepted + dropped) rather
        // than stalling on the saturated semaphore.
        let mut shed = TcpStream::connect(server_addr).await.unwrap();
        let mut buf = [0u8; 1];
        let n = to(Duration::from_secs(2), shed.read(&mut buf))
            .await
            .expect("shed must be prompt — a saturated semaphore must not stall the accept pump")
            .unwrap();
        assert_eq!(n, 0, "shed socket must see EOF, not handshake bytes");
        assert!(
            server
                .disconnect_metrics()
                .get(DisconnectReason::Backpressure)
                >= 1,
            "fail-closed shed must be recorded as a Backpressure disconnect"
        );

        // Once the pinned handshakes time out and release their permits, a
        // well-behaved peer is admitted again.
        let client = bound(73).await;
        let client_conn = to(
            Duration::from_secs(10),
            client.connect_with_backoff(&Peer::dial(server.id(), server_addr), 8),
        )
        .await
        .expect("acceptance must recover after the half-open handshakes time out")
        .unwrap();
        assert_eq!(client_conn.peer_id(), server.id());
    }
}

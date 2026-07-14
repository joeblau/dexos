//! Framed TCP/TLS server for the durable packed validator core.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use codec::{Frame, FRAME_HEADER_LEN};
use network::{
    encode_order_batch_receipt_frame, inspect_authenticated_order_batch, OrderBatchReceipt,
    OrderBatchReceiptStage, TrafficClass, AUTHENTICATED_ORDER_BATCH_MAX_WIRE,
    MAX_PENDING_ORDER_BATCH_FINALITY, MSG_TYPE_ORDER_BATCH,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinSet;

use crate::{
    MinimmitFinalityEvent, MinimmitReceiptBridge, MultiSessionAdmissionReadiness,
    MultiSessionPackedValidatorCore, PackedValidatorCore,
};

/// Bounded packed listener settings. Production callers provide TLS 1.3 through
/// the same [`rpc::TlsMode`] used by the public RPC listener.
#[derive(Clone)]
pub struct PackedServerConfig {
    pub tls: rpc::TlsMode,
    pub max_connections: usize,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
    pub drain_timeout: Duration,
    pub pending_finality_capacity: usize,
    pub connection_finality_capacity: usize,
}

impl Default for PackedServerConfig {
    fn default() -> Self {
        Self {
            tls: rpc::TlsMode::Disabled,
            max_connections: 1_024,
            read_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
            drain_timeout: Duration::from_secs(30),
            pending_finality_capacity: MAX_PENDING_ORDER_BATCH_FINALITY,
            connection_finality_capacity: 1_024,
        }
    }
}

type ReceiptKey = (u64, u64);

struct FinalityRoute {
    route_id: u64,
    server_id: u64,
    connection_id: u64,
    sender: mpsc::Sender<OrderBatchReceipt>,
    executed: Rc<Cell<Option<OrderBatchReceipt>>>,
    checkpoint_bound: Rc<Cell<bool>>,
}

struct PackedFinalityRoutes {
    capacity: usize,
    next_server_id: u64,
    next_connection_id: u64,
    next_route_id: u64,
    undeliverable_receipts: u64,
    routes: BTreeMap<ReceiptKey, FinalityRoute>,
}

/// A capacity slot keyed by the signed wrapper header and acquired before the
/// validator core performs any durable mutation.
struct PackedFinalityReservation {
    router: PackedFinalityRouter,
    key: ReceiptKey,
    route_id: u64,
    executed: Rc<Cell<Option<OrderBatchReceipt>>>,
    active: bool,
}

struct ConnectionRouteGuard {
    router: PackedFinalityRouter,
    connection_id: u64,
}

struct ServerRouteGuard {
    router: PackedFinalityRouter,
    server_id: u64,
}

#[derive(Clone, Copy)]
struct PackedConnectionConfig {
    finality_capacity: usize,
    read_timeout: Duration,
    write_timeout: Duration,
}

struct PackedConnectionContext {
    finality: PackedFinalityRouter,
    server_id: u64,
    connection_id: u64,
    config: PackedConnectionConfig,
    stop: watch::Receiver<bool>,
    sequence_tx: watch::Sender<u64>,
}

enum CoreReadiness {
    Ready,
    Wait,
}

trait PackedServerCore {
    fn readiness(&self, bytes: &[u8]) -> Result<CoreReadiness, String>;
    fn admit_receipt(
        &mut self,
        bytes: &[u8],
        sequencer_now: u64,
        observed_unix_ns: u64,
    ) -> Result<OrderBatchReceipt, String>;
    fn executed_receipt(&mut self, observed_unix_ns: u64) -> Result<OrderBatchReceipt, String>;
}

impl PackedServerCore for PackedValidatorCore {
    fn readiness(&self, _bytes: &[u8]) -> Result<CoreReadiness, String> {
        Ok(CoreReadiness::Ready)
    }

    fn admit_receipt(
        &mut self,
        bytes: &[u8],
        sequencer_now: u64,
        observed_unix_ns: u64,
    ) -> Result<OrderBatchReceipt, String> {
        self.admit(bytes, sequencer_now, observed_unix_ns)
            .map_err(|error| error.to_string())
    }

    fn executed_receipt(&mut self, observed_unix_ns: u64) -> Result<OrderBatchReceipt, String> {
        self.drive_until_receipt(observed_unix_ns)
            .map_err(|error| error.to_string())
    }
}

impl PackedServerCore for MultiSessionPackedValidatorCore {
    fn readiness(&self, bytes: &[u8]) -> Result<CoreReadiness, String> {
        match self.readiness(bytes).map_err(|error| error.to_string())? {
            MultiSessionAdmissionReadiness::Ready => Ok(CoreReadiness::Ready),
            MultiSessionAdmissionReadiness::Wait { .. } => Ok(CoreReadiness::Wait),
            MultiSessionAdmissionReadiness::Stale { expected, actual } => Err(format!(
                "global packed sequence {actual} is stale; next is {expected}"
            )),
        }
    }

    fn admit_receipt(
        &mut self,
        bytes: &[u8],
        sequencer_now: u64,
        observed_unix_ns: u64,
    ) -> Result<OrderBatchReceipt, String> {
        self.admit(bytes, sequencer_now, observed_unix_ns)
            .map_err(|error| error.to_string())
    }

    fn executed_receipt(&mut self, observed_unix_ns: u64) -> Result<OrderBatchReceipt, String> {
        self.drive_until_receipt(observed_unix_ns)
            .map_err(|error| error.to_string())
    }
}

/// Bounded shard-local route from checkpoint-promoted receipts to their socket.
#[derive(Clone)]
pub struct PackedFinalityRouter(Rc<RefCell<PackedFinalityRoutes>>);

impl PackedFinalityRouter {
    pub fn new(capacity: usize) -> Result<Self, PackedFinalityRouterError> {
        if capacity == 0 || capacity > MAX_PENDING_ORDER_BATCH_FINALITY {
            return Err(PackedFinalityRouterError::InvalidCapacity);
        }
        Ok(Self(Rc::new(RefCell::new(PackedFinalityRoutes {
            capacity,
            next_server_id: 0,
            next_connection_id: 0,
            next_route_id: 0,
            undeliverable_receipts: 0,
            routes: BTreeMap::new(),
        }))))
    }

    fn allocate_server(&self) -> Result<u64, PackedFinalityRouterError> {
        let mut inner = self.0.borrow_mut();
        let id = inner.next_server_id;
        inner.next_server_id = id
            .checked_add(1)
            .ok_or(PackedFinalityRouterError::SequenceExhausted)?;
        Ok(id)
    }

    fn allocate_connection(&self) -> Result<u64, PackedFinalityRouterError> {
        let mut inner = self.0.borrow_mut();
        let id = inner.next_connection_id;
        inner.next_connection_id = id
            .checked_add(1)
            .ok_or(PackedFinalityRouterError::SequenceExhausted)?;
        Ok(id)
    }

    fn reserve(
        &self,
        server_id: u64,
        connection_id: u64,
        key: ReceiptKey,
        sender: mpsc::Sender<OrderBatchReceipt>,
    ) -> Result<PackedFinalityReservation, PackedFinalityRouterError> {
        let mut inner = self.0.borrow_mut();
        if inner.routes.len() >= inner.capacity {
            return Err(PackedFinalityRouterError::Backpressure);
        }
        if inner.routes.contains_key(&key) {
            return Err(PackedFinalityRouterError::DuplicateReceipt);
        }
        let route_id = inner.next_route_id;
        inner.next_route_id = route_id
            .checked_add(1)
            .ok_or(PackedFinalityRouterError::SequenceExhausted)?;
        let executed = Rc::new(Cell::new(None));
        inner.routes.insert(
            key,
            FinalityRoute {
                route_id,
                server_id,
                connection_id,
                sender,
                executed: Rc::clone(&executed),
                checkpoint_bound: Rc::new(Cell::new(false)),
            },
        );
        Ok(PackedFinalityReservation {
            router: self.clone(),
            key,
            route_id,
            executed,
            active: true,
        })
    }

    /// Deliver one checkpoint-promoted receipt to the connection that emitted
    /// its exact executed predecessor.
    pub async fn publish(
        &self,
        receipt: OrderBatchReceipt,
    ) -> Result<(), PackedFinalityRouterError> {
        if receipt.stage != OrderBatchReceiptStage::Finalized {
            return Err(PackedFinalityRouterError::WrongStage);
        }
        let key = (receipt.batch_sequence, receipt.first_sequence);
        let (route_id, sender) = {
            let inner = self.0.borrow();
            let route = inner
                .routes
                .get(&key)
                .ok_or(PackedFinalityRouterError::UnknownReceipt)?;
            if !route.checkpoint_bound.get() {
                return Err(PackedFinalityRouterError::UnboundReceipt);
            }
            (route.route_id, route.sender.clone())
        };
        let delivered = sender.send(receipt).await.is_ok();
        let mut inner = self.0.borrow_mut();
        if inner
            .routes
            .get(&key)
            .is_some_and(|route| route.route_id == route_id)
        {
            inner.routes.remove(&key);
        }
        if delivered {
            Ok(())
        } else {
            Err(PackedFinalityRouterError::ConnectionClosed)
        }
    }

    /// Bind every unbound executed socket receipt fully contained in this
    /// checkpoint range to the bridge's already-registered block commitment.
    pub fn bind_checkpoint(
        &self,
        bridge: &mut MinimmitReceiptBridge,
        block_hash: types::Hash,
        first_sequence: u64,
        last_sequence: u64,
    ) -> Result<usize, PackedFinalityDeliveryError> {
        if last_sequence < first_sequence {
            return Err(PackedFinalityDeliveryError::InvalidRange);
        }
        let mut candidates = Vec::new();
        for route in self.0.borrow().routes.values() {
            let Some(executed) = route.executed.get() else {
                continue;
            };
            let end = executed
                .first_sequence
                .checked_add(u64::from(executed.record_count).saturating_sub(1))
                .ok_or(crate::MinimmitReceiptBridgeError::SequenceExhausted)?;
            if !route.checkpoint_bound.get()
                && executed.first_sequence >= first_sequence
                && end <= last_sequence
            {
                candidates.push((executed, Rc::clone(&route.checkpoint_bound)));
            }
        }
        let receipts: Vec<_> = candidates.iter().map(|(receipt, _)| *receipt).collect();
        bridge.bind_executed_batch(block_hash, &receipts)?;

        // The shared flags belong to the exact routes collected above, so this
        // infallible commit cannot target a replacement route with the same key.
        for (_, checkpoint_bound) in &candidates {
            checkpoint_bound.set(true);
        }
        Ok(candidates.len())
    }

    fn remove_connection(&self, connection_id: u64) {
        self.0
            .borrow_mut()
            .routes
            .retain(|_, route| route.connection_id != connection_id);
    }

    fn remove_server(&self, server_id: u64) {
        self.0
            .borrow_mut()
            .routes
            .retain(|_, route| route.server_id != server_id);
    }

    fn account_undeliverable(&self) {
        let mut inner = self.0.borrow_mut();
        inner.undeliverable_receipts = inner.undeliverable_receipts.saturating_add(1);
    }

    #[must_use]
    pub fn pending_receipts(&self) -> usize {
        self.0.borrow().routes.len()
    }

    /// Number of finalized receipts whose connection was already absent or
    /// closed. These receipts were explicitly consumed from bridge retention.
    #[must_use]
    pub fn undeliverable_receipts(&self) -> u64 {
        self.0.borrow().undeliverable_receipts
    }
}

impl PackedFinalityReservation {
    /// Commit the core-produced receipt into its already reserved route. The
    /// verified core derives the same key from the authenticated wrapper, and
    /// no await can remove this shard-local reservation before this call.
    fn commit(mut self, receipt: OrderBatchReceipt) {
        debug_assert_eq!(receipt.stage, OrderBatchReceiptStage::Executed);
        debug_assert_eq!(
            self.key,
            (receipt.batch_sequence, receipt.first_sequence),
            "the verified core must preserve the reserved wrapper identity"
        );
        self.executed.set(Some(receipt));
        self.active = false;
    }
}

impl Drop for PackedFinalityReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut inner = self.router.0.borrow_mut();
        if inner
            .routes
            .get(&self.key)
            .is_some_and(|route| route.route_id == self.route_id)
        {
            inner.routes.remove(&self.key);
        }
    }
}

impl Drop for ConnectionRouteGuard {
    fn drop(&mut self) {
        self.router.remove_connection(self.connection_id);
    }
}

impl Drop for ServerRouteGuard {
    fn drop(&mut self) {
        self.router.remove_server(self.server_id);
    }
}

/// Apply one Minimmit finality event to the commitment bridge and deliver every
/// newly promoted receipt to its original socket. Missing and closed routes are
/// explicitly counted and acknowledged; retryable route failures retain their
/// bridge evidence without preventing delivery to other live routes.
pub async fn deliver_minimmit_finality(
    router: &PackedFinalityRouter,
    bridge: &mut MinimmitReceiptBridge,
    event: MinimmitFinalityEvent,
    observed_unix_ns: u64,
) -> Result<usize, PackedFinalityDeliveryError> {
    let block = match event {
        MinimmitFinalityEvent::ConsensusFinal { block, .. }
        | MinimmitFinalityEvent::Finalized { block, .. } => block,
    };
    let receipts = bridge.observe_finality(event, observed_unix_ns)?;
    let mut acknowledged = 0usize;
    let mut first_error = None;
    for receipt in receipts {
        match router.publish(receipt).await {
            Ok(()) => match bridge.acknowledge_finalized(
                block,
                receipt.batch_sequence,
                receipt.first_sequence,
            ) {
                Ok(()) => acknowledged += 1,
                Err(error) if first_error.is_none() => {
                    first_error = Some(PackedFinalityDeliveryError::Bridge(error));
                }
                Err(_) => {}
            },
            Err(
                PackedFinalityRouterError::UnknownReceipt
                | PackedFinalityRouterError::ConnectionClosed,
            ) => {
                match bridge.acknowledge_finalized(
                    block,
                    receipt.batch_sequence,
                    receipt.first_sequence,
                ) {
                    Ok(()) => {
                        router.account_undeliverable();
                        acknowledged += 1;
                    }
                    Err(error) if first_error.is_none() => {
                        first_error = Some(PackedFinalityDeliveryError::Bridge(error));
                    }
                    Err(_) => {}
                }
            }
            Err(error) if first_error.is_none() => {
                first_error = Some(PackedFinalityDeliveryError::Router(error));
            }
            Err(_) => {}
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok(acknowledged)
}

/// Accept packed connections until stopped, then drain or abort them by deadline.
pub async fn serve_packed_with_shutdown(
    listener: TcpListener,
    core: Rc<RefCell<PackedValidatorCore>>,
    config: PackedServerConfig,
    stop: watch::Receiver<bool>,
) -> Result<u64, PackedServerError> {
    let router = PackedFinalityRouter::new(config.pending_finality_capacity)?;
    serve_packed_with_finality(listener, core, router, config, stop).await
}

/// Accept striped multi-session packed connections until stopped.
pub async fn serve_multi_packed_with_shutdown(
    listener: TcpListener,
    core: Rc<RefCell<MultiSessionPackedValidatorCore>>,
    config: PackedServerConfig,
    stop: watch::Receiver<bool>,
) -> Result<u64, PackedServerError> {
    let router = PackedFinalityRouter::new(config.pending_finality_capacity)?;
    serve_multi_packed_with_finality(listener, core, router, config, stop).await
}

/// Serve packed sockets with an externally retained route for Minimmit-promoted
/// finalized receipts. The server owns a local task set, so callers may await
/// it directly from either current-thread or multi-thread Tokio runtimes; an
/// ambient [`tokio::task::LocalSet`] is not required.
pub async fn serve_packed_with_finality(
    listener: TcpListener,
    core: Rc<RefCell<PackedValidatorCore>>,
    finality: PackedFinalityRouter,
    config: PackedServerConfig,
    stop: watch::Receiver<bool>,
) -> Result<u64, PackedServerError> {
    serve_packed_core_with_finality(listener, core, finality, config, stop).await
}

/// Serve striped multi-session sockets with externally driven Minimmit finality.
/// Like [`serve_packed_with_finality`], this owns its local connection runtime.
pub async fn serve_multi_packed_with_finality(
    listener: TcpListener,
    core: Rc<RefCell<MultiSessionPackedValidatorCore>>,
    finality: PackedFinalityRouter,
    config: PackedServerConfig,
    stop: watch::Receiver<bool>,
) -> Result<u64, PackedServerError> {
    serve_packed_core_with_finality(listener, core, finality, config, stop).await
}

async fn serve_packed_core_with_finality<C>(
    listener: TcpListener,
    core: Rc<RefCell<C>>,
    finality: PackedFinalityRouter,
    config: PackedServerConfig,
    stop: watch::Receiver<bool>,
) -> Result<u64, PackedServerError>
where
    C: PackedServerCore + 'static,
{
    if config.max_connections == 0
        || config.read_timeout.is_zero()
        || config.write_timeout.is_zero()
        || config.drain_timeout.is_zero()
        || config.connection_finality_capacity == 0
    {
        return Err(PackedServerError::InvalidConfig);
    }
    let local = tokio::task::LocalSet::new();
    local
        .run_until(serve_packed_core_on_local(
            &local, listener, core, finality, config, stop,
        ))
        .await
}

async fn serve_packed_core_on_local<C>(
    local: &tokio::task::LocalSet,
    listener: TcpListener,
    core: Rc<RefCell<C>>,
    finality: PackedFinalityRouter,
    config: PackedServerConfig,
    mut stop: watch::Receiver<bool>,
) -> Result<u64, PackedServerError>
where
    C: PackedServerCore + 'static,
{
    let server_id = finality.allocate_server()?;
    let _server_routes = ServerRouteGuard {
        router: finality.clone(),
        server_id,
    };
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let (sequence_tx, _) = watch::channel(0u64);
    let mut tasks = JoinSet::new();
    let mut served = 0u64;
    loop {
        while tasks.try_join_next().is_some() {}
        let accepted = tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
                continue;
            }
            accepted = listener.accept() => accepted,
        };
        let (stream, _) = accepted?;
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let _ = stream.set_nodelay(true);
        served = served.saturating_add(1);
        let core = Rc::clone(&core);
        let tls = config.tls.clone();
        let connection_config = PackedConnectionConfig {
            finality_capacity: config.connection_finality_capacity,
            read_timeout: config.read_timeout,
            write_timeout: config.write_timeout,
        };
        let connection_stop = stop.clone();
        let connection_sequence = sequence_tx.clone();
        let finality = finality.clone();
        let connection_id = finality.allocate_connection()?;
        tasks.spawn_local_on(
            async move {
                let _permit = permit;
                let _connection_routes = ConnectionRouteGuard {
                    router: finality.clone(),
                    connection_id,
                };
                let context = PackedConnectionContext {
                    finality: finality.clone(),
                    server_id,
                    connection_id,
                    config: connection_config,
                    stop: connection_stop,
                    sequence_tx: connection_sequence,
                };
                let result = match tls {
                    rpc::TlsMode::Disabled => handle_packed_connection(stream, core, context).await,
                    rpc::TlsMode::Required(acceptor) => {
                        if let Ok(Ok(stream)) = tokio::time::timeout(
                            context.config.read_timeout,
                            acceptor.accept(stream),
                        )
                        .await
                        {
                            handle_packed_connection(stream, core, context).await
                        } else {
                            Ok(())
                        }
                    }
                };
                let _ = result;
            },
            local,
        );
    }
    drop(listener);
    if tokio::time::timeout(config.drain_timeout, async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    Ok(served)
}

async fn handle_packed_connection<S, C>(
    mut stream: S,
    core: Rc<RefCell<C>>,
    context: PackedConnectionContext,
) -> Result<(), PackedServerError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: PackedServerCore,
{
    let PackedConnectionContext {
        finality,
        server_id,
        connection_id,
        config,
        mut stop,
        sequence_tx,
    } = context;
    let (finality_tx, mut finality_rx) = mpsc::channel(config.finality_capacity);
    let mut expected_transport_sequence = 0u64;
    let mut next_receipt_sequence = 0u64;
    let mut sequence_rx = sequence_tx.subscribe();
    loop {
        let bytes = tokio::select! {
            biased;
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return Ok(());
                }
                continue;
            }
            receipt = finality_rx.recv() => {
                let Some(receipt) = receipt else { return Ok(()); };
                write_receipt(
                    &mut stream,
                    receipt,
                    &mut next_receipt_sequence,
                    config.write_timeout,
                ).await?;
                continue;
            }
            result = tokio::time::timeout(config.read_timeout, read_frame(&mut stream)) => {
                match result {
                    Ok(Ok(bytes)) => bytes,
                    Ok(Err(PackedServerError::Io(error)))
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::UnexpectedEof
                                | std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::BrokenPipe
                        ) => return Ok(()),
                    Ok(Err(error)) => return Err(error),
                    Err(_) => return Err(PackedServerError::ReadTimeout),
                }
            }
        };
        let (frame, consumed) = Frame::decode_with_max(&bytes, AUTHENTICATED_ORDER_BATCH_MAX_WIRE)?;
        if consumed != bytes.len()
            || frame.class != TrafficClass::NewOrder
            || frame.msg_type != MSG_TYPE_ORDER_BATCH
        {
            return Err(PackedServerError::WrongLane);
        }
        if frame.sequence != expected_transport_sequence {
            return Err(PackedServerError::TransportSequence {
                expected: expected_transport_sequence,
                actual: frame.sequence,
            });
        }
        expected_transport_sequence = expected_transport_sequence
            .checked_add(1)
            .ok_or(PackedServerError::SequenceExhausted)?;
        loop {
            let readiness = core
                .borrow()
                .readiness(&frame.payload)
                .map_err(PackedServerError::Core)?;
            match readiness {
                CoreReadiness::Ready => break,
                CoreReadiness::Wait => {
                    tokio::select! {
                        changed = stop.changed() => {
                            if changed.is_err() || *stop.borrow() {
                                return Ok(());
                            }
                        }
                        changed = sequence_rx.changed() => {
                            if changed.is_err() {
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
        let header = inspect_authenticated_order_batch(&frame.payload)?;
        let reservation = finality.reserve(
            server_id,
            connection_id,
            (header.binding.batch_sequence, header.binding.first_sequence),
            finality_tx.clone(),
        )?;
        let (admitted, executed) = {
            // The core is a single shard owner. No await occurs while locked:
            // disk durability and deterministic execution are synchronous.
            let mut core = core.borrow_mut();
            let now = unix_now_ns();
            let admitted = core
                .admit_receipt(&frame.payload, now, now)
                .map_err(PackedServerError::Core)?;
            let executed = core
                .executed_receipt(unix_now_ns())
                .map_err(PackedServerError::Core)?;
            (admitted, executed)
        };
        reservation.commit(executed);
        sequence_tx.send_modify(|version| *version = version.wrapping_add(1));
        for receipt in [admitted, executed] {
            write_receipt(
                &mut stream,
                receipt,
                &mut next_receipt_sequence,
                config.write_timeout,
            )
            .await?;
        }
    }
}

async fn write_receipt<W: AsyncWrite + Unpin>(
    writer: &mut W,
    receipt: OrderBatchReceipt,
    next_sequence: &mut u64,
    write_timeout: Duration,
) -> Result<(), PackedServerError> {
    let sequence = *next_sequence;
    *next_sequence = sequence
        .checked_add(1)
        .ok_or(PackedServerError::SequenceExhausted)?;
    let bytes = encode_order_batch_receipt_frame(&receipt, sequence)?.encode()?;
    tokio::time::timeout(write_timeout, async {
        writer.write_all(&bytes).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| PackedServerError::WriteTimeout)??;
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, PackedServerError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await?;
    let declared = u32::from_le_bytes(header[15..19].try_into().unwrap_or([0; 4])) as usize;
    if declared > AUTHENTICATED_ORDER_BATCH_MAX_WIRE {
        return Err(PackedServerError::Oversize);
    }
    let mut bytes = vec![0; FRAME_HEADER_LEN + declared];
    bytes[..FRAME_HEADER_LEN].copy_from_slice(&header);
    reader.read_exact(&mut bytes[FRAME_HEADER_LEN..]).await?;
    Ok(bytes)
}

fn unix_now_ns() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    )
    .unwrap_or(u64::MAX)
}

/// Packed listener transport or core failure.
#[derive(Debug, thiserror::Error)]
pub enum PackedServerError {
    #[error("invalid packed server configuration")]
    InvalidConfig,
    #[error("packed server I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("packed frame codec error: {0}")]
    Codec(#[from] codec::CodecError),
    #[error("packed receipt error: {0}")]
    Receipt(#[from] network::OrderBatchReceiptError),
    #[error("packed authenticated wrapper is invalid: {0}")]
    Authentication(#[from] network::AuthenticatedOrderBatchError),
    #[error("packed frame exceeds the authenticated batch maximum")]
    Oversize,
    #[error("packed frame arrived on the wrong traffic class or message type")]
    WrongLane,
    #[error("packed transport sequence mismatch: expected {expected}, got {actual}")]
    TransportSequence { expected: u64, actual: u64 },
    #[error("packed transport sequence exhausted")]
    SequenceExhausted,
    #[error("packed connection read timed out")]
    ReadTimeout,
    #[error("packed connection write timed out")]
    WriteTimeout,
    #[error("packed validator core failed: {0}")]
    Core(String),
    #[error(transparent)]
    Finality(#[from] PackedFinalityRouterError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PackedFinalityRouterError {
    #[error("packed finality router capacity must be nonzero")]
    InvalidCapacity,
    #[error("packed finality router is backpressured")]
    Backpressure,
    #[error("packed finality route requires executed registration or finalized delivery")]
    WrongStage,
    #[error("packed finality receipt is already registered")]
    DuplicateReceipt,
    #[error("packed finality receipt has no registered executed predecessor")]
    UnknownReceipt,
    #[error("packed finality receipt is not bound to a committed checkpoint")]
    UnboundReceipt,
    #[error("packed finality connection closed before delivery")]
    ConnectionClosed,
    #[error("packed finality connection sequence exhausted")]
    SequenceExhausted,
}

#[derive(Debug, thiserror::Error)]
pub enum PackedFinalityDeliveryError {
    #[error("checkpoint sequence range is out of order")]
    InvalidRange,
    #[error(transparent)]
    Bridge(#[from] crate::MinimmitReceiptBridgeError),
    #[error(transparent)]
    Router(#[from] PackedFinalityRouterError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::PackedOrder;
    use consensus::{BlockHeader, CheckpointHeader};
    use crypto::KeyPair;
    use execution::{CreateAccount, CreateMarket, DeterministicEngine, Engine, EngineConfig};
    use network::{
        decode_order_batch_receipt_frame, AuthenticatedOrderBatchCodec, OrderBatchBinding,
        OrderBatchReceiptStage,
    };
    use tokio::net::TcpStream;
    use types::{
        AccountId, Amount, Hash, MarketId, MarketType, OrderType, Price, Quantity, Ratio,
        SequenceNumber, ShardId, Side, TimeInForce, RATIO_SCALE,
    };

    fn h(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "dexos-packed-server-{}-{}",
            std::process::id(),
            unix_now_ns()
        ))
    }

    fn genesis() -> Engine {
        let mut engine = Engine::new(EngineConfig::default());
        engine
            .execute(
                SequenceNumber::new(1),
                execution::Command::CreateAccount(CreateAccount {
                    initial_collateral: Amount::from_raw(1_000_000_000),
                }),
            )
            .unwrap();
        engine
            .execute(
                SequenceNumber::new(2),
                execution::Command::CreateMarket(CreateMarket {
                    market: MarketId::new(0),
                    market_type: MarketType::Perpetual,
                    outcomes: 1,
                    mark_price: Price::from_raw(1_000_000),
                }),
            )
            .unwrap();
        engine
    }

    fn batch(signer: &KeyPair) -> Vec<u8> {
        striped_batch(7, signer, 11, 3, 10)
    }

    fn striped_batch(
        session_ref: u32,
        signer: &KeyPair,
        batch_sequence: u64,
        first_sequence: u64,
        nonce_base: u64,
    ) -> Vec<u8> {
        let records: Vec<_> = (0..32)
            .map(|index| PackedOrder::Submit {
                session_ref,
                nonce: nonce_base + index,
                client_id: nonce_base + index,
                account: AccountId::new(0),
                market: MarketId::new(0),
                side: Side::Bid,
                order_type: OrderType::Limit,
                price: Price::from_raw(1),
                quantity: Quantity::from_raw(1),
                time_in_force: TimeInForce::Gtc,
                leverage: Ratio::from_raw(RATIO_SCALE),
            })
            .collect();
        let mut packed = vec![0; records.len() * codec::PACKED_SUBMIT_LEN];
        let len = codec::encode_batch_into(&records, &mut packed).unwrap();
        AuthenticatedOrderBatchCodec::new()
            .encode(
                OrderBatchBinding {
                    destination: [5; 32],
                    session_ref,
                    account: AccountId::new(0),
                    batch_sequence,
                    first_sequence,
                },
                signer,
                32,
                false,
                &packed[..len],
            )
            .unwrap()
            .bytes
            .to_vec()
    }

    async fn read_receipt(stream: &mut TcpStream) -> network::OrderBatchReceipt {
        let bytes = read_frame(stream).await.unwrap();
        let (frame, consumed) = Frame::decode(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        decode_order_batch_receipt_frame(&frame).unwrap()
    }

    fn test_receipt(
        stage: OrderBatchReceiptStage,
        batch_sequence: u64,
        first_sequence: u64,
    ) -> OrderBatchReceipt {
        OrderBatchReceipt {
            stage,
            record_count: 32,
            admitted: 32,
            executed: u8::from(stage == OrderBatchReceiptStage::Executed),
            finalized: 0,
            failed: 0,
            rejection_code: 0,
            batch_sequence,
            first_sequence,
            checkpoint_height: None,
            observed_unix_ns: 10,
        }
    }

    fn executed_receipt(batch_sequence: u64, first_sequence: u64) -> OrderBatchReceipt {
        let mut receipt = test_receipt(
            OrderBatchReceiptStage::Executed,
            batch_sequence,
            first_sequence,
        );
        receipt.executed = 32;
        receipt
    }

    fn checkpoint(first_sequence: u64, last_sequence: u64) -> CheckpointHeader {
        CheckpointHeader {
            epoch: 0,
            shard_id: ShardId::new(0),
            first_sequence,
            last_sequence,
            previous_state_root: h(1),
            new_state_root: h(2),
            command_root: h(3),
            execution_root: h(4),
            oracle_root: h(5),
            timestamp: 6,
        }
    }

    fn checkpoint_block(height: u64, checkpoint: &CheckpointHeader) -> BlockHeader {
        BlockHeader {
            height,
            parent_hash: h(8),
            payload_root: checkpoint.hash(),
        }
    }

    fn register_test_route(
        router: &PackedFinalityRouter,
        server_id: u64,
        connection_id: u64,
        receipt: OrderBatchReceipt,
    ) -> mpsc::Receiver<OrderBatchReceipt> {
        let (sender, receiver) = mpsc::channel(4);
        router
            .reserve(
                server_id,
                connection_id,
                (receipt.batch_sequence, receipt.first_sequence),
                sender,
            )
            .unwrap()
            .commit(receipt);
        receiver
    }

    #[derive(Default)]
    struct TestCore {
        admissions: usize,
        last_key: Option<ReceiptKey>,
    }

    impl PackedServerCore for TestCore {
        fn readiness(&self, _bytes: &[u8]) -> Result<CoreReadiness, String> {
            Ok(CoreReadiness::Ready)
        }

        fn admit_receipt(
            &mut self,
            bytes: &[u8],
            _sequencer_now: u64,
            _observed_unix_ns: u64,
        ) -> Result<OrderBatchReceipt, String> {
            let header =
                inspect_authenticated_order_batch(bytes).map_err(|error| error.to_string())?;
            let key = (header.binding.batch_sequence, header.binding.first_sequence);
            self.admissions += 1;
            self.last_key = Some(key);
            Ok(test_receipt(OrderBatchReceiptStage::Admitted, key.0, key.1))
        }

        fn executed_receipt(
            &mut self,
            _observed_unix_ns: u64,
        ) -> Result<OrderBatchReceipt, String> {
            let (batch_sequence, first_sequence) = self
                .last_key
                .ok_or_else(|| "batch was not admitted".to_owned())?;
            Ok(executed_receipt(batch_sequence, first_sequence))
        }
    }

    async fn direct_runtime_server_smoke() {
        let signer = KeyPair::from_seed(&[21; 32]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let core = Rc::new(RefCell::new(TestCore::default()));
        let router = PackedFinalityRouter::new(4).unwrap();
        let (stop_tx, stop_rx) = watch::channel(false);
        let server = serve_packed_core_with_finality(
            listener,
            Rc::clone(&core),
            router.clone(),
            PackedServerConfig::default(),
            stop_rx,
        );
        let client = async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let frame = Frame {
                class: TrafficClass::NewOrder,
                msg_type: MSG_TYPE_ORDER_BATCH,
                sequence: 0,
                payload: batch(&signer),
            }
            .encode()
            .unwrap();
            stream.write_all(&frame).await.unwrap();
            assert_eq!(
                read_receipt(&mut stream).await.stage,
                OrderBatchReceiptStage::Admitted
            );
            assert_eq!(
                read_receipt(&mut stream).await.stage,
                OrderBatchReceiptStage::Executed
            );
            stop_tx.send(true).unwrap();
        };
        let (served, ()) = tokio::join!(server, client);
        assert_eq!(served.unwrap(), 1);
        assert_eq!(core.borrow().admissions, 1);
        assert_eq!(router.pending_receipts(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn server_can_be_awaited_directly_on_current_thread_runtime() {
        direct_runtime_server_smoke().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_can_be_awaited_directly_on_multi_thread_runtime() {
        direct_runtime_server_smoke().await;
    }

    #[tokio::test]
    async fn finality_capacity_is_reserved_before_core_mutation() {
        let signer = KeyPair::from_seed(&[22; 32]);
        let router = PackedFinalityRouter::new(1).unwrap();
        let server_id = router.allocate_server().unwrap();
        let occupied_connection = router.allocate_connection().unwrap();
        let _occupied_rx = register_test_route(
            &router,
            server_id,
            occupied_connection,
            executed_receipt(99, 99),
        );

        let core = Rc::new(RefCell::new(TestCore::default()));
        let (mut client, server) = tokio::io::duplex(16 * 1024);
        let frame = Frame {
            class: TrafficClass::NewOrder,
            msg_type: MSG_TYPE_ORDER_BATCH,
            sequence: 0,
            payload: batch(&signer),
        }
        .encode()
        .unwrap();
        client.write_all(&frame).await.unwrap();
        let (_stop_tx, stop_rx) = watch::channel(false);
        let (sequence_tx, _) = watch::channel(0);
        let result = handle_packed_connection(
            server,
            Rc::clone(&core),
            PackedConnectionContext {
                finality: router,
                server_id,
                connection_id: 7,
                config: PackedConnectionConfig {
                    finality_capacity: 4,
                    read_timeout: Duration::from_secs(1),
                    write_timeout: Duration::from_secs(1),
                },
                stop: stop_rx,
                sequence_tx,
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(PackedServerError::Finality(
                PackedFinalityRouterError::Backpressure
            ))
        ));
        assert_eq!(core.borrow().admissions, 0);
    }

    #[test]
    fn checkpoint_binding_is_atomic_across_router_and_bridge() {
        let router = PackedFinalityRouter::new(2).unwrap();
        let server_id = router.allocate_server().unwrap();
        let first_connection = router.allocate_connection().unwrap();
        let second_connection = router.allocate_connection().unwrap();
        let _first_rx = register_test_route(
            &router,
            server_id,
            first_connection,
            executed_receipt(1, 100),
        );
        let _second_rx = register_test_route(
            &router,
            server_id,
            second_connection,
            executed_receipt(2, 132),
        );
        let checkpoint = checkpoint(100, 163);
        let block = checkpoint_block(7, &checkpoint);
        let hash = block.hash();
        let mut bridge = MinimmitReceiptBridge::new(1, 1).unwrap();
        bridge.register_checkpoint(&block, checkpoint).unwrap();

        assert!(matches!(
            router.bind_checkpoint(&mut bridge, hash, 100, 163),
            Err(PackedFinalityDeliveryError::Bridge(
                crate::MinimmitReceiptBridgeError::ReceiptBackpressure
            ))
        ));
        assert_eq!(bridge.pending_receipts(), 0);
        assert!(router
            .0
            .borrow()
            .routes
            .values()
            .all(|route| !route.checkpoint_bound.get()));
    }

    #[tokio::test]
    async fn missing_and_closed_routes_do_not_block_live_finality() {
        let router = PackedFinalityRouter::new(3).unwrap();
        let server_id = router.allocate_server().unwrap();
        let missing_connection = router.allocate_connection().unwrap();
        let closed_connection = router.allocate_connection().unwrap();
        let live_connection = router.allocate_connection().unwrap();
        let missing = executed_receipt(1, 100);
        let closed = executed_receipt(2, 132);
        let live = executed_receipt(3, 164);
        let _missing_rx = register_test_route(&router, server_id, missing_connection, missing);
        let closed_rx = register_test_route(&router, server_id, closed_connection, closed);
        let mut live_rx = register_test_route(&router, server_id, live_connection, live);

        let checkpoint = checkpoint(100, 195);
        let block = checkpoint_block(7, &checkpoint);
        let hash = block.hash();
        let mut bridge = MinimmitReceiptBridge::new(1, 3).unwrap();
        bridge.register_checkpoint(&block, checkpoint).unwrap();
        assert_eq!(
            router.bind_checkpoint(&mut bridge, hash, 100, 195).unwrap(),
            3
        );
        router.remove_connection(missing_connection);
        drop(closed_rx);

        assert_eq!(
            deliver_minimmit_finality(
                &router,
                &mut bridge,
                MinimmitFinalityEvent::ConsensusFinal {
                    block: hash,
                    height: 7,
                },
                20,
            )
            .await
            .unwrap(),
            0
        );
        assert_eq!(
            deliver_minimmit_finality(
                &router,
                &mut bridge,
                MinimmitFinalityEvent::Finalized {
                    block: hash,
                    height: 7,
                    execution_root: h(2),
                },
                30,
            )
            .await
            .unwrap(),
            3
        );
        let finalized = live_rx.recv().await.unwrap();
        assert_eq!(finalized.batch_sequence, live.batch_sequence);
        assert_eq!(finalized.stage, OrderBatchReceiptStage::Finalized);
        assert_eq!(router.undeliverable_receipts(), 2);
        assert_eq!(router.pending_receipts(), 0);
        assert_eq!(bridge.pending_receipts(), 0);
        assert_eq!(bridge.pending_checkpoints(), 0);
    }

    #[tokio::test]
    async fn retryable_route_failure_retains_finality_evidence() {
        let router = PackedFinalityRouter::new(1).unwrap();
        let server_id = router.allocate_server().unwrap();
        let connection_id = router.allocate_connection().unwrap();
        let executed = executed_receipt(1, 100);
        let mut receiver = register_test_route(&router, server_id, connection_id, executed);
        let checkpoint = checkpoint(100, 131);
        let block = checkpoint_block(7, &checkpoint);
        let hash = block.hash();
        let mut bridge = MinimmitReceiptBridge::new(1, 1).unwrap();
        bridge.register_checkpoint(&block, checkpoint).unwrap();
        bridge.bind_executed(hash, executed).unwrap();
        bridge
            .observe_finality(
                MinimmitFinalityEvent::ConsensusFinal {
                    block: hash,
                    height: 7,
                },
                20,
            )
            .unwrap();

        assert!(matches!(
            deliver_minimmit_finality(
                &router,
                &mut bridge,
                MinimmitFinalityEvent::Finalized {
                    block: hash,
                    height: 7,
                    execution_root: h(2),
                },
                30,
            )
            .await,
            Err(PackedFinalityDeliveryError::Router(
                PackedFinalityRouterError::UnboundReceipt
            ))
        ));
        assert_eq!(bridge.pending_receipts(), 1);
        assert_eq!(router.pending_receipts(), 1);
        assert_eq!(router.undeliverable_receipts(), 0);

        router
            .0
            .borrow()
            .routes
            .get(&(executed.batch_sequence, executed.first_sequence))
            .unwrap()
            .checkpoint_bound
            .set(true);
        assert_eq!(
            deliver_minimmit_finality(
                &router,
                &mut bridge,
                MinimmitFinalityEvent::Finalized {
                    block: hash,
                    height: 7,
                    execution_root: h(2),
                },
                99,
            )
            .await
            .unwrap(),
            1
        );
        let finalized = receiver.recv().await.unwrap();
        assert_eq!(finalized.observed_unix_ns, 30);
        assert_eq!(bridge.pending_receipts(), 0);
    }

    #[tokio::test]
    async fn abort_and_server_drop_clean_externally_retained_routes() {
        let router = PackedFinalityRouter::new(2).unwrap();
        let server_id = router.allocate_server().unwrap();
        let connection_id = router.allocate_connection().unwrap();
        let _receiver =
            register_test_route(&router, server_id, connection_id, executed_receipt(1, 100));
        let task_router = router.clone();
        tokio::task::LocalSet::new()
            .run_until(async move {
                let task = tokio::task::spawn_local(async move {
                    let _guard = ConnectionRouteGuard {
                        router: task_router,
                        connection_id,
                    };
                    std::future::pending::<()>().await;
                });
                tokio::task::yield_now().await;
                task.abort();
                let _ = task.await;
            })
            .await;
        assert_eq!(router.pending_receipts(), 0);

        let second_connection = router.allocate_connection().unwrap();
        let _receiver = register_test_route(
            &router,
            server_id,
            second_connection,
            executed_receipt(2, 132),
        );
        let server_guard = ServerRouteGuard {
            router: router.clone(),
            server_id,
        };
        drop(server_guard);
        assert_eq!(router.pending_receipts(), 0);
    }

    #[tokio::test]
    async fn real_socket_delivers_only_checkpoint_promoted_finality() {
        let dir = temp_dir();
        let signer = KeyPair::from_seed(&[8; 32]);
        let session = crate::PackedSession {
            destination: [5; 32],
            session_ref: 7,
            account: AccountId::new(0),
            signer: signer.public(),
            authority: crate::PackedAuthority::Master,
            first_batch_sequence: 11,
            first_command_sequence: SequenceNumber::new(3),
            batch_sequence_stride: 1,
            command_sequence_stride: 0,
        };
        let journal = crate::PackedBatchJournal::open(&dir, 1024 * 1024).unwrap();
        let core =
            crate::PackedValidatorCore::recover(genesis(), session, journal, 256, 256, 8).unwrap();
        let core = Rc::new(RefCell::new(core));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = watch::channel(false);
        let server_core = Rc::clone(&core);
        let finality = PackedFinalityRouter::new(8).unwrap();
        let server_finality = finality.clone();
        tokio::task::LocalSet::new()
            .run_until(async move {
                let server = tokio::task::spawn_local(async move {
                    serve_packed_with_finality(
                        listener,
                        server_core,
                        server_finality,
                        PackedServerConfig::default(),
                        stop_rx,
                    )
                    .await
                    .unwrap()
                });

                let mut stream = TcpStream::connect(addr).await.unwrap();
                let frame = Frame {
                    class: TrafficClass::NewOrder,
                    msg_type: MSG_TYPE_ORDER_BATCH,
                    sequence: 0,
                    payload: batch(&signer),
                }
                .encode()
                .unwrap();
                stream.write_all(&frame).await.unwrap();
                let admitted = read_receipt(&mut stream).await;
                let executed = read_receipt(&mut stream).await;
                assert_eq!(admitted.stage, OrderBatchReceiptStage::Admitted);
                assert_eq!(executed.stage, OrderBatchReceiptStage::Executed);
                assert_eq!(executed.executed, 32);
                assert_eq!(executed.finalized, 0);
                assert_eq!(finality.pending_receipts(), 1);
                assert_eq!(
                    finality
                        .publish(crate::finalize_executed_receipt(executed, 9, 80).unwrap())
                        .await,
                    Err(PackedFinalityRouterError::UnboundReceipt)
                );
                let checkpoint = CheckpointHeader {
                    epoch: 0,
                    shard_id: ShardId::new(0),
                    first_sequence: 3,
                    last_sequence: 34,
                    previous_state_root: h(1),
                    new_state_root: h(2),
                    command_root: h(3),
                    execution_root: h(4),
                    oracle_root: h(5),
                    timestamp: 6,
                };
                let block = BlockHeader {
                    height: 9,
                    parent_hash: h(8),
                    payload_root: checkpoint.hash(),
                };
                let block_hash = block.hash();
                let mut bridge = MinimmitReceiptBridge::new(2, 8).unwrap();
                bridge.register_checkpoint(&block, checkpoint).unwrap();
                assert_eq!(
                    finality
                        .bind_checkpoint(&mut bridge, block_hash, 3, 34)
                        .unwrap(),
                    1
                );
                assert_eq!(
                    deliver_minimmit_finality(
                        &finality,
                        &mut bridge,
                        MinimmitFinalityEvent::ConsensusFinal {
                            block: block_hash,
                            height: 9,
                        },
                        70,
                    )
                    .await
                    .unwrap(),
                    0
                );
                assert_eq!(
                    deliver_minimmit_finality(
                        &finality,
                        &mut bridge,
                        MinimmitFinalityEvent::Finalized {
                            block: block_hash,
                            height: 9,
                            execution_root: h(2),
                        },
                        80,
                    )
                    .await
                    .unwrap(),
                    1
                );
                let finalized = read_receipt(&mut stream).await;
                assert_eq!(finalized.stage, OrderBatchReceiptStage::Finalized);
                assert_eq!(finalized.checkpoint_height, Some(9));
                assert_eq!(finality.pending_receipts(), 0);

                drop(stream);
                stop_tx.send(true).unwrap();
                assert_eq!(server.await.unwrap(), 1);
            })
            .await;
        drop(core);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn multi_session_socket_waits_for_the_exact_global_sequence() {
        let dir = temp_dir();
        let low_signer = KeyPair::from_seed(&[10; 32]);
        let high_signer = KeyPair::from_seed(&[11; 32]);
        let session =
            |session_ref, signer: &KeyPair, first_batch, first_command| crate::PackedSession {
                destination: [5; 32],
                session_ref,
                account: AccountId::new(0),
                signer: signer.public(),
                authority: crate::PackedAuthority::Master,
                first_batch_sequence: first_batch,
                first_command_sequence: SequenceNumber::new(first_command),
                batch_sequence_stride: 2,
                command_sequence_stride: 64,
            };
        let sessions = vec![
            session(7, &low_signer, 11, 3),
            session(8, &high_signer, 12, 35),
        ];
        let journal = crate::PackedBatchJournal::open(&dir, 1024 * 1024).unwrap();
        let core = crate::MultiSessionPackedValidatorCore::recover(
            genesis(),
            sessions,
            journal,
            256,
            256,
            8,
        )
        .unwrap();
        let core = Rc::new(RefCell::new(core));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop_tx, stop_rx) = watch::channel(false);
        let server_core = Rc::clone(&core);

        tokio::task::LocalSet::new()
            .run_until(async move {
                let server = tokio::task::spawn_local(async move {
                    serve_multi_packed_with_shutdown(
                        listener,
                        server_core,
                        PackedServerConfig::default(),
                        stop_rx,
                    )
                    .await
                    .unwrap()
                });

                let mut high = TcpStream::connect(addr).await.unwrap();
                let high_frame = Frame {
                    class: TrafficClass::NewOrder,
                    msg_type: MSG_TYPE_ORDER_BATCH,
                    sequence: 0,
                    payload: striped_batch(8, &high_signer, 12, 35, 200),
                }
                .encode()
                .unwrap();
                high.write_all(&high_frame).await.unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(25), read_receipt(&mut high))
                        .await
                        .is_err(),
                    "future striped batch must not be admitted early"
                );

                let mut low = TcpStream::connect(addr).await.unwrap();
                let low_frame = Frame {
                    class: TrafficClass::NewOrder,
                    msg_type: MSG_TYPE_ORDER_BATCH,
                    sequence: 0,
                    payload: striped_batch(7, &low_signer, 11, 3, 100),
                }
                .encode()
                .unwrap();
                low.write_all(&low_frame).await.unwrap();
                let low_admitted = read_receipt(&mut low).await;
                let low_executed = read_receipt(&mut low).await;
                assert_eq!(low_admitted.first_sequence, 3);
                assert_eq!(low_executed.first_sequence, 3);

                let high_admitted = read_receipt(&mut high).await;
                let high_executed = read_receipt(&mut high).await;
                assert_eq!(high_admitted.first_sequence, 35);
                assert_eq!(high_executed.first_sequence, 35);

                drop(low);
                drop(high);
                stop_tx.send(true).unwrap();
                assert_eq!(server.await.unwrap(), 2);
            })
            .await;
        assert_eq!(core.borrow().next_command_sequence(), 67);
        drop(core);
        let _ = std::fs::remove_dir_all(dir);
    }
}

//! Protocol-conformant reference sink for generator-capacity qualification.
//!
//! The sink accepts the exact production `proto::RpcRequest` frame, verifies signed
//! new/cancel/replace commands, and returns correlated production `RpcResponse`
//! acknowledgements. It deliberately does not execute business logic, durability, or
//! consensus, and its counters are labelled `reference-sink`; they must never be
//! reported as validator capacity.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use codec::{FRAME_HEADER_LEN, MAX_RPC_FRAME_PAYLOAD};
use proto::{
    command_hash, decode_request, encode_response, CommandAck, FinalityStatus, RpcError, RpcMethod,
    RpcOk, RpcResponse,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use types::OrderId;

/// Lock-free independently observed sink counters.
#[derive(Debug, Default)]
pub struct ReferenceSinkCounters {
    connections: AtomicU64,
    received: AtomicU64,
    accepted: AtomicU64,
    rejected: AtomicU64,
    malformed: AtomicU64,
    responses: AtomicU64,
}

impl ReferenceSinkCounters {
    /// Acquire a monotonic snapshot for interval reconciliation.
    #[must_use]
    pub fn snapshot(&self) -> ReferenceSinkSnapshot {
        ReferenceSinkSnapshot {
            mode: "reference-sink".to_string(),
            connections: self.connections.load(Ordering::Relaxed),
            received: self.received.load(Ordering::Relaxed),
            accepted: self.accepted.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            malformed: self.malformed.load(Ordering::Relaxed),
            responses: self.responses.load(Ordering::Relaxed),
        }
    }
}

/// Machine-readable reference-sink counter snapshot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReferenceSinkSnapshot {
    /// Permanent disambiguation from a validator run.
    pub mode: String,
    /// Connections accepted since startup.
    pub connections: u64,
    /// Complete production RPC requests decoded.
    pub received: u64,
    /// Valid signed trading requests accepted.
    pub accepted: u64,
    /// Decoded trading requests rejected by protocol/signature validation.
    pub rejected: u64,
    /// Malformed or unsupported frames.
    pub malformed: u64,
    /// Correlated production responses completely written.
    pub responses: u64,
}

/// Bounded reference-sink server settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceSinkConfig {
    /// Maximum concurrently served connections.
    pub max_connections: usize,
    /// Maximum request payload accepted before body allocation.
    pub max_payload: usize,
}

impl Default for ReferenceSinkConfig {
    fn default() -> Self {
        Self {
            max_connections: 16_384,
            max_payload: MAX_RPC_FRAME_PAYLOAD,
        }
    }
}

/// Serve until shutdown changes to true. Order traffic remains directly between
/// generators and this listener; the controller never proxies it.
pub async fn serve_reference_sink(
    listener: TcpListener,
    config: ReferenceSinkConfig,
    counters: Arc<ReferenceSinkCounters>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ReferenceSinkError> {
    if config.max_connections == 0 || config.max_payload == 0 {
        return Err(ReferenceSinkError::InvalidConfig);
    }
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let next_order = Arc::new(AtomicU64::new(1));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                counters.connections.fetch_add(1, Ordering::Relaxed);
                let counters = counters.clone();
                let next_order = next_order.clone();
                let connection_shutdown = shutdown.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let _ = handle_sink_connection(
                        stream,
                        config.max_payload,
                        counters,
                        next_order,
                        connection_shutdown,
                    )
                    .await;
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn handle_sink_connection<S>(
    mut stream: S,
    max_payload: usize,
    counters: Arc<ReferenceSinkCounters>,
    next_order: Arc<AtomicU64>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ReferenceSinkError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let bytes = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
                continue;
            }
            result = read_frame(&mut stream, max_payload) => match result {
                Ok(bytes) => bytes,
                Err(ReferenceSinkError::Io(error))
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::BrokenPipe
                    ) => return Ok(()),
                Err(error) => return Err(error),
            }
        };
        let request = match decode_request(&bytes) {
            Ok(request) => request,
            Err(error) => {
                counters.malformed.fetch_add(1, Ordering::Relaxed);
                let response = RpcResponse::new(0, Err(error));
                write_response(&mut stream, &response).await?;
                counters.responses.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        counters.received.fetch_add(1, Ordering::Relaxed);
        let response = process_request(request, &counters, &next_order);
        write_response(&mut stream, &response).await?;
        counters.responses.fetch_add(1, Ordering::Relaxed);
    }
}

fn process_request(
    request: proto::RpcRequest,
    counters: &ReferenceSinkCounters,
    next_order: &AtomicU64,
) -> RpcResponse {
    let request_id = request.request_id;
    let Some(command) = request.method.to_command() else {
        counters.rejected.fetch_add(1, Ordering::Relaxed);
        return RpcResponse::new(
            request_id,
            Err(RpcError::InvalidRequest(
                "reference sink accepts only trading controls".to_string(),
            )),
        );
    };
    let Some(meta) = request.method.control_meta() else {
        counters.rejected.fetch_add(1, Ordering::Relaxed);
        return RpcResponse::new(request_id, Err(RpcError::InvalidSignature));
    };
    if let Err(error) = meta.verify_signature(&command) {
        counters.rejected.fetch_add(1, Ordering::Relaxed);
        return RpcResponse::new(request_id, Err(error));
    }

    let (order_id, market_id) = match request.method {
        RpcMethod::SubmitOrder(_, params) => (
            Some(OrderId::new(next_order.fetch_add(1, Ordering::Relaxed))),
            Some(params.market),
        ),
        RpcMethod::CancelOrder(_, params) => (None, Some(params.market)),
        RpcMethod::ReplaceOrder(_, params) => (Some(params.order_id), Some(params.market)),
        _ => {
            counters.rejected.fetch_add(1, Ordering::Relaxed);
            return RpcResponse::new(
                request_id,
                Err(RpcError::InvalidRequest(
                    "reference sink accepts only new/cancel/replace".to_string(),
                )),
            );
        }
    };
    counters.accepted.fetch_add(1, Ordering::Relaxed);
    RpcResponse::new(
        request_id,
        Ok(RpcOk::CommandAck(CommandAck {
            command_hash: command_hash(&command),
            finality: FinalityStatus::Accepted,
            order_id,
            market_id,
        })),
    )
}

async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_payload: usize,
) -> Result<Vec<u8>, ReferenceSinkError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header).await?;
    let declared = u32::from_le_bytes([header[15], header[16], header[17], header[18]]);
    let payload_len = usize::try_from(declared).map_err(|_| ReferenceSinkError::Oversize)?;
    if payload_len > max_payload {
        return Err(ReferenceSinkError::Oversize);
    }
    let mut bytes = vec![0u8; FRAME_HEADER_LEN + payload_len];
    bytes[..FRAME_HEADER_LEN].copy_from_slice(&header);
    reader.read_exact(&mut bytes[FRAME_HEADER_LEN..]).await?;
    Ok(bytes)
}

async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: &RpcResponse,
) -> Result<(), ReferenceSinkError> {
    let bytes = encode_response(response).map_err(ReferenceSinkError::Protocol)?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Reference sink transport/protocol failure.
#[derive(Debug, thiserror::Error)]
pub enum ReferenceSinkError {
    /// Invalid zero capacity.
    #[error("invalid reference-sink configuration")]
    InvalidConfig,
    /// Socket failure.
    #[error("reference-sink I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Frame exceeded its configured bound.
    #[error("reference-sink frame exceeds configured payload bound")]
    Oversize,
    /// Response encoding failed.
    #[error("reference-sink protocol error: {0}")]
    Protocol(RpcError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommandKind, GeneratedCommand, RpcSessionAdapter, RpcSessionConfig};
    use proto::{decode_response, encode_request, RpcMethod};
    use tokio::net::TcpStream;
    use types::{AccountId, MarketId, OrderType, Price, Quantity, Side};

    fn generated(kind: CommandKind) -> GeneratedCommand {
        GeneratedCommand {
            session: 0,
            nonce: 0,
            idempotency_key: 1,
            market: MarketId::new(5),
            kind,
            side: Side::Bid,
            order_type: OrderType::Limit,
            time_in_force: types::TimeInForce::Gtc,
            price: Price::from_raw(10_000_000),
            quantity: Quantity::from_raw(1_000_000),
            target_order: None,
        }
    }

    async fn round_trip(stream: &mut TcpStream, request: &proto::RpcRequest) -> RpcResponse {
        let bytes = encode_request(request).unwrap();
        stream.write_all(&bytes).await.unwrap();
        stream.flush().await.unwrap();
        let bytes = read_frame(stream, MAX_RPC_FRAME_PAYLOAD).await.unwrap();
        decode_response(&bytes).unwrap()
    }

    #[tokio::test]
    async fn production_new_replace_cancel_round_trip_and_reconcile() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let counters = Arc::new(ReferenceSinkCounters::default());
        let (stop_tx, stop_rx) = watch::channel(false);
        let server_counters = counters.clone();
        let server = tokio::spawn(async move {
            serve_reference_sink(
                listener,
                ReferenceSinkConfig::default(),
                server_counters,
                stop_rx,
            )
            .await
            .unwrap();
        });
        let mut adapter = RpcSessionAdapter::new(RpcSessionConfig {
            account: AccountId::new(1),
            client_id: 9,
            nonce_base: 100,
            signing_seed: [8; 32],
            max_in_flight: 4,
            max_live_orders: 4,
        })
        .unwrap();
        let mut stream = TcpStream::connect(addr).await.unwrap();
        for (id, kind) in [
            (1, CommandKind::NewOrder),
            (2, CommandKind::Replace),
            (3, CommandKind::Cancel),
        ] {
            let request = adapter.build_request(id, &generated(kind)).unwrap();
            assert!(matches!(
                (&request.method, kind),
                (RpcMethod::SubmitOrder(..), CommandKind::NewOrder)
                    | (RpcMethod::ReplaceOrder(..), CommandKind::Replace)
                    | (RpcMethod::CancelOrder(..), CommandKind::Cancel)
            ));
            let response = round_trip(&mut stream, &request).await;
            adapter.apply_response(response).unwrap();
        }
        assert_eq!(adapter.live_order_count(), 0);
        drop(stream);
        stop_tx.send(true).unwrap();
        server.await.unwrap();
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.mode, "reference-sink");
        assert_eq!(snapshot.received, 3);
        assert_eq!(snapshot.accepted, 3);
        assert_eq!(snapshot.rejected, 0);
        assert_eq!(snapshot.responses, 3);
    }

    #[tokio::test]
    async fn unsigned_or_non_trading_requests_are_rejected_and_counted() {
        let counters = ReferenceSinkCounters::default();
        let next = AtomicU64::new(1);
        let response = process_request(
            proto::RpcRequest::new(7, RpcMethod::GetNetworkStatus),
            &counters,
            &next,
        );
        assert_eq!(response.request_id, 7);
        assert!(response.result.is_err());
        assert_eq!(counters.snapshot().rejected, 1);
    }
}

//! Persistent client for the authenticated production packed-order lane.

use std::collections::HashSet;
use std::io::{BufReader, Cursor};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

pub use codec::PackedOrder;
use codec::{encode_batch_into, Frame, TrafficClass, FRAME_HEADER_LEN, PACKED_SUBMIT_LEN};
use network::{
    decode_order_batch_receipt_frame, AuthenticatedOrderBatchCodec, AuthenticatedOrderBatchError,
    OrderBatchBinding, OrderBatchReceipt, OrderBatchReceiptError, OrderBatchReceiptStage,
    MAX_PENDING_ORDER_BATCH_FINALITY, MSG_TYPE_ORDER_BATCH, ORDER_BATCH_RECEIPT_LEN,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::{client::TlsStream, TlsConnector};
use types::AccountId;

const MIN_RECORDS: usize = 32;
const MAX_RECORDS: usize = 128;
const MAX_PACKED_BYTES: usize = MAX_RECORDS * PACKED_SUBMIT_LEN;

/// Optional client certificate and private key for mutual TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientTlsIdentity {
    pub certificate_chain_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
}

/// Explicit development plaintext or certificate-verified TLS 1.3 transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackedTransport {
    DevPlaintext,
    Tls13 {
        server_name: String,
        ca_certificates_pem: Vec<u8>,
        client_identity: Option<ClientTlsIdentity>,
    },
}

/// Server-issued identity and disjoint replay sequence range for one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedLease {
    pub endpoint: SocketAddr,
    pub source_ip: Option<IpAddr>,
    pub destination: [u8; 32],
    pub session_ref: u32,
    pub account: AccountId,
    pub first_batch_sequence: u64,
    pub first_command_sequence: u64,
    pub batch_sequence_stride: u64,
    /// Zero advances contiguously by the record count.
    pub command_sequence_stride: u64,
}

/// Highest lifecycle boundary that a call must observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionBoundary {
    Executed,
    Finalized,
}

/// Correlated lifecycle evidence returned for a submitted batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackedBatchResult {
    pub batch_sequence: u64,
    pub first_sequence: u64,
    pub admitted: Option<OrderBatchReceipt>,
    pub executed: OrderBatchReceipt,
    pub finalized: Option<OrderBatchReceipt>,
}

/// One persistent, signed packed-order connection.
///
/// Calls are intentionally serialized. Use one client per server-issued lease
/// when an application needs concurrent in-flight batches.
pub struct PackedClient {
    lease: PackedLease,
    stream: PackedStream,
    signer: crypto::KeyPair,
    codec: AuthenticatedOrderBatchCodec,
    next_transport_sequence: u64,
    next_receipt_sequence: u64,
    next_batch_sequence: u64,
    next_command_sequence: u64,
    retired_executed: HashSet<(u64, u64)>,
    usable: bool,
}

impl PackedClient {
    /// Establish a persistent connection and initialize it from a server lease.
    pub async fn connect(
        lease: PackedLease,
        signing_seed: [u8; 32],
        transport: PackedTransport,
    ) -> Result<Self, PackedClientError> {
        validate_lease(&lease)?;
        let stream = connect_stream(lease.endpoint, lease.source_ip, &transport).await?;
        Ok(Self {
            lease,
            stream,
            signer: crypto::KeyPair::from_seed(&signing_seed),
            codec: AuthenticatedOrderBatchCodec::new(),
            next_transport_sequence: 0,
            next_receipt_sequence: 0,
            next_batch_sequence: lease.first_batch_sequence,
            next_command_sequence: lease.first_command_sequence,
            // Allocate lazily: the shared protocol bound is large enough to
            // cover every route the server may retain, but ordinary clients
            // should not pay that memory cost up front.
            retired_executed: HashSet::new(),
            usable: true,
        })
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signer.public()
    }

    #[must_use]
    pub const fn next_batch_sequence(&self) -> u64 {
        self.next_batch_sequence
    }

    #[must_use]
    pub const fn next_command_sequence(&self) -> u64 {
        self.next_command_sequence
    }

    /// Sign, write, and await correlated lifecycle receipts for one full batch.
    pub async fn send_batch(
        &mut self,
        records: &[PackedOrder],
        boundary: CompletionBoundary,
        receipt_timeout: Duration,
    ) -> Result<PackedBatchResult, PackedClientError> {
        if !self.usable {
            return Err(PackedClientError::ConnectionPoisoned);
        }
        if boundary == CompletionBoundary::Executed {
            ensure_finality_correlation_capacity(&self.retired_executed)?;
        }
        validate_records(&self.lease, records)?;
        let count =
            u8::try_from(records.len()).map_err(|_| PackedClientError::BatchSize(records.len()))?;
        let command_advance = if self.lease.command_sequence_stride == 0 {
            u64::from(count)
        } else {
            self.lease.command_sequence_stride
        };
        if command_advance < u64::from(count) {
            return Err(PackedClientError::InvalidLease);
        }
        let next_batch = self
            .next_batch_sequence
            .checked_add(self.lease.batch_sequence_stride)
            .ok_or(PackedClientError::SequenceExhausted)?;
        let next_command = self
            .next_command_sequence
            .checked_add(command_advance)
            .ok_or(PackedClientError::SequenceExhausted)?;
        let next_transport = self
            .next_transport_sequence
            .checked_add(1)
            .ok_or(PackedClientError::SequenceExhausted)?;

        let mut packed = [0u8; MAX_PACKED_BYTES];
        let packed_len = encode_batch_into(records, &mut packed)?;
        let binding = OrderBatchBinding {
            destination: self.lease.destination,
            session_ref: self.lease.session_ref,
            account: self.lease.account,
            batch_sequence: self.next_batch_sequence,
            first_sequence: self.next_command_sequence,
        };
        let payload = self
            .codec
            .encode(binding, &self.signer, count, false, &packed[..packed_len])?
            .bytes
            .to_vec();
        let wire = Frame {
            class: TrafficClass::NewOrder,
            msg_type: MSG_TYPE_ORDER_BATCH,
            sequence: self.next_transport_sequence,
            payload,
        }
        .encode()?;
        // From the first write onward, an error is ambiguous: the peer may have
        // accepted some or all of the frame. Only a correlated completion makes
        // this lease safe to use again.
        self.usable = false;
        self.stream.write_all(&wire).await?;
        self.stream.flush().await?;

        // A write can be ambiguous on failure, so state advances only after the
        // complete frame is accepted by the local socket. Any later error makes
        // this connection unsuitable for an automatic retry.
        self.next_transport_sequence = next_transport;
        self.next_batch_sequence = next_batch;
        self.next_command_sequence = next_command;

        let mut admitted = None;
        let mut executed = None;
        loop {
            let receipt = tokio::time::timeout(receipt_timeout, self.read_receipt())
                .await
                .map_err(|_| PackedClientError::ReceiptTimeout)??;
            let key = (receipt.batch_sequence, receipt.first_sequence);
            if key != (binding.batch_sequence, binding.first_sequence) {
                if receipt.stage == OrderBatchReceiptStage::Finalized
                    && self.retired_executed.remove(&key)
                {
                    continue;
                }
                return Err(PackedClientError::UnknownReceipt {
                    batch_sequence: receipt.batch_sequence,
                    first_sequence: receipt.first_sequence,
                });
            }
            if receipt.record_count != count {
                return Err(PackedClientError::ReceiptCount {
                    expected: count,
                    actual: receipt.record_count,
                });
            }
            match receipt.stage {
                OrderBatchReceiptStage::Rejected => {
                    return Err(PackedClientError::Rejected(receipt.rejection_code));
                }
                OrderBatchReceiptStage::Admitted => admitted = Some(receipt),
                OrderBatchReceiptStage::Executed => {
                    executed = Some(receipt);
                    if boundary == CompletionBoundary::Executed {
                        remember_retired_execution(&mut self.retired_executed, key)?;
                        self.usable = true;
                        return Ok(PackedBatchResult {
                            batch_sequence: binding.batch_sequence,
                            first_sequence: binding.first_sequence,
                            admitted,
                            executed: receipt,
                            finalized: None,
                        });
                    }
                }
                OrderBatchReceiptStage::Finalized => {
                    let execution = executed.ok_or(PackedClientError::MissingExecutionReceipt)?;
                    self.usable = true;
                    return Ok(PackedBatchResult {
                        batch_sequence: binding.batch_sequence,
                        first_sequence: binding.first_sequence,
                        admitted,
                        executed: execution,
                        finalized: Some(receipt),
                    });
                }
            }
        }
    }

    async fn read_receipt(&mut self) -> Result<OrderBatchReceipt, PackedClientError> {
        let mut header = [0u8; FRAME_HEADER_LEN];
        self.stream.read_exact(&mut header).await?;
        let payload_len = usize::try_from(u32::from_le_bytes(
            header[15..19].try_into().unwrap_or([0; 4]),
        ))
        .map_err(|_| PackedClientError::ReceiptFrame)?;
        if payload_len != ORDER_BATCH_RECEIPT_LEN {
            return Err(PackedClientError::ReceiptFrame);
        }
        let mut bytes = vec![0; FRAME_HEADER_LEN + payload_len];
        bytes[..FRAME_HEADER_LEN].copy_from_slice(&header);
        self.stream
            .read_exact(&mut bytes[FRAME_HEADER_LEN..])
            .await?;
        let (frame, consumed) = Frame::decode_with_max(&bytes, ORDER_BATCH_RECEIPT_LEN)?;
        if consumed != bytes.len() || frame.sequence != self.next_receipt_sequence {
            return Err(PackedClientError::ReceiptSequence {
                expected: self.next_receipt_sequence,
                actual: frame.sequence,
            });
        }
        self.next_receipt_sequence = self
            .next_receipt_sequence
            .checked_add(1)
            .ok_or(PackedClientError::SequenceExhausted)?;
        Ok(decode_order_batch_receipt_frame(&frame)?)
    }
}

fn remember_retired_execution(
    retired: &mut HashSet<(u64, u64)>,
    key: (u64, u64),
) -> Result<(), PackedClientError> {
    ensure_finality_correlation_capacity(retired)?;
    if !retired.insert(key) {
        return Err(PackedClientError::DuplicateFinalityCorrelation);
    }
    Ok(())
}

fn ensure_finality_correlation_capacity(
    retired: &HashSet<(u64, u64)>,
) -> Result<(), PackedClientError> {
    if retired.len() >= MAX_PENDING_ORDER_BATCH_FINALITY {
        return Err(PackedClientError::FinalityCorrelationCapacity);
    }
    Ok(())
}

fn validate_lease(lease: &PackedLease) -> Result<(), PackedClientError> {
    if lease.batch_sequence_stride == 0 {
        return Err(PackedClientError::InvalidLease);
    }
    if let Some(source) = lease.source_ip {
        if source.is_ipv4() != lease.endpoint.is_ipv4() {
            return Err(PackedClientError::SourceAddressFamily);
        }
    }
    Ok(())
}

fn validate_records(lease: &PackedLease, records: &[PackedOrder]) -> Result<(), PackedClientError> {
    if !(MIN_RECORDS..=MAX_RECORDS).contains(&records.len()) {
        return Err(PackedClientError::BatchSize(records.len()));
    }
    for record in records {
        if record.session_ref() != lease.session_ref || record.account() != lease.account {
            return Err(PackedClientError::RecordBinding);
        }
    }
    Ok(())
}

enum PackedStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for PackedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for PackedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

async fn connect_stream(
    endpoint: SocketAddr,
    source_ip: Option<IpAddr>,
    transport: &PackedTransport,
) -> Result<PackedStream, PackedClientError> {
    let socket = match endpoint {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    if let Some(source_ip) = source_ip {
        socket.bind(SocketAddr::new(source_ip, 0))?;
    }
    let tcp = socket.connect(endpoint).await?;
    tcp.set_nodelay(true)?;
    match transport {
        PackedTransport::DevPlaintext => Ok(PackedStream::Plain(tcp)),
        PackedTransport::Tls13 {
            server_name,
            ca_certificates_pem,
            client_identity,
        } => {
            let connector = tls_connector(ca_certificates_pem, client_identity.as_ref())?;
            let name = ServerName::try_from(server_name.clone())
                .map_err(|error| PackedClientError::TlsConfig(error.to_string()))?;
            let tls = connector
                .connect(name, tcp)
                .await
                .map_err(|error| PackedClientError::TlsHandshake(error.to_string()))?;
            Ok(PackedStream::Tls(Box::new(tls)))
        }
    }
}

fn tls_connector(
    roots_pem: &[u8],
    identity: Option<&ClientTlsIdentity>,
) -> Result<TlsConnector, PackedClientError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    let certs = rustls_pemfile::certs(&mut BufReader::new(Cursor::new(roots_pem)))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|error| PackedClientError::TlsConfig(error.to_string()))?;
    if certs.is_empty() {
        return Err(PackedClientError::TlsConfig(
            "no CA certificates supplied".to_string(),
        ));
    }
    for cert in certs {
        roots
            .add(cert)
            .map_err(|error| PackedClientError::TlsConfig(error.to_string()))?;
    }
    let builder = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots);
    let mut config = match identity {
        None => builder.with_no_client_auth(),
        Some(identity) => {
            let certs = rustls_pemfile::certs(&mut BufReader::new(Cursor::new(
                &identity.certificate_chain_pem,
            )))
            .collect::<Result<Vec<CertificateDer<'static>>, _>>()
            .map_err(|error| PackedClientError::TlsConfig(error.to_string()))?;
            let key = rustls_pemfile::private_key(&mut BufReader::new(Cursor::new(
                &identity.private_key_pem,
            )))
            .map_err(|error| PackedClientError::TlsConfig(error.to_string()))?
            .ok_or_else(|| PackedClientError::TlsConfig("no client private key".to_string()))?;
            builder
                .with_client_auth_cert(certs, PrivateKeyDer::clone_key(&key))
                .map_err(|error| PackedClientError::TlsConfig(error.to_string()))?
        }
    };
    config.alpn_protocols = vec![b"dexos-rpc/1".to_vec()];
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Packed-lane validation, transport, or lifecycle failure.
#[derive(Debug, thiserror::Error)]
pub enum PackedClientError {
    #[error("invalid packed session lease")]
    InvalidLease,
    #[error("packed connection is unusable after an ambiguous in-flight failure")]
    ConnectionPoisoned,
    #[error("source address and endpoint use different address families")]
    SourceAddressFamily,
    #[error("batch size {0} is outside 32..=128")]
    BatchSize(usize),
    #[error("a record does not match the lease session/account binding")]
    RecordBinding,
    #[error("packed session sequence exhausted")]
    SequenceExhausted,
    #[error("packed record encoding failed: {0}")]
    PackedRecord(#[from] codec::PackedOrderError),
    #[error("authenticated batch encoding failed: {0}")]
    AuthenticatedBatch(#[from] AuthenticatedOrderBatchError),
    #[error("frame codec failed: {0}")]
    Frame(#[from] codec::CodecError),
    #[error("receipt validation failed: {0}")]
    Receipt(#[from] OrderBatchReceiptError),
    #[error("socket I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS configuration failed: {0}")]
    TlsConfig(String),
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),
    #[error("receipt deadline elapsed")]
    ReceiptTimeout,
    #[error("receipt frame has an invalid length")]
    ReceiptFrame,
    #[error("receipt sequence mismatch: expected {expected}, got {actual}")]
    ReceiptSequence { expected: u64, actual: u64 },
    #[error("receipt record count mismatch: expected {expected}, got {actual}")]
    ReceiptCount { expected: u8, actual: u8 },
    #[error("receipt does not correlate: batch={batch_sequence}, first={first_sequence}")]
    UnknownReceipt {
        batch_sequence: u64,
        first_sequence: u64,
    },
    #[error("batch was rejected with code {0}")]
    Rejected(u16),
    #[error("finalized receipt arrived without execution evidence")]
    MissingExecutionReceipt,
    #[error("late-finality correlation capacity was exhausted")]
    FinalityCorrelationCapacity,
    #[error("duplicate late-finality correlation key")]
    DuplicateFinalityCorrelation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finality_correlation_capacity_fails_without_evicting_evidence() {
        let mut retired = HashSet::new();
        for sequence in 0..MAX_PENDING_ORDER_BATCH_FINALITY {
            let sequence = u64::try_from(sequence).expect("protocol bound fits u64");
            remember_retired_execution(&mut retired, (sequence, sequence + 1))
                .expect("within shared finality bound");
        }
        assert!(matches!(
            remember_retired_execution(&mut retired, (u64::MAX, u64::MAX)),
            Err(PackedClientError::FinalityCorrelationCapacity)
        ));
        assert_eq!(retired.len(), MAX_PENDING_ORDER_BATCH_FINALITY);
        assert!(retired.contains(&(0, 1)));
        let last =
            u64::try_from(MAX_PENDING_ORDER_BATCH_FINALITY - 1).expect("protocol bound fits u64");
        assert!(retired.contains(&(last, last + 1)));
        assert!(!retired.contains(&(u64::MAX, u64::MAX)));
    }
}

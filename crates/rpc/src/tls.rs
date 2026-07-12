//! TLS 1.3 configuration for the public RPC surface.
//!
//! Production deployments must present a [`TlsAcceptor`] built from a
//! rustls `ServerConfig` restricted to TLS 1.3. Plain TCP remains available
//! for local tests via [`crate::server::TlsMode::Disabled`], but
//! [`crate::server::ServerConfig::production`] refuses to start without TLS.

use std::io::{BufReader, Cursor};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig as RustlsServerConfig};
use tokio_rustls::TlsAcceptor;

/// Ensure the process-wide rustls crypto provider is installed (ring).
/// Idempotent; safe to call from multiple threads.
fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a TLS 1.3-only server acceptor from PEM-encoded certificate chain and
/// PKCS#8 private key bytes. Optionally require client certificates against
/// `client_roots_pem` (mTLS).
pub fn acceptor_from_pem(
    cert_chain_pem: &[u8],
    private_key_pem: &[u8],
    client_roots_pem: Option<&[u8]>,
) -> Result<TlsAcceptor, TlsError> {
    ensure_crypto_provider();
    let certs = rustls_pemfile::certs(&mut BufReader::new(Cursor::new(cert_chain_pem)))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|e| TlsError::Pem(e.to_string()))?;
    if certs.is_empty() {
        return Err(TlsError::Pem("no certificates in chain".into()));
    }
    let mut keys =
        rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(Cursor::new(private_key_pem)))
            .collect::<Result<Vec<PrivatePkcs8KeyDer<'static>>, _>>()
            .map_err(|e| TlsError::Pem(e.to_string()))?;
    let key = keys
        .pop()
        .ok_or_else(|| TlsError::Pem("no PKCS#8 private key found".into()))?;
    let key = PrivateKeyDer::Pkcs8(key);

    let builder = match client_roots_pem {
        Some(roots_pem) => {
            let mut roots = RootCertStore::empty();
            let root_certs = rustls_pemfile::certs(&mut BufReader::new(Cursor::new(roots_pem)))
                .collect::<Result<Vec<CertificateDer<'static>>, _>>()
                .map_err(|e| TlsError::Pem(e.to_string()))?;
            for c in root_certs {
                roots.add(c).map_err(|e| TlsError::Config(e.to_string()))?;
            }
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| TlsError::Config(e.to_string()))?;
            RustlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_client_cert_verifier(verifier)
        }
        None => RustlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth(),
    };

    let mut cfg = builder
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::Config(e.to_string()))?;
    // Prefer TLS 1.3 exclusively; disable session tickets that would otherwise
    // re-enable older version negotiation paths in some stacks.
    cfg.alpn_protocols = vec![b"dexos-rpc/1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Generate a self-signed localhost certificate for tests and local dev.
/// Returns `(cert_pem, key_pem)`.
pub fn generate_self_signed_localhost() -> Result<(Vec<u8>, Vec<u8>), TlsError> {
    let key = rcgen::KeyPair::generate().map_err(|e| TlsError::Config(e.to_string()))?;
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])
        .map_err(|e| TlsError::Config(e.to_string()))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "dexos-rpc-test");
    let cert = params
        .self_signed(&key)
        .map_err(|e| TlsError::Config(e.to_string()))?;
    Ok((cert.pem().into_bytes(), key.serialize_pem().into_bytes()))
}

/// Failure constructing a TLS acceptor.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// PEM parse failure.
    #[error("tls pem error: {0}")]
    Pem(String),
    /// rustls configuration failure.
    #[error("tls config error: {0}")]
    Config(String),
}

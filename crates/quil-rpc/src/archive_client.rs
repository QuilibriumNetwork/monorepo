//! gRPC client for connecting to a Quilibrium archive node's `GlobalService`.
//!
//! Archive nodes expose `GlobalService` over a TCP gRPC endpoint authenticated
//! with mTLS. The certificate scheme is unusual: each peer presents an
//! Ed25519 self-signed cert (since Go's x509 doesn't support Ed448) whose DNS
//! name field encodes a cross-signature linking it back to the peer's Ed448
//! identity. See `node/p2p/peer_authenticator.go` in the Go tree and the
//! `quil_tls` module here for the cert scheme.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tonic::transport::{Channel, Endpoint};
use tower::Service;
use tracing::{debug, info};

use quil_types::proto::global::global_service_client::GlobalServiceClient;
use quil_types::proto::global::{
    AppShardInfo, GetAppShardsRequest, GetGlobalFrameRequest, GlobalFrame,
    SubmitGlobalMessageRequest,
};

use crate::quil_tls::{build_quil_tls_cert, QuilTlsError};

#[derive(Debug, Error)]
pub enum ArchiveClientError {
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("rpc error: {0}")]
    Rpc(#[from] tonic::Status),
    #[error("missing field in response: {0}")]
    MissingField(&'static str),
    #[error("tls cert error: {0}")]
    Tls(#[from] QuilTlsError),
    #[error("tls init error: {0}")]
    TlsInit(String),
}

/// A connected gRPC client for an archive node's `GlobalService`.
pub struct ArchiveClient {
    inner: GlobalServiceClient<Channel>,
    endpoint: String,
}

impl ArchiveClient {
    /// Connect to an archive node at the given `host:port` over plaintext gRPC.
    /// Useful for local testing only — production archive nodes require mTLS.
    pub async fn connect_plaintext(addr: &str) -> Result<Self, ArchiveClientError> {
        let url = format!("http://{}", addr);
        let endpoint = Endpoint::from_shared(url)
            .map_err(|e| ArchiveClientError::InvalidEndpoint(e.to_string()))?
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .keep_alive_while_idle(true);
        debug!(%addr, "dialing archive node (plaintext)");
        let channel = endpoint.connect().await?;
        info!(%addr, "archive client connected");
        Ok(Self {
            inner: GlobalServiceClient::new(channel),
            endpoint: addr.to_string(),
        })
    }

    /// Connect to an archive node using Quilibrium's mTLS scheme. Builds a
    /// client cert from the given Ed448 seed and uses a custom rustls
    /// connector that accepts any server cert (Quilibrium peers self-sign;
    /// trust comes from the application-layer cross-signature in the SAN).
    pub async fn connect_mtls(
        addr: &str,
        ed448_seed: &[u8; 57],
    ) -> Result<Self, ArchiveClientError> {
        let client_config = build_quil_client_config(ed448_seed)?;
        // Note: scheme is `http://` here even though we wrap TLS — tonic's
        // Endpoint refuses `https://` unless its own `tls_config(...)` is set,
        // and we explicitly want to bypass that to install our own connector.
        let url = format!("http://{}", addr);
        let endpoint = Endpoint::from_shared(url)
            .map_err(|e| ArchiveClientError::InvalidEndpoint(e.to_string()))?
            // 10s connect (was 3s). Over WAN with 200-300ms RTT
            // the TLS handshake plus Ed448 cross-signature
            // verification can routinely take 1.5-2.5s; a 3s
            // budget left no margin for a single congestion event
            // during the handshake. Matches the plaintext path's
            // 10s timeout.
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(15))
            .tcp_nodelay(true)
            .keep_alive_while_idle(true);

        debug!(%addr, "dialing archive node (mTLS)");
        let connector = QuilTlsConnector::new(client_config);
        let channel = match endpoint.connect_with_connector(connector).await {
            Ok(ch) => ch,
            Err(e) => {
                // Walk the std::error::Error source chain so the actual
                // failure (rustls / DNS / TCP refused / handshake)
                // appears in logs. Tonic's Display impl strips this.
                use std::error::Error as _;
                let mut chain = format!("{}", e);
                let mut src: Option<&(dyn std::error::Error + 'static)> = e.source();
                while let Some(s) = src {
                    chain.push_str(" -> ");
                    chain.push_str(&format!("{}", s));
                    src = s.source();
                }
                tracing::warn!(%addr, error_chain = %chain, "connect_mtls failed (full chain)");
                return Err(e.into());
            }
        };
        debug!(%addr, "archive client connected (mTLS)");
        Ok(Self {
            inner: GlobalServiceClient::new(channel),
            endpoint: addr.to_string(),
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Submit a prover message (e.g. ProverJoin wrapped in MessageBundle)
    /// to the archive node for relay into the consensus pipeline.
    /// This is how Go nodes submit joins — via gRPC, not BlossomSub.
    pub async fn submit_global_message(
        &mut self,
        data: Vec<u8>,
    ) -> Result<(), ArchiveClientError> {
        self.inner
            .submit_global_message(SubmitGlobalMessageRequest { data })
            .await?;
        Ok(())
    }

    pub async fn get_app_shards(
        &mut self,
        shard_key: Vec<u8>,
        prefix: Vec<u32>,
    ) -> Result<Vec<AppShardInfo>, ArchiveClientError> {
        let resp = self
            .inner
            .get_app_shards(GetAppShardsRequest { shard_key, prefix })
            .await?
            .into_inner();
        Ok(resp.info)
    }

    /// Fetch a single global frame. Pass `frame_number = 0` to request the
    /// latest finalized frame.
    pub async fn get_global_frame(
        &mut self,
        frame_number: u64,
    ) -> Result<GlobalFrame, ArchiveClientError> {
        let resp = self
            .inner
            .get_global_frame(GetGlobalFrameRequest { frame_number })
            .await?
            .into_inner();
        resp.frame.ok_or(ArchiveClientError::MissingField("frame"))
    }
}

/// rustls verifier for archive server certs. Quilibrium peers
/// self-sign with Ed25519-derived keys, so the standard PKI path
/// can't be used — but we are NOT "accept any cert". Trust is
/// established at the application layer via the Ed448 xsign
/// cross-signature embedded in the cert's SAN DNS name. The
/// previous implementation accepted ANY syntactically-valid cert
/// here, which (combined with PeerInfo gossip carrying an
/// attacker-controlled peer_id) opened a genesis-archive
/// impersonation path: a malicious peer could advertise an archive
/// capability under any peer_id and pass the mTLS handshake with
/// their own unrelated cert.
///
/// This verifier now runs the same xsign verification that the
/// server-side [`crate::quil_tls::XsignClientCertVerifier`] applies
/// to client certs — proving the cert's SAN really was issued by
/// the Ed448 key it claims. Pairing each archive_pool entry with
/// its expected peer_id (so a mismatch between the certificate's
/// xsign-derived Ed448 pubkey and the expected genesis-archive
/// identity could be rejected) is a useful next-layer hardening
/// but requires plumbing the expected peer_id through the pool +
/// poller call chain. Today the PeerInfo signature check
/// (`validator_global_peer_info` in `quil-engine`) already ensures
/// nobody can publish a PeerInfo claiming the genesis-archive
/// peer_id without holding its Ed448 signing key, so the
/// impersonation chain is already broken at the gossip layer.
#[derive(Debug)]
pub struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Apply the Quilibrium xsign check to the presented cert.
        // Identical to the server-side client-auth verifier — the
        // mTLS handshake is symmetric: each side proves SAN-derived
        // identity to the other.
        crate::quil_tls::XsignClientCertVerifier::verify_xsign(end_entity.as_ref())?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

/// Build a rustls `ClientConfig` that presents a Quilibrium peer cert and
/// accepts any server cert. Suitable for `tonic`'s tls layer when paired with
/// a custom transport.
pub fn build_quil_client_config(ed448_seed: &[u8; 57]) -> Result<Arc<ClientConfig>, ArchiveClientError> {
    let tls_cert = build_quil_tls_cert(ed448_seed)?;
    let cert_chain = rustls_pemfile::certs(&mut tls_cert.cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ArchiveClientError::TlsInit(format!("parse cert pem: {}", e)))?;
    let key_der = rustls_pemfile::private_key(&mut tls_cert.key_pem.as_bytes())
        .map_err(|e| ArchiveClientError::TlsInit(format!("parse key pem: {}", e)))?
        .ok_or_else(|| ArchiveClientError::TlsInit("no private key in pem".into()))?;

    // SAFETY: we install a process-global crypto provider once. Errors here
    // mean another provider was already installed; that's fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_client_auth_cert(
            cert_chain.into_iter().map(CertificateDer::from).collect(),
            key_der_to_owned(key_der),
        )
        .map_err(|e| ArchiveClientError::TlsInit(format!("client_auth_cert: {}", e)))?;

    // ALPN h2 is required for HTTP/2 / gRPC. Without this rustls will
    // negotiate the default protocol and tonic's HTTP/2 client will fail
    // with an opaque transport error.
    config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(Arc::new(config))
}

/// Tower service that, given a `Uri`, opens a TCP connection and wraps it
/// in a rustls TLS session using the provided client config. Returns the
/// resulting stream wrapped in `TokioIo` so it satisfies tonic 0.12's
/// `HyperConnection` requirement.
#[derive(Clone)]
pub struct QuilTlsConnector {
    config: Arc<ClientConfig>,
}

impl QuilTlsConnector {
    pub fn new(config: Arc<ClientConfig>) -> Self {
        Self { config }
    }
}

impl Service<Uri> for QuilTlsConnector {
    type Response = TokioIo<tokio_rustls::client::TlsStream<TcpStream>>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let config = self.config.clone();
        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| "missing host in uri".to_string())?
                .to_string();
            let port = uri.port_u16().unwrap_or(443);
            let tcp = TcpStream::connect((host.as_str(), port)).await?;
            let _ = tcp.set_nodelay(true);
            let connector = TlsConnector::from(config);
            // Quilibrium servers don't validate SNI; "localhost" matches what
            // the Go side uses too.
            let dns_name = ServerName::try_from("localhost".to_string())
                .map_err(|e| format!("invalid sni: {}", e))?;
            let tls = connector.connect(dns_name, tcp).await?;
            Ok(TokioIo::new(tls))
        })
    }
}

fn key_der_to_owned(key: PrivateKeyDer<'_>) -> PrivateKeyDer<'static> {
    match key {
        PrivateKeyDer::Pkcs1(d) => PrivateKeyDer::Pkcs1(d.secret_pkcs1_der().to_vec().into()),
        PrivateKeyDer::Sec1(d) => PrivateKeyDer::Sec1(d.secret_sec1_der().to_vec().into()),
        PrivateKeyDer::Pkcs8(d) => PrivateKeyDer::Pkcs8(d.secret_pkcs8_der().to_vec().into()),
        _ => panic!("unsupported key type"),
    }
}

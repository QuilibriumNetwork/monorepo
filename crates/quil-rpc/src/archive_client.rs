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
    AppShardInfo, GetAppShardsRequest, GetGlobalFrameRequest, GetGlobalProposalRequest,
    GlobalFrame, GlobalProposal, SubmitGlobalConsensusRequest, SubmitGlobalMessageRequest,
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
///
/// `Clone` is cheap: the inner tonic client shares one multiplexed h2
/// `Channel`, so cached connections can be cloned per request (e.g. the
/// direct global-consensus publisher fanning to several archives).
#[derive(Clone)]
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
            // 64 MiB decode/encode limit (tonic defaults to 4 MiB). Full
            // global frames and app-shard size sets routinely exceed 4 MiB;
            // the default silently failed those RPCs. Matches the hypersync
            // client limits in `hypergraph_sync_probe`.
            inner: GlobalServiceClient::new(channel)
                .max_decoding_message_size(64 * 1024 * 1024)
                .max_encoding_message_size(64 * 1024 * 1024),
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
            // Actively PING the peer every 10s. `keep_alive_while_idle(true)`
            // alone is a NO-OP in tonic unless an interval is set — without
            // this, an idle cached connection sends nothing, the peer's h2
            // keepalive (20s interval / 10s timeout on the :8340 server)
            // reaps it, and the next use forces a full reconnect + the
            // expensive Ed448 mTLS handshake. Pinging under the peer's reap
            // window keeps consensus/sync connections alive so they're
            // reused instead of re-handshaken.
            .http2_keep_alive_interval(Duration::from_secs(10))
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
            // 64 MiB decode/encode limit (tonic defaults to 4 MiB). Full
            // global frames and app-shard size sets routinely exceed 4 MiB;
            // the default silently failed those RPCs. Matches the hypersync
            // client limits in `hypergraph_sync_probe`.
            inner: GlobalServiceClient::new(channel)
                .max_decoding_message_size(64 * 1024 * 1024)
                .max_encoding_message_size(64 * 1024 * 1024),
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

    /// Deliver a global-consensus message (proposal / vote / timeout)
    /// point-to-point to a peer archive. `bitmask` is the original gossip
    /// topic (GLOBAL_FRAME or GLOBAL_CONSENSUS) so the receiver routes it
    /// through the matching handler. Global consensus uses this instead of
    /// gossip because a full-coverage proposal exceeds the gossip
    /// message-size ceiling.
    pub async fn submit_global_consensus(
        &mut self,
        bitmask: Vec<u8>,
        data: Vec<u8>,
    ) -> Result<(), ArchiveClientError> {
        self.inner
            .submit_global_consensus(SubmitGlobalConsensusRequest { bitmask, data })
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

    /// Fetch the full proposal (state + parent QC + prior TC + vote) for
    /// `frame_number`, so a lagging node can submit it into its consensus loop
    /// to catch up. The server returns an empty response (no proposal) on a
    /// lookup miss, which surfaces here as `MissingField`.
    pub async fn get_global_proposal(
        &mut self,
        frame_number: u64,
    ) -> Result<GlobalProposal, ArchiveClientError> {
        let resp = self
            .inner
            .get_global_proposal(GetGlobalProposalRequest { frame_number })
            .await?
            .into_inner();
        resp.proposal.ok_or(ArchiveClientError::MissingField("proposal"))
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
pub struct AcceptAnyServerCert {
    /// Signature-verification algorithms from the installed crypto provider,
    /// used to perform the real TLS `CertificateVerify` proof-of-possession
    /// check in `verify_tls1x_signature`.
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl Default for AcceptAnyServerCert {
    /// Build a verifier wired to the ring crypto provider's signature
    /// algorithms (matching the provider installed by
    /// `build_quil_client_config`).
    fn default() -> Self {
        Self {
            supported: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }
}

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
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // This callback IS the TLS proof-of-possession check: verify the
        // server's CertificateVerify signature against the cert's Ed25519 key,
        // proving the live server holds the cert's private half. Without it a
        // replayed (public) peer cert would be accepted from any party.
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // The Quilibrium cert always uses Ed25519 — narrow the list so
        // rustls negotiates that scheme. (The Go side leaves it open;
        // restricting here is harmless and surfaces mismatches early.)
        // Mirrors the server-side `XsignClientCertVerifier`.
        vec![SignatureScheme::ED25519]
    }
}

/// Build a rustls `ClientConfig` that presents a Quilibrium peer cert and
/// accepts any server cert. Suitable for `tonic`'s tls layer when paired with
/// a custom transport.
/// Process-wide cache of built client TLS configs, keyed by Ed448 seed.
/// The config is a pure, deterministic function of the seed — same seed
/// always yields the identical cert + cross-signature — but building it
/// runs a (slow, vendored-pure-Rust) Ed448 public-key derivation + Ed448
/// SIGN plus x509 cert generation. Recomputing that on every `connect_mtls`
/// put an Ed448 signature on the critical path of every outbound dial
/// (thousands per node under reconnect churn), starving the `:8340`
/// handshake path that consensus delivery depends on. Build once, reuse.
static CLIENT_CONFIG_CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<[u8; 57], Arc<ClientConfig>>>,
> = std::sync::OnceLock::new();

pub fn build_quil_client_config(ed448_seed: &[u8; 57]) -> Result<Arc<ClientConfig>, ArchiveClientError> {
    let cache = CLIENT_CONFIG_CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    if let Some(cfg) = cache.lock().unwrap().get(ed448_seed) {
        return Ok(cfg.clone());
    }
    let cfg = build_quil_client_config_uncached(ed448_seed)?;
    cache.lock().unwrap().insert(*ed448_seed, cfg.clone());
    Ok(cfg)
}

fn build_quil_client_config_uncached(ed448_seed: &[u8; 57]) -> Result<Arc<ClientConfig>, ArchiveClientError> {
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
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert::default()))
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

// =====================================================================
// Proof-of-possession regression test — CLIENT direction, END-TO-END HANDSHAKE.
//
// Mirror of `quil_tls::tests::acceptor_completes_handshake_with_forged_client_signature`
// for the outbound side. `AcceptAnyServerCert::verify_xsign` proves the
// server's cert is genuine (the Ed448 identity authorized its Ed25519 cert
// key) but NOT that the live server holds the cert's private key. That second
// guarantee is the TLS `CertificateVerify` check, which rustls routes through
// `verify_tls1x_signature`. `AcceptAnyServerCert` now performs that check (it
// previously stubbed those callbacks to `Ok(assertion())`, which let a server
// present a public cert it did not own — signing CertificateVerify with a
// different key — and still be accepted).
//
// The repro drives a real TLS 1.3 handshake through the actual production
// client construction (`build_quil_client_config`) and asserts the client
// REJECTS the forged server. It failed before possession was enforced (the
// handshake succeeded, demonstrating the bypass); it now guards against that
// regression.
// =====================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use rustls::sign::CertifiedKey;
    use rustls::ServerConfig;
    use tokio_rustls::TlsAcceptor;

    fn cert_chain_from_seed(seed: &[u8; 57]) -> Vec<CertificateDer<'static>> {
        let tls = build_quil_tls_cert(seed).unwrap();
        rustls_pemfile::certs(&mut tls.cert_pem.as_bytes())
            .map(|r| r.unwrap())
            .collect()
    }

    /// Load the Ed25519 signing key derived from `seed`. Pairing this with a
    /// *different* seed's cert chain via `CertifiedKey::new` (which — unlike
    /// `from_der` — does not check the key matches the cert) is the forgery:
    /// present someone else's cert, sign with your own key.
    fn signing_key_from_seed(seed: &[u8; 57]) -> Arc<dyn rustls::sign::SigningKey> {
        let tls = build_quil_tls_cert(seed).unwrap();
        let key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut tls.key_pem.as_bytes())
                .unwrap()
                .unwrap();
        rustls::crypto::ring::sign::any_supported_type(&key).unwrap()
    }

    /// Server resolver presenting a fixed `CertifiedKey` — used to pair a
    /// victim's cert chain with an attacker's (mismatched) key for the forged
    /// repro, and a matched pair for the positive control.
    #[derive(Debug)]
    struct StaticServerCert(Arc<CertifiedKey>);
    impl rustls::server::ResolvesServerCert for StaticServerCert {
        fn resolve(
            &self,
            _client_hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    fn acceptor_for(cert: Arc<CertifiedKey>) -> TlsAcceptor {
        // SAFETY: install the default provider once; an error just means
        // another provider is already installed.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(StaticServerCert(cert)));
        // Match the client's ALPN so the handshake fails (or succeeds) on the
        // cert check, not on protocol negotiation.
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        TlsAcceptor::from(Arc::new(cfg))
    }

    #[tokio::test]
    async fn client_rejects_forged_server_signature() {
        // Attacker server: victim's public cert (0x61) + attacker's own,
        // different key (0x62) — a server that does NOT possess the cert key.
        let forged = Arc::new(CertifiedKey::new(
            cert_chain_from_seed(&[0x61u8; 57]),
            signing_key_from_seed(&[0x62u8; 57]),
        ));
        let acceptor = acceptor_for(forged);

        // Production client, built exactly as the node does.
        let connector = TlsConnector::from(build_quil_client_config(&[0x71u8; 57]).unwrap());

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_name = ServerName::try_from("localhost").unwrap();
        let (_server_res, client_res) = tokio::join!(
            acceptor.accept(server_io),
            connector.connect(server_name, client_io),
        );

        assert!(
            client_res.is_err(),
            "VULNERABILITY: build_quil_client_config (AcceptAnyServerCert) completed the \
             handshake with a server that presented the victim's cert but signed \
             CertificateVerify with a different key — proof-of-possession is not \
             enforced, so the server identity is spoofable by cert replay",
        );
    }

    /// Positive control: the SAME client must SUCCEED against a legitimate
    /// server that actually possesses its cert's key. Proves the forged test
    /// fails specifically because possession is missing — not because of ALPN,
    /// the duplex transport, or some other setup detail. Passes before and
    /// after the fix (all possession is legitimate).
    #[tokio::test]
    async fn client_accepts_legitimate_server() {
        let seed = [0x61u8; 57];
        let legit = Arc::new(CertifiedKey::new(
            cert_chain_from_seed(&seed),
            signing_key_from_seed(&seed),
        ));
        let acceptor = acceptor_for(legit);

        let connector = TlsConnector::from(build_quil_client_config(&[0x71u8; 57]).unwrap());

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_name = ServerName::try_from("localhost").unwrap();
        let (server_res, client_res) = tokio::join!(
            acceptor.accept(server_io),
            connector.connect(server_name, client_io),
        );

        assert!(
            client_res.is_ok(),
            "legitimate handshake must succeed (client side): {:?}",
            client_res.err(),
        );
        assert!(
            server_res.is_ok(),
            "legitimate handshake must succeed (server side): {:?}",
            server_res.err(),
        );
    }
}

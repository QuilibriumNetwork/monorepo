//! The gRPC partition proxy's serving loop — a transparent HTTP/2 reverse proxy.
//!
//! gRPC is HTTP/2 with length-prefixed message frames plus a `grpc-status`
//! trailer. Forwarding it requires no protobuf/codec knowledge: we proxy the
//! raw h2 request (method, path, headers, streaming body) to the backend and
//! stream the response (headers, body, trailers) back. The proxy terminates
//! mTLS on both sides — presenting the backend's identity to the caller, and
//! re-originating the call with the caller's identity to the backend — so the
//! backend sees the true requester.
//!
//! One TLS-terminating listener per backend (port `9000 + ordinal`) gives
//! port-based routing. The caller is identified from its client certificate
//! after the handshake; partitioned calls get a gRPC trailers-only `UNAVAILABLE`
//! response.
//!
//! Live-iteration items (need a running backend to tune): mid-stream
//! cancellation on a partition change (currently gated at request start, which
//! covers the short inter-node gRPC calls — the long-lived consensus traffic is
//! gossip, partitioned by the BlossomSub forward filter), and upstream
//! connection-failure retry.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use quil_p2p::PeerId;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::consensus_events::{extract_from_grpc_message, ConsensusEvent};
use crate::grpc_proxy::{caller_peer_id_from_cert, partition_allows, BackendSpec};
use crate::partitioner::NetworkPartitioner;

/// gRPC method whose request bodies carry global consensus since v2.1.0.25.
const SUBMIT_GLOBAL_CONSENSUS_PATH: &str = "/SubmitGlobalConsensus";

/// Body type used for proxied requests/responses (errors type-erased).
type ProxyBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;
type H2Sender = hyper::client::conn::http2::SendRequest<ProxyBody>;

/// Serve every backend concurrently. Returns when all listeners exit (which they
/// don't, barring a bind error), so spawn this on the supervisor.
pub async fn serve_all(
    backends: Vec<Arc<BackendSpec>>,
    partitioner: Arc<NetworkPartitioner>,
    consensus_tx: mpsc::Sender<ConsensusEvent>,
) -> Result<()> {
    let mut handles = Vec::new();
    for spec in backends {
        let partitioner = Arc::clone(&partitioner);
        let consensus_tx = consensus_tx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = serve_backend(spec.clone(), partitioner, consensus_tx).await {
                tracing::error!(port = spec.listen_port, error = %e, "gRPC backend listener exited");
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

/// Accept loop for one backend: TLS-terminate, identify the caller, and serve
/// its forwarded h2 connection.
async fn serve_backend(
    spec: Arc<BackendSpec>,
    partitioner: Arc<NetworkPartitioner>,
    consensus_tx: mpsc::Sender<ConsensusEvent>,
) -> Result<()> {
    let addr: SocketAddr = format!("0.0.0.0:{}", spec.listen_port)
        .parse()
        .context("parse listen addr")?;
    let listener = TcpListener::bind(addr).await.context("bind listener")?;
    let acceptor = TlsAcceptor::from(spec.server_tls.clone());
    tracing::info!(port = spec.listen_port, backend = %spec.backend_addr, "gRPC proxy backend listening");

    loop {
        let (tcp, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let spec = Arc::clone(&spec);
        let partitioner = Arc::clone(&partitioner);
        let consensus_tx = consensus_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_connection(tcp, acceptor, spec, partitioner, consensus_tx).await {
                tracing::debug!(error = %e, "proxied connection ended");
            }
        });
    }
}

async fn serve_connection(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    spec: Arc<BackendSpec>,
    partitioner: Arc<NetworkPartitioner>,
    consensus_tx: mpsc::Sender<ConsensusEvent>,
) -> Result<()> {
    let tls = acceptor.accept(tcp).await.context("server TLS handshake")?;

    // Identify the caller from the client certificate presented during mTLS.
    let caller = {
        let (_, conn) = tls.get_ref();
        conn.peer_certificates()
            .and_then(|certs| certs.first())
            .and_then(|c| caller_peer_id_from_cert(c.as_ref()))
            .context("no/invalid caller certificate")?
    };

    // Open one upstream h2 connection to the backend, presenting the caller's
    // identity. Reused for every request on this inbound connection: the h2
    // `SendRequest` is cheaply cloneable and multiplexes concurrent streams over
    // the single connection, so each request clones it rather than sharing it
    // behind a lock (which would serialize otherwise-concurrent calls).
    let sender = connect_backend(&spec, &caller)
        .await
        .context("dial backend as caller")?;
    let backend_peer = spec.backend_peer_id;
    let partitioner_for_svc = Arc::clone(&partitioner);

    let service = service_fn(move |req: Request<Incoming>| {
        // Clone the h2 sender per request: clones share the single upstream
        // connection but each opens its own multiplexed stream.
        let sender = sender.clone();
        let partitioner = Arc::clone(&partitioner_for_svc);
        let consensus_tx = consensus_tx.clone();
        async move { forward(req, caller, backend_peer, partitioner, sender, consensus_tx).await }
    });

    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(tls), service)
        .await
        .map_err(|e| anyhow::anyhow!("serve_connection: {e}"))
}

/// Dial the backend over mTLS presenting `caller`'s identity and complete an
/// HTTP/2 handshake, returning the request sender.
async fn connect_backend(spec: &BackendSpec, caller: &PeerId) -> Result<H2Sender> {
    let client_config = spec
        .client_tls
        .get(caller)
        .with_context(|| format!("no client TLS config for caller {caller}"))?
        .clone();
    let tcp = TcpStream::connect(&spec.backend_addr)
        .await
        .with_context(|| format!("connect backend {}", spec.backend_addr))?;
    let connector = TlsConnector::from(client_config);
    // The xsign verifier ignores the SNI name (trust is the cert's SAN
    // cross-signature), so any valid DNS name works.
    let server_name = ServerName::try_from("backend").context("server name")?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .context("client TLS handshake")?;
    let (sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(tls))
        .await
        .context("backend h2 handshake")?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(error = %e, "backend h2 connection closed");
        }
    });
    Ok(sender)
}

/// Forward one request to the backend, gating on the partition table.
async fn forward(
    req: Request<Incoming>,
    caller: PeerId,
    backend: PeerId,
    partitioner: Arc<NetworkPartitioner>,
    mut sender: H2Sender,
    consensus_tx: mpsc::Sender<ConsensusEvent>,
) -> Result<Response<ProxyBody>, std::convert::Infallible> {
    let (parts, body) = req.into_parts();

    // Global consensus travels point-to-point over `SubmitGlobalConsensus` since
    // v2.1.0.25. Buffer that (unary) request body so we can snoop the frame for
    // the same ConsensusEvent the gossip path used to yield, then forward it
    // unchanged. Snoop BEFORE the partition gate so an isolated archive's
    // consensus attempts are still observed for rank/frame/timeout tracking even
    // though their delivery is blocked. Every other method streams through
    // untouched.
    let boxed: ProxyBody = if parts.uri.path().ends_with(SUBMIT_GLOBAL_CONSENSUS_PATH) {
        match body.collect().await {
            Ok(collected) => {
                let bytes = collected.to_bytes();
                match extract_from_grpc_message(&bytes) {
                    // Drop on a full/closed channel, never block the forward.
                    // The main loop tolerates duplicates (the same message fans
                    // out to every backend listener).
                    Ok(Some(event)) => {
                        let _ = consensus_tx.try_send(event);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::error!(error = %e, "SubmitGlobalConsensus consensus snoop failed")
                    }
                }
                Full::new(bytes).map_err(|never| match never {}).boxed()
            }
            Err(e) => {
                tracing::debug!(error = %e, "buffering SubmitGlobalConsensus body failed");
                return Ok(error_response("devnet: backend unavailable"));
            }
        }
    } else {
        // Re-box the request body so request and response share one body type.
        body.map_err(box_err).boxed()
    };

    if !partition_allows(&partitioner, &caller, &backend) {
        return Ok(partition_response());
    }

    let upstream_req = Request::from_parts(parts, boxed);

    // This `sender` is the caller's own clone of the shared h2 connection, so
    // the request gets an independent multiplexed stream — concurrent requests
    // on the same inbound connection no longer serialize on a lock.
    let result = match sender.ready().await {
        Ok(()) => sender.send_request(upstream_req).await,
        Err(e) => Err(e),
    };
    match result {
        Ok(resp) => Ok(resp.map(|b| b.map_err(box_err).boxed())),
        Err(e) => {
            tracing::debug!(error = %e, "backend request failed");
            Ok(error_response("devnet: backend unavailable"))
        }
    }
}

fn box_err<E: std::error::Error + Send + Sync + 'static>(
    e: E,
) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(e)
}

fn empty_body() -> ProxyBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// A gRPC "trailers-only" UNAVAILABLE response (status carried in headers).
fn partition_response() -> Response<ProxyBody> {
    error_response("devnet: network partition")
}

fn error_response(message: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .header("grpc-status", "14") // UNAVAILABLE
        .header("grpc-message", message)
        .body(empty_body())
        .expect("static response is valid")
}

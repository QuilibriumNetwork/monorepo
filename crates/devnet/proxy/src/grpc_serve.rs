//! The gRPC partition proxy's serving loop — a transparent HTTP/2 reverse proxy.
//!
//! gRPC is HTTP/2 with length-prefixed message frames plus a `grpc-status`
//! trailer. Forwarding it requires no protobuf/codec knowledge: we proxy the
//! raw h2 request (method, path, headers, streaming body) to the backend and
//! stream the response (headers, body, trailers) back. The proxy terminates
//! the transport on both sides — presenting the backend's identity to the
//! caller, and re-originating the call with the caller's identity to the
//! backend — so the backend sees the true requester.
//!
//! The `:8340` transport is sntrup761 PQNoise (there is no rustls/mTLS on that
//! port since the Falcon peer-id migration), so each side of the relay runs a
//! PQNoise handshake keyed by a Falcon signing key: the backend's when
//! answering a caller, the caller's when dialing the backend.
//!
//! One PQNoise-terminating listener per backend (port `9000 + ordinal`) gives
//! port-based routing. The caller is the peer ID the inbound handshake
//! verifies; partitioned calls get a gRPC trailers-only `UNAVAILABLE`
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
use quil_rpc::pqnoise_channel::{pq_client_handshake, pq_server_handshake};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use std::sync::atomic::{AtomicU64, Ordering};

use crate::consensus_events::{extract_from_grpc_message, ConsensusEvent, CwConsensusCursor};
use crate::grpc_proxy::{partition_allows, BackendSpec};
use crate::partitioner::NetworkPartitioner;
use crate::view_schedule::ViewSchedule;

/// Prover address per caller peer ID, the CW frame cursor, and the partition
/// schedule. Shared by every backend listener so the snoop sees one consistent
/// view of consensus.
pub struct SnoopContext {
    /// Maps a handshake-verified caller to the prover address the event loop
    /// identifies it by.
    pub prover_addresses: std::collections::HashMap<PeerId, Vec<u8>>,
    pub cursor: CwConsensusCursor,
    /// Applied inline by [`forward`], before the partition gate.
    pub schedule: Arc<ViewSchedule>,
    /// Consensus events the event loop could not accept. Any drop invalidates
    /// the run's verdict, so this is reported rather than tolerated.
    pub dropped: AtomicU64,
}

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
    snoop: Arc<SnoopContext>,
) -> Result<()> {
    let mut handles = Vec::new();
    for spec in backends {
        let partitioner = Arc::clone(&partitioner);
        let consensus_tx = consensus_tx.clone();
        let snoop = Arc::clone(&snoop);
        handles.push(tokio::spawn(async move {
            if let Err(e) = serve_backend(spec.clone(), partitioner, consensus_tx, snoop).await {
                tracing::error!(port = spec.listen_port, error = %e, "gRPC backend listener exited");
            }
        }));
    }
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}

/// Accept loop for one backend: run the PQNoise handshake as the backend,
/// identify the caller, and serve its forwarded h2 connection.
async fn serve_backend(
    spec: Arc<BackendSpec>,
    partitioner: Arc<NetworkPartitioner>,
    consensus_tx: mpsc::Sender<ConsensusEvent>,
    snoop: Arc<SnoopContext>,
) -> Result<()> {
    let addr: SocketAddr = format!("0.0.0.0:{}", spec.listen_port)
        .parse()
        .context("parse listen addr")?;
    let listener = TcpListener::bind(addr).await.context("bind listener")?;
    tracing::info!(port = spec.listen_port, backend = %spec.backend_addr, "gRPC proxy backend listening");

    loop {
        let (tcp, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let spec = Arc::clone(&spec);
        let partitioner = Arc::clone(&partitioner);
        let consensus_tx = consensus_tx.clone();
        let snoop = Arc::clone(&snoop);
        tokio::spawn(async move {
            if let Err(e) = serve_connection(tcp, spec, partitioner, consensus_tx, snoop).await {
                tracing::debug!(error = %e, "proxied connection ended");
            }
        });
    }
}

async fn serve_connection(
    tcp: TcpStream,
    spec: Arc<BackendSpec>,
    partitioner: Arc<NetworkPartitioner>,
    consensus_tx: mpsc::Sender<ConsensusEvent>,
    snoop: Arc<SnoopContext>,
) -> Result<()> {
    // Answer as the backend, so the caller believes it reached the archive.
    // The handshake verifies the caller's identity as a side effect — that is
    // the role the mTLS client cert played before the PQNoise migration.
    let secured = pq_server_handshake(tcp, &spec.backend_falcon_key)
        .await
        .context("server PQNoise handshake")?;
    let caller = secured.peer_id();

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
        let snoop = Arc::clone(&snoop);
        async move {
            forward(
                req,
                caller,
                backend_peer,
                partitioner,
                sender,
                consensus_tx,
                snoop,
            )
            .await
        }
    });

    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(secured), service)
        .await
        .map_err(|e| anyhow::anyhow!("serve_connection: {e}"))
}

/// Dial the backend over PQNoise presenting `caller`'s identity and complete an
/// HTTP/2 handshake, returning the request sender.
async fn connect_backend(spec: &BackendSpec, caller: &PeerId) -> Result<H2Sender> {
    let caller_key = spec
        .caller_falcon_keys
        .get(caller)
        .with_context(|| format!("no falcon signing key for caller {caller}"))?
        .clone();
    let tcp = TcpStream::connect(&spec.backend_addr)
        .await
        .with_context(|| format!("connect backend {}", spec.backend_addr))?;
    let (_backend_peer, secured) = pq_client_handshake(tcp, &caller_key)
        .await
        .context("client PQNoise handshake")?;
    let (sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(secured))
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
#[allow(clippy::too_many_arguments)]
async fn forward(
    req: Request<Incoming>,
    caller: PeerId,
    backend: PeerId,
    partitioner: Arc<NetworkPartitioner>,
    mut sender: H2Sender,
    consensus_tx: mpsc::Sender<ConsensusEvent>,
    snoop: Arc<SnoopContext>,
) -> Result<Response<ProxyBody>, std::convert::Infallible> {
    let (parts, body) = req.into_parts();

    // Global consensus travels point-to-point over `SubmitGlobalConsensus` since
    // v2.1.0.25 (legacy topic and commonware-simplex channels alike). Buffer that
    // (unary) request body so we can snoop the frame for the same ConsensusEvent
    // the gossip path used to yield, then forward it unchanged. The event is
    // attributed to `caller`, whose identity the PQNoise handshake verified.
    // Snoop BEFORE the partition gate so an isolated archive's consensus
    // attempts are still observed for view/frame tracking even though their
    // delivery is blocked. Every other method streams through untouched.
    let boxed: ProxyBody = if parts.uri.path().ends_with(SUBMIT_GLOBAL_CONSENSUS_PATH) {
        match body.collect().await {
            Ok(collected) => {
                let bytes = collected.to_bytes();
                let caller_address = snoop
                    .prover_addresses
                    .get(&caller)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                match extract_from_grpc_message(&bytes, caller_address, &snoop.cursor) {
                    Ok(Some(event)) => {
                        // Apply the schedule here, before the partition gate
                        // below, so the message that revealed this view is
                        // itself subject to the partition it triggers. Going
                        // through the event loop instead would let this message
                        // — and every concurrent fan-out copy of it — forward
                        // against the pre-transition state.
                        snoop.schedule.observe_view(event.view);
                        // Never block the forward on a full channel, but a drop
                        // means the event loop's tally is incomplete, so record
                        // it and fail the run rather than degrade quietly.
                        if consensus_tx.try_send(event).is_err()
                            && snoop.dropped.fetch_add(1, Ordering::Relaxed) == 0
                        {
                            tracing::error!(
                                "consensus event dropped; the run verdict is no longer valid"
                            );
                        }
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

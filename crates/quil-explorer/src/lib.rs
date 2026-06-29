//! In-process explorer REST API for the Quilibrium node.
//!
//! A Rust port of the standalone Go `node/explorer` binary, but served
//! **in-process over the node's live stores** rather than over an
//! independently-synced second copy of the chain — eliminating the
//! double-storage cost. The JSON contract is byte-compatible with the Go
//! explorer so existing dashboards work unchanged.
//!
//! Started only on archive nodes (which hold the full frame + hypergraph
//! history) and only when `config.explorer.enabled` is set. See
//! [`router`] / [`serve`] and the wiring in `quil-node`'s master node.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
    routing::any,
    Router,
};
use parking_lot::RwLock;

pub mod handlers;
pub mod message_ring;

pub use message_ring::{RecentMessage, RecentMessageRing};

/// Per-shard metadata provider, structurally identical to
/// `quil_rpc::global_service::AppShardsProvider`: given a 35-byte
/// `shard_key` (L1[3]||L2[32]) and a `prefix` path, returns
/// `(size_be, data_shards, commitments[4])` derived from the live CRDT.
/// The master node passes the same closure it gives the gRPC global
/// service, so `/provers/shards` sizes match the `GetAppShards` RPC the Go
/// explorer queried.
pub type AppShardsProvider =
    Arc<dyn Fn(&[u8], &[u32]) -> Option<(Vec<u8>, u64, [Vec<u8>; 4])> + Send + Sync>;

/// Provider for per-shard coverage-halt durations, keyed by confirmation
/// filter. Given the current frame number, returns the same map the
/// archive evictor consults: a value of `u64::MAX` means the shard is fully
/// halted (exempt from eviction this tick), a smaller value is subtracted
/// from a prover's inactivity. The master node builds this from the live
/// `CoverageMonitor`, so the explorer's eviction-risk numbers match real
/// eviction decisions. `None` when unavailable.
pub type HaltDurationsProvider =
    Arc<dyn Fn(u64) -> std::collections::HashMap<Vec<u8>, u64> + Send + Sync>;

/// Inactivity grace before an active prover is evicted, in frames
/// (`eviction_grace_frames` in `frame_materializer`). Surfaced so the
/// eviction-risk endpoint reports a prover's exact runway.
pub const EVICTION_THRESHOLD_FRAMES: u64 = 360;

/// Shared, cloneable handles the explorer reads from. All are live node
/// stores/state — the explorer never opens its own database.
#[derive(Clone)]
pub struct ExplorerState {
    pub clock_store: Arc<dyn quil_types::store::ClockStore>,
    pub crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    pub prover_registry: Arc<dyn quil_types::consensus::ProverRegistry>,
    pub key_store: Arc<dyn quil_types::store::KeyStore>,
    pub shards_store: Arc<dyn quil_types::store::ShardsStore>,
    pub app_shards_provider: Option<AppShardsProvider>,
    /// Per-shard coverage-halt durations provider (eviction-risk endpoint).
    pub halt_durations_provider: Option<HaltDurationsProvider>,
    pub peer_info_cache: Arc<RwLock<HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>>>,
    pub messages: Arc<RecentMessageRing>,
    /// Current global frame number, used for prover effective-status grace
    /// calculations (`get_prover_shard_summaries`).
    pub current_frame: Arc<AtomicU64>,
    /// Short-lived response cache (3-min TTL), mirroring the Go explorer's
    /// per-request `proverCache`/`proverShardCache` maps. Keyed by an
    /// endpoint-specific string; stores the already-serialized body.
    pub(crate) cache: Arc<RwLock<HashMap<String, (Instant, Vec<u8>)>>>,
}

impl ExplorerState {
    /// Build the state. The cache map is created internally.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clock_store: Arc<dyn quil_types::store::ClockStore>,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
        prover_registry: Arc<dyn quil_types::consensus::ProverRegistry>,
        key_store: Arc<dyn quil_types::store::KeyStore>,
        shards_store: Arc<dyn quil_types::store::ShardsStore>,
        app_shards_provider: Option<AppShardsProvider>,
        halt_durations_provider: Option<HaltDurationsProvider>,
        peer_info_cache: Arc<RwLock<HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>>>,
        messages: Arc<RecentMessageRing>,
        current_frame: Arc<AtomicU64>,
    ) -> Self {
        Self {
            clock_store,
            crdt,
            prover_registry,
            key_store,
            shards_store,
            app_shards_provider,
            halt_durations_provider,
            peer_info_cache,
            messages,
            current_frame,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

/// Build the explorer router with all 11 endpoints. Every route accepts
/// any method (handlers themselves return 405 for non-GET, matching Go's
/// per-handler `if r.Method != GET` check); CORS + OPTIONS short-circuit is
/// applied as a layer (matching Go's `withCORS` wrapper).
pub fn router(state: ExplorerState) -> Router {
    Router::new()
        .route("/frames/:id", any(handlers::handle_frames))
        .route("/certified/:id", any(handlers::handle_certified))
        .route("/messages", any(handlers::handle_messages))
        .route("/hypergraph/vertex/:id", any(handlers::handle_vertex))
        .route("/hypergraph/hyperedge/:id", any(handlers::handle_hyperedge))
        .route("/peers", any(handlers::handle_peers))
        .route("/provers", any(handlers::handle_provers))
        .route("/provers/shards", any(handlers::handle_prover_shards))
        .route("/provers/shards/:filter", any(handlers::handle_prover_shard_detail))
        .route("/provers/eviction-risk", any(handlers::handle_eviction_risk))
        .route("/provers/seniority", any(handlers::handle_seniority))
        .route("/provers/kicked", any(handlers::handle_kicked))
        .route("/stats", any(handlers::handle_stats))
        .route("/keys/identity/:addr", any(handlers::handle_key_identity))
        .route("/keys/prover/:addr", any(handlers::handle_key_prover))
        .layer(axum::middleware::from_fn(cors_layer))
        .with_state(state)
}

/// Run the explorer HTTP server on `listener` until `shutdown` resolves.
/// The caller wires `shutdown` to the lifecycle supervisor's cancellation
/// token (graceful shutdown, like the gRPC servers).
pub async fn serve(
    listener: tokio::net::TcpListener,
    router: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
}

/// CORS + OPTIONS middleware, mirroring Go's `withCORS`: every response
/// carries the three CORS headers, and an `OPTIONS` request short-circuits
/// to 204 No Content (before any handler runs).
async fn cors_layer(req: Request, next: Next) -> Response {
    use axum::http::{header::HeaderValue, Method, StatusCode};

    let is_options = req.method() == Method::OPTIONS;
    let mut resp = if is_options {
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(axum::body::Body::empty())
            .unwrap()
    } else {
        next.run(req).await
    };

    let headers = resp.headers_mut();
    headers.insert(
        "Access-Control-Allow-Origin",
        HeaderValue::from_static("*"),
    );
    headers.insert(
        "Access-Control-Allow-Methods",
        HeaderValue::from_static("GET, OPTIONS"),
    );
    headers.insert(
        "Access-Control-Allow-Headers",
        HeaderValue::from_static("Content-Type"),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_router() -> Router {
        Router::new()
            .route("/x", any(|| async { "ok" }))
            .layer(axum::middleware::from_fn(cors_layer))
    }

    #[tokio::test]
    async fn options_short_circuits_204_with_cors() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/x")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(resp.headers()["Access-Control-Allow-Origin"], "*");
        assert_eq!(resp.headers()["Access-Control-Allow-Methods"], "GET, OPTIONS");
        assert_eq!(resp.headers()["Access-Control-Allow-Headers"], "Content-Type");
    }

    #[tokio::test]
    async fn get_carries_cors_headers() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/x")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["Access-Control-Allow-Origin"], "*");
    }
}

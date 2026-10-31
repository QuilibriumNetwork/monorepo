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

use axum::{extract::Request, middleware::Next, response::Response, routing::any, Router};
use parking_lot::{Mutex, RwLock};

pub mod handlers;
pub mod message_ring;
pub mod production;

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

/// The lowest GLOBAL frame whose request bodies the store keeps (`None`:
/// all of them). A regular node prunes older bodies and keeps only the
/// headers, which would read as empty frames.
pub type RequestRetentionProvider = Arc<dyn Fn() -> Option<u64> + Send + Sync>;

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
    /// endpoint-specific string; stores the already-serialized body. Holds
    /// at most `handlers::CACHE_MAX_ENTRIES` bodies.
    pub(crate) cache: Arc<RwLock<HashMap<String, (Instant, Vec<u8>)>>>,
    /// One permit: full token scans (`/token/supply?scan=1`, each
    /// `/token/coins/:owner`) read every coin of the domain, so they run one
    /// at a time and a request arriving during one is answered 503.
    pub(crate) token_scan: Arc<tokio::sync::Semaphore>,
    /// Permits for shard-frame reads (`/shards/:filter/frames`): a frame
    /// can be megabytes, so only `handlers::MAX_SHARD_FRAME_READS` are read
    /// at once and a request beyond them is answered 503.
    pub(crate) shard_frame_reads: Arc<tokio::sync::Semaphore>,
    /// Every prover known to the registry at one frame, with its build
    /// time, shared by requests within that frame and a few seconds (see
    /// `handlers::all_provers`). Holds at most one snapshot.
    pub(crate) provers_snapshot:
        Arc<Mutex<Option<(u64, Instant, Arc<Vec<quil_types::consensus::ProverInfo>>)>>>,
    /// `/stats` and `/provers/eviction-risk` as [`production::run_indexer`]
    /// last assessed them at its head (see `handlers::eviction_at`); a
    /// request assesses only while none is recent. Holds at most one.
    pub(crate) eviction: Arc<RwLock<Option<Arc<handlers::Eviction>>>>,
    /// Held while an eviction assessment is made, so callers needing one
    /// at once make it once.
    pub(crate) eviction_making: Arc<Mutex<()>>,
    /// `/shards/production` and `/stats` `app_shards` as
    /// [`production::run_indexer`] last built them; `None` until its first
    /// build. Handlers only read it.
    pub(crate) production_snapshot: Arc<RwLock<Option<Arc<production::Snapshot>>>>,
    /// `/shards/production/history` rows, recorded and backfilled by
    /// [`production::run_indexer`]. Handlers only read them.
    pub(crate) production_history: Arc<RwLock<production::history::Rows>>,
    /// Outside archive mode, where request-body pruning starts: the history
    /// backfill stays above it. `None` on archives, which keep every body.
    pub requests_retained_from: Option<RequestRetentionProvider>,
    /// Outside archive mode, the node's archive shard-info cache: the
    /// production snapshot's grid then comes from it, not from the shards
    /// store (see [`production::GridSource`]). `None` on archives.
    pub archive_grid: Option<production::ArchiveGridProvider>,
    /// Where [`production::run_indexer`] saves the final history rows and
    /// restores them at start, so a restart backfills only the rows after
    /// them. `None`: they are held in memory only.
    pub history_file: Option<production::history::persist::HistoryFile>,
}

impl ExplorerState {
    /// Build the state. The cache map and prover snapshot are created
    /// internally.
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
            token_scan: Arc::new(tokio::sync::Semaphore::new(1)),
            shard_frame_reads: Arc::new(tokio::sync::Semaphore::new(
                handlers::MAX_SHARD_FRAME_READS,
            )),
            provers_snapshot: Arc::new(Mutex::new(None)),
            eviction: Arc::new(RwLock::new(None)),
            eviction_making: Arc::new(Mutex::new(())),
            production_snapshot: Arc::new(RwLock::new(None)),
            production_history: Arc::new(RwLock::new(production::history::Rows::default())),
            requests_retained_from: None,
            archive_grid: None,
            history_file: None,
        }
    }

    /// Keep the history backfill above the frames whose request bodies the
    /// store pruned: for a node outside archive mode.
    pub fn with_request_retention(mut self, provider: RequestRetentionProvider) -> Self {
        self.requests_retained_from = Some(provider);
        self
    }

    /// Take the production snapshot's grid from the node's archive
    /// shard-info cache: for a node outside archive mode, whose shards
    /// store keeps the genesis grid.
    pub fn with_archive_grid(mut self, provider: production::ArchiveGridProvider) -> Self {
        self.archive_grid = Some(provider);
        self
    }

    /// Save the final production-history rows to `path`, and restore them
    /// at start, if they were computed on `network` with this build's
    /// parameters (see [`production::history::persist`]).
    pub fn with_history_file(mut self, path: std::path::PathBuf, network: u8) -> Self {
        self.history_file = Some(production::history::persist::HistoryFile::new(
            path, network,
        ));
        self
    }
}

/// Requests the explorer serves at once; a request beyond them is answered
/// 503 at once instead of waiting behind slow store reads.
pub const MAX_IN_FLIGHT: usize = 64;

/// Worker threads of the explorer's own runtime ([`serve`]). Its handlers
/// read the stores synchronously: on these threads a slow or heavy request
/// delays other explorer requests, not the node's consensus and sync.
pub const HTTP_WORKERS: usize = 2;

/// Build the explorer router with all its endpoints. Every route accepts
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
        .route("/peers/releases", any(handlers::handle_peer_releases))
        .route("/provers", any(handlers::handle_provers))
        .route("/provers/shards", any(handlers::handle_prover_shards))
        .route(
            "/provers/shards/:filter",
            any(handlers::handle_prover_shard_detail),
        )
        .route(
            "/provers/eviction-risk",
            any(handlers::handle_eviction_risk),
        )
        .route("/provers/seniority", any(handlers::handle_seniority))
        .route("/provers/kicked", any(handlers::handle_kicked))
        .route("/stats", any(handlers::handle_stats))
        .route("/shards/production", any(handlers::handle_shard_production))
        .route(
            "/shards/production/history",
            any(handlers::handle_shard_production_history),
        )
        .route("/shards/:filter/frames", any(handlers::handle_shard_frames))
        .route(
            "/shards/:filter/frames/:number",
            any(handlers::handle_shard_frame),
        )
        .route("/token/supply", any(handlers::handle_token_supply))
        .route("/token/coin/:address", any(handlers::handle_token_coin))
        .route("/token/coins/:owner", any(handlers::handle_token_coins))
        .route("/token/reward/:prover", any(handlers::handle_token_reward))
        .route("/keys/identity/:addr", any(handlers::handle_key_identity))
        .route("/keys/prover/:addr", any(handlers::handle_key_prover))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT)),
            limit_in_flight,
        ))
        .layer(axum::middleware::from_fn(cors_layer))
        .with_state(state)
}

/// Answer 503 while `permits` requests are already being served.
async fn limit_in_flight(
    axum::extract::State(permits): axum::extract::State<Arc<tokio::sync::Semaphore>>,
    req: Request,
    next: Next,
) -> Response {
    match permits.try_acquire() {
        Ok(_serving) => next.run(req).await,
        Err(_) => handlers::busy(
            "the explorer is serving its maximum of requests; retry shortly",
            1,
        ),
    }
}

/// Run the explorer HTTP server on `listener` until `shutdown` resolves.
/// The caller wires `shutdown` to the lifecycle supervisor's cancellation
/// token (graceful shutdown, like the gRPC servers). The server runs on its
/// own runtime of [`HTTP_WORKERS`] threads, so requests never occupy the
/// node's runtime workers.
pub async fn serve(
    listener: tokio::net::TcpListener,
    router: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let listener = listener.into_std()?;
    let (done, served) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("explorer-http".into())
        .spawn(move || {
            let result = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(HTTP_WORKERS)
                .thread_name("explorer-http")
                .enable_all()
                .build()
                .and_then(|runtime| {
                    runtime.block_on(async move {
                        let listener = tokio::net::TcpListener::from_std(listener)?;
                        axum::serve(listener, router)
                            .with_graceful_shutdown(shutdown)
                            .await
                    })
                });
            let _ = done.send(result);
        })?;
    served.await.unwrap_or_else(|_| {
        Err(std::io::Error::other(
            "the explorer HTTP thread ended without a result",
        ))
    })
}

/// CORS + OPTIONS middleware, mirroring Go's `withCORS`: every response
/// carries the three CORS headers, and an `OPTIONS` request short-circuits
/// to 204 No Content (before any handler runs). It also exposes the
/// eviction-risk `X-Total-Count` header to cross-origin dashboards.
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
    headers.insert("Access-Control-Allow-Origin", HeaderValue::from_static("*"));
    headers.insert(
        "Access-Control-Allow-Methods",
        HeaderValue::from_static("GET, OPTIONS"),
    );
    headers.insert(
        "Access-Control-Allow-Headers",
        HeaderValue::from_static("Content-Type"),
    );
    headers.insert(
        "Access-Control-Expose-Headers",
        HeaderValue::from_static("X-Total-Count"),
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
        assert_eq!(
            resp.headers()["Access-Control-Allow-Methods"],
            "GET, OPTIONS"
        );
        assert_eq!(
            resp.headers()["Access-Control-Allow-Headers"],
            "Content-Type"
        );
        assert_eq!(
            resp.headers()["Access-Control-Expose-Headers"],
            "X-Total-Count"
        );
    }

    #[tokio::test]
    async fn requests_beyond_the_limit_are_answered_busy() {
        let limited = |permits: Arc<tokio::sync::Semaphore>| {
            Router::new().route("/x", any(|| async { "ok" })).layer(
                axum::middleware::from_fn_with_state(permits, limit_in_flight),
            )
        };
        let get = || Request::builder().uri("/x").body(Body::empty()).unwrap();
        // Every permit taken: the request is answered at once, not queued.
        let full = limited(Arc::new(tokio::sync::Semaphore::new(0)))
            .oneshot(get())
            .await
            .unwrap();
        assert_eq!(full.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(full.headers()["Retry-After"], "1");
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let served = limited(permits.clone()).oneshot(get()).await.unwrap();
        assert_eq!(served.status(), StatusCode::OK);
        assert_eq!(
            permits.available_permits(),
            1,
            "a served request returns its permit"
        );
    }

    #[tokio::test]
    async fn requests_are_served_on_the_explorer_runtime() {
        let router = Router::new().route(
            "/thread",
            any(|| async { std::thread::current().name().unwrap_or("").to_string() }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve(listener, router, async move {
            let _ = stopped.await;
        }));
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream
            .write_all(b"GET /thread HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.unwrap();
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(
            answer.ends_with("explorer-http"),
            "served off the caller's runtime: {answer}"
        );
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
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
        assert_eq!(
            resp.headers()["Access-Control-Expose-Headers"],
            "X-Total-Count"
        );
    }
}

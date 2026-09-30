use std::sync::Arc;
/// Canonical rank-1 identity encoding size (one packed polynomial) of the
/// QCT token suite; mirrors `quil_lattice_ct::...::membership::IDENTITY_BYTES`.
const IDENTITY_BYTES: usize = 3648;
/// Canonical root record size: 8 + 32 + 1 + 8 + NODE_BYTES (six 1,216-byte proof-ring polynomials).
const NODE_BYTES: usize = 4 * 1216;
const ROOT_RECORD_BYTES: usize = 8 + 32 + 1 + 8 + NODE_BYTES;
use std::sync::atomic::{AtomicU64, Ordering};

use tonic::{Request, Response, Status};

use quil_engine::current_frame::CurrentFrame;
use quil_types::consensus::{
    epoch_for_frame, epoch_length_frames, EffectiveStatus, ProverRegistry, ShardInfoProvider,
};
use quil_types::proto::{global, node};
use quil_types::proto::node::node_service_server::NodeService;
use quil_types::store::ClockStore;

fn coin_witness_status(error: quil_types::error::QuilError) -> Status {
    use quil_types::error::QuilError;
    match error {
        QuilError::NotFound(message) | QuilError::ExecutionUnavailable(message) => Status::unavailable(message),
        QuilError::InvalidArgument(message) => Status::invalid_argument(message),
        other => Status::internal(format!("coin spend witness: {other}")),
    }
}

// Rebuilding an entire domain accumulator is CPU/memory intensive. Acquire
// before spawning, and retain the permit in the worker even if the RPC cancels.
static COIN_WITNESS_WORKERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

/// Handler installed by the caller to route a Go-CLI `submit_message`
/// into the same message-collection pipeline used by
/// `GlobalService::submit_global_message`. Returns an error string
/// surfaced as `Status::invalid_argument`.
pub type UserSubmitHandler =
    Arc<dyn Fn(Vec<u8>) -> Result<(), String> + Send + Sync>;

/// A provider must resolve the application's execution venue and return its
/// pricing inputs together. Never synthesize this from shard-info totals.
#[derive(Clone, Debug)]
pub struct TokenFeeSnapshot {
    pub network: [u8; 32],
    pub observed_frame: u64,
    pub global_execution: bool,
    pub difficulty: u64,
    pub world_state_bytes: u64,
    pub fee_multiplier_vote: u64,
}
/// `(application, global_venue)`: `global_venue` asks for the global frame
/// materializer's pricing inputs instead of the application's current venue.
pub type TokenFeeProvider = Arc<dyn Fn([u8; 32], bool) -> quil_types::error::Result<TokenFeeSnapshot> + Send + Sync>;
static TOKEN_FEE_WORKERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);

/// A worker entry for populating WorkerInfoResponse.
/// No WorkerManager trait exists yet — the caller pushes entries directly.
#[derive(Debug, Clone)]
pub struct WorkerEntry {
    pub core_id: u32,
    pub filter: Vec<u8>,
    pub available_storage: u64,
    pub total_storage: u64,
    pub manually_managed: bool,
    pub allocated: bool,
}

/// gRPC NodeService implementation with live node state.
/// Forwards a coin-witness request to a node holding the application.
pub type RemoteCoinWitnesses = Arc<
    dyn Fn([u8; 32], Vec<[u8; 32]>)
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<quil_types::store::CoinWitnessBundle>> + Send>>
        + Send
        + Sync,
>;

/// Forwards one vertex read to a node holding the application, as
/// `(present, blob)`.
pub type RemoteVertex = Arc<
    dyn Fn([u8; 32], Vec<u8>)
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<(bool, Vec<u8>)>> + Send>>
        + Send
        + Sync,
>;

/// Forwards one coin-scan page to a node holding the application.
pub type RemoteCoinPage = Arc<
    dyn Fn([u8; 32], Option<[u8; 32]>, Option<[u8; 32]>)
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<quil_types::store::CoinPageData>> + Send>>
        + Send
        + Sync,
>;

pub type RemoteEscrowPage = Arc<
    dyn Fn([u8; 32], Option<[u8; 32]>, Option<[u8; 32]>)
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<quil_types::store::EscrowPageData>> + Send>>
        + Send
        + Sync,
>;

/// Every local worker store holding part of an application. An error means
/// coverage changed while resolving the stores; an empty list uses the master.
pub type AppHypergraphStores = Arc<
    dyn Fn(&[u8]) -> Result<Vec<Arc<dyn quil_types::store::HypergraphStore>>, Status>
        + Send
        + Sync,
>;

pub struct NodeRpcServer {
    pub peer_id: String,
    pub version: Vec<u8>,
    pub patch_number: Vec<u8>,
    /// Source of truth for "what frame is this node on right now."
    /// Use `current_frame.effective()` for any consumer that needs
    /// the current frame — the `last_received_frame` field on the
    /// `NodeInfoResponse` proto is populated from this same value.
    pub current_frame: Arc<CurrentFrame>,
    pub last_global_head_frame: Arc<AtomicU64>,
    pub prover_address: Vec<u8>,
    pub reachable: bool,

    // Stores and registries (optional — None means unavailable).
    pub prover_registry: Option<Arc<dyn ProverRegistry>>,
    pub shard_info_provider: Option<Arc<dyn ShardInfoProvider>>,
    pub token_fee_provider: Option<TokenFeeProvider>,
    pub clock_store: Option<Arc<dyn ClockStore>>,
    pub hypergraph_store: Option<Arc<dyn quil_types::store::HypergraphStore>>,
    /// Local stores for a vertex's application, instead of the master store.
    pub app_hypergraph_stores: Option<AppHypergraphStores>,
    /// See [`NodeRpcServer::with_application_coverage`].
    pub application_coverage: Option<Arc<dyn Fn(&[u8]) -> bool + Send + Sync>>,
    /// See [`NodeRpcServer::with_remote_coin_page`].
    pub remote_coin_page: Option<RemoteCoinPage>,
    pub remote_escrow_page: Option<RemoteEscrowPage>,
    /// See [`NodeRpcServer::with_remote_vertex`].
    pub remote_vertex: Option<RemoteVertex>,
    /// See [`NodeRpcServer::with_remote_coin_witnesses`].
    pub remote_coin_witnesses: Option<RemoteCoinWitnesses>,
    /// QCT3 coin/escrow discovery and membership/mint witnesses.
    pub coin_witness_provider: Option<Arc<dyn quil_types::store::CoinWitnessProvider>>,
    pub submit_handler: Option<UserSubmitHandler>,
    /// Optional Prometheus text-format snapshot handle. When present,
    /// `get_metrics` returns the rendered text as response bytes.
    pub metrics_renderer: Option<Arc<dyn Fn() -> String + Send + Sync>>,
    /// Handler for admin-side worker control.
    pub worker_control: Option<Arc<dyn WorkerControl>>,
    /// Snapshot function returning the current peer-info cache for
    /// `get_peer_info`. Each entry is a raw `CanonicalPeerInfo`
    /// decoded from GLOBAL_PEER_INFO bitmask.
    pub peer_info_snapshot: Option<
        Arc<dyn Fn() -> Vec<quil_p2p::CanonicalPeerInfo> + Send + Sync>,
    >,
    /// Optional traversal-proof generator. Given
    /// `(domain, atom_type, phase_type, keys)`, returns the serialized
    /// `MultiKeyTraversalProof` bytes. Implemented by the caller so
    /// the RPC crate doesn't have to link the live hypergraph CRDT.
    pub traversal_proof_generator: Option<TraversalProofGenerator>,
    /// Optional handler for `NodeService::Send` — verifies
    /// authentication and routes the MessageBundle.
    pub send_handler_fn: Option<SendHandler>,
    /// When unset, `peer_score` in `GetNodeInfo` returns 0.
    pub peer_score_provider: Option<PeerScoreProvider>,
    pub workers: Arc<std::sync::RwLock<Vec<WorkerEntry>>>,
}

/// Async closure returning the local node's peer-score as `f64`. The
/// handler casts to `u64` by truncation.
pub type PeerScoreProvider = Arc<
    dyn Fn() -> std::pin::Pin<
            Box<dyn std::future::Future<Output = f64> + Send>,
        > + Send
        + Sync,
>;

/// Closure signature for traversal-proof generation.
pub type TraversalProofGenerator = Arc<
    dyn Fn([u8; 32], String, String, Vec<Vec<u8>>) -> Result<Vec<u8>, String>
        + Send
        + Sync,
>;

/// Closure signature for `NodeService::Send`. Arguments are
/// `(domain, payload, authentication)`. Verifies the Ed448
/// authentication over the payload under the
/// `NODE_AUTHENTICATION || domain` prefix, then routes the
/// MessageBundle to the correct BlossomSub bitmask.
pub type SendHandler = Arc<
    dyn Fn(Vec<u8>, Vec<u8>, Vec<u8>) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), String>> + Send>,
        > + Send
        + Sync,
>;

/// Admin hook for NodeService worker controls (set_manually_managed,
/// request_join). Implemented by the caller in main.rs to bridge to
/// the live `WorkerManager` and the prover submission pipeline.
pub trait WorkerControl: Send + Sync {
    fn set_manually_managed(&self, core_id: u32, manually_managed: bool) -> Result<(), String>;

    /// Force an immediate `ProverJoin` for the given filters,
    /// bypassing the lifecycle's cooldown + readiness gate. Returns as
    /// soon as the request has been validated and (when `worker_ids`
    /// is supplied) the target workers are pinned — the VDF, sign,
    /// and publish work runs in a detached background task. RPC ack
    /// means "request queued, workers pinned", NOT "message on the
    /// wire". The TUI's await-confirm loop observes alloc landing
    /// separately.
    ///
    /// `worker_ids` is optional. When non-empty it MUST be parallel
    /// to `filters` (one entry per filter, in order). Each
    /// `(filters[i], worker_ids[i])` pair is pre-bound synchronously
    /// so the reconcile pass matches each landing allocation back to
    /// its intended worker via `worker.filter == alloc.filter` —
    /// closing the prior bug where the reconciler `pop()`ed from
    /// `manual_pending` / `idle_workers` with no knowledge of which
    /// manual worker the operator picked for which filter. When
    /// empty, falls back to the legacy reconcile-side pick.
    fn request_join<'a>(
        &'a self,
        filters: Vec<Vec<u8>>,
        worker_ids: Vec<u32>,
        delegate: Vec<u8>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>,
    >;
}

impl NodeRpcServer {
    pub fn new() -> Self {
        Self {
            peer_id: String::new(),
            version: vec![2, 1, 0],
            patch_number: vec![quil_config::PATCH_NUMBER],
            current_frame: CurrentFrame::new(),
            last_global_head_frame: Arc::new(AtomicU64::new(0)),
            prover_address: Vec::new(),
            reachable: false,
            prover_registry: None,
            shard_info_provider: None,
            token_fee_provider: None,
            clock_store: None,
            hypergraph_store: None,
            app_hypergraph_stores: None,
            application_coverage: None,
            remote_coin_page: None,
            remote_escrow_page: None,
            remote_vertex: None,
            remote_coin_witnesses: None,
            coin_witness_provider: None,
            submit_handler: None,
            metrics_renderer: None,
            worker_control: None,
            peer_info_snapshot: None,
            traversal_proof_generator: None,
            send_handler_fn: None,
            peer_score_provider: None,
            workers: Arc::new(std::sync::RwLock::new(Vec::new())),
        }
    }

    pub fn with_token_fee_provider(mut self, provider: TokenFeeProvider) -> Self {
        self.token_fee_provider = Some(provider);
        self
    }

    pub fn with_peer_score_provider(mut self, provider: PeerScoreProvider) -> Self {
        self.peer_score_provider = Some(provider);
        self
    }

    pub fn with_peer_id(mut self, peer_id: String) -> Self {
        self.peer_id = peer_id;
        self
    }
    pub fn with_frame_counters(
        mut self,
        current_frame: Arc<CurrentFrame>,
        last_head: Arc<AtomicU64>,
    ) -> Self {
        self.current_frame = current_frame;
        self.last_global_head_frame = last_head;
        self
    }
    pub fn with_prover_address(mut self, address: Vec<u8>) -> Self {
        self.prover_address = address;
        self
    }
    pub fn with_reachable(mut self, reachable: bool) -> Self {
        self.reachable = reachable;
        self
    }
    pub fn with_prover_registry(mut self, registry: Arc<dyn ProverRegistry>) -> Self {
        self.prover_registry = Some(registry);
        self
    }
    pub fn with_shard_info_provider(mut self, provider: Arc<dyn ShardInfoProvider>) -> Self {
        self.shard_info_provider = Some(provider);
        self
    }
    pub fn with_clock_store(mut self, store: Arc<dyn ClockStore>) -> Self {
        self.clock_store = Some(store);
        self
    }
    /// Refuse a state read for an application this node does not hold, rather
    /// than returning an empty answer that a caller cannot tell apart from
    /// "there is nothing there". Applications with no declared coverage hook
    /// are served as before.
    fn require_application_coverage(&self, application: &[u8]) -> Result<(), Status> {
        if self.serves_application(application) {
            return Ok(());
        }
        Err(self.coverage_error(application))
    }

    /// Whether this node holds `application`'s state. With no coverage hook
    /// wired every application is served, as before.
    fn serves_application(&self, application: &[u8]) -> bool {
        self.application_coverage.as_ref().is_none_or(|serves| serves(application))
    }

    fn coverage_error(&self, application: &[u8]) -> Status {
        Status::unavailable(format!(
            "this node does not serve application {}; read through a node covering it, or an archive",
            hex::encode(&application[..application.len().min(32)])
        ))
    }

    /// Forward a coin scan to a node that holds the application, when this one
    /// does not. The page it returns faces exactly the same validation as a
    /// local page — a peer is a source of data, not of authority.
    pub fn with_remote_coin_page(mut self, remote: RemoteCoinPage) -> Self {
        self.remote_coin_page = Some(remote);
        self
    }

    pub fn with_remote_escrow_page(mut self, remote: RemoteEscrowPage) -> Self {
        self.remote_escrow_page = Some(remote);
        self
    }

    /// Forward a vertex read to a node holding the application. A forwarded
    /// coin scan is not usable without this: the wallet reads spent markers as
    /// vertices to decide which coins it can still spend.
    pub fn with_remote_vertex(mut self, remote: RemoteVertex) -> Self {
        self.remote_vertex = Some(remote);
        self
    }

    /// Forward coin witnesses to a node holding the application, so a holder
    /// can spend a coin from a node that does not cover it.
    pub fn with_remote_coin_witnesses(mut self, remote: RemoteCoinWitnesses) -> Self {
        self.remote_coin_witnesses = Some(remote);
        self
    }

    /// Whether this node can answer for an application's state at all: it
    /// covers the application's shards, or holds it because it materializes
    /// everything. A node that cannot must say so — answering "empty" for an
    /// application it does not hold is indistinguishable from "you have
    /// nothing", which reads as a zero balance for a token the caller owns.
    pub fn with_application_coverage(
        mut self,
        serves: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    ) -> Self {
        self.application_coverage = Some(serves);
        self
    }

    /// Route vertex reads for applications whose state lives outside the
    /// node's own hypergraph store (see `app_hypergraph_stores`).
    pub fn with_app_hypergraph_stores(
        mut self,
        resolver: AppHypergraphStores,
    ) -> Self {
        self.app_hypergraph_stores = Some(resolver);
        self
    }

    pub fn with_hypergraph_store(
        mut self,
        store: Arc<dyn quil_types::store::HypergraphStore>,
    ) -> Self {
        self.hypergraph_store = Some(store);
        self
    }
    pub fn with_coin_witness_provider(
        mut self,
        provider: Arc<dyn quil_types::store::CoinWitnessProvider>,
    ) -> Self {
        self.coin_witness_provider = Some(provider);
        self
    }
    pub fn with_submit_handler(mut self, handler: UserSubmitHandler) -> Self {
        self.submit_handler = Some(handler);
        self
    }
    pub fn with_metrics_renderer(
        mut self,
        renderer: Arc<dyn Fn() -> String + Send + Sync>,
    ) -> Self {
        self.metrics_renderer = Some(renderer);
        self
    }
    pub fn with_worker_control(mut self, ctl: Arc<dyn WorkerControl>) -> Self {
        self.worker_control = Some(ctl);
        self
    }
    pub fn with_peer_info_snapshot(
        mut self,
        snapshot: Arc<dyn Fn() -> Vec<quil_p2p::CanonicalPeerInfo> + Send + Sync>,
    ) -> Self {
        self.peer_info_snapshot = Some(snapshot);
        self
    }
    pub fn with_traversal_proof_generator(
        mut self,
        generator: TraversalProofGenerator,
    ) -> Self {
        self.traversal_proof_generator = Some(generator);
        self
    }
    pub fn with_send_handler_fn(mut self, handler: SendHandler) -> Self {
        self.send_handler_fn = Some(handler);
        self
    }
    pub fn with_workers_view(
        mut self,
        workers: Arc<std::sync::RwLock<Vec<WorkerEntry>>>,
    ) -> Self {
        self.workers = workers;
        self
    }
}

impl Default for NodeRpcServer {
    fn default() -> Self {
        Self::new()
    }
}

#[tonic::async_trait]
impl NodeService for NodeRpcServer {
    async fn get_peer_info(
        &self,
        _request: Request<node::GetPeerInfoRequest>,
    ) -> Result<Response<node::PeerInfoResponse>, Status> {
        let entries = match &self.peer_info_snapshot {
            Some(f) => f(),
            None => Vec::new(),
        };
        let peer_info: Vec<node::PeerInfo> = entries
            .into_iter()
            .map(|i| node::PeerInfo {
                peer_id: i.peer_id,
                reachability: i
                    .reachability
                    .into_iter()
                    .map(|r| node::Reachability {
                        filter: r.filter,
                        pubsub_multiaddrs: r.pubsub_multiaddrs,
                        stream_multiaddrs: r.stream_multiaddrs,
                    })
                    .collect(),
                timestamp: i.timestamp,
                version: i.version,
                patch_number: i.patch_number,
                capabilities: i
                    .capabilities
                    .into_iter()
                    .map(|c| node::Capability {
                        protocol_identifier: c.protocol_identifier,
                        additional_metadata: c.additional_metadata,
                    })
                    .collect(),
                public_key: i.public_key,
                signature: i.signature,
                last_received_frame: i.last_received_frame,
                last_global_head_frame: i.last_global_head_frame,
            })
            .collect();
        Ok(Response::new(node::PeerInfoResponse { peer_info }))
    }

    async fn get_node_info(
        &self,
        _request: Request<node::GetNodeInfoRequest>,
    ) -> Result<Response<node::NodeInfoResponse>, Status> {
        // The non-Send `RwLockReadGuard` must not cross the
        // peer-score `await` below.
        let (running, allocated) = {
            let workers = self.workers.read().unwrap();
            let running = workers.len() as u32;
            let allocated = workers.iter().filter(|w| w.allocated).count() as u32;
            (running, allocated)
        };

        let mut seniority_bytes = vec![0u8; 8];
        let mut shard_allocations = Vec::new();

        if let Some(ref registry) = self.prover_registry {
            if let Ok(Some(info)) = registry.get_prover_info(&self.prover_address) {
                let s = info.seniority;
                seniority_bytes = s.to_be_bytes().to_vec();

                // Use the shared `current_frame.effective()` for the
                // 720-frame grace check. This is the single source
                // of truth — populated by the BlossomSub receive
                // loop, archive poller, and frame materializer, so
                // it stays fresh on any node regardless of its
                // role (archive, observer, or full prover) and
                // regardless of where the latest frame came from.
                let current_frame = self.current_frame.effective();
                for alloc in &info.allocations {
                    // Return live allocations, PLUS `ExpiredEpoch` ones. An
                    // Active data-shard allocation that missed its per-epoch
                    // re-confirm reads as `ExpiredEpoch` (recoverable — the
                    // prover re-registers leaf roots and becomes Active again),
                    // so surfacing it lets the client warn the operator instead
                    // of the allocation silently vanishing. The truly terminal
                    // states (Rejected/Kicked/ExpiredJoining/ExpiredLeaving) are
                    // still filtered out.
                    let eff = alloc.effective_status(current_frame);
                    if !(eff.is_live() || eff == EffectiveStatus::ExpiredEpoch) {
                        continue;
                    }
                    shard_allocations.push(node::ShardAllocationInfo {
                        filter: alloc.confirmation_filter.clone(),
                        status: alloc.status as u32,
                        join_frame_number: alloc.join_frame_number,
                        join_confirm_frame_number: alloc.join_confirm_frame_number,
                        leave_frame_number: alloc.leave_frame_number,
                        last_active_frame_number: alloc.last_active_frame_number,
                        epoch: alloc.epoch,
                        leave_confirm_frame_number: alloc.leave_confirm_frame_number,
                    });
                }
            }
        }

        let peer_score = match &self.peer_score_provider {
            Some(provider) => {
                let score = provider().await;
                if score.is_finite() && score >= 0.0 {
                    score as u64
                } else {
                    0
                }
            }
            None => 0,
        };

        Ok(Response::new(node::NodeInfoResponse {
            peer_id: self.peer_id.clone(),
            peer_score,
            version: self.version.clone(),
            peer_seniority: seniority_bytes,
            running_workers: running,
            allocated_workers: allocated,
            patch_number: self.patch_number.clone(),
            last_received_frame: self.current_frame.effective(),
            last_global_head_frame: self.last_global_head_frame.load(Ordering::Relaxed),
            reachable: self.reachable,
            shard_allocations,
            // Epoch is derived from the same frame the effective-status grace
            // checks above used (`current_frame.effective()`), so the client's
            // epoch matches the one the allocations were evaluated against.
            current_epoch: epoch_for_frame(self.current_frame.effective()),
            epoch_length_frames: epoch_length_frames(),
        }))
    }

    async fn get_worker_info(
        &self,
        _request: Request<node::GetWorkerInfoRequest>,
    ) -> Result<Response<node::WorkerInfoResponse>, Status> {
        let workers = self.workers.read().unwrap();
        let info: Vec<node::WorkerInfo> = workers
            .iter()
            .map(|w| node::WorkerInfo {
                core_id: w.core_id,
                filter: w.filter.clone(),
                available_storage: w.available_storage,
                total_storage: w.total_storage,
                manually_managed: w.manually_managed,
            })
            .collect();

        Ok(Response::new(node::WorkerInfoResponse {
            worker_info: info,
        }))
    }

    async fn send(
        &self,
        request: Request<node::SendRequest>,
    ) -> Result<Response<node::SendResponse>, Status> {
        let handler = self.send_handler_fn.as_ref().ok_or_else(|| {
            Status::unavailable("send handler not wired")
        })?;
        let req = request.into_inner();
        if req.authentication.is_empty() {
            return Err(Status::invalid_argument("authentication required"));
        }
        let Some(bundle) = req.request else {
            return Err(Status::invalid_argument("request required"));
        };
        // Summarise what's in the bundle so the operator can see
        // which TUI action drove the call (Join / Leave / Confirm /
        // etc.) rather than just an opaque "send".
        let action_summary = describe_message_bundle(&bundle);
        tracing::info!(
            domain_len = req.domain.len(),
            requests = bundle.requests.len(),
            actions = %action_summary,
            "Send RPC received"
        );
        // The signing payload is canonical-bytes, not prost-encoded.
        let payload = quil_execution::message_envelope::proto_message_bundle_to_canonical_bytes(
            &bundle,
        )
        .map_err(|e| Status::internal(format!("canonicalize: {e}")))?;
        handler(req.domain, payload, req.authentication)
            .await
            .map_err(|e| Status::unauthenticated(format!("send rejected: {e}")))?;
        Ok(Response::new(node::SendResponse {
            delivery_data: Vec::new(),
        }))
    }

    async fn get_coin_witnesses(
        &self,
        request: Request<node::GetCoinWitnessesRequest>,
    ) -> Result<Response<node::GetCoinWitnessesResponse>, Status> {
        let req = request.into_inner();
        let domain: [u8; 32] = req.domain.try_into()
            .map_err(|_| Status::invalid_argument("domain must be 32 bytes"))?;
        if req.addresses.is_empty() || req.addresses.len() > 4 {
            return Err(Status::invalid_argument("request must contain one to four addresses"));
        }
        let addresses: Vec<[u8; 32]> = req.addresses.into_iter().map(|address| address.try_into()
            .map_err(|_| Status::invalid_argument("coin address must be 32 bytes"))).collect::<Result<_, _>>()?;
        if addresses.iter().collect::<std::collections::BTreeSet<_>>().len() != addresses.len() {
            return Err(Status::invalid_argument("duplicate coin addresses"));
        }
        let expected = addresses.clone();
        // Local when this node covers the application; otherwise a node that
        // does. Either source faces the dimension and path checks below.
        let result = if self.serves_application(&domain) {
            let provider = self.coin_witness_provider.as_ref()
                .ok_or_else(|| Status::unavailable("coin witness provider not available"))?.clone();
            let permit = COIN_WITNESS_WORKERS.try_acquire()
                .map_err(|_| Status::resource_exhausted("coin witness workers busy; retry later"))?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                provider.coin_witnesses(&domain, &addresses)
            }).await.map_err(|e| Status::internal(format!("coin witness task: {e}")))?
                .map_err(coin_witness_status)?
                .ok_or_else(|| Status::unimplemented("coin witnesses are not enabled"))?
        } else {
            let remote = self.remote_coin_witnesses.as_ref().ok_or_else(|| self.coverage_error(&domain))?;
            remote(domain, addresses).await.ok_or_else(|| Status::unavailable(format!(
                "no node serving application {} answered this node", hex::encode(domain)
            )))?
        };
        if !(1..=32).contains(&result.depth) || result.root_record.len() != ROOT_RECORD_BYTES
            || result.root_record.get(..8) != Some(b"QCT3RT\0\x02".as_slice())
            || result.root_record.get(40) != Some(&result.depth)
            || result.witnesses.len() != expected.len() {
            return Err(Status::internal("invalid coin witness dimensions"));
        }
        for (witness, address) in result.witnesses.iter().zip(&expected) {
            let count = if witness.found { usize::from(result.depth) } else { 0 };
            if &witness.address != address || witness.siblings.len() != count || witness.right.len() != count
                || witness.siblings.iter().any(|node| node.len() != NODE_BYTES) {
                return Err(Status::internal("invalid coin witness path"));
            }
        }
        let response = node::GetCoinWitnessesResponse {
            network: result.network.to_vec(), root_record: result.root_record,
            witnesses: result.witnesses.into_iter().map(|witness| node::CoinWitness {
                address: witness.address.to_vec(), found: witness.found, siblings: witness.siblings, right: witness.right,
            }).collect(),
        };
        if prost::Message::encoded_len(&response) >= 1 << 20 {
            return Err(Status::resource_exhausted("coin witness response exceeds size limit"));
        }
        Ok(Response::new(response))
    }

    async fn list_escrows(
        &self,
        request: Request<node::ListCoinsRequest>,
    ) -> Result<Response<node::ListEscrowsResponse>, Status> {
        let req = request.into_inner();
        let domain: [u8; 32] = req.domain.try_into()
            .map_err(|_| Status::invalid_argument("domain must be 32 bytes"))?;
        let optional_address = |bytes: Vec<u8>| -> Result<Option<[u8; 32]>, Status> {
            if bytes.is_empty() { Ok(None) } else {
                bytes.try_into().map(Some).map_err(|_| Status::invalid_argument("scan identity and cursor must be empty or 32 bytes"))
            }
        };
        let snapshot_id = optional_address(req.snapshot_id)?;
        let after = optional_address(req.after)?;
        if after.is_some() && snapshot_id.is_none() {
            return Err(Status::invalid_argument("continuation requires snapshot identity"));
        }
        let page = if self.serves_application(&domain) {
            let provider = self.coin_witness_provider.as_ref()
                .ok_or_else(|| Status::unavailable("coin provider not available"))?.clone();
            let permit = COIN_WITNESS_WORKERS.try_acquire()
                .map_err(|_| Status::resource_exhausted("coin workers busy; retry later"))?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                provider.escrow_page(&domain, snapshot_id.as_ref(), after.as_ref())
            }).await.map_err(|e| Status::internal(format!("escrow scan task: {e}")))?
                .map_err(coin_witness_status)?
                .ok_or_else(|| Status::unimplemented("escrow scan is not enabled"))?
        } else {
            let remote = self.remote_escrow_page.as_ref().ok_or_else(|| self.coverage_error(&domain))?;
            remote(domain, snapshot_id, after).await.ok_or_else(|| Status::unavailable(format!(
                "no node serving application {} answered this node", hex::encode(domain)
            )))?
        };
        if snapshot_id.is_some_and(|id| id != page.snapshot_id)
            || page.escrows.len() > 8
            || (page.has_more && (page.cursor.is_none() || page.cursor <= after))
            || page.cursor < after {
            return Err(Status::internal("invalid coin scan page"));
        }
        let mut previous = after;
        for (address, blob) in &page.escrows {
            if previous.is_some_and(|old| *address <= old)
                || page.cursor.is_none_or(|cursor| *address > cursor)
                || blob.is_empty() || blob.len() > 64 * 1024 {
                return Err(Status::internal("invalid coin scan escrow"));
            }
            previous = Some(*address);
        }
        let response = node::ListEscrowsResponse {
            network: page.network.to_vec(), snapshot_id: page.snapshot_id.to_vec(),
            escrows: page.escrows.into_iter().map(|(address, raw_data)| node::Escrow {
                address: address.to_vec(), raw_data,
            }).collect(),
            cursor: page.cursor.map(|cursor| cursor.to_vec()).unwrap_or_default(), has_more: page.has_more,
        };
        if prost::Message::encoded_len(&response) > 256 * 1024 {
            return Err(Status::resource_exhausted("coin scan response exceeds size limit"));
        }
        Ok(Response::new(response))
    }

    async fn list_coins(
        &self,
        request: Request<node::ListCoinsRequest>,
    ) -> Result<Response<node::ListCoinsResponse>, Status> {
        let req = request.into_inner();
        let domain: [u8; 32] = req.domain.try_into()
            .map_err(|_| Status::invalid_argument("domain must be 32 bytes"))?;
        let optional_address = |bytes: Vec<u8>| -> Result<Option<[u8; 32]>, Status> {
            if bytes.is_empty() { Ok(None) } else {
                bytes.try_into().map(Some).map_err(|_| Status::invalid_argument("scan identity and cursor must be empty or 32 bytes"))
            }
        };
        let snapshot_id = optional_address(req.snapshot_id)?;
        let after = optional_address(req.after)?;
        if after.is_some() && snapshot_id.is_none() {
            return Err(Status::invalid_argument("continuation requires snapshot identity"));
        }
        // Local when this node covers the application; otherwise a node that
        // does. Either way the page is validated below before it is returned.
        let page = if self.serves_application(&domain) {
            let provider = self.coin_witness_provider.as_ref()
                .ok_or_else(|| Status::unavailable("coin provider not available"))?.clone();
            let permit = COIN_WITNESS_WORKERS.try_acquire()
                .map_err(|_| Status::resource_exhausted("coin workers busy; retry later"))?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                provider.coin_page(&domain, snapshot_id.as_ref(), after.as_ref())
            }).await.map_err(|e| Status::internal(format!("coin scan task: {e}")))?
                .map_err(coin_witness_status)?
                .ok_or_else(|| Status::unimplemented("coin scan is not enabled"))?
        } else {
            let remote = self.remote_coin_page.as_ref().ok_or_else(|| self.coverage_error(&domain))?;
            remote(domain, snapshot_id, after).await.ok_or_else(|| Status::unavailable(format!(
                "no node serving application {} answered this node", hex::encode(domain)
            )))?
        };
        if snapshot_id.is_some_and(|id| id != page.snapshot_id)
            || page.root_record.len() != ROOT_RECORD_BYTES
            || page.root_record.get(..8) != Some(b"QCT3RT\0\x02".as_slice())
            || !page.root_record.get(40).is_some_and(|depth| (1..=32).contains(depth))
            || page.coins.len() > 8
            || (page.has_more && (page.cursor.is_none() || page.cursor <= after))
            || page.cursor < after {
            return Err(Status::internal("invalid coin scan page"));
        }
        let mut previous = after;
        for coin in &page.coins {
            if previous.is_some_and(|address| coin.address <= address)
                || page.cursor.is_none_or(|cursor| coin.address > cursor)
                || coin.owner.len() != IDENTITY_BYTES || coin.commitment.len() != 10368 || coin.memo.len() != 1115 {
                return Err(Status::internal("invalid coin scan coin"));
            }
            previous = Some(coin.address);
        }
        let response = node::ListCoinsResponse {
            network: page.network.to_vec(), snapshot_id: page.snapshot_id.to_vec(), root_record: page.root_record,
            coins: page.coins.into_iter().map(|coin| node::ConfidentialCoin {
                address: coin.address.to_vec(), frame_number: coin.frame_number, position: coin.position,
                owner: coin.owner, commitment: coin.commitment, memo: coin.memo,
            }).collect(),
            cursor: page.cursor.map(|cursor| cursor.to_vec()).unwrap_or_default(), has_more: page.has_more,
        };
        if prost::Message::encoded_len(&response) > 256 * 1024 {
            return Err(Status::resource_exhausted("coin scan response exceeds size limit"));
        }
        Ok(Response::new(response))
    }



    async fn get_mint_authorization_witness(
        &self,
        request: Request<node::GetMintAuthorizationWitnessRequest>,
    ) -> Result<Response<node::GetMintAuthorizationWitnessResponse>, Status> {
        let receipt: [u8; 32] = request.into_inner().receipt.as_slice().try_into()
            .map_err(|_| Status::invalid_argument("mint authorization receipt must be 32 bytes"))?;
        let provider = self.coin_witness_provider.as_ref()
            .ok_or_else(|| Status::unavailable("coin witness provider not available"))?.clone();
        let witness = tokio::task::spawn_blocking(move || provider.mint_authorization_witness(&receipt))
            .await.map_err(|_| Status::internal("mint authorization witness worker failed"))?.map_err(|e| {
            if e.is_execution_unavailable() { Status::unavailable(format!("mint authorization witness: {e}")) }
            else { Status::internal(format!("mint authorization witness: {e}")) }
        })?;
        if witness.forest_proof.len() > 32 * 1024 || (witness.found && witness.global_root.len() != 32) {
            return Err(Status::internal("invalid mint authorization witness from provider"));
        }
        Ok(Response::new(node::GetMintAuthorizationWitnessResponse {
            found: witness.found, forest_proof: witness.forest_proof,
            cited_frame: witness.cited_frame, global_root: witness.global_root,
        }))
    }

    async fn get_prover_reward_witness(
        &self,
        request: Request<node::GetProverRewardWitnessRequest>,
    ) -> Result<Response<node::GetProverRewardWitnessResponse>, Status> {
        let provider = self
            .coin_witness_provider
            .as_ref()
            .ok_or_else(|| Status::unavailable("coin witness provider not available"))?;
        let req = request.into_inner();
        let w = provider
            .prover_reward_witness(&req.domain, &req.owner_prover_address)
            .map_err(|e| {
                if e.is_execution_unavailable() {
                    Status::unavailable(format!("prover reward witness: {e}"))
                } else {
                    Status::internal(format!("prover reward witness: {e}"))
                }
            })?;
        Ok(Response::new(node::GetProverRewardWitnessResponse {
            found: w.found,
            forest_proof: w.forest_proof,
            value: w.value.to_le_bytes().to_vec(),
            cited_frame: w.cited_frame,
            reward_root: w.reward_root,
        }))
    }

    async fn get_metrics(
        &self,
        request: Request<node::GetMetricsRequest>,
    ) -> Result<Response<node::GetMetricsResponse>, Status> {
        let req = request.into_inner();
        let text = match &self.metrics_renderer {
            Some(r) => r(),
            None => String::new(),
        };
        // Optional substring filter — matches Go's NodeService::GetMetrics
        // filter arg: only lines whose metric name contains the filter.
        let filtered = if req.filter.is_empty() {
            text
        } else {
            text.lines()
                .filter(|line| line.contains(&req.filter))
                .collect::<Vec<_>>()
                .join("\n")
        };
        Ok(Response::new(node::GetMetricsResponse {
            metrics: filtered.into_bytes(),
        }))
    }

    async fn get_vertex_data(
        &self,
        request: Request<node::GetVertexDataRequest>,
    ) -> Result<Response<node::GetVertexDataResponse>, Status> {
        let req = request.into_inner();
        if req.address.len() != 64 {
            return Err(Status::invalid_argument(
                "invalid address length, expected 64 bytes",
            ));
        }
        // Vertex ID = 32-byte app address || 32-byte data address.
        // Shard derived from app address, matching Go's
        // `GetBloomFilterIndices(id[:32], 256, 3)`.
        let app_address = &req.address[..32];
        let shard = quil_types::store::ShardKey {
            l1: quil_hypergraph::addressing::get_bloom_filter_indices(app_address, 256, 3),
            l2: {
                let mut l2 = [0u8; 32];
                l2.copy_from_slice(app_address);
                l2
            },
        };
        // Both sources use the same response formatting. In particular a
        // forwarded non-full read must enumerate the tree's entries too.
        let raw = if !self.serves_application(app_address) {
            let remote = self.remote_vertex.as_ref().ok_or_else(|| self.coverage_error(app_address))?;
            let (present, blob) = remote(shard.l2, req.address[32..].to_vec()).await
                .ok_or_else(|| Status::unavailable(format!(
                    "no node serving application {} answered this node", hex::encode(app_address)
                )))?;
            present.then_some(blob)
        } else {
            let mut stores = match &self.app_hypergraph_stores {
                Some(resolve) => resolve(app_address)?,
                None => Vec::new(),
            };
            if stores.is_empty() {
                stores.push(self.hypergraph_store.as_ref().ok_or_else(|| {
                    Status::unavailable("hypergraph store not available")
                })?.clone());
            }
            // A spent marker or escrow can be in any local worker store. An
            // arbitrary first store cannot establish absence. Conflicting
            // replicas are retryable, never resolved by map iteration order.
            let mut raw = None;
            for store in stores {
                if let Some(blob) = store.load_vertex_underlying_raw("vertex", "adds", &shard, &req.address)
                    .map_err(|e| Status::internal(format!("load vertex underlying: {e}")))? {
                    if raw.as_ref().is_some_and(|previous| previous != &blob) {
                        return Err(Status::unavailable("local application stores disagree on vertex data; retry later"));
                    }
                    raw = Some(blob);
                }
            }
            raw
        };

        let present = Some(raw.is_some());
        let (entries, raw_data) = match raw {
            None => (Vec::new(), Vec::new()),
            Some(bytes) => {
                if req.full_data {
                    // Return the serialized tree bytes directly —
                    // qclient `DeserializeNonLazyTree`s them.
                    (Vec::new(), bytes)
                } else {
                    // Parse the tree and enumerate canonical leaf
                    // indices (Go reads {0},{4},{8},{12},{16},{20},
                    // {24},{28},{0xff}).
                    let root = quil_tries::deserialize_go_tree(&bytes).map_err(|e| {
                        Status::internal(format!("deserialize vertex tree: {e}"))
                    })?;
                    let tree = quil_tries::VectorCommitmentTree { root };
                    let mut entries = Vec::new();
                    for key in &[
                        &[0u8][..],
                        &[4u8][..],
                        &[8u8][..],
                        &[12u8][..],
                        &[16u8][..],
                        &[20u8][..],
                        &[24u8][..],
                        &[28u8][..],
                        &[0xffu8][..],
                    ] {
                        if let Some(val) = tree.get(key) {
                            entries.push(node::VertexDataEntry {
                                key: key.to_vec(),
                                value: val.to_vec(),
                            });
                        }
                    }
                    (entries, Vec::new())
                }
            }
        };
        Ok(Response::new(node::GetVertexDataResponse {
            present,
            entries,
            set_type: "vertex".into(),
            phase_type: "adds".into(),
            shard_l1: shard.l1.to_vec(),
            shard_l2: shard.l2.to_vec(),
            raw_data,
        }))
    }

    async fn get_hyperedge_data(
        &self,
        request: Request<node::GetHyperedgeDataRequest>,
    ) -> Result<Response<node::GetHyperedgeDataResponse>, Status> {
        let store = self.hypergraph_store.as_ref().ok_or_else(|| {
            Status::unavailable("hypergraph store not available")
        })?;
        let req = request.into_inner();
        if req.address.len() != 64 {
            return Err(Status::invalid_argument(
                "invalid address length, expected 64 bytes",
            ));
        }
        let app_address = &req.address[..32];
        let shard = quil_types::store::ShardKey {
            l1: quil_hypergraph::addressing::get_bloom_filter_indices(app_address, 256, 3),
            l2: {
                let mut l2 = [0u8; 32];
                l2.copy_from_slice(app_address);
                l2
            },
        };
        let raw = store
            .load_vertex_underlying_raw("hyperedge", "adds", &shard, &req.address)
            .map_err(|e| Status::internal(format!("load hyperedge underlying: {e}")))?;
        let entries = match raw {
            None => Vec::new(),
            Some(bytes) => {
                let root = quil_tries::deserialize_go_tree(&bytes).map_err(|e| {
                    Status::internal(format!("deserialize hyperedge tree: {e}"))
                })?;
                let tree = quil_tries::VectorCommitmentTree { root };
                let mut entries = Vec::new();
                for key in &[
                    &[0u8][..],
                    &[4u8][..],
                    &[8u8][..],
                    &[12u8][..],
                    &[16u8][..],
                    &[20u8][..],
                    &[24u8][..],
                    &[28u8][..],
                    &[0xffu8][..],
                ] {
                    if let Some(val) = tree.get(key) {
                        entries.push(node::VertexDataEntry {
                            key: key.to_vec(),
                            value: val.to_vec(),
                        });
                    }
                }
                entries
            }
        };
        Ok(Response::new(node::GetHyperedgeDataResponse {
            entries,
            set_type: "hyperedge".into(),
            phase_type: "adds".into(),
            shard_l1: shard.l1.to_vec(),
            shard_l2: shard.l2.to_vec(),
        }))
    }

    async fn create_traversal_proof(
        &self,
        request: Request<node::CreateTraversalProofRequest>,
    ) -> Result<Response<node::CreateTraversalProofResponse>, Status> {
        let generator = self.traversal_proof_generator.as_ref().ok_or_else(|| {
            Status::unavailable("traversal proof generator not wired")
        })?;
        let req = request.into_inner();
        if req.domain.len() != 32 {
            return Err(Status::invalid_argument("domain must be 32 bytes"));
        }
        if req.keys.is_empty() {
            return Err(Status::invalid_argument("keys must be non-empty"));
        }
        if req.atom_type != "vertex" && req.atom_type != "hyperedge" {
            return Err(Status::invalid_argument(
                "atom_type must be 'vertex' or 'hyperedge'",
            ));
        }
        if req.phase_type != "adds" && req.phase_type != "removes" {
            return Err(Status::invalid_argument(
                "phase_type must be 'adds' or 'removes'",
            ));
        }
        let mut domain_arr = [0u8; 32];
        domain_arr.copy_from_slice(&req.domain);
        let bytes = generator(domain_arr, req.atom_type, req.phase_type, req.keys)
            .map_err(|e| Status::internal(format!("create proof: {e}")))?;
        Ok(Response::new(node::CreateTraversalProofResponse { proof: bytes }))
    }

    async fn get_token_fee_quote(
        &self, request: Request<node::GetTokenFeeQuoteRequest>,
    ) -> Result<Response<node::GetTokenFeeQuoteResponse>, Status> {
        let req = request.into_inner();
        let application: [u8; 32] = req.application.as_slice().try_into()
            .map_err(|_| Status::invalid_argument("application must be 32 bytes"))?;
        // QUIL operations pay their own fee; any other application's writes
        // are paid by a QUIL settlement sized from that application's venue.
        if application == quil_execution::domains::GLOBAL {
            return Err(Status::invalid_argument("the global intrinsic is not a fee venue"));
        }
        if req.max_payload_bytes == 0 || req.max_payload_bytes >= 1 << 20 {
            return Err(Status::invalid_argument("payload bound must be positive and below 1 MiB"));
        }
        let provider = self.token_fee_provider.clone()
            .ok_or_else(|| Status::unavailable("execution fee snapshot not available"))?;
        let permit = TOKEN_FEE_WORKERS.try_acquire()
            .map_err(|_| Status::resource_exhausted("fee quote workers busy"))?;
        let response = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let snapshot = provider(application, req.global_venue).map_err(coin_witness_status)?;
            if req.global_venue && (!snapshot.global_execution || snapshot.fee_multiplier_vote != 1) {
                return Err(Status::internal("global venue quote must use global execution pricing"));
            }
            let network = quil_execution::pricing::network_selector(&snapshot.network)
                .ok_or_else(|| Status::internal("fee snapshot has an invalid network identifier"))?;
            let budget = quil_execution::pricing::fee_budget_for_payload_limit(
                network, snapshot.difficulty, snapshot.world_state_bytes, req.max_payload_bytes,
                snapshot.fee_multiplier_vote,
            ).map_err(|_| Status::unavailable("fee snapshot exceeds supported pricing range"))?;
            let (_, encoded) = budget.to_bytes_be();
            if encoded.len() > 16 {
                return Err(Status::failed_precondition("fee budget exceeds token amount range"));
            }
            let mut fee_budget = vec![0; 16];
            fee_budget[16 - encoded.len()..].copy_from_slice(&encoded);
            Ok(node::GetTokenFeeQuoteResponse {
                application: application.to_vec(), network: snapshot.network.to_vec(),
                observed_frame: snapshot.observed_frame, global_execution: snapshot.global_execution,
                difficulty: snapshot.difficulty, world_state_bytes: snapshot.world_state_bytes,
                fee_multiplier_vote: snapshot.fee_multiplier_vote,
                max_payload_bytes: req.max_payload_bytes, fee_budget,
            })
        }).await.map_err(|_| Status::internal("fee quote worker failed"))??;
        Ok(Response::new(response))
    }

    async fn get_shard_info(
        &self,
        request: Request<node::GetShardInfoRequest>,
    ) -> Result<Response<node::GetShardInfoResponse>, Status> {
        let provider = self.shard_info_provider.as_ref().ok_or_else(|| {
            Status::unavailable("shard info not available")
        })?;

        let req = request.into_inner();
        let (details, difficulty, basis, frame_number) = provider
            .get_shard_info(req.include_all)
            .map_err(|e| Status::internal(format!("get shard info: {e}")))?;

        use num_bigint::BigInt;
        let mut world_bytes = BigInt::from(0);
        let mut shards = Vec::with_capacity(details.len());
        for d in &details {
            world_bytes += &d.shard_size;
            shards.push(node::ShardRewardInfo {
                filter: d.filter.clone(),
                active_provers: d.active_provers,
                ring: d.ring,
                shard_size: d.shard_size.to_signed_bytes_be(),
                estimated_reward: d.estimated_reward.to_signed_bytes_be(),
                is_allocated: d.is_allocated,
                data_shards: d.data_shards,
                materialized_frame: d.materialized_frame,
                latest_frame: d.latest_frame,
            });
        }

        Ok(Response::new(node::GetShardInfoResponse {
            shards,
            difficulty,
            pomw_basis: basis.to_signed_bytes_be(),
            world_state_bytes: world_bytes.to_signed_bytes_be(),
            frame_number,
        }))
    }

    async fn request_join(
        &self,
        request: Request<node::RequestJoinRequest>,
    ) -> Result<Response<node::RequestJoinResponse>, Status> {
        let ctl = self.worker_control.as_ref().ok_or_else(|| {
            Status::unavailable("worker control not wired")
        })?;
        let req = request.into_inner();
        if req.filters.is_empty() {
            return Err(Status::invalid_argument("filters must be non-empty"));
        }
        if !req.worker_ids.is_empty() && req.worker_ids.len() != req.filters.len() {
            return Err(Status::invalid_argument(format!(
                "worker_ids length ({}) must match filters length ({}) when provided",
                req.worker_ids.len(),
                req.filters.len()
            )));
        }
        let filter_hexes: Vec<String> = req.filters.iter().map(hex::encode).collect();
        tracing::info!(
            filter_count = req.filters.len(),
            filters = ?filter_hexes,
            worker_ids = ?req.worker_ids,
            delegate_len = req.delegate.len(),
            "RequestJoin RPC received"
        );
        ctl.request_join(req.filters, req.worker_ids, req.delegate)
            .await
            .map_err(|e| Status::internal(format!("request_join: {e}")))?;
        Ok(Response::new(node::RequestJoinResponse {}))
    }

    async fn set_manually_managed(
        &self,
        request: Request<node::SetManuallyManagedRequest>,
    ) -> Result<Response<node::SetManuallyManagedResponse>, Status> {
        let ctl = self.worker_control.as_ref().ok_or_else(|| {
            Status::unavailable("worker control not wired")
        })?;
        let req = request.into_inner();
        tracing::info!(
            core_id = req.core_id,
            mode = if req.manually_managed { "manual" } else { "auto" },
            "SetManuallyManaged RPC received"
        );
        ctl.set_manually_managed(req.core_id, req.manually_managed)
            .map_err(|e| Status::internal(format!("set_manually_managed: {e}")))?;
        Ok(Response::new(node::SetManuallyManagedResponse {}))
    }

    async fn get_latest_frame(
        &self,
        request: Request<global::GetGlobalFrameRequest>,
    ) -> Result<Response<global::GlobalFrameResponse>, Status> {
        let store = self.clock_store.as_ref().ok_or_else(|| {
            Status::unavailable("clock store not available")
        })?;
        let req = request.into_inner();
        let frame = if req.frame_number == 0 {
            store
                .get_latest_global_clock_frame()
                .map_err(|e| Status::not_found(format!("no frames: {e}")))?
        } else {
            store
                .get_global_clock_frame(req.frame_number)
                .map_err(|e| {
                    Status::not_found(format!("frame {} not found: {e}", req.frame_number))
                })?
        };
        Ok(Response::new(global::GlobalFrameResponse {
            frame: Some(frame),
            proof: Vec::new(),
        }))
    }

    async fn submit_message(
        &self,
        request: Request<node::SubmitMessageRequest>,
    ) -> Result<Response<node::SubmitMessageResponse>, Status> {
        let handler = self.submit_handler.as_ref().ok_or_else(|| {
            Status::unavailable("submit not wired — node is read-only")
        })?;
        let req = request.into_inner();
        if req.data.is_empty() {
            return Err(Status::invalid_argument("empty message"));
        }
        tracing::info!(byte_len = req.data.len(), "SubmitMessage RPC received");
        handler(req.data)
            .map_err(|e| Status::invalid_argument(format!("submit rejected: {e}")))?;
        Ok(Response::new(node::SubmitMessageResponse {}))
    }
}

/// Render a brief, comma-separated tag list of the request kinds in
/// a `MessageBundle` so `Send` RPC log lines tell the operator what
/// action fired (e.g. "Join,Confirm").
fn describe_message_bundle(bundle: &global::MessageBundle) -> String {
    use global::message_request::Request as R;
    let mut tags: Vec<&'static str> = Vec::with_capacity(bundle.requests.len());
    for r in &bundle.requests {
        tags.push(match &r.request {
            None => "None",
            Some(R::Join(_)) => "Join",
            Some(R::Leave(_)) => "Leave",
            Some(R::Pause(_)) => "Pause",
            Some(R::Resume(_)) => "Resume",
            Some(R::Confirm(_)) => "Confirm",
            Some(R::Reject(_)) => "Reject",
            Some(R::Kick(_)) => "Kick",
            Some(R::Update(_)) => "Update",
            Some(R::TokenDeploy(_)) => "TokenDeploy",
            Some(R::TokenUpdate(_)) => "TokenUpdate",
            Some(R::TokenOperation(_)) => "TokenOperation",
            Some(R::HypergraphDeploy(_)) => "HypergraphDeploy",
            Some(R::HypergraphUpdate(_)) => "HypergraphUpdate",
            Some(R::VertexAdd(_)) => "VertexAdd",
            Some(R::VertexRemove(_)) => "VertexRemove",
            Some(R::HyperedgeAdd(_)) => "HyperedgeAdd",
            Some(R::HyperedgeRemove(_)) => "HyperedgeRemove",
            Some(R::ComputeDeploy(_)) => "ComputeDeploy",
            Some(R::ComputeUpdate(_)) => "ComputeUpdate",
            Some(R::CodeDeploy(_)) => "CodeDeploy",
            Some(R::CodeExecute(_)) => "CodeExecute",
            Some(R::CodeFinalize(_)) => "CodeFinalize",
            Some(R::Shard(_)) => "Shard",
            Some(R::AltShardUpdate(_)) => "AltShardUpdate",
            Some(R::SeniorityMerge(_)) => "SeniorityMerge",
            Some(R::ShardSplit(_)) => "ShardSplit",
            Some(R::ShardMerge(_)) => "ShardMerge",
            Some(R::CommitteeHandoff(_)) => "CommitteeHandoff",
        });
    }
    tags.join(",")
}

#[cfg(test)]
mod coin_witness_tests {
    use super::*;
    use std::sync::{Condvar, Mutex};
    use quil_types::store::{CoinWitnessProvider, CoinWitnessBundle};

    struct BlockingWitness {
        gate: Arc<(Mutex<bool>, Condvar)>,
        started: tokio::sync::mpsc::UnboundedSender<()>,
    }

    impl CoinWitnessProvider for BlockingWitness {
        fn coin_witnesses(&self, _: &[u8; 32], _: &[[u8; 32]])
            -> quil_types::error::Result<Option<CoinWitnessBundle>>
        {
            self.started.send(()).unwrap();
            let (lock, ready) = &*self.gate;
            let mut released = lock.lock().unwrap();
            while !*released { released = ready.wait(released).unwrap(); }
            Err(quil_types::error::QuilError::NotFound("snapshot unavailable".into()))
        }

    }

    // Always unblock native workers, including on a failed assertion.
    struct ReleaseOnDrop(Arc<(Mutex<bool>, Condvar)>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            *self.0.0.lock().unwrap() = true;
            self.0.1.notify_all();
        }
    }

    fn request() -> Request<node::GetCoinWitnessesRequest> {
        Request::new(node::GetCoinWitnessesRequest {
            domain: vec![1; 32], addresses: vec![vec![2; 32]],
        })
    }

    #[tokio::test]
    async fn cancelled_rpc_keeps_worker_slot_until_rebuild_finishes() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let release = ReleaseOnDrop(gate.clone());
        let (started, mut starts) = tokio::sync::mpsc::unbounded_channel();
        let mut server = NodeRpcServer::default();
        server.coin_witness_provider = Some(Arc::new(BlockingWitness { gate, started }));
        let server = Arc::new(server);
        let first_server = server.clone();
        let first = tokio::spawn(async move { first_server.get_coin_witnesses(request()).await });
        let second_server = server.clone();
        let second = tokio::spawn(async move { second_server.get_coin_witnesses(request()).await });
        for _ in 0..2 {
            tokio::time::timeout(std::time::Duration::from_secs(5), starts.recv())
                .await.unwrap().unwrap();
        }
        // The async runtime remains responsive while both providers block.
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        let error = server.get_coin_witnesses(request()).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::ResourceExhausted);
        drop(release);
        let error = second.await.unwrap().unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unavailable);
    }
}

#[cfg(test)]
mod mint_authorization_witness_tests {
    use super::*;
    use quil_types::store::*;
    struct Provider { proof_len: usize, root_len: usize, fail: bool, caller: std::thread::ThreadId }
    impl CoinWitnessProvider for Provider {
        fn mint_authorization_witness(&self, receipt: &[u8; 32]) -> quil_types::error::Result<MintAuthorizationWitnessData> {
            assert_eq!(receipt, &[7; 32]);
            assert_ne!(std::thread::current().id(), self.caller, "store work must leave the async thread");
            if self.fail { return Err(quil_types::error::QuilError::ExecutionUnavailable("history pruned".into())); }
            Ok(MintAuthorizationWitnessData { found: true, cited_frame: 19,
                forest_proof: vec![1; self.proof_len], global_root: vec![2; self.root_len] })
        }
    }
    #[tokio::test]
    async fn mint_authorization_rpc_bounds_and_failure_classification() {
        let request = |len| Request::new(node::GetMintAuthorizationWitnessRequest { receipt: vec![7; len] });
        let server = |proof_len, root_len, fail| NodeRpcServer::new().with_coin_witness_provider(Arc::new(Provider {
            proof_len, root_len, fail, caller: std::thread::current().id(),
        }));
        let valid = server(32 * 1024, 32, false);
        assert_eq!(valid.get_mint_authorization_witness(request(31)).await.unwrap_err().code(), tonic::Code::InvalidArgument);
        let response = valid.get_mint_authorization_witness(request(32)).await.unwrap().into_inner();
        assert!(response.found);
        assert_eq!(response.cited_frame, 19);
        assert_eq!(response.global_root, vec![2; 32]);
        assert_eq!(response.forest_proof.len(), 32 * 1024);
        for bad in [server(32 * 1024 + 1, 32, false), server(1, 31, false)] {
            assert_eq!(bad.get_mint_authorization_witness(request(32)).await.unwrap_err().code(), tonic::Code::Internal);
        }
        assert_eq!(server(1, 32, true).get_mint_authorization_witness(request(32)).await.unwrap_err().code(), tonic::Code::Unavailable);
        assert_eq!(NodeRpcServer::new().get_mint_authorization_witness(request(32)).await.unwrap_err().code(), tonic::Code::Unavailable);
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    /// A node that does not hold an application must refuse a read for it
    /// rather than answer empty: a wallet cannot tell "no coins" from "not
    /// served here", and reads a token it owns as a zero balance.
    #[tokio::test]
    async fn a_read_for_an_unserved_application_is_refused_not_answered_empty() {
        let served = [7u8; 32];
        let server = NodeRpcServer::new().with_application_coverage({
            let served = served.to_vec();
            std::sync::Arc::new(move |app: &[u8]| app == served)
        });
        // Served: passes the gate (and then fails for want of a provider,
        // which is a different, honest answer).
        assert!(server.require_application_coverage(&served).is_ok());
        // Not served: refused, and the message says where to look.
        let status = server.require_application_coverage(&[9u8; 32]).unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert!(status.message().contains("does not serve"), "{}", status.message());
        assert!(status.message().contains(&hex::encode([9u8; 32])));
        // A vertex read for it is refused before any store lookup.
        let mut address = vec![9u8; 32];
        address.extend_from_slice(&[1u8; 32]);
        let status = server
            .get_vertex_data(tonic::Request::new(node::GetVertexDataRequest { address, ..Default::default() }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unavailable);
        // With no coverage hook wired, every application is served as before.
        assert!(NodeRpcServer::new().require_application_coverage(&[9u8; 32]).is_ok());
    }

}


#[cfg(test)]
mod witness_tests {
    use super::*;
    use quil_types::store::*;
    struct Provider {
        enabled: bool,
        bad_path: bool,
        bad_root: bool,
    }
    impl CoinWitnessProvider for Provider {
        fn escrow_page(&self, _: &[u8; 32], id: Option<&[u8; 32]>, after: Option<&[u8; 32]>) -> quil_types::error::Result<Option<EscrowPageData>> {
            if !self.enabled { return Ok(None); }
            Ok(Some(EscrowPageData { network: [0; 32], snapshot_id: if self.bad_root { [99; 32] } else { id.copied().unwrap_or([7; 32]) },
                escrows: if after.is_some() { vec![] } else { vec![([1; 32], vec![1; if self.bad_path { 65_537 } else { 64 }])] },
                cursor: Some([1; 32]), has_more: after.is_none() }))
        }

        fn coin_page(&self, _: &[u8; 32], id: Option<&[u8; 32]>, after: Option<&[u8; 32]>) -> quil_types::error::Result<Option<quil_types::store::CoinPageData>> {
            use quil_types::store::{CoinPageData, CoinData};
            if !self.enabled { return Ok(None); }
            let mut root_record = vec![0; ROOT_RECORD_BYTES];
            root_record[..8].copy_from_slice(b"QCT3RT\0\x02"); root_record[40] = 1;
            Ok(Some(CoinPageData {
                network: [0; 32], snapshot_id: if self.bad_root { [99; 32] } else { id.copied().unwrap_or([7; 32]) }, root_record,
                coins: if after.is_some() { Vec::new() } else { (1..=8).map(|i| CoinData {
                    address: [i; 32], frame_number: 1, position: u64::from(i) - 1, owner: vec![0; if self.bad_path { IDENTITY_BYTES - 1 } else { IDENTITY_BYTES }],
                    commitment: vec![0; 10368], memo: vec![0; 1115],
                }).collect() },
                cursor: if after.is_some() { Some([9; 32]) } else { Some([8; 32]) }, has_more: true,
            }))
        }
        fn coin_witnesses(
            &self,
            _: &[u8; 32],
            addresses: &[[u8; 32]],
        ) -> quil_types::error::Result<Option<CoinWitnessBundle>> {
            if !self.enabled {
                return Ok(None);
            }
            let mut root_record = vec![0; ROOT_RECORD_BYTES];
            root_record[..8].copy_from_slice(b"QCT3RT\0\x02");
            root_record[40] = if self.bad_root { 1 } else { 32 };
            Ok(Some(CoinWitnessBundle {
                network: [0; 32],
                root_record,
                depth: 32,
                witnesses: addresses
                    .iter()
                    .map(|address| CoinWitnessData {
                        address: *address,
                        found: true,
                        siblings: vec![vec![0; if self.bad_path { 1 } else { NODE_BYTES }]; 32],
                        right: vec![false; 32],
                    })
                    .collect(),
            }))
        }
    }
    #[test]
    fn witness_index_unavailability_is_retryable() {
        assert_eq!(coin_witness_status(quil_types::error::QuilError::ExecutionUnavailable("index building".into())).code(), tonic::Code::Unavailable);
        assert_eq!(coin_witness_status(quil_types::error::QuilError::InvalidArgument("bad request".into())).code(), tonic::Code::InvalidArgument);
        assert_eq!(coin_witness_status(quil_types::error::QuilError::Store("disk failure".into())).code(), tonic::Code::Internal);
    }

    #[tokio::test]
    async fn escrow_scan_bounds_and_continuation() {
        let request = |id: Vec<u8>, after: Vec<u8>| Request::new(node::ListCoinsRequest { domain: vec![0; 32], snapshot_id: id, after });
        let server = |enabled, bad_path, bad_root| NodeRpcServer::new().with_coin_witness_provider(Arc::new(Provider { enabled, bad_path, bad_root }));
        let valid = server(true, false, false);
        assert_eq!(valid.list_escrows(request(vec![], vec![1; 32])).await.unwrap_err().code(), tonic::Code::InvalidArgument);
        assert_eq!(valid.list_escrows(request(vec![1], vec![])).await.unwrap_err().code(), tonic::Code::InvalidArgument);
        let first = valid.list_escrows(request(vec![], vec![])).await.unwrap().into_inner();
        assert_eq!(first.escrows.len(), 1); assert!(first.has_more);
        let last = valid.list_escrows(request(first.snapshot_id, first.cursor)).await.unwrap().into_inner();
        assert!(last.escrows.is_empty() && !last.has_more);
        assert_eq!(server(true, true, false).list_escrows(request(vec![], vec![])).await.unwrap_err().code(), tonic::Code::Internal);
        assert_eq!(server(true, false, true).list_escrows(request(vec![7; 32], vec![])).await.unwrap_err().code(), tonic::Code::Internal);
        assert_eq!(server(false, false, false).list_escrows(request(vec![], vec![])).await.unwrap_err().code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn witness_scan_bounds_and_continuation() {
        let request = |snapshot_id: Vec<u8>, after: Vec<u8>| Request::new(node::ListCoinsRequest {
            domain: vec![1; 32], snapshot_id, after,
        });
        let empty = NodeRpcServer::new();
        for (id, after) in [(vec![], vec![1; 32]), (vec![1; 31], vec![]), (vec![1; 32], vec![1; 31])] {
            assert_eq!(empty.list_coins(request(id, after)).await.unwrap_err().code(), tonic::Code::InvalidArgument);
        }
        let server = NodeRpcServer::new().with_coin_witness_provider(Arc::new(Provider { enabled: true, bad_path: false, bad_root: false }));
        let first = server.list_coins(request(vec![], vec![])).await.unwrap().into_inner();
        assert_eq!(first.coins.len(), 8);
        assert!(prost::Message::encoded_len(&first) <= 256 * 1024);
        let next = server.list_coins(request(first.snapshot_id.clone(), first.cursor)).await.unwrap().into_inner();
        assert_eq!(next.snapshot_id, first.snapshot_id);
        assert!(next.coins.is_empty()); assert!(next.has_more);
        assert_eq!(next.cursor, vec![9; 32]);
        for (bad_path, bad_root) in [(true, false), (false, true)] {
            let server = NodeRpcServer::new().with_coin_witness_provider(Arc::new(Provider { enabled: true, bad_path, bad_root }));
            assert_eq!(server.list_coins(request(vec![7; 32], vec![])).await.unwrap_err().code(), tonic::Code::Internal);
        }
        let disabled = NodeRpcServer::new().with_coin_witness_provider(Arc::new(Provider { enabled: false, bad_path: false, bad_root: false }));
        assert_eq!(disabled.list_coins(request(vec![], vec![])).await.unwrap_err().code(), tonic::Code::Unimplemented);
    }

    fn request(addresses: Vec<Vec<u8>>) -> Request<node::GetCoinWitnessesRequest> {
        Request::new(node::GetCoinWitnessesRequest {
            domain: vec![1; 32],
            addresses,
        })
    }
    #[tokio::test]
    async fn witness_request_validation_precedes_provider_work() {
        let server = NodeRpcServer::new();
        for addresses in [
            vec![],
            vec![vec![1; 31]],
            vec![vec![1; 32]; 2],
            (0..5).map(|i| vec![i; 32]).collect(),
        ] {
            let error = server
                .get_coin_witnesses(request(addresses))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
        }
        let error = server
            .get_coin_witnesses(Request::new(
                node::GetCoinWitnessesRequest {
                    domain: vec![],
                    addresses: vec![vec![1; 32]],
                },
            ))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
    }
    #[tokio::test]
    async fn witness_transport_bounds_and_optional_provider() {
        let server = NodeRpcServer::new().with_coin_witness_provider(Arc::new(Provider {
            enabled: true,
            bad_path: false,
            bad_root: false,
        }));
        let response = server
            .get_coin_witnesses(request((0..4).map(|i| vec![i; 32]).collect()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.witnesses.len(), 4);
        assert_eq!(response.witnesses[3].address, vec![3; 32]);
        assert_eq!(response.root_record.len(), ROOT_RECORD_BYTES);
        assert!(prost::Message::encoded_len(&response) < 1 << 20);
        let server = NodeRpcServer::new().with_coin_witness_provider(Arc::new(Provider {
            enabled: true,
            bad_path: true,
            bad_root: false,
        }));
        assert_eq!(
            server
                .get_coin_witnesses(request(vec![vec![1; 32]]))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Internal
        );
        let server = NodeRpcServer::new().with_coin_witness_provider(Arc::new(Provider {
            enabled: true,
            bad_path: false,
            bad_root: true,
        }));
        assert_eq!(
            server
                .get_coin_witnesses(request(vec![vec![1; 32]]))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Internal
        );
        let server = NodeRpcServer::new().with_coin_witness_provider(Arc::new(Provider {
            enabled: false,
            bad_path: false,
            bad_root: false,
        }));
        assert_eq!(
            server
                .get_coin_witnesses(request(vec![vec![1; 32]]))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unimplemented
        );
    }
}

#[cfg(test)]
mod token_fee_quote_tests {
    use super::*;

    /// The quote handler admits two concurrent workers process-wide; these
    /// tests each issue several quotes and must not contend for them.
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn request(limit: u64) -> Request<node::GetTokenFeeQuoteRequest> {
        Request::new(node::GetTokenFeeQuoteRequest {
            application: quil_execution::domains::QUIL_TOKEN.to_vec(), max_payload_bytes: limit,
            global_venue: false,
        })
    }
    fn snapshot() -> TokenFeeSnapshot {
        TokenFeeSnapshot { network: [0; 32], observed_frame: 42, global_execution: false,
            difficulty: 50_000, world_state_bytes: 0, fee_multiplier_vote: 7 }
    }

    #[tokio::test]
    async fn token_fee_quote_preserves_snapshot_and_covers_payload_bound() {
        let _serial = SERIAL.lock().await;
        let server = NodeRpcServer::new().with_token_fee_provider(Arc::new(|application, _| {
            assert_eq!(application, quil_execution::domains::QUIL_TOKEN);
            Ok(snapshot())
        }));
        let quote = server.get_token_fee_quote(request(64)).await.unwrap().into_inner();
        assert_eq!(quote.network, vec![0; 32]);
        assert_eq!(quote.application, quil_execution::domains::QUIL_TOKEN.to_vec());
        assert_eq!((quote.observed_frame, quote.difficulty, quote.world_state_bytes,
            quote.fee_multiplier_vote, quote.max_payload_bytes), (42, 50_000, 0, 7, 64));
        assert!(!quote.global_execution);
        assert_eq!(quote.fee_budget.len(), 16);
        let budget = u128::from_be_bytes(quote.fee_budget.try_into().unwrap());
        for cost in 1..=64 { assert!(budget >= cost * 7); }
        // No compiled floor: a zero vote prices the operation at zero.
        let zero_vote = NodeRpcServer::new().with_token_fee_provider(Arc::new(|_, _| Ok(TokenFeeSnapshot {
            fee_multiplier_vote: 0, ..snapshot()
        })));
        let quote = zero_vote.get_token_fee_quote(request(64)).await.unwrap().into_inner();
        assert_eq!(u128::from_be_bytes(quote.fee_budget.try_into().unwrap()), 0);
    }

    #[tokio::test]
    async fn token_fee_quote_rejects_missing_invalid_or_unrepresentable_pricing() {
        let _serial = SERIAL.lock().await;
        let empty = NodeRpcServer::new();
        assert_eq!(empty.get_token_fee_quote(request(64)).await.unwrap_err().code(), tonic::Code::Unavailable);
        for bound in [0, 1 << 20, u64::MAX] {
            assert_eq!(empty.get_token_fee_quote(request(bound)).await.unwrap_err().code(), tonic::Code::InvalidArgument);
        }
        let mut malformed = request(64).into_inner(); malformed.application.pop();
        assert_eq!(empty.get_token_fee_quote(Request::new(malformed)).await.unwrap_err().code(), tonic::Code::InvalidArgument);
        // Any application is a fee venue (settlements are sized from its
        // quote); the global intrinsic is not.
        let mut custom = request(64).into_inner(); custom.application = vec![9; 32];
        assert_eq!(empty.get_token_fee_quote(Request::new(custom)).await.unwrap_err().code(), tonic::Code::Unavailable);
        let mut global = request(64).into_inner(); global.application = vec![0xff; 32];
        assert_eq!(empty.get_token_fee_quote(Request::new(global)).await.unwrap_err().code(), tonic::Code::InvalidArgument);
        let overflow = NodeRpcServer::new().with_token_fee_provider(Arc::new(|_, _| Ok(TokenFeeSnapshot {
            world_state_bytes: u64::MAX, ..snapshot()
        })));
        assert_eq!(overflow.get_token_fee_quote(request(64)).await.unwrap_err().code(), tonic::Code::Unavailable);
        let excessive = NodeRpcServer::new().with_token_fee_provider(Arc::new(|_, _| Ok(TokenFeeSnapshot {
            difficulty: 5_000, world_state_bytes: 1, ..snapshot()
        })));
        assert_eq!(excessive.get_token_fee_quote(request(64)).await.unwrap_err().code(), tonic::Code::FailedPrecondition);
        let malformed_network = NodeRpcServer::new().with_token_fee_provider(Arc::new(|_, _| Ok(TokenFeeSnapshot {
            network: [7; 32], ..snapshot()
        })));
        assert_eq!(malformed_network.get_token_fee_quote(request(64)).await.unwrap_err().code(), tonic::Code::Internal);
    }

    /// Non-mainnet networks quote the fixed per-byte rate, so a young test
    /// network's tiny world state does not make growth unaffordable.
    #[tokio::test]
    async fn token_fee_quote_uses_the_fixed_rate_off_mainnet() {
        let _serial = SERIAL.lock().await;
        let server = NodeRpcServer::new().with_token_fee_provider(Arc::new(|_, _| {
            let mut network = [0u8; 32];
            network[31] = 1;
            Ok(TokenFeeSnapshot { network, difficulty: 5_000, world_state_bytes: 1, ..snapshot() })
        }));
        let quote = server.get_token_fee_quote(request(64)).await.unwrap().into_inner();
        let budget = u128::from_be_bytes(quote.fee_budget.try_into().unwrap());
        assert_eq!(budget, 64 * quil_execution::pricing::NON_MAINNET_UNITS_PER_BYTE as u128 * 7);
    }
}

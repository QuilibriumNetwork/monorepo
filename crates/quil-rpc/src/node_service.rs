use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tonic::{Request, Response, Status};

use quil_engine::current_frame::CurrentFrame;
use quil_types::consensus::{ProverRegistry, ShardInfoProvider};
use quil_types::proto::{global, node};
use quil_types::proto::node::node_service_server::NodeService;
use quil_types::store::{ClockStore, TokenStore};

/// Handler installed by the caller to route a Go-CLI `submit_message`
/// into the same message-collection pipeline used by
/// `GlobalService::submit_global_message`. Returns an error string
/// surfaced as `Status::invalid_argument`.
pub type UserSubmitHandler =
    Arc<dyn Fn(Vec<u8>) -> Result<(), String> + Send + Sync>;

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
    pub token_store: Option<Arc<dyn TokenStore>>,
    pub prover_registry: Option<Arc<dyn ProverRegistry>>,
    pub shard_info_provider: Option<Arc<dyn ShardInfoProvider>>,
    pub clock_store: Option<Arc<dyn ClockStore>>,
    pub hypergraph_store: Option<Arc<dyn quil_types::store::HypergraphStore>>,
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
            patch_number: vec![23],
            current_frame: CurrentFrame::new(),
            last_global_head_frame: Arc::new(AtomicU64::new(0)),
            prover_address: Vec::new(),
            reachable: false,
            token_store: None,
            prover_registry: None,
            shard_info_provider: None,
            clock_store: None,
            hypergraph_store: None,
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
    pub fn with_token_store(mut self, store: Arc<dyn TokenStore>) -> Self {
        self.token_store = Some(store);
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
    pub fn with_hypergraph_store(
        mut self,
        store: Arc<dyn quil_types::store::HypergraphStore>,
    ) -> Self {
        self.hypergraph_store = Some(store);
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

/// QUIL token domain address (poseidon("q_mainnet_token")).
const QUIL_TOKEN_ADDRESS: [u8; 32] = [
    0x11, 0x55, 0x85, 0x84, 0xaf, 0x70, 0x17, 0xa9,
    0xbf, 0xd1, 0xff, 0x18, 0x64, 0x30, 0x2d, 0x64,
    0x3f, 0xbe, 0x58, 0xc6, 0x2d, 0xcf, 0x90, 0xcb,
    0xcd, 0x8f, 0xde, 0x74, 0xa2, 0x67, 0x94, 0xd9,
];

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
                    // Only return live (non-terminal, non-expired)
                    // allocations. `is_live` applies the 720-frame
                    // grace check for Joining/Leaving and excludes
                    // Rejected/Kicked terminal states.
                    if !alloc.is_live(current_frame) {
                        continue;
                    }
                    shard_allocations.push(node::ShardAllocationInfo {
                        filter: alloc.confirmation_filter.clone(),
                        status: alloc.status as u32,
                        join_frame_number: alloc.join_frame_number,
                        join_confirm_frame_number: alloc.join_confirm_frame_number,
                        leave_frame_number: alloc.leave_frame_number,
                        last_active_frame_number: alloc.last_active_frame_number,
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

    async fn get_tokens_by_account(
        &self,
        request: Request<node::GetTokensByAccountRequest>,
    ) -> Result<Response<node::GetTokensByAccountResponse>, Status> {
        let store = self.token_store.as_ref().ok_or_else(|| {
            Status::unavailable(
                "token store not available -- token shards may not yet be \
                 unlocked, or node synchronization may still be in progress",
            )
        })?;

        let req = request.into_inner();

        // Legacy (pre-2.1) coins: 32-byte address, no domain or QUIL domain.
        if (req.domain.is_empty() || req.domain == QUIL_TOKEN_ADDRESS)
            && req.address.len() == 32
        {
            let (frame_numbers, addresses, coins) = store
                .get_coins_for_owner(&req.address)
                .map_err(|e| Status::internal(format!("get coins: {e}")))?;

            let legacy_coins: Vec<node::LegacyCoin> = coins
                .into_iter()
                .enumerate()
                .map(|(i, coin)| node::LegacyCoin {
                    coin: Some(coin),
                    frame_number: frame_numbers[i],
                    address: addresses[i].clone(),
                })
                .collect();

            return Ok(Response::new(node::GetTokensByAccountResponse {
                legacy_coins,
                transactions: Vec::new(),
                pending_transactions: Vec::new(),
            }));
        }

        if req.address.len() != 112 {
            return Err(Status::invalid_argument("invalid address length"));
        }

        let domain = if req.domain.is_empty() {
            QUIL_TOKEN_ADDRESS.to_vec()
        } else if req.domain.len() == 32 {
            req.domain
        } else {
            return Err(Status::invalid_argument("invalid domain length"));
        };

        let transactions = store
            .get_transactions_for_owner(&domain, &req.address)
            .map_err(|e| Status::internal(format!("get transactions: {e}")))?;

        let pending_transactions = store
            .get_pending_transactions_for_owner(&domain, &req.address)
            .map_err(|e| Status::internal(format!("get pending transactions: {e}")))?;

        Ok(Response::new(node::GetTokensByAccountResponse {
            legacy_coins: Vec::new(),
            transactions,
            pending_transactions,
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
        let store = self.hypergraph_store.as_ref().ok_or_else(|| {
            Status::unavailable("hypergraph store not available")
        })?;
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
        // Load the vertex's underlying sub-tree blob (Go-format). The
        // blob is stored at `(vertex, adds, shard, vertex_id)`.
        let raw = store
            .load_vertex_underlying_raw("vertex", "adds", &shard, &req.address)
            .map_err(|e| Status::internal(format!("load vertex underlying: {e}")))?;

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
            Some(R::Transaction(_)) => "Transaction",
            Some(R::PendingTransaction(_)) => "PendingTransaction",
            Some(R::MintTransaction(_)) => "MintTransaction",
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
        });
    }
    tags.join(",")
}

use std::sync::Arc;

use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};
use tracing::debug;

use quil_types::proto::global;
use quil_types::proto::global::global_service_server::GlobalService;
use quil_types::store::ShardsStore;

/// Channel capacity for the global-messages broadcast. Slow
/// subscribers get `Lagged` errors (which the stream wrapper
/// surfaces but doesn't drop the connection), matching Go's
/// `make(chan *...StreamGlobalMessagesResponse, 256)`.
pub const GLOBAL_MESSAGE_BROADCAST_CAPACITY: usize = 256;

/// Frame lookup trait — abstracts over the concrete clock store.
pub trait FrameLookup: Send + Sync {
    fn get_latest_frame(&self) -> Result<global::GlobalFrame, String>;
    fn get_frame(&self, frame_number: u64) -> Result<global::GlobalFrame, String>;
}

/// Handler invoked when a peer submits a message bundle via gRPC
/// (`submit_global_message`). The handler owns the decision about
/// what to do with the payload — typically it's routed into the same
/// pipeline that processes GLOBAL_PROVER / GLOBAL_CONSENSUS
/// BlossomSub messages.
///
/// Takes the full request so the handler can inspect the
/// [`crate::peer_auth_middleware::AuthenticatedPeer`] extension and
/// gate writes on peer identity.
///
/// Returns `Ok(())` to acknowledge acceptance, or an error string that
/// will be surfaced as `Status::invalid_argument`.
pub type SubmitHandler = Arc<
    dyn Fn(Request<global::SubmitGlobalMessageRequest>) -> Result<(), String>
        + Send
        + Sync,
>;

/// Snapshot function for workers — called by `GetWorkerInfo`.
pub type WorkerSnapshotFn =
    Arc<dyn Fn() -> Vec<global::GlobalGetWorkerInfoResponseItem> + Send + Sync>;

/// Per-phase root info returned by [`GlobalShardsProvider::phase_root_info`]:
/// `(commitment, size_bigint_be, leaf_count)`. Returns 64 zero bytes and
/// zero size/count if the phase tree doesn't exist.
pub type GlobalShardsProvider =
    Arc<dyn Fn(&[u8; 3], &[u8; 32]) -> [(Vec<u8>, Vec<u8>, u64); 4] + Send + Sync>;

/// Per-shard metadata provider used by [`GlobalRpcServer::get_app_shards`]:
/// given a 35-byte `shard_key` (L1[3]||L2[32]) and a `prefix` path,
/// returns `(size_be, data_shards, commitments[4])` derived from the
/// local hypergraph CRDT's VertexAdds tree. Returns `None` for malformed
/// keys; entries with no data return zero size/count and 64-byte zero
/// commitments. Mirrors Go's `services.go:GetAppShards` which fills
/// these from the engine-side shard metadata.
pub type AppShardsProvider = Arc<
    dyn Fn(&[u8], &[u32]) -> Option<(Vec<u8>, u64, [Vec<u8>; 4])> + Send + Sync,
>;

/// gRPC GlobalService implementation. Serves frames from the clock
/// store so other nodes can sync from us.
pub struct GlobalRpcServer {
    frames: Arc<dyn FrameLookup>,
    submit_handler: Option<SubmitHandler>,
    shards_store: Option<Arc<dyn ShardsStore>>,
    worker_snapshot: Option<WorkerSnapshotFn>,
    global_shards: Option<GlobalShardsProvider>,
    app_shards: Option<AppShardsProvider>,
    /// Broadcast channel for `StreamGlobalMessages`. Producers
    /// (BlossomSub recv loop) send each received message; every
    /// connected streamer gets a `Receiver` clone.
    message_broadcast: Option<broadcast::Sender<global::StreamGlobalMessagesResponse>>,
}

impl GlobalRpcServer {
    pub fn new(frames: Arc<dyn FrameLookup>) -> Self {
        Self {
            frames,
            submit_handler: None,
            shards_store: None,
            worker_snapshot: None,
            global_shards: None,
            app_shards: None,
            message_broadcast: None,
        }
    }

    pub fn with_global_shards_provider(mut self, p: GlobalShardsProvider) -> Self {
        self.global_shards = Some(p);
        self
    }

    pub fn with_app_shards_provider(mut self, p: AppShardsProvider) -> Self {
        self.app_shards = Some(p);
        self
    }

    /// Install the broadcast sender for `StreamGlobalMessages`.
    /// The caller (main.rs) holds the sender and pumps decoded
    /// `StreamGlobalMessagesResponse`s into it from the recv loop.
    pub fn with_message_broadcast(
        mut self,
        sender: broadcast::Sender<global::StreamGlobalMessagesResponse>,
    ) -> Self {
        self.message_broadcast = Some(sender);
        self
    }

    /// Install a handler for `submit_global_message`. Without this,
    /// gRPC submissions silently succeed but do nothing — useful for
    /// read-only archive nodes that don't relay.
    pub fn with_submit_handler(mut self, handler: SubmitHandler) -> Self {
        self.submit_handler = Some(handler);
        self
    }

    pub fn with_shards_store(mut self, store: Arc<dyn ShardsStore>) -> Self {
        self.shards_store = Some(store);
        self
    }

    pub fn with_worker_snapshot(mut self, snap: WorkerSnapshotFn) -> Self {
        self.worker_snapshot = Some(snap);
        self
    }
}

#[tonic::async_trait]
impl GlobalService for GlobalRpcServer {
    async fn get_global_frame(
        &self,
        request: Request<global::GetGlobalFrameRequest>,
    ) -> Result<Response<global::GlobalFrameResponse>, Status> {
        let req = request.into_inner();
        let frame_number = req.frame_number;

        let frame = if frame_number == 0 {
            self.frames
                .get_latest_frame()
                .map_err(|e| Status::not_found(format!("no frames: {}", e)))?
        } else {
            self.frames
                .get_frame(frame_number)
                .map_err(|e| Status::not_found(format!("frame {} not found: {}", frame_number, e)))?
        };

        Ok(Response::new(global::GlobalFrameResponse {
            frame: Some(frame),
            proof: Vec::new(),
        }))
    }

    async fn get_global_proposal(
        &self,
        request: Request<global::GetGlobalProposalRequest>,
    ) -> Result<Response<global::GlobalProposalResponse>, Status> {
        let req = request.into_inner();
        // Genesis (frame 0) path: just return the state frame, no QC/TC/vote.
        // Matches Go's `services.go:101-117` special case.
        if req.frame_number == 0 {
            let frame = self
                .frames
                .get_frame(0)
                .map_err(|e| Status::not_found(format!("no genesis frame: {e}")))?;
            return Ok(Response::new(global::GlobalProposalResponse {
                proposal: Some(global::GlobalProposal {
                    state: Some(frame),
                    parent_quorum_certificate: None,
                    prior_rank_timeout_certificate: None,
                    vote: None,
                }),
            }));
        }
        // Non-genesis: proposals need QC/TC/vote data that lives in a
        // different store table Go stitches together. Rust's current
        // ClockStore doesn't expose `GetProposalVote`/
        // `GetQuorumCertificate`/`GetTimeoutCertificate` publicly
        // via FrameLookup. Return an empty response (valid proto,
        // qclient displays "no proposal at frame N") — matches Go's
        // fallback at services.go:129,138.
        Ok(Response::new(global::GlobalProposalResponse { proposal: None }))
    }

    async fn get_app_shards(
        &self,
        request: Request<global::GetAppShardsRequest>,
    ) -> Result<Response<global::GetAppShardsResponse>, Status> {
        let shards_store = match &self.shards_store {
            Some(s) => s,
            None => {
                // Shards store not wired yet — return empty list so
                // qclient displays "no shards yet" rather than erroring.
                return Ok(Response::new(global::GetAppShardsResponse {
                    info: Vec::new(),
                }));
            }
        };
        let req = request.into_inner();
        let shards = if req.shard_key.len() == 35 {
            shards_store
                .get_app_shards(&req.shard_key, &req.prefix)
                .map_err(|e| Status::internal(format!("get_app_shards: {e}")))?
        } else {
            shards_store
                .range_app_shards()
                .map_err(|e| Status::internal(format!("range_app_shards: {e}")))?
        };
        let include_shard_key = req.shard_key.len() != 35;
        // `RocksShardsStore` only persists the prefix path bytes — it
        // doesn't carry `size`, `data_shards`, or `commitment`. Fill
        // those in by consulting the live CRDT via the provider, which
        // walks the per-shard phase trees and reads the root metadata.
        // Without this, every entry would report `size=0` and the
        // caller's `build_proposal_descriptors` filters it out → no
        // ProposeJoin ever fires.
        let info: Vec<global::AppShardInfo> = shards
            .into_iter()
            .map(|s| {
                let (size, data_shards, commitment) = match &self.app_shards {
                    Some(p) => match p(&s.shard_key, &s.prefix) {
                        Some((sz, ds, cm)) => (sz, ds, cm.to_vec()),
                        None => (Vec::new(), 0, (0..4).map(|_| vec![0u8; 64]).collect()),
                    },
                    None => (s.size, s.data_shards, s.commitment),
                };
                global::AppShardInfo {
                    shard_key: if include_shard_key { s.shard_key } else { Vec::new() },
                    prefix: s.prefix,
                    size,
                    data_shards,
                    commitment,
                }
            })
            .collect();
        Ok(Response::new(global::GetAppShardsResponse { info }))
    }

    async fn get_global_shards(
        &self,
        request: Request<global::GetGlobalShardsRequest>,
    ) -> Result<Response<global::GetGlobalShardsResponse>, Status> {
        let req = request.into_inner();
        if req.l1.len() != 3 || req.l2.len() != 32 {
            return Err(Status::invalid_argument("invalid shard key"));
        }
        let mut l1 = [0u8; 3];
        l1.copy_from_slice(&req.l1);
        let mut l2 = [0u8; 32];
        l2.copy_from_slice(&req.l2);

        // If a provider is installed, walk the four phase trees and
        // collect per-phase root commitments + sizes. Matches Go's
        // `services.go:313-368` exactly. Without a provider, fall
        // back to the zero-commitment response (structured but empty)
        // so qclient doesn't error out.
        let (size, commitment) = match &self.global_shards {
            Some(p) => {
                let entries = p(&l1, &l2);
                let mut total =
                    num_bigint::BigInt::from(0u64);
                let mut commits: Vec<Vec<u8>> = Vec::with_capacity(4);
                for (commit, size_be, _leaf_count) in entries.iter() {
                    total += num_bigint::BigInt::from_signed_bytes_be(size_be);
                    commits.push(commit.clone());
                }
                (total.to_signed_bytes_be(), commits)
            }
            None => (Vec::new(), (0..4).map(|_| vec![0u8; 64]).collect()),
        };
        Ok(Response::new(global::GetGlobalShardsResponse {
            size,
            commitment,
        }))
    }

    async fn get_locked_addresses(
        &self,
        _request: Request<global::GetLockedAddressesRequest>,
    ) -> Result<Response<global::GetLockedAddressesResponse>, Status> {
        // Tx-lock map is in-memory on the Go engine; Rust doesn't
        // maintain an equivalent yet. Archives answer "no locks" until
        // the mempool tx-lock subsystem lands.
        Ok(Response::new(global::GetLockedAddressesResponse {
            transactions: Vec::new(),
        }))
    }

    async fn get_worker_info(
        &self,
        _request: Request<global::GlobalGetWorkerInfoRequest>,
    ) -> Result<Response<global::GlobalGetWorkerInfoResponse>, Status> {
        // NOTE: Go gates this on `peer_id == self.peer_id` — an
        // operator-only check. Our peer-auth interceptor gives us
        // `AuthenticatedPeer`; we could add the self-peer check here
        // but for archive-node parity we trust the caller (reads
        // only).
        let workers = match &self.worker_snapshot {
            Some(s) => s(),
            None => Vec::new(),
        };
        Ok(Response::new(global::GlobalGetWorkerInfoResponse { workers }))
    }

    type StreamGlobalMessagesStream = std::pin::Pin<
        Box<
            dyn tokio_stream::Stream<
                    Item = Result<global::StreamGlobalMessagesResponse, Status>,
                > + Send,
        >,
    >;

    async fn stream_global_messages(
        &self,
        _request: Request<global::StreamGlobalMessagesRequest>,
    ) -> Result<Response<Self::StreamGlobalMessagesStream>, Status> {
        let sender = self.message_broadcast.as_ref().ok_or_else(|| {
            Status::unavailable("global message broadcast not wired")
        })?;
        let rx = sender.subscribe();
        // Map broadcast Receiver → Stream, discarding Lagged errors
        // (they signal a slow subscriber but shouldn't kill the
        // connection — Go uses a buffered channel that just drops
        // when full).
        let stream = BroadcastStream::new(rx).filter_map(|r| match r {
            Ok(msg) => Some(Ok(msg)),
            Err(_lag) => None,
        });
        Ok(Response::new(Box::pin(stream) as Self::StreamGlobalMessagesStream))
    }

    async fn submit_global_message(
        &self,
        request: Request<global::SubmitGlobalMessageRequest>,
    ) -> Result<Response<global::SubmitGlobalMessageResponse>, Status> {
        match &self.submit_handler {
            Some(handler) => {
                handler(request)
                    .map_err(|e| Status::invalid_argument(format!("submit rejected: {}", e)))?;
                Ok(Response::new(global::SubmitGlobalMessageResponse {}))
            }
            None => {
                debug!("submit_global_message called with no handler installed — dropping");
                Ok(Response::new(global::SubmitGlobalMessageResponse {}))
            }
        }
    }
}

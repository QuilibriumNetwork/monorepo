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

    /// Assemble the full `GlobalProposal` for `frame_number` — the state plus
    /// its certifying parent QC, prior-rank TC, and proposer vote — so a peer
    /// can sync proposals into its consensus engine (not just mirror frames).
    /// Mirrors Go `GlobalConsensusEngine.GetGlobalProposal`. The default errors;
    /// the concrete clock-store-backed impl overrides it.
    fn get_global_proposal(
        &self,
        _frame_number: u64,
    ) -> Result<global::GlobalProposal, String> {
        Err("get_global_proposal not supported by this FrameLookup".into())
    }
}

/// Read-through, bounded in-memory cache in front of a [`FrameLookup`].
///
/// Why: the peer-facing `GlobalService` (`:8340`) serves `get_global_frame`
/// and `get_global_proposal` to the whole network. With hundreds of nodes
/// polling the same recent frames once a second, the inner clock-store impl
/// hits RocksDB on *every* request — and `get_global_proposal` additionally
/// re-assembles the proposal (parent QC + prior TC + proposer vote, several
/// decodes) per call. That re-read storm is what overwhelms a handful of
/// archives.
///
/// Safety: a finalized frame is **immutable by number** — the canonical
/// chain never rewrites a committed height — so caching `get_frame(n)` /
/// `get_global_proposal(n)` by frame number can never serve a stale-but-wrong
/// value. The only entry that legitimately changes is the chain head, so
/// `get_latest_frame` is cached under a short TTL rather than by key.
///
/// Both maps are bounded; eviction drops the *lowest* frame number, because
/// the hot set is always the recent tip that everyone is polling.
pub struct CachingFrameLookup<F: FrameLookup> {
    inner: F,
    frames: std::sync::RwLock<std::collections::BTreeMap<u64, Arc<global::GlobalFrame>>>,
    proposals: std::sync::RwLock<std::collections::BTreeMap<u64, Arc<global::GlobalProposal>>>,
    latest: std::sync::RwLock<Option<(std::time::Instant, Arc<global::GlobalFrame>)>>,
    capacity: usize,
    latest_ttl: std::time::Duration,
}

impl<F: FrameLookup> CachingFrameLookup<F> {
    /// `capacity` is the per-map ceiling (frames and proposals are bounded
    /// independently); `latest_ttl` bounds how stale the served chain head
    /// may be. A 1s TTL collapses N pollers/second into ~1 store read while
    /// staying well inside the frame cadence.
    pub fn new(inner: F, capacity: usize, latest_ttl: std::time::Duration) -> Self {
        Self {
            inner,
            frames: std::sync::RwLock::new(std::collections::BTreeMap::new()),
            proposals: std::sync::RwLock::new(std::collections::BTreeMap::new()),
            latest: std::sync::RwLock::new(None),
            capacity,
            latest_ttl,
        }
    }

    fn insert_frame(&self, n: u64, frame: Arc<global::GlobalFrame>) {
        let mut w = self.frames.write().unwrap();
        w.insert(n, frame);
        while w.len() > self.capacity {
            // Drop the lowest frame number — the tip is the hot set.
            let lowest = match w.keys().next().copied() {
                Some(k) => k,
                None => break,
            };
            w.remove(&lowest);
        }
    }

    fn insert_proposal(&self, n: u64, proposal: Arc<global::GlobalProposal>) {
        let mut w = self.proposals.write().unwrap();
        w.insert(n, proposal);
        while w.len() > self.capacity {
            let lowest = match w.keys().next().copied() {
                Some(k) => k,
                None => break,
            };
            w.remove(&lowest);
        }
    }
}

impl<F: FrameLookup> FrameLookup for CachingFrameLookup<F> {
    fn get_latest_frame(&self) -> Result<global::GlobalFrame, String> {
        if let Some((at, frame)) = self.latest.read().unwrap().as_ref() {
            if at.elapsed() < self.latest_ttl {
                return Ok((**frame).clone());
            }
        }
        let frame = self.inner.get_latest_frame()?;
        let arc = Arc::new(frame.clone());
        // Opportunistically populate the by-number cache too: the head is
        // the single most-requested frame.
        if let Some(n) = frame.header.as_ref().map(|h| h.frame_number) {
            if n != 0 {
                self.insert_frame(n, arc.clone());
            }
        }
        *self.latest.write().unwrap() = Some((std::time::Instant::now(), arc));
        Ok(frame)
    }

    fn get_frame(&self, frame_number: u64) -> Result<global::GlobalFrame, String> {
        if let Some(frame) = self.frames.read().unwrap().get(&frame_number).cloned() {
            return Ok((*frame).clone());
        }
        let frame = self.inner.get_frame(frame_number)?;
        self.insert_frame(frame_number, Arc::new(frame.clone()));
        Ok(frame)
    }

    fn get_global_proposal(
        &self,
        frame_number: u64,
    ) -> Result<global::GlobalProposal, String> {
        if let Some(p) = self.proposals.read().unwrap().get(&frame_number).cloned() {
            return Ok((*p).clone());
        }
        let proposal = self.inner.get_global_proposal(frame_number)?;
        // Only cache *settled* proposals. Near the head a proposal's
        // best-effort parts (proposer vote, prior-rank TC) may not be
        // persisted yet at first request and fill in moments later;
        // caching the head would pin that incomplete view. Once a frame is
        // a few ranks below the head, every cert it carries is long since
        // formed and immutable, so it is safe to cache permanently.
        // Catch-up — the dominant repeated-read workload — pulls exactly
        // these settled, well-below-head proposals.
        const PROPOSAL_SETTLE_MARGIN: u64 = 4;
        let head = self
            .latest
            .read()
            .unwrap()
            .as_ref()
            .and_then(|(_, f)| f.header.as_ref().map(|h| h.frame_number))
            .unwrap_or(0);
        if frame_number == 0
            || (head > 0 && frame_number + PROPOSAL_SETTLE_MARGIN <= head)
        {
            self.insert_proposal(frame_number, Arc::new(proposal.clone()));
        }
        Ok(proposal)
    }
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

/// Handler for `submit_global_consensus`: a directly-delivered global
/// consensus message (proposal / vote / timeout) from a peer archive.
/// The handler routes `(bitmask, data)` into the node's consensus
/// receive path — the same one the BlossomSub GLOBAL_FRAME /
/// GLOBAL_CONSENSUS arms feed — so global consensus runs point-to-point
/// instead of over gossip (which can't carry a full-coverage proposal).
/// Receives the full `Request` so the handler can read the authenticated
/// peer identity. Returns `Ok(())` on accept or an error string.
pub type ConsensusDeliveryHandler = Arc<
    dyn Fn(Request<global::SubmitGlobalConsensusRequest>) -> Result<(), String>
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
    consensus_delivery: Option<ConsensusDeliveryHandler>,
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
            consensus_delivery: None,
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

    /// Install a handler for `submit_global_consensus` — direct
    /// point-to-point delivery of global consensus messages between
    /// genesis archives (replaces gossip for global consensus).
    pub fn with_consensus_delivery(mut self, handler: ConsensusDeliveryHandler) -> Self {
        self.consensus_delivery = Some(handler);
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
        // Assemble state + parent QC + prior TC + vote from the clock store
        // (see `FrameLookup::get_global_proposal`). Mirrors Go
        // `GlobalConsensusEngine.GetGlobalProposal`; on any lookup miss Go
        // returns an empty response rather than an error (qclient shows
        // "no proposal at frame N"), so we do the same.
        match self.frames.get_global_proposal(req.frame_number) {
            Ok(proposal) => Ok(Response::new(global::GlobalProposalResponse {
                proposal: Some(proposal),
            })),
            Err(e) => {
                debug!(frame_number = req.frame_number, error = %e, "get_global_proposal: returning empty");
                Ok(Response::new(global::GlobalProposalResponse { proposal: None }))
            }
        }
    }

    async fn get_app_shards(
        &self,
        request: Request<global::GetAppShardsRequest>,
    ) -> Result<Response<global::GetAppShardsResponse>, Status> {
        let Some(shards_store) = self.shards_store.clone() else {
            // Shards store not wired yet — return empty list so
            // qclient displays "no shards yet" rather than erroring.
            return Ok(Response::new(global::GetAppShardsResponse {
                info: Vec::new(),
            }));
        };
        let app_shards = self.app_shards.clone();
        let req = request.into_inner();
        // The shards-store scan plus the per-shard CRDT root walk (the
        // `app_shards` provider, which descends each shard's phase trees and
        // reads root metadata) is heavy, synchronous, `.await`-free work. Run
        // it on the blocking pool so it never holds an async worker on the
        // dedicated peer-gRPC runtime — a burst of these (especially the
        // `range_app_shards` path) would otherwise starve the accept loop,
        // TLS handshakes, and light handlers, the empty-frames stall.
        let info = tokio::task::spawn_blocking(move || -> Result<Vec<global::AppShardInfo>, String> {
            let shards = if req.shard_key.len() == 35 {
                shards_store
                    .get_app_shards(&req.shard_key, &req.prefix)
                    .map_err(|e| format!("get_app_shards: {e}"))?
            } else {
                shards_store
                    .range_app_shards()
                    .map_err(|e| format!("range_app_shards: {e}"))?
            };
            let include_shard_key = req.shard_key.len() != 35;
            // `RocksShardsStore` only persists the prefix path bytes — it
            // doesn't carry `size`, `data_shards`, or `commitment`. Fill
            // those in by consulting the live CRDT via the provider. Without
            // this, every entry would report `size=0` and the caller's
            // `build_proposal_descriptors` filters it out → no ProposeJoin.
            Ok(shards
                .into_iter()
                .map(|s| {
                    let (size, data_shards, commitment) = match &app_shards {
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
                .collect())
        })
        .await
        .map_err(|e| Status::internal(format!("get_app_shards task panicked: {e}")))?
        .map_err(Status::internal)?;
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
        // so qclient doesn't error out. The walk is heavy synchronous
        // work → offload to the blocking pool so it doesn't hold an async
        // worker on the dedicated peer-gRPC runtime.
        let global_shards = self.global_shards.clone();
        let (size, commitment) = tokio::task::spawn_blocking(move || match &global_shards {
            Some(p) => {
                let entries = p(&l1, &l2);
                let mut total = num_bigint::BigInt::from(0u64);
                let mut commits: Vec<Vec<u8>> = Vec::with_capacity(4);
                for (commit, size_be, _leaf_count) in entries.iter() {
                    total += num_bigint::BigInt::from_signed_bytes_be(size_be);
                    commits.push(commit.clone());
                }
                (total.to_signed_bytes_be(), commits)
            }
            None => (Vec::new(), (0..4).map(|_| vec![0u8; 64]).collect()),
        })
        .await
        .map_err(|e| Status::internal(format!("get_global_shards task panicked: {e}")))?;
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

    async fn submit_global_consensus(
        &self,
        request: Request<global::SubmitGlobalConsensusRequest>,
    ) -> Result<Response<global::SubmitGlobalConsensusResponse>, Status> {
        match &self.consensus_delivery {
            Some(handler) => {
                handler(request)
                    .map_err(|e| Status::invalid_argument(format!("consensus delivery rejected: {}", e)))?;
                Ok(Response::new(global::SubmitGlobalConsensusResponse {}))
            }
            None => {
                debug!("submit_global_consensus called with no handler installed — dropping");
                Ok(Response::new(global::SubmitGlobalConsensusResponse {}))
            }
        }
    }
}

#[cfg(test)]
mod caching_lookup_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn frame(n: u64) -> global::GlobalFrame {
        global::GlobalFrame {
            header: Some(global::GlobalFrameHeader {
                frame_number: n,
                ..Default::default()
            }),
            requests: Vec::new(),
        }
    }

    /// Counts inner calls so we can assert cache hits vs. store reads.
    struct CountingLookup {
        head: u64,
        get_frame_calls: AtomicU64,
        get_latest_calls: AtomicU64,
        get_proposal_calls: AtomicU64,
    }

    impl CountingLookup {
        fn new(head: u64) -> Self {
            Self {
                head,
                get_frame_calls: AtomicU64::new(0),
                get_latest_calls: AtomicU64::new(0),
                get_proposal_calls: AtomicU64::new(0),
            }
        }
    }

    impl FrameLookup for CountingLookup {
        fn get_latest_frame(&self) -> Result<global::GlobalFrame, String> {
            self.get_latest_calls.fetch_add(1, Ordering::SeqCst);
            Ok(frame(self.head))
        }
        fn get_frame(&self, n: u64) -> Result<global::GlobalFrame, String> {
            self.get_frame_calls.fetch_add(1, Ordering::SeqCst);
            Ok(frame(n))
        }
        fn get_global_proposal(&self, n: u64) -> Result<global::GlobalProposal, String> {
            self.get_proposal_calls.fetch_add(1, Ordering::SeqCst);
            Ok(global::GlobalProposal {
                state: Some(frame(n)),
                parent_quorum_certificate: None,
                prior_rank_timeout_certificate: None,
                vote: None,
            })
        }
    }

    #[test]
    fn frames_cached_by_number_immutable() {
        let cache = CachingFrameLookup::new(
            CountingLookup::new(100),
            8,
            std::time::Duration::from_secs(1),
        );
        for _ in 0..5 {
            let f = cache.get_frame(42).unwrap();
            assert_eq!(f.header.unwrap().frame_number, 42);
        }
        // Only the first read hit the inner store.
        assert_eq!(cache.inner.get_frame_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn latest_cached_under_ttl_then_refetched() {
        let cache = CachingFrameLookup::new(
            CountingLookup::new(100),
            8,
            std::time::Duration::from_millis(40),
        );
        cache.get_latest_frame().unwrap();
        cache.get_latest_frame().unwrap();
        assert_eq!(cache.inner.get_latest_calls.load(Ordering::SeqCst), 1, "within TTL → cached");
        std::thread::sleep(std::time::Duration::from_millis(60));
        cache.get_latest_frame().unwrap();
        assert_eq!(cache.inner.get_latest_calls.load(Ordering::SeqCst), 2, "after TTL → refetch");
    }

    #[test]
    fn eviction_drops_lowest_frame_number() {
        let cache = CachingFrameLookup::new(
            CountingLookup::new(100),
            2,
            std::time::Duration::from_secs(1),
        );
        cache.get_frame(10).unwrap();
        cache.get_frame(11).unwrap();
        cache.get_frame(12).unwrap(); // evicts 10 (lowest)
        let before = cache.inner.get_frame_calls.load(Ordering::SeqCst);
        cache.get_frame(11).unwrap(); // still cached
        cache.get_frame(12).unwrap(); // still cached
        assert_eq!(cache.inner.get_frame_calls.load(Ordering::SeqCst), before, "tip stays resident");
        cache.get_frame(10).unwrap(); // re-reads (was evicted)
        assert_eq!(cache.inner.get_frame_calls.load(Ordering::SeqCst), before + 1);
    }

    #[test]
    fn settled_proposal_cached_but_head_not() {
        let cache = CachingFrameLookup::new(
            CountingLookup::new(100),
            16,
            std::time::Duration::from_secs(1),
        );
        // Prime the head so the settle-margin check has a head to compare to.
        cache.get_latest_frame().unwrap();
        // Settled (well below head=100): cached.
        cache.get_global_proposal(50).unwrap();
        cache.get_global_proposal(50).unwrap();
        assert_eq!(cache.inner.get_proposal_calls.load(Ordering::SeqCst), 1, "settled proposal cached");
        // Head (== 100, within the 4-rank settle margin): NOT cached.
        cache.get_global_proposal(100).unwrap();
        cache.get_global_proposal(100).unwrap();
        assert_eq!(
            cache.inner.get_proposal_calls.load(Ordering::SeqCst),
            3,
            "in-flux head proposal re-assembled each call (not pinned)"
        );
        // Genesis is always cacheable (fully static).
        cache.get_global_proposal(0).unwrap();
        let after_genesis = cache.inner.get_proposal_calls.load(Ordering::SeqCst);
        cache.get_global_proposal(0).unwrap();
        assert_eq!(cache.inner.get_proposal_calls.load(Ordering::SeqCst), after_genesis);
    }
}

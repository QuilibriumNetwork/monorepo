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
    // Separate miss locks keep cache hits independent of storage latency.
    // Stripes bound bookkeeping while allowing unrelated heights to load.
    frame_loads: [std::sync::Mutex<()>; 32],
    proposal_loads: [std::sync::Mutex<()>; 32],
    latest_load: std::sync::Mutex<()>,
    capacity: usize,
    frame_capacity: usize,
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
            frame_loads: std::array::from_fn(|_| std::sync::Mutex::new(())),
            proposal_loads: std::array::from_fn(|_| std::sync::Mutex::new(())),
            latest_load: std::sync::Mutex::new(()),
            capacity,
            frame_capacity: capacity,
            latest_ttl,
        }
    }

    /// Disable the duplicate frame map when the backing clock store already
    /// retains finalized frames. Proposal caching remains independently bounded.
    pub fn with_frame_capacity(mut self, capacity: usize) -> Self {
        self.frame_capacity = capacity;
        self
    }

    fn insert_frame(&self, n: u64, frame: Arc<global::GlobalFrame>) {
        if self.frame_capacity == 0 { return; }
        let mut w = self.frames.write().unwrap();
        w.insert(n, frame);
        while w.len() > self.frame_capacity {
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
        let _load = self.latest_load.lock().unwrap();
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
        if self.frame_capacity == 0 { return self.inner.get_frame(frame_number); }
        if let Some(frame) = self.frames.read().unwrap().get(&frame_number).cloned() {
            return Ok((*frame).clone());
        }
        let _load = self.frame_loads[(frame_number % 32) as usize].lock().unwrap();
        if let Some(frame) = self.frames.read().unwrap().get(&frame_number).cloned() {
            return Ok((*frame).clone());
        }
        let frame = self.inner.get_frame(frame_number)?;
        if self.frame_capacity > 0 {
            self.insert_frame(frame_number, Arc::new(frame.clone()));
        }
        Ok(frame)
    }

    fn get_global_proposal(
        &self,
        frame_number: u64,
    ) -> Result<global::GlobalProposal, String> {
        if let Some(p) = self.proposals.read().unwrap().get(&frame_number).cloned() {
            return Ok((*p).clone());
        }
        let _load = self.proposal_loads[(frame_number % 32) as usize].lock().unwrap();
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
        // Proposal-only catchup must refresh the head itself; it cannot rely
        // on another RPC having populated (and kept refreshing) latest.
        let head = self.get_latest_frame().ok()
            .and_then(|f| f.header.map(|h| h.frame_number));
        if frame_number == 0
            || head.is_some_and(|h| h.saturating_sub(frame_number) >= PROPOSAL_SETTLE_MARGIN)
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

/// Delivers a standalone worker's shard resolver message to the committee
/// members it names, directly over this node's peer connections:
/// `(filter, channel, data, recipient committee keys)` → every recipient
/// accepted it.
pub type ShardDirectRelay = Arc<
    dyn Fn(Vec<u8>, u64, Vec<u8>, Vec<Vec<u8>>) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>
        + Send
        + Sync,
>;

/// Sends one of a standalone worker's GLOBAL requests (a certified shard
/// `FrameHeader` or a committee-handoff submission) on through this node's
/// archive transport: `(core_id, canonical request)` → queued (`Ok(false)`:
/// held back by a coverage halt; `Err`: not a request a worker may submit).
pub type WorkerProverSubmitter = Arc<
    dyn Fn(u32, Vec<u8>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, String>> + Send>>
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
/// returns `(size_be, data_shards, commitments[4], materialized_frame,
/// latest_frame)` derived from the local archive state. The latter two values
/// distinguish a committed app state from a stored-but-unmaterialized frame.
/// local hypergraph CRDT's VertexAdds tree. Returns `None` for malformed
/// keys; entries with no data return zero size/count and 64-byte zero
/// commitments. Mirrors Go's `services.go:GetAppShards` which fills
/// these from the engine-side shard metadata.
pub type AppShardsProvider = Arc<
    dyn Fn(&[u8], &[u32]) -> Option<(Vec<u8>, u64, [Vec<u8>; 4], u64, u64)> + Send + Sync,
>;

/// Serves forest-sync data (JMT nodes/values of a shard/phase tree) from the
/// local CRDT's forest, for [`GlobalRpcServer::get_forest_node`] /
/// `get_forest_value`. A pure read proxy: the diff client authenticates every
/// node against the trusted header root, so nothing served here is trusted on
/// its own. Installed by the node (which owns the CRDT).
pub trait ForestServer: Send + Sync {
    fn global_vertex_proof(&self, _root: [u8; 32], _address: [u8; 32]) -> Option<Vec<u8>> { None }
    /// `borsh(NodeKey)` → `borsh(Node)` (None if absent / malformed key).
    fn serve_node(&self, shard_id: &[u8], phase: u32, node_key: &[u8]) -> Option<Vec<u8>>;
    /// `(version, key_hash)` → leaf value (None if absent).
    fn serve_value(&self, shard_id: &[u8], phase: u32, version: u64, key_hash: [u8; 32])
        -> Option<Vec<u8>>;
    /// Head `(version, root)` of a shard/phase tree, for the client's
    /// version-discovery step. None if the tree was never committed.
    fn serve_head(&self, shard_id: &[u8], phase: u32) -> Option<(u64, [u8; 32])>;
    /// The raw l3 key (`vertex_id ‖ field_key`) a `key_hash` was committed from.
    fn serve_preimage(&self, shard_id: &[u8], phase: u32, key_hash: [u8; 32]) -> Option<Vec<u8>>;
    /// A vertex's committed blob (the readable data), keyed under the app
    /// ShardKey bytes (`l1[3] ‖ l2[32]`). `version` MVCC-pins the read to the
    /// tree version the diff addressed (`None` means latest).
    fn serve_vertex_blob(&self, shard_key: &[u8], phase: u32, id: &[u8], version: Option<u64>)
        -> Option<Vec<u8>>;
    /// Leaves of a shard/phase tree with keys in `[first, last]` after `after`,
    /// each at its newest value at or below `version`, in key order, at most
    /// [`MAX_FOREST_LEAVES`] and about [`MAX_FOREST_BATCH_BYTES`], and whether
    /// more may follow. `None` when this server cannot list leaves.
    #[allow(clippy::too_many_arguments)]
    fn serve_leaves(
        &self,
        _shard_id: &[u8],
        _phase: u32,
        _version: u64,
        _first: &[u8; 32],
        _last: &[u8; 32],
        _after: Option<&[u8; 32]>,
    ) -> Option<(Vec<([u8; 32], Vec<u8>)>, bool)> {
        None
    }
    /// Sync-by-hash: authenticated tree `root` → local `(version, global_frame)`
    /// for a `(shard_id, phase)` tree. None if never committed here or pruned.
    fn resolve_root(&self, shard_id: &[u8], phase: u32, root: [u8; 32]) -> Option<(u64, u64)>;
    /// Sync-by-hash (split apps): the sub-shard manifest folding into an
    /// aggregate `app_root` — `[(prefix_words, sub_root, sub_version)]`.
    #[allow(clippy::type_complexity)]
    fn serve_app_manifest(
        &self,
        app_address: &[u8],
        phase: u32,
        app_root: [u8; 32],
    ) -> Option<Vec<(Vec<u8>, [u8; 32], u64)>>;
}

/// The committed GLOBAL frame the node's state is at, if known. Shard
/// topology and pending changes are written only by GLOBAL commits, so rows
/// read at one value stay current until it changes.
pub type AppShardsVersion = Arc<dyn Fn() -> Option<u64> + Send + Sync>;

/// Distinct requests whose shard rows are kept; prefixes are caller-chosen.
const APP_SHARD_TOPOLOGY_ENTRIES: usize = 256;

/// Callers waiting for the one shard-row read in progress.
static APP_SHARDS_WAITING: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// One request's shard rows and whether a pending split or merge freezes each.
type ShardTopology = Vec<(quil_types::store::ShardInfo, bool)>;
type AppShardTopologies =
    std::collections::HashMap<(Vec<u8>, Vec<u32>), (u64, Arc<ShardTopology>)>;

/// The shard rows a `GetAppShards` request names: one application's when
/// `shard_key` is a full 35-byte key, otherwise every application's.
fn read_shard_topology(
    store: &dyn ShardsStore,
    shard_key: &[u8],
    prefix: &[u32],
) -> Result<ShardTopology, String> {
    let shards = if shard_key.len() == 35 {
        store.get_app_shards(shard_key, prefix).map_err(|e| format!("get_app_shards: {e}"))?
    } else {
        store.range_app_shards().map_err(|e| format!("range_app_shards: {e}"))?
    };
    let pending = store
        .all_pending_shard_changes()
        .map_err(|e| format!("all_pending_shard_changes: {e}"))?;
    Ok(shards
        .into_iter()
        .map(|s| {
            let frozen = frozen_by_pending_change(&s.shard_key, &s.prefix, &pending);
            (s, frozen)
        })
        .collect())
}

/// gRPC GlobalService implementation. Serves frames from the clock
/// store so other nodes can sync from us.
pub struct GlobalRpcServer {
    /// `GetAppShards` shard rows, read once per committed GLOBAL frame (see
    /// [`AppShardsVersion`]): every prover polls them.
    app_shard_topologies: Arc<tokio::sync::Mutex<AppShardTopologies>>,
    app_shards_version: Option<AppShardsVersion>,
    frames: Arc<dyn FrameLookup>,
    submit_handler: Option<SubmitHandler>,
    consensus_delivery: Option<ConsensusDeliveryHandler>,
    shards_store: Option<Arc<dyn ShardsStore>>,
    worker_snapshot: Option<WorkerSnapshotFn>,
    global_shards: Option<GlobalShardsProvider>,
    app_shards: Option<AppShardsProvider>,
    forest_server: Option<Arc<dyn ForestServer>>,
    global_vertex_proof_source: Option<quil_engine::storage_history::GlobalVertexProofSource>,
    archive_directory: Option<Arc<crate::ArchiveEndpointPool>>,
    /// Broadcast channel for `StreamGlobalMessages`. Producers
    /// (BlossomSub recv loop) send each received message; every
    /// connected streamer gets a `Receiver` clone.
    message_broadcast: Option<broadcast::Sender<global::StreamGlobalMessagesResponse>>,
    /// The node's OWN peer id (`PeerId::to_bytes()`). When set, worker-privileged
    /// RPCs (`StreamGlobalMessages`, `GetWorkerInfo`, `GetAppShards`) require the
    /// authenticated caller to present THIS identity — i.e. only the node's own
    /// data-worker processes (which dial with the node's Ed448 seed) may invoke
    /// them, mirroring Go's `bytes.Equal(GetPeerID(), peerID)` self-gate. A remote
    /// machine handshakes as a different peer_id and is denied. `None` ⇒ no gate
    /// (single-machine/thread mode, where there is no gRPC boundary).
    self_peer_id: Option<Vec<u8>>,
    /// See [`ShardDirectRelay`]; `None` answers "not delivered".
    shard_direct_relay: Option<ShardDirectRelay>,
    /// See [`WorkerProverSubmitter`]; `None` answers "unimplemented".
    worker_prover_submitter: Option<WorkerProverSubmitter>,
    /// Rebuilds legacy committees for the node's own workers; `None` answers
    /// "unimplemented".
    historical_committees: Option<quil_engine::historical_committee::HistoricalCommitteeSource>,
    /// Authorizer for prover-gated RPCs (`GetGlobalProposal`): returns `true` iff
    /// the authenticated caller is the node's own identity OR resolves to an
    /// ACTIVE prover (Go `authenticateProverFromContext`). `None` ⇒ no gate.
    #[allow(clippy::type_complexity)]
    prover_authorizer:
        Option<Arc<dyn Fn(&crate::peer_auth_middleware::AuthenticatedPeer) -> bool + Send + Sync>>,
}

// Shared across peer-facing server instances. A cancelled RPC keeps its
// permit inside the blocking closure until storage work actually finishes.
// `QUIL_FOREST_READ_SLOTS` concurrent storage reads (default 32); a batched
// request reads up to `MAX_FOREST_BATCH_KEYS` keys under one slot, and cached
// nodes and values (`forest_read_cache`) take no slot at all. Sixteen kept
// an archive's disk below its queue depth while syncs waited on it.
static FOREST_READ_WORKERS: std::sync::LazyLock<tokio::sync::Semaphore> = std::sync::LazyLock::new(|| {
    let slots = std::env::var("QUIL_FOREST_READ_SLOTS").ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| (1..=1024).contains(n))
        .unwrap_or(32);
    tokio::sync::Semaphore::new(slots)
});
static HISTORY_FORWARD_WORKERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

/// How long a forest read waits for a storage slot before the archive answers
/// busy. A syncing client retries; a long queue would only hold its
/// connection open.
const FOREST_READ_WAIT: std::time::Duration = std::time::Duration::from_secs(2);
/// Reads waiting for a slot beyond which further reads are refused at once.
const MAX_FOREST_READ_WAITERS: usize = 64;
/// Storage slots one authenticated peer may hold at once, so a single syncing
/// client cannot occupy all of them. A node's workers all reach the archive
/// under its identity, so this is shared by every worker bootstrapping at
/// once (4 starved a node of 15 after the committee-handoff flag day).
const FOREST_READ_SLOTS_PER_PEER: usize = 8;
/// Keys one batched forest read may name.
pub const MAX_FOREST_BATCH_KEYS: usize = 512;
/// Leaves one leaf listing returns (vertex leaves are 40 bytes, so about
/// 4.7 MB of keys and values).
pub const MAX_FOREST_LEAVES: usize = 65_536;
/// A batched response stops (answering a prefix) once it carries this many
/// bytes; the client asks again for the rest.
pub const MAX_FOREST_BATCH_BYTES: usize = 8 * 1024 * 1024;

static FOREST_READ_WAITERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static FOREST_READ_REFUSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static FOREST_READ_QUEUED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static FOREST_LEAVES_LISTED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static FOREST_READ_PEER_SLOTS: std::sync::LazyLock<parking_lot::Mutex<std::collections::HashMap<Vec<u8>, usize>>> =
    std::sync::LazyLock::new(Default::default);

/// Forest reads this process has served, refused and queued, and its read
/// cache, since start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForestReadStats {
    pub cache: crate::forest_read_cache::ForestReadCacheStats,
    pub refused: u64,
    pub queued: u64,
    /// Leaves served by bootstrap listings (no per-node reads).
    pub listed: u64,
}

pub fn forest_read_stats() -> ForestReadStats {
    ForestReadStats {
        cache: crate::forest_read_cache::ForestReadCache::process().stats(),
        refused: FOREST_READ_REFUSED.load(std::sync::atomic::Ordering::Relaxed),
        queued: FOREST_READ_QUEUED.load(std::sync::atomic::Ordering::Relaxed),
        listed: FOREST_LEAVES_LISTED.load(std::sync::atomic::Ordering::Relaxed),
    }
}

/// The authenticated caller, for the per-peer slot limit.
fn forest_reader(extensions: &tonic::Extensions) -> Option<Vec<u8>> {
    extensions
        .get::<crate::peer_auth_middleware::AuthenticatedPeer>()
        .map(|auth| auth.peer_id.to_bytes())
}

/// One of a peer's storage slots, released on drop.
struct PeerSlot(Option<Vec<u8>>);

impl PeerSlot {
    fn take(peer: Option<Vec<u8>>, limit: usize) -> Result<Self, Status> {
        let Some(peer) = peer else { return Ok(Self(None)) };
        let mut slots = FOREST_READ_PEER_SLOTS.lock();
        let held = slots.entry(peer.clone()).or_insert(0);
        if *held >= limit {
            FOREST_READ_REFUSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return Err(Status::resource_exhausted("forest reads for this peer at their limit; retry later"));
        }
        *held += 1;
        Ok(Self(Some(peer)))
    }
}

impl Drop for PeerSlot {
    fn drop(&mut self) {
        let Some(peer) = self.0.take() else { return };
        let mut slots = FOREST_READ_PEER_SLOTS.lock();
        if let Some(held) = slots.get_mut(&peer) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                slots.remove(&peer);
            }
        }
    }
}

async fn forest_read<T: Send + 'static>(
    server: Option<Arc<dyn ForestServer>>,
    peer: Option<Vec<u8>>,
    read: impl FnOnce(&dyn ForestServer) -> Option<T> + Send + 'static,
) -> Result<Option<T>, Status> {
    let Some(server) = server else { return Ok(None) };
    bounded_forest_read(&*FOREST_READ_WORKERS, FOREST_READ_WAIT, peer, move || read(server.as_ref())).await
}

/// Run `read` on a storage slot. A free slot is taken at once; otherwise the
/// read waits up to `wait` in a bounded queue, and is refused as busy past
/// that or when the queue is full. A peer holds at most
/// `FOREST_READ_SLOTS_PER_PEER` slots, queued or running.
async fn bounded_forest_read<T: Send + 'static>(
    workers: &'static tokio::sync::Semaphore,
    wait: std::time::Duration,
    peer: Option<Vec<u8>>,
    read: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Status> {
    use std::sync::atomic::Ordering;
    let busy = || {
        FOREST_READ_REFUSED.fetch_add(1, Ordering::Relaxed);
        Status::resource_exhausted("forest read workers busy; retry later")
    };
    let peer_slot = PeerSlot::take(peer, FOREST_READ_SLOTS_PER_PEER)?;
    let permit = match workers.try_acquire() {
        Ok(permit) => permit,
        Err(_) if wait.is_zero() => return Err(busy()),
        Err(_) => {
            if FOREST_READ_WAITERS.fetch_add(1, Ordering::Relaxed) >= MAX_FOREST_READ_WAITERS {
                FOREST_READ_WAITERS.fetch_sub(1, Ordering::Relaxed);
                return Err(busy());
            }
            FOREST_READ_QUEUED.fetch_add(1, Ordering::Relaxed);
            let acquired = tokio::time::timeout(wait, workers.acquire()).await;
            FOREST_READ_WAITERS.fetch_sub(1, Ordering::Relaxed);
            match acquired {
                Ok(Ok(permit)) => permit,
                _ => return Err(busy()),
            }
        }
    };
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _peer_slot = peer_slot;
        read()
    }).await.map_err(|e| Status::internal(format!("forest read task failed: {e}")))
}

/// Answer a batched read: each key from `hits` when cached, else through
/// `read` (which may cache it), stopping after `MAX_FOREST_BATCH_BYTES`.
fn answer_batch<K>(
    keys: Vec<K>,
    hits: Vec<Option<Arc<Vec<u8>>>>,
    mut read: impl FnMut(&K) -> Option<Vec<u8>>,
) -> Vec<global::ForestReadResult> {
    let mut out = Vec::with_capacity(keys.len());
    let mut bytes = 0usize;
    for (key, hit) in keys.iter().zip(hits) {
        if !out.is_empty() && bytes >= MAX_FOREST_BATCH_BYTES {
            break;
        }
        let data = match hit {
            Some(data) => Some(data.as_ref().clone()),
            None => read(key),
        };
        bytes += data.as_ref().map_or(0, Vec::len);
        out.push(global::ForestReadResult { found: data.is_some(), data: data.unwrap_or_default() });
    }
    out
}

impl GlobalRpcServer {
    pub fn new(frames: Arc<dyn FrameLookup>) -> Self {
        Self {
            app_shard_topologies: Arc::new(tokio::sync::Mutex::new(AppShardTopologies::new())),
            app_shards_version: None,
            frames,
            submit_handler: None,
            consensus_delivery: None,
            shards_store: None,
            worker_snapshot: None,
            global_shards: None,
            app_shards: None,
            forest_server: None,
            global_vertex_proof_source: None,
            archive_directory: None,
            message_broadcast: None,
            self_peer_id: None,
            shard_direct_relay: None,
            worker_prover_submitter: None,
            historical_committees: None,
            prover_authorizer: None,
        }
    }

    /// Install the source for `GetHistoricalCommittees`.
    pub fn with_historical_committees(mut self, source: quil_engine::historical_committee::HistoricalCommitteeSource) -> Self {
        self.historical_committees = Some(source);
        self
    }

    /// Install the submitter for `SubmitWorkerProverMessage`.
    pub fn with_worker_prover_submitter(mut self, submitter: WorkerProverSubmitter) -> Self {
        self.worker_prover_submitter = Some(submitter);
        self
    }

    /// Install the relay for `SendShardConsensusDirect`.
    pub fn with_shard_direct_relay(mut self, relay: ShardDirectRelay) -> Self {
        self.shard_direct_relay = Some(relay);
        self
    }

    /// Install the prover authorizer for `GetGlobalProposal` (self OR active
    /// prover). See [`prover_authorizer`](Self::prover_authorizer).
    #[allow(clippy::type_complexity)]
    pub fn with_prover_authorizer(
        mut self,
        f: Arc<dyn Fn(&crate::peer_auth_middleware::AuthenticatedPeer) -> bool + Send + Sync>,
    ) -> Self {
        self.prover_authorizer = Some(f);
        self
    }

    /// Strictly the node's own workers, for calls that act as the node (they
    /// send under its identity). Unlike the other worker-privileged calls, no
    /// configured identity is no access.
    fn is_own_identity(&self, ext: &tonic::Extensions) -> bool {
        self.self_peer_id.as_ref().is_some_and(|me| {
            ext.get::<crate::peer_auth_middleware::AuthenticatedPeer>()
                .is_some_and(|auth| auth.peer_id.to_bytes() == *me)
        })
    }

    /// Guard a prover-gated RPC (`GetGlobalProposal`): the authenticated caller
    /// must be the node's own identity OR an active prover. No-op when no
    /// authorizer is configured.
    fn require_prover(&self, ext: &tonic::Extensions) -> Result<(), tonic::Status> {
        let Some(ref authz) = self.prover_authorizer else {
            return Ok(());
        };
        match ext.get::<crate::peer_auth_middleware::AuthenticatedPeer>() {
            Some(auth) if authz(auth) => Ok(()),
            _ => Err(tonic::Status::permission_denied(
                "GetGlobalProposal: caller is not this node's identity or an active prover",
            )),
        }
    }

    /// Set the node's own peer id so worker-privileged RPCs are gated to the
    /// node's own identity (see [`self_peer_id`](Self::self_peer_id)).
    pub fn with_self_peer_id(mut self, peer_id: Vec<u8>) -> Self {
        self.self_peer_id = Some(peer_id);
        self
    }

    /// Guard a worker-privileged RPC: the authenticated caller must be the node's
    /// OWN identity. Returns `PermissionDenied` otherwise. No-op when no self
    /// peer id is configured (thread mode). `ext` is the request's extensions.
    fn require_self_identity(&self, ext: &tonic::Extensions) -> Result<(), tonic::Status> {
        let Some(ref me) = self.self_peer_id else {
            return Ok(());
        };
        match ext.get::<crate::peer_auth_middleware::AuthenticatedPeer>() {
            Some(auth) if auth.peer_id.to_bytes() == *me => Ok(()),
            _ => Err(tonic::Status::permission_denied(
                "worker-privileged RPC: caller is not this node's own identity",
            )),
        }
    }

    pub fn with_global_shards_provider(mut self, p: GlobalShardsProvider) -> Self {
        self.global_shards = Some(p);
        self
    }

    /// Install the forest-sync server (serves JMT nodes/values). Without it, the
    /// `GetForestNode`/`GetForestValue` RPCs report "not found".
    pub fn with_forest_server(mut self, s: Arc<dyn ForestServer>) -> Self {
        self.forest_server = Some(s);
        self
    }

    pub fn with_global_vertex_proof_source(mut self, source: Option<quil_engine::storage_history::GlobalVertexProofSource>) -> Self {
        self.global_vertex_proof_source = source;
        self
    }

    pub fn with_archive_directory(mut self, pool: Arc<crate::ArchiveEndpointPool>) -> Self {
        self.archive_directory = Some(pool);
        self
    }

    pub fn with_app_shards_provider(mut self, p: AppShardsProvider) -> Self {
        self.app_shards = Some(p);
        self
    }

    /// Keep `GetAppShards` shard rows until the committed GLOBAL frame moves.
    /// Without it they are read for every request.
    pub fn with_app_shards_version(mut self, version: AppShardsVersion) -> Self {
        self.app_shards_version = Some(version);
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
    async fn get_archive_endpoints(
        &self, request: Request<global::GetArchiveEndpointsRequest>,
    ) -> Result<Response<global::GetArchiveEndpointsResponse>, Status> {
        self.require_self_identity(request.extensions())?;
        let pool = self.archive_directory.as_ref().ok_or_else(|| Status::unavailable("archive directory unavailable"))?;
        let endpoints = pool.get_all().await.into_iter()
            .filter(|entry| !entry.is_empty() && entry.len() <= 512).take(32).collect();
        Ok(Response::new(global::GetArchiveEndpointsResponse { endpoints }))
    }
    async fn get_global_vertex_proof(
        &self,
        request: Request<global::GetGlobalVertexProofRequest>,
    ) -> Result<Response<global::GetGlobalVertexProofResponse>, Status> {
        use quil_engine::storage_history::verify_global_vertex_proof;
        let peer = forest_reader(request.extensions());
        let req = request.into_inner();
        let root: [u8; 32] = req.root.as_slice().try_into().map_err(|_| Status::invalid_argument("GLOBAL root must be 32 bytes"))?;
        let address: [u8; 32] = req.address.as_slice().try_into().map_err(|_| Status::invalid_argument("GLOBAL address must be 32 bytes"))?;
        let mut proof = forest_read(self.forest_server.clone(), peer, move |s| s.global_vertex_proof(root, address)).await?;
        if proof.is_none() && req.allow_forward {
            if let Some(source) = self.global_vertex_proof_source.as_ref() {
                let _permit = HISTORY_FORWARD_WORKERS.try_acquire().map_err(|_| Status::resource_exhausted("history forwarding busy"))?;
                proof = tokio::time::timeout(std::time::Duration::from_secs(10), source(root, address))
                    .await.map_err(|_| Status::unavailable("historical proof forwarding timed out"))?
                    .map_err(|e| Status::unavailable(e.to_string()))?;
            }
        }
        if let Some(bytes) = proof.as_ref() {
            verify_global_vertex_proof(&root, &address, bytes).map_err(|e| Status::data_loss(e.to_string()))?;
        }
        Ok(Response::new(global::GetGlobalVertexProofResponse {
            found: proof.is_some(), proof: proof.unwrap_or_default(),
        }))
    }
    async fn get_global_frame(
        &self,
        request: Request<global::GetGlobalFrameRequest>,
    ) -> Result<Response<global::GlobalFrameResponse>, Status> {
        let req = request.into_inner();
        let frame_number = req.frame_number;

        // Store read runs on the blocking pool, NOT inline on a peer-gRPC
        // runtime worker. This is the hottest serving RPC on the network
        // (every archive poller + proposal catch-up hits it in a loop) and
        // a global frame record can be multi-MB — a burst of inline
        // synchronous RocksDB reads occupies the runtime's workers and
        // starves the latency-critical consensus delivery (votes/proposals)
        // sharing them. Same treatment as `get_app_shards` below.
        let frames = self.frames.clone();
        let frame = tokio::task::spawn_blocking(move || {
            if frame_number == 0 {
                frames
                    .get_latest_frame()
                    .map_err(|e| format!("no frames: {}", e))
            } else {
                frames
                    .get_frame(frame_number)
                    .map_err(|e| format!("frame {} not found: {}", frame_number, e))
            }
        })
        .await
        .map_err(|e| Status::internal(format!("get_global_frame task panicked: {e}")))?
        .map_err(Status::not_found)?;

        Ok(Response::new(global::GlobalFrameResponse {
            frame: Some(frame),
            proof: Vec::new(),
        }))
    }

    async fn get_global_proposal(
        &self,
        request: Request<global::GetGlobalProposalRequest>,
    ) -> Result<Response<global::GlobalProposalResponse>, Status> {
        // Prover-gated (Go `authenticateProverFromContext`, services.go:95): the
        // global proposal is served only to this node's own identity or an ACTIVE
        // prover.
        self.require_prover(request.extensions())?;
        let req = request.into_inner();
        // Assemble state + parent QC + prior TC + vote from the clock store
        // (see `FrameLookup::get_global_proposal`). Mirrors Go
        // `GlobalConsensusEngine.GetGlobalProposal`; on any lookup miss Go
        // returns an empty response rather than an error (qclient shows
        // "no proposal at frame N"), so we do the same.
        //
        // Offloaded to the blocking pool for the same reason as
        // `get_global_frame`: multiple synchronous store reads (frame,
        // parent frame, QC, TC, vote) that must not hold a peer-gRPC
        // runtime worker while catch-up peers hammer this in a loop.
        let frames = self.frames.clone();
        let frame_number = req.frame_number;
        let result = tokio::task::spawn_blocking(move || frames.get_global_proposal(frame_number))
            .await
            .map_err(|e| Status::internal(format!("get_global_proposal task panicked: {e}")))?;
        match result {
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
        let include_shard_key = req.shard_key.len() != 35;
        let key = (req.shard_key, req.prefix);
        let topologies = self.app_shard_topologies.clone();
        let version = self.app_shards_version.clone();
        // Detached so a caller that gives up still leaves its read behind: the
        // blocking work cannot be cancelled, and the next caller must not
        // start a second copy of it.
        let task = tokio::spawn(async move {
            let started = std::time::Instant::now();
            // Where a slow call's time went: waiting for the shared rows,
            // reading them (None: kept from this frame), waiting for a blocking
            // thread, and the per-shard reads by section.
            let lock_wait;
            let mut rows_read = None;
            // Rows change only with a committed GLOBAL frame: one caller reads
            // them per frame, and callers arriving meanwhile wait and share it.
            let topology = {
                APP_SHARDS_WAITING.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let mut kept = topologies.lock_owned().await;
                APP_SHARDS_WAITING.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                lock_wait = started.elapsed();
                let version = version.as_ref().and_then(|version| version());
                match (version, kept.get(&key)) {
                    (Some(version), Some((at, rows))) if *at == version => rows.clone(),
                    _ => {
                        let read_started = std::time::Instant::now();
                        let (store, (shard_key, prefix)) = (shards_store, key.clone());
                        let rows = Arc::new(
                            tokio::task::spawn_blocking(move || read_shard_topology(store.as_ref(), &shard_key, &prefix))
                                .await
                                .map_err(|e| Status::internal(format!("get_app_shards task panicked: {e}")))?
                                .map_err(Status::internal)?,
                        );
                        rows_read = Some(read_started.elapsed());
                        if let Some(version) = version {
                            if kept.len() >= APP_SHARD_TOPOLOGY_ENTRIES {
                                kept.retain(|_, (at, _)| *at == version);
                                if kept.len() >= APP_SHARD_TOPOLOGY_ENTRIES {
                                    kept.clear();
                                }
                            }
                            kept.insert(key, (version, rows.clone()));
                        }
                        rows
                    }
                }
            };
            // Sizes, executed and latest frames move with every application
            // frame: read now, from memory and per-shard indexes. `RocksShardsStore`
            // persists only the prefix path; without the provider every entry
            // would report `size=0` and `build_proposal_descriptors` would
            // filter it out → no ProposeJoin.
            let shard_reads_started = std::time::Instant::now();
            let (info, shard_reads, sections) = tokio::task::spawn_blocking(move || {
                let started = std::time::Instant::now();
                let sections = quil_execution::step_timing::collect();
                let info: Vec<global::AppShardInfo> = topology
                    .iter()
                    .map(|(s, pending_change)| {
                        let (size, data_shards, commitment, materialized_frame, latest_frame) = match &app_shards {
                            Some(p) => match p(&s.shard_key, &s.prefix) {
                                Some((sz, ds, cm, mat, latest)) => (sz, ds, cm.to_vec(), mat, latest),
                                None => (Vec::new(), 0, (0..4).map(|_| vec![0u8; 64]).collect(), 0, 0),
                            },
                            None => (s.size.clone(), s.data_shards, s.commitment.clone(), 0, 0),
                        };
                        global::AppShardInfo {
                            shard_key: if include_shard_key { s.shard_key.clone() } else { Vec::new() },
                            prefix: s.prefix.clone(),
                            size,
                            data_shards,
                            commitment,
                            materialized_frame,
                            latest_frame,
                            pending_change: *pending_change,
                        }
                    })
                    .collect();
                (info, started.elapsed(), sections.finish())
            })
            .await
            .map_err(|e| Status::internal(format!("get_app_shards task panicked: {e}")))?;
            let blocking_queue = shard_reads_started.elapsed().saturating_sub(shard_reads);
            if started.elapsed() >= std::time::Duration::from_secs(1) {
                let ms = |d: std::time::Duration| d.as_millis() as u64;
                let mut sections = sections;
                sections.sort_by(|a, b| b.2.cmp(&a.2));
                tracing::warn!(
                    ms = ms(started.elapsed()),
                    shards = info.len(),
                    waiting = APP_SHARDS_WAITING.load(std::sync::atomic::Ordering::Relaxed),
                    lock_wait_ms = ms(lock_wait),
                    rows_kept = rows_read.is_none(),
                    rows_read_ms = rows_read.map_or(0, ms),
                    blocking_queue_ms = ms(blocking_queue),
                    shard_reads_ms = ms(shard_reads),
                    sections = %sections
                        .iter()
                        .map(|(name, n, total)| format!("{name}: {n}× {} ms", total.as_millis()))
                        .collect::<Vec<_>>()
                        .join(" | "),
                    "slow GetAppShards computation",
                );
            }
            Result::<_, Status>::Ok(info)
        });
        let info = task
            .await
            .map_err(|e| Status::internal(format!("get_app_shards task failed: {e}")))??;
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
        request: Request<global::GlobalGetWorkerInfoRequest>,
    ) -> Result<Response<global::GlobalGetWorkerInfoResponse>, Status> {
        // Worker-privileged: only the node's own data-worker processes may read
        // the worker roster (Go `services.go:413` self-gate). A remote peer is
        // denied.
        self.require_self_identity(request.extensions())?;
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
        request: Request<global::StreamGlobalMessagesRequest>,
    ) -> Result<Response<Self::StreamGlobalMessagesStream>, Status> {
        // Worker-privileged: the full global dispatch stream is for this node's
        // OWN data-workers only — "only local workers may stream global messages"
        // (Go `services.go:452`). A remote machine that completes the handshake as
        // a different peer_id must NOT be able to subscribe to our dispatch.
        self.require_self_identity(request.extensions())?;
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
                match handler(request) {
                    Ok(()) => Ok(Response::new(global::SubmitGlobalMessageResponse {})),
                    Err(e) => {
                        tracing::debug!(error = %e, "global message submit rejected by collector");
                        Err(Status::invalid_argument(format!("submit rejected: {}", e)))
                    }
                }
            }
            None => {
                tracing::warn!("global message submit received but no handler installed — dropping");
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

    async fn send_shard_consensus_direct(
        &self,
        request: Request<global::SendShardConsensusDirectRequest>,
    ) -> Result<Response<global::SendShardConsensusDirectResponse>, Status> {
        if !self.is_own_identity(request.extensions()) {
            return Err(Status::permission_denied(
                "SendShardConsensusDirect: caller is not this node's own identity",
            ));
        }
        let req = request.into_inner();
        let delivered = match &self.shard_direct_relay {
            Some(relay) => relay(req.filter, req.channel, req.data, req.recipients).await,
            None => false,
        };
        Ok(Response::new(global::SendShardConsensusDirectResponse { delivered }))
    }

    async fn get_historical_committees(
        &self,
        request: Request<global::GetHistoricalCommitteesRequest>,
    ) -> Result<Response<global::GetHistoricalCommitteesResponse>, Status> {
        if !self.is_own_identity(request.extensions()) {
            return Err(Status::permission_denied(
                "GetHistoricalCommittees: caller is not this node's own identity",
            ));
        }
        let Some(source) = &self.historical_committees else {
            return Err(Status::unimplemented("GetHistoricalCommittees: not available"));
        };
        let req = request.into_inner();
        let committees = source(req.filter, req.anchor)
            .await
            .map_err(|e| Status::unavailable(e.to_string()))?;
        Ok(Response::new(global::GetHistoricalCommitteesResponse {
            committees: committees
                .into_iter()
                .map(|members| global::HistoricalCommittee { members })
                .collect(),
        }))
    }

    async fn submit_worker_prover_message(
        &self,
        request: Request<global::SubmitWorkerProverMessageRequest>,
    ) -> Result<Response<global::SubmitWorkerProverMessageResponse>, Status> {
        if !self.is_own_identity(request.extensions()) {
            return Err(Status::permission_denied(
                "SubmitWorkerProverMessage: caller is not this node's own identity",
            ));
        }
        let Some(submitter) = &self.worker_prover_submitter else {
            return Err(Status::unimplemented("SubmitWorkerProverMessage: no prover transport"));
        };
        let req = request.into_inner();
        match submitter(req.core_id, req.request).await {
            Ok(accepted) => Ok(Response::new(global::SubmitWorkerProverMessageResponse { accepted })),
            Err(error) => Err(Status::invalid_argument(error)),
        }
    }

    async fn get_forest_node(
        &self,
        request: Request<global::GetForestNodeRequest>,
    ) -> Result<Response<global::GetForestNodeResponse>, Status> {
        use crate::forest_read_cache::{CacheKey, ForestReadCache, Origin};
        let peer = forest_reader(request.extensions());
        let req = request.into_inner();
        let Some(origin) = self.forest_server.as_ref().map(Origin::of) else {
            return Ok(Response::new(global::GetForestNodeResponse { found: false, node: Vec::new() }));
        };
        let cache = ForestReadCache::process();
        let key = CacheKey::node(origin, &req.shard_id, req.phase, &req.node_key);
        let node = match cache.get(&key) {
            Some(node) => Some(node.as_ref().clone()),
            None => forest_read(self.forest_server.clone(), peer, move |s| {
                let node = s.serve_node(&req.shard_id, req.phase, &req.node_key);
                if let Some(node) = &node {
                    cache.put(key, node.clone());
                }
                node
            }).await?,
        };
        Ok(Response::new(global::GetForestNodeResponse {
            found: node.is_some(),
            node: node.unwrap_or_default(),
        }))
    }

    async fn get_forest_value(
        &self,
        request: Request<global::GetForestValueRequest>,
    ) -> Result<Response<global::GetForestValueResponse>, Status> {
        let peer = forest_reader(request.extensions());
        let req = request.into_inner();
        let key_hash: [u8; 32] = req
            .key_hash
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("key_hash must be 32 bytes"))?;
        let value = forest_read(self.forest_server.clone(), peer, move |s| s.serve_value(&req.shard_id, req.phase, req.version, key_hash)).await?;
        Ok(Response::new(global::GetForestValueResponse {
            found: value.is_some(),
            value: value.unwrap_or_default(),
        }))
    }

    async fn get_forest_head(
        &self,
        request: Request<global::GetForestHeadRequest>,
    ) -> Result<Response<global::GetForestHeadResponse>, Status> {
        let peer = forest_reader(request.extensions());
        let req = request.into_inner();
        let head = forest_read(self.forest_server.clone(), peer, move |s| s.serve_head(&req.shard_id, req.phase)).await?;
        Ok(Response::new(match head {
            Some((version, root)) => global::GetForestHeadResponse {
                found: true,
                version,
                root: root.to_vec(),
            },
            None => global::GetForestHeadResponse { found: false, version: 0, root: Vec::new() },
        }))
    }

    async fn get_forest_preimage(
        &self,
        request: Request<global::GetForestPreimageRequest>,
    ) -> Result<Response<global::GetForestPreimageResponse>, Status> {
        let peer = forest_reader(request.extensions());
        let req = request.into_inner();
        let key_hash: [u8; 32] = req
            .key_hash
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("key_hash must be 32 bytes"))?;
        let raw = forest_read(self.forest_server.clone(), peer, move |s| s.serve_preimage(&req.shard_id, req.phase, key_hash)).await?;
        Ok(Response::new(global::GetForestPreimageResponse {
            found: raw.is_some(),
            raw_key: raw.unwrap_or_default(),
        }))
    }

    async fn get_vertex_blob(
        &self,
        request: Request<global::GetVertexBlobRequest>,
    ) -> Result<Response<global::GetVertexBlobResponse>, Status> {
        let peer = forest_reader(request.extensions());
        let req = request.into_inner();
        let version = (req.exact_version || req.version != 0).then_some(req.version);
        let blob = forest_read(self.forest_server.clone(), peer, move |s| s.serve_vertex_blob(&req.shard_key, req.phase, &req.id, version)).await?;
        Ok(Response::new(global::GetVertexBlobResponse {
            found: blob.is_some(),
            blob: blob.unwrap_or_default(),
        }))
    }

    async fn get_forest_nodes(
        &self,
        request: Request<global::GetForestNodesRequest>,
    ) -> Result<Response<global::GetForestNodesResponse>, Status> {
        use crate::forest_read_cache::{CacheKey, ForestReadCache, Origin};
        let peer = forest_reader(request.extensions());
        let req = request.into_inner();
        if req.node_keys.len() > MAX_FOREST_BATCH_KEYS {
            return Err(Status::invalid_argument(format!("at most {MAX_FOREST_BATCH_KEYS} keys per request")));
        }
        let Some(origin) = self.forest_server.as_ref().map(Origin::of) else {
            let nodes = vec![global::ForestReadResult::default(); req.node_keys.len()];
            return Ok(Response::new(global::GetForestNodesResponse { nodes }));
        };
        let cache = ForestReadCache::process();
        let hits: Vec<_> = req.node_keys.iter()
            .map(|key| cache.get(&CacheKey::node(origin, &req.shard_id, req.phase, key)))
            .collect();
        let (shard_id, phase, keys) = (req.shard_id, req.phase, req.node_keys);
        let nodes = if hits.iter().all(Option::is_some) {
            answer_batch(keys, hits, |_| None)
        } else {
            let unserved = keys.len();
            forest_read(self.forest_server.clone(), peer, move |s| {
                Some(answer_batch(keys, hits, |key| {
                    let node = s.serve_node(&shard_id, phase, key);
                    if let Some(node) = &node {
                        cache.put(CacheKey::node(origin, &shard_id, phase, key), node.clone());
                    }
                    node
                }))
            }).await?.unwrap_or_else(|| vec![global::ForestReadResult::default(); unserved])
        };
        Ok(Response::new(global::GetForestNodesResponse { nodes }))
    }

    async fn get_forest_values(
        &self,
        request: Request<global::GetForestValuesRequest>,
    ) -> Result<Response<global::GetForestValuesResponse>, Status> {
        use crate::forest_read_cache::{CacheKey, ForestReadCache, Origin};
        let peer = forest_reader(request.extensions());
        let req = request.into_inner();
        if req.keys.len() > MAX_FOREST_BATCH_KEYS {
            return Err(Status::invalid_argument(format!("at most {MAX_FOREST_BATCH_KEYS} keys per request")));
        }
        let keys = req.keys.into_iter()
            .map(|key| {
                <[u8; 32]>::try_from(key.key_hash.as_slice())
                    .map(|hash| (key.version, hash))
                    .map_err(|_| Status::invalid_argument("key_hash must be 32 bytes"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let Some(origin) = self.forest_server.as_ref().map(Origin::of) else {
            let values = vec![global::ForestReadResult::default(); keys.len()];
            return Ok(Response::new(global::GetForestValuesResponse { values }));
        };
        let cache = ForestReadCache::process();
        let hits: Vec<_> = keys.iter()
            .map(|(version, hash)| cache.get(&CacheKey::value(origin, &req.shard_id, req.phase, *version, hash)))
            .collect();
        let (shard_id, phase) = (req.shard_id, req.phase);
        let values = if hits.iter().all(Option::is_some) {
            answer_batch(keys, hits, |_| None)
        } else {
            let unserved = keys.len();
            forest_read(self.forest_server.clone(), peer, move |s| {
                // A value read above the tree's head could change when that
                // version commits, so only reads at or below it are kept.
                let head = s.serve_head(&shard_id, phase).map(|(version, _)| version);
                Some(answer_batch(keys, hits, |(version, hash)| {
                    let value = s.serve_value(&shard_id, phase, *version, *hash);
                    if let Some(value) = value.as_ref().filter(|_| head.is_some_and(|head| *version <= head)) {
                        cache.put(CacheKey::value(origin, &shard_id, phase, *version, hash), value.clone());
                    }
                    value
                }))
            }).await?.unwrap_or_else(|| vec![global::ForestReadResult::default(); unserved])
        };
        Ok(Response::new(global::GetForestValuesResponse { values }))
    }

    async fn get_forest_leaves(
        &self,
        request: Request<global::GetForestLeavesRequest>,
    ) -> Result<Response<global::GetForestLeavesResponse>, Status> {
        let peer = forest_reader(request.extensions());
        let req = request.into_inner();
        let key = |bytes: &[u8], name: &str| -> Result<[u8; 32], Status> {
            bytes.try_into().map_err(|_| Status::invalid_argument(format!("{name} must be 32 bytes")))
        };
        let (first, last) = (key(&req.first, "first")?, key(&req.last, "last")?);
        let after = if req.after.is_empty() { None } else { Some(key(&req.after, "after")?) };
        let (shard_id, phase, version) = (req.shard_id, req.phase, req.version);
        let listed = forest_read(self.forest_server.clone(), peer, move |s| {
            s.serve_leaves(&shard_id, phase, version, &first, &last, after.as_ref())
        }).await?;
        let Some((leaves, more)) = listed else {
            return Err(Status::unimplemented("this archive does not list forest leaves"));
        };
        FOREST_LEAVES_LISTED.fetch_add(leaves.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(Response::new(global::GetForestLeavesResponse {
            leaves: leaves.into_iter()
                .map(|(key_hash, value)| global::ForestLeaf { key_hash: key_hash.to_vec(), value })
                .collect(),
            more,
        }))
    }

    async fn get_vertex_blobs(
        &self,
        request: Request<global::GetVertexBlobsRequest>,
    ) -> Result<Response<global::GetVertexBlobsResponse>, Status> {
        let peer = forest_reader(request.extensions());
        let req = request.into_inner();
        if req.blobs.len() > MAX_FOREST_BATCH_KEYS {
            return Err(Status::invalid_argument(format!("at most {MAX_FOREST_BATCH_KEYS} keys per request")));
        }
        let unserved = req.blobs.len();
        let hits = vec![None; req.blobs.len()];
        let (shard_key, phase, keys) = (req.shard_key, req.phase, req.blobs);
        let blobs = forest_read(self.forest_server.clone(), peer, move |s| {
            Some(answer_batch(keys, hits, |key| s.serve_vertex_blob(&shard_key, phase, &key.id, Some(key.version))))
        }).await?.unwrap_or_else(|| vec![global::ForestReadResult::default(); unserved]);
        Ok(Response::new(global::GetVertexBlobsResponse { blobs }))
    }

    async fn resolve_root(
        &self,
        request: Request<global::ResolveRootRequest>,
    ) -> Result<Response<global::ResolveRootResponse>, Status> {
        let peer = forest_reader(request.extensions());
        let req = request.into_inner();
        let root: [u8; 32] = req
            .root
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("root must be 32 bytes"))?;
        let resolved = forest_read(self.forest_server.clone(), peer, move |s| s.resolve_root(&req.shard_id, req.phase, root)).await?;
        Ok(Response::new(match resolved {
            Some((version, global_frame)) => global::ResolveRootResponse {
                found: true,
                version,
                global_frame,
            },
            None => global::ResolveRootResponse { found: false, version: 0, global_frame: 0 },
        }))
    }

    async fn get_app_manifest(
        &self,
        request: Request<global::GetAppManifestRequest>,
    ) -> Result<Response<global::GetAppManifestResponse>, Status> {
        let peer = forest_reader(request.extensions());
        let req = request.into_inner();
        let app_root: [u8; 32] = req
            .app_root
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("app_root must be 32 bytes"))?;
        let manifest = forest_read(self.forest_server.clone(), peer, move |s| s.serve_app_manifest(&req.app_address, req.phase, app_root)).await?;
        Ok(Response::new(match manifest {
            Some(entries) => global::GetAppManifestResponse {
                found: true,
                entries: entries
                    .into_iter()
                    .map(|(prefix, root, version)| global::AppManifestEntry {
                        prefix,
                        root: root.to_vec(),
                        version,
                    })
                    .collect(),
            },
            None => global::GetAppManifestResponse { found: false, entries: Vec::new() },
        }))
    }
}

/// Whether a recorded split or merge that has not applied yet names the shard
/// at `(shard_key, prefix)`. The chain refuses a join that includes such a
/// shard, so a regular node leaves it out of its join candidates.
fn frozen_by_pending_change(
    shard_key: &[u8],
    prefix: &[u32],
    pending: &[quil_types::store::PendingShardChange],
) -> bool {
    let Some(app) = shard_key.get(3..35) else { return false };
    let filter = quil_forest::shard_prefix_to_filter(app, prefix);
    pending.iter().any(|change| change.affects_shard(&filter))
}

#[cfg(test)]
mod pending_change_tests {
    use quil_types::store::{PendingShardChange, ShardChangeKind};

    // A live width run: three shards were staged to split at frame 247 and
    // flipped at 304. Every join the regular nodes proposed in between named
    // one of them, and the chain refused each whole join.
    #[test]
    fn a_shard_named_by_a_pending_split_is_reported_frozen() {
        let app = [0x21u8; 32];
        let shard_key: Vec<u8> = [0u8, 0, 0].into_iter().chain(app).collect();
        let prefix = quil_forest::bit_path_to_prefix;
        let parent = quil_forest::encode_shard_bit_path(&app, &[false, true]);
        let split = PendingShardChange {
            kind: ShardChangeKind::Split,
            parent,
            children: vec![
                quil_forest::encode_shard_bit_path(&app, &[false, true, false]),
                quil_forest::encode_shard_bit_path(&app, &[false, true, true]),
            ],
            effective_epoch: 10,
            proposed_frame: 247,
        };
        let pending = [split];
        assert!(super::frozen_by_pending_change(&shard_key, &prefix(&[false, true]), &pending));
        assert!(!super::frozen_by_pending_change(&shard_key, &prefix(&[false, false]), &pending));
        assert!(!super::frozen_by_pending_change(&shard_key, &prefix(&[false, true]), &[]));
    }
}

#[cfg(test)]
mod identity_gate_tests {
    use super::*;
    use crate::peer_auth_middleware::AuthenticatedPeer;

    struct NoopLookup;
    impl FrameLookup for NoopLookup {
        fn get_latest_frame(&self) -> Result<global::GlobalFrame, String> {
            Err("n/a".into())
        }
        fn get_frame(&self, _: u64) -> Result<global::GlobalFrame, String> {
            Err("n/a".into())
        }
        fn get_global_proposal(&self, _: u64) -> Result<global::GlobalProposal, String> {
            Err("n/a".into())
        }
    }

    fn auth_ext(peer_id: quil_p2p::PeerId) -> tonic::Extensions {
        let mut ext = tonic::Extensions::new();
        ext.insert(AuthenticatedPeer { peer_id, falcon_public_key: Vec::new() });
        ext
    }

    #[tokio::test]
    async fn archive_directory_is_bounded_and_only_served_to_own_workers() {
        let me = quil_p2p::PeerId::random();
        let pool = Arc::new(crate::ArchiveEndpointPool::new(std::time::Duration::ZERO));
        let server = GlobalRpcServer::new(Arc::new(NoopLookup))
            .with_self_peer_id(me.to_bytes()).with_archive_directory(pool.clone());
        let request = |peer| {
            let mut request = Request::new(global::GetArchiveEndpointsRequest {});
            if let Some(peer) = peer { *request.extensions_mut() = auth_ext(peer); }
            request
        };
        for peer in [None, Some(quil_p2p::PeerId::random())] {
            assert_eq!(server.get_archive_endpoints(request(peer)).await.unwrap_err().code(), tonic::Code::PermissionDenied);
        }
        assert!(server.get_archive_endpoints(request(Some(me))).await.unwrap().into_inner().endpoints.is_empty());
        pool.add(String::new()).await;
        pool.add("x".repeat(513)).await;
        for index in 0..40 { pool.add(format!("192.0.2.{}:8340", index+1)).await; }
        let endpoints = server.get_archive_endpoints(request(Some(me))).await.unwrap().into_inner().endpoints;
        assert_eq!(endpoints.len(), 32);
        assert_eq!(endpoints[0], "192.0.2.1:8340");
        assert_eq!(endpoints[31], "192.0.2.32:8340");
    }

    #[test]
    fn self_gate_allows_self_denies_others_and_missing() {
        let me = quil_p2p::PeerId::random();
        let other = quil_p2p::PeerId::random();
        let server = GlobalRpcServer::new(Arc::new(NoopLookup)).with_self_peer_id(me.to_bytes());
        // The node's own identity (its data-workers) → allowed.
        assert!(server.require_self_identity(&auth_ext(me)).is_ok());
        // A different machine's identity → denied (the security fix).
        assert!(server.require_self_identity(&auth_ext(other)).is_err());
        // Unauthenticated (no handshake identity) → denied.
        assert!(server.require_self_identity(&tonic::Extensions::new()).is_err());
    }

    #[test]
    fn no_self_peer_id_configured_is_ungated() {
        // Thread mode (workers in-process, no gRPC boundary): no gate installed,
        // so the check is a no-op.
        let server = GlobalRpcServer::new(Arc::new(NoopLookup));
        assert!(server.require_self_identity(&auth_ext(quil_p2p::PeerId::random())).is_ok());
        assert!(server.require_self_identity(&tonic::Extensions::new()).is_ok());
    }

    #[test]
    fn require_prover_honors_authorizer_and_presence() {
        // Authorizer that only accepts one specific peer (the "active prover").
        let prover = quil_p2p::PeerId::random();
        let prover_bytes = prover.to_bytes();
        let authz: Arc<dyn Fn(&AuthenticatedPeer) -> bool + Send + Sync> =
            Arc::new(move |a: &AuthenticatedPeer| a.peer_id.to_bytes() == prover_bytes);
        let server = GlobalRpcServer::new(Arc::new(NoopLookup)).with_prover_authorizer(authz);
        // active prover → allowed
        assert!(server.require_prover(&auth_ext(prover)).is_ok());
        // non-prover → denied
        assert!(server.require_prover(&auth_ext(quil_p2p::PeerId::random())).is_err());
        // unauthenticated → denied
        assert!(server.require_prover(&tonic::Extensions::new()).is_err());
        // no authorizer configured → ungated
        let ungated = GlobalRpcServer::new(Arc::new(NoopLookup));
        assert!(ungated.require_prover(&tonic::Extensions::new()).is_ok());
    }

    /// The relay sends as the node, so only the node's own identity may use
    /// it, and without a configured identity nobody may.
    #[tokio::test]
    async fn only_the_nodes_own_workers_may_relay_shard_consensus() {
        let me = quil_p2p::PeerId::random();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let relay: ShardDirectRelay = {
            let seen = seen.clone();
            Arc::new(move |filter, channel, data, recipients| {
                seen.lock().unwrap().push((filter, channel, data, recipients));
                Box::pin(async { true })
            })
        };
        let request = |caller: Option<quil_p2p::PeerId>| {
            let mut request = Request::new(global::SendShardConsensusDirectRequest {
                filter: vec![1; 32],
                channel: 2,
                data: b"response".to_vec(),
                recipients: vec![vec![5; 897]],
            });
            if let Some(caller) = caller {
                *request.extensions_mut() = auth_ext(caller);
            }
            request
        };
        let server = GlobalRpcServer::new(Arc::new(NoopLookup))
            .with_self_peer_id(me.to_bytes())
            .with_shard_direct_relay(relay.clone());
        for caller in [None, Some(quil_p2p::PeerId::random())] {
            let denied = server.send_shard_consensus_direct(request(caller)).await.unwrap_err();
            assert_eq!(denied.code(), tonic::Code::PermissionDenied);
        }
        let response = server.send_shard_consensus_direct(request(Some(me))).await.unwrap();
        assert!(response.get_ref().delivered);
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[(vec![1; 32], 2, b"response".to_vec(), vec![vec![5; 897]])]
        );
        let unconfigured = GlobalRpcServer::new(Arc::new(NoopLookup)).with_shard_direct_relay(relay);
        let denied = unconfigured.send_shard_consensus_direct(request(Some(me))).await.unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied, "no identity configured: no access");
    }

    /// Historical committees go only to the node's own workers.
    #[tokio::test]
    async fn only_the_nodes_own_workers_may_ask_for_historical_committees() {
        let me = quil_p2p::PeerId::random();
        let source: quil_engine::historical_committee::HistoricalCommitteeSource =
            Arc::new(|filter, anchor| Box::pin(async move { Ok(vec![vec![filter, anchor.to_be_bytes().to_vec()]]) }));
        let request = |caller: Option<quil_p2p::PeerId>| {
            let mut request = Request::new(global::GetHistoricalCommitteesRequest { filter: b"shard".to_vec(), anchor: 9 });
            if let Some(caller) = caller {
                *request.extensions_mut() = auth_ext(caller);
            }
            request
        };
        let server = GlobalRpcServer::new(Arc::new(NoopLookup))
            .with_self_peer_id(me.to_bytes())
            .with_historical_committees(source);
        for caller in [None, Some(quil_p2p::PeerId::random())] {
            let denied = server.get_historical_committees(request(caller)).await.unwrap_err();
            assert_eq!(denied.code(), tonic::Code::PermissionDenied);
        }
        let answer = server.get_historical_committees(request(Some(me))).await.unwrap().into_inner();
        assert_eq!(answer.committees.len(), 1);
        assert_eq!(answer.committees[0].members, vec![b"shard".to_vec(), 9u64.to_be_bytes().to_vec()]);
        let without = GlobalRpcServer::new(Arc::new(NoopLookup)).with_self_peer_id(me.to_bytes());
        assert_eq!(without.get_historical_committees(request(Some(me))).await.unwrap_err().code(), tonic::Code::Unimplemented);
    }

    /// A worker's GLOBAL submission goes out as the node, so only the node's
    /// own identity may hand one in; the node's answer (queued, held back, or
    /// refused) reaches the worker, and a node without a transport says so.
    #[tokio::test]
    async fn only_the_nodes_own_workers_may_submit_prover_messages() {
        let me = quil_p2p::PeerId::random();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let submitter: WorkerProverSubmitter = {
            let seen = seen.clone();
            Arc::new(move |core_id, request: Vec<u8>| {
                seen.lock().unwrap().push((core_id, request.clone()));
                Box::pin(async move {
                    match request.as_slice() {
                        b"halted" => Ok(false),
                        b"junk" => Err("not a worker submission".to_string()),
                        _ => Ok(true),
                    }
                })
            })
        };
        let request = |caller: Option<quil_p2p::PeerId>, body: &[u8]| {
            let mut request = Request::new(global::SubmitWorkerProverMessageRequest {
                core_id: 3,
                request: body.to_vec(),
            });
            if let Some(caller) = caller {
                *request.extensions_mut() = auth_ext(caller);
            }
            request
        };
        let server = GlobalRpcServer::new(Arc::new(NoopLookup))
            .with_self_peer_id(me.to_bytes())
            .with_worker_prover_submitter(submitter.clone());
        for caller in [None, Some(quil_p2p::PeerId::random())] {
            let denied = server.submit_worker_prover_message(request(caller, b"header")).await.unwrap_err();
            assert_eq!(denied.code(), tonic::Code::PermissionDenied);
        }
        assert!(seen.lock().unwrap().is_empty(), "a stranger's submission never reaches the transport");
        let queued = server.submit_worker_prover_message(request(Some(me), b"header")).await.unwrap();
        assert!(queued.get_ref().accepted);
        let held = server.submit_worker_prover_message(request(Some(me), b"halted")).await.unwrap();
        assert!(!held.get_ref().accepted);
        let refused = server.submit_worker_prover_message(request(Some(me), b"junk")).await.unwrap_err();
        assert_eq!(refused.code(), tonic::Code::InvalidArgument);
        assert_eq!(seen.lock().unwrap()[0], (3, b"header".to_vec()));

        let without = GlobalRpcServer::new(Arc::new(NoopLookup)).with_self_peer_id(me.to_bytes());
        let missing = without.submit_worker_prover_message(request(Some(me), b"header")).await.unwrap_err();
        assert_eq!(missing.code(), tonic::Code::Unimplemented);
        let unconfigured = GlobalRpcServer::new(Arc::new(NoopLookup)).with_worker_prover_submitter(submitter);
        let denied = unconfigured.submit_worker_prover_message(request(Some(me), b"header")).await.unwrap_err();
        assert_eq!(denied.code(), tonic::Code::PermissionDenied, "no identity configured: no access");
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
    fn proposal_only_catchup_populates_cache_and_handles_max_height() {
        let cache = CachingFrameLookup::new(
            CountingLookup::new(100), 16, std::time::Duration::from_secs(1),
        );
        cache.get_global_proposal(50).unwrap();
        cache.get_global_proposal(50).unwrap();
        assert_eq!(cache.inner.get_proposal_calls.load(Ordering::SeqCst), 1);
        assert_eq!(cache.inner.get_latest_calls.load(Ordering::SeqCst), 1);
        cache.get_global_proposal(u64::MAX).unwrap();
        cache.get_global_proposal(u64::MAX).unwrap();
        assert_eq!(cache.inner.get_proposal_calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn concurrent_cold_reads_share_store_loads() {
        struct SlowLookup(CountingLookup);
        impl FrameLookup for SlowLookup {
            fn get_latest_frame(&self) -> Result<global::GlobalFrame, String> {
                std::thread::sleep(std::time::Duration::from_millis(20));
                self.0.get_latest_frame()
            }
            fn get_frame(&self, n: u64) -> Result<global::GlobalFrame, String> {
                std::thread::sleep(std::time::Duration::from_millis(20));
                self.0.get_frame(n)
            }
            fn get_global_proposal(&self, n: u64) -> Result<global::GlobalProposal, String> {
                std::thread::sleep(std::time::Duration::from_millis(20));
                self.0.get_global_proposal(n)
            }
        }
        let cache = CachingFrameLookup::new(
            SlowLookup(CountingLookup::new(100)), 16, std::time::Duration::from_secs(10),
        );
        let start = std::sync::Barrier::new(12);
        std::thread::scope(|scope| {
            for _ in 0..12 {
                scope.spawn(|| {
                    start.wait();
                    cache.get_latest_frame().unwrap();
                    cache.get_frame(42).unwrap();
                    cache.get_global_proposal(50).unwrap();
                });
            }
        });
        assert_eq!(cache.inner.0.get_latest_calls.load(Ordering::SeqCst), 1);
        assert_eq!(cache.inner.0.get_frame_calls.load(Ordering::SeqCst), 1);
        assert_eq!(cache.inner.0.get_proposal_calls.load(Ordering::SeqCst), 1);
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

#[cfg(test)]
mod app_shards_cache_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use quil_types::store::ShardInfo;

    struct NoFrames;
    impl FrameLookup for NoFrames {
        fn get_latest_frame(&self) -> Result<global::GlobalFrame, String> { Err("unused".into()) }
        fn get_frame(&self, _: u64) -> Result<global::GlobalFrame, String> { Err("unused".into()) }
        fn get_global_proposal(&self, _: u64) -> Result<global::GlobalProposal, String> { Err("unused".into()) }
    }

    /// One shard; counts its reads, and holds each until released when gated.
    struct OneShard {
        reads: AtomicUsize,
        gate: Option<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>,
    }
    impl ShardsStore for OneShard {
        fn range_app_shards(&self) -> quil_types::error::Result<Vec<ShardInfo>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = &self.gate {
                let _ = gate.lock().unwrap().recv();
            }
            Ok(vec![ShardInfo { shard_key: vec![0; 35], prefix: vec![1], size: Vec::new(), data_shards: 0, commitment: Vec::new() }])
        }
        fn get_app_shards(&self, _: &[u8], _: &[u32]) -> quil_types::error::Result<Vec<ShardInfo>> {
            self.range_app_shards()
        }
        fn put_app_shard(&self, _: &dyn quil_types::store::Transaction, _: &ShardInfo) -> quil_types::error::Result<()> { Ok(()) }
        fn delete_app_shard(&self, _: &dyn quil_types::store::Transaction, _: &[u8], _: &[u32]) -> quil_types::error::Result<()> { Ok(()) }
    }

    async fn ask(server: Arc<GlobalRpcServer>) -> Result<Vec<global::AppShardInfo>, Status> {
        server
            .get_app_shards(Request::new(global::GetAppShardsRequest { shard_key: vec![0; 35], prefix: vec![1] }))
            .await
            .map(|r| r.into_inner().info)
    }

    /// Reports `size` as the shard's size; the test moves it between calls.
    fn sized(size: Arc<AtomicU64>) -> AppShardsProvider {
        Arc::new(move |_, _| {
            let size = size.load(Ordering::SeqCst);
            Some((size.to_be_bytes().to_vec(), 1, std::array::from_fn(|_| vec![0; 64]), 3, 4))
        })
    }

    // Every prover polls GetAppShards. Its shard rows change only when a
    // GLOBAL frame commits, so they are read once per committed frame; sizes
    // and frame progress move with every application frame and are read for
    // every request.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shard_rows_are_read_once_per_committed_frame_and_sizes_every_time() {
        let store = Arc::new(OneShard { reads: AtomicUsize::new(0), gate: None });
        let (committed, size) = (Arc::new(AtomicU64::new(5)), Arc::new(AtomicU64::new(10)));
        let version = committed.clone();
        let server = Arc::new(GlobalRpcServer::new(Arc::new(NoFrames))
            .with_shards_store(store.clone())
            .with_app_shards_provider(sized(size.clone()))
            .with_app_shards_version(Arc::new(move || Some(version.load(Ordering::SeqCst)))));
        for expected in [10u64, 11, 12] {
            size.store(expected, Ordering::SeqCst);
            assert_eq!(ask(server.clone()).await.unwrap()[0].size, expected.to_be_bytes().to_vec());
        }
        assert_eq!(store.reads.load(Ordering::SeqCst), 1);
        committed.store(6, Ordering::SeqCst);
        ask(server.clone()).await.unwrap();
        ask(server.clone()).await.unwrap();
        assert_eq!(store.reads.load(Ordering::SeqCst), 2, "read again once the committed frame moves");

        let unversioned = Arc::new(OneShard { reads: AtomicUsize::new(0), gate: None });
        let server = Arc::new(GlobalRpcServer::new(Arc::new(NoFrames))
            .with_shards_store(unversioned.clone())
            .with_app_shards_provider(sized(size)));
        ask(server.clone()).await.unwrap();
        ask(server).await.unwrap();
        assert_eq!(unversioned.reads.load(Ordering::SeqCst), 2, "no committed frame known: read every time");
    }

    // Post-split, each answer took minutes and every prover kept asking; each
    // retry started another copy of the work until the archives' CPUs were
    // spent and GLOBAL stopped proposing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_and_abandoned_callers_share_one_read() {
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let store = Arc::new(OneShard { reads: AtomicUsize::new(0), gate: Some(std::sync::Mutex::new(release_rx)) });
        let server = Arc::new(GlobalRpcServer::new(Arc::new(NoFrames))
            .with_shards_store(store.clone())
            .with_app_shards_provider(sized(Arc::new(AtomicU64::new(7))))
            .with_app_shards_version(Arc::new(|| Some(9))));
        let first = tokio::spawn(ask(server.clone()));
        while store.reads.load(Ordering::SeqCst) == 0 { tokio::task::yield_now().await; }
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        let waiting: Vec<_> = (0..8).map(|_| tokio::spawn(ask(server.clone()))).collect();
        release_tx.send(()).unwrap();
        for caller in waiting {
            let info = tokio::time::timeout(std::time::Duration::from_secs(5), caller)
                .await.unwrap().unwrap().unwrap();
            assert_eq!(info[0].size, 7u64.to_be_bytes().to_vec());
        }
        assert_eq!(store.reads.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
mod forest_read_tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_keeps_storage_slot_and_runtime_responsive() {
        static WORKERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        // Dropping release_tx also releases the worker on assertion failure.
        let caller = tokio::spawn(bounded_forest_read(&WORKERS, std::time::Duration::ZERO, None, move || {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
        }));
        tokio::time::timeout(std::time::Duration::from_secs(5), started_rx)
            .await.unwrap().unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert_eq!(bounded_forest_read(&WORKERS, std::time::Duration::ZERO, None, || ()).await.unwrap_err().code(),
            tonic::Code::ResourceExhausted);
        release_tx.send(()).unwrap();
        let permit = tokio::time::timeout(std::time::Duration::from_secs(5), WORKERS.acquire())
            .await.unwrap().unwrap();
        drop(permit);
        assert_eq!(bounded_forest_read(&WORKERS, std::time::Duration::ZERO, None, || 42).await.unwrap(), 42);
    }

    /// A read waits briefly for a slot instead of being refused at once, and
    /// one peer holds at most its share of the slots.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reads_queue_briefly_and_each_peer_holds_a_bounded_share() {
        static WORKERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let holder = tokio::spawn(bounded_forest_read(&WORKERS, std::time::Duration::ZERO, None, move || {
            let _ = release_rx.recv();
        }));
        while WORKERS.available_permits() > 0 {
            tokio::task::yield_now().await;
        }
        let queued = tokio::spawn(bounded_forest_read(&WORKERS, std::time::Duration::from_secs(5), None, || 7));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        release_tx.send(()).unwrap();
        holder.await.unwrap().unwrap();
        assert_eq!(queued.await.unwrap().unwrap(), 7, "a queued read runs once a slot frees");
        let timed_out = bounded_forest_read(&WORKERS, std::time::Duration::from_millis(1), None, || ());
        let held = WORKERS.try_acquire().unwrap();
        assert_eq!(timed_out.await.unwrap_err().code(), tonic::Code::ResourceExhausted);
        drop(held);

        let peer = b"one syncing peer".to_vec();
        let slots: Vec<_> = (0..FOREST_READ_SLOTS_PER_PEER)
            .map(|_| PeerSlot::take(Some(peer.clone()), FOREST_READ_SLOTS_PER_PEER).unwrap())
            .collect();
        assert_eq!(
            PeerSlot::take(Some(peer.clone()), FOREST_READ_SLOTS_PER_PEER).err().unwrap().code(),
            tonic::Code::ResourceExhausted,
        );
        assert!(PeerSlot::take(Some(b"another peer".to_vec()), FOREST_READ_SLOTS_PER_PEER).is_ok());
        drop(slots);
        assert!(PeerSlot::take(Some(peer), FOREST_READ_SLOTS_PER_PEER).is_ok(), "released on drop");
    }

    /// A batch answers a prefix in order, stopping at the byte budget, with
    /// cached entries served as found.
    #[test]
    fn a_batch_answers_a_prefix_within_its_byte_budget() {
        let keys: Vec<u32> = (0..5).collect();
        let hits = vec![None, Some(Arc::new(vec![1u8; 3])), None, None, None];
        let out = answer_batch(keys, hits, |key| match key {
            2 => None,
            _ => Some(vec![0u8; MAX_FOREST_BATCH_BYTES / 2]),
        });
        assert_eq!(out.len(), 4, "the fifth key is past the budget");
        assert!(out[0].found && out[1].found && !out[2].found && out[3].found);
        assert_eq!(out[1].data, vec![1u8; 3]);
        let one = answer_batch(vec![0u32], vec![None], |_| Some(vec![0u8; MAX_FOREST_BATCH_BYTES * 2]));
        assert_eq!(one.len(), 1, "a single oversized entry is still answered");
    }
}

#[cfg(test)]
mod historical_proof_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct EmptyLookup;
    impl FrameLookup for EmptyLookup {
        fn get_latest_frame(&self) -> Result<global::GlobalFrame, String> { Err("unused".into()) }
        fn get_frame(&self, _: u64) -> Result<global::GlobalFrame, String> { Err("unused".into()) }
        fn get_global_proposal(&self, _: u64) -> Result<global::GlobalProposal, String> { Err("unused".into()) }
    }

    #[tokio::test]
    async fn historical_proof_forwarding_is_bounded_one_hop_and_root_verified() {
        let address = [9;32];
        let tree = quil_execution::global_intrinsic::materialize::create_leaf_root_vertex_tree(
            &[7;32], &[8;32], &[], 11, &[1;74], 1, 330,
        ).unwrap();
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        let forest = quil_forest::Forest::in_memory();
        let root = forest.commit_shard_phase_raw(&[0xff;32], quil_forest::Phase::VertexAdds, 0,
            vec![(address.to_vec(), quil_tries::vertex_leaf_value(&blob).unwrap())]).unwrap();
        let vertex: Vec<_> = [0xff;32].into_iter().chain(address).collect();
        let bytes = quil_forest::MembershipProof { inputs:vec![forest.build_vertex_membership_proof(
            &[0xff;32], quil_forest::Phase::VertexAdds, 0, &vertex, &blob,
        ).unwrap()] }.to_bytes();
        let calls = Arc::new(AtomicUsize::new(0));
        let source = {
            let calls = calls.clone();
            let bytes = bytes.clone();
            Arc::new(move |_: [u8;32], _: [u8;32]| {
                calls.fetch_add(1, Ordering::SeqCst);
                let bytes = bytes.clone();
                Box::pin(async move { Ok(Some(bytes)) }) as std::pin::Pin<Box<dyn std::future::Future<Output=quil_types::error::Result<Option<Vec<u8>>>> + Send>>
            }) as quil_engine::storage_history::GlobalVertexProofSource
        };
        let server = GlobalRpcServer::new(Arc::new(EmptyLookup)).with_global_vertex_proof_source(Some(source));
        let request = |root: Vec<u8>, address: Vec<u8>, allow_forward| Request::new(global::GetGlobalVertexProofRequest { root, address, allow_forward });
        let missing = server.get_global_vertex_proof(request(root.to_vec(), address.to_vec(), false)).await.unwrap().into_inner();
        assert!(!missing.found);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(server.get_global_vertex_proof(request(vec![0;31], address.to_vec(), true)).await.unwrap_err().code(), tonic::Code::InvalidArgument);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let valid = server.get_global_vertex_proof(request(root.to_vec(), address.to_vec(), true)).await.unwrap().into_inner();
        assert!(valid.found);
        assert_eq!(valid.proof, bytes);
        assert_eq!(server.get_global_vertex_proof(request(vec![0;32], address.to_vec(), true)).await.unwrap_err().code(), tonic::Code::DataLoss);
        assert_eq!(server.get_global_vertex_proof(request(root.to_vec(), vec![0;32], true)).await.unwrap_err().code(), tonic::Code::DataLoss);
        let held: Vec<_> = (0..4).map(|_| HISTORY_FORWARD_WORKERS.try_acquire().unwrap()).collect();
        let before = calls.load(Ordering::SeqCst);
        assert_eq!(server.get_global_vertex_proof(request(root.to_vec(), address.to_vec(), true)).await.unwrap_err().code(), tonic::Code::ResourceExhausted);
        assert_eq!(calls.load(Ordering::SeqCst), before);
        drop(held);
        let unavailable = GlobalRpcServer::new(Arc::new(EmptyLookup)).with_global_vertex_proof_source(Some(
            Arc::new(|_, _| Box::pin(async { Err(quil_types::error::QuilError::ExecutionUnavailable("pruned".into())) })),
        ));
        assert_eq!(unavailable.get_global_vertex_proof(request(root.to_vec(), address.to_vec(), true)).await.unwrap_err().code(), tonic::Code::Unavailable);
    }
}

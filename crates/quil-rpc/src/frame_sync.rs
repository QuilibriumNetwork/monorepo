//! Forward global-frame poller for non-archive nodes.
//!
//! Mirrors `node/consensus/global/message_processors.go:pollFramesFromArchive`:
//! a non-archive master does NOT walk the chain backwards. Instead it picks
//! one archive node (one that advertises `ArchiveServiceCapabilityID = 0x00050001`
//! in its PeerInfo capabilities) and polls `GlobalService.GetGlobalFrame(0)`
//! every second. When the head advances, any missed frames in between are
//! pulled forward in order, then the new head is processed.
//!
//! What this module is *not*:
//! - Not a backward chain walker. Non-archive nodes don't store full history.
//! - Not the prover tree syncer. That's `HypergraphComparisonService.PerformSync`,
//! which is a 4-phase CRDT walk and lives in a separate module (TBD).
//!
//! Architecture mirror:
//! - Go: `pollFramesFromArchive` (lines 2161-2231)
//! - Go discovery: `tryDiscoverArchiveEndpoint` (lines 2237-2335)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;
use tokio::sync::{Mutex, Notify};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use quil_store::RocksClockStore;
use quil_types::proto::global::GlobalFrame;

use crate::archive_client::{ArchiveClient, ArchiveClientError};

#[derive(Debug, Error)]
pub enum FrameSyncError {
    #[error("no working archive endpoint")]
    NoEndpoint,
}

/// Cooperative pool of *archive-capable* peer endpoints. The poller picks
/// one as its current source and only switches when that source fails.
///
/// Endpoints are added by the BlossomSub PeerInfo handler whenever it
/// decodes a record whose `capabilities` list contains
/// `ARCHIVE_SERVICE_CAPABILITY_ID`. Plain "stream multiaddr" entries from
/// non-archive peers must NOT be added here — they will reject every
/// `GetGlobalFrame` call with "not currently syncable".
pub struct ArchiveEndpointPool {
    inner: Mutex<ArchiveEndpointPoolInner>,
    notify: Notify,
    /// How long a blacklisted endpoint stays banned before becoming
    /// eligible again. Short enough that transient network blips don't
    /// permanently drain the pool, long enough that we don't hammer a
    /// struggling endpoint into the ground. A value of `Duration::ZERO`
    /// disables blacklisting entirely: a failed endpoint's entry is
    /// instantly expired, so it is restored on the very next `next()` and
    /// re-accepted by `add()` — used where instant partition recovery
    /// matters more than backing off a struggling peer.
    blacklist_ttl: Duration,
}

struct ArchiveEndpointPoolInner {
    /// ALL known archive endpoints, in arrival order — once added, an
    /// endpoint is NEVER removed. This is the set the consensus publisher
    /// fans out to (`get_all`), so dropping an endpoint here would silently
    /// stop delivering consensus to a committee member on a transient
    /// connect failure (which, with a flaky :8340 mesh, collapses the
    /// quorum). The poller's "next" pointer rotates through this list,
    /// skipping currently-blacklisted entries for frame-polling only.
    endpoints: Vec<String>,
    /// Endpoints that have failed recently — a SKIP HINT for the poller's
    /// round-robin only; it does NOT remove them from `endpoints`. Each
    /// entry records the instant of the most recent failure; entries older
    /// than `blacklist_ttl` are eligible to be retried.
    blacklist: HashMap<String, Instant>,
    /// Index into `endpoints` for the next pick.
    cursor: usize,
}

impl ArchiveEndpointPool {
    /// Build a pool with the given blacklist TTL. `Duration::ZERO` disables
    /// blacklisting (see the `blacklist_ttl` field). The production default
    /// lives in `quil-config` (`EngineConfig::archive_blacklist_ttl_secs`),
    /// not here — every caller passes an explicit TTL.
    pub fn new(blacklist_ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(ArchiveEndpointPoolInner {
                endpoints: Vec::new(),
                blacklist: HashMap::new(),
                cursor: 0,
            }),
            notify: Notify::new(),
            blacklist_ttl,
        }
    }

    /// Add an archive endpoint if it isn't already known or currently
    /// blacklisted. An endpoint whose blacklist entry has expired is
    /// accepted (the entry is dropped) — that's how recovery from a
    /// transient outage flows back through `add()` after PeerInfo
    /// re-advertises the same address.
    pub async fn add(&self, endpoint: String) {
        let mut inner = self.inner.lock().await;
        if let Some(ts) = inner.blacklist.get(&endpoint) {
            if ts.elapsed() < self.blacklist_ttl {
                return;
            }
            inner.blacklist.remove(&endpoint);
        }
        if inner.endpoints.contains(&endpoint) {
            return;
        }
        info!(%endpoint, total = inner.endpoints.len() + 1, "archive endpoint added");
        inner.endpoints.push(endpoint);
        drop(inner);
        self.notify.notify_waiters();
    }

    pub async fn len(&self) -> usize {
        self.inner.lock().await.endpoints.len()
    }

    /// Get all current archive endpoints (for submitting prover messages).
    pub async fn get_all(&self) -> Vec<String> {
        self.inner.lock().await.endpoints.clone()
    }

    /// Pick the next non-blacklisted endpoint round-robin. Returns `None` if
    /// the pool is empty. Opportunistically restores endpoints whose
    /// blacklist entry has aged past `blacklist_ttl`, so a temporarily
    /// dead archive can be retried without waiting for PeerInfo
    /// re-discovery. With a zero TTL every entry is immediately eligible,
    /// so a failed endpoint returns to rotation on the next call.
    pub async fn next(&self) -> Option<String> {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();
        let expired: Vec<String> = inner
            .blacklist
            .iter()
            .filter(|(_, ts)| now.duration_since(**ts) >= self.blacklist_ttl)
            .map(|(e, _)| e.clone())
            .collect();
        for e in expired {
            inner.blacklist.remove(&e);
            if !inner.endpoints.contains(&e) {
                debug!(endpoint = %e, "restoring expired-blacklist endpoint");
                inner.endpoints.push(e);
            }
        }
        if inner.endpoints.is_empty() {
            return None;
        }
        let len = inner.endpoints.len();
        let start = inner.cursor;
        for i in 0..len {
            let idx = (start + i) % len;
            let candidate = inner.endpoints[idx].clone();
            if !inner.blacklist.contains_key(&candidate) {
                inner.cursor = (idx + 1) % len;
                return Some(candidate);
            }
        }
        None
    }

    async fn blacklist(&self, endpoint: &str) {
        let mut inner = self.inner.lock().await;
        // Record the failure so the poller's `next()` round-robin skips this
        // endpoint for frame-polling until the TTL expires. Do NOT remove it
        // from `endpoints`: it stays in the consensus fan-out set (`get_all`)
        // and is never pruned — a transient poll failure must not drop a
        // committee member from consensus delivery.
        inner.blacklist.insert(endpoint.to_string(), Instant::now());
        debug!(%endpoint, "blacklisted archive endpoint");
    }

    /// Wait until at least one endpoint is available. Used at startup so the
    /// poller can block instead of spinning until PeerInfo discovery feeds
    /// it — and by the far-behind state-jump (in `quil-node`) so it never
    /// no-ops on an empty pool during early-boot discovery.
    pub async fn wait_nonempty(&self, cancel: &CancellationToken) {
        loop {
            if self.len().await > 0 {
                return;
            }
            tokio::select! {
                _ = self.notify.notified() => {}
                _ = cancel.cancelled() => return,
            }
        }
    }
}

/// Callback invoked for each frame after it's stored. The poller
/// calls this with the `GlobalFrame` proto — wiring the execution
/// pipeline in here enables a read-only node to process frames as
/// they arrive.
pub type OnFrameCallback = Arc<dyn Fn(&GlobalFrame) + Send + Sync>;

/// Validates a frame BEFORE it is persisted. Returns `true` to accept
/// (store + fire `on_frame`), `false` to drop. Wired from the node's
/// genesis-prover allowlist + VDF/BLS `GlobalFrameVerifier` so the
/// archive-poll path gates identically to the gossip `GLOBAL_FRAME`
/// handler — a forged frame served by a peer archive is dropped, never
/// stored and never fired to `on_frame`. `None` disables the gate
/// (e.g. a trusted/test caller).
pub type FrameValidator = Arc<dyn Fn(&GlobalFrame) -> bool + Send + Sync>;

/// Async hook the poller invokes when a NON-ARCHIVE node finds itself far behind
/// an endpoint's head at RUNTIME (gap ≥ [`STATE_JUMP_RUNTIME_GAP`]). The argument
/// is the network head just observed; the hook runs a best-effort state-jump
/// (hypersync to a recent target) and returns the synced frame number, or `None`
/// if no jump completed. On `Some(n)` the poller fast-forwards `last_frame` to `n`
/// instead of forward-filling (and re-materializing) the whole gap. Boot-time
/// far-behind is handled separately by [`ArchivePollerConfig::startup_barrier`].
pub type FarBehindJump = Arc<
    dyn Fn(u64, CancellationToken) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<u64>> + Send>>
        + Send
        + Sync,
>;

/// Runtime far-behind threshold: when a non-archive poller sees an endpoint whose
/// head is at least this many frames beyond the poller's `last_frame` MID-RUN, it
/// invokes [`FarBehindJump`] to snapshot-jump near head rather than forward-fill
/// the entire gap. Set comfortably above `STATE_JUMP_MIN_GAP` (the boot gate) so
/// normal small lag never triggers a jump — and a jump lands near head, so the
/// post-jump gap is small and cannot immediately re-trigger.
pub const STATE_JUMP_RUNTIME_GAP: u64 = 2_000;

/// Shared "gossip is delivering the head" signal, written by the gossip
/// `GLOBAL_FRAME` receive path and read by the poller.
///
/// Once regular nodes subscribe to the `GLOBAL_FRAME` gossip topic, finalized
/// frames arrive over the mesh — the same frames the RPC poller fetches. When
/// gossip keeps the head current, the poller's per-second `GetGlobalFrame(0)`
/// call is pure redundant RPC. This tracker lets the poller *back off* while
/// gossip is fresh and resume polling (as a gap-filler) only when the mesh goes
/// quiet, which is the whole point of the gossip-for-global-frames path.
///
/// Non-archive only: archives forward-fill contiguous history and cannot trust
/// unordered/lossy gossip to fill gaps, so their poller ignores this signal.
pub struct GossipFreshness {
    base: Instant,
    /// Millis-since-`base` of the last gossip-delivered frame; 0 = none yet.
    last_millis: std::sync::atomic::AtomicU64,
    /// Highest frame number seen over gossip.
    last_frame: std::sync::atomic::AtomicU64,
    /// Highest global head advertised by a signed, genesis-verified archive
    /// PeerInfo. This is an AUTHENTICATED "network head" hint (PeerInfo is signed
    /// by the archive) that lets the poller answer "am I behind?" for free — the
    /// reconcile only re-pulls when an archive advertises a head above ours,
    /// instead of fetching a full head frame over RPC every interval. 0 = none
    /// seen yet (⇒ don't trust it; fall back to an RPC head-poll).
    network_head: std::sync::atomic::AtomicU64,
}

impl GossipFreshness {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            base: Instant::now(),
            last_millis: std::sync::atomic::AtomicU64::new(0),
            last_frame: std::sync::atomic::AtomicU64::new(0),
            network_head: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Record that a frame was just delivered over gossip. Called from the
    /// `GLOBAL_FRAME` receive path after a successful store.
    ///
    /// Freshness tracks head ADVANCEMENT, not mere arrival: we only refresh the
    /// timestamp when this frame raises the gossip head. Otherwise an attacker
    /// re-broadcasting a single valid, already-finalized OLD frame could keep
    /// `fresh_within` permanently true without the head moving — pinning the
    /// poller in its gossip-paused branch and (combined with a stale
    /// `network_head` under eclipse) suppressing the RPC reconcile indefinitely.
    /// Tying freshness to advancement means a stalled/replayed head lets
    /// `fresh_within` lapse after the window, and the poller falls back to RPC.
    pub fn stamp(&self, frame_number: u64) {
        let prev = self
            .last_frame
            .fetch_max(frame_number, std::sync::atomic::Ordering::Relaxed);
        if frame_number > prev {
            // Store 1-based millis so a stamp at elapsed==0 is distinguishable
            // from the "never stamped" sentinel (0).
            self.last_millis.store(
                (self.base.elapsed().as_millis() as u64).saturating_add(1),
                std::sync::atomic::Ordering::Relaxed,
            );
        }
    }

    /// Highest frame number ever delivered over gossip.
    pub fn head(&self) -> u64 {
        self.last_frame.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record a network head advertised by a signed, genesis-verified archive
    /// PeerInfo. Called from the PeerInfo receive path.
    pub fn note_network_head(&self, frame_number: u64) {
        self.network_head
            .fetch_max(frame_number, std::sync::atomic::Ordering::Relaxed);
    }

    /// Highest authenticated network head seen via archive PeerInfo (0 = none).
    pub fn network_head(&self) -> u64 {
        self.network_head.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// True if a gossip frame landed within the last `window`.
    pub fn fresh_within(&self, window: Duration) -> bool {
        let last = self.last_millis.load(std::sync::atomic::Ordering::Relaxed);
        if last == 0 {
            return false; // never stamped
        }
        let last = last - 1; // undo the 1-based offset from `stamp`
        let now = self.base.elapsed().as_millis() as u64;
        now.saturating_sub(last) < window.as_millis() as u64
    }
}

/// Poller configuration. Defaults match Go's `pollFramesFromArchive`.
pub struct ArchivePollerConfig {
    pub poll_interval: Duration,
    pub call_timeout: Duration,
    /// When set (non-archive nodes), the poller skips its RPC head-fetch while
    /// gossip is keeping the head fresh, polling only as a gap-filler when the
    /// mesh goes quiet — plus a periodic reconcile poll as a safety net. `None`
    /// (the default / archives) → always poll.
    pub gossip_freshness: Option<Arc<GossipFreshness>>,
    /// Optional callback fired for each frame after storage.
    pub on_frame: Option<OnFrameCallback>,
    /// Optional genesis-prover + VDF/BLS gate applied to every frame
    /// BEFORE it is stored. Frames failing this check are dropped
    /// (not stored, `on_frame` not fired), mirroring the gossip
    /// `GLOBAL_FRAME` handler's drop-before-store semantics.
    pub frame_validator: Option<FrameValidator>,
    /// When true, the poller forward-fills every missed frame
    /// between the previously-seen head and the current head — the
    /// archive case where retaining full history is the point.
    /// When false (typical operator), the poller jumps straight to
    /// `head` on each tick: catching up on hundreds of thousands of
    /// genesis-to-tip frames just to start processing the latest
    /// state is wasted bandwidth, and the prover-tree sync provides
    /// the registry view we actually need.
    pub forward_fill: bool,
    /// Optional one-shot barrier the poller awaits (after endpoint discovery,
    /// before reading its starting cursor). Used by the far-behind archive
    /// state-jump: the jump fast-forwards the clock head, and the poller must
    /// not read its `last_frame` — nor start forward-filling — until the jump
    /// has committed, or it would replay (re-materialize) frames the jump
    /// already synced. `None` = no wait.
    pub startup_barrier: Option<tokio::sync::oneshot::Receiver<()>>,
    /// Optional runtime far-behind rescue (non-archive). When the poller falls
    /// ≥ [`STATE_JUMP_RUNTIME_GAP`] behind an endpoint's head AFTER startup, it
    /// invokes this hook to snapshot-jump near head instead of forward-filling
    /// the whole gap. `None` (default / archives) → always forward-fill. See
    /// [`FarBehindJump`].
    pub far_behind_jump: Option<FarBehindJump>,
}

impl Default for ArchivePollerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(1),
            call_timeout: Duration::from_secs(30),
            gossip_freshness: None,
            on_frame: None,
            frame_validator: None,
            forward_fill: false,
            startup_barrier: None,
            far_behind_jump: None,
        }
    }
}

/// The single fetch surface [`run_archive_poller`] needs from its remote
/// source: `GetGlobalFrame(n)`, with `0` meaning "latest head". Extracted
/// from [`ArchiveClient`] so tests can inject an in-process fake source and
/// drive the poller loop deterministically (see the `forward_fill_repro`
/// tests); production goes through the impl below over the real mTLS client.
#[tonic::async_trait]
pub trait PollerFrameSource: Send {
    async fn get_global_frame(
        &mut self,
        frame_number: u64,
    ) -> Result<GlobalFrame, ArchiveClientError>;
}

#[tonic::async_trait]
impl PollerFrameSource for ArchiveClient {
    async fn get_global_frame(
        &mut self,
        frame_number: u64,
    ) -> Result<GlobalFrame, ArchiveClientError> {
        ArchiveClient::get_global_frame(self, frame_number).await
    }
}

/// Long-running task that polls a chosen archive endpoint for the current
/// head, and forward-fills any gap from the previously seen head. The
/// returned future runs until `cancel` fires; callers register it with
/// their supervisor (e.g. `sup.spawn(...)`) so a panic propagates.
pub async fn run_archive_poller(
    pool: Arc<ArchiveEndpointPool>,
    clock_store: Arc<RocksClockStore>,
    falcon_signing_key: Vec<u8>,
    config: ArchivePollerConfig,
    cancel: CancellationToken,
) {
    run_archive_poller_with_connector(pool, clock_store, config, cancel, move |addr: String| {
        let key = falcon_signing_key.clone();
        async move { ArchiveClient::connect_mtls(&addr, &key).await }
    })
    .await
}

/// Generic core of [`run_archive_poller`]: identical loop, with the remote
/// source injectable via `connect` (production passes a closure over
/// `ArchiveClient::connect_mtls`; tests pass an in-process fake). Kept
/// crate-private — the mTLS wrapper above is the public entry point.
pub(crate) async fn run_archive_poller_with_connector<S, F, C>(
    pool: Arc<ArchiveEndpointPool>,
    clock_store: Arc<RocksClockStore>,
    mut config: ArchivePollerConfig,
    cancel: CancellationToken,
    connect: C,
) where
    S: PollerFrameSource,
    C: Fn(String) -> F,
    F: std::future::Future<Output = Result<S, ArchiveClientError>>,
{
    info!("archive frame poller started");
    pool.wait_nonempty(&cancel).await;
    if cancel.is_cancelled() {
        return;
    }
    // Wait for the far-behind state-jump (if any) to commit its fast-forward
    // before reading our starting cursor — otherwise we'd forward-fill from the
    // pre-jump head and re-materialize frames the jump already synced.
    if let Some(barrier) = config.startup_barrier.take() {
        info!("archive poller: waiting for state-jump barrier before forward-fill");
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = barrier => {}
        }
    }

    // Reuse a single client for as long as it works AND it keeps us moving
    // forward. Switch endpoints on an RPC failure OR when an endpoint stops
    // being ahead of us (see the no-progress handling below).
    let mut current_client: Option<(String, S)> = None;
    // Use the local store's latest as our starting "last seen", so a
    // restart doesn't re-fetch frames we already have.
    let mut last_frame: u64 = clock_store.get_latest_frame_number().unwrap_or(0);
    // Consecutive ticks where the current endpoint was not ahead of us. The
    // pool can contain endpoints that are behind, at our height, or even THIS
    // node itself (the mainnet genesis static-IP pool includes self). Latching
    // onto such an endpoint used to wedge catch-up silently forever — we never
    // rotated on no-progress, only on error. After a few no-progress ticks we
    // rotate to keep searching for an endpoint that IS ahead.
    let mut no_progress: u32 = 0;
    const NO_PROGRESS_ROTATE_THRESHOLD: u32 = 3;
    // Back off between no-progress polls. `poll_interval` is 1s (tuned for
    // catch-up throughput while advancing); hammering the head every 1s — and
    // reconnecting on every rotation — when there's nothing new would be a
    // reconnect storm onto the shared :8340 path. When not advancing, poll far
    // more slowly.
    const NO_PROGRESS_BACKOFF: Duration = Duration::from_secs(5);
    // Throttled liveness heartbeat so a not-advancing poller is diagnosable
    // without enabling debug logs (previously it was completely silent).
    let mut last_heartbeat = tokio::time::Instant::now();
    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);

    // Unfillable-gap detection for forward-fill. A single frame that NO
    // committee archive will ever serve — e.g. a hole left when the whole
    // archive fleet was restarted together and the re-bootstrapped chain
    // never produced that number — otherwise wedges catch-up FOREVER: the
    // loop breaks at `bad`, rotates endpoints, and retries `bad` every 5s
    // against peer after peer, all returning NotFound, never advancing past
    // it. We track the stuck frame and the DISTINCT endpoints that have
    // returned NotFound for it; once enough distinct archives agree it's
    // missing AND the network head is well beyond it (so it's not merely
    // "not produced yet"), we abandon it — advance `last_frame` past the
    // hole so catch-up proceeds to the frames that DO exist. Only a genuine
    // `NotFound` counts; transient errors/timeouts never trip the skip.
    let mut stall_frame: Option<u64> = None;
    let mut stall_endpoints: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    // Distinct archives that served a frame at the stuck height which FAILED
    // validation (forged, or — the real case — a legacy pre-migration frame
    // whose VDF/allowlist can never pass under the new chain). Tracked apart
    // from `stall_endpoints` (NotFound) because it's a different failure mode,
    // but it trips the same skip: if enough distinct honest archives all serve
    // an unvalidatable frame at the same height with the head far past, no peer
    // will ever serve a valid one, so the gap must be abandoned to make
    // progress rather than looping "failed validation — rotating" forever.
    let mut stall_invalid_endpoints: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    // Distinct archives that must independently report NotFound for the same
    // frame before we treat it as a permanent hole.
    const UNFILLABLE_DISTINCT_ENDPOINTS: usize = 3;
    // The head must be at least this far past the stuck frame before we skip
    // it — a recently-produced frame that's briefly unavailable is served by
    // its producer within a few frames, so a large lag means "permanent".
    const UNFILLABLE_HEAD_MARGIN: u64 = 16;
    // Most frames a single tick will forward-fill before yielding back to the
    // loop (and its cancellation check). Well above the achievable rate — each
    // frame is a serial round-trip — so this bounds worst-case tick duration
    // without throttling catch-up.
    const MAX_FORWARD_FILL_PER_TICK: u64 = 512;

    let mut ticker = tokio::time::interval(config.poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Gossip-driven RPC reduction (wired on non-archive nodes only — the caller
    // passes `gossip_freshness: Some` there and `None` for archives). While the
    // `GLOBAL_FRAME` mesh keeps delivering the head, the receive path has
    // already stored (and processed) each finalized frame, so the poller sources
    // those frames from the LOCAL STORE instead of re-fetching them over RPC, and
    // skips its `GetGlobalFrame(0)` head-poll entirely. It still fills genuine
    // holes (frames gossip dropped) over RPC — contiguity is preserved for the
    // ρ_N storage anchors — and forces a reconcile head-poll every
    // `GOSSIP_RECONCILE_INTERVAL` so a silently-diverged node re-anchors. When
    // gossip goes quiet for `GOSSIP_FRESH_WINDOW` (a few frame intervals) the
    // poller resumes full RPC polling as the fallback.
    const GOSSIP_FRESH_WINDOW: Duration = Duration::from_secs(30);
    const GOSSIP_RECONCILE_INTERVAL: Duration = Duration::from_secs(120);
    const GOSSIP_IDLE_BACKOFF: Duration = Duration::from_secs(5);
    // Hard wall-clock bound on authenticated archive contact: even when gossip
    // looks fresh AND PeerInfo says we're current, force a real RPC head-poll at
    // least this often. Defense-in-depth so no combination of a stalled/replayed
    // gossip head and a stale/withheld `network_head` (an eclipse) can suppress
    // archive contact indefinitely — the poller re-verifies against the mTLS
    // source on a fixed cadence regardless.
    const HARD_RECONCILE_INTERVAL: Duration = Duration::from_secs(600);
    // Start "due" so the first tick always polls (establishes the endpoint and a
    // baseline head before ceding to gossip).
    let mut last_rpc_poll = tokio::time::Instant::now()
        .checked_sub(GOSSIP_RECONCILE_INTERVAL)
        .unwrap_or_else(tokio::time::Instant::now);
    // Time of the last ACTUAL RPC head-poll (distinct from `last_rpc_poll`, which
    // also resets when a reconcile is satisfied cheaply from PeerInfo).
    let mut last_actual_rpc = tokio::time::Instant::now()
        .checked_sub(HARD_RECONCILE_INTERVAL)
        .unwrap_or_else(tokio::time::Instant::now);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {}
        }

        // Gossip is carrying the head: drain the frames it already stored, over
        // the local store (zero RPC), and only drop into the RPC path below if a
        // hole is found or a reconcile is due. Checked before client acquisition
        // so a fully-gossip-fed poller never even connects to :8340.
        if let Some(gf) = config.gossip_freshness.clone() {
            let reconcile_due = last_rpc_poll.elapsed() >= GOSSIP_RECONCILE_INTERVAL;
            // Cheap, RPC-free "am I behind?" check. `network_head` is the highest
            // head advertised by a signed, genesis-verified archive PeerInfo, so
            // it authenticates the network height without fetching a full head
            // frame. When it confirms we're not behind, a reconcile poll would
            // only re-confirm what PeerInfo already told us — so satisfy the
            // reconcile from PeerInfo instead of an RPC. Only when PeerInfo is
            // unavailable (0) or shows an archive genuinely ahead do we spend the
            // RPC. (Gossip going quiet is handled below — `fresh_within` fails and
            // we fall through to a real poll, preserving the partition backstop.)
            let net_head = gf.network_head();
            let current_per_peerinfo = net_head > 0 && net_head <= last_frame;
            // Hard bound overrides the cheap PeerInfo skip: guarantees periodic
            // authenticated archive contact even under an eclipse.
            let hard_due = last_actual_rpc.elapsed() >= HARD_RECONCILE_INTERVAL;
            let reconcile_needs_rpc = (reconcile_due && !current_per_peerinfo) || hard_due;
            if gf.fresh_within(GOSSIP_FRESH_WINDOW) && !reconcile_needs_rpc {
                // If we hit the reconcile point but PeerInfo already confirms
                // we're current, treat it as reconciled: reset the timer so we
                // don't re-check every tick, and stay paused with no RPC.
                if reconcile_due {
                    last_rpc_poll = tokio::time::Instant::now();
                }
                let target = gf.head();
                // Drain contiguous store-present frames (gossip delivered them);
                // fire on_frame exactly as the RPC path would, just without the
                // network round-trip.
                let mut hole = false;
                while last_frame < target {
                    let next = last_frame + 1;
                    match clock_store.get_global_frame(next) {
                        Ok(frame) => {
                            if let Some(ref cb) = config.on_frame {
                                cb(&frame);
                            }
                            last_frame = next;
                        }
                        Err(_) => {
                            // Gossip missed this frame — fall through to the RPC
                            // path to fill the hole (last_frame sits just below it).
                            hole = true;
                            break;
                        }
                    }
                }
                if !hole {
                    if last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL {
                        info!(
                            local_frame = last_frame,
                            gossip_head = target,
                            "archive poller: gossip is carrying the head — RPC head-poll paused",
                        );
                        last_heartbeat = tokio::time::Instant::now();
                    }
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(GOSSIP_IDLE_BACKOFF) => {}
                    }
                    continue;
                }
                // hole == true: fall through and let the RPC head-poll +
                // forward-fill below fetch the missing frame(s).
            }
        }
        last_rpc_poll = tokio::time::Instant::now();
        // We're committing to an actual RPC head-poll below — reset the hard bound.
        last_actual_rpc = tokio::time::Instant::now();

        // Acquire a working client.
        if current_client.is_none() {
            if let Some(addr) = pool.next().await {
                match connect(addr.clone()).await {
                    Ok(c) => {
                        info!(%addr, "archive poller connected");
                        current_client = Some((addr, c));
                    }
                    Err(e) => {
                        debug!(%addr, error = %e, "poller connect failed");
                        pool.blacklist(&addr).await;
                        continue;
                    }
                }
            } else {
                // Pool empty — wait for PeerInfo discovery to feed us.
                pool.wait_nonempty(&cancel).await;
                continue;
            }
        }

        let Some((addr, ref mut client)) = current_client.as_mut().map(|(a, c)| (a.clone(), c))
        else {
            continue;
        };

        // 1. Fetch the latest frame.
        let head = match tokio::time::timeout(
            config.call_timeout,
            client.get_global_frame(0),
        )
        .await
        {
            Ok(Ok(frame)) => frame,
            Ok(Err(ArchiveClientError::Rpc(s)))
                if s.message().contains("not currently syncable") =>
            {
                // This is an archive node that isn't currently syncable
                // (the operator may have flipped serving off). Try the
                // next endpoint, but don't blacklist — leave it for
                // future polls.
                debug!(%addr, "endpoint not currently syncable, rotating");
                current_client = None;
                continue;
            }
            Ok(Err(e)) => {
                warn!(%addr, error = %e, "archive head fetch failed");
                pool.blacklist(&addr).await;
                current_client = None;
                continue;
            }
            Err(_elapsed) => {
                warn!(%addr, "archive head fetch timed out");
                pool.blacklist(&addr).await;
                current_client = None;
                continue;
            }
        };
        let new_number = head.header.as_ref().map(|h| h.frame_number).unwrap_or(0);
        if new_number == 0 || new_number <= last_frame {
            // This endpoint is not ahead of us. It may be genuinely behind, at
            // our exact height, or this node's own endpoint. Do NOT silently
            // latch onto it forever (the old behavior — an extremely-behind
            // archive whose poller happened to grab a non-advancing endpoint
            // would sit here with zero log output). Count consecutive
            // no-progress ticks and, past a small threshold, rotate to a
            // different endpoint to keep looking for one that IS ahead. This is
            // NOT a blacklist: the endpoint isn't broken, just not useful now.
            no_progress = no_progress.saturating_add(1);
            if last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL {
                info!(
                    %addr,
                    local_frame = last_frame,
                    endpoint_head = new_number,
                    no_progress,
                    "archive poller: not advancing — current endpoint is not ahead of us",
                );
                last_heartbeat = tokio::time::Instant::now();
            }
            if no_progress >= NO_PROGRESS_ROTATE_THRESHOLD {
                debug!(
                    %addr,
                    local_frame = last_frame,
                    endpoint_head = new_number,
                    "archive poller: rotating off non-advancing endpoint",
                );
                current_client = None;
                no_progress = 0;
            }
            // Back off (cancel-aware) so a not-advancing poller neither hot-loops
            // the head nor reconnect-storms :8340 on rotation.
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(NO_PROGRESS_BACKOFF) => {}
            }
            continue;
        }
        // The endpoint is ahead — we're going to make progress this tick.
        no_progress = 0;

        // 1b. Runtime far-behind rescue (non-archive): if we've fallen a long way
        // behind the network head mid-run, snapshot-jump to a recent target
        // instead of forward-filling (and re-materializing) the entire gap — the
        // same rescue the startup barrier gives at boot. Without it a node that
        // drops far behind at runtime (e.g. a long partition, or a restart onto a
        // stale/legacy local head) grinds forward one frame at a time — across the
        // pre-migration LEGACY range it can hit frames it can never validate and
        // crawl a single frame per multi-archive stall. A successful jump advances
        // the clock head + materialized cursor + registry, and lands near head, so
        // the post-jump gap is small and this cannot immediately re-fire.
        if let Some(ref jump) = config.far_behind_jump {
            if config.gossip_freshness.is_some()
                && new_number.saturating_sub(last_frame) >= STATE_JUMP_RUNTIME_GAP
            {
                info!(
                    local_frame = last_frame,
                    head = new_number,
                    "archive poller: far behind at runtime — attempting state-jump",
                );
                if let Some(n) = jump(new_number, cancel.clone()).await {
                    if n > last_frame {
                        last_frame = n;
                    }
                    info!(target = n, "archive poller: runtime state-jump landed — resuming near head");
                    continue;
                }
                warn!(
                    local_frame = last_frame,
                    head = new_number,
                    "archive poller: runtime state-jump did not complete — forward-filling",
                );
            }
        }

        // 2. Forward-fill any missed frames in (last_frame, new_number).
        //    Archive nodes need the full history; everyone else
        //    just wants to start from the current head.
        //
        // An EMPTY store (`last_frame == 0`) is a gap like any other, and used
        // to be excluded here by a `last_frame > 0` arm. That treated every
        // fresh boot as "nothing to fill": the first successful head poll
        // stored ONLY the head and latched the cursor past everything below it,
        // and nothing revisits frames under the cursor at runtime (the
        // record-gap scan runs at bootstrap only), so the hole was permanent.
        // It is not archive-specific — `forward_fill` is set for every node
        // role, because regulars need contiguity too (their app-shard storage
        // attestations anchor ρ_N to an exact global frame that must be present
        // locally). Regulars merely have a smaller window to hit it in: the
        // runtime far-behind rescue above tries a state-jump first, and only a
        // node whose jump does not complete crawls up from genesis here.
        if config.forward_fill && new_number > last_frame + 1 {
            // Bound the span filled per tick. Dropping the guard above means a
            // fresh archive at mainnet height would otherwise attempt a single
            // genesis-to-head crawl inside ONE tick — an unbounded loop with no
            // cancellation check in it. Filling a bounded chunk and resuming on
            // the next tick keeps the loop responsive to `cancel` and bounds the
            // work per iteration, at no throughput cost: each frame is a
            // round-trip, so the real fill rate is far below this ceiling.
            let fill_end = new_number.min(
                last_frame
                    .saturating_add(1)
                    .saturating_add(MAX_FORWARD_FILL_PER_TICK),
            );
            // Track partial progress: every frame we successfully store
            // advances `last_frame`, so a failure midway does NOT throw
            // away the frames we already pulled. The previous design left
            // `last_frame` untouched on any failure and retried the WHOLE
            // gap against the SAME endpoint forever — a single unfetchable
            // frame (e.g. one the source archive never persisted) wedged
            // catch-up permanently, which is exactly the "far-behind node
            // never catches up" symptom.
            let mut failed_frame: Option<u64> = None;
            // Whether the failure was a genuine gRPC NotFound (the peer
            // affirmatively has no such frame), as opposed to a transient
            // transport error / timeout. Only NotFound counts toward
            // declaring a frame permanently unfillable.
            let mut failed_not_found = false;
            // Whether the failure was a served-but-unvalidatable frame (as
            // opposed to NotFound / transport). Counts toward the same skip via
            // its own distinct-endpoint tally.
            let mut failed_validation = false;
            for fn_ in (last_frame + 1)..fill_end {
                // Store-first (non-archive): if gossip already delivered this
                // frame, use the local copy and skip the RPC. Only frames gossip
                // missed cost a network fetch. Fire on_frame just as the RPC arm
                // does, so processing is identical regardless of source.
                if config.gossip_freshness.is_some() {
                    if let Ok(frame) = clock_store.get_global_frame(fn_) {
                        if let Some(ref cb) = config.on_frame {
                            cb(&frame);
                        }
                        last_frame = fn_;
                        continue;
                    }
                }
                match tokio::time::timeout(
                    config.call_timeout,
                    client.get_global_frame(fn_),
                )
                .await
                {
                    Ok(Ok(frame)) => {
                        // Gate BEFORE persist — genesis-prover allowlist +
                        // VDF/BLS, mirroring the gossip GLOBAL_FRAME handler.
                        // A frame that fails validation is never stored and
                        // never fired to on_frame. Treat it like an
                        // unavailable frame: rotate to another endpoint (an
                        // honest archive may serve the real record at this
                        // height) rather than persisting forged data.
                        if let Some(ref validate) = config.frame_validator {
                            if !validate(&frame) {
                                debug!(%addr, frame = fn_, "catchup frame failed validation — rotating endpoint");
                                failed_frame = Some(fn_);
                                failed_validation = true;
                                break;
                            }
                        }
                        if let Err(e) = clock_store.put_global_frame(&frame, None) {
                            warn!(error = %e, frame = fn_, "store catchup frame failed");
                        }
                        if let Some(ref cb) = config.on_frame {
                            cb(&frame);
                        }
                        // Advance over each stored frame so progress is durable.
                        last_frame = fn_;
                    }
                    Ok(Err(e)) => {
                        warn!(%addr, frame = fn_, error = %e, "catchup fetch error");
                        failed_not_found = matches!(
                            &e,
                            ArchiveClientError::Rpc(s) if s.code() == tonic::Code::NotFound
                        );
                        failed_frame = Some(fn_);
                        break;
                    }
                    Err(_) => {
                        warn!(%addr, frame = fn_, "catchup timeout");
                        failed_frame = Some(fn_);
                        break;
                    }
                }
            }
            if let Some(bad) = failed_frame {
                // Track distinct archives that report this exact frame as a
                // genuine NotFound OR serve an unvalidatable frame at it. A new
                // stuck frame resets both tallies.
                if stall_frame != Some(bad) {
                    stall_frame = Some(bad);
                    stall_endpoints.clear();
                    stall_invalid_endpoints.clear();
                }
                if failed_not_found {
                    stall_endpoints.insert(addr.clone());
                }
                if failed_validation {
                    stall_invalid_endpoints.insert(addr.clone());
                }

                // Abandon a permanently-unfillable gap. When enough DISTINCT
                // archives have each affirmatively returned NotFound for the
                // same frame — OR each served a frame at it that fails
                // validation (a legacy pre-migration height the new chain can
                // never validate) — and the network head sits well beyond it,
                // no peer will ever serve a valid record. Retrying forever
                // wedges catch-up at `bad` and never reaches the frames that DO
                // exist. Skip it: advance `last_frame` past the hole so the
                // poller resumes at `bad + 1`. The separate record-gap
                // backfill/scan still tracks the hole for any later fill; this
                // only unblocks forward progress.
                let head_far_past = new_number >= bad.saturating_add(UNFILLABLE_HEAD_MARGIN);
                let notfound_unfillable =
                    stall_endpoints.len() >= UNFILLABLE_DISTINCT_ENDPOINTS;
                let invalid_unfillable =
                    stall_invalid_endpoints.len() >= UNFILLABLE_DISTINCT_ENDPOINTS;
                if (notfound_unfillable || invalid_unfillable) && head_far_past {
                    warn!(
                        failed_frame = bad,
                        head = new_number,
                        distinct_notfound = stall_endpoints.len(),
                        distinct_invalid = stall_invalid_endpoints.len(),
                        skip_to = bad + 1,
                        "catchup: frame is unfillable (NotFound or unvalidatable across multiple archives, head far past) — abandoning gap and skipping past it"
                    );
                    last_frame = bad;
                    stall_frame = None;
                    stall_endpoints.clear();
                    stall_invalid_endpoints.clear();
                    // Keep the current endpoint (it IS ahead and serving) and
                    // continue straight into head processing / next fill.
                    continue;
                }

                // `last_frame` already sits at the last good frame, so we
                // resume from `bad` next tick — never redoing work. Rotate
                // to a DIFFERENT endpoint (a mere missing/slow frame is not
                // grounds to blacklist a committee member: another archive
                // may well have it). Back off briefly so that if EVERY
                // endpoint is missing `bad` (a genuine data hole) we cycle
                // them at a sane cadence instead of a once-a-second mTLS
                // reconnect storm onto the :8340 path consensus shares.
                warn!(
                    %addr,
                    failed_frame = bad,
                    resume_from = bad,
                    head = new_number,
                    not_found = failed_not_found,
                    validation_failed = failed_validation,
                    distinct_notfound = stall_endpoints.len(),
                    distinct_invalid = stall_invalid_endpoints.len(),
                    "catchup stalled at frame; rotating endpoint and retrying from last good frame"
                );
                current_client = None;
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
                continue;
            }
            if fill_end < new_number {
                // Chunk done but the gap is still open. Do NOT fall through to
                // head processing: storing the head here would latch the cursor
                // past the frames we have not fetched yet — the very skip this
                // fill exists to prevent. Resume from `last_frame` next tick.
                debug!(
                    local_frame = last_frame,
                    head = new_number,
                    "catchup: filled a bounded chunk — resuming below head next tick"
                );
                continue;
            }
        }

        // 3. Process the new head.
        // Gate BEFORE persist, same as the forward-fill path above and the
        // gossip GLOBAL_FRAME handler. A head frame failing validation is
        // dropped: don't store, don't fire on_frame, and don't advance
        // last_frame (the next tick re-polls the head).
        if let Some(ref validate) = config.frame_validator {
            if !validate(&head) {
                debug!(%addr, frame = new_number, "head frame failed validation — dropping");
                continue;
            }
        }
        if let Err(e) = clock_store.put_global_frame(&head, None) {
            warn!(error = %e, frame = new_number, "store head frame failed");
            continue;
        }
        if let Some(ref cb) = config.on_frame {
            cb(&head);
        }
        info!(
            head = new_number,
            gap = new_number.saturating_sub(last_frame),
            "advanced head"
        );
        last_frame = new_number;
    }

    info!("archive frame poller stopped");
}

#[cfg(test)]
mod pool_tests {
    use super::*;

    /// Default TTL used by the pool tests that aren't specifically about
    /// the disabled (zero-TTL) path.
    const TEST_TTL: Duration = Duration::from_secs(60);

    /// A pool with a normal (non-zero) blacklist TTL.
    fn pool() -> ArchiveEndpointPool {
        ArchiveEndpointPool::new(TEST_TTL)
    }

    #[tokio::test]
    async fn add_then_get_all_returns_endpoints_in_order() {
        let pool = pool();
        pool.add("a.example.com:443".into()).await;
        pool.add("b.example.com:443".into()).await;
        let all = pool.get_all().await;
        assert_eq!(all, vec!["a.example.com:443", "b.example.com:443"]);
    }

    #[tokio::test]
    async fn add_dedups_existing_endpoint() {
        let pool = pool();
        pool.add("a.example.com:443".into()).await;
        pool.add("a.example.com:443".into()).await;
        assert_eq!(pool.len().await, 1);
    }

    #[tokio::test]
    async fn next_rotates_round_robin() {
        let pool = pool();
        for ep in ["a:1", "b:1", "c:1"] {
            pool.add(ep.into()).await;
        }
        let picks: Vec<_> = vec![
            pool.next().await,
            pool.next().await,
            pool.next().await,
            pool.next().await,
        ];
        // First three should hit every endpoint once.
        let mut sorted = picks
            .iter()
            .take(3)
            .map(|o| o.clone().unwrap())
            .collect::<Vec<_>>();
        sorted.sort();
        assert_eq!(sorted, vec!["a:1", "b:1", "c:1"]);
        // Fourth wraps to "a:1" again.
        assert_eq!(picks[3].as_deref(), Some("a:1"));
    }

    #[tokio::test]
    async fn blacklist_skips_rotation_but_never_prunes() {
        let pool = pool();
        pool.add("a:1".into()).await;
        pool.add("b:1".into()).await;
        pool.blacklist("a:1").await;
        // Blacklist skips "a:1" in the poller's round-robin...
        assert_eq!(pool.next().await.as_deref(), Some("b:1"));
        assert_eq!(pool.next().await.as_deref(), Some("b:1"));
        // ...but it is NEVER removed from the pool. `get_all()` (the
        // consensus fan-out set) must always include every known archive,
        // so a transient poll failure can't drop a committee member from
        // consensus delivery.
        let mut all = pool.get_all().await;
        all.sort();
        assert_eq!(
            all,
            vec!["a:1", "b:1"],
            "blacklist must not prune endpoints from get_all"
        );
    }

    /// Regression: prior to the TTL fix a single timeout permanently
    /// removed an endpoint and `add()` rejected re-adds for the rest of
    /// the process lifetime. Over hours of uptime the pool drained and
    /// every archive call surfaced as `connect_mtls failed: transport
    /// error: deadline has expired`. After the fix an expired
    /// blacklist entry is dropped and the endpoint becomes eligible
    /// again — both via opportunistic restoration in `next()` and via
    /// PeerInfo's re-`add()`.
    #[tokio::test]
    async fn blacklist_expires_after_ttl() {
        let pool = pool();
        pool.add("a:1".into()).await;
        pool.blacklist("a:1").await;
        assert!(pool.next().await.is_none(), "still blacklisted within TTL");

        // Backdate the blacklist entry past the TTL by mutating the
        // inner state directly. Real time would take 60s — too long
        // for a unit test.
        {
            let mut inner = pool.inner.lock().await;
            let past = Instant::now() - (TEST_TTL + Duration::from_secs(1));
            inner.blacklist.insert("a:1".to_string(), past);
        }

        // `next()` opportunistically restores the expired endpoint.
        assert_eq!(
            pool.next().await.as_deref(),
            Some("a:1"),
            "expired-blacklist endpoint must be restored"
        );
        assert_eq!(pool.get_all().await, vec!["a:1"]);
    }

    /// A blacklisted endpoint is never pruned from the pool — it stays in
    /// `get_all()` (consensus fan-out) the whole time, is merely skipped by
    /// the poller's `next()` round-robin while fresh, and becomes eligible
    /// for `next()` again once the TTL expires.
    #[tokio::test]
    async fn blacklisted_endpoint_never_pruned_retried_after_ttl() {
        let pool = pool();
        pool.add("a:1".into()).await;
        pool.blacklist("a:1").await;
        // Never pruned: still in the consensus fan-out set while blacklisted.
        assert_eq!(
            pool.get_all().await,
            vec!["a:1"],
            "blacklisted endpoint must remain in get_all"
        );
        // Skipped by the poller's rotation while the blacklist is fresh.
        assert!(
            pool.next().await.is_none(),
            "blacklisted-within-TTL endpoint is skipped by next()"
        );

        // Backdate the blacklist entry past the TTL.
        {
            let mut inner = pool.inner.lock().await;
            let past = Instant::now() - (TEST_TTL + Duration::from_secs(1));
            inner.blacklist.insert("a:1".to_string(), past);
        }

        // After the TTL, the poller retries it; it was in get_all all along.
        assert_eq!(pool.next().await.as_deref(), Some("a:1"), "retried after TTL");
        assert_eq!(pool.get_all().await, vec!["a:1"]);
    }

    #[tokio::test]
    async fn next_returns_none_on_empty_pool() {
        let pool = pool();
        assert!(pool.next().await.is_none());
    }

    /// A zero TTL disables blacklisting: a failed endpoint is restored on
    /// the very next `next()` (its entry is instantly expired), so it never
    /// leaves rotation for more than a single pick. This is the devnet
    /// configuration where partition recovery must be instantaneous.
    #[tokio::test]
    async fn blacklist_disabled_when_ttl_zero() {
        let pool = ArchiveEndpointPool::new(Duration::ZERO);
        pool.add("a:1".into()).await;
        pool.add("b:1".into()).await;
        pool.blacklist("a:1").await;

        // `next()` immediately restores "a:1" (entry expired at TTL 0), so
        // both endpoints come back into rotation without any wait.
        let mut seen = vec![pool.next().await, pool.next().await]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        seen.sort();
        assert_eq!(
            seen,
            vec!["a:1", "b:1"],
            "zero TTL must restore a blacklisted endpoint on the next pick"
        );
        let mut all = pool.get_all().await;
        all.sort();
        assert_eq!(all, vec!["a:1", "b:1"]);
    }

    /// `wait_nonempty` must release as soon as an endpoint arrives,
    /// without spinning. Models the poller's startup ordering: spawn
    /// poller → PeerInfo discovery feeds endpoint → poller resumes.
    #[tokio::test]
    async fn wait_nonempty_releases_on_add() {
        let pool = Arc::new(pool());
        let cancel = CancellationToken::new();
        let waiter_pool = pool.clone();
        let waiter_cancel = cancel.clone();
        let waiter = tokio::spawn(async move {
            waiter_pool.wait_nonempty(&waiter_cancel).await;
            std::time::Instant::now()
        });
        // Give the waiter time to park.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let added_at = std::time::Instant::now();
        pool.add("x:1".into()).await;
        let released_at = waiter.await.expect("waiter join");
        // Should release within a few ms after add.
        let gap = released_at.saturating_duration_since(added_at);
        assert!(
            gap < Duration::from_millis(200),
            "wait_nonempty took {gap:?} to release after add — expected <200ms"
        );
    }

    /// Cancellation must unblock `wait_nonempty` even with no
    /// endpoints — otherwise shutdown hangs.
    #[tokio::test]
    async fn wait_nonempty_respects_cancellation() {
        let pool = Arc::new(pool());
        let cancel = CancellationToken::new();
        let waiter_pool = pool.clone();
        let waiter_cancel = cancel.clone();
        let waiter = tokio::spawn(async move {
            waiter_pool.wait_nonempty(&waiter_cancel).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_millis(500), waiter)
            .await
            .expect("cancellation must unblock wait_nonempty")
            .expect("waiter join");
    }

    /// Poller config defaults must match Go's behavior: 1s tick,
    /// 30s call timeout, no forward-fill on a fresh non-archive node.
    /// A drift here silently changes catch-up semantics in production.
    #[test]
    fn default_config_matches_go_poll_frames_from_archive() {
        let cfg = ArchivePollerConfig::default();
        assert_eq!(cfg.poll_interval, Duration::from_secs(1));
        assert_eq!(cfg.call_timeout, Duration::from_secs(30));
        assert!(cfg.on_frame.is_none());
        assert!(!cfg.forward_fill);
        // Gossip backoff is opt-in — off by default (archives, and any caller
        // that doesn't wire it) so the poller always RPC-polls.
        assert!(cfg.gossip_freshness.is_none());
    }

    #[test]
    fn gossip_freshness_starts_stale_and_tracks_head() {
        let gf = GossipFreshness::new();
        // Never stamped → not fresh, head 0.
        assert!(!gf.fresh_within(Duration::from_secs(30)));
        assert_eq!(gf.head(), 0);

        gf.stamp(41);
        gf.stamp(42);
        // Just stamped → fresh within any reasonable window.
        assert!(gf.fresh_within(Duration::from_secs(30)));
        // Head is the max seen; an out-of-order older stamp never regresses it.
        assert_eq!(gf.head(), 42);
        gf.stamp(7);
        assert_eq!(gf.head(), 42);
    }

    #[test]
    fn gossip_freshness_network_head_tracks_max_only() {
        let gf = GossipFreshness::new();
        assert_eq!(gf.network_head(), 0, "unset ⇒ 0 (poller falls back to RPC)");
        gf.note_network_head(500);
        gf.note_network_head(742);
        assert_eq!(gf.network_head(), 742);
        // An older/lower advertisement never regresses the head.
        gf.note_network_head(100);
        assert_eq!(gf.network_head(), 742);
    }

    #[test]
    fn gossip_freshness_window_expires() {
        let gf = GossipFreshness::new();
        gf.stamp(100);
        // A zero-length window is never satisfied by a stamp in the past.
        assert!(!gf.fresh_within(Duration::from_millis(0)));
        // A generous window is.
        assert!(gf.fresh_within(Duration::from_secs(60)));
    }
}

/// In-process repro for the poller's empty-store forward-fill hole.
///
/// Observed live in the devnet partition harness: an archive isolated while
/// frames 1..k finalize comes back, polls a head N, and permanently serves
/// NotFound for the missed frames — its serial materializer wedges below the
/// registrations it needs. Mechanism: the forward-fill guard
/// (`config.forward_fill && last_frame > 0 && …`) treats an empty store
/// (`last_frame == 0`, every fresh boot) as "nothing to fill", so the first
/// successful head poll stores ONLY the head and latches `last_frame` past
/// the hole. No runtime path revisits frames below the cursor (the
/// record-gap scan runs at bootstrap only), so the hole is permanent.
///
/// NOT archive-specific: `forward_fill: true` is set for EVERY node role
/// (see `master_node/archive_sync.rs` — regulars need contiguity too, their
/// app-shard storage attestations anchor ρ_N to an exact global frame that
/// must be present locally). Regular nodes merely shrink the window: gossip
/// stores frames independently and a far-behind boot state-jumps, but a
/// client whose store is empty at its first head poll while gossip missed
/// the early frames (boot-time partition, mesh forming late, gossip drops)
/// hits the identical skip — and its materializer/ρ_N anchors wedge the
/// same way.
///
/// The two RED tests are the repro — they FAIL on this branch and are meant
/// to be attached to a bug report:
/// - `empty_store_first_head_poll_must_backfill_full_history` (archive
///   mode: `gossip_freshness: None`)
/// - `client_mode_empty_store_hits_the_same_skip` (regular-node mode:
///   `gossip_freshness: Some`, mesh quiet — the client boot race)
/// `seeded_store_gap_is_forward_filled` is the passing contrast: the same
/// gap above a NON-empty cursor is filled, showing the inconsistency.
#[cfg(test)]
mod forward_fill_repro {
    use super::*;
    use std::collections::BTreeMap;
    use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader};

    /// Minimal frame that satisfies `RocksClockStore::put_global_frame`
    /// (header present; requests empty).
    fn mk_frame(n: u64) -> GlobalFrame {
        GlobalFrame {
            header: Some(GlobalFrameHeader {
                frame_number: n,
                output: vec![n as u8; 32],
                ..Default::default()
            }),
            requests: vec![],
        }
    }

    /// In-process archive: serves `0` as "latest" and exact frame numbers
    /// otherwise, with a real gRPC `NotFound` status for absent frames so the
    /// poller's NotFound-detection paths behave as in production.
    #[derive(Clone)]
    struct FakeArchive {
        frames: Arc<std::sync::Mutex<BTreeMap<u64, GlobalFrame>>>,
    }

    impl FakeArchive {
        fn serving(range: std::ops::RangeInclusive<u64>) -> Self {
            let frames = range.map(|n| (n, mk_frame(n))).collect();
            Self { frames: Arc::new(std::sync::Mutex::new(frames)) }
        }
    }

    #[tonic::async_trait]
    impl PollerFrameSource for FakeArchive {
        async fn get_global_frame(
            &mut self,
            frame_number: u64,
        ) -> Result<GlobalFrame, ArchiveClientError> {
            let frames = self.frames.lock().unwrap();
            let found = if frame_number == 0 {
                frames.values().next_back().cloned()
            } else {
                frames.get(&frame_number).cloned()
            };
            found.ok_or_else(|| {
                ArchiveClientError::Rpc(tonic::Status::not_found(format!(
                    "frame {frame_number} not found"
                )))
            })
        }
    }

    struct Rig {
        _tmp: tempfile::TempDir,
        store: Arc<RocksClockStore>,
        seen: Arc<std::sync::Mutex<Vec<u64>>>,
        cancel: CancellationToken,
        poller: tokio::task::JoinHandle<()>,
    }

    /// Spawn the real poller loop (forward_fill on — every node role runs
    /// with it, see the module comment) against `fake`, over a fresh Rocks
    /// store optionally pre-seeded with frames. `gossip` selects the role:
    /// `None` = archive mode (always RPC-polls); `Some` = regular-node mode
    /// (the poller consults the freshness signal first — an unstamped signal
    /// models a client whose gossip mesh has delivered nothing, so it falls
    /// through to the same RPC head-poll + forward-fill path).
    async fn spawn_poller(
        fake: FakeArchive,
        seed_frames: &[u64],
        gossip: Option<Arc<GossipFreshness>>,
    ) -> Rig {
        spawn_poller_with_jump(fake, seed_frames, gossip, None).await
    }

    /// As `spawn_poller`, but able to wire the runtime far-behind rescue hook —
    /// the branch that decides whether a regular node state-jumps or crawls.
    async fn spawn_poller_with_jump(
        fake: FakeArchive,
        seed_frames: &[u64],
        gossip: Option<Arc<GossipFreshness>>,
        far_behind_jump: Option<FarBehindJump>,
    ) -> Rig {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = quil_store::RocksDb::open(tmp.path()).unwrap();
        let store = Arc::new(RocksClockStore::new(db.inner()));
        for n in seed_frames {
            store.put_global_frame(&mk_frame(*n), None).unwrap();
        }

        let pool = Arc::new(ArchiveEndpointPool::new(Duration::from_secs(60)));
        pool.add("fake-archive:8340".into()).await;

        let seen: Arc<std::sync::Mutex<Vec<u64>>> = Arc::new(std::sync::Mutex::new(vec![]));
        let seen_cb = seen.clone();
        let config = ArchivePollerConfig {
            poll_interval: Duration::from_millis(20),
            call_timeout: Duration::from_secs(1),
            forward_fill: true,
            gossip_freshness: gossip,
            far_behind_jump,
            on_frame: Some(Arc::new(move |f: &GlobalFrame| {
                if let Some(h) = f.header.as_ref() {
                    seen_cb.lock().unwrap().push(h.frame_number);
                }
            })),
            ..Default::default()
        };

        let cancel = CancellationToken::new();
        let poller = tokio::spawn(run_archive_poller_with_connector(
            pool,
            store.clone(),
            config,
            cancel.clone(),
            move |_addr: String| {
                let f = fake.clone();
                async move { Ok::<_, ArchiveClientError>(f) }
            },
        ));
        Rig { _tmp: tmp, store, seen, cancel, poller }
    }

    /// Wait (bounded) until the store's latest-frame cursor reaches `head`,
    /// then stop the poller. Returns whether the head was reached at all.
    async fn await_head_then_stop(rig: &Rig, head: u64) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut reached = false;
        while tokio::time::Instant::now() < deadline {
            if rig.store.get_latest_frame_number() == Some(head) {
                reached = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        rig.cancel.cancel();
        reached
    }

    /// REPRO (fails on this branch): a poller booted on an EMPTY store must
    /// backfill the full history below the first head it sees — an archive
    /// needs frames 1..head, and the materializer requires contiguity.
    /// Instead, the `last_frame > 0` arm of the forward-fill guard skips the
    /// fill, only the head frame is stored, and the hole below it is
    /// permanent (nothing revisits frames under the cursor at runtime).
    #[tokio::test]
    async fn empty_store_first_head_poll_must_backfill_full_history() {
        let rig = spawn_poller(FakeArchive::serving(1..=5), &[], None).await;
        assert!(
            await_head_then_stop(&rig, 5).await,
            "poller never even reached the head — setup problem, not the repro"
        );
        rig.poller.abort();

        let missing: Vec<u64> = (1..=5)
            .filter(|n| rig.store.get_global_frame(*n).is_err())
            .collect();
        assert!(
            missing.is_empty(),
            "frames {missing:?} were permanently skipped: the forward-fill guard \
             (`config.forward_fill && last_frame > 0 && …`) treats an empty store \
             (last_frame == 0) as nothing-to-fill, so the first successful head poll \
             stores only the head and latches the cursor past the hole; no runtime \
             path revisits frames below the cursor (the record-gap scan is \
             bootstrap-only), so a serial materializer wedges here forever. \
             on_frame saw {:?}, want [1, 2, 3, 4, 5]",
            rig.seen.lock().unwrap(),
        );
    }

    /// REPRO (fails on this branch), regular-node flavor: `forward_fill` is
    /// on for regulars too (their ρ_N storage-attestation anchors need exact
    /// global frames locally), and a client can reach its first head poll
    /// with an empty store while gossip missed the early frames — a
    /// boot-time partition or a late-forming mesh (devnet run 1's archive-4
    /// race, on a client). The unstamped freshness signal models the quiet
    /// mesh; the poller falls through to the identical RPC path and the
    /// identical guard skips the identical fill.
    #[tokio::test]
    async fn client_mode_empty_store_hits_the_same_skip() {
        let rig = spawn_poller(FakeArchive::serving(1..=5), &[], Some(GossipFreshness::new()))
            .await;
        assert!(
            await_head_then_stop(&rig, 5).await,
            "poller never even reached the head — setup problem, not the repro"
        );
        rig.poller.abort();

        let missing: Vec<u64> = (1..=5)
            .filter(|n| rig.store.get_global_frame(*n).is_err())
            .collect();
        assert!(
            missing.is_empty(),
            "frames {missing:?} were permanently skipped in REGULAR-NODE mode: the \
             empty-store forward-fill guard is role-independent, so a client that \
             boots into a quiet gossip mesh latches onto the first polled head and \
             never backfills — its serial materializer and ρ_N anchor lookups then \
             wedge exactly like an archive's. on_frame saw {:?}, want [1, 2, 3, 4, 5]",
            rig.seen.lock().unwrap(),
        );
    }

    /// Contrast (passes): the SAME gap above a non-empty cursor IS forward-
    /// filled — store holds frame 1, head jumps to 5, frames 2..4 get
    /// fetched, stored, and fired in order. Shows the empty-store case is an
    /// inconsistency in the guard, not a designed limitation of the loop.
    #[tokio::test]
    async fn seeded_store_gap_is_forward_filled() {
        let rig = spawn_poller(FakeArchive::serving(1..=5), &[1], None).await;
        assert!(
            await_head_then_stop(&rig, 5).await,
            "poller did not fill the gap and reach head 5"
        );
        rig.poller.abort();

        for n in 1..=5u64 {
            assert!(
                rig.store.get_global_frame(n).is_ok(),
                "frame {n} missing after forward-fill from a seeded cursor"
            );
        }
        assert_eq!(
            *rig.seen.lock().unwrap(),
            vec![2, 3, 4, 5],
            "forward-fill must fire on_frame for each filled frame, then the head"
        );
    }

    /// Coverage for the bounded fill that replaced the `last_frame > 0` guard:
    /// a gap wider than `MAX_FORWARD_FILL_PER_TICK` (512) must still close
    /// contiguously, just across several ticks.
    ///
    /// The interesting case is the tick boundary. A chunk that ends below the
    /// head must NOT fall through to head processing — storing the head there
    /// would latch the cursor past the unfetched remainder and reintroduce
    /// exactly the permanent hole this fix removes. So the head is stored only
    /// on the tick that closes the gap, and the result is dense from 1 to head.
    #[tokio::test]
    async fn gap_wider_than_one_chunk_fills_contiguously_across_ticks() {
        const HEAD: u64 = 600; // > MAX_FORWARD_FILL_PER_TICK
        let rig = spawn_poller(FakeArchive::serving(1..=HEAD), &[], None).await;
        assert!(
            await_head_then_stop(&rig, HEAD).await,
            "poller did not reach head {HEAD} across multiple fill chunks"
        );
        rig.poller.abort();

        let missing: Vec<u64> = (1..=HEAD)
            .filter(|n| rig.store.get_global_frame(*n).is_err())
            .collect();
        assert!(
            missing.is_empty(),
            "frames {missing:?} missing — a bounded chunk must resume below the head, \
             never latch the cursor past the frames it has not fetched yet",
        );
        assert_eq!(
            *rig.seen.lock().unwrap(),
            (1..=HEAD).collect::<Vec<u64>>(),
            "on_frame must fire once per frame, in order, across the chunk boundary",
        );
    }

    /// The regular-node escape hatch, and the reason removing the
    /// `last_frame > 0` guard is acceptable for non-archives.
    ///
    /// Filling from an empty store means the head is stored only once the gap
    /// closes, so a node far from head would climb to it one frame at a time.
    /// Regulars must not: the runtime far-behind rescue fires FIRST (empty store
    /// ⇒ the gap is the whole chain, so it clears `STATE_JUMP_RUNTIME_GAP`),
    /// state-jumps near head, and the poller resumes from there. Only a regular
    /// whose jump does not complete crawls up from genesis.
    ///
    /// Archives are deliberately excluded from this path (`far_behind_jump` is
    /// `None` for them in `archive_sync.rs`) — they need the full history, so
    /// crawling is the correct behaviour there.
    #[tokio::test]
    async fn regular_node_far_behind_state_jumps_instead_of_crawling_from_genesis() {
        const HEAD: u64 = STATE_JUMP_RUNTIME_GAP + 500; // far enough to trigger
        const JUMP_TO: u64 = HEAD - 100;

        let jumped: Arc<std::sync::Mutex<Vec<u64>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let jump_log = jumped.clone();
        let jump: FarBehindJump = Arc::new(move |head: u64, _cancel: CancellationToken| {
            jump_log.lock().unwrap().push(head);
            Box::pin(async move { Some(JUMP_TO) })
        });

        let rig = spawn_poller_with_jump(
            FakeArchive::serving(1..=HEAD),
            &[],
            Some(GossipFreshness::new()),
            Some(jump),
        )
        .await;
        assert!(
            await_head_then_stop(&rig, HEAD).await,
            "poller never reached head {HEAD} after the state-jump"
        );
        rig.poller.abort();

        assert!(
            !jumped.lock().unwrap().is_empty(),
            "the far-behind rescue never fired — an empty store is the whole chain \
             behind, so a regular node must state-jump rather than crawl",
        );
        // The jump landed at JUMP_TO, so the poller fills only above it. Nothing
        // below may have been fetched: that crawl is exactly what the rescue exists
        // to avoid.
        let crawled: Vec<u64> = (1..=JUMP_TO)
            .filter(|n| rig.store.get_global_frame(*n).is_ok())
            .collect();
        assert!(
            crawled.is_empty(),
            "frames {crawled:?} were fetched below the state-jump target — the \
             poller crawled from genesis instead of resuming at the jump",
        );
        // Above the jump it still forward-fills contiguously to the head.
        let missing: Vec<u64> = (JUMP_TO + 1..=HEAD)
            .filter(|n| rig.store.get_global_frame(*n).is_err())
            .collect();
        assert!(
            missing.is_empty(),
            "frames {missing:?} missing above the jump target — the post-jump gap \
             must still be forward-filled",
        );
    }
}

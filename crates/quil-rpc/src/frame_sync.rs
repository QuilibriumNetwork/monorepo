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
//!   which is a 4-phase CRDT walk and lives in a separate module (TBD).
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
    pub(crate) async fn next(&self) -> Option<String> {
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
    /// it.
    async fn wait_nonempty(&self, cancel: &CancellationToken) {
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

/// Poller configuration. Defaults match Go's `pollFramesFromArchive`.
pub struct ArchivePollerConfig {
    pub poll_interval: Duration,
    pub call_timeout: Duration,
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
}

impl Default for ArchivePollerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(1),
            call_timeout: Duration::from_secs(30),
            on_frame: None,
            frame_validator: None,
            forward_fill: false,
            startup_barrier: None,
        }
    }
}

/// Long-running task that polls a chosen archive endpoint for the current
/// head, and forward-fills any gap from the previously seen head. The
/// returned future runs until `cancel` fires; callers register it with
/// their supervisor (e.g. `sup.spawn(...)`) so a panic propagates.
pub async fn run_archive_poller(
    pool: Arc<ArchiveEndpointPool>,
    clock_store: Arc<RocksClockStore>,
    ed448_seed: [u8; 57],
    mut config: ArchivePollerConfig,
    cancel: CancellationToken,
) {
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
    let mut current_client: Option<(String, ArchiveClient)> = None;
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

    let mut ticker = tokio::time::interval(config.poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {}
        }

        // Acquire a working client.
        if current_client.is_none() {
            if let Some(addr) = pool.next().await {
                match ArchiveClient::connect_mtls(&addr, &ed448_seed).await {
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

        // 2. Forward-fill any missed frames in (last_frame, new_number).
        //    Archive nodes need the full history; everyone else
        //    just wants to start from the current head.
        if config.forward_fill && last_frame > 0 && new_number > last_frame + 1 {
            // Track partial progress: every frame we successfully store
            // advances `last_frame`, so a failure midway does NOT throw
            // away the frames we already pulled. The previous design left
            // `last_frame` untouched on any failure and retried the WHOLE
            // gap against the SAME endpoint forever — a single unfetchable
            // frame (e.g. one the source archive never persisted) wedged
            // catch-up permanently, which is exactly the "far-behind node
            // never catches up" symptom.
            let mut failed_frame: Option<u64> = None;
            for fn_ in (last_frame + 1)..new_number {
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
                                warn!(%addr, frame = fn_, "catchup frame failed validation — rotating endpoint");
                                failed_frame = Some(fn_);
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
                    "catchup stalled at frame; rotating endpoint and retrying from last good frame"
                );
                current_client = None;
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
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
                warn!(%addr, frame = new_number, "head frame failed validation — dropping");
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
    }
}

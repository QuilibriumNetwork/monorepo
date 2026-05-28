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
}

/// How long a blacklisted endpoint stays banned before becoming
/// eligible again. Short enough that transient network blips don't
/// permanently drain the pool, long enough that we don't hammer a
/// struggling endpoint into the ground. The previous design had no
/// TTL — a single timeout permanently removed the endpoint, and
/// `add()` rejected re-adds from PeerInfo discovery, so over hours
/// of uptime the pool gradually drained to zero and every archive
/// call surfaced as `"connect_mtls failed: transport error: deadline
/// has expired"` even though the endpoints had long since recovered.
const BLACKLIST_TTL: Duration = Duration::from_secs(60);

struct ArchiveEndpointPoolInner {
    /// All known archive endpoints we haven't blacklisted yet, in arrival
    /// order. The poller's "next" pointer rotates through this list.
    endpoints: Vec<String>,
    /// Endpoints that have failed recently. Each entry records the
    /// instant of the most recent failure; entries older than
    /// `BLACKLIST_TTL` are eligible to be restored on the next pool
    /// operation.
    blacklist: HashMap<String, Instant>,
    /// Index into `endpoints` for the next pick.
    cursor: usize,
}

impl ArchiveEndpointPool {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(ArchiveEndpointPoolInner {
                endpoints: Vec::new(),
                blacklist: HashMap::new(),
                cursor: 0,
            }),
            notify: Notify::new(),
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
            if ts.elapsed() < BLACKLIST_TTL {
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
    /// blacklist entry has aged past `BLACKLIST_TTL`, so a temporarily
    /// dead archive can be retried without waiting for PeerInfo
    /// re-discovery.
    pub(crate) async fn next(&self) -> Option<String> {
        let mut inner = self.inner.lock().await;
        let now = Instant::now();
        let expired: Vec<String> = inner
            .blacklist
            .iter()
            .filter(|(_, ts)| now.duration_since(**ts) >= BLACKLIST_TTL)
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
        inner.blacklist.insert(endpoint.to_string(), Instant::now());
        inner.endpoints.retain(|e| e != endpoint);
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

impl Default for ArchiveEndpointPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Callback invoked for each frame after it's stored. The poller
/// calls this with the `GlobalFrame` proto — wiring the execution
/// pipeline in here enables a read-only node to process frames as
/// they arrive.
pub type OnFrameCallback = Arc<dyn Fn(&GlobalFrame) + Send + Sync>;

/// Poller configuration. Defaults match Go's `pollFramesFromArchive`.
pub struct ArchivePollerConfig {
    pub poll_interval: Duration,
    pub call_timeout: Duration,
    /// Optional callback fired for each frame after storage.
    pub on_frame: Option<OnFrameCallback>,
    /// When true, the poller forward-fills every missed frame
    /// between the previously-seen head and the current head — the
    /// archive case where retaining full history is the point.
    /// When false (typical operator), the poller jumps straight to
    /// `head` on each tick: catching up on hundreds of thousands of
    /// genesis-to-tip frames just to start processing the latest
    /// state is wasted bandwidth, and the prover-tree sync provides
    /// the registry view we actually need.
    pub forward_fill: bool,
}

impl Default for ArchivePollerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(1),
            call_timeout: Duration::from_secs(30),
            on_frame: None,
            forward_fill: false,
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
    config: ArchivePollerConfig,
    cancel: CancellationToken,
) {
    info!("archive frame poller started");
    pool.wait_nonempty(&cancel).await;
    if cancel.is_cancelled() {
        return;
    }

    // Reuse a single client for as long as it works. Switch endpoints
    // only when an RPC fails.
    let mut current_client: Option<(String, ArchiveClient)> = None;
    // Use the local store's latest as our starting "last seen", so a
    // restart doesn't re-fetch frames we already have.
    let mut last_frame: u64 = clock_store.get_latest_frame_number().unwrap_or(0);

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
            // No progress.
            continue;
        }

        // 2. Forward-fill any missed frames in (last_frame, new_number).
        //    Archive nodes need the full history; everyone else
        //    just wants to start from the current head.
        if config.forward_fill && last_frame > 0 && new_number > last_frame + 1 {
            let mut catchup_failed = false;
            for fn_ in (last_frame + 1)..new_number {
                match tokio::time::timeout(
                    config.call_timeout,
                    client.get_global_frame(fn_),
                )
                .await
                {
                    Ok(Ok(frame)) => {
                        if let Err(e) = clock_store.put_global_frame(&frame, None) {
                            warn!(error = %e, frame = fn_, "store catchup frame failed");
                        }
                        if let Some(ref cb) = config.on_frame {
                            cb(&frame);
                        }
                    }
                    Ok(Err(e)) => {
                        debug!(%addr, frame = fn_, error = %e, "catchup fetch error");
                        catchup_failed = true;
                        break;
                    }
                    Err(_) => {
                        debug!(%addr, frame = fn_, "catchup timeout");
                        catchup_failed = true;
                        break;
                    }
                }
            }
            if catchup_failed {
                // Drop the connection so we re-try with another endpoint
                // next tick. last_frame stays where it was so we'll try
                // the same gap again.
                current_client = None;
                continue;
            }
        }

        // 3. Process the new head.
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

    #[tokio::test]
    async fn add_then_get_all_returns_endpoints_in_order() {
        let pool = ArchiveEndpointPool::new();
        pool.add("a.example.com:443".into()).await;
        pool.add("b.example.com:443".into()).await;
        let all = pool.get_all().await;
        assert_eq!(all, vec!["a.example.com:443", "b.example.com:443"]);
    }

    #[tokio::test]
    async fn add_dedups_existing_endpoint() {
        let pool = ArchiveEndpointPool::new();
        pool.add("a.example.com:443".into()).await;
        pool.add("a.example.com:443".into()).await;
        assert_eq!(pool.len().await, 1);
    }

    #[tokio::test]
    async fn next_rotates_round_robin() {
        let pool = ArchiveEndpointPool::new();
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
    async fn blacklist_removes_endpoint_from_rotation() {
        let pool = ArchiveEndpointPool::new();
        pool.add("a:1".into()).await;
        pool.add("b:1".into()).await;
        pool.blacklist("a:1").await;
        // After blacklist, only "b:1" comes out and `add()` rejects the
        // re-add while the blacklist entry is still fresh.
        assert_eq!(pool.next().await.as_deref(), Some("b:1"));
        assert_eq!(pool.next().await.as_deref(), Some("b:1"));
        pool.add("a:1".into()).await;
        assert_eq!(
            pool.get_all().await,
            vec!["b:1"],
            "freshly-blacklisted endpoint must not be re-addable"
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
        let pool = ArchiveEndpointPool::new();
        pool.add("a:1".into()).await;
        pool.blacklist("a:1").await;
        assert!(pool.next().await.is_none(), "still blacklisted within TTL");

        // Backdate the blacklist entry past the TTL by mutating the
        // inner state directly. Real time would take 60s — too long
        // for a unit test.
        {
            let mut inner = pool.inner.lock().await;
            let past = Instant::now() - (BLACKLIST_TTL + Duration::from_secs(1));
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

    /// Mirror of the above for the `add()` recovery path: PeerInfo
    /// gossip re-advertising an endpoint after its blacklist entry
    /// expired must re-enter the pool.
    #[tokio::test]
    async fn add_accepts_after_blacklist_expires() {
        let pool = ArchiveEndpointPool::new();
        pool.add("a:1".into()).await;
        pool.blacklist("a:1").await;
        pool.add("a:1".into()).await;
        assert!(
            pool.get_all().await.is_empty(),
            "add() rejected while blacklist is fresh"
        );

        // Backdate the blacklist entry past the TTL.
        {
            let mut inner = pool.inner.lock().await;
            let past = Instant::now() - (BLACKLIST_TTL + Duration::from_secs(1));
            inner.blacklist.insert("a:1".to_string(), past);
        }

        pool.add("a:1".into()).await;
        assert_eq!(
            pool.get_all().await,
            vec!["a:1"],
            "expired-blacklist endpoint must accept re-add"
        );
    }

    #[tokio::test]
    async fn next_returns_none_on_empty_pool() {
        let pool = ArchiveEndpointPool::new();
        assert!(pool.next().await.is_none());
    }

    /// `wait_nonempty` must release as soon as an endpoint arrives,
    /// without spinning. Models the poller's startup ordering: spawn
    /// poller → PeerInfo discovery feeds endpoint → poller resumes.
    #[tokio::test]
    async fn wait_nonempty_releases_on_add() {
        let pool = Arc::new(ArchiveEndpointPool::new());
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
        let pool = Arc::new(ArchiveEndpointPool::new());
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

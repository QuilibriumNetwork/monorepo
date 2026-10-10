//! Trait for syncing the global prover tree from archives.
//!
//! Workers need to sync the prover tree to resolve leader rotation,
//! verify FrameHeaders, and attribute shard work. In Go this is
//! `AppConsensusEngine.performBlockingGlobalHypersync` which calls
//! `HyperSyncSelf` against the master/archive. The Rust port can't
//! call `quil-rpc` from `quil-engine` (circular dep), so the trait
//! lives here and the implementation lives in `quil-node`.

use async_trait::async_trait;
use quil_types::error::Result;
use quil_types::proto::global::AppShardFrame;

/// Syncs the global prover tree (vertex-adds set for the global
/// intrinsic address) from an archive. Returns `true` if the
/// locally-recomputed root matches `expected_root` after sync.
///
/// Implementations should:
/// 1. Connect to an archive endpoint (mTLS)
/// 2. Pull the prover tree via `ensure_prover_tree_incremental`
/// with `expected_root` pinned
/// 3. Return whether the final root matches
#[async_trait]
pub trait ProverTreeSyncer: Send + Sync {
    /// Sync the global prover tree, pinning EACH phase to `expected_roots[phase]`
    /// — `[prover_tree_commitment (phase 0), prover_tree_aux_roots (1,2,3)]` from
    /// the global header (all four phases anchored). Empty slice ⇒
    /// trust the peer (bootstrap). Returns `Ok(true)` if post-sync roots match,
    /// `Ok(false)` if the sync completed but roots still diverge, `Err` on failure.
    async fn sync_prover_tree(&self, expected_roots: &[Vec<u8>]) -> Result<bool>;

    /// Sync a specific app-shard's subtrees from an archive, pinning EACH of
    /// the four phases to `expected_roots[phase]` — the finalized header's
    /// `state_roots` (all four phases anchored, not just vertex-adds).
    /// Used to catch a shard's CRDT up after a frame gap / restart / late-join.
    /// `filter` is the shard filter; the impl derives the `ShardKey`.
    /// An empty entry (or empty slice) trusts the peer for that phase
    /// (bootstrap). Default is a no-op (`Ok(false)`) for syncers without shard
    /// sync.
    async fn sync_shard_tree(&self, _filter: &[u8], _expected_roots: &[Vec<u8>]) -> Result<bool> {
        Ok(false)
    }

    /// Fetch an app-shard frame from an archive. `frame_number == 0` requests
    /// the latest frame and is used to seed an empty worker's clock lineage.
    async fn get_app_shard_frame(&self, _filter: &[u8], _frame_number: u64) -> Result<Option<AppShardFrame>> {
        Ok(None)
    }
}

pub(crate) enum ShardSyncResult {
    Anchored { anchor: AppShardFrame, predecessor: Option<AppShardFrame> },
    /// `pinned`: the origins' sealed state, verified against their roots;
    /// otherwise the archive's current subtree, unauthenticated.
    Inherited { pinned: bool },
    /// Why nothing usable was installed.
    NotReady(&'static str),
}

/// The owning actor authenticates and installs a checkpoint. A recovery task
/// keeps this exact target through completion, even if a worker is reassigned.
#[async_trait]
pub(crate) trait ShardRecoveryTarget: Send + Sync {
    fn materialized(&self) -> u64;
    /// `child`: the certified frame after `frame`, when `frame` has no
    /// certificate of its own and is final only through it.
    async fn replay(&self, frame: AppShardFrame, child: Option<AppShardFrame>) -> Result<u64>;
    async fn validate(&self, anchor: AppShardFrame, predecessor: Option<AppShardFrame>) -> Result<bool>;
    async fn install(&self, anchor: AppShardFrame, predecessor: Option<AppShardFrame>) -> Result<()>;
    fn inherited(&self);
    /// `(source filter, sealed roots)` of the certified state a shard with no
    /// frame of its own syncs against (`app_handoff::origin_anchors`).
    async fn origin_anchors(&self) -> Result<Vec<(Vec<u8>, [[u8; 32]; 4])>> {
        Ok(Vec::new())
    }
    /// The frame GLOBAL has executed the shard's current session through
    /// (`app_handoff::committed_tip`): replay targets at least this, and an
    /// archive below it is behind, not a sign the worker is up to date.
    async fn committed_tip(&self) -> Option<u64> {
        None
    }
}

#[async_trait]
impl ShardRecoveryTarget for crate::app_engine::AppEngineHandle {
    fn materialized(&self) -> u64 { self.materialized_frame() }
    async fn replay(&self, frame: AppShardFrame, child: Option<AppShardFrame>) -> Result<u64> {
        self.replay_archive_frame(frame, child).await
    }
    async fn validate(&self, anchor: AppShardFrame, predecessor: Option<AppShardFrame>) -> Result<bool> {
        self.validate_sync_anchor(anchor, predecessor).await
    }
    async fn install(&self, anchor: AppShardFrame, predecessor: Option<AppShardFrame>) -> Result<()> {
        self.complete_archive_sync(anchor, predecessor).await
    }
    fn inherited(&self) {
        self.send(crate::app_engine::AppEngineMessage::ShardSyncCompleted { synced_to_frame: 0 });
    }
    async fn origin_anchors(&self) -> Result<Vec<(Vec<u8>, [[u8; 32]; 4])>> {
        crate::app_engine::AppEngineHandle::origin_anchors(self).await
    }
    async fn committed_tip(&self) -> Option<u64> {
        crate::app_engine::AppEngineHandle::committed_tip(self).await
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ShardRecoveryProgress {
    /// `archive_tip`: the highest tip an archive reported (`None`: none had a
    /// frame of the shard). `committed_tip`: GLOBAL's executed frame of the
    /// session. Materialized below the committed tip is not up to date.
    Replayed { materialized: u64, archive_tip: Option<u64>, committed_tip: Option<u64> },
    Anchored { frame: u64 },
    Inherited { pinned: bool },
    NotReady(&'static str),
}

impl std::fmt::Display for ShardRecoveryProgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tip = |tip: &Option<u64>| tip.map_or_else(|| "none".to_string(), |tip| tip.to_string());
        match self {
            Self::Replayed { materialized, archive_tip, committed_tip } => write!(f,
                "replayed to frame {materialized} (archive tip {}, committed tip {})", tip(archive_tip), tip(committed_tip)),
            Self::Anchored { frame } => write!(f, "installed the archive checkpoint at frame {frame}"),
            Self::Inherited { pinned: true } => f.write_str("inherited the origins' sealed state"),
            Self::Inherited { pinned: false } => f.write_str("inherited the covered archive subtree, unpinned"),
            Self::NotReady(reason) => f.write_str(reason),
        }
    }
}

/// Common recovery path for thread and separate-process workers. A saved
/// lineage replays certified bodies; an empty worker fetches and authenticates
/// the archive checkpoint before tree writes, then waits for actor installation.
pub(crate) async fn recover_shard_from_latest(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    local: Option<AppShardFrame>,
    target: &dyn ShardRecoveryTarget,
) -> Result<ShardRecoveryProgress> {
    use crate::worker_execution::recovery_phase;
    if let Some(local) = local {
        recovery_phase("replaying_frames");
        let committed_tip = target.committed_tip().await;
        let replay = replay_shard_from_latest(
            syncer, filter, local, target.materialized(), committed_tip, |frame, child| target.replay(frame, child),
        ).await?;
        return Ok(ShardRecoveryProgress::Replayed {
            materialized: replay.materialized, archive_tip: replay.archive_tip, committed_tip,
        });
    }
    let anchors = target.origin_anchors().await.unwrap_or_else(|error| {
        tracing::warn!(filter = %hex::encode(filter), %error, "origin anchors unavailable; bootstrap unpinned");
        Vec::new()
    });
    recovery_phase("fetching_checkpoint");
    match sync_shard_from_latest(syncer, filter, None, &anchors, |anchor, predecessor| target.validate(anchor, predecessor)).await? {
        ShardSyncResult::Anchored { anchor, predecessor } => {
            let frame = anchor.header.as_ref().map_or(0, |header| header.frame_number);
            recovery_phase("installing_checkpoint");
            target.install(anchor, predecessor).await?;
            Ok(ShardRecoveryProgress::Anchored { frame })
        }
        ShardSyncResult::Inherited { pinned } => { target.inherited(); Ok(ShardRecoveryProgress::Inherited { pinned }) }
        ShardSyncResult::NotReady(reason) => Ok(ShardRecoveryProgress::NotReady(reason)),
    }
}

/// Archives asked for a shard's tip when the first answer is behind GLOBAL's
/// committed session tip, and attempts per frame: each request goes to the
/// next archive in the pool.
const TIP_PROBES: usize = 3;
const FRAME_ATTEMPTS: usize = 3;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ShardReplay {
    pub materialized: u64,
    /// The highest tip an archive reported; `None` when none had a frame.
    pub archive_tip: Option<u64>,
    pub target: u64,
}

/// A frame of `filter` from the first of `attempts` archive requests that has
/// it. `Ok(None)` when every archive answered without it.
async fn fetch_shard_frame(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    number: u64,
    attempts: usize,
) -> Result<Option<AppShardFrame>> {
    let mut failure = None;
    let mut answered = false;
    for _ in 0..attempts.max(1) {
        match syncer.get_app_shard_frame(filter, number).await {
            Ok(Some(frame)) => return Ok(Some(frame)),
            Ok(None) => answered = true,
            Err(error) => failure = Some(error),
        }
    }
    match failure {
        Some(error) if !answered => Err(error),
        _ => Ok(None),
    }
}

/// Repair a materialized worker by replaying a bounded number of certified
/// frames through its owning engine. Tree-only fast-forward loses fee, spend,
/// settlement and accumulator history and can race normal materialization.
///
/// The target is the highest archive tip, and at least `committed` (GLOBAL's
/// executed frame of the session): an archive can answer with an old tip, or
/// none, while it or another holds the frames, so one archive's answer alone
/// never ends recovery below what GLOBAL has executed. Every frame is still
/// authenticated by `replay`.
pub(crate) async fn replay_shard_from_latest<F, Fut>(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    local: AppShardFrame,
    mut materialized: u64,
    committed: Option<u64>,
    mut replay: F,
) -> Result<ShardReplay>
where
    F: FnMut(AppShardFrame, Option<AppShardFrame>) -> Fut,
    Fut: std::future::Future<Output = Result<u64>>,
{
    use prost::Message;
    use quil_types::error::QuilError;
    let height = |frame: &AppShardFrame| frame.header.as_ref().map_or(0, |h| h.frame_number);
    let committed = committed.unwrap_or(0);
    let mut remote: Option<AppShardFrame> = None;
    let mut failure = None;
    for probe in 0..TIP_PROBES {
        if probe > 0 && remote.as_ref().map_or(0, height).max(height(&local)) >= committed {
            break;
        }
        match syncer.get_app_shard_frame(filter, 0).await {
            Ok(Some(frame)) if frame.header.as_ref().is_some_and(|h| h.address == filter) => {
                if remote.as_ref().is_none_or(|best| height(&frame) > height(best)) {
                    remote = Some(frame);
                }
            }
            Ok(Some(_)) if probe == 0 && committed == 0 => {
                return Err(QuilError::InvalidArgument("wrong-shard archive replay tip".into()));
            }
            Ok(_) => {}
            Err(error) => failure = Some(error),
        }
    }
    if remote.is_none() {
        if let Some(error) = failure.filter(|_| committed <= height(&local)) {
            return Err(error);
        }
    }
    let archive_tip = remote.as_ref().map(height);
    let tip = match remote {
        Some(remote) if height(&remote) >= height(&local) => remote,
        _ => local,
    };
    if tip.header.as_ref().is_none_or(|h| h.address != filter) {
        return Err(QuilError::InvalidArgument("wrong-shard archive replay tip".into()));
    }
    let tip_height = height(&tip);
    let target = tip_height.max(committed);
    if archive_tip.unwrap_or(0) < committed && materialized < committed {
        tracing::info!(filter = %hex::encode(filter), materialized, ?archive_tip, committed_tip = committed,
            "archive shard tip is behind GLOBAL's committed session tip; replaying by frame number");
    }
    for _ in 0..32 {
        if materialized >= target { break; }
        let next = materialized + 1;
        let frame = if next == tip_height {
            tip.clone()
        } else {
            fetch_shard_frame(syncer, filter, next, FRAME_ATTEMPTS).await?.ok_or_else(|| {
                QuilError::ExecutionUnavailable(format!(
                    "archive replay is missing shard frame {next} (archive tip {archive_tip:?}, committed {committed})"
                ))
            })?
        };
        if frame.header.as_ref().is_none_or(|h| h.address != filter || h.frame_number != next)
            || frame.encoded_len() > 16 * 1024 * 1024 {
            return Err(QuilError::InvalidArgument("invalid or oversized archive replay frame".into()));
        }
        // A frame with no certificate of its own is final only through the
        // certified frame after it, which the replay authenticates it by.
        let uncertified = frame.header.as_ref()
            .and_then(|header| header.public_key_signature_bls48581.as_ref())
            .is_none_or(|signature| signature.signature.is_empty());
        let child = if !uncertified {
            None
        } else if next + 1 == tip_height {
            Some(tip.clone())
        } else {
            fetch_shard_frame(syncer, filter, next + 1, FRAME_ATTEMPTS).await?
        };
        let advanced = replay(frame, child).await?;
        if advanced < next {
            return Err(QuilError::ExecutionUnavailable("archive replay did not materialize its frame".into()));
        }
        materialized = advanced;
    }
    Ok(ShardReplay { materialized, archive_tip, target })
}

/// A stale worker must discover the archive tip even when it has a local
/// clock head. Authenticate the selected chain before installing any leaves.
/// The validator runs on the engine that owns the worker's committee view.
pub(crate) async fn sync_shard_from_latest<F, Fut>(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    local: Option<AppShardFrame>,
    origin_anchors: &[(Vec<u8>, [[u8; 32]; 4])],
    validate: F,
) -> Result<ShardSyncResult>
where
    F: FnOnce(AppShardFrame, Option<AppShardFrame>) -> Fut,
    Fut: std::future::Future<Output = Result<bool>>,
{
    use crate::worker_execution::recovery_phase;
    use quil_types::error::QuilError;
    let remote = syncer.get_app_shard_frame(filter, 0).await?;
    let height = |frame: &AppShardFrame| frame.header.as_ref().map_or(0, |h| h.frame_number);
    let anchor = match (local, remote) {
        (Some(local), Some(remote)) if height(&local) > height(&remote) => Some(local),
        (_, Some(remote)) => Some(remote),
        (local, None) => local,
    };
    let Some(anchor) = anchor else {
        // A new child without a certified frame of its own holds its origins'
        // state. Sync each origin's range pinned to its sealed roots, which the
        // sync verifies; the origins partition the child's range. Without
        // certified origins, or when no archive still resolves them (retention),
        // inherit the covered archive subtree unpinned, as before.
        recovery_phase("installing_leaves");
        if !origin_anchors.is_empty() {
            let mut pinned = true;
            for (source, roots) in origin_anchors {
                let pinned_roots: Vec<Vec<u8>> = roots.iter().map(|root| root.to_vec()).collect();
                let failure = match syncer.sync_shard_tree(source, &pinned_roots).await {
                    Ok(true) => continue,
                    Ok(false) => "the archive does not hold it or the synced roots differ".to_string(),
                    Err(error) => error.to_string(),
                };
                tracing::warn!(filter = %hex::encode(filter), source = %hex::encode(source),
                    sealed_roots = ?roots.iter().map(hex::encode).collect::<Vec<_>>(), %failure,
                    "origin's sealed state could not be synced");
                pinned = false;
                break;
            }
            if pinned {
                tracing::info!(filter = %hex::encode(filter), origins = origin_anchors.len(),
                    "shard bootstrapped from its origins' sealed state");
                return Ok(ShardSyncResult::Inherited { pinned: true });
            }
            // A same-filter origin's sealed roots are what this shard's
            // successor requires at startup (`successor_state_matches`): an
            // unpinned copy is refused there unless it equals them, and the
            // worker installed it, reported success and was refused again
            // every few seconds. Wait for an archive that holds the state.
            if origin_anchors.iter().any(|(source, _)| source.as_slice() == filter) {
                tracing::warn!(filter = %hex::encode(filter),
                    "the predecessor's sealed state is not available from the archive; not inheriting unpinned state its successor would refuse");
                return Ok(ShardSyncResult::NotReady("the predecessor's sealed state is not available from the archive"));
            }
            tracing::warn!(filter = %hex::encode(filter),
                "origins' sealed state is not available from the archive; inheriting the covered subtree unpinned");
        } else {
            tracing::info!(filter = %hex::encode(filter),
                "no certified origin state for this shard; inheriting the covered subtree unpinned");
        }
        return Ok(if syncer.sync_shard_tree(filter, &[]).await? {
            ShardSyncResult::Inherited { pinned: false }
        } else { ShardSyncResult::NotReady("the archive could not supply the covered subtree") });
    };
    let header = anchor.header.as_ref().ok_or_else(|| QuilError::InvalidArgument("archive anchor has no header".into()))?;
    if header.address != filter || header.frame_number == 0
        || header.state_roots.len() != 4 || header.state_roots.iter().any(|root| root.len() != 32) {
        return Err(QuilError::InvalidArgument("malformed or wrong-shard archive anchor".into()));
    }
    let expected_roots = header.state_roots.clone();
    let predecessor = if header.frame_number > 1 {
        syncer.get_app_shard_frame(filter, header.frame_number - 1).await?
    } else { None };
    if !validate(anchor.clone(), predecessor.clone()).await? {
        return Ok(ShardSyncResult::NotReady("the archive checkpoint failed validation"));
    }
    recovery_phase("installing_leaves");
    Ok(if syncer.sync_shard_tree(filter, &expected_roots).await? {
        ShardSyncResult::Anchored { anchor, predecessor }
    } else { ShardSyncResult::NotReady("the archive does not hold the checkpoint's state, or its roots differ") })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct Target {
        calls: Arc<Mutex<Vec<String>>>,
        cursor: std::sync::atomic::AtomicU64,
        valid: bool,
        install_ok: bool,
    }
    #[async_trait]
    impl ShardRecoveryTarget for Target {
        fn materialized(&self) -> u64 { self.cursor.load(std::sync::atomic::Ordering::SeqCst) }
        async fn replay(&self, frame: AppShardFrame, _child: Option<AppShardFrame>) -> Result<u64> {
            let number = frame.header.unwrap().frame_number;
            assert_eq!(number, self.materialized()+1);
            self.calls.lock().unwrap().push(format!("replay {number}"));
            self.cursor.store(number, std::sync::atomic::Ordering::SeqCst);
            Ok(number)
        }
        async fn validate(&self, anchor: AppShardFrame, predecessor: Option<AppShardFrame>) -> Result<bool> {
            let number = anchor.header.unwrap().frame_number;
            assert_eq!(predecessor.unwrap().header.unwrap().frame_number, number-1);
            self.calls.lock().unwrap().push(format!("validate {number}"));
            Ok(self.valid)
        }
        async fn install(&self, anchor: AppShardFrame, _: Option<AppShardFrame>) -> Result<()> {
            let number = anchor.header.unwrap().frame_number;
            self.calls.lock().unwrap().push(format!("install {number}"));
            if !self.install_ok { return Err(quil_types::error::QuilError::ExecutionUnavailable("actor rejected checkpoint".into())); }
            self.cursor.store(number, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        fn inherited(&self) { panic!("a certified archive tip must never use unanchored inheritance") }
    }

    #[tokio::test]
    async fn headless_worker_recovers_from_archive_and_waits_for_authenticated_installation() {
        for (valid, install_ok) in [(true, true), (false, true), (true, false)] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let archive = Archive { latest:Some(frame(500)), calls:calls.clone() };
            let target = Target { calls:calls.clone(), cursor:0.into(), valid, install_ok };
            let result = recover_shard_from_latest(&archive, &[5;32], None, &target).await;
            let mut expected = vec!["fetch 0", "fetch 499", "validate 500"];
            if valid { expected.extend(["sync 244", "install 500"]); }
            assert_eq!(*calls.lock().unwrap(), expected);
            if !valid { assert_eq!(result.unwrap(), ShardRecoveryProgress::NotReady("the archive checkpoint failed validation")); }
            else if !install_ok { assert!(result.is_err()); }
            else { assert_eq!(result.unwrap(), ShardRecoveryProgress::Anchored { frame:500 }); }
            assert_eq!(target.materialized(), if valid && install_ok { 500 } else { 0 });
        }
    }

    #[tokio::test]
    async fn existing_worker_lineage_replays_instead_of_replacing_its_tree() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest:Some(frame(500)), calls:calls.clone() };
        let target = Target { calls:calls.clone(), cursor:129.into(), valid:false, install_ok:false };
        let result = recover_shard_from_latest(&archive, &[5;32], Some(frame(130)), &target).await.unwrap();
        assert_eq!(result, ShardRecoveryProgress::Replayed { materialized:161, archive_tip:Some(500), committed_tip:None });
        let calls = calls.lock().unwrap();
        assert_eq!(calls.iter().filter(|s| s.starts_with("replay ")).count(), 32);
        assert!(!calls.iter().any(|s| s.starts_with("sync ") || s.starts_with("install ")));
    }

    struct Archive {
        latest: Option<AppShardFrame>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    /// A certified frame (its certificate is not checked here).
    fn frame(number: u64) -> AppShardFrame {
        AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                address: vec![5; 32], frame_number: number,
                state_roots: vec![vec![number as u8; 32]; 4],
                public_key_signature_bls48581: Some(quil_types::proto::keys::Bls48581AggregateSignature {
                    signature: vec![1], ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[async_trait]
    impl ProverTreeSyncer for Archive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
        async fn get_app_shard_frame(&self, _: &[u8], number: u64) -> Result<Option<AppShardFrame>> {
            self.calls.lock().unwrap().push(format!("fetch {number}"));
            Ok(if number == 0 { self.latest.clone() } else { Some(frame(number)) })
        }
        async fn sync_shard_tree(&self, _: &[u8], roots: &[Vec<u8>]) -> Result<bool> {
            self.calls.lock().unwrap().push(format!("sync {}", roots[0][0]));
            Ok(true)
        }
    }

    #[tokio::test]
    async fn stale_local_head_uses_newer_certified_archive_anchor_before_any_tree_write() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(600)), calls: calls.clone() };
        let validate_calls = calls.clone();
        let result = sync_shard_from_latest(&archive, &[5; 32], Some(frame(130)), &[],
            move |anchor, predecessor| async move {
                assert_eq!(anchor.header.unwrap().frame_number, 600);
                assert_eq!(predecessor.unwrap().header.unwrap().frame_number, 599);
                validate_calls.lock().unwrap().push("validate 600".into());
                Ok(true)
            }).await.unwrap();
        assert!(matches!(result, ShardSyncResult::Anchored { .. }));
        assert_eq!(*calls.lock().unwrap(), ["fetch 0", "fetch 599", "validate 600", "sync 88"]);
    }

    #[tokio::test]
    async fn archive_replay_fills_a_stale_workers_gap_in_bounded_batches_without_tree_sync() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(600)), calls: calls.clone() };
        let replayed = Arc::new(Mutex::new(Vec::new()));
        let seen = replayed.clone();
        let result = replay_shard_from_latest(&archive, &[5; 32], frame(130), 129, None,
            move |frame, _child| {
                let height = frame.header.unwrap().frame_number;
                seen.lock().unwrap().push(height);
                async move { Ok(height) }
            }).await.unwrap();
        assert_eq!(result, ShardReplay { materialized: 161, archive_tip: Some(600), target: 600 });
        assert_eq!(*replayed.lock().unwrap(), (130..=161).collect::<Vec<_>>());
        assert_eq!(calls.lock().unwrap().len(), 33);
        assert!(calls.lock().unwrap().iter().all(|call| call.starts_with("fetch ")));
    }

    /// Serves certified frames up to a tip of 134, except frame 132, which
    /// has no certificate of its own.
    struct BareArchive;

    #[async_trait]
    impl ProverTreeSyncer for BareArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
        async fn get_app_shard_frame(&self, _: &[u8], number: u64) -> Result<Option<AppShardFrame>> {
            let mut served = frame(if number == 0 { 134 } else { number });
            if number == 132 {
                served.header.as_mut().unwrap().public_key_signature_bls48581 = None;
            }
            Ok(Some(served))
        }
        async fn sync_shard_tree(&self, _: &[u8], _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
    }

    /// A frame with no certificate of its own is replayed together with the
    /// certified frame after it, which finalized it.
    #[tokio::test]
    async fn archive_replay_hands_an_uncertified_frame_its_certified_child() {
        let replayed = Arc::new(Mutex::new(Vec::new()));
        let seen = replayed.clone();
        let result = replay_shard_from_latest(&BareArchive, &[5; 32], frame(130), 130, None,
            move |frame, child| {
                let height = frame.header.unwrap().frame_number;
                seen.lock().unwrap().push((height, child.map(|child| child.header.unwrap().frame_number)));
                async move { Ok(height) }
            }).await.unwrap();
        assert_eq!(result, ShardReplay { materialized: 134, archive_tip: Some(134), target: 134 });
        assert_eq!(*replayed.lock().unwrap(), vec![(131, None), (132, Some(133)), (133, None), (134, None)]);
    }

    #[tokio::test]
    async fn archive_replay_stops_on_engine_rejection_and_never_skips_the_gap() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(600)), calls: calls.clone() };
        assert!(replay_shard_from_latest(&archive, &[5; 32], frame(130), 129, None,
            |_, _| async { Err(quil_types::error::QuilError::InvalidSignature("rejected certificate".into())) }
        ).await.is_err());
        assert_eq!(*calls.lock().unwrap(), ["fetch 0", "fetch 130"]);
    }

    #[tokio::test]
    async fn rejected_archive_chain_never_installs_its_tree() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(600)), calls: calls.clone() };
        let result = sync_shard_from_latest(&archive, &[5; 32], Some(frame(130)), &[],
            |_, _| async { Ok(false) }).await.unwrap();
        assert!(matches!(result, ShardSyncResult::NotReady(_)));
        assert_eq!(*calls.lock().unwrap(), ["fetch 0", "fetch 599"]);
    }

    /// Holds no frame of the shard; records each tree sync as
    /// `(filter's first byte, pinned root's first byte or None)` and refuses
    /// the pinned sync of `refuse`.
    struct FramelessArchive {
        calls: Arc<Mutex<Vec<(u8, Option<u8>)>>>,
        refuse: Option<Vec<u8>>,
    }

    #[async_trait]
    impl ProverTreeSyncer for FramelessArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
        async fn get_app_shard_frame(&self, _: &[u8], _: u64) -> Result<Option<AppShardFrame>> { Ok(None) }
        async fn sync_shard_tree(&self, filter: &[u8], roots: &[Vec<u8>]) -> Result<bool> {
            self.calls.lock().unwrap().push((filter[0], roots.first().map(|root| root[0])));
            Ok(roots.is_empty() || self.refuse.as_deref() != Some(filter))
        }
    }

    /// A shard with no frame of its own syncs each origin's range pinned to
    /// its sealed roots, and inherits the covered subtree unpinned only when
    /// it has no certified origin or the archive cannot serve one.
    #[tokio::test]
    async fn a_frameless_shard_syncs_its_origins_pinned_to_their_sealed_roots() {
        let child = vec![5; 32];
        let (left, right) = (vec![1; 32], vec![2; 32]);
        let anchors = vec![(left.clone(), [[0x51; 32]; 4]), (right.clone(), [[0x61; 32]; 4])];
        let never = |_: AppShardFrame, _: Option<AppShardFrame>| async { panic!("no frame to validate") };

        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = FramelessArchive { calls: calls.clone(), refuse: None };
        let result = sync_shard_from_latest(&archive, &child, None, &anchors, never).await.unwrap();
        assert!(matches!(result, ShardSyncResult::Inherited { pinned: true }));
        assert_eq!(*calls.lock().unwrap(), [(1, Some(0x51)), (2, Some(0x61))], "pinned, never unpinned");

        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = FramelessArchive { calls: calls.clone(), refuse: Some(right) };
        let result = sync_shard_from_latest(&archive, &child, None, &anchors, never).await.unwrap();
        assert!(matches!(result, ShardSyncResult::Inherited { pinned: false }));
        assert_eq!(*calls.lock().unwrap(), [(1, Some(0x51)), (2, Some(0x61)), (5, None)], "falls back when an origin is unavailable");

        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = FramelessArchive { calls: calls.clone(), refuse: None };
        let result = sync_shard_from_latest(&archive, &child, None, &[], never).await.unwrap();
        assert!(matches!(result, ShardSyncResult::Inherited { pinned: false }));
        assert_eq!(*calls.lock().unwrap(), [(5, None)], "no certified origin: unpinned");
    }

    /// A successor of a same-filter predecessor must start from exactly the
    /// predecessor's sealed state (`successor_state_matches`). When no archive
    /// serves it, an unpinned copy would be installed, reported as success and
    /// refused at startup, over and over: recovery waits instead.
    #[tokio::test]
    async fn an_unavailable_same_filter_seal_is_never_replaced_by_unpinned_state() {
        let filter = vec![5; 32];
        let anchors = vec![(filter.clone(), [[0x71; 32]; 4])];
        let never = |_: AppShardFrame, _: Option<AppShardFrame>| async { panic!("no frame to validate") };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = FramelessArchive { calls: calls.clone(), refuse: Some(filter.clone()) };
        let result = sync_shard_from_latest(&archive, &filter, None, &anchors, never).await.unwrap();
        assert!(matches!(result, ShardSyncResult::NotReady(_)));
        assert_eq!(*calls.lock().unwrap(), [(5, Some(0x71))], "pinned only");
    }

    /// Serves frames through 140, reports `tip` as its latest (`None`: no
    /// latest frame indexed) and records each request.
    struct BehindArchive {
        tip: Option<u64>,
        calls: Arc<Mutex<Vec<u64>>>,
    }

    #[async_trait]
    impl ProverTreeSyncer for BehindArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
        async fn get_app_shard_frame(&self, _: &[u8], number: u64) -> Result<Option<AppShardFrame>> {
            self.calls.lock().unwrap().push(number);
            Ok(match number {
                0 => self.tip.map(frame),
                n if n <= 140 => Some(frame(n)),
                _ => None,
            })
        }
        async fn sync_shard_tree(&self, _: &[u8], _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
    }

    /// An archive whose latest is at or below the worker's head, or that has
    /// none, is not proof the worker is current: GLOBAL's committed session
    /// tip is the target, the tip is probed on further archives, and frames
    /// are requested by number. Past what any archive holds it stops with the
    /// missing frame named, never reporting the worker up to date.
    #[tokio::test]
    async fn replay_targets_the_committed_tip_when_archives_report_an_old_one() {
        for tip in [Some(130), None] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let archive = BehindArchive { tip, calls: calls.clone() };
            let result = replay_shard_from_latest(&archive, &[5; 32], frame(130), 130, Some(137),
                |frame, _| async move { Ok(frame.header.unwrap().frame_number) }).await.unwrap();
            assert_eq!(result, ShardReplay { materialized: 137, archive_tip: tip, target: 137 });
            assert_eq!(calls.lock().unwrap()[..TIP_PROBES], [0; TIP_PROBES], "the tip is asked of more archives");
        }
        let archive = BehindArchive { tip: Some(130), calls: Arc::new(Mutex::new(Vec::new())) };
        let missing = replay_shard_from_latest(&archive, &[5; 32], frame(130), 130, Some(150),
            |frame, _| async move { Ok(frame.header.unwrap().frame_number) }).await.unwrap_err();
        assert!(missing.to_string().contains("missing shard frame 141"), "{missing}");
    }

    #[tokio::test]
    async fn missing_peer_tip_does_not_turn_an_existing_worker_into_unanchored_bootstrap() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: None, calls: calls.clone() };
        let result = sync_shard_from_latest(&archive, &[5; 32], Some(frame(130)), &[],
            |anchor, predecessor| async move {
                assert_eq!(anchor.header.unwrap().frame_number, 130);
                assert_eq!(predecessor.unwrap().header.unwrap().frame_number, 129);
                Ok(false)
            }).await.unwrap();
        assert!(matches!(result, ShardSyncResult::NotReady(_)));
        assert_eq!(*calls.lock().unwrap(), ["fetch 0", "fetch 129"]);

        // A malformed source must be refused even if the supplied validator
        // would accept; no forest call can be made without four exact roots.
        let mut malformed = frame(600);
        malformed.header.as_mut().unwrap().state_roots[0].pop();
        let archive = Archive { latest: Some(malformed), calls: calls.clone() };
        assert!(sync_shard_from_latest(&archive, &[5; 32], None, &[],
            |_, _| async { panic!("malformed anchor reached validator") }).await.is_err());
        assert_eq!(calls.lock().unwrap().last().unwrap(), "fetch 0");
    }
}

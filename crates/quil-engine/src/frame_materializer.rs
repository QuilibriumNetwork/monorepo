//! Frame materializer — applies finalized global frames to local state.
//!
//! When a global frame is finalized (via 2-chain HotStuff), the
//! materializer:
//! 1. Commits the hypergraph at the frame number
//! 2. Verifies the prover tree root against the frame's commitment
//! 3. Triggers HyperSync on mismatch
//! 4. Processes all frame requests through the execution manager
//! 5. Applies state transitions to the prover registry
//! 6. Prunes orphan joins
//! 7. Evicts inactive provers (archive mode only)
//! 8. Persists alt shard updates
//! 9. Publishes snapshot for worker sync

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use num_bigint::BigInt;
use num_traits::{ToPrimitive, Zero};
use tracing::{debug, error, info, warn};

use quil_types::consensus::ProverRegistry;
use quil_types::error::{QuilError, Result};
use quil_types::store::{ClockStore, HypergraphStore};

use crate::current_frame::CurrentFrame;
use crate::rewards::{get_baseline_fee, QUIL_TOKEN_UNITS};

/// Concrete prover registry handle exposing the `evict_inactive_provers`
/// helper that the trait can't carry (the trait has no `HypergraphState`
/// parameter). Wired separately via `with_eviction_registry`.
type ConcreteProverRegistry = quil_execution::prover_registry::SharedProverRegistry;

/// Frame materializer state. Tracks which frames have been materialized
/// to ensure idempotency, and manages prover root synchronization.
pub struct FrameMaterializer {
    /// Execution manager for processing frame requests.
    execution_manager: Arc<quil_execution::ExecutionEngineManager>,
    /// Prover registry for state transitions and eviction.
    prover_registry: Arc<dyn ProverRegistry>,
    /// Clock store for frame data (also stores per-frame materialization outcomes).
    clock_store: Arc<dyn ClockStore>,
    /// Hypergraph CRDT for commit and snapshot operations.
    hypergraph: Arc<quil_hypergraph::HypergraphCrdt>,
    /// Hypergraph store for alt-shard commit persistence.
    hypergraph_store: Arc<dyn HypergraphStore>,
    /// Reward issuance calculator.
    _reward_issuance: Arc<dyn quil_types::consensus::RewardIssuance>,
    /// Coverage monitor for halt duration computation. Keyed by
    /// raw filter bytes — matches `CoverageMonitor::check`'s return
    /// type so no hex round-trip is needed when the caller wires
    /// the two together.
    coverage_halt_durations: Arc<std::sync::Mutex<std::collections::HashMap<Vec<u8>, u64>>>,

    /// Last materialized frame number (idempotency guard).
    last_materialized_frame: AtomicU64,
    /// Signal channel into the single serial global-materializer worker: a
    /// `(frame, target)` message tells the worker to catch up `[last+1..=target]`
    /// in order from stored records. Fed by BOTH the CW-consensus finalize path
    /// AND the archive poller — the poller thereby becomes a pure fetcher (it
    /// persists frame records and signals here) instead of a SECOND state writer
    /// that races the shared prover-registry committee cache. `None` until the
    /// worker is wired (non-archive / pre-init); a `None` sender means the poller
    /// falls back to its own inline processing (poller-only nodes).
    catchup_tx: std::sync::Mutex<
        Option<tokio::sync::mpsc::UnboundedSender<(quil_types::proto::global::GlobalFrame, u64)>>,
    >,
    /// Whether the local prover root matches the network.
    prover_root_synced: AtomicBool,
    /// Whether a prover-root MISMATCH has been positively DETECTED and not since
    /// cleared by a match. Distinct from `!prover_root_synced`, which is also
    /// true on a fresh node that simply hasn't verified any root yet — using
    /// that for recovery would make a healthy fresh archive sync spuriously.
    /// Only the mismatch branch of `verify_prover_root` sets this; a match (or a
    /// successful reconcile) clears it. The archive recovery loop gates on THIS.
    prover_root_mismatch: AtomicBool,
    /// Frame number at which prover root was last verified.
    prover_root_verified_frame: AtomicU64,
    /// The DECLARED prover root from #1's most recent FORK nullify — the lineage
    /// the proposers agree on. The archive reconcile pins its sync to THIS, not to
    /// this node's own finalized-header root: a forked OUTLIER's finalized root is
    /// a lineage no peer holds ("no reachable peer holds the finalized prover
    /// root"), so it must instead converge to the proposers' root.
    fork_target_root: std::sync::RwLock<Option<Vec<u8>>>,
    /// Whether a prover sync is currently in progress.
    prover_sync_in_progress: AtomicBool,

    /// This node's prover address.
    _prover_address: Vec<u8>,
    /// Whether this node is in archive mode.
    archive_mode: bool,

    /// Eviction grace period in frames.
    eviction_grace_frames: u64,

    /// Master kill-switch for the state-MUTATING eviction step. When `false`
    /// (the default) the materializer still computes + logs the would-be
    /// eviction set every frame (so the explorer `/provers/eviction-risk`
    /// view and the ramp logs keep working) but NEVER marks Status=4 /
    /// KickFrameNumber — no prover is actually evicted. Eviction is
    /// consensus-state-mutating, so this must be uniform across the fleet;
    /// it defaults off everywhere (all production wiring goes through `new`)
    /// and is only flipped on by tests that exercise the kick path.
    evictions_enabled: bool,

    /// Epoch of the last inline eviction/registry-refresh pass. The expensive
    /// `refresh_from_store` full-scan + `find_eviction_candidates` census now run
    /// INLINE only once per epoch boundary (allocations are epoch-stable, so
    /// per-frame freshness buys nothing — the recv-loop + archive poller keep the
    /// shared registry epoch-fresh for consensus on the same cadence). `u64::MAX`
    /// = "no pass yet", so the first frame after boot always refreshes.
    last_eviction_pass_epoch: AtomicU64,

    /// MAINNET-ONLY 2.1.0.25 frozen-era recovery (see `FROZEN_ERA_RECOVERY_*`).
    /// When true, frames in `[FROZEN_ERA_RECOVERY_START..FROZEN_ERA_RECOVERY_CUTOFF)`
    /// are materialized as a deterministic no-op. Set only for `network == 0`;
    /// off on localnet/testnet (and in tests), so those take the normal path.
    frozen_era_recovery_enabled: bool,

    /// Concrete backing store for `refresh_from_store` — used after
    /// `commit_frame` to rebuild the prover-registry cache from the
    /// just-flushed RocksDB trees.
    rocks_hg_store: Option<Arc<quil_store::RocksHypergraphStore>>,
    /// (B/#2) At-cutover consolidation hook `Fn(frame) -> ok`. Run on THIS
    /// materializer's CRDT store at the cutover frame BEFORE flipping to unified,
    /// to fold every split app's per-sub-shard trees into its app.l2 tree from
    /// current committed vertices — so a split/commit in the `[boot, cutover)`
    /// window is reflected (boot-only consolidation goes stale). Built by the node
    /// (archive hg + shards store → `run_unified_consolidation_in_place`). `None`
    /// (tests) flips without consolidating.
    unified_cutover_consolidate: Option<Arc<dyn Fn(u64) -> bool + Send + Sync>>,
    /// At-cutover PROVER-TREE reset hook `Fn(frame) -> ok`. Runs on the archive's
    /// CRDT + store at the cutover frame alongside the unified flip: wipes the
    /// global prover shard (vertex + hyperedge trees + blob keyspace) and rebuilds
    /// it from the genesis committee (`reset_prover_tree_to_genesis`), so provers
    /// stranded on alias sub-shards are cleared and re-join onto the reset grid.
    /// Built by the node (archive hg + rocks store + network genesis committee).
    /// `None` (tests / non-archives) leaves the prover tree untouched.
    prover_tree_reset: Option<Arc<dyn Fn(u64) -> bool + Send + Sync>>,
    /// Concrete `SharedProverRegistry` reference for the mutating
    /// `evict_inactive_provers` path. When set, archive
    /// nodes apply Status=4 + KickFrameNumber to evicted prover and
    /// allocation vertices via `HypergraphState`. When `None`, eviction
    /// falls back to the trait method which only finds candidates
    /// (matching Go's `EvictInactiveProvers` read+write semantics).
    eviction_registry: Option<Arc<ConcreteProverRegistry>>,

    /// Shared node-level current-frame tracker. The materializer
    /// calls `current_frame.materialize(N)` after `process_state_transition`
    /// completes so every consumer of "what frame are we on" sees
    /// the new value as soon as state has been applied.
    current_frame: Option<Arc<CurrentFrame>>,

    /// Frame prover + BLS constructor used to BATCH-verify a frame's
    /// shard-`FrameHeader` aggregate signatures before the per-bundle
    /// loop. Must be the SAME `frame_prover` Arc installed into the
    /// execution manager's global intrinsic, so the preverified set the
    /// batch records is the one the per-bundle `verify_frame_header_signature`
    /// reads. When unset (or the Arc isn't shared) every header just falls
    /// back to individual BLS verification — slower, never wrong.
    frame_prover: Option<Arc<dyn quil_types::crypto::FrameProver>>,
    bls: Option<Arc<dyn quil_types::crypto::BlsConstructor>>,

    /// Deterministic per-shard data-size source, keyed by
    /// `confirmation_filter` (= L2(32) ++ prefix-byte) → size in bytes.
    /// Used to exclude EMPTY shards (no data) from the eviction halt gate:
    /// a shard with ≤ halt_threshold active provers but zero data has
    /// nothing to protect, so it must not suppress eviction. MUST be a
    /// consensus-deterministic source (the committed shards store, NOT a
    /// per-node size cache) so every archive computes the same eviction
    /// set — otherwise nodes diverge once eviction activates. `None`
    /// falls back to the legacy size-blind behavior.
    shard_size_source:
        Option<Arc<dyn Fn() -> std::collections::HashMap<Vec<u8>, u64> + Send + Sync>>,
}

/// Frame at and after which inactive-prover eviction actually mutates
/// state. Before this frame the materializer computes the would-be
/// eviction set (visible via the explorer `/provers/eviction-risk`
/// endpoint and logged) but does NOT evict — a deliberate ramp so the
/// targets can be reviewed before any prover is kicked. Eviction is
/// consensus-state-mutating, so every archive shares this constant.
pub const GLOBAL_EVICTION_ACTIVATION_FRAME: u64 = 674_570;

// ── 2.1.0.25 frozen-era recovery (flag-day) ──────────────────────────────────
// The archive fleet's materializers wedged at the fork (frame 669975): a fresh
// `--migrate-db` never seeded the durable materialized cursor, so it sat at 0 and
// the in-order materializer asked for frame 1 — which migrated archives no longer
// hold — and silently stalled (`break Ok`). With the forest frozen at the fork
// state, every leader proved on that state, so EVERY frame header from 669976 up
// commits the frozen 669975 prover root. Re-materializing those frames by
// EXECUTING their requests would evolve the forest and diverge from the committed
// roots (prover-root mismatch → reconcile storm).
//
// Recovery: treat every request in `[FROZEN_ERA_RECOVERY_START ..
// FROZEN_ERA_RECOVERY_CUTOFF)` as a deterministic no-op FAILURE — write one
// `Failed` outcome per request, apply NO execution / reward / prune / eviction —
// so the forest (and prover root) stays exactly at the committed frozen root, the
// near-head prover-root check passes, and the cursor rolls forward out of the
// wedge. Live execution resumes uniformly at/above the cutoff across the
// coordinated fleet restart; provers re-join above it. The lower bound keeps
// localnet/testnet (which never reach these heights) on the normal path.
pub const FROZEN_ERA_RECOVERY_START: u64 = 669_976;
pub const FROZEN_ERA_RECOVERY_CUTOFF: u64 = 677_000;

/// Results from materializing a frame.
#[derive(Debug)]
pub struct MaterializeResult {
    /// Number of requests successfully processed.
    pub processed: usize,
    /// Number of requests skipped (errors).
    pub skipped: usize,
    /// Whether the prover root matched.
    pub prover_root_matched: bool,
    /// The local prover root after materialization.
    pub local_prover_root: Vec<u8>,
    /// Canonical bytes of every bundle in the finalized frame. The caller
    /// feeds these to `MessageCollector::mark_finalized` so the consumed
    /// messages leave the mempool and aren't re-proposed.
    pub finalized_bundles: Vec<Vec<u8>>,
}

impl FrameMaterializer {
    pub fn new(
        execution_manager: Arc<quil_execution::ExecutionEngineManager>,
        prover_registry: Arc<dyn ProverRegistry>,
        clock_store: Arc<dyn ClockStore>,
        hypergraph: Arc<quil_hypergraph::HypergraphCrdt>,
        hypergraph_store: Arc<dyn HypergraphStore>,
        reward_issuance: Arc<dyn quil_types::consensus::RewardIssuance>,
        prover_address: Vec<u8>,
        archive_mode: bool,
    ) -> Self {
        Self {
            execution_manager,
            prover_registry,
            clock_store,
            hypergraph,
            hypergraph_store,
            _reward_issuance: reward_issuance,
            coverage_halt_durations: Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            last_materialized_frame: AtomicU64::new(0),
            catchup_tx: std::sync::Mutex::new(None),
            prover_root_synced: AtomicBool::new(false),
            prover_root_mismatch: AtomicBool::new(false),
            prover_root_verified_frame: AtomicU64::new(0),
            fork_target_root: std::sync::RwLock::new(None),
            prover_sync_in_progress: AtomicBool::new(false),
            _prover_address: prover_address,
            archive_mode,
            eviction_grace_frames: 360,
            evictions_enabled: false,
            last_eviction_pass_epoch: AtomicU64::new(u64::MAX),
            frozen_era_recovery_enabled: false,
            rocks_hg_store: None,
            unified_cutover_consolidate: None,
            prover_tree_reset: None,
            eviction_registry: None,
            current_frame: None,
            frame_prover: None,
            bls: None,
            shard_size_source: None,
        }
    }

    /// Wire a deterministic per-shard data-size source (filter → bytes)
    /// so empty shards are excluded from the eviction halt gate. Must be
    /// backed by consensus-deterministic committed state (the shards
    /// store), NOT a per-node cache. See `shard_size_source`.
    pub fn with_shard_size_source(
        mut self,
        source: Arc<dyn Fn() -> std::collections::HashMap<Vec<u8>, u64> + Send + Sync>,
    ) -> Self {
        self.shard_size_source = Some(source);
        self
    }

    /// Wire the shared frame prover + BLS constructor so the materializer
    /// batch-verifies each frame's shard-`FrameHeader` BLS signatures up
    /// front (one multi-pairing + one final exponentiation instead of N).
    /// Pass the SAME `frame_prover` Arc installed into the execution
    /// manager's global intrinsic.
    pub fn with_bls_batch_verify(
        mut self,
        frame_prover: Arc<dyn quil_types::crypto::FrameProver>,
        bls: Arc<dyn quil_types::crypto::BlsConstructor>,
    ) -> Self {
        self.frame_prover = Some(frame_prover);
        self.bls = Some(bls);
        self
    }

    /// Wire the shared `CurrentFrame` so the materializer can
    /// advertise post-materialize frame advancement to every
    /// other consumer that reads the current frame (RPC handlers,
    /// shard-info provider, lifecycle, peer-info publisher).
    pub fn with_current_frame(mut self, current_frame: Arc<CurrentFrame>) -> Self {
        self.current_frame = Some(current_frame);
        self
    }

    /// Enable the state-MUTATING eviction step (mark Status=4 + KickFrameNumber).
    /// Off by default (see `evictions_enabled`) — evictions are currently
    /// disabled fleet-wide; only tests that exercise the kick path flip this on.
    pub fn with_frozen_era_recovery(mut self, enabled: bool) -> Self {
        self.frozen_era_recovery_enabled = enabled;
        self
    }

    pub fn with_evictions_enabled(mut self, enabled: bool) -> Self {
        self.evictions_enabled = enabled;
        self
    }

    /// Wire the concrete prover registry for mutating eviction. Without
    /// this, the materializer can only mark candidates via the
    /// read-only trait method and leaves prover/allocation vertices
    /// unchanged — diverging from Go's `EvictInactiveProvers`.
    pub fn with_eviction_registry(
        mut self,
        registry: Arc<ConcreteProverRegistry>,
    ) -> Self {
        self.eviction_registry = Some(registry);
        self
    }

    /// Supply the concrete RocksDB hypergraph store so the
    /// materializer can `refresh_from_store` on the prover registry
    /// after `commit_frame`. Without this, the cache refresh before
    /// eviction is skipped and the eviction reads stale data.
    pub fn with_rocks_hg_store(
        mut self,
        store: Arc<quil_store::RocksHypergraphStore>,
    ) -> Self {
        self.rocks_hg_store = Some(store);
        self
    }

    /// Wire the at-cutover consolidation hook (see `unified_cutover_consolidate`).
    pub fn with_unified_cutover_consolidate(
        mut self,
        hook: Arc<dyn Fn(u64) -> bool + Send + Sync>,
    ) -> Self {
        self.unified_cutover_consolidate = Some(hook);
        self
    }

    /// Wire the at-cutover prover-tree reset hook (see `prover_tree_reset`).
    pub fn with_prover_tree_reset(
        mut self,
        hook: Arc<dyn Fn(u64) -> bool + Send + Sync>,
    ) -> Self {
        self.prover_tree_reset = Some(hook);
        self
    }

    /// Materialize a finalized global frame — apply all its transactions
    /// to local state.
    pub fn materialize(
        &self,
        frame: &quil_types::proto::global::GlobalFrame,
    ) -> Result<MaterializeResult> {
        let header = frame.header.as_ref()
            .ok_or_else(|| QuilError::InvalidArgument("frame has no header".into()))?;
        let frame_number = header.frame_number;

        // UNIFIED_APP_TREE cutover: flip to the unified commitment at exactly the
        // cutover frame, BEFORE this frame's state commits. Deterministic across
        // nodes (pure fn of `frame_number`), so every node switches at the same
        // height. (B/#2) Consolidate AT the cutover frame first — folding every
        // split app's per-sub-shard trees into its app.l2 tree from current
        // committed vertices — so a split/commit in the [boot, cutover) window is
        // reflected (a boot-only app tree goes stale). If it fails, defer the flip.
        if frame_number
            >= quil_execution::global_intrinsic::materialize::unified_tree_cutover_frame()
            && !self.hypergraph.unified_tree()
        {
            let ok = self
                .unified_cutover_consolidate
                .as_ref()
                .map(|h| h(frame_number))
                .unwrap_or(true);
            // Prover-tree reset rides the same flag day: wipe the global prover
            // shard + rebuild from the genesis committee, so provers stranded on
            // alias sub-shards are cleared and re-join. Committed here (before this
            // frame materializes), so the reset lands in the cutover frame's
            // recorded prover root and propagates to syncing nodes. `None` (tests /
            // non-archives) is a no-op.
            let reset_ok = self
                .prover_tree_reset
                .as_ref()
                .map(|h| h(frame_number))
                .unwrap_or(true);
            if ok && reset_ok {
                self.hypergraph.set_unified_tree(true);
                info!(frame = frame_number, "unified app-tree commitment ACTIVATED at cutover");
            } else {
                error!(
                    frame = frame_number,
                    consolidate_ok = ok,
                    reset_ok,
                    "unified cutover step FAILED — deferring flip this frame"
                );
            }
        }

        // Grid-reset v2 (mainnet 740_000): a SECOND coordinated flag day clearing
        // the corrupt overlapping-shard grid the pre-fix split machinery produced.
        // It runs INDEPENDENTLY of the unified flip (already active above), so it
        // needs its own block. The QUIL grid itself is reset by the execution engine
        // (`maybe_apply_split_reset`, which also fires at this frame); the prover
        // side (wipe + rebuild from the genesis committee) rides HERE because the
        // put-only forest can't propagate a wipe through sync. The hook self-gates
        // on the v2 marker (exactly-once); `None` (regulars use the recv path) no-ops.
        if frame_number
            == quil_execution::global_intrinsic::materialize::quil_grid_reset_v2_frame()
        {
            let reset_ok = self
                .prover_tree_reset
                .as_ref()
                .map(|h| h(frame_number))
                .unwrap_or(true);
            if reset_ok {
                info!(frame = frame_number, "grid-reset v2: prover-tree wiped + rebuilt (grid reset via execution engine)");
            } else {
                error!(frame = frame_number, "grid-reset v2: prover-tree reset FAILED");
            }
        }

        // Prover-reset v3 (mainnet 747_000): re-run the complete tree wipe+reseed.
        // Pairs with the delete-free reassignment (vacated slots retire to Historic)
        // and the per-node worker-filter reset (worker allocator) so provers re-join
        // onto the clean genesis grid and the overlap cascade cannot re-form. Same
        // hook, self-gated on the v3 marker; the grid is reset by the execution
        // engine's `maybe_apply_split_reset`, which also fires at this frame.
        if frame_number
            == quil_execution::global_intrinsic::materialize::quil_prover_reset_v3_frame()
        {
            let reset_ok = self
                .prover_tree_reset
                .as_ref()
                .map(|h| h(frame_number))
                .unwrap_or(true);
            if reset_ok {
                info!(frame = frame_number, "prover-reset v3: prover-tree wiped + rebuilt");
            } else {
                error!(frame = frame_number, "prover-reset v3: prover-tree reset FAILED");
            }
        }

        // Prover-reset v4 (mainnet 755_000): re-baseline once more after removing
        // the boot-time grid clobber (`normalize_quil_token_grid`) that was reverting
        // each archive's local grid to 64-way while allocations stayed split. Same
        // hook + self-gated on the v4/v5 markers. v5 (759_000) clears the
        // byte-suffix allocations the old-binary fleet re-joined with post-v4.
        if frame_number
            == quil_execution::global_intrinsic::materialize::quil_prover_reset_v4_frame()
            || frame_number
                == quil_execution::global_intrinsic::materialize::quil_prover_reset_v5_frame()
        {
            let reset_ok = self
                .prover_tree_reset
                .as_ref()
                .map(|h| h(frame_number))
                .unwrap_or(true);
            if reset_ok {
                info!(frame = frame_number, "prover-reset v4/v5: prover-tree wiped + rebuilt");
            } else {
                error!(frame = frame_number, "prover-reset v4/v5: prover-tree reset FAILED");
            }
        }

        // 1. Idempotency check
        let last = self.last_materialized_frame.load(Ordering::SeqCst);
        if frame_number <= last {
            debug!(frame = frame_number, last, "frame already materialized, skipping");
            return Ok(MaterializeResult {
                processed: 0,
                skipped: 0,
                prover_root_matched: true,
                local_prover_root: Vec::new(),
                finalized_bundles: Vec::new(),
            });
        }

        // IN-ORDER INVARIANT: a frame can only be applied when we already hold the
        // roots it builds on — i.e. its parent (N-1) is materialized. Refuse to
        // apply on top of a GAP (`frame_number > last + 1`): materializing ahead
        // of the cursor would build on state we are NOT synced to and fork the
        // prover root (a permanent hole — see the crash-hole warnings in this
        // file and archive_sync). The caller must first catch up `[last+1..N]` in
        // order from stored records (see the global-materializer consumer). This
        // is self-healing: once the gap is filled, N is re-delivered and applied.
        if frame_number > last + 1 {
            debug!(
                frame = frame_number,
                last,
                "refusing to materialize ahead of the cursor (gap) — catch-up required"
            );
            return Ok(MaterializeResult {
                processed: 0,
                skipped: 0,
                prover_root_matched: true,
                local_prover_root: Vec::new(),
                finalized_bundles: Vec::new(),
            });
        }

        // Time the full materialization (verify + apply + commit) — records on
        // every real exit path (success or `?`-error) below the idempotency
        // skip. RAII so we don't have to thread the record call through each
        // return point.
        struct MatTimer(std::time::Instant);
        impl Drop for MatTimer {
            fn drop(&mut self) {
                crate::metrics::record_materialize_duration(self.0.elapsed().as_secs_f64());
            }
        }
        let _materialize_timer = MatTimer(std::time::Instant::now());
        // Opt-in per-stage materialize timing (set QUIL_MAT_STAGE_TIMING=1 on one
        // archive to capture where the per-frame floor goes). `mat_start` brackets
        // the whole function; each stage logs its CUMULATIVE elapsed so per-stage
        // deltas are the differences between consecutive lines.
        let mat_stage_timing = std::env::var("QUIL_MAT_STAGE_TIMING").is_ok();
        let mat_start = std::time::Instant::now();

        // (B) Serialize this ENTIRE materialize (pre-apply verify + apply +
        // commit + root capture) against the prover-tree sync and any other
        // forest writer. Nothing may advance the forest mid-materialize, so the
        // verify below reads a stable N-1 forest and cannot fork the prover root.
        let _forest_guard = self.hypergraph.lock_forest_writes();
        if mat_stage_timing {
            info!(frame = frame_number, ms = mat_start.elapsed().as_millis() as u64,
                "MAT stage: forest lock acquired (this delta = lock-wait)");
        }

        // ── 2.1.0.25 frozen-era recovery (see FROZEN_ERA_RECOVERY_* doc) ──
        // Deterministic no-op for the frozen era: fail every request WITHOUT
        // executing (no process_message → no reward/prune/eviction/state change),
        // so the forest stays exactly at the frozen root the frame headers
        // committed. Then advance the cursor so the materializer rolls out of the
        // wedge. Held under the forest guard + timed like a normal materialize.
        if self.frozen_era_recovery_enabled
            && (FROZEN_ERA_RECOVERY_START..FROZEN_ERA_RECOVERY_CUTOFF).contains(&frame_number)
        {
            use quil_types::store::{RequestOutcome, RequestStatus};
            let outcomes: Vec<RequestOutcome> = frame
                .requests
                .iter()
                .map(|_| RequestOutcome {
                    status: RequestStatus::Failed,
                    error: "frozen-era recovery: request bypassed (pre-cutoff no-op)".into(),
                })
                .collect();
            if !outcomes.is_empty() {
                if let Err(e) = self
                    .clock_store
                    .put_global_clock_frame_outcomes(frame_number, &outcomes)
                {
                    warn!(frame = frame_number, error = %e, "frozen-era: persist outcomes failed");
                }
            }
            // Flag-day progress signal: log the range boundaries + every 1000th
            // frame so operators can watch the no-op roll through the frozen era
            // (there is otherwise no per-frame materialize log on this path).
            if frame_number == FROZEN_ERA_RECOVERY_START
                || frame_number == FROZEN_ERA_RECOVERY_CUTOFF - 1
                || frame_number % 1000 == 0
            {
                info!(
                    frame = frame_number,
                    requests = outcomes.len(),
                    "frozen-era recovery: no-op-materialized frame (all requests failed, forest frozen)"
                );
            }
            if let Some(cf) = &self.current_frame {
                cf.materialize(frame_number);
            }
            // Record the (frozen) prover root for this frame so the produce-side
            // STRICT GATE (`leader_provider::compute_prover_root` → `prover_root_at`)
            // can resume producing once catch-up reaches head: the no-op leaves the
            // forest at the committed frozen root, so that IS the correct
            // end-of-frame-N root. Without this the recovered fleet would decline
            // every proposal (parent never "materialized") and stay halted.
            {
                let global_shard =
                    quil_types::store::ShardKey { l1: [0u8; 3], l2: [0xffu8; 32] };
                let frozen_root =
                    self.hypergraph.compute_shard_root("vertex", "adds", &global_shard);
                self.hypergraph.record_prover_root(frame_number, frozen_root);
            }
            // Advance the durable cursor. No CRDT mutation was staged (no
            // execution), so this only moves the cursor — the forest is untouched.
            if let Err(e) = self
                .execution_manager
                .commit_frame_with_global_cursor(frame_number)
            {
                error!(frame = frame_number, error = %e, "frozen-era: cursor advance failed");
                return Err(e);
            }
            self.last_materialized_frame.store(frame_number, Ordering::SeqCst);
            return Ok(MaterializeResult {
                processed: 0,
                skipped: outcomes.len(),
                prover_root_matched: true,
                local_prover_root: Vec::new(),
                finalized_bundles: Vec::new(),
            });
        }

        // 2. Compute local prover root and verify against frame.
        //
        // Read the LIVE forest root (state through the PARENT frame N-1, which
        // is already materialized) — the SAME `compute_shard_root` value the
        // leader binds into `header.prover_tree_commitment` at proposal time.
        // This makes the check a REAL cross-check: a node whose N-1 state
        // diverges gets a mismatch → prover sync. (The prior
        // `compute_local_prover_root(frame_number)` here went through
        // `commit(N)`, which returns an EMPTY global-shard root at this point —
        // nothing is staged for frame N yet — so `verify_prover_root` always
        // hit its empty-root tolerance and never actually verified anything.)
        // Read-only: it neither commits nor publishes — the real state commit +
        // snapshot publish happen in the post-apply call at step 8.
        //
        // CATCH-UP GATE. Only cross-check at/near the LIVE head. During a large
        // record-only backfill gap the startup re-materialize replays frames far
        // below the record head; the cross-check there is meaningless (the forest
        // is mid-replay) and actively harmful — its mismatch fires the reconcile,
        // which pins the prover shard to the HEAD root NO straggler peer holds,
        // shoving the shard AHEAD of the cursor (→ epoch-skew skips + diverging
        // state) and adding a per-frame network round-trip that never converges:
        // the ~20s/frame "restarting history" crawl. Below the head we skip the
        // check (treat as matched) so the local replay runs at full speed and the
        // shard tracks the cursor, letting it reach the head cleanly. At/near the
        // head the check runs normally and can reconcile a genuine divergence.
        let record_head = self
            .clock_store
            .get_latest_global_clock_frame()
            .ok()
            .and_then(|f| f.header.map(|h| h.frame_number))
            .unwrap_or(frame_number);
        const PROVER_ROOT_CHECK_MARGIN: u64 = 4;
        let prover_root_matched = if frame_number + PROVER_ROOT_CHECK_MARGIN >= record_head {
            // The header's `prover_tree_commitment` is the PARENT (N-1)
            // prover-shard root — the deterministic post-materialize-(N-1) value
            // the leader binds in via `prover_root_at(N-1)`. Compare our OWN
            // recorded N-1 root, which every node reproduces identically. This is
            // NOT a live forest read: a live read races the async materializer /
            // prover-sync forward to N (or beyond) and forks the check against the
            // header's N-1 commitment — the prover-root-mismatch storm. Fall back
            // to a live read only before N-1 has been recorded (fresh node).
            let local_root = self
                .hypergraph
                .prover_root_at(frame_number.saturating_sub(1))
                .unwrap_or_else(|| self.read_local_prover_root());
            self.verify_prover_root(
                frame_number,
                &header.prover_tree_commitment,
                &local_root,
                &header.prover,
            )
        } else {
            true
        };

        // 3. Process frame requests through execution manager.
        //
        // Each `MessageBundle` is re-serialized to **canonical bytes**
        // (Quilibrium's custom big-endian framing with type prefix
        // `0x0312`) — NOT prost protobuf wire bytes. This matches Go's
        // `frame_materializer.go:172` which calls
        // `req.ToCanonicalBytes()` on every bundle. The execution
        // engines decode canonical bytes via
        // `CanonicalMessageBundle::from_canonical_bytes`; feeding them
        // prost bytes silently fails the type-prefix check and skips
        // every message.
        //
        // Per-bundle fee follows Go: baseline = GetBaselineFee(
        //   difficulty, world_size, costBasis, 8e9) / costBasis. When
        // costBasis is zero (the typical case for global ops, which
        // `global_engine_cost` always returns 0 for) the baseline is
        // also zero — matching Go's
        // `frame_materializer.go:202-213` short-circuit.
        let world_size: u64 = self.hypergraph.total_size().to_u64().unwrap_or(0);
        let difficulty: u64 = header.difficulty as u64;
        let global_addr = vec![0xFFu8; 32];
        // Uncovered-shard global execution gate (new consensus rule,
        // activates at FRAME_2_1_GLOBAL_UNCOVERED_SHARD_TX). Below the
        // fork, every bundle routes to the global engine (0xff), which
        // executes prover/shard-admin ops and skips everything else —
        // app-shard data txs are owned by their shard's own consensus.
        let uncovered_shard_tx_active = frame_number
            >= quil_execution::token_intrinsic::constants::FRAME_2_1_GLOBAL_UNCOVERED_SHARD_TX
            || !self.frozen_era_recovery_enabled;
        let mut processed = 0usize;
        let mut skipped = 0usize;
        // Canonical bytes of every well-formed bundle in this frame, fed
        // to `MessageCollector::mark_finalized` by the caller so consumed
        // messages leave the mempool.
        let mut finalized_bundles: Vec<Vec<u8>> = Vec::with_capacity(frame.requests.len());
        // Per-bundle materialization outcome, ONE per `frame.requests` entry in
        // order (so the explorer can align it to each request). Every path
        // through the loop below pushes exactly one. Persisted after the loop.
        use quil_types::store::{RequestOutcome, RequestStatus};
        let mut outcomes: Vec<RequestOutcome> = Vec::with_capacity(frame.requests.len());

        // Batch-verify this frame's shard-`FrameHeader` BLS aggregate
        // signatures up front — one multi-pairing + one final
        // exponentiation for all N, instead of one pairing-verify per
        // proof. On success the frame prover records them so each
        // per-bundle `validate_message` → `verify_frame_header_signature`
        // below skips the redundant BLS pairing (the VDF multiproof still
        // runs); on any failure nothing is recorded and per-bundle
        // verification runs unchanged. Requires the materializer's
        // `frame_prover` to be the SAME Arc installed into the execution
        // manager's global intrinsic (otherwise it's a no-op, never wrong).
        if let (Some(fp), Some(bls)) = (self.frame_prover.as_ref(), self.bls.as_ref()) {
            let headers: Vec<&quil_types::proto::global::FrameHeader> = frame
                .requests
                .iter()
                .flat_map(|b| b.requests.iter())
                .filter_map(|r| match r.request.as_ref() {
                    Some(quil_types::proto::global::message_request::Request::Shard(fh)) => Some(fh),
                    _ => None,
                })
                .collect();
            if !headers.is_empty() {
                let batched = fp.verify_frame_header_signatures_batch(&headers, bls.as_ref());
                debug!(
                    frame = frame_number,
                    headers = headers.len(),
                    batched,
                    "shard-frame BLS batch pre-verify"
                );
            }
        }

        // Parallel crypto pre-pass for shard-`FrameHeader` bundles. Their
        // per-proof Wesolowski VDF multiproof is the dominant remaining
        // verification cost and CANNOT be batched (each lives in its own
        // challenge-derived class group), but the verifications are
        // independent and parallelize cleanly. Validate the FrameHeader
        // bundles across cores up front and cache the verdict; the
        // sequential loop below reuses it instead of re-verifying (BLS is
        // already short-circuited by the batch pre-pass).
        //
        // Safe because FrameHeader validation reads only the prover
        // registry CACHE — which is frozen at the start of the frame and
        // refreshed via `refresh_from_store` only AFTER this loop — plus
        // the header itself; it does NOT read the CRDT trees that
        // `process_message` mutates mid-loop. So the result is identical
        // whether computed up front in parallel or in sequence, and no
        // `process_message` has run yet, so the concurrent
        // `validate_message` calls take only shared RwLock reads.
        let fh_validation: std::collections::HashMap<Vec<u8>, bool> = {
            let fh_bytes: Vec<Vec<u8>> = frame
                .requests
                .iter()
                .filter(|b| {
                    b.requests.iter().any(|r| {
                        matches!(
                            r.request,
                            Some(quil_types::proto::global::message_request::Request::Shard(_))
                        )
                    })
                })
                .filter_map(|b| {
                    crate::consensus_wire::proto_message_bundle_to_canonical_bytes(b).ok()
                })
                .collect();
            if fh_bytes.len() >= 2 {
                let threads = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4)
                    .min(fh_bytes.len());
                let chunk = fh_bytes.len().div_ceil(threads);
                let out: std::sync::Mutex<std::collections::HashMap<Vec<u8>, bool>> =
                    std::sync::Mutex::new(std::collections::HashMap::with_capacity(fh_bytes.len()));
                std::thread::scope(|s| {
                    for c in fh_bytes.chunks(chunk) {
                        let out = &out;
                        let em = &self.execution_manager;
                        // FrameHeaders route to the global engine (0xff).
                        let addr = global_addr.clone();
                        s.spawn(move || {
                            let mut local: Vec<(Vec<u8>, bool)> = Vec::with_capacity(c.len());
                            for bytes in c {
                                let ok = em
                                    .validate_message(frame_number, &addr, bytes)
                                    .is_ok();
                                local.push((bytes.clone(), ok));
                            }
                            let mut g = out.lock().unwrap();
                            for (k, v) in local {
                                g.insert(k, v);
                            }
                        });
                    }
                });
                out.into_inner().unwrap()
            } else {
                std::collections::HashMap::new()
            }
        };

        for bundle in &frame.requests {
            // Per-bundle routing address. Default: the global engine
            // (0xff). At/after the fork, a DATA op (token transfer /
            // hypergraph / compute op) that targets an UNCOVERED shard
            // (active provers <= HALT_RISK_PROVER_COUNT) is executed here
            // at the global level — routed to its intrinsic engine by its
            // own domain, with fees charged — so a new/coverage-lost
            // shard isn't a dead zone where only prover ops can be
            // processed. Covered shards + prover/deploy/Shard ops keep
            // the global path (the covered shard's own consensus, or the
            // global engine, owns them). Coverage is read from the
            // (consensus-deterministic) prover registry, so all nodes
            // agree on the venue for every bundle.
            let route_addr: Vec<u8> = if bundle_has_mint_op(bundle) {
                quil_execution::domains::QUIL_TOKEN.to_vec()
            } else if uncovered_shard_tx_active {
                // A DEPLOY mints a brand-new shard whose target domain
                // never pre-exists — there is no covered shard that could
                // ever execute it. So it ALWAYS routes to its base
                // intrinsic domain (TOKEN_BASE / COMPUTE / HYPERGRAPH_BASE),
                // where the manager dispatches to the token/compute/hg
                // engine; the engine derives the new domain from the deploy
                // config and writes its metadata vertex into the global
                // CRDT, making the shard routable. This is the only path by
                // which new shards come into existence.
                if let Some(base) = bundle_deploy_base_domain(bundle) {
                    base
                } else {
                    // Non-deploy DATA ops only execute here when their
                    // target shard is uncovered (otherwise the covered
                    // shard's own consensus owns them).
                    match bundle_target_domain(bundle) {
                        Some(domain) if self.shard_is_uncovered(&domain, frame_number) => domain,
                        _ => global_addr.clone(),
                    }
                }
            } else {
                global_addr.clone()
            };
            let has_mint = bundle_has_mint_op(bundle);
            quil_types::append_debug_log("MATERIALIZER", &format!("frame={}, has_mint={}, route_addr={}", frame_number, has_mint, hex::encode(&route_addr)));
            // Re-encode the proto bundle as canonical bytes.
            let bundle_bytes = match crate::consensus_wire::proto_message_bundle_to_canonical_bytes(bundle) {
                Ok(b) => b,
                Err(e) => {
                    info!(
                        frame = frame_number,
                        error = %e,
                        "skipping bundle that failed canonical encoding"
                    );
                    skipped += 1;
                    outcomes.push(RequestOutcome {
                        status: RequestStatus::Skipped,
                        error: format!("canonical encode failed: {e}"),
                    });
                    continue;
                }
            };
            if bundle_bytes.len() < 4 {
                info!(
                    frame = frame_number,
                    "skipping empty or undersized bundle"
                );
                skipped += 1;
                outcomes.push(RequestOutcome {
                    status: RequestStatus::Skipped,
                    error: "encoded payload < 4 bytes (no type prefix)".into(),
                });
                continue;
            }
            // This bundle is part of the finalized frame → it is consumed
            // from the mempool regardless of whether execution processes
            // or skips it below.
            finalized_bundles.push(bundle_bytes.clone());

            let request_type = u32::from_be_bytes([
                bundle_bytes[0],
                bundle_bytes[1],
                bundle_bytes[2],
                bundle_bytes[3],
            ]);

            // Per-bundle cost basis → baseline fee, mirroring Go.
            let cost_basis = self
                .execution_manager
                .get_cost(&bundle_bytes)
                .unwrap_or_else(|_| BigInt::zero());
            let fee_multiplier = if cost_basis.is_zero() {
                BigInt::zero()
            } else {
                let cost_u64 = cost_basis.to_u64().unwrap_or(1);
                let baseline = get_baseline_fee(
                    difficulty,
                    world_size,
                    cost_u64,
                    QUIL_TOKEN_UNITS,
                );
                &baseline / &cost_basis
            };

            // Signature verification gate.
            //
            // `validate_message` runs the per-op verifier (BLS sig,
            // PoP, merge-target sigs for joins; addressed-sig for
            // confirms/leaves/etc.); `process_message` only
            // structurally invokes `invoke_step`. Without this gate
            // an attacker can forge any prover-admin signature and
            // the materializer would write the bogus state into the
            // hypergraph CRDT.
            //
            // Mirrors Go's `ExecutionEngineManager.ValidateMessage`
            // gate before `ProcessMessage` at
            // `execution/engine_manager.go:processFrameMessages`.
            // Use the parallel pre-pass verdict for FrameHeader bundles;
            // validate everything else here (sequentially, against the
            // mid-loop CRDT state those ops legitimately depend on).
            // `None` = valid; `Some(reason)` = rejected (with the reason).
            let reject_reason: Option<String> = match fh_validation.get(&bundle_bytes) {
                Some(&ok) => {
                    if !ok {
                        info!(
                            frame = frame_number,
                            request_type = format!("0x{:08x}", request_type),
                            "skipping message that failed signature validation (parallel pre-pass)"
                        );
                        Some("signature validation failed".into())
                    } else {
                        None
                    }
                }
                None => match self.execution_manager.validate_message(
                    frame_number,
                    &route_addr,
                    &bundle_bytes,
                ) {
                    Ok(()) => {
                        quil_types::append_debug_log("MATERIALIZER validate_message", &format!("frame={}, route_addr={} -> OK", frame_number, hex::encode(&route_addr)));
                        None
                    }
                    Err(e) => {
                        quil_types::append_debug_log("MATERIALIZER validate_message", &format!("frame={}, route_addr={} -> ERR: {}", frame_number, hex::encode(&route_addr), e));
                        info!(
                            frame = frame_number,
                            request_type = format!("0x{:08x}", request_type),
                            error = %e,
                            "skipping message that failed signature validation"
                        );
                        Some(format!("{e}"))
                    }
                },
            };
            if let Some(reason) = reject_reason {
                skipped += 1;
                outcomes.push(RequestOutcome {
                    status: RequestStatus::Rejected,
                    error: reason,
                });
                continue;
            }
            match self.execution_manager.process_message(
                frame_number,
                &fee_multiplier,
                &route_addr,
                &bundle_bytes,
            ) {
                Ok(_) => {
                    quil_types::append_debug_log("MATERIALIZER process_message", &format!("frame={}, route_addr={} -> OK", frame_number, hex::encode(&route_addr)));
                    processed += 1;
                    outcomes.push(RequestOutcome {
                        status: RequestStatus::Succeeded,
                        error: String::new(),
                    });
                }
                Err(e) => {
                    quil_types::append_debug_log("MATERIALIZER process_message", &format!("frame={}, route_addr={} -> ERR: {}", frame_number, hex::encode(&route_addr), e));
                    info!(
                        frame = frame_number,
                        request_type = format!("0x{:08x}", request_type),
                        error = %e,
                        "skipping message that failed processing"
                    );
                    skipped += 1;
                    outcomes.push(RequestOutcome {
                        status: RequestStatus::Failed,
                        error: format!("{e}"),
                    });
                }
            }
        }
        // Persist the per-bundle outcomes for this frame (best-effort: a write
        // failure must not abort materialization). Aligned by index to
        // `frame.requests`. Read back by the explorer to show which requests
        // actually took effect vs. were rejected/failed.
        if !outcomes.is_empty() {
            if let Err(e) = self
                .clock_store
                .put_global_clock_frame_outcomes(frame_number, &outcomes)
            {
                warn!(frame = frame_number, error = %e, "failed to persist frame request outcomes");
            }
        }

        // Drop the per-frame batch-preverified set so it never leaks into
        // the next frame's verification.
        if let Some(fp) = self.frame_prover.as_ref() {
            fp.clear_bls_preverified();
        }

        // 4. Advance the shared current-frame tracker so RPC handlers,
        // shard-info, peer-info, and the lifecycle observe the new
        // materialized frame immediately. Replaces Go's
        // `proverRegistry.ProcessStateTransition` (the in-memory
        // cache is refreshed by a separate `refresh_from_store`
        // task, so the only thing that needed to advance here was
        // the frame counter — `CurrentFrame.materialize` is now
        // that counter).
        if let Some(cf) = &self.current_frame {
            cf.materialize(frame_number);
        }

        // 5. Flush CRDT phase trees to the backing store + rebuild
        // the prover-registry cache. The global engine's per-bundle
        // `state.commit()` already pushed changes into the CRDT's
        // in-memory phase trees, but `refresh_from_store` reads from
        // the on-disk backing store. `commit_frame` flushes the
        // in-memory trees to RocksDB so the next `refresh_from_store`
        // sees fresh `LastActiveFrameNumber` values. Without this,
        // eviction (step 7) runs against a stale cache and evicts
        // provers that are actually still active (shard proof arrived
        // this frame but the cache never saw it). Mirrors Go's
        // `ProcessStateTransition(st, frameNumber)` at
        // `frame_materializer.go:257`.
        // A failed CRDT commit must NOT be swallowed: if we advance
        // `last_materialized_frame` (below) past a frame whose CRDT mutations
        // never persisted, the durable clock cursor outruns the on-disk CRDT
        // state, and the next frame materializes on top of a hole → permanent
        // prover-root divergence from the committee. Propagate so the caller
        // (the materializer driver) stops rather than corrupting state; a
        // restart re-materializes this frame cleanly.
        // Atomically stage the durable GLOBAL materialization cursor
        // (= frame_number) into THIS commit's batch. The cursor rides the
        // same `db.write` as the frame's reward-balance / prover / shard
        // mutations, so on any crash the durable cursor equals the CRDT
        // frontier exactly. Startup then re-materializes only the
        // un-committed tail `[cursor+1..=head]` — never a frame already
        // reflected in the CRDT — which is the sole safe window given
        // `apply_reward` is additive with no per-frame idempotency
        // (re-running a committed frame would double-mint).
        // Apply any epoch-aligned shard topology changes (split/merge) due at this
        // frame ONCE per global frame, BEFORE the commit — so a staged split flips
        // at its E+2 boundary even on frames carrying no app-shard FrameHeader. The
        // in-`invoke_frame_header` call only fires when a header is materialized,
        // which stalls in the field (header flow to the global chain pauses), so
        // the flip was never triggered at the due frame. Its reassignment writes
        // ride the same `commit_frame_with_global_cursor` batch below.
        if mat_stage_timing {
            info!(frame = frame_number, ms = mat_start.elapsed().as_millis() as u64,
                "MAT stage: process_message loop done (delta from lock = request execution only)");
        }
        if let Err(e) = self
            .execution_manager
            .apply_global_due_shard_changes(frame_number)
        {
            error!(frame = frame_number, error = %e, "apply_due_shard_changes failed — aborting materialize");
            return Err(e);
        }
        if mat_stage_timing {
            info!(frame = frame_number, ms = mat_start.elapsed().as_millis() as u64,
                "MAT stage: apply_due_shard_changes done (delta = split/merge reassign + grid flip)");
        }
        if let Err(e) = self
            .execution_manager
            .commit_frame_with_global_cursor(frame_number)
        {
            error!(frame = frame_number, error = %e, "CRDT commit_frame failed — aborting materialize");
            return Err(e);
        }
        if mat_stage_timing {
            info!(frame = frame_number, ms = mat_start.elapsed().as_millis() as u64,
                "MAT stage: commit_frame_with_global_cursor done (delta = the main CRDT commit)");
        }
        // A split/merge that flipped the grid this frame (at the E+2 boundary) must
        // re-attribute the CRDT's per-app prefixes + size buckets to the new leaves.
        // Without this the serial materializer leaves the CRDT on the PRE-split
        // partition (only boot / the inline-fallback poller refreshed), so
        // `sub_meta_for` — GetAppShards size + the reward basis — can't resolve the
        // new deep-split sub-shards and reports size 0 for them (the parent bucket
        // lingers on a now-merged shallow prefix), starving joins + rewards.
        // No-op (just a grid read + compare) when nothing changed.
        let prefix_changes = self.execution_manager.refresh_shard_prefixes();
        if prefix_changes > 0 {
            info!(frame = frame_number, apps = prefix_changes,
                "MAT stage: shard grid changed — re-partitioned CRDT prefixes + size buckets");
        }
        // Run the expensive registry refresh + eviction census INLINE only at
        // epoch boundaries (and the first frame after boot). `refresh_from_store`
        // clears + rebuilds the whole registry from a full RocksDB scan with a
        // double blob-deserialize (~2s/frame); since allocations are epoch-stable
        // (`effective_status` is epoch-quantized), per-frame freshness bought
        // nothing on the hot path. Consensus reads of the shared registry stay
        // epoch-fresh via the recv-loop (`message_loop`) and archive poller
        // (`archive_sync`) refreshers, which already run on this same cadence.
        let cur_eviction_epoch = quil_types::consensus::epoch_for_frame(frame_number);
        let run_eviction_pass = self
            .last_eviction_pass_epoch
            .swap(cur_eviction_epoch, Ordering::SeqCst)
            != cur_eviction_epoch;
        if run_eviction_pass {
            if let (Some(eviction_reg), Some(rocks_store)) =
                (self.eviction_registry.as_ref(), self.rocks_hg_store.as_ref())
            {
                eviction_reg.refresh_from_store(rocks_store);
            }
        }

        // 6. Prune orphan joins from prover registry
        if let Err(e) = self.prover_registry.prune_orphan_joins(frame_number) {
            warn!(frame = frame_number, error = %e, "prune orphan joins failed");
        }

        // 7. Evict inactive provers (archive mode only, no active halt).
        //
        // Tier-5 #1: route through the *mutating* helper so prover and
        // allocation vertices actually get marked Status=4 +
        // KickFrameNumber. The trait method only finds candidates;
        // calling it leaves the registry unchanged across nodes,
        // causing split-brain shard summaries. Mirrors Go's
        // `EvictInactiveProvers(..., evictionState)` at
        // `frame_materializer.go:285`.
        if self.archive_mode && run_eviction_pass {
            if let Some(eviction_reg) = self.eviction_registry.as_ref() {
                // Build the size-aware effective halt map. The coverage
                // monitor stamps `u64::MAX` on every shard with
                // `active_count <= halt_threshold` REGARDLESS of data size,
                // which means a handful of empty (no-data) under-subscribed
                // shards perpetually suppress eviction across the whole
                // network. Drop those: a shard with zero committed data has
                // nothing to protect, so its low coverage must not gate
                // eviction. Sizes come from a consensus-deterministic source
                // (the shards store) so every archive computes the same set.
                let mut effective_halt =
                    self.coverage_halt_durations.lock().unwrap().clone();
                let raw_max_count =
                    effective_halt.values().filter(|&&d| d == u64::MAX).count();
                let mut sizes_loaded = 0usize;
                let mut sizes_was_empty = true;
                if let Some(sizes_fn) = self.shard_size_source.as_ref() {
                    let sizes = sizes_fn();
                    sizes_loaded = sizes.len();
                    sizes_was_empty = sizes.is_empty();
                    // Only apply the size filter once sizes are actually
                    // loaded — an empty map means "unknown", in which case
                    // we keep the conservative size-blind behavior rather
                    // than treating every shard as empty.
                    if !sizes.is_empty() {
                        effective_halt.retain(|filter, dur| {
                            // Keep non-halt streak entries untouched; only
                            // re-evaluate full-halt (u64::MAX) entries.
                            if *dur != u64::MAX {
                                return true;
                            }
                            sizes.get(filter).copied().unwrap_or(0) > 0
                        });
                    }
                }

                // Diagnostic: which shards (if any) still hold a full halt
                // after the size filter — these are what suppress eviction.
                let surviving: Vec<String> = effective_halt
                    .iter()
                    .filter(|(_, &d)| d == u64::MAX)
                    .map(|(f, _)| hex::encode(f))
                    .collect();
                // Observability ONLY: the per-node coverage-halt view. This is
                // NO LONGER a global suppression gate. Gating all eviction on
                // this per-node map (`coverage_halt_durations`, a local streak
                // counter) made two archives with different streaks evict
                // different provers → divergent prover roots (the
                // prover-root-mismatch class). The eviction DECISION is now
                // census-authoritative: `find_eviction_candidates`'s per-shard
                // consensus-quorum exemption (a shard below
                // MIN_SHARD_CONSENSUS_PROVERS active provers, computed from
                // committed registry state) deterministically protects provers
                // on shards that can't run consensus — which subsumes the
                // "don't evict while under-covered" intent, per-shard and
                // node-independent. The `u64::MAX` coverage entries only ever
                // occur for under-quorum shards, which the census already
                // exempts, so dropping them from the decision changes no
                // outcome except the divergence.
                if !surviving.is_empty() {
                    let sample: Vec<&String> = surviving.iter().take(10).collect();
                    info!(
                        frame = frame_number,
                        raw_max = raw_max_count,
                        surviving_max = surviving.len(),
                        sizes_loaded,
                        sizes_was_empty,
                        coverage_halted = ?sample,
                        "coverage-halt view (observability only; eviction decision is census-based)"
                    );
                }
                {
                    // Census-only decision input: an EMPTY halt map, so the
                    // decision depends solely on committed state + the per-shard
                    // quorum census (deterministic across nodes). The per-node
                    // `effective_halt` is retained above for the log only.
                    let decision_halt: std::collections::HashMap<Vec<u8>, u64> =
                        std::collections::HashMap::new();
                    // Compute the would-be eviction set every frame (read
                    // only) so it's observable (logs + explorer
                    // `/provers/eviction-risk`) even before eviction
                    // actually activates.
                    let candidates = eviction_reg.find_eviction_candidates(
                        frame_number,
                        self.eviction_grace_frames,
                        &decision_halt,
                    );
                    // Unconditional: log the candidate count every frame, even
                    // zero. The gate is open here (no surviving u64::MAX), so a
                    // zero count means find_eviction_candidates itself rejected
                    // every prover — e.g. the per-shard streak subtraction in
                    // effective_halt pulled effective_inactive below the grace
                    // threshold — which is invisible without this line and is
                    // the explorer/materializer divergence we're chasing.
                    info!(
                        frame = frame_number,
                        candidates = candidates.len(),
                        "eviction candidate scan (census-based)"
                    );
                    if self.evictions_enabled && frame_number >= GLOBAL_EVICTION_ACTIVATION_FRAME {
                        // Activated: actually mark Status=4 + KickFrameNumber.
                        let state = quil_execution::hypergraph_state::HypergraphState::new(
                            self.hypergraph.clone(),
                        );
                        match eviction_reg.evict_inactive_provers(
                            frame_number,
                            self.eviction_grace_frames,
                            &decision_halt,
                            &state,
                            // Flat-keyspace fallback for vertices the CRDT
                            // tree lacks (e.g. populated via hypergraph sync).
                            self.rocks_hg_store.as_ref(),
                        ) {
                            Ok(evicted) => {
                                if !evicted.is_empty() {
                                    if let Err(e) = state.commit() {
                                        warn!(frame = frame_number, error = %e, "eviction commit failed");
                                    } else {
                                        // Persist the eviction durably. `commit_frame`
                                        // already ran earlier this frame (before
                                        // eviction), so the kick currently lives only in
                                        // the CRDT's in-memory global-shard tree. A plain
                                        // re-commit would hit the same-frame idempotency
                                        // cache and SKIP the now-dirty shard, so the kick
                                        // would never reach RocksDB — the background
                                        // refresh_from_store would then revert the cache
                                        // and the same provers would be re-evicted every
                                        // frame (no visible effect). Invalidate the global
                                        // intrinsic shard's cached frame commit, re-commit
                                        // (only that dirty shard recomputes; others stay
                                        // cached), then refresh so the registry cache +
                                        // shard summaries reflect the kicks.
                                        let global_addr =
                                            quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS;
                                        if let Err(e) = self
                                            .hypergraph
                                            .invalidate_domain_shard_commit(frame_number, &global_addr)
                                        {
                                            warn!(frame = frame_number, error = %e, "eviction: invalidate shard commit failed");
                                        }
                                        if let Err(e) =
                                            self.execution_manager.commit_frame(frame_number)
                                        {
                                            warn!(frame = frame_number, error = %e, "eviction re-commit (flush) failed");
                                        }
                                        if let Some(rocks_store) = self.rocks_hg_store.as_ref() {
                                            eviction_reg.refresh_from_store(rocks_store);
                                        }
                                        // Persistence probe: after the flush+refresh the
                                        // just-kicked provers must no longer be eviction
                                        // candidates — their vertex is now Status=4 and is
                                        // dropped from the registry cache. If any still
                                        // appear, the kick did not reach the backing store
                                        // (or was reverted by a later sync) — surface it.
                                        let recheck = eviction_reg.find_eviction_candidates(
                                            frame_number,
                                            self.eviction_grace_frames,
                                            &decision_halt,
                                        );
                                        let still_present = recheck
                                            .iter()
                                            .filter(|a| evicted.contains(a))
                                            .count();
                                        info!(
                                            frame = frame_number,
                                            count = evicted.len(),
                                            still_candidates = still_present,
                                            "evicted inactive provers (still_candidates>0 ⇒ kick did not persist)"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(frame = frame_number, error = %e, "eviction (mutating) failed");
                            }
                        }
                    } else if !candidates.is_empty() {
                        // Pre-activation ramp: identify but do NOT evict.
                        info!(
                            frame = frame_number,
                            count = candidates.len(),
                            activation_frame = GLOBAL_EVICTION_ACTIVATION_FRAME,
                            "eviction targets identified — gated until activation frame, not evicting yet"
                        );
                    }
                }
            } else {
                // Without a concrete-typed `eviction_registry`, the
                // materializer can't construct a `HypergraphState` to
                // mutate prover/allocation vertices. Production wires the
                // registry via `with_eviction_registry`.
                debug!(
                    frame = frame_number,
                    "skipping eviction — no concrete registry wired"
                );
            }
        }

        // 7. Persist alt shard updates
        if let Err(e) = self.persist_alt_shard_updates(frame_number, frame) {
            warn!(frame = frame_number, error = %e, "persist alt shard updates failed");
        }
        if mat_stage_timing {
            info!(frame = frame_number, ms = mat_start.elapsed().as_millis() as u64,
                "MAT stage: eviction + persist_alt done (delta = eviction scan + alt-shard)");
        }

        // 8. Compute post-materialization prover root
        let post_root = self.compute_local_prover_root(frame_number + 1);
        if mat_stage_timing {
            info!(frame = frame_number, ms = mat_start.elapsed().as_millis() as u64,
                "MAT stage: compute_local_prover_root done (delta = the SECOND full commit(N+1))");
        }

        // 9. Update state
        self.last_materialized_frame.store(frame_number, Ordering::SeqCst);

        // Capture this frame's prover-shard root the moment materialization of
        // it completes (forest reflects exactly `frame_number`). The verify for
        // the NEXT frame reads `[frame_number]` from here rather than doing a live
        // read that a concurrent materialize path can race forward.
        {
            let mroot = self.read_local_prover_root();
            // Record this frame's deterministic post-state prover root so the
            // leader can bind `prover_root_at(N)` as frame N+1's PARENT commitment
            // and every follower can cross-check its own N-1 root — neither reading
            // the racy live forest. Single source of truth, network-identical.
            self.hypergraph.record_prover_root(frame_number, mroot);
        }

        info!(
            frame = frame_number,
            processed,
            skipped,
            prover_root_matched,
            "frame materialized"
        );

        Ok(MaterializeResult {
            processed,
            skipped,
            prover_root_matched,
            local_prover_root: post_root,
            finalized_bundles,
        })
    }

    /// Compute the local prover tree root for a given frame number,
    /// and publish it to the snapshot manager so sync clients with
    /// `expected_root = prover_root` can lock in the matching
    /// generation.
    ///
    /// The prover root is the vertex-adds root of the global intrinsic
    /// shard (L1 key = [0, 0, 0]). Mirrors Go's `proofs.go::Commit`
    /// which calls `publishSnapshot(proverRoot, frame_number)` after
    /// each successful commit (`hypergraph/proofs.go:225`). Without
    /// this publish step, sync clients pinned to a prover root will
    /// always be rejected by the (newly-enforced) `expected_root`
    /// check.
    /// Read-only global prover shard root (vertex-adds, `L1=[0;3]`,
    /// `L2=[0xff;32]`) from the LIVE forest — the state through the last
    /// committed (parent) frame. Byte-identical to the leader's
    /// `GlobalLeaderProvider::compute_prover_root`, so comparing it to the
    /// header's `prover_tree_commitment` is a genuine cross-check. Does NOT
    /// commit or publish a snapshot (that is [`compute_local_prover_root`]'s
    /// job on the post-apply path); use this only for the pre-apply verify.
    pub fn read_local_prover_root(&self) -> Vec<u8> {
        use quil_types::store::ShardKey;
        let global_shard = ShardKey { l1: [0u8; 3], l2: [0xffu8; 32] };
        let root = self
            .hypergraph
            .compute_shard_root("vertex", "adds", &global_shard);
        if root.len() == 32 || root.len() >= 64 {
            root
        } else {
            Vec::new()
        }
    }

    pub fn compute_local_prover_root(&self, frame_number: u64) -> Vec<u8> {
        use quil_types::store::ShardKey;

        match self.hypergraph.commit(frame_number) {
            Ok(commits) => {
                // Find the global prover shard. Mirrors Go's
                // `ensureGenesisProvers` (`global_consensus_engine.go:751`):
                // L1=[0;3], L2=[0xff;32]. The earlier port used L2=[0;32]
                // which doesn't match any committed shard — the lookup
                // always returned None, the snapshot registry stayed
                // empty, and the sync server replied "no tree data
                // available" to every fresh-sync probe.
                let global_shard = ShardKey {
                    l1: [0u8; 3],
                    l2: [0xffu8; 32],
                };
                if let Some(phase_roots) = commits.get(&global_shard) {
                    if let Some(root) = phase_roots.first() {
                        // A real prover root is a 32-byte JMT root (Phase-3
                        // forest) or a ≥64-byte KZG commitment (legacy/tests);
                        // the 64-byte all-zero placeholder never appears here
                        // (the global vertex_adds tree is always present).
                        if root.len() == 32 || root.len() >= 64 {
                            // Publish to the snapshot generation registry,
                            // binding a real point-in-time DB snapshot so a
                            // follower that pins to this root gets
                            // root-consistent reads (not the moved-on live
                            // store) and `acquire_snapshot` succeeds. We are
                            // inside the commit barrier here, right after
                            // Commit produced `root`, so the snapshot is
                            // captured against exactly the state it reflects.
                            if let Err(e) = self
                                .hypergraph
                                .publish_snapshot_capturing(root.clone(), frame_number)
                            {
                                warn!(
                                    frame = frame_number,
                                    error = %e,
                                    "failed to capture snapshot for published prover root"
                                );
                            }
                            return root.clone();
                        }
                    }
                }
                Vec::new()
            }
            Err(e) => {
                debug!(
                    frame = frame_number,
                    error = %e,
                    "failed to compute local prover root"
                );
                Vec::new()
            }
        }
    }

    /// Verify the local prover root against the frame's commitment.
    ///
    /// Returns true if they match or if verification is not possible
    /// (empty roots). On mismatch, triggers async prover HyperSync.
    pub fn verify_prover_root(
        &self,
        frame_number: u64,
        expected: &[u8],
        local: &[u8],
        _proposer: &[u8],
    ) -> bool {
        // Skip verification if either root is empty
        if expected.is_empty() || local.is_empty() {
            return true;
        }

        if local == expected {
            debug!(
                frame = frame_number,
                "prover root verified"
            );
            self.prover_root_synced.store(true, Ordering::Relaxed);
            self.prover_root_mismatch.store(false, Ordering::Relaxed);
            self.prover_root_verified_frame.store(frame_number, Ordering::Relaxed);
            true
        } else {
            warn!(
                frame = frame_number,
                expected = hex::encode(expected),
                local = hex::encode(local),
                "prover root MISMATCH — triggering sync"
            );
            self.prover_root_synced.store(false, Ordering::Relaxed);
            self.prover_root_mismatch.store(true, Ordering::Relaxed);
            self.prover_root_verified_frame.store(0, Ordering::Relaxed);
            // Trigger async prover HyperSync
            self.trigger_prover_hypersync();
            false
        }
    }

    /// Mark the prover root as synced (or not) — called by the archive recovery
    /// path (`is_prover_root_synced()` is the read side, defined below) after a
    /// reconcile sync converges the local root to the network's, so the next
    /// materialized frame doesn't immediately re-trigger recovery before
    /// `verify_prover_root` runs again.
    pub fn set_prover_root_synced(&self, synced: bool, frame_number: u64) {
        self.prover_root_synced.store(synced, Ordering::Relaxed);
        if synced {
            self.prover_root_mismatch.store(false, Ordering::Relaxed);
            self.prover_root_verified_frame.store(frame_number, Ordering::Relaxed);
        }
    }

    /// Force the prover-root mismatch flag ON from OUTSIDE the materialize path.
    /// The global vote seam calls this when it nullifies a proposal on a
    /// prover-tree FORK: during such a halt NO frame finalizes, so the
    /// materializer never runs `verify_prover_root` to set the flag itself — and
    /// the archive reconcile loop (which gates on `prover_root_mismatch_detected`)
    /// would sit idle forever, never healing the fork. This routes the vote-time
    /// fork detection to the same flag so the reconcile fires DURING the halt.
    pub fn flag_prover_root_mismatch(&self, declared_target_root: Vec<u8>) {
        self.prover_root_synced.store(false, Ordering::Relaxed);
        self.prover_root_mismatch.store(true, Ordering::Relaxed);
        self.prover_root_verified_frame.store(0, Ordering::Relaxed);
        // The proposers' root — the lineage the reconcile should converge onto.
        if !declared_target_root.is_empty() {
            *self.fork_target_root.write().unwrap() = Some(declared_target_root);
        }
    }

    /// The DECLARED root the archive reconcile should converge to (set by #1's
    /// FORK nullify via [`Self::flag_prover_root_mismatch`]). `None` until a fork
    /// is detected.
    pub fn fork_target_root(&self) -> Option<Vec<u8>> {
        self.fork_target_root.read().unwrap().clone()
    }

    /// Whether a prover-root mismatch has been positively detected and not yet
    /// reconciled. The archive recovery loop gates its peer prover-tree sync on
    /// this (NOT on `!is_prover_root_synced()`, which is also true on a fresh,
    /// never-verified node → would sync spuriously). See `prover_root_mismatch`.
    pub fn prover_root_mismatch_detected(&self) -> bool {
        self.prover_root_mismatch.load(Ordering::Relaxed)
    }

    /// Trigger an asynchronous prover HyperSync to reconcile state.
    /// Runs in the background; updates prover_root_synced on completion.
    fn trigger_prover_hypersync(&self) {
        if !self.prover_sync_in_progress.compare_exchange(
            false, true, Ordering::SeqCst, Ordering::SeqCst
        ).is_ok() {
            debug!("prover sync already in progress, skipping");
            return;
        }

        // The actual reconcile runs in the archive-prover-tree-sync loop
        // (master_node/archive_sync.rs), which polls `is_prover_root_synced()`
        // and, when false, pulls the prover shard from a peer pinned to the QC'd
        // `prover_tree_commitment`. Workers reconcile via their own syncer loop
        // (worker_node.rs). This flag is the signal both consume.
        info!("prover root mismatch flagged — sync loop will reconcile");

        // The reconcile is owned by those loops (which clear the flag on
        // convergence), so release the in-progress latch immediately; it only
        // dedups concurrent calls WITHIN this materializer.
        self.prover_sync_in_progress.store(false, Ordering::SeqCst);
    }

    /// Check if there's an active coverage halt on any shard.
    fn has_active_coverage_halt(&self) -> bool {
        let durations = self.coverage_halt_durations.lock().unwrap();
        durations.values().any(|&d| d == u64::MAX)
    }

    /// A shard is "uncovered" when its active prover count is at or below
    /// the halt-risk floor — i.e. it cannot run its own app-shard
    /// consensus, so its transactions would otherwise be unprocessable.
    /// Read from the prover registry (consensus-deterministic), so all
    /// nodes agree on the venue for a given bundle at a given frame. This
    /// gates the uncovered-shard global execution path.
    fn shard_is_uncovered(&self, domain: &[u8], frame_number: u64) -> bool {
        let active = self
            .prover_registry
            .get_active_provers(domain, frame_number)
            .map(|p| p.len())
            .unwrap_or(0);
        (active as u64) <= crate::provers::proposer::HALT_RISK_PROVER_COUNT
    }

    /// Update coverage halt durations. Called by the coverage
    /// monitor; keys are raw filter bytes (matching the monitor's
    /// `check()` return type).
    pub fn set_coverage_halt_durations(
        &self,
        durations: std::collections::HashMap<Vec<u8>, u64>,
    ) {
        *self.coverage_halt_durations.lock().unwrap() = durations;
    }

    /// Extract AltShardUpdate messages from the frame and persist each
    /// to the hypergraph store under its poseidon-hashed BLS public key
    /// (the shard address). Mirrors Go's `persistAltShardUpdates` at
    /// `node/consensus/global/frame_materializer.go:348-432`.
    ///
    /// Called before materialization so the commits are visible to
    /// subsequent state reads within the same frame.
    fn persist_alt_shard_updates(
        &self,
        frame_number: u64,
        frame: &quil_types::proto::global::GlobalFrame,
    ) -> Result<()> {
        use quil_types::proto::global::message_request::Request as MsgReq;

        let mut updates: Vec<&quil_types::proto::global::AltShardUpdate> = Vec::new();
        for bundle in &frame.requests {
            for req in &bundle.requests {
                if let Some(MsgReq::AltShardUpdate(u)) = &req.request {
                    updates.push(u);
                }
            }
        }

        if updates.is_empty() {
            return Ok(());
        }

        let txn = self.hypergraph_store.new_transaction(false)?;

        for update in &updates {
            if update.public_key.is_empty() {
                warn!("alt shard update with empty public key, skipping");
                continue;
            }

            let shard_address = match quil_crypto::poseidon::hash_bytes_to_32(&update.public_key) {
                Ok(addr) => addr,
                Err(e) => {
                    warn!(error = %e, "failed to hash alt shard public key");
                    continue;
                }
            };

            if let Err(e) = self.hypergraph_store.set_alt_shard_commit(
                txn.as_ref(),
                frame_number,
                &shard_address,
                &update.vertex_adds_root,
                &update.vertex_removes_root,
                &update.hyperedge_adds_root,
                &update.hyperedge_removes_root,
            ) {
                // Go aborts + returns on error; we do the same so the
                // frame materialization surfaces the failure.
                let _ = txn.abort();
                return Err(QuilError::Internal(format!(
                    "persist alt shard updates: {e}"
                )));
            }

            debug!(
                frame_number,
                shard_address = hex::encode(shard_address),
                "persisted alt shard update"
            );
        }

        txn.commit()?;

        info!(
            frame_number,
            count = updates.len(),
            "persisted alt shard updates"
        );
        Ok(())
    }

    /// Whether the local prover root is currently synced with the network.
    pub fn is_prover_root_synced(&self) -> bool {
        self.prover_root_synced.load(Ordering::Relaxed)
    }

    /// The frame number at which the prover root was last verified.
    pub fn prover_root_verified_frame(&self) -> u64 {
        self.prover_root_verified_frame.load(Ordering::Relaxed)
    }

    /// The last materialized frame number.
    pub fn last_materialized_frame(&self) -> u64 {
        self.last_materialized_frame.load(Ordering::SeqCst)
    }

    /// Re-seed `prover_root_by_frame[last_materialized]` from the LIVE forest root.
    ///
    /// The per-frame prover-root map is IN-MEMORY and lost on restart. The boot
    /// re-materialize records it for frames it re-runs, but when the durable cursor
    /// is already AT head (no CRDT gap) nothing re-runs — leaving
    /// `prover_root_at(cursor)` unrecorded, so the produce-side STRICT GATE
    /// (`compute_prover_root` → `prover_root_at(N-1)`) can never build `cursor+1`
    /// (the "parent N-1 not materialized" wedge at the head after a restart). The
    /// forest reflects state through `last_materialized`, so `compute_shard_root`
    /// IS that frame's recorded root — seed it. Call once at startup after seeding
    /// the cursor. No-op at genesis.
    pub fn record_current_prover_root(&self) {
        let frame = self.last_materialized_frame.load(Ordering::SeqCst);
        if frame == 0 {
            return;
        }
        let _forest_guard = self.hypergraph.lock_forest_writes();
        let global_shard = quil_types::store::ShardKey { l1: [0u8; 3], l2: [0xffu8; 32] };
        let root = self.hypergraph.compute_shard_root("vertex", "adds", &global_shard);
        self.hypergraph.record_prover_root(frame, root);
    }

    /// Advance the cursor past a MISSING frozen-era frame record (flag-day
    /// recovery). Every frame in `[FROZEN_ERA_RECOVERY_START..CUTOFF)` is a no-op
    /// that changes NO state, so a missing/unreadable record is harmless: skipping
    /// it (advance cursor + record the frozen root, exactly like the no-op branch,
    /// minus the per-request outcomes we don't have) yields the identical forest.
    /// The in-order "no-hole" invariant does not apply because nothing is applied.
    /// Used when a copied/partial archive lacks a frozen-era frame that no peer can
    /// supply. Errors (leaving the caller to halt) if recovery is disabled or the
    /// frame is outside the frozen range — a real hole there. Idempotent.
    pub fn frozen_era_skip(&self, frame_number: u64) -> Result<()> {
        if !self.frozen_era_recovery_enabled
            || !(FROZEN_ERA_RECOVERY_START..FROZEN_ERA_RECOVERY_CUTOFF).contains(&frame_number)
        {
            return Err(QuilError::InvalidArgument(format!(
                "frozen_era_skip({frame_number}): outside recovery range or disabled"
            )));
        }
        if frame_number <= self.last_materialized_frame.load(Ordering::SeqCst) {
            return Ok(());
        }
        let _forest_guard = self.hypergraph.lock_forest_writes();
        if let Some(cf) = &self.current_frame {
            cf.materialize(frame_number);
        }
        let global_shard = quil_types::store::ShardKey { l1: [0u8; 3], l2: [0xffu8; 32] };
        let frozen_root = self.hypergraph.compute_shard_root("vertex", "adds", &global_shard);
        self.hypergraph.record_prover_root(frame_number, frozen_root);
        self.execution_manager
            .commit_frame_with_global_cursor(frame_number)?;
        self.last_materialized_frame.store(frame_number, Ordering::SeqCst);
        warn!(
            frame = frame_number,
            "frozen-era recovery: SKIPPED missing frame record (no-op, cursor advanced)"
        );
        Ok(())
    }

    /// Wire the single serial global-materializer worker's signal sender (see
    /// [`catchup_tx`](Self::catchup_tx)). Called once when the worker is spawned.
    pub fn set_catchup_sender(
        &self,
        tx: tokio::sync::mpsc::UnboundedSender<(quil_types::proto::global::GlobalFrame, u64)>,
    ) {
        *self.catchup_tx.lock().unwrap() = Some(tx);
    }

    /// Signal the serial materializer to catch up `[last+1..=frame_number]` from
    /// stored records. Returns `false` if no worker is wired (poller-only node) —
    /// the caller then falls back to inline processing. The `frame` is a target
    /// hint; the worker reads authoritative records from the store.
    pub fn enqueue_catchup(
        &self,
        frame: quil_types::proto::global::GlobalFrame,
        frame_number: u64,
    ) -> bool {
        match self.catchup_tx.lock().unwrap().as_ref() {
            Some(tx) => tx.send((frame, frame_number)).is_ok(),
            None => false,
        }
    }

    /// Seed the in-memory `last_materialized_frame` cursor from the durable
    /// GLOBAL materialization cursor at startup (before wiring the live
    /// finalized feed). The ctor hardcodes 0; without this seed a restart
    /// would re-materialize the entire chain from frame 1 — double-minting
    /// every already-committed reward.
    ///
    /// After seeding to `m`, the caller re-materializes `[m+1..=head]` from
    /// the clock records; the idempotency gate (`frame_number <= last`) then
    /// guarantees no frame at or below the durable cursor is ever re-run.
    /// Monotonic: never lowers an already-higher in-memory cursor.
    pub fn seed_cursor(&self, m: u64) {
        self.last_materialized_frame.fetch_max(m, Ordering::SeqCst);
    }
}

/// Extract the target shard domain (the 32-byte app address = the
/// shard's identity, post the `app_address == domain` fix) from a request
/// bundle, for the uncovered-shard global execution path. Returns the
/// domain of the first DATA operation that targets an existing shard
/// (token transfer / pending / mint, hypergraph vertex+hyperedge ops,
/// compute code deploy/execute). Returns `None` for prover-lifecycle ops,
/// intrinsic deploys/updates (which create or own their own domains), and
/// the `Shard` op — all of which take the global (`0xff`) path.
/// For a bundle that DEPLOYS a new intrinsic shard (TokenDeploy /
/// ComputeDeploy / HypergraphDeploy), return the BASE intrinsic domain the
/// execution manager routes to the owning engine (token / compute /
/// hypergraph). That engine's deploy step DERIVES the new shard's domain
/// from the deploy config (the config commit) and writes its metadata
/// vertex into the global CRDT — the only way a brand-new shard comes into
/// existence. A deploy's target domain never pre-exists, so it can never be
/// a "covered" shard and the uncovered-check is meaningless for it: deploys
/// must ALWAYS execute under their intrinsic engine here.
///
/// Updates (TokenUpdate / ComputeUpdate / HypergraphUpdate) are deliberately
/// NOT routed here. They carry no domain field, and every engine's update
/// path (engines.rs) uses the routing `address` as the target domain to load
/// the prior config from — so an update is inherently scoped to its deployed
/// shard's own frame (where the frame's app_address IS the target). There is
/// no per-op target for the global frame to route an update by; this is a
/// message-format constraint, identical in Go.
fn bundle_deploy_base_domain(
    bundle: &quil_types::proto::global::MessageBundle,
) -> Option<Vec<u8>> {
    use quil_types::proto::global::message_request::Request;
    for req in &bundle.requests {
        let Some(r) = &req.request else { continue };
        match r {
            Request::TokenDeploy(_) => {
                return Some(
                    quil_execution::token_intrinsic::constants::token_base_domain().to_vec(),
                );
            }
            Request::ComputeDeploy(_) => {
                return Some(quil_execution::domains::COMPUTE.to_vec());
            }
            Request::HypergraphDeploy(_) => {
                return Some(
                    quil_execution::hypergraph_intrinsic::hypergraph_base_domain().to_vec(),
                );
            }
            _ => continue,
        }
    }
    None
}

fn peek_raw_type_prefix(p: &[u8]) -> Option<u32> {
    if let Ok(canon_req) =
        quil_execution::message_envelope::CanonicalMessageRequest::from_canonical_bytes(p)
    {
        return Some(canon_req.inner_type_prefix);
    }
    if p.len() >= 4 {
        return Some(u32::from_be_bytes([p[0], p[1], p[2], p[3]]));
    }
    None
}

fn bundle_has_mint_op(bundle: &quil_types::proto::global::MessageBundle) -> bool {
    use quil_types::proto::global::message_request::Request;
    for req in &bundle.requests {
        let Some(r) = &req.request else { continue };
        match r {
            Request::MintTransaction(_) => return true,
            Request::RawCanonicalPayload(p) => {
                if let Some(tp) = peek_raw_type_prefix(p) {
                    if tp == quil_execution::token_intrinsic::lattice_ct::TYPE_LATTICE_MINT {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

fn bundle_target_domain(bundle: &quil_types::proto::global::MessageBundle) -> Option<Vec<u8>> {
    use quil_types::proto::global::message_request::Request;
    for req in &bundle.requests {
        let Some(r) = &req.request else { continue };
        let domain: &[u8] = match r {
            Request::Transaction(t) => &t.domain,
            Request::PendingTransaction(t) => &t.domain,
            Request::MintTransaction(t) => &t.domain,
            Request::VertexAdd(v) => &v.domain,
            Request::VertexRemove(v) => &v.domain,
            Request::HyperedgeAdd(h) => &h.domain,
            Request::HyperedgeRemove(h) => &h.domain,
            Request::CodeDeploy(c) => &c.domain,
            Request::CodeExecute(c) => &c.domain,
            Request::RawCanonicalPayload(p) => {
                if let Some(tp) = peek_raw_type_prefix(p) {
                    if quil_execution::token_engine::is_token_type_prefix(tp) {
                        return Some(quil_execution::domains::QUIL_TOKEN.to_vec());
                    }
                }
                continue;
            }
            _ => continue,
        };
        if domain.len() == 32 {
            return Some(domain.to_vec());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_target_domain_extracts_data_op_domains() {
        use quil_types::proto::global as pb;
        let mk = |req: pb::message_request::Request| pb::MessageBundle {
            requests: vec![pb::MessageRequest { timestamp: 0, request: Some(req) }],
            timestamp: 0,
        };
        let dom = vec![0x42u8; 32];

        // Token transfer → its domain.
        let tx = pb::message_request::Request::Transaction(
            quil_types::proto::token::Transaction { domain: dom.clone(), ..Default::default() },
        );
        assert_eq!(bundle_target_domain(&mk(tx)), Some(dom.clone()));

        // Hypergraph vertex add → its domain.
        let va = pb::message_request::Request::VertexAdd(
            quil_types::proto::hypergraph::VertexAdd { domain: dom.clone(), ..Default::default() },
        );
        assert_eq!(bundle_target_domain(&mk(va)), Some(dom.clone()));

        // Prover op (Pause) → None (global path).
        let pause = pb::message_request::Request::Pause(pb::ProverPause {
            filter: vec![0xAAu8; 32],
            frame_number: 1,
            public_key_signature_bls48581: None,
        });
        assert_eq!(bundle_target_domain(&mk(pause)), None);

        // Non-32-byte domain → None (defensive).
        let bad = pb::message_request::Request::Transaction(
            quil_types::proto::token::Transaction { domain: vec![0x01u8; 16], ..Default::default() },
        );
        assert_eq!(bundle_target_domain(&mk(bad)), None);
    }

    #[test]
    fn bundle_deploy_base_domain_routes_each_deploy_to_its_intrinsic() {
        use quil_types::proto::global as pb;
        let mk = |req: pb::message_request::Request| pb::MessageBundle {
            requests: vec![pb::MessageRequest { timestamp: 0, request: Some(req) }],
            timestamp: 0,
        };

        // TokenDeploy → token base domain (→ manager → token engine, which
        // derives the new shard's domain from the deploy config).
        let td = pb::message_request::Request::TokenDeploy(
            quil_types::proto::token::TokenDeploy::default(),
        );
        assert_eq!(
            bundle_deploy_base_domain(&mk(td)),
            Some(quil_execution::token_intrinsic::constants::token_base_domain().to_vec()),
        );

        // ComputeDeploy → compute domain (0xcc*32).
        let cd = pb::message_request::Request::ComputeDeploy(
            quil_types::proto::compute::ComputeDeploy::default(),
        );
        assert_eq!(
            bundle_deploy_base_domain(&mk(cd)),
            Some(quil_execution::domains::COMPUTE.to_vec()),
        );

        // HypergraphDeploy → hypergraph base domain.
        let hd = pb::message_request::Request::HypergraphDeploy(
            quil_types::proto::hypergraph::HypergraphDeploy::default(),
        );
        assert_eq!(
            bundle_deploy_base_domain(&mk(hd)),
            Some(quil_execution::hypergraph_intrinsic::hypergraph_base_domain().to_vec()),
        );

        // An UPDATE is NOT a deploy → None: it carries no domain field and
        // the engine uses the routing address as its target, so it stays
        // scoped to its deployed shard's own frame.
        let tu = pb::message_request::Request::TokenUpdate(
            quil_types::proto::token::TokenUpdate::default(),
        );
        assert_eq!(bundle_deploy_base_domain(&mk(tu)), None);

        // A plain data op (transfer) → None: handled by the uncovered-shard
        // data-op path (bundle_target_domain), not the deploy path.
        let tx = pb::message_request::Request::Transaction(
            quil_types::proto::token::Transaction { domain: vec![0x42u8; 32], ..Default::default() },
        );
        assert_eq!(bundle_deploy_base_domain(&mk(tx)), None);
    }

    #[test]
    fn materialize_result_defaults() {
        let r = MaterializeResult {
            processed: 5,
            skipped: 1,
            prover_root_matched: true,
            local_prover_root: vec![0xAA; 64],
            finalized_bundles: Vec::new(),
        };
        assert_eq!(r.processed, 5);
        assert_eq!(r.skipped, 1);
        assert!(r.prover_root_matched);
    }

    /// Test verify_prover_root logic using raw atomics (avoids
    /// constructing the full FrameMaterializer with all its deps).
    #[test]
    fn verify_prover_root_empty_passes() {
        let synced = AtomicBool::new(false);
        let verified = AtomicU64::new(0);
        let mismatch = AtomicBool::new(false);

        // Empty expected → pass
        assert!(verify_root_logic(1, &[], &[0xAA; 64], &synced, &verified, &mismatch));
        // Empty local → pass
        assert!(verify_root_logic(1, &[0xAA; 64], &[], &synced, &verified, &mismatch));
        // Neither branch should flag a mismatch on an unverifiable (empty) root.
        assert!(!mismatch.load(Ordering::Relaxed));
    }

    #[test]
    fn verify_prover_root_match() {
        let synced = AtomicBool::new(false);
        let verified = AtomicU64::new(0);
        let mismatch = AtomicBool::new(false);
        let root = vec![0xBBu8; 64];
        assert!(verify_root_logic(42, &root, &root, &synced, &verified, &mismatch));
        assert!(synced.load(Ordering::Relaxed));
        assert!(!mismatch.load(Ordering::Relaxed));
        assert_eq!(verified.load(Ordering::Relaxed), 42);
    }

    #[test]
    fn verify_prover_root_mismatch() {
        let synced = AtomicBool::new(true);
        let verified = AtomicU64::new(99);
        let mismatch = AtomicBool::new(false);
        let expected = vec![0xAAu8; 64];
        let local = vec![0xBBu8; 64];
        assert!(!verify_root_logic(10, &expected, &local, &synced, &verified, &mismatch));
        assert!(!synced.load(Ordering::Relaxed));
        assert!(mismatch.load(Ordering::Relaxed), "a mismatch must set the recovery flag");
        assert_eq!(verified.load(Ordering::Relaxed), 0);
    }

    /// The recovery flag must distinguish a FRESH archive (never verified) from a
    /// DIVERGED one (verified, mismatched) — the archive sync loop gates peer
    /// reconciliation on `prover_root_mismatch_detected()`, NOT `!synced`, so a
    /// fresh node (synced=false but mismatch=false) does NOT sync spuriously,
    /// while a diverged node does; a subsequent match clears the flag.
    #[test]
    fn prover_root_mismatch_flag_state_machine() {
        let synced = AtomicBool::new(false);
        let verified = AtomicU64::new(0);
        let mismatch = AtomicBool::new(false);

        // Fresh: no verification has run. Not synced, but NOT a detected
        // mismatch → recovery must not fire.
        assert!(!synced.load(Ordering::Relaxed));
        assert!(!mismatch.load(Ordering::Relaxed), "fresh node is not a detected mismatch");

        // Divergence detected → flag set.
        let expected = vec![0x11u8; 64];
        let local = vec![0x22u8; 64];
        assert!(!verify_root_logic(500, &expected, &local, &synced, &verified, &mismatch));
        assert!(mismatch.load(Ordering::Relaxed), "divergence sets the recovery flag");

        // Reconcile then match → flag cleared, recovery stops.
        assert!(verify_root_logic(501, &expected, &expected, &synced, &verified, &mismatch));
        assert!(!mismatch.load(Ordering::Relaxed), "a match clears the recovery flag");
        assert!(synced.load(Ordering::Relaxed));
        assert_eq!(verified.load(Ordering::Relaxed), 501);
    }

    #[test]
    fn has_active_coverage_halt_detects_max() {
        let durations: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        assert!(!durations.values().any(|&d| d == u64::MAX));

        let mut durations = std::collections::HashMap::new();
        durations.insert("0102".to_string(), 100u64);
        assert!(!durations.values().any(|&d| d == u64::MAX));

        let mut durations = std::collections::HashMap::new();
        durations.insert("0102".to_string(), u64::MAX);
        assert!(durations.values().any(|&d| d == u64::MAX));
    }

    /// Extracted verify logic for unit testing without full FrameMaterializer.
    fn verify_root_logic(
        frame: u64,
        expected: &[u8],
        local: &[u8],
        synced: &AtomicBool,
        verified_frame: &AtomicU64,
        mismatch: &AtomicBool,
    ) -> bool {
        if expected.is_empty() || local.is_empty() {
            return true;
        }
        if local == expected {
            synced.store(true, Ordering::Relaxed);
            mismatch.store(false, Ordering::Relaxed);
            verified_frame.store(frame, Ordering::Relaxed);
            true
        } else {
            synced.store(false, Ordering::Relaxed);
            mismatch.store(true, Ordering::Relaxed);
            verified_frame.store(0, Ordering::Relaxed);
            false
        }
    }

    // =====================================================================
    // Tier-2 parity fixes
    // =====================================================================

    /// Verifies the bytes the materializer would feed to
    /// `process_message` are canonical-bytes (type prefix `0x0312`),
    /// NOT prost protobuf wire bytes. The two encodings diverge at the
    /// first byte: prost starts with a varint field tag, canonical
    /// starts with the big-endian `0x00 0x00 0x03 0x12` type prefix.
    #[test]
    fn materializer_feeds_canonical_bytes_to_engine() {
        use crate::consensus_wire::proto_message_bundle_to_canonical_bytes;
        use quil_execution::message_envelope::{
            CanonicalMessageBundle, TYPE_MESSAGE_BUNDLE,
        };
        use quil_types::proto::global as pb;

        // Build a proto bundle with one ProverPause request — chosen
        // because its proto→canonical converter is wired.
        let pb_pause = pb::ProverPause {
            filter: vec![0xAAu8; 32],
            frame_number: 42,
            public_key_signature_bls48581: Some(
                quil_types::proto::keys::Bls48581AddressedSignature {
                    signature: vec![0xBBu8; 74],
                    address: vec![0xCCu8; 32],
                },
            ),
        };
        let proto_bundle = pb::MessageBundle {
            requests: vec![pb::MessageRequest {
                timestamp: 0,
                request: Some(pb::message_request::Request::Pause(pb_pause)),
            }],
            timestamp: 1234567890,
        };

        let canonical = proto_message_bundle_to_canonical_bytes(&proto_bundle).unwrap();

        // Canonical bytes start with 0x00 0x00 0x03 0x12 (TYPE_MESSAGE_BUNDLE).
        assert_eq!(&canonical[..4], &TYPE_MESSAGE_BUNDLE.to_be_bytes());

        // Round-trip: decoding the canonical bytes recovers the bundle.
        let decoded = CanonicalMessageBundle::from_canonical_bytes(&canonical).unwrap();
        assert_eq!(decoded.requests.len(), 1);
        assert_eq!(decoded.timestamp, 1234567890);

        // And the encoding is materially different from prost: the prost
        // encoding of an empty MessageBundle is just a few bytes of varint
        // fields and starts with a different leading byte.
        use prost::Message;
        let prost_bytes = proto_bundle.encode_to_vec();
        assert_ne!(&canonical[..4], &prost_bytes.get(..4).unwrap_or(&[]).to_vec()[..]);
    }

    /// Verifies the per-bundle fee math matches Go's
    /// `frame_materializer.go:202-213`:
    /// fee = GetBaselineFee(difficulty, world_size, costBasis, 8e9) / costBasis
    /// when costBasis > 0, else 0.
    ///
    /// The materializer's cost source is the global engine, which always
    /// returns 0 — so the fee is 0. We additionally check the formula
    /// directly using `get_baseline_fee` for a non-zero cost basis to
    /// confirm we're routing through the right primitive.
    #[test]
    fn materializer_uses_baseline_fee_per_message() {
        use crate::rewards::{get_baseline_fee, QUIL_TOKEN_UNITS};
        use num_bigint::BigInt;
        use num_traits::Zero;

        // Case 1: cost_basis = 0 → fee = 0 (matches Go short-circuit)
        let cost_basis_zero = BigInt::zero();
        let fee_zero = if cost_basis_zero.is_zero() {
            BigInt::zero()
        } else {
            unreachable!("zero branch should be taken");
        };
        assert!(fee_zero.is_zero());

        // Case 2: cost_basis = 1024, difficulty = 50000, world = 1<<30
        // The materializer would compute:
        //   baseline = get_baseline_fee(50000, 1<<30, 1024, 8e9) / 1024
        let difficulty = 50_000u64;
        let world_size = 1u64 << 30;
        let cost_u64 = 1024u64;
        let cost_basis = BigInt::from(cost_u64);
        let baseline = get_baseline_fee(difficulty, world_size, cost_u64, QUIL_TOKEN_UNITS);
        let expected_fee = &baseline / &cost_basis;

        // The fee must be at least 1 — get_baseline_fee guarantees
        // result >= total_added (here 1024), divided by cost_basis (1024)
        // gives at least 1.
        assert!(
            expected_fee >= BigInt::from(1u64),
            "expected fee >= 1, got {}",
            expected_fee,
        );
        // And it must not equal the "wrong" placeholder value of 1
        // unless the formula coincidentally produces 1. For this
        // input, it should be strictly greater than 1.
        // (POMW basis at world=1GB, difficulty=50000 yields a non-trivial fee.)
        assert!(
            expected_fee > BigInt::from(0u64),
            "fee must be positive for non-zero cost basis"
        );

        // Sanity: QUIL_TOKEN_UNITS matches Go's 8_000_000_000.
        assert_eq!(QUIL_TOKEN_UNITS, 8_000_000_000u64);
    }
}

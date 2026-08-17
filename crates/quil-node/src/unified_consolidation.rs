//! On-boot, one-time UNIFIED_APP_TREE consolidation + the cutover-frame gate
//! (Phase-2 `UNIFIED_APP_TREE_DESIGN.md` §9/§10, replacing the manual
//! `--migrate-db` cutover with an automatic startup step).
//!
//! Two decoupled concerns:
//!  1. **Consolidation** — rebuild every SPLIT app's per-sub-shard trees into its
//!     single app tree. Expensive (O(state)) but purely local and idempotent, so
//!     it runs UNCONDITIONALLY on the first boot of a cutover-aware binary (a
//!     persisted marker makes it a no-op after). Running it early — long before
//!     the chain reaches the cutover — guarantees the app trees are ready, so the
//!     commitment flip is always safe.
//!  2. **The commitment flip** — switching to unified roots must be network-atomic
//!     at [`unified_tree_cutover_frame`], exactly like `KICK_AMNESTY_FRAME`, or
//!     nodes fork. So the CRDT flag is a pure function of the head frame: set at
//!     boot from the current head, and flipped per frame by [`gate_unified_at_frame`].

use std::sync::Arc;

use quil_execution::global_intrinsic::materialize::unified_tree_cutover_frame;
use quil_hypergraph::HypergraphCrdt;
use quil_types::store::{ClockStore, ShardsStore};
use tracing::{info, warn};

/// Marker key in the hypergraph RocksDB recording that the one-time
/// split→app-tree consolidation has completed. Its presence makes the boot
/// consolidation a no-op.
const MARKER_KEY: &[u8] = b"\x00__quil_unified_consolidated_v1__";

/// Whether the one-time consolidation has already run on this store.
pub fn is_consolidated(hg: &quil_store::RocksHypergraphStore) -> bool {
    hg.raw_db().get(MARKER_KEY).ok().flatten().is_some()
}

/// Run the one-time consolidation if it hasn't run (idempotent via the persisted
/// marker), then set the CRDT's unified-tree flag from the current head frame.
/// Returns whether unified mode is active after this call. Call once at boot,
/// after the forest is installed and the CRDT's shard-prefix sets are populated.
pub fn boot_consolidate_and_gate(
    hg: &Arc<quil_store::RocksHypergraphStore>,
    shards_store: &dyn ShardsStore,
    clock_store: &dyn ClockStore,
    crdt: &HypergraphCrdt,
) -> bool {
    let head = clock_store
        .get_latest_global_clock_frame()
        .ok()
        .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
        .unwrap_or(0);

    if !is_consolidated(hg) {
        info!(
            head,
            cutover = unified_tree_cutover_frame(),
            "running one-time unified-app-tree consolidation (split apps → single app tree)…"
        );
        match quil_forest_migrate::run_unified_consolidation_in_place(
            hg.as_ref(),
            shards_store,
            0,
            head,
        ) {
            Ok(n) => match hg.raw_db().put(MARKER_KEY, [1u8]) {
                Ok(()) => info!(apps = n, "unified consolidation complete — marker persisted"),
                Err(e) => warn!(
                    error = %e,
                    "unified consolidation done but marker write FAILED — will re-run next boot"
                ),
            },
            Err(e) => {
                warn!(error = %e, "unified consolidation FAILED — staying legacy this boot");
                crdt.set_unified_tree(false);
                return false;
            }
        }
    }

    let active = head >= unified_tree_cutover_frame();
    crdt.set_unified_tree(active);
    info!(head, cutover = unified_tree_cutover_frame(), active, "unified-tree gate set at boot");
    active
}

/// Per-frame flip: once the chain reaches [`unified_tree_cutover_frame`], activate
/// unified mode. Safe to call every frame before commit — a no-op once active,
/// and consolidation is guaranteed to have run at boot. Deterministic across
/// nodes (pure function of the frame number), so the commitment switches at
/// exactly the same height everywhere. Mirror hook exists inline in the engine's
/// materializer for the primary commit path.
pub fn gate_unified_at_frame(
    crdt: &HypergraphCrdt,
    hg: &Arc<quil_store::RocksHypergraphStore>,
    shards_store: &dyn ShardsStore,
    frame_number: u64,
) {
    if frame_number >= unified_tree_cutover_frame() && !crdt.unified_tree() {
        // (B/#2) Consolidate AT the cutover frame (not just boot) so any split in
        // the [boot, cutover) window is folded into the app.l2 tree from current
        // committed vertices. On this (master/poller) CRDT the global prover shard
        // is single, so this is typically a no-op — but it keeps the flip correct
        // for ANY split app the CRDT might hold. Defer the flip if it fails.
        match quil_forest_migrate::run_unified_consolidation_in_place(
            hg.as_ref(),
            shards_store,
            0,
            frame_number,
        ) {
            Ok(_) => {
                crdt.set_unified_tree(true);
                info!(frame = frame_number, "unified app-tree commitment ACTIVATED at cutover");
            }
            Err(e) => {
                warn!(error = %e, frame = frame_number,
                    "cutover consolidation FAILED — deferring flip this frame");
            }
        }
    }
}

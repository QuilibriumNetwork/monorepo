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
///
/// VERSIONED: bump the suffix whenever the consolidation LOGIC changes so every
/// node re-runs the fold exactly once (idempotent — content-addressed JMT). v1→v2
/// (2026-08-24): v1 enumerated apps only from the alt-shard index ∪ recent-commit
/// window, which MISSED QUIL (historical, prover-only recent writes) → its unified
/// app tree was left EMPTY and splits could never see data. v2 also enumerates the
/// GRID (`range_app_shards`), folding QUIL in. Nodes stamped v1 must re-run, so the
/// check keys on v2 and the stale v1 key is ignored.
const MARKER_KEY: &[u8] = b"\x00__quil_unified_consolidated_v2__";

/// Whether the one-time consolidation has already run on this store.
pub fn is_consolidated(hg: &quil_store::RocksHypergraphStore) -> bool {
    hg.raw_db().get(MARKER_KEY).ok().flatten().is_some()
}

/// Marker recording that the one-time BOOT cutover reset (grid → genesis +
/// prover-tree wipe/rebuild + unified flip) has run. Distinct from the
/// consolidation marker so the reset is applied exactly once even on a DB that
/// was only consolidated.
const BOOT_RESET_MARKER_KEY: &[u8] = b"\x00__quil_boot_cutover_reset_v1__";

/// Whether the one-time boot cutover reset has already been applied — the
/// frame-gated reset paths check this so they never re-apply on top of it.
pub fn boot_reset_applied(hg: &quil_store::RocksHypergraphStore) -> bool {
    hg.raw_db().get(BOOT_RESET_MARKER_KEY).ok().flatten().is_some()
}

/// Marker recording that the SECOND coordinated grid reset (grid-reset v2, mainnet
/// frame 740_000) has run on this node. DISTINCT from the v1 boot-reset marker so
/// the v1 `boot_reset_applied` guard does not suppress v2, and so the v2 prover
/// wipe runs exactly once (re-running would delete provers that re-joined after).
const GRID_RESET_V2_MARKER_KEY: &[u8] = b"\x00__quil_grid_reset_v2__";

/// Whether the grid-reset v2 prover wipe has already run on this node.
pub fn grid_reset_v2_applied(hg: &quil_store::RocksHypergraphStore) -> bool {
    hg.raw_db().get(GRID_RESET_V2_MARKER_KEY).ok().flatten().is_some()
}

/// Record that grid-reset v2 has run (called after a successful v2 prover wipe).
pub fn mark_grid_reset_v2_applied(hg: &quil_store::RocksHypergraphStore) {
    if let Err(e) = hg.raw_db().put(GRID_RESET_V2_MARKER_KEY, [1u8]) {
        warn!(error = %e, "grid-reset v2: marker write FAILED — may re-run if the frame re-materializes");
    }
}

/// Marker for prover-reset v3 (mainnet frame 747_000) — the complete tree
/// wipe+reseed paired with the per-node worker-filter reset. DISTINCT from v1/v2
/// so their guards don't suppress it and the v3 wipe runs exactly once.
const PROVER_RESET_V3_MARKER_KEY: &[u8] = b"\x00__quil_prover_reset_v3__";

/// Whether the prover-reset v3 wipe has already run on this node.
pub fn prover_reset_v3_applied(hg: &quil_store::RocksHypergraphStore) -> bool {
    hg.raw_db().get(PROVER_RESET_V3_MARKER_KEY).ok().flatten().is_some()
}

/// Record that prover-reset v3 has run (after a successful v3 prover wipe).
pub fn mark_prover_reset_v3_applied(hg: &quil_store::RocksHypergraphStore) {
    if let Err(e) = hg.raw_db().put(PROVER_RESET_V3_MARKER_KEY, [1u8]) {
        warn!(error = %e, "prover-reset v3: marker write FAILED — may re-run if the frame re-materializes");
    }
}

/// Marker for the prover-reset v3 WORKER-filter reset. Separate from the tree-wipe
/// marker: the tree wipe is consensus state (hg store, on materializers), while the
/// worker reset is LOCAL runtime state (worker store, on every node with workers) —
/// they run on different paths, so each needs its own once-guard.
const WORKER_RESET_V3_MARKER_KEY: &[u8] = b"\x00__quil_worker_reset_v3__";

/// Whether the prover-reset v3 worker-filter reset has already run on this node.
pub fn worker_reset_v3_applied(hg: &quil_store::RocksHypergraphStore) -> bool {
    hg.raw_db().get(WORKER_RESET_V3_MARKER_KEY).ok().flatten().is_some()
}

/// Record that the prover-reset v3 worker-filter reset has run.
pub fn mark_worker_reset_v3_applied(hg: &quil_store::RocksHypergraphStore) {
    if let Err(e) = hg.raw_db().put(WORKER_RESET_V3_MARKER_KEY, [1u8]) {
        warn!(error = %e, "worker-reset v3: marker write FAILED — may re-run if the frame re-materializes");
    }
}

/// Marker for prover-reset v4 (mainnet frame 755_000) — the re-baseline after the
/// boot-clobber (`normalize_quil_token_grid`) was removed. DISTINCT from v2/v3 so
/// their guards don't suppress it and the v4 wipe runs exactly once.
const PROVER_RESET_V4_MARKER_KEY: &[u8] = b"\x00__quil_prover_reset_v4__";

/// Whether the prover-reset v4 wipe has already run on this node.
pub fn prover_reset_v4_applied(hg: &quil_store::RocksHypergraphStore) -> bool {
    hg.raw_db().get(PROVER_RESET_V4_MARKER_KEY).ok().flatten().is_some()
}

/// Record that prover-reset v4 has run (after a successful v4 prover wipe).
pub fn mark_prover_reset_v4_applied(hg: &quil_store::RocksHypergraphStore) {
    if let Err(e) = hg.raw_db().put(PROVER_RESET_V4_MARKER_KEY, [1u8]) {
        warn!(error = %e, "prover-reset v4: marker write FAILED — may re-run if the frame re-materializes");
    }
}

/// Prover-reset v5 marker (759_000): clears the byte-suffix allocations the
/// old-binary fleet re-joined with post-v4 and re-baselines to sentinel now that
/// every seeder is sentinel. DISTINCT from v2/v3/v4 so their guards don't
/// suppress it and the v5 wipe runs exactly once.
const PROVER_RESET_V5_MARKER_KEY: &[u8] = b"\x00__quil_prover_reset_v5__";

/// Whether the prover-reset v5 wipe has already run on this node.
pub fn prover_reset_v5_applied(hg: &quil_store::RocksHypergraphStore) -> bool {
    hg.raw_db().get(PROVER_RESET_V5_MARKER_KEY).ok().flatten().is_some()
}

/// Record that prover-reset v5 has run (after a successful v5 prover wipe).
pub fn mark_prover_reset_v5_applied(hg: &quil_store::RocksHypergraphStore) {
    if let Err(e) = hg.raw_db().put(PROVER_RESET_V5_MARKER_KEY, [1u8]) {
        warn!(error = %e, "prover-reset v5: marker write FAILED — may re-run if the frame re-materializes");
    }
}

/// Reseed the LOCAL QUIL grid to the sentinel genesis ON BOOT if this node is
/// past the v5 frame but never ran v5 (state-jumped / synced past 759_000). The
/// prover tree is consensus state and arrives via sync (so it's the wiped
/// post-v5 state), but the GRID is LOCAL and does NOT sync — a state-jumping
/// node keeps its stale pre-v5 grid, so `fetch_shard_sizes_from_archive` can't
/// build sentinel descriptors and the lifecycle's `ProposeJoin` gate never opens
/// (the observed post-v5 "no joins land" — the 64-way grid is present on
/// materializing archives but the fleet never refills it). Grid-only + marker-
/// idempotent: after this runs once the frame-gated v5 path also no-ops.
pub fn boot_apply_v5_grid_reset(
    hg: &quil_store::RocksHypergraphStore,
    shards_store: &dyn ShardsStore,
    shards_db: &dyn quil_types::store::KvDb,
    clock_store: &dyn ClockStore,
    network: u8,
) -> bool {
    if prover_reset_v5_applied(hg) {
        return false;
    }
    let head = clock_store
        .get_latest_global_clock_frame()
        .ok()
        .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
        .unwrap_or(0);
    let v5 = quil_execution::global_intrinsic::materialize::quil_prover_reset_v5_frame();
    if head < v5 {
        // Not yet past v5 — the frame-gated reset (materialize/recv path) owns it.
        return false;
    }
    info!(
        head, v5, network,
        "BOOT v5 grid reset: past v5 without the marker (state-jumped) — reseeding local grid to sentinel genesis"
    );
    let quil = quil_execution::domains::QUIL_TOKEN;
    let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(&quil, 256, 3);
    let mut grid_key = Vec::with_capacity(3 + 32);
    grid_key.extend_from_slice(&l1);
    grid_key.extend_from_slice(&quil);
    let genesis_prefixes = quil_forest::genesis_grid_prefixes(network);
    match shards_db.new_batch(false) {
        Ok(txn) => {
            let mut removed_rows = 0usize;
            if let Ok(rows) = shards_store.range_app_shards() {
                for s in rows.into_iter().filter(|s| s.shard_key == grid_key) {
                    let _ = shards_store.delete_app_shard(txn.as_ref(), &s.shard_key, &s.prefix);
                    removed_rows += 1;
                }
            }
            for p in &genesis_prefixes {
                let _ = shards_store.put_app_shard(
                    txn.as_ref(),
                    &quil_types::store::ShardInfo {
                        shard_key: grid_key.clone(),
                        prefix: p.clone(),
                        size: Vec::new(),
                        data_shards: 0,
                        commitment: Vec::new(),
                    },
                );
            }
            if let Ok(pending) = shards_store.all_pending_shard_changes() {
                for pc in pending {
                    if pc.parent.len() >= 32 && pc.parent[..32] == quil {
                        let _ = shards_store.delete_pending_shard_change(
                            txn.as_ref(),
                            &pc.parent,
                            pc.effective_epoch,
                        );
                    }
                }
            }
            let _ = txn.commit();
            info!(
                removed_rows,
                genesis_shards = genesis_prefixes.len(),
                "BOOT v5 grid reset: QUIL grid reseeded to sentinel genesis"
            );
        }
        Err(e) => {
            warn!(error = %e, "BOOT v5 grid reset: shards txn open failed — grid NOT reset");
            return false;
        }
    }
    mark_prover_reset_v5_applied(hg);
    true
}

/// Apply the ENTIRE unified-tree cutover ONCE, ON BOOT — not gated on reaching a
/// frame number. Idempotent via [`BOOT_RESET_MARKER_KEY`]. Runs BEFORE consensus
/// starts, so the node comes up already in the reset state. Deterministic across
/// nodes: every step is a pure function of committed state + the network's genesis
/// (the reseed uses the fixed cutover frame, not the local head), so all upgraded
/// nodes converge on the identical grid + prover tree regardless of their head.
///
/// Steps (mirrors the flag-day sequence, minus the frame gate):
///  1. consolidate split apps' per-sub-shard trees → their single app.l2 tree;
///  2. reset the QUIL shard grid to the network genesis topology (64-way mainnet,
///     single testnet), dropping cascade rows + pending QUIL changes;
///  3. wipe + rebuild the global prover tree from the genesis committee;
///  4. flip the CRDT to unified-tree commitments.
pub fn boot_apply_cutover_reset(
    hg: &Arc<quil_store::RocksHypergraphStore>,
    crdt: &Arc<HypergraphCrdt>,
    shards_store: &dyn ShardsStore,
    shards_db: &dyn quil_types::store::KvDb,
    clock_store: &dyn ClockStore,
    network: u8,
    genesis_seed: &str,
) -> bool {
    if boot_reset_applied(hg) {
        crdt.set_unified_tree(true);
        return false;
    }
    let head = clock_store
        .get_latest_global_clock_frame()
        .ok()
        .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
        .unwrap_or(0);
    // Deterministic reseed/commit frame — the cutover constant, identical on
    // every node (NOT the local head, which varies).
    let reset_frame = unified_tree_cutover_frame();
    info!(head, reset_frame, network, "BOOT cutover reset: applying the full flag-day reset now (not frame-gated)…");

    // 1. Consolidate (idempotent). Best-effort — a failure here still lets the
    //    grid/prover reset proceed (they rebuild from committed vertices).
    match quil_forest_migrate::run_unified_consolidation_in_place(hg.as_ref(), shards_store, 0, head)
    {
        Ok(n) => info!(apps = n, "boot cutover reset: consolidation complete"),
        Err(e) => warn!(error = %e, "boot cutover reset: consolidation FAILED (continuing)"),
    }

    // 2. QUIL grid → network genesis topology.
    let quil = quil_execution::domains::QUIL_TOKEN;
    let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(&quil, 256, 3);
    let mut grid_key = Vec::with_capacity(3 + 32);
    grid_key.extend_from_slice(&l1);
    grid_key.extend_from_slice(&quil);
    // Canonical SENTINEL genesis (never the legacy byte-suffix `[i]`) — a fresh
    // boot must seed the same format the split-reset commits, or a node that
    // boots past the reset frame (and never re-materializes it) would re-seed a
    // byte-suffix grid and re-open the encoding divergence.
    let genesis_prefixes: Vec<Vec<u32>> = quil_forest::genesis_grid_prefixes(network);
    match shards_db.new_batch(false) {
        Ok(txn) => {
            let mut removed_rows = 0usize;
            if let Ok(rows) = shards_store.range_app_shards() {
                for s in rows.into_iter().filter(|s| s.shard_key == grid_key) {
                    let _ = shards_store.delete_app_shard(txn.as_ref(), &s.shard_key, &s.prefix);
                    removed_rows += 1;
                }
            }
            for p in &genesis_prefixes {
                let _ = shards_store.put_app_shard(
                    txn.as_ref(),
                    &quil_types::store::ShardInfo {
                        shard_key: grid_key.clone(),
                        prefix: p.clone(),
                        size: Vec::new(),
                        data_shards: 0,
                        commitment: Vec::new(),
                    },
                );
            }
            if let Ok(pending) = shards_store.all_pending_shard_changes() {
                for pc in pending {
                    if pc.parent.len() >= 32 && pc.parent[..32] == quil {
                        let _ = shards_store.delete_pending_shard_change(
                            txn.as_ref(),
                            &pc.parent,
                            pc.effective_epoch,
                        );
                    }
                }
            }
            let _ = txn.commit();
            info!(removed_rows, genesis_shards = genesis_prefixes.len(), "boot cutover reset: QUIL grid rebuilt to genesis");
        }
        Err(e) => warn!(error = %e, "boot cutover reset: shards txn open failed — grid NOT reset"),
    }

    // 3. Prover tree: wipe + rebuild from the genesis committee.
    match quil_engine::genesis::reset_prover_tree_to_genesis(
        crdt,
        hg.as_ref(),
        reset_frame,
        network,
        genesis_seed,
        &[],
    ) {
        Ok(seeded) => info!(seeded, "boot cutover reset: prover tree wiped + rebuilt from genesis committee"),
        Err(e) => warn!(error = %e, "boot cutover reset: prover-tree reset FAILED"),
    }

    // 4. Flip to unified commitments + persist the marker.
    crdt.set_unified_tree(true);
    if let Err(e) = hg.raw_db().put(BOOT_RESET_MARKER_KEY, [1u8]) {
        warn!(error = %e, "boot cutover reset: marker write FAILED — will re-run next boot");
    }
    info!("BOOT cutover reset: complete — node is now in unified/genesis-reset state");
    true
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

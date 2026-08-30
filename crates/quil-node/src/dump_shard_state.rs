//! `--dump-shard-state <db_path>`: READ-ONLY offline dump of the QUIL shard grid,
//! prover allocations (grouped by `confirmation_filter`), pending shard changes,
//! and the reset markers. Never writes — safe to run on a shut-down archive while
//! the network keeps running on the others. Point it at the node's data dir (or
//! leave the path empty to use `config.db.path`).
//!
//! The GRID (shards store) and the PROVER ALLOCATIONS (what committees are formed
//! from) are printed separately, each decoded to a canonical bit-path and checked
//! for prefix-overlap — so the two views can be compared directly.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use quil_types::store::{ClockStore, ShardInfo, ShardsStore};

/// Decode a stored GRID prefix (`Vec<u32>`) to `(encoding, bits)`: sentinel
/// bit-path prefixes carry the marker; a plain byte-suffix `[i]` is the 6-bit
/// binary of the byte (the mapping `decode_shard_filter_or_root` uses).
fn grid_prefix_bits(prefix: &[u32]) -> (&'static str, Vec<bool>) {
    match quil_forest::shard_bit_path_from_prefix(prefix) {
        Some(bits) => ("sentinel", bits),
        None => ("byte-suffix", quil_forest::prefix_to_bits(prefix, 6)),
    }
}

/// Decode an app-shard FILTER (`app(32) ‖ suffix`) to `(encoding, bits)`.
fn filter_bits(filter: &[u8]) -> (&'static str, Vec<bool>) {
    let suffix = &filter[filter.len().min(32)..];
    if suffix.is_empty() {
        ("root", Vec::new())
    } else if suffix.len() == 1 {
        ("byte-suffix", quil_forest::prefix_to_bits(&[suffix[0] as u32], 6))
    } else {
        match quil_forest::decode_shard_filter_or_root(filter, 32) {
            Some((_, bits)) => ("sentinel", bits),
            None => ("undecodable", Vec::new()),
        }
    }
}

fn bits_str(bits: &[bool]) -> String {
    bits.iter().map(|&b| if b { '1' } else { '0' }).collect()
}

/// Count entries whose bit-path is a STRICT prefix of another present entry (an
/// overlapping parent that should have been removed when its children were made).
fn count_overlaps(all: &[Vec<bool>]) -> usize {
    all.iter()
        .filter(|b| all.iter().any(|o| *o != **b && o.starts_with(b)))
        .count()
}

pub fn run_dump_shard_state(
    path: &Path,
    config: &quil_config::Config,
    network: u8,
) -> anyhow::Result<()> {
    let db_path = if path.as_os_str().is_empty() {
        config.db.path.clone()
    } else {
        path.to_string_lossy().into_owned()
    };
    if db_path.is_empty() {
        anyhow::bail!("no database path given and config.db.path is empty");
    }

    println!("=== SHARD-STATE DUMP (read-only) ===");
    println!("database: {db_path}");
    println!("network:  {network}");

    let db = quil_store::RocksDb::open(Path::new(&db_path))
        .map_err(|e| anyhow::anyhow!("open rocksdb {db_path}: {e}"))?;
    let inner = db.inner();
    let clock = quil_store::RocksClockStore::new(inner.clone());
    let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(inner.clone()));
    let shards_store = quil_store::RocksShardsStore::new(inner.clone());

    let head = clock
        .get_latest_global_clock_frame()
        .ok()
        .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
        .unwrap_or(0);
    println!("head frame: {head}");
    println!(
        "grid-reset v2 frame: {}   prover-reset v3 frame: {}   prover-reset v4 frame: {}   prover-reset v5 frame: {}   unified cutover frame: {}",
        quil_execution::global_intrinsic::materialize::quil_grid_reset_v2_frame(),
        quil_execution::global_intrinsic::materialize::quil_prover_reset_v3_frame(),
        quil_execution::global_intrinsic::materialize::quil_prover_reset_v4_frame(),
        quil_execution::global_intrinsic::materialize::quil_prover_reset_v5_frame(),
        quil_execution::global_intrinsic::materialize::unified_tree_cutover_frame(),
    );

    // ---- reset markers ----
    println!("\n--- reset markers ---");
    println!("boot cutover reset applied: {}", crate::unified_consolidation::boot_reset_applied(&hg_store));
    println!("grid-reset v2 applied:      {}", crate::unified_consolidation::grid_reset_v2_applied(&hg_store));
    println!("prover-reset v3 applied:    {}", crate::unified_consolidation::prover_reset_v3_applied(&hg_store));
    println!("prover-reset v4 applied:    {}", crate::unified_consolidation::prover_reset_v4_applied(&hg_store));
    println!("prover-reset v5 applied:    {}", crate::unified_consolidation::prover_reset_v5_applied(&hg_store));
    println!("unified consolidated:       {}", crate::unified_consolidation::is_consolidated(&hg_store));

    // QUIL grid key: l1(3) ‖ l2(32).
    let quil = quil_execution::domains::QUIL_TOKEN;
    let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(&quil, 256, 3);
    let mut grid_key = Vec::with_capacity(3 + 32);
    grid_key.extend_from_slice(&l1);
    grid_key.extend_from_slice(&quil);

    // ---- GRID (shards store) ----
    let grid: Vec<ShardInfo> = shards_store
        .range_app_shards()?
        .into_iter()
        .filter(|s| s.shard_key == grid_key)
        .collect();
    println!("\n--- QUIL GRID (shards store): {} rows ---", grid.len());
    let mut grid_lines: Vec<(usize, String, &'static str, Vec<u32>)> = grid
        .iter()
        .map(|s| {
            let (enc, bits) = grid_prefix_bits(&s.prefix);
            (bits.len(), bits_str(&bits), enc, s.prefix.clone())
        })
        .collect();
    grid_lines.sort();
    for (depth, bits, enc, prefix) in &grid_lines {
        println!("  depth={depth:>2} [{enc:<11}] {bits:<12} prefix={prefix:?}");
    }
    let grid_bits: Vec<Vec<bool>> = grid.iter().map(|s| grid_prefix_bits(&s.prefix).1).collect();
    println!("  GRID overlapping rows (a shard prefixing another): {}", count_overlaps(&grid_bits));

    // ---- PENDING changes ----
    let pending: Vec<_> = shards_store
        .all_pending_shard_changes()?
        .into_iter()
        .filter(|pc| pc.parent.len() >= 32 && pc.parent[..32] == quil[..])
        .collect();
    println!("\n--- QUIL PENDING shard changes: {} ---", pending.len());
    for pc in &pending {
        println!(
            "  {:?} parent={} eff_epoch={} proposed_frame={} children={}",
            pc.kind,
            hex::encode(&pc.parent),
            pc.effective_epoch,
            pc.proposed_frame,
            pc.children.len()
        );
    }

    // ---- PROVER ALLOCATIONS (committee source) ----
    if !hg_store.has_forest_data() {
        println!("\n--- PROVER ALLOCATIONS: skipped (DB has no forest data / not migrated) ---");
        println!("\n=== DUMP COMPLETE ===");
        return Ok(());
    }
    let inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver> =
        Arc::new(quil_tries::ShaInclusionProver);
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
        inclusion_prover,
    ));
    quil_forest_migrate::install_forest_boot(crdt.as_ref(), hg_store.as_ref(), false, network == 0);

    // ---- UNIFIED APP TREE vs LEGACY per-prefix trees (is QUIL state populated?) ----
    // Post-699500 (UNIFIED_TREE_CUTOVER_FRAME) QUIL commits into ONE tree per phase
    // keyed by the bare app address; the shard grid is pure navigation (subtree reads
    // by bit-path). The pre-cutover / --migrate-db writes went to per-prefix
    // byte-suffix trees `addr_path_shard_id(QUIL, [i])`. If the unified tree holds the
    // state, reads land; if state is still stranded in the legacy trees, the one-time
    // consolidation never drained it — the post-v5 empty-shards suspect.
    let stats = crdt.dump_app_forest_stats(&quil);
    let phase_names = ["VertexAdds", "VertexRemoves", "HyperedgeAdds", "HyperedgeRemoves"];
    println!("\n--- QUIL UNIFIED app tree (keyed by bare app address) ---");
    for (pi, (count, root, ver)) in stats.unified.iter().enumerate() {
        println!(
            "  phase {pi} {:<17} leaves={count:<12} ver={ver:<4} root={}",
            phase_names[pi],
            hex::encode(root)
        );
    }
    let unified_state_leaves = stats.unified[0].0; // VertexAdds = live vertex/coin count
    println!("  UNIFIED VertexAdds leaves (QUIL state size): {unified_state_leaves}");
    println!("\n--- QUIL LEGACY per-prefix byte-suffix trees (addr_path_shard_id(QUIL,[i])) ---");
    println!(
        "  legacy trees with data: {}   total legacy VertexAdds leaves: {}",
        stats.legacy_nonempty.len(),
        stats.legacy_total_vertex_adds
    );
    for (i, count) in &stats.legacy_nonempty {
        println!("    shard [{i:>2}] leaves={count}");
    }
    let legacy = stats.legacy_total_vertex_adds;
    let verdict = if unified_state_leaves == 0 && legacy > 0 {
        "STRANDED — state is ONLY in legacy per-prefix trees; unified tree EMPTY (consolidation did not drain)"
    } else if unified_state_leaves == 0 && legacy == 0 {
        "EMPTY — no QUIL VertexAdds leaves in either unified or legacy trees"
    } else if unified_state_leaves >= legacy && legacy > 0 {
        // Unified holds the full count; the legacy copies were never deleted
        // (put-only forest) — orphaned duplicates, benign for correctness.
        "POPULATED — unified tree holds the full state; legacy trees are orphaned put-only residue (reclaimable disk, not read on the live path)"
    } else if unified_state_leaves > 0 && legacy == 0 {
        "POPULATED — unified tree holds the state, legacy drained (healthy)"
    } else {
        // unified > 0 but strictly fewer than legacy ⇒ consolidation moved only part.
        "PARTIAL — unified tree has FEWER leaves than legacy; consolidation is incomplete"
    };
    println!("  VERDICT: {verdict}");

    // ---- PERSISTED SIZE BUCKETS (what GetAppShards / the reward basis read) ----
    // `sub_meta_for` folds these by `addr_path_shard_id(app, current-CRDT-prefix)`.
    // If they're byte-suffix (key len 36) while the live CRDT prefixes are sentinel
    // (post-refresh), every fold misses → GetAppShards size 0 → the proposer sees no
    // join candidates and rewards compute 0. Key len 60 = sentinel (matches the grid).
    let buckets = crdt.dump_persisted_size_buckets(&quil);
    println!("\n--- QUIL PERSISTED size buckets (hgsz:buckets — GetAppShards/reward basis) ---");
    if buckets.is_empty() {
        println!("  (no persisted buckets — warm_sizes never ran / cache absent; live node cold-scans on boot)");
    } else {
        let byte_suffix = buckets.iter().filter(|(kl, _, _)| *kl == 36).count();
        let sentinel = buckets.iter().filter(|(kl, _, _)| *kl == 60).count();
        let other = buckets.len() - byte_suffix - sentinel;
        let total_size: i128 = buckets.iter().map(|(_, _, s)| *s).sum();
        let total_count: u64 = buckets.iter().map(|(_, c, _)| *c).sum();
        println!(
            "  buckets: {}   byte-suffix(len36)={byte_suffix}   sentinel(len60)={sentinel}   other={other}",
            buckets.len()
        );
        println!("  total raw_count={total_count}   total live_size={total_size}");
        let enc = if sentinel > 0 && byte_suffix == 0 {
            "SENTINEL — matches the grid/CRDT; GetAppShards sizes resolve (healthy)"
        } else if byte_suffix > 0 && sentinel == 0 {
            "BYTE-SUFFIX — MISMATCHES the sentinel grid: sub_meta_for folds miss → GetAppShards size 0 → no join candidates / 0 reward basis"
        } else {
            "MIXED — some byte-suffix, some sentinel (partial rebucket)"
        };
        println!("  ENCODING: {enc}");
    }

    let provers = quil_execution::prover_registry::all_provers_with_allocations_committed(&crdt);
    // ACTIVE-only view (effective_status(head)==Active) — the set that actually
    // submits coverage. Retired (Historic, from delete-free reassignment),
    // Rejected, Kicked, and expired allocations are excluded so the reject diff
    // below flags only allocations that would REALLY trip the collector, not a
    // vacated slot left behind after a split.
    let active_provers =
        quil_execution::prover_registry::all_provers_with_active_allocations_committed(&crdt, head);
    // Each prover is (address, pubkey, [confirmation_filter, ...]).
    let mut by_filter: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
    for (_addr, _pubkey, filters) in &provers {
        for filter in filters {
            *by_filter.entry(filter.clone()).or_default() += 1;
        }
    }
    let mut active_by_filter: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
    for (_addr, _pubkey, filters) in &active_provers {
        for filter in filters {
            *active_by_filter.entry(filter.clone()).or_default() += 1;
        }
    }
    let quil_filters: Vec<(&Vec<u8>, &usize)> = by_filter
        .iter()
        .filter(|(f, _)| f.len() >= 32 && f[..32] == quil[..])
        .collect();
    println!(
        "\n--- PROVER ALLOCATIONS by confirmation_filter: {} provers, {} distinct QUIL filters (active=N is the effective-Active subset at head {head}) ---",
        provers.len(),
        quil_filters.len()
    );
    let mut alloc_lines: Vec<(usize, String, &'static str, usize, usize)> = quil_filters
        .iter()
        .map(|(f, c)| {
            let (enc, bits) = filter_bits(f);
            let active = active_by_filter.get(f.as_slice()).copied().unwrap_or(0);
            (bits.len(), bits_str(&bits), enc, **c, active)
        })
        .collect();
    alloc_lines.sort();
    for (depth, bits, enc, count, active) in &alloc_lines {
        println!("  depth={depth:>2} [{enc:<11}] {bits:<12} provers={count:<3} active={active}");
    }
    let alloc_bits: Vec<Vec<bool>> = quil_filters.iter().map(|(f, _)| filter_bits(f).1).collect();
    println!("  ALLOCATION overlapping filters (a filter prefixing another): {}", count_overlaps(&alloc_bits));

    // ---- BYTE-EXACT VALID-SET DIFF (the collector's actual reject condition) ----
    // The message collector rejects a shard-frame when `!valid.contains(&address)`,
    // where `valid` = {shard_prefix_to_filter(l2, prefix)} over the GRID rows (built
    // in archive_sync.rs) and `address` = the prover's `confirmation_filter`. So an
    // ACTIVE allocation filter that is NOT byte-for-byte one of these grid filters is
    // a shard whose coverage/reward proofs every archive rejects. Only Active provers
    // submit, so the diff is over the active set (a retired/Historic slot on a
    // now-split parent is NOT a live reject and must not be counted here).
    let grid_valid_set: std::collections::HashSet<Vec<u8>> = grid
        .iter()
        .map(|s| quil_forest::shard_prefix_to_filter(&s.shard_key[3..35], &s.prefix))
        .collect();
    let active_quil_filters: Vec<(&Vec<u8>, &usize)> = active_by_filter
        .iter()
        .filter(|(f, _)| f.len() >= 32 && f[..32] == quil[..])
        .collect();
    let mut rejected: Vec<(usize, String, &'static str, Vec<u8>, usize)> = active_quil_filters
        .iter()
        .filter(|(f, _)| !grid_valid_set.contains(f.as_slice()))
        .map(|(f, c)| {
            let (enc, bits) = filter_bits(f);
            (bits.len(), bits_str(&bits), enc, (*f).clone(), **c)
        })
        .collect();
    rejected.sort();
    println!(
        "\n--- ACTIVE allocation filters NOT in the GRID valid-set (BYTE-EXACT) — these get rejected: {} ---",
        rejected.len()
    );
    for (depth, bits, enc, filter, count) in &rejected {
        println!("  depth={depth:>2} [{enc:<11}] {bits:<14} active={count:<3} filter={}", hex::encode(filter));
    }
    // Retired/non-active allocations that are off-grid — expected after a split
    // (delete-free reassignment leaves the vacated parent slot as Historic). Shown
    // as a count so an operator isn't alarmed by a non-zero reject line.
    let off_grid_nonactive = quil_filters
        .iter()
        .filter(|(f, _)| {
            !grid_valid_set.contains(f.as_slice())
                && !active_by_filter.contains_key(f.as_slice())
        })
        .count();
    if off_grid_nonactive > 0 {
        println!("  (off-grid NON-active allocations — retired/Historic after a split, benign: {off_grid_nonactive})");
    }
    // The reverse: grid shards with NO prover allocated (spine/empty — expected),
    // shown only as a count so the diff above stays focused.
    let alloc_filter_set: std::collections::HashSet<&Vec<u8>> = quil_filters.iter().map(|(f, _)| *f).collect();
    let empty_grid = grid_valid_set.iter().filter(|gf| !alloc_filter_set.contains(gf)).count();
    println!("  (grid shards with no prover allocation — spine/empty, expected: {empty_grid})");

    // ---- STATUS BREAKDOWN (raw byte → effective) — why active=N ----
    // A fresh join is `Joining` (byte) until it confirms in epoch E+1, when the byte
    // flips to `Active` but effective status stays `Joining` until the E+2
    // activation boundary (deferred activation). Surfacing BOTH tells, before the
    // boundary, a confirmed-but-deferred slot (`Active → Joining`, healthy, will
    // activate) from an unconfirmed one (`Joining → Joining`, confirm not done yet).
    // `ExpiredJoining` (missed the confirm slot) / `ExpiredEpoch` (missed a
    // re-confirm) are genuine stalls.
    let diag = quil_execution::prover_registry::allocation_status_breakdown(&crdt, head, &quil);
    let epoch_len = if network == 0 {
        quil_types::consensus::EPOCH_LENGTH_FRAMES
    } else {
        quil_types::consensus::TESTNET_EPOCH_LENGTH_FRAMES
    };
    let cur_epoch = head / epoch_len;
    let next_boundary = (cur_epoch + 1) * epoch_len;
    println!(
        "\n--- QUIL allocation STATUS (raw byte → effective) at head {head} (epoch {cur_epoch}, next boundary frame {next_boundary}, +{} frames) ---",
        next_boundary.saturating_sub(head)
    );
    if diag.by_status.is_empty() {
        println!("  (no QUIL allocations)");
    } else {
        for ((raw, eff), count) in &diag.by_status {
            println!("  {raw:<10} → {eff:<16} {count}");
        }
        // Joins bucketed by proposal epoch: due to confirm in epoch+1.
        if !diag.joining_by_epoch.is_empty() {
            print!("  Joining-byte by PROPOSAL epoch:");
            for (e, c) in &diag.joining_by_epoch {
                print!("  E{e}={c}(confirm due E{})", e + 1);
            }
            println!();
        }
        if !diag.confirmed_by_epoch.is_empty() {
            print!("  Active-byte by CONFIRM epoch:");
            for (e, c) in &diag.confirmed_by_epoch {
                print!("  E{e}={c}(active E{})", e + 1);
            }
            println!();
        }
        let sum_eff = |name: &str| -> usize {
            diag.by_status.iter().filter(|((_, e), _)| e == name).map(|(_, c)| *c).sum()
        };
        let expired = sum_eff("ExpiredJoining") + sum_eff("ExpiredEpoch");
        let active = sum_eff("Active");
        let confirmed_deferred: usize = diag
            .by_status
            .iter()
            .filter(|((r, e), _)| r == "Active" && e == "Joining")
            .map(|(_, c)| *c)
            .sum();
        // A Joining-byte alloc whose proposal epoch < cur_epoch is PAST its confirm
        // window (should have confirmed in proposal+1 ≤ cur_epoch); one at cur_epoch
        // is not due until next epoch.
        let overdue: usize =
            diag.joining_by_epoch.iter().filter(|(e, _)| **e < cur_epoch).map(|(_, c)| *c).sum();
        let not_yet_due: usize =
            diag.joining_by_epoch.iter().filter(|(e, _)| **e >= cur_epoch).map(|(_, c)| *c).sum();
        if expired > 0 {
            println!("  → STALL: {expired} Expired (missed confirm/re-confirm window) — the confirm path is broken.");
        } else if overdue > 0 {
            println!("  → OVERDUE: {overdue} joins proposed in a PAST epoch are still unconfirmed — confirm submission is not landing (a running node should have confirmed by now).");
        } else if not_yet_due > 0 && confirmed_deferred == 0 && active == 0 {
            println!("  → NOT YET DUE: {not_yet_due} joins proposed THIS epoch; confirm is due next epoch (E{}). Run the node forward and re-check — Joining→Joining is expected here.", cur_epoch + 1);
        } else if confirmed_deferred > 0 {
            println!("  → HEALTHY: {confirmed_deferred} confirmed, in deferred-activation window; expect active>0 after their activation epoch.");
        } else if active > 0 {
            println!("  → ACTIVE: {active} allocations effectively Active.");
        }
    }

    println!("\n=== DUMP COMPLETE ===");
    Ok(())
}

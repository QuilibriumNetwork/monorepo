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

#[cfg(test)]
mod tests {
    use super::*;

    /// Opens an inspected store read-only: beside a running node when
    /// `QUIL_INSPECT_LIVE` is set (every table file held open, so compactions
    /// cannot remove one mid-walk), else as a stopped store.
    fn open_inspected(path: &str) -> quil_store::RocksDb {
        if std::env::var_os("QUIL_INSPECT_LIVE").is_some() {
            quil_store::RocksDb::open_for_read_only_live(Path::new(path)).unwrap()
        } else {
            quil_store::RocksDb::open_for_read_only(Path::new(path)).unwrap()
        }
    }

    fn open_state(path: &str) -> quil_execution::hypergraph_state::HypergraphState {
        let db = quil_store::RocksDb::open_for_read_only(Path::new(path)).unwrap();
        let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        quil_forest_migrate::install_forest_boot(crdt.as_ref(), hg_store.as_ref(), false, false);
        std::mem::forget(db);
        quil_execution::hypergraph_state::HypergraphState::new(crdt)
    }

    /// Committed coin deliveries of the QUIL application as GLOBAL records
    /// them, against each local store's block counts and coins. Opens every
    /// store read-only.
    #[test]
    #[ignore = "inspection of localnet stores"]
    fn inspect_coin_deliveries() {
        use quil_execution::token_intrinsic::{coin_blocks, global_commit, roots, state::SnapshotLimits};
        let (Ok(global), Ok(locals)) = (std::env::var("QUIL_INSPECT_GLOBAL"), std::env::var("QUIL_INSPECT_LOCAL")) else { return };
        let network = quil_lattice_ct::confidential::transfer::network_identifier(
            std::env::var("QUIL_INSPECT_NETWORK").ok().and_then(|n| n.parse().ok()).unwrap_or(1));
        let app: [u8; 32] = hex::decode("11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d9").unwrap().try_into().unwrap();
        let limits = SnapshotLimits { max_coins: usize::MAX, max_depth: 32, max_nodes: usize::MAX };
        let disc = quil_execution::hypergraph_state::vertex_adds_discriminator().unwrap();
        let global = open_state(&global);
        let width = global_commit::placement_width(&global, &app).unwrap();
        let locals: Vec<(String, _)> = locals.split(',').map(|p| (p.to_string(), open_state(p))).collect();
        println!("placement width {width}");
        let mut seen = BTreeMap::new();
        for block in coin_blocks::owned_blocks(&[], width) {
            let committed = global_commit::block_sequence(&global, &app, block).unwrap();
            let counts: Vec<u64> = locals.iter().map(|(_, s)| roots::block_count(s, &network, &app, block, limits).unwrap()).collect();
            if committed == 0 && counts.iter().all(|c| *c == 0) {
                continue;
            }
            println!("block {block:#x} width {} committed {committed} local counts {counts:?}", coin_blocks::creation_width(block));
            let summaries: Vec<String> = locals.iter().map(|(_, s)| {
                let summary = roots::block_summary(s, &app).map(|summary| summary.blocks.iter()
                    .find(|(id, _, _)| *id == block).map(|(_, coins, root)| format!("{coins}/{}", hex::encode(&root.to_bytes()[..4]))));
                let root = roots::block_root(s, &app, block).map(|root| root.map(|root| hex::encode(&root.to_bytes()[..4])));
                format!("summary {:?} root {:?}", summary.ok().flatten(), root.ok().flatten())
            }).collect();
            println!("  {}", summaries.join(" | "));
            for seq in 0..committed {
                let Some(d) = global_commit::delivery(&global, &app, block, seq).unwrap() else {
                    println!("  seq {seq}: NO RECORD");
                    continue;
                };
                let present: Vec<bool> = locals.iter().map(|(_, s)| s.get(&app, &d.address, &disc).unwrap().is_some()).collect();
                let duplicate = seen.insert(d.address, (block, seq));
                println!("  seq {seq}: {} src frame {} shard {:?} tx {} present {present:?}{}",
                    hex::encode(&d.address[..8]), d.source_frame, d.source_shard.bits().map(|b| bits_str(&b)),
                    hex::encode(&d.tx_id[..8]),
                    duplicate.map(|(b, s)| format!(" DUPLICATE of block {b:#x} seq {s}")).unwrap_or_default());
            }
        }
        for (path, _) in &locals {
            println!("local: {path}");
        }
    }

    /// The QUIL vertex-adds a thread worker copies from its master at startup
    /// (`sync_app_shard_to_own_crdt`), and each one's value in the worker.
    #[test]
    #[ignore = "inspection of localnet stores"]
    fn inspect_startup_seed_copy() {
        let (Ok(master), Ok(worker)) = (std::env::var("QUIL_INSPECT_MASTER"), std::env::var("QUIL_INSPECT_WORKER")) else { return };
        let app: [u8; 32] = hex::decode("11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d9").unwrap().try_into().unwrap();
        let disc = quil_execution::hypergraph_state::vertex_adds_discriminator().unwrap();
        let master = open_state(&master);
        let worker = open_state(&worker);
        let mut copied = Vec::new();
        master.crdt().for_each_vertex_adds_blob(&app, &mut |key, blob| {
            if key.len() == 64 && !blob.is_empty() {
                copied.push((key.to_vec(), blob.to_vec()));
            }
        }).unwrap();
        for (key, blob) in copied {
            let address: [u8; 32] = key[32..].try_into().unwrap();
            let record = quil_execution::token_intrinsic::state::is_accumulator_record(&address);
            let own = worker.get(&app, &address, &disc).unwrap();
            println!("{} record {record} master {} bytes worker {}",
                hex::encode(&address), blob.len(),
                match own { None => "absent".to_string(), Some(v) if v == blob => "same".to_string(), Some(v) => format!("DIFFERS ({} bytes)", v.len()) });
        }
    }

    /// Every stored MVCC version of chosen QUIL vertices beside the app tree's
    /// head version, read-only: a version above the head shadows later writes.
    #[test]
    #[ignore = "inspection of localnet stores"]
    fn inspect_blob_versions() {
        use quil_execution::token_intrinsic::state::{block_record_address, BLOCK_FRONTIER_TAG, BLOCK_SUMMARY_ADDRESS, ROOT_ADDRESS};
        let Ok(path) = std::env::var("QUIL_INSPECT_STORE") else { return };
        let app: [u8; 32] = hex::decode("11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d9").unwrap().try_into().unwrap();
        let db = quil_store::RocksDb::open_for_read_only(Path::new(&path)).unwrap();
        let forest = quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE);
        println!("app tree head version {:?}", forest.read_head_version(&app, quil_forest::Phase::VertexAdds).unwrap());
        let shard = quil_types::store::ShardKey { l1: quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3), l2: app };
        let mut addresses: Vec<(String, [u8; 32])> = vec![("root".into(), ROOT_ADDRESS), ("summary".into(), BLOCK_SUMMARY_ADDRESS)];
        for block in std::env::var("QUIL_INSPECT_BLOCKS").unwrap_or_default().split(',').filter(|b| !b.is_empty()) {
            let block = u64::from_str_radix(block.trim_start_matches("0x"), 16).unwrap();
            addresses.push((format!("frontier {block:#x}"), block_record_address(BLOCK_FRONTIER_TAG, block)));
        }
        for coin in std::env::var("QUIL_INSPECT_ADDRESSES").unwrap_or_default().split(',').filter(|a| !a.is_empty()) {
            addresses.push((format!("vertex {}", &coin[..16.min(coin.len())]), hex::decode(coin).unwrap().try_into().unwrap()));
        }
        let inner = db.inner();
        for (label, address) in addresses {
            let mut id = app.to_vec();
            id.extend_from_slice(&address);
            let prefix = quil_store::encoding::hypergraph_vertex_data_v2_vk_prefix("vertex", "adds", &shard, &id);
            let mut versions = Vec::new();
            let mut it = inner.raw_iterator();
            it.seek(&prefix);
            while let (Some(key), Some(value)) = (it.key(), it.value()) {
                if !key.starts_with(&prefix) || key.len() != prefix.len() + 8 {
                    break;
                }
                let version = u64::from_be_bytes(key[prefix.len()..].try_into().unwrap());
                versions.push(format!("v{version}:{}", hex::encode(&quil_crypto::poseidon::hash_bytes_to_32(value).unwrap()[..4])));
                it.next();
            }
            println!("{label}: {}", versions.join(" "));
        }
    }

    /// Per phase of one application (default QUIL on mainnet), its tree head
    /// and how many vertices hold a blob above it. Reads take the greatest
    /// version and the next commit writes at head + 1, so any write to one of
    /// those since the head fell below it is already shadowed, and every later
    /// one will be. Keys only, read-only; never copies the store.
    #[test]
    #[ignore = "inspection of a node store"]
    fn inspect_version_shadowing() {
        let Ok(path) = std::env::var("QUIL_INSPECT_STORE") else { return };
        let app: [u8; 32] = match std::env::var("QUIL_INSPECT_APP") {
            Ok(app) => hex::decode(app).unwrap().try_into().unwrap(),
            Err(_) => quil_execution::domains::QUIL_TOKEN,
        };
        let db = open_inspected(&path);
        let forest = quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE);
        let shard = quil_types::store::ShardKey { l1: quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3), l2: app };
        let inner = db.inner();
        for (set, phase, tree) in [
            ("vertex", "adds", quil_forest::Phase::VertexAdds),
            ("vertex", "removes", quil_forest::Phase::VertexRemoves),
            ("hyperedge", "adds", quil_forest::Phase::HyperedgeAdds),
            ("hyperedge", "removes", quil_forest::Phase::HyperedgeRemoves),
        ] {
            let head = forest.read_head_version(&app, tree).unwrap();
            let prefix = quil_store::encoding::hypergraph_vertex_data_v2_shard_prefix(set, phase, &shard);
            let (mut vertices, mut above, mut highest) = (0u64, 0u64, None);
            let mut current: Option<(Vec<u8>, u64)> = None;
            let mut finish = |entry: Option<(Vec<u8>, u64)>| {
                if let Some((_, version)) = entry {
                    vertices += 1;
                    if Some(version) > head {
                        above += 1;
                    }
                }
            };
            let mut it = inner.raw_iterator();
            it.seek(&prefix);
            while let Some(key) = it.key() {
                if !key.starts_with(&prefix) || key.len() < prefix.len() + 8 {
                    break;
                }
                let (vertex, version) = key[prefix.len()..].split_at(key.len() - prefix.len() - 8);
                let version = u64::from_be_bytes(version.try_into().unwrap());
                highest = highest.max(Some(version));
                match &mut current {
                    Some((last, latest)) if last.as_slice() == vertex => *latest = version,
                    _ => finish(current.replace((vertex.to_vec(), version))),
                }
                it.next();
            }
            finish(current.take());
            println!("{set}/{phase}: head {head:?} highest blob {highest:?} vertices {vertices} exposed (blob above head) {above}");
        }
    }

    /// Per phase of one application (default QUIL on mainnet), the vertices a
    /// read gets wrong: the committed tree leaf at the phase head does not
    /// match the leaf of the blob a read returns, the greatest stored version.
    /// Only a vertex with several stored versions can differ, so only those
    /// are looked up in the tree. Read-only; never copies the store. Optional
    /// `QUIL_INSPECT_LIMIT` caps the lookups per phase. A live open sees one
    /// instant, possibly inside a commit: confirm stale reads it reports on a
    /// stopped store.
    #[test]
    #[ignore = "inspection of a node store"]
    fn inspect_stale_reads() {
        let Ok(path) = std::env::var("QUIL_INSPECT_STORE") else { return };
        let app: [u8; 32] = match std::env::var("QUIL_INSPECT_APP") {
            Ok(app) => hex::decode(app).unwrap().try_into().unwrap(),
            Err(_) => quil_execution::domains::QUIL_TOKEN,
        };
        let limit: usize = std::env::var("QUIL_INSPECT_LIMIT").ok().and_then(|n| n.parse().ok()).unwrap_or(usize::MAX);
        let db = open_inspected(&path);
        let forest = quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE);
        let shard = quil_types::store::ShardKey { l1: quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3), l2: app };
        let inner = db.inner();
        for (set, phase, tree) in [
            ("vertex", "adds", quil_forest::Phase::VertexAdds),
            ("vertex", "removes", quil_forest::Phase::VertexRemoves),
            ("hyperedge", "adds", quil_forest::Phase::HyperedgeAdds),
            ("hyperedge", "removes", quil_forest::Phase::HyperedgeRemoves),
        ] {
            let Some(head) = forest.read_head_version(&app, tree).unwrap() else {
                println!("{set}/{phase}: no tree");
                continue;
            };
            let prefix = quil_store::encoding::hypergraph_vertex_data_v2_shard_prefix(set, phase, &shard);
            // One vertex at a time: (vertex key, versions ascending, blob at
            // the greatest version); memory stays bounded on any store.
            let (mut vertices, mut checked, mut stale, mut examples) = (0usize, 0usize, 0usize, Vec::new());
            let mut check = |group: Option<(Vec<u8>, Vec<u64>, Vec<u8>)>| {
                let Some((vertex, versions, newest)) = group else { return };
                vertices += 1;
                if versions.len() < 2 || checked >= limit {
                    return;
                }
                checked += 1;
                let data = if vertex.len() >= 64 { &vertex[32..64] } else { vertex.as_slice() };
                let (committed, _) = forest.shard_phase_get_with_proof_raw(&app, tree, head, data).unwrap();
                let read = if newest.is_empty() { None } else { quil_tries::vertex_leaf_value(&newest).ok() };
                if committed != read {
                    stale += 1;
                    if examples.len() < 10 {
                        examples.push(format!("{} versions {versions:?}", hex::encode(data)));
                    }
                }
            };
            let mut current: Option<(Vec<u8>, Vec<u64>, Vec<u8>)> = None;
            let mut it = inner.raw_iterator();
            it.seek(&prefix);
            while let (Some(key), Some(value)) = (it.key(), it.value()) {
                if !key.starts_with(&prefix) || key.len() < prefix.len() + 8 {
                    break;
                }
                let (vertex, version) = key[prefix.len()..].split_at(key.len() - prefix.len() - 8);
                let version = u64::from_be_bytes(version.try_into().unwrap());
                match &mut current {
                    Some((last, versions, newest)) if last.as_slice() == vertex => {
                        versions.push(version);
                        *newest = value.to_vec();
                    }
                    _ => check(current.replace((vertex.to_vec(), vec![version], value.to_vec()))),
                }
                it.next();
            }
            check(current.take());
            println!("{set}/{phase}: head {head} vertices {vertices} multi-version checked {checked} stale reads {stale}");
            for example in examples {
                println!("  stale {example}");
            }
        }
    }

    /// Bytes by key family, and what superseded versions retain: blob versions
    /// below each vertex's newest, forest nodes already marked stale, and JMT
    /// values below each key's newest. Also whether every root→version index
    /// tree's versions and frames rise together (one frame sequence per tree),
    /// which a frame-based retention watermark assumes. Read-only; keys and
    /// values are only measured, never copied.
    #[test]
    #[ignore = "inspection of a node store"]
    fn inspect_retained_bytes() {
        use std::collections::{BTreeMap, HashMap};
        let Ok(path) = std::env::var("QUIL_INSPECT_STORE") else { return };
        let db = open_inspected(&path);
        let inner = db.inner();
        let mut families: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        let mut add = |family: String, bytes: u64| {
            let entry = families.entry(family).or_default();
            entry.0 += 1;
            entry.1 += bytes;
        };
        // Newest version per blob vertex / forest value key: (key prefix, bytes).
        let (mut blob_versions, mut blob_superseded, mut blob_superseded_bytes) = (0u64, 0u64, 0u64);
        let mut last_blob: Option<(Vec<u8>, u64)> = None;
        let (mut values, mut value_superseded, mut value_superseded_bytes) = (0u64, 0u64, 0u64);
        let mut last_value: Option<(Vec<u8>, u64)> = None;
        let (mut stale, mut stale_bytes) = (0u64, 0u64);
        let mut trees: HashMap<Vec<u8>, Vec<(u64, u64)>> = HashMap::new();
        let mut it = inner.raw_iterator();
        it.seek_to_first();
        while let (Some(key), Some(value)) = (it.key(), it.value()) {
            let bytes = (key.len() + value.len()) as u64;
            match key[0] {
                0x00 if key.len() > 1 => add(format!("00 clock/{:02x}", key[1]), bytes),
                0x31 => {
                    add("31 vertex blobs (versioned)".into(), bytes);
                    blob_versions += 1;
                    let vertex = key[..key.len() - 8].to_vec();
                    if let Some((last, last_bytes)) = last_blob.take() {
                        if last == vertex {
                            blob_superseded += 1;
                            blob_superseded_bytes += last_bytes;
                        }
                    }
                    last_blob = Some((vertex, bytes));
                }
                0x35 => {
                    add("35 root-version index".into(), bytes);
                    if value.len() == 16 && key.len() > 35 {
                        trees.entry(key[1..key.len() - 32].to_vec()).or_default().push((
                            u64::from_be_bytes(value[..8].try_into().unwrap()),
                            u64::from_be_bytes(value[8..].try_into().unwrap()),
                        ));
                    }
                }
                0xF7 if key.len() > 3 && key.len() > 3 + key[2] as usize => {
                    let tag_at = 3 + key[2] as usize;
                    let tag = key[tag_at];
                    add(format!("f7 forest level {} tag {}", key[1], tag as char), bytes);
                    match tag {
                        b's' => { stale += 1; stale_bytes += bytes; }
                        b'v' if key.len() >= tag_at + 1 + 32 + 8 => {
                            values += 1;
                            let hash = key[..tag_at + 1 + 32].to_vec();
                            if let Some((last, last_bytes)) = last_value.take() {
                                if last == hash {
                                    value_superseded += 1;
                                    value_superseded_bytes += last_bytes;
                                }
                            }
                            last_value = Some((hash, bytes));
                        }
                        _ => {}
                    }
                }
                first => add(format!("{first:02x}"), bytes),
            }
            it.next();
        }
        let total: u64 = families.values().map(|(_, b)| b).sum();
        println!("total logical bytes {total}");
        for (family, (count, bytes)) in &families {
            println!("  {family:<32} {count:>9} keys {bytes:>12} bytes");
        }
        println!("blob versions {blob_versions}, superseded {blob_superseded} ({blob_superseded_bytes} bytes)");
        println!("forest values {values}, superseded {value_superseded} ({value_superseded_bytes} bytes)");
        println!("forest stale-node records {stale} ({stale_bytes} bytes; each names one reclaimable node)");
        let mut mixed = 0;
        for (tree, mut entries) in trees {
            entries.sort();
            let monotonic = entries.windows(2).all(|pair| pair[0].1 <= pair[1].1);
            if !monotonic {
                mixed += 1;
                println!("  tree {} ({} entries): versions and frames do NOT rise together", hex::encode(&tree), entries.len());
            }
        }
        println!("root-version trees whose frames are not monotonic in version: {mixed}");
    }

    /// The QUIL shard grid of one store, with each shard's depth in bits and
    /// the persisted `(raw_count, live_size)` of its data, so a live run can
    /// tell when a deep shard holds coins. Opens the store read-only beside a
    /// running node (`QUIL_INSPECT_STORE`); nothing is written.
    #[test]
    #[ignore = "inspection of a node store"]
    fn inspect_quil_grid_sizes() {
        let Ok(path) = std::env::var("QUIL_INSPECT_STORE") else { return };
        let db = quil_store::RocksDb::open_for_read_only_live(Path::new(&path)).unwrap();
        let inner = db.inner();
        let hg = Arc::new(quil_store::RocksHypergraphStore::new(inner.clone()));
        let crdt = quil_hypergraph::HypergraphCrdt::new(
            hg as Arc<dyn quil_types::store::HypergraphStore>,
            Arc::new(quil_tries::ShaInclusionProver),
        );
        let quil = quil_execution::domains::QUIL_TOKEN;
        let mut grid_key = quil_hypergraph::addressing::get_bloom_filter_indices(&quil, 256, 3).to_vec();
        grid_key.extend_from_slice(&quil);
        let shards = quil_store::RocksShardsStore::new(inner.clone());
        let mut rows: Vec<(usize, String, u64, i128)> = shards
            .range_app_shards()
            .unwrap()
            .into_iter()
            .filter(|row| row.shard_key == grid_key)
            .map(|row| {
                let (_, bits) = grid_prefix_bits(&row.prefix);
                let (count, size) = crdt
                    .persisted_size_bucket(&quil_forest::Forest::addr_path_shard_id(&quil, &row.prefix))
                    .unwrap_or((0, 0));
                (bits.len(), bits_str(&bits), count, size)
            })
            .collect();
        rows.sort();
        let head = quil_store::RocksClockStore::new(inner).get_latest_frame_number();
        println!("store {path} (GLOBAL head {head:?}): {} QUIL grid shards", rows.len());
        for (depth, bits, count, size) in &rows {
            println!("  depth={depth:>2} bits={bits:<10} leaves={count:<6} live_size={size}");
        }
        let deepest = rows.iter().map(|r| r.0).max().unwrap_or(0);
        let funded = rows.iter().filter(|r| r.2 > 0).map(|r| r.0).max().unwrap_or(0);
        println!("deepest shard: {deepest} bits; deepest holding data: {funded} bits");
    }

    /// Committed-but-undelivered coin outputs for one shard, read from a
    /// running regular's stores: `QUIL_INSPECT_STORE` (master: GLOBAL view),
    /// `QUIL_INSPECT_WORKER` (that shard's worker store) and
    /// `QUIL_INSPECT_FILTER` (hex filter). Nothing is written.
    #[test]
    #[ignore = "inspection of a node store"]
    fn inspect_pending_deliveries() {
        use quil_execution::token_intrinsic::{coin_blocks, delivery, global_commit, roots};
        let (Ok(master), Ok(worker), Ok(filter)) = (
            std::env::var("QUIL_INSPECT_STORE"),
            std::env::var("QUIL_INSPECT_WORKER"),
            std::env::var("QUIL_INSPECT_FILTER"),
        ) else { return };
        let open = |path: &str| {
            let db = quil_store::RocksDb::open_for_read_only_live(Path::new(path)).unwrap();
            let crdt = quil_hypergraph::HypergraphCrdt::new(
                Arc::new(quil_store::RocksHypergraphStore::new(db.inner())) as Arc<dyn quil_types::store::HypergraphStore>,
                Arc::new(quil_tries::ShaInclusionProver),
            );
            crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE));
            crdt.set_unified_tree(true);
            (db, Arc::new(crdt))
        };
        let (_global_db, global) = open(&master);
        let (_local_db, local) = open(&worker);
        let filter = hex::decode(filter).unwrap();
        let (application, shard) = quil_forest::decode_shard_filter_or_root(&filter, 32).unwrap();
        let application: [u8; 32] = application.try_into().unwrap();
        let network = quil_lattice_ct::confidential::transfer::network_identifier(1);
        let limits = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(1).snapshots;
        let global = quil_execution::hypergraph_state::HypergraphState::new(global);
        let local = quil_execution::hypergraph_state::HypergraphState::new(local);
        let width = global_commit::placement_width(&global, &application).unwrap();
        println!("shard {} placement width {width}", bits_str(&shard));
        for block in coin_blocks::owned_blocks(&shard, width) {
            let committed = global_commit::block_sequence(&global, &application, block).unwrap();
            let delivered = roots::block_count(&local, &network, &application, block, limits).unwrap();
            if committed > 0 || delivered > 0 {
                println!("  block {block} width {}: committed {committed}, delivered {delivered}",
                    coin_blocks::creation_width(block));
            }
        }
        match delivery::pending_deliveries(&global, &local, &network, &application, &shard, limits, 16) {
            Ok(pending) => {
                println!("pending deliveries: {}", pending.len());
                for item in pending {
                    println!("  block {} seq {} source {:?} frame {}", item.block, item.seq,
                        item.source_shard.bits().map(|b| bits_str(&b)), item.source_frame);
                }
            }
            Err(error) => println!("pending deliveries failed: {error}"),
        }
    }

    /// Dry runs of the clock cleanups against one store, opened read-only:
    /// staged application frames with an identical canonical copy, and GLOBAL
    /// candidates below a margin at heights with a canonical record. Also the
    /// store's total logical bytes and its candidate and staged families, for
    /// projection. Nothing is written.
    #[test]
    #[ignore = "inspection of a node store"]
    fn inspect_clock_retention() {
        let Ok(path) = std::env::var("QUIL_INSPECT_STORE") else { return };
        let db = open_inspected(&path);
        let inner = db.inner();
        let (mut total, mut staged, mut candidates) = ((0u64, 0u64), (0u64, 0u64), (0u64, 0u64));
        let mut it = inner.raw_iterator();
        it.seek_to_first();
        while let (Some(key), Some(value)) = (it.key(), it.value()) {
            let bytes = (key.len() + value.len()) as u64;
            total = (total.0 + 1, total.1 + bytes);
            match key {
                [0x00, 0x02, ..] => staged = (staged.0 + 1, staged.1 + bytes),
                [0x00, 0x0F, ..] | [0x00, 0xF8, ..] => candidates = (candidates.0 + 1, candidates.1 + bytes),
                _ => {}
            }
            it.next();
        }
        println!("store {path}");
        println!("  total logical: {} keys, {} bytes", total.0, total.1);
        println!("  staged shard frames: {} keys, {} bytes", staged.0, staged.1);
        println!("  GLOBAL candidates (headers + request bodies): {} keys, {} bytes", candidates.0, candidates.1);
        let clock = quil_store::RocksClockStore::new(inner.clone());
        let pass = clock.prune_committed_staged_shard_frames(None, usize::MAX, true).unwrap();
        println!("  staged cleanup (dry run): deletable {} ({} bytes), kept: differing {}, uncommitted {}, malformed {}",
            pass.deleted, pass.deleted_bytes, pass.differing, pass.uncommitted, pass.malformed);
        println!("  head {:?}, executed cursor {:?}", clock.get_latest_frame_number(), clock.get_global_materialized_cursor());
        for margin in [1440u64, 64] {
            let pass = clock.prune_global_candidates(margin, 0, usize::MAX, true).unwrap();
            println!("  candidate prune margin {margin} (dry run): limit {:?}, deletable {} ({} request keys, {} bytes), kept in record holes {}",
                pass.limit, pass.pruned, pass.pruned_request_keys, pass.pruned_bytes, pass.kept_in_holes);
        }
    }

    /// Where each non-monotonic root-version history breaks, read-only:
    /// `QUIL_INSPECT_STORE`. For every indexed tree whose versions and frames
    /// do not rise together, the entries around the first break, sorted by
    /// version, and the tree's persisted head version.
    #[test]
    #[ignore = "inspection of a node store"]
    fn inspect_root_version_breaks() {
        use std::collections::HashMap;
        let Ok(path) = std::env::var("QUIL_INSPECT_STORE") else { return };
        let db = quil_store::RocksDb::open_for_read_only_live(Path::new(&path)).unwrap();
        let inner = db.inner();
        let mut trees: HashMap<Vec<u8>, Vec<(u64, u64)>> = HashMap::new();
        let mut it = inner.raw_iterator();
        it.seek([quil_store::encoding::HG_ROOT_VERSION]);
        while let (Some(key), Some(value)) = (it.key(), it.value()) {
            if key[0] != quil_store::encoding::HG_ROOT_VERSION { break; }
            if value.len() == 16 && key.len() > 35 {
                trees.entry(key[1..key.len() - 32].to_vec()).or_default().push((
                    u64::from_be_bytes(value[..8].try_into().unwrap()),
                    u64::from_be_bytes(value[8..].try_into().unwrap()),
                ));
            }
            it.next();
        }
        let forest = quil_forest::Forest::with_namespace(inner.clone(), quil_store::FOREST_NAMESPACE);
        for (tree, mut entries) in trees {
            entries.sort();
            let Some(first) = entries.windows(2).position(|w| w[0].0 >= w[1].0 || w[0].1 > w[1].1) else { continue };
            let breaks = entries.windows(2).filter(|w| w[0].0 >= w[1].0 || w[0].1 > w[1].1).count();
            let phase = quil_forest::PHASES[usize::from(tree[0]) * 2 + usize::from(tree[1])];
            let head = forest.read_head_version(&tree[2..], phase).ok().flatten();
            println!("tree {} ({} entries, {breaks} breaks, head version {head:?}, max indexed {:?})",
                hex::encode(&tree), entries.len(), entries.iter().map(|e| e.0).max());
            for (version, frame) in &entries[first.saturating_sub(2)..(first + 4).min(entries.len())] {
                println!("    version {version} frame {frame}");
            }
        }
    }

    /// Which GLOBAL frames one store lacks in `QUIL_INSPECT_FROM..=QUIL_INSPECT_TO`
    /// (default: the 64 below its head), read-only beside a running node
    /// (`QUIL_INSPECT_STORE`), with its head and executed cursor.
    #[test]
    #[ignore = "inspection of a node store"]
    fn inspect_global_frame_holes() {
        let Ok(path) = std::env::var("QUIL_INSPECT_STORE") else { return };
        let db = quil_store::RocksDb::open_for_read_only_live(Path::new(&path)).unwrap();
        let clock = quil_store::RocksClockStore::new(db.inner());
        let head = clock.get_latest_frame_number().unwrap_or(0);
        let from: u64 = std::env::var("QUIL_INSPECT_FROM").ok().and_then(|n| n.parse().ok()).unwrap_or(head.saturating_sub(64));
        let to: u64 = std::env::var("QUIL_INSPECT_TO").ok().and_then(|n| n.parse().ok()).unwrap_or(head);
        let missing: Vec<u64> = (from..=to).filter(|number| clock.get_global_clock_frame(*number).is_err()).collect();
        println!("store {path}: head {head}, executed cursor {:?}; GLOBAL frames {from}..={to} missing {}: {missing:?}",
            clock.get_global_materialized_cursor(), missing.len());
    }

    /// Whether a store still holds a shard's latest header state, read-only
    /// beside a running node: `QUIL_INSPECT_STORE` and `QUIL_INSPECT_FILTER`
    /// (hex). Per phase: the header's root, the subtree root at the tree's
    /// head, and the newest retained version whose subtree root equals the
    /// header's (`QUIL_INSPECT_LOOKBACK` versions back, default 5000).
    #[test]
    #[ignore = "inspection of a node store"]
    fn inspect_shard_subtree_vs_header() {
        let (Ok(path), Ok(filter)) = (std::env::var("QUIL_INSPECT_STORE"), std::env::var("QUIL_INSPECT_FILTER")) else { return };
        let lookback: u64 = std::env::var("QUIL_INSPECT_LOOKBACK").ok().and_then(|n| n.parse().ok()).unwrap_or(5000);
        let filter = hex::decode(filter).unwrap();
        let (app, bits) = quil_forest::decode_shard_filter_or_root(&filter, 32).unwrap();
        let db = quil_store::RocksDb::open_for_read_only_live(Path::new(&path)).unwrap();
        let forest = quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE);
        let clock = quil_store::RocksClockStore::new(db.inner());
        let header = clock.get_latest_shard_clock_frame(&filter).ok().and_then(|frame| frame.header);
        println!("store {path} shard {} ({} bits): latest frame {:?}", hex::encode(&filter[32..]), bits.len(),
            header.as_ref().map(|h| h.frame_number));
        let Some(header) = header else { return };
        for (index, phase) in quil_forest::PHASES.iter().enumerate() {
            let Some(expected) = header.state_roots.get(index).and_then(|root| <[u8; 32]>::try_from(root.as_slice()).ok()) else { continue };
            let Some(head) = forest.read_head_version(&app, *phase).unwrap() else {
                println!("  {phase:?}: no tree; header {}", hex::encode(&expected[..8]));
                continue;
            };
            let at_head = forest.app_subtree_root(&app, *phase, head, &bits).ok();
            let matched = (head.saturating_sub(lookback)..=head).rev()
                .find(|version| forest.app_subtree_root(&app, *phase, *version, &bits).ok() == Some(expected));
            println!("  {phase:?}: header {} head v{head} {} newest match {:?}", hex::encode(&expected[..8]),
                at_head.map_or("unreadable".into(), |root| hex::encode(&root[..8])),
                matched.map(|version| (version, head - version)));
        }
    }

    /// One shard's materialized cursor and latest stored frame, read-only from
    /// a running node's store: `QUIL_INSPECT_STORE` and `QUIL_INSPECT_FILTER`
    /// (hex). With `QUIL_INSPECT_FROM`, also the frames from there to the
    /// latest that the store cannot serve. Nothing is written.
    #[test]
    #[ignore = "inspection of a node store"]
    fn inspect_shard_cursor() {
        use quil_types::store::ClockStore as _;
        let (Ok(path), Ok(filter)) = (std::env::var("QUIL_INSPECT_STORE"), std::env::var("QUIL_INSPECT_FILTER")) else { return };
        let filter = hex::decode(filter).unwrap();
        let db = quil_store::RocksDb::open_for_read_only_live(Path::new(&path)).unwrap();
        let cursor = db.inner().get(quil_store::encoding::consensus_materialized_cursor_key(&filter)).unwrap()
            .filter(|v| v.len() == 8)
            .map(|v| u64::from_be_bytes(v.as_slice().try_into().unwrap()));
        let clock = quil_store::RocksClockStore::new(db.inner().clone());
        let latest = clock.get_latest_shard_clock_frame(&filter).ok().and_then(|f| f.header).map(|h| h.frame_number);
        println!("store {path} filter {}: materialized cursor {cursor:?}, latest frame {latest:?}", hex::encode(&filter));
        if let (Some(from), Some(latest)) = (std::env::var("QUIL_INSPECT_FROM").ok().and_then(|n| n.parse::<u64>().ok()), latest) {
            let missing: Vec<u64> = (from..=latest).filter(|n| clock.get_shard_clock_frame(&filter, *n, false).is_err()).collect();
            println!("  frames {from}..={latest} not stored: {missing:?}");
        }
    }

    /// The largest vertex rows of the QUIL application's coin keyspace (the
    /// rows a wallet scan pages over), read-only from one node's store:
    /// `QUIL_INSPECT_STORE`. The application-wide accumulator records are
    /// looked up by address. With `QUIL_INSPECT_FULL`, every row is walked:
    /// rows above 100 KiB, and the root history wherever it is, are printed
    /// with their size and leading bytes, and the totals split accumulator
    /// records from the rest (bytes per coin).
    #[test]
    #[ignore = "inspection of a node store"]
    fn inspect_large_coin_rows() {
        use quil_execution::token_intrinsic::{constants, legacy_migration, state};
        use quil_types::store::SnapshotReadable as _;
        let Ok(path) = std::env::var("QUIL_INSPECT_STORE") else { return };
        let app: [u8; 32] = hex::decode("11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d9").unwrap().try_into().unwrap();
        let db = quil_store::RocksDb::open_for_read_only_live(Path::new(&path)).unwrap();
        let store = quil_store::RocksHypergraphStore::new(db.inner());
        let snapshot = store.capture_snapshot().unwrap();
        let shard = quil_hypergraph::addressing::shard_key_for_location(
            &quil_hypergraph::addressing::Location { app_address: app, data_address: [0; 32] });
        for (name, address) in [
            ("root history", state::ROOT_ADDRESS),
            ("frontier", state::FRONTIER_ADDRESS),
            ("shape", state::SHAPE_ADDRESS),
            ("block summary", state::BLOCK_SUMMARY_ADDRESS),
            ("legacy accumulator root", constants::LEGACY_ACCUMULATOR_ROOT_ADDRESS),
            ("migration receipt", legacy_migration::MIGRATION_RECEIPT_ADDRESS),
        ] {
            let before = (u128::from_be_bytes(address[..16].try_into().unwrap()),
                u128::from_be_bytes(address[16..].try_into().unwrap()));
            let before = match before.1.checked_sub(1) {
                Some(low) => [before.0.to_be_bytes(), low.to_be_bytes()].concat(),
                None => [(before.0 - 1).to_be_bytes(), u128::MAX.to_be_bytes()].concat(),
            };
            let before: [u8; 32] = before.try_into().unwrap();
            let page = snapshot.page_vertex_underlying_fixed("vertex", "adds", &shard, &app, Some(&before),
                quil_types::store::VertexPageLimits { max_entries: 1, max_bytes: 64 << 20 }).unwrap();
            match page.entries.first() {
                Some((found, blob)) if *found == address => println!("{name}: {} bytes", blob.len()),
                _ => println!("{name}: absent"),
            }
        }
        // The full walk reads every coin row: `QUIL_INSPECT_FULL` only.
        if std::env::var_os("QUIL_INSPECT_FULL").is_none() {
            return;
        }
        let (mut after, mut rows, mut total) = (None::<[u8; 32]>, 0usize, 0usize);
        let (mut records, mut record_bytes) = (0usize, 0usize);
        loop {
            let page = snapshot.page_vertex_underlying_fixed("vertex", "adds", &shard, &app, after.as_ref(),
                quil_types::store::VertexPageLimits { max_entries: 64, max_bytes: 64 << 20 }).unwrap();
            for (address, blob) in &page.entries {
                rows += 1;
                total += blob.len();
                if state::is_accumulator_record(address) {
                    records += 1;
                    record_bytes += blob.len();
                }
                if blob.len() > 100 * 1024 || *address == state::ROOT_ADDRESS {
                    println!("{} {} bytes, head {}", hex::encode(address), blob.len(), hex::encode(&blob[..blob.len().min(24)]));
                }
                after = Some(*address);
            }
            if !page.has_more { break; }
        }
        println!("{rows} rows, {total} bytes");
        let (coins, coin_bytes) = (rows - records, total - record_bytes);
        println!("accumulator records {records} ({record_bytes} bytes); other rows {coins} ({coin_bytes} bytes, {} bytes each)",
            coin_bytes.checked_div(coins).unwrap_or(0));
    }

    /// A store's size as RocksDB estimates it, read-only beside a running node
    /// (`QUIL_INSPECT_STORE`): no key is read, so it costs nothing at any
    /// scale. With the grid's leaf counts this gives bytes per coin.
    #[test]
    #[ignore = "inspection of a node store"]
    fn inspect_store_totals() {
        let Ok(path) = std::env::var("QUIL_INSPECT_STORE") else { return };
        let db = quil_store::RocksDb::open_for_read_only_live(Path::new(&path)).unwrap();
        let inner = db.inner();
        println!("store {path}");
        for property in [
            "rocksdb.estimate-num-keys",
            "rocksdb.estimate-live-data-size",
            "rocksdb.total-sst-files-size",
            "rocksdb.live-sst-files-size",
            "rocksdb.num-live-versions",
        ] {
            println!("  {property}: {:?}", inner.property_int_value(property).ok().flatten());
        }
    }

    /// How fast one store serves the unified QUIL tree, read-only beside a
    /// running node (`QUIL_INSPECT_STORE`): per phase, the time to read every
    /// grid shard's subtree root at the phase head, and the time of sampled
    /// authenticated leaf reads (`QUIL_INSPECT_SAMPLES`, default 256, at
    /// hashed positions of the vertex keyspace), with the stored bytes of the
    /// sampled vertices. Nothing is written.
    #[test]
    #[ignore = "inspection of a node store"]
    fn inspect_forest_serving() {
        use sha2::{Digest as _, Sha256};
        use std::time::{Duration, Instant};
        let Ok(path) = std::env::var("QUIL_INSPECT_STORE") else { return };
        let samples: usize = std::env::var("QUIL_INSPECT_SAMPLES").ok().and_then(|n| n.parse().ok()).unwrap_or(256);
        let app = quil_execution::domains::QUIL_TOKEN;
        let db = quil_store::RocksDb::open_for_read_only_live(Path::new(&path)).unwrap();
        let inner = db.inner();
        let forest = quil_forest::Forest::with_namespace(inner.clone(), quil_store::FOREST_NAMESPACE);
        let mut grid_key = quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3).to_vec();
        grid_key.extend_from_slice(&app);
        let paths: Vec<Vec<bool>> = quil_store::RocksShardsStore::new(inner.clone())
            .range_app_shards()
            .unwrap()
            .into_iter()
            .filter(|row| row.shard_key == grid_key)
            .map(|row| grid_prefix_bits(&row.prefix).1)
            .collect();
        let summary = |mut times: Vec<Duration>| {
            times.sort();
            let total: Duration = times.iter().sum();
            let at = |q: usize| times.get((times.len() * q / 100).min(times.len().saturating_sub(1))).copied().unwrap_or_default();
            format!("n {} total {:?} p50 {:?} p99 {:?} max {:?}", times.len(), total, at(50), at(99), times.last().copied().unwrap_or_default())
        };
        let shard = quil_types::store::ShardKey { l1: quil_hypergraph::addressing::get_bloom_filter_indices(&app, 256, 3), l2: app };
        println!("store {path}: {} QUIL grid shards", paths.len());
        for (set, phase, tree) in [
            ("vertex", "adds", quil_forest::Phase::VertexAdds),
            ("vertex", "removes", quil_forest::Phase::VertexRemoves),
            ("hyperedge", "adds", quil_forest::Phase::HyperedgeAdds),
            ("hyperedge", "removes", quil_forest::Phase::HyperedgeRemoves),
        ] {
            let Some(head) = forest.read_head_version(&app, tree).unwrap() else {
                println!("{set}/{phase}: no tree");
                continue;
            };
            let (mut roots, mut failed) = (Vec::new(), 0usize);
            for bits in &paths {
                let start = Instant::now();
                match forest.app_subtree_root(&app, tree, head, bits) {
                    Ok(_) => roots.push(start.elapsed()),
                    Err(_) => failed += 1,
                }
            }
            // Sampled vertices: seek to a hashed position in the keyspace and
            // take the vertex found there, so no pass walks every key. Each
            // sample's rows (all versions) are measured for bytes per coin.
            let prefix = quil_store::encoding::hypergraph_vertex_data_v2_shard_prefix(set, phase, &shard);
            let mut it = inner.raw_iterator();
            it.seek(&prefix);
            let base = match it.key() {
                Some(key) if key.starts_with(&prefix) && key.len() >= prefix.len() + 8 => {
                    let vertex = &key[prefix.len()..key.len() - 8];
                    if vertex.len() >= 64 { vertex[..32].to_vec() } else { Vec::new() }
                }
                _ => {
                    println!("{set}/{phase}: head {head}, no vertex rows");
                    println!("  subtree roots: {} (failed {failed})", summary(roots));
                    continue;
                }
            };
            let (mut keys, mut rows, mut row_bytes, mut newest_bytes) = (Vec::new(), 0usize, 0usize, 0usize);
            let (mut seen, mut records) = (std::collections::BTreeSet::new(), 0usize);
            for sample in 0..samples as u64 {
                let mut target = prefix.clone();
                target.extend_from_slice(&base);
                target.extend_from_slice(&Sha256::digest(sample.to_be_bytes()));
                it.seek(&target);
                let Some(key) = it.key().filter(|key| key.starts_with(&prefix) && key.len() >= prefix.len() + 8) else { continue };
                let vertex = key[prefix.len()..key.len() - 8].to_vec();
                // A sparse keyspace sends many seeks to one vertex; the
                // accumulator's own records are measured by address instead.
                let data: Option<[u8; 32]> = vertex.get(32..64).and_then(|data| data.try_into().ok());
                if data.is_some_and(|data| quil_execution::token_intrinsic::state::is_accumulator_record(&data)) {
                    records += 1;
                    continue;
                }
                if !seen.insert(vertex.clone()) {
                    continue;
                }
                let mut newest = 0;
                while let (Some(key), Some(value)) = (it.key(), it.value()) {
                    if !key.starts_with(&prefix) || key.len() < prefix.len() + 8 || key[prefix.len()..key.len() - 8] != vertex[..] {
                        break;
                    }
                    rows += 1;
                    row_bytes += key.len() + value.len();
                    newest = key.len() + value.len();
                    it.next();
                }
                newest_bytes += newest;
                keys.push(if vertex.len() >= 64 { vertex[32..64].to_vec() } else { vertex });
            }
            let (mut reads, mut found) = (Vec::new(), 0usize);
            for key in &keys {
                let start = Instant::now();
                let (value, _) = forest.shard_phase_get_with_proof_raw(&app, tree, head, key).unwrap();
                reads.push(start.elapsed());
                found += usize::from(value.is_some());
            }
            println!("{set}/{phase}: head {head}, sampled vertices {} (seeks landing on accumulator records: {records})", keys.len());
            println!("  subtree roots: {} (failed {failed})", summary(roots));
            println!("  proof reads: {} (present {found})", summary(reads));
            println!("  sampled rows {rows} ({row_bytes} bytes; newest version {} bytes per vertex, all versions {} bytes per vertex)",
                newest_bytes.checked_div(keys.len()).unwrap_or(0), row_bytes.checked_div(keys.len()).unwrap_or(0));
        }
    }

    /// The coin deliveries each stored shard frame of the QUIL application
    /// carries, read-only from one node's clock store.
    #[test]
    #[ignore = "inspection of localnet stores"]
    fn inspect_frame_deliveries() {
        use quil_execution::token_intrinsic::delivery::CoinDelivery;
        use quil_types::proto::global::message_request::Request;
        let Ok(path) = std::env::var("QUIL_INSPECT_CLOCK") else { return };
        let network = quil_lattice_ct::confidential::transfer::network_identifier(
            std::env::var("QUIL_INSPECT_NETWORK").ok().and_then(|n| n.parse().ok()).unwrap_or(1));
        let app: [u8; 32] = hex::decode("11558584af7017a9bfd1ff1864302d643fbe58c62dcf90cbcd8fde74a26794d9").unwrap().try_into().unwrap();
        let db = quil_store::RocksDb::open_for_read_only(Path::new(&path)).unwrap();
        let clock = quil_store::RocksClockStore::new(db.inner());
        let from: u64 = std::env::var("QUIL_INSPECT_FROM").ok().and_then(|n| n.parse().ok()).unwrap_or(0);
        let to: u64 = std::env::var("QUIL_INSPECT_TO").ok().and_then(|n| n.parse().ok()).unwrap_or(400);
        for suffix in std::env::var("QUIL_INSPECT_FILTERS").unwrap_or_default().split(',').filter(|s| !s.is_empty()) {
            let mut filter = app.to_vec();
            filter.extend_from_slice(&hex::decode(suffix).unwrap());
            for number in from..=to {
                let Ok(frame) = clock.get_shard_clock_frame(&filter, number, false) else { continue };
                let header = frame.header.clone().unwrap_or_default();
                let mut carried = Vec::new();
                for request in frame.requests.iter().flat_map(|bundle| bundle.requests.iter()) {
                    if let Some(Request::TokenOperation(op)) = request.request.as_ref() {
                        match CoinDelivery::decode(&op.canonical_bytes, &network, &app) {
                            Ok(d) => carried.push(format!("block {:#x} seq {} src {} anchor-cited {}", d.block, d.seq, d.source_frame, d.cited_global_frame)),
                            Err(_) => carried.push(format!("op {:08x} tx {}",
                                u32::from_be_bytes(op.canonical_bytes[..4].try_into().unwrap_or([0; 4])),
                                hex::encode(&quil_execution::token_intrinsic::global_commit_tx_id(&op.canonical_bytes)[..4]))),
                        }
                    }
                }
                if !carried.is_empty() {
                    println!("{suffix} frame {number} rank {} ts {} prover {}: {}", header.rank, header.timestamp,
                        hex::encode(header.prover.get(..4).unwrap_or(&[])), carried.join("; "));
                }
            }
        }
    }
}

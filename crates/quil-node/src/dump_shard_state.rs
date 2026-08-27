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
        "grid-reset v2 frame: {}   prover-reset v3 frame: {}   unified cutover frame: {}",
        quil_execution::global_intrinsic::materialize::quil_grid_reset_v2_frame(),
        quil_execution::global_intrinsic::materialize::quil_prover_reset_v3_frame(),
        quil_execution::global_intrinsic::materialize::unified_tree_cutover_frame(),
    );

    // ---- reset markers ----
    println!("\n--- reset markers ---");
    println!("boot cutover reset applied: {}", crate::unified_consolidation::boot_reset_applied(&hg_store));
    println!("grid-reset v2 applied:      {}", crate::unified_consolidation::grid_reset_v2_applied(&hg_store));
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

    let provers = quil_execution::prover_registry::all_provers_with_allocations_committed(&crdt);
    // Each prover is (address, pubkey, [confirmation_filter, ...]).
    let mut by_filter: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
    for (_addr, _pubkey, filters) in &provers {
        for filter in filters {
            *by_filter.entry(filter.clone()).or_default() += 1;
        }
    }
    let quil_filters: Vec<(&Vec<u8>, &usize)> = by_filter
        .iter()
        .filter(|(f, _)| f.len() >= 32 && f[..32] == quil[..])
        .collect();
    println!(
        "\n--- PROVER ALLOCATIONS by confirmation_filter: {} provers, {} distinct QUIL filters ---",
        provers.len(),
        quil_filters.len()
    );
    let mut alloc_lines: Vec<(usize, String, &'static str, usize)> = quil_filters
        .iter()
        .map(|(f, c)| {
            let (enc, bits) = filter_bits(f);
            (bits.len(), bits_str(&bits), enc, **c)
        })
        .collect();
    alloc_lines.sort();
    for (depth, bits, enc, count) in &alloc_lines {
        println!("  depth={depth:>2} [{enc:<11}] {bits:<12} provers={count}");
    }
    let alloc_bits: Vec<Vec<bool>> = quil_filters.iter().map(|(f, _)| filter_bits(f).1).collect();
    println!("  ALLOCATION overlapping filters (a filter prefixing another): {}", count_overlaps(&alloc_bits));

    println!("\n=== DUMP COMPLETE ===");
    Ok(())
}

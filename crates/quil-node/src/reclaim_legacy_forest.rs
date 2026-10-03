//! `--reclaim-legacy-forest [db_path]`: one-time, offline reclaim of the orphaned
//! pre-cutover QUIL forest trees. Post-699500 (`UNIFIED_TREE_CUTOVER_FRAME`) QUIL
//! commits into ONE tree per phase keyed by the bare app address; the per-prefix
//! BYTE-SUFFIX trees (`addr_path_shard_id(QUIL, [i])`, the `--migrate-db` genesis
//! form) that the consolidation copied FROM are never read again but were never
//! deleted (the forest is put-only), leaving ~121M duplicate JMT leaves on disk.
//!
//! Reclaim is a STREAMING range-delete — `Forest::reset_shard_phase_trees` issues
//! one RocksDB range tombstone per (shard, phase), so nothing is loaded into
//! memory regardless of tree size. A legacy byte-suffix shard id is 36 bytes
//! (`app(32) ‖ [i](4)`), which can never equal the unified tree's id (the bare
//! 32-byte app) or a sentinel grid shard's (60 bytes) — so the wipe provably
//! cannot touch live state. The tool asserts the unified app-phase root is
//! UNCHANGED across the wipe (no consensus-visible effect), then compacts to give
//! the space back. Idempotent via a marker. Destructive on the DB — run with the
//! node shut down (point it at the node's data dir, or leave the path empty to use
//! `config.db.path`).

use std::path::Path;
use std::sync::Arc;

const RECLAIM_MARKER_KEY: &[u8] = b"\x00__quil_legacy_forest_reclaimed__";

pub fn run_reclaim_legacy_forest(
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

    println!("=== RECLAIM LEGACY FOREST (destructive, offline) ===");
    println!("database: {db_path}");
    println!("network:  {network}");

    let db = quil_store::RocksDb::open(Path::new(&db_path))
        .map_err(|e| anyhow::anyhow!("open rocksdb {db_path}: {e}"))?;
    let inner = db.inner();
    let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(inner.clone()));

    if hg_store.raw_db().get(RECLAIM_MARKER_KEY).ok().flatten().is_some() {
        println!("\nalready reclaimed (marker present) — nothing to do.");
        println!("\n=== RECLAIM COMPLETE ===");
        return Ok(());
    }
    if !hg_store.has_forest_data() {
        anyhow::bail!("DB has no forest data (not migrated) — nothing to reclaim");
    }

    let quil = quil_execution::domains::QUIL_TOKEN;

    // A CRDT view purely to REPORT the before/after tree stats (read-only).
    let inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver> =
        Arc::new(quil_tries::ShaInclusionProver);
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
        inclusion_prover,
    ));
    quil_forest_migrate::install_forest_boot(crdt.as_ref(), hg_store.as_ref(), false, network == 0);

    let before = crdt.dump_app_forest_stats(&quil);
    let unified_root_before = before.unified[0].1;
    println!(
        "\nBEFORE: unified VertexAdds leaves={} root={}",
        before.unified[0].0,
        hex::encode(unified_root_before)
    );
    println!(
        "        legacy per-prefix trees with data: {}   total legacy VertexAdds leaves: {}",
        before.legacy_nonempty.len(),
        before.legacy_total_vertex_adds
    );
    if before.legacy_total_vertex_adds == 0 {
        println!("\nno legacy leaves present — writing marker and exiting (nothing to reclaim).");
        let _ = hg_store.raw_db().put(RECLAIM_MARKER_KEY, [1u8]);
        println!("\n=== RECLAIM COMPLETE ===");
        return Ok(());
    }

    // Wipe every legacy byte-suffix QUIL shard tree `addr_path_shard_id(QUIL, [i])`
    // (i in 0..64 — the `--migrate-db` / `quil_shards_for_app` genesis grid, which
    // is exactly what `dump_app_forest_stats` counts as "legacy"). Each id is 36
    // bytes, disjoint from the unified (32) and sentinel-grid (60) ids, so the wipe
    // cannot reach live state. `reset_shard_phase_trees` range-deletes all 4 phase
    // trees per shard — streaming, no in-memory materialization.
    let forest = quil_forest::Forest::with_namespace(
        hg_store.raw_db(),
        quil_store::FOREST_NAMESPACE.to_vec(),
    );
    let mut wiped = 0usize;
    for i in 0..64u32 {
        let shard_id = quil_forest::Forest::addr_path_shard_id(&quil, &[i]);
        forest
            .reset_shard_phase_trees(&shard_id)
            .map_err(|e| anyhow::anyhow!("wipe legacy shard [{i}]: {e}"))?;
        wiped += 1;
    }
    println!("\nwiped {wiped} legacy byte-suffix shard trees (4 phases each) via range-delete.");

    // Compact the forest namespace so the range tombstones actually free disk now
    // rather than at some later background compaction.
    let lower = quil_store::FOREST_NAMESPACE.to_vec();
    let mut upper = quil_store::FOREST_NAMESPACE.to_vec();
    // FOREST_NAMESPACE is a single non-0xFF byte; exclusive upper = +1.
    *upper.last_mut().unwrap() += 1;
    hg_store.raw_db().compact_range(Some(lower.as_slice()), Some(upper.as_slice()));
    println!("compacted the forest namespace to release the tombstoned space.");

    // Safety proof: the unified app-phase root — the consensus-visible commitment —
    // must be byte-identical after the wipe. The legacy trees are a separate
    // keyspace, so this holds; assert it so a mistake can never ship silently.
    let after = crdt.dump_app_forest_stats(&quil);
    let unified_root_after = after.unified[0].1;
    println!(
        "\nAFTER:  unified VertexAdds leaves={} root={}",
        after.unified[0].0,
        hex::encode(unified_root_after)
    );
    println!(
        "        legacy total VertexAdds leaves: {} (expected 0)",
        after.legacy_total_vertex_adds
    );
    if unified_root_before != unified_root_after {
        anyhow::bail!(
            "ABORT: unified app root CHANGED across the wipe ({} -> {}) — refusing to mark done",
            hex::encode(unified_root_before),
            hex::encode(unified_root_after)
        );
    }
    if after.legacy_total_vertex_adds != 0 {
        println!(
            "  WARNING: {} legacy leaves remain — a deeper (non-depth-1) legacy encoding may exist; \
             re-run --dump-shard-state to inspect.",
            after.legacy_total_vertex_adds
        );
    }
    println!("  unified app root UNCHANGED — reclaim had no consensus-visible effect.");

    hg_store
        .raw_db()
        .put(RECLAIM_MARKER_KEY, [1u8])
        .map_err(|e| anyhow::anyhow!("write reclaim marker: {e}"))?;
    println!("\n=== RECLAIM COMPLETE ===");
    Ok(())
}

//! `--migrate-db`: convert the node's existing KZG state into the Phase-3 JMT
//! forest **in place** — the forest is written into the same RocksDB under
//! `quil_store::FOREST_NAMESPACE` (a reserved prefix disjoint from every
//! hypergraph key), so the migrated DB carries both the legacy data and the
//! forest. The runtime then gates the forest commitment path on
//! `RocksHypergraphStore::has_forest_data()`, so only a migrated DB switches
//! off KZG. The heavy lifting lives in `quil_forest_migrate`; this is the CLI
//! glue that opens the stores, guards against a double migration, and reports.

use std::path::Path;

use quil_types::store::ClockStore;

/// Migrate the DB at `target` (empty → `config.db.path`) in place by adding
/// the JMT forest under `FOREST_NAMESPACE`.
pub fn run_migrate_db(target: &Path, config: &quil_config::Config) -> anyhow::Result<()> {
    let path = if target.as_os_str().is_empty() {
        config.db.path.clone()
    } else {
        target.to_string_lossy().into_owned()
    };
    if path.is_empty() {
        anyhow::bail!("no database path given and config.db.path is empty");
    }

    println!("=== Migrating KZG state → JMT forest (in place) ===");
    println!("database (rocksdb): {path}");

    let db = quil_store::RocksDb::open(Path::new(&path))
        .map_err(|e| anyhow::anyhow!("open rocksdb {path}: {e}"))?;
    let inner = db.inner();
    let clock = quil_store::RocksClockStore::new(inner.clone());
    let hg = quil_store::RocksHypergraphStore::new(inner.clone());
    // Source each app's shard set from the shards store so a DB whose apps have
    // already split (non-uniformly) migrates onto the correct sub-shard structure
    // — not the hardcoded QUIL=64/else=1 default.
    let shards_store = quil_store::RocksShardsStore::new(inner.clone());

    // Idempotency guard: a DB that already carries forest data is already
    // migrated — re-running would double-commit at fresh versions.
    if hg.has_forest_data() {
        println!("forest data already present — DB is already migrated; nothing to do");
        return Ok(());
    }

    let head_n = clock
        .get_latest_global_clock_frame()
        .ok()
        .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
        .unwrap_or(0);
    println!("head frame: {head_n}");

    // Step 1 — legacy coins FIRST. The forest is content-addressed over the live
    // vertex set, so the verenc→transparent conversion (which also removes the
    // verenc originals) MUST run before the tree is built, or the forest would
    // encode the old blobs and double-count. Idempotent: a no-op if already done.
    println!("--- converting legacy verenc coins → transparent (pre-forest) ---");
    match crate::legacy_migration::convert_legacy_coins_in_place(&db)? {
        Some(summary) => println!(
            "converted {} legacy verenc coins → transparent entries (total value moved: {})",
            summary.migrated, summary.total_amount
        ),
        None => println!("legacy coins already converted (shadow root present) — skipping"),
    }

    // Step 2 — build the JMT forest over the now-transparent state.
    println!("--- building JMT forest ---");
    let report =
        quil_forest_migrate::run_conversion_in_place_with_shards(&hg, &shards_store, 0, head_n)
            .map_err(|e| anyhow::anyhow!("forest conversion failed: {e}"))?;

    println!(
        "converted {} shards across {} apps; {} global trees written",
        report.shards,
        report.apps,
        report.global_roots.len()
    );
    for (idx, root) in &report.global_roots {
        println!("  global[{idx:#04x}] root = {}", hex::encode(root));
    }
    println!("=== migration complete ===");
    Ok(())
}

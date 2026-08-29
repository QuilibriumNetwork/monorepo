//! `--dry-run-reset <frame>`: OFFLINE validation of the unified split reset
//! against a real snapshot DB (point it at a COPY of a mainnet node's data dir).
//!
//! It opens the store, reports the BEFORE grid + prover state, runs the exact
//! flag-day reset (QUIL grid → genesis topology + prover-tree wipe/rebuild from
//! the genesis committee), and reports the AFTER state — so we can verify on real
//! mainnet state that the reset collapses the legacy cascade (`removed_rows > 1`,
//! non-prefix-free → prefix-free), wipes the stranded provers, and reseeds the
//! genesis committee, WITHOUT ever connecting to the network. Destructive on the
//! DB it's pointed at (run on a copy).

use std::path::Path;
use std::sync::Arc;

use quil_types::store::{ClockStore, KvDb, ShardInfo, ShardKey, ShardsStore};

pub fn run_dry_run_reset(
    path: &Path,
    config: &quil_config::Config,
    network: u8,
    cutover_frame_arg: u64,
) -> anyhow::Result<()> {
    let db_path = if path.as_os_str().is_empty() {
        config.db.path.clone()
    } else {
        path.to_string_lossy().into_owned()
    };
    if db_path.is_empty() {
        anyhow::bail!("no database path given and config.db.path is empty");
    }

    println!("=== DRY-RUN: unified split reset (OFFLINE, against snapshot) ===");
    println!("database (rocksdb): {db_path}");
    println!("network: {network}");

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
    // Default the simulated cutover to just past head so the reseed's
    // frame-numbered writes are ahead of the snapshot.
    let cutover_frame = if cutover_frame_arg == 0 { head + 1 } else { cutover_frame_arg };
    println!("head frame: {head}   simulated cutover frame: {cutover_frame}");

    if !hg_store.has_forest_data() {
        anyhow::bail!(
            "this DB has no forest data (not migrated) — the reset operates on the JMT forest; \
             run against a migrated mainnet snapshot"
        );
    }

    // CRDT backed by the on-disk forest (same wiring as boot).
    let inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver> =
        Arc::new(quil_tries::ShaInclusionProver);
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
        inclusion_prover,
    ));
    quil_forest_migrate::install_forest_boot(crdt.as_ref(), hg_store.as_ref(), false, network == 0);

    // QUIL app grid key: l1(3) ‖ l2(32).
    let quil = quil_execution::domains::QUIL_TOKEN;
    let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(&quil, 256, 3);
    let mut grid_key = Vec::with_capacity(3 + 32);
    grid_key.extend_from_slice(&l1);
    grid_key.extend_from_slice(&quil);
    let prover_shard = ShardKey { l1: [0u8; 3], l2: [0xffu8; 32] };

    // ---- BEFORE ----
    let before_rows: Vec<ShardInfo> = shards_store
        .range_app_shards()?
        .into_iter()
        .filter(|s| s.shard_key == grid_key)
        .collect();
    let before_prefixes: Vec<Vec<u32>> = before_rows.iter().map(|s| s.prefix.clone()).collect();
    let before_provers =
        quil_execution::prover_registry::all_provers_with_allocations_committed(&crdt);
    let legacy_panics = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // The whole-app aggregate over the committed set — panics on a
        // non-prefix-free grid (`app_root_from_shard_paths` OOB).
        let bits = quil_forest::canonical_shard_bit_paths(&before_prefixes);
        let shards: Vec<(Vec<bool>, [u8; 32])> = bits.into_iter().map(|b| (b, [0u8; 32])).collect();
        let _ = quil_forest::app_root_from_shard_paths(&shards);
    }))
    .is_err();
    let before_pending = shards_store
        .all_pending_shard_changes()?
        .into_iter()
        .filter(|pc| pc.parent.len() >= 32 && pc.parent[..32] == quil)
        .count();

    println!("\n--- BEFORE reset ---");
    println!("QUIL shard rows:        {}", before_rows.len());
    println!("QUIL pending changes:   {before_pending}");
    println!("global prover records:  {}", before_provers.len());
    println!(
        "legacy whole-app aggregate over this grid PANICS (non-prefix-free): {legacy_panics}"
    );
    if before_prefixes.len() <= 40 {
        println!("QUIL prefixes: {before_prefixes:?}");
    }

    // ---- RESET ----
    println!("\n--- running reset at frame {cutover_frame} ---");
    // (1) QUIL grid → genesis topology (mainnet 64-way, testnet single), in the
    // canonical sentinel format the real reset commits.
    let genesis_prefixes: Vec<Vec<u32>> = quil_forest::genesis_grid_prefixes(network);
    let txn = KvDb::new_batch(&db, false)?;
    for s in &before_rows {
        shards_store.delete_app_shard(txn.as_ref(), &s.shard_key, &s.prefix)?;
    }
    for p in &genesis_prefixes {
        shards_store.put_app_shard(
            txn.as_ref(),
            &ShardInfo {
                shard_key: grid_key.clone(),
                prefix: p.clone(),
                size: Vec::new(),
                data_shards: 0,
                commitment: Vec::new(),
            },
        )?;
    }
    for pc in shards_store.all_pending_shard_changes()? {
        if pc.parent.len() >= 32 && pc.parent[..32] == quil {
            shards_store.delete_pending_shard_change(txn.as_ref(), &pc.parent, pc.effective_epoch)?;
        }
    }
    txn.commit()?;
    println!("(1) QUIL grid reset to genesis topology ({} rows)", genesis_prefixes.len());

    // (2) Prover-tree wipe + rebuild from the genesis committee.
    let seeded = quil_engine::genesis::reset_prover_tree_to_genesis(
        &crdt,
        hg_store.as_ref(),
        cutover_frame,
        network,
        &config.engine.genesis_seed,
        &[],
    )
    .map_err(|e| anyhow::anyhow!("prover-tree reset: {e}"))?;
    println!("(2) prover tree wiped + rebuilt — seeded {seeded} genesis provers");

    // ---- AFTER ----
    let after_rows: Vec<ShardInfo> = shards_store
        .range_app_shards()?
        .into_iter()
        .filter(|s| s.shard_key == grid_key)
        .collect();
    let after_prefixes: Vec<Vec<u32>> = after_rows.iter().map(|s| s.prefix.clone()).collect();
    let after_provers =
        quil_execution::prover_registry::all_provers_with_allocations_committed(&crdt);
    let after_panics = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bits = quil_forest::canonical_shard_bit_paths(&after_prefixes);
        let shards: Vec<(Vec<bool>, [u8; 32])> = bits.into_iter().map(|b| (b, [0u8; 32])).collect();
        let _ = quil_forest::app_root_from_shard_paths(&shards);
    }))
    .is_err();
    let prover_root = crdt.compute_shard_root("vertex", "adds", &prover_shard);

    println!("\n--- AFTER reset ---");
    println!("QUIL shard rows:        {} (was {})", after_rows.len(), before_rows.len());
    println!("global prover records:  {} (was {})", after_provers.len(), before_provers.len());
    println!("legacy aggregate PANICS: {after_panics}  (expect false ⇒ prefix-free)");
    println!("prover-shard adds root:  {}", hex::encode(&prover_root));

    let ok = after_provers.len() == seeded && !after_panics;
    println!(
        "\n=== DRY-RUN {} ===",
        if ok { "PASS" } else { "CHECK OUTPUT — unexpected result" }
    );
    Ok(())
}

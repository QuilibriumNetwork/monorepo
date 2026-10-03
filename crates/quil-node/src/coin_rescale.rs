//! `--fix-coin-scale`: in-place correction of a DB migrated by the OLD,
//! byte-shifted legacy-coin decode, which inflated every coin amount by exactly
//! 256× (a one-byte left shift).
//!
//! This is the cheap remedy: it operates on the ALREADY-transparent coins, so it
//! does NOT re-decrypt the 100+ GB of verenc originals (the expensive migration
//! step) and does NOT need a pre-migration backup. Per coin it divides the amount
//! by 256 (lossless — the low byte is 0), rebuilds the tree with the same owner
//! and same origin, and re-keys to the corrected content address. The output is
//! byte-identical to a fresh migration run with the FIXED decode.
//!
//! Steps, in order:
//!   1. rescale every transparent coin (legacy 0x30 keyspace): ÷256 + re-key.
//!   2. rewrite the coin-conservation receipt with the corrected Σ.
//!   3. wipe the JMT forest and rebuild it fresh from the corrected coins
//!      (coin content addresses changed, so the whole forest changes).
//! Run `--verify-db` afterward to confirm.

use std::path::Path;
use std::sync::Arc;

use quil_execution::hypergraph_state::HypergraphState;
use quil_execution::token_intrinsic::legacy_migration;
use quil_types::store::ClockStore;

pub fn run_fix_coin_scale(target: &Path, config: &quil_config::Config) -> anyhow::Result<()> {
    let path = if target.as_os_str().is_empty() {
        config.db.path.clone()
    } else {
        target.to_string_lossy().into_owned()
    };
    if path.is_empty() {
        anyhow::bail!("no database path given and config.db.path is empty");
    }

    println!("=== Correcting inflated legacy coin amounts (÷256, in place) ===");
    println!("database (rocksdb): {path}");

    let db = quil_store::RocksDb::open(Path::new(&path))
        .map_err(|e| anyhow::anyhow!("open rocksdb {path}: {e}"))?;
    let inner = db.inner();
    let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(inner.clone()));
    let shards_store = quil_store::RocksShardsStore::new(inner.clone());

    // Guard: the DB must already be migrated (transparent coins + forest present).
    // Running this on an unmigrated DB would be a no-op scan that then wipes a
    // forest that isn't there.
    if !hg_store.has_forest_data() {
        anyhow::bail!(
            "no forest data — this DB has not been migrated (run --migrate-db first). \
             --fix-coin-scale only corrects an already-migrated DB."
        );
    }

    let domain = &quil_execution::domains::QUIL_TOKEN[..];

    // ---- 1. Rescale every transparent coin: ÷256 + re-key ------------------
    println!("--- rescaling transparent coins (÷256, re-key) ---");
    const CHUNK: usize = 8_192;
    const REPORT: std::time::Duration = std::time::Duration::from_secs(30);
    let start = std::time::Instant::now();
    let mut last = std::time::Instant::now();
    let mut progress = |scanned: usize, rescaled: usize| {
        if last.elapsed() < REPORT {
            return;
        }
        last = std::time::Instant::now();
        let secs = start.elapsed().as_secs_f64();
        let rate = if secs > 0.0 { scanned as f64 / secs } else { 0.0 };
        println!("  … scanned {scanned}, rescaled {rescaled} coins ({rate:.0}/s, {:.0}m)", secs / 60.0);
    };
    // Any coin whose amount isn't a clean multiple of 256 makes this hard-fail
    // (the data would not be uniformly inflated and ÷256 could lose value).
    let summary = legacy_migration::rescale_all_legacy_coins(&hg_store, domain, CHUNK, &mut progress)
        .map_err(|e| anyhow::anyhow!("coin rescale failed: {e}"))?;
    println!(
        "  rescaled {} coins in {:.0}s; corrected Σ = {} sub-units",
        summary.migrated,
        start.elapsed().as_secs_f64(),
        summary.total_amount
    );

    // ---- 2. Rewrite the coin-conservation receipt with the corrected Σ -----
    // Written through the CRDT (same path the migration used) so it supersedes
    // the old inflated receipt in the versioned keyspace that `--verify-db` and
    // the forest rebuild read.
    println!("--- rewriting coin-conservation receipt ---");
    let inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver> =
        Arc::new(quil_tries::ShaInclusionProver);
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
        inclusion_prover,
    ));
    let state = HypergraphState::new(crdt.clone());
    legacy_migration::write_migration_receipt(
        &state,
        domain,
        summary.migrated as u64,
        summary.total_amount,
    )
    .map_err(|e| anyhow::anyhow!("write corrected receipt failed: {e}"))?;
    state.commit().map_err(|e| anyhow::anyhow!("state commit failed: {e}"))?;
    let head_n = quil_store::RocksClockStore::new(inner.clone())
        .get_latest_global_clock_frame()
        .ok()
        .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
        .unwrap_or(0);
    crdt.commit(head_n).map_err(|e| anyhow::anyhow!("receipt commit failed: {e}"))?;

    // ---- 3. Wipe + rebuild the forest from the corrected coins -------------
    // Every coin's content address changed, so the whole forest is stale. Clear
    // it and rebuild fresh (version 0), exactly like a first migration — this
    // also re-seeds the sync-by-hash indexes.
    println!("--- rebuilding JMT forest from corrected coins ---");
    hg_store
        .clear_forest_data()
        .map_err(|e| anyhow::anyhow!("clear forest failed: {e}"))?;
    let report =
        quil_forest_migrate::run_conversion_in_place_with_shards(&hg_store, &shards_store, 0, head_n)
            .map_err(|e| anyhow::anyhow!("forest rebuild failed: {e}"))?;
    println!(
        "  rebuilt {} shards across {} apps; {} global trees",
        report.shards,
        report.apps,
        report.global_roots.len()
    );

    println!("=== coin-scale correction complete ===");
    println!("Run `--verify-db {path}` to confirm coin conservation + trie roots.");
    Ok(())
}

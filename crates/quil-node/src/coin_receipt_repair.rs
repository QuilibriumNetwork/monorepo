//! `--repair-receipt`: recompute the coin-conservation receipt from the migrated
//! TRANSPARENT coin set and rewrite it in place.
//!
//! A legacy migration that was STOPPED AND RESTARTED writes a receipt covering
//! only its FINAL run. The migration physically deletes each verenc original as
//! it converts it, and every run's counters restart at 0, so coins converted by
//! an earlier (interrupted) run are invisible to the final run's tally. The
//! migrated STATE is complete and conserved — per-chunk writes are atomic, so no
//! coin is ever deleted without its transparent replacement, and restarts
//! correctly skip already-migrated (already-deleted) coins — but the RECEIPT
//! undercounts.
//!
//! This pass sums the actual transparent set (ground truth, which accumulates
//! across all runs) and rewrites the receipt so `--verify-db`'s coin-conservation
//! check reconciles cleanly. Read-mostly: the only write is the single receipt
//! vertex. Idempotent. It REFUSES to shrink a receipt (transparent < receipt ⇒
//! coins actually missing, not merely under-counted — investigate first).

use std::path::Path;
use std::sync::Arc;

use quil_execution::token_intrinsic::legacy_migration;

pub fn run_repair_receipt(target: &Path, config: &quil_config::Config) -> anyhow::Result<()> {
    let path = if target.as_os_str().is_empty() {
        config.db.path.clone()
    } else {
        target.to_string_lossy().into_owned()
    };
    if path.is_empty() {
        anyhow::bail!("no database path given and config.db.path is empty");
    }

    println!("=== Repairing coin-conservation receipt (from transparent set) ===");
    println!("database (rocksdb): {path}");

    let db = quil_store::RocksDb::open(Path::new(&path))
        .map_err(|e| anyhow::anyhow!("open rocksdb {path}: {e}"))?;
    let inner = db.inner();
    let store = Arc::new(quil_store::RocksHypergraphStore::new(inner.clone()));
    let domain = &quil_execution::domains::QUIL_TOKEN[..];

    let existing = legacy_migration::read_migration_receipt_raw(&store, domain)
        .map_err(|e| anyhow::anyhow!("read receipt: {e}"))?;
    match existing {
        Some((c, t)) => println!("  existing receipt:  {c} coins, Σ = {t}"),
        None => println!("  existing receipt:  (none)"),
    }

    println!("  summing transparent coin set (ground truth) …");
    let started = std::time::Instant::now();
    let (count, total) = legacy_migration::sum_transparent_coins(&store, domain)
        .map_err(|e| anyhow::anyhow!("sum transparent coins: {e}"))?;
    println!(
        "  transparent set:   {count} coins, Σ = {total} ({}s)",
        started.elapsed().as_secs().max(1)
    );

    if count == 0 {
        anyhow::bail!(
            "no transparent coins found — this DB has not been migrated \
             (run --migrate-db / --migrate-legacy first). Nothing to repair."
        );
    }

    if let Some((c, t)) = existing {
        if c == count && t == total {
            println!("  receipt already matches the transparent set — nothing to repair.");
            println!("=== receipt repair complete (no change) ===");
            return Ok(());
        }
        if count < c || total < t {
            anyhow::bail!(
                "REFUSING to repair: the transparent set ({count} coins, Σ={total}) is SMALLER \
                 than the existing receipt ({c} coins, Σ={t}). That means coins are MISSING, not \
                 merely under-counted — investigate before overwriting the receipt."
            );
        }
    }

    legacy_migration::write_migration_receipt_raw(&store, domain, count, total)
        .map_err(|e| anyhow::anyhow!("write receipt: {e}"))?;
    println!("  receipt rewritten: {count} coins, Σ = {total}");
    println!("=== receipt repair complete ===");
    println!("Run --verify-db to confirm the coin-conservation check now passes.");
    Ok(())
}

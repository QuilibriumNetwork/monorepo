//! `--migrate-legacy`: one-shot archive-node conversion of pre-2.1 verenc coins
//! into compact **transparent public token entries** (Ed448-owner ‖ amount).
//!
//! Pre-2.1 coins are stored as verenc blobs under the hard-coded
//! `PUBLIC_READ_KEY` — already publicly readable, so they carry no privacy but
//! cost ~621 B each. This pass decrypts every legacy coin of the QUIL token
//! domain and re-materializes it as a compact transparent entry, then records
//! conservation totals from the complete converted set.
//! The decrypt is deterministic (same key everywhere) ⇒ every archive node
//! produces byte-identical output ⇒ consensus-safe.
//!
//! Mirrors the `--migrate-db` (KZG→forest) glue: open the store, guard against
//! a double run, convert, commit, report. A transparent coin can afterwards be
//! one-way **shielded** into a lattice private coin with its Ed448 signature.

use std::path::Path;

use quil_execution::token_intrinsic::legacy_migration::LegacyMigrationSummary;
use quil_execution::token_intrinsic::legacy_migration;

/// Migrate the DB at `target` (empty → `config.db.path`) in place: decrypt every
/// legacy verenc coin of the QUIL token domain into a transparent entry (and
/// remove the verenc original), then write the conservation receipt.
pub fn run_migrate_legacy(target: &Path, config: &quil_config::Config) -> anyhow::Result<()> {
    let path = if target.as_os_str().is_empty() {
        config.db.path.clone()
    } else {
        target.to_string_lossy().into_owned()
    };
    if path.is_empty() {
        anyhow::bail!("no database path given and config.db.path is empty");
    }

    println!("=== Migrating legacy verenc coins → transparent entries (in place) ===");
    println!("database (rocksdb): {path}");

    let db = quil_store::RocksDb::open(Path::new(&path))
        .map_err(|e| anyhow::anyhow!("open rocksdb {path}: {e}"))?;
    match convert_legacy_coins_in_place(&db)? {
        Some(summary) => println!(
            "migrated {} legacy verenc coins → transparent entries (total value moved: {})",
            summary.migrated, summary.total_amount
        ),
        None => println!(
            "conservation receipt already present — legacy migration already applied; nothing to do"
        ),
    }
    println!("=== legacy migration complete ===");
    Ok(())
}

/// Core legacy-coin conversion over an already-open DB handle. STREAMS every
/// legacy verenc coin of the QUIL token domain into a transparent entry and
/// PHYSICALLY DELETES the verenc original — writing straight to the KV keyspace
/// (no `HypergraphState`, no CRDT commit), so peak memory is O(chunk) even at
/// 100+ GB coin sets. Then writes the conservation receipt directly. The forest is rebuilt afterward.
///
/// Returns `None` when the DB is already migrated (valid receipt present — an
/// idempotent no-op), else `Some(summary)`. Shared by `--migrate-legacy` and the
/// unified `--migrate-db` so the coin pass is byte-identical either way and
/// always runs BEFORE the forest is built (the forest must be built over the
/// transparent set, never the verenc blobs).
pub fn convert_legacy_coins_in_place(
    db: &quil_store::RocksDb,
) -> anyhow::Result<Option<LegacyMigrationSummary>> {
    let inner = db.inner();
    let store = quil_store::RocksHypergraphStore::new(inner.clone());
    let domain = &quil_execution::domains::QUIL_TOKEN[..];
    // The receipt is written only after conversion and a full transparent-set
    // tally. A historical shadow root alone is not a completion marker.
    if legacy_migration::read_migration_receipt_raw(&store, domain)?.is_some() {
        return Ok(None);
    }

    // STREAMING verenc→transparent conversion: writes go straight to the KV
    // keyspace (no HypergraphState changeset, no per-coin KZG) so peak memory is
    // O(chunk) even at 100+ GB coin sets. The forest is rebuilt afterward. A
    // wall-clock-throttled line keeps a multi-hour run observable.
    let started = std::time::Instant::now();
    let mut last = started;
    let mut first = true;
    let mut progress = move |scanned: usize, migrated: usize| {
        let now = std::time::Instant::now();
        // Print the first line as soon as coins flow (so it's visibly alive),
        // then every 15s.
        if first || now.duration_since(last).as_secs() >= 15 {
            first = false;
            last = now;
            let secs = now.duration_since(started).as_secs().max(1);
            println!(
                "  coins: scanned {scanned}, migrated {migrated} ({}/s, {secs}s elapsed)",
                scanned as u64 / secs
            );
        }
    };
    let summary =
        legacy_migration::migrate_all_legacy_coins(&store, domain, 4096, &mut progress)
            .map_err(|e| anyhow::anyhow!("legacy coin migration failed: {e}"))?;

    // Include coins converted by an earlier interrupted invocation. Its
    // originals have already been deleted, so this invocation's counters alone
    // cannot establish conservation. This is an offline, exclusive-DB pass.
    let (count, total) = legacy_migration::sum_transparent_coins(&store, domain)?;
    legacy_migration::write_migration_receipt_raw(&store, domain, count, total)?;

    println!(
        "coin migration invocation: {} coins, Σ = {}; complete-set receipt: {} coins, Σ = {}",
        summary.migrated, summary.total_amount, count, total
    );
    Ok(Some(summary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_execution::token_intrinsic::constants::LEGACY_ACCUMULATOR_ROOT_ADDRESS;

    fn put_raw(store: &quil_store::RocksHypergraphStore, address: &[u8; 32], blob: &[u8]) {
        let domain = &quil_execution::domains::QUIL_TOKEN;
        let mut key = domain.to_vec(); key.extend_from_slice(address);
        store.migrate_put_vertex_underlying("vertex", "adds", &legacy_migration::coin_domain_shard(domain), &key, blob).unwrap();
    }

    fn put_transparent(store: &quil_store::RocksHypergraphStore, id: u8, amount: u128, malformed: bool) {
        let domain = &quil_execution::domains::QUIL_TOKEN;
        let mut tree = legacy_migration::create_transparent_coin_tree(
            &legacy_migration::TransparentCoin { owner_address: [9; 32], amount },
            &legacy_migration::transparent_type_hash(domain).unwrap(), &[id; 32]).unwrap();
        if malformed {
            tree.insert(&[4], &[0; 15], &[], &num_bigint::BigInt::from(15)).unwrap();
        }
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        put_raw(store, &[id; 32], &blob);
    }

    #[test]
    fn migration_receipt_includes_previously_converted_coins_and_is_idempotent() {
        for old_root in [false, true] {
            let db = quil_store::RocksDb::open_in_memory().unwrap();
            let store = quil_store::RocksHypergraphStore::new(db.inner());
            // Model completed chunks from a prior interrupted invocation.
            put_transparent(&store, 1, 7, false);
            put_transparent(&store, 2, 11, false);
            if old_root { put_raw(&store, &LEGACY_ACCUMULATOR_ROOT_ADDRESS, b"historical-root"); }
            let summary = convert_legacy_coins_in_place(&db).unwrap().unwrap();
            assert_eq!(summary.migrated, 0); // this run had no remaining verenc coins
            assert_eq!(legacy_migration::read_migration_receipt_raw(&store, &quil_execution::domains::QUIL_TOKEN).unwrap(), Some((2, 18)));
            assert!(convert_legacy_coins_in_place(&db).unwrap().is_none());
        }
    }

    #[test]
    fn migration_does_not_complete_with_invalid_totals_or_receipt() {
        let domain = &quil_execution::domains::QUIL_TOKEN;
        for failure in 0..4 {
            let db = quil_store::RocksDb::open_in_memory().unwrap();
            let store = quil_store::RocksHypergraphStore::new(db.inner());
            match failure {
                0 => { put_transparent(&store, 1, u128::MAX, false); put_transparent(&store, 2, 1, false); }
                1 => put_transparent(&store, 1, 7, true),
                2 => put_raw(&store, &legacy_migration::MIGRATION_RECEIPT_ADDRESS, &[0; 23]),
                _ => put_raw(&store, &legacy_migration::MIGRATION_RECEIPT_ADDRESS, &[0; 25]),
            }
            assert!(convert_legacy_coins_in_place(&db).is_err());
            if failure < 2 {
                assert!(legacy_migration::read_migration_receipt_raw(&store, domain).unwrap().is_none());
            }
        }
    }
}

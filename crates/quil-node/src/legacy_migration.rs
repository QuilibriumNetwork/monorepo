//! `--migrate-legacy`: one-shot archive-node conversion of pre-2.1 verenc coins
//! into compact **transparent public token entries** (Ed448-owner ‖ amount).
//!
//! Pre-2.1 coins are stored as verenc blobs under the hard-coded
//! `PUBLIC_READ_KEY` — already publicly readable, so they carry no privacy but
//! cost ~621 B each. This pass decrypts every legacy coin of the QUIL token
//! domain and re-materializes it as a ~72 B transparent entry, then refreshes
//! the lattice shadow-accumulator root so the new transparent set is committed.
//! The decrypt is deterministic (same key everywhere) ⇒ every archive node
//! produces byte-identical output ⇒ consensus-safe.
//!
//! Mirrors the `--migrate-db` (KZG→forest) glue: open the store, guard against
//! a double run, convert, commit, report. A transparent coin can afterwards be
//! one-way **shielded** into a lattice private coin with its Ed448 signature.

use std::path::Path;

use quil_execution::token_intrinsic::legacy_migration::LegacyMigrationSummary;
use quil_execution::token_intrinsic::{legacy_migration, shadow_accumulator};

/// Migrate the DB at `target` (empty → `config.db.path`) in place: decrypt every
/// legacy verenc coin of the QUIL token domain into a transparent entry (and
/// remove the verenc original), then refresh the shadow-accumulator root.
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
            "shadow-accumulator root already present — legacy migration already applied; nothing to do"
        ),
    }
    println!("=== legacy migration complete ===");
    Ok(())
}

/// Core legacy-coin conversion over an already-open DB handle. STREAMS every
/// legacy verenc coin of the QUIL token domain into a transparent entry and
/// PHYSICALLY DELETES the verenc original — writing straight to the KV keyspace
/// (no `HypergraphState`, no CRDT commit), so peak memory is O(chunk) even at
/// 100+ GB coin sets. Then writes the (empty) shadow-accumulator root + the
/// conservation receipt directly. The forest is rebuilt afterward.
///
/// Returns `None` when the DB is already migrated (shadow root present — an
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
    let shard = legacy_migration::coin_domain_shard(domain);

    // Idempotency guard: the shadow-accumulator root vertex is written at the END
    // of a successful migration, so its presence means "already migrated" (or a
    // fresh 2.1 DB with no legacy coins). Read the KV directly — no CRDT.
    let acc_vk = {
        let mut k = domain.to_vec();
        k.extend_from_slice(&shadow_accumulator::ACC_ROOT_ADDRESS);
        k
    };
    if store
        .load_vertex_underlying("vertex", "adds", &shard, &acc_vk)?
        .is_some()
    {
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

    // Write the (empty) lattice shadow-accumulator root DIRECTLY — a pre-2.1 DB
    // has no shielded coins, so it's provably empty (no full-set scan). Written
    // to the same unversioned keyspace the coins use, so the forest build picks
    // it up as a normal leaf.
    let acc_rec = shadow_accumulator::empty_root_record(domain)
        .map_err(|e| anyhow::anyhow!("shadow accumulator: {e}"))?;
    store.migrate_put_vertex_underlying("vertex", "adds", &shard, &acc_vk, &acc_rec)?;

    // Conservation receipt `(count u64 BE ‖ Σ u128 BE)` — the verenc originals are
    // gone, so `--verify-db` reconciles `Σ transparent` against this instead.
    let receipt_vk = {
        let mut k = domain.to_vec();
        k.extend_from_slice(&legacy_migration::MIGRATION_RECEIPT_ADDRESS);
        k
    };
    let mut rec = Vec::with_capacity(24);
    rec.extend_from_slice(&(summary.migrated as u64).to_be_bytes());
    rec.extend_from_slice(&summary.total_amount.to_be_bytes());
    store.migrate_put_vertex_underlying("vertex", "adds", &shard, &receipt_vk, &rec)?;

    println!(
        "coin migration complete: {} coins, Σ = {} (shadow root + receipt written)",
        summary.migrated, summary.total_amount
    );
    Ok(Some(summary))
}

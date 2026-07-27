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
use std::sync::Arc;

use quil_execution::hypergraph_state::HypergraphState;
use quil_execution::token_intrinsic::legacy_migration::LegacyMigrationSummary;
use quil_execution::token_intrinsic::{legacy_migration, shadow_accumulator};
use quil_types::store::ClockStore;

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

/// Core legacy-coin conversion over an already-open DB handle. Decrypts every
/// legacy verenc coin of the QUIL token domain into a transparent entry,
/// **removes the verenc original** (tombstone), refreshes the lattice
/// shadow-accumulator root, and commits both the state changeset and the CRDT.
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
    let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(inner.clone()));
    let inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver> =
        Arc::new(quil_tries::ShaInclusionProver);
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
        inclusion_prover,
    ));
    let state = HypergraphState::new(crdt.clone());

    let domain = &quil_execution::domains::QUIL_TOKEN[..];

    // Idempotency guard: a recorded shadow-accumulator root means the node has
    // already been migrated (or is a fresh 2.1 DB with no legacy coins).
    if shadow_accumulator::read_root(&state, domain)?.is_some() {
        return Ok(None);
    }

    let summary = legacy_migration::migrate_all_legacy_coins(&state, domain)
        .map_err(|e| anyhow::anyhow!("legacy migration failed: {e}"))?;

    // Rebuild + record the lattice shadow root over the migrated set so shields
    // can prove membership against it.
    shadow_accumulator::refresh_root(&state, domain)
        .map_err(|e| anyhow::anyhow!("shadow-root refresh failed: {e}"))?;
    state.commit().map_err(|e| anyhow::anyhow!("state commit failed: {e}"))?;

    let head_n = quil_store::RocksClockStore::new(inner)
        .get_latest_global_clock_frame()
        .ok()
        .and_then(|f| f.header.as_ref().map(|h| h.frame_number))
        .unwrap_or(0);
    crdt.commit(head_n)
        .map_err(|e| anyhow::anyhow!("hypergraph commit failed: {e}"))?;

    if let Some((depth, root)) = shadow_accumulator::read_root(&state, domain)? {
        println!("shadow-accumulator root (depth {depth}) = {}", hex::encode(root));
    }
    Ok(Some(summary))
}

//! End-to-end forest cutover: seed a RocksDB-backed hypergraph via a KZG-style
//! CRDT commit, migrate it in place (`run_conversion_in_place`), install the
//! forest on a fresh CRDT (`install_forest_if_migrated`), and confirm the next
//! commit produces 32-byte JMT forest roots — the Phase-3 state-commitment
//! authority — flowing through the same `commit` API the consensus consumers
//! read. Ties together every B1 piece that was validated in isolation.

use std::sync::Arc;

use num_bigint::BigInt;
use quil_hypergraph::{shard_key_for_location, HypergraphCrdt, Location};
use quil_store::RocksHypergraphStore;
use quil_types::store::HypergraphStore;

/// Deterministic 64-byte inclusion prover — stands in for KZG during seeding.
/// The forest re-commit flattens the persisted per-vertex blobs, so the stub's
/// commitment bytes never affect the forest roots.
struct StubProver;
impl quil_types::crypto::InclusionProver for StubProver {
    fn commit_raw(&self, data: &[u8], _: u64) -> quil_types::error::Result<Vec<u8>> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        data.hash(&mut h);
        let mut out = vec![0u8; 64];
        out[..8].copy_from_slice(&h.finish().to_be_bytes());
        Ok(out)
    }
    fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> quil_types::error::Result<Vec<u8>> {
        Ok(vec![0u8; 64])
    }
    fn verify_raw(
        &self,
        _: &[u8],
        _: &[u8],
        _: u64,
        _: &[u8],
        _: u64,
    ) -> quil_types::error::Result<bool> {
        Ok(true)
    }
    fn prove_multiple(
        &self,
        _: &[&[u8]],
        _: &[&[u8]],
        _: &[u64],
        _: u64,
    ) -> quil_types::error::Result<Box<dyn quil_types::crypto::Multiproof>> {
        Err(quil_types::error::QuilError::Internal("stub".into()))
    }
    fn verify_multiple(
        &self,
        _: &[&[u8]],
        _: &[&[u8]],
        _: &[u64],
        _: u64,
        _: &[u8],
        _: &[u8],
    ) -> bool {
        true
    }
}

fn open_db(path: &std::path::Path) -> Arc<rocksdb::DB> {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(true);
    Arc::new(rocksdb::DB::open(&opts, path).unwrap())
}

/// A production-shaped vertex: a serialized per-vertex tree with fields.
fn vertex_blob(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut t = quil_tries::VectorCommitmentTree::new();
    for (k, v) in fields {
        t.insert(k, v, &[], &BigInt::from(v.len() as u64)).unwrap();
    }
    quil_tries::serialize_go_tree(t.root.as_ref()).unwrap()
}

#[test]
fn migrate_then_forest_commit_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_db(dir.path());
    let hg = Arc::new(RocksHypergraphStore::new(db.clone()));

    // --- 1. Seed: a KZG-style CRDT commit persists per-vertex blobs + shard
    //        commits, so the converter's enumeration finds the shard. ---------
    let crdt = HypergraphCrdt::new(
        hg.clone() as Arc<dyn HypergraphStore>,
        Arc::new(StubProver),
    );
    let loc = Location { app_address: [0x2a; 32], data_address: [0x07; 32] };
    crdt.add_vertex(&loc, &vertex_blob(&[(&[0xFFu8; 32], b"prover:Prover")]))
        .unwrap();
    let head = 5u64;
    let seed_commits = crdt.commit(head).unwrap();
    let sk = shard_key_for_location(&loc);
    assert!(seed_commits.contains_key(&sk), "seeded shard committed");
    // The CRDT is forest-native — the seed commit produces 32-byte forest roots
    // (into the CRDT's default in-memory forest) and persists blobs to the store.
    assert_eq!(seed_commits[&sk][0].len(), 32, "forest-native CRDT commits 32-byte roots");
    // The rocks DB itself has no forest namespace yet (in-memory forest ≠ DB).
    assert!(!hg.has_forest_data(), "no forest data in the DB before migration");

    // --- 2. Migrate the DB in place (adds the forest under FOREST_NAMESPACE). -
    let report = quil_forest_migrate::run_conversion_in_place(hg.as_ref(), 0, head).unwrap();
    assert!(report.shards >= 1, "migration converted the seeded shard (shards={})", report.shards);
    assert!(hg.has_forest_data(), "forest data present after migration");

    // --- 3. Fresh CRDT on the migrated DB: install the forest and commit. ----
    let crdt2 = HypergraphCrdt::new(
        hg.clone() as Arc<dyn HypergraphStore>,
        Arc::new(StubProver),
    );
    assert!(
        quil_forest_migrate::install_forest_if_migrated(&crdt2, hg.as_ref()),
        "forest installed on a migrated DB"
    );
    // The migrated state is already committed in the forest; the forest-native
    // CRDT only commits what changed. Add a new vertex and commit to exercise
    // the forest-native commit path on the migrated DB.
    crdt2
        .add_vertex(
            &Location { app_address: [0x2a; 32], data_address: [0x08; 32] },
            &vertex_blob(&[(&[0xFFu8; 32], b"reward:ProverReward")]),
        )
        .unwrap();
    let forest_commits = crdt2.commit(head + 1).unwrap();
    let roots = forest_commits.get(&sk).expect("shard committed on forest path");
    assert_eq!(
        roots[0].len(),
        32,
        "vertex_adds is a 32-byte JMT forest root after migration + install"
    );

    // --- 4. Simulated RESTART: a fresh CRDT on the same DB (empty in-memory
    //        version map) must still PRODUCE a membership proof, reading the
    //        per-phase head version persisted into the forest during crdt2's
    //        commit. This is the restart-robustness the DB-staged head version
    //        buys over the ephemeral map alone. -----------------------------
    let crdt3 = HypergraphCrdt::new(
        hg.clone() as Arc<dyn HypergraphStore>,
        Arc::new(StubProver),
    );
    assert!(
        quil_forest_migrate::install_forest_if_migrated(&crdt3, hg.as_ref()),
        "forest installs on the restarted CRDT"
    );
    let new_loc = Location { app_address: [0x2a; 32], data_address: [0x08; 32] };
    let vertex_id = new_loc.to_id().to_vec();
    let mp = crdt3
        .build_membership_proof(
            "vertex",
            "adds",
            &sk,
            &[(vertex_id.clone(), vec![vec![0xFFu8; 32]])],
        )
        .expect("restarted CRDT produces a proof via the persisted head version");
    let root32: [u8; 32] = roots[0].as_slice().try_into().unwrap();
    quil_forest::verify_vertex_membership(
        &root32,
        &mp.inputs[0],
        &[(vec![0xFFu8; 32], b"reward:ProverReward".to_vec())],
    )
    .expect("proof from the restarted CRDT verifies against the committed root");
}

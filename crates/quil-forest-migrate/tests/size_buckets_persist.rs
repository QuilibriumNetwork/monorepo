//! The per-sub-shard live-size buckets persist across restart: session 1 commits
//! coins (buckets written atomically in the commit txn), session 2 reopens the
//! SAME RocksDB and `warm_sizes(&[])` — an EMPTY app list, so ONLY the persisted
//! fast-path can populate it (a re-scan would find nothing). Proves restart is
//! O(#sub-shards), not O(state).

use std::sync::Arc;

use num_bigint::BigInt;
use quil_forest::Forest;
use quil_hypergraph::{HypergraphCrdt, Location};
use quil_store::{RocksHypergraphStore, FOREST_NAMESPACE};
use quil_types::store::HypergraphStore;

struct StubProver;
impl quil_types::crypto::InclusionProver for StubProver {
    fn commit_raw(&self, _: &[u8], _: u64) -> quil_types::error::Result<Vec<u8>> { Ok(vec![0u8; 64]) }
    fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> quil_types::error::Result<Vec<u8>> { Ok(vec![0u8; 64]) }
    fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> quil_types::error::Result<bool> { Ok(true) }
    fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64) -> quil_types::error::Result<Box<dyn quil_types::crypto::Multiproof>> {
        Err(quil_types::error::QuilError::Internal("stub".into()))
    }
    fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { true }
}

fn open_db(path: &std::path::Path) -> Arc<rocksdb::DB> {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(true);
    Arc::new(rocksdb::DB::open(&opts, path).unwrap())
}

fn crdt(db: Arc<rocksdb::DB>, app: [u8; 32]) -> HypergraphCrdt {
    let hg = Arc::new(RocksHypergraphStore::new(db));
    let c = HypergraphCrdt::new(hg.clone() as Arc<dyn HypergraphStore>, Arc::new(StubProver));
    c.set_forest(Forest::with_namespace(hg.raw_db(), FOREST_NAMESPACE.to_vec()));
    c.set_shard_partition(app, 1);
    c
}

fn loc(app: [u8; 32], d0: u8, tag: u8) -> Location {
    let mut d = [0u8; 32];
    d[0] = d0;
    d[31] = tag;
    Location { app_address: app, data_address: d }
}

#[test]
fn size_buckets_persist_across_restart() {
    let app = [0xCDu8; 32];
    let dir = tempfile::tempdir().unwrap();

    // Session 1: add coins + commit → buckets persisted in the commit txn.
    {
        let c = crdt(open_db(dir.path()), app);
        c.add_vertex(&loc(app, 0x00, 1), b"coinAAAA").unwrap(); // 8 → shard 0
        c.add_vertex(&loc(app, 0xFF, 2), b"coinBB").unwrap(); // 6 → shard 63
        c.commit(1).unwrap();
        assert_eq!(c.total_size(), BigInt::from(14));
    } // db handle dropped → lock released

    // Session 2: reopen SAME db, warm with an EMPTY app list. Correct values can
    // ONLY come from the persisted buckets (a re-scan of "no apps" yields 0).
    {
        let c = crdt(open_db(dir.path()), app);
        c.warm_sizes(&[]).unwrap();
        assert_eq!(c.total_size(), BigInt::from(14), "buckets loaded from persistence");
        let s0 = c.sub_shard_metadata_for_filter(&[app.as_slice(), &[0u8]].concat()).unwrap();
        assert_eq!((s0.leaf_count, s0.size), (1, BigInt::from(8)));
        let s63 = c.sub_shard_metadata_for_filter(&[app.as_slice(), &[63u8]].concat()).unwrap();
        assert_eq!((s63.leaf_count, s63.size), (1, BigInt::from(6)));
    }
}

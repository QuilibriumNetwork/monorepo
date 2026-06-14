//! End-to-end test for `NodeService::GetVertexData`:
//!   1. Build a small VectorCommitmentTree in memory
//!   2. Serialize it in Go's `SerializeNonLazyTree` format
//!   3. Persist it to RocksHypergraphStore as vertex underlying data
//!   4. Call the handler with `full_data=false` — assert the known-
//!      index enumeration returns the exact leaves we wrote
//!   5. Call with `full_data=true` — assert raw_data is the exact
//!      serialized bytes qclient can pass to DeserializeNonLazyTree
//!
//! This covers the code path the Go→Rust interop tester can't
//! (cold-node Go client sees `entries=0` because no vertex data exists).

use std::sync::Arc;

use num_bigint::BigInt;
use tempfile::TempDir;
use tonic::Request;

use quil_crypto::KzgInclusionProver;
use quil_rpc::node_service::NodeRpcServer;
use quil_store::{RocksDb, RocksHypergraphStore};
use quil_tries::{serialize_go_tree, LazyVectorCommitmentTree, VectorCommitmentTree};
use quil_types::proto::node::{
    node_service_server::NodeService, GetHyperedgeDataRequest, GetVertexDataRequest,
};
use quil_types::store::{HypergraphStore, ShardKey};

/// Helper: build a tree with three well-known leaves, then commit
/// and serialize. Returns (bytes, leaves) where leaves is the
/// key→value map we inserted.
fn build_and_serialize() -> (Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>) {
    let leaves: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (vec![0u8], b"leaf-at-0".to_vec()),
        (vec![4u8], b"leaf-at-4".to_vec()),
        (vec![0xffu8], b"leaf-at-ff".to_vec()),
    ];
    let mut tree = VectorCommitmentTree::new();
    let size = BigInt::from(256u32);
    let hash_target = vec![0u8; 32];
    for (k, v) in &leaves {
        tree.insert(k, v, &hash_target, &size).unwrap();
    }
    let prover = KzgInclusionProver;
    tree.commit(&prover);
    let bytes = serialize_go_tree(tree.root.as_ref()).unwrap();
    (bytes, leaves)
}

#[tokio::test]
async fn get_vertex_data_round_trips_inserted_leaves() {
    let tmp = TempDir::new().unwrap();
    let db = RocksDb::open(tmp.path()).unwrap();
    let store = Arc::new(RocksHypergraphStore::new(Arc::new(db).inner()));

    // Vertex ID: 32-byte app address || 32-byte data address.
    let mut address = vec![0u8; 64];
    for (i, b) in address.iter_mut().enumerate().take(32) {
        *b = i as u8;
    }
    let app_address = &address[..32];
    let shard = ShardKey {
        l1: quil_hypergraph::addressing::get_bloom_filter_indices(app_address, 256, 3),
        l2: {
            let mut l2 = [0u8; 32];
            l2.copy_from_slice(app_address);
            l2
        },
    };

    let (serialized_tree, leaves) = build_and_serialize();
    // Persist the serialized sub-tree exactly the way Go's
    // `hypergraph.SetVertexData` → `store.SaveVertexTree` does, which the
    // Rust side mirrors with `save_vertex_underlying`. The handler reads
    // it back via `load_vertex_underlying_raw`, so the writer must use the
    // matching per-vertex key scheme (not `insert_node`, which keys the
    // global prover tree's individual nodes under a different prefix).
    store
        .save_vertex_underlying("vertex", "adds", &shard, &address, &serialized_tree)
        .unwrap();

    let svc = NodeRpcServer::new()
        .with_hypergraph_store(store.clone() as Arc<dyn HypergraphStore>);

    // full_data=false: enumerated known-index entries.
    let resp = svc
        .get_vertex_data(Request::new(GetVertexDataRequest {
            address: address.clone(),
            full_data: false,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.set_type, "vertex");
    assert_eq!(resp.phase_type, "adds");
    assert_eq!(resp.shard_l1, shard.l1.to_vec());
    assert_eq!(resp.shard_l2, shard.l2.to_vec());
    assert!(resp.raw_data.is_empty());

    // All three inserted leaves fell at indices in the canonical set
    // {0, 4, 8, 12, 16, 20, 24, 28, 0xff}, so all three should come
    // back.
    assert_eq!(resp.entries.len(), leaves.len());
    for (k, v) in &leaves {
        let found = resp
            .entries
            .iter()
            .find(|e| &e.key == k)
            .unwrap_or_else(|| panic!("missing entry for key {:?}", k));
        assert_eq!(&found.value, v, "value mismatch for key {:?}", k);
    }

    // full_data=true: raw_data is the exact Go-format serialized tree.
    let resp_full = svc
        .get_vertex_data(Request::new(GetVertexDataRequest {
            address: address.clone(),
            full_data: true,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(resp_full.entries.is_empty());
    assert_eq!(resp_full.raw_data, serialized_tree);
}

#[tokio::test]
async fn get_vertex_data_rejects_wrong_address_size() {
    let tmp = TempDir::new().unwrap();
    let db = RocksDb::open(tmp.path()).unwrap();
    let store = Arc::new(RocksHypergraphStore::new(Arc::new(db).inner()));
    let svc = NodeRpcServer::new()
        .with_hypergraph_store(store.clone() as Arc<dyn HypergraphStore>);

    let err = svc
        .get_vertex_data(Request::new(GetVertexDataRequest {
            address: vec![0u8; 32], // wrong — Go sets 64
            full_data: false,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn get_hyperedge_data_returns_known_indices() {
    let tmp = TempDir::new().unwrap();
    let db = RocksDb::open(tmp.path()).unwrap();
    let store = Arc::new(RocksHypergraphStore::new(Arc::new(db).inner()));

    let mut address = vec![0u8; 64];
    for (i, b) in address.iter_mut().enumerate().take(32) {
        *b = 0xA0 + i as u8;
    }
    let app_address = &address[..32];
    let shard = ShardKey {
        l1: quil_hypergraph::addressing::get_bloom_filter_indices(app_address, 256, 3),
        l2: {
            let mut l2 = [0u8; 32];
            l2.copy_from_slice(app_address);
            l2
        },
    };

    let (serialized_tree, leaves) = build_and_serialize();
    store
        .save_vertex_underlying("hyperedge", "adds", &shard, &address, &serialized_tree)
        .unwrap();

    let svc = NodeRpcServer::new()
        .with_hypergraph_store(store.clone() as Arc<dyn HypergraphStore>);

    let resp = svc
        .get_hyperedge_data(Request::new(GetHyperedgeDataRequest {
            address: address.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.set_type, "hyperedge");
    assert_eq!(resp.phase_type, "adds");
    assert_eq!(resp.entries.len(), leaves.len());
    for (k, v) in &leaves {
        let found = resp
            .entries
            .iter()
            .find(|e| &e.key == k)
            .unwrap_or_else(|| panic!("missing entry for key {:?}", k));
        assert_eq!(&found.value, v);
    }
}

#[tokio::test]
async fn get_vertex_data_round_trips_through_real_commit_path() {
    // Stronger variant of `get_vertex_data_round_trips_inserted_leaves`.
    //
    // The tests above hand-write the per-vertex blob with a direct
    // `save_vertex_underlying` call. That proves the handler's
    // load → `deserialize_go_tree` → canonical-index enumeration is
    // internally correct, but it does NOT prove byte-compatibility with
    // what production actually persists: the writer is mocked.
    //
    // In production nothing calls `save_vertex_underlying` by hand for a
    // vertex. The blob lands in the per-vertex keyspace as a side effect
    // of committing the *global* hypergraph tree: `LazyVectorCommitmentTree
    // ::commit` walks every leaf and persists its `value` via
    // `walk_leaves_persist` → `save_vertex_underlying`
    // (see `crates/quil-tries/src/lazy_tree.rs`). The global-tree leaf's
    // `value` IS the serialized underlying sub-tree, which is exactly what
    // `GetVertexData` later deserializes.
    //
    // So this test drives the real write path end-to-end: build a lazy
    // tree over the same (set, phase, shard), insert a leaf keyed by the
    // 64-byte vertex address whose value is the serialized sub-tree, then
    // `commit`. If the lazy commit's per-vertex persistence ever drifts
    // from the keyspace/format the handler reads, this fails where the
    // hand-written variant would stay green.
    let tmp = TempDir::new().unwrap();
    let db = RocksDb::open(tmp.path()).unwrap();
    let store = Arc::new(RocksHypergraphStore::new(Arc::new(db).inner()));

    let mut address = vec![0u8; 64];
    for (i, b) in address.iter_mut().enumerate().take(32) {
        *b = 0x30 + i as u8;
    }
    let app_address = &address[..32];
    let shard = ShardKey {
        l1: quil_hypergraph::addressing::get_bloom_filter_indices(app_address, 256, 3),
        l2: {
            let mut l2 = [0u8; 32];
            l2.copy_from_slice(app_address);
            l2
        },
    };

    let (serialized_tree, leaves) = build_and_serialize();

    // Persist via the production path: commit a lazy global tree whose one
    // leaf carries the serialized sub-tree as its value.
    let lazy = LazyVectorCommitmentTree::new(
        store.clone() as Arc<dyn HypergraphStore>,
        "vertex",
        "adds",
        shard.clone(),
        Vec::new(), // empty covered_prefix → no shard-range gate
    );
    lazy.insert(
        &address,
        &serialized_tree,
        &[],
        &BigInt::from(serialized_tree.len() as u64),
    )
    .unwrap();
    let txn = store.new_transaction(false).unwrap();
    let prover = KzgInclusionProver;
    lazy.commit(txn.as_ref(), &prover).unwrap();
    txn.commit().unwrap();

    let svc = NodeRpcServer::new()
        .with_hypergraph_store(store.clone() as Arc<dyn HypergraphStore>);

    let resp = svc
        .get_vertex_data(Request::new(GetVertexDataRequest {
            address: address.clone(),
            full_data: false,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.set_type, "vertex");
    assert_eq!(resp.phase_type, "adds");
    assert_eq!(
        resp.entries.len(),
        leaves.len(),
        "lazy-commit-persisted blob must enumerate the same leaves"
    );
    for (k, v) in &leaves {
        let found = resp
            .entries
            .iter()
            .find(|e| &e.key == k)
            .unwrap_or_else(|| panic!("missing entry for key {:?}", k));
        assert_eq!(&found.value, v, "value mismatch for key {:?}", k);
    }

    // full_data=true must hand back the exact bytes the lazy commit wrote.
    let resp_full = svc
        .get_vertex_data(Request::new(GetVertexDataRequest {
            address: address.clone(),
            full_data: true,
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp_full.raw_data, serialized_tree);
}

#[tokio::test]
async fn get_vertex_data_not_visible_when_commit_txn_aborted() {
    // Transaction-fidelity regression test.
    //
    // `get_vertex_data_round_trips_through_real_commit_path` proves the
    // *success* case: when the commit transaction is committed, the vertex
    // underlying blob is visible to the handler. This test covers the
    // *abort* case, which the success test cannot: when the surrounding
    // transaction is aborted (or the process dies before commit), the
    // vertex blob must NOT be durable.
    //
    // `LazyVectorCommitmentTree::commit` stages tree nodes into the txn via
    // `insert_node`, but persists each leaf's underlying value through
    // `walk_leaves_persist` → `save_vertex_underlying`. If that write
    // bypasses the txn and goes straight to RocksDB, the blob survives an
    // abort and `GetVertexData` serves data for a vertex whose tree/shard
    // commit never landed. After the fix, the leaf write joins the same
    // batch as the nodes, so aborting the txn discards everything.
    let tmp = TempDir::new().unwrap();
    let db = RocksDb::open(tmp.path()).unwrap();
    let store = Arc::new(RocksHypergraphStore::new(Arc::new(db).inner()));

    let mut address = vec![0u8; 64];
    for (i, b) in address.iter_mut().enumerate().take(32) {
        *b = 0x50 + i as u8;
    }
    let app_address = &address[..32];
    let shard = ShardKey {
        l1: quil_hypergraph::addressing::get_bloom_filter_indices(app_address, 256, 3),
        l2: {
            let mut l2 = [0u8; 32];
            l2.copy_from_slice(app_address);
            l2
        },
    };

    let (serialized_tree, _leaves) = build_and_serialize();

    // Drive the real commit path, but abort the transaction instead of
    // committing it.
    let lazy = LazyVectorCommitmentTree::new(
        store.clone() as Arc<dyn HypergraphStore>,
        "vertex",
        "adds",
        shard.clone(),
        Vec::new(), // empty covered_prefix → no shard-range gate
    );
    lazy.insert(
        &address,
        &serialized_tree,
        &[],
        &BigInt::from(serialized_tree.len() as u64),
    )
    .unwrap();
    let txn = store.new_transaction(false).unwrap();
    let prover = KzgInclusionProver;
    lazy.commit(txn.as_ref(), &prover).unwrap();
    txn.abort().unwrap(); // drop without committing

    let svc = NodeRpcServer::new()
        .with_hypergraph_store(store.clone() as Arc<dyn HypergraphStore>);

    // Nothing was committed, so the handler must see no vertex data.
    let resp = svc
        .get_vertex_data(Request::new(GetVertexDataRequest {
            address: address.clone(),
            full_data: false,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(
        resp.entries.is_empty(),
        "aborted commit must not leave enumerable vertex entries"
    );

    let resp_full = svc
        .get_vertex_data(Request::new(GetVertexDataRequest {
            address: address.clone(),
            full_data: true,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(
        resp_full.raw_data.is_empty(),
        "aborted commit must not leave a durable vertex underlying blob"
    );
}

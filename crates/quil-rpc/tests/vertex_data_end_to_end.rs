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
use quil_tries::{serialize_go_tree, VectorCommitmentTree};
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
    // `hypergraph.SetVertexData` → `store.SaveVertexTree` does.
    store
        .load_vertex_underlying_raw("vertex", "adds", &shard, &address)
        .unwrap(); // absent lookup is fine
    let txn = store.new_transaction(false).unwrap();
    store
        .insert_node(
            txn.as_ref(),
            "vertex",
            "adds",
            &shard,
            &address,
            &[],
            &serialized_tree,
        )
        .unwrap();
    // Commit the batch: RocksTxn buffers writes until `commit()`.
    txn.commit().unwrap();

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
    let txn = store.new_transaction(false).unwrap();
    store
        .insert_node(
            txn.as_ref(),
            "hyperedge",
            "adds",
            &shard,
            &address,
            &[],
            &serialized_tree,
        )
        .unwrap();
    txn.commit().unwrap();

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

//! Wallet and peer RPCs must share coverage, pagination and worker-store reads.
use std::sync::Arc;

use num_bigint::BigInt;
use quil_rpc::node_service::NodeRpcServer;
use quil_rpc::stub_services::{AppShardFrameProvider, AppShardRpcServer};
use quil_store::{RocksDb, RocksHypergraphStore};
use quil_types::proto::{global, node};
use quil_types::proto::global::app_shard_service_server::AppShardService;
use quil_types::proto::node::node_service_server::NodeService;
use quil_types::store::{CoinWitnessProvider, EscrowPageData, HypergraphStore, ShardKey};
use tonic::{Code, Request, Status};

const DOMAIN: [u8; 32] = [7; 32];

struct NoFrames;

#[tonic::async_trait]
impl AppShardFrameProvider for NoFrames {
    async fn get_app_shard_frame(&self, _: Vec<u8>, _: u64)
        -> Result<Option<global::AppShardFrame>, Status> {
        panic!("wallet reads must not request frames")
    }
}

struct Escrows;

impl CoinWitnessProvider for Escrows {
    fn escrow_page(&self, domain: &[u8; 32], id: Option<&[u8; 32]>, after: Option<&[u8; 32]>)
        -> quil_types::error::Result<Option<EscrowPageData>> {
        assert_eq!(domain, &DOMAIN);
        assert!(id.is_none() || id == Some(&[8; 32]));
        Ok(Some(EscrowPageData {
            network: [11; 32], snapshot_id: [8; 32],
            escrows: if after.is_none() { vec![([9; 32], vec![42; 64])] } else { vec![] },
            cursor: Some([9; 32]), has_more: after.is_none(),
        }))
    }
}

fn peer(covers: bool) -> AppShardRpcServer {
    AppShardRpcServer::with_provider(Arc::new(NoFrames))
        .with_coin_scan(Arc::new(Escrows), Arc::new(move |app| covers && app == DOMAIN))
}

#[tokio::test]
async fn partial_peer_refuses_every_wallet_read() {
    let peer = peer(false);
    let request = || Request::new(global::ListShardCoinsRequest {
        domain: DOMAIN.to_vec(), ..Default::default()
    });
    assert_eq!(peer.list_shard_coins(request()).await.unwrap_err().code(), Code::Unavailable);
    assert_eq!(peer.list_shard_escrows(request()).await.unwrap_err().code(), Code::Unavailable);
    assert_eq!(peer.get_shard_coin_witnesses(Request::new(global::GetShardCoinWitnessesRequest {
        domain: DOMAIN.to_vec(), addresses: vec![vec![1; 32]],
    })).await.unwrap_err().code(), Code::Unavailable);
    assert_eq!(peer.get_shard_vertex(Request::new(global::GetShardVertexRequest {
        address: [DOMAIN.to_vec(), vec![1; 32]].concat(),
    })).await.unwrap_err().code(), Code::Unavailable);
    let own = NodeRpcServer::new().with_coin_witness_provider(Arc::new(Escrows))
        .with_application_coverage(Arc::new(|_| false));
    assert_eq!(own.list_escrows(Request::new(node::ListCoinsRequest {
        domain: DOMAIN.to_vec(), ..Default::default()
    })).await.unwrap_err().code(), Code::Unavailable);
}

#[tokio::test]
async fn forwarded_escrow_scan_preserves_pages_and_rejects_changed_snapshot() {
    let peer = Arc::new(peer(true));
    let wallet = NodeRpcServer::new().with_application_coverage(Arc::new(|_| false))
        .with_remote_escrow_page(Arc::new(move |domain, id, after| {
            let peer = peer.clone();
            Box::pin(async move {
                let page = peer.list_shard_escrows(Request::new(global::ListShardCoinsRequest {
                    domain: domain.to_vec(), snapshot_id: id.map(Vec::from).unwrap_or_default(),
                    after: after.map(Vec::from).unwrap_or_default(),
                })).await.ok()?.into_inner();
                Some(EscrowPageData {
                    network: page.network.try_into().ok()?, snapshot_id: page.snapshot_id.try_into().ok()?,
                    escrows: page.escrows.into_iter().map(|e| Some((e.address.try_into().ok()?, e.raw_data)))
                        .collect::<Option<_>>()?,
                    cursor: Some(page.cursor.try_into().ok()?), has_more: page.has_more,
                })
            })
        }));
    let first = wallet.list_escrows(Request::new(node::ListCoinsRequest {
        domain: DOMAIN.to_vec(), ..Default::default()
    })).await.unwrap().into_inner();
    assert_eq!(first.network, vec![11; 32]);
    assert_eq!(first.escrows[0].raw_data, vec![42; 64]);
    assert!(first.has_more);
    let last = wallet.list_escrows(Request::new(node::ListCoinsRequest {
        domain: DOMAIN.to_vec(), snapshot_id: first.snapshot_id, after: first.cursor,
    })).await.unwrap().into_inner();
    assert!(!last.has_more);
    assert!(last.escrows.is_empty());

    let changed = NodeRpcServer::new().with_application_coverage(Arc::new(|_| false))
        .with_remote_escrow_page(Arc::new(|_, _, after| Box::pin(async move {
            Some(EscrowPageData {
                network: [11; 32], snapshot_id: [99; 32], escrows: vec![], cursor: after, has_more: false,
            })
        })));
    assert_eq!(changed.list_escrows(Request::new(node::ListCoinsRequest {
        domain: DOMAIN.to_vec(), snapshot_id: vec![8; 32], after: vec![9; 32],
    })).await.unwrap_err().code(), Code::Internal);
}

#[tokio::test]
async fn forwarded_vertex_reads_find_worker_data_and_preserve_tree_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let stores: Vec<Arc<RocksHypergraphStore>> = (0..3).map(|i| {
        let db = RocksDb::open(&tmp.path().join(i.to_string())).unwrap();
        Arc::new(RocksHypergraphStore::new(Arc::new(db).inner()))
    }).collect();
    let shard = ShardKey {
        l1: quil_hypergraph::addressing::get_bloom_filter_indices(&DOMAIN, 256, 3), l2: DOMAIN,
    };
    let address = [DOMAIN.to_vec(), vec![1; 32]].concat();
    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.insert(&[0], b"worker marker", &[0; 32], &BigInt::from(256)).unwrap();
    tree.commit(&quil_tries::ShaInclusionProver);
    let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
    stores[2].save_vertex_underlying("vertex", "adds", &shard, &address, &blob).unwrap();
    let workers: Vec<Arc<dyn HypergraphStore>> = stores[1..].iter()
        .map(|store| store.clone() as Arc<dyn HypergraphStore>).collect();
    let peer = Arc::new(peer(true).with_vertex_stores(stores[0].clone(), Arc::new(move |_| Ok(workers.clone()))));
    let wallet = NodeRpcServer::new().with_application_coverage(Arc::new(|_| false))
        .with_remote_vertex({
            let peer = peer.clone();
            Arc::new(move |domain, data_address| {
                let peer = peer.clone();
                Box::pin(async move {
                    let vertex = peer.get_shard_vertex(Request::new(global::GetShardVertexRequest {
                        address: [domain.to_vec(), data_address].concat(),
                    })).await.ok()?.into_inner();
                    Some((vertex.found, vertex.blob))
                })
            })
        });
    for full_data in [true, false] {
        let result = wallet.get_vertex_data(Request::new(node::GetVertexDataRequest {
            address: address.clone(), full_data,
        })).await.unwrap().into_inner();
        assert_eq!(result.present, Some(true));
        assert_eq!(result.shard_l2, DOMAIN);
        if full_data {
            assert_eq!(result.raw_data, blob);
        } else {
            assert_eq!(result.entries.len(), 1);
            assert_eq!(result.entries[0].value, b"worker marker");
        }
    }
    let missing = wallet.get_vertex_data(Request::new(node::GetVertexDataRequest {
        address: [DOMAIN.to_vec(), vec![2; 32]].concat(), full_data: true,
    })).await.unwrap().into_inner();
    assert_eq!(missing.present, Some(false));

    // Disagreement during handoff cannot become arbitrary marker data or a
    // false absence, even when the first worker is the stale one.
    stores[1].save_vertex_underlying("vertex", "adds", &shard, &address, b"stale").unwrap();
    assert_eq!(peer.get_shard_vertex(Request::new(global::GetShardVertexRequest {
        address,
    })).await.unwrap_err().code(), Code::Unavailable);
}

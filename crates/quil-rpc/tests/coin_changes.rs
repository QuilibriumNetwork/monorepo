//! Coin change RPC validation and forwarding.
use quil_rpc::node_service::NodeRpcServer;
use quil_types::proto::node::{
    self,
    node_service_client::NodeServiceClient,
    node_service_server::{NodeService, NodeServiceServer},
};
use quil_types::store::{CoinChangesPageData, CoinData, CoinWitnessProvider};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

async fn feed_status(domain: Vec<u8>) -> tonic::Code {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let incoming = async_stream::stream! {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => yield Ok::<_, std::io::Error>(stream),
                Err(error) => { yield Err(error); break; }
            }
        }
    };
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(NodeServiceServer::new(NodeRpcServer::new()))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = NodeServiceClient::new(channel);
    let result = client
        .list_coin_changes(node::ListCoinChangesRequest {
            domain,
            cursor: Vec::new(),
            max_coins: 0,
        })
        .await;
    server.abort();
    result.unwrap_err().code()
}

#[tokio::test]
async fn coin_changes_rejects_invalid_domain_before_reading_state() {
    assert_eq!(feed_status(vec![7; 31]).await, tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn coin_changes_without_provider_is_unimplemented() {
    assert_eq!(feed_status(vec![7; 32]).await, tonic::Code::Unimplemented);
}

struct Changes(Arc<AtomicUsize>);
impl CoinWitnessProvider for Changes {
    fn coin_changes(
        &self,
        _: &[u8; 32],
        _: &[u8],
        max: usize,
    ) -> quil_types::error::Result<Option<CoinChangesPageData>> {
        self.0.store(max, Ordering::SeqCst);
        Ok(Some(CoinChangesPageData {
            network: [7; 32],
            coins: [9u8, 2]
                .into_iter()
                .map(|i| CoinData {
                    address: [i; 32],
                    frame_number: u64::from(i),
                    position: u64::from(i),
                    owner: vec![0; 3648],
                    commitment: vec![0; 10368],
                    memo: vec![0; 1115],
                })
                .collect(),
            cursor: vec![1, 99],
            has_more: false,
            reset: false,
        }))
    }
}

#[tokio::test]
async fn coin_changes_clamps_pages_and_preserves_coin_frames_and_journal_order() {
    let seen = Arc::new(AtomicUsize::new(0));
    let server = NodeRpcServer::new().with_coin_witness_provider(Arc::new(Changes(seen.clone())));
    for (asked, expected) in [(0, 8), (1, 8), (999, 64)] {
        let page = server
            .list_coin_changes(tonic::Request::new(node::ListCoinChangesRequest {
                domain: vec![7; 32],
                cursor: vec![1],
                max_coins: asked,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(seen.load(Ordering::SeqCst), expected);
        assert_eq!(
            page.coins
                .iter()
                .map(|c| c.frame_number)
                .collect::<Vec<_>>(),
            vec![9, 2]
        );
        assert_eq!(page.next_cursor, vec![1, 99]);
        assert!(!page.reset);
    }
}

#[tokio::test]
async fn coin_changes_preserves_forwarded_unimplemented() {
    let server = NodeRpcServer::new()
        .with_application_coverage(Arc::new(|_| false))
        .with_remote_coin_changes(Arc::new(|_, _, _| {
            Box::pin(async { Err(tonic::Status::unimplemented("older peer")) })
        }));
    let status = server
        .list_coin_changes(tonic::Request::new(node::ListCoinChangesRequest {
            domain: vec![7; 32],
            cursor: vec![2; 40],
            max_coins: 8,
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn forwarded_coin_changes_stay_on_original_backend_after_coverage_changes() {
    let server = NodeRpcServer::new()
        .with_application_coverage(Arc::new(|_| true))
        .with_remote_coin_changes(Arc::new(|_, _, _| {
            Box::pin(async { Err(tonic::Status::unavailable("original backend offline")) })
        }));
    let status = server
        .list_coin_changes(tonic::Request::new(node::ListCoinChangesRequest {
            domain: vec![7; 32],
            cursor: vec![2; 40],
            max_coins: 8,
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable);
    assert!(status.message().contains("original backend"));
}

#[tokio::test]
async fn coin_changes_rejects_oversized_cursor_before_reading_provider() {
    let server = NodeRpcServer::new();
    let status = server
        .list_coin_changes(tonic::Request::new(node::ListCoinChangesRequest {
            domain: vec![7; 32],
            cursor: vec![1; quil_types::store::MAX_COIN_CHANGE_CURSOR_BYTES + 1],
            max_coins: 8,
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

struct NoFrames;
#[tonic::async_trait]
impl quil_rpc::stub_services::AppShardFrameProvider for NoFrames {
    async fn get_app_shard_frame(
        &self,
        _: Vec<u8>,
        _: u64,
    ) -> Result<Option<quil_types::proto::global::AppShardFrame>, tonic::Status> {
        panic!("coin feed must not read frames")
    }
}

#[tokio::test]
async fn peer_coin_changes_maps_identical_encrypted_outputs_and_refuses_incomplete_coverage() {
    use quil_types::proto::global::{self, app_shard_service_server::AppShardService};
    for covers in [true, false] {
        let peer = quil_rpc::stub_services::AppShardRpcServer::with_provider(Arc::new(NoFrames))
            .with_coin_scan(Arc::new(Changes(Arc::default())), Arc::new(move |_| covers));
        let result = peer
            .list_shard_coin_changes(tonic::Request::new(global::ListShardCoinChangesRequest {
                domain: vec![7; 32],
                cursor: vec![1],
                max_coins: 8,
            }))
            .await;
        if covers {
            let page = result.unwrap().into_inner();
            assert_eq!(
                page.coins
                    .iter()
                    .map(|c| c.frame_number)
                    .collect::<Vec<_>>(),
                vec![9, 2]
            );
            assert_eq!(page.coins[0].commitment.len(), 10368);
            assert_eq!(page.next_cursor, vec![1, 99]);
        } else {
            assert_eq!(result.unwrap_err().code(), tonic::Code::Unavailable);
        }
    }
}

#[tokio::test]
async fn coin_changes_rejects_a_stalled_more_page_but_accepts_an_empty_tail() {
    for has_more in [true, false] {
        let server = NodeRpcServer::new()
            .with_application_coverage(Arc::new(|_| false))
            .with_remote_coin_changes(Arc::new(move |_, cursor, _| {
                Box::pin(async move {
                    Ok(CoinChangesPageData {
                        network: [7; 32],
                        coins: vec![],
                        cursor,
                        has_more,
                        reset: false,
                    })
                })
            }));
        let result = server
            .list_coin_changes(tonic::Request::new(node::ListCoinChangesRequest {
                domain: vec![7; 32],
                cursor: vec![2; 40],
                max_coins: 8,
            }))
            .await;
        if has_more {
            assert_eq!(result.unwrap_err().code(), tonic::Code::Internal);
        } else {
            let page = result.unwrap().into_inner();
            assert!(page.coins.is_empty());
            assert!(!page.reset);
            assert!(!page.has_more);
        }
    }
}

#[tokio::test]
async fn coin_changes_rejects_reset_with_a_replacement_tip() {
    let server = NodeRpcServer::new()
        .with_application_coverage(Arc::new(|_| false))
        .with_remote_coin_changes(Arc::new(|_, _, _| {
            Box::pin(async {
                Ok(CoinChangesPageData {
                    network: [7; 32],
                    coins: vec![],
                    cursor: vec![2; 40],
                    has_more: false,
                    reset: true,
                })
            })
        }));
    let status = server
        .list_coin_changes(tonic::Request::new(node::ListCoinChangesRequest {
            domain: vec![7; 32],
            cursor: vec![2; 40],
            max_coins: 8,
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Internal);
}

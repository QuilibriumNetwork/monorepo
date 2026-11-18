use super::*;
use quil_execution::{
    global_intrinsic::storage_snapshot as snapshots, global_schema::GLOBAL_INTRINSIC_ADDRESS,
};

#[test]
fn selects_the_whole_requested_allocation_and_rejects_missing_or_duplicate_shards() {
    let a = hex::encode([1; 32]);
    let b = hex::encode([2; 32]);
    let rows = json!([{"filter":a,"size_bytes":"1"},{"filter":b,"size_bytes":"1000"}]);
    assert_eq!(select(&rows, Some(1), &[]).unwrap(), vec![vec![2; 32]]);
    assert!(select(&rows, Some(3), &[]).is_err());
    assert!(select(&rows, None, &[a.clone(), a.clone()]).is_err());
    assert!(select(&rows, None, &[hex::encode([3; 32])]).is_err());
    assert_eq!(select(&rows, None, &[a, b]).unwrap().len(), 2);
}
#[test]
fn rejects_stale_future_or_missing_checkpoint_time() {
    assert!(freshness(1_000_000, 1_100_000, 900).is_ok());
    // Archive clocks may be slightly ahead; accepted skew must not wrap to u64.
    assert!(freshness(1_101_000, 1_100_000, 900).is_ok());
    assert!(freshness(1_220_000, 1_100_000, 900).is_ok());
    assert!(freshness(1_220_001, 1_100_000, 900).is_err());
    assert!(freshness(1_000_000, 2_000_000, 900).is_err());
    assert!(freshness(2_000_000, 1_000_000, 900).is_err());
    assert!(freshness(0, 1, 900).is_err());
}
#[test]
fn command_parses_without_config_and_requires_an_explicit_workload() {
    use clap::Parser;
    let args = crate::Args::try_parse_from([
        "quil-node",
        "--benchmark-storage",
        "/tmp/quil-bench",
        "--benchmark-storage-seats",
        "16",
        "--benchmark-storage-allow-debug",
    ])
    .unwrap();
    validate(&args.storage_readiness).unwrap();
    let args = crate::Args::try_parse_from([
        "quil-node",
        "--benchmark-storage",
        "/tmp/quil-bench",
        "--benchmark-storage-allow-debug",
    ])
    .unwrap();
    assert!(validate(&args.storage_readiness).is_err());
    assert!(crate::Args::try_parse_from([
        "quil-node",
        "--benchmark-storage",
        "/tmp/quil-bench",
        "--benchmark-storage-seats",
        "2",
        "--benchmark-storage-filter",
        &hex::encode([1; 32])
    ])
    .is_err());
}
fn proof_record(
    held: &[u8],
    field_epoch: u64,
    at_address: &[u8],
    address_epoch: u64,
) -> ([u8; 32], Vec<u8>) {
    let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
    let graph = crate::master_node::worker_manager::build_thread_worker_hypergraph(
        &db,
        Arc::new(quil_tries::ShaInclusionProver),
        false,
    );
    graph.set_unified_tree(true);
    let record = quil_types::consensus::StorageSnapshotRoots {
        epoch: field_epoch,
        frame: 5,
        anchor: 3,
        roots: [[3; 32]; 4],
    };
    let tree = snapshots::to_tree(held, &record).unwrap();
    let address = snapshots::snapshot_address(address_epoch, at_address).unwrap();
    graph
        .add_vertex(
            &quil_hypergraph::Location {
                app_address: GLOBAL_INTRINSIC_ADDRESS,
                data_address: address,
            },
            &quil_execution::prover_registry::vertex_tree_to_blob(&tree),
        )
        .unwrap();
    graph
        .commit_with_global_cursor(6, &quil_store::encoding::global_materialized_cursor_key())
        .unwrap();
    let root = graph
        .current_forest_phase_root(&GLOBAL_INTRINSIC_ADDRESS, 0)
        .unwrap();
    let proof = graph
        .global_vertex_membership_at_root(&root, &address)
        .unwrap()
        .unwrap();
    (
        root,
        quil_forest::MembershipProof {
            inputs: vec![proof],
        }
        .to_bytes(),
    )
}
#[test]
fn authenticates_snapshot_identity_epoch_blob_and_checkpoint_root() {
    let f = [3; 32];
    let (root, bytes) = proof_record(&f, 1500, &f, 1500);
    assert!(snapshot_record(&root, &f, 1500, 10, &bytes).is_ok());
    assert!(snapshot_record(&[0; 32], &f, 1500, 10, &bytes).is_err());
    assert!(snapshot_record(&root, &f, 1500, 5, &bytes).is_err());
    let mut bad = bytes.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(snapshot_record(&root, &f, 1500, 10, &bad).is_err());
    let (root, bytes) = proof_record(&[4; 32], 1500, &f, 1500);
    assert!(snapshot_record(&root, &f, 1500, 10, &bytes).is_err());
    let (root, bytes) = proof_record(&f, 1499, &f, 1500);
    assert!(snapshot_record(&root, &f, 1500, 10, &bytes).is_err());
}
#[tokio::test]
async fn http_errors_and_oversized_selection_bodies_fail_closed() {
    crate::initialize_tls_provider();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn serve(response: Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).await;
            let _ = stream.write_all(&response).await;
        });
        format!("http://{addr}")
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let bad = serve(
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_vec(),
    )
    .await;
    assert!(api_json(&client, &bad).await.is_err());
    let data = vec![b' '; (2 << 20) + 1];
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        data.len()
    )
    .into_bytes();
    response.extend(data);
    let large = serve(response).await;
    assert!(api_json(&client, &large)
        .await
        .unwrap_err()
        .to_string()
        .contains("2 MiB"));
}

/// Opt-in deployment check: fetches metadata only, never a shard or proof workload.
#[tokio::test]
#[ignore = "requires reachable public mainnet explorer and archive RPC"]
async fn live_mainnet_checkpoint_and_snapshot_record_are_authenticated() {
    use clap::Parser;
    crate::initialize_tls_provider();
    quil_crypto::init();
    crate::consensus_settings::initialize(0);
    let args = crate::Args::try_parse_from([
        "quil-node",
        "--benchmark-storage",
        "/unused",
        "--benchmark-storage-seats",
        "1",
        "--benchmark-storage-allow-debug",
    ])
    .unwrap()
    .storage_readiness;
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let base = &args.benchmark_storage_explorer;
    let stats = api_json(&http, &format!("{base}/stats")).await.unwrap();
    let grid = api_json(&http, &format!("{base}/provers/shards"))
        .await
        .unwrap();
    let filters = select(&grid, Some(1), &[]).unwrap();
    let signer = quil_crypto::FalconSigner::generate();
    let verify = verifier().unwrap();
    let mut failures = Vec::new();
    for (endpoint, peer) in endpoints(&args).unwrap() {
        // A conflicting entry keeps the first pin: its dial fails.
        let _ = quil_rpc::archive_client::pin_archive_peer(&endpoint, peer);
        let result = async {
            let mut client =
                quil_rpc::ArchiveClient::connect_mtls(&endpoint, signer.private_key()).await?;
            let header = client
                .get_global_head(u64::MAX)
                .await?
                .header
                .context("missing header")?;
            authenticate(
                &header,
                &verify,
                args.benchmark_storage_checkpoint_age_secs,
                stats["current_frame"]
                    .as_u64()
                    .context("missing explorer frame")?,
            )?;
            let root: [u8; 32] = header.prover_tree_commitment.as_slice().try_into()?;
            let epoch = quil_types::consensus::epoch_for_frame(header.frame_number) + 1;
            let address = snapshots::snapshot_address(epoch, &filters[0])?;
            let proof = client
                .get_global_vertex_proof(root, address, false)
                .await?
                .context("snapshot unavailable at this checkpoint")?;
            let snapshot = snapshot_record(&root, &filters[0], epoch, header.frame_number, &proof)?;
            eprintln!(
                "verified live GLOBAL frame {} and snapshot epoch {} filter {} via {}",
                header.frame_number,
                snapshot.epoch,
                hex::encode(&filters[0]),
                endpoint
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        match result {
            Ok(()) => return,
            Err(error) => failures.push(format!("{endpoint}: {error:#}")),
        }
    }
    panic!("live inputs unavailable: {}", failures.join("; "));
}

#[test]
fn suite_selection_uses_scheduled_mainnet_default_and_rejects_unsupported_parameters() {
    use clap::Parser;
    let defaults = crate::Args::try_parse_from(["quil-node"]).unwrap();
    assert_eq!(defaults.storage_readiness.benchmark_storage_layers, 3);
    let benchmark = crate::Args::try_parse_from([
        "quil-node",
        "--benchmark-storage",
        "/tmp/quil-default-profile",
        "--benchmark-storage-seats",
        "9",
        "--benchmark-storage-allow-debug",
    ])
    .unwrap();
    assert_eq!(benchmark.storage_readiness.benchmark_storage_layers, 3);
    validate(&benchmark.storage_readiness).unwrap();
    assert!(crate::Args::try_parse_from(["quil-node", "--benchmark-storage-layers", "3"]).is_err());
    for layers in ["2", "3", "11"] {
        let args = crate::Args::try_parse_from([
            "quil-node",
            "--benchmark-storage",
            "/tmp/quil-profiles",
            "--benchmark-storage-seats",
            "9",
            "--benchmark-storage-layers",
            layers,
            "--benchmark-storage-allow-debug",
        ])
        .unwrap();
        validate(&args.storage_readiness).unwrap();
        assert_eq!(
            args.storage_readiness.benchmark_storage_layers.to_string(),
            layers
        );
    }
    let args = crate::Args::try_parse_from([
        "quil-node",
        "--benchmark-storage",
        "/tmp/quil-profiles",
        "--benchmark-storage-seats",
        "9",
        "--benchmark-storage-layers",
        "1",
        "--benchmark-storage-allow-debug",
    ])
    .unwrap();
    assert!(validate(&args.storage_readiness).is_err());
}

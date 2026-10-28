//! Loopback transport test. Payloads are structurally valid fixtures, not
//! native proofs; this test establishes delivery/authentication, not admission.
use super::*;
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn wallet_scans_owned_unspent_coins_over_rpc() {
    use quil_lattice_ct::confidential::{coin_tree::CoinRecord, memo::create_output};
    use quil_types::store::*;
    struct Pages {
        network: [u8; 32],
        application: [u8; 32],
        root: Vec<u8>,
        coins: Vec<([u8; 32], Output, u64)>,
        fail_continuation: std::sync::atomic::AtomicBool,
    }
    impl CoinWitnessProvider for Pages {
        fn coin_page(
            &self,
            domain: &[u8; 32],
            snapshot: Option<&[u8; 32]>,
            after: Option<&[u8; 32]>,
        ) -> quil_types::error::Result<Option<CoinPageData>> {
            assert_eq!(domain, &self.application);
            assert!(snapshot.is_none() || snapshot == Some(&[33; 32]));
            if after.is_some()
                && self
                    .fail_continuation
                    .load(std::sync::atomic::Ordering::SeqCst)
            {
                return Err(quil_types::error::QuilError::ExecutionUnavailable(
                    "injected continuation failure".into(),
                ));
            }
            let index = self
                .coins
                .partition_point(|(address, _, _)| after.is_some_and(|old| address <= old));
            let next = self.coins.get(index);
            Ok(Some(CoinPageData {
                network: self.network,
                snapshot_id: [33; 32],
                root_record: self.root.clone(),
                coins: next
                    .into_iter()
                    .map(|(address, output, position)| CoinData {
                        address: *address,
                        frame_number: 1,
                        position: *position,
                        owner: output.owner.to_vec(),
                        commitment: output.commitment.to_bytes().to_vec(),
                        memo: output.memo.to_vec(),
                    })
                    .collect(),
                cursor: next.map(|(address, _, _)| *address).or(after.copied()),
                has_more: index + 1 < self.coins.len(),
            }))
        }
    }
    let network = [31; 32];
    let application = quil_execution::domains::QUIL_TOKEN;
    let make_wallet = || {
        let keys = sntrup761::Sntrup761KeyPair::generate();
        Arc::new(
            RecipientWallet::from_keys(
                &network,
                &application,
                &keys.public,
                Zeroizing::new(keys.secret),
            )
            .unwrap(),
        )
    };
    let wallet = make_wallet();
    let other = make_wallet();
    // Coins sit in the block their address selects, at that block's next free
    // index — the wallet refuses a scanned coin whose position says otherwise.
    use quil_execution::token_intrinsic::coin_blocks;
    let width = coin_blocks::INITIAL_BLOCK_BITS;
    let mut next_local: std::collections::BTreeMap<u64, u64> = Default::default();
    let mut coins = Vec::new();
    let mut spent_image = None;
    for (recipient, amount) in [(&wallet, 7), (&wallet, 11), (&other, 13), (&wallet, 17)] {
        let output = create_output(&wallet.context, recipient.address(), amount)
            .unwrap()
            .output;
        let identity =
            quil_execution::token_intrinsic::state::coin_identity(&wallet.context, 1, &output)
                .unwrap()
                .0;
        let block = coin_blocks::block_for_address(width, &identity).unwrap();
        let local = next_local.entry(block).or_default();
        let position = coin_blocks::position(width, block, *local).unwrap();
        *local += 1;
        let address = quil_execution::token_intrinsic::state::create_coin(
            &wallet.context,
            1,
            &output,
            position,
        )
        .unwrap()
        .0;
        if amount == 7 {
            spent_image = Some(
                wallet
                    .recover_page(vec![(address, output.clone())])
                    .unwrap()[0]
                    .image,
            );
        }
        coins.push((address, output, position));
    }
    coins.sort_by_key(|(address, _, _)| *address);
    let records: Vec<_> = coins
        .iter()
        .map(|(address, output, position)| CoinRecord {
            address: *address,
            owner: output.owner,
            commitment: output.commitment.clone(),
            position: *position,
        })
        .collect();
    let shape = quil_lattice_ct::confidential::sharded_tree::Shape {
        shard_bits: coin_blocks::BLOCK_INDEX_BITS,
        subtree_bits: coin_blocks::SUBTREE_BITS,
    };
    let tree = quil_lattice_ct::confidential::sharded_tree::ShardedCoinTree::build(
        &wallet.context,
        shape,
        &records,
    )
    .unwrap();
    let root = tree
        .root_at_depth(tree.current_depth())
        .unwrap()
        .encode()
        .unwrap()
        .to_vec();
    let provider = Arc::new(Pages {
        network,
        application,
        root,
        coins,
        fail_continuation: std::sync::atomic::AtomicBool::new(false),
    });
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    // A spend is spent once the global commit says so: its consumption record
    // lives in GLOBAL, which is where the wallet's hint looks.
    let marker = quil_execution::token_intrinsic::spent::marker_address(
        &network,
        &application,
        &spent_image.unwrap(),
    )
    .unwrap();
    let global = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS;
    let consumed =
        quil_execution::token_intrinsic::global_commit::consumed_address(&application, &marker)
            .unwrap();
    let mut marker_vertex = global.to_vec();
    marker_vertex.extend_from_slice(&consumed);
    let shard = quil_hypergraph::addressing::shard_key_for_location(
        &quil_hypergraph::addressing::Location {
            app_address: global,
            data_address: consumed,
        },
    );
    let txn = store.new_transaction(false).unwrap();
    store
        .save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &marker_vertex, &[])
        .unwrap();
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_hypergraph_store(store)
        .with_coin_witness_provider(provider.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let incoming = futures::stream::unfold(listener, |listener| async {
        let result = listener.accept().await.map(|(socket, _)| socket);
        Some((result, listener))
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async {
        tonic::transport::Server::builder()
            .add_service(
                quil_types::proto::node::node_service_server::NodeServiceServer::new(server),
            )
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let client = quil_types::proto::node::node_service_client::NodeServiceClient::new(channel);
    let unspent = wallet.clone().scan_unspent(&client, 4, 2).await.unwrap();
    let mut amounts: Vec<_> = unspent.iter().map(|coin| *coin.amount).collect();
    amounts.sort();
    assert_eq!(amounts, [11, 17]);
    // One page carries every coin: the node gathers the provider's pages of
    // one coin into the page of up to 64 the wallet asks for.
    let one_page = wallet.clone().scan_unspent(&client, 1, 2).await.unwrap();
    assert_eq!(one_page.len(), 2);
    assert!(wallet.clone().scan_unspent(&client, 4, 1).await.is_err());
    provider
        .fail_continuation
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(wallet.clone().scan_unspent(&client, 4, 2).await.is_err());
    provider
        .fail_continuation
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(wallet.scan_unspent(&client, 4, 2).await.unwrap().len(), 2);
    stop.send(()).unwrap();
    serving.await.unwrap();
}

#[tokio::test]
async fn wallet_fetches_content_bound_escrow_over_rpc() {
    use quil_execution::token_intrinsic::escrow::StoredEscrow;
    use quil_lattice_ct::confidential::{
        memo::create_escrow_recovery, pending_claim::EscrowPolicy,
    };
    use quil_types::store::*;
    struct EscrowPages {
        network: [u8; 32],
        address: [u8; 32],
        blob: Vec<u8>,
    }
    impl CoinWitnessProvider for EscrowPages {
        fn escrow_page(
            &self,
            _: &[u8; 32],
            id: Option<&[u8; 32]>,
            after: Option<&[u8; 32]>,
        ) -> quil_types::error::Result<Option<EscrowPageData>> {
            assert!(id.is_none() || id == Some(&[33; 32]));
            // Begin with an empty metadata page to exercise continuation.
            Ok(Some(EscrowPageData {
                network: self.network,
                snapshot_id: [33; 32],
                escrows: if after.is_some() {
                    vec![(self.address, self.blob.clone())]
                } else {
                    vec![]
                },
                cursor: Some(if after.is_some() {
                    self.address
                } else {
                    [0; 32]
                }),
                has_more: after.is_none(),
            }))
        }
    }
    let keys = sntrup761::Sntrup761KeyPair::generate();
    let wallet = RecipientWallet::from_keys(
        &[21; 32],
        &quil_execution::domains::QUIL_TOKEN,
        &keys.public,
        Zeroizing::new(keys.secret),
    )
    .unwrap();
    let recovery =
        create_escrow_recovery(&wallet.context, wallet.address(), wallet.address(), 7).unwrap();
    // Record lookup fixture; no claim signature or amount proof is admitted.
    let escrow = StoredEscrow {
        frame_number: 1,
        output: Output {
            commitment: recovery.commitment,
            owner: recovery.recipient.owner,
            memo: recovery.recipient.ciphertext,
        },
        policy: EscrowPolicy {
            recipient: [22; 897],
            refund: [23; 897],
            refund_after_global_frame: 100,
        },
        refund_recovery: recovery.refund,
    };
    let (address, blob) = escrow.encode(&wallet.context).unwrap();
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    let shard = quil_hypergraph::addressing::shard_key_for_location(
        &quil_hypergraph::addressing::Location {
            app_address: wallet.application,
            data_address: address,
        },
    );
    let mut vertex = wallet.application.to_vec();
    vertex.extend_from_slice(&address);
    let txn = store.new_transaction(false).unwrap();
    store
        .save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &vertex, &blob)
        .unwrap();
    use quil_execution::token_intrinsic::global_commit;
    let global = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS;
    let global_shard = quil_types::store::ShardKey {
        l1: quil_hypergraph::addressing::get_bloom_filter_indices(&global, 256, 3),
        l2: global,
    };
    // The escrow's creation committed, unconsumed.
    let mut open_vertex = global.to_vec();
    open_vertex
        .extend_from_slice(&global_commit::escrow_address(&wallet.application, &address).unwrap());
    store
        .save_vertex_underlying(
            txn.as_ref(),
            "vertex",
            "adds",
            &global_shard,
            &open_vertex,
            &global_commit::encode_escrow_record(&[5; 32], 100, false).unwrap(),
        )
        .unwrap();
    let wallet = Arc::new(wallet);
    let provider = Arc::new(EscrowPages {
        network: wallet.network,
        address,
        blob: blob.clone(),
    });
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_hypergraph_store(store.clone())
        .with_coin_witness_provider(provider);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let incoming = futures::stream::unfold(listener, |listener| async {
        let result = listener.accept().await.map(|(socket, _)| socket);
        Some((result, listener))
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async {
        tonic::transport::Server::builder()
            .add_service(
                quil_types::proto::node::node_service_server::NodeServiceServer::new(server),
            )
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let client = quil_types::proto::node::node_service_client::NodeServiceClient::new(channel);
    let recipient = wallet
        .clone()
        .scan_escrows(&client, vec![22; 897], 2, 1)
        .await
        .unwrap();
    assert_eq!(
        (
            recipient[0].0,
            *recipient[0].1,
            recipient[0].2,
            recipient[0].3
        ),
        (address, 7, false, 100)
    );
    let refund = wallet
        .clone()
        .scan_escrows(&client, vec![23; 897], 2, 1)
        .await
        .unwrap();
    assert_eq!((refund[0].0, *refund[0].1, refund[0].2), (address, 7, true));
    assert!(wallet
        .clone()
        .scan_escrows(&client, vec![24; 897], 2, 1)
        .await
        .unwrap()
        .is_empty());
    // One page carries the empty first page and the escrow behind it: the
    // node gathers both into the page of up to 64 the wallet asks for.
    let one_page = wallet
        .clone()
        .scan_escrows(&client, vec![22; 897], 1, 1)
        .await
        .unwrap();
    assert_eq!(one_page.len(), 1);
    // Consumption is the global commit's: the GLOBAL escrow record flips.
    let mut consumed_vertex = global.to_vec();
    consumed_vertex
        .extend_from_slice(&global_commit::escrow_address(&wallet.application, &address).unwrap());
    store
        .save_vertex_underlying(
            txn.as_ref(),
            "vertex",
            "adds",
            &global_shard,
            &consumed_vertex,
            &global_commit::encode_escrow_record(&[5; 32], 100, true).unwrap(),
        )
        .unwrap();
    assert!(wallet
        .clone()
        .scan_escrows(&client, vec![22; 897], 2, 1)
        .await
        .unwrap()
        .is_empty());
    assert!(wallet
        .clone()
        .scan_escrows(&client, vec![23; 897], 2, 1)
        .await
        .unwrap()
        .is_empty());
    // A malformed record fails the scan rather than reading as open.
    store
        .save_vertex_underlying(
            txn.as_ref(),
            "vertex",
            "adds",
            &global_shard,
            &consumed_vertex,
            &[1, 2, 3],
        )
        .unwrap();
    assert!(wallet
        .clone()
        .scan_escrows(&client, vec![22; 897], 2, 1)
        .await
        .is_err());
    let image = [24; IDENTITY_BYTES];
    assert!(wallet.is_unspent_hint(&client, &image).await.unwrap());
    let marker = quil_execution::token_intrinsic::spent::marker_address(
        &wallet.network,
        &wallet.application,
        &image,
    )
    .unwrap();
    // A local marker is not a commit.
    let mut local_marker = wallet.application.to_vec();
    local_marker.extend_from_slice(&marker);
    store
        .save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &local_marker, &[])
        .unwrap();
    assert!(wallet.is_unspent_hint(&client, &image).await.unwrap());
    let mut marker_vertex = global.to_vec();
    marker_vertex
        .extend_from_slice(&global_commit::consumed_address(&wallet.application, &marker).unwrap());
    store
        .save_vertex_underlying(
            txn.as_ref(),
            "vertex",
            "adds",
            &global_shard,
            &marker_vertex,
            &[],
        )
        .unwrap();
    assert!(!wallet.is_unspent_hint(&client, &image).await.unwrap());
    store
        .save_vertex_underlying(
            txn.as_ref(),
            "vertex",
            "adds",
            &global_shard,
            &marker_vertex,
            &[1, 2, 3],
        )
        .unwrap();
    assert!(!wallet.is_unspent_hint(&client, &image).await.unwrap());
    assert_eq!(wallet.fetch_escrow(&client, address).await.unwrap(), escrow);
    assert!(wallet.fetch_escrow(&client, [0; 32]).await.is_err());
    let mut altered = blob.clone();
    altered.push(0);
    store
        .save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &vertex, &altered)
        .unwrap();
    assert!(wallet.fetch_escrow(&client, address).await.is_err());
    let oversized = vec![0; quil_execution::token_intrinsic::escrow::MAX_ESCROW_BLOB_BYTES + 2048];
    store
        .save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &vertex, &oversized)
        .unwrap();
    assert!(wallet.fetch_escrow(&client, address).await.is_err());
    // A failed response cannot poison a later valid lookup.
    store
        .save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &vertex, &blob)
        .unwrap();
    assert_eq!(wallet.fetch_escrow(&client, address).await.unwrap(), escrow);
    stop.send(()).unwrap();
    serving.await.unwrap();
}

#[tokio::test]
async fn wallet_submits_over_authenticated_rpc() {
    use quil_lattice_ct::confidential::{
        memo::create_output,
        mint::{Mint, MintStatement, RewardClaim},
        mint_claim::MintClaim,
    };
    let keys = sntrup761::Sntrup761KeyPair::generate();
    let wallet = RecipientWallet::from_keys(
        &[1; 32],
        &quil_execution::domains::QUIL_TOKEN,
        &keys.public,
        Zeroizing::new(keys.secret),
    )
    .unwrap();
    let output = create_output(&wallet.context, wallet.address(), 7)
        .unwrap()
        .output;
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    let mint = Mint {
        statement: MintStatement {
            network: wallet.network,
            application: wallet.application,
            cited_frame: 1,
            reward_root: [3; 32],
            fee: 1,
            outputs: vec![output.clone()],
            claims: vec![RewardClaim {
                owner: [4; 32],
                value: 8,
                public_key: [0; 897],
                forest_proof: vec![1],
            }],
        },
        signatures: vec![[0; 666]],
        proof,
    }
    .encode()
    .unwrap();
    let claim = MintClaim {
        network: wallet.network,
        application: wallet.application,
        cited_global_frame: 3,
        global_root: [5; 32],
        receipt: [6; 32],
        fee: 1,
        outputs: vec![output],
        forest_proof: vec![1],
    }
    .encode()
    .unwrap();

    let directory = tempfile::tempdir().unwrap();
    let km = quil_keys::FileKeyManager::new(
        directory.path().join("keys.yml"),
        &hex::encode([7; 32]),
        "q-prover-key".into(),
        Box::new(quil_crypto::FalconKeyConstructor),
    )
    .unwrap();
    let seed = [8; 57];
    let public = quil_crypto::Ed448Signer::derive_public(&seed).unwrap();
    let mut peer = seed.to_vec();
    peer.extend_from_slice(&public);
    km.set_peer_priv_key_hex(&hex::encode(peer));

    let received = Arc::new(Mutex::new(Vec::new()));
    let captured = received.clone();
    let server = quil_rpc::node_service::NodeRpcServer::new().with_send_handler_fn(Arc::new(
        move |domain, payload, authentication| {
            let public = public.clone();
            let captured = captured.clone();
            Box::pin(async move {
                let mut signed = crate::send::node_auth_domain(&domain);
                signed.extend_from_slice(&payload);
                if !quil_crypto::ed448_verify(&public, &signed, &authentication) {
                    return Err("invalid test authentication".into());
                }
                let bundle =
                    quil_execution::message_envelope::CanonicalMessageBundle::from_canonical_bytes(
                        &payload,
                    )
                    .map_err(|e| e.to_string())?;
                if bundle.requests.len() != 1 {
                    return Err("expected one operation".into());
                }
                let request = bundle.requests[0].as_ref().ok_or("missing operation")?;
                let mut received = captured.lock().unwrap();
                if received.len() >= 2 {
                    return Err("test delivery rejected".into());
                }
                received.push((domain, request.inner_bytes.clone()));
                Ok(())
            })
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let incoming = futures::stream::unfold(listener, |listener| async {
        let result = listener.accept().await.map(|(socket, _)| socket);
        Some((result, listener))
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async {
        tonic::transport::Server::builder()
            .add_service(
                quil_types::proto::node::node_service_server::NodeServiceServer::new(server),
            )
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = quil_types::proto::node::node_service_client::NodeServiceClient::new(channel);
    wallet.submit(&mut client, &km, mint.clone()).await.unwrap();
    wallet
        .submit(&mut client, &km, claim.clone())
        .await
        .unwrap();
    assert!(wallet.submit(&mut client, &km, mint.clone()).await.is_err());
    assert_eq!(
        *received.lock().unwrap(),
        vec![
            (quil_execution::domains::GLOBAL.to_vec(), mint),
            (wallet.application.to_vec(), claim)
        ]
    );
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// A loopback node serving only fee quotes from `snapshot`; returns its gRPC
/// multiaddr, its quote count and its shutdown.
#[cfg(feature = "native-proof")]
async fn fee_quote_server(
    snapshot: quil_rpc::node_service::TokenFeeSnapshot,
) -> (
    String,
    Arc<std::sync::atomic::AtomicUsize>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = calls.clone();
    let server = quil_rpc::node_service::NodeRpcServer::new().with_token_fee_provider(Arc::new(
        move |application, _global_venue| {
            assert_eq!(application, quil_execution::domains::QUIL_TOKEN);
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(snapshot.clone())
        },
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let multiaddr = format!(
        "/ip4/127.0.0.1/tcp/{}",
        listener.local_addr().unwrap().port()
    );
    let incoming = futures::stream::unfold(listener, |listener| async {
        let result = listener.accept().await.map(|(socket, _)| socket);
        Some((result, listener))
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async {
        tonic::transport::Server::builder()
            .add_service(
                quil_types::proto::node::node_service_server::NodeServiceServer::new(server),
            )
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    (multiaddr, calls, stop, serving)
}

#[cfg(feature = "native-proof")]
#[tokio::test]
async fn automatic_quil_fee_is_quoted_by_the_configured_node_and_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let key_manager = Arc::new(
        quil_keys::FileKeyManager::new(
            directory.path().join("keys.yml"),
            &hex::encode([9; 32]),
            "q-prover-key".into(),
            Box::new(quil_crypto::FalconKeyConstructor),
        )
        .unwrap(),
    );
    let node_config = quil_config::Config::default();
    let network = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(
        node_config.p2p.network,
    )
    .network;
    // Both quotes are self-consistent global prices at vote one; only the
    // world size differs. The read node's would charge thousands of QUIL.
    let snapshot = |world_state_bytes| quil_rpc::node_service::TokenFeeSnapshot {
        network,
        observed_frame: 42,
        global_execution: true,
        difficulty: 50_000,
        world_state_bytes,
        fee_multiplier_vote: 1,
    };
    let (configured, configured_calls, stop_configured, configured_serving) =
        fee_quote_server(snapshot(1 << 40)).await;
    let (read, read_calls, stop_read, read_serving) = fee_quote_server(snapshot(1 << 24)).await;
    let mut tc = TokenCtx {
        node_config,
        config_dir: directory.path().to_path_buf(),
        key_manager,
        connect_opts: crate::rpc::ConnectOpts {
            listen_grpc_multiaddr: read.clone(),
            ..Default::default()
        },
        submit_opts: crate::rpc::ConnectOpts {
            listen_grpc_multiaddr: configured,
            ..Default::default()
        },
        peer_id_bytes: Vec::new(),
        max_fee: crate::commands::token::DEFAULT_MAX_AUTOMATIC_FEE,
    };
    // 4096 bytes in a 1 TiB world cost one unit per byte, plus the headroom.
    assert_eq!(
        quoted_quil_fee_for_cost(&tc, None, 4096, false)
            .await
            .unwrap(),
        with_fee_headroom(4096).unwrap()
    );
    assert_eq!(
        (
            configured_calls.load(std::sync::atomic::Ordering::SeqCst),
            read_calls.load(std::sync::atomic::Ordering::SeqCst)
        ),
        (1, 0)
    );
    // An inflated quote from the node that takes the submission is refused
    // under the default limit, and paid only once the operator raises it.
    tc.submit_opts.listen_grpc_multiaddr = read;
    let error = quoted_quil_fee_for_cost(&tc, None, 4096, false)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("automatic fee limit"), "{error}");
    tc.max_fee = u128::MAX;
    assert!(
        quoted_quil_fee_for_cost(&tc, None, 4096, false)
            .await
            .unwrap()
            > crate::commands::token::DEFAULT_MAX_AUTOMATIC_FEE
    );
    // An explicit fee is the operator's own choice and is never quoted.
    tc.max_fee = 0;
    assert_eq!(
        quoted_quil_fee_for_cost(&tc, Some(7), 4096, false)
            .await
            .unwrap(),
        7
    );
    assert_eq!(read_calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    stop_configured.send(()).unwrap();
    stop_read.send(()).unwrap();
    configured_serving.await.unwrap();
    read_serving.await.unwrap();
}

/// A/B reproducer: a wallet scan lists every confidential coin the application
/// ever placed, spent or not (a spend reveals a key image, never which coin
/// it spent), so a wallet must find its own coin behind all of them within
/// its page budget. At eight coins a page the default budget (2,048 pages)
/// reached 16,384 coins, and every default `token balance` and `token coins`
/// failed once the application held one more. A wallet checks and
/// trial-decrypts every coin it scans, about 0.1 s each in the test profile,
/// so the test keeps the wallet's own page size, which is what changed, and
/// scales the budget down to 16 pages, with one coin more behind them than
/// they reach at eight coins a page.
#[tokio::test]
async fn a_default_wallet_scan_finds_its_coin_behind_the_old_page_budget() {
    use clap::Parser;
    use quil_execution::token_intrinsic::{coin_blocks, state};
    use quil_lattice_ct::confidential::{coin_tree::CoinRecord, memo::create_output};
    use quil_types::store::*;

    /// The application's coins in address order, eight a page as a node's
    /// store answers them.
    struct Coins {
        network: [u8; 32],
        root: Vec<u8>,
        /// `(address, frame, position, the wallet's own)`.
        coins: Vec<([u8; 32], u64, u64, bool)>,
        /// `(owner, commitment, memo)` of the others' output, then the
        /// wallet's.
        outputs: [(Vec<u8>, Vec<u8>, Vec<u8>); 2],
    }
    impl CoinWitnessProvider for Coins {
        fn coin_page(
            &self,
            _: &[u8; 32],
            _: Option<&[u8; 32]>,
            after: Option<&[u8; 32]>,
        ) -> quil_types::error::Result<Option<CoinPageData>> {
            let start = self
                .coins
                .partition_point(|(address, ..)| after.is_some_and(|after| address <= after));
            let page = &self.coins[start..self.coins.len().min(start + 8)];
            Ok(Some(CoinPageData {
                network: self.network,
                snapshot_id: [33; 32],
                root_record: self.root.clone(),
                coins: page
                    .iter()
                    .map(|&(address, frame_number, position, mine)| {
                        let (owner, commitment, memo) = &self.outputs[usize::from(mine)];
                        CoinData {
                            address,
                            frame_number,
                            position,
                            owner: owner.clone(),
                            commitment: commitment.clone(),
                            memo: memo.clone(),
                        }
                    })
                    .collect(),
                cursor: page.last().map(|coin| coin.0).or(after.copied()),
                has_more: start + page.len() < self.coins.len(),
            }))
        }
    }

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        token: super::super::TokenArgs,
    }
    let defaults = Cli::try_parse_from(["qclient", "balance"]).unwrap().token;
    // One coin more than pages of eight reach within the budget.
    let pages = 16;
    let others = pages * 8;

    let network = [31; 32];
    let application = quil_execution::domains::QUIL_TOKEN;
    let make_wallet = || {
        let keys = sntrup761::Sntrup761KeyPair::generate();
        Arc::new(
            RecipientWallet::from_keys(
                &network,
                &application,
                &keys.public,
                Zeroizing::new(keys.secret),
            )
            .unwrap(),
        )
    };
    let wallet = make_wallet();
    let other = make_wallet();
    let mine = create_output(&wallet.context, wallet.address(), 5)
        .unwrap()
        .output;
    let theirs = create_output(&wallet.context, other.address(), 7)
        .unwrap()
        .output;
    let identity = |output: &Output, frame: u64| {
        state::coin_identity(&wallet.context, frame, output)
            .unwrap()
            .0
    };
    // The wallet's coin sorts after every other coin, so the scan reaches it
    // last: it takes the highest address of a few frames, and the others are
    // drawn below it. (An address encodes a field element, so its top byte
    // never reaches 0xff.)
    let (my_address, my_frame) = (1..=16)
        .map(|frame| (identity(&mine, frame), frame))
        .max()
        .unwrap();
    let mut placed = vec![(my_address, my_frame, true)];
    let mut frame = 0;
    while placed.len() <= others {
        frame += 1;
        let address = identity(&theirs, frame);
        if address < my_address {
            placed.push((address, frame, false));
        }
    }
    placed.sort();
    // Each coin sits in the block its address selects, at that block's next
    // free index, as the wallet checks.
    let width = coin_blocks::INITIAL_BLOCK_BITS;
    let mut next_local = std::collections::BTreeMap::<u64, u64>::new();
    let coins: Vec<_> = placed
        .into_iter()
        .map(|(address, frame, mine)| {
            let block = coin_blocks::block_for_address(width, &address).unwrap();
            let local = next_local.entry(block).or_default();
            let position = coin_blocks::position(width, block, *local).unwrap();
            *local += 1;
            (address, frame, position, mine)
        })
        .collect();
    let my_position = coins.last().unwrap().2;
    let tree = quil_lattice_ct::confidential::sharded_tree::ShardedCoinTree::build(
        &wallet.context,
        quil_lattice_ct::confidential::sharded_tree::Shape {
            shard_bits: coin_blocks::BLOCK_INDEX_BITS,
            subtree_bits: coin_blocks::SUBTREE_BITS,
        },
        &[CoinRecord {
            address: my_address,
            owner: mine.owner,
            commitment: mine.commitment.clone(),
            position: my_position,
        }],
    )
    .unwrap();
    let root = tree
        .root_at_depth(tree.current_depth())
        .unwrap()
        .encode()
        .unwrap()
        .to_vec();
    let bytes = |output: &Output| {
        (
            output.owner.to_vec(),
            output.commitment.to_bytes().to_vec(),
            output.memo.to_vec(),
        )
    };
    let provider = Arc::new(Coins {
        network,
        root,
        coins,
        outputs: [bytes(&theirs), bytes(&mine)],
    });
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_hypergraph_store(Arc::new(quil_hypergraph::testing::MemStore::new()))
        .with_coin_witness_provider(provider);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let incoming = futures::stream::unfold(listener, |listener| async {
        let result = listener.accept().await.map(|(socket, _)| socket);
        Some((result, listener))
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async {
        tonic::transport::Server::builder()
            .add_service(
                quil_types::proto::node::node_service_server::NodeServiceServer::new(server),
            )
            .serve_with_incoming_shutdown(incoming, async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let client = quil_types::proto::node::node_service_client::NodeServiceClient::new(channel);
    let unspent = wallet
        .clone()
        .scan_unspent(&client, pages, defaults.max_coins)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "a scan of {pages} pages must reach the wallet's coin behind {others} \
                 others, as a default scan ({} pages) must behind {}: {error}",
                defaults.max_pages,
                defaults.max_pages * 8
            )
        });
    assert_eq!(unspent.len(), 1);
    assert_eq!(unspent[0].address, my_address);
    assert_eq!(*unspent[0].amount, 5);
    stop.send(()).unwrap();
    serving.await.unwrap();
}

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
        /// Continuation reads that fail as a cut transfer does on a node.
        cut_reads: std::sync::atomic::AtomicUsize,
        /// A continuation read reports its snapshot expired.
        expired: std::sync::atomic::AtomicBool,
        continuations: std::sync::atomic::AtomicUsize,
    }
    impl CoinWitnessProvider for Pages {
        fn coin_page(
            &self,
            domain: &[u8; 32],
            snapshot: Option<&[u8; 32]>,
            after: Option<&[u8; 32]>,
        ) -> quil_types::error::Result<Option<CoinPageData>> {
            use std::sync::atomic::Ordering::SeqCst;
            assert_eq!(domain, &self.application);
            assert!(snapshot.is_none() || snapshot == Some(&[33; 32]));
            if after.is_some() {
                self.continuations.fetch_add(1, SeqCst);
                if self.expired.load(SeqCst) {
                    return Err(quil_types::error::QuilError::NotFound(
                        "coin scan snapshot unavailable or expired; restart scan".into(),
                    ));
                }
                if self
                    .cut_reads
                    .fetch_update(SeqCst, SeqCst, |left| left.checked_sub(1))
                    .is_ok()
                {
                    return Err(quil_types::error::QuilError::ExecutionUnavailable(
                        "1 peer declined: 1x Unknown: h2 protocol error: error reading a body \
                         from connection"
                            .into(),
                    ));
                }
            }
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
        cut_reads: Default::default(),
        expired: Default::default(),
        continuations: Default::default(),
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
    assert_eq!(
        wallet
            .clone()
            .scan_unspent(&client, 4, 2)
            .await
            .unwrap()
            .len(),
        2
    );
    // neon, Nov 2: one cut page ended a scan minutes in and threw its pages
    // away. The first cut read only ends the node's gathering of the first
    // page; each one after fails an asking of page 2. Three askings again are
    // allowed: the last recovers, with the scan where it was.
    use std::sync::atomic::Ordering::SeqCst;
    let allowed = 1 + SCAN_READ_RETRIES;
    provider.cut_reads.store(allowed, SeqCst);
    assert_eq!(
        wallet
            .clone()
            .scan_unspent(&client, 4, 2)
            .await
            .unwrap()
            .len(),
        2,
        "the scan went on from its cursor"
    );
    assert_eq!(provider.cut_reads.load(SeqCst), 0);
    // One more cut and the scan ends, naming the page and how far it got.
    provider.cut_reads.store(allowed + 1, SeqCst);
    let stopped = wallet
        .clone()
        .scan_unspent(&client, 4, 2)
        .await
        .err()
        .expect("past the bound the scan stops")
        .to_string();
    assert!(
        stopped.starts_with("scan stopped at page 2 after 1 coins in 1 pages: "),
        "{stopped}"
    );
    assert!(
        stopped.contains("error reading a body from connection"),
        "{stopped}"
    );
    assert_eq!(provider.cut_reads.load(SeqCst), 0);
    // An expired snapshot takes a new scan: no asking again.
    provider.expired.store(true, SeqCst);
    provider.continuations.store(0, SeqCst);
    let expired = wallet
        .clone()
        .scan_unspent(&client, 4, 2)
        .await
        .err()
        .expect("the snapshot is gone")
        .to_string();
    assert!(expired.contains("restart scan"), "{expired}");
    assert_eq!(
        provider.continuations.load(SeqCst),
        2,
        "the node's gathering and one asking, not four"
    );
    provider.expired.store(false, SeqCst);
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
        key_manager: key_manager.clone(),
        connect_opts: crate::rpc::ConnectOpts {
            listen_grpc_multiaddr: read.clone(),
            ..Default::default()
        },
        submit_opts: crate::rpc::ConnectOpts {
            listen_grpc_multiaddr: configured,
            ..Default::default()
        },
        submit_key_manager: key_manager,
        submit_config_dir: directory.path().to_path_buf(),
        submit_identity: Default::default(),
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

/// Serve `server` on `listener` until the returned sender fires.
#[cfg(feature = "native-proof")]
fn serve_node(
    listener: tokio::net::TcpListener,
    server: quil_rpc::node_service::NodeRpcServer,
) -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
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
    (stop, serving)
}

#[cfg(feature = "native-proof")]
async fn bind_loopback() -> (tokio::net::TcpListener, String) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let multiaddr = format!(
        "/ip4/127.0.0.1/tcp/{}",
        listener.local_addr().unwrap().port()
    );
    (listener, multiaddr)
}

/// Parse and dispatch a token command against a loaded context.
#[cfg(feature = "native-proof")]
async fn run_token_command(tc: &TokenCtx, arguments: &[&str]) -> anyhow::Result<()> {
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        token: super::super::TokenArgs,
    }
    // Boxed: the command's future outgrows a test thread's stack.
    Box::pin(super::super::run_with_context(
        tc,
        &Cli::try_parse_from(arguments)?.token,
    ))
    .await
}

/// A reward mint from a config other than the running node's is refused
/// before its fee quote and proof, naming both peers and the fix; nothing is
/// saved or sent. Through the node's own config the check passes and the
/// mint goes on to its fee quote.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn a_mint_from_another_config_fails_before_proving() {
    use super::super::{short_peer, test_nodes};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let directory = tempfile::tempdir().unwrap();
    let (listener, listen) = bind_loopback().await;
    let node = test_nodes::write(&directory.path().join("node"), 41, &listen);
    // A dormant prover's config naming the same listener, as a copy does.
    let dormant = test_nodes::write(&directory.path().join("dormant"), 42, &listen);
    let calls = Arc::new(AtomicUsize::new(0));
    let (quoted, sent) = (calls.clone(), calls.clone());
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_peer_id(node.peer_id.clone())
        .with_token_fee_provider(Arc::new(move |_, _| {
            quoted.fetch_add(1, Ordering::SeqCst);
            Err(quil_types::error::QuilError::ExecutionUnavailable(
                "test node has no fee snapshot".into(),
            ))
        }))
        .with_send_handler_fn(Arc::new(move |_, _, _| {
            sent.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err("test node takes no submissions".into()) })
        }));
    let (stop, serving) = serve_node(listener, server);

    let tc = TokenCtx::from_context(
        &test_nodes::context(false),
        &test_nodes::common(&dormant.dir, None, false),
    )
    .unwrap();
    let error = run_token_command(&tc, &["token", "mint"])
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.starts_with(&format!(
            "the node at {listen} is peer {}, but submissions would be signed by {} (peer {})",
            short_peer(&node.peer_id),
            dormant.dir.display(),
            short_peer(&dormant.peer_id)
        )),
        "{error}"
    );
    assert!(error.ends_with("pass --submit-config <DIR> with the running node's config directory"));
    assert_eq!(calls.load(Ordering::SeqCst), 0, "a quote or send was made");
    let saved: Vec<_> = std::fs::read_dir(&dormant.dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("mint-"))
        .collect();
    assert!(saved.is_empty(), "a mint was saved: {saved:?}");

    // Through the running node's config, the mint passes the check and asks
    // that node for its fee quote.
    let tc = TokenCtx::from_context(
        &test_nodes::context(false),
        &test_nodes::common(&dormant.dir, Some(&node.dir), false),
    )
    .unwrap();
    tc.check_submit_identity().await.unwrap();
    let error = run_token_command(&tc, &["token", "mint"])
        .await
        .unwrap_err()
        .to_string();
    assert!(error.starts_with("fee estimate unavailable"), "{error}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    stop.send(()).unwrap();
    serving.await.unwrap();

    // A node that reports no peer ID is not second-guessed.
    let (listener, _) = bind_loopback().await;
    let mut tc = TokenCtx::from_context(
        &test_nodes::context(false),
        &test_nodes::common(&dormant.dir, None, false),
    )
    .unwrap();
    tc.submit_opts.listen_grpc_multiaddr = format!(
        "/ip4/127.0.0.1/tcp/{}",
        listener.local_addr().unwrap().port()
    );
    let (stop, serving) = serve_node(listener, quil_rpc::node_service::NodeRpcServer::new());
    tc.check_submit_identity().await.unwrap();
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// With `--submit-config`, the Send authentication is signed with the running
/// node's peer key, which that node's check (Ed448 over `NODE_AUTHENTICATION
/// ‖ domain ‖ payload`) accepts, while the reward mint inside is signed with
/// the `--config` prover key. Signed with the `--config` peer key, the same
/// submission is refused.
#[cfg(feature = "native-proof")]
#[tokio::test]
async fn submit_config_signs_the_send_and_the_wallet_signs_the_mint() {
    use super::super::test_nodes;
    use quil_lattice_ct::confidential::mint::{Mint, RewardClaim};
    use quil_types::crypto::Signer;
    let directory = tempfile::tempdir().unwrap();
    let (listener, listen) = bind_loopback().await;
    let node = test_nodes::write(&directory.path().join("node"), 51, &listen);
    let dormant = test_nodes::write(
        &directory.path().join("dormant"),
        52,
        "/ip4/127.0.0.1/tcp/9",
    );
    let received = Arc::new(Mutex::new(Vec::new()));
    let captured = received.clone();
    let node_public = node.ed448_public.clone();
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_peer_id(node.peer_id.clone())
        .with_send_handler_fn(Arc::new(move |domain, payload, authentication| {
            let public = node_public.clone();
            let captured = captured.clone();
            Box::pin(async move {
                // The node's Send check, against its own peer key.
                let mut digest = b"NODE_AUTHENTICATION".to_vec();
                digest.extend_from_slice(&domain);
                digest.extend_from_slice(&payload);
                if !quil_crypto::ed448_verify(&public, &digest, &authentication) {
                    return Err("authentication failed: InvalidSignature".into());
                }
                let bundle =
                    quil_execution::message_envelope::CanonicalMessageBundle::from_canonical_bytes(
                        &payload,
                    )
                    .map_err(|e| e.to_string())?;
                let request = bundle
                    .requests
                    .into_iter()
                    .flatten()
                    .next()
                    .ok_or("missing operation")?;
                captured.lock().unwrap().push((domain, request.inner_bytes));
                Ok(())
            })
        }));
    let (stop, serving) = serve_node(listener, server);

    let tc = TokenCtx::from_context(
        &test_nodes::context(false),
        &test_nodes::common(&dormant.dir, Some(&node.dir), false),
    )
    .unwrap();
    let network =
        quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let wallet =
        RecipientWallet::load(&tc, &network, &quil_execution::domains::QUIL_TOKEN).unwrap();
    // The reward claimant is the --config prover key, as `token mint` signs it.
    let signer = falcon_signer(&tc).unwrap();
    assert_eq!(signer.public_key(), dormant.falcon_public.as_slice());
    let claim = RewardClaim {
        owner: quil_crypto::poseidon::hash_bytes_to_32(&dormant.falcon_public).unwrap(),
        value: 8,
        public_key: dormant.falcon_public.as_slice().try_into().unwrap(),
        forest_proof: vec![1],
    };
    let signer: std::sync::Arc<dyn Signer> = signer;
    let signers = vec![signer];
    let (statement, signatures, _) = wallet
        .prepare_mint(
            1,
            [3; 32],
            &[claim],
            &signers,
            &[(wallet.address().clone(), 7)],
            1,
            1,
            1,
        )
        .unwrap();
    let mut proof = vec![0; 40];
    proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
    let mint = Mint {
        statement,
        signatures,
        proof,
    }
    .encode()
    .unwrap();

    // Signed with the dormant config's own peer key, the node refuses it.
    let refused = wallet
        .submit(
            &mut tc.connect_submit().await.unwrap(),
            &tc.key_manager,
            mint.clone(),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(refused.contains("authentication failed"), "{refused}");
    submit_refreshed_operation(&tc, &wallet, mint.clone())
        .await
        .unwrap();
    let received = received.lock().unwrap().clone();
    assert_eq!(
        received,
        vec![(quil_execution::domains::GLOBAL.to_vec(), mint)]
    );
    let delivered = Mint::decode(
        &received[0].1,
        &network,
        &quil_execution::domains::QUIL_TOKEN,
    )
    .unwrap();
    assert!(quil_crypto::falcon_verify(
        &dormant.falcon_public,
        &delivered.signatures[0],
        &delivered.statement.context_bytes().unwrap(),
        &wallet.context
    ));
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// Coins in their blocks and GLOBAL's accumulator over them, as a node holds
/// both: `early` coins staged at frame 1 in at least two blocks and, when
/// `report`, reported by the shard of each block (six bits deep, one block
/// each); then one coin at frame 2 in the block of each early coin `late`
/// names, which no report covers yet. `coins` is what a scan of that store
/// lists.
struct ReportedCoins {
    _directory: tempfile::TempDir,
    store: Arc<quil_store::RocksHypergraphStore>,
    /// `(address, output, position, frame)` in address order.
    coins: Vec<([u8; 32], Output, u64, u64)>,
    /// The root a scan of the store carries: canonical once reported.
    root: quil_lattice_ct::confidential::coin_tree::RootRecord,
}

impl ReportedCoins {
    /// Returns the fixture, the early coins' addresses in staging order and
    /// the late coins' addresses in `late`'s order.
    fn new(
        wallet: &RecipientWallet,
        early: usize,
        late: &[usize],
        report: bool,
    ) -> (Self, Vec<[u8; 32]>, Vec<[u8; 32]>) {
        Self::with_other(wallet, None, early, late, report)
    }

    /// [`Self::new`], plus four early coins of `other` after the wallet's
    /// in staging order: one in the first early coin's block, two in a block
    /// no coin of the wallet is in and one alone in a third block.
    fn with_other(
        wallet: &RecipientWallet,
        other: Option<&RecipientWallet>,
        early: usize,
        late: &[usize],
        report: bool,
    ) -> (Self, Vec<[u8; 32]>, Vec<[u8; 32]>) {
        use quil_execution::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
        use quil_execution::token_intrinsic::{
            coin_blocks, global_accumulator, roots, scan, shard_accumulator, state,
        };
        let directory = tempfile::tempdir().unwrap();
        let db = quil_store::RocksDb::open(directory.path()).unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        let hypergraph = HypergraphState::new(crdt.clone());
        let (network, application) = (wallet.network, wallet.application);
        let limits = state::SnapshotLimits {
            max_coins: 64,
            max_depth: 32,
            max_nodes: 1 << 14,
        };
        let disc = vertex_adds_discriminator().unwrap();
        let block_of = |address: &[u8; 32]| {
            coin_blocks::block_for_address(coin_blocks::INITIAL_BLOCK_BITS, address).unwrap()
        };
        // An output of `owner` whose coin lands in `block` (any block when
        // `None`).
        let draw = |owner: &RecipientWallet, frame: u64, block: Option<u64>| {
            for _ in 0..4096 {
                let output = quil_lattice_ct::confidential::memo::create_output(
                    &wallet.context,
                    owner.address(),
                    5,
                )
                .unwrap()
                .output;
                let (address, _) = state::coin_identity(&wallet.context, frame, &output).unwrap();
                if block.is_none_or(|block| block_of(&address) == block) {
                    return output;
                }
            }
            panic!("no output landed in the wanted block");
        };
        let stage = |frame: u64, outputs: Vec<Output>| -> Vec<[u8; 32]> {
            let mut staged = std::collections::BTreeMap::new();
            let mut addresses = Vec::new();
            for output in outputs {
                let (address, tree) = roots::stage_coin(
                    &hypergraph,
                    &network,
                    &application,
                    &wallet.context,
                    frame,
                    &output,
                    &mut staged,
                    limits,
                )
                .unwrap();
                hypergraph
                    .set(
                        &application,
                        &address,
                        &disc,
                        frame,
                        quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
                    )
                    .unwrap();
                addresses.push(address);
            }
            roots::refresh_root(&hypergraph, &network, &application, limits).unwrap();
            addresses
        };
        // Early coins in at least two blocks, so inputs come from different
        // subtrees.
        let mut outputs: Vec<Output> = (0..early).map(|_| draw(wallet, 1, None)).collect();
        let first = state::coin_identity(&wallet.context, 1, &outputs[0])
            .unwrap()
            .0;
        if outputs[1..].iter().all(|output| {
            block_of(&state::coin_identity(&wallet.context, 1, output).unwrap().0)
                == block_of(&first)
        }) {
            let elsewhere = (0..4096)
                .map(|_| draw(wallet, 1, None))
                .find(|output| {
                    block_of(&state::coin_identity(&wallet.context, 1, output).unwrap().0)
                        != block_of(&first)
                })
                .expect("an output in another block");
            *outputs.last_mut().unwrap() = elsewhere;
        }
        if let Some(other) = other {
            let identity =
                |output: &Output| state::coin_identity(&wallet.context, 1, output).unwrap().0;
            let mut taken: std::collections::BTreeSet<u64> = outputs
                .iter()
                .map(|output| block_of(&identity(output)))
                .collect();
            outputs.push(draw(other, 1, Some(block_of(&first))));
            for count in [2, 1] {
                let block = (0..4096)
                    .map(|_| block_of(&identity(&draw(other, 1, None))))
                    .find(|block| !taken.contains(block))
                    .expect("a block no coin is in yet");
                taken.insert(block);
                for _ in 0..count {
                    outputs.push(draw(other, 1, Some(block)));
                }
            }
        }
        let staged = outputs.len();
        let early_addresses = stage(1, outputs);
        if report {
            let blocks: std::collections::BTreeSet<u64> = early_addresses
                .iter()
                .map(|address| block_of(address))
                .collect();
            for block in blocks {
                let shard = coin_blocks::block_path(block);
                let report = shard_accumulator::shard_report(
                    &hypergraph,
                    &network,
                    &application,
                    &shard,
                    false,
                )
                .unwrap()
                .expect("the shard holds a coin");
                let filter = quil_forest::encode_shard_bit_path(&application, &shard);
                global_accumulator::materialize_report(
                    &hypergraph,
                    10,
                    &filter,
                    &report.encode().unwrap(),
                )
                .unwrap();
            }
        }
        hypergraph.commit().unwrap();
        hypergraph.abort();
        crdt.commit(1).unwrap();
        let mut late_addresses = Vec::new();
        if !late.is_empty() {
            let outputs = late
                .iter()
                .map(|&i| draw(wallet, 2, Some(block_of(&early_addresses[i]))))
                .collect();
            late_addresses = stage(2, outputs);
            hypergraph.commit().unwrap();
            hypergraph.abort();
            crdt.commit(2).unwrap();
        }
        let snapshot = quil_types::store::HypergraphStore::capture_tree_snapshot(store.as_ref())
            .unwrap()
            .expect("tree snapshot");
        let page = scan::scan_page(
            snapshot.as_ref(),
            &network,
            &application,
            None,
            quil_types::store::VertexPageLimits {
                max_entries: 1024,
                max_bytes: 64 << 20,
            },
        )
        .unwrap();
        assert!(!page.has_more);
        assert_eq!(page.coins.len(), staged + late.len());
        let coins = page
            .coins
            .into_iter()
            .map(|(address, coin)| (address, coin.output, coin.position, coin.frame_number))
            .collect();
        (
            Self {
                _directory: directory,
                store,
                coins,
                root: page.root,
            },
            early_addresses,
            late_addresses,
        )
    }

    fn block(address: &[u8; 32]) -> u64 {
        use quil_execution::token_intrinsic::coin_blocks;
        coin_blocks::block_for_address(coin_blocks::INITIAL_BLOCK_BITS, address).unwrap()
    }
    fn output(&self, address: &[u8; 32]) -> Output {
        self.coins
            .iter()
            .find(|(at, ..)| at == address)
            .map(|(_, output, ..)| output.clone())
            .unwrap()
    }

    /// Every listed coin's path in the whole tree, as a node holding them all
    /// would build it.
    fn whole_tree(&self) -> quil_lattice_ct::confidential::sharded_tree::ShardedCoinTree {
        use quil_execution::token_intrinsic::coin_blocks;
        let records: Vec<_> = self
            .coins
            .iter()
            .map(|(address, output, position, _)| {
                quil_lattice_ct::confidential::coin_tree::CoinRecord {
                    address: *address,
                    owner: output.owner,
                    commitment: output.commitment.clone(),
                    position: *position,
                }
            })
            .collect();
        quil_lattice_ct::confidential::sharded_tree::ShardedCoinTree::build(
            &self.root.context,
            quil_lattice_ct::confidential::sharded_tree::Shape {
                shard_bits: coin_blocks::BLOCK_INDEX_BITS,
                subtree_bits: coin_blocks::SUBTREE_BITS,
            },
            &records,
        )
        .unwrap()
    }
}

/// Serves a store's coin scan in pages of two, and records every coin a
/// `GetCoinWitnesses` request names, answering it from the whole tree.
struct RecordingCoins {
    network: [u8; 32],
    application: [u8; 32],
    root: Vec<u8>,
    coins: Vec<([u8; 32], Output, u64, u64)>,
    tree: quil_lattice_ct::confidential::sharded_tree::ShardedCoinTree,
    named: Mutex<Vec<[u8; 32]>>,
    /// Scan pages served.
    pages: std::sync::atomic::AtomicUsize,
}

impl RecordingCoins {
    fn new(wallet: &RecipientWallet, fixture: &ReportedCoins) -> Self {
        Self {
            network: wallet.network,
            application: wallet.application,
            root: fixture.root.encode().unwrap().to_vec(),
            coins: fixture.coins.clone(),
            tree: fixture.whole_tree(),
            named: Mutex::new(Vec::new()),
            pages: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl quil_types::store::CoinWitnessProvider for RecordingCoins {
    fn coin_page(
        &self,
        domain: &[u8; 32],
        _snapshot: Option<&[u8; 32]>,
        after: Option<&[u8; 32]>,
    ) -> quil_types::error::Result<Option<quil_types::store::CoinPageData>> {
        assert_eq!(domain, &self.application);
        self.pages.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let start = self
            .coins
            .partition_point(|(address, ..)| after.is_some_and(|old| address <= old));
        let page = &self.coins[start..(start + 2).min(self.coins.len())];
        Ok(Some(quil_types::store::CoinPageData {
            network: self.network,
            snapshot_id: [44; 32],
            root_record: self.root.clone(),
            coins: page
                .iter()
                .map(
                    |(address, output, position, frame)| quil_types::store::CoinData {
                        address: *address,
                        frame_number: *frame,
                        position: *position,
                        owner: output.owner.to_vec(),
                        commitment: output.commitment.to_bytes().to_vec(),
                        memo: output.memo.to_vec(),
                    },
                )
                .collect(),
            cursor: page.last().map(|(address, ..)| *address).or(after.copied()),
            has_more: start + page.len() < self.coins.len(),
        }))
    }

    fn coin_witnesses(
        &self,
        domain: &[u8; 32],
        addresses: &[[u8; 32]],
    ) -> quil_types::error::Result<Option<quil_types::store::CoinWitnessBundle>> {
        assert_eq!(domain, &self.application);
        self.named.lock().unwrap().extend_from_slice(addresses);
        let depth = self.tree.current_depth();
        Ok(Some(quil_types::store::CoinWitnessBundle {
            network: self.network,
            depth: depth as u8,
            root_record: self
                .tree
                .root_at_depth(depth)
                .unwrap()
                .encode()
                .unwrap()
                .to_vec(),
            witnesses: addresses
                .iter()
                .map(|address| {
                    let path = self.tree.auth_path(address).unwrap();
                    quil_types::store::CoinWitnessData {
                        address: *address,
                        found: true,
                        siblings: path
                            .siblings
                            .iter()
                            .map(|n| n.to_bytes().to_vec())
                            .collect(),
                        right: path.right,
                    }
                })
                .collect(),
        }))
    }
}

fn witness_wallet() -> Arc<RecipientWallet> {
    let keys = sntrup761::Sntrup761KeyPair::generate();
    Arc::new(
        RecipientWallet::from_keys(
            &[31; 32],
            &quil_execution::domains::QUIL_TOKEN,
            &keys.public,
            Zeroizing::new(keys.secret),
        )
        .unwrap(),
    )
}

async fn witness_client(
    fixture: &ReportedCoins,
    provider: Arc<RecordingCoins>,
) -> (
    quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_hypergraph_store(fixture.store.clone())
        .with_coin_witness_provider(provider);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let (stop, serving) = serve_node(listener, server);
    let channel = tonic::transport::Endpoint::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .unwrap();
    (
        quil_types::proto::node::node_service_client::NodeServiceClient::new(channel),
        stop,
        serving,
    )
}

/// A/B reproducer (wallet privacy): a spend's membership paths must not name
/// its input coins to the node. On the base the wallet asked
/// `GetCoinWitnesses` for the exact input addresses, which a regular node
/// (it never covers QUIL) forwards to a remote node over a connection
/// authenticated with its prover key, so the serving peer learns each spend's
/// real inputs tied to the spender. The paths must still prove both inputs,
/// from different shards, against the canonical root.
#[tokio::test]
async fn spend_witnesses_name_no_input_coin_to_the_node() {
    let wallet = witness_wallet();
    let (fixture, early, _) = ReportedCoins::new(&wallet, 4, &[], true);
    let provider = Arc::new(RecordingCoins::new(&wallet, &fixture));
    let (client, stop, serving) = witness_client(&fixture, provider.clone()).await;
    // Two inputs in different blocks, so in different reported subtrees.
    let other = *early
        .iter()
        .find(|address| ReportedCoins::block(address) != ReportedCoins::block(&early[0]))
        .unwrap();
    let (first, second) = (fixture.output(&early[0]), fixture.output(&other));
    let selected = [(early[0], &first), (other, &second)];
    let result = wallet.witnesses(&client, &selected).await;
    let named = provider.named.lock().unwrap().clone();
    assert!(
        named.is_empty(),
        "the node was told the spend's input coins: {}",
        named.iter().map(hex::encode).collect::<Vec<_>>().join(", ")
    );
    let (root, paths) = result.unwrap();
    assert!(
        root == fixture.root && root.root == provider.tree.root(),
        "the rebuilt root is not the canonical root"
    );
    for ((address, _), path) in selected.iter().zip(&paths) {
        let expected = provider.tree.auth_path(address).unwrap();
        assert!(
            path.siblings == expected.siblings && path.right == expected.right,
            "the rebuilt path of {} is not the whole tree's",
            hex::encode(address)
        );
    }
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// A report lags the coins it covers. The rebuild must prove a reported coin
/// against the canonical root, leaving out its shard's newer coin, and must
/// refuse a coin no report covers yet rather than guess a root for it.
#[tokio::test]
async fn spend_witnesses_follow_lagging_reports_and_refuse_unreported_coins() {
    let wallet = witness_wallet();
    let (fixture, early, late) = ReportedCoins::new(&wallet, 3, &[0], true);
    let provider = Arc::new(RecordingCoins::new(&wallet, &fixture));
    let (client, stop, serving) = witness_client(&fixture, provider.clone()).await;
    assert!(
        fixture.root.root != provider.tree.root(),
        "the late coin must be outside the canonical root"
    );
    let reported = fixture.output(&early[0]);
    let (root, paths) = wallet
        .witnesses(&client, &[(early[0], &reported)])
        .await
        .unwrap();
    assert!(root == fixture.root, "not the canonical root");
    assert_eq!(paths[0].siblings.len(), usize::from(root.depth));
    let newer = fixture.output(&late[0]);
    let Err(error) = wallet.witnesses(&client, &[(late[0], &newer)]).await else {
        panic!("a coin no report covers was given a path");
    };
    let error = error.to_string();
    assert!(error.contains("newer than its subtree's report"), "{error}");
    assert!(provider.named.lock().unwrap().is_empty());
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// An application no shard reports for (one executed in the global venue)
/// has no accumulator index: the wallet rebuilds the whole tree from its
/// scan against the root the scan carries.
#[tokio::test]
async fn spend_witnesses_rebuild_an_unreported_application_from_its_scan() {
    let wallet = witness_wallet();
    let (fixture, early, _) = ReportedCoins::new(&wallet, 3, &[], false);
    let provider = Arc::new(RecordingCoins::new(&wallet, &fixture));
    let (client, stop, serving) = witness_client(&fixture, provider.clone()).await;
    let coin = fixture.output(&early[2]);
    let (root, paths) = wallet
        .witnesses(&client, &[(early[2], &coin)])
        .await
        .unwrap();
    assert!(root == fixture.root, "not the scan's root");
    let expected = provider.tree.auth_path(&early[2]).unwrap();
    assert!(paths[0].siblings == expected.siblings && paths[0].right == expected.right);
    assert!(provider.named.lock().unwrap().is_empty());
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// A spend lists the coins once: the scan that selects its inputs keeps the
/// coins under the subtrees holding the wallet's coins, another wallet's
/// beside them included, and drops the rest, so the witnesses take no second
/// scan, still name no input to the node and still match the whole tree.
#[tokio::test]
async fn spend_witnesses_come_from_the_selection_scan() {
    use std::sync::atomic::Ordering::SeqCst;
    let (wallet, other) = (witness_wallet(), witness_wallet());
    let (fixture, early, _) = ReportedCoins::with_other(&wallet, Some(&other), 3, &[], true);
    let provider = Arc::new(RecordingCoins::new(&wallet, &fixture));
    let (client, stop, serving) = witness_client(&fixture, provider.clone()).await;
    let owned = wallet
        .clone()
        .scan_spendable(&client, 64, 16)
        .await
        .unwrap();
    assert_eq!(owned.len(), 3);
    let scanned = provider.pages.load(SeqCst);
    assert_eq!(scanned, fixture.coins.len().div_ceil(2));
    {
        let ours: std::collections::BTreeSet<u64> =
            early[..3].iter().map(ReportedCoins::block).collect();
        let expected = fixture
            .coins
            .iter()
            .filter(|(address, ..)| ours.contains(&ReportedCoins::block(address)))
            .count();
        assert!(expected > 3, "the other wallet has a coin beside ours");
        let prepared = wallet.prepared.lock().unwrap();
        let kept = prepared
            .as_ref()
            .expect("the selection scan kept the spend's witnesses")
            .kept
            .len();
        assert_eq!(
            kept, expected,
            "the scan must keep exactly the coins in blocks holding ours"
        );
    }
    let first = owned.iter().find(|coin| coin.address == early[0]).unwrap();
    let second = owned
        .iter()
        .find(|coin| ReportedCoins::block(&coin.address) != ReportedCoins::block(&early[0]))
        .unwrap();
    let selected = [
        (first.address, &first.output),
        (second.address, &second.output),
    ];
    let (root, paths) = wallet.witnesses(&client, &selected).await.unwrap();
    assert_eq!(
        provider.pages.load(SeqCst) - scanned,
        0,
        "the spend scanned the coins again for its witnesses"
    );
    assert!(provider.named.lock().unwrap().is_empty());
    assert!(root == fixture.root, "not the canonical root");
    for ((address, _), path) in selected.iter().zip(&paths) {
        let expected = provider.tree.auth_path(address).unwrap();
        assert!(
            path.siblings == expected.siblings && path.right == expected.right,
            "the path of {} is not the whole tree's",
            hex::encode(address)
        );
    }
    assert!(
        wallet.prepared.lock().unwrap().is_none(),
        "a selection scan's witnesses serve one spend"
    );
    stop.send(()).unwrap();
    serving.await.unwrap();
}

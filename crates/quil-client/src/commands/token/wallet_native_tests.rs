//! Opt-in full wallet test over a loopback gRPC server with funded fixtures.
use super::*;
use quil_lattice_ct::confidential::{
    coin_tree::{CoinRecord, CoinTree},
    memo::create_output,
    relation::backend::native::NativeBudget,
    transfer::{CompileLimits, Transfer, TARGET_TRANSACTION_BYTES},
};
use quil_types::store::*;
use std::sync::Arc;

/// Parse and dispatch the public token command; only context loading is supplied
/// by the encrypted-keystore fixture. Proving, RPC and submission are unchanged.
async fn run_parsed_token_command(tc: &TokenCtx, arguments: &[&str]) {
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        token: super::super::TokenArgs,
    }
    let cli = Cli::try_parse_from(arguments).unwrap();
    super::super::run_with_context(tc, &cli.token).await.unwrap();
}

struct WitnessProvider {
    tree: CoinTree,
    network: [u8; 32],
    application: [u8; 32],
    coins: Vec<([u8; 32], Output)>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native claim CLI with encrypted keystore and authenticated loopback RPC"]
async fn wallet_claim_command_proves_and_submits_both_authorities() {
    use quil_execution::{hypergraph_state::{HypergraphState, vertex_adds_discriminator},
        token_intrinsic::escrow::StoredEscrow};
    use quil_lattice_ct::confidential::{memo::create_escrow_recovery,
        pending_claim::{ClaimBranch, EscrowPolicy, PendingClaim}, relation::backend::native};
    let directory = tempfile::tempdir().unwrap();
    let km = Arc::new(quil_keys::FileKeyManager::new(directory.path().join("keys.yml"), &hex::encode([54; 32]),
        "q-prover-key".into(), Box::new(quil_crypto::FalconKeyConstructor)).unwrap());
    km.create_agreement_key("q-onion-key", 9).unwrap();
    let authority = km.create_falcon_key("q-prover-key").unwrap();
    let peer_seed = [55; 57];
    let peer_public = quil_crypto::Ed448Signer::derive_public(&peer_seed).unwrap();
    let mut peer_key = peer_seed.to_vec(); peer_key.extend_from_slice(&peer_public);
    km.set_peer_priv_key_hex(&hex::encode(peer_key));
    let mut tc = TokenCtx { node_config: quil_config::Config::default(), config_dir: directory.path().to_path_buf(),
        key_manager: km, connect_opts: crate::rpc::ConnectOpts::default(), submit_opts: crate::rpc::ConnectOpts::default(), peer_id_bytes: Vec::new() };
    let network = quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let application = quil_execution::domains::QUIL_TOKEN;
    let wallet = RecipientWallet::load(&tc, &network, &application).unwrap();
    let started = std::time::Instant::now();
    for refund in [false, true] {
        let recovery = create_escrow_recovery(&wallet.context, wallet.address(), wallet.address(), 257).unwrap();
        let stored = StoredEscrow { frame_number: 1,
            output: Output { commitment: recovery.commitment, owner: recovery.recipient.owner, memo: recovery.recipient.ciphertext },
            policy: EscrowPolicy { recipient: authority.as_slice().try_into().unwrap(), refund: authority.as_slice().try_into().unwrap(), refund_after_global_frame: 0 },
            refund_recovery: recovery.refund };
        let (address, blob) = stored.encode(&wallet.context).unwrap();
        let store = Arc::new(quil_hypergraph::testing::MemStore::new());
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver)));
        let state = HypergraphState::new(crdt.clone());
        state.set(&application, &address, &vertex_adds_discriminator().unwrap(), 1, blob).unwrap();
        state.commit().unwrap(); state.abort(); crdt.commit(1).unwrap();
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = received.clone(); let public = peer_public.clone();
        let server = quil_rpc::node_service::NodeRpcServer::new().with_hypergraph_store(store)
            .with_send_handler_fn(Arc::new(move |domain, payload, signature| {
                let public = public.clone(); let capture = capture.clone();
                Box::pin(async move {
                    let mut signed = crate::send::node_auth_domain(&domain); signed.extend_from_slice(&payload);
                    if domain != application || !quil_crypto::ed448_verify(&public, &signed, &signature) {
                        return Err("invalid authenticated submission".into());
                    }
                    let bundle = quil_execution::message_envelope::CanonicalMessageBundle::from_canonical_bytes(&payload).map_err(|e| e.to_string())?;
                    if bundle.requests.len() != 1 { return Err("expected one claim".into()); }
                    capture.lock().unwrap().push(bundle.requests[0].as_ref().ok_or("missing claim")?.inner_bytes.clone());
                    Ok(())
                })
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        tc.connect_opts.listen_grpc_multiaddr = format!("/ip4/127.0.0.1/tcp/{}", listener.local_addr().unwrap().port());
    tc.submit_opts = tc.connect_opts.clone();
        let incoming = futures::stream::unfold(listener, |listener| async {
            let result = listener.accept().await.map(|(socket, _)| socket); Some((result, listener))
        });
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(quil_types::proto::node::node_service_server::NodeServiceServer::new(server))
                .serve_with_incoming_shutdown(incoming, async { let _ = stopped.await; }).await.unwrap();
        });
        run_parsed_token_command(&tc, &["token", if refund { "reject" } else { "accept" },
            &hex::encode(address), "--application", &hex::encode(application), "--fee", "2"]).await;
        let bytes = { let guard = received.lock().unwrap(); assert_eq!(guard.len(), 1); guard[0].clone() };
        assert!(bytes.len() <= TARGET_TRANSACTION_BYTES);
        let claim = PendingClaim::decode(&bytes, &network, &application).unwrap();
        assert_eq!(claim.statement.branch, if refund { ClaimBranch::Refund } else { ClaimBranch::Recipient });
        assert_eq!(claim.statement.escrow_address, address);
        assert_eq!(claim.statement.policy, stored.policy);
        assert_eq!(claim.statement.source, stored.output.commitment);
        assert_eq!(claim.statement.fee, 2);
        assert_eq!(claim.statement.outputs.len(), 1);
        assert_eq!(wallet.open(&claim.statement.outputs[0]).unwrap().amount, 255);
        assert!(quil_crypto::falcon_verify(&authority, &claim.signature, &claim.statement.context_bytes().unwrap(), &wallet.context));
        assert!(native::verify_owned(claim.statement.public_relation(1).unwrap(), &claim.proof,
            NativeBudget { max_native_bytes: 1 << 30 }).unwrap());
        stop.send(()).unwrap(); serving.await.unwrap();
        eprintln!("wallet_claim_command_passed refund={refund} bytes={} seconds={:.3}", bytes.len(), started.elapsed().as_secs_f64());
    }
}
/// Serves witnesses the way a node does: from the committed accumulator, at
/// the positions its blocks gave the coins and the depth its root has.
struct SnapshotWitnessProvider {
    snapshot: quil_lattice_ct::confidential::sharded_tree::ShardedCoinTree,
    network: [u8; 32],
    application: [u8; 32],
    coins: Vec<([u8; 32], Output, u64)>,
}

impl CoinWitnessProvider for SnapshotWitnessProvider {
    fn coin_page(&self, domain: &[u8; 32], snapshot: Option<&[u8; 32]>, after: Option<&[u8; 32]>) -> quil_types::error::Result<Option<CoinPageData>> {
        assert_eq!(domain, &self.application);
        assert!(snapshot.is_none() || snapshot == Some(&[64; 32]));
        let mut coins: Vec<_> = self.coins.iter().filter(|(address, _, _)| after.is_none_or(|old| address > old)).collect();
        coins.sort_by_key(|(address, _, _)| *address);
        let has_more = coins.len() > 8; coins.truncate(8);
        let cursor = coins.last().map(|(address, _, _)| *address).or(after.copied());
        Ok(Some(CoinPageData { network: self.network, snapshot_id: [64; 32],
            root_record: self.snapshot.root_at_depth(self.snapshot.current_depth()).unwrap().encode().unwrap().to_vec(),
            coins: coins.into_iter().map(|(address, output, position)| CoinData { address: *address, frame_number: 1,
                position: *position,
                owner: output.owner.to_vec(), commitment: output.commitment.to_bytes().to_vec(), memo: output.memo.to_vec() }).collect(),
            cursor, has_more }))
    }

    fn coin_witnesses(&self, domain: &[u8; 32], addresses: &[[u8; 32]]) -> quil_types::error::Result<Option<CoinWitnessBundle>> {
        assert_eq!(domain, &self.application);
        let depth = self.snapshot.current_depth();
        let root = self.snapshot.root_at_depth(depth).unwrap();
        Ok(Some(CoinWitnessBundle {
            network: self.network,
            depth: depth as u8,
            root_record: root.encode().unwrap().to_vec(),
            witnesses: addresses
                .iter()
                .map(|address| {
                    let path = self.snapshot.auth_path_at_depth(address, depth).unwrap();
                    CoinWitnessData {
                        address: *address,
                        found: true,
                        siblings: path.siblings.iter().map(|node| node.to_bytes().to_vec()).collect(),
                        right: path.right,
                    }
                })
                .collect(),
        }))
    }
}

impl CoinWitnessProvider for WitnessProvider {
    fn coin_page(&self, domain: &[u8; 32], snapshot: Option<&[u8; 32]>, after: Option<&[u8; 32]>) -> quil_types::error::Result<Option<CoinPageData>> {
        assert_eq!(domain, &self.application);
        assert!(snapshot.is_none() || snapshot == Some(&[64; 32]));
        let mut coins: Vec<_> = self.coins.iter().filter(|(address, _)| after.is_none_or(|old| address > old)).collect();
        coins.sort_by_key(|(address, _)| *address);
        let has_more = coins.len() > 8; coins.truncate(8);
        let cursor = coins.last().map(|(address, _)| *address).or(after.copied());
        Ok(Some(CoinPageData { network: self.network, snapshot_id: [64; 32],
            root_record: self.tree.root_at_depth(1).unwrap().encode().unwrap().to_vec(),
            coins: coins.into_iter().map(|(address, output)| CoinData { address: *address, frame_number: 1,
                position: self.tree.position(address).expect("fixture coin is in the witness tree"),
                owner: output.owner.to_vec(), commitment: output.commitment.to_bytes().to_vec(), memo: output.memo.to_vec() }).collect(),
            cursor, has_more }))
    }
    fn coin_witnesses(
        &self,
        domain: &[u8; 32],
        addresses: &[[u8; 32]],
    ) -> quil_types::error::Result<Option<CoinWitnessBundle>> {
        assert_eq!(domain, &self.application);
        let root = self.tree.root_at_depth(1).unwrap();
        Ok(Some(CoinWitnessBundle {
            network: self.network,
            depth: 1,
            root_record: root.encode().unwrap().to_vec(),
            witnesses: addresses
                .iter()
                .map(|address| {
                    let path = self.tree.auth_path(address, 1).unwrap();
                    CoinWitnessData {
                        address: *address,
                        found: true,
                        siblings: path
                            .siblings
                            .iter()
                            .map(|node| node.to_bytes().to_vec())
                            .collect(),
                        right: path.right,
                    }
                })
                .collect(),
        }))
    }
}

fn wallet() -> Arc<RecipientWallet> {
    let keys = sntrup761::Sntrup761KeyPair::generate();
    Arc::new(
        RecipientWallet::from_keys(
            &[1; 32],
            &[2; 32],
            &keys.public,
            Zeroizing::new(keys.secret),
        )
        .unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native wallet escrow lookup, proving, authenticated RPC and worker-backed execution"]
async fn wallet_rpc_proves_and_executes_pending_claims() {
    wallet_pending_flow(false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native wallet funding-to-claim/refund chain over authenticated loopback RPC"]
async fn wallet_rpc_funds_then_claims_pending() {
    wallet_pending_flow(true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native wallet funding/claim/refund chain with RocksDB reopen"]
async fn wallet_rpc_funds_then_claims_pending_with_restart() {
    wallet_pending_flow(true, true).await;
}

async fn wallet_pending_flow(fund_escrow: bool, disk: bool) {
    use quil_execution::{engines::{ExecutionMode, TokenExecutionEngine},
        hypergraph_state::{HypergraphState, vertex_adds_discriminator},
        token_intrinsic::{escrow::StoredEscrow, roots, state,
            dispatch::TokenPolicy}};
    use quil_lattice_ct::confidential::{memo::create_escrow_recovery,
        pending_claim::{ClaimBranch, EscrowPolicy, PendingClaim},
        relation::backend::worker_client::WorkerVerifier};
    use quil_types::{crypto::Signer, execution::{FrameExecutionContext, ShardExecutionEngine}};
    let started = std::time::Instant::now();
    let network = [41; 32]; let application = quil_execution::domains::QUIL_TOKEN;
    let wallets: Vec<_> = (0..2).map(|_| {
        let keys = sntrup761::Sntrup761KeyPair::generate();
        Arc::new(RecipientWallet::from_keys(&network, &application, &keys.public, Zeroizing::new(keys.secret)).unwrap())
    }).collect();
    let signers: Vec<Arc<dyn Signer>> = (0..2).map(|_| Arc::new(quil_crypto::FalconSigner::generate()) as Arc<dyn Signer>).collect();
    // Deadlines come from QUIL_TEST_WORKER_{WALL,CPU}_SECS (default 600 s); Linux
    // ARM64 Docker proving has measured ~960 s per proof, so those runs raise it.
    let worker = WorkerVerifier::from_test_env(std::path::PathBuf::from(std::env::var("QUIL_AMOUNT_WORKER_PATH").unwrap())).unwrap();
    // Coins sit at the positions their blocks give them, so the accumulator
    // has its real depth and the spend circuit must match it.
    let limits = state::SnapshotLimits { max_coins: 8, max_depth: 32, max_nodes: 1 << 12 };
    let budget = NativeBudget { max_native_bytes: if fund_escrow { 24 << 30 } else { 1 << 30 } };
    let key_directory = tempfile::tempdir().unwrap();
    let km = quil_keys::FileKeyManager::new(key_directory.path().join("keys.yml"), &hex::encode([42; 32]),
        "q-prover-key".into(), Box::new(quil_crypto::FalconKeyConstructor)).unwrap();
    let peer_seed = [43; 57];
    let peer_public = quil_crypto::Ed448Signer::derive_public(&peer_seed).unwrap();
    let mut peer_key = peer_seed.to_vec(); peer_key.extend_from_slice(&peer_public);
    km.set_peer_priv_key_hex(&hex::encode(peer_key));
    for (selected, branch) in [ClaimBranch::Recipient, ClaimBranch::Refund].into_iter().enumerate() {
        let recovery = create_escrow_recovery(&wallets[0].context, wallets[0].address(), wallets[1].address(), u128::MAX).unwrap();
        let mut escrow = StoredEscrow { frame_number: 1,
            output: Output { commitment: recovery.commitment, owner: recovery.recipient.owner, memo: recovery.recipient.ciphertext },
            policy: EscrowPolicy { recipient: signers[0].public_key().try_into().unwrap(), refund: signers[1].public_key().try_into().unwrap(), refund_after_global_frame: 100 },
            refund_recovery: recovery.refund };
        let (mut address, blob) = escrow.encode(&wallets[0].context).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let store: Arc<dyn HypergraphStore> = if disk {
            Arc::new(quil_store::RocksHypergraphStore::new(quil_store::RocksDb::open(directory.path()).unwrap().inner()))
        } else {
            Arc::new(quil_hypergraph::testing::MemStore::new())
        };
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver)));
        let state = HypergraphState::new(crdt.clone());
        let disc = vertex_adds_discriminator().unwrap();
        let mut funding_coins = Vec::new();
        if fund_escrow {
            // Fund the wallet the way the network does — a committed claim of
            // an authorized reward — so the coins sit at the positions the
            // commit assigned and its per-block sequence matches the shard's.
            let outputs: Vec<_> = [u128::MAX, 258].into_iter()
                .map(|amount| create_output(&wallets[0].context, wallets[0].address(), amount).unwrap().output)
                .collect();
            let bootstrap = quil_lattice_ct::confidential::mint_claim::MintClaim {
                network, application, cited_global_frame: 1, global_root: [7; 32],
                receipt: [77; 32], fee: 0, outputs: outputs.clone(), forest_proof: vec![8; 8],
            }.encode().unwrap();
            let placed = quil_execution::token_intrinsic::commit_apply::commit_and_place(
                &state, 1, &network, &application,
                quil_execution::token_intrinsic::TYPE_LATTICE_MINT_CLAIM, &bootstrap, limits).unwrap();
            funding_coins = placed.iter().copied().zip(outputs).collect();
        } else {
            state.set(&application, &address, &disc, 1, blob).unwrap();
            // The escrow's creation committed earlier: the record the claim is
            // decided against lives in GLOBAL, the blob above is its delivery.
            let binding = quil_execution::token_intrinsic::global_commit::escrow_binding(
                &wallets[0].context, &address, &escrow.output.commitment.to_bytes(),
                &escrow.policy.recipient, &escrow.policy.refund, escrow.policy.refund_after_global_frame);
            state.set(&quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS,
                &quil_execution::token_intrinsic::global_commit::escrow_address(&application, &address).unwrap(),
                &disc, 1,
                quil_execution::token_intrinsic::global_commit::encode_escrow_record(
                    &binding, escrow.policy.refund_after_global_frame, false).unwrap()).unwrap();
        }
        roots::refresh_root(&state, &network, &application, limits).unwrap();
        // What a shard's accumulator report publishes: without it no spend's
        // root is canonical and the commit refuses every one of them. The
        // bootstrap claim above published it already; this covers the escrow
        // fixture, which seeds state directly.
        quil_execution::token_intrinsic::commit_apply::publish_canonical_root(&state, 1, &network, &application).unwrap();
        state.commit().unwrap(); state.abort(); crdt.commit(1).unwrap();
        // The node answers witness requests from its committed accumulator.
        let witness_provider = fund_escrow.then(|| {
            let snapshot = state::load_committed_snapshot(&state, &network, &application, limits).unwrap();
            let coins = funding_coins.iter()
                .map(|(address, output)| (*address, output.clone(), snapshot.position(address).expect("committed coin")))
                .collect();
            Arc::new(SnapshotWitnessProvider { snapshot, network, application, coins })
        });
        let stubs = quil_execution::testing::NoopExecutionCrypto::new();
        // The global venue: with no shard to relay to, it verifies, commits
        // and places what the operation creates in one pass.
        let engine = Arc::new(TokenExecutionEngine::new_with_state(ExecutionMode::Global,
            Arc::new(quil_types::crypto::NoopInclusionProver), crdt.clone(), stubs.key_manager, stubs.clock_store)
            .with_token_proofs(TokenPolicy { network, limits: CompileLimits { max_inputs: 2, max_outputs: 2, max_depth: 32 },
                snapshots: limits, native_budget: budget }).unwrap()
            .with_token_worker(worker.clone()).unwrap());
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = received.clone(); let public = peer_public.clone();
        let execution = FrameExecutionContext { frame_number: 10_000, finalized_global_frame: Some(100), venue: None, shard: quil_types::execution::ShardPath::WHOLE };
        let next_frame = Arc::new(std::sync::atomic::AtomicU64::new(execution.frame_number));
        let server = quil_rpc::node_service::NodeRpcServer::new().with_hypergraph_store(store)
            .with_send_handler_fn(Arc::new(move |domain, payload, authentication| {
                let engine = engine.clone(); let capture = capture.clone(); let public = public.clone();
                let next_frame = next_frame.clone();
                Box::pin(async move {
                    let mut signed = crate::send::node_auth_domain(&domain); signed.extend_from_slice(&payload);
                    if domain != application || !quil_crypto::ed448_verify(&public, &signed, &authentication) {
                        return Err("invalid authenticated destination or sender".into());
                    }
                    let execution = FrameExecutionContext { frame_number: next_frame.fetch_add(1, std::sync::atomic::Ordering::SeqCst), ..execution };
                    tokio::task::spawn_blocking(move || {
                        let bundle = quil_execution::message_envelope::CanonicalMessageBundle::from_canonical_bytes(&payload).map_err(|e| e.to_string())?;
                        if bundle.requests.len() != 1 { return Err("expected one pending claim".into()); }
                        let request = bundle.requests[0].as_ref().ok_or("missing pending claim")?;
                        engine.validate_message(execution.frame_number, &domain, &payload).map_err(|e| e.to_string())?;
                        engine.process_message_with_context(execution, &num_bigint::BigInt::from(0), &domain, &payload).map_err(|e| e.to_string())?;
                        capture.lock().unwrap().push(request.inner_bytes.clone());
                        Ok(())
                    }).await.map_err(|e| e.to_string())?
                })
            }));
        let server = if let Some(provider) = witness_provider { server.with_coin_witness_provider(provider) } else { server };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let incoming = futures::stream::unfold(listener, |listener| async {
            let result = listener.accept().await.map(|(socket, _)| socket); Some((result, listener))
        });
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn(async {
            tonic::transport::Server::builder()
                .add_service(quil_types::proto::node::node_service_server::NodeServiceServer::new(server))
                .serve_with_incoming_shutdown(incoming, async { let _ = stopped.await; }).await.unwrap();
        });
        let channel = tonic::transport::Endpoint::from_shared(endpoint).unwrap().connect().await.unwrap();
        let mut client = quil_types::proto::node::node_service_client::NodeServiceClient::new(channel);
        let mut expected_deliveries = Vec::new();
        if fund_escrow {
            use quil_lattice_ct::confidential::pending_create::PendingCreate;
            eprintln!("wallet_pending_funding_proving branch={branch:?} seconds={:.3}", started.elapsed().as_secs_f64());
            let bytes = wallets[0].clone().create_pending(&client, funding_coins,
                EscrowDestination { recipient: wallets[0].address().clone(), refund: wallets[1].address().clone(),
                    amount: u128::MAX, policy: escrow.policy.clone() },
                vec![(wallets[0].address().clone(), 256)], 2,
                CompileLimits { max_inputs: 2, max_outputs: 2, max_depth: 32 }, budget).await.unwrap();
            assert!(bytes.len() <= TARGET_TRANSACTION_BYTES);
            let funding = PendingCreate::decode(&bytes, &network, &application).unwrap();
            let (output, change) = funding.statement.split_outputs().unwrap();
            assert_eq!(change.len(), 1);
            escrow = StoredEscrow { frame_number: execution.frame_number, output: output.clone(),
                policy: funding.statement.policy.clone(), refund_recovery: funding.statement.refund_recovery.clone() };
            address = escrow.encode(&wallets[0].context).unwrap().0;
            wallets[0].submit(&mut client, &km, bytes.clone()).await.unwrap();
            assert_eq!(roots::read_current(&state, &network, &application).unwrap().unwrap().coins, 3);
            crdt.commit(execution.frame_number).unwrap();
            eprintln!("wallet_pending_funding_executed branch={branch:?} bytes={} proof_bytes={} seconds={:.3}", bytes.len(), funding.proof.len(), started.elapsed().as_secs_f64());
            expected_deliveries.push(bytes);
        }
        let execution = FrameExecutionContext { frame_number: execution.frame_number + u64::from(fund_escrow), ..execution };
        let fetched = wallets[selected].fetch_escrow(&client, address).await.unwrap();
        assert_eq!(fetched, escrow);
        let amounts = [u128::MAX - 258, 256];
        eprintln!("wallet_pending_claim_proving branch={branch:?} seconds={:.3}", started.elapsed().as_secs_f64());
        let bytes = wallets[selected].clone().create_pending_claim(address, fetched, branch, Some(100), signers[selected].clone(),
            wallets.iter().zip(amounts).map(|(wallet, amount)| (wallet.address().clone(), amount)).collect(), 2, 2, budget).await.unwrap();
        assert!(bytes.len() <= TARGET_TRANSACTION_BYTES);
        let claim = PendingClaim::decode(&bytes, &network, &application).unwrap();
        eprintln!("wallet_pending_claim_proved branch={branch:?} bytes={} proof_bytes={} seconds={:.3}", bytes.len(), claim.proof.len(), started.elapsed().as_secs_f64());
        wallets[selected].submit(&mut client, &km, bytes.clone()).await.unwrap();
        expected_deliveries.push(bytes.clone());
        assert_eq!(*received.lock().unwrap(), expected_deliveries);
        let root = roots::read_current(&state, &network, &application).unwrap().unwrap();
        assert_eq!(root.coins, if fund_escrow { 5 } else { 2 });
        // Resubmitting the executed claim is a replay: the engine rejects it
        // on the committed consumption marker and the root is unchanged.
        let replay = wallets[selected].submit(&mut client, &km, bytes.clone()).await;
        let rejection = replay.unwrap_err().to_string();
        assert!(rejection.contains("already decided") || rejection.contains("escrow already consumed"), "replay must be rejected: {rejection}");
        assert_eq!(roots::read_current(&state, &network, &application).unwrap(), Some(root.clone()));
        crdt.commit(execution.frame_number + 1).unwrap();
        let snapshot = state::load_committed_snapshot(&state, &network, &application, limits).unwrap();
        assert_eq!(snapshot.root_at_depth(usize::from(root.depth)).unwrap(), root);
        // The claim's outputs are at the positions the commit assigned them.
        for (i, output) in claim.statement.outputs.iter().enumerate() {
            // The address is the output's content identity, so its presence is
            // the output itself, wherever the commit placed it.
            let (coin_address, _) = state::coin_identity(&wallets[i].context, execution.frame_number, output).unwrap();
            assert!(state.get(&application, &coin_address, &disc).unwrap().is_some_and(|blob| !blob.is_empty()));
            assert_eq!(wallets[i].open(output).unwrap().amount, amounts[i]);
        }
        stop.send(()).unwrap(); serving.await.unwrap();
        if disk {
            drop(client);
            drop(state);
            drop(crdt);
            let reopened = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
                Arc::new(quil_store::RocksHypergraphStore::new(quil_store::RocksDb::open(directory.path()).unwrap().inner())),
                Arc::new(quil_types::crypto::NoopInclusionProver))));
            assert_eq!(roots::read_current(&reopened, &network, &application).unwrap(), Some(root.clone()));
            let snapshot = state::load_committed_snapshot(&reopened, &network, &application, limits).unwrap();
            assert_eq!(snapshot.root_at_depth(usize::from(root.depth)).unwrap(), root);
            assert_eq!(reopened.get(&application, &address, &disc).unwrap(), Some(escrow.encode(&wallets[0].context).unwrap().1));
            // Consumption is the commit's record, not a marker on the shard.
            assert!(quil_execution::token_intrinsic::global_commit::escrow(&reopened, &application, &address).unwrap().unwrap().2);
            for (i, output) in claim.statement.outputs.iter().enumerate() {
                let (coin_address, _) = state::coin_identity(&wallets[i].context, execution.frame_number, output).unwrap();
                assert!(reopened.get(&application, &coin_address, &disc).unwrap().is_some_and(|blob| !blob.is_empty()));
                assert_eq!(wallets[i].open(output).unwrap().amount, amounts[i]);
            }
            eprintln!("wallet_pending_chain_reopened branch={branch:?} coins={} consumed=true", root.coins);
        }
        eprintln!("wallet_pending_claim_executed branch={branch:?} bytes={} recovered_outputs=2 seconds={:.3}", bytes.len(), started.elapsed().as_secs_f64());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "complete native mint wallet construction"]
async fn wallet_proves_mint() {
    use quil_lattice_ct::confidential::mint::{Mint, RewardClaim, MAX_REWARD_PROOF_BYTES};
    let started = std::time::Instant::now();
    let keys = sntrup761::Sntrup761KeyPair::generate();
    let recipient = Arc::new(
        RecipientWallet::from_keys(
            &[1; 32],
            &quil_execution::domains::QUIL_TOKEN,
            &keys.public,
            Zeroizing::new(keys.secret),
        )
        .unwrap(),
    );
    let signers: Vec<Arc<dyn quil_types::crypto::Signer>> = (0..2)
        .map(|_| {
            Arc::new(quil_crypto::FalconSigner::generate()) as Arc<dyn quil_types::crypto::Signer>
        })
        .collect();
    let claims = signers
        .iter()
        .zip([u128::MAX - 257, 257])
        .map(|(signer, value)| {
            let public_key: [u8; 897] = signer.public_key().try_into().unwrap();
            RewardClaim {
                owner: quil_crypto::poseidon::hash_bytes_to_32(&public_key).unwrap(),
                public_key,
                value,
                // Exercise the full wire budget. These are structural placeholders;
                // this wallet test does not establish reward membership/admission.
                forest_proof: vec![1; MAX_REWARD_PROOF_BYTES],
            }
        })
        .collect();
    let encoded = recipient
        .clone()
        .create_mint(
            7,
            [8; 32],
            claims,
            signers,
            vec![
                (recipient.address().clone(), u128::MAX - 258),
                (recipient.address().clone(), 256),
            ],
            2,
            2,
            2,
            NativeBudget {
                max_native_bytes: 1024 * 1024 * 1024,
            },
        )
        .await
        .unwrap();
    assert!(encoded.len() < TARGET_TRANSACTION_BYTES);
    let mint = Mint::decode(&encoded, &recipient.network, &recipient.application).unwrap();
    for (claim, signature) in mint.statement.claims.iter().zip(&mint.signatures) {
        assert!(quil_crypto::falcon_verify(
            &claim.public_key,
            signature,
            &mint.statement.context_bytes().unwrap(),
            &recipient.context
        ));
    }
    assert_eq!(
        recipient.open(&mint.statement.outputs[0]).unwrap().amount,
        u128::MAX - 258
    );
    assert_eq!(
        recipient.open(&mint.statement.outputs[1]).unwrap().amount,
        256
    );
    if let Ok(path) = std::env::var("QUIL_TEST_TRANSACTION_PATH") {
        std::fs::write(path, &encoded).unwrap();
    }
    eprintln!("wallet_mint native_verified=true claimant_signatures_verified=2 membership_verified=false recipients_recovered=2 bytes={} proof_bytes={} seconds={:.3}",
        encoded.len(),mint.proof.len(),started.elapsed().as_secs_f64());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "complete native shield wallet construction"]
async fn wallet_proves_shield() {
    use quil_lattice_ct::confidential::shield::Shield;
    let started = std::time::Instant::now();
    let sender = wallet();
    let recipient = wallet();
    let public = quil_crypto::Ed448Signer::derive_public(&[3; 57]).unwrap();
    let signer = Arc::new(quil_crypto::Ed448Signer::from_bytes(&[3; 57], &public).unwrap());
    let recipients = vec![
        (recipient.address().clone(), u128::MAX - 258),
        (sender.address().clone(), 256),
    ];
    let encoded = sender
        .clone()
        .create_shield(
            [4; 32],
            u128::MAX,
            signer,
            recipients,
            2,
            2,
            NativeBudget {
                max_native_bytes: 1024 * 1024 * 1024,
            },
        )
        .await
        .unwrap();
    assert!(encoded.len() < TARGET_TRANSACTION_BYTES);
    let shield = Shield::decode(&encoded, &sender.network, &sender.application).unwrap();
    assert!(quil_crypto::ed448_verify(
        &public,
        &shield.statement.context_bytes().unwrap(),
        &shield.signature
    ));
    assert_eq!(
        recipient.open(&shield.statement.outputs[0]).unwrap().amount,
        u128::MAX - 258
    );
    assert_eq!(
        sender.open(&shield.statement.outputs[1]).unwrap().amount,
        256
    );
    if let Ok(path) = std::env::var("QUIL_TEST_TRANSACTION_PATH") {
        std::fs::write(path, &encoded).unwrap();
    }
    eprintln!("wallet_shield native_verified=true recipients_recovered=2 bytes={} proof_bytes={} seconds={:.3}",
        encoded.len(), shield.proof.len(), started.elapsed().as_secs_f64());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "full native wallet proving requires substantial time and memory"]
async fn wallet_rpc_proves_transfer() {
    wallet_transfer_flow(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native transfer command with scan, selection, witness RPC and authenticated submission"]
async fn wallet_transfer_command_proves_and_submits() {
    wallet_transfer_flow(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native parsed transfer with automatic fee quote and submission refresh"]
async fn wallet_transfer_command_quotes_fee_and_submits() {
    wallet_transfer_flow_with_fee(true, true).await;
}

async fn wallet_transfer_flow(command: bool) {
    wallet_transfer_flow_with_fee(command, false).await;
}

async fn wallet_transfer_flow_with_fee(command: bool, automatic_fee: bool) {
    assert!(!automatic_fee || command);

    let start = std::time::Instant::now();
    let directory = tempfile::tempdir().unwrap();
    let km = Arc::new(quil_keys::FileKeyManager::new(directory.path().join("keys.yml"), &hex::encode([65; 32]),
        "q-prover-key".into(), Box::new(quil_crypto::FalconKeyConstructor)).unwrap());
    km.create_agreement_key("q-onion-key", 9).unwrap();
    let peer_seed = [66; 57];
    let public = quil_crypto::Ed448Signer::derive_public(&peer_seed).unwrap();
    let mut peer_key = peer_seed.to_vec(); peer_key.extend_from_slice(&public);
    km.set_peer_priv_key_hex(&hex::encode(peer_key));
    let mut tc = TokenCtx { node_config: quil_config::Config::default(), config_dir: directory.path().to_path_buf(),
        key_manager: km, connect_opts: crate::rpc::ConnectOpts::default(), submit_opts: crate::rpc::ConnectOpts::default(), peer_id_bytes: Vec::new() };
    let sender = if command {
        Arc::new(RecipientWallet::load(&tc, &quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network),
            &quil_execution::domains::QUIL_TOKEN).unwrap())
    } else { wallet() };
    let keys = sntrup761::Sntrup761KeyPair::generate();
    let recipient = Arc::new(RecipientWallet::from_keys(&sender.network, &sender.application, &keys.public, Zeroizing::new(keys.secret)).unwrap());
    let fee = if automatic_fee {
        // The automatic fee prices the transfer's staged shape (two coins and
        // the input limit's markers) at the snapshot below, plus the automatic
        // headroom for fee-vote movement.
        let cost = quil_execution::token_intrinsic::cost::shape_growth(&sender.context,
            quil_execution::token_intrinsic::cost::Shape { coins: 2, markers: 4, escrow: false }).unwrap();
        let charge = (quil_execution::pricing::fee_multiplier_for_cost(quil_execution::pricing::MAINNET_NETWORK, 50_000, 1 << 30, &num_bigint::BigInt::from(cost), 1).unwrap()
            * num_bigint::BigInt::from(cost)).to_string().parse::<u128>().unwrap();
        crate::commands::token::wallet::with_fee_headroom(charge).unwrap()
    } else { 2 };
    let quote_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let outputs: Vec<_> = [u128::MAX, fee.checked_add(6).unwrap()]
        .iter()
        .map(|&amount| {
            create_output(&sender.context, sender.address(), amount)
                .unwrap()
                .output
        })
        .collect();
    // Coins sit in the block their address selects, at that block's next free
    // index — the wallet refuses a scanned coin whose position says otherwise.
    use quil_execution::token_intrinsic::coin_blocks;
    let width = coin_blocks::INITIAL_BLOCK_BITS;
    let mut next_local: std::collections::BTreeMap<u64, u64> = Default::default();
    let mut coins = Vec::new();
    let mut records = Vec::new();
    for output in outputs {
        let identity = quil_execution::token_intrinsic::state::coin_identity(&sender.context, 1, &output).unwrap().0;
        let block = coin_blocks::block_for_address(width, &identity).unwrap();
        let local = next_local.entry(block).or_default();
        let position = coin_blocks::position(width, block, *local).unwrap();
        *local += 1;
        let (address, _) = quil_execution::token_intrinsic::state::create_coin(&sender.context, 1, &output, position).unwrap();
        records.push(CoinRecord { address, owner: output.owner, commitment: output.commitment.clone(), position });
        coins.push((address, output, position));
    }
    let shape = quil_lattice_ct::confidential::sharded_tree::Shape {
        shard_bits: coin_blocks::BLOCK_INDEX_BITS, subtree_bits: coin_blocks::SUBTREE_BITS,
    };
    let tree = quil_lattice_ct::confidential::sharded_tree::ShardedCoinTree::build(&sender.context, shape, &records).unwrap();
    let root = tree.root_at_depth(tree.current_depth()).unwrap();
    let received = Arc::new(std::sync::Mutex::new(Vec::new()));
    let capture = received.clone(); let application = sender.application;
    let mut server = quil_rpc::node_service::NodeRpcServer::new()
        .with_hypergraph_store(Arc::new(quil_hypergraph::testing::MemStore::new()))
        .with_coin_witness_provider(Arc::new(SnapshotWitnessProvider { snapshot: tree, network: sender.network, application, coins: coins.clone() }))
        .with_send_handler_fn(Arc::new(move |domain, payload, signature| {
            let public = public.clone(); let capture = capture.clone();
            Box::pin(async move {
                let mut signed = crate::send::node_auth_domain(&domain); signed.extend_from_slice(&payload);
                if domain != application || !quil_crypto::ed448_verify(&public, &signed, &signature) {
                    return Err("invalid authenticated transfer submission".into());
                }
                let bundle = quil_execution::message_envelope::CanonicalMessageBundle::from_canonical_bytes(&payload).map_err(|e| e.to_string())?;
                if bundle.requests.len() != 1 { return Err("expected one transfer".into()); }
                capture.lock().unwrap().push(bundle.requests[0].as_ref().ok_or("missing transfer")?.inner_bytes.clone());
                Ok(())
            })
        }));
    if automatic_fee {
        let calls = quote_calls.clone();
        let network = sender.network;
        server = server.with_token_fee_provider(Arc::new(move |requested, _global_venue| {
            assert_eq!(requested, application);
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(quil_rpc::node_service::TokenFeeSnapshot {
                network, observed_frame: 42, global_execution: true, difficulty: 50_000,
                world_state_bytes: 1 << 30, fee_multiplier_vote: 1,
            })
        }));
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tc.connect_opts.listen_grpc_multiaddr = format!("/ip4/127.0.0.1/tcp/{}", listener.local_addr().unwrap().port());
    tc.submit_opts = tc.connect_opts.clone();
    let incoming = futures::stream::unfold(listener, |listener| async {
        let result = listener.accept().await.map(|(stream, _)| stream);
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
    // The witnesses come from the accumulator's real shape.
    let limits = CompileLimits {
        max_inputs: 2,
        max_outputs: 2,
        max_depth: 32,
    };
    let mib = std::env::var("QUIL_TEST_NATIVE_MIB")
        .unwrap_or_else(|_| "24576".into())
        .parse::<usize>()
        .unwrap();
    let budget = NativeBudget {
        max_native_bytes: mib.checked_mul(1 << 20).unwrap(),
    };
    let destinations = vec![
        (recipient.address().clone(), u128::MAX),
        (sender.address().clone(), 6),
    ];
    let bytes = if command {
        let mut arguments = vec!["token".to_string(), "transfer".to_string(), hex::encode(recipient.address().encode()),
            u128::MAX.to_string(), "--application".to_string(), hex::encode(sender.application),
            "--max-pages".to_string(), "128".to_string(), "--max-coins".to_string(), "1024".to_string()];
        if !automatic_fee { arguments.extend(["--fee".to_string(), fee.to_string()]); }
        run_parsed_token_command(&tc, &arguments.iter().map(String::as_str).collect::<Vec<_>>()).await;
        if automatic_fee {
            assert_eq!(quote_calls.load(std::sync::atomic::Ordering::SeqCst), 2,
                "expected pre-proving estimate and pre-submission refresh");
        }
        let captured = received.lock().unwrap(); assert_eq!(captured.len(), 1); captured[0].clone()
    } else { sender
        .clone()
        .create_transfer(&client, coins.iter().map(|(address, output, _)| (*address, output.clone())).collect(), destinations, fee, limits, budget)
        .await
        .unwrap() };
    let transfer = Transfer::decode(&bytes, &sender.network, &sender.application).unwrap();
    assert_eq!(transfer.statement.outputs.len(), 2);
    assert!(quil_lattice_ct::confidential::relation::backend::native::verify_owned(
        transfer.statement.public_relation(limits).unwrap(), &transfer.proof, budget).unwrap());
    assert_eq!(transfer.statement.root, root.root);
    assert_eq!(transfer.statement.fee, fee);
    assert_eq!(
        recipient
            .open(&transfer.statement.outputs[0])
            .unwrap()
            .amount,
        u128::MAX
    );
    assert_eq!(
        sender.open(&transfer.statement.outputs[1]).unwrap().amount,
        6
    );
    assert!(sender.open(&transfer.statement.outputs[0]).is_err());
    assert!(bytes.len() <= TARGET_TRANSACTION_BYTES);
    if let Ok(path) = std::env::var("QUIL_TEST_TRANSACTION_PATH") {
        std::fs::write(format!("{path}.root"), root.encode().unwrap()).unwrap();
        std::fs::write(path, &bytes).unwrap();
    }
    stop.send(()).unwrap();
    serving.await.unwrap();
    println!("wallet_transfer_fee automatic={} fee={} quote_calls={}", automatic_fee, fee,
        quote_calls.load(std::sync::atomic::Ordering::SeqCst));
    println!("wallet_rpc_transfer bytes={} proof_bytes={} native_verified=true recipients_recovered=2 seconds={:.3}",
        bytes.len(), transfer.proof.len(), start.elapsed().as_secs_f64());
}

/// A settlement proves over the ordinary funding relation with the settlement
/// header bound, splits its outflow into fee and settlement, returns change,
/// and yields the relay entry the GLOBAL record and the consumer claim share.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "full native settlement proving requires substantial time and memory"]
async fn wallet_rpc_proves_settlement() {
    use quil_lattice_ct::confidential::settlement::Settlement;
    let started = std::time::Instant::now();
    let payer = {
        let keys = sntrup761::Sntrup761KeyPair::generate();
        Arc::new(RecipientWallet::from_keys(&[1; 32], &quil_execution::domains::QUIL_TOKEN, &keys.public, Zeroizing::new(keys.secret)).unwrap())
    };
    let (fee, settlement, price) = (3u128, 1_000u128, 400u128);
    let payee = {
        let keys = sntrup761::Sntrup761KeyPair::generate();
        Arc::new(RecipientWallet::from_keys(&[1; 32], &quil_execution::domains::QUIL_TOKEN, &keys.public, Zeroizing::new(keys.secret)).unwrap())
    };
    let coins: Vec<_> = [settlement + fee + price + 7].iter().enumerate().map(|(position, &amount)| {
        let output = create_output(&payer.context, payer.address(), amount).unwrap().output;
        let (address, _) = quil_execution::token_intrinsic::state::create_coin(&payer.context, 1, &output, position as u64).unwrap();
        (address, output)
    }).collect();
    let records: Vec<_> = coins.iter().enumerate().map(|(position, (address, output))| CoinRecord {
        address: *address, owner: output.owner, commitment: output.commitment.clone(), position: position as u64,
    }).collect();
    let tree = CoinTree::build(&payer.context, &records, 1, 8).unwrap();
    let server = quil_rpc::node_service::NodeRpcServer::new()
        .with_coin_witness_provider(Arc::new(WitnessProvider { tree, network: payer.network, application: payer.application, coins: coins.clone() }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let incoming = futures::stream::unfold(listener, |listener| async {
        Some((listener.accept().await.map(|(stream, _)| stream), listener))
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async {
        tonic::transport::Server::builder()
            .add_service(quil_types::proto::node::node_service_server::NodeServiceServer::new(server))
            .serve_with_incoming_shutdown(incoming, async { let _ = stopped.await; }).await.unwrap();
    });
    let client = quil_types::proto::node::node_service_client::NodeServiceClient::new(
        tonic::transport::Endpoint::from_shared(endpoint).unwrap().connect().await.unwrap());
    let limits = CompileLimits { max_inputs: 2, max_outputs: 2, max_depth: 1 };
    let budget = NativeBudget { max_native_bytes: std::env::var("QUIL_TEST_NATIVE_MIB").unwrap_or_else(|_| "24576".into())
        .parse::<usize>().unwrap().checked_mul(1 << 20).unwrap() };
    let (destination, context) = ([0xD5; 32], [0xC7; 32]);
    let nonce = [0x9A; 32];
    let bytes = payer.clone().create_settlement(&client, coins.clone(), 7, fee, settlement, destination,
        super::SettlementBinding::Bundle(context), Some((payee.address().clone(), nonce, price)), limits, budget).await.unwrap();

    let tx = Settlement::decode(&bytes, &payer.network, &payer.application).unwrap();
    assert_eq!((tx.statement.fee, tx.statement.settlement, tx.statement.funding.fee), (fee, settlement, fee + settlement));
    assert_eq!((tx.statement.destination, tx.statement.context), (destination, context));
    // The payee's payment coin opens for the payee and checks publicly; change returns.
    assert_eq!(payee.open(&tx.statement.funding.outputs[0]).unwrap().amount, price);
    tx.statement.check_payment().unwrap();
    assert_eq!(payer.open(&tx.statement.funding.outputs[1]).unwrap().amount, 7);
    assert!(quil_lattice_ct::confidential::relation::backend::native::verify_owned(
        tx.statement.public_relation(limits).unwrap(), &tx.proof, budget).unwrap());
    // The same proof does not verify as a plain transfer of the funding.
    let as_transfer = Transfer { statement: tx.statement.funding.clone(), proof: tx.proof.clone() };
    assert!(!quil_lattice_ct::confidential::relation::backend::native::verify_owned(
        as_transfer.statement.public_relation(limits).unwrap(), &as_transfer.proof, budget).unwrap_or(false));
    // The node's relay entry and the wallet's receipt agree.
    assert_eq!(quil_execution::token_intrinsic::wire::fee(&bytes).unwrap(), fee);
    let entry = quil_execution::token_intrinsic::settlement_record::operation_entry(&bytes).unwrap().unwrap();
    assert_eq!(entry.receipt, quil_execution::token_intrinsic::settlement_record::receipt_address(&tx.statement).unwrap());
    assert_eq!((entry.destination, entry.context, entry.settlement), (destination, context, settlement));
    assert_eq!((entry.payment_address, entry.payment),
        (quil_execution::token_intrinsic::settlement_record::payment_address(&payee.address().encode()).unwrap(), price));
    // The wallet submits it to the QUIL application like a transfer.
    let (submission_domain, _) = payer.prepare_submission(bytes.clone()).unwrap();
    assert_eq!(submission_domain, quil_execution::domains::QUIL_TOKEN.to_vec());

    // The same spend pre-funded: bound to a claimant key, not to a bundle. Its
    // record carries the claimant's address, and only a claim presenting that
    // exact key can name the bundle it funds.
    let claimant = quil_lattice_ct::confidential::settlement::Claimant { key_type: 1, public_key: vec![0x4C; 57] };
    // Without the payment coin the change absorbs its value: the same inputs
    // fund fee + settlement + change.
    let bytes = payer.clone().create_settlement(&client, coins, 7 + price, fee, settlement, destination,
        super::SettlementBinding::Claimant(claimant.clone()), None, limits, budget).await.unwrap();
    let prefunded = Settlement::decode(&bytes, &payer.network, &payer.application).unwrap();
    assert_eq!(prefunded.statement.context, [0; 32]);
    assert_eq!(prefunded.statement.claimant.as_ref(), Some(&claimant));
    assert!(quil_lattice_ct::confidential::relation::backend::native::verify_owned(
        prefunded.statement.public_relation(limits).unwrap(), &prefunded.proof, budget).unwrap());
    let entry = quil_execution::token_intrinsic::settlement_record::operation_entry(&bytes).unwrap().unwrap();
    assert_eq!((entry.context, entry.claimant), ([0; 32],
        quil_execution::token_intrinsic::settlement_record::claimant_address(claimant.key_type, &claimant.public_key).unwrap()));
    stop.send(()).unwrap(); serving.await.unwrap();
    eprintln!("wallet_settlement bytes={} proof_bytes={} native_verified=true seconds={:.3}",
        bytes.len(), tx.proof.len(), started.elapsed().as_secs_f64());
}

use super::*;
use quil_types::store::{CoinWitnessProvider, RewardWitnessData};
use std::sync::{Arc, Mutex};

struct Rewards {
    owner: [u8; 32],
    witness: Mutex<RewardWitnessData>,
}
impl CoinWitnessProvider for Rewards {
    fn prover_reward_witness(
        &self,
        domain: &[u8],
        owner: &[u8],
    ) -> quil_types::error::Result<RewardWitnessData> {
        assert_eq!(domain, quil_execution::domains::QUIL_TOKEN);
        assert_eq!(owner, self.owner);
        Ok(self.witness.lock().unwrap().clone())
    }
}

// Build a real GLOBAL membership proof, including a genuine zero-valued
// record. No signing, native proving or token submission is involved.
fn reward_witness(owner: [u8; 32], amount: u128) -> RewardWitnessData {
    use quil_execution::{
        global_schema,
        hypergraph_state::{vertex_adds_discriminator, HypergraphState},
    };
    use quil_hypergraph::addressing::{shard_key_for_location, Location};
    let directory = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(directory.path()).unwrap();
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
        Arc::new(quil_types::crypto::NoopInclusionProver),
    ));
    crdt.set_forest(quil_forest::Forest::new(db.inner()));
    let state = HypergraphState::new(crdt.clone());
    let address = quil_execution::global_intrinsic::materialize::reward_address(&owner).unwrap();
    let mut tree = quil_tries::VectorCommitmentTree::new();
    global_schema::write_type(&mut tree, "reward:ProverReward").unwrap();
    global_schema::write_field(&mut tree, "reward:ProverReward", "DelegateAddress", &owner)
        .unwrap();
    let mut balance = [0; 32];
    balance[16..].copy_from_slice(&amount.to_be_bytes());
    global_schema::write_field(&mut tree, "reward:ProverReward", "Balance", &balance).unwrap();
    let global = quil_execution::domains::GLOBAL;
    state
        .set(
            &global,
            &address,
            &vertex_adds_discriminator().unwrap(),
            1,
            quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
        )
        .unwrap();
    state.commit().unwrap();
    crdt.commit(1).unwrap();
    let root = crdt.compute_shard_root(
        "vertex",
        "adds",
        &shard_key_for_location(&Location {
            app_address: global,
            data_address: address,
        }),
    );
    let root: [u8; 32] = root.try_into().unwrap();
    let membership = crdt
        .global_vertex_membership_at_root(&root, &address)
        .unwrap()
        .unwrap();
    RewardWitnessData {
        found: true,
        value: amount,
        cited_frame: 42,
        reward_root: root.to_vec(),
        forest_proof: quil_forest::MembershipProof {
            inputs: vec![membership],
        }
        .to_bytes(),
    }
}

#[tokio::test]
async fn claimable_rewards_are_read_without_coin_scan_and_check_membership() {
    use quil_types::crypto::Signer;
    let signer = quil_crypto::FalconSigner::generate();
    let public = signer.public_key();
    let owner = quil_crypto::poseidon::hash_bytes_to_32(&public).unwrap();
    let provider = Arc::new(Rewards {
        owner,
        witness: Mutex::new(reward_witness(owner, u128::MAX)),
    });
    // No coin-page provider: reward discovery succeeds without one.
    let server =
        quil_rpc::node_service::NodeRpcServer::new().with_coin_witness_provider(provider.clone());
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
    let client = NodeServiceClient::new(channel);
    let value = read_claimable_rewards(client.clone(), &public)
        .await
        .unwrap();
    assert_eq!(value, Some((u128::MAX, 42)));
    let display = format_claimable_rewards(Ok(value));
    assert!(
        display.contains("42535295865117307932921825928.971026431875 QUIL"),
        "{display}"
    );
    assert!(display.contains("global frame 42; requires minting"));

    // A server that alters the amount or root cannot claim that balance.
    provider.witness.lock().unwrap().value -= 1;
    assert!(read_claimable_rewards(client.clone(), &public)
        .await
        .is_err());
    *provider.witness.lock().unwrap() = reward_witness(owner, 0);
    let zero = read_claimable_rewards(client.clone(), &public)
        .await
        .unwrap();
    assert_eq!(zero, Some((0, 42)));
    assert!(format_claimable_rewards(Ok(zero)).contains("0.000000000000 QUIL"));
    provider.witness.lock().unwrap().reward_root[0] ^= 1;
    assert!(read_claimable_rewards(client.clone(), &public)
        .await
        .is_err());
    *provider.witness.lock().unwrap() = RewardWitnessData::default();
    let missing = read_claimable_rewards(client.clone(), &public)
        .await
        .unwrap();
    assert_eq!(missing, None);
    assert!(format_claimable_rewards(Ok(missing)).contains("unavailable"));
    assert!(read_claimable_rewards(client, &[1; 57]).await.is_err());
    stop.send(()).unwrap();
    serving.await.unwrap();
}

#[test]
fn claimable_rewards_report_rpc_failure_as_unavailable() {
    let display = format_claimable_rewards(Err(tonic::Status::unavailable(
        "reward history unavailable",
    )
    .into()));
    assert!(display.contains("Claimable prover rewards: unavailable"));
    assert!(display.contains("reward history unavailable"));
    assert!(!display.contains("0.000000000000 QUIL"));
}

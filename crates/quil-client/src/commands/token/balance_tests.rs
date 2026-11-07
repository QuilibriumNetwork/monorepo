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
pub(crate) fn reward_witness(owner: [u8; 32], amount: u128) -> RewardWitnessData {
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
    let display = format_claimable_rewards(Ok(value), false);
    assert_eq!(
        display,
        "Claimable rewards: 42535295865117307932921825928.971026 QUIL, mint to claim"
    );
    let display = format_claimable_rewards(Ok(value), true);
    assert!(
        display.contains("42535295865117307932921825928.971026431875 QUIL"),
        "{display}"
    );
    assert!(display.contains("witness cites global frame 42), mint to claim"));

    // A server that alters the amount or root cannot claim that balance.
    provider.witness.lock().unwrap().value -= 1;
    assert!(read_claimable_rewards(client.clone(), &public)
        .await
        .is_err());
    *provider.witness.lock().unwrap() = reward_witness(owner, 0);
    let zero = read_claimable_rewards(client.clone(), &public).await;
    assert!(
        zero.is_err(),
        "mint witnesses cannot authenticate zero-valued claims"
    );
    assert!(format_claimable_rewards(zero, false).contains("unavailable"));
    *provider.witness.lock().unwrap() = reward_witness(owner, 1);
    provider.witness.lock().unwrap().reward_root[0] ^= 1;
    assert!(read_claimable_rewards(client.clone(), &public)
        .await
        .is_err());
    *provider.witness.lock().unwrap() = RewardWitnessData::default();
    let missing = read_claimable_rewards(client.clone(), &public)
        .await
        .unwrap();
    assert_eq!(missing, None);
    assert_eq!(
        format_claimable_rewards(Ok(missing), false),
        "Claimable rewards: none"
    );
    assert!(read_claimable_rewards(client, &[1; 57]).await.is_err());
    stop.send(()).unwrap();
    serving.await.unwrap();
}

/// A failed read's line says only "unavailable": the command's error gives
/// the reason, once.
#[test]
fn claimable_rewards_report_rpc_failure_as_unavailable() {
    for verbose in [false, true] {
        let display = format_claimable_rewards(
            Err(tonic::Status::unavailable("reward history unavailable").into()),
            verbose,
        );
        assert_eq!(display, "Claimable rewards: unavailable");
    }
}

/// #698: `token balance` shows every section. A network with no
/// confidential coin yet has no QUIL root, which is one plain line, not an
/// error. By default each line is the fact alone, in QUIL.
#[test]
fn balance_lines_show_the_fact_alone_by_default() {
    let lines = |verbose| {
        [
            format_confidential_coins(&Ok(None), true, verbose),
            format_confidential_coins(&Ok(None), false, verbose),
            format_confidential_coins(&Ok(Some((25, 2))), true, verbose),
            format_confidential_coins(&Ok(Some((25, 1))), false, verbose),
            format_legacy_coins(&Ok(Some((7, 2, 1))), verbose),
            format_legacy_coins(&Ok(None), verbose),
            // An empty listing is an answer, apart from "unavailable".
            format_legacy_coins(&Ok(Some((0, 0, 0))), verbose),
            format_legacy_coins(&Ok(Some((0, 0, 3))), verbose),
            format_legacy_coins(&Err(anyhow::anyhow!("no archive answered")), verbose),
            format_confidential_coins(&Err(anyhow::anyhow!("dial failed")), true, verbose),
        ]
    };
    assert_eq!(
        lines(false),
        [
            "Confidential QUIL coins: none",
            "Confidential coins: none",
            "Confidential QUIL coins: 0.000000003125 QUIL in 2 coins",
            "Confidential coins: 25 base units in 1 coin",
            "Unshielded legacy coins: 0.000000000875 QUIL in 2 coins, shield to spend",
            "Unshielded legacy coins: none",
            "Unshielded legacy coins: none",
            "Unshielded legacy coins: none",
            "Unshielded legacy coins: unavailable",
            "Confidential coins: unavailable",
        ]
    );
}

/// `-v` keeps what each line derives from: base units, the shielded count,
/// why there is none, and that the node's word is not finality.
#[test]
fn balance_lines_keep_their_detail_under_verbose() {
    let unspent = "reported unspent by the configured node (not a finalized balance)";
    assert_eq!(
        [
            format_confidential_coins(&Ok(None), true, true),
            format_confidential_coins(&Ok(None), false, true),
            format_confidential_coins(&Ok(Some((25, 2))), true, true),
            format_confidential_coins(&Ok(Some((25, 1))), false, true),
            format_legacy_coins(&Ok(Some((7, 2, 1))), true),
            format_legacy_coins(&Ok(None), true),
            format_legacy_coins(&Ok(Some((0, 0, 0))), true),
            format_legacy_coins(&Ok(Some((0, 0, 3))), true),
        ],
        [
            "Confidential QUIL coins: none (no QUIL root published on the network yet)".to_string(),
            "Confidential coins: none (no root published in this application yet)".into(),
            format!(
                "Confidential QUIL coins: 0.000000003125 QUIL (25 base units) in 2 coins {unspent}"
            ),
            format!("Confidential coins: 25 base units in 1 coin {unspent}"),
            "Unshielded legacy coins: 0.000000000875 QUIL (7 base units) in 2 coins (1 already \
             shielded), shield to spend"
                .into(),
            "Unshielded legacy coins: none (this node has no Ed448 identity)".into(),
            "Unshielded legacy coins: none (the listing has no coin under this identity's key or \
             peer-id owner)"
                .into(),
            "Unshielded legacy coins: none left (3 already shielded)".into(),
        ]
    );
}

/// Reads failing for one reason name it once; different reasons each
/// follow the reads they failed.
#[test]
fn an_incomplete_balance_names_each_reason_once() {
    let key = r#"not found: no key with id "q-prover-key""#.to_string();
    assert_eq!(
        incomplete(&[
            ("claimable rewards", key.clone()),
            ("confidential coins", key.clone())
        ]),
        format!("balance incomplete: claimable rewards, confidential coins unavailable: {key}")
    );
    assert_eq!(
        incomplete(&[
            ("claimable rewards", key.clone()),
            ("legacy coins", "no archive answered".into()),
            ("confidential coins", key.clone()),
        ]),
        format!(
            "balance incomplete: claimable rewards, confidential coins unavailable: {key}; \
             legacy coins unavailable: no archive answered"
        )
    );
}

/// Six decimals at most, trailing zeros dropped, half up; an amount below
/// that shows exactly rather than as zero.
#[test]
fn quil_amounts_read_briefly() {
    let quil = 8_000_000_000u128;
    assert_eq!(quil_brief(0), "0");
    assert_eq!(quil_brief(quil), "1");
    assert_eq!(quil_brief(quil * 49 / 4), "12.25");
    // 32.942335453750 QUIL
    assert_eq!(quil_brief(263_538_683_630), "32.942335");
    // 0.9999996 QUIL rounds up to a whole QUIL.
    assert_eq!(quil_brief(quil - 3_200), "1");
    assert_eq!(quil_brief(17_659), "0.000002");
    assert_eq!(quil_brief(8), "0.000000001");
    assert_eq!(quil_brief(1), "0.000000000125");
}

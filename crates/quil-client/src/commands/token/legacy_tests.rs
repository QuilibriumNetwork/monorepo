use super::*;
use quil_types::store::{CoinWitnessProvider, LegacyCoinData, LegacyCoinPageData};
use std::sync::Arc;

/// Synthetic Ed448 public keys: the owner derivations hash bytes only.
const KEY_X: [u8; 57] = [1; 57];
const KEY_Y: [u8; 57] = [2; 57];
const KEY_Z: [u8; 57] = [3; 57];

fn node(multiaddr: &str) -> ReadNode {
    ReadNode {
        opts: ConnectOpts {
            public_rpc: false,
            custom_rpc: String::new(),
            listen_grpc_multiaddr: multiaddr.to_string(),
        },
        source: NodeSource::ReadRpc,
    }
}

fn no_node() -> ReadNode {
    node("/ip4/127.0.0.1/tcp/1")
}

/// The owner addresses a shield's admission accepts for a signing key, as
/// `shield::check_sources` derives them, independently of `key_owners`.
fn admitted_owners(public: &[u8; 57]) -> [[u8; 32]; 2] {
    let peer = quil_crypto::peer_id_multihash_from_ed448_pubkey(public);
    [
        quil_crypto::poseidon::hash_bytes_to_32(public).unwrap(),
        quil_crypto::poseidon::hash_bytes_to_32(&peer).unwrap(),
    ]
}

/// A config's peerPrivKey: a synthetic seed, then the public key.
fn peer_priv_key(public: &[u8; 57]) -> String {
    let mut key = vec![0x77; 57];
    key.extend_from_slice(public);
    hex::encode(key)
}

#[test]
fn owner_forms_of_a_key_a_config_and_a_peer_id_match_what_a_shield_admits() {
    let [by_key, by_peer] = admitted_owners(&KEY_X);
    assert_ne!(by_key, by_peer);
    assert_eq!(
        key_owners(&KEY_X).unwrap(),
        vec![(OwnerForm::Key, by_key), (OwnerForm::PeerId, by_peer)]
    );

    // --ed448-pub, with or without 0x.
    assert_eq!(parse_ed448_pub(&hex::encode(KEY_X)).unwrap(), KEY_X);
    assert_eq!(
        parse_ed448_pub(&format!("0x{}", hex::encode(KEY_X))).unwrap(),
        KEY_X
    );
    // A pasted peerPrivKey is refused without echoing it.
    let private = peer_priv_key(&KEY_X);
    let error = parse_ed448_pub(&private).unwrap_err().to_string();
    assert!(error.contains("57-byte public key"), "{error}");
    assert!(!error.contains(&private[..20]), "{error}");
    assert!(parse_ed448_pub("00").is_err());
    assert!(parse_ed448_pub("zz").is_err());

    // A config's peerPrivKey gives the same key; the node's own peer ID
    // bytes give the same peer-id form.
    assert_eq!(config_public_key(&private), Some(KEY_X));
    assert_eq!(config_public_key(""), None);
    assert_eq!(config_public_key(&private[..226]), None);
    let identity = quil_p2p::ed448_identity::Ed448Identity::from_config_hex(&private).unwrap();
    assert_eq!(
        quil_crypto::poseidon::hash_bytes_to_32(&identity.peer_id_bytes).unwrap(),
        by_peer
    );

    // --peer-id: the peer-id form only, with a note saying so.
    let base58 = identity.peer_id_base58();
    let (multihash, shown) = parse_peer_id(&base58).unwrap();
    assert_eq!(
        (multihash.clone(), shown.clone()),
        (identity.peer_id_bytes.clone(), base58.clone())
    );
    assert_eq!(embedded_ed448_key(&multihash), None, "a SHA2-256 peer ID");
    let args = LegacyArgs {
        peer_id: vec![base58.clone()],
        ..LegacyArgs::default()
    };
    let keyed = keyed_identities(&args, no_node).unwrap();
    assert_eq!(keyed.len(), 1);
    assert_eq!(keyed[0].owners, Ok(vec![(OwnerForm::PeerId, by_peer)]));
    assert_eq!(
        keyed[0].peer_tail.as_deref(),
        Some(&base58[base58.len() - 6..])
    );
    assert!(keyed[0]
        .note
        .as_deref()
        .is_some_and(|note| note.contains("only the peer-id owner form")));
    assert!(parse_peer_id("not-a-peer-id").is_err());

    // An identity multihash embedding an Ed448 key would give both forms.
    let mut embedded = vec![0x00, 61, 0x08, 0x04, 0x12, 57];
    embedded.extend_from_slice(&KEY_X);
    assert_eq!(embedded_ed448_key(&embedded), Some(KEY_X));
    embedded[1] = 60;
    assert_eq!(embedded_ed448_key(&embedded), None);

    // --owner.
    let owner = format!("0x{}", hex::encode(by_key));
    assert_eq!(parse_owner(&owner).unwrap(), by_key);
    assert_eq!(parse_owner(&hex::encode(by_key)).unwrap(), by_key);
    assert!(parse_owner("0x00").is_err());
    let args = LegacyArgs {
        ed448_pub: vec![hex::encode(KEY_X), hex::encode(KEY_Y)],
        owner: vec![owner],
        ..LegacyArgs::default()
    };
    let keyed = keyed_identities(&args, no_node).unwrap();
    let labels: Vec<&str> = keyed
        .iter()
        .map(|identity| identity.label.as_str())
        .collect();
    assert_eq!(labels[..2], ["ed448-pub #1", "ed448-pub #2"]);
    assert!(labels[2].starts_with("owner 0x"), "{labels:?}");
    assert_eq!(keyed[0].owners, Ok(key_owners(&KEY_X).unwrap()));
    assert_eq!(keyed[2].owners, Ok(vec![(OwnerForm::Address, by_key)]));
    // One malformed value fails the command before anything is asked.
    let args = LegacyArgs {
        ed448_pub: vec![hex::encode(KEY_X), "00".into()],
        ..LegacyArgs::default()
    };
    assert!(keyed_identities(&args, no_node).is_err());
}

fn context() -> Context {
    Context {
        global: GlobalArgs {
            network: None,
            yes: false,
        },
        client_config: crate::config::ClientConfig {
            data_dir: String::new(),
            symlink_path: String::new(),
            public_rpc: false,
            custom_rpc: String::new(),
            node_symlink_name: String::new(),
        },
    }
}

fn write_config(dir: &Path, public: Option<&[u8; 57]>, listener: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let mut yaml = format!(
        "listenGrpcMultiaddr: {listener}\nkey:\n  keyManagerFile:\n    path: .config/keys.yml\n"
    );
    if let Some(public) = public {
        yaml.push_str(&format!("p2p:\n  peerPrivKey: {}\n", peer_priv_key(public)));
    }
    std::fs::write(dir.join("config.yml"), yaml).unwrap();
}

/// Configs are read for their Ed448 public key alone: a missing, garbled
/// or foreign keys.yml does not matter. A missing config is an unavailable
/// identity, and nothing is created for it.
#[test]
fn configs_and_configs_under_give_identities_without_reading_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let nodes = tmp.path().join("nodes");
    write_config(
        &nodes.join("alpha").join(".config"),
        Some(&KEY_X),
        "/ip4/127.0.0.1/tcp/8889",
    );
    write_config(
        &nodes.join("beta").join(".config"),
        None,
        "/ip4/127.0.0.1/tcp/8890",
    );
    std::fs::write(
        nodes.join("beta").join(".config").join("keys.yml"),
        "not: [a keystore",
    )
    .unwrap();
    write_config(
        &nodes.join(".config"),
        Some(&KEY_Y),
        "/ip4/127.0.0.1/tcp/8891",
    );
    std::fs::create_dir_all(nodes.join("gamma")).unwrap();
    let missing = tmp.path().join("missing").join(".config");

    let ctx = context();
    let choice = NodeChoice {
        ctx: &ctx,
        public_rpc: false,
        read_rpc: None,
        default: None,
    };
    let args = LegacyArgs {
        configs_under: vec![nodes.clone()],
        ..LegacyArgs::default()
    };
    let found = identities(&choice, &[missing.display().to_string()], &args).unwrap();
    let labels: Vec<&str> = found
        .iter()
        .map(|identity| identity.label.as_str())
        .collect();
    assert_eq!(
        labels,
        [
            missing.display().to_string().as_str(),
            "nodes",
            "alpha",
            "beta"
        ]
    );
    assert!(found[0]
        .owners
        .as_ref()
        .is_err_and(|error| error.contains("holds no config.yml")));
    assert!(!tmp.path().join("missing").exists(), "a config was created");
    assert_eq!(found[1].owners, Ok(key_owners(&KEY_Y).unwrap()));
    assert_eq!(found[2].owners, Ok(key_owners(&KEY_X).unwrap()));
    assert_eq!(found[3].owners, Ok(Vec::new()), "no Ed448 key");
    // Each config is read from its own node, named by its config.
    assert_eq!(found[2].node.multiaddr(), "/ip4/127.0.0.1/tcp/8889");
    assert_eq!(
        found[2].node.source,
        NodeSource::Config(nodes.join("alpha").join(".config"))
    );
    assert_eq!(
        found[2].config_arg.as_deref(),
        Some(nodes.join("alpha").join(".config").to_str().unwrap())
    );
    assert_eq!(found[2].peer_tail, key_tail(&KEY_X));

    // --read-rpc overrides every config's node.
    let choice = NodeChoice {
        read_rpc: Some(node("/ip4/127.0.0.1/tcp/8888").opts),
        ..choice
    };
    let found = identities(&choice, &[], &args).unwrap();
    assert!(found
        .iter()
        .all(|identity| identity.node.source == NodeSource::ReadRpc));

    // A directory with no node config is refused.
    assert!(configs_under(&nodes.join("gamma")).is_err());
    assert!(configs_under(&tmp.path().join("absent")).is_err());
}

/// Two identities with one key count once; an identity that cannot be read
/// or whose node does not answer leaves the others listed; an owner whose
/// first listing failed is asked again.
#[test]
fn dedup_counts_an_owner_once_and_only_after_it_was_listed() {
    let a = Identity::keyed("a".into(), None, key_owners(&KEY_X).unwrap(), no_node());
    let b = Identity::keyed("b".into(), None, key_owners(&KEY_X).unwrap(), no_node());
    let [_, x_peer] = admitted_owners(&KEY_X);
    let partial = Identity::keyed(
        "partial".into(),
        None,
        vec![(OwnerForm::Address, x_peer), (OwnerForm::Address, [9; 32])],
        no_node(),
    );
    let mut dedup = Dedup::default();
    assert!(matches!(dedup.plan(&a), Plan::Ask(owners, None) if owners.len() == 2));
    // `a` not listed yet (say its node failed): `b` is still asked.
    assert!(matches!(dedup.plan(&b), Plan::Ask(_, None)));
    dedup.record(&key_owners(&KEY_X).unwrap(), "a");
    assert_eq!(dedup.plan(&b), Plan::Duplicate("a".into()));
    match dedup.plan(&partial) {
        Plan::Ask(owners, Some(note)) => {
            assert_eq!(owners, vec![(OwnerForm::Address, [9; 32])]);
            assert!(note.contains("listed for a"), "{note}");
        }
        other => panic!("{other:?}"),
    }
    let failed = Identity {
        owners: Err("unreadable".into()),
        ..Identity::keyed("f".into(), None, Vec::new(), no_node())
    };
    assert_eq!(dedup.plan(&failed), Plan::Failed("unreadable".into()));
    let keyless = Identity::keyed("k".into(), None, Vec::new(), no_node());
    assert_eq!(dedup.plan(&keyless), Plan::NoKey);
}

/// A legacy owner index serving pages of two coins.
struct Index(HashMap<[u8; 32], Vec<LegacyCoinData>>);

impl CoinWitnessProvider for Index {
    fn legacy_coins(
        &self,
        _domain: &[u8; 32],
        owner: &[u8; 32],
        after: Option<&[u8; 32]>,
    ) -> quil_types::error::Result<Option<LegacyCoinPageData>> {
        let mut coins: Vec<LegacyCoinData> = self
            .0
            .get(owner)
            .into_iter()
            .flatten()
            .filter(|coin| after.map_or(true, |after| coin.address > *after))
            .cloned()
            .collect();
        let has_more = coins.len() > 2;
        coins.truncate(2);
        Ok(Some(LegacyCoinPageData {
            cursor: coins.last().map(|coin| coin.address),
            coins,
            has_more,
        }))
    }
}

/// A node without the owner index and no archive to ask.
struct NoIndex;
impl CoinWitnessProvider for NoIndex {}

async fn serve(
    provider: Arc<dyn CoinWitnessProvider>,
) -> (
    String,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let server = quil_rpc::node_service::NodeRpcServer::new().with_coin_witness_provider(provider);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let multiaddr = format!(
        "/ip4/127.0.0.1/tcp/{}",
        listener.local_addr().unwrap().port()
    );
    let incoming = futures::stream::unfold(listener, |listener| async {
        let result = listener.accept().await.map(|(socket, _)| socket);
        Some((result, listener))
    });
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(async move {
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
    (multiaddr, stop, serving)
}

fn legacy_coin(byte: u8, amount: u128, shielded: bool) -> LegacyCoinData {
    LegacyCoinData {
        address: [byte; 32],
        amount,
        origin: [byte ^ 0xff; 32],
        shielded,
    }
}

/// Over loopback gRPC: paging, both owner forms, "none" apart from
/// "unavailable", one key read twice counted once, and one failing
/// identity leaving the rest listed.
#[tokio::test]
async fn identities_are_listed_paged_deduplicated_and_kept_apart_on_failure() {
    let [x_key, x_peer] = admitted_owners(&KEY_X);
    let quil = 8_000_000_000u128;
    let index = Index(HashMap::from([
        (
            x_key,
            vec![
                legacy_coin(0x10, quil, false),
                legacy_coin(0x20, 2 * quil, true),
                legacy_coin(0x30, quil / 2, false),
            ],
        ),
        (x_peer, vec![legacy_coin(0x40, 5, false)]),
    ]));
    let (good, stop_good, serving_good) = serve(Arc::new(index)).await;
    let (bare, stop_bare, serving_bare) = serve(Arc::new(NoIndex)).await;

    let identities = vec![
        Identity::keyed("a".into(), None, key_owners(&KEY_X).unwrap(), node(&good)),
        Identity::keyed("b".into(), None, key_owners(&KEY_X).unwrap(), node(&good)),
        Identity::keyed("c".into(), None, key_owners(&KEY_Y).unwrap(), node(&good)),
        Identity::keyed("d".into(), None, key_owners(&KEY_Z).unwrap(), node(&bare)),
        Identity {
            owners: Err("no config.yml".into()),
            ..Identity::keyed("e".into(), None, Vec::new(), node(&good))
        },
        Identity::keyed("f".into(), None, Vec::new(), node(&good)),
        // The key whose listing failed at `d` is asked again.
        Identity::keyed("g".into(), None, key_owners(&KEY_Z).unwrap(), node(&good)),
    ];
    let application = quil_execution::domains::QUIL_TOKEN;
    let report = list_all(identities, &application, None, String::new()).await;
    let statuses: Vec<&str> = report.rows.iter().map(|row| row.outcome.status()).collect();
    assert_eq!(
        statuses,
        [
            "listed",
            "duplicate",
            "none",
            "unavailable",
            "unavailable",
            "no_key",
            "none"
        ]
    );
    let Outcome::Listed(coins) = &report.rows[0].outcome else {
        unreachable!()
    };
    let listed: Vec<([u8; 32], OwnerForm, bool)> = coins
        .iter()
        .map(|coin| (coin.address, coin.form, coin.shielded))
        .collect();
    assert_eq!(
        listed,
        [
            ([0x10; 32], OwnerForm::Key, false),
            ([0x20; 32], OwnerForm::Key, true),
            ([0x30; 32], OwnerForm::Key, false),
            ([0x40; 32], OwnerForm::PeerId, false),
        ],
        "both forms, across pages"
    );
    assert_eq!(report.rows[1].outcome, Outcome::Duplicate("a".into()));
    let Outcome::Unavailable(error) = &report.rows[3].outcome else {
        unreachable!()
    };
    assert!(error.contains("keeps no legacy coin index"), "{error}");

    let totals = report.totals().unwrap();
    assert_eq!(
        totals.tally,
        Tally {
            units: quil + quil / 2 + 5,
            unshielded: 3,
            shielded: 1,
        }
    );
    assert_eq!(
        (
            totals.listed,
            totals.none,
            totals.no_key,
            totals.unavailable,
            totals.duplicates
        ),
        (1, 2, 1, 2, 1)
    );
    let error = report.result().unwrap_err().to_string();
    assert!(error.contains("2 of 7 identities: d, e"), "{error}");

    let text = report.text(false).unwrap();
    assert!(
        text.contains(&format!(
            "0x{} 1.000000000000 QUIL (8000000000 base units, key owner)",
            hex::encode([0x10; 32])
        )),
        "{text}"
    );
    assert!(
        text.contains(&format!("0x{} ", hex::encode([0x20; 32]))),
        "{text}"
    );
    assert!(text.contains("key owner, shielded)"), "{text}");
    assert!(text.contains("peer-id owner)"), "{text}");
    assert!(text.contains("same owners as a: counted once"), "{text}");
    assert!(
        text.contains("none: the listing has no coin for it"),
        "{text}"
    );
    assert!(
        text.contains("unavailable: legacy coins: this node keeps no legacy coin index"),
        "{text}"
    );
    assert!(text.contains("none: config.yml has no Ed448 key"), "{text}");
    assert!(
        text.contains("4 of 7 identities listed; 2 unavailable"),
        "{text}"
    );
    let summary = report.text(true).unwrap();
    assert!(!summary.contains(&hex::encode([0x10; 32])), "{summary}");
    assert!(summary.contains("1.500000000625"), "{summary}");

    stop_good.send(()).unwrap();
    stop_bare.send(()).unwrap();
    serving_good.await.unwrap();
    serving_bare.await.unwrap();
}

/// One identity: an empty listing reads "none", which is not an error.
#[tokio::test]
async fn a_single_identity_with_no_coins_reads_none() {
    let (good, stop, serving) = serve(Arc::new(Index(HashMap::new()))).await;
    let identities = vec![Identity::keyed(
        "solo".into(),
        None,
        key_owners(&KEY_Y).unwrap(),
        node(&good),
    )];
    let report = list_all(
        identities,
        &quil_execution::domains::QUIL_TOKEN,
        None,
        String::new(),
    )
    .await;
    assert!(report.result().is_ok());
    let text = report.text(false).unwrap();
    assert_eq!(
        text,
        "Legacy coins: none (the listing has no coin under the key or peer-id owners)\n"
    );
    stop.send(()).unwrap();
    serving.await.unwrap();
}

fn listed_row(config_arg: Option<&str>, coins: Vec<Coin>, plan: Option<ShieldPlan>) -> Row {
    Row {
        identity: Identity {
            config_dir: config_arg.map(PathBuf::from),
            config_arg: config_arg.map(str::to_string),
            network: Some(0),
            ..Identity::keyed(
                "alpha".into(),
                Some("a1b2c3".into()),
                key_owners(&KEY_X).unwrap(),
                no_node(),
            )
        },
        outcome: Outcome::Listed(coins),
        note: None,
        plan,
    }
}

/// The JSON schema: its keys, and amounts as strings.
#[test]
fn json_output_follows_the_documented_schema() {
    let coins = vec![
        Coin {
            address: [0x10; 32],
            amount: u128::MAX / 2,
            shielded: false,
            form: OwnerForm::Key,
        },
        Coin {
            address: [0x20; 32],
            amount: 3,
            shielded: true,
            form: OwnerForm::PeerId,
        },
    ];
    let plan = ShieldPlan {
        batches: 1,
        exact: true,
        outside: 0,
    };
    let report = Report {
        network: 0,
        head: Ok(943_000),
        rule: Some(ShieldRule {
            shield_from: 943_920,
            shield_all_from: 943_920,
        }),
        rows: vec![
            listed_row(Some("/srv/node one/.config"), coins, Some(plan)),
            Row {
                outcome: Outcome::Unavailable("cannot reach the node".into()),
                ..listed_row(None, Vec::new(), None)
            },
        ],
        read_args: String::new(),
    };
    let json = report.json(false).unwrap();
    let keys = |value: &serde_json::Value| -> Vec<String> {
        let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        keys
    };
    assert_eq!(
        keys(&json),
        [
            "global_head_error",
            "global_head_frame",
            "identities",
            "network",
            "schema",
            "shield",
            "total"
        ]
    );
    assert_eq!(json["schema"], JSON_SCHEMA);
    assert_eq!(json["global_head_frame"], 943_000);
    assert!(json["global_head_error"].is_null());
    assert_eq!(
        json["shield"],
        serde_json::json!({
            "shield_from_frame": 943_920,
            "shield_all_from_frame": 943_920,
            "active": false
        })
    );
    let identity = &json["identities"][0];
    assert_eq!(
        keys(identity),
        [
            "coins",
            "config_dir",
            "duplicate_of",
            "error",
            "label",
            "next_command",
            "note",
            "outside_live_shards",
            "owners",
            "peer_id_tail",
            "shield_batches",
            "shield_batches_exact",
            "shielded_count",
            "status",
            "unshielded_base_units",
            "unshielded_count",
            "unshielded_quil"
        ]
    );
    assert_eq!(identity["status"], "listed");
    assert_eq!(identity["peer_id_tail"], "a1b2c3");
    assert_eq!(identity["owners"][1]["form"], "peer_id");
    assert_eq!(
        identity["unshielded_base_units"],
        (u128::MAX / 2).to_string()
    );
    assert_eq!(identity["unshielded_count"], 1);
    assert_eq!(identity["shielded_count"], 1);
    assert_eq!(
        identity["coins"][1],
        serde_json::json!({
            "address": format!("0x{}", hex::encode([0x20; 32])),
            "base_units": "3",
            "quil": "0.000000000375",
            "owner_form": "peer_id",
            "shielded": true
        })
    );
    assert_eq!(identity["shield_batches"], 1);
    assert_eq!(
        identity["next_command"],
        "qclient token shield-all --config '/srv/node one/.config'"
    );
    let failed = &json["identities"][1];
    assert_eq!(failed["status"], "unavailable");
    assert_eq!(failed["error"], "cannot reach the node");
    assert!(failed["next_command"].is_null() && failed["shield_batches"].is_null());
    assert_eq!(json["total"]["unavailable"], 1);
    assert_eq!(
        json["total"]["unshielded_base_units"],
        (u128::MAX / 2).to_string()
    );
    // --summary drops the coins, not the counts.
    let summary = report.json(true).unwrap();
    assert_eq!(summary["identities"][0]["coins"], serde_json::json!([]));
    assert_eq!(summary["identities"][0]["unshielded_count"], 1);
}

/// Shield readiness and the next command, before and after the frame.
#[test]
fn shield_readiness_names_the_frame_and_the_next_command() {
    let coins = vec![Coin {
        address: [0x10; 32],
        amount: 8_000_000_000,
        shielded: false,
        form: OwnerForm::Key,
    }];
    let common = TokenCommonArgs {
        public_rpc: false,
        config: Vec::new(),
        read_rpc: Some("/ip4/127.0.0.1/tcp/8888".into()),
        insecure_read_rpc: false,
        max_fee: 0,
    };
    let mut report = Report {
        network: 0,
        head: Ok(943_000),
        rule: Some(ShieldRule {
            shield_from: 943_920,
            shield_all_from: 943_920,
        }),
        rows: vec![listed_row(
            Some("/srv/alpha/.config"),
            coins,
            Some(ShieldPlan {
                batches: 1,
                exact: false,
                outside: 0,
            }),
        )],
        read_args: read_args(&common),
    };
    let text = report.text(false).unwrap();
    if BATCH_SHIELDS.is_some() {
        assert!(
            text.contains(
                "Shielding: not yet: shields of these coins are admitted from GLOBAL frame \
                 943,920; the GLOBAL head is 943,000 (920 frames to go)"
            ),
            "{text}"
        );
        assert!(
            text.contains("Shield plan: at least 1 shield-all batch for 1 unshielded coin"),
            "{text}"
        );
        assert!(
            text.contains(
                "Next, from GLOBAL frame 943,920: qclient token shield-all --config \
                 /srv/alpha/.config --read-rpc /ip4/127.0.0.1/tcp/8888"
            ),
            "{text}"
        );
    }
    report.head = Ok(943_920);
    let text = report.text(false).unwrap();
    if BATCH_SHIELDS.is_some() {
        assert!(text.contains("Shielding: active"), "{text}");
        assert!(text.contains("\nNext: qclient token shield-all"), "{text}");
    }
    report.head = Err("node info: unimplemented".into());
    let json = report.json(false).unwrap();
    assert!(json["shield"]["active"].is_null());
    assert_eq!(json["global_head_error"], "node info: unimplemented");
}

#[test]
fn mainnet_shields_wait_for_the_migrated_owner_frame() {
    if BATCH_SHIELDS.is_none() {
        assert_eq!(shield_rule(0), None);
        return;
    }
    assert_eq!(
        shield_rule(0),
        Some(ShieldRule {
            shield_from: 943_920,
            shield_all_from: 943_920,
        })
    );
    assert_eq!(shield_rule(1), None, "node settings elsewhere");
}

/// `token legacy`'s batch count is the batches `shield-all` cuts.
#[cfg(feature = "confidential-tokens")]
#[test]
fn batch_counts_match_what_shield_all_submits() {
    let coin = |top: u8, n: u8| {
        let mut address = [n; 32];
        address[0] = top;
        (address, u128::from(n) + 1)
    };
    let coins = vec![
        coin(0x10, 1),
        coin(0x20, 2),
        coin(0x30, 3),
        coin(0x90, 4),
        coin(0xa0, 5),
        coin(0xc0, 6),
        coin(0xd0, 7),
        coin(0xd0, 7),
    ];
    let addresses: Vec<[u8; 32]> = coins.iter().map(|(address, _)| *address).collect();
    for shards in [
        vec![vec![false], vec![true], vec![true, false], vec![true, true]],
        vec![vec![false]],
        Vec::new(),
    ] {
        for max in [1, 2, 96] {
            let (batches, uncovered) =
                super::super::wallet::shield_batches(coins.clone(), &shards, max);
            assert_eq!(
                count_batches(&addresses, &shards, max),
                (batches.len(), uncovered.len()),
                "{shards:?} {max}"
            );
        }
    }
    // Without the shard list, the plan says so and counts at least one batch
    // per 96 coins.
    let many: Vec<Coin> = (0..200u16)
        .map(|n| Coin {
            address: {
                let mut address = [0; 32];
                address[..2].copy_from_slice(&n.to_be_bytes());
                address
            },
            amount: 1,
            shielded: false,
            form: OwnerForm::Key,
        })
        .collect();
    assert_eq!(
        shield_plan(&many, None),
        Some(ShieldPlan {
            batches: 3,
            exact: false,
            outside: 0,
        })
    );
    assert_eq!(shield_plan(&many[..0], None), None);
}

#[test]
fn shell_words_and_frames_print_as_an_operator_types_them() {
    assert_eq!(shell_word("/srv/node/.config"), "/srv/node/.config");
    assert_eq!(
        shell_word("/srv/node one/.config"),
        "'/srv/node one/.config'"
    );
    assert_eq!(shell_word("it's"), r"'it'\''s'");
    assert_eq!(grouped(943_920), "943,920");
    assert_eq!(grouped(920), "920");
    assert_eq!(grouped(1_000), "1,000");
    assert_eq!(tail("QmAbcdefghij"), "efghij");
    assert_eq!(tail("abc"), "abc");
}

//! `token mint --status <file>`: where a saved reward-mint authorization
//! stands, read from a node without building or submitting anything.
//!
//! The node reports whether GLOBAL included the authorization and which frame
//! a claim would cite. Its witness says nothing about whether the claim was
//! made: the global commit records that, keyed by the receipt, and names the
//! operation that consumed it.
use super::{RecipientWallet, TokenCtx};
use quil_execution::token_intrinsic::global_commit;
use quil_types::proto::node::{
    GetMintAuthorizationStatusRequest, GetMintAuthorizationStatusResponse, GetVertexDataRequest,
    MintAuthorizationState,
};

type Client =
    quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>;

/// The operation that consumed `receipt`, from its GLOBAL record; `None` while
/// no claim has committed.
async fn read_consumer(
    client: &Client,
    application: &[u8; 32],
    receipt: &[u8; 32],
) -> anyhow::Result<Option<[u8; 32]>> {
    let mut address = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
    address.extend_from_slice(&global_commit::consumed_address(application, receipt)?);
    let response = client
        .clone()
        .max_decoding_message_size(66_560)
        .get_vertex_data(GetVertexDataRequest {
            address,
            full_data: true,
        })
        .await?
        .into_inner();
    let (present, blob) = RecipientWallet::decode_global_record(response)?;
    if !present {
        return Ok(None);
    }
    Ok(Some(global_commit::parse_consumed_record(&blob)?))
}

/// The line a claim prints when the receipt it is about to claim was already
/// consumed. The commit decides either way, so an unreadable record only says so.
pub(super) async fn note_consumed(client: &Client, application: &[u8; 32], receipt: &[u8; 32]) {
    match read_consumer(client, application, receipt).await {
        Ok(Some(operation)) => super::super::output::line(format!(
            "This authorization's claim already committed as operation {}; the global commit \
             rejects another.",
            hex::encode(operation)
        )),
        Ok(None) => {}
        Err(error) => super::super::output::err_line(format!(
            "Could not read whether this authorization was already claimed: {error}"
        )),
    }
}

/// What the node says of the authorization.
enum Reported {
    Status(GetMintAuthorizationStatusResponse),
    /// A node without the status call, or without a coin provider.
    Not(String),
}

fn state_label(state: MintAuthorizationState) -> &'static str {
    use MintAuthorizationState as State;
    match state {
        State::Claimable => "claimable",
        State::AwaitingCitableRoot => "included, awaiting a root a claim can cite",
        State::NotIncluded => "not included",
        State::NoCitableRoot => "included, but no retained root a claim can cite",
        State::NoRetainedRoot => "no retained root",
        State::Unspecified => "unknown",
    }
}

/// The report of one authorization, one line per question.
fn status_lines(
    saved: &std::path::Path,
    receipt: &[u8; 32],
    reported: &Reported,
    consumer: Option<&[u8; 32]>,
) -> Vec<String> {
    let mut lines = vec![format!(
        "Reward mint authorization {}, receipt {}",
        saved.display(),
        hex::encode(receipt)
    )];
    let mut claimable = true;
    match reported {
        Reported::Status(status) => {
            let state = status.state();
            claimable = state == MintAuthorizationState::Claimable;
            lines.push(if status.reason.is_empty() {
                format!("State: {}.", state_label(state))
            } else {
                format!("State: {}: {}.", state_label(state), status.reason)
            });
            if status.found {
                let (earliest, latest) = (status.inclusion_frame_earliest, status.inclusion_frame);
                lines.push(if earliest == latest {
                    format!("Included: at GLOBAL frame {latest}.")
                } else if earliest == 0 {
                    format!("Included: at or before GLOBAL frame {latest}.")
                } else {
                    format!("Included: between GLOBAL frames {earliest} and {latest}.")
                });
            }
            if claimable {
                lines.push(format!(
                    "Witness: a claim cites GLOBAL frame {}.",
                    status.cited_frame
                ));
            }
        }
        Reported::Not(why) => lines.push(format!(
            "State: the node does not report it ({why}); a claim finds out."
        )),
    }
    lines.push(match (consumer, claimable) {
        (Some(operation), _) => format!(
            "Consumed: yes, by operation {}: the claim committed and another is rejected.",
            hex::encode(operation)
        ),
        (None, true) => format!(
            "Consumed: no. `token mint --claim {}` creates the coins.",
            saved.display()
        ),
        (None, false) => {
            "Consumed: no. No claim can be built until the state above changes.".to_string()
        }
    });
    lines
}

/// The report over `client`, for an authorization whose receipt is known.
async fn report(
    client: &Client,
    saved: &std::path::Path,
    receipt: &[u8; 32],
) -> anyhow::Result<Vec<String>> {
    let reported = match client
        .clone()
        .get_mint_authorization_status(GetMintAuthorizationStatusRequest {
            receipt: receipt.to_vec(),
        })
        .await
    {
        Ok(status) => Reported::Status(status.into_inner()),
        Err(status)
            if matches!(
                status.code(),
                tonic::Code::Unimplemented | tonic::Code::Unavailable
            ) =>
        {
            Reported::Not(status.message().to_string())
        }
        Err(status) => anyhow::bail!("mint authorization status: {status}"),
    };
    let consumer = read_consumer(client, &quil_execution::domains::QUIL_TOKEN, receipt)
        .await
        .map_err(|e| anyhow::anyhow!("whether the claim committed: {e}"))?;
    Ok(status_lines(saved, receipt, &reported, consumer.as_ref()))
}

/// `token mint --status <file>`: reads only, with no wallet keys.
pub(in crate::commands::token) async fn run_mint_status(
    tc: &TokenCtx,
    saved: &std::path::Path,
) -> anyhow::Result<()> {
    let network =
        quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
    let bytes = std::fs::read(saved)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", saved.display()))?;
    let mint = quil_lattice_ct::confidential::mint::Mint::decode(
        &bytes,
        &network,
        &quil_execution::domains::QUIL_TOKEN,
    )
    .map_err(|e| anyhow::anyhow!("invalid original mint: {e:?}"))?;
    let receipt =
        quil_execution::token_intrinsic::mint_authorization::receipt_address(&mint.statement)?;
    let client = tc.connect().await?;
    for line in report(&client, saved, &receipt).await? {
        super::super::output::line(line);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_crypto::sntrup761;
    use quil_types::store::HypergraphStore;
    use std::path::Path;
    use std::sync::Arc;

    fn status(state: MintAuthorizationState) -> GetMintAuthorizationStatusResponse {
        GetMintAuthorizationStatusResponse {
            state: state as i32,
            found: state == MintAuthorizationState::Claimable,
            inclusion_frame: 41,
            inclusion_frame_earliest: 41,
            cited_frame: 43,
            reason: "why".into(),
            ..Default::default()
        }
    }

    /// Each question gets its own line, and the last one says what to do.
    #[test]
    fn a_status_answers_each_question_and_what_to_do() {
        let saved = Path::new("/cfg/mint-42.bin");
        let lines = status_lines(
            saved,
            &[0xab; 32],
            &Reported::Status(status(MintAuthorizationState::Claimable)),
            None,
        );
        assert_eq!(
            lines,
            [
                format!(
                    "Reward mint authorization /cfg/mint-42.bin, receipt {}",
                    hex::encode([0xab; 32])
                ),
                "State: claimable: why.".to_string(),
                "Included: at GLOBAL frame 41.".to_string(),
                "Witness: a claim cites GLOBAL frame 43.".to_string(),
                "Consumed: no. `token mint --claim /cfg/mint-42.bin` creates the coins."
                    .to_string(),
            ]
        );
        let lines = status_lines(
            saved,
            &[0xab; 32],
            &Reported::Status(status(MintAuthorizationState::Claimable)),
            Some(&[0xcd; 32]),
        );
        assert_eq!(
            lines.last().unwrap(),
            &format!(
                "Consumed: yes, by operation {}: the claim committed and another is rejected.",
                hex::encode([0xcd; 32])
            )
        );
        let lines = status_lines(
            saved,
            &[0xab; 32],
            &Reported::Status(status(MintAuthorizationState::NotIncluded)),
            None,
        );
        assert_eq!(lines[1], "State: not included: why.");
        assert_eq!(
            lines.last().unwrap(),
            "Consumed: no. No claim can be built until the state above changes."
        );
        assert!(
            !lines.iter().any(|line| line.starts_with("Witness")),
            "{lines:?}"
        );
    }

    /// Sparse retained roots leave a range of frames; say what is known.
    #[test]
    fn a_status_gives_the_inclusion_frames_it_knows() {
        let included = |earliest, latest| {
            let mut status = status(MintAuthorizationState::Claimable);
            (status.inclusion_frame_earliest, status.inclusion_frame) = (earliest, latest);
            status_lines(Path::new("m"), &[0; 32], &Reported::Status(status), None)[2].clone()
        };
        assert_eq!(included(41, 41), "Included: at GLOBAL frame 41.");
        assert_eq!(included(0, 41), "Included: at or before GLOBAL frame 41.");
        assert_eq!(
            included(30, 41),
            "Included: between GLOBAL frames 30 and 41."
        );
    }

    /// A node holding `receipt`'s consumption record, and no coin provider: it
    /// answers for the record and does not report the authorization.
    fn node_with_consumed(
        listener: tokio::net::TcpListener,
        receipt: [u8; 32],
        operation: [u8; 32],
    ) -> (
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let global = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS;
        let record =
            global_commit::consumed_address(&quil_execution::domains::QUIL_TOKEN, &receipt)
                .unwrap();
        let store = Arc::new(quil_hypergraph::testing::MemStore::new());
        let shard = quil_hypergraph::addressing::shard_key_for_location(
            &quil_hypergraph::addressing::Location {
                app_address: global,
                data_address: record,
            },
        );
        let vertex = [global.as_slice(), record.as_slice()].concat();
        let txn = store.new_transaction(false).unwrap();
        store
            .save_vertex_underlying(
                txn.as_ref(),
                "vertex",
                "adds",
                &shard,
                &vertex,
                &global_commit::encode_consumed_record(&operation).unwrap(),
            )
            .unwrap();
        serve(
            listener,
            quil_rpc::node_service::NodeRpcServer::new().with_hypergraph_store(store),
        )
    }

    fn serve(
        listener: tokio::net::TcpListener,
        server: quil_rpc::node_service::NodeRpcServer,
    ) -> (
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let incoming = futures::stream::unfold(listener, |listener| async {
            Some((listener.accept().await.map(|(stream, _)| stream), listener))
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

    /// Structurally valid authorization bytes on `network`; proofs are not read.
    fn saved_mint(network: u8) -> (Vec<u8>, [u8; 32]) {
        use quil_lattice_ct::confidential::{
            memo::create_output,
            mint::{Mint, MintStatement, RewardClaim},
        };
        let network = quil_lattice_ct::confidential::transfer::network_identifier(network);
        let keys = sntrup761::Sntrup761KeyPair::generate();
        let wallet = RecipientWallet::from_keys(
            &network,
            &quil_execution::domains::QUIL_TOKEN,
            &keys.public,
            zeroize::Zeroizing::new(keys.secret),
        )
        .unwrap();
        let output = create_output(&wallet.context, wallet.address(), 7)
            .unwrap()
            .output;
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        let statement = MintStatement {
            network,
            application: quil_execution::domains::QUIL_TOKEN,
            cited_frame: 1,
            reward_root: [3; 32],
            fee: 1,
            outputs: vec![output],
            claims: vec![RewardClaim {
                owner: [4; 32],
                value: 8,
                public_key: [0; 897],
                forest_proof: vec![1],
            }],
        };
        let receipt =
            quil_execution::token_intrinsic::mint_authorization::receipt_address(&statement)
                .unwrap();
        let bytes = Mint {
            statement,
            signatures: vec![[0; 666]],
            proof,
        }
        .encode()
        .unwrap();
        (bytes, receipt)
    }

    /// Lines the code under `work` sent to the output, in order.
    async fn lines_of<F: std::future::Future>(work: F) -> (F::Output, Vec<String>) {
        let (sink, mut lines) = tokio::sync::mpsc::unbounded_channel();
        let output = super::super::super::output::capture(sink, work).await;
        let mut all = Vec::new();
        while let Ok(line) = lines.try_recv() {
            all.push(line);
        }
        (output, all)
    }

    /// Over RPC: an unconsumed receipt, and one the global commit recorded,
    /// whose operation is named. Another's record says nothing of this one.
    #[tokio::test]
    async fn a_status_reads_the_receipts_consumption_over_rpc() {
        let application = quil_execution::domains::QUIL_TOKEN;
        let (receipt, unclaimed, operation) = ([0x31; 32], [0x32; 32], [0x77; 32]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (stop, serving) = node_with_consumed(listener, receipt, operation);
        let client = Client::new(
            tonic::transport::Endpoint::from_shared(endpoint)
                .unwrap()
                .connect()
                .await
                .unwrap(),
        );
        assert_eq!(
            read_consumer(&client, &application, &receipt)
                .await
                .unwrap(),
            Some(operation)
        );
        assert_eq!(
            read_consumer(&client, &application, &unclaimed)
                .await
                .unwrap(),
            None
        );
        let lines = report(&client, Path::new("m"), &receipt).await.unwrap();
        assert!(
            lines[1].starts_with("State: the node does not report it ("),
            "{lines:?}"
        );
        assert!(lines[2].contains(&hex::encode(operation)), "{lines:?}");
        let lines = report(&client, Path::new("m"), &unclaimed).await.unwrap();
        assert_eq!(
            lines.last().unwrap(),
            "Consumed: no. `token mint --claim m` creates the coins."
        );
        stop.send(()).unwrap();
        serving.await.unwrap();
    }

    /// The command reads the saved file and reports through the node; a claim
    /// of a consumed receipt says so before anything else, and of a fresh one
    /// says nothing.
    #[tokio::test]
    async fn a_saved_mint_reports_its_consumption_and_a_claim_says_so() {
        use super::super::super::test_nodes;
        let operation = [0x77; 32];
        let directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let listen = format!("/ip4/127.0.0.1/tcp/{}", address.port());
        let node = test_nodes::write(&directory.path().join("node"), 41, &listen);
        let tc = TokenCtx::from_context(
            &test_nodes::context(false),
            &test_nodes::common(&node.dir, None, false),
        )
        .unwrap();
        let (bytes, receipt) = saved_mint(tc.node_config.p2p.network);
        let (stop, serving) = node_with_consumed(listener, receipt, operation);
        let saved = directory.path().join("mint-1.bin");
        std::fs::write(&saved, &bytes).unwrap();

        let (result, lines) = lines_of(run_mint_status(&tc, &saved)).await;
        result.unwrap();
        assert!(
            lines[0].ends_with(&format!("receipt {}", hex::encode(receipt))),
            "{lines:?}"
        );
        assert!(
            lines.last().unwrap().starts_with(&format!(
                "Consumed: yes, by operation {}",
                hex::encode(operation)
            )),
            "{lines:?}"
        );

        let network =
            quil_lattice_ct::confidential::transfer::network_identifier(tc.node_config.p2p.network);
        let keys = sntrup761::Sntrup761KeyPair::generate();
        let wallet = RecipientWallet::from_keys(
            &network,
            &quil_execution::domains::QUIL_TOKEN,
            &keys.public,
            zeroize::Zeroizing::new(keys.secret),
        )
        .unwrap();
        let client = tc.connect().await.unwrap();
        // This node has no coin provider, so the witness read ends the claim.
        let (claim, lines) = lines_of(wallet.create_mint_claim(&client, &bytes)).await;
        assert!(claim.is_err());
        assert!(
            lines.iter().any(|line| line.contains(&format!(
                "already committed as operation {}",
                hex::encode(operation)
            ))),
            "{lines:?}"
        );
        // A fresh receipt adds no line.
        let (other, _) = saved_mint(tc.node_config.p2p.network);
        let (_, lines) = lines_of(wallet.create_mint_claim(&client, &other)).await;
        assert!(
            !lines.iter().any(|line| line.contains("already committed")),
            "{lines:?}"
        );
        stop.send(()).unwrap();
        serving.await.unwrap();
    }

    /// `--status` submits nothing, so it needs no signing identity: a config
    /// other than the running node's reads it, and goes on to the file.
    #[tokio::test]
    async fn a_status_needs_no_signing_identity() {
        use super::super::super::test_nodes;
        use clap::Parser;
        let directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = format!(
            "/ip4/127.0.0.1/tcp/{}",
            listener.local_addr().unwrap().port()
        );
        let node = test_nodes::write(&directory.path().join("node"), 41, &listen);
        let dormant = test_nodes::write(&directory.path().join("dormant"), 42, &listen);
        let (stop, serving) = serve(
            listener,
            quil_rpc::node_service::NodeRpcServer::new().with_peer_id(node.peer_id.clone()),
        );
        let tc = TokenCtx::from_context(
            &test_nodes::context(false),
            &test_nodes::common(&dormant.dir, None, false),
        )
        .unwrap();
        let saved = directory.path().join("mint-42.bin");
        std::fs::write(&saved, b"not a mint").unwrap();
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            token: super::super::super::TokenArgs,
        }
        let path = saved.display().to_string();
        let args = Cli::try_parse_from(["token", "mint", "--status", path.as_str()]).unwrap();
        let error = Box::pin(super::super::super::run_with_context(&tc, &args.token))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.starts_with("invalid original mint"), "{error}");
        // It reports; it cannot also claim or mint.
        assert!(Cli::try_parse_from(["token", "mint", "--status", "m", "--claim", "m"]).is_err());
        assert!(Cli::try_parse_from(["token", "mint", "--status", "m", "--fee", "1"]).is_err());
        stop.send(()).unwrap();
        serving.await.unwrap();
    }
}

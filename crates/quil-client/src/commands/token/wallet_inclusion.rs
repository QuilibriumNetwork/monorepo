//! What a confidential submission prints so its sender can find it again,
//! and `--wait`: the operation's GLOBAL commit decision, then its coins.
//!
//! The global commit decides every relayed operation (transfers, splits,
//! merges, escrows, shields, mint claims, custom-token mints, settlements)
//! once and records the decision in GLOBAL state, keyed by the application
//! and the operation id (SHA3-256 of the operation bytes): committed or
//! rejected, and the deciding GLOBAL frame. Any node reads that record like a
//! spend marker. An operation a shard refuses (a bad proof, a short fee) is
//! never decided, so an absent record means pending or refused.
//!
//! A coin's address covers the frame of the shard that executed the
//! operation, so it does not exist at submission. After the commit the wallet
//! finds the operation's coins in a coin scan by their one-time owner keys.
use super::{RecipientWallet, TokenCtx};
use quil_execution::token_intrinsic::global_commit::{self, Decision};
use quil_lattice_ct::confidential::transfer::Output;

type Client =
    quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>;

/// Pause between decision reads, and between coin scans, while waiting.
const POLL: std::time::Duration = std::time::Duration::from_secs(5);

/// The `--wait` a printed check command suggests.
const SUGGESTED_WAIT_SECS: u64 = 600;

/// How long a submitting command follows its operation.
#[derive(Clone, Copy, Debug)]
pub(in crate::commands::token) struct Follow {
    /// `--wait`: zero prints the identifiers and returns.
    pub(in crate::commands::token) wait: std::time::Duration,
    /// Page budget of a coin scan for the operation's coins.
    pub(in crate::commands::token) max_pages: usize,
}

/// Which shard executes a submitted operation, as far as the wallet knows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Route {
    /// Any live shard of the application: the one its bundle hash
    /// designates, or another once that one has held it too long.
    Designated,
    /// A shield: the live shard holding its legacy sources.
    SourceShard,
    /// That shard path (a shield whose source shard the wallet looked up).
    Shard(Vec<bool>),
    /// GLOBAL, for an application no shard covers.
    Global,
}

/// One submitted operation, as its sender can find it again.
pub(in crate::commands::token) struct Submitted {
    pub(super) application: [u8; 32],
    /// The global commit's key for it: SHA3-256 of the operation bytes.
    pub(super) operation: [u8; 32],
    /// SHA3-256 of the signed bundle; node logs name it by its first 4 bytes.
    pub(super) bundle: [u8; 32],
    pub(super) route: Route,
    /// The coins it creates, in its spend entry's order.
    pub(super) outputs: Vec<Output>,
    /// Whether it also funds an escrow (a pending transfer).
    pub(super) escrow: bool,
}

impl Submitted {
    /// `None` for an operation the global commit does not decide: the QUIL
    /// reward mint, whose authorization GLOBAL itself executes.
    pub(super) fn of(network: &[u8; 32], application: [u8; 32], bytes: &[u8]) -> Option<Self> {
        use quil_execution::token_engine::{TYPE_LATTICE_PENDING, TYPE_LATTICE_SHIELD};
        use quil_execution::token_intrinsic::spend_entries;
        let kind = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?);
        if !spend_entries::commits_globally(&application, kind) {
            return None;
        }
        Some(Self {
            application,
            operation: global_commit::tx_id(bytes),
            bundle: [0; 32],
            route: if kind == TYPE_LATTICE_SHIELD {
                Route::SourceShard
            } else {
                Route::Designated
            },
            outputs: spend_entries::operation_outputs(network, &application, kind, bytes)
                .unwrap_or_default(),
            escrow: kind == TYPE_LATTICE_PENDING,
        })
    }
}

/// `0x`-prefixed hex.
fn hex32(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// An argument as a POSIX shell reads it back unchanged.
fn shell_word(word: &str) -> String {
    if !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._:=,+@%-".contains(&b))
    {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', r"'\''"))
    }
}

/// The command that reads the operation's decision later, through the same
/// node and wallet configuration as the command that submitted it.
pub(super) fn check_command(
    program: &str,
    read_flags: &[String],
    application: &[u8; 32],
    operation: &[u8; 32],
) -> String {
    let mut words = vec![program.to_string(), "token".into(), "inclusion".into()];
    words.push(hex32(operation));
    if application != &quil_execution::domains::QUIL_TOKEN {
        words.push("--application".into());
        words.push(hex::encode(application));
    }
    words.extend(read_flags.iter().cloned());
    words.push("--wait".into());
    words.push(SUGGESTED_WAIT_SECS.to_string());
    words
        .iter()
        .map(|word| shell_word(word))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The program name this process was started as, for commands it prints.
fn program() -> String {
    std::env::args()
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "qclient".into())
}

fn coins(n: usize) -> String {
    match n {
        0 => "no coins".into(),
        1 => "1 coin".into(),
        n => format!("{n} coins"),
    }
}

/// The lines a submission prints: what was sent, where it goes, and what is
/// not known yet.
pub(super) fn submitted_lines(what: &str, s: &Submitted, head: Option<u64>) -> Vec<String> {
    let mut lines = vec![match head {
        Some(head) => {
            format!("Confidential {what} submitted; the node's GLOBAL head was frame {head}.")
        }
        None => format!("Confidential {what} submitted."),
    }];
    lines.push(format!("  operation:   {}", hex32(&s.operation)));
    lines.push(format!(
        "  application: {}{}",
        hex32(&s.application),
        if s.application == quil_execution::domains::QUIL_TOKEN {
            " (QUIL)"
        } else {
            ""
        }
    ));
    let logs = format!("node logs: bundle={}", hex::encode(&s.bundle[..4]));
    lines.push(match &s.route {
        Route::Designated => format!(
            "  shard:       chosen as it executes: the live shard its bundle hash designates, \
             any shard if that one holds it too long ({logs})"
        ),
        Route::SourceShard => {
            format!("  shard:       the live shard holding its legacy source coins ({logs})")
        }
        Route::Shard(path) => format!(
            "  shard:       {} (holds its legacy source coins; {logs})",
            hex::encode(quil_forest::encode_shard_bit_path(&s.application, path))
        ),
        Route::Global => {
            "  shard:       none: GLOBAL executes it, as no shard covers the application".into()
        }
    });
    lines.push(format!(
        "  creates:     {}{}; a coin's address exists once the operation executes",
        coins(s.outputs.len()),
        if s.escrow {
            " and an escrow (the recipient's `token escrows` lists it)"
        } else {
            ""
        }
    ));
    lines
}

/// Why waiting has not settled the operation, and what to run later.
pub(super) fn pending_message(
    what: &str,
    waited_secs: u64,
    head: Option<u64>,
    check: &str,
) -> String {
    format!(
        "the {what} is not committed after {waited_secs} s{}: a shard has not executed it yet, \
         or refused it (a refused operation leaves no record and spends nothing). Check again \
         with: {check}",
        head.map(|head| format!(" (GLOBAL head {head})"))
            .unwrap_or_default()
    )
}

/// The decision line, or the error a rejection is.
pub(super) fn decision_outcome(what: &str, decision: &Decision) -> anyhow::Result<String> {
    match decision {
        Decision::Committed { frame } => {
            Ok(format!("The {what} committed in GLOBAL frame {frame}."))
        }
        Decision::Rejected { frame, reason } => Err(anyhow::anyhow!(
            "the {what} was rejected by the global commit in GLOBAL frame {frame}: {reason}; \
             it spent and created nothing"
        )),
    }
}

/// Read the global commit's decision on `operation` of `application`.
pub(super) async fn read_decision(
    client: &Client,
    application: &[u8; 32],
    operation: &[u8; 32],
) -> anyhow::Result<Option<Decision>> {
    let mut address = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
    address.extend_from_slice(&global_commit::decision_address(application, operation)?);
    let response = client
        .clone()
        .max_decoding_message_size(66_560)
        .get_vertex_data(quil_types::proto::node::GetVertexDataRequest {
            address,
            full_data: true,
        })
        .await?
        .into_inner();
    let (present, blob) = RecipientWallet::decode_global_record(response)?;
    if !present {
        return Ok(None);
    }
    global_commit::decode_decision(&blob).map_err(|e| anyhow::anyhow!("{UNDECODABLE}: {e}"))
}

/// Prefix of a decision record that will not decode on a retry either.
const UNDECODABLE: &str = "malformed decision record";

/// The node's GLOBAL head, when it answers.
async fn head(tc: &TokenCtx) -> Option<u64> {
    let mut client = tc.connect().await.ok()?;
    client
        .get_node_info(quil_types::proto::node::GetNodeInfoRequest::default())
        .await
        .ok()
        .map(|info| info.into_inner().last_global_head_frame)
}

/// Poll the decision until it exists or `deadline` passes. Read failures
/// retry until the deadline; the last one is returned with `None`.
async fn await_decision(
    tc: &TokenCtx,
    application: &[u8; 32],
    operation: &[u8; 32],
    deadline: std::time::Instant,
) -> anyhow::Result<(Option<Decision>, Option<String>)> {
    loop {
        let read = match tc.connect().await {
            Ok(client) => read_decision(&client, application, operation).await,
            Err(error) => Err(error),
        };
        let failure = match read {
            Ok(Some(decision)) => return Ok((Some(decision), None)),
            Ok(None) => None,
            Err(error) if error.to_string().starts_with(UNDECODABLE) => return Err(error),
            Err(error) => Some(error.to_string()),
        };
        if std::time::Instant::now() + POLL > deadline {
            return Ok((None, failure));
        }
        tokio::time::sleep(POLL).await;
    }
}

impl RecipientWallet {
    /// The addresses of `wanted` coins, by one-time owner key and content,
    /// from complete coin scans repeated until all are found or `deadline`
    /// passes. A scan reads every coin of the application, as `token coins`
    /// does, without opening any memo.
    pub(super) async fn find_coins(
        &self,
        client: &Client,
        wanted: &[Output],
        max_pages: usize,
        deadline: std::time::Instant,
    ) -> anyhow::Result<Vec<Option<[u8; 32]>>> {
        let mut found = vec![None; wanted.len()];
        loop {
            let started = std::time::Instant::now();
            let mut scan = super::CoinScan::new(max_pages)?;
            let mut pages = 0usize;
            while !scan.finished() && std::time::Instant::now() < deadline {
                for (address, output) in self.scan_next(client, &mut scan).await? {
                    if let Some(index) = wanted.iter().position(|coin| coin == &output) {
                        found[index] = Some(address);
                    }
                }
                pages += 1;
            }
            eprintln!(
                "coin scan: {pages} pages in {:.1} s{}",
                started.elapsed().as_secs_f64(),
                if scan.finished() {
                    ""
                } else {
                    " (stopped when the wait ended)"
                }
            );
            if found.iter().all(Option::is_some) || std::time::Instant::now() + POLL > deadline {
                return Ok(found);
            }
            tokio::time::sleep(POLL).await;
        }
    }

    /// Whether this wallet can open `output`: the coin is its own.
    pub(super) fn owns(&self, output: &Output) -> bool {
        quil_lattice_ct::confidential::memo::open_output(
            &self.context,
            &self.kem_secret,
            &self.recipient,
            output,
        )
        .is_ok()
    }
}

/// Print what identifies a submitted operation, and the command that checks
/// it later unless the caller waits for it.
pub(in crate::commands::token) async fn announce(
    tc: &TokenCtx,
    what: &str,
    submitted: &Submitted,
    waits: bool,
) {
    for line in submitted_lines(what, submitted, head(tc).await) {
        println!("{line}");
    }
    if !waits {
        println!(
            "Not committed yet. Check with: {}",
            check_command(
                &program(),
                &tc.read_flags,
                &submitted.application,
                &submitted.operation
            )
        );
    }
}

/// Wait until `deadline` for the GLOBAL commit decision on each submitted
/// operation, then for the coins the committed ones created. A rejection, or
/// no decision by the deadline, is an error that says what to run later.
pub(in crate::commands::token) async fn settle(
    tc: &TokenCtx,
    wallet: &RecipientWallet,
    what: &str,
    submitted: &[Submitted],
    follow: Follow,
    deadline: std::time::Instant,
) -> anyhow::Result<()> {
    println!(
        "Waiting up to {} s for the global commit to decide it...",
        follow.wait.as_secs()
    );
    let mut failures = Vec::new();
    let mut committed = Vec::new();
    for s in submitted {
        let (decision, failure) =
            await_decision(tc, &s.application, &s.operation, deadline).await?;
        match decision {
            Some(decision) => match decision_outcome(what, &decision) {
                Ok(line) => {
                    println!("{line}");
                    committed.extend(s.outputs.iter().cloned());
                }
                Err(error) => failures.push(error.to_string()),
            },
            None => {
                let check = check_command(&program(), &tc.read_flags, &s.application, &s.operation);
                let mut message =
                    pending_message(what, follow.wait.as_secs(), head(tc).await, &check);
                if let Some(failure) = failure {
                    message.push_str(&format!("; the last read failed: {failure}"));
                }
                failures.push(message);
            }
        }
    }
    if !committed.is_empty() {
        println!(
            "Looking for its {} in coin scans until the wait ends...",
            coins(committed.len())
        );
        // The commit is settled; a scan that fails only leaves the addresses
        // unknown.
        let found = match tc.connect().await {
            Ok(client) => {
                wallet
                    .find_coins(&client, &committed, follow.max_pages, deadline)
                    .await
            }
            Err(error) => Err(error),
        }
        .unwrap_or_else(|error| {
            println!("The coin scan failed: {error}.");
            vec![None; committed.len()]
        });
        for (index, (output, address)) in committed.iter().zip(&found).enumerate() {
            let own = wallet.owns(output);
            let owner = if own {
                "this wallet's"
            } else {
                "the recipient's"
            };
            match address {
                Some(address) => println!("  coin {}: {} ({owner})", index + 1, hex32(address)),
                None => println!(
                    "  coin {}: not in the scan yet ({owner}); the shard owning its block \
                     delivers it after the commit{}",
                    index + 1,
                    if own {
                        ", and `token coins` lists it then"
                    } else {
                        ""
                    }
                ),
            }
        }
    }
    match failures.as_slice() {
        [] => Ok(()),
        [one] => anyhow::bail!("{one}"),
        several => anyhow::bail!("{}", several.join("\n")),
    }
}

/// [`announce`] one submitted operation, then [`settle`] it with `--wait`.
pub(in crate::commands::token) async fn follow(
    tc: &TokenCtx,
    wallet: &RecipientWallet,
    what: &str,
    submitted: Option<Submitted>,
    follow: Follow,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + follow.wait;
    let Some(submitted) = submitted else {
        println!("Confidential {what} submitted.");
        return Ok(());
    };
    announce(tc, what, &submitted, !follow.wait.is_zero()).await;
    if follow.wait.is_zero() {
        return Ok(());
    }
    settle(
        tc,
        wallet,
        what,
        std::slice::from_ref(&submitted),
        follow,
        deadline,
    )
    .await
}

/// `token inclusion <operation>`: the global commit's decision on an
/// operation, waiting up to `wait` for one.
pub(in crate::commands::token) async fn run_inclusion(
    tc: &TokenCtx,
    application: &str,
    operation: &str,
    wait: std::time::Duration,
) -> anyhow::Result<()> {
    let application = super::identifier(application)?;
    let operation = super::identifier(operation)?;
    let deadline = std::time::Instant::now() + wait;
    let (decision, failure) = await_decision(tc, &application, &operation, deadline).await?;
    if let Some(decision) = decision {
        println!("{}", decision_outcome("operation", &decision)?);
        return Ok(());
    }
    if let Some(failure) = failure {
        anyhow::bail!("the node did not answer for the decision: {failure}");
    }
    let message = pending_message(
        "operation",
        wait.as_secs(),
        head(tc).await,
        &check_command(&program(), &tc.read_flags, &application, &operation),
    );
    anyhow::ensure!(wait.is_zero(), "{message}");
    println!("Not decided yet: {message}");
    Ok(())
}

/// A mint authorization's claim readiness, as the node reports it.
fn mint_state_label(state: quil_types::proto::node::MintAuthorizationState) -> &'static str {
    use quil_types::proto::node::MintAuthorizationState as State;
    match state {
        State::Claimable => "claimable",
        State::AwaitingCitableRoot => "included, awaiting a root a claim can cite",
        State::NotIncluded => "not included",
        State::NoCitableRoot => "included, but no retained root a claim can cite",
        State::NoRetainedRoot => "no retained root",
        State::Unspecified => "unknown",
    }
}

/// The command that claims the mint authorization saved at `saved`.
pub(super) fn claim_command(
    program: &str,
    read_flags: &[String],
    saved: &std::path::Path,
) -> String {
    let mut words = vec![
        program.to_string(),
        "token".into(),
        "mint".into(),
        "--claim".into(),
        saved.display().to_string(),
    ];
    words.extend(read_flags.iter().cloned());
    words.push("--wait".into());
    words.push(SUGGESTED_WAIT_SECS.to_string());
    words
        .iter()
        .map(|word| shell_word(word))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Wait until `deadline` for the node to report the reward mint authorization
/// `mint` claimable, polling at least once. A node that does not report
/// authorization status (an older release, or one without a coin provider)
/// leaves the claim to find out: `Ok(false)`.
pub(in crate::commands::token) async fn await_claimable(
    tc: &TokenCtx,
    mint: &quil_lattice_ct::confidential::mint::MintStatement,
    saved: &std::path::Path,
    deadline: std::time::Instant,
) -> anyhow::Result<bool> {
    use quil_types::proto::node::MintAuthorizationState as State;
    let receipt = quil_execution::token_intrinsic::mint_authorization::receipt_address(mint)?;
    loop {
        let status = tc
            .connect()
            .await?
            .get_mint_authorization_status(
                quil_types::proto::node::GetMintAuthorizationStatusRequest {
                    receipt: receipt.to_vec(),
                },
            )
            .await;
        let pending = match status {
            Ok(status) => {
                let status = status.into_inner();
                if status.state() == State::Claimable {
                    println!("The mint authorization is claimable: {}.", status.reason);
                    return Ok(true);
                }
                format!("{}: {}", mint_state_label(status.state()), status.reason)
            }
            Err(status)
                if matches!(
                    status.code(),
                    tonic::Code::Unimplemented | tonic::Code::Unavailable
                ) =>
            {
                println!(
                    "The node does not report mint authorization status ({}); the claim \
                     finds out.",
                    status.message()
                );
                return Ok(false);
            }
            Err(status) => anyhow::bail!("mint authorization status: {status}"),
        };
        if std::time::Instant::now() + POLL > deadline {
            anyhow::bail!(
                "the mint authorization is not claimable yet ({pending}). Run again: {}",
                claim_command(&program(), &tc.read_flags, saved)
            );
        }
        tokio::time::sleep(POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn submitted(application: [u8; 32], outputs: usize, escrow: bool) -> Submitted {
        use quil_lattice_ct::confidential::{AmountOpening, CommitmentKey};
        let context = [1; 32];
        let output = Output {
            commitment: CommitmentKey::derive(&context)
                .commit(5, &AmountOpening::from_seed(&context, &[2; 32])),
            owner: [3; quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES],
            memo: [4; quil_lattice_ct::confidential::transfer::MEMO_BYTES],
        };
        let mut bundle = [0; 32];
        bundle[..4].copy_from_slice(&[0x1a, 0x2b, 0x3c, 0x4d]);
        Submitted {
            application,
            operation: [0xab; 32],
            bundle,
            route: Route::Designated,
            outputs: vec![output; outputs],
            escrow,
        }
    }

    #[test]
    fn a_submission_names_its_operation_application_shard_and_coins() {
        let quil = quil_execution::domains::QUIL_TOKEN;
        let lines = submitted_lines("transfer", &submitted(quil, 2, false), Some(965_678));
        assert_eq!(
            lines[0],
            "Confidential transfer submitted; the node's GLOBAL head was frame 965678."
        );
        assert_eq!(lines[1], format!("  operation:   0x{}", "ab".repeat(32)));
        assert_eq!(
            lines[2],
            format!("  application: 0x{} (QUIL)", hex::encode(quil))
        );
        assert!(
            lines[3].starts_with("  shard:       chosen as it executes: ")
                && lines[3].ends_with("(node logs: bundle=1a2b3c4d)"),
            "{}",
            lines[3]
        );
        assert!(
            lines[4].starts_with("  creates:     2 coins; "),
            "{}",
            lines[4]
        );
        // A shield names the shard holding its sources, as a full filter.
        let mut shield = submitted([9; 32], 1, false);
        shield.route = Route::Shard(vec![true, false, true]);
        let lines = submitted_lines("shield", &shield, None);
        assert_eq!(lines[0], "Confidential shield submitted.");
        assert_eq!(lines[2], format!("  application: 0x{}", "09".repeat(32)));
        assert_eq!(
            lines[3],
            format!(
                "  shard:       {}0003a0 (holds its legacy source coins; node logs: bundle=1a2b3c4d)",
                "09".repeat(32)
            )
        );
        assert!(
            lines[4].starts_with("  creates:     1 coin; "),
            "{}",
            lines[4]
        );
        let mut global = submitted([9; 32], 0, true);
        global.route = Route::Global;
        let lines = submitted_lines("escrow funding", &global, None);
        assert!(lines[3].contains("GLOBAL executes it"), "{}", lines[3]);
        assert!(
            lines[4].starts_with("  creates:     no coins and an escrow "),
            "{}",
            lines[4]
        );
    }

    /// The id a submission prints is the one the executing shard relays to
    /// the global commit, and its coins are the operation's outputs.
    #[test]
    fn a_transfer_is_identified_as_the_shard_relays_it() {
        use quil_lattice_ct::confidential::{
            relation::membership::{Node, IDENTITY_BYTES, NODE_BYTES},
            transfer::{Transfer, TransferStatement},
        };
        let (network, application) = ([1u8; 32], quil_execution::domains::QUIL_TOKEN);
        let mut outputs = submitted(application, 2, false).outputs;
        outputs[1].owner = [8; IDENTITY_BYTES];
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        let bytes = Transfer {
            statement: TransferStatement {
                network,
                application,
                depth: 32,
                root: Node::from_bytes(&[3u8; NODE_BYTES]).unwrap(),
                images: vec![[4; IDENTITY_BYTES], [5; IDENTITY_BYTES]],
                outputs: outputs.clone(),
                fee: 9,
            },
            proof,
        }
        .encode()
        .unwrap();
        let relayed = quil_execution::token_intrinsic::spend_entries::spend_entry(
            &network,
            &application,
            quil_execution::token_engine::TYPE_LATTICE_TRANSACTION,
            &bytes,
            55,
        )
        .unwrap();
        let s = Submitted::of(&network, application, &bytes).unwrap();
        assert_eq!(s.operation, relayed.tx_id);
        assert_eq!(s.outputs, outputs);
        assert_eq!((s.route, s.escrow), (Route::Designated, false));
        // The QUIL reward mint is GLOBAL's own: no commit decision to follow.
        let mut mint = bytes.clone();
        mint[..4].copy_from_slice(&quil_execution::token_engine::TYPE_LATTICE_MINT.to_be_bytes());
        assert!(Submitted::of(&network, application, &mint).is_none());
    }

    #[test]
    fn the_check_command_reads_through_the_same_node_and_config() {
        let quil = quil_execution::domains::QUIL_TOKEN;
        assert_eq!(
            check_command("qclient", &[], &quil, &[0xab; 32]),
            format!("qclient token inclusion 0x{} --wait 600", "ab".repeat(32))
        );
        let flags = ["--config".to_string(), "/a dir/it's".to_string()];
        assert_eq!(
            check_command("./qclient", &flags, &[9; 32], &[1; 32]),
            format!(
                "./qclient token inclusion 0x{} --application {} --config '/a dir/it'\\''s' --wait 600",
                "01".repeat(32),
                "09".repeat(32)
            )
        );
    }

    #[test]
    fn the_claim_command_names_the_saved_authorization() {
        assert_eq!(
            claim_command(
                "qclient",
                &["--read-rpc".into(), "/ip4/127.0.0.1/tcp/8337".into()],
                std::path::Path::new("/cfg/mint-965667.bin")
            ),
            "qclient token mint --claim /cfg/mint-965667.bin --read-rpc /ip4/127.0.0.1/tcp/8337 \
             --wait 600"
        );
    }

    #[test]
    fn a_decision_reports_its_frame_and_a_rejection_fails() {
        assert_eq!(
            decision_outcome("transfer", &Decision::Committed { frame: 42 }).unwrap(),
            "The transfer committed in GLOBAL frame 42."
        );
        let rejected = decision_outcome(
            "merge",
            &Decision::Rejected {
                frame: 43,
                reason: "already consumed".into(),
            },
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            rejected,
            "the merge was rejected by the global commit in GLOBAL frame 43: already consumed; \
             it spent and created nothing"
        );
        let pending = pending_message("split", 30, Some(7), "qclient token inclusion 0x01");
        assert!(
            pending.starts_with("the split is not committed after 30 s (GLOBAL head 7): "),
            "{pending}"
        );
        assert!(pending.ends_with("Check again with: qclient token inclusion 0x01"));
    }
}

//! `qclient node prover …` — prover status + lifecycle.
//!
//! Read subcommands (`status`, `shards`, `shardinfo`) and the lifecycle
//! write subcommands (`join`, `leave`, …). All prover commands talk to the
//! **local** node (`getNodeClient` always uses the local gRPC listener).

use std::collections::HashMap;

use clap::Subcommand;
use num_bigint::{BigInt, Sign};
use tonic::transport::Channel;

use quil_config::Config;
use quil_types::proto::diagnostics::{ConditionKind, ExpectedWait, HealthConditions};
use quil_types::proto::node::node_service_client::NodeServiceClient;
use quil_types::proto::node::GetWorkerInfoRequest;

use crate::context::GlobalArgs;
use crate::rpc::ConnectOpts;
use crate::util::UNITS_PER_QUIL;

pub mod epoch;
mod gossip_traffic;
mod join;
mod leave_check;
pub(crate) mod local_execution;
mod manage;
mod merge;
mod ops;
mod shardinfo;
mod shards;
pub(crate) mod sign;
mod status;

pub(super) use manage::command as manage_command;
pub use manage::ManageArgs;

#[derive(Debug, Subcommand)]
pub enum ProverCommand {
    /// List prover status and shard allocations.
    Status,
    /// List shards with estimated per-frame reward.
    Shards,
    /// List all known shards with prover counts and estimated rewards.
    Shardinfo,
    /// Interactive prover shard management TUI.
    Manage(ManageArgs),
    /// Joins the prover to the network for the given shard filters. Refused
    /// unless a free manual worker waits for each: an auto worker's join is
    /// decided by score. Switch workers to manual in `prover manage` first.
    Join {
        /// Hex-encoded 32-byte shard filters; at least one.
        filters: Vec<String>,
        /// Optional 32-byte hex reward delegate address.
        #[arg(long, default_value = "")]
        delegate: String,
    },
    /// Initiate a prover leave for the given shard filters. Refused while a
    /// filter is on an auto worker, whose leave the node would decide by score:
    /// switch it to manual in `prover manage` first.
    Leave {
        /// Hex-encoded 32-byte shard filters; at least one.
        filters: Vec<String>,
    },
    /// Confirm prover shard allocations for the given filters.
    Confirm { filters: Vec<String> },
    /// Reject prover shard allocations for the given filters.
    Reject { filters: Vec<String> },
    /// Pause the prover for a shard filter.
    Pause {
        /// Hex-encoded 32-byte shard filter (default: all-0xFF).
        filter: Option<String>,
    },
    /// Resume the prover for a shard filter.
    Resume { filter: Option<String> },
    /// Update the reward delegate address (32-byte hex).
    Delegate { address: String },
    /// Submit an alt-shard-update: `<v-adds> <v-removes> <he-adds> <he-removes>` roots.
    AltShardUpdate {
        /// The four root hashes (hex), in order.
        roots: Vec<String>,
    },
    /// Merge config data for prover seniority.
    Merge {
        /// Primary config dir followed by additional config dirs.
        configs: Vec<String>,
        /// Evaluate the seniority score without merging configs, and
        /// simulate on the local node a seniority succession to this
        /// node's prover from the prover the configs' peer keys name.
        #[arg(long = "dry-run", default_value_t = false)]
        dry_run: bool,
    },
}

/// Shared prover context (Go `getConfig` + `getNodeClient`).
pub struct ProverCtx {
    pub node_config: Config,
    /// The directory `node_config` was read from.
    pub config_dir: std::path::PathBuf,
    pub connect_opts: ConnectOpts,
    /// Key manager for signing prover ops (`q-prover-key` Falcon inner
    /// sig + `q-peer-key` Ed448 outer auth). Lazily needed only by the
    /// write ops.
    pub key_manager: std::sync::Arc<quil_keys::FileKeyManager>,
    /// The node's answer on the epoch's end, fixed by a test that serves no
    /// health report.
    #[cfg(test)]
    pub(crate) epoch_waits: Option<EpochWaits>,
}

impl ProverCtx {
    fn load(global: GlobalArgs) -> anyhow::Result<Self> {
        Self::load_with(global, false)
    }

    /// For a CLI command: refuses an empty keystore. The node manager uses
    /// `load`.
    fn load_cli(global: GlobalArgs) -> anyhow::Result<Self> {
        Self::load_with(global, true)
    }

    fn load_with(global: GlobalArgs, cli: bool) -> anyhow::Result<Self> {
        let ctx = crate::context::Context::load(global)?;
        let (node_config, dir) = ctx.load_node_config("default")?;
        let key_manager = if cli {
            ctx.cli_key_manager(&node_config, &dir)?
        } else {
            ctx.key_manager(&node_config, &dir)?
        };
        // Prover commands always use the local node (Go passes
        // lightNode=false unconditionally).
        let connect_opts = ConnectOpts {
            public_rpc: false,
            custom_rpc: String::new(),
            listen_grpc_multiaddr: node_config.listen_grpc_multiaddr.clone(),
        };
        Ok(Self {
            node_config,
            config_dir: dir,
            connect_opts,
            key_manager,
            #[cfg(test)]
            epoch_waits: None,
        })
    }

    pub async fn connect(&self) -> anyhow::Result<NodeServiceClient<Channel>> {
        crate::rpc::connect_node_service(&self.connect_opts).await
    }

    /// Where this node says whether the epoch ends too soon to sign: its
    /// health conditions, read on its peer listener as the node itself.
    pub(crate) fn epoch_waits(&self) -> EpochWaits {
        #[cfg(test)]
        if let Some(waits) = &self.epoch_waits {
            return waits.clone();
        }
        EpochWaits::Node(super::diagnostics::HealthSource::for_node(
            &self.node_config,
            &self.key_manager,
        ))
    }

    /// The frame to sign a pause, resume, leave or update with: the global
    /// head, once this node no longer holds prover ops for the next epoch.
    /// Every node refuses such an op landing in a later epoch than it was
    /// signed in, with nothing reported here, and it can sign in the next
    /// epoch just as well. Says so if it waits.
    pub async fn last_global_head_frame(
        &self,
        client: &mut NodeServiceClient<Channel>,
    ) -> anyhow::Result<u64> {
        let waits = self.epoch_waits();
        frame_clear_of_epoch_end(client, &waits, EPOCH_END_WAIT_CAP, EPOCH_END_POLL, |left| {
            println!(
                "The epoch ends in {left} frames, and an op signed now may land after it, where \
                 every node refuses it: waiting for the next epoch to sign."
            );
        })
        .await
    }

    /// The frame to sign a confirm or reject with: the global head at once, as
    /// each is valid only in this epoch. Warns when this node holds prover
    /// ops for the next epoch, as it may then land too late.
    pub async fn frame_in_this_epoch(
        &self,
        client: &mut NodeServiceClient<Channel>,
        op: &str,
    ) -> anyhow::Result<u64> {
        match self.epoch_waits().wait().await {
            Ok(Some(wait)) => println!(
                "The epoch ends in {} frames and this {op} is valid only in it: if it lands \
                 later every node refuses it. Check with `qclient node prover status`.",
                frames_left(&wait)
            ),
            Ok(None) => {}
            Err(error) => println!(
                "Cannot tell whether this {op} lands within the epoch: {error:#}. If it lands \
                 later every node refuses it. Check with `qclient node prover status`."
            ),
        }
        self.head_frame(client).await
    }

    /// The global head as it stands (`GetNodeInfo.last_global_head_frame`).
    pub async fn head_frame(&self, client: &mut NodeServiceClient<Channel>) -> anyhow::Result<u64> {
        head_frame(client).await
    }

    /// Send a global-domain prover message (outer Ed448 `q-peer-key`
    /// auth over the `0xFF×32` global domain).
    pub async fn send_global(
        &self,
        client: &mut NodeServiceClient<Channel>,
        request: quil_types::proto::global::MessageRequest,
    ) -> anyhow::Result<()> {
        crate::send::send_message_request(client, &self.key_manager, vec![0xFFu8; 32], request)
            .await
    }
}

/// How long to wait for the next epoch: the node's expected time for it, so
/// reaching it means GLOBAL is not advancing, or this node is not following it.
pub(crate) const EPOCH_END_WAIT_CAP: std::time::Duration =
    std::time::Duration::from_millis(quil_rpc::health_conditions::EPOCH_WAIT_EXPECTED_MS);
pub(crate) const EPOCH_END_POLL: std::time::Duration = std::time::Duration::from_secs(2);

/// Where a prover op learns whether to wait for the next epoch: this node's
/// health conditions, which judge the epoch's end on the head it serves.
#[derive(Clone)]
pub(crate) enum EpochWaits {
    Node(Result<super::diagnostics::HealthSource, String>),
    /// A fixed answer: the node's report, or why it could not be read.
    #[cfg(test)]
    Fixed(std::sync::Arc<dyn Fn() -> Result<Option<HealthConditions>, String> + Send + Sync>),
}

impl EpochWaits {
    /// The node's wait for the next epoch, if it holds prover ops; an
    /// error when it cannot say.
    pub(crate) async fn wait(&self) -> anyhow::Result<Option<ExpectedWait>> {
        let report = match self {
            Self::Node(Ok(source)) => source.read().await,
            Self::Node(Err(reason)) => Err(reason.clone()),
            #[cfg(test)]
            Self::Fixed(read) => read(),
        };
        let health = report.map_err(|e| {
            anyhow::anyhow!(
                "cannot read this node's health report, which says whether the epoch ends too \
                 soon to sign: {e}"
            )
        })?;
        epoch_wait_of(health.as_ref())
    }
}

/// The wait for the next epoch in a node's health conditions; an error
/// when they do not judge it: the node predates them, or knows no GLOBAL
/// head yet.
fn epoch_wait_of(health: Option<&HealthConditions>) -> anyhow::Result<Option<ExpectedWait>> {
    let kind = ConditionKind::ProverOpsWaitForEpoch as i32;
    let Some(health) = health else {
        anyhow::bail!(
            "this node predates its health conditions, which say whether the epoch ends too \
             soon to sign; update the node"
        );
    };
    if let Some(c) = health.conditions.iter().find(|c| c.kind == kind) {
        return Ok(Some(c.wait.unwrap_or_default()));
    }
    anyhow::ensure!(
        health
            .sources
            .iter()
            .any(|s| s.kind == kind && s.observed_unix_ms != 0),
        "this node does not judge the epoch's end: it knows no GLOBAL head yet, or predates \
         that judgement (update it)"
    );
    Ok(None)
}

/// The frames left in the epoch while the node holds prover ops.
fn frames_left(wait: &ExpectedWait) -> u64 {
    wait.until_frame.saturating_sub(wait.head_frame).max(1)
}

/// The global head once this node no longer holds prover ops for the next
/// epoch. `on_wait` hears the frames left, once, if this waits; past `cap`,
/// or when the node cannot say, nothing has been signed and the error says
/// why.
pub(crate) async fn frame_clear_of_epoch_end(
    client: &mut NodeServiceClient<Channel>,
    waits: &EpochWaits,
    cap: std::time::Duration,
    poll: std::time::Duration,
    mut on_wait: impl FnMut(u64),
) -> anyhow::Result<u64> {
    let started = std::time::Instant::now();
    let mut told = false;
    loop {
        let wait = waits
            .wait()
            .await
            .map_err(|e| anyhow::anyhow!("not sent: {e:#}"))?;
        let Some(wait) = wait else {
            return head_frame(client).await;
        };
        if !told {
            on_wait(frames_left(&wait));
            told = true;
        }
        if started.elapsed() >= cap {
            anyhow::bail!(
                "not sent: waited {}s for the next epoch and the global head stays at frame {}; \
                 check that this node follows GLOBAL",
                cap.as_secs(),
                wait.head_frame
            );
        }
        tokio::time::sleep(poll).await;
    }
}

/// The global head as the node serves it (`GetNodeInfo.last_global_head_frame`).
async fn head_frame(client: &mut NodeServiceClient<Channel>) -> anyhow::Result<u64> {
    let info = client
        .get_node_info(tonic::Request::new(
            quil_types::proto::node::GetNodeInfoRequest::default(),
        ))
        .await
        .map_err(|e| anyhow::anyhow!("get node info: {e}"))?
        .into_inner();
    Ok(info.last_global_head_frame)
}

pub async fn run(global: GlobalArgs, cmd: &ProverCommand) -> anyhow::Result<()> {
    // `merge` operates directly on config files; its dry run also reads
    // GLOBAL state from the local node.
    if let ProverCommand::Merge { configs, dry_run } = cmd {
        if *dry_run {
            return merge::dry_run(global, configs).await;
        }
        return merge::run(configs);
    }

    // The manager loads the node context itself, unless it only prints help.
    if let ProverCommand::Manage(args) = cmd {
        return manage::command(global, args).await;
    }

    let pc = ProverCtx::load_cli(global)?;
    match cmd {
        ProverCommand::Status => status::run(&pc).await,
        ProverCommand::Shards => shards::run(&pc).await,
        ProverCommand::Shardinfo => shardinfo::run(&pc).await,
        ProverCommand::Join { filters, delegate } => join::run(&pc, filters, delegate).await,
        ProverCommand::Leave { filters } => ops::leave(&pc, filters).await,
        ProverCommand::Confirm { filters } => ops::confirm(&pc, filters).await,
        ProverCommand::Reject { filters } => ops::reject(&pc, filters).await,
        ProverCommand::Pause { filter } => ops::pause(&pc, filter.as_deref()).await,
        ProverCommand::Resume { filter } => ops::resume(&pc, filter.as_deref()).await,
        ProverCommand::Delegate { address } => ops::delegate(&pc, address).await,
        ProverCommand::AltShardUpdate { roots } => ops::alt_shard_update(&pc, roots).await,
        ProverCommand::Merge { .. } | ProverCommand::Manage(_) => unreachable!("handled above"),
    }
}

/// `workerByFilter` — map hex filter → core id from `GetWorkerInfo`.
pub(crate) async fn worker_by_filter(
    client: &mut NodeServiceClient<Channel>,
) -> HashMap<String, u32> {
    let mut m = HashMap::new();
    if let Ok(resp) = client
        .get_worker_info(tonic::Request::new(GetWorkerInfoRequest::default()))
        .await
    {
        for w in resp.into_inner().worker_info {
            m.insert(hex::encode(&w.filter), w.core_id);
        }
    }
    m
}

/// `formatStorage` — human-readable byte size (1 decimal).
pub(crate) fn format_storage(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;
    let b = bytes as f64;
    if bytes >= TB {
        format!("{:.1} TB", b / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", b / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", b / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", b / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// The `Size [MB]` cell — bytes as megabytes, one decimal, bare number.
///
/// The column states its unit in the header so the cells stay short and stay
/// comparable at a glance; that is worth keeping. What it cost was the bottom
/// of the range: one decimal of a megabyte resolves to ~52 KB, so every shard
/// under that printed `0.0`, identical to an empty one.
///
/// A non-zero size that would round to `0.0` prints `<0.1` instead. It is an
/// upper bound in the column's own unit, it right-aligns on the same decimal
/// column as every other cell, and it sorts and filters as the byte value it
/// really is — only the rendering changes.
/// Decimal GB, with small nonzero amounts distinct from an empty shard.
pub(crate) fn format_gb(v: &BigInt) -> String {
    if v.sign() != Sign::Plus {
        return "0.0".into();
    }
    let tenths =
        (v * BigInt::from(10) + BigInt::from(500_000_000u64)) / BigInt::from(1_000_000_000u64);
    if tenths == BigInt::from(0) {
        return "<0.1".into();
    }
    format!("{}.{}", &tenths / 10, &tenths % 10)
}

/// `framesPerDay` — frames in 24h at a 10s target frame time.
const FRAMES_PER_DAY: u64 = 24 * 60 * 60 / 10; // 8640

/// Per-frame reward as QUIL/day, rounded to one decimal. Preserve tiny
/// positive rewards as `<0.1` instead of presenting them as zero.
pub(crate) fn format_quil_daily_round(per_frame: &BigInt) -> String {
    let raw = per_frame * BigInt::from(FRAMES_PER_DAY);
    if raw.sign() != Sign::Plus {
        return "0.0".to_string();
    }
    let tenths = (raw + BigInt::from(UNITS_PER_QUIL / 20)) / BigInt::from(UNITS_PER_QUIL / 10);
    if tenths.sign() != Sign::Plus {
        return "<0.1".to_string();
    }
    format!("{}.{}", &tenths / 10, &tenths % 10)
}

pub(crate) fn format_quil_daily_units(v: &BigInt) -> String {
    let negative = v.sign() == Sign::Minus;
    let magnitude = if negative { -v } else { v.clone() };
    let tenths =
        (&magnitude + BigInt::from(UNITS_PER_QUIL / 20)) / BigInt::from(UNITS_PER_QUIL / 10);
    let text = if magnitude > BigInt::from(0) && tenths == BigInt::from(0) {
        "<0.1".into()
    } else {
        format!("{}.{}", &tenths / 10, &tenths % 10)
    };
    format!("~{}{text}", if negative { "-" } else { "" })
}
/// Signers a shard frame's finalization certificate carries for an
/// `n`-member committee: simplex stops verifying finalize votes at its
/// `N3f1` quorum, `n - (n - 1) / 3`, and a frame credits only those signers.
pub(crate) fn quorum_signers(n: u32) -> u32 {
    n - n.saturating_sub(1) / 3
}

/// A shard's frame committee: its active provers and seated leavers
/// (`get_active_provers`); joining and paused provers do not sign. Servers
/// without phase counts give only the live count, which includes them.
pub(crate) fn committee_size(shard: &quil_types::proto::node::ShardRewardInfo) -> u32 {
    shard
        .prover_counts
        .as_ref()
        .map_or(shard.active_provers, |c| c.active + c.leaving + c.departing)
}

/// A cadence window with enough coverage to read. The node withholds a cadence
/// once its latest sample is over 90s old, so freshness on arrival is the node's
/// call on its own clock; the client's clock takes no part.
pub(crate) fn observed_window(
    cadence: &quil_types::proto::node::FrameCadence,
    day: bool,
) -> Option<&quil_types::proto::node::FrameWindow> {
    let w = if day {
        cadence.day.as_ref()?
    } else {
        cadence.hour.as_ref()?
    };
    (w.observed_seconds >= 60 && w.observed_seconds <= w.window_seconds).then_some(w)
}

/// The share of a shard's frames that pay a seat: `paid` of `frames`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SigningShare {
    pub paid: u64,
    pub frames: u64,
    /// The seat's own certificate share, as the node counted it; else the
    /// share a member voting in time signs, quorum of committee.
    pub measured: bool,
}

/// [`SigningShare`] of a seat in the 60m or 24h window. GLOBAL credits each
/// signer of a frame's certificate the same per-signer reward, so a seat
/// earns the frames it signs: its own share once the node counted a frame
/// in the window, else [`quorum_signers`] of `committee`. A committee of 0
/// or 1 pays every frame.
pub(crate) fn signing_share(
    share: Option<&quil_types::proto::node::CertificateShare>,
    day: bool,
    committee: u32,
) -> SigningShare {
    let own = share.and_then(|s| if day { s.day.as_ref() } else { s.hour.as_ref() });
    if let Some(w) = own.filter(|w| w.frames > 0) {
        return SigningShare {
            paid: w.signed_frames.min(w.frames),
            frames: w.frames,
            measured: true,
        };
    }
    let n = committee.max(1);
    SigningShare {
        paid: u64::from(quorum_signers(n)),
        frames: u64::from(n),
        measured: false,
    }
}

/// Observed QUIL/day of a seat on a shard: the shard's observed frame rate
/// times the [`signing_share`] of its frames that pay the seat.
pub(crate) fn observed_quil_daily(
    per_frame: &BigInt,
    cadence: &quil_types::proto::node::FrameCadence,
    day: bool,
    committee: u32,
    share: Option<&quil_types::proto::node::CertificateShare>,
) -> Option<BigInt> {
    let w = observed_window(cadence, day)?;
    let s = signing_share(share, day, committee);
    Some(
        per_frame * BigInt::from(w.advanced_frames) * BigInt::from(86400) * BigInt::from(s.paid)
            / (BigInt::from(w.observed_seconds) * BigInt::from(s.frames)),
    )
}

/// QUIL/day of a seat that signs every frame of a shard producing one frame
/// per GLOBAL frame, the most GLOBAL credits a shard: at the measured GLOBAL
/// interval (its 24h window, else its 60m one), or the 10s target while
/// none is measured.
pub(crate) fn theory_quil_daily(
    per_frame: &BigInt,
    global: Option<&quil_types::proto::node::FrameCadence>,
) -> BigInt {
    let measured = global.and_then(|c| {
        [true, false]
            .into_iter()
            .find_map(|day| observed_window(c, day).filter(|w| w.advanced_frames > 0))
    });
    match measured {
        Some(w) => {
            per_frame * BigInt::from(w.advanced_frames) * BigInt::from(86400)
                / BigInt::from(w.observed_seconds)
        }
        None => per_frame * BigInt::from(FRAMES_PER_DAY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// The node's answer on `head`: its health registry judges the epoch's
    /// end as it serves a report.
    pub(crate) fn node_waits(head: Arc<AtomicU64>) -> EpochWaits {
        EpochWaits::Fixed(Arc::new(move || {
            let mut registry = quil_rpc::health_conditions::HealthRegistry::default();
            registry.refresh_waits(
                quil_rpc::health_conditions::GlobalObservation {
                    head_frame: head.load(Ordering::SeqCst),
                    epoch_length: quil_types::consensus::epoch_length_frames(),
                    ..Default::default()
                },
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            );
            Ok(Some(registry.snapshot()))
        }))
    }

    /// A node that judged the epoch's end and holds no prover ops (its head
    /// at an epoch's first frame): what a command test serving no health
    /// report signs with.
    pub(crate) fn no_epoch_wait() -> Option<EpochWaits> {
        let length = quil_types::consensus::epoch_length_frames();
        Some(node_waits(Arc::new(AtomicU64::new(length))))
    }

    /// A client on a node whose global head is `head`.
    async fn client_at(head: Arc<AtomicU64>) -> NodeServiceClient<Channel> {
        let mut server = quil_rpc::NodeRpcServer::default();
        server.last_global_head_frame = head;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let multiaddr = format!(
            "/ip4/127.0.0.1/tcp/{}",
            listener.local_addr().unwrap().port()
        );
        let incoming = futures::stream::unfold(listener, |listener| async {
            let result = listener.accept().await.map(|(socket, _)| socket);
            Some((result, listener))
        });
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    quil_types::proto::node::node_service_server::NodeServiceServer::new(server),
                )
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });
        crate::rpc::connect_node_service(&ConnectOpts {
            listen_grpc_multiaddr: multiaddr,
            ..Default::default()
        })
        .await
        .unwrap()
    }

    /// Near the epoch's end the frame comes only from the next epoch, and the
    /// wait is announced once; clear of it, at once and in silence.
    #[tokio::test]
    async fn signing_waits_out_the_end_of_an_epoch() {
        let length = quil_types::consensus::epoch_length_frames();
        let head = Arc::new(AtomicU64::new(length - 1));
        let mut client = client_at(head.clone()).await;
        let advance = head.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            advance.store(length + 3, Ordering::SeqCst);
        });
        let waits = node_waits(head.clone());
        let mut told = Vec::new();
        let frame = tokio::time::timeout(
            Duration::from_secs(20),
            frame_clear_of_epoch_end(
                &mut client,
                &waits,
                Duration::from_secs(15),
                Duration::from_millis(50),
                |left| told.push(left),
            ),
        )
        .await
        .expect("the wait ends with the epoch")
        .unwrap();
        assert_eq!(frame, length + 3);
        assert_eq!(told, vec![1]);

        told.clear();
        let frame = frame_clear_of_epoch_end(
            &mut client,
            &waits,
            Duration::from_secs(15),
            Duration::from_millis(50),
            |left| told.push(left),
        )
        .await
        .unwrap();
        assert_eq!(frame, length + 3);
        assert!(told.is_empty());
    }

    /// The bound and its recovery: a head that stays near the end stops the
    /// wait with the reason, nothing signed, and the next call goes on.
    #[tokio::test]
    async fn a_stalled_head_ends_the_wait_with_the_reason() {
        let length = quil_types::consensus::epoch_length_frames();
        let head = Arc::new(AtomicU64::new(length - 1));
        let mut client = client_at(head.clone()).await;
        let waits = node_waits(head.clone());
        let error = tokio::time::timeout(
            Duration::from_secs(20),
            frame_clear_of_epoch_end(
                &mut client,
                &waits,
                Duration::from_millis(200),
                Duration::from_millis(50),
                |_| {},
            ),
        )
        .await
        .expect("the wait is bounded")
        .unwrap_err()
        .to_string();
        assert!(error.starts_with("not sent: waited"), "{error}");
        assert!(error.contains(&format!("frame {}", length - 1)), "{error}");
        head.store(length, Ordering::SeqCst);
        let frame = frame_clear_of_epoch_end(
            &mut client,
            &waits,
            Duration::from_millis(200),
            Duration::from_millis(50),
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(frame, length);
    }

    /// Nothing is signed when the node cannot say whether the epoch ends
    /// too soon: its report unreadable, predating its conditions, or not
    /// judging the epoch's end (no GLOBAL head yet); each says why.
    #[tokio::test]
    async fn an_op_is_not_signed_without_the_nodes_answer() {
        let length = quil_types::consensus::epoch_length_frames();
        let mut client = client_at(Arc::new(AtomicU64::new(length / 2))).await;
        let fixed = |answer: Result<Option<HealthConditions>, String>| {
            EpochWaits::Fixed(Arc::new(move || answer.clone()))
        };
        let unjudged = HealthConditions {
            sources: vec![quil_types::proto::diagnostics::ConditionSource {
                kind: ConditionKind::ProverOpsWaitForEpoch as i32,
                observed_unix_ms: 0,
                tracked: 0,
            }],
            ..Default::default()
        };
        for (waits, why) in [
            (
                fixed(Err("connect to this node's peer listener: refused".into())),
                "cannot read this node's health report",
            ),
            (fixed(Ok(None)), "this node predates its health conditions"),
            (fixed(Ok(Some(unjudged))), "it knows no GLOBAL head yet"),
            (
                fixed(Ok(Some(HealthConditions::default()))),
                "does not judge the epoch's end",
            ),
        ] {
            let error = frame_clear_of_epoch_end(
                &mut client,
                &waits,
                Duration::from_millis(200),
                Duration::from_millis(50),
                |_| panic!("no wait to tell"),
            )
            .await
            .unwrap_err()
            .to_string();
            assert!(error.starts_with("not sent: "), "{error}");
            assert!(error.contains(why), "{why} in {error}");
        }
        // The node judged it and holds nothing: signed at once.
        let frame = frame_clear_of_epoch_end(
            &mut client,
            &node_waits(Arc::new(AtomicU64::new(length / 2))),
            Duration::from_millis(200),
            Duration::from_millis(50),
            |_| panic!("no wait to tell"),
        )
        .await
        .unwrap();
        assert_eq!(frame, length / 2);
    }

    #[test]
    fn format_storage_units() {
        assert_eq!(format_storage(512), "512 B");
        assert_eq!(format_storage(1536), "1.5 KB");
        assert_eq!(format_storage(1024 * 1024), "1.0 MB");
    }

    #[test]
    fn format_gb_uses_decimal_units_and_retains_small_shards() {
        for (bytes, expected) in [
            (0, "0.0"),
            (2048, "<0.1"),
            (49_999_999, "<0.1"),
            (50_000_000, "0.1"),
            (1_000_000_000, "1.0"),
            (1_673_583_448, "1.7"),
        ] {
            assert_eq!(format_gb(&BigInt::from(bytes)), expected);
        }
    }

    #[test]
    fn format_quil_daily_round_separates_a_trickle_from_nothing() {
        // `per_frame` is scaled by FRAMES_PER_DAY, so 1 unit/frame is
        // 8640 units/day = 0.0000864 QUIL/day — a trickle, but not zero.
        assert_eq!(format_quil_daily_round(&BigInt::from(0)), "0.0");
        assert_eq!(format_quil_daily_round(&BigInt::from(1u64)), "<0.1");
        // Values immediately around 0.5 QUIL/day share the same tenth.
        let half = BigInt::from(UNITS_PER_QUIL / 2 / FRAMES_PER_DAY); // 462962 -> 0.4999…
        assert_eq!(format_quil_daily_round(&half), "0.5");
        assert_eq!(format_quil_daily_round(&(half + BigInt::from(1))), "0.5");
        // A reported total of 269.9 QUIL/day.
        assert_eq!(
            format_quil_daily_round(&BigInt::from(249_921_760u64)),
            "269.9"
        );
        // 8e9 units (one QUIL) per day is 1.0, not 80x more.
        assert_eq!(
            format_quil_daily_round(&BigInt::from(UNITS_PER_QUIL / FRAMES_PER_DAY)),
            "1.0"
        );
        assert_eq!(
            format_quil_daily_units(&BigInt::from(UNITS_PER_QUIL)),
            "~1.0"
        );
        assert_eq!(
            format_quil_daily_units(&BigInt::from(UNITS_PER_QUIL / 20 - 1)),
            "~<0.1"
        );
        // Per-shard rates observed on a live node collapse to a handful of
        // tiers, and the ~15x spread that drives a join decision survives.
        assert_eq!(format_quil_daily_round(&BigInt::from(359_840u64)), "0.4");
        assert_eq!(format_quil_daily_round(&BigInt::from(5_432_000u64)), "5.9");
        assert_eq!(
            format_quil_daily_round(&BigInt::from(21_440_000u64)),
            "23.2"
        );
    }
}

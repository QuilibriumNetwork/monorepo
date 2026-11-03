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
    /// Joins the prover to the network for the given shard filters.
    Join {
        /// Hex-encoded 32-byte shard filters (default: all-0xFF).
        filters: Vec<String>,
        /// Optional 32-byte hex reward delegate address.
        #[arg(long, default_value = "")]
        delegate: String,
    },
    /// Initiate a prover leave for the given shard filters. Refused while a
    /// filter is on an auto worker, whose leave the node would decide by score:
    /// switch it to manual in `prover manage` first.
    Leave {
        /// Hex-encoded 32-byte shard filters (default: all-0xFF).
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
}

impl ProverCtx {
    fn load(global: GlobalArgs) -> anyhow::Result<Self> {
        let ctx = crate::context::Context::load(global)?;
        let (node_config, dir) = ctx.load_node_config("default")?;
        let key_manager = ctx.key_manager(&node_config, &dir)?;
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
        })
    }

    pub async fn connect(&self) -> anyhow::Result<NodeServiceClient<Channel>> {
        crate::rpc::connect_node_service(&self.connect_opts).await
    }

    /// The frame to sign a pause, resume, leave or update with: the global
    /// head, once it is clear of the epoch's end. Every node refuses such an op
    /// landing in a later epoch than it was signed in, with nothing reported
    /// here, and it can sign in the next epoch just as well. Says so if it waits.
    pub async fn last_global_head_frame(
        &self,
        client: &mut NodeServiceClient<Channel>,
    ) -> anyhow::Result<u64> {
        frame_clear_of_epoch_end(client, EPOCH_END_WAIT_CAP, EPOCH_END_POLL, |left| {
            println!(
                "The epoch ends in {left} frames, and an op signed now may land after it, where \
                 every node refuses it: waiting for the next epoch to sign."
            );
        })
        .await
    }

    /// The frame to sign a confirm or reject with: the global head at once, as
    /// each is valid only in this epoch. Warns when it may land too late.
    pub async fn frame_in_this_epoch(
        &self,
        client: &mut NodeServiceClient<Channel>,
        op: &str,
    ) -> anyhow::Result<u64> {
        let (head, epoch_length) = head_and_epoch_length(client).await?;
        if let Some(left) = frames_left_if_close(head, epoch_length) {
            println!(
                "The epoch ends in {left} frames and this {op} is valid only in it: if it lands \
                 later every node refuses it. Check with `qclient node prover status`."
            );
        }
        Ok(head)
    }

    /// The global head as it stands (`GetNodeInfo.last_global_head_frame`).
    pub async fn head_frame(&self, client: &mut NodeServiceClient<Channel>) -> anyhow::Result<u64> {
        let info = client
            .get_node_info(tonic::Request::new(
                quil_types::proto::node::GetNodeInfoRequest::default(),
            ))
            .await
            .map_err(|e| anyhow::anyhow!("get node info: {e}"))?
            .into_inner();
        Ok(info.last_global_head_frame)
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

/// Frames an op takes to land at most: every node refuses one older.
const EPOCH_END_MARGIN_FRAMES: u64 =
    quil_execution::global_intrinsic::verify::PROVER_OP_FRESHNESS_WINDOW;
/// How long to wait for the next epoch: ten mainnet frames many times over, so
/// reaching it means GLOBAL is not advancing, or this node is not following it.
pub(crate) const EPOCH_END_WAIT_CAP: std::time::Duration = std::time::Duration::from_secs(600);
pub(crate) const EPOCH_END_POLL: std::time::Duration = std::time::Duration::from_secs(2);

/// The frames left in the epoch, if an op signed at `head` may not land in it.
/// At most half of an epoch, so a short devnet epoch keeps a time to sign.
fn frames_left_if_close(head: u64, epoch_length: u64) -> Option<u64> {
    let length = epoch::epoch_len(epoch_length);
    let left = length - head % length;
    (left <= EPOCH_END_MARGIN_FRAMES.min(length / 2)).then_some(left)
}

async fn head_and_epoch_length(
    client: &mut NodeServiceClient<Channel>,
) -> anyhow::Result<(u64, u64)> {
    let info = client
        .get_node_info(tonic::Request::new(
            quil_types::proto::node::GetNodeInfoRequest::default(),
        ))
        .await
        .map_err(|e| anyhow::anyhow!("get node info: {e}"))?
        .into_inner();
    Ok((info.last_global_head_frame, info.epoch_length_frames))
}

/// The global head once it is clear of the epoch's end. `on_wait` hears the
/// frames left, once, if this waits; past `cap` nothing has been signed and the
/// error says why.
pub(crate) async fn frame_clear_of_epoch_end(
    client: &mut NodeServiceClient<Channel>,
    cap: std::time::Duration,
    poll: std::time::Duration,
    mut on_wait: impl FnMut(u64),
) -> anyhow::Result<u64> {
    let started = std::time::Instant::now();
    let mut told = false;
    loop {
        let (head, epoch_length) = head_and_epoch_length(client).await?;
        let Some(left) = frames_left_if_close(head, epoch_length) else {
            return Ok(head);
        };
        if !told {
            on_wait(left);
            told = true;
        }
        if started.elapsed() >= cap {
            anyhow::bail!(
                "not sent: waited {}s for the next epoch and the global head stays at frame \
                 {head}; check that this node follows GLOBAL",
                cap.as_secs()
            );
        }
        tokio::time::sleep(poll).await;
    }
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

    let pc = ProverCtx::load(global)?;
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
pub(crate) fn observed_quil_daily(
    per_frame: &BigInt,
    cadence: &quil_types::proto::node::FrameCadence,
    day: bool,
    now: u64,
) -> Option<BigInt> {
    if now < cadence.last_observed_unix_seconds || now - cadence.last_observed_unix_seconds > 90 {
        return None;
    }
    let w = if day {
        cadence.day.as_ref()?
    } else {
        cadence.hour.as_ref()?
    };
    if w.observed_seconds < 60 || w.observed_seconds > w.window_seconds {
        return None;
    }
    Some(
        per_frame * BigInt::from(w.advanced_frames) * BigInt::from(86400)
            / BigInt::from(w.observed_seconds),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// Only the last frames of an epoch, where an op may land in the next one:
    /// the freshness window on a mainnet epoch, half of a short devnet one.
    #[test]
    fn only_the_end_of_an_epoch_is_too_close_to_sign() {
        assert_eq!(frames_left_if_close(720 - 11, 720), None);
        assert_eq!(frames_left_if_close(720 - 10, 720), Some(10));
        assert_eq!(frames_left_if_close(719, 720), Some(1));
        assert_eq!(frames_left_if_close(720, 720), None);
        assert_eq!(frames_left_if_close(89, 30), Some(1));
        assert_eq!(frames_left_if_close(79, 30), None);
        assert_eq!(frames_left_if_close(80, 30), Some(10));
        assert_eq!(frames_left_if_close(4, 10), None);
        assert_eq!(frames_left_if_close(5, 10), Some(5));
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
        let mut told = Vec::new();
        let frame = tokio::time::timeout(
            Duration::from_secs(20),
            frame_clear_of_epoch_end(
                &mut client,
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
        let error = tokio::time::timeout(
            Duration::from_secs(20),
            frame_clear_of_epoch_end(
                &mut client,
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
            Duration::from_millis(200),
            Duration::from_millis(50),
            |_| {},
        )
        .await
        .unwrap();
        assert_eq!(frame, length);
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

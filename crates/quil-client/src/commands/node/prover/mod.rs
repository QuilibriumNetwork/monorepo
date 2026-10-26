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
use crate::util::UNITS_PER_QUIL;
use crate::rpc::ConnectOpts;

pub mod epoch;
mod join;
mod manage;
mod merge;
mod ops;
mod shardinfo;
mod shards;
pub(crate) mod sign;
mod status;
pub(crate) mod local_execution;

#[derive(Debug, Subcommand)]
pub enum ProverCommand {
    /// List prover status and shard allocations.
    Status,
    /// List shards with estimated per-frame reward.
    Shards,
    /// List all known shards with prover counts and estimated rewards.
    Shardinfo,
    /// Interactive prover shard management TUI.
    Manage {
        /// Print one frame as plain text and exit, after fetching once and
        /// applying --keys; never runs joins, lifecycle operations or worker
        /// changes.
        #[arg(long)]
        render: bool,
        /// Print the TUI help as plain text and exit.
        #[arg(long)]
        help_text: bool,
        /// Width of --render and --help-text, in columns.
        #[arg(long, default_value_t = 160)]
        width: u16,
        /// Height of --render, in rows.
        #[arg(long, default_value_t = 50)]
        height: u16,
        /// Keys applied before --render draws, space-separated (e.g. "n Tab Down").
        #[arg(long, default_value = "")]
        keys: String,
        /// Draw --render with colors on, as interactively; plain text then
        /// loses the warnings that the default marks with `!`.
        #[arg(long)]
        color: bool,
        /// Seconds --render waits for the node's answers.
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },
    /// Joins the prover to the network for the given shard filters.
    Join {
        /// Hex-encoded 32-byte shard filters (default: all-0xFF).
        filters: Vec<String>,
        /// Optional 32-byte hex reward delegate address.
        #[arg(long, default_value = "")]
        delegate: String,
    },
    /// Initiate a prover leave for the given shard filters.
    Leave {
        /// Hex-encoded 32-byte shard filters (default: all-0xFF).
        filters: Vec<String>,
    },
    /// Confirm prover shard allocations for the given filters.
    Confirm {
        filters: Vec<String>,
    },
    /// Reject prover shard allocations for the given filters.
    Reject {
        filters: Vec<String>,
    },
    /// Pause the prover for a shard filter.
    Pause {
        /// Hex-encoded 32-byte shard filter (default: all-0xFF).
        filter: Option<String>,
    },
    /// Resume the prover for a shard filter.
    Resume {
        filter: Option<String>,
    },
    /// Update the reward delegate address (32-byte hex).
    Delegate {
        address: String,
    },
    /// Submit an alt-shard-update: `<v-adds> <v-removes> <he-adds> <he-removes>` roots.
    AltShardUpdate {
        /// The four root hashes (hex), in order.
        roots: Vec<String>,
    },
    /// Merge config data for prover seniority.
    Merge {
        /// Primary config dir followed by additional config dirs.
        configs: Vec<String>,
        /// Evaluate the seniority score without merging configs.
        #[arg(long = "dry-run", default_value_t = false)]
        dry_run: bool,
    },
}

/// Shared prover context (Go `getConfig` + `getNodeClient`).
pub struct ProverCtx {
    #[allow(dead_code)]
    pub node_config: Config,
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
            connect_opts,
            key_manager,
        })
    }

    pub async fn connect(&self) -> anyhow::Result<NodeServiceClient<Channel>> {
        crate::rpc::connect_node_service(&self.connect_opts).await
    }

    /// The current global head frame (`GetNodeInfo.last_global_head_frame`),
    /// used as the frame number for prover-op signatures.
    pub async fn last_global_head_frame(
        &self,
        client: &mut NodeServiceClient<Channel>,
    ) -> anyhow::Result<u64> {
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
        crate::send::send_message_request(
            client,
            &self.key_manager,
            vec![0xFFu8; 32],
            request,
        )
        .await
    }
}

pub async fn run(global: GlobalArgs, cmd: &ProverCommand) -> anyhow::Result<()> {
    // `merge` operates directly on config files — no node connection.
    if let ProverCommand::Merge { configs, dry_run } = cmd {
        return merge::run(configs, *dry_run);
    }

    if let ProverCommand::Manage { help_text: true, width, .. } = cmd {
        print!("{}", manage::help_text(*width));
        return Ok(());
    }

    let pc = ProverCtx::load(global)?;
    match cmd {
        ProverCommand::Status => status::run(&pc).await,
        ProverCommand::Shards => shards::run(&pc).await,
        ProverCommand::Shardinfo => shardinfo::run(&pc).await,
        ProverCommand::Manage { render: true, width, height, keys, color, timeout, .. } => {
            manage::render(&pc, manage::RenderOptions {
                width: *width,
                height: *height,
                keys: keys.split_whitespace().map(str::to_string).collect(),
                color: *color,
                timeout: std::time::Duration::from_secs(*timeout),
            })
            .await
        }
        ProverCommand::Manage { .. } => manage::run(&pc).await,
        ProverCommand::Join { filters, delegate } => join::run(&pc, filters, delegate).await,
        ProverCommand::Leave { filters } => ops::leave(&pc, filters).await,
        ProverCommand::Confirm { filters } => ops::confirm(&pc, filters).await,
        ProverCommand::Reject { filters } => ops::reject(&pc, filters).await,
        ProverCommand::Pause { filter } => ops::pause(&pc, filter.as_deref()).await,
        ProverCommand::Resume { filter } => ops::resume(&pc, filter.as_deref()).await,
        ProverCommand::Delegate { address } => ops::delegate(&pc, address).await,
        ProverCommand::AltShardUpdate { roots } => ops::alt_shard_update(&pc, roots).await,
        ProverCommand::Merge { .. } => unreachable!("handled above"),
    }
}

/// `workerByFilter` — map hex filter → core id from `GetWorkerInfo`.
pub(crate) async fn worker_by_filter(client: &mut NodeServiceClient<Channel>) -> HashMap<String, u32> {
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
    if v.sign() != Sign::Plus { return "0.0".into(); }
    let tenths = (v * BigInt::from(10) + BigInt::from(500_000_000u64)) / BigInt::from(1_000_000_000u64);
    if tenths == BigInt::from(0) { return "<0.1".into(); }
    format!("{}.{}", &tenths / 10, &tenths % 10)
}

/// `framesPerDay` — frames in 24h at a 10s target frame time.
const FRAMES_PER_DAY: u64 = 24 * 60 * 60 / 10; // 8640

/// Per-frame reward as QUIL/day, rounded to one decimal. Preserve tiny
/// positive rewards as `<0.1` instead of presenting them as zero.
pub(crate) fn format_quil_daily_round(per_frame: &BigInt) -> String {
    let raw = per_frame * BigInt::from(FRAMES_PER_DAY);
    if raw.sign() != Sign::Plus { return "0.0".to_string(); }
    let tenths = (raw + BigInt::from(UNITS_PER_QUIL / 20)) / BigInt::from(UNITS_PER_QUIL / 10);
    if tenths.sign() != Sign::Plus { return "<0.1".to_string(); }
    format!("{}.{}", &tenths / 10, &tenths % 10)
}

pub(crate) fn format_quil_daily_units(v: &BigInt) -> String {
    let negative = v.sign() == Sign::Minus;
    let magnitude = if negative { -v } else { v.clone() };
    let tenths = (&magnitude + BigInt::from(UNITS_PER_QUIL / 20)) / BigInt::from(UNITS_PER_QUIL / 10);
    let text = if magnitude > BigInt::from(0) && tenths == BigInt::from(0) { "<0.1".into() }
        else { format!("{}.{}", &tenths / 10, &tenths % 10) };
    format!("~{}{text}", if negative { "-" } else { "" })
}
pub(crate) fn observed_quil_daily(per_frame: &BigInt, cadence: &quil_types::proto::node::FrameCadence, day: bool, now: u64) -> Option<BigInt> {
    if now < cadence.last_observed_unix_seconds || now - cadence.last_observed_unix_seconds > 90 { return None; }
    let w = if day { cadence.day.as_ref()? } else { cadence.hour.as_ref()? };
    if w.observed_seconds < 60 || w.observed_seconds > w.window_seconds { return None; }
    Some(per_frame * BigInt::from(w.advanced_frames) * BigInt::from(86400) / BigInt::from(w.observed_seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_storage_units() {
        assert_eq!(format_storage(512), "512 B");
        assert_eq!(format_storage(1536), "1.5 KB");
        assert_eq!(format_storage(1024 * 1024), "1.0 MB");
    }

    #[test]
    fn format_gb_uses_decimal_units_and_retains_small_shards() {
        for (bytes, expected) in [(0, "0.0"), (2048, "<0.1"), (49_999_999, "<0.1"),
            (50_000_000, "0.1"), (1_000_000_000, "1.0"), (1_673_583_448, "1.7")] {
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
        assert_eq!(format_quil_daily_round(&BigInt::from(249_921_760u64)), "269.9");
        // 8e9 units (one QUIL) per day is 1.0, not 80x more.
        assert_eq!(format_quil_daily_round(&BigInt::from(UNITS_PER_QUIL / FRAMES_PER_DAY)), "1.0");
        assert_eq!(format_quil_daily_units(&BigInt::from(UNITS_PER_QUIL)), "~1.0");
        assert_eq!(format_quil_daily_units(&BigInt::from(UNITS_PER_QUIL / 20 - 1)), "~<0.1");
        // Per-shard rates observed on a live node collapse to a handful of
        // tiers, and the ~15x spread that drives a join decision survives.
        assert_eq!(format_quil_daily_round(&BigInt::from(359_840u64)), "0.4");
        assert_eq!(format_quil_daily_round(&BigInt::from(5_432_000u64)), "5.9");
        assert_eq!(format_quil_daily_round(&BigInt::from(21_440_000u64)), "23.2");
    }
}

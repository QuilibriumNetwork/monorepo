//! `qclient node prover …` — prover status + lifecycle.
//!
//! Read subcommands (`status`, `shards`, `shardinfo`) are implemented
//! here; the lifecycle write subcommands (`join`, `leave`, …) are added
//! in a later phase. All prover commands talk to the **local** node
//! (`getNodeClient` always uses the local gRPC listener).

use std::collections::HashMap;

use clap::Subcommand;
use num_bigint::{BigInt, Sign};
use tonic::transport::Channel;

use quil_config::Config;
use quil_types::proto::node::node_service_client::NodeServiceClient;
use quil_types::proto::node::GetWorkerInfoRequest;

use crate::context::GlobalArgs;
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

#[derive(Debug, Subcommand)]
pub enum ProverCommand {
    /// List prover status and shard allocations.
    Status,
    /// List shards with estimated per-frame reward.
    Shards,
    /// List all known shards with prover counts and estimated rewards.
    Shardinfo,
    /// Interactive prover shard management TUI.
    Manage,
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

    let pc = ProverCtx::load(global)?;
    match cmd {
        ProverCommand::Status => status::run(&pc).await,
        ProverCommand::Shards => shards::run(&pc).await,
        ProverCommand::Shardinfo => shardinfo::run(&pc).await,
        ProverCommand::Manage => manage::run(&pc).await,
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

/// `formatQUIL` — reward units (1 QUIL = 10^8 units) → 8-decimal string.
/// NOTE: distinct from the token module's 8e9/12-decimal balance format.
pub(crate) fn format_quil_reward(raw: &BigInt) -> String {
    if raw.sign() == Sign::NoSign {
        return "0.00000000".to_string();
    }
    let divisor = BigInt::from(100_000_000u64); // 10^8
    let whole = raw / &divisor;
    let frac = raw % &divisor;
    // frac fits in i64; pad to 8 digits.
    format!("{whole}.{:0>8}", frac.to_string())
}

/// `framesPerDay` — frames in 24h at a 10s target frame time.
const FRAMES_PER_DAY: u64 = 24 * 60 * 60 / 10; // 8640

/// `formatQUILDaily` — per-frame reward → estimated 24h total.
pub(crate) fn format_quil_daily(per_frame: &BigInt) -> String {
    format_quil_reward(&(per_frame * BigInt::from(FRAMES_PER_DAY)))
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
    fn format_quil_reward_8dp() {
        assert_eq!(format_quil_reward(&BigInt::from(0)), "0.00000000");
        assert_eq!(format_quil_reward(&BigInt::from(100_000_000u64)), "1.00000000");
        assert_eq!(format_quil_reward(&BigInt::from(150_000_000u64)), "1.50000000");
        assert_eq!(format_quil_reward(&BigInt::from(1u64)), "0.00000001");
    }
}

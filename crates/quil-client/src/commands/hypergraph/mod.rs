//! `qclient hypergraph …` — hypergraph read/write.
//!
//! `get vertex|hyperedge` is implemented here; the write subcommands
//! (`put`, `remove`) are added in a later phase. Shared setup (node
//! config, alias store, connection) is gathered in [`HypergraphCtx`].

use std::path::PathBuf;

use clap::Subcommand;
use tonic::transport::Channel;

use quil_config::Config;
use quil_types::proto::node::node_service_client::NodeServiceClient;

use crate::alias_store::{self, Store};
use crate::context::{Context, GlobalArgs};
use crate::rpc::ConnectOpts;

mod get;
pub(crate) mod put;
pub(crate) mod remove;

#[derive(Debug, Subcommand)]
pub enum HypergraphCommand {
    /// Retrieve hypergraph data (vertex or hyperedge).
    Get {
        #[command(subcommand)]
        command: get::GetCommand,
    },
    /// Insert hypergraph data (vertex).
    Put {
        /// 32-byte domain (hex or alias).
        #[arg(short = 'd', long, global = true, default_value = "")]
        domain: String,
        #[command(subcommand)]
        command: put::PutCommand,
    },
    /// Remove hypergraph data (vertex or hyperedge).
    Remove {
        /// 32-byte domain (hex or alias).
        #[arg(short = 'd', long, global = true, default_value = "")]
        domain: String,
        #[command(subcommand)]
        command: remove::RemoveCommand,
    },
}

/// Shared hypergraph context.
pub struct HypergraphCtx {
    #[allow(dead_code)]
    pub node_config: Config,
    #[allow(dead_code)]
    pub config_dir: PathBuf,
    pub alias_store: Option<Store>,
    pub connect_opts: ConnectOpts,
    pub key_manager: std::sync::Arc<quil_keys::FileKeyManager>,
}

impl HypergraphCtx {
    fn load(global: GlobalArgs) -> anyhow::Result<Self> {
        let ctx = Context::load(global)?;
        let (node_config, config_dir) = ctx.load_node_config("default")?;
        let alias_store = alias_store::try_load_for_config_dir(&config_dir);
        let key_manager = ctx.key_manager(&node_config, &config_dir)?;
        // Hypergraph commands use the local node.
        let connect_opts = ConnectOpts {
            public_rpc: false,
            custom_rpc: String::new(),
            listen_grpc_multiaddr: node_config.listen_grpc_multiaddr.clone(),
        };
        Ok(Self {
            node_config,
            config_dir,
            alias_store,
            connect_opts,
            key_manager,
        })
    }

    pub async fn connect(&self) -> anyhow::Result<NodeServiceClient<Channel>> {
        crate::rpc::connect_node_service(&self.connect_opts).await
    }

    /// Resolve an alias or hex address to exactly `expected_len` bytes.
    /// Port of `resolveAddress` (`client/cmd/hypergraph/helpers.go`).
    pub fn resolve_address(&self, input: &str, expected_len: usize) -> anyhow::Result<Vec<u8>> {
        if let Some(store) = &self.alias_store {
            if let Some((addr, _)) = store.resolve(input) {
                if addr.len() != expected_len {
                    anyhow::bail!(
                        "alias {input:?} resolved to {} bytes, expected {expected_len}",
                        addr.len()
                    );
                }
                // Only announce a genuine alias hit (not a bare hex literal
                // that `resolve` also accepts) to match Go's message.
                if store.get(input).is_some() {
                    println!("Resolved alias {input:?} to {}", hex::encode(&addr));
                }
                return Ok(addr);
            }
        }
        let h = input.strip_prefix("0x").unwrap_or(input);
        let b = hex::decode(h).map_err(|e| anyhow::anyhow!("must be an alias or hex address: {e}"))?;
        if b.len() != expected_len {
            anyhow::bail!(
                "expected {expected_len} bytes ({} hex chars), got {} bytes",
                expected_len * 2,
                b.len()
            );
        }
        Ok(b)
    }
}

pub async fn run(global: GlobalArgs, cmd: &HypergraphCommand) -> anyhow::Result<()> {
    let hc = HypergraphCtx::load(global)?;
    match cmd {
        HypergraphCommand::Get { command } => get::run(&hc, command).await,
        HypergraphCommand::Put { domain, command } => put::run(&hc, domain, command).await,
        HypergraphCommand::Remove { domain, command } => remove::run(&hc, domain, command).await,
    }
}

//! `qclient deploy …` — deploy schemas/tokens/compute intrinsics.
//!
//! Port of `client/cmd/deploy/`. The deploy verbs (`token`, `hypergraph`,
//! `compute`) carry **no inner signature** — the node materializes the
//! owner/write/read keys from the config — so they only need the config
//! built from the CLI's key material and submission with a zero domain.
//!
//! Key material (the Go `getDeployKeys` is obsolete — Ed448/BLS):
//! - read key  = `q-onion-key` (sntrup761, 1158 B)
//! - write key = owner key = `q-prover-key` (Falcon-512, 897 B)

use std::path::PathBuf;
use std::sync::Arc;

use clap::Subcommand;
use tonic::transport::Channel;

use quil_config::Config;
use quil_keys::FileKeyManager;
use quil_types::crypto::Signer;
use quil_types::proto::global::MessageRequest;
use quil_types::proto::node::node_service_client::NodeServiceClient;

use crate::context::{Context, GlobalArgs};
use crate::rpc::ConnectOpts;

mod compute;
mod file;
mod file_index;
mod get;
mod hypergraph;
mod hypergraph_update;
mod token;
mod token_update;

#[derive(Debug, Subcommand)]
pub enum DeployCommand {
    /// Deploy a hypergraph schema (requires an RDF schema file).
    Hypergraph {
        /// Args: `[key=value...] <schema.rdf>`.
        args: Vec<String>,
    },
    /// Deploy a token.
    Token {
        /// Args: `[name=… symbol=… behavior=… mintStrategy=… units=… supply=…]`.
        args: Vec<String>,
    },
    /// Deploy a file to the hypergraph (auto-chunks files ≥ 4 MB).
    File {
        /// 32-byte domain (hex or alias).
        #[arg(short = 'd', long)]
        domain: String,
        file: String,
    },
    /// Retrieve a deployed file (single-vertex or chunked) to a local path.
    Get {
        /// 64-byte full address (hex or alias) of the file/index vertex.
        full_address: String,
        /// Output path to write the reconstructed file.
        output: String,
    },
    /// Deploy a QCL compute program.
    ///
    /// With no `--domain`, deploys a new compute intrinsic (config + optional
    /// RDF). With `--domain <addr>`, deploys the QCL file's raw bytes as code
    /// to that existing compute domain.
    Compute {
        /// Compute domain (hex or alias) to deploy code to; omit to create new.
        #[arg(short = 'd', long, default_value = "")]
        domain: String,
        /// Path to the QCL circuit file.
        qcl_file: String,
        /// Optional RDF schema file (inferred from `<name>.rdf` if omitted).
        rdf_file: Option<String>,
    },
    /// Update a deployed token's configuration (owner-signed).
    TokenUpdate {
        /// The token's 32-byte domain (hex or alias).
        #[arg(short = 'd', long)]
        domain: String,
        /// Config `key=value` args (name/symbol/behavior/mintStrategy/units/supply).
        args: Vec<String>,
    },
    /// Update a deployed hypergraph's config/schema (owner-signed).
    HypergraphUpdate {
        /// The hypergraph's 32-byte domain (hex or alias).
        #[arg(short = 'd', long)]
        domain: String,
        /// Optional `rdf=<path>` for a schema evolution (omit for key rotation).
        args: Vec<String>,
    },
}

/// The three deploy public keys (`getDeployKeys`, updated for PQ).
pub struct DeployKeys {
    pub read: Vec<u8>,
    pub write: Vec<u8>,
    pub owner: Vec<u8>,
}

pub struct DeployCtx {
    #[allow(dead_code)]
    pub node_config: Config,
    #[allow(dead_code)]
    pub config_dir: PathBuf,
    pub key_manager: Arc<FileKeyManager>,
    pub connect_opts: ConnectOpts,
    pub alias_store: Option<crate::alias_store::Store>,
}

impl DeployCtx {
    fn load(global: GlobalArgs) -> anyhow::Result<Self> {
        let ctx = Context::load(global)?;
        let (node_config, config_dir) = ctx.load_node_config("default")?;
        let key_manager = ctx.key_manager(&node_config, &config_dir)?;
        let alias_store = crate::alias_store::try_load_for_config_dir(&config_dir);
        let connect_opts = ConnectOpts {
            public_rpc: false,
            custom_rpc: String::new(),
            listen_grpc_multiaddr: node_config.listen_grpc_multiaddr.clone(),
        };
        Ok(Self {
            node_config,
            config_dir,
            key_manager,
            connect_opts,
            alias_store,
        })
    }

    /// Resolve an alias or hex to exactly `expected_len` bytes.
    pub fn resolve_address(&self, input: &str, expected_len: usize) -> anyhow::Result<Vec<u8>> {
        if let Some(store) = &self.alias_store {
            if let Some((addr, _)) = store.resolve(input) {
                if addr.len() != expected_len {
                    anyhow::bail!(
                        "alias {input:?} resolved to {} bytes, expected {expected_len}",
                        addr.len()
                    );
                }
                return Ok(addr);
            }
        }
        let b = hex::decode(input.strip_prefix("0x").unwrap_or(input))
            .map_err(|e| anyhow::anyhow!("must be an alias or hex address: {e}"))?;
        if b.len() != expected_len {
            anyhow::bail!("expected {expected_len} bytes, got {}", b.len());
        }
        Ok(b)
    }

    pub async fn connect(&self) -> anyhow::Result<NodeServiceClient<Channel>> {
        crate::rpc::connect_node_service(&self.connect_opts).await
    }

    /// Read+write+owner public keys for a deploy config.
    pub fn deploy_keys(&self) -> anyhow::Result<DeployKeys> {
        let read = self
            .key_manager
            .public_key_by_id("q-onion-key")
            .map_err(|e| anyhow::anyhow!("read key: {e}"))?
            .ok_or_else(|| anyhow::anyhow!("q-onion-key (sntrup761 read key) not found"))?;
        let signer: Box<dyn Signer> = self
            .key_manager
            .get_signer_by_id("q-prover-key")
            .map_err(|e| anyhow::anyhow!("owner/write key: {e}"))?;
        let falcon = signer.public_key().to_vec();
        Ok(DeployKeys {
            read,
            write: falcon.clone(),
            owner: falcon,
        })
    }

    /// Submit a deploy op with a zero (32-byte) domain.
    pub async fn send_deploy(
        &self,
        client: &mut NodeServiceClient<Channel>,
        request: MessageRequest,
    ) -> anyhow::Result<()> {
        crate::send::send_message_request(client, &self.key_manager, vec![0u8; 32], request).await
    }
}

pub async fn run(global: GlobalArgs, cmd: &DeployCommand) -> anyhow::Result<()> {
    let dc = DeployCtx::load(global)?;
    match cmd {
        DeployCommand::Hypergraph { args } => hypergraph::run(&dc, args).await,
        DeployCommand::Token { args } => token::run(&dc, args).await,
        DeployCommand::File { domain, file } => file::run(&dc, domain, file).await,
        DeployCommand::Get {
            full_address,
            output,
        } => get::run(&dc, full_address, output).await,
        DeployCommand::Compute {
            domain,
            qcl_file,
            rdf_file,
        } => compute::run(&dc, domain, qcl_file, rdf_file.as_deref()).await,
        DeployCommand::TokenUpdate { domain, args } => token_update::run(&dc, domain, args).await,
        DeployCommand::HypergraphUpdate { domain, args } => {
            hypergraph_update::run(&dc, domain, args).await
        }
    }
}

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
pub(crate) mod compute_update;
mod file;
mod file_index;
mod get;
mod hypergraph;
pub(crate) mod hypergraph_update;
mod token;
pub(crate) mod token_update;

#[derive(Debug, Subcommand)]
pub enum DeployCommand {
    /// Deploy a hypergraph schema (requires an RDF schema file).
    Hypergraph {
        /// Args: `[key=value...] <schema.rdf>`.
        args: Vec<String>,
    },
    /// Deploy a token.
    Token {
        /// Args: `[name=… symbol=… behavior=… mintStrategy=… units=… supply=…
        /// additionalReference=…]`; `additionalReference` is the 64-byte address
        /// (hex or alias) of the token's data, e.g. a file `deploy file` stored.
        args: Vec<String>,
    },
    /// Deploy a file to the hypergraph (auto-chunks files ≥ 4 MB).
    File {
        /// 32-byte domain (hex or alias).
        #[arg(short = 'd', long)]
        domain: String,
        /// Seal to the public file key so anyone can read the file
        /// (collectible images); same fee. Default: only your read key opens it.
        #[arg(long)]
        public: bool,
        file: String,
    },
    /// Retrieve a deployed file (single-vertex or chunked) to a local path.
    ///
    /// Opens it with your read key, else with the public file key, and says
    /// which one opened it.
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
        /// Config `key=value` args
        /// (name/symbol/behavior/mintStrategy/units/supply/additionalReference).
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
    /// Update a deployed compute intrinsic's config/schema (owner-signed).
    ComputeUpdate {
        /// The compute domain's 32-byte address (hex or alias).
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
    /// Global flags, to load the QUIL wallet that pays for deploys and writes.
    pub global: GlobalArgs,
}

impl DeployCtx {
    fn load(global: GlobalArgs) -> anyhow::Result<Self> {
        let ctx = Context::load(global.clone())?;
        let (node_config, config_dir) = ctx.load_node_config("default")?;
        let key_manager = ctx.cli_key_manager(&node_config, &config_dir)?;
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
            global,
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

    /// What an owner's update of `domain` signs over after its separator:
    /// from the config replay frame, the digest of the application's metadata
    /// vertex as the node holds it (`vertex` when already read); before it,
    /// nothing. Within [`SIGNING_BINDING_MARGIN_FRAMES`] of the frame it
    /// refuses, as nodes may judge the update either way.
    pub(super) async fn update_binding(
        &self,
        client: &mut NodeServiceClient<Channel>,
        domain: &[u8],
        vertex: Option<&[u8]>,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let from =
            quil_execution::config_replay::init_config_replay_frame(self.node_config.p2p.network);
        let head = client
            .get_node_info(tonic::Request::new(
                quil_types::proto::node::GetNodeInfoRequest::default(),
            ))
            .await
            .map_err(|e| anyhow::anyhow!("get node info: {e}"))?
            .into_inner()
            .last_global_head_frame;
        if !binds_update(head, from)? {
            return Ok(None);
        }
        let vertex = match vertex {
            Some(vertex) => vertex.to_vec(),
            None => metadata_vertex(client, domain).await?,
        };
        quil_execution::config_replay::metadata_vertex_binding(&vertex)
            .map(Some)
            .map_err(|e| anyhow::anyhow!("could not read the application's metadata: {e}"))
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

    /// Submit a deploy op with a zero (32-byte) domain. A deploy grows world
    /// state, so it is paid in QUIL: it executes under its intrinsic's base
    /// domain, which the settlement's claim names as its destination.
    pub async fn send_deploy(
        &self,
        client: &mut NodeServiceClient<Channel>,
        request: MessageRequest,
    ) -> anyhow::Result<()> {
        use quil_types::proto::global::message_request::Request;
        let base: [u8; 32] = match &request.request {
            Some(Request::TokenDeploy(_)) => {
                quil_execution::token_intrinsic::constants::token_base_domain()
            }
            Some(Request::HypergraphDeploy(_)) => {
                quil_execution::hypergraph_intrinsic::hypergraph_base_domain()
            }
            Some(Request::ComputeDeploy(_)) => quil_execution::domains::COMPUTE,
            _ => anyhow::bail!("not a deploy request"),
        };
        // Deploys execute in the global venue, which collects the global
        // prover topic.
        crate::send::send_paid_request(
            self.global.clone(),
            client,
            &self.key_manager,
            vec![0xffu8; 32],
            base,
            request,
        )
        .await
    }

    /// Submit a write to an existing application, paid in QUIL.
    pub async fn send_paid(
        &self,
        client: &mut NodeServiceClient<Channel>,
        domain: &[u8],
        request: MessageRequest,
    ) -> anyhow::Result<()> {
        let execution: [u8; 32] = domain
            .try_into()
            .map_err(|_| anyhow::anyhow!("domain must be 32 bytes"))?;
        crate::send::send_paid_request(
            self.global.clone(),
            client,
            &self.key_manager,
            domain.to_vec(),
            execution,
            request,
        )
        .await
    }
}

/// Refuse any arg that is not `key=value` with one of the `known` keys (in
/// any case), before anything is read, signed or paid: an ignored arg would
/// leave the field the operator meant to set as it was.
pub(super) fn check_key_args(args: &[String], known: &[&str]) -> anyhow::Result<()> {
    let list = known.join(", ");
    for arg in args {
        let Some((key, _)) = arg.split_once('=') else {
            anyhow::bail!("{arg:?} is not key=value; known keys: {list}");
        };
        if !known.contains(&key.to_lowercase().as_str()) {
            anyhow::bail!("unknown key {key:?}; known keys: {list}");
        }
    }
    Ok(())
}

pub async fn run(global: GlobalArgs, cmd: &DeployCommand) -> anyhow::Result<()> {
    let dc = DeployCtx::load(global)?;
    match cmd {
        DeployCommand::Hypergraph { args } => hypergraph::run(&dc, args).await,
        DeployCommand::Token { args } => token::run(&dc, args).await,
        DeployCommand::File {
            domain,
            public,
            file,
        } => file::run(&dc, domain, file, *public).await,
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
        DeployCommand::ComputeUpdate { domain, args } => {
            compute_update::run(&dc, domain, args).await
        }
    }
}

/// The fastest GLOBAL frame time, in seconds.
const FASTEST_FRAME_SECS: u64 = 10;

/// Frames on each side of the config replay frame in which an update is not
/// signed: a paid update executes only once its settlement is certified, up
/// to [`crate::send::PAID_SUBMISSION_WAIT`] after it was signed, and an
/// application shard judges a frame by its GLOBAL anchor, which trails the
/// head. Twice the wait at the fastest frame time covers both (180 frames).
const SIGNING_BINDING_MARGIN_FRAMES: u64 =
    2 * crate::send::PAID_SUBMISSION_WAIT.as_secs() / FASTEST_FRAME_SECS;

/// Whether an update signed at GLOBAL head `head` binds the metadata vertex
/// it replaces, for config replay frame `from`; an error within
/// [`SIGNING_BINDING_MARGIN_FRAMES`] of the frame.
fn binds_update(head: u64, from: u64) -> anyhow::Result<bool> {
    if from == 0 || head >= from.saturating_add(SIGNING_BINDING_MARGIN_FRAMES) {
        return Ok(true);
    }
    if head.saturating_add(SIGNING_BINDING_MARGIN_FRAMES) < from {
        return Ok(false);
    }
    anyhow::bail!(
        "updates sign the state they replace from GLOBAL frame {from}, and the head is {head}: \
         an update signed now may be judged either way, so nothing was sent; retry after \
         frame {}",
        from.saturating_add(SIGNING_BINDING_MARGIN_FRAMES)
    )
}

/// The metadata vertex of the application at `domain`, as the node holds it.
pub(super) async fn metadata_vertex(
    client: &mut NodeServiceClient<Channel>,
    domain: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut address = domain.to_vec();
    address.extend_from_slice(&quil_execution::hypergraph_state::HYPERGRAPH_METADATA_ADDRESS);
    let response = client
        .get_vertex_data(tonic::Request::new(
            quil_types::proto::node::GetVertexDataRequest {
                address,
                full_data: true,
            },
        ))
        .await
        .map_err(|e| anyhow::anyhow!("could not read the application's metadata: {e}"))?
        .into_inner();
    if response.present == Some(false) || response.raw_data.is_empty() {
        anyhow::bail!("no application deployed at {}", hex::encode(domain));
    }
    Ok(response.raw_data)
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_update_near_the_config_replay_frame_is_not_signed() {
        use super::{binds_update, SIGNING_BINDING_MARGIN_FRAMES as MARGIN};
        assert_eq!(MARGIN, 180);
        let from = 1_000;
        assert!(!binds_update(from - MARGIN - 1, from).unwrap());
        assert!(binds_update(from - MARGIN, from).is_err());
        assert!(binds_update(from + MARGIN - 1, from).is_err());
        assert!(binds_update(from + MARGIN, from).unwrap());
        // A network guarded from its first frame binds at once.
        assert!(binds_update(0, 0).unwrap());
    }

    use quil_execution::token_intrinsic::config_resolver::MintVariant;

    use super::*;

    /// A deploy context with an empty keystore and no node: a command fails
    /// once it reaches for its keys or the network.
    pub(super) fn offline_ctx(name: &str) -> DeployCtx {
        let dir =
            std::env::temp_dir().join(format!("quil-client-deploy-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key_manager = FileKeyManager::new(
            dir.join("keys.yml"),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "q-prover-key".into(),
            Box::new(quil_crypto::FalconKeyConstructor),
        )
        .unwrap();
        DeployCtx {
            node_config: Config::default(),
            config_dir: dir,
            key_manager: Arc::new(key_manager),
            connect_opts: ConnectOpts::default(),
            alias_store: None,
            global: GlobalArgs {
                network: None,
                yes: false,
            },
        }
    }

    #[tokio::test]
    async fn token_update_refuses_unknown_keys() {
        let dc = offline_ctx("token-update-keys");
        let domain = "00".repeat(32);
        for (arg, refusal) in [
            ("paymentAddress=5a", "unknown key \"paymentAddress\""),
            ("price=1000", "unknown key \"price\""),
            ("supply", "\"supply\" is not key=value"),
        ] {
            // A known key in any case is taken; the unknown one is named.
            let args = ["mintStrategy=authority".to_string(), arg.to_string()];
            let err = format!(
                "{:#}",
                token_update::run(&dc, &domain, &args).await.unwrap_err()
            );
            assert!(
                err.contains(refusal)
                    && err.contains("name, symbol, behavior, mintstrategy, units, supply"),
                "token-update args misread: {arg} was not refused ({err})"
            );
        }
    }

    #[test]
    fn token_update_proof_strategy_is_deploys() {
        let strategy = token_update::proof_mint_strategy();
        let variant =
            MintVariant::from_flags(strategy.mint_behavior as u16, strategy.proof_basis as u16);
        assert_eq!(
            variant,
            MintVariant::MerkleEntitlementWithSignature,
            "token-update args misread: mintstrategy=proof sets {variant:?}, not the \
             entitlement basis deploy token sets"
        );
    }

    #[tokio::test]
    async fn token_deploy_refuses_unknown_keys() {
        let dc = offline_ctx("token-deploy-keys");
        for (arg, refusal) in [
            ("paymentAdress=5a", "unknown key \"paymentAdress\""),
            ("decimals=8", "unknown key \"decimals\""),
            ("supply", "\"supply\" is not key=value"),
        ] {
            // A known key in any case is taken; the unknown one is named.
            let args = ["mintStrategy=authority".to_string(), arg.to_string()];
            let err = format!("{:#}", token::run(&dc, &args).await.unwrap_err());
            assert!(
                err.contains(refusal) && err.contains("paymentaddress, price, entitlementroot"),
                "token deploy args misread: {arg} was not refused ({err})"
            );
        }
    }

    /// A 64-byte vertex address: a hypergraph domain and a data address.
    fn reference() -> Vec<u8> {
        let mut address = vec![0x0d; 32];
        address.extend_from_slice(&[0x49; 32]);
        address
    }

    /// A token configuration that already points at other data.
    fn referencing_token() -> quil_types::proto::token::TokenConfiguration {
        quil_types::proto::token::TokenConfiguration {
            name: "Example".into(),
            additional_reference: vec![vec![0x7c; 64]],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn token_additional_reference_key_is_known() {
        let dc = offline_ctx("token-reference-keys");
        let one = hex::encode(reference());
        // Taken in any case by both commands: deploy builds its
        // configuration, and the update gets past its keys to its domain.
        let args = [format!("additionalReference={one}")];
        let deployed = token::deploy_config(&dc, &args).map_err(|e| format!("{e:#}"));
        assert!(
            deployed
                .as_ref()
                .is_ok_and(|cfg| cfg.additional_reference == vec![reference()]),
            "token deploy args misread: additionalReference was not taken ({deployed:?})"
        );
        let err = format!(
            "{:#}",
            token_update::run(&dc, "00", &args).await.unwrap_err()
        );
        assert!(
            err.contains("expected 32 bytes, got 1"),
            "token-update args misread: additionalReference was not taken ({err})"
        );

        // Misspelt, both refuse it before anything is read or signed.
        let args = [format!("additionalRefrence={one}")];
        let domain = "00".repeat(32);
        for (command, result) in [
            ("token deploy", token::run(&dc, &args).await),
            ("token-update", token_update::run(&dc, &domain, &args).await),
        ] {
            let err = result.map_err(|e| format!("{e:#}")).err();
            assert!(
                err.as_ref().is_some_and(|e| {
                    e.contains("unknown key \"additionalRefrence\"")
                        && e.contains("additionalreference")
                }),
                "{command} args misread: additionalRefrence was not refused ({err:?})"
            );
        }
    }

    #[test]
    fn token_update_sets_additional_reference() {
        let dc = offline_ctx("token-update-reference");
        let current = referencing_token();
        let args = [format!("additionalreference={}", hex::encode(reference()))];
        let cfg = token_update::update_config(&dc, &current, &args).unwrap();
        assert_eq!(
            cfg.additional_reference,
            vec![reference()],
            "additional reference misread: token update did not set it"
        );
        let cfg =
            token_update::update_config(&dc, &current, &["name=Renamed".to_string()]).unwrap();
        assert_eq!(
            cfg.additional_reference, current.additional_reference,
            "additional reference misread: an update without it dropped the token's"
        );
    }

    #[test]
    fn token_additional_reference_refuses_a_wrong_length() {
        let dc = offline_ctx("token-reference-length");
        // 128 bytes: two references concatenated.
        for len in [32, 63, 65, 128] {
            let args = [format!("additionalreference={}", "ab".repeat(len))];
            let refusal = format!("expected 64 bytes, got {len}");
            for (command, result) in [
                ("deploy token", token::deploy_config(&dc, &args)),
                (
                    "token update",
                    token_update::update_config(&dc, &referencing_token(), &args),
                ),
            ] {
                let err = result.map_err(|e| format!("{e:#}")).err();
                assert!(
                    err.as_ref().is_some_and(|e| e.contains(&refusal)),
                    "additional reference misread: {command} took a {len}-byte \
                     reference ({err:?})"
                );
            }
        }
    }

    #[test]
    fn token_additional_reference_refuses_several_values() {
        let dc = offline_ctx("token-reference-several");
        let one = hex::encode(reference());
        for (args, refusal) in [
            (
                vec![format!("additionalreference={one},{one}")],
                "not a list",
            ),
            (
                vec![
                    format!("additionalreference={one}"),
                    format!("additionalReference={one}"),
                ],
                "given 2 times",
            ),
        ] {
            for (command, result) in [
                ("deploy token", token::deploy_config(&dc, &args)),
                (
                    "token update",
                    token_update::update_config(&dc, &referencing_token(), &args),
                ),
            ] {
                let err = result.map_err(|e| format!("{e:#}")).err();
                assert!(
                    err.as_ref().is_some_and(|e| e.contains(refusal)),
                    "additional reference misread: {command} took several \
                     references {args:?} ({err:?})"
                );
            }
        }
    }
}

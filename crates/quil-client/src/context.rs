//! Shared runtime context passed to every command.
//!
//! Carries the resolved global flags (`--network`, `--signature-check`,
//! `-y/--yes`) and the loaded client config, and offers helpers to load
//! the node config, build a key manager, and derive connection options.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use quil_config::Config;
use quil_keys::FileKeyManager;

use crate::config::ClientConfig;
use crate::rpc::ConnectOpts;
use crate::{config, keys, nodeconfig};

/// Global flags shared across all commands (root persistent flags in Go).
#[derive(Debug, Clone)]
pub struct GlobalArgs {
    /// `--network` / `QUILIBRIUM_NETWORK` — selects the node config set.
    pub network: Option<String>,
    /// `--signature-check` — verify the binary's release signatures.
    pub signature_check: bool,
    /// `-y/--yes` — auto-approve prompts, bypass signature check.
    pub yes: bool,
}

/// Runtime context: global flags + client config.
pub struct Context {
    pub global: GlobalArgs,
    pub client_config: ClientConfig,
}

impl Context {
    /// Build the context, loading (or creating) the client config.
    pub fn load(global: GlobalArgs) -> anyhow::Result<Self> {
        let client_config = config::load()?;
        Ok(Self {
            global,
            client_config,
        })
    }

    /// The `--network` override as an `Option<&str>` (empty → None).
    pub fn network_override(&self) -> Option<&str> {
        self.global.network.as_deref().filter(|s| !s.is_empty())
    }

    /// Resolve + load a node config. `config_arg` is the `--config` value
    /// (`""`/`"default"` → the default-resolved dir).
    pub fn load_node_config(&self, config_arg: &str) -> anyhow::Result<(Config, PathBuf)> {
        nodeconfig::load_node_config(config_arg, self.network_override())
    }

    /// Build a `FileKeyManager` for a loaded node config.
    pub fn key_manager(
        &self,
        node_config: &Config,
        config_dir: &Path,
    ) -> anyhow::Result<Arc<FileKeyManager>> {
        keys::build_key_manager(node_config, config_dir)
    }

    /// Derive connection options from the client + node configs and an
    /// explicit `--public-rpc` flag (from a subcommand). Port of the
    /// light-node decision in `client/cmd/token/token.go`.
    pub fn connect_opts(&self, node_config: &Config, public_rpc_flag: bool) -> ConnectOpts {
        ConnectOpts {
            public_rpc: public_rpc_flag || self.client_config.public_rpc,
            custom_rpc: self.client_config.custom_rpc.clone(),
            listen_grpc_multiaddr: node_config.listen_grpc_multiaddr.clone(),
        }
    }
}

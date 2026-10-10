//! `qclient node config …` — node config management (local files).
//!
//! Port of `client/cmd/node/nodeconfig/{set,assign-rewards}.go`.

use clap::Subcommand;

use quil_p2p::ed448_identity::Ed448Identity;

use crate::context::GlobalArgs;
use crate::{nodeconfig, system};

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Create a default configuration file set for a node.
    Create {
        /// Name for the configuration (defaults to `default-config`; cannot be `default`).
        name: Option<String>,
        /// Symlink this config as the `default` (always set on create, like Go).
        #[arg(short = 'd', long)]
        default: bool,
    },
    /// Set a whitelisted config key on the default node config.
    Set { key: String, value: String },
    /// Assign the rewards address for a config.
    AssignRewards {
        /// The config to modify.
        config_name: String,
        /// Optional target config whose peer id becomes the rewards address.
        target: Option<String>,
        /// Explicit rewards address (hex).
        #[arg(long)]
        address: Option<String>,
        /// Reset the rewards address to default (self).
        #[arg(long)]
        reset: bool,
    },
    /// Set the `default` config symlink to a named config.
    Switch {
        /// The config to make default (lists available configs if omitted).
        name: Option<String>,
    },
    /// Import a config directory into the standard location.
    Import {
        /// Name to import as.
        name: String,
        /// Source directory (must contain config.yml + keys.yml).
        source_dir: String,
        /// Also set it as the default config.
        #[arg(short = 'd', long)]
        default: bool,
    },
}

pub fn run(global: GlobalArgs, cmd: &ConfigCommand) -> anyhow::Result<()> {
    match cmd {
        ConfigCommand::Create { name, default } => create(name.as_deref(), *default),
        ConfigCommand::Set { key, value } => set(global, key, value),
        ConfigCommand::AssignRewards {
            config_name,
            target,
            address,
            reset,
        } => assign_rewards(config_name, target.as_deref(), address.as_deref(), *reset),
        ConfigCommand::Switch { name } => switch(name.as_deref()),
        ConfigCommand::Import {
            name,
            source_dir,
            default,
        } => import(name, source_dir, *default),
    }
}

/// Port of `client/cmd/node/nodeconfig/create.go` `NodeConfigCreateCmd` +
/// `utils.CreateDefaultNodeConfig`. Writes a default `config.yml` (via
/// `quil_config::load_config`, which generates defaults + a random keystore
/// encryption key on first run) plus a `keys.yml` placeholder — the real keys
/// are generated when the node first starts. Like Go, the new config is
/// symlinked as `default` so it is immediately usable.
fn create(name: Option<&str>, _set_default: bool) -> anyhow::Result<()> {
    let config_name = match name {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => "default-config".to_string(),
    };
    if config_name == "default" {
        anyhow::bail!("'default' is reserved for the symlink. Please use a different name.");
    }

    let configs_dir = system::node_config_home_dir()?;
    let config_dir = configs_dir.join(&config_name);

    // Generates config.yml with defaults (and the keystore encryption key).
    quil_config::load_config(&config_dir)
        .map_err(|e| anyhow::anyhow!("create default config: {e}"))?;

    // The node writes real keys on first start; until then keys.yml is a
    // placeholder so the config dir is recognized as valid (`has_node_config_files`).
    let keys_path = config_dir.join("keys.yml");
    if !keys_path.exists() {
        std::fs::write(&keys_path, "null:\n")
            .map_err(|e| anyhow::anyhow!("write keys.yml placeholder: {e}"))?;
    }

    if !nodeconfig::has_node_config_files(&config_dir) {
        anyhow::bail!(
            "Failed to generate configuration files in: {}",
            config_dir.display()
        );
    }

    // Match Go's `CreateDefaultNodeConfig`, which always symlinks the new
    // config as `default` so the node uses it immediately.
    let default_link = configs_dir.join("default");
    if default_link.exists() || std::fs::symlink_metadata(&default_link).is_ok() {
        let _ = std::fs::remove_file(&default_link);
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&config_dir, &default_link)
        .map_err(|e| anyhow::anyhow!("create default symlink: {e}"))?;

    println!("Successfully created {config_name} configuration and symlinked to default");
    println!("The keys.yml file will only contain 'null:' until the node is started.");
    Ok(())
}

fn import(name: &str, source_dir: &str, set_default: bool) -> anyhow::Result<()> {
    let source = std::path::Path::new(source_dir);
    if !source.exists() {
        anyhow::bail!("Source directory does not exist: {source_dir}");
    }
    if !nodeconfig::has_node_config_files(source) {
        anyhow::bail!("{source_dir} is not a valid config directory (needs config.yml + keys.yml)");
    }
    let configs_dir = system::node_config_home_dir()?;
    let target = configs_dir.join(name);
    std::fs::create_dir_all(&target)?;
    copy_dir(source, &target)?;

    if set_default {
        let default_link = configs_dir.join("default");
        if std::fs::symlink_metadata(&default_link).is_ok() {
            let _ = std::fs::remove_file(&default_link);
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &default_link)
            .map_err(|e| anyhow::anyhow!("create default symlink: {e}"))?;
        println!("Successfully imported config files to {name} and symlinked to default");
    } else {
        println!("Successfully imported config files to {}", target.display());
    }
    Ok(())
}

/// Recursively copy a directory tree.
fn copy_dir(from: &std::path::Path, to: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&src, &dst)?;
        } else {
            std::fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}

/// List config dirs under `~/.quilibrium/configs` that have config+keys.
fn list_configs() -> anyhow::Result<Vec<String>> {
    let dir = system::node_config_home_dir()?;
    let mut out = Vec::new();
    if dir.exists() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "default" || name.is_empty() {
                continue;
            }
            if nodeconfig::has_node_config_files(&path) {
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    Ok(out)
}

fn switch(name: Option<&str>) -> anyhow::Result<()> {
    let name = match name {
        Some(n) => n.to_string(),
        None => {
            let configs = list_configs()?;
            if configs.is_empty() {
                anyhow::bail!("No configurations found. Create one with 'qclient node config create'");
            }
            println!("Available configurations:");
            for (i, c) in configs.iter().enumerate() {
                println!("{}. {c}", i + 1);
            }
            anyhow::bail!("Specify a configuration name: qclient node config switch <name>");
        }
    };
    if name == "default" {
        anyhow::bail!("Invalid configuration name. 'default' is reserved.");
    }

    let configs_dir = system::node_config_home_dir()?;
    let source = configs_dir.join(&name);
    if !nodeconfig::has_node_config_files(&source) {
        anyhow::bail!("{} is not a valid config directory (needs config.yml + keys.yml)", source.display());
    }
    let default_link = configs_dir.join("default");
    // Replace any existing `default` symlink/dir entry.
    if default_link.exists() || std::fs::symlink_metadata(&default_link).is_ok() {
        let _ = std::fs::remove_file(&default_link);
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&source, &default_link)
        .map_err(|e| anyhow::anyhow!("create default symlink: {e}"))?;
    println!("Default config set to {name}");
    Ok(())
}

fn set(global: GlobalArgs, key: &str, value: &str) -> anyhow::Result<()> {
    let network = global.network.as_deref().filter(|s| !s.is_empty());
    let dir = nodeconfig::default_node_config_dir(network)?;
    let mut cfg = quil_config::load_config(&dir)
        .map_err(|e| anyhow::anyhow!("load config: {e}"))?;

    match key {
        "engine.statsMultiaddr" => cfg.engine.stats_multiaddr = value.to_string(),
        "p2p.listenMultiaddr" => cfg.p2p.listen_multiaddr = value.to_string(),
        "listenGrpcMultiaddr" => cfg.listen_grpc_multiaddr = value.to_string(),
        "listenRestMultiaddr" => cfg.listen_rest_multiaddr = value.to_string(),
        other => {
            anyhow::bail!(
                "Unsupported configuration key: {other}\nSupported keys: \
                 engine.statsMultiaddr, p2p.listenMultiaddr, listenGrpcMultiaddr, listenRestMultiaddr"
            );
        }
    }

    quil_config::save_config(&dir, &cfg).map_err(|e| anyhow::anyhow!("save config: {e}"))?;
    println!("Successfully updated {key} to {value} in {}", dir.display());
    Ok(())
}

fn assign_rewards(
    config_name: &str,
    target: Option<&str>,
    address: Option<&str>,
    reset: bool,
) -> anyhow::Result<()> {
    let config_dir = system::node_config_home_dir()?.join(config_name);
    let mut cfg = quil_config::load_config(&config_dir)
        .map_err(|e| anyhow::anyhow!("Error loading config {config_name:?}: {e}"))?;

    let new_address: String = if reset {
        println!("Resetting rewards address for {config_name} to default (self)");
        String::new()
    } else if let Some(addr) = address {
        let bytes = hex::decode(addr.strip_prefix("0x").unwrap_or(addr))
            .map_err(|e| anyhow::anyhow!("Invalid address hex: {e}"))?;
        let hexed = hex::encode(&bytes);
        println!("Assigning rewards for {config_name} to address: {hexed}");
        hexed
    } else if let Some(target_name) = target {
        let target_dir = system::node_config_home_dir()?.join(target_name);
        let target_cfg = quil_config::load_config(&target_dir)
            .map_err(|e| anyhow::anyhow!("Error loading target config {target_name:?}: {e}"))?;
        let id = Ed448Identity::from_config_hex(&target_cfg.p2p.peer_priv_key)
            .map_err(|e| anyhow::anyhow!("derive peer id: {e}"))?;
        let hexed = hex::encode(&id.peer_id_bytes);
        println!("Found address from {target_name}: {hexed}");
        hexed
    } else {
        anyhow::bail!(
            "No target specified. Use --address, --reset, or provide a target config name.\n\n\
             Usage:\n  \
             qclient node config assign-rewards <config-name> <target-config-name>\n  \
             qclient node config assign-rewards <config-name> --address <address>\n  \
             qclient node config assign-rewards <config-name> --reset"
        );
    };

    cfg.engine.rewards_address = new_address;
    quil_config::save_config(&config_dir, &cfg)
        .map_err(|e| anyhow::anyhow!("Error saving config: {e}"))?;
    println!("Rewards address updated for {config_name}");
    Ok(())
}

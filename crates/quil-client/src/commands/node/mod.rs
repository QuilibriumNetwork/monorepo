//! `qclient node …` — node management.
//!
//! The `prover` subgroup (status/lifecycle) lives here. Install/update/
//! service/config/log subcommands (OS plumbing) are added in a later
//! phase.

use clap::Subcommand;

use crate::context::GlobalArgs;

pub mod lifecycle;
pub mod log;
pub mod nodeconfig;
pub mod prover;
pub mod service;

#[derive(Debug, Subcommand)]
pub enum NodeCommand {
    /// Prover management.
    Prover {
        #[command(subcommand)]
        command: prover::ProverCommand,
    },
    /// Node config management.
    Config {
        #[command(subcommand)]
        command: nodeconfig::ConfigCommand,
    },
    /// Node log management.
    Log {
        #[command(subcommand)]
        command: log::LogCommand,
    },
    /// Print node info (runs the node binary's `--node-info`).
    Info {
        /// Config name (defaults to the resolved default config).
        config: Option<String>,
    },
    /// Manage the node system service (start/stop/status/install/…).
    Service {
        /// One of: start, stop, restart, status, enable, disable, reload,
        /// install, update, uninstall.
        action: String,
    },
    /// Remove old logs and/or old node binary versions.
    Clean {
        /// Remove both old logs and old node versions.
        #[arg(long)]
        all: bool,
        /// Remove old logs.
        #[arg(long)]
        logs: bool,
        /// Remove old node binary versions (keeps the current one).
        #[arg(long)]
        node: bool,
    },
    /// Download, verify, and install the node binary (+ system service).
    Install { version: Option<String> },
    /// Install a newer node version (optionally restarting the service).
    Update {
        version: Option<String>,
        #[arg(short = 'r', long)]
        restart: bool,
    },
    /// Symlink /usr/local/bin/quilibrium-node to an installed version.
    Link { version: Option<String> },
    /// Stop the service and remove node binaries (configs preserved).
    Uninstall,
    /// Manage a cron job to auto-update the node (enable|disable|status).
    AutoUpdate { action: String },
}

pub async fn run(global: GlobalArgs, cmd: &NodeCommand) -> anyhow::Result<()> {
    match cmd {
        NodeCommand::Prover { command } => prover::run(global, command).await,
        NodeCommand::Config { command } => nodeconfig::run(global, command),
        NodeCommand::Log { command } => log::run(command),
        NodeCommand::Info { config } => info(global, config.as_deref()),
        NodeCommand::Service { action } => service::run(action),
        NodeCommand::Clean { all, logs, node } => clean(*all, *logs, *node),
        NodeCommand::Install { version } => lifecycle::install(version.as_deref()).await,
        NodeCommand::Update { version, restart } => {
            lifecycle::update(version.as_deref(), *restart).await
        }
        NodeCommand::Link { version } => lifecycle::link(version.as_deref()),
        NodeCommand::Uninstall => lifecycle::uninstall(),
        NodeCommand::AutoUpdate { action } => lifecycle::auto_update(action),
    }
}

/// `qclient node clean` — remove old logs / old node versions.
fn clean(all: bool, logs: bool, node: bool) -> anyhow::Result<()> {
    if !all && !logs && !node {
        anyhow::bail!("specify --all, --logs, and/or --node");
    }
    if all || logs {
        let dir = std::path::Path::new(crate::system::LOG_PATH);
        let mut removed = 0;
        if dir.exists() {
            for entry in std::fs::read_dir(dir)? {
                let path = entry?.path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                // Rotated logs only (keep the live .log).
                if name.ends_with(".log.gz") || (name.contains(".log.") && !name.ends_with(".log")) {
                    if std::fs::remove_file(&path).is_ok() {
                        removed += 1;
                    }
                }
            }
        }
        println!("Removed {removed} old log file(s) from {}", dir.display());
    }
    if all || node {
        let data = crate::system::node_data_path();
        // Keep the version the current symlink points into.
        let current = std::fs::read_link(crate::system::default_node_symlink_path()).ok();
        let mut removed = 0;
        if data.exists() {
            for entry in std::fs::read_dir(&data)? {
                let path = entry?.path();
                let is_current = current
                    .as_ref()
                    .map(|c| c.starts_with(&path) || c == &path)
                    .unwrap_or(false);
                if !is_current {
                    if std::fs::remove_dir_all(&path).is_ok() {
                        removed += 1;
                    }
                }
            }
        }
        println!("Removed {removed} old version(s) from {}", data.display());
    }
    Ok(())
}

/// `qclient node info [config]` — shell out to the node binary's
/// `--node-info` (port of `client/cmd/node/info.go`).
fn info(global: GlobalArgs, config: Option<&str>) -> anyhow::Result<()> {
    let network = global.network.as_deref().filter(|s| !s.is_empty());
    let dir = match config {
        Some(name) if name != "default" => crate::system::node_config_home_dir()?.join(name),
        _ => crate::nodeconfig::default_node_config_dir(network)?,
    };
    let output = std::process::Command::new(crate::system::NODE_SERVICE_NAME)
        .arg("--node-info")
        .arg("--config")
        .arg(&dir)
        .output()
        .map_err(|e| anyhow::anyhow!("run {}: {e}", crate::system::NODE_SERVICE_NAME))?;
    std::io::Write::write_all(&mut std::io::stdout(), &output.stdout)?;
    if !output.status.success() {
        std::io::Write::write_all(&mut std::io::stderr(), &output.stderr)?;
        anyhow::bail!("node --node-info exited with {}", output.status);
    }
    Ok(())
}

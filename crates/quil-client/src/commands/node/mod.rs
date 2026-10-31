//! `qclient node …` — node management.
//!
//! The `prover` subgroup (status/lifecycle) and the install/update/
//! service/config/log subcommands (OS plumbing).

use clap::Subcommand;

use crate::context::GlobalArgs;

pub mod archive;
pub mod diagnostics;
pub mod diagnostics_dial;
pub mod diagnostics_logs;
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
    /// Archive peers the node reads from.
    Archive {
        #[command(subcommand)]
        command: archive::ArchiveCommand,
    },
    /// Opt-in diagnostics from other nodes: their health reports and their
    /// redacted logs, as their operators allow.
    Diagnostics {
        #[command(subcommand)]
        command: diagnostics::DiagnosticsCommand,
    },
    /// Node log management.
    Log {
        #[command(subcommand)]
        command: log::LogCommand,
    },
    /// Print node info (runs the node binary's `--node-info`).
    ///
    /// The node binary is `quilibrium-node` on PATH, as `qclient node link`
    /// sets it up; else the release file beside this qclient, named like it
    /// (`qclient-2.1.0.25-linux-amd64` runs `node-2.1.0.25-linux-amd64`);
    /// else the one `node-<version>-<os>-<arch>` file in the current
    /// directory. Run it from the node directory when the node runs from
    /// there.
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
    Install {
        version: Option<String>,
        /// Install a version older than the linked one.
        #[arg(long)]
        allow_downgrade: bool,
    },
    /// Install a newer node version (optionally restarting the service).
    Update {
        version: Option<String>,
        #[arg(short = 'r', long)]
        restart: bool,
        /// Install a version older than the linked one.
        #[arg(long)]
        allow_downgrade: bool,
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
        NodeCommand::Log { command } => log::run(global, command),
        NodeCommand::Archive { command } => archive::run(global, command).await,
        NodeCommand::Diagnostics { command } => diagnostics::run(global, command).await,
        NodeCommand::Info { config } => info(global, config.as_deref()),
        NodeCommand::Service { action } => service::run(action),
        NodeCommand::Clean { all, logs, node } => clean(&global, *all, *logs, *node),
        NodeCommand::Install {
            version,
            allow_downgrade,
        } => lifecycle::install(version.as_deref(), *allow_downgrade).await,
        NodeCommand::Update {
            version,
            restart,
            allow_downgrade,
        } => lifecycle::update(version.as_deref(), *restart, *allow_downgrade).await,
        NodeCommand::Link { version } => lifecycle::link(version.as_deref()),
        NodeCommand::Uninstall => lifecycle::uninstall(),
        NodeCommand::AutoUpdate { action } => lifecycle::auto_update(action),
    }
}

/// `qclient node clean` — remove old logs / old node versions.
fn clean(global: &GlobalArgs, all: bool, logs: bool, node: bool) -> anyhow::Result<()> {
    if !all && !logs && !node {
        anyhow::bail!("specify --all, --logs, and/or --node");
    }
    if all || logs {
        // Without a resolvable node config there are no log files to find.
        if let Err(e) = log::clean(global) {
            eprintln!("skipping logs: {e}");
        }
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
    let node = crate::system::node_binary()?;
    let output = std::process::Command::new(&node)
        .arg("--node-info")
        .arg("--config")
        .arg(&dir)
        .output()
        .map_err(|e| anyhow::anyhow!("run {}: {e}", node.display()))?;
    std::io::Write::write_all(&mut std::io::stdout(), &output.stdout)?;
    if !output.status.success() {
        std::io::Write::write_all(&mut std::io::stderr(), &output.stderr)?;
        anyhow::bail!("node --node-info exited with {}", output.status);
    }
    Ok(())
}

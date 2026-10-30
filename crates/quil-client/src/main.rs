//! `qclient` — the Quilibrium command-line client.
//!
//! Rust port of the Go `client/` CLI. This file owns argument parsing and
//! top-level dispatch.

use clap::{Args, Parser, Subcommand};

use quil_client::commands;
use quil_client::context::GlobalArgs;

/// Global (persistent) flags present on every command, mirroring the Go
/// root command's persistent flags.
#[derive(Debug, Args)]
struct GlobalFlags {
    /// Network config to use (e.g. mainnet, testnet, devnet) — loads from
    /// `~/.quilibrium/configs/{name}/`.
    #[arg(long, global = true, env = "QUILIBRIUM_NETWORK")]
    network: Option<String>,

    /// Accepted and ignored, so commands written for the Go client keep
    /// working: qclient runs no startup self-check, and it verifies every
    /// release it downloads regardless.
    #[arg(
        long = "signature-check",
        global = true,
        hide = true,
        action = clap::ArgAction::Set
    )]
    _signature_check: Option<bool>,

    /// Auto-approve prompts.
    #[arg(short = 'y', long = "yes", global = true, default_value_t = false)]
    yes: bool,
}

impl From<&GlobalFlags> for GlobalArgs {
    fn from(f: &GlobalFlags) -> Self {
        GlobalArgs {
            network: f.network.clone(),
            yes: f.yes,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "qclient",
    about = "Quilibrium client",
    long_about = "Quilibrium client is a command-line tool for managing Quilibrium nodes.\n\
                  It provides commands for installing, updating, and managing Quilibrium nodes.",
    version = quil_config::display_version()
)]
struct Cli {
    #[command(flatten)]
    global: GlobalFlags,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Performs a token operation.
    Token(commands::token::TokenArgs),
    /// Performs a QClient configuration operation.
    Config {
        #[command(subcommand)]
        command: commands::config::ConfigCommand,
    },
    /// Node management (prover status/lifecycle, install/service, …).
    Node {
        #[command(subcommand)]
        command: commands::node::NodeCommand,
    },
    /// Manage address aliases.
    Alias {
        #[command(subcommand)]
        command: commands::alias::AliasCommand,
    },
    /// Hypergraph operations.
    Hypergraph {
        #[command(subcommand)]
        command: commands::hypergraph::HypergraphCommand,
    },
    /// Key management operations.
    Key {
        #[command(subcommand)]
        command: commands::key::KeyCommand,
    },
    /// Messaging operations.
    Message(commands::message::MessageArgs),
    /// Deploy schemas, tokens, and compute intrinsics.
    Deploy {
        #[command(subcommand)]
        command: commands::deploy::DeployCommand,
    },
    /// Compute operations.
    Compute(commands::compute::ComputeArgs),
    /// Download and install the latest (or a specific) qclient release.
    Update {
        version: Option<String>,
        /// Install a version older than the linked one.
        #[arg(long)]
        allow_downgrade: bool,
    },
    /// Download the release signature files for the qclient binary.
    DownloadSignatures {
        #[arg(long)]
        version: Option<String>,
    },
    /// Create a symlink to the qclient binary in /usr/local/bin (requires sudo).
    Link,
    /// Diagnostics identities: ask other nodes for diagnostics without
    /// revealing this node's identity.
    Diagnostics {
        #[command(subcommand)]
        command: commands::node::diagnostics_logs::IdentityCommand,
    },
}

fn main() {
    // Errors are printed to stderr with a non-zero exit, matching Go's
    // `Execute()`.
    if let Err(e) = real_main() {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}

fn real_main() -> anyhow::Result<()> {
    // A native lattice build compiled for CPU features this host lacks dies
    // with SIGILL in its first proof: refuse every command up front.
    #[cfg(feature = "native-proof")]
    if let Some(message) = quil_lattice_ct::native_cpu::unsupported_cpu_message("qclient") {
        anyhow::bail!(message);
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let global = GlobalArgs::from(&cli.global);

    match &cli.command {
        // Sync commands.
        Commands::Config { command } => commands::config::run(command),
        Commands::Alias { command } => commands::alias::run(global, command),
        Commands::Key { command } => commands::key::run(global, command),
        Commands::Link => commands::link::run(),
        Commands::Diagnostics { command } => {
            commands::node::diagnostics_logs::run_identity(command)
        }

        // Async (RPC-bearing) commands run on a Tokio runtime.
        Commands::Token(args) => runtime()?.block_on(commands::token::run(global, args)),
        Commands::Node { command } => runtime()?.block_on(commands::node::run(global, command)),
        Commands::Hypergraph { command } => {
            runtime()?.block_on(commands::hypergraph::run(global, command))
        }
        Commands::Message(args) => runtime()?.block_on(commands::message::run(global, args)),
        Commands::Deploy { command } => runtime()?.block_on(commands::deploy::run(global, command)),
        Commands::Compute(args) => runtime()?.block_on(commands::compute::run(global, args)),
        Commands::Update {
            version,
            allow_downgrade,
        } => runtime()?.block_on(commands::release_cmds::update(
            version.as_deref(),
            *allow_downgrade,
        )),
        Commands::DownloadSignatures { version } => runtime()?.block_on(
            commands::release_cmds::download_signatures(version.as_deref()),
        ),
    }
}

/// Build a multi-threaded Tokio runtime for RPC-bearing commands.
fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    /// The Go client's `--signature-check` still parses, and help no longer
    /// offers a check that qclient never ran.
    #[test]
    fn the_signature_check_flag_is_hidden_and_accepted() {
        use clap::Parser;
        for args in [
            ["qclient", "--signature-check=false", "config", "print"],
            ["qclient", "config", "print", "--signature-check=true"],
        ] {
            super::Cli::try_parse_from(args).unwrap();
        }
        let help = super::Cli::command().render_long_help().to_string();
        assert!(!help.contains("--signature-check"), "{help}");
        assert!(!help.contains("bypass"), "{help}");
    }

    #[test]
    fn the_version_flag_reports_the_release_and_subpatch() {
        assert_eq!(
            super::Cli::command().get_version(),
            Some(quil_config::display_version())
        );
    }
}

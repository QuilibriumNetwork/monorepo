//! `qclient` — the Quilibrium command-line client.
//!
//! Rust port of the Go `client/` CLI. Command groups are wired in
//! phase-by-phase; this file owns argument parsing and top-level dispatch.

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

    /// Verify the binary's release signatures before running
    /// (default true, or the value of QUILIBRIUM_SIGNATURE_CHECK).
    #[arg(long = "signature-check", global = true, env = "QUILIBRIUM_SIGNATURE_CHECK", default_value_t = true)]
    signature_check: bool,

    /// Auto-approve prompts and bypass the signature check.
    #[arg(short = 'y', long = "yes", global = true, default_value_t = false)]
    yes: bool,
}

impl From<&GlobalFlags> for GlobalArgs {
    fn from(f: &GlobalFlags) -> Self {
        GlobalArgs {
            network: f.network.clone(),
            signature_check: f.signature_check,
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
    version
)]
struct Cli {
    #[command(flatten)]
    global: GlobalFlags,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Display the qclient version.
    Version(commands::version::VersionArgs),
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
    },
    /// Download the release signature files for the qclient binary.
    DownloadSignatures {
        #[arg(long)]
        version: Option<String>,
    },
    /// Create a symlink to the qclient binary in /usr/local/bin (requires sudo).
    Link,
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
    // qclient's RPC dependency graph can enable more than one rustls crypto
    // provider.  Select ring explicitly before any command creates a TLS
    // client; otherwise rustls aborts when its process-wide default is first
    // requested.
    install_rustls_provider();

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
        Commands::Version(args) => commands::version::run(args),
        Commands::Config { command } => commands::config::run(command),
        Commands::Alias { command } => commands::alias::run(global, command),
        Commands::Key { command } => commands::key::run(global, command),
        Commands::Link => commands::link::run(),

        // Async (RPC-bearing) commands run on a Tokio runtime.
        Commands::Token(args) => runtime()?.block_on(commands::token::run(global, args)),
        Commands::Node { command } => runtime()?.block_on(commands::node::run(global, command)),
        Commands::Hypergraph { command } => {
            runtime()?.block_on(commands::hypergraph::run(global, command))
        }
        Commands::Message(args) => runtime()?.block_on(commands::message::run(global, args)),
        Commands::Deploy { command } => runtime()?.block_on(commands::deploy::run(global, command)),
        Commands::Compute(args) => runtime()?.block_on(commands::compute::run(global, args)),
        Commands::Update { version } => {
            runtime()?.block_on(commands::release_cmds::update(version.as_deref()))
        }
        Commands::DownloadSignatures { version } => {
            runtime()?.block_on(commands::release_cmds::download_signatures(version.as_deref()))
        }
    }
}

fn install_rustls_provider() {
    // A library may have installed a provider already.  In that case keep the
    // existing process-wide choice; at qclient startup this selects ring.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a multi-threaded Tokio runtime for RPC-bearing commands.
fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?)
}

#[cfg(test)]
mod tests {
    use super::install_rustls_provider;

    #[test]
    fn selects_a_process_wide_rustls_provider() {
        install_rustls_provider();
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }
}

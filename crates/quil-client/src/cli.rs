//! qclient's command-line definition: the root parser, its global flags
//! and its subcommands. The binary parses with it; tests and tools run the
//! real parser through it.

use clap::{Args, Parser, Subcommand};

use crate::commands;
use crate::context::GlobalArgs;

/// Global (persistent) flags present on every command, mirroring the Go
/// root command's persistent flags.
#[derive(Debug, Args)]
pub struct GlobalFlags {
    /// Network config to use (e.g. mainnet, testnet, devnet) — loads from
    /// `~/.quilibrium/configs/{name}/`.
    #[arg(long, global = true, env = "QUILIBRIUM_NETWORK")]
    pub network: Option<String>,

    /// Enable or disable signature validation (default true, override
    /// with `QUILIBRIUM_SIGNATURE_CHECK=false` or
    /// `--signature-check=false`). Both flag and env must be set with
    /// an explicit value — bare `--signature-check` is not accepted.
    #[arg(
        long,
        global = true,
        env = "QUILIBRIUM_SIGNATURE_CHECK",
        default_value_t = true,
        action = clap::ArgAction::Set,
    )]
    pub signature_check: bool,

    /// Auto-approve prompts.
    #[arg(short = 'y', long = "yes", global = true, default_value_t = false)]
    pub yes: bool,

    /// Also print how each result was derived (frames, sizes, margins,
    /// page counts, timings, base units), as a bug report needs.
    #[arg(short = 'v', long = "verbose", global = true, default_value_t = false)]
    pub verbose: bool,
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
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalFlags,

    #[command(subcommand)]
    pub command: Commands,
}

// Moved unchanged from main.rs; boxing a variant would change how every
// match arm binds it, which this move deliberately avoids.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
pub enum Commands {
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
    ///
    /// Installs to /var/quilibrium/bin/qclient/<version> on Linux and
    /// /opt/quilibrium/bin/qclient/<version> on macOS (/var/quilibrium while
    /// an earlier install there exists and /opt/quilibrium does not), and
    /// links /usr/local/bin/qclient to it.
    Update {
        version: Option<String>,
        /// Install a version older than the linked one.
        #[arg(long)]
        allow_downgrade: bool,
        #[command(flatten)]
        source: crate::release_source::ReleaseSourceArgs,
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

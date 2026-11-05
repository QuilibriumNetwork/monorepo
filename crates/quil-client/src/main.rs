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
    signature_check: bool,

    /// Auto-approve prompts.
    #[arg(short = 'y', long = "yes", global = true, default_value_t = false)]
    yes: bool,

    /// Also print how each result was derived (frames, sizes, margins,
    /// page counts, timings, base units), as a bug report needs.
    #[arg(short = 'v', long = "verbose", global = true, default_value_t = false)]
    verbose: bool,
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
    quil_client::init_logging();

    // After parsing: `--help` and `--version` exit there, usable by any build.
    let cli = Cli::parse();
    quil_client::verbosity::set(cli.global.verbose);
    signature_check(&cli)?;
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

/// Whether this command runs the self-check: all do unless it is disabled,
/// but `download-signatures`, which fetches the files the check reads.
fn wants_signature_check(cli: &Cli) -> bool {
    cli.global.signature_check && !matches!(cli.command, Commands::DownloadSignatures { .. })
}

/// The release self-check, as the node runs it at startup: verify this binary
/// against its `.dgst` and `.dgst.sig.N` files, failing closed.
fn signature_check(cli: &Cli) -> anyhow::Result<()> {
    use quil_crypto::release_check::{self_check, SelfCheck, SELF_CHECK_HINT};
    match self_check(wants_signature_check(cli)) {
        Ok(SelfCheck::Verified(count)) => tracing::info!(
            valid_signatures = count,
            total_signatories = quil_config::SIGNATORIES.len(),
            "signature check passed"
        ),
        Ok(SelfCheck::Unavailable) => {
            tracing::info!("signature check not available for windows yet, skipping")
        }
        Ok(SelfCheck::Disabled) => tracing::info!("signature check disabled, skipping"),
        Err(e) => anyhow::bail!(
            "signature check failed: {e} — {SELF_CHECK_HINT}; a release keeps its .dgst and \
             .dgst.sig.N files beside it, which 'qclient download-signatures' fetches"
        ),
    }
    Ok(())
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

    fn signature_check_arg() -> clap::Arg {
        super::Cli::command()
            .get_arguments()
            .find(|a| a.get_long() == Some("signature-check"))
            .unwrap()
            .clone()
    }

    /// Help offers the flag, as the node's does.
    #[test]
    fn the_signature_check_flag_is_visible() {
        assert!(!signature_check_arg().is_hide_set());
        let help = super::Cli::command().render_long_help().to_string();
        assert!(help.contains("--signature-check"), "{help}");
    }

    /// The node's surface: its env var, on by default, an explicit value.
    #[test]
    fn the_signature_check_flag_takes_the_node_env_and_default() {
        let arg = signature_check_arg();
        assert_eq!(
            arg.get_env().and_then(|e| e.to_str()),
            Some("QUILIBRIUM_SIGNATURE_CHECK")
        );
        let defaults: Vec<_> = arg
            .get_default_values()
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(defaults, ["true"]);
        assert!(matches!(arg.get_action(), clap::ArgAction::Set));
    }

    /// The value reaches the check from either side of the subcommand; bare
    /// `--signature-check` is refused.
    #[test]
    fn the_signature_check_flag_needs_a_value_and_is_global() {
        use clap::Parser;
        for args in [
            ["qclient", "--signature-check=false", "config", "print"],
            ["qclient", "config", "print", "--signature-check=false"],
        ] {
            let cli = super::Cli::try_parse_from(args).unwrap();
            assert!(!cli.global.signature_check, "{args:?}");
            assert!(!super::wants_signature_check(&cli), "{args:?}");
        }
        for args in [
            ["qclient", "--signature-check", "config", "print"],
            ["qclient", "config", "print", "--signature-check"],
        ] {
            assert!(super::Cli::try_parse_from(args).is_err(), "{args:?}");
        }
    }

    /// `download-signatures` fetches what the check reads, so it runs without
    /// them; every other command checks.
    #[test]
    fn only_download_signatures_skips_the_signature_check() {
        use clap::Parser;
        let parse = |args: &[&'static str]| {
            let mut all = vec!["qclient", "--signature-check=true"];
            all.extend_from_slice(args);
            super::Cli::try_parse_from(all).unwrap()
        };
        assert!(!super::wants_signature_check(&parse(&[
            "download-signatures"
        ])));
        for args in [
            &["update"][..],
            &["link"],
            &["config", "print"],
            &["node", "update"],
        ] {
            assert!(super::wants_signature_check(&parse(args)), "{args:?}");
        }
    }

    /// `-v` parses before or after the subcommand and is off unless given.
    #[test]
    fn the_verbose_flag_is_global_and_off_by_default() {
        use clap::Parser;
        for (args, verbose) in [
            (&["qclient", "-v", "config", "print"][..], true),
            (&["qclient", "config", "print", "--verbose"][..], true),
            (&["qclient", "config", "print"][..], false),
        ] {
            let cli = super::Cli::try_parse_from(args).unwrap();
            assert_eq!(cli.global.verbose, verbose, "{args:?}");
        }
    }

    #[test]
    fn the_version_flag_reports_the_release_and_subpatch() {
        assert_eq!(
            super::Cli::command().get_version(),
            Some(quil_config::display_version())
        );
    }
}

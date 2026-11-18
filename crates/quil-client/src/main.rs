//! `qclient` — the Quilibrium command-line client.
//!
//! Rust port of the Go `client/` CLI. This file parses the arguments with
//! the library's `cli` definition and dispatches the command.

use clap::Parser;

use quil_client::cli::{Cli, Commands};
use quil_client::commands;
use quil_client::context::GlobalArgs;

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
            source,
        } => runtime()?.block_on(commands::release_cmds::update(
            version.as_deref(),
            *allow_downgrade,
            source,
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
/// against its `.dgst` and `.dgst.sig.N` files, failing closed. A binary
/// the official signatories do not verify passes when the release source
/// stored in its install root does, so the auto-update job runs the
/// qclient it installed.
fn signature_check(cli: &Cli) -> anyhow::Result<()> {
    use quil_crypto::release_check::{self_check, SelfCheck, SELF_CHECK_HINT};
    match self_check(wants_signature_check(cli)) {
        Ok(SelfCheck::Verified(count)) => tracing::info!(
            valid_signatures = count,
            total_signatories = quil_config::SIGNATORIES.len(),
            "signature check passed"
        ),
        Ok(SelfCheck::VerifiedBySource { valid, file }) => tracing::info!(
            valid_signatures = valid,
            release_source = %file.display(),
            "signature check passed under the stored release source"
        ),
        Ok(SelfCheck::Unavailable) => {
            tracing::info!("signature check not available for windows yet, skipping")
        }
        Ok(SelfCheck::Disabled) => tracing::info!("signature check disabled, skipping"),
        Err(e) => anyhow::bail!(
            "signature check failed: {e} — {SELF_CHECK_HINT}; a release keeps its .dgst and \
             .dgst.sig.N files beside it, which 'qclient download-signatures' fetches for an \
             official release; a release from another source starts only under the source \
             stored with 'qclient node auto-update enable --release-source'"
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

    /// Each command that installs releases takes the release source flags;
    /// a key needs a source.
    #[test]
    fn release_source_flags_parse_where_releases_install() {
        use clap::Parser;
        use quil_client::commands::node::NodeCommand;
        let key = "ab".repeat(57);
        let flags = [
            "--release-source",
            "https://releases.example.org",
            "--release-key",
            key.as_str(),
            "--release-quorum",
            "1",
        ];
        for cmd in [
            &["update"][..],
            &["node", "install"],
            &["node", "update", "--restart"],
            &["node", "auto-update", "enable"],
        ] {
            let mut args = vec!["qclient"];
            args.extend_from_slice(cmd);
            args.extend_from_slice(&flags);
            let cli = super::Cli::try_parse_from(args).unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
            let source = match cli.command {
                super::Commands::Update { source, .. } => source,
                super::Commands::Node {
                    command:
                        NodeCommand::Install { source, .. }
                        | NodeCommand::Update { source, .. }
                        | NodeCommand::AutoUpdate { source, .. },
                } => source,
                other => panic!("{cmd:?} parsed as {other:?}"),
            };
            let named = source.named().unwrap();
            assert!(
                named
                    .as_ref()
                    .is_some_and(|s| s.is_custom() && s.keys() == [key.as_str()]),
                "source_flags_lost: {cmd:?} named {named:?}"
            );
        }
        let keyless = ["qclient", "node", "update", "--release-key", key.as_str()];
        assert!(super::Cli::try_parse_from(keyless).is_err());
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

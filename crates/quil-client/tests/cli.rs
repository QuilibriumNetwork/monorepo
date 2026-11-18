//! qclient's command line, parsed as the binary parses it: the definition
//! is consistent, each subcommand parses to its command, and a flag stays
//! in its scope.

use clap::error::ErrorKind;
use clap::{Command, CommandFactory, FromArgMatches};
use quil_client::cli::{Cli, Commands};
use quil_client::commands::node::NodeCommand;
use quil_client::commands::token::TokenCommand;

/// Strips every `env` binding, recursively, so the caller's environment
/// cannot change what a test parses.
fn without_env(cmd: Command) -> Command {
    let cmd = cmd.mut_args(|a| a.env(None));
    let subs: Vec<String> = cmd
        .get_subcommands()
        .map(|s| s.get_name().to_owned())
        .collect();
    subs.into_iter()
        .fold(cmd, |c, name| c.mut_subcommand(name, without_env))
}

/// Parses argv as the binary does, with the environment ignored
/// (QUILIBRIUM_NETWORK, QUILIBRIUM_MAX_FEE and the signature check).
fn try_parse(argv: &[&str]) -> Result<Cli, clap::Error> {
    Cli::from_arg_matches(&without_env(Cli::command()).try_get_matches_from(argv)?)
}

/// clap's own checks of the definition (duplicate flags, dangling
/// references), which a release build skips at runtime.
#[test]
fn the_definition_is_consistent() {
    Cli::command().debug_assert();
}

/// One argv per subcommand, with the forms the devnet kits drive; every
/// subcommand of the definition has a row.
#[test]
fn each_subcommand_parses_to_its_command() {
    type Check = fn(&Commands) -> bool;
    let rows: &[(&[&str], Check)] = &[
        (&["token", "--config", "DIR", "balance"], |c| {
            matches!(c, Commands::Token(a)
                if a.common.config == ["DIR"] && matches!(a.command, TokenCommand::Balance))
        }),
        (&["token", "coins", "--config", "DIR"], |c| {
            matches!(c, Commands::Token(a)
                if a.common.config == ["DIR"] && matches!(a.command, TokenCommand::Coins))
        }),
        (
            &["token", "account"],
            |c| matches!(c, Commands::Token(a) if matches!(a.command, TokenCommand::Account)),
        ),
        (&["config", "print"], |c| {
            matches!(c, Commands::Config { .. })
        }),
        (&["node", "info"], |c| {
            matches!(
                c,
                Commands::Node {
                    command: NodeCommand::Info { config: None }
                }
            )
        }),
        (&["node", "prover", "status"], |c| {
            matches!(
                c,
                Commands::Node {
                    command: NodeCommand::Prover { .. }
                }
            )
        }),
        (&["alias", "list"], |c| matches!(c, Commands::Alias { .. })),
        (&["hypergraph", "get", "vertex", "ADDR"], |c| {
            matches!(c, Commands::Hypergraph { .. })
        }),
        (&["key", "list"], |c| matches!(c, Commands::Key { .. })),
        (&["message", "retrieve", "--all"], |c| {
            matches!(c, Commands::Message(_))
        }),
        (&["deploy", "get", "ADDR", "OUT"], |c| {
            matches!(c, Commands::Deploy { .. })
        }),
        (&["compute", "execute", "ADDR"], |c| {
            matches!(c, Commands::Compute(_))
        }),
        (&["update"], |c| {
            matches!(c, Commands::Update { version: None, .. })
        }),
        (
            &["download-signatures", "--version", "2.1.0.25"],
            |c| matches!(c, Commands::DownloadSignatures { version: Some(v) } if v == "2.1.0.25"),
        ),
        (&["link"], |c| matches!(c, Commands::Link)),
        (&["diagnostics", "keygen", "--out", "FILE"], |c| {
            matches!(c, Commands::Diagnostics { .. })
        }),
    ];
    for (args, check) in rows {
        let argv = [&["qclient", "-y", "-v", "--network", "devnet"][..], *args].concat();
        let cli = try_parse(&argv).unwrap_or_else(|e| panic!("path_refused {argv:?}: {e}"));
        assert!(check(&cli.command), "path_misparsed {argv:?}: {cli:?}");
        assert!(cli.global.yes && cli.global.verbose, "{argv:?}");
        assert_eq!(cli.global.network.as_deref(), Some("devnet"), "{argv:?}");
    }
    for sub in Cli::command().get_subcommands() {
        let name = sub.get_name();
        assert!(
            name == "help" || rows.iter().any(|(args, _)| args[0] == name),
            "path_untested {name}"
        );
    }
}

/// `--config` belongs to `token`: above a subcommand without it, the
/// parser refuses it as an unknown flag.
#[test]
fn config_is_refused_outside_token() {
    for argv in [
        &["qclient", "--config", "DIR", "node", "info"][..],
        &["qclient", "node", "--config", "DIR", "info"],
        &["qclient", "--config", "DIR", "config", "print"],
        &["qclient", "--config", "DIR", "token", "balance"],
    ] {
        match try_parse(argv) {
            Ok(cli) => panic!("accepted_out_of_scope {argv:?}: {cli:?}"),
            Err(e) => assert_eq!(e.kind(), ErrorKind::UnknownArgument, "{argv:?}: {e}"),
        }
    }
}

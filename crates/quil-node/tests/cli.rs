//! quil-node's command line, parsed as the binary parses it: the definition
//! is consistent, the launch forms operators and the supervisor use parse,
//! and --network takes a number.

use std::path::Path;

use clap::error::ErrorKind;
use clap::{Command, CommandFactory, FromArgMatches};
use quil_node::cli::Args;

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

/// Parses argv as the binary does, with QUILIBRIUM_SIGNATURE_CHECK ignored.
fn try_parse(argv: &[&str]) -> Result<Args, clap::Error> {
    Args::from_arg_matches(&without_env(Args::command()).try_get_matches_from(argv)?)
}

fn parse(args: &[&str]) -> Args {
    let argv = [&["quil-node"][..], args].concat();
    try_parse(&argv).unwrap_or_else(|e| panic!("launch_refused {argv:?}: {e}"))
}

/// clap's own checks of the definition (duplicate flags, dangling
/// references), which a release build skips at runtime.
#[test]
fn the_definition_is_consistent() {
    Args::command().debug_assert();
}

/// The bare launch, a config directory on a network, a worker started by
/// its parent, an archive without signature checks, and a storage
/// benchmark, whose options are refused without it.
#[test]
fn the_launch_forms_parse() {
    let bare = parse(&[]);
    assert_eq!(bare.config, Path::new(".config"));
    assert_eq!((bare.core, bare.parent_process, bare.network), (0, 0, 0));
    assert!(!bare.archive);

    for flag in ["-c", "--config"] {
        let a = parse(&[flag, "DIR", "--network", "1"]);
        assert_eq!((a.config.as_path(), a.network), (Path::new("DIR"), 1));
    }

    let worker = parse(&["--core", "3", "--parent-process", "1234"]);
    assert_eq!((worker.core, worker.parent_process), (3, 1234));

    let archive = parse(&["--archive", "--signature-check=false"]);
    assert!(archive.archive);
    assert!(!archive.signature_check);

    let bench = parse(&[
        "--benchmark-storage",
        "DIR",
        "--benchmark-storage-rounds",
        "3",
    ]);
    let b = &bench.storage_readiness;
    assert_eq!(b.benchmark_storage.as_deref(), Some(Path::new("DIR")));
    assert_eq!(b.benchmark_storage_rounds, 3);
    let err = try_parse(&["quil-node", "--benchmark-storage-report", "FILE"])
        .expect_err("bench_option_accepted");
    assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument, "{err}");
}

/// --network is a number in u8: a name or an out-of-range value is
/// refused as an invalid value.
#[test]
fn the_network_flag_takes_a_number() {
    for value in ["devnet", "256"] {
        let err = try_parse(&["quil-node", "--network", value]).expect_err("network_accepted");
        assert_eq!(err.kind(), ErrorKind::ValueValidation, "{value}: {err}");
    }
    assert_eq!(parse(&["--network", "1"]).network, 1);
}

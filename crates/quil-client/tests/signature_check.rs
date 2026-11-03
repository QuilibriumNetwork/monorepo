//! qclient's startup self-check, run on the real binary: a test build has no
//! release files, so it stands for every unsigned build. The signed path is
//! covered in `quil_crypto::release_check`.

use std::path::Path;
use std::process::{Command, Output};

const ENV: &str = "QUILIBRIUM_SIGNATURE_CHECK";

/// `qclient <args>` with a private home and no inherited setting.
fn qclient(home: &Path, env: Option<&str>, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_qclient"));
    cmd.args(args)
        .env("HOME", home)
        .env_remove("SUDO_USER")
        .env_remove("QUILIBRIUM_NETWORK")
        .env_remove(ENV);
    if let Some(value) = env {
        cmd.env(ENV, value);
    }
    cmd.output().unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Every command of an unsigned build refuses to run by default, and says how
/// to proceed.
#[test]
fn an_unsigned_build_fails_closed_by_default() {
    let home = tempfile::TempDir::new().unwrap();
    let out = qclient(home.path(), None, &["config", "print"]);
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("signature check failed"), "{err}");
    assert!(err.contains("--signature-check=false"), "{err}");
    assert!(err.contains("QUILIBRIUM_SIGNATURE_CHECK=false"), "{err}");
    assert!(err.contains("qclient download-signatures"), "{err}");
    assert!(out.stdout.is_empty(), "{:?}", out.stdout);
}

/// Disabling by flag, on either side of the subcommand, or by env runs the
/// command, and prints no banner into its output.
#[test]
fn disabling_the_check_runs_the_command() {
    let home = tempfile::TempDir::new().unwrap();
    let expected = qclient(
        home.path(),
        None,
        &["--signature-check=false", "config", "print"],
    );
    assert!(expected.status.success(), "{}", stderr(&expected));
    assert!(
        !String::from_utf8_lossy(&expected.stdout).contains("ignature"),
        "{:?}",
        expected.stdout
    );
    let cases: [(Option<&str>, &[&str]); 3] = [
        (None, &["config", "print", "--signature-check=false"]),
        (Some("false"), &["config", "print"]),
        (
            Some("true"),
            &["--signature-check=false", "config", "print"],
        ),
    ];
    for (env, args) in cases {
        let out = qclient(home.path(), env, args);
        assert!(out.status.success(), "{env:?} {args:?}: {}", stderr(&out));
        assert_eq!(out.stdout, expected.stdout, "{env:?} {args:?}");
    }
}

/// The flag overrides the env, as on the node: asking for the check still
/// fails closed when the env turns it off.
#[test]
fn the_flag_overrides_the_env() {
    let home = tempfile::TempDir::new().unwrap();
    let out = qclient(
        home.path(),
        Some("false"),
        &["--signature-check=true", "config", "print"],
    );
    assert!(stderr(&out).contains("signature check failed"), "{out:?}");
    assert_eq!(out.status.code(), Some(1));
}

/// `--help` and `--version` stay usable on any build.
#[test]
fn help_and_version_run_with_the_check_on() {
    let home = tempfile::TempDir::new().unwrap();
    for args in [
        &["--help"][..],
        &["--version"],
        &["help"],
        &["config", "--help"],
    ] {
        let out = qclient(home.path(), None, args);
        assert!(out.status.success(), "{args:?}: {}", stderr(&out));
    }
}

/// `download-signatures` runs without the files it fetches: an invalid version
/// reaches its own validation, without touching the network.
#[test]
fn download_signatures_runs_without_signatures() {
    let home = tempfile::TempDir::new().unwrap();
    let out = qclient(
        home.path(),
        None,
        &["download-signatures", "--version", "not-a-version"],
    );
    let err = stderr(&out);
    assert!(!out.status.success());
    assert!(err.contains("invalid release version"), "{err}");
    assert!(!err.contains("signature check failed"), "{err}");
}

/// The node's grammar: an explicit `true` or `false` only.
#[test]
fn only_an_explicit_value_parses() {
    let home = tempfile::TempDir::new().unwrap();
    for args in [
        &["--signature-check", "config", "print"][..],
        &["--signature-check=yes", "config", "print"],
    ] {
        let out = qclient(home.path(), None, args);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", stderr(&out));
    }
    let out = qclient(home.path(), Some("0"), &["config", "print"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
}

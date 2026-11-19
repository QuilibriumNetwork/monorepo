//! qclient's startup self-check, run on the real binary: a test build has no
//! release files, so it stands for every unsigned build; installed with
//! signed release files, it stands for a release. The rest of the signed
//! path is covered in `quil_crypto::release_check`.

use quil_config::release_source::{load_release_source_at, owner_and_mode, RELEASE_SOURCE_FILE};
use quil_config::VERSION_STRING;
use quil_crypto::release_check::{release_file_name, NAME_MISMATCH_HINT};
use quil_types::crypto::Signer;
use sha3::{Digest, Sha3_256};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ENV: &str = "QUILIBRIUM_SIGNATURE_CHECK";

/// `qclient <args>` with a private home and no inherited setting.
fn qclient(home: &Path, env: Option<&str>, args: &[&str]) -> Output {
    qclient_at(Path::new(env!("CARGO_BIN_EXE_qclient")), home, env, args)
}

/// [`qclient`] run from `exe`.
fn qclient_at(exe: &Path, home: &Path, env: Option<&str>, args: &[&str]) -> Output {
    let mut cmd = Command::new(exe);
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

/// `path` with `suffix` appended to its file name.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// This qclient binary installed as `<root>/bin/qclient/<VERSION>/qclient`,
/// as installers name it, its `.dgst` labelled `label` and signed by the one
/// key of a release source stored in `root`; `None` where that source cannot
/// be trusted (it must be owned and writable only by root up to `/`, as the
/// build tree's scratch directory is when tests run as root, in the
/// project's test image).
fn installed_qclient(root: &Path, label: &str) -> Option<PathBuf> {
    let dir = root.join("bin").join("qclient").join(VERSION_STRING);
    std::fs::create_dir_all(&dir).unwrap();
    let exe = dir.join("qclient");
    let built = Path::new(env!("CARGO_BIN_EXE_qclient"));
    if std::fs::hard_link(built, &exe).is_err() {
        std::fs::copy(built, &exe).unwrap();
    }
    let digest = Sha3_256::digest(std::fs::read(&exe).unwrap());
    let dgst = format!("SHA3-256({label})= {}\n", hex::encode(digest));
    std::fs::write(with_suffix(&exe, ".dgst"), &dgst).unwrap();
    let seed = [0xD2u8; 57];
    let public = quil_crypto::Ed448Signer::derive_public(&seed).unwrap();
    let signer = quil_crypto::Ed448Signer::from_bytes(&seed, &public).unwrap();
    let sig = signer.sign(dgst.as_bytes()).unwrap();
    std::fs::write(with_suffix(&exe, ".dgst.sig.1"), sig).unwrap();
    let source = root.join(RELEASE_SOURCE_FILE);
    std::fs::write(
        &source,
        format!(
            "url: https://releases.example.org\nkeys:\n- {}\nquorum: 1\n",
            hex::encode(public)
        ),
    )
    .unwrap();
    match load_release_source_at(&source, &owner_and_mode) {
        Ok(Some(_)) => Some(exe),
        Err(e) if e.contains("must be owned by root") => {
            println!("skip: the release source cannot be trusted here: {e}");
            None
        }
        other => panic!("premise: the stored release source loads: {other:?}"),
    }
}

/// A scratch install root in the build tree.
fn install_root() -> (tempfile::TempDir, PathBuf) {
    let scratch = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let root = std::fs::canonicalize(scratch.path()).unwrap();
    (scratch, root)
}

/// A signed qclient release installed as `qclient` runs its commands: its
/// label names `qclient-<VERSION>-<os>-<arch>`, this build's release, not
/// the file.
#[test]
fn a_renamed_signed_qclient_release_runs() {
    let (_scratch, root) = install_root();
    let release = release_file_name("qclient");
    let Some(exe) = installed_qclient(&root, &release) else {
        return;
    };
    let home = tempfile::TempDir::new().unwrap();
    let out = qclient_at(&exe, home.path(), None, &["config", "print"]);
    println!("REACH release label check: {release} run as qclient");
    let err = stderr(&out);
    assert!(
        out.status.success() && !err.contains("signature check failed"),
        "renamed_qclient_refused: {}\nstderr: {err}",
        out.status
    );
}

/// A signed release whose label names another release, here the node's,
/// stays refused under any name, and the refusal says what the operator
/// does about it instead of suggesting a build from source.
#[test]
fn a_qclient_release_labelled_for_another_release_names_the_action() {
    let (_scratch, root) = install_root();
    let label = release_file_name("node");
    let Some(exe) = installed_qclient(&root, &label) else {
        return;
    };
    let home = tempfile::TempDir::new().unwrap();
    let out = qclient_at(&exe, home.path(), None, &["config", "print"]);
    println!("REACH release label check: {label} run as qclient");
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("signature check failed"), "{err}");
    assert!(err.contains("signed for another release"), "{err}");
    assert!(err.contains(NAME_MISMATCH_HINT), "{err}");
    assert!(!err.contains("--signature-check=false"), "{err}");
    assert!(out.stdout.is_empty(), "{:?}", out.stdout);
}

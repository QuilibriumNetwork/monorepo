//! `install-qclient.sh`: its release platform names and its macOS
//! signature links, run through bash with the script's functions only
//! (`INSTALL_QCLIENT_LIB=1` skips its `main`).
#![cfg(unix)]

use std::path::Path;
use std::process::{Command, Output};

/// Run `body` in bash after sourcing the script, with the variables `env`.
fn run(body: &str, env: &[(&str, &Path)]) -> Output {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../install-qclient.sh");
    let mut cmd = Command::new("bash");
    cmd.arg("-c")
        .arg(format!("source \"$0\"; {body}"))
        .arg(script)
        .env("INSTALL_QCLIENT_LIB", "1");
    for (name, value) in env {
        cmd.env(name, value);
    }
    cmd.output().expect("run bash")
}

/// Each supported `uname -s`/`uname -m` pair names the platform as the
/// release files on the server do (`qclient-2.1.0.23-darwin-arm64`); an
/// unsupported one is refused.
#[test]
fn the_script_names_release_platforms_as_the_server_does() {
    for (kernel, machine, platform) in [
        ("Linux", "x86_64", "linux-amd64"),
        ("Linux", "aarch64", "linux-arm64"),
        ("Darwin", "arm64", "darwin-arm64"),
        ("Darwin", "x86_64", "darwin-amd64"),
    ] {
        let out = run(&format!("os_arch_of {kernel} {machine}"), &[]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{kernel} {machine}: {stderr}");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), platform);
    }
    for (kernel, machine) in [("FreeBSD", "x86_64"), ("Linux", "riscv64")] {
        let out = run(&format!("os_arch_of {kernel} {machine}"), &[]);
        assert!(!out.status.success(), "{kernel} {machine} was accepted");
    }
}

/// On macOS the link gets the release's digest and signatures beside it,
/// where released clients look for them; links to signatures the release
/// lacks go, and an operator's own file stays.
#[test]
fn the_link_gets_the_release_files_beside_it() {
    let tmp = tempfile::TempDir::new().unwrap();
    let dir = tmp.path().join("2.1.0.23");
    let bin = tmp.path().join("bin");
    std::fs::create_dir(&dir).unwrap();
    std::fs::create_dir(&bin).unwrap();
    let base = "qclient-2.1.0.23-darwin-arm64";
    let file = |suffix: &str| dir.join(format!("{base}{suffix}"));
    for suffix in ["", ".dgst", ".dgst.sig.1", ".dgst.sig.2", ".dgst.sig.8"] {
        std::fs::write(file(suffix), suffix).unwrap();
    }
    let at = |suffix: &str| bin.join(format!("qclient{suffix}"));
    std::os::unix::fs::symlink(file(".dgst.sig.5"), at(".dgst.sig.5")).unwrap();
    std::fs::write(at(".dgst.sig.9"), "own").unwrap();

    let out = run(
        &format!("SYMLINK=\"$LINK\"; link_release_files \"$DIR\" {base}"),
        &[("DIR", dir.as_path()), ("LINK", at("").as_path())],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for suffix in [".dgst", ".dgst.sig.1", ".dgst.sig.2", ".dgst.sig.8"] {
        assert_eq!(
            std::fs::read_link(at(suffix)).ok(),
            Some(file(suffix)),
            "{suffix}"
        );
    }
    for suffix in [".dgst.sig.3", ".dgst.sig.5", ".dgst.sig.17"] {
        assert!(std::fs::symlink_metadata(at(suffix)).is_err(), "{suffix}");
    }
    assert_eq!(std::fs::read_to_string(at(".dgst.sig.9")).unwrap(), "own");
}

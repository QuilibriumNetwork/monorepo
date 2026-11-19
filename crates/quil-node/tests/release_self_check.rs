//! The node checks its own release when it starts: a signed release passes
//! under any file name an installer gives it, its signed label naming the
//! release this build is.

use quil_config::release_source::{load_release_source_at, owner_and_mode, RELEASE_SOURCE_FILE};
use quil_config::VERSION_STRING;
use sha3::{Digest, Sha3_256};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// `path` with `suffix` appended to its file name.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// This node binary installed as `<root>/bin/node/<VERSION>/<file>`, its
/// `.dgst` labelled `label` and signed by `sk`, with a release source in
/// `root` trusting `sk`'s key.
fn install(root: &Path, file: &str, label: &str, sk: &ed448_rust::PrivateKey) -> PathBuf {
    let dir = root.join("bin").join("node").join(VERSION_STRING);
    std::fs::create_dir_all(&dir).unwrap();
    let exe = dir.join(file);
    let built = Path::new(env!("CARGO_BIN_EXE_quil-node"));
    if std::fs::hard_link(built, &exe).is_err() {
        std::fs::copy(built, &exe).unwrap();
    }
    let mut hasher = Sha3_256::new();
    std::io::copy(&mut std::fs::File::open(&exe).unwrap(), &mut hasher).unwrap();
    let digest: [u8; 32] = hasher.finalize().into();
    let dgst = format!("SHA3-256({label})= {}\n", hex::encode(digest));
    std::fs::write(with_suffix(&exe, ".dgst"), &dgst).unwrap();
    let sig = sk.sign(dgst.as_bytes(), None).unwrap();
    std::fs::write(with_suffix(&exe, ".dgst.sig.1"), sig).unwrap();
    let pk = hex::encode(ed448_rust::PublicKey::from(sk).as_byte());
    std::fs::write(
        root.join(RELEASE_SOURCE_FILE),
        format!("url: https://releases.example.org\nkeys:\n- {pk}\nquorum: 1\n"),
    )
    .unwrap();
    exe
}

/// A signed node release installed as `quilibrium-node`, as installers name
/// it, gets past the release check of its start (the label names
/// `node-<VERSION>-<os>-<arch>`, not the file). The start then runs
/// `--verify-db` on a file that is no database, which ends it at once.
#[test]
fn a_renamed_signed_node_release_starts() {
    // The release source must be owned by root and writable only by root,
    // up to `/`; the build tree's scratch directory is, when tests run as
    // root (the project's test image).
    let scratch = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let root = std::fs::canonicalize(scratch.path()).unwrap();
    let release = quil_crypto::release_check::release_file_name("node");
    let sk = ed448_rust::PrivateKey::from([0xD1; ed448_rust::KEY_LENGTH]);
    let exe = install(&root, "quilibrium-node", &release, &sk);
    match load_release_source_at(&root.join(RELEASE_SOURCE_FILE), &owner_and_mode) {
        Ok(Some(_)) => {}
        Err(e) if e.contains("must be owned by root") => {
            println!("skip: the release source cannot be trusted here: {e}");
            return;
        }
        other => panic!("premise: the stored release source loads: {other:?}"),
    }
    let not_a_db = root.join("not-a-db");
    std::fs::write(&not_a_db, b"").unwrap();

    let mut child = Command::new(&exe)
        .current_dir(&root)
        .args(["--config", ".config", "--network", "1", "--verify-db"])
        .arg(&not_a_db)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            child.kill().unwrap();
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    println!("REACH release label check: {release} started as quilibrium-node");
    assert!(
        stdout.contains("=== Verifying migrated RocksDB"),
        "renamed_release_refused_at_start: {}\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
    assert!(!stderr.contains("signature check failed"), "{stderr}");
}

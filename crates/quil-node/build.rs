use sha2::{Digest, Sha256};
use std::{env, fs, path::Path, process::Command};

// A source fingerprint, not a reproducible-binary attestation. Include dirty
// and untracked sources without requiring a Git checkout in release containers.
fn hash_tree(root: &Path, path: &Path, hash: &mut Sha256) {
    if !path.exists() {
        return;
    }
    if path.is_dir() {
        println!("cargo:rerun-if-changed={}", path.display());
        let mut entries: Vec<_> = fs::read_dir(path)
            .expect("read build fingerprint directory")
            .map(|e| e.expect("read directory entry").path())
            .collect();
        entries.sort();
        for entry in entries {
            let name = entry.file_name().unwrap().to_string_lossy();
            if name.starts_with('.')
                || matches!(name.as_ref(), "target" | "node_modules" | "worker-store")
                || entry.is_symlink()
            {
                continue;
            }
            hash_tree(root, &entry, hash);
        }
    } else if matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("rs" | "toml" | "lock" | "proto" | "udl" | "c" | "cpp" | "h" | "hpp")
    ) {
        println!("cargo:rerun-if-changed={}", path.display());
        let name = path.strip_prefix(root).unwrap().to_string_lossy();
        let data = fs::read(path).expect("read build fingerprint input");
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name.as_bytes());
        hash.update((data.len() as u64).to_be_bytes());
        hash.update(data);
    }
}

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let root = Path::new(&manifest).parent().unwrap().parent().unwrap();
    let mut hash = Sha256::new();
    hash.update(b"quilibrium/source-build/v1");
    for path in [
        "Cargo.toml",
        "Cargo.lock",
        "crates",
        "protobufs",
        "emp-ot",
        "emp-tool",
    ] {
        hash_tree(root, &root.join(path), &mut hash);
    }
    let mut settings: Vec<_> = env::vars()
        .filter(|(k, _)| {
            k.starts_with("CARGO_FEATURE_")
                || matches!(
                    k.as_str(),
                    "TARGET" | "PROFILE" | "OPT_LEVEL" | "DEBUG" | "CARGO_ENCODED_RUSTFLAGS"
                )
        })
        .collect();
    settings.sort();
    for (key, value) in settings {
        println!("cargo:rerun-if-env-changed={key}");
        hash.update((key.len() as u64).to_be_bytes());
        hash.update(key.as_bytes());
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    let compiler = Command::new(env::var("RUSTC").unwrap())
        .arg("-vV")
        .output()
        .expect("read compiler version");
    assert!(compiler.status.success(), "compiler version failed");
    hash.update(compiler.stdout);
    println!(
        "cargo:rustc-env=QUIL_BUILD_FINGERPRINT={:x}",
        hash.finalize()
    );
}

#[path = "build_support/fingerprint.rs"]
mod fingerprint;

use std::{env, path::Path, process::Command};

fn main() {
    let manifest = env::var("CARGO_MANIFEST_DIR").unwrap();
    let node = Path::new(&manifest);
    let root = node.parent().unwrap().parent().unwrap();
    let settings: Vec<_> = env::vars()
        .filter(|(key, _)| {
            key.starts_with("CARGO_FEATURE_")
                || key.starts_with("CARGO_PROFILE_")
                || matches!(
                    key.as_str(),
                    "TARGET" | "PROFILE" | "OPT_LEVEL" | "DEBUG" | "CARGO_ENCODED_RUSTFLAGS"
                )
        })
        .collect();
    for (key, _) in &settings {
        println!("cargo:rerun-if-env-changed={key}");
    }
    // Track unset overrides too, so adding one later invalidates provenance.
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    for profile in ["RELEASE", "DEV", "TEST", "BENCH"] {
        for field in [
            "LTO",
            "CODEGEN_UNITS",
            "OPT_LEVEL",
            "DEBUG",
            "STRIP",
            "INCREMENTAL",
            "PANIC",
            "OVERFLOW_CHECKS",
            "DEBUG_ASSERTIONS",
            "RPATH",
            "SPLIT_DEBUGINFO",
        ] {
            println!("cargo:rerun-if-env-changed=CARGO_PROFILE_{profile}_{field}");
        }
    }
    let compiler = Command::new(env::var("RUSTC").unwrap())
        .arg("-vV")
        .output()
        .expect("read compiler version");
    assert!(compiler.status.success(), "compiler version failed");
    let digest = fingerprint::fingerprint(root, node, settings, &compiler.stdout, |path| {
        println!("cargo:rerun-if-changed={}", path.display());
    })
    .expect("identify node source inputs");
    let digest = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    println!("cargo:rustc-env=QUIL_BUILD_FINGERPRINT={digest}");
}

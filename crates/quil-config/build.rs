//! Embeds the repository's `subpatch` counter, which the maintainer bumps
//! with each fix within a patch release, as `QUIL_SUBPATCH` (empty when the
//! source tree has no such file).

use std::path::Path;

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let path = Path::new(&manifest_dir).join("../../subpatch");
    println!("cargo:rerun-if-changed={}", path.display());
    let subpatch = std::fs::read_to_string(&path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let subpatch = if !subpatch.is_empty() && subpatch.bytes().all(|b| b.is_ascii_digit()) {
        subpatch
    } else {
        String::new()
    };
    println!("cargo:rustc-env=QUIL_SUBPATCH={subpatch}");
}

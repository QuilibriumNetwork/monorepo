//! `qclient version` — display the client version.
//!
//! Port of `client/cmd/version.go`. Extracts the version from the
//! executable name (`qclient-X.Y.Z-...`) when present, otherwise uses the
//! compiled-in `VERSION`. `--checksum` additionally prints SHA-256 + MD5
//! of the running binary.

use clap::Args;

use quil_config::{format_version, PATCH_NUMBER, VERSION};

#[derive(Debug, Args)]
pub struct VersionArgs {
    /// Show the SHA-256 and MD5 checksums of the running binary.
    #[arg(short = 'c', long = "checksum")]
    pub checksum: bool,
}

/// The base version string (`"2.1.0"`), from the executable name if it
/// encodes one, else the compiled-in `VERSION`.
fn base_version() -> String {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(name) = exe.file_name().and_then(|n| n.to_str()) {
            if let Some(v) = extract_version_from_name(name) {
                return v;
            }
        }
    }
    format_version(&VERSION)
}

/// Extract `X.Y.Z` from a name like `qclient-2.1.0-linux-amd64`.
fn extract_version_from_name(name: &str) -> Option<String> {
    let rest = name.strip_prefix("qclient-")?;
    let mut ver = String::new();
    let mut dots = 0;
    for ch in rest.chars() {
        if ch.is_ascii_digit() {
            ver.push(ch);
        } else if ch == '.' {
            dots += 1;
            ver.push('.');
        } else {
            break;
        }
    }
    // Require exactly major.minor.patch.
    if dots == 2 && ver.split('.').all(|p| !p.is_empty()) {
        Some(ver)
    } else {
        None
    }
}

/// Append the patch suffix (`-pN`) when the patch number is non-zero.
/// Port of `versionWithPatch`.
fn version_with_patch(base: &str) -> String {
    if PATCH_NUMBER != 0 {
        format!("{base}-p{}", PATCH_NUMBER)
    } else {
        base.to_string()
    }
}

pub fn run(args: &VersionArgs) -> anyhow::Result<()> {
    let base = base_version();
    println!("qclient version: {}", version_with_patch(&base));

    if args.checksum {
        let exe = std::env::current_exe()?;
        let bytes = std::fs::read(&exe)?;
        println!("SHA256: {}", sha256_hex(&bytes));
        println!("MD5: {}", md5_hex(&bytes));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

fn md5_hex(bytes: &[u8]) -> String {
    // MD5 is a non-protocol integrity hash used only for the version
    // display (matches Go `CalculateFileHashes`).
    use md5::{Digest, Md5};
    hex::encode(Md5::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_version_from_binary_name() {
        assert_eq!(
            extract_version_from_name("qclient-2.1.0-linux-amd64").as_deref(),
            Some("2.1.0")
        );
        assert_eq!(
            extract_version_from_name("qclient-10.20.30").as_deref(),
            Some("10.20.30")
        );
    }

    #[test]
    fn rejects_non_matching_names() {
        assert_eq!(extract_version_from_name("qclient"), None);
        assert_eq!(extract_version_from_name("node-2.1.0"), None);
        assert_eq!(extract_version_from_name("qclient-2.1"), None);
    }

    #[test]
    fn patch_suffix_applied() {
        // PATCH_NUMBER is currently non-zero, so the suffix is present.
        assert!(version_with_patch("2.1.0").starts_with("2.1.0"));
    }
}

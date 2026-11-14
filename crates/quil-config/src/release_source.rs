//! The release source an operator stored for a host: the file qclient's
//! `node auto-update enable --release-source` writes in the install root,
//! and the trust rules every reader applies to it.
//!
//! The file names an `https://` base URL, the Ed448 public keys (hex) whose
//! signatures make a release from it trusted and how many of them must
//! sign. It decides what root installs and which binaries start, so it is
//! used only while root owns it and every directory above it and no one
//! else can write them; a repeated key is refused, as each signer counts
//! once.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

/// The release source file's name in the install root.
pub const RELEASE_SOURCE_FILE: &str = "release-source.yaml";

/// The length of an Ed448 public key, in bytes.
const ED448_PUBLIC_KEY_LEN: usize = 57;

/// The release source file as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSourceFile {
    /// The source's base URL.
    pub url: String,
    /// Its signers' Ed448 public keys (hex); the i-th verifies
    /// `.dgst.sig.<i+1>`.
    pub keys: Vec<String>,
    /// How many of them must sign a release (default 1).
    #[serde(default)]
    pub quorum: Option<usize>,
}

/// A stored release source whose file passed the trust rules: its keys
/// checked and lowercase, its quorum between 1 and their count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedReleaseSource {
    /// The source's base URL, as stored.
    pub url: String,
    /// Its signers' Ed448 public keys (lowercase hex).
    pub keys: Vec<String>,
    /// How many of [`Self::keys`] must sign a release.
    pub quorum: usize,
}

/// `keys` as release signer keys (lowercase hex) and `quorum` (default 1)
/// as their quorum: each key an Ed448 public key in hex, none repeated,
/// the quorum between 1 and their count.
pub fn check_release_keys(
    keys: &[String],
    quorum: Option<usize>,
) -> Result<(Vec<String>, usize), String> {
    if keys.is_empty() {
        return Err("a release source names no signer key".into());
    }
    let mut seen = BTreeSet::new();
    let mut checked = Vec::with_capacity(keys.len());
    for (i, key) in keys.iter().enumerate() {
        let key = key.trim().to_ascii_lowercase();
        let bytes =
            hex::decode(&key).map_err(|e| format!("release key #{} is not hex: {e}", i + 1))?;
        if bytes.len() != ED448_PUBLIC_KEY_LEN {
            return Err(format!(
                "release key #{} is {} bytes; an Ed448 public key is {ED448_PUBLIC_KEY_LEN}",
                i + 1,
                bytes.len()
            ));
        }
        if !seen.insert(key.clone()) {
            return Err(format!(
                "release key #{} repeats an earlier key: each signer counts once",
                i + 1
            ));
        }
        checked.push(key);
    }
    let quorum = quorum.unwrap_or(1);
    if quorum == 0 || quorum > checked.len() {
        return Err(format!(
            "release quorum {quorum} must be between 1 and the {} key(s) given",
            checked.len()
        ));
    }
    Ok((checked, quorum))
}

/// A path's `(owner uid, mode)`.
pub type Stat<'a> = &'a dyn Fn(&Path) -> std::io::Result<(u32, u32)>;

/// The `(owner uid, mode)` of `path`, following links.
#[cfg(unix)]
pub fn owner_and_mode(path: &Path) -> std::io::Result<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    Ok((meta.uid(), meta.mode()))
}

/// No owners off unix: every path counts as root's, 0644.
#[cfg(not(unix))]
pub fn owner_and_mode(_path: &Path) -> std::io::Result<(u32, u32)> {
    Ok((0, 0o644))
}

/// The release source stored at `path`, or `None` when there is no file.
/// Fails unless the file is a regular file and root owns it and each
/// directory above it, links resolved, and no one else can write them
/// (`stat` reads each `(owner uid, mode)`): whoever can write the file
/// chooses what root installs and runs. The URL is returned as stored; its
/// reader checks it.
pub fn load_release_source_at(
    path: &Path,
    stat: Stat,
) -> Result<Option<TrustedReleaseSource>, String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("stat {}: {e}", path.display())),
        Ok(meta) if !meta.is_file() => {
            return Err(format!(
                "{} is not a regular file; refusing it",
                path.display()
            ))
        }
        Ok(_) => {}
    }
    // The directories that hold the file, not the links naming them: a
    // link's own directory says nothing of who can replace its target.
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let dir = std::fs::canonicalize(dir).map_err(|e| format!("resolve {}: {e}", dir.display()))?;
    let real = dir.join(path.file_name().unwrap_or_default());
    for p in real.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let (uid, mode) = stat(p).map_err(|e| format!("stat {}: {e}", p.display()))?;
        if uid != 0 || mode & 0o022 != 0 {
            return Err(format!(
                "refusing the release source in {}: {} must be owned by root and writable \
                 only by root (owner uid {uid}, mode {:o})",
                path.display(),
                p.display(),
                mode & 0o7777
            ));
        }
    }
    let text =
        std::fs::read_to_string(&real).map_err(|e| format!("read {}: {e}", path.display()))?;
    let stored: ReleaseSourceFile =
        serde_yaml::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
    let (keys, quorum) = check_release_keys(&stored.keys, stored.quorum)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Some(TrustedReleaseSource {
        url: stored.url,
        keys,
        quorum,
    }))
}

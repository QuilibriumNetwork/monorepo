//! The source commit a node build names, read by the build script.
//!
//! `QUIL_BUILD_COMMIT` names it for builds without a git checkout (an image
//! or a source archive): a full object ID, `+dirty` appended when tracked
//! files differed from it. Otherwise git reads `HEAD` and whether tracked
//! files differ; neither gives an empty ID ("commit unknown").

use std::path::{Path, PathBuf};

/// The environment variable that names the commit instead of git.
pub const OVERRIDE: &str = "QUIL_BUILD_COMMIT";

const DIRTY_SUFFIX: &str = "+dirty";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    /// The full object ID in lowercase hex; empty when unread.
    pub id: String,
    /// Tracked files differed from it.
    pub dirty: bool,
}

impl Commit {
    fn unknown() -> Self {
        Self {
            id: String::new(),
            dirty: false,
        }
    }
}

/// A full SHA-1 or SHA-256 object ID, lowercased.
fn object_id(text: &str) -> Option<String> {
    let full = matches!(text.len(), 40 | 64);
    (full && text.bytes().all(|b| b.is_ascii_hexdigit())).then(|| text.to_ascii_lowercase())
}

/// The commit from `override_` (the [`OVERRIDE`] variable's value) when
/// set and not empty, else from `git`, which runs git in the workspace with
/// the arguments it gets and returns its output, `None` when it fails.
/// A malformed override is an error: the build must not guess.
pub fn resolve(
    override_: Option<&str>,
    git: impl Fn(&[&str]) -> Option<String>,
) -> Result<Commit, String> {
    if let Some(value) = override_.map(str::trim).filter(|value| !value.is_empty()) {
        let (id, dirty) = match value.strip_suffix(DIRTY_SUFFIX) {
            Some(id) => (id, true),
            None => (value, false),
        };
        return object_id(id).map(|id| Commit { id, dirty }).ok_or_else(|| {
            format!(
                "{OVERRIDE} must be a full 40- or 64-digit hex commit ID, \
                 optionally followed by {DIRTY_SUFFIX}; got {value:?}"
            )
        });
    }
    let Some(id) = git(&["rev-parse", "--verify", "HEAD"]).and_then(|out| object_id(out.trim()))
    else {
        return Ok(Commit::unknown());
    };
    // Unknown cleanliness names no commit: a clean one may not be claimed.
    let status = git(&[
        "--no-optional-locks",
        "status",
        "--porcelain",
        "--untracked-files=no",
        "--",
        ".",
    ]);
    Ok(match status {
        Some(changes) => Commit {
            id,
            dirty: !changes.trim().is_empty(),
        },
        None => Commit::unknown(),
    })
}

/// The files whose change moves `HEAD`: `HEAD` itself, its reflog, and the
/// branch it names (its loose ref, else `packed-refs`). Only files that
/// exist: Cargo reruns the build script at every build for a missing one,
/// and watching the work tree would rerun it at every edit.
pub fn watched(git_dir: &Path, common_dir: &Path, head_ref: Option<&str>) -> Vec<PathBuf> {
    let mut paths = vec![git_dir.join("HEAD"), git_dir.join("logs/HEAD")];
    if let Some(name) = head_ref {
        let loose = common_dir.join(name);
        paths.push(if loose.is_file() {
            loose
        } else {
            common_dir.join("packed-refs")
        });
    }
    paths.retain(|path| path.is_file());
    paths
}

/// [`watched`] for the checkout `git` runs in; empty without one.
pub fn watched_by(root: &Path, git: impl Fn(&[&str]) -> Option<String>) -> Vec<PathBuf> {
    let dir = |args: &[&str]| git(args).map(|out| root.join(out.trim()));
    let (Some(git_dir), Some(common_dir)) = (
        dir(&["rev-parse", "--git-dir"]),
        dir(&["rev-parse", "--git-common-dir"]),
    ) else {
        return Vec::new();
    };
    let head_ref = git(&["symbolic-ref", "-q", "HEAD"]);
    watched(&git_dir, &common_dir, head_ref.as_deref().map(str::trim))
}

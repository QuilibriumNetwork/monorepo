//! The source commit a node build names, read by the build script.
//!
//! `QUIL_BUILD_COMMIT` names it for builds without a git checkout (an image
//! or a source archive): a full object ID, `+dirty` appended when tracked
//! files differed from it. Otherwise git reads `HEAD` and whether tracked
//! files differ; neither gives an empty ID ("commit unknown") and a build
//! warning with git's error.

use std::{
    io,
    path::{Path, PathBuf},
    process::{Command, Output},
};

/// The environment variable that names the commit instead of git.
pub const OVERRIDE: &str = "QUIL_BUILD_COMMIT";

const DIRTY_SUFFIX: &str = "+dirty";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    /// The full object ID in lowercase hex; empty when unread.
    pub id: String,
    /// Tracked files differed from it.
    pub dirty: bool,
    /// Why no commit was read; `None` when one was.
    pub unread: Option<String>,
}

impl Commit {
    fn read(id: String, dirty: bool) -> Self {
        Self {
            id,
            dirty,
            unread: None,
        }
    }

    fn unknown(why: String) -> Self {
        Self {
            id: String::new(),
            dirty: false,
            unread: Some(why),
        }
    }

    /// The build's warning when it read no commit: the binary then reports
    /// "commit unknown", and the build log says why.
    pub fn warning(&self) -> Option<String> {
        let why = self.unread.as_ref()?;
        Some(format!("source commit unknown: {why}"))
    }
}

/// git run in the workspace at `root`, reading only a repository there.
///
/// It trusts that repository whoever owns it: a build run as another user
/// (a container's root over a mounted checkout) already runs this
/// checkout's code. The ceiling keeps git from climbing to a checkout that
/// merely contains this source (an unpacked archive), whose commit is not
/// this source's and whose owner is not trusted.
pub fn git(root: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-c")
        .arg("safe.directory=*")
        .arg("-C")
        .arg(root);
    if let Some(parent) = root.parent() {
        command.env("GIT_CEILING_DIRECTORIES", parent);
    }
    command
}

/// A git run's output, or its error on one line.
pub fn reply(output: io::Result<Output>) -> Result<String, String> {
    let output = output.map_err(|error| format!("git did not run: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let words: Vec<&str> = stderr.split_whitespace().collect();
        return Err(if words.is_empty() {
            format!("git failed ({})", output.status)
        } else {
            words.join(" ")
        });
    }
    String::from_utf8(output.stdout).map_err(|_| "git printed non-UTF-8 output".to_string())
}

/// A full SHA-1 or SHA-256 object ID, lowercased.
fn object_id(text: &str) -> Option<String> {
    let full = matches!(text.len(), 40 | 64);
    (full && text.bytes().all(|b| b.is_ascii_hexdigit())).then(|| text.to_ascii_lowercase())
}

/// The commit from `override_` (the [`OVERRIDE`] variable's value) when
/// set and not empty, else from `git`, which runs git in the workspace with
/// the arguments it gets and returns its output or its error ([`reply`]).
/// A malformed override is an error: the build must not guess.
pub fn resolve(
    override_: Option<&str>,
    git: impl Fn(&[&str]) -> Result<String, String>,
) -> Result<Commit, String> {
    if let Some(value) = override_.map(str::trim).filter(|value| !value.is_empty()) {
        let (id, dirty) = match value.strip_suffix(DIRTY_SUFFIX) {
            Some(id) => (id, true),
            None => (value, false),
        };
        return object_id(id)
            .map(|id| Commit::read(id, dirty))
            .ok_or_else(|| {
                format!(
                    "{OVERRIDE} must be a full 40- or 64-digit hex commit ID, \
                     optionally followed by {DIRTY_SUFFIX}; got {value:?}"
                )
            });
    }
    let head = ["rev-parse", "--verify", "HEAD"];
    let id = match git(&head) {
        Ok(out) => match object_id(out.trim()) {
            Some(id) => id,
            None => {
                let why = format!("git {} printed {out:?}, not a commit ID", head.join(" "));
                return Ok(Commit::unknown(why));
            }
        },
        Err(error) => return Ok(Commit::unknown(format!("git {}: {error}", head.join(" ")))),
    };
    // Unknown cleanliness names no commit: a clean one may not be claimed.
    let status = [
        "--no-optional-locks",
        "status",
        "--porcelain",
        "--untracked-files=no",
        "--",
        ".",
    ];
    Ok(match git(&status) {
        Ok(changes) => Commit::read(id, !changes.trim().is_empty()),
        Err(error) => Commit::unknown(format!("git status: {error}")),
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
pub fn watched_by(root: &Path, git: impl Fn(&[&str]) -> Result<String, String>) -> Vec<PathBuf> {
    let dir = |args: &[&str]| git(args).ok().map(|out| root.join(out.trim()));
    let (Some(git_dir), Some(common_dir)) = (
        dir(&["rev-parse", "--git-dir"]),
        dir(&["rev-parse", "--git-common-dir"]),
    ) else {
        return Vec::new();
    };
    let head_ref = git(&["symbolic-ref", "-q", "HEAD"]).ok();
    watched(&git_dir, &common_dir, head_ref.as_deref().map(str::trim))
}

#[path = "../build_support/commit.rs"]
mod commit;

use commit::{Commit, OVERRIDE};
use std::{fs, path::Path};

const SHA1: &str = "0123456789abcdef0123456789abcdef01234567";

/// git in a checkout at `head` (`None`: no checkout) whose status prints
/// `status` (`None`: status fails).
fn git(head: Option<&str>, status: Option<&str>) -> impl Fn(&[&str]) -> Option<String> {
    let (head, status) = (head.map(str::to_string), status.map(str::to_string));
    move |args: &[&str]| match args {
        ["rev-parse", "--verify", "HEAD"] => head.as_ref().map(|id| format!("{id}\n")),
        [.., "status", "--porcelain", "--untracked-files=no", "--", "."] => status.clone(),
        _ => panic!("unexpected git {args:?}"),
    }
}

fn no_git(args: &[&str]) -> Option<String> {
    panic!("git ran with an override set: {args:?}")
}

#[test]
fn an_override_names_the_commit_without_git() {
    assert_eq!(OVERRIDE, "QUIL_BUILD_COMMIT");
    let upper = SHA1.to_ascii_uppercase();
    assert_eq!(
        commit::resolve(Some(&upper), no_git),
        Ok(Commit {
            id: SHA1.into(),
            dirty: false
        })
    );
    let sha256 = "ab".repeat(32);
    assert_eq!(
        commit::resolve(Some(&format!(" {sha256}+dirty\n")), no_git),
        Ok(Commit {
            id: sha256,
            dirty: true
        })
    );
    // Empty is unset: git names it.
    assert_eq!(
        commit::resolve(Some(""), git(Some(SHA1), Some(""))),
        Ok(Commit {
            id: SHA1.into(),
            dirty: false
        })
    );
}

#[test]
fn a_malformed_override_fails_the_build() {
    let values = [
        "0123abcde".to_string(),
        "dirty".into(),
        "+dirty".into(),
        SHA1[1..].into(),
        format!("{SHA1}0"),
        format!("{}g", &SHA1[1..]),
        format!("{SHA1}-dirty"),
    ];
    for value in &values {
        let error = commit::resolve(Some(value), no_git).unwrap_err();
        assert!(error.contains(OVERRIDE), "{value}: {error}");
    }
}

#[test]
fn git_names_head_and_whether_tracked_files_differ() {
    let clean = commit::resolve(None, git(Some(SHA1), Some(""))).unwrap();
    assert_eq!(
        clean,
        Commit {
            id: SHA1.into(),
            dirty: false
        },
        "GIT-CLEAN"
    );
    let edited = commit::resolve(None, git(Some(SHA1), Some(" M crates/a.rs\n"))).unwrap();
    assert_eq!(
        edited,
        Commit {
            id: SHA1.into(),
            dirty: true
        },
        "GIT-DIRTY"
    );
}

#[test]
fn unread_head_or_status_names_no_commit() {
    let unknown = Commit {
        id: String::new(),
        dirty: false,
    };
    for (head, status) in [
        (None, Some("")),
        (Some("not a commit"), Some("")),
        (Some(SHA1), None),
    ] {
        assert_eq!(
            commit::resolve(None, git(head, status)),
            Ok(unknown.clone()),
            "UNREAD-UNKNOWN {head:?} {status:?}"
        );
    }
}

fn touch(path: &Path) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, "x\n").unwrap();
}

#[test]
fn only_existing_head_files_are_watched() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let (git_dir, common) = (root.join(".git/worktrees/w"), root.join(".git"));
    // A fresh checkout: no reflog, the branch only in packed-refs.
    touch(&git_dir.join("HEAD"));
    assert_eq!(
        commit::watched(&git_dir, &common, Some("refs/heads/fix/a")),
        [git_dir.join("HEAD")],
        "WATCH-EXISTING"
    );
    touch(&common.join("packed-refs"));
    touch(&git_dir.join("logs/HEAD"));
    assert_eq!(
        commit::watched(&git_dir, &common, Some("refs/heads/fix/a")),
        [
            git_dir.join("HEAD"),
            git_dir.join("logs/HEAD"),
            common.join("packed-refs")
        ]
    );
    // A loose ref replaces packed-refs; a detached HEAD names no branch.
    touch(&common.join("refs/heads/fix/a"));
    assert_eq!(
        commit::watched(&git_dir, &common, Some("refs/heads/fix/a"))[2],
        common.join("refs/heads/fix/a")
    );
    assert_eq!(commit::watched(&git_dir, &common, None).len(), 2);
    // Paths git prints relative to the workspace resolve under it.
    let git = |args: &[&str]| match args {
        ["rev-parse", "--git-dir"] => Some(".git/worktrees/w\n".to_string()),
        ["rev-parse", "--git-common-dir"] => Some(".git\n".to_string()),
        ["symbolic-ref", "-q", "HEAD"] => Some("refs/heads/fix/a\n".to_string()),
        _ => panic!("unexpected git {args:?}"),
    };
    assert_eq!(
        commit::watched_by(root, git),
        commit::watched(&git_dir, &common, Some("refs/heads/fix/a"))
    );
    assert!(commit::watched_by(root, |_: &[&str]| None).is_empty());
}

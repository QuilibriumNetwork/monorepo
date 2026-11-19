#[path = "../build_support/commit.rs"]
mod commit;

use commit::{Commit, OVERRIDE};
use std::{fs, path::Path, process::Command};

const SHA1: &str = "0123456789abcdef0123456789abcdef01234567";

/// git in a checkout at `head` (`None`: no checkout) whose status prints
/// `status` (`None`: status fails).
fn git(head: Option<&str>, status: Option<&str>) -> impl Fn(&[&str]) -> Result<String, String> {
    let (head, status) = (head.map(str::to_string), status.map(str::to_string));
    move |args: &[&str]| match args {
        ["rev-parse", "--verify", "HEAD"] => head
            .as_ref()
            .map(|id| format!("{id}\n"))
            .ok_or_else(|| "fatal: not a git repository".to_string()),
        [.., "status", "--porcelain", "--untracked-files=no", "--", "."] => status
            .clone()
            .ok_or_else(|| "fatal: unable to read index".to_string()),
        _ => panic!("unexpected git {args:?}"),
    }
}

fn no_git(args: &[&str]) -> Result<String, String> {
    panic!("git ran with an override set: {args:?}")
}

fn read(id: &str, dirty: bool) -> Commit {
    Commit {
        id: id.into(),
        dirty,
        unread: None,
    }
}

#[test]
fn an_override_names_the_commit_without_git() {
    assert_eq!(OVERRIDE, "QUIL_BUILD_COMMIT");
    let upper = SHA1.to_ascii_uppercase();
    assert_eq!(commit::resolve(Some(&upper), no_git), Ok(read(SHA1, false)));
    let sha256 = "ab".repeat(32);
    assert_eq!(
        commit::resolve(Some(&format!(" {sha256}+dirty\n")), no_git),
        Ok(read(&sha256, true))
    );
    // Empty is unset: git names it.
    assert_eq!(
        commit::resolve(Some(""), git(Some(SHA1), Some(""))),
        Ok(read(SHA1, false))
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
    assert_eq!(clean, read(SHA1, false), "GIT-CLEAN");
    let edited = commit::resolve(None, git(Some(SHA1), Some(" M crates/a.rs\n"))).unwrap();
    assert_eq!(edited, read(SHA1, true), "GIT-DIRTY");
}

#[test]
fn unread_head_or_status_names_no_commit() {
    for (head, status) in [
        (None, Some("")),
        (Some("not a commit"), Some("")),
        (Some(SHA1), None),
    ] {
        let commit = commit::resolve(None, git(head, status)).unwrap();
        assert_eq!(
            (commit.id.as_str(), commit.dirty),
            ("", false),
            "UNREAD-UNKNOWN {head:?} {status:?}"
        );
    }
}

/// An unread commit warns the build with git's reason; a read one does not.
#[test]
fn an_unread_commit_warns_with_gits_error() {
    for (head, status, why) in [
        (
            None,
            Some(""),
            "git rev-parse --verify HEAD: fatal: not a git repository",
        ),
        (
            Some("not a commit"),
            Some(""),
            "git rev-parse --verify HEAD printed \"not a commit\\n\", not a commit ID",
        ),
        (Some(SHA1), None, "git status: fatal: unable to read index"),
    ] {
        let commit = commit::resolve(None, git(head, status)).unwrap();
        assert_eq!(
            commit.warning().as_deref(),
            Some(format!("source commit unknown: {why}").as_str()),
            "UNREAD-WARNS {head:?} {status:?}"
        );
    }
    let commit = commit::resolve(None, git(Some(SHA1), Some(" M a.rs\n"))).unwrap();
    assert_eq!(commit.warning(), None, "UNREAD-WARNS read");
    assert_eq!(commit::resolve(Some(SHA1), no_git).unwrap().warning(), None);
}

/// git's error reaches the warning on one line, a git that did not run too.
#[test]
fn gits_error_is_one_line() {
    let dir = tempfile::tempdir().unwrap();
    checkout(dir.path());
    // Plain git as another owner: an error over several lines.
    let mut refused = plain_git(dir.path());
    refused.env("GIT_TEST_ASSUME_DIFFERENT_OWNER", "1");
    let error = commit::reply(refused.args(["rev-parse", "HEAD"]).output()).unwrap_err();
    assert!(
        error.starts_with("fatal: detected dubious ownership")
            && error.contains(" safe.directory ")
            && !error.contains('\n'),
        "GIT-ERROR {error:?}"
    );
    let missing = dir.path().join("no-git");
    let error = commit::reply(Command::new(&missing).output()).unwrap_err();
    assert!(
        error.starts_with("git did not run: "),
        "GIT-ERROR {error:?}"
    );
}

/// Plain git in `dir` that trusts no directory unless told: no system or
/// global config (a CI runner's system config trusts every directory).
fn plain_git(dir: &Path) -> Command {
    let mut git = Command::new("git");
    git.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .arg("-C")
        .arg(dir);
    git
}

/// Runs git in `dir` for a test's checkout: an author, no signing.
fn setup(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(["-c", "user.name=t", "-c", "user.email=t@t", "-c"])
        .args(["commit.gpgsign=false", "-C"])
        .arg(dir)
        .args(args)
        .output()
        .expect("run git");
    assert!(out.status.success(), "git {args:?}: {out:?}");
}

/// A checkout with one committed file, and its HEAD.
fn checkout(dir: &Path) -> String {
    setup(dir, &["init", "-q"]);
    fs::write(dir.join("a.txt"), "a\n").unwrap();
    setup(dir, &["add", "a.txt"]);
    setup(dir, &["commit", "-q", "-m", "a"]);
    let head = commit::reply(commit::git(dir).args(["rev-parse", "HEAD"]).output()).unwrap();
    head.trim().to_string()
}

/// git as a user other than the checkout's owner (a container's root over
/// a mounted checkout): the build reads the checkout it builds.
fn as_other_owner(root: &Path) -> impl Fn(&[&str]) -> Result<String, String> + '_ {
    move |args: &[&str]| {
        let mut git = commit::git(root);
        git.env("GIT_TEST_ASSUME_DIFFERENT_OWNER", "1");
        commit::reply(git.args(args).output())
    }
}

#[test]
fn another_owners_checkout_names_its_head() {
    let dir = tempfile::tempdir().unwrap();
    let head = checkout(dir.path());
    // The premise: plain git refuses this checkout for its owner.
    let refused = plain_git(dir.path())
        .args(["rev-parse", "HEAD"])
        .env("GIT_TEST_ASSUME_DIFFERENT_OWNER", "1")
        .output()
        .unwrap();
    assert!(!refused.status.success(), "{refused:?}");
    assert_eq!(
        commit::resolve(None, as_other_owner(dir.path())),
        Ok(read(&head, false)),
        "OTHER-OWNER"
    );
    fs::write(dir.path().join("a.txt"), "b\n").unwrap();
    assert_eq!(
        commit::resolve(None, as_other_owner(dir.path())),
        Ok(read(&head, true)),
        "OTHER-OWNER dirty"
    );
}

/// Plain git refuses another owner's checkout on a machine whose system or
/// global config trusts every directory, as a CI runner's does.
#[test]
fn plain_git_ignores_the_machines_trust() {
    let dir = tempfile::tempdir().unwrap();
    checkout(dir.path());
    let home = tempfile::tempdir().unwrap();
    let trusting = home.path().join(".gitconfig");
    fs::write(&trusting, "[safe]\n\tdirectory = *\n").unwrap();
    let run = |git: &mut Command| {
        git.env("GIT_TEST_ASSUME_DIFFERENT_OWNER", "1")
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
    };
    // The premises: each config alone trusts the checkout.
    let mut system = Command::new("git");
    system
        .env("GIT_CONFIG_SYSTEM", &trusting)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .arg("-C")
        .arg(dir.path());
    assert!(run(&mut system).status.success(), "TRUST-SYSTEM");
    let mut global = Command::new("git");
    global
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_CONFIG_GLOBAL")
        .env("HOME", home.path())
        .arg("-C")
        .arg(dir.path());
    assert!(run(&mut global).status.success(), "TRUST-GLOBAL");
    let mut plain = plain_git(dir.path());
    plain
        .env("GIT_CONFIG_SYSTEM", &trusting)
        .env("HOME", home.path());
    let refused = run(&mut plain);
    assert!(
        !refused.status.success()
            && String::from_utf8_lossy(&refused.stderr).contains("dubious ownership"),
        "UNTRUSTED {refused:?}"
    );
}

/// Source inside another checkout (an archive unpacked there) is not that
/// checkout's commit.
#[test]
fn a_checkout_around_the_source_names_no_commit() {
    let dir = tempfile::tempdir().unwrap();
    checkout(dir.path());
    let source = dir.path().join("source");
    fs::create_dir(&source).unwrap();
    // The premise: git climbs to the checkout around it unless stopped.
    let climbed = plain_git(&source)
        .args(["-c", "safe.directory=*", "rev-parse", "HEAD"])
        .env_remove("GIT_CEILING_DIRECTORIES")
        .output()
        .unwrap();
    assert!(climbed.status.success(), "{climbed:?}");
    let commit = commit::resolve(None, as_other_owner(&source)).unwrap();
    assert_eq!(commit.id, "", "CEILING");
    assert!(
        commit.warning().unwrap().contains("not a git repository"),
        "CEILING {commit:?}"
    );
}

/// This build, in a checkout, names its HEAD whoever ran it (the startup
/// line's `build_commit`). Builds from an archive or the override skip.
#[test]
fn this_build_names_its_checkout_head() {
    if option_env!("QUIL_BUILD_COMMIT").is_some_and(|value| !value.trim().is_empty()) {
        eprintln!("skip: the build named its commit by {OVERRIDE}");
        return;
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let root = root.canonicalize().unwrap();
    let out = Command::new("git")
        .args(["-c", "safe.directory=*", "-C"])
        .arg(&root)
        .args(["rev-parse", "--verify", "HEAD"])
        .env("GIT_CEILING_DIRECTORIES", root.parent().unwrap())
        .output()
        .expect("run git");
    if !out.status.success() {
        eprintln!("skip: the workspace is not a checkout: {out:?}");
        return;
    }
    let head = String::from_utf8(out.stdout).unwrap();
    assert_eq!(env!("QUIL_SOURCE_COMMIT"), head.trim(), "BUILD-HEAD");
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
        ["rev-parse", "--git-dir"] => Ok(".git/worktrees/w\n".to_string()),
        ["rev-parse", "--git-common-dir"] => Ok(".git\n".to_string()),
        ["symbolic-ref", "-q", "HEAD"] => Ok("refs/heads/fix/a\n".to_string()),
        _ => panic!("unexpected git {args:?}"),
    };
    assert_eq!(
        commit::watched_by(root, git),
        commit::watched(&git_dir, &common, Some("refs/heads/fix/a"))
    );
    assert!(commit::watched_by(root, |_: &[&str]| Err("no checkout".to_string())).is_empty());
}

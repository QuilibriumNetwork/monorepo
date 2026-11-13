//! `qclient node install|update|link|uninstall` — node binary lifecycle.
//!
//! Port of `client/cmd/node/{install,update,link,uninstall}.go`. Reuses the
//! shared release download+verify ([`crate::release`]) and service management
//! ([`super::service`]). Install/symlink paths require root.

use std::path::Path;

use quil_config::release_source::{owner_and_mode, Stat};

use crate::release_source::{self, ReleaseSource, ReleaseSourceArgs};
use crate::{release, system};

/// Take the exclusive lock at `path` (created 0600 if absent) until the
/// returned file closes; fail at once if another run holds it. `node
/// install`, `node update`, `node link`, `qclient update` and `node
/// auto-update enable` naming a source hold [`system::update_lock_path`]
/// while they change the install or its release source, so auto-update
/// runs (every 10 minutes) and manual runs never overlap.
pub(crate) fn lock_node_updates(path: &Path) -> anyhow::Result<std::fs::File> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| anyhow::anyhow!("create {}: {e} (root required)", dir.display()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|e| anyhow::anyhow!("open {}: {e} (root required)", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => anyhow::bail!(
            "another qclient install, update or release source change is running (it \
             holds {}); nothing done",
            path.display()
        ),
        Err(std::fs::TryLockError::Error(e)) => {
            anyhow::bail!("lock {}: {e}", path.display())
        }
    }
}

/// `node install [version]` — download+verify+install the node binary from
/// the release source `source` names (else the stored or official one),
/// then install the system service. An older version than the linked one
/// needs `allow_downgrade`.
pub async fn install(
    version: Option<&str>,
    allow_downgrade: bool,
    source: &ReleaseSourceArgs,
) -> anyhow::Result<()> {
    let source = release_source::active(source)?;
    let _lock = lock_node_updates(&system::update_lock_path())?;
    let version = resolve_version(version, &source).await?;
    println!("Installing Quilibrium node {version}...");
    let installed = release::download_and_install(
        &source,
        system::RELEASE_TYPE_NODE,
        &version,
        &system::default_node_symlink_path(),
        allow_downgrade,
    )
    .await?;
    println!("Installed node to {}", installed.path.display());
    super::service::run("install")?;
    Ok(())
}

/// `node update [version] [--restart] [--allow-downgrade]` — install a newer
/// node version from the release source `source` names (else the stored or
/// official one) and optionally restart the service. An older version than
/// the linked one needs `allow_downgrade`.
pub async fn update(
    version: Option<&str>,
    restart: bool,
    allow_downgrade: bool,
    source: &ReleaseSourceArgs,
) -> anyhow::Result<()> {
    let source = release_source::active(source)?;
    let _lock = lock_node_updates(&system::update_lock_path())?;
    let version = resolve_version(version, &source).await?;
    println!("Updating Quilibrium node to {version}...");
    let installed = release::download_and_install(
        &source,
        system::RELEASE_TYPE_NODE,
        &version,
        &system::default_node_symlink_path(),
        allow_downgrade,
    )
    .await?;
    if !installed.fresh {
        println!("Node {version} is already installed; nothing to update");
        return Ok(());
    }
    println!("Updated node to {}", installed.path.display());
    if restart {
        super::service::run("restart")?;
    }
    Ok(())
}

/// `node link [version]` — point `/usr/local/bin/quilibrium-node` at an
/// installed version (latest if unspecified) that the node's startup check
/// starts: signed by the official signatories, or by the release source
/// stored in its install root.
pub fn link(version: Option<&str>) -> anyhow::Result<()> {
    let version = match version {
        Some(v) if !v.is_empty() && v != "latest" => v.to_string(),
        _ => latest_installed_node_version()?,
    };
    let base = release::release_filename(system::RELEASE_TYPE_NODE, &version)?;
    let bin_path = system::node_data_path().join(&version).join(&base);
    let link = system::default_node_symlink_path();
    link_startable(
        &bin_path,
        &version,
        &link,
        &system::update_lock_path(),
        &owner_and_mode,
    )?;
    println!("Linked {} → {}", link.display(), bin_path.display());
    Ok(())
}

/// Point `link` at the installed release `bin_path` (of `version`) only if
/// the node's and qclient's startup check ([`release::check_starts`])
/// starts it, reading its install root's stored release source with
/// `stat`. Both run under the update lock at `lock`, so no install, update
/// or source change runs between the check and the link: linked, a
/// release the check refuses stops the node at its next start.
fn link_startable(
    bin_path: &Path,
    version: &str,
    link: &Path,
    lock: &Path,
    stat: Stat,
) -> anyhow::Result<()> {
    let _lock = lock_node_updates(lock)?;
    if !bin_path.exists() {
        anyhow::bail!("node binary not found: {}", bin_path.display());
    }
    release::check_starts(bin_path, stat).map_err(|e| {
        anyhow::anyhow!("{e}; or reinstall it with 'qclient node install {version}'")
    })?;
    release::switch_symlink(bin_path, link)
}

/// `node uninstall` — stop+remove the service and delete the node binaries +
/// symlink (configs are preserved).
pub fn uninstall() -> anyhow::Result<()> {
    let _ = super::service::run("uninstall");
    let _ = std::fs::remove_file(system::default_node_symlink_path());
    let data = system::node_data_path();
    if data.exists() {
        std::fs::remove_dir_all(&data)
            .map_err(|e| anyhow::anyhow!("remove {}: {e} (root required)", data.display()))?;
    }
    println!("Uninstalled node binaries (configs preserved)");
    Ok(())
}

const CRON_MARKER: &str = "# quilibrium-auto-update";

/// `node auto-update [enable|disable|status]` — manage a cron job that runs
/// `qclient node update --restart` every 10 minutes. The job lives in
/// root's crontab, so each action needs root. `enable` stores the release
/// source `source` names for the job ([`release_source::store`]).
pub fn auto_update(action: &str, source: &ReleaseSourceArgs) -> anyhow::Result<()> {
    let named = source.named()?;
    if named.is_some() && action != "enable" {
        anyhow::bail!("--release-source is taken by 'auto-update enable' only");
    }
    match action {
        "enable" | "disable" | "status" => {}
        other => anyhow::bail!("must specify 'enable', 'disable', or 'status' (got {other:?})"),
    }
    require_root(action, system::is_root())?;
    match action {
        "enable" => cron_enable(named),
        "disable" => cron_disable(),
        _ => cron_status(),
    }
}

/// Fail unless `is_root`. The job installs node releases and restarts the
/// service, which needs root, so it lives in root's crontab; without root,
/// `crontab` would edit or read the invoking user's, whose job fails on
/// every run.
fn require_root(action: &str, is_root: bool) -> anyhow::Result<()> {
    if !is_root {
        anyhow::bail!(
            "auto-update {action} needs root: the job installs node releases under {} and \
             restarts the node service, so it runs from root's crontab; run 'sudo qclient \
             node auto-update {action}'",
            system::binary_path().display()
        );
    }
    Ok(())
}

fn current_crontab() -> String {
    std::process::Command::new("crontab")
        .arg("-l")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// A/B reproducer of the auto-update finding; it calls only functions whose
/// signatures predate the fix.
#[cfg(test)]
mod repro_tests {
    use super::*;

    /// The root cron entry ran the file the enabling qclient was started
    /// from, which an operator's directory lets a non-root user replace.
    /// Without an installed root-owned qclient the entry is now refused.
    #[test]
    fn reproduces_cron_runs_current_exe() {
        let exe = std::env::current_exe().unwrap();
        if let Ok(line) = cron_line() {
            assert!(
                !line.contains(&*exe.to_string_lossy()),
                "the root auto-update cron entry runs the executable that enabled it, {}: {line}",
                exe.display()
            );
        }
    }

    /// Root's cron entry ran `/usr/local/bin/qclient`, a link in a
    /// directory that is not always root's: Homebrew on Intel macOS gives
    /// `/usr/local/bin` to the admin user. That user repoints the link and
    /// root runs their file within 10 minutes. On a host with an installed
    /// qclient, every directory above the path the entry names must be
    /// owned by root and writable by no one else.
    #[cfg(unix)]
    #[test]
    fn reproduces_root_cron_runs_a_link_others_can_write() {
        use std::os::unix::fs::MetadataExt;
        let Ok(line) = cron_line() else {
            return;
        };
        println!("root's auto-update cron entry: {line}");
        let exe = line.split_whitespace().nth(5).unwrap().to_string();
        for dir in Path::new(&exe).ancestors().skip(1) {
            let meta = std::fs::metadata(dir).unwrap();
            assert!(
                meta.uid() == 0 && meta.mode() & 0o022 == 0,
                "root's auto-update cron entry runs {exe} from {}, which uid {} owns with \
                 mode {:o}: whoever can write it makes root run their file: {line}",
                dir.display(),
                meta.uid(),
                meta.mode() & 0o7777
            );
        }
    }
}

fn write_crontab(contents: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let mut child = std::process::Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("run crontab (is cron installed?): {e}"))?;
    child.stdin.take().unwrap().write_all(contents.as_bytes())?;
    if !child.wait()?.success() {
        anyhow::bail!("crontab write failed");
    }
    Ok(())
}

/// The cron entry. It runs `<install root>/current`
/// ([`system::QCLIENT_ROOT_LINK`]), which `qclient update` and
/// install-qclient.sh point at the release they verified: the job runs as
/// root, so it never runs `/usr/local/bin/qclient`, whose directory another
/// user may own (Homebrew gives it to the admin user on Intel macOS), nor
/// the file this qclient was started from.
fn cron_line() -> anyhow::Result<String> {
    let install_root = system::client_data_path();
    let install_root = std::fs::canonicalize(&install_root)
        .map_err(|e| anyhow::anyhow!("resolve {}: {e}", install_root.display()))?;
    let qclient = install_root.join(system::QCLIENT_ROOT_LINK);
    check_cron_target(&qclient, &install_root)?;
    Ok(cron_entry(&qclient))
}

fn cron_entry(qclient: &Path) -> String {
    format!(
        "{} {} node update --restart {CRON_MARKER}",
        system::DEFAULT_AUTO_UPDATE_INTERVAL,
        qclient.display()
    )
}

/// Root runs the auto-update job, so the path its entry names (`qclient`)
/// must resolve to an installed qclient release under `install_root`, and
/// the directories holding that path, the release and every directory
/// above it must be owned by root and writable by no one else: whoever can
/// write one of them can make root run their file.
#[cfg(unix)]
fn check_cron_target(qclient: &Path, install_root: &Path) -> anyhow::Result<()> {
    check_cron_target_with(qclient, install_root, &|path| {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)?;
        Ok((meta.uid(), meta.mode()))
    })
}

/// [`check_cron_target`] reading each path's `(owner uid, mode)` from
/// `stat`, so a test sets owners and modes without chown or host paths.
#[cfg(unix)]
fn check_cron_target_with(
    qclient: &Path,
    install_root: &Path,
    stat: &dyn Fn(&Path) -> std::io::Result<(u32, u32)>,
) -> anyhow::Result<()> {
    let target = std::fs::canonicalize(qclient).map_err(|e| {
        anyhow::anyhow!(
            "resolve {}: {e}; install qclient with 'sudo qclient update' first",
            qclient.display()
        )
    })?;
    if !target.starts_with(install_root) {
        anyhow::bail!(
            "{} is not an installed qclient release under {}; run 'sudo qclient update' to \
             install one",
            target.display(),
            install_root.display()
        );
    }
    let root_only = |path: &Path| -> anyhow::Result<bool> {
        let (uid, mode) =
            stat(path).map_err(|e| anyhow::anyhow!("stat {}: {e}", path.display()))?;
        Ok(uid == 0 && mode & 0o022 == 0)
    };
    for dir in qclient.ancestors().skip(1) {
        if !dir.as_os_str().is_empty() && !root_only(dir)? {
            anyhow::bail!(
                "{} must be owned by root and writable only by root: the auto-update job \
                 runs {} from it as root",
                dir.display(),
                qclient.display()
            );
        }
    }
    for path in target.ancestors() {
        if !root_only(path)? {
            anyhow::bail!(
                "{} must be owned by root and writable only by root: the auto-update job \
                 runs as root",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_cron_target(_target: &Path, _install_root: &Path) -> anyhow::Result<()> {
    anyhow::bail!("auto-update requires cron, which this platform lacks")
}

/// Run `store` on the source `named` gives, under the update lock at
/// `lock` when it names one: an install or update running meanwhile has
/// checked its release against the stored source, and a change under it
/// could leave it linking a release that no longer starts. Naming none
/// only reads the stored source, so it runs beside the auto-update job.
fn store_locked(
    lock: &Path,
    named: Option<ReleaseSource>,
    store: impl FnOnce(Option<ReleaseSource>) -> anyhow::Result<ReleaseSource>,
) -> anyhow::Result<ReleaseSource> {
    let _lock = match named {
        Some(_) => Some(lock_node_updates(lock)?),
        None => None,
    };
    store(named)
}

fn cron_enable(named: Option<ReleaseSource>) -> anyhow::Result<()> {
    let current = current_crontab();
    let line = cron_line()?;
    let source = store_locked(&system::update_lock_path(), named, release_source::store)?;
    println!("Auto-update release source: {}", source.describe());
    if current.lines().any(|l| l == line) {
        println!("Auto-update is already enabled");
        return Ok(());
    }
    // An entry from an earlier qclient may run another executable: replace it.
    let mut lines: Vec<String> = current
        .lines()
        .filter(|l| !l.contains(CRON_MARKER))
        .map(String::from)
        .collect();
    println!("Auto-update enabled (every 10 minutes): {line}");
    lines.push(line);
    write_crontab(&(lines.join("\n") + "\n"))?;
    Ok(())
}

fn cron_disable() -> anyhow::Result<()> {
    let current = current_crontab();
    if !current.contains(CRON_MARKER) {
        println!("Auto-update is not enabled");
        return Ok(());
    }
    let kept: Vec<&str> = current
        .lines()
        .filter(|l| !l.contains(CRON_MARKER))
        .collect();
    write_crontab(&(kept.join("\n") + "\n"))?;
    println!("Auto-update disabled");
    Ok(())
}

fn cron_status() -> anyhow::Result<()> {
    if current_crontab().contains(CRON_MARKER) {
        println!("Auto-update is ENABLED");
    } else {
        println!("Auto-update is DISABLED");
    }
    let source = release_source::resolve(None, release_source::load_stored)?;
    println!("Release source: {}", source.describe());
    Ok(())
}

async fn resolve_version(version: Option<&str>, source: &ReleaseSource) -> anyhow::Result<String> {
    match version {
        Some(v) if !v.is_empty() => Ok(v.to_string()),
        _ => release::get_latest_version(source, system::RELEASE_TYPE_NODE).await,
    }
}

/// The highest installed node version directory.
fn latest_installed_node_version() -> anyhow::Result<String> {
    latest_version_in(&system::node_data_path())
}

/// The numerically highest release-version directory in `data`.
fn latest_version_in(data: &Path) -> anyhow::Result<String> {
    std::fs::read_dir(data)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", data.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|v| release::is_release_version(v))
        .max_by(|a, b| release::compare_versions(a, b))
        .ok_or_else(|| anyhow::anyhow!("no installed node versions in {}", data.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Without root, `auto-update enable` wrote the invoking user's
    /// crontab, whose `node update --restart` then failed on every run.
    #[test]
    fn auto_update_needs_root() {
        for action in ["enable", "disable", "status"] {
            let err = require_root(action, false).unwrap_err().to_string();
            assert!(
                err.contains(&format!("run 'sudo qclient node auto-update {action}'")),
                "{err}"
            );
        }
        require_root("enable", true).unwrap();
    }

    #[test]
    fn cron_entry_runs_the_installed_qclient() {
        assert_eq!(
            cron_entry(&system::client_data_path().join(system::QCLIENT_ROOT_LINK)),
            "*/10 * * * * /var/quilibrium/bin/qclient/current node update --restart \
             # quilibrium-auto-update"
        );
    }

    /// The path root's cron entry runs must sit in a directory only root
    /// writes: a link elsewhere, even to an installed release, is refused.
    #[cfg(unix)]
    #[test]
    fn cron_link_in_a_directory_others_can_write_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("qclient");
        let dir = root.join("2.1.0.25");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("qclient-2.1.0.25-linux-amd64");
        std::fs::write(&target, b"bin").unwrap();
        let links = tmp.path().join("bin");
        std::fs::create_dir(&links).unwrap();
        std::fs::set_permissions(&links, std::fs::Permissions::from_mode(0o777)).unwrap();
        let link = links.join("qclient");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();

        let err = check_cron_target(&link, &root).unwrap_err().to_string();
        assert!(
            err.starts_with(&format!(
                "{} must be owned by root and writable only by root: the auto-update job \
                 runs {} from it",
                links.display(),
                link.display()
            )),
            "{err}"
        );
    }

    /// The cron target is an installed release whose every directory above
    /// it, and itself, root owns and no one else writes. Owners and modes
    /// are faked, so the result does not depend on the host's users or
    /// directories; each case changes one fact and names it in its error.
    #[cfg(unix)]
    #[test]
    fn cron_target_must_be_a_root_owned_installed_release() {
        use std::collections::HashMap;
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("qclient");
        let dir = root.join("2.1.0.25");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("qclient-2.1.0.25-linux-amd64");
        std::fs::write(&target, b"bin").unwrap();
        let links = tmp.path().join("bin");
        std::fs::create_dir(&links).unwrap();
        let link = links.join("current");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let elsewhere = tmp.path().join("qclient-2.1.0.25-linux-amd64");
        std::fs::write(&elsewhere, b"bin").unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        let target = std::fs::canonicalize(&target).unwrap();
        let release = target.parent().unwrap().to_path_buf();

        // Every path root-owned 0755, except the `(uid, mode)` set here.
        let check = |qclient: &Path, set: &[(&Path, (u32, u32))]| {
            let facts: HashMap<std::path::PathBuf, (u32, u32)> =
                set.iter().map(|(p, f)| (p.to_path_buf(), *f)).collect();
            check_cron_target_with(qclient, &root, &|p| {
                Ok(facts.get(p).copied().unwrap_or((0, 0o40755)))
            })
        };

        check(&link, &[]).expect("a root-owned installed release is accepted");

        let err = check(&elsewhere, &[]).unwrap_err();
        assert!(
            err.to_string().contains("not an installed qclient release"),
            "{err}"
        );

        // Owned by another user, mode 0755: only the owner check refuses.
        let err = check(&link, &[(&target, (1000, 0o100755))]).unwrap_err();
        assert!(
            err.to_string().starts_with(&format!(
                "{} must be owned by root and writable only by root",
                target.display()
            )),
            "{err}"
        );
        let err = check(&link, &[(&release, (1000, 0o40755))]).unwrap_err();
        assert!(
            err.to_string().contains(&release.display().to_string()),
            "{err}"
        );
        let err = check(&link, &[(&links, (1000, 0o40755))]).unwrap_err();
        assert!(
            err.to_string().starts_with(&format!(
                "{} must be owned by root and writable only by root",
                links.display()
            )),
            "{err}"
        );

        // Owned by root, but group- or world-writable: only the mode check
        // refuses.
        for mode in [0o100775, 0o100757] {
            let err = check(&link, &[(&target, (0, mode))]).unwrap_err();
            assert!(
                err.to_string().contains("writable only by root"),
                "{mode:o}: {err}"
            );
        }
    }

    #[test]
    fn latest_installed_version_is_numeric() {
        let tmp = tempfile::TempDir::new().unwrap();
        for dir in ["2.1.0.9", "2.1.0.25", "2.1.0.100-x", ".tmp", "latest"] {
            std::fs::create_dir(tmp.path().join(dir)).unwrap();
        }
        std::fs::write(tmp.path().join("2.1.0.30"), b"not a directory").unwrap();
        assert_eq!(latest_version_in(tmp.path()).unwrap(), "2.1.0.25");
    }

    /// While one install or update holds the lock, another fails at once;
    /// it runs once the first ends.
    #[cfg(unix)]
    #[test]
    fn overlapping_node_updates_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("quilibrium").join(".auto-update.lock");
        let held = lock_node_updates(&path).unwrap();
        let err = lock_node_updates(&path).unwrap_err().to_string();
        assert!(
            err.contains("another qclient install, update or release source change"),
            "{err}"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        drop(held);
        lock_node_updates(&path).unwrap();
    }

    /// `auto-update enable` changes the release source only under the
    /// update lock: while an install or update holds it, the change is
    /// refused and nothing is stored; once it ends, the change runs.
    #[test]
    fn a_source_change_during_an_update_is_refused() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("quilibrium").join(".auto-update.lock");
        let held = lock_node_updates(&path).unwrap();
        let mut stored = false;
        let result = store_locked(&path, Some(ReleaseSource::official()), |named| {
            stored = true;
            Ok(named.unwrap())
        });
        assert!(
            !stored,
            "store_during_update: the source changed under a run"
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("release source change is running"), "{err}");
        drop(held);
        let source = store_locked(&path, Some(ReleaseSource::official()), |named| {
            Ok(named.unwrap())
        })
        .unwrap();
        assert_eq!(source, ReleaseSource::official());
    }

    /// `auto-update enable` naming no source only reads the stored one, so
    /// it runs while the auto-update job (or another install or update)
    /// holds the update lock, as it did before release sources.
    #[test]
    fn enable_naming_no_source_runs_during_an_update() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("quilibrium").join(".auto-update.lock");
        let held = lock_node_updates(&path).unwrap();
        let result = store_locked(&path, None, |named| {
            assert_eq!(named, None, "nothing named, nothing stored");
            Ok(ReleaseSource::official())
        });
        match result {
            Ok(source) => assert_eq!(source, ReleaseSource::official()),
            Err(e) => panic!("keep_locked: enable naming no source failed under a run: {e}"),
        }
        drop(held);
    }

    /// Every path root-owned and writable only by root.
    fn root_only(_: &Path) -> std::io::Result<(u32, u32)> {
        Ok((0, 0o40755))
    }

    /// The node release 2.1.0.25 installed in the install root `root`, its
    /// `.dgst` separating label and checksum with `sep`, signed as
    /// `.dgst.sig.1` by the one key of the release source stored in `root`
    /// and by no official signatory; returns its path. qclient's own parse
    /// reads a space or a tab there.
    fn custom_release_in(root: &Path, sep: &str) -> std::path::PathBuf {
        use quil_types::crypto::Signer;
        use sha3::{Digest, Sha3_256};
        let seed = [7u8; 57];
        let public = quil_crypto::Ed448Signer::derive_public(&seed).unwrap();
        let signer = quil_crypto::Ed448Signer::from_bytes(&seed, &public).unwrap();
        let key = hex::encode(public);
        let url = "https://releases.example.org";
        let source = ReleaseSource::custom(url, std::slice::from_ref(&key), None).unwrap();
        let path = root.join(quil_config::release_source::RELEASE_SOURCE_FILE);
        release_source::store_at(&path, Some(source), &root_only, &[]).unwrap();
        let base = release::release_filename(system::RELEASE_TYPE_NODE, "2.1.0.25").unwrap();
        let bin = b"node release".to_vec();
        let digest = format!(
            "SHA3-256({base})={sep}{}\n",
            hex::encode(Sha3_256::digest(&bin))
        );
        let release = release::Release {
            base,
            bin,
            sigs: vec![(1, signer.sign(digest.as_bytes()).unwrap())],
            digest: digest.into_bytes(),
        };
        let dest = root.join("bin").join("node").join("2.1.0.25");
        release.install_with(&dest, &[key.as_str()], 1).unwrap().0
    }

    /// `node link` links a release iff the node's startup check starts it:
    /// a custom release whose `.dgst` separates label and checksum with a
    /// tab, which qclient's own parse reads but the startup check does
    /// not, is refused and nothing is linked; with a space it links.
    #[cfg(unix)]
    #[test]
    fn link_takes_only_a_release_the_startup_check_starts() {
        for (sep, starts) in [(" ", true), ("\t", false)] {
            let tmp = tempfile::TempDir::new().unwrap();
            let root = std::fs::canonicalize(tmp.path()).unwrap();
            let bin = custom_release_in(&root, sep);
            let checked = quil_crypto::release_check::verify_release(
                &bin,
                &quil_config::SIGNATORIES,
                &root_only,
            );
            assert_eq!(checked.is_ok(), starts, "{sep:?}: {checked:?}");
            let link = root.join("quilibrium-node");
            let lock = root.join(".auto-update.lock");
            let result = link_startable(&bin, "2.1.0.25", &link, &lock, &root_only);
            let linked = std::fs::read_link(&link).ok();
            assert_eq!(
                linked.is_some(),
                starts,
                "link_unstartable: {sep:?} linked {linked:?}: {result:?}"
            );
            match result {
                Ok(()) => assert_eq!(linked, Some(bin)),
                Err(e) => assert!(e.to_string().contains("would not start it"), "{e}"),
            }
        }
    }

    /// `node link` does not link while an install, update or source change
    /// holds the update lock, so none of them changes what it checked
    /// before it links; once the lock is free, it links.
    #[cfg(unix)]
    #[test]
    fn link_during_an_update_is_refused() {
        let tmp = tempfile::TempDir::new().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let bin = custom_release_in(&root, " ");
        let link = root.join("quilibrium-node");
        let lock = root.join(".auto-update.lock");
        let held = lock_node_updates(&lock).unwrap();
        let result = link_startable(&bin, "2.1.0.25", &link, &lock, &root_only);
        assert!(
            std::fs::symlink_metadata(&link).is_err(),
            "link_during_update: linked under a run: {result:?}"
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("release source change is running"), "{err}");
        drop(held);
        link_startable(&bin, "2.1.0.25", &link, &lock, &root_only).unwrap();
        assert_eq!(std::fs::read_link(&link).unwrap(), bin);
    }
}

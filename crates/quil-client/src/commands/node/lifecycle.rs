//! `qclient node install|update|link|uninstall` — node binary lifecycle.
//!
//! Port of `client/cmd/node/{install,update,link,uninstall}.go`. Reuses the
//! shared release download+verify ([`crate::release`]) and service management
//! ([`super::service`]). Install/symlink paths require root.

use std::path::Path;

use crate::{release, system};

/// The lock `node install` and `node update` hold while they change the
/// node install, so auto-update runs (every 10 minutes) and manual runs
/// never overlap.
const UPDATE_LOCK: &str = "/var/quilibrium/.auto-update.lock";

/// Take the exclusive lock at `path` (created 0600 if absent) until the
/// returned file closes; fail at once if another run holds it.
fn lock_node_updates(path: &Path) -> anyhow::Result<std::fs::File> {
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
            "another qclient node install or update is running (it holds {}); nothing done",
            path.display()
        ),
        Err(std::fs::TryLockError::Error(e)) => {
            anyhow::bail!("lock {}: {e}", path.display())
        }
    }
}

/// `node install [version]` — download+verify+install the node binary, then
/// install the system service. An older version than the linked one needs
/// `allow_downgrade`.
pub async fn install(version: Option<&str>, allow_downgrade: bool) -> anyhow::Result<()> {
    let _lock = lock_node_updates(Path::new(UPDATE_LOCK))?;
    let version = resolve_version(version).await?;
    println!("Installing Quilibrium node {version}...");
    let installed = release::download_and_install(
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
/// node version and optionally restart the service. An older version than
/// the linked one needs `allow_downgrade`.
pub async fn update(
    version: Option<&str>,
    restart: bool,
    allow_downgrade: bool,
) -> anyhow::Result<()> {
    let _lock = lock_node_updates(Path::new(UPDATE_LOCK))?;
    let version = resolve_version(version).await?;
    println!("Updating Quilibrium node to {version}...");
    let installed = release::download_and_install(
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
/// installed version (latest if unspecified) whose release signatures
/// verify.
pub fn link(version: Option<&str>) -> anyhow::Result<()> {
    let version = match version {
        Some(v) if !v.is_empty() && v != "latest" => v.to_string(),
        _ => latest_installed_node_version()?,
    };
    let base = release::release_filename(system::RELEASE_TYPE_NODE, &version)?;
    let bin_path = system::node_data_path().join(&version).join(&base);
    if !bin_path.exists() {
        anyhow::bail!("node binary not found: {}", bin_path.display());
    }
    release::verify_installed(&bin_path).map_err(|e| {
        anyhow::anyhow!(
            "{} does not verify against its release signatures: {e}; reinstall it with \
             'qclient node install {version}'",
            bin_path.display()
        )
    })?;
    let link = system::default_node_symlink_path();
    release::switch_symlink(&bin_path, &link)?;
    println!("Linked {} → {}", link.display(), bin_path.display());
    Ok(())
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
/// `qclient node update --restart` every 10 minutes.
pub fn auto_update(action: &str) -> anyhow::Result<()> {
    match action {
        "enable" => cron_enable(),
        "disable" => cron_disable(),
        "status" => cron_status(),
        other => anyhow::bail!("must specify 'enable', 'disable', or 'status' (got {other:?})"),
    }
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

/// The cron entry. It runs `/usr/local/bin/qclient`, which `qclient update`
/// points at a verified release, never the file this qclient was started
/// from: the job runs as root.
fn cron_line() -> anyhow::Result<String> {
    let qclient = system::default_qclient_symlink_path();
    let target = std::fs::canonicalize(&qclient).map_err(|e| {
        anyhow::anyhow!(
            "resolve {}: {e}; install qclient with 'sudo qclient update' first",
            qclient.display()
        )
    })?;
    let install_root = system::client_data_path();
    let install_root = std::fs::canonicalize(&install_root)
        .map_err(|e| anyhow::anyhow!("resolve {}: {e}", install_root.display()))?;
    check_cron_target(&target, &install_root)?;
    Ok(cron_entry(&qclient))
}

fn cron_entry(qclient: &Path) -> String {
    format!(
        "{} {} node update --restart {CRON_MARKER}",
        system::DEFAULT_AUTO_UPDATE_INTERVAL,
        qclient.display()
    )
}

/// Root runs the auto-update job, so its executable (`target`, resolved)
/// must be an installed qclient release under `install_root`, and it and
/// every directory above it must be owned by root and writable by no one
/// else.
#[cfg(unix)]
fn check_cron_target(target: &Path, install_root: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if !target.starts_with(install_root) {
        anyhow::bail!(
            "{} is not an installed qclient release under {}; run 'sudo qclient update' to \
             install one",
            target.display(),
            install_root.display()
        );
    }
    for path in target.ancestors() {
        let meta =
            std::fs::metadata(path).map_err(|e| anyhow::anyhow!("stat {}: {e}", path.display()))?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
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

fn cron_enable() -> anyhow::Result<()> {
    let current = current_crontab();
    let line = cron_line()?;
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
    lines.push(line);
    write_crontab(&(lines.join("\n") + "\n"))?;
    println!(
        "Auto-update enabled (every 10 minutes, running {})",
        system::default_qclient_symlink_path().display()
    );
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
    Ok(())
}

async fn resolve_version(version: Option<&str>) -> anyhow::Result<String> {
    match version {
        Some(v) if !v.is_empty() => Ok(v.to_string()),
        _ => release::get_latest_version(system::RELEASE_TYPE_NODE).await,
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

    #[test]
    fn cron_entry_runs_the_installed_qclient() {
        assert_eq!(
            cron_entry(&system::default_qclient_symlink_path()),
            "*/10 * * * * /usr/local/bin/qclient node update --restart # quilibrium-auto-update"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cron_target_must_be_a_root_owned_installed_release() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let root = tmp.path().join("qclient");
        let dir = root.join("2.1.0.25");
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("qclient-2.1.0.25-linux-amd64");
        std::fs::write(&target, b"bin").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o777)).unwrap();
        let elsewhere = tmp.path().join("qclient-2.1.0.25-linux-amd64");
        std::fs::write(&elsewhere, b"bin").unwrap();

        let err = check_cron_target(&elsewhere, &root).unwrap_err();
        assert!(
            err.to_string().contains("not an installed qclient release"),
            "{err}"
        );
        // Writable by others (and, unless the tests run as root, owned by
        // another user).
        let err = check_cron_target(&target, &root).unwrap_err();
        assert!(err.to_string().contains("owned by root"), "{err}");
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
            err.contains("another qclient node install or update is running"),
            "{err}"
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        drop(held);
        lock_node_updates(&path).unwrap();
    }
}

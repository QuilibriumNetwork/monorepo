//! `qclient node install|update|link|uninstall` — node binary lifecycle.
//!
//! Port of `client/cmd/node/{install,update,link,uninstall}.go`. Reuses the
//! shared release download+verify ([`crate::release`]) and service management
//! ([`super::service`]). Install/symlink paths require root.

use crate::{release, system};

/// `node install [version]` — download+verify+install the node binary, then
/// install the system service.
pub async fn install(version: Option<&str>) -> anyhow::Result<()> {
    let version = resolve_version(version).await?;
    println!("Installing Quilibrium node {version}...");
    let bin_path = release::download_and_install(
        system::RELEASE_TYPE_NODE,
        &version,
        &system::default_node_symlink_path(),
    )
    .await?;
    println!("Installed node to {}", bin_path.display());
    super::service::run("install")?;
    Ok(())
}

/// `node update [version] [--restart]` — install a newer node version and
/// optionally restart the service.
pub async fn update(version: Option<&str>, restart: bool) -> anyhow::Result<()> {
    let version = resolve_version(version).await?;
    println!("Updating Quilibrium node to {version}...");
    let bin_path = release::download_and_install(
        system::RELEASE_TYPE_NODE,
        &version,
        &system::default_node_symlink_path(),
    )
    .await?;
    println!("Updated node to {}", bin_path.display());
    if restart {
        super::service::run("restart")?;
    }
    Ok(())
}

/// `node link [version]` — point `/usr/local/bin/quilibrium-node` at an
/// installed version (latest if unspecified).
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
    let link = system::default_node_symlink_path();
    let _ = std::fs::remove_file(&link);
    #[cfg(unix)]
    std::os::unix::fs::symlink(&bin_path, &link)
        .map_err(|e| anyhow::anyhow!("symlink {}: {e} (root required)", link.display()))?;
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

fn cron_line() -> anyhow::Result<String> {
    let exe = std::env::current_exe()?;
    Ok(format!(
        "{} {} node update --restart {CRON_MARKER}",
        system::DEFAULT_AUTO_UPDATE_INTERVAL,
        exe.display()
    ))
}

fn cron_enable() -> anyhow::Result<()> {
    let current = current_crontab();
    if current.contains(CRON_MARKER) {
        println!("Auto-update is already enabled");
        return Ok(());
    }
    let mut lines: Vec<String> = current.lines().map(String::from).collect();
    lines.push(cron_line()?);
    write_crontab(&(lines.join("\n") + "\n"))?;
    println!("Auto-update enabled (every 10 minutes)");
    Ok(())
}

fn cron_disable() -> anyhow::Result<()> {
    let current = current_crontab();
    if !current.contains(CRON_MARKER) {
        println!("Auto-update is not enabled");
        return Ok(());
    }
    let kept: Vec<&str> = current.lines().filter(|l| !l.contains(CRON_MARKER)).collect();
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

/// The lexicographically-highest installed node version directory.
fn latest_installed_node_version() -> anyhow::Result<String> {
    let data = system::node_data_path();
    let mut versions: Vec<String> = std::fs::read_dir(&data)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", data.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    versions.sort();
    versions
        .pop()
        .ok_or_else(|| anyhow::anyhow!("no installed node versions in {}", data.display()))
}

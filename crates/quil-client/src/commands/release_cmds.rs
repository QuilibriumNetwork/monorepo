//! Top-level `update` and `download-signatures` commands.
//!
//! Port of `client/cmd/update.go` + `client/cmd/download-signatures.go`.
//! Download the qclient release + its signatory signatures, verify the
//! quorum, install to `/var/quilibrium/bin/qclient/{version}`, and symlink
//! `/usr/local/bin/qclient`. (Install paths require root.) Nothing reaches
//! the install path before it verifies.

use std::path::{Path, PathBuf};

use crate::{release, system};

/// Where `download-signatures` writes: beside the running binary when it is
/// the release `base`, where its self-check reads them; else `install_dir`.
fn signature_dir(exe: Option<&Path>, base: &str, install_dir: &Path) -> PathBuf {
    exe.and_then(|exe| std::fs::canonicalize(exe).ok())
        .filter(|exe| exe.file_name().is_some_and(|name| name == base))
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| install_dir.to_path_buf())
}

/// The version `download-signatures` fetches: the running one unless named,
/// since the files feed this binary's self-check.
fn signature_version(requested: Option<&str>) -> &str {
    match requested {
        Some(v) if !v.is_empty() => v,
        _ => quil_config::VERSION_STRING,
    }
}

/// `qclient download-signatures [--version V]`.
pub async fn download_signatures(version: Option<&str>) -> anyhow::Result<()> {
    let version = signature_version(version).to_string();
    let base = release::release_filename(system::RELEASE_TYPE_QCLIENT, &version)?;
    let exe = std::env::current_exe().ok();
    let install_dir = system::client_data_path().join(&version);
    let dest = signature_dir(exe.as_deref(), &base, &install_dir);
    println!("Downloading signatures for qclient {version}...");
    let (digest, sigs) = release::fetch_signatures(system::RELEASE_TYPE_QCLIENT, &version).await?;
    let count = release::verify_quorum(&digest, &sigs)?;
    let quorum = quil_config::signatory_quorum();
    println!("{count}/{} signatures valid (quorum {quorum})", sigs.len());
    if count < quorum {
        anyhow::bail!(
            "signature quorum not met; nothing written to {}",
            dest.display()
        );
    }
    release::check_digest_label(&digest, &base)?;
    release::write_signature_files(&dest, &base, &digest, &sigs)?;
    println!("Wrote the signature files to {}", dest.display());
    Ok(())
}

/// `qclient update [version] [--allow-downgrade]`. An older version than the
/// linked one needs `allow_downgrade`.
pub async fn update(version: Option<&str>, allow_downgrade: bool) -> anyhow::Result<()> {
    let (os, arch) = system::system_info()?;
    let version = match version {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => release::get_latest_version(system::RELEASE_TYPE_QCLIENT).await?,
    };
    println!("Updating qclient for {os}-{arch}, version: {version}");
    let installed = release::download_and_install(
        system::RELEASE_TYPE_QCLIENT,
        &version,
        &system::default_qclient_symlink_path(),
        allow_downgrade,
    )
    .await?;
    if installed.fresh {
        println!(
            "Updated qclient to {version} at {}",
            installed.path.display()
        );
    } else {
        println!("qclient {version} is already installed; nothing to update");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_default_to_the_running_version() {
        assert_eq!(signature_version(None), quil_config::VERSION_STRING);
        assert_eq!(signature_version(Some("")), quil_config::VERSION_STRING);
        assert_eq!(signature_version(Some("2.1.0.9")), "2.1.0.9");
    }

    /// A manually downloaded release gets its signature files beside it, so
    /// its self-check passes; any other binary leaves them in the install
    /// directory.
    #[test]
    fn signatures_go_beside_the_running_release() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = std::fs::canonicalize(tmp.path()).unwrap();
        let base = "qclient-2.1.0.25-linux-amd64";
        let release = dir.join(base);
        std::fs::write(&release, b"release").unwrap();
        let other = dir.join("qclient");
        std::fs::write(&other, b"build").unwrap();
        let install = Path::new("/var/quilibrium/bin/qclient/2.1.0.25");

        assert_eq!(signature_dir(Some(&release), base, install), dir);
        assert_eq!(signature_dir(Some(&other), base, install), install);
        assert_eq!(signature_dir(None, base, install), install);
        let older = "qclient-2.1.0.24-linux-amd64";
        assert_eq!(signature_dir(Some(&release), older, install), install);
    }
}

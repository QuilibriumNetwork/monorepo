//! Top-level `update` and `download-signatures` commands.
//!
//! Port of `client/cmd/update.go` + `client/cmd/download-signatures.go`.
//! Download the qclient release + its signatory signatures, verify the
//! quorum, install to `/var/quilibrium/bin/qclient/{version}`, and symlink
//! `/usr/local/bin/qclient`. (Install paths require root.) Nothing reaches
//! the install path before it verifies.

use crate::{release, system};

/// `qclient download-signatures [--version V]`.
pub async fn download_signatures(version: Option<&str>) -> anyhow::Result<()> {
    let version = match version {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => release::get_latest_version(system::RELEASE_TYPE_QCLIENT).await?,
    };
    let base = release::release_filename(system::RELEASE_TYPE_QCLIENT, &version)?;
    let dest = system::client_data_path().join(&version);
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

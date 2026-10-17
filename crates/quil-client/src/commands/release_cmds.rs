//! Top-level `update` and `download-signatures` commands.
//!
//! Port of `client/cmd/update.go` + `client/cmd/download-signatures.go`.
//! Download the qclient release + its signatory signatures, verify the
//! quorum, install to `/var/quilibrium/bin/qclient/{version}`, and symlink
//! `/usr/local/bin/qclient`. (Install paths require root.)

use crate::{release, system};

/// `qclient download-signatures [--version V]`.
pub async fn download_signatures(version: Option<&str>) -> anyhow::Result<()> {
    let version = match version {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => release::get_latest_version(system::RELEASE_TYPE_QCLIENT).await?,
    };
    let dest = system::client_data_path().join(&version);
    println!("Downloading signatures for qclient {version}...");
    let (digest, sigs) = release::download_signatures(system::RELEASE_TYPE_QCLIENT, &version, &dest).await?;
    let count = release::verify_quorum(&digest, &sigs)?;
    println!(
        "{count}/{} signatures valid (quorum {})",
        sigs.len(),
        quil_config::signatory_quorum()
    );
    Ok(())
}

/// `qclient update [version]`.
pub async fn update(version: Option<&str>) -> anyhow::Result<()> {
    let (os, arch) = system::system_info()?;
    let version = match version {
        Some(v) if !v.is_empty() => v.to_string(),
        _ => release::get_latest_version(system::RELEASE_TYPE_QCLIENT).await?,
    };
    println!("Updating qclient for {os}-{arch}, version: {version}");
    let bin_path = release::download_and_install(
        system::RELEASE_TYPE_QCLIENT,
        &version,
        &system::default_qclient_symlink_path(),
    )
    .await?;
    println!("Updated qclient to {version} at {}", bin_path.display());
    Ok(())
}

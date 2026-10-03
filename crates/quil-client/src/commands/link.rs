//! `qclient link` — symlink the qclient binary into `/usr/local/bin` so it can
//! be run from anywhere. Port of `client/cmd/link.go`.
//!
//! Requires write access to `/usr/local/bin` (run with sudo). Unlike the Go
//! version we do not offer to relocate the binary into the standard data path;
//! we symlink the executable wherever it currently lives.

use crate::system;

pub fn run() -> anyhow::Result<()> {
    let exec_path = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("failed to get executable path: {e}"))?;
    // Resolve symlinks so we point at the real binary, not another symlink.
    let exec_path = std::fs::canonicalize(&exec_path).unwrap_or(exec_path);

    let link = system::default_qclient_symlink_path();

    // Replace an existing link/file at the target (CreateSymlink semantics).
    if link.exists() || std::fs::symlink_metadata(&link).is_ok() {
        std::fs::remove_file(&link).map_err(|e| {
            anyhow::anyhow!(
                "failed to remove existing {}: {e} (run with sudo)",
                link.display()
            )
        })?;
    }

    std::os::unix::fs::symlink(&exec_path, &link).map_err(|e| {
        anyhow::anyhow!(
            "failed to create symlink {}: {e} (write access required — run with sudo)",
            link.display()
        )
    })?;

    println!("Symlink created at {} → {}", link.display(), exec_path.display());
    Ok(())
}

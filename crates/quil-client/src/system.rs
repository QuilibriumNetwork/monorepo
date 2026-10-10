//! OS / filesystem plumbing shared across commands.
//!
//! Port of `client/utils/system.go`, `client/utils/client.go`, and the
//! path constants in `client/utils/fileUtils.go` / `client/utils/node.go`.

use std::path::{Path, PathBuf};

/// `client/utils/fileUtils.go:18` — `/var/quilibrium/`.
pub const ROOT_QUILIBRIUM_PATH: &str = "/var/quilibrium";
/// `client/utils/fileUtils.go:19` — `/var/quilibrium/bin`.
pub const BINARY_PATH: &str = "/var/quilibrium/bin";
/// `client/utils/fileUtils.go:20` — `/usr/local/bin`.
pub const DEFAULT_SYMLINK_DIR: &str = "/usr/local/bin";
/// `client/utils/node.go:24` — `/var/log/quilibrium`.
pub const LOG_PATH: &str = "/var/log/quilibrium";

/// Release-type discriminator (`client/utils/types.go`).
pub const RELEASE_TYPE_QCLIENT: &str = "qclient";
pub const RELEASE_TYPE_NODE: &str = "node";

/// `NodeServiceName` (`client/utils/node.go:22`).
pub const NODE_SERVICE_NAME: &str = "quilibrium-node";
/// Default node config directory name (`client/utils/node.go:19`).
pub const DEFAULT_NODE_CONFIG_NAME: &str = "node-quickstart";
/// Default auto-update cron interval (`client/utils/types.go`).
pub const DEFAULT_AUTO_UPDATE_INTERVAL: &str = "*/10 * * * *";

/// Base release URL (`client/utils/download.go:13`).
pub const BASE_RELEASE_URL: &str = "https://releases.quilibrium.com";

/// `client/utils/client.go` — `/var/quilibrium/bin/qclient`.
pub fn client_data_path() -> PathBuf {
    Path::new(BINARY_PATH).join(RELEASE_TYPE_QCLIENT)
}

/// `client/utils/client.go` — `/var/quilibrium/bin/node`.
pub fn node_data_path() -> PathBuf {
    Path::new(BINARY_PATH).join(RELEASE_TYPE_NODE)
}

/// `client/utils/client.go` — `/usr/local/bin/qclient`.
pub fn default_qclient_symlink_path() -> PathBuf {
    Path::new(DEFAULT_SYMLINK_DIR).join(RELEASE_TYPE_QCLIENT)
}

/// `client/utils/node.go:23` — `/usr/local/bin/quilibrium-node`.
pub fn default_node_symlink_path() -> PathBuf {
    Path::new(DEFAULT_SYMLINK_DIR).join(NODE_SERVICE_NAME)
}

/// `client/utils/node.go:21` — `/var/quilibrium/quilibrium.env`.
pub fn node_env_path() -> PathBuf {
    Path::new(ROOT_QUILIBRIUM_PATH).join("quilibrium.env")
}

/// Normalized OS name — `darwin` or `linux` (matches Go `runtime.GOOS`).
pub fn os_type() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        // Unsupported; validated by `system_info`.
        std::env::consts::OS
    }
}

/// Normalized architecture — `amd64` or `arm64` (matches Go `runtime.GOARCH`).
pub fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Validate + return `(os, arch)`. Port of `GetSystemInfo`
/// (`client/utils/system.go:15`).
pub fn system_info() -> anyhow::Result<(&'static str, &'static str)> {
    let os = os_type();
    if os != "darwin" && os != "linux" {
        anyhow::bail!("unsupported operating system: {os}");
    }
    let arch = arch();
    if arch != "amd64" && arch != "arm64" {
        anyhow::bail!("unsupported architecture: {arch}");
    }
    Ok((os, arch))
}

/// The home directory of the invoking user, honoring `SUDO_USER` when
/// running under sudo. Port of `GetCurrentSudoUser` + `GetUserQuilibriumDir`
/// (`client/utils/system.go:37`).
///
/// When `euid != 0` we use the current user's `$HOME`. When running as
/// root under sudo we resolve `$SUDO_USER`'s home so config files land in
/// the operator's `~/.quilibrium`, not root's.
pub fn current_user_home() -> anyhow::Result<PathBuf> {
    // euid: only meaningful on unix; on non-unix fall back to $HOME.
    #[cfg(unix)]
    let is_root = unsafe { libc_geteuid() } == 0;
    #[cfg(not(unix))]
    let is_root = false;

    if is_root {
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            if !sudo_user.is_empty() && sudo_user != "root" {
                if let Some(home) = home_of_user(&sudo_user) {
                    return Ok(home);
                }
            }
        }
    }

    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("could not determine home directory ($HOME unset)"))
}

/// `~/.quilibrium` for the invoking (sudo-aware) user.
pub fn user_quilibrium_dir() -> anyhow::Result<PathBuf> {
    Ok(current_user_home()?.join(".quilibrium"))
}

/// `~/.quilibrium/configs` — the node config home
/// (`client/utils/node.go:GetNodeConfigHomeDir`).
pub fn node_config_home_dir() -> anyhow::Result<PathBuf> {
    Ok(user_quilibrium_dir()?.join("configs"))
}

/// Look up a user's home directory from `/etc/passwd` without pulling in a
/// crate. Returns `None` if not found.
#[cfg(unix)]
fn home_of_user(username: &str) -> Option<PathBuf> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let mut fields = line.split(':');
        if fields.next() == Some(username) {
            // fields: passwd, uid, gid, gecos, home, shell
            let home = fields.nth(3)?; // 4th field after name = index 3
            return Some(PathBuf::from(home));
        }
    }
    None
}

#[cfg(not(unix))]
fn home_of_user(_username: &str) -> Option<PathBuf> {
    None
}

#[cfg(unix)]
extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

/// Whether a file/dir exists (`client/utils/fileUtils.go` `FileExists`).
pub fn file_exists<P: AsRef<Path>>(p: P) -> bool {
    p.as_ref().exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_and_os_are_normalized() {
        // Whatever host we run on, the value is one of the Go-style names
        // or the raw fallback; the important invariant is the mapping.
        assert_eq!(arch(), match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            o => o,
        });
    }

    #[test]
    fn path_constants_match_go() {
        assert_eq!(client_data_path(), PathBuf::from("/var/quilibrium/bin/qclient"));
        assert_eq!(node_data_path(), PathBuf::from("/var/quilibrium/bin/node"));
        assert_eq!(
            default_qclient_symlink_path(),
            PathBuf::from("/usr/local/bin/qclient")
        );
        assert_eq!(
            default_node_symlink_path(),
            PathBuf::from("/usr/local/bin/quilibrium-node")
        );
        assert_eq!(node_env_path(), PathBuf::from("/var/quilibrium/quilibrium.env"));
    }
}

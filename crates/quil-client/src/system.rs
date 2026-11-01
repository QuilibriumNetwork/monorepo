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

/// The name of the invoking (sudo-aware) user, by the rule of
/// [`current_user_home`]: `$SUDO_USER` when root runs under sudo for a
/// user listed in `/etc/passwd`, else the effective user.
#[cfg(unix)]
pub fn current_user_name() -> anyhow::Result<String> {
    let euid = unsafe { libc_geteuid() };
    let passwd = std::fs::read_to_string("/etc/passwd")
        .map_err(|e| anyhow::anyhow!("read /etc/passwd: {e}"))?;
    let sudo_user = std::env::var("SUDO_USER").ok();
    user_name_for(euid, sudo_user.as_deref(), &passwd)
        .ok_or_else(|| anyhow::anyhow!("no /etc/passwd entry for user id {euid}"))
}

#[cfg(not(unix))]
pub fn current_user_name() -> anyhow::Result<String> {
    anyhow::bail!("no user database on this platform")
}

/// [`current_user_name`] for the effective user id `euid`, `$SUDO_USER`
/// `sudo_user` and the `/etc/passwd` text `passwd`.
#[cfg(unix)]
fn user_name_for(euid: u32, sudo_user: Option<&str>, passwd: &str) -> Option<String> {
    match sudo_user {
        Some(user)
            if euid == 0
                && !user.is_empty()
                && user != "root"
                && passwd_home(passwd, user).is_some() =>
        {
            Some(user.to_string())
        }
        _ => passwd_name(passwd, euid),
    }
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
    passwd_home(&passwd, username)
}

/// The fields of each well-formed `/etc/passwd` line:
/// `name:password:uid:gid:gecos:home:shell`.
#[cfg(unix)]
fn passwd_entries(passwd: &str) -> impl Iterator<Item = Vec<&str>> {
    passwd
        .lines()
        .map(|line| line.split(':').collect::<Vec<_>>())
        .filter(|fields| fields.len() == 7)
}

/// The home directory of `username` in the `/etc/passwd` text `passwd`.
#[cfg(unix)]
fn passwd_home(passwd: &str, username: &str) -> Option<PathBuf> {
    passwd_entries(passwd)
        .find(|fields| fields[0] == username)
        .map(|fields| PathBuf::from(fields[5]))
}

/// The name of the user with id `uid` in the `/etc/passwd` text `passwd`.
#[cfg(unix)]
fn passwd_name(passwd: &str, uid: u32) -> Option<String> {
    passwd_entries(passwd)
        .find(|fields| fields[2].parse() == Ok(uid))
        .map(|fields| fields[0].to_string())
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

/// The node binary to run for this host: see [`resolve_node_binary`].
pub fn node_binary() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().ok();
    let cwd_entries: Vec<PathBuf> = std::fs::read_dir(".")
        .map(|dir| dir.filter_map(|e| e.ok().map(|e| e.path())).collect())
        .unwrap_or_default();
    resolve_node_binary(
        find_on_path(NODE_SERVICE_NAME),
        exe.as_deref(),
        &|p| p.is_file(),
        &cwd_entries,
        os_type(),
        arch(),
    )
}

/// The first executable file `name` in a `$PATH` directory, as the shell
/// would run it.
fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| is_executable(p))
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.is_file()
}

/// Locate the node binary, in order: `on_path`, the `quilibrium-node` that
/// `qclient node install`/`link` put on PATH; the release file beside the
/// running qclient `exe`, its leading `qclient` replaced by `node`
/// (`qclient-2.1.0.25-linux-amd64` runs `node-2.1.0.25-linux-amd64`); else
/// the one `node-<version>-<os>-<arch>` file among `cwd_entries`, as a node
/// run from its release files keeps it. Copies with a further suffix
/// (`.bak-…`, `.candidate-…`, `.dgst`) never qualify, and of several
/// versions none is picked.
fn resolve_node_binary(
    on_path: Option<PathBuf>,
    exe: Option<&Path>,
    is_file: &dyn Fn(&Path) -> bool,
    cwd_entries: &[PathBuf],
    os: &str,
    arch: &str,
) -> anyhow::Result<PathBuf> {
    if let Some(path) = on_path {
        return Ok(path);
    }
    let beside = exe.and_then(|exe| {
        let rest = exe
            .file_name()?
            .to_str()?
            .strip_prefix(RELEASE_TYPE_QCLIENT)?;
        // Only a versioned name: a bare `qclient` would map to `node`,
        // which on many hosts is Node.js.
        rest.starts_with('-')
            .then(|| exe.with_file_name(format!("{RELEASE_TYPE_NODE}{rest}")))
    });
    if let Some(path) = beside.filter(|p| is_file(p)) {
        return Ok(path);
    }
    let suffix = format!("-{os}-{arch}");
    let found: Vec<&PathBuf> = cwd_entries
        .iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_prefix("node-"))
                .and_then(|n| n.strip_suffix(suffix.as_str()))
                .is_some_and(is_release_version)
                && is_file(p)
        })
        .collect();
    match found.as_slice() {
        [one] => Ok((*one).clone()),
        [] => anyhow::bail!(
            "no node binary found: {NODE_SERVICE_NAME} is not on PATH, no node-… file \
             matching this qclient's name sits beside it, and the current directory \
             holds no node-<version>{suffix}; run 'qclient node link' to put an installed \
             version on PATH, or run qclient from the node directory"
        ),
        several => {
            let mut names: Vec<String> = several
                .iter()
                .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .collect();
            names.sort();
            anyhow::bail!(
                "several node binaries in the current directory ({}) and none beside this \
                 qclient matches its name; run the qclient-<version>{suffix} of the version \
                 to use from this directory, or move the others away",
                names.join(", ")
            )
        }
    }
}

/// A release version such as `2.1.0.25`: digits and dots.
fn is_release_version(v: &str) -> bool {
    v.starts_with(|c: char| c.is_ascii_digit()) && v.chars().all(|c| c.is_ascii_digit() || c == '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_and_os_are_normalized() {
        // Whatever host we run on, the value is one of the Go-style names
        // or the raw fallback; the important invariant is the mapping.
        assert_eq!(
            arch(),
            match std::env::consts::ARCH {
                "x86_64" => "amd64",
                "aarch64" => "arm64",
                o => o,
            }
        );
    }

    #[test]
    fn path_constants_match_go() {
        assert_eq!(
            client_data_path(),
            PathBuf::from("/var/quilibrium/bin/qclient")
        );
        assert_eq!(node_data_path(), PathBuf::from("/var/quilibrium/bin/node"));
        assert_eq!(
            default_qclient_symlink_path(),
            PathBuf::from("/usr/local/bin/qclient")
        );
        assert_eq!(
            default_node_symlink_path(),
            PathBuf::from("/usr/local/bin/quilibrium-node")
        );
        assert_eq!(
            node_env_path(),
            PathBuf::from("/var/quilibrium/quilibrium.env")
        );
    }

    /// `resolve_node_binary` over a fake file system: `files` are the
    /// regular files, `cwd` the current directory's entries.
    fn resolve(
        on_path: Option<&str>,
        exe: &str,
        files: &[&str],
        cwd: &[&str],
    ) -> anyhow::Result<PathBuf> {
        let cwd: Vec<PathBuf> = cwd.iter().map(PathBuf::from).collect();
        resolve_node_binary(
            on_path.map(PathBuf::from),
            Some(Path::new(exe)),
            &|p| files.iter().any(|f| Path::new(f) == p),
            &cwd,
            "linux",
            "amd64",
        )
    }

    #[test]
    fn node_binary_on_path_comes_first() {
        let node = "./node-2.1.0.25-linux-amd64";
        let found = resolve(
            Some("/usr/local/bin/quilibrium-node"),
            "/opt/q/qclient-2.1.0.25-linux-amd64",
            &["/opt/q/node-2.1.0.25-linux-amd64", node],
            &[node],
        )
        .unwrap();
        assert_eq!(found, PathBuf::from("/usr/local/bin/quilibrium-node"));
    }

    #[test]
    fn node_binary_beside_qclient_matches_its_name() {
        // The sibling wins over the current directory's other version.
        let other = "./node-2.1.0.24-linux-amd64";
        let found = resolve(
            None,
            "/opt/q/qclient-2.1.0.25-linux-amd64",
            &["/opt/q/node-2.1.0.25-linux-amd64", other],
            &[other],
        )
        .unwrap();
        assert_eq!(found, PathBuf::from("/opt/q/node-2.1.0.25-linux-amd64"));
    }

    #[test]
    fn node_binary_beside_bare_qclient_is_not_node_js() {
        let node = "./node-2.1.0.25-linux-amd64";
        let found = resolve(None, "/usr/bin/qclient", &["/usr/bin/node", node], &[node]).unwrap();
        assert_eq!(found, PathBuf::from(node));
    }

    #[test]
    fn node_binary_in_cwd_skips_copies_and_other_platforms() {
        let node = "./node-2.1.0.25-linux-amd64";
        let cwd = [
            node,
            "./node-2.1.0.24-linux-amd64.bak-20261020",
            "./node-2.1.0.25-linux-amd64.candidate-abc",
            "./node-2.1.0.25-linux-amd64.dgst",
            "./node-2.1.0.25-linux-arm64",
            "./node-2.1.0.25-darwin-amd64",
            "./node-linux-amd64",
            "./qclient-2.1.0.25-linux-amd64",
        ];
        // qclient was not started from here, so nothing sits beside it.
        let exe = "/opt/other/qclient-2.1.0.25-linux-amd64";
        let found = resolve(None, exe, &cwd, &cwd).unwrap();
        assert_eq!(found, PathBuf::from(node));
    }

    #[test]
    fn node_binary_in_cwd_must_be_a_regular_file() {
        let node = "./node-2.1.0.25-linux-amd64";
        let dir = "./node-2.1.0.24-linux-amd64";
        let found = resolve(None, "/opt/q/qclient", &[node], &[dir, node]).unwrap();
        assert_eq!(found, PathBuf::from(node));
    }

    #[test]
    fn node_binary_of_several_versions_is_none() {
        let cwd = ["./node-2.1.0.24-linux-amd64", "./node-2.1.0.25-linux-amd64"];
        let err = resolve(None, "/opt/q/qclient", &cwd, &cwd)
            .unwrap_err()
            .to_string();
        assert!(err.contains("several node binaries"), "{err}");
        assert!(
            err.contains("node-2.1.0.24-linux-amd64, node-2.1.0.25-linux-amd64"),
            "{err}"
        );
    }

    #[test]
    fn node_binary_not_found_names_the_fixes() {
        let err = resolve(None, "/opt/q/qclient", &[], &["./.config"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("quilibrium-node is not on PATH"), "{err}");
        assert!(err.contains("node-<version>-linux-amd64"), "{err}");
        assert!(err.contains("qclient node link"), "{err}");
        assert!(err.contains("from the node directory"), "{err}");
    }

    #[cfg(unix)]
    const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\n\
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
        op:x:1000:1000:Node Operator,,,:/home/op:/bin/bash\n\
        bare:x:1001:1001::/srv/bare:/bin/sh\n";

    /// The home directory is the sixth field, not the comment (GECOS)
    /// field before it.
    #[cfg(unix)]
    #[test]
    fn passwd_home_is_the_home_field() {
        assert_eq!(passwd_home(PASSWD, "op"), Some(PathBuf::from("/home/op")));
        assert_eq!(
            passwd_home(PASSWD, "bare"),
            Some(PathBuf::from("/srv/bare"))
        );
        assert_eq!(passwd_home(PASSWD, "root"), Some(PathBuf::from("/root")));
        assert_eq!(passwd_home(PASSWD, "nobody"), None);
    }

    /// The service user is the operator who ran `sudo`, else the effective
    /// user; never a user the passwd file lacks.
    #[cfg(unix)]
    #[test]
    fn invoking_user_name_is_the_sudo_user_or_the_effective_user() {
        assert_eq!(user_name_for(0, Some("op"), PASSWD).as_deref(), Some("op"));
        assert_eq!(user_name_for(0, None, PASSWD).as_deref(), Some("root"));
        assert_eq!(
            user_name_for(0, Some("root"), PASSWD).as_deref(),
            Some("root")
        );
        assert_eq!(
            user_name_for(0, Some("ghost"), PASSWD).as_deref(),
            Some("root")
        );
        assert_eq!(
            user_name_for(1000, Some("bare"), PASSWD).as_deref(),
            Some("op")
        );
        assert_eq!(user_name_for(1001, None, PASSWD).as_deref(), Some("bare"));
        assert_eq!(user_name_for(4242, None, PASSWD), None);
    }
}

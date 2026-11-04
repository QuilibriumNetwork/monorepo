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
    if is_root() {
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
/// user the user database knows, else the effective user.
#[cfg(unix)]
pub fn current_user_name() -> anyhow::Result<String> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let sudo_user = std::env::var("SUDO_USER").ok();
    user_name_for(euid, sudo_user.as_deref(), &user_by_name, &user_by_uid)
        .ok_or_else(|| anyhow::anyhow!("no user database entry for user id {euid}"))
}

#[cfg(not(unix))]
pub fn current_user_name() -> anyhow::Result<String> {
    anyhow::bail!("no user database on this platform")
}

/// [`current_user_name`] for the effective user id `euid` and `$SUDO_USER`
/// `sudo_user`, looking users up by name with `by_name` and by id with
/// `by_uid`.
#[cfg(unix)]
fn user_name_for(
    euid: libc::uid_t,
    sudo_user: Option<&str>,
    by_name: &dyn Fn(&str) -> Option<UserEntry>,
    by_uid: &dyn Fn(libc::uid_t) -> Option<UserEntry>,
) -> Option<String> {
    match sudo_user {
        Some(user)
            if euid == 0 && !user.is_empty() && user != "root" && by_name(user).is_some() =>
        {
            Some(user.to_string())
        }
        _ => by_uid(euid).map(|entry| entry.name),
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

/// A user's home directory, from the user database. Returns `None` if not
/// found.
#[cfg(unix)]
fn home_of_user(username: &str) -> Option<PathBuf> {
    user_by_name(username).map(|entry| entry.home)
}

#[cfg(not(unix))]
fn home_of_user(_username: &str) -> Option<PathBuf> {
    None
}

/// A user database entry: the fields qclient reads.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct UserEntry {
    name: String,
    home: PathBuf,
}

/// The user database entry of `name` (`getpwnam_r`). The C library
/// answers from the system's user database, which on macOS is Directory
/// Services rather than `/etc/passwd`.
#[cfg(unix)]
fn user_by_name(name: &str) -> Option<UserEntry> {
    let name = std::ffi::CString::new(name).ok()?;
    user_entry(|pwd, buf, len, result| {
        // SAFETY: `name` is NUL-terminated and outlives the call; the
        // other pointers come from `user_entry`, valid for `len` bytes.
        unsafe { libc::getpwnam_r(name.as_ptr(), pwd, buf, len, result) }
    })
}

/// The user database entry of user id `uid` (`getpwuid_r`).
#[cfg(unix)]
fn user_by_uid(uid: libc::uid_t) -> Option<UserEntry> {
    user_entry(|pwd, buf, len, result| {
        // SAFETY: the pointers come from `user_entry`, valid for `len`
        // bytes.
        unsafe { libc::getpwuid_r(uid, pwd, buf, len, result) }
    })
}

/// The largest buffer [`user_entry`] offers a lookup, 1 MiB.
#[cfg(unix)]
const USER_ENTRY_MAX_BUF: usize = 1 << 20;

/// Run a `getpw*_r` style `lookup` (entry, buffer, buffer length, result),
/// doubling its buffer from 1 KiB while it reports `ERANGE`. `None` when
/// the user is unknown, the lookup fails, or the name is not UTF-8.
#[cfg(unix)]
fn user_entry(
    lookup: impl Fn(
        *mut libc::passwd,
        *mut libc::c_char,
        libc::size_t,
        *mut *mut libc::passwd,
    ) -> libc::c_int,
) -> Option<UserEntry> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;
    let mut len = 1024;
    loop {
        let mut buf: Vec<libc::c_char> = vec![0; len];
        let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = lookup(pwd.as_mut_ptr(), buf.as_mut_ptr(), buf.len(), &mut result);
        if rc == libc::ERANGE && len < USER_ENTRY_MAX_BUF {
            len *= 2;
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        // SAFETY: on success `result` points at the filled `pwd`, whose
        // strings are NUL-terminated within `buf`; both live to the end of
        // this iteration.
        let entry = unsafe { &*result };
        let field = |p: *mut libc::c_char| {
            // SAFETY: as above, a non-null field is a NUL-terminated string.
            (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes())
        };
        let name = std::str::from_utf8(field(entry.pw_name)?).ok()?.to_string();
        let home = PathBuf::from(OsStr::from_bytes(field(entry.pw_dir)?));
        return Some(UserEntry { name, home });
    }
}

/// Whether this process runs as root (effective user id 0).
#[cfg(unix)]
pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Whether this process runs as root: never off unix.
#[cfg(not(unix))]
pub fn is_root() -> bool {
    false
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

    /// A user database of `(name, uid, home)` rows.
    #[cfg(unix)]
    const USERS: &[(&str, libc::uid_t, &str)] = &[
        ("root", 0, "/root"),
        ("op", 1000, "/Users/op"),
        ("bare", 1001, "/srv/bare"),
    ];

    #[cfg(unix)]
    fn entry(&(name, _, home): &(&str, libc::uid_t, &str)) -> UserEntry {
        UserEntry {
            name: name.to_string(),
            home: PathBuf::from(home),
        }
    }

    #[cfg(unix)]
    fn by_name(name: &str) -> Option<UserEntry> {
        USERS.iter().find(|row| row.0 == name).map(entry)
    }

    #[cfg(unix)]
    fn by_uid(uid: libc::uid_t) -> Option<UserEntry> {
        USERS.iter().find(|row| row.1 == uid).map(entry)
    }

    /// The service user is the operator who ran `sudo`, else the effective
    /// user; never a user the user database lacks.
    #[cfg(unix)]
    #[test]
    fn invoking_user_name_is_the_sudo_user_or_the_effective_user() {
        let name = |euid, sudo| user_name_for(euid, sudo, &by_name, &by_uid);
        assert_eq!(name(0, Some("op")).as_deref(), Some("op"));
        assert_eq!(name(0, None).as_deref(), Some("root"));
        assert_eq!(name(0, Some("root")).as_deref(), Some("root"));
        assert_eq!(name(0, Some("ghost")).as_deref(), Some("root"));
        assert_eq!(name(0, Some("")).as_deref(), Some("root"));
        assert_eq!(name(1000, Some("bare")).as_deref(), Some("op"));
        assert_eq!(name(1001, None).as_deref(), Some("bare"));
        assert_eq!(name(4242, None), None);
    }

    /// The C library's user database answers for root by id and by name,
    /// with its home directory, not its comment (GECOS) field; an unknown
    /// or malformed name has no entry.
    #[cfg(unix)]
    #[test]
    fn the_user_database_answers_for_root() {
        let root = user_by_uid(0).expect("user id 0 has an entry");
        assert_eq!(root.name, "root");
        let home = if cfg!(target_os = "macos") {
            "/var/root"
        } else {
            "/root"
        };
        assert_eq!(root.home, PathBuf::from(home));
        assert_eq!(user_by_name("root"), Some(root));
        assert_eq!(home_of_user("root"), Some(PathBuf::from(home)));
        assert_eq!(user_by_name("qclient-test-no-such-user"), None);
        assert_eq!(user_by_name("ro\0ot"), None);
    }

    /// A lookup reporting `ERANGE` gets a doubled buffer until its entry
    /// fits; an unknown user (no result) is `None`.
    #[cfg(unix)]
    #[test]
    fn a_lookup_grows_its_buffer_until_the_entry_fits() {
        let lens = std::cell::RefCell::new(Vec::new());
        let found = user_entry(|pwd, buf, len, result| {
            lens.borrow_mut().push(len);
            if len < 4096 {
                return libc::ERANGE;
            }
            let text = b"op\0/Users/op\0";
            // SAFETY: `buf` holds `len` >= 4096 bytes, `pwd` and `result`
            // are valid for writes.
            unsafe {
                std::ptr::copy_nonoverlapping(text.as_ptr().cast(), buf, text.len());
                let mut entry: libc::passwd = std::mem::zeroed();
                entry.pw_name = buf;
                entry.pw_dir = buf.add(3);
                pwd.write(entry);
                *result = pwd;
            }
            0
        });
        assert_eq!(
            found,
            Some(UserEntry {
                name: "op".to_string(),
                home: PathBuf::from("/Users/op"),
            })
        );
        assert_eq!(*lens.borrow(), [1024, 2048, 4096]);
        assert_eq!(user_entry(|_, _, _, _| 0), None);
        assert_eq!(user_entry(|_, _, _, _| libc::EIO), None);
    }
}

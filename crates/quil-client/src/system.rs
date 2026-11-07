//! OS / filesystem plumbing shared across commands.
//!
//! Port of `client/utils/system.go`, `client/utils/client.go`, and the
//! path constants in `client/utils/fileUtils.go` / `client/utils/node.go`.

use std::path::{Path, PathBuf};

/// Install root on Linux (`client/utils/fileUtils.go:18`), and on macOS
/// for an install made there before [`OPT_ROOT_PATH`]: see
/// [`InstallLayout`].
pub const VAR_ROOT_PATH: &str = "/var/quilibrium";
/// Install root on macOS: see [`InstallLayout`].
pub const OPT_ROOT_PATH: &str = "/opt/quilibrium";
/// `client/utils/fileUtils.go:20` — `/usr/local/bin`.
pub const DEFAULT_SYMLINK_DIR: &str = "/usr/local/bin";
/// The service log directory of the [`VAR_ROOT_PATH`] layout
/// (`client/utils/node.go:24`).
pub const VAR_LOG_PATH: &str = "/var/log/quilibrium";

/// Release-type discriminator (`client/utils/types.go`).
pub const RELEASE_TYPE_QCLIENT: &str = "qclient";
pub const RELEASE_TYPE_NODE: &str = "node";

/// `NodeServiceName` (`client/utils/node.go:22`).
pub const NODE_SERVICE_NAME: &str = "quilibrium-node";
/// Default node config directory name (`client/utils/node.go:19`).
pub const DEFAULT_NODE_CONFIG_NAME: &str = "node-quickstart";
/// Default auto-update cron interval (`client/utils/types.go`).
pub const DEFAULT_AUTO_UPDATE_INTERVAL: &str = "*/10 * * * *";
/// The link in the qclient install directory ([`client_data_path`]) to
/// the release `qclient update` or install-qclient.sh installed last.
/// Root's auto-update cron entry runs it: unlike
/// [`default_qclient_symlink_path`], it sits in a directory only root
/// writes.
pub const QCLIENT_ROOT_LINK: &str = "current";

/// Base release URL (`client/utils/download.go:13`).
pub const BASE_RELEASE_URL: &str = "https://releases.quilibrium.com";

/// Where qclient installs releases and the node service keeps its files.
///
/// On Linux the root is `/var/quilibrium`, as the Go client had it. On
/// macOS the root is `/opt/quilibrium`, and the launchd service writes the
/// node's stdout and stderr (`node.log`, `node.err`) beside the node's own
/// log files, in the `.log` directory of its config; except that when
/// `/var/quilibrium` exists and `/opt/quilibrium` does not, an install made
/// there before keeps its whole `/var` layout, service logs in
/// `/var/log/quilibrium` included: upgrades then find its releases,
/// environment file, update lock and service logs where it left them.
/// Releases sit in `<root>/bin/{node,qclient}/<version>`; the links stay in
/// [`DEFAULT_SYMLINK_DIR`] and configs in `~/.quilibrium/configs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallLayout {
    /// Holds `bin/`, `quilibrium.env` and the auto-update lock.
    pub root: PathBuf,
    /// The `/var` layout: Linux, or on macOS kept for an existing install.
    pub var_layout: bool,
    /// macOS only: the `/var` layout kept for an existing install.
    pub kept_var_install: bool,
}

impl InstallLayout {
    /// The layout on `os` (`darwin` or `linux`, as [`os_type`] names
    /// them), where `exists` tells whether a path exists.
    pub fn for_os(os: &str, exists: &dyn Fn(&Path) -> bool) -> Self {
        let var = |kept_var_install| Self {
            root: PathBuf::from(VAR_ROOT_PATH),
            var_layout: true,
            kept_var_install,
        };
        if os != "darwin" {
            return var(false);
        }
        if !exists(Path::new(OPT_ROOT_PATH)) && exists(Path::new(VAR_ROOT_PATH)) {
            return var(true);
        }
        Self {
            root: PathBuf::from(OPT_ROOT_PATH),
            var_layout: false,
            kept_var_install: false,
        }
    }

    /// Where the node service's stdout and stderr go for the node config
    /// directory `node_config_dir` the service runs: `/var/log/quilibrium`
    /// in the `/var` layout, else beside the node's own log files in its
    /// default log directory, `<node_config_dir>/.log`.
    pub fn service_log_dir(&self, node_config_dir: &Path) -> PathBuf {
        if self.var_layout {
            PathBuf::from(VAR_LOG_PATH)
        } else {
            node_config_dir.join(quil_config::DEFAULT_LOG_DIR)
        }
    }

    /// `<root>/bin`, holding the installed releases.
    pub fn binary_path(&self) -> PathBuf {
        self.root.join("bin")
    }

    /// `<root>/bin/qclient`, also the client config's default `dataDir`.
    pub fn client_data_path(&self) -> PathBuf {
        self.binary_path().join(RELEASE_TYPE_QCLIENT)
    }

    /// `<root>/bin/node`.
    pub fn node_data_path(&self) -> PathBuf {
        self.binary_path().join(RELEASE_TYPE_NODE)
    }

    /// `<root>/quilibrium.env`, the node service's environment file.
    pub fn node_env_path(&self) -> PathBuf {
        self.root.join("quilibrium.env")
    }

    /// `<root>/.auto-update.lock`, held by `node install` and `node
    /// update`.
    pub fn update_lock_path(&self) -> PathBuf {
        self.root.join(".auto-update.lock")
    }

    /// The line naming the layout in use.
    pub fn notice(&self) -> String {
        if self.kept_var_install {
            format!(
                "qclient: using the existing install under {} (service logs in \
                 {VAR_LOG_PATH}), as {OPT_ROOT_PATH} does not exist",
                self.root.display(),
            )
        } else {
            format!(
                "qclient: install root {} (service logs beside the node's, in its \
                 config's {})",
                self.root.display(),
                quil_config::DEFAULT_LOG_DIR
            )
        }
    }
}

/// This host's [`InstallLayout`], resolved once per process. On macOS the
/// first call prints its [`InstallLayout::notice`] to stderr.
pub fn install_layout() -> &'static InstallLayout {
    static LAYOUT: std::sync::OnceLock<InstallLayout> = std::sync::OnceLock::new();
    LAYOUT.get_or_init(|| {
        let layout = InstallLayout::for_os(os_type(), &|p| p.exists());
        if os_type() == "darwin" {
            eprintln!("{}", layout.notice());
        }
        layout
    })
}

/// [`InstallLayout::binary_path`] of this host.
pub fn binary_path() -> PathBuf {
    install_layout().binary_path()
}

/// [`InstallLayout::service_log_dir`] of this host for the config the node
/// service runs, `~/.quilibrium/configs/default`.
pub fn service_log_dir() -> anyhow::Result<PathBuf> {
    Ok(install_layout().service_log_dir(&node_config_home_dir()?.join("default")))
}

/// [`InstallLayout::client_data_path`] of this host
/// (`client/utils/client.go`).
pub fn client_data_path() -> PathBuf {
    install_layout().client_data_path()
}

/// [`InstallLayout::node_data_path`] of this host
/// (`client/utils/client.go`).
pub fn node_data_path() -> PathBuf {
    install_layout().node_data_path()
}

/// [`InstallLayout::update_lock_path`] of this host.
pub fn update_lock_path() -> PathBuf {
    install_layout().update_lock_path()
}

/// `client/utils/client.go` — `/usr/local/bin/qclient`.
pub fn default_qclient_symlink_path() -> PathBuf {
    Path::new(DEFAULT_SYMLINK_DIR).join(RELEASE_TYPE_QCLIENT)
}

/// `client/utils/node.go:23` — `/usr/local/bin/quilibrium-node`.
pub fn default_node_symlink_path() -> PathBuf {
    Path::new(DEFAULT_SYMLINK_DIR).join(NODE_SERVICE_NAME)
}

/// [`InstallLayout::node_env_path`] of this host
/// (`client/utils/node.go:21`).
pub fn node_env_path() -> PathBuf {
    install_layout().node_env_path()
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
/// the operator's `~/.quilibrium`, not root's. With `$HOME` unset or empty
/// the home is the effective user's in the user database.
#[cfg(unix)]
pub fn current_user_home() -> anyhow::Result<PathBuf> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let sudo_user = std::env::var("SUDO_USER").ok();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    home_for(
        euid,
        sudo_user.as_deref(),
        home,
        &user_by_name,
        &user_by_uid,
    )
    .ok_or_else(|| {
        anyhow::anyhow!(
            "could not determine home directory: $HOME is unset or empty and the user \
             database has no entry for user id {euid}"
        )
    })
}

#[cfg(not(unix))]
pub fn current_user_home() -> anyhow::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("could not determine home directory ($HOME unset)"))
}

/// [`current_user_home`] for the effective user id `euid`, `$SUDO_USER`
/// `sudo_user` and `$HOME` `home`, looking users up by name with `by_name`
/// and by id with `by_uid`.
#[cfg(unix)]
fn home_for(
    euid: libc::uid_t,
    sudo_user: Option<&str>,
    home: Option<PathBuf>,
    by_name: &dyn Fn(&str) -> Option<UserEntry>,
    by_uid: &dyn Fn(libc::uid_t) -> Option<UserEntry>,
) -> Option<PathBuf> {
    sudo_user
        .filter(|user| euid == 0 && !user.is_empty() && *user != "root")
        .and_then(by_name)
        .map(|entry| entry.home)
        .or_else(|| home.filter(|home| !home.as_os_str().is_empty()))
        .or_else(|| by_uid(euid).map(|entry| entry.home))
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

/// Create the link directory `dir` (such as [`DEFAULT_SYMLINK_DIR`], which
/// a fresh macOS host may lack) and any missing parents: each new one mode
/// 0755 and, run as root, owned by root and group 0 (`wheel` on macOS).
/// An existing directory is left as it is.
#[cfg(unix)]
pub fn ensure_symlink_dir(dir: &Path) -> anyhow::Result<()> {
    create_dirs(dir, is_root().then_some((0, 0)))
}

/// Off unix there are no release links to place.
#[cfg(not(unix))]
pub fn ensure_symlink_dir(_dir: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// Create `dir` and any missing parents, each mode 0755 and, run as root,
/// owned like the nearest existing parent: the operator's for a directory
/// in their home, root's for one under `/var/log`.
#[cfg(unix)]
pub fn ensure_dir_owned_like_parent(dir: &Path) -> anyhow::Result<()> {
    create_dirs(dir, if is_root() { nearest_owner(dir) } else { None })
}

/// Off unix: create `dir` and its parents.
#[cfg(not(unix))]
pub fn ensure_dir_owned_like_parent(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| anyhow::anyhow!("create {}: {e}", dir.display()))
}

/// The `(uid, gid)` of the nearest existing ancestor of `dir` (itself
/// included).
#[cfg(unix)]
fn nearest_owner(dir: &Path) -> Option<(u32, u32)> {
    nearest_owner_by(dir, &|p| {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(p)
            .ok()
            .map(|meta| (meta.uid(), meta.gid()))
    })
}

/// [`nearest_owner`] reading each path's `(uid, gid)` from `owner_of`
/// (`None` for a path that does not exist), so a test sets owners without
/// chown or host paths.
#[cfg(unix)]
fn nearest_owner_by(
    dir: &Path,
    owner_of: &dyn Fn(&Path) -> Option<(u32, u32)>,
) -> Option<(u32, u32)> {
    dir.ancestors().find_map(owner_of)
}

/// [`ensure_symlink_dir`], giving each created directory the owner `(uid,
/// gid)`. A directory is created private, then given its owner, then
/// opened to 0755, so no one else can write to it in between.
#[cfg(unix)]
fn create_dirs(dir: &Path, owner: Option<(u32, u32)>) -> anyhow::Result<()> {
    create_dirs_with(dir, owner, &|path, uid, gid| {
        std::os::unix::fs::chown(path, Some(uid), Some(gid))
    })
}

/// [`create_dirs`] giving the owner with `chown(path, uid, gid)`, so a test
/// records the calls instead of needing root.
#[cfg(unix)]
fn create_dirs_with(
    dir: &Path,
    owner: Option<(u32, u32)>,
    chown: &dyn Fn(&Path, u32, u32) -> std::io::Result<()>,
) -> anyhow::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let missing: Vec<&Path> = dir
        .ancestors()
        .take_while(|p| !p.as_os_str().is_empty() && !p.is_dir())
        .collect();
    for path in missing.into_iter().rev() {
        match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            // Created meanwhile by another run: it is that run's to set up.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => continue,
            Err(e) => anyhow::bail!("create {}: {e} (root required)", path.display()),
        }
        if let Some((uid, gid)) = owner {
            chown(path, uid, gid).map_err(|e| anyhow::anyhow!("chown {}: {e}", path.display()))?;
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| anyhow::anyhow!("chmod {}: {e}", path.display()))?;
    }
    Ok(())
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
    fn symlinks_stay_in_usr_local_bin() {
        assert_eq!(
            default_qclient_symlink_path(),
            PathBuf::from("/usr/local/bin/qclient")
        );
        assert_eq!(
            default_node_symlink_path(),
            PathBuf::from("/usr/local/bin/quilibrium-node")
        );
    }

    /// A missing link directory and its missing parents are created 0755;
    /// an existing parent keeps its mode.
    #[cfg(unix)]
    #[test]
    fn a_missing_link_dir_is_created_0755_and_an_existing_one_kept() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        let tmp = tempfile::TempDir::new().unwrap();
        let usr = tmp.path().join("usr");
        std::fs::create_dir(&usr).unwrap();
        std::fs::set_permissions(&usr, std::fs::Permissions::from_mode(0o700)).unwrap();
        let bin = usr.join("local").join("bin");
        let me = std::fs::metadata(tmp.path()).unwrap();
        create_dirs(&bin, Some((me.uid(), me.gid()))).unwrap();
        assert_eq!(mode(&usr.join("local")), 0o755);
        assert_eq!(mode(&bin), 0o755);
        assert_eq!(mode(&usr), 0o700);
        create_dirs(&bin, None).unwrap();
        assert_eq!(mode(&bin), 0o755);
    }

    /// A directory created under an existing one takes that one's owner,
    /// every directory created, none that existed. Owners are faked (the
    /// home belongs to uid 1000, the rest to root) and chown is recorded,
    /// so the result does not depend on the host's users or privileges.
    #[cfg(unix)]
    #[test]
    fn a_new_dir_takes_the_owner_of_its_nearest_parent() {
        use std::cell::RefCell;
        let tmp = tempfile::TempDir::new().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir(&home).unwrap();
        let quil = home.join(".quilibrium");
        let log = quil.join("configs").join(".log");
        let owner_of = |p: &Path| {
            if !p.exists() {
                None
            } else if p.starts_with(&home) {
                Some((1000, 1001))
            } else {
                Some((0, 0))
            }
        };

        assert_eq!(nearest_owner_by(&log, &owner_of), Some((1000, 1001)));
        assert_eq!(nearest_owner_by(&home, &owner_of), Some((1000, 1001)));
        assert_eq!(
            nearest_owner_by(&tmp.path().join("x").join("y"), &owner_of),
            Some((0, 0))
        );

        let chowned = RefCell::new(Vec::new());
        create_dirs_with(&log, nearest_owner_by(&log, &owner_of), &|p, uid, gid| {
            chowned.borrow_mut().push((p.to_path_buf(), uid, gid));
            Ok(())
        })
        .unwrap();
        let want: Vec<(PathBuf, u32, u32)> = [quil.clone(), quil.join("configs"), log.clone()]
            .into_iter()
            .map(|p| (p, 1000, 1001))
            .collect();
        assert_eq!(*chowned.borrow(), want);
        assert!(log.is_dir());
    }

    /// The layout on `os` where of the two roots only those flagged exist.
    fn layout(os: &str, opt_exists: bool, var_exists: bool) -> InstallLayout {
        InstallLayout::for_os(os, &|p: &Path| {
            (opt_exists && p == Path::new(OPT_ROOT_PATH))
                || (var_exists && p == Path::new(VAR_ROOT_PATH))
        })
    }

    /// The node config directory the service runs, in the tests.
    const SERVICE_CONFIG: &str = "/Users/op/.quilibrium/configs/default";

    /// Every path of a layout, the service logs for [`SERVICE_CONFIG`]
    /// last.
    fn paths(layout: &InstallLayout) -> [PathBuf; 6] {
        [
            layout.root.clone(),
            layout.client_data_path(),
            layout.node_data_path(),
            layout.node_env_path(),
            layout.update_lock_path(),
            layout.service_log_dir(Path::new(SERVICE_CONFIG)),
        ]
    }

    fn expected(root: &str, log: &str) -> [PathBuf; 6] {
        [
            PathBuf::from(root),
            PathBuf::from(format!("{root}/bin/qclient")),
            PathBuf::from(format!("{root}/bin/node")),
            PathBuf::from(format!("{root}/quilibrium.env")),
            PathBuf::from(format!("{root}/.auto-update.lock")),
            PathBuf::from(log),
        ]
    }

    /// Linux keeps the Go client's layout whichever roots exist.
    #[test]
    fn linux_keeps_the_var_layout() {
        for (opt, var) in [(false, false), (true, false), (false, true), (true, true)] {
            let linux = layout("linux", opt, var);
            assert_eq!(
                paths(&linux),
                expected("/var/quilibrium", "/var/log/quilibrium"),
                "opt={opt} var={var}"
            );
            assert!(!linux.kept_var_install);
        }
    }

    /// A macOS host without an earlier install gets the layout under
    /// `/opt/quilibrium`, the service logs beside the node's own.
    #[test]
    fn macos_installs_under_opt() {
        let mac = layout("darwin", false, false);
        assert_eq!(
            paths(&mac),
            expected(
                "/opt/quilibrium",
                "/Users/op/.quilibrium/configs/default/.log"
            )
        );
        assert!(!mac.kept_var_install);
    }

    /// Once `/opt/quilibrium` exists it is the root, also beside an older
    /// `/var/quilibrium`.
    #[test]
    fn macos_prefers_opt_once_it_exists() {
        for var in [false, true] {
            let mac = layout("darwin", true, var);
            assert_eq!(mac.root, PathBuf::from("/opt/quilibrium"), "var={var}");
            assert!(!mac.kept_var_install);
        }
    }

    /// An earlier macOS install under `/var/quilibrium` keeps its whole
    /// layout while `/opt/quilibrium` does not exist, so upgrades find its
    /// releases, lock, environment file and logs.
    #[test]
    fn macos_keeps_an_existing_var_install() {
        let mac = layout("darwin", false, true);
        assert_eq!(
            paths(&mac),
            expected("/var/quilibrium", "/var/log/quilibrium")
        );
        assert!(mac.kept_var_install);
    }

    /// The printed line names the root and log directory, and says why an
    /// existing `/var` install is kept.
    #[test]
    fn the_layout_in_use_is_named() {
        let opt = InstallLayout {
            root: PathBuf::from("/opt/quilibrium"),
            var_layout: false,
            kept_var_install: false,
        };
        assert_eq!(
            opt.notice(),
            "qclient: install root /opt/quilibrium (service logs beside the node's, in its \
             config's .log)"
        );
        let kept = InstallLayout {
            root: PathBuf::from("/var/quilibrium"),
            var_layout: true,
            kept_var_install: true,
        };
        assert_eq!(
            kept.notice(),
            "qclient: using the existing install under /var/quilibrium (service logs in \
             /var/log/quilibrium), as /opt/quilibrium does not exist"
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

    /// The home is the operator's under sudo, else `$HOME`, else, with
    /// `$HOME` unset or empty, the effective user's in the user database.
    #[cfg(unix)]
    #[test]
    fn a_missing_home_falls_back_to_the_user_database() {
        let home = |euid, sudo, env: Option<&str>| {
            home_for(euid, sudo, env.map(PathBuf::from), &by_name, &by_uid)
        };
        let op = Some(PathBuf::from("/Users/op"));
        assert_eq!(home(1000, None, None), op);
        assert_eq!(home(1000, None, Some("")), op);
        assert_eq!(
            home(1000, None, Some("/tmp/h")),
            Some(PathBuf::from("/tmp/h"))
        );
        assert_eq!(home(0, Some("op"), Some("/var/root")), op);
        assert_eq!(home(0, Some("op"), None), op);
        assert_eq!(
            home(0, Some("ghost"), Some("/var/root")),
            Some(PathBuf::from("/var/root"))
        );
        assert_eq!(home(0, Some("ghost"), None), Some(PathBuf::from("/root")));
        assert_eq!(home(1000, Some("bare"), None), op);
        assert_eq!(home(4242, None, None), None);
    }

    /// The C library's user database answers for the current user by id
    /// and by name, whatever the host calls it; an unknown or malformed
    /// name has no entry.
    #[cfg(unix)]
    #[test]
    fn the_user_database_answers_for_the_current_user() {
        // SAFETY: geteuid has no preconditions and cannot fail.
        let uid = unsafe { libc::geteuid() };
        let me = user_by_uid(uid).expect("the effective user has an entry");
        assert!(!me.name.is_empty(), "{me:?}");
        assert!(me.home.is_absolute(), "{me:?}");
        // Another name may share the id; the name found must answer for
        // itself.
        let named = user_by_name(&me.name).expect("the name found has an entry");
        assert_eq!(named.name, me.name);
        assert!(named.home.is_absolute(), "{named:?}");
        assert_eq!(user_by_name("qclient-test-no-such-user"), None);
        assert_eq!(user_by_name("ro\0ot"), None);
    }

    /// The home is the entry's home directory, not its comment (GECOS)
    /// field or its name.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn an_entrys_home_is_its_home_directory() {
        let found = user_entry(|pwd, buf, len, result| {
            let text = b"op\0/Users/op\0Op Q. User\0";
            assert!(len >= text.len());
            // SAFETY: `buf` holds `len` >= text.len() bytes, `pwd` and
            // `result` are valid for writes.
            unsafe {
                std::ptr::copy_nonoverlapping(text.as_ptr().cast(), buf, text.len());
                let mut entry: libc::passwd = std::mem::zeroed();
                entry.pw_name = buf;
                entry.pw_dir = buf.add(3);
                entry.pw_gecos = buf.add(13);
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

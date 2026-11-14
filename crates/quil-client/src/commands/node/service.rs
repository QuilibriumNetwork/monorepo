//! `qclient node service <action>` — manage the node system service.
//!
//! Port of `client/cmd/node/service.go`. Wraps `systemctl` (Linux) /
//! `launchctl` (macOS) and generates the systemd unit / launchd plist.
//! These operations require root (invoked via `sudo`).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::system;

const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/quilibrium-node.service";
const LAUNCHD_LABEL: &str = "com.quilibrium.quilibrium-node";

fn launchd_plist_path() -> String {
    format!("/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist")
}

/// The node service's file on `os`: the launchd plist on macOS, else the
/// systemd unit.
pub fn service_file_path(os: &str) -> PathBuf {
    if os == "darwin" {
        PathBuf::from(launchd_plist_path())
    } else {
        PathBuf::from(SYSTEMD_UNIT_PATH)
    }
}

pub fn run(action: &str) -> anyhow::Result<()> {
    match action {
        "start" | "stop" | "restart" | "status" | "enable" | "disable" | "reload" => {
            control(action)
        }
        "install" => install(),
        "update" => install(), // regenerate the unit file
        "uninstall" => uninstall(),
        other => anyhow::bail!(
            "Unknown command: {other}\nAvailable: start, stop, restart, status, \
             enable, disable, reload, install, update, uninstall"
        ),
    }
}

/// The `launchctl` arguments of a lifecycle action. launchctl has no
/// `restart`: `kickstart -k` restarts a running job (or starts it), as
/// for `reload`. enable and disable use `load -w` / `unload -w`, which
/// also record the job as enabled or disabled; `start`, `stop` and `list`
/// take the label.
fn launchctl_args(action: &str) -> Vec<String> {
    match action {
        "enable" => vec!["load".into(), "-w".into(), launchd_plist_path()],
        "disable" => vec!["unload".into(), "-w".into(), launchd_plist_path()],
        "status" => vec!["list".into(), LAUNCHD_LABEL.into()],
        "restart" | "reload" => vec![
            "kickstart".into(),
            "-k".into(),
            format!("system/{LAUNCHD_LABEL}"),
        ],
        a => vec![a.into(), LAUNCHD_LABEL.into()],
    }
}

/// Run a simple lifecycle action via the platform service manager.
fn control(action: &str) -> anyhow::Result<()> {
    let status = if system::os_type() == "darwin" {
        Command::new("sudo")
            .arg("launchctl")
            .args(launchctl_args(action))
            .status()
    } else {
        Command::new("sudo")
            .arg("systemctl")
            .arg(action)
            .arg(system::NODE_SERVICE_NAME)
            .status()
    }
    .map_err(|e| anyhow::anyhow!("run service manager: {e}"))?;
    if !status.success() {
        anyhow::bail!("service {action} failed ({status})");
    }
    Ok(())
}

fn install() -> anyhow::Result<()> {
    println!(
        "Installing Quilibrium node service for {}...",
        system::os_type()
    );
    if system::os_type() == "darwin" {
        install_launchd()
    } else if system::os_type() == "linux" {
        install_systemd()
    } else {
        anyhow::bail!("Unsupported operating system: {}", system::os_type());
    }
}

fn install_systemd() -> anyhow::Result<()> {
    let user = system::current_user_name()?;
    let config_default = system::node_config_home_dir()?.join("default");
    let env_path = system::node_env_path();
    let node_bin = system::default_node_symlink_path();

    ensure_env_file(&env_path, write_root_file)?;

    let unit = systemd_unit(&user, &env_path, &node_bin, &config_default);
    write_root_file(SYSTEMD_UNIT_PATH, &unit)?;

    let _ = Command::new("sudo")
        .args(["systemctl", "daemon-reload"])
        .status();
    println!(
        "Created systemd service file at {SYSTEMD_UNIT_PATH}: the node runs as {user} \
         with config {}",
        config_default.display()
    );
    Ok(())
}

fn install_launchd() -> anyhow::Result<()> {
    let user = system::current_user_name()?;
    let bin = system::default_node_symlink_path();
    let cfg = system::node_config_home_dir()?.join("default");
    let env_path = system::node_env_path();
    #[cfg(unix)]
    check_daemon_paths(&user, &bin, &cfg, &env_path)?;
    // launchd opens the log files but creates no directory for them.
    let log_dir = system::service_log_dir()?;
    system::ensure_dir_owned_like_parent(&log_dir)?;
    #[cfg(unix)]
    check_log_dir(&user, &log_dir, 0)?;
    // launchd reads no environment file: render the node's into the plist.
    if let Some(dir) = env_path.parent() {
        system::ensure_dir_owned_like_parent(dir)?;
    }
    ensure_env_file(&env_path, write_root_file)?;
    let env = launchd_environment(&env_path)?;
    let plist = launchd_plist(&user, &bin, &cfg, &log_dir, &env);
    write_root_file(&launchd_plist_path(), &plist)?;
    println!(
        "Created launchd plist at {}: the node runs as {user} with config {}, logs to {} \
         and runs with the environment of {}; after editing that file, run 'sudo qclient \
         node service update', then reload the service ('qclient node service disable', \
         then 'enable')",
        launchd_plist_path(),
        cfg.display(),
        log_dir.display(),
        env_path.display()
    );
    Ok(())
}

/// The launchd daemon of the node service. It runs as `user`, as the
/// systemd unit does: without `UserName` launchd runs a daemon as root,
/// which then ran the node from `/usr/local/bin` (another user may own it:
/// Homebrew gives it to the admin user on Intel macOS) with the config in
/// the operator's home, and either lets that user make root run their
/// code.
fn launchd_plist(user: &str, bin: &Path, cfg: &Path, log: &Path, env: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{label}</string>
	<key>UserName</key>
	<string>{user}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{bin}</string>
		<string>--config</string>
		<string>{cfg}</string>
	</array>
{env}	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardErrorPath</key>
	<string>{log}/node.err</string>
	<key>StandardOutPath</key>
	<string>{log}/node.log</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        bin = bin.display(),
        cfg = cfg.display(),
        log = log.display(),
    )
}

/// The plist's `EnvironmentVariables` entry for the environment file
/// `path` ([`env_assignments`]), warning of each line it skips; empty when
/// the file sets nothing.
fn launchd_environment(path: &Path) -> anyhow::Result<String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
    let (vars, skipped) = env_assignments(&text);
    for line in skipped {
        eprintln!(
            "warning: {} line {line} is not KEY=VALUE; the service does not get it",
            path.display()
        );
    }
    Ok(launchd_env_dict(&vars))
}

/// The `KEY=VALUE` assignments of an environment file, in the plain form
/// systemd's `EnvironmentFile=` reads: blank lines and lines starting with
/// `#` or `;` are comments, whitespace around keys and values is trimmed,
/// a value wholly in matching single or double quotes loses them, and a
/// later assignment of a key replaces an earlier one. Returns the
/// assignments and the (1-based) numbers of the other lines, which are
/// skipped.
fn env_assignments(text: &str) -> (Vec<(String, String)>, Vec<usize>) {
    let mut vars: Vec<(String, String)> = Vec::new();
    let mut skipped = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            skipped.push(i + 1);
            continue;
        };
        let key = key.trim();
        let valid = key.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            skipped.push(i + 1);
            continue;
        }
        let value = value.trim();
        let value = ['"', '\'']
            .iter()
            .find_map(|q| value.strip_prefix(*q).and_then(|v| v.strip_suffix(*q)))
            .unwrap_or(value);
        match vars.iter_mut().find(|(k, _)| k == key) {
            Some(var) => var.1 = value.to_string(),
            None => vars.push((key.to_string(), value.to_string())),
        }
    }
    (vars, skipped)
}

/// The plist `EnvironmentVariables` entry setting `vars`, XML-escaped;
/// empty for none.
fn launchd_env_dict(vars: &[(String, String)]) -> String {
    if vars.is_empty() {
        return String::new();
    }
    let escape = |s: &str| {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    };
    let mut dict = String::from("\t<key>EnvironmentVariables</key>\n\t<dict>\n");
    for (key, value) in vars {
        dict.push_str(&format!(
            "\t\t<key>{}</key>\n\t\t<string>{}</string>\n",
            escape(key),
            escape(value)
        ));
    }
    dict.push_str("\t</dict>\n");
    dict
}

/// Refuse a node service that would let a non-root user make root run
/// their code, or that its user cannot run. As root (`user` is root when
/// qclient runs from a root shell, or cannot resolve the sudo user), every
/// existing directory above the binary `bin`, the config `cfg` and the
/// environment file `env`, which is rendered into the plist, and `cfg` and
/// `env` themselves, must be owned by root and writable only by root. As
/// another user, `cfg` must hold nothing a root-run node left owned by
/// root, which that user could not open.
#[cfg(unix)]
fn check_daemon_paths(user: &str, bin: &Path, cfg: &Path, env: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;
    check_daemon_paths_with(user, bin, cfg, env, |dir| {
        std::fs::metadata(dir).map(|meta| (meta.uid(), meta.mode()))
    })
}

/// [`check_daemon_paths`], reading the owner uid and mode of a directory
/// through `owner_mode`.
#[cfg(unix)]
fn check_daemon_paths_with(
    user: &str,
    bin: &Path,
    cfg: &Path,
    env: &Path,
    owner_mode: impl Fn(&Path) -> std::io::Result<(u32, u32)>,
) -> anyhow::Result<()> {
    if user == "root" {
        let dirs = bin
            .ancestors()
            .skip(1)
            .chain(cfg.ancestors())
            .chain(env.ancestors());
        for dir in dirs.filter(|d| !d.as_os_str().is_empty()) {
            let (uid, mode) = match owner_mode(dir) {
                Ok(found) => found,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => anyhow::bail!("stat {}: {e}", dir.display()),
            };
            if uid != 0 || mode & 0o022 != 0 {
                anyhow::bail!(
                    "the node service would run as root from {} with config {} and environment \
                     {}, but {} is \
                     owned by uid {} with mode {:o}: whoever can write it could make root run \
                     their code. Run 'sudo qclient node service install' from the operator's \
                     account, so the node runs as that user",
                    bin.display(),
                    cfg.display(),
                    env.display(),
                    dir.display(),
                    uid,
                    mode & 0o7777
                );
            }
        }
        return Ok(());
    }
    let left = entries_owned_by(cfg, 0)?;
    if let Some(first) = left.first() {
        anyhow::bail!(
            "{} and {} other entries in {} are owned by root, as a node run as root leaves \
             them; the service now runs as {user}, who cannot open them. Stop the node, run \
             'sudo chown -R {user} {}', then install the service again",
            first.display(),
            left.len() - 1,
            cfg.display(),
            cfg.display()
        );
    }
    Ok(())
}

/// Refuse a service log directory its user cannot write to: launchd opens
/// the log files for a daemon that runs as `user`, and the `/var` layout's
/// directory, or the logs a root-run node left in it, belong to root
/// (`root_uid`).
#[cfg(unix)]
fn check_log_dir(user: &str, log: &Path, root_uid: u32) -> anyhow::Result<()> {
    if user == "root" {
        return Ok(());
    }
    let left = entries_owned_by(log, root_uid)?;
    if let Some(first) = left.first() {
        anyhow::bail!(
            "{} is owned by root, but the node service runs as {user} and logs to {}. Run \
             'sudo chown -R {user} {}', then install the service again",
            first.display(),
            log.display(),
            log.display()
        );
    }
    Ok(())
}

/// `dir` and its entries (not recursing, not following links) that the
/// user id `uid` owns; none when `dir` does not exist.
#[cfg(unix)]
fn entries_owned_by(dir: &Path, uid: u32) -> anyhow::Result<Vec<std::path::PathBuf>> {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => anyhow::bail!("stat {}: {e}", dir.display()),
    };
    let mut owned = Vec::new();
    if meta.uid() == uid {
        owned.push(dir.to_path_buf());
    }
    if meta.is_dir() {
        let entries =
            std::fs::read_dir(dir).map_err(|e| anyhow::anyhow!("read {}: {e}", dir.display()))?;
        let mut found = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| anyhow::anyhow!("read {}: {e}", dir.display()))?;
            let meta = entry
                .metadata()
                .map_err(|e| anyhow::anyhow!("stat {}: {e}", entry.path().display()))?;
            if meta.uid() == uid {
                found.push(entry.path());
            }
        }
        found.sort();
        owned.extend(found);
    }
    Ok(owned)
}

/// Create the node's environment file `path`, with a comment, through
/// `write` (path, contents) unless it exists: it holds the operator's
/// settings (such as `QUILIBRIUM_SIGNATURE_CHECK`), which a reinstall or a
/// unit update must keep.
fn ensure_env_file(
    path: &Path,
    write: impl FnOnce(&str, &str) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            println!("Keeping the existing environment file {}", path.display());
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let name = path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("invalid path {}", path.display()))?;
            write(name, "# Quilibrium Node Environment\n")?;
            println!("Created the environment file {}", path.display());
            Ok(())
        }
        Err(e) => anyhow::bail!("stat {}: {e}", path.display()),
    }
}

#[cfg(test)]
mod env_file_tests {
    use super::*;

    fn pairs(vars: &[(&str, &str)]) -> Vec<(String, String)> {
        vars.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    /// The service gets the assignments systemd reads from the same file:
    /// comments and blank lines are no assignments, quotes are dropped, a
    /// later value wins, and other lines are reported.
    #[test]
    fn env_file_lines_parse_as_systemd_reads_them() {
        let text = "# Quilibrium Node Environment\n\
                    ; old = comment\n\
                    \n\
                    QUIL_A=1\n  \
                    QUIL_B = \"two words\"  \n\
                    QUIL_C='single'\n\
                    QUIL_D=\n\
                    not an assignment\n\
                    9BAD=1\n\
                    QUIL_A=override\n\
                    QUIL_E=\"unbalanced\n\
                    QUIL_F=\"\n";
        let (vars, skipped) = env_assignments(text);
        assert_eq!(
            vars,
            pairs(&[
                ("QUIL_A", "override"),
                ("QUIL_B", "two words"),
                ("QUIL_C", "single"),
                ("QUIL_D", ""),
                ("QUIL_E", "\"unbalanced"),
                ("QUIL_F", "\""),
            ])
        );
        assert_eq!(skipped, [8, 9]);
    }

    /// Keys and values are XML-escaped in the plist.
    #[test]
    fn env_values_are_escaped_in_the_plist() {
        assert_eq!(
            launchd_env_dict(&pairs(&[("QUIL_X", "a&b<c>\"d'e"), ("QUIL_Y", "2")])),
            "\t<key>EnvironmentVariables</key>\n\t<dict>\n\
             \t\t<key>QUIL_X</key>\n\t\t<string>a&amp;b&lt;c&gt;&quot;d&apos;e</string>\n\
             \t\t<key>QUIL_Y</key>\n\t\t<string>2</string>\n\
             \t</dict>\n"
        );
    }

    /// An environment file that sets nothing adds no entry to the plist.
    #[test]
    fn an_env_file_without_assignments_adds_no_entry() {
        let (vars, _) = env_assignments("# Quilibrium Node Environment\n");
        assert_eq!(launchd_env_dict(&vars), "");
    }

    fn write_file(path: &str, contents: &str) -> anyhow::Result<()> {
        Ok(std::fs::write(path, contents)?)
    }

    /// A reinstall keeps the operator's settings; a fresh install creates
    /// the file.
    #[test]
    fn existing_env_file_is_kept() {
        let tmp = tempfile::TempDir::new().unwrap();
        let env = tmp.path().join("quilibrium.env");
        ensure_env_file(&env, write_file).unwrap();
        assert_eq!(
            std::fs::read_to_string(&env).unwrap(),
            "# Quilibrium Node Environment\n"
        );
        let settings = "QUILIBRIUM_SIGNATURE_CHECK=false\n";
        std::fs::write(&env, settings).unwrap();
        ensure_env_file(&env, write_file).unwrap();
        ensure_env_file(&env, write_file).unwrap();
        assert_eq!(std::fs::read_to_string(&env).unwrap(), settings);
    }
}

fn uninstall() -> anyhow::Result<()> {
    if system::os_type() == "darwin" {
        let plist = launchd_plist_path();
        let _ = Command::new("sudo")
            .args(["launchctl", "unload", &plist])
            .status();
        let _ = Command::new("sudo").args(["rm", "-f", &plist]).status();
        println!("Removed launchd service");
    } else {
        let _ = Command::new("sudo")
            .args(["systemctl", "disable", "--now", system::NODE_SERVICE_NAME])
            .status();
        let _ = Command::new("sudo")
            .args(["rm", "-f", SYSTEMD_UNIT_PATH])
            .status();
        let _ = Command::new("sudo")
            .args(["systemctl", "daemon-reload"])
            .status();
        println!("Removed systemd service");
    }
    Ok(())
}

/// Write a file that lives under a root-owned path via `sudo tee`.
fn write_root_file(path: &str, contents: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let mut child = Command::new("sudo")
        .arg("tee")
        .arg(path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .map_err(|e| anyhow::anyhow!("sudo tee {path}: {e}"))?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(contents.as_bytes())
        .map_err(|e| anyhow::anyhow!("write {path}: {e}"))?;
    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("failed writing {path}");
    }
    Ok(())
}

/// The systemd unit of the node service. It runs as `user`, the operator
/// whose `~/.quilibrium` holds the config `cfg`: the installer creates no
/// account for the node.
fn systemd_unit(user: &str, env: &Path, bin: &Path, cfg: &Path) -> String {
    format!(
        "[Unit]\n\
         Description=Quilibrium Node Service\n\
         After=network.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         Type=simple\n\
         User={user}\n\
         EnvironmentFile={env}\n\
         ExecStart={bin} --config {cfg}\n\
         Restart=always\n\
         RestartSec=10\n\
         ExecStop=/bin/kill -s SIGINT $MAINPID\n\
         KillSignal=SIGINT\n\
         FinalKillSignal=SIGKILL\n\
         TimeoutStopSec=240\n\
         LimitNOFILE=65535\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        env = env.display(),
        bin = bin.display(),
        cfg = cfg.display(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each action maps to a verb launchctl has: restart, which `node
    /// update --restart` and auto-update use, kickstarts the job.
    #[test]
    fn launchctl_gets_verbs_it_has() {
        let args = |action| launchctl_args(action).join(" ");
        let label = "com.quilibrium.quilibrium-node";
        let plist = "/Library/LaunchDaemons/com.quilibrium.quilibrium-node.plist";
        assert_eq!(args("restart"), format!("kickstart -k system/{label}"));
        assert_eq!(args("reload"), format!("kickstart -k system/{label}"));
        assert_eq!(args("enable"), format!("load -w {plist}"));
        assert_eq!(args("disable"), format!("unload -w {plist}"));
        assert_eq!(args("status"), format!("list {label}"));
        assert_eq!(args("start"), format!("start {label}"));
        assert_eq!(args("stop"), format!("stop {label}"));
    }

    /// The launchd daemon runs as the given user, as the systemd unit
    /// does, never as root by default.
    #[test]
    fn launchd_daemon_runs_as_the_given_user() {
        let plist = launchd_plist(
            "op",
            Path::new("/usr/local/bin/quilibrium-node"),
            Path::new("/Users/op/.quilibrium/configs/default"),
            Path::new("/var/log/quilibrium"),
            "\t<key>EnvironmentVariables</key>\n",
        );
        assert!(
            plist.contains("\t<key>UserName</key>\n\t<string>op</string>\n"),
            "{plist}"
        );
        assert!(
            plist.contains(
                "\t\t<string>/usr/local/bin/quilibrium-node</string>\n\t\t<string>--config</string>\n\
                 \t\t<string>/Users/op/.quilibrium/configs/default</string>\n"
            ),
            "{plist}"
        );
        assert!(
            plist.contains("<string>/var/log/quilibrium/node.err</string>"),
            "{plist}"
        );
        assert!(
            plist.contains("</array>\n\t<key>EnvironmentVariables</key>\n\t<key>RunAtLoad</key>"),
            "{plist}"
        );
    }

    /// A node run as root must have a binary and config only root can
    /// write: a directory another user owns or can write is refused. The
    /// owners and modes are faked, so the host's directories do not decide
    /// the outcome.
    #[cfg(unix)]
    #[test]
    fn root_node_service_needs_root_only_paths() {
        use std::os::unix::fs::PermissionsExt;
        /// A tree of root-owned 0755 directories, but for `odd`, a
        /// directory with the given owner and mode; nothing else exists.
        fn tree(
            odd: Option<(&str, u32, u32)>,
        ) -> impl Fn(&Path) -> std::io::Result<(u32, u32)> + '_ {
            move |dir: &Path| match (dir.to_str().unwrap(), odd) {
                (dir, Some((path, uid, mode))) if dir == path => Ok((uid, mode)),
                ("/" | "/opt" | "/opt/quil" | "/opt/quil/bin" | "/opt/quil/configs", _) => {
                    Ok((0, 0o40755))
                }
                _ => Err(std::io::ErrorKind::NotFound.into()),
            }
        }
        let bin = Path::new("/opt/quil/bin/quilibrium-node");
        let cfg = Path::new("/opt/quil/configs/default");
        let env = Path::new("/opt/quil-env/quilibrium.env");

        check_daemon_paths_with("root", bin, cfg, env, tree(None)).unwrap();
        for (dir, uid, mode) in [
            ("/opt/quil/configs", 0, 0o40777),
            ("/opt/quil/bin", 0, 0o40775),
            ("/opt/quil/configs/default", 0, 0o40757),
            ("/opt", 501, 0o40755),
            // The environment file is rendered into the root daemon's plist.
            ("/opt/quil-env", 501, 0o40755),
            ("/opt/quil-env/quilibrium.env", 501, 0o100644),
        ] {
            let err = check_daemon_paths_with("root", bin, cfg, env, tree(Some((dir, uid, mode))))
                .unwrap_err()
                .to_string();
            assert!(
                err.starts_with(&format!(
                    "the node service would run as root from {} with config {} and environment \
                     {}, but {dir} is \
                     owned by uid {uid} with mode {:o}: ",
                    bin.display(),
                    cfg.display(),
                    env.display(),
                    mode & 0o7777
                )),
                "{err}"
            );
        }

        // The real lookup: a directory anyone can write, whatever is above it.
        let tmp = tempfile::TempDir::new().unwrap();
        let open = tmp.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let err = check_daemon_paths(
            "root",
            &open.join("quilibrium-node"),
            &open.join("default"),
            &open.join("quilibrium.env"),
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains(&format!(", but {} is owned by uid ", open.display()))
                && err.contains(" with mode 777: "),
            "{err}"
        );
    }

    /// A log directory, or a log in it, that belongs to root is refused
    /// with the command that fixes it, before a plist naming it is
    /// rendered for a user who could not open it; root's own daemon and a
    /// directory free of root's files pass, and the plist then logs there.
    /// The directory's real owner stands in for root.
    #[cfg(unix)]
    #[test]
    fn root_owned_log_dir_is_refused_for_a_user_daemon() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let log = tmp.path().join("quilibrium");
        std::fs::create_dir(&log).unwrap();
        let owner = std::fs::metadata(&log).unwrap().uid();

        let err = check_log_dir("op", &log, owner).unwrap_err().to_string();
        assert!(
            err.contains(&format!("'sudo chown -R op {}'", log.display())),
            "{err}"
        );
        check_log_dir("root", &log, owner).unwrap();

        check_log_dir("op", &log, owner + 1).unwrap();
        let plist = launchd_plist(
            "op",
            Path::new("/usr/local/bin/quilibrium-node"),
            Path::new("/Users/op/.quilibrium/configs/default"),
            &log,
            "",
        );
        assert!(
            plist.contains("\t<key>UserName</key>\n\t<string>op</string>\n")
                && plist.contains(&format!("<string>{}/node.log</string>", log.display())),
            "{plist}"
        );
    }

    /// Files a root-run node left in the config are found, so the
    /// service is not moved to a user who cannot open them.
    #[cfg(unix)]
    #[test]
    fn entries_a_root_node_left_are_found() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = tmp.path().join("default");
        std::fs::create_dir_all(cfg.join("store")).unwrap();
        std::fs::write(cfg.join("config.yml"), b"").unwrap();
        let uid = std::fs::metadata(&cfg).unwrap().uid();

        assert_eq!(
            entries_owned_by(&cfg, uid).unwrap(),
            [cfg.clone(), cfg.join("config.yml"), cfg.join("store")]
        );
        assert!(entries_owned_by(&cfg, uid + 1).unwrap().is_empty());
        assert!(entries_owned_by(&tmp.path().join("none"), uid)
            .unwrap()
            .is_empty());
    }

    /// The unit runs as the given user, whose config it names: systemd
    /// refuses to start a unit whose user does not exist.
    #[test]
    fn unit_runs_as_the_given_user() {
        let unit = systemd_unit(
            "op",
            Path::new("/var/quilibrium/quilibrium.env"),
            Path::new("/usr/local/bin/quilibrium-node"),
            Path::new("/home/op/.quilibrium/configs/default"),
        );
        let lines: Vec<&str> = unit.lines().collect();
        let users: Vec<&&str> = lines.iter().filter(|l| l.starts_with("User=")).collect();
        assert_eq!(users, [&"User=op"], "{unit}");
        assert!(
            lines.contains(
                &"ExecStart=/usr/local/bin/quilibrium-node --config \
                  /home/op/.quilibrium/configs/default"
            ),
            "{unit}"
        );
        assert!(
            lines.contains(&"EnvironmentFile=/var/quilibrium/quilibrium.env"),
            "{unit}"
        );
    }
}

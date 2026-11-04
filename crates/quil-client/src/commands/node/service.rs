//! `qclient node service <action>` — manage the node system service.
//!
//! Port of `client/cmd/node/service.go`. Wraps `systemctl` (Linux) /
//! `launchctl` (macOS) and generates the systemd unit / launchd plist.
//! These operations require root (invoked via `sudo`).

use std::path::Path;
use std::process::Command;

use crate::system;

const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/quilibrium-node.service";
const LAUNCHD_LABEL: &str = "com.quilibrium.quilibrium-node";

fn launchd_plist_path() -> String {
    format!("/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist")
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

/// Run a simple lifecycle action via the platform service manager.
fn control(action: &str) -> anyhow::Result<()> {
    let status = if system::os_type() == "darwin" {
        // launchctl uses load/unload for enable/disable.
        let mapped = match action {
            "enable" => vec!["load".into(), "-w".into(), launchd_plist_path()],
            "disable" => vec!["unload".into(), "-w".into(), launchd_plist_path()],
            "status" => vec!["list".into(), LAUNCHD_LABEL.into()],
            "reload" => vec![
                "kickstart".into(),
                "-k".into(),
                format!("system/{LAUNCHD_LABEL}"),
            ],
            a => vec![a.into(), LAUNCHD_LABEL.into()],
        };
        Command::new("sudo").arg("launchctl").args(&mapped).status()
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
    // launchd opens the log files but creates no directory for them.
    let log_dir = system::service_log_dir()?;
    system::ensure_dir_owned_like_parent(&log_dir)?;
    // launchd reads no environment file: render the node's into the plist.
    let env_path = system::node_env_path();
    if let Some(dir) = env_path.parent() {
        system::ensure_dir_owned_like_parent(dir)?;
    }
    ensure_env_file(&env_path, write_root_file)?;
    let env = launchd_environment(&env_path)?;
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{label}</string>
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
        bin = system::default_node_symlink_path().display(),
        cfg = system::node_config_home_dir()?.join("default").display(),
        log = log_dir.display(),
    );
    write_root_file(&launchd_plist_path(), &plist)?;
    println!(
        "Created launchd plist at {}: the node logs to {} and runs with the \
         environment of {}; after editing that file, run 'sudo qclient node service \
         update', then reload the service ('qclient node service disable', then \
         'enable')",
        launchd_plist_path(),
        log_dir.display(),
        env_path.display()
    );
    Ok(())
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

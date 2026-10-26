//! `qclient node log …` — view/clean node logs.
//!
//! The node writes `master.log` and `worker-N.log` (rotated as
//! `<name>.<timestamp>[.gz]`) to its log directory, `logger.path` or by
//! default `.log` under its config directory; with `path: none` it logs only
//! to stderr, which the system service captures (the systemd journal on
//! Linux, `node.err` under the log directory on macOS). `export` writes a
//! redacted bundle of a time window for bug reports.

use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Subcommand;
use quil_rpc::log_export::is_rotated_log;

use crate::context::GlobalArgs;
use crate::{nodeconfig, system};

pub mod export;

#[derive(Debug, Subcommand)]
pub enum LogCommand {
    /// View the node log (last N lines, optionally following).
    View {
        #[arg(short = 'n', long, default_value_t = 100)]
        lines: u64,
        #[arg(short = 'f', long)]
        follow: bool,
        /// Core whose log to view: 0 is the master, N is worker N.
        #[arg(long, default_value_t = 0)]
        core: u32,
    },
    /// Delete rotated node logs (the live logs are kept).
    Clean,
    /// Export a redacted node log bundle of a time window, to attach to a
    /// bug report.
    ///
    /// Reads the node's log files (live and rotated, every core) or, when
    /// the node writes none, the service journal; merges them in time
    /// order and keeps lines of the window (at most 24 h). With --filter or
    /// --match only matching lines are kept, plus every warn and error line
    /// as context.
    ///
    /// Redaction hides your network location (IP addresses, DNS names,
    /// multiaddrs, peer IDs), host and user names, home paths and reward
    /// balances; equal values share a token like ip4#7c21a0b3 within one
    /// export. Public bootstrap archive endpoints and shard filters, frame
    /// numbers and versions are kept. It does not hide which prover you are:
    /// your shard set and join/reward frames are on-chain and stay in the
    /// log.
    ///
    /// Writes <dir>/node.log.gz, manifest.json and SHA256SUMS after a
    /// preview you confirm by typing yes (or the global --yes), and the
    /// token map to <dir>.map.txt, owner-readable only: keep it private and
    /// never share it.
    Export(export::ExportArgs),
}

pub fn run(global: GlobalArgs, cmd: &LogCommand) -> anyhow::Result<()> {
    match cmd {
        LogCommand::View {
            lines,
            follow,
            core,
        } => view(&global, *lines, *follow, *core),
        LogCommand::Clean => clean(&global).map(|_| ()),
        LogCommand::Export(args) => export::run(&global, args),
    }
}

/// The directory the node of the resolved config writes its log files to, or
/// `None` when it logs only to stderr.
///
/// Without `--network`, an installed node service names the node's own
/// config and working directory ([`ServiceLocation`]), so the logs are found
/// from any directory; otherwise the config resolves as for every command
/// and a relative `logger.path` is taken from the current directory.
pub(crate) fn configured_log_dir(global: &GlobalArgs) -> anyhow::Result<Option<PathBuf>> {
    let network = global.network.as_deref().filter(|s| !s.is_empty());
    let service = if network.is_none() {
        service_location()
    } else {
        None
    };
    let (config_dir, node_dir) =
        match service.filter(|s| nodeconfig::has_node_config_files(&s.config_dir())) {
            Some(service) => (service.config_dir(), Some(service.working_dir)),
            None => (nodeconfig::default_node_config_dir(network)?, None),
        };
    let config =
        quil_config::load_config(&config_dir).map_err(|e| anyhow::anyhow!("load config: {e}"))?;
    Ok(config
        .logger
        .log_dir(&config_dir)
        .map(|dir| from_node_dir(node_dir.as_deref(), dir)))
}

/// `path` as the node resolves it: a relative path from its working
/// directory, when that is known.
fn from_node_dir(node_dir: Option<&Path>, path: PathBuf) -> PathBuf {
    match node_dir {
        Some(node_dir) if path.is_relative() => node_dir.join(path),
        _ => path,
    }
}

/// Where the node service runs, as its unit sets it: the working directory
/// (systemd's default is `/`) and the `--config` the node is started with
/// (the node's default is `.config`).
#[derive(Debug, PartialEq)]
struct ServiceLocation {
    working_dir: PathBuf,
    config: PathBuf,
}

impl ServiceLocation {
    /// The node's config directory: `--config`, from the working directory
    /// when relative.
    fn config_dir(&self) -> PathBuf {
        from_node_dir(Some(&self.working_dir), self.config.clone())
    }

    /// Parse `systemctl show -p LoadState -p WorkingDirectory -p ExecStart`;
    /// `None` unless the unit is loaded and its directory is a plain path.
    fn parse(show: &str) -> Option<Self> {
        let mut loaded = false;
        let mut location = Self {
            working_dir: PathBuf::from("/"),
            config: PathBuf::from(".config"),
        };
        for line in show.lines() {
            if let Some(state) = line.strip_prefix("LoadState=") {
                loaded = state == "loaded";
            } else if let Some(dir) = line.strip_prefix("WorkingDirectory=") {
                // A leading `-` only makes a missing directory non-fatal; `~`
                // is the service user's home, which qclient cannot resolve.
                let dir = dir.trim_start_matches('-');
                if dir.starts_with('~') {
                    return None;
                }
                if !dir.is_empty() {
                    location.working_dir = PathBuf::from(dir);
                }
            } else if let Some(exec) = line.strip_prefix("ExecStart=") {
                let argv = exec.split("argv[]=").nth(1)?.split(" ;").next()?;
                let mut args = argv.split_whitespace().skip(1);
                while let Some(arg) = args.next() {
                    if let Some(dir) = arg
                        .strip_prefix("--config=")
                        .or_else(|| arg.strip_prefix("-c="))
                    {
                        location.config = PathBuf::from(dir);
                    } else if arg == "--config" || arg == "-c" {
                        location.config = PathBuf::from(args.next()?);
                    }
                }
            }
        }
        loaded.then_some(location)
    }
}

/// The installed node service's location (Linux), if there is one.
fn service_location() -> Option<ServiceLocation> {
    if system::os_type() != "linux" {
        return None;
    }
    let show = Command::new("systemctl")
        .args([
            "show",
            system::NODE_SERVICE_NAME,
            "-p",
            "LoadState",
            "-p",
            "WorkingDirectory",
            "-p",
            "ExecStart",
        ])
        .output()
        .ok()
        .filter(|out| out.status.success())?;
    ServiceLocation::parse(&String::from_utf8_lossy(&show.stdout))
}

/// The node's live log file name for `core` (as the node's logging names it).
fn log_file_name(core: u32) -> String {
    if core == 0 {
        "master.log".to_string()
    } else {
        format!("worker-{core}.log")
    }
}

fn view(global: &GlobalArgs, lines: u64, follow: bool, core: u32) -> anyhow::Result<()> {
    let mut cmd = match configured_log_dir(global)? {
        Some(dir) => {
            let file = dir.join(log_file_name(core));
            if !file.exists() {
                anyhow::bail!("log file not found: {}", file.display());
            }
            let mut cmd = Command::new("tail");
            if follow {
                cmd.arg("-f");
            }
            cmd.arg("-n").arg(lines.to_string()).arg(file);
            cmd
        }
        None if system::os_type() == "linux" => {
            // Stderr only: every core's lines are in the service's journal.
            let mut cmd = Command::new("journalctl");
            cmd.args([
                "--utc",
                "-o",
                "cat",
                "--no-pager",
                "-u",
                system::NODE_SERVICE_NAME,
            ]);
            if follow {
                cmd.arg("-f");
            }
            cmd.arg("-n").arg(lines.to_string());
            cmd
        }
        None => {
            let file = Path::new(system::LOG_PATH).join("node.err");
            if !file.exists() {
                anyhow::bail!(
                    "the node logs to stderr only and {} is missing",
                    file.display()
                );
            }
            let mut cmd = Command::new("tail");
            if follow {
                cmd.arg("-f");
            }
            cmd.arg("-n").arg(lines.to_string()).arg(file);
            cmd
        }
    };
    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!("run {:?}: {e}", cmd.get_program()))?;
    if !status.success() {
        anyhow::bail!("{:?} exited with {status}", cmd.get_program());
    }
    Ok(())
}

/// Delete the rotated logs in the node's log directory; returns how many.
pub(crate) fn clean(global: &GlobalArgs) -> anyhow::Result<usize> {
    let Some(dir) = configured_log_dir(global)? else {
        println!("The node writes no log files (logger.path is none)");
        return Ok(0);
    };
    let removed = remove_rotated_logs(&dir)?;
    println!(
        "Removed {removed} rotated log file(s) from {}",
        dir.display()
    );
    Ok(removed)
}

fn remove_rotated_logs(dir: &Path) -> anyhow::Result<usize> {
    if !dir.exists() {
        return Ok(0);
    }
    let mut removed = 0;
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !is_rotated_log(name) {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(e) => eprintln!("failed to remove {}: {e}", path.display()),
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_logs_are_never_rotated_logs() {
        for rotated in [
            "master.log.20261017T120000.gz",
            "worker-3.log.20261017T120000",
            "worker-12.log.1",
        ] {
            assert!(is_rotated_log(rotated), "{rotated}");
        }
        for kept in [
            "master.log",
            "worker-3.log",
            "node.log",
            "other.log.gz",
            "worker-.log.1",
            "worker-x.log.1",
        ] {
            assert!(!is_rotated_log(kept), "{kept}");
        }
    }

    /// Cleaning removes the rotated logs only and keeps every live log and
    /// any other file.
    #[test]
    fn cleaning_keeps_live_logs() {
        let dir = std::env::temp_dir().join(format!("qclient-log-clean-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let names = [
            "master.log",
            "master.log.20261017T120000.gz",
            "worker-2.log",
            "worker-2.log.20261017T120000.gz",
            "notes.txt",
        ];
        for name in names {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        assert_eq!(remove_rotated_logs(&dir).unwrap(), 2);
        let mut left: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["master.log", "notes.txt", "worker-2.log"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The unit `qclient node service install` writes: no working directory,
    /// an absolute `--config`.
    #[test]
    fn an_installed_service_names_its_config() {
        let show = "LoadState=loaded\n\
            ExecStart={ path=/usr/local/bin/quilibrium-node ; argv[]=/usr/local/bin/quilibrium-node --config /root/.quilibrium/configs/default ; ignore_errors=no ; pid=0 }\n\
            WorkingDirectory=\n";
        let service = ServiceLocation::parse(show).expect("a loaded unit");
        assert_eq!(
            service.config_dir(),
            PathBuf::from("/root/.quilibrium/configs/default")
        );
        assert_eq!(service.working_dir, PathBuf::from("/"));
    }

    /// A unit that runs the node from its directory: the default `.config`
    /// and a relative `logger.path` both resolve from there, not from where
    /// qclient runs.
    #[test]
    fn relative_paths_resolve_from_the_service_directory() {
        let show = "LoadState=loaded\n\
            ExecStart={ path=/srv/node/node ; argv[]=/srv/node/node --signature-check=false ; ignore_errors=no }\n\
            WorkingDirectory=-/srv/node\n";
        let service = ServiceLocation::parse(show).expect("a loaded unit");
        assert_eq!(service.config_dir(), PathBuf::from("/srv/node/.config"));
        assert_eq!(
            from_node_dir(Some(&service.working_dir), PathBuf::from(".log")),
            PathBuf::from("/srv/node/.log")
        );
        assert_eq!(
            from_node_dir(Some(&service.working_dir), PathBuf::from("/var/log/q")),
            PathBuf::from("/var/log/q")
        );
        assert_eq!(
            from_node_dir(None, PathBuf::from(".log")),
            PathBuf::from(".log")
        );
    }

    /// No service, or one whose directory qclient cannot resolve: the
    /// config resolves as before.
    #[test]
    fn without_a_usable_service_nothing_changes() {
        assert_eq!(
            ServiceLocation::parse("LoadState=not-found\nWorkingDirectory=\n"),
            None
        );
        assert_eq!(
            ServiceLocation::parse("LoadState=loaded\nWorkingDirectory=~\n"),
            None
        );
    }
}

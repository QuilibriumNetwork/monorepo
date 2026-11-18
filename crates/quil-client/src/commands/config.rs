//! `qclient config …` — client config management (local file only).
//!
//! Port of `client/cmd/config/*.go`.

use std::fmt::Write as _;
use std::path::Path;

use clap::Subcommand;

use crate::commands::node::service;
use crate::config::{self, ClientConfig};
use crate::system::{self, InstallLayout};

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Print where qclient installs and reads its files, and the client
    /// settings.
    Print,
    /// Create a default configuration file.
    CreateDefault,
    /// Set public RPC setting (`true`/`false`, toggles if omitted).
    PublicRpc { value: Option<String> },
    /// Set custom RPC URL (`domain:port`, or `clear`).
    SetCustomRpc { value: Option<String> },
}

pub fn run(cmd: &ConfigCommand) -> anyhow::Result<()> {
    match cmd {
        ConfigCommand::Print => print(),
        ConfigCommand::CreateDefault => config::create_default(),
        ConfigCommand::PublicRpc { value } => public_rpc(value.as_deref()),
        ConfigCommand::SetCustomRpc { value } => set_custom_rpc(value.as_deref()),
    }
}

fn print() -> anyhow::Result<()> {
    let cfg = config::load()?;
    print!(
        "{}",
        render(
            &cfg,
            system::install_layout(),
            system::os_type(),
            &system::node_config_home_dir()?.join("default"),
            &config::config_path()?,
        )
    );
    Ok(())
}

/// `qclient config print`: where each file qclient installs or reads lives
/// under `layout` on `os`, for the node config the service runs,
/// `node_config_dir`, and the client config file `client_config`; then the
/// client settings, and the file's `dataDir` and `symlinkPath` when they
/// name other paths, as nothing reads them.
fn render(
    cfg: &ClientConfig,
    layout: &InstallLayout,
    os: &str,
    node_config_dir: &Path,
    client_config: &Path,
) -> String {
    let qclient_dir = layout.client_data_path();
    let qclient_link = system::default_qclient_symlink_path();
    let lines = [
        ("Install root", layout.root.clone()),
        ("qclient releases", qclient_dir.clone()),
        ("qclient link", qclient_link.clone()),
        ("Node releases", layout.node_data_path()),
        ("Node environment", layout.node_env_path()),
        ("Node service", service::service_file_path(os)),
        ("Service logs", layout.service_log_dir(node_config_dir)),
        ("Node config", node_config_dir.to_path_buf()),
        ("Client config", client_config.to_path_buf()),
    ];
    let mut out = String::new();
    for (label, path) in &lines {
        let _ = writeln!(out, "{:<18}{}", format!("{label}:"), path.display());
    }
    let _ = writeln!(out, "{:<18}{}", "Public RPC:", cfg.public_rpc);
    let mut unused = Vec::new();
    if !cfg.data_dir.is_empty() && Path::new(&cfg.data_dir) != qclient_dir {
        unused.push(format!("dataDir {}", cfg.data_dir));
    }
    let link = Path::new(&cfg.symlink_path);
    if !cfg.symlink_path.is_empty()
        && link != qclient_link
        && link != qclient_dir.join(system::QCLIENT_ROOT_LINK)
    {
        unused.push(format!("symlinkPath {}", cfg.symlink_path));
    }
    if !unused.is_empty() {
        let _ = writeln!(out, "Unused config keys: {}", unused.join(", "));
    }
    out
}

fn public_rpc(value: Option<&str>) -> anyhow::Result<()> {
    let mut cfg = config::load()?;
    match value.map(|v| v.to_lowercase()) {
        Some(v) if v == "true" => cfg.public_rpc = true,
        Some(v) if v == "false" => cfg.public_rpc = false,
        Some(v) => anyhow::bail!("Invalid value '{v}'. Please use 'true' or 'false'."),
        None => cfg.public_rpc = !cfg.public_rpc,
    }
    config::save(&cfg)?;
    let status = if cfg.public_rpc {
        "enabled"
    } else {
        "disabled"
    };
    println!(
        "Public RPC has been set to {status} and will be persisted across future commands unless reset."
    );
    Ok(())
}

fn set_custom_rpc(value: Option<&str>) -> anyhow::Result<()> {
    let mut cfg = config::load()?;
    let value = value.ok_or_else(|| {
        anyhow::anyhow!(
            "No argument provided. Please provide a valid URL or 'clear' to clear the custom RPC setting."
        )
    })?;

    if value == "clear" {
        cfg.custom_rpc = String::new();
    } else {
        validate_custom_rpc(value)?;
        cfg.custom_rpc = value.to_string();
    }

    config::save(&cfg)?;
    if value == "clear" {
        println!("Custom RPC URL cleared.");
    } else {
        println!("Custom RPC URL set to: {value}");
    }
    println!("Custom RPC setting will be persisted across future commands unless reset.");
    Ok(())
}

/// Port of `ValidateCustomRpc` — requires `domain:port` shape.
fn validate_custom_rpc(custom_rpc: &str) -> anyhow::Result<()> {
    if custom_rpc.is_empty() {
        anyhow::bail!("custom RPC URL cannot be empty");
    }
    if !custom_rpc.contains('.') || !custom_rpc.contains(':') {
        anyhow::bail!("custom RPC URL must be in format domain:port (e.g. example.com:8080)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(data_dir: &str, symlink_path: &str) -> ClientConfig {
        ClientConfig {
            data_dir: data_dir.into(),
            symlink_path: symlink_path.into(),
            public_rpc: false,
            custom_rpc: String::new(),
            node_symlink_name: String::new(),
            no_action_log: false,
        }
    }

    fn render_on(os: &str, exists: &dyn Fn(&Path) -> bool, cfg: &ClientConfig) -> String {
        render(
            cfg,
            &InstallLayout::for_os(os, exists),
            os,
            Path::new("/home/op/.quilibrium/configs/default"),
            Path::new("/home/op/.quilibrium/qclient-config.yaml"),
        )
    }

    /// The printout is the layout in use, not the config file's keys: a
    /// macOS file written for the /var layout prints the /opt paths, and
    /// its keys as unused.
    #[test]
    fn print_shows_the_macos_layout_and_unused_keys() {
        let stale = cfg(
            "/var/quilibrium/bin/qclient",
            "/var/quilibrium/bin/qclient/current",
        );
        assert_eq!(
            render_on("darwin", &|_| false, &stale),
            "Install root:     /opt/quilibrium\n\
             qclient releases: /opt/quilibrium/bin/qclient\n\
             qclient link:     /usr/local/bin/qclient\n\
             Node releases:    /opt/quilibrium/bin/node\n\
             Node environment: /opt/quilibrium/quilibrium.env\n\
             Node service:     /Library/LaunchDaemons/com.quilibrium.quilibrium-node.plist\n\
             Service logs:     /home/op/.quilibrium/configs/default/.log\n\
             Node config:      /home/op/.quilibrium/configs/default\n\
             Client config:    /home/op/.quilibrium/qclient-config.yaml\n\
             Public RPC:       false\n\
             Unused config keys: dataDir /var/quilibrium/bin/qclient, \
             symlinkPath /var/quilibrium/bin/qclient/current\n",
            "LAYOUT-PATH darwin printout"
        );
    }

    /// On Linux, and for a file naming the layout's own paths (either
    /// link), nothing is reported unused.
    #[test]
    fn print_shows_the_linux_layout() {
        let expected = "Install root:     /var/quilibrium\n\
             qclient releases: /var/quilibrium/bin/qclient\n\
             qclient link:     /usr/local/bin/qclient\n\
             Node releases:    /var/quilibrium/bin/node\n\
             Node environment: /var/quilibrium/quilibrium.env\n\
             Node service:     /etc/systemd/system/quilibrium-node.service\n\
             Service logs:     /var/log/quilibrium\n\
             Node config:      /home/op/.quilibrium/configs/default\n\
             Client config:    /home/op/.quilibrium/qclient-config.yaml\n\
             Public RPC:       false\n";
        for link in [
            "/var/quilibrium/bin/qclient/current",
            "/usr/local/bin/qclient",
        ] {
            let own = cfg("/var/quilibrium/bin/qclient", link);
            assert_eq!(
                render_on("linux", &|_| true, &own),
                expected,
                "LAYOUT-PATH linux printout, symlinkPath {link}"
            );
        }
    }

    #[test]
    fn validate_custom_rpc_shape() {
        assert!(validate_custom_rpc("example.com:8080").is_ok());
        assert!(validate_custom_rpc("nodots").is_err());
        assert!(validate_custom_rpc("no.colon").is_err());
        assert!(validate_custom_rpc("").is_err());
    }
}

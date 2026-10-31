//! Node config directory resolution + loading.
//!
//! Port of the path/name logic in `client/utils/node.go`
//! (`GetDefaultNodeConfigDir`, `LoadNodeConfig`, `HasNodeConfigFiles`).
//! The actual YAML parsing is delegated to `quil_config::load_config`.

use std::path::{Path, PathBuf};

use quil_config::Config;

use crate::system;

/// A node contains both `config.yml` and `keys.yml`
/// (`HasNodeConfigFiles`, `node.go`).
pub fn has_node_config_files(dir: &Path) -> bool {
    dir.join("config.yml").exists() && dir.join("keys.yml").exists()
}

/// Resolve the node config directory, honoring the `--network` /
/// `QUILIBRIUM_NETWORK` override. Port of `GetDefaultNodeConfigDir`.
///
/// Resolution order (matching Go):
/// 1. `~/.quilibrium/configs/{name}` where `name` = network override or
///    `node-quickstart`. If it's a symlink, follow it.
/// 2. Else, if `./.config` exists in the cwd, use it.
/// 3. Else error (auto-creation is handled by `node config create`, which
///    needs the node binary).
pub fn default_node_config_dir(network_override: Option<&str>) -> anyhow::Result<PathBuf> {
    let name = network_override
        .filter(|s| !s.is_empty())
        .unwrap_or(system::DEFAULT_NODE_CONFIG_NAME);

    let config_path = system::node_config_home_dir()?.join(name);

    if config_path.exists() {
        // Follow symlinks (the `default` alias is a symlink).
        return Ok(std::fs::canonicalize(&config_path).unwrap_or(config_path));
    }

    // Fall back to `./.config` in the working directory.
    let alt = PathBuf::from("./.config");
    if alt.exists() {
        return Ok(alt);
    }

    if network_override.map(|s| !s.is_empty()).unwrap_or(false) {
        anyhow::bail!(
            "network config directory does not exist: {}",
            config_path.display()
        );
    }

    anyhow::bail!(
        "default node config directory does not exist: {} \
         (run `qclient node config create` to create one)",
        config_path.display()
    )
}

/// Resolve + load a node config. `config_directory` may be:
/// - `"default"` or empty → resolve via `default_node_config_dir`
/// - an explicit path → loaded directly
///
/// Port of `LoadNodeConfig` / `LoadDefaultNodeConfig`, except that a
/// directory without `config.yml` is refused rather than given a fresh
/// config: that config would carry a new identity, and a client command
/// reading it would report on that identity instead of the node's. Only
/// `node config create` and the node itself create configs.
pub fn load_node_config(
    config_directory: &str,
    network_override: Option<&str>,
) -> anyhow::Result<(Config, PathBuf)> {
    let explicit = !(config_directory.is_empty() || config_directory == "default");
    let dir = if explicit {
        PathBuf::from(config_directory)
    } else {
        default_node_config_dir(network_override)?
    };
    let cfg = load_existing_node_config(&dir, explicit)?;
    Ok((cfg, dir))
}

/// The node config in `dir`, which must already hold `config.yml`: nothing
/// is created. `explicit` says whether the operator named `dir` (`--config`)
/// or it was resolved by default, for the refusal's advice.
pub fn load_existing_node_config(dir: &Path, explicit: bool) -> anyhow::Result<Config> {
    if !dir.join("config.yml").is_file() {
        if explicit {
            anyhow::bail!(
                "{} holds no config.yml: pass the node's config directory, the one holding \
                 config.yml (usually .config in the node directory). qclient creates no config \
                 here: a new config would carry a new identity",
                dir.display()
            );
        }
        anyhow::bail!(
            "the default node config directory {} holds no config.yml: start the node once, \
             run `qclient node config create`, or pass --config with the node's config directory",
            dir.display()
        );
    }
    quil_config::load_config(dir)
        .map_err(|e| anyhow::anyhow!("load node config {}: {}", dir.display(), e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A directory without config.yml is refused, and nothing is created in
    /// it or for it: a fresh config would carry a new identity.
    #[test]
    fn a_config_directory_without_config_yml_is_refused_and_left_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let absent = tmp.path().join("node").join(".config");
        let error = load_node_config(absent.to_str().unwrap(), None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("holds no config.yml"), "{error}");
        assert!(!absent.exists(), "the missing directory was created");
        assert!(!tmp.path().join("node").exists());

        let empty = tmp.path().join("empty");
        fs::create_dir(&empty).unwrap();
        assert!(load_node_config(empty.to_str().unwrap(), None).is_err());
        assert_eq!(
            fs::read_dir(&empty).unwrap().count(),
            0,
            "files were created"
        );
        let error = load_existing_node_config(&empty, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("default node config directory"), "{error}");

        // An existing config still loads.
        fs::write(
            empty.join("config.yml"),
            "listenGrpcMultiaddr: /ip4/127.0.0.1/tcp/8888\n",
        )
        .unwrap();
        let (config, dir) = load_node_config(empty.to_str().unwrap(), None).unwrap();
        assert_eq!(dir, empty);
        assert_eq!(config.listen_grpc_multiaddr, "/ip4/127.0.0.1/tcp/8888");
        assert_eq!(fs::read_dir(&empty).unwrap().count(), 1);
    }

    #[test]
    fn has_node_config_files_requires_both() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!has_node_config_files(tmp.path()));
        fs::write(tmp.path().join("config.yml"), "x").unwrap();
        assert!(!has_node_config_files(tmp.path()));
        fs::write(tmp.path().join("keys.yml"), "y").unwrap();
        assert!(has_node_config_files(tmp.path()));
    }
}

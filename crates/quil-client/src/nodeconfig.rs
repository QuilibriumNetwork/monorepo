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
/// Port of `LoadNodeConfig` / `LoadDefaultNodeConfig`.
pub fn load_node_config(
    config_directory: &str,
    network_override: Option<&str>,
) -> anyhow::Result<(Config, PathBuf)> {
    let dir = if config_directory.is_empty() || config_directory == "default" {
        default_node_config_dir(network_override)?
    } else {
        PathBuf::from(config_directory)
    };
    let cfg = quil_config::load_config(&dir)
        .map_err(|e| anyhow::anyhow!("load node config {}: {}", dir.display(), e))?;
    Ok((cfg, dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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

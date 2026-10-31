//! Key-manager construction for the client.
//!
//! Mirrors the node's `master_node/keys.rs` setup: a `FileKeyManager`
//! backed by `keys.yml`, with `q-peer-key` sourced from
//! `config.p2p.peer_priv_key`. Uses `FalconKeyConstructor` as the
//! post-quantum drop-in for the former BLS constructor, so any signing
//! key the client creates or loads matches the node's verify path.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use quil_config::Config;
use quil_keys::FileKeyManager;

/// The keystore a node config names. A relative `keyManagerFile.path` is
/// read beside the config directory when the file exists there: pre-2.1
/// nodes wrote `.config/keys.yml`, relative to the directory the node ran
/// in, which is the parent of its config directory. So `--config
/// <node>/.config` reads that node's keystore wherever qclient runs, not
/// one under the current directory. Otherwise the path is used as given.
/// The node itself is unchanged: it still opens the path from its own
/// working directory.
pub fn keystore_path(config: &Config, config_dir: &Path) -> PathBuf {
    let configured = &config.key.key_store_file.path;
    if configured.is_empty() {
        return config_dir.join("keys.yml");
    }
    let path = PathBuf::from(configured);
    if path.is_relative() {
        // Through symlinks: a `default` link to `<node>/.config` has the
        // node directory as its real parent.
        let real = std::fs::canonicalize(config_dir).unwrap_or_else(|_| config_dir.to_path_buf());
        if let Some(beside) = real.parent().map(|parent| parent.join(&path)) {
            if beside.is_file() {
                return beside;
            }
        }
    }
    path
}

/// Build a `FileKeyManager` for the given node config + directory.
///
/// Does NOT auto-create the standard keys — the client reads existing
/// keys and creates specific ones on demand (e.g. `q-view-key` /
/// `q-spend-key` for token balances, or via `qclient key create`).
pub fn build_key_manager(
    config: &Config,
    config_dir: &Path,
) -> anyhow::Result<Arc<FileKeyManager>> {
    let keys_path = keystore_path(config, config_dir);

    let proving_key_id = if config.engine.proving_key_id.is_empty() {
        "default-proving-key".to_string()
    } else {
        config.engine.proving_key_id.clone()
    };

    let fkm = FileKeyManager::new(
        keys_path,
        &config.key.key_store_file.encryption_key,
        proving_key_id,
        Box::new(quil_crypto::FalconKeyConstructor),
    )?;

    // `q-peer-key` lives in config, not keys.yml — wire it through so
    // outer-auth signing (Send RPC) and peer-id derivation work.
    fkm.set_peer_priv_key_hex(&config.p2p.peer_priv_key);

    Ok(Arc::new(fkm))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_naming(path: &str) -> Config {
        let mut config = Config::default();
        config.key.key_store_file.path = path.to_string();
        config
    }

    /// A pre-2.1 config names `.config/keys.yml`: read from the node
    /// directory holding the config, not from the current directory.
    #[test]
    fn a_relative_keystore_is_read_beside_the_config_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join("node").join(".config");
        std::fs::create_dir_all(&config_dir).unwrap();
        let config = config_naming(".config/keys.yml");
        // Not there yet: the path stays as given (current directory).
        assert_eq!(
            keystore_path(&config, &config_dir),
            PathBuf::from(".config/keys.yml")
        );
        std::fs::write(config_dir.join("keys.yml"), "null:\n").unwrap();
        let resolved = keystore_path(&config, &config_dir);
        assert_eq!(
            resolved,
            std::fs::canonicalize(config_dir.join("keys.yml")).unwrap()
        );

        // Through a symlinked config directory, the real parent is used.
        #[cfg(unix)]
        {
            let link = tmp.path().join("default");
            std::os::unix::fs::symlink(&config_dir, &link).unwrap();
            assert_eq!(keystore_path(&config, &link), resolved);
        }

        // Absolute paths and the empty default are unchanged.
        let absolute = tmp.path().join("elsewhere").join("keys.yml");
        assert_eq!(
            keystore_path(&config_naming(absolute.to_str().unwrap()), &config_dir),
            absolute
        );
        assert_eq!(
            keystore_path(&config_naming(""), &config_dir),
            config_dir.join("keys.yml")
        );
    }
}

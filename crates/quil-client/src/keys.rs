//! Key-manager construction for the client.
//!
//! Mirrors the node's `master_node/keys.rs` setup: a `FileKeyManager`
//! backed by `keys.yml`, with `q-peer-key` sourced from
//! `config.p2p.peer_priv_key`. Uses `FalconKeyConstructor` as the
//! post-quantum drop-in for the former BLS constructor, so any signing
//! key the client creates or loads matches the node's verify path.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use quil_config::Config;
use quil_keys::FileKeyManager;

/// The keystore a node config names. A relative `keyManagerFile.path` is
/// read beside the config directory when the file exists there: pre-2.1
/// nodes wrote `.config/keys.yml`, relative to the directory the node ran
/// in, which is the parent of its config directory. So `--config
/// <node>/.config` reads that node's keystore wherever qclient runs, not
/// one under the current directory. A path of that generated form,
/// `<directory>/<file>`, names the config directory as the node was given
/// it: once that directory is moved or renamed (`.config-old`), the
/// keystore is the file of that name inside it, read first, so the path
/// does not reach the `.config/keys.yml` of whichever node directory holds
/// the copy or qclient runs in. Otherwise the path is used as given.
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
        if let Some(inside) = renamed_config_dir_keystore(&path, &real) {
            if inside.is_file() {
                return inside;
            }
        }
        if let Some(beside) = real.parent().map(|parent| parent.join(&path)) {
            if beside.is_file() {
                return beside;
            }
        }
    }
    path
}

/// For a generated `<directory>/<file>` path whose directory is not the
/// config directory's own name, that file in the config directory.
fn renamed_config_dir_keystore(path: &Path, config_dir: &Path) -> Option<PathBuf> {
    let parts: Vec<&std::ffi::OsStr> = path
        .components()
        .filter(|part| *part != Component::CurDir)
        .map(|part| match part {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect::<Option<_>>()?;
    match parts.as_slice() {
        [directory, file] if config_dir.file_name() != Some(*directory) => {
            Some(config_dir.join(file))
        }
        _ => None,
    }
}

/// Whether a keystore can be read with its config's `encryptionKey`.
#[derive(Debug, PartialEq, Eq)]
pub enum KeystoreAccess {
    /// No keys: a missing or empty file.
    Empty,
    /// At least one key decrypts: the keystore belongs to the config.
    Readable,
    /// Keys exist and none decrypts: another config's keystore. Holds
    /// their ids.
    Foreign(Vec<String>),
}

/// Probe `key_manager`'s keys with its encryption key. A built manager
/// already holds every key it could decrypt in memory, so this exposes no
/// further secret.
pub fn keystore_access(key_manager: &FileKeyManager) -> KeystoreAccess {
    let mut undecryptable = Vec::new();
    for key in key_manager.list_keys() {
        match key_manager.get_secret_key_bytes_by_id(&key.id) {
            Ok(_) => return KeystoreAccess::Readable,
            Err(e) if e.to_string().contains("decryption failed") => undecryptable.push(key.id),
            // An entry without a payload says nothing about the key.
            Err(_) => {}
        }
    }
    if undecryptable.is_empty() {
        KeystoreAccess::Empty
    } else {
        KeystoreAccess::Foreign(undecryptable)
    }
}

/// The keystore `config` reads, for messages: its absolute path and how
/// `key.keyManagerFile.path` led there.
pub fn describe_keystore(config: &Config, config_dir: &Path) -> String {
    let path = keystore_path(config, config_dir);
    let configured = &config.key.key_store_file.path;
    let config_file = config_dir.join("config.yml");
    if configured.is_empty() {
        return format!(
            "{} (the default of {})",
            path.display(),
            config_file.display()
        );
    }
    if path.is_relative() {
        let cwd = std::env::current_dir().unwrap_or_default();
        return format!(
            "{} (key.keyManagerFile.path {configured:?} of {}, resolved against the current \
             directory)",
            cwd.join(&path).display(),
            config_file.display()
        );
    }
    format!(
        "{} (key.keyManagerFile.path {configured:?} of {})",
        path.display(),
        config_file.display()
    )
}

/// `path` made absolute against the current directory, without touching
/// the file system.
fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// The one header line of a token command: the node's peer ID (none for a
/// config without a network identity) and the absolute config directory
/// it was loaded from, so an operator whose default resolution picked
/// another config sees it.
pub fn node_line(peer: Option<&str>, config_dir: &Path) -> String {
    let dir = absolute(config_dir).display().to_string();
    match peer {
        Some(peer) => format!("Node {peer} (config {dir})"),
        None => format!("Node without network identity (config {dir})"),
    }
}

/// Refuse a keystore that holds no keys, for a command that signs or reads
/// a key: the later `no key with id` error does not say which keystore was
/// read. `config_flag` says whether the command takes `--config`.
pub fn require_keys(
    key_manager: &FileKeyManager,
    config: &Config,
    config_dir: &Path,
    config_flag: bool,
) -> anyhow::Result<()> {
    if keystore_access(key_manager) != KeystoreAccess::Empty {
        return Ok(());
    }
    let fix = if config_flag {
        "pass --config with the node's .config directory"
    } else {
        "run qclient where it finds the node's .config directory"
    };
    anyhow::bail!(
        "keystore {} (from {}) holds no keys: that is not this node's config, or its keystore          lies elsewhere; {fix}, or set key.keyManagerFile.path in that config.yml to the          node's keys.yml",
        absolute(&keystore_path(config, config_dir)).display(),
        absolute(&config_dir.join("config.yml")).display(),
    )
}

/// Build a `FileKeyManager` for the given node config + directory.
///
/// Does NOT auto-create the standard keys — the client reads existing
/// keys and creates specific ones on demand (e.g. the `q-onion-key`
/// wallet key, or via `qclient key create`).
///
/// Refuses a keystore none of whose keys decrypts with the config's
/// `encryptionKey`: it belongs to another config, most often a running
/// node's reached by a relative or stale `keyManagerFile.path`, and
/// reading it would present that node's keys as this config's.
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
        keys_path.clone(),
        &config.key.key_store_file.encryption_key,
        proving_key_id,
        Box::new(quil_crypto::FalconKeyConstructor),
    )?;

    if let KeystoreAccess::Foreign(ids) = keystore_access(&fkm) {
        let own = config_dir.join("keys.yml");
        let hint = if own.is_file() && !same_file(&own, &keys_path) {
            format!(" ({} lies beside that config.yml)", own.display())
        } else {
            String::new()
        };
        anyhow::bail!(
            "keystore {} holds {} keys ({}), and none decrypts with \
             key.keyManagerFile.encryptionKey of {}: it is another config's keystore. Set \
             key.keyManagerFile.path in that config.yml to the absolute path of this config's \
             keys.yml{hint}",
            describe_keystore(config, config_dir),
            ids.len(),
            ids.join(", "),
            config_dir.join("config.yml").display()
        );
    }

    // `q-peer-key` lives in config, not keys.yml — wire it through so
    // outer-auth signing (Send RPC) and peer-id derivation work.
    fkm.set_peer_priv_key_hex(&config.p2p.peer_priv_key);

    Ok(Arc::new(fkm))
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
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

    /// A keystore under `path`, encrypted with `[seed; 32]`, holding the
    /// given wallet-less pre-2.1 keys plus `extra` agreement keys.
    fn write_keystore(path: &Path, seed: u8, extra: &[&str]) -> Arc<FileKeyManager> {
        let km = FileKeyManager::new(
            path.to_path_buf(),
            &hex::encode([seed; 32]),
            "default-proving-key".into(),
            Box::new(quil_crypto::FalconKeyConstructor),
        )
        .unwrap();
        km.create_bls_key("q-prover-key").unwrap();
        km.create_agreement_key("q-device-key", 4).unwrap();
        for id in extra {
            km.create_agreement_key(id, 9).unwrap();
        }
        Arc::new(km)
    }

    /// The operator's layout: a pre-2.1 config directory copied under
    /// another name into the directory of the running node, whose own
    /// keystore is `.config/keys.yml`. The old config's generated path
    /// `.config/keys.yml` must read the keystore beside its own config.yml,
    /// not the running node's, wherever the copy lies.
    #[test]
    fn a_renamed_config_directory_reads_its_own_keystore() {
        let tmp = tempfile::tempdir().unwrap();
        let node = tmp.path().join("node");
        let running = node.join(".config");
        let old = node.join(".config-old");
        std::fs::create_dir_all(&running).unwrap();
        std::fs::create_dir_all(&old).unwrap();
        std::fs::write(running.join("keys.yml"), "null:\n").unwrap();
        std::fs::write(old.join("keys.yml"), "null:\n").unwrap();
        let own = std::fs::canonicalize(old.join("keys.yml")).unwrap();
        for path in [".config/keys.yml", "./.config/keys.yml"] {
            assert_eq!(keystore_path(&config_naming(path), &old), own, "{path}");
        }
        // Moved away from any node directory, the same.
        let moved = tmp.path().join("backup").join("old-identity");
        std::fs::create_dir_all(&moved).unwrap();
        std::fs::write(moved.join("keys.yml"), "null:\n").unwrap();
        assert_eq!(
            keystore_path(&config_naming(".config/keys.yml"), &moved),
            std::fs::canonicalize(moved.join("keys.yml")).unwrap()
        );
        // The running node's own config still reads its keystore, and a
        // path of another form is not reinterpreted.
        assert_eq!(
            keystore_path(&config_naming(".config/keys.yml"), &running),
            std::fs::canonicalize(running.join("keys.yml")).unwrap()
        );
        assert_eq!(
            keystore_path(&config_naming("keys/keys.yml/x"), &old),
            PathBuf::from("keys/keys.yml/x")
        );
    }

    /// A config whose path names another config's keystore (here the
    /// running node's, by absolute path) is refused by name: the keystore,
    /// the config and the setting to fix. Before, qclient opened it and the
    /// first wallet key read failed with a bare decryption error.
    #[test]
    fn another_configs_keystore_is_refused_naming_it_and_the_config() {
        let tmp = tempfile::tempdir().unwrap();
        let running = tmp.path().join("node").join(".config");
        let old = tmp.path().join("old-identity");
        std::fs::create_dir_all(&running).unwrap();
        std::fs::create_dir_all(&old).unwrap();
        let foreign = running.join("keys.yml");
        write_keystore(&foreign, 7, &["q-onion-key"]);
        write_keystore(&old.join("keys.yml"), 8, &[]);
        let mut config = config_naming(foreign.to_str().unwrap());
        config.key.key_store_file.encryption_key = hex::encode([8u8; 32]);
        let before = std::fs::read(&foreign).unwrap();

        let error = match build_key_manager(&config, &old) {
            Ok(km) => panic!(
                "opened another config's keystore; its wallet key reads as: {}",
                km.get_secret_key_bytes_by_id("q-onion-key").unwrap_err()
            ),
            Err(error) => error.to_string(),
        };
        for part in [
            foreign.to_str().unwrap(),
            old.join("config.yml").to_str().unwrap(),
            "none decrypts with key.keyManagerFile.encryptionKey",
            "q-onion-key",
            "Set key.keyManagerFile.path",
            old.join("keys.yml").to_str().unwrap(),
        ] {
            assert!(error.contains(part), "{part:?} missing from: {error}");
        }
        assert_eq!(std::fs::read(&foreign).unwrap(), before);

        // Its own keystore, and a keystore with one readable key, open.
        config.key.key_store_file.path = old.join("keys.yml").to_string_lossy().into_owned();
        let own = build_key_manager(&config, &old).unwrap();
        assert!(own.get_secret_key_bytes_by_id("q-device-key").is_ok());
        config.key.key_store_file.path = tmp.path().join("none.yml").to_string_lossy().into_owned();
        assert!(build_key_manager(&config, &old)
            .unwrap()
            .list_keys()
            .is_empty());
    }

    /// The header names the peer (or its absence) and the absolute config
    /// directory, in one line.
    #[test]
    fn node_line_names_the_peer_and_the_config_directory() {
        let dir = std::env::current_dir().unwrap().join(".config");
        assert_eq!(
            node_line(Some("QmPeer"), &dir),
            format!("Node QmPeer (config {})", dir.display())
        );
        assert_eq!(
            node_line(None, Path::new(".config")),
            format!("Node without network identity (config {})", dir.display())
        );
    }

    /// A config directory with config.yml and no keys.yml is refused at once
    /// by naming the keystore, the config and the fix; a keystore holding a
    /// key passes. Before, the first key read failed with `no key with id`.
    #[test]
    fn a_keystore_without_keys_is_refused_naming_it_and_the_config() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".config");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.yml"), "{}\n").unwrap();
        let config = config_naming("");
        let empty = build_key_manager(&config, &dir).unwrap();

        let error = require_keys(&empty, &config, &dir, true)
            .expect_err("an empty keystore was accepted")
            .to_string();
        for part in [
            dir.join("keys.yml").to_str().unwrap(),
            dir.join("config.yml").to_str().unwrap(),
            "holds no keys",
            "pass --config with the node's .config directory",
            "key.keyManagerFile.path",
        ] {
            assert!(error.contains(part), "{part:?} missing from: {error}");
        }
        let error = require_keys(&empty, &config, &dir, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("run qclient where it finds"), "{error}");

        write_keystore(&dir.join("keys.yml"), 3, &[]);
        let mut config = config_naming("");
        config.key.key_store_file.encryption_key = hex::encode([3u8; 32]);
        let full = build_key_manager(&config, &dir).unwrap();
        require_keys(&full, &config, &dir, true).expect("a keystore with keys was refused");
    }
}

//! Resolution of a node's `keys.yml` path from its config.
//!
//! The keystore holds the node's prover key. When the configured file is
//! missing or holds no prover key, [`FileKeyManager::ensure_standard_keys`]
//! creates one, which gives the node a new prover address; seniority earned
//! by the old key stays on the old address. A wrong path must therefore stop
//! the node instead of silently creating that new identity.
//!
//! [`FileKeyManager::ensure_standard_keys`]: crate::FileKeyManager::ensure_standard_keys

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use quil_config::KeyStoreFileConfig;
use quil_types::error::{QuilError, Result};

/// The keystore entry that holds the node's prover identity.
const PROVER_KEY_ID: &str = "q-prover-key";

/// Resolve the keystore path of `config` for a command that may create the
/// node's prover key, and refuse a path where creating it would most likely
/// replace an existing identity.
///
/// An empty `path` means `<config_dir>/keys.yml`. A relative `path` resolves
/// against the working directory, as the Go node opened it; the returned
/// path is absolute. A dangling symbolic link, a directory or an unreadable
/// path is refused. When the resolved keystore is missing or holds no
/// prover key, this also refuses if a keystore holding a prover key exists
/// at `<config_dir>/keys.yml`, or at `path` taken relative to `config_dir`:
/// the path most likely points at the wrong place, and the error names both
/// paths. A missing keystore is refused when `createIfMissing` is false, as
/// the Go node refused to open it then; a keystore that exists without a
/// prover key receives one, as in the Go node.
pub fn resolve_keystore_path(config: &KeyStoreFileConfig, config_dir: &Path) -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    resolve_in(config, config_dir, &cwd, Creation::Allowed)
}

/// Resolve the keystore path of `config` for a tool that only uses the
/// node's prover identity: as [`resolve_keystore_path`], but refuse unless
/// the keystore already holds a prover key.
pub fn resolve_existing_keystore_path(
    config: &KeyStoreFileConfig,
    config_dir: &Path,
) -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    resolve_in(config, config_dir, &cwd, Creation::Refused)
}

/// Whether the caller may create a missing prover key.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Creation {
    Allowed,
    Refused,
}

/// What a keystore path holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Keystore {
    Missing,
    WithoutProverKey,
    WithProverKey,
}

fn resolve_in(
    config: &KeyStoreFileConfig,
    config_dir: &Path,
    cwd: &Path,
    creation: Creation,
) -> Result<PathBuf> {
    let configured = if config.path.is_empty() {
        config_dir.join("keys.yml")
    } else {
        PathBuf::from(&config.path)
    };
    let resolved = cwd.join(&configured);
    let state = inspect(&resolved)?;
    if state == Keystore::WithProverKey {
        return Ok(resolved);
    }

    let lacks = if state == Keystore::Missing {
        "does not exist"
    } else {
        "holds no q-prover-key"
    };
    let setting = format!(
        "key.keyManagerFile.path {:?} names {}, which {lacks}; a relative path resolves \
         against the working directory {}",
        config.path,
        resolved.display(),
        cwd.display()
    );

    let mut candidates = vec![config_dir.join("keys.yml")];
    if !config.path.is_empty() && configured.is_relative() {
        candidates.push(config_dir.join(&configured));
    }
    for candidate in candidates {
        let candidate = cwd.join(candidate);
        if holds_prover_key(&candidate)? && !same_file(&candidate, &resolved) {
            return Err(QuilError::InvalidArgument(format!(
                "{setting}. The keystore {} holds a prover key: refusing to create a new \
                 prover identity, which would leave the seniority earned by that key on its \
                 address. Set key.keyManagerFile.path in {} to the keystore this node should \
                 use, for example {}, or move that keystore away to start a new identity",
                candidate.display(),
                cwd.join(config_dir).join("config.yml").display(),
                candidate.display(),
            )));
        }
    }

    if creation == Creation::Refused {
        return Err(QuilError::InvalidArgument(format!(
            "{setting}. This command only uses an existing prover identity: correct \
             key.keyManagerFile.path, or start the node once to create the identity"
        )));
    }
    if state == Keystore::Missing && !config.create_if_missing {
        return Err(QuilError::InvalidArgument(format!(
            "{setting}, and key.keyManagerFile.createIfMissing is false. Restore keys.yml at \
             that path or correct the path; set createIfMissing to true only to create a new \
             prover identity"
        )));
    }

    Ok(resolved)
}

/// Inspect the keystore at `path` without following a dangling link into a
/// fresh file.
fn inspect(path: &Path) -> Result<Keystore> {
    let entry = match std::fs::symlink_metadata(path) {
        Ok(entry) => entry,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Keystore::Missing),
        Err(e) => return Err(unreadable(path, e)),
    };
    let target = if entry.file_type().is_symlink() {
        match std::fs::metadata(path) {
            Ok(target) => target,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let link = std::fs::read_link(path)
                    .map(|t| t.display().to_string())
                    .unwrap_or_else(|e| format!("an unreadable target ({e})"));
                return Err(QuilError::InvalidArgument(format!(
                    "the keystore {} is a symbolic link to {link}, which does not exist. \
                     Refusing to create a new prover identity in its place: restore the link \
                     target or correct key.keyManagerFile.path",
                    path.display()
                )));
            }
            Err(e) => return Err(unreadable(path, e)),
        }
    } else {
        entry
    };
    if target.is_dir() {
        return Err(QuilError::InvalidArgument(format!(
            "key.keyManagerFile.path names the directory {}; it must name the keys.yml file",
            path.display()
        )));
    }

    let contents = std::fs::read_to_string(path).map_err(|e| unreadable(path, e))?;
    if contents.trim().is_empty() {
        return Ok(Keystore::WithoutProverKey);
    }
    let keys: serde_yaml::Value = serde_yaml::from_str(&contents).map_err(|e| {
        QuilError::Serialization(format!("cannot parse the keystore {}: {e}", path.display()))
    })?;
    let has_prover_key = keys
        .as_mapping()
        .is_some_and(|keys| keys.contains_key(PROVER_KEY_ID));
    Ok(if has_prover_key {
        Keystore::WithProverKey
    } else {
        Keystore::WithoutProverKey
    })
}

/// Whether `path` names a keystore file that holds a prover key, following
/// links; an unreadable path is an error rather than an absent keystore.
fn holds_prover_key(path: &Path) -> Result<bool> {
    match std::fs::metadata(path) {
        Ok(entry) if entry.is_file() => Ok(inspect(path)? == Keystore::WithProverKey),
        Ok(_) => Ok(false),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(unreadable(path, e)),
    }
}

/// Whether two paths name the same file, after resolving links and `..`.
fn same_file(a: &Path, b: &Path) -> bool {
    a == b
        || matches!(
            (std::fs::canonicalize(a), std::fs::canonicalize(b)),
            (Ok(a), Ok(b)) if a == b
        )
}

fn unreadable(path: &Path, e: std::io::Error) -> QuilError {
    QuilError::Io(std::io::Error::new(
        e.kind(),
        format!("cannot read the keystore {}: {e}", path.display()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A fresh directory standing in for the node's working directory.
    fn workdir(name: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "quil-keystore-path-{}-{}-{}",
            name,
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn keystore_config(path: &str, create_if_missing: bool) -> KeyStoreFileConfig {
        KeyStoreFileConfig {
            path: path.to_string(),
            create_if_missing,
            encryption_key: String::new(),
        }
    }

    fn write(path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    /// A keystore holding a prover key (the entry body is not parsed here).
    fn write_keystore(path: &Path) {
        write(path, "q-prover-key:\n  id: q-prover-key\n  type: 8\n");
    }

    /// The `null:` placeholder of a keystore that holds no key yet.
    fn write_placeholder(path: &Path) {
        write(path, "null:\n");
    }

    /// A keystore holding only client keys, as a client run may write it.
    fn write_client_keystore(path: &Path) {
        write(path, "q-view-key:\n  id: q-view-key\n  type: 4\n");
    }

    fn resolve(
        config: &KeyStoreFileConfig,
        config_dir: &Path,
        cwd: &Path,
    ) -> std::result::Result<PathBuf, String> {
        resolve_in(config, config_dir, cwd, Creation::Allowed).map_err(|e| e.to_string())
    }

    fn shown(path: &Path) -> String {
        path.display().to_string()
    }

    #[test]
    fn an_existing_relative_keystore_resolves_against_the_working_directory() {
        let cwd = workdir("existing_relative");
        write_keystore(&cwd.join(".config/keys.yml"));
        let config = keystore_config(".config/keys.yml", false);

        let path = resolve(&config, Path::new(".config"), &cwd).unwrap();

        assert_eq!(path, cwd.join(".config/keys.yml"));
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[test]
    fn a_first_start_may_create_the_keystore() {
        let cwd = workdir("first_start");
        let config_dir = cwd.join("configs/default");
        let config = keystore_config("", true);

        let path = resolve(&config, &config_dir, &cwd).unwrap();

        assert_eq!(path, config_dir.join("keys.yml"));
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[test]
    fn a_first_start_in_the_go_layout_may_create_the_keystore() {
        // Go's default: `--config .config` with path `.config/keys.yml`, both
        // relative to the node directory, and nothing on disk yet.
        let cwd = workdir("first_start_go_layout");
        let config = keystore_config(".config/keys.yml", true);

        let path = resolve(&config, Path::new(".config"), &cwd).unwrap();

        assert_eq!(path, cwd.join(".config/keys.yml"));
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[test]
    fn a_first_start_on_a_placeholder_may_create_the_prover_key() {
        // The placeholder is the keystore the config names, reached through
        // a differently spelled path: no other keystore exists.
        let cwd = workdir("first_start_placeholder");
        write_placeholder(&cwd.join(".config/keys.yml"));
        let config = keystore_config("./.config/keys.yml", true);

        let path = resolve(&config, Path::new(".config"), &cwd).unwrap();

        assert_eq!(path, cwd.join("./.config/keys.yml"));
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[test]
    fn a_placeholder_with_create_if_missing_false_may_receive_the_prover_key() {
        // Go 2.1 wrote a `null:` placeholder with createIfMissing false and
        // then created the prover key in that existing file.
        let cwd = workdir("placeholder_create_false");
        write_placeholder(&cwd.join(".config/keys.yml"));
        let config = keystore_config(".config/keys.yml", false);

        let path = resolve(&config, Path::new(".config"), &cwd).unwrap();

        assert_eq!(path, cwd.join(".config/keys.yml"));
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[test]
    fn a_client_keystore_with_create_if_missing_false_gets_a_prover_key_and_a_warn() {
        let cwd = workdir("client_keystore_create_false");
        let config_dir = cwd.join(".config");
        let keys_path = config_dir.join("keys.yml");
        let client = crate::FileKeyManager::new(
            keys_path.clone(),
            "",
            "default-proving-key".into(),
            Box::new(quil_crypto::FalconKeyConstructor),
        )
        .unwrap();
        client.create_agreement_key("q-view-key", 4).unwrap();
        let config = keystore_config(".config/keys.yml", false);

        let path = resolve(&config, Path::new(".config"), &cwd).unwrap();
        assert_eq!(path, keys_path);
        let node = crate::FileKeyManager::new(
            path,
            "",
            "default-proving-key".into(),
            Box::new(quil_crypto::FalconKeyConstructor),
        )
        .unwrap();
        let warns =
            crate::file_key_manager::tests::warns_of(|| node.ensure_standard_keys().unwrap());

        assert!(
            warns.iter().any(|w| w.contains("new prover identity")),
            "the created prover key must be announced: {warns:?}"
        );
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[test]
    fn a_first_start_on_a_placeholder_or_empty_keystore_creates_the_prover_key() {
        // The real startup path on what `qclient node config create` (`null:`)
        // or a truncated write (empty file) leaves before the first start.
        use crate::KeyManager as _;
        use quil_types::crypto::KeyType;

        for (name, contents) in [("null_placeholder", "null:\n"), ("empty_file", "")] {
            let cwd = workdir(name);
            let keys_path = cwd.join(".config/keys.yml");
            write(&keys_path, contents);
            let config = keystore_config(".config/keys.yml", false);
            let open = |path: PathBuf| {
                crate::FileKeyManager::new(
                    path,
                    "",
                    "default-proving-key".into(),
                    Box::new(quil_crypto::FalconKeyConstructor),
                )
                .unwrap_or_else(|e| panic!("{name}: the keystore must load: {e}"))
            };

            let path = resolve(&config, Path::new(".config"), &cwd)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            let node = open(path);
            let warns =
                crate::file_key_manager::tests::warns_of(|| node.ensure_standard_keys().unwrap());

            assert!(
                warns.iter().any(|w| w.contains("new prover identity")),
                "{name}: the created prover key must be announced: {warns:?}"
            );
            let saved = std::fs::read_to_string(&keys_path).unwrap();
            assert!(saved.contains("q-prover-key"), "{name}: {saved}");
            assert!(
                !saved.lines().any(|line| line.starts_with("null")),
                "{name}: the placeholder must not be written back: {saved}"
            );
            assert_eq!(
                open(keys_path).get_public_key(KeyType::Falcon512).unwrap(),
                node.get_public_key(KeyType::Falcon512).unwrap(),
                "{name}: the created prover key loads on the next start"
            );
            let _ = std::fs::remove_dir_all(&cwd);
        }
    }

    #[test]
    fn a_missing_keystore_with_create_if_missing_false_is_refused() {
        let cwd = workdir("create_false");
        let config_dir = cwd.join("configs/default");
        let config = keystore_config(".config/keys.yml", false);

        let err = resolve(&config, &config_dir, &cwd)
            .expect_err("a missing keystore must not be created when createIfMissing is false");

        assert!(err.contains(&shown(&cwd.join(".config/keys.yml"))), "{err}");
        assert!(err.contains("createIfMissing is false"), "{err}");
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[test]
    fn a_wrong_path_beside_a_keystore_in_the_config_dir_is_refused() {
        // The reported case: the config lives outside the working directory
        // and its relative path misses the keys.yml stored beside it, so a
        // node allowed to create keys would start a new prover identity.
        let cwd = workdir("beside_config");
        let config_dir = cwd.join("configs/default");
        write_keystore(&config_dir.join("keys.yml"));
        let config = keystore_config("./.config/keys.yml", true);

        let err = resolve(&config, &config_dir, &cwd)
            .expect_err("a keystore beside the config must not be replaced by a new one");

        assert!(
            err.starts_with("invalid argument: key.keyManagerFile.path"),
            "{err}"
        );
        assert!(
            err.contains(&shown(&cwd.join("./.config/keys.yml"))),
            "{err}"
        );
        assert!(err.contains(&shown(&config_dir.join("keys.yml"))), "{err}");
        assert!(err.contains("move that keystore away"), "{err}");
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[test]
    fn a_stray_keystore_without_prover_key_beside_the_real_one_is_refused() {
        // A keys.yml without prover key at the configured path (for example
        // written by a client run from another directory) must not hide the
        // node's keystore beside its config.
        let cwd = workdir("stray_keystore");
        let config_dir = cwd.join("configs/default");
        write_keystore(&config_dir.join("keys.yml"));
        write_client_keystore(&cwd.join(".config/keys.yml"));
        let config = keystore_config(".config/keys.yml", true);

        let err = resolve(&config, &config_dir, &cwd)
            .expect_err("a stray keystore must not receive a new prover key");

        assert!(err.contains("holds no q-prover-key"), "{err}");
        assert!(err.contains(&shown(&cwd.join(".config/keys.yml"))), "{err}");
        assert!(err.contains(&shown(&config_dir.join("keys.yml"))), "{err}");
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[test]
    fn a_relative_path_found_only_under_the_config_dir_is_refused() {
        let cwd = workdir("relative_to_config");
        let config_dir = cwd.join("configs/default");
        write_keystore(&config_dir.join("keys/node.yml"));
        let config = keystore_config("keys/node.yml", true);

        let err = resolve(&config, &config_dir, &cwd)
            .expect_err("a keystore under the config dir must not be replaced by a new one");

        assert!(err.contains(&shown(&cwd.join("keys/node.yml"))), "{err}");
        assert!(
            err.contains(&shown(&config_dir.join("keys/node.yml"))),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[test]
    fn a_keystore_without_prover_key_beside_the_config_does_not_block_a_first_start() {
        for (name, write_rival) in [
            ("rival_placeholder", write_placeholder as fn(&Path)),
            ("rival_client_keystore", write_client_keystore as fn(&Path)),
        ] {
            let cwd = workdir(name);
            let config_dir = cwd.join("configs/default");
            write_rival(&config_dir.join("keys.yml"));
            let config = keystore_config(".config/keys.yml", true);

            let path = resolve(&config, &config_dir, &cwd).unwrap_or_else(|err| {
                panic!("{name}: no prover key beside the config to protect: {err}")
            });

            assert_eq!(path, cwd.join(".config/keys.yml"), "{name}");
            let _ = std::fs::remove_dir_all(&cwd);
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_keystore_is_refused() {
        let cwd = workdir("dangling_symlink");
        let link = cwd.join("keys.yml");
        let target = cwd.join("mounted/keys.yml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let config = keystore_config(&shown(&link), true);

        let err = resolve(&config, &cwd.join("configs/default"), &cwd)
            .expect_err("a new keystore must not replace a link whose target is missing");

        assert!(err.contains(&shown(&link)), "{err}");
        assert!(err.contains(&shown(&target)), "{err}");
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[test]
    fn a_directory_keystore_path_is_refused() {
        let cwd = workdir("directory");
        std::fs::create_dir_all(cwd.join(".config/keys.yml")).unwrap();
        let config = keystore_config(".config/keys.yml", true);

        let err =
            resolve(&config, Path::new(".config"), &cwd).expect_err("a directory is no keystore");

        assert!(err.contains(&shown(&cwd.join(".config/keys.yml"))), "{err}");
        assert!(err.contains("names the directory"), "{err}");
        let _ = std::fs::remove_dir_all(&cwd);
    }

    #[test]
    fn a_tool_refuses_a_missing_keystore_and_uses_an_existing_one() {
        let cwd = workdir("tool");
        let config = keystore_config(".config/keys.yml", true);

        let err = resolve_in(&config, Path::new(".config"), &cwd, Creation::Refused)
            .expect_err("a tool must not create a prover identity")
            .to_string();
        assert!(err.contains(&shown(&cwd.join(".config/keys.yml"))), "{err}");
        assert!(
            err.contains("only uses an existing prover identity"),
            "{err}"
        );

        write_keystore(&cwd.join(".config/keys.yml"));
        let path = resolve_in(&config, Path::new(".config"), &cwd, Creation::Refused).unwrap();
        assert_eq!(path, cwd.join(".config/keys.yml"));
        let _ = std::fs::remove_dir_all(&cwd);
    }
}

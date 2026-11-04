//! `qclient node config …` — node config management (local files).
//!
//! Port of `client/cmd/node/nodeconfig/set.go`, plus `clean`.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap::Subcommand;

use quil_p2p::ed448_identity::Ed448Identity;

use crate::context::GlobalArgs;
use crate::{keys, nodeconfig, system};

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Create a default configuration file set for a node.
    Create {
        /// Name for the configuration (defaults to `default-config`; cannot be `default`).
        name: Option<String>,
        /// Make this config the `default` even though `default` holds keys,
        /// which changes the identity of a node started from `default`. A
        /// `default` without keys always moves to the new config.
        #[arg(short = 'd', long)]
        default: bool,
    },
    /// Set a config key on the default node config.
    Set {
        /// The key: p2p.listenMultiaddr or listenGrpcMultiaddr.
        key: String,
        /// The new value, a multiaddr.
        value: String,
    },
    /// Comment out settings of earlier releases that have no effect.
    ///
    /// Edits the config.yml of the default node config (as `set` resolves
    /// it) line by line: each retired setting and its value is commented
    /// out, everything else stays as written. Keys the node does not know
    /// are left for you to check. The original is kept as config.yml.bak.
    Clean {
        /// Print the changes without writing them.
        #[arg(long)]
        dry_run: bool,
    },
    /// Set the `default` config symlink to a named config, and with it the
    /// identity of a node started from `default`.
    Switch {
        /// The config to make default (lists available configs if omitted).
        name: Option<String>,
    },
    /// Import a config directory into the standard location.
    Import {
        /// Name to import as.
        name: String,
        /// Source directory (must contain config.yml + keys.yml).
        source_dir: String,
        /// Also set it as the default config, and with it the identity of a
        /// node started from `default`.
        #[arg(short = 'd', long)]
        default: bool,
    },
}

pub fn run(global: GlobalArgs, cmd: &ConfigCommand) -> anyhow::Result<()> {
    match cmd {
        ConfigCommand::Create { name, default } => create(name.as_deref(), *default),
        ConfigCommand::Set { key, value } => set(global, key, value),
        ConfigCommand::Clean { dry_run } => clean(global, *dry_run),
        ConfigCommand::Switch { name } => switch(name.as_deref()),
        ConfigCommand::Import {
            name,
            source_dir,
            default,
        } => import(name, source_dir, *default),
    }
}

/// Port of `client/cmd/node/nodeconfig/create.go` `NodeConfigCreateCmd` +
/// `utils.CreateDefaultNodeConfig`. Writes a default `config.yml` (via
/// `quil_config::load_config`, which generates defaults + a random keystore
/// encryption key on first run) plus a `keys.yml` placeholder — the real keys
/// are generated when the node first starts. Like Go, the new config is
/// symlinked as `default` so it is immediately usable, unless `default` holds
/// keys: moving it would change a node's identity, which needs `set_default`.
fn create(name: Option<&str>, set_default: bool) -> anyhow::Result<()> {
    let notice = create_in(&system::node_config_home_dir()?, name, set_default)?;
    println!("{notice}");
    Ok(())
}

fn create_in(configs_dir: &Path, name: Option<&str>, set_default: bool) -> anyhow::Result<String> {
    let config_name = match name {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => "default-config".to_string(),
    };
    if config_name == "default" {
        anyhow::bail!("'default' is reserved for the symlink. Please use a different name.");
    }

    let config_dir = configs_dir.join(&config_name);
    quil_keys::refuse_recreated_config(&config_dir).map_err(|e| anyhow::anyhow!("{e}"))?;
    let existed = config_dir.join("config.yml").is_file();

    // Generates config.yml with defaults (and the keystore encryption key).
    quil_config::load_config(&config_dir)
        .map_err(|e| anyhow::anyhow!("create default config: {e}"))?;

    // The node writes real keys on first start; until then keys.yml is a
    // placeholder so the config dir is recognized as valid (`has_node_config_files`).
    let keys_path = config_dir.join("keys.yml");
    if !keys_path.exists() {
        quil_config::write_private_file(&keys_path, b"null:\n")
            .map_err(|e| anyhow::anyhow!("write keys.yml placeholder: {e}"))?;
    }

    if !nodeconfig::has_node_config_files(&config_dir) {
        anyhow::bail!(
            "Failed to generate configuration files in: {}",
            config_dir.display()
        );
    }

    let done = if existed {
        format!("The {config_name} configuration already exists and is unchanged")
    } else {
        format!("Successfully created {config_name} configuration")
    };
    let mut lines = match current_default(configs_dir) {
        Some((dir, identity))
            if identity.has_keys()
                && !set_default
                && std::fs::canonicalize(&config_dir).ok().as_ref() != Some(&dir) =>
        {
            vec![format!(
                "{done}; default stays on {} ({}). To run this config, which changes the node's \
                 identity: qclient node config switch {config_name}",
                dir.display(),
                identity.describe()
            )]
        }
        // Go's `CreateDefaultNodeConfig` symlinks the new config as `default`
        // so the node uses it immediately.
        _ => {
            let change = repoint_default(configs_dir, &config_dir)?;
            let mut lines = vec![format!("{done}; symlinked to default")];
            lines.extend(change);
            lines
        }
    };
    if !existed {
        lines.push("The keys.yml file will only contain 'null:' until the node is started.".into());
    }
    Ok(lines.join("\n"))
}

/// Who a node started from a config directory is, for messages.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigIdentity {
    prover: Option<String>,
    peer: Option<String>,
}

impl ConfigIdentity {
    /// Read from `dir` without creating anything in it. The keys of a config
    /// that cannot be read stay unknown; a keystore that cannot be read still
    /// counts as holding a key.
    fn of(dir: &Path) -> Self {
        let config = nodeconfig::load_existing_node_config(dir, true).ok();
        let keystore = config
            .as_ref()
            .map_or_else(|| dir.join("keys.yml"), |c| keys::keystore_path(c, dir));
        let prover = match quil_keys::stored_prover_address(&keystore) {
            Ok(address) => address.map(|a| tail(&hex::encode(a))),
            Err(_) => Some("unreadable".to_string()),
        };
        let peer = config
            .and_then(|c| Ed448Identity::from_config_hex(&c.p2p.peer_priv_key).ok())
            .map(|id| tail(&id.peer_id_base58()));
        Self { prover, peer }
    }

    fn has_keys(&self) -> bool {
        self.prover.is_some() || self.peer.is_some()
    }

    fn describe(&self) -> String {
        let prover = self
            .prover
            .as_ref()
            .map_or("no prover key yet".to_string(), |p| format!("prover {p}"));
        match &self.peer {
            Some(peer) => format!("{prover}, peer {peer}"),
            None => prover,
        }
    }
}

/// `…` and the last six characters of `id`, as logs name peers and provers.
fn tail(id: &str) -> String {
    format!("…{}", &id[id.len().saturating_sub(6)..])
}

/// The directory `default` points at, and who it is.
fn current_default(configs_dir: &Path) -> Option<(PathBuf, ConfigIdentity)> {
    let dir = std::fs::canonicalize(configs_dir.join("default")).ok()?;
    let identity = ConfigIdentity::of(&dir);
    Some((dir, identity))
}

/// Point `default` at `target`. Returns what that changes for a node started
/// from `default`, if it changes who that node is.
fn repoint_default(configs_dir: &Path, target: &Path) -> anyhow::Result<Option<String>> {
    let previous = current_default(configs_dir);
    let default_link = configs_dir.join("default");
    if std::fs::symlink_metadata(&default_link).is_ok() {
        let _ = std::fs::remove_file(&default_link);
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, &default_link)
        .map_err(|e| anyhow::anyhow!("create default symlink: {e}"))?;
    let new = ConfigIdentity::of(target);
    Ok(previous.and_then(|(dir, old)| {
        (old.has_keys() && old != new).then(|| {
            let to = if new.prover.is_some() {
                new.describe()
            } else {
                "a new prover made at its first start".to_string()
            };
            format!(
                "A node started from default changes identity: {} (in {}) to {to}. The old \
                 identity keeps its seats and seniority; restart the node to apply.",
                old.describe(),
                dir.display()
            )
        })
    }))
}

fn import(name: &str, source_dir: &str, set_default: bool) -> anyhow::Result<()> {
    let notice = import_in(
        &system::node_config_home_dir()?,
        name,
        source_dir,
        set_default,
    )?;
    println!("{notice}");
    Ok(())
}

fn import_in(
    configs_dir: &Path,
    name: &str,
    source_dir: &str,
    set_default: bool,
) -> anyhow::Result<String> {
    let source = std::path::Path::new(source_dir);
    if !source.exists() {
        anyhow::bail!("Source directory does not exist: {source_dir}");
    }
    if !nodeconfig::has_node_config_files(source) {
        anyhow::bail!("{source_dir} is not a valid config directory (needs config.yml + keys.yml)");
    }
    let target = configs_dir.join(name);
    if target.join("config.yml").exists() || target.join("keys.yml").exists() {
        anyhow::bail!(
            "{} already holds a config: importing would overwrite its keys. Choose another name, \
             or move it away first",
            target.display()
        );
    }
    quil_config::create_private_dir_all(&target)?;
    copy_dir(source, &target)?;

    if set_default {
        let change = repoint_default(configs_dir, &target)?;
        let mut lines = vec![format!(
            "Successfully imported config files to {name} and symlinked to default"
        )];
        lines.extend(change);
        Ok(lines.join("\n"))
    } else {
        Ok(format!(
            "Successfully imported config files to {}",
            target.display()
        ))
    }
}

/// Recursively copy a directory tree. It holds private keys: directories
/// this creates are accessible by their owner only.
fn copy_dir(from: &std::path::Path, to: &std::path::Path) -> anyhow::Result<()> {
    quil_config::create_private_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&src, &dst)?;
        } else {
            std::fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}

/// List config dirs under `~/.quilibrium/configs` that have config+keys.
fn list_configs() -> anyhow::Result<Vec<String>> {
    let dir = system::node_config_home_dir()?;
    let mut out = Vec::new();
    if dir.exists() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "default" || name.is_empty() {
                continue;
            }
            if nodeconfig::has_node_config_files(&path) {
                out.push(name.to_string());
            }
        }
    }
    out.sort();
    Ok(out)
}

fn switch(name: Option<&str>) -> anyhow::Result<()> {
    let name = match name {
        Some(n) => n.to_string(),
        None => {
            let configs = list_configs()?;
            if configs.is_empty() {
                anyhow::bail!(
                    "No configurations found. Create one with 'qclient node config create'"
                );
            }
            println!("Available configurations:");
            for (i, c) in configs.iter().enumerate() {
                println!("{}. {c}", i + 1);
            }
            anyhow::bail!("Specify a configuration name: qclient node config switch <name>");
        }
    };
    if name == "default" {
        anyhow::bail!("Invalid configuration name. 'default' is reserved.");
    }

    let notice = switch_in(&system::node_config_home_dir()?, &name)?;
    println!("{notice}");
    Ok(())
}

fn switch_in(configs_dir: &Path, name: &str) -> anyhow::Result<String> {
    let source = configs_dir.join(name);
    if !nodeconfig::has_node_config_files(&source) {
        anyhow::bail!(
            "{} is not a valid config directory (needs config.yml + keys.yml)",
            source.display()
        );
    }
    let change = repoint_default(configs_dir, &source)?;
    let mut lines = vec![format!("Default config set to {name}")];
    lines.extend(change);
    Ok(lines.join("\n"))
}

fn set(global: GlobalArgs, key: &str, value: &str) -> anyhow::Result<()> {
    let network = global.network.as_deref().filter(|s| !s.is_empty());
    let dir = nodeconfig::default_node_config_dir(network)?;
    set_at(&dir, key, value)
}

fn set_at(dir: &Path, key: &str, value: &str) -> anyhow::Result<()> {
    let mut cfg = nodeconfig::load_existing_node_config(dir, false)?;

    match key {
        "p2p.listenMultiaddr" => cfg.p2p.listen_multiaddr = value.to_string(),
        "listenGrpcMultiaddr" => cfg.listen_grpc_multiaddr = value.to_string(),
        other => {
            anyhow::bail!(
                "Unsupported configuration key: {other}\nSupported keys: p2p.listenMultiaddr, listenGrpcMultiaddr"
            );
        }
    }

    quil_config::save_config(dir, &cfg).map_err(|e| anyhow::anyhow!("save config: {e}"))?;
    println!("Successfully updated {key} to {value} in {}", dir.display());
    Ok(())
}

fn clean(global: GlobalArgs, dry_run: bool) -> anyhow::Result<()> {
    let network = global.network.as_deref().filter(|s| !s.is_empty());
    let dir = nodeconfig::default_node_config_dir(network)?;
    let (path, outcome) = clean_config_file(&dir.join("config.yml"), dry_run)?;
    let lines = |keys: &[quil_config::CleanedKey]| {
        for key in keys {
            match key.last_line - key.first_line {
                0 => println!("  {} (line {})", key.path, key.first_line),
                _ => println!(
                    "  {} (lines {}-{})",
                    key.path, key.first_line, key.last_line
                ),
            }
        }
    };
    match outcome {
        CleanOutcome::NothingToClean => println!("Nothing to clean in {}", path.display()),
        CleanOutcome::DryRun(keys) => {
            println!("Would comment out {} obsolete settings:", keys.len());
            lines(&keys);
            println!("Dry run: {} is unchanged", path.display());
        }
        CleanOutcome::Cleaned { keys, backup } => {
            println!("Commented out {} obsolete settings:", keys.len());
            lines(&keys);
            println!(
                "Updated {}; the original is in {}",
                path.display(),
                backup.display()
            );
        }
    }
    Ok(())
}

/// What `clean` did to a config file.
#[derive(Debug, PartialEq, Eq)]
enum CleanOutcome {
    NothingToClean,
    DryRun(Vec<quil_config::CleanedKey>),
    Cleaned {
        keys: Vec<quil_config::CleanedKey>,
        backup: PathBuf,
    },
}

/// Comment out the retired settings of the config file at `path` (a
/// symlink is followed): back it up, replace it atomically with the
/// verified result, verify the written file again and restore the backup
/// if that fails. Returns the resolved path and the outcome.
fn clean_config_file(path: &Path, dry_run: bool) -> anyhow::Result<(PathBuf, CleanOutcome)> {
    let path = std::fs::canonicalize(path).with_context(|| format!("find {}", path.display()))?;
    let original =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let cleaned = quil_config::clean_retired_keys(&original)
        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
    if cleaned.keys.is_empty() {
        return Ok((path, CleanOutcome::NothingToClean));
    }
    if dry_run {
        return Ok((path, CleanOutcome::DryRun(cleaned.keys)));
    }
    // The config holds private keys: the backup and the replacement are
    // readable by its owner only, also when the original was not.
    let permissions = owner_only(std::fs::metadata(&path)?.permissions());
    let backup = write_backup(&path, &original, &permissions)?;
    replace_file(&path, &cleaned.contents, &permissions)?;
    let removed: Vec<String> = cleaned.keys.iter().map(|key| key.path.clone()).collect();
    let written = std::fs::read_to_string(&path).unwrap_or_default();
    if let Err(e) = quil_config::verify_cleaned(&original, &written, &removed) {
        let saved = std::fs::read_to_string(&backup)
            .with_context(|| format!("read {}", backup.display()))?;
        replace_file(&path, &saved, &permissions)?;
        anyhow::bail!(
            "{}: {e}; restored it from {}",
            path.display(),
            backup.display()
        );
    }
    Ok((
        path,
        CleanOutcome::Cleaned {
            keys: cleaned.keys,
            backup,
        },
    ))
}

/// `permissions` without any access for group and others.
pub(super) fn owner_only(permissions: std::fs::Permissions) -> std::fs::Permissions {
    #[cfg(unix)]
    let permissions = {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::Permissions::from_mode(permissions.mode() & 0o700)
    };
    permissions
}

/// Write `contents` to the first free of `<file>.bak`, `<file>.bak.1`, …
/// beside `path`, with the given permissions.
fn write_backup(
    path: &Path,
    contents: &str,
    permissions: &std::fs::Permissions,
) -> anyhow::Result<PathBuf> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config.yml".into());
    for n in 0..100 {
        let backup = path.with_file_name(if n == 0 {
            format!("{name}.bak")
        } else {
            format!("{name}.bak.{n}")
        });
        match new_private_file(&backup) {
            Ok(mut file) => {
                file.write_all(contents.as_bytes())
                    .and_then(|()| file.sync_all())
                    .and_then(|()| std::fs::set_permissions(&backup, permissions.clone()))
                    .with_context(|| {
                        format!("write backup {}; nothing changed", backup.display())
                    })?;
                return Ok(backup);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("create backup {}; nothing changed", backup.display())
                })
            }
        }
    }
    anyhow::bail!(
        "no free backup name beside {}; nothing changed",
        path.display()
    )
}

/// Replace `path` atomically: write a temporary file beside it with the
/// given permissions, then rename it over `path`.
pub(super) fn replace_file(
    path: &Path,
    contents: &str,
    permissions: &std::fs::Permissions,
) -> anyhow::Result<()> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp = path.with_file_name(format!(".{name}.clean-{}.tmp", std::process::id()));
    let written = new_private_file(&temp).and_then(|mut file| {
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        std::fs::set_permissions(&temp, permissions.clone())?;
        std::fs::rename(&temp, path)
    });
    if let Err(e) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(e).with_context(|| format!("replace {}", path.display()));
    }
    Ok(())
}

/// Create a new file readable by its owner only, failing if it exists.
fn new_private_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    mod identity {
        use super::*;

        /// The config home under `home`, as qclient lays it out.
        fn configs(home: &Path) -> PathBuf {
            home.join(".quilibrium").join("configs")
        }

        fn create_under(
            home: &Path,
            name: Option<&str>,
            set_default: bool,
        ) -> anyhow::Result<String> {
            create_in(&configs(home), name, set_default)
        }

        fn import_under(home: &Path, name: &str, source: &Path) -> anyhow::Result<String> {
            import_in(&configs(home), name, source.to_str().unwrap(), false)
        }

        fn set_under(dir: &Path, key: &str, value: &str) -> anyhow::Result<()> {
            set_at(dir, key, value)
        }

        /// `dir` as a node leaves it: a config with a peer key and a keystore
        /// with a prover key. Returns the prover's address in hex.
        fn node_config(dir: &Path) -> String {
            let mut config = quil_config::load_config(dir).unwrap();
            config.p2p.peer_priv_key = Ed448Identity::generate().unwrap().to_config_hex();
            quil_config::save_config(dir, &config).unwrap();
            let km = quil_keys::FileKeyManager::new(
                dir.join("keys.yml"),
                &config.key.key_store_file.encryption_key,
                "default-proving-key".into(),
                Box::new(quil_crypto::FalconKeyConstructor),
            )
            .unwrap();
            let public_key = km.create_falcon_key("q-prover-key").unwrap();
            hex::encode(quil_crypto::poseidon::hash_bytes_to_32(&public_key).unwrap())
        }

        /// A home whose `default` points at the config `old`, which holds keys.
        fn home_with_default_identity() -> (tempfile::TempDir, PathBuf, String) {
            let home = tempfile::tempdir().unwrap();
            let old = configs(home.path()).join("old");
            let address = node_config(&old);
            std::os::unix::fs::symlink(&old, configs(home.path()).join("default")).unwrap();
            (home, old, address)
        }

        fn default_target(home: &Path) -> PathBuf {
            std::fs::read_link(configs(home).join("default")).unwrap()
        }

        #[test]
        fn create_keeps_a_default_that_holds_an_identity() {
            let (home, old, _) = home_with_default_identity();

            create_under(home.path(), Some("other"), false).unwrap();

            let now = default_target(home.path());
            assert_eq!(
                now,
                old,
                "node config create moved default from a config holding keys to {}: a node \
                 started from it gets a new identity",
                now.display()
            );
            assert!(configs(home.path()).join("other/config.yml").is_file());
        }

        #[test]
        fn create_says_default_stays_and_how_to_switch() {
            let (home, old, address) = home_with_default_identity();

            let notice = create_under(home.path(), Some("other"), false).unwrap();

            assert!(notice.contains("default stays on"), "{notice}");
            let old = std::fs::canonicalize(old).unwrap();
            assert!(notice.contains(&old.display().to_string()), "{notice}");
            assert!(notice.contains(&tail(&address)), "{notice}");
            assert!(
                notice.contains("qclient node config switch other"),
                "{notice}"
            );
        }

        #[test]
        fn create_with_the_default_flag_moves_it_and_names_the_identity_change() {
            let (home, old, address) = home_with_default_identity();

            let notice = create_under(home.path(), Some("other"), true).unwrap();

            assert_eq!(
                default_target(home.path()),
                configs(home.path()).join("other")
            );
            assert!(notice.contains("changes identity"), "{notice}");
            assert!(notice.contains(&tail(&address)), "{notice}");
            let old = std::fs::canonicalize(old).unwrap();
            assert!(notice.contains(&old.display().to_string()), "{notice}");
            assert!(
                notice.contains("a new prover made at its first start"),
                "{notice}"
            );
        }

        #[test]
        fn create_points_default_at_the_new_config_when_it_holds_no_keys() {
            let home = tempfile::tempdir().unwrap();

            let first = create_under(home.path(), Some("first"), false).unwrap();
            assert_eq!(
                default_target(home.path()),
                configs(home.path()).join("first")
            );
            assert!(!first.contains("changes identity"), "{first}");

            let second = create_under(home.path(), Some("second"), false).unwrap();
            assert_eq!(
                default_target(home.path()),
                configs(home.path()).join("second")
            );
            assert!(!second.contains("changes identity"), "{second}");
        }

        #[test]
        fn create_refuses_a_directory_a_node_left_without_config() {
            let home = tempfile::tempdir().unwrap();
            let dir = configs(home.path()).join("lost");
            node_config(&dir);
            std::fs::remove_file(dir.join("config.yml")).unwrap();

            let err = create_under(home.path(), Some("lost"), false)
                .expect_err("a new config could not decrypt the keystore there")
                .to_string();

            assert!(err.contains("refusing to create a new config.yml"), "{err}");
            assert!(!dir.join("config.yml").exists());
        }

        #[test]
        fn create_on_an_existing_config_says_so_and_changes_nothing() {
            let (home, old, _) = home_with_default_identity();
            let config_before = std::fs::read(old.join("config.yml")).unwrap();

            let notice = create_under(home.path(), Some("old"), false).unwrap();

            assert!(notice.contains("already exists"), "{notice}");
            assert!(!notice.contains("changes identity"), "{notice}");
            assert_eq!(
                std::fs::read(old.join("config.yml")).unwrap(),
                config_before
            );
        }

        #[test]
        fn switch_names_the_identity_it_changes() {
            let (home, _, old_address) = home_with_default_identity();
            let new_address = node_config(&configs(home.path()).join("new"));

            let notice = switch_in(&configs(home.path()), "new").unwrap();

            assert_eq!(
                default_target(home.path()),
                configs(home.path()).join("new")
            );
            assert!(notice.contains("changes identity"), "{notice}");
            assert!(notice.contains(&tail(&old_address)), "{notice}");
            assert!(notice.contains(&tail(&new_address)), "{notice}");
        }

        #[test]
        fn switch_back_to_the_current_default_changes_no_identity() {
            let (home, _, _) = home_with_default_identity();
            let notice = switch_in(&configs(home.path()), "old").unwrap();
            assert_eq!(notice, "Default config set to old");
        }

        #[test]
        fn import_does_not_overwrite_a_config_that_holds_keys() {
            let (home, old, _) = home_with_default_identity();
            let keystore = std::fs::read(old.join("keys.yml")).unwrap();
            let source = tempfile::tempdir().unwrap();
            node_config(source.path());

            let outcome = import_under(home.path(), "old", source.path());

            assert!(
                std::fs::read(old.join("keys.yml")).unwrap() == keystore,
                "node config import overwrote the keystore of an existing config"
            );
            assert!(outcome.is_err());
        }

        #[test]
        fn set_writes_no_config_into_a_directory_without_one() {
            let dir = tempfile::tempdir().unwrap();

            let outcome = set_under(dir.path(), "p2p.listenMultiaddr", "/ip4/0.0.0.0/udp/8336");

            assert!(
                !dir.path().join("config.yml").exists(),
                "node config set wrote a new config, with a new identity, into a directory \
                 without one"
            );
            assert!(outcome.is_err());
        }
    }

    const RETIRED: &str = "p2p:\n  network: 1\n  d: 8\n  bootstrapPeer: x\nengine:\n  framePublish:\n    mode: full\n  archiveMode: true\n";

    fn config_in(dir: &Path, contents: &str) -> PathBuf {
        let path = dir.join("config.yml");
        std::fs::write(&path, contents).unwrap();
        path
    }

    /// A run backs up the original, comments out the retired settings
    /// keeping the file's owner permissions but none for group and others,
    /// and a second run finds nothing.
    #[test]
    fn clean_backs_up_and_comments_out_retired_settings() {
        let dir = tempfile::tempdir().unwrap();
        let path = config_in(dir.path(), RETIRED);
        #[cfg(unix)]
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o640))
            .unwrap();
        let (resolved, outcome) = clean_config_file(&path, false).unwrap();
        let (keys, backup) = match outcome {
            CleanOutcome::Cleaned { keys, backup } => (keys, backup),
            other => panic!("{other:?}"),
        };
        assert_eq!(
            keys.iter().map(|key| key.path.as_str()).collect::<Vec<_>>(),
            ["p2p.d", "engine.framePublish"]
        );
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), RETIRED);
        assert_eq!(backup, resolved.with_file_name("config.yml.bak"));
        let cleaned = std::fs::read_to_string(&resolved).unwrap();
        assert!(
            cleaned.contains("  # obsolete, no effect: d: 8\n  bootstrapPeer: x\n"),
            "{cleaned}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&resolved).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            clean_config_file(&path, false).unwrap().1,
            CleanOutcome::NothingToClean
        );
        let entries = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(entries, 2, "config.yml and its backup only");
    }

    /// A dry run and a refused config leave the file byte-identical and
    /// write no backup.
    #[test]
    fn dry_runs_and_refusals_write_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = config_in(dir.path(), RETIRED);
        let (_, outcome) = clean_config_file(&path, true).unwrap();
        assert!(
            matches!(&outcome, CleanOutcome::DryRun(keys) if keys.len() == 2),
            "{outcome:?}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), RETIRED);
        let refused = "p2p:\n  network: 1\n  d: &degree 8\n";
        std::fs::write(&path, refused).unwrap();
        let error = clean_config_file(&path, false).unwrap_err().to_string();
        assert!(error.contains("cannot safely change p2p.d"), "{error}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), refused);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    /// A symlinked config directory is followed: the target file is
    /// edited and backed up beside it, and an existing backup is kept.
    #[cfg(unix)]
    #[test]
    fn clean_follows_a_symlinked_config_dir() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("mainnet");
        std::fs::create_dir(&target).unwrap();
        config_in(&target, RETIRED);
        std::fs::write(target.join("config.yml.bak"), "older backup").unwrap();
        let link = dir.path().join("default");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let (resolved, outcome) = clean_config_file(&link.join("config.yml"), false).unwrap();
        assert_eq!(
            resolved,
            std::fs::canonicalize(target.join("config.yml")).unwrap()
        );
        let backup = match outcome {
            CleanOutcome::Cleaned { backup, .. } => backup,
            other => panic!("{other:?}"),
        };
        assert_eq!(backup, resolved.with_file_name("config.yml.bak.1"));
        assert_eq!(
            std::fs::read_to_string(target.join("config.yml.bak")).unwrap(),
            "older backup"
        );
        assert_eq!(std::fs::read_to_string(&backup).unwrap(), RETIRED);
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

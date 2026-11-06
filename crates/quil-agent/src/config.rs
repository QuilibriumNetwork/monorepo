//! Operator settings. Keys live in `~/.quilibrium/qagent.yaml` (mode 0600).
//!
//! Each key has a name. `qagent key issue <name>` adds one, and the request
//! log records that name. A missing full key or read-only key is created on
//! startup. `--api-key` replaces the first full key for this process only.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// How long a confirmation id can be submitted.
pub const CONFIRM_TTL: Duration = Duration::from_secs(10 * 60);

/// Default MCP listen address: this machine only.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8350";

/// Default fee slippage: 2%.
pub const DEFAULT_SLIPPAGE_BPS: u32 = 200;

/// Name of the full key created when the file has none.
pub const DEFAULT_FULL_KEY_NAME: &str = "operator";

/// Name of the read-only key created when the file has none.
pub const DEFAULT_READ_ONLY_KEY_NAME: &str = "read-only";

fn default_listen() -> String {
    DEFAULT_LISTEN.to_string()
}

fn default_slippage() -> u32 {
    DEFAULT_SLIPPAGE_BPS
}

fn default_max_fee() -> u64 {
    u64::try_from(quil_client::commands::token::DEFAULT_MAX_AUTOMATIC_FEE).unwrap_or(u64::MAX)
}

/// What a key is allowed to call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyAccess {
    /// May ask for a quote. The quote is approved on this computer.
    Full,
    /// `node_info` and `balance` only.
    ReadOnly,
}

impl KeyAccess {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::ReadOnly => "read-only",
        }
    }
}

impl std::fmt::Display for KeyAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A named API key. The log records `name`, never `secret`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKey {
    pub name: String,
    pub secret: String,
    pub access: KeyAccess,
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKey")
            .field("name", &self.name)
            .field("access", &self.access)
            .finish_non_exhaustive()
    }
}

impl ApiKey {
    pub fn new(name: impl Into<String>, secret: impl Into<String>, access: KeyAccess) -> Self {
        Self {
            name: name.into(),
            secret: secret.into(),
            access,
        }
    }
}

/// What `qagent` was started with.
#[derive(Clone)]
pub struct Settings {
    pub listen: String,
    pub keys: Vec<ApiKey>,
    pub fee_slippage_bps: u32,
    pub max_fee: u128,
    /// Node config directory, as `qclient --config`. Empty selects the default.
    pub node_config: String,
    pub network: Option<String>,
    pub config_path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileSettings {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default)]
    keys: Vec<ApiKey>,
    /// Previous single full key. Folded into `keys` and not written back.
    #[serde(default, skip_serializing)]
    api_key: String,
    /// Previous single read-only key. Folded into `keys` and not written back.
    #[serde(default, skip_serializing)]
    read_only_api_key: String,
    #[serde(default = "default_slippage")]
    fee_slippage_bps: u32,
    #[serde(default = "default_max_fee")]
    max_fee: u64,
    #[serde(default)]
    node_config: String,
    #[serde(default)]
    network: String,
}

/// Flags that override the file. Empty options leave the file's value.
#[derive(Debug, Default)]
pub struct Overrides {
    pub listen: Option<String>,
    pub api_key: Option<String>,
    pub fee_slippage_bps: Option<u32>,
    pub max_fee: Option<u64>,
    pub node_config: Option<String>,
    pub network: Option<String>,
}

impl Settings {
    /// Load `path`, creating named keys when the file or either access is missing.
    pub fn load(path: &Path, overrides: &Overrides) -> anyhow::Result<Self> {
        let mut file = read_normalized(path)?;
        if let Some(secret) = overrides
            .api_key
            .clone()
            .filter(|secret| !secret.is_empty())
        {
            if let Some(key) = file
                .keys
                .iter_mut()
                .find(|key| key.access == KeyAccess::Full)
            {
                key.secret = secret;
            }
        }
        let fee_slippage_bps = overrides.fee_slippage_bps.unwrap_or(file.fee_slippage_bps);
        anyhow::ensure!(
            fee_slippage_bps <= 10_000,
            "fee slippage is {fee_slippage_bps} basis points; the maximum is 10000 (100%)"
        );
        anyhow::ensure!(
            file.keys
                .iter()
                .any(|key| key.access == KeyAccess::Full && !key.secret.is_empty()),
            "qagent requires an API key"
        );
        let network = overrides
            .network
            .clone()
            .or_else(|| Some(file.network))
            .filter(|network| !network.is_empty());
        Ok(Self {
            listen: overrides.listen.clone().unwrap_or(file.listen),
            keys: file.keys,
            fee_slippage_bps,
            max_fee: u128::from(overrides.max_fee.unwrap_or(file.max_fee)),
            node_config: overrides.node_config.clone().unwrap_or(file.node_config),
            network,
            config_path: path.to_path_buf(),
        })
    }

    /// The first full key stored in the file, for `--print-api-key`.
    ///
    /// Loading first creates a missing key. A `--api-key` override for this
    /// process is not printed.
    pub fn reveal_key(path: &Path) -> anyhow::Result<String> {
        secret_of(path, KeyAccess::Full)
    }

    /// The first read-only key stored in the file, for `--print-read-only-api-key`.
    ///
    /// Loading first creates the key when the file does not have one.
    pub fn reveal_read_only_key(path: &Path) -> anyhow::Result<String> {
        secret_of(path, KeyAccess::ReadOnly)
    }

    /// Add a key. The name is stored and later written to the request log.
    pub fn issue_key(path: &Path, name: &str, access: KeyAccess) -> anyhow::Result<ApiKey> {
        let name = validate_key_name(name)?;
        let mut file = read_normalized(path)?;
        anyhow::ensure!(
            file.keys.iter().all(|key| key.name != name),
            "an API key named \"{name}\" already exists"
        );
        let key = ApiKey::new(name, distinct_secret(&file.keys), access);
        file.keys.push(key.clone());
        write_private(path, &serde_yaml::to_string(&file)?)?;
        Ok(key)
    }

    /// Names and access of every key. Secrets stay in the file.
    pub fn list_keys(path: &Path) -> anyhow::Result<Vec<ApiKey>> {
        Ok(read_normalized(path)?.keys)
    }

    /// Remove every key with this name.
    ///
    /// The next start creates a new `operator` or `read-only` key when that
    /// access no longer has one.
    pub fn revoke_key(path: &Path, name: &str) -> anyhow::Result<()> {
        let name = name.trim();
        anyhow::ensure!(!name.is_empty(), "a key name is required");
        let mut file = read_normalized(path)?;
        let before = file.keys.len();
        file.keys.retain(|key| key.name != name);
        anyhow::ensure!(file.keys.len() < before, "no API key named \"{name}\"");
        write_private(path, &serde_yaml::to_string(&file)?)?;
        Ok(())
    }
}

fn secret_of(path: &Path, access: KeyAccess) -> anyhow::Result<String> {
    read_normalized(path)?
        .keys
        .into_iter()
        .find(|key| key.access == access)
        .map(|key| key.secret)
        .with_context(|| format!("no {access} API key"))
}

/// Load the file, fold older `apiKey` fields into named keys, and create a
/// full key and a read-only key when either access is missing.
fn read_normalized(path: &Path) -> anyhow::Result<FileSettings> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let existed = path.is_file();
    let mut file = if existed {
        let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        serde_yaml::from_str::<FileSettings>(&text)
            .with_context(|| format!("parse {}", path.display()))?
    } else {
        FileSettings {
            listen: default_listen(),
            keys: Vec::new(),
            api_key: String::new(),
            read_only_api_key: String::new(),
            fee_slippage_bps: default_slippage(),
            max_fee: default_max_fee(),
            node_config: String::new(),
            network: String::new(),
        }
    };
    let changed = normalize(&mut file);
    if !existed || changed {
        write_private(path, &serde_yaml::to_string(&file)?)?;
    }
    Ok(file)
}

fn normalize(file: &mut FileSettings) -> bool {
    let mut changed = false;
    if !file.api_key.is_empty() {
        insert_secret(
            &mut file.keys,
            file.api_key.clone(),
            KeyAccess::Full,
            DEFAULT_FULL_KEY_NAME,
        );
        file.api_key.clear();
        changed = true;
    }
    if !file.read_only_api_key.is_empty() {
        insert_secret(
            &mut file.keys,
            file.read_only_api_key.clone(),
            KeyAccess::ReadOnly,
            DEFAULT_READ_ONLY_KEY_NAME,
        );
        file.read_only_api_key.clear();
        changed = true;
    }
    changed |= ensure_access(&mut file.keys, KeyAccess::Full, DEFAULT_FULL_KEY_NAME);
    changed |= ensure_access(
        &mut file.keys,
        KeyAccess::ReadOnly,
        DEFAULT_READ_ONLY_KEY_NAME,
    );
    changed
}

fn insert_secret(keys: &mut Vec<ApiKey>, secret: String, access: KeyAccess, default_name: &str) {
    if secret.is_empty() || keys.iter().any(|key| key.secret == secret) {
        return;
    }
    let name = unused_name(keys, default_name);
    keys.push(ApiKey::new(name, secret, access));
}

fn ensure_access(keys: &mut Vec<ApiKey>, access: KeyAccess, default_name: &str) -> bool {
    if let Some(index) = keys.iter().position(|key| key.access == access) {
        let mut changed = false;
        if keys[index].name.trim().is_empty() {
            let name = unused_name(keys, default_name);
            keys[index].name = name;
            changed = true;
        }
        if keys[index].secret.is_empty() {
            let secret = distinct_secret(keys);
            keys[index].secret = secret;
            changed = true;
        }
        return changed;
    }
    let name = unused_name(keys, default_name);
    let secret = distinct_secret(keys);
    keys.push(ApiKey::new(name, secret, access));
    true
}

fn unused_name(keys: &[ApiKey], base: &str) -> String {
    if keys.iter().all(|key| key.name != base) {
        return base.to_string();
    }
    let mut suffix = 2u32;
    loop {
        let candidate = format!("{base}-{suffix}");
        if keys.iter().all(|key| key.name != candidate) {
            return candidate;
        }
        suffix += 1;
    }
}

fn distinct_secret(keys: &[ApiKey]) -> String {
    loop {
        let secret = random_hex(32);
        if keys.iter().all(|key| key.secret != secret) {
            return secret;
        }
    }
}

fn validate_key_name(name: &str) -> anyhow::Result<String> {
    let name = name.trim();
    anyhow::ensure!(!name.is_empty(), "a key name is required");
    anyhow::ensure!(name.len() <= 64, "key name is longer than 64 characters");
    anyhow::ensure!(
        name.chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')),
        "a key name uses letters, digits, '.', '_', or '-'"
    );
    Ok(name.to_string())
}

/// True when `listen` is not a loopback address.
pub fn listens_beyond_loopback(listen: &str) -> bool {
    let host = listen
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(listen);
    let host = host.trim_matches(|ch| ch == '[' || ch == ']');
    !matches!(host, "127.0.0.1" | "localhost" | "::1")
}

pub fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buffer);
    hex::encode(buffer)
}

fn write_private(path: &Path, text: &str) -> anyhow::Result<()> {
    fs::write(path, text).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restrict {}", path.display()))?;
    }
    Ok(())
}

/// `~/.quilibrium/qagent.yaml`.
pub fn default_path() -> anyhow::Result<PathBuf> {
    Ok(quil_client::system::user_quilibrium_dir()?.join("qagent.yaml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn by_access(settings: &Settings, access: KeyAccess) -> &ApiKey {
        settings
            .keys
            .iter()
            .find(|key| key.access == access)
            .unwrap()
    }

    #[test]
    fn a_missing_file_is_created_with_named_private_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qagent.yaml");
        let settings = Settings::load(&path, &Overrides::default()).unwrap();
        assert_eq!(settings.listen, DEFAULT_LISTEN);
        assert_eq!(settings.fee_slippage_bps, DEFAULT_SLIPPAGE_BPS);
        let full = by_access(&settings, KeyAccess::Full);
        let read_only = by_access(&settings, KeyAccess::ReadOnly);
        assert_eq!(full.name, DEFAULT_FULL_KEY_NAME);
        assert_eq!(read_only.name, DEFAULT_READ_ONLY_KEY_NAME);
        assert_eq!(full.secret.len(), 64);
        assert_eq!(read_only.secret.len(), 64);
        assert_ne!(full.secret, read_only.secret);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let again = Settings::load(&path, &Overrides::default()).unwrap();
        assert_eq!(by_access(&again, KeyAccess::Full).secret, full.secret);
        assert_eq!(Settings::reveal_key(&path).unwrap(), full.secret);
        assert_eq!(
            Settings::reveal_read_only_key(&path).unwrap(),
            read_only.secret
        );
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("apiKey:"));
    }

    #[test]
    fn a_file_without_a_read_only_key_gains_a_named_one_and_keeps_its_full_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qagent.yaml");
        fs::write(&path, "apiKey: existing-full-key\nlisten: 127.0.0.1:8350\n").unwrap();
        let settings = Settings::load(&path, &Overrides::default()).unwrap();
        let full = by_access(&settings, KeyAccess::Full);
        let read_only = by_access(&settings, KeyAccess::ReadOnly);
        assert_eq!(full.name, DEFAULT_FULL_KEY_NAME);
        assert_eq!(full.secret, "existing-full-key");
        assert_eq!(read_only.name, DEFAULT_READ_ONLY_KEY_NAME);
        assert_eq!(read_only.secret.len(), 64);
        assert_ne!(read_only.secret, "existing-full-key");
        let again = Settings::load(&path, &Overrides::default()).unwrap();
        assert_eq!(
            by_access(&again, KeyAccess::ReadOnly).secret,
            read_only.secret
        );
        assert_eq!(
            by_access(&again, KeyAccess::Full).secret,
            "existing-full-key"
        );
    }

    #[test]
    fn an_issued_key_keeps_the_name_it_was_given() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qagent.yaml");
        let issued = Settings::issue_key(&path, "laptop", KeyAccess::Full).unwrap();
        assert_eq!(issued.name, "laptop");
        assert_eq!(issued.access, KeyAccess::Full);
        assert_eq!(issued.secret.len(), 64);
        let listed = Settings::list_keys(&path).unwrap();
        assert!(listed
            .iter()
            .any(|key| key.name == "laptop" && key.secret == issued.secret));
        assert!(listed.iter().any(|key| key.name == DEFAULT_FULL_KEY_NAME));
        let error = Settings::issue_key(&path, "laptop", KeyAccess::ReadOnly).unwrap_err();
        assert!(error.to_string().contains("already exists"));
        assert!(Settings::issue_key(&path, "bad name", KeyAccess::Full).is_err());
        Settings::revoke_key(&path, "laptop").unwrap();
        let listed = Settings::list_keys(&path).unwrap();
        assert!(listed.iter().all(|key| key.name != "laptop"));
        assert!(Settings::revoke_key(&path, "laptop").is_err());
    }

    #[test]
    fn flags_override_the_file_and_slippage_above_100_percent_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qagent.yaml");
        let settings = Settings::load(
            &path,
            &Overrides {
                listen: Some("0.0.0.0:9000".into()),
                api_key: Some("override-key".into()),
                fee_slippage_bps: Some(50),
                max_fee: Some(10),
                node_config: Some("/tmp/node".into()),
                network: Some("devnet".into()),
            },
        )
        .unwrap();
        assert_eq!(settings.listen, "0.0.0.0:9000");
        assert_eq!(by_access(&settings, KeyAccess::Full).secret, "override-key");
        assert_eq!(
            by_access(&settings, KeyAccess::Full).name,
            DEFAULT_FULL_KEY_NAME
        );
        assert_eq!(settings.fee_slippage_bps, 50);
        assert_eq!(settings.max_fee, 10);
        assert_eq!(settings.node_config, "/tmp/node");
        assert_eq!(settings.network.as_deref(), Some("devnet"));
        // The file keeps its own key; the override is this process only.
        let file_key = Settings::reveal_key(&path).unwrap();
        assert_ne!(file_key, "override-key");
        let error = Settings::load(
            &path,
            &Overrides {
                fee_slippage_bps: Some(10_001),
                ..Overrides::default()
            },
        );
        assert!(error.is_err());
    }

    #[test]
    fn loopback_is_not_exposed() {
        assert!(!listens_beyond_loopback("127.0.0.1:8350"));
        assert!(!listens_beyond_loopback("[::1]:8350"));
        assert!(listens_beyond_loopback("0.0.0.0:8350"));
    }
}

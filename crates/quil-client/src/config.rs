//! Client-side configuration (`~/.quilibrium/qclient-config.yaml`).
//!
//! Port of `client/utils/types.go` (`ClientConfig`) and
//! `client/utils/clientConfig.go` (load/save/create-default).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::system;

/// `client/utils/types.go:3` — the qclient config, serialized as YAML with
/// camelCase keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientConfig {
    #[serde(rename = "dataDir", default)]
    pub data_dir: String,
    #[serde(rename = "symlinkPath", default)]
    pub symlink_path: String,
    #[serde(rename = "publicRpc", default)]
    pub public_rpc: bool,
    #[serde(rename = "customRpc", default)]
    pub custom_rpc: String,
    #[serde(rename = "nodeSymlinkName", default)]
    pub node_symlink_name: String,
    /// `noActionLog: true` turns off the private action log of wallet
    /// actions (`<node config dir>/wallet/actions.jsonl`); written only
    /// when set.
    #[serde(
        rename = "noActionLog",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub no_action_log: bool,
}

impl ClientConfig {
    /// The default written by `CreateDefaultConfig`
    /// (`client/utils/clientConfig.go:15`).
    pub fn default_for_create() -> Self {
        Self {
            data_dir: system::client_data_path().to_string_lossy().into_owned(),
            symlink_path: system::default_qclient_symlink_path()
                .to_string_lossy()
                .into_owned(),
            public_rpc: false,
            custom_rpc: String::new(),
            node_symlink_name: String::new(),
            no_action_log: false,
        }
    }

    /// The default auto-created by `LoadClientConfig` when the file is
    /// missing (`client/utils/clientConfig.go:37`). Differs from
    /// `default_for_create` only in `symlink_path` (`<dataDir>/current`).
    fn default_for_load() -> Self {
        Self {
            symlink_path: system::client_data_path()
                .join("current")
                .to_string_lossy()
                .into_owned(),
            ..Self::default_for_create()
        }
    }
}

/// `~/.quilibrium/qclient-config.yaml` (`client/utils/client.go`).
pub fn config_path() -> anyhow::Result<PathBuf> {
    Ok(
        system::user_quilibrium_dir()?
            .join(format!("{}-config.yaml", system::RELEASE_TYPE_QCLIENT)),
    )
}

/// `~/.quilibrium` (`GetConfigDir`).
pub fn config_dir() -> anyhow::Result<PathBuf> {
    system::user_quilibrium_dir()
}

/// Load the client config, auto-creating a default if the file is missing.
/// Port of `LoadClientConfig` (`client/utils/clientConfig.go:31`).
pub fn load() -> anyhow::Result<ClientConfig> {
    let path = config_path()?;
    if !path.exists() {
        let cfg = ClientConfig::default_for_load();
        save(&cfg)?;
        return Ok(cfg);
    }
    let data = std::fs::read_to_string(&path)?;
    let cfg: ClientConfig = serde_yaml::from_str(&data)?;
    Ok(cfg)
}

/// Save the client config (0644 after ensuring the dir exists at 0755).
/// Port of `SaveClientConfig`.
pub fn save(cfg: &ClientConfig) -> anyhow::Result<()> {
    let dir = config_dir()?;
    std::fs::create_dir_all(&dir)?;
    let data = serde_yaml::to_string(cfg)?;
    std::fs::write(config_path()?, data)?;
    Ok(())
}

/// Write the create-default config. Port of `CreateDefaultConfig`.
pub fn create_default() -> anyhow::Result<()> {
    let path = config_path()?;
    println!("Creating default config: {}", path.display());
    save(&ClientConfig::default_for_create())
}

/// Whether the qclient config turns the private action log off; read
/// without creating the file.
pub fn action_log_off() -> bool {
    config_path()
        .ok()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|data| serde_yaml::from_str::<ClientConfig>(&data).ok())
        .is_some_and(|cfg| cfg.no_action_log)
}

/// Whether the client config file exists.
pub fn is_configured() -> bool {
    config_path().map(|p| p.exists()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_yaml_with_camelcase_keys() {
        let cfg = ClientConfig::default_for_create();
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        assert!(yaml.contains("dataDir:"));
        assert!(!yaml.contains("signatureCheck"));
        assert!(yaml.contains("publicRpc: false"));
        assert!(!yaml.contains("noActionLog"), "{yaml}");
        let back: ClientConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(cfg, back);
        let off = ClientConfig {
            no_action_log: true,
            ..cfg
        };
        let yaml = serde_yaml::to_string(&off).unwrap();
        assert!(yaml.contains("noActionLog: true"), "{yaml}");
        assert_eq!(serde_yaml::from_str::<ClientConfig>(&yaml).unwrap(), off);
    }

    #[test]
    fn parses_go_written_yaml() {
        // A config as the Go client would emit it. Its signatureCheck key,
        // which nothing reads, is ignored.
        let go_yaml = "dataDir: /var/quilibrium/bin/qclient\n\
                       symlinkPath: /usr/local/bin/qclient\n\
                       signatureCheck: true\n\
                       publicRpc: true\n\
                       customRpc: \"example.com:8337\"\n\
                       nodeSymlinkName: \"\"\n";
        let cfg: ClientConfig = serde_yaml::from_str(go_yaml).unwrap();
        assert!(cfg.public_rpc);
        assert_eq!(cfg.custom_rpc, "example.com:8337");
    }

    #[test]
    fn missing_fields_default_sensibly() {
        // Partial config still loads.
        let cfg: ClientConfig = serde_yaml::from_str("publicRpc: true\n").unwrap();
        assert!(cfg.public_rpc);
        assert!(cfg.custom_rpc.is_empty());
    }
}

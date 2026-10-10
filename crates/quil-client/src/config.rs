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
    #[serde(rename = "signatureCheck", default = "default_true")]
    pub signature_check: bool,
    #[serde(rename = "publicRpc", default)]
    pub public_rpc: bool,
    #[serde(rename = "customRpc", default)]
    pub custom_rpc: String,
    #[serde(rename = "nodeSymlinkName", default)]
    pub node_symlink_name: String,
}

fn default_true() -> bool {
    true
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
            signature_check: true,
            public_rpc: false,
            custom_rpc: String::new(),
            node_symlink_name: String::new(),
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
    Ok(system::user_quilibrium_dir()?.join(format!("{}-config.yaml", system::RELEASE_TYPE_QCLIENT)))
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
        assert!(yaml.contains("signatureCheck: true"));
        assert!(yaml.contains("publicRpc: false"));
        let back: ClientConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn parses_go_written_yaml() {
        // A config as the Go client would emit it.
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
        // Partial config still loads; signatureCheck defaults to true.
        let cfg: ClientConfig = serde_yaml::from_str("publicRpc: true\n").unwrap();
        assert!(cfg.signature_check);
        assert!(cfg.public_rpc);
        assert!(cfg.custom_rpc.is_empty());
    }
}

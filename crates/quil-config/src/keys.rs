use serde::{Deserialize, Serialize};

/// The node's file key store (`keys.yml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyStoreFileConfig {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub create_if_missing: bool,
    #[serde(default)]
    pub encryption_key: String,
}

impl Default for KeyStoreFileConfig {
    fn default() -> Self {
        Self {
            path: String::new(),
            create_if_missing: true,
            encryption_key: String::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyConfig {
    #[serde(default, rename = "keyManagerFile")]
    pub key_store_file: KeyStoreFileConfig,
}

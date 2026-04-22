use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[repr(i32)]
pub enum KeyManagerType {
    #[serde(alias = "inmemory", alias = "inMemory")]
    InMemory = 0,
    #[serde(alias = "file")]
    File = 1,
}

impl Default for KeyManagerType {
    fn default() -> Self {
        Self::File
    }
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyConfig {
    #[serde(default, rename = "keyManagerType")]
    pub key_store: KeyManagerType,
    #[serde(default, rename = "keyManagerFile")]
    pub key_store_file: KeyStoreFileConfig,
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            key_store: KeyManagerType::File,
            key_store_file: KeyStoreFileConfig::default(),
        }
    }
}

use serde::{Deserialize, Serialize};

use crate::{DbConfig, EngineConfig, KeyConfig, LogConfig, P2PConfig};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(default)]
    pub key: KeyConfig,
    #[serde(default)]
    pub p2p: P2PConfig,
    #[serde(default)]
    pub engine: EngineConfig,
    #[serde(default)]
    pub db: DbConfig,
    #[serde(default, deserialize_with = "crate::deserialize_null_default")]
    pub logger: LogConfig,
    #[serde(default, alias = "listenGRPCMultiaddr")]
    pub listen_grpc_multiaddr: String,
    #[serde(default, rename = "listenRESTMultiaddr")]
    pub listen_rest_multiaddr: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            key: KeyConfig::default(),
            p2p: P2PConfig::default(),
            engine: EngineConfig::default(),
            db: DbConfig::default(),
            logger: LogConfig::default(),
            listen_grpc_multiaddr: String::new(),
            listen_rest_multiaddr: String::new(),
        }
    }
}

impl Config {
    /// Apply defaults to all sub-configs (mirrors Go's WithDefaults pattern).
    pub fn apply_defaults(&mut self) {
        self.p2p.apply_defaults();
        self.engine.apply_defaults();
        self.db.apply_defaults();
    }
}

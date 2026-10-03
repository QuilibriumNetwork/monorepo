use serde::{Deserialize, Serialize};

use crate::{DbConfig, EngineConfig, ExplorerConfig, KeyConfig, LogConfig, P2PConfig, ProofWorkerConfig};

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
    #[serde(default)]
    pub explorer: ExplorerConfig,
    /// Token proof verifier worker (operator-tunable resource
    /// limits and executable path; the network policy itself is compiled in).
    #[serde(default, deserialize_with = "crate::deserialize_null_default")]
    pub proof_worker: ProofWorkerConfig,
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
            explorer: ExplorerConfig::default(),
            proof_worker: ProofWorkerConfig::default(),
        }
    }
}

impl Config {
    /// Apply defaults to all sub-configs (mirrors Go's WithDefaults pattern).
    pub fn apply_defaults(&mut self) {
        self.p2p.apply_defaults();
        self.engine.apply_defaults();
        self.db.apply_defaults();
        self.explorer.apply_defaults();
        self.proof_worker.apply_defaults();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_worker_section_defaults_when_absent_and_round_trips() {
        let mut absent: Config = serde_yaml::from_str("p2p:\n  network: 1\n").unwrap();
        absent.apply_defaults();
        assert_eq!(absent.proof_worker, ProofWorkerConfig::default());
        let mut null: Config = serde_yaml::from_str("proofWorker: null\n").unwrap();
        null.apply_defaults();
        assert_eq!(null.proof_worker, ProofWorkerConfig::default());
        let explicit: Config = serde_yaml::from_str(
            "proofWorker:\n  path: /opt/quil/quil-amount-proof-worker\n  cpuSeconds: 900\n  wallTimeoutSecs: 1200\n  disabled: true\n",
        )
        .unwrap();
        assert_eq!(explicit.proof_worker.path, "/opt/quil/quil-amount-proof-worker");
        assert_eq!((explicit.proof_worker.cpu_seconds, explicit.proof_worker.wall_timeout_secs), (900, 1200));
        assert!(explicit.proof_worker.disabled);
        let encoded = serde_yaml::to_string(&explicit).unwrap();
        assert!(encoded.contains("proofWorker:"));
        let decoded: Config = serde_yaml::from_str(&encoded).unwrap();
        assert_eq!(decoded.proof_worker, explicit.proof_worker);
    }
}

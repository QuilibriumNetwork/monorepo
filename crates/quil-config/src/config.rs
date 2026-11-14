use serde::{Deserialize, Serialize};

use crate::{
    DbConfig, DiagnosticsConfig, EngineConfig, ExplorerConfig, KeyConfig, LogConfig, P2PConfig,
    ProofWorkerConfig,
};

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
    /// Serve NodeService on a `listenGrpcMultiaddr` that is not a loopback
    /// address. NodeService authenticates no caller and lets any of them
    /// steer the node's provers (joins, leaves, manual management) and read
    /// its state, so without this the node serves it on loopback only.
    #[serde(default)]
    pub listen_grpc_allow_remote: bool,
    #[serde(default)]
    pub explorer: ExplorerConfig,
    /// Token proof verifier worker (operator-tunable resource
    /// limits and executable path; the network policy itself is compiled in).
    #[serde(default, deserialize_with = "crate::deserialize_null_default")]
    pub proof_worker: ProofWorkerConfig,
    /// Opt-in diagnostics served to peers this node names; off by default.
    #[serde(default, deserialize_with = "crate::deserialize_null_default")]
    pub diagnostics: DiagnosticsConfig,
}

/// The gRPC listener a node binds when `listenGrpcMultiaddr` is empty: local
/// only, since NodeService serves unauthenticated control RPCs.
pub const DEFAULT_LISTEN_GRPC_MULTIADDR: &str = "/ip4/127.0.0.1/tcp/8337";

impl Config {
    /// The gRPC listener the node binds: the configured multiaddr, or
    /// [`DEFAULT_LISTEN_GRPC_MULTIADDR`] when it is empty.
    pub fn effective_listen_grpc_multiaddr(&self) -> &str {
        if self.listen_grpc_multiaddr.is_empty() {
            DEFAULT_LISTEN_GRPC_MULTIADDR
        } else {
            &self.listen_grpc_multiaddr
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            key: KeyConfig::default(),
            p2p: P2PConfig::default(),
            engine: EngineConfig::default(),
            db: DbConfig::default(),
            logger: LogConfig::default(),
            listen_grpc_multiaddr: DEFAULT_LISTEN_GRPC_MULTIADDR.to_string(),
            listen_grpc_allow_remote: false,
            explorer: ExplorerConfig::default(),
            proof_worker: ProofWorkerConfig::default(),
            diagnostics: DiagnosticsConfig::default(),
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
        self.diagnostics.apply_defaults();
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
        assert_eq!(
            explicit.proof_worker.path,
            "/opt/quil/quil-amount-proof-worker"
        );
        assert_eq!(
            (
                explicit.proof_worker.cpu_seconds,
                explicit.proof_worker.wall_timeout_secs
            ),
            (900, 1200)
        );
        assert!(explicit.proof_worker.disabled);
        let encoded = serde_yaml::to_string(&explicit).unwrap();
        assert!(encoded.contains("proofWorker:"));
        let decoded: Config = serde_yaml::from_str(&encoded).unwrap();
        assert_eq!(decoded.proof_worker, explicit.proof_worker);
    }

    #[test]
    fn diagnostics_are_off_unless_configured_and_their_interval_is_clamped() {
        for yaml in [
            "p2p:\n  network: 1\n",
            "diagnostics: null\n",
            "diagnostics:\n  healthReport: null\n",
        ] {
            let mut config: Config = serde_yaml::from_str(yaml).unwrap();
            config.apply_defaults();
            assert_eq!(config.diagnostics, DiagnosticsConfig::default(), "{yaml}");
            assert!(!config.diagnostics.health_report.enabled);
        }
        assert!(!Config::default().diagnostics.health_report.enabled);
        let mut config: Config = serde_yaml::from_str(
            "diagnostics:\n  healthReport:\n    enabled: true\n    allowedPeers: [QmPeer]\n    minIntervalSecs: 1\n",
        )
        .unwrap();
        config.apply_defaults();
        let report = &config.diagnostics.health_report;
        assert!(report.enabled);
        assert_eq!(
            (report.allowed_peers.as_slice(), report.min_interval_secs),
            (["QmPeer".to_string()].as_slice(), 10)
        );
        let decoded: Config =
            serde_yaml::from_str(&serde_yaml::to_string(&config).unwrap()).unwrap();
        assert_eq!(decoded.diagnostics, config.diagnostics);
    }
}

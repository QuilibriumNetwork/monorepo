use serde::{Deserialize, Serialize};

/// Configuration for the in-process explorer REST service.
///
/// The explorer serves a read-only JSON API (chain frames, certified state,
/// hypergraph atoms, peers, provers, key registry) over the node's LIVE
/// stores — it does NOT open a second database or run its own sync, unlike
/// the standalone Go `node/explorer` binary it replaces.
///
/// It is only started on archive nodes (which hold the complete frame +
/// hypergraph history) and only when `enabled` is true.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplorerConfig {
    /// Enable the explorer REST service. Off by default.
    #[serde(default)]
    pub enabled: bool,
    /// Address to bind the REST server to. Mirrors the Go explorer's
    /// `:6600` (all interfaces).
    #[serde(default = "default_explorer_listen_addr")]
    pub listen_addr: String,
}

fn default_explorer_listen_addr() -> String {
    "0.0.0.0:6600".to_string()
}

impl Default for ExplorerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: default_explorer_listen_addr(),
        }
    }
}

impl ExplorerConfig {
    /// Populate empty fields with defaults (mirrors the other sub-configs'
    /// `apply_defaults`).
    pub fn apply_defaults(&mut self) {
        if self.listen_addr.is_empty() {
            self.listen_addr = default_explorer_listen_addr();
        }
    }
}

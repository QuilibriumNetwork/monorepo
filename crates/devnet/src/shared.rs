//! Wire types shared between the orchestrator and the proxy.
//!
//! The JSON field names here are a contract with the proxy: `NodeInfo` is
//! serialized into the `NODE_INFOS` docker env var and decoded by the proxy,
//! and `FrameNotification` is the JSON body the proxy POSTs back to the
//! orchestrator's notification server. The names mirror the Go `shared` package.

use serde::{Deserialize, Serialize};

/// The kind of notification emitted by the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationType {
    #[serde(rename = "terminal_frame_reached")]
    TerminalFrame,
    #[serde(rename = "global_timeout")]
    GlobalTimeout,
    /// Intermediate liveness update: the global-consensus frame advanced. The
    /// reached frame is carried in `frame_number` (`FrameNotification::stop_frame`).
    /// The run continues; the orchestrator just logs it as progress.
    #[serde(rename = "frame_progress")]
    Progress,
}

/// Per-node address and identity information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NodeInfo {
    /// Service name, e.g. "archive-1" or "client-1".
    pub name: String,
    /// Hostname, e.g. "archive-1".
    pub hostname: String,
    /// TCP stream port, e.g. 8340.
    pub stream_port: i32,
    /// Plaintext NodeService gRPC port, e.g. 8337.
    pub node_port: i32,
    /// base58-encoded peer ID, empty if unknown.
    pub peer_id: String,
    /// hex-encoded Ed448 private key.
    pub peer_priv_key: String,
    /// true for archive nodes; false for client (non-archive) nodes.
    pub is_archive: bool,
    /// Hex-encoded 32-byte Poseidon(BLS pubkey) derived from the node's
    /// q-prover-key. Used by the enrollment monitor to assert that a client's
    /// prover registration landed in the archives' registry. Pre-computed at
    /// startup so the proxy doesn't need a Poseidon dependency.
    pub prover_address: String,
}

impl NodeInfo {
    /// Returns `hostname:stream_port`.
    pub fn stream_address(&self) -> String {
        format!("{}:{}", self.hostname, self.stream_port)
    }

    /// Returns the numeric suffix of the service name (e.g. "archive-3" → 3).
    pub fn ordinal(&self) -> Result<i64, std::num::ParseIntError> {
        let suffix = self.name.rsplit('-').next().unwrap_or(&self.name);
        suffix.parse()
    }
}

/// Run-completion notification posted by the proxy to the orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FrameNotification {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub run_id: String,
    /// The configured stop frame for the run (JSON key `frame_number`).
    #[serde(rename = "frame_number")]
    pub stop_frame: u64,
    #[serde(rename = "type")]
    pub notification_type: NotificationType,
    /// Set when the proxy detected a consensus safety violation.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub safety_error: String,
    pub nodes_reached_stop_frame: i32,
    pub total_nodes: i32,
    /// Set when one or more client nodes failed to land their prover_address in
    /// at least `minimum_nodes` archives' prover registries. Empty when there
    /// are no client nodes or when all clients are confirmed enrolled.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub enrollment_error: String,
    /// Set when one or more archives failed to vote for the last frame
    /// (`stop_frame`) — i.e. they never rejoined consensus after a partition and
    /// merely passively synced frames. Empty when every archive originated a
    /// consensus message for the last frame.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rejoin_error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_info_json_roundtrip_keys() {
        let n = NodeInfo {
            name: "archive-1".into(),
            hostname: "archive-1".into(),
            stream_port: 8340,
            node_port: 8337,
            peer_id: "QmAbc".into(),
            peer_priv_key: "deadbeef".into(),
            is_archive: true,
            prover_address: String::new(),
        };
        let v: serde_json::Value = serde_json::to_value(&n).unwrap();
        // Exact wire keys consumed by the proxy.
        for key in [
            "name",
            "hostname",
            "stream_port",
            "node_port",
            "peer_id",
            "peer_priv_key",
            "is_archive",
            "prover_address",
        ] {
            assert!(v.get(key).is_some(), "missing wire key {key}");
        }
    }

    #[test]
    fn frame_notification_decodes_proxy_body() {
        let body = r#"{
            "run_id": "r1",
            "frame_number": 5,
            "type": "terminal_frame_reached",
            "nodes_reached_stop_frame": 3,
            "total_nodes": 4
        }"#;
        let n: FrameNotification = serde_json::from_str(body).unwrap();
        assert_eq!(n.run_id, "r1");
        assert_eq!(n.stop_frame, 5);
        assert_eq!(n.notification_type, NotificationType::TerminalFrame);
        assert_eq!(n.nodes_reached_stop_frame, 3);
        assert!(n.safety_error.is_empty());
    }

    #[test]
    fn progress_notification_roundtrips() {
        let n = FrameNotification {
            run_id: "r1".into(),
            stop_frame: 3,
            notification_type: NotificationType::Progress,
            safety_error: String::new(),
            nodes_reached_stop_frame: 0,
            total_nodes: 4,
            enrollment_error: String::new(),
            rejoin_error: String::new(),
        };
        let v: serde_json::Value = serde_json::to_value(&n).unwrap();
        assert_eq!(v.get("type").unwrap(), "frame_progress");
        assert_eq!(v.get("frame_number").unwrap(), 3);
        let back: FrameNotification = serde_json::from_value(v).unwrap();
        assert_eq!(back.notification_type, NotificationType::Progress);
        assert_eq!(back.stop_frame, 3);
    }

    #[test]
    fn ordinal_parses_suffix() {
        let n = NodeInfo {
            name: "archive-3".into(),
            hostname: "archive-3".into(),
            stream_port: 0,
            node_port: 0,
            peer_id: String::new(),
            peer_priv_key: String::new(),
            is_archive: true,
            prover_address: String::new(),
        };
        assert_eq!(n.ordinal().unwrap(), 3);
    }
}

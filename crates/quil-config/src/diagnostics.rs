//! Opt-in diagnostics this node serves to peers its operator names. Every
//! feature is off by default and serves, when on, only this node itself and
//! the peers listed by ID; changes take effect on restart.
use serde::{Deserialize, Serialize};

/// Bounds of `diagnostics.healthReport.minIntervalSecs`.
pub const HEALTH_REPORT_INTERVAL_SECS: std::ops::RangeInclusive<u64> = 10..=3600;

fn default_min_interval_secs() -> u64 {
    60
}

/// Bounds of `diagnostics.logRequests.requestsPerDay`.
pub const LOG_REQUESTS_PER_DAY: std::ops::RangeInclusive<u32> = 1..=24;
/// Bounds of `diagnostics.logRequests.maxPending`.
pub const LOG_REQUESTS_MAX_PENDING: std::ops::RangeInclusive<u32> = 1..=16;
/// Bounds of `diagnostics.logRequests.ttlSecs`: from ten minutes to a week.
pub const LOG_REQUEST_TTL_SECS: std::ops::RangeInclusive<u64> = 600..=7 * 86_400;
/// Bounds of `diagnostics.logRequests.maxBundleBytes`: 64 KiB to 256 MiB.
pub const LOG_BUNDLE_BYTES: std::ops::RangeInclusive<u64> = 64 * 1024..=256 * 1024 * 1024;

fn default_requests_per_day() -> u32 {
    4
}

fn default_max_pending() -> u32 {
    4
}

fn default_ttl_secs() -> u64 {
    86_400
}

fn default_max_bundle_bytes() -> u64 {
    32 * 1024 * 1024
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsConfig {
    /// A health report of this node's workers (phase, frames, recovery
    /// counts; no text, addresses or keys) on the peer gRPC listener.
    #[serde(default, deserialize_with = "crate::deserialize_null_default")]
    pub health_report: HealthReportConfig,
    /// Requests from the listed peers for this node's redacted logs.
    /// Listing a peer is consent: the node exports, redacts and seals each
    /// requested window itself and keeps the sealed bundle for that peer
    /// alone, writing the token map to `.diagnostics/token-maps`; `qclient
    /// node diagnostics pending|deny` lists requests and withdraws a bundle.
    /// A node that writes no log files leaves each request to its operator's
    /// `qclient node diagnostics approve`.
    #[serde(default, deserialize_with = "crate::deserialize_null_default")]
    pub log_requests: LogRequestsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HealthReportConfig {
    /// Serve the report to the peers in `allowedPeers`.
    #[serde(default)]
    pub enabled: bool,
    /// Base58 peer IDs (a node's network identity, as `qclient node info`
    /// prints it) allowed to ask. This node itself is always allowed.
    #[serde(default, deserialize_with = "crate::deserialize_null_default")]
    pub allowed_peers: Vec<String>,
    /// Seconds before the same peer is served again (10..=3600).
    #[serde(default = "default_min_interval_secs")]
    pub min_interval_secs: u64,
}

impl Default for HealthReportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_peers: Vec::new(),
            min_interval_secs: default_min_interval_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LogRequestsConfig {
    /// Take log requests from the peers in `allowedPeers` and approve them:
    /// listing a peer consents to sending it this node's redacted logs.
    #[serde(default)]
    pub enabled: bool,
    /// Base58 peer IDs allowed to ask, as for `healthReport`.
    #[serde(default, deserialize_with = "crate::deserialize_null_default")]
    pub allowed_peers: Vec<String>,
    /// Requests queued per peer in any 24 h (1..=24).
    #[serde(default = "default_requests_per_day")]
    pub requests_per_day: u32,
    /// Requests waiting for a decision or a fetch at once (1..=16).
    #[serde(default = "default_max_pending")]
    pub max_pending: u32,
    /// Seconds a request waits for approval, and an approved bundle for its
    /// fetch (600..=604800).
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,
    /// Largest sealed bundle this node builds itself or accepts from its
    /// operator, and keeps for a peer (65536..=268435456); this node denies a
    /// request whose own export is larger.
    #[serde(default = "default_max_bundle_bytes")]
    pub max_bundle_bytes: u64,
}

impl Default for LogRequestsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_peers: Vec::new(),
            requests_per_day: default_requests_per_day(),
            max_pending: default_max_pending(),
            ttl_secs: default_ttl_secs(),
            max_bundle_bytes: default_max_bundle_bytes(),
        }
    }
}

impl LogRequestsConfig {
    /// The limits clamped into their bounds.
    pub fn clamped(&self) -> Self {
        let clamp = |value: u64, range: &std::ops::RangeInclusive<u64>| {
            value.clamp(*range.start(), *range.end())
        };
        Self {
            enabled: self.enabled,
            allowed_peers: self.allowed_peers.clone(),
            requests_per_day: self
                .requests_per_day
                .clamp(*LOG_REQUESTS_PER_DAY.start(), *LOG_REQUESTS_PER_DAY.end()),
            max_pending: self.max_pending.clamp(
                *LOG_REQUESTS_MAX_PENDING.start(),
                *LOG_REQUESTS_MAX_PENDING.end(),
            ),
            ttl_secs: clamp(self.ttl_secs, &LOG_REQUEST_TTL_SECS),
            max_bundle_bytes: clamp(self.max_bundle_bytes, &LOG_BUNDLE_BYTES),
        }
    }
}

impl DiagnosticsConfig {
    /// Clamp the intervals into their bounds.
    pub fn apply_defaults(&mut self) {
        let interval = &mut self.health_report.min_interval_secs;
        *interval = (*interval).clamp(
            *HEALTH_REPORT_INTERVAL_SECS.start(),
            *HEALTH_REPORT_INTERVAL_SECS.end(),
        );
        self.log_requests = self.log_requests.clamped();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_health_report_is_off_with_no_peers_unless_configured() {
        for yaml in [
            "{}",
            "healthReport: null\n",
            "healthReport:\n  allowedPeers: null\n",
        ] {
            let parsed: DiagnosticsConfig = serde_yaml::from_str(yaml).unwrap();
            assert_eq!(parsed, DiagnosticsConfig::default(), "{yaml}");
            assert!(!parsed.health_report.enabled && parsed.health_report.allowed_peers.is_empty());
            assert_eq!(parsed.health_report.min_interval_secs, 60);
        }
        let parsed: DiagnosticsConfig = serde_yaml::from_str(
            "healthReport:\n  enabled: true\n  allowedPeers: [QmPeerOne, QmPeerTwo]\n  minIntervalSecs: 120\n",
        )
        .unwrap();
        let report = &parsed.health_report;
        assert!(report.enabled);
        assert_eq!(report.allowed_peers, ["QmPeerOne", "QmPeerTwo"]);
        assert_eq!(report.min_interval_secs, 120);
        let encoded = serde_yaml::to_string(&parsed).unwrap();
        assert!(
            encoded.contains("healthReport:")
                && encoded.contains("allowedPeers:")
                && encoded.contains("minIntervalSecs: 120")
        );
        assert_eq!(
            serde_yaml::from_str::<DiagnosticsConfig>(&encoded).unwrap(),
            parsed
        );
    }

    #[test]
    fn log_requests_are_off_unless_configured_and_their_limits_are_clamped() {
        for yaml in [
            "{}",
            "logRequests: null\n",
            "logRequests:\n  allowedPeers: null\n",
        ] {
            let parsed: DiagnosticsConfig = serde_yaml::from_str(yaml).unwrap();
            assert_eq!(parsed.log_requests, LogRequestsConfig::default(), "{yaml}");
            let requests = &parsed.log_requests;
            assert!(!requests.enabled && requests.allowed_peers.is_empty());
            assert_eq!(
                (
                    requests.requests_per_day,
                    requests.max_pending,
                    requests.ttl_secs,
                    requests.max_bundle_bytes
                ),
                (4, 4, 86_400, 32 * 1024 * 1024)
            );
        }
        let mut parsed: DiagnosticsConfig = serde_yaml::from_str(
            "logRequests:\n  enabled: true\n  allowedPeers: [QmPeerOne]\n  requestsPerDay: 0\n  maxPending: 99\n  ttlSecs: 60\n  maxBundleBytes: 1099511627776\n",
        )
        .unwrap();
        parsed.apply_defaults();
        let requests = &parsed.log_requests;
        assert!(requests.enabled);
        assert_eq!(requests.allowed_peers, ["QmPeerOne"]);
        assert_eq!(
            (
                requests.requests_per_day,
                requests.max_pending,
                requests.ttl_secs,
                requests.max_bundle_bytes
            ),
            (1, 16, 600, 256 * 1024 * 1024)
        );
        let encoded = serde_yaml::to_string(&parsed).unwrap();
        for key in [
            "logRequests:",
            "requestsPerDay:",
            "maxPending:",
            "ttlSecs:",
            "maxBundleBytes:",
        ] {
            assert!(encoded.contains(key), "{key}");
        }
        assert_eq!(
            serde_yaml::from_str::<DiagnosticsConfig>(&encoded).unwrap(),
            parsed
        );
    }

    #[test]
    fn the_interval_is_clamped() {
        for (configured, effective) in [
            (0, 10),
            (9, 10),
            (10, 10),
            (600, 600),
            (3600, 3600),
            (86_400, 3600),
        ] {
            let mut config = DiagnosticsConfig::default();
            config.health_report.min_interval_secs = configured;
            config.apply_defaults();
            assert_eq!(
                config.health_report.min_interval_secs, effective,
                "{configured}"
            );
        }
    }
}

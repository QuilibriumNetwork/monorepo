mod config;
mod db;
mod engine;
mod keys;
mod logger;
mod p2p;
mod version;

pub use config::*;
pub use db::*;
pub use engine::*;
pub use keys::*;
pub use logger::*;
pub use p2p::*;
pub use version::*;

use serde::{Deserialize, Deserializer};
use std::path::Path;

/// Deserialize a field that may be `null` in YAML as `Default::default()`.
pub(crate) fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::deserialize(deserializer)?.unwrap_or_default())
}

/// Deserialize a Go `time.Duration` value into milliseconds (u64).
///
/// Go's YAML marshaler writes durations as strings like `"0s"`, `"100ms"`,
/// `"700ms"`, `"1s"`, `"60s"`, `"10m0s"`. This deserializer accepts:
/// - Go duration strings: `"0s"`, `"100ms"`, `"1s"`, `"60s"`, `"5m0s"`, `"10s"`
/// - Raw nanosecond integers (Go's internal representation): `100000000` → 100ms
/// - Raw millisecond integers (Rust format): `100`
/// - Zero/null → 0 (use default)
pub(crate) fn deserialize_go_duration_ms<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum DurationValue {
        Str(String),
        Int(u64),
    }

    match Option::<DurationValue>::deserialize(deserializer)? {
        None => Ok(0),
        Some(DurationValue::Int(v)) => {
            // Heuristic: if value > 1_000_000, it's likely nanoseconds (Go internal)
            // 1_000_000 ns = 1 ms. Any millisecond value < 1s is < 1000.
            if v > 1_000_000 {
                Ok(v / 1_000_000) // nanoseconds → milliseconds
            } else {
                Ok(v) // already milliseconds
            }
        }
        Some(DurationValue::Str(s)) => parse_go_duration_ms(&s).map_err(de::Error::custom),
    }
}

/// Parse a Go duration string like "100ms", "1s", "60s", "5m0s", "0s" into ms.
fn parse_go_duration_ms(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() || s == "0" || s == "0s" {
        return Ok(0);
    }

    let mut total_ms: u64 = 0;
    let mut remaining = s;

    while !remaining.is_empty() {
        // Find the end of the numeric part
        let num_end = remaining
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(remaining.len());

        if num_end == 0 {
            return Err(format!("invalid duration: {}", s));
        }

        let num_str = &remaining[..num_end];
        let after_num = &remaining[num_end..];

        // Find the unit suffix
        let unit_end = after_num
            .find(|c: char| c.is_ascii_digit())
            .unwrap_or(after_num.len());
        let unit = &after_num[..unit_end];
        remaining = &after_num[unit_end..];

        let value: f64 = num_str.parse().map_err(|_| format!("invalid number in duration: {}", s))?;

        let ms = match unit {
            "ns" => value / 1_000_000.0,
            "us" | "µs" => value / 1_000.0,
            "ms" => value,
            "s" => value * 1_000.0,
            "m" => value * 60_000.0,
            "h" => value * 3_600_000.0,
            "" => {
                // No unit — treat as nanoseconds if large, ms otherwise
                if value > 1_000_000.0 { value / 1_000_000.0 } else { value }
            }
            _ => return Err(format!("unknown duration unit '{}' in: {}", unit, s)),
        };

        total_ms += ms as u64;
    }

    Ok(total_ms)
}
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("yaml parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("config error: {0}")]
    Other(String),
}

/// Load a config from the given directory, applying defaults.
pub fn load_config(config_dir: &Path) -> Result<Config, ConfigError> {
    let config_path = config_dir.join("config.yml");

    if !config_path.exists() {
        // First run — create config directory and generate defaults,
        // matching Go's LoadConfig behavior.
        std::fs::create_dir_all(config_dir)?;

        let mut config = Config::default();
        config.apply_defaults();

        // Set keys path to <config_dir>/keys.yml (matching Go)
        config.key.key_store_file.path =
            config_dir.join("keys.yml").to_string_lossy().to_string();

        // Generate random encryption key (matching Go)
        let mut key_bytes = [0u8; 32];
        use std::io::Read;
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut key_bytes))
            .map_err(|e| ConfigError::Io(e))?;
        config.key.key_store_file.encryption_key = hex::encode(key_bytes);
        config.key.key_store_file.create_if_missing = true;

        // Set DB paths (matching Go's `config/config.go:285-286`).
        // Both `path` and `worker_path_prefix` live INSIDE the config
        // directory — without this the worker stores leak to cwd.
        config.db.path = config_dir.join("store").to_string_lossy().to_string();
        config.db.worker_path_prefix = config_dir
            .join("worker-store")
            .join("%d")
            .to_string_lossy()
            .to_string();

        // Save config.yml
        save_config(config_dir, &config)?;

        return Ok(config);
    }

    let contents = std::fs::read_to_string(&config_path)?;
    let mut config: Config = serde_yaml::from_str(&contents)?;
    config.apply_defaults();

    // Fill in defaults for keys path if empty (matching Go)
    if config.key.key_store_file.path.is_empty() {
        config.key.key_store_file.path =
            config_dir.join("keys.yml").to_string_lossy().to_string();
    }
    if config.db.path.is_empty() {
        config.db.path = config_dir.join("store").to_string_lossy().to_string();
    }
    // `apply_defaults` set worker_path_prefix to the bare
    // `"worker-store/%d"` literal if it was missing from the YAML.
    // That value is cwd-relative and lands worker stores outside the
    // config dir. Promote it to `<config_dir>/worker-store/%d` so it
    // mirrors Go's `LoadConfig` write-time default.
    if config.db.worker_path_prefix.is_empty()
        || config.db.worker_path_prefix == "worker-store/%d"
    {
        config.db.worker_path_prefix = config_dir
            .join("worker-store")
            .join("%d")
            .to_string_lossy()
            .to_string();
    }

    Ok(config)
}

/// Save a config to the given directory.
pub fn save_config(config_dir: &Path, config: &Config) -> Result<(), ConfigError> {
    std::fs::create_dir_all(config_dir)?;
    let config_path = config_dir.join("config.yml");
    let contents = serde_yaml::to_string(config)?;
    std::fs::write(config_path, contents)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Unique temp dir per test — process id + counter keeps parallel
    // test runs from stepping on each other.
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
    fn tempdir(test_name: &str) -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "quil-config-test-{}-{}-{}",
            test_name,
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    // =================================================================
    // Default construction
    // =================================================================

    #[test]
    fn default_config_constructs_without_panic() {
        let _c = Config::default();
    }

    #[test]
    fn default_config_has_empty_listen_addresses() {
        let c = Config::default();
        assert!(c.listen_grpc_multiaddr.is_empty());
        assert!(c.listen_rest_multiaddr.is_empty());
    }

    #[test]
    fn engine_config_defaults_populated_via_yaml_empty_object() {
        let e = EngineConfig::default();
        assert_eq!(e.data_worker_base_p2p_port, 25000);
        assert_eq!(e.data_worker_base_stream_port, 32500);
        assert_eq!(e.data_worker_memory_limit, 1792 * 1024 * 1024);
        assert_eq!(e.sync_timeout_ms, 4000);
        assert_eq!(e.sync_candidates, 8);
        assert_eq!(e.reward_strategy, "reward-greedy");
    }

    #[test]
    fn p2p_config_defaults_populated_via_yaml_empty_object() {
        let p = P2PConfig::default();
        assert_eq!(p.low_watermark_connections, 160);
        assert_eq!(p.high_watermark_connections, 192);
        assert_eq!(p.min_bootstrap_peers, 3);
        assert_eq!(p.grpc_server_rate_limit, 10);
        assert_eq!(p.stream_listen_multiaddr, "/ip4/0.0.0.0/tcp/8340");
        assert_eq!(p.ping_timeout_ms, 5000);
        assert_eq!(p.ping_period_ms, 30000);
        assert_eq!(p.ping_attempts, 3);
    }

    #[test]
    fn db_config_defaults_populated_via_yaml_empty_object() {
        let d = DbConfig::default();
        assert_eq!(d.worker_path_prefix, "worker-store/%d");
        assert_eq!(d.notice_percentage, 70);
        assert_eq!(d.warn_percentage, 90);
        assert_eq!(d.terminate_percentage, 95);
    }

    // =================================================================
    // apply_defaults
    // =================================================================

    #[test]
    fn apply_defaults_populates_zero_engine_fields() {
        let yaml = r#"
minimumPeersRequired: 0
syncTimeoutMs: 0
syncCandidates: 0
rewardStrategy: ""
"#;
        let mut e: EngineConfig = serde_yaml::from_str(yaml).unwrap();
        e.apply_defaults();
        assert_eq!(e.minimum_peers_required, 3);
        assert_eq!(e.sync_timeout_ms, 4000);
        assert_eq!(e.sync_candidates, 8);
        assert_eq!(e.reward_strategy, "reward-greedy");
    }

    #[test]
    fn apply_defaults_preserves_non_zero_fields() {
        let yaml = r#"
minimumPeersRequired: 42
syncTimeoutMs: 1000
rewardStrategy: "custom-strategy"
"#;
        let mut e: EngineConfig = serde_yaml::from_str(yaml).unwrap();
        e.apply_defaults();
        assert_eq!(e.minimum_peers_required, 42);
        assert_eq!(e.sync_timeout_ms, 1000);
        assert_eq!(e.reward_strategy, "custom-strategy");
    }

    #[test]
    fn apply_defaults_populates_db_fields() {
        let mut d = DbConfig::default();
        d.worker_path_prefix = String::new();
        d.notice_percentage = 0;
        d.warn_percentage = 0;
        d.terminate_percentage = 0;
        d.apply_defaults();
        assert_eq!(d.worker_path_prefix, "worker-store/%d");
        assert_eq!(d.notice_percentage, 70);
        assert_eq!(d.warn_percentage, 90);
        assert_eq!(d.terminate_percentage, 95);
    }

    #[test]
    fn apply_defaults_populates_p2p_stream_addr_when_empty() {
        let mut p = P2PConfig::default();
        p.stream_listen_multiaddr = String::new();
        p.low_watermark_connections = 0;
        p.high_watermark_connections = 0;
        p.apply_defaults();
        assert_eq!(p.stream_listen_multiaddr, "/ip4/0.0.0.0/tcp/8340");
        assert_eq!(p.low_watermark_connections, 160);
        assert_eq!(p.high_watermark_connections, 192);
    }

    #[test]
    fn top_level_apply_defaults_cascades_to_subconfigs() {
        let mut c = Config::default();
        c.engine.minimum_peers_required = 0;
        c.engine.sync_timeout_ms = 0;
        c.db.notice_percentage = 0;
        c.p2p.low_watermark_connections = 0;

        c.apply_defaults();

        assert_eq!(c.engine.minimum_peers_required, 3);
        assert_eq!(c.engine.sync_timeout_ms, 4000);
        assert_eq!(c.db.notice_percentage, 70);
        assert_eq!(c.p2p.low_watermark_connections, 160);
    }

    // =================================================================
    // YAML round-trip
    // =================================================================

    #[test]
    fn yaml_round_trip_preserves_scalar_fields() {
        let mut c = Config::default();
        c.engine.minimum_peers_required = 17;
        c.engine.sync_timeout_ms = 5555;
        c.engine.archive_mode = true;
        c.engine.delegate_address = "delegate-xyz".into();
        c.db.path = "/data/store".into();
        c.db.notice_percentage = 42;
        c.p2p.network = 7;

        let yaml = serde_yaml::to_string(&c).unwrap();
        let c2: Config = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(c2.engine.minimum_peers_required, 17);
        assert_eq!(c2.engine.sync_timeout_ms, 5555);
        assert!(c2.engine.archive_mode);
        assert_eq!(c2.engine.delegate_address, "delegate-xyz");
        assert_eq!(c2.db.path, "/data/store");
        assert_eq!(c2.db.notice_percentage, 42);
        assert_eq!(c2.p2p.network, 7);
    }

    #[test]
    fn yaml_round_trip_preserves_vec_fields() {
        let mut c = Config::default();
        c.engine.data_worker_filters =
            vec!["shard-a".into(), "shard-b".into(), "shard-c".into()];
        c.p2p.bootstrap_peers = vec![
            "/ip4/1.2.3.4/tcp/100".into(),
            "/ip4/5.6.7.8/tcp/200".into(),
        ];

        let yaml = serde_yaml::to_string(&c).unwrap();
        let c2: Config = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(c2.engine.data_worker_filters.len(), 3);
        assert_eq!(c2.engine.data_worker_filters[0], "shard-a");
        assert_eq!(c2.p2p.bootstrap_peers.len(), 2);
        assert_eq!(c2.p2p.bootstrap_peers[0], "/ip4/1.2.3.4/tcp/100");
    }

    #[test]
    fn yaml_field_names_use_camel_case() {
        let mut c = Config::default();
        c.engine.minimum_peers_required = 5;
        let yaml = serde_yaml::to_string(&c).unwrap();
        assert!(
            yaml.contains("minimumPeersRequired"),
            "yaml missing camelCase field: {}",
            yaml
        );
        assert!(
            !yaml.contains("minimum_peers_required"),
            "yaml has snake_case field: {}",
            yaml
        );
    }

    #[test]
    fn yaml_special_rest_multiaddr_rename() {
        let mut c = Config::default();
        c.listen_rest_multiaddr = "/ip4/0.0.0.0/tcp/9000".into();
        let yaml = serde_yaml::to_string(&c).unwrap();
        assert!(
            yaml.contains("listenRESTMultiaddr"),
            "yaml missing listenRESTMultiaddr: {}",
            yaml
        );
    }

    #[test]
    fn parse_yaml_with_unknown_fields_ignores_them() {
        let yaml = r#"
engine:
  minimumPeersRequired: 5
  unknownFutureField: "ignored"
"#;
        let result: std::result::Result<Config, _> = serde_yaml::from_str(yaml);
        assert!(
            result.is_ok(),
            "unknown fields should be ignored, got: {:?}",
            result.err()
        );
        let c = result.unwrap();
        assert_eq!(c.engine.minimum_peers_required, 5);
    }

    // =================================================================
    // load_config / save_config
    // =================================================================

    #[test]
    fn load_config_from_missing_dir_creates_defaults() {
        let dir = tempdir("missing_dir_creates");
        let _ = std::fs::remove_dir_all(&dir);
        let c = load_config(&dir).unwrap();
        // Creates config directory and config.yml (matching Go's LoadConfig)
        assert!(dir.exists());
        assert!(dir.join("config.yml").exists());
        // Generates a random encryption key
        assert!(!c.key.key_store_file.encryption_key.is_empty());
        assert_eq!(c.key.key_store_file.encryption_key.len(), 64); // 32 bytes hex
        // Sets keys path
        assert!(c.key.key_store_file.path.contains("keys.yml"));
        // Sets DB path
        assert!(c.db.path.contains("store"));
        cleanup(&dir);
    }

    #[test]
    fn load_config_parses_real_yaml_file() {
        let dir = tempdir("parse_real_yaml");
        let yaml = r#"
engine:
  minimumPeersRequired: 5
  rewardStrategy: "custom"
  archiveMode: true
db:
  path: "/var/quil-db"
  noticePercentage: 50
p2p:
  network: 42
  bootstrapPeers:
    - "/ip4/1.1.1.1/tcp/8000"
"#;
        let mut f = std::fs::File::create(dir.join("config.yml")).unwrap();
        f.write_all(yaml.as_bytes()).unwrap();
        drop(f);

        let c = load_config(&dir).unwrap();
        assert_eq!(c.engine.minimum_peers_required, 5);
        assert_eq!(c.engine.reward_strategy, "custom");
        assert!(c.engine.archive_mode);
        assert_eq!(c.db.path, "/var/quil-db");
        assert_eq!(c.db.notice_percentage, 50);
        assert_eq!(c.p2p.network, 42);
        assert_eq!(
            c.p2p.bootstrap_peers,
            vec!["/ip4/1.1.1.1/tcp/8000".to_string()]
        );

        cleanup(&dir);
    }

    #[test]
    fn load_config_applies_defaults_after_parse() {
        let dir = tempdir("apply_defaults_after_parse");
        let yaml = r#"
engine:
  archiveMode: true
"#;
        std::fs::write(dir.join("config.yml"), yaml).unwrap();
        let c = load_config(&dir).unwrap();
        assert!(c.engine.archive_mode);
        assert_eq!(c.engine.minimum_peers_required, 3);
        assert_eq!(c.engine.sync_timeout_ms, 4000);

        cleanup(&dir);
    }

    #[test]
    fn save_config_creates_dir_and_writes_yaml() {
        let dir = tempdir("save_creates_dir");
        let nested = dir.join("subdir");
        assert!(!nested.exists());

        let mut c = Config::default();
        c.engine.minimum_peers_required = 99;

        save_config(&nested, &c).unwrap();
        assert!(nested.exists());
        assert!(nested.join("config.yml").exists());

        let loaded = load_config(&nested).unwrap();
        assert_eq!(loaded.engine.minimum_peers_required, 99);

        cleanup(&dir);
    }

    #[test]
    fn save_then_load_round_trip_preserves_config() {
        let dir = tempdir("save_load_round_trip");
        let mut c = Config::default();
        c.engine.minimum_peers_required = 25;
        c.engine.archive_mode = true;
        c.engine.rewards_address = "rewards-abc".into();
        c.db.path = "/nested/path".into();
        c.listen_grpc_multiaddr = "/ip4/0.0.0.0/tcp/8337".into();

        save_config(&dir, &c).unwrap();
        let loaded = load_config(&dir).unwrap();

        assert_eq!(loaded.engine.minimum_peers_required, 25);
        assert!(loaded.engine.archive_mode);
        assert_eq!(loaded.engine.rewards_address, "rewards-abc");
        assert_eq!(loaded.db.path, "/nested/path");
        assert_eq!(loaded.listen_grpc_multiaddr, "/ip4/0.0.0.0/tcp/8337");

        cleanup(&dir);
    }

    #[test]
    fn load_config_invalid_yaml_returns_error() {
        let dir = tempdir("invalid_yaml");
        std::fs::write(dir.join("config.yml"), "not: [valid: yaml").unwrap();
        let err = load_config(&dir).unwrap_err();
        assert!(matches!(err, ConfigError::Yaml(_)));
        cleanup(&dir);
    }

    // =================================================================
    // Frame publish / Reed-Solomon sub-config
    // =================================================================

    #[test]
    fn reed_solomon_defaults() {
        let rs = ReedSolomonConfig::default();
        assert_eq!(rs.data_shards, 224);
        assert_eq!(rs.parity_shards, 32);
    }

    #[test]
    fn frame_publish_defaults() {
        let fp = FramePublishConfig::default();
        assert_eq!(fp.mode, "full");
        assert_eq!(fp.threshold, 1024 * 1024);
        assert_eq!(fp.fragmentation.algorithm, "reed-solomon");
        assert_eq!(fp.fragmentation.reed_solomon.data_shards, 224);
        assert_eq!(fp.fragmentation.reed_solomon.parity_shards, 32);
    }

    #[test]
    fn grpc_message_limits_defaults_scale_with_sync_limit() {
        let g = GrpcMessageLimitsConfig::default();
        let expected = 64 * 1024 * 1024;
        assert_eq!(g.max_recv_msg_size, expected);
        assert_eq!(g.max_send_msg_size, expected);
    }

    #[test]
    fn apply_defaults_sets_frame_publish_mode_when_empty() {
        let yaml = r#"
framePublish:
  mode: ""
  threshold: 2048
"#;
        let mut e: EngineConfig = serde_yaml::from_str(yaml).unwrap();
        e.apply_defaults();
        assert_eq!(e.frame_publish.mode, "full");
        assert_eq!(e.frame_publish.threshold, 2048);
    }

    #[test]
    fn parse_go_duration_strings() {
        assert_eq!(parse_go_duration_ms("0s").unwrap(), 0);
        assert_eq!(parse_go_duration_ms("100ms").unwrap(), 100);
        assert_eq!(parse_go_duration_ms("700ms").unwrap(), 700);
        assert_eq!(parse_go_duration_ms("1s").unwrap(), 1_000);
        assert_eq!(parse_go_duration_ms("10s").unwrap(), 10_000);
        assert_eq!(parse_go_duration_ms("30s").unwrap(), 30_000);
        assert_eq!(parse_go_duration_ms("60s").unwrap(), 60_000);
        assert_eq!(parse_go_duration_ms("5m0s").unwrap(), 300_000);
        assert_eq!(parse_go_duration_ms("1h0m0s").unwrap(), 3_600_000);
        assert_eq!(parse_go_duration_ms("").unwrap(), 0);
        assert_eq!(parse_go_duration_ms("0").unwrap(), 0);
    }

    #[test]
    fn go_config_yaml_loads_with_duration_strings() {
        let yaml = r#"
p2p:
  heartbeatInitialDelay: 100ms
  heartbeatInterval: 700ms
  fanoutTTL: 60s
  pruneBackoff: 60s
  unsubscribeBackoff: 10s
  connectionTimeout: 30s
  directConnectInitialDelay: 1s
  graftFloodThreshold: 10s
  iWantFollowupTime: 3s
  pingTimeout: 5s
  pingPeriod: 30s
  peerReconnectCheckInterval: 60s
engine:
  syncTimeout: 4s
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.p2p.heartbeat_initial_delay_ms, 100);
        assert_eq!(config.p2p.heartbeat_interval_ms, 700);
        assert_eq!(config.p2p.fanout_ttl_ms, 60_000);
        assert_eq!(config.p2p.prune_backoff_ms, 60_000);
        assert_eq!(config.p2p.unsubscribe_backoff_ms, 10_000);
        assert_eq!(config.p2p.connection_timeout_ms, 30_000);
        assert_eq!(config.p2p.direct_connect_initial_delay_ms, 1_000);
        assert_eq!(config.p2p.graft_flood_threshold_ms, 10_000);
        assert_eq!(config.p2p.iwant_followup_time_ms, 3_000);
        assert_eq!(config.p2p.ping_timeout_ms, 5_000);
        assert_eq!(config.p2p.ping_period_ms, 30_000);
        assert_eq!(config.p2p.peer_reconnect_check_interval_ms, 60_000);
        assert_eq!(config.engine.sync_timeout_ms, 4_000);
    }

    #[test]
    fn go_config_yaml_loads_with_zero_durations() {
        // Go's default config has "0s" for all durations (meaning "use defaults")
        let yaml = r#"
p2p:
  heartbeatInitialDelay: 0s
  heartbeatInterval: 0s
  pingTimeout: 0s
engine:
  syncTimeout: 0s
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.p2p.heartbeat_initial_delay_ms, 0);
        assert_eq!(config.p2p.heartbeat_interval_ms, 0);
        assert_eq!(config.p2p.ping_timeout_ms, 0);
        assert_eq!(config.engine.sync_timeout_ms, 0);
    }

    #[test]
    fn loads_actual_go_config_file() {
        // Test loading the real Go-generated config at node/.config-rust/
        let config_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap()
            .join("quil-node")
            .join("..").join("..").join("node").join(".config-rust");
        if config_path.join("config.yml").exists() {
            let result = load_config(&config_path);
            assert!(result.is_ok(), "failed to load Go config: {:?}", result.err());
            let config = result.unwrap();
            // Verify it loaded meaningful data
            assert!(!config.p2p.peer_priv_key.is_empty(), "peer key should be set");
            assert!(!config.p2p.bootstrap_peers.is_empty(), "bootstrap peers should be set");
        }
    }
}

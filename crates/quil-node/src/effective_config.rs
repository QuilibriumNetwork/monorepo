//! The configuration this process runs with, as one startup line.
//!
//! `loaded configuration` names only the config directory, so a remote log
//! request could not tell which limits a node used (for example whether an
//! archive had raised `proofWorker.maxConcurrent`). [`EffectiveConfig`] holds
//! the operationally relevant settings as they are used: defaults applied,
//! `QUIL_*` overrides resolved, caches sized. It never holds keys, peer IDs,
//! addresses, listen multiaddrs, paths, credentials or endpoints; the
//! exclusions are listed beside [`EffectiveConfig::resolve`].
//!
//! The line is logged at startup by every process (the master and each
//! standalone worker read the config separately), and the master repeats its
//! few most-asked values ([`EffectiveConfig::status_brief`]) in `node status`,
//! so any recent log window answers them after the startup line rotated away.

use quil_config::Config;
use tracing::info;

/// Most `QUIL_*` overrides the line lists; the rest are counted.
const MAX_ENV_LISTED: usize = 24;
/// Longest value of an override the line prints.
const MAX_ENV_VALUE_LEN: usize = 32;
/// Name fragments of overrides whose values are never printed (paths,
/// addresses, files, secrets); the name is still listed as `<set>`.
const PRIVATE_NAME_PARTS: [&str; 14] = [
    "PATH", "FILE", "DIR", "STORE", "KEY", "SECRET", "TOKEN", "PASS", "ADDR", "ENDPOINT", "PEER",
    "URL", "HOST", "PID",
];

/// What the process knows about itself that the config file does not say.
#[derive(Debug, Clone)]
pub(crate) struct Runtime {
    /// 0 for the master, the data worker's core otherwise.
    pub core: u32,
    pub network: u8,
    pub archive: bool,
    pub dht_only: bool,
    /// CPUs this process may use (cgroup-aware).
    pub cpus: u32,
    /// This process's store cache, bytes, when the store has one of its own:
    /// an archive's, or any store's under `QUIL_ROCKSDB_BLOCK_CACHE_MB`.
    pub store_cache_bytes: u64,
    /// A data worker's own store cache, bytes, under the same override.
    pub worker_cache_bytes: u64,
    /// The block cache `n` stores of this process share once open
    /// ([`quil_store::shared_block_cache_bytes`], budget
    /// `QUIL_ROCKSDB_BLOCK_CACHE_TOTAL_MB`); `None` when
    /// `QUIL_ROCKSDB_BLOCK_CACHE_MB` gives each store its own.
    pub shared_cache_bytes: fn(usize) -> Option<usize>,
    pub rocksdb_bg_threads: i32,
    /// Every `QUIL_*` variable of the environment, as `(name, value)`.
    pub env: Vec<(String, String)>,
}

impl Runtime {
    /// The values of the running process.
    pub(crate) fn detect(core: u32, network: u8, archive: bool, dht_only: bool) -> Self {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(4);
        let mut env: Vec<(String, String)> = std::env::vars()
            .filter(|(name, _)| name.starts_with("QUIL_"))
            .collect();
        env.sort();
        Self {
            core,
            network,
            archive,
            dht_only,
            cpus,
            store_cache_bytes: quil_store::effective_block_cache_bytes(archive && core == 0) as u64,
            worker_cache_bytes: quil_store::effective_block_cache_bytes(false) as u64,
            shared_cache_bytes: quil_store::shared_block_cache_bytes,
            rocksdb_bg_threads: quil_store::background_threads(),
            env,
        }
    }
}

/// The settings logged, resolved. Field names are the log field names.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EffectiveConfig {
    pub build_fingerprint: &'static str,
    pub core: u32,
    pub network: u8,
    /// `archive`, `regular`, `worker` (a standalone data worker) or `dht-only`.
    pub mode: &'static str,
    /// `thread` (workers run inside the master) or `cluster` (standalone
    /// worker processes reached over `dataWorkerStreamMultiaddrs`).
    pub worker_layout: &'static str,
    pub data_worker_count_configured: i32,
    /// Data workers the master runs or expects; 0 on an archive.
    pub workers: u32,
    pub data_worker_filters_pinned: usize,
    pub cpus: u32,
    pub proof_disabled: bool,
    /// Verifications admitted at once, shared by every worker of the node.
    /// `proofWorker.maxConcurrent` as written: the number, or `unset` when the
    /// node chooses it (releases that size an archive's slots from its machine).
    /// The slots in use are in the `token proof worker configured` line and,
    /// for the master, in `node status` (`proof_slots`).
    pub proof_slots_configured: String,
    pub proof_native_threads: u8,
    pub proof_admission_wait_ms: u64,
    pub proof_verify_budget_secs: u64,
    pub proof_cpu_seconds: u64,
    pub proof_wall_timeout_secs: u64,
    pub proof_max_resident_mb: u64,
    pub proof_address_space_mb: u64,
    /// Block cache of this process's store: its own size, or `shared` when
    /// it uses the process's shared cache.
    pub block_cache_mb: String,
    /// Block cache of each data worker's store, likewise.
    pub worker_block_cache_mb: String,
    /// What this process's stores hold together: the shared cache sized for
    /// the master and every thread-mode worker store (this process's one
    /// store otherwise), or the sum of their own caches. An archive's store
    /// has its own; its scratch stores share a separate cache.
    pub block_cache_total_mb: u64,
    pub rocksdb_bg_threads: i32,
    pub disk_notice_pct: i32,
    pub disk_warn_pct: i32,
    pub disk_terminate_pct: i32,
    pub log_files: bool,
    pub stderr_level: &'static str,
    pub log_max_size_mb: i32,
    pub log_max_backups: i32,
    pub log_max_age_days: i32,
    pub log_compress: bool,
    pub reward_strategy: String,
    pub consensus_leader_timeout_secs: u64,
    pub app_consensus_cw: bool,
    pub enable_master_proxy: bool,
    pub archive_blacklist_ttl_secs: i64,
    pub archive_endpoints_configured: usize,
    pub onion_routing: bool,
    pub stream_max_connections: usize,
    pub stream_max_connections_per_source: usize,
    pub gossip_d_lo: i32,
    pub gossip_heartbeat_ms: u64,
    pub grpc_allow_remote: bool,
    pub explorer_enabled: bool,
    pub health_report_enabled: bool,
    pub log_requests_enabled: bool,
    pub log_requests_per_day: u32,
    pub log_requests_max_bundle_bytes: u64,
    /// `NAME=value,...` of the `QUIL_*` overrides set; `none` if there are none.
    pub env_overrides: String,
}

fn mb(bytes: u64) -> u64 {
    bytes >> 20
}

/// A store's block cache as logged: its own size in MB, or `shared`.
fn cache_field(own: bool, mb: u64) -> String {
    if own {
        mb.to_string()
    } else {
        "shared".to_string()
    }
}

/// A value printed for an override: short, and without path or address
/// characters. `None` means print `<set>` instead.
fn printable_env_value(name: &str, value: &str) -> Option<String> {
    let private_name = PRIVATE_NAME_PARTS.iter().any(|part| name.contains(part));
    let plain = !value.is_empty()
        && value.len() <= MAX_ENV_VALUE_LEN
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ',' | '@' | '.' | '_' | ':' | '-'));
    (!private_name && plain).then(|| value.to_string())
}

fn render_env(env: &[(String, String)]) -> String {
    if env.is_empty() {
        return "none".to_string();
    }
    let mut parts: Vec<String> = env
        .iter()
        .take(MAX_ENV_LISTED)
        .map(|(name, value)| match printable_env_value(name, value) {
            Some(value) => format!("{name}={value}"),
            None => format!("{name}=<set>"),
        })
        .collect();
    if env.len() > MAX_ENV_LISTED {
        parts.push(format!("+{}_more", env.len() - MAX_ENV_LISTED));
    }
    parts.join(",")
}

impl EffectiveConfig {
    /// Resolve the settings from the loaded `config` and the process's
    /// `runtime`.
    ///
    /// Excluded on purpose, as private or identifying: `key.*` (key files and
    /// their encryption keys), `p2p.peerPrivKey`, every listen, announce and
    /// stream multiaddr, `bootstrapPeers`, `directPeers`, `engine.delegateAddress`,
    /// `alertKey`, `genesisSeed`, `provingKeyId`, archive endpoints and
    /// blacklist (only the endpoint count is logged), `consensusCommittee*`,
    /// the pinned shard filters (only their count), all paths (`db.path`,
    /// `db.workerPaths`, `logger.path`, `proofWorker.path`, the explorer
    /// address), `diagnostics.*.allowedPeers`, and the value of any `QUIL_*`
    /// override named like a path, file, key, address or endpoint.
    pub(crate) fn resolve(config: &Config, runtime: &Runtime) -> Self {
        let master = runtime.core == 0 && !runtime.dht_only;
        let mode = if runtime.dht_only {
            "dht-only"
        } else if runtime.core != 0 {
            "worker"
        } else if runtime.archive {
            "archive"
        } else {
            "regular"
        };
        let cluster = !config.engine.data_worker_stream_multiaddrs.is_empty();
        let configured = config.engine.data_worker_count;
        let workers = if !master || runtime.archive {
            0
        } else if configured > 0 {
            configured as u32
        } else if cluster {
            0
        } else {
            runtime.cpus.saturating_sub(1).max(1)
        };
        let own = mb(runtime.store_cache_bytes);
        let per_worker = mb(runtime.worker_cache_bytes);
        let worker_stores = if master && !cluster { workers } else { 0 };
        let shared = (runtime.shared_cache_bytes)(1 + worker_stores as usize);
        // An archive's store has a cache of its own even when the others share.
        let own_cache = shared.is_none() || (master && runtime.archive);
        let total = match shared {
            Some(bytes) if !own_cache => mb(bytes as u64),
            Some(_) => own,
            None => own + u64::from(worker_stores) * per_worker,
        };
        let proof = &config.proof_worker;
        let (log_max_size, log_max_backups, log_max_age, log_compress) = config.logger.rotation();
        let log_files = config.logger.log_dir(std::path::Path::new("")).is_some();
        Self {
            build_fingerprint: env!("QUIL_BUILD_FINGERPRINT"),
            core: runtime.core,
            network: runtime.network,
            mode,
            worker_layout: if cluster { "cluster" } else { "thread" },
            data_worker_count_configured: configured,
            workers,
            data_worker_filters_pinned: config.engine.data_worker_filters.len(),
            cpus: runtime.cpus,
            proof_disabled: proof.disabled,
            // `Option::from` takes the field whether it is a number (as on
            // older releases) or already an `Option`.
            proof_slots_configured: Option::<usize>::from(proof.max_concurrent)
                .map_or_else(|| "unset".to_string(), |slots| slots.to_string()),
            proof_native_threads: proof.native_threads,
            proof_admission_wait_ms: proof.admission_wait_ms,
            proof_verify_budget_secs: proof.verify_budget_secs,
            proof_cpu_seconds: proof.cpu_seconds,
            proof_wall_timeout_secs: proof.wall_timeout_secs,
            proof_max_resident_mb: mb(proof.max_resident_bytes),
            proof_address_space_mb: mb(proof.address_space_bytes),
            block_cache_mb: cache_field(own_cache, own),
            worker_block_cache_mb: cache_field(shared.is_none(), per_worker),
            block_cache_total_mb: total,
            rocksdb_bg_threads: runtime.rocksdb_bg_threads,
            disk_notice_pct: config.db.notice_percentage,
            disk_warn_pct: config.db.warn_percentage,
            disk_terminate_pct: config.db.terminate_percentage,
            log_files,
            stderr_level: config.logger.stderr_level(),
            log_max_size_mb: log_max_size,
            log_max_backups,
            log_max_age_days: log_max_age,
            log_compress,
            reward_strategy: config.engine.reward_strategy.chars().take(32).collect(),
            consensus_leader_timeout_secs: config.engine.consensus_leader_timeout_secs,
            app_consensus_cw: config.engine.app_consensus_cw,
            enable_master_proxy: config.engine.enable_master_proxy,
            archive_blacklist_ttl_secs: config.engine.archive_blacklist_ttl_secs,
            archive_endpoints_configured: config.engine.archive_endpoints.len(),
            onion_routing: !config.p2p.disable_onion_routing,
            stream_max_connections: config.p2p.stream_max_connections,
            stream_max_connections_per_source: config.p2p.stream_max_connections_per_source,
            gossip_d_lo: config.p2p.d_lo,
            gossip_heartbeat_ms: config.p2p.heartbeat_interval_ms,
            grpc_allow_remote: config.listen_grpc_allow_remote,
            explorer_enabled: config.explorer.enabled,
            health_report_enabled: config.diagnostics.health_report.enabled,
            log_requests_enabled: config.diagnostics.log_requests.enabled,
            log_requests_per_day: config.diagnostics.log_requests.requests_per_day,
            log_requests_max_bundle_bytes: config.diagnostics.log_requests.max_bundle_bytes,
            env_overrides: render_env(&runtime.env),
        }
    }

    /// The few values operators ask for most, short enough for every
    /// `node status` line.
    ///
    /// `proof_slots` is the built verifier's concurrency (`None`: no verifier,
    /// the suite is disabled or not compiled in).
    pub(crate) fn status_brief(&self, proof_slots: Option<usize>) -> String {
        format!(
            "mode={} workers={} proof_slots={} proof_slots_configured={} proof_threads={} block_cache_mb={} overrides={}",
            self.mode,
            self.workers,
            proof_slots.map_or_else(|| "none".to_string(), |slots| slots.to_string()),
            self.proof_slots_configured,
            self.proof_native_threads,
            self.block_cache_total_mb,
            self.env_overrides.matches('=').count(),
        )
    }

    /// Log the line. Fixed field set; one line per process start.
    pub(crate) fn log(&self) {
        info!(
            build_fingerprint = self.build_fingerprint,
            core = self.core,
            network = self.network,
            mode = self.mode,
            worker_layout = self.worker_layout,
            data_worker_count_configured = self.data_worker_count_configured,
            workers = self.workers,
            data_worker_filters_pinned = self.data_worker_filters_pinned,
            cpus = self.cpus,
            proof_disabled = self.proof_disabled,
            proof_slots_configured = %self.proof_slots_configured,
            proof_native_threads = self.proof_native_threads,
            proof_admission_wait_ms = self.proof_admission_wait_ms,
            proof_verify_budget_secs = self.proof_verify_budget_secs,
            proof_cpu_seconds = self.proof_cpu_seconds,
            proof_wall_timeout_secs = self.proof_wall_timeout_secs,
            proof_max_resident_mb = self.proof_max_resident_mb,
            proof_address_space_mb = self.proof_address_space_mb,
            block_cache_mb = %self.block_cache_mb,
            worker_block_cache_mb = %self.worker_block_cache_mb,
            block_cache_total_mb = self.block_cache_total_mb,
            rocksdb_bg_threads = self.rocksdb_bg_threads,
            disk_notice_pct = self.disk_notice_pct,
            disk_warn_pct = self.disk_warn_pct,
            disk_terminate_pct = self.disk_terminate_pct,
            log_files = self.log_files,
            stderr_level = self.stderr_level,
            log_max_size_mb = self.log_max_size_mb,
            log_max_backups = self.log_max_backups,
            log_max_age_days = self.log_max_age_days,
            log_compress = self.log_compress,
            reward_strategy = %self.reward_strategy,
            consensus_leader_timeout_secs = self.consensus_leader_timeout_secs,
            app_consensus_cw = self.app_consensus_cw,
            enable_master_proxy = self.enable_master_proxy,
            archive_blacklist_ttl_secs = self.archive_blacklist_ttl_secs,
            archive_endpoints_configured = self.archive_endpoints_configured,
            onion_routing = self.onion_routing,
            stream_max_connections = self.stream_max_connections,
            stream_max_connections_per_source = self.stream_max_connections_per_source,
            gossip_d_lo = self.gossip_d_lo,
            gossip_heartbeat_ms = self.gossip_heartbeat_ms,
            grpc_allow_remote = self.grpc_allow_remote,
            explorer_enabled = self.explorer_enabled,
            health_report_enabled = self.health_report_enabled,
            log_requests_enabled = self.log_requests_enabled,
            log_requests_per_day = self.log_requests_per_day,
            log_requests_max_bundle_bytes = self.log_requests_max_bundle_bytes,
            env_overrides = %self.env_overrides,
            "effective configuration"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// The text of the lines `emit` logs.
    fn captured(emit: impl FnOnce()) -> String {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, emit);
        let bytes = capture.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    fn runtime(env: &[(&str, &str)]) -> Runtime {
        Runtime {
            core: 0,
            network: 0,
            archive: false,
            dht_only: false,
            cpus: 8,
            store_cache_bytes: 256 << 20,
            worker_cache_bytes: 256 << 20,
            shared_cache_bytes: default_shared_cache,
            rocksdb_bg_threads: 8,
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    /// The shared cache as sized without overrides: 256 MB per store up to
    /// 1 GB.
    fn default_shared_cache(stores: usize) -> Option<usize> {
        Some((stores << 28).min(1 << 30))
    }

    fn archive_brief_has_no_slots(effective: &EffectiveConfig) -> bool {
        effective.status_brief(None).contains("proof_slots=none")
    }

    /// The config the node would load from this `config.yml`, defaults applied.
    fn config_from(yaml: &str) -> Config {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("config.yml"), yaml).unwrap();
        quil_config::load_config(directory.path()).expect("test config")
    }

    /// The line carries what the node uses: proof slots from the config,
    /// the cache from the `QUIL_ROCKSDB_BLOCK_CACHE_MB` override the process
    /// really sees, and the override itself by name and value.
    #[test]
    fn the_line_carries_the_values_in_use_not_the_written_ones() {
        std::env::set_var("QUIL_ROCKSDB_BLOCK_CACHE_MB", "64");
        let config = config_from(
            "proofWorker:\n  maxConcurrent: 6\n  nativeThreads: 2\nengine:\n  dataWorkerCount: 3\nlogger:\n  stderrLevel: info\n",
        );
        let runtime = Runtime::detect(0, 0, false, false);
        let effective = EffectiveConfig::resolve(&config, &runtime);
        std::env::remove_var("QUIL_ROCKSDB_BLOCK_CACHE_MB");
        assert_eq!(effective.mode, "regular");
        assert_eq!(effective.worker_layout, "thread");
        assert_eq!(effective.workers, 3);
        assert_eq!(effective.proof_slots_configured, "6");
        assert_eq!(effective.proof_native_threads, 2);
        assert_eq!(effective.stderr_level, "info");
        assert_eq!(
            effective.block_cache_mb, "64",
            "a cache of its own of the override, not the shared one"
        );
        assert_eq!(effective.worker_block_cache_mb, "64");
        assert_eq!(effective.block_cache_total_mb, 64 * 4, "master + 3 workers");
        assert!(effective
            .env_overrides
            .contains("QUIL_ROCKSDB_BLOCK_CACHE_MB=64"));
        let text = captured(|| effective.log());
        assert!(text.contains("effective configuration"), "{text}");
        assert!(text.contains("proof_slots_configured=6"), "{text}");
        assert!(text.contains("block_cache_total_mb=256"), "{text}");
        assert!(text.contains("worker_block_cache_mb=64 "), "{text}");
        assert!(text.contains("stderr_level=\"info\""), "{text}");
        let brief = effective.status_brief(Some(6));
        assert!(
            brief.contains("proof_slots=6") && brief.contains("workers=3"),
            "{brief}"
        );
    }

    /// Defaults apply to unset settings, and an archive runs no workers and
    /// sizes its own cache.
    #[test]
    fn defaults_and_archive_mode_resolve() {
        let config = config_from("p2p: {}\n");
        let mut archive = runtime(&[]);
        archive.archive = true;
        archive.store_cache_bytes = 4 << 30;
        let effective = EffectiveConfig::resolve(&config, &archive);
        assert_eq!(effective.mode, "archive");
        assert_eq!(effective.workers, 0);
        // A number on releases with a fixed default, `unset` where the node
        // chooses; both mean the operator wrote nothing.
        assert!(["2", "unset"].contains(&effective.proof_slots_configured.as_str()));
        assert!(archive_brief_has_no_slots(&effective));
        assert_eq!(effective.block_cache_mb, "4096", "an archive's own cache");
        assert_eq!(effective.block_cache_total_mb, 4096);
        assert_eq!(effective.env_overrides, "none");
        let regular = EffectiveConfig::resolve(&config, &runtime(&[]));
        assert_eq!(regular.workers, 7, "cpus - 1 when dataWorkerCount is unset");
        assert_eq!(
            regular.block_cache_total_mb, 1024,
            "master and 7 workers share the 1 GB budget"
        );
        assert_eq!(regular.block_cache_mb, "shared");
        assert_eq!(regular.worker_block_cache_mb, "shared");
        let mut worker = runtime(&[]);
        worker.core = 4;
        let effective = EffectiveConfig::resolve(&config, &worker);
        assert_eq!((effective.mode, effective.workers), ("worker", 0));
        assert_eq!(effective.block_cache_total_mb, 256, "its one store's share");
        assert_eq!(effective.block_cache_mb, "shared");
    }

    /// Without `QUIL_ROCKSDB_BLOCK_CACHE_MB` the stores share one cache: the
    /// line reports it once for the process, sized for its stores, not a
    /// cache per store; with it, each store's own cache and their sum.
    #[test]
    fn a_shared_block_cache_is_reported_once_per_process() {
        let thread =
            |workers: u32| config_from(&format!("engine:\n  dataWorkerCount: {workers}\n"));
        if std::env::var_os("QUIL_ROCKSDB_BLOCK_CACHE_MB").is_none()
            && std::env::var_os("QUIL_ROCKSDB_BLOCK_CACHE_TOTAL_MB").is_none()
        {
            let detected = Runtime::detect(0, 0, false, false);
            let effective = EffectiveConfig::resolve(&thread(15), &detected);
            let text = captured(|| effective.log());
            for shown in [
                " block_cache_mb=shared ",
                "worker_block_cache_mb=shared ",
                "block_cache_total_mb=1024 ",
            ] {
                assert!(text.contains(shown), "{shown} missing: {text}");
            }
            let worker = Runtime::detect(3, 0, false, false);
            let effective = EffectiveConfig::resolve(&thread(15), &worker);
            assert_eq!(effective.block_cache_total_mb, 256, "a worker process");
        }
        let few = EffectiveConfig::resolve(&thread(2), &runtime(&[]));
        assert_eq!(few.block_cache_total_mb, 768, "master and 2 workers");
        let mut own = runtime(&[]);
        own.shared_cache_bytes = |_| None;
        own.store_cache_bytes = 32 << 20;
        own.worker_cache_bytes = 32 << 20;
        let effective = EffectiveConfig::resolve(&thread(15), &own);
        assert_eq!(effective.block_cache_mb, "32");
        assert_eq!(effective.worker_block_cache_mb, "32");
        assert_eq!(effective.block_cache_total_mb, 32 * 16);
        own.archive = true;
        own.store_cache_bytes = 4 << 30;
        let effective = EffectiveConfig::resolve(&thread(15), &own);
        assert_eq!(
            effective.block_cache_total_mb, 4096,
            "an archive runs no workers"
        );
    }

    /// No private setting reaches the logged line, whatever the config and
    /// environment hold; overrides named like paths or addresses show only
    /// that they are set.
    #[test]
    fn no_private_value_reaches_the_line() {
        let config = config_from(
            "key:\n  keyStoreFile:\n    path: /srv/secret-key-dir/keys.yml\n    encryptionKey: ENCKEYSENTINEL\n\
             p2p:\n  peerPrivKey: PRIVKEYSENTINEL\n  listenMultiaddr: /ip4/10.9.8.7/tcp/9999\n  bootstrapPeers: [\"/ip4/10.1.2.3/tcp/1/p2p/BOOTPEERSENTINEL\"]\n\
             engine:\n  delegateAddress: DELEGATESENTINEL\n  alertKey: ALERTSENTINEL\n  genesisSeed: SEEDSENTINEL\n  provingKeyId: PROVINGIDSENTINEL\n  \
             archiveEndpoints: [\"ENDPOINTSENTINEL.example:8340\"]\n  dataWorkerFilters: [\"FILTERSENTINEL\"]\n  dataWorkerStreamMultiaddrs: [\"/ip4/10.4.4.4/tcp/5000\"]\n\
             db:\n  path: /srv/dbpath-sentinel\n\
             logger:\n  path: /srv/logpath-sentinel\n\
             proofWorker:\n  path: /srv/workerpath-sentinel\n\
             listenGrpcMultiaddr: /ip4/10.5.5.5/tcp/8337\n\
             explorer:\n  listenAddr: 10.6.6.6:8080\n\
             diagnostics:\n  logRequests:\n    enabled: true\n    allowedPeers: [PEERSENTINEL]\n",
        );
        let env = [
            ("QUIL_AMOUNT_WORKER_PATH", "/srv/envpath-sentinel/worker"),
            ("QUIL_SOMETHING_ENDPOINT", "10.7.7.7"),
            ("QUIL_NODE_SECRET", "ENVSECRETSENTINEL"),
            ("QUIL_SPLIT_MAX_PROVERS", "4"),
            ("QUIL_ROCKSDB_BLOCK_CACHE_TOTAL_MB", "512"),
            ("QUIL_FRAME_TIME_MS", "2500,10000@240"),
            ("QUIL_ODD_VALUE", "has spaces and /slashes"),
        ];
        let effective = EffectiveConfig::resolve(&config, &runtime(&env));
        let text = captured(|| effective.log());
        assert!(text.contains("effective configuration"), "{text}");
        assert!(text.contains("log_requests_enabled=true"), "{text}");
        assert!(text.contains("archive_endpoints_configured=1"), "{text}");
        assert!(text.contains("worker_layout=\"cluster\""), "{text}");
        for private in [
            "SENTINEL",
            "sentinel",
            "10.9.8.7",
            "10.1.2.3",
            "10.4.4.4",
            "10.5.5.5",
            "10.6.6.6",
            "10.7.7.7",
            "/srv/",
            "/ip4/",
            "example:8340",
            "spaces",
        ] {
            assert!(!text.contains(private), "{private} leaked: {text}");
        }
        for shown in [
            "QUIL_SPLIT_MAX_PROVERS=4",
            "QUIL_ROCKSDB_BLOCK_CACHE_TOTAL_MB=512",
            "QUIL_FRAME_TIME_MS=2500,10000@240",
            "QUIL_AMOUNT_WORKER_PATH=<set>",
            "QUIL_NODE_SECRET=<set>",
            "QUIL_ODD_VALUE=<set>",
        ] {
            assert!(text.contains(shown), "{shown} missing: {text}");
        }
    }

    /// The override list is bounded.
    #[test]
    fn many_overrides_are_counted_not_listed() {
        let names: Vec<(String, String)> = (0..40)
            .map(|i| (format!("QUIL_X{i:02}"), "1".to_string()))
            .collect();
        let rendered = render_env(&names);
        assert!(rendered.ends_with("+16_more"), "{rendered}");
        assert_eq!(rendered.matches("QUIL_X").count(), MAX_ENV_LISTED);
    }
}

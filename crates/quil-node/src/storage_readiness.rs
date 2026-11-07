//! Standalone, read-only-to-mainnet qualification of a blank node. The working
//! directory is new and isolated; no config, production DB or keystore opens.
use anyhow::{ensure, Context};
use clap::Args;
use quil_engine::{
    storage_readiness::{self as verdict, Evidence},
    storage_snapshot::BenchmarkOptions,
};
use quil_types::{
    crypto::Signer,
    proto::global::{GlobalFrame, GlobalFrameHeader},
};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

fn scheduled_benchmark_layers() -> u8 {
    quil_types::consensus::MAINNET_FAST_STORAGE_PROFILE
        .unwrap_or(quil_types::consensus::StorageSealProfile::Eleven)
        .layers() as u8
}

#[derive(Args, Debug)]
pub struct Arguments {
    /// Measure storage readiness on this disk, starting with an empty scratch directory; exit without joining mainnet.
    #[arg(long)]
    pub benchmark_storage: Option<PathBuf>,
    /// Benchmark this many largest reported live shards (explicit allocation filters take precedence).
    #[arg(
        long,
        requires = "benchmark_storage",
        conflicts_with = "benchmark_storage_filter"
    )]
    pub benchmark_storage_seats: Option<usize>,
    /// Exact intended shard filters, hex, comma-separated or repeated.
    #[arg(
        long,
        value_delimiter = ',',
        requires = "benchmark_storage",
        conflicts_with = "benchmark_storage_seats"
    )]
    pub benchmark_storage_filter: Vec<String>,
    /// Live mainnet sizing/selection API. Data roots are authenticated independently over archive RPC.
    #[arg(long, default_value = "https://explorer-api.quilibrium.com")]
    pub benchmark_storage_explorer: String,
    /// Archive endpoint=peer-id; repeat for failover. Defaults to the pinned genesis archive endpoints.
    #[arg(long, requires = "benchmark_storage")]
    pub benchmark_storage_archive: Vec<String>,
    /// Output artifact; defaults to WORKDIR/report.json.
    #[arg(long, requires = "benchmark_storage")]
    pub benchmark_storage_report: Option<PathBuf>,
    /// Persistent suite to rehearse; defaults to the scheduled mainnet profile.
    #[arg(long, default_value_t = scheduled_benchmark_layers(), requires = "benchmark_storage")]
    pub benchmark_storage_layers: u8,
    /// After measured rounds, time full sector regeneration without stored labels.
    /// This is a one-CPU diagnostic, not a GPU/ASIC or partial-storage security assessment.
    #[arg(long, requires = "benchmark_storage")]
    pub benchmark_storage_regeneration_probe: bool,
    /// Fully re-encode and prove every selected shard this many times (2..5).
    #[arg(long, default_value_t = 2)]
    pub benchmark_storage_rounds: usize,
    /// Settlement frame workload; reduced values are measurements only and cannot yield GO.
    #[arg(long, default_value_t = 720)]
    pub benchmark_storage_frames: usize,
    /// Multiply measured times by this operating headroom (at least 1).
    #[arg(long, default_value_t = 2.0)]
    pub benchmark_storage_headroom: f64,
    /// Assumed share of GLOBAL storage-message bytes for the modeled inclusion scenario (1..100).
    #[arg(long, default_value_t = 25, requires = "benchmark_storage")]
    pub benchmark_storage_network_share_percent: u8,
    /// Memory reserved for the node's other work, outside the benchmark's RSS budget.
    #[arg(long, default_value_t = 2)]
    pub benchmark_storage_reserve_memory_gib: u64,
    /// Maximum whole-run duration; zero uses the current coordinated warmup duration.
    #[arg(long, default_value_t = 0)]
    pub benchmark_storage_timeout_secs: u64,
    /// Maximum age of the finalized GLOBAL checkpoint at the start of the run.
    #[arg(long, default_value_t = 900)]
    pub benchmark_storage_checkpoint_age_secs: u64,
    /// Snapshot epoch to reproduce; defaults to the epoch after the authenticated GLOBAL head.
    #[arg(long, requires = "benchmark_storage")]
    pub benchmark_storage_epoch: Option<u64>,
    /// Allow running the harness in a debug build. Its verdict is always INCOMPLETE.
    #[arg(long, requires = "benchmark_storage")]
    pub benchmark_storage_allow_debug: bool,
}

fn validate(args: &Arguments) -> anyhow::Result<()> {
    ensure!(
        [2, 3, 11].contains(&args.benchmark_storage_layers),
        "storage layers must be 2, 3 or 11"
    );
    ensure!(
        (2..=5).contains(&args.benchmark_storage_rounds),
        "rounds must be between 2 and 5"
    );
    ensure!(
        args.benchmark_storage_frames > 0
            && args.benchmark_storage_frames <= quil_types::consensus::EPOCH_LENGTH_FRAMES as usize,
        "frames must be 1..720"
    );
    ensure!(
        (1..=100).contains(&args.benchmark_storage_network_share_percent),
        "network share must be between 1 and 100 percent"
    );
    ensure!(
        args.benchmark_storage_headroom.is_finite() && args.benchmark_storage_headroom >= 1.,
        "headroom must be finite and at least 1"
    );
    ensure!(
        args.benchmark_storage_seats.is_some_and(|n| n > 0)
            || !args.benchmark_storage_filter.is_empty(),
        "specify --benchmark-storage-seats N or --benchmark-storage-filter HEX,..."
    );
    ensure!(
        args.benchmark_storage_checkpoint_age_secs > 0,
        "checkpoint freshness bound must be positive"
    );
    ensure!(!cfg!(debug_assertions) || args.benchmark_storage_allow_debug,"use a release binary for production qualification; --benchmark-storage-allow-debug only exercises the harness");
    Ok(())
}
fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
fn freshness(timestamp: i64, now: i64, max_age: u64) -> anyhow::Result<()> {
    ensure!(
        timestamp > 0 && timestamp <= now.saturating_add(120_000),
        "checkpoint timestamp is missing or in the future"
    );
    ensure!(
        now.saturating_sub(timestamp).max(0) as u64 <= max_age.saturating_mul(1000),
        "archive checkpoint is stale: timestamp_ms={timestamp}, now_ms={now}, maximum_age_secs={max_age}"
    );
    Ok(())
}
async fn api_json(client: &reqwest::Client, url: &str) -> anyhow::Result<Value> {
    let mut response = client.get(url).send().await?.error_for_status()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= 2 << 20,
            "explorer response exceeds 2 MiB"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}
fn filter(bytes: &str) -> anyhow::Result<Vec<u8>> {
    let filter = hex::decode(bytes).context("invalid shard filter hex")?;
    ensure!(
        (32..=64).contains(&filter.len())
            && quil_forest::decode_shard_filter_or_root(&filter, 32).is_some(),
        "invalid canonical shard filter"
    );
    Ok(filter)
}
fn select(
    shards: &Value,
    seats: Option<usize>,
    explicit: &[String],
) -> anyhow::Result<Vec<Vec<u8>>> {
    let rows = shards
        .as_array()
        .context("explorer shard response is not an array")?;
    let live: std::collections::BTreeSet<_> =
        rows.iter().filter_map(|r| r["filter"].as_str()).collect();
    let mut selected = if !explicit.is_empty() {
        let mut out = Vec::new();
        for value in explicit {
            ensure!(
                live.contains(value.as_str()),
                "requested shard {value} is absent from the live explorer grid"
            );
            out.push(filter(value)?);
        }
        out
    } else {
        let n = seats.context("missing allocation size")?;
        ensure!(
            n > 0 && n <= rows.len(),
            "requested {n} seats, but the live grid has {} shards",
            rows.len()
        );
        let mut ranked = rows
            .iter()
            .map(|row| -> anyhow::Result<_> {
                let name = row["filter"].as_str().context("missing shard filter")?;
                let size = row["size_bytes"]
                    .as_str()
                    .context("missing shard size")?
                    .parse::<u64>()?;
                Ok((std::cmp::Reverse(size), name))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        ranked.sort();
        ranked
            .into_iter()
            .take(n)
            .map(|(_, f)| filter(f))
            .collect::<anyhow::Result<Vec<_>>>()?
    };
    let before = selected.len();
    selected.sort();
    selected.dedup();
    ensure!(before == selected.len(), "duplicate allocation filters");
    Ok(selected)
}
fn endpoints(args: &Arguments) -> anyhow::Result<Vec<(String, quil_p2p::PeerId)>> {
    if args.benchmark_storage_archive.is_empty() {
        quil_engine::genesis::genesis_archive_static_ips()
            .into_iter()
            .map(|(peer, ip)| {
                let addr = if ip.contains(':') {
                    format!("[{ip}]:8340")
                } else {
                    format!("{ip}:8340")
                };
                Ok((addr, peer.parse()?))
            })
            .collect()
    } else {
        args.benchmark_storage_archive
            .iter()
            .map(|entry| {
                let (host, peer) = entry
                    .rsplit_once('=')
                    .context("archive must be endpoint=peer-id")?;
                ensure!(!host.is_empty(), "empty archive endpoint");
                Ok((host.to_owned(), peer.parse()?))
            })
            .collect()
    }
}
fn snapshot_record(
    root: &[u8; 32],
    filter: &[u8],
    epoch: u64,
    head: u64,
    proof: &[u8],
) -> anyhow::Result<quil_types::consensus::StorageSnapshotRoots> {
    use quil_execution::{global_intrinsic::storage_snapshot as snapshots, global_schema};
    let address = snapshots::snapshot_address(epoch, filter)?;
    let vertex = quil_engine::storage_history::verify_global_vertex_proof(root, &address, proof)?;
    let tree = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(&vertex.vertex_blob)?,
    };
    ensure!(
        !tree.has_unbound_values() && global_schema::read_type(&tree) == Some(snapshots::CLASS),
        "snapshot record has unbound values or the wrong type"
    );
    let (held, snapshot) =
        snapshots::from_tree(&tree).context("malformed storage snapshot record")?;
    ensure!(
        held == filter
            && snapshot.epoch == epoch
            && snapshot.frame > 0
            && snapshot.frame < head
            && snapshot.anchor < head,
        "snapshot record names a different shard/epoch or a future frame"
    );
    Ok(snapshot)
}
fn verifier() -> anyhow::Result<quil_engine::frame_validator::GlobalFrameVerifier> {
    Ok(
        quil_engine::frame_validator::GlobalFrameVerifier::new(Arc::new(
            quil_crypto::WesolowskiFrameProver::new(2048),
        ))
        .with_global_committee(
            quil_engine::genesis::genesis_archive_peers()?
                .into_iter()
                .map(|(_, key)| key)
                .collect(),
        )
        .with_global_committee_successor(
            quil_engine::genesis::genesis_archive_successor_peers()?
                .into_iter()
                .map(|(_, key)| key)
                .collect(),
        ),
    )
}
fn authenticate(
    header: &GlobalFrameHeader,
    verify: &quil_engine::frame_validator::GlobalFrameVerifier,
    max_age: u64,
    explorer_frame: u64,
) -> anyhow::Result<()> {
    freshness(header.timestamp, now_ms(), max_age)?;
    ensure!(
        header.frame_number.saturating_add(120) >= explorer_frame,
        "archive is more than 120 frames behind the explorer"
    );
    ensure!(
        verify.verify_global_finalization_cert(header),
        "GLOBAL finalization certificate failed"
    );
    let cert = header
        .public_key_signature_bls48581
        .as_ref()
        .and_then(|s| quil_cw_consensus::app_cert::unwrap_cert_from_header(&s.signature))
        .context("missing GLOBAL certificate")?;
    let (epoch, committee) = verify.committee_for_frame(header.frame_number);
    let digest = quil_crypto::poseidon::hash_bytes_to_32(&header.output)?;
    let details = quil_cw_consensus::app_cert::verify_finalization_details(
        cert, committee, b"global", digest,
    )
    .context("GLOBAL certificate failed")?;
    ensure!(
        details.finalization.proposal.round.view().get() == header.rank
            && details.finalization.proposal.round.epoch().get() == epoch,
        "GLOBAL certificate view/epoch mismatch"
    );
    ensure!(
        verify.validate(&GlobalFrame {
            header: Some(header.clone()),
            requests: Vec::new()
        })?,
        "GLOBAL VDF/header commitment failed"
    );
    Ok(())
}
#[derive(Clone)]
struct Dataset {
    filter: Vec<u8>,
    snapshot: quil_types::consensus::StorageSnapshotRoots,
    path: PathBuf,
}
fn open_dataset(
    path: &Path,
) -> anyhow::Result<(
    Arc<quil_store::RocksDb>,
    Arc<quil_hypergraph::HypergraphCrdt>,
)> {
    std::fs::create_dir_all(path)?;
    let db = Arc::new(quil_store::RocksDb::open(path)?);
    let graph = crate::master_node::worker_manager::build_thread_worker_hypergraph(
        &db,
        Arc::new(quil_tries::ShaInclusionProver),
        false,
    );
    graph.set_unified_tree(true);
    Ok((db, graph))
}
async fn pull(dataset: &Dataset, archive: &str, key: &[u8]) -> anyhow::Result<()> {
    let (_db, graph) = open_dataset(&dataset.path)?;
    let (app, bits) = quil_forest::decode_shard_filter_or_root(&dataset.filter, 32)
        .context("invalid snapshot filter")?;
    let app: [u8; 32] = app
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid application address length"))?;
    let mut client = quil_rpc::ArchiveClient::connect_mtls(archive, key).await?;
    let handle = tokio::runtime::Handle::current();
    for (phase, root) in dataset.snapshot.roots.iter().enumerate() {
        if crate::forest_sync::is_empty_phase_root(root) {
            continue;
        }
        let (version, _) = client
            .resolve_root(dataset.filter.clone(), phase as u32, root.to_vec())
            .await?
            .with_context(|| {
                format!(
                    "archive does not retain phase {phase} root {}",
                    hex::encode(root)
                )
            })?;
        let got = crate::forest_sync::sync_subtree_one_phase(
            &mut client,
            &handle,
            &graph,
            &app,
            &dataset.filter,
            phase as u32,
            version,
            bits.clone(),
            Some(*root),
        )
        .await?;
        ensure!(
            got == *root,
            "downloaded shard root differs from its GLOBAL snapshot record"
        );
    }
    ensure!(
        graph
            .snapshot_versions(&app, bits.as_slice(), &dataset.snapshot.roots)
            .is_some(),
        "downloaded snapshot versions are incomplete"
    );
    Ok(())
}
fn rss_peak() -> Option<u64> {
    #[cfg(unix)]
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &mut usage) != 0 {
            return None;
        }
        #[cfg(target_os = "macos")]
        return Some(usage.ru_maxrss.max(0) as u64);
        #[cfg(not(target_os = "macos"))]
        return Some((usage.ru_maxrss.max(0) as u64).saturating_mul(1024));
    }
    #[cfg(not(unix))]
    None
}
struct Monitor {
    done: Arc<AtomicBool>,
    initial_setup_complete: Arc<AtomicBool>,
    initial_setup_seconds: Arc<AtomicU64>,
    started: Instant,
    initial_deadline_exceeded: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    exceeded: Arc<AtomicBool>,
    peak: Arc<AtomicU64>,
    min_free: Arc<AtomicU64>,
    memory_limit: u64,
    memory_budget: u64,
    initial_free: u64,
    disk_floor_bytes: u64,
}
impl Monitor {
    fn start(root: &Path, reserve: u64, timeout: Duration) -> anyhow::Result<Self> {
        let mut system = sysinfo::System::new();
        system.refresh_memory();
        let total = system.cgroup_limits().map_or(system.total_memory(), |c| {
            c.total_memory.min(system.total_memory())
        });
        ensure!(total > reserve, "memory reserve leaves no storage budget");
        let memory_budget = total - reserve;
        let usage = quil_forest::storage_health::fs_usage(root)
            .context("cannot measure benchmark filesystem space")?;
        let disk_floor_bytes = verdict::disk_floor(usage.total_bytes);
        let done = Arc::new(AtomicBool::new(false));
        let initial_setup_complete = Arc::new(AtomicBool::new(false));
        let initial_deadline_exceeded = Arc::new(AtomicBool::new(false));
        let deadline_exceeded = initial_deadline_exceeded.clone();
        let initial_setup_seconds = Arc::new(AtomicU64::new(0));
        let (ready, startup_seconds) = (
            initial_setup_complete.clone(),
            initial_setup_seconds.clone(),
        );
        let stop = Arc::new(AtomicBool::new(false));
        let exceeded = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicU64::new(0));
        let min_free = Arc::new(AtomicU64::new(usage.free_bytes));
        let (d, s, x, p, f, path) = (
            done.clone(),
            stop.clone(),
            exceeded.clone(),
            peak.clone(),
            min_free.clone(),
            root.to_path_buf(),
        );
        let start = Instant::now();
        let join = std::thread::spawn(move || {
            while !d.load(Ordering::Relaxed) {
                if let Some(rss) = rss_peak() {
                    p.fetch_max(rss, Ordering::Relaxed);
                    if rss > memory_budget {
                        x.store(true, Ordering::Relaxed);
                        s.store(true, Ordering::Relaxed);
                    }
                }
                if let Some(usage) = quil_forest::storage_health::fs_usage(&path) {
                    f.fetch_min(usage.free_bytes, Ordering::Relaxed);
                    if usage.free_bytes < disk_floor_bytes {
                        x.store(true, Ordering::Relaxed);
                        s.store(true, Ordering::Relaxed);
                    }
                }
                if ready.load(Ordering::Relaxed) {
                    let elapsed_ms = (start.elapsed().as_millis() as u64).max(1);
                    if startup_seconds
                        .compare_exchange(0, elapsed_ms, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                    {
                        let milestone = json!({"local_setup_complete":true,"local_setup_wall_seconds":elapsed_ms as f64 / 1000.,"budget_seconds":quil_types::consensus::INITIAL_STORAGE_SETUP_BUDGET_SECS,"global_inclusion":"reserved separately in assessment; not submitted"});
                        let temporary = path.join("initial-setup.json.tmp");
                        if std::fs::write(&temporary, milestone.to_string()).is_ok() {
                            let _ = std::fs::rename(temporary, path.join("initial-setup.json"));
                        }
                    }
                } else if verdict::initial_setup_expired(start.elapsed(), false) {
                    deadline_exceeded.store(true, Ordering::Relaxed);
                    x.store(true, Ordering::Relaxed);
                    s.store(true, Ordering::Relaxed);
                }
                if start.elapsed() > timeout {
                    x.store(true, Ordering::Relaxed);
                    s.store(true, Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        Ok(Self {
            done,
            initial_setup_complete,
            initial_setup_seconds,
            started: start,
            initial_deadline_exceeded,
            join: Some(join),
            stop,
            exceeded,
            peak,
            min_free,
            memory_limit: total,
            memory_budget,
            initial_free: usage.free_bytes,
            disk_floor_bytes,
        })
    }
    fn sample(&self) -> Value {
        json!({"initial_setup_complete":self.initial_setup_complete.load(Ordering::Relaxed),"initial_setup_wall_seconds":if self.initial_setup_seconds.load(Ordering::Relaxed)>0 {self.initial_setup_seconds.load(Ordering::Relaxed) as f64 / 1000.} else {self.started.elapsed().as_secs_f64()},"initial_setup_deadline_exceeded":self.initial_deadline_exceeded.load(Ordering::Relaxed),"initial_setup_budget_seconds":quil_types::consensus::INITIAL_STORAGE_SETUP_BUDGET_SECS,"effective_memory_limit_bytes":self.memory_limit,"storage_rss_budget_bytes":self.memory_budget,"peak_process_rss_bytes":self.peak.load(Ordering::Relaxed),
        "filesystem_free_floor_bytes":self.disk_floor_bytes,"filesystem_max_used_percent":99.9,"filesystem_free_before_bytes":self.initial_free,"filesystem_minimum_free_bytes":self.min_free.load(Ordering::Relaxed),"filesystem_free_space_delta_peak_bytes":self.initial_free.saturating_sub(self.min_free.load(Ordering::Relaxed)),"budget_exceeded":self.exceeded.load(Ordering::Relaxed)})
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}
fn collect_progress(directory: &Path) -> anyhow::Result<Value> {
    let mut records = Vec::new();
    if directory.exists() {
        let mut paths = Vec::new();
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                paths.extend(
                    std::fs::read_dir(entry.path())?
                        .filter_map(|e| e.ok())
                        .map(|e| e.path()),
                );
            } else {
                paths.push(entry.path());
            }
        }
        paths.sort();
        for path in paths {
            if path.extension().is_some_and(|e| e == "json") {
                let record: Value = serde_json::from_slice(&std::fs::read(path)?)?;
                records.push(record);
            }
        }
    }
    Ok(
        json!({"directory":directory,"records":records,"qualification":"partial records never substitute for a completed allocation"}),
    )
}

fn save(path: &Path, report: &Value) -> anyhow::Result<()> {
    let tmp = path.with_extension("json.tmp");
    let mut file = std::fs::File::create(&tmp)?;
    serde_json::to_writer_pretty(&mut file, report)?;
    std::io::Write::write_all(&mut file, b"\n")?;
    file.sync_all()?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

pub async fn run(args: &Arguments) -> anyhow::Result<ExitCode> {
    validate(args)?;
    let root = args
        .benchmark_storage
        .as_ref()
        .context("missing scratch directory")?;
    ensure!(!root.exists() || std::fs::read_dir(root)?.next().is_none(),"benchmark directory must be empty; existing input/output is never reused for a cold qualification");
    std::fs::create_dir_all(root)?;
    let artifact = args
        .benchmark_storage_report
        .clone()
        .unwrap_or_else(|| root.join("report.json"));
    let frame_seconds = quil_types::consensus::IDEAL_FRAME_TIME_MS as f64 / 1000.;
    let warmup_frames = quil_types::consensus::PERSISTENT_STORAGE_WARMUP_EPOCHS
        * quil_types::consensus::epoch_length_frames();
    let timeout = Duration::from_secs(if args.benchmark_storage_timeout_secs == 0 {
        warmup_frames.saturating_mul(10)
    } else {
        args.benchmark_storage_timeout_secs
    });
    let monitor = Monitor::start(
        root,
        args.benchmark_storage_reserve_memory_gib
            .checked_mul(1 << 30)
            .context("memory reserve overflow")?,
        timeout,
    )?;
    let mut report = json!({"format":"quil-storage-readiness-v3","verdict":"incomplete","scope":"persistent-storage hardware rehearsal at one authenticated mainnet checkpoint; GLOBAL inclusion and concurrent node work are reserved, not submitted or measured",
        "started_at":chrono::Utc::now().to_rfc3339(),"build":{"version":quil_config::display_version(),"optimized":!cfg!(debug_assertions),"arch":std::env::consts::ARCH,"os":std::env::consts::OS},
        "available_cpus":std::thread::available_parallelism().map(|n|n.get()).unwrap_or(1),"rounds_requested":args.benchmark_storage_rounds,"settlement_frames_requested":args.benchmark_storage_frames,
        "headroom_multiplier":args.benchmark_storage_headroom,"modeled_network_share_percent":args.benchmark_storage_network_share_percent,"input_mode":"download_actual_authenticated_mainnet_snapshots","cache_condition":"OS page cache is not globally cleared; all rounds force full input reads and fresh replica outputs",
        "experimental_profile":args.benchmark_storage_layers != 11,"initial_setup_budget_seconds":quil_types::consensus::INITIAL_STORAGE_SETUP_BUDGET_SECS,"seal_profile_layers":args.benchmark_storage_layers as usize,"measurements":[],"phase":"starting"});
    save(&artifact, &report)?;
    let outcome = run_inner(
        args,
        root,
        &artifact,
        &monitor,
        &mut report,
        frame_seconds,
        warmup_frames,
    )
    .await;
    if let Err(error) = &outcome {
        report["verdict"] = json!(if monitor.exceeded.load(Ordering::Relaxed)
            || report["phase"] == "measuring_production_storage_paths"
        {
            "no_go"
        } else {
            "incomplete"
        });
        report["error"] = json!(
            if monitor.initial_deadline_exceeded.load(Ordering::Relaxed) {
                format!("initial local setup exceeded 7200 seconds: {error:#}")
            } else {
                format!("{error:#}")
            }
        );
    }
    if monitor.exceeded.load(Ordering::Relaxed) && report["verdict"] == "go_for_checkpoint" {
        report["verdict"] = json!("no_go");
    }
    report["resources"] = monitor.sample();
    report["local_startup"] = json!({
        "complete":monitor.initial_setup_complete.load(Ordering::Relaxed),
        "wall_seconds":report["resources"]["initial_setup_wall_seconds"],
        "budget_seconds":quil_types::consensus::INITIAL_STORAGE_SETUP_BUDGET_SECS,
        "verdict":if monitor.initial_deadline_exceeded.load(Ordering::Relaxed)
            || monitor.initial_setup_seconds.load(Ordering::Relaxed) > quil_types::consensus::INITIAL_STORAGE_SETUP_BUDGET_SECS * 1000 { "no_go" }
            else if monitor.initial_setup_complete.load(Ordering::Relaxed) && !cfg!(debug_assertions) { "go_for_checkpoint" }
            else { "incomplete" },
        "scope":"measured local work through verified first registration; no GLOBAL inclusion"});
    let compute = quil_crypto::storage_proof::label_compute_metrics();
    report["label_compute"] = json!({"packing_width":compute.packing_width,"graphs_built":compute.graphs_built,
        "resident_graphs_built":compute.resident_graphs_built,"graph_cache_hits":compute.graph_cache_hits,
        "resident_columns_created":compute.resident_columns_created,"scalar_batches":compute.scalar_batches,"packed_batches":compute.packed_batches});
    match collect_progress(&root.join("storage/progress")) {
        Ok(progress) => report["progress"] = progress,
        Err(error) => {
            report["progress_read_error"] = json!(error.to_string());
            if report["verdict"] == "go_for_checkpoint" {
                report["verdict"] = json!("incomplete");
            }
        }
    }
    report["finished_at"] = json!(chrono::Utc::now().to_rfc3339());
    if monitor.peak.load(Ordering::Relaxed) == 0 && report["verdict"] == "go_for_checkpoint" {
        report["verdict"] = json!("incomplete");
        report["error"] = json!("RSS measurement was unavailable");
    }
    save(&artifact, &report)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    eprintln!(
        "Storage readiness: {}; artifact {}",
        report["verdict"],
        artifact.display()
    );
    Ok(match report["verdict"].as_str() {
        Some("go_for_checkpoint") => ExitCode::SUCCESS,
        Some("no_go") => ExitCode::from(2),
        _ => ExitCode::from(3),
    })
}
async fn run_inner(
    args: &Arguments,
    root: &Path,
    artifact: &Path,
    monitor: &Monitor,
    report: &mut Value,
    frame_seconds: f64,
    warmup_frames: u64,
) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let base = args.benchmark_storage_explorer.trim_end_matches('/');
    eprintln!("storage benchmark: fetching live mainnet allocation sizes");
    let stats = api_json(&client, &format!("{base}/stats")).await?;
    let grid = api_json(&client, &format!("{base}/provers/shards")).await?;
    let explorer_frame = stats["current_frame"]
        .as_u64()
        .context("explorer has no current frame")?;
    let filters = select(
        &grid,
        args.benchmark_storage_seats,
        &args.benchmark_storage_filter,
    )?;
    report["selection"] = json!({"explorer":base,"explorer_frame":explorer_frame,"policy":if args.benchmark_storage_filter.is_empty(){"largest reported live shards"}else{"explicit allocation"},"filters":filters.iter().map(hex::encode).collect::<Vec<_>>()});
    save(artifact, report)?;
    let archives = endpoints(args)?;
    ensure!(!archives.is_empty(), "no archive endpoints");
    for (endpoint, peer) in &archives {
        // A conflicting entry keeps the first pin: its dial fails.
        let _ = quil_rpc::archive_client::pin_archive_peer(endpoint, *peer);
    }
    let signer = quil_crypto::FalconSigner::generate();
    let key = signer.private_key();
    let verify = verifier()?;
    let mut selected = None;
    let mut failures = Vec::new();
    for (endpoint, _) in &archives {
        let result = async {
            let mut client = quil_rpc::ArchiveClient::connect_mtls(endpoint, key).await?;
            let frame = client.get_global_head(u64::MAX).await?;
            let header = frame.header.context("missing GLOBAL header")?;
            authenticate(
                &header,
                &verify,
                args.benchmark_storage_checkpoint_age_secs,
                explorer_frame,
            )?;
            Ok::<_, anyhow::Error>(header)
        }
        .await;
        match result {
            Ok(header) => {
                selected = Some((endpoint.clone(), header));
                break;
            }
            Err(e) => failures.push(format!("{endpoint}: {e:#}")),
        }
    }
    let (endpoint, header) = selected.with_context(|| {
        format!(
            "no archive supplied a fresh authenticated checkpoint: {}",
            failures.join("; ")
        )
    })?;
    let epoch = args
        .benchmark_storage_epoch
        .unwrap_or(quil_types::consensus::epoch_for_frame(header.frame_number) + 1);
    let prover_root: [u8; 32] = header
        .prover_tree_commitment
        .as_slice()
        .try_into()
        .context("GLOBAL prover root length")?;
    use base64::Engine as _;
    use prost::Message as _;
    report["checkpoint"] = json!({"global_frame":header.frame_number,"timestamp_ms":header.timestamp,"global_prover_root":hex::encode(prover_root),"snapshot_epoch":epoch,
        "header_protobuf_base64":base64::engine::general_purpose::STANDARD.encode(header.encode_to_vec()),"archive":endpoint,"certificate_and_vdf_verified":true});
    report["phase"] = json!("downloading_authenticated_snapshots");
    save(artifact, report)?;
    let download = Instant::now();
    let mut datasets = Vec::new();
    let mut records = Vec::new();
    let intended_shards = filters.len();
    use futures::{stream, StreamExt};
    let global_frame = header.frame_number;
    let archive_list = &archives;
    let downloads = stream::iter(filters.into_iter().map(|filter| async move {
        let archives = archive_list;
        ensure!(
            !monitor.stop.load(Ordering::Relaxed),
            "benchmark resource/time limit reached"
        );
        let address =
            quil_execution::global_intrinsic::storage_snapshot::snapshot_address(epoch, &filter)?;
        let mut snapshot = None;
        let mut errors = Vec::new();
        for (peer, _) in archives {
            let result = async {
                let mut client = quil_rpc::ArchiveClient::connect_mtls(peer, key).await?;
                let proof = client
                    .get_global_vertex_proof(prover_root, address, false)
                    .await?
                    .context("archive lacks this snapshot record at the checkpoint")?;
                let value =
                    snapshot_record(&prover_root, &filter, epoch, global_frame, &proof)?;
                Ok::<_, anyhow::Error>((value, proof))
            }
            .await;
            match result {
                Ok(value) => {
                    snapshot = Some(value);
                    break;
                }
                Err(e) => errors.push(format!("{peer}: {e:#}")),
            }
        }
        let (snapshot, proof) = snapshot.with_context(|| {
            format!(
                "cannot authenticate snapshot {} for epoch {epoch}: {}",
                hex::encode(&filter),
                errors.join("; ")
            )
        })?;
        let dataset = Dataset {
            path: root.join("input").join(hex::encode(&filter)),
            filter,
            snapshot,
        };
        eprintln!(
            "storage benchmark: downloading {} at its authenticated snapshot roots",
            hex::encode(&dataset.filter)
        );
        let mut served = None;
        let mut errors = Vec::new();
        for (peer, _) in archives {
            match pull(&dataset, peer, key).await {
                Ok(()) => {
                    served = Some(peer.clone());
                    break;
                }
                Err(e) => errors.push(format!("{peer}: {e:#}")),
            }
        }
        let served = served.with_context(|| {
            format!(
                "no archive retains the exact snapshot: {}",
                errors.join("; ")
            )
        })?;
        let record = json!({"filter":hex::encode(&dataset.filter),"epoch":epoch,"frame":dataset.snapshot.frame,"roots":dataset.snapshot.roots.iter().map(hex::encode).collect::<Vec<_>>(),"membership_proof_hex":hex::encode(proof),"downloaded_from":served,"root_match":true});
        Ok::<_,anyhow::Error>((dataset,record))
    })).buffer_unordered(quil_engine::storage_jobs::job_slots());
    futures::pin_mut!(downloads);
    while let Some(result) = tokio::select! {
        result = downloads.next() => result,
        _ = async {
            while !monitor.stop.load(Ordering::Relaxed) { tokio::time::sleep(Duration::from_millis(100)).await; }
        } => anyhow::bail!("benchmark resource/time limit reached while downloading authenticated inputs"),
    } {
        let (dataset, record) = result?;
        records.push(record);
        report["snapshots"] = json!(&records);
        save(artifact, report)?;
        datasets.push(dataset);
    }
    datasets.sort_by(|a, b| a.filter.cmp(&b.filter));
    let download_seconds = download.elapsed().as_secs_f64();
    report["download_seconds"] = json!(download_seconds);
    report["phase"] = json!("measuring_production_storage_paths");
    save(artifact, report)?;
    let member = quil_execution::global_intrinsic::materialize::prover_address_from_pubkey(
        signer.public_key(),
    )?;
    let profile = quil_types::consensus::StorageSealProfile::from_layers(
        args.benchmark_storage_layers as usize,
    )
    .context("unsupported seal profile")?;
    report["seal_profile_layers"] = json!(profile.layers());
    report["experimental_profile"] =
        json!(profile != quil_types::consensus::StorageSealProfile::Eleven);
    let options = BenchmarkOptions {
        profile,
        initial_setup_complete: monitor.initial_setup_complete.clone(),
        regeneration_probe: Arc::new(AtomicBool::new(args.benchmark_storage_regeneration_probe)),
        directory: root.join("storage"),
        member,
        beacon: quil_crypto::porep::derive_storage_beacon(header.frame_number, &header.output),
        rounds: args.benchmark_storage_rounds,
        frames: args.benchmark_storage_frames,
        memory_budget_bytes: monitor.memory_budget,
        stop: monitor.stop.clone(),
    };
    report["parallel_storage_jobs"] = json!(quil_engine::storage_jobs::job_slots());
    save(artifact, report)?;
    let (measured, allocation) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let mut inputs = Vec::with_capacity(datasets.len());
        for dataset in datasets {
            let (db, graph) = open_dataset(&dataset.path)?;
            inputs.push(quil_engine::storage_snapshot::BenchmarkInput {
                crdt: graph,
                snapshot: dataset.snapshot,
                filter: dataset.filter,
                keep: Box::new(db),
            });
        }
        Ok(quil_engine::storage_snapshot::measure_allocation(
            inputs, &options,
        )?)
    })
    .await??;
    report["measurements"] = serde_json::to_value(&measured)?;
    report["allocation_measurements"] = serde_json::to_value(&allocation)?;
    report["resources"] = monitor.sample();
    save(artifact, report)?;
    let epoch_length = quil_types::consensus::epoch_length_frames();
    let (start, end) = quil_execution::global_intrinsic::storage_seat::settlement_window(epoch);
    let assessment = verdict::assess(Evidence {
        measurements: &measured,
        allocation: Some(&allocation),
        expected_shards: intended_shards,
        roots_verified: records.iter().all(|r| r["root_match"] == true),
        release_build: !cfg!(debug_assertions),
        expected_rounds: args.benchmark_storage_rounds,
        frame_count: args.benchmark_storage_frames,
        expected_frame_count: epoch_length as usize,
        download_seconds,
        frame_seconds,
        warmup_frames,
        registration_frames: quil_engine::app_shard_metadata::storage_snapshot_grace(),
        settlement_frames: end.saturating_sub(start),
        initial_local_setup_seconds: Some(monitor.initial_setup_seconds.load(Ordering::Relaxed))
            .filter(|&ms| ms > 0)
            .map(|ms| ms as f64 / 1000.),
        network_share_percent: args.benchmark_storage_network_share_percent,
        headroom: args.benchmark_storage_headroom,
        resource_exceeded: monitor.exceeded.load(Ordering::Relaxed),
    });
    report["verdict"] = serde_json::to_value(assessment.verdict)?;
    report["assessment"] = serde_json::to_value(assessment)?;
    report["phase"] = json!("complete");
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod progress_tests {
    use super::*;
    #[test]
    fn final_report_collects_atomic_checkpoints_and_ignores_unfinished_writes() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("shard")).unwrap();
        std::fs::write(
            dir.path().join("shard/sector.json"),
            br#"{"stage":"certificate_proof","layers_completed":3}"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("shard/sector.json.tmp"), b"partial").unwrap();
        let report = collect_progress(dir.path()).unwrap();
        assert_eq!(report["records"].as_array().unwrap().len(), 1);
        assert_eq!(report["records"][0]["layers_completed"], 3);
    }
}

//! The storage-readiness benchmark's flags, flattened into the node's
//! command line.

use std::path::PathBuf;

use clap::Args;

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

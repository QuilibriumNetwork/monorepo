//! quil-node's command line: the definition the binary parses with, so
//! tests and tools run the real parser.

use std::path::PathBuf;

use clap::Parser;

pub mod storage_readiness;

/// Quilibrium Node — Rust implementation
#[derive(Parser, Debug)]
#[command(name = "quil-node", version = quil_config::display_version(), about)]
pub struct Args {
    #[command(flatten)]
    pub storage_readiness: storage_readiness::Arguments,
    /// Configuration directory path
    #[arg(short, long, default_value = ".config")]
    pub config: PathBuf,

    /// CPU core affinity (0 = master, >0 = worker)
    #[arg(long, default_value_t = 0)]
    pub core: u32,

    /// Parent process PID (for worker-to-master communication)
    #[arg(long, default_value_t = 0)]
    pub parent_process: u32,

    /// Run as DHT bootstrap peer only
    #[arg(long)]
    pub dht_only: bool,

    /// Network ID (0 = mainnet, 1 = primary testnet)
    #[arg(long, default_value_t = 0)]
    pub network: u8,

    /// Enable debug logging
    #[arg(long)]
    pub debug: bool,

    /// Archive mode
    #[arg(long)]
    pub archive: bool,

    /// Import a Pebble database export file into RocksDB
    #[arg(long)]
    pub import_db: Option<PathBuf>,

    /// Verify a migrated RocksDB is valid/accepted by the node's loaders
    /// and validators (trie root, frame, QC/TC, certified state), then
    /// exit. Empty path uses config.db.path.
    #[arg(long)]
    pub verify_db: Option<PathBuf>,

    /// Convert the node's current KZG state DB (config.db.path) into a fresh
    /// JMT forest DB at the given destination path, then exit. The forest is
    /// the hash-Merkle state tree; the destination MUST be a new/empty
    /// path (its key-space collides with the source DB's).
    #[arg(long)]
    pub migrate_db: Option<PathBuf>,

    /// OFFLINE dry-run of the unified split reset against a snapshot DB (the given
    /// path, or config.db.path). Reports the BEFORE grid + prover state, runs the
    /// flag-day reset (QUIL grid → genesis + prover-tree wipe/rebuild), reports the
    /// AFTER state, then exits. Destructive on the DB — point it at a COPY of a
    /// mainnet snapshot. Never connects to the network.
    #[arg(long)]
    pub dry_run_reset: Option<PathBuf>,

    /// The simulated cutover frame for `--dry-run-reset` (0 ⇒ head + 1).
    #[arg(long, default_value_t = 0)]
    pub dry_run_reset_frame: u64,

    /// OFFLINE READ-ONLY dump of the QUIL shard grid, prover allocations (by
    /// confirmation_filter), pending changes, and reset markers (the given path, or
    /// config.db.path), then exit. NEVER writes — safe to run on a shut-down archive
    /// while the network keeps running on the others.
    #[arg(long)]
    pub dump_shard_state: Option<PathBuf>,

    /// OFFLINE READ-ONLY generation-zero migration preflight of a STOPPED node's
    /// master store: one JSON line per registered application shard (committee
    /// and certificate compatibility, roots, outgoing-history availability,
    /// handoff status, blockers), bound to one checkpoint. NEVER writes and never
    /// copies the store.
    #[arg(long)]
    pub gen0_preflight: Option<PathBuf>,

    /// Worker stores (comma-separated) searched for application frames and their
    /// history records alongside the master, for --gen0-preflight.
    #[arg(long, value_delimiter = ',')]
    pub gen0_preflight_workers: Vec<PathBuf>,

    /// Frames of outgoing history checked below each shard's head (--gen0-preflight).
    #[arg(long, default_value_t = 64)]
    pub gen0_preflight_window: u64,

    /// Resume --gen0-preflight after this shard filter (hex); requires
    /// --gen0-preflight-checkpoint from the interrupted run's header line.
    #[arg(long)]
    pub gen0_preflight_resume_after: Option<String>,

    /// Refuse to run --gen0-preflight unless the stores are at this checkpoint.
    #[arg(long)]
    pub gen0_preflight_checkpoint: Option<String>,

    /// --gen0-preflight of an archive that is not a committee member: its
    /// materialized cursor and history records, which lag its clock head under
    /// sequenced ingest, are reported as notes instead of blockers.
    #[arg(long)]
    pub gen0_preflight_archive: bool,

    /// --gen0-preflight of a RUNNING node's stores: open each read-only beside
    /// the node (no lock, every file held open) and report that point-in-time
    /// view. Never writes the node's stores; cannot be resumed (the checkpoint
    /// moves).
    #[arg(long)]
    pub gen0_preflight_live: bool,

    /// Read-only evidence for a GLOBAL halt from this store (a master store
    /// path): the head, the parent records the next frame binds, candidates
    /// above the head, and GLOBAL's committee. One JSON line; compare it
    /// across archives stopped at the same head. With --gen0-preflight-live,
    /// opens beside a running node.
    #[arg(long)]
    pub global_halt_report: Option<PathBuf>,

    /// Read-only listing of the GLOBAL prover shard's records in this store
    /// (a master store path): one sorted `address length sha256` line each,
    /// then a summary. Diff two archives' listings to find the records their
    /// prover roots disagree on.
    #[arg(long)]
    pub prover_shard_dump: Option<PathBuf>,

    /// With --prover-shard-dump: decode these record addresses (hex,
    /// comma-separated) field by field instead of listing every record.
    #[arg(long, value_delimiter = ',')]
    pub prover_shard_show: Vec<String>,

    /// Read-only history of the last GLOBAL frames in this store (a master
    /// store path): each frame's requests with the outcome this node recorded,
    /// and, for the records named by --prover-shard-show, each value they held
    /// after each frame. JSON lines; diff two archives' output. Starts at
    /// --history-from (default: seven frames below the head).
    #[arg(long)]
    pub global_frame_history: Option<PathBuf>,

    /// With --global-frame-history: the first frame to report.
    #[arg(long)]
    pub history_from: Option<u64>,

    /// OFFLINE one-time reclaim of the orphaned pre-cutover QUIL forest trees (the
    /// per-prefix byte-suffix trees the unified-tree consolidation copied from but
    /// never deleted). Streaming range-delete + compact; asserts the unified app
    /// root is unchanged (no consensus effect). Destructive — run with the node
    /// shut down. Empty path uses config.db.path. Idempotent (marker-gated).
    #[arg(long)]
    pub reclaim_legacy_forest: Option<PathBuf>,

    /// LIVE check: connect to an archive over :8340 Falcon-mTLS, pull its head
    /// global frame, and run the root-addressed prover-tree sync against it into a
    /// fresh in-memory forest — verifying the synced root == the frame's
    /// prover_tree_commitment. Pass `ip:8340` for a specific archive, or the flag
    /// alone to use engine.archiveEndpoints / the embedded genesis archives.
    /// Read-only against the archive; then exit.
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    pub test_prover_sync: Option<String>,

    /// LIVE GetAppShards query of the QUIL grid from an archive over :8340 (remote
    /// equivalent of --dump-shard-state's grid view: per-shard prefix, size,
    /// data_shards, materialized/latest frame). Pass `ip:8340`, or the flag alone
    /// for engine.archiveEndpoints / embedded genesis archives. Read-only; then exit.
    #[arg(long, num_args = 0..=1, default_missing_value = "")]
    pub query_shards: Option<String>,

    /// LIVE read-only query of another node (`ip:8340`): its GLOBAL head and
    /// GLOBAL prover shard root, over the :8340 mTLS transport with this
    /// node's Falcon identity. One JSON line, then exit.
    #[arg(long)]
    pub query_prover_root: Option<String>,

    /// OFFLINE repair: replace this master store's GLOBAL prover shard with the
    /// one --adopt-from holds at --adopt-root, via the node's root-addressed
    /// sync. The root must be the state after this store's head frame. Dry run
    /// (lists the records that would change) unless --adopt-commit, which
    /// needs the node stopped. Needs --config for the :8340 identity.
    #[arg(long)]
    pub adopt_prover_root: Option<PathBuf>,

    /// With --adopt-prover-root: the archive to pull from (`ip:8340`).
    #[arg(long, default_value = "")]
    pub adopt_from: String,

    /// With --adopt-prover-root: the prover root to adopt (hex).
    #[arg(long, default_value = "")]
    pub adopt_root: String,

    /// With --adopt-prover-root: write to the store (otherwise a dry run).
    #[arg(long)]
    pub adopt_commit: bool,

    /// With --adopt-prover-root: accept a root held at a frame other than the
    /// store's head. For localnet tests only.
    #[arg(long, hide = true)]
    pub adopt_any_frame: bool,

    /// Archive-only: convert pre-2.1 verenc coins in the DB (config.db.path, or
    /// the given path) into compact transparent public token entries and refresh
    /// the lattice shadow-accumulator root, then exit. Deterministic and
    /// consensus-safe; run once at the flag frame. Empty path uses config.db.path.
    #[arg(long)]
    pub migrate_legacy: Option<PathBuf>,

    /// Archive-only: recompute the coin-conservation receipt from the migrated
    /// TRANSPARENT coin set and rewrite it, then exit. Use when a legacy
    /// migration was STOPPED AND RESTARTED: the receipt then records only the
    /// final run's slice (the state is complete, but `--verify-db`'s conservation
    /// check would flag the undercount). Read-mostly — only the receipt vertex is
    /// written; refuses to shrink a receipt. Empty path uses config.db.path.
    #[arg(long)]
    pub repair_receipt: Option<PathBuf>,

    /// Diagnose the consensus bootstrap root: replay the latest-QC
    /// candidate-frame lookup and report whether the forks-root identity
    /// (Poseidon of the frame output) matches the QC selector the leader
    /// resolves its parent by. Empty path uses config.db.path. Read-only.
    #[arg(long)]
    pub check_bootstrap: Option<PathBuf>,

    /// Diagnose prover-message submission to an archive. Connects to the
    /// given `host:8340` over Ed448 mTLS and submits a no-op ProverJoin
    /// bundle, reporting where the path breaks (handshake vs RPC). Use a
    /// known archive, e.g. `--check-submit 192.69.222.130:8340`.
    #[arg(long)]
    pub check_submit: Option<String>,

    /// Dump a ladder of stored global-frame fingerprints (frame, rank,
    /// poseidon(output)) at back-off offsets from the head, then exit.
    /// Run on every archive and diff the outputs to find where their chains
    /// forked; the deepest frame all still share is the re-bootstrap
    /// checkpoint. Empty path uses config.db.path. Read-only.
    #[arg(long)]
    pub fork_ladder: Option<PathBuf>,

    /// Optional comma-separated back-off offsets for `--fork-ladder`
    /// (e.g. `0,1000,30000,31000,32000`). Default is a wide ladder.
    #[arg(long)]
    pub fork_ladder_offsets: Option<String>,

    /// Print the peer ID to stdout and exit
    #[arg(long)]
    pub peer_id: bool,

    /// Print node info (version, prover address, frame) and exit
    #[arg(long)]
    pub node_info: bool,

    /// Ensure the node's identity keys exist (Ed448 seniority-root peer key +
    /// the unified Falcon-512 `q-prover-key`), then print machine-readable
    /// `PEER_ID=<base58>` (derived from the FALCON network identity),
    /// `ED448_PEER_ID=<base58>` (the seniority-root id), `BLS_PUBKEY`,
    /// `CONSENSUS_PUBKEY`, and `PROVER_ADDRESS` lines and exit. Used by
    /// `scripts/localnet.sh` to assemble a genesis seed + peer multiaddrs.
    #[arg(long)]
    pub print_identity: bool,

    /// Ensure all standard keys exist in `keys.yml` (creating any missing —
    /// including the unified Falcon-512 `q-prover-key`, which is BOTH the prover
    /// and the commonware-simplex consensus committee identity), then print
    /// `CONSENSUS_PUBKEY=<hex>` and exit. Does NOT open the state DB
    /// or start the node — a lightweight keys-only mode (mirrors Go's
    /// `--generate-keys`). Safe to run against a stopped node's config.
    #[arg(long)]
    pub generate_keys: bool,

    /// With `--generate-keys`: create or replace the prover key and create
    /// the peer key although the config directory or store shows this node
    /// already had an identity. Its seats and seniority stay on the old one.
    /// A one-time run, so that no setting hides the next accident; a replaced
    /// key stays in the keystore as a `-legacy` entry.
    #[arg(long, requires = "generate_keys")]
    pub allow_new_identity: bool,

    /// Print peer info and exit
    #[arg(long)]
    pub peer_info: bool,

    /// Fetch prometheus metrics from the RUNNING node (over its gRPC
    /// GetMetrics on listenGrpcMultiaddr), print, and exit
    #[arg(long)]
    pub metrics: bool,

    /// Filter metrics output by substring match
    #[arg(long)]
    pub metrics_filter: Option<String>,

    /// Live metrics dashboard: attach to the RUNNING node's gRPC and watch
    /// every metric (p2p connections, blossomsub mesh/grafts/prunes, RPC
    /// requests, consensus) with rates, sections, and filtering. Keys:
    /// `/` filter, Tab section, s sort, p pause, q quit.
    #[arg(long)]
    pub metrics_tui: bool,

    /// Write CPU profile to file
    #[arg(long)]
    pub cpuprofile: Option<PathBuf>,

    /// Write memory profile to file after 20 minutes
    #[arg(long)]
    pub memprofile: Option<PathBuf>,

    /// Enable prometheus metrics server on specified address (e.g. localhost:8080)
    #[arg(long)]
    pub prometheus_server: Option<String>,

    /// Enable or disable signature validation (default true, override
    /// with `QUILIBRIUM_SIGNATURE_CHECK=false` or
    /// `--signature-check=false`). Both flag and env must be set with
    /// an explicit value — bare `--signature-check` is not accepted.
    #[arg(
        long,
        env = "QUILIBRIUM_SIGNATURE_CHECK",
        default_value_t = true,
        action = clap::ArgAction::Set,
    )]
    pub signature_check: bool,

    /// Per-component log levels, comma-separated (e.g. "bootstrap=debug,peer_monitor=warn")
    #[arg(long)]
    pub log_filter: Option<String>,
}

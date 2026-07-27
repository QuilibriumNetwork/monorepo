//! `--fork-ladder`: dump a ladder of stored global-frame fingerprints so two
//! archives' outputs can be diffed to find WHERE their chains forked.
//!
//! The global consensus fork (nodes finalizing conflicting states at the same
//! rank) means every node holds a different chain in its clock store. For each
//! frame number in a back-off ladder from the local head, this prints
//! `(frame, rank, fp)` where `fp = poseidon(header.output)` — a deterministic
//! per-frame fingerprint. Run it on every archive; diff the outputs top to
//! bottom. The deepest frame where ALL nodes still share the same `fp` is the
//! last commonly-agreed frame — the safe re-bootstrap checkpoint `N`.
//!
//! Read-only; opens the DB, prints to stdout, exits. Modelled on
//! `check_bootstrap`. Offsets are configurable (comma-separated) so the ladder
//! can be widened/narrowed once the split is bracketed.

use std::path::Path;

use quil_types::store::ClockStore;

/// Default back-off offsets from the local head frame.
const DEFAULT_OFFSETS: &[u64] = &[
    0, 10, 100, 1000, 5000, 10_000, 20_000, 30_000, 31_000, 32_000, 50_000, 100_000,
];

fn poseidon_hex(output: &[u8]) -> String {
    quil_crypto::poseidon::hash_bytes_to_32(output)
        .map(hex::encode)
        .unwrap_or_default()
}

/// Run the fork-ladder dump. `db_path` empty → `config.db.path`. `offsets_csv`
/// empty/None → [`DEFAULT_OFFSETS`]; otherwise a comma-separated list of u64
/// back-off offsets from the head frame.
pub fn run_fork_ladder(
    db_path: &Path,
    config: &quil_config::Config,
    offsets_csv: Option<&str>,
) -> anyhow::Result<()> {
    let path = if db_path.as_os_str().is_empty() {
        std::path::PathBuf::from(&config.db.path)
    } else {
        db_path.to_path_buf()
    };
    if path.as_os_str().is_empty() {
        anyhow::bail!("no database path given and config.db.path is empty");
    }

    let offsets: Vec<u64> = match offsets_csv {
        Some(s) if !s.trim().is_empty() => s
            .split(',')
            .map(|t| {
                t.trim()
                    .parse::<u64>()
                    .map_err(|e| anyhow::anyhow!("bad offset '{}': {e}", t.trim()))
            })
            .collect::<anyhow::Result<Vec<u64>>>()?,
        _ => DEFAULT_OFFSETS.to_vec(),
    };

    let db = quil_store::RocksDb::open(&path)
        .map_err(|e| anyhow::anyhow!("open rocksdb {}: {e}", path.display()))?;
    let inner = db.inner();
    let clock = quil_store::RocksClockStore::new(inner.clone());

    let head = clock
        .get_latest_global_clock_frame()
        .map_err(|e| anyhow::anyhow!("get_latest_global_clock_frame: {e}"))?;
    let head_fn = head.header.as_ref().map(|h| h.frame_number).unwrap_or(0);
    let head_rank = head.header.as_ref().map(|h| h.rank).unwrap_or(0);

    println!("=== Fork ladder ===");
    println!("target (rocksdb) : {}", path.display());
    println!("head frame       : {}", head_fn);
    println!("head rank        : {}", head_rank);
    println!("head fp          : {}", poseidon_hex(head.header.as_ref().map(|h| h.output.as_slice()).unwrap_or(&[])));
    println!();
    println!("{:>10}  {:>10}  {}", "frame", "rank", "fp (poseidon(output))");

    // Descending unique frame numbers.
    let mut frames: Vec<u64> = offsets.iter().map(|off| head_fn.saturating_sub(*off)).collect();
    frames.sort_unstable_by(|a, b| b.cmp(a));
    frames.dedup();

    for fnum in frames {
        match clock.get_global_clock_frame(fnum) {
            Ok(f) => {
                let (rank, fp) = f
                    .header
                    .as_ref()
                    .map(|h| (h.rank, poseidon_hex(&h.output)))
                    .unwrap_or((0, String::new()));
                println!("{:>10}  {:>10}  {}", fnum, rank, fp);
            }
            Err(_) => println!("{:>10}  {:>10}  (not in store)", fnum, "-"),
        }
    }

    Ok(())
}

//! Diagnostic that opens a migrated RocksDB store and dumps the
//! global-shard prover registry: how many provers, who's "active",
//! and what their seniorities (= committee weights) look like.
//!
//! Useful when consensus rejects a QC for "insufficient weight" — the
//! number you want to know is the total weight of active provers,
//! because that's the divisor in the Go/Rust quorum formula
//! `(total * 2) / 3`.
//!
//! Run:
//!   cargo run --release -p quil-store --example inspect_committee -- \
//!     /path/to/store

use std::path::Path;
use std::sync::Arc;

use quil_execution::InMemoryProverRegistry;
use quil_store::RocksHypergraphStore;
use quil_types::consensus::ProverRegistry;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: inspect_committee <rocksdb-path>");
        std::process::exit(2);
    }

    // Open as a secondary reader so we can inspect while the node
    // holds the primary lock. catch_up_with_primary pulls in any
    // recent writes.
    let primary = Path::new(&args[1]);
    let scratch = std::env::temp_dir().join(format!(
        "inspect-committee-{}",
        std::process::id(),
    ));
    std::fs::create_dir_all(&scratch).expect("scratch dir");
    let mut opts = rocksdb::Options::default();
    opts.set_max_open_files(64);
    let db = rocksdb::DB::open_as_secondary(&opts, primary, &scratch)
        .expect("open RocksDB as secondary");
    let _ = db.try_catch_up_with_primary();
    let db_arc = Arc::new(db);

    let hg_store = Arc::new(RocksHypergraphStore::new(db_arc));

    let mut reg = InMemoryProverRegistry::new();
    reg.refresh(&hg_store);

    println!("provers_visited={}", reg.provers_visited());
    println!("unknown_vertex_count (registry-level): n/a (private)");
    println!();

    // Global shard = empty filter.
    // Use the inherent method (returns Vec<&ProverInfo>); the trait
    // returns owned Vec<ProverInfo> with QuilResult — either works.
    let active = reg.get_active_provers(&[]);
    println!("active provers under global filter: {}", active.len());
    let mut total_weight: u64 = 0;
    for (i, p) in active.iter().enumerate() {
        total_weight = total_weight.saturating_add(p.seniority);
        println!(
            "  [{}] address={} seniority(weight)={}  pubkey_len={}",
            i,
            hex::encode(&p.address),
            p.seniority,
            p.public_key.len(),
        );
    }
    println!();
    println!("total active weight: {}", total_weight);
    println!("quorum_threshold = (total*2)/3 = {}", (total_weight * 2) / 3);
    println!("timeout_threshold = same = {}", (total_weight * 2) / 3);

    // 1-byte bitmask weight readout: for a QC carrying bitmask 0x0B
    // (bits 0, 1, 3), sum the weights at those indices so we can see
    // exactly what `decode_signers` will report.
    let bm: u8 = 0x0B;
    let mut bm_weight: u64 = 0;
    println!();
    println!("for bitmask 0x{:02X} (bits 0,1,3):", bm);
    for i in 0..active.len() {
        if (bm >> i) & 1 == 1 {
            bm_weight = bm_weight.saturating_add(active[i].seniority);
            println!(
                "  bit {} → {}  weight {}",
                i,
                hex::encode(&active[i].address),
                active[i].seniority,
            );
        }
    }
    println!("  total bitmask weight: {}", bm_weight);
}

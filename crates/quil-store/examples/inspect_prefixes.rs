//! One-shot RocksDB diagnostic: opens the store at the given path
//! (read-only secondary, so it can be run while another process holds
//! the primary lock) and counts entries by tree-relevant prefixes.
//!
//! Run:
//!   cargo run --release -p quil-store --example inspect_prefixes -- \
//!     /path/to/store
//!
//! Specifically targets the global prover tree's shard
//! (l1=[0;3], l2=[0xff;32]) since that's the one the user is
//! debugging.

use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: inspect_prefixes <rocksdb-path>");
        std::process::exit(2);
    }
    let primary = Path::new(&args[1]);
    let scratch = std::env::temp_dir().join(format!(
        "inspect-prefixes-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&scratch).expect("scratch dir");

    let mut opts = rocksdb::Options::default();
    opts.set_max_open_files(64);
    let db = rocksdb::DB::open_as_secondary(&opts, primary, &scratch)
        .expect("open as secondary");
    let _ = db.try_catch_up_with_primary();

    // The global prover tree's shard key for the standard genesis
    // intrinsic. Both the Go and Rust nodes use this exact pair.
    let l1: [u8; 3] = [0, 0, 0];
    let l2: [u8; 32] = [0xff; 32];

    let prefixes: Vec<(&'static str, Vec<u8>)> = vec![
        // Rust per-vertex keyspace for global vertex_adds.
        // [0x30, set=0, phase=0, l1, l2]
        ("rust [0x30] per-vertex (vertex/adds, global shard)",
            build_prefix(0x30, 0, 0, &l1, &l2)),
        // Rust per-node tree by-key for global vertex_adds.
        // [0x33, set=0, phase=0, l1, l2]
        ("rust [0x33] tree-node-by-key (vertex/adds, global shard)",
            build_prefix(0x33, 0, 0, &l1, &l2)),
        // Rust per-node tree by-path for global vertex_adds.
        // [0x34, set=0, phase=0, l1, l2]
        ("rust [0x34] tree-node-by-path (vertex/adds, global shard)",
            build_prefix(0x34, 0, 0, &l1, &l2)),
        // Rust legacy whole-tree blob (in case the migrator wrote one).
        ("rust [0x2F] whole-tree blob (vertex/adds, global shard)",
            build_prefix(0x2F, 0, 0, &l1, &l2)),
        // Go format orphans that should be GONE after migration.
        // [0x09, 0x02, l1, l2]
        ("go [0x09 0x02] tree-node (vertex/adds, global shard)",
            build_go_prefix(0x09, 0x02, &l1, &l2)),
        // [0x09, 0x22, l1, l2]
        ("go [0x09 0x22] tree-node-by-path (vertex/adds, global shard)",
            build_go_prefix(0x09, 0x22, &l1, &l2)),
    ];

    let mut grand_first: Option<u8> = None;
    let mut grand_byte_counts: [u64; 256] = [0; 256];
    // Walk the whole DB once to compute per-leading-byte totals.
    {
        let iter = db.iterator(rocksdb::IteratorMode::Start);
        for entry in iter {
            let (k, _) = entry.expect("walk");
            if let Some(&b) = k.first() {
                if grand_first.is_none() {
                    grand_first = Some(b);
                }
                grand_byte_counts[b as usize] = grand_byte_counts[b as usize].saturating_add(1);
            }
        }
    }

    println!("--- leading byte distribution (whole DB) ---");
    for b in 0..=255u16 {
        if grand_byte_counts[b as usize] > 0 {
            println!("  0x{:02X}: {} entries", b as u8, grand_byte_counts[b as usize]);
        }
    }

    println!("\n--- targeted prefix counts ---");
    for (label, prefix) in &prefixes {
        let count = count_prefix(&db, prefix);
        println!("  {} -> {}", label, count);
    }

    // Walk every [0x30, ...] global-shard entry, parse the Go vertex
    // sub-tree, find the [0xFF; 32] type-hash leaf, and tally by
    // vertex class. This is exactly what `SharedProverRegistry::refresh`
    // does — if it produces zero classified entries here, the registry
    // will also see zero.
    println!("\n--- classifying [0x30] global-shard entries ---");
    let sample_prefix = build_prefix(0x30, 0, 0, &l1, &l2);
    let iter = db.iterator(rocksdb::IteratorMode::From(
        &sample_prefix,
        rocksdb::Direction::Forward,
    ));
    let mut total = 0;
    let mut decoded = 0;
    let mut classified = std::collections::BTreeMap::<String, usize>::new();
    let mut sample_dump_remaining = 2;
    for entry in iter {
        let (k, v) = match entry {
            Ok(p) => p,
            Err(_) => break,
        };
        if !k.starts_with(&sample_prefix) {
            break;
        }
        total += 1;
        let root = match quil_tries::deserialize_go_tree(&v) {
            Ok(Some(r)) => r,
            Ok(None) => {
                *classified.entry("deserialize_returned_None".into()).or_insert(0) += 1;
                continue;
            }
            Err(e) => {
                *classified
                    .entry(format!("deserialize_error: {}", e))
                    .or_insert(0) += 1;
                continue;
            }
        };
        decoded += 1;
        let vk = &k[sample_prefix.len()..];
        let type_hash = root.find_leaf_value(&vec![0xFFu8; 32]);
        let class = match type_hash.as_ref() {
            Some(th) => {
                let classified_name = classify_type_hash(th)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("unknown_type_hash[{}]", hex_short(th)));
                classified_name
            }
            None => "missing_type_hash".into(),
        };
        *classified.entry(class.clone()).or_insert(0) += 1;
        if sample_dump_remaining > 0 {
            println!("  vk_len={} vk={} class={}", vk.len(), hex_short(vk), class);
            sample_dump_remaining -= 1;
        }
    }
    println!("  total entries iterated: {}", total);
    println!("  successfully deserialize_go_tree: {}", decoded);
    println!("  classification tally:");
    for (k, v) in classified.iter() {
        println!("    {}: {}", k, v);
    }
}

/// Mirror of `prover_registry::class_for_type_hash` so the diagnostic
/// classifies the same way `SharedProverRegistry::refresh` does. Type
/// hashes are sha3-256 of the class name. We hardcode the three classes
/// the registry cares about; everything else lumps into "unknown".
fn classify_type_hash(th: &[u8]) -> Option<&'static str> {
    use sha3::{Digest, Sha3_256};
    fn h(s: &str) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(s.as_bytes());
        hasher.finalize().into()
    }
    let prover = h("prover:Prover");
    let reward = h("reward:ProverReward");
    let alloc = h("allocation:ProverAllocation");
    if th == prover {
        Some("prover:Prover")
    } else if th == reward {
        Some("reward:ProverReward")
    } else if th == alloc {
        Some("allocation:ProverAllocation")
    } else {
        None
    }
}

fn build_prefix(top: u8, set: u8, phase: u8, l1: &[u8; 3], l2: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(3 + 3 + 32);
    k.push(top);
    k.push(set);
    k.push(phase);
    k.extend_from_slice(l1);
    k.extend_from_slice(l2);
    k
}

fn build_go_prefix(top: u8, sub: u8, l1: &[u8; 3], l2: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + 3 + 32);
    k.push(top);
    k.push(sub);
    k.extend_from_slice(l1);
    k.extend_from_slice(l2);
    k
}

fn count_prefix(db: &rocksdb::DB, prefix: &[u8]) -> u64 {
    let iter = db.iterator(rocksdb::IteratorMode::From(
        prefix,
        rocksdb::Direction::Forward,
    ));
    let mut n = 0u64;
    for entry in iter {
        let (k, _) = match entry {
            Ok(p) => p,
            Err(_) => break,
        };
        if !k.starts_with(prefix) {
            break;
        }
        n += 1;
    }
    n
}

fn hex_short(b: &[u8]) -> String {
    b.iter().map(|byte| format!("{:02x}", byte)).collect()
}

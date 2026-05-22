//! Read-only diagnostic that opens a RocksDB store as a secondary
//! reader and reports the clock-frame state — specifically the keys
//! the node reads at startup to decide `head_frame`.
//!
//! Run:
//!   cargo run --release -p quil-store --example inspect_clock -- \
//!     /path/to/store
//!
//! What this looks at:
//!  - [0x00, 0x20]                 latest-frame index → 8-byte BE u64
//!  - [0x00, 0x10]                 earliest-frame index → 8-byte BE u64
//!  - [0x00, 0x00, frame_be]       global frame header at a specific number
//!  - [0x00, 0x0B, rank_be]        QC at a specific rank
//!  - [0x00, 0x2B]                 latest-QC index → 8-byte BE u64
//!
//! Also dumps a histogram of leading bytes so we can see whether the
//! store is empty, partially migrated, or fully populated.

use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: inspect_clock <rocksdb-path>");
        std::process::exit(2);
    }
    let primary = Path::new(&args[1]);
    let scratch = std::env::temp_dir().join(format!(
        "inspect-clock-{}",
        std::process::id(),
    ));
    std::fs::create_dir_all(&scratch).expect("scratch dir");

    let mut opts = rocksdb::Options::default();
    opts.set_max_open_files(64);
    let db = rocksdb::DB::open_as_secondary(&opts, primary, &scratch)
        .expect("open as secondary");
    let _ = db.try_catch_up_with_primary();

    println!("=== leading byte distribution ===");
    let mut counts: [u64; 256] = [0; 256];
    let mut total: u64 = 0;
    for entry in db.iterator(rocksdb::IteratorMode::Start) {
        let (k, _) = match entry {
            Ok(p) => p,
            Err(_) => break,
        };
        if let Some(&b) = k.first() {
            counts[b as usize] = counts[b as usize].saturating_add(1);
            total += 1;
        }
    }
    println!("  total entries: {}", total);
    for b in 0..=255u16 {
        let n = counts[b as usize];
        if n > 0 {
            println!("  0x{:02X}: {}", b as u8, n);
        }
    }

    println!();
    println!("=== global frame indexes (under [0x00, ...]) ===");

    // [0x00, 0x20] — latest-frame index
    let latest_idx = vec![0x00u8, 0x20];
    match db.get(&latest_idx) {
        Ok(Some(v)) => {
            if v.len() == 8 {
                let n = u64::from_be_bytes(v[..8].try_into().unwrap());
                println!("  latest-frame-index [0x00,0x20] -> frame {}", n);
            } else {
                println!(
                    "  latest-frame-index [0x00,0x20] -> {} bytes (unexpected)",
                    v.len()
                );
            }
        }
        Ok(None) => println!("  latest-frame-index [0x00,0x20] -> MISSING"),
        Err(e) => println!("  latest-frame-index [0x00,0x20] -> error {}", e),
    }

    let earliest_idx = vec![0x00u8, 0x10];
    match db.get(&earliest_idx) {
        Ok(Some(v)) => {
            if v.len() == 8 {
                let n = u64::from_be_bytes(v[..8].try_into().unwrap());
                println!("  earliest-frame-index [0x00,0x10] -> frame {}", n);
            } else {
                println!(
                    "  earliest-frame-index [0x00,0x10] -> {} bytes (unexpected)",
                    v.len()
                );
            }
        }
        Ok(None) => println!("  earliest-frame-index [0x00,0x10] -> MISSING"),
        Err(e) => println!("  earliest-frame-index [0x00,0x10] -> error {}", e),
    }

    // [0x00, 0x2B] — latest-QC index
    let latest_qc_idx = vec![0x00u8, 0x2B];
    match db.get(&latest_qc_idx) {
        Ok(Some(v)) => {
            if v.len() == 8 {
                let n = u64::from_be_bytes(v[..8].try_into().unwrap());
                println!("  latest-qc-index [0x00,0x2B] -> rank {}", n);
            } else {
                println!(
                    "  latest-qc-index [0x00,0x2B] -> {} bytes (unexpected)",
                    v.len()
                );
            }
        }
        Ok(None) => println!("  latest-qc-index [0x00,0x2B] -> MISSING"),
        Err(e) => println!("  latest-qc-index [0x00,0x2B] -> error {}", e),
    }

    println!();
    println!("=== count of stored global frames ([0x00, 0x00, frame_be]) ===");
    let prefix = vec![0x00u8, 0x00];
    let iter = db.iterator(rocksdb::IteratorMode::From(
        &prefix,
        rocksdb::Direction::Forward,
    ));
    let mut frame_count = 0u64;
    let mut min_seen: Option<u64> = None;
    let mut max_seen: Option<u64> = None;
    for entry in iter {
        let (k, _) = match entry {
            Ok(p) => p,
            Err(_) => break,
        };
        if !k.starts_with(&prefix) {
            break;
        }
        if k.len() != 10 {
            continue;
        }
        let frame = u64::from_be_bytes(k[2..10].try_into().unwrap());
        frame_count += 1;
        min_seen = Some(min_seen.map_or(frame, |m| m.min(frame)));
        max_seen = Some(max_seen.map_or(frame, |m| m.max(frame)));
    }
    println!("  total frame headers: {}", frame_count);
    println!("  min frame: {:?}", min_seen);
    println!("  max frame: {:?}", max_seen);

    println!();
    println!("=== count of stored QCs ([0x00, 0x0B, rank_be]) ===");
    let qc_prefix = vec![0x00u8, 0x0B];
    let mut qc_count = 0u64;
    let mut qc_min: Option<u64> = None;
    let mut qc_max: Option<u64> = None;
    let iter = db.iterator(rocksdb::IteratorMode::From(
        &qc_prefix,
        rocksdb::Direction::Forward,
    ));
    for entry in iter {
        let (k, _) = match entry {
            Ok(p) => p,
            Err(_) => break,
        };
        if !k.starts_with(&qc_prefix) {
            break;
        }
        if k.len() != 10 {
            continue;
        }
        let rank = u64::from_be_bytes(k[2..10].try_into().unwrap());
        qc_count += 1;
        qc_min = Some(qc_min.map_or(rank, |m| m.min(rank)));
        qc_max = Some(qc_max.map_or(rank, |m| m.max(rank)));
    }
    println!("  total QCs: {}", qc_count);
    println!("  min QC rank: {:?}", qc_min);
    println!("  max QC rank: {:?}", qc_max);
}

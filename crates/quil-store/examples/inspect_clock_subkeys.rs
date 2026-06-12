//! Count entries by (first_byte, second_byte) pair so we can see how
//! many entries live under each clock-store sub-discriminator. Used to
//! confirm the migrator brought over `0xF8` (frame request candidates)
//! and other less-obvious keyspaces.
//!
//! Run:
//!   cargo run --release -p quil-store --example inspect_clock_subkeys -- \
//!     /path/to/store

use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: inspect_clock_subkeys <rocksdb-path>");
        std::process::exit(2);
    }
    let primary = Path::new(&args[1]);
    let scratch = std::env::temp_dir().join(format!(
        "inspect-subkeys-{}",
        std::process::id(),
    ));
    std::fs::create_dir_all(&scratch).expect("scratch dir");

    let mut opts = rocksdb::Options::default();
    opts.set_max_open_files(64);
    let db = rocksdb::DB::open_as_secondary(&opts, primary, &scratch)
        .expect("open as secondary");
    let _ = db.try_catch_up_with_primary();

    // 256 x 256 = 65536 bucket counters keyed by (first, second) byte.
    let mut counts: Vec<u64> = vec![0u64; 256 * 256];
    let mut singletons: u64 = 0;
    for entry in db.iterator(rocksdb::IteratorMode::Start) {
        let (k, _) = match entry {
            Ok(p) => p,
            Err(_) => break,
        };
        match k.len() {
            0 => continue,
            1 => singletons += 1,
            _ => {
                let i = (k[0] as usize) * 256 + (k[1] as usize);
                counts[i] = counts[i].saturating_add(1);
            }
        }
    }

    println!("singletons (1-byte keys): {}", singletons);
    println!();
    println!("(first_byte, second_byte) → count");
    for first in 0..=255u16 {
        for second in 0..=255u16 {
            let n = counts[(first * 256 + second) as usize];
            if n > 0 {
                println!(
                    "  [0x{:02X}, 0x{:02X}]: {}",
                    first as u8, second as u8, n
                );
            }
        }
    }
}

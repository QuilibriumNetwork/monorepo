//! Dump the proto-encoded QuorumCertificate at a given rank from a
//! RocksDB store. Used to understand what frame a QC certifies (the
//! rank, frame_number, and selector/identity fields).
//!
//! Run:
//!   cargo run --release -p quil-store --example inspect_qc -- \
//!     /path/to/store <rank>

use std::path::Path;

use prost::Message;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: inspect_qc <rocksdb-path> <rank>");
        std::process::exit(2);
    }
    let primary = Path::new(&args[1]);
    let rank: u64 = args[2].parse().expect("rank must be a u64");

    let scratch = std::env::temp_dir().join(format!(
        "inspect-qc-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&scratch).expect("scratch dir");

    let mut opts = rocksdb::Options::default();
    opts.set_max_open_files(64);
    let db = rocksdb::DB::open_as_secondary(&opts, primary, &scratch)
        .expect("open as secondary");
    let _ = db.try_catch_up_with_primary();

    // QC key: [0x00 CLOCK_FRAME, 0x0B CLOCK_QUORUM_CERTIFICATE, rank(8 BE)]
    let mut key = vec![0x00u8, 0x0B];
    key.extend_from_slice(&rank.to_be_bytes());

    let value = match db.get(&key) {
        Ok(Some(v)) => v,
        Ok(None) => {
            eprintln!("no QC at rank {}", rank);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("get error: {}", e);
            std::process::exit(1);
        }
    };

    println!("raw bytes len: {}", value.len());

    let qc = quil_types::proto::global::QuorumCertificate::decode(value.as_slice())
        .expect("decode QC");

    println!("QC at rank {}:", rank);
    println!("  filter:        {} bytes hex={}", qc.filter.len(), hex::encode(&qc.filter));
    println!("  rank:          {}", qc.rank);
    println!("  frame_number:  {}", qc.frame_number);
    println!("  selector:      {}", hex::encode(&qc.selector));
    println!("  timestamp:     {}", qc.timestamp);
    if let Some(sig) = qc.aggregate_signature.as_ref() {
        println!(
            "  signature_len: {} pubkey_len: {} bitmask: {}",
            sig.signature.len(),
            sig.public_key.as_ref().map(|p| p.key_value.len()).unwrap_or(0),
            hex::encode(&sig.bitmask),
        );
    } else {
        println!("  aggregate_signature: <none>");
    }

    // For comparison: also dump the frame at frame_number, if any.
    let mut fkey = vec![0x00u8, 0x00];
    fkey.extend_from_slice(&qc.frame_number.to_be_bytes());
    // Also dump any global frame candidates at this frame_number.
    let mut cand_prefix = vec![0x00u8, 0x0F];
    cand_prefix.extend_from_slice(&qc.frame_number.to_be_bytes());
    println!();
    println!("looking for global frame candidates at frame_number {}:", qc.frame_number);
    let iter = db.iterator(rocksdb::IteratorMode::From(
        &cand_prefix,
        rocksdb::Direction::Forward,
    ));
    let mut found_candidates = 0;
    let qc_selector_vec = qc.selector.clone();
    for entry in iter {
        let (k, v) = match entry {
            Ok(p) => p,
            Err(_) => break,
        };
        if !k.starts_with(&cand_prefix) {
            break;
        }
        if k.len() < cand_prefix.len() {
            continue;
        }
        let selector: Vec<u8> = k[cand_prefix.len()..].to_vec();
        found_candidates += 1;
        println!(
            "  candidate selector={} bytes={} matches QC.selector? {}",
            hex::encode(&selector),
            v.len(),
            selector == qc_selector_vec,
        );
        if let Ok(frame) = quil_types::proto::global::GlobalFrame::decode(v.as_ref()) {
            if let Some(hdr) = frame.header.as_ref() {
                println!("    decoded rank={} frame_number={}", hdr.rank, hdr.frame_number);
            }
        }
    }
    if found_candidates == 0 {
        println!("  none");
    }

    match db.get(&fkey) {
        Ok(Some(v)) => {
            println!();
            println!("frame at frame_number {} exists ({} bytes)", qc.frame_number, v.len());
            // Decode the proto frame header
            if let Ok(header) = quil_types::proto::global::GlobalFrameHeader::decode(v.as_slice()) {
                let output_identity = quil_crypto::poseidon::hash_bytes_to_32(&header.output)
                    .map(|h| hex::encode(h))
                    .unwrap_or_else(|_| "<poseidon failed>".into());
                println!("  frame.rank:         {}", header.rank);
                println!("  frame.frame_number: {}", header.frame_number);
                println!("  frame.output:       {} bytes", header.output.len());
                println!("  poseidon(output):   {}", output_identity);
                println!("  matches QC.selector? {}", qc.selector == hex::decode(&output_identity).unwrap_or_default());
            }
        }
        _ => println!("\nno frame at frame_number {}", qc.frame_number),
    }
}

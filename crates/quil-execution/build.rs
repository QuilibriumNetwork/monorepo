//! Preprocess the Go-embedded seniority JSON files into compact binary
//! tables so the runtime crate can zero-copy load them via `include_bytes!`.
//!
//! The inputs live under `node/execution/intrinsics/global/compat/`.
//! `mainnet_244200_seniority.json` alone is 210 MB; parsing it at every
//! startup is unacceptable, so we serialize once at build-time as:
//!
//!   mainnet_seniority.bin:
//!     [u64 BE count]
//!     repeated: [32 bytes address][u64 BE seniority]
//!     (entries sorted ascending by address for binary search)
//!
//! Retro JSONs are smaller (~60 MB combined) — we keep them as JSON and
//! parse lazily at runtime via `include_bytes!` + `serde_json`.

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use serde::Deserialize;

const COMPAT_DIR_FROM_CRATE: &str = "../../node/execution/intrinsics/global/compat";

#[derive(Deserialize)]
struct RawMap(std::collections::BTreeMap<String, u64>);

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let compat_dir = manifest.join(COMPAT_DIR_FROM_CRATE);
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let seniority_json = compat_dir.join("mainnet_244200_seniority.json");
    let seniority_bin = out_dir.join("mainnet_seniority.bin");

    println!("cargo:rerun-if-changed={}", seniority_json.display());

    if seniority_json.exists() {
        preprocess_mainnet_seniority(&seniority_json, &seniority_bin);
    } else {
        // Data file absent (e.g. minimal checkout) — emit an empty table
        // so the crate still builds. Seniority lookups will all return 0
        // until the file is restored.
        emit_empty_table(&seniority_bin);
    }
}

fn preprocess_mainnet_seniority(json_path: &PathBuf, bin_path: &PathBuf) {
    let bytes = fs::read(json_path).unwrap_or_else(|e| {
        panic!("failed to read {}: {}", json_path.display(), e)
    });
    let map: RawMap = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!("failed to parse {}: {}", json_path.display(), e)
    });

    // BTreeMap already iterates in sorted ascending key order, which
    // matches the ordering we want for binary search. Convert hex keys
    // to 32-byte addresses; skip any malformed entries.
    let mut entries: Vec<([u8; 32], u64)> = Vec::with_capacity(map.0.len());
    for (hex_addr, seniority) in &map.0 {
        if hex_addr.len() != 64 {
            continue;
        }
        let mut addr = [0u8; 32];
        if hex::decode_to_slice(hex_addr, &mut addr).is_err() {
            continue;
        }
        entries.push((addr, *seniority));
    }

    // The BTreeMap guarantees lexicographic string order on hex keys,
    // which for 32-byte fixed-width hex matches big-endian byte order —
    // so the entries are already sorted for binary search by raw bytes.
    // Verify defensively since silent mis-ordering would break lookups.
    let mut last: Option<[u8; 32]> = None;
    for (addr, _) in &entries {
        if let Some(prev) = last {
            assert!(prev < *addr, "mainnet seniority entries out of order");
        }
        last = Some(*addr);
    }

    let mut out = fs::File::create(bin_path).unwrap();
    out.write_all(&(entries.len() as u64).to_be_bytes()).unwrap();
    for (addr, s) in &entries {
        out.write_all(addr).unwrap();
        out.write_all(&s.to_be_bytes()).unwrap();
    }
}

fn emit_empty_table(bin_path: &PathBuf) {
    let mut out = fs::File::create(bin_path).unwrap();
    out.write_all(&0u64.to_be_bytes()).unwrap();
}

// A self-contained hex decoder — avoids adding a build-dependency for
// what is effectively two-line logic.
mod hex {
    pub fn decode_to_slice(s: &str, out: &mut [u8]) -> Result<(), ()> {
        if s.len() != out.len() * 2 {
            return Err(());
        }
        let bytes = s.as_bytes();
        for i in 0..out.len() {
            let hi = from_hex_digit(bytes[2 * i])?;
            let lo = from_hex_digit(bytes[2 * i + 1])?;
            out[i] = (hi << 4) | lo;
        }
        Ok(())
    }
    fn from_hex_digit(b: u8) -> Result<u8, ()> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(()),
        }
    }
}

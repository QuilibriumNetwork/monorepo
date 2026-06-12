//! Mainnet seniority compatibility table. Port of Go's
//! `node/execution/intrinsics/global/compat/seniority.go`.
//!
//! Returns the highest aggregated seniority earned by any of the given
//! libp2p peer IDs across four retro airdrop epochs plus the mainnet
//! snapshot at frame 244200.
//!
//! The mainnet snapshot is 210 MB of JSON in Go; `build.rs` preprocesses
//! it into a sorted `[address:32 | seniority:u64]` binary blob so
//! runtime lookups are O(log n) binary searches on a memory-mapped
//! `include_bytes!` slice. Retro JSONs are smaller and stay JSON,
//! parsed lazily on first use.

use std::sync::OnceLock;

use quil_crypto::poseidon::hash_bytes_to_32;

// Preprocessed mainnet table: `[u64 BE count][count * {32 bytes addr, 8 bytes BE seniority}]`.
static MAINNET_SENIORITY_BIN: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/mainnet_seniority.bin"));

// The four retro-airdrop JSONs. Small enough to keep as JSON and parse
// lazily on first call. Paths use `concat!` with `CARGO_MANIFEST_DIR`
// because `include_bytes!` requires a literal path string. The
// `node/execution/intrinsics/global/compat/` prefix is Go's authoritative
// location — we don't copy the files to the Rust crate.
static FIRST_RETRO_JSON: &[u8] = include_bytes!(
    "../../../node/execution/intrinsics/global/compat/first_retro.json"
);
static SECOND_RETRO_JSON: &[u8] = include_bytes!(
    "../../../node/execution/intrinsics/global/compat/second_retro.json"
);
static THIRD_RETRO_JSON: &[u8] = include_bytes!(
    "../../../node/execution/intrinsics/global/compat/third_retro.json"
);
static FOURTH_RETRO_JSON: &[u8] = include_bytes!(
    "../../../node/execution/intrinsics/global/compat/fourth_retro.json"
);

/// A parsed first-retro entry. `reward` is an integer string (no decimals).
#[derive(Debug, serde::Deserialize)]
struct FirstRetro {
    #[serde(rename = "peerId")]
    peer_id: String,
    reward: String,
}

/// Second-retro entry. `reward` is a decimal string; we only read the
/// presence flags so decimals don't matter here.
#[derive(Debug, serde::Deserialize)]
struct SecondRetro {
    #[serde(rename = "peerId")]
    peer_id: String,
    #[serde(rename = "janPresence", default)]
    jan_presence: bool,
    #[serde(rename = "febPresence", default)]
    feb_presence: bool,
    #[serde(rename = "marPresence", default)]
    mar_presence: bool,
    #[serde(rename = "aprPresence", default)]
    apr_presence: bool,
    #[serde(rename = "mayPresence", default)]
    may_presence: bool,
}

#[derive(Debug, serde::Deserialize)]
struct ThirdRetro {
    #[serde(rename = "peerId")]
    peer_id: String,
}

#[derive(Debug, serde::Deserialize)]
struct FourthRetro {
    #[serde(rename = "peerId")]
    peer_id: String,
}

static FIRST_RETRO: OnceLock<Vec<FirstRetro>> = OnceLock::new();
static SECOND_RETRO: OnceLock<Vec<SecondRetro>> = OnceLock::new();
static THIRD_RETRO: OnceLock<Vec<ThirdRetro>> = OnceLock::new();
static FOURTH_RETRO: OnceLock<Vec<FourthRetro>> = OnceLock::new();

fn first_retro() -> &'static [FirstRetro] {
    FIRST_RETRO.get_or_init(|| serde_json::from_slice(FIRST_RETRO_JSON).unwrap_or_default())
}
fn second_retro() -> &'static [SecondRetro] {
    SECOND_RETRO.get_or_init(|| serde_json::from_slice(SECOND_RETRO_JSON).unwrap_or_default())
}
fn third_retro() -> &'static [ThirdRetro] {
    THIRD_RETRO.get_or_init(|| serde_json::from_slice(THIRD_RETRO_JSON).unwrap_or_default())
}
fn fourth_retro() -> &'static [FourthRetro] {
    FOURTH_RETRO.get_or_init(|| serde_json::from_slice(FOURTH_RETRO_JSON).unwrap_or_default())
}

/// Lookup the mainnet seniority for a 32-byte `peer_address` (the poseidon
/// hash of the base58-decoded libp2p peer ID). Returns 0 if not present.
fn mainnet_seniority_for_address(peer_address: &[u8; 32]) -> u64 {
    let count = u64::from_be_bytes(MAINNET_SENIORITY_BIN[0..8].try_into().unwrap()) as usize;
    let entries = &MAINNET_SENIORITY_BIN[8..];
    debug_assert_eq!(entries.len(), count * 40);

    // Binary search on 40-byte stride (32-byte address + 8-byte seniority).
    let mut lo = 0usize;
    let mut hi = count;
    while lo < hi {
        let mid = (lo + hi) / 2;
        let off = mid * 40;
        let addr = &entries[off..off + 32];
        match addr.cmp(&peer_address[..]) {
            std::cmp::Ordering::Equal => {
                let val = &entries[off + 32..off + 40];
                return u64::from_be_bytes(val.try_into().unwrap());
            }
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
        }
    }
    0
}

/// Mirror of Go's `GetAggregatedSeniority(peerIds []string) *big.Int` at
/// `node/execution/intrinsics/global/compat/seniority.go:125`.
///
/// For each retro epoch, the highest value earned by any peer in the
/// input list wins. The four epochs' winners are summed. Separately,
/// each peer ID is base58-decoded, poseidon-hashed to a 32-byte address,
/// and looked up in the mainnet snapshot; the maximum mainnet value is
/// taken. The final result is `max(retro_sum, mainnet_max)`.
pub fn get_aggregated_seniority(peer_ids: &[String]) -> u64 {
    let peer_set: std::collections::HashSet<&str> =
        peer_ids.iter().map(|s| s.as_str()).collect();

    let mut highest_first: u64 = 0;
    for f in first_retro() {
        if !peer_set.contains(f.peer_id.as_str()) {
            continue;
        }
        let actual: i64 = f.reward.parse().unwrap_or(0);
        if actual == 0 {
            continue;
        }
        // Go: uint64(10 * 6 * 60 * 24 * 92 / (max / actual)) with max = 157_208.
        // The `max / actual` is integer division — truncates, so we
        // faithfully reproduce that (small divergence from floating-point
        // would break byte-for-byte parity with the Go snapshot).
        const MAX: i64 = 157_208;
        const PERIOD: u64 = 10 * 6 * 60 * 24 * 92;
        if actual > 0 {
            let divisor = (MAX / actual) as u64;
            if divisor > 0 {
                let s = PERIOD / divisor;
                if s > highest_first {
                    highest_first = s;
                }
            }
        }
    }

    let mut highest_second: u64 = 0;
    for f in second_retro() {
        if !peer_set.contains(f.peer_id.as_str()) {
            continue;
        }
        let mut amt: u64 = 0;
        if f.jan_presence { amt += 10 * 6 * 60 * 24 * 31; }
        if f.feb_presence { amt += 10 * 6 * 60 * 24 * 29; }
        if f.mar_presence { amt += 10 * 6 * 60 * 24 * 31; }
        if f.apr_presence { amt += 10 * 6 * 60 * 24 * 30; }
        if f.may_presence { amt += 10 * 6 * 60 * 24 * 31; }
        if amt > highest_second {
            highest_second = amt;
        }
    }

    let mut highest_third: u64 = 0;
    for f in third_retro() {
        if !peer_set.contains(f.peer_id.as_str()) {
            continue;
        }
        let s = 10 * 6 * 60 * 24 * 30u64;
        if s > highest_third {
            highest_third = s;
        }
    }

    let mut highest_fourth: u64 = 0;
    for f in fourth_retro() {
        if !peer_set.contains(f.peer_id.as_str()) {
            continue;
        }
        let s = 10 * 6 * 60 * 24 * 31u64;
        if s > highest_fourth {
            highest_fourth = s;
        }
    }

    let current_aggregated = highest_first + highest_second + highest_third + highest_fourth;

    // Mainnet snapshot lookup: decode peer_id base58 → poseidon-hash → 32-byte address.
    let mut highest_mainnet: u64 = 0;
    for peer_id in peer_ids {
        let decoded = match bs58::decode(peer_id).into_vec() {
            Ok(b) => b,
            Err(_) => continue,
        };
        let addr = match hash_bytes_to_32(&decoded) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let s = mainnet_seniority_for_address(&addr);
        if s > highest_mainnet {
            highest_mainnet = s;
        }
    }

    current_aggregated.max(highest_mainnet)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_peers_return_zero() {
        let ids = vec!["QmUnknownPeerId1".to_string(), "QmUnknownPeerId2".to_string()];
        // Unknown peers not in any retro list and not resolving to a mainnet
        // address return 0. Base58 decode may still succeed on any valid
        // base58 string, but the poseidon hash won't land on a stored
        // address — zero is expected.
        let s = get_aggregated_seniority(&ids);
        assert_eq!(s, 0);
    }

    #[test]
    fn empty_input_returns_zero() {
        let s = get_aggregated_seniority(&[]);
        assert_eq!(s, 0);
    }

    #[test]
    fn bad_base58_skipped() {
        // "not a valid base58 peer id" contains invalid characters; decode
        // fails and we skip rather than panic.
        let ids = vec!["!!!!bad-input!!!!".to_string()];
        let s = get_aggregated_seniority(&ids);
        assert_eq!(s, 0);
    }
}

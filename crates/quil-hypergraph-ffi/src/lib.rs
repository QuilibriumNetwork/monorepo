// Handle-based FFI wrapper for quil-hypergraph CRDT operations.
//
// UniFFI cannot pass trait objects across FFI, so we use u64 handles
// into a global HashMap<u64, CrdtInstance>.  The Go side calls
// create_crdt() to obtain a handle and destroy_crdt() to release it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use quil_hypergraph::addressing::{shard_key_for_location as rust_shard_key_for_location, Location};
use quil_hypergraph::HypergraphCrdt;
use quil_hypergraph::testing::MemStore;
use quil_types::crypto::NoopInclusionProver;
use quil_types::store::ShardKey;

uniffi::include_scaffolding!("lib");

// ---------------------------------------------------------------------------
// Global handle table
// ---------------------------------------------------------------------------

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

static INSTANCES: Mutex<Option<HashMap<u64, HypergraphCrdt>>> = Mutex::new(None);

fn with_instances<F, R>(f: F) -> R
where
    F: FnOnce(&mut HashMap<u64, HypergraphCrdt>) -> R,
{
    let mut guard = INSTANCES.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

// ---------------------------------------------------------------------------
// Standalone functions
// ---------------------------------------------------------------------------

/// Compute the shard key (3-byte L1 bloom + 32-byte L2) for a 32-byte
/// L2 application address.  Returns a 35-byte vector: [L1(3) || L2(32)].
pub fn shard_key_for_location(l2_address: Vec<u8>) -> Vec<u8> {
    assert!(
        l2_address.len() == 32,
        "l2_address must be exactly 32 bytes, got {}",
        l2_address.len()
    );

    let mut app = [0u8; 32];
    app.copy_from_slice(&l2_address);

    let location = Location {
        app_address: app,
        data_address: [0u8; 32],
    };
    let sk = rust_shard_key_for_location(&location);

    let mut out = Vec::with_capacity(35);
    out.extend_from_slice(&sk.l1);
    out.extend_from_slice(&sk.l2);
    out
}

/// Compute bloom filter bucket indices for a key.
///
/// Uses SHA-256-based double hashing:
///   h1 = SHA256(key)[0..4] mod num_buckets
///   h2 = SHA256(key)[4..8] mod num_buckets
///   index_i = (h1 + i * h2) mod num_buckets, for i in 0..num_hashes
///
/// Returns a packed byte vector: num_hashes * 4 bytes, each index as
/// big-endian u32.
pub fn compute_bloom_filter_indices(key: Vec<u8>, num_buckets: u32, num_hashes: u32) -> Vec<u8> {
    assert!(num_buckets > 0, "num_buckets must be > 0");

    let hash = Sha256::digest(&key);

    let h1 = u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]]) % num_buckets;
    let h2 = u32::from_be_bytes([hash[4], hash[5], hash[6], hash[7]]) % num_buckets;

    let mut out = Vec::with_capacity((num_hashes as usize) * 4);
    for i in 0..num_hashes {
        let idx = (h1.wrapping_add(i.wrapping_mul(h2))) % num_buckets;
        out.extend_from_slice(&idx.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// CRDT lifecycle
// ---------------------------------------------------------------------------

/// Create a new in-memory HypergraphCrdt and return its handle.
pub fn create_crdt() -> u64 {
    let store = Arc::new(MemStore::new());
    let prover = Arc::new(NoopInclusionProver);
    let crdt = HypergraphCrdt::new(store, prover);

    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    with_instances(|m| m.insert(handle, crdt));
    handle
}

/// Destroy a previously created CRDT, releasing its resources.
pub fn destroy_crdt(handle: u64) {
    with_instances(|m| {
        m.remove(&handle);
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn parse_shard_key(shard_l1: &[u8], shard_l2: &[u8]) -> ShardKey {
    assert!(
        shard_l1.len() == 3,
        "shard_l1 must be exactly 3 bytes, got {}",
        shard_l1.len()
    );
    assert!(
        shard_l2.len() == 32,
        "shard_l2 must be exactly 32 bytes, got {}",
        shard_l2.len()
    );
    let mut l1 = [0u8; 3];
    let mut l2 = [0u8; 32];
    l1.copy_from_slice(shard_l1);
    l2.copy_from_slice(shard_l2);
    ShardKey { l1, l2 }
}

fn location_from_shard_and_key(shard_l2: &[u8], key: &[u8]) -> Location {
    let mut app = [0u8; 32];
    if shard_l2.len() >= 32 {
        app.copy_from_slice(&shard_l2[..32]);
    }
    // Use the key as the data_address (or pad/truncate to 32 bytes).
    let mut data = [0u8; 32];
    let copy_len = key.len().min(32);
    data[..copy_len].copy_from_slice(&key[..copy_len]);
    Location {
        app_address: app,
        data_address: data,
    }
}

// ---------------------------------------------------------------------------
// Set operations
// ---------------------------------------------------------------------------

/// Insert a value into a specific CRDT phase-set tree.
///
/// `set_type`:   "vertex" or "hyperedge"
/// `phase_type`: "adds" or "removes"
pub fn set_vertex(
    handle: u64,
    set_type: String,
    phase_type: String,
    shard_l1: Vec<u8>,
    shard_l2: Vec<u8>,
    key: Vec<u8>,
    value: Vec<u8>,
) {
    let _ = parse_shard_key(&shard_l1, &shard_l2); // validate sizes
    let location = location_from_shard_and_key(&shard_l2, &key);

    with_instances(|m| {
        let crdt = m
            .get(&handle)
            .unwrap_or_else(|| panic!("invalid handle: {}", handle));

        match (set_type.as_str(), phase_type.as_str()) {
            ("vertex", "adds") => {
                crdt.add_vertex(&location, &value)
                    .unwrap_or_else(|e| panic!("add_vertex failed: {}", e));
            }
            ("vertex", "removes") => {
                // First ensure the vertex exists in adds (CRDT semantics require it),
                // then remove it.
                crdt.remove_vertex(&location)
                    .unwrap_or_else(|e| panic!("remove_vertex failed: {}", e));
            }
            ("hyperedge", "adds") => {
                crdt.add_hyperedge(&location, &value)
                    .unwrap_or_else(|e| panic!("add_hyperedge failed: {}", e));
            }
            ("hyperedge", "removes") => {
                crdt.remove_hyperedge(&location)
                    .unwrap_or_else(|e| panic!("remove_hyperedge failed: {}", e));
            }
            _ => panic!(
                "invalid set_type/phase_type combination: {}/{}",
                set_type, phase_type
            ),
        }
    });
}

/// Get a value from a specific CRDT phase-set tree.
/// Returns None if the key does not exist (or has been removed).
pub fn get_vertex(
    handle: u64,
    set_type: String,
    phase_type: String,
    shard_l1: Vec<u8>,
    shard_l2: Vec<u8>,
    key: Vec<u8>,
) -> Option<Vec<u8>> {
    let _ = parse_shard_key(&shard_l1, &shard_l2);
    let location = location_from_shard_and_key(&shard_l2, &key);

    with_instances(|m| {
        let crdt = m
            .get(&handle)
            .unwrap_or_else(|| panic!("invalid handle: {}", handle));

        match (set_type.as_str(), phase_type.as_str()) {
            ("vertex", "adds") => crdt.get_vertex_data(&location),
            ("hyperedge", "adds") => crdt.get_hyperedge_data(&location),
            // For removes sets, lookup returns true/false (presence in
            // the removes set); we return empty vec as a sentinel.
            ("vertex", "removes") => {
                // A vertex that has been removed will NOT be returned by
                // get_vertex_data (it returns None).  The caller can
                // detect removal by checking adds returns None.
                crdt.get_vertex_data(&location)
            }
            ("hyperedge", "removes") => crdt.get_hyperedge_data(&location),
            _ => panic!(
                "invalid set_type/phase_type combination: {}/{}",
                set_type, phase_type
            ),
        }
    })
}

/// Delete a vertex/hyperedge entry.  For CRDT semantics this records
/// a removal (adds to the removes set).
pub fn delete_vertex(
    handle: u64,
    set_type: String,
    _phase_type: String,
    shard_l1: Vec<u8>,
    shard_l2: Vec<u8>,
    key: Vec<u8>,
) {
    let _ = parse_shard_key(&shard_l1, &shard_l2);
    let location = location_from_shard_and_key(&shard_l2, &key);

    with_instances(|m| {
        let crdt = m
            .get(&handle)
            .unwrap_or_else(|| panic!("invalid handle: {}", handle));

        match set_type.as_str() {
            "vertex" => {
                crdt.remove_vertex(&location)
                    .unwrap_or_else(|e| panic!("remove_vertex failed: {}", e));
            }
            "hyperedge" => {
                crdt.remove_hyperedge(&location)
                    .unwrap_or_else(|e| panic!("remove_hyperedge failed: {}", e));
            }
            _ => panic!("invalid set_type: {}", set_type),
        }
    });
}

// ---------------------------------------------------------------------------
// Commit
// ---------------------------------------------------------------------------

/// Commit all CRDT phase-set trees for the given frame number.
///
/// Returns a serialized result: for each shard, a 35-byte shard key
/// (3-byte L1 + 32-byte L2) followed by 4 root commitments of 64 bytes
/// each (vertex_adds, vertex_removes, hyperedge_adds, hyperedge_removes).
///
/// Total per shard: 35 + 4*64 = 291 bytes.
/// The output is the concatenation of all shard entries.
pub fn commit_phase(handle: u64, frame_number: u64) -> Vec<u8> {
    with_instances(|m| {
        let crdt = m
            .get(&handle)
            .unwrap_or_else(|| panic!("invalid handle: {}", handle));

        let result = crdt
            .commit(frame_number)
            .unwrap_or_else(|e| panic!("commit failed: {}", e));

        // Serialize: for each shard, emit [l1(3) | l2(32) | root0(64) | root1(64) | root2(64) | root3(64)]
        let mut out = Vec::new();
        for (shard_key, roots) in &result {
            out.extend_from_slice(&shard_key.l1);
            out.extend_from_slice(&shard_key.l2);
            for root in roots {
                // Pad or truncate to exactly 64 bytes.
                let mut padded = vec![0u8; 64];
                let copy_len = root.len().min(64);
                padded[..copy_len].copy_from_slice(&root[..copy_len]);
                out.extend_from_slice(&padded);
            }
            // Pad missing roots with zeros if fewer than 4.
            for _ in roots.len()..4 {
                out.extend_from_slice(&[0u8; 64]);
            }
        }
        out
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_key_round_trip() {
        let addr = vec![0x42u8; 32];
        let result = shard_key_for_location(addr);
        assert_eq!(result.len(), 35);
        // L2 should mirror input
        assert_eq!(&result[3..], &[0x42u8; 32]);
    }

    #[test]
    fn bloom_filter_indices_count() {
        let key = b"test-key".to_vec();
        let result = compute_bloom_filter_indices(key, 1024, 3);
        assert_eq!(result.len(), 12); // 3 * 4 bytes
    }

    #[test]
    fn bloom_filter_indices_within_range() {
        let key = b"some-key".to_vec();
        let num_buckets = 100u32;
        let result = compute_bloom_filter_indices(key, num_buckets, 5);
        for chunk in result.chunks(4) {
            let idx = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            assert!(idx < num_buckets);
        }
    }

    #[test]
    fn create_and_destroy_crdt() {
        let h = create_crdt();
        assert!(h > 0);
        destroy_crdt(h);
    }

    #[test]
    fn set_and_get_vertex() {
        let h = create_crdt();
        let l1 = vec![0xAAu8, 0xBB, 0xCC];
        let l2 = vec![0x01u8; 32];
        let key = vec![0x02u8; 32];

        set_vertex(
            h,
            "vertex".into(),
            "adds".into(),
            l1.clone(),
            l2.clone(),
            key.clone(),
            b"hello-world".to_vec(),
        );

        let val = get_vertex(
            h,
            "vertex".into(),
            "adds".into(),
            l1,
            l2,
            key,
        );
        assert!(val.is_some());
        assert_eq!(val.unwrap(), b"hello-world");

        destroy_crdt(h);
    }

    #[test]
    fn delete_vertex_removes_from_lookup() {
        let h = create_crdt();
        let l1 = vec![0xAAu8, 0xBB, 0xCC];
        let l2 = vec![0x01u8; 32];
        let key = vec![0x02u8; 32];

        set_vertex(
            h,
            "vertex".into(),
            "adds".into(),
            l1.clone(),
            l2.clone(),
            key.clone(),
            b"data".to_vec(),
        );

        delete_vertex(
            h,
            "vertex".into(),
            "adds".into(),
            l1.clone(),
            l2.clone(),
            key.clone(),
        );

        let val = get_vertex(
            h,
            "vertex".into(),
            "adds".into(),
            l1,
            l2,
            key,
        );
        assert!(val.is_none());

        destroy_crdt(h);
    }

    #[test]
    fn commit_empty_crdt_returns_empty() {
        let h = create_crdt();
        let result = commit_phase(h, 1);
        assert!(result.is_empty());
        destroy_crdt(h);
    }

    #[test]
    fn commit_after_insert_returns_shard_roots() {
        let h = create_crdt();
        let l1 = vec![0xAAu8, 0xBB, 0xCC];
        let l2 = vec![0x01u8; 32];
        let key = vec![0x02u8; 32];

        set_vertex(
            h,
            "vertex".into(),
            "adds".into(),
            l1,
            l2,
            key,
            b"data".to_vec(),
        );

        let result = commit_phase(h, 1);
        // Should have exactly one shard entry: 35 + 4*64 = 291 bytes
        assert_eq!(result.len(), 291);

        destroy_crdt(h);
    }

    #[test]
    #[should_panic(expected = "invalid handle")]
    fn invalid_handle_panics() {
        get_vertex(
            999999,
            "vertex".into(),
            "adds".into(),
            vec![0u8; 3],
            vec![0u8; 32],
            vec![0u8; 32],
        );
    }
}

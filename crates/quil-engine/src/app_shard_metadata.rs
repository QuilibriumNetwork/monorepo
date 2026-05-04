//! Per-shard size + commitment metadata derived from the hypergraph CRDT.

use num_bigint::BigInt;
use num_traits::Zero;

use quil_hypergraph::HypergraphCrdt;
use quil_tries::{get_full_path, NodeMetadata};
use quil_types::store::{ShardInfo, ShardKey};

#[derive(Debug, Clone)]
pub struct AppShardMetadata {
    pub prefix: Vec<u32>,
    /// Big-endian, leading zero bytes stripped.
    pub size: Vec<u8>,
    pub data_shards: u64,
    /// `[vertex_adds, vertex_removes, hyperedge_adds, hyperedge_removes]`,
    /// each 64 bytes; missing nodes contribute a 64-byte zero blob.
    pub commitments: [Vec<u8>; 4],
}

impl AppShardMetadata {
    pub fn size_bigint(&self) -> BigInt {
        BigInt::from_bytes_be(num_bigint::Sign::Plus, &self.size)
    }
}

pub fn build_app_shard_full_prefix(l2: &[u8], prefix: &[u32]) -> Vec<i32> {
    let mut full = get_full_path(l2);
    full.reserve(prefix.len());
    for &p in prefix {
        full.push(p as i32);
    }
    full
}

/// `ShardInfo.shard_key` is 35 bytes: `L1[3] ++ L2[32]`.
pub fn shard_key_from_bytes(shard_key: &[u8]) -> Option<ShardKey> {
    if shard_key.len() != 35 {
        return None;
    }
    let mut l1 = [0u8; 3];
    let mut l2 = [0u8; 32];
    l1.copy_from_slice(&shard_key[..3]);
    l2.copy_from_slice(&shard_key[3..]);
    Some(ShardKey { l1, l2 })
}

/// Returns `None` only for a malformed `shard_key`. Empty/missing nodes
/// contribute a 64-byte zero commitment and 0 size.
pub fn get_app_shard_metadata(
    crdt: &HypergraphCrdt,
    shard: &ShardInfo,
) -> Option<AppShardMetadata> {
    let typed_key = shard_key_from_bytes(&shard.shard_key)?;
    let full_prefix = build_app_shard_full_prefix(&typed_key.l2, &shard.prefix);

    let metas = match crdt.phase_set_metadata_at_path(&typed_key, &full_prefix) {
        Ok(m) => m,
        Err(_) => [None, None, None, None],
    };

    let zero64 = || vec![0u8; 64];
    let unwrap_commitment = |m: &Option<NodeMetadata>| -> Vec<u8> {
        match m {
            Some(meta) if meta.commitment.len() == 64 => meta.commitment.clone(),
            _ => zero64(),
        }
    };

    let commitments: [Vec<u8>; 4] = [
        unwrap_commitment(&metas[0]),
        unwrap_commitment(&metas[1]),
        unwrap_commitment(&metas[2]),
        unwrap_commitment(&metas[3]),
    ];

    // `size` and `data_shards` come from vertex_adds only.
    let (size_bytes, data_shards) = match &metas[0] {
        Some(meta) => {
            let bytes = if meta.size.is_zero() {
                Vec::new()
            } else {
                let (_, b) = meta.size.to_bytes_be();
                b
            };
            (bytes, meta.leaf_count)
        }
        None => (Vec::new(), 0u64),
    };

    Some(AppShardMetadata {
        prefix: shard.prefix.clone(),
        size: size_bytes,
        data_shards,
        commitments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use quil_hypergraph::Location;
    use quil_types::crypto::{InclusionProver, Multiproof};
    use quil_types::error::{QuilError, Result};
    use quil_types::store::{ChangeRecord, HypergraphStore, Transaction};
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MemStore {
        nodes: Mutex<HashMap<String, Vec<u8>>>,
        roots: Mutex<HashMap<String, Vec<u8>>>,
    }
    impl MemStore {
        fn new() -> Self {
            Self {
                nodes: Mutex::new(HashMap::new()),
                roots: Mutex::new(HashMap::new()),
            }
        }
        fn node_key(set: &str, phase: &str, shard: &ShardKey, key: &[u8]) -> String {
            format!("n/{}/{}/{:?}{:?}/{:?}", set, phase, shard.l1, shard.l2, key)
        }
        fn root_key(set: &str, phase: &str, shard: &ShardKey) -> String {
            format!("r/{}/{}/{:?}{:?}", set, phase, shard.l1, shard.l2)
        }
    }
    struct NoopTxn;
    impl Transaction for NoopTxn {
        fn get(&self, _: &[u8]) -> Result<Option<Vec<u8>>> { Ok(None) }
        fn set(&self, _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
        fn commit(self: Box<Self>) -> Result<()> { Ok(()) }
        fn delete(&self, _: &[u8]) -> Result<()> { Ok(()) }
        fn abort(self: Box<Self>) -> Result<()> { Ok(()) }
        fn new_iter(&self, _: &[u8], _: &[u8]) -> Result<Box<dyn quil_types::store::Iterator>> {
            Err(QuilError::Internal("noop iter".into()))
        }
        fn delete_range(&self, _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
        fn as_any(&self) -> &dyn std::any::Any { self }
    }
    impl HypergraphStore for MemStore {
        fn new_transaction(&self, _: bool) -> Result<Box<dyn Transaction>> { Ok(Box::new(NoopTxn)) }
        fn get_node_by_key(&self, set: &str, phase: &str, shard: &ShardKey, key: &[u8]) -> Result<Option<Vec<u8>>> {
            Ok(self.nodes.lock().unwrap().get(&Self::node_key(set, phase, shard, key)).cloned())
        }
        fn get_node_by_path(&self, _: &str, _: &str, _: &ShardKey, _: &[i32]) -> Result<Option<Vec<u8>>> { Ok(None) }
        fn insert_node(&self, _: &dyn Transaction, set: &str, phase: &str, shard: &ShardKey, key: &[u8], _: &[i32], data: &[u8]) -> Result<()> {
            self.nodes.lock().unwrap().insert(Self::node_key(set, phase, shard, key), data.to_vec());
            Ok(())
        }
        fn save_root(&self, _: &dyn Transaction, set: &str, phase: &str, shard: &ShardKey, data: &[u8]) -> Result<()> {
            self.roots.lock().unwrap().insert(Self::root_key(set, phase, shard), data.to_vec());
            Ok(())
        }
        fn delete_node(&self, _: &dyn Transaction, _: &str, _: &str, _: &ShardKey, _: &[u8], _: &[i32]) -> Result<()> { Ok(()) }
        fn set_covered_prefix(&self, _: &[i32]) -> Result<()> { Ok(()) }
        fn set_shard_commit(&self, _: &dyn Transaction, _: u64, _: &str, _: &str, _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
        fn get_shard_commit(&self, _: u64, _: &str, _: &str, _: &[u8]) -> Result<Vec<u8>> { Ok(vec![]) }
        fn get_root_commits(&self, _: u64) -> Result<HashMap<ShardKey, Vec<Vec<u8>>>> { Ok(HashMap::new()) }
        fn load_vertex_underlying_raw(&self, set: &str, phase: &str, shard: &ShardKey, key: &[u8]) -> Result<Option<Vec<u8>>> {
            Ok(self.nodes.lock().unwrap().get(&Self::node_key(set, phase, shard, key)).cloned())
        }
        fn apply_snapshot(&self, _: &str) -> Result<()> { Ok(()) }
        fn set_alt_shard_commit(&self, _: &dyn Transaction, _: u64, _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<()> { Ok(()) }
        fn get_latest_alt_shard_commit(&self, _: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> { Ok((vec![], vec![], vec![], vec![])) }
        fn range_alt_shard_addresses(&self) -> Result<Vec<Vec<u8>>> { Ok(vec![]) }
        fn reap_old_changesets(&self, _: &dyn Transaction, _: u64) -> Result<()> { Ok(()) }
        fn track_change(&self, _: &dyn Transaction, _: &[u8], _: Option<&[u8]>, _: u64, _: &str, _: &str, _: &ShardKey) -> Result<()> { Ok(()) }
        fn get_changes(&self, _: u64, _: u64, _: &str, _: &str, _: &ShardKey) -> Result<Vec<ChangeRecord>> { Ok(vec![]) }
        fn untrack_change(&self, _: &dyn Transaction, _: &[u8], _: u64, _: &str, _: &str, _: &ShardKey) -> Result<()> { Ok(()) }
    }
    struct StubProver;
    impl InclusionProver for StubProver {
        fn commit_raw(&self, data: &[u8], _: u64) -> Result<Vec<u8>> {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            data.hash(&mut h);
            let hash = h.finish().to_be_bytes();
            let mut out = vec![0u8; 64];
            out[..8].copy_from_slice(&hash);
            Ok(out)
        }
        fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> { Ok(vec![0u8; 64]) }
        fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> { Ok(true) }
        fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64) -> Result<Box<dyn Multiproof>> {
            Err(QuilError::Internal("multiproof not supported".into()))
        }
        fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { true }
    }

    fn make_crdt() -> Arc<HypergraphCrdt> {
        let store: Arc<dyn HypergraphStore> = Arc::new(MemStore::new());
        let prover: Arc<dyn InclusionProver> = Arc::new(StubProver);
        Arc::new(HypergraphCrdt::new(store, prover))
    }

    #[test]
    fn shard_key_from_bytes_round_trip() {
        let mut buf = vec![0u8; 35];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(1);
        }
        let key = shard_key_from_bytes(&buf).expect("valid 35-byte key");
        assert_eq!(&key.l1[..], &buf[..3]);
        assert_eq!(&key.l2[..], &buf[3..]);
    }

    #[test]
    fn shard_key_from_bytes_rejects_bad_length() {
        assert!(shard_key_from_bytes(&[]).is_none());
        assert!(shard_key_from_bytes(&vec![0u8; 34]).is_none());
        assert!(shard_key_from_bytes(&vec![0u8; 36]).is_none());
    }

    #[test]
    fn build_full_prefix_concats_l2_path_and_shard_prefix() {
        // L2 = [0xAB] => 2 nibbles {42, 48} per `get_full_path` test
        // (lib.rs::full_path_single_byte_ab_has_two_nibbles).
        let l2 = vec![0xABu8];
        let prefix = vec![5u32, 12u32];
        let path = build_app_shard_full_prefix(&l2, &prefix);
        assert_eq!(path, vec![42i32, 48, 5, 12]);
    }

    #[test]
    fn empty_shard_returns_zero_metadata() {
        let crdt = make_crdt();
        let mut shard_key = vec![0u8; 35];
        shard_key[0] = 0x01;
        let shard = ShardInfo {
            shard_key,
            prefix: vec![],
            size: vec![],
            data_shards: 0,
            commitment: vec![],
        };
        let meta = get_app_shard_metadata(&crdt, &shard).expect("valid key");
        assert_eq!(meta.size, Vec::<u8>::new());
        assert_eq!(meta.data_shards, 0);
        for c in &meta.commitments {
            assert_eq!(c, &vec![0u8; 64]);
        }
    }

    #[test]
    fn shard_with_vertex_returns_well_formed_metadata() {
        // Single-vertex shards collapse so the leaf sits at root —
        // walking the L2 path returns `None` and we fall back to
        // the zero-metadata shape. Multi-leaf path-walk coverage
        // lives in `lazy_tree`'s own tests.
        //
        // Here we only assert that the call returns a well-formed
        // `AppShardMetadata` for a populated shard.
        let crdt = make_crdt();

        let mut app_address = [0xCDu8; 32];
        app_address[0] = 0xAB;
        let location = Location {
            app_address,
            data_address: [0x11u8; 32],
        };
        crdt.add_vertex(&location, b"some-vertex-payload").unwrap();

        let typed = quil_hypergraph::addressing::shard_key_for_location(&location);
        let mut shard_key_bytes = Vec::with_capacity(35);
        shard_key_bytes.extend_from_slice(&typed.l1);
        shard_key_bytes.extend_from_slice(&typed.l2);

        let shard = ShardInfo {
            shard_key: shard_key_bytes,
            prefix: vec![],
            size: vec![],
            data_shards: 0,
            commitment: vec![],
        };

        let meta = get_app_shard_metadata(&crdt, &shard).expect("valid key");
        // Well-formed shape: 4 phase commitments, prefix matches.
        assert_eq!(meta.commitments.len(), 4);
        for c in &meta.commitments {
            assert_eq!(c.len(), 64, "phase commitment must be 64 bytes");
        }
        assert_eq!(meta.prefix, Vec::<u32>::new());
    }
}

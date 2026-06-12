//! Prover census + named-class extraction from the persisted vertex
//! data cache.
//!
//! Walks every persisted `underlying_data` sub-tree, reads the type-hash
//! key `[0xff * 32]` to partition vertices into type buckets, looks
//! them up in `KNOWN_TYPE_HASHES` to name the class, and reads per-class
//! fields via the `order << 2` key encoding from `GLOBAL_RDF_SCHEMA`.
//!
//! Each known type hash was observed from a live mainnet census on
//! 2026-04-11 and corresponds to a class defined in the global
//! intrinsic's RDF schema. These constants should be stable for as long
//! as both `GLOBAL_INTRINSIC_ADDRESS` and the schema class names don't
//! change. A future Poseidon port can compute them at runtime and
//! double-check.

use std::collections::BTreeMap;
use std::sync::Arc;

use quil_store::RocksHypergraphStore;
use quil_tries::{deserialize_go_tree, VectorCommitmentNode};
use quil_types::store::ShardKey;

/// Type hash → RDF class name, observed from live mainnet (2026-04-11).
///
/// These are `poseidon(GLOBAL_INTRINSIC_ADDRESS || class_name)` values,
/// hard-coded until we port iden3 Poseidon. Any runtime observation of
/// a type hash NOT in this table is logged as "unknown".
pub const KNOWN_TYPE_HASHES: &[(&str, &[u8; 32])] = &[
    (
        "prover:Prover",
        &[
            0x27, 0x99, 0x01, 0x8a, 0x52, 0xe2, 0xa0, 0x68, 0x99, 0x8e, 0xd0, 0xcd, 0xad,
            0x60, 0xe8, 0x60, 0x12, 0xf3, 0x2b, 0x8d, 0xf0, 0xd3, 0x05, 0x99, 0x9f, 0x53,
            0x67, 0xe1, 0x09, 0x8b, 0xda, 0xec,
        ],
    ),
    (
        "allocation:ProverAllocation",
        &[
            0x17, 0xfa, 0x31, 0x02, 0x82, 0x87, 0x55, 0x19, 0x78, 0xab, 0xcb, 0xc3, 0x14,
            0x50, 0xb1, 0xb1, 0x4b, 0xe4, 0x3c, 0x09, 0xbe, 0xc9, 0x0d, 0x7d, 0x9f, 0xb0,
            0x0e, 0xcd, 0x59, 0x56, 0xcf, 0x38,
        ],
    ),
    (
        "reward:ProverReward",
        &[
            0x04, 0xb1, 0x0a, 0x01, 0x84, 0x44, 0x11, 0xbb, 0x0c, 0x39, 0x0f, 0x4c, 0xd2,
            0x62, 0x9b, 0x48, 0xcc, 0x7e, 0xf5, 0x61, 0x45, 0x5c, 0x3a, 0xda, 0xc5, 0xeb,
            0xcb, 0xad, 0x38, 0x34, 0xbf, 0xa4,
        ],
    ),
];

/// Return the RDF class name associated with a type hash, or `None` if
/// the hash isn't in `KNOWN_TYPE_HASHES`.
pub fn class_for_type_hash(hash: &[u8]) -> Option<&'static str> {
    if hash.len() != 32 {
        return None;
    }
    for (name, known) in KNOWN_TYPE_HASHES {
        if hash == known.as_slice() {
            return Some(name);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Schema-driven field keys
// ---------------------------------------------------------------------------

/// Convert an RDF field `order` to the key used in the per-vertex
/// sub-tree. Mirrors Go's `schema.OrderToKey(order, maxOrder)` — single
/// byte for `maxOrder <= 63`, which every live class falls under.
const fn order_key_byte(order: u8) -> [u8; 1] {
    [order << 2]
}

/// Field keys for `prover:Prover`. Orders 0-4, single-byte encoding.
pub mod prover_keys {
    use super::order_key_byte;
    pub const PUBLIC_KEY: [u8; 1] = order_key_byte(0);
    pub const STATUS: [u8; 1] = order_key_byte(1);
    pub const AVAILABLE_STORAGE: [u8; 1] = order_key_byte(2);
    pub const SENIORITY: [u8; 1] = order_key_byte(3);
    pub const KICK_FRAME_NUMBER: [u8; 1] = order_key_byte(4);
}

/// A decoded `prover:Prover` vertex. Mirrors the fields Go's
/// `ProverRegistry.extractGlobalState` reads.
#[derive(Debug, Clone)]
pub struct DecodedProver {
    /// 32-byte prover address extracted from the main-tree vertex key
    /// (the last 32 bytes of the 64-byte key).
    pub address: [u8; 32],
    pub public_key: Vec<u8>,
    pub status: u8,
    pub available_storage: u64,
    pub seniority: u64,
    pub kick_frame_number: u64,
}

#[derive(Debug, Default)]
pub struct ProverCensus {
    /// Total vertex entries visited.
    pub total_vertices: usize,
    /// Vertices whose `underlying_data` failed to deserialize.
    pub deserialize_failures: usize,
    /// Vertices that had no type hash at `[0xff * 32]`.
    pub missing_type_hash: usize,
    /// Per-type-hash counts. Keys are 32-byte Poseidon hashes, mapped
    /// to RDF class names via `KNOWN_TYPE_HASHES` where recognised.
    pub by_type_hash: BTreeMap<Vec<u8>, TypeCount>,
}

#[derive(Debug, Default, Clone)]
pub struct TypeCount {
    /// Number of vertices with this type hash.
    pub count: usize,
    /// The resolved RDF class name, or `None` for unknown type hashes.
    pub class_name: Option<&'static str>,
    /// Count by Status byte (key `[0x04]`). Only meaningful for
    /// classes where Status (order 1) is actually a status byte
    /// (`prover:Prover` and `allocation:ProverAllocation`). For
    /// `reward:ProverReward` order 1 is `Balance` (32-byte big int),
    /// so the byte-level read is incidental.
    pub by_status: BTreeMap<u8, usize>,
    /// Vertices of this type where the value at key `[0x04]` was not
    /// a single byte (either absent or wider). For `reward:ProverReward`
    /// this is the normal case.
    pub no_status: usize,
}

/// Walk every persisted vertex in the global prover shard under the
/// given `(set_type, phase_type)`, parse its `underlying_data` as a
/// Go-format sub-tree, and bucket counts by type hash and status byte.
pub fn census_global_prover_phase(
    hg_store: &Arc<RocksHypergraphStore>,
    set_type: &str,
    phase_type: &str,
) -> ProverCensus {
    let shard = ShardKey {
        l1: [0u8; 3],
        l2: [0xffu8; 32],
    };
    let mut census = ProverCensus::default();

    let _ = hg_store.for_each_vertex_underlying(set_type, phase_type, &shard, |_key, data| {
        census.total_vertices += 1;
        let root = match deserialize_go_tree(&data) {
            Ok(Some(r)) => r,
            Ok(None) => {
                census.missing_type_hash += 1;
                return;
            }
            Err(_) => {
                census.deserialize_failures += 1;
                return;
            }
        };

        let type_hash = root.find_leaf_value(&vec![0xFFu8; 32]);
        let status = root.find_leaf_value(&prover_keys::STATUS);

        let Some(type_hash) = type_hash else {
            census.missing_type_hash += 1;
            return;
        };
        let entry = census.by_type_hash.entry(type_hash.clone()).or_default();
        if entry.class_name.is_none() {
            entry.class_name = class_for_type_hash(&type_hash);
        }
        entry.count += 1;
        match status {
            Some(s) if s.len() == 1 => {
                *entry.by_status.entry(s[0]).or_insert(0) += 1;
            }
            _ => entry.no_status += 1,
        }
    });

    census
}

/// Iterate every persisted `prover:Prover` vertex and decode it into a
/// `DecodedProver`. Skips vertices of other classes, vertices whose
/// sub-tree can't be parsed, and vertices missing the status field.
///
/// `vertex_key` on the main tree is 64 bytes (32-byte global intrinsic
/// domain + 32-byte prover address). We take the last 32 bytes as the
/// prover address, matching
/// `node/consensus/provers/prover_registry.go:886`.
pub fn list_provers(hg_store: &Arc<RocksHypergraphStore>) -> Vec<DecodedProver> {
    let shard = ShardKey {
        l1: [0u8; 3],
        l2: [0xffu8; 32],
    };
    let prover_type_hash: &[u8] = KNOWN_TYPE_HASHES
        .iter()
        .find(|(name, _)| *name == "prover:Prover")
        .map(|(_, h)| h.as_slice())
        .expect("prover:Prover hash must be in KNOWN_TYPE_HASHES");

    let mut out: Vec<DecodedProver> = Vec::with_capacity(1024);
    let _ = hg_store.for_each_vertex_underlying("vertex", "adds", &shard, |vertex_key, data| {
        if vertex_key.len() != 64 {
            return;
        }
        let root = match deserialize_go_tree(&data) {
            Ok(Some(r)) => r,
            _ => return,
        };

        // Only prover:Prover vertices.
        let type_hash = root.find_leaf_value(&vec![0xFFu8; 32]);
        if type_hash.as_deref() != Some(prover_type_hash) {
            return;
        }

        let public_key = root.find_leaf_value(&prover_keys::PUBLIC_KEY).unwrap_or_default();
        let status_bytes = match root.find_leaf_value(&prover_keys::STATUS) {
            Some(b) if b.len() == 1 => b,
            _ => return,
        };
        let status = status_bytes[0];
        let available_storage =
            read_u64_be_at(&root, &prover_keys::AVAILABLE_STORAGE).unwrap_or(0);
        let seniority = read_u64_be_at(&root, &prover_keys::SENIORITY).unwrap_or(0);
        let kick_frame_number =
            read_u64_be_at(&root, &prover_keys::KICK_FRAME_NUMBER).unwrap_or(0);

        let mut address = [0u8; 32];
        address.copy_from_slice(&vertex_key[32..64]);
        out.push(DecodedProver {
            address,
            public_key,
            status,
            available_storage,
            seniority,
            kick_frame_number,
        });
    });
    out
}

/// Read a u64 from an 8-byte-or-longer leaf value found at `key`.
fn read_u64_be_at(root: &VectorCommitmentNode, key: &[u8]) -> Option<u64> {
    let bytes = root.find_leaf_value(key)?;
    if bytes.len() < 8 {
        return None;
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    Some(u64::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;
    use quil_tries::{BranchNode, LeafNode, VectorCommitmentNode, BRANCH_NODES};

    // =================================================================
    // KNOWN_TYPE_HASHES sanity
    // =================================================================

    #[test]
    fn known_type_hashes_contains_three_expected_classes() {
        assert_eq!(KNOWN_TYPE_HASHES.len(), 3);
        let names: Vec<&str> = KNOWN_TYPE_HASHES.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"prover:Prover"));
        assert!(names.contains(&"allocation:ProverAllocation"));
        assert!(names.contains(&"reward:ProverReward"));
    }

    #[test]
    fn known_type_hashes_are_all_32_bytes() {
        for (name, hash) in KNOWN_TYPE_HASHES {
            assert_eq!(hash.len(), 32, "{} hash is not 32 bytes", name);
        }
    }

    #[test]
    fn known_type_hashes_are_distinct() {
        // Each hash must be unique — otherwise class_for_type_hash
        // would return the wrong class for one of them.
        use std::collections::HashSet;
        let set: HashSet<&[u8; 32]> = KNOWN_TYPE_HASHES.iter().map(|(_, h)| *h).collect();
        assert_eq!(set.len(), KNOWN_TYPE_HASHES.len());
    }

    // =================================================================
    // class_for_type_hash
    // =================================================================

    #[test]
    fn class_for_known_prover_hash_returns_name() {
        let (_, hash) = KNOWN_TYPE_HASHES
            .iter()
            .find(|(n, _)| *n == "prover:Prover")
            .unwrap();
        assert_eq!(class_for_type_hash(*hash), Some("prover:Prover"));
    }

    #[test]
    fn class_for_known_allocation_hash_returns_name() {
        let (_, hash) = KNOWN_TYPE_HASHES
            .iter()
            .find(|(n, _)| *n == "allocation:ProverAllocation")
            .unwrap();
        assert_eq!(
            class_for_type_hash(*hash),
            Some("allocation:ProverAllocation")
        );
    }

    #[test]
    fn class_for_known_reward_hash_returns_name() {
        let (_, hash) = KNOWN_TYPE_HASHES
            .iter()
            .find(|(n, _)| *n == "reward:ProverReward")
            .unwrap();
        assert_eq!(class_for_type_hash(*hash), Some("reward:ProverReward"));
    }

    #[test]
    fn class_for_unknown_hash_returns_none() {
        let unknown = [0u8; 32];
        assert_eq!(class_for_type_hash(&unknown), None);
    }

    #[test]
    fn class_for_wrong_length_hash_returns_none() {
        // Short hash → None (can't match any 32-byte entry).
        assert_eq!(class_for_type_hash(&[0u8; 31]), None);
        // Long hash → None.
        assert_eq!(class_for_type_hash(&[0u8; 33]), None);
        // Empty hash → None.
        assert_eq!(class_for_type_hash(&[]), None);
    }

    // =================================================================
    // order_key_byte encoding
    // =================================================================

    #[test]
    fn order_key_byte_shifts_left_by_2() {
        // order 0 → 0x00, order 1 → 0x04, order 2 → 0x08, ...
        assert_eq!(order_key_byte(0), [0x00]);
        assert_eq!(order_key_byte(1), [0x04]);
        assert_eq!(order_key_byte(2), [0x08]);
        assert_eq!(order_key_byte(3), [0x0C]);
        assert_eq!(order_key_byte(4), [0x10]);
        assert_eq!(order_key_byte(13), [0x34]);
        // Max encodable single-byte order is 63 (0x3F << 2 = 0xFC).
        assert_eq!(order_key_byte(63), [0xFC]);
    }

    #[test]
    fn prover_keys_match_order_encoding() {
        // prover_keys constants must match the schema field ordering:
        // 0 = PublicKey, 1 = Status, 2 = AvailableStorage,
        // 3 = Seniority, 4 = KickFrameNumber.
        assert_eq!(prover_keys::PUBLIC_KEY, [0x00]);
        assert_eq!(prover_keys::STATUS, [0x04]);
        assert_eq!(prover_keys::AVAILABLE_STORAGE, [0x08]);
        assert_eq!(prover_keys::SENIORITY, [0x0C]);
        assert_eq!(prover_keys::KICK_FRAME_NUMBER, [0x10]);
    }

    // =================================================================
    // find_leaf_value
    // =================================================================

    fn leaf(key: &[u8], value: &[u8]) -> VectorCommitmentNode {
        VectorCommitmentNode::Leaf(LeafNode {
            key: key.to_vec(),
            value: value.to_vec(),
            hash_target: vec![],
            commitment: vec![],
            size: BigInt::from(value.len() as u64),
        })
    }

    fn empty_children() -> [Option<Box<VectorCommitmentNode>>; BRANCH_NODES] {
        std::array::from_fn(|_| None)
    }

    fn branch_with_children(
        children_vec: Vec<(usize, VectorCommitmentNode)>,
    ) -> VectorCommitmentNode {
        let mut children = empty_children();
        for (idx, node) in children_vec {
            children[idx] = Some(Box::new(node));
        }
        VectorCommitmentNode::Branch(BranchNode {
            prefix: vec![],
            children,
            commitment: vec![],
            size: BigInt::from(0),
            leaf_count: 0,
            longest_branch: 0,
            full_prefix: Vec::new(),
            fully_loaded: true,
        })
    }

    #[test]
    fn find_leaf_in_single_leaf_with_matching_key() {
        let node = leaf(b"\x04", b"active");
        assert_eq!(node.find_leaf_value(&[0x04]), Some(b"active".to_vec()));
    }

    #[test]
    fn find_leaf_in_single_leaf_with_non_matching_key() {
        let node = leaf(b"\x04", b"active");
        assert_eq!(node.find_leaf_value(&[0x08]), None);
    }

    #[test]
    fn find_leaf_under_branch_with_single_child() {
        let child = leaf(&prover_keys::STATUS, &[2u8]); // Active status byte
        let branch = branch_with_children(vec![(0, child)]);
        let result = branch.find_leaf_value(&prover_keys::STATUS);
        assert_eq!(result, Some(vec![2u8]));
    }

    #[test]
    fn find_leaf_searches_all_children_until_match() {
        // Build a branch with leaves at multiple positions, plus one
        // matching target. find_leaf_value should return the first
        // match it encounters.
        let l0 = leaf(&prover_keys::PUBLIC_KEY, b"pub-bytes");
        let l1 = leaf(&prover_keys::STATUS, &[2u8]);
        let l2 = leaf(&prover_keys::AVAILABLE_STORAGE, &[0u8; 8]);
        let branch = branch_with_children(vec![(0, l0), (10, l1), (20, l2)]);

        assert_eq!(
            branch.find_leaf_value(&prover_keys::PUBLIC_KEY),
            Some(b"pub-bytes".to_vec())
        );
        assert_eq!(
            branch.find_leaf_value(&prover_keys::STATUS),
            Some(vec![2u8])
        );
        assert_eq!(
            branch.find_leaf_value(&prover_keys::AVAILABLE_STORAGE),
            Some(vec![0u8; 8])
        );
        // Target not in branch.
        assert_eq!(
            branch.find_leaf_value(&prover_keys::SENIORITY),
            None
        );
    }

    #[test]
    fn find_leaf_recurses_into_nested_branches() {
        // branch → branch → leaf hierarchy (typical of prefix-compressed
        // sub-trees under type hash fanout).
        let leaf_node = leaf(&vec![0xFFu8; 32], b"type-hash-value");
        let inner = branch_with_children(vec![(5, leaf_node)]);
        let outer = branch_with_children(vec![(0, inner)]);
        assert_eq!(
            outer.find_leaf_value(&vec![0xFFu8; 32]),
            Some(b"type-hash-value".to_vec())
        );
    }

    #[test]
    fn find_leaf_empty_branch_returns_none() {
        let branch = branch_with_children(vec![]);
        assert_eq!(branch.find_leaf_value(&[0x04]), None);
    }

    #[test]
    fn find_leaf_target_not_in_tree_returns_none() {
        let l0 = leaf(&prover_keys::PUBLIC_KEY, b"value");
        let branch = branch_with_children(vec![(0, l0)]);
        assert_eq!(branch.find_leaf_value(&prover_keys::STATUS), None);
    }

    // =================================================================
    // read_u64_be_at
    // =================================================================

    #[test]
    fn read_u64_be_from_8_byte_leaf() {
        // Build a leaf with 8 bytes of big-endian u64 data.
        let value = 0x0102030405060708u64.to_be_bytes();
        let leaf_node = leaf(&prover_keys::SENIORITY, &value);
        assert_eq!(
            read_u64_be_at(&leaf_node, &prover_keys::SENIORITY),
            Some(0x0102030405060708u64)
        );
    }

    #[test]
    fn read_u64_be_from_longer_leaf_truncates_to_first_8() {
        // Value is 16 bytes; read_u64_be_at should take the first 8.
        let mut value = vec![0u8; 16];
        value[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        let leaf_node = leaf(&prover_keys::AVAILABLE_STORAGE, &value);
        assert_eq!(
            read_u64_be_at(&leaf_node, &prover_keys::AVAILABLE_STORAGE),
            Some(u64::MAX)
        );
    }

    #[test]
    fn read_u64_be_from_short_leaf_returns_none() {
        // 4-byte value is too short for a u64 read.
        let leaf_node = leaf(&prover_keys::KICK_FRAME_NUMBER, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(
            read_u64_be_at(&leaf_node, &prover_keys::KICK_FRAME_NUMBER),
            None
        );
    }

    #[test]
    fn read_u64_be_from_missing_key_returns_none() {
        let leaf_node = leaf(&prover_keys::PUBLIC_KEY, &[0u8; 8]);
        // Query for a different key — not found → None.
        assert_eq!(
            read_u64_be_at(&leaf_node, &prover_keys::KICK_FRAME_NUMBER),
            None
        );
    }

    #[test]
    fn read_u64_be_zero_value() {
        let leaf_node = leaf(&prover_keys::SENIORITY, &[0u8; 8]);
        assert_eq!(read_u64_be_at(&leaf_node, &prover_keys::SENIORITY), Some(0));
    }

    #[test]
    fn read_u64_be_u64_max() {
        let leaf_node = leaf(&prover_keys::SENIORITY, &u64::MAX.to_be_bytes());
        assert_eq!(
            read_u64_be_at(&leaf_node, &prover_keys::SENIORITY),
            Some(u64::MAX)
        );
    }

    // =================================================================
    // ProverCensus / TypeCount defaults
    // =================================================================

    #[test]
    fn prover_census_default_is_empty() {
        let c = ProverCensus::default();
        assert_eq!(c.total_vertices, 0);
        assert_eq!(c.deserialize_failures, 0);
        assert_eq!(c.missing_type_hash, 0);
        assert!(c.by_type_hash.is_empty());
    }

    #[test]
    fn type_count_default_is_empty() {
        let tc = TypeCount::default();
        assert_eq!(tc.count, 0);
        assert_eq!(tc.class_name, None);
        assert!(tc.by_status.is_empty());
        assert_eq!(tc.no_status, 0);
    }

    #[test]
    fn type_count_clone_preserves_counts() {
        let mut original = TypeCount::default();
        original.count = 42;
        original.class_name = Some("prover:Prover");
        original.by_status.insert(2, 10);
        original.no_status = 3;

        let cloned = original.clone();
        assert_eq!(cloned.count, 42);
        assert_eq!(cloned.class_name, Some("prover:Prover"));
        assert_eq!(cloned.by_status.get(&2), Some(&10));
        assert_eq!(cloned.no_status, 3);
    }

    // =================================================================
    // DecodedProver smoke
    // =================================================================

    #[test]
    fn decoded_prover_debug_format_contains_fields() {
        let p = DecodedProver {
            address: [0xAB; 32],
            public_key: vec![0x01, 0x02, 0x03],
            status: 2,
            available_storage: 1_000_000,
            seniority: 12345,
            kick_frame_number: 0,
        };
        let s = format!("{:?}", p);
        assert!(s.contains("1000000"));
        assert!(s.contains("12345"));
    }
}

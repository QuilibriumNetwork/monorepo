//! Static `GLOBAL_RDF_SCHEMA` — hard-coded from the Turtle RDF schema.
//!
//! Rather than port a Turtle parser, we hard-code the schema as a Rust
//! constant: a `class_name -> field_name -> RDFTag` map with each tag
//! carrying an `order` value that drives key encoding.
//!
//! - `order_to_key` — converts schema order to tree key bytes.
//! - `class_field_key` — point lookup for a class's field by name.
//! - `max_order` — determines the key width (single/double/triple byte).
//! - `TYPE_HASH_*` — hard-coded Poseidon type hashes observed from
//!   mainnet on 2026-04-11. Replace with computed values once Poseidon
//!   is ported.
//!
//! Source: see `GLOBAL_RDF_SCHEMA` at
//! `node/execution/intrinsics/global/global_intrinsic.go:44-161`.

/// One RDF field tag.
#[derive(Debug, Clone, Copy)]
pub struct FieldTag {
    pub name: &'static str,
    pub order: u16,
    /// Declared size in the schema. For Uint/Int it's in bytes. For
    /// ByteArray it's the max length. Not currently used in the port
    /// (kept for parity with Go's `Field.Size`).
    pub size: u32,
    /// RDF range/type (`Uint`, `ByteArray`, `Struct`, etc.).
    pub rdf_type: RdfType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdfType {
    Uint,
    Int,
    ByteArray,
    Bool,
    String,
    /// Anything else — we don't use this in the global schema.
    Other,
}

/// One RDF class entry.
pub struct ClassDef {
    pub name: &'static str,
    pub fields: &'static [FieldTag],
}

/// The full parsed `GLOBAL_RDF_SCHEMA`. Order of classes in this array
/// is NOT significant; look up by name.
pub const GLOBAL_CLASSES: &[ClassDef] = &[
    ClassDef {
        name: "prover:Prover",
        fields: &[
            // order 0 — BLS48-581 pubkey (585 bytes per schema).
            FieldTag { name: "PublicKey",        order: 0, size: 585, rdf_type: RdfType::ByteArray },
            // order 1 — 1-byte enum {Joining=0, Active=1, Paused=2, Leaving=3, Kicked=4}.
            FieldTag { name: "Status",           order: 1, size: 1,   rdf_type: RdfType::Uint },
            // order 2 — 8-byte big-endian u64.
            FieldTag { name: "AvailableStorage", order: 2, size: 8,   rdf_type: RdfType::Uint },
            // order 3 — 8-byte big-endian u64.
            FieldTag { name: "Seniority",        order: 3, size: 8,   rdf_type: RdfType::Uint },
            // order 4 — 8-byte big-endian u64.
            FieldTag { name: "KickFrameNumber",  order: 4, size: 8,   rdf_type: RdfType::Uint },
        ],
    },
    ClassDef {
        name: "allocation:ProverAllocation",
        fields: &[
            // order 0 — pointer to the parent `prover:Prover` (Struct, 32 bytes).
            FieldTag { name: "Prover",                  order: 0,  size: 32, rdf_type: RdfType::Other },
            FieldTag { name: "Status",                  order: 1,  size: 1,  rdf_type: RdfType::Uint },
            FieldTag { name: "ConfirmationFilter",      order: 2,  size: 64, rdf_type: RdfType::ByteArray },
            FieldTag { name: "RejectionFilter",         order: 3,  size: 64, rdf_type: RdfType::ByteArray },
            FieldTag { name: "JoinFrameNumber",         order: 4,  size: 8,  rdf_type: RdfType::Uint },
            FieldTag { name: "LeaveFrameNumber",        order: 5,  size: 8,  rdf_type: RdfType::Uint },
            FieldTag { name: "PauseFrameNumber",        order: 6,  size: 8,  rdf_type: RdfType::Uint },
            FieldTag { name: "ResumeFrameNumber",       order: 7,  size: 8,  rdf_type: RdfType::Uint },
            FieldTag { name: "KickFrameNumber",         order: 8,  size: 8,  rdf_type: RdfType::Uint },
            FieldTag { name: "JoinConfirmFrameNumber",  order: 9,  size: 8,  rdf_type: RdfType::Uint },
            FieldTag { name: "JoinRejectFrameNumber",   order: 10, size: 8,  rdf_type: RdfType::Uint },
            FieldTag { name: "LeaveConfirmFrameNumber", order: 11, size: 8,  rdf_type: RdfType::Uint },
            FieldTag { name: "LeaveRejectFrameNumber",  order: 12, size: 8,  rdf_type: RdfType::Uint },
            FieldTag { name: "LastActiveFrameNumber",   order: 13, size: 8,  rdf_type: RdfType::Uint },
        ],
    },
    ClassDef {
        name: "reward:ProverReward",
        fields: &[
            // order 0 — 32-byte delegate address.
            FieldTag { name: "DelegateAddress", order: 0, size: 32, rdf_type: RdfType::ByteArray },
            // order 1 — 32-byte big-endian u256 balance.
            FieldTag { name: "Balance",         order: 1, size: 32, rdf_type: RdfType::ByteArray },
        ],
    },
    // NOTE: merge:SpentMerge is NOT in the Go GLOBAL_RDF_SCHEMA turtle.
    // The Go code references it via rdfMultiprover.Set/Get calls, which
    // would fail at class lookup. We include it here for forward
    // compatibility with the seniority merge spent-marker logic.
    ClassDef {
        name: "merge:SpentMerge",
        fields: &[
            // order 0 — 32-byte prover address that consumed this merge target.
            FieldTag { name: "ProverAddress", order: 0, size: 32, rdf_type: RdfType::ByteArray },
        ],
    },
];

/// The schema's max `order` across all classes. For `GLOBAL_CLASSES`
/// this is 13 (allocation's `LastActiveFrameNumber`). Used to decide
/// the `order_to_key` encoding width.
pub const GLOBAL_MAX_ORDER: u16 = 13;

/// Encoding boundaries from `types/schema/order_encoding.go`.
pub const MAX_ORDER_SINGLE_BYTE: u16 = 63;
pub const MAX_ORDER_TWO_BYTE: u16 = 4093;
pub const MAX_ORDER_THREE_BYTE: u32 = 262142;

/// Convert an RDF field `order` to the key used to look up that field
/// in a per-vertex `VectorCommitmentTree`. The width of the key depends
/// on the document's *maximum* order value, so that all keys in the
/// same document have the same byte length.
///
/// Returns a 1-, 2-, or 3-byte key, left-padded with bits shifted
/// from the low end.
pub fn order_to_key(order: u16, max_order: u16) -> Vec<u8> {
    if max_order <= MAX_ORDER_SINGLE_BYTE {
        return vec![(order << 2) as u8];
    }
    if max_order <= MAX_ORDER_TWO_BYTE {
        let shifted = (order as u32) << 4;
        return vec![(shifted >> 8) as u8, (shifted & 0xFF) as u8];
    }
    let shifted = (order as u32) << 6;
    vec![
        (shifted >> 16) as u8,
        ((shifted >> 8) & 0xFF) as u8,
        (shifted & 0xFF) as u8,
    ]
}

/// Look up a class definition by name.
pub fn class_def(name: &str) -> Option<&'static ClassDef> {
    GLOBAL_CLASSES.iter().find(|c| c.name == name)
}

/// Look up a field's tag by (class, field) name.
pub fn field_tag(class: &str, field: &str) -> Option<&'static FieldTag> {
    class_def(class)?.fields.iter().find(|f| f.name == field)
}

/// Compute the tree-lookup key bytes for a given `(class, field)` pair
/// using the global schema's max order. `None` if the field is missing.
pub fn field_key(class: &str, field: &str) -> Option<Vec<u8>> {
    let tag = field_tag(class, field)?;
    Some(order_to_key(tag.order, GLOBAL_MAX_ORDER))
}

// ---------------------------------------------------------------------------
// Type hashes (Poseidon)
// ---------------------------------------------------------------------------

/// The 32-byte global intrinsic domain used as the Poseidon pre-image
/// prefix for all class names.
pub const GLOBAL_INTRINSIC_ADDRESS: [u8; 32] = [0xFFu8; 32];

/// Compute a class's type hash at runtime:
/// `poseidon.HashBytes(GLOBAL_INTRINSIC_ADDRESS || class_name_bytes)`.
///
/// Prefer the `TYPE_HASH_*` constants below for point lookups —
/// they're already verified against live mainnet and avoid the
/// sponge-hash cost on hot paths.
pub fn compute_type_hash(class_name: &str) -> [u8; 32] {
    let mut msg = Vec::with_capacity(32 + class_name.len());
    msg.extend_from_slice(&GLOBAL_INTRINSIC_ADDRESS);
    msg.extend_from_slice(class_name.as_bytes());
    quil_crypto::hash_bytes_to_32(&msg).expect("poseidon hash cannot fail on non-empty input")
}

/// `poseidon(GLOBAL_INTRINSIC_ADDRESS || "prover:Prover")` — observed
/// from live mainnet on 2026-04-11 and verified to equal the output of
/// `compute_type_hash("prover:Prover")` in a unit test.
pub const TYPE_HASH_PROVER: [u8; 32] = [
    0x27, 0x99, 0x01, 0x8a, 0x52, 0xe2, 0xa0, 0x68, 0x99, 0x8e, 0xd0, 0xcd, 0xad,
    0x60, 0xe8, 0x60, 0x12, 0xf3, 0x2b, 0x8d, 0xf0, 0xd3, 0x05, 0x99, 0x9f, 0x53,
    0x67, 0xe1, 0x09, 0x8b, 0xda, 0xec,
];

/// `poseidon(GLOBAL_INTRINSIC_ADDRESS || "allocation:ProverAllocation")`
/// — observed from live mainnet on 2026-04-11.
pub const TYPE_HASH_ALLOCATION: [u8; 32] = [
    0x17, 0xfa, 0x31, 0x02, 0x82, 0x87, 0x55, 0x19, 0x78, 0xab, 0xcb, 0xc3, 0x14,
    0x50, 0xb1, 0xb1, 0x4b, 0xe4, 0x3c, 0x09, 0xbe, 0xc9, 0x0d, 0x7d, 0x9f, 0xb0,
    0x0e, 0xcd, 0x59, 0x56, 0xcf, 0x38,
];

/// `poseidon(GLOBAL_INTRINSIC_ADDRESS || "reward:ProverReward")` —
/// observed from live mainnet on 2026-04-11.
pub const TYPE_HASH_REWARD: [u8; 32] = [
    0x04, 0xb1, 0x0a, 0x01, 0x84, 0x44, 0x11, 0xbb, 0x0c, 0x39, 0x0f, 0x4c, 0xd2,
    0x62, 0x9b, 0x48, 0xcc, 0x7e, 0xf5, 0x61, 0x45, 0x5c, 0x3a, 0xda, 0xc5, 0xeb,
    0xcb, 0xad, 0x38, 0x34, 0xbf, 0xa4,
];

/// Compute `poseidon(GLOBAL_INTRINSIC_ADDRESS || "merge:SpentMerge")`
/// at runtime. Used by seniority merge spent-marker logic.
///
/// NOTE: This class is NOT in the Go GLOBAL_RDF_SCHEMA turtle, but is
/// referenced by seniority merge spent-marker logic. Included for
/// forward compatibility.
pub fn type_hash_spent_merge() -> [u8; 32] {
    compute_type_hash("merge:SpentMerge")
}

/// The full `[type_hash; 32] → class_name` mapping for the global
/// intrinsic schema. Does not include `merge:SpentMerge` because its
/// hash is computed at runtime — use `class_for_type_hash` which
/// checks it as a fallback.
pub const TYPE_HASH_TABLE: &[([u8; 32], &str)] = &[
    (TYPE_HASH_PROVER, "prover:Prover"),
    (TYPE_HASH_ALLOCATION, "allocation:ProverAllocation"),
    (TYPE_HASH_REWARD, "reward:ProverReward"),
];

/// Resolve a type-hash blob to its class name, or `None` for unknown.
pub fn class_for_type_hash(hash: &[u8]) -> Option<&'static str> {
    if hash.len() != 32 {
        return None;
    }
    for (known, name) in TYPE_HASH_TABLE {
        if hash == known.as_slice() {
            return Some(*name);
        }
    }
    // Fallback: check merge:SpentMerge (computed at runtime)
    let spent_merge_hash = type_hash_spent_merge();
    if hash == spent_merge_hash.as_slice() {
        return Some("merge:SpentMerge");
    }
    None
}

// =====================================================================
// Tree field reader
// =====================================================================

/// Read a named field from a `VectorCommitmentTree` using the global
/// RDF schema.
///
/// Returns `None` if the field is not found in the schema or the tree
/// doesn't contain data at that key.
pub fn read_field(
    tree: &quil_tries::VectorCommitmentTree,
    class: &str,
    field: &str,
) -> Option<Vec<u8>> {
    let key = field_key(class, field)?;
    tree.get(&key).map(|v| v.to_vec())
}

/// Write a named field value into a `VectorCommitmentTree` using the
/// global RDF schema. Inverse of `read_field`.
///
/// Returns `Err` if the field is not in the schema.
pub fn write_field(
    tree: &mut quil_tries::VectorCommitmentTree,
    class: &str,
    field: &str,
    value: &[u8],
) -> quil_types::error::Result<()> {
    use num_bigint::BigInt;
    let key = field_key(class, field).ok_or_else(|| {
        quil_types::error::QuilError::InvalidArgument(format!(
            "write_field: unknown field {}.{}",
            class, field
        ))
    })?;
    tree.insert(&key, value, &[], &BigInt::from(value.len() as u64))
        .map_err(|e| quil_types::error::QuilError::Internal(format!("write_field insert: {}", e)))
}

/// Write the type hash at key `[0xFF; 32]` into a vertex tree.
pub fn write_type(
    tree: &mut quil_tries::VectorCommitmentTree,
    class: &str,
) -> quil_types::error::Result<()> {
    use num_bigint::BigInt;
    let hash = compute_type_hash(class);
    tree.insert(&[0xFFu8; 32], &hash, &[], &BigInt::from(32))
        .map_err(|e| quil_types::error::QuilError::Internal(format!("write_type insert: {}", e)))
}

/// Read the type hash stored at key `[0xFF; 32]` in a vertex tree
/// and resolve it to a class name.
pub fn read_type(tree: &quil_tries::VectorCommitmentTree) -> Option<&'static str> {
    let type_key = [0xFFu8; 32];
    let hash = tree.get(&type_key)?;
    class_for_type_hash(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_to_key_single_byte() {
        // max_order ≤ 63 → single-byte encoding, `order << 2`.
        assert_eq!(order_to_key(0, 13), vec![0x00]);
        assert_eq!(order_to_key(1, 13), vec![0x04]);
        assert_eq!(order_to_key(13, 13), vec![0x34]);
        assert_eq!(order_to_key(63, 63), vec![0xfc]);
    }

    #[test]
    fn order_to_key_two_byte() {
        // max_order in 64..=4093 → 2 bytes, `order << 4`.
        // order=0 → 0x0000, order=64 → 0x0400, order=4093 → 0xfffd << 4 = 0xfffd0...
        let k = order_to_key(64, 64);
        assert_eq!(k, vec![0x04, 0x00]);
        let k = order_to_key(1, 64);
        assert_eq!(k, vec![0x00, 0x10]);
    }

    #[test]
    fn order_to_key_three_byte() {
        // max_order > 4093 → 3 bytes, `order << 6`.
        let k = order_to_key(1, 4094);
        assert_eq!(k, vec![0x00, 0x00, 0x40]);
    }

    #[test]
    fn field_key_matches_live_mainnet_observations() {
        // Observed from the inspection probe on 2026-04-11:
        // allocation:ProverAllocation keys that appeared in live data
        // were 0x00, 0x04, 0x08, 0x10, 0x24, 0x34 — single byte.
        //   Prover           → order 0  → 0x00
        //   Status           → order 1  → 0x04
        //   ConfirmationFilter → order 2 → 0x08
        //   JoinFrameNumber  → order 4  → 0x10
        //   JoinConfirmFrameNumber → order 9  → 0x24
        //   LastActiveFrameNumber  → order 13 → 0x34
        let cls = "allocation:ProverAllocation";
        assert_eq!(field_key(cls, "Prover"), Some(vec![0x00]));
        assert_eq!(field_key(cls, "Status"), Some(vec![0x04]));
        assert_eq!(field_key(cls, "ConfirmationFilter"), Some(vec![0x08]));
        assert_eq!(field_key(cls, "JoinFrameNumber"), Some(vec![0x10]));
        assert_eq!(field_key(cls, "JoinConfirmFrameNumber"), Some(vec![0x24]));
        assert_eq!(field_key(cls, "LastActiveFrameNumber"), Some(vec![0x34]));

        // prover:Prover keys
        assert_eq!(field_key("prover:Prover", "Status"), Some(vec![0x04]));
        assert_eq!(field_key("prover:Prover", "AvailableStorage"), Some(vec![0x08]));
        assert_eq!(field_key("prover:Prover", "Seniority"), Some(vec![0x0C]));
        assert_eq!(field_key("prover:Prover", "KickFrameNumber"), Some(vec![0x10]));
    }

    #[test]
    fn type_hash_table_is_unique() {
        let mut seen = std::collections::HashSet::new();
        for (h, _) in TYPE_HASH_TABLE {
            assert!(seen.insert(*h), "duplicate type hash");
        }
        assert_eq!(seen.len(), 3);
        // Also verify SpentMerge is distinct from the const entries
        let spent_merge = type_hash_spent_merge();
        assert!(seen.insert(spent_merge), "SpentMerge hash collides");
    }

    /// Runtime Poseidon cross-check: every hard-coded `TYPE_HASH_*`
    /// constant must equal `compute_type_hash(class_name)`. If this
    /// test fails, it means either the constants were corrupted OR
    /// the Poseidon implementation drifted from Go.
    #[test]
    fn hardcoded_type_hashes_match_runtime_poseidon() {
        assert_eq!(compute_type_hash("prover:Prover"), TYPE_HASH_PROVER);
        assert_eq!(
            compute_type_hash("allocation:ProverAllocation"),
            TYPE_HASH_ALLOCATION
        );
        assert_eq!(
            compute_type_hash("reward:ProverReward"),
            TYPE_HASH_REWARD
        );
        // SpentMerge is runtime-computed, verify round-trip
        assert_eq!(
            compute_type_hash("merge:SpentMerge"),
            type_hash_spent_merge()
        );
    }

    // =================================================================
    // read_field / read_type
    // =================================================================

    #[test]
    fn read_field_from_tree() {
        use num_bigint::BigInt;
        let mut tree = quil_tries::VectorCommitmentTree::new();
        // Insert a pubkey at order 0 → key 0x00
        let pubkey = vec![0xAAu8; 585];
        tree.insert(&[0x00], &pubkey, &[], &BigInt::from(585)).unwrap();
        // read_field should find it
        let result = read_field(&tree, "prover:Prover", "PublicKey");
        assert_eq!(result, Some(pubkey));
    }

    #[test]
    fn read_field_missing_returns_none() {
        let tree = quil_tries::VectorCommitmentTree::new();
        assert_eq!(read_field(&tree, "prover:Prover", "PublicKey"), None);
    }

    #[test]
    fn read_field_unknown_class_returns_none() {
        let tree = quil_tries::VectorCommitmentTree::new();
        assert_eq!(read_field(&tree, "nonexistent:Class", "Field"), None);
    }

    #[test]
    fn read_type_from_tree() {
        use num_bigint::BigInt;
        let mut tree = quil_tries::VectorCommitmentTree::new();
        // Store the prover type hash at key [0xFF; 32]
        tree.insert(&[0xFFu8; 32], &TYPE_HASH_PROVER, &[], &BigInt::from(32)).unwrap();
        assert_eq!(read_type(&tree), Some("prover:Prover"));
    }

    #[test]
    fn read_type_unknown_hash_returns_none() {
        use num_bigint::BigInt;
        let mut tree = quil_tries::VectorCommitmentTree::new();
        tree.insert(&[0xFFu8; 32], &[0x00u8; 32], &[], &BigInt::from(32)).unwrap();
        assert_eq!(read_type(&tree), None);
    }

    #[test]
    fn read_type_empty_tree_returns_none() {
        let tree = quil_tries::VectorCommitmentTree::new();
        assert_eq!(read_type(&tree), None);
    }

    // =================================================================
    // write_field / write_type
    // =================================================================

    #[test]
    fn write_field_then_read_field_round_trips() {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        write_field(&mut tree, "prover:Prover", "PublicKey", &vec![0xBBu8; 585]).unwrap();
        let val = read_field(&tree, "prover:Prover", "PublicKey");
        assert_eq!(val, Some(vec![0xBBu8; 585]));
    }

    #[test]
    fn write_field_overwrites_existing() {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        write_field(&mut tree, "prover:Prover", "Status", &[1u8]).unwrap();
        assert_eq!(read_field(&tree, "prover:Prover", "Status"), Some(vec![1u8]));
        write_field(&mut tree, "prover:Prover", "Status", &[2u8]).unwrap();
        assert_eq!(read_field(&tree, "prover:Prover", "Status"), Some(vec![2u8]));
    }

    #[test]
    fn write_field_rejects_unknown_field() {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        assert!(write_field(&mut tree, "prover:Prover", "Nonexistent", &[1u8]).is_err());
    }

    #[test]
    fn write_type_then_read_type() {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        write_type(&mut tree, "prover:Prover").unwrap();
        assert_eq!(read_type(&tree), Some("prover:Prover"));
    }

    #[test]
    fn write_type_allocation() {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        write_type(&mut tree, "allocation:ProverAllocation").unwrap();
        assert_eq!(read_type(&tree), Some("allocation:ProverAllocation"));
    }
}

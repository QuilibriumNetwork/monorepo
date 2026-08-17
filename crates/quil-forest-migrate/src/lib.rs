//! KZG → JMT state converter.
//!
//! Runs at the migration rewind point: reads the existing on-chain state —
//! whose commitments are all KZG/BLS48-581 vector commitments in
//! [`quil_tries`] — and re-commits it into the [`quil_forest`] three-tier
//! JMT. `quil-tries` is retained precisely for this read side; only branch
//! commitments differ between the schemes (leaf commits were already SHA-512),
//! so the conversion is a re-roll, not a re-hash of leaf content.
//!
//! # The flattening (design decision "b")
//!
//! In the legacy layout each shard-phase tree leaf VALUE is itself a
//! serialized per-vertex [`VectorCommitmentTree`]
//! (`quil_tries::deserialize_go_tree`), whose own leaves are the vertex's
//! `(field_key, value)` fields. The forest does **not** nest: every vertex
//! field becomes a first-class Level-3 leaf keyed
//! `vertex_address ++ field_key` (see [`quil_forest::l3_leaf_key`]). This
//! module's core, [`flatten_vertex_blob`], performs that lift; the shard /
//! app / global walk composes it over the whole DB.
//!
//! This crate currently provides the pure, DB-independent core. The store
//! walk (`range_alt_shard_addresses` → `for_each_vertex_underlying` →
//! `flatten_vertex_blob` → `Forest::commit_shard`) is added on top of the
//! `RocksHypergraphStore` in the node's migration entrypoint.

use quil_forest::l3_leaf_key;
use quil_tries::{deserialize_go_tree, VectorCommitmentTree};

mod walk;
pub use walk::{
    convert_app, convert_db, convert_shard, install_forest_boot, install_forest_for_sync,
    install_forest_if_migrated, quil_shards_for_app, run_conversion, run_conversion_in_place,
    run_conversion_in_place_with_shards, run_unified_consolidation_in_place,
    shards_for_app_from_store, ConvertReport, ShardConversion,
};

/// Flatten one legacy per-vertex blob into the forest's flat Level-3 leaves.
///
/// `blob` is a Go-serialized `VectorCommitmentTree` (the leaf value stored
/// under `vertex_address` in a shard-phase tree). Each inner field
/// `(field_key, value)` becomes an L3 leaf `(vertex_address ++ field_key,
/// value)`. An empty or `None` blob yields no leaves (a tombstoned/absent
/// vertex contributes nothing).
///
/// Determinism: `VectorCommitmentTree::leaves()` walks in nibble order, so
/// repeated conversions of the same blob produce identical L3 leaf sets — the
/// property the migration relies on to be reproducible across nodes.
pub fn flatten_vertex_blob(
    vertex_address: &[u8],
    blob: &[u8],
) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    // An empty value is a TOMBSTONE / placeholder — an OR-set `removes` entry,
    // or an `adds`-side placeholder for a removed-but-never-added id. It has no
    // fields to flatten, but it MUST still contribute a leaf: otherwise the
    // phase root wouldn't reflect the removal and two nodes disagreeing on
    // removals would compute identical `state_roots`. Keep it as a single leaf
    // keyed by the vertex address (64 bytes — never collides with a flattened
    // field key, which is 64 + field_key bytes).
    if blob.is_empty() {
        return Ok(vec![(vertex_address.to_vec(), Vec::new())]);
    }
    let mut tree = VectorCommitmentTree::new();
    match deserialize_go_tree(blob) {
        Ok(Some(root)) => tree.root = Some(root),
        // Non-empty but not a decodable go-tree (parse error or empty tree):
        // preserve the raw bytes as a single address-keyed leaf.
        _ => return Ok(vec![(vertex_address.to_vec(), blob.to_vec())]),
    }
    Ok(tree
        .leaves()
        .into_iter()
        .map(|(field_key, value)| (l3_leaf_key(vertex_address, &field_key), value))
        .collect())
}

/// Flatten a whole shard-phase tree's leaves (each `(vertex_address, blob)`)
/// into the shard's Level-3 leaves, ready for
/// [`quil_forest::Forest::commit_shard_phase`]. This is the per-phase body of
/// the shard walk; the caller supplies the phase's `(vertex_address, blob)`
/// pairs (from `for_each_vertex_underlying`) and commits the returned leaves.
pub fn flatten_phase_leaves(
    vertex_blobs: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut out = Vec::new();
    for (vertex_address, blob) in vertex_blobs {
        out.extend(flatten_vertex_blob(&vertex_address, &blob)?);
    }
    Ok(out)
}

/// Per-vertex-subtree migration leaf builder: each `(vertex_address, blob)` →
/// ONE shard leaf `(data_address = vertex_address[32..64], vertex_leaf_value(blob))`.
/// This MIRRORS the running node's `HypergraphCrdt::per_vertex_leaf` exactly, so
/// migration and live commit produce IDENTICAL shard roots.
pub fn per_vertex_phase_leaves(
    vertex_blobs: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut out = Vec::new();
    for (vertex_address, blob) in vertex_blobs {
        let data_address = if vertex_address.len() >= 64 {
            vertex_address[32..64].to_vec()
        } else {
            vertex_address
        };
        out.push((data_address, quil_tries::vertex_leaf_value(&blob)?));
    }
    Ok(out)
}

/// Compute the forest phase root a set of per-vertex blobs would produce, using
/// a FRESH in-memory JMT — the sync-side verification primitive.
///
/// A syncing node uses this to check pulled state against the header's
/// `expected_root` WITHOUT touching the persistent forest, so it needs no
/// version coordination with the live commit path. The JMT root is
/// content-addressed, so a fresh commit of the complete leaf set equals the
/// incrementally-committed forest phase root exactly when the blobs are the
/// complete, correct state for that shard-phase. On a match the caller persists
/// the vertex CONTENT (`save_vertex_underlying`) and the CRDT's next commit
/// rebuilds the persistent forest from it.
pub fn forest_root_of_vertex_blobs(
    vertex_blobs: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
) -> anyhow::Result<[u8; 32]> {
    let leaves = flatten_phase_leaves(vertex_blobs)?;
    let mem = quil_forest::MemTreeStore::default();
    Ok(quil_forest::commit(&mem, 0, leaves)
        .map_err(|e| anyhow::anyhow!("forest verify commit: {e}"))?
        .0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;
    use quil_tries::{serialize_go_tree, VectorCommitmentTree};

    /// Build a legacy per-vertex tree with the given `(field_key, value)`
    /// fields and serialize it the way the on-chain DB stores it.
    fn make_vertex_blob(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut t = VectorCommitmentTree::new();
        for (k, v) in fields {
            t.insert(k, v, &[], &BigInt::from(v.len() as u64)).unwrap();
        }
        serialize_go_tree(t.root.as_ref()).unwrap()
    }

    #[test]
    fn verify_root_equals_persistent_commit_root() {
        // The sync-side fresh-JMT verification must equal the persistent
        // forest phase root for the same blobs (content-determinism) — the
        // property that lets sync verify without touching the live forest.
        let blobs = vec![
            (vec![0x11u8; 64], make_vertex_blob(&[(&[0xAAu8; 32], b"x")])),
            (vec![0x22u8; 64], make_vertex_blob(&[(&[0xBBu8; 32], b"y"), (&[0xCCu8; 32], b"z")])),
        ];
        let verify_root = forest_root_of_vertex_blobs(blobs.clone()).unwrap();

        // Persistent forest commit of the same flattened leaves.
        let dir = tempfile::tempdir().unwrap();
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        let db = std::sync::Arc::new(rocksdb::DB::open(&opts, dir.path()).unwrap());
        let forest = quil_forest::Forest::new(db);
        let committed = forest
            .commit_shard_phase(b"shard", quil_forest::Phase::VertexAdds, 0, flatten_phase_leaves(blobs).unwrap())
            .unwrap();
        assert_eq!(verify_root, committed, "fresh-JMT verify root == persistent commit root");
    }

    #[test]
    fn flatten_prefixes_fields_with_vertex_address() {
        let vaddr = vec![0xABu8; 64]; // global-shard leaf key width
        let type_key = vec![0xFFu8; 32];
        let status_key = vec![0x00u8; 32];
        let blob = make_vertex_blob(&[
            (&type_key, b"prover:Prover"),
            (&status_key, &[1u8]),
        ]);

        let leaves = flatten_vertex_blob(&vaddr, &blob).unwrap();
        assert_eq!(leaves.len(), 2);
        // Every L3 key is the vertex address followed by the inner field key.
        for (k, _) in &leaves {
            assert_eq!(&k[..64], &vaddr[..], "L3 key carries the vertex address prefix");
            assert_eq!(k.len(), 64 + 32);
        }
        // The type field survived with its value.
        let type_leaf = leaves
            .iter()
            .find(|(k, _)| k[64..] == type_key[..])
            .expect("type field present");
        assert_eq!(type_leaf.1, b"prover:Prover");
    }

    #[test]
    fn flatten_is_deterministic() {
        let vaddr = vec![0x07u8; 64];
        let blob = make_vertex_blob(&[
            (&[0x01u8; 32], b"a"),
            (&[0x02u8; 32], b"bb"),
            (&[0x03u8; 32], b"ccc"),
        ]);
        let a = flatten_vertex_blob(&vaddr, &blob).unwrap();
        let b = flatten_vertex_blob(&vaddr, &blob).unwrap();
        assert_eq!(a, b, "same blob → identical L3 leaves (reproducible migration)");
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn empty_value_yields_tombstone_leaf() {
        // A raw-empty value — an OR-set `removes` entry or an add-side
        // placeholder — must yield exactly one tombstone leaf keyed by the
        // vertex address, so the phase root reflects the removal.
        let addr = vec![0u8; 64];
        let leaves = flatten_vertex_blob(&addr, &[]).unwrap();
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0], (addr, Vec::<u8>::new()));
    }

    #[test]
    fn flatten_phase_composes_multiple_vertices() {
        let v1 = vec![0x11u8; 64];
        let v2 = vec![0x22u8; 64];
        let b1 = make_vertex_blob(&[(&[0xAAu8; 32], b"x")]);
        let b2 = make_vertex_blob(&[(&[0xBBu8; 32], b"y"), (&[0xCCu8; 32], b"z")]);
        let leaves =
            flatten_phase_leaves(vec![(v1.clone(), b1), (v2.clone(), b2)]).unwrap();
        assert_eq!(leaves.len(), 3);
        assert!(leaves.iter().any(|(k, _)| k.starts_with(&v1)));
        assert_eq!(leaves.iter().filter(|(k, _)| k.starts_with(&v2)).count(), 2);
    }
}

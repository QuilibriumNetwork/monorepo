//! Phase F — epoch-aligned deterministic prover reassignment on shard
//! split/merge.
//!
//! When an app-shard split (parent P → children C[0..N]) or merge
//! (children → parent) takes effect at the E+2 epoch boundary, every
//! prover allocated to the affected shard(s) must be moved to the new
//! shard by rewriting its allocation's `ConfirmationFilter`. Because the
//! allocation vertex address is `poseidon("PROVER_ALLOCATION" || pubkey
//! || filter)` (see [`super::materialize::allocation_address`]), rewriting
//! the filter **re-keys** the vertex — it cannot be mutated in place. So
//! reassignment writes a new vertex at the child-filter address, removes
//! the old one, and rebuilds the prover's allocation hyperedge atom so
//! ProverKick can still enumerate the moved allocation.
//!
//! This is a deliberate hard-fork DIVERGENCE from Go (whose split
//! materialize is grid-only; provers redistribute emergently via the
//! normal join/leave lifecycle). The child-assignment rule here is a
//! NET-NEW consensus invariant: every node MUST compute it identically
//! over committed state. The pure functions in this module encode that
//! invariant; the orchestration (enumerate affected provers, write to
//! `HypergraphState`) lives in `intrinsic.rs::reassign_shard_allocations`.

use num_bigint::BigInt;
use quil_tries::VectorCommitmentTree;
use quil_types::error::Result;

use super::materialize::allocation_hyperedge_atom;
use crate::global_schema::{write_field, GLOBAL_INTRINSIC_ADDRESS};
use crate::prover_registry::{rebuild_vertex_tree_from_blob, vertex_tree_to_blob};

const ALLOCATION_CLASS: &str = "allocation:ProverAllocation";

/// Deterministic prover→child-shard assignment for an epoch-aligned split.
///
/// Buckets the prover by the high bits of its 32-byte address into the
/// ordered child list: `(addr[0] * n) >> 8` maps the leading address byte
/// uniformly onto `[0, n)`. For `n ∈ {2,4,8}` this equals
/// `addr[0] >> (8 - log2 n)`, i.e. it selects the child whose suffix-bucket
/// matches the prover's leading address bits (children are suffix-ordered
/// ascending by `shard_rebalancer::compute_proposed_shards`:
/// `{0x00,0x80}` / `{0x00,0x40,0x80,0xC0}` / `{0x00,0x20,…,0xE0}`). The
/// `* n >> 8` form also generalizes cleanly to any `2..=8` child count.
///
/// CONSENSUS-CRITICAL: the prover address is committed state (poseidon of
/// the registered pubkey), so this is identical on every node. Do not
/// change the bucketing without a fork.
pub fn assign_child_index(prover_address: &[u8], num_children: usize) -> usize {
    if num_children <= 1 {
        return 0;
    }
    let lead = prover_address.first().copied().unwrap_or(0) as usize;
    ((lead * num_children) >> 8).min(num_children - 1)
}

/// Rewrite an allocation vertex blob's `ConfirmationFilter` field to
/// `new_filter`, preserving every other field verbatim — Status, Epoch,
/// and all frame-number fields carry forward unchanged (no Epoch bump: a
/// re-key is a pure address move, not a lifecycle event, matching the
/// reject-leave invariant in `materialize_prover_reject`). Returns the new
/// blob to be written at the child-filter allocation address.
pub fn rewrite_allocation_filter(old_blob: &[u8], new_filter: &[u8]) -> Result<Vec<u8>> {
    let mut tree = rebuild_vertex_tree_from_blob(old_blob);
    write_field(&mut tree, ALLOCATION_CLASS, "ConfirmationFilter", new_filter)?;
    Ok(vertex_tree_to_blob(&tree))
}

/// Rebuild a prover's allocation hyperedge blob, replacing the atom for
/// `old_alloc_addr` with one for `new_alloc_addr` (built from
/// `new_alloc_tree`) while keeping every other atom byte-identical.
///
/// The hyperedge is a vector-commitment trie keyed by 64-byte atom ids
/// `GLOBAL_INTRINSIC_ADDRESS || allocation_address`; its structure is a
/// pure function of the `(key, value)` set, so re-inserting unchanged
/// atoms verbatim (in any order) reproduces an identical blob across
/// nodes. The replaced atom's value is recomputed deterministically via
/// the shared [`allocation_hyperedge_atom`] builder.
///
/// An empty/absent existing blob yields a hyperedge with just the new
/// atom (a prover whose only allocation is the one being reassigned).
pub fn rebuild_hyperedge_with_reassigned_atom(
    existing_blob: &[u8],
    old_alloc_addr: &[u8; 32],
    new_alloc_addr: &[u8; 32],
    new_alloc_tree: &VectorCommitmentTree,
) -> Result<Vec<u8>> {
    let mut old_key = [0u8; 64];
    old_key[..32].copy_from_slice(&GLOBAL_INTRINSIC_ADDRESS);
    old_key[32..].copy_from_slice(old_alloc_addr);

    let mut new_key = [0u8; 64];
    new_key[..32].copy_from_slice(&GLOBAL_INTRINSIC_ADDRESS);
    new_key[32..].copy_from_slice(new_alloc_addr);

    let mut tree = VectorCommitmentTree::new();

    // Re-insert every existing atom except the one being replaced (and any
    // stale entry already at the new key, in case of a merge collision).
    if !existing_blob.is_empty() {
        if let Some(root) = quil_tries::deserialize_go_tree(existing_blob)? {
            let mut src = VectorCommitmentTree::new();
            src.root = Some(root);
            for (key, value) in src.leaves() {
                if key.as_slice() == old_key.as_slice() || key.as_slice() == new_key.as_slice() {
                    continue;
                }
                tree.insert(&key, &value, &[], &BigInt::from(value.len() as u64))?;
            }
        }
    }

    let (atom_id, atom_bytes) = allocation_hyperedge_atom(new_alloc_addr, new_alloc_tree)?;
    tree.insert(
        &atom_id,
        &atom_bytes,
        &[],
        &BigInt::from(atom_bytes.len() as u64),
    )?;

    Ok(vertex_tree_to_blob(&tree))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global_schema::read_field;
    use crate::prover_registry::rebuild_vertex_tree_from_blob;

    // ---- assign_child_index -------------------------------------------

    #[test]
    fn assign_child_index_single_child_is_zero() {
        assert_eq!(assign_child_index(&[0xAB; 32], 1), 0);
        assert_eq!(assign_child_index(&[0x00; 32], 0), 0);
    }

    #[test]
    fn assign_child_index_binary_split_partitions_at_0x80() {
        // n=2: top bit selects the child.
        assert_eq!(assign_child_index(&[0x00], 2), 0);
        assert_eq!(assign_child_index(&[0x7F], 2), 0);
        assert_eq!(assign_child_index(&[0x80], 2), 1);
        assert_eq!(assign_child_index(&[0xFF], 2), 1);
    }

    #[test]
    fn assign_child_index_quaternary_split_uses_top_two_bits() {
        // n=4: top two bits → 0..3, boundaries at 0x40/0x80/0xC0.
        assert_eq!(assign_child_index(&[0x00], 4), 0);
        assert_eq!(assign_child_index(&[0x3F], 4), 0);
        assert_eq!(assign_child_index(&[0x40], 4), 1);
        assert_eq!(assign_child_index(&[0x80], 4), 2);
        assert_eq!(assign_child_index(&[0xC0], 4), 3);
        assert_eq!(assign_child_index(&[0xFF], 4), 3);
    }

    #[test]
    fn assign_child_index_octal_split_uses_top_three_bits() {
        assert_eq!(assign_child_index(&[0x00], 8), 0);
        assert_eq!(assign_child_index(&[0x20], 8), 1);
        assert_eq!(assign_child_index(&[0xE0], 8), 7);
        assert_eq!(assign_child_index(&[0xFF], 8), 7);
    }

    #[test]
    fn assign_child_index_is_in_range_and_deterministic() {
        for n in [2usize, 3, 4, 5, 8] {
            for b in 0u16..=255 {
                let idx = assign_child_index(&[b as u8], n);
                assert!(idx < n, "idx {idx} out of range for n={n}, byte={b}");
                // Deterministic — same input, same output.
                assert_eq!(idx, assign_child_index(&[b as u8], n));
            }
        }
    }

    #[test]
    fn assign_child_index_empty_address_is_zero() {
        assert_eq!(assign_child_index(&[], 4), 0);
    }

    // ---- rewrite_allocation_filter ------------------------------------

    fn make_alloc_blob(prover_addr: &[u8; 32], filter: &[u8]) -> Vec<u8> {
        let tree =
            super::super::materialize::create_allocation_vertex_tree(prover_addr, filter, 42)
                .unwrap();
        vertex_tree_to_blob(&tree)
    }

    #[test]
    fn rewrite_allocation_filter_swaps_filter_keeps_other_fields() {
        let prover_addr = [0x11u8; 32];
        let parent = vec![0xAAu8; 32];
        let mut child = parent.clone();
        child.push(0x80);

        let old_blob = make_alloc_blob(&prover_addr, &parent);
        let new_blob = rewrite_allocation_filter(&old_blob, &child).unwrap();

        let tree = rebuild_vertex_tree_from_blob(&new_blob);
        // ConfirmationFilter rewritten.
        assert_eq!(
            read_field(&tree, ALLOCATION_CLASS, "ConfirmationFilter").unwrap(),
            child
        );
        // Prover reference + JoinFrameNumber preserved verbatim.
        assert_eq!(
            read_field(&tree, ALLOCATION_CLASS, "Prover").unwrap(),
            prover_addr.to_vec()
        );
        assert_eq!(
            read_field(&tree, ALLOCATION_CLASS, "JoinFrameNumber").unwrap(),
            42u64.to_be_bytes().to_vec()
        );
    }

    // ---- rebuild_hyperedge_with_reassigned_atom -----------------------

    #[test]
    fn rebuild_hyperedge_from_empty_yields_single_atom() {
        let prover_addr = [0x22u8; 32];
        let new_filter = vec![0xBBu8; 33];
        let new_addr = super::super::materialize::allocation_address(&prover_addr, &new_filter)
            .unwrap();
        let new_tree =
            super::super::materialize::create_allocation_vertex_tree(&prover_addr, &new_filter, 7)
                .unwrap();

        let old_addr = super::super::materialize::allocation_address(&prover_addr, &[0xBBu8; 32])
            .unwrap();
        let blob =
            rebuild_hyperedge_with_reassigned_atom(&[], &old_addr, &new_addr, &new_tree).unwrap();

        let mut tree = VectorCommitmentTree::new();
        tree.root = quil_tries::deserialize_go_tree(&blob).unwrap();
        let leaves = tree.leaves();
        assert_eq!(leaves.len(), 1);
        // Atom key = GLOBAL_INTRINSIC_ADDRESS || new_addr.
        let mut expect = [0u8; 64];
        expect[..32].copy_from_slice(&GLOBAL_INTRINSIC_ADDRESS);
        expect[32..].copy_from_slice(&new_addr);
        assert_eq!(leaves[0].0.as_slice(), expect.as_slice());
    }

    #[test]
    fn rebuild_hyperedge_replaces_old_atom_keeps_unrelated() {
        use super::super::materialize::{
            allocation_address, build_prover_allocation_hyperedge_blob,
            create_allocation_vertex_tree,
        };
        let prover_addr = [0x33u8; 32];

        // Prover has two allocations: parent shard (to be reassigned) and
        // an unrelated shard (must survive untouched).
        let parent = vec![0xCCu8; 32];
        let unrelated = vec![0xDDu8; 32];
        let parent_addr = allocation_address(&prover_addr, &parent).unwrap();
        let unrelated_addr = allocation_address(&prover_addr, &unrelated).unwrap();
        let parent_tree = create_allocation_vertex_tree(&prover_addr, &parent, 1).unwrap();
        let unrelated_tree = create_allocation_vertex_tree(&prover_addr, &unrelated, 1).unwrap();

        let existing = build_prover_allocation_hyperedge_blob(
            &prover_addr,
            &[(parent_addr, &parent_tree), (unrelated_addr, &unrelated_tree)],
        )
        .unwrap();

        // Reassign parent → child. Use the 0x80 suffix child: a 0x00
        // suffix would re-key to the SAME address (poseidon absorbs
        // trailing zero bytes — see `child_zero_suffix_collides_with_parent`),
        // which is the in-place case, not the re-key case under test here.
        let mut child = parent.clone();
        child.push(0x80);
        let child_addr = allocation_address(&prover_addr, &child).unwrap();
        let child_tree = create_allocation_vertex_tree(&prover_addr, &child, 1).unwrap();

        let rebuilt = rebuild_hyperedge_with_reassigned_atom(
            &existing,
            &parent_addr,
            &child_addr,
            &child_tree,
        )
        .unwrap();

        let mut tree = VectorCommitmentTree::new();
        tree.root = quil_tries::deserialize_go_tree(&rebuilt).unwrap();
        let keys: Vec<Vec<u8>> = tree.leaves().into_iter().map(|(k, _)| k).collect();

        let atom_key = |addr: &[u8; 32]| {
            let mut k = [0u8; 64];
            k[..32].copy_from_slice(&GLOBAL_INTRINSIC_ADDRESS);
            k[32..].copy_from_slice(addr);
            k.to_vec()
        };

        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&atom_key(&child_addr)), "child atom present");
        assert!(keys.contains(&atom_key(&unrelated_addr)), "unrelated atom kept");
        assert!(!keys.contains(&atom_key(&parent_addr)), "old parent atom removed");
    }

    #[test]
    fn child_zero_suffix_collides_with_parent_address() {
        // Documents the in-place reassignment case the orchestration must
        // guard: poseidon's byte→field packing absorbs trailing zero bytes,
        // so a parent filter and its first split child (parent‖0x00) hash to
        // the SAME allocation address. Reassigning a prover onto that child
        // is therefore an in-place ConfirmationFilter update (set), NOT a
        // re-key — the caller MUST NOT then delete the old address (it's the
        // same vertex) or it would erase the allocation.
        use super::super::materialize::allocation_address;
        let prover_addr = [0x44u8; 32];
        let parent = vec![0xEEu8; 32];
        let mut child_zero = parent.clone();
        child_zero.push(0x00);
        let mut child_high = parent.clone();
        child_high.push(0x80);

        let parent_a = allocation_address(&prover_addr, &parent).unwrap();
        let child_zero_a = allocation_address(&prover_addr, &child_zero).unwrap();
        let child_high_a = allocation_address(&prover_addr, &child_high).unwrap();

        assert_eq!(parent_a, child_zero_a, "0x00-suffix child collides → in-place");
        assert_ne!(parent_a, child_high_a, "non-zero-suffix child re-keys");
    }
}

//! Efficient JMT-native forest sync — a Merkle diff, not a full transfer.
//!
//! # Why a diff, not a snapshot
//!
//! A behind/joining node already holds *most* of a shard's state; only the
//! frames since it fell behind changed anything. Transferring every leaf (or
//! rebuilding the tree from blobs) is O(shard); the tree is a hash trie, so we
//! can do O(changed) instead: a subtree whose root hash already matches the
//! peer's needs nothing, and we descend only where hashes differ.
//!
//! # Self-authenticating
//!
//! The walk is rooted at the peer's tree root, which the caller has already
//! pinned to the trusted header root (for a QUIL sub-shard, via the app
//! aggregation co-path — see [`crate::app_root_from_shard_path`]). Every node we
//! fetch is addressed through its parent's child-hash, so a peer cannot serve a
//! node that doesn't hash into the trusted root: the diff walk *is* the proof.
//!
//! # Transport-agnostic
//!
//! [`diff_leaves`] drives the walk against any two [`TreeReader`]s. In a local
//! test both are in-memory; in production the `source` reader is gRPC-backed, so
//! the *same* walk fetches only the nodes whose hash differs — the efficiency is
//! intrinsic to the walk, not the transport.
//!
//! # Monotonic phase trees
//!
//! A phase tree only ever gains keys or updates a key's value (the OR-set keeps
//! adds and removes in separate trees; nothing deletes a key from a phase tree).
//! So a behind client's key set is a subset of the peer's, and applying the
//! peer's differing leaves brings it exactly to the peer's root — which the
//! caller then verifies by root equality as the safety net.

use std::collections::HashMap;

use jmt::storage::{Node, NodeKey, TreeReader};
use jmt::{storage::NibblePath, KeyHash, OwnedValue, Version};

/// The `(key_hash, value)` leaves that `source` (at version `v_s`) has but
/// `target` (at version `v_t`) lacks or holds a different value for — exactly
/// what must transfer to bring `target` to `source`'s root. Subtrees whose hash
/// already matches `target`'s are skipped without descending, so a
/// network-backed `source` is only asked for the O(changed) nodes.
pub fn diff_leaves<S: TreeReader, T: TreeReader>(
    source: &S,
    v_s: Version,
    target: &T,
    v_t: Version,
) -> anyhow::Result<Vec<(KeyHash, OwnedValue)>> {
    let mut out = Vec::new();
    let s_key = NodeKey::new(v_s, NibblePath::new(vec![]));
    let t_key = NodeKey::new(v_t, NibblePath::new(vec![]));
    if let Some(s_node) = source.get_node_option(&s_key)? {
        let t_node = target.get_node_option(&t_key)?;
        walk(source, v_s, &s_key, s_node, target, &t_key, t_node, &mut out)?;
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn walk<S: TreeReader, T: TreeReader>(
    source: &S,
    v_s: Version,
    s_key: &NodeKey,
    s_node: Node,
    target: &T,
    t_key: &NodeKey,
    t_node: Option<Node>,
    out: &mut Vec<(KeyHash, OwnedValue)>,
) -> anyhow::Result<()> {
    let s_int = match s_node {
        Node::Null => return Ok(()),
        Node::Leaf(leaf) => {
            // We only reach a source leaf when its subtree hash differed from the
            // target's (or the target had nothing here), so it must transfer.
            let value = source.get_value(v_s, leaf.key_hash())?;
            out.push((leaf.key_hash(), value));
            return Ok(());
        }
        Node::Internal(int) => int,
    };
    // Target's children at this node, indexed by nibble: (child hash, version).
    let t_children: HashMap<u8, ([u8; 32], Version)> = match &t_node {
        Some(Node::Internal(t_int)) => t_int
            .children_sorted()
            .map(|(n, c)| (n.as_usize() as u8, (c.hash, c.version)))
            .collect(),
        _ => HashMap::new(),
    };
    for (nibble, s_child) in s_int.children_sorted() {
        let nib = nibble.as_usize() as u8;
        let t_match = t_children.get(&nib);
        if let Some((t_hash, _)) = t_match {
            if *t_hash == s_child.hash {
                continue; // identical subtree — transfer nothing below here
            }
        }
        let s_child_key = s_key.gen_child_node_key(s_child.version, nibble);
        let s_child_node = source.get_node(&s_child_key)?;
        let (t_child_key, t_child_node) = match t_match {
            Some((_, t_ver)) => {
                let k = t_key.gen_child_node_key(*t_ver, nibble);
                let n = target.get_node_option(&k)?;
                (k, n)
            }
            // Target has no child here: descend with an empty target so every
            // source leaf below transfers. The placeholder key is never fetched
            // (t_node is None ⇒ no further target children).
            None => (t_key.gen_child_node_key(t_key.version(), nibble), None),
        };
        walk(source, v_s, &s_child_key, s_child_node, target, &t_child_key, t_child_node, out)?;
    }
    Ok(())
}

/// MSB-first `bits` (1..=4) → nibble value 0..15.
fn bits_to_nibble(bits: &[bool]) -> u8 {
    let mut v = 0u8;
    for &b in bits {
        v = (v << 1) | (b as u8);
    }
    v
}

/// Whether `key`'s leading bits (MSB-first) equal `bit_path`.
fn key_has_bits(key: &[u8; 32], bit_path: &[bool]) -> bool {
    bit_path.iter().enumerate().all(|(i, &want)| {
        let byte = i / 8;
        let bit = 7 - (i % 8);
        key.get(byte).map(|b| (b >> bit) & 1 == 1).unwrap_or(false) == want
    })
}

/// Descend `reader` from its root `full` whole nibbles along `bit_path`, and —
/// when `pinned_root` is `Some` — AUTHENTICATE the descent: the root node must
/// hash to `pinned_root` (the trusted header app root), and every child fetched
/// must hash to the hash its parent recorded for it. So a peer cannot steer the
/// descent onto a node that doesn't chain into the trusted root — the node
/// returned at the prefix is authentic. Returns the node at the path (`None` if
/// the path leaves the tree). A leaf reached mid-descent is returned as-is (the
/// caller checks whether it lies under the full prefix). Mirrors
/// [`crate::Forest::app_subtree_root`]'s descent.
fn descend_nibbles<R: TreeReader>(
    reader: &R,
    version: Version,
    bit_path: &[bool],
    full: usize,
    pinned_root: Option<[u8; 32]>,
) -> anyhow::Result<Option<(NodeKey, Node)>> {
    let mut cur_key = NodeKey::new(version, NibblePath::new(vec![]));
    let mut cur_node = match reader.get_node_option(&cur_key)? {
        Some(n) => n,
        None => return Ok(None),
    };
    if let Some(root) = pinned_root {
        if node_hash(&cur_node) != root {
            anyhow::bail!("subtree sync: source root does not match the pinned header root");
        }
    }
    for i in 0..full {
        let nib_val = bits_to_nibble(&bit_path[i * 4..i * 4 + 4]);
        let int = match cur_node {
            Node::Internal(int) => int,
            // Collapsed to a leaf / nothing above the target depth — return it;
            // the caller checks whether it lies under the full prefix.
            other => return Ok(Some((cur_key, other))),
        };
        let child = int
            .children_sorted()
            .find(|(n, _)| n.as_usize() as u8 == nib_val)
            .map(|(n, c)| (n, c.version, c.hash));
        let (nibble, cver, chash) = match child {
            Some(x) => x,
            None => return Ok(None),
        };
        cur_key = cur_key.gen_child_node_key(cver, nibble);
        cur_node = match reader.get_node_option(&cur_key)? {
            Some(n) => n,
            None => return Ok(None),
        };
        // Authenticate: the fetched child must hash to what the (already-trusted)
        // parent committed for it — chaining trust from the pinned root down.
        if pinned_root.is_some() && node_hash(&cur_node) != chash {
            anyhow::bail!("subtree sync: descended child does not hash into its parent");
        }
    }
    Ok(Some((cur_key, cur_node)))
}

/// The Merkle hash of a node (matching the forest's `Sha256Jmt`).
fn node_hash(node: &Node) -> [u8; 32] {
    match node {
        Node::Internal(int) => int.hash::<sha2::Sha256>(),
        Node::Leaf(leaf) => leaf.hash::<sha2::Sha256>(),
        Node::Null => [0u8; 32],
    }
}

/// `target`'s children at a node keyed by nibble → (hash, version), or empty.
fn children_map(node: &Option<(NodeKey, Node)>) -> HashMap<u8, ([u8; 32], Version)> {
    match node {
        Some((_, Node::Internal(int))) => int
            .children_sorted()
            .map(|(n, c)| (n.as_usize() as u8, (c.hash, c.version)))
            .collect(),
        _ => HashMap::new(),
    }
}

/// Like [`diff_leaves`] but scoped to the SUBTREE at `bit_path` (a shard's
/// prefix) — the shard-prover sync that pulls ONLY its shard's leaves, not the
/// whole app tree. Descends both trees to the prefix and diffs just that
/// subtree. Handles nibble-aligned prefixes (the subtree is one node) and
/// non-nibble-aligned ones (the 64-way / 6-bit boundary — a width-`16>>rem`
/// child sub-range of the node at the whole-nibble depth). Empty `bit_path`
/// == [`diff_leaves`] (whole tree).
///
/// `pinned_root` is the trusted header app root: when `Some`, the descent to the
/// prefix is authenticated against it (see [`descend_nibbles`]), so the returned
/// **source subtree root** is guaranteed to compose to the header — a peer cannot
/// serve a fake subtree. The caller applies the returned leaves and verifies its
/// resulting local subtree root equals this source subtree root.
///
/// Returns `(leaves_to_transfer, source_subtree_root)`.
pub fn diff_leaves_under_prefix<S: TreeReader, T: TreeReader>(
    source: &S,
    v_s: Version,
    target: &T,
    v_t: Version,
    bit_path: &[bool],
    pinned_root: Option<[u8; 32]>,
) -> anyhow::Result<(Vec<(KeyHash, OwnedValue)>, [u8; 32])> {
    if bit_path.is_empty() {
        let leaves = diff_leaves(source, v_s, target, v_t)?;
        let root = match source.get_node_option(&NodeKey::new(v_s, NibblePath::new(vec![])))? {
            Some(n) => node_hash(&n),
            None => [0u8; 32],
        };
        return Ok((leaves, root));
    }
    let full = bit_path.len() / 4;
    let rem = bit_path.len() % 4;
    let mut out = Vec::new();

    let (s_key, s_node) = match descend_nibbles(source, v_s, bit_path, full, pinned_root)? {
        Some(x) => x,
        None => return Ok((out, [0u8; 32])), // source has nothing under this prefix
    };
    let t = descend_nibbles(target, v_t, bit_path, full, None)?;

    // Nibble-aligned: the subtree IS the node at the prefix path. Diff it whole.
    if rem == 0 {
        let subtree_root = node_hash(&s_node);
        let (t_key, t_node) = match t {
            Some((k, n)) => (k, Some(n)),
            None => (s_key.clone(), None),
        };
        walk(source, v_s, &s_key, s_node, target, &t_key, t_node, &mut out)?;
        return Ok((out, subtree_root));
    }

    // Non-nibble-aligned: diff only children [start, start+width) of the node.
    let top = bits_to_nibble(&bit_path[full * 4..]);
    let width = 16u8 >> rem;
    let start = top << (4 - rem);

    let s_int = match s_node {
        Node::Internal(i) => i,
        // A single leaf sits at the whole-nibble node: transfer iff it lies under
        // the FULL (sub-nibble) prefix. The subtree root is that leaf's hash.
        Node::Leaf(leaf) => {
            let under = key_has_bits(&leaf.key_hash().0, bit_path);
            let root = if under { node_hash(&Node::Leaf(leaf.clone())) } else { [0u8; 32] };
            if under {
                out.push((leaf.key_hash(), source.get_value(v_s, leaf.key_hash())?));
            }
            return Ok((out, root));
        }
        Node::Null => return Ok((out, [0u8; 32])),
    };
    // The shard commitment for this sub-range (authentic: `s_int` is authenticated).
    let subtree_root = s_int.subtree_hash::<sha2::Sha256>(start, width);
    let t_children = children_map(&t);
    for (nibble, s_child) in s_int.children_sorted() {
        let nib = nibble.as_usize() as u8;
        if nib < start || nib >= start + width {
            continue; // outside this shard's sub-range
        }
        if let Some((t_hash, _)) = t_children.get(&nib) {
            if *t_hash == s_child.hash {
                continue; // identical child subtree — nothing to pull
            }
        }
        let s_child_key = s_key.gen_child_node_key(s_child.version, nibble);
        let s_child_node = source.get_node(&s_child_key)?;
        let (t_child_key, t_child_node) = match (&t, t_children.get(&nib)) {
            (Some((tk, _)), Some((_, tver))) => {
                let k = tk.gen_child_node_key(*tver, nibble);
                let n = target.get_node_option(&k)?;
                (k, n)
            }
            (Some((tk, _)), None) => (tk.gen_child_node_key(tk.version(), nibble), None),
            (None, _) => (s_child_key.clone(), None),
        };
        walk(source, v_s, &s_child_key, s_child_node, target, &t_child_key, t_child_node, &mut out)?;
    }
    Ok((out, subtree_root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jmt::mock::MockTreeStore;
    use jmt::{JellyfishMerkleTree, KeyHash};
    use sha2::Sha256;

    type Jmt<'a> = JellyfishMerkleTree<'a, MockTreeStore, Sha256>;

    fn kh(i: u64) -> KeyHash {
        // Spread keys across the trie so they occupy different subtrees.
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&i.to_be_bytes());
        b[0] = (i as u8).wrapping_mul(37); // vary the top nibble
        KeyHash(b)
    }

    /// Commit a set of `(key_hash, value)` at `version` onto `store`.
    fn commit(store: &MockTreeStore, version: Version, kvs: Vec<(KeyHash, Vec<u8>)>) -> [u8; 32] {
        let tree = Jmt::new(store);
        let (root, batch) = tree
            .put_value_set(kvs.into_iter().map(|(k, v)| (k, Some(v))), version)
            .unwrap();
        store.write_tree_update_batch(batch).unwrap();
        root.0
    }

    /// Raw-key address → KeyHash (the forest positions leaves by raw address).
    fn addr(b0: u8, tag: u8) -> KeyHash {
        let mut k = [0u8; 32];
        k[0] = b0;
        k[31] = tag;
        KeyHash(k)
    }

    /// Shard-prover subtree-range sync: pull ONLY a shard's leaves (not the whole
    /// app tree), authenticate the subtree against the pinned header root, and
    /// reject a wrong pin. Covers the real 64-way / 6-bit boundary.
    #[test]
    fn subtree_diff_pulls_only_the_shard_and_authenticates() {
        // SOURCE app tree: shard X = top-6-bits 000000 (byte0 0x00..0x03) has 3
        // leaves; shard Y = 000001 (0x04..0x07) and a far shard (0x80) have data.
        let source = MockTreeStore::new(true);
        let mut kvs: Vec<(KeyHash, Vec<u8>)> = Vec::new();
        for (b0, tag) in [(0x00u8, 1u8), (0x01, 2), (0x03, 3)] {
            kvs.push((addr(b0, tag), vec![0xCC, b0])); // shard X
        }
        for b0 in [0x04u8, 0x05, 0x80] {
            kvs.push((addr(b0, b0), vec![0xDD, b0])); // shard Y + far shard
        }
        let app_root = commit(&source, 0, kvs);

        // Shard X's 6-bit prefix = 000000.
        let bits_x = vec![false; 6];

        // FOLLOWER starts empty; pull ONLY shard X, pinned to the trusted root.
        let empty = MockTreeStore::new(true);
        let (leaves, subtree_root) =
            diff_leaves_under_prefix(&source, 0, &empty, 0, &bits_x, Some(app_root)).unwrap();

        // Scoping: exactly shard X's 3 leaves transfer — NOT shard Y or the far
        // shard (would be 6 for the whole tree).
        assert_eq!(leaves.len(), 3, "pull ONLY shard X's leaves, not the whole app");
        for (k, _) in &leaves {
            assert!(k.0[0] < 0x04, "only byte0 0x00..0x03 (shard X) transfers, got {:#x}", k.0[0]);
        }
        assert_ne!(subtree_root, [0u8; 32]);

        // Apply the pulled leaves to the follower and confirm it now holds shard X
        // completely: a re-diff pulls nothing and its subtree root matches.
        let applied: Vec<(KeyHash, Vec<u8>)> = leaves.iter().map(|(k, v)| (*k, v.clone())).collect();
        commit(&empty, 0, applied);
        let (leaves2, root2) =
            diff_leaves_under_prefix(&source, 0, &empty, 0, &bits_x, Some(app_root)).unwrap();
        assert!(leaves2.is_empty(), "follower now has shard X — nothing left to pull");
        assert_eq!(root2, subtree_root, "authentic subtree root is stable");

        // A WRONG pinned root (fake header) is rejected — a peer cannot serve a
        // subtree that doesn't chain into the trusted root.
        let mut bad = app_root;
        bad[0] ^= 0xFF;
        let err = diff_leaves_under_prefix(&source, 0, &empty, 0, &bits_x, Some(bad));
        assert!(err.is_err(), "wrong pinned root must be rejected");
    }

    /// The diff transfers ONLY the changed leaves, and applying them to a copy of
    /// the stale tree reaches the source root exactly.
    #[test]
    fn diff_transfers_only_changed_leaves_and_reaches_source_root() {
        // TARGET (stale): keys 0..100 at value "v0".
        let target = MockTreeStore::new(true);
        let base: Vec<_> = (0..100u64).map(|i| (kh(i), b"v0".to_vec())).collect();
        let _t_root = commit(&target, 0, base.clone());

        // SOURCE: same 100 + 5 new keys + 3 updated values (version 1 on a fresh
        // store built from the same base so versions line up with a real catch-up).
        let source = MockTreeStore::new(true);
        commit(&source, 0, base.clone());
        let mut delta: Vec<(KeyHash, Vec<u8>)> = Vec::new();
        for i in 100..105u64 {
            delta.push((kh(i), b"new".to_vec())); // 5 additions
        }
        for i in [7u64, 42, 88] {
            delta.push((kh(i), b"v1".to_vec())); // 3 updates
        }
        let s_root = commit(&source, 1, delta.clone());

        // DIFF: source@1 vs target@0.
        let transferred = diff_leaves(&source, 1, &target, 0).unwrap();

        // Efficiency: only the 8 changed leaves move, not all 105.
        assert_eq!(transferred.len(), 8, "diff transfers exactly the changed leaves");
        let moved: std::collections::HashSet<_> =
            transferred.iter().map(|(k, _)| k.0).collect();
        for (k, _) in &delta {
            assert!(moved.contains(&k.0), "every changed key is in the diff");
        }

        // Correctness: apply the diff to a copy of the stale tree → source root.
        let patched = MockTreeStore::new(true);
        commit(&patched, 0, base);
        let got = commit(&patched, 1, transferred.into_iter().map(|(k, v)| (k, v)).collect());
        assert_eq!(got, s_root, "patched stale tree reaches the source root");
    }

    /// Identical trees diff to nothing (no transfer when already caught up).
    #[test]
    fn identical_trees_diff_to_empty() {
        let a = MockTreeStore::new(true);
        let b = MockTreeStore::new(true);
        let kvs: Vec<_> = (0..50u64).map(|i| (kh(i), b"x".to_vec())).collect();
        commit(&a, 0, kvs.clone());
        commit(&b, 0, kvs);
        assert!(diff_leaves(&a, 0, &b, 0).unwrap().is_empty());
    }
}

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

use jmt::storage::{LeafNode, Node, NodeKey, TreeReader};
use jmt::{storage::NibblePath, KeyHash, OwnedValue, ValueHash, Version};

/// Which commitment authenticates a subtree sync. Unified shard headers carry
/// the covered subtree root; a whole-application snapshot carries the app root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubtreeSyncAnchor {
    AppRoot([u8; 32]),
    SubtreeRoot([u8; 32]),
}

/// A tree reader that can answer many reads in one round trip. The diff walk
/// asks for a whole chunk of differing children (and of transferring leaves'
/// values) at once: a remote source turns each chunk into a few batched
/// requests instead of one request per node, and a local reader reads them
/// in turn.
pub trait BatchTreeReader: TreeReader {
    /// The node at each key, in order (`None` where absent).
    fn get_nodes(&self, keys: &[NodeKey]) -> anyhow::Result<Vec<Option<Node>>> {
        keys.iter().map(|key| self.get_node_option(key)).collect()
    }

    /// The value of each `(max_version, key)`, in order (`None` where absent).
    fn get_values(&self, reads: &[(Version, KeyHash)]) -> anyhow::Result<Vec<Option<OwnedValue>>> {
        reads.iter().map(|(version, key)| self.get_value_option(*version, *key)).collect()
    }
}

/// Pairs of (source, target) nodes the walk expands per round: a remote
/// source answers each round in a few batched requests.
const WALK_CHUNK: usize = 256;

/// A source node still to compare against the target's node at its path.
struct WalkPair {
    s_key: NodeKey,
    s_node: Node,
    t_key: NodeKey,
    t_node: Option<Node>,
}

/// A source child to fetch: its key, the hash its parent committed for it,
/// and the target's key at the same path when the target has a child there.
struct ChildRead {
    s_key: NodeKey,
    hash: [u8; 32],
    t_key: NodeKey,
    t_present: bool,
}

/// Fetch `children` from both trees (one batched read each) as pairs to walk,
/// authenticating every source child against its parent's hash.
fn fetch_children<S: BatchTreeReader, T: BatchTreeReader>(
    source: &S,
    target: &T,
    children: Vec<ChildRead>,
) -> anyhow::Result<Vec<WalkPair>> {
    let s_keys: Vec<NodeKey> = children.iter().map(|c| c.s_key.clone()).collect();
    let s_nodes = source.get_nodes(&s_keys)?;
    anyhow::ensure!(s_nodes.len() == children.len(), "sync: source answered a different number of nodes");
    let t_keys: Vec<NodeKey> = children.iter().filter(|c| c.t_present).map(|c| c.t_key.clone()).collect();
    let t_nodes = target.get_nodes(&t_keys)?;
    anyhow::ensure!(t_nodes.len() == t_keys.len(), "sync: target answered a different number of nodes");
    let mut t_nodes = t_nodes.into_iter();
    let mut pairs = Vec::with_capacity(children.len());
    for (child, s_node) in children.into_iter().zip(s_nodes) {
        let s_node = s_node.ok_or_else(|| anyhow::anyhow!("sync: source is missing a child node"))?;
        anyhow::ensure!(node_hash(&s_node) == child.hash, "sync: child does not hash into its parent");
        let t_node = if child.t_present { t_nodes.next().flatten() } else { None };
        pairs.push(WalkPair { s_key: child.s_key, s_node, t_key: child.t_key, t_node });
    }
    Ok(pairs)
}

fn authenticated_value<R: TreeReader>(
    reader: &R,
    version: Version,
    leaf: &LeafNode,
) -> anyhow::Result<OwnedValue> {
    let value = reader.get_value(version, leaf.key_hash())?;
    let reconstructed = LeafNode::new(leaf.key_hash(), ValueHash::with::<sha2::Sha256>(&value));
    anyhow::ensure!(reconstructed == *leaf, "sync: value does not match its committed leaf");
    Ok(value)
}

/// The `(key_hash, value)` leaves that `source` (at version `v_s`) has but
/// `target` (at version `v_t`) lacks or holds a different value for — exactly
/// what must transfer to bring `target` to `source`'s root. Subtrees whose hash
/// already matches `target`'s are skipped without descending, so a
/// network-backed `source` is only asked for the O(changed) nodes.
pub fn diff_leaves<S: BatchTreeReader, T: BatchTreeReader>(
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
        walk(source, target, vec![WalkPair { s_key, s_node, t_key, t_node }], &mut out)?;
    }
    Ok(out)
}

/// Walk `pairs` (and everything under them) depth first, a chunk of pairs per
/// round, collecting the source leaves the target lacks or holds differently.
/// Subtrees whose hash matches the target's are never read. Leaves are
/// returned in key order, as a depth-first walk in nibble order visits them.
fn walk<S: BatchTreeReader, T: BatchTreeReader>(
    source: &S,
    target: &T,
    pairs: Vec<WalkPair>,
    out: &mut Vec<(KeyHash, OwnedValue)>,
) -> anyhow::Result<()> {
    let first = out.len();
    let mut stack = pairs;
    while !stack.is_empty() {
        let chunk = stack.split_off(stack.len().saturating_sub(WALK_CHUNK));
        let mut leaves: Vec<(Version, LeafNode)> = Vec::new();
        let mut children: Vec<ChildRead> = Vec::new();
        for pair in chunk {
            let s_int = match pair.s_node {
                Node::Null => continue,
                Node::Leaf(leaf) => {
                    // We only reach a source leaf when its subtree hash differed
                    // from the target's (or the target had nothing here), so it
                    // must transfer. Its value is read at the version that wrote
                    // it, which every client syncing this tree asks for alike.
                    if pair.t_node.as_ref() != Some(&Node::Leaf(leaf.clone())) {
                        leaves.push((pair.s_key.version(), leaf));
                    }
                    continue;
                }
                Node::Internal(int) => int,
            };
            // Target's children at this node, indexed by nibble: (child hash, version).
            let t_children: HashMap<u8, ([u8; 32], Version)> = match &pair.t_node {
                Some(Node::Internal(t_int)) => t_int
                    .children_sorted()
                    .map(|(n, c)| (n.as_usize() as u8, (c.hash, c.version)))
                    .collect(),
                _ => HashMap::new(),
            };
            for (nibble, s_child) in s_int.children_sorted() {
                let t_match = t_children.get(&(nibble.as_usize() as u8));
                if t_match.is_some_and(|(t_hash, _)| *t_hash == s_child.hash) {
                    continue; // identical subtree — transfer nothing below here
                }
                // Target has no child here: descend with an empty target so
                // every source leaf below transfers. The placeholder key is
                // never fetched.
                let (t_key, t_present) = match t_match {
                    Some((_, t_ver)) => (pair.t_key.gen_child_node_key(*t_ver, nibble), true),
                    None => (pair.t_key.gen_child_node_key(pair.t_key.version(), nibble), false),
                };
                children.push(ChildRead {
                    s_key: pair.s_key.gen_child_node_key(s_child.version, nibble),
                    hash: s_child.hash,
                    t_key,
                    t_present,
                });
            }
        }
        stack.extend(fetch_children(source, target, children)?);
        let reads: Vec<(Version, KeyHash)> = leaves.iter().map(|(v, leaf)| (*v, leaf.key_hash())).collect();
        let values = source.get_values(&reads)?;
        anyhow::ensure!(values.len() == leaves.len(), "sync: source answered a different number of values");
        for ((_, leaf), value) in leaves.into_iter().zip(values) {
            let value = value.ok_or_else(|| anyhow::anyhow!("sync: source is missing a leaf value"))?;
            let reconstructed = LeafNode::new(leaf.key_hash(), ValueHash::with::<sha2::Sha256>(&value));
            anyhow::ensure!(reconstructed == leaf, "sync: value does not match its committed leaf");
            out.push((leaf.key_hash(), value));
        }
    }
    out[first..].sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
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
        None => {
            anyhow::ensure!(pinned_root.is_none() || pinned_root == Some([0; 32]),
                "subtree sync: missing source for the pinned header root");
            return Ok(None);
        }
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
        cur_node = reader.get_node(&cur_key)?;
        // Authenticate: the fetched child must hash to what the (already-trusted)
        // parent committed for it — chaining trust from the pinned root down.
        if node_hash(&cur_node) != chash {
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
        Node::Null => *b"SPARSE_MERKLE_PLACEHOLDER_HASH__",
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

/// Read a subtree commitment from a versioned reader, including a staged
/// update overlay. This lets an importer verify its result before committing.
pub(crate) fn subtree_root<R: TreeReader>(
    reader: &R,
    version: Version,
    bits: &[bool],
) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(bits.len() <= 256, "subtree prefix exceeds key width");
    let full = bits.len() / 4;
    let rem = bits.len() % 4;
    let Some((_, node)) = descend_nibbles(reader, version, bits, full, None)? else {
        return Ok([0; 32]);
    };
    Ok(match node {
        Node::Leaf(leaf) => if key_has_bits(&leaf.key_hash().0, bits) {
            leaf.hash::<sha2::Sha256>()
        } else { [0; 32] },
        Node::Null => if bits.is_empty() { node_hash(&Node::Null) } else { [0; 32] },
        Node::Internal(int) => if rem == 0 {
            int.hash::<sha2::Sha256>()
        } else {
            int.subtree_hash::<sha2::Sha256>(bits_to_nibble(&bits[full * 4..]) << (4 - rem), 16 >> rem)
        },
    })
}

/// Like [`diff_leaves`] but scoped to the SUBTREE at `bit_path` (a shard's
/// prefix) — the shard-prover sync that pulls ONLY its shard's leaves, not the
/// whole app tree. Descends both trees to the prefix and diffs just that
/// subtree. Handles nibble-aligned prefixes (the subtree is one node) and
/// non-nibble-aligned ones (the 64-way / 6-bit boundary — a width-`16>>rem`
/// child sub-range of the node at the whole-nibble depth). Empty `bit_path`
/// == [`diff_leaves`] (whole tree).
///
/// `anchor` authenticates either the whole app before descent, or the selected
/// subtree before its leaves are returned. The latter is the commitment in a
/// unified shard header and is independent of the peer's sibling subtrees.
///
/// Returns `(leaves_to_transfer, source_subtree_root)`.
pub fn diff_leaves_under_prefix<S: BatchTreeReader, T: BatchTreeReader>(
    source: &S,
    v_s: Version,
    target: &T,
    v_t: Version,
    bit_path: &[bool],
    anchor: Option<SubtreeSyncAnchor>,
) -> anyhow::Result<(Vec<(KeyHash, OwnedValue)>, [u8; 32])> {
    anyhow::ensure!(bit_path.len() <= 256, "subtree sync: prefix exceeds key width");
    let pinned_app_root = match anchor {
        Some(SubtreeSyncAnchor::AppRoot(root)) => Some(root),
        _ => None,
    };
    let check_subtree = |root| -> anyhow::Result<()> {
        if let Some(SubtreeSyncAnchor::SubtreeRoot(expected)) = anchor {
            anyhow::ensure!(root == expected, "subtree sync: source subtree does not match the pinned header root");
        }
        Ok(())
    };
    let full = bit_path.len() / 4;
    let rem = bit_path.len() % 4;
    let mut out = Vec::new();

    let (s_key, s_node) = match descend_nibbles(source, v_s, bit_path, full, pinned_app_root)? {
        Some(x) => x,
        None => {
            check_subtree([0; 32])?;
            return Ok((out, [0; 32]));
        }
    };
    let t = descend_nibbles(target, v_t, bit_path, full, None)?;

    // A compressed leaf can occur ABOVE the requested depth, including at a
    // nibble-aligned prefix. It belongs to this shard only if its key matches.
    if let Node::Leaf(leaf) = &s_node {
        let under = key_has_bits(&leaf.key_hash().0, bit_path);
        let root = if under { node_hash(&s_node) } else { [0; 32] };
        check_subtree(root)?;
        if under && t.as_ref().map(|(_, n)| n) != Some(&s_node) {
            out.push((leaf.key_hash(), authenticated_value(source, s_key.version(), leaf)?));
        }
        return Ok((out, root));
    }
    if matches!(s_node, Node::Null) && !bit_path.is_empty() {
        check_subtree([0; 32])?;
        return Ok((out, [0; 32]));
    }

    // Nibble-aligned: the subtree IS the node at the prefix path. Diff it whole.
    if rem == 0 {
        let subtree_root = node_hash(&s_node);
        check_subtree(subtree_root)?;
        let (t_key, t_node) = match t {
            Some((k, n)) => (k, Some(n)),
            None => (s_key.clone(), None),
        };
        walk(source, target, vec![WalkPair { s_key, s_node, t_key, t_node }], &mut out)?;
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
        Node::Leaf(_) | Node::Null => unreachable!("handled above"),
    };
    // The shard commitment for this sub-range (authentic: `s_int` is authenticated).
    let subtree_root = s_int.subtree_hash::<sha2::Sha256>(start, width);
    check_subtree(subtree_root)?;
    let t_children = children_map(&t);
    let mut children = Vec::new();
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
        let (t_key, t_present) = match (&t, t_children.get(&nib)) {
            (Some((tk, _)), Some((_, tver))) => (tk.gen_child_node_key(*tver, nibble), true),
            (Some((tk, _)), None) => (tk.gen_child_node_key(tk.version(), nibble), false),
            (None, _) => (s_child_key.clone(), false),
        };
        children.push(ChildRead { s_key: s_child_key, hash: s_child.hash, t_key, t_present });
    }
    let pairs = fetch_children(source, target, children)?;
    walk(source, target, pairs, &mut out)?;
    Ok((out, subtree_root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jmt::mock::MockTreeStore;
    use jmt::{JellyfishMerkleTree, KeyHash};
    use sha2::Sha256;

    type Jmt<'a> = JellyfishMerkleTree<'a, MockTreeStore, Sha256>;

    impl BatchTreeReader for MockTreeStore {}

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
            diff_leaves_under_prefix(&source, 0, &empty, 0, &bits_x, Some(SubtreeSyncAnchor::AppRoot(app_root))).unwrap();

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
            diff_leaves_under_prefix(&source, 0, &empty, 0, &bits_x, Some(SubtreeSyncAnchor::AppRoot(app_root))).unwrap();
        assert!(leaves2.is_empty(), "follower now has shard X — nothing left to pull");
        assert_eq!(root2, subtree_root, "authentic subtree root is stable");

        // A WRONG pinned root (fake header) is rejected — a peer cannot serve a
        // subtree that doesn't chain into the trusted root.
        let mut bad = app_root;
        bad[0] ^= 0xFF;
        let err = diff_leaves_under_prefix(&source, 0, &empty, 0, &bits_x, Some(SubtreeSyncAnchor::AppRoot(bad)));
        assert!(err.is_err(), "wrong pinned root must be rejected");
    }

    #[test]
    fn subtree_pin_handles_compressed_leaves_and_empty_prefixes() {
        let source = MockTreeStore::new(true);
        let root = commit(&source, 0, vec![(addr(0x80, 1), b"only leaf".to_vec())]);
        let empty = MockTreeStore::new(true);
        let (leaves, got) = diff_leaves_under_prefix(
            &source, 0, &empty, 0, &[false; 4], Some(SubtreeSyncAnchor::SubtreeRoot([0; 32])),
        ).unwrap();
        assert!(leaves.is_empty(), "a compressed leaf outside the shard must not transfer");
        assert_eq!(got, [0; 32]);
        for anchor in [SubtreeSyncAnchor::AppRoot([9; 32]), SubtreeSyncAnchor::SubtreeRoot([9; 32])] {
            assert!(diff_leaves_under_prefix(&source, 0, &empty, 0, &[], Some(anchor)).is_err());
        }
        let (leaves, got) = diff_leaves_under_prefix(
            &source, 0, &empty, 0, &[], Some(SubtreeSyncAnchor::SubtreeRoot(root)),
        ).unwrap();
        assert_eq!(got, root);
        assert_eq!(leaves.len(), 1);
        assert!(diff_leaves_under_prefix(
            &empty, 0, &source, 0, &[false], Some(SubtreeSyncAnchor::SubtreeRoot(root)),
        ).is_err(), "an absent tree cannot satisfy a nonempty anchor");
    }

    struct CorruptReader<'a> {
        source: &'a MockTreeStore,
        corrupt_child: bool,
    }

    impl BatchTreeReader for CorruptReader<'_> {}

    impl TreeReader for CorruptReader<'_> {
        fn get_node_option(&self, key: &NodeKey) -> anyhow::Result<Option<Node>> {
            let node = self.source.get_node_option(key)?;
            Ok(if self.corrupt_child && key.nibble_path().num_nibbles() > 0 {
                node.map(|_| Node::Null)
            } else { node })
        }
        fn get_value_option(&self, version: Version, key: KeyHash) -> anyhow::Result<Option<OwnedValue>> {
            let value = self.source.get_value_option(version, key)?;
            Ok(if self.corrupt_child { value } else { value.map(|_| b"forged value".to_vec()) })
        }
        fn get_rightmost_leaf(&self) -> anyhow::Result<Option<(NodeKey, LeafNode)>> { Ok(None) }
    }

    #[test]
    fn pinned_subtree_rejects_forged_descendants_and_values() {
        let source = MockTreeStore::new(true);
        let root = commit(&source, 0, vec![
            (addr(0x00, 1), b"one".to_vec()),
            (addr(0x01, 2), b"two".to_vec()),
            (addr(0x80, 3), b"sibling".to_vec()),
        ]);
        let empty = MockTreeStore::new(true);
        let (_, shard_root) = diff_leaves_under_prefix(
            &source, 0, &empty, 0, &[false], Some(SubtreeSyncAnchor::AppRoot(root)),
        ).unwrap();
        for corrupt_child in [true, false] {
            let peer = CorruptReader { source: &source, corrupt_child };
            let error = diff_leaves_under_prefix(
                &peer, 0, &empty, 0, &[false], Some(SubtreeSyncAnchor::SubtreeRoot(shard_root)),
            ).unwrap_err();
            assert!(error.to_string().contains(if corrupt_child { "child" } else { "value" }), "{error}");
        }
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

    /// Counts the round trips a remote source would make.
    struct Counting<'a> {
        inner: &'a MockTreeStore,
        node_batches: std::cell::Cell<usize>,
        nodes: std::cell::Cell<usize>,
        value_batches: std::cell::Cell<usize>,
    }

    impl TreeReader for Counting<'_> {
        fn get_node_option(&self, key: &NodeKey) -> anyhow::Result<Option<Node>> {
            self.node_batches.set(self.node_batches.get() + 1);
            self.nodes.set(self.nodes.get() + 1);
            self.inner.get_node_option(key)
        }
        fn get_value_option(&self, version: Version, key: KeyHash) -> anyhow::Result<Option<OwnedValue>> {
            self.value_batches.set(self.value_batches.get() + 1);
            self.inner.get_value_option(version, key)
        }
        fn get_rightmost_leaf(&self) -> anyhow::Result<Option<(NodeKey, LeafNode)>> {
            self.inner.get_rightmost_leaf()
        }
    }

    impl BatchTreeReader for Counting<'_> {
        fn get_nodes(&self, keys: &[NodeKey]) -> anyhow::Result<Vec<Option<Node>>> {
            self.node_batches.set(self.node_batches.get() + 1);
            self.nodes.set(self.nodes.get() + keys.len());
            keys.iter().map(|key| self.inner.get_node_option(key)).collect()
        }
        fn get_values(&self, reads: &[(Version, KeyHash)]) -> anyhow::Result<Vec<Option<OwnedValue>>> {
            self.value_batches.set(self.value_batches.get() + 1);
            reads.iter().map(|(version, key)| self.inner.get_value_option(*version, *key)).collect()
        }
    }

    /// A cold walk of a few thousand leaves takes a few dozen round trips,
    /// not one per node, and still returns every leaf in key order at the
    /// version that wrote it (here, across several versions).
    #[test]
    fn a_cold_walk_reads_each_chunk_in_one_round_trip() {
        let source = MockTreeStore::new(true);
        let mut expected: std::collections::BTreeMap<[u8; 32], Vec<u8>> = Default::default();
        for version in 0..3u64 {
            let kvs: Vec<_> = (0..1000u64)
                .map(|i| {
                    let mut key = <sha2::Sha256 as sha2::Digest>::digest((version * 1000 + i).to_be_bytes());
                    key[0] = key[0].wrapping_add(version as u8);
                    (KeyHash(key.into()), vec![version as u8; 8])
                })
                .collect();
            for (key, value) in &kvs {
                expected.insert(key.0, value.clone());
            }
            commit(&source, version, kvs);
        }
        let empty = MockTreeStore::new(true);
        let counting = Counting {
            inner: &source,
            node_batches: Default::default(),
            nodes: Default::default(),
            value_batches: Default::default(),
        };
        let out = diff_leaves(&counting, 2, &empty, 0).unwrap();
        let expected: Vec<_> = expected.into_iter().map(|(k, v)| (KeyHash(k), v)).collect();
        assert_eq!(out, expected, "every leaf, in key order, with its latest value");
        assert!(counting.nodes.get() > 3000);
        let round_trips = counting.node_batches.get() + counting.value_batches.get();
        assert!(round_trips < 80, "{round_trips} round trips for {} nodes", counting.nodes.get());
    }
}

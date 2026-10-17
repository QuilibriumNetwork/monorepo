//! Confines an application's shard/phase tree to the scopes a store still
//! serves. A worker keeps one tree per application phase across reassignments,
//! so the subtrees of every shard it served before stay reachable from its head
//! and on disk, although its frames commit only the served subtree roots.
//!
//! [`Forest::stage_scope_confinement`] rewrites only the nodes above the kept
//! scopes, dropping every child outside them, as a commit at a fresh version.
//! Kept subtrees and their roots are untouched, and the result is the tree a
//! store holding only the kept leaves would build. Afterwards
//! [`Forest::delete_outside_scope`] removes the records outside the scopes at
//! every version; it refuses unless the head no longer reaches them. Older
//! versions keep their in-scope reads, but no longer read the dropped subtrees.
use anyhow::Result;
use jmt::storage::{
    Child, Children, Node, NodeBatch, NodeKey, NibblePath, StaleNodeIndex, StaleNodeIndexBatch, TreeReader,
    TreeUpdateBatch,
};

use crate::forest::TreeStore;
use crate::{Forest, Phase, TreeId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    Inside,
    Ancestor,
    Outside,
}

/// A path is inside a kept scope when the scope prefixes it, an ancestor when
/// it prefixes a scope, and outside otherwise.
fn scope_of(bits: &[bool], keep: &[Vec<bool>]) -> Scope {
    if keep.iter().any(|k| bits.len() >= k.len() && bits[..k.len()] == k[..]) {
        Scope::Inside
    } else if keep.iter().any(|k| k[..bits.len().min(k.len())] == bits[..bits.len().min(k.len())]) {
        Scope::Ancestor
    } else {
        Scope::Outside
    }
}

fn key_bits(key: &[u8; 32]) -> Vec<bool> {
    (0..256).map(|i| key[i / 8] >> (7 - i % 8) & 1 == 1).collect()
}

fn path_bits(path: &NibblePath) -> Vec<bool> {
    path.bits().collect()
}

enum Rebuilt {
    Same,
    Gone,
    New(Node),
}

fn child_of(node: &Node) -> Child {
    match node {
        Node::Leaf(leaf) => Child::new(leaf.hash::<sha2::Sha256>(), 0, jmt::storage::NodeType::Leaf),
        Node::Internal(internal) => Child::new(internal.hash::<sha2::Sha256>(), 0, internal.node_type()),
        Node::Null => unreachable!("a null node is never a child"),
    }
}

struct Rebuild<'a> {
    reader: &'a TreeStore,
    keep: &'a [Vec<bool>],
    version: u64,
    batch: NodeBatch,
    stale: StaleNodeIndexBatch,
}

impl Rebuild<'_> {
    fn node(&mut self, key: &NodeKey) -> Result<Rebuilt> {
        let node = self.reader.get_node_option(key)?
            .ok_or_else(|| anyhow::anyhow!("forest node at version {} is missing", key.version()))?;
        let internal = match node {
            Node::Null => return Ok(Rebuilt::Same),
            Node::Leaf(leaf) => {
                return Ok(match scope_of(&key_bits(&leaf.key_hash().0), self.keep) {
                    Scope::Outside => Rebuilt::Gone,
                    _ => Rebuilt::Same,
                })
            }
            Node::Internal(internal) => internal,
        };
        let bits = path_bits(key.nibble_path());
        match scope_of(&bits, self.keep) {
            Scope::Inside => return Ok(Rebuilt::Same),
            Scope::Outside => return Ok(Rebuilt::Gone),
            Scope::Ancestor => {}
        }
        let mut children = Children::new();
        let mut fresh = Vec::new();
        let mut changed = false;
        for (nibble, child) in internal.children_sorted() {
            let child_key = key.gen_child_node_key(child.version, nibble);
            let rebuilt = match scope_of(&path_bits(child_key.nibble_path()), self.keep) {
                Scope::Inside => Rebuilt::Same,
                // A leaf stored here holds a key under this path, so it is out too.
                Scope::Outside => Rebuilt::Gone,
                Scope::Ancestor => self.node(&child_key)?,
            };
            match rebuilt {
                Rebuilt::Same => children.insert(nibble, child.clone()),
                Rebuilt::Gone => changed = true,
                Rebuilt::New(node) => {
                    changed = true;
                    let mut entry = child_of(&node);
                    entry.version = self.version;
                    children.insert(nibble, entry);
                    fresh.push((nibble, node));
                }
            }
        }
        if !changed {
            return Ok(Rebuilt::Same);
        }
        self.stale.insert(StaleNodeIndex { stale_since_version: self.version, node_key: key.clone() });
        if children.num_children() == 0 {
            return Ok(Rebuilt::Gone);
        }
        let only_leaf = (children.num_children() == 1)
            .then(|| children.iter().next().map(|(nibble, child)| (nibble, child.clone())))
            .flatten()
            .filter(|(_, child)| child.is_leaf());
        if let Some((nibble, child)) = only_leaf {
            // A lone leaf moves up to its parent, as a deletion would leave it.
            if let Some(position) = fresh.iter().position(|(n, _)| *n == nibble) {
                return Ok(Rebuilt::New(fresh.swap_remove(position).1));
            }
            let old = key.gen_child_node_key(child.version, nibble);
            let leaf = self.reader.get_node_option(&old)?
                .ok_or_else(|| anyhow::anyhow!("forest leaf at version {} is missing", old.version()))?;
            self.stale.insert(StaleNodeIndex { stale_since_version: self.version, node_key: old });
            return Ok(Rebuilt::New(leaf));
        }
        let here = NodeKey::new(self.version, key.nibble_path().clone());
        for (nibble, node) in fresh {
            self.batch.insert_node(here.gen_child_node_key(self.version, nibble), node);
        }
        Ok(Rebuilt::New(Node::Internal(jmt::storage::InternalNode::new(children))))
    }
}

/// Interval of 32-byte keys under `bits`: `[low, high)`, `high` absent at the
/// end of the key space.
fn key_interval(bits: &[bool]) -> ([u8; 32], Option<[u8; 32]>) {
    let mut low = [0u8; 32];
    for (i, bit) in bits.iter().enumerate().take(256) {
        if *bit {
            low[i / 8] |= 1 << (7 - i % 8);
        }
    }
    let mut high = low;
    for i in bits.len().min(256)..256 {
        high[i / 8] |= 1 << (7 - i % 8);
    }
    // Exclusive successor of the interval's last key.
    for byte in high.iter_mut().rev() {
        if *byte == 0xff {
            *byte = 0;
        } else {
            *byte += 1;
            return (low, Some(high));
        }
    }
    (low, None)
}

/// Key ranges outside every kept scope, as `[low, high)` with `None` for an
/// open end.
pub(crate) fn outside_key_ranges(keep: &[Vec<bool>]) -> Vec<(Option<[u8; 32]>, Option<[u8; 32]>)> {
    let mut covered: Vec<_> = keep.iter().map(|bits| key_interval(bits)).collect();
    covered.sort();
    let mut ranges = Vec::new();
    let mut cursor: Option<Option<[u8; 32]>> = Some(None); // Some(None): start of key space
    for (low, high) in covered {
        let Some(start) = cursor else { break };
        if start.map_or(low != [0; 32], |s| s < low) {
            ranges.push((start, Some(low)));
        }
        cursor = match (start, high) {
            (_, None) => None,
            (Some(s), Some(h)) if s > h => Some(Some(s)),
            (_, Some(h)) => Some(Some(h)),
        };
    }
    if let Some(start) = cursor {
        ranges.push((start, None));
    }
    ranges
}

/// Progress of [`Forest::delete_outside_scope`]; `cursor` resumes the node
/// sweep, `None` once it is complete.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScopeDeletion {
    pub nodes: usize,
    pub stale_records: usize,
    pub key_ranges: usize,
    pub cursor: Option<Vec<u8>>,
}

impl Forest {
    /// The commit, at `version` above `head`, that drops every subtree of an
    /// application's phase tree outside `keep` (canonical bit paths of its
    /// kept shards). `None` when the head reaches nothing outside them. The
    /// returned root is the new tree root; the puts carry the rewritten nodes,
    /// their size memos and stale records for the replaced ones.
    pub fn stage_scope_confinement(
        &self,
        app: &[u8],
        phase: Phase,
        head: u64,
        version: u64,
        keep: &[Vec<bool>],
    ) -> Result<Option<([u8; 32], Vec<(Vec<u8>, Vec<u8>)>)>> {
        anyhow::ensure!(version > head, "a confinement commit needs a version above the head");
        anyhow::ensure!(!keep.is_empty(), "confinement needs at least one kept scope");
        let reader = self.store(&TreeId::shard_phase(app, phase));
        let TreeStore::Rocks(store) = &reader else { return Ok(None) };
        let root_key = NodeKey::new(head, NibblePath::new(vec![]));
        let mut rebuild = Rebuild { reader: &reader, keep, version, batch: NodeBatch::default(), stale: Default::default() };
        let root = match rebuild.node(&root_key)? {
            Rebuilt::Same => return Ok(None),
            Rebuilt::Gone => Node::Null,
            Rebuilt::New(node) => node,
        };
        let hash = match &root {
            Node::Null => *b"SPARSE_MERKLE_PLACEHOLDER_HASH__",
            Node::Leaf(leaf) => leaf.hash::<sha2::Sha256>(),
            Node::Internal(internal) => internal.hash::<sha2::Sha256>(),
        };
        let mut batch = rebuild.batch;
        batch.insert_node(NodeKey::new(version, NibblePath::new(vec![])), root);
        let update = TreeUpdateBatch { node_batch: batch, stale_node_index_batch: rebuild.stale, node_stats: Vec::new() };
        Ok(Some((hash, store.update_puts(&update)?)))
    }

    /// Delete records of an application's phase tree outside `keep` at every
    /// version: nodes and their size memos (at most `scan_budget` node records
    /// examined per call, resuming at `cursor`), then, once the node sweep is
    /// complete, stale records, leaf values and preimages. Refuses unless the
    /// head at `head` reaches nothing outside `keep`.
    pub fn delete_outside_scope(
        &self,
        app: &[u8],
        phase: Phase,
        head: u64,
        keep: &[Vec<bool>],
        cursor: Option<Vec<u8>>,
        scan_budget: usize,
    ) -> Result<ScopeDeletion> {
        anyhow::ensure!(!keep.is_empty(), "scope deletion needs at least one kept scope");
        let staged = self.stage_scope_confinement(app, phase, head, head.saturating_add(1), keep)?;
        anyhow::ensure!(staged.is_none(), "the head still reaches subtrees outside the kept scopes");
        let reader = self.store(&TreeId::shard_phase(app, phase));
        let TreeStore::Rocks(store) = &reader else { return Ok(ScopeDeletion::default()) };
        let outside = |path: &NibblePath| scope_of(&path_bits(path), keep) == Scope::Outside;
        let (nodes, cursor) = store.delete_nodes_where(&outside, cursor, scan_budget)?;
        let mut deletion = ScopeDeletion { nodes, cursor, ..Default::default() };
        if deletion.cursor.is_none() {
            deletion.stale_records = store.delete_stale_where(&outside)?;
            let ranges = outside_key_ranges(keep);
            deletion.key_ranges = ranges.len();
            store.delete_keyed_ranges(&ranges)?;
        }
        Ok(deletion)
    }

    /// Compact an application phase tree's key range after a scope deletion.
    pub fn compact_shard_phase(&self, app: &[u8], phase: Phase) {
        if let TreeStore::Rocks(store) = self.store(&TreeId::shard_phase(app, phase)) {
            store.compact();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bits(byte: u8, len: usize) -> Vec<bool> {
        (0..len).map(|i| byte >> (7 - i) & 1 == 1).collect()
    }

    #[test]
    fn outside_ranges_complement_the_kept_intervals() {
        assert_eq!(outside_key_ranges(&[Vec::new()]), vec![]);
        let mut half = [0u8; 32];
        half[0] = 0x80;
        assert_eq!(outside_key_ranges(&[vec![false]]), vec![(Some(half), None)]);
        assert_eq!(outside_key_ranges(&[vec![true]]), vec![(None, Some(half))]);
        let mut a = [0u8; 32];
        a[0] = 0x40;
        let mut b = [0u8; 32];
        b[0] = 0x80;
        let mut c = [0u8; 32];
        c[0] = 0xc0;
        assert_eq!(outside_key_ranges(&[bits(0x40, 2), bits(0xc0, 2)]),
            vec![(None, Some(a)), (Some(b), Some(c))]);
        assert_eq!(scope_of(&bits(0x40, 1), &[bits(0x40, 2)]), Scope::Ancestor);
        assert_eq!(scope_of(&bits(0x40, 4), &[bits(0x40, 2)]), Scope::Inside);
        assert_eq!(scope_of(&bits(0x80, 4), &[bits(0x40, 2)]), Scope::Outside);
    }

    fn key(first: u8, last: u8) -> Vec<u8> {
        let mut key = vec![0u8; 32];
        key[0] = first;
        key[31] = last;
        key
    }

    fn open() -> (tempfile::TempDir, crate::CoordinatedDb, Forest) {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::CoordinatedDb::new(rocksdb::DB::open_default(dir.path()).unwrap());
        let forest = Forest::with_namespace(db.clone(), b"scope-test/".to_vec());
        (dir, db, forest)
    }

    fn apply(db: &crate::CoordinatedDb, puts: Vec<(Vec<u8>, Vec<u8>)>) {
        for (k, v) in puts {
            db.put(k, v).unwrap();
        }
    }

    fn fresh_root(leaves: &[(Vec<u8>, Vec<u8>)]) -> [u8; 32] {
        let (_dir, _db, forest) = open();
        forest.commit_shard_phase_raw(&APP, PHASE, 0, leaves.to_vec()).unwrap();
        forest.shard_phase_root(&APP, PHASE, 0).unwrap().unwrap()
    }

    fn outside_nodes(db: &crate::CoordinatedDb, keep: &[Vec<bool>]) -> usize {
        let mut prefix = b"scope-test/".to_vec();
        prefix.extend_from_slice(&TreeId::shard_phase(&APP, PHASE).prefix());
        prefix.push(b'n');
        let mut it = db.raw_iterator();
        it.seek(&prefix);
        let mut count = 0;
        while it.valid() && it.key().is_some_and(|k| k.starts_with(&prefix)) {
            let node_key = borsh::from_slice::<NodeKey>(&it.key().unwrap()[prefix.len()..]).unwrap();
            if scope_of(&path_bits(node_key.nibble_path()), keep) == Scope::Outside { count += 1; }
            it.next();
        }
        count
    }

    const APP: [u8; 32] = [7; 32];
    const PHASE: Phase = Phase::VertexAdds;

    /// The kept scope is the 6-bit shard 000001, which shares its first nibble
    /// with the dropped keys 0x01.. and 0x09.., below a dropped 0x80.. half.
    #[test]
    fn confinement_matches_a_tree_of_only_the_kept_leaves() {
        let (_dir, db, forest) = open();
        let keep = vec![bits(0x04, 6)];
        let all: Vec<_> = [(0x05, 1), (0x06, 2), (0x07, 3), (0x01, 4), (0x09, 5), (0x81, 6), (0xc1, 7)]
            .into_iter().map(|(first, last)| (key(first, last), vec![first, last])).collect();
        forest.commit_shard_phase_raw(&APP, PHASE, 0, all.clone()).unwrap();
        // History outside the scope, and an in-scope change at the head.
        forest.commit_shard_phase_raw(&APP, PHASE, 1, vec![(key(0x81, 6), vec![9]), (key(0x06, 2), vec![8])]).unwrap();
        let kept_before = forest.app_subtree_root(&APP, PHASE, 1, &keep[0]).unwrap();
        assert!(forest.delete_outside_scope(&APP, PHASE, 1, &keep, None, 100).is_err(),
            "deletion refuses while the head reaches dropped subtrees");

        let (root, puts) = forest.stage_scope_confinement(&APP, PHASE, 1, 2, &keep).unwrap().unwrap();
        apply(&db, puts);
        let kept: Vec<_> = vec![(key(0x05, 1), vec![5, 1]), (key(0x06, 2), vec![8]), (key(0x07, 3), vec![7, 3])];
        assert_eq!(root, fresh_root(&kept));
        assert_eq!(forest.shard_phase_root(&APP, PHASE, 2).unwrap().unwrap(), root);
        assert_eq!(forest.app_subtree_root(&APP, PHASE, 2, &keep[0]).unwrap(), kept_before);
        let (_fresh_dir, _, fresh) = open();
        fresh.commit_shard_phase_raw(&APP, PHASE, 0, kept.clone()).unwrap();
        for path in [bits(0x80, 1), bits(0x00, 4), bits(0x08, 5), Vec::new()] {
            assert_eq!(forest.app_subtree_root(&APP, PHASE, 2, &path).unwrap(),
                fresh.app_subtree_root(&APP, PHASE, 0, &path).unwrap());
        }
        assert!(forest.stage_scope_confinement(&APP, PHASE, 2, 3, &keep).unwrap().is_none(), "a repeat finds nothing");
        assert!(outside_nodes(&db, &keep) > 0);

        // A small budget resumes the sweep across calls.
        let mut cursor = None;
        let mut calls = 0;
        loop {
            let deletion = forest.delete_outside_scope(&APP, PHASE, 2, &keep, cursor, 2).unwrap();
            calls += 1;
            cursor = deletion.cursor;
            if cursor.is_none() {
                assert_eq!(deletion.key_ranges, 2);
                break;
            }
        }
        assert!(calls > 1);
        assert_eq!(outside_nodes(&db, &keep), 0);
        let reader = forest.shard_phase_reader(&APP, PHASE);
        let hash = |k: Vec<u8>| crate::KeyHash(k.try_into().unwrap());
        assert_eq!(reader.get_value_option(2, hash(key(0x05, 1))).unwrap(), Some(vec![5, 1]));
        assert_eq!(reader.get_value_option(2, hash(key(0x81, 6))).unwrap(), None);
        assert_eq!(reader.get_value_option(2, hash(key(0x01, 4))).unwrap(), None);
        // In-scope reads of an older version still work.
        assert_eq!(forest.app_subtree_root(&APP, PHASE, 1, &keep[0]).unwrap(), kept_before);
        assert_eq!(forest.app_subtree_root(&APP, PHASE, 2, &keep[0]).unwrap(), kept_before);

        // Later commits build exactly as on a store that only held the scope.
        forest.commit_shard_phase_raw(&APP, PHASE, 3, vec![(key(0x05, 1), vec![1])]).unwrap();
        let mut expected = kept.clone();
        expected[0].1 = vec![1];
        assert_eq!(forest.shard_phase_root(&APP, PHASE, 3).unwrap().unwrap(), fresh_root(&expected));
    }

    #[test]
    fn a_lone_kept_leaf_moves_up_and_an_unkept_tree_empties() {
        let (_dir, db, forest) = open();
        let leaves = vec![(key(0x41, 1), vec![1]), (key(0x81, 2), vec![2]), (key(0x82, 3), vec![3])];
        forest.commit_shard_phase_raw(&APP, PHASE, 0, leaves.clone()).unwrap();
        let keep = vec![bits(0x40, 2)];
        let (root, puts) = forest.stage_scope_confinement(&APP, PHASE, 0, 1, &keep).unwrap().unwrap();
        apply(&db, puts);
        assert_eq!(root, fresh_root(&leaves[..1]));
        assert_eq!(forest.app_subtree_root(&APP, PHASE, 1, &keep[0]).unwrap(),
            forest.app_subtree_root(&APP, PHASE, 0, &keep[0]).unwrap());

        let (_dir, db, forest) = open();
        forest.commit_shard_phase_raw(&APP, PHASE, 0, leaves[1..].to_vec()).unwrap();
        let (root, puts) = forest.stage_scope_confinement(&APP, PHASE, 0, 1, &keep).unwrap().unwrap();
        apply(&db, puts);
        assert_eq!(root, *b"SPARSE_MERKLE_PLACEHOLDER_HASH__");
        assert_eq!(forest.shard_phase_root(&APP, PHASE, 1).unwrap().unwrap(), root);
        forest.delete_outside_scope(&APP, PHASE, 1, &keep, None, 100).unwrap();
        assert_eq!(outside_nodes(&db, &keep), 0);
    }
}

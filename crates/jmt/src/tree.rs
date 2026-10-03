use crate::storage::Node::Leaf;
use alloc::{collections::BTreeMap, vec::Vec};
use alloc::{format, vec};
use anyhow::{bail, ensure, format_err, Context, Result};
use core::marker::PhantomData;
use core::{cmp::Ordering, convert::TryInto};
#[cfg(not(feature = "std"))]
use hashbrown::HashMap;
#[cfg(feature = "std")]
use std::collections::HashMap;

use crate::proof::definition::UpdateMerkleProof;
use crate::proof::{SparseMerkleLeafNode, SparseMerkleNode};
use crate::{
    node_type::{Child, Children, InternalNode, LeafNode, Node, NodeKey, NodeType},
    storage::{TreeReader, TreeUpdateBatch},
    tree_cache::TreeCache,
    types::{
        nibble::{
            nibble_path::{skip_common_prefix, NibbleIterator, NibblePath},
            Nibble, NibbleRangeIterator, ROOT_NIBBLE_HEIGHT,
        },
        proof::{SparseMerkleProof, SparseMerkleRangeProof},
        Version,
    },
    Bytes32Ext, KeyHash, MissingRootError, OwnedValue, RootHash, SimpleHasher, ValueHash,
};

/// A [`JellyfishMerkleTree`] instantiated using the `sha2::Sha256` hasher.
/// This is a sensible default choice for most applications.
#[cfg(any(test, feature = "sha2"))]
pub type Sha256Jmt<'a, R> = JellyfishMerkleTree<'a, R, sha2::Sha256>;

/// A Jellyfish Merkle tree data structure, parameterized by a [`TreeReader`] `R`
/// and a [`SimpleHasher`] `H`. See [`crate`] for description.
pub struct JellyfishMerkleTree<'a, R, H: SimpleHasher> {
    reader: &'a R,
    _phantom_hasher: PhantomData<H>,
}

#[cfg(feature = "ics23")]
pub mod ics23_impl;

impl<'a, R, H> JellyfishMerkleTree<'a, R, H>
where
    R: 'a + TreeReader,
    H: SimpleHasher,
{
    /// Creates a `JellyfishMerkleTree` backed by the given [`TreeReader`].
    pub fn new(reader: &'a R) -> Self {
        Self {
            reader,
            _phantom_hasher: Default::default(),
        }
    }

    /// Get the node hash from the cache if exists, otherwise compute it.
    fn get_hash(
        node_key: &NodeKey,
        node: &Node,
        hash_cache: &Option<&HashMap<NibblePath, [u8; 32]>>,
    ) -> [u8; 32] {
        if let Some(cache) = hash_cache {
            match cache.get(node_key.nibble_path()) {
                Some(hash) => *hash,
                None => unreachable!("{:?} can not be found in hash cache", node_key),
            }
        } else {
            node.hash::<H>()
        }
    }

    /// The batch version of `put_value_sets`.
    pub fn batch_put_value_sets(
        &self,
        value_sets: Vec<Vec<(KeyHash, OwnedValue)>>,
        node_hashes: Option<Vec<&HashMap<NibblePath, [u8; 32]>>>,
        first_version: Version,
    ) -> Result<(Vec<RootHash>, TreeUpdateBatch)> {
        let mut tree_cache = TreeCache::new(self.reader, first_version)?;
        let hash_sets: Vec<_> = match node_hashes {
            Some(hashes) => hashes.into_iter().map(Some).collect(),
            None => (0..value_sets.len()).map(|_| None).collect(),
        };

        for (idx, (value_set, hash_set)) in
            itertools::zip_eq(value_sets.into_iter(), hash_sets.into_iter()).enumerate()
        {
            assert!(
                !value_set.is_empty(),
                "Transactions that output empty write set should not be included.",
            );
            let version = first_version + idx as u64;
            let deduped_and_sorted_kvs = value_set
                .into_iter()
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .map(|(key, value)| {
                    let value_hash = ValueHash::with::<H>(value.as_slice());
                    tree_cache.put_value(version, key, Some(value));
                    (key, value_hash)
                })
                .collect::<Vec<_>>();
            let root_node_key = tree_cache.get_root_node_key().clone();
            let (new_root_node_key, _) = self.batch_insert_at(
                root_node_key,
                version,
                deduped_and_sorted_kvs.as_slice(),
                0,
                &hash_set,
                &mut tree_cache,
            )?;
            tree_cache.set_root_node_key(new_root_node_key);

            // Freezes the current cache to make all contents in the current cache immutable.
            tree_cache.freeze::<H>()?;
        }

        Ok(tree_cache.into())
    }

    fn batch_insert_at(
        &self,
        mut node_key: NodeKey,
        version: Version,
        kvs: &[(KeyHash, ValueHash)],
        depth: usize,
        hash_cache: &Option<&HashMap<NibblePath, [u8; 32]>>,
        tree_cache: &mut TreeCache<R>,
    ) -> Result<(NodeKey, Node)> {
        assert!(!kvs.is_empty());

        let node = tree_cache.get_node(&node_key)?;
        Ok(match node {
            Node::Internal(internal_node) => {
                // We always delete the existing internal node here because it will not be referenced anyway
                // since this version.
                tree_cache.delete_node(&node_key, false /* is_leaf */);

                // Reuse the current `InternalNode` in memory to create a new internal node.
                let mut children: Children = internal_node.clone().into();

                // Traverse all the path touched by `kvs` from this internal node.
                for (left, right) in NibbleRangeIterator::new(kvs, depth) {
                    // Traverse downwards from this internal node recursively by splitting the updates into
                    // each child index
                    let child_index = kvs[left].0 .0.get_nibble(depth);

                    let (new_child_node_key, new_child_node) =
                        match internal_node.child(child_index) {
                            Some(child) => {
                                let child_node_key =
                                    node_key.gen_child_node_key(child.version, child_index);
                                self.batch_insert_at(
                                    child_node_key,
                                    version,
                                    &kvs[left..=right],
                                    depth + 1,
                                    hash_cache,
                                    tree_cache,
                                )?
                            }
                            None => {
                                let new_child_node_key =
                                    node_key.gen_child_node_key(version, child_index);
                                self.batch_create_subtree(
                                    new_child_node_key,
                                    version,
                                    &kvs[left..=right],
                                    depth + 1,
                                    hash_cache,
                                    tree_cache,
                                )?
                            }
                        };

                    children.insert(
                        child_index,
                        Child::new(
                            Self::get_hash(&new_child_node_key, &new_child_node, hash_cache),
                            version,
                            new_child_node.node_type(),
                        ),
                    );
                }
                let new_internal_node = InternalNode::new(children);

                node_key.set_version(version);

                // Cache this new internal node.
                tree_cache.put_node(node_key.clone(), new_internal_node.clone().into())?;
                (node_key, new_internal_node.into())
            }
            Node::Leaf(leaf_node) => {
                // We are on a leaf node but trying to insert another node, so we may diverge.
                // We always delete the existing leaf node here because it will not be referenced anyway
                // since this version.
                tree_cache.delete_node(&node_key, true /* is_leaf */);
                node_key.set_version(version);
                self.batch_create_subtree_with_existing_leaf(
                    node_key, version, leaf_node, kvs, depth, hash_cache, tree_cache,
                )?
            }
            Node::Null => {
                if !node_key.nibble_path().is_empty() {
                    bail!(
                        "Null node exists for non-root node with node_key {:?}",
                        node_key
                    );
                }

                if node_key.version() == version {
                    tree_cache.delete_node(&node_key, false /* is_leaf */);
                }
                self.batch_create_subtree(
                    NodeKey::new_empty_path(version),
                    version,
                    kvs,
                    depth,
                    hash_cache,
                    tree_cache,
                )?
            }
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn batch_create_subtree_with_existing_leaf(
        &self,
        node_key: NodeKey,
        version: Version,
        existing_leaf_node: LeafNode,
        kvs: &[(KeyHash, ValueHash)],
        depth: usize,
        hash_cache: &Option<&HashMap<NibblePath, [u8; 32]>>,
        tree_cache: &mut TreeCache<R>,
    ) -> Result<(NodeKey, Node)> {
        let existing_leaf_key = existing_leaf_node.key_hash();

        if kvs.len() == 1 && kvs[0].0 == existing_leaf_key {
            let new_leaf_node = Node::Leaf(LeafNode::new(existing_leaf_key, kvs[0].1));
            tree_cache.put_node(node_key.clone(), new_leaf_node.clone())?;
            Ok((node_key, new_leaf_node))
        } else {
            let existing_leaf_bucket = existing_leaf_key.0.get_nibble(depth);
            let mut isolated_existing_leaf = true;
            let mut children = Children::new();
            for (left, right) in NibbleRangeIterator::new(kvs, depth) {
                let child_index = kvs[left].0 .0.get_nibble(depth);
                let child_node_key = node_key.gen_child_node_key(version, child_index);
                let (new_child_node_key, new_child_node) = if existing_leaf_bucket == child_index {
                    isolated_existing_leaf = false;
                    self.batch_create_subtree_with_existing_leaf(
                        child_node_key,
                        version,
                        existing_leaf_node.clone(),
                        &kvs[left..=right],
                        depth + 1,
                        hash_cache,
                        tree_cache,
                    )?
                } else {
                    self.batch_create_subtree(
                        child_node_key,
                        version,
                        &kvs[left..=right],
                        depth + 1,
                        hash_cache,
                        tree_cache,
                    )?
                };
                children.insert(
                    child_index,
                    Child::new(
                        Self::get_hash(&new_child_node_key, &new_child_node, hash_cache),
                        version,
                        new_child_node.node_type(),
                    ),
                );
            }
            if isolated_existing_leaf {
                let existing_leaf_node_key =
                    node_key.gen_child_node_key(version, existing_leaf_bucket);
                children.insert(
                    existing_leaf_bucket,
                    Child::new(existing_leaf_node.hash::<H>(), version, NodeType::Leaf),
                );

                tree_cache.put_node(existing_leaf_node_key, existing_leaf_node.into())?;
            }

            let new_internal_node = InternalNode::new(children);

            tree_cache.put_node(node_key.clone(), new_internal_node.clone().into())?;
            Ok((node_key, new_internal_node.into()))
        }
    }

    fn batch_create_subtree(
        &self,
        node_key: NodeKey,
        version: Version,
        kvs: &[(KeyHash, ValueHash)],
        depth: usize,
        hash_cache: &Option<&HashMap<NibblePath, [u8; 32]>>,
        tree_cache: &mut TreeCache<R>,
    ) -> Result<(NodeKey, Node)> {
        if kvs.len() == 1 {
            let new_leaf_node = Node::Leaf(LeafNode::new(kvs[0].0, kvs[0].1));
            tree_cache.put_node(node_key.clone(), new_leaf_node.clone())?;
            Ok((node_key, new_leaf_node))
        } else {
            let mut children = Children::new();
            for (left, right) in NibbleRangeIterator::new(kvs, depth) {
                let child_index = kvs[left].0 .0.get_nibble(depth);
                let child_node_key = node_key.gen_child_node_key(version, child_index);
                let (new_child_node_key, new_child_node) = self.batch_create_subtree(
                    child_node_key,
                    version,
                    &kvs[left..=right],
                    depth + 1,
                    hash_cache,
                    tree_cache,
                )?;
                children.insert(
                    child_index,
                    Child::new(
                        Self::get_hash(&new_child_node_key, &new_child_node, hash_cache),
                        version,
                        new_child_node.node_type(),
                    ),
                );
            }
            let new_internal_node = InternalNode::new(children);

            tree_cache.put_node(node_key.clone(), new_internal_node.clone().into())?;
            Ok((node_key, new_internal_node.into()))
        }
    }

    /// This is a convenient function that calls
    /// [`put_value_sets`](struct.JellyfishMerkleTree.html#method.put_value_sets) with a single
    /// `keyed_value_set`.
    pub fn put_value_set(
        &self,
        value_set: impl IntoIterator<Item = (KeyHash, Option<OwnedValue>)>,
        version: Version,
    ) -> Result<(RootHash, TreeUpdateBatch)> {
        let (root_hashes, tree_update_batch) = self.put_value_sets(vec![value_set], version)?;
        assert_eq!(
            root_hashes.len(),
            1,
            "root_hashes must consist of a single value.",
        );
        Ok((root_hashes[0], tree_update_batch))
    }

    /// This is a convenient function that calls
    /// [`put_value_sets_with_proof`](struct.JellyfishMerkleTree.html#method.put_value_sets) with a single
    /// `keyed_value_set`.
    pub fn put_value_set_with_proof(
        &self,
        value_set: impl IntoIterator<Item = (KeyHash, Option<OwnedValue>)>,
        version: Version,
    ) -> Result<(RootHash, UpdateMerkleProof<H>, TreeUpdateBatch)> {
        let (mut hash_and_proof, batch_update) =
            self.put_value_sets_with_proof(vec![value_set], version)?;
        assert_eq!(
            hash_and_proof.len(),
            1,
            "root_hashes must consist of a single value.",
        );

        let (hash, proof) = hash_and_proof.pop().unwrap();

        Ok((hash, proof, batch_update))
    }

    /// Returns the new nodes and values in a batch after applying `value_set`. For
    /// example, if after transaction `T_i` the committed state of tree in the persistent storage
    /// looks like the following structure:
    ///
    /// ```text
    ///              S_i
    ///             /   \
    ///            .     .
    ///           .       .
    ///          /         \
    ///         o           x
    ///        / \
    ///       A   B
    ///        storage (disk)
    /// ```
    ///
    /// where `A` and `B` denote the states of two adjacent accounts, and `x` is a sibling subtree
    /// of the path from root to A and B in the tree. Then a `value_set` produced by the next
    /// transaction `T_{i+1}` modifies other accounts `C` and `D` exist in the subtree under `x`, a
    /// new partial tree will be constructed in memory and the structure will be:
    ///
    /// ```text
    ///                 S_i      |      S_{i+1}
    ///                /   \     |     /       \
    ///               .     .    |    .         .
    ///              .       .   |   .           .
    ///             /         \  |  /             \
    ///            /           x | /               x'
    ///           o<-------------+-               / \
    ///          / \             |               C   D
    ///         A   B            |
    ///           storage (disk) |    cache (memory)
    /// ```
    ///
    /// With this design, we are able to query the global state in persistent storage and
    /// generate the proposed tree delta based on a specific root hash and `value_set`. For
    /// example, if we want to execute another transaction `T_{i+1}'`, we can use the tree `S_i` in
    /// storage and apply the `value_set` of transaction `T_{i+1}`. Then if the storage commits
    /// the returned batch, the state `S_{i+1}` is ready to be read from the tree by calling
    /// [`get_with_proof`](struct.JellyfishMerkleTree.html#method.get_with_proof). Anything inside
    /// the batch is not reachable from public interfaces before being committed.
    pub fn put_value_sets(
        &self,
        value_sets: impl IntoIterator<Item = impl IntoIterator<Item = (KeyHash, Option<OwnedValue>)>>,
        first_version: Version,
    ) -> Result<(Vec<RootHash>, TreeUpdateBatch)> {
        let mut tree_cache = TreeCache::new(self.reader, first_version)?;
        for (idx, value_set) in value_sets.into_iter().enumerate() {
            let version = first_version + idx as u64;
            for (i, (key, value)) in value_set.into_iter().enumerate() {
                let action = if value.is_some() { "insert" } else { "delete" };
                let value_hash = value.as_ref().map(|v| ValueHash::with::<H>(v));
                tree_cache.put_value(version, key, value);
                self.put(key, value_hash, version, &mut tree_cache, false)
                    .with_context(|| {
                        format!(
                            "failed to {} key {} for version {}, key = {:?}",
                            action, i, version, key
                        )
                    })?;
            }

            // Freezes the current cache to make all contents in the current cache immutable.
            tree_cache.freeze::<H>()?;
        }

        Ok(tree_cache.into())
    }

    #[cfg(feature = "migration")]
    /// Append value sets to the latest version of the tree, without incrementing its version.
    pub fn append_value_set(
        &self,
        value_set: impl IntoIterator<Item = (KeyHash, Option<OwnedValue>)>,
        latest_version: Version,
    ) -> Result<(RootHash, TreeUpdateBatch)> {
        let mut tree_cache = TreeCache::new_overwrite(self.reader, latest_version)?;
        for (i, (key, value)) in value_set.into_iter().enumerate() {
            let action = if value.is_some() { "insert" } else { "delete" };
            let value_hash = value.as_ref().map(|v| ValueHash::with::<H>(v));
            tree_cache.put_value(latest_version, key, value);
            self.put(key, value_hash, latest_version, &mut tree_cache, false)
                .with_context(|| {
                    format!(
                        "failed to {} key {} for version {}, key = {:?}",
                        action, i, latest_version, key
                    )
                })?;
        }

        // Freezes the current cache to make all contents in the current cache immutable.
        tree_cache.freeze::<H>()?;
        let (root_hash_vec, tree_batch) = tree_cache.into();
        if root_hash_vec.len() != 1 {
            bail!(
                "appending a value set failed, we expected a single root hash, but got {}",
                root_hash_vec.len()
            );
        }
        Ok((root_hash_vec[0], tree_batch))
    }

    /// Same as [`put_value_sets`], this method returns a Merkle proof for every update of the Merkle tree.
    /// The proofs can be verified using the [`verify_update`] method, which requires the old `root_hash`, the `merkle_proof` and the new `root_hash`
    /// The first argument contains all the root hashes that were stored in the tree cache so far. The last one is the new root hash of the tree.
    pub fn put_value_sets_with_proof(
        &self,
        value_sets: impl IntoIterator<Item = impl IntoIterator<Item = (KeyHash, Option<OwnedValue>)>>,
        first_version: Version,
    ) -> Result<(Vec<(RootHash, UpdateMerkleProof<H>)>, TreeUpdateBatch)> {
        let mut tree_cache = TreeCache::new(self.reader, first_version)?;
        let mut batch_proofs = Vec::new();
        for (idx, value_set) in value_sets.into_iter().enumerate() {
            let version = first_version + idx as u64;
            let mut proofs = Vec::new();
            for (i, (key, value)) in value_set.into_iter().enumerate() {
                let action = if value.is_some() { "insert" } else { "delete" };
                let value_hash = value.as_ref().map(|v| ValueHash::with::<H>(v));
                tree_cache.put_value(version, key, value.clone());
                let merkle_proof = self
                    .put(key, value_hash, version, &mut tree_cache, true)
                    .with_context(|| {
                        format!(
                            "failed to {} key {} for version {}, key = {:?}",
                            action, i, version, key
                        )
                    })?
                    .unwrap();

                proofs.push(merkle_proof);
            }

            batch_proofs.push(UpdateMerkleProof::new(proofs));

            // Freezes the current cache to make all contents in the current cache immutable.
            tree_cache.freeze::<H>()?;
        }

        let (root_hashes, update_batch): (Vec<RootHash>, TreeUpdateBatch) = tree_cache.into();

        let zipped_hashes_proofs = root_hashes
            .into_iter()
            .zip(batch_proofs.into_iter())
            .collect();

        Ok((zipped_hashes_proofs, update_batch))
    }

    fn put(
        &self,
        key: KeyHash,
        value: Option<ValueHash>,
        version: Version,
        tree_cache: &mut TreeCache<R>,
        with_proof: bool,
    ) -> Result<Option<SparseMerkleProof<H>>> {
        // tree_cache.ensure_initialized()?;

        let nibble_path = NibblePath::new(key.0.to_vec());

        // Get the root node. If this is the first operation, it would get the root node from the
        // underlying db. Otherwise it most likely would come from `cache`.
        let root_node_key = tree_cache.get_root_node_key().clone();
        let mut nibble_iter = nibble_path.nibbles();

        let (put_result, merkle_proof) = self.insert_at(
            root_node_key,
            version,
            &mut nibble_iter,
            value,
            tree_cache,
            with_proof,
        )?;

        // Start insertion from the root node.
        match put_result {
            PutResult::Updated((new_root_node_key, _)) => {
                tree_cache.set_root_node_key(new_root_node_key);
            }
            PutResult::NotChanged => {
                // Nothing has changed, so do nothing
            }
            PutResult::Removed => {
                // root node becomes empty, insert a null node at root
                let genesis_root_key = NodeKey::new_empty_path(version);
                tree_cache.set_root_node_key(genesis_root_key.clone());
                tree_cache.put_node(genesis_root_key, Node::new_null())?;
            }
        }

        Ok(merkle_proof)
    }

    /// Helper function for recursive insertion into the subtree that starts from the current
    /// [`NodeKey`](node_type/struct.NodeKey.html). Returns the newly inserted node.
    /// It is safe to use recursion here because the max depth is limited by the key length which
    /// for this tree is the length of the hash of account addresses.
    fn insert_at(
        &self,
        root_node_key: NodeKey,
        version: Version,
        nibble_iter: &mut NibbleIterator,
        value: Option<ValueHash>,
        tree_cache: &mut TreeCache<R>,
        with_proof: bool,
    ) -> Result<(PutResult<(NodeKey, Node)>, Option<SparseMerkleProof<H>>)> {
        // Because deletions could cause the root node not to exist, we try to get the root node,
        // and if it doesn't exist, we synthesize a `Null` node, noting that it hasn't yet been
        // committed anywhere (we need to track this because the tree cache will panic if we try to
        // delete a node that it doesn't know about).
        let (node, node_already_exists) = tree_cache
            .get_node_option(&root_node_key)?
            .map(|node| (node, true))
            .unwrap_or((Node::Null, false));

        match node {
            Node::Internal(internal_node) => self.insert_at_internal_node(
                root_node_key,
                internal_node,
                version,
                nibble_iter,
                value,
                tree_cache,
                with_proof,
            ),
            Node::Leaf(leaf_node) => self.insert_at_leaf_node(
                root_node_key,
                leaf_node,
                version,
                nibble_iter,
                value,
                tree_cache,
                with_proof,
            ),
            Node::Null => {
                let merkle_proof_null = if with_proof {
                    Some(SparseMerkleProof::new(None, vec![]))
                } else {
                    None
                };

                if !root_node_key.nibble_path().is_empty() {
                    bail!(
                        "Null node exists for non-root node with node_key {:?}",
                        root_node_key
                    );
                }
                // Delete the old null node if the at the same version
                if root_node_key.version() == version && node_already_exists {
                    tree_cache.delete_node(&root_node_key, false /* is_leaf */);
                }
                if let Some(value) = value {
                    // If we're inserting into the null root node, we should change it to be a leaf node
                    let (new_root_node_key, new_root_node) = Self::create_leaf_node(
                        NodeKey::new_empty_path(version),
                        nibble_iter,
                        value,
                        tree_cache,
                    )?;
                    Ok((
                        PutResult::Updated((new_root_node_key, new_root_node)),
                        merkle_proof_null,
                    ))
                } else {
                    // If we're deleting from the null root node, nothing needs to change
                    Ok((PutResult::NotChanged, merkle_proof_null))
                }
            }
        }
    }

    /// Helper function for recursive insertion into the subtree that starts from the current
    /// `internal_node`. Returns the newly inserted node with its
    /// [`NodeKey`](node_type/struct.NodeKey.html).
    fn insert_at_internal_node(
        &self,
        mut node_key: NodeKey,
        internal_node: InternalNode,
        version: Version,
        nibble_iter: &mut NibbleIterator,
        value: Option<ValueHash>,
        tree_cache: &mut TreeCache<R>,
        with_proof: bool,
    ) -> Result<(PutResult<(NodeKey, Node)>, Option<SparseMerkleProof<H>>)> {
        // Find the next node to visit following the next nibble as index.
        let child_index = nibble_iter.next().expect("Ran out of nibbles");

        // Traverse downwards from this internal node recursively to get the `node_key` of the child
        // node at `child_index`.
        let (put_result, merkle_proof) = match internal_node.child(child_index) {
            Some(child) => {
                let (child_node_key, mut siblings) = if with_proof {
                    let (child_key, siblings) = internal_node.get_child_with_siblings::<H>(
                        tree_cache,
                        &node_key,
                        child_index,
                    );
                    (child_key.unwrap(), siblings)
                } else {
                    (
                        node_key.gen_child_node_key(child.version, child_index),
                        vec![],
                    )
                };

                let (update_result, proof_opt) = self.insert_at(
                    child_node_key,
                    version,
                    nibble_iter,
                    value,
                    tree_cache,
                    with_proof,
                )?;

                let new_proof_opt = proof_opt.map(|proof| {
                    // The move siblings function allows zero copy moves for proof
                    let proof_leaf = proof.leaf();
                    let mut new_siblings = proof.take_siblings();
                    // We need to reverse the siblings
                    siblings.reverse();
                    new_siblings.append(&mut siblings);
                    SparseMerkleProof::new(proof_leaf, new_siblings)
                });

                (update_result, new_proof_opt)
            }
            None => {
                // In that case we couldn't find a child for this node at the nibble's position.
                // We have to traverse down the virtual 4-level tree (which is the compressed
                // representation of the jellyfish merkle tree) to get the closest leaf of the nibble
                // we are looking for.
                let merkle_proof = if with_proof {
                    let (child_key_opt, mut siblings) = internal_node
                        .get_only_child_with_siblings::<H>(tree_cache, &node_key, child_index);

                    let leaf: Option<SparseMerkleLeafNode> = child_key_opt.map(|child_key|
                    {
                        // We should be able to find the node in the case
                        let node = tree_cache.get_node(&child_key).expect("this node should be in the cache");
                        match node {
                            Leaf(leaf_node) => {
                                leaf_node.into()
                            },
                            _ => unreachable!("get_only_child_with_siblings should return a leaf node in that case")
                        }
                    });

                    siblings.reverse();
                    Some(SparseMerkleProof::new(leaf, siblings))
                } else {
                    None
                };

                if let Some(value) = value {
                    // insert
                    let new_child_node_key = node_key.gen_child_node_key(version, child_index);

                    // The Merkle proof doesn't have a leaf
                    (
                        PutResult::Updated(Self::create_leaf_node(
                            new_child_node_key,
                            nibble_iter,
                            value,
                            tree_cache,
                        )?),
                        merkle_proof,
                    )
                } else {
                    // If there was no changes, don't generate a proof
                    (
                        PutResult::NotChanged,
                        if with_proof {
                            Some(SparseMerkleProof::new(None, vec![]))
                        } else {
                            None
                        },
                    )
                }
            }
        };

        // Reuse the current `InternalNode` in memory to create a new internal node.
        let mut children: Children = internal_node.into();
        match put_result {
            PutResult::NotChanged => {
                return Ok((
                    PutResult::NotChanged,
                    if with_proof {
                        Some(SparseMerkleProof::new(None, vec![]))
                    } else {
                        None
                    },
                ));
            }
            PutResult::Updated((_, new_node)) => {
                // update child
                children.insert(
                    child_index,
                    Child::new(new_node.hash::<H>(), version, new_node.node_type()),
                );
            }
            PutResult::Removed => {
                // remove child
                children.remove(child_index);
            }
        }

        // We always delete the existing internal node here because it will not be referenced anyway
        // since this version.
        tree_cache.delete_node(&node_key, false /* is_leaf */);

        let mut it = children.iter();
        if let Some((child_nibble, child)) = it.next() {
            if it.next().is_none() && child.is_leaf() {
                // internal node has only one child left and it's leaf node, replace it with the leaf node
                let child_key = node_key.gen_child_node_key(child.version, child_nibble);
                let child_node = tree_cache.get_node(&child_key)?;
                tree_cache.delete_node(&child_key, true /* is_leaf */);

                node_key.set_version(version);
                tree_cache.put_node(node_key.clone(), child_node.clone())?;
                Ok((PutResult::Updated((node_key, child_node)), merkle_proof))
            } else {
                drop(it);
                let new_internal_node: InternalNode = InternalNode::new(children);

                node_key.set_version(version);

                // Cache this new internal node.
                tree_cache.put_node(node_key.clone(), new_internal_node.clone().into())?;
                Ok((
                    PutResult::Updated((node_key, new_internal_node.into())),
                    merkle_proof,
                ))
            }
        } else {
            // internal node becomes empty, remove it
            Ok((PutResult::Removed, merkle_proof))
        }
    }

    /// Helper function for recursive insertion into the subtree that starts from the
    /// `existing_leaf_node`. Returns the newly inserted node with its
    /// [`NodeKey`](node_type/struct.NodeKey.html).
    fn insert_at_leaf_node(
        &self,
        /* the root of the subtree we are inserting into */
        mut node_key: NodeKey,
        /* the leaf node that we are inserting at */
        existing_leaf_node: LeafNode,
        version: Version,
        /* the nibble iterator of the key hash we are inserting */
        nibble_iter: &mut NibbleIterator,
        value_hash: Option<ValueHash>,
        tree_cache: &mut TreeCache<R>,
        with_proof: bool,
    ) -> Result<(PutResult<(NodeKey, Node)>, Option<SparseMerkleProof<H>>)> {
        // We are inserting a new key that shares a common prefix with the existing leaf node.
        // This check is to make sure that the visited nibble path of the inserted key is a
        // subpath of the existing leaf node's nibble path.
        let mut visited_path = nibble_iter.visited_nibbles();
        let path_to_leaf_node = NibblePath::new(existing_leaf_node.key_hash().0.to_vec());
        let mut path_to_leaf = path_to_leaf_node.nibbles();
        skip_common_prefix(&mut visited_path, &mut path_to_leaf);

        assert!(
            visited_path.is_finished(),
            "Inserting a key at the wrong leaf node (no common prefix - index={})",
            path_to_leaf.visited_nibbles().num_nibbles()
        );

        // We have established that the visited nibble path of the inserted key is a prefix of the
        // leaf node's nibble path. Now, we can check if the unvisited nibble path of the inserted
        // key overlaps with more the leaf node's nibble path.
        let mut path_to_leaf_remaining = path_to_leaf.remaining_nibbles();
        // To do this, we skip the common prefix between the remaining nibbles of the inserted key and
        // and those of the leaf node.
        let common_nibbles = skip_common_prefix(nibble_iter, &mut path_to_leaf_remaining);
        let mut common_nibble_path = nibble_iter.visited_nibbles().collect::<NibblePath>();

        // If we have exhausted the nibble iterator of the inserted key, this means that the
        // inserted key and leaf node have the same path. In this case, we just need to update the
        // value of the leaf node.
        if nibble_iter.is_finished() {
            assert!(path_to_leaf_remaining.is_finished());
            tree_cache.delete_node(&node_key, true /* is_leaf */);

            let merkle_proof = if with_proof {
                Some(SparseMerkleProof::new(
                    Some(existing_leaf_node.into()),
                    vec![],
                ))
            } else {
                None
            };

            if let Some(value_hash) = value_hash {
                // The new leaf node will have the same nibble_path with a new version as node_key.
                node_key.set_version(version);
                // Create the new leaf node with the same address but new blob content.
                return Ok((
                    PutResult::Updated(Self::create_leaf_node(
                        node_key,
                        nibble_iter,
                        value_hash,
                        tree_cache,
                    )?),
                    merkle_proof,
                ));
            } else {
                // deleted
                return Ok((PutResult::Removed, merkle_proof));
            };
        }

        // If skipping the common prefix leaves us with some remaining nibbles, this means that the
        // two nibble paths do overlap, but are not identical. In this case, we need to create an internal
        // node to represent the common prefix, and two leaf nodes to represent each leaves.
        if let Some(value) = value_hash {
            tree_cache.delete_node(&node_key, true /* is_leaf */);

            // 2.2. both are unfinished(They have keys with same length so it's impossible to have one
            // finished and the other not). This means the incoming key forks at some point between the
            // position where step 1 ends and the last nibble, inclusive. Then create a seris of
            // internal nodes the number of which equals to the length of the extra part of the
            // common prefix in step 2, a new leaf node for the incoming key, and update the
            // [`NodeKey`] of existing leaf node. We create new internal nodes in a bottom-up
            // order.
            let existing_leaf_index = path_to_leaf_remaining.next().expect("Ran out of nibbles");
            let new_leaf_index = nibble_iter.next().expect("Ran out of nibbles");
            assert_ne!(existing_leaf_index, new_leaf_index);

            let mut children = Children::new();
            children.insert(
                existing_leaf_index,
                Child::new(existing_leaf_node.hash::<H>(), version, NodeType::Leaf),
            );
            node_key = NodeKey::new(version, common_nibble_path.clone());
            tree_cache.put_node(
                node_key.gen_child_node_key(version, existing_leaf_index),
                existing_leaf_node.clone().into(),
            )?;

            let (_, new_leaf_node) = Self::create_leaf_node(
                node_key.gen_child_node_key(version, new_leaf_index),
                nibble_iter,
                value,
                tree_cache,
            )?;
            children.insert(
                new_leaf_index,
                Child::new(new_leaf_node.hash::<H>(), version, NodeType::Leaf),
            );

            let internal_node = InternalNode::new(children);
            let mut next_internal_node = internal_node.clone();
            tree_cache.put_node(node_key.clone(), internal_node.into())?;

            for _i in 0..common_nibbles {
                // Pop a nibble from the end of path.
                let nibble = common_nibble_path
                    .pop()
                    .expect("Common nibble_path below internal node ran out of nibble");
                node_key = NodeKey::new(version, common_nibble_path.clone());
                let mut children = Children::new();
                children.insert(
                    nibble,
                    Child::new(
                        next_internal_node.hash::<H>(),
                        version,
                        next_internal_node.node_type(),
                    ),
                );
                let internal_node = InternalNode::new(children);
                next_internal_node = internal_node.clone();
                tree_cache.put_node(node_key.clone(), internal_node.into())?;
            }

            Ok((
                PutResult::Updated((node_key, next_internal_node.into())),
                if with_proof {
                    Some(SparseMerkleProof::new(
                        Some(existing_leaf_node.into()),
                        vec![],
                    ))
                } else {
                    None
                },
            ))
        } else {
            // delete not found
            Ok((
                PutResult::NotChanged,
                if with_proof {
                    Some(SparseMerkleProof::new(None, vec![]))
                } else {
                    None
                },
            ))
        }
    }

    /// Helper function for creating leaf nodes. Returns the newly created leaf node.
    fn create_leaf_node(
        node_key: NodeKey,
        nibble_iter: &NibbleIterator,
        value_hash: ValueHash,
        tree_cache: &mut TreeCache<R>,
    ) -> Result<(NodeKey, Node)> {
        // Get the underlying bytes of nibble_iter which must be a key, i.e., hashed account address
        // with `HashValue::LENGTH` bytes.
        let new_leaf_node = Node::new_leaf(
            KeyHash(
                nibble_iter
                    .get_nibble_path()
                    .bytes()
                    .try_into()
                    .expect("LeafNode must have full nibble path."),
            ),
            value_hash,
        );

        tree_cache.put_node(node_key.clone(), new_leaf_node.clone())?;
        Ok((node_key, new_leaf_node))
    }

    /// Returns the value (if applicable) and the corresponding merkle proof.
    pub fn get_with_proof(
        &self,
        key: KeyHash,
        version: Version,
    ) -> Result<(Option<OwnedValue>, SparseMerkleProof<H>)> {
        // Empty tree just returns proof with no sibling hash.
        let mut next_node_key = NodeKey::new_empty_path(version);
        let mut siblings: Vec<SparseMerkleNode> = vec![];
        let nibble_path = NibblePath::new(key.0.to_vec());
        let mut nibble_iter = nibble_path.nibbles();

        // We limit the number of loops here deliberately to avoid potential cyclic graph bugs
        // in the tree structure.
        for nibble_depth in 0..=ROOT_NIBBLE_HEIGHT {
            let next_node = self.reader.get_node(&next_node_key).map_err(|err| {
                if nibble_depth == 0 {
                    anyhow::anyhow!(MissingRootError { version })
                } else {
                    err
                }
            })?;
            match next_node {
                Node::Internal(internal_node) => {
                    let queried_child_index = nibble_iter
                        .next()
                        .ok_or_else(|| format_err!("ran out of nibbles"))?;

                    let (child_node_key, mut siblings_in_internal) = internal_node
                        .get_only_child_with_siblings::<H>(
                            self.reader,
                            &next_node_key,
                            queried_child_index,
                        );

                    siblings.append(&mut siblings_in_internal);
                    next_node_key = match child_node_key {
                        Some(node_key) => node_key,
                        None => {
                            return Ok((
                                None,
                                SparseMerkleProof::new(None, {
                                    siblings.reverse();
                                    siblings
                                }),
                            ))
                        }
                    };
                }
                Node::Leaf(leaf_node) => {
                    return Ok((
                        if leaf_node.key_hash() == key {
                            Some(self.reader.get_value(version, leaf_node.key_hash())?)
                        } else {
                            None
                        },
                        SparseMerkleProof::new(Some(leaf_node.into()), {
                            siblings.reverse();
                            siblings
                        }),
                    ));
                }
                Node::Null => {
                    if nibble_depth == 0 {
                        return Ok((None, SparseMerkleProof::new(None, vec![])));
                    } else {
                        bail!(
                            "Non-root null node exists with node key {:?}",
                            next_node_key
                        );
                    }
                }
            }
        }
        bail!("Jellyfish Merkle tree has cyclic graph inside.");
    }

    fn search_closest_extreme_node(
        &self,
        version: Version,
        extreme: Extreme,
        to: NibblePath,
        parents: Vec<InternalNode>,
    ) -> Result<Option<KeyHash>> {
        fn neighbor_nibble(
            node: &InternalNode,
            child_index: Nibble,
            extreme: Extreme,
        ) -> Option<(Nibble, Version)> {
            match extreme {
                // Rightmost left neighbor
                Extreme::Left => node
                    .children_unsorted()
                    .filter(|(nibble, _)| nibble < &child_index)
                    .max_by_key(|(nibble, _)| *nibble)
                    .map(|p| (p.0, p.1.version)),
                // Leftmost right neighbor
                Extreme::Right => node
                    .children_unsorted()
                    .filter(|(nibble, _)| nibble > &child_index)
                    .min_by_key(|(nibble, _)| *nibble)
                    .map(|p| (p.0, p.1.version)),
            }
        }
        let mut parents = parents;
        let mut path = to;

        while let (Some(index), Some(parent)) = (path.pop(), parents.pop()) {
            if let Some((neighbor, found_version)) = neighbor_nibble(&parent, index, extreme) {
                // nibble path will represent the left nibble path. this is currently at
                // the parent of the leaf for `key`
                path.push(neighbor);
                return Ok(Some(self.get_extreme_key_hash(
                    version,
                    NodeKey::new(found_version, path.clone()),
                    path.num_nibbles(),
                    extreme.opposite(),
                )?));
            }
        }
        Ok(None)
    }

    // given a search_key,
    fn search_for_closest_node(
        &self,
        version: Version,
        search_key: KeyHash,
    ) -> Result<SearchResult> {
        let search_path = NibblePath::new(search_key.0.to_vec());
        let mut search_nibbles = search_path.nibbles();
        let mut next_node_key = NodeKey::new_empty_path(version);
        let mut internal_nodes = vec![];

        for nibble_depth in 0..=ROOT_NIBBLE_HEIGHT {
            let next_node = self.reader.get_node(&next_node_key).map_err(|err| {
                if nibble_depth == 0 {
                    anyhow::anyhow!(MissingRootError { version })
                } else {
                    err
                }
            })?;

            match next_node {
                Node::Internal(node) => {
                    internal_nodes.push(node.clone());
                    let queried_child_index = search_nibbles
                        .next()
                        .ok_or_else(|| format_err!("ran out of nibbles"))?;

                    let child_node_key =
                        node.get_only_child_without_siblings(&next_node_key, queried_child_index);

                    match child_node_key {
                        Some(node_key) => {
                            next_node_key = node_key;
                        }
                        None => {
                            return Ok(SearchResult::FoundInternal {
                                path_to_internal: search_nibbles
                                    .visited_nibbles()
                                    .get_nibble_path(),
                                parents: internal_nodes,
                            });
                        }
                    }
                }
                Node::Leaf(node) => {
                    let key_hash = node.key_hash();
                    return Ok(SearchResult::FoundLeaf {
                        ordering: key_hash.cmp(&search_key),
                        leaf_hash: key_hash,
                        path_to_leaf: search_nibbles.visited_nibbles().get_nibble_path(),
                        parents: internal_nodes,
                    });
                }
                Node::Null => {
                    if nibble_depth == 0 {
                        bail!(
                            "Cannot manufacture nonexistence proof by exclusion for the empty tree"
                        );
                    } else {
                        bail!(
                            "Non-root null node exists with node key {:?}",
                            next_node_key
                        );
                    }
                }
            }
        }

        bail!("Jellyfish Merkle tree has cyclic graph inside.");
    }

    fn get_bounding_path(
        &self,
        search_key: KeyHash,
        version: Version,
    ) -> Result<(Option<KeyHash>, Option<KeyHash>)> {
        let search_result = self.search_for_closest_node(version, search_key)?;

        match search_result {
            SearchResult::FoundLeaf {
                ordering,
                leaf_hash,
                path_to_leaf,
                parents,
            } => {
                match ordering {
                    Ordering::Less => {
                        // found the closest leaf to the left of the search key.
                        // find the other bound (the leftmost right keyhash)
                        let leftmost_right_keyhash = self.search_closest_extreme_node(
                            version,
                            Extreme::Right,
                            path_to_leaf,
                            parents,
                        )?;

                        Ok((Some(leaf_hash), leftmost_right_keyhash))
                    }
                    Ordering::Greater => {
                        // found the closest leaf to the right of the search key
                        let rightmost_left_keyhash = self.search_closest_extreme_node(
                            version,
                            Extreme::Left,
                            path_to_leaf,
                            parents,
                        )?;

                        Ok((rightmost_left_keyhash, Some(leaf_hash)))
                    }
                    Ordering::Equal => {
                        bail!("found exact key when searching for bounding path for nonexistence proof")
                    }
                }
            }
            SearchResult::FoundInternal {
                path_to_internal,
                parents,
            } => {
                let leftmost_right_keyhash = self.search_closest_extreme_node(
                    version,
                    Extreme::Right,
                    path_to_internal.clone(),
                    parents.clone(),
                )?;
                let rightmost_left_keyhash = self.search_closest_extreme_node(
                    version,
                    Extreme::Left,
                    path_to_internal,
                    parents,
                )?;

                Ok((rightmost_left_keyhash, leftmost_right_keyhash))
            }
        }
    }

    /// Returns the value (if applicable) and the corresponding merkle proof.
    pub fn get_with_exclusion_proof(
        &self,
        key_hash: KeyHash,
        version: Version,
    ) -> Result<Result<(OwnedValue, SparseMerkleProof<H>), ExclusionProof<H>>> {
        // Optimistically attempt get_with_proof, if that succeeds, we're done.
        if let (Some(value), proof) = self.get_with_proof(key_hash, version)? {
            return Ok(Ok((value, proof)));
        }

        // Otherwise, we know this key doesn't exist, so construct an exclusion proof.

        // first, find out what are its bounding path, i.e. the greatest key that is strictly less
        // than the non-present search key and/or the smallest key that is strictly greater than
        // the search key.
        let (left_bound, right_bound) = self.get_bounding_path(key_hash, version)?;

        match (left_bound, right_bound) {
            (Some(left_bound), Some(right_bound)) => {
                let left_proof = self.get_with_proof(left_bound, version)?.1;
                let right_proof = self.get_with_proof(right_bound, version)?.1;

                Ok(Err(ExclusionProof::Middle {
                    rightmost_left_proof: left_proof,
                    leftmost_right_proof: right_proof,
                }))
            }
            (Some(left_bound), None) => {
                let left_proof = self.get_with_proof(left_bound, version)?.1;
                Ok(Err(ExclusionProof::Rightmost {
                    rightmost_left_proof: left_proof,
                }))
            }
            (None, Some(right_bound)) => {
                let right_proof = self.get_with_proof(right_bound, version)?.1;
                Ok(Err(ExclusionProof::Leftmost {
                    leftmost_right_proof: right_proof,
                }))
            }
            _ => bail!("Invalid exclusion proof"),
        }
    }

    fn get_extreme_key_hash(
        &self,
        version: Version,
        mut node_key: NodeKey,
        nibble_depth: usize,
        extreme: Extreme,
    ) -> Result<KeyHash> {
        // Depending on the extreme specified, get either the least nibble or the most nibble
        let min_or_max = |internal_node: &InternalNode| {
            match extreme {
                Extreme::Left => internal_node.children_unsorted().min_by_key(|c| c.0),
                Extreme::Right => internal_node.children_unsorted().max_by_key(|c| c.0),
            }
            .map(|(nibble, _)| nibble)
        };

        for nibble_depth in nibble_depth..=ROOT_NIBBLE_HEIGHT {
            let node = self.reader.get_node(&node_key).map_err(|err| {
                if nibble_depth == 0 {
                    anyhow::anyhow!(MissingRootError { version })
                } else {
                    err
                }
            })?;
            match node {
                Node::Internal(internal_node) => {
                    // Find the leftmost nibble in the children
                    let queried_child_index =
                        min_or_max(&internal_node).expect("a child always exists");
                    let child_node_key = internal_node
                        .get_only_child_without_siblings(&node_key, queried_child_index);
                    // Proceed downwards
                    node_key = match child_node_key {
                        Some(node_key) => node_key,
                        None => {
                            bail!("Internal node has no children");
                        }
                    };
                }
                Node::Leaf(leaf_node) => {
                    return Ok(leaf_node.key_hash());
                }
                Node::Null => bail!("Null node cannot have children"),
            }
        }
        bail!("Jellyfish Merkle tree has cyclic graph inside.");
    }

    fn get_without_proof(&self, key: KeyHash, version: Version) -> Result<Option<OwnedValue>> {
        self.reader.get_value_option(version, key)
    }

    /// Gets the proof that shows a list of keys up to `rightmost_key_to_prove` exist at `version`.
    pub fn get_range_proof(
        &self,
        rightmost_key_to_prove: KeyHash,
        version: Version,
    ) -> Result<SparseMerkleRangeProof<H>> {
        let (account, proof) = self.get_with_proof(rightmost_key_to_prove, version)?;
        ensure!(account.is_some(), "rightmost_key_to_prove must exist.");

        let siblings = proof
            .siblings()
            .iter()
            .rev()
            .zip(rightmost_key_to_prove.0.iter_bits())
            .filter_map(|(sibling, bit)| {
                // We only need to keep the siblings on the right.
                if !bit {
                    Some(*sibling)
                } else {
                    None
                }
            })
            .rev()
            .collect();
        Ok(SparseMerkleRangeProof::new(siblings))
    }

    /// Returns the value (if applicable), without any proof.
    ///
    /// Equivalent to [`get_with_proof`](JellyfishMerkleTree::get_with_proof) and dropping the
    /// proof, but more efficient.
    pub fn get(&self, key: KeyHash, version: Version) -> Result<Option<OwnedValue>> {
        self.get_without_proof(key, version)
    }

    fn get_root_node(&self, version: Version) -> Result<Node> {
        self.get_root_node_option(version)?
            .ok_or_else(|| format_err!("Root node not found for version {}.", version))
    }

    pub(crate) fn get_root_node_option(&self, version: Version) -> Result<Option<Node>> {
        let root_node_key = NodeKey::new_empty_path(version);
        self.reader.get_node_option(&root_node_key)
    }

    pub fn get_root_hash(&self, version: Version) -> Result<RootHash> {
        self.get_root_node(version).map(|n| RootHash(n.hash::<H>()))
    }

    pub fn get_root_hash_option(&self, version: Version) -> Result<Option<RootHash>> {
        Ok(self
            .get_root_node_option(version)?
            .map(|n| RootHash(n.hash::<H>())))
    }

    // TODO: should this be public? seems coupled to tests?
    pub fn get_leaf_count(&self, version: Version) -> Result<usize> {
        self.get_root_node(version).map(|n| n.leaf_count())
    }
}

/// The result of putting a single key-value pair into the tree, or deleting a key.
enum PutResult<T> {
    // Put a key-value pair successfully.
    Updated(T),
    // Deleted a key successfully.
    Removed,
    // Key to delete not found.
    NotChanged,
}

/// A proof of non-existence by exclusion between two adjacent neighbors.
#[derive(Debug)]
pub enum ExclusionProof<H: SimpleHasher> {
    Leftmost {
        leftmost_right_proof: SparseMerkleProof<H>,
    },
    Middle {
        leftmost_right_proof: SparseMerkleProof<H>,
        rightmost_left_proof: SparseMerkleProof<H>,
    },
    Rightmost {
        rightmost_left_proof: SparseMerkleProof<H>,
    },
}

#[derive(Debug, Clone, Copy)]
enum Extreme {
    Left,
    Right,
}

impl Extreme {
    fn opposite(&self) -> Self {
        match self {
            Extreme::Left => Extreme::Right,
            Extreme::Right => Extreme::Left,
        }
    }
}

#[derive(Debug)]
enum SearchResult {
    FoundLeaf {
        ordering: Ordering,
        leaf_hash: KeyHash,
        path_to_leaf: NibblePath,
        parents: Vec<InternalNode>,
    },
    FoundInternal {
        path_to_internal: NibblePath,
        parents: Vec<InternalNode>,
    },
}

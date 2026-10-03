//! Bounded v3 coin-snapshot tree for canonical roots and membership paths.
//! Leaves are ordered by each coin's committed insertion `position`, so the
//! tree is append-only and a persisted [`Frontier`] can extend the root in
//! O(depth) per coin. `CoinTree` remains the full reconstruction used for
//! membership paths and cross-checks. Callers provide committed coin records
//! and an explicit node allocation cap. This is not a persistent store,
//! admitted-root history or spent-image index.

use super::{
    relation::membership::{MembershipKey, Node, MAX_DEPTH, NODE_BYTES},
    AmountCommitment,
};
use super::relation::membership::IDENTITY_BYTES;

pub const ROOT_RECORD_BYTES: usize = 8 + 32 + 1 + 8 + NODE_BYTES;
const VERSION: &[u8; 8] = b"QCT3RT\0\x02";
const FRONTIER_VERSION: &[u8; 8] = b"QCT3FR\0\x02";
const FRONTIER_HEADER_BYTES: usize = 8 + 32 + 1 + 8;

#[derive(Debug, PartialEq, Eq)]
pub enum TreeError {
    Capacity,
    Depth,
    DuplicateAddress,
    /// Positions must be exactly `0..n` with no gaps or repeats.
    Position,
    MissingCoin,
    Encoding,
    Context,
}

pub struct CoinRecord {
    pub address: [u8; 32],
    pub owner: [u8; IDENTITY_BYTES],
    pub commitment: AmountCommitment,
    /// Leaf index assigned at staging; determines canonical leaf order.
    pub position: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootRecord {
    pub context: [u8; 32],
    pub depth: u8,
    pub coins: u64,
    pub root: Node,
}
impl RootRecord {
    fn validate(&self) -> Result<(), TreeError> {
        if self.depth == 0
            || usize::from(self.depth) > MAX_DEPTH
            || self.coins > (1u64 << self.depth)
        {
            return Err(TreeError::Depth);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<[u8; ROOT_RECORD_BYTES], TreeError> {
        self.validate()?;
        let mut bytes = [0; ROOT_RECORD_BYTES];
        bytes[..8].copy_from_slice(VERSION);
        bytes[8..40].copy_from_slice(&self.context);
        bytes[40] = self.depth;
        bytes[41..49].copy_from_slice(&self.coins.to_le_bytes());
        bytes[49..].copy_from_slice(&self.root.to_bytes());
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8], context: &[u8; 32]) -> Result<Self, TreeError> {
        if bytes.len() != ROOT_RECORD_BYTES || &bytes[..8] != VERSION {
            return Err(TreeError::Encoding);
        }
        if &bytes[8..40] != context {
            return Err(TreeError::Context);
        }
        let record = Self {
            context: *context,
            depth: bytes[40],
            coins: u64::from_le_bytes(bytes[41..49].try_into().map_err(|_| TreeError::Encoding)?),
            root: Node::from_bytes(&bytes[49..]).map_err(|_| TreeError::Encoding)?,
        };
        record.validate()?;
        Ok(record)
    }
}

pub struct AuthPath {
    pub siblings: Vec<Node>,
    pub right: Vec<bool>,
}

/// A fully populated subtree emitted once as the frontier advances. These
/// nodes can be kept in a local derived index; they are not new protocol data.
#[derive(Clone)]
pub struct CompletedNode {
    pub level: u8,
    pub index: u64,
    pub node: Node,
}

#[derive(Debug)]
pub enum IndexedWitnessError<E> {
    Tree(TreeError),
    Lookup(E),
    MissingNode,
    RootMismatch,
}

/// Reconstruct paths from completed subtrees without retaining all leaves.
/// The selected root and coin must come from the caller's canonical state.
/// A missing/corrupt index is an availability failure, never an absent coin.
pub struct IndexedTree {
    context: [u8; 32],
    key: MembershipKey,
    zeros: Vec<Node>,
}
impl IndexedTree {
    pub fn new(context: &[u8; 32], max_depth: usize) -> Result<Self, TreeError> {
        if !(1..=MAX_DEPTH).contains(&max_depth) { return Err(TreeError::Depth); }
        let key = MembershipKey::derive(context);
        Ok(Self { context: *context, zeros: zero_nodes(&key, max_depth), key })
    }

    /// At most twice `root.depth` completed-node lookups, including the one
    /// partially populated sibling subtree at the right edge. No full scan.
    /// The reconstructed leaf-to-root path is checked before returning it.
    pub fn auth_path<E>(
        &self, root: &RootRecord, coin: &CoinRecord,
        mut lookup: impl FnMut(u8, u64) -> Result<Option<Node>, E>,
    ) -> Result<AuthPath, IndexedWitnessError<E>> {
        use IndexedWitnessError as Error;
        root.validate().map_err(Error::Tree)?;
        if root.context != self.context { return Err(Error::Tree(TreeError::Context)); }
        let depth = usize::from(root.depth);
        if depth >= self.zeros.len() { return Err(Error::Tree(TreeError::Depth)); }
        if coin.position >= root.coins { return Err(Error::Tree(TreeError::MissingCoin)); }
        let owner = Node::from_identity_bytes(&coin.owner).map_err(|_| Error::Tree(TreeError::Encoding))?;
        let mut node = self.key.leaf(&owner, &coin.commitment);
        let mut path = AuthPath { siblings: Vec::with_capacity(depth), right: Vec::with_capacity(depth) };
        let mut index = coin.position;
        for level in 0..depth {
            let sibling = self.subtree(root.coins, level, index ^ 1, &mut lookup)?;
            let right = index & 1 != 0;
            node = if right { self.key.parent(&sibling, &node) } else { self.key.parent(&node, &sibling) };
            path.siblings.push(sibling); path.right.push(right);
            index >>= 1;
        }
        if node != root.root { return Err(Error::RootMismatch); }
        Ok(path)
    }

    fn subtree<E>(
        &self, count: u64, level: usize, index: u64,
        lookup: &mut impl FnMut(u8, u64) -> Result<Option<Node>, E>,
    ) -> Result<Node, IndexedWitnessError<E>> {
        let start = index << level;
        if start >= count { return Ok(self.zeros[level].clone()); }
        if start + (1u64 << level) <= count {
            return lookup(level as u8, index).map_err(IndexedWitnessError::Lookup)?
                .ok_or(IndexedWitnessError::MissingNode);
        }
        // A partially occupied subtree has level >= 1. Only the side
        // containing `count` can recurse; the other side is complete or zero.
        let left = self.subtree(count, level - 1, index * 2, lookup)?;
        let right = self.subtree(count, level - 1, index * 2 + 1, lookup)?;
        Ok(self.key.parent(&left, &right))
    }
}

/// Minimal depth (at least one) whose capacity holds `count` leaves.
fn depth_for(count: u64) -> usize {
    let mut depth = 1;
    while depth < MAX_DEPTH && (1u64 << depth) < count {
        depth += 1;
    }
    depth
}

fn zero_nodes(key: &MembershipKey, max_depth: usize) -> Vec<Node> {
    let mut zeros = vec![Node::zero()];
    for level in 0..max_depth {
        zeros.push(key.parent(&zeros[level], &zeros[level]));
    }
    zeros
}

pub struct CoinTree {
    context: [u8; 32],
    key: MembershipKey,
    /// Coin addresses in leaf (position) order.
    addresses: Vec<[u8; 32]>,
    /// `(address, position)` sorted by address for membership lookups.
    index: Vec<([u8; 32], usize)>,
    layers: Vec<Vec<Node>>,
    zeros: Vec<Node>,
    depth: usize,
    max_depth: usize,
}

impl CoinTree {
    /// Order leaves by committed position (which must be exactly `0..n`),
    /// reject duplicate addresses, and bound all cached tree nodes before
    /// allocating them. `max_nodes` also includes zero nodes.
    pub fn build(
        context: &[u8; 32],
        coins: &[CoinRecord],
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<Self, TreeError> {
        if !(1..=MAX_DEPTH).contains(&max_depth) {
            return Err(TreeError::Depth);
        }
        if coins.len() as u64 > (1u64 << max_depth) {
            return Err(TreeError::Capacity);
        }
        let mut width = coins.len().max(1);
        let mut nodes = max_depth + 1;
        let mut depth = 0;
        loop {
            nodes = nodes.checked_add(width).ok_or(TreeError::Capacity)?;
            if width == 1 && depth >= 1 {
                break;
            }
            width = width.div_ceil(2);
            depth += 1;
        }
        if nodes > max_nodes {
            return Err(TreeError::Capacity);
        }
        let mut order: Vec<_> = (0..coins.len()).collect();
        order.sort_unstable_by_key(|&i| coins[i].position);
        if order
            .iter()
            .enumerate()
            .any(|(expected, &i)| coins[i].position != expected as u64)
        {
            return Err(TreeError::Position);
        }
        let mut index: Vec<([u8; 32], usize)> = order
            .iter()
            .map(|&i| (coins[i].address, coins[i].position as usize))
            .collect();
        index.sort_unstable_by_key(|(address, _)| *address);
        if index
            .windows(2)
            .any(|pair| pair[0].0 == pair[1].0)
        {
            return Err(TreeError::DuplicateAddress);
        }
        let key = MembershipKey::derive(context);
        let zeros = zero_nodes(&key, max_depth);
        let mut leaves = Vec::with_capacity(coins.len().max(1));
        for &i in &order {
            let coin = &coins[i];
            let owner = Node::from_identity_bytes(&coin.owner).map_err(|_| TreeError::Encoding)?;
            leaves.push(key.leaf(&owner, &coin.commitment));
        }
        if leaves.is_empty() {
            leaves.push(zeros[0].clone());
        }
        let mut layers = vec![leaves];
        for level in 0..depth {
            let previous = &layers[level];
            let next = previous
                .chunks(2)
                .map(|pair| key.parent(&pair[0], pair.get(1).unwrap_or(&zeros[level])))
                .collect();
            layers.push(next);
        }
        Ok(Self {
            context: *context,
            key,
            addresses: order.iter().map(|&i| coins[i].address).collect(),
            index,
            layers,
            zeros,
            depth,
            max_depth,
        })
    }

    pub fn current_depth(&self) -> usize {
        self.depth
    }
    pub fn coins(&self) -> u64 {
        self.addresses.len() as u64
    }
    /// Leaf position of a coin in this tree, if present.
    pub fn position(&self, address: &[u8; 32]) -> Option<u64> {
        self.index
            .binary_search_by_key(address, |(address, _)| *address)
            .ok()
            .map(|i| self.index[i].1 as u64)
    }
    /// Padded roots support explicitly configured depths and benchmark profiles.
    /// The admission layer must choose which (depth,root) records it accepts.
    pub fn root_at_depth(&self, depth: usize) -> Result<RootRecord, TreeError> {
        if depth < self.depth || depth > self.max_depth {
            return Err(TreeError::Depth);
        }
        let mut root = self.layers[self.depth][0].clone();
        for level in self.depth..depth {
            root = self.key.parent(&root, &self.zeros[level]);
        }
        Ok(RootRecord {
            context: self.context,
            depth: depth as u8,
            coins: self.addresses.len() as u64,
            root,
        })
    }
    pub fn auth_path(&self, address: &[u8; 32], depth: usize) -> Result<AuthPath, TreeError> {
        if depth < self.depth || depth > self.max_depth {
            return Err(TreeError::Depth);
        }
        let mut index = self
            .index
            .binary_search_by_key(address, |(address, _)| *address)
            .map(|i| self.index[i].1)
            .map_err(|_| TreeError::MissingCoin)?;
        let mut path = AuthPath {
            siblings: Vec::with_capacity(depth),
            right: Vec::with_capacity(depth),
        };
        for level in 0..depth {
            path.right.push(index & 1 != 0);
            path.siblings.push(
                self.layers
                    .get(level)
                    .and_then(|layer| layer.get(index ^ 1))
                    .unwrap_or(&self.zeros[level])
                    .clone(),
            );
            index >>= 1;
        }
        Ok(path)
    }
    /// The persisted append state equivalent to this tree.
    pub fn frontier(&self) -> Frontier {
        let mut frontier = Frontier {
            context: self.context,
            key: MembershipKey::derive(&self.context),
            zeros: self.zeros.clone(),
            max_depth: self.max_depth,
            count: 0,
            filled: vec![None; self.max_depth + 1],
        };
        for leaf in &self.layers[0][..self.addresses.len()] {
            frontier.append_leaf(leaf.clone());
        }
        frontier
    }
}

/// Append-only Merkle frontier: for each level, the left node awaiting its
/// right sibling. Its roots equal `CoinTree::build` over the same leaves in
/// position order, so the hot path extends the accumulator in O(depth) per
/// coin without decoding the whole coin set. `filled` has `max_depth + 1`
/// slots so a completely full tree keeps its root at the top level.
pub struct Frontier {
    context: [u8; 32],
    key: MembershipKey,
    zeros: Vec<Node>,
    max_depth: usize,
    count: u64,
    filled: Vec<Option<Node>>,
}

impl Frontier {
    pub fn new(context: &[u8; 32], max_depth: usize) -> Result<Self, TreeError> {
        if !(1..=MAX_DEPTH).contains(&max_depth) {
            return Err(TreeError::Depth);
        }
        let key = MembershipKey::derive(context);
        Ok(Self {
            context: *context,
            zeros: zero_nodes(&key, max_depth),
            key,
            max_depth,
            count: 0,
            filled: vec![None; max_depth + 1],
        })
    }
    pub fn count(&self) -> u64 {
        self.count
    }
    pub fn max_depth(&self) -> usize {
        self.max_depth
    }
    pub fn current_depth(&self) -> usize {
        depth_for(self.count).min(self.max_depth)
    }
    fn append_leaf(&mut self, node: Node) {
        self.append_leaf_with(node, &mut |_, _, _| {});
    }
    fn append_leaf_with(&mut self, mut node: Node, emit: &mut impl FnMut(u8, u64, &Node)) {
        for level in 0..=self.max_depth {
            emit(level as u8, self.count >> level, &node);
            match self.filled[level].take() {
                None => {
                    self.filled[level] = Some(node);
                    break;
                }
                Some(left) => node = self.key.parent(&left, &node),
            }
        }
        self.count += 1;
    }
    /// Append the coin at the next position. Capacity is `2^max_depth` leaves.
    pub fn append(&mut self, owner: &[u8; IDENTITY_BYTES], commitment: &AmountCommitment) -> Result<u64, TreeError> {
        if self.count >= (1u64 << self.max_depth) {
            return Err(TreeError::Capacity);
        }
        let owner = Node::from_identity_bytes(owner).map_err(|_| TreeError::Encoding)?;
        let position = self.count;
        self.append_leaf(self.key.leaf(&owner, commitment));
        Ok(position)
    }
    /// Append while exposing the newly completed leaf and parent subtrees.
    /// Over N appends this emits fewer than 2N nodes in total; a single append
    /// emits at most max_depth + 1. Existing append/root encoding is unchanged.
    pub fn append_with_nodes(&mut self, owner: &[u8; IDENTITY_BYTES], commitment: &AmountCommitment) -> Result<(u64, Vec<CompletedNode>), TreeError> {
        if self.count >= (1u64 << self.max_depth) { return Err(TreeError::Capacity); }
        let owner = Node::from_identity_bytes(owner).map_err(|_| TreeError::Encoding)?;
        let position = self.count;
        let mut nodes = Vec::new();
        self.append_leaf_with(self.key.leaf(&owner, commitment), &mut |level, index, node| {
            nodes.push(CompletedNode { level, index, node: node.clone() });
        });
        Ok((position, nodes))
    }

    pub fn root_at_depth(&self, depth: usize) -> Result<RootRecord, TreeError> {
        if depth < self.current_depth() || depth > self.max_depth {
            return Err(TreeError::Depth);
        }
        // Fold the pending left nodes upward, padding with zero subtrees.
        let mut node: Option<Node> = None;
        for level in 0..depth {
            node = match (&self.filled[level], node) {
                (Some(left), Some(right)) => Some(self.key.parent(left, &right)),
                (Some(left), None) => Some(self.key.parent(left, &self.zeros[level])),
                (None, Some(right)) => Some(self.key.parent(&right, &self.zeros[level])),
                (None, None) => None,
            };
        }
        // When the count exactly fills `depth` levels the complete subtree
        // sits in `filled[depth]` with nothing carried; otherwise the carried
        // node is the root, or the zero subtree for an empty accumulator.
        let root = node
            .or_else(|| self.filled.get(depth).cloned().flatten())
            .unwrap_or_else(|| self.zeros[depth].clone());
        Ok(RootRecord {
            context: self.context,
            depth: depth as u8,
            coins: self.count,
            root,
        })
    }
    /// `QCT3FR` ‖ context ‖ max_depth ‖ count ‖ the filled node of every set
    /// bit of `count`, in ascending level order.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(FRONTIER_HEADER_BYTES + self.filled.len() * NODE_BYTES);
        bytes.extend_from_slice(FRONTIER_VERSION);
        bytes.extend_from_slice(&self.context);
        bytes.push(self.max_depth as u8);
        bytes.extend_from_slice(&self.count.to_le_bytes());
        for node in self.filled.iter().flatten() {
            bytes.extend_from_slice(&node.to_bytes());
        }
        bytes
    }
    pub fn decode(bytes: &[u8], context: &[u8; 32], max_depth: usize) -> Result<Self, TreeError> {
        if bytes.len() < FRONTIER_HEADER_BYTES || &bytes[..8] != FRONTIER_VERSION {
            return Err(TreeError::Encoding);
        }
        if &bytes[8..40] != context {
            return Err(TreeError::Context);
        }
        if usize::from(bytes[40]) != max_depth || !(1..=MAX_DEPTH).contains(&max_depth) {
            return Err(TreeError::Depth);
        }
        let count = u64::from_le_bytes(bytes[41..49].try_into().map_err(|_| TreeError::Encoding)?);
        if count > (1u64 << max_depth) {
            return Err(TreeError::Capacity);
        }
        let expected = (0..=max_depth).filter(|level| count >> level & 1 == 1).count();
        if bytes.len() != FRONTIER_HEADER_BYTES + expected * NODE_BYTES {
            return Err(TreeError::Encoding);
        }
        let mut frontier = Self::new(context, max_depth)?;
        frontier.count = count;
        let mut offset = FRONTIER_HEADER_BYTES;
        for level in 0..=max_depth {
            if count >> level & 1 == 1 {
                frontier.filled[level] = Some(
                    Node::from_bytes(&bytes[offset..offset + NODE_BYTES]).map_err(|_| TreeError::Encoding)?,
                );
                offset += NODE_BYTES;
            }
        }
        Ok(frontier)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{AmountOpening, CommitmentKey};
    use super::*;
    fn coins(count: usize) -> Vec<CoinRecord> {
        let key = CommitmentKey::derive(&[3; 32]);
        (0..count)
            .map(|i| CoinRecord {
                // Addresses deliberately decrease so address order differs
                // from insertion order.
                address: [200 - i as u8; 32],
                owner: [i as u8; IDENTITY_BYTES],
                commitment: key.commit(
                    i as u128,
                    &AmountOpening::from_seed(&[3; 32], &[i as u8; 32]),
                ),
                position: i as u64,
            })
            .collect()
    }
    #[test]
    fn indexed_paths_match_full_trees_and_reject_missing_or_corrupt_nodes() {
        use std::collections::BTreeMap;
        let context = [3; 32];
        let records = coins(9);
        let mut frontier = Frontier::new(&context, 8).unwrap();
        let reader = IndexedTree::new(&context, 8).unwrap();
        let mut nodes = BTreeMap::new();
        for count in 1..=records.len() {
            let coin = &records[count - 1];
            let (_, emitted) = frontier.append_with_nodes(&coin.owner, &coin.commitment).unwrap();
            assert!(emitted.len() <= 9);
            for node in emitted { assert!(nodes.insert((node.level, node.index), node.node).is_none()); }
            assert!(nodes.len() < 2 * count);
            let tree = CoinTree::build(&context, &records[..count], 8, 100).unwrap();
            for depth in [tree.current_depth(), 8] {
                let root = frontier.root_at_depth(depth).unwrap();
                assert_eq!(root, tree.root_at_depth(depth).unwrap());
                for coin in &records[..count] {
                    let mut reads = 0;
                    let path = reader.auth_path(&root, coin, |level, index| -> Result<_, ()> {
                        reads += 1; Ok(nodes.get(&(level, index)).cloned())
                    }).unwrap();
                    assert!(reads <= 2 * depth);
                    let full = tree.auth_path(&coin.address, depth).unwrap();
                    assert_eq!(path.siblings, full.siblings); assert_eq!(path.right, full.right);
                }
            }
        }
        let root = frontier.root_at_depth(8).unwrap();
        assert!(matches!(reader.auth_path(&root, &records[0], |_, _| Ok::<_, ()>(None)), Err(IndexedWitnessError::MissingNode)));
        assert!(matches!(reader.auth_path(&root, &records[0], |_, _| Err::<Option<Node>, _>("disk error")), Err(IndexedWitnessError::Lookup("disk error"))));
        assert!(matches!(reader.auth_path(&root, &records[0], |_, _| Ok::<_, ()>(Some(Node::zero()))), Err(IndexedWitnessError::RootMismatch)));
        let mut wrong = root.clone(); wrong.context[0] ^= 1;
        assert!(matches!(reader.auth_path(&wrong, &records[0], |_, _| Ok::<_, ()>(None)), Err(IndexedWitnessError::Tree(TreeError::Context))));
        let mut absent = coins(1).remove(0); absent.position = root.coins;
        assert!(matches!(reader.auth_path(&root, &absent, |_, _| Ok::<_, ()>(None)), Err(IndexedWitnessError::Tree(TreeError::MissingCoin))));
    }

    #[test]
    fn indexed_paths_above_4096_and_at_max_capacity_have_bounded_reads() {
        // Homogeneous leaves let us construct the exact large-tree subtrees
        // by repeated hashing, without allocating billions of fixture leaves.
        let context = [3; 32];
        let key = MembershipKey::derive(&context);
        let mut coin = coins(1).remove(0);
        let mut full = vec![key.leaf(&Node::from_identity_bytes(&coin.owner).unwrap(), &coin.commitment)];
        for level in 0..32 { full.push(key.parent(&full[level], &full[level])); }
        let reader = IndexedTree::new(&context, 32).unwrap();
        for count in [4097u64, (1u64 << 32) - 1, 1u64 << 32] {
            let mut frontier = Frontier::new(&context, 32).unwrap();
            frontier.count = count;
            for level in 0..=32 {
                frontier.filled[level] = if (count >> level) & 1 == 1 { Some(full[level].clone()) } else { None };
            }
            let root = frontier.root_at_depth(frontier.current_depth()).unwrap();
            for position in [0, count / 2, count - 1] {
                coin.position = position;
                let mut reads = 0;
                reader.auth_path(&root, &coin, |level, index| -> Result<_, ()> {
                    reads += 1;
                    assert!((index + 1) << level <= count);
                    Ok(Some(full[usize::from(level)].clone()))
                }).unwrap();
                assert!(reads <= 2 * usize::from(root.depth));
            }
        }
    }

    #[test]
    fn canonical_order_paths_growth_and_padding_match_leaf_hashes() {
        let context = [3; 32];
        let key = MembershipKey::derive(&context);
        for count in [0, 1, 2, 3, 5] {
            let mut records = coins(count);
            let tree = CoinTree::build(&context, &records, 8, 100).unwrap();
            assert_eq!(
                tree.current_depth(),
                match count {
                    0..=2 => 1,
                    3 => 2,
                    _ => 3,
                }
            );
            let root = tree.root_at_depth(8).unwrap();
            for coin in &records {
                let path = tree.auth_path(&coin.address, 8).unwrap();
                let mut node = key.leaf(
                    &Node::from_identity_bytes(&coin.owner).unwrap(),
                    &coin.commitment,
                );
                for (sibling, right) in path.siblings.iter().zip(&path.right) {
                    node = if *right {
                        key.parent(sibling, &node)
                    } else {
                        key.parent(&node, sibling)
                    };
                }
                assert_eq!(node, root.root);
            }
            // Record order does not matter; position does.
            records.reverse();
            assert_eq!(
                CoinTree::build(&context, &records, 8, 100)
                    .unwrap()
                    .root_at_depth(8)
                    .unwrap(),
                root
            );
            let encoded = root.encode().unwrap();
            assert_eq!(RootRecord::decode(&encoded, &context).unwrap(), root);
            assert!(tree.auth_path(&[255; 32], 8).is_err());
        }
        // Swapping positions changes the root: leaf order is committed.
        let mut records = coins(3);
        let original = CoinTree::build(&context, &records, 8, 100).unwrap().root_at_depth(8).unwrap();
        records[0].position = 1;
        records[1].position = 0;
        assert_ne!(CoinTree::build(&context, &records, 8, 100).unwrap().root_at_depth(8).unwrap(), original);
    }
    #[test]
    fn frontier_matches_full_reconstruction_and_round_trips() {
        let context = [3; 32];
        let records = coins(9);
        let mut frontier = Frontier::new(&context, 8).unwrap();
        assert_eq!(frontier.root_at_depth(8).unwrap(), CoinTree::build(&context, &[], 8, 100).unwrap().root_at_depth(8).unwrap());
        assert_eq!(frontier.root_at_depth(1).unwrap().root, CoinTree::build(&context, &[], 8, 100).unwrap().root_at_depth(1).unwrap().root);
        for count in 1..=records.len() {
            let coin = &records[count - 1];
            assert_eq!(frontier.append(&coin.owner, &coin.commitment).unwrap(), coin.position);
            let tree = CoinTree::build(&context, &records[..count], 8, 100).unwrap();
            assert_eq!(frontier.count(), tree.coins());
            assert_eq!(frontier.current_depth(), tree.current_depth());
            for depth in tree.current_depth()..=8 {
                assert_eq!(frontier.root_at_depth(depth).unwrap(), tree.root_at_depth(depth).unwrap());
            }
            assert!(frontier.root_at_depth(tree.current_depth().saturating_sub(1)).is_err() || tree.current_depth() == 1);
            let bytes = frontier.encode();
            let decoded = Frontier::decode(&bytes, &context, 8).unwrap();
            assert_eq!(decoded.count(), frontier.count());
            assert_eq!(decoded.root_at_depth(8).unwrap(), frontier.root_at_depth(8).unwrap());
            assert_eq!(tree.frontier().encode(), bytes);
            assert!(Frontier::decode(&bytes, &[4; 32], 8).is_err());
            assert!(Frontier::decode(&bytes, &context, 7).is_err());
            assert!(Frontier::decode(&bytes[..bytes.len() - 1], &context, 8).is_err());
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(Frontier::decode(&trailing, &context, 8).is_err());
        }
        assert!(frontier.root_at_depth(9).is_err());
        // Capacity is 2^max_depth leaves.
        let mut tiny = Frontier::new(&context, 1).unwrap();
        tiny.append(&records[0].owner, &records[0].commitment).unwrap();
        tiny.append(&records[1].owner, &records[1].commitment).unwrap();
        assert_eq!(tiny.root_at_depth(1).unwrap(), CoinTree::build(&context, &records[..2], 1, 100).unwrap().root_at_depth(1).unwrap());
        assert!(matches!(tiny.append(&records[2].owner, &records[2].commitment), Err(TreeError::Capacity)));
        assert!(Frontier::new(&context, 0).is_err());
        assert!(Frontier::new(&context, 33).is_err());
    }
    #[test]
    fn capacity_duplicate_position_and_root_record_rejections() {
        let context = [3; 32];
        let mut records = coins(3);
        assert!(matches!(
            CoinTree::build(&context, &records, 3, 9),
            Err(TreeError::Capacity)
        ));
        let tree = CoinTree::build(&context, &records, 3, 10).unwrap();
        assert!(tree.root_at_depth(1).is_err());
        assert!(tree.auth_path(&records[0].address, 4).is_err());
        assert!(matches!(
            CoinTree::build(&context, &records, 1, 100),
            Err(TreeError::Capacity)
        ));
        assert!(matches!(
            CoinTree::build(&context, &records, 33, 100),
            Err(TreeError::Depth)
        ));
        let root = tree.root_at_depth(3).unwrap();
        let encoded = root.encode().unwrap();
        assert_eq!(
            RootRecord::decode(&encoded, &[4; 32]),
            Err(TreeError::Context)
        );
        for length in [0, 7, 40, 48, ROOT_RECORD_BYTES - 1] {
            assert!(RootRecord::decode(&encoded[..length], &context).is_err());
        }
        let mut bad = encoded;
        bad[0] ^= 1;
        assert!(RootRecord::decode(&bad, &context).is_err());
        let mut bad = encoded;
        bad[40] = 0;
        assert!(RootRecord::decode(&bad, &context).is_err());
        let mut bad = encoded;
        bad[41..49].copy_from_slice(&9u64.to_le_bytes());
        assert!(RootRecord::decode(&bad, &context).is_err());
        let mut bad = encoded;
        // First root coefficient set to p: non-canonical in the 38-bit packing.
        bad[49..54].copy_from_slice(&crate::rp::P.to_le_bytes()[..5]);
        assert!(RootRecord::decode(&bad, &context).is_err());
        let mut gap = coins(3);
        gap[2].position = 3;
        assert!(matches!(CoinTree::build(&context, &gap, 3, 100), Err(TreeError::Position)));
        let mut repeat = coins(3);
        repeat[2].position = 1;
        assert!(matches!(CoinTree::build(&context, &repeat, 3, 100), Err(TreeError::Position)));
        records[1].address = records[0].address;
        assert!(matches!(
            CoinTree::build(&context, &records, 3, 100),
            Err(TreeError::DuplicateAddress)
        ));
    }
}

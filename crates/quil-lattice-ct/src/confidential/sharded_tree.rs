//! Coin accumulator for an application whose coins are split across shards.
//!
//! One tree, whose leaf index carries the shard in its high bits:
//! `position = (shard << subtree_bits) | local`. Each shard owns the
//! contiguous index range under its prefix and computes that subtree's root
//! from its own coins alone; the application's root is the fold of those
//! subtree roots, which is exactly the top `shard_bits` levels of the same
//! tree. So the two-level structure is a *view*, not a different object:
//!
//! * a membership proof is still ONE leaf-to-root path, so the ZK membership
//!   relation, the proof size and the admission rule are unchanged — the top
//!   `shard_bits` siblings are simply the other shards' subtree roots;
//! * a shard writes only its own range, so no cross-shard coordination is
//!   needed to advance the accumulator;
//! * a single transaction can still spend inputs from different shards, since
//!   every input's path ends at the same application root.
//!
//! Occupancy is per shard rather than a dense prefix: within a shard, coins
//! fill `0..count` of its range, and every index above that — and every shard
//! with no coins — is the canonical zero node for its level.
use super::relation::membership::{MembershipKey, Node, MAX_DEPTH};
use super::AmountCommitment;
use super::coin_tree::{AuthPath, CoinRecord, TreeError};

/// Split a position into `(shard, local)`.
pub fn split_position(position: u64, subtree_bits: u8) -> (u64, u64) {
    if subtree_bits >= 64 {
        return (0, position);
    }
    (position >> subtree_bits, position & ((1u64 << subtree_bits) - 1))
}

/// Compose a position from a shard and its local leaf index.
pub fn position_of(shard: u64, local: u64, subtree_bits: u8) -> Result<u64, TreeError> {
    if subtree_bits >= 64 || local >= (1u64 << subtree_bits) {
        return Err(TreeError::Position);
    }
    shard
        .checked_shl(u32::from(subtree_bits))
        .and_then(|high| high.checked_add(local))
        .ok_or(TreeError::Position)
}

/// The shape every node must agree on to compute the same application root:
/// how many levels partition shards, and how many address coins inside one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub shard_bits: u8,
    pub subtree_bits: u8,
}

impl Shape {
    pub fn depth(&self) -> usize {
        usize::from(self.shard_bits) + usize::from(self.subtree_bits)
    }
    pub fn shards(&self) -> u64 {
        1u64 << self.shard_bits
    }
    fn validate(&self) -> Result<(), TreeError> {
        if self.subtree_bits == 0 || self.depth() == 0 || self.depth() > MAX_DEPTH {
            return Err(TreeError::Depth);
        }
        Ok(())
    }
}

fn zero_nodes(key: &MembershipKey, depth: usize) -> Vec<Node> {
    let mut zeros = vec![Node::zero()];
    for level in 0..depth {
        zeros.push(key.parent(&zeros[level], &zeros[level]));
    }
    zeros
}

/// The subtree root one shard computes from its own coins, with no knowledge
/// of any other shard. `local_leaves` are the shard's coins in local position
/// order; absent positions above them are zeros.
pub fn subtree_root(
    context: &[u8; 32],
    shape: Shape,
    coins: &[CoinRecord],
) -> Result<Node, TreeError> {
    shape.validate()?;
    let key = MembershipKey::derive(context);
    let zeros = zero_nodes(&key, shape.depth());
    let mut leaves: Vec<(u64, Node)> = Vec::with_capacity(coins.len());
    for coin in coins {
        let (_, local) = split_position(coin.position, shape.subtree_bits);
        if local >= (1u64 << shape.subtree_bits) {
            return Err(TreeError::Position);
        }
        let owner =
            Node::from_identity_bytes(&coin.owner).map_err(|_| TreeError::Encoding)?;
        leaves.push((local, key.leaf(&owner, &coin.commitment)));
    }
    fold_level(&key, &zeros, leaves, usize::from(shape.subtree_bits))
}

/// One level of the sparse fold. `nodes` must be sorted by index and hold no
/// duplicates; `zeros[level]` is the zero node at the nodes' own level.
/// The path from one reported subtree up to the application root, over the
/// sparse set every shard reports (`fold_sparse`). `mine` is the level and
/// index of the subtree the path starts at, and must be one of `nodes`.
///
/// A shard proves its own coins up to its subtree root from its own state;
/// this is the rest of the path, which only the shards' reports can supply.
pub fn fold_sparse_auth_path(
    context: &[u8; 32],
    top_level: usize,
    nodes: &[(usize, u64, Node)],
    mine: (usize, u64),
) -> Result<AuthPath, TreeError> {
    if top_level == 0 || top_level > MAX_DEPTH || mine.0 >= top_level {
        return Err(TreeError::Depth);
    }
    if !nodes.iter().any(|(level, index, _)| (*level, *index) == mine) {
        return Err(TreeError::MissingCoin);
    }
    let key = MembershipKey::derive(context);
    let zeros = zero_nodes(&key, top_level);
    let mut placed: std::collections::BTreeMap<usize, Vec<(u64, Node)>> = std::collections::BTreeMap::new();
    for (level, index, node) in nodes {
        if *level >= top_level || *index >= (1u64 << (top_level - level)) {
            return Err(TreeError::Position);
        }
        placed.entry(*level).or_default().push((*index, node.clone()));
    }
    let start = *placed.keys().next().expect("mine is placed");
    let mut carried: Vec<(u64, Node)> = Vec::new();
    let mut index = mine.1;
    let mut path = AuthPath {
        siblings: Vec::with_capacity(top_level - mine.0),
        right: Vec::with_capacity(top_level - mine.0),
    };
    for level in start..top_level {
        let mut here = placed.remove(&level).unwrap_or_default();
        here.extend(carried.drain(..));
        let here = sorted_level(here, None)?;
        // Below the subtree's own level the path has not started: those levels
        // are the shard's own, proven from its own state.
        if level >= mine.0 {
            let sibling = here
                .binary_search_by_key(&(index ^ 1), |(at, _)| *at)
                .map(|at| here[at].1.clone())
                .unwrap_or_else(|_| zeros[level].clone());
            path.siblings.push(sibling);
            path.right.push(index & 1 != 0);
            index >>= 1;
        }
        carried = fold_once(&key, &zeros, &here, level);
    }
    Ok(path)
}

fn fold_once(
    key: &MembershipKey,
    zeros: &[Node],
    nodes: &[(u64, Node)],
    level: usize,
) -> Vec<(u64, Node)> {
    let mut next: Vec<(u64, Node)> = Vec::with_capacity(nodes.len().div_ceil(2));
    let mut i = 0;
    while i < nodes.len() {
        let (index, ref node) = nodes[i];
        let parent = index >> 1;
        let (left, right) = if index & 1 == 0 {
            let sibling = match nodes.get(i + 1) {
                Some((next_index, next_node)) if *next_index == index + 1 => {
                    i += 1;
                    next_node.clone()
                }
                _ => zeros[level].clone(),
            };
            (node.clone(), sibling)
        } else {
            (zeros[level].clone(), node.clone())
        };
        next.push((parent, key.parent(&left, &right)));
        i += 1;
    }
    next
}

/// Sorted, duplicate-free sparse level, as every fold requires.
fn sorted_level(mut nodes: Vec<(u64, Node)>, shards: Option<u64>) -> Result<Vec<(u64, Node)>, TreeError> {
    nodes.sort_unstable_by_key(|(index, _)| *index);
    if nodes.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(TreeError::Position);
    }
    if shards.is_some_and(|shards| nodes.iter().any(|(index, _)| *index >= shards)) {
        return Err(TreeError::Position);
    }
    Ok(nodes)
}

/// Fold a sparse level up `levels` times, filling absent nodes with zeros.
fn fold_level(
    key: &MembershipKey,
    zeros: &[Node],
    nodes: Vec<(u64, Node)>,
    levels: usize,
) -> Result<Node, TreeError> {
    let mut nodes = sorted_level(nodes, None)?;
    for level in 0..levels {
        nodes = fold_once(key, zeros, &nodes, level);
    }
    Ok(match nodes.first() {
        Some((0, node)) => node.clone(),
        Some(_) => return Err(TreeError::Position),
        None => zeros[levels].clone(),
    })
}

/// The application root from the per-shard subtree roots: the top
/// `shard_bits` levels of the same tree. A shard that has never held a coin
/// may be omitted; it folds as the zero subtree.
pub fn fold_subtree_roots(
    context: &[u8; 32],
    shape: Shape,
    roots: &[(u64, Node)],
) -> Result<Node, TreeError> {
    shape.validate()?;
    let key = MembershipKey::derive(context);
    let zeros = zero_nodes(&key, shape.depth());
    if roots.iter().any(|(shard, _)| *shard >= shape.shards()) {
        return Err(TreeError::Position);
    }
    // The shard roots sit at level `subtree_bits`, so their zero is that
    // level's zero node, not the leaf zero.
    fold_level(
        &key,
        &zeros[usize::from(shape.subtree_bits)..],
        roots.to_vec(),
        usize::from(shape.shard_bits),
    )
}

/// The siblings from one shard's subtree root up to the application root,
/// given every non-empty shard's subtree root. The shard's own root is not
/// part of the result: a path continues from it, so appending these siblings
/// to a within-shard path gives the whole leaf-to-root path.
///
/// This is what lets a node holding only its own shard serve a full witness:
/// the shard roots are public (every node publishes them), and the top levels
/// are a fold over at most one entry per non-empty shard.
pub fn fold_auth_path(
    context: &[u8; 32],
    shape: Shape,
    roots: &[(u64, Node)],
    shard: u64,
) -> Result<AuthPath, TreeError> {
    shape.validate()?;
    if shard >= shape.shards() {
        return Err(TreeError::Position);
    }
    let key = MembershipKey::derive(context);
    let zeros = zero_nodes(&key, shape.depth());
    let upper = &zeros[usize::from(shape.subtree_bits)..];
    let mut nodes = sorted_level(roots.to_vec(), Some(shape.shards()))?;
    let mut index = shard;
    let mut path = AuthPath {
        siblings: Vec::with_capacity(usize::from(shape.shard_bits)),
        right: Vec::with_capacity(usize::from(shape.shard_bits)),
    };
    for level in 0..usize::from(shape.shard_bits) {
        let sibling = nodes
            .binary_search_by_key(&(index ^ 1), |(at, _)| *at)
            .map(|at| nodes[at].1.clone())
            .unwrap_or_else(|_| upper[level].clone());
        path.siblings.push(sibling);
        path.right.push(index & 1 != 0);
        nodes = fold_once(&key, upper, &nodes, level);
        index >>= 1;
    }
    Ok(path)
}

/// Fold nodes placed at arbitrary levels into the node at (`top_level`,
/// relative index 0) — the root of a subtree `top_level` levels above the
/// leaves, or of the whole tree when `top_level` is its depth.
///
/// `nodes` are `(level, index, node)`, with `index` counted within that level
/// of the subtree being folded. Positions must be prefix-free: no node may sit
/// inside another's subtree or share its position, since that would count the
/// same coins twice. Everything absent folds as the zero subtree of its level.
///
/// This is what lets shards at different depths report one subtree root each:
/// a shard holding a larger part of the application reports a node higher up,
/// and the fold places every report where it belongs.
pub fn fold_sparse(
    context: &[u8; 32],
    top_level: usize,
    nodes: &[(usize, u64, Node)],
) -> Result<Node, TreeError> {
    if top_level == 0 || top_level > MAX_DEPTH {
        return Err(TreeError::Depth);
    }
    let key = MembershipKey::derive(context);
    let zeros = zero_nodes(&key, top_level);
    let mut placed: std::collections::BTreeMap<usize, Vec<(u64, Node)>> = std::collections::BTreeMap::new();
    for (level, index, node) in nodes {
        if *level >= top_level || *index >= (1u64 << (top_level - level)) {
            return Err(TreeError::Position);
        }
        placed.entry(*level).or_default().push((*index, node.clone()));
    }
    let Some(&start) = placed.keys().next() else {
        return Ok(zeros[top_level].clone());
    };
    let mut carried: Vec<(u64, Node)> = Vec::new();
    for level in start..top_level {
        let mut here = placed.remove(&level).unwrap_or_default();
        here.extend(carried.drain(..));
        // A carried parent landing on a placed node means one reported node
        // lies inside another's subtree; a repeated index is a double report.
        let here = sorted_level(here, None)?;
        carried = fold_once(&key, &zeros, &here, level);
    }
    Ok(match carried.as_slice() {
        [] => zeros[top_level].clone(),
        [(0, node)] => node.clone(),
        _ => return Err(TreeError::Position),
    })
}

/// The whole application's tree, built from every shard's coins. Used by a
/// node that holds all of them (an archive) and by the tests that pin the
/// fold against a direct build.
pub struct ShardedCoinTree {
    context: [u8; 32],
    // Construction context retained alongside the precomputed tree nodes.
    #[allow(dead_code)]
    key: MembershipKey,
    zeros: Vec<Node>,
    shape: Shape,
    /// Sparse nodes per level, sorted by index.
    levels: Vec<Vec<(u64, Node)>>,
    /// `(address, position)` sorted by address.
    index: Vec<([u8; 32], u64)>,
}

impl ShardedCoinTree {
    pub fn build(
        context: &[u8; 32],
        shape: Shape,
        coins: &[CoinRecord],
    ) -> Result<Self, TreeError> {
        shape.validate()?;
        let key = MembershipKey::derive(context);
        let zeros = zero_nodes(&key, shape.depth());
        let mut leaves: Vec<(u64, Node)> = Vec::with_capacity(coins.len());
        let mut index: Vec<([u8; 32], u64)> = Vec::with_capacity(coins.len());
        for coin in coins {
            let (shard, _) = split_position(coin.position, shape.subtree_bits);
            if shard >= shape.shards() {
                return Err(TreeError::Position);
            }
            let owner =
                Node::from_identity_bytes(&coin.owner).map_err(|_| TreeError::Encoding)?;
            leaves.push((coin.position, key.leaf(&owner, &coin.commitment)));
            index.push((coin.address, coin.position));
        }
        leaves.sort_unstable_by_key(|(position, _)| *position);
        if leaves.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(TreeError::Position);
        }
        index.sort_unstable_by_key(|(address, _)| *address);
        if index.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(TreeError::DuplicateAddress);
        }
        // Keep every level so a path can read its siblings.
        let mut levels = vec![leaves];
        for level in 0..shape.depth() {
            let previous = &levels[level];
            let mut next: Vec<(u64, Node)> = Vec::with_capacity(previous.len().div_ceil(2));
            let mut i = 0;
            while i < previous.len() {
                let (position, ref node) = previous[i];
                let parent = position >> 1;
                let (left, right) = if position & 1 == 0 {
                    let sibling = match previous.get(i + 1) {
                        Some((next_index, next_node)) if *next_index == position + 1 => {
                            i += 1;
                            next_node.clone()
                        }
                        _ => zeros[level].clone(),
                    };
                    (node.clone(), sibling)
                } else {
                    (zeros[level].clone(), node.clone())
                };
                next.push((parent, key.parent(&left, &right)));
                i += 1;
            }
            levels.push(next);
        }
        Ok(Self { context: *context, key, zeros, shape, levels, index })
    }

    pub fn shape(&self) -> Shape {
        self.shape
    }

    /// Coins in the tree.
    pub fn coins(&self) -> u64 {
        self.index.len() as u64
    }

    /// The accumulator has ONE shape, so this is the only depth there is. The
    /// argument is checked rather than ignored: a caller asking for another
    /// depth is asking about a different tree.
    pub fn root_at_depth(&self, depth: usize) -> Result<super::coin_tree::RootRecord, TreeError> {
        if depth != self.shape.depth() {
            return Err(TreeError::Depth);
        }
        Ok(super::coin_tree::RootRecord {
            context: self.context,
            depth: depth as u8,
            coins: self.coins(),
            root: self.root(),
        })
    }

    pub fn current_depth(&self) -> usize {
        self.shape.depth()
    }

    /// [`Self::auth_path`] with the caller's expected depth checked.
    pub fn auth_path_at_depth(&self, address: &[u8; 32], depth: usize) -> Result<AuthPath, TreeError> {
        if depth != self.shape.depth() {
            return Err(TreeError::Depth);
        }
        self.auth_path(address)
    }

    pub fn root(&self) -> Node {
        match self.levels[self.shape.depth()].first() {
            Some((_, node)) => node.clone(),
            None => self.zeros[self.shape.depth()].clone(),
        }
    }

    /// The node at `(level, index)`, which is the zero node for that level
    /// when no coin sits beneath it.
    fn node(&self, level: usize, index: u64) -> Node {
        self.levels[level]
            .binary_search_by_key(&index, |(i, _)| *i)
            .map(|at| self.levels[level][at].1.clone())
            .unwrap_or_else(|_| self.zeros[level].clone())
    }

    pub fn position(&self, address: &[u8; 32]) -> Option<u64> {
        self.index
            .binary_search_by_key(address, |(address, _)| *address)
            .ok()
            .map(|at| self.index[at].1)
    }

    /// One leaf-to-root path. Its top `shard_bits` siblings are the other
    /// shards' subtree roots, which is what lets a wallet spend a coin from
    /// one shard against the application's root.
    pub fn auth_path(&self, address: &[u8; 32]) -> Result<AuthPath, TreeError> {
        let position = self.position(address).ok_or(TreeError::MissingCoin)?;
        let mut path = AuthPath {
            siblings: Vec::with_capacity(self.shape.depth()),
            right: Vec::with_capacity(self.shape.depth()),
        };
        let mut index = position;
        for level in 0..self.shape.depth() {
            path.siblings.push(self.node(level, index ^ 1));
            path.right.push(index & 1 != 0);
            index >>= 1;
        }
        Ok(path)
    }

    /// Recompute the root from a leaf and its path, exactly as a verifier
    /// does. `owner`/`commitment` are the coin's committed fields.
    pub fn root_from_path(
        context: &[u8; 32],
        owner: &Node,
        commitment: &AmountCommitment,
        path: &AuthPath,
    ) -> Result<Node, TreeError> {
        if path.siblings.len() != path.right.len() || path.siblings.len() > MAX_DEPTH {
            return Err(TreeError::Depth);
        }
        let key = MembershipKey::derive(context);
        let mut node = key.leaf(owner, commitment);
        for (sibling, right) in path.siblings.iter().zip(&path.right) {
            node = if *right { key.parent(sibling, &node) } else { key.parent(&node, sibling) };
        }
        Ok(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::{
        relation::membership::IDENTITY_BYTES, AmountOpening, CommitmentKey,
    };

    fn coin(context: &[u8; 32], seed: u8, position: u64) -> CoinRecord {
        CoinRecord {
            address: [seed; 32],
            owner: [seed; IDENTITY_BYTES],
            commitment: CommitmentKey::derive(context)
                .commit(u128::from(seed), &AmountOpening::from_seed(context, &[seed; 32])),
            position,
        }
    }

    /// The property the whole design rests on: a shard computing its subtree
    /// root from its own coins alone, folded with the other shards' roots,
    /// gives exactly the root a node holding every coin would build.
    #[test]
    fn folding_per_shard_roots_equals_building_the_whole_tree() {
        let context = [7u8; 32];
        let shape = Shape { shard_bits: 3, subtree_bits: 4 };
        // Three of eight shards hold coins; the rest are empty.
        let mut all = Vec::new();
        let mut per_shard: Vec<(u64, Vec<CoinRecord>)> = Vec::new();
        for (shard, count) in [(0u64, 3usize), (2, 1), (5, 5)] {
            let mut shard_coins = Vec::new();
            for local in 0..count {
                let seed = (shard * 16 + local as u64 + 1) as u8;
                let position = position_of(shard, local as u64, shape.subtree_bits).unwrap();
                shard_coins.push(coin(&context, seed, position));
                all.push(coin(&context, seed, position));
            }
            per_shard.push((shard, shard_coins));
        }
        let whole = ShardedCoinTree::build(&context, shape, &all).unwrap();
        let roots: Vec<(u64, Node)> = per_shard
            .iter()
            .map(|(shard, coins)| (*shard, subtree_root(&context, shape, coins).unwrap()))
            .collect();
        assert_eq!(fold_subtree_roots(&context, shape, &roots).unwrap(), whole.root());
        // Omitting an empty shard is the same as folding it as zero.
        let mut with_empty = roots.clone();
        with_empty.push((7, subtree_root(&context, shape, &[]).unwrap()));
        assert_eq!(fold_subtree_roots(&context, shape, &with_empty).unwrap(), whole.root());
    }

    /// A coin in one shard proves against the APPLICATION root, so inputs
    /// from different shards can be spent in one transaction.
    #[test]
    fn a_path_from_any_shard_verifies_against_the_application_root() {
        let context = [9u8; 32];
        let shape = Shape { shard_bits: 2, subtree_bits: 3 };
        let coins: Vec<CoinRecord> = [(0u64, 0u64), (0, 1), (1, 0), (3, 4)]
            .iter()
            .enumerate()
            .map(|(i, (shard, local))| {
                coin(&context, i as u8 + 1, position_of(*shard, *local, shape.subtree_bits).unwrap())
            })
            .collect();
        let tree = ShardedCoinTree::build(&context, shape, &coins).unwrap();
        let root = tree.root();
        for c in &coins {
            let path = tree.auth_path(&c.address).unwrap();
            assert_eq!(path.siblings.len(), shape.depth());
            let owner = Node::from_identity_bytes(&c.owner).unwrap();
            assert_eq!(
                ShardedCoinTree::root_from_path(&context, &owner, &c.commitment, &path).unwrap(),
                root,
                "coin at position {} must prove against the application root", c.position
            );
        }
        // A coin that is not in the tree has no path.
        assert!(tree.auth_path(&[0xFF; 32]).is_err());
    }

    /// A node holding one shard can serve a whole witness: its own subtree
    /// path, then the fold over the public shard roots. The result must equal
    /// the path a node holding every coin would produce.
    #[test]
    fn a_shard_path_plus_the_public_fold_equals_the_whole_tree_path() {
        let context = [11u8; 32];
        let shape = Shape { shard_bits: 3, subtree_bits: 4 };
        let mut all = Vec::new();
        let mut per_shard: Vec<(u64, Vec<CoinRecord>)> = Vec::new();
        for (shard, count) in [(1u64, 2usize), (4, 3), (6, 1)] {
            let mut shard_coins = Vec::new();
            for local in 0..count {
                let seed = (shard * 16 + local as u64 + 1) as u8;
                let position = position_of(shard, local as u64, shape.subtree_bits).unwrap();
                shard_coins.push(coin(&context, seed, position));
                all.push(coin(&context, seed, position));
            }
            per_shard.push((shard, shard_coins));
        }
        let whole = ShardedCoinTree::build(&context, shape, &all).unwrap();
        let roots: Vec<(u64, Node)> = per_shard
            .iter()
            .map(|(shard, coins)| (*shard, subtree_root(&context, shape, coins).unwrap()))
            .collect();
        for (shard, coins) in &per_shard {
            // The shard's own subtree, built from its coins alone.
            let local_tree = ShardedCoinTree::build(
                &context,
                Shape { shard_bits: 0, subtree_bits: shape.subtree_bits },
                &coins
                    .iter()
                    .map(|c| CoinRecord {
                        address: c.address,
                        owner: c.owner,
                        commitment: c.commitment.clone(),
                        position: split_position(c.position, shape.subtree_bits).1,
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            let upper = fold_auth_path(&context, shape, &roots, *shard).unwrap();
            for c in coins {
                let mut path = local_tree.auth_path(&c.address).unwrap();
                path.siblings.extend(upper.siblings.iter().cloned());
                path.right.extend(upper.right.iter().copied());
                assert_eq!(path.siblings, whole.auth_path(&c.address).unwrap().siblings);
                let owner = Node::from_identity_bytes(&c.owner).unwrap();
                assert_eq!(
                    ShardedCoinTree::root_from_path(&context, &owner, &c.commitment, &path).unwrap(),
                    whole.root(),
                );
            }
        }
        // A shard outside the shape has no path.
        assert!(fold_auth_path(&context, shape, &roots, shape.shards()).is_err());
    }

    /// Subtree roots reported from different depths fold to the root a node
    /// holding every coin builds, and overlapping reports are refused.
    #[test]
    fn subtree_roots_from_mixed_depths_fold_to_the_whole_tree_root() {
        let context = [13u8; 32];
        let shape = Shape { shard_bits: 3, subtree_bits: 4 };
        let key = MembershipKey::derive(&context);
        let mut all = Vec::new();
        let mut leaves: Vec<(u64, Node)> = Vec::new();
        for (shard, count) in [(0u64, 2usize), (1, 1), (5, 3), (6, 1)] {
            for local in 0..count {
                let seed = (shard * 16 + local as u64 + 1) as u8;
                let position = position_of(shard, local as u64, shape.subtree_bits).unwrap();
                let c = coin(&context, seed, position);
                let owner = Node::from_identity_bytes(&c.owner).unwrap();
                leaves.push((position, key.leaf(&owner, &c.commitment)));
                all.push(c);
            }
        }
        let whole = ShardedCoinTree::build(&context, shape, &all).unwrap();
        let depth = shape.depth();
        // Shard roots at level 4 (one per shard) fold to the whole root.
        let per_shard: Vec<(usize, u64, Node)> = [0u64, 1, 5, 6]
            .iter()
            .map(|shard| (4, *shard, whole.node(4, *shard)))
            .collect();
        assert_eq!(fold_sparse(&context, depth, &per_shard).unwrap(), whole.root());
        // A shard holding shards 0..=1 reports ONE node at level 5; another
        // reports shards 4..=7 as one node at level 6. Mixed depths, same root.
        let mixed = vec![(5, 0, whole.node(5, 0)), (6, 1, whole.node(6, 1))];
        assert_eq!(fold_sparse(&context, depth, &mixed).unwrap(), whole.root());
        // Raw leaves fold to it too, and nothing at all folds to the zero root.
        let raw: Vec<(usize, u64, Node)> = leaves.iter().map(|(p, n)| (0, *p, n.clone())).collect();
        assert_eq!(fold_sparse(&context, depth, &raw).unwrap(), whole.root());
        assert_eq!(fold_sparse(&context, depth, &[]).unwrap(), zero_nodes(&key, depth)[depth]);
        // A subtree root, relative to its own position, folds from its leaves.
        let shard5: Vec<(usize, u64, Node)> = leaves
            .iter()
            .filter(|(p, _)| split_position(*p, shape.subtree_bits).0 == 5)
            .map(|(p, n)| (0, split_position(*p, shape.subtree_bits).1, n.clone()))
            .collect();
        assert_eq!(fold_sparse(&context, 4, &shard5).unwrap(), whole.node(4, 5));
        // Overlap: a node inside another reported subtree, or a repeat.
        assert!(fold_sparse(&context, depth, &[(5, 0, whole.node(5, 0)), (4, 1, whole.node(4, 1))]).is_err());
        assert!(fold_sparse(&context, depth, &[(4, 2, whole.node(4, 2)), (4, 2, whole.node(4, 2))]).is_err());
        // Out of range: past the top, or an index the level cannot hold.
        assert!(fold_sparse(&context, depth, &[(depth, 0, whole.root())]).is_err());
        assert!(fold_sparse(&context, depth, &[(6, 4, whole.node(6, 1))]).is_err());
    }

    #[test]
    fn positions_partition_by_shard_and_reject_overflow() {
        let shape = Shape { shard_bits: 2, subtree_bits: 3 };
        assert_eq!(position_of(3, 7, shape.subtree_bits).unwrap(), 31);
        assert_eq!(split_position(31, shape.subtree_bits), (3, 7));
        // A local index beyond the subtree, or a shard beyond the shape.
        assert!(position_of(0, 8, shape.subtree_bits).is_err());
        let context = [1u8; 32];
        let beyond = coin(&context, 1, position_of(4, 0, shape.subtree_bits).unwrap());
        assert!(ShardedCoinTree::build(&context, shape, &[beyond]).is_err());
        // An empty application still has a well-defined root.
        let empty = ShardedCoinTree::build(&context, shape, &[]).unwrap();
        assert_eq!(fold_subtree_roots(&context, shape, &[]).unwrap(), empty.root());
    }

    /// A shard's path to the application root, over what every shard reports:
    /// folding the path back gives the same root `fold_sparse` computes, and
    /// each shard gets its own path.
    #[test]
    fn a_sparse_path_folds_back_to_the_application_root() {
        let context = [3u8; 32];
        let key = MembershipKey::derive(&context);
        let top = 8;
        let node = |seed: u8| Node::from_bytes(&[seed; crate::confidential::relation::membership::NODE_BYTES]).unwrap();
        // Three shards at mixed depths, as reports come in after a split.
        let nodes = vec![(5usize, 1u64, node(1)), (5, 3, node(2)), (4, 0, node(3))];
        let root = fold_sparse(&context, top, &nodes).unwrap();
        for (level, index, subtree) in &nodes {
            let path = fold_sparse_auth_path(&context, top, &nodes, (*level, *index)).unwrap();
            assert_eq!(path.siblings.len(), top - level);
            let mut folded = subtree.clone();
            let mut at = *index;
            for (sibling, right) in path.siblings.iter().zip(&path.right) {
                folded = if *right { key.parent(sibling, &folded) } else { key.parent(&folded, sibling) };
                assert_eq!(*right, at & 1 != 0);
                at >>= 1;
            }
            assert_eq!(folded, root, "level {level} index {index}");
        }
        // A subtree nobody reported has no path.
        assert!(matches!(fold_sparse_auth_path(&context, top, &nodes, (5, 2)), Err(TreeError::MissingCoin)));
    }

}

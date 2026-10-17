//! The application's block summary as a stored binary tree over block ids.
//!
//! The flat summary kept `(block, coins, root)` for every non-empty block in
//! one record: 7,312 bytes a block, 7.5 MB at the block cap, read whole and
//! folded on every refresh. Here every non-empty block is a leaf record and
//! every internal node of the id tree above the leaves is stored:
//!
//! * a node at level `h` with index `i` covers block ids
//!   `[i << h, (i + 1) << h)`. Leaves (level 0) are indexed by block id. The
//!   top (level [`LEVELS`], index 0) is the application root.
//! * Each node is the parent of its children, with an absent child standing
//!   for the zero subtree of its level. That is
//!   `sharded_tree::fold_subtree_roots` stored, so the root is the same value.
//! * A node also records the coins and non-empty blocks under it. The coin
//!   total and each of a shard's per-width subtrees (its report) are then
//!   single reads: a shard's owned range inside one width layer is an aligned
//!   subtree of the id tree.
//!
//! A refresh rewrites the changed leaves and their ancestors, reading each
//! ancestor's other child: [`LEVELS`] parents per changed block.
//!
//! The records are private copies, like the flat summary before them (see
//! `ExecutionEngineManager::rebuild_block_summary_before_report`). They are
//! node-local records at their addresses (`state::LOCAL_RECORD_PREFIX`), not
//! vertices of the application tree; copies stored in the tree before are
//! read until overwritten.
//!
//! **Upgrade.** The first refresh over state that still holds a flat summary
//! builds the tree from it and overwrites the flat record with [`MOVED`].
//! Every member executes that refresh at the same frame. Until then, every
//! read uses the flat record, and a rebuild (member-local: restart, sync,
//! merge) keeps it flat.
use super::coin_blocks::{BLOCK_INDEX_BITS, SUBTREE_BITS};
use super::roots::{BlockSummary, MAX_NONEMPTY_BLOCKS};
use super::state::BLOCK_SUMMARY_ADDRESS;
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
use quil_lattice_ct::confidential::relation::membership::{MembershipKey, Node, NODE_BYTES};
use quil_types::error::{QuilError, Result};
use std::collections::{BTreeMap, BTreeSet};

/// Levels above the leaves: the block index field.
pub const LEVELS: u8 = BLOCK_INDEX_BITS;

/// Tag of the tree's records. Layout:
///
/// ```text
/// [0..23]  0xff
/// [23]     NODE_TAG
/// [24]     level
/// [25..30] 0xff
/// [30..32] index, big-endian
/// ```
///
/// The leading ones keep the family out of every block's own prefix (a block
/// path is at most 15 bits, so its record prefix never reads `ffff`). Byte 23
/// keeps it apart from the application-wide records, where that byte is 0xff.
pub const NODE_TAG: u8 = 0xf4;

/// What the flat summary record holds once its tree has replaced it.
pub const MOVED: &[u8; 8] = b"QCT3BS\0\x02";

const HEADER: usize = 16;
const RECORD: usize = HEADER + NODE_BYTES;
/// A node whose range lost every block in a rebuild. Coins are never
/// removed, so only a rebuild clears one; a cleared node reads as absent.
const CLEARED: [u8; HEADER] = [0; HEADER];

fn invalid() -> QuilError {
    QuilError::InvalidArgument("coin block summary: invalid tree record".into())
}

pub fn node_address(level: u8, index: u64) -> [u8; 32] {
    debug_assert!(level <= LEVELS && index < 1u64 << (LEVELS - level));
    let mut address = [0xff; 32];
    address[23] = NODE_TAG;
    address[24] = level;
    address[30..32].copy_from_slice(&(index as u16).to_be_bytes());
    address
}

/// Whether `address` is one of the tree's records, exactly where
/// [`node_address`] puts them.
pub fn is_node_address(address: &[u8; 32]) -> bool {
    let level = address[24];
    let index = u64::from(u16::from_be_bytes([address[30], address[31]]));
    address[..23].iter().all(|byte| *byte == 0xff)
        && address[23] == NODE_TAG
        && level <= LEVELS
        && address[25..30].iter().all(|byte| *byte == 0xff)
        && index < 1u64 << (LEVELS - level)
}

/// One stored node: the coins and non-empty blocks under it, and its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeNode {
    pub coins: u64,
    pub blocks: u64,
    pub node: Node,
}

impl TreeNode {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECORD);
        bytes.extend_from_slice(&self.coins.to_be_bytes());
        bytes.extend_from_slice(&self.blocks.to_be_bytes());
        bytes.extend_from_slice(&self.node.to_bytes());
        bytes
    }

    /// `None` for a cleared node.
    pub fn decode(bytes: &[u8], level: u8) -> Result<Option<Self>> {
        if bytes == CLEARED {
            return Ok(None);
        }
        if bytes.len() != RECORD || level > LEVELS {
            return Err(invalid());
        }
        let coins = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        let blocks = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        // Every block under a stored node holds at least one coin.
        if blocks == 0 || blocks > 1u64 << level || coins < blocks {
            return Err(invalid());
        }
        let node = Node::from_bytes(&bytes[HEADER..]).map_err(|_| invalid())?;
        Ok(Some(Self { coins, blocks, node }))
    }
}

fn read_node(state: &HypergraphState, application: &[u8; 32], level: u8, index: u64) -> Result<Option<TreeNode>> {
    if level > LEVELS || index >= 1u64 << (LEVELS - level) {
        return Err(invalid());
    }
    match super::state::read_local(state, application, &node_address(level, index))? {
        Some(bytes) => TreeNode::decode(&bytes, level),
        None => Ok(None),
    }
}

/// The flat summary, while one is still stored in its place.
pub fn legacy_summary(state: &HypergraphState, application: &[u8; 32]) -> Result<Option<BlockSummary>> {
    match super::state::read_local(state, application, &BLOCK_SUMMARY_ADDRESS)? {
        Some(bytes) if bytes.as_slice() == MOVED => Ok(None),
        Some(bytes) => BlockSummary::decode(&bytes).map(Some),
        None => Ok(None),
    }
}

/// The top node: coins, non-empty blocks and the application root.
pub fn top(state: &HypergraphState, application: &[u8; 32]) -> Result<Option<TreeNode>> {
    read_node(state, application, LEVELS, 0)
}

/// The node over one shard's owned range in one width layer, at the report's
/// `(level, index)` counted from the coins (`shard_accumulator::subtree_position`).
pub fn subtree(state: &HypergraphState, application: &[u8; 32], level: usize, index: u64) -> Result<Option<TreeNode>> {
    let level = level.checked_sub(usize::from(SUBTREE_BITS)).ok_or_else(invalid)?;
    read_node(state, application, u8::try_from(level).map_err(|_| invalid())?, index)
}

/// Every stored node's position, walked down from the top: a node exists only
/// under a stored parent.
fn stored_positions(state: &HypergraphState, application: &[u8; 32]) -> Result<Vec<(u8, u64, TreeNode)>> {
    let mut found = Vec::new();
    let mut pending = vec![(LEVELS, 0u64)];
    while let Some((level, index)) = pending.pop() {
        let Some(node) = read_node(state, application, level, index)? else { continue };
        if level > 0 {
            pending.push((level - 1, (index << 1) | 1));
            pending.push((level - 1, index << 1));
        }
        found.push((level, index, node));
    }
    Ok(found)
}

/// Every non-empty block, `(block, coins, root)` ascending.
pub fn entries(state: &HypergraphState, application: &[u8; 32]) -> Result<Vec<(u64, u64, Node)>> {
    Ok(stored_positions(state, application)?
        .into_iter()
        .filter(|(level, _, _)| *level == 0)
        .map(|(_, block, leaf)| (block, leaf.coins, leaf.node))
        .collect())
}

/// Writes the tree: the membership key and the zero subtree of every level,
/// derived once per use.
pub struct SummaryTree<'a> {
    state: &'a HypergraphState,
    application: &'a [u8; 32],
    key: MembershipKey,
    /// `zeros[l]`: the zero subtree `l` levels above the coins.
    zeros: Vec<Node>,
}

impl<'a> SummaryTree<'a> {
    pub fn new(state: &'a HypergraphState, context: &[u8; 32], application: &'a [u8; 32]) -> Self {
        let key = MembershipKey::derive(context);
        let mut zeros = vec![Node::zero()];
        for level in 0..usize::from(SUBTREE_BITS + LEVELS) {
            let next = key.parent(&zeros[level], &zeros[level]);
            zeros.push(next);
        }
        Self { state, application, key, zeros }
    }

    /// The application root: the top node, or the zero tree with no blocks.
    pub fn root(&self) -> Result<Node> {
        Ok(match top(self.state, self.application)? {
            Some(top) => top.node,
            None => self.zeros[usize::from(SUBTREE_BITS + LEVELS)].clone(),
        })
    }

    fn read(&self, level: u8, index: u64) -> Result<Option<TreeNode>> {
        read_node(self.state, self.application, level, index)
    }

    /// Stores `node`, which differs from what is stored there.
    fn write(&self, level: u8, index: u64, node: Option<&TreeNode>) -> Result<()> {
        let bytes = node.map(TreeNode::encode).unwrap_or_else(|| CLEARED.to_vec());
        super::state::write_local(self.state, self.application, &node_address(level, index), bytes);
        Ok(())
    }

    /// The parent of two children at `level`; absent when both are.
    fn parent(&self, level: u8, left: Option<&TreeNode>, right: Option<&TreeNode>) -> Result<Option<TreeNode>> {
        if left.is_none() && right.is_none() {
            return Ok(None);
        }
        let zero = &self.zeros[usize::from(SUBTREE_BITS + level)];
        let sum = |field: fn(&TreeNode) -> u64| {
            left.map_or(0, field).checked_add(right.map_or(0, field)).ok_or_else(invalid)
        };
        Ok(Some(TreeNode {
            coins: sum(|node| node.coins)?,
            blocks: sum(|node| node.blocks)?,
            node: self.key.parent(
                left.map_or(zero, |node| &node.node),
                right.map_or(zero, |node| &node.node),
            ),
        }))
    }

    fn leaf_level(leaves: &[(u64, u64, Node)]) -> Result<BTreeMap<u64, Option<TreeNode>>> {
        let mut level = BTreeMap::new();
        for (block, coins, root) in leaves {
            if *block >= 1u64 << LEVELS {
                return Err(invalid());
            }
            let leaf = (*coins > 0).then(|| TreeNode { coins: *coins, blocks: 1, node: root.clone() });
            if level.insert(*block, leaf).is_some() {
                return Err(invalid());
            }
        }
        Ok(level)
    }

    fn check_cap(&self) -> Result<()> {
        match top(self.state, self.application)? {
            Some(top) if usize::try_from(top.blocks).map_or(true, |blocks| blocks > MAX_NONEMPTY_BLOCKS) => Err(invalid()),
            _ => Ok(()),
        }
    }

    /// Set these blocks' `(coins, root)` and rewrite their ancestors. Blocks
    /// not named keep their stored leaves.
    pub fn update(&self, leaves: &[(u64, u64, Node)]) -> Result<()> {
        let mut changed = BTreeMap::new();
        for (block, leaf) in Self::leaf_level(leaves)? {
            if self.read(0, block)? != leaf {
                changed.insert(block, leaf);
            }
        }
        for level in 0..=LEVELS {
            for (index, node) in &changed {
                self.write(level, *index, node.as_ref())?;
            }
            if level == LEVELS {
                break;
            }
            let mut parents = BTreeMap::new();
            for parent in changed.keys().map(|index| index >> 1).collect::<BTreeSet<_>>() {
                let child = |index: u64| match changed.get(&index) {
                    Some(node) => Ok(node.clone()),
                    None => self.read(level, index),
                };
                let (left, right) = (child(parent << 1)?, child((parent << 1) | 1)?);
                let node = self.parent(level, left.as_ref(), right.as_ref())?;
                if self.read(level + 1, parent)? != node {
                    parents.insert(parent, node);
                }
            }
            changed = parents;
        }
        self.check_cap()
    }

    /// Make the tree exactly these blocks: every other stored node is cleared.
    pub fn replace(&self, leaves: &[(u64, u64, Node)]) -> Result<()> {
        let stale: BTreeMap<(u8, u64), TreeNode> = stored_positions(self.state, self.application)?
            .into_iter()
            .map(|(level, index, node)| ((level, index), node))
            .collect();
        let mut kept = BTreeSet::new();
        let mut nodes: BTreeMap<u64, TreeNode> = Self::leaf_level(leaves)?
            .into_iter()
            .filter_map(|(block, leaf)| leaf.map(|leaf| (block, leaf)))
            .collect();
        for level in 0..=LEVELS {
            for (index, node) in &nodes {
                kept.insert((level, *index));
                if stale.get(&(level, *index)) != Some(node) {
                    self.write(level, *index, Some(node))?;
                }
            }
            if level == LEVELS {
                break;
            }
            let mut parents = BTreeMap::new();
            for parent in nodes.keys().map(|index| index >> 1).collect::<BTreeSet<_>>() {
                let (left, right) = (nodes.get(&(parent << 1)), nodes.get(&((parent << 1) | 1)));
                if let Some(node) = self.parent(level, left, right)? {
                    parents.insert(parent, node);
                }
            }
            nodes = parents;
        }
        for (level, index) in stale.keys().filter(|position| !kept.contains(position)) {
            self.write(*level, *index, None)?;
        }
        self.check_cap()
    }

    /// Replace a flat summary with its tree, once. Returns whether it did.
    pub fn upgrade(&self) -> Result<bool> {
        let Some(flat) = legacy_summary(self.state, self.application)? else { return Ok(false) };
        self.replace(&flat.blocks)?;
        super::state::write_local(self.state, self.application, &BLOCK_SUMMARY_ADDRESS, MOVED.to_vec());
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::coin_blocks::{self, INITIAL_BLOCK_BITS};
    use quil_lattice_ct::confidential::sharded_tree::fold_subtree_roots;

    fn mem_state() -> HypergraphState {
        HypergraphState::new(std::sync::Arc::new(quil_hypergraph::HypergraphCrdt::new(
            std::sync::Arc::new(quil_hypergraph::testing::MemStore::new()),
            std::sync::Arc::new(quil_types::crypto::NoopInclusionProver),
        )))
    }

    struct Rng(u64);
    impl Rng {
        fn below(&mut self, n: u64) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (self.0 >> 33) % n
        }
    }

    /// Distinct valid nodes standing in for block roots.
    fn block_roots(context: &[u8; 32], count: usize) -> Vec<Node> {
        let key = MembershipKey::derive(context);
        let mut node = Node::zero();
        (0..count).map(|_| { node = key.parent(&node, &Node::zero()); node.clone() }).collect()
    }

    fn fold(context: &[u8; 32], blocks: &BTreeMap<u64, (u64, Node)>) -> Node {
        let roots: Vec<(u64, Node)> = blocks.iter().map(|(block, (_, root))| (*block, root.clone())).collect();
        fold_subtree_roots(context, coin_blocks::shape(INITIAL_BLOCK_BITS).unwrap(), &roots).unwrap()
    }

    fn leaves(blocks: &BTreeMap<u64, (u64, Node)>) -> Vec<(u64, u64, Node)> {
        blocks.iter().map(|(block, (coins, root))| (*block, *coins, root.clone())).collect()
    }

    fn assert_matches(state: &HypergraphState, context: &[u8; 32], application: &[u8; 32], blocks: &BTreeMap<u64, (u64, Node)>) {
        let tree = SummaryTree::new(state, context, application);
        assert_eq!(tree.root().unwrap(), fold(context, blocks), "the tree root is the fold of its blocks");
        let top = top(state, application).unwrap();
        assert_eq!(top.as_ref().map_or(0, |top| top.coins), blocks.values().map(|(coins, _)| coins).sum::<u64>());
        assert_eq!(top.as_ref().map_or(0, |top| top.blocks), blocks.len() as u64);
        assert_eq!(entries(state, application).unwrap(), leaves(blocks));
    }

    /// Blocks arrive width by width, as an application grows, and existing
    /// blocks gain coins; after every refresh the stored root is the fold of
    /// every block root, and the coin and block counts are the sums.
    #[test]
    fn the_root_is_the_fold_of_the_blocks_across_growth() {
        let state = mem_state();
        let (context, application) = ([5u8; 32], [6u8; 32]);
        let tree = SummaryTree::new(&state, &context, &application);
        let roots = block_roots(&context, 64);
        let mut rng = Rng(7);
        let mut blocks: BTreeMap<u64, (u64, Node)> = BTreeMap::new();
        assert_matches(&state, &context, &application, &blocks);
        for (round, width) in [6u8, 6, 7, 8, 8, 11, 15, 15].into_iter().enumerate() {
            let mut changed = BTreeMap::new();
            for _ in 0..4 {
                let block = coin_blocks::block_id(width, rng.below(1 << width)).unwrap();
                let coins = blocks.get(&block).map_or(0, |(coins, _)| *coins) + 1 + rng.below(50);
                changed.insert(block, (coins, roots[rng.below(64) as usize].clone()));
            }
            // An existing block gains coins too.
            if let Some((&block, (coins, _))) = blocks.iter().nth(rng.below(blocks.len().max(1) as u64) as usize) {
                changed.insert(block, (coins + 3, roots[rng.below(64) as usize].clone()));
            }
            tree.update(&leaves(&changed)).unwrap();
            blocks.extend(changed);
            assert_matches(&state, &context, &application, &blocks);
            if round % 2 == 1 {
                state.commit().unwrap();
                state.abort();
                assert_matches(&state, &context, &application, &blocks);
            }
        }
        // Rebuilt from scratch, the same blocks store the same records.
        let rebuilt = mem_state();
        SummaryTree::new(&rebuilt, &context, &application).replace(&leaves(&blocks)).unwrap();
        assert_eq!(stored_positions(&rebuilt, &application).unwrap(), stored_positions(&state, &application).unwrap(),
            "an incremental history stores exactly what a rebuild of its blocks stores");
    }

    /// A refresh that names only unchanged blocks writes nothing.
    #[test]
    fn an_unchanged_refresh_writes_nothing() {
        let state = mem_state();
        let (context, application) = ([5u8; 32], [6u8; 32]);
        let tree = SummaryTree::new(&state, &context, &application);
        let roots = block_roots(&context, 3);
        let blocks: BTreeMap<u64, (u64, Node)> =
            [(64, (2, roots[0].clone())), (65, (1, roots[1].clone())), (300, (4, roots[2].clone()))].into();
        tree.update(&leaves(&blocks)).unwrap();
        state.commit().unwrap();
        state.abort();
        tree.update(&leaves(&blocks)).unwrap();
        assert_eq!(state.changeset_len(), 0);
    }

    /// A rebuild that no longer holds a block clears it and every ancestor
    /// left without blocks; a cleared range can fill again.
    #[test]
    fn a_rebuild_clears_what_it_no_longer_holds() {
        let state = mem_state();
        let (context, application) = ([5u8; 32], [6u8; 32]);
        let tree = SummaryTree::new(&state, &context, &application);
        let roots = block_roots(&context, 4);
        let kept: BTreeMap<u64, (u64, Node)> = [(64, (2, roots[0].clone())), (200, (3, roots[1].clone()))].into();
        let mut all = kept.clone();
        all.extend([(127u64, (1u64, roots[2].clone())), (40_000, (9, roots[3].clone()))]);
        tree.replace(&leaves(&all)).unwrap();
        assert_matches(&state, &context, &application, &all);
        state.commit().unwrap();
        state.abort();

        tree.replace(&leaves(&kept)).unwrap();
        assert_matches(&state, &context, &application, &kept);
        let fresh = mem_state();
        SummaryTree::new(&fresh, &context, &application).replace(&leaves(&kept)).unwrap();
        assert_eq!(stored_positions(&state, &application).unwrap(), stored_positions(&fresh, &application).unwrap());
        state.commit().unwrap();
        state.abort();
        assert_eq!(super::super::state::read_local(&state, &application, &node_address(0, 40_000)).unwrap(),
            Some(CLEARED.to_vec()), "a cleared leaf is rewritten, not removed");

        tree.update(&leaves(&[(40_000u64, (11u64, roots[3].clone()))].into())).unwrap();
        let mut again = kept.clone();
        again.insert(40_000, (11, roots[3].clone()));
        assert_matches(&state, &context, &application, &again);
    }

    /// A refresh that is abandoned with its changeset leaves the committed
    /// tree as it was.
    #[test]
    fn an_aborted_changeset_leaves_the_tree_as_it_was() {
        let state = mem_state();
        let (context, application) = ([5u8; 32], [6u8; 32]);
        let tree = SummaryTree::new(&state, &context, &application);
        let roots = block_roots(&context, 2);
        let blocks: BTreeMap<u64, (u64, Node)> = [(70, (5, roots[0].clone()))].into();
        tree.update(&leaves(&blocks)).unwrap();
        state.commit().unwrap();
        state.abort();
        tree.update(&leaves(&[(70u64, (6u64, roots[1].clone())), (9_000, (1, roots[1].clone()))].into())).unwrap();
        state.abort();
        assert_matches(&state, &context, &application, &blocks);
    }

    /// State written before the tree holds a flat summary. Every read uses it
    /// until the first refresh converts it, once, into the same root.
    #[test]
    fn a_flat_summary_is_read_until_converted_once() {
        let state = mem_state();
        let (network, application) = ([8u8; 32], [9u8; 32]);
        let context = quil_lattice_ct::confidential::transfer::parameter_context(&network, &application);
        let disc = vertex_adds_discriminator().unwrap();
        let roots = block_roots(&context, 3);
        let blocks: BTreeMap<u64, (u64, Node)> =
            [(64, (2, roots[0].clone())), (130, (7, roots[1].clone())), (1_000, (1, roots[2].clone()))].into();
        let mut flat = BlockSummary::default();
        for (block, (coins, root)) in &blocks {
            flat.put(*block, *coins, root.clone()).unwrap();
        }
        state.set(&application, &BLOCK_SUMMARY_ADDRESS, &disc, 0, flat.encode()).unwrap();
        state.commit().unwrap();
        state.abort();

        let before = super::super::roots::fold_application_root(&state, &network, &application).unwrap();
        assert_eq!(before, fold(&context, &blocks));
        assert_eq!(super::super::roots::summary_coins(&state, &application).unwrap(), 10);
        assert!(top(&state, &application).unwrap().is_none());

        let tree = SummaryTree::new(&state, &context, &application);
        assert!(tree.upgrade().unwrap());
        assert_eq!(super::super::state::read_local(&state, &application, &BLOCK_SUMMARY_ADDRESS).unwrap().as_deref(), Some(MOVED.as_slice()));
        assert!(!tree.upgrade().unwrap(), "a converted summary is not converted again");
        assert_matches(&state, &context, &application, &blocks);
        assert_eq!(super::super::roots::fold_application_root(&state, &network, &application).unwrap(), before);
        assert_eq!(super::super::roots::summary_coins(&state, &application).unwrap(), 10);
        assert_eq!(super::super::roots::block_summary(&state, &application).unwrap().blocks, leaves(&blocks));
    }

    /// The tree keeps the flat summary's block cap.
    #[test]
    fn the_tree_refuses_more_blocks_than_the_cap() {
        let state = mem_state();
        let (context, application) = ([5u8; 32], [6u8; 32]);
        let root = block_roots(&context, 1).remove(0);
        let mut blocks: Vec<(u64, u64, Node)> = (1024..2048).map(|block| (block, 1, root.clone())).collect();
        SummaryTree::new(&state, &context, &application).replace(&blocks).unwrap();
        blocks.push((2048, 1, root));
        assert!(SummaryTree::new(&state, &context, &application).replace(&blocks).is_err());
    }

    /// The records sit exactly where [`node_address`] puts them, apart from
    /// every other accumulator record, and wallet scans pass over them.
    #[test]
    fn tree_records_are_accumulator_records_of_their_own() {
        use super::super::state::{self, block_record_address};
        for (level, index) in [(0u8, 64u64), (0, 65_535), (5, 2_047), (LEVELS, 0)] {
            let address = node_address(level, index);
            assert!(is_node_address(&address));
            assert!(state::is_accumulator_record(&address));
        }
        let mut outside = node_address(LEVELS, 0);
        outside[31] = 1;
        assert!(!is_node_address(&outside), "the top level has one node");
        let mut deeper = node_address(0, 64);
        deeper[24] = LEVELS + 1;
        assert!(!is_node_address(&deeper));
        let mut unfilled = node_address(3, 9);
        unfilled[27] = 0;
        assert!(!is_node_address(&unfilled));
        for address in [state::ROOT_ADDRESS, state::FRONTIER_ADDRESS, state::SHAPE_ADDRESS, BLOCK_SUMMARY_ADDRESS,
            block_record_address(state::BLOCK_ROOT_TAG, coin_blocks::block_id(15, (1 << 15) - 1).unwrap())]
        {
            assert!(!is_node_address(&address));
        }
    }
}

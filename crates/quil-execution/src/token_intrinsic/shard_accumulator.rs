//! A shard's report of its part of the coin accumulator, and the application
//! root folded from every shard's report.
//!
//! A shard holding the addresses under bit path `p` owns every block whose path
//! begins with `p`. In one width layer those blocks form exactly one subtree of
//! the accumulator, so the shard reports one node per layer — never a node per
//! block, which matters because a node is 4,864 bytes. The global materializer
//! places each report at its position and folds them into the application
//! root; shards at different depths simply report nodes at different levels.
//!
//! Layout of a report (the app-shard header's `accumulator` field):
//!
//! ```text
//! version(8) ‖ parameter_context(32) ‖ layers(1) ‖ layers × { width(1) ‖ coins(8 BE) ‖ root(NODE_BYTES) }
//! ```
//!
//! Widths strictly ascending, every layer non-empty. A shard with no coins
//! sends no report (the empty field). The parameter context is carried so the
//! global writer needs no network configuration, as settlement entries do.
//!
//! From the orphan re-placement frame (`global_commit::orphan_replacement_frame`)
//! a report may also attest the blocks whose records the shard holds but which
//! it is too deep to own (version 2; see [`BlockAttestation`]):
//!
//! ```text
//! version(8) ‖ context(32) ‖ layers(1) ‖ layers × {…} ‖ attestations(1) ‖ attestations × { block(8) ‖ coins(8) ‖ escrows(8) }
//! ```
//!
//! A report without attestations keeps version 1, byte for byte.
use super::coin_blocks;
use crate::hypergraph_state::HypergraphState;
use quil_lattice_ct::confidential::{
    relation::membership::{Node, NODE_BYTES},
    sharded_tree,
    transfer::parameter_context,
};
use quil_types::error::{QuilError, Result};
use std::collections::BTreeMap;

pub const REPORT_VERSION: &[u8; 8] = b"QCT3AR\0\x01";
/// A report carrying block attestations.
pub const ATTESTING_REPORT_VERSION: &[u8; 8] = b"QCT3AR\0\x02";
/// Bytes of one width layer in a report.
pub const LAYER_BYTES: usize = 1 + 8 + NODE_BYTES;
const ATTESTATION_BYTES: usize = 8 + 8 + 8;
/// Width layers a report can hold: one per block width the accumulator allows.
pub const MAX_LAYERS: usize = (coin_blocks::MAX_BLOCK_BITS - coin_blocks::INITIAL_BLOCK_BITS + 1) as usize;
/// Longest a report can be. A shard attests at most one block per width.
pub const MAX_REPORT_BYTES: usize = 8 + 32 + 1 + MAX_LAYERS * LAYER_BYTES + 1 + MAX_LAYERS * ATTESTATION_BYTES;

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("accumulator report: {message}"))
}

/// One width layer of a shard's part of the accumulator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubtreeReport {
    pub width: u8,
    pub coins: u64,
    pub root: Node,
}

/// What a shard holds of a block on its own path that it is too deep to own:
/// the coins and escrows delivered there. The shard holding a block's records
/// never owns it, so in its lineage these counts are final, and GLOBAL
/// re-places whatever else was committed to an orphaned block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockAttestation {
    pub block: u64,
    pub coins: u64,
    pub escrows: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardReport {
    pub context: [u8; 32],
    pub subtrees: Vec<SubtreeReport>,
    /// Ascending by block; empty before the orphan re-placement frame.
    pub attestations: Vec<BlockAttestation>,
}

impl ShardReport {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(8 + 32 + 1 + self.subtrees.len() * LAYER_BYTES);
        bytes.extend_from_slice(if self.attestations.is_empty() { REPORT_VERSION } else { ATTESTING_REPORT_VERSION });
        bytes.extend_from_slice(&self.context);
        bytes.push(self.subtrees.len() as u8);
        for subtree in &self.subtrees {
            bytes.push(subtree.width);
            bytes.extend_from_slice(&subtree.coins.to_be_bytes());
            bytes.extend_from_slice(&subtree.root.to_bytes());
        }
        if !self.attestations.is_empty() {
            bytes.push(self.attestations.len() as u8);
            for attestation in &self.attestations {
                bytes.extend_from_slice(&attestation.block.to_be_bytes());
                bytes.extend_from_slice(&attestation.coins.to_be_bytes());
                bytes.extend_from_slice(&attestation.escrows.to_be_bytes());
            }
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let attesting = bytes.get(..8) == Some(ATTESTING_REPORT_VERSION.as_slice());
        if bytes.len() < 8 + 32 + 1 || bytes.len() > MAX_REPORT_BYTES || (&bytes[..8] != REPORT_VERSION && !attesting) {
            return Err(invalid("malformed envelope"));
        }
        let context: [u8; 32] = bytes[8..40].try_into().unwrap();
        let layers = usize::from(bytes[40]);
        let layers_end = 41 + layers * LAYER_BYTES;
        let attestations = if attesting {
            let count = usize::from(*bytes.get(layers_end).ok_or_else(|| invalid("length does not match its layer count"))?);
            if count == 0 || bytes.len() != layers_end + 1 + count * ATTESTATION_BYTES {
                return Err(invalid("length does not match its attestation count"));
            }
            bytes[layers_end + 1..]
                .chunks_exact(ATTESTATION_BYTES)
                .map(|entry| BlockAttestation {
                    block: u64::from_be_bytes(entry[..8].try_into().unwrap()),
                    coins: u64::from_be_bytes(entry[8..16].try_into().unwrap()),
                    escrows: u64::from_be_bytes(entry[16..].try_into().unwrap()),
                })
                .collect()
        } else {
            if bytes.len() != layers_end {
                return Err(invalid("length does not match its layer count"));
            }
            Vec::new()
        };
        let subtrees = bytes[41..layers_end]
            .chunks_exact(LAYER_BYTES)
            .map(|layer| {
                Ok(SubtreeReport {
                    width: layer[0],
                    coins: u64::from_be_bytes(layer[1..9].try_into().unwrap()),
                    root: Node::from_bytes(&layer[9..]).map_err(|_| invalid("malformed root"))?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let report = Self { context, subtrees, attestations };
        report.validate()?;
        Ok(report)
    }

    fn validate(&self) -> Result<()> {
        if (self.subtrees.is_empty() && self.attestations.is_empty()) || self.subtrees.len() > MAX_LAYERS {
            return Err(invalid("a report carries 1..=MAX_LAYERS layers, or only attestations"));
        }
        if self.attestations.len() > MAX_LAYERS
            || self.attestations.windows(2).any(|pair| pair[0].block >= pair[1].block)
            || self.attestations.iter().any(|a| !coin_blocks::is_allocated_width(coin_blocks::MAX_BLOCK_BITS, a.block))
        {
            return Err(invalid("attestations name distinct valid blocks in ascending order"));
        }
        if self.subtrees.windows(2).any(|pair| pair[0].width >= pair[1].width) {
            return Err(invalid("layers must be in strictly ascending width"));
        }
        if self.subtrees.iter().any(|subtree| {
            subtree.coins == 0
                || !(coin_blocks::INITIAL_BLOCK_BITS..=coin_blocks::MAX_BLOCK_BITS).contains(&subtree.width)
        }) {
            return Err(invalid("every layer holds coins at a valid width"));
        }
        Ok(())
    }
}

pub use super::accumulator_header::{header_carries, report_digest, HEARTBEAT_FRAMES};

/// Where a shard's subtree sits in the accumulator: `(level, index)`, counted
/// from the leaves. The shard with bit path `p` (d bits) owns the width-`w`
/// blocks `(1 << w) | p‖x`, which are exactly the subtree at level
/// `SUBTREE_BITS + (w - d)` with index `(1 << d) | p`.
///
/// A shard deeper than a layer's width would own PART of a block, which the
/// accumulator cannot express; that layer is refused, not folded.
pub fn subtree_position(width: u8, shard: &[bool]) -> Result<(usize, u64)> {
    let depth = shard.len();
    if !(coin_blocks::INITIAL_BLOCK_BITS..=coin_blocks::MAX_BLOCK_BITS).contains(&width) {
        return Err(invalid("width outside the accumulator's range"));
    }
    if depth > usize::from(width) {
        return Err(invalid("a shard deeper than a layer's width owns part of a block"));
    }
    let path = shard.iter().fold(0u64, |acc, bit| (acc << 1) | u64::from(*bit));
    Ok((
        usize::from(coin_blocks::SUBTREE_BITS) + usize::from(width) - depth,
        (1u64 << depth) | path,
    ))
}

/// The attestations of `shard`: every block on its own path narrower than
/// it whose records it holds, with the coins and escrows delivered there.
/// Zero counts are listed, since a zero is an attestation too. `read` returns
/// one of the application's records by address.
fn attestations(
    context: &[u8; 32],
    shard: &[bool],
    mut read: impl FnMut(&[u8; 32]) -> Result<Option<Vec<u8>>>,
) -> Result<Vec<BlockAttestation>> {
    use super::state::{block_record_address, BLOCK_ESCROW_COUNT_TAG, BLOCK_FRONTIER_TAG};
    let top = shard.len().min(usize::from(coin_blocks::MAX_BLOCK_BITS) + 1);
    let mut held = Vec::new();
    for width in usize::from(coin_blocks::INITIAL_BLOCK_BITS)..top {
        let path = shard[..width].iter().fold(0u64, |acc, bit| (acc << 1) | u64::from(*bit));
        let block = coin_blocks::block_id(width as u8, path)?;
        if !super::global_commit::holds_block_records(shard, block) {
            continue;
        }
        let coins = match read(&block_record_address(BLOCK_FRONTIER_TAG, block))? {
            Some(bytes) => quil_lattice_ct::confidential::coin_tree::Frontier::decode(
                &bytes, context, usize::from(coin_blocks::SUBTREE_BITS),
            )
            .map_err(|_| invalid("malformed block frontier"))?
            .count(),
            None => 0,
        };
        let escrows = match read(&block_record_address(BLOCK_ESCROW_COUNT_TAG, block))? {
            Some(bytes) => u64::from_be_bytes(bytes.as_slice().try_into().map_err(|_| invalid("malformed escrow count"))?),
            None => 0,
        };
        held.push(BlockAttestation { block, coins, escrows });
    }
    Ok(held)
}

/// This shard's report from committed state, or `None` when it holds no coins
/// and attests nothing. `attest`: whether the frame is at or past the orphan
/// re-placement frame (`global_commit::orphan_replacement_frame`).
///
/// Reads the application's block summary: per width layer, the stored tree
/// node over the shard's owned range (a flat summary, while one is stored,
/// is folded as before).
pub fn shard_report(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    shard: &[bool],
    attest: bool,
) -> Result<Option<ShardReport>> {
    let context = parameter_context(network, application);
    let attestations = if attest {
        let disc = crate::hypergraph_state::vertex_adds_discriminator()?;
        attestations(&context, shard, |address| state.get(application, address, &disc))?
    } else {
        Vec::new()
    };
    if let Some(flat) = super::summary_tree::legacy_summary(state, application)? {
        return report_from_summary(context, shard, &flat, attestations);
    }
    // A shard's owned range inside one width layer is an aligned subtree of
    // the block id tree, so each layer's report is one stored node: the same
    // root and coins `report_from_summary` folds from the layer's blocks.
    let mut subtrees = Vec::new();
    for width in coin_blocks::INITIAL_BLOCK_BITS..=coin_blocks::MAX_BLOCK_BITS {
        if shard.len() > usize::from(width) {
            continue;
        }
        let (level, index) = subtree_position(width, shard)?;
        if let Some(node) = super::summary_tree::subtree(state, application, level, index)? {
            subtrees.push(SubtreeReport { width, coins: node.coins, root: node.node });
        }
    }
    if subtrees.is_empty() && attestations.is_empty() {
        return Ok(None);
    }
    Ok(Some(ShardReport { context, subtrees, attestations }))
}

/// Derive a report exclusively from the same committed snapshot as the
/// caller's cursor and phase roots. This does not use or repair the private
/// summary and never reads staged/live blobs while recovering old history.
pub fn snapshot_report(
    snapshot: &dyn quil_types::store::SnapshotReadable,
    network: &[u8; 32],
    application: &[u8; 32],
    shard: &[bool],
    attest: bool,
) -> Result<Option<ShardReport>> {
    if !snapshot.has_snapshot_vertex_reads() {
        return Err(QuilError::ExecutionUnavailable("accumulator recovery needs isolated vertex reads".into()));
    }
    let context = parameter_context(network, application);
    let key = quil_types::store::ShardKey {
        l1: quil_hypergraph::addressing::get_bloom_filter_indices(application, 256, 3),
        l2: *application,
    };
    let read = |address: &[u8; 32]| -> Result<Option<Vec<u8>>> {
        let id = [application.as_slice(), address.as_slice()].concat();
        if snapshot.load_vertex_underlying_raw("vertex", "removes", &key, &id)?.is_some() {
            return Ok(None);
        }
        Ok(snapshot.load_vertex_underlying_raw("vertex", "adds", &key, &id)?.filter(|v| !v.is_empty()))
    };
    let summary = super::roots::block_summary_from_records(&context, shard, read)?;
    let attestations = if attest { attestations(&context, shard, read)? } else { Vec::new() };
    report_from_summary(context, shard, &summary, attestations)
}

fn report_from_summary(
    context: [u8; 32],
    shard: &[bool],
    summary: &super::roots::BlockSummary,
    attestations: Vec<BlockAttestation>,
) -> Result<Option<ShardReport>> {
    let mut layers: BTreeMap<u8, Vec<(u64, u64, Node)>> = BTreeMap::new();
    for (block, coins, root) in &summary.blocks {
        if *coins > 0 && coin_blocks::shard_owns_block(shard, *block) {
            layers
                .entry(coin_blocks::creation_width(*block))
                .or_default()
                .push((*block, *coins, root.clone()));
        }
    }
    let mut subtrees = Vec::with_capacity(layers.len());
    for (width, blocks) in layers {
        let (level, index) = subtree_position(width, shard)?;
        let block_level = usize::from(coin_blocks::SUBTREE_BITS);
        let first_block = index << (level - block_level);
        let nodes: Vec<(usize, u64, Node)> = blocks
            .iter()
            .map(|(block, _, root)| (block_level, block - first_block, root.clone()))
            .collect();
        // A shard exactly as deep as the layer's width owns one block, and its
        // subtree is that block: its root is the block root, with nothing to
        // fold (and a fold to a node's own level is refused). The first shard
        // ever to reach seven bits hit this and could report nothing.
        let root = if level == block_level {
            match nodes.as_slice() {
                [(_, 0, root)] => root.clone(),
                _ => return Err(invalid("a one-block subtree holds exactly its block")),
            }
        } else {
            sharded_tree::fold_sparse(&context, level, &nodes)
                .map_err(|e| invalid(&format!("fold: {e:?}")))?
        };
        let coins = blocks.iter().try_fold(0u64, |total, (_, coins, _)| {
            total.checked_add(*coins).ok_or_else(|| invalid("coin count overflow"))
        })?;
        subtrees.push(SubtreeReport { width, coins, root });
    }
    if subtrees.is_empty() && attestations.is_empty() {
        return Ok(None);
    }
    Ok(Some(ShardReport { context, subtrees, attestations }))
}

/// The application root from its shards' subtrees: `(width, shard path, root)`
/// each. Subtrees must not overlap; an absent one folds as zeros.
pub fn fold_application_root(context: &[u8; 32], subtrees: &[(u8, Vec<bool>, Node)]) -> Result<Node> {
    let nodes = subtrees
        .iter()
        .map(|(width, shard, root)| {
            let (level, index) = subtree_position(*width, shard)?;
            Ok((level, index, root.clone()))
        })
        .collect::<Result<Vec<_>>>()?;
    sharded_tree::fold_sparse(context, usize::from(coin_blocks::DEPTH), &nodes)
        .map_err(|e| invalid(&format!("fold: {e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypergraph_state::vertex_adds_discriminator;
    use quil_lattice_ct::confidential::{
        relation::membership::IDENTITY_BYTES, transfer::Output, AmountOpening, CommitmentKey,
    };

    fn mem_state() -> HypergraphState {
        HypergraphState::new(std::sync::Arc::new(quil_hypergraph::HypergraphCrdt::new(
            std::sync::Arc::new(quil_hypergraph::testing::MemStore::new()),
            std::sync::Arc::new(quil_types::crypto::NoopInclusionProver),
        )))
    }

    /// The property cross-shard commit rests on: however the application is
    /// partitioned into shards, folding their reports gives the root the
    /// accumulator itself publishes.
    #[test]
    fn reports_from_any_partition_fold_to_the_published_root() {
        let state = mem_state();
        let (network, application) = ([31u8; 32], [32u8; 32]);
        let context = parameter_context(&network, &application);
        let limits = super::super::state::SnapshotLimits { max_coins: 64, max_depth: 32, max_nodes: 1 << 16 };
        let disc = vertex_adds_discriminator().unwrap();
        let key = CommitmentKey::derive(&context);
        let mut staged = BTreeMap::new();
        for seed in 1..=24u8 {
            let output = Output {
                owner: [seed; IDENTITY_BYTES],
                commitment: key.commit(u128::from(seed), &AmountOpening::from_seed(&context, &[seed; 32])),
                memo: [seed; 1115],
            };
            let (address, tree) = super::super::roots::stage_coin(
                &state, &network, &application, &context, 1, &output, &mut staged, limits,
            )
            .unwrap();
            state
                .set(&application, &address, &disc, 1, quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap())
                .unwrap();
        }
        let published = super::super::roots::refresh_root(&state, &network, &application, limits).unwrap();

        // Partitions: the whole application, halves, quarters, and a deep split
        // with its spine (prefix-free and complete).
        let partitions: Vec<Vec<Vec<bool>>> = vec![
            vec![vec![]],
            vec![vec![false], vec![true]],
            vec![vec![false, false], vec![false, true], vec![true, false], vec![true, true]],
            vec![vec![true], vec![false, true], vec![false, false, false], vec![false, false, true]],
        ];
        for shards in partitions {
            let mut subtrees = Vec::new();
            let mut coins = 0;
            for shard in &shards {
                let Some(report) = shard_report(&state, &network, &application, shard, false).unwrap() else { continue };
                // A report round-trips through its header encoding.
                assert_eq!(ShardReport::decode(&report.encode().unwrap()).unwrap(), report);
                assert_eq!(report.context, context);
                for subtree in report.subtrees {
                    coins += subtree.coins;
                    subtrees.push((subtree.width, shard.clone(), subtree.root));
                }
            }
            assert_eq!(coins, published.coins, "{shards:?} accounts for every coin");
            assert_eq!(
                fold_application_root(&context, &subtrees).unwrap(),
                published.root,
                "{shards:?} folds to the published root"
            );
        }
    }

    #[test]
    fn reports_are_canonical_and_positions_are_exact() {
        let context = [5u8; 32];
        let root = Node::from_bytes(&[0u8; NODE_BYTES]).unwrap();
        let report = ShardReport {
            context,
            subtrees: vec![
                SubtreeReport { width: 6, coins: 3, root: root.clone() },
                SubtreeReport { width: 8, coins: 1, root: root.clone() },
            ],
            attestations: Vec::new(),
        };
        let bytes = report.encode().unwrap();
        assert_eq!(ShardReport::decode(&bytes).unwrap(), report);
        // Truncated, extended, unordered, empty or coinless layers are refused.
        assert!(ShardReport::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(ShardReport::decode(&extended).is_err());
        for bad in [
            ShardReport { subtrees: vec![report.subtrees[1].clone(), report.subtrees[0].clone()], ..report.clone() },
            ShardReport { subtrees: vec![], ..report.clone() },
            ShardReport { subtrees: vec![SubtreeReport { coins: 0, ..report.subtrees[0].clone() }], ..report.clone() },
            ShardReport { subtrees: vec![SubtreeReport { width: 5, ..report.subtrees[0].clone() }], ..report.clone() },
        ] {
            assert!(bad.encode().is_err());
        }
        // The whole application's width-6 layer is the node at level 22, index 1;
        // a one-bit shard's is one level down; a shard deeper than the width is
        // refused.
        assert_eq!(subtree_position(6, &[]).unwrap(), (22, 1));
        assert_eq!(subtree_position(6, &[true]).unwrap(), (21, 3));
        assert_eq!(subtree_position(6, &[false, true, true, false, false, true]).unwrap(), (16, 0b1_011001));
        assert!(subtree_position(6, &[true; 7]).is_err());
    }

    /// Each layer of a report is one stored tree node, and it is exactly what
    /// the flat summary's fold gives for every shard, whole, split, deep or
    /// deeper than a layer.
    #[test]
    fn a_report_from_the_tree_is_the_report_from_the_flat_summary() {
        use super::super::roots::BlockSummary;
        use super::super::summary_tree::SummaryTree;
        use quil_lattice_ct::confidential::relation::membership::MembershipKey;
        let (network, application) = ([12u8; 32], [13u8; 32]);
        let context = parameter_context(&network, &application);
        let key = MembershipKey::derive(&context);
        let mut root = Node::zero();
        let mut flat = BlockSummary::default();
        for (seed, (width, path)) in [(6u8, 0u64), (6, 1), (6, 45), (7, 3), (8, 0), (8, 255), (9, 130), (12, 7)]
            .into_iter()
            .enumerate()
        {
            root = key.parent(&root, &Node::zero());
            flat.put(coin_blocks::block_id(width, path).unwrap(), 1 + seed as u64, root.clone()).unwrap();
        }
        let tree_state = mem_state();
        SummaryTree::new(&tree_state, &context, &application).replace(&flat.blocks).unwrap();
        let flat_state = mem_state();
        flat_state.set(&application, &super::super::state::BLOCK_SUMMARY_ADDRESS, &vertex_adds_discriminator().unwrap(),
            0, flat.encode()).unwrap();
        let bits = |text: &str| text.chars().map(|c| c == '1').collect::<Vec<bool>>();
        for shard in ["", "0", "1", "00", "000000", "000001", "0000000", "00000000", "101101", "1111111", "000000000111"] {
            let shard = bits(shard);
            let expected = report_from_summary(context, &shard, &flat, Vec::new()).unwrap();
            assert_eq!(shard_report(&tree_state, &network, &application, &shard, false).unwrap(), expected,
                "shard {shard:?}");
            assert_eq!(shard_report(&flat_state, &network, &application, &shard, false).unwrap(), expected,
                "a flat summary still reports as before");
        }
    }
}

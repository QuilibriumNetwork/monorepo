//! Coin root publication in the execution changeset. Writers must
//! serialize changeset mutation exactly as for coins.
//!
//! The accumulator is append-only: every staged coin carries its leaf
//! `position`, and a persisted [`Frontier`] at `FRONTIER_ADDRESS` lets each
//! operation extend the root in O(depth) per new coin instead of decoding and
//! rehashing the whole coin set. The first publication for an application (no
//! frontier yet) reconstructs from all live coins; `full_rebuild_root` remains
//! available as a cross-check (`QUIL_ACCUMULATOR_VERIFY=1` runs it on every
//! publication and fails on divergence).
use super::state::{decode_snapshot_coin, read_local, write_local, SnapshotLimits, FRONTIER_ADDRESS, ROOT_ADDRESS};
use quil_lattice_ct::confidential::relation::membership::{IDENTITY_BYTES, NODE_BYTES};
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
use quil_lattice_ct::confidential::{
    coin_tree::{CoinRecord, CoinTree, Frontier, RootRecord, ROOT_RECORD_BYTES},
    relation::membership::Node,
    transfer::parameter_context,
};
use quil_types::error::{QuilError, Result};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::collections::{BTreeMap, BTreeSet};

/// Root histories keep 32-byte digests of their root ids. With the 2,432-byte
/// ids themselves a full history outgrew a scan page.
const VERSION: &[u8; 8] = b"QCT3RH\0\x03";
/// The earlier encoding, holding the ids: still read, never written. The next
/// publication rewrites a history in [`VERSION`].
const VERSION_IDS: &[u8; 8] = b"QCT3RH\0\x02";
pub const HISTORY_LIMIT: usize = 128;
const ID_BYTES: usize = IDENTITY_BYTES;

fn invalid() -> QuilError {
    QuilError::InvalidArgument("coin root: invalid history record".into())
}
pub(crate) fn root_id(context: &[u8; 32], depth: u8, root: &Node) -> [u8; ID_BYTES] {
    let mut hash = Shake256::default();
    hash.update(b"quil/coin/root-history/v4\0");
    hash.update(context);
    hash.update(&[depth]);
    hash.update(&root.to_bytes());
    let mut id = [0; ID_BYTES];
    hash.finalize_xof().read(&mut id);
    id
}
struct History {
    current: RootRecord,
    /// [`root_digest`] of each retained root, oldest first; the last is
    /// `current`'s.
    digests: Vec<[u8; 32]>,
}
impl History {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = VERSION.to_vec();
        bytes.extend_from_slice(&self.current.encode().map_err(|_| invalid())?);
        bytes.extend_from_slice(&(self.digests.len() as u16).to_le_bytes());
        for digest in &self.digests {
            bytes.extend_from_slice(digest);
        }
        // Enforce the same invariants for locally constructed and stored data.
        Self::decode(&bytes, &self.current.context)?;
        Ok(bytes)
    }
    fn decode(bytes: &[u8], context: &[u8; 32]) -> Result<Self> {
        let end = 8 + ROOT_RECORD_BYTES;
        let entry = match bytes.get(..8) {
            Some(version) if version == VERSION.as_slice() => 32,
            Some(version) if version == VERSION_IDS.as_slice() => ID_BYTES,
            _ => return Err(invalid()),
        };
        if bytes.len() < end + 2 {
            return Err(invalid());
        }
        let count = u16::from_le_bytes(bytes[end..end + 2].try_into().unwrap()) as usize;
        if count == 0 || count > HISTORY_LIMIT || bytes.len() != end + 2 + count * entry {
            return Err(invalid());
        }
        let current = RootRecord::decode(&bytes[8..end], context).map_err(|_| invalid())?;
        let digests: Vec<[u8; 32]> = bytes[end + 2..]
            .chunks_exact(entry)
            .map(|chunk| match entry {
                32 => chunk.try_into().unwrap(),
                _ => id_digest(chunk.try_into().unwrap()),
            })
            .collect();
        if digests.iter().collect::<BTreeSet<_>>().len() != count
            || digests.last() != Some(&root_digest(context, current.depth, &current.root))
        {
            return Err(invalid());
        }
        Ok(Self { current, digests })
    }
    fn publish(&mut self, current: RootRecord) -> Result<()> {
        if current.context != self.current.context {
            return Err(invalid());
        }
        let digest = root_digest(&current.context, current.depth, &current.root);
        if self.digests.last() != Some(&digest) {
            self.digests.retain(|old| old != &digest);
            self.digests.push(digest);
            if self.digests.len() > HISTORY_LIMIT {
                self.digests.remove(0);
            }
        }
        self.current = current;
        Ok(())
    }
}

/// Publish `current` into an encoded root history, creating it when `existing`
/// is `None`. The same bounded, deduplicated history a shard keeps locally, so
/// the canonical application root the global materializer publishes is read
/// and checked exactly like a local one.
pub(crate) fn publish_history(existing: Option<&[u8]>, current: RootRecord) -> Result<Vec<u8>> {
    let mut history = match existing {
        Some(bytes) => History::decode(bytes, &current.context)?,
        None => History { current: current.clone(), digests: Vec::new() },
    };
    history.publish(current)?;
    history.encode()
}

/// A 32-byte digest of a root's history id: what a spend relay carries
/// instead of the root (4,864 bytes) or its id (3,648 bytes).
pub(crate) fn root_digest(context: &[u8; 32], depth: u8, root: &Node) -> [u8; 32] {
    id_digest(&root_id(context, depth, root))
}

fn id_digest(id: &[u8; ID_BYTES]) -> [u8; 32] {
    let mut hash = <sha3::Sha3_256 as sha3::Digest>::new();
    sha3::Digest::update(&mut hash, b"quil/commit/root-id/v1\0");
    sha3::Digest::update(&mut hash, id);
    sha3::Digest::finalize(hash).into()
}

/// Whether an encoded root history retains the root whose [`root_digest`] this
/// is. At most `HISTORY_LIMIT` digests are computed.
pub(crate) fn history_retains_digest(bytes: &[u8], context: &[u8; 32], digest: &[u8; 32]) -> Result<bool> {
    Ok(History::decode(bytes, context)?.digests.contains(digest))
}

/// Whether an encoded root history retains `root` at `depth`.
pub(crate) fn history_retains(bytes: &[u8], context: &[u8; 32], depth: u8, root: &Node) -> Result<bool> {
    let history = History::decode(bytes, context)?;
    Ok(history.digests.contains(&root_digest(context, depth, root)))
}

pub(crate) fn decode_current(bytes: &[u8], context: &[u8; 32]) -> Result<RootRecord> {
    History::decode(bytes, context).map(|history| history.current)
}

pub fn read_current(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
) -> Result<Option<RootRecord>> {
    let context = parameter_context(network, application);
    read_local(state, application, &ROOT_ADDRESS)?
        .map(|bytes| decode_current(&bytes, &context))
        .transpose()
}

/// Query locally retained roots. An absent record admits no roots. The caller
/// must combine this with proof and spent-image checks in serialized admission.
pub fn accepts_root(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    depth: u8,
    root: &Node,
) -> Result<bool> {
    if !(1..=32).contains(&depth) {
        return Ok(false);
    }
    let context = parameter_context(network, application);
    let Some(bytes) = read_local(state, application, &ROOT_ADDRESS)? else {
        return Ok(false);
    };
    Ok(History::decode(&bytes, &context)?
        .digests
        .contains(&root_digest(&context, depth, root)))
}

/// Every live coin record: committed store, live CRDT writes from preceding
/// messages, and the current changeset. This is the O(n) path; the underlying
/// live-leaf API collects blobs before applying coin/node caps, so those caps
/// do not bound its memory or I/O.
fn collect_live_records(
    state: &HypergraphState,
    context: &[u8; 32],
    application: &[u8; 32],
    limits: SnapshotLimits,
) -> Result<Vec<CoinRecord>> {
    let mut blobs = BTreeMap::new();
    for (key, blob) in state.crdt().collect_live_vertex_adds(application)? {
        if key.len() != 64 || &key[..32] != application {
            return Err(invalid());
        }
        blobs.insert(key, blob);
    }
    for (address, blob) in state.pending_vertex_adds(application)? {
        if address.len() != 32 {
            return Err(invalid());
        }
        let mut key = application.to_vec();
        key.extend_from_slice(&address);
        blobs.insert(key, blob);
    }
    let mut records = Vec::new();
    for (key, blob) in blobs {
        if let Some(record) = decode_snapshot_coin(context, application, &key, &blob)? {
            if records.len() >= limits.max_coins {
                return Err(invalid());
            }
            records.push(record);
        }
    }
    Ok(records)
}

fn load_frontier(
    state: &HypergraphState,
    context: &[u8; 32],
    application: &[u8; 32],
    limits: SnapshotLimits,
) -> Result<Option<Frontier>> {
    read_local(state, application, &FRONTIER_ADDRESS)?
        .map(|bytes| Frontier::decode(&bytes, context, limits.max_depth).map_err(|_| invalid()))
        .transpose()
}

/// Non-empty blocks one application may carry. A block appears only once it
/// holds a coin. The stored summary tree does not need the bound; the flat
/// summary it replaced, and the witness index's copy, still do.
pub const MAX_NONEMPTY_BLOCKS: usize = 1024;

/// Sorted `(block, coins, root)` for every non-empty block: the flat summary
/// record the stored tree (`summary_tree`) replaces, and the in-memory form
/// recovery builds from block records.
#[derive(Default)]
pub struct BlockSummary {
    pub blocks: Vec<(u64, u64, Node)>,
}

impl BlockSummary {
    const ENTRY: usize = 8 + 8 + NODE_BYTES;

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() % Self::ENTRY != 0 || bytes.len() / Self::ENTRY > MAX_NONEMPTY_BLOCKS {
            return Err(invalid());
        }
        let mut blocks = Vec::with_capacity(bytes.len() / Self::ENTRY);
        for entry in bytes.chunks_exact(Self::ENTRY) {
            let block = u64::from_be_bytes(entry[..8].try_into().unwrap());
            let coins = u64::from_be_bytes(entry[8..16].try_into().unwrap());
            let root = Node::from_bytes(&entry[16..]).map_err(|_| invalid())?;
            blocks.push((block, coins, root));
        }
        if blocks.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(invalid());
        }
        Ok(Self { blocks })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.blocks.len() * Self::ENTRY);
        for (block, coins, root) in &self.blocks {
            bytes.extend_from_slice(&block.to_be_bytes());
            bytes.extend_from_slice(&coins.to_be_bytes());
            bytes.extend_from_slice(&root.to_bytes());
        }
        bytes
    }

    pub fn put(&mut self, block: u64, coins: u64, root: Node) -> Result<()> {
        match self.blocks.binary_search_by_key(&block, |(id, _, _)| *id) {
            Ok(at) => self.blocks[at] = (block, coins, root),
            Err(at) => {
                if self.blocks.len() >= MAX_NONEMPTY_BLOCKS {
                    return Err(invalid());
                }
                self.blocks.insert(at, (block, coins, root));
            }
        }
        Ok(())
    }

    pub fn coins(&self) -> u64 {
        self.blocks.iter().map(|(_, coins, _)| *coins).sum()
    }

    /// Coins held by one block, zero for a block that has never held one.
    pub fn count(&self, block: u64) -> u64 {
        self.blocks
            .binary_search_by_key(&block, |(id, _, _)| *id)
            .map(|at| self.blocks[at].1)
            .unwrap_or(0)
    }

    /// One block's subtree root, absent for a block with no coins.
    pub fn root_of(&self, block: u64) -> Option<Node> {
        self.blocks
            .binary_search_by_key(&block, |(id, _, _)| *id)
            .map(|at| self.blocks[at].2.clone())
            .ok()
    }

    pub fn roots(&self) -> Vec<(u64, Node)> {
        self.blocks.iter().map(|(block, _, root)| (*block, root.clone())).collect()
    }
}

/// Every non-empty block of the application's summary, from the flat record
/// while one is stored, else from the tree's leaves. Reads every leaf: the
/// refresh, reports and coin count read single nodes instead.
pub fn block_summary(state: &HypergraphState, application: &[u8; 32]) -> Result<BlockSummary> {
    match super::summary_tree::legacy_summary(state, application)? {
        Some(flat) => Ok(flat),
        None => Ok(BlockSummary { blocks: super::summary_tree::entries(state, application)? }),
    }
}

/// Coins held across the application's summary.
pub fn summary_coins(state: &HypergraphState, application: &[u8; 32]) -> Result<u64> {
    match super::summary_tree::legacy_summary(state, application)? {
        Some(flat) => Ok(flat.coins()),
        None => Ok(super::summary_tree::top(state, application)?.map_or(0, |top| top.coins)),
    }
}

/// Rebuild a sub-shard's private summary from the block records inside its
/// authenticated range. Sync imports those records but cannot import the
/// private summary at the all-ones address. Inspect every permitted width:
/// the private width record may be absent or stale for the same reason.
///
/// This reads at most two records per owned block (65,472 possible blocks for
/// the whole application), retains at most MAX_NONEMPTY_BLOCKS entries and
/// never enumerates coins. Nothing is staged until all records agree.
pub fn rebuild_block_summary(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    shard: &[bool],
) -> Result<()> {
    let context = parameter_context(network, application);
    let disc = vertex_adds_discriminator()?;
    let summary = block_summary_from_records(&context, shard, |address| state.get(application, address, &disc))?;
    let flat = read_local(state, application, &super::state::BLOCK_SUMMARY_ADDRESS)?;
    // Empty non-token applications acquire no token metadata just because
    // their shard synced. An existing summary/root still needs correction
    // when the newly inherited range contains no blocks.
    if summary.blocks.is_empty()
        && flat.is_none()
        && super::summary_tree::top(state, application)?.is_none()
        && read_local(state, application, &ROOT_ADDRESS)?.is_none()
    {
        return Ok(());
    }
    // A flat summary is rebuilt flat: only `refresh_root`, which every member
    // executes at the same frame, converts. (While these records sat in the
    // tree, a member-local conversion changed one member's committed state;
    // they are node-local now, and the single conversion point stays.)
    if flat.as_ref().is_some_and(|flat| flat.as_slice() != super::summary_tree::MOVED) {
        let bytes = summary.encode();
        if flat.as_deref() != Some(bytes.as_slice()) {
            write_local(state, application, &super::state::BLOCK_SUMMARY_ADDRESS, bytes);
        }
        let shape = super::coin_blocks::shape(block_width(state, application)?)?;
        let root = quil_lattice_ct::confidential::sharded_tree::fold_subtree_roots(&context, shape, &summary.roots())
            .map_err(|_| invalid())?;
        publish_root(state, network, application, root, summary.coins())?;
        return Ok(());
    }
    let tree = super::summary_tree::SummaryTree::new(state, &context, application);
    tree.replace(&summary.blocks)?;
    publish_root(state, network, application, tree.root()?, super::summary_tree::top(state, application)?.map_or(0, |top| top.coins))?;
    Ok(())
}

/// Reconstruct the bounded block summary through either a changeset reader or
/// a committed snapshot. A recovery reader must never mix their generations.
pub(crate) fn block_summary_from_records(
    context: &[u8; 32],
    shard: &[bool],
    mut read: impl FnMut(&[u8; 32]) -> Result<Option<Vec<u8>>>,
) -> Result<BlockSummary> {
    use super::state::{block_record_address, BLOCK_FRONTIER_TAG, BLOCK_ROOT_TAG};
    let mut summary = BlockSummary::default();
    let depth = usize::from(super::coin_blocks::SUBTREE_BITS);
    for block in super::coin_blocks::owned_blocks(shard, super::coin_blocks::MAX_BLOCK_BITS) {
        let frontier = read(&block_record_address(BLOCK_FRONTIER_TAG, block))?
            .map(|bytes| Frontier::decode(&bytes, context, depth).map_err(|_| invalid())).transpose()?;
        let root = read(&block_record_address(BLOCK_ROOT_TAG, block))?
            .map(|bytes| Node::from_bytes(&bytes).map_err(|_| invalid())).transpose()?;
        match (frontier, root) {
            (None, None) => {}
            (Some(frontier), Some(root)) => {
                let reconstructed = frontier.root_at_depth(depth)
                    .map_err(|_| invalid())?;
                if reconstructed.root != root {
                    return Err(QuilError::ExecutionUnavailable("coin block frontier/root mismatch during summary recovery".into()));
                }
                if frontier.count() > 0 {
                    summary.put(block, frontier.count(), root)?;
                }
            }
            _ => return Err(QuilError::ExecutionUnavailable("incomplete coin block during summary recovery".into())),
        }
    }
    Ok(summary)
}

/// Read one block's stored subtree root, if the block has ever held a coin.
pub fn block_root(
    state: &HypergraphState,
    application: &[u8; 32],
    block: u64,
) -> Result<Option<quil_lattice_ct::confidential::relation::membership::Node>> {
    use quil_lattice_ct::confidential::relation::membership::{Node, NODE_BYTES};
    let address = super::state::block_record_address(super::state::BLOCK_ROOT_TAG, block);
    let Some(bytes) = state.get(application, &address, &vertex_adds_discriminator()?)? else {
        return Ok(None);
    };
    if bytes.len() != NODE_BYTES {
        return Err(invalid());
    }
    Ok(Some(Node::from_bytes(&bytes).map_err(|_| invalid())?))
}

/// Recompute the application root from the per-block subtree roots: the fold
/// is the top levels of the same tree, so this equals the root a node holding
/// every coin would build (proved in `sharded_tree`). A block that has never
/// held a coin contributes its zero subtree and may be absent.
pub fn fold_application_root(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
) -> Result<quil_lattice_ct::confidential::relation::membership::Node> {
    let context = parameter_context(network, application);
    let width = block_width(state, application)?;
    let shape = super::coin_blocks::shape(width)?;
    match super::summary_tree::legacy_summary(state, application)? {
        Some(flat) => quil_lattice_ct::confidential::sharded_tree::fold_subtree_roots(&context, shape, &flat.roots())
            .map_err(|_| invalid()),
        None => super::summary_tree::SummaryTree::new(state, &context, application).root(),
    }
}

/// The committed accumulator width, in block levels. Absent means an
/// application that has not yet written one, which starts at the initial
/// width; growth raises it and never moves an existing coin.
pub fn block_width(state: &HypergraphState, application: &[u8; 32]) -> Result<u8> {
    let stored = read_local(state, application, &super::state::SHAPE_ADDRESS)?;
    match stored.as_deref() {
        Some([width]) => Ok(*width),
        Some(_) => Err(invalid()),
        None => Ok(super::coin_blocks::INITIAL_BLOCK_BITS),
    }
}

/// Per-block append frontier. Each block advances on its own, which is what
/// lets the shard owning it extend the accumulator with no coordination.
fn load_block_frontier(
    state: &HypergraphState,
    context: &[u8; 32],
    application: &[u8; 32],
    block: u64,
    _limits: SnapshotLimits,
) -> Result<Option<Frontier>> {
    // A block's frontier spans the block's own levels, which is a property of
    // the accumulator's shape and not of the caller's snapshot limits. Reading
    // it at anything else fails to decode a frontier this node itself wrote.
    let subtree = usize::from(super::coin_blocks::SUBTREE_BITS);
    let address = super::state::block_record_address(super::state::BLOCK_FRONTIER_TAG, block);
    state
        .get(application, &address, &vertex_adds_discriminator()?)?
        .map(|bytes| Frontier::decode(&bytes, context, subtree).map_err(|_| invalid()))
        .transpose()
}

/// Coins already appended to `block`.
pub fn block_count(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    block: u64,
    limits: SnapshotLimits,
) -> Result<u64> {
    let context = parameter_context(network, application);
    Ok(load_block_frontier(state, &context, application, block, limits)?
        .map(|frontier| frontier.count())
        .unwrap_or(0))
}

/// Leaf index for the next coin staged into `block`: the block's own count,
/// composed with the block id. The staging shard must own the block, which is
/// looked up rather than derived from the coin's address — see `coin_blocks`.
pub fn next_block_position(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    block: u64,
    limits: SnapshotLimits,
) -> Result<u64> {
    let width = block_width(state, application)?;
    let local = block_count(state, network, application, block, limits)?;
    super::coin_blocks::position(width, block, local)
}

/// Place one output in the accumulator.
///
/// The order is forced by what depends on what: a coin's identity fixes its
/// address, the address selects its block, the block's owner is the shard that
/// stores the coin, and only then does that block's own counter give a
/// position. `staged` carries the counts a single transaction has already
/// placed per block, so several outputs landing in one block take consecutive
/// local indices while outputs in different blocks never collide.
#[allow(clippy::too_many_arguments)]
pub fn stage_coin(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    context: &[u8; 32],
    frame: u64,
    output: &quil_lattice_ct::confidential::transfer::Output,
    staged: &mut BTreeMap<u64, u64>,
    limits: SnapshotLimits,
) -> Result<([u8; 32], quil_tries::VectorCommitmentTree)> {
    let (address, mut tree) = super::state::coin_identity(context, frame, output)?;
    let width = block_width(state, application)?;
    let block = super::coin_blocks::block_for_address(width, &address)?;
    let placed = staged.entry(block).or_default();
    let local = block_count(state, network, application, block, limits)?
        .checked_add(*placed)
        .ok_or_else(invalid)?;
    let position = super::coin_blocks::position(width, block, local)?;
    *placed += 1;
    super::state::place_coin(&mut tree, position)?;
    Ok((address, tree))
}

/// Leaf index for the next coin staged into this application. Adapters assign
/// consecutive positions from here to the coins they create before publishing.
pub fn next_position(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    limits: SnapshotLimits,
) -> Result<u64> {
    if !(1..=32).contains(&limits.max_depth) {
        return Err(invalid());
    }
    let context = parameter_context(network, application);
    match load_frontier(state, &context, application, limits)? {
        Some(frontier) => Ok(frontier.count()),
        None => Ok(collect_live_records(state, &context, application, limits)?.len() as u64),
    }
}

/// Full O(n) reconstruction of the current root from every live coin. Used for
/// the first publication and as an independent cross-check of the frontier.
pub fn full_rebuild_root(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    limits: SnapshotLimits,
) -> Result<RootRecord> {
    if !(1..=32).contains(&limits.max_depth) {
        return Err(invalid());
    }
    let context = parameter_context(network, application);
    let records = collect_live_records(state, &context, application, limits)?;
    let width = block_width(state, application)?;
    let shape = super::coin_blocks::shape(width)?;
    // The independent cross-check of the per-block fold: build the whole tree
    // from every live coin and take its root. The two must agree, which is the
    // property `sharded_tree` proves and this recomputes over real state.
    let tree = quil_lattice_ct::confidential::sharded_tree::ShardedCoinTree::build(&context, shape, &records)
        .map_err(|_| invalid())?;
    tree.root_at_depth(shape.depth()).map_err(|_| invalid())
}

/// Stage the root, frontier and bounded history alongside coins in the same
/// changeset. New coins are those in the pending changeset whose position is at
/// or beyond the persisted frontier; they must be consecutive from there.
/// Does not commit state. Callers serialize mutations and own rollback on error.
pub fn refresh_root(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    limits: SnapshotLimits,
) -> Result<RootRecord> {
    if !(1..=32).contains(&limits.max_depth) {
        return Err(invalid());
    }
    let context = parameter_context(network, application);
    let disc = vertex_adds_discriminator()?;
    let width = block_width(state, application)?;
    super::coin_blocks::shape(width)?;
    let subtree = usize::from(super::coin_blocks::SUBTREE_BITS);

    // An application that has never published a root — or that holds coins
    // predating the accumulator, as after the legacy migration — is folded
    // from every live coin. Afterwards the summary tree carries each block's
    // state and a publication only rewrites the blocks its changeset added
    // to, with their ancestors. A flat summary left from before the tree is
    // converted first, here, inside the frame's changeset.
    let published = read_local(state, application, &ROOT_ADDRESS)?;
    let tree = super::summary_tree::SummaryTree::new(state, &context, application);
    tree.upgrade()?;
    let held = super::summary_tree::top(state, application)?;
    let bootstrap = published.is_none() || held.is_none();

    // Group the coins this publication folds by the block their position
    // names. In the steady state a transaction touches only the blocks it
    // writes into, so the work is proportional to what changed rather than to
    // the size of the application.
    let records = if bootstrap {
        collect_live_records(state, &context, application, limits)?
    } else {
        let mut pending = Vec::new();
        for (address, blob) in state.pending_vertex_adds(application)? {
            if address.len() != 32 {
                return Err(invalid());
            }
            let mut key = application.to_vec();
            key.extend_from_slice(&address);
            if let Some(record) = decode_snapshot_coin(&context, application, &key, &blob)? {
                pending.push(record);
            }
        }
        pending
    };
    let mut by_block: BTreeMap<u64, Vec<CoinRecord>> = BTreeMap::new();
    for record in records {
        let (block, _) = super::coin_blocks::locate(record.position);
        // Bounded by the widest block, not the stored width record: a coin
        // delivered into a block wider than six bits is valid (see
        // `delivery::place_committed`), and the tree's shape does not depend
        // on the width.
        if !super::coin_blocks::is_allocated_width(super::coin_blocks::MAX_BLOCK_BITS, block) {
            return Err(invalid());
        }
        by_block.entry(block).or_default().push(record);
    }

    let held = if bootstrap { 0 } else { held.map_or(0, |top| top.coins) };
    // Load each touched block's frontier and separate the genuinely new coins:
    // a changeset may be refreshed several times, so coins already folded into
    // a block appear again in `pending_vertex_adds` and must not be recounted.
    let mut touched: Vec<(u64, Frontier, Vec<CoinRecord>)> = Vec::with_capacity(by_block.len());
    let mut incoming = 0usize;
    for (block, mut records) in by_block {
        let frontier = match load_block_frontier(state, &context, application, block, limits)? {
            // A bootstrap rebuilds each block from its coins, so it starts
            // from an empty frontier even where one was left behind.
            Some(frontier) if !bootstrap => frontier,
            _ => Frontier::new(&context, subtree).map_err(|_| invalid())?,
        };
        records.sort_by_key(|record| record.position);
        records.retain(|record| super::coin_blocks::locate(record.position).1 >= frontier.count());
        incoming += records.len();
        touched.push((block, frontier, records));
    }
    // The coin cap bounds the APPLICATION, not one block: blocks are an
    // internal partition, so a limit that counted per block would let an
    // application grow without bound by spreading across them.
    if usize::try_from(held)
        .ok()
        .and_then(|held| held.checked_add(incoming))
        .is_none_or(|total| total > limits.max_coins)
    {
        return Err(invalid());
    }
    let mut leaves = Vec::with_capacity(touched.len());
    for (block, mut frontier, fresh) in touched {
        // Each new coin must continue its block's sequence exactly, so a gap
        // or a reused index is refused rather than folded into the root.
        for record in &fresh {
            let (_, local) = super::coin_blocks::locate(record.position);
            if local != frontier.count() {
                return Err(invalid());
            }
            frontier
                .append(&record.owner, &record.commitment)
                .map_err(|_| invalid())?;
        }
        let root = frontier
            .root_at_depth(subtree)
            .map_err(|_| invalid())?;
        let encoded = frontier.encode();
        let frontier_address =
            super::state::block_record_address(super::state::BLOCK_FRONTIER_TAG, block);
        if state.get(application, &frontier_address, &disc)?.as_deref() != Some(encoded.as_slice()) {
            state.set(application, &frontier_address, &disc, 0, encoded)?;
        }
        let root_address = super::state::block_record_address(super::state::BLOCK_ROOT_TAG, block);
        let root_bytes = root.root.to_bytes().to_vec();
        if state.get(application, &root_address, &disc)?.as_deref() != Some(root_bytes.as_slice()) {
            state.set(application, &root_address, &disc, 0, root_bytes)?;
        }
        leaves.push((block, frontier.count(), root.root));
    }
    if bootstrap {
        tree.replace(&leaves)?;
    } else {
        tree.update(&leaves)?;
    }
    let coins = super::summary_tree::top(state, application)?.map_or(0, |top| top.coins);
    publish_root(state, network, application, tree.root()?, coins)
}

/// Publish `root`, the top of the summary tree, into the root history.
fn publish_root(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    root: Node,
    coins: u64,
) -> Result<RootRecord> {
    let context = parameter_context(network, application);
    let shape = super::coin_blocks::shape(block_width(state, application)?)?;
    // The application root is the fold of the block roots — the top levels of
    // the same tree, so this equals what a node holding every coin would build.
    let current = RootRecord {
        context,
        depth: shape.depth() as u8,
        coins,
        root,
    };

    let existing = read_local(state, application, &ROOT_ADDRESS)?;
    let mut history = match &existing {
        Some(bytes) => History::decode(bytes, &context)?,
        None => History {
            current: current.clone(),
            digests: Vec::new(),
        },
    };
    history.publish(current.clone())?;
    let bytes = history.encode()?;
    if existing.as_deref() != Some(bytes.as_slice()) {
        write_local(state, application, &ROOT_ADDRESS, bytes);
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_state() -> HypergraphState {
        HypergraphState::new(std::sync::Arc::new(quil_hypergraph::HypergraphCrdt::new(
            std::sync::Arc::new(quil_hypergraph::testing::MemStore::new()),
            std::sync::Arc::new(quil_types::crypto::NoopInclusionProver),
        )))
    }

    /// A rebuild is member-local (restart, sync, merge), so it never converts:
    /// a flat summary is rebuilt flat, with unchanged bytes when its blocks are
    /// unchanged, and a converted store is rebuilt as a tree with the same root.
    #[test]
    fn a_rebuild_keeps_a_flat_summary_flat() {
        use super::super::state::{block_record_address, BLOCK_FRONTIER_TAG, BLOCK_ROOT_TAG, BLOCK_SUMMARY_ADDRESS};
        use super::super::summary_tree::{self, MOVED};
        use quil_lattice_ct::confidential::{AmountOpening, CommitmentKey};
        let state = mem_state();
        let (network, application) = ([23u8; 32], [24u8; 32]);
        let context = parameter_context(&network, &application);
        let disc = vertex_adds_discriminator().unwrap();
        let key = CommitmentKey::derive(&context);
        let depth = usize::from(super::super::coin_blocks::SUBTREE_BITS);
        let mut flat = BlockSummary::default();
        for (seed, width, path) in [(1u8, 6u8, 0u64), (2, 6, 9), (3, 7, 100)] {
            let block = super::super::coin_blocks::block_id(width, path).unwrap();
            let mut frontier = Frontier::new(&context, depth).unwrap();
            let commitment = key.commit(u128::from(seed), &AmountOpening::from_seed(&context, &[seed; 32]));
            frontier.append(&[seed; IDENTITY_BYTES], &commitment).unwrap();
            let root = frontier.root_at_depth(depth).unwrap().root;
            state.set(&application, &block_record_address(BLOCK_FRONTIER_TAG, block), &disc, 0, frontier.encode()).unwrap();
            state.set(&application, &block_record_address(BLOCK_ROOT_TAG, block), &disc, 0, root.to_bytes().to_vec()).unwrap();
            flat.put(block, 1, root).unwrap();
        }
        state.set(&application, &BLOCK_SUMMARY_ADDRESS, &disc, 0, flat.encode()).unwrap();
        state.commit().unwrap();
        state.abort();

        rebuild_block_summary(&state, &network, &application, &[]).unwrap();
        assert_eq!(super::super::state::read_local(&state, &application, &BLOCK_SUMMARY_ADDRESS).unwrap(), Some(flat.encode()),
            "a rebuild leaves a flat summary flat");
        assert!(summary_tree::top(&state, &application).unwrap().is_none());
        let root = fold_application_root(&state, &network, &application).unwrap();
        state.commit().unwrap();
        state.abort();

        summary_tree::SummaryTree::new(&state, &context, &application).upgrade().unwrap();
        state.commit().unwrap();
        state.abort();
        rebuild_block_summary(&state, &network, &application, &[]).unwrap();
        assert_eq!(super::super::state::read_local(&state, &application, &BLOCK_SUMMARY_ADDRESS).unwrap().as_deref(), Some(MOVED.as_slice()));
        assert_eq!(summary_tree::top(&state, &application).unwrap().map(|top| top.coins), Some(3));
        assert_eq!(fold_application_root(&state, &network, &application).unwrap(), root);
    }

    /// A store written before the summary tree holds a flat summary. Its first
    /// refresh converts it inside that refresh's changeset, and publishes the
    /// root every coin gives.
    #[test]
    fn the_first_refresh_converts_a_flat_summary() {
        use super::super::state::BLOCK_SUMMARY_ADDRESS;
        use super::super::summary_tree::{self, SummaryTree, MOVED};
        use quil_lattice_ct::confidential::{transfer::Output, AmountOpening, CommitmentKey};
        let state = mem_state();
        let (network, application) = ([21u8; 32], [22u8; 32]);
        let context = parameter_context(&network, &application);
        let limits = SnapshotLimits { max_coins: 64, max_depth: 32, max_nodes: 1 << 16 };
        let disc = vertex_adds_discriminator().unwrap();
        let key = CommitmentKey::derive(&context);
        // One changeset's coins share the positions staged so far.
        let stage = |seed: u8, staged: &mut BTreeMap<_, _>| {
            let output = Output {
                owner: [seed; IDENTITY_BYTES],
                commitment: key.commit(u128::from(seed), &AmountOpening::from_seed(&context, &[seed; 32])),
                memo: [seed; 1115],
            };
            let (address, tree) =
                stage_coin(&state, &network, &application, &context, 1, &output, staged, limits).unwrap();
            state.set(&application, &address, &disc, 1, quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()).unwrap();
        };
        let mut staged = BTreeMap::new();
        for seed in 1..=6 {
            stage(seed, &mut staged);
        }
        refresh_root(&state, &network, &application, limits).unwrap();
        // The same state in its pre-tree form.
        let flat = block_summary(&state, &application).unwrap();
        SummaryTree::new(&state, &context, &application).replace(&[]).unwrap();
        state.set(&application, &BLOCK_SUMMARY_ADDRESS, &disc, 0, flat.encode()).unwrap();
        state.commit().unwrap();
        state.abort();
        assert!(summary_tree::top(&state, &application).unwrap().is_none());
        assert_eq!(summary_coins(&state, &application).unwrap(), 6);

        let mut staged = BTreeMap::new();
        for seed in 7..=9 {
            stage(seed, &mut staged);
        }
        let published = refresh_root(&state, &network, &application, limits).unwrap();
        assert_eq!(super::super::state::read_local(&state, &application, &BLOCK_SUMMARY_ADDRESS).unwrap().as_deref(), Some(MOVED.as_slice()));
        assert_eq!(published, full_rebuild_root(&state, &network, &application, limits).unwrap());
        assert_eq!(published.coins, 9);
        assert_eq!(summary_tree::top(&state, &application).unwrap().map(|top| top.coins), Some(9));
        assert_eq!(fold_application_root(&state, &network, &application).unwrap(), published.root);
    }

    /// Blocks advance independently: each keeps its own count, so the shard
    /// owning one appends without consulting any other, and positions never
    /// collide across blocks.
    #[test]
    fn blocks_count_independently_and_positions_never_collide() {
        let state = mem_state();
        let (network, application) = ([3u8; 32], [4u8; 32]);
        let limits = SnapshotLimits { max_coins: 1024, max_depth: 32, max_nodes: 1 << 16 };
        let width = block_width(&state, &application).unwrap();
        assert_eq!(width, super::super::coin_blocks::INITIAL_BLOCK_BITS,
            "an application with no committed width starts at the initial one");

        // Nothing staged yet: every block starts empty, and each block's first
        // position is its own, not a shared counter.
        let mut seen = std::collections::BTreeSet::new();
        let ids: Vec<u64> = [0u64, 1, 5, 63]
            .iter()
            .map(|path| super::super::coin_blocks::block_id(width, *path).unwrap())
            .collect();
        for block in ids {
            assert_eq!(block_count(&state, &network, &application, block, limits).unwrap(), 0);
            let position = next_block_position(&state, &network, &application, block, limits).unwrap();
            assert_eq!(super::super::coin_blocks::locate(position), (block, 0));
            assert!(seen.insert(position), "block {block} must not reuse another block's position");
        }

        // A block wider than the committed width does not exist yet, and is
        // refused rather than aliased onto an existing block's region.
        let beyond = super::super::coin_blocks::block_id(width + 1, 0).unwrap();
        assert!(next_block_position(&state, &network, &application, beyond, limits).is_err());
        // An id with no sentinel is not a block at all.
        assert!(next_block_position(&state, &network, &application, 0, limits).is_err());

        // The fold over an application with no coins is well defined and
        // matches the empty tree — the base case every later root builds on.
        let empty = fold_application_root(&state, &network, &application).unwrap();
        let context = parameter_context(&network, &application);
        let shape = super::super::coin_blocks::shape(width).unwrap();
        assert_eq!(
            empty,
            quil_lattice_ct::confidential::sharded_tree::fold_subtree_roots(&context, shape, &[]).unwrap()
        );
        // And no block has a root yet.
        let first = super::super::coin_blocks::block_id(width, 0).unwrap();
        assert!(block_root(&state, &application, first).unwrap().is_none());
    }
    #[test]
    fn history_codec_is_bounded_unique_and_context_bound() {
        let mut history = History {
            current: RootRecord {
                context: [1; 32],
                depth: 1,
                coins: 0,
                root: Node::zero(),
            },
            digests: Vec::new(),
        };
        history.publish(history.current.clone()).unwrap();
        let original = history.encode().unwrap();
        history.publish(history.current.clone()).unwrap();
        assert_eq!(history.encode().unwrap(), original);
        assert!(History::decode(&original, &[2; 32]).is_err());
        for n in [0, 8, original.len() - 1] {
            assert!(History::decode(&original[..n], &[1; 32]).is_err());
        }
        let mut trailing = original.clone();
        trailing.push(0);
        assert!(History::decode(&trailing, &[1; 32]).is_err());
        for i in 0..HISTORY_LIMIT + 1 {
            let mut next = history.current.clone();
            next.root = Node::from_identity_bytes(&[i as u8; IDENTITY_BYTES]).unwrap();
            history.publish(next).unwrap();
        }
        assert_eq!(history.digests.len(), HISTORY_LIMIT);
        let bytes = history.encode().unwrap();
        assert_eq!(History::decode(&bytes, &[1; 32]).unwrap().digests, history.digests);
        assert!(bytes.len() < 12 * 1024, "a full history fits a scan page: {} bytes", bytes.len());
        history.digests[0] = history.digests[1];
        assert!(history.encode().is_err());
    }

    /// A history stored with root ids (the earlier encoding) reads as the same
    /// retained roots, and its next publication rewrites it with digests.
    #[test]
    fn a_history_of_root_ids_reads_as_digests_and_is_rewritten() {
        let context = [1; 32];
        let root = |i: u8| RootRecord {
            context, depth: 1, coins: 0, root: Node::from_identity_bytes(&[i; IDENTITY_BYTES]).unwrap(),
        };
        let mut legacy = VERSION_IDS.to_vec();
        legacy.extend_from_slice(&root(3).encode().unwrap());
        legacy.extend_from_slice(&3u16.to_le_bytes());
        for i in 1..=3u8 {
            legacy.extend_from_slice(&root_id(&context, 1, &root(i).root));
        }
        for i in 1..=3u8 {
            assert!(history_retains(&legacy, &context, 1, &root(i).root).unwrap());
            assert!(history_retains_digest(&legacy, &context, &root_digest(&context, 1, &root(i).root)).unwrap());
        }
        assert!(!history_retains(&legacy, &context, 1, &root(4).root).unwrap());
        let rewritten = publish_history(Some(&legacy), root(4)).unwrap();
        assert_eq!(&rewritten[..8], VERSION.as_slice());
        assert!(rewritten.len() < legacy.len());
        for i in 1..=4u8 {
            assert!(history_retains(&rewritten, &context, 1, &root(i).root).unwrap());
        }
        assert_eq!(decode_current(&rewritten, &context).unwrap(), root(4));
        // A root published again moves to the end rather than repeating.
        let again = publish_history(Some(&rewritten), root(2)).unwrap();
        let history = History::decode(&again, &context).unwrap();
        assert_eq!(history.digests.len(), 4);
        assert_eq!(history.digests.last(), Some(&root_digest(&context, 1, &root(2).root)));
        let mut wrong_last = legacy.clone();
        let tail = wrong_last.len() - ID_BYTES;
        wrong_last[tail..].copy_from_slice(&root_id(&context, 1, &root(9).root));
        assert!(History::decode(&wrong_last, &context).is_err(), "the last id must be the current root's");
    }

    /// The accumulator's own records are node-local: a publication writes no
    /// vertex at their addresses, so no shard root or size includes them, and
    /// the next frame reads them back. A copy an earlier build left in the
    /// tree is read until a publication overwrites it locally; the tree copy
    /// itself is never touched.
    #[test]
    fn accumulator_records_are_node_local() {
        use super::super::state::SHAPE_ADDRESS;
        use super::super::summary_tree::{node_address, top, LEVELS};
        use quil_lattice_ct::confidential::{transfer::Output, AmountOpening, CommitmentKey};
        use quil_types::crypto::NoopInclusionProver;
        use std::sync::Arc;
        let network = [1; 32];
        let application = [2; 32];
        let context = parameter_context(&network, &application);
        let limits = SnapshotLimits { max_coins: 4, max_depth: 3, max_nodes: 16 };
        let disc = vertex_adds_discriminator().unwrap();
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(NoopInclusionProver),
        ));
        let state = HypergraphState::new(crdt.clone());
        let key = CommitmentKey::derive(&context);
        let output = Output {
            owner: [1; IDENTITY_BYTES],
            commitment: key.commit(123, &AmountOpening::from_seed(&context, &[1; 32])),
            memo: [0; 1115],
        };
        let (address, tree) =
            stage_coin(&state, &network, &application, &context, 1, &output, &mut BTreeMap::new(), limits).unwrap();
        state.set(&application, &address, &disc, 1, quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()).unwrap();
        let published = refresh_root(&state, &network, &application, limits).unwrap();
        state.commit().unwrap();

        let next = HypergraphState::new(crdt.clone());
        for address in [ROOT_ADDRESS, node_address(LEVELS, 0)] {
            assert_eq!(next.get(&application, &address, &disc).unwrap(), None, "no vertex in the tree");
        }
        assert_eq!(read_current(&next, &network, &application).unwrap(), Some(published.clone()));
        assert!(accepts_root(&next, &network, &application, published.depth, &published.root).unwrap());
        assert_eq!(top(&next, &application).unwrap().map(|node| node.coins), Some(1));

        // An earlier build's copy in the tree: read in place, then superseded
        // by the next publication without being rewritten.
        let legacy = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(NoopInclusionProver),
        )));
        let history = next.get_record(&super::super::state::local_record_key(&application, &ROOT_ADDRESS)).unwrap().unwrap();
        legacy.set(&application, &ROOT_ADDRESS, &disc, 1, history.clone()).unwrap();
        legacy.set(&application, &SHAPE_ADDRESS, &disc, 1, vec![super::super::coin_blocks::INITIAL_BLOCK_BITS]).unwrap();
        legacy.commit().unwrap();
        assert_eq!(read_current(&legacy, &network, &application).unwrap(), Some(published));
        assert_eq!(block_width(&legacy, &application).unwrap(), super::super::coin_blocks::INITIAL_BLOCK_BITS);
        publish_root(&legacy, &network, &application, Node::zero(), 0).unwrap();
        assert_eq!(read_current(&legacy, &network, &application).unwrap().unwrap().coins, 0);
        assert_eq!(legacy.get(&application, &ROOT_ADDRESS, &disc).unwrap(), Some(history), "the tree copy is not rewritten");
    }

    #[test]
    fn publication_covers_staged_coins_and_rolls_back_with_them() {
        use super::super::state::{create_coin, load_committed_snapshot};
        use quil_lattice_ct::confidential::{transfer::Output, AmountOpening, CommitmentKey};
        use quil_types::crypto::NoopInclusionProver;
        use std::sync::Arc;
        let network = [1; 32];
        let application = [2; 32];
        let context = parameter_context(&network, &application);
        let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(NoopInclusionProver),
        )));
        let limits = SnapshotLimits {
            max_coins: 4,
            max_depth: 3,
            max_nodes: 16,
        };
        let disc = vertex_adds_discriminator().unwrap();
        assert!(!accepts_root(&state, &network, &application, 1, &Node::zero()).unwrap());
        assert!(next_position(&state, &network, &application, SnapshotLimits { max_depth: 0, ..limits }).is_err());
        let key = CommitmentKey::derive(&context);
        // Adapters assign positions from `next_position`; the fixture does the same.
        // Stage the way every adapter does: identity first, then the block its
        // address selects, then that block's own next index.
        let stage = |seed: u8| {
            let output = Output {
                owner: [seed; IDENTITY_BYTES],
                commitment: key.commit(123, &AmountOpening::from_seed(&context, &[seed; 32])),
                memo: [0; 1115],
            };
            let mut staged = BTreeMap::new();
            let (address, tree) = stage_coin(
                &state, &network, &application, &context, 1, &output, &mut staged, limits,
            )
            .unwrap();
            let position = super::super::state::read_coin(&tree, &context).unwrap().unwrap().position;
            let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
            state.set(&application, &address, &disc, 1, blob).unwrap();
            position
        };
        let first_position = stage(1);
        // A staged coin lands in the block its address selects, at that
        // block's first free index.
        assert_eq!(super::super::coin_blocks::locate(first_position).1, 0);
        // First publication bootstraps the frontier from live coins.
        let first = refresh_root(&state, &network, &application, limits).unwrap();
        assert_eq!(first.coins, 1);
        // The frontier written is the BLOCK's, not one shared by the
        // application: that is what lets each shard advance on its own.
        let first_block = super::super::coin_blocks::locate(first_position).0;
        let frontier_address =
            super::super::state::block_record_address(super::super::state::BLOCK_FRONTIER_TAG, first_block);
        assert!(state.get(&application, &frontier_address, &disc).unwrap().is_some());
        assert_eq!(block_count(&state, &network, &application, first_block, limits).unwrap(), 1);
        assert_eq!(full_rebuild_root(&state, &network, &application, limits).unwrap(), first);
        let saved = state.changeset_len();
        refresh_root(&state, &network, &application, limits).unwrap();
        assert_eq!(state.changeset_len(), saved);
        let second_position = stage(2);
        // Incremental publication appends only the new coin, matching a rebuild.
        let second = refresh_root(&state, &network, &application, limits).unwrap();
        assert_eq!(second.coins, 2);
        assert_eq!(full_rebuild_root(&state, &network, &application, limits).unwrap(), second);
        assert!(accepts_root(&state, &network, &application, first.depth, &first.root).unwrap());
        state.rollback_to(saved);
        assert_eq!(
            read_current(&state, &network, &application).unwrap(),
            Some(first.clone())
        );
        assert_eq!(block_count(&state, &network, &application, first_block, limits).unwrap(), 1);
        assert!(!accepts_root(&state, &network, &application, second.depth, &second.root).unwrap());
        state.commit().unwrap();
        state.abort();
        // The first coin is now a live CRDT write, not yet in the committed store.
        assert_eq!(stage(2), second_position);
        assert_eq!(
            refresh_root(&state, &network, &application, limits).unwrap(),
            second
        );
        // A coin staged with a gap in its position cannot be published.
        let saved = state.changeset_len();
        let stray = Output {
            owner: [9; IDENTITY_BYTES],
            commitment: key.commit(1, &AmountOpening::from_seed(&context, &[9; 32])),
            memo: [0; 1115],
        };
        // A gap INSIDE a valid block: the block holds one coin, so local index
        // 5 skips four. Publication must refuse it rather than fold a hole
        // into the block's root.
        let gapped = super::super::coin_blocks::position(
            block_width(&state, &application).unwrap(),
            first_block,
            5,
        )
        .unwrap();
        let (address, tree) = create_coin(&context, 1, &stray, gapped).unwrap();
        state.set(&application, &address, &disc, 1, quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()).unwrap();
        assert!(refresh_root(&state, &network, &application, limits).is_err());
        state.rollback_to(saved);
        // The coin cap applies to the running total.
        assert!(refresh_root(&state, &network, &application, SnapshotLimits { max_coins: 1, ..limits }).is_err());
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(1).unwrap();
        let snapshot = load_committed_snapshot(&state, &network, &application, limits).unwrap();
        assert_eq!(
            snapshot.root_at_depth(snapshot.current_depth()).unwrap(),
            second
        );
        assert_eq!(
            read_current(&state, &network, &application).unwrap(),
            Some(second.clone())
        );
        // Committed frontier resumes appends without a rebuild and stays in
        // step with the full reconstruction over several more coins.
        // Committed per-block frontiers resume appends without a rebuild and
        // stay in step with the full reconstruction, whichever blocks the
        // coins land in.
        for expected in 2..6u64 {
            let position = stage(10 + expected as u8);
            let (block, local) = super::super::coin_blocks::locate(position);
            assert_eq!(
                local,
                block_count(&state, &network, &application, block, limits).unwrap(),
                "a staged coin takes its own block's next index"
            );
            let wide = SnapshotLimits { max_coins: 8, max_nodes: 32, ..limits };
            let root = refresh_root(&state, &network, &application, wide).unwrap();
            assert_eq!(root.coins, expected + 1);
            assert_eq!(full_rebuild_root(&state, &network, &application, wide).unwrap(), root);
        }
    }

    /// Widening an application that already holds coins moves nothing. A block
    /// id carries the width it was created at, so an existing coin keeps its
    /// block and its position while new coins land in the wider space, and the
    /// root still equals a rebuild from every live coin.
    ///
    /// The mechanism is what is tested here; no code writes the shape record
    /// yet, because WHEN an application widens is a policy every node must
    /// agree on and nobody has chosen one.
    #[test]
    fn widening_keeps_every_existing_coin_where_it_is() {
        use quil_lattice_ct::confidential::{transfer::Output, AmountOpening, CommitmentKey};
        let state = mem_state();
        let (network, application) = ([21u8; 32], [22u8; 32]);
        let context = parameter_context(&network, &application);
        let limits = SnapshotLimits { max_coins: 64, max_depth: 32, max_nodes: 1 << 16 };
        let disc = vertex_adds_discriminator().unwrap();
        let key = CommitmentKey::derive(&context);
        let stage = |seed: u8| {
            let output = Output {
                owner: [seed; IDENTITY_BYTES],
                commitment: key.commit(u128::from(seed), &AmountOpening::from_seed(&context, &[seed; 32])),
                memo: [0; 1115],
            };
            let mut staged = BTreeMap::new();
            let (address, tree) =
                stage_coin(&state, &network, &application, &context, 1, &output, &mut staged, limits).unwrap();
            let position = super::super::state::read_coin(&tree, &context).unwrap().unwrap().position;
            state
                .set(&application, &address, &disc, 1, quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap())
                .unwrap();
            (address, position)
        };

        let narrow = block_width(&state, &application).unwrap();
        let mut before = Vec::new();
        for seed in 1..4u8 {
            before.push(stage(seed));
        }
        let first = refresh_root(&state, &network, &application, limits).unwrap();
        state.commit().unwrap();
        state.abort();

        // Widen by one level. Nothing else changes.
        state
            .set(&application, &super::super::state::SHAPE_ADDRESS, &disc, 1, vec![narrow + 1])
            .unwrap();
        assert_eq!(block_width(&state, &application).unwrap(), narrow + 1);

        // Every coin staged before the widening keeps its block and position,
        // and the root the application published still stands.
        for (address, position) in &before {
            let (block, _) = super::super::coin_blocks::locate(*position);
            assert_eq!(
                super::super::coin_blocks::creation_width(block),
                narrow,
                "an existing coin's block keeps the width it was created at"
            );
            assert_eq!(
                super::super::coin_blocks::block_for_address(narrow, address).unwrap(),
                block
            );
            assert!(super::super::coin_blocks::is_allocated_width(narrow + 1, block));
        }
        assert_eq!(read_current(&state, &network, &application).unwrap(), Some(first.clone()));

        // New coins take blocks of the wider space, and the incremental root
        // still equals a rebuild over every live coin — old and new together.
        for seed in 10..14u8 {
            let (_, position) = stage(seed);
            assert_eq!(
                super::super::coin_blocks::creation_width(super::super::coin_blocks::locate(position).0),
                narrow + 1,
                "a coin staged after the widening uses the wider space"
            );
            let root = refresh_root(&state, &network, &application, limits).unwrap();
            assert_eq!(full_rebuild_root(&state, &network, &application, limits).unwrap(), root);
            // Widening does not reshape the tree, so the depth never moves.
            assert_eq!(root.depth, first.depth);
        }
        assert_eq!(
            read_current(&state, &network, &application).unwrap().unwrap().coins,
            (before.len() + 4) as u64
        );
    }
}

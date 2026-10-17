//! Local, rebuildable completed-subtree index. Keys never enter hypergraph
//! state, transaction encodings, or forest replication. Index contents are
//! untrusted hints: every returned path must match the caller's selected root.
//!
//! The owner must serialize population/reset for an application. A failed
//! cache write must not fail consensus execution. Node population, startup
//! rebuild and RPC scheduling are wired separately from this storage primitive.
use std::sync::Arc;
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
use sha3::{Digest, Sha3_256};

use quil_lattice_ct::confidential::{
    coin_tree::{AuthPath, CoinRecord, Frontier, IndexedTree, RootRecord},
    relation::membership::Node,
    sharded_tree,
};
use quil_types::{error::{QuilError, Result}, store::{KvDb, Transaction}};

use super::{coin_blocks, roots::BlockSummary};

const MAX_BATCH_COINS: usize = 8;

/// Tips one generation keeps a block summary for. A wallet proves against the
/// root it just read, so refusing every root but the newest would race it out
/// whenever another transaction lands first. Bounded, because each retained
/// tip costs one summary record.
const INDEX_SUMMARY_HISTORY: usize = 16;

pub const MAX_UPDATE_VERTICES: usize = 256;
pub const MAX_UPDATE_BYTES: usize = 2 * 1024 * 1024;
const MAX_UPDATE_COINS: usize = 128;

/// The generation selects immutable cache keys; the tip advances within it.
pub struct ReadyIndex {
    pub generation: RootRecord,
    pub root: RootRecord,
}
impl ReadyIndex {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = self.generation.encode().map_err(|e| unavailable(format!("generation: {e:?}")))?.to_vec();
        bytes.extend_from_slice(&self.root.encode().map_err(|e| unavailable(format!("tip: {e:?}")))?);
        Ok(bytes)
    }
}

pub struct LocalWitnessIndex {
    db: Arc<dyn KvDb>,
    context: [u8; 32],
    max_depth: usize,
    prefix: Vec<u8>,
    reader: std::sync::OnceLock<IndexedTree>,
}

fn unavailable(message: impl std::fmt::Display) -> QuilError {
    QuilError::ExecutionUnavailable(format!("local witness index: {message}"))
}

impl LocalWitnessIndex {
    pub fn new(db: Arc<dyn KvDb>, context: &[u8; 32], max_depth: usize) -> Result<Self> {
        if !(1..=32).contains(&max_depth) { return Err(unavailable("invalid index depth")); }
        let reader = std::sync::OnceLock::new();
        let mut prefix = b"quil/local/qct3-witness/v3/".to_vec();
        prefix.extend_from_slice(context);
        prefix.push(b'/');
        Ok(Self { db, context: *context, max_depth, prefix, reader })
    }

    /// Isolate a rebuild from the currently serving generation.
    pub fn for_root(db: Arc<dyn KvDb>, root: &RootRecord, max_depth: usize) -> Result<Self> {
        let mut index = Self::new(db, &root.context, max_depth)?;
        index.prefix = Self::root_prefix(root)?;
        Ok(index)
    }
    fn root_prefix(root: &RootRecord) -> Result<Vec<u8>> {
        let encoded = root.encode().map_err(|e| unavailable(format!("root: {e:?}")))?;
        let mut prefix = Self::metadata_key(&root.context, b'g');
        prefix.extend_from_slice(&Sha3_256::digest(encoded)); prefix.push(b'/');
        Ok(prefix)
    }
    fn clear_root(db: &dyn KvDb, root: &RootRecord) -> Result<()> {
        let prefix = Self::root_prefix(root)?;
        let mut upper = prefix.clone(); *upper.last_mut().unwrap() = b'/' + 1;
        db.delete_range(&prefix, &upper)
    }
    fn metadata_key(context: &[u8; 32], kind: u8) -> Vec<u8> {
        let mut key = b"quil/local/qct3-witness/v3/".to_vec();
        key.extend_from_slice(context); key.extend_from_slice(&[b'/', kind]); key
    }
    pub fn ready(db: &dyn KvDb, context: &[u8; 32]) -> Result<Option<ReadyIndex>> {
        use quil_lattice_ct::confidential::coin_tree::ROOT_RECORD_BYTES;
        let Some(bytes) = db.get(&Self::metadata_key(context, b'a'))? else { return Ok(None); };
        if bytes.len() != ROOT_RECORD_BYTES && bytes.len() != 2 * ROOT_RECORD_BYTES { return Err(unavailable("invalid ready index metadata")); }
        let generation = RootRecord::decode(&bytes[..ROOT_RECORD_BYTES], context).map_err(|e| unavailable(format!("generation: {e:?}")))?;
        // Upgrade the earlier local format, whose generation and tip matched.
        let root = if bytes.len() == ROOT_RECORD_BYTES { generation.clone() } else {
            RootRecord::decode(&bytes[ROOT_RECORD_BYTES..], context).map_err(|e| unavailable(format!("tip: {e:?}")))?
        };
        if generation.coins > root.coins { return Err(unavailable("index tip precedes generation")); }
        Ok(Some(ReadyIndex { generation, root }))
    }
    pub fn ready_root(db: &dyn KvDb, context: &[u8; 32]) -> Result<Option<RootRecord>> {
        Ok(Self::ready(db, context)?.map(|ready| ready.root))
    }
    fn read_metadata(db: &dyn KvDb, context: &[u8; 32], kind: u8) -> Result<Option<RootRecord>> {
        if kind == b'a' { return Self::ready_root(db, context); }
        db.get(&Self::metadata_key(context, kind))?
            .map(|bytes| RootRecord::decode(&bytes, context).map_err(|e| unavailable(format!("metadata: {e:?}"))))
            .transpose()
    }

    /// Extend an already populated generation, atomically publishing nodes,
    /// frontier and tip only if the complete extension matches `next`.
    /// The owner serializes this with bootstrap and validates canonical roots.
    pub fn advance_ready(db: Arc<dyn KvDb>, next: &RootRecord, coins: &[CoinRecord]) -> Result<bool> {
        let Some(ready) = Self::ready(db.as_ref(), &next.context)? else { return Ok(false); };
        if &ready.root == next || next.coins < ready.root.coins { return Ok(false); }
        if coins.is_empty() || coins.len() > MAX_UPDATE_COINS
            || ready.root.coins.checked_add(coins.len() as u64) != Some(next.coins) {
            return Err(unavailable("incomplete or oversized index extension"));
        }
        let index = Self::for_root(db, &ready.generation, 32)?;
        let mut summary = index.summary_for(&ready.root)?
            .ok_or_else(|| unavailable("index does not hold its published tip"))?;
        let batch = index.db.new_batch(false)?;
        index.append_blocks(batch.as_ref(), &mut summary, coins)?;
        if index.fold(&summary)? != next.root || summary.coins() != next.coins {
            return Err(unavailable("index extension does not match canonical root"));
        }
        index.publish_summary(batch.as_ref(), next, &summary)?;
        batch.set(&Self::metadata_key(&next.context, b'a'), &ReadyIndex { generation: ready.generation, root: next.clone() }.encode()?)?;
        batch.commit()?;
        Ok(true)
    }

    /// The accumulator's one shape. Widening an application allocates more
    /// blocks inside the same index field, so the tree never changes shape and
    /// the index never has to reinterpret a key it already wrote.
    fn shape(&self) -> sharded_tree::Shape {
        sharded_tree::Shape {
            shard_bits: coin_blocks::BLOCK_INDEX_BITS,
            subtree_bits: coin_blocks::SUBTREE_BITS,
        }
    }

    /// Each block advances on its own, so its frontier and its completed nodes
    /// are keyed under it: appending to one block never rewrites another's.
    fn frontier_key(&self, block: u64) -> Vec<u8> {
        let mut key = self.prefix.clone(); key.push(b'f');
        key.extend_from_slice(&block.to_be_bytes()); key
    }
    fn node_key(&self, block: u64, level: u8, index: u64) -> Vec<u8> {
        let mut key = self.prefix.clone(); key.push(b'n');
        key.extend_from_slice(&block.to_be_bytes());
        key.push(level);
        key.extend_from_slice(&index.to_be_bytes()); key
    }
    fn block_frontier(&self, block: u64) -> Result<Frontier> {
        let subtree = usize::from(coin_blocks::SUBTREE_BITS);
        match self.db.get(&self.frontier_key(block))? {
            Some(bytes) => Frontier::decode(&bytes, &self.context, subtree),
            None => Frontier::new(&self.context, subtree),
        }.map_err(|e| unavailable(format!("frontier: {e:?}")))
    }

    /// The application root the indexed block roots fold to — the top levels
    /// of the same tree, so this is the root canonical state publishes.
    fn fold(&self, summary: &BlockSummary) -> Result<Node> {
        sharded_tree::fold_subtree_roots(&self.context, self.shape(), &summary.roots())
            .map_err(|e| unavailable(format!("fold: {e:?}")))
    }

    fn summary_key(&self, root: &RootRecord) -> Result<Vec<u8>> {
        let encoded = root.encode().map_err(|e| unavailable(format!("root: {e:?}")))?;
        let mut key = self.prefix.clone(); key.push(b'S');
        key.extend_from_slice(&Sha3_256::digest(encoded));
        Ok(key)
    }
    fn ring_key(&self) -> Vec<u8> {
        let mut key = self.prefix.clone(); key.push(b'r'); key
    }

    /// The block summary this generation holds for `root`, if it still keeps
    /// one. Absent means the index cannot answer at that root — never that a
    /// coin is missing.
    fn summary_for(&self, root: &RootRecord) -> Result<Option<BlockSummary>> {
        self.db.get(&self.summary_key(root)?)?
            .map(|bytes| BlockSummary::decode(&bytes))
            .transpose()
            .map_err(|e| unavailable(format!("summary: {e}")))
    }

    /// Record the block state at `root` and retire the oldest retained tip.
    fn publish_summary(&self, batch: &dyn Transaction, root: &RootRecord, summary: &BlockSummary) -> Result<()> {
        let key = self.summary_key(root)?;
        batch.set(&key, &summary.encode())?;
        let mut ring = self.db.get(&self.ring_key())?.unwrap_or_default();
        if ring.len() % 32 != 0 { return Err(unavailable("invalid retained tip ring")); }
        let hash = key[key.len() - 32..].to_vec();
        if ring.chunks_exact(32).any(|entry| entry == hash) { return Ok(()); }
        ring.extend_from_slice(&hash);
        while ring.len() > INDEX_SUMMARY_HISTORY * 32 {
            let mut retired = self.prefix.clone(); retired.push(b'S');
            retired.extend_from_slice(&ring[..32]);
            batch.delete(&retired)?;
            ring.drain(..32);
        }
        batch.set(&self.ring_key(), &ring)?;
        Ok(())
    }

    /// Append coins to the blocks their positions name, writing each completed
    /// node once. A coin must continue its block's sequence exactly: a gap
    /// would leave the index publishing a root no node holds.
    fn append_blocks(&self, batch: &dyn Transaction, summary: &mut BlockSummary, coins: &[CoinRecord]) -> Result<()> {
        let subtree = usize::from(coin_blocks::SUBTREE_BITS);
        let mut by_block: std::collections::BTreeMap<u64, Vec<&CoinRecord>> = std::collections::BTreeMap::new();
        for coin in coins {
            let (block, _) = coin_blocks::locate(coin.position);
            by_block.entry(block).or_default().push(coin);
        }
        for (block, mut records) in by_block {
            records.sort_by_key(|coin| coin.position);
            let mut frontier = self.block_frontier(block)?;
            for coin in records {
                let (_, local) = coin_blocks::locate(coin.position);
                if local != frontier.count() { return Err(unavailable("index update position gap")); }
                let (_, nodes) = frontier.append_with_nodes(&coin.owner, &coin.commitment)
                    .map_err(|e| unavailable(format!("append: {e:?}")))?;
                for node in nodes {
                    let key = self.node_key(block, node.level, node.index);
                    let bytes = node.node.to_bytes();
                    // Completed subtrees are immutable along an append-only
                    // history. Stale fork/cache contents require a rebuild.
                    if self.db.get(&key)?.is_some_and(|old| old != bytes) {
                        return Err(unavailable("conflicting cached subtree; rebuild required"));
                    }
                    batch.set(&key, &bytes)?;
                }
            }
            let root = frontier.root_at_depth(subtree).map_err(|e| unavailable(format!("block root: {e:?}")))?;
            batch.set(&self.frontier_key(block), &frontier.encode())?;
            summary.put(block, frontier.count(), root.root)
                .map_err(|e| unavailable(format!("summary: {e}")))?;
        }
        Ok(())
    }

    /// Populate a small batch, atomically with the blocks it touches. Both
    /// endpoint roots are checked before any write commits. The caller obtains
    /// these roots/coins from canonical execution or a retained snapshot.
    pub fn append(&mut self, previous: &RootRecord, next: &RootRecord, coins: &[CoinRecord]) -> Result<()> {
        if coins.is_empty() || coins.len() > MAX_BATCH_COINS
            || previous.context != self.context || next.context != self.context
            || previous.coins.checked_add(coins.len() as u64) != Some(next.coins) {
            return Err(unavailable("invalid append dimensions or context"));
        }
        let empty = BlockSummary::default();
        let mut summary = match self.summary_for(previous)? {
            Some(summary) => summary,
            // An index with nothing in it holds the empty root implicitly,
            // which is where every generation starts.
            None if previous.coins == 0 && self.fold(&empty)? == previous.root => empty,
            None => return Err(unavailable("previous root is not indexed; rebuild required")),
        };
        let batch = self.db.new_batch(false)?;
        self.append_blocks(batch.as_ref(), &mut summary, coins)?;
        if self.fold(&summary)? != next.root || summary.coins() != next.coins {
            return Err(unavailable("appended coins do not match the selected root"));
        }
        self.publish_summary(batch.as_ref(), next, &summary)?;
        batch.commit()
    }

    /// Bounded point reads. Cache misses/corruption return unavailability,
    /// never a negative membership answer. Recently retained roots are usable
    /// too, so a wallet proving against the root it read a moment ago is not
    /// raced out by another transaction landing first.
    ///
    /// The path is assembled the way the accumulator is built: the coin's own
    /// block supplies the lower levels from its cached completed subtrees, and
    /// the other blocks' roots — public state every node publishes — supply
    /// the top levels. So a node holding one block can serve a whole witness.
    pub fn auth_path(&self, root: &RootRecord, coin: &CoinRecord) -> Result<AuthPath> {
        let shape = self.shape();
        if root.context != self.context || usize::from(root.depth) != shape.depth() {
            return Err(unavailable("path requested against a different tree"));
        }
        let Some(summary) = self.summary_for(root)? else {
            return Err(unavailable("index does not hold the selected root"));
        };
        let (block, local) = coin_blocks::locate(coin.position);
        let count = summary.count(block);
        // Not being in the indexed block is not a negative membership answer:
        // the coin may have been added after this root was published.
        if local >= count {
            return Err(unavailable("coin is not held at the selected root"));
        }
        let block_root = summary
            .root_of(block)
            .ok_or_else(|| unavailable("indexed block has no root"))?;
        let within = RootRecord {
            context: self.context,
            depth: coin_blocks::SUBTREE_BITS,
            coins: count,
            root: block_root,
        };
        let local_coin = CoinRecord {
            address: coin.address,
            owner: coin.owner,
            commitment: coin.commitment.clone(),
            position: local,
        };
        let mut path = self
            .reader
            .get_or_init(|| IndexedTree::new(&self.context, self.max_depth)
                .expect("index depth validated at construction"))
            .auth_path(&within, &local_coin, |level, index| -> Result<Option<Node>> {
                self.db.get(&self.node_key(block, level, index))?
                    .map(|bytes| Node::from_bytes(&bytes).map_err(|e| unavailable(format!("node encoding: {e:?}"))))
                    .transpose()
            })
            .map_err(|e| unavailable(format!("path: {e:?}")))?;
        let upper = sharded_tree::fold_auth_path(&self.context, shape, &summary.roots(), block)
            .map_err(|e| unavailable(format!("fold: {e:?}")))?;
        path.siblings.extend(upper.siblings);
        path.right.extend(upper.right);
        // The index is an untrusted hint, so the assembled path is checked
        // against the caller's selected root before it is returned.
        let owner = Node::from_identity_bytes(&coin.owner)
            .map_err(|e| unavailable(format!("owner: {e:?}")))?;
        let reached = sharded_tree::ShardedCoinTree::root_from_path(
            &self.context, &owner, &coin.commitment, &path,
        )
        .map_err(|e| unavailable(format!("path: {e:?}")))?;
        if reached != root.root {
            return Err(unavailable("reconstructed path does not reach the selected root"));
        }
        Ok(path)
    }

    /// Discard only this application's local index; canonical state is untouched.
    pub fn clear(&mut self) -> Result<()> {
        let mut upper = self.prefix.clone();
        *upper.last_mut().unwrap() = b'/' + 1;
        self.db.delete_range(&self.prefix, &upper)
    }
}

/// A bounded two-phase bootstrap from one retained snapshot. Scan pages put
/// records into a local position-keyed staging area; build steps read at most
/// eight consecutive positions. Only the verified final root is published.
/// One owner serializes bootstrap for an application and drives `step` off
/// the RPC thread, yielding/cancelling between steps.
pub struct WitnessBootstrap {
    index: LocalWitnessIndex,
    snapshot: Arc<dyn quil_types::store::SnapshotReadable>,
    network: [u8; 32],
    application: [u8; 32],
    root: RootRecord,
    after: Option<[u8; 32]>,
    scanned: u64,
    scanning: bool,
    /// The block being rebuilt and its frontier. Staged coins are walked in
    /// position order, which visits one block's coins consecutively, so only
    /// one block is ever open.
    building: Option<(u64, Frontier)>,
    /// Block roots completed so far; folded into the application root once
    /// every block has been rebuilt.
    summary: BlockSummary,
    /// Where the next build step resumes in the staging area.
    resume: Option<Vec<u8>>,
    finished: bool,
}
impl WitnessBootstrap {
    pub fn new(db: Arc<dyn KvDb>, snapshot: Arc<dyn quil_types::store::SnapshotReadable>, network: &[u8; 32], application: &[u8; 32]) -> Result<Self> {
        let root = super::scan::local_snapshot_root(snapshot.as_ref(), network, application)?;
        // Malformed local metadata must not permanently block repair. Only
        // decode failures reset this context; storage I/O errors propagate.
        for kind in [b'a', b'b'] {
            match LocalWitnessIndex::read_metadata(db.as_ref(), &root.context, kind) {
                Err(QuilError::ExecutionUnavailable(_)) => LocalWitnessIndex::new(db.clone(), &root.context, 32)?.clear()?,
                Err(error) => return Err(error),
                Ok(_) => {},
            }
        }
        // Clean the previous interrupted build before creating another one.
        if let Some(old) = LocalWitnessIndex::read_metadata(db.as_ref(), &root.context, b'b')? {
            LocalWitnessIndex::clear_root(db.as_ref(), &old)?;
        }
        let mut index = LocalWitnessIndex::for_root(db, &root, 32)?;
        index.clear()?;
        index.db.set(&LocalWitnessIndex::metadata_key(&root.context, b'b'),
            &root.encode().map_err(|e| unavailable(format!("root: {e:?}")))?)?;
        Ok(Self { index, snapshot, network: *network, application: *application, root, after: None,
            scanned: 0, scanning: true, building: None, summary: BlockSummary::default(), resume: None, finished: false })
    }
    fn coin_key(&self, position: u64) -> Vec<u8> {
        let mut key = self.index.prefix.clone(); key.push(b'c'); key.extend_from_slice(&position.to_be_bytes()); key
    }
    /// The staging area's key range. Positions are big-endian, so walking it
    /// visits coins in position order: block by block, and in local order
    /// inside each block — exactly the order the accumulator appends them.
    fn staged_range(&self) -> (Vec<u8>, Vec<u8>) {
        let mut lower = self.index.prefix.clone(); lower.push(b'c');
        let mut upper = self.index.prefix.clone(); upper.push(b'd');
        (lower, upper)
    }
    /// Close the open block: its frontier is durable and its root joins the
    /// summary the application root is folded from.
    fn finish_block(&mut self, batch: &dyn Transaction) -> Result<()> {
        let Some((block, frontier)) = self.building.take() else { return Ok(()) };
        let subtree = usize::from(coin_blocks::SUBTREE_BITS);
        let root = frontier.root_at_depth(subtree).map_err(|e| unavailable(format!("block root: {e:?}")))?;
        batch.set(&self.index.frontier_key(block), &frontier.encode())?;
        self.summary.put(block, frontier.count(), root.root).map_err(|e| unavailable(format!("summary: {e}")))?;
        Ok(())
    }
    pub fn root(&self) -> &RootRecord { &self.root }

    /// Returns true only when the final root has been verified and published.
    pub fn step(&mut self) -> Result<bool> {
        if self.finished { return Ok(true); }
        if self.scanning {
            let page = super::scan::scan_local_page(self.snapshot.as_ref(), &self.network, &self.application,
                self.after.as_ref(), quil_types::store::VertexPageLimits { max_entries: 8, max_bytes: 240 * 1024 })?;
            if page.root != self.root { return Err(unavailable("bootstrap snapshot root changed")); }
            let batch = self.index.db.new_batch(false)?;
            let mut positions = std::collections::BTreeSet::new();
            for (address, coin) in &page.coins {
                let key = self.coin_key(coin.position);
                // A position names a block and a leaf inside it. Its block
                // must exist in the accumulator's shape; how full the block is
                // cannot be judged here, only when it is rebuilt in order.
                let (block, _) = coin_blocks::locate(coin.position);
                if block >= self.index.shape().shards() || !positions.insert(coin.position)
                    || self.index.db.get(&key)?.is_some() {
                    return Err(unavailable("duplicate or out-of-range bootstrap position"));
                }
                let mut value = address.to_vec(); value.extend_from_slice(&coin.output.owner);
                value.extend_from_slice(&coin.output.commitment.to_bytes());
                batch.set(&key, &value)?;
            }
            batch.commit()?;
            self.scanned += page.coins.len() as u64;
            self.after = page.cursor;
            if !page.has_more {
                if self.scanned != self.root.coins { return Err(unavailable("bootstrap snapshot has incomplete coin coverage")); }
                self.scanning = false;
            }
            return Ok(false);
        }
        // Rebuild in staged position order: a block's coins are consecutive
        // there, so each block is opened once, filled, and closed.
        let (lower, upper) = self.staged_range();
        let batch = self.index.db.new_batch(false)?;
        let mut iterator = self.index.db.new_iter(&lower, &upper)?;
        let mut valid = match &self.resume {
            Some(resume) => iterator.seek_ge(resume),
            None => iterator.first(),
        };
        let mut processed = 0;
        while valid && processed < MAX_BATCH_COINS {
            let key = iterator.key().to_vec();
            let bytes = iterator.value().to_vec();
            if key.len() != lower.len() + 8 { return Err(unavailable("bootstrap staging key")); }
            let position = u64::from_be_bytes(key[key.len() - 8..].try_into().unwrap());
            let (block, local) = coin_blocks::locate(position);
            if self.building.as_ref().is_some_and(|(open, _)| *open != block) {
                self.finish_block(batch.as_ref())?;
            }
            if self.building.is_none() {
                let subtree = usize::from(coin_blocks::SUBTREE_BITS);
                self.building = Some((block, Frontier::new(&self.root.context, subtree)
                    .map_err(|e| unavailable(format!("frontier: {e:?}")))?));
            }
            let (_, frontier) = self.building.as_mut().expect("opened above");
            // A block holds its coins at consecutive local indices, so a gap
            // means the snapshot did not carry every coin of that block.
            if local != frontier.count() { return Err(unavailable("bootstrap position gap")); }
            if bytes.len() != 32 + IDENTITY_BYTES + quil_lattice_ct::confidential::COMMITMENT_BYTES { return Err(unavailable("bootstrap record length")); }
            let owner: [u8; IDENTITY_BYTES] = bytes[32..32 + IDENTITY_BYTES].try_into().unwrap();
            let commitment = quil_lattice_ct::confidential::AmountCommitment::from_bytes(&bytes[32 + IDENTITY_BYTES..])
                .map_err(|e| unavailable(format!("commitment: {e:?}")))?;
            // This generation was cleared at construction and has one writer.
            // Compute each node once; no whole-tree reconstruction per batch.
            let (_, nodes) = frontier.append_with_nodes(&owner, &commitment)
                .map_err(|e| unavailable(format!("append: {e:?}")))?;
            for node in nodes { batch.set(&self.index.node_key(block, node.level, node.index), &node.node.to_bytes())?; }
            let mut resume = key; resume.push(0);
            self.resume = Some(resume);
            processed += 1;
            valid = iterator.next();
        }
        iterator.close()?;
        if valid {
            batch.commit()?;
            return Ok(false);
        }
        self.finish_block(batch.as_ref())?;
        if self.index.fold(&self.summary)? != self.root.root || self.summary.coins() != self.root.coins {
            return Err(unavailable("bootstrap reconstructed root mismatch"));
        }
        self.index.publish_summary(batch.as_ref(), &self.root, &self.summary)?;
        let previous = LocalWitnessIndex::ready(self.index.db.as_ref(), &self.root.context)?;
        batch.set(&LocalWitnessIndex::metadata_key(&self.root.context, b'a'),
            &ReadyIndex { generation: self.root.clone(), root: self.root.clone() }.encode()?)?;
        batch.delete(&LocalWitnessIndex::metadata_key(&self.root.context, b'b'))?;
        batch.delete_range(&lower, &upper)?;
        batch.commit()?;
        self.finished = true;
        if let Some(old) = previous.filter(|old| old.generation != self.root) {
            LocalWitnessIndex::clear_root(self.index.db.as_ref(), &old.generation)?;
        }
        Ok(true)
    }
}

/// Apply bounded durable vertex notifications. They are hints: coverage,
/// retained roots, record content addresses and the resulting root are checked.
/// Any error leaves consensus untouched; RPC bootstrap repairs missed updates.
pub fn apply_vertex_updates(
    state: &crate::hypergraph_state::HypergraphState, db: Arc<dyn KvDb>, network: &[u8; 32],
    vertices: &[(Vec<u8>, Vec<u8>)],
) -> Result<usize> {
    if vertices.len() > MAX_UPDATE_VERTICES || vertices.iter().try_fold(0usize, |size, (key, value)|
        size.checked_add(key.len()).and_then(|size| size.checked_add(value.len()))).is_none_or(|size| size > MAX_UPDATE_BYTES) {
        return Err(unavailable("oversized vertex notification"));
    }
    let mut roots = std::collections::BTreeMap::new();
    for (key, value) in vertices {
        // The node-local root record, or a legacy root vertex.
        let application = super::state::local_record_application(key, &super::state::ROOT_ADDRESS).or_else(||
            (key.len() == 64 && key[32..] == super::state::ROOT_ADDRESS).then(|| key[..32].try_into().unwrap()));
        if let Some(application) = application {
            let context = quil_lattice_ct::confidential::transfer::parameter_context(network, &application);
            roots.insert(application, super::roots::decode_current(value, &context)?);
        }
    }
    let mut updated = 0;
    for (application, next) in roots {
        let Some(ready) = LocalWitnessIndex::ready(db.as_ref(), &next.context)? else { continue; };
        if next.coins < ready.root.coins || next == ready.root { continue; }
        state.require_full_domain_coverage(&application)?;
        if !super::roots::accepts_root(state, network, &application, next.depth, &next.root)? {
            return Err(unavailable("notified root is not retained"));
        }
        // Which coins are new is decided per block, not by a single count:
        // a coin whose block already holds its local index is one this index
        // has, and `advance_ready` refuses a gap rather than skipping a coin.
        let index = LocalWitnessIndex::for_root(db.clone(), &ready.generation, 32)?;
        let held = index.summary_for(&ready.root)?.unwrap_or_default();
        let mut coins = Vec::new();
        for (key, value) in vertices {
            if key.len() == 64 && key[..32] == application {
                if let Some(coin) = super::state::decode_snapshot_coin(&next.context, &application, key, value)? {
                    let (block, local) = super::coin_blocks::locate(coin.position);
                    if local >= held.count(block) { coins.push(coin); }
                }
            }
        }
        coins.sort_by_key(|coin| coin.position);
        if coins.is_empty() { continue; }
        updated += usize::from(LocalWitnessIndex::advance_ready(db.clone(), &next, &coins)?);
    }
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_lattice_ct::confidential::{sharded_tree::ShardedCoinTree, AmountOpening, CommitmentKey};

    /// Coins spread over several blocks, at the positions the accumulator
    /// would place them: two in one block, then one each in two others, so
    /// every fixture here exercises both the within-block levels and the fold.
    fn block_coins(context: &[u8; 32]) -> Vec<CoinRecord> {
        let key = CommitmentKey::derive(context);
        let width = coin_blocks::INITIAL_BLOCK_BITS;
        [(0u64, 0u64), (0, 1), (5, 0), (33, 0)]
            .iter()
            .enumerate()
            .map(|(i, (path, local))| {
                let block = coin_blocks::block_id(width, *path).unwrap();
                CoinRecord {
                    address: [i as u8; 32],
                    position: coin_blocks::position(width, block, *local).unwrap(),
                    owner: [i as u8; IDENTITY_BYTES],
                    commitment: key.commit(i as u128, &AmountOpening::from_seed(context, &[i as u8; 32])),
                }
            })
            .collect()
    }

    fn accumulator_shape() -> quil_lattice_ct::confidential::sharded_tree::Shape {
        quil_lattice_ct::confidential::sharded_tree::Shape {
            shard_bits: coin_blocks::BLOCK_INDEX_BITS,
            subtree_bits: coin_blocks::SUBTREE_BITS,
        }
    }

    fn accumulator(context: &[u8; 32], coins: &[CoinRecord]) -> ShardedCoinTree {
        ShardedCoinTree::build(context, accumulator_shape(), coins).unwrap()
    }

    #[test]
    fn ready_generation_advances_atomically_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap(); let context = [19; 32];
        let coins = block_coins(&context);
        let depth = accumulator_shape().depth();
        let root = |count: usize| accumulator(&context, &coins[..count]).root_at_depth(depth).unwrap();
        let generation = root(2);
        let (second_block, _) = coin_blocks::locate(coins[2].position);
        {
            let db = Arc::new(quil_store::RocksDb::open(dir.path()).unwrap());
            let mut index = LocalWitnessIndex::for_root(db.clone(), &generation, 32).unwrap();
            index.append(&root(0), &generation, &coins[..2]).unwrap();
            // Prior local format remains readable and upgrades on advancement.
            db.set(&LocalWitnessIndex::metadata_key(&context, b'a'), &generation.encode().unwrap()).unwrap();
            let mut wrong = root(3); wrong.root = Node::zero();
            assert!(LocalWitnessIndex::advance_ready(db.clone(), &wrong, &coins[2..3]).is_err());
            assert_eq!(LocalWitnessIndex::ready_root(db.as_ref(), &context).unwrap(), Some(generation.clone()));
            // A refused extension leaves nothing of the block it would open.
            assert!(db.get(&index.frontier_key(second_block)).unwrap().is_none());
            assert!(LocalWitnessIndex::advance_ready(db.clone(), &root(4), &coins[3..]).is_err());
            assert!(LocalWitnessIndex::advance_ready(db.clone(), &root(3), &coins[2..3]).unwrap());
            assert!(!LocalWitnessIndex::advance_ready(db.clone(), &root(3), &coins[2..3]).unwrap());
            assert!(LocalWitnessIndex::advance_ready(db, &root(4), &coins[3..]).unwrap());
        }
        let db = Arc::new(quil_store::RocksDb::open(dir.path()).unwrap());
        let ready = LocalWitnessIndex::ready(db.as_ref(), &context).unwrap().unwrap();
        assert_eq!(ready.generation, generation); assert_eq!(ready.root, root(4));
        let index = LocalWitnessIndex::for_root(db, &ready.generation, 32).unwrap();
        // A root the generation still retains serves paths, so a wallet that
        // read the accumulator a moment ago is not raced out by a newer coin.
        index.auth_path(&generation, &coins[0]).unwrap();
        index.auth_path(&ready.root, &coins[3]).unwrap();
        // A coin added after the older root is not served against it.
        assert!(index.auth_path(&generation, &coins[3]).is_err());
    }

    #[test]
    fn bounded_bootstrap_publishes_only_complete_roots_and_serves_point_witnesses() {
        use crate::{hypergraph_state::{HypergraphState, vertex_adds_discriminator}, token_intrinsic::{roots,
            state::SnapshotLimits, witnesses::indexed_witnesses}};
        use quil_lattice_ct::confidential::transfer::{parameter_context, Output};
        use quil_types::crypto::NoopInclusionProver;
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(quil_store::RocksDb::open(dir.path()).unwrap());
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(store.clone(), Arc::new(NoopInclusionProver))));
        let network = [1; 32]; let application = [2; 32]; let context = parameter_context(&network, &application);
        let key = CommitmentKey::derive(&context);
        let disc = vertex_adds_discriminator().unwrap();
        let limits = SnapshotLimits { max_coins: 16, max_depth: 4, max_nodes: 40 };
        let mut addresses = Vec::new();
        // One staging map across the whole fixture: coins landing in the same
        // block take consecutive local indices, exactly as a transaction does.
        let mut staged = std::collections::BTreeMap::new();
        let width = roots::block_width(&state, &application).unwrap();
        let mut positions = Vec::new();
        for position in 0..10u8 {
            let output = Output { owner: [position; IDENTITY_BYTES], memo: [0; 1115],
                commitment: key.commit(u128::from(position), &AmountOpening::from_seed(&context, &[position; 32])) };
            let (address, tree) = roots::stage_coin(
                &state, &network, &application, &context, 1, &output, &mut staged, limits,
            )
            .unwrap();
            let block = super::super::coin_blocks::block_for_address(width, &address).unwrap();
            positions.push(super::super::coin_blocks::position(width, block, staged[&block] - 1).unwrap());
            addresses.push(address);
            state.set(&application, &address, &disc, 1, quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()).unwrap();
        }
        let first = roots::refresh_root(&state, &network, &application, limits).unwrap();
        state.commit().unwrap(); state.abort(); state.crdt().commit(1).unwrap();
        let snapshot = store.capture_snapshot().unwrap();
        let mut broken = WitnessBootstrap::new(db.clone(), snapshot.clone(), &network, &application).unwrap();
        let mut scans = 0;
        while broken.scanning { assert!(!broken.step().unwrap()); scans += 1; }
        assert!(scans >= 2);
        // A staging gap must not publish even a partial root. The build may
        // get as far as the fold before noticing — what must never happen is
        // that it finishes and publishes one.
        db.delete(&broken.coin_key(*positions.iter().min().unwrap())).unwrap();
        let refused = loop {
            match broken.step() {
                Ok(true) => break false,
                Ok(false) => continue,
                Err(_) => break true,
            }
        };
        assert!(refused, "a gap in the staged coins must not publish a root");
        assert!(LocalWitnessIndex::ready_root(db.as_ref(), &context).unwrap().is_none());
        drop(broken);
        // Restart cleans the interrupted generation's staging/index data.
        let mut builder = WitnessBootstrap::new(db.clone(), snapshot, &network, &application).unwrap();
        let mut steps = 0;
        while !builder.step().unwrap() { steps += 1; assert!(steps < 10); }
        assert!(steps >= 3);
        assert_eq!(LocalWitnessIndex::ready_root(db.as_ref(), &context).unwrap(), Some(first.clone()));
        assert!(db.get(&builder.coin_key(0)).unwrap().is_none());
        let index = LocalWitnessIndex::for_root(db.clone(), &first, 32).unwrap();
        let witnesses = indexed_witnesses(&state, &network, &application, &addresses[..4], first.clone(), &index).unwrap();
        assert!(witnesses.coins.iter().all(|coin| coin.path.is_some()));
        assert!(indexed_witnesses(&state, &network, &application, &[[255; 32]], first.clone(), &index).unwrap().coins[0].path.is_none());
        // A newly committed coin is not reported absent against the older root.
        let output = Output { owner: [10; IDENTITY_BYTES], memo: [0; 1115], commitment: key.commit(10, &AmountOpening::from_seed(&context, &[10; 32])) };
        // A second transaction stages against committed state, so it starts
        // with an empty per-block tally of its own.
        let mut later = std::collections::BTreeMap::new();
        let (address, tree) = roots::stage_coin(
            &state, &network, &application, &context, 2, &output, &mut later, limits,
        )
        .unwrap();
        state.set(&application, &address, &disc, 2, quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()).unwrap();
        let next = roots::refresh_root(&state, &network, &application, limits).unwrap();
        state.commit().unwrap(); state.abort(); state.crdt().commit(2).unwrap();
        assert!(matches!(indexed_witnesses(&state, &network, &application, &[address], first.clone(), &index), Err(QuilError::ExecutionUnavailable(_))));
        assert!(indexed_witnesses(&state, &network, &application, &addresses[..1], first.clone(), &index).is_ok());
        let mut builder = WitnessBootstrap::new(db.clone(), store.capture_snapshot().unwrap(), &network, &application).unwrap();
        while !builder.step().unwrap() {}
        let (first_block, _) = super::super::coin_blocks::locate(0);
        let old_frontier_key = index.frontier_key(first_block);
        let index = LocalWitnessIndex::for_root(db.clone(), &next, 32).unwrap();
        assert!(indexed_witnesses(&state, &network, &application, &[address], next.clone(), &index).unwrap().coins[0].path.is_some());
        assert!(db.get(&old_frontier_key).unwrap().is_none());
        // Losing the block state for a root makes the index unavailable at it,
        // never a claim that a coin is absent. (A corrupt cached NODE is
        // covered by `local_index_reopens_and_rejects_incomplete_or_corrupt_updates`,
        // whose fixture puts two coins in one block so the node is read.)
        db.delete(&index.summary_key(&next).unwrap()).unwrap();
        assert!(matches!(indexed_witnesses(&state, &network, &application, &addresses[..1], next.clone(), &index), Err(QuilError::ExecutionUnavailable(_))));
        db.set(&LocalWitnessIndex::metadata_key(&context, b'a'), b"corrupt ready pointer").unwrap();
        let mut repair = WitnessBootstrap::new(db.clone(), store.capture_snapshot().unwrap(), &network, &application).unwrap();
        while !repair.step().unwrap() {}
        assert_eq!(LocalWitnessIndex::ready_root(db.as_ref(), &context).unwrap(), Some(next.clone()));
        assert!(indexed_witnesses(&state, &network, &application, &addresses[..1], next, &index).is_ok());
    }

    #[test]
    fn local_index_reopens_and_rejects_incomplete_or_corrupt_updates() {
        let dir = tempfile::tempdir().unwrap();
        let context = [5; 32];
        let coins = block_coins(&context);
        let depth = accumulator_shape().depth();
        let tree = |count: usize| accumulator(&context, &coins[..count]);
        let root = |count: usize| tree(count).root_at_depth(depth).unwrap();
        // The first two coins share a block; the rest sit in their own.
        let (first_block, _) = coin_blocks::locate(coins[0].position);
        let (last_block, _) = coin_blocks::locate(coins[3].position);
        {
            let db = Arc::new(quil_store::RocksDb::open(dir.path()).unwrap());
            let mut index = LocalWitnessIndex::new(db.clone(), &context, 32).unwrap();
            index.append(&root(0), &root(3), &coins[..3]).unwrap();
            let mut wrong = root(4); wrong.root = Node::zero();
            assert!(index.append(&root(3), &wrong, &coins[3..]).is_err());
            assert_eq!(index.block_frontier(first_block).unwrap().count(), 2);
            // A refused extension writes nothing of the block it would open.
            assert!(db.get(&index.frontier_key(last_block)).unwrap().is_none());
            index.append(&root(3), &root(4), &coins[3..]).unwrap();
            assert!(index.append(&root(3), &root(4), &coins[3..]).is_err());
        }
        let db = Arc::new(quil_store::RocksDb::open(dir.path()).unwrap());
        let mut index = LocalWitnessIndex::new(db.clone(), &context, 32).unwrap();
        // Every served path must equal the one a node holding every coin
        // builds — the whole point of folding block roots into one tree.
        for count in [3, 4] {
            for coin in &coins[..count] {
                let path = index.auth_path(&root(count), coin).unwrap();
                let full = tree(count).auth_path_at_depth(&coin.address, depth).unwrap();
                assert_eq!(path.siblings, full.siblings); assert_eq!(path.right, full.right);
            }
        }
        // A corrupt or missing cached node is an availability failure, never
        // a claim that the coin is absent.
        let sibling = index.node_key(first_block, 0, 1);
        db.set(&sibling, &Node::zero().to_bytes()).unwrap();
        assert!(index.auth_path(&root(4), &coins[0]).is_err());
        db.delete(&sibling).unwrap();
        assert!(index.auth_path(&root(4), &coins[0]).is_err());
        let other = LocalWitnessIndex::new(db.clone(), &[6; 32], 32).unwrap();
        db.set(&other.frontier_key(first_block), b"unrelated application").unwrap();
        index.clear().unwrap();
        assert_eq!(index.block_frontier(first_block).unwrap().count(), 0);
        assert!(db.get(&index.node_key(first_block, 1, 0)).unwrap().is_none());
        assert_eq!(db.get(&other.frontier_key(first_block)).unwrap().unwrap(), b"unrelated application");
        index.append(&root(0), &root(4), &coins).unwrap();
        index.auth_path(&root(4), &coins[0]).unwrap();
    }
}

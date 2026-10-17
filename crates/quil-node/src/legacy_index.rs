//! Node-local index of an application's legacy (transparent) coins by owner.
//!
//! Legacy coins were written once, by the verenc→transparent migration, and
//! never change: shielding consumes one through a GLOBAL marker without
//! touching the coin. So the index is built once, by one pass over the
//! application's vertices, and needs no upkeep afterwards. Only a node that
//! holds the whole application (an archive) builds it; other nodes ask an
//! archive.
//!
//! Keys, in the node's KV store and outside every tree:
//!
//! ```text
//! PREFIX ‖ application ‖ 'o' ‖ owner(32) ‖ address(32) → amount(16, LE) ‖ origin(32)
//! PREFIX ‖ application ‖ 'p' → swept(1) ‖ swept-through address(32) ‖ coins(8, BE) ‖ done(1)
//! ```
//!
//! The pass pages the vertex keyspace in address order, each page from a
//! fresh store snapshot (the coins never change, so pages need not share
//! one), and records how far it has swept with every page, so a restart
//! resumes where it stopped.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use quil_types::error::{QuilError, Result};
use quil_types::store::{HypergraphStore, KvDb, VertexPageLimits};

const PREFIX: &[u8] = b"quil/local/legacy-owner/v1/";
/// Vertices one sweep page reads, and the bytes it may hold.
const SWEEP_PAGE: VertexPageLimits = VertexPageLimits { max_entries: 4096, max_bytes: 16 * 1024 * 1024 };
/// Pause between sweep pages, so the pass yields the disk to serving.
const SWEEP_PAUSE: std::time::Duration = std::time::Duration::from_millis(5);
/// Sweep pages between progress lines.
const REPORT_EVERY: u64 = 256;

/// One indexed legacy coin: `(address, amount, origin)`.
pub(crate) type LegacyCoin = ([u8; 32], u128, [u8; 32]);

pub(crate) struct LegacyOwnerIndex {
    db: Arc<dyn KvDb>,
    store: Arc<dyn HypergraphStore>,
    application: [u8; 32],
    type_hash: [u8; 32],
    done: AtomicBool,
}

struct Progress {
    swept_through: Option<[u8; 32]>,
    coins: u64,
    done: bool,
}

impl LegacyOwnerIndex {
    pub(crate) fn new(db: Arc<dyn KvDb>, store: Arc<dyn HypergraphStore>, application: [u8; 32]) -> Result<Arc<Self>> {
        let type_hash = quil_execution::token_intrinsic::legacy_migration::transparent_type_hash(&application)?;
        let index = Arc::new(Self { db, store, application, type_hash, done: AtomicBool::new(false) });
        let done = index.progress()?.done;
        index.done.store(done, Ordering::Release);
        Ok(index)
    }

    /// The index for `application`, and its build started in the background
    /// unless a previous run finished it.
    pub(crate) fn start(
        db: Arc<dyn KvDb>,
        store: Arc<dyn HypergraphStore>,
        application: [u8; 32],
        spawner: &quil_lifecycle::DetachedSpawner<anyhow::Error>,
    ) -> Result<Arc<Self>> {
        let index = Self::new(db, store, application)?;
        if !index.ready() {
            let builder = index.clone();
            spawner.detach("legacy-owner-index", async move {
                match tokio::task::spawn_blocking(move || builder.build(SWEEP_PAUSE)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => tracing::warn!(%error, "legacy owner index: build failed; it resumes on restart"),
                    Err(error) => tracing::warn!(%error, "legacy owner index: build task failed"),
                }
                Ok(())
            });
        }
        Ok(index)
    }

    /// Whether every legacy coin is indexed.
    pub(crate) fn ready(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    fn key(&self, tag: u8) -> Vec<u8> {
        let mut key = Vec::with_capacity(PREFIX.len() + 32 + 1 + 64);
        key.extend_from_slice(PREFIX);
        key.extend_from_slice(&self.application);
        key.push(tag);
        key
    }

    fn coin_key(&self, owner: &[u8; 32], address: &[u8; 32]) -> Vec<u8> {
        let mut key = self.key(b'o');
        key.extend_from_slice(owner);
        key.extend_from_slice(address);
        key
    }

    fn progress(&self) -> Result<Progress> {
        let Some(bytes) = self.db.get(&self.key(b'p'))? else {
            return Ok(Progress { swept_through: None, coins: 0, done: false });
        };
        if bytes.len() != 42 || bytes[0] > 1 || bytes[41] > 1 {
            return Err(QuilError::Store("legacy owner index: malformed progress record".into()));
        }
        Ok(Progress {
            swept_through: (bytes[0] == 1).then(|| bytes[1..33].try_into().unwrap()),
            coins: u64::from_be_bytes(bytes[33..41].try_into().unwrap()),
            done: bytes[41] == 1,
        })
    }

    fn encode_progress(progress: &Progress) -> Vec<u8> {
        let mut record = vec![u8::from(progress.swept_through.is_some())];
        record.extend_from_slice(&progress.swept_through.unwrap_or([0; 32]));
        record.extend_from_slice(&progress.coins.to_be_bytes());
        record.push(u8::from(progress.done));
        record
    }

    /// Sweep the application's vertices from where the last run stopped,
    /// indexing every transparent coin.
    pub(crate) fn build(&self, pause: std::time::Duration) -> Result<()> {
        let mut progress = self.progress()?;
        if progress.done {
            self.done.store(true, Ordering::Release);
            return Ok(());
        }
        let shard = quil_hypergraph::addressing::shard_key_for_location(&quil_hypergraph::addressing::Location {
            app_address: self.application,
            data_address: [0; 32],
        });
        tracing::info!(application = %hex::encode(self.application), resumed_at = ?progress.swept_through.map(hex::encode),
            coins = progress.coins, "legacy owner index: building");
        let started = std::time::Instant::now();
        let mut pages = 0u64;
        loop {
            let snapshot = self.store.capture_tree_snapshot()?
                .ok_or_else(|| QuilError::ExecutionUnavailable("legacy owner index: store cannot snapshot".into()))?;
            let page = snapshot.page_vertex_underlying_fixed_skipping(
                "vertex", "adds", &shard, &self.application, progress.swept_through.as_ref(), SWEEP_PAGE, &|_| false,
            )?;
            drop(snapshot);
            let batch = self.db.new_batch(false)?;
            for (address, blob) in &page.entries {
                if let Some((owner, amount, origin)) =
                    quil_execution::token_intrinsic::legacy_migration::read_transparent_coin(blob, &self.type_hash)
                {
                    let mut value = amount.to_le_bytes().to_vec();
                    value.extend_from_slice(&origin);
                    batch.set(&self.coin_key(&owner, address), &value)?;
                    progress.coins += 1;
                }
            }
            if let Some((last, _)) = page.entries.last() {
                progress.swept_through = Some(*last);
            }
            progress.done = !page.has_more;
            batch.set(&self.key(b'p'), &Self::encode_progress(&progress))?;
            batch.commit()?;
            pages += 1;
            if progress.done {
                self.done.store(true, Ordering::Release);
                tracing::info!(application = %hex::encode(self.application), coins = progress.coins,
                    secs = started.elapsed().as_secs(), "legacy owner index: complete");
                return Ok(());
            }
            if pages % REPORT_EVERY == 0 {
                tracing::info!(swept_through = %hex::encode(&progress.swept_through.unwrap_or_default()[..4]),
                    coins = progress.coins, pages, secs = started.elapsed().as_secs(), "legacy owner index: building");
            }
            if !pause.is_zero() {
                std::thread::sleep(pause);
            }
        }
    }

    /// Up to `limit` of `owner`'s coins after `after`, ascending by address,
    /// and whether more follow. `None` until the index is complete: a partial
    /// index would silently omit coins.
    pub(crate) fn page(&self, owner: &[u8; 32], after: Option<&[u8; 32]>, limit: usize) -> Result<Option<(Vec<LegacyCoin>, bool)>> {
        if !self.ready() {
            return Ok(None);
        }
        let lower = match after {
            Some(after) => {
                let mut key = self.coin_key(owner, after);
                key.push(0);
                key
            }
            None => self.coin_key(owner, &[0; 32]),
        };
        let mut upper = self.coin_key(owner, &[0xff; 32]);
        upper.push(0);
        let mut iter = self.db.new_iter(&lower, &upper)?;
        let start = self.coin_key(owner, &[0; 32]).len() - 32;
        let mut coins = Vec::new();
        let mut valid = iter.first();
        while valid && coins.len() < limit {
            let (key, value) = (iter.key(), iter.value());
            if key.len() != start + 32 || value.len() != 48 {
                iter.close()?;
                return Err(QuilError::Store("legacy owner index: malformed entry".into()));
            }
            coins.push((
                key[start..].try_into().unwrap(),
                u128::from_le_bytes(value[..16].try_into().unwrap()),
                value[16..].try_into().unwrap(),
            ));
            valid = iter.next();
        }
        iter.close()?;
        Ok(Some((coins, valid)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_execution::token_intrinsic::legacy_migration::{create_transparent_coin_tree, transparent_type_hash, TransparentCoin};

    const APP: [u8; 32] = [0x33; 32];

    fn seeded(owners: &[[u8; 32]], per_owner: u8) -> (Arc<dyn KvDb>, Arc<quil_store::RocksHypergraphStore>, Vec<(usize, [u8; 32], u128)>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = quil_store::RocksDb::open(dir.path()).unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = quil_hypergraph::HypergraphCrdt::new(store.clone(), Arc::new(quil_types::crypto::NoopInclusionProver));
        crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE));
        let th = transparent_type_hash(&APP).unwrap();
        let mut expected = Vec::new();
        for (o, owner) in owners.iter().enumerate() {
            for i in 0..per_owner {
                let amount = u128::from(i) * 1_000 + o as u128;
                let mut origin = [0u8; 32];
                origin[0] = o as u8;
                origin[1] = i;
                let tree = create_transparent_coin_tree(&TransparentCoin { owner_address: *owner, amount }, &th, &origin).unwrap();
                let address = quil_execution::token_intrinsic::materialize::coin_content_address(&tree).unwrap();
                let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
                crdt.add_vertex(&quil_hypergraph::Location { app_address: APP, data_address: address }, &blob).unwrap();
                expected.push((o, address, amount));
            }
        }
        // Vertices that are not legacy coins are passed over.
        for d in 0u8..20 {
            crdt.add_vertex(&quil_hypergraph::Location { app_address: APP, data_address: [d; 32] }, &[d; 300]).unwrap();
        }
        crdt.commit(1).unwrap();
        let kv: Arc<dyn KvDb> = Arc::new(db);
        (kv, store, expected, dir)
    }

    #[test]
    fn the_index_lists_each_owner_coins_in_address_order_and_resumes() {
        let owners = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let (db, store, expected, _dir) = seeded(&owners, 40);
        let index = LegacyOwnerIndex::new(db.clone(), store.clone(), APP).unwrap();
        assert!(index.page(&owners[0], None, 10).unwrap().is_none(), "nothing is listed before the build completes");

        index.build(std::time::Duration::ZERO).unwrap();
        assert!(index.ready());
        let reopened = LegacyOwnerIndex::new(db, store, APP).unwrap();
        assert!(reopened.ready(), "completion survives a restart");

        for (o, owner) in owners.iter().enumerate() {
            let mut want: Vec<([u8; 32], u128)> = expected.iter().filter(|(eo, _, _)| *eo == o).map(|(_, a, m)| (*a, *m)).collect();
            want.sort();
            let mut got = Vec::new();
            let mut after = None;
            loop {
                let (coins, more) = reopened.page(owner, after.as_ref(), 16).unwrap().unwrap();
                assert!(coins.len() <= 16);
                after = coins.last().map(|(address, _, _)| *address).or(after);
                got.extend(coins.into_iter().map(|(address, amount, origin)| {
                    assert_eq!(origin[0] as usize, o);
                    (address, amount)
                }));
                if !more { break; }
            }
            assert_eq!(got, want, "owner {o}");
        }
        assert_eq!(reopened.page(&[9; 32], None, 16).unwrap().unwrap(), (Vec::new(), false));
    }

    #[test]
    fn a_build_resumes_from_its_recorded_progress() {
        let owners = [[4u8; 32]];
        let (db, store, expected, _dir) = seeded(&owners, 30);
        let index = LegacyOwnerIndex::new(db.clone(), store.clone(), APP).unwrap();
        // Record progress part way: as if a run stopped after its first page.
        let mut sorted: Vec<[u8; 32]> = expected.iter().map(|(_, a, _)| *a).collect();
        sorted.sort();
        let stop = sorted[9];
        let record = LegacyOwnerIndex::encode_progress(&Progress { swept_through: Some(stop), coins: 0, done: false });
        db.set(&index.key(b'p'), &record).unwrap();
        index.build(std::time::Duration::ZERO).unwrap();
        let (coins, more) = index.page(&owners[0], None, 512).unwrap().unwrap();
        assert!(!more);
        // The resumed pass indexes only what lies past the recorded point.
        let listed: Vec<[u8; 32]> = coins.iter().map(|(a, _, _)| *a).collect();
        assert_eq!(listed, sorted[10..].to_vec());
    }
}

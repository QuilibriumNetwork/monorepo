//! Supply summary. The node's commit observer only queues vertex keys;
//! all scanning, decoding and index writes happen on this background worker.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use quil_hypergraph::{shard_key_for_location, HypergraphCrdt, Location};
use quil_types::error::{QuilError, Result};
use quil_types::store::{
    HypergraphStore, KvDb, LocalVertexCommitObserver, SnapshotReadable, VertexPageLimits,
};

const QUIL: [u8; 32] = quil_execution::domains::QUIL_TOKEN;
const GLOBAL: [u8; 32] = quil_execution::domains::GLOBAL;
const INDEX_PREFIX: &[u8] = &[quil_store::encoding::EXPLORER_SUPPLY, 1];
const INDEX_END: &[u8] = &[quil_store::encoding::EXPLORER_SUPPLY, 2];
const LEGACY_INDEX_PREFIX: &[u8] = b"\0explorer-supply-v1/";
const LEGACY_INDEX_END: &[u8] = b"\0explorer-supply-v2/";
const EVENT_KEYS_LIMIT: usize = 16_384;
const EVENT_QUEUE_LIMIT: usize = 256;
static TOKEN_TYPES: OnceLock<(Option<[u8; 32]>, Option<[u8; 32]>)> = OnceLock::new();

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SupplyCounts {
    pub transparent_coins: u64,
    pub transparent_subunits: u128,
    pub reward_provers: u64,
    pub reward_subunits: u128,
    pub value_hidden_coins: u64,
    pub scanned: usize,
}

impl SupplyCounts {
    fn change(&mut self, old: Option<Contribution>, new: Option<Contribution>) {
        if let Some(old) = old {
            self.scanned = self.scanned.saturating_sub(1);
            match old {
                Contribution::Other => {}
                Contribution::Transparent(amount) => {
                    self.transparent_coins = self.transparent_coins.saturating_sub(1);
                    self.transparent_subunits = self.transparent_subunits.saturating_sub(amount);
                }
                Contribution::Hidden => {
                    self.value_hidden_coins = self.value_hidden_coins.saturating_sub(1);
                }
                Contribution::Reward(amount) => {
                    self.reward_provers = self.reward_provers.saturating_sub(1);
                    self.reward_subunits = self.reward_subunits.saturating_sub(amount);
                }
            }
        }
        if let Some(new) = new {
            self.scanned = self.scanned.saturating_add(1);
            match new {
                Contribution::Other => {}
                Contribution::Transparent(amount) => {
                    self.transparent_coins = self.transparent_coins.saturating_add(1);
                    self.transparent_subunits = self.transparent_subunits.saturating_add(amount);
                }
                Contribution::Hidden => {
                    self.value_hidden_coins = self.value_hidden_coins.saturating_add(1);
                }
                Contribution::Reward(amount) => {
                    self.reward_provers = self.reward_provers.saturating_add(1);
                    self.reward_subunits = self.reward_subunits.saturating_add(amount);
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Contribution {
    Other,
    Transparent(u128),
    Hidden,
    Reward(u128),
}

impl Contribution {
    fn encode(self) -> Vec<u8> {
        match self {
            Self::Other => vec![0],
            Self::Transparent(amount) => {
                let mut bytes = vec![1];
                bytes.extend_from_slice(&amount.to_le_bytes());
                bytes
            }
            Self::Hidden => vec![2],
            Self::Reward(amount) => {
                let mut bytes = vec![3];
                bytes.extend_from_slice(&amount.to_le_bytes());
                bytes
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        match bytes {
            [0] => Ok(Self::Other),
            [2] => Ok(Self::Hidden),
            [1, amount @ ..] if amount.len() == 16 => Ok(Self::Transparent(u128::from_le_bytes(
                amount.try_into().unwrap(),
            ))),
            [3, amount @ ..] if amount.len() == 16 => Ok(Self::Reward(u128::from_le_bytes(
                amount.try_into().unwrap(),
            ))),
            _ => Err(QuilError::Store(
                "invalid explorer supply index entry".into(),
            )),
        }
    }
}

struct Event {
    sequence: u64,
    keys: Vec<[u8; 64]>,
}

#[derive(Default)]
struct RebuildBackoff {
    last_finished: Option<Instant>,
    retries: u32,
}

impl RebuildBackoff {
    fn delay(&mut self, now: Instant) -> Duration {
        let Some(last_finished) = self.last_finished else {
            return Duration::ZERO;
        };
        if now.duration_since(last_finished) >= Duration::from_secs(120) {
            self.retries = 0;
            return Duration::ZERO;
        }
        self.retries = (self.retries + 1).min(6);
        Duration::from_secs((1u64 << self.retries).min(60))
    }

    fn finished(&mut self, now: Instant) {
        self.last_finished = Some(now);
    }
}

pub struct SupplyIndex {
    counts: RwLock<Option<SupplyCounts>>,
    lost: AtomicBool,
    sequence: AtomicU64,
    sender: SyncSender<Event>,
}

impl SupplyIndex {
    pub fn start(
        crdt: Arc<HypergraphCrdt>,
        store: Arc<dyn HypergraphStore>,
        db: Arc<dyn KvDb>,
    ) -> (Arc<Self>, SupplyIndexRunner) {
        let (sender, receiver) = mpsc::sync_channel(EVENT_QUEUE_LIMIT);
        let index = Arc::new(Self {
            counts: RwLock::new(None),
            lost: AtomicBool::new(false),
            sequence: AtomicU64::new(0),
            sender,
        });
        crdt.add_local_vertex_observer(index.clone());
        (
            index.clone(),
            SupplyIndexRunner {
                crdt,
                store,
                db,
                index,
                receiver,
            },
        )
    }

    pub(crate) fn read(&self) -> Option<SupplyCounts> {
        let counts = self.counts.read();
        if self.lost.load(Ordering::Acquire) {
            None
        } else {
            *counts
        }
    }

    fn mark_lost(&self) {
        self.lost.store(true, Ordering::Release);
        *self.counts.write() = None;
    }

    #[cfg(test)]
    pub(crate) fn ready_for_test(counts: SupplyCounts) -> Arc<Self> {
        let (sender, _receiver) = mpsc::sync_channel(1);
        Arc::new(Self {
            counts: RwLock::new(Some(counts)),
            lost: AtomicBool::new(false),
            sequence: AtomicU64::new(0),
            sender,
        })
    }
}

impl LocalVertexCommitObserver for SupplyIndex {
    fn committed<'a>(&self, vertices: &mut dyn Iterator<Item = (&'a [u8], &'a [u8])>) {
        if self.lost.load(Ordering::Acquire) {
            return;
        }
        let mut keys = Vec::new();
        for (key, _) in vertices {
            if key.len() != 64 || (key[..32] != QUIL && key[..32] != GLOBAL) {
                continue;
            }
            let mut id = [0u8; 64];
            id.copy_from_slice(key);
            keys.push(id);
            if keys.len() > EVENT_KEYS_LIMIT {
                self.sequence.fetch_add(1, Ordering::AcqRel);
                self.mark_lost();
                return;
            }
        }
        if keys.is_empty() {
            return;
        }
        let sequence = self.sequence.fetch_add(1, Ordering::AcqRel) + 1;
        if self.sender.try_send(Event { sequence, keys }).is_err() {
            self.mark_lost();
        }
    }

    fn watches_sync(&self, app: &[u8]) -> bool {
        app.len() >= 32 && (app[..32] == QUIL || app[..32] == GLOBAL)
    }

    fn invalidated(&self) {
        self.mark_lost();
    }
}

pub struct SupplyIndexRunner {
    crdt: Arc<HypergraphCrdt>,
    store: Arc<dyn HypergraphStore>,
    db: Arc<dyn KvDb>,
    index: Arc<SupplyIndex>,
    receiver: Receiver<Event>,
}

impl SupplyIndexRunner {
    /// Run on a blocking worker. A failed or missed notification discards the
    /// summary; the next pass rebuilds it from a fresh committed snapshot.
    pub fn run(self, stop: &AtomicBool) {
        let mut counts = None;
        let mut backoff = RebuildBackoff::default();
        while !stop.load(Ordering::Acquire) {
            if counts.is_none() || self.index.lost.load(Ordering::Acquire) {
                let delay = backoff.delay(Instant::now());
                let deadline = Instant::now() + delay;
                while Instant::now() < deadline {
                    if stop.load(Ordering::Acquire) {
                        return;
                    }
                    std::thread::sleep(
                        deadline
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_secs(1)),
                    );
                }
                counts = None;
                self.index.lost.store(false, Ordering::Release);
                *self.index.counts.write() = None;
                let rebuilt = self.rebuild(stop);
                backoff.finished(Instant::now());
                match rebuilt {
                    Ok(Some(rebuilt)) => {
                        counts = Some(rebuilt);
                        tracing::info!("explorer supply index ready");
                    }
                    Ok(None) => continue,
                    Err(error) => {
                        tracing::warn!(%error, "explorer supply index rebuild failed");
                        continue;
                    }
                }
            }
            match self.receiver.recv_timeout(Duration::from_secs(1)) {
                Ok(event) => {
                    if let Some(current) = counts.as_mut() {
                        if let Err(error) = self.apply_keys(&event.keys, current) {
                            tracing::warn!(%error, "explorer supply index update failed");
                            self.index.mark_lost();
                            counts = None;
                        } else {
                            let mut published = self.index.counts.write();
                            if !self.index.lost.load(Ordering::Acquire) {
                                *published = Some(*current);
                            }
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    }

    fn rebuild(&self, stop: &AtomicBool) -> Result<Option<SupplyCounts>> {
        // The snapshot and notification sequence must describe the same
        // committed point; later notifications are replayed after the scan.
        let before = self.index.sequence.load(Ordering::Acquire);
        let snapshot = self.crdt.capture_fresh_committed_snapshot()?;
        let at_snapshot = self.index.sequence.load(Ordering::Acquire);
        if before != at_snapshot {
            return Ok(None);
        }
        // Observer writes are not atomic with CRDT commits, so rebuild from
        // canonical state after a restart or a missed notification.
        if self
            .db
            .first_key_in(LEGACY_INDEX_PREFIX, LEGACY_INDEX_END)?
            .is_some()
        {
            self.db
                .delete_range(LEGACY_INDEX_PREFIX, LEGACY_INDEX_END)?;
        }
        self.db.delete_range(INDEX_PREFIX, INDEX_END)?;
        let mut counts = SupplyCounts::default();
        self.scan_domain(snapshot.as_ref(), &QUIL, &mut counts, stop)?;
        self.scan_domain(snapshot.as_ref(), &GLOBAL, &mut counts, stop)?;
        drop(snapshot);
        if stop.load(Ordering::Acquire) || self.index.lost.load(Ordering::Acquire) {
            return Ok(None);
        }
        while let Ok(event) = self.receiver.try_recv() {
            if event.sequence > at_snapshot {
                self.apply_keys(&event.keys, &mut counts)?;
            }
            if stop.load(Ordering::Acquire) || self.index.lost.load(Ordering::Acquire) {
                return Ok(None);
            }
        }
        let mut published = self.index.counts.write();
        if self.index.lost.load(Ordering::Acquire) {
            return Ok(None);
        }
        *published = Some(counts);
        Ok(Some(counts))
    }

    fn scan_domain(
        &self,
        snapshot: &dyn SnapshotReadable,
        domain: &[u8; 32],
        counts: &mut SupplyCounts,
        stop: &AtomicBool,
    ) -> Result<()> {
        let shard = shard_key_for_location(&Location {
            app_address: *domain,
            data_address: [0; 32],
        });
        let mut after = None;
        loop {
            if stop.load(Ordering::Acquire) || self.index.lost.load(Ordering::Acquire) {
                return Ok(());
            }
            let page = snapshot.page_vertex_underlying_fixed(
                "vertex",
                "adds",
                &shard,
                domain,
                after.as_ref(),
                VertexPageLimits {
                    max_entries: 256,
                    max_bytes: 64 * 1024 * 1024,
                },
            )?;
            let batch = self.db.new_batch(false)?;
            for (address, blob) in &page.entries {
                let mut id = [0u8; 64];
                id[..32].copy_from_slice(domain);
                id[32..].copy_from_slice(address);
                let value = classify(&id, blob);
                batch.set(&index_key(&id), &value.encode())?;
                counts.change(None, Some(value));
            }
            batch.commit()?;
            if !page.has_more {
                return Ok(());
            }
            after = page.entries.last().map(|(address, _)| *address);
            if after.is_none() {
                return Err(QuilError::Store("supply page made no progress".into()));
            }
        }
    }

    fn apply_keys(&self, keys: &[[u8; 64]], counts: &mut SupplyCounts) -> Result<()> {
        let batch = self.db.new_batch(false)?;
        let mut next = *counts;
        let mut seen = std::collections::HashSet::new();
        let mut changed = false;
        for key in keys {
            if !seen.insert(*key) {
                continue;
            }
            let indexed = index_key(key);
            let old = batch
                .get(&indexed)?
                .map(|bytes| Contribution::decode(&bytes))
                .transpose()?;
            let domain = &key[..32];
            let shard = shard_key_for_location(&Location {
                app_address: domain.try_into().unwrap(),
                data_address: [0; 32],
            });
            let new = self
                .store
                .load_vertex_underlying_raw("vertex", "adds", &shard, key)?
                .map(|blob| classify(key, &blob));
            if old == new {
                continue;
            }
            changed = true;
            next.change(old, new);
            match new {
                Some(value) => batch.set(&indexed, &value.encode())?,
                None => batch.delete(&indexed)?,
            }
        }
        if changed {
            batch.commit()?;
        }
        *counts = next;
        Ok(())
    }
}

fn index_key(key: &[u8; 64]) -> Vec<u8> {
    let mut index = Vec::with_capacity(INDEX_PREFIX.len() + key.len());
    index.extend_from_slice(INDEX_PREFIX);
    index.extend_from_slice(key);
    index
}

fn classify(key: &[u8; 64], blob: &[u8]) -> Contribution {
    if key[..32] == QUIL {
        if crate::handlers::is_reserved_token_addr(&key[32..]) {
            return Contribution::Other;
        }
        let root = quil_tries::deserialize_go_tree(blob).ok().flatten();
        let tree = quil_tries::VectorCommitmentTree { root };
        let (transparent, private) = TOKEN_TYPES.get_or_init(|| {
            (
                quil_execution::token_intrinsic::legacy_migration::transparent_type_hash(&QUIL)
                    .ok(),
                quil_execution::token_intrinsic::materialize::coin_type_hash(&QUIL).ok(),
            )
        });
        match tree.get(&[0xff; 32]) {
            Some(ty)
                if transparent
                    .as_ref()
                    .is_some_and(|hash| ty == hash.as_slice()) =>
            {
                let Some(amount) = tree.get(&[4]) else {
                    return Contribution::Other;
                };
                let mut bytes = [0u8; 16];
                let n = amount.len().min(16);
                bytes[..n].copy_from_slice(&amount[..n]);
                Contribution::Transparent(u128::from_le_bytes(bytes))
            }
            Some(ty) if private.as_ref().is_some_and(|hash| ty == hash.as_slice()) => {
                Contribution::Hidden
            }
            _ => Contribution::Other,
        }
    } else if key[..32] == GLOBAL {
        let tree = quil_execution::prover_registry::rebuild_vertex_tree_from_blob(blob);
        if quil_execution::global_schema::read_type(&tree) != Some("reward:ProverReward") {
            return Contribution::Other;
        }
        let balance = quil_execution::global_intrinsic::materialize::read_reward_balance(&tree);
        let amount = crate::handlers::be_bytes_to_u128(&balance);
        if amount == 0 {
            Contribution::Other
        } else {
            Contribution::Reward(amount)
        }
    } else {
        Contribution::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Query, State};
    use axum::http::Method;
    use quil_execution::token_intrinsic::legacy_migration::{
        create_transparent_coin_tree, transparent_type_hash, TransparentCoin,
    };
    use std::collections::HashMap;

    #[test]
    fn large_commits_keep_the_index_current() {
        let (sender, receiver) = mpsc::sync_channel(4);
        let index = SupplyIndex {
            counts: RwLock::new(Some(SupplyCounts::default())),
            lost: AtomicBool::new(false),
            sequence: AtomicU64::new(0),
            sender,
        };
        // Observed mainnet GLOBAL syncs have reached 10,405 changed leaves.
        let rows = (0..10_405)
            .map(|number| {
                let mut key = [0u8; 64];
                key[..32].copy_from_slice(&QUIL);
                key[32..40].copy_from_slice(&(number as u64).to_be_bytes());
                (key.to_vec(), Vec::new())
            })
            .collect::<Vec<_>>();
        index.committed(
            &mut rows
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
        );
        assert!(!index.lost.load(Ordering::Acquire));
        assert_eq!(
            receiver
                .try_iter()
                .map(|event| event.keys.len())
                .sum::<usize>(),
            10_405
        );
    }

    #[test]
    fn saturated_commit_queue_invalidates_without_collecting_more_keys() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw,
            quil_store::FOREST_NAMESPACE,
        ));
        let (index, runner) = SupplyIndex::start(crdt.clone(), store, db);
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&QUIL);
        for _ in 0..=256 {
            index.committed(&mut std::iter::once((key.as_slice(), &[][..])));
        }
        assert!(index.lost.load(Ordering::Acquire));
        let sequence = index.sequence.load(Ordering::Acquire);
        index.committed(&mut std::iter::once((key.as_slice(), &[][..])));
        assert_eq!(index.sequence.load(Ordering::Acquire), sequence);

        add_coin(&crdt, 1, 16_000_000_000);
        crdt.commit(1).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = std::thread::spawn(move || runner.run(&worker_stop));
        assert_eq!(wait_for(&index, 1).transparent_subunits, 16_000_000_000);
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
    }

    #[test]
    fn repeated_rebuilds_back_off_and_reset_after_a_quiet_period() {
        let mut backoff = RebuildBackoff::default();
        let now = std::time::Instant::now();
        assert_eq!(backoff.delay(now), Duration::ZERO);
        backoff.finished(now);
        for seconds in [2, 4, 8, 16, 32, 60, 60] {
            assert_eq!(backoff.delay(now), Duration::from_secs(seconds));
            backoff.finished(now);
        }
        assert_eq!(
            backoff.delay(now + Duration::from_secs(120)),
            Duration::ZERO
        );
    }

    #[test]
    fn unchanged_contributions_do_not_write_to_store() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw.clone(),
            quil_store::FOREST_NAMESPACE,
        ));
        add_coin(&crdt, 1, 16_000_000_000);
        crdt.commit(1).unwrap();

        let (_, runner) = SupplyIndex::start(crdt, store, db);
        let mut counts = runner.rebuild(&AtomicBool::new(false)).unwrap().unwrap();
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(&QUIL);
        key[32..].fill(1);
        let before = raw.latest_sequence_number();
        runner.apply_keys(&[key], &mut counts).unwrap();
        assert_eq!(raw.latest_sequence_number(), before);
        assert_eq!(counts.transparent_subunits, 16_000_000_000);

        key[32..].fill(2);
        runner.apply_keys(&[key], &mut counts).unwrap();
        assert_eq!(raw.latest_sequence_number(), before);
        assert_eq!(counts.scanned, 1);
    }

    fn add_coin(crdt: &HypergraphCrdt, address: u8, amount: u128) {
        let coin = TransparentCoin {
            owner_address: [address; 32],
            amount,
        };
        let ty = transparent_type_hash(&QUIL).unwrap();
        let tree = create_transparent_coin_tree(&coin, &ty, &[address; 32]).unwrap();
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        crdt.add_vertex(
            &Location {
                app_address: QUIL,
                data_address: [address; 32],
            },
            &blob,
        )
        .unwrap();
    }

    fn add_hidden_coin(crdt: &HypergraphCrdt, address: u8) {
        let ty = quil_execution::token_intrinsic::materialize::coin_type_hash(&QUIL).unwrap();
        let mut tree = quil_tries::VectorCommitmentTree::new();
        tree.insert(&[0xff; 32], &ty, &[], &num_bigint::BigInt::from(32))
            .unwrap();
        crdt.add_vertex(
            &Location {
                app_address: QUIL,
                data_address: [address; 32],
            },
            &quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
        )
        .unwrap();
    }

    fn add_reward(crdt: &HypergraphCrdt, address: u8, amount: u64) {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        let mut balance = [0u8; 32];
        balance[24..].copy_from_slice(&amount.to_be_bytes());
        quil_execution::global_intrinsic::materialize::set_reward_balance(&mut tree, &balance)
            .unwrap();
        crdt.add_vertex(
            &Location {
                app_address: GLOBAL,
                data_address: [address; 32],
            },
            &quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
        )
        .unwrap();
    }

    async fn live_supply(state: crate::ExplorerState) -> serde_json::Value {
        let response = crate::handlers::handle_token_supply(
            Method::GET,
            State(state),
            Query(HashMap::from([("scan".to_string(), "1".to_string())])),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["live_public"].clone()
    }

    fn wait_for(index: &SupplyIndex, coins: u64) -> SupplyCounts {
        for _ in 0..300 {
            if let Some(counts) = index.read() {
                if counts.transparent_coins == coins {
                    return counts;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("supply index did not reach {coins} transparent coins");
    }

    #[test]
    fn committed_coins_build_and_update_the_supply_summary() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let mut legacy_key = LEGACY_INDEX_PREFIX.to_vec();
        legacy_key.extend_from_slice(&[0; 64]);
        db.set(&legacy_key, &[0]).unwrap();
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw,
            quil_store::FOREST_NAMESPACE,
        ));
        add_coin(&crdt, 1, 16_000_000_000);
        crdt.commit(1).unwrap();

        let (index, runner) = SupplyIndex::start(crdt.clone(), store, db.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = std::thread::spawn(move || runner.run(&worker_stop));
        let first = wait_for(&index, 1);
        assert_eq!(first.transparent_subunits, 16_000_000_000);
        assert!(db.get(&legacy_key).unwrap().is_none());

        add_coin(&crdt, 2, 8_000_000_000);
        crdt.commit(2).unwrap();
        let second = wait_for(&index, 2);
        assert_eq!(second.transparent_subunits, 24_000_000_000);
        assert_eq!(second.scanned, 2);
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
    }

    #[tokio::test]
    async fn indexed_supply_matches_full_scan_after_coin_removal() {
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let raw = db.inner();
        let store: Arc<dyn HypergraphStore> =
            Arc::new(quil_store::RocksHypergraphStore::new(raw.clone()));
        let crdt = Arc::new(HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            raw.clone(),
            quil_store::FOREST_NAMESPACE,
        ));
        add_coin(&crdt, 1, 16_000_000_000);
        add_hidden_coin(&crdt, 2);
        add_reward(&crdt, 3, 8_000_000_000);
        crdt.commit(1).unwrap();

        let (index, runner) = SupplyIndex::start(crdt.clone(), store, db);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = std::thread::spawn(move || runner.run(&worker_stop));
        let initial = wait_for(&index, 1);
        assert_eq!(initial.reward_subunits, 8_000_000_000);
        assert_eq!(initial.value_hidden_coins, 1);

        crdt.remove_vertex(&Location {
            app_address: QUIL,
            data_address: [1; 32],
        })
        .unwrap();
        add_reward(&crdt, 3, 16_000_000_000);
        crdt.commit(2).unwrap();
        let updated = (0..300)
            .find_map(|_| {
                let counts = index.read();
                if counts.is_some_and(|counts| counts.reward_subunits == 16_000_000_000) {
                    counts
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                    None
                }
            })
            .expect("supply index did not apply the reward update");
        assert_eq!(updated.transparent_subunits, 16_000_000_000);

        let make_state = || {
            crate::ExplorerState::new(
                Arc::new(quil_store::RocksClockStore::new(raw.clone())),
                crdt.clone(),
                Arc::new(quil_execution::prover_registry::SharedProverRegistry::new()),
                Arc::new(quil_store::RocksKeyStore::new(raw.clone())),
                Arc::new(quil_store::RocksShardsStore::new(raw.clone())),
                None,
                None,
                Arc::new(parking_lot::RwLock::new(HashMap::new())),
                Arc::new(crate::RecentMessageRing::new(16)),
                Arc::new(AtomicU64::new(2)),
            )
        };
        let full_scan = live_supply(make_state()).await;
        let indexed = live_supply(make_state().with_supply_index(index)).await;
        // The existing scan counts add blobs even when a remove tombstone exists.
        assert_eq!(full_scan["transparent_coins"], 1);
        assert_eq!(full_scan["value_hidden_coins"], 1);
        assert_eq!(full_scan["reward_provers"], 1);
        assert_eq!(full_scan["reward_subunits"], "16000000000");
        assert_eq!(indexed, full_scan);
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
    }
}

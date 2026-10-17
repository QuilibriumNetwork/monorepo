//! Shared local witness-index serving and cooperative, single-flight bootstrap.
//! Cache failures affect RPC availability, never consensus execution success.
#[cfg(test)]
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};

use quil_execution::{hypergraph_state::HypergraphState, token_intrinsic::{
    state::network_identifier,
    witness_index::{LocalWitnessIndex, WitnessBootstrap, apply_vertex_updates, MAX_UPDATE_BYTES, MAX_UPDATE_VERTICES},
    witnesses::{indexed_witnesses, Witnesses},
}};
use quil_lattice_ct::confidential::transfer::parameter_context;
use quil_types::{error::{QuilError, Result}, store::KvDb};

struct BuildPermit(Arc<AtomicBool>);
impl Drop for BuildPermit {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); }
}

struct UpdateSender(tokio::sync::mpsc::Sender<Vec<(Vec<u8>, Vec<u8>)>>);
impl quil_types::store::LocalVertexCommitObserver for UpdateSender {
    fn committed<'a>(&self, vertices: &mut dyn std::iter::Iterator<Item = (&'a [u8], &'a [u8])>) {
        // Do not copy unbounded frame data or perform cache I/O on commit.
        let vertices: Vec<_> = vertices.take(MAX_UPDATE_VERTICES + 1).collect();
        use quil_execution::token_intrinsic::state::{local_record_application, ROOT_ADDRESS};
        if vertices.len() > MAX_UPDATE_VERTICES || !vertices.iter().any(|(key, _)|
            local_record_application(key, &ROOT_ADDRESS).is_some()
                || (key.len() == 64 && key[32..] == ROOT_ADDRESS)) { return; }
        if vertices.iter().try_fold(0usize, |bytes, (key, value)| bytes.checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value.len()))).is_none_or(|bytes| bytes > MAX_UPDATE_BYTES) { return; }
        let event = vertices.into_iter().map(|(key, value)| (key.to_vec(), value.to_vec())).collect();
        if self.0.try_send(event).is_err() { tracing::debug!("local witness update queue full or stopped; rebuild remains available"); }
    }
}

pub(crate) struct NodeWitnessIndex {
    db: Arc<dyn KvDb>,
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    network: [u8; 32],
    spawner: quil_lifecycle::DetachedSpawner<anyhow::Error>,
    building: Arc<AtomicBool>,
    readers: Mutex<std::collections::VecDeque<(quil_lattice_ct::confidential::coin_tree::RootRecord, Arc<LocalWitnessIndex>)>>,
}
impl NodeWitnessIndex {
    pub(crate) fn new(db: Arc<dyn KvDb>, crdt: Arc<quil_hypergraph::HypergraphCrdt>, network: u8,
        spawner: quil_lifecycle::DetachedSpawner<anyhow::Error>) -> Self {
        Self { db, crdt, network: network_identifier(network), spawner, building: Arc::new(AtomicBool::new(false)), readers: Mutex::new(std::collections::VecDeque::new()) }
    }

    pub(crate) fn start(db: Arc<dyn KvDb>, crdt: Arc<quil_hypergraph::HypergraphCrdt>, network: u8,
        spawner: quil_lifecycle::DetachedSpawner<anyhow::Error>) -> Arc<Self> {
        let service = Arc::new(Self::new(db, crdt.clone(), network, spawner.clone()));
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        crdt.set_local_vertex_observer(Arc::new(UpdateSender(tx)));
        let worker = service.clone(); let token = spawner.token();
        spawner.detach("token-witness-index-updates", async move {
            loop {
                let event = tokio::select! { _ = token.cancelled() => return Ok(()), event = rx.recv() => match event {
                    Some(event) => event, None => return Ok(()),
                }};
                // Bootstrap and updates share one writer slot. Queue memory is
                // bounded even while a long bootstrap is holding the slot.
                loop {
                    if worker.building.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_ok() { break; }
                    tokio::select! { _ = token.cancelled() => return Ok(()), _ = tokio::time::sleep(std::time::Duration::from_millis(25)) => {} }
                }
                let permit = BuildPermit(worker.building.clone());
                let worker = worker.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let state = HypergraphState::new(worker.crdt.clone());
                    apply_vertex_updates(&state, worker.db.clone(), &worker.network, &event)
                }).await;
                match result {
                    Ok(Ok(_)) => {},
                    Ok(Err(error)) => tracing::debug!(%error, "local witness update skipped; RPC can rebuild"),
                    Err(error) => tracing::warn!(%error, "local witness update task failed"),
                }
            }
        });
        service
    }

    /// Witnesses against the application's canonical root — the root the
    /// global commit accepts — when a shard of it has reported one, else the
    /// shard's own (a whole application nobody has reported yet).
    ///
    /// `global` holds GLOBAL state. Which subtree a coin's path runs through
    /// is decided by the coin, so this serves whatever part of the application
    /// the node holds — one shard's coins, or every shard's on an archive.
    pub(crate) fn canonical_witnesses(
        &self,
        application: &[u8; 32],
        addresses: &[[u8; 32]],
        global: Arc<quil_hypergraph::HypergraphCrdt>,
    ) -> Result<Witnesses> {
        let global = HypergraphState::new(global);
        match quil_execution::token_intrinsic::global_accumulator::subtrees(&global, application) {
            Ok(reported) if !reported.is_empty() => {}
            _ => return self.witnesses(application, addresses),
        }
        self.with_index(application, addresses, |state, root, generation, index| {
            // Newest first: the reported root is usually the older one, since
            // a report lags the coins it reports.
            let candidates = if root == generation { vec![root] } else { vec![root, generation] };
            quil_execution::token_intrinsic::witnesses::canonical_witnesses(
                state, &global, &self.network, application, addresses, &candidates, index,
            )
        })
    }

    pub(crate) fn witnesses(&self, application: &[u8; 32], addresses: &[[u8; 32]]) -> Result<Witnesses> {
        self.with_index(application, addresses, |state, root, _generation, index| {
            indexed_witnesses(state, &self.network, application, addresses, root, index)
        })
    }

    /// The committed state, the index's ready root and a cached reader for it.
    fn with_index(
        &self,
        application: &[u8; 32],
        addresses: &[[u8; 32]],
        build: impl FnOnce(
            &HypergraphState,
            quil_lattice_ct::confidential::coin_tree::RootRecord,
            quil_lattice_ct::confidential::coin_tree::RootRecord,
            &LocalWitnessIndex,
        ) -> Result<Witnesses>,
    ) -> Result<Witnesses> {
        if addresses.is_empty() || addresses.len() > 4
            || addresses.iter().collect::<std::collections::BTreeSet<_>>().len() != addresses.len() {
            return Err(QuilError::InvalidArgument("invalid witness addresses".into()));
        }
        let context = parameter_context(&self.network, application);
        let state = HypergraphState::new(self.crdt.clone());
        let result = (|| {
            let ready = LocalWitnessIndex::ready(self.db.as_ref(), &context)?
                .ok_or_else(|| QuilError::ExecutionUnavailable("witness index has not been built".into()))?;
            let root = ready.root; let generation = ready.generation.clone();
            let served = ready.generation;
            // Deriving the membership key and zero subtrees is expensive;
            // retain at most four readers, including across RPC requests.
            let index = {
                let mut readers = self.readers.lock().map_err(|_| QuilError::ExecutionUnavailable("witness reader cache poisoned".into()))?;
                if let Some(position) = readers.iter().position(|(old, _)| old == &generation) {
                    let entry = readers.remove(position).unwrap();
                    let index = entry.1.clone(); readers.push_back(entry); index
                } else {
                    let index = Arc::new(LocalWitnessIndex::for_root(self.db.clone(), &generation, 32)?);
                    if readers.len() == 4 { readers.pop_front(); }
                    readers.push_back((generation, index.clone())); index
                }
            };
            build(&state, root, served, index.as_ref())
        })();
        if result.is_err() { self.schedule(*application); }
        result
    }

    fn schedule(&self, application: [u8; 32]) {
        if self.building.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
        let permit = BuildPermit(self.building.clone());
        // CAPTURE one if none exists. A node that never publishes root
        // generations carrying store snapshots — an archive serving an
        // application it materializes but does not cover — has nothing to
        // reuse, so the non-capturing acquire returned None and the bootstrap
        // silently never started: the index stayed unbuilt forever and every
        // witness request failed with "witness index has not been built",
        // which is what stops a holder spending a coin there. The wallet scan
        // already captures the same way.
        let generation = match self.crdt.acquire_or_capture_scan_snapshot(None) {
            Ok(Some(generation)) => generation,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(%error, "witness index bootstrap could not capture a snapshot");
                return;
            }
        };
        let Some(snapshot) = generation.db_snapshot.clone() else { return; };
        let db = self.db.clone(); let network = self.network;
        let token = self.spawner.token();
        self.spawner.detach("token-witness-index-bootstrap", async move {
            // Keep the permit inside each blocking step too: cancellation of
            // this future must not admit a concurrent writer before it exits.
            let permit = Arc::new(permit);
            let guard = permit.clone();
            let started = tokio::task::spawn_blocking(move || {
                let _guard = guard;
                WitnessBootstrap::new(db, snapshot, &network, &application)
            }).await;
            let mut builder = match started {
                Ok(Ok(builder)) => builder,
                Ok(Err(error)) => { tracing::warn!(application = %hex::encode(application), %error, "witness index bootstrap could not start"); return Ok(()); }
                Err(error) => { tracing::warn!(%error, "witness index bootstrap task could not start"); return Ok(()); }
            };
            tracing::info!(application = %hex::encode(application), coins = builder.root().coins, "building local witness index");
            loop {
                if token.is_cancelled() { return Ok(()); }
                let guard = permit.clone();
                let step = tokio::task::spawn_blocking(move || {
                    let _guard = guard;
                    let result = builder.step(); (builder, result)
                }).await;
                match step {
                    Ok((next, Ok(false))) => builder = next,
                    Ok((_, Ok(true))) => { tracing::info!(application = %hex::encode(application), "local witness index ready"); return Ok(()); }
                    Ok((_, Err(error))) => { tracing::warn!(application = %hex::encode(application), %error, "witness index bootstrap failed; a later request can retry"); return Ok(()); }
                    Err(error) => { tracing::warn!(%error, "witness index bootstrap task failed"); return Ok(()); }
                }
                tokio::task::yield_now().await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_execution::{hypergraph_state::vertex_adds_discriminator, token_intrinsic::{roots, state::SnapshotLimits}};
    use quil_lattice_ct::confidential::{transfer::Output, AmountOpening, CommitmentKey};

    #[tokio::test]
    async fn node_bootstraps_repairs_and_serves_verified_witnesses() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(quil_store::RocksDb::open(dir.path()).unwrap());
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store,
            Arc::new(quil_types::crypto::NoopInclusionProver)));
        let state = HypergraphState::new(crdt.clone());
        let network = network_identifier(1); let application = [11; 32];
        let context = parameter_context(&network, &application);
        let key = CommitmentKey::derive(&context); let disc = vertex_adds_discriminator().unwrap();
        let mut addresses = Vec::new();
        let limits = SnapshotLimits { max_coins: 2, max_depth: 32, max_nodes: 1 << 16 };
        // Coins go where staging would put them: into the block their address
        // selects, at that block's next free index.
        let mut staged = std::collections::BTreeMap::new();
        for position in 0..2u8 {
            let output = Output { owner: [position; IDENTITY_BYTES], memo: [0; 1115],
                commitment: key.commit(u128::from(position), &AmountOpening::from_seed(&context, &[position; 32])) };
            let (address, tree) = roots::stage_coin(
                &state, &network, &application, &context, 1, &output, &mut staged, limits).unwrap();
            state.set(&application, &address, &disc, 1, quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()).unwrap();
            addresses.push(address);
        }
        let root = roots::refresh_root(&state, &network, &application, limits).unwrap();
        state.commit().unwrap(); state.abort(); crdt.commit(1).unwrap();
        assert!(crdt.publish_snapshot_capturing(vec![1; 32], 1).unwrap());
        let mut supervisor = quil_lifecycle::Supervisor::<anyhow::Error>::new();
        supervisor.spawn("test-main", |token| async move { token.cancelled().await; Ok(()) });
        let spawner = supervisor.detached_spawner(); let token = spawner.token();
        let service = NodeWitnessIndex::start(db.clone(), crdt.clone(), 1, spawner);
        // First request schedules work and returns an availability error.
        assert!(matches!(service.witnesses(&application, &addresses), Err(QuilError::ExecutionUnavailable(_))));
        let running = tokio::spawn(supervisor.run());
        for repair in [false, true] {
            if repair {
                LocalWitnessIndex::for_root(db.clone(), &root, 32).unwrap().clear().unwrap();
                crdt.close_snapshots();
                assert!(matches!(service.witnesses(&application, &addresses), Err(QuilError::ExecutionUnavailable(_))));
                assert!(!service.building.load(Ordering::Acquire));
                crdt.reopen_snapshots();
                assert!(crdt.publish_snapshot_capturing(vec![2; 32], 2).unwrap());
            }
            let result = tokio::time::timeout(std::time::Duration::from_secs(120), async {
                loop {
                    let service = service.clone(); let addresses = addresses.clone();
                    let result = tokio::task::spawn_blocking(move || service.witnesses(&application, &addresses)).await.unwrap();
                    if let Ok(witnesses) = result { break witnesses; }
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
            }).await.unwrap();
            assert_eq!(result.root, root);
            assert_eq!(result.coins.len(), 2);
            assert!(result.coins.iter().all(|coin| coin.path.is_some()));
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while service.building.load(Ordering::Acquire) { tokio::task::yield_now().await; }
            }).await.unwrap();
        }
        // Advance through the actual durable-commit notification while no
        // snapshot is available. A full bootstrap cannot satisfy this request.
        crdt.close_snapshots();
        let output = Output { owner: [2; IDENTITY_BYTES], memo: [0; 1115],
            commitment: key.commit(2, &AmountOpening::from_seed(&context, &[2; 32])) };
        // A later transaction stages against committed state, with its own
        // per-block tally.
        let later_limits = SnapshotLimits { max_coins: 4, ..limits };
        let mut later = std::collections::BTreeMap::new();
        let (address, tree) = roots::stage_coin(
            &state, &network, &application, &context, 3, &output, &mut later, later_limits).unwrap();
        state.set(&application, &address, &disc, 3, quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()).unwrap();
        let next = roots::refresh_root(&state, &network, &application, later_limits).unwrap();
        state.commit().unwrap(); state.abort();
        assert_eq!(LocalWitnessIndex::ready_root(db.as_ref(), &context).unwrap(), Some(root.clone()));
        crdt.commit(3).unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(120), async {
            loop {
                let service = service.clone();
                let result = tokio::task::spawn_blocking(move || service.witnesses(&application, &[address])).await.unwrap();
                if let Ok(witnesses) = result { break witnesses; }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        }).await.unwrap();
        assert_eq!(result.root, next);
        assert!(result.coins[0].path.is_some());
        let ready = LocalWitnessIndex::ready(db.as_ref(), &context).unwrap().unwrap();
        assert_eq!(ready.generation, root);
        assert_eq!(ready.root, next);
        // A local observer failure cannot undo/fail the durable state commit.
        struct BrokenObserver;
        impl quil_types::store::LocalVertexCommitObserver for BrokenObserver {
            fn committed<'a>(&self, _: &mut dyn std::iter::Iterator<Item = (&'a [u8], &'a [u8])>) { panic!("simulated local cache failure"); }
        }
        crdt.set_local_vertex_observer(Arc::new(BrokenObserver));
        let output = Output { owner: [3; IDENTITY_BYTES], memo: [0; 1115],
            commitment: key.commit(3, &AmountOpening::from_seed(&context, &[3; 32])) };
        let mut last = std::collections::BTreeMap::new();
        let (address, tree) = roots::stage_coin(
            &state, &network, &application, &context, 4, &output, &mut last, later_limits).unwrap();
        state.set(&application, &address, &disc, 4, quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()).unwrap();
        let committed = roots::refresh_root(&state, &network, &application, later_limits).unwrap();
        state.commit().unwrap(); state.abort(); crdt.commit(4).unwrap();
        let persisted = quil_store::RocksHypergraphStore::new(db.inner()).capture_snapshot().unwrap();
        assert_eq!(quil_execution::token_intrinsic::scan::snapshot_root(persisted.as_ref(), &network, &application).unwrap(), committed);
        assert_eq!(LocalWitnessIndex::ready_root(db.as_ref(), &context).unwrap(), Some(next));
        assert!(matches!(service.witnesses(&application, &[address]), Err(QuilError::ExecutionUnavailable(_))));
        token.cancel(); running.await.unwrap();
    }
}

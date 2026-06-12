//! Shared test helpers for `quil-engine` unit and integration tests.
//!
//! [`TestProverRegistry`] is a single configurable `ProverRegistry`
//! stub carrying the union of state every consumer (shard_info,
//! committee, worker_allocator, lifecycle, …) needs: prover info
//! list, shard summaries, optional next-leader override, frame
//! counter. Tests construct one, seed the relevant fields, and pass
//! it through.
//!
//! Exposed publicly (behind `#[doc(hidden)]`) so integration tests
//! in `crates/quil-engine/tests/` — which build the crate without
//! `#[cfg(test)]` — can use the same mocks. The doc-hidden attribute
//! keeps the mocks out of the user-facing docs.

use std::collections::HashMap;
use std::sync::Mutex;

use quil_types::consensus::{
    ProverInfo, ProverRegistry, ProverShardSummary, ProverStatus,
};
use quil_types::error::Result;

use crate::worker::{WorkerInfo, WorkerManager};

/// All-purpose `ProverRegistry` stub. Each piece of state is
/// independently configurable; default behavior is "empty registry,
/// frame 0." Setters take `&self` so tests can mutate the stub
/// from inside the call site under test (mirroring how the real
/// registry handles concurrent updates).
pub struct TestProverRegistry {
    provers: Mutex<Vec<ProverInfo>>,
    summaries: Mutex<Vec<ProverShardSummary>>,
    /// When `Some`, `get_next_prover` returns this address; when
    /// `None`, falls back to the first prover's address. Matches
    /// the leader-pin behavior the `committee` tests need.
    next_prover: Mutex<Option<Vec<u8>>>,
}

impl Default for TestProverRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TestProverRegistry {
    pub fn new() -> Self {
        Self {
            provers: Mutex::new(Vec::new()),
            summaries: Mutex::new(Vec::new()),
            next_prover: Mutex::new(None),
        }
    }

    pub fn with_provers(provers: Vec<ProverInfo>) -> Self {
        let r = Self::new();
        *r.provers.lock().unwrap() = provers;
        r
    }

    pub fn with_prover(info: ProverInfo) -> Self {
        Self::with_provers(vec![info])
    }

    pub fn set_prover(&self, info: ProverInfo) {
        let mut guard = self.provers.lock().unwrap();
        // Replace if address matches, else append.
        match guard.iter().position(|p| p.address == info.address) {
            Some(i) => guard[i] = info,
            None => guard.push(info),
        }
    }

    pub fn set_provers(&self, provers: Vec<ProverInfo>) {
        *self.provers.lock().unwrap() = provers;
    }

    pub fn set_summaries(&self, summaries: Vec<ProverShardSummary>) {
        *self.summaries.lock().unwrap() = summaries;
    }

    pub fn set_next_prover(&self, address: Vec<u8>) {
        *self.next_prover.lock().unwrap() = Some(address);
    }
}

impl ProverRegistry for TestProverRegistry {
    fn get_prover_info(&self, address: &[u8]) -> Result<Option<ProverInfo>> {
        Ok(self
            .provers
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.address == address)
            .cloned())
    }

    fn get_next_prover(&self, _input: &[u8; 32], _filter: &[u8]) -> Result<Vec<u8>> {
        if let Some(addr) = self.next_prover.lock().unwrap().clone() {
            return Ok(addr);
        }
        Ok(self
            .provers
            .lock()
            .unwrap()
            .first()
            .map(|p| p.address.clone())
            .unwrap_or_default())
    }

    fn get_ordered_provers(&self, _: &[u8; 32], _: &[u8]) -> Result<Vec<Vec<u8>>> {
        Ok(self
            .provers
            .lock()
            .unwrap()
            .iter()
            .map(|p| p.address.clone())
            .collect())
    }

    fn get_active_provers(&self, _filter: &[u8]) -> Result<Vec<ProverInfo>> {
        Ok(self
            .provers
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.status == ProverStatus::Active)
            .cloned()
            .collect())
    }

    fn get_prover_count(&self, _filter: &[u8]) -> Result<usize> {
        Ok(self.provers.lock().unwrap().len())
    }

    fn get_provers(&self, _filter: &[u8]) -> Result<Vec<ProverInfo>> {
        Ok(self.provers.lock().unwrap().clone())
    }

    fn get_provers_by_status(
        &self,
        _filter: &[u8],
        status: ProverStatus,
    ) -> Result<Vec<ProverInfo>> {
        Ok(self
            .provers
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.status == status)
            .cloned()
            .collect())
    }

    fn get_prover_shard_summaries(
        &self,
        _frame_number: u64,
    ) -> Result<Vec<ProverShardSummary>> {
        Ok(self.summaries.lock().unwrap().clone())
    }
}

/// Shared `WorkerManager` stub used across worker_allocator and
/// lifecycle tests. Backs every operation by a single
/// `HashMap<core_id, WorkerInfo>` so test setup is uniform:
///
/// - `add(info)` inserts/replaces a worker directly (use for
///   tests that need pre-populated state).
/// - `set_worker_filter(core_id, filter, start_consensus)`
///   matches the production trait method and creates missing
///   workers on demand.
/// - `set_manually_managed` is also wired so tests can flip
///   the manual flag without going through the full Worker
///   plumbing.
pub struct TestWorkerManager {
    workers: Mutex<HashMap<u32, WorkerInfo>>,
}

impl Default for TestWorkerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TestWorkerManager {
    pub fn new() -> Self {
        Self {
            workers: Mutex::new(HashMap::new()),
        }
    }

    /// Insert or replace a worker directly. Useful when a test
    /// wants to seed specific `pending_filter_frame` /
    /// `allocated` / `manually_managed` combinations that the
    /// trait's `set_worker_filter` can't reach.
    pub fn add(&self, info: WorkerInfo) {
        self.workers.lock().unwrap().insert(info.core_id, info);
    }

    /// Convenience for tests that want to set the filter
    /// directly without going through `set_worker_filter`.
    pub fn add_with_filter(&self, core_id: u32, filter: Vec<u8>) {
        let allocated = !filter.is_empty();
        self.add(WorkerInfo {
            core_id,
            filter,
            available_storage: 0,
            total_storage: 0,
            manually_managed: false,
            pending_filter_frame: 0,
            allocated,
        });
    }
}

impl WorkerManager for TestWorkerManager {
    fn set_worker_filter(
        &self,
        core_id: u32,
        filter: &[u8],
        start_consensus: bool,
    ) -> Result<()> {
        let mut g = self.workers.lock().unwrap();
        let entry = g.entry(core_id).or_insert(WorkerInfo {
            core_id,
            filter: Vec::new(),
            available_storage: 0,
            total_storage: 0,
            manually_managed: false,
            pending_filter_frame: 0,
            allocated: false,
        });
        entry.filter = filter.to_vec();
        entry.allocated = !filter.is_empty() && start_consensus;
        Ok(())
    }

    fn deallocate_worker(&self, core_id: u32) -> Result<()> {
        self.workers.lock().unwrap().remove(&core_id);
        Ok(())
    }

    fn check_workers_connected(&self) -> Result<Vec<u32>> {
        Ok(self.workers.lock().unwrap().keys().copied().collect())
    }

    fn range_workers(&self) -> Result<Vec<WorkerInfo>> {
        let mut out: Vec<WorkerInfo> =
            self.workers.lock().unwrap().values().cloned().collect();
        out.sort_by_key(|w| w.core_id);
        Ok(out)
    }

    fn respawn_worker(&self, core_id: u32, filter: &[u8]) -> Result<()> {
        self.allocate_worker(core_id, filter)
    }

    fn set_manually_managed(&self, core_id: u32, manually_managed: bool) -> Result<()> {
        let mut g = self.workers.lock().unwrap();
        let entry = g.entry(core_id).or_insert(WorkerInfo {
            core_id,
            filter: Vec::new(),
            available_storage: 0,
            total_storage: 0,
            manually_managed: false,
            pending_filter_frame: 0,
            allocated: false,
        });
        entry.manually_managed = manually_managed;
        Ok(())
    }
}

// =====================================================================
// SpawningWorkerManager
// =====================================================================

/// `WorkerManager` that, on `set_worker_filter(core_id, filter, start_consensus=true)`,
/// invokes a caller-provided closure to spawn an `AppEngineHandle`
/// for that filter. The closure owns whatever deps (clock store,
/// frame prover, registry, etc.) are needed to construct an
/// `AppConsensusEngine`. Resulting handles are stored so tests can
/// route shard-bitmask messages to them.
///
/// Mirrors production's `ThreadWorkerManager::respawn` shape (which
/// constructs an engine via core-pinned thread + `AppEngineHandle`).
/// This variant runs everything on the current tokio runtime.
pub struct SpawningWorkerManager {
    workers: Mutex<HashMap<u32, crate::worker::WorkerInfo>>,
    handles: Mutex<HashMap<u32, crate::app_engine::AppEngineHandle>>,
    spawn_fn:
        std::sync::Arc<dyn Fn(u32, Vec<u8>) -> crate::app_engine::AppEngineHandle + Send + Sync>,
}

impl SpawningWorkerManager {
    pub fn new(
        spawn_fn: std::sync::Arc<
            dyn Fn(u32, Vec<u8>) -> crate::app_engine::AppEngineHandle + Send + Sync,
        >,
    ) -> Self {
        Self {
            workers: Mutex::new(HashMap::new()),
            handles: Mutex::new(HashMap::new()),
            spawn_fn,
        }
    }

    /// Snapshot of all spawned engine handles, keyed by core_id.
    pub fn snapshot_handles(&self) -> Vec<(u32, crate::app_engine::AppEngineHandle)> {
        self.handles
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }

    /// Pre-seed a worker entry (sets storage caps + flags) so the
    /// allocator can discover it.
    pub fn add(&self, info: crate::worker::WorkerInfo) {
        self.workers.lock().unwrap().insert(info.core_id, info);
    }
}

impl crate::worker::WorkerManager for SpawningWorkerManager {
    fn set_worker_filter(
        &self,
        core_id: u32,
        filter: &[u8],
        start_consensus: bool,
    ) -> Result<()> {
        let mut g = self.workers.lock().unwrap();
        let entry = g.entry(core_id).or_insert(crate::worker::WorkerInfo {
            core_id,
            filter: Vec::new(),
            available_storage: 0,
            total_storage: 0,
            manually_managed: false,
            pending_filter_frame: 0,
            allocated: false,
        });
        entry.filter = filter.to_vec();
        entry.allocated = !filter.is_empty() && start_consensus;
        drop(g);

        if start_consensus && !filter.is_empty() {
            let handle = (self.spawn_fn)(core_id, filter.to_vec());
            self.handles.lock().unwrap().insert(core_id, handle);
        }
        Ok(())
    }

    fn deallocate_worker(&self, core_id: u32) -> Result<()> {
        self.workers.lock().unwrap().remove(&core_id);
        self.handles.lock().unwrap().remove(&core_id);
        Ok(())
    }

    fn check_workers_connected(&self) -> Result<Vec<u32>> {
        Ok(self.workers.lock().unwrap().keys().copied().collect())
    }

    fn range_workers(&self) -> Result<Vec<crate::worker::WorkerInfo>> {
        let mut out: Vec<crate::worker::WorkerInfo> =
            self.workers.lock().unwrap().values().cloned().collect();
        out.sort_by_key(|w| w.core_id);
        Ok(out)
    }

    fn respawn_worker(&self, core_id: u32, filter: &[u8]) -> Result<()> {
        self.set_worker_filter(core_id, filter, true)
    }

    fn set_pending_filter_frame(&self, core_id: u32, frame: u64) -> Result<()> {
        let mut g = self.workers.lock().unwrap();
        let entry = g.entry(core_id).or_insert(crate::worker::WorkerInfo {
            core_id,
            filter: Vec::new(),
            available_storage: 0,
            total_storage: 0,
            manually_managed: false,
            pending_filter_frame: 0,
            allocated: false,
        });
        entry.pending_filter_frame = frame;
        Ok(())
    }
}

// =====================================================================
// TestProverMessageTransport
// =====================================================================

/// In-memory [`ProverMessageTransport`] for tests. Captures every
/// outbound bundle into a shared `Vec`, lets the test driver pop them
/// and inject into whichever harness simulates the network. Returns a
/// configurable `GlobalFrameHeader` for `submit_join`'s
/// `latest_global_frame_header` call.
///
/// The transport owns a `head_header: Mutex<GlobalFrameHeader>` so the
/// test can advance the "latest frame" as the chain progresses.
pub struct TestProverMessageTransport {
    head_header: std::sync::Mutex<quil_types::proto::global::GlobalFrameHeader>,
    /// Outbound bundles captured in submission order. The test driver
    /// drains this after each pipeline action.
    outbound: std::sync::Mutex<Vec<Vec<u8>>>,
    /// Optional sink: when set, every outbound bundle is also pushed
    /// into the provided callback. Useful for wiring directly into an
    /// in-memory network without the test having to poll `outbound`.
    sink: std::sync::Mutex<Option<std::sync::Arc<dyn Fn(Vec<u8>) + Send + Sync>>>,
}

impl Default for TestProverMessageTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl TestProverMessageTransport {
    pub fn new() -> Self {
        Self {
            head_header: std::sync::Mutex::new(
                quil_types::proto::global::GlobalFrameHeader::default(),
            ),
            outbound: std::sync::Mutex::new(Vec::new()),
            sink: std::sync::Mutex::new(None),
        }
    }

    /// Set the header that `latest_global_frame_header` returns.
    pub fn set_head_header(&self, h: quil_types::proto::global::GlobalFrameHeader) {
        *self.head_header.lock().unwrap() = h;
    }

    /// Drain all captured outbound bundle bytes.
    pub fn drain_outbound(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.outbound.lock().unwrap())
    }

    /// Number of captured outbound bundles (peek without draining).
    pub fn outbound_len(&self) -> usize {
        self.outbound.lock().unwrap().len()
    }

    /// Install a sink that fires on every outbound bundle. Used to
    /// wire the transport directly into an in-memory network so the
    /// test doesn't have to poll `drain_outbound`.
    pub fn set_sink(&self, sink: std::sync::Arc<dyn Fn(Vec<u8>) + Send + Sync>) {
        *self.sink.lock().unwrap() = Some(sink);
    }
}

#[async_trait::async_trait]
impl crate::prover_message_transport::ProverMessageTransport for TestProverMessageTransport {
    async fn latest_global_frame_header(
        &self,
    ) -> quil_types::error::Result<quil_types::proto::global::GlobalFrameHeader> {
        Ok(self.head_header.lock().unwrap().clone())
    }

    async fn publish_prover_bundle(
        &self,
        bundle_bytes: Vec<u8>,
    ) -> quil_types::error::Result<()> {
        // Capture and forward.
        let sink = self.sink.lock().unwrap().clone();
        self.outbound.lock().unwrap().push(bundle_bytes.clone());
        if let Some(sink) = sink {
            sink(bundle_bytes);
        }
        Ok(())
    }
}

// =====================================================================
// TestKeyManager
// =====================================================================

/// Test [`quil_keys::KeyManager`] that wraps a pre-generated BLS48-581
/// key pair. Used by `ProverPipeline` (which calls `get_signer` to
/// sign `ProverJoin` / `ProverConfirm` payloads).
///
/// Only `Bls48581G1` is implemented — other key types return an error.
pub struct TestKeyManager {
    bls_private: Vec<u8>,
    bls_public: Vec<u8>,
}

impl TestKeyManager {
    pub fn new(bls_private: Vec<u8>, bls_public: Vec<u8>) -> Self {
        Self {
            bls_private,
            bls_public,
        }
    }
}

impl quil_keys::KeyManager for TestKeyManager {
    fn get_proving_key_id(&self) -> &str {
        "test-key"
    }

    fn get_signer(
        &self,
        key_type: quil_types::crypto::KeyType,
    ) -> quil_types::error::Result<Box<dyn quil_types::crypto::Signer>> {
        match key_type {
            quil_types::crypto::KeyType::Bls48581G1 => {
                use quil_types::crypto::BlsConstructor;
                let ctor = quil_crypto::Bls48581KeyConstructor;
                ctor.from_bytes(&self.bls_private, &self.bls_public)
            }
            other => Err(quil_types::error::QuilError::Internal(format!(
                "TestKeyManager does not support key type {:?}",
                other
            ))),
        }
    }

    fn get_public_key(
        &self,
        key_type: quil_types::crypto::KeyType,
    ) -> quil_types::error::Result<Vec<u8>> {
        match key_type {
            quil_types::crypto::KeyType::Bls48581G1 => Ok(self.bls_public.clone()),
            other => Err(quil_types::error::QuilError::Internal(format!(
                "TestKeyManager does not support key type {:?}",
                other
            ))),
        }
    }

    fn get_private_key(
        &self,
        key_type: quil_types::crypto::KeyType,
    ) -> quil_types::error::Result<Vec<u8>> {
        match key_type {
            quil_types::crypto::KeyType::Bls48581G1 => Ok(self.bls_private.clone()),
            other => Err(quil_types::error::QuilError::Internal(format!(
                "TestKeyManager does not support key type {:?}",
                other
            ))),
        }
    }

    fn get_peer_id(&self) -> quil_types::error::Result<Vec<u8>> {
        // Tests don't exercise the libp2p peer-id path; return a
        // deterministic placeholder derived from the pubkey.
        Ok(quil_crypto::poseidon::hash_bytes_to_32(&self.bls_public)
            .map(|h| h.to_vec())
            .unwrap_or_default())
    }
}

// =====================================================================
// AcceptAllKeyManager
// =====================================================================

/// Trivial [`quil_types::crypto::KeyManager`] for tests: every
/// `validate_signature` returns `Ok(true)`. Plumbed into
/// [`quil_execution::ExecutionEngineManager::new`] so the materializer
/// can process ProverJoin / ProverConfirm bundles without the test
/// having to produce byte-identical BLS aggregate signatures.
///
/// Not suitable for any production-bug verification path — by
/// definition it ignores cryptographic state. Wrap a real BLS verifier
/// when testing signature-failure paths.
pub struct AcceptAllKeyManager;

impl quil_types::crypto::KeyManager for AcceptAllKeyManager {
    fn validate_signature(
        &self,
        _key_type: quil_types::crypto::KeyType,
        _public_key: &[u8],
        _message: &[u8],
        _signature: &[u8],
        _domain: &[u8],
    ) -> quil_types::error::Result<bool> {
        Ok(true)
    }
}

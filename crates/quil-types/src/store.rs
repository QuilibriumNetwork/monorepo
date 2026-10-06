use crate::error::{QuilError, Result};
use crate::proto;
use num_bigint::BigInt;

// ---------------------------------------------------------------------------
// Core KV abstractions
// ---------------------------------------------------------------------------

/// Opaque process-local identity of one backing database or execution overlay.
/// It keeps the owner alive but grants no read/write access. Equal identities
/// name the same allocation, not merely the same path or on-disk contents.
#[derive(Clone)]
pub struct BackingStoreIdentity(std::sync::Arc<dyn std::any::Any + Send + Sync>);

impl BackingStoreIdentity {
    pub fn of<T: std::any::Any + Send + Sync>(owner: &std::sync::Arc<T>) -> Self {
        Self(owner.clone())
    }
}

impl PartialEq for BackingStoreIdentity {
    fn eq(&self, other: &Self) -> bool { std::sync::Arc::ptr_eq(&self.0, &other.0) }
}
impl Eq for BackingStoreIdentity {}

/// One ancillary record staged with an execution frame. `None` deletes the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordMutation {
    pub key: Vec<u8>,
    pub value: Option<Vec<u8>>,
}

/// Optional local-cache notification after a successful durable CRDT commit:
/// the committed vertex-adds blobs, then the execution records it wrote.
/// The callback must not block, perform I/O, or reenter the CRDT. Dropped
/// notifications are permitted: consumers must validate/rebuild their caches.
pub trait LocalVertexCommitObserver: Send + Sync {
    fn committed<'a>(&self, vertices: &mut dyn std::iter::Iterator<Item = (&'a [u8], &'a [u8])>);
}

/// Low-level key-value database interface (Pebble in Go, RocksDB in Rust).
pub trait KvDb: Send + Sync {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    fn set(&self, key: &[u8], value: &[u8]) -> Result<()>;
    fn delete(&self, key: &[u8]) -> Result<()>;
    fn new_batch(&self, indexed: bool) -> Result<Box<dyn Transaction>>;
    fn new_iter(&self, lower: &[u8], upper: &[u8]) -> Result<Box<dyn Iterator>>;
    fn compact(&self, start: &[u8], end: &[u8], parallelize: bool) -> Result<()>;
    fn compact_all(&self) -> Result<()>;
    fn close(&self) -> Result<()>;
    fn delete_range(&self, start: &[u8], end: &[u8]) -> Result<()>;
    /// Approximate bytes of process memory this DB instance holds (block
    /// cache + memtables + table-reader index/filter blocks). Used by memory
    /// diagnostics to attribute RSS to RocksDB — especially worker DBs, which
    /// run in separate threads invisible to the master's structural snapshot.
    /// Default `0` for non-RocksDB (in-memory / test) impls.
    fn approximate_memory_bytes(&self) -> u64 {
        0
    }
}

/// Batch/transaction abstraction over the KV store.
pub trait Transaction: Send + std::any::Any {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    fn set(&self, key: &[u8], value: &[u8]) -> Result<()>;
    fn commit(self: Box<Self>) -> Result<()>;
    fn delete(&self, key: &[u8]) -> Result<()>;
    fn abort(self: Box<Self>) -> Result<()>;
    fn new_iter(&self, lower: &[u8], upper: &[u8]) -> Result<Box<dyn Iterator>>;
    fn delete_range(&self, lower: &[u8], upper: &[u8]) -> Result<()>;
    /// Downcast hook: concrete impls (e.g. `RocksTxn`) that expose a
    /// `rocksdb::WriteBatch` return `self` via `Any` so store impls
    /// can batch writes into the backing batch rather than going
    /// straight to the DB. No-op txn types (MemStore, NoopTxn) should
    /// also return `self` here; it's the caller's job to inspect the
    /// concrete type.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Forward/reverse iterator over KV ranges.
pub trait Iterator: Send {
    fn key(&self) -> &[u8];
    fn value(&self) -> &[u8];
    fn first(&mut self) -> bool;
    fn next(&mut self) -> bool;
    fn prev(&mut self) -> bool;
    fn valid(&self) -> bool;
    fn close(&mut self) -> Result<()>;
    fn seek_lt(&mut self, target: &[u8]) -> bool;
    fn seek_ge(&mut self, target: &[u8]) -> bool;
    fn last(&mut self) -> bool;
}

// ---------------------------------------------------------------------------
// Shard info
// ---------------------------------------------------------------------------

/// Metadata about an application shard.
#[derive(Debug, Clone)]
pub struct ShardInfo {
    pub shard_key: Vec<u8>,
    pub prefix: Vec<u32>,
    pub size: Vec<u8>,
    pub data_shards: u64,
    pub commitment: Vec<Vec<u8>>,
}

/// The kind of a staged shard topology change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardChangeKind {
    /// Parent shard splits into the listed child sub-shards.
    Split,
    /// The listed child sub-shards merge back into the parent.
    Merge,
}

/// A staged (epoch-aligned) shard topology change. A split/merge proposed in
/// epoch E is recorded as pending and only flips the live topology at the E+2
/// boundary (`effective_epoch`), keeping committee membership frozen within an
/// epoch. Recorded deterministically by every node that materializes the op, so
/// the shards store stays consistent across the network. See
/// `[[epoch-aligned-lifecycle-design]]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingShardChange {
    pub kind: ShardChangeKind,
    /// The parent shard address (split source / merge target).
    pub parent: Vec<u8>,
    /// The child sub-shard addresses (split targets / merge sources).
    pub children: Vec<Vec<u8>>,
    /// The epoch at which the change takes effect (= epoch_for_frame(proposed)+2).
    pub effective_epoch: u64,
    /// The frame the op was materialized at (for diagnostics / ordering).
    pub proposed_frame: u64,
}

impl PendingShardChange {
    /// True when this pending change touches the given shard address — either as
    /// the parent or one of the children. Used by the join-freeze gate: a join
    /// targeting a shard with a pending change (between E and E+2) is rejected
    /// because the shard's existence/identity is about to change.
    pub fn affects_shard(&self, shard: &[u8]) -> bool {
        self.parent == shard || self.children.iter().any(|c| c == shard)
    }
}

// ---------------------------------------------------------------------------
// Domain-specific stores
// ---------------------------------------------------------------------------

/// The result of MATERIALIZING one request bundle in a finalized frame.
/// A frame carries every structurally-valid bundle, but that does not mean the
/// bundle's op actually applied — it may fail signature validation or execution.
/// Recorded per bundle (in frame order) so the explorer can show whether each
/// request took effect. Deterministic across nodes (same frame → same outcomes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestStatus {
    /// `process_message` succeeded — the op applied.
    Succeeded,
    /// Failed signature / PoP / protocol validation before execution.
    Rejected,
    /// Passed validation but `process_message` returned an error.
    Failed,
    /// Structurally unusable (canonical-encode failure / too short).
    Skipped,
}

impl RequestStatus {
    pub fn as_u8(&self) -> u8 {
        match self {
            RequestStatus::Succeeded => 0,
            RequestStatus::Rejected => 1,
            RequestStatus::Failed => 2,
            RequestStatus::Skipped => 3,
        }
    }
    pub fn from_u8(b: u8) -> Self {
        match b {
            1 => RequestStatus::Rejected,
            2 => RequestStatus::Failed,
            3 => RequestStatus::Skipped,
            _ => RequestStatus::Succeeded,
        }
    }
    /// Lowercase wire name for the explorer JSON.
    pub fn name(&self) -> &'static str {
        match self {
            RequestStatus::Succeeded => "succeeded",
            RequestStatus::Rejected => "rejected",
            RequestStatus::Failed => "failed",
            RequestStatus::Skipped => "skipped",
        }
    }
}

/// One bundle's materialization outcome: status + a short reason (empty for
/// `Succeeded`/`Skipped`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestOutcome {
    pub status: RequestStatus,
    pub error: String,
}

/// Clock/frame storage.
/// A prepared local cache change. Acquire all fallible locks before the durable
/// execution batch; adoption performs no I/O and must not reenter the store.
/// Retain the guard until all related execution metadata has been adopted.
pub trait ExecutionPublicationObserver {
    fn adopt(&mut self);
}

pub trait ClockStore: Send + Sync {
    /// Process-local backing storage identity for constructing execution contexts.
    fn backing_store_identity(&self) -> Option<BackingStoreIdentity> { None }

    fn prepare_execution_publication(&self) -> Result<Box<dyn ExecutionPublicationObserver + '_>> {
        Err(QuilError::ExecutionUnavailable("clock does not support canonical execution publication".into()))
    }

    fn new_transaction(&self, indexed: bool) -> Result<Box<dyn Transaction>>;

    // Global frames
    fn get_latest_global_clock_frame(&self) -> Result<proto::global::GlobalFrame>;
    fn get_earliest_global_clock_frame(&self) -> Result<proto::global::GlobalFrame>;
    fn get_global_clock_frame(&self, frame_number: u64) -> Result<proto::global::GlobalFrame>;
    fn put_global_clock_frame(
        &self,
        frame: &proto::global::GlobalFrame,
        txn: &dyn Transaction,
    ) -> Result<()>;
    fn put_global_clock_frame_candidate(
        &self,
        frame: &proto::global::GlobalFrame,
        txn: &dyn Transaction,
    ) -> Result<()>;
    fn get_global_clock_frame_candidate(
        &self,
        frame_number: u64,
        selector: &[u8],
    ) -> Result<proto::global::GlobalFrame>;
    /// Persist the per-bundle MATERIALIZATION outcomes for a frame (in frame
    /// order, one per `frame.requests` bundle). Written by the materializer
    /// AFTER the frame + its requests are stored. Default no-op for backends
    /// that don't record outcomes (tests / in-memory).
    fn put_global_clock_frame_outcomes(
        &self,
        _frame_number: u64,
        _outcomes: &[RequestOutcome],
    ) -> Result<()> {
        Ok(())
    }
    /// Persist the fee total (QUIL base units) of a materialized shard frame:
    /// the next proposal carries it as `FrameHeader.fee_total` and every
    /// validator recomputes it, so it must survive a restart. Default no-op.
    fn put_shard_frame_fee_total(&self, _filter: &[u8], _frame_number: u64, _fee_total: u128) -> Result<()> {
        Ok(())
    }
    /// The persisted fee total of a materialized shard frame, if recorded.
    fn get_shard_frame_fee_total(&self, _filter: &[u8], _frame_number: u64) -> Result<Option<u128>> {
        Ok(None)
    }
    /// Persist the settlement relay entries a materialized shard frame
    /// produced (canonical `settlement_record::encode_entries` bytes, empty
    /// for none). Later frame headers relay them. Default no-op.
    fn put_shard_frame_settlements(&self, _filter: &[u8], _frame_number: u64, _entries: &[u8]) -> Result<()> {
        Ok(())
    }
    /// The persisted settlement entries of a shard frame, if recorded.
    fn get_shard_frame_settlements(&self, _filter: &[u8], _frame_number: u64) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    /// Persist a materialized shard frame's accumulator record: the digest of
    /// the shard's report at that frame (empty for none), and the report bytes
    /// under that digest. Later frame headers carry the report. Default no-op.
    fn put_shard_frame_accumulator(&self, _filter: &[u8], _frame_number: u64, _digest: &[u8], _report: &[u8]) -> Result<()> {
        Ok(())
    }
    /// The recorded accumulator-report digest of a shard frame, if recorded.
    fn get_shard_frame_accumulator(&self, _filter: &[u8], _frame_number: u64) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    /// Persist the spend entries a materialized shard frame produced
    /// (`spend_relay::encode_frame_entries` bytes). Default no-op.
    fn put_shard_frame_spends(&self, _filter: &[u8], _frame_number: u64, _entries: &[u8]) -> Result<()> {
        Ok(())
    }
    /// The recorded spend entries of a shard frame, if recorded.
    fn get_shard_frame_spends(&self, _filter: &[u8], _frame_number: u64) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    /// The report bytes stored under `digest`, if recorded.
    fn get_shard_accumulator_report(&self, _filter: &[u8], _digest: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    /// Read the per-bundle materialization outcomes for a frame (empty if the
    /// frame hasn't materialized yet or the backend doesn't record them).
    fn get_global_clock_frame_outcomes(
        &self,
        _frame_number: u64,
    ) -> Result<Vec<RequestOutcome>> {
        Ok(Vec::new())
    }
    /// Returns up to `limit` candidate frames in
    /// `[min_frame_number, max_frame_number]` (any selector). Used as
    /// a fallback when the certified frame isn't available — mirrors
    /// Go's `RangeGlobalClockFrameCandidates` at
    /// `clock_store.go:RangeGlobalClockFrameCandidates`. Default
    /// implementation returns an empty vec for backends that don't
    /// store candidates; kick-verify treats that as "no fallback
    /// available" and surfaces the certified-fetch error.
    fn range_global_clock_frame_candidates(
        &self,
        _min_frame_number: u64,
        _max_frame_number: u64,
        _limit: usize,
    ) -> Result<Vec<proto::global::GlobalFrame>> {
        Ok(Vec::new())
    }
    fn delete_global_clock_frame_range(
        &self,
        min_frame: u64,
        max_frame: u64,
    ) -> Result<()>;
    fn reset_global_clock_frames(&self) -> Result<()>;

    // Global certified state
    fn get_latest_certified_global_state(&self) -> Result<proto::global::GlobalProposal>;
    fn get_earliest_certified_global_state(&self) -> Result<proto::global::GlobalProposal>;
    fn get_certified_global_state(&self, rank: u64) -> Result<proto::global::GlobalProposal>;
    fn put_certified_global_state(
        &self,
        state: &proto::global::GlobalProposal,
        txn: &dyn Transaction,
    ) -> Result<()>;

    // Quorum certificates
    fn get_latest_quorum_certificate(
        &self,
        filter: &[u8],
    ) -> Result<proto::global::QuorumCertificate>;
    fn get_quorum_certificate(
        &self,
        filter: &[u8],
        rank: u64,
    ) -> Result<proto::global::QuorumCertificate>;
    fn put_quorum_certificate(
        &self,
        qc: &proto::global::QuorumCertificate,
        txn: &dyn Transaction,
    ) -> Result<()>;

    // Timeout certificates
    fn get_latest_timeout_certificate(
        &self,
        filter: &[u8],
    ) -> Result<proto::global::TimeoutCertificate>;
    fn get_timeout_certificate(
        &self,
        filter: &[u8],
        rank: u64,
    ) -> Result<proto::global::TimeoutCertificate>;
    fn put_timeout_certificate(
        &self,
        tc: &proto::global::TimeoutCertificate,
        txn: &dyn Transaction,
    ) -> Result<()>;

    // Shard frames
    fn get_latest_shard_clock_frame(
        &self,
        filter: &[u8],
    ) -> Result<proto::global::AppShardFrame>;
    /// The latest stored frame number of shard `filter`, without reading the
    /// frame: an application frame can be megabytes, and status queries need
    /// only its number. `None` when the shard has no frame.
    fn get_latest_shard_clock_frame_number(&self, filter: &[u8]) -> Result<Option<u64>> {
        match self.get_latest_shard_clock_frame(filter) {
            Ok(frame) => Ok(frame.header.map(|header| header.frame_number)),
            Err(crate::error::QuilError::NotFound(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }
    fn get_shard_clock_frame(
        &self,
        filter: &[u8],
        frame_number: u64,
        truncate: bool,
    ) -> Result<proto::global::AppShardFrame>;
    fn commit_shard_clock_frame(
        &self,
        filter: &[u8],
        frame_number: u64,
        selector: &[u8],
        txn: &dyn Transaction,
        backfill: bool,
    ) -> Result<()>;
    fn stage_shard_clock_frame(
        &self,
        selector: &[u8],
        frame: &proto::global::AppShardFrame,
        txn: &dyn Transaction,
    ) -> Result<()>;
    fn get_staged_shard_clock_frame(
        &self,
        filter: &[u8],
        frame_number: u64,
        parent_selector: &[u8],
        truncate: bool,
    ) -> Result<proto::global::AppShardFrame>;
    fn set_latest_shard_clock_frame_number(
        &self,
        filter: &[u8],
        frame_number: u64,
    ) -> Result<()>;
    fn delete_shard_clock_frame_range(
        &self,
        filter: &[u8],
        min_frame: u64,
        max_frame: u64,
    ) -> Result<()>;
    fn reset_shard_clock_frames(&self, filter: &[u8]) -> Result<()>;

    /// Committee-handoff flag day: discard every application-shard frame
    /// chain this store holds (frames, their indexes and staged copies,
    /// per-frame relay records, application cursors and legacy consensus
    /// keys), keeping application state and every GLOBAL frame, and record
    /// that it ran at `global_frame`. One write; idempotent.
    fn discard_app_frame_history(&self, _global_frame: u64) -> Result<()> {
        Err(crate::error::QuilError::Internal(
            "this clock store cannot discard application frame history".into(),
        ))
    }

    /// The GLOBAL frame [`Self::discard_app_frame_history`] ran at, if it has.
    fn app_frame_history_discarded(&self) -> Result<Option<u64>> {
        Ok(None)
    }

    // Shard certified state
    fn get_latest_certified_app_shard_state(
        &self,
        filter: &[u8],
    ) -> Result<proto::global::AppShardProposal>;
    fn put_certified_app_shard_state(
        &self,
        state: &proto::global::AppShardProposal,
        txn: &dyn Transaction,
    ) -> Result<()>;

    // Proposal / timeout votes
    fn put_proposal_vote(
        &self,
        txn: &dyn Transaction,
        vote: &proto::global::ProposalVote,
    ) -> Result<()>;
    fn get_proposal_vote(
        &self,
        filter: &[u8],
        rank: u64,
        identity: &[u8],
    ) -> Result<proto::global::ProposalVote>;
    fn get_proposal_votes(
        &self,
        filter: &[u8],
        rank: u64,
    ) -> Result<Vec<proto::global::ProposalVote>>;
    fn put_timeout_vote(
        &self,
        txn: &dyn Transaction,
        vote: &proto::global::TimeoutState,
    ) -> Result<()>;
    fn get_timeout_vote(
        &self,
        filter: &[u8],
        rank: u64,
        identity: &[u8],
    ) -> Result<proto::global::TimeoutState>;
    fn get_timeout_votes(
        &self,
        filter: &[u8],
        rank: u64,
    ) -> Result<Vec<proto::global::TimeoutState>>;

    // Distance / seniority
    fn get_total_distance(
        &self,
        filter: &[u8],
        frame_number: u64,
        selector: &[u8],
    ) -> Result<BigInt>;
    fn set_total_distance(
        &self,
        filter: &[u8],
        frame_number: u64,
        selector: &[u8],
        total_distance: &BigInt,
    ) -> Result<()>;
    fn get_peer_seniority_map(
        &self,
        filter: &[u8],
    ) -> Result<std::collections::HashMap<String, u64>>;
    fn put_peer_seniority_map(
        &self,
        txn: &dyn Transaction,
        filter: &[u8],
        seniority_map: &std::collections::HashMap<String, u64>,
    ) -> Result<()>;

    // Compaction
    fn compact_data(&self, data_filter: &[u8]) -> Result<()>;
}

/// Token/balance storage.
pub trait TokenStore: Send + Sync {
    fn new_transaction(&self, indexed: bool) -> Result<Box<dyn Transaction>>;

    // Coins (legacy)
    fn get_coins_for_owner(
        &self,
        owner: &[u8],
    ) -> Result<(Vec<u64>, Vec<Vec<u8>>, Vec<proto::node::Coin>)>;
    fn get_coin_by_address(&self, address: &[u8]) -> Result<(u64, proto::node::Coin)>;
    fn put_coin(
        &self,
        txn: &dyn Transaction,
        frame_number: u64,
        address: &[u8],
        coin: &proto::node::Coin,
    ) -> Result<()>;
    fn delete_coin(
        &self,
        txn: &dyn Transaction,
        address: &[u8],
        coin: &proto::node::Coin,
    ) -> Result<()>;

    // Materialized transactions
    fn get_transactions_for_owner(
        &self,
        domain: &[u8],
        owner: &[u8],
    ) -> Result<Vec<proto::node::MaterializedTransaction>>;
    fn get_transaction_by_address(
        &self,
        domain: &[u8],
        address: &[u8],
    ) -> Result<proto::node::MaterializedTransaction>;
    fn put_transaction(
        &self,
        txn: &dyn Transaction,
        domain: &[u8],
        owner: &[u8],
        transaction: &proto::node::MaterializedTransaction,
    ) -> Result<()>;
    fn delete_transaction(
        &self,
        txn: &dyn Transaction,
        domain: &[u8],
        address: &[u8],
        owner: &[u8],
    ) -> Result<()>;

    // Pending transactions
    fn get_pending_transactions_for_owner(
        &self,
        domain: &[u8],
        owner: &[u8],
    ) -> Result<Vec<proto::node::MaterializedPendingTransaction>>;
    fn get_pending_transaction_by_address(
        &self,
        domain: &[u8],
        address: &[u8],
    ) -> Result<proto::node::MaterializedPendingTransaction>;
    fn put_pending_transaction(
        &self,
        txn: &dyn Transaction,
        domain: &[u8],
        owner: &[u8],
        pending: &proto::node::MaterializedPendingTransaction,
    ) -> Result<()>;
    fn delete_pending_transaction(
        &self,
        txn: &dyn Transaction,
        domain: &[u8],
        owner: &[u8],
        pending: &proto::node::MaterializedPendingTransaction,
    ) -> Result<()>;
}

/// Key registry storage.
pub trait KeyStore: Send + Sync {
    fn new_transaction(&self) -> Result<Box<dyn Transaction>>;
    fn put_identity_key(
        &self,
        txn: &dyn Transaction,
        address: &[u8],
        key: &proto::keys::Ed448PublicKey,
    ) -> Result<()>;
    fn get_identity_key(&self, address: &[u8]) -> Result<proto::keys::Ed448PublicKey>;
    fn put_proving_key(
        &self,
        txn: &dyn Transaction,
        address: &[u8],
        key: &proto::keys::Bls48581SignatureWithProofOfPossession,
    ) -> Result<()>;
    fn get_proving_key(
        &self,
        address: &[u8],
    ) -> Result<proto::keys::Bls48581SignatureWithProofOfPossession>;
    fn put_cross_signature(
        &self,
        txn: &dyn Transaction,
        identity_key_address: &[u8],
        proving_key_address: &[u8],
        identity_sig_of_proving: &[u8],
        proving_sig_of_identity: &[u8],
    ) -> Result<()>;
    fn get_cross_signature_by_identity_key(
        &self,
        identity_key_address: &[u8],
    ) -> Result<Vec<u8>>;
    fn get_cross_signature_by_proving_key(
        &self,
        proving_key_address: &[u8],
    ) -> Result<Vec<u8>>;
    fn put_signed_x448_key(
        &self,
        txn: &dyn Transaction,
        address: &[u8],
        key: &proto::keys::SignedX448Key,
    ) -> Result<()>;
    fn get_signed_x448_key(&self, address: &[u8]) -> Result<proto::keys::SignedX448Key>;
    fn get_signed_x448_keys_by_parent(
        &self,
        parent_key_address: &[u8],
        key_purpose: &str,
    ) -> Result<Vec<proto::keys::SignedX448Key>>;
    fn get_key_registry(&self, identity_key_address: &[u8]) -> Result<proto::keys::KeyRegistry>;
    fn get_key_registry_by_prover(
        &self,
        prover_key_address: &[u8],
    ) -> Result<proto::keys::KeyRegistry>;
}

/// Persisted per-worker state. Mirrors Go's `store.WorkerInfo` —
/// kept on disk so that `manually_managed` and the assigned
/// `filter` survive node restarts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedWorkerInfo {
    pub core_id: u32,
    pub filter: Vec<u8>,
    pub manually_managed: bool,
    pub allocated: bool,
    pub pending_filter_frame: u64,
}

/// Worker registry storage. Persists `(core_id, filter,
/// manually_managed, allocated, pending_filter_frame)` so the
/// operator's intent (manual mode + which shard the worker is
/// pinned to) carries across restarts. Mirrors Go's
/// `store.WorkerStore`.
pub trait WorkerStore: Send + Sync {
    fn get_worker(&self, core_id: u32) -> Result<Option<PersistedWorkerInfo>>;
    fn put_worker(&self, worker: &PersistedWorkerInfo) -> Result<()>;
    fn delete_worker(&self, core_id: u32) -> Result<()>;
    fn range_workers(&self) -> Result<Vec<PersistedWorkerInfo>>;
}

/// Application shard metadata storage.
pub trait ShardsStore: Send + Sync {
    /// Identity of the committed backing store. A staged metadata batch is
    /// deliberately not an independently capturable committed store.
    fn backing_store_identity(&self) -> Option<BackingStoreIdentity> { None }

    fn range_app_shards(&self) -> Result<Vec<ShardInfo>>;
    fn get_app_shards(&self, shard_key: &[u8], prefix: &[u32]) -> Result<Vec<ShardInfo>>;
    fn put_app_shard(&self, txn: &dyn Transaction, shard: &ShardInfo) -> Result<()>;
    fn delete_app_shard(
        &self,
        txn: &dyn Transaction,
        shard_key: &[u8],
        prefix: &[u32],
    ) -> Result<()>;

    // ---- Epoch-aligned pending topology changes -----------------------------
    // Default no-ops so light/test stores don't need to implement staging; the
    // persistent RocksDB store overrides them.

    /// Stage a pending split/merge. Recorded by `invoke_shard_split/merge` at
    /// proposal time; applied at the `effective_epoch` boundary.
    fn put_pending_shard_change(
        &self,
        _txn: &dyn Transaction,
        _change: &PendingShardChange,
    ) -> Result<()> {
        Ok(())
    }

    /// All pending changes that take effect at exactly `effective_epoch` — the
    /// set the epoch-boundary materializer applies when the chain crosses into
    /// that epoch.
    fn get_pending_shard_changes(&self, _effective_epoch: u64) -> Result<Vec<PendingShardChange>> {
        Ok(Vec::new())
    }

    /// Every staged change not yet applied — used by the join-freeze gate to ask
    /// "does any pending change touch this shard?".
    fn all_pending_shard_changes(&self) -> Result<Vec<PendingShardChange>> {
        Ok(Vec::new())
    }

    /// Remove a staged change after it has been applied (or superseded).
    fn delete_pending_shard_change(
        &self,
        _txn: &dyn Transaction,
        _parent: &[u8],
        _effective_epoch: u64,
    ) -> Result<()> {
        Ok(())
    }
}

/// A PoMW reward-mint witness (see [`CoinWitnessProvider::prover_reward_witness`]):
/// the forest membership proof of the owner's `reward:ProverReward` vertex, the
/// current claimable `value` (the Balance field), and the `cited_frame` whose
/// header `prover_tree_commitment` is the reward root the proof verifies against.
#[derive(Debug, Clone, Default)]
pub struct RewardWitnessData {
    pub found: bool,
    pub forest_proof: Vec<u8>,
    pub value: u128,
    pub cited_frame: u64,
    pub reward_root: Vec<u8>,
}

/// Historical global membership, not proof that the authorization is unspent.
/// The consumer must verify its exact receipt/output fields and consensus root.
#[derive(Debug, Clone, Default)]
pub struct MintAuthorizationWitnessData {
    pub found: bool,
    pub forest_proof: Vec<u8>,
    pub cited_frame: u64,
    pub global_root: Vec<u8>,
}

/// Coin witness transport data, independent of lattice implementation types.
pub struct CoinWitnessData {
    pub address: [u8; 32],
    pub found: bool,
    pub siblings: Vec<Vec<u8>>,
    pub right: Vec<bool>,
}
pub struct CoinWitnessBundle {
    pub network: [u8; 32],
    pub root_record: Vec<u8>,
    pub depth: u8,
    pub witnesses: Vec<CoinWitnessData>,
}

pub struct CoinData {
    pub address: [u8; 32],
    pub frame_number: u64,
    /// Accumulator leaf index; part of the coin's committed content address.
    pub position: u64,
    pub owner: Vec<u8>,
    pub commitment: Vec<u8>,
    pub memo: Vec<u8>,
}
pub struct EscrowPageData {
    pub network: [u8; 32],
    pub snapshot_id: [u8; 32],
    pub escrows: Vec<([u8; 32], Vec<u8>)>,
    pub cursor: Option<[u8; 32]>,
    pub has_more: bool,
}

pub struct CoinPageData {
    pub network: [u8; 32],
    pub snapshot_id: [u8; 32],
    pub root_record: Vec<u8>,
    pub coins: Vec<CoinData>,
    pub cursor: Option<[u8; 32]>,
    pub has_more: bool,
}

/// Node-side QCT3 wallet discovery, membership and mint-witness provider.
pub trait CoinWitnessProvider: Send + Sync {
    fn escrow_page(&self, _domain: &[u8; 32], _snapshot_id: Option<&[u8; 32]>, _after: Option<&[u8; 32]>) -> Result<Option<EscrowPageData>> {
        Ok(None)
    }

    fn mint_authorization_witness(&self, _receipt: &[u8; 32]) -> Result<MintAuthorizationWitnessData> {
        Err(crate::error::QuilError::ExecutionUnavailable("mint authorization witnesses unavailable".into()))
    }
    fn coin_page(&self, _domain: &[u8; 32], _snapshot_id: Option<&[u8; 32]>, _after: Option<&[u8; 32]>) -> Result<Option<CoinPageData>> {
        Ok(None)
    }

    /// None means the provider has not enabled the token suite.
    fn coin_witnesses(&self, _domain: &[u8; 32], _addresses: &[[u8; 32]]) -> Result<Option<CoinWitnessBundle>> {
        Ok(None)
    }

    /// Build a PoMW reward-mint witness for `owner_prover_address` in `domain`
    /// (for the `token mint` flow). Default `found = false` so existing
    /// providers compile without change.
    fn prover_reward_witness(
        &self,
        _domain: &[u8],
        _owner_prover_address: &[u8],
    ) -> Result<RewardWitnessData> {
        Ok(RewardWitnessData::default())
    }
}

/// Bounds retained page data; excludes iterator/internal database memory.
#[derive(Clone, Copy)]
pub struct VertexPageLimits {
    pub max_entries: usize,
    pub max_bytes: usize,
}

pub struct VertexDataPage {
    /// Address and latest blob, in ascending address order, for one domain.
    pub entries: Vec<([u8; 32], Vec<u8>)>,
    pub has_more: bool,
}

pub trait HypergraphStore: Send + Sync {
    /// Clear legacy and versioned underlying rows in all four phases of one
    /// shard. Forest maintenance is separate and must share the same barrier.
    fn clear_shard_underlying(&self, _shard: &ShardKey) -> Result<()> {
        Err(QuilError::ExecutionUnavailable("shard record reset unsupported".into()))
    }

    /// Delete every `root → (version, frame)` index entry of one shard id's four
    /// phase trees, for a tree that was just wiped. Returns how many.
    fn clear_root_versions(&self, _shard_id: &[u8]) -> Result<usize> {
        Ok(0)
    }

    /// [`Self::clear_root_versions`] for one `(set, phase)` tree.
    fn clear_phase_root_versions(&self, _set_type: &str, _phase_type: &str, _shard_id: &[u8]) -> Result<usize> {
        Ok(0)
    }

    /// Required when constructing an execution fork: the forest and record
    /// store must address the same backing database/overlay. Unknown backends
    /// cannot claim this invariant by default.
    fn backing_store_identity(&self) -> Option<BackingStoreIdentity> { None }

    /// Page fixed 64-byte domain/address keys, merging latest MVCC and legacy
    /// values. The cursor is exclusive. Each call is a consistent snapshot;
    /// separate calls are not automatically pinned to the same version.
    fn page_vertex_underlying_fixed(
        &self, _set_type: &str, _phase_type: &str, _shard: &ShardKey,
        _domain: &[u8; 32], _after: Option<&[u8; 32]>, _limits: VertexPageLimits,
    ) -> Result<VertexDataPage> {
        Err(QuilError::Store("fixed vertex paging is unsupported by this backend".into()))
    }

    fn new_transaction(&self, indexed: bool) -> Result<Box<dyn Transaction>>;

    fn get_node_by_key(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>>;

    fn get_node_by_path(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        path: &[i32],
    ) -> Result<Option<Vec<u8>>>;

    fn insert_node(
        &self,
        txn: &dyn Transaction,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        key: &[u8],
        path: &[i32],
        data: &[u8],
    ) -> Result<()>;

    fn save_root(
        &self,
        txn: &dyn Transaction,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        data: &[u8],
    ) -> Result<()>;

    fn delete_node(
        &self,
        txn: &dyn Transaction,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        key: &[u8],
        path: &[i32],
    ) -> Result<()>;

    fn set_covered_prefix(&self, covered_prefix: &[i32]) -> Result<()>;

    fn set_shard_commit(
        &self,
        txn: &dyn Transaction,
        frame_number: u64,
        phase_type: &str,
        set_type: &str,
        shard_address: &[u8],
        commitment: &[u8],
    ) -> Result<()>;

    fn get_shard_commit(
        &self,
        frame_number: u64,
        phase_type: &str,
        set_type: &str,
        shard_address: &[u8],
    ) -> Result<Vec<u8>>;

    fn get_root_commits(
        &self,
        frame_number: u64,
    ) -> Result<std::collections::HashMap<ShardKey, Vec<Vec<u8>>>>;

    /// Delete the cached per-frame shard-commit roots (all four phases)
    /// for a single shard, identified by its 32-byte shard address (the
    /// `ShardKey.l2`). Used to force `commit(frame_number)` to recompute
    /// and reflush a shard whose tree was mutated AFTER that frame's first
    /// commit — the same-frame idempotency cache would otherwise reuse the
    /// stale cached root and skip the now-dirty tree. Default no-op for
    /// stores without a per-frame commit cache (test/in-memory impls).
    fn delete_shard_commits(
        &self,
        _frame_number: u64,
        _shard_address: &[u8],
    ) -> Result<()> {
        Ok(())
    }

    /// Load one vertex's underlying data blob (Go-serialized tree format
    /// per `SerializeNonLazyTree`), or `Ok(None)` if absent. Used by
    /// `NodeService::GetVertexData` / `GetHyperedgeData` to serve
    /// `full_data=true` responses and to enumerate known leaf indices.
    fn load_vertex_underlying_raw(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        vertex_key: &[u8],
    ) -> Result<Option<Vec<u8>>>;

    /// Persist one vertex's underlying data blob to the per-vertex
    /// keyspace. Mirrors Go's `SetVertexData` —
    /// `vertex_key` is the 64-byte `domain || address` identifier and
    /// `data` is the Go-serialized sub-tree blob. The per-vertex
    /// keyspace is the canonical record of vertex content; the lazy
    /// commitment tree blob is metadata-only.
    ///
    /// The write joins `txn` (staged into its batch) so that vertex
    /// content becomes durable atomically with the tree nodes and shard
    /// commit of the surrounding transaction — matching Go's
    /// `SaveVertexTree`, which threads the transaction through to
    /// `txn.Set`. 
    fn save_vertex_underlying(
        &self,
        txn: &dyn Transaction,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        vertex_key: &[u8],
        data: &[u8],
    ) -> Result<()>;

    /// Iterate every `(vertex_key, data)` pair persisted for the given
    /// `(set, phase, shard)`. The callback receives owned bytes.
    /// Returns the count of entries visited.
    fn for_each_vertex_underlying(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        callback: &mut dyn FnMut(Vec<u8>, Vec<u8>),
    ) -> Result<usize>;

    // -------------------------------------------------------------------
    // Versioned (MVCC) blob store + root→version index + split-app manifest.
    // Default impls make the versioned store degrade to the legacy unversioned
    // behavior so mocks and alternate backends compile unchanged;
    // RocksHypergraphStore overrides
    // them with real MVCC semantics.
    // -------------------------------------------------------------------

    /// Persist a vertex blob at a specific per-`(shard,phase)` commit `version`,
    /// staged into `txn`. The read path (`load_vertex_underlying_at`) resolves
    /// the latest write with version ≤ a requested version.
    fn save_vertex_underlying_versioned(
        &self,
        txn: &dyn Transaction,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        vertex_key: &[u8],
        data: &[u8],
        _version: u64,
    ) -> Result<()> {
        // Default: fall back to the unversioned write (latest-only).
        self.save_vertex_underlying(txn, set_type, phase_type, shard_key, vertex_key, data)
    }

    /// MVCC read: the blob for `vertex_key` as-of `version` (latest write ≤ V).
    fn load_vertex_underlying_at(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
        vertex_key: &[u8],
        _version: u64,
    ) -> Result<Option<Vec<u8>>> {
        // Default: no versioning — return the latest.
        self.load_vertex_underlying_raw(set_type, phase_type, shard_key, vertex_key)
    }

    /// Delete every stored version of `vertex_key`'s blob from `first` on,
    /// staged into `txn`. A shard rewind uses it for removals made after the
    /// state it restores: any removes-phase blob hides its vertex, so a newer
    /// empty one cannot undo a removal. Default: unsupported.
    fn delete_vertex_underlying_versions_from(
        &self,
        _txn: &dyn Transaction,
        _set_type: &str,
        _phase_type: &str,
        _shard_key: &ShardKey,
        _vertex_key: &[u8],
        _first: u64,
    ) -> Result<()> {
        Err(crate::error::QuilError::Internal("this store keeps no blob versions to delete".into()))
    }

    /// Record `root_hash → (version, global_frame)` for a `(shard, phase)` tree,
    /// staged into `txn`. Written atomically with the tree/blob commit so any
    /// committed root resolves to the local version that can fully serve it.
    fn put_root_version(
        &self,
        _txn: &dyn Transaction,
        _set_type: &str,
        _phase_type: &str,
        _shard_id: &[u8],
        _root_hash: &[u8],
        _version: u64,
        _frame_number: u64,
    ) -> Result<()> {
        Ok(())
    }

    /// Resolve a `(shard, phase)` tree root → `(version, global_frame)` on this
    /// node. `None` if this node never committed that root (behind or pruned).
    fn get_root_version(
        &self,
        _set_type: &str,
        _phase_type: &str,
        _shard_id: &[u8],
        _root_hash: &[u8],
    ) -> Result<Option<(u64, u64)>> {
        Ok(None)
    }

    /// Record a split app's `app_root → [(prefix, sub_root, version)]` manifest,
    /// staged into `txn`, so a sync-by-hash of the aggregate root can be split
    /// into per-sub-shard syncs. `entries` are `(prefix_bytes, sub_root(32), ver)`.
    fn put_app_manifest(
        &self,
        _txn: &dyn Transaction,
        _set_type: &str,
        _phase_type: &str,
        _app_address: &[u8],
        _app_root: &[u8],
        _entries: &[(Vec<u8>, [u8; 32], u64)],
        _frame_number: u64,
    ) -> Result<()> {
        Ok(())
    }

    /// Resolve a split app's `app_root` → its sub-shard manifest on this node.
    fn get_app_manifest(
        &self,
        _set_type: &str,
        _phase_type: &str,
        _app_address: &[u8],
        _app_root: &[u8],
    ) -> Result<Option<Vec<(Vec<u8>, [u8; 32], u64)>>> {
        Ok(None)
    }

    /// Prune superseded versioned state older than the 2-epoch retention
    /// watermark derived from `cull_frame` (the versioned blob keyspace, the
    /// `root→version` index, and split-app manifests). Returns per-tree
    /// `(shard_id, phase_idx, min_readable_version)` so the caller can prune the
    /// matching forest trees in lockstep. Default: no-op (unversioned backends).
    fn prune_versioned(&self, _cull_frame: u64) -> Result<Vec<(Vec<u8>, usize, u64)>> {
        Ok(Vec::new())
    }

    /// Like [`prune_versioned`](Self::prune_versioned), but each tree keeps the
    /// last `retain_frames` of its own indexed frames, and at most
    /// `max_blob_deletes` blob versions are deleted per call. `head` gives a
    /// tree's current version, `(shard id, phase index)`. Trees whose versions
    /// restart are left untouched; with a head known, a tree whose frames fall
    /// while its versions rise is pruned conservatively.
    fn prune_versioned_retaining(
        &self,
        _retain_frames: u64,
        _max_blob_deletes: usize,
        _head: &dyn Fn(&[u8], usize) -> Option<u64>,
    ) -> Result<Vec<(Vec<u8>, usize, u64)>> {
        Ok(Vec::new())
    }

    fn apply_snapshot(&self, db_path: &str) -> Result<()>;

    fn set_alt_shard_commit(
        &self,
        txn: &dyn Transaction,
        frame_number: u64,
        shard_address: &[u8],
        vertex_adds_root: &[u8],
        vertex_removes_root: &[u8],
        hyperedge_adds_root: &[u8],
        hyperedge_removes_root: &[u8],
    ) -> Result<()>;

    fn get_latest_alt_shard_commit(
        &self,
        shard_address: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>;

    fn range_alt_shard_addresses(&self) -> Result<Vec<Vec<u8>>>;

    fn reap_old_changesets(
        &self,
        txn: &dyn Transaction,
        frame_number: u64,
    ) -> Result<()>;

    fn track_change(
        &self,
        txn: &dyn Transaction,
        key: &[u8],
        old_value: Option<&[u8]>,
        frame_number: u64,
        phase_type: &str,
        set_type: &str,
        shard_key: &ShardKey,
    ) -> Result<()>;

    fn get_changes(
        &self,
        frame_start: u64,
        frame_end: u64,
        phase_type: &str,
        set_type: &str,
        shard_key: &ShardKey,
    ) -> Result<Vec<ChangeRecord>>;

    fn untrack_change(
        &self,
        txn: &dyn Transaction,
        key: &[u8],
        frame_number: u64,
        phase_type: &str,
        set_type: &str,
        shard_key: &ShardKey,
    ) -> Result<()>;

    /// Capture a point-in-time snapshot of all known per-shard tree
    /// blobs. Used by the snapshot manager to bind a published root to
    /// the exact backing-store state at publish time, so concurrent
    /// writes after the publish do not corrupt the bytes a sync client
    /// receives. Returns `None` if the implementation cannot capture a
    /// snapshot (default behaviour); callers fall back to the live
    /// store. Mirrors Go `TreeBackingStore.NewDBSnapshot`.
    fn capture_tree_snapshot(
        &self,
    ) -> Result<Option<std::sync::Arc<dyn SnapshotReadable>>> {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Supporting types used across store traits
// ---------------------------------------------------------------------------

/// Where a read-only scan read one database: the database instance and an
/// interval containing the sequence of the snapshot it read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanPoint {
    pub database: u64,
    pub from: u64,
    pub to: u64,
}

/// A captured view of one database, with the sequence of the last write to
/// the database's watched keys when it was captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapturePoint {
    pub database: u64,
    pub sequence: u64,
    pub watched: u64,
}

impl CapturePoint {
    /// Whether a scan of the watched keys at `scan` read exactly what this
    /// view holds there: the same database, no later than this view, and no
    /// watched write after the scan's snapshot.
    pub fn sees_watched_keys_of(&self, scan: &ScanPoint) -> bool {
        scan.database == self.database && scan.to <= self.sequence && self.watched <= scan.from
    }
}

/// Shard key: L1 bloom filter (3 bytes) + L2 app address (32 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ShardKey {
    pub l1: [u8; 3],
    pub l2: [u8; 32],
}

/// A record of a tree mutation, for reversion support.
#[derive(Debug, Clone)]
pub struct ChangeRecord {
    pub key: Vec<u8>,
    pub old_value: Option<Vec<u8>>,
    pub frame: u64,
}

/// Point-in-time read interface for hypergraph trees, used by the
/// snapshot manager. A `SnapshotReadable` reflects the state of the
/// hypergraph store at the moment it was captured: subsequent writes
/// to the live store are NOT visible through this interface.
///
/// Mirror of Go's `tries.DBSnapshot` (`hypergraph/snapshot_manager.go`)
/// at the level the sync server actually consumes — `load_tree_for_phase`
/// only ever calls `load_tree_blob`, so that's the only required
/// method. Additional read methods can be added as future sync code
/// paths require them; in the meantime callers must still go to the
/// live store for anything not covered here.
pub trait SnapshotReadable: Send + Sync {
    /// Read a metadata key at the same captured sequence as the tree data.
    /// Consumers of commit cursors must not substitute a live-store read.
    fn read_record(&self, _key: &[u8]) -> Result<Option<Vec<u8>>> {
        Err(QuilError::Store("snapshot metadata reads are unsupported by this backend".into()))
    }

    /// Page fixed domain/address vertex keys from this retained snapshot.
    /// Reusing the same handle across pages keeps concurrent commits invisible.
    /// Callers must bound handle lifetime/count because snapshots retain old DB data.
    fn page_vertex_underlying_fixed(
        &self, _set_type: &str, _phase_type: &str, _shard: &ShardKey,
        _domain: &[u8; 32], _after: Option<&[u8; 32]>, _limits: VertexPageLimits,
    ) -> Result<VertexDataPage> {
        Err(QuilError::Store("fixed vertex snapshot paging is unsupported by this backend".into()))
    }

    /// [`Self::page_vertex_underlying_fixed`], passing over the rows whose
    /// address `skip` names without copying, returning or counting them, so
    /// a large row the caller does not want cannot fail its pages.
    fn page_vertex_underlying_fixed_skipping(
        &self, _set_type: &str, _phase_type: &str, _shard: &ShardKey,
        _domain: &[u8; 32], _after: Option<&[u8; 32]>, _limits: VertexPageLimits,
        _skip: &dyn Fn(&[u8; 32]) -> bool,
    ) -> Result<VertexDataPage> {
        Err(QuilError::Store("fixed vertex snapshot paging is unsupported by this backend".into()))
    }

    /// Load the serialized tree blob for `(set_type, phase_type, shard_key)`
    /// as it existed when the snapshot was captured, or `None` if absent.
    fn load_tree_blob(
        &self,
        set_type: &str,
        phase_type: &str,
        shard_key: &ShardKey,
    ) -> Result<Option<Vec<u8>>>;

    /// Read one tree node by its by-path index, point-in-time consistent
    /// at the captured sequence. Mirrors
    /// [`HypergraphStore::get_node_by_path`] (SeekGE + prefix
    /// compression). Lets a consumer walk a whole tree over a single
    /// consistent snapshot (e.g. the prover shard) instead of issuing
    /// non-isolated live reads. Default `Ok(None)` for blob-only snapshot
    /// impls that don't support per-node reads.
    fn get_node_by_path(
        &self,
        _set_type: &str,
        _phase_type: &str,
        _shard_key: &ShardKey,
        _path: &[i32],
    ) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    /// Whether underlying vertex reads are supported at the captured sequence.
    /// Recovery must distinguish an unsupported reader (whose default returns
    /// `None`) from authenticated absence. Live-store adapters must leave this
    /// false because they do not pin a generation.
    fn has_snapshot_vertex_reads(&self) -> bool {
        false
    }

    /// The database state this snapshot's reads of the database's watched
    /// keys see, if it has one. Live-store adapters must leave this `None`.
    fn scan_point(&self) -> Option<ScanPoint> {
        None
    }

    /// Read one vertex's underlying data blob at the captured sequence.
    /// Mirrors [`HypergraphStore::load_vertex_underlying_raw`]. Default
    /// `Ok(None)`.
    fn load_vertex_underlying_raw(
        &self,
        _set_type: &str,
        _phase_type: &str,
        _shard_key: &ShardKey,
        _vertex_key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

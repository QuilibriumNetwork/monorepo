use crate::error::Result;
use crate::proto;
use num_bigint::BigInt;

// ---------------------------------------------------------------------------
// Core KV abstractions
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Domain-specific stores
// ---------------------------------------------------------------------------

/// Clock/frame storage.
pub trait ClockStore: Send + Sync {
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

/// Application shard metadata storage.
pub trait ShardsStore: Send + Sync {
    fn range_app_shards(&self) -> Result<Vec<ShardInfo>>;
    fn get_app_shards(&self, shard_key: &[u8], prefix: &[u32]) -> Result<Vec<ShardInfo>>;
    fn put_app_shard(&self, txn: &dyn Transaction, shard: &ShardInfo) -> Result<()>;
    fn delete_app_shard(
        &self,
        txn: &dyn Transaction,
        shard_key: &[u8],
        prefix: &[u32],
    ) -> Result<()>;
}

/// Hypergraph tree backing store (vector commitment trees).
pub trait HypergraphStore: Send + Sync {
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
}

// ---------------------------------------------------------------------------
// Supporting types used across store traits
// ---------------------------------------------------------------------------

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

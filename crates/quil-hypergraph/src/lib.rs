pub mod addressing;
pub mod crdt;
pub mod retention;
pub mod snapshot;

#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

pub use addressing::{shard_key_for_location, Location};
pub use crdt::{
    commit_lock_wait_on_this_thread, ExecutionCapture, ExecutionFork, ExecutionForkLimits,
    ExecutionMetadataUsage, ForestConfinement, ForestWriteGuard, HypergraphCrdt, LineageRecord,
    Mutation, PreparedCrdtAdoption, ShardMetadata,
};
pub use retention::{
    snapshot_pin_limit_from_env, spawn_retention_pruner, RetentionPacing, RetentionPass,
    RetentionPolicy, RetentionStep,
};
pub use snapshot::{
    GenerationHandle, SnapshotManager, MAX_GENERATIONS as SNAPSHOT_MAX_GENERATIONS,
};

/// Vertex ID is 64 bytes: [32 bytes app_address][32 bytes data_address].
pub const VERTEX_ID_LEN: usize = 64;

/// Discriminators for the four CRDT phase sets.
pub const VERTEX_ADDS: &str = "vertex";
pub const VERTEX_REMOVES: &str = "vertex";
pub const HYPEREDGE_ADDS: &str = "hyperedge";
pub const HYPEREDGE_REMOVES: &str = "hyperedge";

pub const PHASE_ADDS: &str = "adds";
pub const PHASE_REMOVES: &str = "removes";

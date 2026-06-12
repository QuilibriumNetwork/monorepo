pub mod crdt;
pub mod addressing;
pub mod snapshot;

#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

pub use crdt::{HypergraphCrdt, ShardMetadata};
pub use snapshot::{SnapshotManager, GenerationHandle, MAX_GENERATIONS as SNAPSHOT_MAX_GENERATIONS};
pub use addressing::{Location, shard_key_for_location};

/// Vertex ID is 64 bytes: [32 bytes app_address][32 bytes data_address].
pub const VERTEX_ID_LEN: usize = 64;

/// Discriminators for the four CRDT phase sets.
pub const VERTEX_ADDS: &str = "vertex";
pub const VERTEX_REMOVES: &str = "vertex";
pub const HYPEREDGE_ADDS: &str = "hyperedge";
pub const HYPEREDGE_REMOVES: &str = "hyperedge";

pub const PHASE_ADDS: &str = "adds";
pub const PHASE_REMOVES: &str = "removes";

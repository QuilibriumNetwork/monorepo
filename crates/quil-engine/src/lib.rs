pub mod app_engine;
pub mod app_glue;
pub mod app_shard_cache;
pub mod app_shard_metadata;
pub mod app_timeout_aggregation;
pub mod app_types;
pub mod app_vote_aggregation;
pub mod multi_proof_cache;
pub mod bls_signature_aggregator;
pub mod bls_verifier;
pub mod committee;
pub mod consensus_activation;
pub mod consensus_bootstrap;
pub mod consensus_glue;
pub mod consensus_metrics;
pub mod consensus_store;
pub mod consensus_types;
pub mod consensus_wire;
pub mod coverage;
pub mod current_frame;
pub mod shard_rebalancer;
pub mod difficulty;
pub mod engine_state;
pub mod event_distributor;
pub mod fees;
pub mod fork_choice;
pub mod frame_chain_checker;
pub mod frame_materializer;
pub mod frame_processor;
pub mod genesis;
pub mod frame_replay;
pub mod frame_validator;
pub mod halt_state;
pub mod message_collector;
pub mod message_router;
pub mod global_engine;
pub mod leader_provider;
pub mod metrics;
pub mod remote_worker;
pub mod rewards;
pub mod thread_worker;
pub mod time_reel;
pub mod timeout_aggregation;
pub mod prover_message_transport;
pub mod prover_pipeline;
pub mod provers;
pub mod shard_info;
pub mod worker_allocator;
pub mod worker_node;
pub mod validator;
pub mod vote_aggregation;
pub mod voting_provider;
pub mod worker;
pub mod prover_tree_syncer;

/// Test support mocks (TestProverRegistry, TestWorkerManager).
/// Exposed for integration tests in `tests/`; hidden from public
/// docs since these are not part of the production API.
#[doc(hidden)]
pub mod test_support;

pub use global_engine::GlobalConsensusEngine;
pub use app_engine::AppConsensusEngine;
pub use app_shard_cache::AppShardCache;
pub use difficulty::AsertDifficultyAdjuster;
pub use rewards::OptRewardIssuance;
pub use fees::InMemoryDynamicFeeManager;
pub use time_reel::GlobalTimeReel;

/// Consensus bitmask constants matching the Go implementation.
pub mod bitmasks {
    /// Global consensus coordination.
    pub const GLOBAL_CONSENSUS: &[u8] = &[0x00];
    /// Global frame distribution.
    pub const GLOBAL_FRAME: &[u8] = &[0x00, 0x00];
    /// Prover work delegation.
    pub const GLOBAL_PROVER: &[u8] = &[0x00, 0x00, 0x00];
    /// Peer info exchange.
    pub const GLOBAL_PEER_INFO: &[u8] = &[0x00, 0x00, 0x00, 0x00];
    /// Global alert channel (16 zero bytes).
    pub const GLOBAL_ALERT: &[u8] = &[0u8; 16];

    /// Compute the 32-byte `appFilter` from a shard address. Mirrors
    /// Go's `up2p.GetBloomFilter(address, 256, 3)` — a 256-bit
    /// bitmask with exactly 3 bits set, used as the per-shard
    /// pubsub topic identifier. The shard `address` is typically a
    /// 32-byte poseidon hash; only the first 32 bytes participate
    /// in the SHA3-256 the bloom function consumes.
    pub fn shard_app_filter(address: &[u8]) -> Vec<u8> {
        quil_hypergraph::addressing::get_bloom_filter(address, 256, 3)
    }

    /// Per-shard frame bitmask = the shard's `appFilter` (32 bytes
    /// with 3 bits set).
    pub fn shard_frame_bitmask(address: &[u8]) -> Vec<u8> {
        shard_app_filter(address)
    }

    /// Per-shard consensus bitmask = `0x00 || appFilter`.
    pub fn shard_consensus_bitmask(address: &[u8]) -> Vec<u8> {
        let af = shard_app_filter(address);
        let mut v = Vec::with_capacity(1 + af.len());
        v.push(0u8);
        v.extend_from_slice(&af);
        v
    }

    /// Per-shard prover bitmask = `0x00 0x00 0x00 || appFilter`.
    pub fn shard_prover_bitmask(address: &[u8]) -> Vec<u8> {
        let af = shard_app_filter(address);
        let mut v = Vec::with_capacity(3 + af.len());
        v.extend_from_slice(&[0u8, 0u8, 0u8]);
        v.extend_from_slice(&af);
        v
    }

    /// Per-shard dispatch bitmask = `0x00 0x00 || appFilter`.
    pub fn shard_dispatch_bitmask(address: &[u8]) -> Vec<u8> {
        let af = shard_app_filter(address);
        let mut v = Vec::with_capacity(2 + af.len());
        v.extend_from_slice(&[0u8, 0u8]);
        v.extend_from_slice(&af);
        v
    }
}

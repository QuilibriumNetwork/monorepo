pub mod app_engine;
pub mod app_glue;
pub mod archive_ingest;
pub mod app_shard_cache;
pub mod app_shard_metadata;
pub mod app_types;
pub mod multi_proof_cache;
pub mod committee;
pub mod consensus_metrics;
pub mod consensus_types;
/// Commonware-simplex consensus seams (P2b): real-state impls of the
/// quil-cw-consensus GlobalProposer/FrameSink/FrameFinalizer traits.
pub mod cw_app_seams;
pub mod cw_global_seams;
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
pub mod leader_provider;
pub mod metrics;
pub mod remote_worker;
pub mod rewards;
pub mod thread_worker;
pub mod time_reel;
pub mod prover_message_transport;
pub mod prover_pipeline;
pub mod provers;
pub mod shard_info;
pub mod worker_allocator;
pub mod worker_node;
pub mod worker;
pub mod prover_tree_syncer;

/// Test support mocks (TestProverRegistry, TestWorkerManager).
/// Exposed for integration tests in `tests/`; hidden from public
/// docs since these are not part of the production API.
#[doc(hidden)]
pub mod test_support;

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
    // Commonware-simplex consensus channels (P2 cutover). Distinct bitmasks so
    // the node demuxes an inbound `:8340` message back to the right simplex
    // channel. Only used when the simplex committee is configured.
    /// simplex vote channel (id 0).
    pub const GLOBAL_CW_VOTE: &[u8] = &[0x00, 0x10];
    /// simplex certificate channel (id 1).
    pub const GLOBAL_CW_CERT: &[u8] = &[0x00, 0x11];
    /// simplex resolver channel (id 2).
    pub const GLOBAL_CW_RESOLVER: &[u8] = &[0x00, 0x12];
    /// Out-of-band block (frame-bytes) delivery channel (id 3). Not a simplex
    /// engine channel — the node routes it into the shared `BlockStore`.
    pub const GLOBAL_CW_BLOCK: &[u8] = &[0x00, 0x13];

    /// Map a CW channel id (0/1/2/3) to its `:8340` bitmask.
    pub const fn global_cw_channel_bitmask(channel: u64) -> &'static [u8] {
        match channel {
            0 => GLOBAL_CW_VOTE,
            1 => GLOBAL_CW_CERT,
            2 => GLOBAL_CW_RESOLVER,
            _ => GLOBAL_CW_BLOCK,
        }
    }

    /// Inverse: map a `:8340` bitmask back to a CW channel id, if it is one.
    pub fn global_cw_channel_of(bitmask: &[u8]) -> Option<u64> {
        match bitmask {
            b if b == GLOBAL_CW_VOTE => Some(0),
            b if b == GLOBAL_CW_CERT => Some(1),
            b if b == GLOBAL_CW_RESOLVER => Some(2),
            b if b == GLOBAL_CW_BLOCK => Some(3),
            _ => None,
        }
    }
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

    /// Per-shard commonware-simplex bitmask = `0x01 || appFilter` (P3). ONE
    /// gossip topic per shard for all CW consensus traffic; the CW channel id
    /// (0=vote,1=cert,2=resolver,3=block) is carried as the FIRST payload byte
    /// (see `shard_cw_split_payload`). The `0x01` discriminator distinguishes it
    /// from every legacy shard bitmask (which start with `0x00` or are the raw
    /// 32-byte `appFilter`), so it can't collide.
    pub fn shard_cw_bitmask(address: &[u8]) -> Vec<u8> {
        let af = shard_app_filter(address);
        let mut v = Vec::with_capacity(1 + af.len());
        v.push(0x01u8);
        v.extend_from_slice(&af);
        v
    }

    /// Frame a CW message for gossip: `[channel_u8] || cw_bytes`.
    pub fn shard_cw_frame_payload(channel: u64, cw_bytes: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + cw_bytes.len());
        v.push(channel as u8);
        v.extend_from_slice(cw_bytes);
        v
    }

    /// Inverse of [`shard_cw_frame_payload`]: `(channel, cw_bytes)` or `None` if empty.
    pub fn shard_cw_split_payload(payload: &[u8]) -> Option<(u64, &[u8])> {
        payload.split_first().map(|(c, rest)| (*c as u64, rest))
    }
}

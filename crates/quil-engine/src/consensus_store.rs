//! KV-backed [`ConsensusStore`] adapter.
//!
//! The consensus store persists two pieces of state per filter
//! (shard / consensus instance):
//!
//! - [`ConsensusState`] — the safety-rules view (finalized rank,
//!   latest acknowledged rank, latest timeout).
//! - [`LivenessState`] — the pacemaker view (current rank, newest
//!   QC, prior-rank TC).
//!
//! Both structs carry trait-object QC / TC references, so they
//! cannot be serialized directly by a generic store. We split that
//! concern out into a [`ConsensusStateCodec`] trait that the
//! application layer implements for its concrete QC / TC types.
//! The store itself is a thin KV wrapper that just moves bytes.
//!
//! # Key layout
//!
//! Keys live under the workspace-wide CONSENSUS namespace
//! (`0x0C`) with sub-discriminators that match the Go store layout
//! (`node/store/consensus.go:40,118`):
//!
//! - `[0x0C, 0x00, filter]` — consensus state (safety-rules view)
//! - `[0x0C, 0x01, filter]` — liveness state (pacemaker view)
//!
//! Builder functions live in `quil_store::encoding` so the layout
//! definition has a single source of truth shared with the migrator.

use std::sync::Arc;

use quil_consensus::event_handler::ConsensusStore;
use quil_consensus::models::{ConsensusState, LivenessState, Unique};
use quil_store::encoding::{consensus_liveness_key, consensus_state_key};
use quil_types::error::{QuilError, Result};
use quil_types::store::KvDb;

/// Encode/decode callbacks for the opaque QC / TC references inside
/// [`ConsensusState`] / [`LivenessState`]. The codec is
/// application-specific because the consensus layer doesn't know the
/// concrete QC / TC types.
///
/// The codec is invoked atomically by [`KvConsensusStore`] — callers
/// don't need to worry about partial writes.
pub trait ConsensusStateCodec<V: Unique>: Send + Sync {
    /// Serialize a full [`ConsensusState<V>`] to bytes. Implementations
    /// typically use protobuf for wire compatibility with the Go side.
    fn encode_consensus_state(&self, state: &ConsensusState<V>) -> Result<Vec<u8>>;

    /// Deserialize bytes previously produced by
    /// [`encode_consensus_state`].
    fn decode_consensus_state(&self, bytes: &[u8]) -> Result<ConsensusState<V>>;

    /// Serialize a full [`LivenessState`] to bytes.
    fn encode_liveness_state(&self, state: &LivenessState) -> Result<Vec<u8>>;

    /// Deserialize bytes previously produced by
    /// [`encode_liveness_state`].
    fn decode_liveness_state(&self, bytes: &[u8]) -> Result<LivenessState>;
}

// Key builders live in `quil_store::encoding` — imported above as
// `consensus_state_key` / `consensus_liveness_key`.

/// KV-backed [`ConsensusStore`] implementation.
pub struct KvConsensusStore<V: Unique, C: ConsensusStateCodec<V>> {
    db: Arc<dyn KvDb>,
    codec: Arc<C>,
    /// Initial bootstrap consensus-state value returned by
    /// [`get_consensus_state`] when the key is missing. This is the
    /// "cold start" state a freshly-initialized replica sees: no
    /// acknowledged rank, no timeout, finalized rank 0.
    bootstrap_consensus: Arc<dyn Fn(&[u8]) -> ConsensusState<V> + Send + Sync>,
    /// Bootstrap liveness value. Must include the genesis QC —
    /// callers typically pass a closure that rebuilds it from the
    /// application's known-good root certificate.
    bootstrap_liveness: Arc<dyn Fn(&[u8]) -> LivenessState + Send + Sync>,
}

impl<V: Unique, C: ConsensusStateCodec<V>> KvConsensusStore<V, C> {
    pub fn new(
        db: Arc<dyn KvDb>,
        codec: Arc<C>,
        bootstrap_consensus: Arc<dyn Fn(&[u8]) -> ConsensusState<V> + Send + Sync>,
        bootstrap_liveness: Arc<dyn Fn(&[u8]) -> LivenessState + Send + Sync>,
    ) -> Self {
        Self {
            db,
            codec,
            bootstrap_consensus,
            bootstrap_liveness,
        }
    }
}

impl<V: Unique, C: ConsensusStateCodec<V>> ConsensusStore<V> for KvConsensusStore<V, C> {
    fn get_consensus_state(&self, filter: &[u8]) -> Result<ConsensusState<V>> {
        let key = consensus_state_key(filter);
        match self.db.get(&key)? {
            Some(bytes) => self.codec.decode_consensus_state(&bytes),
            None => Ok((self.bootstrap_consensus)(filter)),
        }
    }

    fn put_consensus_state(&self, state: &ConsensusState<V>) -> Result<()> {
        let key = consensus_state_key(&state.filter);
        let bytes = self.codec.encode_consensus_state(state)?;
        self.db.set(&key, &bytes)
    }

    fn get_liveness_state(&self, filter: &[u8]) -> Result<LivenessState> {
        let key = consensus_liveness_key(filter);
        match self.db.get(&key)? {
            Some(bytes) => self.codec.decode_liveness_state(&bytes),
            None => Ok((self.bootstrap_liveness)(filter)),
        }
    }

    fn put_liveness_state(&self, state: &LivenessState) -> Result<()> {
        let key = consensus_liveness_key(&state.filter);
        let bytes = self.codec.encode_liveness_state(state)?;
        self.db.set(&key, &bytes)
    }
}

// =====================================================================
// A trivial in-memory test codec for exercising the store without
// requiring protobuf wire compatibility with Go. Real consensus
// runs plug in an application-specific codec.
// =====================================================================

/// Simple length-prefixed binary codec for tests. Does NOT support
/// arbitrary QC / TC trait objects — encodes only the
/// `filter/finalized_rank/latest_acknowledged_rank/current_rank`
/// scalar fields and drops all trait-object references. Adequate for
/// round-trip tests of the store's KV plumbing.
#[doc(hidden)]
pub struct ScalarOnlyTestCodec<V: Unique, F> {
    /// Factory for a fresh genesis QC (needed to rehydrate
    /// `LivenessState::latest_quorum_certificate` on decode).
    pub qc_factory: F,
    _marker: std::marker::PhantomData<V>,
}

impl<V: Unique, F> ScalarOnlyTestCodec<V, F>
where
    F: Fn() -> Arc<dyn quil_consensus::models::QuorumCertificate> + Send + Sync,
{
    pub fn new(qc_factory: F) -> Self {
        Self {
            qc_factory,
            _marker: std::marker::PhantomData,
        }
    }

    fn write_u64(out: &mut Vec<u8>, v: u64) {
        out.extend_from_slice(&v.to_be_bytes());
    }
    fn read_u64(bytes: &[u8], offset: &mut usize) -> Result<u64> {
        if *offset + 8 > bytes.len() {
            return Err(QuilError::Serialization("short u64".into()));
        }
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[*offset..*offset + 8]);
        *offset += 8;
        Ok(u64::from_be_bytes(buf))
    }
    fn write_bytes(out: &mut Vec<u8>, b: &[u8]) {
        Self::write_u64(out, b.len() as u64);
        out.extend_from_slice(b);
    }
    fn read_bytes<'a>(bytes: &'a [u8], offset: &mut usize) -> Result<&'a [u8]> {
        let len = Self::read_u64(bytes, offset)? as usize;
        if *offset + len > bytes.len() {
            return Err(QuilError::Serialization("short byte blob".into()));
        }
        let slice = &bytes[*offset..*offset + len];
        *offset += len;
        Ok(slice)
    }
}

impl<V: Unique, F> ConsensusStateCodec<V> for ScalarOnlyTestCodec<V, F>
where
    F: Fn() -> Arc<dyn quil_consensus::models::QuorumCertificate> + Send + Sync,
{
    fn encode_consensus_state(&self, state: &ConsensusState<V>) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        Self::write_bytes(&mut out, &state.filter);
        Self::write_u64(&mut out, state.finalized_rank);
        Self::write_u64(&mut out, state.latest_acknowledged_rank);
        // latest_timeout is not encoded — round-trip drops it.
        Ok(out)
    }

    fn decode_consensus_state(&self, bytes: &[u8]) -> Result<ConsensusState<V>> {
        let mut offset = 0;
        let filter = Self::read_bytes(bytes, &mut offset)?.to_vec();
        let finalized_rank = Self::read_u64(bytes, &mut offset)?;
        let latest_acknowledged_rank = Self::read_u64(bytes, &mut offset)?;
        Ok(ConsensusState {
            filter,
            finalized_rank,
            latest_acknowledged_rank,
            latest_timeout: None,
        })
    }

    fn encode_liveness_state(&self, state: &LivenessState) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        Self::write_bytes(&mut out, &state.filter);
        Self::write_u64(&mut out, state.current_rank);
        Self::write_u64(&mut out, state.latest_quorum_certificate.rank());
        // We don't serialize the actual QC body — the decoder
        // rebuilds a fresh genesis QC via the factory.
        Ok(out)
    }

    fn decode_liveness_state(&self, bytes: &[u8]) -> Result<LivenessState> {
        let mut offset = 0;
        let filter = Self::read_bytes(bytes, &mut offset)?.to_vec();
        let current_rank = Self::read_u64(bytes, &mut offset)?;
        let _qc_rank = Self::read_u64(bytes, &mut offset)?;
        Ok(LivenessState {
            filter,
            current_rank,
            latest_quorum_certificate: (self.qc_factory)(),
            prior_rank_timeout_certificate: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_consensus::models::{
        AggregatedSignature, Identity, QuorumCertificate,
    };
    use quil_types::store::{Iterator as KvIterator, Transaction};
    use std::collections::HashMap;
    use std::sync::Mutex;

    // =================================================================
    // App types
    // =================================================================

    #[derive(Debug, Clone)]
    struct AppVote {
        id: Identity,
        rank: u64,
    }
    impl Unique for AppVote {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &[] }
    }

    // =================================================================
    // QC stub
    // =================================================================

    #[derive(Debug)]
    struct StubAgg;
    impl AggregatedSignature for StubAgg {
        fn signature(&self) -> &[u8] { &[] }
        fn public_key(&self) -> &[u8] { &[] }
        fn bitmask(&self) -> &[u8] { &[] }
    }

    #[derive(Debug)]
    struct GenesisQc;
    impl QuorumCertificate for GenesisQc {
        fn filter(&self) -> &[u8] { &[] }
        fn rank(&self) -> u64 { 0 }
        fn frame_number(&self) -> u64 { 0 }
        fn identity(&self) -> &Identity {
            use std::sync::OnceLock;
            static ID: OnceLock<Identity> = OnceLock::new();
            ID.get_or_init(|| "genesis".into())
        }
        fn timestamp(&self) -> u64 { 0 }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &StubAgg }
        fn equals(&self, o: &dyn QuorumCertificate) -> bool { o.rank() == 0 }
    }

    fn genesis_qc() -> Arc<dyn QuorumCertificate> {
        Arc::new(GenesisQc)
    }

    // =================================================================
    // In-memory KvDb stub (minimal methods needed by the store)
    // =================================================================

    struct MemKvDb {
        data: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
    }
    impl MemKvDb {
        fn new() -> Arc<dyn KvDb> {
            Arc::new(Self {
                data: Mutex::new(HashMap::new()),
            })
        }
    }
    impl KvDb for MemKvDb {
        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
            Ok(self.data.lock().unwrap().get(key).cloned())
        }
        fn set(&self, key: &[u8], value: &[u8]) -> Result<()> {
            self.data.lock().unwrap().insert(key.to_vec(), value.to_vec());
            Ok(())
        }
        fn delete(&self, key: &[u8]) -> Result<()> {
            self.data.lock().unwrap().remove(key);
            Ok(())
        }
        fn new_batch(&self, _indexed: bool) -> Result<Box<dyn Transaction>> {
            Err(QuilError::Internal("test stub — store never touches transactions".into()))
        }
        fn new_iter(&self, _lower: &[u8], _upper: &[u8]) -> Result<Box<dyn KvIterator>> {
            Err(QuilError::Internal("iterator not supported on in-memory store".into()))
        }
        fn compact(&self, _s: &[u8], _e: &[u8], _p: bool) -> Result<()> { Ok(()) }
        fn compact_all(&self) -> Result<()> { Ok(()) }
        fn close(&self) -> Result<()> { Ok(()) }
        fn delete_range(&self, _s: &[u8], _e: &[u8]) -> Result<()> { Ok(()) }
    }

    // =================================================================
    // Store builder
    // =================================================================

    fn build_store(
        db: Arc<dyn KvDb>,
    ) -> KvConsensusStore<AppVote, ScalarOnlyTestCodec<AppVote, impl Fn() -> Arc<dyn QuorumCertificate> + Send + Sync>>
    {
        let codec = Arc::new(ScalarOnlyTestCodec::<AppVote, _>::new(genesis_qc));
        let bootstrap_consensus = Arc::new(|filter: &[u8]| ConsensusState::<AppVote> {
            filter: filter.to_vec(),
            finalized_rank: 0,
            latest_acknowledged_rank: 0,
            latest_timeout: None,
        });
        let bootstrap_liveness = Arc::new(|filter: &[u8]| LivenessState {
            filter: filter.to_vec(),
            current_rank: 0,
            latest_quorum_certificate: genesis_qc(),
            prior_rank_timeout_certificate: None,
        });
        KvConsensusStore::new(db, codec, bootstrap_consensus, bootstrap_liveness)
    }

    // =================================================================
    // Tests
    // =================================================================

    #[test]
    fn get_missing_returns_bootstrap_consensus_state() {
        let db = MemKvDb::new();
        let store = build_store(db);
        let state = store.get_consensus_state(b"my-filter").unwrap();
        assert_eq!(state.filter, b"my-filter");
        assert_eq!(state.finalized_rank, 0);
        assert_eq!(state.latest_acknowledged_rank, 0);
        assert!(state.latest_timeout.is_none());
    }

    #[test]
    fn get_missing_returns_bootstrap_liveness_state() {
        let db = MemKvDb::new();
        let store = build_store(db);
        let state = store.get_liveness_state(b"my-filter").unwrap();
        assert_eq!(state.filter, b"my-filter");
        assert_eq!(state.current_rank, 0);
        assert_eq!(state.latest_quorum_certificate.rank(), 0);
    }

    #[test]
    fn put_then_get_consensus_state_round_trips_scalars() {
        let db = MemKvDb::new();
        let store = build_store(db);
        let state = ConsensusState::<AppVote> {
            filter: b"filter-x".to_vec(),
            finalized_rank: 7,
            latest_acknowledged_rank: 10,
            latest_timeout: None,
        };
        store.put_consensus_state(&state).unwrap();
        let got = store.get_consensus_state(b"filter-x").unwrap();
        assert_eq!(got.filter, b"filter-x");
        assert_eq!(got.finalized_rank, 7);
        assert_eq!(got.latest_acknowledged_rank, 10);
    }

    #[test]
    fn put_then_get_liveness_state_round_trips_scalars() {
        let db = MemKvDb::new();
        let store = build_store(db);
        let state = LivenessState {
            filter: b"filter-y".to_vec(),
            current_rank: 42,
            latest_quorum_certificate: genesis_qc(),
            prior_rank_timeout_certificate: None,
        };
        store.put_liveness_state(&state).unwrap();
        let got = store.get_liveness_state(b"filter-y").unwrap();
        assert_eq!(got.filter, b"filter-y");
        assert_eq!(got.current_rank, 42);
    }

    #[test]
    fn consensus_and_liveness_use_different_key_prefixes() {
        let db = MemKvDb::new();
        let store = build_store(db);
        // Same filter bytes, different entries — writes to one must
        // not overwrite the other.
        store
            .put_consensus_state(&ConsensusState::<AppVote> {
                filter: b"shared".to_vec(),
                finalized_rank: 1,
                latest_acknowledged_rank: 2,
                latest_timeout: None,
            })
            .unwrap();
        store
            .put_liveness_state(&LivenessState {
                filter: b"shared".to_vec(),
                current_rank: 99,
                latest_quorum_certificate: genesis_qc(),
                prior_rank_timeout_certificate: None,
            })
            .unwrap();

        let cs = store.get_consensus_state(b"shared").unwrap();
        let ls = store.get_liveness_state(b"shared").unwrap();
        assert_eq!(cs.finalized_rank, 1);
        assert_eq!(ls.current_rank, 99);
    }

    #[test]
    fn different_filters_are_isolated() {
        let db = MemKvDb::new();
        let store = build_store(db);
        store
            .put_consensus_state(&ConsensusState::<AppVote> {
                filter: b"shard-a".to_vec(),
                finalized_rank: 5,
                latest_acknowledged_rank: 5,
                latest_timeout: None,
            })
            .unwrap();
        store
            .put_consensus_state(&ConsensusState::<AppVote> {
                filter: b"shard-b".to_vec(),
                finalized_rank: 100,
                latest_acknowledged_rank: 100,
                latest_timeout: None,
            })
            .unwrap();
        let a = store.get_consensus_state(b"shard-a").unwrap();
        let b = store.get_consensus_state(b"shard-b").unwrap();
        assert_eq!(a.finalized_rank, 5);
        assert_eq!(b.finalized_rank, 100);
    }

    #[test]
    fn put_then_overwrite_replaces_previous_value() {
        let db = MemKvDb::new();
        let store = build_store(db);
        store
            .put_consensus_state(&ConsensusState::<AppVote> {
                filter: b"f".to_vec(),
                finalized_rank: 1,
                latest_acknowledged_rank: 1,
                latest_timeout: None,
            })
            .unwrap();
        store
            .put_consensus_state(&ConsensusState::<AppVote> {
                filter: b"f".to_vec(),
                finalized_rank: 10,
                latest_acknowledged_rank: 12,
                latest_timeout: None,
            })
            .unwrap();
        let got = store.get_consensus_state(b"f").unwrap();
        assert_eq!(got.finalized_rank, 10);
        assert_eq!(got.latest_acknowledged_rank, 12);
    }

    #[test]
    fn corrupted_bytes_yield_serialization_error() {
        let db = MemKvDb::new();
        // Stuff garbage directly into the consensus-state key.
        let key = consensus_state_key(b"broken");
        db.set(&key, b"\x00\x01").unwrap();
        let store = build_store(db);
        let err = store.get_consensus_state(b"broken").unwrap_err();
        assert!(matches!(err, QuilError::Serialization(_)));
    }
}

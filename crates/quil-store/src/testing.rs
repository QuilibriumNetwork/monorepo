//! In-memory implementations of the persistent store traits, for
//! integration tests that need real storage semantics without
//! depending on RocksDB.
//!
//! Currently exposes [`InMemoryClockStore`]; companions for
//! [`TokenStore`], [`KeyStore`], etc. can be added as tests require.
//!
//! Hidden from the public docs since this is test-only surface.

#![doc(hidden)]

use std::collections::HashMap;
use std::sync::Mutex;

use num_bigint::BigInt;

use quil_types::error::{QuilError, Result};
use quil_types::proto::global as gpb;
use quil_types::store::{ClockStore, Iterator as StoreIterator, Transaction};

/// Trivial in-memory `Transaction`. Mutations apply directly to the
/// store (no actual two-phase commit) since tests don't need atomicity
/// across multi-statement writes.
pub struct InMemoryTxn;

impl Transaction for InMemoryTxn {
    fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn set(&self, _key: &[u8], _value: &[u8]) -> Result<()> {
        Ok(())
    }
    fn commit(self: Box<Self>) -> Result<()> {
        Ok(())
    }
    fn delete(&self, _key: &[u8]) -> Result<()> {
        Ok(())
    }
    fn abort(self: Box<Self>) -> Result<()> {
        Ok(())
    }
    fn new_iter(&self, _start: &[u8], _end: &[u8]) -> Result<Box<dyn StoreIterator>> {
        Err(QuilError::NotFound("in-memory txn iteration unsupported".into()))
    }
    fn delete_range(&self, _start: &[u8], _end: &[u8]) -> Result<()> {
        Ok(())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Full in-memory `ClockStore`. Backs every persistent operation
/// with `HashMap`s keyed by the appropriate identifiers. Sufficient
/// for happy-path consensus integration tests; not optimized for
/// throughput.
///
/// Lookup-by-latest is computed via `keys().max()` rather than
/// maintaining a separate index — fine for tests where frame counts
/// stay small (~hundreds).
#[derive(Default)]
pub struct InMemoryClockStore {
    // Global frames
    global_frames: Mutex<HashMap<u64, gpb::GlobalFrame>>,
    /// Frame candidates indexed by `(frame_number, selector)`.
    global_frame_candidates: Mutex<HashMap<(u64, Vec<u8>), gpb::GlobalFrame>>,
    /// Certified states indexed by rank.
    certified_states: Mutex<HashMap<u64, gpb::GlobalProposal>>,

    // QCs / TCs — keyed by (filter, rank).
    qcs: Mutex<HashMap<(Vec<u8>, u64), gpb::QuorumCertificate>>,
    latest_qc: Mutex<HashMap<Vec<u8>, gpb::QuorumCertificate>>,
    tcs: Mutex<HashMap<(Vec<u8>, u64), gpb::TimeoutCertificate>>,
    latest_tc: Mutex<HashMap<Vec<u8>, gpb::TimeoutCertificate>>,

    // Shard frames — keyed by (filter, frame_number).
    shard_frames: Mutex<HashMap<(Vec<u8>, u64), gpb::AppShardFrame>>,
    latest_shard_frame_number: Mutex<HashMap<Vec<u8>, u64>>,
    /// Staged shard frames indexed by `(filter, frame_number, parent_selector)`.
    staged_shard_frames: Mutex<HashMap<(Vec<u8>, u64, Vec<u8>), gpb::AppShardFrame>>,

    // App-shard certified state — keyed by filter.
    app_shard_certified: Mutex<HashMap<Vec<u8>, gpb::AppShardProposal>>,

    // Votes — keyed by (filter, rank, identity).
    proposal_votes: Mutex<HashMap<(Vec<u8>, u64, Vec<u8>), gpb::ProposalVote>>,
    timeout_votes: Mutex<HashMap<(Vec<u8>, u64, Vec<u8>), gpb::TimeoutState>>,

    // Distance / seniority.
    total_distance: Mutex<HashMap<(Vec<u8>, u64, Vec<u8>), BigInt>>,
    seniority_maps: Mutex<HashMap<Vec<u8>, HashMap<String, u64>>>,
}

impl InMemoryClockStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a `GlobalFrame` directly. Useful for genesis bootstrapping
    /// where the genesis frame must already be present before
    /// `activate_consensus` runs `get_latest_global_clock_frame()`.
    pub fn seed_frame(&self, frame: gpb::GlobalFrame) {
        if let Some(h) = frame.header.as_ref() {
            self.global_frames
                .lock()
                .unwrap()
                .insert(h.frame_number, frame);
        }
    }
}

impl ClockStore for InMemoryClockStore {
    fn new_transaction(&self, _indexed: bool) -> Result<Box<dyn Transaction>> {
        Ok(Box::new(InMemoryTxn))
    }

    // -----------------------------------------------------------------
    // Global frames
    // -----------------------------------------------------------------

    fn get_latest_global_clock_frame(&self) -> Result<gpb::GlobalFrame> {
        let frames = self.global_frames.lock().unwrap();
        let highest = frames
            .keys()
            .copied()
            .max()
            .ok_or_else(|| QuilError::NotFound("no frames stored".into()))?;
        Ok(frames[&highest].clone())
    }

    fn get_earliest_global_clock_frame(&self) -> Result<gpb::GlobalFrame> {
        let frames = self.global_frames.lock().unwrap();
        let lowest = frames
            .keys()
            .copied()
            .min()
            .ok_or_else(|| QuilError::NotFound("no frames stored".into()))?;
        Ok(frames[&lowest].clone())
    }

    fn get_global_clock_frame(&self, frame_number: u64) -> Result<gpb::GlobalFrame> {
        self.global_frames
            .lock()
            .unwrap()
            .get(&frame_number)
            .cloned()
            .ok_or_else(|| QuilError::NotFound(format!("frame {frame_number}")))
    }

    fn put_global_clock_frame(
        &self,
        frame: &gpb::GlobalFrame,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        if let Some(h) = frame.header.as_ref() {
            self.global_frames
                .lock()
                .unwrap()
                .insert(h.frame_number, frame.clone());
        }
        Ok(())
    }

    fn put_global_clock_frame_candidate(
        &self,
        frame: &gpb::GlobalFrame,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        if let Some(h) = frame.header.as_ref() {
            // Key by state identity = Poseidon(output), matching the
            // `get_global_clock_frame_candidate` selector convention.
            // Raw `output` bytes would not match the lookup since the
            // leader_provider passes `qc.identity()` (a Poseidon hash)
            // as the selector argument.
            let selector = quil_crypto::poseidon::hash_bytes_to_32(&h.output)
                .map(|h| h.to_vec())
                .unwrap_or_default();
            self.global_frame_candidates
                .lock()
                .unwrap()
                .insert((h.frame_number, selector), frame.clone());
        }
        Ok(())
    }

    fn get_global_clock_frame_candidate(
        &self,
        frame_number: u64,
        selector: &[u8],
    ) -> Result<gpb::GlobalFrame> {
        self.global_frame_candidates
            .lock()
            .unwrap()
            .get(&(frame_number, selector.to_vec()))
            .cloned()
            .ok_or_else(|| QuilError::NotFound("no candidate".into()))
    }

    fn delete_global_clock_frame_range(&self, min_frame: u64, max_frame: u64) -> Result<()> {
        self.global_frames
            .lock()
            .unwrap()
            .retain(|&k, _| k < min_frame || k > max_frame);
        Ok(())
    }

    fn reset_global_clock_frames(&self) -> Result<()> {
        self.global_frames.lock().unwrap().clear();
        Ok(())
    }

    // -----------------------------------------------------------------
    // Certified global states
    // -----------------------------------------------------------------

    fn get_latest_certified_global_state(&self) -> Result<gpb::GlobalProposal> {
        let m = self.certified_states.lock().unwrap();
        let k = m
            .keys()
            .copied()
            .max()
            .ok_or_else(|| QuilError::NotFound("no certified state".into()))?;
        Ok(m[&k].clone())
    }

    fn get_earliest_certified_global_state(&self) -> Result<gpb::GlobalProposal> {
        let m = self.certified_states.lock().unwrap();
        let k = m
            .keys()
            .copied()
            .min()
            .ok_or_else(|| QuilError::NotFound("no certified state".into()))?;
        Ok(m[&k].clone())
    }

    fn get_certified_global_state(&self, rank: u64) -> Result<gpb::GlobalProposal> {
        self.certified_states
            .lock()
            .unwrap()
            .get(&rank)
            .cloned()
            .ok_or_else(|| QuilError::NotFound(format!("certified state rank {rank}")))
    }

    fn put_certified_global_state(
        &self,
        state: &gpb::GlobalProposal,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        // Key by the rank from the proposal's vote field (always populated
        // by the leader at proposal time).
        let rank = state.vote.as_ref().map(|v| v.rank).unwrap_or(0);
        self.certified_states
            .lock()
            .unwrap()
            .insert(rank, state.clone());
        Ok(())
    }

    // -----------------------------------------------------------------
    // Quorum certificates
    // -----------------------------------------------------------------

    fn get_latest_quorum_certificate(&self, filter: &[u8]) -> Result<gpb::QuorumCertificate> {
        self.latest_qc
            .lock()
            .unwrap()
            .get(filter)
            .cloned()
            .ok_or_else(|| QuilError::NotFound("no QC".into()))
    }

    fn get_quorum_certificate(
        &self,
        filter: &[u8],
        rank: u64,
    ) -> Result<gpb::QuorumCertificate> {
        self.qcs
            .lock()
            .unwrap()
            .get(&(filter.to_vec(), rank))
            .cloned()
            .ok_or_else(|| QuilError::NotFound("no QC".into()))
    }

    fn put_quorum_certificate(
        &self,
        qc: &gpb::QuorumCertificate,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        let filter = qc.filter.clone();
        let rank = qc.rank;
        self.qcs
            .lock()
            .unwrap()
            .insert((filter.clone(), rank), qc.clone());
        let mut latest = self.latest_qc.lock().unwrap();
        let cur = latest.get(&filter).map(|q| q.rank).unwrap_or(0);
        if rank >= cur {
            latest.insert(filter, qc.clone());
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Timeout certificates
    // -----------------------------------------------------------------

    fn get_latest_timeout_certificate(
        &self,
        filter: &[u8],
    ) -> Result<gpb::TimeoutCertificate> {
        self.latest_tc
            .lock()
            .unwrap()
            .get(filter)
            .cloned()
            .ok_or_else(|| QuilError::NotFound("no TC".into()))
    }

    fn get_timeout_certificate(
        &self,
        filter: &[u8],
        rank: u64,
    ) -> Result<gpb::TimeoutCertificate> {
        self.tcs
            .lock()
            .unwrap()
            .get(&(filter.to_vec(), rank))
            .cloned()
            .ok_or_else(|| QuilError::NotFound("no TC".into()))
    }

    fn put_timeout_certificate(
        &self,
        tc: &gpb::TimeoutCertificate,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        let filter = tc.filter.clone();
        let rank = tc.rank;
        self.tcs
            .lock()
            .unwrap()
            .insert((filter.clone(), rank), tc.clone());
        let mut latest = self.latest_tc.lock().unwrap();
        let cur = latest.get(&filter).map(|t| t.rank).unwrap_or(0);
        if rank >= cur {
            latest.insert(filter, tc.clone());
        }
        Ok(())
    }

    // -----------------------------------------------------------------
    // Shard frames
    // -----------------------------------------------------------------

    fn get_latest_shard_clock_frame(&self, filter: &[u8]) -> Result<gpb::AppShardFrame> {
        let latest_n = self
            .latest_shard_frame_number
            .lock()
            .unwrap()
            .get(filter)
            .copied();
        let frame_number = latest_n.ok_or_else(|| QuilError::NotFound("no shard frame".into()))?;
        self.shard_frames
            .lock()
            .unwrap()
            .get(&(filter.to_vec(), frame_number))
            .cloned()
            .ok_or_else(|| QuilError::NotFound("no shard frame".into()))
    }

    fn get_shard_clock_frame(
        &self,
        filter: &[u8],
        frame_number: u64,
        _truncate: bool,
    ) -> Result<gpb::AppShardFrame> {
        self.shard_frames
            .lock()
            .unwrap()
            .get(&(filter.to_vec(), frame_number))
            .cloned()
            .ok_or_else(|| QuilError::NotFound("no shard frame".into()))
    }

    fn commit_shard_clock_frame(
        &self,
        filter: &[u8],
        frame_number: u64,
        selector: &[u8],
        _txn: &dyn Transaction,
        _backfill: bool,
    ) -> Result<()> {
        // Move from staged → committed.
        let key = (filter.to_vec(), frame_number, selector.to_vec());
        let frame = self
            .staged_shard_frames
            .lock()
            .unwrap()
            .remove(&key)
            .ok_or_else(|| QuilError::NotFound("no staged shard frame".into()))?;
        self.shard_frames
            .lock()
            .unwrap()
            .insert((filter.to_vec(), frame_number), frame);
        let mut latest = self.latest_shard_frame_number.lock().unwrap();
        let cur = latest.get(filter).copied().unwrap_or(0);
        if frame_number >= cur {
            latest.insert(filter.to_vec(), frame_number);
        }
        Ok(())
    }

    fn stage_shard_clock_frame(
        &self,
        selector: &[u8],
        frame: &gpb::AppShardFrame,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        let header = frame
            .header
            .as_ref()
            .ok_or_else(|| QuilError::InvalidArgument("shard frame has no header".into()))?;
        let filter = header.address.clone();
        let frame_number = header.frame_number;
        let key = (filter, frame_number, selector.to_vec());
        self.staged_shard_frames
            .lock()
            .unwrap()
            .insert(key, frame.clone());
        Ok(())
    }

    fn get_staged_shard_clock_frame(
        &self,
        filter: &[u8],
        frame_number: u64,
        parent_selector: &[u8],
        _truncate: bool,
    ) -> Result<gpb::AppShardFrame> {
        self.staged_shard_frames
            .lock()
            .unwrap()
            .get(&(filter.to_vec(), frame_number, parent_selector.to_vec()))
            .cloned()
            .ok_or_else(|| QuilError::NotFound("no staged shard frame".into()))
    }

    fn set_latest_shard_clock_frame_number(
        &self,
        filter: &[u8],
        frame_number: u64,
    ) -> Result<()> {
        self.latest_shard_frame_number
            .lock()
            .unwrap()
            .insert(filter.to_vec(), frame_number);
        Ok(())
    }

    fn delete_shard_clock_frame_range(
        &self,
        filter: &[u8],
        min_frame: u64,
        max_frame: u64,
    ) -> Result<()> {
        self.shard_frames
            .lock()
            .unwrap()
            .retain(|(f, n), _| f != filter || *n < min_frame || *n > max_frame);
        Ok(())
    }

    fn reset_shard_clock_frames(&self, filter: &[u8]) -> Result<()> {
        self.shard_frames
            .lock()
            .unwrap()
            .retain(|(f, _), _| f != filter);
        self.latest_shard_frame_number
            .lock()
            .unwrap()
            .remove(filter);
        Ok(())
    }

    // -----------------------------------------------------------------
    // App-shard certified states
    // -----------------------------------------------------------------

    fn get_latest_certified_app_shard_state(
        &self,
        filter: &[u8],
    ) -> Result<gpb::AppShardProposal> {
        self.app_shard_certified
            .lock()
            .unwrap()
            .get(filter)
            .cloned()
            .ok_or_else(|| QuilError::NotFound("no certified app shard".into()))
    }

    fn put_certified_app_shard_state(
        &self,
        state: &gpb::AppShardProposal,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        // Key by the filter from the vote field.
        let filter = state
            .vote
            .as_ref()
            .map(|v| v.filter.clone())
            .unwrap_or_default();
        self.app_shard_certified
            .lock()
            .unwrap()
            .insert(filter, state.clone());
        Ok(())
    }

    // -----------------------------------------------------------------
    // Votes
    // -----------------------------------------------------------------

    fn put_proposal_vote(
        &self,
        _txn: &dyn Transaction,
        vote: &gpb::ProposalVote,
    ) -> Result<()> {
        let identity = vote
            .public_key_signature_bls48581
            .as_ref()
            .map(|s| s.address.clone())
            .unwrap_or_default();
        let key = (vote.filter.clone(), vote.rank, identity);
        self.proposal_votes
            .lock()
            .unwrap()
            .insert(key, vote.clone());
        Ok(())
    }

    fn get_proposal_vote(
        &self,
        filter: &[u8],
        rank: u64,
        identity: &[u8],
    ) -> Result<gpb::ProposalVote> {
        self.proposal_votes
            .lock()
            .unwrap()
            .get(&(filter.to_vec(), rank, identity.to_vec()))
            .cloned()
            .ok_or_else(|| QuilError::NotFound("no proposal vote".into()))
    }

    fn get_proposal_votes(
        &self,
        filter: &[u8],
        rank: u64,
    ) -> Result<Vec<gpb::ProposalVote>> {
        Ok(self
            .proposal_votes
            .lock()
            .unwrap()
            .iter()
            .filter(|((f, r, _), _)| f == filter && *r == rank)
            .map(|(_, v)| v.clone())
            .collect())
    }

    fn put_timeout_vote(
        &self,
        _txn: &dyn Transaction,
        vote: &gpb::TimeoutState,
    ) -> Result<()> {
        let v = vote
            .vote
            .as_ref()
            .ok_or_else(|| QuilError::InvalidArgument("timeout state has no vote".into()))?;
        let identity = v
            .public_key_signature_bls48581
            .as_ref()
            .map(|s| s.address.clone())
            .unwrap_or_default();
        let key = (v.filter.clone(), v.rank, identity);
        self.timeout_votes
            .lock()
            .unwrap()
            .insert(key, vote.clone());
        Ok(())
    }

    fn get_timeout_vote(
        &self,
        filter: &[u8],
        rank: u64,
        identity: &[u8],
    ) -> Result<gpb::TimeoutState> {
        self.timeout_votes
            .lock()
            .unwrap()
            .get(&(filter.to_vec(), rank, identity.to_vec()))
            .cloned()
            .ok_or_else(|| QuilError::NotFound("no timeout vote".into()))
    }

    fn get_timeout_votes(
        &self,
        filter: &[u8],
        rank: u64,
    ) -> Result<Vec<gpb::TimeoutState>> {
        Ok(self
            .timeout_votes
            .lock()
            .unwrap()
            .iter()
            .filter(|((f, r, _), _)| f == filter && *r == rank)
            .map(|(_, v)| v.clone())
            .collect())
    }

    // -----------------------------------------------------------------
    // Distance / seniority
    // -----------------------------------------------------------------

    fn get_total_distance(
        &self,
        filter: &[u8],
        frame_number: u64,
        selector: &[u8],
    ) -> Result<BigInt> {
        self.total_distance
            .lock()
            .unwrap()
            .get(&(filter.to_vec(), frame_number, selector.to_vec()))
            .cloned()
            .ok_or_else(|| QuilError::NotFound("no total distance".into()))
    }

    fn set_total_distance(
        &self,
        filter: &[u8],
        frame_number: u64,
        selector: &[u8],
        total_distance: &BigInt,
    ) -> Result<()> {
        self.total_distance.lock().unwrap().insert(
            (filter.to_vec(), frame_number, selector.to_vec()),
            total_distance.clone(),
        );
        Ok(())
    }

    fn get_peer_seniority_map(&self, filter: &[u8]) -> Result<HashMap<String, u64>> {
        Ok(self
            .seniority_maps
            .lock()
            .unwrap()
            .get(filter)
            .cloned()
            .unwrap_or_default())
    }

    fn put_peer_seniority_map(
        &self,
        _txn: &dyn Transaction,
        filter: &[u8],
        seniority_map: &HashMap<String, u64>,
    ) -> Result<()> {
        self.seniority_maps
            .lock()
            .unwrap()
            .insert(filter.to_vec(), seniority_map.clone());
        Ok(())
    }

    fn compact_data(&self, _data_filter: &[u8]) -> Result<()> {
        // No-op for in-memory store.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::proto::global::GlobalFrameHeader;

    fn frame(n: u64) -> gpb::GlobalFrame {
        gpb::GlobalFrame {
            header: Some(GlobalFrameHeader {
                frame_number: n,
                ..Default::default()
            }),
            requests: vec![],
        }
    }

    #[test]
    fn put_and_get_global_frame() {
        let store = InMemoryClockStore::new();
        let txn = store.new_transaction(false).unwrap();
        store.put_global_clock_frame(&frame(42), txn.as_ref()).unwrap();
        let got = store.get_global_clock_frame(42).unwrap();
        assert_eq!(got.header.unwrap().frame_number, 42);
    }

    #[test]
    fn latest_returns_highest_frame_number() {
        let store = InMemoryClockStore::new();
        let txn = store.new_transaction(false).unwrap();
        store.put_global_clock_frame(&frame(10), txn.as_ref()).unwrap();
        store.put_global_clock_frame(&frame(50), txn.as_ref()).unwrap();
        store.put_global_clock_frame(&frame(30), txn.as_ref()).unwrap();
        let latest = store.get_latest_global_clock_frame().unwrap();
        assert_eq!(latest.header.unwrap().frame_number, 50);
    }

    #[test]
    fn seed_frame_makes_genesis_visible() {
        let store = InMemoryClockStore::new();
        store.seed_frame(frame(0));
        let g = store.get_global_clock_frame(0).unwrap();
        assert_eq!(g.header.unwrap().frame_number, 0);
    }

    #[test]
    fn qc_latest_tracks_max_rank() {
        let store = InMemoryClockStore::new();
        let txn = store.new_transaction(false).unwrap();
        let qc_low = gpb::QuorumCertificate {
            filter: vec![1, 2, 3],
            rank: 5,
            frame_number: 1,
            selector: vec![],
            timestamp: 0,
            aggregate_signature: None,
        };
        let qc_high = gpb::QuorumCertificate {
            filter: vec![1, 2, 3],
            rank: 10,
            frame_number: 2,
            selector: vec![],
            timestamp: 0,
            aggregate_signature: None,
        };
        store.put_quorum_certificate(&qc_low, txn.as_ref()).unwrap();
        store.put_quorum_certificate(&qc_high, txn.as_ref()).unwrap();
        let latest = store.get_latest_quorum_certificate(&[1, 2, 3]).unwrap();
        assert_eq!(latest.rank, 10);
    }

    #[test]
    fn seniority_map_round_trips() {
        let store = InMemoryClockStore::new();
        let txn = store.new_transaction(false).unwrap();
        let mut map: HashMap<String, u64> = HashMap::new();
        map.insert("peer-a".into(), 100);
        map.insert("peer-b".into(), 250);
        store
            .put_peer_seniority_map(txn.as_ref(), &[0xAA], &map)
            .unwrap();
        let got = store.get_peer_seniority_map(&[0xAA]).unwrap();
        assert_eq!(got.get("peer-a"), Some(&100));
        assert_eq!(got.get("peer-b"), Some(&250));
    }
}

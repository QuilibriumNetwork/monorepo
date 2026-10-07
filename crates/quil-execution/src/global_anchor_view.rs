//! Read-only, height-bounded GLOBAL frames from another database.
//!
//! A thread worker's engines read GLOBAL frames from the master's clock store,
//! which a private execution branch over the worker's own database cannot
//! capture. Private application execution reads the GLOBAL frames its input
//! is anchored to through this view instead: canonical GLOBAL frames at or
//! below the anchor are immutable, so the reads are stable, and every write,
//! candidate, certificate or shard-chain access is refused. The caller must
//! authenticate the anchor height; this view only bounds it.

use std::collections::HashMap;
use std::sync::Arc;

use num_bigint::BigInt;
use quil_types::error::{QuilError, Result};
use quil_types::proto;
use quil_types::store::{ClockStore, Transaction};

pub struct GlobalAnchorView {
    inner: Arc<dyn ClockStore>,
    max_frame: u64,
}

impl GlobalAnchorView {
    pub fn new(inner: Arc<dyn ClockStore>, max_frame: u64) -> Self {
        Self { inner, max_frame }
    }

    pub fn max_frame(&self) -> u64 {
        self.max_frame
    }
}

fn refused<T>(what: &str) -> Result<T> {
    Err(QuilError::ExecutionUnavailable(format!(
        "GLOBAL anchor view is read-only and bounded: {what}"
    )))
}

impl ClockStore for GlobalAnchorView {
    // No identity: this view must never stand in for a store in publication or
    // provider-identity checks.
    fn new_transaction(&self, _indexed: bool) -> Result<Box<dyn Transaction>> {
        refused("transaction")
    }

    fn get_latest_global_clock_frame(&self) -> Result<proto::global::GlobalFrame> {
        self.inner.get_global_clock_frame(self.max_frame)
    }
    fn app_frame_history_discarded(&self) -> Result<Option<u64>> {
        self.inner.app_frame_history_discarded()
    }
    fn get_earliest_global_clock_frame(&self) -> Result<proto::global::GlobalFrame> {
        let frame = self.inner.get_earliest_global_clock_frame()?;
        if frame.header.as_ref().is_some_and(|h| h.frame_number > self.max_frame) {
            return Err(QuilError::NotFound("no GLOBAL frame at or below the anchor".into()));
        }
        Ok(frame)
    }
    fn get_global_clock_frame(&self, frame_number: u64) -> Result<proto::global::GlobalFrame> {
        if frame_number > self.max_frame {
            return Err(QuilError::NotFound(format!(
                "GLOBAL frame {frame_number} is above the anchor {}",
                self.max_frame
            )));
        }
        self.inner.get_global_clock_frame(frame_number)
    }
    fn get_global_clock_frame_outcomes(
        &self,
        frame_number: u64,
    ) -> Result<Vec<quil_types::store::RequestOutcome>> {
        if frame_number > self.max_frame {
            return Err(QuilError::NotFound("GLOBAL outcomes above the anchor".into()));
        }
        self.inner.get_global_clock_frame_outcomes(frame_number)
    }
    fn put_global_clock_frame(
        &self,
        _frame: &proto::global::GlobalFrame,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        refused("GLOBAL frame write")
    }
    fn put_global_clock_frame_candidate(
        &self,
        _frame: &proto::global::GlobalFrame,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        refused("candidate write")
    }
    fn get_global_clock_frame_candidate(
        &self,
        _frame_number: u64,
        _selector: &[u8],
    ) -> Result<proto::global::GlobalFrame> {
        refused("candidate read")
    }
    fn range_global_clock_frame_candidates(
        &self,
        _min: u64,
        _max: u64,
        _limit: usize,
    ) -> Result<Vec<proto::global::GlobalFrame>> {
        refused("candidate scan")
    }
    fn put_global_clock_frame_outcomes(
        &self,
        _frame_number: u64,
        _outcomes: &[quil_types::store::RequestOutcome],
    ) -> Result<()> {
        refused("outcome write")
    }
    fn put_shard_frame_fee_total(&self, _filter: &[u8], _frame_number: u64, _fee_total: u128) -> Result<()> {
        refused("shard fee write")
    }
    fn get_shard_frame_fee_total(&self, _filter: &[u8], _frame_number: u64) -> Result<Option<u128>> {
        refused("shard fee read")
    }
    fn put_shard_frame_settlements(&self, _filter: &[u8], _frame_number: u64, _entries: &[u8]) -> Result<()> {
        refused("shard settlement write")
    }
    fn get_shard_frame_settlements(&self, _filter: &[u8], _frame_number: u64) -> Result<Option<Vec<u8>>> {
        refused("shard settlement read")
    }
    fn put_shard_frame_accumulator(&self, _filter: &[u8], _frame_number: u64, _digest: &[u8], _report: &[u8]) -> Result<()> {
        refused("shard accumulator write")
    }
    fn get_shard_frame_accumulator(&self, _filter: &[u8], _frame_number: u64) -> Result<Option<Vec<u8>>> {
        refused("shard accumulator read")
    }
    fn put_shard_frame_spends(&self, _filter: &[u8], _frame_number: u64, _entries: &[u8]) -> Result<()> {
        refused("shard spend write")
    }
    fn get_shard_frame_spends(&self, _filter: &[u8], _frame_number: u64) -> Result<Option<Vec<u8>>> {
        refused("shard spend read")
    }
    fn get_shard_accumulator_report(&self, _filter: &[u8], _digest: &[u8]) -> Result<Option<Vec<u8>>> {
        refused("shard accumulator report read")
    }
    fn delete_global_clock_frame_range(&self, _min_frame: u64, _max_frame: u64) -> Result<()> {
        refused("GLOBAL frame delete")
    }
    fn reset_global_clock_frames(&self) -> Result<()> {
        refused("GLOBAL frame reset")
    }

    fn get_latest_certified_global_state(&self) -> Result<proto::global::GlobalProposal> {
        refused("certified state")
    }
    fn get_earliest_certified_global_state(&self) -> Result<proto::global::GlobalProposal> {
        refused("certified state")
    }
    fn get_certified_global_state(&self, _rank: u64) -> Result<proto::global::GlobalProposal> {
        refused("certified state")
    }
    fn put_certified_global_state(
        &self,
        _state: &proto::global::GlobalProposal,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        refused("certified state write")
    }

    fn get_latest_quorum_certificate(&self, _filter: &[u8]) -> Result<proto::global::QuorumCertificate> {
        refused("quorum certificate")
    }
    fn get_quorum_certificate(&self, _filter: &[u8], _rank: u64) -> Result<proto::global::QuorumCertificate> {
        refused("quorum certificate")
    }
    fn put_quorum_certificate(
        &self,
        _qc: &proto::global::QuorumCertificate,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        refused("quorum certificate write")
    }

    fn get_latest_timeout_certificate(&self, _filter: &[u8]) -> Result<proto::global::TimeoutCertificate> {
        refused("timeout certificate")
    }
    fn get_timeout_certificate(&self, _filter: &[u8], _rank: u64) -> Result<proto::global::TimeoutCertificate> {
        refused("timeout certificate")
    }
    fn put_timeout_certificate(
        &self,
        _tc: &proto::global::TimeoutCertificate,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        refused("timeout certificate write")
    }

    fn get_latest_shard_clock_frame(&self, _filter: &[u8]) -> Result<proto::global::AppShardFrame> {
        refused("shard frame")
    }
    fn get_shard_clock_frame(
        &self,
        _filter: &[u8],
        _frame_number: u64,
        _truncate: bool,
    ) -> Result<proto::global::AppShardFrame> {
        refused("shard frame")
    }
    fn commit_shard_clock_frame(
        &self,
        _filter: &[u8],
        _frame_number: u64,
        _selector: &[u8],
        _txn: &dyn Transaction,
        _backfill: bool,
    ) -> Result<()> {
        refused("shard frame write")
    }
    fn stage_shard_clock_frame(
        &self,
        _selector: &[u8],
        _frame: &proto::global::AppShardFrame,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        refused("shard frame write")
    }
    fn get_staged_shard_clock_frame(
        &self,
        _filter: &[u8],
        _frame_number: u64,
        _parent_selector: &[u8],
        _truncate: bool,
    ) -> Result<proto::global::AppShardFrame> {
        refused("staged shard frame")
    }
    fn set_latest_shard_clock_frame_number(&self, _filter: &[u8], _frame_number: u64) -> Result<()> {
        refused("shard frame write")
    }
    fn delete_shard_clock_frame_range(&self, _filter: &[u8], _min_frame: u64, _max_frame: u64) -> Result<()> {
        refused("shard frame delete")
    }
    fn reset_shard_clock_frames(&self, _filter: &[u8]) -> Result<()> {
        refused("shard frame reset")
    }

    fn get_latest_certified_app_shard_state(&self, _filter: &[u8]) -> Result<proto::global::AppShardProposal> {
        refused("certified shard state")
    }
    fn put_certified_app_shard_state(
        &self,
        _state: &proto::global::AppShardProposal,
        _txn: &dyn Transaction,
    ) -> Result<()> {
        refused("certified shard state write")
    }

    fn put_proposal_vote(&self, _txn: &dyn Transaction, _vote: &proto::global::ProposalVote) -> Result<()> {
        refused("vote write")
    }
    fn get_proposal_vote(
        &self,
        _filter: &[u8],
        _rank: u64,
        _identity: &[u8],
    ) -> Result<proto::global::ProposalVote> {
        refused("vote")
    }
    fn get_proposal_votes(&self, _filter: &[u8], _rank: u64) -> Result<Vec<proto::global::ProposalVote>> {
        refused("votes")
    }
    fn put_timeout_vote(&self, _txn: &dyn Transaction, _vote: &proto::global::TimeoutState) -> Result<()> {
        refused("timeout vote write")
    }
    fn get_timeout_vote(
        &self,
        _filter: &[u8],
        _rank: u64,
        _identity: &[u8],
    ) -> Result<proto::global::TimeoutState> {
        refused("timeout vote")
    }
    fn get_timeout_votes(&self, _filter: &[u8], _rank: u64) -> Result<Vec<proto::global::TimeoutState>> {
        refused("timeout votes")
    }

    fn get_total_distance(&self, _filter: &[u8], _frame_number: u64, _selector: &[u8]) -> Result<BigInt> {
        refused("total distance")
    }
    fn set_total_distance(
        &self,
        _filter: &[u8],
        _frame_number: u64,
        _selector: &[u8],
        _total_distance: &BigInt,
    ) -> Result<()> {
        refused("total distance write")
    }
    fn get_peer_seniority_map(&self, _filter: &[u8]) -> Result<HashMap<String, u64>> {
        refused("seniority")
    }
    fn put_peer_seniority_map(
        &self,
        _txn: &dyn Transaction,
        _filter: &[u8],
        _seniority_map: &HashMap<String, u64>,
    ) -> Result<()> {
        refused("seniority write")
    }

    fn compact_data(&self, _data_filter: &[u8]) -> Result<()> {
        refused("compaction")
    }
}

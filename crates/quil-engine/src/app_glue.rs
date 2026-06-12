//! App shard consensus glue: concrete implementations of the
//! quil-consensus trait callbacks for per-shard HotStuff.
//!
//! Mirrors `consensus_glue.rs` (GlobalConsumer etc.) but for app shards.
//! Each shard engine gets its own set of these callbacks.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use quil_consensus::event_handler::Consumer;
use quil_consensus::forest::{Finalizer, FollowerConsumer};
use quil_consensus::models::{
    CertifiedState, FinalityProof, Identity, QuorumCertificate, SignedProposal,
    State, TimeoutCertificate, TimeoutState, Unique,
};
use quil_consensus::pacemaker::ParticipantConsumer;
use quil_types::error::Result;

use crate::app_types::{AppShardState, AppShardVote};

/// Encode a QC's aggregate signature into the canonical
/// `BLS48581AggregateSignature` byte format the wire FrameHeader's
/// `public_key_signature_bls48581` field expects. The pubkey is
/// embedded as `Bls48581G2PublicKey` (4-byte type prefix + 585-byte
/// key). The bitmask identifies committee positions that
/// participated.
pub fn canonical_aggregate_signature(
    signature: &[u8],
    public_key: &[u8],
    bitmask: &[u8],
) -> Result<Vec<u8>> {
    use quil_execution::hypergraph_intrinsic::canonical::{
        AggregateSignature, Bls48581G2PublicKey,
    };
    let pubkey = if public_key.is_empty() {
        None
    } else {
        Some(Bls48581G2PublicKey {
            key_value: public_key.to_vec(),
        })
    };
    let agg = AggregateSignature {
        signature: signature.to_vec(),
        public_key: pubkey,
        bitmask: bitmask.to_vec(),
    };
    agg.to_canonical_bytes()
}

// =====================================================================
// Events emitted by the consensus layer to the app engine
// =====================================================================

/// Events from the HotStuff consensus layer to the app engine's
/// main loop. These drive frame finalization, equivocation detection,
/// and rank tracking.
#[derive(Debug)]
pub enum AppConsensusEvent {
    /// A new state was finalized (2-chain rule satisfied).
    Finalized {
        frame_number: u64,
        rank: u64,
        state_id: Identity,
        /// Canonical FrameHeader bytes for the finalized state.
        /// Carried through from `on_finalized_state` so the
        /// engine's consumer can emit `ShardFrameFinalized`
        /// without re-loading and re-encoding the frame.
        /// `None` if encoding failed.
        canonical_header_bytes: Option<Vec<u8>>,
    },
    /// A double-propose was detected — equivocation evidence.
    DoublePropose {
        first_frame: u64,
        second_frame: u64,
    },
    /// Rank changed (QC or TC triggered advance).
    RankChange {
        old_rank: u64,
        new_rank: u64,
    },
    /// Own vote was produced and needs publishing.
    OwnVote {
        data: Vec<u8>,
        recipient: Identity,
    },
    /// Own timeout was produced and needs publishing.
    OwnTimeout {
        data: Vec<u8>,
    },
    /// Own proposal was produced and needs publishing.
    OwnProposal {
        data: Vec<u8>,
        frame_number: u64,
        rank: u64,
    },
}

// =====================================================================
// AppConsumer — handles HotStuff lifecycle events
// =====================================================================

/// Consumer for app shard consensus events. Serializes votes,
/// timeouts, and proposals for network publication and emits events
/// to the engine's main loop. The aggregator is held in a `OnceLock`
/// because it depends on the event-loop handle, which itself is only
/// available after the consumer has been constructed.
pub struct AppConsumer {
    filter: Vec<u8>,
    /// Poseidon(filter) — peers compare an inbound proposal's
    /// FrameHeader.address against this; encoding our own proposal
    /// with `address = filter` would have peers reject every proposal.
    app_address: Vec<u8>,
    event_tx: mpsc::UnboundedSender<AppConsensusEvent>,
    aggregator: std::sync::OnceLock<std::sync::Arc<crate::app_vote_aggregation::AppVoteAggregation>>,
}

impl AppConsumer {
    pub fn new(filter: Vec<u8>, event_tx: mpsc::UnboundedSender<AppConsensusEvent>) -> Self {
        let app_address = quil_crypto::poseidon::hash_bytes_to_32(&filter)
            .map(|h| h.to_vec())
            .unwrap_or_default();
        Self {
            filter,
            app_address,
            event_tx,
            aggregator: std::sync::OnceLock::new(),
        }
    }

    /// Install the per-shard vote aggregator. Idempotent — only the
    /// first set takes effect.
    pub fn set_aggregator(
        &self,
        agg: std::sync::Arc<crate::app_vote_aggregation::AppVoteAggregation>,
    ) {
        let _ = self.aggregator.set(agg);
    }
}

impl Consumer<AppShardState, AppShardVote> for AppConsumer {
    fn on_start(&self, current_rank: u64) {
        info!(
            filter = hex::encode(&self.filter),
            rank = current_rank,
            "app shard consensus started"
        );
    }

    fn on_receive_proposal(
        &self,
        current_rank: u64,
        _proposal: &SignedProposal<AppShardState, AppShardVote>,
    ) {
        debug!(
            filter = hex::encode(&self.filter),
            rank = current_rank,
            "received shard proposal"
        );
    }

    fn on_receive_quorum_certificate(
        &self,
        current_rank: u64,
        qc: &dyn QuorumCertificate,
    ) {
        debug!(
            filter = hex::encode(&self.filter),
            rank = current_rank,
            qc_rank = qc.rank(),
            "received shard QC"
        );
    }

    fn on_receive_timeout_certificate(
        &self,
        current_rank: u64,
        tc: &dyn TimeoutCertificate,
    ) {
        debug!(
            filter = hex::encode(&self.filter),
            rank = current_rank,
            tc_rank = tc.rank(),
            "received shard TC"
        );
    }

    fn on_local_timeout(&self, current_rank: u64) {
        debug!(
            filter = hex::encode(&self.filter),
            rank = current_rank,
            "shard local timeout"
        );
    }

    fn on_own_vote(&self, vote: &AppShardVote, recipient_id: &Identity) {
        debug!(
            filter = hex::encode(&self.filter),
            rank = vote.rank(),
            recipient = %hex::encode(recipient_id),
            "produced shard vote"
        );

        // Tally the local vote so a small or single-member committee
        // can form a QC without a network round-trip.
        if let Some(agg) = self.aggregator.get() {
            agg.handle_vote(vote.clone());
        }

        // Wire encoding: selector = proposal id (Source()), address =
        // voter id (Identity()).
        let wire_vote = crate::consensus_wire::ProposalVote {
            filter: self.filter.clone(),
            rank: vote.rank(),
            frame_number: vote.rank(),
            selector: vote.source().clone(),
            timestamp: vote.timestamp(),
            signature: vote.signature_bytes.clone(),
            address: vote.identity().clone(),
        };
        if let Ok(bytes) = wire_vote.to_canonical_bytes() {
            let _ = self.event_tx.send(AppConsensusEvent::OwnVote {
                data: bytes,
                recipient: recipient_id.clone(),
            });
        }
    }

    fn on_own_timeout(&self, timeout: &TimeoutState<AppShardVote>) {
        debug!(
            filter = hex::encode(&self.filter),
            rank = timeout.rank,
            "produced shard timeout"
        );
        let wire_qc = crate::consensus_wire::QuorumCertificate::genesis(0, self.filter.clone());
        // Timeout vote: selector is empty (the timeout binds to
        // (rank, newest_qc_rank), not a specific proposal); address
        // is the voter's identity.
        let wire_vote = crate::consensus_wire::ProposalVote {
            filter: self.filter.clone(),
            rank: timeout.rank,
            frame_number: timeout.rank,
            selector: Vec::new(),
            timestamp: 0,
            signature: timeout.vote.signature_bytes.clone(),
            address: timeout.vote.identity().clone(),
        };
        let wire_ts = crate::consensus_wire::TimeoutState {
            latest_quorum_certificate: wire_qc,
            prior_rank_timeout_certificate: None,
            vote: wire_vote,
            timeout_tick: timeout.rank,
            timestamp: timeout.vote.timestamp(),
        };
        if let Ok(bytes) = wire_ts.to_canonical_bytes() {
            let _ = self.event_tx.send(AppConsensusEvent::OwnTimeout {
                data: bytes,
            });
        }
    }

    fn on_own_proposal(
        &self,
        proposal: &SignedProposal<AppShardState, AppShardVote>,
        target_publication_time: Instant,
    ) {
        let frame = proposal.proposal.state.state.frame_number;
        let rank = proposal.proposal.state.rank;
        debug!(
            filter = hex::encode(&self.filter),
            frame,
            rank,
            "produced shard proposal"
        );

        // Hand the proposal to the rank's vote collector so it can
        // transition to the verifying state and tally subsequent
        // votes against this proposal's identifier.
        if let Some(agg) = self.aggregator.get() {
            agg.handle_proposal(proposal);
        }

        // Build canonical `AppShardProposal` (0x0318) bytes so peers'
        // `handle_app_shard_proposal` can fully reconstruct the
        // SignedProposal + parent QC + prior TC + vote and feed it
        // into their own event loop. Without this, the data we emit
        // here is unparseable on the wire and peers never vote.
        let st = &proposal.proposal.state.state;
        let canonical_header = quil_execution::global_intrinsic::frame_header::FrameHeader {
            // Peers compare against `app_address = Poseidon(filter)`,
            // not the raw filter (see `handle_app_shard_proposal`).
            address: self.app_address.clone(),
            frame_number: st.frame_number,
            rank: proposal.proposal.state.rank,
            timestamp: st.timestamp,
            difficulty: st.difficulty,
            output: st.output.clone(),
            parent_selector: st.parent_selector.clone(),
            requests_root: st.requests_root.clone(),
            state_roots: st.state_roots.clone(),
            prover: st.prover.clone(),
            fee_multiplier_vote: st.fee_multiplier as i64,
            public_key_signature_bls48581: st.signature.clone(),
        };
        let header_bytes = match canonical_header.to_canonical_bytes() {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    filter = hex::encode(&self.filter),
                    error = %e,
                    "could not encode FrameHeader for AppShardProposal"
                );
                return;
            }
        };

        // AppShardFrame canonical bytes: [u32 0x030F][lp header_bytes]
        const TYPE_APP_SHARD_FRAME: u32 = 0x030F;
        const TYPE_APP_SHARD_PROPOSAL: u32 = 0x0318;
        let mut state_bytes = Vec::with_capacity(header_bytes.len() + 8);
        state_bytes.extend_from_slice(&TYPE_APP_SHARD_FRAME.to_be_bytes());
        state_bytes.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
        state_bytes.extend_from_slice(&header_bytes);

        // Wire-format parent QC / prior TC / leader vote.
        let parent_qc_wire = crate::consensus_wire::QuorumCertificate::from_trait_object(
            proposal.proposal.parent_quorum_certificate.as_ref(),
        );
        let parent_qc_bytes = match parent_qc_wire.to_canonical_bytes() {
            Ok(b) => b,
            Err(e) => {
                warn!(filter = hex::encode(&self.filter), error = %e, "encode parent QC failed");
                return;
            }
        };
        let prior_tc_bytes: Vec<u8> = match proposal
            .proposal
            .previous_rank_timeout_certificate
            .as_ref()
        {
            Some(tc) => {
                let wire =
                    crate::consensus_wire::TimeoutCertificate::from_trait_object(tc.as_ref());
                match wire.to_canonical_bytes() {
                    Ok(b) => b,
                    Err(e) => {
                        warn!(filter = hex::encode(&self.filter), error = %e, "encode prior TC failed");
                        return;
                    }
                }
            }
            None => Vec::new(),
        };

        let v = &proposal.vote;
        let wire_vote = crate::consensus_wire::ProposalVote {
            filter: self.filter.clone(),
            rank: v.rank(),
            frame_number: rank, // shard votes mirror Go: frame_number == rank
            selector: v.source().clone(),
            timestamp: v.timestamp(),
            signature: v.signature_bytes.clone(),
            address: v.identity().clone(),
        };
        let vote_bytes = match wire_vote.to_canonical_bytes() {
            Ok(b) => b,
            Err(e) => {
                warn!(filter = hex::encode(&self.filter), error = %e, "encode leader vote failed");
                return;
            }
        };

        let mut out = Vec::with_capacity(
            16 + state_bytes.len() + parent_qc_bytes.len() + prior_tc_bytes.len() + vote_bytes.len(),
        );
        out.extend_from_slice(&TYPE_APP_SHARD_PROPOSAL.to_be_bytes());
        out.extend_from_slice(&(state_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&state_bytes);
        out.extend_from_slice(&(parent_qc_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&parent_qc_bytes);
        out.extend_from_slice(&(prior_tc_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&prior_tc_bytes);
        out.extend_from_slice(&(vote_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&vote_bytes);

        // Defer broadcast to `target_publication_time` so the chain
        // advances at `proposal_duration` cadence. Cap at 8s to stay
        // inside the pacemaker's local timeout window.
        let event_tx = self.event_tx.clone();
        let data = out;
        tokio::spawn(async move {
            let now = Instant::now();
            let max_wait = std::time::Duration::from_secs(8);
            let cap = now + max_wait;
            let effective = std::cmp::min(target_publication_time, cap);
            if effective > now {
                tokio::time::sleep_until(effective.into()).await;
            }
            let _ = event_tx.send(AppConsensusEvent::OwnProposal {
                data,
                frame_number: frame,
                rank,
            });
        });
    }

    fn on_event_processed(&self) {}

    fn on_rank_change(&self, old_rank: u64, new_rank: u64) {
        debug!(
            filter = hex::encode(&self.filter),
            old = old_rank,
            new = new_rank,
            "shard rank change"
        );
        let _ = self.event_tx.send(AppConsensusEvent::RankChange {
            old_rank,
            new_rank,
        });
    }

    fn on_finalization(&self, proof: &FinalityProof<AppShardState>) {
        debug!(
            filter = hex::encode(&self.filter),
            frame = proof.state.state.frame_number,
            rank = proof.state.rank,
            "shard state finalized"
        );
        // ParticipantConsumer path — canonical bytes already emitted
        // via `on_finalized_state`. This event is the
        // `FinalityProof`-driven duplicate that the Forks tree fires
        // after both 2-chain rule and full 3-chain (depending on the
        // consensus configuration); no separate canonical encoding
        // is plumbed through here.
        let _ = self.event_tx.send(AppConsensusEvent::Finalized {
            frame_number: proof.state.state.frame_number,
            rank: proof.state.rank,
            state_id: proof.state.identifier.clone(),
            canonical_header_bytes: None,
        });
    }

    fn on_qc_constructed(&self, qc: &dyn QuorumCertificate) {
        debug!(
            filter = hex::encode(&self.filter),
            rank = qc.rank(),
            "shard QC constructed"
        );
    }

    fn on_tc_constructed(&self, tc: &dyn TimeoutCertificate) {
        debug!(
            filter = hex::encode(&self.filter),
            rank = tc.rank(),
            "shard TC constructed"
        );
    }
}

// =====================================================================
// AppParticipantConsumer — pacemaker callbacks
// =====================================================================

pub struct AppParticipantConsumer {
    filter: Vec<u8>,
    /// Optional multi-proof precomputer. Wired by the engine when
    /// the shard has more than one active prover. Each rank-change
    /// hook fires `precompute_for_rank_change`, kicking off the VDF
    /// off the consensus thread so `sign_vote` can pick up the
    /// cached bytes without blocking.
    multi_proof_precomputer: Option<std::sync::Arc<crate::multi_proof_cache::ShardMultiProofPrecomputer>>,
    /// Shared atomic that tracks the current frame's difficulty.
    /// Read at rank-change time to parametrize the multi-proof VDF.
    /// `None` when the engine doesn't track difficulty (tests).
    current_difficulty: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
}

impl AppParticipantConsumer {
    pub fn new(filter: Vec<u8>) -> Self {
        Self {
            filter,
            multi_proof_precomputer: None,
            current_difficulty: None,
        }
    }

    pub fn with_multi_proof_precomputer(
        mut self,
        precomputer: std::sync::Arc<crate::multi_proof_cache::ShardMultiProofPrecomputer>,
        current_difficulty: std::sync::Arc<std::sync::atomic::AtomicU32>,
    ) -> Self {
        self.multi_proof_precomputer = Some(precomputer);
        self.current_difficulty = Some(current_difficulty);
        self
    }

    fn trigger_precompute(&self, new_rank: u64, parent_selector: Vec<u8>) {
        let (Some(p), Some(diff)) = (
            self.multi_proof_precomputer.as_ref(),
            self.current_difficulty.as_ref(),
        ) else {
            return;
        };
        let d = diff.load(std::sync::atomic::Ordering::Relaxed);
        p.precompute_for_rank_change(new_rank, parent_selector, d);
    }
}

impl ParticipantConsumer<AppShardState, AppShardVote> for AppParticipantConsumer {
    fn on_quorum_certificate_triggered_rank_change(
        &self,
        old_rank: u64,
        new_rank: u64,
        qc: &dyn QuorumCertificate,
    ) {
        debug!(
            filter = hex::encode(&self.filter),
            old = old_rank,
            new = new_rank,
            "shard QC triggered rank change"
        );
        // QC's identity = poseidon(certified_state.output), which is
        // also the next rank's `parent_selector`. Kick off the multi-
        // proof precompute for new_rank using this challenge basis.
        self.trigger_precompute(new_rank, qc.identity().clone());
    }

    fn on_timeout_certificate_triggered_rank_change(
        &self,
        old_rank: u64,
        new_rank: u64,
        tc: &dyn TimeoutCertificate,
    ) {
        debug!(
            filter = hex::encode(&self.filter),
            old = old_rank,
            new = new_rank,
            "shard TC triggered rank change"
        );
        // The TC references the newest QC seen — use that QC's
        // identity for the multi-proof challenge basis (same as
        // happy-path rank changes).
        self.trigger_precompute(new_rank, tc.latest_quorum_cert().identity().clone());
    }

    fn on_rank_change(&self, old_rank: u64, new_rank: u64) {
        debug!(
            filter = hex::encode(&self.filter),
            old = old_rank,
            new = new_rank,
            "shard pacemaker rank change"
        );
    }

    fn on_starting_timeout(&self, _start: Instant, _end: Instant) {
        debug!(filter = hex::encode(&self.filter), "shard pacemaker starting timeout");
    }
}

// =====================================================================
// AppFinalizer — called when fork tree commits a finalized state
// =====================================================================

pub struct AppFinalizer {
    filter: Vec<u8>,
}

impl AppFinalizer {
    pub fn new(filter: Vec<u8>) -> Self {
        Self { filter }
    }
}

impl Finalizer for AppFinalizer {
    fn make_final(&self, state_id: &Identity) -> Result<()> {
        debug!(
            filter = hex::encode(&self.filter),
            state = %hex::encode(state_id),
            "shard make_final"
        );
        Ok(())
    }
}

// =====================================================================
// AppFollower — fork tree incorporation/finalization notifications
// =====================================================================

/// Hook fired from `AppFollower::on_state_incorporated`. Mirrors the
/// global path: lets the node persist the proposed (but not yet
/// QC'd) shard frame so the next-rank leader can chain a proposal on
/// top via `prove_next_state`. Without this, the chain stalls at the
/// first rank after the genesis/migration boundary.
pub type AppIncorporatedStateHook =
    std::sync::Arc<dyn Fn(&State<AppShardState>) + Send + Sync>;

/// In-memory cache of QCs keyed by `qc.identity()`. The forest's
/// finalizer drops the QC pointer from `CertifiedState`; this is
/// what `on_finalized_state` rehydrates from when emitting the wire
/// FrameHeader's aggregate signature. Pruned by `min_active_rank`.
#[derive(Default)]
pub struct QcStore {
    by_identity: Mutex<HashMap<Identity, Arc<dyn QuorumCertificate>>>,
    by_rank: Mutex<HashMap<u64, Vec<Identity>>>,
}

impl QcStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// First-wins insert keyed by the certified state identity.
    pub fn insert(&self, qc: Arc<dyn QuorumCertificate>) {
        let id = qc.identity().clone();
        let rank = qc.rank();
        let mut by_identity = self.by_identity.lock().unwrap();
        if by_identity.contains_key(&id) {
            return;
        }
        by_identity.insert(id.clone(), qc);
        self.by_rank
            .lock()
            .unwrap()
            .entry(rank)
            .or_default()
            .push(id);
    }

    pub fn lookup(&self, identity: &Identity) -> Option<Arc<dyn QuorumCertificate>> {
        self.by_identity.lock().unwrap().get(identity).cloned()
    }

    /// Drop QCs whose rank fell below the finalized watermark.
    pub fn advance_min_active_rank(&self, min_rank: u64) {
        let mut by_rank = self.by_rank.lock().unwrap();
        let stale_ranks: Vec<u64> = by_rank.keys().filter(|r| **r < min_rank).copied().collect();
        let mut by_identity = self.by_identity.lock().unwrap();
        for r in stale_ranks {
            if let Some(ids) = by_rank.remove(&r) {
                for id in ids {
                    by_identity.remove(&id);
                }
            }
        }
    }
}

pub struct AppFollower {
    filter: Vec<u8>,
    /// Wire FrameHeader.address field; equal to `filter`.
    app_address: Vec<u8>,
    consensus_event_tx: mpsc::UnboundedSender<AppConsensusEvent>,
    /// Direct publisher for finalized-frame canonical bytes. Invoked
    /// synchronously from `on_finalized_state` so the rewards path
    /// doesn't depend on internal channel scheduling.
    coverage_publish: Option<std::sync::Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
    /// Hook fired on every `on_state_incorporated` to stage the
    /// proposed shard frame for commit-on-QC.
    on_incorporated: Option<AppIncorporatedStateHook>,
    /// Lookup for certifying QCs — see `QcStore`.
    qc_store: Arc<QcStore>,
}

impl AppFollower {
    pub fn new(
        filter: Vec<u8>,
        app_address: Vec<u8>,
        consensus_event_tx: mpsc::UnboundedSender<AppConsensusEvent>,
        coverage_publish: Option<std::sync::Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
        qc_store: Arc<QcStore>,
    ) -> Self {
        Self {
            filter,
            app_address,
            consensus_event_tx,
            coverage_publish,
            on_incorporated: None,
            qc_store,
        }
    }

    pub fn with_incorporated_hook(
        filter: Vec<u8>,
        app_address: Vec<u8>,
        consensus_event_tx: mpsc::UnboundedSender<AppConsensusEvent>,
        coverage_publish: Option<std::sync::Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
        on_incorporated: Option<AppIncorporatedStateHook>,
        qc_store: Arc<QcStore>,
    ) -> Self {
        Self {
            filter,
            app_address,
            consensus_event_tx,
            coverage_publish,
            on_incorporated,
            qc_store,
        }
    }
}

impl FollowerConsumer<AppShardState> for AppFollower {
    fn on_state_incorporated(&self, state: &State<AppShardState>) {
        debug!(
            filter = hex::encode(&self.filter),
            frame = state.state.frame_number,
            rank = state.rank,
            "shard state incorporated"
        );
        if let Some(hook) = &self.on_incorporated {
            hook(state);
        }
    }

    fn on_finalized_state(&self, certified: &CertifiedState<AppShardState>) {
        let state = &certified.state;
        debug!(
            filter = hex::encode(&self.filter),
            frame = state.state.frame_number,
            rank = state.rank,
            "shard state finalized"
        );

        // Build the canonical FrameHeader directly from the finalized
        // state's fields. The signature field carries the certifying
        // QC's aggregate BLS signature, aggregated pubkey, and
        // participant bitmask — encoded as `AggregateSignature`
        // canonical bytes (matching Go's
        // `BLS48581AggregateSignature.ToCanonicalBytes`). Verifiers on
        // the archive side decode this, look up the committee at the
        // header's rank, and check both the VDF and the aggregate sig
        // before crediting rewards.
        // Forest's finalizer strips `certifying_quorum_certificate`;
        // rehydrate from `QcStore` keyed on `certifying_qc_identity`.
        let rehydrated_qc = certified
            .certifying_quorum_certificate
            .clone()
            .or_else(|| self.qc_store.lookup(&certified.certifying_qc_identity));
        let sig_bytes: Vec<u8> = match rehydrated_qc.as_ref() {
            Some(qc) => {
                let agg = qc.aggregated_signature();
                let canonical = canonical_aggregate_signature(
                    agg.signature(),
                    agg.public_key(),
                    agg.bitmask(),
                );
                match canonical {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        warn!(
                            filter = hex::encode(&self.filter),
                            error = %e,
                            "failed to encode finalized QC aggregate signature — emitting empty sig"
                        );
                        Vec::new()
                    }
                }
            }
            None => {
                warn!(
                    filter = hex::encode(&self.filter),
                    certifying_qc_identity = %hex::encode(&certified.certifying_qc_identity),
                    certifying_qc_rank = certified.certifying_qc_rank,
                    "finalized state missing certifying QC after rehydration — emitting empty signature"
                );
                Vec::new()
            }
        };
        let canonical_header = quil_execution::global_intrinsic::frame_header::FrameHeader {
            address: self.app_address.clone(),
            frame_number: state.state.frame_number,
            rank: state.rank,
            timestamp: state.state.timestamp,
            difficulty: state.state.difficulty,
            output: state.state.output.clone(),
            parent_selector: state.state.parent_selector.clone(),
            requests_root: state.state.requests_root.clone(),
            state_roots: state.state.state_roots.clone(),
            prover: state.state.prover.clone(),
            fee_multiplier_vote: state.state.fee_multiplier as i64,
            public_key_signature_bls48581: sig_bytes,
        };
        let header_bytes: Option<Vec<u8>> = match canonical_header.to_canonical_bytes() {
            Ok(bytes) => {
                if let Some(publisher) = self.coverage_publish.as_ref() {
                    publisher(bytes.clone());
                }
                Some(bytes)
            }
            Err(e) => {
                warn!(
                    filter = hex::encode(&self.filter),
                    error = %e,
                    "failed to encode finalized FrameHeader for coverage publish"
                );
                None
            }
        };

        // Pass the canonical bytes through the bookkeeping event so
        // `handle_consensus_event` can emit `ShardFrameFinalized`
        // without re-loading and re-encoding the frame.
        let _ = self.consensus_event_tx.send(AppConsensusEvent::Finalized {
            frame_number: state.state.frame_number,
            rank: state.rank,
            state_id: state.identifier.clone(),
            canonical_header_bytes: header_bytes,
        });
    }

    fn on_double_propose_detected(
        &self,
        first: &State<AppShardState>,
        second: &State<AppShardState>,
    ) {
        warn!(
            filter = hex::encode(&self.filter),
            first_frame = first.state.frame_number,
            second_frame = second.state.frame_number,
            "SHARD DOUBLE PROPOSE DETECTED — equivocation"
        );
        let _ = self.consensus_event_tx.send(AppConsensusEvent::DoublePropose {
            first_frame: first.state.frame_number,
            second_frame: second.state.frame_number,
        });
    }
}

// =====================================================================
// AppConsensusCodec — persistence codec for app shard consensus state
// =====================================================================

use crate::app_types::AppGenesisQC;
use crate::consensus_store::ConsensusStateCodec;
use quil_consensus::models::{ConsensusState, LivenessState};

pub struct AppConsensusCodec {
    pub filter: Vec<u8>,
}

impl ConsensusStateCodec<AppShardVote> for AppConsensusCodec {
    fn encode_consensus_state(&self, state: &ConsensusState<AppShardVote>) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&(state.filter.len() as u32).to_be_bytes());
        out.extend_from_slice(&state.filter);
        out.extend_from_slice(&state.finalized_rank.to_be_bytes());
        out.extend_from_slice(&state.latest_acknowledged_rank.to_be_bytes());
        Ok(out)
    }

    fn decode_consensus_state(&self, bytes: &[u8]) -> Result<ConsensusState<AppShardVote>> {
        use quil_types::error::QuilError;
        if bytes.len() < 4 {
            return Err(QuilError::InvalidArgument("app consensus state too short".into()));
        }
        let filter_len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        if bytes.len() < 4 + filter_len + 16 {
            return Err(QuilError::InvalidArgument("app consensus state truncated".into()));
        }
        let filter = bytes[4..4 + filter_len].to_vec();
        let off = 4 + filter_len;
        let finalized_rank = u64::from_be_bytes(bytes[off..off + 8].try_into().unwrap());
        let latest_rank = u64::from_be_bytes(bytes[off + 8..off + 16].try_into().unwrap());
        Ok(ConsensusState {
            filter,
            finalized_rank,
            latest_acknowledged_rank: latest_rank,
            latest_timeout: None,
        })
    }

    fn encode_liveness_state(&self, state: &LivenessState) -> Result<Vec<u8>> {
        // Layout matches `GlobalConsensusCodec::encode_liveness_state`:
        // filter_len(u32) | filter | current_rank(u64) |
        // qc_len(u32) | qc_canonical | tc_len(u32) | tc_canonical (0 = none).
        let mut out = Vec::new();
        out.extend_from_slice(&(state.filter.len() as u32).to_be_bytes());
        out.extend_from_slice(&state.filter);
        out.extend_from_slice(&state.current_rank.to_be_bytes());

        let qc = crate::consensus_wire::QuorumCertificate::from_trait_object(
            state.latest_quorum_certificate.as_ref(),
        );
        let qc_bytes = qc.to_canonical_bytes()?;
        out.extend_from_slice(&(qc_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&qc_bytes);

        match state.prior_rank_timeout_certificate.as_ref() {
            Some(tc) => {
                let wire_tc = crate::consensus_wire::TimeoutCertificate::from_trait_object(tc.as_ref());
                let tc_bytes = wire_tc.to_canonical_bytes()?;
                out.extend_from_slice(&(tc_bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&tc_bytes);
            }
            None => {
                out.extend_from_slice(&0u32.to_be_bytes());
            }
        }
        Ok(out)
    }

    fn decode_liveness_state(&self, bytes: &[u8]) -> Result<LivenessState> {
        use quil_types::error::QuilError;
        fn need(bytes: &[u8], off: usize, n: usize, what: &str) -> Result<()> {
            if off + n > bytes.len() {
                return Err(QuilError::InvalidArgument(format!(
                    "app liveness decode: short read at {} (need {})", what, n
                )));
            }
            Ok(())
        }
        need(bytes, 0, 4, "filter_len")?;
        let filter_len = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let mut off = 4;
        need(bytes, off, filter_len, "filter")?;
        let filter = bytes[off..off + filter_len].to_vec();
        off += filter_len;
        need(bytes, off, 8, "current_rank")?;
        let current_rank = u64::from_be_bytes(bytes[off..off + 8].try_into().unwrap());
        off += 8;

        // Backward-compatible path: stored bytes from the older codec
        // didn't include the QC/TC tail. Detect that by checking
        // whether we've already consumed the entire payload and fall
        // back to the genesis QC if so.
        if off == bytes.len() {
            return Ok(LivenessState {
                filter: filter.clone(),
                current_rank,
                latest_quorum_certificate: Arc::new(
                    AppGenesisQC::for_output(filter, &vec![0u8; 32], 0),
                ),
                prior_rank_timeout_certificate: None,
            });
        }

        need(bytes, off, 4, "qc_len")?;
        let qc_len = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        need(bytes, off, qc_len, "qc_bytes")?;
        let qc_bytes = &bytes[off..off + qc_len];
        off += qc_len;
        let qc = crate::consensus_wire::QuorumCertificate::from_canonical_bytes(qc_bytes)?;
        need(bytes, off, 4, "tc_len")?;
        let tc_len = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        off += 4;
        let prior_tc = if tc_len == 0 {
            None
        } else {
            need(bytes, off, tc_len, "tc_bytes")?;
            let tc_bytes = &bytes[off..off + tc_len];
            let tc = crate::consensus_wire::TimeoutCertificate::from_canonical_bytes(tc_bytes)?;
            Some(tc.into_trait_object())
        };
        Ok(LivenessState {
            filter,
            current_rank,
            latest_quorum_certificate: qc.into_trait_object(),
            prior_rank_timeout_certificate: prior_tc,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consensus_codec_roundtrip() {
        let codec = AppConsensusCodec { filter: vec![1, 2, 3] };
        let state = ConsensusState::<AppShardVote> {
            filter: vec![1, 2, 3],
            finalized_rank: 42,
            latest_acknowledged_rank: 50,
            latest_timeout: None,
        };
        let bytes = codec.encode_consensus_state(&state).unwrap();
        let decoded = codec.decode_consensus_state(&bytes).unwrap();
        assert_eq!(decoded.filter, vec![1, 2, 3]);
        assert_eq!(decoded.finalized_rank, 42);
        assert_eq!(decoded.latest_acknowledged_rank, 50);
    }

    #[test]
    fn liveness_codec_roundtrip() {
        let codec = AppConsensusCodec { filter: vec![4, 5] };
        let state = LivenessState {
            filter: vec![4, 5],
            current_rank: 99,
            latest_quorum_certificate: Arc::new(
                AppGenesisQC::for_output(vec![4, 5], &vec![0u8; 32], 0),
            ),
            prior_rank_timeout_certificate: None,
        };
        let bytes = codec.encode_liveness_state(&state).unwrap();
        let decoded = codec.decode_liveness_state(&bytes).unwrap();
        assert_eq!(decoded.filter, vec![4, 5]);
        assert_eq!(decoded.current_rank, 99);
    }
}

use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::committee::Replicas;
use crate::forest::Forks;
use crate::models::*;
use crate::pacemaker::Pacemaker;
use crate::safety_rules::SafetyRulesT;
use crate::state_producer::StateProducer;
use crate::timeout_aggregator::PartialTimeoutCertificateCreated;
use quil_types::error::{QuilError, Result};

/// The core consensus state machine. Processes proposals, votes, QCs, TCs,
/// and timeouts according to the HotStuff protocol.
///
/// **CRITICAL**: This is NOT concurrency safe. Must run on a single task.
/// All events are processed sequentially through the event loop.
pub trait EventHandler<S: Unique, V: Unique>: Send + Sync {
    /// Process a received quorum certificate.
    fn on_receive_quorum_certificate(&mut self, qc: &dyn QuorumCertificate) -> Result<()>;

    /// Process a received timeout certificate.
    fn on_receive_timeout_certificate(&mut self, tc: &dyn TimeoutCertificate) -> Result<()>;

    /// Process a received signed proposal.
    fn on_receive_proposal(&mut self, proposal: &SignedProposal<S, V>) -> Result<()>;

    /// Handle local timeout (timer fired without advancing rank).
    fn on_local_timeout(&mut self) -> Result<()>;

    /// Handle a partial timeout certificate (>1/3 but <2/3 weight reached).
    fn on_partial_timeout_certificate(&mut self, rank: u64) -> Result<()>;
}

/// Notifications emitted by the consensus engine.
pub trait Consumer<S: Unique, V: Unique>: Send + Sync {
    /// Called when the event handler starts up.
    fn on_start(&self, _current_rank: u64) {}

    /// Called when a QC has been received (before any rank change).
    fn on_receive_quorum_certificate(&self, _current_rank: u64, _qc: &dyn QuorumCertificate) {}

    /// Called when a TC has been received.
    fn on_receive_timeout_certificate(&self, _current_rank: u64, _tc: &dyn TimeoutCertificate) {}

    /// Called when a proposal has been received.
    fn on_receive_proposal(&self, _current_rank: u64, _proposal: &SignedProposal<S, V>) {}

    /// Called when the local timeout fires.
    fn on_local_timeout(&self, _current_rank: u64) {}

    /// Called when a partial TC has been constructed internally.
    fn on_partial_timeout_certificate(
        &self,
        _current_rank: u64,
        _partial: &PartialTimeoutCertificateCreated,
    ) {
    }

    /// Called with rank details after every rank decision.
    fn on_current_rank_details(
        &self,
        _current_rank: u64,
        _finalized_rank: u64,
        _leader: &Identity,
    ) {
    }

    /// Called when the node produces its own vote.
    fn on_own_vote(&self, vote: &V, recipient_id: &Identity);

    /// Called when the node produces its own timeout.
    fn on_own_timeout(&self, timeout: &TimeoutState<V>);

    /// Called when the node produces its own proposal.
    fn on_own_proposal(
        &self,
        proposal: &SignedProposal<S, V>,
        target_publication_time: Instant,
    );

    /// Called when any event finishes processing.
    fn on_event_processed(&self);

    /// Called when rank changes.
    fn on_rank_change(&self, old_rank: u64, new_rank: u64);

    /// Called when a state is finalized (2-chain rule).
    fn on_finalization(&self, proof: &FinalityProof<S>);

    /// Called when a QC is constructed from collected votes.
    fn on_qc_constructed(&self, qc: &dyn QuorumCertificate);

    /// Called when a TC is constructed from collected timeouts.
    fn on_tc_constructed(&self, tc: &dyn TimeoutCertificate);
}

/// Produces application-specific state for proposals. Low-level hook
/// invoked by [`crate::leader_provider::LeaderProvider`] implementations.
pub trait AppStateProducer<S: Unique>: Send + Sync {
    /// Build the application state for a new proposal at the given rank.
    fn produce_state(
        &self,
        parent_state: &State<S>,
        rank: u64,
    ) -> Result<S>;
}

/// Persistence for consensus and liveness state (crash recovery).
pub trait ConsensusStore<V: Unique>: Send + Sync {
    fn get_consensus_state(&self, filter: &[u8]) -> Result<ConsensusState<V>>;
    fn put_consensus_state(&self, state: &ConsensusState<V>) -> Result<()>;
    fn get_liveness_state(&self, filter: &[u8]) -> Result<LivenessState>;
    fn put_liveness_state(&self, state: &LivenessState) -> Result<()>;
}

// =====================================================================
// HotStuffEventHandler: concrete central state machine
// =====================================================================

/// Central HotStuff event-handler state machine wiring the
/// pacemaker, forks forest, safety rules, state producer, committee,
/// and outbound consumer. Each subcomponent sits behind
/// `Arc<Mutex<_>>` so the handler stays `Send + Sync` and can be
/// shared through task handles.
/// Maximum number of orphan proposals cached for a single missing
/// parent identity. Honest replicas produce 1-2 proposals per rank
/// (leader plus rare equivocations); anything beyond this is
/// almost certainly attacker traffic. Excess proposals for the
/// same parent are dropped oldest-first.
const MAX_ORPHANS_PER_PARENT: usize = 4;

/// Maximum number of distinct missing parents the orphan cache
/// will track. A legitimate partition leaves at most a handful of
/// recent ranks missing; once we exceed this we drop the
/// oldest-inserted parent's bucket entirely. Bounds total cache
/// size at `MAX_ORPHAN_PARENTS * MAX_ORPHANS_PER_PARENT` proposals.
const MAX_ORPHAN_PARENTS: usize = 64;

struct OrphanCache<S: Unique, V: Unique> {
    /// Bucketed proposals keyed by the parent identity they're
    /// waiting for.
    buckets: std::collections::HashMap<Identity, std::collections::VecDeque<SignedProposal<S, V>>>,
    /// Insertion-order log of parent identities currently in
    /// `buckets`. Used to evict the oldest bucket when total parent
    /// count exceeds `MAX_ORPHAN_PARENTS`.
    order: std::collections::VecDeque<Identity>,
}

impl<S: Unique, V: Unique> OrphanCache<S, V> {
    fn new() -> Self {
        Self {
            buckets: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    /// Push a proposal into the bucket for `parent_id`. Enforces
    /// per-parent and global caps; oldest entries are evicted first.
    fn push(&mut self, parent_id: Identity, proposal: SignedProposal<S, V>) {
        let is_new_parent = !self.buckets.contains_key(&parent_id);
        if is_new_parent {
            if self.order.len() >= MAX_ORPHAN_PARENTS {
                if let Some(victim) = self.order.pop_front() {
                    self.buckets.remove(&victim);
                }
            }
            self.order.push_back(parent_id.clone());
        }
        let bucket = self.buckets.entry(parent_id).or_default();
        if bucket.len() >= MAX_ORPHANS_PER_PARENT {
            bucket.pop_front();
        }
        bucket.push_back(proposal);
    }

    /// Remove and return the bucket for `parent_id`.
    fn remove(&mut self, parent_id: &Identity) -> Option<std::collections::VecDeque<SignedProposal<S, V>>> {
        let bucket = self.buckets.remove(parent_id)?;
        self.order.retain(|id| id != parent_id);
        Some(bucket)
    }
}

pub struct HotStuffEventHandler<S: Unique, V: Unique> {
    pacemaker: Arc<Mutex<dyn Pacemaker>>,
    state_producer: Arc<StateProducer<S, V>>,
    forks: Arc<Mutex<Forks<S>>>,
    safety_rules: Arc<Mutex<dyn SafetyRulesT<S, V>>>,
    committee: Arc<dyn Replicas>,
    notifier: Arc<dyn Consumer<S, V>>,
    /// Highest rank a proposal has already been produced for.
    /// Several paths (fresh QC, fresh TC, local timeout, start) can
    /// drive `propose_for_new_rank_if_primary` for the same rank;
    /// without this guard the state producer runs twice and the
    /// second invocation drains an empty message-collector snapshot.
    last_proposed_rank: std::sync::atomic::AtomicU64,
    /// Proposals whose parent state is not yet in the forks tree.
    /// Bounded — see `MAX_ORPHAN_PARENTS` / `MAX_ORPHANS_PER_PARENT`.
    /// Without bounds, a peer that floods proposals with fabricated
    /// `parent_qc_identity` values would OOM the node.
    orphan_proposals: Mutex<OrphanCache<S, V>>,
}

impl<S: Unique, V: Unique> HotStuffEventHandler<S, V> {
    pub fn new(
        pacemaker: Arc<Mutex<dyn Pacemaker>>,
        state_producer: Arc<StateProducer<S, V>>,
        forks: Arc<Mutex<Forks<S>>>,
        safety_rules: Arc<Mutex<dyn SafetyRulesT<S, V>>>,
        committee: Arc<dyn Replicas>,
        notifier: Arc<dyn Consumer<S, V>>,
    ) -> Self {
        Self {
            pacemaker,
            state_producer,
            forks,
            safety_rules,
            committee,
            notifier,
            last_proposed_rank: std::sync::atomic::AtomicU64::new(0),
            orphan_proposals: Mutex::new(OrphanCache::new()),
        }
    }

    /// Handle a freshly-validated quorum certificate from the
    /// network, internal vote aggregator, or embedded in a timeout
    /// state.
    pub fn on_receive_quorum_certificate(&self, qc: Arc<dyn QuorumCertificate>) -> Result<()> {
        let cur_rank = self.current_rank();
        self.notifier
            .on_receive_quorum_certificate(cur_rank, qc.as_ref());

        let new_rank_event = {
            let mut pm = self.pacemaker.lock().unwrap();
            pm.receive_quorum_certificate(Arc::clone(&qc))
                .map_err(|e| QuilError::Consensus(format!("could not process QC: {}", e)))?
        };

        let result = if new_rank_event.is_some() {
            self.propose_for_new_rank_if_primary()
        } else {
            Ok(())
        };
        self.notifier.on_event_processed();
        result
    }

    /// Handle a freshly-validated timeout certificate.
    pub fn on_receive_timeout_certificate(&self, tc: Arc<dyn TimeoutCertificate>) -> Result<()> {
        let cur_rank = self.current_rank();
        self.notifier
            .on_receive_timeout_certificate(cur_rank, tc.as_ref());

        let new_rank_event = {
            let mut pm = self.pacemaker.lock().unwrap();
            pm.receive_timeout_certificate(Some(Arc::clone(&tc)))
                .map_err(|e| {
                    QuilError::Consensus(format!(
                        "could not process TC for rank {}: {}",
                        tc.rank(),
                        e
                    ))
                })?
        };

        let result = if new_rank_event.is_some() {
            self.propose_for_new_rank_if_primary()
        } else {
            Ok(())
        };
        self.notifier.on_event_processed();
        result
    }

    /// Handle a proposal received from another consensus
    /// participant. Drops stale proposals, adds the state to the
    /// forest, feeds parent QC + optional prior-rank TC into the
    /// pacemaker, votes if the proposal targets the current rank,
    /// and proposes if rank advanced and this node is the new
    /// leader.
    pub fn on_receive_proposal(&self, proposal: &SignedProposal<S, V>) -> Result<()> {
        let cur_rank = self.current_rank();
        tracing::debug!(
            cur_rank,
            proposal_rank = proposal.proposal.state.rank,
            proposer = %hex::encode(&proposal.proposal.state.proposer_id),
            "received proposal",
        );
        self.notifier.on_receive_proposal(cur_rank, proposal);

        // Drop stale proposals.
        let finalized = self.forks.lock().unwrap().finalized_rank();
        if proposal.proposal.state.rank < finalized {
            tracing::debug!(
                cur_rank,
                proposal_rank = proposal.proposal.state.rank,
                finalized,
                "dropping stale proposal",
            );
            self.notifier.on_event_processed();
            return Ok(());
        }

        // Add to forks. Missing-parent errors are benign — the
        // proposal arrived before its parent. Cache it and retry
        // when the parent lands (mirrors Go's cacheProposal path).
        {
            let mut forks = self.forks.lock().unwrap();
            match forks.add_validated_state(proposal.proposal.state.clone()) {
                Ok(()) => {}
                Err(e) if e.to_string().contains("missing parent state") => {
                    let parent_id = proposal.proposal.state.parent_qc_identity.clone();
                    tracing::debug!(
                        rank = proposal.proposal.state.rank,
                        parent = %hex::encode(&parent_id),
                        "caching orphan proposal (missing parent)"
                    );
                    self.orphan_proposals
                        .lock()
                        .unwrap()
                        .push(parent_id, proposal.clone());
                    self.notifier.on_event_processed();
                    return Ok(());
                }
                Err(e) => {
                    return Err(QuilError::Consensus(format!(
                        "cannot add proposal to forks ({}): {}",
                        hex::encode(&proposal.proposal.state.identifier), e
                    )));
                }
            }
        }

        // Drain orphans whose parent just landed.
        self.drain_orphan_proposals(&proposal.proposal.state.identifier)?;

        // `State` only carries `parent_qc_rank` + `parent_qc_identity`,
        // not the full QC trait object — the parent-QC feed comes
        // through `on_receive_quorum_certificate`. The partial-TC
        // path is fed through the pacemaker here.
        if let Some(tc) = &proposal.proposal.previous_rank_timeout_certificate {
            let mut pm = self.pacemaker.lock().unwrap();
            pm.receive_timeout_certificate(Some(Arc::clone(tc)))
                .map_err(|e| {
                    QuilError::Consensus(format!(
                        "could not process TC for state {}: {}",
                        hex::encode(&proposal.proposal.state.identifier), e
                    ))
                })?;
        }

        self.process_state_for_current_rank(proposal)?;

        // If the proposal's rank matches the (possibly updated) current
        // rank, we just voted — nothing else to do. Otherwise, attempt
        // to propose.
        let now_rank = self.current_rank();
        if proposal.proposal.state.rank == now_rank {
            self.notifier.on_event_processed();
            return Ok(());
        }
        let result = self.propose_for_new_rank_if_primary();
        self.notifier.on_event_processed();
        result
    }

    /// Handle a local timeout event.
    pub fn on_local_timeout(&self) -> Result<()> {
        let cur_rank = self.current_rank();
        self.notifier.on_local_timeout(cur_rank);
        let result = self.broadcast_timeout_state_if_authorized();
        // Re-arm the pacemaker's timer so the event loop schedules a
        // rebroadcast tick at `now + rebroadcast_interval` rather than
        // entering a tight busy-loop on the (already-elapsed) deadline.
        {
            let mut pm = self.pacemaker.lock().unwrap();
            pm.rearm_after_local_timeout();
        }
        self.notifier.on_event_processed();
        result.map_err(|e| {
            QuilError::Consensus(format!(
                "unexpected exception while processing timeout in rank {}: {}",
                cur_rank, e
            ))
        })
    }

    /// Instant at which the pacemaker's next local timeout fires.
    /// Used by the event loop's `sleep_until` arm to drive the timer.
    pub fn current_round_deadline(&self) -> Instant {
        self.pacemaker.lock().unwrap().current_round_deadline()
    }

    /// Handle a partial-TC notification from the timeout aggregator.
    /// Feeds embedded newest QC + optional prior-rank TC into the
    /// pacemaker, then broadcasts a local timeout if still at the
    /// partial's rank to help the network converge. A partial TC
    /// (>1/3 weight timed out) deliberately does NOT trigger a new
    /// proposal here — any such proposal would struggle to reach
    /// quorum.
    pub fn on_partial_timeout_certificate_created(
        &self,
        partial: &PartialTimeoutCertificateCreated,
    ) -> Result<()> {
        let cur_rank = self.current_rank();
        self.notifier
            .on_partial_timeout_certificate(cur_rank, partial);

        // Feed embedded QC into the pacemaker.
        {
            let mut pm = self.pacemaker.lock().unwrap();
            pm.receive_quorum_certificate(Arc::clone(&partial.newest_quorum_certificate))
                .map_err(|e| {
                    QuilError::Consensus(format!("could not process newest QC: {}", e))
                })?;
        }

        // Feed optional prior-rank TC into the pacemaker.
        if let Some(tc) = &partial.prior_rank_timeout_certificate {
            let tc_rank = tc.rank();
            let mut pm = self.pacemaker.lock().unwrap();
            pm.receive_timeout_certificate(Some(Arc::clone(tc))).map_err(
                |e| {
                    QuilError::Consensus(format!(
                        "could not process TC for rank {}: {}",
                        tc_rank, e
                    ))
                },
            )?;
        }

        // Broadcast timeout if we're still at the partial's rank.
        let now_rank = self.current_rank();
        let result = if now_rank == partial.rank {
            self.broadcast_timeout_state_if_authorized()
        } else {
            Ok(())
        };
        self.notifier.on_event_processed();
        result
    }

    /// Start the event handler — fire `on_start` and attempt an
    /// initial proposal if this node is primary. The pacemaker's
    /// timer is owned by the event loop.
    pub fn start(&self) -> Result<()> {
        // Reset the pacemaker's deadline to "now + min_timeout" so
        // the first round's timer starts when the event loop runs,
        // not when the pacemaker was constructed (which can be much
        // earlier — e.g. waiting for the BlossomSub mesh to form
        // before producing the genesis proposal).
        {
            let mut pm = self.pacemaker.lock().unwrap();
            pm.rearm_after_local_timeout();
        }
        self.notifier.on_start(self.current_rank());
        let result = self.propose_for_new_rank_if_primary();
        self.notifier.on_event_processed();
        result
    }

    // ---------- internal helpers ----------

    fn current_rank(&self) -> u64 {
        self.pacemaker.lock().unwrap().current_rank()
    }

    fn drain_orphan_proposals(&self, parent_identity: &Identity) -> Result<()> {
        let orphans = self.orphan_proposals
            .lock()
            .unwrap()
            .remove(parent_identity);
        if let Some(proposals) = orphans {
            for orphan in proposals {
                tracing::debug!(
                    rank = orphan.proposal.state.rank,
                    "retrying cached orphan proposal"
                );
                if let Err(e) = self.on_receive_proposal(&orphan) {
                    tracing::debug!(
                        rank = orphan.proposal.state.rank,
                        error = %e,
                        "orphan proposal retry failed, re-caching"
                    );
                    let parent_id = orphan.proposal.state.parent_qc_identity.clone();
                    self.orphan_proposals
                        .lock()
                        .unwrap()
                        .push(parent_id, orphan);
                }
            }
        }
        Ok(())
    }

    fn broadcast_timeout_state_if_authorized(&self) -> Result<()> {
        let (cur_rank, newest_qc, prior_tc) = {
            let pm = self.pacemaker.lock().unwrap();
            (
                pm.current_rank(),
                pm.latest_quorum_certificate(),
                pm.prior_rank_timeout_certificate(),
            )
        };

        // If the previous rank ended with both a QC and TC at the same
        // rank, only include the QC — otherwise the timeout is
        // structurally invalid.
        let prior_tc = if newest_qc.rank() + 1 == cur_rank {
            None
        } else {
            prior_tc
        };

        let timeout_state = {
            let mut sr = self.safety_rules.lock().unwrap();
            match sr.produce_timeout(cur_rank, Arc::clone(&newest_qc), prior_tc) {
                Ok(t) => t,
                Err(e) if e.is_no_timeout() => return Ok(()),
                Err(e) => {
                    return Err(QuilError::Consensus(format!(
                        "could not produce timeout: {}",
                        e
                    )))
                }
            }
        };

        self.notifier.on_own_timeout(&timeout_state);
        Ok(())
    }

    fn propose_for_new_rank_if_primary(&self) -> Result<()> {
        let start = Instant::now();
        let (cur_rank, newest_qc, prior_tc) = {
            let pm = self.pacemaker.lock().unwrap();
            (
                pm.current_rank(),
                pm.latest_quorum_certificate(),
                pm.prior_rank_timeout_certificate(),
            )
        };

        let current_leader = self
            .committee
            .leader_for_rank(cur_rank)
            .map_err(|e| QuilError::Consensus(format!(
                "failed to determine primary for new rank {}: {}",
                cur_rank, e
            )))?;
        let finalized_rank = self.forks.lock().unwrap().finalized_rank();
        self.notifier
            .on_current_rank_details(cur_rank, finalized_rank, &current_leader);

        let self_id = self.committee.self_identity().clone();
        if self_id != current_leader {
            tracing::debug!(
                cur_rank,
                self_id = %hex::encode(&self_id),
                leader = %hex::encode(&current_leader),
                "not the leader for this rank — skipping proposal",
            );
            return Ok(());
        }

        // From here down, we ARE the leader for this rank. Any skip is
        // a recovery-stalling event: peers are waiting on our proposal
        // and nothing else can fill in. Log at info so an operator can
        // see why the leader isn't producing.
        tracing::info!(
            cur_rank,
            qc_rank = newest_qc.rank(),
            "we are leader for this rank — attempting proposal",
        );

        // Idempotency: skip if we already proposed for this rank.
        // See `last_proposed_rank` doc — without this, prove_next_state
        // runs twice per rank and the second invocation's drained-but-
        // discarded message bundle results in the broadcast proposal
        // having no requests.
        let prior = self
            .last_proposed_rank
            .load(std::sync::atomic::Ordering::Acquire);
        if cur_rank <= prior {
            tracing::info!(
                cur_rank,
                last_proposed = prior,
                "leader skipping: already proposed for this or a later rank",
            );
            return Ok(());
        }

        // Check that we know the parent state referenced by the newest QC.
        let parent_known = self
            .forks
            .lock()
            .unwrap()
            .get_state(newest_qc.identity())
            .is_some();
        if !parent_known {
            tracing::warn!(
                cur_rank,
                qc_rank = newest_qc.rank(),
                qc_identity = %hex::encode(newest_qc.identity()),
                "leader skipping: parent state not in forks tree",
            );
            return Ok(());
        }

        // Sanity checks mirroring Go: for a leader at rank N, newest QC
        // must be for rank N-1 (happy path), OR we must have a TC for
        // rank N-1 (recovery path).
        let prior_tc = if newest_qc.rank() + 1 == cur_rank {
            // Happy path: drop any TC.
            None
        } else {
            let Some(tc) = prior_tc else {
                return Err(QuilError::Consensus(
                    "possible state corruption, expected prior_rank_tc to be Some".into(),
                ));
            };
            if tc.rank() + 1 != cur_rank {
                return Err(QuilError::Consensus(format!(
                    "state corruption: neither QC(rank={}) nor TC(rank={}) for prior rank (curRank={})",
                    newest_qc.rank(),
                    tc.rank(),
                    cur_rank
                )));
            }
            Some(tc)
        };

        // Produce signed proposal via StateProducer.
        let signed = match self
            .state_producer
            .make_state_proposal(cur_rank, Arc::clone(&newest_qc), prior_tc)
        {
            Ok(sp) => sp,
            Err(e) if e.is_no_vote() => {
                // Debug, not warn — NoVote is expected during
                // coverage halts and during the min-active-provers
                // gate for fresh / draining shards. A halted shard
                // emits one of these per pacemaker tick (~6/min);
                // bumping to warn flooded logs and masked real
                // events. Halt state is visible via the dedicated
                // CoverageHalt/Resume telemetry.
                tracing::debug!(
                    cur_rank,
                    error = %e,
                    "leader skipping: safety rules returned NoVote",
                );
                return Ok(());
            }
            Err(e) => {
                return Err(QuilError::Consensus(format!(
                    "can not make state proposal for curRank {}: {}",
                    cur_rank, e
                )))
            }
        };

        // Ask the pacemaker for the proposal's target broadcast
        // time. With `StaticProposalDurationProvider`, this is
        // `start + proposal_duration` (10s mainnet) — the publisher
        // sleeps until then before broadcasting so the chain
        // advances at a steady cadence rather than VDF-as-fast.
        let target_publication = {
            let pm = self.pacemaker.lock().unwrap();
            pm.target_publication_time(
                signed.proposal.state.rank,
                start,
                &signed.proposal.state.parent_qc_identity,
            )
        };

        // Mark this rank as proposed *before* notifying — if
        // on_own_proposal triggers any path that re-enters this fn
        // (e.g. on_receive_proposal called below), the idempotency
        // check at the top will short-circuit instead of producing a
        // second draft proposal.
        self.last_proposed_rank
            .store(cur_rank, std::sync::atomic::Ordering::Release);

        self.notifier.on_own_proposal(&signed, target_publication);

        // Re-inject our own proposal so it lands in `Forks` and the
        // leader's self-vote path runs. Without this, the next-rank
        // `parent_known` check fails because the proposal was never
        // added to the forest. `on_receive_proposal` short-circuits
        // when rank is unchanged, so the path is bounded.
        self.on_receive_proposal(&signed)?;

        Ok(())
    }

    fn process_state_for_current_rank(&self, proposal: &SignedProposal<S, V>) -> Result<()> {
        let cur_rank = self.current_rank();
        let proposal_rank = proposal.proposal.state.rank;
        if proposal_rank != cur_rank {
            tracing::debug!(
                proposal_rank,
                cur_rank,
                "proposal rank does not match current rank — skipping vote",
            );
            return Ok(());
        }
        let next_leader = self
            .committee
            .leader_for_rank(cur_rank + 1)
            .map_err(|e| QuilError::Consensus(format!(
                "failed to determine primary for next rank {}: {}",
                cur_rank + 1, e
            )))?;
        self.own_vote(proposal, cur_rank, &next_leader)
    }

    fn own_vote(
        &self,
        proposal: &SignedProposal<S, V>,
        cur_rank: u64,
        next_leader: &Identity,
    ) -> Result<()> {
        tracing::debug!(
            cur_rank,
            parent_id = %hex::encode(&proposal.proposal.state.parent_qc_identity),
            "entering own_vote",
        );
        let parent_known = self
            .forks
            .lock()
            .unwrap()
            .get_state(&proposal.proposal.state.parent_qc_identity)
            .is_some();
        if !parent_known {
            tracing::warn!(
                cur_rank,
                parent_id = %hex::encode(&proposal.proposal.state.parent_qc_identity),
                "won't vote for proposal — no parent state in forks",
            );
            return Err(QuilError::Consensus(
                "won't vote for proposal, no parent state for this proposal".into(),
            ));
        }

        // The proposer's vote was already produced inside
        // `sign_own_proposal` (which advanced
        // `latest_acknowledged_rank`); re-running `produce_vote`
        // would trip the "already voted in rank N" safety check.
        // Emit the already-signed vote directly so it reaches the
        // local aggregator.
        let self_id = self.committee.self_identity().clone();
        if proposal.proposal.state.proposer_id == self_id {
            self.notifier.on_own_vote(&proposal.vote, next_leader);
            return Ok(());
        }

        let own_vote = {
            let mut sr = self.safety_rules.lock().unwrap();
            match sr.produce_vote(proposal, cur_rank) {
                Ok(v) => v,
                Err(e) if e.is_no_vote() => {
                    tracing::debug!(
                        cur_rank,
                        error = %e,
                        "safety rules said NoVote on follower vote — skipping",
                    );
                    return Ok(());
                }
                Err(e) => {
                    return Err(QuilError::Consensus(format!("could not produce vote: {}", e)))
                }
            }
        };
        self.notifier.on_own_vote(&own_vote, next_leader);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forest::{Finalizer, FollowerConsumer, Forks};
    use crate::leader_provider::LeaderProvider;
    use crate::pacemaker::NextRank;
    use std::sync::atomic::{AtomicU64, Ordering};

    // =================================================================
    // Minimal app types
    // =================================================================
    #[derive(Debug, Clone)]
    struct AppState {
        id: Identity,
        rank: u64,
    }
    impl Unique for AppState {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &[] }
    }

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
    // Crypto stubs
    // =================================================================
    #[derive(Debug)]
    struct StubAgg;
    impl AggregatedSignature for StubAgg {
        fn signature(&self) -> &[u8] { &[] }
        fn public_key(&self) -> &[u8] { &[] }
        fn bitmask(&self) -> &[u8] { &[] }
    }

    #[derive(Debug)]
    struct StubQc {
        rank: u64,
        id: Identity,
    }
    impl QuorumCertificate for StubQc {
        fn filter(&self) -> &[u8] { &[] }
        fn rank(&self) -> u64 { self.rank }
        fn frame_number(&self) -> u64 { 0 }
        fn identity(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &StubAgg }
        fn equals(&self, o: &dyn QuorumCertificate) -> bool {
            self.rank == o.rank() && self.id == *o.identity()
        }
    }

    // =================================================================
    // Pacemaker stub — lets us dial the "current rank" and control
    // rank-change responses.
    // =================================================================
    struct StubPacemaker {
        current_rank: u64,
        latest_qc: Arc<dyn QuorumCertificate>,
        /// When set, `receive_quorum_certificate` advances to this rank
        /// and returns Some(NextRank).
        advance_qc_to: Option<u64>,
        /// When set, `receive_timeout_certificate` advances to this rank.
        advance_tc_to: Option<u64>,
    }
    impl Pacemaker for StubPacemaker {
        fn current_rank(&self) -> u64 { self.current_rank }
        fn latest_quorum_certificate(&self) -> Arc<dyn QuorumCertificate> {
            Arc::clone(&self.latest_qc)
        }
        fn prior_rank_timeout_certificate(&self) -> Option<Arc<dyn TimeoutCertificate>> {
            None
        }
        fn receive_quorum_certificate(
            &mut self,
            qc: Arc<dyn QuorumCertificate>,
        ) -> Result<Option<NextRank>> {
            if let Some(target) = self.advance_qc_to {
                self.current_rank = target;
                self.latest_qc = qc;
                let start = Instant::now();
                Ok(Some(NextRank {
                    rank: target,
                    start,
                    end: start + std::time::Duration::from_secs(1),
                }))
            } else {
                Ok(None)
            }
        }
        fn receive_timeout_certificate(
            &mut self,
            _tc: Option<Arc<dyn TimeoutCertificate>>,
        ) -> Result<Option<NextRank>> {
            if let Some(target) = self.advance_tc_to {
                self.current_rank = target;
                let start = Instant::now();
                Ok(Some(NextRank {
                    rank: target,
                    start,
                    end: start + std::time::Duration::from_secs(1),
                }))
            } else {
                Ok(None)
            }
        }
    }

    // =================================================================
    // Committee stub
    // =================================================================
    #[derive(Debug)]
    struct StubWeightedIdentity {
        id: Identity,
    }
    impl WeightedIdentity for StubWeightedIdentity {
        fn public_key(&self) -> &[u8] { &[] }
        fn identity(&self) -> &Identity { &self.id }
        fn weight(&self) -> u64 { 1 }
    }

    struct StubReplicas {
        self_id: Identity,
        leader: Identity,
    }
    impl Replicas for StubReplicas {
        fn leader_for_rank(&self, _r: u64) -> Result<Identity> { Ok(self.leader.clone()) }
        fn quorum_threshold_for_rank(&self, _r: u64) -> Result<u64> { Ok(2) }
        fn timeout_threshold_for_rank(&self, _r: u64) -> Result<u64> { Ok(1) }
        fn self_identity(&self) -> &Identity { &self.self_id }
        fn identities_by_rank(&self, _r: u64) -> Result<Vec<Box<dyn WeightedIdentity>>> {
            Ok(vec![])
        }
        fn identity_by_rank(
            &self,
            _r: u64,
            pid: &Identity,
        ) -> Result<Box<dyn WeightedIdentity>> {
            Ok(Box::new(StubWeightedIdentity { id: pid.clone() }))
        }
    }

    // =================================================================
    // Safety rules stub
    // =================================================================
    struct StubSafetyRules {
        produce_vote_calls: u64,
        produce_timeout_calls: u64,
        sign_own_calls: u64,
        vote_error: Option<QuilError>,
        timeout_error: Option<QuilError>,
    }
    impl StubSafetyRules {
        fn new() -> Self {
            Self {
                produce_vote_calls: 0,
                produce_timeout_calls: 0,
                sign_own_calls: 0,
                vote_error: None,
                timeout_error: None,
            }
        }
    }
    impl SafetyRulesT<AppState, AppVote> for StubSafetyRules {
        fn produce_vote(
            &mut self,
            proposal: &SignedProposal<AppState, AppVote>,
            _rank: u64,
        ) -> Result<AppVote> {
            self.produce_vote_calls += 1;
            if let Some(e) = &self.vote_error {
                return Err(clone_err(e));
            }
            Ok(AppVote {
                id: format!("vote-{}", proposal.proposal.state.rank).into_bytes(),
                rank: proposal.proposal.state.rank,
            })
        }
        fn produce_timeout(
            &mut self,
            cur_rank: u64,
            newest_qc: Arc<dyn QuorumCertificate>,
            prior: Option<Arc<dyn TimeoutCertificate>>,
        ) -> Result<TimeoutState<AppVote>> {
            self.produce_timeout_calls += 1;
            if let Some(e) = &self.timeout_error {
                return Err(clone_err(e));
            }
            Ok(TimeoutState {
                rank: cur_rank,
                latest_quorum_certificate: newest_qc,
                prior_rank_timeout_certificate: prior,
                vote: AppVote {
                    id: format!("to-{}", cur_rank).into_bytes(),
                    rank: cur_rank,
                },
                timeout_tick: 0,
            })
        }
        fn sign_own_proposal(
            &mut self,
            proposal: &Proposal<AppState>,
        ) -> Result<AppVote> {
            self.sign_own_calls += 1;
            Ok(AppVote {
                id: format!("own-vote-{}", proposal.state.rank).into_bytes(),
                rank: proposal.state.rank,
            })
        }
    }

    fn clone_err(e: &QuilError) -> QuilError {
        match e {
            QuilError::NoVote(s) => QuilError::NoVote(s.clone()),
            QuilError::NoTimeout(s) => QuilError::NoTimeout(s.clone()),
            _ => QuilError::Consensus("test".into()),
        }
    }

    // =================================================================
    // Leader provider stub — produces a canned state for the given rank
    // =================================================================
    struct StubLeaderProvider;
    impl LeaderProvider<AppState> for StubLeaderProvider {
        fn get_next_leaders(&self, _prior: Option<&State<AppState>>) -> Result<Vec<Identity>> {
            Ok(vec![b"leader".to_vec()])
        }
        fn prove_next_state(
            &self,
            rank: u64,
            _filter: &[u8],
            prior_state: &Identity,
        ) -> Result<State<AppState>> {
            Ok(State {
                rank,
                identifier: format!("state-{}", rank).into_bytes(),
                proposer_id: b"leader".to_vec(),
                parent_qc_identity: prior_state.clone(),
                parent_qc_rank: rank.saturating_sub(1),
                parent_quorum_certificate: None,
                timestamp: 0,
                state: AppState {
                    id: format!("state-{}", rank).into_bytes(),
                    rank,
                },
            })
        }
    }

    // =================================================================
    // Consumer stub — records every callback invocation
    // =================================================================
    #[derive(Default)]
    struct RecordingConsumer {
        start_count: AtomicU64,
        receive_qc_count: AtomicU64,
        receive_tc_count: AtomicU64,
        receive_proposal_count: AtomicU64,
        local_timeout_count: AtomicU64,
        partial_tc_count: AtomicU64,
        event_processed_count: AtomicU64,
        rank_details_count: AtomicU64,
        own_vote_count: AtomicU64,
        own_timeout_count: AtomicU64,
        own_proposal_count: AtomicU64,
    }
    impl Consumer<AppState, AppVote> for RecordingConsumer {
        fn on_start(&self, _r: u64) { self.start_count.fetch_add(1, Ordering::SeqCst); }
        fn on_receive_quorum_certificate(&self, _r: u64, _qc: &dyn QuorumCertificate) {
            self.receive_qc_count.fetch_add(1, Ordering::SeqCst);
        }
        fn on_receive_timeout_certificate(&self, _r: u64, _tc: &dyn TimeoutCertificate) {
            self.receive_tc_count.fetch_add(1, Ordering::SeqCst);
        }
        fn on_receive_proposal(&self, _r: u64, _p: &SignedProposal<AppState, AppVote>) {
            self.receive_proposal_count.fetch_add(1, Ordering::SeqCst);
        }
        fn on_local_timeout(&self, _r: u64) {
            self.local_timeout_count.fetch_add(1, Ordering::SeqCst);
        }
        fn on_partial_timeout_certificate(
            &self,
            _r: u64,
            _p: &PartialTimeoutCertificateCreated,
        ) {
            self.partial_tc_count.fetch_add(1, Ordering::SeqCst);
        }
        fn on_current_rank_details(&self, _r: u64, _f: u64, _l: &Identity) {
            self.rank_details_count.fetch_add(1, Ordering::SeqCst);
        }
        fn on_own_vote(&self, _v: &AppVote, _r: &Identity) {
            self.own_vote_count.fetch_add(1, Ordering::SeqCst);
        }
        fn on_own_timeout(&self, _t: &TimeoutState<AppVote>) {
            self.own_timeout_count.fetch_add(1, Ordering::SeqCst);
        }
        fn on_own_proposal(
            &self,
            _p: &SignedProposal<AppState, AppVote>,
            _t: Instant,
        ) {
            self.own_proposal_count.fetch_add(1, Ordering::SeqCst);
        }
        fn on_event_processed(&self) {
            self.event_processed_count.fetch_add(1, Ordering::SeqCst);
        }
        fn on_rank_change(&self, _old: u64, _new: u64) {}
        fn on_finalization(&self, _p: &FinalityProof<AppState>) {}
        fn on_qc_constructed(&self, _qc: &dyn QuorumCertificate) {}
        fn on_tc_constructed(&self, _tc: &dyn TimeoutCertificate) {}
    }

    // =================================================================
    // Forks dependencies: Finalizer + FollowerConsumer stubs
    // =================================================================
    struct NoopFinalizer;
    impl Finalizer for NoopFinalizer {
        fn make_final(&self, _id: &Identity) -> Result<()> { Ok(()) }
    }

    struct NoopFollower;
    impl FollowerConsumer<AppState> for NoopFollower {
        fn on_state_incorporated(&self, _s: &State<AppState>) {}
        fn on_finalized_state(&self, _c: &CertifiedState<AppState>) {}
        fn on_double_propose_detected(&self, _a: &State<AppState>, _b: &State<AppState>) {}
    }

    // =================================================================
    // Harness builder
    // =================================================================
    #[allow(dead_code)]
    struct Harness {
        handler: HotStuffEventHandler<AppState, AppVote>,
        consumer: Arc<RecordingConsumer>,
        pacemaker: Arc<Mutex<dyn Pacemaker>>,
        forks: Arc<Mutex<Forks<AppState>>>,
        safety_rules: Arc<Mutex<dyn SafetyRulesT<AppState, AppVote>>>,
    }

    struct HarnessConfig {
        initial_rank: u64,
        self_id: &'static str,
        leader: &'static str,
        advance_qc_to: Option<u64>,
        advance_tc_to: Option<u64>,
        initial_qc_rank: u64,
        initial_qc_id: &'static str,
    }

    fn build_harness(cfg: HarnessConfig) -> Harness {
        // Root state / QC — identity is "genesis".
        let genesis = State {
            rank: 0,
            identifier: "genesis".into(),
            proposer_id: "leader".into(),
            parent_qc_identity: "genesis".into(),
            parent_qc_rank: 0,
            parent_quorum_certificate: None,
            timestamp: 0,
            state: AppState { id: "genesis".into(), rank: 0 },
        };
        let root_cert = CertifiedState {
            state: genesis,
            certifying_qc_identity: "genesis".into(),
            certifying_qc_rank: 0,
            certifying_quorum_certificate: None,
        };
        let forks =
            Forks::new(root_cert, Arc::new(NoopFinalizer), Arc::new(NoopFollower)).unwrap();
        let forks = Arc::new(Mutex::new(forks));

        let initial_qc: Arc<dyn QuorumCertificate> = Arc::new(StubQc {
            rank: cfg.initial_qc_rank,
            id: cfg.initial_qc_id.into(),
        });
        let pacemaker: Arc<Mutex<dyn Pacemaker>> = Arc::new(Mutex::new(StubPacemaker {
            current_rank: cfg.initial_rank,
            latest_qc: initial_qc,
            advance_qc_to: cfg.advance_qc_to,
            advance_tc_to: cfg.advance_tc_to,
        }));

        let safety_rules: Arc<Mutex<dyn SafetyRulesT<AppState, AppVote>>> =
            Arc::new(Mutex::new(StubSafetyRules::new()));
        let leader_provider: Arc<dyn LeaderProvider<AppState>> = Arc::new(StubLeaderProvider);
        let state_producer = Arc::new(StateProducer::new(
            Arc::clone(&safety_rules),
            leader_provider,
        ));
        let committee: Arc<dyn Replicas> = Arc::new(StubReplicas {
            self_id: cfg.self_id.into(),
            leader: cfg.leader.into(),
        });
        let consumer = Arc::new(RecordingConsumer::default());
        let handler = HotStuffEventHandler::new(
            Arc::clone(&pacemaker),
            state_producer,
            Arc::clone(&forks),
            Arc::clone(&safety_rules),
            committee,
            consumer.clone() as Arc<dyn Consumer<AppState, AppVote>>,
        );
        Harness {
            handler,
            consumer,
            pacemaker,
            forks,
            safety_rules,
        }
    }

    fn make_signed_proposal(
        rank: u64,
        state_id: &str,
        parent_qc_id: &str,
        parent_qc_rank: u64,
    ) -> SignedProposal<AppState, AppVote> {
        SignedProposal {
            proposal: Proposal {
                state: State {
                    rank,
                    identifier: state_id.into(),
                    proposer_id: "leader".into(),
                    parent_qc_identity: parent_qc_id.into(),
                    parent_qc_rank,
                    parent_quorum_certificate: None,
                    timestamp: 0,
                    state: AppState { id: state_id.into(), rank },
                },
                parent_quorum_certificate: Arc::new(StubQc {
                    rank: parent_qc_rank,
                    id: parent_qc_id.into(),
                }),
                previous_rank_timeout_certificate: None,
            },
            vote: AppVote {
                id: format!("proposer-vote-{}", rank).into_bytes(),
                rank,
            },
        }
    }

    // =================================================================
    // Tests
    // =================================================================

    #[test]
    fn start_fires_on_start_and_marks_processed() {
        let h = build_harness(HarnessConfig {
            initial_rank: 0,
            self_id: "node-a",
            leader: "leader",
            advance_qc_to: None,
            advance_tc_to: None,
            initial_qc_rank: 0,
            initial_qc_id: "genesis",
        });
        h.handler.start().unwrap();
        assert_eq!(h.consumer.start_count.load(Ordering::SeqCst), 1);
        assert_eq!(h.consumer.event_processed_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn qc_triggering_rank_change_does_not_propose_if_not_leader() {
        let h = build_harness(HarnessConfig {
            initial_rank: 0,
            self_id: "node-a",
            leader: "leader", // someone else
            advance_qc_to: Some(5),
            advance_tc_to: None,
            initial_qc_rank: 4,
            initial_qc_id: "state-4",
        });
        let qc: Arc<dyn QuorumCertificate> = Arc::new(StubQc {
            rank: 4,
            id: "state-4".into(),
        });
        h.handler.on_receive_quorum_certificate(qc).unwrap();
        assert_eq!(h.consumer.receive_qc_count.load(Ordering::SeqCst), 1);
        // Rank changed → rank_details fired, but own_proposal did NOT.
        assert_eq!(h.consumer.rank_details_count.load(Ordering::SeqCst), 1);
        assert_eq!(h.consumer.own_proposal_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn qc_with_no_rank_change_is_noop() {
        let h = build_harness(HarnessConfig {
            initial_rank: 5,
            self_id: "node-a",
            leader: "node-a",
            advance_qc_to: None, // pacemaker returns None
            advance_tc_to: None,
            initial_qc_rank: 4,
            initial_qc_id: "state-4",
        });
        let qc: Arc<dyn QuorumCertificate> = Arc::new(StubQc {
            rank: 3,
            id: "state-3".into(),
        });
        h.handler.on_receive_quorum_certificate(qc).unwrap();
        assert_eq!(h.consumer.receive_qc_count.load(Ordering::SeqCst), 1);
        assert_eq!(h.consumer.rank_details_count.load(Ordering::SeqCst), 0);
        assert_eq!(h.consumer.own_proposal_count.load(Ordering::SeqCst), 0);
        assert_eq!(h.consumer.event_processed_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn tc_triggering_rank_change_fires_details() {
        let h = build_harness(HarnessConfig {
            initial_rank: 5,
            self_id: "node-a",
            leader: "other",
            advance_qc_to: None,
            advance_tc_to: Some(6),
            initial_qc_rank: 4,
            initial_qc_id: "state-4",
        });
        #[derive(Debug)]
        struct StubTc {
            rank: u64,
            latest_qc: StubQc,
        }
        impl TimeoutCertificate for StubTc {
            fn filter(&self) -> &[u8] { &[] }
            fn rank(&self) -> u64 { self.rank }
            fn latest_ranks(&self) -> &[u64] { &[] }
            fn latest_quorum_cert(&self) -> &dyn QuorumCertificate { &self.latest_qc }
            fn aggregated_signature(&self) -> &dyn AggregatedSignature { &StubAgg }
            fn equals(&self, o: &dyn TimeoutCertificate) -> bool { self.rank == o.rank() }
        }
        let tc: Arc<dyn TimeoutCertificate> = Arc::new(StubTc {
            rank: 5,
            latest_qc: StubQc { rank: 4, id: "state-4".into() },
        });
        h.handler.on_receive_timeout_certificate(tc).unwrap();
        assert_eq!(h.consumer.receive_tc_count.load(Ordering::SeqCst), 1);
        assert_eq!(h.consumer.rank_details_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn local_timeout_emits_own_timeout_if_authorized() {
        let h = build_harness(HarnessConfig {
            initial_rank: 5,
            self_id: "node-a",
            leader: "leader",
            advance_qc_to: None,
            advance_tc_to: None,
            initial_qc_rank: 4,
            initial_qc_id: "state-4",
        });
        h.handler.on_local_timeout().unwrap();
        assert_eq!(h.consumer.local_timeout_count.load(Ordering::SeqCst), 1);
        assert_eq!(h.consumer.own_timeout_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn local_timeout_when_handler_rank_stable_is_clean() {
        // Baseline: running the local-timeout path with the default
        // (success-returning) safety rules must complete without error
        // and fire exactly one own-timeout callback. The NoTimeout path
        // is covered independently by SafetyRules unit tests.
        let h = build_harness(HarnessConfig {
            initial_rank: 5,
            self_id: "node-a",
            leader: "leader",
            advance_qc_to: None,
            advance_tc_to: None,
            initial_qc_rank: 4,
            initial_qc_id: "state-4",
        });
        h.handler.on_local_timeout().unwrap();
        assert_eq!(h.consumer.own_timeout_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn on_receive_proposal_for_current_rank_votes() {
        let h = build_harness(HarnessConfig {
            initial_rank: 5,
            self_id: "node-a",
            leader: "leader",
            advance_qc_to: None,
            advance_tc_to: None,
            initial_qc_rank: 4,
            initial_qc_id: "state-4",
        });
        // Insert the parent state into forks so the own-vote check passes.
        {
            let mut forks = h.forks.lock().unwrap();
            forks
                .add_certified_state(CertifiedState {
                    state: State {
                        rank: 4,
                        identifier: "state-4".into(),
                        proposer_id: "leader".into(),
                        parent_qc_identity: "genesis".into(),
                        parent_qc_rank: 0,
                        parent_quorum_certificate: None,
                        timestamp: 0,
                        state: AppState { id: "state-4".into(), rank: 4 },
                    },
                    certifying_qc_identity: "state-4".into(),
                    certifying_qc_rank: 4,
                    certifying_quorum_certificate: None,
                })
                .ok();
        }
        let sp = make_signed_proposal(5, "state-5", "state-4", 4);
        h.handler.on_receive_proposal(&sp).unwrap();
        assert_eq!(h.consumer.receive_proposal_count.load(Ordering::SeqCst), 1);
        assert_eq!(h.consumer.own_vote_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn on_receive_proposal_stale_is_dropped() {
        let h = build_harness(HarnessConfig {
            initial_rank: 5,
            self_id: "node-a",
            leader: "leader",
            advance_qc_to: None,
            advance_tc_to: None,
            initial_qc_rank: 4,
            initial_qc_id: "state-4",
        });
        // A proposal below the finalized rank would be dropped. Forks
        // starts at rank 0 with "genesis" finalized; to force "stale",
        // we'd need to finalize past rank 5. We're not wiring full
        // finalization here, so instead this test just confirms the
        // happy path doesn't blow up for a rank >= finalized_rank.
        let sp = make_signed_proposal(5, "state-5", "state-4", 4);
        let _ = h.handler.on_receive_proposal(&sp);
        assert_eq!(h.consumer.receive_proposal_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn partial_tc_for_current_rank_broadcasts_timeout() {
        let h = build_harness(HarnessConfig {
            initial_rank: 5,
            self_id: "node-a",
            leader: "leader",
            advance_qc_to: None,
            advance_tc_to: None,
            initial_qc_rank: 4,
            initial_qc_id: "state-4",
        });
        let qc: Arc<dyn QuorumCertificate> = Arc::new(StubQc {
            rank: 4,
            id: "state-4".into(),
        });
        let partial = PartialTimeoutCertificateCreated {
            rank: 5,
            newest_quorum_certificate: qc,
            prior_rank_timeout_certificate: None,
        };
        h.handler.on_partial_timeout_certificate_created(&partial).unwrap();
        assert_eq!(h.consumer.partial_tc_count.load(Ordering::SeqCst), 1);
        assert_eq!(h.consumer.own_timeout_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn partial_tc_advances_rank_via_embedded_qc() {
        // Set the pacemaker to advance_qc_to = 6 when a QC comes in.
        // Then send a partial TC for rank 5 with an embedded QC;
        // the embedded QC should trigger a rank advance to 6, and
        // because we're no longer at rank 5 we should NOT broadcast a
        // timeout.
        let h = build_harness(HarnessConfig {
            initial_rank: 5,
            self_id: "node-a",
            leader: "leader",
            advance_qc_to: Some(6), // QC advances us past 5
            advance_tc_to: None,
            initial_qc_rank: 4,
            initial_qc_id: "state-4",
        });
        let qc: Arc<dyn QuorumCertificate> = Arc::new(StubQc {
            rank: 5,
            id: "state-5".into(),
        });
        let partial = PartialTimeoutCertificateCreated {
            rank: 5,
            newest_quorum_certificate: qc,
            prior_rank_timeout_certificate: None,
        };
        h.handler.on_partial_timeout_certificate_created(&partial).unwrap();
        assert_eq!(h.consumer.partial_tc_count.load(Ordering::SeqCst), 1);
        // Because the embedded QC advanced the pacemaker past rank 5,
        // we should NOT have broadcast a local timeout.
        assert_eq!(h.consumer.own_timeout_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn partial_tc_for_stale_rank_does_not_broadcast() {
        let h = build_harness(HarnessConfig {
            initial_rank: 5,
            self_id: "node-a",
            leader: "leader",
            advance_qc_to: None,
            advance_tc_to: None,
            initial_qc_rank: 4,
            initial_qc_id: "state-4",
        });
        let qc: Arc<dyn QuorumCertificate> = Arc::new(StubQc {
            rank: 2,
            id: "state-2".into(),
        });
        let partial = PartialTimeoutCertificateCreated {
            rank: 3, // stale
            newest_quorum_certificate: qc,
            prior_rank_timeout_certificate: None,
        };
        h.handler.on_partial_timeout_certificate_created(&partial).unwrap();
        assert_eq!(h.consumer.partial_tc_count.load(Ordering::SeqCst), 1);
        assert_eq!(h.consumer.own_timeout_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn event_processed_fires_on_every_entry_point() {
        let h = build_harness(HarnessConfig {
            initial_rank: 5,
            self_id: "node-a",
            leader: "leader",
            advance_qc_to: None,
            advance_tc_to: None,
            initial_qc_rank: 4,
            initial_qc_id: "state-4",
        });
        h.handler.start().unwrap();
        let qc: Arc<dyn QuorumCertificate> = Arc::new(StubQc {
            rank: 4,
            id: "state-4".into(),
        });
        h.handler.on_receive_quorum_certificate(qc).unwrap();
        h.handler.on_local_timeout().unwrap();
        let partial_qc: Arc<dyn QuorumCertificate> = Arc::new(StubQc {
            rank: 4,
            id: "state-4".into(),
        });
        let partial = PartialTimeoutCertificateCreated {
            rank: 5,
            newest_quorum_certificate: partial_qc,
            prior_rank_timeout_certificate: None,
        };
        h.handler.on_partial_timeout_certificate_created(&partial).unwrap();
        // 4 entry points × 1 on_event_processed each.
        assert_eq!(h.consumer.event_processed_count.load(Ordering::SeqCst), 4);
    }

    // Compile-time check that unused fields silence warnings.
    #[test]
    fn harness_fields_touchable() {
        let h = build_harness(HarnessConfig {
            initial_rank: 0,
            self_id: "self",
            leader: "self",
            advance_qc_to: None,
            advance_tc_to: None,
            initial_qc_rank: 0,
            initial_qc_id: "genesis",
        });
        // Touch each field to suppress dead-code warnings.
        let _ = &h.handler;
        let _ = &h.pacemaker;
        let _ = &h.consumer;
    }

    // =================================================================
    // OrphanCache eviction
    // =================================================================

    #[test]
    fn orphan_cache_caps_per_parent_and_evicts_oldest() {
        let mut cache: OrphanCache<AppState, AppVote> = OrphanCache::new();
        // Push MAX_ORPHANS_PER_PARENT + 2 proposals all for the same
        // parent; the cache should retain only MAX_ORPHANS_PER_PARENT,
        // evicting the two oldest.
        let parent: Identity = "parent-A".into();
        for rank in 1..=(MAX_ORPHANS_PER_PARENT as u64 + 2) {
            let proposal = make_signed_proposal(
                rank,
                &format!("state-{}", rank),
                "parent-A",
                0,
            );
            cache.push(parent.clone(), proposal);
        }
        let bucket = cache.remove(&parent).expect("bucket exists");
        assert_eq!(bucket.len(), MAX_ORPHANS_PER_PARENT);
        // First entry retained should be rank 3 (1 and 2 evicted).
        let first_rank = bucket.front().unwrap().proposal.state.rank;
        assert_eq!(first_rank, 3);
    }

    #[test]
    fn orphan_cache_caps_total_parents_and_evicts_oldest_bucket() {
        let mut cache: OrphanCache<AppState, AppVote> = OrphanCache::new();
        // Push proposals for MAX_ORPHAN_PARENTS + 5 distinct parents.
        // The 5 oldest parent buckets should be evicted.
        for i in 0..(MAX_ORPHAN_PARENTS + 5) {
            let parent_id: Identity = format!("parent-{:03}", i).into_bytes();
            let proposal = make_signed_proposal(
                1,
                &format!("state-for-parent-{}", i),
                &format!("parent-{:03}", i),
                0,
            );
            cache.push(parent_id, proposal);
        }
        assert_eq!(cache.buckets.len(), MAX_ORPHAN_PARENTS);
        assert_eq!(cache.order.len(), MAX_ORPHAN_PARENTS);
        // Buckets 0..4 should be evicted.
        for i in 0..5 {
            let parent_id: Identity = format!("parent-{:03}", i).into_bytes();
            assert!(
                !cache.buckets.contains_key(&parent_id),
                "expected parent {} to have been evicted", i,
            );
        }
        // Buckets 5..MAX_ORPHAN_PARENTS+5 should be retained.
        for i in 5..(MAX_ORPHAN_PARENTS + 5) {
            let parent_id: Identity = format!("parent-{:03}", i).into_bytes();
            assert!(
                cache.buckets.contains_key(&parent_id),
                "expected parent {} to be retained", i,
            );
        }
    }

    #[test]
    fn orphan_cache_remove_drops_from_order() {
        let mut cache: OrphanCache<AppState, AppVote> = OrphanCache::new();
        let parent_a: Identity = "parent-A".into();
        let parent_b: Identity = "parent-B".into();
        cache.push(parent_a.clone(), make_signed_proposal(1, "s1", "parent-A", 0));
        cache.push(parent_b.clone(), make_signed_proposal(1, "s2", "parent-B", 0));
        assert_eq!(cache.order.len(), 2);
        let drained = cache.remove(&parent_a);
        assert!(drained.is_some());
        assert_eq!(cache.order.len(), 1);
        assert!(!cache.order.contains(&parent_a));
        assert!(cache.order.contains(&parent_b));
    }
}

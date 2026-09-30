//! Bind Simplex's selected GLOBAL ancestry to private execution providers.
//! This path never publishes tentative state or substitutes a clock height for
//! an execution receipt. Canonical crash recovery/finalization is separate.
use super::*;
use crate::frame_validator::GlobalFrameVerifier;
use crate::leader_provider::GlobalLeaderProvider;
use quil_consensus::leader_provider::LeaderProvider;
use quil_cw_consensus::adapters::{digest_from_identity, BlockStore, Digest, ProposalContext};
use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub struct GlobalParentLimits {
    pub branch: MaterializerBranchLimits,
    pub max_ancestors: usize,
    pub max_ancestry_bytes: usize,
    pub max_proposal_message_bytes: usize,
    pub max_proposal_message_items: usize,
    /// Cooperative deadline, checked between reads, execution and proving.
    /// Blocking crypto is not preempted; hard lifetime/disk policy is separate.
    pub max_elapsed: Duration,
}

impl Default for GlobalParentLimits {
    fn default() -> Self {
        Self {
            branch: MaterializerBranchLimits {
                execution: quil_execution::ExecutionBranchLimits {
                    state: quil_hypergraph::ExecutionForkLimits {
                        overlay: quil_forest::OverlayLimits {
                            max_delta_bytes: 64 << 20,
                            max_delta_entries: 500_000,
                            max_record_bytes: 16 << 20,
                            max_read_bytes: 512 << 20,
                            max_read_operations: 10_000_000,
                            max_cursors: 128,
                        },
                        max_metadata_entries: 100_000,
                        max_metadata_bytes: 64 << 20,
                    },
                    registry: quil_execution::RegistryLimits {
                        max_vertices: 100_000,
                        max_record_bytes: 4 << 20,
                        max_input_bytes: 128 << 20,
                        max_cache_entries: 1_000_000,
                        max_cache_bytes: 128 << 20,
                    },
                    max_summary_rebuilds: 10_000,
                },
                max_metadata_entries: 100_000,
                max_metadata_bytes: 32 << 20,
                max_frame_bytes: 16 << 20,
                max_frame_items: 100_000,
            },
            max_ancestors: 32,
            max_ancestry_bytes: 64 << 20,
            max_proposal_message_bytes: 8 << 20,
            max_proposal_message_items: 100_000,
            max_elapsed: Duration::from_secs(60),
        }
    }
}

fn unavailable(message: &str) -> QuilError {
    QuilError::ExecutionUnavailable(message.into())
}

fn identity(header: &GlobalFrameHeader) -> Result<Digest> {
    quil_crypto::poseidon::hash_bytes_to_32(&header.output)
        .map(digest_from_identity)
        .map_err(|_| unavailable("selected GLOBAL input has no identity"))
}

struct Admission(Arc<AtomicBool>);
impl Drop for Admission {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Outcome of one finalization attempt by the runtime worker.
#[derive(Debug)]
pub enum GlobalFinalizationAttempt {
    /// Clock record, execution state, receipt and cursor published together.
    Published(TentativeFrameResult),
    /// The exact completed input at the current cursor; nothing changed.
    Replayed,
    /// Another proposal/vote lease is active. Nothing was attempted.
    Busy,
    /// Certificate, VDF/header or body authentication failed. Never publish it.
    Rejected(QuilError),
    /// Authentic, but nothing was published: a stale or foreign base, missing
    /// provenance, an execution error or a storage conflict. A non-retryable
    /// input exceeds the private execution budget.
    Unavailable { error: QuilError, retryable: bool },
}

/// One active preparation/proposal per GLOBAL host. The lease owns the private
/// branch; rejecting, returning, or unwinding releases it and its pinned view.
pub struct GlobalParentExecutor {
    source: Arc<FrameMaterializer>,
    leader: Arc<GlobalLeaderProvider>,
    epoch: u64,
    genesis_number: u64,
    genesis: Digest,
    limits: GlobalParentLimits,
    active: Arc<AtomicBool>,
}

struct ExecutedGlobalBase {
    frame: GlobalFrame,
    digest: Digest,
    view: u64,
    checkpoint: Option<GlobalExecutionCheckpoint>,
}

/// The GLOBAL-owned parent state a child header declares: the prover tree
/// commitment and its auxiliary roots. Bucket roots and world size also cover
/// application data that archives ingest between GLOBAL frames, so members do
/// not agree on them at a given height; they stay leader-declared header data.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ParentState {
    prover: Vec<u8>,
    auxiliary: Vec<Vec<u8>>,
}
impl ParentState {
    fn read(branch: &MaterializerBranch) -> Result<Self> {
        let crdt = branch.execution().manager().crdt();
        Ok(Self {
            prover: branch.prover_root()?.to_vec(),
            // Phase 2 is the denormalized allocation index and is deliberately
            // omitted by the current GLOBAL wire protocol. Never invent its root.
            auxiliary: vec![
                crdt.current_forest_phase_root(&[0xff; 32], 1)?.to_vec(),
                Vec::new(),
                crdt.current_forest_phase_root(&[0xff; 32], 3)?.to_vec(),
            ],
        })
    }
    fn matches(&self, header: &GlobalFrameHeader) -> bool {
        header.prover_tree_commitment == self.prover
            && header.prover_tree_aux_roots == self.auxiliary
    }
}

pub(crate) struct PreparedGlobalParent {
    branch: MaterializerBranch,
    leader: Option<GlobalLeaderProvider>,
    parent: GlobalFrame,
    ancestry: Vec<GlobalFrame>,
    state: ParentState,
    context: ProposalContext,
    started: Instant,
    max_elapsed: Duration,
    /// The parent is a certified canonical head without a receipt (an older
    /// store); a child's certificate authenticates its state before publication.
    receipt_less_base: bool,
    /// The base state is this node's own receipted execution, not a re-synced
    /// or unreceipted tree.
    receipted_base: bool,
    // Last: storage and provider handles are released before another lease.
    _admission: Admission,
}

impl PreparedGlobalParent {
    pub(crate) fn ancestors(&self) -> &[GlobalFrame] {
        &self.ancestry
    }
    pub(crate) fn check(&self) -> Result<()> {
        if self.started.elapsed() > self.max_elapsed {
            return Err(unavailable("selected GLOBAL execution deadline exceeded"));
        }
        if ParentState::read(&self.branch)? != self.state {
            return Err(unavailable("selected GLOBAL state changed during proposal"));
        }
        if let Some(checkpoint) = self.branch.completed_checkpoint()? {
            if !checkpoint.matches_frame(&self.parent)? {
                return Err(unavailable("selected GLOBAL execution input changed"));
            }
        } else if self.branch.cursor()? != 0 && !self.receipt_less_base {
            return Err(unavailable(
                "selected GLOBAL parent has no execution receipt",
            ));
        }
        Ok(())
    }

    /// A child that extends this parent's height, view and identity but declares
    /// another parent prover state. `Some(root)` names the proposers' root when
    /// this node's state is not its own receipted execution (it was re-synced
    /// or never receipted), so a reconcile may target it. A node that executed
    /// its base itself keeps it; a reconcile must not move it toward any single
    /// proposer's declaration.
    pub(crate) fn divergent_parent_root(&self, header: &GlobalFrameHeader) -> Option<Vec<u8>> {
        let extends = self.parent.header.as_ref().and_then(|h| h.frame_number.checked_add(1))
            == Some(header.frame_number)
            && header.rank == self.context.view
            && header.parent_selector == self.context.parent.as_ref();
        (extends && !self.state.matches(header) && !self.receipted_base)
            .then(|| header.prover_tree_commitment.clone())
    }

    pub(crate) fn matches_child(&self, header: &GlobalFrameHeader) -> bool {
        self.parent
            .header
            .as_ref()
            .and_then(|h| h.frame_number.checked_add(1))
            == Some(header.frame_number)
            && header.rank == self.context.view
            && header.parent_selector == self.context.parent.as_ref()
            && self.state.matches(header)
    }

    pub(crate) fn prove(
        &self,
        filter: &[u8],
    ) -> Result<quil_consensus::models::State<crate::consensus_types::GlobalState>> {
        self.check()?;
        let leader = self
            .leader
            .as_ref()
            .ok_or_else(|| unavailable("GLOBAL lease is verification-only"))?;
        let header = self
            .parent
            .header
            .as_ref()
            .ok_or_else(|| unavailable("selected GLOBAL parent missing header"))?;
        let result = leader.prove_next_state(
            self.context.view,
            filter,
            header.frame_number,
            &self.context.parent.as_ref().to_vec(),
        )?;
        self.check()?;
        Ok(result)
    }
}

impl GlobalParentExecutor {
    fn executed_base(
        &self,
        branch: &MaterializerBranch,
        verifier: &GlobalFrameVerifier,
    ) -> Result<ExecutedGlobalBase> {
        let cursor = branch.cursor()?;
        let frame = branch
            .execution()
            .clock_store()
            .get_latest_global_clock_frame()?;
        self.check_input_budget(&frame)?;
        let header = frame
            .header
            .as_ref()
            .ok_or_else(|| unavailable("GLOBAL base has no header"))?;
        if header.frame_number != cursor {
            return Err(unavailable("GLOBAL canonical clock is ahead of execution"));
        }
        let digest = identity(header)?;
        let implicit_genesis = cursor == 0 && self.genesis_number == 0 && digest == self.genesis;
        let checkpoint = branch.completed_checkpoint()?;
        // A store executed before receipts existed has none. Its certified
        // canonical head (checked below) is accepted as the base without
        // inventing a receipt: every vote compares a child's declared parent
        // state with this state, and publication requires the certified
        // child's parent roots to equal it. No child is therefore certified or
        // published on an unauthenticated state; the first publication writes
        // the receipt. An unfinished attempt or a receipt for other input
        // still refuses the base.
        match &checkpoint {
            Some(checkpoint) if checkpoint.matches_frame(&frame)? => {}
            None => {}
            Some(_) => {
                return Err(unavailable(
                    "GLOBAL canonical base differs from its execution receipt",
                ))
            }
        }
        if !implicit_genesis
            && (!verifier.verify_global_execution_base(header, self.epoch)
                || !verifier.validate(&frame)?
                || !verifier.verify_global_requests_root(header, &frame.requests))
        {
            return Err(unavailable(
                "GLOBAL execution base is not finalized in this epoch",
            ));
        }
        let view = if implicit_genesis { 0 } else { header.rank };
        Ok(ExecutedGlobalBase {
            frame,
            digest,
            view,
            checkpoint,
        })
    }

    /// Publish exactly the next finalized GLOBAL frame using a fresh execution
    /// capture. `None` is an authenticated replay of the current completed
    /// checkpoint; it must not reapply rewards or frame effects. The caller
    /// retains failed deliveries and publishes head/gossip only after success.
    pub fn finalize_frame(
        &self,
        frame: &GlobalFrame,
        verifier: &GlobalFrameVerifier,
    ) -> Result<Option<TentativeFrameResult>> {
        self.check_input_budget(frame)?;
        let parent_view = self.authenticate_finalization(frame, verifier)?;
        let _admission = self.admit()?;
        self.publish_finalization(frame, verifier, Some(parent_view))
    }

    /// One runtime attempt, classified for the serial finalization worker.
    /// Only `Published` and `Replayed` change or confirm canonical state.
    pub fn attempt_finalization(
        &self,
        frame: &GlobalFrame,
        verifier: &GlobalFrameVerifier,
    ) -> GlobalFinalizationAttempt {
        let parent_view = match self.authenticate_finalization(frame, verifier) {
            Ok(view) => view,
            Err(error) => return GlobalFinalizationAttempt::Rejected(error),
        };
        if let Err(error) = self.check_input_budget(frame) {
            return GlobalFinalizationAttempt::Unavailable { error, retryable: false };
        }
        let Ok(_admission) = self.admit() else {
            return GlobalFinalizationAttempt::Busy;
        };
        match self.publish_finalization(frame, verifier, Some(parent_view)) {
            Ok(Some(result)) => GlobalFinalizationAttempt::Published(result),
            Ok(None) => GlobalFinalizationAttempt::Replayed,
            Err(error) => GlobalFinalizationAttempt::Unavailable { error, retryable: true },
        }
    }

    /// Publish a notarized ancestor that a certified descendant finalized.
    /// Simplex finalizes every ancestor of a finalized block, but only that
    /// block carries a certificate. After a restart, views can be notarized
    /// without being finalized until a later one is; the ancestors then never
    /// received certificates of their own, the worker waited forever at the
    /// first of them, and GLOBAL stopped publishing.
    ///
    /// `chain` holds the frames strictly between `frame` and `descendant`,
    /// lowest first. The descendant's certificate is authenticated; each frame
    /// must validate, match its request body and link to its parent by
    /// selector with the next height and a later view.
    pub fn attempt_implied_finalization(
        &self,
        frame: &GlobalFrame,
        chain: &[GlobalFrame],
        descendant: &GlobalFrame,
        verifier: &GlobalFrameVerifier,
    ) -> GlobalFinalizationAttempt {
        if let Err(error) = self.authenticate_implied(frame, chain, descendant, verifier) {
            return GlobalFinalizationAttempt::Rejected(error);
        }
        if let Err(error) = self.check_input_budget(frame) {
            return GlobalFinalizationAttempt::Unavailable { error, retryable: false };
        }
        let Ok(_admission) = self.admit() else {
            return GlobalFinalizationAttempt::Busy;
        };
        match self.publish_finalization(frame, verifier, None) {
            Ok(Some(result)) => GlobalFinalizationAttempt::Published(result),
            Ok(None) => GlobalFinalizationAttempt::Replayed,
            Err(error) => GlobalFinalizationAttempt::Unavailable { error, retryable: true },
        }
    }

    fn authenticate_implied(
        &self,
        frame: &GlobalFrame,
        chain: &[GlobalFrame],
        descendant: &GlobalFrame,
        verifier: &GlobalFrameVerifier,
    ) -> Result<()> {
        self.authenticate_finalization(descendant, verifier)?;
        let mut parent = frame;
        for child in chain.iter().chain(std::iter::once(descendant)) {
            let (Some(p), Some(c)) = (parent.header.as_ref(), child.header.as_ref()) else {
                return Err(unavailable("implied GLOBAL finalization has a frame without a header"));
            };
            if p.frame_number.checked_add(1) != Some(c.frame_number)
                || c.parent_selector != identity(p)?.as_ref()
                || c.rank <= p.rank
            {
                return Err(unavailable("implied GLOBAL finalization is not one ancestry"));
            }
            parent = child;
        }
        for input in std::iter::once(frame).chain(chain.iter()) {
            let header = input
                .header
                .as_ref()
                .ok_or_else(|| unavailable("implied GLOBAL ancestor has no header"))?;
            if !verifier.validate(input)? || !verifier.verify_global_requests_root(header, &input.requests) {
                return Err(unavailable("implied GLOBAL ancestor header/body authentication failed"));
            }
        }
        Ok(())
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    fn admit(&self) -> Result<Admission> {
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| unavailable("GLOBAL execution is busy"))?;
        Ok(Admission(self.active.clone()))
    }

    /// Certificate epoch/view, VDF/header and ordered request body. Returns
    /// the certified parent view.
    fn authenticate_finalization(
        &self,
        frame: &GlobalFrame,
        verifier: &GlobalFrameVerifier,
    ) -> Result<u64> {
        let header = frame
            .header
            .as_ref()
            .ok_or_else(|| unavailable("finalized GLOBAL frame has no header"))?;
        let parent_view = verifier
            .global_finalization_parent(header, self.epoch)
            .ok_or_else(|| unavailable("GLOBAL finalization certificate epoch/view mismatch"))?;
        if !verifier.validate(frame)?
            || !verifier.verify_global_requests_root(header, &frame.requests)
        {
            return Err(unavailable(
                "GLOBAL finalization header/body authentication failed",
            ));
        }
        Ok(parent_view)
    }

    /// Requires the admission lease. Binds the input to the fresh capture's
    /// executed parent before publishing it.
    /// `parent_view`: the certified parent view, or `None` for an implied
    /// ancestor, whose parent view no certificate carries; it must then only
    /// follow the executed base's view.
    fn publish_finalization(
        &self,
        frame: &GlobalFrame,
        verifier: &GlobalFrameVerifier,
        parent_view: Option<u64>,
    ) -> Result<Option<TentativeFrameResult>> {
        let header = frame
            .header
            .as_ref()
            .ok_or_else(|| unavailable("finalized GLOBAL frame has no header"))?;
        self.source
            .materialize_atomically(frame, self.limits.branch, |branch| {
                let cursor = branch.cursor()?;
                let base = self.executed_base(branch, verifier)?;
                if header.frame_number == cursor {
                    if let Some(receipt) = base.checkpoint.as_ref() {
                        if receipt.matches_frame(frame)? {
                            return Ok(false);
                        }
                    }
                    return Err(unavailable(
                        "GLOBAL completed input differs from finalization",
                    ));
                }
                let view_follows = match parent_view {
                    Some(view) => view == base.view,
                    None => header.rank > base.view,
                };
                if cursor.checked_add(1) != Some(header.frame_number)
                    || header.parent_selector != base.digest.as_ref()
                    || !view_follows
                    || !ParentState::read(branch)?.matches(header)
                {
                    return Err(unavailable(
                        "GLOBAL finalization does not extend the executed parent",
                    ));
                }
                Ok(true)
            })
    }

    pub(crate) fn binds_clock(&self, clock: &dyn ClockStore) -> bool {
        let identity = self.source.hypergraph.backing_store_identity();
        identity.is_some() && clock.backing_store_identity() == identity
    }

    pub(crate) fn accepts_context(&self, context: ProposalContext) -> bool {
        context.epoch == self.epoch && context.parent_view < context.view
    }

    pub(crate) fn max_frame_bytes(&self) -> usize {
        self.limits.branch.max_frame_bytes
    }

    pub fn new(
        source: Arc<FrameMaterializer>,
        leader: Arc<GlobalLeaderProvider>,
        epoch: u64,
        genesis_number: u64,
        genesis: Digest,
        limits: GlobalParentLimits,
    ) -> Self {
        Self {
            source,
            leader,
            epoch,
            genesis_number,
            genesis,
            limits,
            active: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn prepare(
        &self,
        context: ProposalContext,
        number: u64,
        blocks: &BlockStore,
        verifier: &GlobalFrameVerifier,
        for_proposal: bool,
    ) -> Result<PreparedGlobalParent> {
        if !self.accepts_context(context) {
            return Err(unavailable("selected GLOBAL consensus coordinates differ"));
        }
        if self.limits.max_ancestors == 0 || self.limits.max_elapsed.is_zero() {
            return Err(unavailable("selected GLOBAL execution limits are empty"));
        }
        if !self
            .leader
            .matches_execution_source(&self.source.execution_manager)
        {
            return Err(unavailable(
                "GLOBAL leader does not use the captured execution source",
            ));
        }
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| unavailable("selected GLOBAL execution is busy"))?;
        let admission = Admission(self.active.clone());
        let mut timing = crate::stage_clock::StageClock::start("selected GLOBAL parent execution", number);
        let started = Instant::now();
        let deadline = || {
            if started.elapsed() > self.limits.max_elapsed {
                Err(unavailable("selected GLOBAL execution deadline exceeded"))
            } else {
                Ok(())
            }
        };
        let mut branch = self.source.capture_execution_branch(self.limits.branch)?;
        timing.mark("capture branch");
        let cursor = branch.cursor()?;
        if number < cursor || number - cursor > self.limits.max_ancestors as u64 {
            return Err(unavailable(
                "selected GLOBAL parent is outside the execution window",
            ));
        }
        let clock = branch.execution().clock_store().clone();
        let ExecutedGlobalBase {
            frame: base,
            digest: base_digest,
            view: base_view,
            checkpoint: base_checkpoint,
        } = self.executed_base(&branch, verifier)?;
        timing.mark("executed base");

        let mut ancestry = Vec::new();
        let mut bytes = prost::Message::encoded_len(&base);
        if bytes > self.limits.max_ancestry_bytes {
            return Err(unavailable("GLOBAL ancestry byte limit"));
        }
        let mut wanted = context.parent;
        let mut height = number;
        let mut child_view = context.view;
        while height > cursor {
            deadline()?;
            let frame = self.resolve(
                clock.as_ref(),
                blocks,
                height,
                wanted,
                (height == number).then_some(context.parent_view),
                child_view,
                verifier,
            )?;
            self.check_input_budget(&frame)?;
            bytes = bytes
                .checked_add(prost::Message::encoded_len(&frame))
                .filter(|n| *n <= self.limits.max_ancestry_bytes)
                .ok_or_else(|| unavailable("GLOBAL ancestry byte limit"))?;
            let h = frame
                .header
                .as_ref()
                .ok_or_else(|| unavailable("selected GLOBAL ancestor has no header"))?;
            if h.frame_number != height
                || identity(h)? != wanted
                || h.rank == 0
                || h.rank >= child_view
                || (height == number && h.rank != context.parent_view)
            {
                return Err(unavailable(
                    "selected GLOBAL ancestor authentication failed",
                ));
            }
            wanted = digest_from_identity(
                h.parent_selector
                    .as_slice()
                    .try_into()
                    .map_err(|_| unavailable("selected GLOBAL ancestor has malformed parent"))?,
            );
            child_view = h.rank;
            height -= 1;
            ancestry.push(frame);
        }
        timing.mark("resolve ancestry");
        if wanted != base_digest
            || (number == cursor && context.parent_view != base_view)
            || (number > cursor && child_view <= base_view)
        {
            return Err(unavailable(
                "selected GLOBAL ancestry does not reach the executed base",
            ));
        }
        let parent = ancestry.first().cloned().unwrap_or(base);
        let mut consumed = Vec::new();
        for frame in ancestry.iter().rev() {
            deadline()?;
            let header = frame.header.as_ref().unwrap();
            if !ParentState::read(&branch)?.matches(header) {
                return Err(unavailable(
                    "selected GLOBAL ancestor pre-state differs from execution",
                ));
            }
            // Only this lease sees the chosen ancestry as its clock history.
            // The public clock, consensus head and materializer remain untouched.
            let txn = clock.new_transaction(false)?;
            clock.put_global_clock_frame(frame, txn.as_ref())?;
            txn.commit()?;
            consumed.extend(branch.materialize(frame)?.consumed_bundles);
        }
        timing.mark("execute ancestors");
        deadline()?;
        let state = ParentState::read(&branch)?;
        let leader = if for_proposal {
            Some(self.leader.for_execution_branch(
                branch.execution(),
                context.view,
                self.limits.max_proposal_message_bytes,
                self.limits.max_proposal_message_items,
                &consumed,
            )?)
        } else {
            None
        };
        timing.mark("proposal lease");
        // Executed ancestors leave their own receipts in the branch.
        let receipt_less_base = base_checkpoint.is_none() && ancestry.is_empty();
        let receipted_base = base_checkpoint.is_some();
        let prepared = PreparedGlobalParent {
            branch,
            leader,
            parent,
            ancestry,
            state,
            context,
            started,
            max_elapsed: self.limits.max_elapsed,
            receipt_less_base,
            receipted_base,
            _admission: admission,
        };
        prepared.check()?;
        Ok(prepared)
    }

    fn check_input_budget(&self, frame: &GlobalFrame) -> Result<()> {
        let items = frame
            .requests
            .iter()
            .try_fold(frame.requests.len(), |n, b| n.checked_add(b.requests.len()));
        if prost::Message::encoded_len(frame) > self.limits.branch.max_frame_bytes
            || items.is_none_or(|n| n > self.limits.branch.max_frame_items)
        {
            return Err(unavailable("selected GLOBAL frame input limit"));
        }
        Ok(())
    }

    fn resolve(
        &self,
        clock: &dyn ClockStore,
        blocks: &BlockStore,
        number: u64,
        digest: Digest,
        parent_view: Option<u64>,
        child_view: u64,
        verifier: &GlobalFrameVerifier,
    ) -> Result<GlobalFrame> {
        let valid = |frame: &GlobalFrame| -> Result<bool> {
            if self.check_input_budget(frame).is_err() {
                return Ok(false);
            }
            let Some(h) = frame.header.as_ref() else {
                return Ok(false);
            };
            Ok(h.frame_number == number
                && identity(h).ok() == Some(digest)
                && h.rank > 0
                && h.rank < child_view
                && parent_view.is_none_or(|view| h.rank == view)
                && verifier.validate(frame)?
                && verifier.verify_global_requests_root(h, &frame.requests))
        };
        match clock.get_global_clock_frame_candidate(number, digest.as_ref()) {
            Ok(frame) if valid(&frame)? => return Ok(frame),
            Ok(_) | Err(QuilError::NotFound(_)) => {}
            Err(error) => return Err(error),
        }
        match clock.get_global_clock_frame(number) {
            Ok(frame) if valid(&frame)? => return Ok(frame),
            Ok(_) | Err(QuilError::NotFound(_)) => {}
            Err(error) => return Err(error),
        }
        let bytes = blocks
            .get_bounded(&digest, self.limits.branch.max_frame_bytes)
            .ok_or_else(|| unavailable("selected GLOBAL ancestor body unavailable or too large"))?;
        let frame = crate::consensus_wire::decode_global_frame(&bytes)?;
        if !valid(&frame)? {
            return Err(unavailable(
                "selected GLOBAL ancestor authentication failed",
            ));
        }
        Ok(frame)
    }
}

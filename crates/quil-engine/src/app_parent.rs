//! Private execution of one selected application parent.
//!
//! Simplex may select a parent that is notarized but not finalized, and so not
//! yet materialized anywhere; every later leader must extend it. The canonical
//! engine executes a frame only after finalization, so without this a shard
//! stalls on such a parent. This executes exactly one parent, a validated child
//! of the materialized tip, in a private branch over the member's stores, and
//! lets the leader build and voters check its child against that branch. It
//! never publishes: finalization still executes the parent canonically.
use super::*;
use crate::cw_app_seams::{app_frame_digest, decode_app_frame, AppRequestsRootCheck};
use quil_cw_consensus::adapters::{digest_from_identity, BlockStore, Digest};
use quil_types::proto::global::AppShardFrame;

/// Unfinalized frames above the materialized tip one private execution may
/// cover.
const MAX_PRIVATE_CHAIN: usize = 8;

/// [`AppParentExecutor::extendable`] verdicts kept, by view, parent and
/// materialized height. A leader asks about a few views per turn.
const EXTENDABLE_VERDICTS: usize = 32;

/// A selected parent whose stored ancestry does not reach the materialized
/// tip within [`MAX_PRIVATE_CHAIN`] frames, so no member can build on it, or
/// (judged as a nullified parent) reaches it only at that limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Refused {
    /// The parent's height above the materialized tip.
    depth: u64,
}

/// One validated unfinalized frame: `(digest, frame number, exact bytes)`.
pub(crate) type ChainBody = (Digest, u64, Vec<u8>);

/// Proposal validation (output, committee, storage attestation, structure).
pub(crate) type ProposalValidation = Arc<dyn Fn(&AppShardFrame) -> Result<bool> + Send + Sync>;

/// Pending-message copy bounds for a private leader (as for GLOBAL proposals).
pub(super) const PRIVATE_PARENT_MESSAGE_BYTES: usize = 8 << 20;
pub(super) const PRIVATE_PARENT_MESSAGE_ITEMS: usize = 100_000;

fn unavailable(message: impl Into<String>) -> QuilError {
    QuilError::ExecutionUnavailable(message.into())
}

pub(crate) fn private_branch_limits() -> quil_execution::ExecutionBranchLimits {
    quil_execution::ExecutionBranchLimits {
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
    }
}

/// One executed, unpublished parent. Holding it pins the branch's read view;
/// the executor drops it once canonical materialization passes its base.
pub struct PrivateAppParent {
    pub(crate) frame: AppShardFrame,
    pub(crate) digest: Digest,
    pub(crate) view: u64,
    /// Materialized height the parent extends.
    pub(crate) base: u64,
    /// The parent's height, materialized in the branch.
    pub(crate) frame_number: u64,
    /// Whether each unfinalized frame between the base and the parent (oldest
    /// first) carried no requests: they count toward a session's drain.
    pub(crate) request_free_below: Vec<bool>,
    /// The bodies of the unfinalized frames above the base, the parent last,
    /// each validated as part of the chain: a leader building on them may
    /// re-send them (`AppSeamProposer::resend_parent_bodies`).
    pub(crate) chain_bodies: Vec<ChainBody>,
    pub(crate) clock: Arc<dyn ClockStore>,
    pub(crate) crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    pub(crate) manager: Arc<quil_execution::ExecutionEngineManager>,
    pub(crate) outflows: Arc<FrameOutflows>,
    /// Voter checks of a child against the parent's post-state.
    pub(crate) check: AppRequestsRootCheck,
    _branch: quil_execution::ExecutionBranch,
}

/// The materialized tip a parent must extend.
#[derive(Clone)]
struct Tip {
    cursor: u64,
    digest: [u8; 32],
    view: u64,
}

pub struct AppParentExecutor {
    filter: Vec<u8>,
    app_address: Vec<u8>,
    exec: Arc<quil_execution::ExecutionEngineManager>,
    hypergraph: Arc<quil_hypergraph::HypergraphCrdt>,
    clock: Arc<dyn ClockStore>,
    global_anchor_store: Arc<dyn ClockStore>,
    frame_outflows: Arc<FrameOutflows>,
    inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver>,
    validate: ProposalValidation,
    /// Canonical voter check: the parent must be a valid child of the tip.
    canonical_check: AppRequestsRootCheck,
    /// Canonical materialized height (the engine's mirror).
    materialized: Arc<std::sync::atomic::AtomicU64>,
    leader: Arc<AppLeaderProvider>,
    /// A committee session's virtual genesis: `(base frame, identity)`.
    session_base: Option<(u64, [u8; 32])>,
    blocks: std::sync::OnceLock<BlockStore>,
    // One execution at a time; the result serves the leader and every vote.
    prepared: std::sync::Mutex<Option<Arc<PrivateAppParent>>>,
    /// See [`Self::extendable`].
    verdicts: std::sync::Mutex<std::collections::VecDeque<((u64, Digest, u64), Option<Refused>)>>,
    /// The tip as last read by a proposal or vote; [`Self::extendable`] runs
    /// in the consensus loop and must not wait for the store's commit lock.
    tip_hint: std::sync::Mutex<Option<Tip>>,
    /// The worker this executor serves, for its log lines: they run outside
    /// the worker's span.
    core_id: u32,
}

impl AppParentExecutor {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        filter: Vec<u8>,
        app_address: Vec<u8>,
        exec: Arc<quil_execution::ExecutionEngineManager>,
        hypergraph: Arc<quil_hypergraph::HypergraphCrdt>,
        clock: Arc<dyn ClockStore>,
        global_anchor_store: Arc<dyn ClockStore>,
        frame_outflows: Arc<FrameOutflows>,
        inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver>,
        validate: ProposalValidation,
        canonical_check: AppRequestsRootCheck,
        materialized: Arc<std::sync::atomic::AtomicU64>,
        leader: Arc<AppLeaderProvider>,
        session_base: Option<(u64, [u8; 32])>,
    ) -> Self {
        Self {
            filter,
            app_address,
            exec,
            hypergraph,
            clock,
            global_anchor_store,
            frame_outflows,
            inclusion_prover,
            validate,
            canonical_check,
            materialized,
            leader,
            session_base,
            blocks: std::sync::OnceLock::new(),
            prepared: std::sync::Mutex::new(None),
            verdicts: std::sync::Mutex::new(std::collections::VecDeque::new()),
            tip_hint: std::sync::Mutex::new(None),
            core_id: 0,
        }
    }

    /// Name the worker in this executor's lines ([`Self::core_id`]).
    pub(super) fn for_core(mut self, core_id: u32) -> Self {
        self.core_id = core_id;
        self
    }

    /// The consensus host's body store, where selected parents' bytes arrive.
    pub(crate) fn bind_blocks(&self, blocks: BlockStore) {
        let _ = self.blocks.set(blocks);
    }

    /// Drop any prepared parent: the frame history it extends was discarded.
    pub(crate) fn clear(&self) {
        if let Ok(mut prepared) = self.prepared.lock() {
            *prepared = None;
        }
    }

    /// Release a prepared parent that canonical materialization has reached.
    pub(crate) fn retire_through(&self, materialized: u64) {
        if let Ok(mut prepared) = self.prepared.lock() {
            if prepared.as_ref().is_some_and(|p| p.base < materialized) {
                *prepared = None;
            }
        }
    }

    fn tip(&self) -> Result<Tip> {
        let tip = self.read_tip()?;
        *self.tip_hint.lock().unwrap_or_else(|e| e.into_inner()) = Some(tip.clone());
        Ok(tip)
    }

    fn read_tip(&self) -> Result<Tip> {
        let shard = self.hypergraph.capture_committed_shard(&self.filter)?;
        let recorded = shard
            .records
            .read_record(&quil_store::encoding::consensus_materialized_cursor_key(
                &self.filter,
            ))?
            .map(|bytes| {
                bytes
                    .as_slice()
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| unavailable("malformed materialized cursor"))
            })
            .transpose()?;
        let cursor = recorded.unwrap_or(0);
        if let Some((base, genesis)) = self.session_base {
            if cursor < base {
                return Err(unavailable(
                    "materialized state precedes the session genesis",
                ));
            }
            if cursor == base {
                return Ok(Tip {
                    cursor,
                    digest: genesis,
                    view: 0,
                });
            }
        }
        if cursor == 0 {
            // The implicit genesis extends the zero output.
            return Ok(Tip {
                cursor,
                digest: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32])?,
                view: 0,
            });
        }
        let header = self
            .clock
            .get_shard_clock_frame(&self.filter, cursor, false)?
            .header
            .ok_or_else(|| unavailable("materialized frame has no header"))?;
        if header.frame_number != cursor || header.address != self.filter {
            return Err(unavailable("materialized frame record is inconsistent"));
        }
        Ok(Tip {
            cursor,
            digest: quil_crypto::poseidon::hash_bytes_to_32(&header.output)?,
            view: header.rank,
        })
    }

    /// True when the selected parent is the materialized tip: use the
    /// canonical leader and checks.
    pub(crate) fn is_canonical_parent(&self, parent: Digest) -> Result<bool> {
        Ok(self.tip()?.digest == parent.0)
    }

    /// Whether a leader can build on `parent`, certified at `view` and also
    /// nullified, leaving room for the next leader: false when its stored
    /// ancestry does not reach the materialized tip within [`MAX_PRIVATE_CHAIN`]
    /// frames ([`Self::unfinalized_chain`]), or reaches it only at that limit,
    /// where a child would be the last frame anyone could extend. Judged from
    /// the bodies alone, without execution. Consensus asks this in its loop,
    /// so it reads the tip a proposal or vote last read rather than the store,
    /// and caches definitive verdicts by materialized height. Anything it
    /// cannot judge (no current tip, a missing, undecodable or seal body)
    /// answers true, leaving the leader's choice as it was.
    pub(crate) fn extendable(&self, parent: Digest, view: u64) -> bool {
        self.refusal(parent, view).is_none()
    }

    fn refusal(&self, parent: Digest, view: u64) -> Option<Refused> {
        let height = self.materialized.load(std::sync::atomic::Ordering::SeqCst);
        let key = (view, parent, height);
        let mut verdicts = self.verdicts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, verdict)) = verdicts.iter().find(|(cached, _)| *cached == key) {
            return *verdict;
        }
        let hint = self
            .tip_hint
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        // A tip read at another height than the engine's is stale or ahead.
        let tip = hint.filter(|tip| tip.cursor == height)?;
        let verdict = if tip.digest == parent.0 {
            None
        } else {
            match self.walk_chain(&tip, parent, view) {
                Ok(Ok((chain, _))) if chain.len() >= MAX_PRIVATE_CHAIN => Some(Refused {
                    depth: chain.len() as u64,
                }),
                Ok(Ok(_)) => None,
                Ok(Err(refused)) => Some(refused),
                // A body may still arrive: judge again next time.
                Err(_) => return None,
            }
        };
        if verdicts.len() >= EXTENDABLE_VERDICTS {
            verdicts.pop_front();
        }
        verdicts.push_back((key, verdict));
        verdict
    }

    /// Execute the selected parent privately, or return the prepared result.
    /// The parent and its unfinalized ancestors down to the materialized tip
    /// ([`Self::unfinalized_chain`], at most [`MAX_PRIVATE_CHAIN`] frames)
    /// must link by parent selector, rise in view and pass the proposal
    /// checks: the first against canonical state, each later one against the
    /// private branch its predecessors built.
    pub(crate) fn prepare(
        &self,
        parent: Digest,
        parent_view: u64,
    ) -> Result<Arc<PrivateAppParent>> {
        let mut prepared = self
            .prepared
            .lock()
            .map_err(|_| unavailable("private parent cache poisoned"))?;
        let started = std::time::Instant::now();
        let tip = self.tip()?;
        if let Some(existing) = prepared.as_ref() {
            if existing.digest == parent
                && existing.view == parent_view
                && existing.base == tip.cursor
                && existing._branch.overlay().ensure_readable().is_ok()
            {
                return Ok(existing.clone());
            }
        }
        if tip.digest == parent.0 {
            return Err(unavailable("selected parent is the materialized tip"));
        }
        let first = tip
            .cursor
            .checked_add(1)
            .ok_or_else(|| unavailable("application frame number exhausted"))?;
        // A finalized frame is written to the clock before it executes; its
        // canonical execution is then in progress.
        if self
            .clock
            .get_latest_shard_clock_frame(&self.filter)
            .ok()
            .and_then(|f| f.header)
            .is_some_and(|h| h.frame_number > tip.cursor)
        {
            return Err(unavailable(
                "canonical execution of the next frame is in progress",
            ));
        }
        if self.materialized.load(std::sync::atomic::Ordering::SeqCst) != tip.cursor {
            return Err(unavailable("canonical materialization is changing"));
        }
        // The selected parent and every unfinalized ancestor above the
        // materialized tip, oldest first. A restart can leave several frames
        // notarized but not finalized; executing only a child of the tip, every
        // member abstained from a parent two frames up and the shard stopped
        // (e.g. frames 5403 and 5404 above tip 5402).
        let (chain, chain_bodies) = self.unfinalized_chain(&tip, parent, parent_view)?;
        // Each frame's own checks; its requests root is checked against the
        // state it extends, which for all but the first is the branch below.
        for frame in &chain {
            if !(self.validate)(frame)? {
                return Err(unavailable("selected parent fails proposal validation"));
            }
        }
        if let Err((reason, detail)) = (self.canonical_check)(&chain[0]) {
            return Err(unavailable(format!(
                "selected parent fails proposal validation: {reason} ({detail})"
            )));
        }
        let frame = chain
            .last()
            .expect("a chain holds the selected parent")
            .clone();
        let header = frame
            .header
            .clone()
            .ok_or_else(|| unavailable("selected parent has no header"))?;
        let number = header.frame_number;

        // Drop any stale branch before capturing another, but only now: a
        // proposal on a parent that cannot be executed keeps the one in use.
        *prepared = None;
        let branch = match (
            self.global_anchor_store.backing_store_identity(),
            self.exec.crdt().backing_store_identity(),
        ) {
            (Some(anchor), Some(own)) if anchor == own => self
                .exec
                .capture_execution_branch(private_branch_limits())?,
            _ => self.exec.capture_anchored_execution_branch(
                private_branch_limits(),
                self.global_anchor_store.clone(),
                header.global_frame_number,
            )?,
        };
        let clock: Arc<dyn ClockStore> = branch.clock_store().clone();
        let manager = branch.manager().clone();
        let copy = self
            .frame_outflows
            .lock()
            .map_err(|_| unavailable("frame outflows poisoned"))?
            .clone();
        let outflows: Arc<FrameOutflows> = Arc::new(std::sync::Mutex::new(copy));
        let mut processed = 0;
        for (offset, frame) in chain.iter().enumerate() {
            let header = frame.header.as_ref().expect("checked above");
            let at = first + offset as u64;
            if offset > 0 {
                let check = build_requests_root_check(
                    manager.clone(),
                    self.inclusion_prover.clone(),
                    manager.crdt(),
                    self.app_address.clone(),
                    Arc::new(std::sync::atomic::AtomicU64::new(at - 1)),
                    outflows.clone(),
                    clock.clone(),
                    self.filter.clone(),
                    self.leader.shard_drain.clone(),
                    None,
                );
                if let Err((reason, detail)) = check(frame) {
                    return Err(unavailable(format!(
                        "selected parent fails proposal validation: {reason} ({detail})"
                    )));
                }
            }
            let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output)?.to_vec();
            let txn = clock.new_transaction(false)?;
            clock.stage_shard_clock_frame(&selector, frame, txn.as_ref())?;
            txn.commit()?;
            let txn = clock.new_transaction(false)?;
            clock.commit_shard_clock_frame(&self.filter, at, &selector, txn.as_ref(), false)?;
            txn.commit()?;
            let world_size = certified_world_size(
                self.global_anchor_store.as_ref(),
                header.global_frame_number,
            )?;
            let materialized = materialize_app_shard_requests(
                manager.as_ref(),
                &frame.requests,
                at,
                header.difficulty,
                world_size,
                header.fee_multiplier_vote,
                &self.app_address,
                header.global_frame_number,
            )?;
            processed += materialized.processed;
            let digest = quil_execution::token_intrinsic::accumulator_header::report_digest(
                &materialized.accumulator_report,
            );
            update_outflow(&outflows, at, |outflow| {
                outflow.fee_total = Some(materialized.fee_total);
                outflow.settlements = Some(materialized.settlements);
                outflow.spends = Some(materialized.spends);
                outflow.accumulator = Some(digest);
            });
        }
        let crdt = manager.crdt();
        let check = build_requests_root_check(
            manager.clone(),
            self.inclusion_prover.clone(),
            crdt.clone(),
            self.app_address.clone(),
            Arc::new(std::sync::atomic::AtomicU64::new(number)),
            outflows.clone(),
            clock.clone(),
            self.filter.clone(),
            self.leader.shard_drain.clone(),
            None,
        );
        info!(
            core_id = self.core_id,
            filter = %hex::encode(&self.filter),
            frame = number,
            view = parent_view,
            base = tip.cursor,
            frames = chain.len(),
            processed,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "executed unfinalized selected app parent privately"
        );
        let result = Arc::new(PrivateAppParent {
            frame,
            digest: parent,
            view: parent_view,
            base: tip.cursor,
            frame_number: number,
            request_free_below: chain[..chain.len() - 1]
                .iter()
                .map(|frame| frame.requests.is_empty())
                .collect(),
            chain_bodies,
            clock,
            crdt,
            manager,
            outflows,
            check,
            _branch: branch,
        });
        *prepared = Some(result.clone());
        Ok(result)
    }

    /// A re-seal's checkpoint view names a seal, not necessarily its data
    /// frame. Recover the data view from its body, then use the ordinary
    /// bounded, validated private execution path. Roots are checked by the
    /// handoff automaton against the state this execution actually derives.
    pub(crate) fn prepare_checkpoint(
        &self,
        checkpoint: &quil_cw_consensus::handoff::Checkpoint,
    ) -> Result<Arc<PrivateAppParent>> {
        let digest = digest_from_identity(checkpoint.digest);
        let blocks = self
            .blocks
            .get()
            .ok_or_else(|| unavailable("seal checkpoint body is not available"))?;
        let bytes = blocks
            .get(&digest)
            .ok_or_else(|| unavailable("seal checkpoint body is not available"))?;
        if quil_cw_consensus::handoff::Seal::is_encoding(&bytes) {
            return Err(unavailable("seal checkpoint body is a terminal seal"));
        }
        let frame = decode_app_frame(&bytes)
            .ok_or_else(|| unavailable("seal checkpoint body is not a data frame"))?;
        let header = frame
            .header
            .as_ref()
            .ok_or_else(|| unavailable("seal checkpoint has no header"))?;
        if header.frame_number != checkpoint.frame || app_frame_digest(&frame) != Some(digest) {
            return Err(unavailable(
                "seal checkpoint body differs from its frame or digest",
            ));
        }
        self.prepare(digest, header.rank)
    }

    /// The selected parent and its unfinalized ancestors down to the child of
    /// the materialized tip, oldest first, from the stored bodies. Each frame
    /// names the one below as its parent, numbers rise by one from the tip,
    /// views rise strictly above the tip's, and the selected parent carries the
    /// selected view. At most [`MAX_PRIVATE_CHAIN`] frames, with the bytes
    /// each was decoded from.
    fn unfinalized_chain(
        &self,
        tip: &Tip,
        parent: Digest,
        parent_view: u64,
    ) -> Result<(Vec<AppShardFrame>, Vec<ChainBody>)> {
        self.walk_chain(tip, parent, parent_view)?
            .map_err(|_| unavailable("selected parent does not extend the materialized tip"))
    }

    /// [`Self::unfinalized_chain`], telling the bodies' definitive refusal
    /// apart from what this member cannot read (a missing, undecodable or
    /// seal body).
    fn walk_chain(
        &self,
        tip: &Tip,
        parent: Digest,
        parent_view: u64,
    ) -> Result<std::result::Result<(Vec<AppShardFrame>, Vec<ChainBody>), Refused>> {
        let blocks = self
            .blocks
            .get()
            .ok_or_else(|| unavailable("selected parent body is not available"))?;
        let mut chain: Vec<AppShardFrame> = Vec::new();
        let mut bodies = Vec::new();
        let mut next = parent;
        let mut depth = None;
        loop {
            let bytes = blocks
                .get(&next)
                .ok_or_else(|| unavailable("selected parent body is not available"))?;
            if quil_cw_consensus::handoff::Seal::is_encoding(&bytes) {
                return Err(unavailable("selected parent body is a terminal seal"));
            }
            let frame = decode_app_frame(&bytes)
                .ok_or_else(|| unavailable("undecodable selected parent"))?;
            let header = frame
                .header
                .as_ref()
                .ok_or_else(|| unavailable("selected parent has no header"))?;
            let refused = Refused {
                depth: *depth.get_or_insert(header.frame_number.saturating_sub(tip.cursor)),
            };
            if app_frame_digest(&frame) != Some(next)
                || header.address != self.filter
                || header.rank <= tip.view
            {
                return Ok(Err(refused));
            }
            match chain.last().and_then(|above| above.header.as_ref()) {
                Some(above)
                    if above.frame_number != header.frame_number + 1
                        || above.rank <= header.rank =>
                {
                    return Ok(Err(refused));
                }
                None if header.rank != parent_view => return Ok(Err(refused)),
                _ => {}
            }
            let reaches_tip = header.parent_selector == digest_from_identity(tip.digest).as_ref();
            let (number, selector) = (header.frame_number, header.parent_selector.clone());
            chain.push(frame);
            bodies.push((next, number, bytes));
            if reaches_tip {
                if number != tip.cursor + 1 {
                    return Ok(Err(refused));
                }
                break;
            }
            if chain.len() >= MAX_PRIVATE_CHAIN || number <= tip.cursor + 1 {
                return Ok(Err(refused));
            }
            let Ok(identity) = <[u8; 32]>::try_from(selector.as_slice()) else {
                return Ok(Err(refused));
            };
            next = digest_from_identity(identity);
        }
        chain.reverse();
        bodies.reverse();
        Ok(Ok((chain, bodies)))
    }

    /// The canonical leader rebound to a prepared parent for `rank`.
    pub(crate) fn leader_for(
        &self,
        parent: &PrivateAppParent,
        rank: u64,
    ) -> Result<Arc<dyn quil_consensus::leader_provider::LeaderProvider<AppShardState>>> {
        Ok(Arc::new(self.leader.for_parent(parent, rank)?))
    }
}

/// A leader skips notarized parents that were nullified (they can never
/// finalize) and that no member can extend, for an older certified parent.
impl quil_cw_consensus::engine_host::ParentFallback for AppParentExecutor {
    fn extendable(&self, view: u64, payload: Digest) -> bool {
        AppParentExecutor::extendable(self, payload, view)
    }

    fn fell_back(&self, view: u64, parent: u64, skipped: &[u64]) {
        // The newest skipped parent's height above the tip, as last judged.
        let depth = skipped.first().and_then(|newest| {
            let verdicts = self.verdicts.lock().unwrap_or_else(|e| e.into_inner());
            verdicts
                .iter()
                .rev()
                .find(|((cached, _, _), _)| cached == newest)
                .and_then(|(_, verdict)| verdict.map(|refused| refused.depth))
        });
        info!(
            core_id = self.core_id,
            filter = %hex::encode(&self.filter),
            view,
            parent_view = parent,
            skipped = ?skipped,
            // Views from the parent through the newest skipped one, whose
            // nullifications simplex forwards (a bounded number per turn).
            nullification_gap = skipped.first().map_or(0, |newest| newest.saturating_sub(parent)),
            depth = ?depth,
            max_depth = MAX_PRIVATE_CHAIN,
            materialized = self.materialized.load(std::sync::atomic::Ordering::SeqCst),
            "app leader builds on an older certified parent: newer notarized parents were nullified and lie max_depth or more frames above the materialized tip"
        );
    }
}

#[cfg(test)]
#[path = "app_parent_tests.rs"]
mod tests;

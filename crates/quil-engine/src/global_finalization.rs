//! Serial publication of consensus-finalized GLOBAL frames.
//!
//! The consensus finalizer durably stores each certified body as a candidate
//! and queues it here; it does not write the canonical clock. The single
//! materializer worker publishes the clock record, execution state, receipt
//! and cursor in one batch through [`GlobalParentExecutor`], and only then
//! advances the advertised head, gossips the frame and updates the mempool.
//!
//! An authentic frame that cannot be published atomically — an older store
//! without an execution receipt, a canonical clock already written ahead by
//! sync, an input over the private execution budget, or repeated failures —
//! is written to the canonical clock for the legacy materializer, the
//! previous order of operations. A frame failing authentication is never
//! published; the node then relies on peers' canonical frames.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use quil_types::error::Result;
use quil_types::proto::global::GlobalFrame;
use quil_types::store::ClockStore;

use crate::consensus_wire::encode_global_frame;
use crate::cw_global_seams::HeadHook;
use crate::frame_materializer::{
    GlobalFinalizationAttempt, GlobalParentExecutor, TentativeFrameResult,
};
use crate::frame_validator::GlobalFrameVerifier;

/// Gossip is skipped for a finalized frame whose encoding exceeds this. The
/// p2p `MAX_MESSAGE_SIZE` is 16 MiB; stay under it for framing overhead.
/// Oversized frames fall back to the archive poller.
const MAX_GOSSIP_GLOBAL_FRAME: usize = 15 * 1024 * 1024;

/// Head and gossip effects of a finalized GLOBAL frame.
#[derive(Clone)]
pub struct FinalizedFrameAnnouncer {
    head_hook: HeadHook,
    /// Non-blocking hand-off to the `GLOBAL_FRAME` gossip publisher. `None`
    /// disables gossip (regulars then rely on the RPC poller).
    publisher: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
    /// Only the frame's proposer gossips it, to avoid committee duplicates.
    /// A header's `prover` is the proposer's 32-byte address.
    local_prover_address: Vec<u8>,
}

impl FinalizedFrameAnnouncer {
    pub fn new(
        head_hook: HeadHook,
        publisher: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
        local_prover_address: Vec<u8>,
    ) -> Self {
        Self {
            head_hook,
            publisher,
            local_prover_address,
        }
    }

    /// Call only after the frame is canonical. The published frame carries
    /// its finalization certificate, so receivers can authenticate it.
    pub fn announce(&self, frame: &GlobalFrame) {
        let Some(header) = frame.header.as_ref() else {
            return;
        };
        (self.head_hook)(header.frame_number, header.rank);
        let Some(publish) = self.publisher.as_ref() else {
            return;
        };
        if header.prover.is_empty() || header.prover != self.local_prover_address {
            return;
        }
        match encode_global_frame(frame) {
            Ok(encoded) if encoded.len() <= MAX_GOSSIP_GLOBAL_FRAME => publish(encoded),
            Ok(encoded) => tracing::debug!(
                frame = header.frame_number,
                bytes = encoded.len(),
                "finalized global frame exceeds gossip size — poller fallback"
            ),
            Err(e) => tracing::debug!(error = %e, "encode finalized frame for gossip failed"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GlobalFinalizationLimits {
    /// Certified frames kept in memory. The durable candidate store remains
    /// the source of truth for any frame evicted from this queue.
    pub max_queued: usize,
    /// Consecutive failed attempts at one height before the legacy path.
    pub max_attempts: u32,
    /// First retry delay; it doubles with each counted failure.
    pub retry: Duration,
    /// Heights above the canonical head admitted as durable certified
    /// candidates. Beyond it, frames use the legacy canonical write, so a
    /// stalled worker cannot grow the unresolved-candidate tail without bound;
    /// restart recovery restores the lowest 64. It must exceed the proposal
    /// ancestor bound (32): a finalization can arrive that far above the
    /// canonical head, and writing it directly left a hole below it.
    pub max_ahead: u64,
}

impl Default for GlobalFinalizationLimits {
    fn default() -> Self {
        Self {
            max_queued: 64,
            max_attempts: 3,
            retry: Duration::from_millis(100),
            max_ahead: 64,
        }
    }
}

/// What the worker does after one step at its next height.
#[derive(Debug)]
pub enum FinalizationStep {
    /// No certified frame is waiting at that height.
    Idle,
    /// Published atomically. Run mempool/topology follow-ups, then announce.
    Published {
        frame: GlobalFrame,
        result: TentativeFrameResult,
    },
    /// Written to the canonical clock for the legacy materializer. Announce
    /// it after that materialization succeeds (see [`GlobalFinalizationPipeline::finish_legacy`]).
    Legacy,
    /// Nothing changed; step again after the delay.
    Retry(Duration),
}

#[derive(Default)]
struct State {
    queued: BTreeMap<u64, GlobalFrame>,
    /// Counted failures at one height.
    attempts: Option<(u64, u32)>,
    /// Inputs that failed authentication, by height and VDF output.
    rejected: BTreeSet<(u64, Vec<u8>)>,
}

/// Brings an archive's application state to the point the GLOBAL frame about
/// to execute requires: every shard's frames through the highest one the frame
/// references. `Ok(false)` while a needed application frame is missing.
pub type SequencedIngest = Arc<dyn Fn(&GlobalFrame) -> quil_types::error::Result<bool> + Send + Sync>;

pub struct GlobalFinalizationPipeline {
    executor: Arc<GlobalParentExecutor>,
    verifier: Arc<GlobalFrameVerifier>,
    clock: Arc<dyn ClockStore>,
    announcer: FinalizedFrameAnnouncer,
    limits: GlobalFinalizationLimits,
    state: Mutex<State>,
    sequenced_ingest: Option<SequencedIngest>,
}

impl GlobalFinalizationPipeline {
    pub fn new(
        executor: Arc<GlobalParentExecutor>,
        verifier: Arc<GlobalFrameVerifier>,
        clock: Arc<dyn ClockStore>,
        announcer: FinalizedFrameAnnouncer,
        limits: GlobalFinalizationLimits,
    ) -> Self {
        Self {
            executor,
            verifier,
            clock,
            announcer,
            limits,
            state: Mutex::new(State::default()),
            sequenced_ingest: None,
        }
    }

    /// Run `ingest` on each frame before executing it (archives only).
    pub fn with_sequenced_ingest(mut self, ingest: SequencedIngest) -> Self {
        self.sequenced_ingest = Some(ingest);
        self
    }

    /// Apply the sequenced ingest `frame` requires. False: wait and retry.
    pub fn ingest_before(&self, frame: &GlobalFrame) -> bool {
        let Some(ingest) = self.sequenced_ingest.as_ref() else { return true };
        match ingest(frame) {
            Ok(ready) => ready,
            Err(error) => {
                tracing::warn!(
                    frame = frame.header.as_ref().map_or(0, |h| h.frame_number),
                    %error,
                    "GLOBAL frame waits: its application frames could not be ingested"
                );
                false
            }
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // The state is a cache over durable candidates; no invariant spans a
        // panic, so recover from poisoning instead of halting finalization.
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Queue a certified body the finalizer has already made durable. The
    /// first body at a height is kept. A full queue keeps the lowest heights;
    /// an evicted frame is reloaded from the candidate store when needed.
    pub fn offer(&self, frame: GlobalFrame) -> bool {
        let Some(number) = frame.header.as_ref().map(|h| h.frame_number) else {
            return false;
        };
        let mut state = self.lock();
        if state.queued.contains_key(&number) {
            return true;
        }
        if state.queued.len() >= self.limits.max_queued {
            match state.queued.last_key_value() {
                Some((&highest, _)) if highest > number => {
                    state.queued.remove(&highest);
                }
                _ => return false,
            }
        }
        state.queued.insert(number, frame);
        drop(state);
        self.executor.note_finalized(number);
        true
    }

    /// True when `number` may wait as a durable certified candidate: above the
    /// canonical head and within `max_ahead` of it.
    pub fn admits(&self, number: u64) -> bool {
        let head = match self.clock.get_latest_global_clock_frame() {
            Ok(frame) => frame.header.map_or(0, |h| h.frame_number),
            Err(quil_types::error::QuilError::NotFound(_)) => 0,
            Err(_) => return false,
        };
        number > head && number - head <= self.limits.max_ahead
    }

    /// A validated frame fetched from a peer archive. When it carries this
    /// epoch's finalization certificate and is admitted, keep it as a durable
    /// certified candidate and queue it, so it is published with its execution
    /// state. False: the caller stores it canonically (legacy order).
    pub fn offer_synced(&self, frame: &GlobalFrame) -> bool {
        let Some(header) = frame.header.as_ref() else {
            return false;
        };
        if !self.admits(header.frame_number)
            || self
                .verifier
                .global_finalization_parent(header, self.executor.epoch())
                .is_none()
        {
            return false;
        }
        // The consensus finalizer (or an earlier poll) usually holds this
        // frame already. Rewriting it would record a candidate write under the
        // plan executing it, which read its candidate, and that plan would then
        // fall back. Certificates of one block may differ; either suffices.
        if !self.holds_certified_candidate(frame) {
            if let Err(error) = self
                .clock
                .put_global_clock_frame_candidate(frame, &crate::cw_global_seams::NoopTxn)
            {
                tracing::warn!(frame = header.frame_number, %error, "persist synced GLOBAL candidate failed");
                return false;
            }
        }
        // A full queue reloads this durable candidate at its height.
        self.offer(frame.clone());
        true
    }

    /// Whether the clock already holds `frame`'s body as a certified candidate
    /// under its identity.
    fn holds_certified_candidate(&self, frame: &GlobalFrame) -> bool {
        let Some(header) = frame.header.as_ref() else { return false };
        let Ok(identity) = quil_crypto::poseidon::hash_bytes_to_32(&header.output) else { return false };
        self.clock
            .get_global_clock_frame_candidate(header.frame_number, &identity)
            .is_ok_and(|stored| {
                stored.requests == frame.requests
                    && stored.header.as_ref().is_some_and(|h| {
                        h.frame_number == header.frame_number
                            && h.public_key_signature_bls48581.as_ref().is_some_and(|s| !s.signature.is_empty())
                    })
            })
    }

    /// [`Self::offer_synced`] for a certified frame preceded by the uncertified
    /// ancestors it links down to by parent selector, lowest first: how a peer
    /// serves ancestors Simplex finalized through a descendant, without
    /// certificates of their own. Every ancestor is kept as a durable candidate
    /// (not canonical), so the implied-ancestor path publishes it atomically,
    /// authenticating the chain from the certified frame. False when any link,
    /// the certificate or admission fails; the caller then stores them
    /// canonically as before.
    pub fn offer_synced_chain(&self, chain: &[GlobalFrame]) -> bool {
        let Some((top, ancestors)) = chain.split_last() else { return false };
        if ancestors.is_empty() {
            return self.offer_synced(top);
        }
        let Some(header) = top.header.as_ref() else { return false };
        if !self.admits(header.frame_number)
            || self.verifier.global_finalization_parent(header, self.executor.epoch()).is_none()
        {
            return false;
        }
        let mut child = top;
        for parent in ancestors.iter().rev() {
            let (Some(child_header), Some(parent_header)) = (child.header.as_ref(), parent.header.as_ref()) else {
                return false;
            };
            let links = parent_header.frame_number.checked_add(1) == Some(child_header.frame_number)
                && quil_crypto::poseidon::hash_bytes_to_32(&parent_header.output)
                    .is_ok_and(|identity| identity.as_slice() == child_header.parent_selector.as_slice());
            if !links || !self.admits(parent_header.frame_number) {
                return false;
            }
            child = parent;
        }
        for ancestor in ancestors {
            if let Err(error) = self
                .clock
                .put_global_clock_frame_candidate(ancestor, &crate::cw_global_seams::NoopTxn)
            {
                tracing::warn!(
                    frame = ancestor.header.as_ref().map_or(0, |h| h.frame_number),
                    %error,
                    "persist synced GLOBAL ancestor candidate failed"
                );
                return false;
            }
        }
        self.offer_synced(top)
    }

    /// Forget every height at or below the executed cursor.
    pub fn prune_through(&self, cursor: u64) {
        let mut state = self.lock();
        state.queued.retain(|number, _| *number > cursor);
        state.rejected.retain(|(number, _)| *number > cursor);
        if matches!(state.attempts, Some((number, _)) if number <= cursor) {
            state.attempts = None;
        }
    }

    pub fn queued(&self) -> usize {
        self.lock().queued.len()
    }

    pub fn announce(&self, frame: &GlobalFrame) {
        self.announcer.announce(frame);
    }

    /// The legacy materializer completed `frame`. True when it is the queued
    /// consensus finalization at that height, which the caller then announces.
    pub fn finish_legacy(&self, frame: &GlobalFrame) -> bool {
        let Some(header) = frame.header.as_ref() else {
            return false;
        };
        let mut state = self.lock();
        if matches!(state.attempts, Some((number, _)) if number == header.frame_number) {
            state.attempts = None;
        }
        match state.queued.remove(&header.frame_number) {
            Some(queued) => {
                let same = queued.header.as_ref().map(|h| &h.output) == Some(&header.output);
                if !same {
                    tracing::warn!(
                        frame = header.frame_number,
                        "canonical GLOBAL frame differs from the local finalization"
                    );
                }
                same
            }
            None => false,
        }
    }

    /// Try to publish the certified frame at `next` (the executed cursor + 1).
    /// The caller has already found no canonical clock record at `next`.
    pub fn step(&self, next: u64) -> FinalizationStep {
        let queued = self.lock().queued.get(&next).cloned();
        let (frame, implied) = match queued.or_else(|| self.load_durable(next)) {
            Some(frame) => (frame, None),
            None => match self.implied(next) {
                Some((frame, chain, descendant)) => (frame, Some((chain, descendant))),
                None => return FinalizationStep::Idle,
            },
        };
        // A sync hole below the canonical head cannot use the executed base.
        if let Ok(latest) = self.clock.get_latest_global_clock_frame() {
            if latest.header.is_some_and(|h| h.frame_number >= next) {
                return self.legacy(next, &frame, "canonical clock is ahead of execution");
            }
        }
        if !self.ingest_before(&frame) {
            return FinalizationStep::Retry(self.limits.retry);
        }
        let attempt = match implied.as_ref() {
            None => self.executor.attempt_finalization(&frame, &self.verifier),
            Some((chain, descendant)) => {
                self.executor.attempt_implied_finalization(&frame, chain, descendant, &self.verifier)
            }
        };
        if implied.is_some() && matches!(attempt, GlobalFinalizationAttempt::Published(_)) {
            tracing::info!(frame = next, "GLOBAL ancestor finalized by a certified descendant");
        }
        match attempt {
            GlobalFinalizationAttempt::Published(result) => {
                let mut state = self.lock();
                state.queued.remove(&next);
                state.attempts = None;
                drop(state);
                tracing::info!(
                    frame = next,
                    processed = result.processed,
                    skipped = result.skipped,
                    "GLOBAL frame published atomically"
                );
                FinalizationStep::Published { frame, result }
            }
            GlobalFinalizationAttempt::Replayed => {
                let mut state = self.lock();
                state.queued.remove(&next);
                state.attempts = None;
                FinalizationStep::Idle
            }
            GlobalFinalizationAttempt::Busy => FinalizationStep::Retry(self.limits.retry / 2),
            GlobalFinalizationAttempt::Rejected(error) => {
                tracing::error!(
                    frame = next,
                    %error,
                    "finalized GLOBAL frame failed authentication; not publishing it"
                );
                let output = frame.header.map(|h| h.output).unwrap_or_default();
                let mut state = self.lock();
                state.queued.remove(&next);
                state.rejected.insert((next, output));
                FinalizationStep::Idle
            }
            GlobalFinalizationAttempt::Unavailable {
                error,
                retryable: false,
            } => self.legacy(next, &frame, &error.to_string()),
            GlobalFinalizationAttempt::Unavailable {
                error,
                retryable: true,
            } => {
                let attempts = {
                    let mut state = self.lock();
                    let attempts = match state.attempts {
                        Some((number, n)) if number == next => n.saturating_add(1),
                        _ => 1,
                    };
                    state.attempts = Some((next, attempts));
                    attempts
                };
                if attempts >= self.limits.max_attempts {
                    return self.legacy(next, &frame, &error.to_string());
                }
                tracing::debug!(
                    frame = next,
                    attempts,
                    %error,
                    "atomic GLOBAL finalization unavailable; retrying"
                );
                FinalizationStep::Retry(self.limits.retry.saturating_mul(1 << (attempts - 1).min(8)))
            }
        }
    }

    fn legacy(&self, next: u64, frame: &GlobalFrame, reason: &str) -> FinalizationStep {
        let write = || -> Result<()> {
            let txn = self.clock.new_transaction(false)?;
            self.clock.put_global_clock_frame(frame, txn.as_ref())?;
            txn.commit()
        };
        match write() {
            Ok(()) => {
                tracing::warn!(
                    frame = next,
                    reason,
                    "publishing finalized GLOBAL frame through the legacy materializer"
                );
                FinalizationStep::Legacy
            }
            Err(error) => {
                tracing::warn!(frame = next, %error, "canonical GLOBAL frame write failed");
                FinalizationStep::Retry(self.limits.retry)
            }
        }
    }

    /// The frame at `next` when a certified frame above it finalizes it as an
    /// ancestor: the lowest certified frame above `next` (queued, else durable
    /// within the admission window), walked down to `next` through local
    /// candidates by parent selector. Returns `(frame, frames between, lowest
    /// first, descendant)`. The executor authenticates the whole chain.
    fn implied(&self, next: u64) -> Option<(GlobalFrame, Vec<GlobalFrame>, GlobalFrame)> {
        let queued = self
            .lock()
            .queued
            .range(next.checked_add(1)?..)
            .next()
            .map(|(_, frame)| frame.clone());
        let descendant = queued.or_else(|| {
            let upper = next.saturating_add(self.limits.max_ahead);
            let candidates = self
                .clock
                .range_global_clock_frame_candidates(next + 1, upper, 256)
                .ok()?;
            let rejected = self.lock().rejected.clone();
            candidates
                .into_iter()
                .filter(|frame| {
                    frame.header.as_ref().is_some_and(|h| {
                        h.frame_number > next
                            && !rejected.contains(&(h.frame_number, h.output.clone()))
                            && self
                                .verifier
                                .global_finalization_parent(h, self.executor.epoch())
                                .is_some()
                    })
                })
                .min_by_key(|frame| frame.header.as_ref().map_or(u64::MAX, |h| h.frame_number))
        })?;
        let top = descendant.header.as_ref()?.frame_number;
        let mut chain = Vec::with_capacity((top - next) as usize);
        let mut child = descendant.clone();
        for number in (next..top).rev() {
            let selector = child.header.as_ref()?.parent_selector.clone();
            let parent = self
                .clock
                .get_global_clock_frame_candidate(number, &selector)
                .ok()?;
            if parent.header.as_ref()?.frame_number != number {
                return None;
            }
            chain.push(parent.clone());
            child = parent;
        }
        let frame = chain.pop()?;
        chain.reverse();
        Some((frame, chain, descendant))
    }

    /// A certified candidate the finalizer persisted before a restart or a
    /// queue eviction. Unfinalized (certificate-less) candidates are ignored.
    fn load_durable(&self, next: u64) -> Option<GlobalFrame> {
        let candidates = match self.clock.range_global_clock_frame_candidates(next, next, 8) {
            Ok(candidates) => candidates,
            Err(error) => {
                tracing::debug!(frame = next, %error, "GLOBAL candidate scan failed");
                return None;
            }
        };
        let rejected = self.lock().rejected.clone();
        let frame = candidates.into_iter().find(|frame| {
            frame.header.as_ref().is_some_and(|h| {
                h.frame_number == next
                    && !rejected.contains(&(next, h.output.clone()))
                    && self
                        .verifier
                        .global_finalization_parent(h, self.executor.epoch())
                        .is_some()
            })
        })?;
        self.offer(frame.clone());
        Some(frame)
    }
}

//! Real-state implementations of the commonware-simplex consensus seams for
//! GLOBAL consensus. These bridge `quil-cw-consensus`'s three narrow seam
//! traits to Quilibrium's existing global-chain machinery:
//!
//! - [`GlobalSeamProposer`] (`GlobalProposer`) — `propose` builds the next frame
//! via `LeaderProvider::prove_next_state`; `verify` runs `GlobalFrameVerifier`.
//! - [`GlobalSeamSink`] (`FrameSink`) — ships frame bytes to the committee over
//! the CW `:8340` transport on the dedicated block channel (channel 3).
//! - [`GlobalSeamFinalizer`] (`FrameFinalizer`) — hands finalized frames to
//! execution (atomically via the finalization pipeline when wired), writes a
//! candidate on notarize.
//!
//! The simplex digest is the 32-byte global-frame identity
//! (`Poseidon(header.output)`), so `digest ↔ Identity` is a direct byte map.
//!
//! This module is self-contained and compiles against the real interfaces;
//! the node wires these seams into GLOBAL consensus.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use quil_cw_consensus::adapters::{
    digest_from_identity, digest_to_identity, Digest, FrameFinalizer, FrameSink, GlobalProposer,
    Recipients, ProposalContext,
};
use quil_cw_consensus::falcon_base::FalconPublicKey;

use quil_consensus::leader_provider::LeaderProvider;
use quil_consensus::models::State;
use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader};
use quil_types::store::{ClockStore, Transaction};

use crate::consensus_types::GlobalState;
use crate::consensus_wire::{decode_global_frame, encode_global_frame};
use crate::frame_validator::GlobalFrameVerifier;

/// No-op transaction for the non-batched clock-store writes on the consensus
/// path (mirrors the local `NoTxn` in `archive_sync.rs`).
pub(crate) struct NoopTxn;
impl Transaction for NoopTxn {
    fn get(&self, _: &[u8]) -> quil_types::error::Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn set(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> {
        Ok(())
    }
    fn commit(self: Box<Self>) -> quil_types::error::Result<()> {
        Ok(())
    }
    fn delete(&self, _: &[u8]) -> quil_types::error::Result<()> {
        Ok(())
    }
    fn abort(self: Box<Self>) -> quil_types::error::Result<()> {
        Ok(())
    }
    fn new_iter(
        &self,
        _: &[u8],
        _: &[u8],
    ) -> quil_types::error::Result<Box<dyn quil_types::store::Iterator>> {
        Err(quil_types::error::QuilError::NotFound("noop".into()))
    }
    fn delete_range(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> {
        Ok(())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Rebuild a `GlobalFrame` from a produced/finalized `State<GlobalState>`.
/// Mirrors the finalized-frame rebuild at `archive_sync.rs:1932`.
fn global_frame_from_state(state: &State<GlobalState>) -> GlobalFrame {
    let app = &state.state;
    let header = GlobalFrameHeader {
        frame_number: app.frame_number,
        rank: app.rank,
        timestamp: app.timestamp,
        difficulty: app.difficulty,
        output: app.output.clone(),
        parent_selector: app.parent_selector.clone(),
        prover: app.prover.clone(),
        prover_tree_commitment: app.prover_tree_commitment.clone(),
        global_commitments: app.global_commitments.clone(),
        prover_tree_aux_roots: app.prover_tree_aux_roots.clone(),
        world_state_size: app.world_state_size,
        requests_root: app.requests_root.clone(),
        ..Default::default()
    };
    GlobalFrame {
        header: Some(header),
        requests: app.messages.clone(),
    }
}

/// Frame identity (`Poseidon(output)[..32]`) as the consensus digest.
fn frame_digest(header: &GlobalFrameHeader) -> Option<Digest> {
    let id = quil_crypto::poseidon::hash_bytes_to_32(&header.output).ok()?;
    Some(digest_from_identity(id))
}

// ---------------------------------------------------------------------------
// GlobalProposer
// ---------------------------------------------------------------------------

/// Builds/validates global frames via the existing leader-provider + verifier.
pub struct GlobalSeamProposer {
    leader_provider: Arc<dyn LeaderProvider<GlobalState>>,
    verifier: Arc<GlobalFrameVerifier>,
    filter: Vec<u8>,
    /// digest → frame_number, so `propose` can resolve the parent frame number
    /// from the simplex parent digest (simplex only carries the digest).
    block_meta: Arc<Mutex<HashMap<Digest, u64>>>,
    /// Resolve a parent omitted from the in-memory map after restart. A clock
    /// head is usable only when its identity matches Simplex's selected parent.
    clock_store: Arc<dyn ClockStore>,
    /// A selected parent may arrive from a peer after journal replay. Only
    /// consensus selection authorizes moving such a body into durable recovery.
    block_store: Option<BlockStore>,
    selected_execution: Option<Arc<crate::frame_materializer::GlobalParentExecutor>>,
    /// Invoked when `verify` nullifies a proposal on a prover-tree FORK. Wired to
    /// the frame materializer's `flag_prover_root_mismatch` so a fork detected at
    /// VOTE time — during the resulting halt, when nothing finalizes/materializes
    /// — still sets the mismatch flag the archive prover-tree reconcile gates on.
    /// Without it, the vote-time check halts on the fork but the reconcile never
    /// hears about it → permanent stall. `None` in tests / non-archive nodes.
    on_prover_fork: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
}

impl GlobalSeamProposer {
    pub fn new(
        leader_provider: Arc<dyn LeaderProvider<GlobalState>>,
        verifier: Arc<GlobalFrameVerifier>,
        filter: Vec<u8>,
        clock_store: Arc<dyn ClockStore>,
        on_prover_fork: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
    ) -> Self {
        Self {
            leader_provider,
            verifier,
            filter,
            block_meta: Arc::new(Mutex::new(HashMap::new())),
            clock_store,
            block_store: None,
            selected_execution: None,
            on_prover_fork,
        }
    }

    /// Build peer ingress without capturing the validated parent-height index.
    /// Peer bytes are candidates until consensus verifies them; the digest does
    /// not authenticate a claimed height. Only validated or recovered frames
    /// may populate `block_meta`.
    fn peer_ingress(self: &Arc<Self>, store: BlockStore) -> Arc<dyn Fn(Vec<u8>) + Send + Sync> {
        Arc::new(move |bytes: Vec<u8>| {
            let Ok(frame) = decode_global_frame(&bytes) else {
                tracing::debug!("cw block ingress: undecodable frame, dropping");
                return;
            };
            let Some(header) = frame.header.as_ref() else { return };
            let Some(digest) = frame_digest(header) else { return };
            let frame_number = header.frame_number;
            store.put(digest, bytes);
            tracing::debug!(frame = frame_number, "cw block ingress: stored peer frame");
        })
    }

    /// Record the height of a validated or locally recovered frame.
    pub fn note_frame(&self, digest: Digest, frame_number: u64) {
        self.block_meta.lock().unwrap().insert(digest, frame_number);
    }

    pub fn with_block_store(mut self, store: BlockStore) -> Self {
        self.block_store = Some(store);
        self
    }

    pub fn with_selected_execution(mut self, execution: Arc<crate::frame_materializer::GlobalParentExecutor>) -> Self {
        self.selected_execution = Some(execution);
        self
    }

    fn selected_parent_number(&self, digest: Digest) -> Option<u64> {
        if let Some(number) = self.block_meta.lock().ok()?.get(&digest).copied() { return Some(number); }
        let frame = self.clock_store.get_latest_global_clock_frame().ok()?;
        let header = frame.header.as_ref()?;
        (frame_digest(header) == Some(digest)).then_some(header.frame_number)
    }

    /// The selected parent's recorded timestamp, from whichever local copy
    /// holds it. Not authenticated here: it only sets the pacing wait, which
    /// is capped at one interval and re-checked on the authenticated parent
    /// while proving.
    fn selected_parent_timestamp(&self, digest: Digest, number: u64) -> Option<i64> {
        let recorded = |frame: GlobalFrame| {
            frame
                .header
                .filter(|h| h.frame_number == number && frame_digest(h) == Some(digest))
                .map(|h| h.timestamp)
        };
        if let Some(bytes) = self.block_store.as_ref().and_then(|store| store.get(&digest)) {
            if let Some(timestamp) = decode_global_frame(&bytes).ok().and_then(recorded) {
                return Some(timestamp);
            }
        }
        self.clock_store
            .get_global_clock_frame_candidate(number, digest.as_ref())
            .ok()
            .and_then(recorded)
            .or_else(|| self.clock_store.get_global_clock_frame(number).ok().and_then(recorded))
    }

    fn persist_selected_parent(&self, digest: Digest, number: u64) -> bool {
        let Some(store) = self.block_store.as_ref() else { return true };
        let matches = |frame: &GlobalFrame| frame.header.as_ref()
            .is_some_and(|header| header.frame_number == number && frame_digest(header) == Some(digest));
        if self.clock_store.get_global_clock_frame_candidate(number, digest.as_ref())
            .or_else(|_| self.clock_store.get_global_clock_frame(number))
            .is_ok_and(|frame| matches(&frame)) {
            return true;
        }
        let Some(bytes) = store.get(&digest) else { return false };
        let Ok(frame) = decode_global_frame(&bytes) else { return false };
        if !matches(&frame) || !self.verifier.validate(&frame).unwrap_or(false)
            || !self.verifier.verify_global_requests_root(frame.header.as_ref().unwrap(), &frame.requests) {
            return false;
        }
        self.persist_candidate(&frame)
    }

    /// Restore the canonical tip and all outstanding candidate bodies before
    /// journal replay. Bounds apply to the unresolved tail, never to the full
    /// chain. A tail exceeding the budget refuses activation instead of
    /// silently dropping a parent the journal may have selected.
    pub fn recover_pending(&self, store: &BlockStore) -> quil_types::error::Result<Vec<(u64, Digest, Vec<u8>)>> {
        use quil_types::error::QuilError;
        let head = match self.clock_store.get_latest_global_clock_frame() {
            Ok(frame) => frame,
            Err(QuilError::NotFound(_)) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let height = head.header.as_ref().ok_or_else(|| QuilError::Store("GLOBAL head has no header".into()))?.frame_number;
        // Candidate bodies are a cache: a body not restored here is fetched
        // from or re-advertised by peers, or this member abstains and catches
        // up. A long halt persists a proposal per view; refusing activation
        // over that backlog would remove members from consensus.
        // Restore the lowest heights that fit the budgets and skip the rest.
        let mut frames = Vec::new();
        if let Some(next) = height.checked_add(1) {
            for limit in [65usize, 16, 4, 1] {
                match self.clock_store.range_global_clock_frame_candidates(next, u64::MAX, limit) {
                    Ok(found) => {
                        frames = found;
                        break;
                    }
                    Err(error) => tracing::warn!(limit, %error, "GLOBAL candidate recovery over budget; restoring fewer"),
                }
            }
        }
        if frames.len() > 64 {
            tracing::warn!(found = frames.len(), "GLOBAL recovery restores the lowest 64 unresolved candidates");
            frames.truncate(64);
        }
        let head_digest = frame_digest(head.header.as_ref().ok_or_else(|| QuilError::Store("GLOBAL head has no header".into()))?)
            .ok_or_else(|| QuilError::Store("GLOBAL head has no identity".into()))?;
        if height > 0 {
            match self.verifier.validate(&head) {
                Ok(true) => {}
                Ok(false) => return Err(QuilError::Store(
                    "invalid canonical GLOBAL head: its header or certificate does not verify".into())),
                Err(error) => return Err(QuilError::Store(format!("invalid canonical GLOBAL head: {error}"))),
            }
            if !self.verifier.verify_global_requests_root(head.header.as_ref().unwrap(), &head.requests) {
                return Err(QuilError::Store(
                    "invalid canonical GLOBAL head: its request body does not match its requests root".into()));
            }
        }
        let head_bytes = encode_global_frame(&head)?;
        let mut bytes_used = head_bytes.len();
        self.note_frame(head_digest, height);
        store.put(head_digest, head_bytes);
        let mut recovered = Vec::new();
        for frame in frames {
            let Some(header) = frame.header.as_ref() else { continue };
            let Some(digest) = frame_digest(header) else { continue };
            if !self.verifier.validate(&frame).unwrap_or(false)
                || !self.verifier.verify_global_requests_root(header, &frame.requests)
            {
                tracing::warn!(frame = header.frame_number, "skipping an invalid GLOBAL recovery candidate");
                continue;
            }
            let bytes = encode_global_frame(&frame)?;
            bytes_used = bytes_used.saturating_add(bytes.len());
            if bytes_used > 64 * 1024 * 1024 {
                tracing::warn!(frame = header.frame_number, "GLOBAL recovery byte budget reached; skipping the rest");
                break;
            }
            self.note_frame(digest, header.frame_number);
            // A stored candidate is not evidence of this process validating its
            // pre-state. Keep the unverified flag for the finalization boundary.
            store.put(digest, bytes.clone());
            recovered.push((header.frame_number, digest, bytes));
        }
        Ok(recovered)
    }

    fn persist_candidate(&self, frame: &GlobalFrame) -> bool {
        self.clock_store.put_global_clock_frame_candidate(frame, &NoopTxn)
            .inspect_err(|error| tracing::warn!(%error, "cw global: could not persist proposal body; abstaining"))
            .is_ok()
    }
}

impl GlobalProposer for GlobalSeamProposer {
    fn propose_with_context(&self, context: ProposalContext) -> Option<(Digest, Vec<u8>)> {
        let Some(executor) = self.selected_execution.as_ref() else {
            return self.propose(context.view, context.parent);
        };
        if !executor.accepts_context(context) || !executor.binds_clock(self.clock_store.as_ref()) { return None; }
        let number = self.selected_parent_number(context.parent)?;
        let prepared = match executor.prepare(context, number, self.block_store.as_ref()?, &self.verifier, true) {
            Ok(prepared) => prepared,
            Err(error) => {
                tracing::warn!(view = context.view, parent = number, %error, "selected GLOBAL parent execution unavailable");
                return None;
            }
        };
        let state = prepared.prove(&self.filter)
            .inspect_err(|error| tracing::warn!(view = context.view, %error, "private GLOBAL proposal failed")).ok()?;
        let frame = global_frame_from_state(&state);
        let header = frame.header.as_ref()?;
        let state_matches = prepared.matches_child(header);
        let proof_matches = self.verifier.validate(&frame).ok()?;
        let body_matches = self.verifier.verify_global_requests_root(header, &frame.requests);
        if !state_matches || !proof_matches || !body_matches {
            tracing::warn!(view = context.view, state_matches, proof_matches, body_matches,
                "private GLOBAL proposal does not reproduce selected parent state or valid input");
            return None;
        }
        let digest = frame_digest(header)?;
        let bytes = encode_global_frame(&frame).ok()?;
        if bytes.len() > executor.max_frame_bytes() || prepared.check().is_err() { return None; }
        for ancestor in prepared.ancestors() {
            if !self.persist_candidate(ancestor) { return None; }
        }
        if !self.persist_candidate(&frame) { return None; }
        prepared.check().ok()?;
        self.note_frame(digest, header.frame_number);
        Some((digest, bytes))
    }

    fn verify_with_context(&self, context: ProposalContext, digest: Digest, bytes: Option<Vec<u8>>) -> bool {
        self.verify_or_defer(context, digest, bytes).unwrap_or(false)
    }

    /// Defers only while this node's own execution is busy (publishing the
    /// previous frame, proposing, or checking another proposal). Answering then
    /// nullified valid proposals at once, and a view needs 4 of 5 votes.
    fn verify_or_defer(&self, context: ProposalContext, digest: Digest, bytes: Option<Vec<u8>>) -> Result<bool, std::time::Duration> {
        const DEFER: std::time::Duration = std::time::Duration::from_millis(200);
        let Some(executor) = self.selected_execution.as_ref() else {
            return Ok(self.verify(context.view, context.parent, digest, bytes));
        };
        if !executor.accepts_context(context) || !executor.binds_clock(self.clock_store.as_ref()) { return Ok(false); }
        if executor.busy() { return Err(DEFER); }
        let Some(bytes) = bytes.filter(|b| b.len() <= executor.max_frame_bytes()) else { return Ok(false) };
        let Ok(frame) = decode_global_frame(&bytes) else { return Ok(false) };
        let Some(header) = frame.header.as_ref() else { return Ok(false) };
        if header.rank != context.view || header.parent_selector != context.parent.as_ref()
            || frame_digest(header) != Some(digest) || !self.verifier.validate(&frame).unwrap_or(false)
            || !self.verifier.verify_global_requests_root(header, &frame.requests) { return Ok(false); }
        let Some(number) = self.selected_parent_number(context.parent) else { return Ok(false) };
        let Some(blocks) = self.block_store.as_ref() else { return Ok(false) };
        let prepared = match executor.prepare(context, number, blocks, &self.verifier, false) {
            Ok(prepared) => prepared,
            Err(_) if executor.busy() => return Err(DEFER),
            Err(error) => {
                tracing::warn!(view = context.view, parent = number, %error, "selected GLOBAL verification parent unavailable");
                return Ok(false);
            }
        };
        if !prepared.matches_child(header) {
            // A re-synced or unreceipted member that disagrees with the
            // proposers' parent state routes the fork to the prover-tree
            // reconcile, targeting their root; otherwise it could never vote
            // again (the reconcile would target a stale header root).
            if let Some(declared) = prepared.divergent_parent_root(header) {
                tracing::warn!(view = context.view, frame = header.frame_number,
                    declared = %hex::encode(&declared),
                    "cw verify: unreceipted local prover tree differs from the proposal's parent — reconciling toward it");
                if let Some(cb) = self.on_prover_fork.as_ref() {
                    cb(declared);
                }
            }
            return Ok(false);
        }
        if prepared.check().is_err() { return Ok(false); }
        for ancestor in prepared.ancestors() {
            if !self.persist_candidate(ancestor) { return Ok(false); }
        }
        if !self.persist_candidate(&frame) { return Ok(false); }
        if prepared.check().is_err() { return Ok(false); }
        self.note_frame(digest, header.frame_number);
        Ok(true)
    }

    fn propose_retry(&self) -> Option<std::time::Duration> {
        // Missing parents and materialization lag can clear during this view.
        // Avoid creating journals at network speed while every leader waits.
        Some(std::time::Duration::from_secs(1))
    }

    /// Wait out the leader's interval pacing before preparing: a
    /// selected-parent proposal holds the GLOBAL execution lease from
    /// preparation to proof, and pacing inside it held the lease ~10 s on
    /// every proposal, so the proposer published its parent ~10 s late and
    /// deferred its own votes (2026-10-04).
    fn proposal_pacing(&self, context: ProposalContext) -> Option<std::time::Duration> {
        let number = self.selected_parent_number(context.parent)?;
        let timestamp = self.selected_parent_timestamp(context.parent, number)?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        Some(crate::leader_provider::proposal_pacing_wait(timestamp, now_ms)).filter(|wait| !wait.is_zero())
    }
    fn propose(&self, view: u64, parent_digest: Digest) -> Option<(Digest, Vec<u8>)> {
        if self.selected_execution.is_some() { return None; } // Full context is mandatory.
        // parent digest bytes == prior frame identity (Poseidon(output)).
        let meta_hit = self.block_meta.lock().unwrap().get(&parent_digest).copied();
        let (prior_frame_number, prior_state_id): (u64, Vec<u8>) = match meta_hit {
            Some(n) => (n, digest_to_identity(&parent_digest).to_vec()),
            None => {
                let latest = self.clock_store.get_latest_global_clock_frame().ok()?;
                let header = latest.header.as_ref()?;
                if frame_digest(header) != Some(parent_digest) {
                    tracing::debug!(view, parent = %parent_digest, head = header.frame_number,
                        "cw propose: selected parent differs from the available clock head");
                    return None;
                }
                self.note_frame(parent_digest, header.frame_number);
                (header.frame_number, digest_to_identity(&parent_digest).to_vec())
            }
        };

        if !self.persist_selected_parent(parent_digest, prior_frame_number) {
            tracing::debug!(view, parent = %parent_digest,
                "cw propose: selected parent body is not durably available yet");
            return None;
        }

        let state = match self.leader_provider.prove_next_state(
            view,
            &self.filter,
            prior_frame_number,
            &prior_state_id,
        ) {
            Ok(s) => s,
            Err(e) => {
                // Surface WHY we can't propose — a swallowed error here means the
                // leader silently nullifies its own view, which (across all
                // leaders) stalls global production into a perpetual nullify
                // loop with no on-disk signal. Common causes: "needs sync"
                // (local parent frame identity ≠ the consensus parent) or "not a
                // prover".
                tracing::warn!(
                    view,
                    prior_frame_number,
                    parent = %hex::encode(&prior_state_id),
                    error = %e,
                    "cw propose: prove_next_state failed — cannot build a proposal (view nullifies)"
                );
                return None;
            }
        };

        let frame = global_frame_from_state(&state);
        let header = frame.header.as_ref()?;
        if header.rank != view || header.parent_selector != parent_digest.as_ref() {
            tracing::warn!(view, "cw propose: assembled frame changed the selected view or parent");
            return None;
        }
        let digest = frame_digest(header)?;
        let frame_number = header.frame_number;
        let bytes = encode_global_frame(&frame).ok()?;
        if !self.persist_candidate(&frame) { return None; }

        self.block_meta.lock().unwrap().insert(digest, frame_number);
        Some((digest, bytes))
    }

    fn verify(&self, view: u64, parent: Digest, digest: Digest, bytes: Option<Vec<u8>>) -> bool {
        if self.selected_execution.is_some() { return false; }
        let Some(bytes) = bytes else {
            // Block not yet delivered — nullify rather than vote blind.
            tracing::warn!(view, "cw verify: block not delivered (nullify)");
            return false;
        };
        let Ok(frame) = decode_global_frame(&bytes) else {
            tracing::warn!(view, "cw verify: undecodable block (nullify)");
            return false;
        };
        let Some(header) = frame.header.as_ref() else {
            return false;
        };
        if header.rank != view || header.parent_selector != parent.as_ref() {
            tracing::warn!(view, rank = header.rank, "cw verify: view or parent mismatch (nullify)");
            return false;
        }
        // The digest must bind to this frame's identity.
        if frame_digest(header) != Some(digest) {
            tracing::warn!(view, frame = header.frame_number, "cw verify: digest mismatch (nullify)");
            return false;
        }
        // Structural + VDF/BLS validation.
        match self.verifier.validate(&frame) {
            Ok(true) => {
                // BIND THE BODY TO THE HEADER. The digest commits only
                // `header.output` (which binds `requests_root` via the VDF
                // challenge) — NOT the carried `frame.requests`. Two frames with
                // the same header but different bodies share one digest, and the
                // channel-3 BlockStore is overwrite + re-read at verify/finalize/
                // broadcast time, so without this an attacker submits a valid
                // header + tampered body under the agreed digest → the committee
                // materializes a body inconsistent with the certified
                // `requests_root` (state divergence / halt). Recompute + reject on
                // mismatch, mirroring the app-shard seam (`app_engine`) and the
                // gossip receive path.
                if !self.verifier.verify_global_requests_root(header, &frame.requests) {
                    tracing::warn!(
                        view,
                        frame = header.frame_number,
                        "cw verify: request body does not match certified requests_root (nullify)"
                    );
                    return false;
                }
                // VERIFY THE PROVER ROOT AGAINST LOCAL STATE BEFORE SIGNING. The
                // prover_tree_commitment is a deterministic function of committed
                // state through N-1 — which a valid voter has already materialized —
                // so reproducing it is a cheap local read. FAIL CLOSED: nullify if it
                // differs (a genuine prover-tree FORK) OR if we can't reproduce it yet
                // (not materialized to N-1). Previously the seam only checked the
                // leader's proof was self-consistent with the leader's OWN declared
                // root, so a divergent leader's frame finalized and every follower
                // reconcile-stormed forever. Nullifying makes a fork HALT (no quorum
                // forms) and paces production to materialization. Genesis (frame ≤ 1)
                // is deterministic/degenerate — skip.
                let n = header.frame_number;
                if n > 1 {
                    match self.leader_provider.local_prover_root(n) {
                        Some(local) if local == header.prover_tree_commitment => {}
                        Some(local) => {
                            tracing::warn!(
                                view,
                                frame = n,
                                local = %hex::encode(&local),
                                declared = %hex::encode(&header.prover_tree_commitment),
                                "cw verify: prover_tree_commitment != local computation \
                                 (prover-tree FORK) — nullify"
                            );
                            // Route this vote-time fork detection to the archive
                            // prover-tree reconcile: no frame will materialize during
                            // the halt to set the mismatch flag the reconcile gates
                            // on, so set it here. This is what makes the halt
                            // self-healing (fork → flag → reconcile → converge →
                            // unhalt) instead of a permanent stall.
                            if let Some(cb) = self.on_prover_fork.as_ref() {
                                // Pass the DECLARED root (the proposers' lineage) so
                                // the archive reconcile targets it — a forked outlier
                                // must converge to the proposers, not to its own
                                // finalized root (which no peer holds).
                                cb(header.prover_tree_commitment.clone());
                            }
                            return false;
                        }
                        None => {
                            tracing::warn!(
                                view,
                                frame = n,
                                "cw verify: cannot reproduce prover root — parent (N-1) not \
                                 materialized locally (lag) — nullify",
                            );
                            return false;
                        }
                    }
                    // The certified world-state size every venue prices from
                    // must equal the size this voter recorded at N-1. Fail
                    // closed exactly like the prover root.
                    match self.leader_provider.local_world_state_size(n) {
                        Some(local) if local == header.world_state_size => {}
                        other => {
                            tracing::warn!(
                                view,
                                frame = n,
                                local = ?other,
                                declared = header.world_state_size,
                                "cw verify: world_state_size != local recorded size at N-1 — nullify"
                            );
                            return false;
                        }
                    }
                }
                if !self.persist_candidate(&frame) { return false; }
                self.block_meta.lock().unwrap().insert(digest, header.frame_number);
                tracing::debug!(view, frame = header.frame_number, "cw verify: OK (vote)");
                true
            }
            other => {
                tracing::warn!(view, frame = header.frame_number, result = ?other, "cw verify: validate failed (nullify)");
                false
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FrameSink
// ---------------------------------------------------------------------------

/// simplex channel id reserved for out-of-band block (frame-bytes) delivery.
/// Distinct from the engine's three channels (0=vote, 1=cert, 2=resolver); the
/// node's inbound router feeds channel-3 payloads into the [`BlockStore`] rather
/// than the engine.
pub const CW_BLOCK_CHANNEL: u64 = 3;

/// Ships frame bytes to the committee over the CW `:8340` transport on the
/// dedicated block channel. The peer's inbound router demuxes channel 3 into its
/// `BlockStore` so `verify` can find the block behind a proposed digest.
pub struct GlobalSeamSink {
    transport: Arc<dyn GlobalConsensusTransport>,
    peers: Arc<[FalconPublicKey]>,
}

impl GlobalSeamSink {
    pub fn new(transport: Arc<dyn GlobalConsensusTransport>, peers: Arc<[FalconPublicKey]>) -> Self {
        Self { transport, peers }
    }
}

impl FrameSink for GlobalSeamSink {
    fn broadcast(&self, _digest: Digest, bytes: Vec<u8>, recipients: Recipients<FalconPublicKey>) {
        // Expand recipients; the transport fans out to the whole committee
        // regardless, so `All` and a forward-subset both deliver safely.
        let to: Vec<FalconPublicKey> = match recipients {
            Recipients::All => self.peers.to_vec(),
            Recipients::Some(r) => r,
            Recipients::One(r) => vec![r],
        };
        self.transport.deliver(CW_BLOCK_CHANNEL, to, bytes);
    }
}

// ---------------------------------------------------------------------------
// FrameFinalizer
// ---------------------------------------------------------------------------

/// Hook the node supplies to bump head atomics / `CurrentFrame` when a frame
/// finalizes (so PeerInfo advertises the real head, catch-up starts from the
/// right point, and status reflects progress). Called with `(frame_number, rank)`.
pub type HeadHook = Arc<dyn Fn(u64, u64) + Send + Sync>;

/// Hands finalized frames to execution; writes candidates on notarize.
pub struct GlobalSeamFinalizer {
    clock_store: Arc<dyn ClockStore>,
    /// Hand finalized frames to the node's existing global-materializer worker
    /// (which commits the CRDT/prover tree, verifies the root, evicts, marks
    /// bundles consumed, and drives split/merge rebalance). Reuses the exact
    /// same `(frame, frame_number)` channel the quil-consensus path fed, so no
    /// materialize logic is duplicated. Materialize MUST run off the consensus
    /// task — a slow commit must not stall the engine.
    mat_job_tx: tokio::sync::mpsc::UnboundedSender<(GlobalFrame, u64)>,
    /// Head atomics / CurrentFrame and proposer-only gossip. With a pipeline,
    /// the worker announces only after the frame is published.
    announcer: crate::global_finalization::FinalizedFrameAnnouncer,
    /// Atomic mode: keep the certified body as a durable candidate and queue
    /// it; the worker publishes clock and execution state together.
    pipeline: Option<Arc<crate::global_finalization::GlobalFinalizationPipeline>>,
}

impl GlobalSeamFinalizer {
    pub fn new(
        clock_store: Arc<dyn ClockStore>,
        mat_job_tx: tokio::sync::mpsc::UnboundedSender<(GlobalFrame, u64)>,
        head_hook: HeadHook,
        global_frame_publisher: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
        local_prover_address: Vec<u8>,
    ) -> Self {
        Self {
            clock_store,
            mat_job_tx,
            announcer: crate::global_finalization::FinalizedFrameAnnouncer::new(
                head_hook,
                global_frame_publisher,
                local_prover_address,
            ),
            pipeline: None,
        }
    }

    pub fn with_pipeline(
        mut self,
        pipeline: Option<Arc<crate::global_finalization::GlobalFinalizationPipeline>>,
    ) -> Self {
        self.pipeline = pipeline;
        self
    }
}

impl FrameFinalizer for GlobalSeamFinalizer {
    fn on_notarized(&self, view: u64, digest: Digest, bytes: Option<Vec<u8>>) {
        // Write the notarized (uncommitted) frame as a candidate so a later
        // `propose` can build on this tip before it finalizes (the leader
        // provider resolves the parent from committed-or-candidate).
        let Some(bytes) = bytes else { return };
        let Ok(frame) = decode_global_frame(&bytes) else { return };
        let Some(header) = frame.header.as_ref() else { return };
        if header.rank != view || frame_digest(header) != Some(digest)
            || !crate::frame_validator::global_frame_body_matches_requests_root(header, &frame.requests)
        {
            tracing::warn!(view, "cw notarize: frame differs from reported proposal");
            return;
        }
        if let Err(e) = self
            .clock_store
            .put_global_clock_frame_candidate(&frame, &NoopTxn)
        {
            tracing::warn!(error = %e, "put candidate frame failed");
        }
    }

    fn on_finalized(
        &self,
        view: u64,
        digest: Digest,
        bytes: Option<Vec<u8>>,
        cert: Option<Vec<u8>>,
        _locally_verified: bool,
    ) {
        // Certificate-only replicas may not have locally verified these bytes,
        // so retain the context-free body re-bind check below at the persistence
        // boundary regardless of `_locally_verified`.
        let Some(bytes) = bytes else {
            tracing::warn!(view, "cw finalize: finalized block body not held locally; relying on peers");
            return;
        };
        let Ok(mut frame) = decode_global_frame(&bytes) else {
            tracing::warn!(view, "cw finalize: finalized block body does not decode");
            return;
        };
        let Some(header) = frame.header.as_ref() else { return };
        if header.rank != view || frame_digest(header) != Some(digest) {
            tracing::warn!(view, "cw finalize: frame differs from finalized proposal");
            return;
        }
        // Re-bind the body to the header at FINALIZE, not just at verify. The
        // block bytes are re-read from the shared (overwrite-able) BlockStore by
        // digest, so a body swapped in AFTER this node voted would otherwise be
        // materialized. Recompute the requests root and drop on mismatch — the
        // "post-verification body swap" guard the app-shard seam also has.
        if let Some(h) = frame.header.as_ref() {
            if !crate::frame_validator::global_frame_body_matches_requests_root(h, &frame.requests) {
                tracing::warn!(
                    frame = h.frame_number,
                    "cw finalize: request body does not match certified requests_root — dropping"
                );
                return;
            }
        }
        // Attach the simplex FINALIZATION cert to the frame header so followers
        // can verify this CW-finalized global frame against the fixed global
        // committee (genesis archives) rather than trusting VDF + the archive
        // source alone. Rides in the sig field's `signature` bytes with the CWCT
        // magic; `GlobalFrameVerifier` (poller path) detects + verifies it. The
        // cert isn't needed for coverage (the archives ARE the committee), but
        // delivering it makes synced global frames self-verifying.
        if let Some(cert) = cert.filter(|c| !c.is_empty()) {
            if let Some(h) = frame.header.as_mut() {
                h.public_key_signature_bls48581 =
                    Some(quil_types::proto::keys::Bls48581AggregateSignature {
                        public_key: Some(quil_types::proto::keys::Bls48581g2PublicKey {
                            key_value: Vec::new(),
                        }),
                        signature: quil_cw_consensus::app_cert::wrap_cert_for_header(&cert),
                        bitmask: Vec::new(),
                    });
            }
        }
        let frame_number = match frame.header.as_ref() {
            Some(h) => h.frame_number,
            None => return,
        };
        // Beyond the admission window (a stalled worker), keep the legacy
        // order so the unresolved-candidate tail stays bounded for restarts.
        if let Some(pipeline) = self.pipeline.as_ref().filter(|p| p.admits(frame_number)) {
            // The certified body survives a restart as a candidate. The
            // canonical clock, head and gossip wait for atomic publication.
            // A failed durable write still queues it: publication is atomic,
            // and only restart recovery depends on the candidate.
            if let Err(e) = self
                .clock_store
                .put_global_clock_frame_candidate(&frame, &NoopTxn)
            {
                tracing::warn!(error = %e, frame = frame_number, "persist finalized candidate failed");
            }
            pipeline.offer(frame.clone());
            let _ = self.mat_job_tx.send((frame, frame_number));
            return;
        }
        // A journal replay after a restart finalizes again the frames the
        // canonical clock already holds (every restart re-finalized the head).
        // Rewriting and re-announcing them is redundant. A different frame at
        // that height means the canonical record diverged from consensus; the
        // certified frame replaces it, loudly.
        if let Ok(stored) = self.clock_store.get_global_clock_frame(frame_number) {
            let identity = |frame: &GlobalFrame| {
                frame.header.as_ref().and_then(|h| quil_crypto::poseidon::hash_bytes_to_32(&h.output).ok())
            };
            if identity(&stored).is_some() && identity(&stored) == identity(&frame) {
                tracing::debug!(frame = frame_number, view, "finalized GLOBAL frame is already canonical (journal replay)");
                let _ = self.mat_job_tx.send((frame, frame_number));
                return;
            }
            tracing::error!(frame = frame_number, view,
                "finalized GLOBAL frame differs from the canonical record at its height; replacing the record");
        } else if self.pipeline.is_some() {
            tracing::warn!(frame = frame_number, view,
                "finalized GLOBAL frame beyond the admission window: writing it canonically");
        }
        // Durable commit, bump head atomics and gossip (proposer only), then
        // hand off to the materialize worker (non-blocking send; the worker
        // materializes in finalize order).
        if let Err(e) = self.clock_store.put_global_clock_frame(&frame, &NoopTxn) {
            tracing::warn!(error = %e, "put finalized frame failed");
            return;
        }
        self.announcer.announce(&frame);
        let _ = self.mat_job_tx.send((frame, frame_number));
    }
}

#[cfg(test)]
#[path = "cw_global_finalizer_tests.rs"]
mod finalizer_tests;

// ---------------------------------------------------------------------------
// Live activation orchestration. Assembles the simplex-backed global
// consensus from real dependencies and exposes the minimal contract the node
// must satisfy (implement `GlobalConsensusTransport`, feed inbound RPC into the
// returned `inbound` senders).
// ---------------------------------------------------------------------------

use quil_cw_consensus::adapters::BlockStore;
use quil_cw_consensus::engine_host::{spawn_global_host, GlobalEngineParams};
use quil_cw_consensus::falcon_simplex::SimplexFalconScheme;

/// Carries simplex's consensus channel messages over the node's `:8340`
/// transport. The node implements this (over `DirectGlobalConsensusPublisher`),
/// tagging `channel` so the receiving peer can demux back to the right channel.
pub trait GlobalConsensusTransport: Send + Sync + 'static {
    /// Deliver a simplex message on `channel` (0=vote, 1=certificate,
    /// 2=resolver) to `recipients` over `:8340`.
    fn deliver(&self, channel: u64, recipients: Vec<FalconPublicKey>, bytes: Vec<u8>);
}

/// The node's handle to the running simplex-backed global consensus. On each
/// inbound `:8340` message the node demuxes the channel id:
/// - channels 0/1/2 (vote/cert/resolver) → `inbound[channel].send(...)`;
/// - channel 3 (block) → `ingest_block(bytes)` (feeds the shared `BlockStore`).
pub struct GlobalConsensusCwHandle {
    pub inbound: [tokio::sync::mpsc::UnboundedSender<quil_cw_consensus::p2p_bridge::Message<FalconPublicKey>>; 3],
    /// Feed a peer-delivered frame's canonical bytes into the engine's
    /// `BlockStore` (so `verify` finds the block behind a proposed digest) and
    /// leave its parent-height metadata untouched. Drops malformed bytes.
    pub ingest_block: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
}

/// Assemble + start the simplex-backed global consensus from real dependencies.
/// Must be called from within the node's tokio runtime (spawns the outbound
/// drain task there); the engine itself runs on its own runtime thread.
///
/// `mat_job_tx` is the node's existing global-materializer channel (reused so
/// finalized frames run through the same commit/evict/rebalance worker). The
/// block bytes are shipped by the sink over the CW transport (channel 3); the
/// node must route inbound channel-3 payloads back into `ingest_block`.
#[allow(clippy::too_many_arguments)]
pub fn activate_global_consensus_cw(
    scheme: SimplexFalconScheme,
    peers: Arc<[FalconPublicKey]>,
    leader_provider: Arc<dyn LeaderProvider<GlobalState>>,
    verifier: Arc<GlobalFrameVerifier>,
    clock_store: Arc<dyn ClockStore>,
    mat_job_tx: tokio::sync::mpsc::UnboundedSender<(GlobalFrame, u64)>,
    head_hook: HeadHook,
    filter: Vec<u8>,
    epoch: u64,
    genesis_digest: quil_cw_consensus::adapters::Digest,
    genesis_frame_number: u64,
    leader_timeout_secs: u64,
    transport: Arc<dyn GlobalConsensusTransport>,
    // Persistent simplex-journal directory (see `spawn_global_host`). A stable
    // path under the node's data dir so consensus resumes across restarts
    // instead of replaying from the migration head.
    storage_directory: std::path::PathBuf,
    // GOSSIP publisher for finalized global frames (proposer-only), + this node's
    // prover address for the proposer gate. `None` publisher disables gossip
    // dissemination (regulars then rely on the RPC poller).
    global_frame_publisher: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
    local_prover_address: Vec<u8>,
    // Called from the vote seam's `verify` when it nullifies on a prover-tree
    // FORK — wired to the materializer's `flag_prover_root_mismatch` so the
    // archive reconcile fires during the halt. `None` disables (tests/regulars).
    on_prover_fork: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
    selected_execution: Arc<crate::frame_materializer::GlobalParentExecutor>,
    // Atomic finalization: the finalizer queues certified bodies for the
    // materializer worker instead of writing the canonical clock first.
    pipeline: Option<Arc<crate::global_finalization::GlobalFinalizationPipeline>>,
) -> quil_types::error::Result<GlobalConsensusCwHandle> {
    // Shared block store: `propose` inserts our own frame; the node inserts
    // peer-delivered frames via `ingest_block`; `verify`/`Relay`/`Reporter`
    // read it.
    let store = BlockStore::new();

    // Seams over real state. The proposer keeps a clock-store handle so it can
    // recover the parent frame number from the latest committed head when the
    // in-memory block map misses it after a restart.
    let proposer = GlobalSeamProposer::new(
        leader_provider,
        verifier,
        filter,
        clock_store.clone(),
        on_prover_fork,
    ).with_block_store(store.clone()).with_selected_execution(selected_execution);
    let proposer = Arc::new(proposer);
    // Seed the parent map so the FIRST proposal resolves the genesis parent's
    // frame number (block_meta is otherwise empty → prior_frame_number 0).
    proposer.note_frame(genesis_digest, genesis_frame_number);
    let sink = Arc::new(GlobalSeamSink::new(transport.clone(), peers.clone()));
    let mut recovered = proposer.recover_pending(&store)?;
    tracing::info!(candidates = recovered.len(), "restored GLOBAL consensus bodies before journal replay");
    let finalizer = Arc::new(
        GlobalSeamFinalizer::new(
            clock_store.clone(),
            mat_job_tx,
            head_hook,
            global_frame_publisher,
            local_prover_address,
        )
        .with_pipeline(pipeline),
    );

    // Rebuild a failed host only after it joins. The transport routes, fixed
    // committee, body store and on-disk journal survive every replacement.
    let inbound = crate::cw_host_supervisor::supervise_global_host({
        let proposer = proposer.clone();
        let sink = sink.clone();
        let store = store.clone();
        move |shutdown| spawn_global_host(
            scheme.clone(),
            peers.clone(),
            proposer.clone(),
            sink.clone(),
            finalizer.clone(),
            store.clone(),
            GlobalEngineParams::new("global", epoch, genesis_digest)
                .with_leader_timeout_secs(leader_timeout_secs),
            Some(storage_directory.clone()),
            Some(shutdown),
        )
    }, transport);

    // Another member may have stopped after voting but before keeping the old
    // candidate. Re-advertise this bounded recovered tail until finalized. The
    // receiver still authenticates it against the consensus-selected digest.
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(8));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut index = 0usize;
        while !recovered.is_empty() {
            tick.tick().await;
            if let Ok(head) = clock_store.get_latest_global_clock_frame() {
                if let Some(header) = head.header {
                    recovered.retain(|(number, _, _)| *number > header.frame_number);
                }
            }
            if recovered.is_empty() { break; }
            index %= recovered.len();
            let (_, digest, bytes) = &recovered[index];
            sink.broadcast(*digest, bytes.clone(), Recipients::All);
            index += 1;
        }
    });

    // Peer ingress can store candidates, but cannot change trusted heights.
    let ingest_block = proposer.peer_ingress(store.clone());

    Ok(GlobalConsensusCwHandle { inbound, ingest_block })
}

#[cfg(test)]
mod ingress_tests {
    use super::*;

    struct NoProposal;
    impl LeaderProvider<GlobalState> for NoProposal {
        fn get_next_leaders(&self, _: Option<&State<GlobalState>>) -> quil_types::error::Result<Vec<Vec<u8>>> {
            unreachable!()
        }
        fn prove_next_state(&self, _: u64, _: &[u8], _: u64, _: &Vec<u8>) -> quil_types::error::Result<State<GlobalState>> {
            unreachable!()
        }
    }

    #[test]
    fn peer_ingress_preserves_validated_parent_height() {
        let proposer = Arc::new(GlobalSeamProposer::new(
            Arc::new(NoProposal),
            Arc::new(GlobalFrameVerifier::new(Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)))),
            vec![], Arc::new(quil_store::testing::InMemoryClockStore::new()), None,
        ));
        let store = BlockStore::new();
        let ingress = proposer.peer_ingress(store.clone());
        let mut frame = GlobalFrame { header: Some(GlobalFrameHeader {
            frame_number: 7, output: vec![3; 516], ..Default::default()
        }), ..Default::default() };
        let digest = frame_digest(frame.header.as_ref().unwrap()).unwrap();
        let honest = encode_global_frame(&frame).unwrap();
        proposer.note_frame(digest, 7);
        ingress(honest.clone());
        assert_eq!(store.get(&digest), Some(honest.clone()));
        frame.header.as_mut().unwrap().frame_number = u64::MAX / 2;
        assert_eq!(frame_digest(frame.header.as_ref().unwrap()), Some(digest));
        let forged = encode_global_frame(&frame).unwrap();
        ingress(forged.clone());
        assert_eq!(store.get(&digest), Some(forged.clone()));
        assert_eq!(proposer.selected_parent_number(digest), Some(7));
        store.seal(digest, honest.clone());
        ingress(forged);
        assert_eq!(store.get(&digest), Some(honest));
        ingress(vec![0xff]);
        assert_eq!(proposer.selected_parent_number(digest), Some(7));
        frame.header.as_mut().unwrap().output = vec![4; 516];
        let unknown = frame_digest(frame.header.as_ref().unwrap()).unwrap();
        ingress(encode_global_frame(&frame).unwrap());
        assert_eq!(proposer.selected_parent_number(unknown), None);
    }
}

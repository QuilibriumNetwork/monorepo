//! Global chain leader provider. Port of
//! `node/consensus/global/consensus_leader_provider.go`.
//!
//! Selects leaders from the prover registry and produces new global
//! frames when this node is the elected leader.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use quil_consensus::leader_provider::LeaderProvider;
use quil_consensus::models::{Identity, State};
use quil_types::consensus::{DifficultyAdjuster, ProverRegistry};
use quil_types::crypto::{FrameProver, InclusionProver, Signer};
use quil_types::error::{QuilError, Result};
use quil_types::store::ClockStore;

use crate::committee::address_to_identity;
use crate::consensus_types::GlobalState;
use crate::message_collector::MessageCollector;

/// Expected length of a valid VDF output (258-byte Y + 258-byte proof).
const VDF_OUTPUT_LEN: usize = 516;

/// Global chain leader provider. Selects leaders based on the prover
/// registry's ordered prover list, seeded by the parent frame's
/// `parent_selector`. Produces frames by collecting messages, computing
/// VDF proofs, and assembling GlobalFrameHeaders.
pub struct GlobalLeaderProvider {
    prover_registry: Arc<dyn ProverRegistry>,
    frame_prover: Arc<dyn FrameProver>,
    difficulty_adjuster: Arc<dyn DifficultyAdjuster>,
    clock_store: Arc<dyn ClockStore>,
    message_collector: Arc<MessageCollector>,
    /// This node's prover address (32-byte Poseidon hash of BLS pubkey).
    local_prover_address: Vec<u8>,
    /// This node's BLS48-581 public key (585 bytes).
    local_public_key: Vec<u8>,
    /// BLS48-581 signer used by `ProveGlobalFrameHeader` to sign the
    /// (challenge || output) payload under the "global" domain. Mirrors
    /// Go's `provingKey qcrypto.Signer` parameter at
    /// `vdf/wesolowski_frame_prover.go:402`.
    signer: Arc<dyn Signer>,
    /// KZG-style inclusion prover used to commit the request tree.
    /// Mirrors Go's `p.engine.inclusionProver` at
    /// `consensus_leader_provider.go:307`. The explicit `+ Send + Sync`
    /// bound is required because `VectorCommitmentTree::commit` walks
    /// branches in parallel via rayon.
    inclusion_prover: Arc<dyn InclusionProver + Send + Sync>,
    /// Execution manager used to validate collected messages before they
    /// ride into a proposal. Mirrors Go's
    /// `executionManager.ValidateMessage` gate in the liveness provider's
    /// collect loop (`consensus_liveness_provider.go:86-97`): a message
    /// that fails validation is dropped from the mempool
    /// (`MessageCollector::remove`) instead of being re-collected and
    /// re-proposed every rank until it ages out. `None` disables the gate
    /// (tests / nodes without an execution manager wired).
    message_validator: Option<Arc<quil_execution::ExecutionEngineManager>>,
    /// Hypergraph CRDT used to compute the `prover_tree_commitment` the
    /// leader binds into the frame header (and the VDF challenge) at
    /// proving time. Mirrors Go's `rebuildShardCommitments`, which commits
    /// the CRDT and reads the global prover shard's (`L1=[0;3]`,
    /// `L2=[0xff;32]`) phase-0 root — the state-through-parent commitment
    /// every follower re-derives and cross-checks in the materializer
    /// (`verify_prover_root`), POMW mint, prover-kick verification, and
    /// state-jump sync anchoring. `None` (unit tests without a store)
    /// leaves the commitment empty, which those consumers tolerate.
    hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
}

impl GlobalLeaderProvider {
    pub fn new(
        prover_registry: Arc<dyn ProverRegistry>,
        frame_prover: Arc<dyn FrameProver>,
        difficulty_adjuster: Arc<dyn DifficultyAdjuster>,
        clock_store: Arc<dyn ClockStore>,
        message_collector: Arc<MessageCollector>,
        local_prover_address: Vec<u8>,
        local_public_key: Vec<u8>,
        signer: Arc<dyn Signer>,
        inclusion_prover: Arc<dyn InclusionProver + Send + Sync>,
        message_validator: Option<Arc<quil_execution::ExecutionEngineManager>>,
        hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
    ) -> Self {
        Self {
            prover_registry,
            frame_prover,
            difficulty_adjuster,
            clock_store,
            message_collector,
            local_prover_address,
            local_public_key,
            signer,
            inclusion_prover,
            message_validator,
            hypergraph,
        }
    }

    /// Compute the `prover_tree_commitment` for the frame being proved:
    /// the global prover shard's (`L1=[0;3]`, `L2=[0xff;32]`) vertex-adds
    /// forest root over the CURRENT committed state (which, at proposal
    /// time, reflects the parent frame — the last one materialized on
    /// finalization).
    ///
    /// Reads the LIVE forest root via `compute_shard_root`, whose doc
    /// contract is "the same value `commit_inner` puts in the header."
    /// This deliberately does NOT go through `commit(frame_number)`: at
    /// proposal time nothing is staged for the new frame and no root is
    /// persisted at that frame number yet, so `commit()` (union of
    /// pending + per-frame cached commits) would return an EMPTY set for
    /// the global shard. The forest read is the authoritative
    /// point-in-time root.
    ///
    /// Returns empty only when no CRDT is wired (unit tests) or the shard
    /// truly has no root — tolerated by the empty-root branch in
    /// `verify_prover_root`.
    fn compute_prover_root(&self) -> Vec<u8> {
        let Some(hg) = self.hypergraph.as_ref() else {
            return Vec::new();
        };
        let global_shard = quil_types::store::ShardKey {
            l1: [0u8; 3],
            l2: [0xffu8; 32],
        };
        let root = hg.compute_shard_root("vertex", "adds", &global_shard);
        // A real forest root is 32 bytes; reject the empty/degenerate case.
        if root.len() == 32 || root.len() >= 64 {
            root
        } else {
            Vec::new()
        }
    }

    /// Compute the parent selector from a VDF output: Poseidon hash of
    /// the output bytes, yielding a 32-byte selector. Falls back to
    /// SHA-256 if the Poseidon hash fails (should not happen with
    /// well-formed output).
    fn compute_parent_selector(output: &[u8]) -> [u8; 32] {
        match quil_crypto::poseidon::hash_bytes_to_32(output) {
            Ok(hash) => hash,
            Err(_) => {
                // Fallback: this should not happen with valid 516-byte
                // VDF output. Log would be appropriate here but we keep
                // the function pure and let callers notice via
                // mismatched selectors.
                let hash = Sha256::digest(output);
                let mut out = [0u8; 32];
                out.copy_from_slice(&hash);
                out
            }
        }
    }

    /// Compute the QC identity. Mirror of Go's
    /// `QuorumCertificate.Identity()` at `protobufs/global.go:46-48`
    /// which returns `models.Identity(g.Selector)` — i.e. the Selector
    /// bytes interpreted as the identity directly (Go strings are byte
    /// sequences).
    fn qc_identity(
        qc: &quil_types::proto::global::QuorumCertificate,
    ) -> Identity {
        qc.selector.clone()
    }

    /// Compute the identity of a GlobalFrame. Mirror of Go's
    /// `GlobalFrame.Identity()` at `protobufs/global.go:142-149`:
    /// `poseidon.HashBytes(g.Header.Output).FillBytes(make([]byte, 32))`.
    fn frame_identity(header: &quil_types::proto::global::GlobalFrameHeader) -> Identity {
        match quil_crypto::poseidon::hash_bytes_to_32(&header.output) {
            Ok(hash) => hash.to_vec(),
            Err(_) => Vec::new(),
        }
    }

    /// Build the request root: a `VectorCommitmentTree` over the
    /// collected MessageBundle payloads, keyed by `sha3_256(payload)`.
    /// Mirrors Go's `consensus_leader_provider.go:256-307`:
    ///
    /// ```go
    /// requestTree := &tries.VectorCommitmentTree{}
    /// for _, msgData := range collectedMessages {
    /// id := sha3.Sum256(msgData)
    /// requestTree.Insert(id[:], msgData, nil, big.NewInt(0))
    /// }
    /// requestRoot := requestTree.Commit(inclusionProver, false)
    /// ```
    ///
    /// Empty inputs yield the canonical empty-root `[0u8; 64]` produced
    /// by `VectorCommitmentTree::commit` on an empty tree. Insert
    /// failures are logged and skipped, matching Go's `if err != nil`
    /// soft-fail (a single bad bundle does not abort the whole frame).
    fn compute_requests_root(&self, messages: &[Vec<u8>]) -> Vec<u8> {
        use sha3::{Digest as _, Sha3_256};
        let mut tree = quil_tries::VectorCommitmentTree::new();
        for msg in messages {
            let id: [u8; 32] = Sha3_256::digest(msg).into();
            if let Err(e) = tree.insert(
                &id,
                msg,
                &[],
                &num_bigint::BigInt::from(0),
            ) {
                tracing::warn!(
                    error = %e,
                    "failed to add global request to tree",
                );
                continue;
            }
        }
        tree.commit(self.inclusion_prover.as_ref())
    }
}

impl LeaderProvider<GlobalState> for GlobalLeaderProvider {
    /// Return leaders for the next rank, ordered by the prover
    /// registry's VDF-distance walk seeded by the parent frame's
    /// Poseidon-hashed output.
    fn get_next_leaders(&self, prior: Option<&State<GlobalState>>) -> Result<Vec<Identity>> {
        // The prior state must have a valid VDF output to seed the
        // ordering. Without it we cannot determine leader order.
        let prior = prior.ok_or_else(|| {
            QuilError::Consensus("no prior frame for leader selection".into())
        })?;

        if prior.state.output.len() != VDF_OUTPUT_LEN {
            return Err(QuilError::Consensus(format!(
                "prior frame output length {} != expected {}",
                prior.state.output.len(),
                VDF_OUTPUT_LEN,
            )));
        }

        // Compute the parent selector: Poseidon(output) -> 32 bytes.
        let parent_selector = Self::compute_parent_selector(&prior.state.output);

        // Get provers ordered by VDF distance to the parent selector.
        // Empty filter = global chain (matches Go's `nil` filter).
        // Committee/leader-rotation set for the frame being decided
        // (parent + 1) — the epoch-aligned membership at that frame.
        let ordered_addresses = self.prover_registry.get_ordered_provers(
            &parent_selector,
            &[],
            prior.state.frame_number + 1,
        )?;

        if ordered_addresses.is_empty() {
            return Err(QuilError::Consensus(
                "no active provers in registry".into(),
            ));
        }

        let leaders: Vec<Identity> = ordered_addresses
            .iter()
            .map(|addr| address_to_identity(addr))
            .collect();

        if !leaders.is_empty() {
            tracing::debug!(
                count = leaders.len(),
                first = %hex::encode(&leaders[0]),
                "determined next global leaders",
            );
        }

        Ok(leaders)
    }

    /// Produce a new global frame at the given rank. Full port of Go's
    /// `ProveNextState`:
    ///
    /// 1. Fetch the latest QC and resolve the prior frame
    /// 2. Validate that the prior frame identity matches `prior_state_id`
    /// 3. Collect pending messages from the message collector
    /// 4. Compute the request root from collected messages
    /// 5. Determine prover index among active provers
    /// 6. Compute next difficulty via ASERT
    /// 7. Call `frame_prover.prove_global_frame_header()` (blocks for VDF)
    /// 8. Assemble `GlobalState` with all fields populated
    /// 9. Return `State<GlobalState>`
    fn prove_next_state(
        &self,
        rank: u64,
        _filter: &[u8],
        prior_frame_number: u64,
        prior_state_id: &Identity,
    ) -> Result<State<GlobalState>> {
        // ------------------------------------------------------------------
        // 1. Resolve the prior frame the CONSENSUS layer chose to build on.
        //
        // `(prior_frame_number, prior_state_id)` come straight from the
        // newest QC the pacemaker handed the state producer. We must build
        // on EXACTLY that parent. Historically this re-read the clock
        // store's OWN `get_latest_quorum_certificate`, but that QC can
        // diverge from the consensus newest-QC — e.g. after a coordinated
        // halt the clock store may still name an uncommitted candidate
        // (frame N) that consensus has NOT adopted (its newest-QC is the
        // committed head N-1), or a peer's candidate this node never
        // received. Reading it there made the producer try to load a frame
        // that isn't local (`frame N not found`) or build on a different
        // parent than consensus asked for (a fork). Resolving purely from
        // the passed parent removes that whole divergence class.
        //
        // Resolve the parent by the consensus-chosen IDENTITY, not merely by
        // height. The committed frame at `prior_frame_number` can be a DIFFERENT
        // fork candidate than the one consensus certified (`prior_state_id`) —
        // e.g. this node materialized fork A while the newest QC is on fork B at
        // the same height. Looking up the COMMITTED frame first and only falling
        // back to the candidate on error (the previous order) accepted that
        // wrong-fork committed frame and never consulted the candidate the node
        // actually anchored on, wedging the leader in a permanent "needs sync".
        // So query the candidate keyed by the exact consensus identity FIRST
        // (returns the anchored tip when we hold it), then fall back to the
        // committed frame — whose identity is validated just below, yielding a
        // clean "needs sync + catch-up" only when we genuinely lack the parent.
        let prior = if prior_frame_number == 0 {
            self.clock_store.get_global_clock_frame(0)?
        } else {
            self.clock_store
                .get_global_clock_frame_candidate(prior_frame_number, prior_state_id)
                .or_else(|_| self.clock_store.get_global_clock_frame(prior_frame_number))?
        };

        let prior_header = prior.header.as_ref().ok_or_else(|| {
            QuilError::Consensus("prior frame has no header".into())
        })?;

        // ------------------------------------------------------------------
        // 2. Validate the resolved frame's identity matches what consensus
        //    asked for. A mismatch means this node doesn't hold the parent
        //    consensus wants (it needs to sync it) — a clean, recoverable
        //    skip, not a fork.
        // ------------------------------------------------------------------
        let prior_identity = Self::frame_identity(prior_header);
        if prior_identity != *prior_state_id {
            return Err(QuilError::Consensus(format!(
                "needs sync: local frame {} has identity {} but consensus parent is {} — \
                 fetch the parent via catch-up and retry",
                prior_frame_number,
                hex::encode(&prior_identity),
                hex::encode(prior_state_id),
            )));
        }

        let frame_number = prior_header.frame_number + 1;

        // ------------------------------------------------------------------
        // 2b. Pace the chain to the mainnet inter-frame interval.
        //
        // commonware-simplex has no minimum block time: it proposes,
        // finalizes, and immediately opens the next view as fast as the
        // network + VDF prove allow. With the VDF difficulty pinned near
        // the floor that round is ~3s, so frames land at the testnet rate
        // regardless of `IDEAL_FRAME_TIME`. The VDF is NOT the pace-setter
        // under CW — the proposer is. So gate proposal production here.
        //
        // Each header's `timestamp` is set to `production_now + IDEAL`
        // (step 6 below), so the parent's timestamp is 1 interval ahead of
        // the instant the parent was produced. Sleeping until
        // `now >= prior_header.timestamp` therefore spaces our production
        // instant exactly one `IDEAL_FRAME_TIME` after the parent's — a
        // clean 10s cadence in both wall-clock and recorded timestamps —
        // without any dependence on VDF difficulty.
        //
        // Capped at one interval so a parent timestamp far in the future
        // (cross-leader clock skew, or a misbehaving prior leader) can
        // never stall this node more than a single frame; if the parent
        // timestamp is already in the past we proceed immediately (we're
        // catching up, don't slow down).
        {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            let target = prior_header.timestamp;
            let wait_ms = (target - now_ms)
                .clamp(0, crate::difficulty::IDEAL_FRAME_TIME);
            if wait_ms > 0 {
                tracing::debug!(
                    frame = frame_number,
                    wait_ms,
                    "pacing global proposal to mainnet interval",
                );
                std::thread::sleep(std::time::Duration::from_millis(wait_ms as u64));
            }
        }

        // ------------------------------------------------------------------
        // 3. Collect pending messages, then drop protocol-invalid ones.
        //
        // Collection is non-destructive (so a timed-out proposal doesn't
        // vaporize the mempool). That means a message which fails protocol
        // validation would otherwise be re-collected and re-proposed every
        // rank until it ages out of the retention window. Mirror Go's
        // liveness-provider collect loop
        // (`consensus_liveness_provider.go:86-97`): validate each collected
        // message and `MessageCollector::remove` the failures so they leave
        // the mempool the moment we know they're invalid. Only the
        // surviving (valid) messages ride into this proposal.
        //
        // Shard-`FrameHeader` bundles are NOT re-validated here: they are
        // deduplicated at ingest and fully validated by the materializer,
        // and re-verifying their per-proof VDF multiproofs (unbatchable,
        // and now uncapped — a frame can carry thousands) would load the
        // latency-sensitive prove path. Structurally-invalid bundles were
        // already rejected at ingest.
        // ------------------------------------------------------------------
        let collected = self.message_collector.collect_for_rank(rank);
        let messages = match self.message_validator.as_ref() {
            Some(validator) => {
                // The collector holds GLOBAL messages, validated against the
                // global intrinsic engine address (0xff..), matching Go's
                // `globalMessageAddress`.
                let global_addr = [0xFFu8; 32];
                let mut valid: Vec<Vec<u8>> = Vec::with_capacity(collected.len());
                let mut invalid: Vec<Vec<u8>> = Vec::new();
                for raw in collected {
                    if crate::message_collector::bundle_has_shard_frame(&raw) {
                        // Strict lockstep: include a shard-frame proof ONLY if it
                        // anchors to `frame_number - 1` (or genesis anchor 0). The
                        // materializer hard-rejects any frame carrying an
                        // out-of-lockstep shard op, so packing a stale proof would
                        // halt the chain — drop it here instead. A lagging shard
                        // must re-attest against the new tip to be included.
                        if crate::message_collector::bundle_shard_frames_in_lockstep(
                            &raw,
                            frame_number,
                        ) {
                            valid.push(raw);
                        } else {
                            tracing::debug!(
                                frame = frame_number,
                                "dropping out-of-lockstep shard frame proof from global mempool",
                            );
                            invalid.push(raw);
                        }
                        continue;
                    }
                    match validator.validate_message(frame_number, &global_addr, &raw) {
                        Ok(()) => valid.push(raw),
                        Err(e) => {
                            tracing::debug!(
                                frame = frame_number,
                                error = %e,
                                "dropping protocol-invalid message from global mempool",
                            );
                            invalid.push(raw);
                        }
                    }
                }
                if !invalid.is_empty() {
                    tracing::info!(
                        frame = frame_number,
                        removed = invalid.len(),
                        "dropped protocol-invalid messages from global mempool",
                    );
                    self.message_collector.remove(&invalid);
                }
                valid
            }
            None => collected,
        };

        tracing::info!(
            frame = frame_number,
            rank,
            message_count = messages.len(),
            "proving next global state",
        );

        // ------------------------------------------------------------------
        // 4. Compute request root from collected messages
        // ------------------------------------------------------------------
        let requests_root = self.compute_requests_root(&messages);

        // ------------------------------------------------------------------
        // 5. Verify this node is an active prover and find our index
        // ------------------------------------------------------------------
        let active_provers = self.prover_registry.get_active_provers(&[], frame_number)?;
        let prover_index = active_provers
            .iter()
            .position(|p| p.address == self.local_prover_address);

        if prover_index.is_none() {
            return Err(QuilError::Consensus("not a prover".into()));
        }

        // ------------------------------------------------------------------
        // 6. Compute difficulty
        // ------------------------------------------------------------------
        // Go adds 10 seconds to the timestamp for the difficulty
        // calculation, matching the expected block interval.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let timestamp = now_ms + 10_000; // +10s, matching Go
        let difficulty = self.difficulty_adjuster.get_next_difficulty(rank, timestamp);

        tracing::debug!(
            difficulty,
            frame = frame_number,
            "next difficulty for frame",
        );

        // ------------------------------------------------------------------
        // 7. VDF prove + sign — blocks for seconds.
        //
        // ProveGlobalFrameHeader internally computes
        //   parent = poseidon(previous_frame.output[:516])
        //   challenge = sha3(frame# || timestamp || difficulty ||
        //                     parent || commitments... || prover_root ||
        //                     request_root)
        //   output = WesolowskiSolve(challenge, difficulty)
        //   signature = signer.SignWithDomain(challenge||output, "global")
        //
        // `prover_root` is the global prover shard commitment over the
        // committed state through the parent frame — bound into the VDF
        // challenge here AND carried on the header (`prover_tree_commitment`)
        // so every follower re-derives and cross-checks it in the
        // materializer, POMW mint, prover-kick verification, and state
        // sync. Computed from the CRDT (Go's `rebuildShardCommitments`
        // proverRoot). The per-L1 `global_commitments` array is still a
        // placeholder (not cross-checked at runtime, only VDF-bound) —
        // follow-up wiring.
        let prover_index_u8 = prover_index.map(|i| i as u8).unwrap_or(0);
        // The 256 Level-1 global bucket commitments (per first address byte),
        // retrieved live from the CRDT forest. Bound into the VDF challenge and
        // carried on the header via `GlobalState.global_commitments`.
        let commitments: Vec<Vec<u8>> = self
            .hypergraph
            .as_ref()
            .map(|hg| hg.global_commitments())
            .unwrap_or_default();
        let prover_root: Vec<u8> = self.compute_prover_root();
        if prover_root.is_empty() {
            tracing::warn!(
                frame = frame_number,
                "proving global frame with EMPTY prover_tree_commitment — \
                 CRDT root unavailable (rewards/kick/sync anchoring degraded for this frame)",
            );
        }
        let prove_start = std::time::Instant::now();
        let header = self.frame_prover.prove_global_frame_header(
            prior_header,
            &commitments,
            &prover_root,
            &requests_root,
            self.signer.as_ref(),
            timestamp,
            difficulty as u32,
            prover_index_u8,
        )?;
        crate::metrics::record_vdf_prove_duration(prove_start.elapsed().as_secs_f64());

        // ------------------------------------------------------------------
        // 9. Assemble GlobalState
        // ------------------------------------------------------------------
        // The prover_tree_commitment is the CRDT prover-shard root we just
        // bound into the VDF challenge above — it MUST equal the
        // `prover_root` passed to `prove_global_frame_header`, since the
        // stored header is rebuilt from THIS `GlobalState`
        // (`cw_global_seams::global_frame_from_state`) and every follower's
        // `verify_global_frame_header` recomputes the challenge from the
        // header's own `prover_tree_commitment`. The signature is populated
        // by the consensus signing step after the proposal is voted on.
        // Decode each canonical bundle into a prost `MessageBundle`
        // (the proto type the materializer expects). Bundles that
        // fail decode are skipped — `requests_root` was hashed over
        // the canonical bytes, so a partial set here would mismatch,
        // but in practice the same `decode_message_bundle` call has
        // already round-tripped these on every other replica's
        // receive path, so a leader-side failure indicates the same
        // bundle would also fail downstream.
        let proto_messages: Vec<quil_types::proto::global::MessageBundle> = messages
            .iter()
            .filter_map(|raw| crate::consensus_wire::decode_message_bundle(raw).ok())
            .collect();
        let state = GlobalState::new(
            frame_number,
            rank,
            timestamp,
            difficulty as u32,
            header.output.clone(),
            header.parent_selector.clone(),
            self.local_prover_address.clone(),
            prover_root.clone(), // prover_tree_commitment — must match the VDF challenge
            requests_root,
            Vec::new(), // signature — populated by consensus signing step
        )
        // Attach the collected messages so they ride with the proposal
        // into `GlobalFrame.requests` and reach every replica's
        // materializer on finalization.
        .with_messages(proto_messages)
        // Carry the 256 global commitments bound into the VDF challenge so the
        // rebuilt header (`global_frame_from_state`) reproduces them verbatim.
        .with_global_commitments(commitments);

        // ------------------------------------------------------------------
        // 10. Build and return State<GlobalState>
        // ------------------------------------------------------------------
        let identifier = state.compute_identity();

        tracing::info!(
            frame = frame_number,
            rank,
            identifier = %hex::encode(&identifier),
            "proved global frame",
        );

        Ok(State {
            rank,
            identifier,
            proposer_id: address_to_identity(&self.local_prover_address),
            parent_qc_identity: prior_state_id.clone(),
            parent_qc_rank: rank.saturating_sub(1),
            // Leader-side construction: `prove_next_state` doesn't
            // receive the parent QC trait object. The QC arc is
            // populated on the receiver side from the wire-decoded
            // proposal.
            parent_quorum_certificate: None,
            timestamp: timestamp as u64,
            state,
        })
    }
}

// `prove_next_state` (the VDF/clock-store path) is integration-tested
// via the consensus bootstrap tests on real stores. The unit tests
// below cover `get_next_leaders` (leader selection) and the pure
// helper functions, which need only a `ProverRegistry`.
#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::consensus::{ProverInfo, ProverStatus};
    use quil_types::proto::global::GlobalFrameHeader;

    use crate::difficulty::AsertDifficultyAdjuster;
    use crate::test_support::TestProverRegistry;

    /// Minimal `FrameProver` stub — `get_next_leaders` never invokes it.
    #[derive(Default)]
    struct StubFrameProver;
    impl FrameProver for StubFrameProver {
        fn prove_frame_header(
            &self, _: &[u8], _: &[u8], _: &[u8], _: &[Vec<u8>], _: &[u8], _: i64, _: u32, _: u64, _: u64, _: &[u8], _: u64,
        ) -> Result<quil_types::proto::global::FrameHeader> {
            Err(QuilError::Internal("stub".into()))
        }
        fn verify_frame_header(
            &self, _: &quil_types::proto::global::FrameHeader,
        ) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        fn prove_global_frame_header(
            &self, _: &GlobalFrameHeader, _: &[Vec<u8>], _: &[u8], _: &[u8],
            _: &dyn Signer, _: i64, _: u32, _: u8,
        ) -> Result<GlobalFrameHeader> {
            Err(QuilError::Internal("stub".into()))
        }
        fn verify_global_frame_header(&self, _: &GlobalFrameHeader) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        fn calculate_multi_proof(&self, _: &[u8; 32], _: u32, _: &[&[u8]], _: u32) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }
        fn verify_multi_proof(&self, _: &[u8; 32], _: u32, _: &[&[u8]], _: &[&[u8]]) -> Result<bool> {
            Ok(true)
        }
    }

    fn make_prover(addr_byte: u8) -> ProverInfo {
        ProverInfo {
            public_key: vec![addr_byte; 96],
            address: vec![addr_byte; 32],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![],
            available_storage: 0,
            seniority: 1,
            delegate_address: vec![],
        }
    }

    /// Structure-only signer (never actually invoked by these tests).
    struct DummySigner;
    impl Signer for DummySigner {
        fn key_type(&self) -> quil_types::crypto::KeyType {
            quil_types::crypto::KeyType::Bls48581G1
        }
        fn public_key(&self) -> &[u8] {
            &[]
        }
        fn private_key(&self) -> &[u8] {
            &[0u8]
        }
        fn sign(&self, _: &[u8]) -> Result<Vec<u8>> {
            Ok(vec![0xAA; 74])
        }
        fn sign_with_domain(&self, _: &[u8], _: &[u8]) -> Result<Vec<u8>> {
            Ok(vec![0xAA; 74])
        }
    }

    fn provider_with(registry: Arc<dyn ProverRegistry>) -> GlobalLeaderProvider {
        let signer: Arc<dyn Signer> = Arc::new(DummySigner);
        GlobalLeaderProvider::new(
            registry,
            Arc::new(StubFrameProver),
            Arc::new(AsertDifficultyAdjuster::new(0, 0, 100)),
            Arc::new(quil_store::testing::InMemoryClockStore::new()),
            Arc::new(MessageCollector::new()),
            vec![0xABu8; 32],
            vec![0xABu8; 96],
            signer,
            // Real KZG prover so `compute_requests_root` reflects tree
            // contents (the noop prover returns all-zero roots).
            Arc::new(quil_crypto::KzgInclusionProver),
            // No execution manager in these unit tests — the validate-and-
            // drop gate is exercised via integration tests on real stores.
            None,
            // No CRDT wired — prover_tree_commitment stays empty (tolerated).
            None,
        )
    }

    fn provider_with_prover(
        prover: Arc<dyn quil_types::crypto::InclusionProver + Send + Sync>,
    ) -> GlobalLeaderProvider {
        let signer: Arc<dyn Signer> = Arc::new(DummySigner);
        GlobalLeaderProvider::new(
            Arc::new(TestProverRegistry::new()),
            Arc::new(StubFrameProver),
            Arc::new(AsertDifficultyAdjuster::new(0, 0, 100)),
            Arc::new(quil_store::testing::InMemoryClockStore::new()),
            Arc::new(MessageCollector::new()),
            vec![0xABu8; 32],
            vec![0xABu8; 96],
            signer,
            prover,
            None,
            None,
        )
    }

    /// Regression for the archive-consensus `requests_root = 0x00..00` bug.
    /// `compute_requests_root` builds a VectorCommitmentTree and commits it
    /// via the WIRED inclusion prover. A `NoopInclusionProver` commits any
    /// BRANCH (>= 2 messages) to 64 zero bytes — so every non-trivial frame
    /// shipped a zero root. A single message is a LEAF (SHA-512), non-zero
    /// even under Noop, which is exactly why the bug was invisible on
    /// near-empty frames. The real KZG prover yields a non-zero root. The
    /// archive path had been wired with Noop (fixed to Kzg); this pins the
    /// contract so it can't silently regress.
    #[test]
    fn requests_root_zero_under_noop_nonzero_under_kzg_for_branch() {
        let msgs: Vec<Vec<u8>> = vec![vec![1u8; 40], vec![2u8; 40], vec![3u8; 40]];

        let noop = provider_with_prover(Arc::new(quil_types::crypto::NoopInclusionProver));
        assert_eq!(
            noop.compute_requests_root(&msgs),
            vec![0u8; 64],
            "Noop prover commits the multi-message branch to zeros — the bug"
        );

        let kzg = provider_with_prover(Arc::new(quil_crypto::KzgInclusionProver));
        assert_ne!(
            kzg.compute_requests_root(&msgs),
            vec![0u8; 64],
            "real KZG prover must produce a non-zero requests_root for a multi-message frame"
        );
    }

    fn prior_state(output_len: usize) -> State<GlobalState> {
        let gs = GlobalState::new(
            5,                          // frame_number
            5,                          // rank
            0,                          // timestamp
            100,                        // difficulty
            vec![0x11u8; output_len],   // output
            vec![0x03u8; 32],           // parent_selector
            vec![0x02u8; 32],           // prover
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        State {
            rank: 5,
            identifier: vec![0x01u8; 32],
            proposer_id: vec![0x02u8; 32],
            parent_qc_identity: vec![0x03u8; 32],
            parent_qc_rank: 4,
            parent_quorum_certificate: None,
            timestamp: 0,
            state: gs,
        }
    }

    #[test]
    fn get_next_leaders_errors_without_prior() {
        let p = provider_with(Arc::new(TestProverRegistry::new()));
        let err = p.get_next_leaders(None).unwrap_err();
        assert!(err.to_string().contains("no prior frame"));
    }

    #[test]
    fn get_next_leaders_errors_on_wrong_output_length() {
        let p = provider_with(Arc::new(TestProverRegistry::with_provers(vec![make_prover(1)])));
        let prior = prior_state(100); // != VDF_OUTPUT_LEN
        let err = p.get_next_leaders(Some(&prior)).unwrap_err();
        assert!(err.to_string().contains("output length"));
    }

    #[test]
    fn get_next_leaders_errors_when_registry_empty() {
        let p = provider_with(Arc::new(TestProverRegistry::new()));
        let prior = prior_state(VDF_OUTPUT_LEN);
        let err = p.get_next_leaders(Some(&prior)).unwrap_err();
        assert!(err.to_string().contains("no active provers"));
    }

    #[test]
    fn get_next_leaders_returns_ordered_identities() {
        let registry = TestProverRegistry::with_provers(vec![
            make_prover(0xAA),
            make_prover(0xBB),
            make_prover(0xCC),
        ]);
        let p = provider_with(Arc::new(registry));
        let prior = prior_state(VDF_OUTPUT_LEN);
        let leaders = p.get_next_leaders(Some(&prior)).unwrap();
        assert_eq!(leaders.len(), 3);
        // Identities are the raw 32-byte addresses (address_to_identity).
        assert_eq!(leaders[0], vec![0xAAu8; 32]);
        assert_eq!(leaders[1], vec![0xBBu8; 32]);
        assert_eq!(leaders[2], vec![0xCCu8; 32]);
    }

    #[test]
    fn compute_parent_selector_is_deterministic_and_32_bytes() {
        let out = vec![0x42u8; VDF_OUTPUT_LEN];
        let a = GlobalLeaderProvider::compute_parent_selector(&out);
        let b = GlobalLeaderProvider::compute_parent_selector(&out);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        // Different input → different selector.
        let c = GlobalLeaderProvider::compute_parent_selector(&vec![0x43u8; VDF_OUTPUT_LEN]);
        assert_ne!(a, c);
    }

    #[test]
    fn frame_identity_hashes_output() {
        let header = GlobalFrameHeader {
            output: vec![0x55u8; VDF_OUTPUT_LEN],
            ..Default::default()
        };
        let id = GlobalLeaderProvider::frame_identity(&header);
        assert_eq!(id.len(), 32);
        // Matches the direct poseidon hash of the output.
        let expected = quil_crypto::poseidon::hash_bytes_to_32(&header.output).unwrap();
        assert_eq!(id, expected.to_vec());
    }

    #[test]
    fn qc_identity_returns_selector_bytes() {
        let qc = quil_types::proto::global::QuorumCertificate {
            selector: vec![0x77u8; 32],
            ..Default::default()
        };
        assert_eq!(GlobalLeaderProvider::qc_identity(&qc), vec![0x77u8; 32]);
    }

    #[test]
    fn compute_requests_root_empty_vs_nonempty_differ() {
        let p = provider_with(Arc::new(TestProverRegistry::new()));
        let empty = p.compute_requests_root(&[]);
        let nonempty = p.compute_requests_root(&[vec![0x01u8; 16], vec![0x02u8; 16]]);
        assert_ne!(empty, nonempty);
        // Deterministic for the same input.
        assert_eq!(empty, p.compute_requests_root(&[]));
    }

    /// Build a leader whose only non-default wiring is the hypergraph CRDT,
    /// so `compute_prover_root` can be exercised in isolation.
    fn provider_with_crdt(
        crdt: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
    ) -> GlobalLeaderProvider {
        let signer: Arc<dyn Signer> = Arc::new(DummySigner);
        GlobalLeaderProvider::new(
            Arc::new(TestProverRegistry::new()),
            Arc::new(StubFrameProver),
            Arc::new(AsertDifficultyAdjuster::new(0, 0, 100)),
            Arc::new(quil_store::testing::InMemoryClockStore::new()),
            Arc::new(MessageCollector::new()),
            vec![0xABu8; 32],
            vec![0xABu8; 96],
            signer,
            Arc::new(quil_crypto::KzgInclusionProver),
            None,
            crdt,
        )
    }

    /// The `prover_tree_commitment` the leader binds into the VDF challenge
    /// is the global prover shard's (`L1=[0;3]`, `L2=[0xff;32]`) live
    /// vertex-adds forest root — read via `compute_shard_root`, the same
    /// value `commit_inner` writes into the header, and the value every
    /// follower re-derives. Seeding that shard and committing must yield a
    /// real (32-byte, non-zero) root that `compute_prover_root` returns,
    /// matching a direct `compute_shard_root`, while a populated distractor
    /// shard's root is NOT returned (targets the global shard specifically).
    #[test]
    fn compute_prover_root_reads_live_global_shard_root() {
        use quil_hypergraph::testing::{MemStore, StubProver};
        use quil_hypergraph::Location;
        use quil_types::store::ShardKey;

        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(StubProver),
        ));
        let global_shard = ShardKey { l1: [0u8; 3], l2: [0xffu8; 32] };
        // Seed real state into the global prover shard (app == global
        // address) plus a distractor app shard, then commit to the forest.
        crdt.add_vertex(
            &Location { app_address: [0xff; 32], data_address: [0x01; 32] },
            b"prover-state",
        )
        .unwrap();
        crdt.add_vertex(
            &Location { app_address: [0x2a; 32], data_address: [0x07; 32] },
            b"distractor",
        )
        .unwrap();
        crdt.commit(1).unwrap();

        let expected = crdt.compute_shard_root("vertex", "adds", &global_shard);
        let distractor = crdt.compute_shard_root(
            "vertex",
            "adds",
            &ShardKey { l1: [0u8; 3], l2: [0x2a; 32] },
        );

        let provider = provider_with_crdt(Some(crdt.clone()));
        let got = provider.compute_prover_root();

        assert_eq!(
            got, expected,
            "compute_prover_root must return the live global-shard vertex-adds root",
        );
        assert_eq!(got.len(), 32, "a real forest root is 32 bytes");
        assert!(got.iter().any(|&b| b != 0), "global shard has data → non-zero root");
        assert_ne!(got, distractor, "must target the global shard, not another app shard");
        // Deterministic across re-proves of the same committed state.
        assert_eq!(got, provider.compute_prover_root());
    }

    /// No CRDT wired (unit-test / degraded node) → empty commitment, which
    /// `verify_prover_root`'s empty-root branch tolerates without a halt.
    #[test]
    fn compute_prover_root_empty_without_crdt() {
        let provider = provider_with_crdt(None);
        assert!(provider.compute_prover_root().is_empty());
    }
}

//! Real-state implementations of the commonware-simplex consensus seams for
//! GLOBAL consensus (P2b). These bridge `quil-cw-consensus`'s three narrow seam
//! traits to Quilibrium's existing global-chain machinery:
//!
//! - [`GlobalSeamProposer`] (`GlobalProposer`) — `propose` builds the next frame
//! via `LeaderProvider::prove_next_state`; `verify` runs `GlobalFrameVerifier`.
//! - [`GlobalSeamSink`] (`FrameSink`) — ships frame bytes to the committee over
//! the CW `:8340` transport on the dedicated block channel (channel 3).
//! - [`GlobalSeamFinalizer`] (`FrameFinalizer`) — persists + materializes on
//! finalize, writes a candidate on notarize.
//!
//! The simplex digest is the 32-byte global-frame identity
//! (`Poseidon(header.output)`), so `digest ↔ Identity` is a direct byte map.
//!
//! This module is self-contained (it does not yet replace the live
//! `activate_consensus` path — that swap is P2c). It compiles against the real
//! interfaces so the type bridges are validated ahead of wiring.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use quil_cw_consensus::adapters::{
    digest_from_identity, digest_to_identity, Digest, FrameFinalizer, FrameSink, GlobalProposer,
    Recipients,
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
struct NoopTxn;
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
    /// Fallback resolver. `block_meta` is in-memory and empty after a restart,
    /// so the notarized parent digest can't be mapped to a frame number →
    /// `propose` would default to 0 and fail "frame 0 not found" forever. The
    /// clock store's latest committed frame is exactly the head the explorer
    /// surfaces; building the next frame on it recovers liveness (any
    /// unfinalized candidates above it are simply re-derived).
    clock_store: Arc<dyn ClockStore>,
}

impl GlobalSeamProposer {
    pub fn new(
        leader_provider: Arc<dyn LeaderProvider<GlobalState>>,
        verifier: Arc<GlobalFrameVerifier>,
        filter: Vec<u8>,
        clock_store: Arc<dyn ClockStore>,
    ) -> Self {
        Self {
            leader_provider,
            verifier,
            filter,
            block_meta: Arc::new(Mutex::new(HashMap::new())),
            clock_store,
        }
    }

    /// Record digest → frame_number (also used by inbound-frame ingestion so a
    /// synced parent resolves its number).
    pub fn note_frame(&self, digest: Digest, frame_number: u64) {
        self.block_meta.lock().unwrap().insert(digest, frame_number);
    }
}

impl GlobalProposer for GlobalSeamProposer {
    fn propose(&self, view: u64, parent_digest: Digest) -> Option<(Digest, Vec<u8>)> {
        // parent digest bytes == prior frame identity (Poseidon(output)).
        let meta_hit = self.block_meta.lock().unwrap().get(&parent_digest).copied();
        let (prior_frame_number, prior_state_id): (u64, Vec<u8>) = match meta_hit {
            Some(n) => (n, digest_to_identity(&parent_digest).to_vec()),
            None => {
                // block_meta is in-memory and only holds frames THIS node built
                // or verified this run; after a restart it's empty (seeded only
                // with the genesis floor), so the notarized parent digest can't
                // be mapped → we'd default to 0 → "frame 0 not found" → permanent
                // nullify. Fall back to the clock store's latest committed frame
                // (exactly the head the explorer shows) and build the next frame
                // on it. Any unfinalized candidates above it are re-derived.
                match self.clock_store.get_latest_global_clock_frame() {
                    Ok(latest) => match latest.header.as_ref().and_then(frame_digest) {
                        Some(head_digest) => {
                            let n = latest.header.as_ref().map(|h| h.frame_number).unwrap_or(0);
                            tracing::warn!(
                                view,
                                parent = %hex::encode(&parent_digest),
                                resolved_frame = n,
                                head = %hex::encode(head_digest),
                                "cw propose: parent not in block map (restart) — building on clock-store head"
                            );
                            (n, digest_to_identity(&head_digest).to_vec())
                        }
                        None => (0, digest_to_identity(&parent_digest).to_vec()),
                    },
                    Err(e) => {
                        tracing::warn!(view, error = %e, "cw propose: parent not in block map and no latest frame");
                        (0, digest_to_identity(&parent_digest).to_vec())
                    }
                }
            }
        };

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
        let digest = frame_digest(header)?;
        let frame_number = header.frame_number;
        let bytes = encode_global_frame(&frame).ok()?;

        self.block_meta.lock().unwrap().insert(digest, frame_number);
        Some((digest, bytes))
    }

    fn verify(&self, view: u64, digest: Digest, bytes: Option<Vec<u8>>) -> bool {
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

/// Persists + materializes finalized frames; writes candidates on notarize.
pub struct GlobalSeamFinalizer {
    clock_store: Arc<dyn ClockStore>,
    /// Hand finalized frames to the node's existing global-materializer worker
    /// (which commits the CRDT/prover tree, verifies the root, evicts, marks
    /// bundles consumed, and drives split/merge rebalance). Reuses the exact
    /// same `(frame, frame_number)` channel the quil-consensus path fed, so no
    /// materialize logic is duplicated. Materialize MUST run off the consensus
    /// task — a slow commit must not stall the engine.
    mat_job_tx: tokio::sync::mpsc::UnboundedSender<(GlobalFrame, u64)>,
    /// Bump head atomics / CurrentFrame (node-supplied).
    head_hook: HeadHook,
    /// Optional GOSSIP publisher for finalized global frames: non-blocking hand-off
    /// (the node drains it and publishes on the `GLOBAL_FRAME` bitmask). This lets
    /// NON-committee/regular nodes receive global frames over gossip instead of
    /// RPC-polling archives. Only the PROPOSER of a frame publishes (gated on
    /// `local_prover_address`) to avoid N-way committee duplication; gossip dedup
    /// would absorb dupes anyway but the gate saves upstream bandwidth. `None`
    /// disables (no p2p wired). The frame published carries the finalization cert
    /// (attached above), so it is self-verifying to receivers.
    global_frame_publisher: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>>,
    /// This node's 32-byte PROVER ADDRESS — the proposer gate for
    /// `global_frame_publisher`. A finalized global frame header's `prover` field
    /// is the proposer's 32-byte poseidon address (confirmed at runtime: it
    /// rotates through the committee members' `prover_address`es), so the gate
    /// compares against the address, NOT the 897-byte Falcon pubkey.
    local_prover_address: Vec<u8>,
}

/// Gossip publish is skipped for a finalized frame whose encoding exceeds this —
/// the p2p `MAX_MESSAGE_SIZE` is 16 MiB; stay safely under it (wire framing +
/// bitmask overhead). Oversized (extreme full-coverage) frames fall back to the
/// archive poller, which still fetches them by number.
const MAX_GOSSIP_GLOBAL_FRAME: usize = 15 * 1024 * 1024;

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
            head_hook,
            global_frame_publisher,
            local_prover_address,
        }
    }
}

impl FrameFinalizer for GlobalSeamFinalizer {
    fn on_notarized(&self, _view: u64, _digest: Digest, bytes: Option<Vec<u8>>) {
        // Write the notarized (uncommitted) frame as a candidate so a later
        // `propose` can build on this tip before it finalizes (the leader
        // provider resolves the parent from committed-or-candidate).
        let Some(bytes) = bytes else { return };
        let Ok(frame) = decode_global_frame(&bytes) else { return };
        if let Err(e) = self
            .clock_store
            .put_global_clock_frame_candidate(&frame, &NoopTxn)
        {
            tracing::warn!(error = %e, "put candidate frame failed");
        }
    }

    fn on_finalized(
        &self,
        _view: u64,
        _digest: Digest,
        bytes: Option<Vec<u8>>,
        cert: Option<Vec<u8>>,
        _locally_verified: bool,
    ) {
        // Certificate-only replicas may not have locally verified these bytes,
        // so retain the context-free body re-bind check below at the persistence
        // boundary regardless of `_locally_verified`.
        let Some(bytes) = bytes else { return };
        let Ok(mut frame) = decode_global_frame(&bytes) else { return };
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
        let (frame_number, rank) = match frame.header.as_ref() {
            Some(h) => (h.frame_number, h.rank),
            None => return,
        };
        // Durable commit, bump head atomics, then hand off to the materialize
        // worker (non-blocking send; the worker materializes in finalize order).
        if let Err(e) = self.clock_store.put_global_clock_frame(&frame, &NoopTxn) {
            tracing::warn!(error = %e, "put finalized frame failed");
        }
        (self.head_hook)(frame_number, rank);

        // GOSSIP the finalized (cert-attached) frame so regular/non-committee
        // nodes receive it over the `GLOBAL_FRAME` topic instead of RPC-polling.
        // Proposer-only (this node produced it) to avoid N-way committee dupes;
        // size-gated (oversized frames fall back to the poller).
        if let Some(publish) = self.global_frame_publisher.as_ref() {
            let is_proposer = frame
                .header
                .as_ref()
                .map(|h| !h.prover.is_empty() && h.prover == self.local_prover_address)
                .unwrap_or(false);
            if is_proposer {
                match encode_global_frame(&frame) {
                    Ok(encoded) if encoded.len() <= MAX_GOSSIP_GLOBAL_FRAME => publish(encoded),
                    Ok(encoded) => tracing::debug!(
                        frame = frame_number,
                        bytes = encoded.len(),
                        "finalized global frame exceeds gossip size — poller fallback"
                    ),
                    Err(e) => tracing::debug!(error = %e, "encode finalized frame for gossip failed"),
                }
            }
        }

        let _ = self.mat_job_tx.send((frame, frame_number));
    }
}

// ---------------------------------------------------------------------------
// Live activation orchestration (P2c). Additive: this does NOT replace the
// existing `activate_consensus` yet — it assembles the simplex-backed global
// consensus from real dependencies and exposes the minimal contract the node
// must satisfy (implement `GlobalConsensusTransport`, feed inbound RPC into the
// returned `inbound` senders). Deleting the quil-consensus glue + swapping the
// `activate_consensus` call site is the final node-session step (P2c hookup).
// ---------------------------------------------------------------------------

use quil_cw_consensus::adapters::BlockStore;
use quil_cw_consensus::engine_host::{spawn_global_host, GlobalEngineParams, GlobalHostHandle};
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
    /// record its digest→frame_number mapping. Idempotent; drops malformed bytes.
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
) -> GlobalConsensusCwHandle {
    // Shared block store: `propose` inserts our own frame; the node inserts
    // peer-delivered frames via `ingest_block`; `verify`/`Relay`/`Reporter`
    // read it.
    let store = BlockStore::new();

    // Seams over real state. The proposer keeps a clock-store handle so it can
    // recover the parent frame number from the latest committed head when the
    // in-memory block map misses it after a restart.
    let proposer = Arc::new(GlobalSeamProposer::new(
        leader_provider,
        verifier,
        filter,
        clock_store.clone(),
    ));
    // Seed the parent map so the FIRST proposal resolves the genesis parent's
    // frame number (block_meta is otherwise empty → prior_frame_number 0).
    proposer.note_frame(genesis_digest, genesis_frame_number);
    let sink = Arc::new(GlobalSeamSink::new(transport.clone(), peers.clone()));
    let finalizer = Arc::new(GlobalSeamFinalizer::new(
        clock_store,
        mat_job_tx,
        head_hook,
        global_frame_publisher,
        local_prover_address,
    ));

    // Host the engine on its own runtime thread.
    let GlobalHostHandle { inbound, mut outbound } = spawn_global_host(
        scheme,
        peers,
        proposer.clone(),
        sink,
        finalizer,
        store.clone(),
        GlobalEngineParams::new("global", epoch, genesis_digest)
            .with_leader_timeout_secs(leader_timeout_secs),
        Some(storage_directory),
        // Global committee is fixed (genesis archives) — never rebuilt.
        None,
    );

    // Drain the engine's outbound (votes/certs/resolver) onto the :8340 transport.
    tokio::spawn(async move {
        while let Some(ob) = outbound.recv().await {
            transport.deliver(ob.channel, ob.recipients, ob.bytes);
        }
    });

    // Block ingress: decode a peer frame, compute its identity digest, insert
    // into the store, and note digest→frame_number for parent resolution.
    let ingest_block: Arc<dyn Fn(Vec<u8>) + Send + Sync> = {
        let store = store.clone();
        let proposer = proposer.clone();
        Arc::new(move |bytes: Vec<u8>| {
            let Ok(frame) = decode_global_frame(&bytes) else {
                tracing::debug!("cw block ingress: undecodable frame, dropping");
                return;
            };
            let Some(header) = frame.header.as_ref() else { return };
            let Some(digest) = frame_digest(header) else { return };
            let frame_number = header.frame_number;
            store.put(digest, bytes);
            proposer.note_frame(digest, frame_number);
            tracing::debug!(frame = frame_number, "cw block ingress: stored peer frame");
        })
    };

    GlobalConsensusCwHandle { inbound, ingest_block }
}

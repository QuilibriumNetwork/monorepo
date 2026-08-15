//! Real-state implementations of the commonware-simplex consensus seams for
//! APP-SHARD consensus (P3). Analogous to [`crate::cw_global_seams`] but for the
//! per-shard chains. See `crates/quil-cw-consensus/CUTOVER.md` §7.
//!
//! Structural differences from the global path (why this can't be a copy-paste):
//! - The app leader provider (`AppLeaderProvider`) is PRIVATE to `app_engine.rs`
//! and tightly coupled to the engine (it shares the `frame_requests` map and
//! `halted` flag). So instead of extracting it, the CW app path is activated
//! INSIDE `AppConsensusEngine::start_consensus`, reusing the `Arc<dyn
//! LeaderProvider<AppShardState>>` already built there.
//! - The full `AppShardFrame{header, requests}` cannot be rebuilt from the
//! consensus `State` alone — the `requests` live in the engine's per-frame
//! `frame_requests` map. So the engine supplies an ASSEMBLER callback that
//! turns a produced `State<AppShardState>` into the full frame.
//! - `verify` only needs the header (`BlsAppFrameValidator::validate_proposal`
//! checks VDF + structure, not requests), but the block shipped to peers must
//! carry the FULL frame so `on_finalized` can materialize it.
//!
//! The three commonware seam traits are reused verbatim from
//! `quil_cw_consensus::adapters` — they are generic over the 32-byte `Sha256`
//! digest, so the `Global*` naming is incidental.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use quil_cw_consensus::adapters::{
    digest_from_identity, digest_to_identity, Digest, FrameFinalizer, FrameSink, GlobalProposer,
    Recipients,
};
use quil_cw_consensus::falcon_base::FalconPublicKey;

use quil_consensus::leader_provider::LeaderProvider;
use quil_consensus::models::State;
use quil_types::proto::global::AppShardFrame;

use crate::app_types::AppShardState;
use crate::frame_validator::BlsAppFrameValidator;

/// simplex channel id reserved for out-of-band app block (frame-bytes) delivery
/// — the app analog of `cw_global_seams::CW_BLOCK_CHANNEL`.
pub const CW_APP_BLOCK_CHANNEL: u64 = 3;

/// Build the full `AppShardFrame{header, requests}` from a produced consensus
/// state. Supplied by `AppConsensusEngine` (it owns the per-frame `frame_requests`
/// map the leader recorded); returns `None` if assembly fails.
pub type AppFrameAssembler =
    Arc<dyn Fn(&State<AppShardState>) -> Option<AppShardFrame> + Send + Sync>;

/// Called with a finalized `AppShardFrame` — the engine materializes its requests
/// (`materialize_app_shard_requests`) and publishes the full frame on
/// `shard_frame_bitmask` for archives/followers.
pub type AppFrameSink = Arc<dyn Fn(AppShardFrame) + Send + Sync>;

/// Like [`AppFrameSink`] but also carries the serialized simplex finalization
/// certificate (proposal + Falcon quorum cert), so the engine can attach it to
/// the reward-coverage bundle for global-level verification.
/// The boolean marks whether this exact frame was locally validated and sealed
/// before finalization (vs. a certificate-only replica that learned the cert
/// without locally verifying the bytes).
pub type AppFinalizedSink = Arc<dyn Fn(AppShardFrame, Vec<u8>, bool) + Send + Sync>;

/// Build the full `AppShardFrame` from a produced consensus state + the leader's
/// recorded request bundles. Mirrors the finalized-frame rebuild at
/// `app_engine.rs:2805` but sourced from `AppShardState` (the fields carry
/// through losslessly). At propose time there is no committee quorum signature
/// yet — `verify` uses `validate_proposal` (VDF + structure), which doesn't
/// require one — so `public_key_signature_bls48581` is left `None`.
///
/// This is the pure core of the engine-supplied `AppFrameAssembler`: the engine's
/// closure reads `frame_requests[state.frame_number]` and calls this.
pub fn app_frame_from_state(
    state: &State<AppShardState>,
    requests: Vec<quil_types::proto::global::MessageBundle>,
    storage_attestation: Vec<u8>,
) -> AppShardFrame {
    let app = &state.state;
    let header = quil_types::proto::global::FrameHeader {
        address: app.filter.clone(),
        frame_number: app.frame_number,
        rank: app.rank,
        timestamp: app.timestamp,
        difficulty: app.difficulty,
        output: app.output.clone(),
        parent_selector: app.parent_selector.clone(),
        requests_root: app.requests_root.clone(),
        state_roots: app.state_roots.clone(),
        prover: app.prover.clone(),
        fee_multiplier_vote: app.fee_multiplier,
        public_key_signature_bls48581: None,
        storage_attestation_root: app.storage_attestation_root.clone(),
        global_frame_number: app.global_frame_number,
        ..Default::default()
    };
    // Proposer self storage-attestation (CW PoRep port): the serialized
    // `StorageAttestation` openings the leader stashed at prove time, decoded onto
    // the full frame so followers/archives + the global reward audit see them.
    // Empty blob → no attestation (pre-storage-fork / uncovered frame).
    let storage_attestation = if storage_attestation.is_empty() {
        None
    } else {
        <quil_types::proto::global::StorageAttestation as prost::Message>::decode(
            storage_attestation.as_slice(),
        )
        .ok()
    };
    AppShardFrame {
        header: Some(header),
        requests,
        storage_attestation,
    }
}

/// Frame identity (`Poseidon(output)[..32]`) as the consensus digest — identical
/// scheme to global (`AppShardState`/`GlobalFrame` share `compute_output_identity`).
fn app_frame_digest(frame: &AppShardFrame) -> Option<Digest> {
    let output = &frame.header.as_ref()?.output;
    let id = quil_crypto::poseidon::hash_bytes_to_32(output).ok()?;
    Some(digest_from_identity(id))
}

fn encode_app_frame(frame: &AppShardFrame) -> Vec<u8> {
    prost::Message::encode_to_vec(frame)
}

fn decode_app_frame(bytes: &[u8]) -> Option<AppShardFrame> {
    <AppShardFrame as prost::Message>::decode(bytes).ok()
}

/// Feed a peer-delivered block into the shared [`BlockStore`] so `verify` finds
/// the bytes behind a proposed digest. Drops malformed bytes; idempotent.
///
/// SECURITY — this path is UNVALIDATED. The node authorizes the sender only far
/// enough to resolve a peer key (`app_engine`'s `CwIn` handler), and nothing
/// here checks the frame: the VDF, the roots, and the parent linkage are all
/// `verify`'s job. Critically, the consensus digest is `Poseidon(header.output)`
/// and does NOT commit to `header.frame_number`, so a peer can pair any real
/// frame's `output` with any height it likes and have it land on the honest
/// frame's digest.
///
/// So this function stores bytes and NOTHING else — it must never record
/// digest→frame_number. `propose` reads that index for the height it builds on;
/// today the app leader provider treats that height as advisory (it resolves its
/// parent from the shard clock store) and `verify` no longer derives anything
/// from it, so a forged entry currently has no reachable consumer here. The
/// global twin is not so lucky — the same primitive halts the global chain
/// outright (see `cw_global_seams::ingest_global_block`) — and the app seam has
/// already carried a height-derived `verify` gate once. Keeping the index
/// unreachable from unvalidated input makes the property structural instead of a
/// standing invariant for every future reader of `block_meta`.
///
/// The block bytes themselves are safe to accept here: [`BlockStore`] seals the
/// exact bytes that pass `verify`, after which ingress cannot substitute a
/// different body under the same digest.
pub(crate) fn ingest_app_block(store: &BlockStore, bytes: Vec<u8>) {
    let Some(frame) = decode_app_frame(&bytes) else {
        tracing::debug!("cw app block ingress: undecodable frame, dropping");
        return;
    };
    let Some(header) = frame.header.as_ref() else { return };
    let Some(digest) = app_frame_digest(&frame) else { return };
    let claimed_frame_number = header.frame_number;
    store.put(digest, bytes);
    tracing::debug!(
        claimed_frame = claimed_frame_number,
        "cw app block ingress: stored peer frame (height unverified)",
    );
}

// ---------------------------------------------------------------------------
// Proposer (GlobalProposer seam)
// ---------------------------------------------------------------------------

/// Builds/validates app-shard frames via the engine's own `AppLeaderProvider`
/// (passed as `Arc<dyn LeaderProvider<AppShardState>>`) + `BlsAppFrameValidator`.
/// Engine-supplied proposal predicate run in `verify` BEFORE signing; returns
/// `true` iff the proposal is safe to sign. It performs the two body/state
/// integrity checks the lightweight seam validator can't (no exec manager /
/// inclusion prover / hypergraph):
/// - **body-root (audit #2)** — recompute `requests_root` from the carried
///   `frame.requests` and reject a mismatch, so every replica executes the one
///   body that matches the declared+certified root (no divergence);
/// - **pre-state `state_roots` (audit #3)** — when this node is EXACTLY at
///   frame N-1, recompute the 4 deterministic phase roots and reject if they
///   don't equal `header.state_roots`, so an honest member never signs a
///   leader's false pre-state root claim; a behind/lagged member abstains
///   (signs) so it can't spuriously nullify. Under the unified sharded model the
///   per-shard root is the covered SUBTREE root
///   (`sub_shard_commitment_for_filter`, computable from partial storage); legacy
///   pre-cutover uses the whole-app aggregate (`compute_shard_root`).
///
/// The engine builds it capturing its deps; `None` skips both checks (tests /
/// no-exec paths).
pub type AppRequestsRootCheck =
    Arc<dyn Fn(&quil_types::proto::global::AppShardFrame) -> bool + Send + Sync>;

pub struct AppSeamProposer {
    leader_provider: Arc<dyn LeaderProvider<AppShardState>>,
    validator: Arc<BlsAppFrameValidator>,
    assemble: AppFrameAssembler,
    filter: Vec<u8>,
    /// digest → frame_number (resolves the parent frame number from the simplex
    /// parent digest, which carries only the identity). VALIDATED WRITES ONLY —
    /// see [`ingest_app_block`] and [`AppSeamProposer::note_frame`].
    block_meta: Arc<Mutex<HashMap<Digest, u64>>>,
    /// Body-root cross-check (audit Finding #2); see [`AppRequestsRootCheck`].
    requests_root_check: Option<AppRequestsRootCheck>,
}

impl AppSeamProposer {
    pub fn new(
        leader_provider: Arc<dyn LeaderProvider<AppShardState>>,
        validator: Arc<BlsAppFrameValidator>,
        assemble: AppFrameAssembler,
        filter: Vec<u8>,
        requests_root_check: Option<AppRequestsRootCheck>,
    ) -> Self {
        Self {
            leader_provider,
            validator,
            assemble,
            filter,
            block_meta: Arc::new(Mutex::new(HashMap::new())),
            requests_root_check,
        }
    }

    /// Record digest → frame_number for a block whose bytes this node has
    /// VALIDATED (built in `propose`, accepted in `verify`) or that it read from
    /// its own committed store (the activation seed). Never call this with a
    /// height learned from a peer — that is the poisoning primitive documented
    /// on [`ingest_app_block`].
    pub fn note_frame(&self, digest: Digest, frame_number: u64) {
        self.block_meta.lock().unwrap().insert(digest, frame_number);
    }

}

impl GlobalProposer for AppSeamProposer {
    fn propose(&self, view: u64, parent_digest: Digest) -> Option<(Digest, Vec<u8>)> {
        let prior_state_id: Vec<u8> = digest_to_identity(&parent_digest).to_vec();
        let prior_frame_number = self
            .block_meta
            .lock()
            .unwrap()
            .get(&parent_digest)
            .copied()
            .unwrap_or(0);

        // App shards resolve their parent from the shard clock store internally,
        // so `prior_frame_number` is advisory; `prior_state_id` is the identity.
        let state = match self.leader_provider.prove_next_state(
            view,
            &self.filter,
            prior_frame_number,
            &prior_state_id,
        ) {
            Ok(state) => state,
            Err(e) => {
                // Surface WHY (mirrors the global seam). Swallowing this is how a
                // shard halt becomes invisible: the leader nullifies its own view
                // with no on-disk signal, and across all leaders the shard spins
                // through views producing nothing.
                tracing::warn!(
                    view,
                    prior_frame_number,
                    parent = %hex::encode(&prior_state_id),
                    error = %e,
                    "cw app propose: prove_next_state failed — cannot build a proposal \
                     (view nullifies)",
                );
                return None;
            }
        };

        // The engine assembles the FULL frame (header + recorded requests).
        let frame = (self.assemble)(&state)?;
        let digest = app_frame_digest(&frame)?;
        let frame_number = frame.header.as_ref()?.frame_number;
        let bytes = encode_app_frame(&frame);

        self.block_meta.lock().unwrap().insert(digest, frame_number);
        Some((digest, bytes))
    }

    fn verify(&self, _view: u64, digest: Digest, bytes: Option<Vec<u8>>) -> bool {
        let Some(bytes) = bytes else {
            tracing::warn!("cw app verify: block not delivered (nullify)");
            return false;
        };
        let Some(frame) = decode_app_frame(&bytes) else {
            tracing::warn!("cw app verify: undecodable block (nullify)");
            return false;
        };
        let Some(header) = frame.header.as_ref() else {
            return false;
        };
        if app_frame_digest(&frame) != Some(digest) {
            tracing::warn!(frame = header.frame_number, "cw app verify: digest mismatch");
            return false;
        }
        // Proposal-mode validation: VDF + structure, no committee QC required yet.
        match self.validator.validate_proposal(&frame) {
            Ok(true) => {
                // Body-root cross-check (audit Finding #2). `validate_proposal`
                // recomputes the output from the DECLARED `requests_root` but
                // never checks the carried `frame.requests` against it, so a
                // proposal can pair a legitimate header/root with a mismatched
                // body. Reject before signing so no honest member certifies a
                // body its declared (and soon certified) root does not cover.
                // audit residual #3: a wired check that FAILS is fail-closed
                // (nullify). A committee member with NO check wired (missing
                // execution engine / inclusion prover / hypergraph) cannot validate
                // the body or pre-state — it votes blind. Production always wires the
                // check; hard-nullifying the unwired case would break lightweight /
                // relay committee members and the test harness, so we WARN loudly
                // (was silent) so the misconfiguration is visible + alertable, but
                // still sign. (Requiring state to vote is a committee-policy change.)
                match self.requests_root_check.as_ref() {
                    Some(check) => {
                        if !check(&frame) {
                            tracing::warn!(
                                frame = header.frame_number,
                                "cw app verify: requests_root/state-root check failed \
                                 (body/pre-state does not match declared roots) — nullify",
                            );
                            return false;
                        }
                    }
                    None => {
                        tracing::warn!(
                            frame = header.frame_number,
                            "cw app verify: NO requests_root/state-root check wired \
                             (stateless committee member voting WITHOUT validation) — \
                             signing blind; wire execution engine + inclusion prover + \
                             hypergraph to validate",
                        );
                    }
                }
                self.block_meta
                    .lock()
                    .unwrap()
                    .insert(digest, header.frame_number);
                true
            }
            other => {
                tracing::warn!(frame = header.frame_number, result = ?other, "cw app verify: validate failed");
                false
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Sink (FrameSink seam) — ships block bytes to the shard committee.
// ---------------------------------------------------------------------------

/// Carries app-shard simplex channel messages over the node's per-shard gossip
/// (`shard_consensus_bitmask`) — the app analog of `GlobalConsensusTransport`.
/// The node implements this over BlossomSub; `channel` is tagged so the peer
/// demuxes back to the right simplex channel (0=vote,1=cert,2=resolver,3=block).
pub trait AppConsensusTransport: Send + Sync + 'static {
    fn deliver(&self, channel: u64, recipients: Vec<FalconPublicKey>, bytes: Vec<u8>);
}

/// Ships the full app frame bytes to the shard committee over the CW block channel.
pub struct AppSeamSink {
    transport: Arc<dyn AppConsensusTransport>,
    peers: Arc<[FalconPublicKey]>,
}

impl AppSeamSink {
    pub fn new(transport: Arc<dyn AppConsensusTransport>, peers: Arc<[FalconPublicKey]>) -> Self {
        Self { transport, peers }
    }
}

impl FrameSink for AppSeamSink {
    fn broadcast(&self, _digest: Digest, bytes: Vec<u8>, recipients: Recipients<FalconPublicKey>) {
        let to: Vec<FalconPublicKey> = match recipients {
            Recipients::All => self.peers.to_vec(),
            Recipients::Some(r) => r,
            Recipients::One(r) => vec![r],
        };
        self.transport.deliver(CW_APP_BLOCK_CHANNEL, to, bytes);
    }
}

// ---------------------------------------------------------------------------
// Finalizer (FrameFinalizer seam) — materialize on finalize.
// ---------------------------------------------------------------------------

/// Materializes finalized app frames + writes candidates on notarize, via
/// engine-supplied callbacks (materialize + full-frame publish live in the
/// engine, keyed by the per-shard hypergraph the seam has no handle to).
pub struct AppSeamFinalizer {
    /// Called on notarize with the (uncommitted) frame — optional candidate persist.
    on_notarized: AppFrameSink,
    /// Called on finalize — materialize + publish the full frame + coverage. Also
    /// receives the serialized finalization certificate for reward attribution.
    on_finalized: AppFinalizedSink,
}

impl AppSeamFinalizer {
    pub fn new(on_notarized: AppFrameSink, on_finalized: AppFinalizedSink) -> Self {
        Self { on_notarized, on_finalized }
    }
}

impl FrameFinalizer for AppSeamFinalizer {
    fn on_notarized(&self, _view: u64, _digest: Digest, bytes: Option<Vec<u8>>) {
        let Some(bytes) = bytes else { return };
        let Some(frame) = decode_app_frame(&bytes) else { return };
        (self.on_notarized)(frame);
    }

    fn on_finalized(
        &self,
        _view: u64,
        _digest: Digest,
        bytes: Option<Vec<u8>>,
        cert: Option<Vec<u8>>,
        locally_verified: bool,
    ) {
        let Some(bytes) = bytes else { return };
        let Some(frame) = decode_app_frame(&bytes) else { return };
        (self.on_finalized)(frame, cert.unwrap_or_default(), locally_verified);
    }
}

// ---------------------------------------------------------------------------
// Live activation (analog of `cw_global_seams::activate_global_consensus_cw`).
// ---------------------------------------------------------------------------

use quil_cw_consensus::adapters::BlockStore;
use quil_cw_consensus::engine_host::{spawn_global_host, GlobalEngineParams, GlobalHostHandle};
use quil_cw_consensus::falcon_simplex::SimplexFalconScheme;

/// Assemble an app-shard CW committee from the shard's active provers.
///
/// EQUAL VOTES: reuses the count-based [`build_global_committee`] — there is no
/// seniority weighting in the CW path (that was the legacy app-shard model this
/// migration drops). The committee members are the active provers' Falcon
/// `public_key`s (the same keys `BlsAppFrameValidator` verifies votes against);
/// this node signs with its own q-prover-key (`my_signing_key`/`my_public_key`).
/// The domain namespace is `b"appshard"‖app_address`, matching the legacy app
/// vote domain so the Falcon domain separation is shard-scoped.
///
/// Returns `None` if any key is malformed, the set is empty, or this node's key
/// is not in the active set.
pub fn build_app_committee(
    member_pubkeys: &[Vec<u8>],
    my_signing_key: &[u8],
    my_public_key: &[u8],
    app_address: &[u8],
) -> Option<(SimplexFalconScheme, Arc<[FalconPublicKey]>)> {
    let mut namespace = b"appshard".to_vec();
    namespace.extend_from_slice(app_address);
    let committee = quil_cw_consensus::committee::build_global_committee(
        member_pubkeys,
        my_signing_key,
        my_public_key,
        &namespace,
    )?;
    Some((committee.scheme, committee.peers))
}

/// The engine's handle to a running simplex-backed app-shard consensus. On each
/// inbound CW‑tagged shard‑consensus message the node demuxes the channel id:
/// - channels 0/1/2 (vote/cert/resolver) → `inbound[channel].send(...)`;
/// - channel 3 (block) → `ingest_block(bytes)` (feeds the shared `BlockStore`).
pub struct AppConsensusCwHandle {
    pub inbound:
        [tokio::sync::mpsc::UnboundedSender<quil_cw_consensus::p2p_bridge::Message<FalconPublicKey>>; 3],
    /// Feed a peer-delivered app frame's bytes into the engine's `BlockStore`,
    /// so `verify` finds the block behind a proposed digest. Stores bytes only —
    /// nothing a peer claims about a frame's height is recorded. Idempotent;
    /// drops malformed bytes. See [`ingest_app_block`].
    pub ingest_block: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
    /// Cooperative shutdown flag for the simplex host thread. Set it to stop this
    /// instance (the engine drops + the runtime thread returns) — used to REBUILD
    /// the committee when the shard's active-prover set changes.
    pub shutdown: Arc<std::sync::atomic::AtomicBool>,
}

/// Assemble + start the simplex-backed app-shard consensus for one shard.
/// Must be called from within the node's tokio runtime (spawns the outbound
/// drain there); the engine runs on its own runtime thread.
///
/// `namespace` = `b"appshard"‖app_address` (matches the legacy app vote domain).
/// `partition` should be unique per shard (e.g. `app-<filter-hex>`).
#[allow(clippy::too_many_arguments)]
pub fn activate_app_consensus_cw(
    scheme: SimplexFalconScheme,
    peers: Arc<[FalconPublicKey]>,
    leader_provider: Arc<dyn LeaderProvider<AppShardState>>,
    validator: Arc<BlsAppFrameValidator>,
    assemble: AppFrameAssembler,
    on_notarized: AppFrameSink,
    on_finalized: AppFinalizedSink,
    filter: Vec<u8>,
    partition: String,
    epoch: u64,
    genesis_digest: Digest,
    genesis_frame_number: u64,
    leader_timeout_secs: u64,
    transport: Arc<dyn AppConsensusTransport>,
    // Persistent per-shard simplex-journal dir. `Some(dir)` resumes across
    // restarts; `None` uses the runtime default (ephemeral random temp).
    storage_directory: Option<std::path::PathBuf>,
    // Body-root cross-check for the verify path (audit Finding #2); see
    // [`AppRequestsRootCheck`]. `None` skips it (tests / no-exec).
    requests_root_check: Option<AppRequestsRootCheck>,
) -> AppConsensusCwHandle {
    let proposer = Arc::new(AppSeamProposer::new(
        leader_provider,
        validator,
        assemble,
        filter,
        requests_root_check,
    ));
    // Seed the genesis parent so the first proposal resolves its frame number.
    proposer.note_frame(genesis_digest, genesis_frame_number);
    let sink = Arc::new(AppSeamSink::new(transport.clone(), peers.clone()));
    let finalizer = Arc::new(AppSeamFinalizer::new(on_notarized, on_finalized));

    let store = BlockStore::new();

    // Cooperative shutdown so the caller can stop this instance to rebuild the
    // committee (dynamic app-shard membership).
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let GlobalHostHandle { inbound, mut outbound } = spawn_global_host(
        scheme,
        peers,
        proposer.clone(),
        sink,
        finalizer,
        store.clone(),
        GlobalEngineParams::new(partition, epoch, genesis_digest)
            .with_leader_timeout_secs(leader_timeout_secs),
        storage_directory,
        Some(shutdown.clone()),
    );

    // Drain the engine's outbound (votes/certs/resolver) onto the shard transport.
    tokio::spawn(async move {
        while let Some(ob) = outbound.recv().await {
            transport.deliver(ob.channel, ob.recipients, ob.bytes);
        }
    });

    // Block ingress: decode a peer app frame, compute its identity digest, and
    // store the bytes so `verify` can find them. Deliberately has NO handle on
    // the proposer's digest→frame-number index — see [`ingest_app_block`].
    let ingest_block: Arc<dyn Fn(Vec<u8>) + Send + Sync> = {
        let store = store.clone();
        Arc::new(move |bytes: Vec<u8>| ingest_app_block(&store, bytes))
    };

    AppConsensusCwHandle { inbound, ingest_block, shutdown }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::Signer as _;

    #[test]
    fn app_committee_builds_and_scopes_by_shard() {
        // This node + 2 other shard members.
        let me = quil_crypto::FalconSigner::generate();
        let others: Vec<quil_crypto::FalconSigner> =
            (0..2).map(|_| quil_crypto::FalconSigner::generate()).collect();
        let mut members: Vec<Vec<u8>> = others.iter().map(|s| s.public_key().to_vec()).collect();
        members.push(me.public_key().to_vec());

        let app_a = vec![0xAAu8; 32];
        let (_scheme, peers) = build_app_committee(
            &members,
            me.private_key(),
            me.public_key(),
            &app_a,
        )
        .expect("app committee builds");
        assert_eq!(peers.len(), 3);

        // A different shard address yields a distinct domain (scheme differs),
        // but the same member set → same peer set.
        let app_b = vec![0xBBu8; 32];
        let (_scheme_b, peers_b) =
            build_app_committee(&members, me.private_key(), me.public_key(), &app_b)
                .expect("app committee builds for shard B");
        assert_eq!(peers_b.len(), 3);

        // A node not in the active set cannot build a signer.
        let outsider = quil_crypto::FalconSigner::generate();
        assert!(build_app_committee(
            &members,
            outsider.private_key(),
            outsider.public_key(),
            &app_a,
        )
        .is_none());
    }
    /// An app frame carrying `output` at `frame_number`. Only the fields the
    /// digest and the parent checks read are meaningful.
    fn test_frame(filter: &[u8], frame_number: u64, output: &[u8]) -> AppShardFrame {
        AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                address: filter.to_vec(),
                frame_number,
                output: output.to_vec(),
                ..Default::default()
            }),
            requests: vec![],
            storage_attestation: None,
        }
    }

    /// The attack behind the #593 review comments, at the unit level: the
    /// consensus digest is `Poseidon(output)` and does not commit to
    /// `frame_number`, so a peer can gossip a real frame's `output` under a
    /// forged height and land on the honest frame's digest. Ingress must not be
    /// able to move the height that `propose`/`verify` then trust.
    #[test]
    fn peer_ingress_cannot_forge_the_parent_height() {
        let filter = vec![0x55u8; 32];
        let honest = test_frame(&filter, 7, b"honest-output");
        let digest = app_frame_digest(&honest).expect("frame digests");

        // What `verify` records once the honest parent passes validation.
        let meta: Mutex<HashMap<Digest, u64>> = Mutex::new(HashMap::new());
        meta.lock().unwrap().insert(digest, 7);

        let store = BlockStore::new();
        ingest_app_block(&store, encode_app_frame(&honest));

        // Attacker: identical `output` (→ identical digest), forged height.
        let mut forged = honest.clone();
        forged.header.as_mut().unwrap().frame_number = u64::MAX / 2;
        assert_eq!(
            app_frame_digest(&forged),
            Some(digest),
            "the forgery must collide with the honest digest or it models nothing",
        );
        ingest_app_block(&store, encode_app_frame(&forged));

        assert_eq!(
            meta.lock().unwrap().get(&digest).copied(),
            Some(7),
            "unvalidated peer ingress moved the parent height",
        );

        // Delivery still works, and the sealed bytes are immutable afterwards.
        let honest_bytes = encode_app_frame(&honest);
        store.seal(digest, honest_bytes.clone());
        ingest_app_block(&store, encode_app_frame(&forged));
        assert_eq!(store.get(&digest), Some(honest_bytes));
    }

    /// The hardening must not cost block delivery: `verify` reads the proposed
    /// block out of the store, so ingress still has to put bytes there.
    #[test]
    fn peer_ingress_still_delivers_block_bytes() {
        let filter = vec![0x55u8; 32];
        let frame = test_frame(&filter, 3, b"delivered-output");
        let digest = app_frame_digest(&frame).expect("frame digests");
        let bytes = encode_app_frame(&frame);

        let store = BlockStore::new();
        ingest_app_block(&store, bytes.clone());
        assert_eq!(store.get(&digest), Some(bytes.clone()));

        // Once the exact bytes pass validation they are sealed, and later
        // ingress cannot substitute a different body under the same digest.
        store.seal(digest, bytes.clone());
        let mut swapped = frame.clone();
        swapped.header.as_mut().unwrap().frame_number = 999;
        ingest_app_block(&store, encode_app_frame(&swapped));
        assert_eq!(store.get(&digest), Some(bytes));

        ingest_app_block(&store, b"not a frame".to_vec());
    }
}

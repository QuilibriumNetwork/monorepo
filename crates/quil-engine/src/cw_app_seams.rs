//! Real-state implementations of the commonware-simplex consensus seams for
//! APP-SHARD consensus. Analogous to [`crate::cw_global_seams`] but for the
//! per-shard chains.
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
//! checks the deterministic output, storage attestation and structure), but the block shipped to peers must
//! carry the FULL frame so `on_finalized` can materialize it.
//!
//! The three commonware seam traits are reused verbatim from
//! `quil_cw_consensus::adapters` — they are generic over the 32-byte `Sha256`
//! digest, so the `Global*` naming is incidental.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use quil_cw_consensus::adapters::{
    digest_from_identity, digest_to_identity, Digest, FrameFinalizer, FrameSink, GlobalProposer,
    Liveness, ProposalContext, Recipients, Step,
};
use quil_cw_consensus::falcon_base::FalconPublicKey;
use quil_cw_consensus::handoff::automaton::{HandoffProposer, ParentReader};
use quil_cw_consensus::handoff::{Seal, Session};

use quil_consensus::leader_provider::LeaderProvider;
use quil_consensus::models::State;
use quil_types::consensus::AppFrameValidator as _;
use quil_types::proto::global::AppShardFrame;

use crate::app_types::AppShardState;
use crate::frame_validator::BlsAppFrameValidator;

/// simplex channel id reserved for out-of-band app block (frame-bytes) delivery
/// — the app analog of `cw_global_seams::CW_BLOCK_CHANNEL`.
pub const CW_APP_BLOCK_CHANNEL: u64 = 3;

/// The simplex resolver's channel: requests for missing certificates and their
/// responses, each addressed to one committee member. The only channel whose
/// recipients travel to the network layer ([`crate::app_engine::AppEngineEvent::CwOut`]),
/// so it can be delivered directly instead of to the shard's whole topic.
pub const CW_APP_RESOLVER_CHANNEL: u64 = 2;

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
/// Return true only when the engine accepted the notification. Must be
/// nonblocking and must not re-enter the finalizer.
///
/// The last argument carries the frame's implied ancestors, lowest first, each
/// with its verified flag: frames the committee notarized without finalizing
/// on their own, which the finalized frame makes final (see
/// [`AppSeamFinalizer::implied_ancestors`]). They carry no certificate of
/// their own; the finalized frame's certificate authenticates them through
/// the parent links.
pub type AppFinalizedSink =
    Arc<dyn Fn(AppShardFrame, Vec<u8>, bool, Vec<(AppShardFrame, bool)>) -> bool + Send + Sync>;

/// Called with a finalized terminal seal's bytes and its finalization
/// certificate. Same contract as [`AppFinalizedSink`]: nonblocking, returns
/// true only when the engine accepted the notification. The last argument
/// carries the data frames the seal makes final that never finalized on their
/// own, lowest first, its checkpoint frame last (see
/// [`AppSeamFinalizer::seal_implied`]).
pub type AppSealedSink =
    Arc<dyn Fn(Vec<u8>, Vec<u8>, Vec<(AppShardFrame, bool)>) -> bool + Send + Sync>;

/// A globally authorized committee session for this host. Its namespace, epoch
/// and genesis replace the legacy `appshard‖filter` / epoch-zero configuration,
/// and proposals pass through the terminal-seal automaton.
pub struct SessionHost {
    pub session: Session,
    pub read_parent: ParentReader,
    /// Authorizes a selected parent that is notarized but not yet
    /// materialized, from its private execution (see `AppParentExecutor`).
    pub read_private_parent: Option<ParentReader>,
    /// Locally reconstruct the data state underlying an unmaterialized seal.
    pub read_private_checkpoint: Option<quil_cw_consensus::handoff::automaton::CheckpointReader>,
    /// The authorized checkpoint at the materialized tip, whatever the
    /// selection: what a re-seal of a notarized seal is checked against
    /// (`HandoffProposer::with_seal_parents`).
    pub read_tip: ParentReader,
    pub on_sealed: AppSealedSink,
    /// Records the session's votes and certificates for operators.
    pub liveness: Arc<quil_cw_consensus::adapters::Liveness>,
    /// Told whether each seal this member verifies shares its state roots
    /// (`HandoffProposer::with_checkpoint_votes`).
    pub checkpoint_votes: Option<quil_cw_consensus::handoff::automaton::CheckpointVotes>,
    /// Says why no closing request authorizes a seal, and whether a refresh
    /// of the committed GLOBAL view is on its way
    /// (`HandoffProposer::with_closing_probe`).
    pub closing_probe: Option<quil_cw_consensus::handoff::automaton::ClosingProbe>,
}

/// Build the full `AppShardFrame` from a produced consensus state + the leader's
/// recorded request bundles. Mirrors the finalized-frame rebuild at
/// `app_engine.rs:2805` but sourced from `AppShardState` (the fields carry
/// through losslessly). At propose time there is no committee quorum signature
/// yet — `verify` uses `validate_proposal` (deterministic output + storage + structure), which doesn't
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
        fee_total: quil_execution::global_intrinsic::frame_header::fee_total_field(app.fee_total),
        settlements: app.settlements.clone(),
        accumulator: app.accumulator.clone(),
        spends: app.spends.clone(),
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
pub(crate) fn app_frame_digest(frame: &AppShardFrame) -> Option<Digest> {
    let output = &frame.header.as_ref()?.output;
    let id = quil_crypto::poseidon::hash_bytes_to_32(output).ok()?;
    Some(digest_from_identity(id))
}

fn encode_app_frame(frame: &AppShardFrame) -> Vec<u8> {
    prost::Message::encode_to_vec(frame)
}

pub(crate) fn decode_app_frame(bytes: &[u8]) -> Option<AppShardFrame> {
    <AppShardFrame as prost::Message>::decode(bytes).ok()
}

// ---------------------------------------------------------------------------
// Proposer (GlobalProposer seam)
// ---------------------------------------------------------------------------

/// Builds/validates app-shard frames via the engine's own `AppLeaderProvider`
/// (passed as `Arc<dyn LeaderProvider<AppShardState>>`) + `BlsAppFrameValidator`.
/// Engine-supplied proposal predicate run in `verify` BEFORE signing; returns
/// `Ok` iff the proposal is safe to sign, else why not. It performs the two body/state
/// integrity checks the lightweight seam validator can't (no exec manager /
/// inclusion prover / hypergraph):
/// - **body-root** — recompute `requests_root` from the carried
///   `frame.requests` and reject a mismatch, so every replica executes the one
///   body that matches the declared+certified root (no divergence);
/// - **pre-state `state_roots`** — when this node is EXACTLY at
///   frame N-1, recompute the 4 deterministic phase roots and reject if they
///   don't equal `header.state_roots`, so an honest member never signs a
///   leader's false pre-state root claim; a lagging member rejects verification
///   until it catches up. Under the unified sharded model the
///   per-shard root is the covered SUBTREE root
///   (`sub_shard_commitment_for_filter`, computable from partial storage); legacy
///   pre-cutover uses the whole-app aggregate (`compute_shard_root`).
///
/// The engine builds it capturing its deps; `None` disables proposing and
/// verification because the body and state cannot be checked.
pub type AppRequestsRootCheck = Arc<
    dyn Fn(&quil_types::proto::global::AppShardFrame) -> Result<(), CheckRefusal> + Send + Sync,
>;

/// Why a proposal failed an [`AppRequestsRootCheck`]: a short reason, counted
/// per session ([`Liveness`]), and its specifics.
pub type CheckRefusal = (&'static str, String);

/// Durable copies of the proposal bodies this node SEALED: the ones it built
/// or verified, which are exactly the ones its votes refer to.
///
/// The consensus journal survives a restart and remembers every view this node
/// voted to notarize; the [`BlockStore`] holding the bytes behind those digests
/// does not. After a whole-committee restart the protocol then insists on a
/// parent nobody can produce: leaders cannot build on it, voters cannot check a
/// child against it, and a finalization for it has no frame to deliver. (A live
/// run wedged a shard exactly there.) Bodies are written before the vote can
/// leave the node and are dropped once a later frame is delivered.
pub struct SealedBodies {
    directory: std::path::PathBuf,
}

impl SealedBodies {
    pub fn open(directory: std::path::PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&directory)?;
        Ok(Self { directory })
    }

    fn path(&self, digest: &Digest) -> std::path::PathBuf {
        self.directory.join(hex::encode(digest_to_identity(digest)))
    }

    /// Write-then-rename, synced: a torn file must never be read back as a body.
    fn persist(&self, digest: &Digest, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        let path = self.path(digest);
        if path.exists() {
            return Ok(());
        }
        let staged = path.with_extension("tmp");
        let mut file = std::fs::File::create(&staged)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&staged, &path)?;
        std::fs::File::open(&self.directory)?.sync_all()
    }

    /// Every body whose file name is the identity of its own contents. Anything
    /// else (a stray or damaged file) is removed rather than trusted.
    fn load(&self) -> std::io::Result<Vec<(Digest, Vec<u8>)>> {
        let mut bodies = Vec::new();
        for entry in std::fs::read_dir(&self.directory)? {
            let path = entry?.path();
            let bytes = std::fs::read(&path)?;
            let named = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| hex::decode(n).ok());
            let actual = if Seal::is_encoding(&bytes) {
                Seal::decode(&bytes).ok().map(|seal| seal.digest())
            } else {
                decode_app_frame(&bytes)
                    .as_ref()
                    .and_then(app_frame_digest)
                    .map(|d| digest_to_identity(&d))
            };
            match (named, actual) {
                (Some(named), Some(actual)) if named == actual => {
                    bodies.push((digest_from_identity(actual), bytes))
                }
                _ => {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        Ok(bodies)
    }

    /// Drop data-frame bodies at or below a delivered frame; they can no longer
    /// be a parent anyone needs.
    fn prune_through(&self, frame_number: u64) {
        let Ok(entries) = std::fs::read_dir(&self.directory) else {
            return;
        };
        for path in entries.flatten().map(|entry| entry.path()) {
            let stale = std::fs::read(&path)
                .ok()
                .and_then(|bytes| decode_app_frame(&bytes))
                .and_then(|frame| frame.header.map(|h| h.frame_number))
                .is_some_and(|number| number <= frame_number);
            if stale {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

/// Durable copies of finalized data frames, with their finalization
/// certificates, kept until the engine has materialized them.
///
/// Delivery to the engine is a nonblocking queue send. A frame whose delivery
/// was queued but not yet committed by the engine is gone after a restart: the
/// restarted instance resumes from the engine's certified head, and Simplex
/// does not report a finalization again. A sole-member shard can lose frame 2
/// that way: the restarted instance finalizes frame 3 on top of it, no node
/// holds frame 2, and every archive's sequenced ingest waits on it forever, so
/// GLOBAL halts. Records are written before the queue send, pruned
/// only below the engine's materialized cursor, and replayed at host start.
pub struct FinalizedRecords {
    directory: std::path::PathBuf,
}

impl FinalizedRecords {
    pub fn open(directory: std::path::PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&directory)?;
        Ok(Self { directory })
    }

    fn path(&self, frame_number: u64) -> std::path::PathBuf {
        self.directory.join(format!("{frame_number:020}"))
    }

    fn implied_path(&self, frame_number: u64) -> std::path::PathBuf {
        self.directory.join(format!("{frame_number:020}.implied"))
    }

    fn write_synced(
        &self,
        path: &std::path::Path,
        staged: &std::path::Path,
        record: &[u8],
    ) -> std::io::Result<()> {
        if std::fs::read(path).is_ok_and(|present| present == record) {
            return Ok(());
        }
        std::fs::write(staged, record)?;
        std::fs::File::open(staged)?.sync_all()?;
        std::fs::rename(staged, path)?;
        std::fs::File::open(&self.directory)?.sync_all()
    }

    /// A frame the committee notarized that a finalized descendant makes
    /// final: `locally_verified (1) ‖ frame bytes`. It is delivered again only
    /// with a certified descendant that links to it, never on its own.
    fn persist_implied(
        &self,
        frame_number: u64,
        verified: bool,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        let mut record = Vec::with_capacity(1 + bytes.len());
        record.push(verified as u8);
        record.extend_from_slice(bytes);
        let staged = self
            .directory
            .join(format!("{frame_number:020}.implied-staged"));
        self.write_synced(&self.implied_path(frame_number), &staged, &record)
    }

    /// `cert_len (4, BE) ‖ cert ‖ locally_verified (1) ‖ frame bytes`;
    /// write-then-rename, synced. The latest delivery of a frame number wins;
    /// an identical record is not rewritten (backpressured deliveries retry).
    fn persist(
        &self,
        frame_number: u64,
        cert: &[u8],
        verified: bool,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        let path = self.path(frame_number);
        let cert_len = u32::try_from(cert.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "certificate too large")
        })?;
        let mut record = Vec::with_capacity(5 + cert.len() + bytes.len());
        record.extend_from_slice(&cert_len.to_be_bytes());
        record.extend_from_slice(cert);
        record.push(verified as u8);
        record.extend_from_slice(bytes);
        let staged = path.with_extension("tmp");
        self.write_synced(&path, &staged, &record)
    }

    /// The frame number a record's file name carries, and whether it is an
    /// implied ancestor. `None` for anything else, including staged writes.
    fn record_name(path: &std::path::Path) -> Option<(u64, bool)> {
        let name = path.file_name()?.to_str()?;
        match name.strip_suffix(".implied") {
            Some(number) => Some((number.parse().ok()?, true)),
            None => Some((name.parse().ok()?, false)),
        }
    }

    /// Records above `after`, in frame order: `(frame_number, frame bytes,
    /// cert, locally_verified)`, with no cert for an implied ancestor. A
    /// record that does not decode to a frame of its own number is removed
    /// rather than trusted.
    fn load_above(
        &self,
        after: u64,
    ) -> std::io::Result<Vec<(u64, Vec<u8>, Option<Vec<u8>>, bool)>> {
        let mut records = Vec::new();
        for entry in std::fs::read_dir(&self.directory)? {
            let path = entry?.path();
            let named = Self::record_name(&path);
            let bytes = std::fs::read(&path)?;
            let parsed = (|| {
                let (cert, rest) = if named?.1 {
                    (None, bytes.as_slice())
                } else {
                    let (cert_len, rest) = bytes.split_first_chunk::<4>()?;
                    let cert_len = u32::from_be_bytes(*cert_len) as usize;
                    (Some(rest.get(..cert_len)?.to_vec()), rest.get(cert_len..)?)
                };
                let (&verified, frame) = rest.split_first()?;
                let number = decode_app_frame(frame)?.header?.frame_number;
                Some((number, frame.to_vec(), cert, verified == 1))
            })();
            match (named, parsed) {
                (Some((named, _)), Some(record)) if named == record.0 => {
                    if record.0 > after {
                        records.push(record);
                    }
                }
                _ => {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        records.sort_by_key(|record| (record.0, record.2.is_some()));
        Ok(records)
    }

    /// Drop records above `frame_number`: frames a GLOBAL fence discarded,
    /// after the shard rewound to the fence.
    pub(crate) fn discard_above(&self, frame_number: u64) {
        let Ok(entries) = std::fs::read_dir(&self.directory) else {
            return;
        };
        for path in entries.flatten().map(|entry| entry.path()) {
            let discarded =
                Self::record_name(&path).is_some_and(|(number, _)| number > frame_number);
            if discarded {
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    /// Drop records of frames anchored before GLOBAL frame `activation`: a
    /// committee-handoff flag day discarded that history, and every session
    /// frame anchors at or after it. Returns how many were dropped.
    pub(crate) fn discard_anchored_before(&self, activation: u64) -> usize {
        let Ok(records) = self.load_above(0) else {
            return 0;
        };
        let mut dropped = 0;
        for (number, bytes, cert, _) in records {
            let anchored = decode_app_frame(&bytes)
                .and_then(|frame| frame.header)
                .map_or(0, |h| h.global_frame_number);
            if anchored < activation {
                let path = if cert.is_some() {
                    self.path(number)
                } else {
                    self.implied_path(number)
                };
                if std::fs::remove_file(path).is_ok() {
                    dropped += 1;
                }
            }
        }
        dropped
    }

    /// Drop records at or below a materialized frame.
    fn prune_through(&self, frame_number: u64) {
        let Ok(entries) = std::fs::read_dir(&self.directory) else {
            return;
        };
        for path in entries.flatten().map(|entry| entry.path()) {
            let done = Self::record_name(&path).is_some_and(|(number, _)| number <= frame_number);
            if done {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

/// Gives terminal seals the durability [`AppSeamProposer`] gives data frames.
/// The handoff automaton builds and verifies seals itself, above the data
/// proposer, so they pass through here on their way to the vote.
struct PersistingSeals<P> {
    inner: P,
    bodies: Option<Arc<SealedBodies>>,
}

impl<P> PersistingSeals<P> {
    fn keep(&self, digest: &Digest, bytes: &[u8]) -> bool {
        match self.bodies.as_ref().filter(|_| Seal::is_encoding(bytes)) {
            Some(bodies) => bodies
                .persist(digest, bytes)
                .inspect_err(|error| {
                    tracing::warn!(%error, "cw app: could not persist a terminal seal; abstaining");
                })
                .is_ok(),
            None => true,
        }
    }
}

impl<P: GlobalProposer> GlobalProposer for PersistingSeals<P> {
    fn propose(&self, view: u64, parent: Digest) -> Option<(Digest, Vec<u8>)> {
        self.inner.propose(view, parent)
    }
    fn verify(&self, view: u64, parent: Digest, digest: Digest, bytes: Option<Vec<u8>>) -> bool {
        self.inner.verify(view, parent, digest, bytes)
    }
    fn propose_retry(&self) -> Option<std::time::Duration> {
        self.inner.propose_retry()
    }
    fn proposal_pacing(&self, context: ProposalContext) -> Option<std::time::Duration> {
        self.inner.proposal_pacing(context)
    }
    fn verify_delay(&self, context: ProposalContext, bytes: &[u8]) -> Option<std::time::Duration> {
        self.inner.verify_delay(context, bytes)
    }
    fn propose_with_context(
        &self,
        context: quil_cw_consensus::adapters::ProposalContext,
    ) -> Option<(Digest, Vec<u8>)> {
        self.inner
            .propose_with_context(context)
            .filter(|(digest, bytes)| self.keep(digest, bytes))
    }
    fn verify_with_context(
        &self,
        context: quil_cw_consensus::adapters::ProposalContext,
        digest: Digest,
        bytes: Option<Vec<u8>>,
    ) -> bool {
        let copy = bytes.clone();
        self.inner.verify_with_context(context, digest, bytes)
            && copy.is_none_or(|bytes| self.keep(&digest, &bytes))
    }
}

pub struct AppSeamProposer {
    leader_provider: Arc<dyn LeaderProvider<AppShardState>>,
    validator: Arc<BlsAppFrameValidator>,
    assemble: AppFrameAssembler,
    filter: Vec<u8>,
    /// digest → frame_number (resolves the parent frame number from the simplex
    /// parent digest, which carries only the identity).
    block_meta: Arc<Mutex<HashMap<Digest, u64>>>,
    /// Body-root cross-check; see [`AppRequestsRootCheck`].
    requests_root_check: Option<AppRequestsRootCheck>,
    /// Whether this member has staged the covered sub-shard's committed data into
    /// its own CRDT. A member covers its shard's DATA before it can honestly
    /// produce/attest: without the leaves, `build_vote_openings` yields no storage
    /// openings, so the frame carries no attestation and the global proof-of-storage
    /// gate zeroes the shard reward. Until staged, proposal production and
    /// verification are disabled. Set true once the join-time / bootstrap
    /// data sync converges (see `AppEngineEvent::ShardDataBootstrapRequested`).
    data_ready: Arc<std::sync::atomic::AtomicBool>,
    /// See [`SealedBodies`]. `None` for an ephemeral (journal-less) host.
    sealed_bodies: Option<Arc<SealedBodies>>,
    /// The last declined turn was an expected skip (`no vote:`), which clears by
    /// itself: the cadence gate at the next global frame, an allocation on its
    /// way to Active at the next lifecycle step.
    paced: std::sync::atomic::AtomicBool,
    /// Executes a selected parent that is notarized but not yet materialized.
    private_parents: Option<Arc<crate::app_engine::AppParentExecutor>>,
    /// Wait for the parent to materialize before building on a private copy.
    /// A committee session's handoff proposer already waited.
    gate_private_proposals: bool,
    /// `(view, retries)` spent waiting for the selected parent to materialize.
    private_waits: Mutex<(u64, u32)>,
    /// Where a session notes why this member declines a turn or refuses a vote.
    liveness: Option<Arc<Liveness>>,
    /// Takes the unfinalized chain a proposal over a private parent builds
    /// on ([`Self::resend_parent_bodies`]).
    ancestor_sink: Option<Arc<dyn FrameSink>>,
    /// Bounds the re-send log lines while this host keeps re-sending.
    resent: Mutex<crate::bounded_warn::WarnLimiter<()>>,
}

/// How far ahead of this node's latest GLOBAL frame a proposal's anchor may
/// be and still be waited for rather than refused.
const ANCHOR_DEFER_AHEAD: u64 = 2;

/// Wait between checks of a proposal whose anchor is on its way.
const ANCHOR_DEFER: std::time::Duration = std::time::Duration::from_millis(250);

/// Proposal retries (250 ms apart) waiting for a selected parent to
/// materialize before a leader builds on a private execution of it. Normally
/// the parent finalizes and materializes moments after its notarization.
const PRIVATE_PARENT_WAITS: u32 = 12;

impl AppSeamProposer {
    pub fn new(
        leader_provider: Arc<dyn LeaderProvider<AppShardState>>,
        validator: Arc<BlsAppFrameValidator>,
        assemble: AppFrameAssembler,
        filter: Vec<u8>,
        requests_root_check: Option<AppRequestsRootCheck>,
        data_ready: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            leader_provider,
            validator,
            assemble,
            filter,
            block_meta: Arc::new(Mutex::new(HashMap::new())),
            requests_root_check,
            data_ready,
            sealed_bodies: None,
            paced: std::sync::atomic::AtomicBool::new(false),
            private_parents: None,
            gate_private_proposals: true,
            private_waits: Mutex::new((0, 0)),
            liveness: None,
            ancestor_sink: None,
            resent: Mutex::new(crate::bounded_warn::WarnLimiter::new()),
        }
    }

    pub fn with_liveness(mut self, liveness: Option<Arc<Liveness>>) -> Self {
        self.liveness = liveness;
        self
    }

    fn note(&self, step: Step, view: u64, reason: &'static str, detail: impl Into<String>) {
        if let Some(liveness) = self.liveness.as_ref() {
            liveness.note(step, view, reason, detail);
        }
    }

    pub(crate) fn with_private_parents(
        mut self,
        executor: Arc<crate::app_engine::AppParentExecutor>,
        gate_proposals: bool,
    ) -> Self {
        self.private_parents = Some(executor);
        self.gate_private_proposals = gate_proposals;
        self
    }

    pub fn with_sealed_bodies(mut self, bodies: Arc<SealedBodies>) -> Self {
        self.sealed_bodies = Some(bodies);
        self
    }

    fn with_ancestor_sink(mut self, sink: Arc<dyn FrameSink>) -> Self {
        self.ancestor_sink = Some(sink);
        self
    }

    /// Returns false when a durable copy is required and could not be written:
    /// the caller must then neither propose nor vote for these bytes.
    fn persist_sealed(&self, digest: &Digest, bytes: &[u8]) -> bool {
        let Some(bodies) = self.sealed_bodies.as_ref() else {
            return true;
        };
        match bodies.persist(digest, bytes) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(%error, "cw app: could not persist a sealed proposal body; abstaining");
                false
            }
        }
    }

    /// Build peer ingress without capturing the validated parent-height index.
    /// Peer bytes are candidates until consensus verifies them; the digest does
    /// not authenticate a claimed height. Only validated or recovered frames
    /// may populate `block_meta`.
    fn peer_ingress(self: &Arc<Self>, store: BlockStore) -> Arc<dyn Fn(Vec<u8>) + Send + Sync> {
        Arc::new(move |bytes: Vec<u8>| {
            if Seal::is_encoding(&bytes) {
                // A peer's terminal-seal proposal: a replaceable candidate until
                // this member's own automaton verifies it against its parent.
                if let Ok(seal) = Seal::decode(&bytes) {
                    store.put(digest_from_identity(seal.digest()), bytes);
                }
                return;
            }
            let Some(frame) = decode_app_frame(&bytes) else {
                tracing::debug!("cw app block ingress: undecodable frame, dropping");
                return;
            };
            let Some(header) = frame.header.as_ref() else {
                return;
            };
            let Some(digest) = app_frame_digest(&frame) else {
                return;
            };
            let frame_number = header.frame_number;
            store.put(digest, bytes);
            tracing::debug!(
                frame = frame_number,
                "cw app block ingress: stored peer frame"
            );
        })
    }

    /// Record the height of a validated or locally recovered frame.
    pub fn note_frame(&self, digest: Digest, frame_number: u64) {
        self.block_meta.lock().unwrap().insert(digest, frame_number);
    }

    fn recover_head(
        &self,
        store: &BlockStore,
        frame: &AppShardFrame,
    ) -> quil_types::error::Result<()> {
        let header = frame.header.as_ref().ok_or_else(|| {
            quil_types::error::QuilError::Internal("recovered app head has no header".into())
        })?;
        if header.address != self.filter {
            return Err(quil_types::error::QuilError::Internal(
                "recovered app head belongs to another shard".into(),
            ));
        }
        let digest = app_frame_digest(frame).ok_or_else(|| {
            quil_types::error::QuilError::Internal(
                "cannot derive recovered app head identity".into(),
            )
        })?;
        store.put(digest, encode_app_frame(frame));
        self.note_frame(digest, header.frame_number);
        Ok(())
    }
}

impl GlobalProposer for AppSeamProposer {
    fn propose_retry(&self) -> Option<std::time::Duration> {
        self.paced
            .load(std::sync::atomic::Ordering::Acquire)
            .then_some(std::time::Duration::from_millis(250))
    }

    fn propose(&self, view: u64, parent_digest: Digest) -> Option<(Digest, Vec<u8>)> {
        self.propose_with(self.leader_provider.as_ref(), view, parent_digest)
    }

    fn propose_with_context(&self, context: ProposalContext) -> Option<(Digest, Vec<u8>)> {
        let Some(parents) = self.private_parents.as_ref() else {
            return self.propose(context.view, context.parent);
        };
        match parents.is_canonical_parent(context.parent) {
            Ok(false) => {}
            // The tip, or a state this executor cannot read: the canonical path
            // decides exactly as it did before private parents existed.
            Ok(true) => {
                let proposal = self.propose(context.view, context.parent);
                if proposal.is_some() {
                    self.settle_resends();
                }
                return proposal;
            }
            Err(_) => return self.propose(context.view, context.parent),
        }
        if self.gate_private_proposals {
            let mut waits = self.private_waits.lock().unwrap_or_else(|e| e.into_inner());
            *waits = if waits.0 == context.view {
                (context.view, waits.1 + 1)
            } else {
                (context.view, 1)
            };
            if waits.1 <= PRIVATE_PARENT_WAITS {
                self.note(
                    Step::Propose,
                    context.view,
                    "waiting for the selected parent to materialize",
                    format!("parent view {}", context.parent_view),
                );
                self.paced.store(true, std::sync::atomic::Ordering::Release);
                return None;
            }
        }
        let (parent, leader) = match parents
            .prepare(context.parent, context.parent_view)
            .and_then(|parent| {
                parents
                    .leader_for(&parent, context.view)
                    .map(|leader| (parent, leader))
            }) {
            Ok(prepared) => prepared,
            Err(error) => {
                tracing::debug!(view = context.view, %error, "cw app propose: selected parent not executable privately");
                self.note(
                    Step::Propose,
                    context.view,
                    "selected parent not executable privately",
                    error.to_string(),
                );
                self.paced.store(true, std::sync::atomic::Ordering::Release);
                return None;
            }
        };
        let proposal = self.propose_with(leader.as_ref(), context.view, context.parent);
        // Only with a proposal that goes out: a declined turn is asked again
        // every 250 ms and would send the chain each time.
        if proposal.is_some() {
            self.resend_parent_bodies(&parent, context);
        }
        proposal
    }

    fn verify_with_context(
        &self,
        context: ProposalContext,
        digest: Digest,
        bytes: Option<Vec<u8>>,
    ) -> bool {
        let canonical = self.requests_root_check.as_ref();
        let leader = context.leader;
        let Some(parents) = self.private_parents.as_ref() else {
            return self.verify_with(
                canonical,
                leader,
                context.view,
                context.parent,
                digest,
                bytes,
            );
        };
        match parents.is_canonical_parent(context.parent) {
            Ok(false) => match parents.prepare(context.parent, context.parent_view) {
                Ok(parent) => self.verify_with(
                    Some(&parent.check),
                    leader,
                    context.view,
                    context.parent,
                    digest,
                    bytes,
                ),
                Err(error) => {
                    tracing::debug!(view = context.view, %error, "cw app verify: selected parent not executable privately");
                    // The canonical check then fails for lack of the parent;
                    // the private failure is the reason.
                    let verified = self.verify_with(
                        canonical,
                        leader,
                        context.view,
                        context.parent,
                        digest,
                        bytes,
                    );
                    if !verified {
                        self.note(
                            Step::Verify,
                            context.view,
                            "selected parent not executable privately",
                            error.to_string(),
                        );
                    }
                    verified
                }
            },
            Ok(true) | Err(_) => self.verify_with(
                canonical,
                leader,
                context.view,
                context.parent,
                digest,
                bytes,
            ),
        }
    }

    fn verify(&self, view: u64, parent: Digest, digest: Digest, bytes: Option<Vec<u8>>) -> bool {
        self.verify_with(
            self.requests_root_check.as_ref(),
            None,
            view,
            parent,
            digest,
            bytes,
        )
    }

    /// Waits while the proposal's anchored GLOBAL frame is just ahead of this
    /// node's latest: members build on a GLOBAL frame as soon as it
    /// finalizes, and one that receives it moments later refused (nullified)
    /// their proposals instead. The adapter asks again while the view lasts;
    /// an anchor further ahead, or one below this node's head (a hole), is
    /// checked and refused as before.
    fn verify_delay(&self, context: ProposalContext, bytes: &[u8]) -> Option<std::time::Duration> {
        let frame = decode_app_frame(bytes)?;
        let (wanted, Some(latest)) = self.validator.missing_global_anchor(&frame)? else {
            return None;
        };
        if wanted > latest && wanted - latest <= ANCHOR_DEFER_AHEAD {
            tracing::debug!(
                view = context.view,
                wanted,
                latest,
                "cw app verify: anchored global frame not here yet; deferring the vote"
            );
            self.note(
                Step::Verify,
                context.view,
                "anchored GLOBAL frame not here yet",
                format!("anchor {wanted}, latest {latest}"),
            );
            return Some(ANCHOR_DEFER);
        }
        None
    }
}

impl AppSeamProposer {
    fn propose_with(
        &self,
        leader_provider: &dyn LeaderProvider<AppShardState>,
        view: u64,
        parent_digest: Digest,
    ) -> Option<(Digest, Vec<u8>)> {
        self.paced
            .store(false, std::sync::atomic::Ordering::Release);
        // Don't take our leader turn until the covered shard's data is staged —
        // proposing on empty state produces a frame with no storage attestation
        // (reward withheld) and forks the shard's real state. Skipping lets the
        // view rotate to a staged member.
        if !self.data_ready.load(std::sync::atomic::Ordering::Acquire)
            || self.requests_root_check.is_none()
        {
            tracing::debug!(
                view,
                data_ready = self.data_ready.load(std::sync::atomic::Ordering::Acquire),
                validator = self.requests_root_check.is_some(),
                "cw app propose: not ready — skipping turn",
            );
            self.note(Step::Propose, view, self.unready_reason(), String::new());
            return None;
        }
        tracing::debug!(view, "cw app propose: building proposal");
        let prior_state_id: Vec<u8> = digest_to_identity(&parent_digest).to_vec();
        let Some(prior_frame_number) = self.block_meta.lock().unwrap().get(&parent_digest).copied()
        else {
            tracing::warn!(
                view,
                "cw app propose: parent block metadata unknown — skipping turn"
            );
            self.note(
                Step::Propose,
                view,
                "parent block unknown",
                hex::encode(&prior_state_id[..4]),
            );
            return None;
        };

        // The leader checks that its local shard head matches this exact
        // consensus-selected number and identity before building a child.
        let state = match leader_provider.prove_next_state(
            view,
            &self.filter,
            prior_frame_number,
            &prior_state_id,
        ) {
            Ok(state) => state,
            Err(error) => {
                // "no vote: …" is the expected skip while this leader's shard
                // head catches up to the chosen parent; anything else is a fault.
                // Every "no vote:" refusal clears by itself (the next global
                // frame, a lifecycle transition, a parent landing): hold the
                // turn rather than nullify at network speed.
                if error.to_string().contains("no vote:") {
                    self.paced.store(true, std::sync::atomic::Ordering::Release);
                }
                if error.to_string().contains("no vote:") {
                    tracing::debug!(view, prior_frame_number, %error, "cw app propose: parent not local yet — skipping turn");
                    self.note(
                        Step::Propose,
                        view,
                        "leader not ready to build on the parent",
                        format!("parent frame {prior_frame_number}: {error}"),
                    );
                } else {
                    tracing::warn!(view, prior_frame_number, %error, "cw app propose: prove_next_state failed — skipping turn");
                    self.note(
                        Step::Propose,
                        view,
                        "building the next state failed",
                        format!("parent frame {prior_frame_number}: {error}"),
                    );
                }
                return None;
            }
        };

        // The engine assembles the FULL frame (header + recorded requests).
        let Some(frame) = (self.assemble)(&state) else {
            tracing::warn!(
                view,
                prior_frame_number,
                "cw app propose: frame assembly failed — skipping turn"
            );
            self.note(
                Step::Propose,
                view,
                "frame assembly failed",
                format!("parent frame {prior_frame_number}"),
            );
            return None;
        };
        let (Some(header), Some(digest)) = (frame.header.as_ref(), app_frame_digest(&frame)) else {
            self.note(
                Step::Propose,
                view,
                "frame assembly failed",
                "no header or identity",
            );
            return None;
        };
        if header.address != self.filter
            || header.rank != view
            || header.parent_selector != parent_digest.as_ref()
        {
            tracing::warn!(
                view,
                "cw app propose: assembled frame changed the selected shard, view or parent"
            );
            self.note(
                Step::Propose,
                view,
                "assembled frame changed its shard, view or parent",
                String::new(),
            );
            return None;
        }
        let frame_number = header.frame_number;
        let bytes = encode_app_frame(&frame);

        if !self.persist_sealed(&digest, &bytes) {
            self.note(
                Step::Propose,
                view,
                "proposal body not persisted",
                String::new(),
            );
            return None;
        }
        self.block_meta.lock().unwrap().insert(digest, frame_number);
        Some((digest, bytes))
    }

    fn verify_with(
        &self,
        requests_root_check: Option<&AppRequestsRootCheck>,
        leader: Option<[u8; 32]>,
        view: u64,
        parent: Digest,
        digest: Digest,
        bytes: Option<Vec<u8>>,
    ) -> bool {
        // Approval is a vote and seals these bytes as locally verified. A
        // syncing member must never approve data it cannot validate.
        if !self.data_ready.load(std::sync::atomic::Ordering::Acquire)
            || requests_root_check.is_none()
        {
            tracing::warn!("cw app verify: state or validation dependencies unavailable");
            self.note(Step::Verify, view, self.unready_reason(), String::new());
            return false;
        }
        let Some(bytes) = bytes else {
            tracing::warn!("cw app verify: block not delivered (nullify)");
            self.note(Step::Verify, view, "block not delivered", String::new());
            return false;
        };
        let Some(frame) = decode_app_frame(&bytes) else {
            tracing::warn!("cw app verify: undecodable block (nullify)");
            self.note(
                Step::Verify,
                view,
                "undecodable block",
                format!("{} bytes", bytes.len()),
            );
            return false;
        };
        let Some(header) = frame.header.as_ref() else {
            self.note(Step::Verify, view, "undecodable block", "no header");
            return false;
        };
        if header.address != self.filter
            || header.rank != view
            || header.parent_selector != parent.as_ref()
        {
            tracing::warn!(
                view,
                rank = header.rank,
                "cw app verify: shard, view or parent mismatch"
            );
            self.note(
                Step::Verify,
                view,
                "shard, view or parent differs",
                format!(
                    "frame {} rank {}, shard matches {}, parent matches {}",
                    header.frame_number,
                    header.rank,
                    header.address == self.filter,
                    header.parent_selector == parent.as_ref(),
                ),
            );
            return false;
        }
        // Hash storage proofs (decided 2026-10-21): GLOBAL chains a frame's
        // openings root into its proposer's storage seat and kicks a member
        // that never proves what was chained there, so a frame must name the
        // view's leader as its proposer.
        let hash_storage = header.global_frame_number > 0
            && quil_types::consensus::hash_storage_proofs_at(
                quil_types::consensus::epoch_for_frame(header.global_frame_number),
            );
        if let Some(leader) =
            leader.filter(|leader| hash_storage && header.prover.as_slice() != leader)
        {
            tracing::warn!(view, frame = header.frame_number, prover = %hex::encode(&header.prover),
                leader = %hex::encode(leader), "cw app verify: the frame names another proposer than the view's leader");
            self.note(
                Step::Verify,
                view,
                "proposer is not the view's leader",
                format!("frame {}", header.frame_number),
            );
            return false;
        }
        if app_frame_digest(&frame) != Some(digest) {
            tracing::warn!(
                frame = header.frame_number,
                "cw app verify: digest mismatch"
            );
            self.note(
                Step::Verify,
                view,
                "digest mismatch",
                format!("frame {}", header.frame_number),
            );
            return false;
        }
        // Validate the app digest, storage attestation and structure before voting.
        match self.validator.validate_proposal(&frame) {
            Ok(true) => {
                // Body-root cross-check. `validate_proposal`
                // recomputes the output from the DECLARED `requests_root` but
                // never checks the carried `frame.requests` against it, so a
                // proposal can pair a legitimate header/root with a mismatched
                // body. Reject before signing so no honest member certifies a
                // body its declared (and soon certified) root does not cover.
                // Missing validation dependencies and failed checks both prevent
                // a vote. A node must finish synchronization before participating.
                match requests_root_check {
                    Some(check) => {
                        if let Err((reason, detail)) = check(&frame) {
                            tracing::warn!(
                                frame = header.frame_number, reason, %detail,
                                "cw app verify: requests_root/state-root check failed \
                                 (body/pre-state does not match declared roots) — nullify",
                            );
                            self.note(Step::Verify, view, reason, detail);
                            return false;
                        }
                    }
                    None => {
                        return false;
                    }
                }
                if !self.persist_sealed(&digest, &bytes) {
                    self.note(
                        Step::Verify,
                        view,
                        "proposal body not persisted",
                        String::new(),
                    );
                    return false;
                }
                self.block_meta
                    .lock()
                    .unwrap()
                    .insert(digest, header.frame_number);
                true
            }
            other => {
                tracing::warn!(frame = header.frame_number, result = ?other, "cw app verify: validate failed");
                let detail = match &other {
                    Err(error) => error.to_string(),
                    _ => "invalid".to_string(),
                };
                self.note(
                    Step::Verify,
                    view,
                    validation_reason(&detail),
                    format!("frame {}: {detail}", header.frame_number),
                );
                false
            }
        }
    }

    /// Queue the bodies of a private parent's unfinalized chain, oldest
    /// first, on the shard's consensus topic ahead of the proposal built on
    /// it, once a view was nullified since the parent's. A voter executes
    /// that chain before it can check the proposal, and holds a body only if
    /// the block channel delivered it: no peer serves bodies, and archives
    /// hold only finalized frames. A member that missed one refuses every
    /// child of the parent, and a committee one vote short of quorum stays
    /// stuck, since finalizing the parent takes a child's quorum. Right after
    /// the parent's view every member that voted for it holds it, and the
    /// parent usually finalizes moments later: nothing is re-sent then.
    /// Receivers keep the bodies as candidates (peer ingress) and validate
    /// the whole chain before voting. At most `MAX_PRIVATE_CHAIN` bodies per
    /// proposal; none once the parent materializes. Returns how many went.
    fn resend_parent_bodies(
        &self,
        parent: &crate::app_engine::PrivateAppParent,
        context: ProposalContext,
    ) -> usize {
        let Some(sink) = self.ancestor_sink.as_ref() else {
            return 0;
        };
        if context.view <= context.parent_view.saturating_add(1) {
            return 0;
        }
        for (digest, _, bytes) in &parent.chain_bodies {
            sink.broadcast(*digest, bytes.clone(), Recipients::All);
        }
        let report = self
            .resent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .failed_at(&(), parent.frame_number, std::time::Instant::now());
        if let Some(crate::bounded_warn::Report::Failing { attempts, duration }) = report {
            let frames: Vec<u64> = parent
                .chain_bodies
                .iter()
                .map(|(_, number, _)| *number)
                .collect();
            let digests: Vec<String> = parent
                .chain_bodies
                .iter()
                .map(|(digest, _, _)| hex::encode(&digest_to_identity(digest)[..4]))
                .collect();
            tracing::info!(
                filter = %hex::encode(&self.filter), ?frames, ?digests, view = context.view,
                parent_view = context.parent_view, resends = attempts, since_secs = duration.as_secs(),
                "re-sent unfinalized parent bodies to the committee",
            );
        }
        parent.chain_bodies.len()
    }

    /// A proposal on the materialized tip ends a run of re-sends.
    fn settle_resends(&self) {
        let report = self
            .resent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .succeeded_at(&(), u64::MAX, std::time::Instant::now());
        if let Some(crate::bounded_warn::Report::Recovered { attempts, duration }) = report {
            tracing::info!(
                filter = %hex::encode(&self.filter), resends = attempts, duration_secs = duration.as_secs(),
                "stopped re-sending unfinalized parent bodies: proposing on the materialized tip",
            );
        }
    }

    fn unready_reason(&self) -> &'static str {
        if !self.data_ready.load(std::sync::atomic::Ordering::Acquire) {
            "covered shard data not staged"
        } else {
            "no state to check proposals against"
        }
    }
}

/// The counted reason for a proposal `validate_proposal` refused.
fn validation_reason(error: &str) -> &'static str {
    if error.contains("anchored global frame")
        || error.contains("storage attestation: global frame")
    {
        "anchored GLOBAL frame missing"
    } else if error.contains("historical storage registration unavailable") {
        "storage registration unavailable"
    } else if error.contains("storage attestation rejected") {
        "storage attestation rejected"
    } else if error.contains("deterministic output") {
        "output does not match the header"
    } else if error.contains("timestamp") {
        "timestamp out of range"
    } else {
        "frame validation failed"
    }
}

/// Bind a host's private-parent executor to its block store, and the
/// leader's re-sends of unfinalized parents to its block channel.
pub(crate) fn bind_private_parents(
    proposer: AppSeamProposer,
    parents: Option<Arc<crate::app_engine::AppParentExecutor>>,
    store: &BlockStore,
    sink: Arc<dyn FrameSink>,
    gate_proposals: bool,
) -> AppSeamProposer {
    let Some(parents) = parents else {
        return proposer;
    };
    parents.bind_blocks(store.clone());
    proposer
        .with_private_parents(parents, gate_proposals)
        .with_ancestor_sink(sink)
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

/// How long the head of the pending finalizations may stay undeliverable
/// before the operator is warned, and how often the warning repeats.
const HEAD_STALL_WARN_AFTER: std::time::Duration = std::time::Duration::from_secs(30);
const HEAD_STALL_REPEAT: std::time::Duration = std::time::Duration::from_secs(600);

/// Why a pending finalization was not delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Held {
    /// The frame body is not in the block store.
    BodyMissing,
    /// The stored bytes are not this shard's frame or seal under the
    /// certified digest.
    BodyMismatch,
    /// The closing certificate could not be stored durably.
    SealNotPersisted,
    /// The engine did not accept the notification.
    SinkRefused,
}

impl Held {
    fn reason(self) -> &'static str {
        match self {
            Held::BodyMissing => "frame body not held by this worker",
            Held::BodyMismatch => "stored bytes do not match the certified digest",
            Held::SealNotPersisted => "closing certificate not persisted",
            Held::SinkRefused => "engine did not accept the frame",
        }
    }

    fn action(self) -> &'static str {
        match self {
            Held::BodyMissing => "expected to clear once archive replay materializes the frame; until then this worker follows the shard by archive replay and sends no reward proofs, full frames or closing certificate; report this line if it persists",
            Held::BodyMismatch => "a peer served other bytes under this digest; report this line if it persists",
            Held::SealNotPersisted => "check free space and permissions of this node's store",
            Held::SinkRefused => "the engine is busy or stalled; check this worker's materialized height",
        }
    }
}

/// The first pending finalization, in view order, that was not delivered.
struct Head {
    view: u64,
    digest: Digest,
    held: Held,
    frame: Option<u64>,
    /// Pending finalizations at later views, waiting behind it.
    behind: usize,
}

/// How long the same head has been undeliverable, and when it was reported.
struct HeadStall {
    digest: Digest,
    view: u64,
    since: std::time::Instant,
    warned: Option<std::time::Instant>,
}

/// Pending finalizations dropped since the last line about them.
#[derive(Default)]
struct DropReport {
    last: Option<std::time::Instant>,
    dropped: usize,
    /// The lowest and highest dropped view.
    views: Option<(u64, u64)>,
}

/// What [`AppSeamFinalizer::retry_pending_at`] told the operator.
#[derive(Debug, PartialEq, Eq)]
enum HeadSignal {
    Stalled,
    StillStalled,
    Cleared,
}

/// Materializes finalized app frames + writes candidates on notarize, via
/// engine-supplied callbacks (materialize + full-frame publish live in the
/// engine, keyed by the per-shard hypergraph the seam has no handle to).
pub struct AppSeamFinalizer {
    /// Called on notarize with the (uncommitted) frame — optional candidate persist.
    on_notarized: AppFrameSink,
    /// Called on finalize — materialize + publish the full frame + coverage. Also
    /// receives the serialized finalization certificate for reward attribution.
    on_finalized: AppFinalizedSink,
    store: BlockStore,
    filter: Vec<u8>,
    /// Receives a finalized terminal seal and its certificate (session hosts).
    on_sealed: Option<AppSealedSink>,
    sealed_bodies: Option<Arc<SealedBodies>>,
    closing_certificate: Option<Arc<crate::closing_certificate::ClosingCertificate>>,
    seal_persist_error: std::sync::atomic::AtomicBool,
    /// See [`FinalizedRecords`]. `None` for an ephemeral (journal-less) host.
    finalized_records: Option<Arc<FinalizedRecords>>,
    /// The engine's contiguous materialized cursor: bodies and records at or
    /// below it are no longer needed. `None` prunes through each delivered
    /// frame, as before records existed.
    materialized: Option<Arc<std::sync::atomic::AtomicU64>>,
    /// The highest frame number handed to the engine, so a later walk does not
    /// hand over again an ancestor already queued there.
    delivered: std::sync::atomic::AtomicU64,
    // Only consensus-validated finalization certificates enter this queue.
    // Repeated reports for the same digest coalesce; bytes stay in BlockStore.
    // The flag marks a finalization this instance reported, or its own
    // closing certificate replayed: its view is in this session's numbering.
    // A replayed record carries the rank of whichever session finalized it.
    pending: Mutex<HashMap<Digest, (u64, Vec<u8>, bool)>>,
    /// Set once this instance's engine reports a finalization (replayed
    /// records are not reports): its members agreed on its genesis.
    reported: Arc<std::sync::atomic::AtomicBool>,
    /// The undeliverable head of `pending`, for the operator warning.
    head_stall: Mutex<Option<HeadStall>>,
    /// `(materialized cursor, pending count)` at the last scan for entries
    /// already materialized, so a stuck queue is not rescanned every tick.
    scanned: Mutex<Option<(u64, usize)>>,
    /// Entries dropped as already materialized, for the operator.
    drop_report: Mutex<DropReport>,
}

impl AppSeamFinalizer {
    pub fn new(
        on_notarized: AppFrameSink,
        on_finalized: AppFinalizedSink,
        store: BlockStore,
        filter: Vec<u8>,
    ) -> Self {
        Self {
            on_notarized,
            on_finalized,
            store,
            filter,
            on_sealed: None,
            sealed_bodies: None,
            closing_certificate: None,
            seal_persist_error: Default::default(),
            finalized_records: None,
            materialized: None,
            delivered: std::sync::atomic::AtomicU64::new(0),
            pending: Mutex::new(HashMap::new()),
            reported: Default::default(),
            head_stall: Default::default(),
            scanned: Default::default(),
            drop_report: Default::default(),
        }
    }

    /// The lowest view whose finalized body this finalizer still has to
    /// deliver, for the block store's window (`BlockStore::hold_from`); `0`
    /// while it holds a replayed record, whose view may be another
    /// instance's.
    pub fn held_view(&self) -> Option<u64> {
        let pending = self.pending.lock().ok()?;
        pending
            .values()
            .map(|(view, _, reported)| if *reported { *view } else { 0 })
            .min()
    }

    /// Whether the engine has reported a finalization (see `reported`).
    pub fn reported(&self) -> Arc<std::sync::atomic::AtomicBool> {
        self.reported.clone()
    }

    pub fn with_sealed_bodies(mut self, bodies: Arc<SealedBodies>) -> Self {
        self.sealed_bodies = Some(bodies);
        self
    }

    /// Keep finalized frames durably until the engine's `materialized` cursor
    /// passes them, and prune sealed bodies by that cursor too.
    pub fn with_finalized_records(
        mut self,
        records: Arc<FinalizedRecords>,
        materialized: Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        self.finalized_records = Some(records);
        self.materialized = Some(materialized);
        self
    }

    /// Queue again every finalized frame recorded above the materialized
    /// cursor, in order, with its own certificate: frames an earlier instance
    /// finalized whose delivery the engine never committed. Run at host start,
    /// before the host can finalize anything new.
    pub fn replay_finalized_records(&self) -> std::io::Result<usize> {
        let (Some(records), Some(materialized)) =
            (self.finalized_records.as_ref(), self.materialized.as_ref())
        else {
            return Ok(0);
        };
        let after = materialized.load(std::sync::atomic::Ordering::SeqCst);
        let mut replayed = 0;
        for (number, bytes, cert, verified) in records.load_above(after)? {
            let Some(frame) = decode_app_frame(&bytes) else {
                continue;
            };
            let Some(digest) = app_frame_digest(&frame) else {
                continue;
            };
            // Delivery refuses another shard's frame, and a queued frame that
            // can never be delivered would hold back every later one.
            if frame.header.as_ref().map(|h| h.address.as_slice()) != Some(self.filter.as_slice()) {
                continue;
            }
            let view = frame.header.as_ref().map_or(number, |h| h.rank);
            if verified {
                self.store.seal(digest, bytes)
            } else {
                self.store.put(digest, bytes)
            }
            self.store.recorded_final(&digest);
            // An implied ancestor is only a body: it is delivered again with
            // the certified descendant that links to it.
            let Some(cert) = cert else { continue };
            self.pending
                .lock()
                .unwrap()
                .entry(digest)
                .or_insert_with(|| (view, cert, false));
            replayed += 1;
        }
        self.retry_pending();
        Ok(replayed)
    }

    fn prune_delivered(&self, delivered: u64) {
        let through = match self.materialized.as_ref() {
            Some(cursor) => cursor.load(std::sync::atomic::Ordering::SeqCst),
            None => delivered,
        };
        if let Some(bodies) = self.sealed_bodies.as_ref() {
            bodies.prune_through(through);
        }
        if let Some(records) = self.finalized_records.as_ref() {
            records.prune_through(through);
        }
    }

    fn with_closing_certificate(
        mut self,
        record: Arc<crate::closing_certificate::ClosingCertificate>,
    ) -> Self {
        self.closing_certificate = Some(record);
        self
    }

    fn replay_closing_certificate(&self) -> std::io::Result<bool> {
        let Some(record) = self.closing_certificate.as_ref() else {
            return Ok(false);
        };
        let Some(submission) = record.load()? else {
            return Ok(false);
        };
        let digest = digest_from_identity(submission.seal.digest());
        self.store.seal(digest, submission.seal.encode());
        self.pending.lock().unwrap().entry(digest).or_insert((
            submission.seal.view,
            submission.certificate,
            true,
        ));
        self.retry_pending();
        Ok(true)
    }

    pub fn with_sealed_sink(mut self, on_sealed: AppSealedSink) -> Self {
        self.on_sealed = Some(on_sealed);
        self
    }

    /// The ancestors `frame`'s finalization makes final that the engine has
    /// not been handed: every frame from just above the engine's cursor (or
    /// the last delivered frame) up to `frame`'s parent, lowest first, each
    /// with its bytes and verified flag.
    ///
    /// Simplex finalizes a view's ancestors with it, and a member may build on
    /// a notarized parent before that parent finalizes (it executes it
    /// privately). Such a parent never gets a finalization of its own; a live
    /// run's GLOBAL halted waiting for one. Each ancestor must link to its
    /// child exactly (`app_frame_links_to_child`) and be held in the block
    /// store; if the chain is incomplete, none is returned and the frame is
    /// delivered alone, as before.
    fn implied_ancestors(&self, frame: &AppShardFrame) -> Vec<(AppShardFrame, bool, Vec<u8>)> {
        use std::sync::atomic::Ordering;
        let Some(materialized) = self.materialized.as_ref() else {
            return Vec::new();
        };
        let Some(header) = frame.header.as_ref() else {
            return Vec::new();
        };
        let floor = materialized
            .load(Ordering::SeqCst)
            .max(self.delivered.load(Ordering::SeqCst));
        let mut chain = Vec::new();
        let mut child = header.clone();
        while child.frame_number > floor.saturating_add(1) {
            let Ok(identity) = <[u8; 32]>::try_from(child.parent_selector.as_slice()) else {
                return Vec::new();
            };
            let digest = digest_from_identity(identity);
            let Some((bytes, verified)) = self.store.get_with_verification(&digest) else {
                return Vec::new();
            };
            if Seal::is_encoding(&bytes) {
                return Vec::new();
            }
            let Some(parent) = decode_app_frame(&bytes) else {
                return Vec::new();
            };
            let links = parent.header.as_ref().is_some_and(|parent_header| {
                parent_header.address == self.filter
                    && crate::frame_validator::app_frame_links_to_child(parent_header, &child)
            });
            if !links || app_frame_digest(&parent) != Some(digest) {
                return Vec::new();
            }
            child = parent.header.clone().expect("checked above");
            chain.push((parent, verified, bytes));
        }
        chain.reverse();
        chain
    }

    /// The data frames `seal`'s finalization makes final that the engine has
    /// not been handed: its checkpoint frame, when it never finalized on its
    /// own, and that frame's own implied ancestors, lowest first. A seal
    /// built on a notarized parent finalizes it with no certificate of its
    /// own; handed nothing, the engine never committed the checkpoint frame,
    /// its seal went to GLOBAL without the frame as a drain header, and was
    /// refused until GLOBAL fenced the session (eight sessions, 2026-10-15).
    /// Empty when the chain is incomplete, as for a data frame.
    fn seal_implied(&self, seal: &Seal) -> Vec<(AppShardFrame, bool, Vec<u8>)> {
        use std::sync::atomic::Ordering;
        let Some(materialized) = self.materialized.as_ref() else {
            return Vec::new();
        };
        let floor = materialized
            .load(Ordering::SeqCst)
            .max(self.delivered.load(Ordering::SeqCst));
        if seal.checkpoint.frame <= floor {
            return Vec::new();
        }
        let digest = digest_from_identity(seal.checkpoint.digest);
        let Some((bytes, verified)) = self.store.get_with_verification(&digest) else {
            return Vec::new();
        };
        if Seal::is_encoding(&bytes) {
            return Vec::new();
        }
        let Some(frame) = decode_app_frame(&bytes) else {
            return Vec::new();
        };
        let sealed = frame.header.as_ref().is_some_and(|header| {
            header.address == self.filter && header.frame_number == seal.checkpoint.frame
        });
        if !sealed || app_frame_digest(&frame) != Some(digest) {
            return Vec::new();
        }
        let mut chain = self.implied_ancestors(&frame);
        if chain.is_empty() && seal.checkpoint.frame > floor.saturating_add(1) {
            return Vec::new();
        }
        chain.push((frame, verified, bytes));
        chain
    }

    /// Record `implied` durably before it goes to the engine: a restart
    /// between the send and the engine's commit must not lose them.
    fn persist_implied(&self, implied: &[(AppShardFrame, bool, Vec<u8>)]) {
        let Some(records) = self.finalized_records.as_ref() else {
            return;
        };
        for (frame, verified, bytes) in implied {
            let number = frame.header.as_ref().map_or(0, |h| h.frame_number);
            if let Err(error) = records.persist_implied(number, *verified, bytes) {
                tracing::warn!(frame = number, %error, "could not record an implied app frame; delivering it anyway");
            }
        }
    }

    /// The engine's materialized cursor, or, for a host without one, the
    /// highest frame handed to the engine.
    fn materialized_floor(&self) -> u64 {
        match self.materialized.as_ref() {
            Some(cursor) => cursor.load(std::sync::atomic::Ordering::SeqCst),
            None => self.delivered.load(std::sync::atomic::Ordering::SeqCst),
        }
    }

    /// Hand one pending finalization to the engine, or say why it is still
    /// held. One that can never be delivered here is dropped instead.
    fn try_deliver(&self, digest: Digest) -> Result<(), (Held, Option<u64>)> {
        // Serializes delivery across the host, ingress and retry timer. The
        // engine callback only attempts a nonblocking channel send.
        let mut pending = self.pending.lock().unwrap();
        let Some((view, cert, _)) = pending.get(&digest) else {
            return Ok(());
        };
        let view = *view;
        let Some((bytes, locally_verified)) = self.store.get_with_verification(&digest) else {
            return Err((Held::BodyMissing, None));
        };
        if Seal::is_encoding(&bytes) {
            let Some(seal) = Seal::decode(&bytes)
                .ok()
                .filter(|seal| seal.digest() == digest.0)
            else {
                return Err((Held::BodyMismatch, None));
            };
            let checkpoint = Some(seal.checkpoint.frame);
            // A terminal seal is not a data frame. Only a session host installs
            // the sink; elsewhere the reserved encoding can never be delivered,
            // and kept, it would hold back every later finalization.
            let Some(on_sealed) = self.on_sealed.as_ref() else {
                tracing::warn!(filter = %hex::encode(&self.filter), view,
                    digest = %hex::encode(&digest.0[..4]), checkpoint = seal.checkpoint.frame,
                    "dropping a finalized terminal seal this legacy consensus instance cannot deliver: a peer proposed a seal outside a session and the committee finalized it; report this line");
                pending.remove(&digest);
                return Ok(());
            };
            if let Some(record) = self.closing_certificate.as_ref() {
                if let Err(error) = record.persist(&bytes, cert) {
                    if !self
                        .seal_persist_error
                        .swap(true, std::sync::atomic::Ordering::Relaxed)
                    {
                        tracing::warn!(%error, "closing certificate persistence failed; retaining for retry");
                    }
                    return Err((Held::SealNotPersisted, checkpoint));
                }
                self.seal_persist_error
                    .store(false, std::sync::atomic::Ordering::Relaxed);
            }
            let implied = self.seal_implied(&seal);
            self.persist_implied(&implied);
            let through = implied
                .last()
                .and_then(|(frame, _, _)| frame.header.as_ref().map(|h| h.frame_number));
            if !implied.is_empty() {
                tracing::info!(checkpoint = seal.checkpoint.frame, implied = implied.len(),
                    "finalized seal makes its notarized checkpoint final; delivering it with the seal");
            }
            let implied = implied
                .into_iter()
                .map(|(frame, verified, _)| (frame, verified))
                .collect();
            if on_sealed(bytes, cert.clone(), implied) {
                pending.remove(&digest);
                if let Some(number) = through {
                    self.delivered
                        .fetch_max(number, std::sync::atomic::Ordering::SeqCst);
                }
                return Ok(());
            }
            return Err((Held::SinkRefused, checkpoint));
        }
        let Some(frame) = decode_app_frame(&bytes) else {
            return Err((Held::BodyMismatch, None));
        };
        let delivered = frame.header.as_ref().map(|h| h.frame_number);
        if frame.header.as_ref().map(|h| h.address.as_slice()) != Some(self.filter.as_slice())
            || app_frame_digest(&frame) != Some(digest)
        {
            return Err((Held::BodyMismatch, delivered));
        }
        let implied = self.implied_ancestors(&frame);
        // Durable before the queue send: a restart between the send and the
        // engine's commit must not lose a finalized frame.
        if let (Some(records), Some(number)) = (self.finalized_records.as_ref(), delivered) {
            self.persist_implied(&implied);
            if let Err(error) = records.persist(number, cert, locally_verified, &bytes) {
                tracing::warn!(frame = number, %error, "could not record a finalized app frame; delivering it anyway");
            }
        }
        if !implied.is_empty() {
            tracing::info!(
                frame = delivered,
                implied = implied.len(),
                "finalized app frame makes notarized ancestors final; delivering them first"
            );
        }
        let implied: Vec<(AppShardFrame, bool)> = implied
            .into_iter()
            .map(|(ancestor, verified, _)| (ancestor, verified))
            .collect();
        if (self.on_finalized)(frame, cert.clone(), locally_verified, implied) {
            pending.remove(&digest);
            if let Some(number) = delivered {
                self.delivered
                    .fetch_max(number, std::sync::atomic::Ordering::SeqCst);
                self.prune_delivered(number);
            }
            return Ok(());
        }
        Err((Held::SinkRefused, delivered))
    }

    fn retry_pending(&self) {
        self.retry_pending_at(std::time::Instant::now());
    }

    /// Deliver pending finalizations in view order, up to the first that
    /// cannot be delivered, and warn at `now` when that head stays stuck.
    fn retry_pending_at(&self, now: std::time::Instant) -> Option<HeadSignal> {
        let mut head = self.deliver_in_order();
        if head.is_some() && self.drop_materialized(now) > 0 {
            head = self.deliver_in_order();
        }
        self.note_head(head, now)
    }

    fn deliver_in_order(&self) -> Option<Head> {
        let mut entries: Vec<_> = self
            .pending
            .lock()
            .unwrap()
            .iter()
            .map(|(digest, (view, _, _))| (*view, *digest))
            .collect();
        entries.sort_by_key(|(view, _)| *view);
        let count = entries.len();
        for (index, (view, digest)) in entries.into_iter().enumerate() {
            // Do not knowingly deliver newer finalizations ahead of a missing
            // earlier body or a backpressured notification.
            if let Err((held, frame)) = self.try_deliver(digest) {
                return Some(Head {
                    view,
                    digest,
                    held,
                    frame,
                    behind: count - index - 1,
                });
            }
        }
        None
    }

    /// Drop pending finalizations whose bodies this worker never held once a
    /// later verified frame or seal shows them materialized. Such a
    /// finalization (one reported across a restart, its block broadcast
    /// before it) does not say its frame number, and archive replay, which
    /// materializes the frame meanwhile, does not supply the body. Finalized
    /// views form one chain, though: one at a lower view than a frame whose
    /// parent is materialized, or than a seal whose checkpoint is, finalized
    /// a frame at or below the cursor too. Only this session's own reports,
    /// with bytes this node verified, set that bound. An entry with a body is
    /// never dropped: it is delivered as usual, and the engine republishes a
    /// materialized frame with its reward proof, which archive replay never
    /// sends. Returns how many were dropped.
    fn drop_materialized(&self, now: std::time::Instant) -> usize {
        let floor = self.materialized_floor();
        let mut pending = self.pending.lock().unwrap();
        let key = (floor, pending.len());
        if self.scanned.lock().unwrap().replace(key) == Some(key) {
            return 0;
        }
        let mut through = None;
        for (digest, (view, _, reported)) in pending.iter() {
            if !*reported {
                continue;
            }
            let Some((bytes, true)) = self.store.get_with_verification(digest) else {
                continue;
            };
            let below = if Seal::is_encoding(&bytes) {
                Seal::decode(&bytes)
                    .ok()
                    .filter(|seal| seal.digest() == digest.0)
                    .map(|seal| seal.checkpoint.frame)
            } else {
                decode_app_frame(&bytes)
                    .filter(|frame| app_frame_digest(frame) == Some(*digest))
                    .and_then(|frame| frame.header)
                    .filter(|header| header.address == self.filter)
                    .map(|header| header.frame_number.saturating_sub(1))
            };
            if below.is_some_and(|below| below <= floor) {
                through = through.max(Some(*view));
            }
        }
        let Some(through) = through else { return 0 };
        let before = pending.len();
        let mut report = self.drop_report.lock().unwrap();
        pending.retain(|digest, (view, _, _)| {
            let dropped = *view < through && self.store.get(digest).is_none();
            if dropped {
                report.views = Some(report.views.map_or((*view, *view), |(low, high)| {
                    (low.min(*view), high.max(*view))
                }));
            }
            !dropped
        });
        let dropped = before - pending.len();
        drop(pending);
        report.dropped += dropped;
        if dropped > 0
            && report
                .last
                .is_none_or(|last| now.saturating_duration_since(last) >= HEAD_STALL_REPEAT)
        {
            self.flush_drops(&mut report, now);
        }
        dropped
    }

    /// Log the entries dropped since the last such line, if any.
    fn flush_drops(&self, report: &mut DropReport, now: std::time::Instant) {
        let Some((low, high)) = report.views.take() else {
            return;
        };
        tracing::info!(filter = %hex::encode(&self.filter), dropped = report.dropped,
            views = %format!("{low}-{high}"), materialized = self.materialized_floor(),
            "dropped pending finalizations whose bodies this worker never held: archive replay had already materialized their frames, and later finalizations deliver in order");
        report.dropped = 0;
        report.last = Some(now);
    }

    /// Warn once the same head has been undeliverable for
    /// [`HEAD_STALL_WARN_AFTER`], again every [`HEAD_STALL_REPEAT`], and say
    /// when it clears. A missing body with nothing behind it holds nothing
    /// back: it is the engine's own gap, which the engine reports.
    fn note_head(&self, head: Option<Head>, now: std::time::Instant) -> Option<HeadSignal> {
        let mut stall = self.head_stall.lock().unwrap();
        let mut signal = None;
        let moved = stall
            .as_ref()
            .is_some_and(|stall| head.as_ref().is_none_or(|head| head.digest != stall.digest));
        if let Some(previous) = stall.take_if(|_| moved) {
            if previous.warned.is_some() {
                tracing::info!(filter = %hex::encode(&self.filter), view = previous.view,
                    digest = %hex::encode(&previous.digest.0[..4]),
                    stalled_secs = now.saturating_duration_since(previous.since).as_secs(),
                    materialized = self.materialized_floor(),
                    "finalized app frame delivery resumed: the pending finalization that held back later ones was delivered or dropped");
                signal = Some(HeadSignal::Cleared);
            }
        }
        let Some(head) = head else {
            self.flush_drops(&mut self.drop_report.lock().unwrap(), now);
            return signal;
        };
        let stall = stall.get_or_insert_with(|| HeadStall {
            digest: head.digest,
            view: head.view,
            since: now,
            warned: None,
        });
        let stuck = now.saturating_duration_since(stall.since);
        if stuck < HEAD_STALL_WARN_AFTER
            || (head.held == Held::BodyMissing && head.behind == 0)
            || stall
                .warned
                .is_some_and(|warned| now.saturating_duration_since(warned) < HEAD_STALL_REPEAT)
        {
            return signal;
        }
        let first = stall.warned.replace(now).is_none();
        tracing::warn!(filter = %hex::encode(&self.filter), view = head.view,
            digest = %hex::encode(&head.digest.0[..4]),
            frame = %head.frame.map_or_else(|| "unknown".to_string(), |frame| frame.to_string()),
            reason = head.held.reason(), materialized = self.materialized_floor(),
            stalled_secs = stuck.as_secs(), held_back = head.behind, scope = "this node", action = head.held.action(),
            "finalized app frames are not reaching this worker's engine: the oldest pending finalization cannot be delivered and holds back later finalizations");
        Some(if first {
            HeadSignal::Stalled
        } else {
            HeadSignal::StillStalled
        })
    }
}

impl FrameFinalizer for AppSeamFinalizer {
    fn on_notarized(&self, _view: u64, _digest: Digest, bytes: Option<Vec<u8>>) {
        let Some(bytes) = bytes else { return };
        let Some(frame) = decode_app_frame(&bytes) else {
            return;
        };
        (self.on_notarized)(frame);
    }

    fn on_finalized(
        &self,
        view: u64,
        digest: Digest,
        _bytes: Option<Vec<u8>>,
        cert: Option<Vec<u8>>,
        _locally_verified: bool,
    ) {
        // Read bytes + verification status together from BlockStore when
        // delivering, including after a delayed body arrives. A certificate by
        // itself never upgrades an unverified candidate into verified data.
        self.reported
            .store(true, std::sync::atomic::Ordering::Release);
        self.pending
            .lock()
            .unwrap()
            .entry(digest)
            .or_insert_with(|| (view, cert.unwrap_or_default(), true));
        self.retry_pending();
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
    build_committee_in_namespace(member_pubkeys, my_signing_key, my_public_key, &namespace)
}

/// The committee of an authorized session: exactly its members, signing in the
/// session's own namespace.
pub fn build_session_committee(
    session: &Session,
    my_signing_key: &[u8],
    my_public_key: &[u8],
) -> Option<(SimplexFalconScheme, Arc<[FalconPublicKey]>)> {
    build_committee_in_namespace(
        &session.members,
        my_signing_key,
        my_public_key,
        &session.namespace().ok()?,
    )
}

fn build_committee_in_namespace(
    member_pubkeys: &[Vec<u8>],
    my_signing_key: &[u8],
    my_public_key: &[u8],
    namespace: &[u8],
) -> Option<(SimplexFalconScheme, Arc<[FalconPublicKey]>)> {
    let committee = quil_cw_consensus::committee::build_global_committee(
        member_pubkeys,
        my_signing_key,
        my_public_key,
        namespace,
    )?;
    Some((committee.scheme, committee.peers))
}

/// What a restarting instance resumes from at its recovered `header`, which
/// the caller has validated under the committee that certified it (a
/// historical one if need be): this committee's finalization of it, the
/// Simplex floor at its actual view.
///
/// `Ok(None)` only for a legacy instance whose genesis is this head
/// (`head_is_genesis`) when this committee did not certify it: the instance
/// starts from the head as genesis. A legacy committee follows the registry
/// and has no handoff to carry a finalized floor across a membership change,
/// so its members restart from the head they share (public issue #664). An
/// authorized session changes committee only through its handoff, and a head
/// its own committee cannot authenticate stops it.
pub fn restart_finalization(
    header: &quil_types::proto::global::FrameHeader,
    peers: &[FalconPublicKey],
    namespace: &[u8],
    epoch: u64,
    head_is_genesis: bool,
) -> quil_types::error::Result<Option<quil_cw_consensus::app_cert::VerifiedFinalization>> {
    use quil_types::error::QuilError;
    let certificate = header
        .public_key_signature_bls48581
        .as_ref()
        .and_then(|signature| {
            quil_cw_consensus::app_cert::unwrap_cert_from_header(&signature.signature)
        });
    let keys: Vec<Vec<u8>> = peers.iter().map(|key| key.as_ref().to_vec()).collect();
    let identity = quil_crypto::poseidon::hash_bytes_to_32(&header.output)?;
    let verified = certificate.and_then(|certificate| {
        quil_cw_consensus::app_cert::verify_finalization_details(
            certificate,
            &keys,
            namespace,
            identity,
        )
    });
    let Some(verified) = verified else {
        if head_is_genesis {
            return Ok(None);
        }
        return Err(QuilError::ExecutionUnavailable(match certificate {
            None => "app restart needs a finalized certificate or an authenticated committee handoff",
            Some(_) => "app restart certificate does not authenticate under this committee; a handoff is required",
        }.into()));
    };
    if verified.finalization.proposal.round.epoch().get() != epoch {
        return Err(QuilError::ExecutionUnavailable(
            "app restart head was certified in another committee generation".into(),
        ));
    }
    if verified.finalization.proposal.round.view().get() != header.rank {
        return Err(QuilError::ExecutionUnavailable(
            "app restart head rank disagrees with its certified view".into(),
        ));
    }
    Ok(Some(verified))
}

/// The engine's handle to a running simplex-backed app-shard consensus. On each
/// inbound CW‑tagged shard‑consensus message the node demuxes the channel id:
/// - channels 0/1/2 (vote/cert/resolver) → `inbound[channel].send(...)`;
/// - channel 3 (block) → `ingest_block(bytes)` (feeds the shared `BlockStore`).
pub struct AppConsensusCwHandle {
    /// Declared first so it drops first: the shutdown flag is set before the
    /// inbound senders close, and the host reports a requested stop.
    _stop_on_drop: StopOnDrop,
    pub inbound: [tokio::sync::mpsc::UnboundedSender<
        quil_cw_consensus::p2p_bridge::Message<FalconPublicKey>,
    >; 3],
    /// Feed a peer-delivered app frame's bytes into the engine's `BlockStore`
    /// so `verify` finds the block behind a proposed digest. Peer ingress never
    /// records an unverified height. Drops malformed bytes.
    pub ingest_block: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
    /// Cooperative shutdown flag for the simplex host thread. Set it to stop this
    /// instance (the engine drops + the runtime thread returns) — used to REBUILD
    /// the committee when the shard's active-prover set changes.
    pub shutdown: Arc<std::sync::atomic::AtomicBool>,
    /// `Some(frame)`: a legacy instance that started from its recovered head
    /// as genesis because another committee certified that head (see
    /// [`restart_finalization`]).
    pub adopted_genesis: Option<u64>,
    /// Set once this instance finalizes anything.
    pub finalized: Arc<std::sync::atomic::AtomicBool>,
    thread: std::thread::JoinHandle<()>,
    outbound_task: tokio::task::JoinHandle<()>,
}

/// Sets a host's shutdown flag when its handle is dropped without
/// `shutdown_and_join`, as when the owning runtime is torn down.
struct StopOnDrop(Arc<std::sync::atomic::AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

impl AppConsensusCwHandle {
    /// A handle whose host has already returned: an engine with it counts as
    /// running consensus, and materializes nothing.
    #[cfg(test)]
    pub(crate) fn idle_for_test() -> Self {
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        AppConsensusCwHandle {
            _stop_on_drop: StopOnDrop(shutdown.clone()),
            inbound: std::array::from_fn(|_| tokio::sync::mpsc::unbounded_channel().0),
            ingest_block: Arc::new(|_| {}),
            shutdown,
            adopted_genesis: None,
            finalized: Default::default(),
            thread: std::thread::spawn(|| {}),
            outbound_task: tokio::spawn(std::future::pending()),
        }
    }

    /// The host thread has returned without being asked: its engine stopped
    /// (an actor panicked, for instance) and this shard is taking no part in
    /// consensus until the owner rebuilds the host.
    pub fn is_dead(&self) -> bool {
        !self.shutdown.load(std::sync::atomic::Ordering::Acquire) && self.thread.is_finished()
    }

    /// Stop and join the complete runtime before a replacement can use its
    /// journal. Aborting the drain also discards queued outbound old votes.
    pub async fn shutdown_and_join(self) -> Result<(), String> {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Release);
        self.outbound_task.abort();
        let _ = self.outbound_task.await;
        tokio::task::spawn_blocking(move || self.thread.join())
            .await
            .map_err(|e| format!("joining consensus host task: {e}"))?
            .map_err(|_| "consensus host panicked before shutdown".to_string())
    }
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
    recovered_head: Option<AppShardFrame>,
    leader_timeout_secs: u64,
    transport: Arc<dyn AppConsensusTransport>,
    // Persistent per-shard simplex-journal dir. `Some(dir)` resumes across
    // restarts; `None` uses the runtime default (ephemeral random temp).
    storage_directory: Option<std::path::PathBuf>,
    // Body-root cross-check for the verify path; see
    // [`AppRequestsRootCheck`]. `None` disables proposal production and voting.
    requests_root_check: Option<AppRequestsRootCheck>,
    // Gates propose/verify until the covered shard's data is staged (see
    // `AppSeamProposer::data_ready`).
    data_ready: Arc<std::sync::atomic::AtomicBool>,
    // `Some` runs an authorized committee session; `epoch`/`genesis_*` must be
    // that session's generation, genesis and base frame. Generation zero is
    // the exception: it continues a legacy instance, whose journal keeps the
    // genesis it began with and which resumes from its certified local head.
    session: Option<SessionHost>,
    // Executes a selected parent that is notarized but not yet materialized.
    private_parents: Option<Arc<crate::app_engine::AppParentExecutor>>,
    // Where this shard's finalized frames are kept (one directory per filter,
    // across sessions) and the engine's contiguous materialized cursor they
    // are kept until (see [`FinalizedRecords`]).
    finalized_records: Option<(std::path::PathBuf, Arc<std::sync::atomic::AtomicU64>)>,
) -> quil_types::error::Result<AppConsensusCwHandle> {
    // An instance that restarts from its certified local head: every legacy
    // instance, and generation zero, which continues one.
    let resumes_legacy = session
        .as_ref()
        .is_none_or(|host| host.session.generation == 0);
    if let Some(host) = session.as_ref() {
        let anchored = host.session.generation == 0
            || (genesis_digest.0 == host.session.genesis
                && genesis_frame_number == host.session.base_frame);
        if epoch != host.session.generation || !anchored {
            return Err(quil_types::error::QuilError::Internal(
                "app session host configuration differs from its authorization".into(),
            ));
        }
        // Generation zero's instance must already hold its base, the legacy
        // tip GLOBAL registered, or its first proposal has no certified parent.
        let head = recovered_head
            .as_ref()
            .and_then(|frame| frame.header.as_ref())
            .map(|h| h.frame_number);
        if host.session.generation == 0 && head.is_none_or(|head| head < host.session.base_frame) {
            return Err(quil_types::error::QuilError::ExecutionUnavailable(
                "local shard head precedes the registered legacy tip; recover the source state first".into()));
        }
    }
    let sealed_bodies = storage_directory
        .as_ref()
        .map(|dir| SealedBodies::open(dir.with_extension("bodies")).map(Arc::new))
        .transpose()
        .map_err(|e| {
            quil_types::error::QuilError::Internal(format!("open sealed proposal bodies: {e}"))
        })?;
    let finalized_records = finalized_records
        .map(|(dir, cursor)| FinalizedRecords::open(dir).map(|records| (Arc::new(records), cursor)))
        .transpose()
        .map_err(|e| {
            quil_types::error::QuilError::Internal(format!("open finalized app frames: {e}"))
        })?;
    let mut proposer = AppSeamProposer::new(
        leader_provider,
        validator,
        assemble,
        filter,
        requests_root_check,
        data_ready,
    );
    if let Some(bodies) = sealed_bodies.clone() {
        proposer = proposer.with_sealed_bodies(bodies);
    }
    proposer = proposer.with_liveness(session.as_ref().map(|host| host.liveness.clone()));
    let store = BlockStore::with_limits(
        quil_cw_consensus::adapters::BlockStoreLimits::default(),
        format!("app shard {}", hex::encode(&proposer.filter)),
    );
    let sink = Arc::new(AppSeamSink::new(transport.clone(), peers.clone()));
    // A session's handoff proposer waits for the parent before using its
    // private execution; the plain host waits here.
    proposer = bind_private_parents(
        proposer,
        private_parents.clone(),
        &store,
        sink.clone(),
        session.is_none(),
    );
    let proposer = Arc::new(proposer);
    // Seed the genesis parent so the first proposal resolves its frame number.
    proposer.note_frame(genesis_digest, genesis_frame_number);
    // Restore what this node sealed in an earlier life BEFORE the host can
    // replay a journal that refers to it.
    if let Some(bodies) = sealed_bodies.as_ref() {
        let restored = bodies.load().map_err(|e| {
            quil_types::error::QuilError::Internal(format!("load sealed proposal bodies: {e}"))
        })?;
        for (digest, bytes) in restored {
            if let Some(number) =
                decode_app_frame(&bytes).and_then(|f| f.header.map(|h| h.frame_number))
            {
                proposer.note_frame(digest, number);
            }
            store.seal(digest, bytes);
        }
    }
    let mut finalizer = AppSeamFinalizer::new(
        on_notarized,
        on_finalized,
        store.clone(),
        proposer.filter.clone(),
    );
    if let Some(host) = session.as_ref() {
        finalizer = finalizer.with_sealed_sink(host.on_sealed.clone());
        if let Some(directory) = storage_directory.as_ref() {
            finalizer = finalizer.with_closing_certificate(Arc::new(
                crate::closing_certificate::ClosingCertificate::new(
                    directory.with_extension("closing-certificate"),
                    host.session.clone(),
                ),
            ));
        }
    }
    if let Some(bodies) = sealed_bodies.clone() {
        finalizer = finalizer.with_sealed_bodies(bodies);
    }
    if let Some((records, cursor)) = finalized_records {
        finalizer = finalizer.with_finalized_records(records, cursor);
    }
    let finalizer = Arc::new(finalizer);
    // Finalized bodies wait in the store until the engine takes them, in
    // order: keep the window open below the oldest one still waiting.
    store.hold_from({
        let finalizer = Arc::downgrade(&finalizer);
        Arc::new(move || {
            finalizer
                .upgrade()
                .and_then(|finalizer| finalizer.held_view())
        })
    });
    let finalized = finalizer.reported();
    // Frames an earlier instance finalized but the engine never materialized
    // go to the engine again, in order, before anything new is finalized.
    let replayed = finalizer.replay_finalized_records().map_err(|e| {
        quil_types::error::QuilError::Internal(format!("load finalized app frames: {e}"))
    })?;
    if replayed > 0 {
        tracing::info!(filter = %hex::encode(&proposer.filter), replayed,
            "delivering app frames finalized before a restart");
    }
    if finalizer.replay_closing_certificate().map_err(|error| {
        quil_types::error::QuilError::Internal(format!(
            "load finalized closing certificate: {error}"
        ))
    })? {
        tracing::info!(filter = %hex::encode(&proposer.filter),
            "replaying authenticated closing certificate after restart");
    }
    let mut params = GlobalEngineParams::new(partition, epoch, genesis_digest)
        .with_leader_timeout_secs(leader_timeout_secs);
    params.liveness = session.as_ref().map(|host| host.liveness.clone());
    // A leader skips nullified notarized parents too deep to execute privately.
    params.parent_fallback = private_parents
        .map(|parents| parents as Arc<dyn quil_cw_consensus::engine_host::ParentFallback>);
    let mut adopted_genesis = None;
    // Populate the persisted head BEFORE the host can replay its journal. These
    // bytes are candidates, not proof that this process validated historical
    // pre-state. Intermediate and unfinalized journal bodies still need recovery.
    if let Some(frame) = recovered_head {
        proposer.recover_head(&store, &frame)?;
        let header = frame.header.as_ref().ok_or_else(|| {
            quil_types::error::QuilError::Internal("recovered app head has no header".into())
        })?;
        if session
            .as_ref()
            .is_some_and(|host| header.frame_number < host.session.base_frame)
        {
            return Err(quil_types::error::QuilError::ExecutionUnavailable(
                "local shard head precedes the session genesis; recover the source state first"
                    .into(),
            ));
        }
        // A session's base frame was certified by its predecessor and is bound
        // by the authorization itself; only later heads carry this committee's
        // certificate. A legacy or generation-zero head, including generation
        // zero's base, carries the legacy committee's own certificate.
        if header.frame_number > 0 && (resumes_legacy || header.frame_number > genesis_frame_number)
        {
            // The certificate authenticates the output digest. Recompute that
            // output before using the header's height/rank as restart metadata;
            // possessing certified output bytes does not authenticate a changed
            // header. Body/pre-state validation remains on the materializer path.
            if !proposer.validator.validate(&frame)? {
                return Err(quil_types::error::QuilError::ExecutionUnavailable(
                    "app restart head failed frame validation".into(),
                ));
            }
            let namespace = match session.as_ref() {
                Some(host) => host.session.namespace()?,
                None => {
                    let mut namespace = b"appshard".to_vec();
                    namespace.extend_from_slice(&proposer.filter);
                    namespace
                }
            };
            let identity = quil_crypto::poseidon::hash_bytes_to_32(&header.output)?;
            // Only a legacy instance whose genesis IS this head may start from
            // it without this committee's certificate.
            let head_is_genesis = session.is_none()
                && header.frame_number == genesis_frame_number
                && genesis_digest == digest_from_identity(identity);
            match restart_finalization(header, &peers, &namespace, epoch, head_is_genesis)? {
                Some(verified) => {
                    let certified_view = verified.finalization.proposal.round.view().get();
                    params =
                        params
                            .with_finalized_floor(verified.finalization)
                            .map_err(|error| {
                                quil_types::error::QuilError::ExecutionUnavailable(error.into())
                            })?;
                    tracing::info!(
                        filter = %hex::encode(&proposer.filter), frame = header.frame_number,
                        view = certified_view, epoch,
                        "resuming app consensus from certified floor",
                    );
                }
                None => {
                    adopted_genesis = Some(header.frame_number);
                    tracing::info!(
                        filter = %hex::encode(&proposer.filter), frame = header.frame_number,
                        members = peers.len(),
                        "starting legacy app consensus from its head as genesis: another committee certified it",
                    );
                }
            }
        }
    }

    // Cooperative shutdown so the caller can stop this instance to rebuild the
    // committee (dynamic app-shard membership).
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let GlobalHostHandle {
        inbound,
        mut outbound,
        thread,
    } = match session {
        Some(host) => spawn_global_host(
            scheme,
            peers,
            Arc::new(PersistingSeals {
                inner: HandoffProposer::new(
                    proposer.clone() as Arc<dyn GlobalProposer>,
                    host.session,
                    host.read_parent,
                )?
                .with_private_reader(host.read_private_parent)
                .with_private_checkpoint_reader(host.read_private_checkpoint)
                .with_seal_parents(store.clone(), host.read_tip)
                .with_checkpoint_votes(host.checkpoint_votes)
                .with_closing_probe(host.closing_probe)
                .with_liveness(Some(host.liveness)),
                bodies: sealed_bodies.clone(),
            }),
            sink,
            finalizer.clone(),
            store.clone(),
            params,
            storage_directory,
            Some(shutdown.clone()),
        ),
        None => spawn_global_host(
            scheme,
            peers,
            proposer.clone(),
            sink,
            finalizer.clone(),
            store.clone(),
            params,
            storage_directory,
            Some(shutdown.clone()),
        ),
    };

    // Drain the engine's outbound (votes/certs/resolver) onto the shard transport.
    let retry_finalizer = finalizer.clone();
    let outbound_task = tokio::spawn(async move {
        let mut retry = tokio::time::interval(std::time::Duration::from_millis(250));
        retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                ob = outbound.recv() => match ob {
                    Some(ob) => transport.deliver(ob.channel, ob.recipients, ob.bytes),
                    None => break,
                },
                _ = retry.tick() => retry_finalizer.retry_pending(),
            }
        }
    });

    // Peer ingress can store candidates, but cannot change trusted heights.
    let ingress = proposer.peer_ingress(store.clone());
    let ingest_block: Arc<dyn Fn(Vec<u8>) + Send + Sync> = Arc::new(move |bytes| {
        ingress(bytes);
        finalizer.retry_pending();
    });

    Ok(AppConsensusCwHandle {
        _stop_on_drop: StopOnDrop(shutdown.clone()),
        inbound,
        ingest_block,
        shutdown,
        adopted_genesis,
        finalized,
        thread,
        outbound_task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::Signer as _;

    #[tokio::test]
    async fn shutdown_waits_for_host_exit() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let shutdown = Arc::new(AtomicBool::new(false));
        let stopped = Arc::new(AtomicBool::new(false));
        let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let thread = {
            let flag = shutdown.clone();
            let stopped = stopped.clone();
            std::thread::spawn(move || {
                while !flag.load(Ordering::Acquire) {
                    std::thread::park_timeout(std::time::Duration::from_millis(1));
                }
                let _ = observed_tx.send(());
                release_rx.recv().unwrap();
                stopped.store(true, Ordering::Release);
            })
        };
        let handle = AppConsensusCwHandle {
            _stop_on_drop: StopOnDrop(shutdown.clone()),
            inbound: std::array::from_fn(|_| tokio::sync::mpsc::unbounded_channel().0),
            ingest_block: Arc::new(|_| {}),
            shutdown,
            adopted_genesis: None,
            finalized: Default::default(),
            thread,
            outbound_task: tokio::spawn(std::future::pending()),
        };
        let joining = tokio::spawn(handle.shutdown_and_join());
        tokio::time::timeout(std::time::Duration::from_secs(5), observed_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !joining.is_finished(),
            "replacement must wait for runtime exit"
        );
        release_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), joining)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(stopped.load(Ordering::Acquire));
    }

    /// A handle dropped without `shutdown_and_join` (its runtime torn down at
    /// process stop) asks its host to stop before closing the host's inputs,
    /// so the host reports a requested stop rather than a failure.
    #[tokio::test]
    async fn a_dropped_handle_requests_the_stop_before_closing_inputs() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let shutdown = Arc::new(AtomicBool::new(false));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let observer = {
            let flag = shutdown.clone();
            std::thread::spawn(move || {
                assert!(rx.blocking_recv().is_none());
                flag.load(Ordering::Acquire)
            })
        };
        let handle = AppConsensusCwHandle {
            _stop_on_drop: StopOnDrop(shutdown.clone()),
            inbound: [
                tx,
                tokio::sync::mpsc::unbounded_channel().0,
                tokio::sync::mpsc::unbounded_channel().0,
            ],
            ingest_block: Arc::new(|_| {}),
            shutdown: shutdown.clone(),
            adopted_genesis: None,
            finalized: Default::default(),
            thread: std::thread::spawn(|| {}),
            outbound_task: tokio::spawn(std::future::pending()),
        };
        assert!(!shutdown.load(Ordering::Acquire));
        drop(handle);
        assert!(
            observer.join().unwrap(),
            "inputs closed before the stop was requested"
        );
    }

    /// Certify `header` (its output digest at its rank) by `signer` alone.
    fn certify_head(
        header: &mut quil_types::proto::global::FrameHeader,
        signer: &quil_crypto::FalconSigner,
        namespace: &[u8],
    ) {
        use quil_cw_consensus::{
            _consensus::{
                simplex::{
                    scheme::Namespace,
                    types::{Finalization, Proposal, Subject},
                },
                types::{Epoch, Round, View},
            },
            _crypto::{sha256::Digest, Signer as _},
            _utils::{ordered::Set, N3f1},
            app_cert::{encode_finalization, wrap_cert_for_header},
            falcon_base::FalconPrivateKey,
            falcon_scheme::Generic,
            falcon_simplex::SimplexFalconScheme,
        };
        let key = FalconPrivateKey::from_bytes(signer.private_key(), signer.public_key()).unwrap();
        let participants: Set<_> = vec![key.public_key()].try_into().unwrap();
        let scheme = Generic::<Namespace>::signer(namespace, participants, key).unwrap();
        let proposal = Proposal::new(
            Round::new(Epoch::new(0), View::new(header.rank)),
            View::new(header.rank - 1),
            Digest(quil_crypto::poseidon::hash_bytes_to_32(&header.output).unwrap()),
        );
        let vote = scheme
            .sign::<SimplexFalconScheme, Digest>(Subject::Finalize {
                proposal: &proposal,
            })
            .unwrap();
        let certificate = scheme
            .assemble::<SimplexFalconScheme, _, N3f1>(vec![vote])
            .unwrap();
        header.public_key_signature_bls48581 =
            Some(quil_types::proto::keys::Bls48581AggregateSignature {
                signature: wrap_cert_for_header(&encode_finalization(&Finalization {
                    proposal,
                    certificate,
                })),
                bitmask: vec![1],
                ..Default::default()
            });
    }

    #[test]
    fn a_head_another_committee_certified_is_only_a_legacy_instances_genesis() {
        let then = quil_crypto::FalconSigner::generate();
        let now = quil_crypto::FalconSigner::generate();
        let committee = |signer: &quil_crypto::FalconSigner| {
            vec![FalconPublicKey::from_bytes(signer.public_key()).unwrap()]
        };
        let namespace = [b"appshard".as_slice(), &[7; 32]].concat();
        let mut head = quil_types::proto::global::FrameHeader {
            address: vec![7; 32],
            frame_number: 40,
            rank: 900,
            output: vec![4; 516],
            ..Default::default()
        };
        certify_head(&mut head, &then, &namespace);

        // The committee that certified it resumes from its finalization.
        for head_is_genesis in [false, true] {
            let verified =
                restart_finalization(&head, &committee(&then), &namespace, 0, head_is_genesis)
                    .unwrap()
                    .expect("its own committee's floor");
            assert_eq!(verified.finalization.proposal.round.view().get(), 900);
        }
        // Another committee starts from it only as the instance's genesis.
        assert!(
            restart_finalization(&head, &committee(&now), &namespace, 0, true)
                .unwrap()
                .is_none()
        );
        let Err(refused) = restart_finalization(&head, &committee(&now), &namespace, 0, false)
        else {
            panic!("accepted")
        };
        assert!(
            refused.to_string().contains("a handoff is required"),
            "{refused}"
        );
        // Another namespace (an authorized session's) never authenticates it.
        let session = [b"appsession".as_slice(), &[7; 32]].concat();
        assert!(restart_finalization(&head, &committee(&then), &session, 0, false).is_err());
        // Its own committee still refuses a head relabeled to another view or
        // a floor in another generation.
        let relabeled = quil_types::proto::global::FrameHeader {
            rank: 901,
            ..head.clone()
        };
        assert!(restart_finalization(&relabeled, &committee(&then), &namespace, 0, true).is_err());
        assert!(restart_finalization(&head, &committee(&then), &namespace, 1, true).is_err());
        // A head without a certificate has no floor to offer.
        let bare = quil_types::proto::global::FrameHeader {
            public_key_signature_bls48581: None,
            ..head.clone()
        };
        assert!(
            restart_finalization(&bare, &committee(&then), &namespace, 0, true)
                .unwrap()
                .is_none()
        );
        let Err(refused) = restart_finalization(&bare, &committee(&then), &namespace, 0, false)
        else {
            panic!("accepted")
        };
        assert!(
            refused
                .to_string()
                .contains("needs a finalized certificate"),
            "{refused}"
        );
    }

    #[tokio::test]
    async fn a_host_that_returns_unasked_is_dead() {
        use std::sync::atomic::AtomicBool;
        let (exit_tx, exit_rx) = std::sync::mpsc::channel::<()>();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = AppConsensusCwHandle {
            _stop_on_drop: StopOnDrop(shutdown.clone()),
            inbound: std::array::from_fn(|_| tokio::sync::mpsc::unbounded_channel().0),
            ingest_block: Arc::new(|_| {}),
            shutdown,
            adopted_genesis: None,
            finalized: Default::default(),
            thread: std::thread::spawn(move || {
                let _ = exit_rx.recv();
            }),
            outbound_task: tokio::spawn(std::future::pending()),
        };
        assert!(!handle.is_dead());
        exit_tx.send(()).unwrap();
        while !handle.thread.is_finished() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(handle.is_dead());
        handle.shutdown_and_join().await.unwrap();
    }

    fn closing_test_certificate() -> (Session, Seal, Vec<u8>) {
        use quil_types::crypto::Signer;
        let signer = quil_crypto::FalconSigner::generate();
        let session = Session {
            chain_id: [1; 32],
            filter: vec![1; 32],
            generation: 1,
            genesis: [2; 32],
            base_frame: 0,
            authorization: [3; 32],
            members: vec![signer.public_key().to_vec()],
        };
        let seal = Seal {
            request: [4; 32],
            session: session.id().unwrap(),
            view: 9,
            checkpoint: quil_cw_consensus::handoff::Checkpoint {
                frame: 0,
                view: 0,
                digest: session.genesis,
                state_roots: [[5; 32]; 4],
                history_root: [6; 32],
            },
        };
        let certificate = crate::test_support::certify_seal(&session, &[signer], &seal);
        (session, seal, certificate)
    }

    #[test]
    fn closing_certificate_survives_restart_before_or_after_queue_acceptance() {
        let (session, seal, certificate) = closing_test_certificate();
        let digest = digest_from_identity(seal.digest());
        for (durable, accepted) in [(false, true), (true, false), (true, true)] {
            let directory = test_directory("closing-certificate-replay");
            std::fs::create_dir_all(&directory).unwrap();
            let record = Arc::new(crate::closing_certificate::ClosingCertificate::new(
                directory.join("certificate"),
                session.clone(),
            ));
            let host = |store: BlockStore, seen: Arc<Mutex<Vec<(Vec<u8>, Vec<u8>)>>>, accepted| {
                let mut finalizer = AppSeamFinalizer::new(
                    Arc::new(|_| panic!("seal cannot become data")),
                    Arc::new(|_, _, _, _| panic!("seal cannot become data")),
                    store,
                    session.filter.clone(),
                )
                .with_sealed_sink(Arc::new(move |bytes, cert, _| {
                    seen.lock().unwrap().push((bytes, cert));
                    accepted
                }));
                if durable {
                    finalizer = finalizer.with_closing_certificate(record.clone());
                }
                finalizer
            };
            let store = BlockStore::new();
            store.seal(digest, seal.encode());
            let first = host(store, Default::default(), accepted);
            first.on_finalized(seal.view, digest, None, Some(certificate.clone()), true);
            assert_eq!(first.pending.lock().unwrap().is_empty(), accepted);
            drop(first);
            let seen = Arc::new(Mutex::new(Vec::new()));
            let restarted = host(BlockStore::new(), seen.clone(), true);
            assert_eq!(restarted.replay_closing_certificate().unwrap(), durable);
            assert_eq!(
                seen.lock().unwrap().as_slice(),
                if durable {
                    vec![(seal.encode(), certificate.clone())]
                } else {
                    vec![]
                }
                .as_slice()
            );
            assert!(restarted.pending.lock().unwrap().is_empty());
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn closing_certificate_replay_requires_the_original_session_and_valid_finalization() {
        let (session, seal, certificate) = closing_test_certificate();
        let directory = test_directory("closing-certificate-auth");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("certificate");
        let record =
            crate::closing_certificate::ClosingCertificate::new(path.clone(), session.clone());
        assert!(
            record.persist(&seal.encode(), &[]).is_err(),
            "notarization/body alone is insufficient"
        );
        assert!(record.load().unwrap().is_none());
        record.persist(&seal.encode(), &certificate).unwrap();
        let mut wrong = session;
        wrong.generation += 1;
        assert!(
            crate::closing_certificate::ClosingCertificate::new(path.clone(), wrong)
                .load()
                .is_err()
        );
        let mut bytes = std::fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(
            record.load().is_err(),
            "corrupted finalization must not be replayed"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn closing_certificate_io_failure_retains_pending_delivery_until_durable() {
        let (session, seal, certificate) = closing_test_certificate();
        let directory = test_directory("closing-certificate-io");
        std::fs::create_dir_all(&directory).unwrap();
        let blocked = directory.join("blocked");
        std::fs::write(&blocked, b"preserve").unwrap();
        let record = Arc::new(crate::closing_certificate::ClosingCertificate::new(
            blocked.join("certificate"),
            session.clone(),
        ));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let captured = seen.clone();
        let store = BlockStore::new();
        let digest = digest_from_identity(seal.digest());
        store.seal(digest, seal.encode());
        let finalizer = AppSeamFinalizer::new(
            Arc::new(|_| unreachable!()),
            Arc::new(|_, _, _, _| unreachable!()),
            store,
            session.filter,
        )
        .with_closing_certificate(record.clone())
        .with_sealed_sink(Arc::new(move |bytes, cert, _| {
            captured.lock().unwrap().push((bytes, cert));
            true
        }));
        finalizer.on_finalized(seal.view, digest, None, Some(certificate.clone()), true);
        assert!(seen.lock().unwrap().is_empty());
        assert!(finalizer.pending.lock().unwrap().contains_key(&digest));
        assert_eq!(std::fs::read(&blocked).unwrap(), b"preserve");
        std::fs::remove_file(&blocked).unwrap();
        finalizer.retry_pending();
        assert_eq!(*seen.lock().unwrap(), vec![(seal.encode(), certificate)]);
        assert!(record.load().unwrap().is_some());
        assert!(finalizer.pending.lock().unwrap().is_empty());
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn finalized_test_frame(number: u64) -> AppShardFrame {
        AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                address: vec![1; 32],
                frame_number: number,
                output: vec![number as u8; 32],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Frames `from..=to` of one shard, each linked to the one before it.
    fn linked_frames(from: u64, to: u64) -> Vec<AppShardFrame> {
        let mut frames: Vec<AppShardFrame> = Vec::new();
        for number in from..=to {
            let mut frame = finalized_test_frame(number);
            let header = frame.header.as_mut().unwrap();
            header.rank = number + 10;
            if let Some(parent) = frames.last() {
                header.parent_selector = quil_crypto::poseidon::hash_bytes_to_32(
                    &parent.header.as_ref().unwrap().output,
                )
                .unwrap()
                .to_vec();
            }
            frames.push(frame);
        }
        frames
    }

    type Delivered = Arc<Mutex<Vec<(u64, Vec<u8>, Vec<u64>)>>>;

    fn implied_host(
        records: &std::path::Path,
        cursor: u64,
        delivered: Delivered,
    ) -> (BlockStore, AppSeamFinalizer) {
        gap_host(
            records,
            Arc::new(std::sync::atomic::AtomicU64::new(cursor)),
            delivered,
        )
    }

    /// [`implied_host`] with a materialized cursor the test moves, as archive
    /// replay does.
    fn gap_host(
        records: &std::path::Path,
        cursor: Arc<std::sync::atomic::AtomicU64>,
        delivered: Delivered,
    ) -> (BlockStore, AppSeamFinalizer) {
        let store = BlockStore::new();
        let finalizer = AppSeamFinalizer::new(
            Arc::new(|_| {}),
            Arc::new(
                move |frame: AppShardFrame, cert, _, implied: Vec<(AppShardFrame, bool)>| {
                    delivered.lock().unwrap().push((
                        frame.header.unwrap().frame_number,
                        cert,
                        implied
                            .into_iter()
                            .map(|(ancestor, _)| ancestor.header.unwrap().frame_number)
                            .collect(),
                    ));
                    true
                },
            ),
            store.clone(),
            vec![1; 32],
        )
        .with_finalized_records(
            Arc::new(FinalizedRecords::open(records.to_path_buf()).unwrap()),
            cursor,
        );
        (store, finalizer)
    }

    /// A member built on a notarized parent before it finalized; the child's
    /// finalization makes the parent final, and GLOBAL halts if no member ever
    /// delivers it.
    #[test]
    fn a_finalized_frame_delivers_the_notarized_parent_it_makes_final() {
        let directory = test_directory("implied-parent");
        let frames = linked_frames(1, 3);
        let delivered: Delivered = Default::default();
        let (store, finalizer) = implied_host(&directory, 1, delivered.clone());
        for frame in &frames[1..] {
            store.seal(app_frame_digest(frame).unwrap(), encode_app_frame(frame));
        }
        finalizer.on_finalized(
            13,
            app_frame_digest(&frames[2]).unwrap(),
            None,
            Some(vec![3]),
            true,
        );
        assert_eq!(*delivered.lock().unwrap(), vec![(3, vec![3], vec![2])]);

        // After a restart that kept only the records, the chain is delivered
        // once more, from the certified descendant; the ancestor alone never is.
        let again: Delivered = Default::default();
        let (_, restarted) = implied_host(&directory, 1, again.clone());
        assert_eq!(restarted.replay_finalized_records().unwrap(), 1);
        assert_eq!(*again.lock().unwrap(), vec![(3, vec![3], vec![2])]);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A seal built on a notarized checkpoint makes that frame (and a notarized
    /// frame under it) final with no certificate of its own. They reach the
    /// engine with the seal, and again after a restart that kept only the
    /// records; one already delivered, or a broken chain, is not handed over.
    #[test]
    fn a_finalized_seal_delivers_the_notarized_checkpoint_it_makes_final() {
        use quil_types::crypto::Signer;
        let signer = quil_crypto::FalconSigner::generate();
        let session = Session {
            chain_id: [1; 32],
            filter: vec![1; 32],
            generation: 1,
            genesis: [2; 32],
            base_frame: 0,
            authorization: [3; 32],
            members: vec![signer.public_key().to_vec()],
        };
        let frames = linked_frames(1, 3);
        let checkpoint = &frames[2];
        let seal = Seal {
            request: [4; 32],
            session: session.id().unwrap(),
            view: 20,
            checkpoint: quil_cw_consensus::handoff::Checkpoint {
                frame: 3,
                view: checkpoint.header.as_ref().unwrap().rank,
                digest: app_frame_digest(checkpoint).unwrap().0,
                state_roots: [[5; 32]; 4],
                history_root: [6; 32],
            },
        };
        let certificate = crate::test_support::certify_seal(&session, &[signer], &seal);
        let digest = digest_from_identity(seal.digest());
        type Sealed = Arc<Mutex<Vec<Vec<u64>>>>;
        let host = |directory: &std::path::Path, cursor: u64, sealed: Sealed| {
            let store = BlockStore::new();
            let finalizer = AppSeamFinalizer::new(
                Arc::new(|_| {}),
                Arc::new(|_, _, _, _| panic!("no data frame finalized")),
                store.clone(),
                vec![1; 32],
            )
            .with_finalized_records(
                Arc::new(FinalizedRecords::open(directory.join("records")).unwrap()),
                Arc::new(std::sync::atomic::AtomicU64::new(cursor)),
            )
            .with_closing_certificate(Arc::new(
                crate::closing_certificate::ClosingCertificate::new(
                    directory.join("certificate"),
                    session.clone(),
                ),
            ))
            .with_sealed_sink(Arc::new(
                move |_, _, implied: Vec<(AppShardFrame, bool)>| {
                    sealed.lock().unwrap().push(
                        implied
                            .into_iter()
                            .map(|(frame, _)| frame.header.unwrap().frame_number)
                            .collect(),
                    );
                    true
                },
            ));
            (store, finalizer)
        };
        let deliver = |directory: &std::path::Path, cursor: u64, bodies: &[&AppShardFrame]| {
            std::fs::create_dir_all(directory).unwrap();
            let sealed: Sealed = Default::default();
            let (store, finalizer) = host(directory, cursor, sealed.clone());
            for frame in bodies {
                store.seal(app_frame_digest(frame).unwrap(), encode_app_frame(frame));
            }
            store.seal(digest, seal.encode());
            finalizer.on_finalized(seal.view, digest, None, Some(certificate.clone()), true);
            assert!(finalizer.pending.lock().unwrap().is_empty());
            let delivered = sealed.lock().unwrap().clone();
            delivered
        };

        let directory = test_directory("seal-implied");
        assert_eq!(
            deliver(&directory, 1, &[&frames[1], &frames[2]]),
            vec![vec![2, 3]]
        );
        let again: Sealed = Default::default();
        let (_, restarted) = host(&directory, 1, again.clone());
        assert_eq!(
            restarted.replay_finalized_records().unwrap(),
            0,
            "implied frames are bodies only"
        );
        assert!(restarted.replay_closing_certificate().unwrap());
        assert_eq!(*again.lock().unwrap(), vec![vec![2, 3]]);
        std::fs::remove_dir_all(&directory).unwrap();

        let directory = test_directory("seal-implied-delivered");
        assert_eq!(
            deliver(&directory, 3, &[&frames[1], &frames[2]]),
            vec![Vec::<u64>::new()]
        );
        std::fs::remove_dir_all(&directory).unwrap();
        let directory = test_directory("seal-implied-broken");
        assert_eq!(
            deliver(&directory, 1, &[&frames[2]]),
            vec![Vec::<u64>::new()],
            "frame 2's body is missing"
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_parent_that_does_not_link_is_not_delivered() {
        let directory = test_directory("implied-unlinked");
        for corrupt in [0, 1, 2] {
            let mut frames = linked_frames(1, 3);
            let parent = frames[1].header.as_mut().unwrap();
            match corrupt {
                0 => parent.rank = 20,
                1 => parent.address = vec![2; 32],
                _ => frames[2].header.as_mut().unwrap().parent_selector = vec![9; 32],
            }
            let delivered: Delivered = Default::default();
            let (store, finalizer) =
                implied_host(&directory.join(corrupt.to_string()), 1, delivered.clone());
            for frame in &frames[1..] {
                store.seal(app_frame_digest(frame).unwrap(), encode_app_frame(frame));
            }
            finalizer.on_finalized(
                13,
                app_frame_digest(&frames[2]).unwrap(),
                None,
                Some(vec![3]),
                true,
            );
            assert_eq!(
                *delivered.lock().unwrap(),
                vec![(3, vec![3], vec![])],
                "case {corrupt}"
            );
        }
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn finalization_waits_for_body_and_coalesces_pending_reports() {
        let store = BlockStore::new();
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let out = delivered.clone();
        let finalizer = AppSeamFinalizer::new(
            Arc::new(|_| {}),
            Arc::new(move |frame, cert, verified, _implied| {
                out.lock().unwrap().push((frame, cert, verified));
                true
            }),
            store.clone(),
            vec![1; 32],
        );
        let frame = finalized_test_frame(1);
        let digest = app_frame_digest(&frame).unwrap();
        for _ in 0..2 {
            finalizer.on_finalized(1, digest, None, Some(vec![7]), false);
        }
        assert_eq!(finalizer.pending.lock().unwrap().len(), 1);
        assert!(delivered.lock().unwrap().is_empty());
        store.put(digest, encode_app_frame(&frame));
        finalizer.retry_pending();
        finalizer.retry_pending();
        assert_eq!(*delivered.lock().unwrap(), vec![(frame, vec![7], false)]);
        assert!(finalizer.pending.lock().unwrap().is_empty());
    }

    #[test]
    fn finalizations_retry_backpressure_in_view_order_and_preserve_verification() {
        let store = BlockStore::new();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        tx.try_send((finalized_test_frame(0), vec![], false))
            .unwrap();
        let finalizer = AppSeamFinalizer::new(
            Arc::new(|_| {}),
            Arc::new(move |frame, cert, verified, _implied| {
                tx.try_send((frame, cert, verified)).is_ok()
            }),
            store.clone(),
            vec![1; 32],
        );
        let first = finalized_test_frame(1);
        let second = finalized_test_frame(2);
        let first_id = app_frame_digest(&first).unwrap();
        let second_id = app_frame_digest(&second).unwrap();
        finalizer.on_finalized(10, first_id, None, Some(vec![10]), false);
        store.seal(second_id, encode_app_frame(&second));
        finalizer.on_finalized(
            20,
            second_id,
            Some(encode_app_frame(&second)),
            Some(vec![20]),
            true,
        );
        store.put(first_id, encode_app_frame(&first));
        finalizer.retry_pending();
        assert_eq!(
            finalizer.pending.lock().unwrap().len(),
            2,
            "full queue retains both"
        );
        rx.try_recv().unwrap(); // clear the occupied slot
        finalizer.retry_pending();
        assert_eq!(rx.try_recv().unwrap(), (first, vec![10], false));
        assert_eq!(finalizer.pending.lock().unwrap().len(), 1);
        finalizer.retry_pending();
        assert_eq!(rx.try_recv().unwrap(), (second, vec![20], true));
        assert!(finalizer.pending.lock().unwrap().is_empty());
    }

    #[test]
    fn sealed_bodies_survive_a_restart_and_reject_anything_but_their_own_contents() {
        let directory = std::env::temp_dir().join(format!(
            "quil-sealed-bodies-{}-{:?}",
            std::process::id(),
            std::time::Instant::now()
        ));
        let bodies = SealedBodies::open(directory.clone()).unwrap();
        let frames: Vec<_> = (5..8).map(finalized_test_frame).collect();
        for frame in &frames {
            bodies
                .persist(&app_frame_digest(frame).unwrap(), &encode_app_frame(frame))
                .unwrap();
        }
        // A stray file and a body stored under another body's name are dropped.
        std::fs::write(directory.join("not-a-body"), b"junk").unwrap();
        std::fs::write(
            directory.join(hex::encode([7u8; 32])),
            encode_app_frame(&frames[0]),
        )
        .unwrap();
        let reopened = SealedBodies::open(directory.clone()).unwrap();
        let mut restored = reopened.load().unwrap();
        restored.sort_by_key(|(_, bytes)| {
            decode_app_frame(bytes)
                .unwrap()
                .header
                .unwrap()
                .frame_number
        });
        assert_eq!(
            restored,
            frames
                .iter()
                .map(|f| (app_frame_digest(f).unwrap(), encode_app_frame(f)))
                .collect::<Vec<_>>()
        );
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 3);
        // Delivering frame 6 makes it and everything below it unnecessary.
        reopened.prune_through(6);
        let left = reopened.load().unwrap();
        assert_eq!(
            left,
            vec![(
                app_frame_digest(&frames[2]).unwrap(),
                encode_app_frame(&frames[2])
            )]
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    fn test_directory(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "quil-{name}-{}-{:?}",
            std::process::id(),
            std::time::Instant::now()
        ))
    }

    #[test]
    fn finalized_records_survive_a_restart_and_drop_malformed_ones() {
        let directory = test_directory("finalized-records");
        let records = FinalizedRecords::open(directory.clone()).unwrap();
        for number in 5..8 {
            let bytes = encode_app_frame(&finalized_test_frame(number));
            records
                .persist(number, &[number as u8; 3], number % 2 == 0, &bytes)
                .unwrap();
        }
        // The latest delivery of a frame number wins.
        records
            .persist(
                6,
                &[0xee],
                false,
                &encode_app_frame(&finalized_test_frame(6)),
            )
            .unwrap();
        records
            .persist(
                6,
                &[6; 3],
                true,
                &encode_app_frame(&finalized_test_frame(6)),
            )
            .unwrap();
        // A stray file, a record under another frame's number and a truncated
        // record are dropped.
        std::fs::write(directory.join("not-a-record"), b"junk").unwrap();
        std::fs::copy(records.path(5), records.path(9)).unwrap();
        std::fs::write(records.path(10), [0, 0, 0, 9, 1]).unwrap();
        let reopened = FinalizedRecords::open(directory.clone()).unwrap();
        let loaded = reopened.load_above(5).unwrap();
        assert_eq!(
            loaded,
            (6..8)
                .map(|number| (
                    number,
                    encode_app_frame(&finalized_test_frame(number)),
                    Some(vec![number as u8; 3]),
                    number % 2 == 0,
                ))
                .collect::<Vec<_>>()
        );
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 3);
        reopened.prune_through(6);
        assert_eq!(
            reopened
                .load_above(0)
                .unwrap()
                .iter()
                .map(|r| r.0)
                .collect::<Vec<_>>(),
            vec![7]
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A sole-member shard's frame 2: delivery is queued, the process restarts
    /// before the engine materializes it, the next instance finalizes frame 3,
    /// and without replay GLOBAL waits on frame 2 forever.
    #[test]
    fn a_finalized_frame_the_engine_never_materialized_is_delivered_again_after_a_restart() {
        let records_dir = test_directory("finalized-replay");
        let bodies_dir = test_directory("finalized-replay-bodies");
        let materialized = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let frame = |number: u64| {
            let mut frame = finalized_test_frame(number);
            frame.header.as_mut().unwrap().rank = number + 10;
            frame
        };
        let host = |delivered: Arc<Mutex<Vec<(u64, Vec<u8>, bool)>>>| {
            let store = BlockStore::new();
            let finalizer = AppSeamFinalizer::new(
                Arc::new(|_| {}),
                Arc::new(move |frame: AppShardFrame, cert, verified, _implied| {
                    delivered.lock().unwrap().push((
                        frame.header.unwrap().frame_number,
                        cert,
                        verified,
                    ));
                    true
                }),
                store.clone(),
                vec![1; 32],
            )
            .with_sealed_bodies(Arc::new(SealedBodies::open(bodies_dir.clone()).unwrap()))
            .with_finalized_records(
                Arc::new(FinalizedRecords::open(records_dir.clone()).unwrap()),
                materialized.clone(),
            );
            (store, finalizer)
        };
        let finalize = |store: &BlockStore, finalizer: &AppSeamFinalizer, number: u64| {
            let frame = frame(number);
            let digest = app_frame_digest(&frame).unwrap();
            store.seal(digest, encode_app_frame(&frame));
            finalizer
                .sealed_bodies
                .as_ref()
                .unwrap()
                .persist(&digest, &encode_app_frame(&frame))
                .unwrap();
            finalizer.on_finalized(number + 10, digest, None, Some(vec![number as u8]), true);
        };

        // The first instance hands frames 2 and 3 to the engine, which never
        // materializes them.
        let first = Arc::new(Mutex::new(Vec::new()));
        let (store, finalizer) = host(first.clone());
        finalize(&store, &finalizer, 2);
        finalize(&store, &finalizer, 3);
        assert_eq!(
            *first.lock().unwrap(),
            vec![(2, vec![2], true), (3, vec![3], true)]
        );
        assert_eq!(
            SealedBodies::open(bodies_dir.clone())
                .unwrap()
                .load()
                .unwrap()
                .len(),
            2,
            "bodies are kept until materialized, not until delivered"
        );
        drop((store, finalizer));
        // Another shard's record in the directory must not hold back delivery.
        let mut foreign = frame(4);
        foreign.header.as_mut().unwrap().address = vec![2; 32];
        FinalizedRecords::open(records_dir.clone())
            .unwrap()
            .persist(4, &[9], true, &encode_app_frame(&foreign))
            .unwrap();

        // The restarted instance holds nothing in memory; its records deliver
        // both frames again, in order, with their own certificates.
        let second = Arc::new(Mutex::new(Vec::new()));
        let (store, finalizer) = host(second.clone());
        assert_eq!(finalizer.replay_finalized_records().unwrap(), 2);
        assert_eq!(
            *second.lock().unwrap(),
            vec![(2, vec![2], true), (3, vec![3], true)]
        );
        assert!(finalizer.pending.lock().unwrap().is_empty());

        // Once the engine has materialized them, the next delivery prunes them.
        materialized.store(3, std::sync::atomic::Ordering::SeqCst);
        finalize(&store, &finalizer, 5);
        let left: Vec<u64> = FinalizedRecords::open(records_dir.clone())
            .unwrap()
            .load_above(0)
            .unwrap()
            .iter()
            .map(|record| record.0)
            .collect();
        assert_eq!(left, vec![4, 5]);
        assert_eq!(
            SealedBodies::open(bodies_dir.clone())
                .unwrap()
                .load()
                .unwrap()
                .len(),
            1
        );
        for directory in [records_dir, bodies_dir] {
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn a_finalized_seal_reaches_only_a_session_host_and_never_the_data_sink() {
        use quil_cw_consensus::handoff::Checkpoint;
        let seal = Seal {
            request: [1; 32],
            session: [2; 32],
            view: 9,
            checkpoint: Checkpoint {
                frame: 4,
                view: 7,
                digest: [3; 32],
                state_roots: [[4; 32]; 4],
                history_root: [5; 32],
            },
        };
        let digest = digest_from_identity(seal.digest());
        let data = Arc::new(Mutex::new(0usize));
        let sealed = Arc::new(Mutex::new(Vec::new()));
        let build = |with_sink: bool| {
            let store = BlockStore::new();
            let data = data.clone();
            let mut finalizer = AppSeamFinalizer::new(
                Arc::new(|_| {}),
                Arc::new(move |_, _, _, _| {
                    *data.lock().unwrap() += 1;
                    true
                }),
                store.clone(),
                vec![1; 32],
            );
            if with_sink {
                let sealed = sealed.clone();
                finalizer = finalizer.with_sealed_sink(Arc::new(move |bytes, cert, _| {
                    sealed.lock().unwrap().push((bytes, cert));
                    true
                }));
            }
            (store, finalizer)
        };
        // A legacy host has nowhere to deliver the reserved encoding.
        let (store, legacy) = build(false);
        store.put(digest, seal.encode());
        legacy.on_finalized(9, digest, None, Some(vec![7]), false);
        assert!(
            legacy.pending.lock().unwrap().is_empty(),
            "dropped: it could never be delivered here"
        );
        // Bytes stored under another digest are not this seal.
        let (store, host) = build(true);
        store.put(digest_from_identity([9; 32]), seal.encode());
        host.on_finalized(9, digest_from_identity([9; 32]), None, Some(vec![7]), false);
        assert!(sealed.lock().unwrap().is_empty());
        // (A fresh host: pending finalizations deliver in view order, so the
        // undeliverable one above would rightly hold back anything after it.)
        let (store, host) = build(true);
        store.put(digest, seal.encode());
        host.on_finalized(9, digest, None, Some(vec![8]), false);
        assert_eq!(*sealed.lock().unwrap(), vec![(seal.encode(), vec![8])]);
        assert_eq!(*data.lock().unwrap(), 0);
    }

    /// A finalization reported across a restart whose block this worker never
    /// verified: its body went with the old process, and archive replay
    /// materializes the frame instead. Later finalizations, the seal included,
    /// must still reach the engine (2026-10-21: seven workers materialized
    /// every frame by archive replay until their next session started).
    #[test]
    fn a_finalization_whose_body_was_lost_across_a_restart_does_not_hold_back_later_ones() {
        use quil_cw_consensus::handoff::Checkpoint;
        use std::sync::atomic::{AtomicU64, Ordering};
        let directory = test_directory("restart-gap");
        let frames = linked_frames(5, 9);
        let digest = |number: u64| app_frame_digest(&frames[number as usize - 5]).unwrap();
        let body = |number: u64| encode_app_frame(&frames[number as usize - 5]);
        let cursor = Arc::new(AtomicU64::new(5));
        let delivered: Delivered = Default::default();
        let sealed = Arc::new(Mutex::new(Vec::new()));
        let (store, finalizer) = gap_host(&directory, cursor.clone(), delivered.clone());
        let finalizer = finalizer.with_sealed_sink({
            let sealed = sealed.clone();
            Arc::new(
                move |bytes: Vec<u8>, cert: Vec<u8>, implied: Vec<(AppShardFrame, bool)>| {
                    sealed.lock().unwrap().push((bytes, cert, implied.len()));
                    true
                },
            )
        });
        // Frame 6 finalized across the restart; only the bodies of frames 7
        // and 8 are held.
        finalizer.on_finalized(16, digest(6), None, Some(vec![6]), true);
        for number in [7, 8] {
            store.seal(digest(number), body(number));
            finalizer.on_finalized(
                number + 10,
                digest(number),
                None,
                Some(vec![number as u8]),
                true,
            );
        }
        assert!(
            delivered.lock().unwrap().is_empty(),
            "frames 7 and 8 wait for frame 6"
        );

        // Archive replay materializes all three, without the block store.
        // Frames 7 and 8 still reach the engine, which republishes them with
        // their reward proofs; frame 6 has no body to deliver.
        cursor.store(8, Ordering::SeqCst);
        finalizer.retry_pending();
        assert!(finalizer.pending.lock().unwrap().is_empty());
        assert_eq!(
            *delivered.lock().unwrap(),
            vec![(7, vec![7], vec![]), (8, vec![8], vec![])]
        );

        // A seal waits behind another lost body until replay passes it.
        let seal = Seal {
            request: [4; 32],
            session: [5; 32],
            view: 20,
            checkpoint: Checkpoint {
                frame: 9,
                view: 19,
                digest: digest(9).0,
                state_roots: [[6; 32]; 4],
                history_root: [7; 32],
            },
        };
        let seal_digest = digest_from_identity(seal.digest());
        finalizer.on_finalized(19, digest(9), None, Some(vec![9]), true);
        store.seal(seal_digest, seal.encode());
        finalizer.on_finalized(20, seal_digest, None, Some(vec![20]), true);
        assert!(
            sealed.lock().unwrap().is_empty(),
            "the seal waits for frame 9"
        );
        cursor.store(9, Ordering::SeqCst);
        finalizer.retry_pending();
        assert_eq!(*sealed.lock().unwrap(), vec![(seal.encode(), vec![20], 0)]);
        assert!(finalizer.pending.lock().unwrap().is_empty());
        assert_eq!(delivered.lock().unwrap().len(), 2);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A lost body above the materialized cursor still holds back later
    /// frames: delivering frame 7 first would skip frame 6. Once the body
    /// arrives, both go in order, each recorded before it is handed over.
    #[test]
    fn a_missing_body_above_the_cursor_still_holds_back_later_finalizations() {
        let directory = test_directory("gap-in-order");
        let frames = linked_frames(5, 7);
        let delivered: Delivered = Default::default();
        let (store, finalizer) = implied_host(&directory, 5, delivered.clone());
        finalizer.on_finalized(
            16,
            app_frame_digest(&frames[1]).unwrap(),
            None,
            Some(vec![6]),
            true,
        );
        store.seal(
            app_frame_digest(&frames[2]).unwrap(),
            encode_app_frame(&frames[2]),
        );
        finalizer.on_finalized(
            17,
            app_frame_digest(&frames[2]).unwrap(),
            None,
            Some(vec![7]),
            true,
        );
        finalizer.retry_pending();
        assert!(delivered.lock().unwrap().is_empty());
        assert_eq!(finalizer.pending.lock().unwrap().len(), 2);
        store.put(
            app_frame_digest(&frames[1]).unwrap(),
            encode_app_frame(&frames[1]),
        );
        finalizer.retry_pending();
        assert_eq!(
            *delivered.lock().unwrap(),
            vec![(6, vec![6], vec![]), (7, vec![7], vec![])]
        );
        let recorded: Vec<u64> = FinalizedRecords::open(directory.clone())
            .unwrap()
            .load_above(5)
            .unwrap()
            .iter()
            .map(|record| record.0)
            .collect();
        assert_eq!(
            recorded,
            vec![6, 7],
            "kept until the engine materializes them"
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A finalization that arrives after archive replay materialized its
    /// frame still reaches the engine: it republishes the frame with its
    /// reward proof, which archive replay never sends.
    #[test]
    fn a_finalization_the_engine_already_materialized_is_still_handed_over() {
        let directory = test_directory("already-materialized");
        let frames = linked_frames(5, 7);
        let delivered: Delivered = Default::default();
        let (store, finalizer) = implied_host(&directory, 6, delivered.clone());
        for frame in &frames[1..] {
            store.seal(app_frame_digest(frame).unwrap(), encode_app_frame(frame));
        }
        finalizer.on_finalized(
            16,
            app_frame_digest(&frames[1]).unwrap(),
            None,
            Some(vec![6]),
            true,
        );
        assert!(finalizer.pending.lock().unwrap().is_empty());
        finalizer.on_finalized(
            17,
            app_frame_digest(&frames[2]).unwrap(),
            None,
            Some(vec![7]),
            true,
        );
        assert_eq!(
            *delivered.lock().unwrap(),
            vec![(6, vec![6], vec![]), (7, vec![7], vec![])]
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A record replayed from an earlier session carries that session's view
    /// numbering; it must not drop this session's finalizations as if they
    /// were below it.
    #[test]
    fn a_record_from_an_earlier_session_does_not_drop_finalizations_of_this_one() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        let directory = test_directory("cross-session-anchor");
        let mut frames = linked_frames(5, 7);
        frames[1].header.as_mut().unwrap().rank = 900;
        FinalizedRecords::open(directory.clone())
            .unwrap()
            .persist(6, &[6], true, &encode_app_frame(&frames[1]))
            .unwrap();
        let accept = Arc::new(AtomicBool::new(false));
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let finalizer = {
            let (accept, out) = (accept.clone(), delivered.clone());
            AppSeamFinalizer::new(
                Arc::new(|_| {}),
                Arc::new(move |frame: AppShardFrame, _, _, _| {
                    let accepted = accept.load(Ordering::SeqCst);
                    if accepted {
                        out.lock().unwrap().push(frame.header.unwrap().frame_number);
                    }
                    accepted
                }),
                BlockStore::new(),
                vec![1; 32],
            )
            .with_finalized_records(
                Arc::new(FinalizedRecords::open(directory.clone()).unwrap()),
                Arc::new(AtomicU64::new(5)),
            )
        };
        assert_eq!(finalizer.replay_finalized_records().unwrap(), 1);
        // This session's view 16 finalized frame 7, whose body was lost.
        let later = app_frame_digest(&frames[2]).unwrap();
        finalizer.on_finalized(16, later, None, Some(vec![7]), true);
        finalizer.retry_pending();
        assert!(finalizer.pending.lock().unwrap().contains_key(&later));
        assert!(delivered.lock().unwrap().is_empty());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// After a lost body is dropped, the next frame is still recorded before
    /// it is handed to the engine.
    #[test]
    fn the_frame_after_a_dropped_entry_is_recorded_before_the_send() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let directory = test_directory("record-after-drop");
        let frames = linked_frames(5, 7);
        let cursor = Arc::new(AtomicU64::new(5));
        let recorded_at_send = Arc::new(Mutex::new(Vec::new()));
        let store = BlockStore::new();
        let finalizer = {
            let (seen, records) = (recorded_at_send.clone(), directory.clone());
            AppSeamFinalizer::new(
                Arc::new(|_| {}),
                Arc::new(move |frame: AppShardFrame, _, _, _| {
                    let held: Vec<u64> = FinalizedRecords::open(records.clone())
                        .unwrap()
                        .load_above(0)
                        .unwrap()
                        .iter()
                        .map(|record| record.0)
                        .collect();
                    seen.lock()
                        .unwrap()
                        .push((frame.header.unwrap().frame_number, held));
                    true
                }),
                store.clone(),
                vec![1; 32],
            )
            .with_finalized_records(
                Arc::new(FinalizedRecords::open(directory.clone()).unwrap()),
                cursor.clone(),
            )
        };
        finalizer.on_finalized(
            16,
            app_frame_digest(&frames[1]).unwrap(),
            None,
            Some(vec![6]),
            true,
        );
        store.seal(
            app_frame_digest(&frames[2]).unwrap(),
            encode_app_frame(&frames[2]),
        );
        finalizer.on_finalized(
            17,
            app_frame_digest(&frames[2]).unwrap(),
            None,
            Some(vec![7]),
            true,
        );
        cursor.store(6, Ordering::SeqCst);
        finalizer.retry_pending();
        assert_eq!(*recorded_at_send.lock().unwrap(), vec![(7, vec![7])]);
        assert!(finalizer.pending.lock().unwrap().is_empty());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// Bytes this node did not verify cannot make a pending finalization look
    /// materialized: the digest binds only the output, so a peer can store a
    /// header with a lower frame number under it.
    #[test]
    fn unverified_bytes_do_not_drop_pending_finalizations() {
        let directory = test_directory("unverified-anchor");
        let frames = linked_frames(5, 7);
        let delivered: Delivered = Default::default();
        let (store, finalizer) = implied_host(&directory, 5, delivered.clone());
        let mut forged = frames[2].clone();
        forged.header.as_mut().unwrap().frame_number = 3;
        let forged_digest = app_frame_digest(&forged).unwrap();
        assert_eq!(forged_digest, app_frame_digest(&frames[2]).unwrap());
        finalizer.on_finalized(
            16,
            app_frame_digest(&frames[1]).unwrap(),
            None,
            Some(vec![6]),
            true,
        );
        store.put(forged_digest, encode_app_frame(&forged));
        finalizer.on_finalized(17, forged_digest, None, Some(vec![7]), true);
        finalizer.retry_pending();
        assert_eq!(finalizer.pending.lock().unwrap().len(), 2);
        assert!(delivered.lock().unwrap().is_empty());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A legacy host drops a finalized seal it can never deliver instead of
    /// holding every later finalization behind it.
    #[test]
    fn a_seal_a_legacy_host_cannot_deliver_does_not_hold_back_later_frames() {
        use quil_cw_consensus::handoff::Checkpoint;
        let seal = Seal {
            request: [1; 32],
            session: [2; 32],
            view: 9,
            checkpoint: Checkpoint {
                frame: 4,
                view: 7,
                digest: [3; 32],
                state_roots: [[4; 32]; 4],
                history_root: [5; 32],
            },
        };
        let seal_digest = digest_from_identity(seal.digest());
        let store = BlockStore::new();
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let out = delivered.clone();
        let finalizer = AppSeamFinalizer::new(
            Arc::new(|_| {}),
            Arc::new(move |frame: AppShardFrame, _, _, _| {
                out.lock().unwrap().push(frame.header.unwrap().frame_number);
                true
            }),
            store.clone(),
            vec![1; 32],
        );
        store.seal(seal_digest, seal.encode());
        finalizer.on_finalized(9, seal_digest, None, Some(vec![9]), true);
        let frame = finalized_test_frame(5);
        store.seal(app_frame_digest(&frame).unwrap(), encode_app_frame(&frame));
        finalizer.on_finalized(
            10,
            app_frame_digest(&frame).unwrap(),
            None,
            Some(vec![10]),
            true,
        );
        assert_eq!(*delivered.lock().unwrap(), vec![5]);
        assert!(finalizer.pending.lock().unwrap().is_empty());
    }

    /// The operator hears of a stuck head after 30 s, again every 10 min,
    /// and when it clears; a missing body with nothing behind it is the
    /// engine's own gap and stays silent here.
    #[test]
    fn a_stuck_head_warns_after_thirty_seconds_repeats_every_ten_minutes_and_reports_its_end() {
        use std::time::Duration;
        let directory = test_directory("head-stall");
        let frames = linked_frames(5, 7);
        let (_, alone) = implied_host(&directory.join("alone"), 5, Default::default());
        alone.on_finalized(
            16,
            app_frame_digest(&frames[1]).unwrap(),
            None,
            Some(vec![6]),
            true,
        );
        let start = std::time::Instant::now();
        assert_eq!(
            alone.retry_pending_at(start + Duration::from_secs(40)),
            None
        );

        let delivered: Delivered = Default::default();
        let (store, finalizer) = implied_host(&directory.join("held"), 5, delivered.clone());
        finalizer.on_finalized(
            16,
            app_frame_digest(&frames[1]).unwrap(),
            None,
            Some(vec![6]),
            true,
        );
        store.seal(
            app_frame_digest(&frames[2]).unwrap(),
            encode_app_frame(&frames[2]),
        );
        finalizer.on_finalized(
            17,
            app_frame_digest(&frames[2]).unwrap(),
            None,
            Some(vec![7]),
            true,
        );
        let start = std::time::Instant::now();
        let at = |secs| start + Duration::from_secs(secs);
        assert_eq!(finalizer.retry_pending_at(at(20)), None);
        assert_eq!(
            finalizer.retry_pending_at(at(31)),
            Some(HeadSignal::Stalled)
        );
        assert_eq!(finalizer.retry_pending_at(at(300)), None);
        assert_eq!(
            finalizer.retry_pending_at(at(631)),
            Some(HeadSignal::StillStalled)
        );
        assert_eq!(finalizer.retry_pending_at(at(700)), None);
        store.put(
            app_frame_digest(&frames[1]).unwrap(),
            encode_app_frame(&frames[1]),
        );
        assert_eq!(
            finalizer.retry_pending_at(at(701)),
            Some(HeadSignal::Cleared)
        );
        assert_eq!(finalizer.retry_pending_at(at(702)), None);
        assert_eq!(
            delivered
                .lock()
                .unwrap()
                .iter()
                .map(|d| d.0)
                .collect::<Vec<_>>(),
            vec![6, 7]
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn finalization_retains_certificate_until_matching_body_arrives() {
        let store = BlockStore::new();
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let out = delivered.clone();
        let finalizer = AppSeamFinalizer::new(
            Arc::new(|_| {}),
            Arc::new(move |frame, _, _, _| {
                out.lock().unwrap().push(frame);
                true
            }),
            store.clone(),
            vec![1; 32],
        );
        let frame = finalized_test_frame(1);
        let digest = app_frame_digest(&frame).unwrap();
        finalizer.on_finalized(1, digest, None, Some(vec![7]), false);
        let mut wrong_shard = frame.clone();
        wrong_shard.header.as_mut().unwrap().address = vec![2; 32];
        for bytes in [
            vec![0xff],
            encode_app_frame(&wrong_shard),
            encode_app_frame(&finalized_test_frame(2)),
        ] {
            store.put(digest, bytes);
            finalizer.retry_pending();
            assert!(delivered.lock().unwrap().is_empty());
            assert_eq!(finalizer.pending.lock().unwrap().len(), 1);
        }
        store.put(digest, encode_app_frame(&frame));
        finalizer.retry_pending();
        assert_eq!(*delivered.lock().unwrap(), vec![frame]);
    }

    struct NoProposal;
    impl LeaderProvider<AppShardState> for NoProposal {
        fn get_next_leaders(
            &self,
            _: Option<&State<AppShardState>>,
        ) -> quil_types::error::Result<Vec<quil_consensus::models::Identity>> {
            unreachable!("an unavailable voter must not select a leader")
        }

        fn prove_next_state(
            &self,
            _: u64,
            _: &[u8],
            _: u64,
            _: &quil_consensus::models::Identity,
        ) -> quil_types::error::Result<State<AppShardState>> {
            unreachable!("an unavailable voter must not produce a proposal")
        }
    }

    #[test]
    fn peer_ingress_preserves_validated_parent_height_and_delivers_seals() {
        let proposer = Arc::new(AppSeamProposer::new(
            Arc::new(NoProposal),
            Arc::new(BlsAppFrameValidator::new(
                Arc::new(crate::test_support::TestProverRegistry::default()),
                Arc::new(quil_crypto::FalconKeyConstructor),
                Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            )),
            Arc::new(|_| unreachable!()),
            vec![1; 32],
            Some(Arc::new(|_| Ok(()))),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
        ));
        let store = BlockStore::new();
        let ingress = proposer.peer_ingress(store.clone());
        let mut frame = AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                address: vec![1; 32],
                frame_number: 7,
                output: vec![3; 32],
                ..Default::default()
            }),
            ..Default::default()
        };
        let digest = app_frame_digest(&frame).unwrap();
        let honest = encode_app_frame(&frame);
        proposer.note_frame(digest, 7);
        ingress(honest.clone());
        assert_eq!(store.get(&digest), Some(honest.clone()));
        // A frame below those already held, such as an unfinalized parent a
        // leader re-sends, is kept under its own digest, still unvalidated.
        let older = AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                address: vec![1; 32],
                frame_number: 3,
                output: vec![5; 32],
                ..Default::default()
            }),
            ..Default::default()
        };
        let older_digest = app_frame_digest(&older).unwrap();
        ingress(encode_app_frame(&older));
        assert_eq!(
            store.get_with_verification(&older_digest),
            Some((encode_app_frame(&older), false))
        );
        assert!(!proposer
            .block_meta
            .lock()
            .unwrap()
            .contains_key(&older_digest));
        frame.header.as_mut().unwrap().frame_number = u64::MAX / 2;
        assert_eq!(app_frame_digest(&frame), Some(digest));
        let forged = encode_app_frame(&frame);
        ingress(forged.clone());
        assert_eq!(store.get(&digest), Some(forged.clone()));
        assert_eq!(proposer.block_meta.lock().unwrap().get(&digest), Some(&7));
        store.seal(digest, honest.clone());
        ingress(forged);
        assert_eq!(store.get(&digest), Some(honest));
        ingress(vec![0xff]);
        frame.header.as_mut().unwrap().output = vec![4; 32];
        let unknown = app_frame_digest(&frame).unwrap();
        ingress(encode_app_frame(&frame));
        assert!(!proposer.block_meta.lock().unwrap().contains_key(&unknown));
        let seal = Seal {
            request: [1; 32],
            session: [2; 32],
            view: 9,
            checkpoint: quil_cw_consensus::handoff::Checkpoint {
                frame: 4,
                view: 7,
                digest: [3; 32],
                state_roots: [[4; 32]; 4],
                history_root: [5; 32],
            },
        };
        let bytes = seal.encode();
        ingress(bytes.clone());
        assert_eq!(store.get(&digest_from_identity(seal.digest())), Some(bytes));
        assert_eq!(proposer.block_meta.lock().unwrap().len(), 1);
        assert_eq!(proposer.block_meta.lock().unwrap().get(&digest), Some(&7));
    }

    #[test]
    fn unavailable_state_or_validation_disables_voting() {
        for (ready, has_check) in [(false, true), (true, false), (false, false)] {
            let validator = Arc::new(BlsAppFrameValidator::new(
                Arc::new(crate::test_support::TestProverRegistry::default()),
                Arc::new(quil_crypto::FalconKeyConstructor),
                Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            ));
            let check: Option<AppRequestsRootCheck> = has_check.then(|| {
                Arc::new(|_: &AppShardFrame| -> Result<(), CheckRefusal> {
                    panic!("state is unavailable")
                }) as AppRequestsRootCheck
            });
            let proposer = AppSeamProposer::new(
                Arc::new(NoProposal),
                validator,
                Arc::new(|_| unreachable!()),
                vec![1; 32],
                check,
                Arc::new(std::sync::atomic::AtomicBool::new(ready)),
            );
            let digest = digest_from_identity([0; 32]);
            assert!(proposer.propose(1, digest).is_none());
            assert!(!proposer.verify(1, digest, digest, None));
        }
    }

    #[test]
    fn app_proposal_must_match_consensus_shard_view_and_parent() {
        let filter = vec![1; 32];
        let proposer = AppSeamProposer::new(
            Arc::new(NoProposal),
            Arc::new(BlsAppFrameValidator::new(
                Arc::new(crate::test_support::TestProverRegistry::default()),
                Arc::new(quil_crypto::FalconKeyConstructor),
                Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            )),
            Arc::new(|_| unreachable!()),
            filter.clone(),
            Some(Arc::new(|_| Ok(()))),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
        );
        let liveness = Arc::new(Liveness::default());
        let proposer = proposer.with_liveness(Some(liveness.clone()));
        let mut header = quil_types::proto::global::FrameHeader {
            address: filter,
            frame_number: 7,
            rank: 43,
            parent_selector: vec![7; 32],
            state_roots: vec![vec![0; 32]; 4],
            ..Default::default()
        };
        header.output = quil_crypto::porep::deterministic_app_frame_output(
            &header.parent_selector,
            &header.requests_root,
            &header.state_roots,
            &quil_crypto::porep::derive_storage_beacon(0, &[]),
            header.frame_number,
            header.rank,
            &header.prover,
            header.difficulty,
            header.fee_multiplier_vote,
            header.timestamp,
            &header.storage_attestation_root,
            0,
            &header.settlements,
            &header.accumulator,
            &header.spends,
        );
        let frame = AppShardFrame {
            header: Some(header),
            ..Default::default()
        };
        let digest = app_frame_digest(&frame).unwrap();
        let parent = digest_from_identity([7; 32]);
        assert!(proposer.verify(43, parent, digest, Some(encode_app_frame(&frame))));
        assert!(!proposer.verify(44, parent, digest, Some(encode_app_frame(&frame))));
        assert!(!proposer.verify(
            43,
            digest_from_identity([8; 32]),
            digest,
            Some(encode_app_frame(&frame))
        ));
        let mut wrong_shard = frame;
        wrong_shard.header.as_mut().unwrap().address = vec![2; 32];
        assert!(!proposer.verify(43, parent, digest, Some(encode_app_frame(&wrong_shard))));
        // Each refusal is noted under its view with why.
        liveness.settle(Step::Verify, 43, false);
        liveness.settle(Step::Verify, 44, false);
        let refused = liveness.decisions().refused;
        assert_eq!(refused.get("shard, view or parent differs"), Some(&2));
        assert!(!proposer.verify(43, parent, digest, None));
        liveness.settle(Step::Verify, 43, false);
        assert_eq!(
            liveness.decisions().refused.get("block not delivered"),
            Some(&1)
        );
    }

    /// A proposal anchored one or two GLOBAL frames past this node's latest
    /// waits for the anchor rather than being refused; once it arrives the
    /// proposal is checked as usual. Further ahead, or a hole below the head,
    /// is refused, naming the frame and this node's latest.
    #[test]
    fn a_proposal_anchored_just_ahead_waits_for_its_global_frame() {
        use quil_cw_consensus::adapters::{GlobalProposer as _, ProposalContext};
        use quil_types::store::ClockStore as _;
        let db = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
        let put_global = |number: u64| {
            let frame = quil_types::proto::global::GlobalFrame {
                header: Some(quil_types::proto::global::GlobalFrameHeader {
                    frame_number: number,
                    output: vec![number as u8; 516],
                    ..Default::default()
                }),
                ..Default::default()
            };
            let txn = clock.new_transaction(false).unwrap();
            clock.put_global_clock_frame(&frame, txn.as_ref()).unwrap();
            txn.commit().unwrap();
        };
        for number in [5, 7, 8, 9, 10] {
            put_global(number);
        }
        let filter = vec![1; 32];
        let validator = Arc::new(
            BlsAppFrameValidator::new(
                Arc::new(crate::test_support::TestProverRegistry::default()),
                Arc::new(quil_crypto::FalconKeyConstructor),
                Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            )
            .with_clock_store(clock.clone()),
        );
        let proposer = AppSeamProposer::new(
            Arc::new(NoProposal),
            validator.clone(),
            Arc::new(|_| unreachable!()),
            filter.clone(),
            Some(Arc::new(|_| Ok(()))),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
        );
        let proposal = |anchor: u64| {
            let frame = AppShardFrame {
                header: Some(quil_types::proto::global::FrameHeader {
                    address: filter.clone(),
                    frame_number: 7,
                    rank: 43,
                    parent_selector: vec![7; 32],
                    state_roots: vec![vec![0; 32]; 4],
                    global_frame_number: anchor,
                    output: vec![3; 32],
                    ..Default::default()
                }),
                ..Default::default()
            };
            let context = ProposalContext {
                epoch: 0,
                view: 43,
                parent_view: 42,
                parent: digest_from_identity([7; 32]),
                leader: None,
            };
            (
                frame.clone(),
                context,
                app_frame_digest(&frame).unwrap(),
                Some(encode_app_frame(&frame)),
            )
        };
        for anchor in [11, 12] {
            let (_, context, digest, bytes) = proposal(anchor);
            assert_eq!(
                proposer.verify_or_defer(context, digest, bytes),
                Err(ANCHOR_DEFER),
                "anchor {anchor}"
            );
        }
        for anchor in [13, 6] {
            let (frame, context, digest, bytes) = proposal(anchor);
            assert_eq!(
                proposer.verify_or_defer(context, digest, bytes),
                Ok(false),
                "anchor {anchor}"
            );
            let error = validator.validate_proposal(&frame).unwrap_err().to_string();
            assert!(
                error.contains(&format!("anchored global frame {anchor} unavailable"))
                    && error.contains("latest local global frame: 10"),
                "{error}"
            );
        }
        put_global(11);
        let (frame, context, digest, bytes) = proposal(11);
        assert_eq!(validator.missing_global_anchor(&frame), None);
        assert!(
            proposer.verify_or_defer(context, digest, bytes).is_ok(),
            "checked once it arrives"
        );
    }

    #[test]
    fn unknown_parent_does_not_fall_back_to_genesis() {
        let proposer = AppSeamProposer::new(
            Arc::new(NoProposal),
            Arc::new(BlsAppFrameValidator::new(
                Arc::new(crate::test_support::TestProverRegistry::default()),
                Arc::new(quil_crypto::FalconKeyConstructor),
                Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            )),
            Arc::new(|_| unreachable!()),
            vec![1; 32],
            Some(Arc::new(|_| Ok(()))),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
        );
        proposer.note_frame(digest_from_identity([1; 32]), 0);
        assert!(proposer.propose(1, digest_from_identity([2; 32])).is_none());
        let store = BlockStore::new();
        let frame = AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                address: vec![1; 32],
                frame_number: 7,
                output: vec![3; 32],
                ..Default::default()
            }),
            ..Default::default()
        };
        proposer.recover_head(&store, &frame).unwrap();
        let digest = app_frame_digest(&frame).unwrap();
        assert_eq!(proposer.block_meta.lock().unwrap().get(&digest), Some(&7));
        assert_eq!(
            store.get_with_verification(&digest),
            Some((encode_app_frame(&frame), false))
        );
        let mut wrong_shard = frame;
        wrong_shard.header.as_mut().unwrap().address = vec![2; 32];
        assert!(proposer.recover_head(&store, &wrong_shard).is_err());
    }

    #[test]
    fn app_committee_builds_and_scopes_by_shard() {
        // This node + 2 other shard members.
        let me = quil_crypto::FalconSigner::generate();
        let others: Vec<quil_crypto::FalconSigner> = (0..2)
            .map(|_| quil_crypto::FalconSigner::generate())
            .collect();
        let mut members: Vec<Vec<u8>> = others.iter().map(|s| s.public_key().to_vec()).collect();
        members.push(me.public_key().to_vec());

        let app_a = vec![0xAAu8; 32];
        let (_scheme, peers) =
            build_app_committee(&members, me.private_key(), me.public_key(), &app_a)
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
}

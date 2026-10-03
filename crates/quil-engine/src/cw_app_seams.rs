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

use quil_cw_consensus::adapters::{ProposalContext, 
    digest_from_identity, digest_to_identity, Digest, FrameFinalizer, FrameSink, GlobalProposer,
    Recipients,
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
pub type AppFinalizedSink = Arc<dyn Fn(AppShardFrame, Vec<u8>, bool, Vec<(AppShardFrame, bool)>) -> bool + Send + Sync>;

/// Called with a finalized terminal seal's bytes and its finalization
/// certificate. Same contract as [`AppFinalizedSink`]: nonblocking, returns
/// true only when the engine accepted the notification.
pub type AppSealedSink = Arc<dyn Fn(Vec<u8>, Vec<u8>) -> bool + Send + Sync>;

/// A globally authorized committee session for this host. Its namespace, epoch
/// and genesis replace the legacy `appshard‖filter` / epoch-zero configuration,
/// and proposals pass through the terminal-seal automaton.
pub struct SessionHost {
    pub session: Session,
    pub read_parent: ParentReader,
    /// Authorizes a selected parent that is notarized but not yet
    /// materialized, from its private execution (see `AppParentExecutor`).
    pub read_private_parent: Option<ParentReader>,
    pub on_sealed: AppSealedSink,
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
/// `true` iff the proposal is safe to sign. It performs the two body/state
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
pub type AppRequestsRootCheck =
    Arc<dyn Fn(&quil_types::proto::global::AppShardFrame) -> bool + Send + Sync>;

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
            let named = path.file_name().and_then(|n| n.to_str()).and_then(|n| hex::decode(n).ok());
            let actual = if Seal::is_encoding(&bytes) {
                Seal::decode(&bytes).ok().map(|seal| seal.digest())
            } else {
                decode_app_frame(&bytes).as_ref().and_then(app_frame_digest).map(|d| digest_to_identity(&d))
            };
            match (named, actual) {
                (Some(named), Some(actual)) if named == actual => bodies.push((digest_from_identity(actual), bytes)),
                _ => { let _ = std::fs::remove_file(&path); }
            }
        }
        Ok(bodies)
    }

    /// Drop data-frame bodies at or below a delivered frame; they can no longer
    /// be a parent anyone needs.
    fn prune_through(&self, frame_number: u64) {
        let Ok(entries) = std::fs::read_dir(&self.directory) else { return };
        for path in entries.flatten().map(|entry| entry.path()) {
            let stale = std::fs::read(&path).ok()
                .and_then(|bytes| decode_app_frame(&bytes))
                .and_then(|frame| frame.header.map(|h| h.frame_number))
                .is_some_and(|number| number <= frame_number);
            if stale { let _ = std::fs::remove_file(&path); }
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

    fn write_synced(&self, path: &std::path::Path, staged: &std::path::Path, record: &[u8]) -> std::io::Result<()> {
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
    fn persist_implied(&self, frame_number: u64, verified: bool, bytes: &[u8]) -> std::io::Result<()> {
        let mut record = Vec::with_capacity(1 + bytes.len());
        record.push(verified as u8);
        record.extend_from_slice(bytes);
        let staged = self.directory.join(format!("{frame_number:020}.implied-staged"));
        self.write_synced(&self.implied_path(frame_number), &staged, &record)
    }

    /// `cert_len (4, BE) ‖ cert ‖ locally_verified (1) ‖ frame bytes`;
    /// write-then-rename, synced. The latest delivery of a frame number wins;
    /// an identical record is not rewritten (backpressured deliveries retry).
    fn persist(&self, frame_number: u64, cert: &[u8], verified: bool, bytes: &[u8]) -> std::io::Result<()> {
        let path = self.path(frame_number);
        let cert_len = u32::try_from(cert.len())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "certificate too large"))?;
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
    fn load_above(&self, after: u64) -> std::io::Result<Vec<(u64, Vec<u8>, Option<Vec<u8>>, bool)>> {
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
                _ => { let _ = std::fs::remove_file(&path); }
            }
        }
        records.sort_by_key(|record| (record.0, record.2.is_some()));
        Ok(records)
    }

    /// Drop records above `frame_number`: frames a GLOBAL fence discarded,
    /// after the shard rewound to the fence.
    pub(crate) fn discard_above(&self, frame_number: u64) {
        let Ok(entries) = std::fs::read_dir(&self.directory) else { return };
        for path in entries.flatten().map(|entry| entry.path()) {
            let discarded = Self::record_name(&path).is_some_and(|(number, _)| number > frame_number);
            if discarded { let _ = std::fs::remove_file(&path); }
        }
    }

    /// Drop records at or below a materialized frame.
    fn prune_through(&self, frame_number: u64) {
        let Ok(entries) = std::fs::read_dir(&self.directory) else { return };
        for path in entries.flatten().map(|entry| entry.path()) {
            let done = Self::record_name(&path).is_some_and(|(number, _)| number <= frame_number);
            if done { let _ = std::fs::remove_file(&path); }
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
            Some(bodies) => bodies.persist(digest, bytes).inspect_err(|error| {
                tracing::warn!(%error, "cw app: could not persist a terminal seal; abstaining");
            }).is_ok(),
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
    fn propose_with_context(&self, context: quil_cw_consensus::adapters::ProposalContext) -> Option<(Digest, Vec<u8>)> {
        self.inner.propose_with_context(context).filter(|(digest, bytes)| self.keep(digest, bytes))
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
}

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

    /// Returns false when a durable copy is required and could not be written:
    /// the caller must then neither propose nor vote for these bytes.
    fn persist_sealed(&self, digest: &Digest, bytes: &[u8]) -> bool {
        let Some(bodies) = self.sealed_bodies.as_ref() else { return true };
        match bodies.persist(digest, bytes) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(%error, "cw app: could not persist a sealed proposal body; abstaining");
                false
            }
        }
    }

    /// Record digest → frame_number (used by inbound-block ingestion so a synced
    /// parent resolves its number).
    pub fn note_frame(&self, digest: Digest, frame_number: u64) {
        self.block_meta.lock().unwrap().insert(digest, frame_number);
    }

    fn recover_head(&self, store: &BlockStore, frame: &AppShardFrame) -> quil_types::error::Result<()> {
        let header = frame.header.as_ref().ok_or_else(||
            quil_types::error::QuilError::Internal("recovered app head has no header".into()))?;
        if header.address != self.filter {
            return Err(quil_types::error::QuilError::Internal("recovered app head belongs to another shard".into()));
        }
        let digest = app_frame_digest(frame).ok_or_else(||
            quil_types::error::QuilError::Internal("cannot derive recovered app head identity".into()))?;
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
            Ok(true) | Err(_) => return self.propose(context.view, context.parent),
        }
        if self.gate_private_proposals {
            let mut waits = self.private_waits.lock().unwrap_or_else(|e| e.into_inner());
            *waits = if waits.0 == context.view { (context.view, waits.1 + 1) } else { (context.view, 1) };
            if waits.1 <= PRIVATE_PARENT_WAITS {
                self.paced.store(true, std::sync::atomic::Ordering::Release);
                return None;
            }
        }
        let leader = match parents
            .prepare(context.parent, context.parent_view)
            .and_then(|parent| parents.leader_for(&parent, context.view))
        {
            Ok(leader) => leader,
            Err(error) => {
                tracing::debug!(view = context.view, %error, "cw app propose: selected parent not executable privately");
                self.paced.store(true, std::sync::atomic::Ordering::Release);
                return None;
            }
        };
        self.propose_with(leader.as_ref(), context.view, context.parent)
    }

    fn verify_with_context(&self, context: ProposalContext, digest: Digest, bytes: Option<Vec<u8>>) -> bool {
        let Some(parents) = self.private_parents.as_ref() else {
            return self.verify(context.view, context.parent, digest, bytes);
        };
        match parents.is_canonical_parent(context.parent) {
            Ok(false) => match parents.prepare(context.parent, context.parent_view) {
                Ok(parent) => self.verify_with(Some(&parent.check), context.view, context.parent, digest, bytes),
                Err(error) => {
                    tracing::debug!(view = context.view, %error, "cw app verify: selected parent not executable privately");
                    self.verify(context.view, context.parent, digest, bytes)
                }
            },
            Ok(true) | Err(_) => self.verify(context.view, context.parent, digest, bytes),
        }
    }

    fn verify(&self, view: u64, parent: Digest, digest: Digest, bytes: Option<Vec<u8>>) -> bool {
        self.verify_with(self.requests_root_check.as_ref(), view, parent, digest, bytes)
    }
}

impl AppSeamProposer {
    fn propose_with(
        &self,
        leader_provider: &dyn LeaderProvider<AppShardState>,
        view: u64,
        parent_digest: Digest,
    ) -> Option<(Digest, Vec<u8>)> {
        self.paced.store(false, std::sync::atomic::Ordering::Release);
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
            return None;
        }
        tracing::debug!(view, "cw app propose: building proposal");
        let prior_state_id: Vec<u8> = digest_to_identity(&parent_digest).to_vec();
        let Some(prior_frame_number) = self
            .block_meta
            .lock()
            .unwrap()
            .get(&parent_digest)
            .copied()
        else {
            tracing::warn!(view, "cw app propose: parent block metadata unknown — skipping turn");
            return None;
        };

        // The leader checks that its local shard head matches this exact
        // consensus-selected number and identity before building a child.
        let state = match leader_provider
            .prove_next_state(view, &self.filter, prior_frame_number, &prior_state_id)
        {
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
                } else {
                    tracing::warn!(view, prior_frame_number, %error, "cw app propose: prove_next_state failed — skipping turn");
                }
                return None;
            }
        };

        // The engine assembles the FULL frame (header + recorded requests).
        let Some(frame) = (self.assemble)(&state) else {
            tracing::warn!(view, prior_frame_number, "cw app propose: frame assembly failed — skipping turn");
            return None;
        };
        let header = frame.header.as_ref()?;
        if header.address != self.filter || header.rank != view
            || header.parent_selector != parent_digest.as_ref()
        {
            tracing::warn!(view, "cw app propose: assembled frame changed the selected shard, view or parent");
            return None;
        }
        let digest = app_frame_digest(&frame)?;
        let frame_number = frame.header.as_ref()?.frame_number;
        let bytes = encode_app_frame(&frame);

        if !self.persist_sealed(&digest, &bytes) {
            return None;
        }
        self.block_meta.lock().unwrap().insert(digest, frame_number);
        Some((digest, bytes))
    }

    fn verify_with(
        &self,
        requests_root_check: Option<&AppRequestsRootCheck>,
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
            return false;
        }
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
        if header.address != self.filter || header.rank != view
            || header.parent_selector != parent.as_ref()
        {
            tracing::warn!(view, rank = header.rank, "cw app verify: shard, view or parent mismatch");
            return false;
        }
        if app_frame_digest(&frame) != Some(digest) {
            tracing::warn!(
                frame = header.frame_number,
                "cw app verify: digest mismatch"
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
                        return false;
                    }
                }
                if !self.persist_sealed(&digest, &bytes) {
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
    store: BlockStore,
    filter: Vec<u8>,
    /// Receives a finalized terminal seal and its certificate (session hosts).
    on_sealed: Option<AppSealedSink>,
    sealed_bodies: Option<Arc<SealedBodies>>,
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
    pending: Mutex<HashMap<Digest, (u64, Vec<u8>)>>,
}

impl AppSeamFinalizer {
    pub fn new(
        on_notarized: AppFrameSink,
        on_finalized: AppFinalizedSink,
        store: BlockStore,
        filter: Vec<u8>,
    ) -> Self {
        Self { on_notarized, on_finalized, store, filter, on_sealed: None, sealed_bodies: None,
            finalized_records: None, materialized: None, delivered: std::sync::atomic::AtomicU64::new(0),
            pending: Mutex::new(HashMap::new()) }
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
        let (Some(records), Some(materialized)) = (self.finalized_records.as_ref(), self.materialized.as_ref()) else {
            return Ok(0);
        };
        let after = materialized.load(std::sync::atomic::Ordering::SeqCst);
        let mut replayed = 0;
        for (number, bytes, cert, verified) in records.load_above(after)? {
            let Some(frame) = decode_app_frame(&bytes) else { continue };
            let Some(digest) = app_frame_digest(&frame) else { continue };
            // Delivery refuses another shard's frame, and a queued frame that
            // can never be delivered would hold back every later one.
            if frame.header.as_ref().map(|h| h.address.as_slice()) != Some(self.filter.as_slice()) {
                continue;
            }
            let view = frame.header.as_ref().map_or(number, |h| h.rank);
            if verified { self.store.seal(digest, bytes) } else { self.store.put(digest, bytes) }
            // An implied ancestor is only a body: it is delivered again with
            // the certified descendant that links to it.
            let Some(cert) = cert else { continue };
            self.pending.lock().unwrap().entry(digest).or_insert_with(|| (view, cert));
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
        let Some(materialized) = self.materialized.as_ref() else { return Vec::new() };
        let Some(header) = frame.header.as_ref() else { return Vec::new() };
        let floor = materialized.load(Ordering::SeqCst).max(self.delivered.load(Ordering::SeqCst));
        let mut chain = Vec::new();
        let mut child = header.clone();
        while child.frame_number > floor.saturating_add(1) {
            let Ok(identity) = <[u8; 32]>::try_from(child.parent_selector.as_slice()) else { return Vec::new() };
            let digest = digest_from_identity(identity);
            let Some((bytes, verified)) = self.store.get_with_verification(&digest) else { return Vec::new() };
            if Seal::is_encoding(&bytes) {
                return Vec::new();
            }
            let Some(parent) = decode_app_frame(&bytes) else { return Vec::new() };
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

    fn try_deliver(&self, digest: Digest) -> bool {
        // Serializes delivery across the host, ingress and retry timer. The
        // engine callback only attempts a nonblocking channel send.
        let mut pending = self.pending.lock().unwrap();
        let Some((_, cert)) = pending.get(&digest) else { return true };
        let Some((bytes, locally_verified)) = self.store.get_with_verification(&digest) else { return false };
        if Seal::is_encoding(&bytes) {
            // A terminal seal is not a data frame. Only a session host installs
            // the sink; elsewhere the reserved encoding can never be delivered.
            let Some(on_sealed) = self.on_sealed.as_ref() else { return false };
            let matches = Seal::decode(&bytes).is_ok_and(|seal| seal.digest() == digest.0);
            if matches && on_sealed(bytes, cert.clone()) {
                pending.remove(&digest);
                return true;
            }
            return false;
        }
        let Some(frame) = decode_app_frame(&bytes) else { return false };
        if frame.header.as_ref().map(|h| h.address.as_slice()) != Some(self.filter.as_slice())
            || app_frame_digest(&frame) != Some(digest)
        {
            return false;
        }
        let delivered = frame.header.as_ref().map(|h| h.frame_number);
        let implied = self.implied_ancestors(&frame);
        // Durable before the queue send: a restart between the send and the
        // engine's commit must not lose a finalized frame.
        if let (Some(records), Some(number)) = (self.finalized_records.as_ref(), delivered) {
            for (ancestor, verified, ancestor_bytes) in &implied {
                let ancestor_number = ancestor.header.as_ref().map_or(0, |h| h.frame_number);
                if let Err(error) = records.persist_implied(ancestor_number, *verified, ancestor_bytes) {
                    tracing::warn!(frame = ancestor_number, %error, "could not record an implied app frame; delivering it anyway");
                }
            }
            if let Err(error) = records.persist(number, cert, locally_verified, &bytes) {
                tracing::warn!(frame = number, %error, "could not record a finalized app frame; delivering it anyway");
            }
        }
        if !implied.is_empty() {
            tracing::info!(frame = delivered, implied = implied.len(),
                "finalized app frame makes notarized ancestors final; delivering them first");
        }
        let implied: Vec<(AppShardFrame, bool)> = implied.into_iter().map(|(ancestor, verified, _)| (ancestor, verified)).collect();
        if (self.on_finalized)(frame, cert.clone(), locally_verified, implied) {
            pending.remove(&digest);
            if let Some(number) = delivered {
                self.delivered.fetch_max(number, std::sync::atomic::Ordering::SeqCst);
                self.prune_delivered(number);
            }
            return true;
        }
        false
    }

    fn retry_pending(&self) {
        let mut entries: Vec<_> = self.pending.lock().unwrap().iter()
            .map(|(digest, (view, _))| (*view, *digest)).collect();
        entries.sort_by_key(|(view, _)| *view);
        for (_, digest) in entries {
            // Do not knowingly deliver newer finalizations ahead of a missing
            // earlier body or a backpressured notification.
            if !self.try_deliver(digest) { break; }
        }
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
        self.pending.lock().unwrap().entry(digest).or_insert_with(|| (view, cert.unwrap_or_default()));
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
    build_committee_in_namespace(&session.members, my_signing_key, my_public_key, &session.namespace().ok()?)
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

/// The engine's handle to a running simplex-backed app-shard consensus. On each
/// inbound CW‑tagged shard‑consensus message the node demuxes the channel id:
/// - channels 0/1/2 (vote/cert/resolver) → `inbound[channel].send(...)`;
/// - channel 3 (block) → `ingest_block(bytes)` (feeds the shared `BlockStore`).
pub struct AppConsensusCwHandle {
    pub inbound: [tokio::sync::mpsc::UnboundedSender<
        quil_cw_consensus::p2p_bridge::Message<FalconPublicKey>,
    >; 3],
    /// Feed a peer-delivered app frame's bytes into the engine's `BlockStore`
    /// (so `verify` finds the block behind a proposed digest) and record its
    /// digest→frame_number. Idempotent; drops malformed bytes.
    pub ingest_block: Arc<dyn Fn(Vec<u8>) + Send + Sync>,
    /// Cooperative shutdown flag for the simplex host thread. Set it to stop this
    /// instance (the engine drops + the runtime thread returns) — used to REBUILD
    /// the committee when the shard's active-prover set changes.
    pub shutdown: Arc<std::sync::atomic::AtomicBool>,
    thread: std::thread::JoinHandle<()>,
    outbound_task: tokio::task::JoinHandle<()>,
}

impl AppConsensusCwHandle {
    /// The host thread has returned without being asked: its engine stopped
    /// (an actor panicked, for instance) and this shard is taking no part in
    /// consensus until the owner rebuilds the host.
    pub fn is_dead(&self) -> bool {
        !self.shutdown.load(std::sync::atomic::Ordering::Acquire) && self.thread.is_finished()
    }

    /// Stop and join the complete runtime before a replacement can use its
    /// journal. Aborting the drain also discards queued outbound old votes.
    pub async fn shutdown_and_join(self) -> Result<(), String> {
        self.shutdown.store(true, std::sync::atomic::Ordering::Release);
        self.outbound_task.abort();
        let _ = self.outbound_task.await;
        tokio::task::spawn_blocking(move || self.thread.join())
            .await.map_err(|e| format!("joining consensus host task: {e}"))?
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
    let resumes_legacy = session.as_ref().is_none_or(|host| host.session.generation == 0);
    if let Some(host) = session.as_ref() {
        let anchored = host.session.generation == 0
            || (genesis_digest.0 == host.session.genesis && genesis_frame_number == host.session.base_frame);
        if epoch != host.session.generation || !anchored {
            return Err(quil_types::error::QuilError::Internal(
                "app session host configuration differs from its authorization".into()));
        }
        // Generation zero's instance must already hold its base, the legacy
        // tip GLOBAL registered, or its first proposal has no certified parent.
        let head = recovered_head.as_ref().and_then(|frame| frame.header.as_ref()).map(|h| h.frame_number);
        if host.session.generation == 0 && head.is_none_or(|head| head < host.session.base_frame) {
            return Err(quil_types::error::QuilError::ExecutionUnavailable(
                "local shard head precedes the registered legacy tip; recover the source state first".into()));
        }
    }
    let sealed_bodies = storage_directory.as_ref()
        .map(|dir| SealedBodies::open(dir.with_extension("bodies")).map(Arc::new))
        .transpose()
        .map_err(|e| quil_types::error::QuilError::Internal(format!("open sealed proposal bodies: {e}")))?;
    let finalized_records = finalized_records
        .map(|(dir, cursor)| FinalizedRecords::open(dir).map(|records| (Arc::new(records), cursor)))
        .transpose()
        .map_err(|e| quil_types::error::QuilError::Internal(format!("open finalized app frames: {e}")))?;
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
    let store = BlockStore::new();
    if let Some(parents) = private_parents {
        parents.bind_blocks(store.clone());
        // A session's handoff proposer waits for the parent before using its
        // private execution; the plain host waits here.
        proposer = proposer.with_private_parents(parents, session.is_none());
    }
    let proposer = Arc::new(proposer);
    // Seed the genesis parent so the first proposal resolves its frame number.
    proposer.note_frame(genesis_digest, genesis_frame_number);
    let sink = Arc::new(AppSeamSink::new(transport.clone(), peers.clone()));
    // Restore what this node sealed in an earlier life BEFORE the host can
    // replay a journal that refers to it.
    if let Some(bodies) = sealed_bodies.as_ref() {
        let restored = bodies.load()
            .map_err(|e| quil_types::error::QuilError::Internal(format!("load sealed proposal bodies: {e}")))?;
        for (digest, bytes) in restored {
            if let Some(number) = decode_app_frame(&bytes).and_then(|f| f.header.map(|h| h.frame_number)) {
                proposer.note_frame(digest, number);
            }
            store.seal(digest, bytes);
        }
    }
    let mut finalizer = AppSeamFinalizer::new(
        on_notarized, on_finalized, store.clone(), proposer.filter.clone(),
    );
    if let Some(host) = session.as_ref() {
        finalizer = finalizer.with_sealed_sink(host.on_sealed.clone());
    }
    if let Some(bodies) = sealed_bodies.clone() {
        finalizer = finalizer.with_sealed_bodies(bodies);
    }
    if let Some((records, cursor)) = finalized_records {
        finalizer = finalizer.with_finalized_records(records, cursor);
    }
    let finalizer = Arc::new(finalizer);
    // Frames an earlier instance finalized but the engine never materialized
    // go to the engine again, in order, before anything new is finalized.
    let replayed = finalizer.replay_finalized_records()
        .map_err(|e| quil_types::error::QuilError::Internal(format!("load finalized app frames: {e}")))?;
    if replayed > 0 {
        tracing::info!(filter = %hex::encode(&proposer.filter), replayed,
            "delivering app frames finalized before a restart");
    }
    let mut params = GlobalEngineParams::new(partition, epoch, genesis_digest)
        .with_leader_timeout_secs(leader_timeout_secs);
    // Populate the persisted head BEFORE the host can replay its journal. These
    // bytes are candidates, not proof that this process validated historical
    // pre-state. Intermediate and unfinalized journal bodies still need recovery.
    if let Some(frame) = recovered_head {
        proposer.recover_head(&store, &frame)?;
        let header = frame.header.as_ref().ok_or_else(||
            quil_types::error::QuilError::Internal("recovered app head has no header".into()))?;
        if session.as_ref().is_some_and(|host| header.frame_number < host.session.base_frame) {
            return Err(quil_types::error::QuilError::ExecutionUnavailable(
                "local shard head precedes the session genesis; recover the source state first".into()));
        }
        // A session's base frame was certified by its predecessor and is bound
        // by the authorization itself; only later heads carry this committee's
        // certificate. A legacy or generation-zero head, including generation
        // zero's base, carries the legacy committee's own certificate.
        if header.frame_number > 0 && (resumes_legacy || header.frame_number > genesis_frame_number) {
            // The certificate authenticates the output digest. Recompute that
            // output before using the header's height/rank as restart metadata;
            // possessing certified output bytes does not authenticate a changed
            // header. Body/pre-state validation remains on the materializer path.
            if !proposer.validator.validate(&frame)? {
                return Err(quil_types::error::QuilError::ExecutionUnavailable(
                    "app restart head failed frame validation".into()));
            }
            let certificate = header.public_key_signature_bls48581.as_ref()
                .and_then(|signature| quil_cw_consensus::app_cert::unwrap_cert_from_header(&signature.signature))
                .ok_or_else(|| quil_types::error::QuilError::ExecutionUnavailable(
                    "app restart needs a finalized certificate or an authenticated committee handoff".into()))?;
            let namespace = match session.as_ref() {
                Some(host) => host.session.namespace()?,
                None => {
                    let mut namespace = b"appshard".to_vec();
                    namespace.extend_from_slice(&proposer.filter);
                    namespace
                }
            };
            let keys: Vec<Vec<u8>> = peers.iter().map(|key| key.as_ref().to_vec()).collect();
            let identity = quil_crypto::poseidon::hash_bytes_to_32(&header.output)?;
            let verified = quil_cw_consensus::app_cert::verify_finalization_details(
                certificate, &keys, &namespace, identity,
            ).ok_or_else(|| quil_types::error::QuilError::ExecutionUnavailable(
                "app restart certificate does not authenticate under this committee; a handoff is required".into()))?;
            let certified_view = verified.finalization.proposal.round.view().get();
            if verified.finalization.proposal.round.epoch().get() != epoch {
                return Err(quil_types::error::QuilError::ExecutionUnavailable(
                    "app restart head was certified in another committee generation".into()));
            }
            if certified_view != header.rank {
                return Err(quil_types::error::QuilError::ExecutionUnavailable(
                    "app restart head rank disagrees with its certified view".into()));
            }
            params = params.with_finalized_floor(verified.finalization)
                .map_err(|error| quil_types::error::QuilError::ExecutionUnavailable(error.into()))?;
            tracing::info!(
                filter = %hex::encode(&proposer.filter), frame = header.frame_number,
                view = certified_view, epoch,
                "resuming app consensus from certified floor",
            );
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
                    proposer.clone() as Arc<dyn GlobalProposer>, host.session, host.read_parent,
                )?
                .with_private_reader(host.read_private_parent),
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

    // Block ingress: decode a peer app frame, compute identity digest, store it,
    // and note digest→frame_number for parent resolution.
    let ingest_block: Arc<dyn Fn(Vec<u8>) + Send + Sync> = {
        let store = store.clone();
        let proposer = proposer.clone();
        Arc::new(move |bytes: Vec<u8>| {
            if Seal::is_encoding(&bytes) {
                // A peer's terminal-seal proposal: a replaceable candidate until
                // this member's own automaton verifies it against its parent.
                if let Ok(seal) = Seal::decode(&bytes) {
                    store.put(digest_from_identity(seal.digest()), bytes);
                    finalizer.retry_pending();
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
            proposer.note_frame(digest, frame_number);
            finalizer.retry_pending();
            tracing::debug!(
                frame = frame_number,
                "cw app block ingress: stored peer frame"
            );
        })
    };

    Ok(AppConsensusCwHandle {
        inbound,
        ingest_block,
        shutdown,
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
            inbound: std::array::from_fn(|_| tokio::sync::mpsc::unbounded_channel().0),
            ingest_block: Arc::new(|_| {}),
            shutdown,
            thread,
            outbound_task: tokio::spawn(std::future::pending()),
        };
        let joining = tokio::spawn(handle.shutdown_and_join());
        tokio::time::timeout(std::time::Duration::from_secs(5), observed_rx).await.unwrap().unwrap();
        assert!(!joining.is_finished(), "replacement must wait for runtime exit");
        release_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), joining).await.unwrap().unwrap().unwrap();
        assert!(stopped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn a_host_that_returns_unasked_is_dead() {
        use std::sync::atomic::AtomicBool;
        let (exit_tx, exit_rx) = std::sync::mpsc::channel::<()>();
        let handle = AppConsensusCwHandle {
            inbound: std::array::from_fn(|_| tokio::sync::mpsc::unbounded_channel().0),
            ingest_block: Arc::new(|_| {}),
            shutdown: Arc::new(AtomicBool::new(false)),
            thread: std::thread::spawn(move || { let _ = exit_rx.recv(); }),
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

    fn finalized_test_frame(number: u64) -> AppShardFrame {
        AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                address: vec![1; 32], frame_number: number, output: vec![number as u8; 32],
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
                header.parent_selector = quil_crypto::poseidon::hash_bytes_to_32(&parent.header.as_ref().unwrap().output)
                    .unwrap()
                    .to_vec();
            }
            frames.push(frame);
        }
        frames
    }

    type Delivered = Arc<Mutex<Vec<(u64, Vec<u8>, Vec<u64>)>>>;

    fn implied_host(records: &std::path::Path, cursor: u64, delivered: Delivered) -> (BlockStore, AppSeamFinalizer) {
        let store = BlockStore::new();
        let finalizer = AppSeamFinalizer::new(
            Arc::new(|_| {}),
            Arc::new(move |frame: AppShardFrame, cert, _, implied: Vec<(AppShardFrame, bool)>| {
                delivered.lock().unwrap().push((
                    frame.header.unwrap().frame_number,
                    cert,
                    implied.into_iter().map(|(ancestor, _)| ancestor.header.unwrap().frame_number).collect(),
                ));
                true
            }),
            store.clone(), vec![1; 32],
        )
        .with_finalized_records(
            Arc::new(FinalizedRecords::open(records.to_path_buf()).unwrap()),
            Arc::new(std::sync::atomic::AtomicU64::new(cursor)),
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
        finalizer.on_finalized(13, app_frame_digest(&frames[2]).unwrap(), None, Some(vec![3]), true);
        assert_eq!(*delivered.lock().unwrap(), vec![(3, vec![3], vec![2])]);

        // After a restart that kept only the records, the chain is delivered
        // once more, from the certified descendant; the ancestor alone never is.
        let again: Delivered = Default::default();
        let (_, restarted) = implied_host(&directory, 1, again.clone());
        assert_eq!(restarted.replay_finalized_records().unwrap(), 1);
        assert_eq!(*again.lock().unwrap(), vec![(3, vec![3], vec![2])]);
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
            let (store, finalizer) = implied_host(&directory.join(corrupt.to_string()), 1, delivered.clone());
            for frame in &frames[1..] {
                store.seal(app_frame_digest(frame).unwrap(), encode_app_frame(frame));
            }
            finalizer.on_finalized(13, app_frame_digest(&frames[2]).unwrap(), None, Some(vec![3]), true);
            assert_eq!(*delivered.lock().unwrap(), vec![(3, vec![3], vec![])], "case {corrupt}");
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
            store.clone(), vec![1; 32],
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
        tx.try_send((finalized_test_frame(0), vec![], false)).unwrap();
        let finalizer = AppSeamFinalizer::new(
            Arc::new(|_| {}),
            Arc::new(move |frame, cert, verified, _implied| tx.try_send((frame, cert, verified)).is_ok()),
            store.clone(), vec![1; 32],
        );
        let first = finalized_test_frame(1);
        let second = finalized_test_frame(2);
        let first_id = app_frame_digest(&first).unwrap();
        let second_id = app_frame_digest(&second).unwrap();
        finalizer.on_finalized(10, first_id, None, Some(vec![10]), false);
        store.seal(second_id, encode_app_frame(&second));
        finalizer.on_finalized(20, second_id, Some(encode_app_frame(&second)), Some(vec![20]), true);
        store.put(first_id, encode_app_frame(&first));
        finalizer.retry_pending();
        assert_eq!(finalizer.pending.lock().unwrap().len(), 2, "full queue retains both");
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
        let directory = std::env::temp_dir().join(format!("quil-sealed-bodies-{}-{:?}",
            std::process::id(), std::time::Instant::now()));
        let bodies = SealedBodies::open(directory.clone()).unwrap();
        let frames: Vec<_> = (5..8).map(finalized_test_frame).collect();
        for frame in &frames {
            bodies.persist(&app_frame_digest(frame).unwrap(), &encode_app_frame(frame)).unwrap();
        }
        // A stray file and a body stored under another body's name are dropped.
        std::fs::write(directory.join("not-a-body"), b"junk").unwrap();
        std::fs::write(directory.join(hex::encode([7u8; 32])), encode_app_frame(&frames[0])).unwrap();
        let reopened = SealedBodies::open(directory.clone()).unwrap();
        let mut restored = reopened.load().unwrap();
        restored.sort_by_key(|(_, bytes)| decode_app_frame(bytes).unwrap().header.unwrap().frame_number);
        assert_eq!(restored, frames.iter()
            .map(|f| (app_frame_digest(f).unwrap(), encode_app_frame(f))).collect::<Vec<_>>());
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 3);
        // Delivering frame 6 makes it and everything below it unnecessary.
        reopened.prune_through(6);
        let left = reopened.load().unwrap();
        assert_eq!(left, vec![(app_frame_digest(&frames[2]).unwrap(), encode_app_frame(&frames[2]))]);
        std::fs::remove_dir_all(&directory).unwrap();
    }

    fn test_directory(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("quil-{name}-{}-{:?}", std::process::id(), std::time::Instant::now()))
    }

    #[test]
    fn finalized_records_survive_a_restart_and_drop_malformed_ones() {
        let directory = test_directory("finalized-records");
        let records = FinalizedRecords::open(directory.clone()).unwrap();
        for number in 5..8 {
            let bytes = encode_app_frame(&finalized_test_frame(number));
            records.persist(number, &[number as u8; 3], number % 2 == 0, &bytes).unwrap();
        }
        // The latest delivery of a frame number wins.
        records.persist(6, &[0xee], false, &encode_app_frame(&finalized_test_frame(6))).unwrap();
        records.persist(6, &[6; 3], true, &encode_app_frame(&finalized_test_frame(6))).unwrap();
        // A stray file, a record under another frame's number and a truncated
        // record are dropped.
        std::fs::write(directory.join("not-a-record"), b"junk").unwrap();
        std::fs::copy(records.path(5), records.path(9)).unwrap();
        std::fs::write(records.path(10), [0, 0, 0, 9, 1]).unwrap();
        let reopened = FinalizedRecords::open(directory.clone()).unwrap();
        let loaded = reopened.load_above(5).unwrap();
        assert_eq!(loaded, (6..8).map(|number| (
            number, encode_app_frame(&finalized_test_frame(number)), Some(vec![number as u8; 3]), number % 2 == 0,
        )).collect::<Vec<_>>());
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 3);
        reopened.prune_through(6);
        assert_eq!(reopened.load_above(0).unwrap().iter().map(|r| r.0).collect::<Vec<_>>(), vec![7]);
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
                    delivered.lock().unwrap().push((frame.header.unwrap().frame_number, cert, verified));
                    true
                }),
                store.clone(), vec![1; 32],
            )
            .with_sealed_bodies(Arc::new(SealedBodies::open(bodies_dir.clone()).unwrap()))
            .with_finalized_records(Arc::new(FinalizedRecords::open(records_dir.clone()).unwrap()), materialized.clone());
            (store, finalizer)
        };
        let finalize = |store: &BlockStore, finalizer: &AppSeamFinalizer, number: u64| {
            let frame = frame(number);
            let digest = app_frame_digest(&frame).unwrap();
            store.seal(digest, encode_app_frame(&frame));
            finalizer.sealed_bodies.as_ref().unwrap().persist(&digest, &encode_app_frame(&frame)).unwrap();
            finalizer.on_finalized(number + 10, digest, None, Some(vec![number as u8]), true);
        };

        // The first instance hands frames 2 and 3 to the engine, which never
        // materializes them.
        let first = Arc::new(Mutex::new(Vec::new()));
        let (store, finalizer) = host(first.clone());
        finalize(&store, &finalizer, 2);
        finalize(&store, &finalizer, 3);
        assert_eq!(*first.lock().unwrap(), vec![(2, vec![2], true), (3, vec![3], true)]);
        assert_eq!(SealedBodies::open(bodies_dir.clone()).unwrap().load().unwrap().len(), 2,
            "bodies are kept until materialized, not until delivered");
        drop((store, finalizer));
        // Another shard's record in the directory must not hold back delivery.
        let mut foreign = frame(4);
        foreign.header.as_mut().unwrap().address = vec![2; 32];
        FinalizedRecords::open(records_dir.clone()).unwrap()
            .persist(4, &[9], true, &encode_app_frame(&foreign)).unwrap();

        // The restarted instance holds nothing in memory; its records deliver
        // both frames again, in order, with their own certificates.
        let second = Arc::new(Mutex::new(Vec::new()));
        let (store, finalizer) = host(second.clone());
        assert_eq!(finalizer.replay_finalized_records().unwrap(), 2);
        assert_eq!(*second.lock().unwrap(), vec![(2, vec![2], true), (3, vec![3], true)]);
        assert!(finalizer.pending.lock().unwrap().is_empty());

        // Once the engine has materialized them, the next delivery prunes them.
        materialized.store(3, std::sync::atomic::Ordering::SeqCst);
        finalize(&store, &finalizer, 5);
        let left: Vec<u64> = FinalizedRecords::open(records_dir.clone()).unwrap()
            .load_above(0).unwrap().iter().map(|record| record.0).collect();
        assert_eq!(left, vec![4, 5]);
        assert_eq!(SealedBodies::open(bodies_dir.clone()).unwrap().load().unwrap().len(), 1);
        for directory in [records_dir, bodies_dir] {
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn a_finalized_seal_reaches_only_a_session_host_and_never_the_data_sink() {
        use quil_cw_consensus::handoff::Checkpoint;
        let seal = Seal {
            request: [1; 32], session: [2; 32], view: 9,
            checkpoint: Checkpoint { frame: 4, view: 7, digest: [3; 32], state_roots: [[4; 32]; 4], history_root: [5; 32] },
        };
        let digest = digest_from_identity(seal.digest());
        let data = Arc::new(Mutex::new(0usize));
        let sealed = Arc::new(Mutex::new(Vec::new()));
        let build = |with_sink: bool| {
            let store = BlockStore::new();
            let data = data.clone();
            let mut finalizer = AppSeamFinalizer::new(
                Arc::new(|_| {}),
                Arc::new(move |_, _, _, _| { *data.lock().unwrap() += 1; true }),
                store.clone(), vec![1; 32],
            );
            if with_sink {
                let sealed = sealed.clone();
                finalizer = finalizer.with_sealed_sink(Arc::new(move |bytes, cert| {
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
        assert_eq!(legacy.pending.lock().unwrap().len(), 1);
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

    #[test]
    fn finalization_retains_certificate_until_matching_body_arrives() {
        let store = BlockStore::new();
        let delivered = Arc::new(Mutex::new(Vec::new()));
        let out = delivered.clone();
        let finalizer = AppSeamFinalizer::new(
            Arc::new(|_| {}),
            Arc::new(move |frame, _, _, _| { out.lock().unwrap().push(frame); true }),
            store.clone(), vec![1; 32],
        );
        let frame = finalized_test_frame(1);
        let digest = app_frame_digest(&frame).unwrap();
        finalizer.on_finalized(1, digest, None, Some(vec![7]), false);
        let mut wrong_shard = frame.clone();
        wrong_shard.header.as_mut().unwrap().address = vec![2; 32];
        for bytes in [vec![0xff], encode_app_frame(&wrong_shard), encode_app_frame(&finalized_test_frame(2))] {
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
    fn unavailable_state_or_validation_disables_voting() {
        for (ready, has_check) in [(false, true), (true, false), (false, false)] {
            let validator = Arc::new(BlsAppFrameValidator::new(
                Arc::new(crate::test_support::TestProverRegistry::default()),
                Arc::new(quil_crypto::FalconKeyConstructor),
                Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            ));
            let check: Option<AppRequestsRootCheck> = has_check.then(|| {
                Arc::new(|_: &AppShardFrame| -> bool { panic!("state is unavailable") })
                    as AppRequestsRootCheck
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
            Some(Arc::new(|_| true)),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
        );
        let mut header = quil_types::proto::global::FrameHeader {
            address: filter,
            frame_number: 7,
            rank: 43,
            parent_selector: vec![7; 32],
            state_roots: vec![vec![0; 32]; 4],
            ..Default::default()
        };
        header.output = quil_crypto::porep::deterministic_app_frame_output(
            &header.parent_selector, &header.requests_root, &header.state_roots,
            &quil_crypto::porep::derive_storage_beacon(0, &[]),
            header.frame_number, header.rank, &header.prover, header.difficulty,
            header.fee_multiplier_vote, header.timestamp, &header.storage_attestation_root,
            0, &header.settlements, &header.accumulator, &header.spends,
        );
        let frame = AppShardFrame { header: Some(header), ..Default::default() };
        let digest = app_frame_digest(&frame).unwrap();
        let parent = digest_from_identity([7; 32]);
        assert!(proposer.verify(43, parent, digest, Some(encode_app_frame(&frame))));
        assert!(!proposer.verify(44, parent, digest, Some(encode_app_frame(&frame))));
        assert!(!proposer.verify(43, digest_from_identity([8; 32]), digest, Some(encode_app_frame(&frame))));
        let mut wrong_shard = frame;
        wrong_shard.header.as_mut().unwrap().address = vec![2; 32];
        assert!(!proposer.verify(43, parent, digest, Some(encode_app_frame(&wrong_shard))));
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
            Some(Arc::new(|_| true)),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
        );
        proposer.note_frame(digest_from_identity([1; 32]), 0);
        assert!(proposer.propose(1, digest_from_identity([2; 32])).is_none());
        let store = BlockStore::new();
        let frame = AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                address: vec![1; 32], frame_number: 7, output: vec![3; 32],
                ..Default::default()
            }),
            ..Default::default()
        };
        proposer.recover_head(&store, &frame).unwrap();
        let digest = app_frame_digest(&frame).unwrap();
        assert_eq!(proposer.block_meta.lock().unwrap().get(&digest), Some(&7));
        assert_eq!(store.get_with_verification(&digest), Some((encode_app_frame(&frame), false)));
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

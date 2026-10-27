//! Archive-side ingest of full app-shard frames.
//!
//! Archives don't run an `AppConsensusEngine`, but they bulk-subscribe to
//! all shard traffic (`[0xFF;32]`) and must materialize every shard's
//! state so they can serve it via HyperSync. This receives the full
//! `AppShardFrame`s published on `shard_frame_bitmask`, verifies them, and
//! materializes them — in strict frame order per shard — into the
//! archive's (global) hypergraph CRDT via its existing
//! `ExecutionEngineManager`.
//!
//! Verification (no consensus participation required):
//!   1. The header's quorum aggregate BLS cert is checked against the
//!      shard committee (active provers under the frame's address) via
//!      `BlsAppFrameValidator` — same check the consensus path uses. This
//!      proves the header (and its `requests_root`) was finalized by the
//!      shard's quorum.
//!   2. The carried `requests` are recomputed to a `requests_root` and
//!      required to equal the signed one — defends against a relay
//!      swapping requests under an otherwise-valid header.
//!
//! A frame that passes, and is admitted (certified, or linked to by a
//! certified frame), is also stored in the archive's clock store, from which
//! it serves shard frames to peers.

use std::collections::{BTreeMap, HashMap};
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use quil_types::consensus::{AppFrameValidator, ProverRegistry as ProverRegistryTrait};
use quil_types::crypto::{BlsConstructor, FrameProver, InclusionProver};
use quil_types::proto::global::AppShardFrame;

use crate::app_engine::{compute_requests_root, materialize_app_shard_requests};
use crate::frame_validator::BlsAppFrameValidator;

pub struct ArchiveAppShardIngest {
    /// Shared with the gap fetch, which prepares a fetched frame's historical
    /// storage registrations into it before the frame reaches this ingest.
    validator: Arc<BlsAppFrameValidator>,
    execution_manager: Arc<quil_execution::ExecutionEngineManager>,
    inclusion_prover: Arc<dyn InclusionProver>,
    hypergraph: Arc<quil_hypergraph::HypergraphCrdt>,
    /// Per-shard (address) → highest frame number materialized.
    /// Lazily seeded from the durable cursor (`kv_db`) on first access so
    /// it survives restart instead of resetting to 0 and re-materializing
    /// (or skipping frames the CRDT already advanced past).
    last_materialized: HashMap<Vec<u8>, u64>,
    /// Out-of-order verified frames, buffered until the gap fills:
    /// address → (frame_number → frame).
    buffered: HashMap<Vec<u8>, HashMap<u64, AppShardFrame>>,
    /// Frames above the cursor that were admitted and stored for serving, per
    /// address: frame → digest of the stored encoding ([`body_digest`]). A
    /// frame the buffer bound evicted is read back from the store, and
    /// materialized when the stored copy still has this digest, so it counts
    /// as held as a buffered frame does. Kept in memory only: after a restart
    /// such frames are admitted again, from this archive's store first
    /// ([`ArchiveFrameVerifier::stored_above_cursor`]).
    stored: HashMap<Vec<u8>, BTreeMap<u64, [u8; 32]>>,
    /// What [`Self::holds_bodies_through`] answers, per shard, readable
    /// without this ingest.
    held_bodies: HeldBodies,
    /// Validated frames without a certificate, waiting for a certified
    /// descendant to link to them: address → ((frame, identity) → frame).
    held: HashMap<Vec<u8>, std::collections::BTreeMap<(u64, [u8; 32]), AppShardFrame>>,
    /// Global clock frames, for the certified world-state size app frames price from.
    clock_store: Arc<dyn quil_types::store::ClockStore>,
    /// Where to ask for a frame this archive is missing: `(shard filter, frame)`.
    /// `None` leaves a gap unrecoverable, which is what it was before.
    gap_requests: Option<tokio::sync::mpsc::Sender<(Vec<u8>, u64)>>,
    /// Where to ask, behind every request on `gap_requests`, for frames a
    /// GLOBAL frame after the executing one rewards ([`Self::prefetch_through`]).
    prefetch_requests: Option<tokio::sync::mpsc::Sender<(Vec<u8>, u64)>>,
    /// Frames asked for per address, when, and whether on `gap_requests`, so a
    /// gap that persists across many inbound frames or passes asks once.
    requested: HashMap<Vec<u8>, BTreeMap<u64, (Instant, bool)>>,
    /// Frames received whose anchoring GLOBAL frame is not stored here, per
    /// address: frame → that GLOBAL frame. Not asked for again until it is.
    awaiting_anchor: HashMap<Vec<u8>, BTreeMap<u64, u64>>,
    /// The GLOBAL frames [`Self::awaiting_anchor`] has logged waiting on.
    anchors_noted: std::collections::BTreeSet<u64>,
    /// Frames received whose session generation executed GLOBAL state has not
    /// authorized, anchored past it, per address: frame → (that anchor, since
    /// when). Not asked for again until execution reaches the anchor
    /// ([`Self::await_execution`]).
    awaiting_execution: HashMap<Vec<u8>, BTreeMap<u64, (u64, Instant)>>,
    /// The operator lines on [`Self::awaiting_execution`].
    execution_deferrals: crate::execution_deferral::DeferralLog,
    /// Frames are materialized only through [`Self::materialize_through`], at
    /// the points the GLOBAL chain sequences, never on arrival.
    sequenced: bool,
    /// The frame a GLOBAL frame waits on per address, since when, and whether
    /// its header-only materialization was refused and logged.
    missing_since: HashMap<Vec<u8>, (u64, Instant, bool)>,
    /// How long a provably empty frame's body is sought before the frame is
    /// materialized from its certified header ([`EMPTY_FRAME_BODY_GRACE`]).
    empty_body_grace: Duration,
    /// The shards allocated provers serve, whose committed GLOBAL tips
    /// [`Self::request_committed_tips`] compares with what this archive serves.
    prover_registry: Arc<dyn ProverRegistryTrait>,
    /// When [`Self::request_committed_tips`] last compared them.
    last_tip_scan: Option<Instant>,
    /// Shards whose committed GLOBAL tip this archive does not serve.
    missing_tips: HashMap<Vec<u8>, MissingTip>,
    /// Frames at or below the cursor whose bodies this archive does not serve,
    /// per address: those materialized from certified headers that carried
    /// no verifiable storage attestation ([`Self::empty_frame_from_header`])
    /// and those a peer asked for and found missing
    /// ([`Self::with_missing_frame_reports`]). Each is asked for until its
    /// certified body is stored, for at most [`OWED_BODY_ASKS`] asks and
    /// [`OWED_BODY_TTL`] ([`Self::request_owed_bodies`]). Kept in memory
    /// only: after a restart a frame is owed again once a peer asks for it.
    owed_bodies: HashMap<Vec<u8>, BTreeMap<u64, OwedBody>>,
    /// When [`Self::request_owed_bodies`] last warned about bodies still owed.
    owed_warned: Option<Instant>,
    /// Frames peers asked this archive for that it does not serve.
    missing_frame_reports: Option<tokio::sync::mpsc::Receiver<(Vec<u8>, u64)>>,
    /// Reported frames found not to be owed, and since when: such a report
    /// is not looked into again for [`NOT_OWED_TTL`]; at most [`MAX_NOT_OWED`].
    not_owed: HashMap<(Vec<u8>, u64), Instant>,
    #[cfg(test)]
    skip_header_authentication: bool,
}

const GAP_RETRY_INTERVAL: Duration = Duration::from_secs(30);
/// Retry interval while a GLOBAL frame waits on the missing frame: GLOBAL
/// execution is stalled for as long as it is missing.
const GLOBAL_WAIT_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const MAX_BUFFERED_FRAMES_PER_SHARD: usize = 128;
/// Frames above a shard's cursor whose stored bodies are remembered
/// ([`ArchiveAppShardIngest::stored`]), 32 bytes each. The buffer holds at most
/// [`MAX_BUFFERED_FRAMES_PER_SHARD`] frames, and GLOBAL can carry only a recent
/// header, so a shard whose head ran further ahead than the buffer could never
/// have a header proposed again: from 03:20Z on 2026-10-27 about 100 shards
/// sat 270–600 frames behind, growing about 5 a minute, and GLOBAL frames
/// carried almost no shard headers. This bound is about a day of such growth.
const MAX_STORED_BODIES_PER_SHARD: usize = 8192;
/// Headers proposals could not carry that wait for the ingest to look into
/// them ([`HeldBodies::frames_held`]), one per shard.
const MAX_WANTED_SHARDS: usize = 4096;
/// Frames of one shard asked for at once while a GLOBAL frame waits on it.
/// Asked one at a time, each only once the one before it arrived, an archive
/// behind by thousands of frames per shard recovered about one frame a second:
/// QmQr15 executed one GLOBAL frame every two hours or more while the network
/// made 3.8 a minute, and fell further behind (2026-10-19).
const GAP_WINDOW: u64 = 32;
/// How far above its cursor a shard's frames are fetched for GLOBAL frames
/// after the executing one. Below the buffer bound, so prefetched frames are
/// never evicted by the frames above them, and small enough that every shard
/// read ahead holding this many frames stays within memory.
const PREFETCH_DEPTH: u64 = 64;
const _: () = assert!(PREFETCH_DEPTH < MAX_BUFFERED_FRAMES_PER_SHARD as u64);
/// Frames without a certificate held per shard until a certified descendant
/// links to them. Keyed by output identity, so a well-formed impostor cannot
/// displace the real frame at the same height.
const MAX_HELD_FRAMES_PER_SHARD: usize = 32;
/// Frames of one shard that wait for GLOBAL execution to reach their anchor
/// ([`ArchiveAppShardIngest::await_execution`]). Past it the farthest frame is
/// forgotten: it is asked for again like any missing frame once a GLOBAL frame
/// needs it, and verified then.
const MAX_AWAITING_EXECUTION_PER_SHARD: usize = MAX_BUFFERED_FRAMES_PER_SHARD;
/// Frames of all shards that wait for GLOBAL execution to reach their anchor.
/// Past it a frame is not parked: it is asked for like any missing frame.
const MAX_AWAITING_EXECUTION: usize = 4096;
/// The longest a frame waits for GLOBAL execution to reach its anchor before
/// it may be asked for, and verified, again.
const AWAIT_EXECUTION_TTL: Duration = Duration::from_secs(30 * 60);
/// How often an archive compares each shard's committed GLOBAL tip with the
/// frame it serves ([`ArchiveAppShardIngest::request_committed_tips`]).
const COMMITTED_TIP_SCAN: Duration = Duration::from_secs(60);
/// How often the frame at a shard's committed tip is asked for while this
/// archive does not serve it.
const COMMITTED_TIP_ASK: Duration = Duration::from_secs(300);
/// How long that frame stays missing before a warning, and between warnings.
const COMMITTED_TIP_WARN: Duration = Duration::from_secs(3600);

/// A shard's committed GLOBAL tip this archive does not serve, since when,
/// and when it was last asked for and warned about.
struct MissingTip {
    tip: u64,
    served: u64,
    since: Instant,
    asked: Option<Instant>,
    asks: u32,
    warned: Option<Instant>,
}

/// Bodies owed at once, across shards. A frame found missing beyond this is
/// owed once a peer asks for it again after others were stored or expired.
const MAX_OWED_BODIES: usize = 1024;
/// Owed bodies asked for per retry pass, each at most every
/// [`COMMITTED_TIP_ASK`], on the prefetch queue, which the gap fetch serves
/// only while no frame a waiting GLOBAL frame needs is asked for.
const OWED_BODY_ASKS_PER_PASS: usize = 16;
/// How often an owed body is asked for, at most, and for how long: one ask
/// every [`COMMITTED_TIP_ASK`] for 24 hours. No member or archive serving it
/// by then, it is forgotten until a peer asks for the frame again.
const OWED_BODY_ASKS: u32 = 288;
const OWED_BODY_TTL: Duration = Duration::from_secs(24 * 3600);
const _: () =
    assert!(OWED_BODY_ASKS as u64 * COMMITTED_TIP_ASK.as_secs() == OWED_BODY_TTL.as_secs());
/// How long a reported frame found not to be owed is not looked into again,
/// and how many such frames are remembered.
const NOT_OWED_TTL: Duration = Duration::from_secs(3600);
const MAX_NOT_OWED: usize = 1024;
/// Peer reports of frames this archive does not serve, checked per retry pass.
const MISSING_FRAME_REPORTS_PER_PASS: usize = 64;

/// The body of a frame this archive executed, or found missing below its
/// cursor, without serving it: the digest of the output it must carry
/// (`poseidon(output)`, the selector it is stored and linked under) and
/// where that digest came from, since when it is owed, when it was last
/// asked for, whether a copy without its certificate is served meanwhile,
/// and how often a certified body with another output was warned about
/// (once).
struct OwedBody {
    selector: [u8; 32],
    origin: OwedOrigin,
    since: Instant,
    asked: Option<Instant>,
    asks: u32,
    uncertified_served: bool,
    mismatch_warns: u32,
}

/// Where an owed body's output digest came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwedOrigin {
    /// The certified header GLOBAL carried, which this archive executed: the
    /// body carries a certificate of its own.
    Executed,
    /// The digest GLOBAL committed at that height: final as it is, with or
    /// without a certificate of its own (a sealed session's last frame).
    Committed,
    /// The parent the stored frame after it names: that frame authenticates
    /// the body, with or without a certificate of its own.
    Successor,
}

/// How long GLOBAL execution waits for the body of a frame whose certified
/// header proves it carried no requests before materializing it from that
/// header. Every gap-fetch round in the meantime asks every member and archive.
const EMPTY_FRAME_BODY_GRACE: Duration = Duration::from_secs(90);

impl ArchiveAppShardIngest {
    pub fn new(
        prover_registry: Arc<dyn ProverRegistryTrait>,
        bls_constructor: Arc<dyn BlsConstructor>,
        frame_prover: Arc<dyn FrameProver>,
        execution_manager: Arc<quil_execution::ExecutionEngineManager>,
        inclusion_prover: Arc<dyn InclusionProver>,
        hypergraph: Arc<quil_hypergraph::HypergraphCrdt>,
        clock_store: Arc<dyn quil_types::store::ClockStore>,
    ) -> Self {
        Self {
            // clock_store is REQUIRED: post-genesis app frames
            // (global_frame_number > 0) use the deterministic ρ_N-bound
            // output, which the validator recomputes from the anchored global
            // frame's VDF output. Without a clock store that branch
            // (frame_validator: deterministic-output) hard-errors and the
            // archive rejects every post-genesis app frame at ingest, so it
            // never materializes app-shard state.
            prover_registry: prover_registry.clone(),
            last_tip_scan: None,
            missing_tips: HashMap::new(),
            owed_bodies: HashMap::new(),
            owed_warned: None,
            missing_frame_reports: None,
            not_owed: HashMap::new(),
            validator: Arc::new(
                BlsAppFrameValidator::new(prover_registry, bls_constructor, frame_prover)
                    .with_clock_store(clock_store.clone())
                    .with_handoff_authority(hypergraph.clone()),
            ),
            clock_store,
            execution_manager,
            inclusion_prover,
            hypergraph,
            last_materialized: HashMap::new(),
            buffered: HashMap::new(),
            stored: HashMap::new(),
            held_bodies: HeldBodies::default(),
            held: HashMap::new(),
            gap_requests: None,
            prefetch_requests: None,
            requested: HashMap::new(),
            awaiting_anchor: HashMap::new(),
            anchors_noted: std::collections::BTreeSet::new(),
            awaiting_execution: HashMap::new(),
            execution_deferrals: crate::execution_deferral::DeferralLog::new("archive ingest"),
            sequenced: false,
            missing_since: HashMap::new(),
            empty_body_grace: EMPTY_FRAME_BODY_GRACE,
            #[cfg(test)]
            skip_header_authentication: false,
        }
    }

    /// Materialize only at GLOBAL-sequenced points ([`Self::materialize_through`]).
    ///
    /// GLOBAL reward execution reads shard and world sizes from the state this
    /// ingest writes. Materialized on arrival, the same GLOBAL frame could
    /// credit different rewards on archives that ingested a moment apart,
    /// diverging their prover roots. Arrival-time ingest also
    /// shared the CRDT's staging with an in-place GLOBAL execution, so either
    /// commit could publish the other's partial mutations.
    pub fn sequenced(mut self) -> Self {
        self.sequenced = true;
        self
    }

    /// For tests elsewhere in the crate: `address` materialized through
    /// `height`, and a frame rebuilt from its header without waiting for its
    /// body ([`Self::empty_frame_from_header`]).
    #[cfg(test)]
    pub(crate) fn rebuilding_at_once_from(mut self, address: &[u8], height: u64) -> Self {
        self.empty_body_grace = Duration::ZERO;
        self.last_materialized.insert(address.to_vec(), height);
        self
    }

    /// Ask `requests` for any app-shard frame this archive is missing.
    ///
    /// Without it a single missed frame — one produced while this node was
    /// restarting, say — is never recovered: the frames after it buffer
    /// forever, the durable cursor never advances, and that application's
    /// app-shard state is frozen for good. That is invisible while an
    /// application is whole, because a wallet reads its own node, and fatal
    /// once it splits, when a wallet's node covers only part of it and must
    /// read an archive.
    pub fn with_gap_fetch(mut self, requests: tokio::sync::mpsc::Sender<(Vec<u8>, u64)>) -> Self {
        self.gap_requests = Some(requests);
        self
    }

    /// Where this archive's frame service reports each numbered frame a peer
    /// asked for and the store lacks. One below the cursor is a hole: GLOBAL
    /// executed it, from its body or its certified header, but the body was
    /// never stored, so every node replaying the shard from archives stops
    /// there. Such a frame is owed and asked for ([`Self::request_owed_bodies`])
    /// when the stored frame after it names its output.
    pub fn with_missing_frame_reports(
        mut self,
        reports: tokio::sync::mpsc::Receiver<(Vec<u8>, u64)>,
    ) -> Self {
        self.missing_frame_reports = Some(reports);
        self
    }

    /// Where [`Self::prefetch_through`] asks for frames. The fetcher serves
    /// these only when no request from [`Self::with_gap_fetch`] is waiting.
    pub fn with_prefetch(mut self, requests: tokio::sync::mpsc::Sender<(Vec<u8>, u64)>) -> Self {
        self.prefetch_requests = Some(requests);
        self
    }

    /// Where to fetch a storage registration that neither this archive's
    /// executed GLOBAL state nor its live registry holds: the one an app
    /// frame's GLOBAL anchor names when this archive's execution is behind
    /// that anchor. Executing the next GLOBAL frame first needs the app frames
    /// it rewards, so an archive that fell behind could otherwise never
    /// validate them or execute again: one sat at 869,765 for two days
    /// ("historical storage registration unavailable at epoch 1208"). The
    /// gap fetch prepares them ([`Self::validator`]); each proof is checked
    /// against the root the anchor frame declares.
    pub fn with_storage_history_source(
        mut self,
        source: crate::storage_history::GlobalVertexProofSource,
    ) -> Self {
        self.validator = match Arc::try_unwrap(self.validator) {
            Ok(validator) => Arc::new(validator.with_storage_history_source(source)),
            Err(shared) => shared,
        };
        self
    }

    /// The validator this ingest checks frames with, for preparing a frame's
    /// historical storage registrations without holding the ingest.
    pub fn validator(&self) -> Arc<BlsAppFrameValidator> {
        self.validator.clone()
    }

    /// This ingest's checks on a received frame, to run without holding the
    /// ingest ([`Self::admit_verified`]).
    pub fn verifier(&self) -> ArchiveFrameVerifier {
        ArchiveFrameVerifier {
            held_bodies: self.held_bodies.clone(),
            validator: self.validator.clone(),
            execution_manager: self.execution_manager.clone(),
            inclusion_prover: self.inclusion_prover.clone(),
            has_forest: self.hypergraph.has_forest(),
            clock_store: self.clock_store.clone(),
            hypergraph: self.hypergraph.clone(),
        }
    }

    /// The bodies this ingest holds per shard, as last published, to read
    /// without holding the ingest: a GLOBAL proposal checks the headers it
    /// may carry against them ([`HeldBodies::frames_held`]).
    pub fn held_bodies(&self) -> HeldBodies {
        self.held_bodies.clone()
    }

    /// Look into the headers proposals could not carry
    /// ([`HeldBodies::frames_held`]): publish what is held of each shard and
    /// ask for the first frame it lacks ([`Self::holds_bodies_through`]).
    pub fn look_into_wanted(&mut self) {
        for (address, (through, empty)) in self.held_bodies.take_wanted() {
            if let Err(error) = self.holds_bodies_through(&address, through, empty) {
                debug!(%error, address = %hex::encode(&address),
                    "shard body check unavailable; its header is held back");
            }
        }
    }

    /// Park frame `number` of `address` until GLOBAL frame `anchor`, which it
    /// is anchored to and which this archive has not stored, is stored: no
    /// request for it goes out before then ([`ArchiveFrameVerifier::missing_anchor`]).
    ///
    /// Every such frame fails validation, so asking for it again only loads
    /// the shard's members: an archive missing GLOBAL frames 907,473–907,511
    /// fetched and refused about 200 frames a second (2026-10-20).
    pub fn await_anchor(&mut self, address: &[u8], number: u64, anchor: u64) {
        if self
            .materialized_height(address)
            .is_ok_and(|height| number <= height)
        {
            return;
        }
        self.awaiting_anchor
            .entry(address.to_vec())
            .or_default()
            .insert(number, anchor);
        if self.anchors_noted.insert(anchor) {
            info!(anchor, frame = number, address = %hex::encode(address),
                "archive app-shard frames wait for a GLOBAL frame this archive has not stored; \
                 they are asked for again once it is");
        }
    }

    /// Park frame `number` of `address` until GLOBAL execution, at `executed`,
    /// reaches `anchor`, the GLOBAL frame it is anchored to: executed state
    /// holds no session for the generation its certificate names, which is the
    /// shard's next ([`FrameCheck::AwaitExecution`]). It is asked for again
    /// then, at once when a GLOBAL frame waits for it, or after
    /// [`AWAIT_EXECUTION_TTL`], and verified again; one still unauthorized is
    /// refused then. Only shards this archive holds frames of are parked, at
    /// most [`MAX_AWAITING_EXECUTION_PER_SHARD`] frames each and
    /// [`MAX_AWAITING_EXECUTION`] in all; the first anchor and time stand, so
    /// a copy received again does not extend the wait. Returns whether the
    /// frame waits; one that does not is dropped and asked for as any missing
    /// frame.
    ///
    /// Refused instead, such frames were fetched again and again: an archive
    /// 510 frames behind refused 9870 of them on 83 shards in 24 minutes, and
    /// its gap fetch recovered 3677 (2026-10-25).
    pub fn await_execution(
        &mut self,
        address: &[u8],
        number: u64,
        anchor: u64,
        executed: u64,
    ) -> bool {
        match self.materialized_height(address) {
            Ok(height) if height > 0 && number > height => {}
            _ => return false,
        }
        let parked: usize = self.awaiting_execution.values().map(BTreeMap::len).sum();
        let waiting = self.awaiting_execution.entry(address.to_vec()).or_default();
        if waiting.contains_key(&number) {
            return true;
        }
        if parked >= MAX_AWAITING_EXECUTION {
            if waiting.is_empty() {
                self.awaiting_execution.remove(address);
            }
            return false;
        }
        waiting.insert(number, (anchor, Instant::now()));
        while waiting.len() > MAX_AWAITING_EXECUTION_PER_SHARD {
            waiting.pop_last();
        }
        if !waiting.contains_key(&number) {
            return false;
        }
        let shards = self.awaiting_execution.len();
        self.execution_deferrals
            .deferred(address, number, anchor, executed, Some(shards));
        true
    }

    /// The GLOBAL frame executed state is at; `None` when unreadable.
    fn executed_global_frame(&self) -> Option<u64> {
        self.hypergraph
            .read_frame_cursor(&quil_store::encoding::global_materialized_cursor_key())
            .ok()
    }

    /// Log the end of a wait for execution once it reached every anchor.
    fn note_execution(&self) {
        if self.execution_deferrals.waiting() {
            if let Some(executed) = self.executed_global_frame() {
                self.execution_deferrals.executed(executed);
            }
        }
    }

    /// Read the cursor co-committed with app state. Read failures must not look
    /// like genesis and trigger reexecution against already advanced state.
    pub fn materialized_height(&mut self, address: &[u8]) -> quil_types::error::Result<u64> {
        if let Some(&h) = self.last_materialized.get(address) {
            return Ok(h);
        }
        let h = self.hypergraph.read_frame_cursor(
            &quil_store::encoding::consensus_materialized_cursor_key(address),
        )?;
        self.last_materialized.insert(address.to_vec(), h);
        Ok(h)
    }

    /// Publish in memory only after state and cursor have committed together.
    fn set_materialized_height(&mut self, address: &[u8], frame: u64) {
        self.last_materialized.insert(address.to_vec(), frame);
        if let Some(stored) = self.stored.get_mut(address) {
            *stored = stored.split_off(&(frame + 1));
            if stored.is_empty() {
                self.stored.remove(address);
            }
        }
        if let Some(requested) = self.requested.get_mut(address) {
            *requested = requested.split_off(&(frame + 1));
            if requested.is_empty() {
                self.requested.remove(address);
            }
        }
        if let Some(waiting) = self.awaiting_anchor.get_mut(address) {
            *waiting = waiting.split_off(&(frame + 1));
            if waiting.is_empty() {
                self.awaiting_anchor.remove(address);
            }
            let awaiting = &self.awaiting_anchor;
            self.anchors_noted.retain(|anchor| {
                awaiting
                    .values()
                    .any(|waiting| waiting.values().any(|a| a == anchor))
            });
        }
        if let Some(waiting) = self.awaiting_execution.get_mut(address) {
            *waiting = waiting.split_off(&(frame + 1));
            if waiting.is_empty() {
                self.awaiting_execution.remove(address);
            }
        }
        self.missing_since.remove(address);
    }

    /// Retry missing frames and deferred execution even if gossip goes quiet.
    /// Sequenced ingest is driven by GLOBAL execution instead.
    /// Committee-handoff flag day (`LegacyHistory::Discard`): before the
    /// GLOBAL frame `global_frame` executes, once it reaches activation,
    /// discard every application frame chain this archive holds (frames,
    /// per-frame records and cursors; application state kept) and what this
    /// ingest remembers of them. Runs once per store. Returns whether it did.
    pub fn discard_legacy_history_at(
        &mut self,
        global_frame: u64,
    ) -> quil_types::error::Result<bool> {
        let Some(policy) = quil_types::consensus::committee_handoff_policy().filter(|policy| {
            policy.legacy_history == quil_types::consensus::LegacyHistory::Discard
        }) else {
            return Ok(false);
        };
        if global_frame < policy.activation_frame
            || self.clock_store.app_frame_history_discarded()?.is_some()
        {
            return Ok(false);
        }
        self.clock_store.discard_app_frame_history(global_frame)?;
        self.last_materialized.clear();
        self.buffered.clear();
        self.stored.clear();
        self.held_bodies.clear();
        self.held.clear();
        self.requested.clear();
        self.owed_bodies.clear();
        crate::app_engine::forget_legacy_relay_boundaries();
        tracing::info!(
            global_frame,
            "committee-handoff flag day: archive discarded its legacy app frame history"
        );
        Ok(true)
    }

    pub fn retry_pending(&mut self) {
        let holding: Vec<_> = self.held.keys().cloned().collect();
        for address in holding {
            self.serve_committed_held(&address);
        }
        self.request_committed_tips();
        self.take_missing_frame_reports();
        self.request_owed_bodies();
        self.note_execution();
        self.look_into_wanted();
        if self.sequenced {
            return;
        }
        let addresses: Vec<_> = self.buffered.keys().cloned().collect();
        for address in addresses {
            self.try_materialize(&address);
        }
    }

    /// Ingest a gossiped full `AppShardFrame` (prost bytes).
    pub fn ingest(&mut self, data: &[u8]) {
        let frame = match <AppShardFrame as prost::Message>::decode(data) {
            Ok(f) => f,
            Err(_) => return,
        };
        let (address, frame_number) = match frame.header.as_ref() {
            Some(h) if !h.address.is_empty() => (h.address.clone(), h.frame_number),
            _ => {
                debug!("archive ingest: shard frame missing header or empty address — dropping");
                return;
            }
        };

        // Reaching here means a full app-shard frame actually arrived on the
        // frame topic. Logged because its ABSENCE is the only symptom when an
        // archive holds no app-shard state, and every rejection below is a
        // warning — so without this, "never received" and "never published"
        // look identical from the archive's log.
        let held = match self.materialized_height(&address) {
            Ok(height) => height,
            Err(error) => {
                warn!(error = %error, "archive ingest deferred: materialized cursor unavailable");
                return;
            }
        };
        debug!(
            frame = frame_number,
            held,
            address = %hex::encode(&address),
            "archive ingest: received a full app-shard frame"
        );
        // Already materialized (or older): ignore, unless this archive owes
        // the frame's body, which is then checked and served, never executed.
        if frame_number <= held {
            if self.wants_owed_body(&address, &frame) {
                let verifier = self.verifier();
                if verifier.missing_anchor(&frame).is_none() {
                    if let Some(certified) = verifier.verify(&frame) {
                        self.store_owed_body(&address, &frame, certified, "gossip");
                    }
                }
            }
            return;
        }

        let verifier = self.verifier();
        if let Some(anchor) = verifier.missing_anchor(&frame) {
            self.await_anchor(&address, frame_number, anchor);
            return;
        }
        let certified = match verifier.check(&frame) {
            FrameCheck::Admit { certified } => certified,
            FrameCheck::AwaitExecution { anchor, executed } => {
                self.await_execution(&address, frame_number, anchor, executed);
                return;
            }
            FrameCheck::Refused => return,
        };
        self.admit(&address, frame, certified);
        if !self.sequenced {
            self.try_materialize(&address);
        }
    }

    /// Admit a frame [`ArchiveFrameVerifier::verify`] passed, as [`Self::ingest`]
    /// does. The gap fetch verifies the frames it recovers without holding the
    /// ingest or the message loop, which used to run every check in turn.
    pub fn admit_verified(&mut self, frame: AppShardFrame, certified: bool) {
        let Some((address, frame_number)) = frame
            .header
            .as_ref()
            .filter(|header| !header.address.is_empty())
            .map(|header| (header.address.clone(), header.frame_number))
        else {
            return;
        };
        match self.materialized_height(&address) {
            Ok(held) if frame_number > held => {}
            Ok(_) => {
                self.store_owed_body(&address, &frame, certified, "gap fetch");
                return;
            }
            Err(error) => {
                warn!(error = %error, "archive ingest deferred: materialized cursor unavailable");
                return;
            }
        }
        self.admit(&address, frame, certified);
        if !self.sequenced {
            self.try_materialize(&address);
        }
    }

    /// Buffer a validated frame for in-order materialization. A certified
    /// frame is buffered as is; a frame without a certificate only when the
    /// buffered frame after it links to it (`app_frame_links_to_child`), and
    /// otherwise it is held until such a frame arrives. So `buffered` only
    /// ever holds certified frames and the ancestors they authenticate.
    ///
    /// A member may build on a notarized parent before it finalizes; the
    /// child's finalization then makes the parent final with no certificate
    /// of its own. Refusing such a parent leaves archives waiting for it
    /// forever and halts GLOBAL's sequenced ingest.
    fn admit(&mut self, address: &[u8], frame: AppShardFrame, certified: bool) {
        self.admit_frames(address, frame, certified);
        self.publish_held(address);
    }

    fn admit_frames(&mut self, address: &[u8], frame: AppShardFrame, certified: bool) {
        use crate::frame_validator::app_frame_links_to_child;
        let Some(header) = frame.header.clone() else {
            return;
        };
        let number = header.frame_number;
        let linked = self
            .buffered
            .get(address)
            .and_then(|buffered| buffered.get(&(number + 1)))
            .and_then(|child| child.header.as_ref())
            .is_some_and(|child| app_frame_links_to_child(&header, child));
        if !certified && !linked {
            let Ok(identity) = quil_crypto::poseidon::hash_bytes_to_32(&header.output) else {
                return;
            };
            let held = self.held.entry(address.to_vec()).or_default();
            held.insert((number, identity), frame);
            while held.len() > MAX_HELD_FRAMES_PER_SHARD {
                let Some(farthest) = held.keys().next_back().copied() else {
                    break;
                };
                held.remove(&farthest);
            }
            return;
        }
        // Held ancestors this frame now authenticates, down the chain.
        let mut authenticated = vec![(number, frame)];
        let mut child = header;
        if let Some(held) = self.held.get_mut(address) {
            while child.frame_number > 0 {
                let below = child.frame_number - 1;
                let parent = held
                    .range((below, [0; 32])..=(below, [0xff; 32]))
                    .find(|(_, parent)| {
                        parent
                            .header
                            .as_ref()
                            .is_some_and(|p| app_frame_links_to_child(p, &child))
                    })
                    .map(|(key, _)| *key);
                let Some(key) = parent else { break };
                let parent = held.remove(&key).expect("found above");
                child = parent.header.clone().expect("held frames have headers");
                authenticated.push((below, parent));
            }
        }
        for (number, frame) in authenticated {
            match self.store_body(&frame) {
                Some(digest) => self.remember_stored(address, number, digest),
                None => self.forget_stored(address, number),
            }
            self.buffered
                .entry(address.to_vec())
                .or_default()
                .insert(number, frame);
        }
        // The farthest frame leaves the buffer; stored, it is still held
        // ([`Self::read_back_stored`]).
        let buffered = self.buffered.entry(address.to_vec()).or_default();
        if buffered.len() > MAX_BUFFERED_FRAMES_PER_SHARD {
            if let Some(farthest) = buffered.keys().max().copied() {
                buffered.remove(&farthest);
            }
        }
    }

    /// Remember that the body of frame `number` of `address`, above the
    /// cursor, is stored with `digest`, within [`MAX_STORED_BODIES_PER_SHARD`]:
    /// past it the farthest is forgotten, and asked for again once needed.
    fn remember_stored(&mut self, address: &[u8], number: u64, digest: [u8; 32]) {
        if self
            .last_materialized
            .get(address)
            .is_some_and(|&cursor| number <= cursor)
        {
            return;
        }
        let stored = self.stored.entry(address.to_vec()).or_default();
        stored.insert(number, digest);
        if stored.len() > MAX_STORED_BODIES_PER_SHARD {
            let farthest = stored.pop_last().map_or(number, |(farthest, _)| farthest);
            let cursor = self.last_materialized.get(address).copied().unwrap_or(0);
            self.held_bodies
                .note_beyond_bound(address, cursor, farthest);
        }
    }

    fn forget_stored(&mut self, address: &[u8], number: u64) {
        if let Some(stored) = self.stored.get_mut(address) {
            stored.remove(&number);
            if stored.is_empty() {
                self.stored.remove(address);
            }
        }
    }

    /// Whether the body of frame `number` of `address` is buffered, or stored
    /// with its digest remembered.
    fn body_held(&self, address: &[u8], number: u64) -> bool {
        self.buffered
            .get(address)
            .is_some_and(|frames| frames.contains_key(&number))
            || self
                .stored
                .get(address)
                .is_some_and(|stored| stored.contains_key(&number))
    }

    /// Frame `number` of `address` read back from the store, when its body was
    /// admitted and stored above the cursor and the stored copy is still that
    /// body ([`Self::stored`]); a copy since replaced or lost is forgotten, so
    /// the frame is asked for again.
    fn read_back_stored(&mut self, address: &[u8], number: u64) -> Option<AppShardFrame> {
        let digest = *self.stored.get(address)?.get(&number)?;
        let frame = self
            .clock_store
            .get_shard_clock_frame(address, number, false)
            .ok()
            .filter(|frame| body_digest(frame) == digest);
        if frame.is_none() {
            self.forget_stored(address, number);
            warn!(address = %hex::encode(address), frame = number,
                "archive ingest: a shard frame body stored above the cursor is no longer the one admitted; \
                 it is asked for again");
        }
        frame
    }

    /// The highest frame of `address` through which every body above
    /// `cursor` is held: buffered, stored ([`Self::body_held`]) or held as the
    /// frame GLOBAL committed at that height ([`Self::committed_held`]).
    fn held_through(&self, address: &[u8], cursor: u64) -> u64 {
        let bound = cursor
            .saturating_add((MAX_STORED_BODIES_PER_SHARD + MAX_BUFFERED_FRAMES_PER_SHARD) as u64);
        let mut through = cursor;
        while through < bound
            && (self.body_held(address, through + 1)
                || self.committed_held(address, through + 1).is_some())
        {
            through += 1;
        }
        through
    }

    /// Publish what this ingest holds of `address` ([`HeldBodies`]).
    fn publish_held(&mut self, address: &[u8]) {
        let Ok(cursor) = self.materialized_height(address) else {
            return;
        };
        let through = self.held_through(address, cursor);
        self.held_bodies.publish(address, cursor, through);
    }

    /// Serve the frame held without a certificate at `address`'s committed
    /// tip when it is the frame GLOBAL committed there
    /// ([`crate::app_handoff::committed_frame_digest_looked_through`]): a
    /// sealed session's last frame, which the seal's certificate made final.
    /// No certified frame of its session follows it, so it was never
    /// admitted, no archive served it, and every successor replaying to the
    /// seal stopped one frame short (…091f80, frame 4693, 2026-10-20). It
    /// stays held: serving it neither buffers nor materializes it, which
    /// only a certified child or GLOBAL's sequencing does.
    fn serve_committed_held(&self, address: &[u8]) {
        let Some(held) = self.held.get(address) else {
            return;
        };
        let Ok(Some(tip)) = crate::app_handoff::committed_tip(&self.hypergraph, address) else {
            return;
        };
        let at_tip = |identity: [u8; 32]| held.contains_key(&(tip, identity));
        if held
            .range((tip, [0; 32])..=(tip, [0xff; 32]))
            .next()
            .is_none()
        {
            return;
        }
        let served = self
            .clock_store
            .get_shard_clock_frame(address, tip, false)
            .ok()
            .and_then(|frame| frame.header)
            .and_then(|header| quil_crypto::poseidon::hash_bytes_to_32(&header.output).ok());
        if served.is_some_and(at_tip) {
            return;
        }
        let Ok(Some(digest)) = crate::app_handoff::committed_frame_digest_looked_through(
            &self.hypergraph,
            address,
            tip,
        ) else {
            return;
        };
        let Some(frame) = held.get(&(tip, digest)) else {
            return;
        };
        self.store_for_serving(frame);
        info!(address = %hex::encode(address), frame = tip, digest = %hex::encode(&digest[..4]),
            "archive serves the frame GLOBAL committed without a certificate of its own (a sealed session's last frame)");
    }

    /// Ask for the frame at each shard's committed GLOBAL tip this archive
    /// does not serve, on the gap fetch, which asks the shard's members first
    /// and then archives. An archive stores every frame GLOBAL sequences
    /// before executing it, so its served tip trails the committed one only
    /// where GLOBAL committed a frame it never sequenced: a sealed session's
    /// last frame, final through the seal ([`Self::serve_committed_held`]).
    /// Gossiped once, that frame was lost to every archive that restarted
    /// since, and nothing asked for it again (…091f80, frame 4693,
    /// 2026-10-20). A fetched frame is admitted as any fetched frame is, and
    /// served only under the digest GLOBAL committed. Each shard is asked at
    /// most every [`COMMITTED_TIP_ASK`]; a frame still missing after
    /// [`COMMITTED_TIP_WARN`] is warned about once per that interval.
    fn request_committed_tips(&mut self) {
        let Some(sender) = self.gap_requests.clone() else {
            return;
        };
        if self
            .last_tip_scan
            .is_some_and(|at| at.elapsed() < COMMITTED_TIP_SCAN)
        {
            return;
        }
        self.last_tip_scan = Some(Instant::now());
        let global_frame = self
            .clock_store
            .get_latest_global_clock_frame()
            .ok()
            .and_then(|frame| frame.header)
            .map_or(0, |header| header.frame_number);
        let Ok(summaries) = self
            .prover_registry
            .get_prover_shard_summaries(global_frame)
        else {
            return;
        };
        let filters: Vec<Vec<u8>> = summaries
            .into_iter()
            .map(|summary| summary.filter)
            .filter(|filter| !filter.is_empty())
            .collect();
        let Ok(tips) = crate::app_handoff::committed_tips(&self.hypergraph, &filters) else {
            return;
        };
        let mut missing = HashMap::new();
        for (filter, tip) in tips {
            let tracked = self.missing_tips.remove(&filter);
            let served = self
                .clock_store
                .get_latest_shard_clock_frame_number(&filter)
                .ok()
                .flatten()
                .unwrap_or(0);
            if tip == 0 || served >= tip {
                if let Some(found) = tracked.filter(|found| found.asks > 0) {
                    info!(filter = %hex::encode(&filter), committed_tip = found.tip, asks = found.asks,
                        missing_secs = found.since.elapsed().as_secs(),
                        "archive serves the frame at a shard's committed GLOBAL tip it had asked its members for");
                }
                continue;
            }
            let now = Instant::now();
            let mut entry = tracked
                .filter(|entry| entry.tip == tip)
                .unwrap_or(MissingTip {
                    tip,
                    served,
                    since: now,
                    asked: None,
                    asks: 0,
                    warned: None,
                });
            entry.served = served;
            if entry
                .asked
                .is_none_or(|at| at.elapsed() >= COMMITTED_TIP_ASK)
                && sender.try_send((filter.clone(), tip)).is_ok()
            {
                entry.asked = Some(now);
                entry.asks += 1;
            }
            if entry.since.elapsed() >= COMMITTED_TIP_WARN
                && entry
                    .warned
                    .is_none_or(|at| at.elapsed() >= COMMITTED_TIP_WARN)
            {
                entry.warned = Some(now);
                warn!(filter = %hex::encode(&filter), committed_tip = tip, served_tip = entry.served, asks = entry.asks,
                    missing_secs = entry.since.elapsed().as_secs(),
                    "archive cannot find the frame at a shard's committed GLOBAL tip: the shard's members and up to \
                     8 archives were asked (the gap fetch's line for this frame names each answer); members \
                     replaying to this tip stay blocked until one serves it");
            }
            missing.insert(filter, entry);
        }
        self.missing_tips = missing;
    }

    /// Store an authenticated frame where this archive serves shard frames
    /// from (`get_app_shard_frame`, the latest by frame 0). Only admitted frames
    /// get here: certified ones and the ancestors a certified frame links to.
    /// The receive loop used to store every gossiped frame before this check,
    /// so one forged far-future frame could pin the head an archive serves;
    /// and frames recovered through the gap fetch were never stored at all.
    /// The header's own `storage_attestation` field, which only the header a
    /// GLOBAL frame carries fills and no certificate binds, is stored empty.
    /// Returns whether the frame was stored.
    fn store_for_serving(&self, frame: &AppShardFrame) -> bool {
        self.store_body(frame).is_some()
    }

    /// [`Self::store_for_serving`], returning the digest of what was stored
    /// ([`body_digest`]). Materializing reads a frame's requests and its
    /// header's other fields, never the cleared `storage_attestation`, so the
    /// stored copy materializes as the one received.
    fn store_body(&self, frame: &AppShardFrame) -> Option<[u8; 32]> {
        if frame
            .header
            .as_ref()
            .is_some_and(|header| !header.storage_attestation.is_empty())
        {
            let mut cleared = frame.clone();
            if let Some(header) = cleared.header.as_mut() {
                header.storage_attestation.clear();
            }
            return self.store_body(&cleared);
        }
        let header = frame.header.as_ref()?;
        let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output).ok()?;
        // Outside every GLOBAL execution footprint, so it does not make a
        // concurrent atomic execution stale.
        if let Err(error) = self
            .clock_store
            .store_shard_clock_frame_for_serving(&selector, frame)
        {
            warn!(frame = header.frame_number, %error,
                address = %hex::encode(&header.address),
                "archive ingest: storing a verified shard frame for serving failed");
            return None;
        }
        Some(body_digest(frame))
    }

    /// Whether this archive owes the body of frame `number` of `address`.
    pub(crate) fn owes_body(&self, address: &[u8], number: u64) -> bool {
        self.owed_bodies
            .get(address)
            .is_some_and(|owed| owed.contains_key(&number))
    }

    /// Whether `frame` has the output of a body this archive owes and could
    /// take its place: checked before the frame is verified, which only such
    /// a frame is. A copy without its own certificate cannot replace the one
    /// already served.
    fn wants_owed_body(&self, address: &[u8], frame: &AppShardFrame) -> bool {
        let Some(header) = frame.header.as_ref() else {
            return false;
        };
        let Some(owed) = self
            .owed_bodies
            .get(address)
            .and_then(|owed| owed.get(&header.frame_number))
        else {
            return false;
        };
        (has_certificate(frame) || !owed.uncertified_served)
            && quil_crypto::poseidon::hash_bytes_to_32(&header.output)
                .is_ok_and(|selector| selector == owed.selector)
    }

    /// Owe the body of frame `number` of `address`, whose output hashes to
    /// `selector` by `origin`, so [`Self::request_owed_bodies`] asks for it
    /// until it is stored. Returns whether it was newly owed.
    fn owe_body(
        &mut self,
        address: &[u8],
        number: u64,
        selector: [u8; 32],
        origin: OwedOrigin,
    ) -> bool {
        let owed: usize = self.owed_bodies.values().map(BTreeMap::len).sum();
        if owed >= MAX_OWED_BODIES || self.owes_body(address, number) {
            return false;
        }
        self.owed_bodies
            .entry(address.to_vec())
            .or_default()
            .insert(
                number,
                OwedBody {
                    selector,
                    origin,
                    since: Instant::now(),
                    asked: None,
                    asks: 0,
                    uncertified_served: false,
                    mismatch_warns: 0,
                },
            );
        true
    }

    /// Whether the report of frame `number` of `address` was found not to be
    /// owed within [`NOT_OWED_TTL`].
    fn not_owed(&self, address: &[u8], number: u64) -> bool {
        self.not_owed
            .get(&(address.to_vec(), number))
            .is_some_and(|at| at.elapsed() < NOT_OWED_TTL)
    }

    /// Remember that frame `number` of `address` is not owed, within
    /// [`MAX_NOT_OWED`].
    fn note_not_owed(&mut self, address: &[u8], number: u64) {
        self.not_owed.retain(|_, at| at.elapsed() < NOT_OWED_TTL);
        if self.not_owed.len() >= MAX_NOT_OWED {
            if let Some(oldest) = self
                .not_owed
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(key, _)| key.clone())
            {
                self.not_owed.remove(&oldest);
            }
        }
        self.not_owed
            .insert((address.to_vec(), number), Instant::now());
    }

    fn forget_owed_body(&mut self, address: &[u8], number: u64) {
        let Some(owed) = self.owed_bodies.get_mut(address) else {
            return;
        };
        owed.remove(&number);
        if owed.is_empty() {
            self.owed_bodies.remove(address);
        }
    }

    /// Store the verified body of an owed frame at or below the cursor for
    /// serving when its output is the one executed there, the digest
    /// [`OwedBody::selector`] holds; any other body at that height is refused.
    /// It is neither buffered nor executed again: GLOBAL executed the frame.
    /// A copy without its own certificate is final when the digest is the one
    /// GLOBAL committed or the stored frame after it names
    /// ([`OwedOrigin`]); a frame executed from its certified header is served
    /// so only until a certified copy replaces it.
    ///
    /// Every archive used to drop a body arriving after GLOBAL executed its
    /// frame from the certified header, and nothing asked for it again, so
    /// a 90 s miss became a hole every archive served for good: nodes
    /// replaying …d9000a1b40 stopped at frame 5577 ("archive replay is
    /// missing shard frame 5577"), while its members held the body
    /// (2026-10-23).
    fn store_owed_body(
        &mut self,
        address: &[u8],
        frame: &AppShardFrame,
        certified: bool,
        via: &'static str,
    ) {
        let Some(header) = frame.header.as_ref() else {
            return;
        };
        let number = header.frame_number;
        let Some(owed) = self
            .owed_bodies
            .get_mut(address)
            .and_then(|owed| owed.get_mut(&number))
        else {
            return;
        };
        let Ok(selector) = quil_crypto::poseidon::hash_bytes_to_32(&header.output) else {
            return;
        };
        if selector != owed.selector {
            let (origin, expected) = (owed.origin, owed.selector);
            if !certified {
                debug!(filter = %hex::encode(address), frame = number, via,
                    "archive refused a shard frame body whose output differs from the frame executed at that height");
            } else if origin == OwedOrigin::Successor {
                // A certified frame the stored frame after it does not name:
                // that frame opens a session GLOBAL holds no record of here,
                // and names its genesis. The digest owed is no frame's.
                self.forget_owed_body(address, number);
                self.note_not_owed(address, number);
                warn!(filter = %hex::encode(address), frame = number, via,
                    body = %hex::encode(&selector[..4]), named = %hex::encode(&expected[..4]),
                    "archive stopped asking for the body of a shard frame below its cursor: a certified body has \
                     another output than the stored frame after it names, which then opens a session; nodes \
                     replaying the shard need the frame GLOBAL committed there");
            } else if owed.mismatch_warns == 0 {
                owed.mismatch_warns += 1;
                warn!(filter = %hex::encode(address), frame = number, via,
                    body = %hex::encode(&selector[..4]), executed = %hex::encode(&expected[..4]),
                    "archive refused a certified shard frame body whose output differs from the frame executed at \
                     that height: two certified frames at one height is a defect to report with this line");
            }
            return;
        }
        if !certified && owed.uncertified_served {
            return;
        }
        let (since, asks) = (owed.since, owed.asks);
        let complete = certified || owed.origin != OwedOrigin::Executed;
        if !self.store_for_serving(frame) {
            return;
        }
        if !complete {
            if let Some(owed) = self
                .owed_bodies
                .get_mut(address)
                .and_then(|owed| owed.get_mut(&number))
            {
                owed.uncertified_served = true;
            }
            info!(filter = %hex::encode(address), frame = number, via, asks, owed_secs = since.elapsed().as_secs(),
                "archive stored the late body of a shard frame below its cursor without its own certificate; nodes \
                 replaying the shard can fetch it with the certified frame after it, and the archive still asks \
                 for a certified copy");
            return;
        }
        self.forget_owed_body(address, number);
        info!(filter = %hex::encode(address), frame = number, via, asks, owed_secs = since.elapsed().as_secs(),
            "archive stored the late body of a shard frame below its cursor; nodes replaying the shard from \
             archives can fetch it now");
    }

    /// Whether frame `number + 1` of `address` opens a committee session:
    /// it then names the session's genesis as its parent, not frame
    /// `number`'s output. `Err` when GLOBAL's records cannot be read.
    fn opens_session_after(&self, address: &[u8], number: u64) -> quil_types::error::Result<bool> {
        use quil_execution::global_intrinsic::handoff;
        let Some(view) = crate::app_handoff::committed_view(&self.hypergraph)? else {
            return Ok(false);
        };
        let Some(head) = handoff::head(&view, address)? else {
            return Ok(false);
        };
        // A successor's base is its predecessor's closing checkpoint, never
        // below that predecessor's base (`app_engine::session_based_at`).
        for generation in (1..=head.generation).rev() {
            match handoff::session_at_generation(&view, address, generation)? {
                Some(session) if session.base_frame == number => return Ok(true),
                Some(session) if session.base_frame < number => return Ok(false),
                _ => {}
            }
        }
        Ok(false)
    }

    /// Owe the body of each frame below the cursor that a peer asked for and
    /// this archive does not serve, under the output GLOBAL committed at that
    /// height (a session's last frame), else the one the stored frame after
    /// it names (`parent_selector`), unless that frame opens a session and
    /// names its genesis instead. A hole left before archives kept asking for
    /// such bodies, or forgotten across a restart, is so recovered the first
    /// time a node replaying the shard asks for it. Only a hole whose next
    /// frame is stored gets that far: of consecutive holes, all but the last
    /// are owed only under a digest GLOBAL committed. A report found not to be
    /// owed is not looked into again for [`NOT_OWED_TTL`]. At most
    /// [`MISSING_FRAME_REPORTS_PER_PASS`] reports a pass; the rest wait.
    fn take_missing_frame_reports(&mut self) {
        let mut reports = Vec::new();
        if let Some(receiver) = self.missing_frame_reports.as_mut() {
            while reports.len() < MISSING_FRAME_REPORTS_PER_PASS {
                let Ok(report) = receiver.try_recv() else {
                    break;
                };
                reports.push(report);
            }
        }
        for (address, number) in reports {
            if number == 0
                || self.owes_body(&address, number)
                || self.not_owed(&address, number)
                || self
                    .clock_store
                    .get_shard_clock_frame(&address, number, false)
                    .is_ok()
            {
                continue;
            }
            // Read before the cursor, which is cached per address: only a
            // shard this archive stores frames of gets that far.
            let Some(child) = self
                .clock_store
                .get_shard_clock_frame(&address, number + 1, false)
                .ok()
                .and_then(|child| child.header)
            else {
                continue;
            };
            if !self
                .materialized_height(&address)
                .is_ok_and(|height| number <= height)
            {
                continue;
            }
            let committed = crate::app_handoff::committed_frame_digest_looked_through(
                &self.hypergraph,
                &address,
                number,
            )
            .ok()
            .flatten();
            let (selector, origin) = match committed {
                Some(digest) => (digest, OwedOrigin::Committed),
                // Records unreadable now: the next report looks again.
                None => match self.opens_session_after(&address, number) {
                    Err(_) => continue,
                    Ok(true) => {
                        self.note_not_owed(&address, number);
                        continue;
                    }
                    Ok(false) => match <[u8; 32]>::try_from(child.parent_selector.as_slice()) {
                        Ok(selector) => (selector, OwedOrigin::Successor),
                        Err(_) => continue,
                    },
                },
            };
            if self.owe_body(&address, number, selector, origin) {
                info!(filter = %hex::encode(&address), frame = number,
                    "archive does not serve a shard frame below its cursor that a peer asked for; asking the \
                     shard's members and archives for its body");
            }
        }
    }

    /// Ask for each owed body on the prefetch queue, at most every
    /// [`COMMITTED_TIP_ASK`] and [`OWED_BODY_ASKS_PER_PASS`] a pass; forget
    /// one stored with its certificate meanwhile, and one asked for
    /// [`OWED_BODY_ASKS`] times or owed for [`OWED_BODY_TTL`] (warned about
    /// once a pass). While one has been owed for [`COMMITTED_TIP_WARN`],
    /// warn once per that interval.
    fn request_owed_bodies(&mut self) {
        let mut expired: Vec<(Vec<u8>, u64, u32)> = Vec::new();
        for (address, owed) in self.owed_bodies.iter_mut() {
            owed.retain(|&number, body| {
                let keep = body.asks < OWED_BODY_ASKS && body.since.elapsed() < OWED_BODY_TTL;
                if !keep {
                    expired.push((address.clone(), number, body.asks));
                }
                keep
            });
        }
        self.owed_bodies.retain(|_, owed| !owed.is_empty());
        if let Some((address, number, asks)) = expired.first() {
            warn!(expired = expired.len(), filter = %hex::encode(address), frame = number, asks,
                ttl_secs = OWED_BODY_TTL.as_secs(),
                "archive stopped asking for the bodies of shard frames below its cursor: no member or archive \
                 served one (the gap fetch's line for each frame names each answer); nodes replaying such a \
                 shard from archives stop at the frame, which is owed again once one asks for it");
        }
        let Some(sender) = self.prefetch_requests.clone() else {
            return;
        };
        let due: Vec<(Vec<u8>, u64)> = self
            .owed_bodies
            .iter()
            .flat_map(|(address, owed)| {
                owed.iter()
                    .filter(|(_, body)| {
                        body.asked
                            .is_none_or(|at| at.elapsed() >= COMMITTED_TIP_ASK)
                    })
                    .map(move |(&number, _)| (address.clone(), number))
            })
            .take(OWED_BODY_ASKS_PER_PASS)
            .collect();
        for (address, number) in due {
            if self
                .clock_store
                .get_shard_clock_frame(&address, number, false)
                .is_ok_and(|stored| has_certificate(&stored))
            {
                self.forget_owed_body(&address, number);
                continue;
            }
            if sender.try_send((address.clone(), number)).is_err() {
                break;
            }
            if let Some(body) = self
                .owed_bodies
                .get_mut(&address)
                .and_then(|owed| owed.get_mut(&number))
            {
                body.asked = Some(Instant::now());
                body.asks += 1;
            }
        }
        let oldest = self
            .owed_bodies
            .iter()
            .flat_map(|(address, owed)| {
                owed.iter()
                    .map(move |(&number, body)| (body.since, address, number))
            })
            .min_by_key(|(since, _, _)| *since)
            .map(|(since, address, number)| (since, hex::encode(address), number));
        let Some((since, filter, frame)) = oldest else {
            return;
        };
        if since.elapsed() >= COMMITTED_TIP_WARN
            && self
                .owed_warned
                .is_none_or(|at| at.elapsed() >= COMMITTED_TIP_WARN)
        {
            self.owed_warned = Some(Instant::now());
            let owed: usize = self.owed_bodies.values().map(BTreeMap::len).sum();
            warn!(owed, shards = self.owed_bodies.len(), oldest_filter = %filter, oldest_frame = frame,
                oldest_owed_secs = since.elapsed().as_secs(),
                "archive still lacks the bodies of shard frames below its cursor: it asks the shards' members \
                 and archives for each at most every 5 minutes, behind the frames GLOBAL execution waits on, for \
                 up to 24 hours (the gap fetch's line for a frame names each answer); nodes replaying a shard \
                 from archives stop at such a frame until one serves it");
        }
    }

    fn try_materialize(&mut self, address: &[u8]) {
        if let Err(error) = self.materialize_in_order(address, u64::MAX, &HashMap::new()) {
            warn!(error = %error, "archive materialize deferred");
        }
    }

    /// Materialize `address`'s buffered frames in order through `through`, the
    /// highest frame of that shard a GLOBAL frame about to execute rewards.
    /// `Ok(false)` while a frame at or below `through` is missing (it is
    /// requested); an error leaves the cursor where it was, for a retry.
    ///
    /// GLOBAL reward execution reads the shard and world sizes this state
    /// makes up, so every archive must hold exactly the frames the GLOBAL chain
    /// has referenced when it executes a frame: never materialize ahead of
    /// that, never execute behind it.
    pub fn materialize_through(
        &mut self,
        address: &[u8],
        through: u64,
    ) -> quil_types::error::Result<bool> {
        self.materialize_in_order(address, through, &HashMap::new())
    }

    /// [`Self::materialize_through`] for a GLOBAL frame that carries the
    /// certified `headers` (by frame number) of this shard. A frame among them
    /// whose body no endpoint serves is materialized from its header once
    /// the header proves the frame carried no requests
    /// ([`Self::empty_frame_from_header`]).
    pub fn materialize_through_vouched(
        &mut self,
        address: &[u8],
        through: u64,
        headers: &HashMap<u64, quil_types::proto::global::FrameHeader>,
    ) -> quil_types::error::Result<bool> {
        self.materialize_in_order(address, through, headers)
    }

    fn materialize_in_order(
        &mut self,
        address: &[u8],
        through: u64,
        vouched: &HashMap<u64, quil_types::proto::global::FrameHeader>,
    ) -> quil_types::error::Result<bool> {
        let reached = loop {
            let last = self.materialized_height(address)?;
            if last >= through {
                break true;
            }
            let Some(next) = last.checked_add(1) else {
                break true;
            };
            // `rebuilt`: rebuilt from its header, and whether whole.
            let buffered = self
                .buffered
                .get(address)
                .and_then(|m| m.get(&next))
                .cloned();
            let (frame, rebuilt) = match buffered.or_else(|| self.read_back_stored(address, next)) {
                Some(f) => (f, None),
                None => match self.committed_held(address, next) {
                    Some(frame) => {
                        self.store_for_serving(&frame);
                        info!(address = %hex::encode(address), frame = next,
                            "archive sequences the frame GLOBAL committed without a certificate of its own (a sealed session's last frame)");
                        (frame, None)
                    }
                    None => match self.empty_frame_from_header(address, next, vouched) {
                        Some((frame, whole)) => (frame, Some(whole)),
                        None => break false, // gap — wait for the missing frame (or sync)
                    },
                },
            };
            let fee_multiplier_vote = frame
                .header
                .as_ref()
                .map(|h| h.fee_multiplier_vote)
                .unwrap_or(0);
            let global_frame_number = frame.header.as_ref().map_or(0, |h| h.global_frame_number);
            let world_size = crate::app_engine::certified_world_size(
                self.clock_store.as_ref(),
                global_frame_number,
            )
            .map_err(|e| {
                quil_types::error::QuilError::ExecutionUnavailable(format!(
                    "archive materialize of frame {next}: certified world size unavailable: {e}"
                ))
            })?;
            // Fees decide whether a token operation is admitted, so the archive
            // prices exactly as the committee did: certified header difficulty,
            // vote and anchored world size.
            let materialized = materialize_app_shard_requests(
                self.execution_manager.as_ref(),
                &frame.requests,
                next,
                frame.header.as_ref().map_or(0, |h| h.difficulty),
                world_size,
                fee_multiplier_vote,
                address,
                frame.header.as_ref().map_or(0, |h| h.global_frame_number),
            )?;
            self.set_materialized_height(address, next);
            if let Some(m) = self.buffered.get_mut(address) {
                m.remove(&next);
            }
            // A frame rebuilt whole is its body, served; one executed
            // without it owes its body, still sought, to serve.
            match rebuilt {
                Some(true) => {
                    self.store_for_serving(&frame);
                }
                Some(false) => {
                    let selector = frame.header.as_ref().and_then(|header| {
                        quil_crypto::poseidon::hash_bytes_to_32(&header.output).ok()
                    });
                    if let Some(selector) = selector {
                        self.owe_body(address, next, selector, OwedOrigin::Executed);
                    }
                }
                None => {}
            }
            // Info, not debug: an archive holding app-shard state is a
            // duty, and its only positive evidence. At debug a WORKING
            // ingest is indistinguishable from one that never ran,
            // which is how "the archive attempts zero ingests" was
            // read off a log that simply never said otherwise.
            info!(
                frame = next,
                processed = materialized.processed,
                skipped = materialized.skipped,
                address = %hex::encode(address),
                "archive materialized shard frame"
            );
        };
        // Gap detection: the next-needed frame is missing while frames are
        // buffered ahead of it, or while a GLOBAL frame needs it. Ask for it
        // through `with_gap_fetch` — nothing else will deliver it, since gossip
        // carries a frame once.
        let last = *self.last_materialized.get(address).unwrap_or(&0);
        let next_needed = last + 1;
        let ahead = self
            .buffered
            .get(address)
            .map_or(0, |m| m.keys().filter(|&&f| f > next_needed).count())
            + self.stored.get(address).map_or(0, |stored| {
                stored
                    .range(next_needed + 1..)
                    .filter(|(f, _)| {
                        !self
                            .buffered
                            .get(address)
                            .is_some_and(|m| m.contains_key(*f))
                    })
                    .count()
            });
        let missing = !self.body_held(address, next_needed);
        let waiting = !reached && through != u64::MAX;
        if missing && (ahead > 0 || waiting) {
            // A frame already held without a certificate needs its certified
            // descendant, not itself: ask for the first frame above the run.
            let mut wanted = next_needed;
            while self.is_held(address, wanted) {
                wanted += 1;
            }
            // While a GLOBAL frame waits, every missing frame it needs is asked
            // for at once, up to the window; otherwise the first missing frame.
            let (upto, interval) = if waiting {
                (
                    through.min(last.saturating_add(GAP_WINDOW)).max(wanted),
                    GLOBAL_WAIT_RETRY_INTERVAL,
                )
            } else {
                (wanted, GAP_RETRY_INTERVAL)
            };
            let requested = self.request_frames(address, wanted..=upto, true, waiting, interval);
            if requested > 0 {
                // Counted into the inclusion summary; a GLOBAL frame waiting on
                // the gap has a warning of its own.
                crate::inclusion_summary::note_gap(address, next_needed, requested);
                debug!(
                    address = %hex::encode(address),
                    missing_from = next_needed,
                    requested,
                    buffered_ahead = ahead,
                    "archive app-shard frame gap awaiting recovery"
                );
            }
        }
        // Bound the buffer to frames still ahead of us. An outstanding request
        // stays: a GLOBAL frame can need a frame with nothing buffered past it,
        // and advancing the cursor clears it.
        if let Some(held) = self.held.get_mut(address) {
            held.retain(|&(frame, _), _| frame > last);
            if held.is_empty() {
                self.held.remove(address);
            }
        }
        if let Some(m) = self.buffered.get_mut(address) {
            m.retain(|&f, _| f > last);
            if m.is_empty() {
                self.buffered.remove(address);
            }
        }
        self.publish_held(address);
        Ok(reached)
    }

    /// Ask for the frames of `address` that a GLOBAL frame after the executing
    /// one rewards, through `through` and at most [`PREFETCH_DEPTH`] above the
    /// cursor, behind every request a waiting GLOBAL frame makes. They wait in
    /// the buffer, unmaterialized, for the GLOBAL frame that sequences them.
    /// Only for a shard this archive already holds frames of: the stored GLOBAL
    /// frames this reads ahead in are not verified against executed state yet,
    /// and a header naming any other address may be forged. Returns how many
    /// frames were asked for.
    pub fn prefetch_through(
        &mut self,
        address: &[u8],
        through: u64,
    ) -> quil_types::error::Result<usize> {
        let last = self.materialized_height(address)?;
        let upto = through.min(last.saturating_add(PREFETCH_DEPTH));
        if last == 0 || upto <= last {
            return Ok(0);
        }
        Ok(self.request_frames(address, last + 1..=upto, false, false, GAP_RETRY_INTERVAL))
    }

    /// Whether this archive holds every frame of `address` that
    /// materializing it through `through` needs: each frame above its cursor
    /// buffered, stored with its digest remembered ([`Self::stored`]: frames
    /// the buffer bound evicted), or held as the frame GLOBAL committed at that
    /// height (a sealed session's last frame); `through` itself may instead be
    /// provably empty (`empty`: its certified header's `requests_root` is all
    /// zero), which [`Self::empty_frame_from_header`] rebuilds from that
    /// header. The first frame it lacks is asked for, with those above it to
    /// the prefetch depth, for a shard it already holds frames of: a header
    /// naming any other address may be forged (a bundle carrying several
    /// shards' headers rides without verification). What is held is
    /// published for proposals ([`Self::held_bodies`]).
    ///
    /// Buffered frames alone, a shard whose head ran more than the buffer
    /// bound past its cursor could never be held through a header GLOBAL can
    /// still carry, and its headers were held back for good.
    ///
    /// A GLOBAL prover proposes a shard's certified header only while this
    /// holds. Execution on every archive waits for the body of each frame a
    /// GLOBAL frame sequences, so a header whose body its committee never
    /// released halted GLOBAL for everyone. Held back, it rides a later
    /// GLOBAL frame within its anchor window once the body arrives.
    pub fn holds_bodies_through(
        &mut self,
        address: &[u8],
        through: u64,
        empty: bool,
    ) -> quil_types::error::Result<bool> {
        let last = self.materialized_height(address)?;
        let held = self.held_through(address, last);
        self.held_bodies.publish(address, last, held);
        if through <= held || (empty && through == held + 1) {
            return Ok(true);
        }
        let number = held + 1;
        let known =
            last > 0 || self.buffered.contains_key(address) || self.stored.contains_key(address);
        if known || self.held.contains_key(address) {
            let upto = through.min(number.saturating_add(PREFETCH_DEPTH));
            self.request_frames(address, number..=upto, false, false, GAP_RETRY_INTERVAL);
        }
        Ok(false)
    }

    /// Ask for each frame of `frames` neither buffered nor held, unless it was
    /// asked for within `interval` (at this priority or above). `urgent` asks
    /// on `gap_requests`, otherwise on `prefetch_requests`. A full queue
    /// leaves the rest for the next pass.
    /// `global_waits`: a GLOBAL frame waits for these frames, so one parked
    /// until execution reaches its anchor is asked for at once.
    fn request_frames(
        &mut self,
        address: &[u8],
        frames: RangeInclusive<u64>,
        urgent: bool,
        global_waits: bool,
        interval: Duration,
    ) -> usize {
        let sender = if urgent {
            self.gap_requests.clone()
        } else {
            self.prefetch_requests.clone()
        };
        let Some(sender) = sender else { return 0 };
        let mut sent = 0;
        let mut stored: HashMap<u64, bool> = HashMap::new();
        let mut executed: Option<Option<u64>> = None;
        for number in frames {
            if self.body_held(address, number) || self.is_held(address, number) {
                continue;
            }
            if let Some(anchor) = self
                .awaiting_anchor
                .get(address)
                .and_then(|waiting| waiting.get(&number))
                .copied()
            {
                let clock = &self.clock_store;
                if !*stored
                    .entry(anchor)
                    .or_insert_with(|| clock.get_global_clock_frame_header(anchor).is_ok())
                {
                    continue;
                }
                // The anchor arrived: the frame can validate now, so ask at once.
                if let Some(waiting) = self.awaiting_anchor.get_mut(address) {
                    waiting.remove(&number);
                    if waiting.is_empty() {
                        self.awaiting_anchor.remove(address);
                    }
                }
                self.anchors_noted.remove(&anchor);
                if let Some(requested) = self.requested.get_mut(address) {
                    requested.remove(&number);
                }
            }
            if let Some((anchor, since)) = self
                .awaiting_execution
                .get(address)
                .and_then(|waiting| waiting.get(&number))
                .copied()
            {
                // A GLOBAL frame waiting for this one sequences only a frame
                // anchored at or below the executed frame, so the parked copy
                // is not it: ask at once. A gap alone does not (unsequenced
                // ingest asks for the first missing frame urgently too).
                // Unreadable, the cursor holds nothing back: verification then
                // refuses as before.
                let reached = global_waits
                    || executed
                        .get_or_insert_with(|| self.executed_global_frame())
                        .is_none_or(|executed| executed >= anchor);
                if !reached && since.elapsed() < AWAIT_EXECUTION_TTL {
                    continue;
                }
                // Execution reached the anchor: verify the frame again, so ask at once.
                if let Some(waiting) = self.awaiting_execution.get_mut(address) {
                    waiting.remove(&number);
                    if waiting.is_empty() {
                        self.awaiting_execution.remove(address);
                    }
                }
                if let Some(requested) = self.requested.get_mut(address) {
                    requested.remove(&number);
                }
            }
            let due = self
                .requested
                .get(address)
                .and_then(|requested| requested.get(&number))
                .is_none_or(|&(at, was_urgent)| {
                    (urgent && !was_urgent) || at.elapsed() >= interval
                });
            if !due {
                continue;
            }
            if sender.try_send((address.to_vec(), number)).is_err() {
                break;
            }
            self.requested
                .entry(address.to_vec())
                .or_default()
                .insert(number, (Instant::now(), urgent));
            sent += 1;
        }
        if let Some(Some(executed)) = executed {
            self.execution_deferrals.executed(executed);
        }
        sent
    }

    /// The frame held without a certificate at `number` of `address` under
    /// the digest GLOBAL committed there: a sealed session's last frame,
    /// final through the seal. Its successor's first frame names the
    /// session's genesis, not this frame, so no certified frame ever links to
    /// it, and the GLOBAL frame sequencing the successor waited on it forever
    /// (…091f80, frame 4693, GLOBAL frame 935144, 2026-10-25). Committed state
    /// is the same on every archive, so every archive takes the same frame.
    fn committed_held(&self, address: &[u8], number: u64) -> Option<AppShardFrame> {
        let held = self.held.get(address)?;
        held.range((number, [0; 32])..=(number, [0xff; 32]))
            .next()?;
        let digest = crate::app_handoff::committed_frame_digest_looked_through(
            &self.hypergraph,
            address,
            number,
        )
        .ok()
        .flatten()?;
        held.get(&(number, digest)).cloned()
    }

    /// Whether a frame `number` of `address` is held without a certificate.
    fn is_held(&self, address: &[u8], number: u64) -> bool {
        self.held.get(address).is_some_and(|held| {
            held.range((number, [0; 32])..=(number, [0xff; 32]))
                .next()
                .is_some()
        })
    }

    /// The frame `number` of `address`, rebuilt from the certified header the
    /// executing GLOBAL frame carries, when no endpoint has served its body for
    /// [`EMPTY_FRAME_BODY_GRACE`] and the header proves the frame carried no
    /// requests (an all-zero `requests_root`, which the frame's output binds),
    /// with whether it is whole.
    ///
    /// Materializing a frame reads only its requests and header fields, so
    /// such a frame leaves exactly the state its body would, on every archive,
    /// whether or not it holds the body. The header carries the committee's
    /// storage attestation ([`crate::app_handoff::frame_from_carried_header`]):
    /// rebuilt with it, the frame is its body, and once it passes full
    /// validation it is stored for serving. Rebuilt without it (the header
    /// holds none, or it does not verify), the frame is executed on its
    /// certificate and output and not served: its body is owed and asked for
    /// until it arrives ([`Self::store_owed_body`]). A frame that carried
    /// requests cannot be rebuilt and keeps waiting for its body.
    ///
    /// GLOBAL 903,302 rewarded frame 2063 of a shard whose body no member or
    /// archive served, and every archive's execution stopped there
    /// (2026-10-19); decided 2026-10-19.
    fn empty_frame_from_header(
        &mut self,
        address: &[u8],
        number: u64,
        vouched: &HashMap<u64, quil_types::proto::global::FrameHeader>,
    ) -> Option<(AppShardFrame, bool)> {
        let header = vouched
            .get(&number)
            .filter(|header| header.address == address && header.frame_number == number)?;
        if !requests_root_is_empty(&header.requests_root) {
            return None;
        }
        let since = match self.missing_since.get(address) {
            Some(&(frame, since, _)) if frame == number => since,
            _ => {
                self.missing_since
                    .insert(address.to_vec(), (number, Instant::now(), false));
                return None;
            }
        };
        if since.elapsed() < self.empty_body_grace {
            return None;
        }
        let (frame, missing) = crate::app_handoff::frame_from_carried_header(header);
        let whole = match missing {
            Some(reason) => Err(reason),
            None => self.authenticate_body(&frame),
        };
        let reason = match whole {
            Ok(()) => {
                info!(frame = number, address = %hex::encode(address), waited_secs = since.elapsed().as_secs(),
                    attested = frame.storage_attestation.is_some(),
                    "archive materialized an empty shard frame from the certified header GLOBAL carried, with its \
                     committee's storage attestation: no endpoint served its body, and this archive serves the \
                     rebuilt one");
                return Some((frame, true));
            }
            Err(reason) => reason,
        };
        let frame = AppShardFrame {
            storage_attestation: None,
            ..frame
        };
        if let Err(refused) = self.authenticate_header(&frame) {
            if let Some(entry) = self.missing_since.get_mut(address).filter(|entry| !entry.2) {
                entry.2 = true;
                warn!(frame = number, address = %hex::encode(address), reason = %refused,
                    "archive cannot materialize an empty shard frame from its header: the header does not authenticate");
            }
            return None;
        }
        warn!(frame = number, address = %hex::encode(address), waited_secs = since.elapsed().as_secs(), %reason,
            "archive materialized an empty shard frame from its certified header without its storage attestation: \
             no endpoint served its body, which this archive asks for to serve");
        Some((frame, false))
    }

    /// Full validation of a frame rebuilt with its storage attestation:
    /// certificate, deterministic output and possession.
    fn authenticate_body(&self, frame: &AppShardFrame) -> Result<(), String> {
        #[cfg(test)]
        if self.skip_header_authentication {
            return Ok(());
        }
        match self.validator.validate(frame) {
            Ok(true) => Ok(()),
            Ok(false) => Err("certificate refused".into()),
            Err(error) => Err(format!("full validation failed: {error}")),
        }
    }

    /// Certificate and deterministic output (which binds `requests_root`),
    /// without the storage attestation the body would carry.
    fn authenticate_header(&self, frame: &AppShardFrame) -> Result<(), String> {
        #[cfg(test)]
        if self.skip_header_authentication {
            return Ok(());
        }
        match self.validator.validate_certified_without_storage(frame) {
            Ok(true) => Ok(()),
            Ok(false) => Err("certificate refused".into()),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// The checks a received app-shard frame passes before [`ArchiveAppShardIngest`]
/// admits it, apart from the ingest, so they can run without holding it.
#[derive(Clone)]
pub struct ArchiveFrameVerifier {
    /// What the ingest holds per shard, whose cursors tell a frame above the
    /// cursor ([`Self::stored_above_cursor`]).
    held_bodies: HeldBodies,
    validator: Arc<BlsAppFrameValidator>,
    execution_manager: Arc<quil_execution::ExecutionEngineManager>,
    inclusion_prover: Arc<dyn InclusionProver>,
    has_forest: bool,
    clock_store: Arc<dyn quil_types::store::ClockStore>,
    /// GLOBAL state frames verify against, whose executed frame tells a frame
    /// that waits for execution from one that is refused.
    hypergraph: Arc<quil_hypergraph::HypergraphCrdt>,
}

/// What [`ArchiveFrameVerifier::check`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameCheck {
    /// It may be admitted; `certified` says whether it carries its own
    /// certificate.
    Admit { certified: bool },
    /// GLOBAL state executed through `executed` holds no session for its
    /// generation, and it is anchored past it, at `anchor`: it waits for
    /// execution to reach the anchor
    /// ([`ArchiveAppShardIngest::await_execution`]).
    AwaitExecution { anchor: u64, executed: u64 },
    /// Refused (logged).
    Refused,
}

impl ArchiveFrameVerifier {
    /// Frame `number` of `address` as this archive's store holds it, when it
    /// is above the shard's cursor as the ingest last published it
    /// ([`HeldBodies`]); unverified, like a frame any endpoint serves. Bodies
    /// stored above the cursor are remembered in memory only, so after a
    /// restart an archive whose shards ran far ahead of their cursors admits
    /// them again from here before it asks the network.
    pub fn stored_above_cursor(&self, address: &[u8], number: u64) -> Option<AppShardFrame> {
        let cursor = self.held_bodies.cursor(address)?;
        if number <= cursor {
            return None;
        }
        self.clock_store
            .get_shard_clock_frame(address, number, false)
            .ok()
            .filter(|frame| {
                frame.header.as_ref().is_some_and(|header| {
                    header.address == address && header.frame_number == number
                })
            })
    }

    /// The GLOBAL frame `frame` is anchored to, when this archive has not
    /// stored it. Validation derives the frame's output from that GLOBAL
    /// frame, so it cannot pass before the GLOBAL frame is stored.
    pub fn missing_anchor(&self, frame: &AppShardFrame) -> Option<u64> {
        let anchor = frame.header.as_ref()?.global_frame_number;
        (anchor > 0
            && self
                .clock_store
                .get_global_clock_frame_header(anchor)
                .is_err())
        .then_some(anchor)
    }

    /// `Some(certified)` when `frame` may be admitted, `certified` saying
    /// whether it carries its own certificate; `None` when refused or when it
    /// waits for execution ([`Self::check`]).
    pub fn verify(&self, frame: &AppShardFrame) -> Option<bool> {
        match self.check(frame) {
            FrameCheck::Admit { certified } => Some(certified),
            FrameCheck::AwaitExecution { .. } | FrameCheck::Refused => None,
        }
    }

    /// Whether `frame` may be admitted, waits for GLOBAL execution to reach
    /// its anchor, or is refused (logged).
    pub fn check(&self, frame: &AppShardFrame) -> FrameCheck {
        let Some(header) = frame
            .header
            .as_ref()
            .filter(|header| !header.address.is_empty())
        else {
            return FrameCheck::Refused;
        };
        let (address, frame_number, requests_root) =
            (&header.address, header.frame_number, &header.requests_root);
        // 1. Quorum BLS cert + VDF against the shard committee. A frame with
        // no certificate of its own is one a certified descendant finalized
        // (see `admit`): it gets every check but the quorum here, and is only
        // ever materialized once a certified frame links to it.
        let certified = has_certificate(frame);
        let validated = if certified {
            self.validator.validate(frame)
        } else {
            self.validator.validate_proposal(frame)
        };
        match validated {
            Ok(true) => {}
            Ok(false) => {
                warn!(
                    frame = frame_number,
                    address = %hex::encode(address),
                    "archive ingest: shard frame REJECTED — quorum cert / signature validation returned false"
                );
                return FrameCheck::Refused;
            }
            Err(e) => {
                let anchor = header.global_frame_number;
                let executed = self
                    .hypergraph
                    .read_frame_cursor(&quil_store::encoding::global_materialized_cursor_key())
                    .ok()
                    .filter(|&executed| {
                        crate::execution_deferral::awaits_execution(&e, anchor, executed)
                    })
                    // Only the shard's next generation can be authorized by
                    // GLOBAL frames not yet executed; any other is refused, so a
                    // header naming an arbitrary generation is not parked.
                    .filter(|_| {
                        let claimed = header.public_key_signature_bls48581.as_ref().and_then(|s| {
                            crate::execution_deferral::claimed_generation(&s.signature)
                        });
                        claimed.is_some()
                            && claimed
                                == crate::execution_deferral::next_generation(
                                    &self.hypergraph,
                                    address,
                                )
                    });
                if let Some(executed) = executed {
                    debug!(frame = frame_number, address = %hex::encode(address), anchor, executed, error = %e,
                        "archive ingest: shard frame waits for GLOBAL execution to reach its anchor");
                    return FrameCheck::AwaitExecution { anchor, executed };
                }
                // Elevated from debug: this is the primary "why wasn't my shard
                // frame accepted" signal. A common cause is the anchored GLOBAL
                // frame being absent from the local clock store (ρ_N unavailable,
                // frame_validator.rs), which chains directly off any global-frame
                // propagation gap.
                warn!(
                    frame = frame_number,
                    address = %hex::encode(address),
                    certified,
                    error = %e,
                    "archive ingest: shard frame validation FAILED — rejecting"
                );
                return FrameCheck::Refused;
            }
        }

        // 2. Verify the carried requests recompute to the signed root.
        let canonical: Vec<Vec<u8>> = frame
            .requests
            .iter()
            // As the application committee judges it: an application frame
            // never carries a claim or a nullify report.
            .filter_map(|b| crate::consensus_wire::app_bundle_to_canonical_bytes(b).ok())
            .collect();
        if canonical.len() != frame.requests.len() {
            warn!(
                frame = frame_number,
                address = %hex::encode(address),
                converted = canonical.len(),
                total = frame.requests.len(),
                "archive ingest: {} of {} request bundles failed canonical conversion (consensus-wire converter gap) — rejecting frame",
                frame.requests.len().saturating_sub(canonical.len()),
                frame.requests.len(),
            );
            return FrameCheck::Refused;
        }
        let recomputed = match compute_requests_root(
            &canonical,
            address,
            frame_number,
            Some(self.execution_manager.as_ref()),
            Some(self.inclusion_prover.as_ref()),
            self.has_forest,
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    frame = frame_number,
                    address = %hex::encode(address),
                    error = %e,
                    "archive ingest: requests_root recompute errored — rejecting frame"
                );
                return FrameCheck::Refused;
            }
        };
        if recomputed != *requests_root {
            warn!(frame = frame_number, address = %hex::encode(address), "archive ingest: requests_root mismatch — rejecting");
            return FrameCheck::Refused;
        }

        FrameCheck::Admit { certified }
    }
}

/// The digest of a frame's encoding as it is stored, with its header's
/// `storage_attestation` cleared, which a body read back from the store must
/// match ([`ArchiveAppShardIngest::stored`]).
fn body_digest(frame: &AppShardFrame) -> [u8; 32] {
    use sha2::Digest as _;
    if frame
        .header
        .as_ref()
        .is_some_and(|header| !header.storage_attestation.is_empty())
    {
        let mut cleared = frame.clone();
        if let Some(header) = cleared.header.as_mut() {
            header.storage_attestation.clear();
        }
        return body_digest(&cleared);
    }
    sha2::Sha256::digest(prost::Message::encode_to_vec(frame)).into()
}

/// Per shard, the run of frames above its cursor whose bodies an archive's
/// ingest holds, published by the ingest
/// ([`ArchiveAppShardIngest::holds_bodies_through`]) and read without it.
///
/// A GLOBAL proposal checks the headers it may carry against it. It used to
/// wait up to 2 s for the ingest itself, which sequenced execution holds while
/// it materializes and the receive loop held while it verified each gossiped
/// frame, and to carry no shard header at all when the wait ran out: on
/// 2026-10-27 most proposals of every archive did.
#[derive(Clone, Default)]
pub struct HeldBodies {
    inner: Arc<std::sync::Mutex<HeldBodiesInner>>,
}

#[derive(Default)]
struct HeldBodiesInner {
    runs: HashMap<Vec<u8>, HeldRun>,
    /// Shards whose frames ran further above the cursor than the ingest
    /// tracks ([`MAX_STORED_BODIES_PER_SHARD`]), since when.
    beyond_bound: HashMap<Vec<u8>, Instant>,
    /// Headers a proposal could not carry, per shard: (frame, empty).
    wanted: HashMap<Vec<u8>, (u64, bool)>,
}

/// A shard's cursor, the highest frame through which every body above it is
/// held, and whether a header past the frame buffer was refused since one
/// was last proposable.
#[derive(Clone, Copy, Debug)]
struct HeldRun {
    cursor: u64,
    through: u64,
    refused: bool,
}

impl HeldBodies {
    /// The record, also after a holder panicked.
    fn lock(&self) -> std::sync::MutexGuard<'_, HeldBodiesInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The application frames materializing `address` through `through`
    /// executes, when every body it needs is held, as
    /// [`ArchiveAppShardIngest::holds_bodies_through`] last found; `None`
    /// otherwise, and the header is left for the ingest to look into
    /// ([`ArchiveAppShardIngest::look_into_wanted`]).
    pub fn frames_held(&self, address: &[u8], through: u64, empty: bool) -> Option<u64> {
        let mut guard = self.lock();
        let inner = &mut *guard;
        if let Some(run) = inner.runs.get_mut(address) {
            if through <= run.through || (empty && through == run.through + 1) {
                let frames = through.saturating_sub(run.cursor);
                if std::mem::take(&mut run.refused) {
                    // Held past the frame buffer: read back from the store.
                    crate::inclusion_summary::note_caught_up(address, frames);
                }
                if let Some(since) = inner.beyond_bound.remove(address) {
                    info!(scope = "this archive", address = %hex::encode(address), through, frames,
                        beyond_secs = since.elapsed().as_secs(),
                        "archive holds a shard's application frame bodies again from its cursor through a header \
                         GLOBAL can carry, after the shard ran further ahead than this archive tracks; its \
                         headers can be proposed again");
                }
                return Some(frames);
            }
            let gap = through.saturating_sub(run.cursor);
            if gap > MAX_BUFFERED_FRAMES_PER_SHARD as u64 {
                run.refused = true;
                crate::inclusion_summary::note_behind(address, gap);
            }
        }
        if inner.wanted.len() < MAX_WANTED_SHARDS || inner.wanted.contains_key(address) {
            let wanted = inner
                .wanted
                .entry(address.to_vec())
                .or_insert((through, empty));
            if through > wanted.0 {
                *wanted = (through, empty);
            }
        }
        None
    }

    /// `address`'s frames ran past [`MAX_STORED_BODIES_PER_SHARD`] above its
    /// `cursor`, to `farthest`: warned once, until its headers can be
    /// proposed again ([`Self::frames_held`]).
    fn note_beyond_bound(&self, address: &[u8], cursor: u64, farthest: u64) {
        let mut inner = self.lock();
        if inner.beyond_bound.contains_key(address) {
            return;
        }
        inner.beyond_bound.insert(address.to_vec(), Instant::now());
        warn!(scope = "this archive", address = %hex::encode(address), cursor, farthest,
            bound = MAX_STORED_BODIES_PER_SHARD,
            "archive ingest: a shard's frames run further above its cursor than this archive tracks, so its \
             newest headers cannot be proposed until frames below are executed; frames past the bound are asked \
             for again once needed. A defect to report with this line; a line follows when it recovers");
    }

    /// `address`'s cursor as last published.
    pub fn cursor(&self, address: &[u8]) -> Option<u64> {
        self.lock().runs.get(address).map(|run| run.cursor)
    }

    fn publish(&self, address: &[u8], cursor: u64, through: u64) {
        let mut inner = self.lock();
        match inner.runs.get_mut(address) {
            Some(run) => {
                run.cursor = cursor;
                run.through = through;
            }
            None => {
                inner.runs.insert(
                    address.to_vec(),
                    HeldRun {
                        cursor,
                        through,
                        refused: false,
                    },
                );
            }
        }
    }

    fn take_wanted(&self) -> HashMap<Vec<u8>, (u64, bool)> {
        std::mem::take(&mut self.lock().wanted)
    }

    fn clear(&self) {
        let mut inner = self.lock();
        inner.runs.clear();
        inner.wanted.clear();
        inner.beyond_bound.clear();
    }
}

/// Ingest a gossiped full `AppShardFrame` (prost bytes) as
/// [`ArchiveAppShardIngest::ingest`] does, verifying it without holding
/// `ingest`, which is held only to read the cursor and to admit.
///
/// The receive loop used to verify every gossiped frame of every shard while
/// it held the ingest, which GLOBAL execution and proposals wait for.
pub fn ingest_gossiped(
    ingest: &std::sync::Mutex<ArchiveAppShardIngest>,
    verifier: &ArchiveFrameVerifier,
    data: &[u8],
) {
    let lock = || ingest.lock().unwrap_or_else(|p| p.into_inner());
    let frame = match <AppShardFrame as prost::Message>::decode(data) {
        Ok(f) => f,
        Err(_) => return,
    };
    let (address, frame_number) = match frame.header.as_ref() {
        Some(h) if !h.address.is_empty() => (h.address.clone(), h.frame_number),
        _ => {
            debug!("archive ingest: shard frame missing header or empty address — dropping");
            return;
        }
    };
    {
        let mut guard = lock();
        let held = match guard.materialized_height(&address) {
            Ok(height) => height,
            Err(error) => {
                warn!(error = %error, "archive ingest deferred: materialized cursor unavailable");
                return;
            }
        };
        debug!(
            frame = frame_number,
            held,
            address = %hex::encode(&address),
            "archive ingest: received a full app-shard frame"
        );
        // Already materialized (or older): ignore, unless this archive owes
        // the frame's body, which is then checked and served, never executed.
        if frame_number <= held && !guard.wants_owed_body(&address, &frame) {
            return;
        }
    }
    if let Some(anchor) = verifier.missing_anchor(&frame) {
        lock().await_anchor(&address, frame_number, anchor);
        return;
    }
    match verifier.check(&frame) {
        FrameCheck::Admit { certified } => lock().admit_verified(frame, certified),
        FrameCheck::AwaitExecution { anchor, executed } => {
            lock().await_execution(&address, frame_number, anchor, executed);
        }
        FrameCheck::Refused => {}
    }
}

/// What [`admit_fetched`] made of the frames one endpoint served.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchedFrames {
    /// The frame asked for was admitted, or waits for its GLOBAL anchor to
    /// be stored.
    Admitted,
    /// The frame asked for failed verification.
    Refused,
    /// The frame asked for waits for GLOBAL execution to reach `anchor`
    /// ([`FrameCheck::AwaitExecution`]). Not recovered from this endpoint:
    /// another may serve a copy that verifies now.
    AwaitsExecution { anchor: u64, executed: u64 },
}

/// Check the frames a gap fetch recovered from one endpoint (the frame asked
/// for first, then the run up to its certified descendant) and admit them to
/// `ingest`, which is held only to admit.
pub fn admit_fetched(
    ingest: &std::sync::Mutex<ArchiveAppShardIngest>,
    verifier: &ArchiveFrameVerifier,
    address: &[u8],
    frames: Vec<AppShardFrame>,
) -> FetchedFrames {
    let lock = || ingest.lock().unwrap_or_else(|p| p.into_inner());
    let mut outcome = FetchedFrames::Admitted;
    for (index, frame) in frames.into_iter().enumerate() {
        let number = frame.header.as_ref().map_or(0, |h| h.frame_number);
        if let Some(anchor) = verifier.missing_anchor(&frame) {
            lock().await_anchor(address, number, anchor);
            continue;
        }
        match verifier.check(&frame) {
            FrameCheck::Admit { certified } => lock().admit_verified(frame, certified),
            FrameCheck::AwaitExecution { anchor, executed } => {
                lock().await_execution(address, number, anchor, executed);
                if index == 0 {
                    outcome = FetchedFrames::AwaitsExecution { anchor, executed };
                }
            }
            FrameCheck::Refused if index == 0 => return FetchedFrames::Refused,
            FrameCheck::Refused => {}
        }
    }
    outcome
}

/// The `requests_root` of a frame with no requests: zero bytes, 32 on the
/// forest path and 64 on the legacy one ([`compute_requests_root`]).
pub(crate) fn requests_root_is_empty(root: &[u8]) -> bool {
    matches!(root.len(), 32 | 64) && root.iter().all(|&byte| byte == 0)
}

/// Frames above a gap-fetched frame without a certificate that the gap
/// fetch follows to the certified descendant making it final: as many as
/// the ingest holds without one.
const MAX_LINKED_RUN: usize = MAX_HELD_FRAMES_PER_SHARD;

fn has_certificate(frame: &AppShardFrame) -> bool {
    frame
        .header
        .as_ref()
        .and_then(|header| header.public_key_signature_bls48581.as_ref())
        .is_some_and(|signature| !signature.signature.is_empty())
}

/// Prepare the historical storage registrations a gap-fetched frame's
/// validation needs ([`BlsAppFrameValidator::prepare_storage_history`]),
/// returning the frames to hand the ingest and whether preparing succeeded.
///
/// A frame without a certificate is final only through a certified
/// descendant, and its registrations are fetched only once that descendant's
/// certificate and every link down to the frame check out, as a member's
/// archive replay does. The run up to the descendant comes from `fetch` and
/// is handed over with the frame. The gap fetch used to prepare certified
/// frames only, so the ingest refused such a frame on every retry and never
/// asked for its descendant: one archive sat at GLOBAL 870,123 for 20 hours
/// on frames 291–292 of a shard (2026-10-12).
pub async fn prepare_gap_fetched<F, Fut>(
    validator: &BlsAppFrameValidator,
    frame: AppShardFrame,
    mut fetch: F,
) -> (Vec<AppShardFrame>, quil_types::error::Result<()>)
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = Option<AppShardFrame>>,
{
    use quil_types::error::QuilError;
    // A sealed session's last frame has no certificate of its own and no
    // certified frame after it; the digest GLOBAL committed for it
    // authenticates it instead. Its registrations were never prepared: the
    // search for a descendant stopped first, and validation then refused it
    // where this archive no longer resolves its GLOBAL anchor's registrations
    // locally, so the frame the committed-tip request fetched was never held
    // or served.
    if !has_certificate(&frame) && validator.committed_by_global(&frame) {
        let prepared = validator.prepare_storage_history_of_linked(&frame).await;
        return (vec![frame], prepared);
    }
    let mut run = vec![frame];
    while let Some(parent) = run
        .last()
        .filter(|frame| !has_certificate(frame))
        .and_then(|frame| frame.header.clone())
    {
        if run.len() > MAX_LINKED_RUN {
            return (
                run,
                Err(QuilError::ExecutionUnavailable(format!(
                    "no certified descendant within {MAX_LINKED_RUN} frames"
                ))),
            );
        }
        let Some(child) = fetch(parent.frame_number + 1).await else {
            return (
                run,
                Err(QuilError::ExecutionUnavailable(format!(
                    "certified descendant unavailable: frame {} not fetched",
                    parent.frame_number + 1
                ))),
            );
        };
        if !child
            .header
            .as_ref()
            .is_some_and(|child| crate::frame_validator::app_frame_links_to_child(&parent, child))
        {
            return (
                run,
                Err(QuilError::InvalidArgument(format!(
                    "fetched frame {} does not link to frame {}",
                    parent.frame_number + 1,
                    parent.frame_number
                ))),
            );
        }
        run.push(child);
    }
    let prepared = async {
        let (descendant, linked) = run.split_last().expect("the run holds the fetched frame");
        if !linked.is_empty() && !validator.validate_certified_without_storage(descendant)? {
            return Err(QuilError::InvalidSignature(
                "certified descendant of a gap-fetched frame is invalid".into(),
            ));
        }
        validator.prepare_storage_history(descendant).await?;
        for frame in linked.iter().rev() {
            validator.prepare_storage_history_of_linked(frame).await?;
        }
        Ok(())
    }
    .await;
    (run, prepared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::proto::global::FrameHeader;

    fn fixture() -> (
        ArchiveAppShardIngest,
        Arc<quil_hypergraph::testing::MemStore>,
    ) {
        fixture_with_clock(None)
    }

    /// The fixture, serving from `clock` when given.
    fn fixture_with_clock(
        clock: Option<Arc<dyn quil_types::store::ClockStore>>,
    ) -> (
        ArchiveAppShardIngest,
        Arc<quil_hypergraph::testing::MemStore>,
    ) {
        let store = Arc::new(quil_hypergraph::testing::MemStore::new());
        let inclusion = Arc::new(quil_types::crypto::NoopInclusionProver);
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store.clone(),
            inclusion,
        ));
        (fixture_over(crdt, clock), store)
    }

    /// The fixture over the GLOBAL state `crdt`, serving from `clock` when given.
    fn fixture_over(
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
        clock: Option<Arc<dyn quil_types::store::ClockStore>>,
    ) -> ArchiveAppShardIngest {
        fixture_with_registry(
            crdt,
            clock,
            Arc::new(crate::test_support::TestProverRegistry::new()),
        )
    }

    /// [`fixture_over`] with the prover registry `registry`.
    fn fixture_with_registry(
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
        clock: Option<Arc<dyn quil_types::store::ClockStore>>,
        registry: Arc<crate::test_support::TestProverRegistry>,
    ) -> ArchiveAppShardIngest {
        let inclusion = Arc::new(quil_types::crypto::NoopInclusionProver);
        let crypto = quil_execution::testing::NoopExecutionCrypto::new();
        let manager = Arc::new(quil_execution::ExecutionEngineManager::new(
            inclusion.clone(),
            crypto.key_manager,
            crdt.clone(),
            crypto.circuit_compiler,
            crypto.clock_store.clone(),
            Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
            false,
        ));
        ArchiveAppShardIngest::new(
            registry,
            Arc::new(quil_crypto::FalconKeyConstructor),
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            manager,
            inclusion,
            crdt,
            clock.unwrap_or(crypto.clock_store),
        )
    }

    /// GLOBAL state in which `filter`'s first session sealed at frame
    /// `frame` with checkpoint digest `digest`, and its successor is based
    /// there without a frame of its own.
    fn sealed_global(
        filter: &[u8],
        frame: u64,
        digest: [u8; 32],
    ) -> Arc<quil_hypergraph::HypergraphCrdt> {
        use quil_cw_consensus::handoff::{Checkpoint, Seal, Session};
        use quil_execution::global_intrinsic::handoff::{
            self, CertificateSubmission, DesiredCommittee,
        };
        use quil_types::crypto::Signer as _;
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let global = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
            Arc::new(quil_hypergraph::testing::StubProver),
        ));
        global.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        let signers: Vec<_> = (0..3)
            .map(|_| quil_crypto::FalconSigner::generate())
            .collect();
        let mut members: Vec<Vec<u8>> = signers.iter().map(|s| s.public_key().to_vec()).collect();
        members.sort();
        let source = Session {
            chain_id: [7; 32],
            filter: filter.to_vec(),
            generation: 1,
            genesis: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap(),
            base_frame: 0,
            authorization: [0; 32],
            members: members.clone(),
        };
        let state = quil_execution::hypergraph_state::HypergraphState::new(global.clone());
        let commit = |number| {
            state.commit().unwrap();
            state.abort();
            global
                .commit_with_global_cursor(
                    number,
                    &quil_store::encoding::global_materialized_cursor_key(),
                )
                .unwrap();
        };
        commit(1);
        handoff::initialize(&state, 2, &source).unwrap();
        commit(2);
        let request = handoff::schedule(
            &state,
            3,
            vec![filter.to_vec()],
            vec![DesiredCommittee {
                filter: filter.to_vec(),
                members,
            }],
        )
        .unwrap();
        commit(3);
        let seal = Seal {
            request: request.id().unwrap(),
            session: source.id().unwrap(),
            view: 9,
            checkpoint: Checkpoint {
                frame,
                view: 5,
                digest,
                state_roots: [[1; 32]; 4],
                history_root: [0; 32],
            },
        };
        let certificate = crate::test_support::certify_seal(&source, &signers, &seal);
        handoff::record_session_tip(&state, 4, &seal.session, &seal.checkpoint).unwrap();
        assert!(
            handoff::apply_submission(&state, 4, &CertificateSubmission { seal, certificate })
                .unwrap()
        );
        commit(4);
        assert_eq!(
            crate::app_handoff::committed_tip(&global, filter).unwrap(),
            Some(frame)
        );
        global
    }

    // These fixtures enter after certificate validation to exercise the gap
    // queue and the actual materializer/cursor commit independently of crypto.
    fn verified_frame(filter: &[u8], number: u64) -> AppShardFrame {
        AppShardFrame {
            header: Some(FrameHeader {
                address: filter.to_vec(),
                frame_number: number,
                ..Default::default()
            }),
            requests: Vec::new(),
            storage_attestation: None,
        }
    }

    /// Frames `1..=to` of one shard, each naming the one before it.
    fn chain(filter: &[u8], to: u64) -> Vec<AppShardFrame> {
        let mut frames: Vec<AppShardFrame> = Vec::new();
        for number in 1..=to {
            let mut frame = verified_frame(filter, number);
            let header = frame.header.as_mut().unwrap();
            header.rank = number * 2;
            header.output = vec![number as u8; 32];
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

    /// A frame the committee notarized and a certified descendant finalized
    /// has no certificate of its own. It is held until a certified frame
    /// links to it, then materialized in order; one that does not link never is.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_uncertified_frame_is_admitted_only_under_a_certified_descendant() {
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let frames = chain(&filter, 5);
        let buffered = |ingest: &ArchiveAppShardIngest| {
            let mut numbers: Vec<u64> = ingest
                .buffered
                .get(&filter)
                .map_or(Vec::new(), |m| m.keys().copied().collect());
            numbers.sort();
            numbers
        };

        // The ancestor first: held, then promoted by its certified child.
        let (mut ingest, _) = fixture();
        ingest.admit(&filter, frames[0].clone(), true);
        ingest.admit(&filter, frames[1].clone(), false);
        assert_eq!(buffered(&ingest), vec![1]);
        ingest.admit(&filter, frames[2].clone(), true);
        assert_eq!(buffered(&ingest), vec![1, 2, 3]);
        ingest.retry_pending();
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 3);

        // The child first: the ancestor is buffered on arrival. A chain of
        // two held frames is promoted by one certified descendant.
        let (mut ingest, _) = fixture();
        ingest.admit(&filter, frames[2].clone(), true);
        ingest.admit(&filter, frames[1].clone(), false);
        assert_eq!(buffered(&ingest), vec![2, 3]);
        let (mut ingest, _) = fixture();
        ingest.admit(&filter, frames[1].clone(), false);
        ingest.admit(&filter, frames[2].clone(), false);
        ingest.admit(&filter, frames[3].clone(), true);
        assert_eq!(buffered(&ingest), vec![2, 3, 4]);

        // An impostor at the same height never links, whatever arrives.
        let (mut ingest, _) = fixture();
        let mut impostor = frames[1].clone();
        impostor.header.as_mut().unwrap().output = vec![0xee; 32];
        ingest.admit(&filter, impostor, false);
        ingest.admit(&filter, frames[2].clone(), true);
        assert_eq!(buffered(&ingest), vec![3]);

        // A held run asks for the certified frame above it, not for itself.
        let (mut ingest, _) = fixture();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        ingest = ingest.with_gap_fetch(tx);
        ingest.admit(&filter, frames[0].clone(), true);
        ingest.admit(&filter, frames[4].clone(), true);
        ingest.admit(&filter, frames[1].clone(), false);
        ingest.admit(&filter, frames[2].clone(), false);
        ingest.retry_pending();
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 1);
        assert_eq!(rx.try_recv().unwrap(), (filter.clone(), 4));
    }

    /// An admitted frame is stored where the archive serves shard frames from.
    /// A frame without a certificate is stored only once a certified frame
    /// links to it, and an impostor at its height never is.
    #[tokio::test(flavor = "multi_thread")]
    async fn admitted_frames_are_stored_for_serving() {
        use quil_types::store::ClockStore as _;
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let frames = chain(&filter, 3);
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (mut ingest, _) = fixture_with_clock(Some(clock.clone()));
        let served = |number| clock.get_shard_clock_frame(&filter, number, false).ok();
        ingest.admit(&filter, frames[0].clone(), true);
        assert_eq!(served(1), Some(frames[0].clone()));
        let mut impostor = frames[1].clone();
        impostor.header.as_mut().unwrap().output = vec![0xee; 32];
        ingest.admit(&filter, impostor, false);
        ingest.admit(&filter, frames[1].clone(), false);
        assert_eq!(served(2), None, "held until a certified frame links to it");
        ingest.admit(&filter, frames[2].clone(), true);
        assert_eq!(served(2), Some(frames[1].clone()));
        assert_eq!(served(3), Some(frames[2].clone()));
        assert_eq!(
            clock.get_latest_shard_clock_frame(&filter).unwrap(),
            frames[2]
        );
    }

    /// A sealed session's last frame has no certificate of its own and no
    /// certified frame after it, so it was held and never served, and every
    /// successor replaying to the seal stopped one frame short (…091f80,
    /// frame 4693, 2026-10-20). Held at GLOBAL's committed tip under the
    /// digest the seal committed, it is served, still neither buffered nor
    /// materialized; an impostor at that height never is.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_held_frame_global_committed_is_stored_for_serving() {
        use quil_types::store::ClockStore as _;
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let frames = chain(&filter, 3);
        let sealed =
            quil_crypto::poseidon::hash_bytes_to_32(&frames[2].header.as_ref().unwrap().output)
                .unwrap();
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let mut ingest =
            fixture_over(sealed_global(&filter, 3, sealed), Some(clock.clone())).sequenced();
        let served = |number| clock.get_shard_clock_frame(&filter, number, false).ok();
        ingest.admit(&filter, frames[0].clone(), true);
        ingest.admit(&filter, frames[1].clone(), true);
        let mut impostor = frames[2].clone();
        impostor.header.as_mut().unwrap().output = vec![0xee; 32];
        ingest.admit(&filter, impostor, false);
        ingest.retry_pending();
        assert_eq!(
            served(3),
            None,
            "an impostor at the committed tip is never served"
        );
        ingest.admit(&filter, frames[2].clone(), false);
        assert_eq!(served(3), None, "held");
        ingest.retry_pending();
        assert_eq!(served(3), Some(frames[2].clone()));
        assert_eq!(
            clock.get_latest_shard_clock_frame(&filter).unwrap(),
            frames[2]
        );
        assert!(ingest.is_held(&filter, 3), "still held");
        assert!(
            ingest
                .buffered
                .get(&filter)
                .is_some_and(|buffered| !buffered.contains_key(&3)),
            "never buffered"
        );
        ingest.retry_pending();
        assert_eq!(served(3), Some(frames[2].clone()));

        // Under any other committed digest, nothing held is served.
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let mut ingest =
            fixture_over(sealed_global(&filter, 3, [0x33; 32]), Some(clock.clone())).sequenced();
        ingest.admit(&filter, frames[2].clone(), false);
        ingest.retry_pending();
        assert!(clock.get_shard_clock_frame(&filter, 3, false).is_err());
    }

    /// A sealed session's last frame stays held: its successor's first frame
    /// names the session's genesis, so no certified frame links to it. GLOBAL's
    /// sequencing takes it under the digest the seal committed and serves it,
    /// so the GLOBAL frame sequencing the successor does not wait on it forever
    /// (…091f80, frame 4693, GLOBAL frame 935144, 2026-10-25); an impostor at
    /// that height never is taken.
    #[tokio::test(flavor = "multi_thread")]
    async fn sequencing_takes_the_sealed_last_frame_global_committed() {
        use quil_types::store::ClockStore as _;
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let mut frames = chain(&filter, 4);
        frames[3].header.as_mut().unwrap().parent_selector = vec![0x5e; 32];
        let sealed =
            quil_crypto::poseidon::hash_bytes_to_32(&frames[2].header.as_ref().unwrap().output)
                .unwrap();
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let mut ingest =
            fixture_over(sealed_global(&filter, 3, sealed), Some(clock.clone())).sequenced();
        ingest.admit(&filter, frames[0].clone(), true);
        ingest.admit(&filter, frames[1].clone(), true);
        let mut impostor = frames[2].clone();
        impostor.header.as_mut().unwrap().output = vec![0xee; 32];
        ingest.admit(&filter, impostor, false);
        ingest.admit(&filter, frames[3].clone(), true);
        assert!(
            !ingest.materialize_through(&filter, 4).unwrap(),
            "an impostor is never sequenced"
        );
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 2);
        ingest.admit(&filter, frames[2].clone(), false);
        assert!(ingest.is_held(&filter, 3), "no certified frame links to it");
        assert!(ingest.materialize_through(&filter, 4).unwrap());
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 4);
        assert_eq!(
            clock.get_shard_clock_frame(&filter, 3, false).ok(),
            Some(frames[2].clone())
        );
        assert!(!ingest.is_held(&filter, 3));
    }

    /// An archive that lost a sealed session's last frame (it restarted after
    /// the frame was gossiped) never asked for it again, and no archive
    /// served it (…091f80, frame 4693, 2026-10-20). A shard whose committed
    /// GLOBAL tip is above the frame the archive serves gets that frame asked
    /// for on the gap fetch, at most every few minutes; once fetched and
    /// served under the committed digest, it is not asked for again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_committed_tip_the_archive_does_not_serve_is_asked_for() {
        use quil_types::store::ClockStore as _;
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let frames = chain(&filter, 3);
        let sealed =
            quil_crypto::poseidon::hash_bytes_to_32(&frames[2].header.as_ref().unwrap().output)
                .unwrap();
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let registry = Arc::new(crate::test_support::TestProverRegistry::new());
        registry.set_summaries(vec![quil_types::consensus::ProverShardSummary {
            filter: filter.clone(),
            status_counts: HashMap::new(),
            total_size: 1,
        }]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let mut ingest = fixture_with_registry(
            sealed_global(&filter, 3, sealed),
            Some(clock.clone()),
            registry,
        )
        .with_gap_fetch(tx)
        .sequenced();
        ingest.admit(&filter, frames[0].clone(), true);
        ingest.admit(&filter, frames[1].clone(), true);
        ingest.retry_pending();
        assert_eq!(
            rx.try_recv().unwrap(),
            (filter.clone(), 3),
            "the committed tip above the served frame 2"
        );
        ingest.last_tip_scan = None;
        ingest.retry_pending();
        assert!(rx.try_recv().is_err(), "asked at most once per interval");
        assert_eq!(
            ingest.missing_tips.get(&filter).map(|missing| (
                missing.tip,
                missing.served,
                missing.asks
            )),
            Some((3, 2, 1))
        );

        // The fetched frame, without a certificate of its own, is served
        // under the committed digest; then nothing is missing.
        ingest.admit(&filter, frames[2].clone(), false);
        ingest.retry_pending();
        assert_eq!(
            clock.get_shard_clock_frame(&filter, 3, false).ok(),
            Some(frames[2].clone())
        );
        ingest.last_tip_scan = None;
        ingest.retry_pending();
        assert!(rx.try_recv().is_err());
        assert!(ingest.missing_tips.is_empty());
    }

    /// A gap-fetched frame without a certificate of its own is prepared
    /// only once its certified descendant is found, which a sealed session's
    /// last frame never has: its registrations were never prepared, so
    /// validation could refuse it and the frame was never served. The frame
    /// GLOBAL committed is prepared at once, without asking for a
    /// descendant, held and served; any other frame still needs one.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_gap_fetched_committed_frame_is_prepared_without_a_descendant_and_served() {
        use quil_types::store::ClockStore as _;
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let frames = chain(&filter, 3);
        let sealed =
            quil_crypto::poseidon::hash_bytes_to_32(&frames[2].header.as_ref().unwrap().output)
                .unwrap();
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let mut ingest =
            fixture_over(sealed_global(&filter, 3, sealed), Some(clock.clone())).sequenced();
        let validator = ingest.validator();
        let asked = std::sync::Mutex::new(Vec::new());
        let fetch = |number: u64| {
            asked.lock().unwrap().push(number);
            async { None }
        };
        let (run, prepared) = prepare_gap_fetched(&validator, frames[2].clone(), fetch).await;
        assert!(prepared.is_ok(), "{prepared:?}");
        assert!(
            asked.lock().unwrap().is_empty(),
            "no descendant is asked for"
        );
        ingest.admit(&filter, frames[0].clone(), true);
        ingest.admit(&filter, frames[1].clone(), true);
        for frame in run {
            ingest.admit(&filter, frame, false);
        }
        ingest.retry_pending();
        assert_eq!(
            clock.get_shard_clock_frame(&filter, 3, false).ok(),
            Some(frames[2].clone())
        );

        let mut impostor = frames[2].clone();
        impostor.header.as_mut().unwrap().output = vec![0xee; 32];
        let (_, prepared) = prepare_gap_fetched(&validator, impostor, fetch).await;
        assert!(prepared.is_err());
        assert_eq!(
            *asked.lock().unwrap(),
            vec![4],
            "any other frame still needs its certified descendant"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_gap_fetch_retries_then_drains_and_restores_its_cursor() {
        let (mut ingest, _) = fixture();
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        ingest = ingest.with_gap_fetch(tx);
        ingest
            .buffered
            .entry(filter.clone())
            .or_default()
            .insert(2, verified_frame(&filter, 2));
        ingest.retry_pending();
        assert_eq!(rx.try_recv().unwrap(), (filter.clone(), 1));
        ingest.retry_pending();
        assert!(rx.try_recv().is_err(), "one active request per gap");
        // The peer had no frame / connection failed. No new gossip arrives.
        ingest
            .requested
            .get_mut(&filter)
            .unwrap()
            .get_mut(&1)
            .unwrap()
            .0 = Instant::now() - GAP_RETRY_INTERVAL;
        ingest.retry_pending();
        assert_eq!(
            rx.try_recv().unwrap(),
            (filter.clone(), 1),
            "timer retries without inbound frames"
        );
        ingest
            .buffered
            .get_mut(&filter)
            .unwrap()
            .insert(1, verified_frame(&filter, 1));
        ingest.retry_pending();
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 2);
        assert!(ingest.buffered.is_empty());
        assert!(ingest.requested.is_empty());
        ingest.last_materialized.clear();
        assert_eq!(
            ingest.materialized_height(&filter).unwrap(),
            2,
            "recover the co-committed cursor"
        );
    }

    /// Sequenced ingest materializes only when GLOBAL execution asks, in
    /// order, exactly through the frame asked for, and asks for a missing
    /// frame a GLOBAL frame needs even with nothing buffered past it.
    #[tokio::test(flavor = "multi_thread")]
    async fn sequenced_ingest_materializes_only_through_what_global_execution_asks() {
        let (ingest, _) = fixture();
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let mut ingest = ingest.with_gap_fetch(tx).sequenced();
        for number in 1..=3 {
            ingest
                .buffered
                .entry(filter.clone())
                .or_default()
                .insert(number, verified_frame(&filter, number));
        }
        ingest.retry_pending();
        assert_eq!(
            ingest.materialized_height(&filter).unwrap(),
            0,
            "nothing on arrival or on the timer"
        );

        assert!(ingest.materialize_through(&filter, 2).unwrap());
        assert_eq!(
            ingest.materialized_height(&filter).unwrap(),
            2,
            "exactly through the frame asked for"
        );
        assert!(ingest.buffered[&filter].contains_key(&3));

        assert!(
            !ingest.materialize_through(&filter, 4).unwrap(),
            "frame 4 is missing"
        );
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 3);
        assert_eq!(
            rx.try_recv().unwrap(),
            (filter.clone(), 4),
            "requested with nothing buffered past it"
        );
        assert!(!ingest.materialize_through(&filter, 4).unwrap());
        assert!(rx.try_recv().is_err(), "one active request per gap");
        // GLOBAL execution is waiting: the request is repeated sooner than an
        // ordinary gap's.
        ingest
            .requested
            .get_mut(&filter)
            .unwrap()
            .get_mut(&4)
            .unwrap()
            .0 = Instant::now() - GLOBAL_WAIT_RETRY_INTERVAL;
        assert!(!ingest.materialize_through(&filter, 4).unwrap());
        assert_eq!(
            rx.try_recv().unwrap(),
            (filter.clone(), 4),
            "retried while GLOBAL waits"
        );

        ingest
            .buffered
            .entry(filter.clone())
            .or_default()
            .insert(4, verified_frame(&filter, 4));
        assert!(ingest.materialize_through(&filter, 4).unwrap());
        assert!(
            ingest.materialize_through(&filter, 1).unwrap(),
            "behind the cursor is already there"
        );
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 4);
    }

    /// A GLOBAL prover proposes a shard's certified header only while it
    /// holds every body executing it needs. A frame whose body never arrives,
    /// at the header or below it, holds the header back and is asked for; a
    /// provably empty header stands in for its own body only. Once the body
    /// arrives the header rides and is sequenced as before.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_shard_header_is_proposed_only_while_its_bodies_are_held() {
        let (ingest, _) = fixture();
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let (prefetch_tx, mut prefetch_rx) = tokio::sync::mpsc::channel(256);
        let mut ingest = ingest.with_prefetch(prefetch_tx).sequenced();
        let buffer = |ingest: &mut ArchiveAppShardIngest, number: u64| {
            ingest
                .buffered
                .entry(filter.clone())
                .or_default()
                .insert(number, verified_frame(&filter, number));
        };
        assert!(!ingest.holds_bodies_through(&filter, 2, false).unwrap());
        assert!(
            prefetch_rx.try_recv().is_err(),
            "a shard this archive holds nothing of is not asked for"
        );
        buffer(&mut ingest, 1);
        buffer(&mut ingest, 3);
        assert!(ingest.holds_bodies_through(&filter, 1, false).unwrap());
        assert!(
            !ingest.holds_bodies_through(&filter, 3, false).unwrap(),
            "frame 2's body was never released"
        );
        assert_eq!(
            prefetch_rx.try_recv().unwrap(),
            (filter.clone(), 2),
            "and is asked for"
        );
        assert!(
            !ingest.holds_bodies_through(&filter, 3, true).unwrap(),
            "an empty header stands in for its own body, not for one below it"
        );
        assert!(!ingest.holds_bodies_through(&filter, 4, false).unwrap());

        buffer(&mut ingest, 2);
        assert!(ingest.holds_bodies_through(&filter, 3, false).unwrap());
        assert!(!ingest.holds_bodies_through(&filter, 4, false).unwrap());
        assert!(
            ingest.holds_bodies_through(&filter, 4, true).unwrap(),
            "a provably empty frame is rebuilt from its header"
        );
        assert!(ingest.materialize_through(&filter, 3).unwrap());
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 3);
        assert!(
            ingest.holds_bodies_through(&filter, 2, false).unwrap(),
            "behind the cursor is already there"
        );
    }

    /// A shard whose head ran more than the frame buffer past its cursor
    /// holds every body it received: those the buffer bound evicted were
    /// stored for serving, and are read back from the store, so the shard's
    /// header can be proposed and executed. Buffered frames alone, such a
    /// shard's headers were held back for good: from 03:20Z on 2026-10-27
    /// about 100 shards sat 270–600 frames behind and GLOBAL frames carried
    /// almost no shard headers.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_shard_further_ahead_than_the_frame_buffer_holds_the_bodies_it_received() {
        use quil_types::store::ClockStore as _;
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let frames = chain(&filter, 201);
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (ingest, _) = fixture_with_clock(Some(clock.clone()));
        let mut ingest = ingest.sequenced();
        ingest.admit(&filter, frames[0].clone(), true);
        assert!(ingest.materialize_through(&filter, 1).unwrap());
        for frame in &frames[1..] {
            ingest.admit(&filter, frame.clone(), true);
        }
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 1);
        assert!(
            (2..=201).all(|number| clock.get_shard_clock_frame(&filter, number, false).is_ok()),
            "every frame received is stored for serving"
        );
        assert!(
            ingest.buffered[&filter].len() < 200,
            "the buffer is full: frames past its bound were evicted"
        );
        assert!(
            ingest.holds_bodies_through(&filter, 201, false).unwrap(),
            "shard latched: all 200 frames above its cursor were received and stored, yet the header 200 \
             frames ahead is held back from every GLOBAL proposal"
        );
        assert!(ingest.materialize_through(&filter, 201).unwrap());
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 201);
    }

    /// A body read back from the store counts as held only when this ingest
    /// admitted it: a frame that never arrived holds every header above it
    /// back and is asked for, though another copy sits in the store, and
    /// nothing past it is executed; a stored copy that is no longer the body
    /// admitted is not executed, and is asked for again.
    #[tokio::test(flavor = "multi_thread")]
    async fn only_bodies_this_archive_admitted_are_read_back_from_the_store() {
        use quil_types::store::ClockStore as _;
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let frames = chain(&filter, 201);
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (ingest, _) = fixture_with_clock(Some(clock.clone()));
        let (prefetch_tx, mut prefetch_rx) = tokio::sync::mpsc::channel(256);
        let mut ingest = ingest.with_prefetch(prefetch_tx).sequenced();
        ingest.admit(&filter, frames[0].clone(), true);
        assert!(ingest.materialize_through(&filter, 1).unwrap());
        // Frame 150 never arrives; a copy that does not link to frame 151 is
        // stored anyway, as a writer this ingest does not check could.
        for frame in &frames[1..] {
            if frame.header.as_ref().unwrap().frame_number != 150 {
                ingest.admit(&filter, frame.clone(), true);
            }
        }
        let mut forged = frames[149].clone();
        forged.header.as_mut().unwrap().output = vec![0xee; 32];
        clock
            .store_shard_clock_frame_for_serving(&[0xee; 32], &forged)
            .unwrap();
        assert!(ingest.holds_bodies_through(&filter, 149, false).unwrap());
        assert!(
            !ingest.holds_bodies_through(&filter, 201, false).unwrap(),
            "frame 150 was never received"
        );
        assert_eq!(
            prefetch_rx.try_recv().unwrap(),
            (filter.clone(), 150),
            "and is asked for, not the frames above it this archive holds"
        );
        assert!(prefetch_rx.try_recv().is_err());
        let held = ingest.held_bodies();
        assert_eq!(held.frames_held(&filter, 201, false), None);
        assert_eq!(held.frames_held(&filter, 149, false), Some(148));
        assert!(!ingest.materialize_through(&filter, 201).unwrap());
        assert_eq!(
            ingest.materialized_height(&filter).unwrap(),
            149,
            "nothing past the missing frame is executed"
        );
        let verifier = ingest.verifier();
        assert_eq!(verifier.stored_above_cursor(&filter, 149), None);
        assert_eq!(
            verifier.stored_above_cursor(&filter, 151),
            Some(frames[150].clone()),
            "a frame stored above the cursor can be admitted again from the store"
        );

        // Frame 180's stored copy is replaced by another body after it was
        // admitted: execution stops below it, and it is asked for again.
        let mut replaced = frames[179].clone();
        replaced.header.as_mut().unwrap().fee_multiplier_vote = 9;
        clock
            .store_shard_clock_frame_for_serving(&[0xdd; 32], &replaced)
            .unwrap();
        ingest.admit(&filter, frames[149].clone(), true);
        assert!(ingest.holds_bodies_through(&filter, 201, false).unwrap());
        assert!(!ingest.materialize_through(&filter, 201).unwrap());
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 179);
        assert!(!ingest.holds_bodies_through(&filter, 201, false).unwrap());
        assert_eq!(prefetch_rx.try_recv().unwrap(), (filter.clone(), 180));

        ingest.admit(&filter, frames[179].clone(), true);
        assert!(ingest.holds_bodies_through(&filter, 201, false).unwrap());
        assert!(ingest.materialize_through(&filter, 201).unwrap());
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 201);
    }

    /// What the ingest holds is read without it, so a proposal does not wait
    /// for execution or intake holding the ingest. A header it has published
    /// nothing for is left to the ingest, which publishes the shard on its
    /// next retry pass.
    #[tokio::test(flavor = "multi_thread")]
    async fn held_bodies_answer_while_the_ingest_is_held() {
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let unknown = vec![0x42; 32];
        let (ingest, _) = fixture();
        let mut ingest = ingest.sequenced();
        for frame in chain(&filter, 3) {
            ingest.admit(&filter, frame, true);
        }
        let held = ingest.held_bodies();
        let ingest = std::sync::Mutex::new(ingest);
        let execution = ingest.lock().unwrap();
        assert_eq!(held.frames_held(&filter, 3, false), Some(3));
        assert_eq!(
            held.frames_held(&filter, 4, true),
            Some(4),
            "a provably empty header stands in for its own body"
        );
        assert_eq!(held.frames_held(&filter, 5, true), None);
        assert_eq!(held.frames_held(&unknown, 1, true), None);
        drop(execution);
        ingest.lock().unwrap().retry_pending();
        assert_eq!(held.frames_held(&unknown, 1, true), Some(1));
        assert_eq!(held.frames_held(&unknown, 1, false), None);
    }

    /// Archives that hold different bodies execute the same GLOBAL frame
    /// alike: what each materializes follows the headers the frame carries,
    /// not what it happens to hold beyond them.
    #[tokio::test(flavor = "multi_thread")]
    async fn archives_holding_different_bodies_sequence_a_global_frame_alike() {
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let (one, _) = fixture();
        let (two, _) = fixture();
        let mut archives = [one.sequenced(), two.sequenced()];
        for (held, archive) in [3, 2].into_iter().zip(archives.iter_mut()) {
            for number in 1..=held {
                archive
                    .buffered
                    .entry(filter.clone())
                    .or_default()
                    .insert(number, verified_frame(&filter, number));
            }
        }
        // The leader held frame 3's header back: the GLOBAL frame carries 2.
        for archive in archives.iter_mut() {
            assert!(archive.materialize_through(&filter, 2).unwrap());
            assert_eq!(archive.materialized_height(&filter).unwrap(), 2);
        }
    }

    /// A GLOBAL frame waiting on a shard asks for every missing frame it needs
    /// at once, up to the window, and each only once per retry interval. Frames
    /// later GLOBAL frames need are asked for behind those, up to the prefetch
    /// depth, only for a shard already held, and are not materialized until a
    /// GLOBAL frame sequences them. A frame only prefetched is asked for again
    /// at once when a GLOBAL frame comes to wait on it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_waiting_global_frame_asks_for_a_window_of_frames_and_prefetches_behind_it() {
        let (ingest, _) = fixture();
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let (prefetch_tx, mut prefetch_rx) = tokio::sync::mpsc::channel(256);
        let mut ingest = ingest
            .with_gap_fetch(tx)
            .with_prefetch(prefetch_tx)
            .sequenced();
        let drain = |rx: &mut tokio::sync::mpsc::Receiver<(Vec<u8>, u64)>| {
            let mut frames = Vec::new();
            while let Ok((address, number)) = rx.try_recv() {
                assert_eq!(address, filter);
                frames.push(number);
            }
            frames
        };

        assert_eq!(
            ingest.prefetch_through(&filter, 50).unwrap(),
            0,
            "no frame of this shard held yet"
        );
        ingest
            .buffered
            .entry(filter.clone())
            .or_default()
            .insert(1, verified_frame(&filter, 1));
        ingest
            .buffered
            .entry(filter.clone())
            .or_default()
            .insert(5, verified_frame(&filter, 5));
        assert!(!ingest.materialize_through(&filter, 200).unwrap());
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 1);
        let window: Vec<u64> = (2..=1 + GAP_WINDOW).filter(|&number| number != 5).collect();
        assert_eq!(
            drain(&mut rx),
            window,
            "the window above the cursor, less what is buffered"
        );
        assert!(!ingest.materialize_through(&filter, 200).unwrap());
        assert!(drain(&mut rx).is_empty(), "each asked once per interval");

        assert_eq!(
            ingest.prefetch_through(&filter, 500).unwrap(),
            (PREFETCH_DEPTH - GAP_WINDOW) as usize
        );
        assert_eq!(
            drain(&mut prefetch_rx),
            (2 + GAP_WINDOW..=1 + PREFETCH_DEPTH).collect::<Vec<_>>(),
            "behind the window, to the prefetch depth"
        );
        assert_eq!(ingest.prefetch_through(&filter, 500).unwrap(), 0);

        for number in 2..=40 {
            ingest
                .buffered
                .entry(filter.clone())
                .or_default()
                .insert(number, verified_frame(&filter, number));
        }
        assert!(ingest.materialize_through(&filter, 20).unwrap());
        assert_eq!(
            ingest.materialized_height(&filter).unwrap(),
            20,
            "prefetched frames wait for their GLOBAL frame"
        );
        assert!(
            ingest.requested[&filter].keys().all(|&number| number > 20),
            "requests at or below the cursor are dropped"
        );
        assert!(!ingest.materialize_through(&filter, 60).unwrap());
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 40);
        assert_eq!(
            drain(&mut rx),
            (41..=60).collect::<Vec<_>>(),
            "prefetched frames a GLOBAL frame waits on"
        );
        assert!(drain(&mut prefetch_rx).is_empty());

        ingest.admit_verified(verified_frame(&filter, 3), true);
        assert!(
            ingest
                .buffered
                .get(&filter)
                .is_none_or(|buffered| !buffered.contains_key(&3)),
            "below the cursor"
        );
        ingest.admit_verified(verified_frame(&filter, 41), true);
        assert!(ingest.buffered[&filter].contains_key(&41));
    }

    /// A frame anchored to a GLOBAL frame this archive has not stored cannot
    /// validate, so it is not asked for again, however long a GLOBAL frame
    /// waits on it, until that GLOBAL frame is stored; then it is asked for
    /// at once.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_frame_anchored_to_a_missing_global_frame_is_asked_for_once_that_frame_is_stored() {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let clock: Arc<dyn quil_types::store::ClockStore> =
            Arc::new(quil_store::RocksClockStore::new(db.inner()));
        let (ingest, _) = fixture_with_clock(Some(clock.clone()));
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let mut ingest = ingest.with_gap_fetch(tx).sequenced();
        let drain = |rx: &mut tokio::sync::mpsc::Receiver<(Vec<u8>, u64)>| {
            let mut frames = Vec::new();
            while let Ok((_, number)) = rx.try_recv() {
                frames.push(number);
            }
            frames
        };
        let all_due = |ingest: &mut ArchiveAppShardIngest| {
            for request in ingest.requested.get_mut(&filter).unwrap().values_mut() {
                request.0 = Instant::now() - GLOBAL_WAIT_RETRY_INTERVAL;
            }
        };
        ingest
            .buffered
            .entry(filter.clone())
            .or_default()
            .insert(1, verified_frame(&filter, 1));
        assert!(!ingest.materialize_through(&filter, 3).unwrap());
        assert_eq!(drain(&mut rx), vec![2, 3]);

        let mut anchored = verified_frame(&filter, 2);
        anchored.header.as_mut().unwrap().global_frame_number = 907_473;
        let verifier = ingest.verifier();
        assert_eq!(verifier.missing_anchor(&anchored), Some(907_473));
        assert_eq!(
            verifier.missing_anchor(&verified_frame(&filter, 2)),
            None,
            "a frame anchored to no GLOBAL frame"
        );
        ingest.await_anchor(&filter, 2, 907_473);
        ingest.await_anchor(&filter, 1, 907_473);
        assert_eq!(
            ingest.awaiting_anchor[&filter]
                .keys()
                .copied()
                .collect::<Vec<_>>(),
            vec![2],
            "not at or below the cursor"
        );

        all_due(&mut ingest);
        assert!(!ingest.materialize_through(&filter, 3).unwrap());
        assert_eq!(
            drain(&mut rx),
            vec![3],
            "the parked frame is not asked for again"
        );

        let txn = clock.new_transaction(false).unwrap();
        clock
            .put_global_clock_frame(
                &quil_types::proto::global::GlobalFrame {
                    header: Some(quil_types::proto::global::GlobalFrameHeader {
                        frame_number: 907_473,
                        ..Default::default()
                    }),
                    requests: Vec::new(),
                },
                txn.as_ref(),
            )
            .unwrap();
        txn.commit().unwrap();
        assert_eq!(verifier.missing_anchor(&anchored), None);
        assert!(!ingest.materialize_through(&filter, 3).unwrap());
        assert_eq!(
            drain(&mut rx),
            vec![2],
            "asked for at once, ahead of its retry interval"
        );
        assert!(ingest.awaiting_anchor.is_empty() && ingest.anchors_noted.is_empty());

        ingest.await_anchor(&filter, 3, 907_480);
        for number in 2..=3 {
            ingest
                .buffered
                .entry(filter.clone())
                .or_default()
                .insert(number, verified_frame(&filter, number));
        }
        assert!(ingest.materialize_through(&filter, 3).unwrap());
        assert!(
            ingest.awaiting_anchor.is_empty() && ingest.anchors_noted.is_empty(),
            "frames at or below the cursor no longer wait"
        );
    }

    /// A frame that waits for GLOBAL execution to reach its anchor is not asked
    /// for again until execution does, or at once when a GLOBAL frame waits
    /// for it: that frame sequences only one anchored at or below the
    /// executed frame, so the parked copy is not it. A copy received again
    /// keeps the first wait. Only shards this archive holds frames of are
    /// parked, within the per-shard and overall caps.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_frame_awaiting_execution_is_asked_for_once_execution_reaches_its_anchor() {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let global = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
            Arc::new(quil_hypergraph::testing::StubProver),
        ));
        global.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        let execute = |number: u64| {
            global
                .commit_with_global_cursor(
                    number,
                    &quil_store::encoding::global_materialized_cursor_key(),
                )
                .unwrap();
        };
        execute(907_000);
        let filter = vec![0x5c; 32];
        let (urgent_tx, mut urgent_rx) = tokio::sync::mpsc::channel(256);
        let (prefetch_tx, mut prefetch_rx) = tokio::sync::mpsc::channel(256);
        let mut ingest = fixture_over(global.clone(), None)
            .with_gap_fetch(urgent_tx)
            .with_prefetch(prefetch_tx)
            .sequenced();
        ingest.last_materialized.insert(filter.clone(), 1);
        // `urgent` asks on the gap fetch, `waits` for a waiting GLOBAL frame.
        let mut ask_for = |ingest: &mut ArchiveAppShardIngest, urgent: bool, waits: bool| {
            for request in ingest
                .requested
                .values_mut()
                .flat_map(|requested| requested.values_mut())
            {
                request.0 = Instant::now() - GAP_RETRY_INTERVAL;
            }
            ingest.request_frames(&filter, 2..=4, urgent, waits, GLOBAL_WAIT_RETRY_INTERVAL);
            let rx = if urgent {
                &mut urgent_rx
            } else {
                &mut prefetch_rx
            };
            let mut frames = Vec::new();
            while let Ok((_, number)) = rx.try_recv() {
                frames.push(number);
            }
            frames
        };
        assert_eq!(ask_for(&mut ingest, false, false), vec![2, 3, 4]);
        assert!(ingest.await_execution(&filter, 3, 907_473, 907_000));
        assert!(
            !ingest.await_execution(&filter, 1, 907_473, 907_000),
            "at or below the cursor"
        );
        assert!(
            !ingest.await_execution(&[0x5d; 32], 3, 907_473, 907_000),
            "a shard this archive holds no frames of"
        );
        assert!(ingest.execution_deferrals.waiting());
        assert_eq!(
            ask_for(&mut ingest, false, false),
            vec![2, 4],
            "frame 3 waits for execution"
        );
        let first = ingest.awaiting_execution[&filter][&3];
        assert!(ingest.await_execution(&filter, 3, 907_480, 907_000));
        assert_eq!(
            ingest.awaiting_execution[&filter][&3], first,
            "a copy received again keeps the first wait"
        );
        execute(907_472);
        assert_eq!(ask_for(&mut ingest, false, false), vec![2, 4]);
        execute(907_473);
        assert_eq!(
            ask_for(&mut ingest, false, false),
            vec![2, 3, 4],
            "asked for again once execution reached its anchor"
        );
        assert!(ingest.awaiting_execution.is_empty());
        assert!(
            !ingest.execution_deferrals.waiting(),
            "the wait's end is logged"
        );

        // A forged copy anchored far ahead cannot hold back a GLOBAL frame
        // that waits for the real one.
        assert!(ingest.await_execution(&filter, 3, 908_000, 907_473));
        assert_eq!(ask_for(&mut ingest, false, false), vec![2, 4]);
        assert_eq!(
            ask_for(&mut ingest, true, false),
            vec![2, 4],
            "a gap alone does not release it"
        );
        assert_eq!(
            ask_for(&mut ingest, true, true),
            vec![2, 3, 4],
            "asked for at once for a waiting GLOBAL frame"
        );
        assert!(ingest.awaiting_execution.is_empty());

        let cap = MAX_AWAITING_EXECUTION_PER_SHARD as u64;
        for number in 2..=cap + 6 {
            ingest.await_execution(&filter, number, 908_000, 907_473);
        }
        let waiting = &ingest.awaiting_execution[&filter];
        assert_eq!(waiting.len(), MAX_AWAITING_EXECUTION_PER_SHARD);
        assert_eq!(
            waiting.keys().next_back().copied(),
            Some(cap + 1),
            "the farthest frames are forgotten"
        );
        let shards = MAX_AWAITING_EXECUTION / MAX_AWAITING_EXECUTION_PER_SHARD;
        for shard in 1..shards {
            let address = vec![shard as u8; 32];
            ingest.last_materialized.insert(address.clone(), 1);
            for number in 2..=cap + 1 {
                assert!(ingest.await_execution(&address, number, 908_000, 907_473));
            }
        }
        let address = vec![0xfe; 32];
        ingest.last_materialized.insert(address.clone(), 1);
        assert!(
            !ingest.await_execution(&address, 2, 908_000, 907_473),
            "the overall cap"
        );
        assert!(!ingest.awaiting_execution.contains_key(&address));
    }

    /// A frame no endpoint serves is materialized from the certified header the
    /// GLOBAL frame carries only when that header proves it had no requests,
    /// and only after the body has been sought for the grace period. A frame
    /// that had requests, or one the GLOBAL frame does not carry, keeps waiting.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_lost_empty_frame_is_materialized_from_its_certified_header() {
        let (ingest, _) = fixture();
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let mut ingest = ingest.with_gap_fetch(tx).sequenced();
        ingest.skip_header_authentication = true;
        ingest
            .buffered
            .entry(filter.clone())
            .or_default()
            .insert(1, verified_frame(&filter, 1));
        let header = |number: u64, requests_root: Vec<u8>| quil_types::proto::global::FrameHeader {
            requests_root,
            ..verified_frame(&filter, number).header.unwrap()
        };
        let vouched = |header: quil_types::proto::global::FrameHeader| {
            HashMap::from([(header.frame_number, header)])
        };

        let empty = vouched(header(2, vec![0; 32]));
        assert!(
            !ingest
                .materialize_through_vouched(&filter, 2, &empty)
                .unwrap(),
            "the body is sought first"
        );
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 1);
        ingest.missing_since.get_mut(&filter).unwrap().1 = Instant::now() - EMPTY_FRAME_BODY_GRACE;
        assert!(
            !ingest.materialize_through(&filter, 2).unwrap(),
            "only a header the GLOBAL frame carries"
        );
        assert!(ingest
            .materialize_through_vouched(&filter, 2, &empty)
            .unwrap());
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 2);
        assert!(ingest.missing_since.is_empty());

        let with_requests = vouched(header(3, vec![7; 32]));
        assert!(!ingest
            .materialize_through_vouched(&filter, 3, &with_requests)
            .unwrap());
        assert!(
            ingest.missing_since.is_empty(),
            "a frame with requests is never rebuilt"
        );
        let legacy_empty = vouched(header(3, vec![0; 64]));
        assert!(!ingest
            .materialize_through_vouched(&filter, 3, &legacy_empty)
            .unwrap());
        ingest.missing_since.get_mut(&filter).unwrap().1 = Instant::now() - EMPTY_FRAME_BODY_GRACE;
        let elsewhere = HashMap::from([(
            3,
            quil_types::proto::global::FrameHeader {
                address: vec![9; 32],
                ..header(3, vec![0; 64])
            },
        )]);
        assert!(
            !ingest
                .materialize_through_vouched(&filter, 3, &elsewhere)
                .unwrap(),
            "another shard's header"
        );
        assert!(ingest
            .materialize_through_vouched(&filter, 3, &legacy_empty)
            .unwrap());
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 3);
    }

    /// A frame materialized from a certified header that carried no storage
    /// attestation owes its body: it is asked for on the prefetch queue,
    /// behind the frames GLOBAL execution waits on, until one arrives. A body
    /// whose output is the one executed is then stored for serving, neither
    /// buffered nor executed again; a body with another output is refused,
    /// and one without its certificate is served only until a certified one
    /// replaces it. A frame its header rebuilds whole (here, one committing to
    /// no attestation) is served at once and owes nothing. Archives used to
    /// drop such a body below their cursor, so every one served a hole at
    /// that frame for good (…d9000a1b40, frame 5577, 2026-10-23).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_frame_executed_from_its_header_has_its_late_body_stored_for_serving() {
        use quil_types::store::ClockStore as _;
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let frames = chain(&filter, 3);
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (ingest, _) = fixture_with_clock(Some(clock.clone()));
        let (gap, mut gaps) = tokio::sync::mpsc::channel(64);
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let mut ingest = ingest.with_gap_fetch(gap).with_prefetch(tx).sequenced();
        ingest.skip_header_authentication = true;
        ingest.empty_body_grace = Duration::ZERO;
        let served = |number| clock.get_shard_clock_frame(&filter, number, false).ok();
        ingest.admit(&filter, frames[0].clone(), true);
        let mut body = frames[1].clone();
        let header = body.header.as_mut().unwrap();
        header.requests_root = vec![0; 32];
        header.storage_attestation_root = vec![1; 32];
        let vouched = HashMap::from([(2, body.header.clone().unwrap())]);
        assert!(
            !ingest
                .materialize_through_vouched(&filter, 2, &vouched)
                .unwrap(),
            "the body is sought first"
        );
        assert!(ingest
            .materialize_through_vouched(&filter, 2, &vouched)
            .unwrap());
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 2);
        assert_eq!(
            served(2),
            None,
            "a frame rebuilt without its attestation is not served"
        );
        while gaps.try_recv().is_ok() {}
        while rx.try_recv().is_ok() {}

        ingest.retry_pending();
        assert_eq!(
            rx.try_recv().ok(),
            Some((filter.clone(), 2)),
            "the body is asked for again"
        );
        assert!(
            gaps.try_recv().is_err(),
            "not ahead of the frames GLOBAL execution waits on"
        );
        ingest.retry_pending();
        assert!(rx.try_recv().is_err(), "at most once per interval");

        let mut impostor = body.clone();
        impostor.header.as_mut().unwrap().output = vec![0xee; 32];
        ingest.admit_verified(impostor, true);
        assert_eq!(served(2), None, "a body with another output is refused");

        ingest.admit_verified(body.clone(), false);
        assert_eq!(
            served(2),
            Some(body.clone()),
            "a copy without its certificate is served meanwhile"
        );
        assert!(
            ingest.owes_body(&filter, 2),
            "a certified one is still asked for"
        );
        let mut certified = body.clone();
        let header = certified.header.as_mut().unwrap();
        header.public_key_signature_bls48581 =
            Some(quil_types::proto::keys::Bls48581AggregateSignature {
                signature: vec![1],
                ..Default::default()
            });
        header.storage_attestation = vec![0xaa; 8];
        ingest.admit_verified(certified.clone(), true);
        certified
            .header
            .as_mut()
            .unwrap()
            .storage_attestation
            .clear();
        assert_eq!(
            served(2),
            Some(certified),
            "replaced, without the header's uncertified attestation field"
        );
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 2);
        assert!(
            ingest
                .buffered
                .get(&filter)
                .is_none_or(|buffered| !buffered.contains_key(&2)),
            "never buffered"
        );
        assert!(ingest.owed_bodies.is_empty());
        ingest.retry_pending();
        assert!(rx.try_recv().is_err(), "a stored body is not asked for");

        let mut whole = frames[2].clone();
        whole.header.as_mut().unwrap().requests_root = vec![0; 32];
        let vouched = HashMap::from([(3, whole.header.clone().unwrap())]);
        assert!(!ingest
            .materialize_through_vouched(&filter, 3, &vouched)
            .unwrap());
        assert!(ingest
            .materialize_through_vouched(&filter, 3, &vouched)
            .unwrap());
        assert_eq!(
            served(3),
            Some(whole),
            "rebuilt whole, it is served at once"
        );
        assert!(ingest.owed_bodies.is_empty());
    }

    /// A frame below the cursor that a peer asks for and this archive does
    /// not serve, a hole left before archives kept asking for such bodies,
    /// is owed once reported, when the stored frame after it names its
    /// output: it is asked for, and its body is stored for serving, final
    /// without a certificate of its own, as that frame authenticates it. A
    /// report of a stored frame, of one above the cursor or of one without a
    /// stored successor is ignored. An owed body asked for its whole
    /// allowance is forgotten.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_missing_frame_a_peer_asks_for_is_recovered_for_serving() {
        use quil_types::store::ClockStore as _;
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let frames = chain(&filter, 4);
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (ingest, _) = fixture_with_clock(Some(clock.clone()));
        let (gap, _gaps) = tokio::sync::mpsc::channel(64);
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let (report, reports) = tokio::sync::mpsc::channel(8);
        let mut ingest = ingest
            .with_gap_fetch(gap)
            .with_prefetch(tx)
            .with_missing_frame_reports(reports)
            .sequenced();
        for index in [0, 2, 3] {
            ingest.admit(&filter, frames[index].clone(), true);
        }
        // Executed through frame 4, frame 2 from its header before this fix.
        ingest.last_materialized.insert(filter.clone(), 4);
        for number in [2, 2, 3, 5] {
            report.try_send((filter.clone(), number)).unwrap();
        }
        report.try_send((vec![9; 32], 2)).unwrap();
        ingest.retry_pending();
        let mut asked = Vec::new();
        while let Ok(request) = rx.try_recv() {
            asked.push(request);
        }
        assert_eq!(asked, vec![(filter.clone(), 2)]);

        ingest.admit_verified(frames[1].clone(), false);
        assert_eq!(
            clock.get_shard_clock_frame(&filter, 2, false).ok(),
            Some(frames[1].clone())
        );
        assert!(ingest.owed_bodies.is_empty());

        assert!(ingest.owe_body(&filter, 7, [7; 32], OwedOrigin::Successor));
        ingest
            .owed_bodies
            .get_mut(&filter)
            .unwrap()
            .get_mut(&7)
            .unwrap()
            .asks = OWED_BODY_ASKS;
        ingest.retry_pending();
        assert!(
            ingest.owed_bodies.is_empty(),
            "asked for its whole allowance"
        );
        assert!(rx.try_recv().is_err());
    }

    /// A certified body with another output than the stored frame after it
    /// names shows that frame opens a session GLOBAL holds no record of: the
    /// hole is no longer owed, and its reports are not looked into again for
    /// a while. Another output for a frame this archive executed is warned
    /// about once. A copy without its own certificate is not verified while
    /// one is served: it could not replace it.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_owed_body_contradicted_or_already_served_is_not_asked_for_again() {
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let frames = chain(&filter, 4);
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (ingest, _) = fixture_with_clock(Some(clock.clone()));
        let (gap, _gaps) = tokio::sync::mpsc::channel(64);
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let (report, reports) = tokio::sync::mpsc::channel(8);
        let mut ingest = ingest
            .with_gap_fetch(gap)
            .with_prefetch(tx)
            .with_missing_frame_reports(reports)
            .sequenced();
        for index in [0, 2, 3] {
            ingest.admit(&filter, frames[index].clone(), true);
        }
        ingest.last_materialized.insert(filter.clone(), 4);
        report.try_send((filter.clone(), 2)).unwrap();
        ingest.retry_pending();
        assert_eq!(rx.try_recv().ok(), Some((filter.clone(), 2)));
        let mut other = frames[1].clone();
        other.header.as_mut().unwrap().output = vec![0xee; 32];
        ingest.admit_verified(other.clone(), true);
        assert!(
            !ingest.owes_body(&filter, 2),
            "the digest owed is no frame's"
        );
        report.try_send((filter.clone(), 2)).unwrap();
        ingest.retry_pending();
        assert!(
            !ingest.owes_body(&filter, 2) && rx.try_recv().is_err(),
            "nor owed again for a while"
        );

        let selector =
            quil_crypto::poseidon::hash_bytes_to_32(&frames[1].header.as_ref().unwrap().output)
                .unwrap();
        assert!(ingest.owe_body(&filter, 2, selector, OwedOrigin::Executed));
        let warns = |ingest: &ArchiveAppShardIngest| ingest.owed_bodies[&filter][&2].mismatch_warns;
        ingest.admit_verified(other.clone(), false);
        assert_eq!(
            warns(&ingest),
            0,
            "another output without a certificate is no defect"
        );
        ingest.admit_verified(other.clone(), true);
        ingest.admit_verified(other, true);
        assert_eq!(
            warns(&ingest),
            1,
            "two certified frames at one height: warned once, and still owed"
        );

        let mut certified = frames[1].clone();
        certified
            .header
            .as_mut()
            .unwrap()
            .public_key_signature_bls48581 =
            Some(quil_types::proto::keys::Bls48581AggregateSignature {
                signature: vec![1],
                ..Default::default()
            });
        assert!(ingest.wants_owed_body(&filter, &frames[1]));
        ingest.admit_verified(frames[1].clone(), false);
        assert!(
            !ingest.wants_owed_body(&filter, &frames[1]),
            "one copy without its certificate is served"
        );
        assert!(ingest.wants_owed_body(&filter, &certified));
    }

    /// While GLOBAL's records cannot be read (a committee-handoff policy is
    /// installed and this archive holds no GLOBAL cursor yet), whether the
    /// frame after a reported hole opens a session cannot be told: the hole
    /// is not owed, nor remembered as not owed, so the next report looks
    /// again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_report_whose_session_cannot_be_told_is_looked_into_again() {
        use quil_types::consensus::{CommitteeHandoffPolicy, LegacyHistory};
        struct RestorePolicy(Option<CommitteeHandoffPolicy>);
        impl Drop for RestorePolicy {
            fn drop(&mut self) {
                quil_types::consensus::set_committee_handoff_policy(self.0);
            }
        }
        let _restore = RestorePolicy(quil_types::consensus::committee_handoff_policy());
        quil_types::consensus::set_committee_handoff_policy(Some(CommitteeHandoffPolicy {
            activation_frame: 0,
            chain_id: [1; 32],
            legacy_history: LegacyHistory::Discard,
            membership_boundary_frame: u64::MAX,
            first_session_boundary_frame: u64::MAX,
        }));
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let frames = chain(&filter, 4);
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (ingest, _) = fixture_with_clock(Some(clock.clone()));
        let (gap, _gaps) = tokio::sync::mpsc::channel(64);
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let (report, reports) = tokio::sync::mpsc::channel(8);
        let mut ingest = ingest
            .with_gap_fetch(gap)
            .with_prefetch(tx)
            .with_missing_frame_reports(reports)
            .sequenced();
        for index in [0, 2, 3] {
            ingest.admit(&filter, frames[index].clone(), true);
        }
        ingest.last_materialized.insert(filter.clone(), 4);
        assert!(
            ingest.opens_session_after(&filter, 2).is_err(),
            "GLOBAL's records cannot be read"
        );
        report.try_send((filter.clone(), 2)).unwrap();
        ingest.retry_pending();
        assert!(
            !ingest.owes_body(&filter, 2) && rx.try_recv().is_err(),
            "not owed"
        );
        assert!(!ingest.not_owed(&filter, 2), "nor remembered as not owed");
    }

    /// A session's first frame names the session's genesis as its parent,
    /// not the frame before it: a hole at a sealed session's last frame is
    /// owed under the digest GLOBAL committed for it, so its genuine body,
    /// final through the seal without a certificate of its own, is served.
    /// Owed under the next frame's parent, it was refused for good.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_hole_at_a_sealed_sessions_last_frame_is_owed_under_the_committed_digest() {
        use quil_types::store::ClockStore as _;
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let frames = chain(&filter, 4);
        let sealed =
            quil_crypto::poseidon::hash_bytes_to_32(&frames[2].header.as_ref().unwrap().output)
                .unwrap();
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (gap, _gaps) = tokio::sync::mpsc::channel(64);
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let (report, reports) = tokio::sync::mpsc::channel(8);
        let mut ingest = fixture_over(sealed_global(&filter, 3, sealed), Some(clock.clone()))
            .with_gap_fetch(gap)
            .with_prefetch(tx)
            .with_missing_frame_reports(reports)
            .sequenced();
        assert!(ingest.opens_session_after(&filter, 3).unwrap());
        assert!(!ingest.opens_session_after(&filter, 2).unwrap());
        let mut opening = frames[3].clone();
        opening.header.as_mut().unwrap().parent_selector = vec![0x77; 32];
        for frame in [&frames[0], &frames[1], &opening] {
            ingest.admit(&filter, frame.clone(), true);
        }
        ingest.last_materialized.insert(filter.clone(), 4);
        report.try_send((filter.clone(), 3)).unwrap();
        ingest.retry_pending();
        assert_eq!(rx.try_recv().ok(), Some((filter.clone(), 3)));
        ingest.admit_verified(frames[2].clone(), false);
        assert_eq!(
            clock.get_shard_clock_frame(&filter, 3, false).ok(),
            Some(frames[2].clone())
        );
        assert!(
            ingest.owed_bodies.is_empty(),
            "final through the seal, it owes nothing more"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failed_commit_keeps_the_frame_for_a_timer_retry() {
        let (mut ingest, store) = fixture();
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 0);
        ingest
            .buffered
            .entry(filter.clone())
            .or_default()
            .insert(1, verified_frame(&filter, 1));
        store.fail_commit_setup(true, false);
        ingest.retry_pending();
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 0);
        assert!(ingest.buffered[&filter].contains_key(&1));
        ingest.last_materialized.clear();
        assert!(
            ingest.materialized_height(&filter).is_err(),
            "a failed cursor read is not genesis"
        );
        store.fail_commit_setup(false, false);
        ingest.retry_pending();
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 1);
    }
}

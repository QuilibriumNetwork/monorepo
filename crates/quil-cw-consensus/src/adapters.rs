//! Quilibrium adapters for commonware `simplex`.
//!
//! simplex's `Engine` is driven by three application traits — `Automaton`
//! (propose/verify a payload), `Relay` (broadcast the block bytes behind a
//! payload digest), and `Reporter` (observe notarization/finalization). This
//! module implements those three commonware traits over three **narrow,
//! Quilibrium-facing seam traits** so the engine-facing glue is fixed here and
//! the real state wiring (leader_provider / frame validation / materialize)
//! lives behind the seams (implemented in quil-engine):
//!
//! - [`GlobalProposer`] ← `Automaton`: build the next global frame on a parent
//! (propose) and validate a proposed frame (verify).
//! - [`FrameSink`] ← `Relay`: ship the `GlobalFrame` bytes to peers.
//! - [`FrameFinalizer`] ← `Reporter`: commit/materialize on finalize, write a
//! candidate on notarize, report equivocation.
//!
//! The consensus digest `D` is the frame identity (`Sha256` here; the real node
//! uses `Poseidon(output)[..32]` — a 32-byte hash either way). Block bytes
//! travel out-of-band via [`FrameSink`]; simplex only gossips digests + certs.
//! A shared [`BlockStore`] maps digest → frame bytes across the three adapters.

use std::collections::HashMap;
use std::sync::Arc;

use commonware_actor::Feedback;
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_runtime::{Clock, Spawner, Supervisor as _};
use commonware_utils::channel::oneshot;
use commonware_utils::sync::Mutex;

use crate::falcon_base::FalconPublicKey;
use crate::falcon_simplex::SimplexFalconScheme;

use commonware_consensus::simplex::types::{Activity, Context};
use commonware_consensus::simplex::Plan;
use commonware_consensus::{
    Automaton, CertifiableAutomaton, Epochable as _, Relay, Reporter, Viewable as _,
};

/// Digest type consensus agrees on (the frame identity).
pub type Digest = Sha256Digest;
/// simplex activity for the Falcon scheme.
pub type FalconActivity = Activity<SimplexFalconScheme, Digest>;

/// The coordinates Simplex selected for this proposal. Application frame
/// numbers are independent of views: nullified rounds can leave gaps, and a
/// committee transition starts another epoch. A terminal handoff must bind
/// these exact coordinates, not infer the parent view from a local clock head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalContext {
    pub epoch: u64,
    pub view: u64,
    pub parent_view: u64,
    pub parent: Digest,
}

impl From<Context<Digest, FalconPublicKey>> for ProposalContext {
    fn from(context: Context<Digest, FalconPublicKey>) -> Self {
        Self {
            epoch: context.epoch().get(),
            view: context.view().get(),
            parent_view: context.parent.0.get(),
            parent: context.parent.1,
        }
    }
}

/// Re-exported so seam implementors (quil-engine) needn't depend on commonware-p2p.
pub use commonware_p2p::Recipients;

/// Wrap a 32-byte frame identity (`Poseidon(output)[..32]`) as the consensus
/// digest. simplex treats the digest opaquely, so any 32-byte identity is valid.
pub fn digest_from_identity(identity: [u8; 32]) -> Digest {
    Sha256Digest(identity)
}

/// The 32 raw identity bytes behind a consensus digest.
pub fn digest_to_identity(digest: &Digest) -> [u8; 32] {
    digest.0
}

/// Shared digest → frame-bytes store. `Automaton::propose` seals the frame it
/// built; successful `verify` seals the exact peer bytes the application
/// accepted. Frames arriving from peers remain replaceable candidates until
/// application validation succeeds — so a re-proposed/unverified block at a
/// finalized digest can no longer overwrite the finalized frame (the
/// "preserve finalized app shard frames" fix).
#[derive(Clone, Default)]
pub struct BlockStore {
    inner: Arc<Mutex<HashMap<Digest, StoredBlock>>>,
}

#[derive(Clone)]
struct StoredBlock {
    bytes: Vec<u8>,
    verified: bool,
}

impl BlockStore {
    pub fn new() -> Self {
        Self::default()
    }
    /// Insert an unverified block candidate. Candidates may be replaced until
    /// one exact byte sequence passes application validation and is sealed.
    /// Once sealed, peer ingress cannot substitute different bytes for the
    /// consensus digest that was actually verified.
    pub fn put(&self, digest: Digest, bytes: Vec<u8>) {
        let mut inner = self.inner.lock();
        match inner.get_mut(&digest) {
            Some(stored) if stored.verified => {}
            Some(stored) => stored.bytes = bytes,
            None => {
                inner.insert(
                    digest,
                    StoredBlock {
                        bytes,
                        verified: false,
                    },
                );
            }
        }
    }
    pub fn get(&self, digest: &Digest) -> Option<Vec<u8>> {
        self.inner.lock().get(digest).map(|stored| stored.bytes.clone())
    }

    /// Refuse oversized recovery input before copying peer-controlled bytes.
    pub fn get_bounded(&self, digest: &Digest, max_bytes: usize) -> Option<Vec<u8>> {
        self.inner.lock().get(digest)
            .filter(|stored| stored.bytes.len() <= max_bytes)
            .map(|stored| stored.bytes.clone())
    }

    /// Seal the exact bytes that passed application validation (or were built
    /// locally). Idempotent: once a digest is sealed, a later `seal`/`put`
    /// cannot substitute different bytes for it.
    pub fn seal(&self, digest: Digest, bytes: Vec<u8>) {
        let mut inner = self.inner.lock();
        if inner.get(&digest).map(|stored| stored.verified).unwrap_or(false) {
            return;
        }
        inner.insert(
            digest,
            StoredBlock {
                bytes,
                verified: true,
            },
        );
    }

    /// Return the current bytes together with whether this node's application
    /// validator accepted and sealed this exact value. A replica can learn a
    /// finalization certificate before locally verifying its block, so the
    /// reporter must preserve that distinction for the finalizer.
    pub fn get_with_verification(&self, digest: &Digest) -> Option<(Vec<u8>, bool)> {
        self.inner
            .lock()
            .get(digest)
            .map(|stored| (stored.bytes.clone(), stored.verified))
    }
}

// ---------------------------------------------------------------------------
// Seam traits (Quilibrium-facing; impl'd in quil-engine against real state).
// ---------------------------------------------------------------------------

/// Builds and validates global frames — the `Automaton` behind consensus.
///
/// simplex calls `propose` ONLY on the round leader, so no leadership check is
/// needed here. Both methods are called off the engine's critical path (the
/// adapter spawns them), so a blocking VDF prove in `propose` is fine.
/// Longest a pacing leader holds its turn before giving the view up.
const PROPOSE_PATIENCE: std::time::Duration = std::time::Duration::from_secs(20);

/// Longest a voter keeps asking to check a proposal it could not check yet.
const VERIFY_PATIENCE: std::time::Duration = std::time::Duration::from_secs(20);

pub trait GlobalProposer: Send + Sync + 'static {
    /// Build the next frame on parent `parent_digest` for consensus `view`.
    /// Returns `(frame_identity_digest, canonical_frame_bytes)`, or `None` if
    /// this node cannot build (e.g. it lacks the parent) — simplex then times
    /// out and nullifies the view (mirrors the existing leader-can't-build SKIP).
    fn propose(&self, view: u64, parent_digest: Digest) -> Option<(Digest, Vec<u8>)>;

    /// Validate a proposed frame `digest` for `view` and the consensus-selected
    /// `parent_digest`. The frame's own parent must match this digest; a valid
    /// self-contained frame is not enough to authorize another ancestry.
    /// `bytes` is the frame body
    /// if already delivered (via `FrameSink`), else `None` (not yet arrived →
    /// return `false` so the view nullifies rather than votes blind).
    fn verify(&self, view: u64, parent_digest: Digest, digest: Digest, bytes: Option<Vec<u8>>) -> bool;

    /// After `propose` declined: how long until asking again for the same view
    /// can succeed, or `None` to give the view up. A leader that is only pacing
    /// itself must hold its turn; dropping it nullifies the view at network
    /// speed and the committee burns hundreds of views per frame.
    fn propose_retry(&self) -> Option<std::time::Duration> {
        None
    }

    /// How long this node paces itself before it produces the proposal for
    /// `context`. The adapter waits it out before calling
    /// [`Self::propose_with_context`], so nothing the proposal holds (an
    /// execution lease, a runtime thread) is held through the wait.
    fn proposal_pacing(&self, _context: ProposalContext) -> Option<std::time::Duration> {
        None
    }

    /// Build with all consensus coordinates. Ordinary frame implementations
    /// can use the default; session-aware handoff implementations must override
    /// it to validate the epoch and selected parent view before producing bytes.
    fn propose_with_context(&self, context: ProposalContext) -> Option<(Digest, Vec<u8>)> {
        self.propose(context.view, context.parent)
    }

    /// Validate with the same complete context as proposal production.
    fn verify_with_context(
        &self,
        context: ProposalContext,
        digest: Digest,
        bytes: Option<Vec<u8>>,
    ) -> bool {
        self.verify(context.view, context.parent, digest, bytes)
    }

    /// [`Self::verify_with_context`], or `Err(delay)` when this node could not
    /// check the proposal yet for a reason of its own that clears (its execution
    /// was busy). The adapter asks again after `delay` while the view lasts. Each
    /// attempt is a complete check, so deferring never accepts more.
    fn verify_or_defer(
        &self,
        context: ProposalContext,
        digest: Digest,
        bytes: Option<Vec<u8>>,
    ) -> Result<bool, std::time::Duration> {
        Ok(self.verify_with_context(context, digest, bytes))
    }
}

/// Ships frame bytes to peers — the `Relay` behind consensus. In the node this
/// wraps the `:8340` fan-out (`publish_frame`).
pub trait FrameSink: Send + Sync + 'static {
    /// Broadcast the frame `bytes` (identified by `digest`) to `recipients`
    /// (`All` on initial propose; a subset when forwarding to lagging peers).
    fn broadcast(&self, digest: Digest, bytes: Vec<u8>, recipients: Recipients<FalconPublicKey>);
}

/// Observes consensus outcomes — the `Reporter` behind consensus. In the node
/// this drives the finalized-frame commit/materialize + candidate write.
pub trait FrameFinalizer: Send + Sync + 'static {
    /// A frame was NOTARIZED (2-phase candidate). Write it as a candidate so a
    /// later `propose` can build on this uncommitted tip.
    fn on_notarized(&self, view: u64, digest: Digest, bytes: Option<Vec<u8>>);
    /// A frame was FINALIZED (committed). Materialize + persist + rewards/lifecycle.
    /// `cert` is the serialized simplex finalization certificate (proposal +
    /// Falcon quorum cert) — carried so the finalizer can attach it to a coverage
    /// bundle for off-chain / global-level verification (reward
    /// attribution). `None` if the reporter couldn't recover it.
    /// `locally_verified` is true only when the reported bytes are the immutable
    /// value this node's application verifier accepted (or built locally) — a
    /// replica can learn a finalization certificate before locally verifying its
    /// block, and the finalizer must preserve that distinction.
    fn on_finalized(
        &self,
        view: u64,
        digest: Digest,
        bytes: Option<Vec<u8>>,
        cert: Option<Vec<u8>>,
        locally_verified: bool,
    );
    /// A proposer equivocated (double-propose/finalize). Drives a ProverKick.
    fn on_equivocation(&self, _view: u64) {}
}

// ---------------------------------------------------------------------------
// Automaton adapter
// ---------------------------------------------------------------------------

/// `Automaton` + `CertifiableAutomaton` over a [`GlobalProposer`]. Holds a
/// runtime context `E` to spawn propose/verify off the engine's task so a
/// blocking VDF prove never stalls consensus.
///
/// `E` need not be `Clone` (runtime contexts aren't): both the `Clone` impl and
/// per-call spawning vend a fresh child via `Supervisor::child`.
pub struct FalconAutomaton<E: Spawner + Clock, Pr: GlobalProposer> {
    context: E,
    proposer: Arc<Pr>,
    store: BlockStore,
}

impl<E: Spawner + Clock, Pr: GlobalProposer> Clone for FalconAutomaton<E, Pr> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.child("automaton"),
            proposer: self.proposer.clone(),
            store: self.store.clone(),
        }
    }
}

impl<E: Spawner + Clock, Pr: GlobalProposer> FalconAutomaton<E, Pr> {
    pub fn new(context: E, proposer: Arc<Pr>, store: BlockStore) -> Self {
        Self { context, proposer, store }
    }
}

impl<E: Spawner + Clock + Send + 'static, Pr: GlobalProposer> Automaton
    for FalconAutomaton<E, Pr>
{
    type Digest = Digest;
    type Context = Context<Digest, FalconPublicKey>;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (tx, rx) = oneshot::channel();
        let proposal_context = ProposalContext::from(context);
        let proposer = self.proposer.clone();
        let store = self.store.clone();
        self.context.child("propose").spawn(move |ctx| async move {
            if let Some(pacing) = proposer.proposal_pacing(proposal_context) {
                ctx.sleep(pacing).await;
                if tx.is_closed() {
                    return;
                }
            }
            // Bounded under `leader_timeout` (30s); simplex drops the receiver
            // when the view ends.
            let mut waited = std::time::Duration::ZERO;
            loop {
                if let Some((digest, bytes)) = proposer.propose_with_context(proposal_context) {
                    // Locally-produced bytes came directly from the application
                    // proposer and are the value Simplex is about to certify — seal
                    // them so peer ingress can't substitute a different body later.
                    store.seal(digest, bytes);
                    let _ = tx.send(digest);
                    return;
                }
                match proposer.propose_retry() {
                    Some(delay) if waited < PROPOSE_PATIENCE && !tx.is_closed() => {
                        ctx.sleep(delay).await;
                        waited += delay;
                    }
                    // drop tx → receiver cancelled → simplex nullifies the view.
                    _ => return,
                }
            }
        });
        rx
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        let proposal_context = ProposalContext::from(context);
        let proposer = self.proposer.clone();
        let store = self.store.clone();
        self.context.child("verify").spawn(move |ctx| async move {
            // The block bytes travel out-of-band (FrameSink → :8340) and may
            // arrive slightly after the vote-request digest. Poll the store a
            // bounded number of times before giving up, so an ordinary delivery
            // reorder nullifies a view only when the block is genuinely missing
            // (which the resolver/catch-up then backfills).
            let mut bytes = store.get(&payload);
            let mut waited = 0u32;
            // Up to ~6s: the block travels over :8340 out-of-band and, under CPU
            // load (co-located localnet, mTLS handshake + decode), can lag the
            // vote-request by seconds. Bounded well under `leader_timeout` (30s).
            while bytes.is_none() && waited < 60 {
                ctx.sleep(std::time::Duration::from_millis(100)).await;
                bytes = store.get(&payload);
                waited += 1;
            }
            let verified_bytes = bytes.clone();
            // A voter busy with its own execution (for example publishing the
            // previous frame) answers once it is free, not with a nullify.
            let mut deferred = std::time::Duration::ZERO;
            let ok = loop {
                match proposer.verify_or_defer(proposal_context, payload, bytes.clone()) {
                    Ok(ok) => break ok,
                    Err(delay) if deferred < VERIFY_PATIENCE && !tx.is_closed() => {
                        ctx.sleep(delay).await;
                        deferred += delay;
                    }
                    Err(_) => break false,
                }
            };
            // On success, seal the EXACT bytes the application validated, so a
            // racing peer candidate at the same digest can't replace them.
            if ok {
                if let Some(bytes) = verified_bytes {
                    store.seal(payload, bytes);
                }
            }
            let _ = tx.send(ok);
        });
        rx
    }
}

impl<E: Spawner + Clock + Send + 'static, Pr: GlobalProposer> CertifiableAutomaton
    for FalconAutomaton<E, Pr>
{
    // Default certify() = always-true is correct: our verify already gates the
    // frame, and there is no separate reconstruction step.
}

// ---------------------------------------------------------------------------
// Relay adapter
// ---------------------------------------------------------------------------

/// `Relay` over a [`FrameSink`]; reads the frame bytes from the [`BlockStore`]
/// and ships them per the simplex `Plan`.
pub struct FalconRelay<Sk: FrameSink> {
    sink: Arc<Sk>,
    store: BlockStore,
}

impl<Sk: FrameSink> Clone for FalconRelay<Sk> {
    fn clone(&self) -> Self {
        Self { sink: self.sink.clone(), store: self.store.clone() }
    }
}

impl<Sk: FrameSink> FalconRelay<Sk> {
    pub fn new(sink: Arc<Sk>, store: BlockStore) -> Self {
        Self { sink, store }
    }
}

impl<Sk: FrameSink> Relay for FalconRelay<Sk> {
    type Digest = Digest;
    type PublicKey = FalconPublicKey;
    type Plan = Plan<FalconPublicKey>;

    fn broadcast(&mut self, payload: Self::Digest, plan: Self::Plan) -> Feedback {
        let Some(bytes) = self.store.get(&payload) else {
            // We don't hold the block (shouldn't happen for our own proposal);
            // nothing to ship.
            return Feedback::Closed;
        };
        let recipients = match plan {
            Plan::Propose { .. } => Recipients::All,
            Plan::Forward { recipients, .. } => recipients,
        };
        self.sink.broadcast(payload, bytes, recipients);
        Feedback::Ok
    }
}

// ---------------------------------------------------------------------------
// Reporter adapter
// ---------------------------------------------------------------------------

/// Views over which [`Liveness`] counts distinct voters.
const LIVENESS_VIEWS: u64 = 16;

/// What one consensus instance has seen, for operators: how far its views
/// advanced, which of them ended in a certificate, and how many members voted
/// recently. A session that starts but never produces a frame shows here
/// whether views move, and whether enough members vote to certify any.
#[derive(Default)]
pub struct Liveness {
    inner: std::sync::Mutex<LivenessState>,
}

#[derive(Default)]
struct LivenessState {
    snapshot: LivenessSnapshot,
    /// Signers seen per recent view.
    voters: std::collections::BTreeMap<u64, std::collections::BTreeSet<u32>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LivenessSnapshot {
    /// Highest view any vote or certificate named.
    pub view: u64,
    pub notarized: u64,
    pub nullified: u64,
    pub finalized: u64,
    /// Distinct members that voted in the last [`LIVENESS_VIEWS`] views.
    pub voters: usize,
    pub notarize_votes: u64,
    pub nullify_votes: u64,
    pub finalize_votes: u64,
}

impl Liveness {
    fn vote(&self, view: u64, signer: u32, count: impl FnOnce(&mut LivenessSnapshot)) {
        let Ok(mut state) = self.inner.lock() else { return };
        count(&mut state.snapshot);
        state.snapshot.view = state.snapshot.view.max(view);
        let floor = state.snapshot.view.saturating_sub(LIVENESS_VIEWS);
        if view > floor {
            state.voters.entry(view).or_default().insert(signer);
        }
        state.voters.retain(|recent, _| *recent > floor);
    }

    fn certificate(&self, view: u64, record: impl FnOnce(&mut LivenessSnapshot)) {
        let Ok(mut state) = self.inner.lock() else { return };
        record(&mut state.snapshot);
        state.snapshot.view = state.snapshot.view.max(view);
    }

    pub fn snapshot(&self) -> LivenessSnapshot {
        let Ok(state) = self.inner.lock() else { return LivenessSnapshot::default() };
        let mut snapshot = state.snapshot;
        snapshot.voters = state.voters.values().flatten().collect::<std::collections::BTreeSet<_>>().len();
        snapshot
    }

    fn observe(&self, activity: &FalconActivity) {
        use commonware_consensus::simplex::types::Attributable as _;
        use commonware_consensus::Viewable as _;
        let signer = |participant: commonware_utils::Participant| usize::from(participant) as u32;
        match activity {
            Activity::Notarize(vote) => self.vote(vote.view().get(), signer(vote.signer()), |s| s.notarize_votes += 1),
            Activity::Nullify(vote) => self.vote(vote.view().get(), signer(vote.signer()), |s| s.nullify_votes += 1),
            Activity::Finalize(vote) => self.vote(vote.view().get(), signer(vote.signer()), |s| s.finalize_votes += 1),
            Activity::Notarization(cert) => {
                let view = cert.view().get();
                self.certificate(view, |s| s.notarized = s.notarized.max(view));
            }
            Activity::Nullification(cert) => {
                let view = cert.view().get();
                self.certificate(view, |s| s.nullified = s.nullified.max(view));
            }
            Activity::Finalization(cert) => {
                let view = cert.view().get();
                self.certificate(view, |s| s.finalized = s.finalized.max(view));
            }
            _ => {}
        }
    }
}

/// `Reporter` over a [`FrameFinalizer`]; maps simplex activities to the
/// candidate-write / commit / equivocation hooks.
pub struct FalconReporter<Fin: FrameFinalizer> {
    finalizer: Arc<Fin>,
    store: BlockStore,
    liveness: Option<Arc<Liveness>>,
}

impl<Fin: FrameFinalizer> Clone for FalconReporter<Fin> {
    fn clone(&self) -> Self {
        Self { finalizer: self.finalizer.clone(), store: self.store.clone(), liveness: self.liveness.clone() }
    }
}

impl<Fin: FrameFinalizer> FalconReporter<Fin> {
    pub fn new(finalizer: Arc<Fin>, store: BlockStore) -> Self {
        Self { finalizer, store, liveness: None }
    }

    /// Also record every vote and certificate in `liveness`.
    pub fn with_liveness(mut self, liveness: Option<Arc<Liveness>>) -> Self {
        self.liveness = liveness;
        self
    }
}

impl<Fin: FrameFinalizer> Reporter for FalconReporter<Fin> {
    type Activity = FalconActivity;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        if let Some(liveness) = self.liveness.as_ref() {
            liveness.observe(&activity);
        }
        match activity {
            Activity::Notarization(n) => {
                let digest = n.proposal.payload;
                let view: u64 = n.proposal.round.view().get();
                let bytes = self.store.get(&digest);
                self.finalizer.on_notarized(view, digest, bytes);
            }
            Activity::Finalization(f) => {
                let digest = f.proposal.payload;
                let view: u64 = f.proposal.round.view().get();
                // Distinguish "we sealed the exact validated/built bytes" from
                // "we only learned the finalization cert" (bytes present but
                // never locally verified) — the finalizer needs it to decide
                // whether to trust the local bytes or re-fetch.
                let (bytes, locally_verified) = self
                    .store
                    .get_with_verification(&digest)
                    .map_or((None, false), |(bytes, verified)| (Some(bytes), verified));
                // Serialize the finalization certificate (proposal + Falcon
                // quorum cert) so the finalizer can carry it into a coverage
                // bundle for global-level reward verification.
                let cert = Some(crate::app_cert::encode_finalization(&f));
                self.finalizer
                    .on_finalized(view, digest, bytes, cert, locally_verified);
            }
            Activity::ConflictingNotarize(_)
            | Activity::ConflictingFinalize(_)
            | Activity::NullifyFinalize(_) => {
                self.finalizer.on_equivocation(0);
            }
            // Individual votes / nullifies / certifications are not surfaced to
            // the Quilibrium layer (simplex handles quorum internally).
            _ => {}
        }
        Feedback::Ok
    }
}

#[cfg(test)]
mod block_store_seal_tests {
    use super::*;

    fn digest(byte: u8) -> Digest {
        digest_from_identity([byte; 32])
    }

    #[test]
    fn unverified_candidates_are_distinguished_from_verified_blocks() {
        let store = BlockStore::new();
        let block = digest(1);
        store.put(block, b"candidate".to_vec());
        assert_eq!(store.get(&block), Some(b"candidate".to_vec()));
        assert_eq!(
            store.get_with_verification(&block),
            Some((b"candidate".to_vec(), false))
        );
    }

    #[test]
    fn verified_bytes_cannot_be_substituted() {
        let store = BlockStore::new();
        let block = digest(2);
        let verified = b"committee-validated bytes".to_vec();
        store.put(block, verified.clone());
        store.seal(block, verified.clone());
        // A later peer `put` at the same digest must NOT overwrite the sealed value.
        store.put(block, b"same digest, substituted body".to_vec());
        assert_eq!(store.get(&block), Some(verified.clone()));
        assert_eq!(store.get_with_verification(&block), Some((verified, true)));
    }

    #[test]
    fn sealing_uses_the_bytes_that_were_validated() {
        let store = BlockStore::new();
        let block = digest(3);
        let validated = b"validated candidate".to_vec();
        store.put(block, validated.clone());
        // Model peer ingress racing between the Automaton's read and the end of
        // application validation: `seal` freezes the clone that was actually
        // checked, not whichever candidate is currently stored.
        store.put(block, b"racing replacement".to_vec());
        store.seal(block, validated.clone());
        assert_eq!(store.get_with_verification(&block), Some((validated, true)));
    }
}

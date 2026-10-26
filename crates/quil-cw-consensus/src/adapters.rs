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
use commonware_runtime::{Clock, Spawner};
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
    /// The view's leader as a prover address (Poseidon of its Falcon key);
    /// `None` for a context not made by Simplex.
    pub leader: Option<[u8; 32]>,
}

impl From<Context<Digest, FalconPublicKey>> for ProposalContext {
    fn from(context: Context<Digest, FalconPublicKey>) -> Self {
        Self {
            epoch: context.epoch().get(),
            view: context.view().get(),
            parent_view: context.parent.0.get(),
            parent: context.parent.1,
            leader: prover_address(&context.leader),
        }
    }
}

/// A committee member's prover address, `poseidon(public key)`, remembered:
/// every proposal and vote asks for its leader's.
fn prover_address(key: &FalconPublicKey) -> Option<[u8; 32]> {
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};
    static REMEMBERED: LazyLock<Mutex<HashMap<FalconPublicKey, [u8; 32]>>> = LazyLock::new(Default::default);
    if let Some(address) = REMEMBERED.lock().ok().and_then(|cache| cache.get(key).copied()) {
        return Some(address);
    }
    let address = quil_crypto::poseidon::hash_bytes_to_32(key.as_ref()).ok()?;
    if let Ok(mut cache) = REMEMBERED.lock() {
        if cache.len() >= 4096 {
            cache.clear();
        }
        cache.insert(key.clone(), address);
    }
    Some(address)
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

/// A [`BlockStore`] handle that does not keep the blocks alive: once the
/// host that owns the store stops, its bodies are freed.
#[derive(Clone)]
pub struct WeakBlockStore {
    inner: std::sync::Weak<Mutex<HashMap<Digest, StoredBlock>>>,
}

impl WeakBlockStore {
    pub fn upgrade(&self) -> Option<BlockStore> {
        self.inner.upgrade().map(|inner| BlockStore { inner })
    }
}

#[derive(Clone)]
struct StoredBlock {
    bytes: Vec<u8>,
    verified: bool,
}

impl BlockStore {
    pub fn downgrade(&self) -> WeakBlockStore {
        WeakBlockStore { inner: Arc::downgrade(&self.inner) }
    }

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

    /// How long to wait before checking the proposal `bytes`, when something
    /// it needs is on its way to this node (its GLOBAL anchor, just ahead of
    /// this node's latest); `None` checks it now. Wrapping proposers forward
    /// it to the one that knows.
    fn verify_delay(&self, _context: ProposalContext, _bytes: &[u8]) -> Option<std::time::Duration> {
        None
    }

    /// [`Self::verify_with_context`], or `Err(delay)` when this node could not
    /// check the proposal yet for a reason of its own that clears (its execution
    /// was busy, see also [`Self::verify_delay`]). The adapter asks again after
    /// `delay` while the view lasts. Each attempt is a complete check, so
    /// deferring never accepts more.
    fn verify_or_defer(
        &self,
        context: ProposalContext,
        digest: Digest,
        bytes: Option<Vec<u8>>,
    ) -> Result<bool, std::time::Duration> {
        if let Some(delay) = bytes.as_deref().and_then(|bytes| self.verify_delay(context, bytes)) {
            return Err(delay);
        }
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
    liveness: Option<Arc<Liveness>>,
}

impl<E: Spawner + Clock, Pr: GlobalProposer> Clone for FalconAutomaton<E, Pr> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.child("automaton"),
            proposer: self.proposer.clone(),
            store: self.store.clone(),
            liveness: self.liveness.clone(),
        }
    }
}

impl<E: Spawner + Clock, Pr: GlobalProposer> FalconAutomaton<E, Pr> {
    pub fn new(context: E, proposer: Arc<Pr>, store: BlockStore) -> Self {
        Self { context, proposer, store, liveness: None }
    }

    /// Also count, in `liveness`, how each proposal and vote of this member
    /// ended, under the reason the proposer noted ([`Liveness::note`]).
    pub fn with_liveness(mut self, liveness: Option<Arc<Liveness>>) -> Self {
        self.liveness = liveness;
        self
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
        let liveness = self.liveness.clone();
        let settle = move |proposed: bool| if let Some(liveness) = liveness.as_ref() {
            liveness.settle(Step::Propose, proposal_context.view, proposed);
        };
        self.context.child("propose").spawn(move |ctx| async move {
            if let Some(pacing) = proposer.proposal_pacing(proposal_context) {
                ctx.sleep(pacing).await;
                if tx.is_closed() {
                    settle(false);
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
                    settle(true);
                    return;
                }
                match proposer.propose_retry() {
                    Some(delay) if waited < PROPOSE_PATIENCE && !tx.is_closed() => {
                        ctx.sleep(delay).await;
                        waited += delay;
                    }
                    // drop tx → receiver cancelled → simplex nullifies the view.
                    _ => {
                        settle(false);
                        return;
                    }
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
        let liveness = self.liveness.clone();
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
            if let Some(liveness) = liveness.as_ref() {
                liveness.settle(Step::Verify, proposal_context.view, ok);
            }
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

/// Views over which [`Liveness`] counts distinct voters and keeps tallies.
const LIVENESS_VIEWS: u64 = 16;

/// Views a noted reason waits for its step to end before it is dropped.
const NOTE_VIEWS: u64 = 64;

/// Distinct peers [`Liveness`] remembers having blocked.
const BLOCKED_PEERS: usize = 256;

/// What one consensus instance has seen, for operators: how far its views
/// advanced, which of them ended in a certificate, how many members voted
/// recently and for what, and why this member's own turns and votes went as
/// they did. A session that starts but never produces a frame shows here
/// whether views move, whether enough members vote for any one proposal, and
/// why this member declined to propose or voted against a proposal.
#[derive(Default)]
pub struct Liveness {
    inner: std::sync::Mutex<LivenessState>,
    /// The host's block store, for the bodies behind the notarize votes
    /// ([`Liveness::notarized`]); bound by the host's reporter, and not kept
    /// alive by it.
    blocks: std::sync::OnceLock<WeakBlockStore>,
    /// Set once [`Liveness::notarized`] has warned that no store is bound.
    unbound_warned: std::sync::atomic::AtomicBool,
    /// Whether notarize votes keep their signatures ([`Liveness::keep_votes`]).
    keep_votes: std::sync::atomic::AtomicBool,
}

#[derive(Default)]
struct LivenessState {
    snapshot: LivenessSnapshot,
    /// Votes received per recent view.
    views: std::collections::BTreeMap<u64, ViewVotes>,
    /// Why a step that has not ended yet failed; the latest note wins.
    notes: std::collections::BTreeMap<(Step, u64), (&'static str, String)>,
    decisions: Decisions,
    blocked: std::collections::BTreeSet<FalconPublicKey>,
}

#[derive(Default)]
struct ViewVotes {
    /// Signers per proposal digest.
    notarize: std::collections::BTreeMap<[u8; 32], std::collections::BTreeSet<u32>>,
    nullify: std::collections::BTreeSet<u32>,
    finalize: std::collections::BTreeSet<u32>,
    /// The notarize votes themselves, per proposal (parent view, digest).
    evidence: std::collections::BTreeMap<(u64, [u8; 32]), Evidence>,
}

struct Evidence {
    epoch: u64,
    /// Signature bytes per signer; a signer's first vote stays.
    signatures: std::collections::BTreeMap<u32, Vec<u8>>,
}

/// A proposal of a recent view with the notarize votes received for it, and
/// the body this node built or verified ([`Liveness::notarized`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NotarizedProposal {
    pub epoch: u64,
    pub view: u64,
    pub parent: u64,
    pub payload: [u8; 32],
    /// Signer index and signature bytes, in ascending signer order. Not
    /// checked: consensus verifies vote signatures only in batches, once a
    /// certificate could form.
    pub votes: Vec<(u32, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// One notarize vote of a recent view ([`Liveness::notarize_votes`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NotarizeKey {
    /// The round epoch (a session's generation).
    pub epoch: u64,
    pub view: u64,
    pub parent: u64,
    pub payload: [u8; 32],
    pub signer: u32,
}

impl ViewVotes {
    fn tally(&self, view: u64) -> ViewTally {
        ViewTally {
            view,
            notarize: self.notarize.values().map(|signers| signers.len()).max().unwrap_or(0),
            proposals: self.notarize.len(),
            nullify: self.nullify.len(),
            finalize: self.finalize.len(),
        }
    }

    fn signers(&self) -> impl Iterator<Item = u32> + '_ {
        self.notarize.values().flatten().chain(&self.nullify).chain(&self.finalize).copied()
    }
}

/// Votes received for one view. Each came from its own signer (consensus
/// drops any other), but its signature is checked only later, in a batch,
/// once a certificate could form; a bad one blocks its peer ([`Liveness`]
/// counts those).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ViewTally {
    pub view: u64,
    /// The most signers behind any one proposal.
    pub notarize: usize,
    /// Distinct proposals voted for (more than one: a leader equivocated).
    pub proposals: usize,
    pub nullify: usize,
    pub finalize: usize,
}

/// Who voted in one recent view ([`Liveness::view_signers`]), by signer
/// (member) index.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ViewSigners {
    pub view: u64,
    /// The signers behind the view's best-supported proposal, as counted by
    /// [`ViewTally::notarize`].
    pub notarize: std::collections::BTreeSet<u32>,
    pub nullify: std::collections::BTreeSet<u32>,
    pub finalize: std::collections::BTreeSet<u32>,
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
    /// The highest view with votes.
    pub current: ViewTally,
    /// Of the last [`LIVENESS_VIEWS`] views, the one whose best proposal had
    /// the most notarize votes.
    pub best: ViewTally,
    /// Of the last [`LIVENESS_VIEWS`] views, the one with the most nullify
    /// votes.
    pub most_nullified: ViewTally,
    /// Messages consensus discarded as invalid, and from how many peers.
    pub blocked: u64,
    pub blocked_peers: usize,
}

/// One part this member plays in a view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    /// Leading the view: building its proposal.
    Propose,
    /// Checking the leader's proposal before voting for it.
    Verify,
}

/// A step that ended without success, and why.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub view: u64,
    pub reason: &'static str,
    pub detail: String,
}

/// How this member's turns and votes ended, one count per view.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Decisions {
    pub proposed: u64,
    /// Turns this member led without proposing, by reason.
    pub declined: std::collections::BTreeMap<&'static str, u64>,
    pub last_declined: Option<Outcome>,
    pub accepted: u64,
    /// Proposals this member refused to vote for, by reason.
    pub refused: std::collections::BTreeMap<&'static str, u64>,
    pub last_refused: Option<Outcome>,
}

impl Liveness {
    fn vote(&self, view: u64, count: impl FnOnce(&mut LivenessSnapshot, &mut ViewVotes)) {
        let Ok(mut state) = self.inner.lock() else { return };
        let state = &mut *state;
        state.snapshot.view = state.snapshot.view.max(view);
        let floor = state.snapshot.view.saturating_sub(LIVENESS_VIEWS);
        let mut ignored = ViewVotes::default();
        let votes = if view > floor { state.views.entry(view).or_default() } else { &mut ignored };
        count(&mut state.snapshot, votes);
        state.views.retain(|recent, _| *recent > floor);
    }

    #[cfg(test)]
    fn notarize(&self, view: u64, signer: u32, proposal: [u8; 32]) {
        self.notarize_vote(view, signer, proposal, None)
    }

    /// Count a notarize vote and, with `evidence` (round epoch, parent view
    /// and signature), keep it; a signer's first vote of a proposal stays.
    fn notarize_vote(&self, view: u64, signer: u32, payload: [u8; 32], evidence: Option<(u64, u64, Vec<u8>)>) {
        self.vote(view, |s, votes| {
            s.notarize_votes += 1;
            votes.notarize.entry(payload).or_default().insert(signer);
            if let Some((epoch, parent, signature)) = evidence {
                votes
                    .evidence
                    .entry((parent, payload))
                    .or_insert_with(|| Evidence { epoch, signatures: Default::default() })
                    .signatures
                    .entry(signer)
                    .or_insert(signature);
            }
        })
    }

    #[cfg(test)]
    fn evidence(&self, view: u64, epoch: u64, parent: u64, payload: [u8; 32], signer: u32, signature: Vec<u8>) {
        self.notarize_vote(view, signer, payload, Some((epoch, parent, signature)))
    }

    fn nullify(&self, view: u64, signer: u32) {
        self.vote(view, |s, votes| {
            s.nullify_votes += 1;
            votes.nullify.insert(signer);
        })
    }

    fn finalize(&self, view: u64, signer: u32) {
        self.vote(view, |s, votes| {
            s.finalize_votes += 1;
            votes.finalize.insert(signer);
        })
    }

    fn certificate(&self, view: u64, record: impl FnOnce(&mut LivenessSnapshot)) {
        let Ok(mut state) = self.inner.lock() else { return };
        record(&mut state.snapshot);
        state.snapshot.view = state.snapshot.view.max(view);
    }

    pub fn snapshot(&self) -> LivenessSnapshot {
        let Ok(state) = self.inner.lock() else { return LivenessSnapshot::default() };
        let mut snapshot = state.snapshot;
        snapshot.voters = state.views.values().flat_map(ViewVotes::signers)
            .collect::<std::collections::BTreeSet<_>>().len();
        let tallies = || state.views.iter().map(|(view, votes)| votes.tally(*view));
        snapshot.current = tallies().last().unwrap_or_default();
        snapshot.best = tallies().max_by_key(|tally| (tally.notarize, tally.view)).unwrap_or_default();
        snapshot.most_nullified = tallies().max_by_key(|tally| (tally.nullify, tally.view)).unwrap_or_default();
        snapshot.blocked_peers = state.blocked.len();
        snapshot
    }

    /// Who voted in `view` while it is one of the last [`LIVENESS_VIEWS`]
    /// views; `None` for a view without votes or one that left them.
    pub fn view_signers(&self, view: u64) -> Option<ViewSigners> {
        let Ok(state) = self.inner.lock() else { return None };
        let votes = state.views.get(&view)?;
        Some(ViewSigners {
            view,
            notarize: votes.notarize.values().max_by_key(|signers| signers.len()).cloned().unwrap_or_default(),
            nullify: votes.nullify.clone(),
            finalize: votes.finalize.clone(),
        })
    }

    /// Let [`Self::notarized`] read the bodies `store` holds while its host
    /// runs. The first binding stays.
    pub fn bind_blocks(&self, store: &BlockStore) {
        let _ = self.blocks.set(store.downgrade());
    }

    /// Keep the signatures of the notarize votes this consensus reports, for
    /// [`Self::notarize_votes`] and [`Self::notarized`] (presence reports).
    /// Off by default: then no signature is decoded, copied or stored.
    pub fn keep_votes(&self, keep: bool) {
        self.keep_votes.store(keep, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether notarize votes keep their signatures ([`Self::keep_votes`]).
    pub fn keeps_votes(&self) -> bool {
        self.keep_votes.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The proposals of the recent views that received notarize votes, in
    /// ascending view order, each with its votes and the body this node
    /// built or verified; a proposal without such a body is left out.
    pub fn notarized(&self) -> Vec<NotarizedProposal> {
        let Some(blocks) = self.blocks.get().and_then(WeakBlockStore::upgrade) else {
            // A host that failed part-way through activation never bound its
            // store; a bound store that is gone is an ordinary shutdown.
            if self.blocks.get().is_none() && !self.unbound_warned.swap(true, std::sync::atomic::Ordering::Relaxed) {
                tracing::warn!(
                    "consensus liveness has no block store bound, so notarized proposals are reported without \
                     bodies; this node's consensus activation did not finish (defect to report with the \
                     preceding activation errors)",
                );
            }
            return Vec::new();
        };
        let recent: Vec<NotarizedProposal> = {
            let Ok(state) = self.inner.lock() else { return Vec::new() };
            state.views.iter().flat_map(|(view, votes)| {
                votes.evidence.iter().map(move |((parent, payload), evidence)| NotarizedProposal {
                    epoch: evidence.epoch,
                    view: *view,
                    parent: *parent,
                    payload: *payload,
                    votes: evidence.signatures.iter().map(|(signer, signature)| (*signer, signature.clone())).collect(),
                    body: Vec::new(),
                })
            }).collect()
        };
        recent.into_iter().filter_map(|mut proposal| {
            let (body, verified) = blocks.get_with_verification(&digest_from_identity(proposal.payload))?;
            verified.then(|| {
                proposal.body = body;
                proposal
            })
        }).collect()
    }

    /// Every notarize vote of the recent views, in ascending view order,
    /// with its signature bytes where `wanted` asks for them and `None`
    /// elsewhere, so a caller that keeps the result of checking a vote
    /// copies only the votes it has not checked yet. No body is read.
    pub fn notarize_votes(&self, wanted: impl Fn(&NotarizeKey) -> bool) -> Vec<(NotarizeKey, Option<Vec<u8>>)> {
        let Ok(state) = self.inner.lock() else { return Vec::new() };
        let mut votes = Vec::new();
        for (view, recent) in &state.views {
            for ((parent, payload), evidence) in &recent.evidence {
                for (signer, signature) in &evidence.signatures {
                    let key = NotarizeKey {
                        epoch: evidence.epoch,
                        view: *view,
                        parent: *parent,
                        payload: *payload,
                        signer: *signer,
                    };
                    let signature = wanted(&key).then(|| signature.clone());
                    votes.push((key, signature));
                }
            }
        }
        votes
    }

    pub fn decisions(&self) -> Decisions {
        self.inner.lock().map(|state| state.decisions.clone()).unwrap_or_default()
    }

    /// Why `step` of `view` has not succeeded (so far): the reason its outcome
    /// is counted under if it ends without success. A later note replaces it.
    pub fn note(&self, step: Step, view: u64, reason: &'static str, detail: impl Into<String>) {
        let Ok(mut state) = self.inner.lock() else { return };
        let floor = state.snapshot.view.saturating_sub(NOTE_VIEWS);
        state.notes.retain(|(_, noted), _| *noted > floor);
        state.notes.insert((step, view), (reason, detail.into()));
    }

    /// `step` of `view` ended, successfully or under its last note.
    pub fn settle(&self, step: Step, view: u64, succeeded: bool) {
        let Ok(mut state) = self.inner.lock() else { return };
        let (reason, detail) = state.notes.remove(&(step, view)).unwrap_or(("unexplained", String::new()));
        let decisions = &mut state.decisions;
        let (done, failed, last) = match step {
            Step::Propose => (&mut decisions.proposed, &mut decisions.declined, &mut decisions.last_declined),
            Step::Verify => (&mut decisions.accepted, &mut decisions.refused, &mut decisions.last_refused),
        };
        if succeeded {
            *done += 1;
        } else {
            *failed.entry(reason).or_default() += 1;
            *last = Some(Outcome { view, reason, detail });
        }
    }

    fn blocked(&self, peer: FalconPublicKey) {
        let Ok(mut state) = self.inner.lock() else { return };
        state.snapshot.blocked += 1;
        if state.blocked.len() < BLOCKED_PEERS {
            state.blocked.insert(peer);
        }
    }

    fn observe(&self, activity: &FalconActivity) {
        use commonware_consensus::simplex::types::Attributable as _;
        use commonware_consensus::Viewable as _;
        let signer = |participant: commonware_utils::Participant| usize::from(participant) as u32;
        match activity {
            Activity::Notarize(vote) => {
                let evidence = if self.keep_votes.load(std::sync::atomic::Ordering::Relaxed) {
                    vote.attestation.signature.get().map(|signature| {
                        (vote.proposal.round.epoch().get(), vote.proposal.parent.get(), signature.to_vec())
                    })
                } else {
                    None
                };
                self.notarize_vote(vote.view().get(), signer(vote.signer()), vote.proposal.payload.0, evidence);
            }
            Activity::Nullify(vote) => self.nullify(vote.view().get(), signer(vote.signer())),
            Activity::Finalize(vote) => self.finalize(vote.view().get(), signer(vote.signer())),
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

/// `Blocker` that blocks nobody (as [`crate::p2p_bridge::NoopBlocker`]) but
/// counts, in [`Liveness`], what consensus discarded: a vote with a bad
/// signature, from a non-member, or signed by someone other than its sender.
pub struct CountingBlocker {
    liveness: Option<Arc<Liveness>>,
}

impl CountingBlocker {
    pub fn new(liveness: Option<Arc<Liveness>>) -> Self {
        Self { liveness }
    }
}

impl Clone for CountingBlocker {
    fn clone(&self) -> Self {
        Self { liveness: self.liveness.clone() }
    }
}

impl commonware_p2p::Blocker for CountingBlocker {
    type PublicKey = FalconPublicKey;
    fn block(&mut self, peer: FalconPublicKey) -> Feedback {
        if let Some(liveness) = self.liveness.as_ref() {
            liveness.blocked(peer);
        }
        Feedback::Ok
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

    /// Also record every vote and certificate in `liveness`, which reads the
    /// bodies behind notarize votes from this reporter's store.
    pub fn with_liveness(mut self, liveness: Option<Arc<Liveness>>) -> Self {
        if let Some(liveness) = liveness.as_ref() {
            liveness.bind_blocks(&self.store);
        }
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

#[cfg(test)]
mod liveness_tests {
    use super::*;

    /// A view's tally counts the signers behind its best-supported proposal,
    /// not the sum over proposals, so a split committee never looks like a
    /// quorum; votes repeated by one signer count once.
    #[test]
    fn view_tallies_count_distinct_signers_behind_one_proposal() {
        let liveness = Liveness::default();
        for signer in 0..5 {
            liveness.notarize(7, signer, [1; 32]);
        }
        liveness.notarize(7, 0, [1; 32]);
        for signer in 5..8 {
            liveness.notarize(7, signer, [2; 32]);
        }
        for signer in 0..3 {
            liveness.nullify(8, signer);
        }
        liveness.finalize(7, 1);
        let seen = liveness.snapshot();
        assert_eq!(seen.best, ViewTally { view: 7, notarize: 5, proposals: 2, nullify: 0, finalize: 1 });
        assert_eq!(seen.current, ViewTally { view: 8, notarize: 0, proposals: 0, nullify: 3, finalize: 0 });
        assert_eq!(seen.most_nullified, seen.current);
        assert_eq!(seen.voters, 8);
        assert_eq!(seen.notarize_votes, 9);
        // Views older than the window leave the tallies and the voter count:
        // view 7 drops out, view 8 stays.
        liveness.nullify(7 + LIVENESS_VIEWS, 9);
        let seen = liveness.snapshot();
        assert_eq!(seen.best.notarize, 0);
        assert_eq!(seen.voters, 4);
    }

    /// A view's signers name the members behind its best-supported proposal
    /// and its other votes, while the view is recent.
    #[test]
    fn view_signers_name_the_members_behind_the_best_proposal() {
        let liveness = Liveness::default();
        assert_eq!(liveness.view_signers(7), None, "no votes");
        for signer in [0, 2, 3] {
            liveness.notarize(7, signer, [1; 32]);
        }
        liveness.notarize(7, 4, [2; 32]);
        liveness.nullify(7, 4);
        liveness.nullify(7, 5);
        liveness.finalize(7, 0);
        let set = |signers: &[u32]| signers.iter().copied().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            liveness.view_signers(7),
            Some(ViewSigners { view: 7, notarize: set(&[0, 2, 3]), nullify: set(&[4, 5]), finalize: set(&[0]) }),
        );
        liveness.nullify(7 + LIVENESS_VIEWS, 1);
        assert_eq!(liveness.view_signers(7), None, "left the recent views");
    }

    /// Each step ends once per view under the last reason noted for it, and
    /// a success forgets the reasons noted before it.
    #[test]
    fn outcomes_are_counted_once_per_view_under_their_last_reason() {
        let liveness = Liveness::default();
        liveness.note(Step::Propose, 3, "parent unavailable", "not yet");
        liveness.note(Step::Propose, 3, "leader not ready to build on the parent", "frame 0");
        liveness.settle(Step::Propose, 3, false);
        liveness.note(Step::Propose, 4, "parent unavailable", "not yet");
        liveness.settle(Step::Propose, 4, true);
        liveness.note(Step::Verify, 4, "pre-state root differs", "phase vertex adds");
        liveness.settle(Step::Verify, 4, false);
        liveness.settle(Step::Verify, 5, false);
        liveness.settle(Step::Verify, 6, true);
        let decided = liveness.decisions();
        assert_eq!(decided.proposed, 1);
        assert_eq!(decided.declined.into_iter().collect::<Vec<_>>(), vec![("leader not ready to build on the parent", 1)]);
        assert_eq!(decided.last_declined.map(|o| (o.view, o.detail)), Some((3, "frame 0".to_string())));
        assert_eq!(decided.accepted, 1);
        assert_eq!(
            decided.refused.into_iter().collect::<Vec<_>>(),
            vec![("pre-state root differs", 1), ("unexplained", 1)],
        );
        assert_eq!(decided.last_refused.map(|o| o.view), Some(5));
    }

    /// Notarize votes are kept with their signatures for the recent views and
    /// returned only for a proposal whose body this node sealed.
    #[test]
    fn notarized_proposals_carry_their_votes_and_sealed_body() {
        let liveness = Liveness::default();
        liveness.evidence(7, 3, 6, [1; 32], 2, vec![0xa2]);
        assert!(liveness.notarized().is_empty(), "no block store bound");
        assert!(liveness.unbound_warned.load(std::sync::atomic::Ordering::Relaxed), "an unbound store warns once");
        let store = BlockStore::new();
        liveness.bind_blocks(&store);
        liveness.evidence(7, 3, 6, [1; 32], 0, vec![0xa0]);
        liveness.evidence(7, 3, 6, [1; 32], 2, vec![0xff]);
        liveness.evidence(8, 3, 7, [2; 32], 1, vec![0xb1]);
        store.put(digest_from_identity([2; 32]), b"candidate".to_vec());
        assert!(liveness.notarized().is_empty(), "no body sealed yet");
        store.seal(digest_from_identity([1; 32]), b"body".to_vec());
        assert_eq!(
            liveness.notarized(),
            vec![NotarizedProposal {
                epoch: 3, view: 7, parent: 6, payload: [1; 32],
                votes: vec![(0, vec![0xa0]), (2, vec![0xa2])], body: b"body".to_vec(),
            }],
            "a signer's first vote stays",
        );
        let key = |view, parent, payload, signer| NotarizeKey { epoch: 3, view, parent, payload, signer };
        assert_eq!(
            liveness.notarize_votes(|key| key.signer == 2),
            vec![
                (key(7, 6, [1; 32], 0), None),
                (key(7, 6, [1; 32], 2), Some(vec![0xa2])),
                (key(8, 7, [2; 32], 1), None),
            ],
            "every vote is listed, with only the wanted signatures, and none needs a body",
        );
        // Votes leave with their view.
        liveness.nullify(7 + LIVENESS_VIEWS, 9);
        assert!(liveness.notarized().is_empty());
        assert_eq!(liveness.notarize_votes(|_| true).len(), 1);
    }

    /// A member's real notarize vote of view 9 whose parent is view 5 (not
    /// the view before, so a swap of the two shows), with its scheme.
    fn signed_notarize() -> (
        SimplexFalconScheme,
        commonware_consensus::simplex::types::Notarize<SimplexFalconScheme, Digest>,
    ) {
        use commonware_consensus::simplex::types::{Notarize, Proposal};
        use commonware_consensus::types::{Epoch, Round, View};
        use commonware_cryptography::Signer as _;
        use commonware_utils::ordered::Set;
        use quil_types::crypto::Signer as _;
        let mut keys: Vec<_> = (0..2)
            .map(|_| {
                let key = quil_crypto::FalconSigner::generate();
                crate::falcon_base::FalconPrivateKey::from_bytes(key.private_key(), key.public_key()).unwrap()
            })
            .collect();
        keys.sort_by_key(|key| key.public_key().as_ref().to_vec());
        let participants: Set<_> = keys.iter().map(|key| key.public_key()).collect::<Vec<_>>().try_into().unwrap();
        let scheme = SimplexFalconScheme::signer(b"test", participants, keys[1].clone()).unwrap();
        let proposal = Proposal::new(Round::new(Epoch::new(3), View::new(9)), View::new(5), digest_from_identity([4; 32]));
        let vote = Notarize::sign(&scheme, proposal).unwrap();
        (scheme, vote)
    }

    /// A notarize vote consensus reports keeps its round, parent view,
    /// payload, signer and signature as signed, so the vote verifies again
    /// from what [`Liveness`] returns.
    #[test]
    fn a_reported_notarize_keeps_its_round_parent_and_signature() {
        use commonware_consensus::simplex::types::Proposal;
        use commonware_consensus::types::{Epoch, Round, View};
        let (scheme, vote) = signed_notarize();
        let liveness = Liveness::default();
        liveness.keep_votes(true);
        liveness.observe(&Activity::Notarize(vote.clone()));
        let votes = liveness.notarize_votes(|_| true);
        let key = NotarizeKey { epoch: 3, view: 9, parent: 5, payload: [4; 32], signer: 1 };
        assert_eq!(votes, vec![(key, Some(vote.attestation.signature.get().unwrap().to_vec()))]);
        let listed = Proposal::new(
            Round::new(Epoch::new(key.epoch), View::new(key.view)),
            View::new(key.parent),
            digest_from_identity(key.payload),
        );
        assert!(scheme.verify_notarize(&listed, &vote.attestation), "the listed vote verifies as consensus checks it");
    }

    /// Unless presence reports ask for them, notarize votes are only
    /// counted: no signature is kept.
    #[test]
    fn notarize_signatures_are_kept_only_when_asked() {
        let (_, vote) = signed_notarize();
        let liveness = Liveness::default();
        liveness.observe(&Activity::Notarize(vote.clone()));
        assert_eq!(liveness.snapshot().notarize_votes, 1, "the vote is counted");
        assert!(liveness.notarize_votes(|_| true).is_empty(), "and its signature not kept");
        assert!(liveness.inner.lock().unwrap().views.values().all(|votes| votes.evidence.is_empty()));
        liveness.keep_votes(true);
        liveness.observe(&Activity::Notarize(vote));
        assert_eq!(liveness.notarize_votes(|_| true).len(), 1);
    }

    /// Liveness reads the host's bodies only while the host's store lives:
    /// a retired host's bodies are freed.
    #[test]
    fn a_dropped_block_store_is_not_kept_alive() {
        let liveness = Liveness::default();
        let store = BlockStore::new();
        liveness.bind_blocks(&store);
        liveness.evidence(7, 3, 6, [1; 32], 0, vec![0xa0]);
        store.seal(digest_from_identity([1; 32]), b"body".to_vec());
        assert_eq!(liveness.notarized().len(), 1);
        drop(store);
        assert!(liveness.notarized().is_empty(), "the bodies went with their store");
    }

    #[test]
    fn blocked_messages_are_counted_with_their_distinct_peers() {
        use commonware_cryptography::Signer as _;
        use commonware_math::algebra::Random as _;
        use commonware_p2p::Blocker as _;
        let liveness = Arc::new(Liveness::default());
        let mut blocker = CountingBlocker::new(Some(liveness.clone()));
        let peers: Vec<_> = (0..2)
            .map(|_| crate::falcon_base::FalconPrivateKey::random(commonware_utils::test_rng()).public_key())
            .collect();
        for peer in [&peers[0], &peers[0], &peers[1]] {
            blocker.block((*peer).clone());
        }
        let seen = liveness.snapshot();
        assert_eq!((seen.blocked, seen.blocked_peers), (3, 2));
    }
}

//! Quilibrium adapters for commonware `simplex`.
//!
//! simplex's `Engine` is driven by three application traits — `Automaton`
//! (propose/verify a payload), `Relay` (broadcast the block bytes behind a
//! payload digest), and `Reporter` (observe notarization/finalization). This
//! module implements those three commonware traits over three **narrow,
//! Quilibrium-facing seam traits** so the engine-facing glue is fixed here and
//! the real state wiring (leader_provider / frame validation / materialize)
//! lives behind the seams (implemented in quil-engine, P2b):
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
    Automaton, CertifiableAutomaton, Relay, Reporter, Viewable as _,
};

/// Digest type consensus agrees on (the frame identity).
pub type Digest = Sha256Digest;
/// simplex activity for the Falcon scheme.
pub type FalconActivity = Activity<SimplexFalconScheme, Digest>;

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

/// Shared digest → frame-bytes store. `Automaton::propose` inserts the frame it
/// built; `Relay` reads it to ship; `verify`/`Reporter` read it to validate /
/// commit. Frames arriving from peers (over `FrameSink`'s transport) are also
/// inserted here by the node's inbound path.
#[derive(Clone, Default)]
pub struct BlockStore {
    inner: Arc<Mutex<HashMap<Digest, Vec<u8>>>>,
}

impl BlockStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn put(&self, digest: Digest, bytes: Vec<u8>) {
        self.inner.lock().insert(digest, bytes);
    }
    pub fn get(&self, digest: &Digest) -> Option<Vec<u8>> {
        self.inner.lock().get(digest).cloned()
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
pub trait GlobalProposer: Send + Sync + 'static {
    /// Build the next frame on parent `parent_digest` for consensus `view`.
    /// Returns `(frame_identity_digest, canonical_frame_bytes)`, or `None` if
    /// this node cannot build (e.g. it lacks the parent) — simplex then times
    /// out and nullifies the view (mirrors the existing leader-can't-build SKIP).
    fn propose(&self, view: u64, parent_digest: Digest) -> Option<(Digest, Vec<u8>)>;

    /// Validate a proposed frame `digest` for `view` as a child of
    /// `parent_digest`. `bytes` is the frame body if already delivered (via
    /// `FrameSink`), else `None` (not yet arrived → return `false` so the view
    /// nullifies rather than votes blind). Passing the consensus parent lets
    /// application seams enforce height + parent linkage before voting.
    fn verify(
        &self,
        view: u64,
        parent_digest: Digest,
        digest: Digest,
        bytes: Option<Vec<u8>>,
    ) -> bool;
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
    fn on_finalized(&self, view: u64, digest: Digest, bytes: Option<Vec<u8>>, cert: Option<Vec<u8>>);
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
        let view: u64 = context.view().get();
        let parent = context.parent.1;
        let proposer = self.proposer.clone();
        let store = self.store.clone();
        self.context.child("propose").spawn(move |_| async move {
            if let Some((digest, bytes)) = proposer.propose(view, parent) {
                store.put(digest, bytes);
                let _ = tx.send(digest);
            }
            // else: drop tx → receiver cancelled → simplex nullifies the view.
        });
        rx
    }

    async fn verify(
        &mut self,
        context: Self::Context,
        payload: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        let view: u64 = context.view().get();
        let parent = context.parent.1;
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
            let ok = proposer.verify(view, parent, payload, bytes);
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

/// `Reporter` over a [`FrameFinalizer`]; maps simplex activities to the
/// candidate-write / commit / equivocation hooks.
pub struct FalconReporter<Fin: FrameFinalizer> {
    finalizer: Arc<Fin>,
    store: BlockStore,
}

impl<Fin: FrameFinalizer> Clone for FalconReporter<Fin> {
    fn clone(&self) -> Self {
        Self { finalizer: self.finalizer.clone(), store: self.store.clone() }
    }
}

impl<Fin: FrameFinalizer> FalconReporter<Fin> {
    pub fn new(finalizer: Arc<Fin>, store: BlockStore) -> Self {
        Self { finalizer, store }
    }
}

impl<Fin: FrameFinalizer> Reporter for FalconReporter<Fin> {
    type Activity = FalconActivity;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
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
                let bytes = self.store.get(&digest);
                // Serialize the finalization certificate (proposal + Falcon
                // quorum cert) so the finalizer can carry it into a coverage
                // bundle for global-level reward verification.
                let cert = Some(crate::app_cert::encode_finalization(&f));
                self.finalizer.on_finalized(view, digest, bytes, cert);
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

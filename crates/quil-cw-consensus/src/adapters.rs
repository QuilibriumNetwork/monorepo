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
    static REMEMBERED: LazyLock<Mutex<HashMap<FalconPublicKey, [u8; 32]>>> =
        LazyLock::new(Default::default);
    if let Some(address) = REMEMBERED
        .lock()
        .ok()
        .and_then(|cache| cache.get(key).copied())
    {
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
///
/// The store is bounded by [`BlockStoreLimits`]. Each block carries a view:
/// the latest certificate's view when it arrived, raised when a notarization
/// or finalization names it. Once a view finalizes, blocks more than
/// `keep_views` below it are dropped: consensus no longer builds on or votes
/// for them, and the window leaves the slower readers of finalized bodies
/// (materialization, recovery) time to take them. A reader that takes them
/// later than that holds the window at the lowest view it still has to take
/// ([`BlockStore::hold_from`]). Over a cap, the store evicts first the
/// candidates (blocks no certificate names and this node never verified),
/// then the blocks of the oldest views, but never a verified or certified
/// block of the latest `protected_views` views or of the held window. A
/// body that arrives after a certificate named it is stored as certified.
#[derive(Clone, Default)]
pub struct BlockStore {
    inner: Arc<Mutex<Blocks>>,
}

/// A [`BlockStore`] handle that does not keep the blocks alive: once the
/// host that owns the store stops, its bodies are freed.
#[derive(Clone)]
pub struct WeakBlockStore {
    inner: std::sync::Weak<Mutex<Blocks>>,
}

impl WeakBlockStore {
    pub fn upgrade(&self) -> Option<BlockStore> {
        self.inner.upgrade().map(|inner| BlockStore { inner })
    }
}

/// How long a [`BlockStore`] keeps blocks, and how many it holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockStoreLimits {
    /// Views below the latest finalized view whose blocks are kept.
    pub keep_views: u64,
    /// Views below the latest certified view whose verified or certified
    /// blocks are never evicted over a cap.
    pub protected_views: u64,
    /// Blocks held at most, unless protected.
    pub max_blocks: usize,
    /// Bytes held at most, unless protected.
    pub max_bytes: usize,
    /// Candidates (blocks no certificate names and this node never
    /// verified) held at most.
    pub max_candidate_blocks: usize,
    /// Candidate bytes held at most.
    pub max_candidate_bytes: usize,
}

impl Default for BlockStoreLimits {
    /// Sized for an application shard, whose finalizer may hold finalized
    /// bodies here until its engine materializes them. The candidate caps
    /// hold eight GLOBAL frames of the 16 MiB maximum, or 1024 smaller
    /// blocks; honest members deliver about one proposal per view.
    fn default() -> Self {
        Self {
            keep_views: 1024,
            protected_views: 32,
            max_blocks: 4096,
            max_bytes: 512 << 20,
            max_candidate_blocks: 1024,
            max_candidate_bytes: 128 << 20,
        }
    }
}

impl BlockStoreLimits {
    /// GLOBAL: its finalizer takes each finalized body when the finalization
    /// is reported, and proposals and ancestors are also kept in the clock
    /// store, so a shorter window suffices.
    pub fn global() -> Self {
        Self {
            keep_views: 128,
            ..Self::default()
        }
    }
}

/// Reports the lowest view whose finalized bodies a reader of a
/// [`BlockStore`] still has to take, if any.
pub type BlockHold = Arc<dyn Fn() -> Option<u64> + Send + Sync>;

/// Minimum interval between two eviction log lines of one store.
const EVICTION_REPORT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Clone)]
struct StoredBlock {
    bytes: Vec<u8>,
    verified: bool,
    /// A notarization or finalization names this digest.
    certified: bool,
    /// The view consensus last placed this block at (see [`BlockStore`]).
    view: u64,
    /// Arrival order of the digest.
    seq: u64,
}

impl StoredBlock {
    /// This node verified or built the block, or a certificate names it.
    fn vouched(&self) -> bool {
        self.verified || self.certified
    }
}

struct Blocks {
    map: HashMap<Digest, StoredBlock>,
    limits: BlockStoreLimits,
    /// Names the store in its log lines.
    scope: String,
    bytes: usize,
    candidates: usize,
    candidate_bytes: usize,
    /// The highest view a certificate named.
    certified_view: u64,
    /// The highest finalized view.
    finalized_view: u64,
    /// Digests certificates named, with the highest such view, so that a
    /// body arriving after its certificate is stored as certified. Pruned
    /// with the window, and at most `max_blocks` of them.
    certified_digests: HashMap<Digest, u64>,
    /// What [`BlockStore::hold_from`] reported at the latest finalization.
    held_view: Option<u64>,
    hold: Option<BlockHold>,
    next_seq: u64,
    evicted: Evicted,
}

/// Blocks evicted over a cap since the last eviction log line.
#[derive(Default)]
struct Evicted {
    candidates: u64,
    vouched: u64,
    bytes: u64,
    last_report: Option<std::time::Instant>,
}

/// One eviction log line.
struct EvictionReport {
    scope: String,
    candidates: u64,
    vouched: u64,
    bytes: u64,
    held_blocks: usize,
    held_bytes: usize,
    since_previous: Option<std::time::Duration>,
}

impl EvictionReport {
    fn log(&self) {
        let window = match self.since_previous {
            Some(elapsed) => format!("the last {}s", elapsed.as_secs()),
            None => "the store started".to_string(),
        };
        if self.vouched > 0 {
            tracing::warn!(
                scope = %self.scope,
                candidates = self.candidates,
                vouched = self.vouched,
                bytes = self.bytes,
                held_blocks = self.held_blocks,
                held_bytes = self.held_bytes,
                "consensus block store over its limits since {window}: evicted verified or \
                 certified blocks of old views; a body still needed is read from storage or \
                 fetched again; report this line if it repeats"
            );
        } else {
            tracing::info!(
                scope = %self.scope,
                candidates = self.candidates,
                bytes = self.bytes,
                held_blocks = self.held_blocks,
                held_bytes = self.held_bytes,
                "consensus block store over its limits since {window}: evicted candidate blocks \
                 no certificate names (peer deliveries or proposals that did not notarize)"
            );
        }
    }
}

impl Default for Blocks {
    fn default() -> Self {
        Self::new(BlockStoreLimits::default(), "consensus".to_string())
    }
}

impl Blocks {
    fn new(limits: BlockStoreLimits, scope: String) -> Self {
        Self {
            map: HashMap::new(),
            limits,
            scope,
            bytes: 0,
            candidates: 0,
            candidate_bytes: 0,
            certified_view: 0,
            finalized_view: 0,
            certified_digests: HashMap::new(),
            held_view: None,
            hold: None,
            next_seq: 0,
            evicted: Evicted::default(),
        }
    }

    /// Store `bytes` under `digest`, replacing what is held there.
    fn insert(&mut self, digest: Digest, bytes: Vec<u8>, verified: bool) -> Option<EvictionReport> {
        let (view, seq, certified) = match self.take(&digest) {
            Some(old) => (old.view.max(self.certified_view), old.seq, old.certified),
            None => {
                self.next_seq += 1;
                match self.certified_digests.get(&digest) {
                    Some(view) => (self.certified_view.max(*view), self.next_seq, true),
                    None => (self.certified_view, self.next_seq, false),
                }
            }
        };
        self.add(
            digest,
            StoredBlock {
                bytes,
                verified,
                certified,
                view,
                seq,
            },
        );
        self.enforce_caps()
    }

    fn add(&mut self, digest: Digest, block: StoredBlock) {
        let len = block.bytes.len();
        self.bytes += len;
        if !block.vouched() {
            self.candidates += 1;
            self.candidate_bytes += len;
        }
        self.map.insert(digest, block);
    }

    fn take(&mut self, digest: &Digest) -> Option<StoredBlock> {
        let block = self.map.remove(digest)?;
        let len = block.bytes.len();
        self.bytes -= len;
        if !block.vouched() {
            self.candidates -= 1;
            self.candidate_bytes -= len;
        }
        Some(block)
    }

    fn note_certificate(&mut self, view: u64) {
        if self.certified_view == 0 && view > 0 {
            // Blocks restored before any certificate take the first view one
            // names, so the window does not drop them at the first
            // finalization.
            for block in self.map.values_mut() {
                block.view = block.view.max(view);
            }
        }
        self.certified_view = self.certified_view.max(view);
    }

    /// A certificate names `digest`; `view` is its view, when it is one of
    /// this store's.
    fn certify(&mut self, digest: &Digest, view: Option<u64>) {
        if let Some(view) = view {
            self.note_certificate(view);
        }
        let view = view.unwrap_or(self.certified_view);
        let known = self.certified_digests.entry(*digest).or_insert(view);
        *known = (*known).max(view);
        while self.certified_digests.len() > self.limits.max_blocks {
            let Some(oldest) = self
                .certified_digests
                .iter()
                .min_by_key(|(_, view)| **view)
                .map(|(digest, _)| *digest)
            else {
                break;
            };
            self.certified_digests.remove(&oldest);
        }
        if let Some(mut block) = self.take(digest) {
            block.certified = true;
            block.view = block.view.max(view);
            self.add(*digest, block);
        }
    }

    /// `view` finalized, and a reader still has to take the finalized bodies
    /// from `held` on.
    fn finalize(&mut self, view: u64, held: Option<u64>) {
        self.note_certificate(view);
        self.held_view = held;
        if view <= self.finalized_view {
            return;
        }
        self.finalized_view = view;
        let anchor = held.map_or(view, |held| held.min(view));
        let below = anchor.saturating_sub(self.limits.keep_views);
        let stale: Vec<Digest> = self
            .map
            .iter()
            .filter(|(_, block)| block.view < below)
            .map(|(digest, _)| *digest)
            .collect();
        for digest in stale {
            self.take(&digest);
        }
        self.certified_digests
            .retain(|_, certified| *certified >= below);
    }

    fn enforce_caps(&mut self) -> Option<EvictionReport> {
        let limits = self.limits;
        while self.candidates > limits.max_candidate_blocks
            || self.candidate_bytes > limits.max_candidate_bytes
        {
            let Some(victim) = self.eviction_victim(|block| !block.vouched()) else {
                break;
            };
            self.evict(&victim);
        }
        let mut floor = self.certified_view.saturating_sub(limits.protected_views);
        if let Some(held) = self.held_view {
            floor = floor.min(held.saturating_sub(limits.keep_views));
        }
        while self.map.len() > limits.max_blocks || self.bytes > limits.max_bytes {
            let Some(victim) = self.eviction_victim(|block| !block.vouched() || block.view < floor)
            else {
                break;
            };
            self.evict(&victim);
        }
        self.eviction_report(std::time::Instant::now())
    }

    /// The block to evict first among the `eligible`: candidates before
    /// vouched blocks, then the lowest view, then the earliest arrival.
    fn eviction_victim(&self, eligible: impl Fn(&StoredBlock) -> bool) -> Option<Digest> {
        self.map
            .iter()
            .filter(|(_, block)| eligible(*block))
            .min_by_key(|(_, block)| (block.vouched(), block.view, block.seq))
            .map(|(digest, _)| *digest)
    }

    fn evict(&mut self, digest: &Digest) {
        if let Some(block) = self.take(digest) {
            if block.vouched() {
                self.evicted.vouched += 1;
            } else {
                self.evicted.candidates += 1;
            }
            self.evicted.bytes += block.bytes.len() as u64;
        }
    }

    /// At most one report per [`EVICTION_REPORT_INTERVAL`]; the first
    /// eviction after a quiet interval is reported at once.
    fn eviction_report(&mut self, now: std::time::Instant) -> Option<EvictionReport> {
        if self.evicted.candidates == 0 && self.evicted.vouched == 0 {
            return None;
        }
        let since_previous = self
            .evicted
            .last_report
            .map(|last| now.saturating_duration_since(last));
        if since_previous.is_some_and(|elapsed| elapsed < EVICTION_REPORT_INTERVAL) {
            return None;
        }
        self.evicted.last_report = Some(now);
        Some(EvictionReport {
            scope: self.scope.clone(),
            candidates: std::mem::take(&mut self.evicted.candidates),
            vouched: std::mem::take(&mut self.evicted.vouched),
            bytes: std::mem::take(&mut self.evicted.bytes),
            held_blocks: self.map.len(),
            held_bytes: self.bytes,
            since_previous,
        })
    }
}

impl BlockStore {
    pub fn downgrade(&self) -> WeakBlockStore {
        WeakBlockStore {
            inner: Arc::downgrade(&self.inner),
        }
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// A store bounded by `limits`, named `scope` in its log lines.
    pub fn with_limits(limits: BlockStoreLimits, scope: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Blocks::new(limits, scope.into()))),
        }
    }

    /// Insert an unverified block candidate. Candidates may be replaced until
    /// one exact byte sequence passes application validation and is sealed.
    /// Once sealed, peer ingress cannot substitute different bytes for the
    /// consensus digest that was actually verified.
    pub fn put(&self, digest: Digest, bytes: Vec<u8>) {
        let report = {
            let mut inner = self.inner.lock();
            let sealed = inner.map.get(&digest).is_some_and(|stored| stored.verified);
            if sealed {
                None
            } else {
                inner.insert(digest, bytes, false)
            }
        };
        if let Some(report) = report {
            report.log();
        }
    }
    pub fn get(&self, digest: &Digest) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .map
            .get(digest)
            .map(|stored| stored.bytes.clone())
    }

    /// Refuse oversized recovery input before copying peer-controlled bytes.
    pub fn get_bounded(&self, digest: &Digest, max_bytes: usize) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .map
            .get(digest)
            .filter(|stored| stored.bytes.len() <= max_bytes)
            .map(|stored| stored.bytes.clone())
    }

    /// Seal the exact bytes that passed application validation (or were built
    /// locally). Idempotent: once a digest is sealed, a later `seal`/`put`
    /// cannot substitute different bytes for it.
    pub fn seal(&self, digest: Digest, bytes: Vec<u8>) {
        let report = {
            let mut inner = self.inner.lock();
            let sealed = inner.map.get(&digest).is_some_and(|stored| stored.verified);
            if sealed {
                None
            } else {
                inner.insert(digest, bytes, true)
            }
        };
        if let Some(report) = report {
            report.log();
        }
    }

    /// Return the current bytes together with whether this node's application
    /// validator accepted and sealed this exact value. A replica can learn a
    /// finalization certificate before locally verifying its block, so the
    /// reporter must preserve that distinction for the finalizer.
    pub fn get_with_verification(&self, digest: &Digest) -> Option<(Vec<u8>, bool)> {
        self.inner
            .lock()
            .map
            .get(digest)
            .map(|stored| (stored.bytes.clone(), stored.verified))
    }

    /// A certificate of `view` names `digest`: its block, if held, is one
    /// consensus or its finalizer may still need, at least until `view`
    /// leaves the window.
    pub fn certified(&self, digest: &Digest, view: u64) {
        self.inner.lock().certify(digest, Some(view));
    }

    /// A finalization this node recorded earlier names `digest`, at a view
    /// that may belong to another consensus instance: keep its block as a
    /// certified one without moving this store's views.
    pub fn recorded_final(&self, digest: &Digest) {
        self.inner.lock().certify(digest, None);
    }

    /// A certificate of `view` that names no block (a nullification).
    pub fn observe_certificate(&self, view: u64) {
        self.inner.lock().note_certificate(view);
    }

    /// `view` finalized: drop the blocks more than `keep_views` below it, or
    /// below the view the hold reports if that is lower.
    pub fn finalized(&self, view: u64) {
        // Asked outside the store's lock: the reader takes its own lock, and
        // holds it while it reads the store.
        let hold = self.inner.lock().hold.clone();
        let held = hold.and_then(|hold| hold());
        self.inner.lock().finalize(view, held);
    }

    /// Let a reader that takes finalized bodies later than their
    /// finalization (the application finalizer delivers them in order) hold
    /// the window: `hold` reports the lowest view it still has to take. Asked
    /// at each finalization, outside the store's lock.
    pub fn hold_from(&self, hold: BlockHold) {
        self.inner.lock().hold = Some(hold);
    }

    /// The blocks and bytes held.
    pub fn usage(&self) -> (usize, usize) {
        let inner = self.inner.lock();
        (inner.map.len(), inner.bytes)
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
pub const VERIFY_PATIENCE: std::time::Duration = std::time::Duration::from_secs(20);

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
    fn verify(
        &self,
        view: u64,
        parent_digest: Digest,
        digest: Digest,
        bytes: Option<Vec<u8>>,
    ) -> bool;

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
    fn verify_delay(
        &self,
        _context: ProposalContext,
        _bytes: &[u8],
    ) -> Option<std::time::Duration> {
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
        if let Some(delay) = bytes
            .as_deref()
            .and_then(|bytes| self.verify_delay(context, bytes))
        {
            return Err(delay);
        }
        Ok(self.verify_with_context(context, digest, bytes))
    }

    /// The adapter declined `context`'s proposal because it was still
    /// deferred, `waited` in all, when [`VERIFY_PATIENCE`] ran out. Called
    /// once per check, so a proposer can report why without a line per
    /// deferral.
    fn verify_patience_ran_out(&self, _context: ProposalContext, _waited: std::time::Duration) {}
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
        Self {
            context,
            proposer,
            store,
            liveness: None,
        }
    }

    /// Also count, in `liveness`, how each proposal and vote of this member
    /// ended, under the reason the proposer noted ([`Liveness::note`]).
    pub fn with_liveness(mut self, liveness: Option<Arc<Liveness>>) -> Self {
        self.liveness = liveness;
        self
    }
}

impl<E: Spawner + Clock + Send + 'static, Pr: GlobalProposer> Automaton for FalconAutomaton<E, Pr> {
    type Digest = Digest;
    type Context = Context<Digest, FalconPublicKey>;

    async fn propose(&mut self, context: Self::Context) -> oneshot::Receiver<Self::Digest> {
        let (tx, rx) = oneshot::channel();
        let proposal_context = ProposalContext::from(context);
        let proposer = self.proposer.clone();
        let store = self.store.clone();
        let liveness = self.liveness.clone();
        let settle = move |proposed: bool| {
            if let Some(liveness) = liveness.as_ref() {
                liveness.settle(Step::Propose, proposal_context.view, proposed);
            }
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
                    Err(_) => {
                        if deferred >= VERIFY_PATIENCE {
                            proposer.verify_patience_ran_out(proposal_context, deferred);
                        }
                        break false;
                    }
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
        Self {
            sink: self.sink.clone(),
            store: self.store.clone(),
        }
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
    /// The nullify votes themselves: round epoch and signature bytes per
    /// signer; a signer's first vote stays.
    nullify_evidence: std::collections::BTreeMap<u32, (u64, Vec<u8>)>,
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

/// One nullify vote of a recent view ([`Liveness::nullify_votes`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NullifyKey {
    /// The round epoch (a session's generation).
    pub epoch: u64,
    pub view: u64,
    pub signer: u32,
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
            notarize: self
                .notarize
                .values()
                .map(|signers| signers.len())
                .max()
                .unwrap_or(0),
            proposals: self.notarize.len(),
            nullify: self.nullify.len(),
            finalize: self.finalize.len(),
        }
    }

    fn signers(&self) -> impl Iterator<Item = u32> + '_ {
        self.notarize
            .values()
            .flatten()
            .chain(&self.nullify)
            .chain(&self.finalize)
            .copied()
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
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        let state = &mut *state;
        state.snapshot.view = state.snapshot.view.max(view);
        let floor = state.snapshot.view.saturating_sub(LIVENESS_VIEWS);
        let mut ignored = ViewVotes::default();
        let votes = if view > floor {
            state.views.entry(view).or_default()
        } else {
            &mut ignored
        };
        count(&mut state.snapshot, votes);
        state.views.retain(|recent, _| *recent > floor);
    }

    #[cfg(test)]
    fn notarize(&self, view: u64, signer: u32, proposal: [u8; 32]) {
        self.notarize_vote(view, signer, proposal, None)
    }

    /// Count a notarize vote and, with `evidence` (round epoch, parent view
    /// and signature), keep it; a signer's first vote of a proposal stays.
    fn notarize_vote(
        &self,
        view: u64,
        signer: u32,
        payload: [u8; 32],
        evidence: Option<(u64, u64, Vec<u8>)>,
    ) {
        self.vote(view, |s, votes| {
            s.notarize_votes += 1;
            votes.notarize.entry(payload).or_default().insert(signer);
            if let Some((epoch, parent, signature)) = evidence {
                votes
                    .evidence
                    .entry((parent, payload))
                    .or_insert_with(|| Evidence {
                        epoch,
                        signatures: Default::default(),
                    })
                    .signatures
                    .entry(signer)
                    .or_insert(signature);
            }
        })
    }

    #[cfg(test)]
    fn evidence(
        &self,
        view: u64,
        epoch: u64,
        parent: u64,
        payload: [u8; 32],
        signer: u32,
        signature: Vec<u8>,
    ) {
        self.notarize_vote(view, signer, payload, Some((epoch, parent, signature)))
    }

    #[cfg(test)]
    fn nullify(&self, view: u64, signer: u32) {
        self.nullify_vote(view, signer, None)
    }

    /// Count a nullify vote and, with `evidence` (round epoch and
    /// signature), keep it; a signer's first nullify of a view stays.
    fn nullify_vote(&self, view: u64, signer: u32, evidence: Option<(u64, Vec<u8>)>) {
        self.vote(view, |s, votes| {
            s.nullify_votes += 1;
            votes.nullify.insert(signer);
            if let Some(evidence) = evidence {
                votes.nullify_evidence.entry(signer).or_insert(evidence);
            }
        })
    }

    fn finalize(&self, view: u64, signer: u32) {
        self.vote(view, |s, votes| {
            s.finalize_votes += 1;
            votes.finalize.insert(signer);
        })
    }

    fn certificate(&self, view: u64, record: impl FnOnce(&mut LivenessSnapshot)) {
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        record(&mut state.snapshot);
        state.snapshot.view = state.snapshot.view.max(view);
    }

    pub fn snapshot(&self) -> LivenessSnapshot {
        let Ok(state) = self.inner.lock() else {
            return LivenessSnapshot::default();
        };
        let mut snapshot = state.snapshot;
        snapshot.voters = state
            .views
            .values()
            .flat_map(ViewVotes::signers)
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        let tallies = || state.views.iter().map(|(view, votes)| votes.tally(*view));
        snapshot.current = tallies().last().unwrap_or_default();
        snapshot.best = tallies()
            .max_by_key(|tally| (tally.notarize, tally.view))
            .unwrap_or_default();
        snapshot.most_nullified = tallies()
            .max_by_key(|tally| (tally.nullify, tally.view))
            .unwrap_or_default();
        snapshot.blocked_peers = state.blocked.len();
        snapshot
    }

    /// Who voted in `view` while it is one of the last [`LIVENESS_VIEWS`]
    /// views; `None` for a view without votes or one that left them.
    pub fn view_signers(&self, view: u64) -> Option<ViewSigners> {
        let Ok(state) = self.inner.lock() else {
            return None;
        };
        let votes = state.views.get(&view)?;
        Some(ViewSigners {
            view,
            notarize: votes
                .notarize
                .values()
                .max_by_key(|signers| signers.len())
                .cloned()
                .unwrap_or_default(),
            nullify: votes.nullify.clone(),
            finalize: votes.finalize.clone(),
        })
    }

    /// Let [`Self::notarized`] read the bodies `store` holds while its host
    /// runs. The first binding stays.
    pub fn bind_blocks(&self, store: &BlockStore) {
        let _ = self.blocks.set(store.downgrade());
    }

    /// Keep the signatures of the notarize and nullify votes this consensus
    /// reports, for [`Self::notarize_votes`], [`Self::notarized`] and
    /// [`Self::nullify_votes`] (presence reports).
    /// Off by default: then no signature is decoded, copied or stored.
    pub fn keep_votes(&self, keep: bool) {
        self.keep_votes
            .store(keep, std::sync::atomic::Ordering::Relaxed);
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
            if self.blocks.get().is_none()
                && !self
                    .unbound_warned
                    .swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                tracing::warn!(
                    "consensus liveness has no block store bound, so notarized proposals are reported without \
                     bodies; this node's consensus activation did not finish (defect to report with the \
                     preceding activation errors)",
                );
            }
            return Vec::new();
        };
        let recent: Vec<NotarizedProposal> = {
            let Ok(state) = self.inner.lock() else {
                return Vec::new();
            };
            state
                .views
                .iter()
                .flat_map(|(view, votes)| {
                    votes
                        .evidence
                        .iter()
                        .map(move |((parent, payload), evidence)| NotarizedProposal {
                            epoch: evidence.epoch,
                            view: *view,
                            parent: *parent,
                            payload: *payload,
                            votes: evidence
                                .signatures
                                .iter()
                                .map(|(signer, signature)| (*signer, signature.clone()))
                                .collect(),
                            body: Vec::new(),
                        })
                })
                .collect()
        };
        recent
            .into_iter()
            .filter_map(|mut proposal| {
                let (body, verified) =
                    blocks.get_with_verification(&digest_from_identity(proposal.payload))?;
                verified.then(|| {
                    proposal.body = body;
                    proposal
                })
            })
            .collect()
    }

    /// Every notarize vote of the recent views, in ascending view order,
    /// with its signature bytes where `wanted` asks for them and `None`
    /// elsewhere, so a caller that keeps the result of checking a vote
    /// copies only the votes it has not checked yet. No body is read.
    pub fn notarize_votes(
        &self,
        wanted: impl Fn(&NotarizeKey) -> bool,
    ) -> Vec<(NotarizeKey, Option<Vec<u8>>)> {
        let Ok(state) = self.inner.lock() else {
            return Vec::new();
        };
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

    /// Every kept nullify vote of the recent views, in ascending view and
    /// signer order, with its signature bytes where `wanted` asks for them
    /// and `None` elsewhere ([`Self::notarize_votes`]).
    pub fn nullify_votes(
        &self,
        wanted: impl Fn(&NullifyKey) -> bool,
    ) -> Vec<(NullifyKey, Option<Vec<u8>>)> {
        let Ok(state) = self.inner.lock() else {
            return Vec::new();
        };
        let mut votes = Vec::new();
        for (view, recent) in &state.views {
            for (signer, (epoch, signature)) in &recent.nullify_evidence {
                let key = NullifyKey {
                    epoch: *epoch,
                    view: *view,
                    signer: *signer,
                };
                let signature = wanted(&key).then(|| signature.clone());
                votes.push((key, signature));
            }
        }
        votes
    }

    pub fn decisions(&self) -> Decisions {
        self.inner
            .lock()
            .map(|state| state.decisions.clone())
            .unwrap_or_default()
    }

    /// Why `step` of `view` has not succeeded (so far): the reason its outcome
    /// is counted under if it ends without success. A later note replaces it.
    pub fn note(&self, step: Step, view: u64, reason: &'static str, detail: impl Into<String>) {
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        let floor = state.snapshot.view.saturating_sub(NOTE_VIEWS);
        state.notes.retain(|(_, noted), _| *noted > floor);
        state.notes.insert((step, view), (reason, detail.into()));
    }

    /// `step` of `view` ended, successfully or under its last note.
    pub fn settle(&self, step: Step, view: u64, succeeded: bool) {
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        let (reason, detail) = state
            .notes
            .remove(&(step, view))
            .unwrap_or(("unexplained", String::new()));
        let decisions = &mut state.decisions;
        let (done, failed, last) = match step {
            Step::Propose => (
                &mut decisions.proposed,
                &mut decisions.declined,
                &mut decisions.last_declined,
            ),
            Step::Verify => (
                &mut decisions.accepted,
                &mut decisions.refused,
                &mut decisions.last_refused,
            ),
        };
        if succeeded {
            *done += 1;
        } else {
            *failed.entry(reason).or_default() += 1;
            *last = Some(Outcome {
                view,
                reason,
                detail,
            });
        }
    }

    fn blocked(&self, peer: FalconPublicKey) {
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
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
                        (
                            vote.proposal.round.epoch().get(),
                            vote.proposal.parent.get(),
                            signature.to_vec(),
                        )
                    })
                } else {
                    None
                };
                self.notarize_vote(
                    vote.view().get(),
                    signer(vote.signer()),
                    vote.proposal.payload.0,
                    evidence,
                );
            }
            Activity::Nullify(vote) => {
                let evidence = if self.keep_votes.load(std::sync::atomic::Ordering::Relaxed) {
                    vote.attestation
                        .signature
                        .get()
                        .map(|signature| (vote.round.epoch().get(), signature.to_vec()))
                } else {
                    None
                };
                self.nullify_vote(vote.view().get(), signer(vote.signer()), evidence);
            }
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
        Self {
            liveness: self.liveness.clone(),
        }
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
        Self {
            finalizer: self.finalizer.clone(),
            store: self.store.clone(),
            liveness: self.liveness.clone(),
        }
    }
}

impl<Fin: FrameFinalizer> FalconReporter<Fin> {
    pub fn new(finalizer: Arc<Fin>, store: BlockStore) -> Self {
        Self {
            finalizer,
            store,
            liveness: None,
        }
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
                self.store.certified(&digest, view);
                let bytes = self.store.get(&digest);
                self.finalizer.on_notarized(view, digest, bytes);
            }
            Activity::Certification(n) => {
                self.store
                    .certified(&n.proposal.payload, n.proposal.round.view().get());
            }
            Activity::Nullification(n) => {
                self.store.observe_certificate(n.round.view().get());
            }
            Activity::Finalization(f) => {
                let digest = f.proposal.payload;
                let view: u64 = f.proposal.round.view().get();
                self.store.certified(&digest, view);
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
                // Views far below this one, and below what a finalizer still
                // holds (`BlockStore::hold_from`), leave the store's window.
                self.store.finalized(view);
            }
            Activity::ConflictingNotarize(_)
            | Activity::ConflictingFinalize(_)
            | Activity::NullifyFinalize(_) => {
                self.finalizer.on_equivocation(0);
            }
            // Individual votes and nullifies are not surfaced to the
            // Quilibrium layer (simplex handles quorum internally).
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
mod block_store_bound_tests {
    use super::*;

    fn digest_n(n: u32) -> Digest {
        let mut identity = [0u8; 32];
        identity[..4].copy_from_slice(&n.to_be_bytes());
        identity[31] = 0xb5;
        digest_from_identity(identity)
    }

    fn held(store: &BlockStore, digests: impl IntoIterator<Item = u32>) -> usize {
        digests
            .into_iter()
            .filter(|n| store.get(&digest_n(*n)).is_some())
            .count()
    }

    /// Candidate bytes are capped as well as their count.
    #[test]
    fn candidate_bytes_are_capped() {
        let limits = BlockStoreLimits {
            max_candidate_bytes: 64 << 10,
            ..BlockStoreLimits::default()
        };
        let store = BlockStore::with_limits(limits, "test");
        for n in 1..=100 {
            store.put(digest_n(n), vec![3; 4 << 10]);
        }
        assert_eq!(store.usage(), (16, 64 << 10));
        assert_eq!(held(&store, 85..=100), 16);
    }

    /// A finalization drops the blocks more than `keep_views` below it and
    /// keeps the rest, certified or not.
    #[test]
    fn finalization_drops_only_blocks_below_the_window() {
        let limits = BlockStoreLimits {
            keep_views: 10,
            ..BlockStoreLimits::default()
        };
        let store = BlockStore::with_limits(limits, "test");
        for view in 1..=30u32 {
            store.observe_certificate(view.into());
            store.put(digest_n(view), vec![view as u8; 8]);
            if view % 2 == 0 {
                store.certified(&digest_n(view), view.into());
            }
        }
        store.finalized(30);
        assert_eq!(held(&store, 1..=19), 0);
        assert_eq!(held(&store, 20..=30), 11);
        assert_eq!(store.usage(), (11, 88));
        // An older finalization reported late prunes nothing more.
        store.finalized(25);
        assert_eq!(store.usage().0, 11);
    }

    /// A block restored at startup, before any certificate, takes the view
    /// of the first one, so that finalization does not drop it.
    #[test]
    fn blocks_restored_before_any_certificate_survive_the_first_finalization() {
        let limits = BlockStoreLimits {
            keep_views: 10,
            ..BlockStoreLimits::default()
        };
        let store = BlockStore::with_limits(limits, "test");
        store.put(digest_n(1), vec![1; 8]);
        store.seal(digest_n(2), vec![2; 8]);
        store.finalized(500);
        assert_eq!(held(&store, 1..=2), 2);
        store.finalized(600);
        assert_eq!(held(&store, 1..=2), 0);
    }

    /// Over the byte cap, candidates go first, then vouched blocks of old
    /// views; verified or certified blocks of the latest views stay even
    /// when they alone exceed the cap.
    #[test]
    fn over_the_byte_cap_recent_vouched_blocks_stay() {
        let limits = BlockStoreLimits {
            keep_views: 1000,
            protected_views: 2,
            max_bytes: 10 << 10,
            ..BlockStoreLimits::default()
        };
        let store = BlockStore::with_limits(limits, "test");
        store.observe_certificate(1);
        store.seal(digest_n(1), vec![1; 3 << 10]);
        store.observe_certificate(10);
        store.seal(digest_n(2), vec![2; 3 << 10]);
        store.put(digest_n(3), vec![3; 2 << 10]);
        store.put(digest_n(4), vec![4; 2 << 10]);
        assert_eq!(held(&store, 1..=4), 4);
        // A certified candidate is vouched for: the plain candidate goes.
        store.certified(&digest_n(4), 10);
        store.put(digest_n(5), vec![5; 2 << 10]);
        assert!(store.get(&digest_n(3)).is_none());
        assert_eq!(held(&store, [1, 2, 4, 5]), 4);
        // Room for a recent verified block: the last candidate, then the
        // verified block of view 1 (below the protected views) go.
        store.seal(digest_n(6), vec![6; 4 << 10]);
        assert_eq!(held(&store, [1, 3, 5]), 0);
        assert_eq!(held(&store, [2, 4, 6]), 3);
        // Protected blocks alone may exceed the cap.
        store.seal(digest_n(7), vec![7; 4 << 10]);
        assert_eq!(held(&store, [2, 4, 6, 7]), 4);
        assert_eq!(store.usage(), (4, 13 << 10));
    }

    /// A reader still taking finalized bodies holds the window at the lowest
    /// view it has to take; once it lets go, the next finalization prunes.
    #[test]
    fn a_hold_keeps_bodies_a_reader_has_not_taken() {
        let limits = BlockStoreLimits {
            keep_views: 10,
            ..BlockStoreLimits::default()
        };
        let store = BlockStore::with_limits(limits, "test");
        let pending = Arc::new(std::sync::Mutex::new(Some(5u64)));
        let hold = pending.clone();
        store.hold_from(Arc::new(move || *hold.lock().unwrap()));
        for view in 1..=30u32 {
            store.observe_certificate(view.into());
            store.put(digest_n(view), vec![view as u8; 8]);
            store.certified(&digest_n(view), view.into());
        }
        store.finalized(30);
        assert_eq!(held(&store, 1..=30), 30);
        *pending.lock().unwrap() = None;
        store.finalized(31);
        assert_eq!(held(&store, 1..=20), 0);
        assert_eq!(held(&store, 21..=30), 10);
    }

    /// A body that arrives after a certificate named it is stored as a
    /// certified block, not as an evictable candidate.
    #[test]
    fn a_body_arriving_after_its_certificate_is_kept_as_certified() {
        let limits = BlockStoreLimits {
            max_candidate_blocks: 4,
            ..BlockStoreLimits::default()
        };
        let store = BlockStore::with_limits(limits, "test");
        store.observe_certificate(10);
        store.certified(&digest_n(1), 10);
        store.put(digest_n(1), vec![1; 8]);
        for n in 2..=20 {
            store.put(digest_n(n), vec![2; 8]);
        }
        assert_eq!(
            store.get_with_verification(&digest_n(1)),
            Some((vec![1; 8], false))
        );
        assert_eq!(held(&store, 2..=20), 4);
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
        assert_eq!(
            seen.best,
            ViewTally {
                view: 7,
                notarize: 5,
                proposals: 2,
                nullify: 0,
                finalize: 1
            }
        );
        assert_eq!(
            seen.current,
            ViewTally {
                view: 8,
                notarize: 0,
                proposals: 0,
                nullify: 3,
                finalize: 0
            }
        );
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
        let set = |signers: &[u32]| {
            signers
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
        };
        assert_eq!(
            liveness.view_signers(7),
            Some(ViewSigners {
                view: 7,
                notarize: set(&[0, 2, 3]),
                nullify: set(&[4, 5]),
                finalize: set(&[0])
            }),
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
        liveness.note(
            Step::Propose,
            3,
            "leader not ready to build on the parent",
            "frame 0",
        );
        liveness.settle(Step::Propose, 3, false);
        liveness.note(Step::Propose, 4, "parent unavailable", "not yet");
        liveness.settle(Step::Propose, 4, true);
        liveness.note(
            Step::Verify,
            4,
            "pre-state root differs",
            "phase vertex adds",
        );
        liveness.settle(Step::Verify, 4, false);
        liveness.settle(Step::Verify, 5, false);
        liveness.settle(Step::Verify, 6, true);
        let decided = liveness.decisions();
        assert_eq!(decided.proposed, 1);
        assert_eq!(
            decided.declined.into_iter().collect::<Vec<_>>(),
            vec![("leader not ready to build on the parent", 1)]
        );
        assert_eq!(
            decided.last_declined.map(|o| (o.view, o.detail)),
            Some((3, "frame 0".to_string()))
        );
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
        assert!(
            liveness
                .unbound_warned
                .load(std::sync::atomic::Ordering::Relaxed),
            "an unbound store warns once"
        );
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
                epoch: 3,
                view: 7,
                parent: 6,
                payload: [1; 32],
                votes: vec![(0, vec![0xa0]), (2, vec![0xa2])],
                body: b"body".to_vec(),
            }],
            "a signer's first vote stays",
        );
        let key = |view, parent, payload, signer| NotarizeKey {
            epoch: 3,
            view,
            parent,
            payload,
            signer,
        };
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
                crate::falcon_base::FalconPrivateKey::from_bytes(
                    key.private_key(),
                    key.public_key(),
                )
                .unwrap()
            })
            .collect();
        keys.sort_by_key(|key| key.public_key().as_ref().to_vec());
        let participants: Set<_> = keys
            .iter()
            .map(|key| key.public_key())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let scheme = SimplexFalconScheme::signer(b"test", participants, keys[1].clone()).unwrap();
        let proposal = Proposal::new(
            Round::new(Epoch::new(3), View::new(9)),
            View::new(5),
            digest_from_identity([4; 32]),
        );
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
        let key = NotarizeKey {
            epoch: 3,
            view: 9,
            parent: 5,
            payload: [4; 32],
            signer: 1,
        };
        assert_eq!(
            votes,
            vec![(
                key,
                Some(vote.attestation.signature.get().unwrap().to_vec())
            )]
        );
        let listed = Proposal::new(
            Round::new(Epoch::new(key.epoch), View::new(key.view)),
            View::new(key.parent),
            digest_from_identity(key.payload),
        );
        assert!(
            scheme.verify_notarize(&listed, &vote.attestation),
            "the listed vote verifies as consensus checks it"
        );
    }

    /// A nullify vote consensus reports keeps its round and signature when
    /// presence reports ask for votes, so it verifies again from what
    /// [`Liveness`] returns; otherwise it is only counted.
    #[test]
    fn a_reported_nullify_keeps_its_round_and_signature_when_asked() {
        use commonware_consensus::simplex::types::Nullify;
        use commonware_consensus::types::{Epoch, Round, View};
        let (scheme, _) = signed_notarize();
        let vote =
            Nullify::sign::<Digest>(&scheme, Round::new(Epoch::new(3), View::new(11))).unwrap();
        let liveness = Liveness::default();
        liveness.observe(&Activity::Nullify(vote.clone()));
        assert_eq!(liveness.snapshot().nullify_votes, 1, "the vote is counted");
        assert!(
            liveness.nullify_votes(|_| true).is_empty(),
            "and its signature not kept"
        );
        liveness.keep_votes(true);
        liveness.observe(&Activity::Nullify(vote.clone()));
        let key = NullifyKey {
            epoch: 3,
            view: 11,
            signer: 1,
        };
        let signature = vote.attestation.signature.get().unwrap().to_vec();
        assert_eq!(
            liveness.nullify_votes(|_| true),
            vec![(key, Some(signature))]
        );
        assert_eq!(liveness.nullify_votes(|_| false), vec![(key, None)]);
        assert!(
            scheme.verify_nullify(&vote),
            "the listed vote verifies as consensus checks it"
        );
    }

    /// Unless presence reports ask for them, notarize votes are only
    /// counted: no signature is kept.
    #[test]
    fn notarize_signatures_are_kept_only_when_asked() {
        let (_, vote) = signed_notarize();
        let liveness = Liveness::default();
        liveness.observe(&Activity::Notarize(vote.clone()));
        assert_eq!(liveness.snapshot().notarize_votes, 1, "the vote is counted");
        assert!(
            liveness.notarize_votes(|_| true).is_empty(),
            "and its signature not kept"
        );
        assert!(liveness
            .inner
            .lock()
            .unwrap()
            .views
            .values()
            .all(|votes| votes.evidence.is_empty()));
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
        assert!(
            liveness.notarized().is_empty(),
            "the bodies went with their store"
        );
    }

    #[test]
    fn blocked_messages_are_counted_with_their_distinct_peers() {
        use commonware_cryptography::Signer as _;
        use commonware_math::algebra::Random as _;
        use commonware_p2p::Blocker as _;
        let liveness = Arc::new(Liveness::default());
        let mut blocker = CountingBlocker::new(Some(liveness.clone()));
        let peers: Vec<_> = (0..2)
            .map(|_| {
                crate::falcon_base::FalconPrivateKey::random(commonware_utils::test_rng())
                    .public_key()
            })
            .collect();
        for peer in [&peers[0], &peers[0], &peers[1]] {
            blocker.block((*peer).clone());
        }
        let seen = liveness.snapshot();
        assert_eq!((seen.blocked, seen.blocked_peers), (3, 2));
    }
}

#[cfg(test)]
mod block_store_flood_reproducer {
    use super::*;

    fn candidate(n: u32) -> Digest {
        let mut identity = [0u8; 32];
        identity[..4].copy_from_slice(&n.to_be_bytes());
        identity[31] = 0xf1;
        digest_from_identity(identity)
    }

    /// A peer that sends GLOBAL blocks under distinct digests (any decodable
    /// frame with a fresh `output`) has each stored as a candidate. The store
    /// must stay bounded (at most 1024 candidates by default) and keep the
    /// verified block consensus still needs.
    #[test]
    fn reproduces_unbounded_candidate_flood() {
        let store = BlockStore::new();
        let verified = candidate(0);
        store.seal(verified, vec![1; 1024]);
        let flood: u32 = 4096;
        for n in 1..=flood {
            store.put(candidate(n), vec![2; 64]);
        }
        let held = (1..=flood)
            .filter(|n| store.get(&candidate(*n)).is_some())
            .count();
        assert!(
            held <= 1024,
            "block store grows without bound: it holds all {held} of {flood} flooded peer \
             candidates"
        );
        assert!(
            store.get(&candidate(flood)).is_some(),
            "the newest candidate was evicted before older flood candidates"
        );
        assert_eq!(
            store.get_with_verification(&verified),
            Some((vec![1; 1024], true)),
            "the flood displaced the verified block"
        );
    }
}

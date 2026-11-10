//! Crash safety of the simplex vote journal at every write.
//!
//! One member of a four-member committee is crashed before each storage
//! operation on its vote journal in turn (open, write, resize, sync, remove),
//! as a power cut would: the operation and every later one never run, and
//! every write it had not synced is lost. It restarts at once from what was
//! synced, runs cut off from the others for a while, so it acts on its
//! journal alone, and is then reconnected. It must (a) never sign a vote that
//! conflicts with one it signed before the crash and (b) recover and finalize
//! again.
//!
//! Its journal uses 16-byte pages and no write buffer, so every vote or
//! certificate appended reaches storage as its own write and a crash lands
//! between any two appends. The deterministic runtime's storage hands a
//! reopened blob only its synced bytes. Votes are read from the member's
//! outbound queue, so a conflicting vote is caught even after the other
//! members have moved past its view.
//!
//! The other members run on through the crash. A second run keeps a fourth
//! member silent, so every view it leads is nullified and the crashed member
//! is needed for every quorum. A third cuts the member off until the others
//! are past its activity window, so the first finalization it hears prunes
//! the views it voted in, and crashes it at each operation after that.
//!
//! The simplex unit tests live in `commonware-consensus`, which the workspace
//! excludes, so CI runs this one. It uses ed25519 and the simplex mocks.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use commonware_codec::DecodeExt as _;
use commonware_consensus::simplex::scheme::ed25519;
use commonware_consensus::simplex::types::{Proposal, Vote};
use commonware_consensus::simplex::{
    elector::RoundRobin, mocks, Config, Engine, Floor, ForwardingPolicy,
};
use commonware_consensus::types::{Epoch, View, ViewDelta};
use commonware_cryptography::certificate::mocks::Fixture;
use commonware_cryptography::ed25519::PublicKey;
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_cryptography::Sha256;
use commonware_parallel::Sequential;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_runtime::{
    deterministic, signal, Blob, BufferPool, BufferPooler, Clock, Error, Handle, IoBufs, IoBufsMut,
    Metrics, Name, Runner as _, Spawner, Storage, Supervisor,
};
use commonware_utils::{ordered::Set, test_rng, NZUsize, NZU16};
use quil_cw_consensus::p2p_bridge::{
    build_channel, build_vote_channel, inbound_message, Message, NoopBlocker, Outbound,
};
use tokio::sync::mpsc;

const MEMBERS: usize = 4;
/// The member that crashes.
const TARGET: usize = 0;
/// Crash points per run: about five views of the target's journal writes,
/// so at least one view it leads.
const CRASH_POINTS: u64 = 64;
/// Views every member finalizes before the crash is armed.
const WARM_UP: u64 = 4;
/// Views the restarted member must finalize beyond its last pre-crash vote.
const RECOVERY: u64 = 5;

type Scheme = ed25519::Scheme;
type SentVote = Vote<Scheme, Sha256Digest>;
type MockReporter =
    mocks::reporter::Reporter<deterministic::Context, Scheme, RoundRobin, Sha256Digest>;

/// A storage operation on the target's journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Op {
    Open,
    Write,
    WriteSync,
    Resize,
    Sync,
    Remove,
}

#[derive(Default)]
struct HookState {
    ops: u64,
    crash_before: Option<u64>,
    crashed: Option<Op>,
}

/// Counts the target's journal operations and stops the one it crashes at.
struct Hook {
    partition: String,
    state: Mutex<HookState>,
}

impl Hook {
    fn new(partition: String) -> Arc<Self> {
        Arc::new(Self {
            partition,
            state: Mutex::default(),
        })
    }

    /// Counts `op`; false once the member has crashed, at `op` or before.
    fn admit(&self, op: Op) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.crashed.is_some() {
            return false;
        }
        state.ops += 1;
        if state.crash_before == Some(state.ops) {
            state.crashed = Some(op);
            return false;
        }
        true
    }

    async fn gate(&self, op: Op) {
        if !self.admit(op) {
            // The process is gone: this operation and every later one never run.
            std::future::pending::<()>().await;
        }
    }

    /// Crash before the `nth` operation from now (1 = the next one).
    fn arm(&self, nth: u64) {
        let mut state = self.state.lock().unwrap();
        state.crash_before = Some(state.ops + nth);
    }

    fn crashed(&self) -> Option<Op> {
        self.state.lock().unwrap().crashed
    }

    fn restart(&self) {
        let mut state = self.state.lock().unwrap();
        state.crashed = None;
        state.crash_before = None;
    }
}

type InnerBlob = <deterministic::Context as Storage>::Blob;

#[derive(Clone)]
struct CrashBlob {
    inner: InnerBlob,
    hook: Option<Arc<Hook>>,
}

impl CrashBlob {
    async fn gate(&self, op: Op) {
        if let Some(hook) = &self.hook {
            hook.gate(op).await;
        }
    }
}

impl Blob for CrashBlob {
    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.inner.read_at(offset, len).await
    }

    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        self.inner.read_at_buf(offset, len, bufs).await
    }

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        self.gate(Op::Write).await;
        self.inner.write_at(offset, bufs).await
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        self.gate(Op::WriteSync).await;
        self.inner.write_at_sync(offset, bufs).await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.gate(Op::Resize).await;
        self.inner.resize(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.gate(Op::Sync).await;
        self.inner.sync().await
    }

    async fn start_sync(&self) -> Handle<()> {
        self.gate(Op::Sync).await;
        self.inner.start_sync().await
    }
}

/// The deterministic runtime with the target's journal storage hooked; every
/// other capability is forwarded unchanged.
struct CrashCtx {
    inner: deterministic::Context,
    hook: Option<Arc<Hook>>,
}

impl CrashCtx {
    fn hook_for(&self, partition: &str) -> Option<Arc<Hook>> {
        self.hook
            .as_ref()
            .filter(|hook| hook.partition == partition)
            .cloned()
    }
}

impl Storage for CrashCtx {
    type Blob = CrashBlob;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: RangeInclusive<u16>,
    ) -> Result<(CrashBlob, u64, u16), Error> {
        let hook = self.hook_for(partition);
        if let Some(hook) = &hook {
            hook.gate(Op::Open).await;
        }
        let (inner, len, version) = self.inner.open_versioned(partition, name, versions).await?;
        Ok((CrashBlob { inner, hook }, len, version))
    }

    async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
        if let Some(hook) = self.hook_for(partition) {
            hook.gate(Op::Remove).await;
        }
        self.inner.remove(partition, name).await
    }

    async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.inner.scan(partition).await
    }
}

impl Supervisor for CrashCtx {
    fn name(&self) -> Name {
        self.inner.name()
    }
    fn child(&self, label: &'static str) -> Self {
        Self {
            inner: self.inner.child(label),
            hook: self.hook.clone(),
        }
    }
    fn with_attribute(self, key: &'static str, value: impl std::fmt::Display) -> Self {
        Self {
            inner: self.inner.with_attribute(key, value),
            hook: self.hook,
        }
    }
}

impl Spawner for CrashCtx {
    fn shared(self, blocking: bool) -> Self {
        Self {
            inner: self.inner.shared(blocking),
            hook: self.hook,
        }
    }
    fn dedicated(self) -> Self {
        Self {
            inner: self.inner.dedicated(),
            hook: self.hook,
        }
    }
    fn spawn<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let hook = self.hook;
        self.inner.spawn(move |inner| f(Self { inner, hook }))
    }
    async fn stop(self, value: i32, timeout: Option<Duration>) -> Result<(), Error> {
        self.inner.stop(value, timeout).await
    }
    fn stopped(&self) -> signal::Signal {
        self.inner.stopped()
    }
}

impl Metrics for CrashCtx {
    fn register<
        N: Into<String>,
        H: Into<String>,
        M: commonware_runtime::telemetry::metrics::Metric,
    >(
        &self,
        name: N,
        help: H,
        metric: M,
    ) -> commonware_runtime::telemetry::metrics::Registered<M> {
        self.inner.register(name, help, metric)
    }
    fn encode(&self) -> String {
        self.inner.encode()
    }
}

impl governor::clock::Clock for CrashCtx {
    type Instant = SystemTime;
    fn now(&self) -> Self::Instant {
        governor::clock::Clock::now(&self.inner)
    }
}
impl governor::clock::ReasonablyRealtime for CrashCtx {}
impl Clock for CrashCtx {
    fn current(&self) -> SystemTime {
        self.inner.current()
    }
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
        self.inner.sleep(duration)
    }
    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
        self.inner.sleep_until(deadline)
    }
}

impl BufferPooler for CrashCtx {
    fn network_buffer_pool(&self) -> &BufferPool {
        self.inner.network_buffer_pool()
    }
    fn storage_buffer_pool(&self) -> &BufferPool {
        self.inner.storage_buffer_pool()
    }
}

impl rand_core::TryRng for CrashCtx {
    type Error = <deterministic::Context as rand_core::TryRng>::Error;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.inner.try_next_u32()
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.inner.try_next_u64()
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.try_fill_bytes(bytes)
    }
}
impl rand_core::TryCryptoRng for CrashCtx {}

type Inbox = [mpsc::UnboundedSender<Message<PublicKey>>; 3];

/// Delivers each member's outbound messages at once and records every vote
/// the target sends.
struct Net {
    keys: Vec<PublicKey>,
    inboxes: Mutex<Vec<Option<Inbox>>>,
    /// The target is cut off: nothing it sends is delivered, nothing reaches it.
    cut: AtomicBool,
    /// (incarnation, vote), in send order.
    sent: Mutex<Vec<(usize, SentVote)>>,
}

impl Net {
    fn route(
        self: &Arc<Self>,
        context: &deterministic::Context,
        from: usize,
        incarnation: usize,
        mut out: mpsc::UnboundedReceiver<Outbound<PublicKey>>,
    ) {
        let net = self.clone();
        context.child("router").spawn(move |_| async move {
            while let Some(message) = out.recv().await {
                net.deliver(from, incarnation, message);
            }
        });
    }

    fn deliver(&self, from: usize, incarnation: usize, message: Outbound<PublicKey>) {
        if from == TARGET && message.channel == 0 {
            let vote = SentVote::decode(message.bytes.as_slice()).expect("own vote");
            self.sent.lock().unwrap().push((incarnation, vote));
        }
        let cut = self.cut.load(Ordering::SeqCst);
        let channel = usize::try_from(message.channel).unwrap();
        let inboxes = self.inboxes.lock().unwrap();
        for to in &message.recipients {
            let index = self.keys.iter().position(|key| key == to).unwrap();
            if cut && (from == TARGET || index == TARGET) {
                continue;
            }
            if let Some(inbox) = &inboxes[index] {
                let _ = inbox[channel].send(inbound_message(
                    self.keys[from].clone(),
                    message.bytes.clone(),
                ));
            }
        }
    }

    /// Highest view the target voted in during `incarnation`.
    fn last_vote(&self, incarnation: usize) -> Option<View> {
        let sent = self.sent.lock().unwrap();
        sent.iter()
            .filter(|(i, _)| *i == incarnation)
            .map(|(_, vote)| vote_view(vote))
            .max()
    }

    /// Whether the target sent a finalize vote above `view` in `incarnation`.
    fn finalized_above(&self, incarnation: usize, view: View) -> bool {
        let sent = self.sent.lock().unwrap();
        sent.iter().any(|(i, vote)| {
            *i == incarnation && matches!(vote, Vote::Finalize(f) if f.proposal.round.view() > view)
        })
    }

    /// (a): no two votes of the target conflict, across all incarnations.
    fn assert_no_conflicting_votes(&self) {
        let sent = self.sent.lock().unwrap();
        let mut notarized: BTreeMap<View, BTreeSet<Proposal<Sha256Digest>>> = BTreeMap::new();
        let mut finalized: BTreeMap<View, BTreeSet<Proposal<Sha256Digest>>> = BTreeMap::new();
        let mut nullified: BTreeSet<View> = BTreeSet::new();
        for (_, vote) in sent.iter() {
            match vote {
                Vote::Notarize(v) => {
                    let view = v.proposal.round.view();
                    notarized
                        .entry(view)
                        .or_default()
                        .insert(v.proposal.clone());
                }
                Vote::Finalize(v) => {
                    let view = v.proposal.round.view();
                    finalized
                        .entry(view)
                        .or_default()
                        .insert(v.proposal.clone());
                }
                Vote::Nullify(v) => {
                    nullified.insert(v.round.view());
                }
            }
        }
        let history = || -> Vec<String> {
            sent.iter()
                .map(|(i, vote)| format!("incarnation {i}: {}", describe(vote)))
                .collect()
        };
        for (view, proposals) in &notarized {
            assert!(
                proposals.len() == 1,
                "conflicting votes: two notarizes at view {view}: {:#?}",
                history()
            );
        }
        for (view, proposals) in &finalized {
            assert!(
                proposals.len() == 1,
                "conflicting votes: two finalizes at view {view}: {:#?}",
                history()
            );
            assert!(
                !nullified.contains(view),
                "conflicting votes: nullify and finalize at view {view}: {:#?}",
                history()
            );
        }
    }
}

fn vote_view(vote: &SentVote) -> View {
    match vote {
        Vote::Notarize(v) => v.proposal.round.view(),
        Vote::Finalize(v) => v.proposal.round.view(),
        Vote::Nullify(v) => v.round.view(),
    }
}

fn describe(vote: &SentVote) -> String {
    match vote {
        Vote::Notarize(v) => format!("notarize {:?}", v.proposal),
        Vote::Finalize(v) => format!("finalize {:?}", v.proposal),
        Vote::Nullify(v) => format!("nullify view {}", v.round.view()),
    }
}

fn partition(index: usize) -> String {
    format!("crash-points-{index}")
}

struct Member {
    engine: Handle<()>,
    application: Handle<()>,
}

struct Committee {
    epoch: Epoch,
    schemes: Vec<Scheme>,
    relay: Arc<mocks::relay::Relay<Sha256Digest, PublicKey>>,
    reporters: Vec<MockReporter>,
    net: Arc<Net>,
    /// Never started: every view it leads is nullified.
    silent: Option<usize>,
}

impl Committee {
    fn new(context: &deterministic::Context, silent: Option<usize>) -> Self {
        let epoch = Epoch::new(333);
        let Fixture {
            participants,
            schemes,
            ..
        } = ed25519::fixture(&mut test_rng(), b"journal-crash-points", MEMBERS as u32);
        let members: Set<PublicKey> = participants.clone().try_into().unwrap();
        let reporters = (0..MEMBERS)
            .map(|index| {
                mocks::reporter::Reporter::new(
                    context.child("reporter").with_attribute("index", index),
                    mocks::reporter::Config {
                        participants: members.clone(),
                        scheme: schemes[index].clone(),
                        elector: RoundRobin::<Sha256>::default(),
                    },
                )
            })
            .collect();
        let net = Arc::new(Net {
            inboxes: Mutex::new(vec![None; participants.len()]),
            keys: participants,
            cut: AtomicBool::new(false),
            sent: Mutex::default(),
        });
        Self {
            epoch,
            schemes,
            relay: Arc::new(mocks::relay::Relay::new()),
            reporters,
            net,
            silent,
        }
    }

    fn live(&self) -> impl Iterator<Item = usize> + '_ {
        (0..MEMBERS).filter(move |index| Some(*index) != self.silent)
    }

    /// Highest view `index`'s reporter saw finalized.
    fn finalized(&self, index: usize) -> View {
        let finalizations = self.reporters[index].finalizations.lock();
        finalizations.keys().max().copied().unwrap_or(View::zero())
    }

    fn start(
        &self,
        context: &deterministic::Context,
        index: usize,
        incarnation: usize,
        hook: Option<Arc<Hook>>,
    ) -> Member {
        let keys = &self.net.keys;
        let me = keys[index].clone();
        let context = context
            .child("member")
            .with_attribute("index", index)
            .with_attribute("incarnation", incarnation);
        let peers: Arc<[PublicKey]> = keys.iter().filter(|key| **key != me).cloned().collect();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let votes = build_vote_channel(0, peers.clone(), out_tx.clone(), Some(me.clone()));
        let certificates = build_channel(1, peers.clone(), out_tx.clone());
        let resolver = build_channel(2, peers, out_tx);
        self.net.inboxes.lock().unwrap()[index] = Some([
            votes.inbound_tx.clone(),
            certificates.inbound_tx.clone(),
            resolver.inbound_tx.clone(),
        ]);
        self.net.route(&context, index, incarnation, out_rx);

        let (actor, application) = mocks::application::Application::new(
            context.child("application"),
            mocks::application::Config {
                hasher: Sha256::default(),
                relay: self.relay.clone(),
                me,
                propose_latency: (10.0, 5.0),
                verify_latency: (10.0, 5.0),
                certify_latency: (10.0, 5.0),
                should_certify: mocks::application::Certifier::Always,
            },
        );
        let application_handle = actor.start();
        // The hooked journal: one append per storage write (see module doc).
        let (page_cache, write_buffer) = if hook.is_some() {
            (
                CacheRef::from_pooler(&context, NZU16!(16), NZUsize!(64)),
                NZUsize!(1),
            )
        } else {
            (
                CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10)),
                NZUsize!(1024 * 1024),
            )
        };
        let engine = Engine::new(
            CrashCtx {
                inner: context.child("engine"),
                hook,
            },
            Config {
                scheme: self.schemes[index].clone(),
                elector: RoundRobin::<Sha256>::default(),
                blocker: NoopBlocker::<PublicKey>::default(),
                automaton: application.clone(),
                relay: application,
                reporter: self.reporters[index].clone(),
                strategy: Sequential,
                partition: partition(index),
                mailbox_size: NZUsize!(1024),
                epoch: self.epoch,
                floor: Floor::Genesis(mocks::application::genesis::<Sha256>(self.epoch)),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(10),
                fetch_timeout: Duration::from_secs(1),
                // Short, so crash points include pruning of old views.
                activity_timeout: ViewDelta::new(4),
                skip_timeout: ViewDelta::new(2),
                fetch_concurrent: NZUsize!(4),
                replay_buffer: NZUsize!(1024 * 1024),
                write_buffer,
                page_cache,
                forwarding: ForwardingPolicy::Disabled,
            },
        );
        let engine = engine.start(
            (votes.sender, votes.receiver),
            (certificates.sender, certificates.receiver),
            (resolver.sender, resolver.receiver),
        );
        Member {
            engine,
            application: application_handle,
        }
    }
}

/// Waits until `done`, checking (a) at every poll so a conflicting vote fails
/// with its own message even if the run then stalls.
async fn wait_for(
    context: &deterministic::Context,
    net: &Net,
    what: &str,
    limit: Duration,
    mut done: impl FnMut() -> bool,
) {
    let deadline = context.current() + limit;
    loop {
        net.assert_no_conflicting_votes();
        if done() {
            return;
        }
        assert!(context.current() < deadline, "{what}: not within {limit:?}");
        context.sleep(Duration::from_millis(10)).await;
    }
}

/// How the committee runs around the crash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    /// All four members run.
    AllLive,
    /// The fourth member never starts.
    Silent,
    /// The target is cut off until the others finalize `CATCH_UP` more views,
    /// then crashed at each operation after it hears from them again.
    CatchUp,
}

/// Views the others finalize while the target is cut off: well past its
/// activity window of 4, so the first finalization it hears prunes its votes.
const CATCH_UP: u64 = 12;
/// How long the restarted target runs cut off: longer than its 1 s leader
/// timeout, so it proposes or nullifies in the view its journal puts it in.
const ALONE: Duration = Duration::from_secs(3);

/// Crashes the target before the `point`-th journal operation after warm-up,
/// restarts it, and checks (a) and (b). Returns the operation it crashed at.
fn crash_at(point: u64, scenario: Scenario) -> Op {
    deterministic::Runner::timed(Duration::from_secs(1800)).start(|context| async move {
        let silent = (scenario == Scenario::Silent).then_some(MEMBERS - 1);
        let committee = Committee::new(&context, silent);
        let net = committee.net.clone();
        let hook = Hook::new(partition(TARGET));
        let mut members: Vec<Option<Member>> = (0..MEMBERS)
            .map(|index| {
                (Some(index) != silent).then(|| {
                    let hook = (index == TARGET).then(|| hook.clone());
                    committee.start(&context, index, 0, hook)
                })
            })
            .collect();

        wait_for(
            &context,
            &net,
            "warm-up finalization",
            Duration::from_secs(120),
            || {
                committee
                    .live()
                    .all(|index| committee.finalized(index) >= View::new(WARM_UP))
            },
        )
        .await;

        if scenario == Scenario::CatchUp {
            net.cut.store(true, Ordering::SeqCst);
            let behind = committee.finalized(1).get();
            wait_for(
                &context,
                &net,
                "the others finalizing past the target's window",
                Duration::from_secs(300),
                || committee.finalized(1) >= View::new(behind + CATCH_UP),
            )
            .await;
        }

        hook.arm(point);
        net.cut.store(false, Ordering::SeqCst);
        wait_for(
            &context,
            &net,
            &format!("crash point {point}"),
            Duration::from_secs(120),
            || hook.crashed().is_some(),
        )
        .await;
        let op = hook.crashed().unwrap();

        // The process dies: no message reaches it, its tasks stop, and what
        // it had not synced is lost.
        net.inboxes.lock().unwrap()[TARGET] = None;
        let crashed = members[TARGET].take().unwrap();
        crashed.engine.abort();
        crashed.application.abort();
        let _ = crashed.engine.await;
        let _ = crashed.application.await;
        let last_vote = net.last_vote(0);

        // Alone, nothing it hears moves it past the view its journal puts it in.
        hook.restart();
        net.cut.store(true, Ordering::SeqCst);
        members[TARGET] = Some(committee.start(&context, TARGET, 1, Some(hook.clone())));
        let until = context.current() + ALONE;
        wait_for(&context, &net, "restart alone", ALONE * 2, || {
            context.current() >= until
        })
        .await;
        net.cut.store(false, Ordering::SeqCst);

        // (b): it finalizes again, and signs finalize votes again.
        let before = last_vote.unwrap_or(View::zero());
        wait_for(
            &context,
            &net,
            &format!("recovery after a crash at point {point} ({op:?}), last vote {last_vote:?}"),
            Duration::from_secs(600),
            || {
                committee.finalized(TARGET) >= View::new(before.get() + RECOVERY)
                    && net.finalized_above(1, before)
            },
        )
        .await;

        // (a): no vote it signed conflicts with another, before or after.
        net.assert_no_conflicting_votes();
        for index in committee.live() {
            committee.reporters[index].assert_no_faults();
            committee.reporters[index].assert_no_invalid();
        }
        op
    })
}

fn crash_at_every_point(scenario: Scenario) {
    let mut ops = BTreeMap::<Op, u64>::new();
    for point in 1..=CRASH_POINTS {
        *ops.entry(crash_at(point, scenario)).or_default() += 1;
    }
    // Crashes landed before appends, syncs and the pruning of old views.
    let count = |op| ops.get(&op).copied().unwrap_or(0);
    assert!(count(Op::Write) > 0, "no crash before a write: {ops:?}");
    assert!(
        count(Op::Sync) + count(Op::WriteSync) > 0,
        "no crash before a sync: {ops:?}"
    );
    assert!(count(Op::Remove) > 0, "no crash before a prune: {ops:?}");
}

#[test]
fn crash_at_each_journal_write_never_equivocates_and_recovers() {
    crash_at_every_point(Scenario::AllLive);
}

#[test]
fn crash_at_each_journal_write_with_a_silent_member() {
    crash_at_every_point(Scenario::Silent);
}

#[test]
fn crash_after_catching_up_past_the_activity_window() {
    crash_at_every_point(Scenario::CatchUp);
}

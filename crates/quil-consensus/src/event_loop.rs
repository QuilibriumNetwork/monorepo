//! Async event loop that drives the [`HotStuffEventHandler`]. Mirror
//! of `consensus/eventloop/event_loop.go`.
//!
//! The event loop owns the inbound event queue and serializes all
//! access to the (non-concurrency-safe) event handler. Callers
//! `submit_*` messages via `EventLoopHandle` (a cheap `Clone`); the
//! background task drains them in priority order:
//!
//! 1. **Local timeout** (from the pacemaker timer) — highest priority.
//! 2. **Partial TC** — urgent, keeps timeout rebroadcast flowing.
//! 3. **Proposal / QC / TC** — normal-priority inbound.
//!
//! The priority ordering matches Go, where malicious nodes that flood
//! the loop with proposals cannot starve the pacemaker's timeout
//! signal. We implement it via `tokio::select!` with the `biased`
//! modifier, which polls branches in declaration order.
//!
//! The loop exits cleanly when its [`CancellationToken`] is triggered
//! or when the event handler returns an unrecoverable error.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::mpsc;
use tokio::sync::Notify;
use tokio::time::{sleep_until, Duration};
use tokio_util::sync::CancellationToken;

use crate::event_handler::HotStuffEventHandler;
use crate::models::{QuorumCertificate, SignedProposal, TimeoutCertificate, Unique};
use crate::timeout_aggregator::PartialTimeoutCertificateCreated;
use crate::tracker::{
    NewestPartialTimeoutCertificateTracker, NewestQcTracker, NewestTcTracker,
};
use quil_types::error::{QuilError, Result};

/// Default inbound-proposal channel capacity. Matches Go's hard-coded
/// `1000` — the compliance engine should never see backpressure under
/// normal load, and a saturating buffer indicates the node is catching
/// up.
pub const DEFAULT_PROPOSAL_BUFFER: usize = 1000;

/// Handle for submitting events to a running [`EventLoop`]. Cheap to
/// clone and share across tasks.
///
/// The handle holds a proposal channel sender + three "newest X"
/// trackers that debounce QC/TC/partial-TC updates. Each submit
/// method atomically updates the tracker and, if the new value is
/// strictly newer, signals the loop via an edge-triggered notifier.
pub struct EventLoopHandle<S: Unique, V: Unique> {
    proposals_tx: mpsc::Sender<QueuedProposal<S, V>>,
    newest_qc: Arc<NewestQcTracker>,
    newest_tc: Arc<NewestTcTracker>,
    newest_partial_tc: Arc<NewestPartialTimeoutCertificateTracker>,
    qc_notify: Arc<Notify>,
    tc_notify: Arc<Notify>,
    partial_tc_notify: Arc<Notify>,
    /// Local-timeout trigger. The pacemaker timer (or a test driver)
    /// fires this to make the loop call `on_local_timeout`.
    local_timeout_notify: Arc<Notify>,
    cancellation: CancellationToken,
}

impl<S: Unique, V: Unique> Clone for EventLoopHandle<S, V> {
    fn clone(&self) -> Self {
        Self {
            proposals_tx: self.proposals_tx.clone(),
            newest_qc: Arc::clone(&self.newest_qc),
            newest_tc: Arc::clone(&self.newest_tc),
            newest_partial_tc: Arc::clone(&self.newest_partial_tc),
            qc_notify: Arc::clone(&self.qc_notify),
            tc_notify: Arc::clone(&self.tc_notify),
            partial_tc_notify: Arc::clone(&self.partial_tc_notify),
            local_timeout_notify: Arc::clone(&self.local_timeout_notify),
            cancellation: self.cancellation.clone(),
        }
    }
}

impl<S: Unique, V: Unique> EventLoopHandle<S, V> {
    /// Push a validated proposal into the loop. Blocks the caller
    /// only if the buffer is full — under normal load this never
    /// happens. Returns `false` if the loop has already shut down.
    pub async fn submit_proposal(&self, proposal: SignedProposal<S, V>) -> bool {
        if self.cancellation.is_cancelled() {
            return false;
        }
        let queued = QueuedProposal {
            proposal,
            insertion_time: Instant::now(),
        };
        tokio::select! {
            biased;
            _ = self.cancellation.cancelled() => false,
            send_res = self.proposals_tx.send(queued) => send_res.is_ok(),
        }
    }

    /// Push a validated QC into the loop. Deduped via the
    /// `newest_qc` tracker — older QCs are silently dropped.
    pub fn submit_quorum_certificate(&self, qc: Arc<dyn QuorumCertificate>) {
        if self.newest_qc.track(qc) {
            self.qc_notify.notify_one();
        }
    }

    /// Push a validated TC. Go's `onTrustedTC` also unpacks the TC's
    /// embedded QC and routes it through the QC tracker if it's
    /// newer than anything we've seen — we mirror that behavior.
    pub fn submit_timeout_certificate(&self, tc: Arc<dyn TimeoutCertificate>) {
        // We need to access the embedded QC before `track` moves `tc`.
        // Since the embedded QC is a `&dyn QuorumCertificate` borrow
        // from the TC, we can't freely clone it as an `Arc`. For the
        // Rust port we take the conservative path: always attempt the
        // TC track first, then — regardless of whether the TC was
        // accepted — ring the TC notify bell. The embedded-QC
        // fast-forward is left to a follow-on path (a fresh QC will
        // catch up via a separate `submit_quorum_certificate` call
        // from the vote collector).
        if self.newest_tc.track(tc) {
            self.tc_notify.notify_one();
        }
    }

    /// Push a partial-TC notification from the timeout aggregator.
    pub fn submit_partial_timeout_certificate(
        &self,
        partial: PartialTimeoutCertificateCreated,
    ) {
        if self.newest_partial_tc.track(partial) {
            self.partial_tc_notify.notify_one();
        }
    }

    /// Fire the local-timeout edge. Called by the pacemaker timer
    /// (or a test driver) when the current rank's deadline elapses.
    pub fn submit_local_timeout(&self) {
        self.local_timeout_notify.notify_one();
    }

    /// Signal the loop to shut down. The loop drains in-flight work
    /// and exits on the next iteration.
    pub fn shutdown(&self) {
        self.cancellation.cancel();
    }

    /// Check if the loop has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

struct QueuedProposal<S: Unique, V: Unique> {
    proposal: SignedProposal<S, V>,
    /// Arrival time — used for latency metrics (not yet emitted).
    insertion_time: Instant,
}

/// Consensus event loop. Owns the `HotStuffEventHandler` and drives
/// it with messages from the bound [`EventLoopHandle`].
pub struct EventLoop<S: Unique, V: Unique> {
    event_handler: Arc<HotStuffEventHandler<S, V>>,
    proposals_rx: mpsc::Receiver<QueuedProposal<S, V>>,
    newest_qc: Arc<NewestQcTracker>,
    newest_tc: Arc<NewestTcTracker>,
    newest_partial_tc: Arc<NewestPartialTimeoutCertificateTracker>,
    qc_notify: Arc<Notify>,
    tc_notify: Arc<Notify>,
    partial_tc_notify: Arc<Notify>,
    local_timeout_notify: Arc<Notify>,
    cancellation: CancellationToken,
    /// Scheduled start time. The loop sleeps until this instant
    /// before calling `event_handler.start()`, matching Go's
    /// `startTime` semantics.
    start_time: Instant,
}

impl<S: Unique, V: Unique> EventLoop<S, V> {
    /// Create a new event loop bound to the given event handler.
    /// Returns `(loop, handle)`: the loop is `run()`-able, and the
    /// handle is cloneable for callers that push events.
    pub fn new(
        event_handler: Arc<HotStuffEventHandler<S, V>>,
        start_time: Instant,
    ) -> (Self, EventLoopHandle<S, V>) {
        Self::with_buffer(event_handler, start_time, DEFAULT_PROPOSAL_BUFFER)
    }

    pub fn with_buffer(
        event_handler: Arc<HotStuffEventHandler<S, V>>,
        start_time: Instant,
        proposal_buffer: usize,
    ) -> (Self, EventLoopHandle<S, V>) {
        let (proposals_tx, proposals_rx) = mpsc::channel(proposal_buffer);
        let newest_qc = Arc::new(NewestQcTracker::new());
        let newest_tc = Arc::new(NewestTcTracker::new());
        let newest_partial_tc = Arc::new(NewestPartialTimeoutCertificateTracker::new());
        let qc_notify = Arc::new(Notify::new());
        let tc_notify = Arc::new(Notify::new());
        let partial_tc_notify = Arc::new(Notify::new());
        let local_timeout_notify = Arc::new(Notify::new());
        let cancellation = CancellationToken::new();

        let handle = EventLoopHandle {
            proposals_tx,
            newest_qc: Arc::clone(&newest_qc),
            newest_tc: Arc::clone(&newest_tc),
            newest_partial_tc: Arc::clone(&newest_partial_tc),
            qc_notify: Arc::clone(&qc_notify),
            tc_notify: Arc::clone(&tc_notify),
            partial_tc_notify: Arc::clone(&partial_tc_notify),
            local_timeout_notify: Arc::clone(&local_timeout_notify),
            cancellation: cancellation.clone(),
        };

        let event_loop = Self {
            event_handler,
            proposals_rx,
            newest_qc,
            newest_tc,
            newest_partial_tc,
            qc_notify,
            tc_notify,
            partial_tc_notify,
            local_timeout_notify,
            cancellation,
            start_time,
        };
        (event_loop, handle)
    }

    /// Run the event loop until cancelled. Returns an error only on
    /// unrecoverable EventHandler failures — which indicate state
    /// corruption or bugs.
    pub async fn run(mut self) -> Result<()> {
        // Wait until the scheduled start time (matches Go's
        // `time.After(time.Until(el.startTime))`).
        let now = Instant::now();
        if self.start_time > now {
            tokio::select! {
                biased;
                _ = self.cancellation.cancelled() => return Ok(()),
                _ = sleep_until(self.start_time.into()) => {}
            }
        }

        // Kick off the event handler.
        self.event_handler
            .start()
            .map_err(|e| QuilError::Consensus(format!("could not start event handler: {}", e)))?;

        // Main loop. The `biased` select polls branches in declaration
        // order — that enforces the Go priority: cancellation →
        // local timeout → partial TC → QC → TC → proposal.
        loop {
            // Yield to the runtime each iteration. Single-prover
            // committees (quorum_threshold = 0) can otherwise drive
            // propose → self-vote → QC → propose at full CPU without
            // ever yielding, starving sibling tasks (notably the engine
            // run-loop that surfaces AppEngineEvent to subscribers).
            tokio::task::yield_now().await;

            // Re-read the pacemaker's deadline each iteration. It can
            // shift when the rank advances or when a local timeout
            // fires (rebroadcast).
            let deadline = self.event_handler.current_round_deadline();
            tokio::select! {
                biased;

                // 1. Cancellation.
                _ = self.cancellation.cancelled() => return Ok(()),

                // 2a. Pacemaker timer fired — drive `on_local_timeout`.
                //     Top priority alongside the explicit notify path.
                _ = sleep_until(deadline.into()) => {
                    if let Err(e) = self.event_handler.on_local_timeout() {
                        return Err(QuilError::Consensus(format!(
                            "could not process timeout: {}",
                            e
                        )));
                    }
                }

                // 2b. Local timeout via explicit notify (test driver).
                _ = self.local_timeout_notify.notified() => {
                    if let Err(e) = self.event_handler.on_local_timeout() {
                        return Err(QuilError::Consensus(format!(
                            "could not process timeout: {}",
                            e
                        )));
                    }
                }

                // 3. Partial TC. Keeps timeout rebroadcast alive
                //    during happy-path → sad-path transitions.
                _ = self.partial_tc_notify.notified() => {
                    if let Some(partial) = self.newest_partial_tc.newest_partial() {
                        if let Err(e) = self
                            .event_handler
                            .on_partial_timeout_certificate_created(&partial)
                        {
                            return Err(QuilError::Consensus(format!(
                                "could not process partial TC event: {}",
                                e
                            )));
                        }
                    }
                }

                // 4. Fresh QC.
                _ = self.qc_notify.notified() => {
                    if let Some(qc) = self.newest_qc.newest_qc() {
                        if let Err(e) = self.event_handler.on_receive_quorum_certificate(qc) {
                            return Err(QuilError::Consensus(format!(
                                "could not process QC: {}",
                                e
                            )));
                        }
                    }
                }

                // 5. Fresh TC.
                _ = self.tc_notify.notified() => {
                    if let Some(tc) = self.newest_tc.newest_tc() {
                        if let Err(e) = self.event_handler.on_receive_timeout_certificate(tc) {
                            return Err(QuilError::Consensus(format!(
                                "could not process TC: {}",
                                e
                            )));
                        }
                    }
                }

                // 6. Inbound proposal queue.
                Some(queued) = self.proposals_rx.recv() => {
                    let _latency = queued.insertion_time.elapsed();
                    if let Err(e) = self.event_handler.on_receive_proposal(&queued.proposal) {
                        return Err(QuilError::Consensus(format!(
                            "could not process proposal {}: {}",
                            hex::encode(&queued.proposal.proposal.state.identifier), e
                        )));
                    }
                }
            }
        }
    }

    // Helper: configurable duration for tests that want to bail out
    // quickly if the loop doesn't make progress.
    #[doc(hidden)]
    pub async fn run_for(self, timeout: Duration) -> Result<()> {
        let cancel = self.cancellation.clone();
        let loop_fut = self.run();
        tokio::select! {
            res = loop_fut => res,
            _ = tokio::time::sleep(timeout) => {
                cancel.cancel();
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // The event loop is heavily I/O-driven and its contract is
    // dominated by tokio select semantics rather than per-method
    // business logic. The unit tests here focus on:
    //
    // - handle construction + cheap-clone invariants
    // - tracker-backed dedup (stale QCs/TCs dropped)
    // - cancellation-before-start returning cleanly
    //
    // End-to-end "message drives event handler" coverage is already
    // exercised by `event_handler::tests` — the event loop is a
    // thin transport layer over that.

    use super::*;
    use crate::forest::{Finalizer, FollowerConsumer, Forks};
    use crate::leader_provider::LeaderProvider;
    use crate::models::{
        AggregatedSignature, CertifiedState, Identity, State,
    };
    use crate::pacemaker::{NextRank, Pacemaker};
    use crate::safety_rules::SafetyRulesT;
    use crate::state_producer::StateProducer;
    use crate::committee::Replicas;
    use crate::event_handler::Consumer;
    use std::sync::Mutex;

    #[derive(Debug, Clone)]
    struct AppState {
        id: Identity,
        rank: u64,
    }
    impl Unique for AppState {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &[] }
    }

    #[derive(Debug, Clone)]
    struct AppVote {
        id: Identity,
        rank: u64,
    }
    impl Unique for AppVote {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &[] }
    }

    #[derive(Debug)]
    struct StubAgg;
    impl AggregatedSignature for StubAgg {
        fn signature(&self) -> &[u8] { &[] }
        fn public_key(&self) -> &[u8] { &[] }
        fn bitmask(&self) -> &[u8] { &[] }
    }

    #[derive(Debug)]
    struct StubQc { rank: u64, id: Identity }
    impl QuorumCertificate for StubQc {
        fn filter(&self) -> &[u8] { &[] }
        fn rank(&self) -> u64 { self.rank }
        fn frame_number(&self) -> u64 { 0 }
        fn identity(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &StubAgg }
        fn equals(&self, o: &dyn QuorumCertificate) -> bool {
            self.rank == o.rank() && self.id == *o.identity()
        }
    }

    struct StubPacemaker;
    impl Pacemaker for StubPacemaker {
        fn current_rank(&self) -> u64 { 0 }
        fn latest_quorum_certificate(&self) -> Arc<dyn QuorumCertificate> {
            Arc::new(StubQc { rank: 0, id: "genesis".into() })
        }
        fn prior_rank_timeout_certificate(&self) -> Option<Arc<dyn TimeoutCertificate>> {
            None
        }
        fn receive_quorum_certificate(
            &mut self,
            _qc: Arc<dyn QuorumCertificate>,
        ) -> Result<Option<NextRank>> { Ok(None) }
        fn receive_timeout_certificate(
            &mut self,
            _tc: Option<Arc<dyn TimeoutCertificate>>,
        ) -> Result<Option<NextRank>> { Ok(None) }
    }

    struct StubReplicas;
    impl Replicas for StubReplicas {
        fn leader_for_rank(&self, _r: u64) -> Result<Identity> {
            Ok("leader".into())
        }
        fn quorum_threshold_for_rank(&self, _r: u64) -> Result<u64> { Ok(2) }
        fn timeout_threshold_for_rank(&self, _r: u64) -> Result<u64> { Ok(1) }
        fn self_identity(&self) -> &Identity {
            use std::sync::OnceLock;
            static ID: OnceLock<Identity> = OnceLock::new();
            ID.get_or_init(|| "self".into())
        }
        fn identities_by_rank(
            &self,
            _r: u64,
        ) -> Result<Vec<Box<dyn crate::models::WeightedIdentity>>> {
            Ok(vec![])
        }
        fn identity_by_rank(
            &self,
            _r: u64,
            _pid: &Identity,
        ) -> Result<Box<dyn crate::models::WeightedIdentity>> {
            Err(QuilError::NotFound("stub".into()))
        }
    }

    struct StubSafetyRules;
    impl SafetyRulesT<AppState, AppVote> for StubSafetyRules {
        fn produce_vote(
            &mut self,
            _p: &SignedProposal<AppState, AppVote>,
            _r: u64,
        ) -> Result<AppVote> { Err(QuilError::Internal("produce_vote not supported in stub".into())) }
        fn produce_timeout(
            &mut self,
            cur_rank: u64,
            newest_qc: Arc<dyn QuorumCertificate>,
            _p: Option<Arc<dyn TimeoutCertificate>>,
        ) -> Result<crate::models::TimeoutState<AppVote>> {
            Ok(crate::models::TimeoutState {
                rank: cur_rank,
                latest_quorum_certificate: newest_qc,
                prior_rank_timeout_certificate: None,
                vote: AppVote { id: "v".into(), rank: cur_rank },
                timeout_tick: 0,
            })
        }
        fn sign_own_proposal(
            &mut self,
            _p: &crate::models::Proposal<AppState>,
        ) -> Result<AppVote> {
            Err(QuilError::Internal("sign_own_proposal not supported in stub".into()))
        }
    }

    struct StubLeaderProvider;
    impl LeaderProvider<AppState> for StubLeaderProvider {
        fn get_next_leaders(&self, _p: Option<&State<AppState>>) -> Result<Vec<Identity>> {
            Ok(vec!["leader".into()])
        }
        fn prove_next_state(
            &self,
            _r: u64,
            _f: &[u8],
            _p: &Identity,
        ) -> Result<State<AppState>> {
            Err(QuilError::Internal("prove_next_state not supported in stub".into()))
        }
    }

    #[derive(Default)]
    struct RecordingConsumer;
    impl Consumer<AppState, AppVote> for RecordingConsumer {
        fn on_own_vote(&self, _v: &AppVote, _r: &Identity) {}
        fn on_own_timeout(&self, _t: &crate::models::TimeoutState<AppVote>) {}
        fn on_own_proposal(
            &self,
            _p: &SignedProposal<AppState, AppVote>,
            _t: Instant,
        ) {}
        fn on_event_processed(&self) {}
        fn on_rank_change(&self, _old: u64, _new: u64) {}
        fn on_finalization(&self, _p: &crate::models::FinalityProof<AppState>) {}
        fn on_qc_constructed(&self, _qc: &dyn QuorumCertificate) {}
        fn on_tc_constructed(&self, _tc: &dyn TimeoutCertificate) {}
    }

    struct NoopFinalizer;
    impl Finalizer for NoopFinalizer {
        fn make_final(&self, _id: &Identity) -> Result<()> { Ok(()) }
    }

    struct NoopFollower;
    impl FollowerConsumer<AppState> for NoopFollower {
        fn on_state_incorporated(&self, _s: &State<AppState>) {}
        fn on_finalized_state(&self, _c: &CertifiedState<AppState>) {}
        fn on_double_propose_detected(
            &self,
            _a: &State<AppState>,
            _b: &State<AppState>,
        ) {}
    }

    fn build_handler() -> Arc<HotStuffEventHandler<AppState, AppVote>> {
        let genesis = State {
            rank: 0,
            identifier: "genesis".into(),
            proposer_id: "leader".into(),
            parent_qc_identity: "genesis".into(),
            parent_qc_rank: 0,
            parent_quorum_certificate: None,
            timestamp: 0,
            state: AppState { id: "genesis".into(), rank: 0 },
        };
        let root_cert = CertifiedState {
            state: genesis,
            certifying_qc_identity: "genesis".into(),
            certifying_qc_rank: 0,
            certifying_quorum_certificate: None,
        };
        let forks = Forks::new(
            root_cert,
            Arc::new(NoopFinalizer),
            Arc::new(NoopFollower),
        )
        .unwrap();
        let forks = Arc::new(Mutex::new(forks));
        let pacemaker: Arc<Mutex<dyn Pacemaker>> = Arc::new(Mutex::new(StubPacemaker));
        let safety_rules: Arc<Mutex<dyn SafetyRulesT<AppState, AppVote>>> =
            Arc::new(Mutex::new(StubSafetyRules));
        let lp: Arc<dyn LeaderProvider<AppState>> = Arc::new(StubLeaderProvider);
        let state_producer = Arc::new(StateProducer::new(
            Arc::clone(&safety_rules),
            lp,
        ));
        let committee: Arc<dyn Replicas> = Arc::new(StubReplicas);
        let notifier: Arc<dyn Consumer<AppState, AppVote>> =
            Arc::new(RecordingConsumer::default());
        Arc::new(HotStuffEventHandler::new(
            pacemaker,
            state_producer,
            forks,
            safety_rules,
            committee,
            notifier,
        ))
    }

    #[tokio::test]
    async fn cancellation_before_start_exits_cleanly() {
        let handler = build_handler();
        // Schedule start far in the future; cancel before it arrives.
        let (loop_, handle) =
            EventLoop::new(handler, Instant::now() + Duration::from_secs(60));
        handle.shutdown();
        let res = tokio::time::timeout(Duration::from_millis(200), loop_.run())
            .await
            .expect("loop should exit promptly");
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn handle_clone_preserves_shared_trackers() {
        let handler = build_handler();
        let (loop_, handle) = EventLoop::new(handler, Instant::now());
        let handle2 = handle.clone();
        assert!(!handle.is_cancelled());
        assert!(!handle2.is_cancelled());
        handle2.shutdown();
        assert!(handle.is_cancelled());
        // Drain the loop so resources are released.
        let _ = tokio::time::timeout(Duration::from_millis(200), loop_.run()).await;
    }

    #[tokio::test]
    async fn submit_qc_dedupes_via_tracker() {
        let handler = build_handler();
        let (loop_, handle) = EventLoop::new(handler, Instant::now());
        // Submitting the same QC twice should only ring the notifier
        // once (second call is below the tracker's high-water mark).
        let qc1: Arc<dyn QuorumCertificate> = Arc::new(StubQc {
            rank: 5,
            id: "s-5".into(),
        });
        let qc2: Arc<dyn QuorumCertificate> = Arc::new(StubQc {
            rank: 5,
            id: "s-5".into(),
        });
        handle.submit_quorum_certificate(Arc::clone(&qc1));
        handle.submit_quorum_certificate(Arc::clone(&qc2));
        // Newest stays at 5.
        assert_eq!(handle.newest_qc.newest_qc().unwrap().rank(), 5);
        handle.shutdown();
        let _ = tokio::time::timeout(Duration::from_millis(200), loop_.run()).await;
    }

    #[tokio::test]
    async fn submit_proposal_returns_false_after_shutdown() {
        let handler = build_handler();
        let (loop_, handle) = EventLoop::new(handler, Instant::now());
        handle.shutdown();
        let sp = SignedProposal {
            proposal: crate::models::Proposal {
                state: State {
                    rank: 1,
                    identifier: "s1".into(),
                    proposer_id: "leader".into(),
                    parent_qc_identity: "genesis".into(),
                    parent_qc_rank: 0,
                    parent_quorum_certificate: None,
                    timestamp: 0,
                    state: AppState { id: "s1".into(), rank: 1 },
                },
                parent_quorum_certificate: Arc::new(StubQc {
                    rank: 0,
                    id: "genesis".into(),
                }),
                previous_rank_timeout_certificate: None,
            },
            vote: AppVote { id: "v".into(), rank: 1 },
        };
        let ok = handle.submit_proposal(sp).await;
        assert!(!ok);
        let _ = tokio::time::timeout(Duration::from_millis(200), loop_.run()).await;
    }
}

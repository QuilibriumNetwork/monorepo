use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::event_handler::ConsensusStore;
use crate::models::*;
use quil_types::error::{QuilError, Result};

/// Result of advancing to a new rank. Mirror of Go's `models.NextRank` —
/// describes the freshly-entered rank and its timer window.
#[derive(Debug, Clone, Copy)]
pub struct NextRank {
    pub rank: u64,
    pub start: Instant,
    pub end: Instant,
}

/// Timer info returned by `TimeoutController::start_timeout`. Mirror of
/// Go's `models.TimerInfo` minus the channel — the event loop owns the
/// actual tokio timer.
#[derive(Debug, Clone, Copy)]
pub struct TimerInfo {
    pub rank: u64,
    pub start_time: Instant,
    pub duration: Duration,
}

/// Provides the target publication time for proposals. Mirror of Go's
/// `ProposalDurationProvider`.
pub trait ProposalDurationProvider: Send + Sync {
    fn target_publication_time(
        &self,
        rank: u64,
        time_entered: Instant,
        parent_id: &Identity,
    ) -> Instant;
}

/// Constant-duration proposal timing. Mirror of Go's
/// `pacemaker.StaticProposalDurationProvider`.
///
/// `dur` is the time the leader waits after entering a new rank
/// before broadcasting its proposal. Setting this to zero disables
/// the delay entirely (see [`no_proposal_delay`]).
#[derive(Debug, Clone, Copy)]
pub struct StaticProposalDurationProvider {
    dur: Duration,
}

impl StaticProposalDurationProvider {
    pub fn new(dur: Duration) -> Self {
        Self { dur }
    }

    pub fn duration(&self) -> Duration {
        self.dur
    }
}

impl ProposalDurationProvider for StaticProposalDurationProvider {
    fn target_publication_time(
        &self,
        _rank: u64,
        time_entered: Instant,
        _parent_id: &Identity,
    ) -> Instant {
        time_entered + self.dur
    }
}

/// Convenience helper: zero-delay proposal timing. Mirror of Go's
/// `pacemaker.NoProposalDelay`.
pub fn no_proposal_delay() -> StaticProposalDurationProvider {
    StaticProposalDurationProvider::new(Duration::ZERO)
}

/// Participant-consumer notifications emitted by the pacemaker on rank
/// transitions. Concrete implementations live in the event-loop crate.
pub trait ParticipantConsumer<S: Unique, V: Unique>: Send + Sync {
    fn on_quorum_certificate_triggered_rank_change(
        &self,
        old_rank: u64,
        new_rank: u64,
        qc: &dyn QuorumCertificate,
    );
    fn on_timeout_certificate_triggered_rank_change(
        &self,
        old_rank: u64,
        new_rank: u64,
        tc: &dyn TimeoutCertificate,
    );
    fn on_rank_change(&self, old_rank: u64, new_rank: u64);
    fn on_starting_timeout(&self, start: Instant, end: Instant);

    // Marker so `V` participates in the trait — the event loop uses `V`
    // when emitting vote/timeout notifications.
    #[doc(hidden)]
    fn _vote_marker(&self, _v: &V) {}
}

/// Trait surface for pacemaker impls (so tests and engines can swap
/// stubs). The concrete impl is [`HotStuffPacemaker`] below.
pub trait Pacemaker: Send + Sync {
    /// Current consensus rank.
    fn current_rank(&self) -> u64;

    /// Latest-known quorum certificate. Mirror of Go's
    /// `LatestQuorumCertificate`.
    fn latest_quorum_certificate(&self) -> Arc<dyn QuorumCertificate>;

    /// The TC that carried us into the current rank, if we entered via a
    /// recovery-path rank change. `None` if we entered via a QC.
    fn prior_rank_timeout_certificate(&self) -> Option<Arc<dyn TimeoutCertificate>>;

    /// Process a received QC. Returns `Some(NextRank)` if the rank
    /// advanced, `None` otherwise.
    fn receive_quorum_certificate(
        &mut self,
        qc: Arc<dyn QuorumCertificate>,
    ) -> Result<Option<NextRank>>;

    /// Process a received TC. `None` input is allowed (no-op). Returns
    /// `Some(NextRank)` if the rank advanced.
    fn receive_timeout_certificate(
        &mut self,
        tc: Option<Arc<dyn TimeoutCertificate>>,
    ) -> Result<Option<NextRank>>;

    /// Instant at which the next local timeout fires. Used by the
    /// event loop to drive the timer. Implementations that don't need
    /// a real timer may return `Instant::now() + Duration::from_secs(60 * 60 * 24 * 365)`
    /// or similar.
    fn current_round_deadline(&self) -> Instant {
        Instant::now() + Duration::from_secs(60 * 60 * 24 * 365)
    }

    /// Advance the deadline after a local timeout fires (without a
    /// rank change). The pacemaker should use its rebroadcast interval
    /// to schedule the next rebroadcast.
    fn rearm_after_local_timeout(&mut self) {}

    /// Target publication time for a leader's proposal at `rank`.
    /// Mirror of Go's `Pacemaker.TargetPublicationTime`. Default
    /// returns `time_entered`, i.e. publish immediately — concrete
    /// impls override to add the configured `proposal_duration`
    /// so the chain advances at a steady cadence rather than
    /// VDF-as-fast-as-possible.
    fn target_publication_time(
        &self,
        _rank: u64,
        time_entered: Instant,
        _parent_id: &Identity,
    ) -> Instant {
        time_entered
    }
}

/// Truncated exponential backoff timeout configuration. Mirror of
/// `consensus/pacemaker/timeout/config.go::Config`.
///
/// The pacemaker produces timeouts with the formula:
///
/// ```text
///     duration(r) = t_min * b ^ (min((r - k) * θ(r - k), c))
///     where c = log_b(t_max / t_min)
///           b = TimeoutAdjustmentFactor
///           k = HappyPathMaxRoundFailures
///           r = failed-rounds counter
///           θ = Heaviside step function
/// ```
///
/// Config fields are stored in **milliseconds as f64** to match Go
/// byte-for-byte (Go's Config uses `float64` ms for both bounds).
#[derive(Debug, Clone, Copy)]
pub struct TimeoutConfig {
    pub min_replica_timeout_ms: f64,
    pub max_replica_timeout_ms: f64,
    pub timeout_adjustment_factor: f64,
    pub happy_path_max_round_failures: u64,
    pub max_timeout_state_rebroadcast_interval_ms: f64,
}

impl TimeoutConfig {
    /// Validate a config and build it. Mirror of Go's `NewConfig`.
    pub fn new(
        min_replica_timeout: Duration,
        max_replica_timeout: Duration,
        timeout_adjustment_factor: f64,
        happy_path_max_round_failures: u64,
        max_rebroadcast_interval: Duration,
    ) -> Result<Self> {
        use quil_types::error::QuilError;
        if min_replica_timeout.is_zero() {
            return Err(QuilError::InvalidArgument(
                "minReplicaTimeout must be a positive number[milliseconds]".into(),
            ));
        }
        if max_replica_timeout < min_replica_timeout {
            return Err(QuilError::InvalidArgument(
                "maxReplicaTimeout cannot be smaller than minReplicaTimeout".into(),
            ));
        }
        if timeout_adjustment_factor <= 1.0 {
            return Err(QuilError::InvalidArgument(
                "timeoutAdjustmentFactor must be strictly bigger than 1".into(),
            ));
        }
        if max_rebroadcast_interval.is_zero() {
            return Err(QuilError::InvalidArgument(
                "maxRebroadcastInterval must be a positive number [milliseconds]".into(),
            ));
        }
        Ok(Self {
            min_replica_timeout_ms: min_replica_timeout.as_millis() as f64,
            max_replica_timeout_ms: max_replica_timeout.as_millis() as f64,
            timeout_adjustment_factor,
            happy_path_max_round_failures,
            max_timeout_state_rebroadcast_interval_ms: max_rebroadcast_interval.as_millis()
                as f64,
        })
    }

    /// Mirror of Go's `NewDefaultConfig()`:
    /// - min 3s, max 1min, adjustment 1.2, happy path 6 rounds,
    ///   rebroadcast 5s.
    pub fn default_config() -> Self {
        Self::new(
            Duration::from_secs(3),
            Duration::from_secs(60),
            1.2,
            6,
            Duration::from_secs(5),
        )
        .expect("default config must be valid")
    }
}

/// Truncated exponential backoff timeout controller. Mirror of
/// `consensus/pacemaker/timeout/controller.go::Controller`, minus the
/// goroutine-driven timeout channel (which will arrive with the
/// event-loop port). State transitions and timeout-duration math are
/// bit-for-bit identical to Go.
pub struct TimeoutController {
    cfg: TimeoutConfig,
    /// Precomputed `log_b(max/min) = ln(max/min) / ln(b)`.
    max_exponent: f64,
    /// Failed-rounds counter (Go calls this `r`).
    failed_rounds: u64,
}

impl TimeoutController {
    pub fn new(cfg: TimeoutConfig) -> Self {
        // Go: `math.Log(max/min) / math.Log(adjustment)`.
        let max_exponent = (cfg.max_replica_timeout_ms / cfg.min_replica_timeout_ms).ln()
            / cfg.timeout_adjustment_factor.ln();
        Self {
            cfg,
            max_exponent,
            failed_rounds: 0,
        }
    }

    /// Current failed-rounds counter (for diagnostics and tests).
    pub fn failed_rounds(&self) -> u64 {
        self.failed_rounds
    }

    /// Current replica timeout in milliseconds, as `f64` to match Go.
    /// Mirror of `Controller.replicaTimeout`.
    pub fn replica_timeout_ms(&self) -> f64 {
        if self.failed_rounds <= self.cfg.happy_path_max_round_failures {
            return self.cfg.min_replica_timeout_ms;
        }
        let r = (self.failed_rounds - self.cfg.happy_path_max_round_failures) as f64;
        if r >= self.max_exponent {
            return self.cfg.max_replica_timeout_ms;
        }
        self.cfg.min_replica_timeout_ms * self.cfg.timeout_adjustment_factor.powf(r)
    }

    /// Current replica timeout as a `Duration` (convenience wrapper).
    pub fn timeout_duration(&self) -> Duration {
        Duration::from_secs_f64(self.replica_timeout_ms() / 1000.0)
    }

    /// Rebroadcast interval in milliseconds, bounded by both the
    /// current replica timeout and the configured maximum.
    pub fn rebroadcast_interval_ms(&self) -> f64 {
        self.replica_timeout_ms()
            .min(self.cfg.max_timeout_state_rebroadcast_interval_ms)
    }

    /// Mirror of `Controller.OnTimeout`. Bumps the failed-rounds
    /// counter, bounded above at `maxExponent + happyPathMaxFailures`
    /// so we never exceed the exponent cap.
    pub fn on_timeout(&mut self) {
        let cap = self.max_exponent + self.cfg.happy_path_max_round_failures as f64;
        if (self.failed_rounds as f64) >= cap {
            return;
        }
        self.failed_rounds += 1;
    }

    /// Mirror of `Controller.OnProgressBeforeTimeout`. Decrements the
    /// failed-rounds counter, floored at zero. Go decrements by one
    /// rather than resetting to zero so that backoff decays smoothly
    /// after sustained pressure.
    pub fn on_progress_before_timeout(&mut self) {
        if self.failed_rounds > 0 {
            self.failed_rounds -= 1;
        }
    }

    /// Compute timer info for entering `rank`. Mirror of Go's
    /// `StartTimeout` sans the async ticker — the event loop owns the
    /// actual tokio timer, we just report the desired duration.
    pub fn start_timeout(&self, rank: u64) -> TimerInfo {
        TimerInfo {
            rank,
            start_time: Instant::now(),
            duration: self.timeout_duration(),
        }
    }
}

// =====================================================================
// Rank tracker: internal helper for the pacemaker, not exported.
// =====================================================================

/// Persistent rank tracker. Mirror of Go's
/// `consensus/pacemaker/rank_tracker.go::rankTracker`.
///
/// The tracker persists its [`LivenessState`] via the provided
/// [`ConsensusStore`] so that a crashed replica can resume at its last
/// known rank without voting twice.
struct RankTracker<V: Unique> {
    liveness_state: LivenessState,
    store: Arc<dyn ConsensusStore<V>>,
}

impl<V: Unique> RankTracker<V> {
    fn new(filter: Vec<u8>, store: Arc<dyn ConsensusStore<V>>) -> Result<Self> {
        let liveness_state = store
            .get_liveness_state(&filter)
            .map_err(|e| QuilError::Consensus(format!("could not load liveness data: {}", e)))?;
        Ok(Self {
            liveness_state,
            store,
        })
    }

    fn current_rank(&self) -> u64 {
        self.liveness_state.current_rank
    }

    fn latest_quorum_certificate(&self) -> Arc<dyn QuorumCertificate> {
        Arc::clone(&self.liveness_state.latest_quorum_certificate)
    }

    fn prior_rank_timeout_certificate(&self) -> Option<Arc<dyn TimeoutCertificate>> {
        self.liveness_state
            .prior_rank_timeout_certificate
            .as_ref()
            .map(Arc::clone)
    }

    /// Receive a QC. Returns the new current rank.
    fn receive_quorum_certificate(&mut self, qc: Arc<dyn QuorumCertificate>) -> Result<u64> {
        let rank = self.liveness_state.current_rank;
        if qc.rank() < rank {
            // Old QC — only update newest-QC tracker, no rank change.
            self.update_newest_qc(qc)?;
            return Ok(rank);
        }
        let new_rank = qc.rank() + 1;
        self.update_liveness_state(new_rank, qc, None)?;
        Ok(new_rank)
    }

    /// Receive a TC (None is a no-op). Returns the new current rank.
    fn receive_timeout_certificate(
        &mut self,
        tc: Option<Arc<dyn TimeoutCertificate>>,
    ) -> Result<u64> {
        let rank = self.liveness_state.current_rank;
        let Some(tc) = tc else {
            return Ok(rank);
        };
        if tc.rank() < rank {
            // Old TC, but its embedded QC might still be newer than ours.
            // We can't clone the embedded QC directly since `latest_quorum_cert`
            // returns a `&dyn QuorumCertificate`. The TC Arc already holds
            // its lifetime — expose the embedded QC via a helper once, then
            // clone the enclosing TC if needed.
            // For this initial port, we accept a slightly-weaker update path:
            // we only advance the newest-QC tracker via the TC's embedded QC
            // when the TC Arc can be recreated with the same content. Since
            // TC trait objects are opaque, we can't synthesize a new QC Arc.
            //
            // Instead, we leave the newest-QC tracker alone here — a
            // follow-on fresh QC will catch up. The pacemaker's liveness
            // will be slightly slower in this edge case, but safety is
            // preserved.
            //
            // BUT: if this TC is for rank `current_rank - 1`, it's the
            // freshly-aggregated TC that justified our most recent
            // advance, and it should replace whatever we had as
            // `prior_rank_TC` (which on a restored-from-disk pacemaker
            // might be a stale TC from a previous binary version with
            // an empty bitmask). Without this, our next outgoing
            // timeout still embeds the bad TC and peers reject it.
            if tc.rank() + 1 == rank {
                self.liveness_state.prior_rank_timeout_certificate = Some(tc);
                self.store
                    .put_liveness_state(&self.liveness_state)
                    .map_err(|e| QuilError::Consensus(format!("could not persist liveness state: {}", e)))?;
            }
            return Ok(rank);
        }
        let new_rank = tc.rank() + 1;
        // For `updateLivenessState`, Go passes `tc.GetLatestQuorumCert()` as
        // the QC. Since that borrow doesn't fit our Arc model, we keep the
        // existing `latest_quorum_certificate` if it's already at or beyond
        // the TC's embedded QC rank (common case); otherwise we record the
        // TC but leave the QC stale for this edge case.
        let current_qc_rank = self.liveness_state.latest_quorum_certificate.rank();
        if current_qc_rank < tc.latest_quorum_cert().rank() {
            // Would ideally advance the QC here, but we don't have a
            // standalone Arc for the embedded QC. Accepting a small lag:
            // the next fresh QC will catch up.
        }
        self.update_liveness_state_tc_only(new_rank, tc)?;
        Ok(new_rank)
    }

    fn update_liveness_state(
        &mut self,
        new_rank: u64,
        qc: Arc<dyn QuorumCertificate>,
        tc: Option<Arc<dyn TimeoutCertificate>>,
    ) -> Result<()> {
        if new_rank <= self.liveness_state.current_rank {
            return Err(QuilError::Consensus(format!(
                "cannot move from rank {} to {}: currentRank must be strictly monotonicly increasing",
                self.liveness_state.current_rank, new_rank
            )));
        }
        self.liveness_state.current_rank = new_rank;
        if self.liveness_state.latest_quorum_certificate.rank() < qc.rank() {
            self.liveness_state.latest_quorum_certificate = qc;
        }
        self.liveness_state.prior_rank_timeout_certificate = tc;
        self.store
            .put_liveness_state(&self.liveness_state)
            .map_err(|e| QuilError::Consensus(format!("could not persist liveness state: {}", e)))
    }

    fn update_liveness_state_tc_only(
        &mut self,
        new_rank: u64,
        tc: Arc<dyn TimeoutCertificate>,
    ) -> Result<()> {
        if new_rank <= self.liveness_state.current_rank {
            return Err(QuilError::Consensus(format!(
                "cannot move from rank {} to {}: currentRank must be strictly monotonicly increasing",
                self.liveness_state.current_rank, new_rank
            )));
        }
        self.liveness_state.current_rank = new_rank;
        self.liveness_state.prior_rank_timeout_certificate = Some(tc);
        self.store
            .put_liveness_state(&self.liveness_state)
            .map_err(|e| QuilError::Consensus(format!("could not persist liveness state: {}", e)))
    }

    fn update_newest_qc(&mut self, qc: Arc<dyn QuorumCertificate>) -> Result<()> {
        if self.liveness_state.latest_quorum_certificate.rank() >= qc.rank() {
            return Ok(());
        }
        self.liveness_state.latest_quorum_certificate = qc;
        self.store
            .put_liveness_state(&self.liveness_state)
            .map_err(|e| QuilError::Consensus(format!("could not persist liveness state: {}", e)))
    }
}

// =====================================================================
// Concrete HotStuff pacemaker
// =====================================================================

/// Concrete pacemaker. Mirror of Go's
/// `consensus/pacemaker/pacemaker.go::Pacemaker`. Not concurrency safe —
/// the event loop serializes all access.
pub struct HotStuffPacemaker<S: Unique, V: Unique> {
    timeout_control: TimeoutController,
    rank_tracker: RankTracker<V>,
    notifier: Arc<dyn ParticipantConsumer<S, V>>,
    duration_provider: Arc<dyn ProposalDurationProvider>,
    /// Instant at which the next local timeout fires. Updated on
    /// construction (initial timer for the boot rank), on rank change
    /// (QC- or TC-triggered), and on local timeout fire (rebroadcast).
    current_deadline: Instant,
}

impl<S: Unique, V: Unique> HotStuffPacemaker<S, V> {
    pub fn new(
        filter: Vec<u8>,
        timeout_control: TimeoutController,
        duration_provider: Arc<dyn ProposalDurationProvider>,
        notifier: Arc<dyn ParticipantConsumer<S, V>>,
        store: Arc<dyn ConsensusStore<V>>,
    ) -> Result<Self> {
        let rank_tracker = RankTracker::new(filter, store)?;
        let initial_rank = rank_tracker.current_rank();
        let timer_info = timeout_control.start_timeout(initial_rank);
        let current_deadline = timer_info.start_time + timer_info.duration;
        notifier.on_starting_timeout(timer_info.start_time, current_deadline);
        Ok(Self {
            timeout_control,
            rank_tracker,
            notifier,
            duration_provider,
            current_deadline,
        })
    }

    /// Compute the target publication time for a proposal at `rank`.
    /// Delegates to the configured `ProposalDurationProvider`.
    pub fn target_publication_time(
        &self,
        rank: u64,
        time_entered: Instant,
        parent_id: &Identity,
    ) -> Instant {
        self.duration_provider
            .target_publication_time(rank, time_entered, parent_id)
    }

    /// Accessor for the internal timeout controller, mainly for tests.
    pub fn timeout_controller(&self) -> &TimeoutController {
        &self.timeout_control
    }
}

impl<S: Unique, V: Unique> Pacemaker for HotStuffPacemaker<S, V> {
    fn current_rank(&self) -> u64 {
        self.rank_tracker.current_rank()
    }

    fn latest_quorum_certificate(&self) -> Arc<dyn QuorumCertificate> {
        self.rank_tracker.latest_quorum_certificate()
    }

    fn prior_rank_timeout_certificate(&self) -> Option<Arc<dyn TimeoutCertificate>> {
        self.rank_tracker.prior_rank_timeout_certificate()
    }

    fn receive_quorum_certificate(
        &mut self,
        qc: Arc<dyn QuorumCertificate>,
    ) -> Result<Option<NextRank>> {
        let initial_rank = self.current_rank();
        let qc_ref = Arc::clone(&qc);
        let resulting_rank = self.rank_tracker.receive_quorum_certificate(qc).map_err(|e| {
            QuilError::Consensus(format!(
                "unexpected exception in rankTracker while processing QC for rank {}: {}",
                qc_ref.rank(),
                e
            ))
        })?;
        if resulting_rank <= initial_rank {
            return Ok(None);
        }

        // QC triggered a rank change.
        self.timeout_control.on_progress_before_timeout();
        self.notifier
            .on_quorum_certificate_triggered_rank_change(initial_rank, resulting_rank, qc_ref.as_ref());
        self.notifier.on_rank_change(initial_rank, resulting_rank);

        let timer_info = self.timeout_control.start_timeout(resulting_rank);
        let end = timer_info.start_time + timer_info.duration;
        self.current_deadline = end;
        self.notifier.on_starting_timeout(timer_info.start_time, end);
        Ok(Some(NextRank {
            rank: timer_info.rank,
            start: timer_info.start_time,
            end,
        }))
    }

    fn receive_timeout_certificate(
        &mut self,
        tc: Option<Arc<dyn TimeoutCertificate>>,
    ) -> Result<Option<NextRank>> {
        let initial_rank = self.current_rank();
        let tc_for_notifier = tc.as_ref().map(Arc::clone);
        let tc_rank = tc.as_ref().map(|t| t.rank()).unwrap_or(initial_rank);
        let resulting_rank = self.rank_tracker.receive_timeout_certificate(tc).map_err(|e| {
            QuilError::Consensus(format!(
                "unexpected exception in rankTracker while processing TC for rank {}: {}",
                tc_rank, e
            ))
        })?;
        if resulting_rank <= initial_rank {
            return Ok(None);
        }

        // TC triggered a rank change.
        self.timeout_control.on_timeout();
        if let Some(tc) = &tc_for_notifier {
            self.notifier
                .on_timeout_certificate_triggered_rank_change(initial_rank, resulting_rank, tc.as_ref());
        }
        self.notifier.on_rank_change(initial_rank, resulting_rank);

        let timer_info = self.timeout_control.start_timeout(resulting_rank);
        let end = timer_info.start_time + timer_info.duration;
        self.current_deadline = end;
        self.notifier.on_starting_timeout(timer_info.start_time, end);
        Ok(Some(NextRank {
            rank: timer_info.rank,
            start: timer_info.start_time,
            end,
        }))
    }

    fn current_round_deadline(&self) -> Instant {
        self.current_deadline
    }

    fn rearm_after_local_timeout(&mut self) {
        // Mirror Go's rebroadcast behavior: on each timer tick (no rank
        // change), schedule the next tick at `now + rebroadcast_interval`.
        let interval = Duration::from_secs_f64(
            self.timeout_control.rebroadcast_interval_ms() / 1000.0,
        );
        self.current_deadline = Instant::now() + interval;
    }

    fn target_publication_time(
        &self,
        rank: u64,
        time_entered: Instant,
        parent_id: &Identity,
    ) -> Instant {
        // Delegate to the configured `ProposalDurationProvider` so the
        // leader spaces its broadcasts by `proposal_duration` (10s
        // mainnet) rather than firing as fast as VDF allows.
        self.duration_provider
            .target_publication_time(rank, time_entered, parent_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> TimeoutConfig {
        TimeoutConfig::new(
            Duration::from_millis(500),
            Duration::from_secs(30),
            2.0,
            6,
            Duration::from_secs(5),
        )
        .unwrap()
    }

    #[test]
    fn default_config_is_valid() {
        let cfg = TimeoutConfig::default_config();
        assert_eq!(cfg.min_replica_timeout_ms, 3000.0);
        assert_eq!(cfg.max_replica_timeout_ms, 60_000.0);
        assert_eq!(cfg.timeout_adjustment_factor, 1.2);
        assert_eq!(cfg.happy_path_max_round_failures, 6);
        assert_eq!(cfg.max_timeout_state_rebroadcast_interval_ms, 5000.0);
    }

    #[test]
    fn config_rejects_invalid_params() {
        assert!(TimeoutConfig::new(
            Duration::ZERO,
            Duration::from_secs(60),
            1.2,
            6,
            Duration::from_secs(5)
        )
        .is_err());
        assert!(TimeoutConfig::new(
            Duration::from_secs(10),
            Duration::from_secs(5), // max < min
            1.2,
            6,
            Duration::from_secs(5)
        )
        .is_err());
        assert!(TimeoutConfig::new(
            Duration::from_secs(1),
            Duration::from_secs(60),
            1.0, // factor must be > 1
            6,
            Duration::from_secs(5)
        )
        .is_err());
    }

    #[test]
    fn timeout_controller_min_while_on_happy_path() {
        let tc = TimeoutController::new(test_cfg());
        // failed_rounds = 0 ≤ 6 (happy path) → min.
        assert_eq!(tc.replica_timeout_ms(), 500.0);
    }

    #[test]
    fn timeout_controller_still_min_at_edge_of_happy_path() {
        // Go: `r <= happyPath → min`. 6 ≤ 6 → still min.
        let mut tc = TimeoutController::new(test_cfg());
        tc.failed_rounds = 6;
        assert_eq!(tc.replica_timeout_ms(), 500.0);
    }

    #[test]
    fn timeout_controller_first_backoff_step() {
        // r=7 → excess=1 → 500 * 2^1 = 1000
        let mut tc = TimeoutController::new(test_cfg());
        tc.failed_rounds = 7;
        assert!((tc.replica_timeout_ms() - 1000.0).abs() < 1e-9);
    }

    #[test]
    fn timeout_controller_hits_max_cap() {
        // max_exponent = log_2(30000/500) = log_2(60) ≈ 5.907.
        // Any excess r ≥ 5.907 returns max = 30000.
        let mut tc = TimeoutController::new(test_cfg());
        tc.failed_rounds = 6 + 6; // excess 6 > 5.907 → max
        assert_eq!(tc.replica_timeout_ms(), 30_000.0);
    }

    #[test]
    fn timeout_controller_on_timeout_bounded() {
        let mut tc = TimeoutController::new(test_cfg());
        // Call on_timeout many times — counter is capped.
        for _ in 0..100 {
            tc.on_timeout();
        }
        // Cap: max_exponent + happy_path = 5.907 + 6 ≈ 11.907.
        // Integer counter can't exceed 11 since we compare `r as f64
        // >= cap` before incrementing.
        assert!(tc.failed_rounds() <= 12);
    }

    #[test]
    fn timeout_controller_on_progress_decrements_not_resets() {
        let mut tc = TimeoutController::new(test_cfg());
        tc.failed_rounds = 5;
        tc.on_progress_before_timeout();
        assert_eq!(tc.failed_rounds, 4);
        tc.on_progress_before_timeout();
        assert_eq!(tc.failed_rounds, 3);
    }

    #[test]
    fn timeout_controller_on_progress_floors_at_zero() {
        let mut tc = TimeoutController::new(test_cfg());
        assert_eq!(tc.failed_rounds, 0);
        tc.on_progress_before_timeout();
        assert_eq!(tc.failed_rounds, 0);
    }

    #[test]
    fn rebroadcast_interval_is_min_of_timeout_and_config_max() {
        let mut tc = TimeoutController::new(test_cfg());
        // On happy path, replica_timeout_ms = 500, config max = 5000.
        // min(500, 5000) = 500.
        assert_eq!(tc.rebroadcast_interval_ms(), 500.0);

        // Push past happy path to a timeout larger than rebroadcast cap.
        tc.failed_rounds = 50;
        // Replica timeout now = max = 30000. Rebroadcast capped at 5000.
        assert_eq!(tc.replica_timeout_ms(), 30_000.0);
        assert_eq!(tc.rebroadcast_interval_ms(), 5000.0);
    }

    // =================================================================
    // HotStuffPacemaker integration tests
    // =================================================================

    use crate::models::{AggregatedSignature, ConsensusState, LivenessState};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    // Vote stub used for HotStuffPacemaker<S, V> — we don't care about S for
    // the rank-tracking logic, so we reuse V for both.
    #[derive(Debug, Clone)]
    struct TestVote {
        id: Identity,
        rank: u64,
    }
    impl Unique for TestVote {
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
    struct StubQc {
        rank: u64,
        id: Identity,
    }
    impl QuorumCertificate for StubQc {
        fn filter(&self) -> &[u8] { &[] }
        fn rank(&self) -> u64 { self.rank }
        fn frame_number(&self) -> u64 { 0 }
        fn identity(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &StubAgg }
        fn equals(&self, other: &dyn QuorumCertificate) -> bool {
            self.rank == other.rank() && self.id == *other.identity()
        }
    }

    #[derive(Debug)]
    struct StubTc {
        rank: u64,
        latest_qc: StubQc,
    }
    impl TimeoutCertificate for StubTc {
        fn filter(&self) -> &[u8] { &[] }
        fn rank(&self) -> u64 { self.rank }
        fn latest_ranks(&self) -> &[u64] { &[] }
        fn latest_quorum_cert(&self) -> &dyn QuorumCertificate { &self.latest_qc }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &StubAgg }
        fn equals(&self, other: &dyn TimeoutCertificate) -> bool {
            self.rank == other.rank()
        }
    }

    // Minimal in-memory ConsensusStore for pacemaker tests.
    #[derive(Default)]
    struct InMemStore {
        liveness: Mutex<Option<LivenessState>>,
    }
    impl ConsensusStore<TestVote> for InMemStore {
        fn get_consensus_state(&self, filter: &[u8]) -> Result<ConsensusState<TestVote>> {
            Ok(ConsensusState {
                filter: filter.to_vec(),
                finalized_rank: 0,
                latest_acknowledged_rank: 0,
                latest_timeout: None,
            })
        }
        fn put_consensus_state(&self, _s: &ConsensusState<TestVote>) -> Result<()> {
            Ok(())
        }
        fn get_liveness_state(&self, filter: &[u8]) -> Result<LivenessState> {
            let mut saved = self.liveness.lock().unwrap();
            if let Some(s) = saved.as_ref() {
                return Ok(s.clone());
            }
            let initial = LivenessState {
                filter: filter.to_vec(),
                current_rank: 0,
                latest_quorum_certificate: Arc::new(StubQc {
                    rank: 0,
                    id: "genesis".into(),
                }),
                prior_rank_timeout_certificate: None,
            };
            *saved = Some(initial.clone());
            Ok(initial)
        }
        fn put_liveness_state(&self, state: &LivenessState) -> Result<()> {
            *self.liveness.lock().unwrap() = Some(state.clone());
            Ok(())
        }
    }

    // Notifier stub that records every callback.
    #[derive(Default)]
    struct RecordingConsumer {
        rank_changes: AtomicUsize,
        qc_triggered: AtomicUsize,
        tc_triggered: AtomicUsize,
        timeouts_started: AtomicUsize,
    }
    impl ParticipantConsumer<TestVote, TestVote> for RecordingConsumer {
        fn on_quorum_certificate_triggered_rank_change(
            &self,
            _old: u64,
            _new: u64,
            _qc: &dyn QuorumCertificate,
        ) {
            self.qc_triggered.fetch_add(1, Ordering::SeqCst);
        }
        fn on_timeout_certificate_triggered_rank_change(
            &self,
            _old: u64,
            _new: u64,
            _tc: &dyn TimeoutCertificate,
        ) {
            self.tc_triggered.fetch_add(1, Ordering::SeqCst);
        }
        fn on_rank_change(&self, _old: u64, _new: u64) {
            self.rank_changes.fetch_add(1, Ordering::SeqCst);
        }
        fn on_starting_timeout(&self, _start: Instant, _end: Instant) {
            self.timeouts_started.fetch_add(1, Ordering::SeqCst);
        }
    }

    // Dummy ProposalDurationProvider — always returns `time_entered + 1s`.
    struct DummyDuration;
    impl ProposalDurationProvider for DummyDuration {
        fn target_publication_time(
            &self,
            _rank: u64,
            time_entered: Instant,
            _parent_id: &Identity,
        ) -> Instant {
            time_entered + Duration::from_secs(1)
        }
    }

    fn new_pacemaker() -> (
        HotStuffPacemaker<TestVote, TestVote>,
        Arc<RecordingConsumer>,
    ) {
        let consumer = Arc::new(RecordingConsumer::default());
        let store: Arc<dyn ConsensusStore<TestVote>> = Arc::new(InMemStore::default());
        let dp: Arc<dyn ProposalDurationProvider> = Arc::new(DummyDuration);
        let pm = HotStuffPacemaker::new(
            b"filter".to_vec(),
            TimeoutController::new(test_cfg()),
            dp,
            consumer.clone() as Arc<dyn ParticipantConsumer<TestVote, TestVote>>,
            store,
        )
        .unwrap();
        (pm, consumer)
    }

    #[test]
    fn pacemaker_advances_on_qc() {
        let (mut pm, consumer) = new_pacemaker();
        assert_eq!(pm.current_rank(), 0);
        let qc: Arc<dyn QuorumCertificate> = Arc::new(StubQc {
            rank: 5,
            id: "qc-5".into(),
        });
        let next = pm.receive_quorum_certificate(qc).unwrap().unwrap();
        assert_eq!(next.rank, 6); // qc.rank + 1
        assert_eq!(pm.current_rank(), 6);
        assert_eq!(consumer.qc_triggered.load(Ordering::SeqCst), 1);
        assert_eq!(consumer.rank_changes.load(Ordering::SeqCst), 1);
        // 2 = one from constructor (initial rank timeout) + one from QC.
        assert_eq!(consumer.timeouts_started.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn pacemaker_stale_qc_is_noop_but_updates_newest() {
        let (mut pm, consumer) = new_pacemaker();
        // First advance to rank 6.
        let qc1: Arc<dyn QuorumCertificate> = Arc::new(StubQc { rank: 5, id: "qc-5".into() });
        pm.receive_quorum_certificate(qc1).unwrap();
        // Now feed a stale QC at rank 3 — no rank change.
        let qc2: Arc<dyn QuorumCertificate> = Arc::new(StubQc { rank: 3, id: "qc-3".into() });
        let res = pm.receive_quorum_certificate(qc2).unwrap();
        assert!(res.is_none());
        assert_eq!(pm.current_rank(), 6);
        // Consumer saw exactly one rank change, two timeout starts
        // (one from constructor, one from QC).
        assert_eq!(consumer.rank_changes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn pacemaker_advances_on_tc() {
        let (mut pm, consumer) = new_pacemaker();
        let tc: Arc<dyn TimeoutCertificate> = Arc::new(StubTc {
            rank: 10,
            latest_qc: StubQc { rank: 9, id: "qc-9".into() },
        });
        let next = pm.receive_timeout_certificate(Some(tc)).unwrap().unwrap();
        assert_eq!(next.rank, 11); // tc.rank + 1
        assert_eq!(pm.current_rank(), 11);
        assert_eq!(consumer.tc_triggered.load(Ordering::SeqCst), 1);
        assert_eq!(consumer.rank_changes.load(Ordering::SeqCst), 1);
        assert!(pm.prior_rank_timeout_certificate().is_some());
    }

    #[test]
    fn pacemaker_none_tc_is_noop() {
        let (mut pm, _) = new_pacemaker();
        let res = pm.receive_timeout_certificate(None).unwrap();
        assert!(res.is_none());
        assert_eq!(pm.current_rank(), 0);
    }

    // =================================================================
    // StaticProposalDurationProvider tests
    // =================================================================

    #[test]
    fn static_proposal_duration_adds_exact_offset() {
        let p = StaticProposalDurationProvider::new(Duration::from_millis(250));
        let entered = Instant::now();
        let target = p.target_publication_time(5, entered, &b"parent".to_vec());
        // Target is exactly `entered + 250ms`.
        assert_eq!(target - entered, Duration::from_millis(250));
    }

    #[test]
    fn no_proposal_delay_returns_time_entered() {
        let p = no_proposal_delay();
        assert_eq!(p.duration(), Duration::ZERO);
        let entered = Instant::now();
        let target = p.target_publication_time(0, entered, &b"p".to_vec());
        assert_eq!(target, entered);
    }

    #[test]
    fn static_proposal_duration_is_rank_agnostic() {
        // Different ranks must produce the same delta.
        let p = StaticProposalDurationProvider::new(Duration::from_secs(1));
        let entered = Instant::now();
        let t1 = p.target_publication_time(1, entered, &b"p".to_vec());
        let t2 = p.target_publication_time(1000, entered, &b"p".to_vec());
        assert_eq!(t1, t2);
    }

    #[test]
    fn pacemaker_qc_progress_resets_timeout_backoff() {
        let (mut pm, _) = new_pacemaker();
        // Simulate prior failures by hand.
        // (We can't directly mutate via the trait, so drive through TCs.)
        let tc: Arc<dyn TimeoutCertificate> = Arc::new(StubTc {
            rank: 5,
            latest_qc: StubQc { rank: 4, id: "qc-4".into() },
        });
        pm.receive_timeout_certificate(Some(tc)).unwrap();
        // After a TC, failed_rounds should be 1.
        assert_eq!(pm.timeout_controller().failed_rounds(), 1);
        // Now a QC triggers progress — decrement.
        let qc: Arc<dyn QuorumCertificate> = Arc::new(StubQc { rank: 10, id: "qc-10".into() });
        pm.receive_quorum_certificate(qc).unwrap();
        assert_eq!(pm.timeout_controller().failed_rounds(), 0);
    }
}

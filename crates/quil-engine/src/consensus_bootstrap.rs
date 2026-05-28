//! Consensus event loop bootstrap for the global chain.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::info;

use quil_consensus::committee::{DynamicCommittee, Replicas};
use quil_consensus::event_handler::{Consumer, ConsensusStore, HotStuffEventHandler};
use quil_consensus::event_loop::{EventLoop, EventLoopHandle};
use quil_consensus::forest::Forks;
use quil_consensus::leader_provider::LeaderProvider;
use quil_consensus::pacemaker::{
    HotStuffPacemaker, ParticipantConsumer, StaticProposalDurationProvider,
    TimeoutConfig, TimeoutController,
};
use quil_consensus::safety_rules::SafetyRules;
use quil_consensus::signer::Signer;
use quil_consensus::state_producer::StateProducer;

use crate::consensus_types::{GlobalState, GlobalVote};

/// Configuration for the consensus event loop.
#[derive(Clone)]
pub struct ConsensusConfig {
    pub filter: Vec<u8>,
    pub min_timeout: Duration,
    pub max_timeout: Duration,
    pub timeout_adjustment_factor: f64,
    pub happy_path_max_round_failures: u64,
    pub max_rebroadcast_interval: Duration,
    pub proposal_duration: Duration,
    /// Grace period before the consensus event loop emits its first
    /// proposal. Production needs this for the BlossomSub mesh to
    /// finish forming (~25-30s of formation latency observed); tests
    /// should set it to `Duration::ZERO` so the loop runs
    /// immediately under `tokio::time::pause()`.
    pub startup_delay: Duration,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        // Mostly Go's values at
        // `consensus/participant/participant.go:46-106`:
        //   - min_replica_timeout = 36s
        //   - max_replica_timeout = 3 min
        //   - timeout_adjustment_factor = 1.2
        //   - happy_path_max_round_failures = 6
        //   - max_rebroadcast_interval = 28s
        // …with `proposal_duration` bumped from Go's 8s to 10s.
        // Go's 8s was slow in practice (its propose path adds many
        // ms of overhead the Rust port doesn't have), so an 8s nominal
        // delay translated to ~10s wall-clock there. In Rust the
        // delay is exact, so we set it explicitly to the target 10s
        // cadence the chain is calibrated around.
        // Critically, proposal_duration < min_timeout — otherwise the
        // round-timeout fires at or before the leader's first
        // broadcast and every rank ends in a timeout instead of a QC.
        Self {
            // Global consensus filter — Go uses nil/empty here and
            // writes its CONSENSUS-namespace keys with no suffix
            // (`node/store/consensus.go:40`, callers in
            // `node/consensus/global/genesis.go:489,498` and
            // `node/consensus/global/global_consensus_engine.go:806,919`).
            // Rust must match so a future migrator can translate
            // those keys 1:1.
            filter: Vec::new(),
            min_timeout: Duration::from_secs(36),
            max_timeout: Duration::from_secs(180),
            timeout_adjustment_factor: 1.2,
            happy_path_max_round_failures: 6,
            max_rebroadcast_interval: Duration::from_secs(28),
            proposal_duration: Duration::from_secs(10),
            startup_delay: Duration::from_secs(45),
        }
    }
}

/// Spawn the global consensus event loop. Returns the handle for
/// submitting proposals, QCs, TCs, and timeouts.
pub fn spawn_global_consensus(
    config: ConsensusConfig,
    signer: Arc<dyn Signer<GlobalState, GlobalVote>>,
    consensus_store: Arc<dyn ConsensusStore<GlobalVote>>,
    committee: Arc<dyn Replicas>,
    dynamic_committee: Arc<dyn DynamicCommittee>,
    leader_provider: Arc<dyn LeaderProvider<GlobalState>>,
    notifier: Arc<dyn Consumer<GlobalState, GlobalVote>>,
    participant_consumer: Arc<dyn ParticipantConsumer<GlobalState, GlobalVote>>,
) -> quil_types::error::Result<ConsensusComponents> {
    // Timeout config
    let timeout_cfg = TimeoutConfig::new(
        config.min_timeout,
        config.max_timeout,
        config.timeout_adjustment_factor,
        config.happy_path_max_round_failures,
        config.max_rebroadcast_interval,
    )?;
    let timeout_ctrl = TimeoutController::new(timeout_cfg);

    let duration_provider = Arc::new(StaticProposalDurationProvider::new(config.proposal_duration));

    // Pacemaker
    let pacemaker = HotStuffPacemaker::<GlobalState, GlobalVote>::new(
        config.filter.clone(),
        timeout_ctrl,
        duration_provider,
        participant_consumer,
        consensus_store.clone(),
    )?;

    // Safety rules — shared between handler and state producer
    let safety_rules = Arc::new(Mutex::new(SafetyRules::<GlobalState, GlobalVote>::new(
        config.filter,
        signer,
        consensus_store,
        dynamic_committee,
    )?));

    let state_producer = Arc::new(StateProducer::new(
        safety_rules.clone(),
        leader_provider,
    ));

    info!("consensus components ready");

    Ok(ConsensusComponents {
        pacemaker: Arc::new(Mutex::new(pacemaker)),
        state_producer,
        safety_rules,
        committee,
        notifier,
        startup_delay: config.startup_delay,
    })
}

/// Pre-assembled consensus components. The caller starts the event
/// loop by providing the genesis/trusted root state.
pub struct ConsensusComponents {
    pub pacemaker: Arc<Mutex<HotStuffPacemaker<GlobalState, GlobalVote>>>,
    pub state_producer: Arc<StateProducer<GlobalState, GlobalVote>>,
    pub safety_rules: Arc<Mutex<SafetyRules<GlobalState, GlobalVote>>>,
    pub committee: Arc<dyn Replicas>,
    pub notifier: Arc<dyn Consumer<GlobalState, GlobalVote>>,
    /// Startup grace period for the event loop. Production uses 45s
    /// (mesh formation latency); tests set `Duration::ZERO`.
    pub startup_delay: Duration,
}

/// Outputs of [`ConsensusComponents::start`].
///
/// Caller is expected to:
/// 1. Use `handle` to submit proposals, votes, QCs, TCs, timeouts.
/// 2. Drive `run_future` to completion on a supervised task. Calling
///    `tokio::spawn(run_future)` is a bug — a panic there leaves
///    consensus dead with no visibility. Register the future with the
///    supervisor instead, so panics surface as `JoinError` and the
///    node shuts down cleanly.
pub struct ConsensusStart {
    pub handle: EventLoopHandle<GlobalState, GlobalVote>,
    pub run_future: std::pin::Pin<
        Box<dyn std::future::Future<Output = quil_types::error::Result<()>> + Send + 'static>,
    >,
}

impl ConsensusComponents {
    /// Build the consensus event loop and return the handle + the
    /// future that drives it.
    ///
    /// The caller MUST schedule `run_future` on a supervised task —
    /// dropping it without driving it means the loop never starts.
    pub fn start(
        self,
        trusted_root: quil_consensus::models::CertifiedState<GlobalState>,
        finalizer: Arc<dyn quil_consensus::forest::Finalizer>,
        follower: Arc<dyn quil_consensus::forest::FollowerConsumer<GlobalState>>,
    ) -> quil_types::error::Result<ConsensusStart> {
        let forks = Forks::<GlobalState>::new(trusted_root, finalizer, follower)?;

        let handler = Arc::new(HotStuffEventHandler::new(
            self.pacemaker,
            self.state_producer,
            Arc::new(Mutex::new(forks)),
            self.safety_rules,
            self.committee,
            self.notifier,
        ));

        // Delay consensus loop start by `startup_delay` so the
        // BlossomSub mesh has time to form before the leader
        // broadcasts its first proposal. Production uses 45s
        // (BlossomSub heartbeats every 1s; first network message
        // arrival observed ~25-30s after startup on a local 4-node
        // bootstrap; a 20s delay was not enough to clear that
        // formation latency). Without sufficient delay, the
        // leader's initial GlobalProposal lands on a bitmask that
        // has zero peers grafted into the mesh — followers never
        // see the proposal, never vote, and the chain stalls at
        // rank 1. Tests can set `startup_delay = Duration::ZERO`
        // to skip the wait entirely.
        let (event_loop, handle) = EventLoop::new(handler, Instant::now() + self.startup_delay);

        info!("global consensus event loop ready");
        Ok(ConsensusStart {
            handle,
            run_future: Box::pin(async move { event_loop.run().await }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consensus_config_default_values() {
        let c = ConsensusConfig::default();
        // Mirrors Go's participant.go:46-106; proposal_duration bumped
        // from 8s to 10s (see Default impl docstring).
        // Empty filter matches Go's global consensus key layout
        // (no filter suffix on CONSENSUS_STATE / LIVENESS keys).
        assert_eq!(c.filter, Vec::<u8>::new());
        assert_eq!(c.min_timeout, Duration::from_secs(36));
        assert_eq!(c.max_timeout, Duration::from_secs(180));
        assert_eq!(c.timeout_adjustment_factor, 1.2);
        assert_eq!(c.happy_path_max_round_failures, 6);
        assert_eq!(c.max_rebroadcast_interval, Duration::from_secs(28));
        assert_eq!(c.proposal_duration, Duration::from_secs(10));
        assert_eq!(c.startup_delay, Duration::from_secs(45));
    }
}

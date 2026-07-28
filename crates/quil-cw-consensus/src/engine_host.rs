//! `build_global_engine` — one call that assembles a simplex `Engine` for
//! Quilibrium global consensus from the three seams + runtime context, hiding
//! the (large) simplex `Config` and generic surface. P2c wires the node by:
//!
//! 1. implementing the three seam traits against real state (P2b);
//! 2. obtaining a runtime context + the 3 p2p channels + a `Blocker`;
//! 3. `build_global_engine(...).start(vote, cert, resolver)`.
//!
//! Equal votes: the elector is `RoundRobin` and the quorum is count-based via
//! the Falcon scheme — no seniority weighting anywhere.

use std::sync::Arc;
use std::time::Duration;

use commonware_consensus::simplex::{
    elector::RoundRobin, Config, Engine, Floor, ForwardingPolicy,
};
use commonware_consensus::types::{Epoch, ViewDelta};
use commonware_cryptography::Sha256;
use commonware_p2p::Blocker;
use commonware_parallel::Sequential;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage, Supervisor as _};
use commonware_utils::{NZUsize, NZU16};

use crate::adapters::{
    BlockStore, Digest, FalconAutomaton, FalconRelay, FalconReporter, FrameFinalizer, FrameSink,
    GlobalProposer,
};
use crate::falcon_base::FalconPublicKey;
use crate::falcon_simplex::SimplexFalconScheme;
use crate::p2p_bridge::{build_channel, NoopBlocker, Outbound};
use commonware_p2p::Message;
use commonware_runtime::{tokio as cw_tokio, Runner as _};

/// Tunables for the global engine. Defaults mirror the current quil-consensus
/// global config intent (see `ConsensusConfig`): a few-second leader timeout,
/// certification ≥ leader, generous fetch/retry.
pub struct GlobalEngineParams {
    /// Unique on-disk journal partition (per engine instance).
    pub partition: String,
    /// Consensus epoch (committee generation).
    pub epoch: u64,
    /// Genesis payload digest = the genesis global-frame identity.
    pub genesis_digest: Digest,
    pub leader_timeout: Duration,
    /// Must be `>= leader_timeout`.
    pub certification_timeout: Duration,
    pub timeout_retry: Duration,
    pub fetch_timeout: Duration,
    /// Must be `>= skip_timeout`.
    pub activity_timeout: u64,
    pub skip_timeout: u64,
}

impl GlobalEngineParams {
    /// Construct with the standard timeouts, supplying only the per-instance
    /// partition/epoch/genesis.
    pub fn new(partition: impl Into<String>, epoch: u64, genesis_digest: Digest) -> Self {
        Self {
            partition: partition.into(),
            epoch,
            genesis_digest,
            // The leader must VDF-prove the next frame INSIDE `propose` before it
            // can return a digest, so `leader_timeout` has to exceed the VDF prove
            // time or every view nullifies before the proposal lands. Localnet
            // difficulty proves in a few seconds (debug ~4s); mainnet is slower.
            // These values mirror the legacy pacemaker's 30–120s replica-timeout
            // window (`min_replica_timeout` 30s). TODO(perf): make difficulty-aware
            // / configurable.
            leader_timeout: Duration::from_secs(30),
            certification_timeout: Duration::from_secs(35),
            timeout_retry: Duration::from_secs(15),
            fetch_timeout: Duration::from_secs(5),
            activity_timeout: 10,
            skip_timeout: 5,
        }
    }

    /// Override the leader timeout (seconds). Certification timeout is kept at
    /// `leader + 5s` (it must be `>= leader_timeout`), and `timeout_retry` at
    /// half the leader timeout (min 5s). `0` leaves the defaults untouched.
    pub fn with_leader_timeout_secs(mut self, secs: u64) -> Self {
        if secs > 0 {
            self.leader_timeout = Duration::from_secs(secs);
            self.certification_timeout = Duration::from_secs(secs + 5);
            self.timeout_retry = Duration::from_secs((secs / 2).max(5));
        }
        self
    }
}

/// The concrete simplex `Engine` type for Quilibrium global consensus.
pub type GlobalEngine<E, B, Pr, Sk, Fin> = Engine<
    E,
    SimplexFalconScheme,
    RoundRobin<Sha256>,
    B,
    Digest,
    FalconAutomaton<E, Pr>,
    FalconRelay<Sk>,
    FalconReporter<Fin>,
    Sequential,
>;

/// Assemble a global-consensus `Engine` from the seams. Call `.start(vote,
/// certificate, resolver)` on the result (three distinct p2p channels) to run it.
#[allow(clippy::too_many_arguments)]
pub fn build_global_engine<E, B, Pr, Sk, Fin>(
    context: E,
    scheme: SimplexFalconScheme,
    blocker: B,
    proposer: Arc<Pr>,
    sink: Arc<Sk>,
    finalizer: Arc<Fin>,
    store: BlockStore,
    params: GlobalEngineParams,
) -> GlobalEngine<E, B, Pr, Sk, Fin>
where
    E: BufferPooler + Clock + rand_core::CryptoRng + Spawner + Storage + Metrics + Send + 'static,
    B: Blocker<PublicKey = FalconPublicKey>,
    Pr: GlobalProposer,
    Sk: FrameSink,
    Fin: FrameFinalizer,
{
    let automaton = FalconAutomaton::new(context.child("automaton"), proposer, store.clone());
    let relay = FalconRelay::new(sink, store.clone());
    let reporter = FalconReporter::new(finalizer, store);

    let cfg = Config {
        scheme,
        elector: RoundRobin::<Sha256>::default(),
        blocker,
        automaton,
        relay,
        reporter,
        strategy: Sequential,
        partition: params.partition,
        mailbox_size: NZUsize!(1024),
        epoch: Epoch::new(params.epoch),
        floor: Floor::Genesis(params.genesis_digest),
        leader_timeout: params.leader_timeout,
        certification_timeout: params.certification_timeout,
        timeout_retry: params.timeout_retry,
        fetch_timeout: params.fetch_timeout,
        activity_timeout: ViewDelta::new(params.activity_timeout),
        skip_timeout: ViewDelta::new(params.skip_timeout),
        fetch_concurrent: NZUsize!(4),
        replay_buffer: NZUsize!(1024 * 1024),
        write_buffer: NZUsize!(1024 * 1024),
        page_cache: CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(10)),
        forwarding: ForwardingPolicy::Disabled,
    };
    Engine::new(context.child("engine"), cfg)
}

// ---------------------------------------------------------------------------
// Node hosting: run the engine on a dedicated commonware tokio runtime thread.
// ---------------------------------------------------------------------------

/// The node's handle to a hosted global-consensus engine. The engine runs on a
/// dedicated OS thread (a commonware tokio runtime cannot nest inside the node's
/// tokio runtime), and the node communicates with it purely over channels:
///
/// - feed each demuxed `:8340` message into `inbound[channel_id]`;
/// - drain `outbound` and fan each message out over `:8340`.
pub struct GlobalHostHandle {
    /// Per-channel inbound senders (0=vote, 1=certificate, 2=resolver).
    pub inbound: [tokio::sync::mpsc::UnboundedSender<Message<FalconPublicKey>>; 3],
    /// Outbound messages the node must deliver over `:8340`.
    pub outbound: tokio::sync::mpsc::UnboundedReceiver<Outbound<FalconPublicKey>>,
}

/// Spawn the global-consensus engine on its own commonware tokio runtime thread
/// and return the node's channel handle. Non-blocking: the engine runs on the
/// spawned thread; the node drives I/O over the returned channels.
#[allow(clippy::too_many_arguments)]
pub fn spawn_global_host<Pr, Sk, Fin>(
    scheme: SimplexFalconScheme,
    peers: std::sync::Arc<[FalconPublicKey]>,
    proposer: Arc<Pr>,
    sink: Arc<Sk>,
    finalizer: Arc<Fin>,
    store: BlockStore,
    params: GlobalEngineParams,
    // Persistent on-disk directory for the simplex journal (view state,
    // notarizations, finalizations). `Some(dir)` MUST be a stable path under
    // the node's data dir so consensus resumes across restarts. `None` uses the
    // runtime default (a RANDOM TEMP dir) — ephemeral, so the engine restarts
    // from `Floor::Genesis` every launch; acceptable only for tests or callers
    // that intentionally don't persist.
    storage_directory: Option<std::path::PathBuf>,
) -> GlobalHostHandle
// NOTE: `store` is supplied by the caller (not created here) so the node can
// hold a clone and insert peer-delivered frame bytes into it — followers must
// populate their BlockStore from inbound blocks or `verify` can never succeed.
where
    Pr: GlobalProposer,
    Sk: FrameSink,
    Fin: FrameFinalizer,
{
    let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel::<Outbound<FalconPublicKey>>();
    let ch0 = build_channel(0, peers.clone(), out_tx.clone());
    let ch1 = build_channel(1, peers.clone(), out_tx.clone());
    let ch2 = build_channel(2, peers, out_tx);

    let inbound = [
        ch0.inbound_tx.clone(),
        ch1.inbound_tx.clone(),
        ch2.inbound_tx.clone(),
    ];
    let (s0, r0) = (ch0.sender, ch0.receiver);
    let (s1, r1) = (ch1.sender, ch1.receiver);
    let (s2, r2) = (ch2.sender, ch2.receiver);

    std::thread::spawn(move || {
        let cfg = match storage_directory {
            Some(dir) => cw_tokio::Config::new().with_storage_directory(dir),
            None => cw_tokio::Config::new(),
        };
        let runner = cw_tokio::Runner::new(cfg);
        runner.start(move |context| async move {
            let engine = build_global_engine(
                context,
                scheme,
                NoopBlocker::<FalconPublicKey>::default(),
                proposer,
                sink,
                finalizer,
                store,
                params,
            );
            // Hold the engine handle alive; keep the runtime resident.
            let _handle = engine.start((s0, r0), (s1, r1), (s2, r2));
            std::future::pending::<()>().await;
        });
    });

    GlobalHostHandle { inbound, outbound: out_rx }
}

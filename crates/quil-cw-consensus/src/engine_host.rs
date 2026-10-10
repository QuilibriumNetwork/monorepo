//! `build_global_engine` — one call that assembles a simplex `Engine` for
//! Quilibrium global consensus from the three seams + runtime context, hiding
//! the (large) simplex `Config` and generic surface. The node wires it by:
//!
//! 1. implementing the three seam traits against real state;
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
    BlockStore, CountingBlocker, Digest, FalconAutomaton, FalconRelay, FalconReporter, FrameFinalizer,
    FrameSink, GlobalProposer,
};
use crate::falcon_base::FalconPublicKey;
use crate::falcon_simplex::SimplexFalconScheme;
use crate::p2p_bridge::{build_channel, build_vote_channel, Outbound};
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
    /// Optional certified restart point, retaining its actual Simplex view.
    finalized_floor: Option<crate::app_cert::AppFinalization>,
    pub leader_timeout: Duration,
    /// Must be `>= leader_timeout`.
    pub certification_timeout: Duration,
    pub timeout_retry: Duration,
    pub fetch_timeout: Duration,
    /// Must be `>= skip_timeout`.
    pub activity_timeout: u64,
    pub skip_timeout: u64,
    /// Records votes and certificates for operators ([`crate::adapters::Liveness`]).
    pub liveness: Option<Arc<crate::adapters::Liveness>>,
}

impl GlobalEngineParams {
    /// Construct with the standard timeouts, supplying only the per-instance
    /// partition/epoch/genesis.
    pub fn new(partition: impl Into<String>, epoch: u64, genesis_digest: Digest) -> Self {
        Self {
            partition: partition.into(),
            epoch,
            genesis_digest,
            finalized_floor: None,
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
            liveness: None,
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

    /// Resume an already finalized proposal without relabeling it as view 0.
    /// The caller authenticates the certificate against its selected committee;
    /// Simplex independently verifies it again when constructing the engine.
    pub fn with_finalized_floor(
        mut self,
        finalization: crate::app_cert::AppFinalization,
    ) -> Result<Self, &'static str> {
        if finalization.proposal.round.epoch() != Epoch::new(self.epoch) {
            return Err("restart certificate belongs to another consensus epoch");
        }
        if finalization.proposal.round.view().is_zero() {
            return Err("restart certificate cannot use the implicit genesis view");
        }
        self.finalized_floor = Some(finalization);
        Ok(self)
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
    let automaton = FalconAutomaton::new(context.child("automaton"), proposer, store.clone())
        .with_liveness(params.liveness.clone());
    let relay = FalconRelay::new(sink, store.clone());
    let reporter = FalconReporter::new(finalizer, store).with_liveness(params.liveness.clone());

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
        floor: match params.finalized_floor {
            Some(finalization) => Floor::Finalized(finalization),
            None => Floor::Genesis(params.genesis_digest),
        },
        leader_timeout: params.leader_timeout,
        certification_timeout: params.certification_timeout,
        timeout_retry: params.timeout_retry,
        fetch_timeout: params.fetch_timeout,
        activity_timeout: ViewDelta::new(params.activity_timeout),
        skip_timeout: ViewDelta::new(params.skip_timeout),
        fetch_concurrent: NZUsize!(4),
        replay_buffer: NZUsize!(1024 * 1024),
        // One writer buffer exists per unpruned view, and a session that does
        // not finalize keeps every view since its last finalization. Two
        // 1 KiB pages is the writer's floor; a vote fits, and a certificate
        // (up to ~23 KB at 34 members) bypasses the buffer in whole pages.
        // The on-disk format does not depend on it.
        write_buffer: NZUsize!(2 * 1024),
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
    /// Join before opening the same journal with a replacement engine.
    pub thread: std::thread::JoinHandle<()>,
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
    // Optional cooperative shutdown flag. `None` → the engine runs until the
    // process exits or an actor stops. `Some(flag)` → the host thread polls it
    // and, once set, stops the engine and drains its work before returning.
    // GLOBAL supervision uses this on shutdown; app-shard consensus also uses
    // it to rebuild a dynamic committee after joining the old instance.
    shutdown: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
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
    let me = {
        use commonware_cryptography::certificate::Scheme as _;
        use commonware_utils::ordered::Quorum as _;
        scheme.me().and_then(|index| scheme.participants().key(index).cloned())
    };
    let ch0 = build_vote_channel(0, peers.clone(), out_tx.clone(), me);
    let ch1 = build_channel(1, peers.clone(), out_tx.clone());
    let ch2 = build_channel(2, peers, out_tx);

    let inbound = [
        ch0.inbound_tx.clone(),
        ch1.inbound_tx.clone(),
        ch2.inbound_tx.clone(),
    ];
    let (s0, r0) = (ch0.sender, crate::nullify_receiver::NullifyReceiver::new(
        ch0.receiver, scheme.clone(), params.epoch));
    let (s1, r1) = (ch1.sender, ch1.receiver);
    let (s2, r2) = (ch2.sender, ch2.receiver);

    let thread = std::thread::spawn(move || {
        let cfg = match storage_directory {
            Some(dir) => {
                let removed = remove_torn_blobs(&dir);
                if removed > 0 {
                    tracing::warn!(removed, storage_directory = %dir.display(),
                        "removed journal blobs whose header was never written (unclean shutdown)");
                }
                cw_tokio::Config::new().with_storage_directory(dir)
            }
            None => cw_tokio::Config::new(),
        };
        // Let the engine observe a failed actor and drain its descendants.
        // Propagating the panic directly to Runner::start would bypass the
        // cleanup below and let detached I/O drop the runtime from within it.
        let runner = cw_tokio::Runner::new(cfg.with_catch_panics(true));
        runner.start(move |context| async move {
            let context = crate::journal_context::JournalContext::new(context);
            let engine = build_global_engine(
                context.child("consensus"),
                scheme,
                CountingBlocker::new(params.liveness.clone()),
                proposer,
                sink,
                finalizer,
                store,
                params,
            );
            // Hold the engine handle alive; keep the runtime resident. The
            // engine stops itself when any of its actors stops (a panicked
            // voter, say): then this thread returns, so the owner can see the
            // host is dead (`thread.is_finished()`) and rebuild it.
            let mut handle = engine.start((s0, r0), (s1, r1), (s2, r2));
            let mut stopped = None;
            loop {
                // Poll the flag (cw_tokio is tokio-backed, so tokio::time works
                // in this runtime); on set, fall through and drop the engine
                // handle to stop this instance. Without a shutdown flag, run
                // until the engine exits or the process stops.
                if shutdown.as_ref().is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire)) {
                    break;
                }
                tokio::select! {
                    outcome = &mut handle => {
                        stopped = Some(outcome);
                        break;
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {}
                }
            }
            if let Some(outcome) = stopped {
                tracing::error!(?outcome, "consensus engine stopped on its own; host exiting");
            }
            // An actor may still be returning from a blocking proposer or
            // filesystem operation after its parent stopped. Dropping the
            // runtime first makes the last actor destroy it from inside Tokio.
            handle.abort();
            context.wait_idle().await;
        });
    });

    GlobalHostHandle { inbound, outbound: out_rx, thread }
}

/// Runtime blob header: magic, runtime version, blob version.
const BLOB_HEADER_BYTES: u64 = 8;
const BLOB_MAGIC: &[u8; 4] = b"CWIC";

/// Remove blobs that hold no more than a header and whose header was never
/// written. A process killed while the journal opens its next section leaves
/// such a file; the runtime reports it as corrupt, the voter panics on open and
/// the member silently stops taking part. Nothing is lost: records follow the
/// header. A larger blob with a bad header is real corruption and is left.
fn remove_torn_blobs(dir: &std::path::Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_dir() {
            removed += remove_torn_blobs(&path);
        } else if meta.len() <= BLOB_HEADER_BYTES
            && std::fs::read(&path).is_ok_and(|bytes| !bytes.starts_with(BLOB_MAGIC))
            && std::fs::remove_file(&path).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod torn_blob_tests {
    use super::*;

    #[test]
    fn only_record_less_blobs_without_a_header_are_removed() {
        let dir = std::env::temp_dir().join(format!("quil-torn-blobs-{}", std::process::id()));
        let partition = dir.join("app-00");
        std::fs::create_dir_all(&partition).unwrap();
        std::fs::write(partition.join("torn"), [0u8; 8]).unwrap();
        std::fs::write(partition.join("empty"), []).unwrap();
        std::fs::write(partition.join("fresh"), b"CWIC\0\0\0\0").unwrap();
        std::fs::write(partition.join("damaged"), [0u8; 64]).unwrap();

        assert_eq!(remove_torn_blobs(&dir), 2);
        assert!(!partition.join("torn").exists() && !partition.join("empty").exists());
        assert!(partition.join("fresh").exists() && partition.join("damaged").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

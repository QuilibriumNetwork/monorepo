//! End-to-end: a real simplex Engine finalizing while driven by OUR
//! `FalconAutomaton` / `FalconRelay` / `FalconReporter` adapters (not
//! commonware's mocks), over trivial in-memory seam impls. This proves the
//! production adapter GLUE — propose → digest → verify → notarize/finalize
//! report — wires correctly into the Engine.
//!
//! Simplification vs the real node: all nodes share ONE `BlockStore`, so a
//! proposed frame is visible to every verifier without a real transport (the
//! `FrameSink` is a no-op here). The transport is exercised separately by the
//! mock-relay round in `falcon_finalize.rs`; here we validate the adapters.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use commonware_consensus::simplex::mocks;
use commonware_consensus::types::{Epoch, Round, View};
use commonware_consensus::simplex::types::{Proposal, Subject};
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_cryptography::{certificate::Scheme as _, Hasher as _, Sha256, Signer as _};
use commonware_math::algebra::Random;
use commonware_p2p::simulated::{Config as NetConfig, Link, Network, Oracle, Receiver, Sender};
use commonware_p2p::Recipients;
use commonware_runtime::{deterministic, Quota, Runner, Supervisor as _};
use commonware_utils::channel::fallible::FallibleExt as _;
use commonware_utils::channel::mpsc;
use commonware_utils::{ordered::Set, N3f1, NZUsize};
use commonware_parallel::Sequential;

use quil_cw_consensus::adapters::{
    BlockStore, FrameFinalizer, FrameSink, GlobalProposer,
};
use quil_cw_consensus::engine_host::{build_global_engine, GlobalEngineParams};
use quil_cw_consensus::falcon_base::{FalconPrivateKey, FalconPublicKey};
use quil_cw_consensus::falcon_simplex::SimplexFalconScheme;

type Chan = (
    Sender<FalconPublicKey, deterministic::Context>,
    Receiver<FalconPublicKey>,
);
const TEST_QUOTA: Quota = Quota::per_second(std::num::NonZeroU32::MAX);

// --- in-memory seam impls -------------------------------------------------

/// Builds a deterministic frame digest per (view, parent); "bytes" = the digest.
struct TestProposer {
    certified_floor: Option<u64>,
}
impl GlobalProposer for TestProposer {
    fn propose(&self, view: u64, parent: Sha256Digest) -> Option<(Sha256Digest, Vec<u8>)> {
        if let Some(floor) = self.certified_floor {
            assert!(view > floor, "the host must resume above the certified view");
        }
        let mut h = Sha256::default();
        h.update(&view.to_be_bytes());
        h.update(parent.as_ref());
        let digest = h.finalize();
        Some((digest, digest.as_ref().to_vec()))
    }
    fn verify(&self, view: u64, parent: Sha256Digest, digest: Sha256Digest, bytes: Option<Vec<u8>>) -> bool {
        let mut h = Sha256::default();
        h.update(&view.to_be_bytes());
        h.update(parent.as_ref());
        h.finalize() == digest && bytes.as_deref() == Some(digest.as_ref())
    }
}

struct NoopSink;
impl FrameSink for NoopSink {
    fn broadcast(&self, _d: Sha256Digest, _b: Vec<u8>, _r: Recipients<FalconPublicKey>) {}
}

/// Signals every finalized view onto a channel so the test can await progress.
struct SignalFinalizer {
    tx: mpsc::UnboundedSender<u64>,
}
impl FrameFinalizer for SignalFinalizer {
    fn on_notarized(&self, _v: u64, _d: Sha256Digest, _b: Option<Vec<u8>>) {}
    fn on_finalized(&self, view: u64, _d: Sha256Digest, _b: Option<Vec<u8>>, _c: Option<Vec<u8>>, _lv: bool) {
        let _ = self.tx.send_lossy(view);
    }
}

async fn register_one(
    oracle: &mut Oracle<FalconPublicKey, deterministic::Context>,
    v: FalconPublicKey,
) -> (Chan, Chan, Chan) {
    let control = oracle.control(v);
    let vote = control.register(0, TEST_QUOTA).await.unwrap();
    let cert = control.register(1, TEST_QUOTA).await.unwrap();
    let resolver = control.register(2, TEST_QUOTA).await.unwrap();
    (vote, cert, resolver)
}

#[test]
fn falcon_adapters_finalize() {
    run_adapters(None);
}

#[test]
fn falcon_adapters_resume_certified_view_despite_different_local_genesis() {
    run_adapters(Some(50));
}

fn run_adapters(certified_view: Option<u64>) {
    let n: usize = 4;
    let namespace = b"global".to_vec();

    let sks: Vec<FalconPrivateKey> =
        (0..n).map(|_| FalconPrivateKey::random(commonware_utils::test_rng())).collect();
    let participants: Vec<FalconPublicKey> = sks.iter().map(|s| s.public_key()).collect();
    let part_set: Set<FalconPublicKey> = participants.clone().try_into().unwrap();
    let schemes: Vec<SimplexFalconScheme> = sks
        .into_iter()
        .map(|sk| SimplexFalconScheme::signer(&namespace, part_set.clone(), sk).unwrap())
        .collect();

    let target_view = certified_view.unwrap_or(0) + 10;
    let epoch = Epoch::new(333);
    let checkpoint = certified_view.map(|view| {
        let proposal = Proposal::new(Round::new(epoch, View::new(view)), View::new(view - 1), Sha256Digest([0xCC; 32]));
        let attestations: Vec<_> = schemes[..3].iter().map(|scheme|
            scheme.sign(Subject::Finalize { proposal: &proposal }).unwrap()).collect();
        quil_cw_consensus::app_cert::AppFinalization {
            proposal,
            certificate: schemes[0].assemble::<_, N3f1>(attestations, &Sequential).unwrap(),
        }
    });

    let executor = deterministic::Runner::timed(Duration::from_secs(300));
    executor.start(|context| async move {
        let (network, mut oracle) = Network::new_with_peers(
            context.child("network"),
            NetConfig { max_size: 1024 * 1024, disconnect_on_block: true, tracked_peer_sets: NZUsize!(1) },
            participants.clone(),
        )
        .await;
        network.start();

        let mut regs: HashMap<FalconPublicKey, (Chan, Chan, Chan)> = HashMap::new();
        for v in participants.iter() {
            regs.insert(v.clone(), register_one(&mut oracle, v.clone()).await);
        }
        let link = Link { latency: Duration::from_millis(10), jitter: Duration::from_millis(1), success_rate: 1.0 };
        for v1 in participants.iter() {
            for v2 in participants.iter() {
                if v1 != v2 {
                    oracle.add_link(v1.clone(), v2.clone(), link.clone()).await.unwrap();
                }
            }
        }

        // Shared seams across all nodes.
        let store = BlockStore::new();
        let proposer = Arc::new(TestProposer { certified_floor: certified_view });
        let (fin_tx, mut fin_rx) = mpsc::unbounded_channel::<u64>();
        let finalizer = Arc::new(SignalFinalizer { tx: fin_tx });

        // Genesis payload digest (shared across nodes).
        let genesis = mocks::application::genesis::<Sha256>(epoch);
        let mut handlers = Vec::new();
        for (idx, v) in participants.iter().enumerate() {
            let vctx = context.child("validator").with_attribute("pk", v);
            let params = if let Some(checkpoint) = &checkpoint {
                GlobalEngineParams::new(format!("adapters-{idx}"), 333, Sha256Digest([idx as u8; 32]))
                    .with_finalized_floor(checkpoint.clone()).unwrap()
            } else {
                GlobalEngineParams::new(format!("adapters-{idx}"), 333, genesis)
            };

            // Build the whole engine through the production host wrapper.
            let engine = build_global_engine(
                vctx,
                schemes[idx].clone(),
                oracle.control(v.clone()),
                proposer.clone(),
                Arc::new(NoopSink),
                finalizer.clone(),
                store.clone(),
                params,
            );
            let (vote, cert, resolver) = regs.remove(v).expect("registered");
            handlers.push(engine.start(vote, cert, resolver));
        }

        // Wait until our FalconReporter observes the target view finalize.
        let mut max_seen = 0u64;
        while max_seen < target_view {
            let v = fin_rx.recv().await.expect("finalization signal");
            if v > max_seen {
                max_seen = v;
            }
        }
        assert!(max_seen >= target_view, "reached finalized view {max_seen}");
    });
}

/// Declines its first turns the way a production-paced leader does.
struct PacedProposer {
    declines: std::sync::atomic::AtomicU32,
    retry: bool,
}
impl GlobalProposer for PacedProposer {
    fn propose(&self, _view: u64, _parent: Sha256Digest) -> Option<(Sha256Digest, Vec<u8>)> {
        use std::sync::atomic::Ordering;
        if self.declines.load(Ordering::Acquire) > 0 {
            self.declines.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some((Sha256Digest([7; 32]), vec![7]))
    }
    fn verify(&self, _: u64, _: Sha256Digest, _: Sha256Digest, _: Option<Vec<u8>>) -> bool {
        false
    }
    fn propose_retry(&self) -> Option<Duration> {
        self.retry.then_some(Duration::from_millis(250))
    }
}

fn paced_propose(retry: bool) -> Option<Sha256Digest> {
    use commonware_consensus::{simplex::types::Context, Automaton as _};
    let leader = FalconPrivateKey::random(commonware_utils::test_rng()).public_key();
    deterministic::Runner::timed(Duration::from_secs(60)).start(|context| async move {
        let proposer = Arc::new(PacedProposer { declines: 3.into(), retry });
        let mut automaton = quil_cw_consensus::adapters::FalconAutomaton::new(
            context.child("automaton"), proposer, BlockStore::new());
        let round = Round::new(Epoch::new(1), View::new(5));
        let pending = automaton
            .propose(Context { round, leader, parent: (View::new(4), Sha256Digest([1; 32])) })
            .await;
        pending.await.ok()
    })
}

#[test]
fn pacing_leader_holds_its_turn_and_others_give_it_up() {
    assert_eq!(paced_propose(true), Some(Sha256Digest([7; 32])));
    assert_eq!(paced_propose(false), None, "a declined turn without a retry nullifies the view");
}

/// Builds at once when asked, but paces itself first.
struct PacingProposer {
    calls: std::sync::atomic::AtomicU32,
}
impl GlobalProposer for PacingProposer {
    fn propose(&self, _view: u64, _parent: Sha256Digest) -> Option<(Sha256Digest, Vec<u8>)> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Some((Sha256Digest([8; 32]), vec![8]))
    }
    fn verify(&self, _: u64, _: Sha256Digest, _: Sha256Digest, _: Option<Vec<u8>>) -> bool {
        false
    }
    fn proposal_pacing(&self, _context: quil_cw_consensus::adapters::ProposalContext) -> Option<Duration> {
        Some(Duration::from_secs(5))
    }
}

/// The pacing is waited out before the proposer is asked to build, so a
/// proposal holds nothing (a selected-parent execution lease) through it.
#[test]
fn a_pacing_leader_is_asked_to_build_only_after_its_wait() {
    use commonware_consensus::{simplex::types::Context, Automaton as _};
    use commonware_runtime::Clock as _;
    use std::sync::atomic::Ordering;
    let leader = FalconPrivateKey::random(commonware_utils::test_rng()).public_key();
    deterministic::Runner::timed(Duration::from_secs(60)).start(|context| async move {
        let proposer = Arc::new(PacingProposer { calls: 0.into() });
        let mut automaton = quil_cw_consensus::adapters::FalconAutomaton::new(
            context.child("automaton"), proposer.clone(), BlockStore::new());
        let started = context.current();
        let round = Round::new(Epoch::new(1), View::new(5));
        let pending = automaton
            .propose(Context { round, leader, parent: (View::new(4), Sha256Digest([1; 32])) })
            .await;
        context.sleep(Duration::from_secs(4)).await;
        assert_eq!(proposer.calls.load(Ordering::Acquire), 0, "nothing is built while pacing");
        assert_eq!(pending.await.ok(), Some(Sha256Digest([8; 32])));
        assert!(context.current().duration_since(started).unwrap() >= Duration::from_secs(5));
        assert_eq!(proposer.calls.load(Ordering::Acquire), 1);
    });
}

/// Busy the way a voter publishing the previous frame is: it defers a number
/// of checks, then answers.
struct BusyVerifier {
    busy_for: std::sync::atomic::AtomicU32,
    answer: bool,
    asked: std::sync::atomic::AtomicU32,
}
impl GlobalProposer for BusyVerifier {
    fn propose(&self, _view: u64, _parent: Sha256Digest) -> Option<(Sha256Digest, Vec<u8>)> {
        None
    }
    fn verify(&self, _: u64, _: Sha256Digest, _: Sha256Digest, _: Option<Vec<u8>>) -> bool {
        unreachable!("the adapter checks through verify_or_defer")
    }
    fn verify_or_defer(
        &self,
        _: quil_cw_consensus::adapters::ProposalContext,
        _: Sha256Digest,
        bytes: Option<Vec<u8>>,
    ) -> Result<bool, Duration> {
        use std::sync::atomic::Ordering;
        assert_eq!(bytes.as_deref(), Some(&[9u8][..]), "every attempt sees the delivered body");
        self.asked.fetch_add(1, Ordering::AcqRel);
        if self.busy_for.load(Ordering::Acquire) > 0 {
            self.busy_for.fetch_sub(1, Ordering::AcqRel);
            return Err(Duration::from_millis(200));
        }
        Ok(self.answer)
    }
}

fn busy_verify(busy_for: u32, answer: bool) -> (Option<bool>, u32) {
    use commonware_consensus::{simplex::types::Context, Automaton as _};
    let leader = FalconPrivateKey::random(commonware_utils::test_rng()).public_key();
    deterministic::Runner::timed(Duration::from_secs(120)).start(|context| async move {
        let verifier = Arc::new(BusyVerifier { busy_for: busy_for.into(), answer, asked: 0.into() });
        let store = BlockStore::new();
        let payload = Sha256Digest([9; 32]);
        store.put(payload, vec![9]);
        let mut automaton = quil_cw_consensus::adapters::FalconAutomaton::new(
            context.child("automaton"), verifier.clone(), store);
        let round = Round::new(Epoch::new(1), View::new(5));
        let pending = automaton
            .verify(Context { round, leader, parent: (View::new(4), Sha256Digest([1; 32])) }, payload)
            .await;
        let verdict = pending.await.ok();
        (verdict, verifier.asked.load(std::sync::atomic::Ordering::Acquire))
    })
}

#[test]
fn a_busy_voter_answers_once_free_instead_of_nullifying() {
    assert_eq!(busy_verify(5, true), (Some(true), 6), "deferred checks are asked again");
    assert_eq!(busy_verify(0, false), (Some(false), 1), "a rejection is final");
    assert_eq!(busy_verify(3, false), (Some(false), 4));
    let (verdict, asked) = busy_verify(u32::MAX, true);
    assert_eq!(verdict, Some(false), "a voter busy past its patience declines");
    assert!(asked > 50 && asked < 200, "bounded by patience, asked {asked} times");
}

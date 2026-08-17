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
use commonware_consensus::types::Epoch;
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_cryptography::{Hasher as _, Sha256, Signer as _};
use commonware_math::algebra::Random;
use commonware_p2p::simulated::{Config as NetConfig, Link, Network, Oracle, Receiver, Sender};
use commonware_p2p::Recipients;
use commonware_runtime::{deterministic, Quota, Runner, Spawner as _, Supervisor as _};
use commonware_utils::channel::fallible::FallibleExt as _;
use commonware_utils::channel::mpsc;
use commonware_utils::{ordered::Set, NZUsize};

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
struct TestProposer;
impl GlobalProposer for TestProposer {
    fn propose(&self, view: u64, parent: Sha256Digest) -> Option<(Sha256Digest, Vec<u8>)> {
        let mut h = Sha256::default();
        h.update(&view.to_be_bytes());
        h.update(parent.as_ref());
        let digest = h.finalize();
        Some((digest, digest.as_ref().to_vec()))
    }
    fn verify(&self, _view: u64, _digest: Sha256Digest, bytes: Option<Vec<u8>>) -> bool {
        // With a shared store the block is always present; a real verifier runs
        // frame validation here.
        bytes.is_some()
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

    let target_view: u64 = 10;
    let epoch = Epoch::new(333);

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
        let proposer = Arc::new(TestProposer);
        let (fin_tx, mut fin_rx) = mpsc::unbounded_channel::<u64>();
        let finalizer = Arc::new(SignalFinalizer { tx: fin_tx });

        // Genesis payload digest (shared across nodes).
        let genesis = mocks::application::genesis::<Sha256>(epoch);
        let mut handlers = Vec::new();
        for (idx, v) in participants.iter().enumerate() {
            let vctx = context.child("validator").with_attribute("pk", v);

            // Build the whole engine through the production host wrapper.
            let engine = build_global_engine(
                vctx,
                schemes[idx].clone(),
                oracle.control(v.clone()),
                proposer.clone(),
                Arc::new(NoopSink),
                finalizer.clone(),
                store.clone(),
                GlobalEngineParams::new(format!("adapters-{idx}"), 333, genesis),
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

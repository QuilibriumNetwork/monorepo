//! Capstone P2c isolation test: N simplex engines on the **real commonware
//! tokio runtime** (the one the node will host), wired through our
//! `p2p_bridge` channels via an in-memory router that stands in for the `:8340`
//! transport, driven by our Falcon adapters. Proves the entire P2c mechanical
//! stack — tokio runtime host + channel Sender/Receiver + adapters + Falcon —
//! finalizes, without the live node.

use std::collections::HashMap;
use std::sync::Arc;

use commonware_consensus::simplex::mocks;
use commonware_consensus::types::Epoch;
use commonware_cryptography::sha256::Digest as Sha256Digest;
use commonware_cryptography::{Hasher as _, Sha256, Signer as _};
use commonware_math::algebra::Random;
use commonware_p2p::Recipients;
use commonware_runtime::{tokio as cw_tokio, Runner as _, Spawner as _, Supervisor as _};
use commonware_utils::ordered::Set;
use tokio::sync::mpsc;

use quil_cw_consensus::adapters::{BlockStore, FrameFinalizer, FrameSink, GlobalProposer};
use quil_cw_consensus::engine_host::{build_global_engine, GlobalEngineParams};
use quil_cw_consensus::falcon_base::{FalconPrivateKey, FalconPublicKey};
use quil_cw_consensus::falcon_simplex::SimplexFalconScheme;
use quil_cw_consensus::p2p_bridge::{build_channel, inbound_message, NoopBlocker, Outbound};

// --- in-memory seams ------------------------------------------------------

struct TestProposer;
impl GlobalProposer for TestProposer {
    fn propose(&self, view: u64, parent: Sha256Digest) -> Option<(Sha256Digest, Vec<u8>)> {
        let mut h = Sha256::default();
        h.update(&view.to_be_bytes());
        h.update(parent.as_ref());
        let digest = h.finalize();
        Some((digest, digest.as_ref().to_vec()))
    }
    fn verify(&self, _v: u64, _d: Sha256Digest, bytes: Option<Vec<u8>>) -> bool {
        bytes.is_some()
    }
}

struct NoopSink;
impl FrameSink for NoopSink {
    fn broadcast(&self, _d: Sha256Digest, _b: Vec<u8>, _r: Recipients<FalconPublicKey>) {}
}

struct SignalFinalizer {
    tx: mpsc::UnboundedSender<u64>,
}
impl FrameFinalizer for SignalFinalizer {
    fn on_notarized(&self, _v: u64, _d: Sha256Digest, _b: Option<Vec<u8>>) {}
    fn on_finalized(
        &self,
        view: u64,
        _d: Sha256Digest,
        _b: Option<Vec<u8>>,
        _c: Option<Vec<u8>>,
        _locally_verified: bool,
    ) {
        let _ = self.tx.send(view);
    }
}

type InMsg = commonware_p2p::Message<FalconPublicKey>;

#[test]
fn falcon_tokio_router_finalizes() {
    let n: usize = 4;
    let namespace = b"global".to_vec();

    let sks: Vec<FalconPrivateKey> =
        (0..n).map(|_| FalconPrivateKey::random(commonware_utils::test_rng())).collect();
    let participants: Vec<FalconPublicKey> = sks.iter().map(|s| s.public_key()).collect();
    let peers: Arc<[FalconPublicKey]> = Arc::from(participants.clone());
    let part_set: Set<FalconPublicKey> = participants.clone().try_into().unwrap();
    let schemes: Vec<SimplexFalconScheme> = sks
        .into_iter()
        .map(|sk| SimplexFalconScheme::signer(&namespace, part_set.clone(), sk).unwrap())
        .collect();

    let target_view: u64 = 8;
    let epoch = Epoch::new(333);

    // The REAL commonware tokio runtime (auto temp storage dir).
    let runner = cw_tokio::Runner::new(cw_tokio::Config::new());
    runner.start(|context| async move {
        let store = BlockStore::new();
        let proposer = Arc::new(TestProposer);
        let (fin_tx, mut fin_rx) = mpsc::unbounded_channel::<u64>();
        let finalizer = Arc::new(SignalFinalizer { tx: fin_tx });
        let genesis = mocks::application::genesis::<Sha256>(epoch);

        // Per-node inbound senders (3 channels each) + outbound receivers.
        let mut inbound: HashMap<FalconPublicKey, [mpsc::UnboundedSender<InMsg>; 3]> = HashMap::new();
        let mut node_outs: Vec<(FalconPublicKey, mpsc::UnboundedReceiver<Outbound<FalconPublicKey>>)> =
            Vec::new();
        let mut handlers = Vec::new();

        for (idx, pk) in participants.iter().enumerate() {
            let vctx = context.child("validator").with_attribute("pk", pk);
            let (out_tx, out_rx) = mpsc::unbounded_channel::<Outbound<FalconPublicKey>>();

            let ch0 = build_channel(0, peers.clone(), out_tx.clone());
            let ch1 = build_channel(1, peers.clone(), out_tx.clone());
            let ch2 = build_channel(2, peers.clone(), out_tx);

            inbound.insert(
                pk.clone(),
                [ch0.inbound_tx.clone(), ch1.inbound_tx.clone(), ch2.inbound_tx.clone()],
            );
            node_outs.push((pk.clone(), out_rx));

            let engine = build_global_engine(
                vctx,
                schemes[idx].clone(),
                NoopBlocker::<FalconPublicKey>::default(),
                proposer.clone(),
                Arc::new(NoopSink),
                finalizer.clone(),
                store.clone(),
                GlobalEngineParams::new(format!("tokio-{idx}"), 333, genesis),
            );
            handlers.push(engine.start(
                (ch0.sender, ch0.receiver),
                (ch1.sender, ch1.receiver),
                (ch2.sender, ch2.receiver),
            ));
        }

        // In-memory router (stands in for :8340): drain each node's outbound and
        // deliver to recipients' matching inbound channel, tagging the sender.
        let inbound = Arc::new(inbound);
        for (pk, mut out_rx) in node_outs {
            let inbound = inbound.clone();
            context.child("router").spawn(move |_| async move {
                while let Some(ob) = out_rx.recv().await {
                    for r in &ob.recipients {
                        if r == &pk {
                            continue; // don't loop our own broadcast back
                        }
                        if let Some(txs) = inbound.get(r) {
                            let _ = txs[ob.channel as usize]
                                .send(inbound_message(pk.clone(), ob.bytes.clone()));
                        }
                    }
                }
            });
        }

        // Await finalization of the target view.
        let mut max_seen = 0u64;
        while max_seen < target_view {
            let v = fin_rx.recv().await.expect("finalization signal");
            if v > max_seen {
                max_seen = v;
            }
        }
        assert!(max_seen >= target_view, "finalized view {max_seen}");
    });
}

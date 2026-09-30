//! Real Falcon/Simplex terminal sealing through the production adapters.
//! Storage/authorization is supplied by a controlled parent reader here; this
//! does not certify runtime state recovery or the live application transport.

use std::collections::{HashMap, HashSet};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256, Signer as _};
use commonware_math::algebra::Random;
use commonware_p2p::{
    simulated::{Config as NetConfig, Link, Network},
    Recipients,
};
use commonware_runtime::{deterministic, Clock as _, Quota, Runner, Supervisor as _};
use commonware_utils::{
    channel::{fallible::FallibleExt as _, mpsc},
    ordered::Set,
    NZUsize,
};
use quil_cw_consensus::{
    adapters::{BlockStore, FrameFinalizer, FrameSink, GlobalProposer, ProposalContext},
    engine_host::{build_global_engine, GlobalEngineParams},
    falcon_base::{FalconPrivateKey, FalconPublicKey},
    falcon_simplex::SimplexFalconScheme,
    handoff::{
        automaton::{AuthorizedParent, HandoffProposer, ParentReader},
        verify_seal, Checkpoint, Seal, Session,
    },
};
use quil_types::error::QuilError;

fn session() -> (Session, Vec<FalconPrivateKey>) {
    let keys: Vec<_> = (0..4)
        .map(|_| FalconPrivateKey::random(commonware_utils::test_rng()))
        .collect();
    let mut members: Vec<Vec<u8>> = keys
        .iter()
        .map(|k| k.public_key().as_ref().to_vec())
        .collect();
    members.sort();
    (
        Session {
            chain_id: [1; 32],
            filter: vec![2; 32],
            generation: 7,
            genesis: [3; 32],
            base_frame: 20,
            authorization: [4; 32],
            members,
        },
        keys,
    )
}

fn genesis(session: &Session) -> AuthorizedParent {
    AuthorizedParent {
        checkpoint: Checkpoint {
            frame: session.base_frame,
            view: 0,
            digest: session.genesis,
            state_roots: [[5; 32]; 4],
            history_root: [6; 32],
        },
        closing_request: None,
    }
}

fn context(session: &Session, parent: &AuthorizedParent, view: u64) -> ProposalContext {
    ProposalContext {
        epoch: session.generation,
        view,
        parent_view: parent.checkpoint.view,
        parent: Digest(parent.checkpoint.digest),
    }
}

struct DataProposer;
impl GlobalProposer for DataProposer {
    fn propose(&self, view: u64, parent: Digest) -> Option<(Digest, Vec<u8>)> {
        let mut bytes = b"DATA".to_vec();
        bytes.extend_from_slice(&view.to_be_bytes());
        bytes.extend_from_slice(&parent.0);
        Some((Sha256::hash(&bytes), bytes))
    }
    fn verify(&self, view: u64, parent: Digest, digest: Digest, bytes: Option<Vec<u8>>) -> bool {
        self.propose(view, parent)
            .map(|(d, b)| d == digest && Some(b) == bytes)
            .unwrap()
    }
}

fn reader(state: Arc<Mutex<Option<AuthorizedParent>>>) -> ParentReader {
    Arc::new(move |_| {
        state
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| QuilError::ExecutionUnavailable("parent state/history not ready".into()))
    })
}

#[test]
fn seal_votes_bind_every_checkpoint_field_and_consensus_coordinate() {
    let (session, _) = session();
    let mut parent = genesis(&session);
    parent.checkpoint.frame += 1;
    parent.checkpoint.view = 11;
    parent.checkpoint.digest = [9; 32];
    parent.closing_request = Some([8; 32]);
    let state = Arc::new(Mutex::new(Some(parent.clone())));
    let proposer =
        HandoffProposer::new(Arc::new(DataProposer), session.clone(), reader(state)).unwrap();
    let ctx = context(&session, &parent, 18);
    let (digest, bytes) = proposer.propose_with_context(ctx).unwrap();
    let seal = Seal::decode(&bytes).unwrap();
    assert_eq!(seal.checkpoint, parent.checkpoint);
    assert!(proposer.verify_with_context(ctx, digest, Some(bytes.clone())));
    for field in 0..11 {
        let mut changed = seal.clone();
        match field {
            0 => changed.request[0] ^= 1,
            1 => changed.session[0] ^= 1,
            2 => changed.view += 1,
            3 => changed.checkpoint.frame += 1,
            4 => changed.checkpoint.view += 1,
            5 => changed.checkpoint.digest[0] ^= 1,
            6..=9 => changed.checkpoint.state_roots[field - 6][0] ^= 1,
            _ => changed.checkpoint.history_root[0] ^= 1,
        }
        // Even its correctly recomputed digest cannot authorize changed state.
        assert!(!proposer.verify_with_context(
            ctx,
            Digest(changed.digest()),
            Some(changed.encode())
        ));
    }
    for changed in [
        ProposalContext {
            epoch: ctx.epoch + 1,
            ..ctx
        },
        ProposalContext {
            view: ctx.parent_view,
            ..ctx
        },
        ProposalContext {
            parent_view: ctx.parent_view + 1,
            ..ctx
        },
        ProposalContext {
            parent: Digest([99; 32]),
            ..ctx
        },
    ] {
        assert!(proposer.propose_with_context(changed).is_none());
        assert!(!proposer.verify_with_context(changed, digest, Some(bytes.clone())));
    }
    assert!(!proposer.verify_with_context(
        ProposalContext {
            view: ctx.view + 1,
            ..ctx
        },
        digest,
        Some(bytes.clone())
    ));
    assert!(!proposer.verify_with_context(ctx, Digest([99; 32]), Some(bytes)));
    assert!(!proposer.verify_with_context(ctx, digest, None));
    assert!(proposer.propose(ctx.view, ctx.parent).is_none());
    assert!(!proposer.verify(ctx.view, ctx.parent, digest, None));
}

#[test]
fn closing_keeps_inflight_data_valid_but_read_failure_and_seal_descendants_abstain() {
    let (session, _) = session();
    let parent = genesis(&session);
    let state = Arc::new(Mutex::new(Some(parent.clone())));
    let proposer = HandoffProposer::new(
        Arc::new(DataProposer),
        session.clone(),
        reader(state.clone()),
    )
    .unwrap();
    let ctx = context(&session, &parent, 4);
    let (data_digest, data_bytes) = proposer.propose_with_context(ctx).unwrap();
    assert!(proposer.verify_with_context(ctx, data_digest, Some(data_bytes.clone())));
    state.lock().unwrap().as_mut().unwrap().closing_request = Some([8; 32]);
    assert!(proposer.verify_with_context(ctx, data_digest, Some(data_bytes.clone())));
    let (seal_digest, seal_bytes) = proposer.propose_with_context(ctx).unwrap();
    assert!(Seal::decode(&seal_bytes).is_ok());
    let child = ProposalContext {
        view: 9,
        parent_view: ctx.view,
        parent: seal_digest,
        ..ctx
    };
    let (child_digest, child_bytes) = DataProposer.propose(child.view, child.parent).unwrap();
    // A fresh guard has never seen the seal. It still refuses all descendants.
    let restarted =
        HandoffProposer::new(Arc::new(DataProposer), session, reader(state.clone())).unwrap();
    assert!(restarted.propose_with_context(child).is_none());
    assert!(!restarted.verify_with_context(child, child_digest, Some(child_bytes)));
    state.lock().unwrap().as_mut().unwrap().closing_request = None;
    assert!(!proposer.verify_with_context(ctx, seal_digest, Some(seal_bytes.clone())));
    *state.lock().unwrap() = None;
    assert!(proposer.propose_with_context(ctx).is_none());
    assert!(!proposer.verify_with_context(ctx, data_digest, Some(data_bytes)));
    assert!(!proposer.verify_with_context(ctx, seal_digest, Some(seal_bytes)));
}

#[test]
fn unauthorized_genesis_and_malformed_seals_cannot_be_proposed_or_voted() {
    let (session, _) = session();
    let mut parent = genesis(&session);
    parent.closing_request = Some([8; 32]);
    let state = Arc::new(Mutex::new(Some(parent.clone())));
    let proposer = HandoffProposer::new(
        Arc::new(DataProposer),
        session.clone(),
        reader(state.clone()),
    )
    .unwrap();
    let ctx = context(&session, &parent, 4);
    let (_, bytes) = proposer.propose_with_context(ctx).unwrap();
    for bad in [
        bytes[..bytes.len() - 1].to_vec(),
        [bytes.clone(), vec![0]].concat(),
        b"QHSL\x02".to_vec(),
    ] {
        assert!(!proposer.verify_with_context(ctx, Sha256::hash(&bad), Some(bad)));
    }
    for bad in [
        Checkpoint {
            frame: session.base_frame - 1,
            ..parent.checkpoint.clone()
        },
        Checkpoint {
            frame: session.base_frame + 1,
            ..parent.checkpoint.clone()
        },
        Checkpoint {
            view: 2,
            ..parent.checkpoint.clone()
        },
        Checkpoint {
            digest: [99; 32],
            ..parent.checkpoint.clone()
        },
    ] {
        let bad_parent = AuthorizedParent {
            checkpoint: bad,
            closing_request: parent.closing_request,
        };
        let bad_ctx = context(&session, &bad_parent, 4);
        *state.lock().unwrap() = Some(bad_parent);
        assert!(proposer.propose_with_context(bad_ctx).is_none());
    }
}

struct NoopSink;
impl FrameSink for NoopSink {
    fn broadcast(&self, _: Digest, _: Vec<u8>, _: Recipients<FalconPublicKey>) {}
}

struct Finalizer {
    node: usize,
    session: Session,
    state: Arc<Mutex<Option<AuthorizedParent>>>,
    tx: mpsc::UnboundedSender<(usize, Seal, Vec<u8>)>,
}
impl FrameFinalizer for Finalizer {
    fn on_notarized(&self, _: u64, _: Digest, _: Option<Vec<u8>>) {}
    fn on_finalized(
        &self,
        view: u64,
        digest: Digest,
        bytes: Option<Vec<u8>>,
        cert: Option<Vec<u8>>,
        _: bool,
    ) {
        let bytes = bytes.unwrap();
        if Seal::is_encoding(&bytes) {
            let seal = Seal::decode(&bytes).unwrap();
            let certificate = cert.unwrap();
            assert_eq!(seal.view, view);
            assert_eq!(seal.digest(), digest.0);
            assert!(verify_seal(&self.session, &[8; 32], &seal, &certificate).is_some());
            let _ = self.tx.send_lossy((self.node, seal, certificate));
        } else {
            let mut state = self.state.lock().unwrap();
            let parent = state.as_mut().unwrap();
            assert_eq!(
                parent.checkpoint.frame, self.session.base_frame,
                "only one data frame may finalize"
            );
            parent.checkpoint = Checkpoint {
                frame: self.session.base_frame + 1,
                view,
                digest: digest.0,
                state_roots: [[10; 32]; 4],
                history_root: [11; 32],
            };
            parent.closing_request = Some([8; 32]);
        }
    }
}

#[test]
fn four_member_simplex_finalizes_a_terminal_seal_after_nullified_views() {
    let (session, keys) = session();
    let participants: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
    let set: Set<_> = participants.clone().try_into().unwrap();
    let schemes: Vec<_> = keys
        .into_iter()
        .map(|key| {
            SimplexFalconScheme::signer(&session.namespace().unwrap(), set.clone(), key).unwrap()
        })
        .collect();
    deterministic::Runner::timed(Duration::from_secs(120)).start(|ctx| async move {
        let (network, oracle) = Network::new_with_peers(
            ctx.child("network"),
            NetConfig {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
            participants.clone(),
        )
        .await;
        network.start();
        let mut regs = HashMap::new();
        for peer in &participants {
            let control = oracle.control(peer.clone());
            let quota = Quota::per_second(std::num::NonZeroU32::MAX);
            regs.insert(
                peer.clone(),
                (
                    control.register(0, quota).await.unwrap(),
                    control.register(1, quota).await.unwrap(),
                    control.register(2, quota).await.unwrap(),
                ),
            );
        }
        for a in &participants {
            for b in &participants {
                if a != b {
                    oracle
                        .add_link(
                            a.clone(),
                            b.clone(),
                            Link {
                                latency: Duration::from_millis(10),
                                jitter: Duration::from_millis(1),
                                success_rate: 1.0,
                            },
                        )
                        .await
                        .unwrap();
                }
            }
        }
        // The real vote/certificate/resolver channels are simulated. Payload
        // bytes share a store, as in the existing production-adapter tests.
        let store = BlockStore::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let rejected_descendants = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for (node, peer) in participants.iter().enumerate() {
            let state = Arc::new(Mutex::new(Some(genesis(&session))));
            let parent_state = state.clone();
            let rejected = rejected_descendants.clone();
            let read: ParentReader = Arc::new(move |context| {
                let parent = parent_state.lock().unwrap().clone().unwrap();
                if context.parent.0 != parent.checkpoint.digest && parent.closing_request.is_some()
                {
                    rejected.fetch_add(1, Ordering::SeqCst);
                }
                // Exercise a genuine gap between the data parent and the seal.
                if context.parent_view > 0 && context.view < 5 {
                    return Err(QuilError::ExecutionUnavailable(
                        "checkpoint not ready yet".into(),
                    ));
                }
                Ok(parent)
            });
            let proposer = Arc::new(
                HandoffProposer::new(Arc::new(DataProposer), session.clone(), read).unwrap(),
            );
            let finalizer = Arc::new(Finalizer {
                node,
                session: session.clone(),
                state,
                tx: tx.clone(),
            });
            let params = GlobalEngineParams::new(
                format!("handoff-{node}"),
                session.generation,
                Digest(session.genesis),
            )
            .with_leader_timeout_secs(1);
            let engine = build_global_engine(
                ctx.child("validator").with_attribute("node", node),
                schemes[node].clone(),
                oracle.control(peer.clone()),
                proposer,
                Arc::new(NoopSink),
                finalizer,
                store.clone(),
                params,
            );
            let (vote, cert, resolver) = regs.remove(peer).unwrap();
            handles.push(engine.start(vote, cert, resolver));
        }
        let mut seen = HashSet::new();
        let mut expected = None;
        while seen.len() < participants.len() {
            let (node, seal, _) = rx.recv().await.unwrap();
            assert!(seal.view >= 5 && seal.view > seal.checkpoint.view + 1);
            assert_eq!(seal.checkpoint.frame, session.base_frame + 1);
            if let Some(prior) = &expected {
                assert_eq!(&seal, prior);
            }
            expected = Some(seal);
            seen.insert(node);
        }
        ctx.sleep(Duration::from_secs(12)).await;
        assert!(
            rejected_descendants.load(Ordering::SeqCst) > 0,
            "live host attempted to extend the seal and abstained"
        );
    });
}

#[test]
fn leader_waits_briefly_for_a_parent_it_has_not_materialized() {
    let (session, _) = session();
    let parent = genesis(&session);
    let ctx = context(&session, &parent, 1);
    let state = Arc::new(Mutex::new(None));
    let proposer =
        HandoffProposer::new(Arc::new(DataProposer), session, reader(state.clone())).unwrap();

    assert!(proposer.propose_with_context(ctx).is_none());
    assert!(proposer.propose_retry().is_some(), "the parent is about to be finalized locally");
    *state.lock().unwrap() = Some(parent);
    assert!(proposer.propose_with_context(ctx).is_some());
    assert!(proposer.propose_retry().is_none(), "a built proposal leaves nothing to wait for");

    // A member that stays behind gives the view up after a bounded wait.
    *state.lock().unwrap() = None;
    let mut asked = 0;
    while proposer.propose_with_context(ctx).is_none() && proposer.propose_retry().is_some() {
        asked += 1;
        assert!(asked < 100, "the wait is bounded");
    }
    assert!(asked >= 4);
    // The next view starts its own count.
    let next = ProposalContext { view: 2, ..ctx };
    assert!(proposer.propose_with_context(next).is_none());
    assert!(proposer.propose_retry().is_some());
}

#[test]
fn an_unmaterialized_parent_is_read_privately_after_the_leader_waits_and_at_once_for_votes() {
    let (session, _) = session();
    let parent = genesis(&session);
    let ctx = context(&session, &parent, 1);
    let committed = Arc::new(Mutex::new(None));
    let private_reads = Arc::new(AtomicUsize::new(0));
    let private: ParentReader = {
        let parent = parent.clone();
        let reads = private_reads.clone();
        Arc::new(move |_| {
            reads.fetch_add(1, Ordering::SeqCst);
            Ok(parent.clone())
        })
    };
    let proposer = HandoffProposer::new(Arc::new(DataProposer), session.clone(), reader(committed.clone()))
        .unwrap()
        .with_private_reader(Some(private.clone()));
    // The leader first waits for its own materialization, as before.
    let mut asked = 0;
    let built = loop {
        match proposer.propose_with_context(ctx) {
            Some(built) => break built,
            None => {
                assert!(proposer.propose_retry().is_some(), "still waiting for the parent");
                assert_eq!(private_reads.load(Ordering::SeqCst), 0, "no private execution while waiting");
                asked += 1;
                assert!(asked < 100);
            }
        }
    };
    assert!(asked >= 4, "waited before executing privately");
    assert_eq!(private_reads.load(Ordering::SeqCst), 1);
    // A voter reads the private parent at once rather than refusing its vote.
    let (digest, bytes) = DataProposer.propose(1, Digest(parent.checkpoint.digest)).unwrap();
    assert_eq!(built.0, digest);
    let voter = HandoffProposer::new(Arc::new(DataProposer), session.clone(), reader(committed.clone()))
        .unwrap()
        .with_private_reader(Some(private));
    assert!(voter.verify_with_context(ctx, digest, Some(bytes.clone())));
    assert_eq!(private_reads.load(Ordering::SeqCst), 2);
    // Without one, an unmaterialized parent still refuses the vote.
    let plain = HandoffProposer::new(Arc::new(DataProposer), session, reader(committed)).unwrap();
    assert!(!plain.verify_with_context(ctx, digest, Some(bytes)));
}

#[test]
fn a_generation_zero_session_extends_its_certified_legacy_tip() {
    let (mut session, _) = session();
    session.generation = 0;
    // The registered tip: a certified legacy frame at its own view.
    let tip = AuthorizedParent {
        checkpoint: Checkpoint { view: 41, ..genesis(&session).checkpoint },
        closing_request: None,
    };
    let state = Arc::new(Mutex::new(Some(tip.clone())));
    let proposer =
        HandoffProposer::new(Arc::new(DataProposer), session.clone(), reader(state.clone())).unwrap();
    let ctx = context(&session, &tip, 44);
    let (digest, bytes) = proposer.propose_with_context(ctx).unwrap();
    assert!(proposer.verify_with_context(ctx, digest, Some(bytes)));

    // Any other frame at the base is not the registered tip.
    let other = AuthorizedParent {
        checkpoint: Checkpoint { digest: [99; 32], ..tip.checkpoint.clone() },
        closing_request: None,
    };
    *state.lock().unwrap() = Some(other.clone());
    assert!(proposer.propose_with_context(context(&session, &other, 44)).is_none());

    // A positive generation still requires its virtual genesis at view zero.
    let mut later = session.clone();
    later.generation = 1;
    *state.lock().unwrap() = Some(tip.clone());
    let strict = HandoffProposer::new(Arc::new(DataProposer), later.clone(), reader(state)).unwrap();
    assert!(strict.propose_with_context(ProposalContext { epoch: 1, ..ctx }).is_none());
}

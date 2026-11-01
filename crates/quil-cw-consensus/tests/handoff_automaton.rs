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
    adapters::{
        BlockStore, FrameFinalizer, FrameSink, GlobalProposer, Liveness, ProposalContext, Step,
    },
    engine_host::{build_global_engine, GlobalEngineParams},
    falcon_base::{FalconPrivateKey, FalconPublicKey},
    falcon_simplex::SimplexFalconScheme,
    handoff::{
        automaton::{
            AuthorizedParent, ClosingAbsence, ClosingProbe, HandoffProposer, ParentReader,
            CLOSING_REQUEST_WAIT,
        },
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
        leader: None,
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

/// [`DataProposer`] whose proposals wait for something on its way (a GLOBAL
/// anchor) while `waiting`.
struct AnchoredProposer {
    waiting: std::sync::atomic::AtomicBool,
}

const ANCHOR_WAIT: Duration = Duration::from_millis(250);

impl GlobalProposer for AnchoredProposer {
    fn propose(&self, view: u64, parent: Digest) -> Option<(Digest, Vec<u8>)> {
        DataProposer.propose(view, parent)
    }
    fn verify(&self, view: u64, parent: Digest, digest: Digest, bytes: Option<Vec<u8>>) -> bool {
        DataProposer.verify(view, parent, digest, bytes)
    }
    fn verify_delay(&self, _: ProposalContext, _: &[u8]) -> Option<Duration> {
        self.waiting.load(Ordering::SeqCst).then_some(ANCHOR_WAIT)
    }
}

/// A session member that cannot take its turn or vote for a proposal says
/// why, once per view; and a data proposal waits for what its data proposer
/// waits for, where the session once refused it outright. A seal is checked
/// at once.
#[test]
fn session_refusals_are_named_and_data_proposals_wait_for_their_anchor() {
    let (session, _) = session();
    let parent = genesis(&session);
    let state = Arc::new(Mutex::new(None));
    let liveness = Arc::new(Liveness::default());
    let inner = Arc::new(AnchoredProposer {
        waiting: true.into(),
    });
    let proposer = HandoffProposer::new(inner.clone(), session.clone(), reader(state.clone()))
        .unwrap()
        .with_liveness(Some(liveness.clone()));

    // No authorized parent yet: the turn is declined and the vote refused.
    let first = context(&session, &parent, 1);
    assert!(proposer.propose_with_context(first).is_none());
    liveness.settle(Step::Propose, 1, false);
    let (digest, bytes) = DataProposer.propose(1, first.parent).unwrap();
    assert!(!proposer.verify_with_context(first, digest, Some(bytes)));
    liveness.settle(Step::Verify, 1, false);
    // A block that never arrived.
    *state.lock().unwrap() = Some(parent.clone());
    let second = context(&session, &parent, 2);
    assert!(!proposer.verify_with_context(second, digest, None));
    liveness.settle(Step::Verify, 2, false);
    // Another epoch's coordinates.
    let other_epoch = ProposalContext {
        epoch: session.generation + 1,
        ..context(&session, &parent, 3)
    };
    assert!(!proposer.verify_with_context(other_epoch, digest, Some(vec![1])));
    liveness.settle(Step::Verify, 3, false);
    let decided = liveness.decisions();
    assert_eq!(decided.declined.get("parent unavailable"), Some(&1));
    assert!(decided
        .last_declined
        .unwrap()
        .detail
        .contains("parent state/history not ready"));
    assert_eq!(decided.refused.get("parent unavailable"), Some(&1));
    assert_eq!(decided.refused.get("block not delivered"), Some(&1));
    assert_eq!(
        decided.refused.get("epoch is not the session's generation"),
        Some(&1)
    );

    // A data proposal waits while its anchor is on its way, then is checked.
    let fourth = context(&session, &parent, 4);
    let (digest, bytes) = DataProposer.propose(4, fourth.parent).unwrap();
    assert_eq!(
        proposer.verify_or_defer(fourth, digest, Some(bytes.clone())),
        Err(ANCHOR_WAIT)
    );
    inner.waiting.store(false, Ordering::SeqCst);
    assert_eq!(
        proposer.verify_or_defer(fourth, digest, Some(bytes)),
        Ok(true)
    );
    // A seal is checked at once (refused here: nothing is closing).
    inner.waiting.store(true, Ordering::SeqCst);
    let seal = Seal {
        request: [8; 32],
        session: session.id().unwrap(),
        view: 4,
        checkpoint: parent.checkpoint.clone(),
    };
    assert_eq!(
        proposer.verify_or_defer(fourth, Digest(seal.digest()), Some(seal.encode())),
        Ok(false)
    );
    liveness.settle(Step::Verify, 4, false);
    assert_eq!(
        liveness
            .decisions()
            .refused
            .get("seal while no closing request"),
        Some(&1)
    );
}

/// A seal of this session whose closing request this member's committed
/// GLOBAL view lacks waits while that view is being refreshed and is accepted
/// once the request arrives; with a current view, or for another session, it
/// is refused at once, naming what this member's view lacked.
#[test]
fn a_seal_waits_for_a_refreshing_view_to_bring_its_closing_request() {
    let (session, _) = session();
    let mut parent = genesis(&session);
    parent.checkpoint.frame += 1;
    parent.checkpoint.view = 11;
    parent.checkpoint.digest = [9; 32];
    let state = Arc::new(Mutex::new(Some(parent.clone())));
    let liveness = Arc::new(Liveness::default());
    let absence = Arc::new(Mutex::new(ClosingAbsence {
        detail: "no closing request in the committed GLOBAL view at frame 40, GLOBAL head 45"
            .into(),
        refreshing: true,
    }));
    let (probe, asked) = (absence.clone(), Arc::new(AtomicUsize::new(0)));
    let probe_asked = asked.clone();
    let proposer = HandoffProposer::new(
        Arc::new(DataProposer),
        session.clone(),
        reader(state.clone()),
    )
    .unwrap()
    .with_liveness(Some(liveness.clone()))
    .with_closing_probe(Some(Arc::new(move || {
        probe_asked.fetch_add(1, Ordering::SeqCst);
        probe.lock().unwrap().clone()
    })));
    let ctx = context(&session, &parent, 18);
    let seal = Seal {
        request: [8; 32],
        session: session.id().unwrap(),
        view: 18,
        checkpoint: parent.checkpoint.clone(),
    };
    let (digest, bytes) = (Digest(seal.digest()), seal.encode());

    // Behind and refreshing: checked again later, not refused.
    assert_eq!(
        proposer.verify_or_defer(ctx, digest, Some(bytes.clone())),
        Err(CLOSING_REQUEST_WAIT)
    );
    // Another session's seal is not waited for, and asks nothing of the view.
    let foreign = Seal {
        session: [0; 32],
        ..seal.clone()
    };
    let before = asked.load(Ordering::SeqCst);
    assert_eq!(
        proposer.verify_or_defer(ctx, Digest(foreign.digest()), Some(foreign.encode())),
        Ok(false)
    );
    assert_eq!(asked.load(Ordering::SeqCst), before);
    // The refresh brings the request: the same seal is accepted.
    state.lock().unwrap().as_mut().unwrap().closing_request = Some([8; 32]);
    assert_eq!(proposer.verify_or_defer(ctx, digest, Some(bytes)), Ok(true));
    liveness.settle(Step::Verify, 18, true);

    // A current view refuses at once and names the input it lacked.
    state.lock().unwrap().as_mut().unwrap().closing_request = None;
    absence.lock().unwrap().refreshing = false;
    let next = context(&session, &parent, 19);
    let current = Seal { view: 19, ..seal };
    assert_eq!(
        proposer.verify_or_defer(next, Digest(current.digest()), Some(current.encode())),
        Ok(false)
    );
    liveness.settle(Step::Verify, 19, false);
    let decided = liveness.decisions();
    assert_eq!(decided.accepted, 1);
    assert_eq!(
        decided.refused.get("seal while no closing request"),
        Some(&1)
    );
    let last = decided.last_refused.unwrap();
    assert_eq!(
        (last.view, last.detail.as_str()),
        (
            19,
            "no closing request in the committed GLOBAL view at frame 40, GLOBAL head 45"
        )
    );
}

/// One vote through the adapter's verify loop on a seal whose closing request
/// this member's refreshing view lacks; the request arrives with the probe's
/// `lands_at` check, if ever. Returns the verdict, whether it took the voter's
/// whole patience, and the refusals noted under the missing request.
fn vote_on_waiting_seal(lands_at: Option<usize>) -> (Option<bool>, bool, Option<u64>) {
    use commonware_consensus::{
        simplex::types::Context,
        types::{Epoch, Round, View},
        Automaton as _,
    };
    let (session, _) = session();
    let mut parent = genesis(&session);
    parent.checkpoint.frame += 1;
    parent.checkpoint.view = 11;
    parent.checkpoint.digest = [9; 32];
    let state = Arc::new(Mutex::new(Some(parent.clone())));
    let (landing, checks) = (state.clone(), Arc::new(AtomicUsize::new(0)));
    let probe: ClosingProbe = Arc::new(move || {
        if lands_at.is_some_and(|at| checks.fetch_add(1, Ordering::SeqCst) + 1 >= at) {
            landing.lock().unwrap().as_mut().unwrap().closing_request = Some([8; 32]);
        }
        ClosingAbsence {
            detail: "no closing request in the committed GLOBAL view at frame 40, GLOBAL head 45"
                .into(),
            refreshing: true,
        }
    });
    let liveness = Arc::new(Liveness::default());
    let proposer = Arc::new(
        HandoffProposer::new(Arc::new(DataProposer), session.clone(), reader(state))
            .unwrap()
            .with_liveness(Some(liveness.clone()))
            .with_closing_probe(Some(probe)),
    );
    let seal = Seal {
        request: [8; 32],
        session: session.id().unwrap(),
        view: 18,
        checkpoint: parent.checkpoint.clone(),
    };
    let leader = FalconPrivateKey::random(commonware_utils::test_rng()).public_key();
    let generation = session.generation;
    let counted = liveness.clone();
    let (verdict, whole_patience) =
        deterministic::Runner::timed(Duration::from_secs(120)).start(|context| async move {
            let store = BlockStore::new();
            let payload = Digest(seal.digest());
            store.put(payload, seal.encode());
            let mut automaton = quil_cw_consensus::adapters::FalconAutomaton::new(
                context.child("automaton"),
                proposer,
                store,
            )
            .with_liveness(Some(counted));
            let started = context.current();
            let round = Round::new(Epoch::new(generation), View::new(18));
            let pending = automaton
                .verify(
                    Context {
                        round,
                        leader,
                        parent: (View::new(11), Digest([9; 32])),
                    },
                    payload,
                )
                .await;
            let verdict = pending.await.ok();
            (
                verdict,
                context.current().duration_since(started).unwrap() >= Duration::from_secs(20),
            )
        });
    (
        verdict,
        whole_patience,
        liveness
            .decisions()
            .refused
            .get("seal while no closing request")
            .copied(),
    )
}

/// A waiting seal is accepted once the refresh brings its closing request,
/// and refused, never accepted, when its patience runs out without it.
#[test]
fn a_waiting_seal_is_refused_when_its_closing_request_never_arrives() {
    assert_eq!(vote_on_waiting_seal(Some(3)), (Some(true), false, None));
    assert_eq!(vote_on_waiting_seal(None), (Some(false), true, Some(1)));
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

/// A seal notarized without a finalization stays the parent of every later
/// view; nothing could extend it, so every view was nullified until GLOBAL
/// fenced the session. Its re-seal (same request, session and checkpoint, at
/// its own view, `checkpoint.view` naming the seal's view) extends it and is
/// the only proposal voters accept there; a re-seal extends a re-seal alike.
#[test]
fn a_notarized_seal_is_extended_only_by_its_re_seal() {
    let (session, _) = session();
    let mut tip = genesis(&session);
    tip.checkpoint.frame += 3;
    tip.checkpoint.view = 11;
    tip.checkpoint.digest = [9; 32];
    tip.closing_request = Some([8; 32]);
    let state = Arc::new(Mutex::new(Some(tip.clone())));
    let store = BlockStore::new();
    let liveness = Arc::new(Liveness::default());
    let proposer = HandoffProposer::new(
        Arc::new(DataProposer),
        session.clone(),
        reader(state.clone()),
    )
    .unwrap()
    .with_seal_parents(store.clone(), reader(state.clone()))
    .with_liveness(Some(liveness.clone()));
    let ctx = context(&session, &tip, 13);
    let (seal_digest, seal_bytes) = proposer.propose_with_context(ctx).unwrap();
    let seal = Seal::decode(&seal_bytes).unwrap();
    // Notarized at view 13: every member that voted for it holds its body.
    store.seal(seal_digest, seal_bytes);
    let above = ProposalContext {
        view: 20,
        parent_view: 13,
        parent: seal_digest,
        ..ctx
    };
    let (digest, bytes) = proposer.propose_with_context(above).unwrap();
    let reseal = Seal::decode(&bytes).unwrap();
    assert_eq!(
        reseal,
        Seal {
            view: 20,
            checkpoint: Checkpoint {
                view: 13,
                ..tip.checkpoint.clone()
            },
            ..seal.clone()
        }
    );
    assert_eq!(digest.0, reseal.digest());
    assert!(proposer.verify_with_context(above, digest, Some(bytes.clone())));

    // A re-seal that was itself only notarized is extended the same way.
    store.seal(digest, bytes.clone());
    let next = ProposalContext {
        view: 24,
        parent_view: 20,
        parent: digest,
        ..ctx
    };
    let (next_digest, next_bytes) = proposer.propose_with_context(next).unwrap();
    assert_eq!(
        Seal::decode(&next_bytes).unwrap().checkpoint,
        Checkpoint {
            view: 20,
            ..tip.checkpoint.clone()
        }
    );
    assert!(proposer.verify_with_context(next, next_digest, Some(next_bytes.clone())));

    // A member that never held the seal's body (it did not vote for it)
    // recognises the seal of its own tip by its certified digest; a re-seal
    // above a re-seal it holds no body of, it cannot.
    let other = HandoffProposer::new(
        Arc::new(DataProposer),
        session.clone(),
        reader(state.clone()),
    )
    .unwrap()
    .with_seal_parents(BlockStore::new(), reader(state.clone()));
    assert!(other.verify_with_context(above, digest, Some(bytes.clone())));
    assert_eq!(
        other.propose_with_context(above),
        Some((digest, bytes.clone()))
    );
    assert!(!other.verify_with_context(next, next_digest, Some(next_bytes)));

    // Data never continues a seal; nor does a re-seal naming anything else.
    let (data_digest, data_bytes) = DataProposer.propose(above.view, above.parent).unwrap();
    assert!(!proposer.verify_with_context(above, data_digest, Some(data_bytes)));
    liveness.settle(Step::Verify, above.view, false);
    for field in 0..9 {
        let mut changed = reseal.clone();
        match field {
            0 => changed.request[0] ^= 1,
            1 => changed.view += 1,
            2 => changed.checkpoint.view = tip.checkpoint.view,
            3 => changed.checkpoint.frame += 1,
            4 => changed.checkpoint.digest[0] ^= 1,
            5 => changed.checkpoint.state_roots[1][0] ^= 1,
            6 => changed.checkpoint.history_root[0] ^= 1,
            7 => changed.session[0] ^= 1,
            _ => changed = seal.clone(),
        }
        assert!(
            !proposer.verify_with_context(above, Digest(changed.digest()), Some(changed.encode())),
            "field {field}"
        );
    }
    assert!(!proposer.verify_with_context(
        ProposalContext {
            parent_view: 12,
            ..above
        },
        digest,
        Some(bytes.clone())
    ));
    liveness.settle(Step::Verify, above.view, false);
    let refused = liveness.decisions().refused;
    assert!(
        refused.contains_key("data frame above a terminal seal"),
        "{refused:?}"
    );
    assert!(
        refused.contains_key("seal parent differs from the authorized checkpoint"),
        "{refused:?}"
    );

    // A member without the seal's body, or whose tip is not the sealed
    // checkpoint, or which no longer sees the request, neither proposes nor
    // accepts one.
    let blind = HandoffProposer::new(
        Arc::new(DataProposer),
        session.clone(),
        reader(state.clone()),
    )
    .unwrap();
    assert!(blind.propose_with_context(above).is_none());
    assert!(!blind.verify_with_context(above, digest, Some(bytes.clone())));
    state
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .checkpoint
        .history_root[0] ^= 1;
    assert!(proposer.propose_with_context(above).is_none());
    assert!(!proposer.verify_with_context(above, digest, Some(bytes.clone())));
    *state.lock().unwrap() = Some(AuthorizedParent {
        closing_request: None,
        ..tip.clone()
    });
    assert!(!proposer.verify_with_context(above, digest, Some(bytes.clone())));
    *state.lock().unwrap() = Some(AuthorizedParent {
        closing_request: Some([7; 32]),
        ..tip.clone()
    });
    assert!(!proposer.verify_with_context(above, digest, Some(bytes)));

    // A seal at the session base names the genesis at view zero; its re-seal
    // names the genesis at that seal's view, and GLOBAL accepts it from its
    // seal recovery frame. Members that never held the base seal recognise it.
    let base = AuthorizedParent {
        closing_request: Some([8; 32]),
        ..genesis(&session)
    };
    *state.lock().unwrap() = Some(base.clone());
    let (base_digest, base_bytes) = proposer
        .propose_with_context(context(&session, &base, 3))
        .unwrap();
    store.seal(base_digest, base_bytes);
    let above_base = ProposalContext {
        view: 6,
        parent_view: 3,
        parent: base_digest,
        ..ctx
    };
    let (reseal_digest, reseal_bytes) = proposer.propose_with_context(above_base).unwrap();
    let base_reseal = Seal::decode(&reseal_bytes).unwrap();
    assert_eq!(
        base_reseal.checkpoint,
        Checkpoint {
            view: 3,
            ..base.checkpoint.clone()
        }
    );
    assert!(other.verify_with_context(above_base, reseal_digest, Some(reseal_bytes)));
    assert!(base_reseal.validate(&session, &[8; 32]).is_err());
    assert!(base_reseal.validate_with(&session, &[8; 32], true).is_ok());
}

/// At a session base a member sees only seals: each one it verifies says
/// whether it shares the member's state roots. Seals differing in anything
/// else, or closing another request, say nothing about its state.
#[test]
fn verified_seals_report_whether_they_share_this_members_state_roots() {
    let (session, _) = session();
    let tip = AuthorizedParent {
        closing_request: Some([8; 32]),
        ..genesis(&session)
    };
    let state = Arc::new(Mutex::new(Some(tip.clone())));
    let votes = Arc::new(Mutex::new(Vec::new()));
    let record = votes.clone();
    let proposer = HandoffProposer::new(
        Arc::new(DataProposer),
        session.clone(),
        reader(state.clone()),
    )
    .unwrap()
    .with_checkpoint_votes(Some(Arc::new(move |agreed| {
        record.lock().unwrap().push(agreed)
    })));
    let ctx = context(&session, &tip, 4);
    let seal = Seal {
        request: [8; 32],
        session: session.id().unwrap(),
        view: 4,
        checkpoint: tip.checkpoint.clone(),
    };
    let verify =
        |seal: &Seal| proposer.verify_with_context(ctx, Digest(seal.digest()), Some(seal.encode()));
    assert!(verify(&seal));
    let mut other_roots = seal.clone();
    other_roots.checkpoint.state_roots[2][0] ^= 1;
    assert!(!verify(&other_roots));
    let mut other_history = seal.clone();
    other_history.checkpoint.history_root[0] ^= 1;
    assert!(!verify(&other_history));
    let other_request = Seal {
        request: [7; 32],
        ..other_roots.clone()
    };
    assert!(!verify(&other_request));
    assert_eq!(*votes.lock().unwrap(), vec![true, false]);
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
    assert!(
        proposer.propose_retry().is_some(),
        "the parent is about to be finalized locally"
    );
    *state.lock().unwrap() = Some(parent);
    assert!(proposer.propose_with_context(ctx).is_some());
    assert!(
        proposer.propose_retry().is_none(),
        "a built proposal leaves nothing to wait for"
    );

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
    let proposer = HandoffProposer::new(
        Arc::new(DataProposer),
        session.clone(),
        reader(committed.clone()),
    )
    .unwrap()
    .with_private_reader(Some(private.clone()));
    // The leader first waits for its own materialization, as before.
    let mut asked = 0;
    let built = loop {
        match proposer.propose_with_context(ctx) {
            Some(built) => break built,
            None => {
                assert!(
                    proposer.propose_retry().is_some(),
                    "still waiting for the parent"
                );
                assert_eq!(
                    private_reads.load(Ordering::SeqCst),
                    0,
                    "no private execution while waiting"
                );
                asked += 1;
                assert!(asked < 100);
            }
        }
    };
    assert!(asked >= 4, "waited before executing privately");
    assert_eq!(private_reads.load(Ordering::SeqCst), 1);
    // A voter reads the private parent at once rather than refusing its vote.
    let (digest, bytes) = DataProposer
        .propose(1, Digest(parent.checkpoint.digest))
        .unwrap();
    assert_eq!(built.0, digest);
    let voter = HandoffProposer::new(
        Arc::new(DataProposer),
        session.clone(),
        reader(committed.clone()),
    )
    .unwrap()
    .with_private_reader(Some(private));
    assert!(voter.verify_with_context(ctx, digest, Some(bytes.clone())));
    assert_eq!(private_reads.load(Ordering::SeqCst), 2);
    // Without one, an unmaterialized parent still refuses the vote.
    let plain = HandoffProposer::new(Arc::new(DataProposer), session, reader(committed)).unwrap();
    assert!(!plain.verify_with_context(ctx, digest, Some(bytes)));
}

/// A seal finalizes a notarized checkpoint with no certificate of its own,
/// which GLOBAL could then never execute (eight sessions refused until the
/// fence, 2026-10-15). A closing session's leader extends such a parent with
/// data; a voter waits for the checkpoint to finalize before voting for its
/// seal, and seals of a finalized one go through as before.
#[test]
fn a_closing_session_seals_only_a_checkpoint_that_finalized() {
    let (session, _) = session();
    let mut data = genesis(&session);
    data.closing_request = Some([8; 32]);
    data.checkpoint.frame += 1;
    data.checkpoint.view = 5;
    data.checkpoint.digest = [9; 32];
    let committed = Arc::new(Mutex::new(None));
    let private = Arc::new(Mutex::new(Some(data.clone())));
    let member = || {
        HandoffProposer::new(
            Arc::new(DataProposer),
            session.clone(),
            reader(committed.clone()),
        )
        .unwrap()
        .with_private_reader(Some(reader(private.clone())))
    };
    let (leader, voter) = (member(), member());
    let ctx = context(&session, &data, 6);
    let seal = Seal {
        request: [8; 32],
        session: session.id().unwrap(),
        view: 6,
        checkpoint: data.checkpoint.clone(),
    };
    let (seal_digest, seal_bytes) = (Digest(seal.digest()), seal.encode());

    let mut built = None;
    for _ in 0..20 {
        built = leader.propose_with_context(ctx);
        if built.is_some() {
            break;
        }
    }
    let (digest, bytes) = built.expect("the leader proposes after its waits");
    assert!(
        !Seal::is_encoding(&bytes),
        "data, not a seal of an unfinalized checkpoint"
    );
    assert!(
        voter.verify_with_context(ctx, digest, Some(bytes)),
        "the data extending it is voted for"
    );
    assert!(
        voter
            .verify_or_defer(ctx, seal_digest, Some(seal_bytes.clone()))
            .is_err(),
        "the voter waits"
    );
    assert!(!voter.verify_with_context(ctx, seal_digest, Some(seal_bytes.clone())));

    *committed.lock().unwrap() = Some(data);
    let (digest, bytes) = leader
        .propose_with_context(ctx)
        .expect("a finalized checkpoint is sealed at once");
    assert_eq!((digest, bytes.clone()), (seal_digest, seal_bytes));
    assert_eq!(voter.verify_or_defer(ctx, digest, Some(bytes)), Ok(true));
}

#[test]
fn a_generation_zero_session_extends_its_certified_legacy_tip() {
    let (mut session, _) = session();
    session.generation = 0;
    // The registered tip: a certified legacy frame at its own view.
    let tip = AuthorizedParent {
        checkpoint: Checkpoint {
            view: 41,
            ..genesis(&session).checkpoint
        },
        closing_request: None,
    };
    let state = Arc::new(Mutex::new(Some(tip.clone())));
    let proposer = HandoffProposer::new(
        Arc::new(DataProposer),
        session.clone(),
        reader(state.clone()),
    )
    .unwrap();
    let ctx = context(&session, &tip, 44);
    let (digest, bytes) = proposer.propose_with_context(ctx).unwrap();
    assert!(proposer.verify_with_context(ctx, digest, Some(bytes)));

    // Any other frame at the base is not the registered tip.
    let other = AuthorizedParent {
        checkpoint: Checkpoint {
            digest: [99; 32],
            ..tip.checkpoint.clone()
        },
        closing_request: None,
    };
    *state.lock().unwrap() = Some(other.clone());
    assert!(proposer
        .propose_with_context(context(&session, &other, 44))
        .is_none());

    // A positive generation still requires its virtual genesis at view zero.
    let mut later = session.clone();
    later.generation = 1;
    *state.lock().unwrap() = Some(tip.clone());
    let strict =
        HandoffProposer::new(Arc::new(DataProposer), later.clone(), reader(state)).unwrap();
    assert!(strict
        .propose_with_context(ProposalContext { epoch: 1, ..ctx })
        .is_none());
}

#[test]
fn a_seal_of_private_data_can_be_resealed_without_materializing_its_checkpoint() {
    let (session, _) = session();
    let mut tip = genesis(&session);
    tip.closing_request = Some([8; 32]);
    let committed = Arc::new(Mutex::new(Some(tip.clone())));
    let mut data = tip.clone();
    data.checkpoint.frame += 1;
    data.checkpoint.view = 5;
    data.checkpoint.digest = [9; 32];
    data.checkpoint.state_roots = [[10; 32]; 4];
    data.checkpoint.history_root = [11; 32];
    let private = Arc::new(Mutex::new(Some(data.clone())));
    let blocks = BlockStore::new();
    let reads = Arc::new(AtomicUsize::new(0));
    let proposer = HandoffProposer::new(
        Arc::new(DataProposer),
        session.clone(),
        reader(committed.clone()),
    )
    .unwrap()
    .with_private_reader(Some(reader(private.clone())))
    .with_seal_parents(blocks.clone(), reader(committed.clone()))
    .with_private_checkpoint_reader(Some({
        let private = private.clone();
        let reads = reads.clone();
        Arc::new(move |_, _| {
            reads.fetch_add(1, Ordering::SeqCst);
            private.lock().unwrap().clone().ok_or_else(|| {
                QuilError::ExecutionUnavailable("checkpoint body unavailable".into())
            })
        })
    }));
    let ctx = context(&session, &data, 6);
    let mut built = None;
    for _ in 0..20 {
        built = proposer.propose_with_context(ctx);
        if built.is_some() {
            break;
        }
    }
    // This leader extends private data with data, not a seal (decided
    // 2026-10-16); an older leader sealed it, and that seal must still be
    // re-sealable.
    let (_, bytes) = built.expect("the private-parent path proposes");
    assert!(
        !Seal::is_encoding(&bytes),
        "no seal of an unfinalized checkpoint"
    );
    let older = Seal {
        request: [8; 32],
        session: session.id().unwrap(),
        view: 6,
        checkpoint: data.checkpoint.clone(),
    };
    let (digest, bytes) = (Digest(older.digest()), older.encode());
    blocks.seal(digest, bytes);
    let above = ProposalContext {
        view: 8,
        parent_view: 6,
        parent: digest,
        ..ctx
    };
    let (digest, bytes) = proposer
        .propose_with_context(above)
        .expect("a seal of private data must have a valid successor");
    assert!(proposer.verify_with_context(above, digest, Some(bytes.clone())));
    blocks.seal(digest, bytes);
    let again = ProposalContext {
        view: 11,
        parent_view: 8,
        parent: digest,
        ..ctx
    };
    let (digest, bytes) = proposer
        .propose_with_context(again)
        .expect("re-seal of a re-seal");
    assert!(proposer.verify_with_context(again, digest, Some(bytes.clone())));
    assert_eq!(Seal::decode(&bytes).unwrap().checkpoint.view, 8);
    assert_eq!(
        committed.lock().unwrap().as_ref().unwrap().checkpoint,
        tip.checkpoint
    );

    // Independently derived state/history, exact frame/digest and the current
    // authorized request still have to match the selected seal.
    for field in 0..6 {
        let mut changed = data.clone();
        match field {
            0 => changed.checkpoint.frame += 1,
            1 => changed.checkpoint.digest[0] ^= 1,
            2 => changed.checkpoint.state_roots[0][0] ^= 1,
            3 => changed.checkpoint.history_root[0] ^= 1,
            4 => changed.closing_request = Some([7; 32]),
            _ => changed.closing_request = None,
        }
        *private.lock().unwrap() = Some(changed);
        assert!(
            proposer.propose_with_context(again).is_none(),
            "field {field}"
        );
        assert!(
            !proposer.verify_with_context(again, digest, Some(bytes.clone())),
            "field {field}"
        );
    }
    *private.lock().unwrap() = None;
    assert!(proposer.propose_with_context(again).is_none());
    assert!(!proposer.verify_with_context(again, digest, Some(bytes.clone())));

    // A same-height disagreement is never repaired using a private overlay.
    let mut divergent = data.clone();
    divergent.checkpoint.state_roots[0][0] ^= 1;
    *committed.lock().unwrap() = Some(divergent);
    *private.lock().unwrap() = Some(data);
    let count = reads.load(Ordering::SeqCst);
    assert!(proposer.propose_with_context(again).is_none());
    assert!(!proposer.verify_with_context(again, digest, Some(bytes)));
    assert_eq!(reads.load(Ordering::SeqCst), count);
}

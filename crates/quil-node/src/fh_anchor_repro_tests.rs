//! A/B reproducers for the GLOBAL anchor of a shard frame header. GLOBAL's
//! validation reads the header's GLOBAL anchor from the clock store before
//! any window check, and a frame it does not hold is `ExecutionUnavailable`:
//! the materializer then fails the whole GLOBAL frame, on every replica, on
//! every retry. Only an honest leader's collector keeps anchors in the
//! lockstep window, so the header needs no key, only a leader that carries
//! it. A deterministic refusal skips the header instead.
//! The controls run a localnet process's consensus settings
//! (`initialize(1)`) with real Falcon certificates and an authorized
//! session.

use std::{collections::HashMap, sync::Arc};

use num_bigint::BigInt;
use quil_cw_consensus::{
    _consensus::{
        simplex::{
            scheme::Namespace,
            types::{Finalization, Proposal, Subject},
        },
        types::{Epoch, Round, View},
    },
    _crypto::{sha256::Digest, Signer as _},
    _utils::{ordered::Set, N3f1},
    app_cert::{encode_finalization, wrap_cert_for_header},
    falcon_base::FalconPrivateKey,
    falcon_scheme::Generic,
    falcon_simplex::SimplexFalconScheme,
    handoff::Session,
};
use quil_engine::execution_deferral::held_unverified;
use quil_engine::message_collector::{anchor_in_lockstep, bundle_shard_frames_in_lockstep};
use quil_engine::test_support::TestProverRegistry;
use quil_execution::{
    global_intrinsic::{
        frame_header::{
            anchor_outside_window, anchor_window, FrameHeader as CanonicalHeader, TYPE_FRAME_HEADER,
        },
        handoff,
        intrinsic::GlobalIntrinsic,
    },
    hypergraph_state::HypergraphState,
    message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest},
};
use quil_types::{
    consensus::{ProverAllocation, ProverInfo, ProverStatus, RewardIssuance},
    crypto::Signer as _,
    error::{QuilError, Result},
    proto::{global::FrameHeader, keys::Bls48581AggregateSignature},
};

/// Anchors no store holds when GLOBAL frame [`HALT_FRAME`] executes: the
/// next frame, the frame itself, far ahead, the largest number, and one
/// below the frames the rig holds (as a frame below a node's history).
const UNHELD_ANCHORS: [u64; 5] = [17, 16, 1_000_000, u64::MAX, 1];
/// The GLOBAL frame validating them; the rig holds frames 2 to 15.
const HALT_FRAME: u64 = 16;

/// Pays nothing.
struct NoIssuance;
impl RewardIssuance for NoIssuance {
    fn calculate(
        &self,
        _: u64,
        _: u64,
        _: u64,
        provers: &[HashMap<String, ProverAllocation>],
    ) -> Result<Vec<BigInt>> {
        Ok(vec![BigInt::from(0); provers.len()])
    }
}

fn keys() -> Vec<FalconPrivateKey> {
    (0..4)
        .map(|_| {
            let key = quil_crypto::FalconSigner::generate();
            FalconPrivateKey::from_bytes(key.private_key(), key.public_key()).unwrap()
        })
        .collect()
}

fn session(keys: &[FalconPrivateKey]) -> Session {
    let mut members: Vec<_> = keys
        .iter()
        .map(|key| key.public_key().as_ref().to_vec())
        .collect();
    members.sort();
    Session {
        chain_id: [0x21; 32],
        filter: vec![0x68; 32],
        generation: 1,
        genesis: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap(),
        base_frame: 0,
        authorization: [0x34; 32],
        members,
    }
}

/// A finalization of `digest` at `view` by three of the four `keys`.
fn sign(session: &Session, keys: &[FalconPrivateKey], view: u64, digest: [u8; 32]) -> Vec<u8> {
    let proposal = Proposal::new(
        Round::new(Epoch::new(session.generation), View::new(view)),
        View::new(0),
        Digest(digest),
    );
    let participants: Set<_> = keys
        .iter()
        .map(|key| key.public_key())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let schemes: Vec<Generic<Namespace>> = keys
        .iter()
        .cloned()
        .map(|key| {
            Generic::signer(&session.namespace().unwrap(), participants.clone(), key).unwrap()
        })
        .collect();
    let votes: Vec<_> = schemes[..3]
        .iter()
        .map(|scheme| {
            scheme
                .sign::<SimplexFalconScheme, Digest>(Subject::Finalize {
                    proposal: &proposal,
                })
                .unwrap()
        })
        .collect();
    let certificate = schemes[0]
        .assemble::<SimplexFalconScheme, _, N3f1>(votes)
        .unwrap();
    encode_finalization(&Finalization {
        proposal,
        certificate,
    })
}

/// The output GLOBAL frame `number` has in the rig's clock store.
fn global_output(number: u64) -> Vec<u8> {
    vec![0x40 ^ (number as u8); 32]
}

/// The session's first frame, anchored to GLOBAL frame `anchor`, certified
/// by three of its four members.
fn certified_header(session: &Session, keys: &[FalconPrivateKey], anchor: u64) -> CanonicalHeader {
    let beacon = if anchor == 0 {
        quil_crypto::porep::derive_storage_beacon(0, &[])
    } else {
        quil_crypto::porep::derive_storage_beacon(anchor, &global_output(anchor))
    };
    let mut header = FrameHeader {
        address: session.filter.clone(),
        frame_number: session.base_frame + 1,
        rank: 5,
        difficulty: 50_000,
        timestamp: 1_700_000_000_000,
        global_frame_number: anchor,
        parent_selector: session.genesis.to_vec(),
        requests_root: vec![0; 32],
        state_roots: vec![vec![0; 32]; 4],
        ..Default::default()
    };
    header.output = quil_crypto::porep::deterministic_app_frame_output(
        &header.parent_selector,
        &header.requests_root,
        &header.state_roots,
        &beacon,
        header.frame_number,
        header.rank,
        &header.prover,
        header.difficulty,
        header.fee_multiplier_vote,
        header.timestamp,
        &header.storage_attestation_root,
        0,
        &header.settlements,
        &header.accumulator,
        &header.spends,
    );
    let certificate = sign(
        session,
        keys,
        header.rank,
        quil_crypto::poseidon::hash_bytes_to_32(&header.output).unwrap(),
    );
    header.public_key_signature_bls48581 = Some(Bls48581AggregateSignature {
        signature: wrap_cert_for_header(&certificate),
        ..Default::default()
    });
    CanonicalHeader {
        address: header.address,
        frame_number: header.frame_number,
        rank: header.rank,
        timestamp: header.timestamp,
        difficulty: header.difficulty,
        output: header.output,
        parent_selector: header.parent_selector,
        requests_root: header.requests_root,
        state_roots: header.state_roots,
        prover: header.prover,
        global_frame_number: header.global_frame_number,
        public_key_signature_bls48581: header
            .public_key_signature_bls48581
            .map_or_else(Vec::new, |s| s.signature),
        ..Default::default()
    }
}

/// A shard frame header anyone can write: no certificate, no signature, an
/// output that matches nothing, anchored to GLOBAL frame `anchor`.
fn junk_header(anchor: u64) -> Vec<u8> {
    CanonicalHeader {
        address: vec![0x77; 32],
        frame_number: 9,
        rank: 9,
        global_frame_number: anchor,
        output: vec![0x5a; 32],
        parent_selector: vec![0x11; 32],
        requests_root: vec![0; 32],
        state_roots: vec![vec![0; 32]; 4],
        ..Default::default()
    }
    .to_canonical_bytes()
    .unwrap()
}

/// A bundle carrying `header` bytes as they are.
fn header_bundle(header: Vec<u8>) -> Vec<u8> {
    CanonicalMessageBundle {
        requests: vec![Some(CanonicalMessageRequest {
            inner_type_prefix: TYPE_FRAME_HEADER,
            inner_bytes: header,
        })],
        timestamp: 0,
    }
    .to_canonical_bytes()
    .unwrap()
}

fn commit(state: &HypergraphState, number: u64) {
    state.commit().unwrap();
    state.abort();
    state
        .crdt()
        .commit_with_global_cursor(
            number,
            &quil_store::encoding::global_materialized_cursor_key(),
        )
        .unwrap();
}

/// GLOBAL as an archive executes it: the full frame-header dependencies,
/// GLOBAL frames `held` in its clock store, and the session authorized at
/// GLOBAL frame 2.
struct Rig {
    keys: Vec<FalconPrivateKey>,
    session: Session,
    state: HypergraphState,
    intrinsic: GlobalIntrinsic,
}

impl Rig {
    fn new(held: impl IntoIterator<Item = u64>) -> Self {
        crate::consensus_settings::initialize(1);
        let keys = keys();
        let session = session(&keys);
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let inclusion = Arc::new(quil_hypergraph::testing::StubProver);
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store,
            inclusion.clone(),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        let state = HypergraphState::new(crdt);
        commit(&state, 1);
        let registry = Arc::new(TestProverRegistry::with_provers(
            session
                .members
                .iter()
                .map(|key| ProverInfo {
                    address: quil_crypto::poseidon::hash_bytes_to_32(key)
                        .unwrap()
                        .to_vec(),
                    public_key: key.clone(),
                    status: ProverStatus::Historic,
                    kick_frame_number: 0,
                    allocations: Vec::new(),
                    available_storage: 0,
                    seniority: 0,
                    delegate_address: Vec::new(),
                })
                .collect(),
        ));
        let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
        {
            use quil_types::store::ClockStore as _;
            let txn = clock.new_transaction(false).unwrap();
            for number in held {
                clock
                    .put_global_clock_frame(
                        &quil_types::proto::global::GlobalFrame {
                            header: Some(quil_types::proto::global::GlobalFrameHeader {
                                frame_number: number,
                                output: global_output(number),
                                difficulty: 160_000,
                                ..Default::default()
                            }),
                            requests: Vec::new(),
                        },
                        txn.as_ref(),
                    )
                    .unwrap();
            }
            txn.commit().unwrap();
        }
        handoff::initialize(&state, 2, &session).unwrap();
        commit(&state, 2);
        let intrinsic = GlobalIntrinsic::new_with_stores(
            Arc::new(quil_execution::testing::NoopKeyManager),
            Some(Arc::new(quil_crypto::WesolowskiFrameProver::new(2048))),
            Some(clock),
            None,
            None,
        )
        .with_kick_verify_deps(
            Arc::new(quil_crypto::FalconKeyConstructor),
            state.crdt().clone(),
            inclusion,
        )
        .with_frame_header_deps(registry, Arc::new(NoIssuance));
        Self {
            keys,
            session,
            state,
            intrinsic,
        }
    }

    fn certified(&self, anchor: u64) -> Vec<u8> {
        certified_header(&self.session, &self.keys, anchor)
            .to_canonical_bytes()
            .unwrap()
    }
}

/// The materializer fails the whole GLOBAL frame on an `ExecutionUnavailable`
/// from validation (`frame_materializer.rs`, both the sequential step and the
/// parallel header pre-pass), and retries it forever: validation must refuse
/// a header whose anchor this node cannot hold now, never report it
/// unavailable.
#[test]
fn fh_halt_global_validation_refuses_unheld_anchors_deterministically() {
    let rig = Rig::new(2..HALT_FRAME);
    let setup = rig
        .intrinsic
        .validate(HALT_FRAME, &junk_header(HALT_FRAME - 1), None, None);
    match &setup {
        Err(error) if !error.is_execution_unavailable() => {}
        other => panic!(
            "FH SETUP: the junk header anchored to a held in-window frame must be refused \
             deterministically (deps installed, anchor read), got {other:?}"
        ),
    }
    let mut halts = Vec::new();
    for anchor in UNHELD_ANCHORS {
        match rig
            .intrinsic
            .validate(HALT_FRAME, &junk_header(anchor), None, None)
        {
            Ok(_) => panic!(
                "FH UNEXPECTED: GLOBAL frame {HALT_FRAME} admitted a junk header anchored to \
                 {anchor}"
            ),
            Err(error) if error.is_execution_unavailable() => halts.push((anchor, error)),
            Err(_) => {}
        }
    }
    assert!(
        halts.is_empty(),
        "FH HALT: GLOBAL frame {HALT_FRAME} validation reports a shard header that no key \
         signed as unavailable for {} of {} unheld anchors, so the materializer fails the whole \
         frame on every archive and every retry: {:?}",
        halts.len(),
        UNHELD_ANCHORS.len(),
        halts
            .iter()
            .map(|(anchor, error)| format!("{anchor}: {error}"))
            .collect::<Vec<_>>()
    );
}

/// A certified header anchored inside the window, at both edges, is admitted
/// and executed.
#[test]
fn fh_control_certified_header_anchored_in_window_is_admitted() {
    // [frame - 1 - 12, frame - 1]: anchor 2 is the newest for frame 3 and the
    // oldest for frame 15.
    for frame in [3, 15] {
        let rig = Rig::new([2]);
        let wire = rig.certified(2);
        let admitted = rig.intrinsic.validate(frame, &wire, None, None);
        assert!(
            matches!(admitted, Ok(true)),
            "control: GLOBAL frame {frame} must admit a certified header anchored to 2: \
             {admitted:?}"
        );
        let executed = rig.intrinsic.invoke_step(frame, &wire, &rig.state);
        assert!(
            executed.is_ok(),
            "control: GLOBAL frame {frame} must execute a certified header anchored to 2: \
             {executed:?}"
        );
    }
    eprintln!("FH CONTROL: in-window certified headers are admitted and executed");
}

/// A frame inside the window that this node lacks while the others hold it
/// is a local gap: the node must wait for it, not refuse the header, or it
/// would split from the nodes that execute the header.
#[test]
fn fh_control_in_window_anchor_this_node_lacks_stays_unavailable() {
    let gap = HALT_FRAME - 2;
    let rig = Rig::new((2..HALT_FRAME).filter(|number| *number != gap));
    match rig
        .intrinsic
        .validate(HALT_FRAME, &rig.certified(gap), None, None)
    {
        Err(error) if error.is_execution_unavailable() => {}
        other => panic!(
            "control: an in-window anchor this node lacks must stay unavailable, got {other:?}"
        ),
    }
    eprintln!("FH CONTROL: an in-window anchor this node lacks stays unavailable");
}

/// What a held anchor outside the window does today, whichever way
/// validation decides: execution refuses it deterministically (the engine
/// rolls the step back and the materializer skips it). A refusal in
/// validation therefore changes no outcome for a header whose anchor a
/// node holds.
#[test]
fn fh_fact_held_anchor_outside_the_window_is_refused_in_execution() {
    // Older than the window (frame 16 needs [3, 15]); newer than it (frame 5
    // needs [0, 4]), as on a node holding GLOBAL headers above its execution.
    for (frame, anchor) in [(16, 2), (5, 9)] {
        let rig = Rig::new([2, 9]);
        let wire = rig.certified(anchor);
        let validated = rig.intrinsic.validate(frame, &wire, None, None);
        let executed = rig.intrinsic.invoke_step(frame, &wire, &rig.state);
        match executed {
            Err(QuilError::InvalidArgument(reason)) if reason.contains("lockstep") => {
                eprintln!(
                    "FH FACT: GLOBAL frame {frame}, held anchor {anchor}: validation {:?}, \
                     execution refused: {reason}",
                    validated.map_err(|e| e.to_string())
                );
            }
            other => panic!(
                "fact changed: GLOBAL frame {frame} with held anchor {anchor} outside the \
                 window: execution {other:?}, validation {validated:?}"
            ),
        }
    }
}

/// From the required-anchor epoch a header without an anchor is refused
/// deterministically.
#[test]
fn fh_control_header_without_anchor_is_refused_deterministically() {
    std::env::set_var("QUIL_REQUIRED_ANCHOR_EPOCH", "0");
    let rig = Rig::new(2..HALT_FRAME);
    for wire in [junk_header(0), rig.certified(0)] {
        match rig.intrinsic.validate(HALT_FRAME, &wire, None, None) {
            Err(QuilError::InvalidArgument(reason)) => {
                assert!(reason.contains("names no GLOBAL anchor"), "{reason}")
            }
            other => panic!("control: an unanchored header must be refused: {other:?}"),
        }
    }
    eprintln!("FH CONTROL: unanchored headers are refused deterministically");
}

/// An honest leader carries a header only with an anchor in the window
/// (`message_collector.rs`, `anchor_in_lockstep`), so it never carries one
/// of [`UNHELD_ANCHORS`]; only a leader running other code does.
#[test]
fn fh_fact_honest_leader_drops_unheld_anchors() {
    for anchor in UNHELD_ANCHORS {
        assert!(
            !anchor_in_lockstep(anchor, HALT_FRAME)
                && !bundle_shard_frames_in_lockstep(
                    &header_bundle(junk_header(anchor)),
                    HALT_FRAME
                ),
            "fact changed: an honest leader carries anchor {anchor} in GLOBAL frame {HALT_FRAME}"
        );
    }
    for anchor in [HALT_FRAME - 13, HALT_FRAME - 1] {
        assert!(
            anchor_in_lockstep(anchor, HALT_FRAME),
            "fact changed: window edge {anchor} for GLOBAL frame {HALT_FRAME}"
        );
    }
    eprintln!("FH FACT: honest leaders drop every unheld anchor");
}

/// Execution refuses a header by its window before reading anything at its
/// anchor, as validation does: a frame replayed without validation cannot
/// fail on an anchor no store holds either.
#[test]
fn fh_fix_execution_refuses_by_the_window_before_reading_the_anchor() {
    let rig = Rig::new(2..HALT_FRAME);
    for anchor in UNHELD_ANCHORS {
        let wire = junk_header(anchor);
        for (step, outcome) in [
            (
                "validation",
                rig.intrinsic
                    .validate(HALT_FRAME, &wire, None, None)
                    .map(|_| ()),
            ),
            (
                "execution",
                rig.intrinsic.invoke_step(HALT_FRAME, &wire, &rig.state),
            ),
        ] {
            match outcome {
                Err(error) if anchor_outside_window(&error) => {}
                other => panic!(
                    "FH FIX: GLOBAL frame {HALT_FRAME} {step} must refuse anchor {anchor} by \
                     the lockstep window first, got {other:?}"
                ),
            }
        }
    }
    eprintln!("FH FIX: validation and execution refuse unheld anchors by the window");
}

/// An honest leader packs exactly the anchors validation does not refuse by
/// the window: a header it packs is never refused for its anchor, and none
/// validation refuses that way is ever packed.
#[test]
fn fh_fix_validation_refuses_exactly_the_anchors_an_honest_leader_drops() {
    let rig = Rig::new(2..HALT_FRAME);
    let (oldest, newest) = anchor_window(HALT_FRAME);
    assert_eq!((oldest, newest), (HALT_FRAME - 13, HALT_FRAME - 1));
    for anchor in (1..=HALT_FRAME + 1).chain([1_000_000, u64::MAX]) {
        let refused = match rig
            .intrinsic
            .validate(HALT_FRAME, &junk_header(anchor), None, None)
        {
            Err(error) => anchor_outside_window(&error),
            Ok(_) => false,
        };
        assert_eq!(
            refused,
            !anchor_in_lockstep(anchor, HALT_FRAME),
            "FH FIX: GLOBAL frame {HALT_FRAME}, anchor {anchor}: validation refused by the \
             window: {refused}, honest leader packs it: {}",
            anchor_in_lockstep(anchor, HALT_FRAME)
        );
    }
    eprintln!("FH FIX: validation and the honest leader share one window");
}

/// The window's bound, hit and recovered: a certified header anchored ahead
/// of a GLOBAL frame's window is refused there, never as unavailable, and a
/// collector holds it (`held_unverified`); the next GLOBAL frame admits and
/// executes it, and so does each through the window's last; past that it is
/// refused as stale. An anchor this node lacks inside the window stays
/// unavailable (control C4).
#[test]
fn fh_liveness_a_header_ahead_of_its_window_rides_the_next_frame() {
    let anchor = 2;
    let rig = Rig::new([anchor]);
    match rig
        .intrinsic
        .validate(anchor, &rig.certified(anchor), None, None)
    {
        Err(error) if anchor_outside_window(&error) && !error.is_execution_unavailable() => {
            assert!(
                held_unverified(&error),
                "FH LIVENESS: a collector must hold a header anchored ahead of the window, \
                 not drop it: {error}"
            )
        }
        other => panic!(
            "FH LIVENESS: GLOBAL frame {anchor} must refuse a header anchored to itself by \
             the window, got {other:?}"
        ),
    }
    let last = anchor + 1 + 12;
    for frame in [anchor + 1, last] {
        let rig = Rig::new([anchor]);
        let wire = rig.certified(anchor);
        let admitted = rig.intrinsic.validate(frame, &wire, None, None);
        assert!(
            matches!(admitted, Ok(true)),
            "FH LIVENESS: GLOBAL frame {frame} must admit the header anchored to {anchor}: \
             {admitted:?}"
        );
        let executed = rig.intrinsic.invoke_step(frame, &wire, &rig.state);
        assert!(
            executed.is_ok(),
            "FH LIVENESS: GLOBAL frame {frame} must execute the header anchored to {anchor}: \
             {executed:?}"
        );
    }
    let rig = Rig::new([anchor]);
    match rig
        .intrinsic
        .validate(last + 1, &rig.certified(anchor), None, None)
    {
        Err(error) if anchor_outside_window(&error) && !error.is_execution_unavailable() => {
            assert!(
                !held_unverified(&error),
                "FH LIVENESS: a collector must refuse a header behind the window, which rides \
                 no later frame, not hold it: {error}"
            )
        }
        other => panic!(
            "FH LIVENESS: GLOBAL frame {} must refuse the header as stale by the window, got \
             {other:?}",
            last + 1
        ),
    }
    eprintln!("FH LIVENESS: a header ahead of its window is held and rides the next frame");
}

/// A window refusal names its direction at both edges, and only an anchor
/// ahead of the window is one a later GLOBAL frame can carry.
#[test]
fn fh_fix_a_window_refusal_names_its_direction() {
    use quil_execution::global_intrinsic::frame_header::anchor_ahead_of_window;
    let rig = Rig::new(2..HALT_FRAME);
    let (oldest, newest) = anchor_window(HALT_FRAME);
    for (anchor, ahead) in [
        (oldest - 1, false),
        (1, false),
        (newest + 1, true),
        (1_000_000, true),
        (u64::MAX, true),
    ] {
        match rig
            .intrinsic
            .validate(HALT_FRAME, &junk_header(anchor), None, None)
        {
            Err(error) if anchor_outside_window(&error) => {
                assert_eq!(
                    anchor_ahead_of_window(&error),
                    ahead,
                    "FH FIX: anchor {anchor}, GLOBAL frame {HALT_FRAME}: {error}"
                );
                assert_eq!(
                    held_unverified(&error),
                    ahead,
                    "FH FIX: anchor {anchor}: only one ahead of the window is held"
                );
            }
            other => panic!("FH FIX: anchor {anchor} must be refused, got {other:?}"),
        }
    }
    eprintln!("FH FIX: a window refusal names its direction");
}

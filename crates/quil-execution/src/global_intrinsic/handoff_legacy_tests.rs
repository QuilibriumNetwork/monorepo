//! Generation-zero migration over synthetic legacy histories: real Falcon
//! certificates in the legacy (`appshard‖filter`, epoch 0) namespace, GLOBAL
//! records in RocksDB.
use super::*;
use crate::global_intrinsic::handoff::frames::{self, FrameClaim};
use crate::global_intrinsic::handoff::legacy::{self, LegacyTip};

fn epoch_length() -> u64 {
    quil_types::consensus::epoch_length_frames()
}

/// A legacy-verified header GLOBAL executed: frame `frame` of `filter`,
/// anchored at GLOBAL frame `anchor`.
fn legacy_tip(frame: u64, anchor: u64) -> LegacyTip {
    LegacyTip {
        checkpoint: Checkpoint {
            frame,
            view: frame + 10,
            digest: [frame as u8; 32],
            state_roots: [[0x40; 32], [0x41; 32], [0x42; 32], [0x43; 32]],
            history_root: [0; 32],
        },
        anchor,
    }
}

/// The legacy committee's view of `filter`: generation 0 in the legacy
/// namespace, which is what `Session::namespace` gives generation zero.
fn legacy_signer(filter: &[u8], keys: &[FalconPrivateKey]) -> Session {
    let mut session = initial(filter.to_vec(), keys);
    session.generation = 0;
    session
}

/// A finalization by the first `signers` of `keys`.
fn sign_by(session: &Session, keys: &[FalconPrivateKey], signers: usize, view: u64, parent: u64, digest: [u8; 32]) -> Vec<u8> {
    let proposal = Proposal::new(
        Round::new(Epoch::new(session.generation), View::new(view)),
        View::new(parent),
        Digest(digest),
    );
    let participants: Set<_> = keys.iter().map(|key| key.public_key()).collect::<Vec<_>>().try_into().unwrap();
    let schemes: Vec<Generic<Namespace>> = keys
        .iter()
        .cloned()
        .map(|key| Generic::signer(&session.namespace().unwrap(), participants.clone(), key).unwrap())
        .collect();
    let votes: Vec<_> = schemes[..signers]
        .iter()
        .map(|s| s.sign::<SimplexFalconScheme, Digest>(Subject::Finalize { proposal: &proposal }).unwrap())
        .collect();
    let certificate = schemes[0].assemble::<SimplexFalconScheme, _, N3f1>(votes).unwrap();
    encode_finalization(&Finalization { proposal, certificate })
}

/// A seal by `signers` of the source's committee, of `checkpoint`.
fn seal_of(request: &Request, source: &Session, keys: &[FalconPrivateKey], signers: usize, checkpoint: Checkpoint) -> CertificateSubmission {
    let seal = Seal { request: request.id().unwrap(), session: source.id().unwrap(), view: checkpoint.view + 3, checkpoint };
    let certificate = sign_by(source, keys, signers, seal.view, seal.checkpoint.view, seal.digest());
    CertificateSubmission { seal, certificate }
}

fn checkpoint(frame: u64) -> Checkpoint {
    Checkpoint {
        frame,
        view: frame + 10,
        digest: [frame as u8; 32],
        state_roots: [[0x50; 32]; 4],
        history_root: [0x44; 32],
    }
}

struct Legacy {
    _directory: tempfile::TempDir,
    _db: &'static quil_store::RocksDb,
    state: HypergraphState,
    filter: Vec<u8>,
    keys: Vec<FalconPrivateKey>,
}

/// A GLOBAL store holding one legacy shard whose header for frame `tip_frame`
/// executed at GLOBAL frame 1, anchored at `anchor`.
fn legacy(filter: Vec<u8>, tip_frame: u64, anchor: u64) -> Legacy {
    let directory = tempfile::tempdir().unwrap();
    let db: &'static quil_store::RocksDb = Box::leak(Box::new(quil_store::RocksDb::open(directory.path()).unwrap()));
    let (_, state) = make_state(db);
    legacy::record_tip(&state, 1, &filter, &legacy_tip(tip_frame, anchor)).unwrap();
    commit(&state, 1);
    Legacy { _directory: directory, _db: db, state, filter, keys: keys() }
}

#[test]
fn only_the_audited_path_creates_generation_zero() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    assert!(initialize(&state, 1, &legacy_signer(&[0x61; 32], &keys)).is_err(),
        "a trusted initialization cannot claim the legacy namespace");
    assert!(legacy::records_tips(&policy(), 0), "activation at 2 records from genesis");
    let late = quil_types::consensus::CommitteeHandoffPolicy { activation_frame: 5_000, chain_id: [0x11; 32], legacy_history: quil_types::consensus::LegacyHistory::Migrate };
    assert!(!legacy::records_tips(&late, 5_000 - legacy::LEGACY_TIP_LEAD - 1));
    assert!(legacy::records_tips(&late, 5_000 - legacy::LEGACY_TIP_LEAD));
}

/// A pending shard is registered at its legacy tip, with the eligible
/// committee, and scheduled into a generation-1 successor in the same frame.
/// Reconciliation never gives it an empty-genesis first session, and repeated
/// passes register nothing more.
#[test]
fn a_legacy_shard_becomes_generation_zero_and_is_scheduled_into_its_successor() {
    let fixture = legacy(vec![0x62; 32], 40, 1);
    let (state, filter, keys) = (&fixture.state, &fixture.filter, &fixture.keys);
    let scan = scan_of(&[(filter, keys)]);
    assert!(legacy::pending(state, filter).unwrap());
    assert_eq!(schedule::reconcile_membership(state, 8, &policy(), &[filter.clone()], &scan).unwrap(), 0,
        "legacy history never restarts from the empty genesis");
    assert!(head(state, filter).unwrap().is_none());

    assert_eq!(legacy::migrate(state, 8, &policy(), &[filter.clone()], &scan).unwrap(), 1);
    commit(state, 8);
    let zero = head(state, filter).unwrap().unwrap();
    assert_eq!((zero.generation, zero.base_frame, zero.genesis), (0, 40, [40; 32]));
    assert_eq!(zero.members, members(keys));
    assert_eq!(zero.namespace().unwrap(), [b"appshard".as_slice(), filter].concat(), "the legacy namespace");
    let source = legacy::source(state, &zero.id().unwrap()).unwrap().unwrap();
    assert_eq!((source.registered_at, source.tip), (8, legacy_tip(40, 1)));
    let Status::Sealing(request_id) = status(state, &zero.id().unwrap()).unwrap() else {
        panic!("generation zero is closing from the start");
    };
    let request = request(state, &request_id).unwrap().unwrap();
    assert_eq!((request.targets.len(), request.targets[0].generation), (1, 1));
    assert_eq!(request.targets[0].committee.members, members(keys));
    assert_eq!(session_tip(state, &zero.id().unwrap()).unwrap().unwrap().frame, 40,
        "GLOBAL executed the shard through its tip");
    assert!(!legacy::pending(state, filter).unwrap());

    assert_eq!(legacy::migrate(state, 16, &policy(), &[filter.clone()], &scan).unwrap(), 0);
    assert_eq!(schedule::reconcile_membership(state, 16, &policy(), &[filter.clone()], &scan).unwrap(), 0,
        "a closing source is not scheduled twice");
}

/// The legacy committee seals its own head in the legacy namespace; GLOBAL
/// accepts it as generation zero's terminal seal and authorizes generation 1
/// in its own namespace from the sealed checkpoint.
#[test]
fn a_legacy_committee_seals_generation_zero_and_generation_one_activates() {
    let fixture = legacy(vec![0x63; 32], 40, 1);
    let (state, filter, keys) = (&fixture.state, &fixture.filter, &fixture.keys);
    legacy::migrate(state, 8, &policy(), &[filter.clone()], &scan_of(&[(filter, keys)])).unwrap();
    commit(state, 8);
    let zero = head(state, filter).unwrap().unwrap();
    let Status::Sealing(request_id) = status(state, &zero.id().unwrap()).unwrap() else { panic!() };
    let request = request(state, &request_id).unwrap().unwrap();

    // Competing heads: a member behind the tip proposes a seal below the base
    // (refused by the seal's own validation).
    let behind = seal_of(&request, &zero, keys, 3, checkpoint(39));
    assert!(super::super::apply_submission(state, 9, &behind).is_err(), "a checkpoint below the base");
    // Pending cross-shard outflows: a head GLOBAL has not executed yet waits.
    let ahead = seal_of(&request, &zero, keys, 3, checkpoint(42));
    assert!(super::super::apply_submission(state, 9, &ahead).is_err(), "frames 41 and 42 not yet executed");
    record_session_tip(state, 9, &zero.id().unwrap(), &checkpoint(42)).unwrap();
    // Unavailable members: two members and outsiders cannot make a quorum of
    // the registered committee.
    let outsiders = super::keys();
    let mixed: Vec<FalconPrivateKey> = keys[..2].iter().chain(&outsiders[..2]).cloned().collect();
    let mut short = seal_of(&request, &zero, &mixed, 3, checkpoint(42));
    short.certificate = sign_by(&zero, &mixed, 3, short.seal.view, short.seal.checkpoint.view, short.seal.digest());
    assert!(super::super::apply_submission(state, 9, &short).is_err());
    assert!(super::super::apply_submission(state, 9, &ahead).unwrap());
    commit(state, 9);

    assert!(matches!(status(state, &zero.id().unwrap()).unwrap(), Status::Closed(_)));
    let one = head(state, filter).unwrap().unwrap();
    assert_eq!((one.generation, one.base_frame, one.members.clone()), (1, 42, members(keys)));
    assert_ne!(one.namespace().unwrap(), zero.namespace().unwrap());
    let conflicting = seal_of(&request, &zero, keys, 3, checkpoint(43));
    assert!(super::super::apply_submission(state, 10, &conflicting).is_err(),
        "one closing checkpoint per source");
}

/// Archive catch-up and the verifier boundary: legacy frames keep the legacy
/// verifier before and after registration, frames above the base verify
/// against generation zero (any parent view: legacy instances restart at
/// local heads), and nothing past its terminal seal is accepted.
#[test]
fn legacy_history_keeps_the_legacy_verifier_across_the_migration() {
    let fixture = legacy(vec![0x64; 32], 40, 1);
    let (state, filter, keys) = (&fixture.state, &fixture.filter, &fixture.keys);
    let signer = legacy_signer(filter, keys);
    let claim = |frame: u64, digest: [u8; 32]| FrameClaim { filter, frame, view: frame + 10, parent: &[0x21; 32], digest };
    let old = sign_by(&signer, keys, 3, 45, 44, [35; 32]);

    // Pending, even once a sibling shard of the application is managed.
    let mut sibling = filter.clone();
    sibling.extend_from_slice(&[0, 1, 0]);
    initialize(state, 2, &initial(sibling, &keys[..])).unwrap();
    commit(state, 2);
    assert!(manages_application(state, filter).unwrap());
    assert!(frames::verify(state, &claim(35, [35; 32]), &old).unwrap().is_none(), "pending: legacy verifier");
    frames::require_legacy_allowed(state, filter, 35).unwrap();

    legacy::migrate(state, 8, &policy(), &[filter.clone()], &scan_of(&[(filter, keys)])).unwrap();
    commit(state, 8);
    assert!(frames::verify(state, &claim(35, [35; 32]), &old).unwrap().is_none(), "history below the base");
    frames::require_legacy_allowed(state, filter, 40).unwrap();
    assert!(frames::require_legacy_allowed(state, filter, 41).is_err());

    // Above the base: the registered committee, at any parent view.
    let restarted = sign_by(&signer, keys, 3, 51, 0, [41; 32]);
    let verified = frames::verify(state, &FrameClaim { view: 51, ..claim(41, [41; 32]) }, &restarted).unwrap();
    assert_eq!(verified.unwrap().session.generation, 0);
    let strangers = super::keys();
    let forged = sign_by(&legacy_signer(filter, &strangers), &strangers, 3, 52, 51, [42; 32]);
    assert!(frames::verify(state, &FrameClaim { view: 52, ..claim(42, [42; 32]) }, &forged).is_err());

    // Sealed at 42: frame 43 is past the terminal checkpoint; 42 is not.
    let zero = head(state, filter).unwrap().unwrap();
    let Status::Sealing(request_id) = status(state, &zero.id().unwrap()).unwrap() else { panic!() };
    let request = request(state, &request_id).unwrap().unwrap();
    record_session_tip(state, 9, &zero.id().unwrap(), &checkpoint(42)).unwrap();
    super::super::apply_submission(state, 9, &seal_of(&request, &zero, keys, 3, checkpoint(42))).unwrap();
    commit(state, 9);
    let last = sign_by(&signer, keys, 3, 52, 51, [42; 32]);
    assert!(frames::verify(state, &FrameClaim { view: 52, ..claim(42, [42; 32]) }, &last).unwrap().is_some());
    let beyond = sign_by(&signer, keys, 3, 60, 52, [43; 32]);
    assert!(frames::verify(state, &FrameClaim { view: 60, ..claim(43, [43; 32]) }, &beyond).is_err());
    assert!(frames::verify(state, &claim(35, [35; 32]), &old).unwrap().is_none(), "archive catch-up of history");
}

/// Changing committees: a tip certified in an earlier storage epoch (whose
/// committee may differ) waits for a tip of the current epoch, then registers
/// the current committee. The tip only advances until registration.
#[test]
fn a_tip_from_an_earlier_epoch_waits_for_the_current_committee() {
    let length = epoch_length();
    let fixture = legacy(vec![0x65; 32], 40, length - 1);
    let (state, filter, keys) = (&fixture.state, &fixture.filter, &fixture.keys);
    let later = super::keys();
    let scan = scan_of(&[(filter, &later)]);
    let frame = 2 * length;
    assert_eq!(legacy::migrate(state, frame, &policy(), &[filter.clone()], &scan).unwrap(), 0);
    legacy::record_tip(state, frame, filter, &legacy_tip(39, frame - 1)).unwrap();
    assert_eq!(legacy::tip(state, filter).unwrap().unwrap().checkpoint.frame, 40, "tips only rise");
    legacy::record_tip(state, frame, filter, &legacy_tip(44, frame + 1)).unwrap();
    assert_eq!(legacy::migrate(state, frame + 8, &policy(), &[filter.clone()], &scan).unwrap(), 1);
    commit(state, frame + 8);
    let zero = head(state, filter).unwrap().unwrap();
    assert_eq!((zero.base_frame, zero.members.clone()), (44, members(&later)));
    legacy::record_tip(state, frame + 9, filter, &legacy_tip(50, frame + 9)).unwrap();
    assert_eq!(legacy::tip(state, filter).unwrap().unwrap().checkpoint.frame, 44,
        "a registered shard keeps the tip it was registered from");
}

/// Partial migration and restart: a pass that never committed (a crash)
/// leaves nothing, and replaying the same frame registers the identical
/// session; later passes resume with the shards still pending.
#[test]
fn an_interrupted_pass_replays_to_the_same_registration_and_later_passes_resume() {
    let fixture = legacy(vec![0x66; 32], 40, 1);
    let (state, first, keys) = (&fixture.state, fixture.filter.clone(), &fixture.keys);
    let second = vec![0x67; 32];
    let filters = vec![first.clone(), second.clone()];
    let scan = scan_of(&[(&first, keys), (&second, keys)]);
    assert_eq!(legacy::migrate(state, 8, &policy(), &filters, &scan).unwrap(), 1, "only the shard with a tip");
    let id = head(state, &first).unwrap().unwrap().id().unwrap();
    state.abort();
    assert!(head(state, &first).unwrap().is_none(), "nothing survives an uncommitted pass");
    assert_eq!(legacy::migrate(state, 8, &policy(), &filters, &scan).unwrap(), 1);
    commit(state, 8);
    assert_eq!(head(state, &first).unwrap().unwrap().id().unwrap(), id, "a replay registers the same session");

    legacy::record_tip(state, 9, &second, &legacy_tip(7, 5)).unwrap();
    commit(state, 9);
    assert!(legacy::pending(state, &second).unwrap());
    assert_eq!(legacy::migrate(state, 16, &policy(), &filters, &scan).unwrap(), 1);
    commit(state, 16);
    assert_eq!(head(state, &second).unwrap().unwrap().base_frame, 7);
    assert_eq!(legacy::migrate(state, 24, &policy(), &filters, &scan).unwrap(), 0);
}

/// Unavailable members: no eligible provers, no registration; the shard stays
/// pending (legacy verifier) rather than starting without a committee.
#[test]
fn a_legacy_shard_without_eligible_members_stays_pending() {
    let fixture = legacy(vec![0x68; 32], 40, 1);
    let (state, filter) = (&fixture.state, &fixture.filter);
    assert_eq!(legacy::migrate(state, 8, &policy(), &[filter.clone()], &scan_of(&[])).unwrap(), 0);
    assert!(legacy::pending(state, filter).unwrap());
    assert_eq!(legacy::migrate(state, 1, &policy(), &[filter.clone()], &scan_of(&[(filter, &fixture.keys)])).unwrap(), 0,
        "nothing before activation");
}

/// A due split of a pending legacy shard waits for generation zero, instead
/// of applying as if no committee had ever formed there.
#[test]
fn a_topology_change_of_a_pending_legacy_shard_waits() {
    use quil_types::store::{PendingShardChange, ShardChangeKind};
    let app = [0x69u8; 32];
    let fixture = legacy(app.to_vec(), 40, 1);
    let children: Vec<Vec<u8>> = [false, true]
        .into_iter()
        .map(|bit| quil_forest::encode_shard_bit_path(&app, &[bit]))
        .collect();
    let change = PendingShardChange {
        kind: ShardChangeKind::Split, parent: app.to_vec(), children, effective_epoch: 2, proposed_frame: 1,
    };
    let scan = scan_of(&[(&app, &fixture.keys)]);
    assert_eq!(schedule::gate_topology_change(&fixture.state, 8, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Wait);
}

/// A generation 0 that never seals (its quorum is lost after registration) is
/// fenced like any closing session, at the tip GLOBAL executed for it, and
/// generation 1 is authorized from that fence with the same members. A late
/// seal is refused, and legacy history keeps its verifier.
#[test]
fn a_generation_zero_that_never_seals_is_fenced_at_its_executed_tip() {
    let fixture = legacy(vec![0x6a; 32], 40, 1);
    let (state, filter, keys) = (&fixture.state, &fixture.filter, &fixture.keys);
    assert_eq!(legacy::migrate(state, 8, &policy(), &[filter.clone()], &scan_of(&[(filter, keys)])).unwrap(), 1);
    commit(state, 8);
    let zero = head(state, filter).unwrap().unwrap();
    let id = zero.id().unwrap();
    // Generation 0 finalized frames 41 and 42, and GLOBAL executed their headers.
    record_session_tip(state, 9, &id, &checkpoint(42)).unwrap();
    commit(state, 9);

    let due = 8 + schedule::FENCE_AFTER_EPOCHS * epoch_length();
    assert_eq!(schedule::fence_stalled_sources(state, due - 1, &[filter.clone()]).unwrap(), 0, "not before the timeout");
    assert_eq!(schedule::fence_stalled_sources(state, due, &[filter.clone()]).unwrap(), 1);
    commit(state, due);
    assert!(is_fenced(state, &id).unwrap());
    let fence = closed_checkpoint(state, &id).unwrap().unwrap();
    assert_eq!((fence.frame, fence.view, fence.digest), (42, 52, [42; 32]));
    assert_eq!((fence.state_roots, fence.history_root), ([[0; 32]; 4], [0; 32]), "nothing certifies the post-tip state");
    let one = head(state, filter).unwrap().unwrap();
    assert_eq!((one.generation, one.base_frame, one.members.clone()), (1, 42, members(keys)));

    let Status::Closed(request_id) = status(state, &id).unwrap() else { panic!("generation zero closed by its fence") };
    let request = request(state, &request_id).unwrap().unwrap();
    assert!(super::super::apply_submission(state, due + 1, &seal_of(&request, &zero, keys, 3, checkpoint(42))).is_err(),
        "a seal after the fence is refused");
    frames::require_legacy_allowed(state, filter, 40).unwrap();
    assert!(frames::require_legacy_allowed(state, filter, 41).is_err());
}

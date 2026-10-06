use super::*;
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
    app_cert::encode_finalization,
    falcon_base::FalconPrivateKey,
    falcon_scheme::Generic,
    falcon_simplex::SimplexFalconScheme,
};
use quil_hypergraph::{testing::StubProver, HypergraphCrdt};
use quil_types::crypto::Signer as _;
use std::sync::Arc;

/// GLOBAL executed the source's data frames through the seal's checkpoint,
/// which [`super::verify_submission`] requires before accepting the seal.
fn executed(state: &HypergraphState, submission: &CertificateSubmission) {
    record_session_tip(state, 1, &submission.seal.session, &submission.seal.checkpoint).unwrap();
}

/// [`super::apply_submission`] after the source's frames were executed. The
/// seal-before-execution rule has its own test.
fn apply_submission(state: &HypergraphState, frame: u64, submission: &CertificateSubmission) -> Result<bool> {
    executed(state, submission);
    super::apply_submission(state, frame, submission)
}

/// [`super::verify_submission`] after the source's frames were executed.
fn verify_submission(state: &HypergraphState, frame: u64, submission: &CertificateSubmission) -> Result<Request> {
    executed(state, submission);
    super::verify_submission(state, frame, submission)
}

fn keys() -> Vec<FalconPrivateKey> {
    (0..4)
        .map(|_| {
            let signer = quil_crypto::FalconSigner::generate();
            FalconPrivateKey::from_bytes(signer.private_key(), signer.public_key()).unwrap()
        })
        .collect()
}

fn members(keys: &[FalconPrivateKey]) -> Vec<Vec<u8>> {
    let mut members: Vec<_> = keys
        .iter()
        .map(|key| key.public_key().as_ref().to_vec())
        .collect();
    members.sort();
    members
}

fn initial(filter: Vec<u8>, keys: &[FalconPrivateKey]) -> Session {
    Session {
        chain_id: [0x11; 32],
        filter,
        generation: 1,
        genesis: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap(),
        base_frame: 0,
        authorization: [0x22; 32],
        members: members(keys),
    }
}

fn desired(filter: &[u8], keys: &[FalconPrivateKey]) -> DesiredCommittee {
    DesiredCommittee {
        filter: filter.to_vec(),
        members: members(keys),
    }
}

fn make_state(
    db: &quil_store::RocksDb,
) -> (Arc<quil_store::RocksHypergraphStore>, HypergraphState) {
    let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
    let crdt = Arc::new(HypergraphCrdt::new(store.clone(), Arc::new(StubProver)));
    crdt.set_forest(quil_forest::Forest::with_namespace(
        db.inner(),
        quil_store::FOREST_NAMESPACE,
    ));
    (store, HypergraphState::new(crdt))
}

fn commit(state: &HypergraphState, frame: u64) {
    state.commit().unwrap();
    state.abort();
    state
        .crdt()
        .commit_with_global_cursor(
            frame,
            &quil_store::encoding::global_materialized_cursor_key(),
        )
        .unwrap();
}

#[test]
fn outgoing_history_is_complete_and_snapshot_pinned_across_retry_and_reopen() {
    use crate::token_intrinsic::{accumulator_header, spend_relay};
    use quil_store::encoding as enc;
    let directory = tempfile::tempdir().unwrap();
    let session = initial(vec![7; 32], &keys());
    let filter = &session.filter;
    let cursor = enc::consensus_materialized_cursor_key(filter);
    let records = |frame: u64| {
        let report = vec![frame as u8; 32];
        let digest = accumulator_header::report_digest(&report);
        vec![
            (enc::clock_shard_frame_fee_total_key(filter, frame), (frame as u128).to_be_bytes().to_vec()),
            (enc::clock_shard_frame_settlements_key(filter, frame), vec![]),
            (enc::clock_shard_frame_spends_key(filter, frame), spend_relay::encode_frame_entries(&[vec![frame as u8; 24]]).unwrap()),
            (enc::clock_shard_frame_accumulator_key(filter, frame), digest.clone()),
            (enc::clock_shard_accumulator_report_key(filter, &digest), report),
        ]
    };
    let final_root;
    {
        let db = quil_store::RocksDb::open(directory.path()).unwrap();
        let (store, state) = make_state(&db);
        let crdt = state.crdt();
        let absent = crdt.capture_committed_shard(filter).unwrap();
        assert!(history::root(absent.records.as_ref(), &session, 0).is_err(), "no implicit empty cursor");
        crdt.checkpoint_frame_cursor(0, &cursor).unwrap();
        let genesis = crdt.capture_committed_shard(filter).unwrap();
        let genesis_root = history::root(genesis.records.as_ref(), &session, 0).unwrap();
        crdt.commit_with_frame_cursor_and_records(1, &cursor, &records(1)).unwrap();
        let first = crdt.capture_committed_shard(filter).unwrap();
        let first_root = history::root(first.records.as_ref(), &session, 1).unwrap();
        assert_ne!(first_root, genesis_root);
        assert!(history::root(first.records.as_ref(), &session, 0).is_err());
        store.fail_commit_for_test(true);
        assert!(crdt.commit_with_frame_cursor_and_records(2, &cursor, &records(2)).is_err());
        let failed = crdt.capture_committed_shard(filter).unwrap();
        assert_eq!(history::root(failed.records.as_ref(), &session, 1).unwrap(), first_root);
        assert!(history::root(failed.records.as_ref(), &session, 2).is_err());
        store.fail_commit_for_test(false);
        crdt.commit_with_frame_cursor_and_records(2, &cursor, &records(2)).unwrap();
        let second = crdt.capture_committed_shard(filter).unwrap();
        final_root = history::root(second.records.as_ref(), &session, 2).unwrap();
        assert_ne!(final_root, first_root);
        assert_eq!(history::root(first.records.as_ref(), &session, 1).unwrap(), first_root);
        let mut successor = session.clone();
        successor.generation += 1;
        assert_ne!(history::root(second.records.as_ref(), &successor, 2).unwrap(), final_root);
        // Old, unreported records are still required; a current relay window
        // or a complete latest frame cannot repair their loss.
        for (key, value) in records(1) {
            db.inner().delete(&key).unwrap();
            let broken = crdt.capture_committed_shard(filter).unwrap();
            assert!(history::root(broken.records.as_ref(), &session, 2).is_err());
            assert_eq!(history::root(second.records.as_ref(), &session, 2).unwrap(), final_root);
            db.inner().put(key, value).unwrap();
        }
        let report_key = records(2).pop().unwrap().0;
        db.inner().put(&report_key, b"corrupted report").unwrap();
        let broken = crdt.capture_committed_shard(filter).unwrap();
        assert!(history::root(broken.records.as_ref(), &session, 2).is_err());
        db.inner().put(&report_key, records(2).pop().unwrap().1).unwrap();
    }
    let db = quil_store::RocksDb::open(directory.path()).unwrap();
    let (_, state) = make_state(&db);
    let reopened = state.crdt().capture_committed_shard(filter).unwrap();
    assert_eq!(history::root(reopened.records.as_ref(), &session, 2).unwrap(), final_root);
}

fn submission(
    request: &Request,
    source: usize,
    keys: &[FalconPrivateKey],
    last_frame: u64,
) -> CertificateSubmission {
    let session = &request.sources[source];
    let seal = Seal {
        request: request.id().unwrap(),
        session: session.id().unwrap(),
        view: 9,
        checkpoint: Checkpoint {
            frame: last_frame,
            view: 5,
            digest: [0x33; 32],
            state_roots: [[0x40; 32], [0x41; 32], [0x42; 32], [0x43; 32]],
            history_root: [0x44; 32],
        },
    };
    let certificate = sign_certificate(session, keys, seal.view, seal.checkpoint.view, seal.digest());
    CertificateSubmission { seal, certificate }
}

fn sign_certificate(session: &Session, keys: &[FalconPrivateKey], view: u64, parent: u64, digest: [u8; 32]) -> Vec<u8> {
    let proposal = Proposal::new(
        Round::new(Epoch::new(session.generation), View::new(view)),
        View::new(parent),
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
        .map(|s| {
            s.sign::<SimplexFalconScheme, Digest>(Subject::Finalize {
                proposal: &proposal,
            })
            .unwrap()
        })
        .collect();
    let certificate = schemes[0]
        .assemble::<SimplexFalconScheme, _, N3f1>(votes)
        .unwrap();
    encode_finalization(&Finalization { proposal, certificate })
}

#[test]
fn historical_frame_authorization_survives_rotation_and_reopen_without_legacy_fallback() {
    use super::frames::{verify, FrameClaim};
    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let first = initial(vec![0x51; 32], &keys);
    let certificate = sign_certificate(&first, &keys, 5, 0, [0x33; 32]);
    let claim = FrameClaim {
        filter: &first.filter, frame: 1, view: 5, parent: &first.genesis, digest: [0x33; 32],
    };
    {
        let db = quil_store::RocksDb::open(directory.path()).unwrap();
        let (store, state) = make_state(&db);
        commit(&state, 1);
        let before = CommittedView::capture(state.crdt()).unwrap();
        initialize(&state, 2, &first).unwrap();
        assert!(verify(&state, &claim, &certificate).unwrap().is_some());
        assert!(verify(&before, &claim, &certificate).is_err(), "staged authorization is not committed");
        state.commit().unwrap();
        state.abort();
        store.fail_commit_for_test(true);
        assert!(state.crdt().commit_with_global_cursor(2, &quil_store::encoding::global_materialized_cursor_key()).is_err());
        assert!(verify(&CommittedView::capture(state.crdt()).unwrap(), &claim, &certificate).is_err());
        store.fail_commit_for_test(false);
        state.crdt().commit_with_global_cursor(2, &quil_store::encoding::global_materialized_cursor_key()).unwrap();
        let committed = CommittedView::capture(state.crdt()).unwrap();
        assert_eq!(session_at_generation(&committed, &first.filter, 1).unwrap(), Some(first.clone()));
        assert!(verify(&committed, &claim, &certificate).unwrap().is_some());
        for (frame, view, parent) in [(0, 5, first.genesis), (1, 4, first.genesis), (2, 5, first.genesis), (1, 5, [0x44; 32])] {
            let invalid = FrameClaim { filter: &first.filter, frame, view, parent: &parent, digest: claim.digest };
            assert!(verify(&committed, &invalid, &certificate).is_err());
        }
        let mut trailing = certificate.clone();
        trailing.push(0);
        assert!(verify(&committed, &claim, &trailing).is_err());
        assert!(verify(&committed, &claim, &[0; 10]).is_err());
        let other = vec![0x52; 32];
        assert!(verify(&committed, &FrameClaim { filter: &other, ..claim }, &certificate).is_err());

        let request = schedule(&state, 3, vec![first.filter.clone()], vec![desired(&first.filter, &keys)]).unwrap();
        let seal = submission(&request, 0, &keys, 1);
        apply_submission(&state, 4, &seal).unwrap();
        commit(&state, 4);
        let second = head(&state, &first.filter).unwrap().unwrap();
        assert_eq!(second.generation, 2);
        let after = CommittedView::capture(state.crdt()).unwrap();
        assert!(verify(&after, &claim, &certificate).unwrap().is_some(), "old committee remains historically verifiable");
        let latest = sign_certificate(&second, &keys, 1, 0, [0x55; 32]);
        let next = FrameClaim { filter: &first.filter, frame: 2, view: 1, parent: &second.genesis, digest: [0x55; 32] };
        assert!(verify(&after, &next, &latest).unwrap().is_some());
        assert!(verify(&after, &next, &certificate).is_err());
        let mut unauthenticated = first.clone();
        unauthenticated.generation = 0;
        let old_namespace = sign_certificate(&unauthenticated, &keys, 5, 0, claim.digest);
        assert!(verify(&after, &claim, &old_namespace).is_err(), "same keys cannot downgrade namespace");
        assert!(frames::require_unregistered(&after, &first.filter).is_err());

        // A corrupt generation mapping cannot resolve by the latest head or
        // quietly pick the old namespace. Restore it before the reopen check.
        let key = generation_key(&first.filter, 1).unwrap();
        write(&state, 5, b"generation", &key, &second.id().unwrap()).unwrap();
        assert!(session_at_generation(&state, &first.filter, 1).is_err());
        state.abort();
    }
    let db = quil_store::RocksDb::open(directory.path()).unwrap();
    let (_, state) = make_state(&db);
    let recovered = CommittedView::capture(state.crdt()).unwrap();
    assert_eq!(session_at_generation(&recovered, &first.filter, 1).unwrap(), Some(first.clone()));
    assert_eq!(head(&recovered, &first.filter).unwrap().unwrap().generation, 2);
    assert!(verify(&recovered, &claim, &certificate).unwrap().is_some());
}

#[test]
fn a_source_seal_bounds_data_even_before_the_other_merge_source_closes() {
    use super::frames::{verify, FrameClaim};
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let root = vec![0x53; 32];
    let mut left_filter = root.clone(); left_filter.extend_from_slice(&[0, 1, 0]);
    let mut right_filter = root.clone(); right_filter.extend_from_slice(&[0, 1, 128]);
    let left = initial(left_filter.clone(), &keys);
    initialize(&state, 1, &left).unwrap();
    initialize(&state, 1, &initial(right_filter.clone(), &keys)).unwrap();
    let request = schedule(&state, 2, vec![left_filter, right_filter], vec![desired(&root, &keys)]).unwrap();
    let mut seal = submission(&request, 0, &keys, 3);
    seal.seal.checkpoint.view = 7;
    seal.certificate = sign_certificate(&left, &keys, seal.seal.view, 7, seal.seal.digest());
    let first = FrameClaim { filter: &left.filter, frame: 1, view: 2, parent: &left.genesis, digest: [0x22; 32] };
    let first_cert = sign_certificate(&left, &keys, 2, 0, first.digest);
    let last = FrameClaim { filter: &left.filter, frame: 3, view: 7, parent: &[0x21; 32], digest: [0x33; 32] };
    let last_cert = sign_certificate(&left, &keys, 7, 4, last.digest);
    let beyond = FrameClaim { filter: &left.filter, frame: 4, view: 8, parent: &last.digest, digest: [0x77; 32] };
    let beyond_cert = sign_certificate(&left, &keys, 8, 7, beyond.digest);
    assert!(verify(&state, &beyond, &beyond_cert).unwrap().is_some());
    assert!(!apply_submission(&state, 3, &seal).unwrap());
    commit(&state, 3);
    let committed = CommittedView::capture(state.crdt()).unwrap();
    assert!(matches!(status(&committed, &left.id().unwrap()).unwrap(), Status::Sealing(_)));
    assert!(verify(&committed, &first, &first_cert).unwrap().is_some());
    assert!(verify(&committed, &last, &last_cert).unwrap().is_some());
    assert!(verify(&committed, &beyond, &beyond_cert).is_err());
    let conflict = FrameClaim { digest: [0x99; 32], ..last };
    let conflict_cert = sign_certificate(&left, &keys, 7, 4, conflict.digest);
    assert!(verify(&committed, &conflict, &conflict_cert).is_err());
    let late_view = FrameClaim { frame: 2, view: 8, ..conflict };
    let late_cert = sign_certificate(&left, &keys, 8, 4, late_view.digest);
    assert!(verify(&committed, &late_view, &late_cert).is_err());
}

#[test]
fn managed_app_legacy_sources_require_explicit_generation_zero_authorization() {
    use super::frames::{verify, FrameClaim};
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let mut legacy = initial(vec![0x54; 32], &keys);
    legacy.generation = 0;
    let certificate = sign_certificate(&legacy, &keys, 2, 0, [0x55; 32]);
    let claim = FrameClaim { filter: &legacy.filter, frame: 1, view: 2, parent: &legacy.genesis, digest: [0x55; 32] };
    assert!(verify(&state, &claim, &certificate).unwrap().is_none(), "unmanaged application uses legacy verifier");
    assert!(initialize(&state, 1, &legacy).is_err(), "generation zero only through the legacy migration");
    let tip = super::legacy::LegacyTip {
        checkpoint: Checkpoint { frame: 0, view: 0, digest: legacy.genesis, state_roots: [[0; 32]; 4], history_root: [0; 32] },
        anchor: 0,
    };
    super::legacy::record_tip(&state, 1, &legacy.filter, &tip).unwrap();
    assert_eq!(super::legacy::migrate(&state, 8, &policy(), &[legacy.filter.clone()], &scan_of(&[(&legacy.filter, &keys)])).unwrap(), 1);
    commit(&state, 8);
    let committed = CommittedView::capture(state.crdt()).unwrap();
    assert!(verify(&committed, &claim, &certificate).unwrap().is_some());
    let mut child = legacy.clone();
    child.filter.extend_from_slice(&[0, 1, 0]);
    let child_cert = sign_certificate(&child, &keys, 2, 0, claim.digest);
    assert!(verify(&committed, &FrameClaim { filter: &child.filter, ..claim }, &child_cert).is_err());
    child.filter = vec![0x56; 32];
    let unrelated = sign_certificate(&child, &keys, 2, 0, claim.digest);
    assert!(verify(&committed, &FrameClaim { filter: &child.filter, ..claim }, &unrelated).unwrap().is_none());
    // The marker is protocol state, not a process-local toggle.
    assert!(manages_application(&committed, &legacy.filter).unwrap());
    assert!(!manages_application(&committed, &child.filter).unwrap());
    write(&state, 2, b"generation", &generation_key(&legacy.filter, 0).unwrap(), &[]).unwrap();
    assert!(verify(&state, &claim, &certificate).is_err(), "damaged index cannot select legacy fallback");
}

#[test]
fn committee_replacement_and_returning_members_require_new_authorization() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let a = keys();
    let b = keys();
    let filter = vec![7; 32];
    let original = initial(filter.clone(), &a);
    initialize(&state, 1, &original).unwrap();
    commit(&state, 1);
    let request = schedule(&state, 2, vec![filter.clone()], vec![desired(&filter, &b)]).unwrap();
    assert_eq!(head(&state, &filter).unwrap(), Some(original.clone()));
    assert_eq!(
        status(&state, &original.id().unwrap()).unwrap(),
        Status::Sealing(request.id().unwrap())
    );
    let seal_a = submission(&request, 0, &a, 10);
    assert!(
        verify_submission(&state, 2, &seal_a).is_err(),
        "request must be committed in an earlier frame"
    );
    assert!(apply_submission(&state, 3, &seal_a).unwrap());
    let second = head(&state, &filter).unwrap().unwrap();
    assert_eq!((second.generation, second.base_frame), (2, 10));
    assert_eq!(second.members, members(&b));
    assert_eq!(
        origins(&state, &second.id().unwrap()).unwrap(),
        vec![(original.clone(), seal_a.seal.checkpoint.clone())]
    );
    let checkpoint = state.changeset_len();
    assert!(!apply_submission(&state, 3, &seal_a).unwrap());
    assert_eq!(
        state.changeset_len(),
        checkpoint,
        "duplicate activation must stage nothing"
    );
    commit(&state, 3);

    let request = schedule(&state, 4, vec![filter.clone()], vec![desired(&filter, &a)]).unwrap();
    let wrong_committee = submission(&request, 0, &a, 15);
    assert!(apply_submission(&state, 5, &wrong_committee).is_err());
    assert!(
        !apply_submission(&state, 5, &seal_a).unwrap(),
        "historical certificate is only an idempotent replay"
    );
    assert_eq!(head(&state, &filter).unwrap(), Some(second));
    let seal_b = submission(&request, 0, &b, 15);
    assert!(apply_submission(&state, 5, &seal_b).unwrap());
    let third = head(&state, &filter).unwrap().unwrap();
    assert_eq!((third.generation, third.base_frame), (3, 15));
    assert_eq!(third.members, original.members);
    assert_ne!(third.namespace().unwrap(), original.namespace().unwrap());
    assert_ne!(third.genesis, original.genesis);
    assert!(origins(&state, &[0xff; 32]).is_err());
}

#[test]
fn split_merge_split_waits_for_every_source_and_retains_retired_generations() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let filter = vec![9; 32];
    let children: Vec<_> = [false, true]
        .iter()
        .map(|bit| quil_forest::encode_shard_bit_path(&filter, &[*bit]))
        .collect();
    let original = initial(filter.clone(), &keys);
    initialize(&state, 1, &original).unwrap();
    let split = schedule(
        &state,
        2,
        vec![filter.clone()],
        children.iter().map(|f| desired(f, &keys)).collect(),
    )
    .unwrap();
    let root_seal = submission(&split, 0, &keys, 10);
    assert!(apply_submission(&state, 3, &root_seal).unwrap());
    commit(&state, 3);
    let first_children: Vec<_> = children
        .iter()
        .map(|f| head(&state, f).unwrap().unwrap())
        .collect();
    assert!(first_children
        .iter()
        .all(|s| s.generation == 1 && s.base_frame == 0));
    let merge = schedule(&state, 4, children.clone(), vec![desired(&filter, &keys)]).unwrap();
    let left = submission(&merge, 0, &keys, 5);
    assert!(!apply_submission(&state, 5, &left).unwrap());
    assert_eq!(head(&state, &filter).unwrap(), Some(original));
    assert_eq!(
        status(&state, &first_children[0].id().unwrap()).unwrap(),
        Status::Sealing(merge.id().unwrap())
    );
    let checkpoint = state.changeset_len();
    assert!(!apply_submission(&state, 5, &left).unwrap());
    assert_eq!(
        state.changeset_len(),
        checkpoint,
        "a repeated partial submission does not rewrite its stored certificate"
    );
    let right = submission(&merge, 1, &keys, 7);
    assert!(apply_submission(&state, 6, &right).unwrap());
    commit(&state, 6);
    let merged = head(&state, &filter).unwrap().unwrap();
    assert_eq!((merged.generation, merged.base_frame), (2, 10));
    assert_eq!(origins(&state, &merged.id().unwrap()).unwrap().len(), 2);
    let split = schedule(
        &state,
        7,
        vec![filter.clone()],
        children.iter().map(|f| desired(f, &keys)).collect(),
    )
    .unwrap();
    assert!(!apply_submission(&state, 8, &root_seal).unwrap());
    let root_seal = submission(&split, 0, &keys, 13);
    assert!(apply_submission(&state, 8, &root_seal).unwrap());
    for (i, filter) in children.iter().enumerate() {
        let next = head(&state, filter).unwrap().unwrap();
        assert_eq!((next.generation, next.base_frame), (2, [5, 7][i]));
        assert_ne!(
            next.namespace().unwrap(),
            first_children[i].namespace().unwrap()
        );
        assert_eq!(
            origins(&state, &next.id().unwrap()).unwrap(),
            vec![(merged.clone(), root_seal.seal.checkpoint.clone())]
        );
    }
}

#[test]
fn request_partition_and_codec_reject_gaps_overlap_aliases_and_unbounded_counts() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let app = vec![8; 32];
    let original = initial(app.clone(), &keys);
    initialize(&state, 1, &original).unwrap();
    commit(&state, 1);
    let left = quil_forest::encode_shard_bit_path(&app, &[false]);
    let right = quil_forest::encode_shard_bit_path(&app, &[true]);
    let left_left = quil_forest::encode_shard_bit_path(&app, &[false, false]);
    let left_right = quil_forest::encode_shard_bit_path(&app, &[false, true]);
    for targets in [
        vec![left.clone()],
        vec![app.clone(), right.clone()],
        vec![vec![3; 32]],
        vec![app.clone(), quil_forest::encode_shard_bit_path(&app, &[])],
        vec![left.clone(), left.clone(), right.clone()],
    ] {
        let before = state.changeset_len();
        assert!(schedule(
            &state,
            2,
            vec![app.clone()],
            targets.iter().map(|f| desired(f, &keys)).collect()
        )
        .is_err());
        assert_eq!(state.changeset_len(), before);
        assert_eq!(
            status(&state, &original.id().unwrap()).unwrap(),
            Status::Active
        );
    }
    let mut invalid_legacy = app.clone();
    invalid_legacy.push(64);
    assert!(partition(&[invalid_legacy]).is_err());
    let request = schedule(
        &state,
        2,
        vec![app.clone()],
        [left_left, left_right, right]
            .iter()
            .map(|f| desired(f, &keys))
            .collect(),
    )
    .unwrap();
    let bytes = request.encode().unwrap();
    assert_eq!(Request::decode(&bytes).unwrap(), request);
    for n in 0..bytes.len() {
        assert!(Request::decode(&bytes[..n]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Request::decode(&trailing).is_err());
    let mut huge = bytes.clone();
    huge[13..17].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(Request::decode(&huge).is_err());
    let encoded = submission(&request, 0, &keys, 1)
        .to_canonical_bytes()
        .unwrap();
    for n in 0..encoded.len() {
        assert!(CertificateSubmission::from_canonical_bytes(&encoded[..n]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(CertificateSubmission::from_canonical_bytes(&trailing).is_err());
    let mut huge = encoded;
    huge[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(CertificateSubmission::from_canonical_bytes(&huge).is_err());
}

#[test]
fn transition_and_activation_follow_message_rollback() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let filter = vec![6; 32];
    let original = initial(filter.clone(), &keys);
    initialize(&state, 1, &original).unwrap();
    commit(&state, 1);
    let checkpoint = state.changeset_len();
    let request = schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    let id = request.id().unwrap();
    state.rollback_to(checkpoint);
    assert!(super::request(&state, &id).unwrap().is_none());
    assert_eq!(
        status(&state, &original.id().unwrap()).unwrap(),
        Status::Active
    );
    let request = schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    assert_eq!(id, request.id().unwrap());
    commit(&state, 2);
    let checkpoint = state.changeset_len();
    let seal = submission(&request, 0, &keys, 4);
    assert!(apply_submission(&state, 3, &seal).unwrap());
    let next = head(&state, &filter).unwrap().unwrap();
    state.rollback_to(checkpoint);
    assert!(session(&state, &next.id().unwrap()).unwrap().is_none());
    assert_eq!(head(&state, &filter).unwrap(), Some(original));
    assert!(apply_submission(&state, 3, &seal).unwrap());
    assert_eq!(head(&state, &filter).unwrap(), Some(next));
}

#[test]
fn closing_certificates_and_activation_commit_with_cursor_and_survive_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let app = vec![5; 32];
    let children: Vec<_> = [false, true]
        .iter()
        .map(|b| quil_forest::encode_shard_bit_path(&app, &[*b]))
        .collect();
    let cursor = quil_store::encoding::global_materialized_cursor_key();
    let request;
    {
        let db = quil_store::RocksDb::open(directory.path()).unwrap();
        let (_, state) = make_state(&db);
        for child in &children {
            initialize(&state, 1, &initial(child.clone(), &keys)).unwrap();
        }
        commit(&state, 1);
        request = schedule(&state, 2, children.clone(), vec![desired(&app, &keys)]).unwrap();
        commit(&state, 2);
        let left = submission(&request, 0, &keys, 3);
        assert!(!apply_submission(&state, 3, &left).unwrap());
        commit(&state, 3);
    }
    let next;
    {
        let db = quil_store::RocksDb::open(directory.path()).unwrap();
        let (store, state) = make_state(&db);
        let before = CommittedView::capture(state.crdt()).unwrap();
        assert_eq!(before.frame(), 3);
        assert_eq!(state.crdt().read_frame_cursor(&cursor).unwrap(), 3);
        let right = submission(&request, 1, &keys, 4);
        assert!(apply_submission(&state, 4, &right).unwrap());
        next = head(&state, &app).unwrap().unwrap();
        assert!(head(&before, &app).unwrap().is_none());
        state.commit().unwrap();
        state.abort();
        store.fail_commit_for_test(true);
        for _ in 0..2 {
            assert!(state.crdt().commit_with_global_cursor(4, &cursor).is_err());
            let view = CommittedView::capture(state.crdt()).unwrap();
            assert_eq!(view.frame(), 3);
            assert!(
                head(&view, &app).unwrap().is_none(),
                "staged CRDT state must not authorize a committee"
            );
            let (_, reader) = make_state(&db);
            assert!(head(&reader, &app).unwrap().is_none());
            assert_eq!(reader.crdt().read_frame_cursor(&cursor).unwrap(), 3);
            for source in &request.sources {
                assert_eq!(
                    status(&reader, &source.id().unwrap()).unwrap(),
                    Status::Sealing(request.id().unwrap())
                );
            }
        }
        store.fail_commit_for_test(false);
        state.crdt().commit_with_global_cursor(4, &cursor).unwrap();
        let after = CommittedView::capture(state.crdt()).unwrap();
        assert_eq!(after.frame(), 4);
        assert_eq!(head(&after, &app).unwrap(), Some(next.clone()));
        assert!(
            head(&before, &app).unwrap().is_none(),
            "held view stays at its captured sequence"
        );
        assert_eq!(before.frame(), 3);
        for source in &request.sources {
            assert_eq!(
                status(&before, &source.id().unwrap()).unwrap(),
                Status::Sealing(request.id().unwrap())
            );
            assert_eq!(
                status(&after, &source.id().unwrap()).unwrap(),
                Status::Closed(request.id().unwrap())
            );
        }
    }
    let db = quil_store::RocksDb::open(directory.path()).unwrap();
    let (_, state) = make_state(&db);
    assert_eq!(state.crdt().read_frame_cursor(&cursor).unwrap(), 4);
    assert_eq!(head(&state, &app).unwrap(), Some(next.clone()));
    assert_eq!(origins(&state, &next.id().unwrap()).unwrap().len(), 2);
    for source in &request.sources {
        assert_eq!(
            status(&state, &source.id().unwrap()).unwrap(),
            Status::Closed(request.id().unwrap())
        );
    }
}

#[test]
fn partial_global_coverage_cannot_authorize_a_session() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    state.crdt().set_covered_prefix(&[63; 43]).unwrap();
    assert!(matches!(
        initialize(&state, 1, &initial(vec![5; 32], &keys)),
        Err(QuilError::ExecutionUnavailable(_))
    ));
    assert_eq!(state.changeset_len(), 0);
    assert!(CommittedView::capture(state.crdt()).is_err());
}

#[test]
fn committed_view_requires_a_valid_cursor_and_supported_snapshot_store() {
    use quil_types::store::KvDb as _;
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    assert!(CommittedView::capture(state.crdt()).is_err());
    let transaction = db.new_batch(false).unwrap();
    transaction
        .set(
            &quil_store::encoding::global_materialized_cursor_key(),
            &[0; 7],
        )
        .unwrap();
    transaction.commit().unwrap();
    assert!(CommittedView::capture(state.crdt()).is_err());
    let memory = Arc::new(HypergraphCrdt::new(
        Arc::new(quil_hypergraph::testing::MemStore::new()),
        Arc::new(StubProver),
    ));
    assert!(CommittedView::capture(&memory).is_err());
}

#[test]
fn canonical_global_dispatch_validates_real_certificate_and_rejects_stateless_admission() {
    use crate::{
        engines::GlobalExecutionEngine,
        message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest},
    };
    use quil_types::execution::ShardExecutionEngine as _;
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let filter = vec![0x12; 32];
    initialize(&state, 1, &initial(filter.clone(), &keys)).unwrap();
    commit(&state, 1);
    let request = schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    let seal = submission(&request, 0, &keys, 2);
    executed(&state, &seal);
    commit(&state, 2);
    let bundle = CanonicalMessageBundle {
        timestamp: 0,
        requests: vec![Some(
            CanonicalMessageRequest::wrap(seal.to_canonical_bytes().unwrap()).unwrap(),
        )],
    };
    let wire = bundle.to_canonical_bytes().unwrap();
    let stateless = GlobalExecutionEngine::new(Arc::new(StubProver));
    assert!(matches!(
        stateless.validate_message(3, &GLOBAL_INTRINSIC_ADDRESS, &wire),
        Err(QuilError::ExecutionUnavailable(_))
    ));
    assert!(matches!(
        stateless.process_message(3, &BigInt::from(0), &GLOBAL_INTRINSIC_ADDRESS, &wire),
        Err(QuilError::ExecutionUnavailable(_))
    ));
    let engine = GlobalExecutionEngine::new_with_intrinsic(
        Arc::new(StubProver),
        Arc::new(crate::testing::NoopKeyManager),
        state.crdt().clone(),
        Arc::new(quil_store::RocksClockStore::new(db.inner())),
        None,
        None,
    );
    assert!(engine
        .validate_message(2, &GLOBAL_INTRINSIC_ADDRESS, &wire)
        .is_err());
    engine
        .validate_message(3, &GLOBAL_INTRINSIC_ADDRESS, &wire)
        .unwrap();
    engine
        .process_message(3, &BigInt::from(0), &GLOBAL_INTRINSIC_ADDRESS, &wire)
        .unwrap();
    assert_eq!(head(&state, &filter).unwrap().unwrap().generation, 2);
    let mut altered = seal;
    altered.seal.checkpoint.history_root[0] ^= 1;
    let bad = CanonicalMessageRequest::wrap(altered.to_canonical_bytes().unwrap())
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
    assert!(engine
        .validate_message(3, &GLOBAL_INTRINSIC_ADDRESS, &bad)
        .is_err());
    let (_, durable) = make_state(&db);
    assert_eq!(
        head(&durable, &filter).unwrap().unwrap().generation,
        1,
        "dispatch only stages the activation"
    );
    commit(&state, 3);
    let (_, durable) = make_state(&db);
    assert_eq!(head(&durable, &filter).unwrap().unwrap().generation, 2);
}

fn scan_of(assignments: &[(&[u8], &[FalconPrivateKey])]) -> crate::prover_registry::CommittedProverScan {
    use quil_types::consensus::{ProverAllocationInfo, ProverStatus};
    let mut pubkeys = std::collections::HashMap::new();
    let mut allocations = Vec::new();
    for (filter, keys) in assignments {
        for key in keys.iter() {
            let public_key = key.public_key().as_ref().to_vec();
            let address = quil_crypto::poseidon::hash_bytes_to_32(&public_key).unwrap().to_vec();
            pubkeys.insert(address.clone(), public_key);
            allocations.push((address, ProverAllocationInfo {
                status: ProverStatus::Active,
                confirmation_filter: filter.to_vec(),
                rejection_filter: vec![],
                join_frame_number: 0, leave_frame_number: 0, pause_frame_number: 0,
                resume_frame_number: 0, kick_frame_number: 0, join_confirm_frame_number: 0,
                join_reject_frame_number: 0, leave_confirm_frame_number: 0,
                leave_reject_frame_number: 0, last_active_frame_number: 0,
                epoch: u64::MAX, ring: 0, vertex_address: vec![],
            }));
        }
    }
    crate::prover_registry::CommittedProverScan::from_parts(pubkeys, allocations)
}

fn policy() -> quil_types::consensus::CommitteeHandoffPolicy {
    quil_types::consensus::CommitteeHandoffPolicy { activation_frame: 2, chain_id: [0x11; 32], legacy_history: quil_types::consensus::LegacyHistory::Migrate, membership_boundary_frame: u64::MAX, first_session_boundary_frame: u64::MAX}
}

#[test]
fn scheduler_authorizes_first_sessions_and_membership_successors_once() {
    let directory = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(directory.path()).unwrap();
    let (_store, state) = make_state(&db);
    commit(&state, 1);
    let filter = vec![7u8; 32];
    let filters = vec![filter.clone()];
    let old = keys();
    let scan = scan_of(&[(&filter, &old)]);
    assert_eq!(schedule::reconcile_membership(&state, 1, &policy(), &filters, &scan).unwrap(), 0,
        "nothing is authorized before activation");
    assert_eq!(schedule::reconcile_membership(&state, 2, &policy(), &filters, &scan).unwrap(), 1);
    commit(&state, 2);
    let first = head(&state, &filter).unwrap().unwrap();
    assert_eq!((first.generation, first.base_frame, first.members.clone()), (1, 0, members(&old)));
    assert!(origins(&state, &first.id().unwrap()).unwrap().is_empty());
    assert_eq!(schedule::reconcile_membership(&state, 3, &policy(), &filters, &scan).unwrap(), 0,
        "an unchanged committee schedules nothing");
    assert_eq!(schedule::reconcile_membership(&state, 3, &policy(), &filters, &scan_of(&[])).unwrap(), 0,
        "an empty eligible set never replaces a committee");

    let mut new = keys();
    new.push(old[0].clone());
    let changed = scan_of(&[(&filter, &new)]);
    assert_eq!(schedule::reconcile_membership(&state, 4, &policy(), &filters, &changed).unwrap(), 1);
    commit(&state, 4);
    let Status::Sealing(request_id) = status(&state, &first.id().unwrap()).unwrap() else {
        panic!("source must be closing");
    };
    assert_eq!(schedule::closing_request(&state, &first).unwrap(), Some(request_id));
    assert!(!schedule::seal_submitted(&state, &first).unwrap());
    assert_eq!(schedule::reconcile_membership(&state, 5, &policy(), &filters, &changed).unwrap(), 0,
        "a closing source is not scheduled twice");
    let request = request(&state, &request_id).unwrap().unwrap();
    let closing = submission(&request, 0, &old, 3);
    assert!(!submission_settled(&state, &closing).unwrap());
    assert!(apply_submission(&state, 6, &closing).unwrap());
    assert!(submission_settled(&state, &closing).unwrap(), "a recorded seal is settled");
    commit(&state, 6);
    assert!(schedule::seal_submitted(&state, &first).unwrap());
    assert!(schedule::closing_request(&state, &first).is_err(), "a retired session has no parent");
    let second = head(&state, &filter).unwrap().unwrap();
    assert_eq!((second.generation, second.base_frame, second.members.clone()), (2, 3, members(&new)));
    assert_eq!(schedule::reconcile_membership(&state, 7, &policy(), &filters, &changed).unwrap(), 0);
}

/// From `membership_boundary_frame` a changed eligible set replaces a session
/// only at the first pass of an epoch; before it, at any pass.
#[test]
fn membership_successors_wait_for_the_epoch_boundary() {
    let epoch = quil_types::consensus::epoch_length_frames();
    let pass = |frame: u64| frame - frame % schedule::SESSION_PASS_FRAMES;
    for (rule_from, mid_epoch_schedules) in [(0u64, false), (u64::MAX, true)] {
        let policy = quil_types::consensus::CommitteeHandoffPolicy {
            membership_boundary_frame: rule_from,
            ..policy()
        };
        let directory = tempfile::tempdir().unwrap();
        let db = quil_store::RocksDb::open(directory.path()).unwrap();
        let (_store, state) = make_state(&db);
        commit(&state, 1);
        let filter = vec![7u8; 32];
        let filters = vec![filter.clone()];
        let old = keys();
        assert_eq!(schedule::reconcile_membership(&state, 2, &policy, &filters, &scan_of(&[(&filter, &old)])).unwrap(), 1,
            "a first session is authorized at any pass");
        commit(&state, 2);
        let mut new = keys();
        new.push(old[0].clone());
        let changed = scan_of(&[(&filter, &new)]);
        let mid = pass(epoch + epoch / 2);
        assert!(!schedule::first_pass_of_epoch(mid));
        assert_eq!(schedule::reconcile_membership(&state, mid, &policy, &filters, &changed).unwrap(),
            usize::from(mid_epoch_schedules));
        if !mid_epoch_schedules {
            assert!(schedule::first_pass_of_epoch(2 * epoch));
            assert_eq!(schedule::reconcile_membership(&state, 2 * epoch, &policy, &filters, &changed).unwrap(), 1,
                "the boundary pass replaces the committee");
        }
    }
}

/// From `first_session_boundary_frame` a shard's first session is also
/// authorized only at the first pass of an epoch.
#[test]
fn first_sessions_wait_for_the_epoch_boundary() {
    let epoch = quil_types::consensus::epoch_length_frames();
    let policy = quil_types::consensus::CommitteeHandoffPolicy { first_session_boundary_frame: 0, ..policy() };
    let directory = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(directory.path()).unwrap();
    let (_store, state) = make_state(&db);
    commit(&state, 1);
    let filter = vec![7u8; 32];
    let filters = vec![filter.clone()];
    let scan = scan_of(&[(&filter, &keys())]);
    let mid = epoch + epoch / 2 - (epoch / 2) % schedule::SESSION_PASS_FRAMES;
    assert!(!schedule::first_pass_of_epoch(mid));
    assert_eq!(schedule::reconcile_membership(&state, mid, &policy, &filters, &scan).unwrap(), 0);
    assert!(head(&state, &filter).unwrap().is_none());
    assert_eq!(schedule::reconcile_membership(&state, 2 * epoch, &policy, &filters, &scan).unwrap(), 1,
        "the boundary pass authorizes the first session");
}

#[test]
fn scheduler_holds_a_governed_split_until_its_parent_seals() {
    use quil_types::store::{PendingShardChange, ShardChangeKind};
    let directory = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(directory.path()).unwrap();
    let (_store, state) = make_state(&db);
    commit(&state, 1);
    let app = [9u8; 32];
    let parent = app.to_vec();
    let children: Vec<Vec<u8>> = [false, true]
        .into_iter()
        .map(|bit| quil_forest::encode_shard_bit_path(&app, &[bit]))
        .collect();
    let change = PendingShardChange {
        kind: ShardChangeKind::Split, parent: parent.clone(), children: children.clone(),
        effective_epoch: 2, proposed_frame: 1,
    };
    let provers = keys();
    let scan = scan_of(&[(&parent, &provers)]);

    // No committee ever formed on the parent: nothing to seal.
    assert_eq!(schedule::gate_topology_change(&state, 2, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Apply);
    assert_eq!(schedule::gate_topology_change(&state, 1, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Apply, "legacy before activation");

    schedule::reconcile_membership(&state, 2, &policy(), &[parent.clone()], &scan).unwrap();
    commit(&state, 2);
    let source = head(&state, &parent).unwrap().unwrap();
    assert_eq!(schedule::gate_topology_change(&state, 3, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Wait);
    commit(&state, 3);
    let Status::Sealing(request_id) = status(&state, &source.id().unwrap()).unwrap() else {
        panic!("parent must be closing");
    };
    let request = request(&state, &request_id).unwrap().unwrap();
    let planned = schedule::split_assignment(&scan, &change, 3, true);
    assert_eq!(planned.iter().map(Vec::len).collect::<Vec<_>>(), vec![2, 2]);
    for (target, members) in request.targets.iter().zip(&planned) {
        assert_eq!(&target.committee.members, members);
    }
    // A node without committed prover state (a regular keeping a local grid)
    // never schedules, and holds the change until activation reaches it.
    assert_eq!(schedule::gate_topology_change(&state, 4, &policy(), &change, None, true).unwrap(),
        schedule::TopologyGate::Wait);
    // Waiting neither reschedules nor lets the children be claimed separately.
    assert_eq!(schedule::gate_topology_change(&state, 4, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Wait);
    let moved = scan_of(&[(&children[0], &provers[..2]), (&children[1], &provers[2..])]);
    assert_eq!(schedule::reconcile_membership(&state, 4, &policy(), &children, &moved).unwrap(), 0,
        "reserved successors are not initialized as unrelated first sessions");
    assert!(head(&state, &children[0]).unwrap().is_none());

    assert!(apply_submission(&state, 5, &submission(&request, 0, &provers, 4)).unwrap());
    commit(&state, 5);
    assert_eq!(schedule::gate_topology_change(&state, 6, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Apply);
    assert_eq!(schedule::gate_topology_change(&state, 6, &policy(), &change, None, true).unwrap(),
        schedule::TopologyGate::Apply);
    for (child, members) in children.iter().zip(&planned) {
        let session = head(&state, child).unwrap().unwrap();
        assert_eq!((session.generation, &session.members), (1, members));
        assert_eq!(origins(&state, &session.id().unwrap()).unwrap()[0].0, source);
    }
}

/// The shape a live localnet produced: a deep (bit-path) split registers the
/// two leaves AND the co-path spine, which has no provers. Only that complete
/// set covers the parent's range; scheduling the leaves alone was refused as a
/// range change and, before the scheduler learned to contain such a refusal,
/// stopped global materialization.
#[test]
fn scheduler_covers_a_deep_split_with_member_less_spine_shards() {
    use quil_types::store::{PendingShardChange, ShardChangeKind};
    let directory = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(directory.path()).unwrap();
    let (_store, state) = make_state(&db);
    commit(&state, 1);
    let app = [0x11u8; 32];
    let parent = app.to_vec();
    let children: Vec<Vec<u8>> = [[0x00u8, 0x03, 0x00], [0x00, 0x03, 0x20]]
        .iter().map(|suffix| [app.as_slice(), suffix].concat()).collect();
    let deep = super::super::materialize::unified_tree_cutover_frame() + 10;
    let change = PendingShardChange {
        kind: ShardChangeKind::Split, parent: parent.clone(), children: children.clone(),
        effective_epoch: 2, proposed_frame: deep,
    };
    let registered = super::super::materialize::materialize_shard_split(&parent, &children, true).unwrap();
    assert!(registered.new_shards.len() > children.len(), "this split registers spine shards too");
    let provers = keys();
    let scan = scan_of(&[(&parent, &provers)]);
    schedule::reconcile_membership(&state, deep, &policy(), &[parent.clone()], &scan).unwrap();
    commit(&state, deep);
    let source = head(&state, &parent).unwrap().unwrap();

    assert_eq!(schedule::gate_topology_change(&state, deep + 1, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Wait);
    commit(&state, deep + 1);
    let Status::Sealing(request_id) = status(&state, &source.id().unwrap()).unwrap() else {
        panic!("the parent must be closing");
    };
    let request = request(&state, &request_id).unwrap().unwrap();
    assert_eq!(request.targets.len(), registered.new_shards.len());
    let staffed: Vec<_> = request.targets.iter().filter(|t| !t.committee.members.is_empty()).collect();
    assert_eq!(staffed.iter().map(|t| t.committee.filter.clone()).collect::<Vec<_>>(), {
        let mut leaves = children.clone(); leaves.sort(); leaves
    }, "exactly the leaves the allocations move to are staffed, spelled as the allocations spell them");
    assert_eq!(Request::decode(&request.encode().unwrap()).unwrap(), request);

    assert!(apply_submission(&state, deep + 2, &submission(&request, 0, &provers, 4)).unwrap());
    commit(&state, deep + 2);
    assert_eq!(schedule::gate_topology_change(&state, deep + 3, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Apply);
    let spine: Vec<_> = request.targets.iter().filter(|t| t.committee.members.is_empty())
        .map(|t| t.committee.filter.clone()).collect();
    for leaf in &children {
        assert_eq!(head(&state, leaf).unwrap().unwrap().generation, 1);
    }
    for filter in &spine {
        assert!(head(&state, filter).unwrap().is_none(), "a range without provers gets no session");
    }
    // Provers that later become eligible on a spine shard get an ordinary
    // first session: the range was authorized, not left reserved.
    let joined = scan_of(&[(&spine[0], &provers[..2])]);
    assert_eq!(schedule::reconcile_membership(&state, deep + 8, &policy(), &spine, &joined).unwrap(), 1);
    assert_eq!(head(&state, &spine[0]).unwrap().unwrap().members, members(&provers[..2]));
}

/// A merge seals two governed sources and activates one successor whose
/// members are the union. The successor's activating request is readable from
/// its filter, and it names both sources: that is how an app engine tells a
/// merged shard (whose members each hold half the range) from a split child.
#[test]
fn scheduler_merges_two_governed_sources_into_one_successor() {
    use quil_types::store::{PendingShardChange, ShardChangeKind};
    let directory = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(directory.path()).unwrap();
    let (_store, state) = make_state(&db);
    commit(&state, 1);
    let app = [9u8; 32];
    let parent = quil_forest::encode_shard_bit_path(&app, &[false]);
    let children: Vec<Vec<u8>> = [false, true]
        .into_iter()
        .map(|bit| quil_forest::encode_shard_bit_path(&app, &[false, bit]))
        .collect();
    // Three members a side: the seal certificates need three signers each.
    let provers: Vec<FalconPrivateKey> = keys().into_iter().chain(keys()).take(6).collect();
    let scan = scan_of(&[(&children[0], &provers[..3]), (&children[1], &provers[3..])]);
    schedule::reconcile_membership(&state, 2, &policy(), &children, &scan).unwrap();
    commit(&state, 2);
    let sources: Vec<_> = children.iter().map(|c| head(&state, c).unwrap().unwrap()).collect();
    assert!(schedule::activating_request(&state, &children[0]).unwrap().is_none(),
        "a reconciled first session has no activating request");

    // Bit-path children: proposed after the unified-tree cutover.
    let change = PendingShardChange {
        kind: ShardChangeKind::Merge, parent: parent.clone(), children: children.clone(),
        effective_epoch: 2, proposed_frame: super::super::materialize::unified_tree_cutover_frame() + 1,
    };
    assert_eq!(schedule::gate_topology_change(&state, 3, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Wait);
    commit(&state, 3);
    let Status::Sealing(request_id) = status(&state, &sources[0].id().unwrap()).unwrap() else {
        panic!("both sources must be closing");
    };
    assert!(matches!(status(&state, &sources[1].id().unwrap()).unwrap(), Status::Sealing(id) if id == request_id));
    let request = request(&state, &request_id).unwrap().unwrap();
    assert_eq!(request.sources.len(), 2);
    let mut union: Vec<Vec<u8>> = provers.iter().map(|k| k.public_key().as_ref().to_vec()).collect();
    union.sort();
    assert_eq!(request.targets.len(), 1);
    assert_eq!(request.targets[0].committee.members, union);
    assert_eq!(schedule::activating_request(&state, &parent).unwrap().unwrap().id().unwrap(), request_id,
        "the reserved target resolves to the request that will activate it");

    // One seal is not enough; the second activates the union.
    assert!(!apply_submission(&state, 4, &submission(&request, 0, &provers[..3], 7)).unwrap());
    commit(&state, 4);
    assert_eq!(schedule::gate_topology_change(&state, 5, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Wait);
    assert!(apply_submission(&state, 5, &submission(&request, 1, &provers[3..], 9)).unwrap());
    commit(&state, 5);
    assert_eq!(schedule::gate_topology_change(&state, 6, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Apply);
    let merged = head(&state, &parent).unwrap().unwrap();
    assert_eq!((merged.generation, &merged.members), (1, &union));
    assert_eq!(origins(&state, &merged.id().unwrap()).unwrap().len(), 2);
    let activating = schedule::activating_request(&state, &parent).unwrap().unwrap();
    assert_eq!(activating.sources.len() + activating.vacant.len(), 2);
}

/// A removed shard keeps no allocation: the reassignment enumerates every
/// prover on it, Joining ones included, while committee membership still
/// counts only eligible ones.
#[test]
fn every_allocation_leaves_a_removed_shard() {
    use quil_types::consensus::ProverStatus;
    let filter = vec![3u8; 33];
    let provers = keys();
    let mut scan = scan_of(&[(&filter, &provers)]);
    // The scan's allocations are `(address, allocation)`; demote two of them.
    let mut allocations = std::mem::take(&mut scan.allocations);
    for (_, alloc) in allocations.iter_mut().take(2) {
        alloc.status = ProverStatus::Joining;
        alloc.epoch = 0;
    }
    // A retired slot is not an allocation: moving it would overwrite the
    // live allocation at its destination.
    allocations[2].1.status = ProverStatus::Historic;
    scan.allocations = allocations;
    assert_eq!(scan.active_on_filter(&filter, 1000).len(), 1, "joining and retired allocations are not eligible");
    assert_eq!(scan.all_on_filter(&filter).len(), 3, "joining ones still move with the shard; the retired one stays");
    assert!(scan.all_on_filter(&[4u8; 33]).is_empty());
}

/// A governed split whose parent has lost every eligible prover since it was
/// proposed has no one to hand to. Holding it would keep the record due
/// forever; it is dropped instead, and the decision is recorded so a node
/// without a prover scan drops it too.
#[test]
fn scheduler_drops_a_split_no_successor_would_staff() {
    use quil_types::store::{PendingShardChange, ShardChangeKind};
    let directory = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(directory.path()).unwrap();
    let (_store, state) = make_state(&db);
    commit(&state, 1);
    let app = [9u8; 32];
    let parent = app.to_vec();
    let children: Vec<Vec<u8>> = [false, true]
        .into_iter()
        .map(|bit| quil_forest::encode_shard_bit_path(&app, &[bit]))
        .collect();
    let provers = keys();
    schedule::reconcile_membership(&state, 2, &policy(), &[parent.clone()], &scan_of(&[(&parent, &provers)])).unwrap();
    commit(&state, 2);
    let session = head(&state, &parent).unwrap().unwrap();

    let change = PendingShardChange {
        kind: ShardChangeKind::Split, parent: parent.clone(), children,
        effective_epoch: 2, proposed_frame: super::super::materialize::unified_tree_cutover_frame() + 1,
    };
    // Every prover has left the parent.
    let empty = scan_of(&[]);
    assert_eq!(schedule::gate_topology_change(&state, 3, &policy(), &change, Some(&empty), true).unwrap(),
        schedule::TopologyGate::Drop);
    commit(&state, 3);
    assert_eq!(status(&state, &session.id().unwrap()).unwrap(), Status::Active, "nothing was scheduled");
    // A regular, without a scan, reads the recorded decision.
    assert_eq!(schedule::gate_topology_change(&state, 4, &policy(), &change, None, true).unwrap(),
        schedule::TopologyGate::Drop);
}

/// A source's last outflows ride only its drain headers. Its seal is refused
/// until GLOBAL has executed its data frames through the sealed checkpoint,
/// and accepted once it has; the tip only ever rises.
#[test]
fn a_seal_waits_until_global_executed_the_source_through_its_checkpoint() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let filter = vec![0x5a; 32];
    initialize(&state, 1, &initial(filter.clone(), &keys)).unwrap();
    let request = schedule(&state, 2, vec![filter.clone()], vec![desired(&filter, &keys)]).unwrap();
    let seal = submission(&request, 0, &keys, 6);
    let session = seal.seal.session;
    assert!(super::verify_submission(&state, 3, &seal).is_err(), "no source frame executed yet");
    let mut tip = seal.seal.checkpoint.clone();
    tip.frame = 5;
    record_session_tip(&state, 3, &session, &tip).unwrap();
    assert!(super::apply_submission(&state, 3, &seal).is_err(), "the checkpoint frame itself is not executed");
    tip.frame = 6;
    record_session_tip(&state, 3, &session, &tip).unwrap();
    tip.frame = 4;
    record_session_tip(&state, 3, &session, &tip).unwrap();
    assert_eq!(session_tip(&state, &session).unwrap().unwrap().frame, 6, "the tip only rises");
    assert!(super::apply_submission(&state, 3, &seal).unwrap());
}

/// A seal must name the source's executed tip itself. One below it, or at it
/// with another digest, would authorize a successor that drops or forks frames
/// GLOBAL executed, and is refused however often it is resubmitted.
#[test]
fn a_seal_below_or_beside_the_executed_tip_is_refused() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let filter = vec![0x5c; 32];
    initialize(&state, 1, &initial(filter.clone(), &keys)).unwrap();
    let request = schedule(&state, 2, vec![filter.clone()], vec![desired(&filter, &keys)]).unwrap();
    let seal = submission(&request, 0, &keys, 6);
    let session = seal.seal.session;
    let mut executed = seal.seal.checkpoint.clone();
    executed.frame = 7;
    record_session_tip(&state, 3, &session, &executed).unwrap();
    let below = super::verify_submission(&state, 3, &seal).unwrap_err();
    assert!(below.to_string().contains("below the source's executed frames"), "{below}");

    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    initialize(&state, 1, &initial(filter.clone(), &keys)).unwrap();
    let request = schedule(&state, 2, vec![filter.clone()], vec![desired(&filter, &keys)]).unwrap();
    let seal = submission(&request, 0, &keys, 6);
    let mut forked = seal.seal.checkpoint.clone();
    forked.digest[0] ^= 1;
    record_session_tip(&state, 3, &seal.seal.session, &forked).unwrap();
    let beside = super::verify_submission(&state, 3, &seal).unwrap_err();
    assert!(beside.to_string().contains("differs from the source's executed frame"), "{beside}");
    // Only the digest decides: the roots GLOBAL records are the header's.
    let mut same = seal.seal.checkpoint.clone();
    same.state_roots = [[0x71; 32]; 4];
    same.history_root = [0; 32];
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    initialize(&state, 1, &initial(filter.clone(), &keys)).unwrap();
    let request = schedule(&state, 2, vec![filter.clone()], vec![desired(&filter, &keys)]).unwrap();
    let seal = submission(&request, 0, &keys, 6);
    record_session_tip(&state, 3, &seal.seal.session, &same).unwrap();
    assert!(super::apply_submission(&state, 3, &seal).unwrap());
}

fn fence_timeout() -> u64 {
    schedule::FENCE_AFTER_EPOCHS * quil_types::consensus::epoch_length_frames()
}

fn tip(frame: u64, view: u64, digest: [u8; 32]) -> Checkpoint {
    Checkpoint { frame, view, digest, state_roots: [[0x61; 32]; 4], history_root: [0x62; 32] }
}

/// A source asked to close before GLOBAL executed any frame of it seals at its
/// base. It has nothing to drain, so the seal is accepted without a tip; a
/// seal above the base still waits for its frames.
#[test]
fn a_session_closed_before_its_first_frame_seals_at_its_base() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let filter = vec![0x5b; 32];
    let first = initial(filter.clone(), &keys);
    initialize(&state, 1, &first).unwrap();
    let request = schedule(&state, 2, vec![filter.clone()], vec![desired(&filter, &keys)]).unwrap();
    let above = submission(&request, 0, &keys, first.base_frame + 1);
    assert!(super::verify_submission(&state, 3, &above).is_err(), "a seal above the base waits for its frames");
    let mut at_base = submission(&request, 0, &keys, first.base_frame);
    at_base.seal.checkpoint.view = 0;
    at_base.seal.checkpoint.digest = first.genesis;
    at_base.certificate = sign_certificate(&first, &keys, at_base.seal.view, 0, at_base.seal.digest());
    assert!(super::apply_submission(&state, 3, &at_base).unwrap());
    assert_eq!(head(&state, &filter).unwrap().unwrap().generation, first.generation + 1);
}

/// A closing session that never seals is fenced at its executed tip once
/// its request is FENCE_AFTER_EPOCHS old, and its successor is authorized
/// from that checkpoint: frames past the fence are refused like frames past a
/// seal, and a late seal is refused.
#[test]
fn a_session_that_never_seals_is_fenced_at_its_tip_and_succeeded() {
    use super::frames::{verify, FrameClaim};
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let filter = vec![0x6a; 32];
    let first = initial(filter.clone(), &keys);
    initialize(&state, 1, &first).unwrap();
    let request = schedule(&state, 2, vec![filter.clone()], vec![desired(&filter, &keys)]).unwrap();
    let id = first.id().unwrap();
    record_session_tip(&state, 3, &id, &tip(6, 9, [0x66; 32])).unwrap();
    commit(&state, 3);
    let beyond = FrameClaim { filter: &filter, frame: 7, view: 10, parent: &[0x66; 32], digest: [0x77; 32] };
    let beyond_cert = sign_certificate(&first, &keys, 10, 9, beyond.digest);
    assert!(verify(&state, &beyond, &beyond_cert).unwrap().is_some(), "still closing: not yet bounded");

    let due = 2 + fence_timeout();
    assert_eq!(schedule::fence_stalled_sources(&state, due - 1, &[filter.clone()]).unwrap(), 0, "not before the timeout");
    assert!(!is_fenced(&state, &id).unwrap());
    assert_eq!(schedule::fence_stalled_sources(&state, due, &[filter.clone()]).unwrap(), 1);
    commit(&state, due);
    assert!(is_fenced(&state, &id).unwrap());
    assert!(matches!(status(&state, &id).unwrap(), Status::Closed(_)));
    let fence = closed_checkpoint(&state, &id).unwrap().unwrap();
    assert_eq!((fence.frame, fence.view, fence.digest), (6, 9, [0x66; 32]));
    assert_eq!((fence.state_roots, fence.history_root), ([[0; 32]; 4], [0; 32]), "nothing certifies the post-tip state");
    let successor = head(&state, &filter).unwrap().unwrap();
    assert_eq!((successor.generation, successor.base_frame), (2, 6));
    assert!(schedule::activated(&state, &request.id().unwrap()).unwrap());
    assert!(verify(&state, &beyond, &beyond_cert).is_err(), "the fence bounds the session's frames");
    let at_fence = FrameClaim { filter: &filter, frame: 6, view: 9, parent: &[0x55; 32], digest: [0x66; 32] };
    assert!(verify(&state, &at_fence, &sign_certificate(&first, &keys, 9, 8, at_fence.digest)).unwrap().is_some());

    // A seal arriving after the fence is refused, and fencing is idempotent.
    let late = submission(&request, 0, &keys, 6);
    record_session_tip(&state, due, &id, &late.seal.checkpoint).unwrap();
    assert!(super::apply_submission(&state, due + 1, &late).is_err());
    assert_eq!(schedule::fence_stalled_sources(&state, due + 8, &[filter.clone()]).unwrap(), 0);

    // The authorization commits to the fence, not to any seal of that checkpoint.
    let db2 = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, sealed_state) = make_state(&db2);
    initialize(&sealed_state, 1, &first).unwrap();
    let sealed_request = schedule(&sealed_state, 2, vec![filter.clone()], vec![desired(&filter, &keys)]).unwrap();
    assert_eq!(sealed_request.id().unwrap(), request.id().unwrap());
    let mut seal = submission(&sealed_request, 0, &keys, 6);
    seal.seal.view = 12;
    seal.seal.checkpoint.view = 9;
    seal.seal.checkpoint.digest = [0x66; 32];
    seal.certificate = sign_certificate(&first, &keys, seal.seal.view, 9, seal.seal.digest());
    assert!(apply_submission(&sealed_state, 3, &seal).unwrap());
    assert_ne!(head(&sealed_state, &filter).unwrap().unwrap().authorization, successor.authorization);
}

/// A stalled session GLOBAL never executed a frame of is fenced at its base
/// and succeeded. With a same-filter predecessor the fence carries that
/// predecessor's certified roots; a first session (like a split or merge
/// child) has none, and its fence carries no roots.
#[test]
fn a_stalled_session_without_a_tip_is_fenced_at_its_base() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let filter = vec![0x6b; 32];
    let first = initial(filter.clone(), &keys);
    initialize(&state, 1, &first).unwrap();
    let request = schedule(&state, 2, vec![filter.clone()], vec![desired(&filter, &keys)]).unwrap();
    let due = 2 + fence_timeout();
    assert_eq!(schedule::fence_stalled_sources(&state, due - 1, &[filter.clone()]).unwrap(), 0, "not before the timeout");
    assert_eq!(schedule::fence_stalled_sources(&state, due, &[filter.clone()]).unwrap(), 1, "a first session without a tip");
    assert!(is_fenced(&state, &first.id().unwrap()).unwrap());
    let fence = closed_checkpoint(&state, &first.id().unwrap()).unwrap().unwrap();
    assert_eq!((fence.frame, fence.view, fence.digest), (first.base_frame, 0, first.genesis));
    assert_eq!((fence.state_roots, fence.history_root), ([[0; 32]; 4], [0; 32]), "nothing certifies its state");
    assert!(schedule::activated(&state, &request.id().unwrap()).unwrap());
    let successor = head(&state, &filter).unwrap().unwrap();
    assert_eq!((successor.generation, successor.base_frame), (first.generation + 1, first.base_frame));
    assert_eq!(origins(&state, &successor.id().unwrap()).unwrap(), vec![(first.clone(), fence)]);

    // With a same-filter predecessor sealed at frame 4, a successor that then
    // stalls is fenced at its base with the predecessor's sealed roots.
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    initialize(&state, 1, &first).unwrap();
    let request = schedule(&state, 2, vec![filter.clone()], vec![desired(&filter, &keys)]).unwrap();
    assert!(apply_submission(&state, 3, &submission(&request, 0, &keys, 4)).unwrap());
    let second = head(&state, &filter).unwrap().unwrap();
    let second_request = schedule(&state, 4, vec![filter.clone()], vec![desired(&filter, &keys)]).unwrap();
    let later = 4 + fence_timeout();
    assert_eq!(schedule::fence_stalled_sources(&state, later, &[filter.clone()]).unwrap(), 1);
    let fence = closed_checkpoint(&state, &second.id().unwrap()).unwrap().unwrap();
    assert_eq!((fence.frame, fence.digest), (second.base_frame, second.genesis));
    assert_eq!(fence.state_roots, [[0x40; 32], [0x41; 32], [0x42; 32], [0x43; 32]], "the predecessor's sealed roots");
    assert!(schedule::activated(&state, &second_request.id().unwrap()).unwrap());
}

/// Merge sources end independently: one by its seal, the other by a fence.
/// Neither alone activates the successor; together they do.
#[test]
fn a_merge_activates_from_one_sealed_and_one_fenced_source() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let root = vec![0x6c; 32];
    let mut left_filter = root.clone(); left_filter.extend_from_slice(&[0, 1, 0]);
    let mut right_filter = root.clone(); right_filter.extend_from_slice(&[0, 1, 128]);
    let left = initial(left_filter.clone(), &keys);
    let right = initial(right_filter.clone(), &keys);
    initialize(&state, 1, &left).unwrap();
    initialize(&state, 1, &right).unwrap();
    let request = schedule(&state, 2, vec![left_filter.clone(), right_filter.clone()], vec![desired(&root, &keys)]).unwrap();
    let sealed_index = request.sources.iter().position(|s| s.filter == left_filter).unwrap();
    assert!(!apply_submission(&state, 3, &submission(&request, sealed_index, &keys, 5)).unwrap());
    record_session_tip(&state, 3, &right.id().unwrap(), &tip(8, 11, [0x88; 32])).unwrap();
    let filters = vec![left_filter.clone(), right_filter.clone()];
    assert_eq!(schedule::fence_stalled_sources(&state, 2 + fence_timeout(), &filters).unwrap(), 1, "only the unsealed source");
    assert!(!is_fenced(&state, &left.id().unwrap()).unwrap());
    assert!(is_fenced(&state, &right.id().unwrap()).unwrap());
    assert!(schedule::activated(&state, &request.id().unwrap()).unwrap());
    assert_eq!(head(&state, &root).unwrap().unwrap().generation, 1);
}

#[path = "handoff_legacy_tests.rs"]
mod legacy_tests;

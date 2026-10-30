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
    record_session_tip(
        state,
        1,
        &submission.seal.session,
        &submission.seal.checkpoint,
    )
    .unwrap();
}

/// [`super::apply_submission`] after the source's frames were executed. The
/// seal-before-execution rule has its own test.
fn apply_submission(
    state: &HypergraphState,
    frame: u64,
    submission: &CertificateSubmission,
) -> Result<bool> {
    executed(state, submission);
    super::apply_submission(state, frame, submission)
}

/// [`super::verify_submission`] after the source's frames were executed.
fn verify_submission(
    state: &HypergraphState,
    frame: u64,
    submission: &CertificateSubmission,
) -> Result<Request> {
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
            (
                enc::clock_shard_frame_fee_total_key(filter, frame),
                (frame as u128).to_be_bytes().to_vec(),
            ),
            (
                enc::clock_shard_frame_settlements_key(filter, frame),
                vec![],
            ),
            (
                enc::clock_shard_frame_spends_key(filter, frame),
                spend_relay::encode_frame_entries(&[vec![frame as u8; 24]]).unwrap(),
            ),
            (
                enc::clock_shard_frame_accumulator_key(filter, frame),
                digest.clone(),
            ),
            (
                enc::clock_shard_accumulator_report_key(filter, &digest),
                report,
            ),
        ]
    };
    let final_root;
    {
        let db = quil_store::RocksDb::open(directory.path()).unwrap();
        let (store, state) = make_state(&db);
        let crdt = state.crdt();
        let absent = crdt.capture_committed_shard(filter).unwrap();
        assert!(
            history::root(absent.records.as_ref(), &session, 0).is_err(),
            "no implicit empty cursor"
        );
        crdt.checkpoint_frame_cursor(0, &cursor).unwrap();
        let genesis = crdt.capture_committed_shard(filter).unwrap();
        let genesis_root = history::root(genesis.records.as_ref(), &session, 0).unwrap();
        crdt.commit_with_frame_cursor_and_records(1, &cursor, &records(1))
            .unwrap();
        let first = crdt.capture_committed_shard(filter).unwrap();
        let first_root = history::root(first.records.as_ref(), &session, 1).unwrap();
        assert_ne!(first_root, genesis_root);
        assert!(history::root(first.records.as_ref(), &session, 0).is_err());
        store.fail_commit_for_test(true);
        assert!(crdt
            .commit_with_frame_cursor_and_records(2, &cursor, &records(2))
            .is_err());
        let failed = crdt.capture_committed_shard(filter).unwrap();
        assert_eq!(
            history::root(failed.records.as_ref(), &session, 1).unwrap(),
            first_root
        );
        assert!(history::root(failed.records.as_ref(), &session, 2).is_err());
        store.fail_commit_for_test(false);
        crdt.commit_with_frame_cursor_and_records(2, &cursor, &records(2))
            .unwrap();
        let second = crdt.capture_committed_shard(filter).unwrap();
        final_root = history::root(second.records.as_ref(), &session, 2).unwrap();
        assert_ne!(final_root, first_root);
        assert_eq!(
            history::root(first.records.as_ref(), &session, 1).unwrap(),
            first_root
        );
        let mut successor = session.clone();
        successor.generation += 1;
        assert_ne!(
            history::root(second.records.as_ref(), &successor, 2).unwrap(),
            final_root
        );
        // Old, unreported records are still required; a current relay window
        // or a complete latest frame cannot repair their loss.
        for (key, value) in records(1) {
            db.inner().delete(&key).unwrap();
            let broken = crdt.capture_committed_shard(filter).unwrap();
            assert!(history::root(broken.records.as_ref(), &session, 2).is_err());
            assert_eq!(
                history::root(second.records.as_ref(), &session, 2).unwrap(),
                final_root
            );
            db.inner().put(key, value).unwrap();
        }
        let report_key = records(2).pop().unwrap().0;
        db.inner().put(&report_key, b"corrupted report").unwrap();
        let broken = crdt.capture_committed_shard(filter).unwrap();
        assert!(history::root(broken.records.as_ref(), &session, 2).is_err());
        db.inner()
            .put(&report_key, records(2).pop().unwrap().1)
            .unwrap();
    }
    let db = quil_store::RocksDb::open(directory.path()).unwrap();
    let (_, state) = make_state(&db);
    let reopened = state.crdt().capture_committed_shard(filter).unwrap();
    assert_eq!(
        history::root(reopened.records.as_ref(), &session, 2).unwrap(),
        final_root
    );
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
    let certificate = sign_certificate(
        session,
        keys,
        seal.view,
        seal.checkpoint.view,
        seal.digest(),
    );
    CertificateSubmission { seal, certificate }
}

fn sign_certificate(
    session: &Session,
    keys: &[FalconPrivateKey],
    view: u64,
    parent: u64,
    digest: [u8; 32],
) -> Vec<u8> {
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
    encode_finalization(&Finalization {
        proposal,
        certificate,
    })
}

#[test]
fn historical_frame_authorization_survives_rotation_and_reopen_without_legacy_fallback() {
    use super::frames::{verify, FrameClaim};
    let directory = tempfile::tempdir().unwrap();
    let keys = keys();
    let first = initial(vec![0x51; 32], &keys);
    let certificate = sign_certificate(&first, &keys, 5, 0, [0x33; 32]);
    let claim = FrameClaim {
        filter: &first.filter,
        frame: 1,
        view: 5,
        parent: &first.genesis,
        digest: [0x33; 32],
    };
    {
        let db = quil_store::RocksDb::open(directory.path()).unwrap();
        let (store, state) = make_state(&db);
        commit(&state, 1);
        let before = CommittedView::capture(state.crdt()).unwrap();
        initialize(&state, 2, &first).unwrap();
        assert!(verify(&state, &claim, &certificate).unwrap().is_some());
        assert!(
            verify(&before, &claim, &certificate).is_err(),
            "staged authorization is not committed"
        );
        state.commit().unwrap();
        state.abort();
        store.fail_commit_for_test(true);
        assert!(state
            .crdt()
            .commit_with_global_cursor(2, &quil_store::encoding::global_materialized_cursor_key())
            .is_err());
        assert!(verify(
            &CommittedView::capture(state.crdt()).unwrap(),
            &claim,
            &certificate
        )
        .is_err());
        store.fail_commit_for_test(false);
        state
            .crdt()
            .commit_with_global_cursor(2, &quil_store::encoding::global_materialized_cursor_key())
            .unwrap();
        let committed = CommittedView::capture(state.crdt()).unwrap();
        assert_eq!(
            session_at_generation(&committed, &first.filter, 1).unwrap(),
            Some(first.clone())
        );
        assert!(verify(&committed, &claim, &certificate).unwrap().is_some());
        for (frame, view, parent) in [
            (0, 5, first.genesis),
            (1, 4, first.genesis),
            (2, 5, first.genesis),
            (1, 5, [0x44; 32]),
        ] {
            let invalid = FrameClaim {
                filter: &first.filter,
                frame,
                view,
                parent: &parent,
                digest: claim.digest,
            };
            assert!(verify(&committed, &invalid, &certificate).is_err());
        }
        let mut trailing = certificate.clone();
        trailing.push(0);
        assert!(verify(&committed, &claim, &trailing).is_err());
        assert!(verify(&committed, &claim, &[0; 10]).is_err());
        let other = vec![0x52; 32];
        assert!(verify(
            &committed,
            &FrameClaim {
                filter: &other,
                ..claim
            },
            &certificate
        )
        .is_err());

        let request = schedule(
            &state,
            3,
            vec![first.filter.clone()],
            vec![desired(&first.filter, &keys)],
        )
        .unwrap();
        let seal = submission(&request, 0, &keys, 1);
        apply_submission(&state, 4, &seal).unwrap();
        commit(&state, 4);
        let second = head(&state, &first.filter).unwrap().unwrap();
        assert_eq!(second.generation, 2);
        let after = CommittedView::capture(state.crdt()).unwrap();
        assert!(
            verify(&after, &claim, &certificate).unwrap().is_some(),
            "old committee remains historically verifiable"
        );
        let latest = sign_certificate(&second, &keys, 1, 0, [0x55; 32]);
        let next = FrameClaim {
            filter: &first.filter,
            frame: 2,
            view: 1,
            parent: &second.genesis,
            digest: [0x55; 32],
        };
        assert!(verify(&after, &next, &latest).unwrap().is_some());
        assert!(verify(&after, &next, &certificate).is_err());
        let mut unauthenticated = first.clone();
        unauthenticated.generation = 0;
        let old_namespace = sign_certificate(&unauthenticated, &keys, 5, 0, claim.digest);
        assert!(
            verify(&after, &claim, &old_namespace).is_err(),
            "same keys cannot downgrade namespace"
        );
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
    assert_eq!(
        session_at_generation(&recovered, &first.filter, 1).unwrap(),
        Some(first.clone())
    );
    assert_eq!(
        head(&recovered, &first.filter).unwrap().unwrap().generation,
        2
    );
    assert!(verify(&recovered, &claim, &certificate).unwrap().is_some());
}

#[test]
fn a_source_seal_bounds_data_even_before_the_other_merge_source_closes() {
    use super::frames::{verify, FrameClaim};
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let root = vec![0x53; 32];
    let mut left_filter = root.clone();
    left_filter.extend_from_slice(&[0, 1, 0]);
    let mut right_filter = root.clone();
    right_filter.extend_from_slice(&[0, 1, 128]);
    let left = initial(left_filter.clone(), &keys);
    initialize(&state, 1, &left).unwrap();
    initialize(&state, 1, &initial(right_filter.clone(), &keys)).unwrap();
    let request = schedule(
        &state,
        2,
        vec![left_filter, right_filter],
        vec![desired(&root, &keys)],
    )
    .unwrap();
    let mut seal = submission(&request, 0, &keys, 3);
    seal.seal.checkpoint.view = 7;
    seal.certificate = sign_certificate(&left, &keys, seal.seal.view, 7, seal.seal.digest());
    let first = FrameClaim {
        filter: &left.filter,
        frame: 1,
        view: 2,
        parent: &left.genesis,
        digest: [0x22; 32],
    };
    let first_cert = sign_certificate(&left, &keys, 2, 0, first.digest);
    let last = FrameClaim {
        filter: &left.filter,
        frame: 3,
        view: 7,
        parent: &[0x21; 32],
        digest: [0x33; 32],
    };
    let last_cert = sign_certificate(&left, &keys, 7, 4, last.digest);
    let beyond = FrameClaim {
        filter: &left.filter,
        frame: 4,
        view: 8,
        parent: &last.digest,
        digest: [0x77; 32],
    };
    let beyond_cert = sign_certificate(&left, &keys, 8, 7, beyond.digest);
    assert!(verify(&state, &beyond, &beyond_cert).unwrap().is_some());
    assert!(!apply_submission(&state, 3, &seal).unwrap());
    commit(&state, 3);
    let committed = CommittedView::capture(state.crdt()).unwrap();
    assert!(matches!(
        status(&committed, &left.id().unwrap()).unwrap(),
        Status::Sealing(_)
    ));
    assert!(verify(&committed, &first, &first_cert).unwrap().is_some());
    assert!(verify(&committed, &last, &last_cert).unwrap().is_some());
    assert!(verify(&committed, &beyond, &beyond_cert).is_err());
    let conflict = FrameClaim {
        digest: [0x99; 32],
        ..last
    };
    let conflict_cert = sign_certificate(&left, &keys, 7, 4, conflict.digest);
    assert!(verify(&committed, &conflict, &conflict_cert).is_err());
    let late_view = FrameClaim {
        frame: 2,
        view: 8,
        ..conflict
    };
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
    let claim = FrameClaim {
        filter: &legacy.filter,
        frame: 1,
        view: 2,
        parent: &legacy.genesis,
        digest: [0x55; 32],
    };
    assert!(
        verify(&state, &claim, &certificate).unwrap().is_none(),
        "unmanaged application uses legacy verifier"
    );
    assert!(
        initialize(&state, 1, &legacy).is_err(),
        "generation zero only through the legacy migration"
    );
    let tip = super::legacy::LegacyTip {
        checkpoint: Checkpoint {
            frame: 0,
            view: 0,
            digest: legacy.genesis,
            state_roots: [[0; 32]; 4],
            history_root: [0; 32],
        },
        anchor: 0,
    };
    super::legacy::record_tip(&state, 1, &legacy.filter, &tip).unwrap();
    assert_eq!(
        super::legacy::migrate(
            &state,
            8,
            &policy(),
            &[legacy.filter.clone()],
            &scan_of(&[(&legacy.filter, &keys)])
        )
        .unwrap(),
        1
    );
    commit(&state, 8);
    let committed = CommittedView::capture(state.crdt()).unwrap();
    assert!(verify(&committed, &claim, &certificate).unwrap().is_some());
    let mut child = legacy.clone();
    child.filter.extend_from_slice(&[0, 1, 0]);
    let child_cert = sign_certificate(&child, &keys, 2, 0, claim.digest);
    assert!(verify(
        &committed,
        &FrameClaim {
            filter: &child.filter,
            ..claim
        },
        &child_cert
    )
    .is_err());
    child.filter = vec![0x56; 32];
    let unrelated = sign_certificate(&child, &keys, 2, 0, claim.digest);
    assert!(verify(
        &committed,
        &FrameClaim {
            filter: &child.filter,
            ..claim
        },
        &unrelated
    )
    .unwrap()
    .is_none());
    // The marker is protocol state, not a process-local toggle.
    assert!(manages_application(&committed, &legacy.filter).unwrap());
    assert!(!manages_application(&committed, &child.filter).unwrap());
    write(
        &state,
        2,
        b"generation",
        &generation_key(&legacy.filter, 0).unwrap(),
        &[],
    )
    .unwrap();
    assert!(
        verify(&state, &claim, &certificate).is_err(),
        "damaged index cannot select legacy fallback"
    );
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

/// Archive state sync installs a GLOBAL tree in chunks, each its own
/// commit; a view between them mixed the state before the sync with part of
/// the archive's (a head whose session record was not in yet). The view is
/// withheld from the first chunk until the last one is in.
#[test]
fn committed_view_is_withheld_while_a_global_sync_installs_its_chunks() {
    use quil_types::store::KvDb as _;
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let batch = db.new_batch(false).unwrap();
    batch
        .set(
            &quil_store::encoding::global_materialized_cursor_key(),
            &7u64.to_be_bytes(),
        )
        .unwrap();
    batch.commit().unwrap();
    let crdt = state.crdt();
    assert_eq!(CommittedView::capture(crdt).unwrap().frame(), 7);

    let archive = Arc::new(HypergraphCrdt::new(
        Arc::new(quil_hypergraph::testing::MemStore::new()),
        Arc::new(StubProver),
    ));
    for byte in 1..=3u8 {
        let location = quil_hypergraph::Location {
            app_address: GLOBAL_INTRINSIC_ADDRESS,
            data_address: [byte; 32],
        };
        archive.add_vertex(&location, &[byte; 48]).unwrap();
    }
    archive.commit(1).unwrap();
    let (version, root) = archive
        .serve_forest_head(&GLOBAL_INTRINSIC_ADDRESS, 0)
        .unwrap();
    let reader = quil_hypergraph::testing::CrdtTreeReader {
        source: archive,
        shard_id: GLOBAL_INTRINSIC_ADDRESS.to_vec(),
        phase: 0,
    };
    let mut plan = crdt
        .prepare_phase_sync(
            &reader,
            version,
            &GLOBAL_INTRINSIC_ADDRESS,
            0,
            &[],
            Some(quil_forest::SubtreeSyncAnchor::AppRoot(root)),
        )
        .unwrap();
    assert_eq!(plan.remaining().len(), 3);
    while plan.remaining().len() > 1 {
        let byte = plan.remaining()[0].0[0];
        crdt.apply_sync_chunk(&mut plan, &[vec![byte; 48]]).unwrap();
        let error = CommittedView::capture(crdt)
            .err()
            .expect("no committed view between a sync's chunks");
        assert!(global_sync_in_progress(&error), "{error}");
    }
    let byte = plan.remaining()[0].0[0];
    crdt.apply_sync_chunk(&mut plan, &[vec![byte; 48]]).unwrap();
    assert_eq!(crdt.finish_phase_sync(&plan).unwrap(), root);
    assert_eq!(
        CommittedView::capture(crdt).unwrap().frame(),
        7,
        "the view returns once the last chunk is in"
    );
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

fn scan_of(
    assignments: &[(&[u8], &[FalconPrivateKey])],
) -> crate::prover_registry::CommittedProverScan {
    use quil_types::consensus::{ProverAllocationInfo, ProverStatus};
    let mut pubkeys = std::collections::HashMap::new();
    let mut allocations = Vec::new();
    for (filter, keys) in assignments {
        for key in keys.iter() {
            let public_key = key.public_key().as_ref().to_vec();
            let address = quil_crypto::poseidon::hash_bytes_to_32(&public_key)
                .unwrap()
                .to_vec();
            pubkeys.insert(address.clone(), public_key);
            allocations.push((
                address,
                ProverAllocationInfo {
                    status: ProverStatus::Active,
                    confirmation_filter: filter.to_vec(),
                    rejection_filter: vec![],
                    join_frame_number: 0,
                    leave_frame_number: 0,
                    pause_frame_number: 0,
                    resume_frame_number: 0,
                    kick_frame_number: 0,
                    join_confirm_frame_number: 0,
                    join_reject_frame_number: 0,
                    leave_confirm_frame_number: 0,
                    leave_reject_frame_number: 0,
                    last_active_frame_number: 0,
                    last_signed_frame_number: 0,
                    epoch: u64::MAX,
                    ring: 0,
                    vertex_address: vec![],
                },
            ));
        }
    }
    crate::prover_registry::CommittedProverScan::from_parts(pubkeys, allocations)
}

fn policy() -> quil_types::consensus::CommitteeHandoffPolicy {
    quil_types::consensus::CommitteeHandoffPolicy {
        activation_frame: 2,
        chain_id: [0x11; 32],
        legacy_history: quil_types::consensus::LegacyHistory::Migrate,
        membership_boundary_frame: u64::MAX,
        first_session_boundary_frame: u64::MAX,
    }
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
    assert_eq!(
        schedule::reconcile_membership(&state, 1, &policy(), &filters, &scan).unwrap(),
        0,
        "nothing is authorized before activation"
    );
    assert_eq!(
        schedule::reconcile_membership(&state, 2, &policy(), &filters, &scan).unwrap(),
        1
    );
    commit(&state, 2);
    let first = head(&state, &filter).unwrap().unwrap();
    assert_eq!(
        (first.generation, first.base_frame, first.members.clone()),
        (1, 0, members(&old))
    );
    assert!(origins(&state, &first.id().unwrap()).unwrap().is_empty());
    assert_eq!(
        schedule::reconcile_membership(&state, 3, &policy(), &filters, &scan).unwrap(),
        0,
        "an unchanged committee schedules nothing"
    );
    assert_eq!(
        schedule::reconcile_membership(&state, 3, &policy(), &filters, &scan_of(&[])).unwrap(),
        0,
        "an empty eligible set never replaces a committee"
    );

    let mut new = keys();
    new.push(old[0].clone());
    let changed = scan_of(&[(&filter, &new)]);
    assert_eq!(
        schedule::reconcile_membership(&state, 4, &policy(), &filters, &changed).unwrap(),
        1
    );
    commit(&state, 4);
    let Status::Sealing(request_id) = status(&state, &first.id().unwrap()).unwrap() else {
        panic!("source must be closing");
    };
    assert_eq!(
        schedule::closing_request(&state, &first).unwrap(),
        Some(request_id)
    );
    assert!(!schedule::seal_submitted(&state, &first).unwrap());
    assert_eq!(
        schedule::reconcile_membership(&state, 5, &policy(), &filters, &changed).unwrap(),
        0,
        "a closing source is not scheduled twice"
    );
    let request = request(&state, &request_id).unwrap().unwrap();
    let closing = submission(&request, 0, &old, 3);
    assert!(!submission_settled(&state, &closing).unwrap());
    assert!(apply_submission(&state, 6, &closing).unwrap());
    assert!(
        submission_settled(&state, &closing).unwrap(),
        "a recorded seal is settled"
    );
    commit(&state, 6);
    assert!(schedule::seal_submitted(&state, &first).unwrap());
    assert!(
        schedule::closing_request(&state, &first).is_err(),
        "a retired session has no parent"
    );
    let second = head(&state, &filter).unwrap().unwrap();
    assert_eq!(
        (second.generation, second.base_frame, second.members.clone()),
        (2, 3, members(&new))
    );
    assert_eq!(
        scheduled_frame(&state, &second.id().unwrap()).unwrap(),
        Some(4),
        "its committee was chosen at 4"
    );
    assert_eq!(
        scheduled_frame(&state, &first.id().unwrap()).unwrap(),
        None,
        "no request authorized a first session"
    );
    assert_eq!(
        schedule::reconcile_membership(&state, 7, &policy(), &filters, &changed).unwrap(),
        0
    );
}

/// From a release eligibility step's frame new sessions seat only
/// allocations whose recorded release is at least its minimum: one with an
/// older release or none recorded is not desired, and a shard left with no
/// such member keeps its current session.
#[test]
fn release_eligibility_seats_only_recorded_minimum_releases() {
    use crate::global_intrinsic::prover_release::{
        set_release_eligibility_for_thread, Release, ReleaseMinimum,
    };
    let directory = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(directory.path()).unwrap();
    let (_store, state) = make_state(&db);
    commit(&state, 1);
    let filter = vec![7u8; 32];
    let filters = vec![filter.clone()];
    let provers = keys();
    let address = |key: &FalconPrivateKey| {
        quil_crypto::poseidon::hash_bytes_to_32(key.public_key().as_ref())
            .unwrap()
            .to_vec()
    };
    let minimum = Release {
        version: [2, 1, 0],
        patch: 25,
        subpatch: 90,
    };
    let older = Release {
        subpatch: 89,
        ..minimum
    };
    let recorded = |releases: &[Option<Release>]| {
        provers.iter().zip(releases).fold(
            scan_of(&[(&filter, &provers)]),
            |scan, (key, release)| match release {
                Some(release) => scan.with_release(&address(key), &filter, *release),
                None => scan,
            },
        )
    };
    let current = Some(minimum);
    // Two current, one older, one absent (its last confirm recorded none).
    let mixed = recorded(&[current, current, Some(older), None]);
    set_release_eligibility_for_thread(None).unwrap();
    assert_eq!(
        schedule::desired_members(&mixed, &filter, 10),
        members(&provers),
        "unset: the gate never applies"
    );
    set_release_eligibility_for_thread(Some(vec![ReleaseMinimum {
        from_frame: 10,
        minimum,
    }]))
    .unwrap();
    assert_eq!(
        schedule::desired_members(&mixed, &filter, 9),
        members(&provers),
        "not before its frame"
    );
    assert_eq!(
        schedule::desired_members(&mixed, &filter, 10),
        members(&provers[..2]),
        "an older or absent release is not seated"
    );
    assert!(
        schedule::desired_members(&recorded(&[None; 4]), &filter, 10).is_empty(),
        "absent fails closed"
    );
    assert_eq!(
        mixed.active_on_filter(&filter, 10).len(),
        4,
        "committee eligibility is unchanged"
    );

    assert_eq!(
        schedule::reconcile_membership(&state, 10, &policy(), &filters, &mixed).unwrap(),
        1
    );
    commit(&state, 10);
    let first = head(&state, &filter).unwrap().unwrap();
    assert_eq!(first.members, members(&provers[..2]));
    assert_eq!(
        schedule::reconcile_membership(&state, 11, &policy(), &filters, &recorded(&[None; 4]))
            .unwrap(),
        0,
        "no member left keeps the current session"
    );
    assert_eq!(head(&state, &filter).unwrap().unwrap(), first);
    assert_eq!(
        status(&state, &first.id().unwrap()).unwrap(),
        Status::Active
    );
    assert_eq!(
        schedule::reconcile_membership(&state, 12, &policy(), &filters, &recorded(&[current; 4]))
            .unwrap(),
        1,
        "members that record a current release are seated by the next session"
    );
    set_release_eligibility_for_thread(None).unwrap();
}

/// From the leaver currency frame the membership pass seats a leaving
/// allocation only if it was current when it left. One whose leave landed
/// epochs after its last re-confirm raised its committee's quorum beyond the
/// members that vote; it is no longer seated, and a session that seated it
/// gets a successor without it. A current leaver still serves its notice.
#[test]
fn the_membership_pass_seats_a_lapsed_leaver_only_before_the_leaver_currency_frame() {
    use crate::prover_registry::set_leaver_currency_frame_for_thread;
    use quil_types::consensus::ProverStatus;
    let epoch = quil_types::consensus::epoch_length_frames();
    let filter = vec![7u8; 32];
    let filters = vec![filter.clone()];
    let provers = keys();
    // Leaves proposed in epoch 5: the third prover re-confirmed for epoch 5,
    // the fourth last for epoch 2.
    let mut scan = scan_of(&[(&filter, &provers)]);
    for (index, recorded) in [(2, 5), (3, 2)] {
        let alloc = &mut scan.allocations[index].1;
        alloc.status = ProverStatus::Leaving;
        alloc.leave_frame_number = 5 * epoch + 10;
        alloc.epoch = recorded;
    }
    // The epoch's first frame, where successor committees are seated.
    let boundary = 6 * epoch;
    let seated = |activation: Option<u64>| -> (quil_store::RocksDb, HypergraphState, Vec<Vec<u8>>) {
        set_leaver_currency_frame_for_thread(activation);
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let (_, state) = make_state(&db);
        commit(&state, 1);
        assert_eq!(
            schedule::reconcile_membership(&state, boundary, &policy(), &filters, &scan).unwrap(),
            1
        );
        commit(&state, boundary);
        let members = head(&state, &filter).unwrap().unwrap().members;
        (db, state, members)
    };
    // Unset (assumes QUIL_LEAVER_CURRENCY_FRAME is unset): the old rule.
    let (_db, old, seated_old) = seated(None);
    assert_eq!(
        seated_old,
        members(&provers),
        "unset: every unexpired leaver is seated"
    );
    assert_eq!(
        seated(Some(boundary + 1)).2,
        members(&provers),
        "not before the frame"
    );
    assert_eq!(
        seated(Some(boundary)).2,
        members(&provers[..3]),
        "a lapsed leaver is not seated"
    );
    set_leaver_currency_frame_for_thread(None);
    assert_eq!(
        schedule::reconcile_membership(&old, boundary + 1, &policy(), &filters, &scan).unwrap(),
        0,
        "unset: the seated committee stands"
    );
    set_leaver_currency_frame_for_thread(Some(boundary));
    assert_eq!(
        schedule::desired_members(&scan, &filter, 7 * epoch - 1),
        members(&provers[..3]),
        "a current leaver serves its notice"
    );
    assert_eq!(
        schedule::reconcile_membership(&old, boundary + 1, &policy(), &filters, &scan).unwrap(),
        1,
        "a session that seated a lapsed leaver gets a successor without it"
    );
    set_leaver_currency_frame_for_thread(None);
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
        assert_eq!(
            schedule::reconcile_membership(
                &state,
                2,
                &policy,
                &filters,
                &scan_of(&[(&filter, &old)])
            )
            .unwrap(),
            1,
            "a first session is authorized at any pass"
        );
        commit(&state, 2);
        let mut new = keys();
        new.push(old[0].clone());
        let changed = scan_of(&[(&filter, &new)]);
        let mid = pass(epoch + epoch / 2);
        assert!(!schedule::first_pass_of_epoch(mid));
        assert_eq!(
            schedule::reconcile_membership(&state, mid, &policy, &filters, &changed).unwrap(),
            usize::from(mid_epoch_schedules)
        );
        if !mid_epoch_schedules {
            assert!(schedule::first_pass_of_epoch(2 * epoch));
            assert_eq!(
                schedule::reconcile_membership(&state, 2 * epoch, &policy, &filters, &changed)
                    .unwrap(),
                1,
                "the boundary pass replaces the committee"
            );
        }
    }
}

/// From `first_session_boundary_frame` a shard's first session is also
/// authorized only at the first pass of an epoch.
#[test]
fn first_sessions_wait_for_the_epoch_boundary() {
    let epoch = quil_types::consensus::epoch_length_frames();
    let policy = quil_types::consensus::CommitteeHandoffPolicy {
        first_session_boundary_frame: 0,
        ..policy()
    };
    let directory = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(directory.path()).unwrap();
    let (_store, state) = make_state(&db);
    commit(&state, 1);
    let filter = vec![7u8; 32];
    let filters = vec![filter.clone()];
    let scan = scan_of(&[(&filter, &keys())]);
    let mid = epoch + epoch / 2 - (epoch / 2) % schedule::SESSION_PASS_FRAMES;
    assert!(!schedule::first_pass_of_epoch(mid));
    assert_eq!(
        schedule::reconcile_membership(&state, mid, &policy, &filters, &scan).unwrap(),
        0
    );
    assert!(head(&state, &filter).unwrap().is_none());
    assert_eq!(
        schedule::reconcile_membership(&state, 2 * epoch, &policy, &filters, &scan).unwrap(),
        1,
        "the boundary pass authorizes the first session"
    );
}

/// A due change that only waits never builds the prover scan, which reads all
/// of GLOBAL's committed provers: a change is gated on every frame it is due,
/// and building the scan anyway made every such frame read 8.6 GB on mainnet.
/// It waits without one when its source closes for another request, and once
/// scheduled, until its request activates.
#[test]
fn a_waiting_topology_change_never_builds_the_prover_scan() {
    use quil_types::store::{PendingShardChange, ShardChangeKind};
    let directory = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(directory.path()).unwrap();
    let (_store, state) = make_state(&db);
    commit(&state, 1);
    let split = |app: [u8; 32]| PendingShardChange {
        kind: ShardChangeKind::Split,
        parent: app.to_vec(),
        children: [false, true]
            .into_iter()
            .map(|bit| quil_forest::encode_shard_bit_path(&app, &[bit]))
            .collect(),
        effective_epoch: 2,
        proposed_frame: 1,
    };
    let (closing, scheduled) = (split([9u8; 32]), split([10u8; 32]));
    let provers = keys();
    let scan = scan_of(&[(&closing.parent, &provers), (&scheduled.parent, &provers)]);
    schedule::reconcile_membership(
        &state,
        2,
        &policy(),
        &[closing.parent.clone(), scheduled.parent.clone()],
        &scan,
    )
    .unwrap();
    commit(&state, 2);
    let unused = || -> Result<&crate::prover_registry::CommittedProverScan> {
        panic!("a waiting change built the prover scan")
    };
    let gate = |frame, change: &PendingShardChange| {
        schedule::gate_topology_change_sized(
            &state,
            frame,
            &policy(),
            change,
            Some(&unused),
            true,
            &|_| 0,
        )
        .unwrap()
    };

    // The source closes for a membership change first.
    schedule(
        &state,
        3,
        vec![closing.parent.clone()],
        vec![desired(&closing.parent, &keys())],
    )
    .unwrap();
    // The other split is scheduled, with the scan.
    assert_eq!(
        schedule::gate_topology_change(&state, 3, &policy(), &scheduled, Some(&scan), true)
            .unwrap(),
        schedule::TopologyGate::Wait
    );
    commit(&state, 3);
    for frame in 4..7 {
        assert_eq!(gate(frame, &closing), schedule::TopologyGate::Wait);
        assert_eq!(gate(frame, &scheduled), schedule::TopologyGate::Wait);
    }
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
        kind: ShardChangeKind::Split,
        parent: parent.clone(),
        children: children.clone(),
        effective_epoch: 2,
        proposed_frame: 1,
    };
    let provers = keys();
    let scan = scan_of(&[(&parent, &provers)]);

    // No committee ever formed on the parent: nothing to seal.
    assert_eq!(
        schedule::gate_topology_change(&state, 2, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Apply
    );
    assert_eq!(
        schedule::gate_topology_change(&state, 1, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Apply,
        "legacy before activation"
    );

    schedule::reconcile_membership(&state, 2, &policy(), &[parent.clone()], &scan).unwrap();
    commit(&state, 2);
    let source = head(&state, &parent).unwrap().unwrap();
    assert_eq!(
        schedule::gate_topology_change(&state, 3, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Wait
    );
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
    assert_eq!(
        schedule::gate_topology_change(&state, 4, &policy(), &change, None, true).unwrap(),
        schedule::TopologyGate::Wait
    );
    // Waiting neither reschedules nor lets the children be claimed separately.
    assert_eq!(
        schedule::gate_topology_change(&state, 4, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Wait
    );
    let moved = scan_of(&[(&children[0], &provers[..2]), (&children[1], &provers[2..])]);
    assert_eq!(
        schedule::reconcile_membership(&state, 4, &policy(), &children, &moved).unwrap(),
        0,
        "reserved successors are not initialized as unrelated first sessions"
    );
    assert!(head(&state, &children[0]).unwrap().is_none());

    assert!(apply_submission(&state, 5, &submission(&request, 0, &provers, 4)).unwrap());
    commit(&state, 5);
    assert_eq!(
        schedule::gate_topology_change(&state, 6, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Apply
    );
    assert_eq!(
        schedule::gate_topology_change(&state, 6, &policy(), &change, None, true).unwrap(),
        schedule::TopologyGate::Apply
    );
    for (child, members) in children.iter().zip(&planned) {
        let session = head(&state, child).unwrap().unwrap();
        assert_eq!((session.generation, &session.members), (1, members));
        assert_eq!(
            origins(&state, &session.id().unwrap()).unwrap()[0].0,
            source
        );
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
        .iter()
        .map(|suffix| [app.as_slice(), suffix].concat())
        .collect();
    let deep = super::super::materialize::unified_tree_cutover_frame() + 10;
    let change = PendingShardChange {
        kind: ShardChangeKind::Split,
        parent: parent.clone(),
        children: children.clone(),
        effective_epoch: 2,
        proposed_frame: deep,
    };
    let registered =
        super::super::materialize::materialize_shard_split(&parent, &children, true).unwrap();
    assert!(
        registered.new_shards.len() > children.len(),
        "this split registers spine shards too"
    );
    let provers = keys();
    let scan = scan_of(&[(&parent, &provers)]);
    schedule::reconcile_membership(&state, deep, &policy(), &[parent.clone()], &scan).unwrap();
    commit(&state, deep);
    let source = head(&state, &parent).unwrap().unwrap();

    assert_eq!(
        schedule::gate_topology_change(&state, deep + 1, &policy(), &change, Some(&scan), true)
            .unwrap(),
        schedule::TopologyGate::Wait
    );
    commit(&state, deep + 1);
    let Status::Sealing(request_id) = status(&state, &source.id().unwrap()).unwrap() else {
        panic!("the parent must be closing");
    };
    let request = request(&state, &request_id).unwrap().unwrap();
    assert_eq!(request.targets.len(), registered.new_shards.len());
    let staffed: Vec<_> = request
        .targets
        .iter()
        .filter(|t| !t.committee.members.is_empty())
        .collect();
    assert_eq!(staffed.iter().map(|t| t.committee.filter.clone()).collect::<Vec<_>>(), {
        let mut leaves = children.clone(); leaves.sort(); leaves
    }, "exactly the leaves the allocations move to are staffed, spelled as the allocations spell them");
    assert_eq!(
        Request::decode(&request.encode().unwrap()).unwrap(),
        request
    );

    assert!(apply_submission(&state, deep + 2, &submission(&request, 0, &provers, 4)).unwrap());
    commit(&state, deep + 2);
    assert_eq!(
        schedule::gate_topology_change(&state, deep + 3, &policy(), &change, Some(&scan), true)
            .unwrap(),
        schedule::TopologyGate::Apply
    );
    let spine: Vec<_> = request
        .targets
        .iter()
        .filter(|t| t.committee.members.is_empty())
        .map(|t| t.committee.filter.clone())
        .collect();
    for leaf in &children {
        assert_eq!(head(&state, leaf).unwrap().unwrap().generation, 1);
    }
    for filter in &spine {
        assert!(
            head(&state, filter).unwrap().is_none(),
            "a range without provers gets no session"
        );
    }
    // Provers that later become eligible on a spine shard get an ordinary
    // first session: the range was authorized, not left reserved.
    let joined = scan_of(&[(&spine[0], &provers[..2])]);
    assert_eq!(
        schedule::reconcile_membership(&state, deep + 8, &policy(), &spine, &joined).unwrap(),
        1
    );
    assert_eq!(
        head(&state, &spine[0]).unwrap().unwrap().members,
        members(&provers[..2])
    );
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
    let sources: Vec<_> = children
        .iter()
        .map(|c| head(&state, c).unwrap().unwrap())
        .collect();
    assert!(
        schedule::activating_request(&state, &children[0])
            .unwrap()
            .is_none(),
        "a reconciled first session has no activating request"
    );

    // Bit-path children: proposed after the unified-tree cutover.
    let change = PendingShardChange {
        kind: ShardChangeKind::Merge,
        parent: parent.clone(),
        children: children.clone(),
        effective_epoch: 2,
        proposed_frame: super::super::materialize::unified_tree_cutover_frame() + 1,
    };
    assert_eq!(
        schedule::gate_topology_change(&state, 3, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Wait
    );
    commit(&state, 3);
    let Status::Sealing(request_id) = status(&state, &sources[0].id().unwrap()).unwrap() else {
        panic!("both sources must be closing");
    };
    assert!(
        matches!(status(&state, &sources[1].id().unwrap()).unwrap(), Status::Sealing(id) if id == request_id)
    );
    let request = request(&state, &request_id).unwrap().unwrap();
    assert_eq!(request.sources.len(), 2);
    let mut union: Vec<Vec<u8>> = provers
        .iter()
        .map(|k| k.public_key().as_ref().to_vec())
        .collect();
    union.sort();
    assert_eq!(request.targets.len(), 1);
    assert_eq!(request.targets[0].committee.members, union);
    assert_eq!(
        schedule::activating_request(&state, &parent)
            .unwrap()
            .unwrap()
            .id()
            .unwrap(),
        request_id,
        "the reserved target resolves to the request that will activate it"
    );

    // One seal is not enough; the second activates the union.
    assert!(!apply_submission(&state, 4, &submission(&request, 0, &provers[..3], 7)).unwrap());
    commit(&state, 4);
    assert_eq!(
        schedule::gate_topology_change(&state, 5, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Wait
    );
    assert!(apply_submission(&state, 5, &submission(&request, 1, &provers[3..], 9)).unwrap());
    commit(&state, 5);
    assert_eq!(
        schedule::gate_topology_change(&state, 6, &policy(), &change, Some(&scan), true).unwrap(),
        schedule::TopologyGate::Apply
    );
    let merged = head(&state, &parent).unwrap().unwrap();
    assert_eq!((merged.generation, &merged.members), (1, &union));
    assert_eq!(origins(&state, &merged.id().unwrap()).unwrap().len(), 2);
    let activating = schedule::activating_request(&state, &parent)
        .unwrap()
        .unwrap();
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
    assert_eq!(
        scan.active_on_filter(&filter, 1000).len(),
        1,
        "joining and retired allocations are not eligible"
    );
    assert_eq!(
        scan.all_on_filter(&filter).len(),
        3,
        "joining ones still move with the shard; the retired one stays"
    );
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
    schedule::reconcile_membership(
        &state,
        2,
        &policy(),
        &[parent.clone()],
        &scan_of(&[(&parent, &provers)]),
    )
    .unwrap();
    commit(&state, 2);
    let session = head(&state, &parent).unwrap().unwrap();

    let change = PendingShardChange {
        kind: ShardChangeKind::Split,
        parent: parent.clone(),
        children,
        effective_epoch: 2,
        proposed_frame: super::super::materialize::unified_tree_cutover_frame() + 1,
    };
    // Every prover has left the parent.
    let empty = scan_of(&[]);
    assert_eq!(
        schedule::gate_topology_change(&state, 3, &policy(), &change, Some(&empty), true).unwrap(),
        schedule::TopologyGate::Drop
    );
    commit(&state, 3);
    assert_eq!(
        status(&state, &session.id().unwrap()).unwrap(),
        Status::Active,
        "nothing was scheduled"
    );
    // A regular, without a scan, reads the recorded decision.
    assert_eq!(
        schedule::gate_topology_change(&state, 4, &policy(), &change, None, true).unwrap(),
        schedule::TopologyGate::Drop
    );
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
    let request = schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    let seal = submission(&request, 0, &keys, 6);
    let session = seal.seal.session;
    assert!(
        super::verify_submission(&state, 3, &seal).is_err(),
        "no source frame executed yet"
    );
    let mut tip = seal.seal.checkpoint.clone();
    tip.frame = 5;
    record_session_tip(&state, 3, &session, &tip).unwrap();
    assert!(
        super::apply_submission(&state, 3, &seal).is_err(),
        "the checkpoint frame itself is not executed"
    );
    tip.frame = 6;
    record_session_tip(&state, 3, &session, &tip).unwrap();
    tip.frame = 4;
    record_session_tip(&state, 3, &session, &tip).unwrap();
    assert_eq!(
        session_tip(&state, &session).unwrap().unwrap().frame,
        6,
        "the tip only rises"
    );
    assert!(super::apply_submission(&state, 3, &seal).unwrap());
}

/// GLOBAL records the frame of a tip advance only from the presence report
/// frame on: before it, and by default, the same steps stage the same writes
/// as a build without the record.
#[test]
fn tip_advance_frames_are_staged_only_from_the_presence_report_frame() {
    let keys = keys();
    let filter = vec![0x5d; 32];
    let first = initial(filter.clone(), &keys);
    let id = first.id().unwrap();
    let run = |activation: Option<u64>| {
        set_presence_report_frame_for_thread(activation);
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let (_, state) = make_state(&db);
        initialize(&state, 1, &first).unwrap();
        schedule(
            &state,
            2,
            vec![filter.clone()],
            vec![desired(&filter, &keys)],
        )
        .unwrap();
        for frame in [5, 6, 6, 4] {
            record_session_tip(&state, 3, &id, &tip(frame, frame + 3, [frame as u8; 32])).unwrap();
        }
        let staged = state
            .pending_vertex_adds(&crate::global_schema::GLOBAL_INTRINSIC_ADDRESS)
            .unwrap();
        set_presence_report_frame_for_thread(None);
        staged
    };
    let default = run(None);
    assert_eq!(
        run(Some(4)),
        default,
        "below the activation frame nothing new is staged"
    );
    let active = run(Some(1));
    let record = address(b"tip-frame", &id);
    assert_eq!(
        active.iter().filter(|(at, _)| at[..] == record[..]).count(),
        3,
        "the creation and the two advances"
    );
    let rest: Vec<_> = active
        .into_iter()
        .filter(|(at, _)| at[..] != record[..])
        .collect();
    assert_eq!(rest, default, "the record is the only addition");
}

/// From the presence report frame on, a session records the GLOBAL frame that
/// created it, then each GLOBAL frame that advanced its tip; a tip at or below
/// the executed one is no advance. The successor a seal authorizes is anchored
/// at the activating frame.
#[test]
fn a_tip_advance_records_the_global_frame_that_executed_it() {
    set_presence_report_frame_for_thread(Some(0));
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let filter = vec![0x5e; 32];
    let first = initial(filter.clone(), &keys);
    let id = first.id().unwrap();
    initialize(&state, 1, &first).unwrap();
    assert_eq!(
        session_tip_frame(&state, &id).unwrap(),
        Some(1),
        "anchored at its creation"
    );
    let request = schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    let seal = submission(&request, 0, &keys, 6);
    assert_eq!(
        session_tip_frame(&state, &id).unwrap(),
        Some(1),
        "scheduling advances nothing"
    );
    record_session_tip(&state, 3, &id, &tip(5, 4, [0x55; 32])).unwrap();
    assert_eq!(session_tip_frame(&state, &id).unwrap(), Some(3));
    record_session_tip(&state, 4, &id, &tip(5, 4, [0x55; 32])).unwrap();
    record_session_tip(&state, 5, &id, &tip(4, 3, [0x44; 32])).unwrap();
    assert_eq!(
        session_tip_frame(&state, &id).unwrap(),
        Some(3),
        "an equal or lower tip is no advance"
    );
    assert_eq!(frames_since_tip_advance(&state, &id, 9).unwrap(), Some(6));
    commit(&state, 5);
    record_session_tip(&state, 6, &id, &seal.seal.checkpoint).unwrap();
    commit(&state, 6);
    let view = CommittedView::capture(state.crdt()).unwrap();
    assert_eq!(
        session_tip_frame(&view, &id).unwrap(),
        Some(6),
        "committed with the tip"
    );

    assert!(super::apply_submission(&state, 7, &seal).unwrap());
    let successor = head(&state, &filter).unwrap().unwrap().id().unwrap();
    assert_eq!(session_tip_frame(&state, &successor).unwrap(), Some(7));
    assert_eq!(
        session_tip_frame(&state, &id).unwrap(),
        Some(6),
        "the seal advances no tip"
    );
    set_presence_report_frame_for_thread(None);
}

/// A session created before the presence report frame has no record until
/// its tip advances. Until then the frames since the activation frame bound
/// how long it has not advanced; before that frame nothing is known.
#[test]
fn a_session_created_before_the_presence_report_frame_is_bounded_from_it() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let first = initial(vec![0x5f; 32], &keys());
    let id = first.id().unwrap();
    initialize(&state, 1, &first).unwrap();
    record_session_tip(&state, 3, &id, &tip(5, 8, [0x55; 32])).unwrap();
    commit(&state, 3);
    assert_eq!(
        frames_since_tip_advance(&state, &id, 9).unwrap(),
        None,
        "disabled by default"
    );
    set_presence_report_frame_for_thread(Some(10));
    assert_eq!(session_tip_frame(&state, &id).unwrap(), None);
    assert_eq!(
        frames_since_tip_advance(&state, &id, 9).unwrap(),
        None,
        "before the activation frame"
    );
    assert_eq!(frames_since_tip_advance(&state, &id, 10).unwrap(), Some(0));
    assert_eq!(
        frames_since_tip_advance(&state, &id, 14).unwrap(),
        Some(4),
        "a lower bound"
    );
    record_session_tip(&state, 15, &id, &tip(6, 9, [0x66; 32])).unwrap();
    assert_eq!(session_tip_frame(&state, &id).unwrap(), Some(15));
    assert_eq!(frames_since_tip_advance(&state, &id, 20).unwrap(), Some(5));
    assert_eq!(
        frames_since_tip_advance(&state, &id, 12).unwrap(),
        Some(0),
        "not after the advance"
    );
    set_presence_report_frame_for_thread(None);
}

/// A seal's drain headers trail the certificate submission: without them the
/// bytes are a [`CertificateSubmission`]'s, so older builds and GLOBAL's
/// records read them unchanged. Counts outside 1..=8 and trailing bytes are
/// refused.
#[test]
fn seal_submission_codec_keeps_plain_seals_byte_identical() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let filter = vec![0x5b; 32];
    initialize(&state, 1, &initial(filter.clone(), &keys)).unwrap();
    let request = schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    let plain = submission(&request, 0, &keys, 6);
    let bytes = |drain: Vec<Vec<u8>>| {
        SealSubmission {
            submission: plain.clone(),
            drain,
        }
        .to_canonical_bytes()
    };

    let without = bytes(Vec::new()).unwrap();
    assert_eq!(without, plain.to_canonical_bytes().unwrap());
    assert_eq!(
        SealSubmission::from_canonical_bytes(&without)
            .unwrap()
            .drain,
        Vec::<Vec<u8>>::new()
    );

    let drain = vec![vec![1u8; 40], Vec::new(), vec![3u8; 7]];
    let with = bytes(drain.clone()).unwrap();
    let decoded = SealSubmission::from_canonical_bytes(&with).unwrap();
    assert_eq!((decoded.submission, decoded.drain), (plain.clone(), drain));
    assert!(
        CertificateSubmission::from_canonical_bytes(&with).is_err(),
        "an older build refuses a drain"
    );

    let full = bytes(vec![vec![9u8; 4]; MAX_DRAIN_HEADERS]).unwrap();
    assert_eq!(
        SealSubmission::from_canonical_bytes(&full)
            .unwrap()
            .drain
            .len(),
        MAX_DRAIN_HEADERS
    );
    assert!(bytes(vec![vec![9u8; 4]; MAX_DRAIN_HEADERS + 1]).is_err());
    let mut over = without.clone();
    over.push((MAX_DRAIN_HEADERS + 1) as u8);
    over.extend(std::iter::repeat_n([0u8; 4], MAX_DRAIN_HEADERS + 1).flatten());
    assert!(SealSubmission::from_canonical_bytes(&over).is_err());
    let mut empty = without.clone();
    empty.push(0);
    assert!(
        SealSubmission::from_canonical_bytes(&empty).is_err(),
        "a zero count is not the plain encoding"
    );
    let mut trailing = with.clone();
    trailing.push(0);
    assert!(SealSubmission::from_canonical_bytes(&trailing).is_err());
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
    let request = schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    let seal = submission(&request, 0, &keys, 6);
    let session = seal.seal.session;
    let mut executed = seal.seal.checkpoint.clone();
    executed.frame = 7;
    record_session_tip(&state, 3, &session, &executed).unwrap();
    let below = super::verify_submission(&state, 3, &seal).unwrap_err();
    assert!(
        below
            .to_string()
            .contains("below the source's executed frames"),
        "{below}"
    );

    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    initialize(&state, 1, &initial(filter.clone(), &keys)).unwrap();
    let request = schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    let seal = submission(&request, 0, &keys, 6);
    let mut forked = seal.seal.checkpoint.clone();
    forked.digest[0] ^= 1;
    record_session_tip(&state, 3, &seal.seal.session, &forked).unwrap();
    let beside = super::verify_submission(&state, 3, &seal).unwrap_err();
    assert!(
        beside
            .to_string()
            .contains("differs from the source's executed frame"),
        "{beside}"
    );
    // Only the digest decides: the roots GLOBAL records are the header's.
    let mut same = seal.seal.checkpoint.clone();
    same.state_roots = [[0x71; 32]; 4];
    same.history_root = [0; 32];
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    initialize(&state, 1, &initial(filter.clone(), &keys)).unwrap();
    let request = schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    let seal = submission(&request, 0, &keys, 6);
    record_session_tip(&state, 3, &seal.seal.session, &same).unwrap();
    assert!(super::apply_submission(&state, 3, &seal).unwrap());
}

/// A seal notarized without a finalization is extended by a re-seal (the app
/// automaton's `with_seal_parents`): the same checkpoint frame, digest, roots
/// and history, at a later view, with `checkpoint.view` naming the notarized
/// seal's view. GLOBAL accepts its finalization as it does any seal's, and
/// authorizes the successor from the same frame.
#[test]
fn a_re_seal_of_a_notarized_seal_closes_the_source_at_the_same_frame() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let filter = vec![0x5d; 32];
    initialize(&state, 1, &initial(filter.clone(), &keys)).unwrap();
    let request = schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    let notarized = submission(&request, 0, &keys, 6).seal;
    let source = &request.sources[0];
    let reseal = Seal {
        view: 14,
        checkpoint: Checkpoint {
            view: notarized.view,
            ..notarized.checkpoint.clone()
        },
        ..notarized.clone()
    };
    // Certified as a child of the data frame instead of the seal: refused.
    let misbound = CertificateSubmission {
        seal: reseal.clone(),
        certificate: sign_certificate(
            source,
            &keys,
            reseal.view,
            notarized.checkpoint.view,
            reseal.digest(),
        ),
    };
    record_session_tip(&state, 3, &reseal.session, &notarized.checkpoint).unwrap();
    assert!(super::verify_submission(&state, 3, &misbound).is_err());
    let finalized = CertificateSubmission {
        seal: reseal.clone(),
        certificate: sign_certificate(source, &keys, reseal.view, notarized.view, reseal.digest()),
    };
    assert!(super::apply_submission(&state, 3, &finalized).unwrap());
    let successor = head(&state, &filter).unwrap().unwrap();
    assert_eq!((successor.generation, successor.base_frame), (2, 6));
    assert_eq!(
        closed_checkpoint(&state, &reseal.session).unwrap().unwrap(),
        reseal.checkpoint
    );
}

/// A re-seal's checkpoint names the notarized seal's view, not its data
/// frame's. That frame, the session tip GLOBAL executed, stays verifiable as
/// history (archives ingest its body after the seal); GLOBAL header execution
/// still refuses it, and nothing else at or past the checkpoint passes.
#[test]
fn a_re_sealed_checkpoint_keeps_its_data_frame_verifiable_as_history() {
    use super::frames::{verify, verify_history, FrameClaim};
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let filter = vec![0x5f; 32];
    initialize(&state, 1, &initial(filter.clone(), &keys)).unwrap();
    let request = schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    let source = &request.sources[0];
    let notarized = submission(&request, 0, &keys, 6).seal;
    let reseal = Seal {
        view: 14,
        checkpoint: Checkpoint {
            view: notarized.view,
            ..notarized.checkpoint.clone()
        },
        ..notarized.clone()
    };
    let data = notarized.checkpoint.clone();
    let tip = FrameClaim {
        filter: &filter,
        frame: data.frame,
        view: data.view,
        parent: &[0x21; 32],
        digest: data.digest,
    };
    let tip_cert = sign_certificate(source, &keys, tip.view, 4, tip.digest);
    let earlier = FrameClaim {
        frame: 5,
        view: 4,
        digest: [0x32; 32],
        ..tip
    };
    let earlier_cert = sign_certificate(source, &keys, 4, 3, earlier.digest);
    record_session_tip(&state, 3, &reseal.session, &data).unwrap();
    let finalized = CertificateSubmission {
        certificate: sign_certificate(source, &keys, reseal.view, notarized.view, reseal.digest()),
        seal: reseal,
    };
    assert!(super::apply_submission(&state, 3, &finalized).unwrap());
    commit(&state, 3);
    let committed = CommittedView::capture(state.crdt()).unwrap();

    assert!(verify_history(&committed, &tip, &tip_cert)
        .unwrap()
        .is_some());
    assert!(verify_history(&committed, &earlier, &earlier_cert)
        .unwrap()
        .is_some());
    let refused = verify(&committed, &tip, &tip_cert).err().unwrap();
    assert!(
        refused
            .to_string()
            .contains("outside the terminal checkpoint"),
        "{refused}"
    );
    assert!(verify(&committed, &earlier, &earlier_cert)
        .unwrap()
        .is_some());

    // Another frame at the checkpoint, the tip's digest at another view
    // below the seal's, and a frame past it.
    let forked = FrameClaim {
        digest: [0x34; 32],
        ..tip
    };
    let other_view = FrameClaim { view: 7, ..tip };
    let beyond = FrameClaim {
        frame: 7,
        view: 15,
        digest: [0x35; 32],
        ..tip
    };
    for claim in [forked, other_view, beyond] {
        let certificate = sign_certificate(source, &keys, claim.view, 4, claim.digest);
        let error = verify_history(&committed, &claim, &certificate)
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("outside the terminal checkpoint"),
            "{error}"
        );
    }
}

/// A session GLOBAL fenced at its base finalized frame 1 that GLOBAL never
/// executed. As history it is refused (past the terminal checkpoint); as the
/// attestation of the session's base state it is accepted. It is not while
/// the session is open, nor for a session that ended past its base, nor for
/// any later frame.
#[test]
fn the_first_frame_of_a_session_ended_at_its_base_attests_its_base_state() {
    use super::frames::{verify_discarded_base_frame, verify_history, FrameClaim};
    let keys = keys();
    let filter = vec![0x6c; 32];
    let first = initial(filter.clone(), &keys);
    let claim = FrameClaim {
        filter: &filter,
        frame: first.base_frame + 1,
        view: 1,
        parent: &first.genesis,
        digest: [0x51; 32],
    };
    let certificate = sign_certificate(&first, &keys, 1, 0, claim.digest);
    let second = FrameClaim {
        frame: first.base_frame + 2,
        view: 2,
        parent: &[0x52; 32],
        digest: [0x53; 32],
        ..claim
    };
    let second_certificate = sign_certificate(&first, &keys, 2, 1, second.digest);

    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    initialize(&state, 1, &first).unwrap();
    let open = verify_discarded_base_frame(&state, &claim, &certificate).unwrap_err();
    assert!(
        open.to_string().contains("did not end at its base"),
        "{open}"
    );
    schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    assert_eq!(
        schedule::fence_stalled_sources(&state, 2 + fence_timeout(), &[filter.clone()], None)
            .unwrap(),
        1
    );
    let refused = verify_history(&state, &claim, &certificate).err().unwrap();
    assert!(
        refused
            .to_string()
            .contains("outside the terminal checkpoint"),
        "{refused}"
    );
    assert_eq!(
        verify_discarded_base_frame(&state, &claim, &certificate).unwrap(),
        first
    );
    let later = verify_discarded_base_frame(&state, &second, &second_certificate).unwrap_err();
    assert!(
        later.to_string().contains("not the certified first frame"),
        "{later}"
    );

    // Sealed past its base at frame 4: frame 1 is executed history.
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    initialize(&state, 1, &first).unwrap();
    let request = schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    assert!(apply_submission(&state, 3, &submission(&request, 0, &keys, 4)).unwrap());
    assert!(verify_history(&state, &claim, &certificate)
        .unwrap()
        .is_some());
    let ran = verify_discarded_base_frame(&state, &claim, &certificate).unwrap_err();
    assert!(ran.to_string().contains("did not end at its base"), "{ran}");
}

/// A session asked to close before its first frame seals at its base; when
/// that seal is notarized but never finalized, its re-seal names the genesis
/// at the notarized seal's view. GLOBAL refuses it before the seal recovery
/// frame, as an older build does, and accepts it from that frame.
#[test]
fn a_re_seal_at_the_base_is_accepted_from_the_seal_recovery_frame() {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let filter = vec![0x5e; 32];
    initialize(&state, 1, &initial(filter.clone(), &keys)).unwrap();
    let request = schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    let source = &request.sources[0];
    let reseal = Seal {
        request: request.id().unwrap(),
        session: source.id().unwrap(),
        view: 7,
        checkpoint: Checkpoint {
            frame: source.base_frame,
            view: 3,
            digest: source.genesis,
            state_roots: [[0x40; 32]; 4],
            history_root: [0x44; 32],
        },
    };
    let submission = CertificateSubmission {
        certificate: sign_certificate(source, &keys, 7, 3, reseal.digest()),
        seal: reseal,
    };
    set_seal_recovery_frame_for_thread(Some(5));
    let before = super::verify_submission(&state, 4, &submission).unwrap_err();
    assert!(
        before
            .to_string()
            .contains("invalid source finalization certificate"),
        "{before}"
    );
    assert!(super::apply_submission(&state, 5, &submission).unwrap());
    set_seal_recovery_frame_for_thread(None);
    let successor = head(&state, &filter).unwrap().unwrap();
    assert_eq!((successor.generation, successor.base_frame), (2, 0));
}

/// Partial drains and base re-seals are GLOBAL consensus: mainnet starts at
/// a fixed epoch boundary whatever the environment says; other networks only
/// when set.
#[test]
fn seal_recovery_activates_at_the_mainnet_frame_or_the_testnet_setting() {
    assert_eq!(seal_recovery_frame_for(0, None), 875_520);
    assert_eq!(seal_recovery_frame_for(0, Some("7")), 875_520);
    assert_eq!(875_520 % quil_types::consensus::epoch_length_frames(), 0);
    assert_eq!(seal_recovery_frame_for(1, Some("7")), 7);
    assert_eq!(seal_recovery_frame_for(1, Some("soon")), u64::MAX);
    assert_eq!(seal_recovery_frame_for(1, None), u64::MAX);
}

/// Drains of frames certified only by their seal are GLOBAL consensus:
/// mainnet starts at a fixed epoch boundary whatever the environment says;
/// other networks only when set.
#[test]
fn seal_checkpoint_drains_activate_only_at_a_scheduled_frame() {
    assert_eq!(seal_checkpoint_drain_frame_for(0, None), 887_040);
    assert_eq!(seal_checkpoint_drain_frame_for(0, Some("7")), 887_040);
    assert_eq!(887_040 % quil_types::consensus::epoch_length_frames(), 0);
    assert_eq!(seal_checkpoint_drain_frame_for(1, Some("7")), 7);
    assert_eq!(seal_checkpoint_drain_frame_for(1, Some("soon")), u64::MAX);
    assert_eq!(seal_checkpoint_drain_frame_for(1, None), u64::MAX);
}

fn fence_timeout() -> u64 {
    schedule::FENCE_AFTER_EPOCHS * quil_types::consensus::epoch_length_frames()
}

fn tip(frame: u64, view: u64, digest: [u8; 32]) -> Checkpoint {
    Checkpoint {
        frame,
        view,
        digest,
        state_roots: [[0x61; 32]; 4],
        history_root: [0x62; 32],
    }
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
    let request = schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    let above = submission(&request, 0, &keys, first.base_frame + 1);
    assert!(
        super::verify_submission(&state, 3, &above).is_err(),
        "a seal above the base waits for its frames"
    );
    let mut at_base = submission(&request, 0, &keys, first.base_frame);
    at_base.seal.checkpoint.view = 0;
    at_base.seal.checkpoint.digest = first.genesis;
    at_base.certificate =
        sign_certificate(&first, &keys, at_base.seal.view, 0, at_base.seal.digest());
    assert!(super::apply_submission(&state, 3, &at_base).unwrap());
    assert_eq!(
        head(&state, &filter).unwrap().unwrap().generation,
        first.generation + 1
    );
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
    let request = schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    let id = first.id().unwrap();
    record_session_tip(&state, 3, &id, &tip(6, 9, [0x66; 32])).unwrap();
    commit(&state, 3);
    let beyond = FrameClaim {
        filter: &filter,
        frame: 7,
        view: 10,
        parent: &[0x66; 32],
        digest: [0x77; 32],
    };
    let beyond_cert = sign_certificate(&first, &keys, 10, 9, beyond.digest);
    assert!(
        verify(&state, &beyond, &beyond_cert).unwrap().is_some(),
        "still closing: not yet bounded"
    );

    let due = 2 + fence_timeout();
    assert_eq!(
        schedule::fence_stalled_sources(&state, due - 1, &[filter.clone()], None).unwrap(),
        0,
        "not before the timeout"
    );
    assert!(!is_fenced(&state, &id).unwrap());
    assert_eq!(
        schedule::fence_stalled_sources(&state, due, &[filter.clone()], None).unwrap(),
        1
    );
    commit(&state, due);
    assert!(is_fenced(&state, &id).unwrap());
    assert!(matches!(status(&state, &id).unwrap(), Status::Closed(_)));
    let fence = closed_checkpoint(&state, &id).unwrap().unwrap();
    assert_eq!((fence.frame, fence.view, fence.digest), (6, 9, [0x66; 32]));
    assert_eq!(
        (fence.state_roots, fence.history_root),
        ([[0; 32]; 4], [0; 32]),
        "nothing certifies the post-tip state"
    );
    let successor = head(&state, &filter).unwrap().unwrap();
    assert_eq!((successor.generation, successor.base_frame), (2, 6));
    assert!(schedule::activated(&state, &request.id().unwrap()).unwrap());
    assert!(
        verify(&state, &beyond, &beyond_cert).is_err(),
        "the fence bounds the session's frames"
    );
    let at_fence = FrameClaim {
        filter: &filter,
        frame: 6,
        view: 9,
        parent: &[0x55; 32],
        digest: [0x66; 32],
    };
    assert!(verify(
        &state,
        &at_fence,
        &sign_certificate(&first, &keys, 9, 8, at_fence.digest)
    )
    .unwrap()
    .is_some());

    // A seal arriving after the fence is refused, and fencing is idempotent.
    let late = submission(&request, 0, &keys, 6);
    record_session_tip(&state, due, &id, &late.seal.checkpoint).unwrap();
    assert!(super::apply_submission(&state, due + 1, &late).is_err());
    assert_eq!(
        schedule::fence_stalled_sources(&state, due + 8, &[filter.clone()], None).unwrap(),
        0
    );

    // The authorization commits to the fence, not to any seal of that checkpoint.
    let db2 = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, sealed_state) = make_state(&db2);
    initialize(&sealed_state, 1, &first).unwrap();
    let sealed_request = schedule(
        &sealed_state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    assert_eq!(sealed_request.id().unwrap(), request.id().unwrap());
    let mut seal = submission(&sealed_request, 0, &keys, 6);
    seal.seal.view = 12;
    seal.seal.checkpoint.view = 9;
    seal.seal.checkpoint.digest = [0x66; 32];
    seal.certificate = sign_certificate(&first, &keys, seal.seal.view, 9, seal.seal.digest());
    assert!(apply_submission(&sealed_state, 3, &seal).unwrap());
    assert_ne!(
        head(&sealed_state, &filter).unwrap().unwrap().authorization,
        successor.authorization
    );
}

/// A fence's membership successor takes its shard's eligible provers at the
/// fence, not the committee its request fixed four epochs earlier, so the
/// same pass's reconciliation leaves it running instead of asking it to close
/// at once (2026-10-16: one node's sixteen sessions, fenced again and again,
/// sat at view 1 below quorum). Before the activation frame, with nobody
/// eligible, or with the request's committee still eligible, the request's
/// committee stands.
#[test]
fn a_fenced_membership_successor_takes_the_eligible_committee() {
    let filter = vec![0x6d; 32];
    let filters = vec![filter.clone()];
    let (old, requested, eligible_now) = (keys(), keys(), keys());
    let due = 4 + fence_timeout();
    let fence = |activation: u64, eligible_at_fence: &[FalconPrivateKey]| {
        set_fenced_successor_eligibility_frame_for_thread(Some(activation));
        let directory = tempfile::tempdir().unwrap();
        let db = quil_store::RocksDb::open(directory.path()).unwrap();
        let (_store, state) = make_state(&db);
        commit(&state, 1);
        assert_eq!(
            schedule::reconcile_membership(
                &state,
                2,
                &policy(),
                &filters,
                &scan_of(&[(&filter, &old)])
            )
            .unwrap(),
            1
        );
        commit(&state, 2);
        assert_eq!(
            schedule::reconcile_membership(
                &state,
                4,
                &policy(),
                &filters,
                &scan_of(&[(&filter, &requested)])
            )
            .unwrap(),
            1
        );
        commit(&state, 4);
        let scan = scan_of(&[(&filter, eligible_at_fence)]);
        let mut eligible = |filter: &[u8]| -> Result<Vec<Vec<u8>>> {
            Ok(schedule::desired_members(&scan, filter, due))
        };
        assert_eq!(
            schedule::fence_stalled_sources(&state, due, &filters, Some(&mut eligible)).unwrap(),
            1
        );
        let rescheduled =
            schedule::reconcile_membership(&state, due, &policy(), &filters, &scan).unwrap();
        commit(&state, due);
        let successor = head(&state, &filter).unwrap().unwrap();
        assert_eq!(successor.generation, 2);
        let closing = matches!(
            status(&state, &successor.id().unwrap()).unwrap(),
            Status::Sealing(_)
        );
        (successor.members, closing, rescheduled)
    };
    assert_eq!(
        fence(u64::MAX, &eligible_now),
        (members(&requested), true, 1),
        "before activation: the request's committee, asked at once to close"
    );
    assert_eq!(
        fence(due, &eligible_now),
        (members(&eligible_now), false, 0)
    );
    assert_eq!(
        fence(due, &[]),
        (members(&requested), false, 0),
        "nobody eligible"
    );
    assert_eq!(
        fence(due, &requested),
        (members(&requested), false, 0),
        "still eligible"
    );
}

/// Fenced membership successors from current eligibility are GLOBAL
/// consensus: mainnet starts at a fixed epoch boundary whatever the
/// environment says; other networks only when set.
#[test]
fn fenced_successor_eligibility_activates_only_at_a_scheduled_frame() {
    assert_eq!(fenced_successor_eligibility_frame_for(0, None), 891_360);
    assert_eq!(
        fenced_successor_eligibility_frame_for(0, Some("7")),
        891_360
    );
    assert_eq!(891_360 % quil_types::consensus::epoch_length_frames(), 0);
    assert_eq!(fenced_successor_eligibility_frame_for(1, Some("7")), 7);
    assert_eq!(
        fenced_successor_eligibility_frame_for(1, Some("soon")),
        u64::MAX
    );
    assert_eq!(fenced_successor_eligibility_frame_for(1, None), u64::MAX);
}

/// From the seal successor eligibility frame a membership request's seal
/// leaves its successor to the next session pass, which seats the shard's
/// eligible provers then, not the committee the request fixed when it was
/// scheduled (2026-10-29: a successor seated at a seal eight hours after
/// its request had four of twelve members expired or rejected, one short of
/// quorum, and its shard halted until the fence). The pass authorizes it
/// once; a resubmitted seal changes nothing; a fence leaves the sealed
/// source alone. Before the frame the seal seats the request's committee at
/// once, as before; with nobody eligible, or with the request's committee
/// still eligible, the request's committee stands.
#[test]
fn a_sealed_membership_successor_takes_the_eligible_committee() {
    let filter = vec![0x6e; 32];
    let filters = vec![filter.clone()];
    let (old, requested, eligible_now) = (keys(), keys(), keys());
    let (sealed_at, pass) = (5, 8);
    let seal = |activation: u64, eligible_at_pass: &[FalconPrivateKey]| {
        set_seal_successor_eligibility_frame_for_thread(Some(activation));
        let directory = tempfile::tempdir().unwrap();
        let db = quil_store::RocksDb::open(directory.path()).unwrap();
        let (_store, state) = make_state(&db);
        commit(&state, 1);
        assert_eq!(
            schedule::reconcile_membership(
                &state,
                2,
                &policy(),
                &filters,
                &scan_of(&[(&filter, &old)])
            )
            .unwrap(),
            1
        );
        commit(&state, 2);
        assert_eq!(
            schedule::reconcile_membership(
                &state,
                4,
                &policy(),
                &filters,
                &scan_of(&[(&filter, &requested)])
            )
            .unwrap(),
            1
        );
        commit(&state, 4);
        let source = head(&state, &filter).unwrap().unwrap();
        let Status::Sealing(request_id) = status(&state, &source.id().unwrap()).unwrap() else {
            panic!("the source is closing");
        };
        let request = request(&state, &request_id).unwrap().unwrap();
        let submission = submission(&request, 0, &old, 6);
        let at_seal = apply_submission(&state, sealed_at, &submission).unwrap();
        commit(&state, sealed_at);
        let seated_at_seal = head(&state, &filter).unwrap().unwrap().generation == 2;
        // A resubmitted seal is accepted and changes nothing.
        assert!(!super::apply_submission(&state, sealed_at + 1, &submission).unwrap());
        assert_eq!(
            schedule::fence_stalled_sources(&state, 4 + fence_timeout(), &filters, None).unwrap(),
            0,
            "a sealed source is never fenced"
        );
        let scan = scan_of(&[(&filter, eligible_at_pass)]);
        let mut eligible = |filter: &[u8]| -> Result<Vec<Vec<u8>>> {
            Ok(schedule::desired_members(&scan, filter, pass))
        };
        let at_pass =
            schedule::activate_sealed_successors(&state, pass, &filters, &mut eligible).unwrap();
        assert_eq!(
            schedule::activate_sealed_successors(&state, pass + 8, &filters, &mut eligible)
                .unwrap(),
            0,
            "authorized once"
        );
        let rescheduled =
            schedule::reconcile_membership(&state, pass, &policy(), &filters, &scan).unwrap();
        commit(&state, pass);
        let successor = head(&state, &filter).unwrap().unwrap();
        assert_eq!(successor.generation, 2);
        assert!(schedule::activated(&state, &request_id).unwrap());
        let closing = matches!(
            status(&state, &successor.id().unwrap()).unwrap(),
            Status::Sealing(_)
        );
        set_seal_successor_eligibility_frame_for_thread(None);
        (
            (at_seal, seated_at_seal, at_pass),
            successor.members,
            closing,
            rescheduled,
        )
    };
    assert_eq!(
        seal(u64::MAX, &eligible_now),
        ((true, true, 0), members(&requested), true, 1),
        "before activation: the request's committee at the seal, asked at once to close"
    );
    assert_eq!(
        seal(sealed_at, &eligible_now),
        ((false, false, 1), members(&eligible_now), false, 0)
    );
    assert_eq!(
        seal(sealed_at, &[]),
        ((false, false, 1), members(&requested), false, 0),
        "nobody eligible"
    );
    assert_eq!(
        seal(sealed_at, &requested),
        ((false, false, 1), members(&requested), false, 0),
        "still eligible"
    );
}

/// Sealed membership successors from current eligibility are GLOBAL
/// consensus: not scheduled on mainnet, whatever the environment says;
/// other networks only when set.
#[test]
fn seal_successor_eligibility_is_not_scheduled_by_default() {
    assert_eq!(MAINNET_SEAL_SUCCESSOR_ELIGIBILITY_FRAME, None);
    assert_eq!(seal_successor_eligibility_frame_for(0, None), u64::MAX);
    assert_eq!(seal_successor_eligibility_frame_for(0, Some("7")), u64::MAX);
    assert_eq!(seal_successor_eligibility_frame_for(1, Some("7")), 7);
    assert_eq!(
        seal_successor_eligibility_frame_for(1, Some("soon")),
        u64::MAX
    );
    assert_eq!(seal_successor_eligibility_frame_for(1, None), u64::MAX);
}

/// From the early fence frame GLOBAL fences a closing session that has not
/// sealed two epochs after its request, and not before: not at one epoch,
/// where seals delayed by a slow GLOBAL still land (GLOBAL frame 907,920:
/// six app committees whose older-build members refused every closing seal
/// sat closing for the full four epochs). The request's frame selects the
/// rule: a request made before the frame keeps four epochs, even past it.
#[test]
fn an_unsealed_close_is_fenced_two_epochs_after_its_request_from_the_early_fence_frame() {
    let epoch = quil_types::consensus::epoch_length_frames();
    let fenced_after = |activation: Option<u64>, requested: u64| -> u64 {
        set_early_fence_frame_for_thread(activation);
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let (_, state) = make_state(&db);
        let keys = keys();
        let filter = vec![0x6e; 32];
        let first = initial(filter.clone(), &keys);
        initialize(&state, 1, &first).unwrap();
        schedule(
            &state,
            requested,
            vec![filter.clone()],
            vec![desired(&filter, &keys)],
        )
        .unwrap();
        let due = schedule::fence_due_frame(requested);
        for early in [requested + epoch - 1, requested + epoch, due - 1] {
            if early < due {
                assert_eq!(
                    schedule::fence_stalled_sources(&state, early, &[filter.clone()], None)
                        .unwrap(),
                    0,
                    "not at {early}, before {due}"
                );
            }
        }
        assert!(!is_fenced(&state, &first.id().unwrap()).unwrap());
        assert_eq!(
            schedule::fence_stalled_sources(&state, due, &[filter.clone()], None).unwrap(),
            1
        );
        assert!(is_fenced(&state, &first.id().unwrap()).unwrap());
        set_early_fence_frame_for_thread(None);
        due - requested
    };
    // Without a setting, never (assumes QUIL_EARLY_FENCE_FRAME is unset).
    assert_eq!(fenced_after(None, 2), 4 * epoch, "by default four epochs");
    assert_eq!(fenced_after(Some(0), 2), 2 * epoch);
    assert_eq!(
        fenced_after(Some(2), 2),
        2 * epoch,
        "a request at the frame"
    );
    assert_eq!(
        fenced_after(Some(3), 2),
        4 * epoch,
        "a request before the frame keeps four epochs"
    );
}

/// Early fences are GLOBAL consensus: mainnet starts them at a fixed epoch
/// boundary whatever the environment says; other networks only when set, so
/// by default every closing session there keeps the four-epoch timeout.
#[test]
fn early_fences_activate_only_at_a_scheduled_frame() {
    assert_eq!(MAINNET_EARLY_FENCE_FRAME, Some(984_240));
    assert_eq!(984_240 % quil_types::consensus::EPOCH_LENGTH_FRAMES, 0);
    assert_eq!(early_fence_frame_for(0, None), 984_240);
    assert_eq!(early_fence_frame_for(0, Some("7")), 984_240);
    assert_eq!(early_fence_frame_for(1, Some("7")), 7);
    assert_eq!(early_fence_frame_for(1, Some("soon")), u64::MAX);
    assert_eq!(early_fence_frame_for(1, None), u64::MAX);
    set_early_fence_frame_for_thread(None);
    assert_eq!(
        schedule::fence_after_epochs(u64::MAX - 1),
        schedule::FENCE_AFTER_EPOCHS
    );
    assert_eq!(schedule::fence_due_frame(2), 2 + fence_timeout());
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
    let request = schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    let due = 2 + fence_timeout();
    assert_eq!(
        schedule::fence_stalled_sources(&state, due - 1, &[filter.clone()], None).unwrap(),
        0,
        "not before the timeout"
    );
    assert_eq!(
        schedule::fence_stalled_sources(&state, due, &[filter.clone()], None).unwrap(),
        1,
        "a first session without a tip"
    );
    assert!(is_fenced(&state, &first.id().unwrap()).unwrap());
    let fence = closed_checkpoint(&state, &first.id().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        (fence.frame, fence.view, fence.digest),
        (first.base_frame, 0, first.genesis)
    );
    assert_eq!(
        (fence.state_roots, fence.history_root),
        ([[0; 32]; 4], [0; 32]),
        "nothing certifies its state"
    );
    assert!(schedule::activated(&state, &request.id().unwrap()).unwrap());
    let successor = head(&state, &filter).unwrap().unwrap();
    assert_eq!(
        (successor.generation, successor.base_frame),
        (first.generation + 1, first.base_frame)
    );
    assert_eq!(
        origins(&state, &successor.id().unwrap()).unwrap(),
        vec![(first.clone(), fence)]
    );

    // With a same-filter predecessor sealed at frame 4, a successor that then
    // stalls is fenced at its base with the predecessor's sealed roots.
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    initialize(&state, 1, &first).unwrap();
    let request = schedule(
        &state,
        2,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    assert!(apply_submission(&state, 3, &submission(&request, 0, &keys, 4)).unwrap());
    let second = head(&state, &filter).unwrap().unwrap();
    let second_request = schedule(
        &state,
        4,
        vec![filter.clone()],
        vec![desired(&filter, &keys)],
    )
    .unwrap();
    let later = 4 + fence_timeout();
    assert_eq!(
        schedule::fence_stalled_sources(&state, later, &[filter.clone()], None).unwrap(),
        1
    );
    let fence = closed_checkpoint(&state, &second.id().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        (fence.frame, fence.digest),
        (second.base_frame, second.genesis)
    );
    assert_eq!(
        fence.state_roots,
        [[0x40; 32], [0x41; 32], [0x42; 32], [0x43; 32]],
        "the predecessor's sealed roots"
    );
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
    let mut left_filter = root.clone();
    left_filter.extend_from_slice(&[0, 1, 0]);
    let mut right_filter = root.clone();
    right_filter.extend_from_slice(&[0, 1, 128]);
    let left = initial(left_filter.clone(), &keys);
    let right = initial(right_filter.clone(), &keys);
    initialize(&state, 1, &left).unwrap();
    initialize(&state, 1, &right).unwrap();
    let request = schedule(
        &state,
        2,
        vec![left_filter.clone(), right_filter.clone()],
        vec![desired(&root, &keys)],
    )
    .unwrap();
    let sealed_index = request
        .sources
        .iter()
        .position(|s| s.filter == left_filter)
        .unwrap();
    assert!(!apply_submission(&state, 3, &submission(&request, sealed_index, &keys, 5)).unwrap());
    record_session_tip(&state, 3, &right.id().unwrap(), &tip(8, 11, [0x88; 32])).unwrap();
    let filters = vec![left_filter.clone(), right_filter.clone()];
    // A merge's successor keeps the committee its request authorized.
    set_fenced_successor_eligibility_frame_for_thread(Some(0));
    let mut eligible =
        |_: &[u8]| -> Result<Vec<Vec<u8>>> { panic!("a merge's fence read eligibility") };
    assert_eq!(
        schedule::fence_stalled_sources(&state, 2 + fence_timeout(), &filters, Some(&mut eligible))
            .unwrap(),
        1,
        "only the unsealed source"
    );
    assert!(!is_fenced(&state, &left.id().unwrap()).unwrap());
    assert!(is_fenced(&state, &right.id().unwrap()).unwrap());
    assert!(schedule::activated(&state, &request.id().unwrap()).unwrap());
    assert_eq!(head(&state, &root).unwrap().unwrap().generation, 1);
}

#[path = "handoff_legacy_tests.rs"]
mod legacy_tests;

#[path = "handoff_presence_tests.rs"]
mod presence_tests;

#[path = "handoff_exclusion_tests.rs"]
mod exclusion_tests;

/// The pending-change repair rebuilds a split whose parent's committee
/// SEALED (not fenced) from its request, both while the parent seals and once
/// it closed; it leaves the request alone once a shard the split registers,
/// or one overlapping the parent, is in the grid; and it reports, rather than
/// rebuilds, a request it cannot rebuild unambiguously.
#[test]
fn the_repair_rebuilds_a_sealed_split_and_reports_what_it_cannot_rebuild() {
    use quil_types::store::{PendingShardChange, ShardChangeKind};
    use schedule::{recover_topology_change, Recovery, RecoveryFloor};
    let directory = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(directory.path()).unwrap();
    let (_store, state) = make_state(&db);
    let length = quil_types::consensus::epoch_length_frames();
    let start = (super::super::materialize::unified_tree_cutover_frame() / length + 10) * length;
    commit(&state, start - 1);
    let floor = RecoveryFloor {
        request_frame: 0,
        proposed_frame: 0,
    };
    let none = |_: &[u8]| false;
    let split = |app: u8, proposed: u64| {
        let app = [app; 32];
        PendingShardChange {
            kind: ShardChangeKind::Split,
            parent: quil_forest::encode_shard_bit_path(&app, &[true]),
            children: [false, true]
                .map(|bit| quil_forest::encode_shard_bit_path(&app, &[true, true, bit]))
                .to_vec(),
            effective_epoch: proposed / length + 2,
            proposed_frame: proposed,
        }
    };
    let provers = keys();
    // Three splits: staffed (four provers), one with a single prover (a child
    // without members), and one scheduled long after it came due.
    let staffed = split(0x21, start + 5);
    let single = split(0x22, start + 6);
    let late = split(0x23, start + 7);
    for (change, members) in [
        (&staffed, &provers[..]),
        (&single, &provers[..1]),
        (&late, &provers[..]),
    ] {
        let scan = scan_of(&[(&change.parent, members)]);
        schedule::reconcile_membership(&state, start, &policy(), &[change.parent.clone()], &scan)
            .unwrap();
    }
    commit(&state, start);
    let due = staffed.effective_epoch * length;
    let schedule_at = |change: &PendingShardChange, members: &[FalconPrivateKey], frame: u64| {
        let scan = scan_of(&[(&change.parent, members)]);
        assert_eq!(
            schedule::gate_topology_change(&state, frame, &policy(), change, Some(&scan), true)
                .unwrap(),
            schedule::TopologyGate::Wait
        );
        commit(&state, frame);
        let source = head(&state, &change.parent).unwrap().unwrap();
        let Status::Sealing(id) = status(&state, &source.id().unwrap()).unwrap() else {
            panic!("the parent must be closing");
        };
        (source, id)
    };
    let mut scheduled = vec![
        schedule_at(&staffed, &provers, due),
        schedule_at(&single, &provers[..1], due + 1),
    ];
    let in_grid = |change: &PendingShardChange| {
        let parent = change.parent.clone();
        move |filter: &[u8]| filter == parent.as_slice()
    };

    let (source, id) = &scheduled[0];
    assert_eq!(
        recover_topology_change(&state, id, floor, &in_grid(&staffed), &none).unwrap(),
        Recovery::Restore(staffed.clone()),
        "rebuilt while the parent seals"
    );
    let request = request(&state, id).unwrap().unwrap();
    assert!(apply_submission(&state, due + 2, &submission(&request, 0, &provers, 4)).unwrap());
    commit(&state, due + 2);
    assert_eq!(
        status(&state, &source.id().unwrap()).unwrap(),
        Status::Closed(*id)
    );
    assert!(
        !is_fenced(&state, &source.id().unwrap()).unwrap(),
        "sealed, not fenced"
    );
    assert_eq!(
        recover_topology_change(&state, id, floor, &in_grid(&staffed), &none).unwrap(),
        Recovery::Restore(staffed.clone()),
        "rebuilt once the seal closed the parent"
    );
    // A child in the grid beside the parent, or anything overlapping it: the
    // split applied here and something registered the parent again.
    let child = staffed.children[0].clone();
    let parent = staffed.parent.clone();
    assert_eq!(
        recover_topology_change(
            &state,
            id,
            floor,
            &|f: &[u8]| f == parent.as_slice() || f == child.as_slice(),
            &none
        )
        .unwrap(),
        Recovery::Applied("a shard the change registers is in the grid")
    );
    assert_eq!(
        recover_topology_change(&state, id, floor, &in_grid(&staffed), &|f: &[u8]| f
            == parent.as_slice())
        .unwrap(),
        Recovery::Applied("a shard overlapping a source is in the grid")
    );
    // Floors: a request before them is never rebuilt.
    let later = RecoveryFloor {
        request_frame: due + 1,
        proposed_frame: 0,
    };
    assert_eq!(
        recover_topology_change(&state, id, later, &in_grid(&staffed), &none).unwrap(),
        Recovery::Never
    );

    scheduled.push(schedule_at(&late, &provers, due + 20 * length));
    assert_eq!(
        recover_topology_change(&state, &scheduled[1].1, floor, &in_grid(&single), &none).unwrap(),
        Recovery::Unresolved("a split child may have received no members")
    );
    // The applied-here guards come first: a healthy store whose grid holds
    // the staffed child reports nothing.
    let staffed_child = single.children[0].clone();
    let single_parent = single.parent.clone();
    assert_eq!(
        recover_topology_change(
            &state,
            &scheduled[1].1,
            floor,
            &|f: &[u8]| f == single_parent.as_slice() || f == staffed_child.as_slice(),
            &none
        )
        .unwrap(),
        Recovery::Applied("a shard the change registers is in the grid")
    );
    assert_eq!(
        recover_topology_change(&state, &scheduled[2].1, floor, &in_grid(&late), &none).unwrap(),
        Recovery::Unresolved(
            "no topology record of the searched proposal frames names the request"
        )
    );
    assert_eq!(
        recover_topology_change(&state, &[0x5a; 32], floor, &in_grid(&staffed), &none).unwrap(),
        Recovery::Unresolved("the request record is absent")
    );
}

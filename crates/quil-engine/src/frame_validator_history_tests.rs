use super::*;
use crate::storage_history::{tests::Archive, GlobalVertexProofSource};
use quil_execution::global_intrinsic::{leaf_id_bytes, materialize};
use quil_types::proto::{
    global::{FrameHeader, StorageAttestation},
    keys::Bls48581AggregateSignature,
};
use quil_types::{
    consensus::{ProverInfo, ProverStatus},
    crypto::Signer as _,
};
use std::sync::atomic::{AtomicUsize, Ordering};

fn certify(frame: &mut AppShardFrame, signer: &quil_crypto::FalconSigner, global_output: &[u8]) {
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
    };
    let h = frame.header.as_mut().unwrap();
    let rho = quil_crypto::porep::derive_storage_beacon(h.global_frame_number, global_output);
    h.output = quil_crypto::porep::deterministic_app_frame_output(
        &h.parent_selector,
        &h.requests_root,
        &h.state_roots,
        &rho,
        h.frame_number,
        h.rank,
        &h.prover,
        h.difficulty,
        h.fee_multiplier_vote,
        h.timestamp,
        &h.storage_attestation_root,
        quil_execution::global_intrinsic::frame_header::fee_total_from_bytes(&h.fee_total),
        &h.settlements,
        &h.accumulator,
        &h.spends,
    );
    let key = FalconPrivateKey::from_bytes(signer.private_key(), signer.public_key()).unwrap();
    let participants: Set<_> = vec![key.public_key()].try_into().unwrap();
    let mut namespace = b"appshard".to_vec();
    namespace.extend_from_slice(&h.address);
    let scheme = Generic::<Namespace>::signer(&namespace, participants, key).unwrap();
    let proposal = Proposal::new(
        Round::new(Epoch::new(0), View::new(h.rank)),
        View::new(h.rank - 1),
        Digest(quil_crypto::poseidon::hash_bytes_to_32(&h.output).unwrap()),
    );
    let vote = scheme
        .sign::<SimplexFalconScheme, Digest>(Subject::Finalize {
            proposal: &proposal,
        })
        .unwrap();
    let certificate = scheme
        .assemble::<SimplexFalconScheme, _, N3f1>(vec![vote])
        .unwrap();
    h.public_key_signature_bls48581 = Some(Bls48581AggregateSignature {
        signature: wrap_cert_for_header(&encode_finalization(&Finalization {
            proposal,
            certificate,
        })),
        bitmask: vec![1],
        ..Default::default()
    });
}

#[tokio::test]
async fn certified_storage_frame_recovers_an_aged_out_registration_without_skipping_possession() {
    quil_crypto::init();
    let member = [7; 32];
    let filter = [8; 32];
    let leaf_id = leaf_id_bytes(&filter, &[]);
    let global_frame = quil_types::consensus::epoch_length_frames() * 11 + 3;
    let epoch = quil_types::consensus::epoch_for_frame(global_frame);
    let output = vec![9; 516];
    let rho = quil_crypto::porep::derive_storage_beacon(global_frame, &output);
    let poly = quil_types::consensus::STORAGE_BLOCK_POLY_SIZE;
    let (replica, leaf) = quil_crypto::sdr::build_leaf_replica(
        &vec![1; poly as usize * 32],
        &member,
        &leaf_id,
        epoch,
        poly,
        &Default::default(),
    );
    let openings: Vec<_> = (0..2)
        .map(|query| {
            quil_crypto::porep::build_storage_opening(
                &replica, &leaf, &leaf_id, epoch, &member, query, &rho, poly,
            )
        })
        .collect();
    let (attestation, attestation_root): (StorageAttestation, _) =
        quil_crypto::porep::build_frame_storage_attestation(&openings, 95, &rho, &[1], poly);
    let archive = Archive::new(&member, &leaf_id);
    let mut tree = materialize::create_leaf_root_vertex_tree(
        &member,
        &filter,
        &[],
        epoch,
        &leaf.root,
        1,
        global_frame - 1,
    )
    .unwrap();
    let root = archive.commit(&tree, global_frame - 1);
    for e in epoch + 1..=epoch + 4 {
        tree = materialize::upsert_leaf_root_registration(
            Some(&tree),
            &member,
            &filter,
            &[],
            e,
            &[e as u8; 74],
            1,
            global_frame + e,
        )
        .unwrap();
        archive.commit(&tree, global_frame + e);
    }
    assert!(materialize::leaf_root_registration_for_epoch(&tree, epoch).is_none());
    let proof = archive.proof(root);
    let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
    clock.seed_frame(GlobalFrame {
        header: Some(GlobalFrameHeader {
            frame_number: global_frame,
            output: output.clone(),
            prover_tree_commitment: root.to_vec(),
            ..Default::default()
        }),
        requests: vec![],
    });
    let signer = quil_crypto::FalconSigner::generate();
    let registry = Arc::new(crate::test_support::TestProverRegistry::with_prover(
        ProverInfo {
            public_key: signer.public_key().to_vec(),
            address: member.to_vec(),
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![quil_types::consensus::ProverAllocationInfo {
                status: ProverStatus::Active, confirmation_filter: filter.to_vec(),
                rejection_filter: vec![], join_frame_number: 1, leave_frame_number: 0,
                pause_frame_number: 0, resume_frame_number: 0, kick_frame_number: 0,
                join_confirm_frame_number: 0, join_reject_frame_number: 0,
                leave_confirm_frame_number: 0, leave_reject_frame_number: 0,
                last_active_frame_number: global_frame, epoch, ring: 0, vertex_address: vec![],
            }],
            available_storage: 0,
            seniority: 0,
            delegate_address: vec![],
        },
    ));
    let mut frame = AppShardFrame {
        header: Some(FrameHeader {
            address: filter.to_vec(),
            frame_number: 95,
            rank: 95,
            global_frame_number: global_frame,
            timestamp: 1,
            state_roots: vec![vec![0; 32]; 4],
            prover: member.to_vec(),
            storage_attestation_root: attestation_root,
            ..Default::default()
        }),
        requests: vec![],
        storage_attestation: Some(attestation),
    };
    certify(&mut frame, &signer, &output);
    let validator = || {
        BlsAppFrameValidator::new(
            registry.clone(),
            Arc::new(quil_crypto::FalconKeyConstructor),
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        )
        .with_clock_store(clock.clone())
    };
    // A local retained root works after the live epoch ring has rotated.
    assert!(validator()
        .with_handoff_authority(archive.crdt.clone())
        .validate(&frame)
        .unwrap());
    assert!(validator().validate(&frame).is_err());

    let calls = Arc::new(AtomicUsize::new(0));
    let source: GlobalVertexProofSource = {
        let calls = calls.clone();
        let address = archive.address;
        Arc::new(move |requested_root, requested_address| {
            assert_eq!(requested_root, root);
            assert_eq!(requested_address, address);
            calls.fetch_add(1, Ordering::SeqCst);
            let bytes = proof.clone();
            Box::pin(async move { Ok(Some(bytes)) })
        })
    };
    let remote = validator().with_storage_history_source(source.clone());
    assert!(matches!(
        remote.validate(&frame),
        Err(QuilError::ExecutionUnavailable(_))
    ));
    // Used as a notarized parent, the frame is excused a registration this
    // node does not hold: the notarizing quorum verified possession.
    assert!(remote.validate_notarized_parent(&frame).unwrap());
    let mut unsigned = frame.clone();
    unsigned
        .header
        .as_mut()
        .unwrap()
        .public_key_signature_bls48581 = None;
    assert!(remote.prepare_storage_history(&unsigned).await.is_err());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "authenticate before remote reads"
    );
    remote.prepare_storage_history(&frame).await.unwrap();
    assert!(remote.validate(&frame).unwrap());
    remote.prepare_storage_history(&frame).await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "two openings share one authenticated record"
    );
    let mut corrupt = frame.clone();
    corrupt.storage_attestation.as_mut().unwrap().openings[0].proof[0] ^= 1;
    assert!(
        remote.validate(&corrupt).is_err(),
        "a valid registry proof cannot replace possession"
    );
    assert!(remote.validate_notarized_parent(&corrupt).is_err(), "a failed possession proof is not excused");
    let mut wrong_epoch = frame.clone();
    wrong_epoch.storage_attestation.as_mut().unwrap().openings[0].epoch += 1;
    assert!(remote.validate(&wrong_epoch).is_err());
    // A cold validator has no volatile cache, so it must fetch again.
    // A newer same-epoch registration must not replace the anchored one.
    registry.register_leaf_root(&member, &leaf_id, vec![22; 74], 9, epoch);
    let restarted = validator().with_storage_history_source(source.clone());
    restarted.prepare_storage_history(&frame).await.unwrap();
    assert!(restarted.validate(&frame).unwrap());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let unavailable =
        validator().with_storage_history_source(Arc::new(|_, _| Box::pin(async { Ok(None) })));
    assert!(matches!(
        unavailable.prepare_storage_history(&frame).await,
        Err(QuilError::ExecutionUnavailable(_))
    ));
    assert!(unavailable.validate(&frame).is_err());
    // No archive retains the registration any longer: the certified frame is
    // accepted on its quorum certificate alone (sync anchors, certified
    // replays and a member's own head), and an uncertified copy is not.
    assert!(unavailable.validate_certified_without_storage(&frame).unwrap());
    // Without a committee-handoff policy a node may hold no GLOBAL cursor (a
    // regular, or one upgraded from the mainnet build). Nothing is managed
    // then, so the certificate verifies in the legacy namespace.
    assert!(quil_types::consensus::committee_handoff_policy().is_none());
    let uncursored_db = quil_store::RocksDb::open_in_memory().unwrap();
    let uncursored = validator().with_handoff_authority(Archive::open_crdt(&uncursored_db));
    assert!(uncursored.validate_certified_without_storage(&frame).unwrap());
    assert!(!unavailable.validate_certified_without_storage(&unsigned).unwrap_or(false));
    let mut altered = frame.clone();
    altered.header.as_mut().unwrap().state_roots[0][0] ^= 1;
    assert!(!unavailable.validate_certified_without_storage(&altered).unwrap_or(false),
        "the certificate still binds the header");
    // A frame final only through its certified child has no certificate of
    // its own: its registrations are fetched once the caller has
    // authenticated it through the child. (This fixture's openings are bound
    // to the certificate's signers, so the copy without one cannot then pass
    // possession; a real child-linked frame's can.)
    let linked_calls = calls.load(Ordering::SeqCst);
    let linked = validator().with_storage_history_source(source.clone());
    assert!(linked.prepare_storage_history(&unsigned).await.is_err());
    linked.prepare_storage_history_of_linked(&unsigned).await.unwrap();
    assert!(calls.load(Ordering::SeqCst) > linked_calls, "the registrations were fetched");
    assert!(unavailable.validate_linked_without_storage(&unsigned).unwrap());
    let mut malformed = unsigned.clone();
    malformed.header.as_mut().unwrap().state_roots.pop();
    assert!(linked.prepare_storage_history_of_linked(&malformed).await.is_err(), "structure is checked before any read");
    let untrusted = validator()
        .with_storage_history_source(Arc::new(|_, _| Box::pin(async { Ok(Some(vec![0; 8])) })));
    assert!(untrusted.prepare_storage_history(&frame).await.is_err());
    assert!(untrusted.validate(&frame).is_err());

    // A separate worker joined after this GLOBAL anchor and received only the
    // later live feed. Recover the older anchor from its own pinned master,
    // then run the same certificate and possession checks on the shard frame.
    use quil_types::store::ClockStore as _;
    let late_clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
    late_clock.seed_frame(GlobalFrame {
        header: Some(GlobalFrameHeader {
            frame_number: global_frame + 20,
            ..Default::default()
        }),
        requests: vec![],
    });
    let anchor = clock.get_global_clock_frame(global_frame).unwrap();
    let late = validator()
        .with_clock_store(late_clock.clone())
        .with_storage_history_source(source)
        .with_global_anchor_source(Arc::new(move |number| {
            assert_eq!(number, global_frame);
            let anchor = anchor.clone();
            Box::pin(async move { Ok(anchor) })
        }));
    assert!(late.validate(&frame).is_err());
    late.prepare_storage_history(&frame).await.unwrap();
    assert!(late.validate(&frame).unwrap());
    assert_eq!(
        late_clock
            .get_latest_global_clock_frame()
            .unwrap()
            .header
            .unwrap()
            .frame_number,
        global_frame + 20
    );
}

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

pub(crate) fn certify(
    frame: &mut AppShardFrame,
    signer: &quil_crypto::FalconSigner,
    global_output: &[u8],
) {
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

/// A certified storage-bearing frame whose registration aged out of the live
/// registry, and the archive state that still proves it.
struct AgedOutRegistration {
    member: [u8; 32],
    leaf_id: Vec<u8>,
    global_frame: u64,
    epoch: u64,
    archive: Archive,
    root: [u8; 32],
    proof: Vec<u8>,
    clock: Arc<quil_store::testing::InMemoryClockStore>,
    registry: Arc<crate::test_support::TestProverRegistry>,
    frame: AppShardFrame,
    signer: quil_crypto::FalconSigner,
    output: Vec<u8>,
}

fn aged_out_registration(requests_root: Vec<u8>) -> AgedOutRegistration {
    aged_out_registration_attested(requests_root, &[1])
}

/// [`aged_out_registration`] with the attestation bound to `bitmask`: the
/// certificate's (`[1]`), or none (`[]`) for a frame that will carry no
/// certificate of its own.
fn aged_out_registration_attested(requests_root: Vec<u8>, bitmask: &[u8]) -> AgedOutRegistration {
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
        quil_crypto::porep::build_frame_storage_attestation(&openings, 95, &rho, bitmask, poly);
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
                status: ProverStatus::Active,
                confirmation_filter: filter.to_vec(),
                rejection_filter: vec![],
                join_frame_number: 1,
                leave_frame_number: 0,
                pause_frame_number: 0,
                resume_frame_number: 0,
                kick_frame_number: 0,
                join_confirm_frame_number: 0,
                join_reject_frame_number: 0,
                leave_confirm_frame_number: 0,
                leave_reject_frame_number: 0,
                last_active_frame_number: global_frame,
                epoch,
                ring: 0,
                vertex_address: vec![],
                last_signed_frame_number: 0,
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
            requests_root,
            ..Default::default()
        }),
        requests: vec![],
        storage_attestation: Some(attestation),
    };
    certify(&mut frame, &signer, &output);
    AgedOutRegistration {
        member,
        leaf_id,
        global_frame,
        epoch,
        archive,
        root,
        proof,
        clock,
        registry,
        frame,
        signer,
        output,
    }
}

/// A proof source serving `proof` for `root`'s record, counting requests.
fn serving(
    root: [u8; 32],
    address: [u8; 32],
    proof: Vec<u8>,
    calls: Arc<AtomicUsize>,
) -> GlobalVertexProofSource {
    Arc::new(move |requested_root, requested_address| {
        assert_eq!(requested_root, root);
        assert_eq!(requested_address, address);
        calls.fetch_add(1, Ordering::SeqCst);
        let bytes = proof.clone();
        Box::pin(async move { Ok(Some(bytes)) })
    })
}

#[tokio::test]
async fn certified_storage_frame_recovers_an_aged_out_registration_without_skipping_possession() {
    let AgedOutRegistration {
        member,
        leaf_id,
        global_frame,
        epoch,
        archive,
        root,
        proof,
        clock,
        registry,
        frame,
        ..
    } = aged_out_registration(Vec::new());
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
    let source = serving(root, archive.address, proof, calls.clone());
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
    assert!(
        remote.validate_notarized_parent(&corrupt).is_err(),
        "a failed possession proof is not excused"
    );
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
    assert!(unavailable
        .validate_certified_without_storage(&frame)
        .unwrap());
    // Without a committee-handoff policy a node may hold no GLOBAL cursor (a
    // regular, or one upgraded from the mainnet build). Nothing is managed
    // then, so the certificate verifies in the legacy namespace.
    assert!(quil_types::consensus::committee_handoff_policy().is_none());
    let uncursored_db = quil_store::RocksDb::open_in_memory().unwrap();
    let uncursored = validator().with_handoff_authority(Archive::open_crdt(&uncursored_db));
    assert!(uncursored
        .validate_certified_without_storage(&frame)
        .unwrap());
    assert!(!unavailable
        .validate_certified_without_storage(&unsigned)
        .unwrap_or(false));
    let mut altered = frame.clone();
    altered.header.as_mut().unwrap().state_roots[0][0] ^= 1;
    assert!(
        !unavailable
            .validate_certified_without_storage(&altered)
            .unwrap_or(false),
        "the certificate still binds the header"
    );
    // A frame final only through its certified child has no certificate of
    // its own: its registrations are fetched once the caller has
    // authenticated it through the child. (This fixture's openings are bound
    // to the certificate's signers, so the copy without one cannot then pass
    // possession; a real child-linked frame's can.)
    let linked_calls = calls.load(Ordering::SeqCst);
    let linked = validator().with_storage_history_source(source.clone());
    assert!(linked.prepare_storage_history(&unsigned).await.is_err());
    // A sync anchor check prepares such a frame as the linked frame it is:
    // no "missing BLS signature" refusal reported as its storage history,
    // and no registration read before its child authenticates it.
    assert!(
        crate::app_engine::storage_history_unavailable(&linked, &unsigned)
            .await
            .is_none()
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        linked_calls,
        "nothing fetched for an unauthenticated frame"
    );
    // Controls: a certified frame still prepares its registrations, and one
    // whose registration no archive retains still reports why.
    let certified = validator().with_storage_history_source(source.clone());
    assert!(
        crate::app_engine::storage_history_unavailable(&certified, &frame)
            .await
            .is_none()
    );
    assert!(
        calls.load(Ordering::SeqCst) > linked_calls,
        "the certified frame's registrations were fetched"
    );
    assert!(matches!(
        crate::app_engine::storage_history_unavailable(&unavailable, &frame).await,
        Some(QuilError::ExecutionUnavailable(_))
    ));
    let linked_calls = calls.load(Ordering::SeqCst);
    linked
        .prepare_storage_history_of_linked(&unsigned)
        .await
        .unwrap();
    assert!(
        calls.load(Ordering::SeqCst) > linked_calls,
        "the registrations were fetched"
    );
    assert!(unavailable
        .validate_linked_without_storage(&unsigned)
        .unwrap());
    let mut malformed = unsigned.clone();
    malformed.header.as_mut().unwrap().state_roots.pop();
    assert!(
        linked
            .prepare_storage_history_of_linked(&malformed)
            .await
            .is_err(),
        "structure is checked before any read"
    );
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

/// An archive whose GLOBAL execution is behind an app frame's anchor holds
/// neither that anchor's root nor the registration in its live registry, so
/// its ingest refused the frame; GLOBAL execution waited on that frame, and
/// the archive sat at 869,765 for two days (2026-10-11). Its gap fetch now
/// prepares the registration from another archive into the validator the
/// ingest checks with.
#[tokio::test(flavor = "multi_thread")]
async fn an_archive_behind_a_frames_anchor_fetches_its_registration_and_ingests_it() {
    use quil_types::store::ClockStore as _;
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    let inclusion = Arc::new(quil_types::crypto::NoopInclusionProver);
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        store,
        inclusion.clone(),
    ));
    let crypto = quil_execution::testing::NoopExecutionCrypto::new();
    let manager = Arc::new(quil_execution::ExecutionEngineManager::new(
        inclusion.clone(),
        crypto.key_manager,
        crdt.clone(),
        crypto.circuit_compiler,
        crypto.clock_store.clone(),
        Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
        false,
    ));
    let filter = [8; 32];
    let requests_root = crate::app_engine::compute_requests_root(
        &[],
        &filter,
        95,
        Some(manager.as_ref()),
        Some(inclusion.as_ref()),
        crdt.has_forest(),
    )
    .unwrap();
    let aged = aged_out_registration(requests_root);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut ingest = crate::archive_ingest::ArchiveAppShardIngest::new(
        aged.registry.clone(),
        Arc::new(quil_crypto::FalconKeyConstructor),
        Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        manager,
        inclusion,
        crdt,
        aged.clock.clone(),
    )
    .with_storage_history_source(serving(
        aged.root,
        aged.archive.address,
        aged.proof.clone(),
        calls.clone(),
    ))
    .sequenced();
    let bytes = prost::Message::encode_to_vec(&aged.frame);
    let served = || aged.clock.get_shard_clock_frame(&filter, 95, false).ok();

    ingest.ingest(&bytes);
    assert_eq!(
        served(),
        None,
        "refused before its registration is prepared"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "ingest itself never waits on a peer"
    );
    ingest
        .validator()
        .prepare_storage_history(&aged.frame)
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    ingest.ingest(&bytes);
    assert_eq!(served(), Some(aged.frame.clone()));
}

/// A frame final only through its certified child carries no certificate of
/// its own. The gap fetch prepared certified frames only, so the ingest
/// refused such a frame on every retry and never asked for the child: an
/// archive sat at GLOBAL 870,123 for 20 hours (2026-10-12). The gap fetch now
/// fetches the child and prepares the frame once the child's certificate and
/// the link check out, and nothing before.
#[tokio::test(flavor = "multi_thread")]
async fn an_archive_gap_fetch_prepares_a_frame_final_through_its_certified_child() {
    use crate::archive_ingest::prepare_gap_fetched;
    use quil_types::store::ClockStore as _;
    let store = Arc::new(quil_hypergraph::testing::MemStore::new());
    let inclusion = Arc::new(quil_types::crypto::NoopInclusionProver);
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        store,
        inclusion.clone(),
    ));
    let crypto = quil_execution::testing::NoopExecutionCrypto::new();
    let manager = Arc::new(quil_execution::ExecutionEngineManager::new(
        inclusion.clone(),
        crypto.key_manager,
        crdt.clone(),
        crypto.circuit_compiler,
        crypto.clock_store.clone(),
        Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
        false,
    ));
    let filter = [8; 32];
    let requests_root = |number| {
        crate::app_engine::compute_requests_root(
            &[],
            &filter,
            number,
            Some(manager.as_ref()),
            Some(inclusion.as_ref()),
            crdt.has_forest(),
        )
        .unwrap()
    };
    let aged = aged_out_registration_attested(requests_root(95), &[]);
    let mut frame = aged.frame.clone();
    frame.header.as_mut().unwrap().public_key_signature_bls48581 = None;
    let child_signed_by = |signer: &quil_crypto::FalconSigner, parent: &AppShardFrame| {
        let mut child = AppShardFrame {
            header: Some(FrameHeader {
                address: filter.to_vec(),
                frame_number: 96,
                rank: 96,
                global_frame_number: aged.global_frame,
                timestamp: 2,
                state_roots: vec![vec![0; 32]; 4],
                prover: aged.member.to_vec(),
                parent_selector: quil_crypto::poseidon::hash_bytes_to_32(
                    &parent.header.as_ref().unwrap().output,
                )
                .unwrap()
                .to_vec(),
                requests_root: requests_root(96),
                ..Default::default()
            }),
            requests: vec![],
            storage_attestation: None,
        };
        certify(&mut child, signer, &aged.output);
        child
    };
    let child = child_signed_by(&aged.signer, &frame);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut ingest = crate::archive_ingest::ArchiveAppShardIngest::new(
        aged.registry.clone(),
        Arc::new(quil_crypto::FalconKeyConstructor),
        Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        manager.clone(),
        inclusion.clone(),
        crdt.clone(),
        aged.clock.clone(),
    )
    .with_storage_history_source(serving(
        aged.root,
        aged.archive.address,
        aged.proof.clone(),
        calls.clone(),
    ))
    .sequenced();
    let validator = ingest.validator();
    let served = |number| {
        aged.clock
            .get_shard_clock_frame(&filter, number, false)
            .ok()
    };
    let fetched = |offered: Option<AppShardFrame>| {
        move |number: u64| {
            let offered = offered.clone().filter(|frame| {
                frame
                    .header
                    .as_ref()
                    .is_some_and(|h| h.frame_number == number)
            });
            async move { offered }
        }
    };

    ingest.ingest(&prost::Message::encode_to_vec(&frame));
    assert_eq!(
        served(95),
        None,
        "refused before its registration is prepared"
    );

    // No child, a child that does not link, one without a certificate and
    // one certified by a stranger authenticate nothing: no peer is asked.
    let mut stranger_parent = frame.clone();
    stranger_parent.header.as_mut().unwrap().output[0] ^= 1;
    let mut uncertified = child.clone();
    uncertified
        .header
        .as_mut()
        .unwrap()
        .public_key_signature_bls48581 = None;
    for offered in [
        None,
        Some(child_signed_by(&aged.signer, &stranger_parent)),
        Some(uncertified),
        Some(child_signed_by(
            &quil_crypto::FalconSigner::generate(),
            &frame,
        )),
    ] {
        let (frames, prepared) =
            prepare_gap_fetched(&validator, frame.clone(), fetched(offered)).await;
        assert!(prepared.is_err());
        assert_eq!(frames[0], frame);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "authenticate before remote reads"
        );
    }

    let (frames, prepared) =
        prepare_gap_fetched(&validator, frame.clone(), fetched(Some(child.clone()))).await;
    prepared.unwrap();
    assert_eq!(frames, vec![frame.clone(), child.clone()]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    for delivered in &frames {
        ingest.ingest(&prost::Message::encode_to_vec(delivered));
    }
    assert_eq!(served(95), Some(frame.clone()));
    assert_eq!(served(96), Some(child.clone()));

    // A certified frame is prepared on its own, as before.
    let (frames, prepared) = prepare_gap_fetched(&validator, child.clone(), fetched(None)).await;
    prepared.unwrap();
    assert_eq!(frames, vec![child]);
}

/// The header a GLOBAL frame carries for an app frame holds its committee's
/// storage attestation (`app_handoff::canonical_header`). An archive that
/// materializes an empty frame from that header, its body unserved, rebuilds
/// the body its members stored: it passes full validation, possession
/// included, and is served. Rebuilt from a header without the attestation,
/// the frame is materialized on its certificate and output, not served, and
/// its body is owed.
#[tokio::test(flavor = "multi_thread")]
async fn an_archive_serves_an_empty_frame_it_rebuilt_whole_from_its_carried_header() {
    use quil_execution::global_intrinsic::{
        conversions::frame_header_to_proto, FrameHeader as CarriedHeader,
    };
    use quil_types::store::ClockStore as _;
    let aged = aged_out_registration_attested(vec![0; 32], &[]);
    // As a member stores a commonware-finalized frame.
    let mut body = aged.frame.clone();
    let signature = body
        .header
        .as_mut()
        .unwrap()
        .public_key_signature_bls48581
        .as_mut()
        .unwrap();
    signature.public_key = Some(quil_types::proto::keys::Bls48581g2PublicKey {
        key_value: Vec::new(),
    });
    signature.bitmask = Vec::new();
    let carried = frame_header_to_proto(
        &CarriedHeader::from_canonical_bytes(&crate::app_handoff::canonical_header(&body).unwrap())
            .unwrap(),
    );
    assert!(
        !carried.storage_attestation.is_empty(),
        "GLOBAL carries the attestation"
    );
    let filter = [8; 32];
    for attested in [true, false] {
        let mut header = carried.clone();
        if !attested {
            header.storage_attestation.clear();
        }
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        clock.seed_frame(
            aged.clock
                .get_global_clock_frame(aged.global_frame)
                .unwrap(),
        );
        let store = Arc::new(quil_hypergraph::testing::MemStore::new());
        let inclusion = Arc::new(quil_types::crypto::NoopInclusionProver);
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store,
            inclusion.clone(),
        ));
        let crypto = quil_execution::testing::NoopExecutionCrypto::new();
        let manager = Arc::new(quil_execution::ExecutionEngineManager::new(
            inclusion.clone(),
            crypto.key_manager,
            crdt.clone(),
            crypto.circuit_compiler,
            crypto.clock_store.clone(),
            Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
            false,
        ));
        let mut ingest = crate::archive_ingest::ArchiveAppShardIngest::new(
            aged.registry.clone(),
            Arc::new(quil_crypto::FalconKeyConstructor),
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            manager,
            inclusion,
            crdt,
            clock.clone(),
        )
        .with_storage_history_source(serving(
            aged.root,
            aged.archive.address,
            aged.proof.clone(),
            Arc::default(),
        ))
        .sequenced()
        .rebuilding_at_once_from(&filter, 94);
        ingest
            .validator()
            .prepare_storage_history(&body)
            .await
            .unwrap();
        let vouched = std::collections::HashMap::from([(95, header)]);
        assert!(
            !ingest
                .materialize_through_vouched(&filter, 95, &vouched)
                .unwrap(),
            "the body is sought first"
        );
        assert!(ingest
            .materialize_through_vouched(&filter, 95, &vouched)
            .unwrap());
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 95);
        let served = clock.get_shard_clock_frame(&filter, 95, false).ok();
        if attested {
            assert_eq!(
                served,
                Some(body.clone()),
                "the rebuilt body is the stored one"
            );
            assert!(!ingest.owes_body(&filter, 95));
        } else {
            assert_eq!(served, None);
            assert!(ingest.owes_body(&filter, 95));
        }
    }
}

/// A legacy certificate signed by a committee today's registry no longer
/// reproduces is rejected, and accepted once the committee rebuilt from
/// GLOBAL history is prepared; a rebuilt committee that did not sign it does
/// not help, and the source is asked once per anchor.
#[tokio::test]
async fn a_legacy_certificate_verifies_under_its_rebuilt_historical_committee() {
    quil_crypto::init();
    let filter = [8; 32];
    let global_frame = 4_000;
    let output = vec![9; 516];
    let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
    clock.seed_frame(GlobalFrame {
        header: Some(GlobalFrameHeader {
            frame_number: global_frame,
            output: output.clone(),
            ..Default::default()
        }),
        requests: vec![],
    });
    let prover = |signer: &quil_crypto::FalconSigner, address: u8| ProverInfo {
        public_key: signer.public_key().to_vec(),
        address: vec![address; 32],
        status: ProverStatus::Active,
        kick_frame_number: 0,
        allocations: vec![],
        available_storage: 0,
        seniority: 0,
        delegate_address: vec![],
    };
    let then = quil_crypto::FalconSigner::generate();
    let now = quil_crypto::FalconSigner::generate();
    // Today's registry: only a prover that joined later.
    let registry = Arc::new(crate::test_support::TestProverRegistry::with_prover(
        prover(&now, 2),
    ));
    let mut frame = AppShardFrame {
        header: Some(FrameHeader {
            address: filter.to_vec(),
            frame_number: 40,
            rank: 40,
            global_frame_number: global_frame,
            timestamp: 1,
            state_roots: vec![vec![0; 32]; 4],
            prover: vec![1; 32],
            ..Default::default()
        }),
        requests: vec![],
        storage_attestation: None,
    };
    certify(&mut frame, &then, &output);
    let validator = |source: Option<crate::historical_committee::HistoricalCommitteeSource>| {
        let validator = BlsAppFrameValidator::new(
            registry.clone(),
            Arc::new(quil_crypto::FalconKeyConstructor),
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        )
        .with_clock_store(clock.clone());
        match source {
            Some(source) => validator.with_historical_committee_source(source),
            None => validator,
        }
    };
    let plain = validator(None);
    plain.prepare_historical_committee(&frame).await.unwrap();
    assert!(
        plain.validate(&frame).is_err(),
        "today's registry cannot reproduce the committee"
    );

    let calls = Arc::new(AtomicUsize::new(0));
    let source_for =
        |members: Vec<Vec<u8>>| -> crate::historical_committee::HistoricalCommitteeSource {
            let calls = calls.clone();
            Arc::new(move |requested_filter, anchor| {
                assert_eq!(requested_filter, filter.to_vec());
                assert_eq!(anchor, global_frame);
                calls.fetch_add(1, Ordering::SeqCst);
                let members = members.clone();
                Box::pin(async move { Ok(vec![members]) })
            })
        };
    let wrong = validator(Some(source_for(vec![now.public_key().to_vec()])));
    wrong.prepare_historical_committee(&frame).await.unwrap();
    assert!(
        wrong.validate(&frame).is_err(),
        "a committee that did not sign does not verify it"
    );

    let rebuilt = validator(Some(source_for(vec![then.public_key().to_vec()])));
    rebuilt.prepare_historical_committee(&frame).await.unwrap();
    rebuilt.prepare_historical_committee(&frame).await.unwrap();
    assert!(rebuilt.validate(&frame).unwrap());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "once per validator and anchor"
    );
}

/// An empty frame rebuilt from the certified header GLOBAL carried, which
/// is all archives hold of some frames, has no storage attestation: archive
/// replay validates it on its certificate and output. Its body's possession
/// proof is still verified when present, and a frame with requests, without
/// a certificate or altered gets no exception.
#[test]
fn archive_replay_validates_a_certified_empty_frame_without_its_attestation() {
    let validator = |fixture: &AgedOutRegistration| {
        BlsAppFrameValidator::new(
            fixture.registry.clone(),
            Arc::new(quil_crypto::FalconKeyConstructor),
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        )
        .with_clock_store(fixture.clock.clone())
    };
    let validate = crate::app_engine::validate_certified_frame;
    let empty = aged_out_registration(vec![0; 32]);
    let rebuilt = AppShardFrame {
        storage_attestation: None,
        ..empty.frame.clone()
    };
    assert!(validate(&validator(&empty), &rebuilt, true).unwrap());
    assert!(
        validate(&validator(&empty), &empty.frame, true).is_err(),
        "the body's proof is verified: this registration aged out of the live registry"
    );
    let mut unsigned = rebuilt.clone();
    unsigned
        .header
        .as_mut()
        .unwrap()
        .public_key_signature_bls48581 = None;
    assert!(!validate(&validator(&empty), &unsigned, true).unwrap_or(false));
    let mut altered = rebuilt.clone();
    altered.header.as_mut().unwrap().state_roots[0][0] ^= 1;
    assert!(
        !validate(&validator(&empty), &altered, true).unwrap_or(false),
        "the certificate binds the header"
    );
    let mut bundled = rebuilt.clone();
    bundled.requests.push(Default::default());
    assert!(validate(&validator(&empty), &bundled, true).is_err());
    let with_requests = aged_out_registration(vec![7; 32]);
    let stripped = AppShardFrame {
        storage_attestation: None,
        ..with_requests.frame.clone()
    };
    assert!(validate(&validator(&with_requests), &stripped, true).is_err());
}

/// The header a GLOBAL frame carries for an app frame holds its committee's
/// storage attestation (`app_handoff::canonical_header`). An empty frame
/// rebuilt from it is the body its members stored, and passes full
/// validation, possession included; a corrupt attestation fails it. Without
/// the attestation (a member that held none submitted the header) the
/// possession proof cannot be verified, and archive replay validates the
/// frame on its certificate and output alone.
#[test]
fn an_empty_frame_rebuilt_from_its_carried_header_is_its_stored_body() {
    use crate::app_handoff::{canonical_header, frame_from_carried_header};
    use quil_execution::global_intrinsic::{
        conversions::frame_header_to_proto, FrameHeader as CarriedHeader,
    };
    let fixture = aged_out_registration_attested(vec![0; 32], &[]);
    // As a member stores a commonware-finalized frame.
    let mut body = fixture.frame.clone();
    let signature = body
        .header
        .as_mut()
        .unwrap()
        .public_key_signature_bls48581
        .as_mut()
        .unwrap();
    signature.public_key = Some(quil_types::proto::keys::Bls48581g2PublicKey {
        key_value: Vec::new(),
    });
    signature.bitmask = Vec::new();
    let validator = || {
        BlsAppFrameValidator::new(
            fixture.registry.clone(),
            Arc::new(quil_crypto::FalconKeyConstructor),
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        )
        .with_clock_store(fixture.clock.clone())
        .with_handoff_authority(fixture.archive.crdt.clone())
    };
    let replayed = |frame: &AppShardFrame| {
        crate::app_engine::validate_certified_frame(&validator(), frame, true)
    };
    let carried = |body: &AppShardFrame| {
        frame_header_to_proto(
            &CarriedHeader::from_canonical_bytes(&canonical_header(body).unwrap()).unwrap(),
        )
    };
    assert!(
        validator().validate(&body).unwrap(),
        "the stored body validates"
    );
    let header = carried(&body);
    assert!(
        !header.storage_attestation.is_empty(),
        "GLOBAL carries the attestation"
    );
    let (rebuilt, missing) = frame_from_carried_header(&header);
    assert_eq!(missing, None);
    assert_eq!(rebuilt, body);
    assert!(
        validator().validate(&rebuilt).unwrap(),
        "possession is verified"
    );
    assert!(replayed(&rebuilt).unwrap());

    let mut corrupt = body.clone();
    corrupt.storage_attestation.as_mut().unwrap().openings[0].proof[0] ^= 1;
    let (tampered, missing) = frame_from_carried_header(&carried(&corrupt));
    assert_eq!(missing, None);
    assert!(validator().validate(&tampered).is_err());
    assert!(
        replayed(&tampered).is_err(),
        "a carried attestation is verified"
    );

    let mut bare = header.clone();
    bare.storage_attestation.clear();
    let (stripped, missing) = frame_from_carried_header(&bare);
    assert!(missing.unwrap().contains("holds no storage attestation"));
    assert_eq!(stripped.storage_attestation, None);
    assert!(
        validator().validate(&stripped).is_err(),
        "no possession proof"
    );
    assert!(replayed(&stripped).unwrap(), "its certificate and output");

    let mut junk = header;
    junk.storage_attestation = vec![0xff; 3];
    let (undecoded, missing) = frame_from_carried_header(&junk);
    assert!(missing.unwrap().contains("does not decode"));
    assert_eq!(undecoded.storage_attestation, None);
}

/// Before a search keeps a copy of the header GLOBAL carried, it is
/// checked as archive replay checks a certified frame: certificate and
/// deterministic output, then an attestation it holds, in full. A copy with
/// another output is refused; one whose attestation does not decode or
/// fails possession keeps only its cleared form, as does one whose
/// registrations cannot be fetched; one whose anchored GLOBAL frame this
/// node lacks waits. The validator reports the missing frame as
/// unavailable, not as a refusal, so replay keeps the copy too.
#[tokio::test(flavor = "multi_thread")]
async fn a_carried_copy_is_checked_as_replay_checks_it_and_a_missing_anchor_is_a_wait() {
    use crate::prover_tree_syncer::{refuses_frame, verify_carried_copy, CopyVerdict};
    use quil_execution::global_intrinsic::{
        conversions::frame_header_to_proto, FrameHeader as CarriedHeader,
    };
    let fixture = aged_out_registration_attested(vec![0; 32], &[]);
    let mut body = fixture.frame.clone();
    let signature = body
        .header
        .as_mut()
        .unwrap()
        .public_key_signature_bls48581
        .as_mut()
        .unwrap();
    signature.public_key = Some(quil_types::proto::keys::Bls48581g2PublicKey {
        key_value: Vec::new(),
    });
    signature.bitmask = Vec::new();
    let carried = |body: &AppShardFrame| {
        frame_header_to_proto(
            &CarriedHeader::from_canonical_bytes(
                &crate::app_handoff::canonical_header(body).unwrap(),
            )
            .unwrap(),
        )
    };
    let header = carried(&body);
    let validator = |clock: Arc<quil_store::testing::InMemoryClockStore>| {
        Arc::new(
            BlsAppFrameValidator::new(
                fixture.registry.clone(),
                Arc::new(quil_crypto::FalconKeyConstructor),
                Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            )
            .with_clock_store(clock)
            .with_handoff_authority(fixture.archive.crdt.clone()),
        )
    };
    let verify = |header: &quil_types::proto::global::FrameHeader| {
        verify_carried_copy(validator(fixture.clock.clone()), header.clone())
    };
    assert_eq!(
        verify(&header).await,
        CopyVerdict::Certified,
        "possession included"
    );
    let cleared = quil_types::proto::global::FrameHeader {
        storage_attestation: Vec::new(),
        ..header.clone()
    };
    assert_eq!(verify(&cleared).await, CopyVerdict::Certified);
    let mut forged = header.clone();
    forged.output[0] ^= 1;
    assert_eq!(verify(&forged).await, CopyVerdict::Refused);
    let mut junk = header.clone();
    junk.storage_attestation = vec![0xff; 3];
    assert_eq!(
        verify(&junk).await,
        CopyVerdict::AttestationRefused,
        "does not decode"
    );
    let mut corrupt = body.clone();
    corrupt.storage_attestation.as_mut().unwrap().openings[0].proof[0] ^= 1;
    assert_eq!(
        verify(&carried(&corrupt)).await,
        CopyVerdict::AttestationRefused,
        "fails possession"
    );
    let unavailable = Arc::new(
        BlsAppFrameValidator::new(
            fixture.registry.clone(),
            Arc::new(quil_crypto::FalconKeyConstructor),
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        )
        .with_clock_store(fixture.clock.clone())
        .with_storage_history_source(Arc::new(|_, _| Box::pin(async { Ok(None) }))),
    );
    assert_eq!(
        verify_carried_copy(unavailable, header.clone()).await,
        CopyVerdict::AttestationUnavailable,
        "registrations unavailable"
    );

    let lacking = Arc::new(quil_store::testing::InMemoryClockStore::new());
    let (frame, _) = crate::app_handoff::frame_from_carried_header(&cleared);
    // The validator's other callers keep refusing a frame whose anchor this
    // node lacks; archive replay and its copies wait for it.
    let error = validator(lacking.clone())
        .validate_certified_without_storage(&frame)
        .unwrap_err();
    assert!(matches!(error, QuilError::Crypto(_)), "{error}");
    assert!(!refuses_frame(&error));
    let full = validator(lacking.clone()).validate(&body).unwrap_err();
    assert!(!refuses_frame(&full), "{full}");
    assert!(matches!(
        crate::app_engine::refusal_of(40, full),
        QuilError::ExecutionUnavailable(_)
    ));
    assert_eq!(
        verify_carried_copy(validator(lacking), header).await,
        CopyVerdict::Unavailable
    );
}

/// A certified frame refused while the committee that may have signed it
/// cannot be had waits only when it passes without its certificate as it
/// would be checked with it: with its storage history, possession
/// included, whether that history was had with the certificate or without
/// it. A frame whose possession proof fails is refused all the same; one
/// whose storage history cannot be had at all is checked without
/// possession, and waits.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_certificate_waits_only_when_possession_holds() {
    use crate::app_engine::Prepared;
    let fixture = aged_out_registration_attested(vec![0; 32], &[]);
    let body = fixture.frame.clone();
    let mut corrupt = body.clone();
    corrupt.storage_attestation.as_mut().unwrap().openings[0].proof[0] ^= 1;
    let validator = |handoff: bool, source: bool| {
        let validator = BlsAppFrameValidator::new(
            fixture.registry.clone(),
            Arc::new(quil_crypto::FalconKeyConstructor),
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        )
        .with_clock_store(fixture.clock.clone());
        let validator = match handoff {
            true => validator.with_handoff_authority(fixture.archive.crdt.clone()),
            false => validator,
        };
        match source {
            true => {
                validator.with_storage_history_source(Arc::new(|_, _| Box::pin(async { Ok(None) })))
            }
            false => validator,
        }
    };
    let unavailable = || QuilError::ExecutionUnavailable("no archive answered".into());
    let refused = || {
        Err(QuilError::InvalidSignature(
            "app shard frame certificate rejected".into(),
        ))
    };
    let judged = |validator: &BlsAppFrameValidator, prepared: &Prepared, frame: &AppShardFrame| {
        match prepared.judge(validator, frame, refused()) {
            Err(QuilError::ExecutionUnavailable(_)) => "waits",
            Err(error) if crate::prover_tree_syncer::refuses_frame(&error) => "refused",
            other => panic!("{other:?}"),
        }
    };
    let with_history = Prepared {
        committee: Some(unavailable()),
        ..Default::default()
    };
    let full = validator(true, false);
    assert_eq!(judged(&full, &with_history, &body), "waits");
    assert_eq!(
        judged(&full, &with_history, &corrupt),
        "refused",
        "possession is checked with its own history"
    );
    for (frame, expected) in [(&body, "waits"), (&corrupt, "refused")] {
        let mut prepared = Prepared {
            committee: Some(unavailable()),
            history: Some(unavailable()),
            ..Default::default()
        };
        prepared.prepare_without_certificate(&full, frame).await;
        assert!(prepared.possession);
        assert_eq!(
            judged(&full, &prepared, frame),
            expected,
            "and with the history had without its certificate"
        );
    }
    let lacking = validator(false, true);
    let mut prepared = Prepared {
        committee: Some(unavailable()),
        history: Some(unavailable()),
        ..Default::default()
    };
    prepared.prepare_without_certificate(&lacking, &body).await;
    assert!(!prepared.possession);
    assert_eq!(
        judged(&lacking, &prepared, &body),
        "waits",
        "no history at all: checked without possession"
    );
}

/// A shard GLOBAL manages through a session of generation 1, as GLOBAL's
/// committed view gives it.
fn managed_shard(filter: &[u8]) -> Arc<quil_hypergraph::HypergraphCrdt> {
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let global = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
        Arc::new(quil_hypergraph::testing::StubProver),
    ));
    global.set_forest(quil_forest::Forest::with_namespace(
        db.inner(),
        quil_store::FOREST_NAMESPACE,
    ));
    let state = quil_execution::hypergraph_state::HypergraphState::new(global.clone());
    let commit = |frame: u64| {
        state.commit().unwrap();
        state.abort();
        global
            .commit_with_global_cursor(
                frame,
                &quil_store::encoding::global_materialized_cursor_key(),
            )
            .unwrap();
    };
    let signer = quil_crypto::FalconSigner::generate();
    let session = quil_cw_consensus::handoff::Session {
        chain_id: [7; 32],
        filter: filter.to_vec(),
        generation: 1,
        genesis: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap(),
        base_frame: 0,
        authorization: [0; 32],
        members: vec![signer.public_key().to_vec()],
    };
    commit(1);
    quil_execution::global_intrinsic::handoff::initialize(&state, 2, &session).unwrap();
    commit(2);
    global
}

/// A copy wrapping a legacy (generation-0) certificate around the frame of
/// a shard GLOBAL manages is refused (for now: this node's view may lack a
/// session), never a wait on a historical committee, which could not decide
/// it: neither its check nor its replay asks for one, so a source that never
/// answers holds neither, and replay refuses the frame.
#[tokio::test(flavor = "multi_thread")]
async fn a_legacy_wrapper_on_a_managed_shard_is_refused_not_a_wait() {
    use crate::app_engine::{prepare_replayed_frame, validate_certified_frame};
    use crate::prover_tree_syncer::{refuses_frame, verify_carried_copy, CopyVerdict};
    let fixture = aged_out_registration_attested(vec![0; 32], &[]);
    let filter = fixture.frame.header.as_ref().unwrap().address.clone();
    let never: crate::historical_committee::HistoricalCommitteeSource =
        Arc::new(|_, _| Box::pin(std::future::pending()));
    let validator = Arc::new(
        BlsAppFrameValidator::new(
            fixture.registry.clone(),
            Arc::new(quil_crypto::FalconKeyConstructor),
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        )
        .with_clock_store(fixture.clock.clone())
        .with_handoff_authority(managed_shard(&filter))
        .with_historical_committee_source(never),
    );
    // A generation-0 certificate today's committee does not verify (another
    // frame's), wrapped around the genuine header.
    let mut header = fixture.frame.header.clone().unwrap();
    header.public_key_signature_bls48581 = legacy_committee_frame()
        .frame
        .header
        .unwrap()
        .public_key_signature_bls48581;
    assert!(!validator.legacy_committee_applies(&header));
    let within = std::time::Duration::from_secs(30);
    let verdict = tokio::time::timeout(
        within,
        verify_carried_copy(validator.clone(), header.clone()),
    )
    .await
    .expect("no historical committee is waited on");
    assert_eq!(verdict, CopyVerdict::CertificateRefused);
    let frame = AppShardFrame {
        header: Some(header),
        ..fixture.frame.clone()
    };
    let prepared = tokio::time::timeout(within, prepare_replayed_frame(&validator, &frame))
        .await
        .unwrap();
    assert!(prepared.committee.is_none(), "{:?}", prepared.committee);
    let judged = prepared.judge(
        &validator,
        &frame,
        validate_certified_frame(&validator, &frame, prepared.retained()),
    );
    assert!(
        match &judged {
            Ok(valid) => !valid,
            Err(error) => refuses_frame(error),
        },
        "{judged:?}"
    );
}

/// Archive replay, in the engine, waits on a legacy certificate's
/// historical committee at most `REPLAY_COMMITTEE_WAIT`: the reconstruction
/// goes on in its own task, and a frame needing the same committee
/// meanwhile starts no other.
#[tokio::test(start_paused = true)]
async fn replay_waits_briefly_on_a_committee_being_rebuilt() {
    use crate::app_engine::prepare_replayed_frame;
    let legacy = legacy_committee_frame();
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let never: crate::historical_committee::HistoricalCommitteeSource = Arc::new(move |_, _| {
        counted.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::pending())
    });
    let validator = (legacy.validator)(never);
    let first = prepare_replayed_frame(&validator, &legacy.frame).await;
    assert!(
        first
            .committee
            .as_ref()
            .is_some_and(|error| error.to_string().contains("not rebuilt within 20s")),
        "{:?}",
        first.committee
    );
    let second = prepare_replayed_frame(&validator, &legacy.frame).await;
    assert!(
        second
            .committee
            .as_ref()
            .is_some_and(|error| error.to_string().contains("not rebuilt within 20s")),
        "it waits on the reconstruction under way: {:?}",
        second.committee
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "one reconstruction");
}

/// A frame needing a committee another frame is rebuilding waits on that
/// reconstruction and takes its result, as it would its own: sync anchors
/// and engine starts are not refused because a carried copy or another
/// frame started it first.
#[tokio::test(start_paused = true)]
async fn frames_needing_one_committee_share_its_reconstruction() {
    use crate::app_engine::prepare_certified_frame;
    let legacy = legacy_committee_frame();
    let calls = Arc::new(AtomicUsize::new(0));
    let (counted, members) = (calls.clone(), legacy.members.clone());
    let slow: crate::historical_committee::HistoricalCommitteeSource = Arc::new(move |_, _| {
        counted.fetch_add(1, Ordering::SeqCst);
        let members = members.clone();
        Box::pin(async move {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            Ok(vec![members])
        })
    });
    let validator = (legacy.validator)(slow);
    let (first, second) = tokio::join!(
        prepare_certified_frame(&validator, &legacy.frame),
        prepare_certified_frame(&validator, &legacy.frame),
    );
    assert!(
        first.committee.is_none() && second.committee.is_none(),
        "{:?} {:?}",
        first.committee,
        second.committee
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// A copy with the genuine output under a junk legacy certificate and
/// another anchor (the output binds the anchor) is refused by its output,
/// before any historical committee is prepared for that anchor, in the
/// copy check and in replay alike.
#[tokio::test(flavor = "multi_thread")]
async fn a_copy_anchored_elsewhere_is_refused_before_any_committee_is_rebuilt() {
    use crate::app_engine::prepare_replayed_frame;
    use crate::prover_tree_syncer::{verify_carried_copy, CopyVerdict};
    let legacy = legacy_committee_frame();
    legacy.clock.seed_frame(GlobalFrame {
        header: Some(GlobalFrameHeader {
            frame_number: 4_001,
            output: vec![3; 516],
            ..Default::default()
        }),
        requests: vec![],
    });
    let calls = Arc::new(AtomicUsize::new(0));
    let (counted, members) = (calls.clone(), legacy.members.clone());
    let source: crate::historical_committee::HistoricalCommitteeSource = Arc::new(move |_, _| {
        counted.fetch_add(1, Ordering::SeqCst);
        let members = members.clone();
        Box::pin(async move { Ok(vec![members]) })
    });
    let validator = (legacy.validator)(source);
    let mut header = legacy.frame.header.clone().unwrap();
    header.global_frame_number = 4_001;
    assert_eq!(
        verify_carried_copy(validator.clone(), header.clone()).await,
        CopyVerdict::Refused
    );
    let frame = AppShardFrame {
        header: Some(header),
        ..legacy.frame.clone()
    };
    let prepared = prepare_replayed_frame(&validator, &frame).await;
    assert!(prepared.committee.is_none(), "{:?}", prepared.committee);
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no committee rebuilt");
}

/// A legacy-certified empty frame whose committee today's registry no
/// longer reproduces, with validators over that registry and a historical
/// committee source.
struct LegacyCommitteeFrame {
    frame: AppShardFrame,
    members: Vec<Vec<u8>>,
    clock: Arc<quil_store::testing::InMemoryClockStore>,
    validator: Box<
        dyn Fn(crate::historical_committee::HistoricalCommitteeSource) -> Arc<BlsAppFrameValidator>,
    >,
}

fn legacy_committee_frame() -> LegacyCommitteeFrame {
    quil_crypto::init();
    let filter = [8; 32];
    let global_frame = 4_000;
    let output = vec![9; 516];
    let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
    clock.seed_frame(GlobalFrame {
        header: Some(GlobalFrameHeader {
            frame_number: global_frame,
            output: output.clone(),
            ..Default::default()
        }),
        requests: vec![],
    });
    let prover = |signer: &quil_crypto::FalconSigner, address: u8| ProverInfo {
        public_key: signer.public_key().to_vec(),
        address: vec![address; 32],
        status: ProverStatus::Active,
        kick_frame_number: 0,
        allocations: vec![],
        available_storage: 0,
        seniority: 0,
        delegate_address: vec![],
    };
    let then = quil_crypto::FalconSigner::generate();
    let now = quil_crypto::FalconSigner::generate();
    let registry = Arc::new(crate::test_support::TestProverRegistry::with_prover(
        prover(&now, 2),
    ));
    let mut frame = AppShardFrame {
        header: Some(FrameHeader {
            address: filter.to_vec(),
            frame_number: 40,
            rank: 40,
            global_frame_number: global_frame,
            timestamp: 1,
            state_roots: vec![vec![0; 32]; 4],
            prover: vec![1; 32],
            requests_root: vec![0; 32],
            ..Default::default()
        }),
        requests: vec![],
        storage_attestation: None,
    };
    certify(&mut frame, &then, &output);
    LegacyCommitteeFrame {
        frame,
        members: vec![then.public_key().to_vec()],
        clock: clock.clone(),
        validator: Box::new(move |source| {
            Arc::new(
                BlsAppFrameValidator::new(
                    registry.clone(),
                    Arc::new(quil_crypto::FalconKeyConstructor),
                    Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
                )
                .with_clock_store(clock.clone())
                .with_historical_committee_source(source),
            )
        }),
    }
}

/// Historical committee sources answering `members`, and failing.
fn committee_sources(
    members: Vec<Vec<u8>>,
) -> [crate::historical_committee::HistoricalCommitteeSource; 2] {
    let rebuilt: crate::historical_committee::HistoricalCommitteeSource = Arc::new(move |_, _| {
        let members = members.clone();
        Box::pin(async move { Ok(vec![members]) })
    });
    let failing: crate::historical_committee::HistoricalCommitteeSource = Arc::new(|_, _| {
        Box::pin(async {
            Err(QuilError::ExecutionUnavailable(
                "no archive answered".into(),
            ))
        })
    });
    [rebuilt, failing]
}

/// A copy with a legacy certificate whose committee today's registry no
/// longer reproduces is checked after that committee is rebuilt from GLOBAL
/// history, as replay prepares it: it is certified, not refused for good.
/// When the committee cannot be had, the copy waits; one whose output is
/// forged is refused all the same. A certificate refused over a sound
/// output (here, no committee reconstructed) is refused only for a while:
/// this node's view, not the copy, may be at fault.
#[tokio::test(flavor = "multi_thread")]
async fn a_carried_copy_whose_committee_needs_history_is_certified() {
    use crate::prover_tree_syncer::{verify_carried_copy, CopyVerdict};
    let legacy = legacy_committee_frame();
    let header = legacy.frame.header.clone().unwrap();
    let [rebuilt, failing] = committee_sources(legacy.members.clone());
    assert_eq!(
        verify_carried_copy((legacy.validator)(rebuilt), header.clone()).await,
        CopyVerdict::Certified
    );
    assert_eq!(
        verify_carried_copy((legacy.validator)(failing), header.clone()).await,
        CopyVerdict::Unavailable,
        "a committee that cannot be had says nothing of the copy"
    );
    let [_, failing] = committee_sources(legacy.members.clone());
    let mut forged = header.clone();
    forged.output[0] ^= 1;
    assert_eq!(
        verify_carried_copy((legacy.validator)(failing), forged).await,
        CopyVerdict::Refused,
        "a forged output is refused whatever the committee"
    );
    // A committee rebuilt that does not verify it: refused for now.
    let other = vec![quil_crypto::FalconSigner::generate().public_key().to_vec()];
    let wrong: crate::historical_committee::HistoricalCommitteeSource = Arc::new(move |_, _| {
        let other = other.clone();
        Box::pin(async move { Ok(vec![other]) })
    });
    assert_eq!(
        verify_carried_copy((legacy.validator)(wrong), header.clone()).await,
        CopyVerdict::CertificateRefused
    );
    // None rebuilt is no answer: no committee kept, a wait, answered as a
    // failure for a while (in-actor callers do not repeat it at once), then
    // asked again.
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let none: crate::historical_committee::HistoricalCommitteeSource = Arc::new(move |_, _| {
        counted.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(Vec::new()) })
    });
    let validator = (legacy.validator)(none);
    for _ in 0..2 {
        assert_eq!(
            verify_carried_copy(validator.clone(), header.clone()).await,
            CopyVerdict::Unavailable
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the failure answers for a while"
    );
    assert!(validator
        .historical_committees
        .get(&header.address, legacy_committee_frame_of(&header))
        .is_none());
    validator.historical_committees.expire();
    assert_eq!(
        verify_carried_copy(validator.clone(), header.clone()).await,
        CopyVerdict::Unavailable
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2, "asked again after it");
}

/// At most two historical reconstructions run at a time, node-wide: forced
/// rebuilds at chosen anchors queue rather than pile up.
#[tokio::test(start_paused = true)]
async fn historical_reconstructions_run_two_at_a_time() {
    let legacy = legacy_committee_frame();
    let (running, most) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (counted, peak, members) = (running.clone(), most.clone(), legacy.members.clone());
    let source: crate::historical_committee::HistoricalCommitteeSource = Arc::new(move |_, _| {
        let (counted, peak, members) = (counted.clone(), peak.clone(), members.clone());
        Box::pin(async move {
            peak.fetch_max(counted.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            counted.fetch_sub(1, Ordering::SeqCst);
            Ok(vec![members])
        })
    });
    let validator = (legacy.validator)(source);
    let at = |anchor: u64| {
        let mut frame = legacy.frame.clone();
        frame.header.as_mut().unwrap().global_frame_number = anchor;
        frame
    };
    let (a, b, c) = (at(4_000), at(4_001), at(4_002));
    let (ra, rb, rc) = tokio::join!(
        validator.prepare_historical_committee(&a),
        validator.prepare_historical_committee(&b),
        validator.prepare_historical_committee(&c),
    );
    assert!(
        ra.is_ok() && rb.is_ok() && rc.is_ok(),
        "{ra:?} {rb:?} {rc:?}"
    );
    assert_eq!(most.load(Ordering::SeqCst), 2);
}

/// The anchor a legacy certificate's committee is rebuilt for.
fn legacy_committee_frame_of(header: &FrameHeader) -> u64 {
    super::legacy_committee_frame(header)
}

/// Archive replay applies the same rule: a legacy-certified frame whose
/// committee cannot be had waits rather than being refused, so the copy it
/// was rebuilt from is not passed over (`refuses_frame`); with the committee
/// rebuilt it validates.
#[tokio::test(flavor = "multi_thread")]
async fn replay_waits_on_a_frame_whose_committee_cannot_be_had() {
    use crate::app_engine::{prepare_certified_frame, validate_certified_frame};
    use crate::prover_tree_syncer::refuses_frame;
    let legacy = legacy_committee_frame();
    let [rebuilt, failing] = committee_sources(legacy.members.clone());
    let replayed = |validator: Arc<BlsAppFrameValidator>| {
        let frame = legacy.frame.clone();
        async move {
            let prepared = prepare_certified_frame(&validator, &frame).await;
            prepared.judge(
                &validator,
                &frame,
                validate_certified_frame(&validator, &frame, prepared.retained()),
            )
        }
    };
    assert!(replayed((legacy.validator)(rebuilt)).await.unwrap());
    let waits = replayed((legacy.validator)(failing)).await.unwrap_err();
    assert!(
        matches!(waits, QuilError::ExecutionUnavailable(_)) && !refuses_frame(&waits),
        "{waits}"
    );

    // Only a refused certificate waits on the committee: a frame whose
    // output is forged is refused while it cannot be had too.
    let [_, failing] = committee_sources(legacy.members.clone());
    let validator = (legacy.validator)(failing);
    let mut forged = legacy.frame.clone();
    forged.header.as_mut().unwrap().output[0] ^= 1;
    let prepared = prepare_certified_frame(&validator, &forged).await;
    let refused = prepared.judge(
        &validator,
        &forged,
        validate_certified_frame(&validator, &forged, prepared.retained()),
    );
    assert!(
        match &refused {
            Ok(valid) => !valid,
            Err(error) => refuses_frame(error),
        },
        "{refused:?}"
    );
}

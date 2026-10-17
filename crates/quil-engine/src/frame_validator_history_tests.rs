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
            requests_root,
            ..Default::default()
        }),
        requests: vec![],
        storage_attestation: Some(attestation),
    };
    certify(&mut frame, &signer, &output);
    AgedOutRegistration { member, leaf_id, global_frame, epoch, archive, root, proof, clock, registry, frame, signer, output }
}

/// A proof source serving `proof` for `root`'s record, counting requests.
fn serving(root: [u8; 32], address: [u8; 32], proof: Vec<u8>, calls: Arc<AtomicUsize>) -> GlobalVertexProofSource {
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
    let AgedOutRegistration { member, leaf_id, global_frame, epoch, archive, root, proof, clock, registry, frame, .. } =
        aged_out_registration(Vec::new());
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
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store, inclusion.clone()));
    let crypto = quil_execution::testing::NoopExecutionCrypto::new();
    let manager = Arc::new(quil_execution::ExecutionEngineManager::new(
        inclusion.clone(), crypto.key_manager, crdt.clone(), crypto.circuit_compiler,
        crypto.clock_store.clone(), Arc::new(quil_execution::testing::NoopHypergraphConfigResolver), false,
    ));
    let filter = [8; 32];
    let requests_root = crate::app_engine::compute_requests_root(
        &[], &filter, 95, Some(manager.as_ref()), Some(inclusion.as_ref()), crdt.has_forest(),
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
    .with_storage_history_source(serving(aged.root, aged.archive.address, aged.proof.clone(), calls.clone()))
    .sequenced();
    let bytes = prost::Message::encode_to_vec(&aged.frame);
    let served = || aged.clock.get_shard_clock_frame(&filter, 95, false).ok();

    ingest.ingest(&bytes);
    assert_eq!(served(), None, "refused before its registration is prepared");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "ingest itself never waits on a peer");
    ingest.validator().prepare_storage_history(&aged.frame).await.unwrap();
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
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store, inclusion.clone()));
    let crypto = quil_execution::testing::NoopExecutionCrypto::new();
    let manager = Arc::new(quil_execution::ExecutionEngineManager::new(
        inclusion.clone(), crypto.key_manager, crdt.clone(), crypto.circuit_compiler,
        crypto.clock_store.clone(), Arc::new(quil_execution::testing::NoopHypergraphConfigResolver), false,
    ));
    let filter = [8; 32];
    let requests_root = |number| crate::app_engine::compute_requests_root(
        &[], &filter, number, Some(manager.as_ref()), Some(inclusion.as_ref()), crdt.has_forest(),
    )
    .unwrap();
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
                parent_selector: quil_crypto::poseidon::hash_bytes_to_32(&parent.header.as_ref().unwrap().output).unwrap().to_vec(),
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
    .with_storage_history_source(serving(aged.root, aged.archive.address, aged.proof.clone(), calls.clone()))
    .sequenced();
    let validator = ingest.validator();
    let served = |number| aged.clock.get_shard_clock_frame(&filter, number, false).ok();
    let fetched = |offered: Option<AppShardFrame>| move |number: u64| {
        let offered = offered.clone().filter(|frame| frame.header.as_ref().is_some_and(|h| h.frame_number == number));
        async move { offered }
    };

    ingest.ingest(&prost::Message::encode_to_vec(&frame));
    assert_eq!(served(95), None, "refused before its registration is prepared");

    // No child, a child that does not link, one without a certificate and
    // one certified by a stranger authenticate nothing: no peer is asked.
    let mut stranger_parent = frame.clone();
    stranger_parent.header.as_mut().unwrap().output[0] ^= 1;
    let mut uncertified = child.clone();
    uncertified.header.as_mut().unwrap().public_key_signature_bls48581 = None;
    for offered in [
        None,
        Some(child_signed_by(&aged.signer, &stranger_parent)),
        Some(uncertified),
        Some(child_signed_by(&quil_crypto::FalconSigner::generate(), &frame)),
    ] {
        let (frames, prepared) = prepare_gap_fetched(&validator, frame.clone(), fetched(offered)).await;
        assert!(prepared.is_err());
        assert_eq!(frames[0], frame);
        assert_eq!(calls.load(Ordering::SeqCst), 0, "authenticate before remote reads");
    }

    let (frames, prepared) = prepare_gap_fetched(&validator, frame.clone(), fetched(Some(child.clone()))).await;
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
        header: Some(GlobalFrameHeader { frame_number: global_frame, output: output.clone(), ..Default::default() }),
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
    let registry = Arc::new(crate::test_support::TestProverRegistry::with_prover(prover(&now, 2)));
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
    assert!(plain.validate(&frame).is_err(), "today's registry cannot reproduce the committee");

    let calls = Arc::new(AtomicUsize::new(0));
    let source_for = |members: Vec<Vec<u8>>| -> crate::historical_committee::HistoricalCommitteeSource {
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
    assert!(wrong.validate(&frame).is_err(), "a committee that did not sign does not verify it");

    let rebuilt = validator(Some(source_for(vec![then.public_key().to_vec()])));
    rebuilt.prepare_historical_committee(&frame).await.unwrap();
    rebuilt.prepare_historical_committee(&frame).await.unwrap();
    assert!(rebuilt.validate(&frame).unwrap());
    assert_eq!(calls.load(Ordering::SeqCst), 2, "once per validator and anchor");
}

//! The union of a shard frame's copies against a real session in real RocksDB
//! state, read back by the verifier GLOBAL executes with.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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
use quil_engine::message_collector::{
    session_committees, MessageCollector, Provenance, Refusal, ShardFrameVerdict,
    ShardFrameVerifier, SubmitOutcome,
};
use quil_engine::test_support::TestProverRegistry;
use quil_execution::{
    global_intrinsic::{
        frame_header::{FrameHeader, TYPE_FRAME_HEADER},
        handoff,
        prover_shard_update::verify_frame_header_in_state,
    },
    hypergraph_state::HypergraphState,
    message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest},
};
use quil_types::{
    consensus::{ProverInfo, ProverStatus},
    crypto::Signer as _,
};

const MEMBERS: usize = 7;

struct Fixture {
    _db: quil_store::RocksDb,
    state: HypergraphState,
    registry: Arc<TestProverRegistry>,
    prover: Arc<quil_crypto::WesolowskiFrameProver>,
    session: Session,
    schemes: Vec<Generic<Namespace>>,
    output: Vec<u8>,
    parent: Vec<u8>,
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

impl Fixture {
    fn new() -> Self {
        let keys: Vec<FalconPrivateKey> = (0..MEMBERS)
            .map(|_| {
                let key = quil_crypto::FalconSigner::generate();
                FalconPrivateKey::from_bytes(key.private_key(), key.public_key()).unwrap()
            })
            .collect();
        let mut members: Vec<Vec<u8>> = keys
            .iter()
            .map(|key| key.public_key().as_ref().to_vec())
            .collect();
        members.sort();
        let session = Session {
            chain_id: [0x21; 32],
            filter: vec![0x63; 32],
            generation: 1,
            genesis: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap(),
            base_frame: 0,
            authorization: [0x34; 32],
            members,
        };
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store,
            Arc::new(quil_hypergraph::testing::StubProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        let state = HypergraphState::new(crdt);
        commit(&state, 1);
        handoff::initialize(&state, 2, &session).unwrap();
        commit(&state, 2);
        let registry = Arc::new(TestProverRegistry::with_provers(
            session
                .members
                .iter()
                .map(|key| ProverInfo {
                    address: quil_crypto::poseidon::hash_bytes_to_32(key)
                        .unwrap()
                        .to_vec(),
                    public_key: key.clone(),
                    status: ProverStatus::Active,
                    kick_frame_number: 0,
                    allocations: Vec::new(),
                    available_storage: 0,
                    seniority: 0,
                    delegate_address: Vec::new(),
                })
                .collect(),
        ));
        let set: Set<_> = keys
            .iter()
            .map(|key| key.public_key())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let mut schemes: Vec<Generic<Namespace>> = keys
            .into_iter()
            .map(|key| Generic::signer(&session.namespace().unwrap(), set.clone(), key).unwrap())
            .collect();
        schemes.sort_by_key(|scheme| scheme.me().unwrap().get());
        let output = quil_crypto::porep::deterministic_app_frame_output(
            &session.genesis,
            &[0; 32],
            &[vec![0; 32], vec![0; 32], vec![0; 32], vec![0; 32]],
            &quil_crypto::porep::derive_storage_beacon(0, &[]),
            session.base_frame + 1,
            5,
            &[],
            1,
            0,
            0,
            &[],
            0,
            &[],
            &[],
            &[],
        );
        Self {
            _db: db,
            parent: session.genesis.to_vec(),
            state,
            registry,
            prover: Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            session,
            schemes,
            output,
        }
    }

    fn header(&self, signers: &[usize]) -> FrameHeader {
        let proposal = Proposal::new(
            Round::new(Epoch::new(self.session.generation), View::new(5)),
            View::new(0),
            Digest(quil_crypto::poseidon::hash_bytes_to_32(&self.output).unwrap()),
        );
        let votes: Vec<_> = signers
            .iter()
            .map(|&i| {
                self.schemes[i]
                    .sign::<SimplexFalconScheme, Digest>(Subject::Finalize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();
        let certificate = self.schemes[0]
            .assemble::<SimplexFalconScheme, _, N3f1>(votes)
            .unwrap();
        FrameHeader {
            address: self.session.filter.clone(),
            frame_number: self.session.base_frame + 1,
            rank: 5,
            difficulty: 1,
            parent_selector: self.parent.clone(),
            requests_root: vec![0; 32],
            state_roots: vec![vec![0; 32]; 4],
            output: self.output.clone(),
            public_key_signature_bls48581: wrap_cert_for_header(&encode_finalization(
                &Finalization {
                    proposal,
                    certificate,
                },
            )),
            ..Default::default()
        }
    }

    /// Whom the verifier GLOBAL executes with pays for `header`.
    fn paid(&self, header: &FrameHeader) -> quil_types::error::Result<Vec<usize>> {
        verify_frame_header_in_state(
            &self.state,
            header,
            self.prover.as_ref(),
            &quil_crypto::FalconKeyConstructor,
            self.registry.as_ref(),
            5,
            5,
        )
        .map(|(_, bitmask)| quil_consensus::bitmask::set_bit_indices(&bitmask).collect())
    }
}

fn bundle(header: &FrameHeader) -> Vec<u8> {
    CanonicalMessageBundle {
        requests: vec![Some(CanonicalMessageRequest {
            inner_type_prefix: TYPE_FRAME_HEADER,
            inner_bytes: header.to_canonical_bytes().unwrap(),
        })],
        timestamp: 0,
    }
    .to_canonical_bytes()
    .unwrap()
}

fn header_of(raw: &[u8]) -> FrameHeader {
    let bundle = CanonicalMessageBundle::from_canonical_bytes(raw).unwrap();
    let request = bundle.requests[0].as_ref().unwrap();
    FrameHeader::from_canonical_bytes(&request.inner_bytes).unwrap()
}

/// The session's committee, read from state, verifies the signers a copy adds;
/// the union then passes the check GLOBAL executes with on every build, which
/// pays each signer. The whole-frame verifier runs once.
#[test]
fn sca_a_union_against_a_real_session_pays_each_signer_in_execution() {
    let fixture = Arc::new(Fixture::new());
    let source = session_committees(fixture.state.crdt().clone());
    let started = std::time::Instant::now();
    let committee = source(&fixture.session.filter, 1).unwrap();
    let read = started.elapsed();
    let started = std::time::Instant::now();
    let again = source(&fixture.session.filter, 1).unwrap();
    println!(
        "SCA-COST session_committee first_read_us={} cached_read_us={}",
        read.as_micros(),
        started.elapsed().as_micros()
    );
    assert_eq!(committee.members, fixture.session.members);
    assert_eq!(committee.namespace, fixture.session.namespace().unwrap());
    assert!(Arc::ptr_eq(&committee, &again));
    assert!(source(&fixture.session.filter, 0).is_none(), "generation 0");
    assert!(
        source(&fixture.session.filter, 2).is_none(),
        "no such session"
    );
    assert!(source(&[0x64; 32], 1).is_none(), "no such shard");

    let collector = MessageCollector::new();
    let verified = Arc::new(AtomicUsize::new(0));
    {
        let (fixture, verified) = (fixture.clone(), verified.clone());
        let verifier: ShardFrameVerifier = Arc::new(move |raw: &[u8]| {
            verified.fetch_add(1, Ordering::SeqCst);
            match fixture.paid(&header_of(raw)) {
                Ok(_) => ShardFrameVerdict::Valid,
                Err(error) => ShardFrameVerdict::Invalid(error.to_string()),
            }
        });
        collector.set_shard_frame_verifier(verifier);
    }
    collector.set_certificate_committees(source);
    let submit = |signers: &[usize]| {
        collector.add_message_outcome_from(1, bundle(&fixture.header(signers)), Provenance::Other)
    };
    assert_eq!(submit(&[0, 1, 2, 3, 4]), SubmitOutcome::Accepted);
    assert_eq!(submit(&[1, 2, 3, 4, 5]), SubmitOutcome::Accepted);
    assert_eq!(submit(&[2, 3, 4, 5, 6]), SubmitOutcome::Accepted);
    assert_eq!(submit(&[0, 2, 4, 5, 6]), SubmitOutcome::Duplicate);
    assert_eq!(verified.load(Ordering::SeqCst), 1);
    let held = collector.collect_for_rank(1);
    assert_eq!(held.len(), 1);
    assert_eq!(
        fixture.paid(&header_of(&held[0])).unwrap(),
        (0..7).collect::<Vec<_>>()
    );

    // Keys from outside the session sign under its coordinates: refused, whether
    // or not they name a member index the union lacks, and nothing changes.
    let stranger_fixture = Fixture::new();
    let mut stranger = Fixture {
        session: fixture.session.clone(),
        ..stranger_fixture
    };
    stranger.output = fixture.output.clone();
    let stranger_collector = MessageCollector::new();
    {
        let fixture = fixture.clone();
        let verifier: ShardFrameVerifier =
            Arc::new(move |raw: &[u8]| match fixture.paid(&header_of(raw)) {
                Ok(_) => ShardFrameVerdict::Valid,
                Err(error) => ShardFrameVerdict::Invalid(error.to_string()),
            });
        stranger_collector.set_shard_frame_verifier(verifier);
    }
    stranger_collector.set_certificate_committees(session_committees(fixture.state.crdt().clone()));
    assert_eq!(
        stranger_collector.add_message_outcome_from(
            1,
            bundle(&fixture.header(&[0, 1, 2, 3, 4])),
            Provenance::Other
        ),
        SubmitOutcome::Accepted
    );
    assert_eq!(
        stranger_collector.add_message_outcome_from(
            1,
            bundle(&stranger.header(&[1, 2, 3, 4, 5])),
            Provenance::Other
        ),
        SubmitOutcome::Filtered(Refusal::InvalidShardFrame)
    );
    let held = stranger_collector.collect_for_rank(1);
    assert_eq!(
        fixture.paid(&header_of(&held[0])).unwrap(),
        vec![0, 1, 2, 3, 4]
    );
}

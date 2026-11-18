//! A/B reproducers for shard frame headers GLOBAL accepts: one that names no
//! GLOBAL anchor, and a copy of one a finalized frame already carried.
//! The first runs a localnet process's consensus settings (`initialize(1)`)
//! with `QUIL_REQUIRED_ANCHOR_EPOCH=0`, so it expects the required-anchor
//! rule from GLOBAL frame 0; a build without the rule ignores the setting.
//! Real Falcon certificates and an authorized session.

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
use quil_engine::message_collector::{MessageCollector, ShardFrameVerdict, SubmitOutcome};
use quil_engine::test_support::TestProverRegistry;
use quil_execution::{
    global_intrinsic::{
        frame_header::{FrameHeader as CanonicalHeader, TYPE_FRAME_HEADER},
        handoff,
        intrinsic::GlobalIntrinsic,
    },
    hypergraph_state::HypergraphState,
    message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest},
};
use quil_types::{
    consensus::{ProverAllocation, ProverInfo, ProverStatus, RewardIssuance},
    crypto::Signer as _,
    error::Result,
    proto::{global::FrameHeader, keys::Bls48581AggregateSignature},
};

/// Pays nothing, counting the issuance calculations.
#[derive(Default)]
struct CreditProbe(std::sync::Mutex<usize>);
impl RewardIssuance for CreditProbe {
    fn calculate(
        &self,
        _: u64,
        _: u64,
        _: u64,
        provers: &[HashMap<String, ProverAllocation>],
    ) -> Result<Vec<BigInt>> {
        *self.0.lock().unwrap() += 1;
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

/// The session's first frame, certified by three of its four members, with
/// no GLOBAL anchor (`global_frame_number == 0`), as GLOBAL receives it.
fn unanchored_first_header(session: &Session, keys: &[FalconPrivateKey]) -> CanonicalHeader {
    let mut header = FrameHeader {
        address: session.filter.clone(),
        frame_number: session.base_frame + 1,
        rank: 5,
        difficulty: 50_000,
        timestamp: 1_700_000_000_000,
        global_frame_number: 0,
        parent_selector: session.genesis.to_vec(),
        requests_root: vec![0; 32],
        state_roots: vec![vec![0; 32]; 4],
        ..Default::default()
    };
    header.output = quil_crypto::porep::deterministic_app_frame_output(
        &header.parent_selector,
        &header.requests_root,
        &header.state_roots,
        &quil_crypto::porep::derive_storage_beacon(0, &[]),
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

/// A session-certified header without a GLOBAL anchor escapes the lockstep
/// window, the storage seat and the proof-of-storage gate, which are all
/// keyed on the anchor: GLOBAL must neither admit nor credit it.
#[test]
fn reproduces_unanchored_session_header_credit() {
    // A localnet process, as the node starts one, requiring an anchor from
    // epoch 0.
    std::env::set_var("QUIL_REQUIRED_ANCHOR_EPOCH", "0");
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
    let prover = Arc::new(quil_crypto::WesolowskiFrameProver::new(2048));

    // GLOBAL frame 2 authorizes the session.
    handoff::initialize(&state, 2, &session).unwrap();
    commit(&state, 2);
    let wire = unanchored_first_header(&session, &keys)
        .to_canonical_bytes()
        .unwrap();

    let probe = Arc::new(CreditProbe::default());
    let intrinsic = GlobalIntrinsic::new_with_stores(
        Arc::new(quil_execution::testing::NoopKeyManager),
        Some(prover),
        Some(clock),
        None,
        None,
    )
    .with_kick_verify_deps(
        Arc::new(quil_crypto::FalconKeyConstructor),
        state.crdt().clone(),
        inclusion,
    )
    .with_frame_header_deps(registry, probe.clone());
    let admitted = intrinsic.validate(3, &wire, None, None).is_ok();
    let executed = intrinsic.invoke_step(3, &wire, &state).is_ok();
    let credited = *probe.0.lock().unwrap();
    assert!(
        !admitted && !executed && credited == 0,
        "unanchored session header accepted by GLOBAL frame 3: admitted {admitted}, \
         executed {executed}, credited {credited} time(s)"
    );
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

/// A header a finalized GLOBAL frame carried, resubmitted with bytes
/// appended, decodes to the same header but hashes as a new message: the
/// collector that feeds GLOBAL proposals must not hold it for a later frame,
/// which would credit the header again.
#[test]
fn reproduces_reencoded_included_header_readmitted() {
    let collector = MessageCollector::new();
    collector.set_shard_frame_verifier(Arc::new(|_: &[u8]| ShardFrameVerdict::Valid));
    let header = CanonicalHeader {
        address: vec![0x11; 32],
        frame_number: 5,
        global_frame_number: 99,
        storage_attestation: vec![0xAB; 8],
        ..Default::default()
    };
    let canonical = header.to_canonical_bytes().unwrap();
    collector.mark_finalized(&[header_bundle(canonical.clone())]);
    let mut appended = canonical;
    appended.extend_from_slice(&[0xEE; 3]);
    assert_eq!(
        CanonicalHeader::from_canonical_bytes(&appended).unwrap(),
        header
    );
    let outcome = collector.add_message_outcome(1, header_bundle(appended));
    assert_ne!(
        outcome,
        SubmitOutcome::Accepted,
        "a re-encoded copy of a header a finalized GLOBAL frame carried was accepted for a \
         later frame"
    );
}

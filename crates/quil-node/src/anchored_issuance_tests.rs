//! A/B reproducers for shard header issuance at GLOBAL: a certified header's
//! difficulty, which its leader chooses, and how often GLOBAL credits it.
//! They run a localnet process's consensus settings (`initialize(1)`) with
//! `QUIL_ANCHORED_ISSUANCE_EPOCH=0`, so they expect the anchored issuance
//! rules from GLOBAL frame 0; a build without them prices and credits as
//! the header says. Real Falcon certificates and an authorized session.

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
use quil_engine::test_support::TestProverRegistry;
use quil_execution::{
    global_intrinsic::{
        frame_header::FrameHeader as CanonicalHeader, handoff, intrinsic::GlobalIntrinsic,
    },
    hypergraph_state::HypergraphState,
};
use quil_types::{
    consensus::{ProverAllocation, ProverInfo, ProverStatus, RewardIssuance},
    crypto::Signer as _,
    error::Result,
    proto::{global::FrameHeader, keys::Bls48581AggregateSignature},
};

/// The difficulty of the GLOBAL frame the header anchors to.
const ANCHOR_DIFFICULTY: u32 = 160_000;
/// The difficulty the shard's leader writes into the header: below 10,000,
/// issuance is priced with no square root.
const LEADER_DIFFICULTY: u32 = 1;

/// Pays nothing, recording the difficulty each calculation was priced at.
#[derive(Default)]
struct DifficultyProbe(std::sync::Mutex<Vec<u64>>);
impl RewardIssuance for DifficultyProbe {
    fn calculate(
        &self,
        difficulty: u64,
        _: u64,
        _: u64,
        provers: &[HashMap<String, ProverAllocation>],
    ) -> Result<Vec<BigInt>> {
        self.0.lock().unwrap().push(difficulty);
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

/// The session's first frame, anchored to GLOBAL frame `anchor` whose output
/// is `anchor_output`, at the leader's difficulty, as GLOBAL receives it.
fn anchored_first_header(
    session: &Session,
    keys: &[FalconPrivateKey],
    anchor: u64,
    anchor_output: &[u8],
) -> CanonicalHeader {
    let mut header = FrameHeader {
        address: session.filter.clone(),
        frame_number: session.base_frame + 1,
        rank: 5,
        difficulty: LEADER_DIFFICULTY,
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
        &quil_crypto::porep::derive_storage_beacon(anchor, anchor_output),
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

/// Executes the same certified header, anchored to a GLOBAL frame of
/// [`ANCHOR_DIFFICULTY`], in each GLOBAL frame of `frames`, and returns the
/// difficulty of every issuance calculation, in order.
fn priced_difficulties(frames: &[u64]) -> Vec<u64> {
    // A localnet process, as the node starts one, with the anchored issuance
    // rules from epoch 0.
    std::env::set_var("QUIL_ANCHORED_ISSUANCE_EPOCH", "0");
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

    // GLOBAL frame 2 authorizes the session; the header anchors to it.
    handoff::initialize(&state, 2, &session).unwrap();
    commit(&state, 2);
    let anchor_output = vec![0x46; 32];
    {
        use quil_types::store::ClockStore as _;
        let txn = clock.new_transaction(false).unwrap();
        clock
            .put_global_clock_frame(
                &quil_types::proto::global::GlobalFrame {
                    header: Some(quil_types::proto::global::GlobalFrameHeader {
                        frame_number: 2,
                        output: anchor_output.clone(),
                        difficulty: ANCHOR_DIFFICULTY,
                        ..Default::default()
                    }),
                    requests: Vec::new(),
                },
                txn.as_ref(),
            )
            .unwrap();
        txn.commit().unwrap();
    }
    let wire = anchored_first_header(&session, &keys, 2, &anchor_output)
        .to_canonical_bytes()
        .unwrap();

    let probe = Arc::new(DifficultyProbe::default());
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
    for &frame in frames {
        intrinsic.invoke_step(frame, &wire, &state).unwrap();
        commit(&state, frame);
    }
    let difficulties = probe.0.lock().unwrap().clone();
    difficulties
}

/// The leader's difficulty, bound into the certified output but compared
/// with GLOBAL's by no one, must not price the header's issuance.
#[test]
fn reproduces_leader_chosen_issuance_difficulty() {
    let priced = priced_difficulties(&[3]);
    assert!(!priced.is_empty(), "the header was not rewarded at all");
    assert!(
        priced.iter().all(|d| *d == u64::from(ANCHOR_DIFFICULTY)),
        "header priced at its leader's difficulty {:?} instead of the anchor's {}",
        priced,
        ANCHOR_DIFFICULTY,
    );
}

/// A certified header GLOBAL already executed earns nothing when a later
/// GLOBAL frame includes it again.
#[test]
fn reproduces_repeated_header_credit() {
    let priced = priced_difficulties(&[3, 4]);
    assert_eq!(
        priced.len(),
        1,
        "header credited in {} GLOBAL frames (difficulties {:?}), not once",
        priced.len(),
        priced,
    );
}

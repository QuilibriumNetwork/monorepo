//! An app-shard frame whose execution fails after some of its bundles were
//! staged, then is retried. These tests use only interfaces of the release
//! base, so they show its outcome there. Each frame carries paid hypergraph
//! writes: a settlement claim funds a vertex add and leaves a consumption
//! marker, so a bundle that runs twice over its own staged writes is refused
//! ("already consumed") instead of taking effect. A replica that ran the frame
//! once and one that retried it must record the same outcome.
use super::*;
use quil_execution::hypergraph_intrinsic::{
    confidential, vertex_add_domain_separator, vertex_add_signing_message, VertexAdd,
};
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
use quil_execution::token_intrinsic::settlement_claim::{
    bundle_context, consumption_marker, is_consumption_marker, marker_record, request_cost,
    SettlementClaim,
};
use quil_execution::token_intrinsic::settlement_record::{create_record, SettlementEntry};
use quil_types::crypto::Signer as _;
use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader, MessageBundle};
use std::sync::Arc;

/// A test network: its claims may cite GLOBAL frames from 0.
const NETWORK: u8 = 1;
const NETWORK_ID: [u8; 32] = [1; 32];
/// The shard frame every test executes, and the GLOBAL frames it may cite.
const FRAME: u64 = 3;
const CITED: u64 = 9;
const LATER: u64 = 10;

fn app() -> [u8; 32] {
    quil_execution::hypergraph_intrinsic::hypergraph_base_domain()
}

struct Resolver(Vec<u8>);
impl quil_execution::hypergraph_intrinsic::HypergraphConfigResolver for Resolver {
    fn write_public_key(&self, _domain: &[u8]) -> Option<Vec<u8>> {
        Some(self.0.clone())
    }
}

/// One replica of the shard: its own store, CRDT, GLOBAL clock and manager.
struct Replica {
    store: Arc<quil_hypergraph::testing::MemStore>,
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    clock: Arc<quil_store::testing::InMemoryClockStore>,
    manager: Arc<quil_execution::ExecutionEngineManager>,
}

impl Replica {
    fn new(write_key: &[u8]) -> Self {
        let store = Arc::new(quil_hypergraph::testing::MemStore::new());
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store.clone(),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let crypto = quil_execution::testing::NoopExecutionCrypto::new();
        let manager = quil_execution::ExecutionEngineManager::new(
            Arc::new(quil_types::crypto::NoopInclusionProver),
            Arc::new(crate::test_support::AcceptAllKeyManager),
            crdt.clone(),
            crypto.circuit_compiler.clone(),
            clock.clone(),
            Arc::new(Resolver(write_key.to_vec())),
            false, // application mode
        )
        .with_global_clock_store(clock.clone())
        .unwrap()
        .with_pricing_network(NETWORK);
        Self {
            store,
            crdt,
            clock,
            manager: Arc::new(manager),
        }
    }

    fn hold(&self, frame: &GlobalFrame) {
        self.clock.seed_frame(frame.clone());
    }

    fn execute(&self, bundles: &[MessageBundle], anchor: u64) -> Result<MaterializedAppFrame> {
        materialize_app_shard_requests(
            self.manager.as_ref(),
            bundles,
            FRAME,
            50_000,
            0,
            1,
            &app(),
            anchor,
        )
    }

    /// What this replica committed for the frame: its vertex-adds root and
    /// its recorded fee total.
    fn committed(&self) -> (Vec<u8>, Option<Vec<u8>>) {
        let root = self
            .crdt
            .sub_shard_commitment_for_filter("vertex", "adds", &app());
        let fee = self
            .crdt
            .read_execution_record(&quil_store::encoding::clock_shard_frame_fee_total_key(
                &app(),
                FRAME,
            ))
            .unwrap();
        (root, fee)
    }

    fn consumed(&self, receipt: &[u8; 32]) -> bool {
        let disc = quil_execution::hypergraph_state::vertex_adds_discriminator().unwrap();
        let view = quil_execution::hypergraph_state::HypergraphState::new(self.crdt.clone());
        let marker = consumption_marker(&app(), receipt).unwrap();
        view.get(&app(), &marker, &disc)
            .unwrap()
            .is_some_and(|blob| is_consumption_marker(&blob))
    }
}

/// A paid write: a signed vertex add at `data_address`, funded by a GLOBAL
/// settlement record proven at the root of GLOBAL frame `cited`.
struct Paid {
    bundle: MessageBundle,
    canonical: Vec<u8>,
    receipt: [u8; 32],
    settlement: u128,
    /// The GLOBAL frame whose prover root proves the record.
    global: GlobalFrame,
}

fn paid(
    signer: &quil_crypto::FalconSigner,
    data_address: u8,
    receipt: [u8; 32],
    cited: u64,
) -> Paid {
    let app = app();
    let field = confidential::ConfidentialField {
        commitment: [data_address; 32],
        kem_ct: vec![0u8; confidential::KEM_CT_LEN],
        nonce: [0u8; confidential::NONCE_LEN],
        aead_ct: vec![0u8; confidential::SALT_LEN + confidential::TAG_LEN],
    };
    let chunks = vec![confidential::encode(&field)];
    let data_address = vec![data_address; 32];
    let mut signed = vertex_add_domain_separator(&app).unwrap();
    signed.extend_from_slice(&vertex_add_signing_message(&app, &data_address, &chunks).unwrap());
    let add = VertexAdd {
        domain: app.to_vec(),
        data_address,
        data: quil_execution::hypergraph_intrinsic::pack_vertex_add_proof_chunks(&chunks).unwrap(),
        signature: signer.sign_with_domain(&signed, &[]).unwrap(),
    }
    .to_canonical_bytes()
    .unwrap();
    let mut bundle = CanonicalMessageBundle {
        requests: vec![None, Some(CanonicalMessageRequest::wrap(add).unwrap())],
        timestamp: 7,
    };
    let context = bundle_context(&bundle).unwrap();
    let cost = request_cost(bundle.requests[1].as_ref().unwrap()).unwrap()
        + marker_record().unwrap().len() as u64;
    let settlement = u128::from(cost) * 3;
    let entry = SettlementEntry {
        receipt,
        parameter_context: quil_lattice_ct::confidential::transfer::parameter_context(
            &NETWORK_ID,
            &quil_execution::domains::QUIL_TOKEN,
        ),
        destination: app,
        context,
        settlement,
        payment_address: [0; 32],
        payment: 0,
        claimant: [0; 32],
    };
    let blob = create_record(&entry).unwrap();
    let tree = format!("retry-settlement-{}", hex::encode(&receipt[..4]));
    let forest = quil_forest::Forest::in_memory();
    let root = forest
        .commit_shard_phase_raw(
            tree.as_bytes(),
            quil_forest::Phase::VertexAdds,
            0,
            [(
                receipt.to_vec(),
                quil_tries::vertex_leaf_value(&blob).unwrap(),
            )],
        )
        .unwrap();
    let address = [quil_execution::domains::GLOBAL.to_vec(), receipt.to_vec()].concat();
    let membership = forest
        .build_vertex_membership_proof(
            tree.as_bytes(),
            quil_forest::Phase::VertexAdds,
            0,
            &address,
            &blob,
        )
        .unwrap();
    let claim = SettlementClaim {
        network: NETWORK_ID,
        application: app,
        cited_global_frame: cited,
        global_root: root,
        receipt,
        settlement,
        context,
        payment_address: [0; 32],
        payment: 0,
        forest_proof: quil_forest::MembershipProof {
            inputs: vec![membership],
        }
        .to_bytes(),
        claimant_key_type: 0,
        claimant_public_key: Vec::new(),
        claimant_signature: Vec::new(),
    };
    bundle.requests[0] = Some(CanonicalMessageRequest::wrap(claim.encode().unwrap()).unwrap());
    let canonical = bundle.to_canonical_bytes().unwrap();
    let proto = crate::consensus_wire::decode_app_message_bundle(&canonical).unwrap();
    assert_eq!(
        crate::consensus_wire::app_bundle_to_canonical_bytes(&proto).unwrap(),
        canonical,
        "RETRY SETUP: the paid bundle must survive the wire form a frame carries"
    );
    Paid {
        bundle: proto,
        canonical,
        receipt,
        settlement,
        global: GlobalFrame {
            header: Some(GlobalFrameHeader {
                frame_number: cited,
                prover_tree_commitment: root.to_vec(),
                ..Default::default()
            }),
            ..Default::default()
        },
    }
}

/// The outcome a replica records for the frame, compared across replicas:
/// processed, skipped, taken, fee total, vertex-adds root and fee record.
type Outcome = (usize, usize, Vec<Vec<u8>>, u128, Vec<u8>, Option<Vec<u8>>);

fn outcome(replica: &Replica, frame: &MaterializedAppFrame) -> Outcome {
    let (root, fee_record) = replica.committed();
    (
        frame.processed,
        frame.skipped,
        frame.taken.clone(),
        frame.fee_total,
        root,
        fee_record,
    )
}

/// The guard every retry test shares: the first attempt failed as an
/// infrastructure fault (the frame is held for retry, never skipped) at the
/// step named by `step`, which runs only after the earlier bundles executed;
/// otherwise the test shows nothing about a retry.
fn expect_failed_at(step: &str, attempt: Result<MaterializedAppFrame>) {
    match attempt {
        Ok(frame) => panic!(
            "RETRY SETUP: the first attempt must fail, but it finished ({} processed)",
            frame.processed
        ),
        Err(error) => assert!(
            error.is_execution_unavailable() && error.to_string().contains(step),
            "RETRY SETUP: the first attempt must fail as an infrastructure fault at \"{step}\", \
             not {error}"
        ),
    }
}

/// A store fault at the frame's commit, after every bundle executed: the
/// retry must record what a replica without the fault records.
#[test]
fn a_retry_after_a_failed_commit_records_what_a_single_run_records() {
    let signer = quil_crypto::FalconSigner::generate();
    let write = paid(&signer, 0x31, [0x51; 32], CITED);
    let bundles = vec![write.bundle.clone()];

    let clean = Replica::new(signer.public_key());
    clean.hold(&write.global);
    let once = clean.execute(&bundles, CITED).unwrap();
    assert_eq!(
        (once.processed, once.fee_total),
        (1, write.settlement),
        "RETRY SETUP: a single run must admit the paid write"
    );
    let expected = outcome(&clean, &once);

    let retried = Replica::new(signer.public_key());
    retried.hold(&write.global);
    retried.store.fail_commit_setup(false, true);
    expect_failed_at(
        "injected root read failure",
        retried.execute(&bundles, CITED),
    );
    retried.store.fail_commit_setup(false, false);
    let again = retried.execute(&bundles, CITED).unwrap();
    assert!(retried.consumed(&write.receipt));
    assert!(!retried.crdt.has_staged_mutations());
    assert_eq!(
        outcome(&retried, &again),
        expected,
        "RETRY DIVERGENCE: a retry after a failed commit records another outcome than a single \
         run of the same frame"
    );
}

/// A bundle failing as an infrastructure fault after an earlier bundle of the
/// frame executed (its cited GLOBAL frame is not held yet): the retry, once
/// the frame is held, must record what a replica holding it all along records.
#[test]
fn a_retry_after_a_mid_frame_fault_records_what_a_single_run_records() {
    let signer = quil_crypto::FalconSigner::generate();
    let first = paid(&signer, 0x32, [0x52; 32], CITED);
    let second = paid(&signer, 0x33, [0x53; 32], LATER);
    let bundles = vec![first.bundle.clone(), second.bundle.clone()];

    let clean = Replica::new(signer.public_key());
    clean.hold(&first.global);
    clean.hold(&second.global);
    let once = clean.execute(&bundles, LATER).unwrap();
    assert_eq!(
        (once.processed, once.fee_total),
        (2, first.settlement + second.settlement),
        "RETRY SETUP: a single run must admit both paid writes"
    );
    assert_eq!(
        once.taken,
        vec![first.canonical.clone(), second.canonical.clone()]
    );
    let expected = outcome(&clean, &once);

    let retried = Replica::new(signer.public_key());
    retried.hold(&first.global);
    expect_failed_at(
        "cannot load canonical global reward frame",
        retried.execute(&bundles, LATER),
    );
    retried.hold(&second.global);
    let again = retried.execute(&bundles, LATER).unwrap();
    assert!(retried.consumed(&first.receipt) && retried.consumed(&second.receipt));
    assert_eq!(
        outcome(&retried, &again),
        expected,
        "RETRY DIVERGENCE: a retry after a mid-frame fault records another outcome than a single \
         run of the same frame"
    );
}

/// Control: two replicas running the frame once record the same outcome, and
/// a retry whose first attempt failed before any bundle took effect (the
/// faulting bundle comes first) records it too. Passes with and without the
/// defect: only work staged by a failed attempt diverges.
#[test]
fn control_a_retry_with_nothing_staged_records_what_a_single_run_records() {
    let signer = quil_crypto::FalconSigner::generate();
    let first = paid(&signer, 0x34, [0x54; 32], CITED);
    let second = paid(&signer, 0x35, [0x55; 32], LATER);
    let bundles = vec![second.bundle.clone(), first.bundle.clone()];

    let run_once = || {
        let replica = Replica::new(signer.public_key());
        replica.hold(&first.global);
        replica.hold(&second.global);
        let once = replica.execute(&bundles, LATER).unwrap();
        outcome(&replica, &once)
    };
    let expected = run_once();
    assert_eq!(
        (expected.0, expected.3),
        (2, first.settlement + second.settlement),
        "RETRY SETUP: a single run must admit both paid writes"
    );
    assert_eq!(run_once(), expected, "a single run is deterministic");

    let retried = Replica::new(signer.public_key());
    retried.hold(&first.global);
    let failed = retried.execute(&bundles, LATER);
    assert!(failed.is_err_and(|error| error.is_execution_unavailable()));
    assert!(
        !retried.crdt.has_staged_mutations(),
        "the faulting bundle is first: nothing was staged"
    );
    retried.hold(&second.global);
    let again = retried.execute(&bundles, LATER).unwrap();
    assert_eq!(outcome(&retried, &again), expected);
}

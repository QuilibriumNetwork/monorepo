//! A leader near the compute domain frame leaves out bundles carrying a
//! compute op naming another application: voters that reached the frame
//! refuse a proposal anchored before it that carries one, and no frame
//! anchored at or after it runs the op.
use super::shield_hold_tests::{bundle, rig, turn, Proofs, Rig};
use super::*;

/// An application deployed with the compute type domain.
const COMPUTE_APP: [u8; 32] = [0x42; 32];

/// A free CodeExecute naming `domain`.
fn execute(domain: [u8; 32]) -> Vec<u8> {
    quil_execution::compute_intrinsic::CodeExecute {
        proof_of_payment: vec![vec![0u8; 57]],
        domain,
        rendezvous: [0x44; 32],
        execute_operations: Vec::new(),
    }
    .to_canonical_bytes()
    .unwrap()
}

/// Record `app` in the rig's store as deployed with the compute type
/// domain, so execution routes its messages to the compute engine.
fn deploy_compute_app(rig: &Rig, app: &[u8; 32]) {
    let state = quil_execution::hypergraph_state::HypergraphState::new(
        rig.engine.execution_engine.as_ref().unwrap().crdt(),
    );
    let mut config = quil_tries::VectorCommitmentTree::new();
    config
        .insert(&[0x40u8], b"cfg", &[], &num_bigint::BigInt::from(3))
        .unwrap();
    let mut additional: Vec<Option<quil_tries::VectorCommitmentTree>> =
        (0..14).map(|_| None).collect();
    additional[13] = Some(config);
    state
        .init_metadata_vertex(
            app,
            &mut quil_tries::VectorCommitmentTree::new(),
            &mut quil_tries::VectorCommitmentTree::new(),
            "schema",
            &mut additional,
            &quil_execution::domains::COMPUTE,
            1,
            &quil_types::crypto::NoopInclusionProver,
        )
        .unwrap();
    state.commit().unwrap();
}

/// With no GLOBAL frame the leader anchors at none, its latest frame 0,
/// within two frames of a domain frame of 2: it drops the bundle with a
/// foreign CodeExecute for good and keeps the one naming its own
/// application. A token shard's leader keeps the same bundle: its engine
/// never runs the op.
#[tokio::test]
async fn a_leader_drops_a_cross_domain_compute_op_voters_refuse() {
    // The test-network setting; nextest runs each test in its own process.
    std::env::set_var("QUIL_COMPUTE_DOMAIN_FRAME", "2");
    let crossing = bundle(vec![execute([0x22; 32])]);

    let compute = rig(COMPUTE_APP.to_vec(), Proofs::Unconfigured);
    deploy_compute_app(&compute, &COMPUTE_APP);
    assert!(compute.collector.add_message(0, crossing.clone()));
    assert!(compute
        .collector
        .add_message(0, bundle(vec![execute(COMPUTE_APP)])));
    turn(&compute.leader, 1);
    assert_eq!(
        compute.collector.total_pending(),
        1,
        "a leader kept a cross-domain compute op voters refuse"
    );
    assert!(
        !compute.collector.add_message(0, crossing.clone()),
        "a dropped cross-domain compute op was collected again"
    );

    let token = rig(
        quil_execution::domains::QUIL_TOKEN.to_vec(),
        Proofs::Unconfigured,
    );
    assert!(token.collector.add_message(0, crossing));
    turn(&token.leader, 1);
    assert_eq!(
        token.collector.total_pending(),
        1,
        "a token shard dropped a compute op it never runs"
    );
}

/// The window a leader drops such bundles in, for a domain frame of 100:
/// from a latest GLOBAL frame two short of it while the anchor is before
/// it (or none), and never for an anchor at it.
#[test]
fn a_leader_drops_cross_domain_ops_only_while_voters_refuse_them() {
    std::env::set_var("QUIL_COMPUTE_DOMAIN_FRAME", "100");
    assert!(
        !leader_drops_cross_domain(93, 97),
        "a leader dropped a bundle no voter refuses yet"
    );
    assert!(
        leader_drops_cross_domain(94, 98),
        "a leader kept a bundle a voter ahead of it refuses"
    );
    assert!(
        leader_drops_cross_domain(99, 103),
        "a leader kept a bundle anchored before the domain frame"
    );
    assert!(
        leader_drops_cross_domain(0, 98),
        "a leader kept an unanchored bundle a voter refuses"
    );
    assert!(
        !leader_drops_cross_domain(100, 104),
        "a leader dropped a bundle anchored at the domain frame"
    );
}

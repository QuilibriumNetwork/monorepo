//! The application creation floor end to end: a hypergraph deploy executed
//! in the GLOBAL venue, as the GLOBAL materializer runs it, is priced with the
//! basis the materializer computes for its frame (`frame_pomw_basis`) and
//! pays for itself with a settlement proven at a certified root.

use super::*;
use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
use crate::token_intrinsic::{settlement_claim::*, settlement_record::*};
use quil_crypto::FalconSigner;
use quil_types::crypto::{NoopInclusionProver, Signer};
use quil_types::execution::{FrameExecutionContext, ShardExecutionEngine, ShardPath, Venue};
use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader};

/// The GLOBAL frame executing the deploy and its finalized anchor, the
/// frame its settlement records are certified at.
const FRAME: u64 = 10;
const ANCHOR: u64 = FRAME - 1;

/// A hypergraph deploy of a fresh owner and write key.
fn deploy_request() -> CanonicalMessageRequest {
    let owner = FalconSigner::generate();
    let write = FalconSigner::generate();
    let deploy = crate::hypergraph_intrinsic::HypergraphDeploy {
        config: Some(crate::hypergraph_intrinsic::HypergraphConfiguration {
            read_public_key: vec![7; quil_crypto::SNTRUP761_PUBLIC_KEY_LEN],
            write_public_key: write.public_key().to_vec(),
            owner_public_key: owner.public_key().to_vec(),
        }),
        rdf_schema: b"@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\
              @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n\
              @prefix qcl: <https://types.quilibrium.com/qcl/> .\n\
              :Note a rdfs:Class .\n\
              :Field a rdfs:Property ;\n  rdfs:domain qcl:Uint ;\n  qcl:size 8 ;\n  \
              qcl:order 0 ;\n  rdfs:range :Note .\n"
            .to_vec(),
    }
    .to_canonical_bytes()
    .unwrap();
    CanonicalMessageRequest::wrap(deploy).unwrap()
}

#[test]
fn a_global_deploy_pays_the_creation_floor_through_the_engine() {
    set_app_creation_floor_frame_for_thread(Some(ANCHOR));
    let network = [1u8; 32];
    // Deploys execute in the GLOBAL venue under their base domain.
    let app = crate::hypergraph_intrinsic::hypergraph_base_domain();
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_hypergraph::testing::MemStore::new()),
        Arc::new(NoopInclusionProver),
    ));
    let mut engine = HypergraphExecutionEngine::new_with_state(
        ExecutionMode::Global,
        crdt.clone(),
        Arc::new(crate::hypergraph_intrinsic::CrdtHypergraphConfigResolver::new(crdt.clone())),
    )
    .with_key_manager(Arc::new(quil_crypto::DefaultKeyManager::new()));
    let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
    engine.set_global_clock_store(clock.clone());
    // A test network: its claims may cite frames from 0.
    engine.set_network(1);

    // The basis the GLOBAL materializer computes for this frame.
    let basis = crate::pricing::frame_pomw_basis(50_000, 1 << 30).unwrap();
    let floor = basis / 4;

    // One bundle per amount, each funded by its own GLOBAL record, all
    // certified at the anchor.
    let amounts = [floor - 1, floor];
    let bundles: Vec<(CanonicalMessageBundle, SettlementEntry, Vec<u8>)> = amounts
        .iter()
        .enumerate()
        .map(|(i, &settlement)| {
            let bundle = CanonicalMessageBundle {
                requests: vec![None, Some(deploy_request())],
                timestamp: 7,
            };
            let entry = SettlementEntry {
                receipt: [0x50 + i as u8; 32],
                parameter_context: quil_lattice_ct::confidential::transfer::parameter_context(
                    &network,
                    &crate::domains::QUIL_TOKEN,
                ),
                destination: app,
                context: bundle_context(&bundle).unwrap(),
                settlement,
                payment_address: [0; 32],
                payment: 0,
                claimant: [0; 32],
            };
            let blob = create_record(&entry).unwrap();
            (bundle, entry, blob)
        })
        .collect();
    let forest = quil_forest::Forest::in_memory();
    let root = forest
        .commit_shard_phase_raw(
            b"creation-floor",
            quil_forest::Phase::VertexAdds,
            0,
            bundles.iter().map(|(_, entry, blob)| {
                (
                    entry.receipt.to_vec(),
                    quil_tries::vertex_leaf_value(blob).unwrap(),
                )
            }),
        )
        .unwrap();
    clock.seed_frame(GlobalFrame {
        header: Some(GlobalFrameHeader {
            frame_number: ANCHOR,
            prover_tree_commitment: root.to_vec(),
            ..Default::default()
        }),
        ..Default::default()
    });
    let paid: Vec<Vec<u8>> = bundles
        .into_iter()
        .map(|(mut bundle, entry, blob)| {
            let address = [crate::domains::GLOBAL.to_vec(), entry.receipt.to_vec()].concat();
            let membership = forest
                .build_vertex_membership_proof(
                    b"creation-floor",
                    quil_forest::Phase::VertexAdds,
                    0,
                    &address,
                    &blob,
                )
                .unwrap();
            let claim = SettlementClaim {
                network,
                application: app,
                cited_global_frame: ANCHOR,
                global_root: root,
                receipt: entry.receipt,
                settlement: entry.settlement,
                context: entry.context,
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
            bundle.requests[0] =
                Some(CanonicalMessageRequest::wrap(claim.encode().unwrap()).unwrap());
            bundle.to_canonical_bytes().unwrap()
        })
        .collect();
    // The GLOBAL materializer's context for this frame.
    let context = FrameExecutionContext {
        frame_number: FRAME,
        finalized_global_frame: Some(ANCHOR),
        shard: ShardPath::WHOLE,
        venue: Some(Venue::Global),
        pomw_basis: Some(basis),
    };
    let multiplier = BigInt::from(2);
    let view = crate::hypergraph_state::HypergraphState::new(crdt.clone());
    let disc = crate::hypergraph_state::vertex_adds_discriminator().unwrap();
    let marker_of = |i: usize| consumption_marker(&app, &[0x50 + i as u8; 32]).unwrap();

    let at = engine.process_message_with_context(context, &multiplier, &app, &paid[1]);
    println!("REACH creation-floor admit");
    assert!(
        at.is_ok(),
        "engine_floor_refused: a deploy settling the floor {floor}: {:?}",
        at.as_ref().map(|_| ())
    );
    assert!(is_consumption_marker(
        &view.get(&app, &marker_of(1), &disc).unwrap().unwrap()
    ));

    let below = engine.process_message_with_context(context, &multiplier, &app, &paid[0]);
    assert!(
        below
            .as_ref()
            .is_err_and(|e| e.to_string().contains("creation floor")),
        "engine_floor_unenforced: a deploy settling {} below the floor {floor}: {:?}",
        floor - 1,
        below.as_ref().map(|_| ())
    );
    assert!(view.get(&app, &marker_of(0), &disc).unwrap().is_none());
}

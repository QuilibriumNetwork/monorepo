//! An application's configuration only moves forward: a deploy (unsigned,
//! its domain derived from its configuration) or an owner-signed update
//! applied again after a later update must not restore the configuration it
//! carried, and a deploy of a deployed hypergraph or compute configuration
//! must not rewrite the schema its deployer chose.

use super::*;
use crate::message_envelope::CanonicalMessageRequest;
use crate::token_intrinsic::{
    constants::token_base_domain, materialize, metadata_schema, TokenConfiguration, TokenDeploy,
    TokenUpdate,
};
use quil_crypto::FalconSigner;
use quil_types::crypto::{NoopInclusionProver, Signer};
use quil_types::execution::ShardExecutionEngine;

fn engine() -> TokenExecutionEngine {
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_hypergraph::testing::MemStore::new()),
        Arc::new(NoopInclusionProver),
    ));
    TokenExecutionEngine::new_with_state(
        ExecutionMode::Application,
        Arc::new(NoopInclusionProver),
        crdt,
        Arc::new(quil_crypto::DefaultKeyManager::new()),
        Arc::new(crate::testing::NoopClockStore),
    )
}

fn config(name: &[u8], owner: &FalconSigner) -> TokenConfiguration {
    TokenConfiguration {
        behavior: 1,
        units: vec![1],
        name: name.to_vec(),
        symbol: b"RPL".to_vec(),
        owner_public_key: owner.public_key().to_vec(),
        ..Default::default()
    }
}

/// Apply one token request at `address` in frame `frame` (fee multiplier 0:
/// payment is not what these tests check).
fn apply(engine: &TokenExecutionEngine, frame: u64, address: &[u8], inner: Vec<u8>) -> Result<()> {
    let message = CanonicalMessageRequest::wrap(inner)?.to_canonical_bytes()?;
    engine.validate_message(frame, address, &message)?;
    engine
        .process_message(frame, &num_bigint::BigInt::from(0), address, &message)
        .map(|_| ())
}

fn deploy(cfg: &TokenConfiguration) -> Vec<u8> {
    TokenDeploy {
        config: cfg.to_canonical_bytes().unwrap(),
        rdf_schema: Vec::new(),
    }
    .to_canonical_bytes()
    .unwrap()
}

/// An update to `cfg` signed by `signer` under `separator`.
fn signed(cfg: &TokenConfiguration, signer: &FalconSigner, separator: &[u8]) -> Vec<u8> {
    let mut update = TokenUpdate {
        config: cfg.to_canonical_bytes().unwrap(),
        rdf_schema: Vec::new(),
        public_key_signature_bls48581: Vec::new(),
    };
    update.public_key_signature_bls48581 = signer
        .sign_with_domain(&update.to_canonical_bytes().unwrap(), separator)
        .unwrap();
    update.to_canonical_bytes().unwrap()
}

/// An update to `cfg` signed by `signer` the way the wallet signs it: over
/// the configuration `engine` holds for `domain`, which it replaces.
fn update(
    engine: &TokenExecutionEngine,
    domain: &[u8; 32],
    cfg: &TokenConfiguration,
    signer: &FalconSigner,
) -> Vec<u8> {
    let binding = stored_binding(engine, domain);
    signed(
        cfg,
        signer,
        &crate::config_replay::update_signing_domain(
            domain,
            crate::config_replay::TOKEN_UPDATE_TAG,
            Some(&binding),
        ),
    )
}

/// An update signed the way a client before the config replay frame signs
/// it: over `domain ‖ "TOKEN_UPDATE"` alone.
fn unbound_update(domain: &[u8; 32], cfg: &TokenConfiguration, signer: &FalconSigner) -> Vec<u8> {
    signed(
        cfg,
        signer,
        &crate::config_replay::update_signing_domain(
            domain,
            crate::config_replay::TOKEN_UPDATE_TAG,
            None,
        ),
    )
}

/// The binding of the metadata vertex the chain holds for `domain`.
fn stored_binding(engine: &TokenExecutionEngine, domain: &[u8; 32]) -> Vec<u8> {
    crate::config_replay::stored_binding(engine.state.as_ref().unwrap(), domain)
        .unwrap()
        .expect("token metadata vertex")
}

/// The configuration the chain holds for `domain`, read as an update reads it.
fn stored(engine: &TokenExecutionEngine, domain: &[u8; 32]) -> TokenConfiguration {
    let state = engine.state.as_ref().unwrap();
    let va = crate::hypergraph_state::vertex_adds_discriminator().unwrap();
    let blob = state
        .get(
            domain,
            &crate::hypergraph_state::HYPERGRAPH_METADATA_ADDRESS,
            &va,
        )
        .unwrap()
        .expect("token metadata vertex");
    let outer = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(&blob).unwrap(),
    };
    let inner = outer
        .get(&materialize::TOKEN_CONFIG_OUTER_KEY)
        .expect("token config subtree");
    let inner = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(inner).unwrap(),
    };
    metadata_schema::decode_token_config_from_tree(&inner).unwrap()
}

/// Deploy C0 (owner K0), rotate the owner to K1 by an update K0 signs,
/// then submit C0's deploy again. Anyone can: a deploy carries no signature
/// and derives the same domain from the same configuration.
#[test]
fn reproduces_a_replayed_token_deploy_restoring_a_rotated_owner() {
    let engine = engine();
    let old_owner = FalconSigner::generate();
    let new_owner = FalconSigner::generate();
    let original = config(b"replay", &old_owner);
    let domain = materialize::token_deploy_domain(&original).unwrap();
    let base = token_base_domain();

    apply(&engine, 10, &base, deploy(&original)).expect("harness: the first deploy applies");
    assert_eq!(
        stored(&engine, &domain).owner_public_key,
        old_owner.public_key(),
        "harness: the deploy wrote its owner at the derived domain"
    );

    let rotated = config(b"replay", &new_owner);
    apply(
        &engine,
        11,
        &domain,
        update(&engine, &domain, &rotated, &old_owner),
    )
    .expect("harness: the owner-signed rotation applies");
    assert_eq!(
        stored(&engine, &domain).owner_public_key,
        new_owner.public_key(),
        "harness: the rotation took effect"
    );

    let replay = apply(&engine, 12, &base, deploy(&original));
    let after = stored(&engine, &domain);
    if after.owner_public_key == new_owner.public_key() {
        return;
    }
    // Rolled back: show the superseded key now controls the token.
    let thief = FalconSigner::generate();
    let takeover = apply(
        &engine,
        13,
        &domain,
        update(&engine, &domain, &config(b"stolen", &thief), &old_owner),
    );
    panic!(
        "REPLAY-ACCEPTED: a replayed deploy (result {replay:?}) restored the rotated-out owner \
         key (stored owner is the old key: {}); an update signed by that old key then {} the \
         token",
        after.owner_public_key == old_owner.public_key(),
        if takeover.is_ok() {
            "took over"
        } else {
            "failed to take over"
        },
    );
}

/// Sibling: an owner-signed update binds only (domain, configuration), so
/// the owner's earlier update, applied again after a later one, restores the
/// configuration the later update replaced.
#[test]
fn reproduces_a_replayed_token_update_restoring_a_superseded_config() {
    let engine = engine();
    let owner = FalconSigner::generate();
    let original = config(b"zero", &owner);
    let domain = materialize::token_deploy_domain(&original).unwrap();
    apply(&engine, 10, &token_base_domain(), deploy(&original))
        .expect("harness: the deploy applies");

    let first = update(&engine, &domain, &config(b"one", &owner), &owner);
    apply(&engine, 11, &domain, first.clone()).expect("harness: the first update applies");
    let second = update(&engine, &domain, &config(b"two", &owner), &owner);
    apply(&engine, 12, &domain, second).expect("harness: the second update applies");
    let name = stored(&engine, &domain).name;
    assert_eq!(name, b"two", "harness: the second update took effect");

    let replay = apply(&engine, 13, &domain, first);
    let name = stored(&engine, &domain).name;
    assert_eq!(
        name,
        b"two",
        "REPLAY-ACCEPTED (update replay): the owner's superseded update applied again \
         (result {replay:?}) and restored name {:?}",
        String::from_utf8_lossy(&name),
    );
}

/// Apply one request through any engine (fee multiplier 0).
fn apply_to(
    engine: &dyn ShardExecutionEngine,
    frame: u64,
    address: &[u8],
    inner: Vec<u8>,
) -> Result<()> {
    let message = CanonicalMessageRequest::wrap(inner)?.to_canonical_bytes()?;
    engine.validate_message(frame, address, &message)?;
    engine
        .process_message(frame, &num_bigint::BigInt::from(0), address, &message)
        .map(|_| ())
}

/// A schema both the hypergraph and the compute deploy accept, declaring
/// class `class`.
fn schema(class: &str) -> Vec<u8> {
    format!(
        "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\
         @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n\
         @prefix qcl: <https://types.quilibrium.com/qcl/> .\n\
         :{class} a rdfs:Class .\n\
         :Field a rdfs:Property ;\n  rdfs:domain qcl:Uint ;\n  qcl:size 8 ;\n  \
         qcl:order 0 ;\n  rdfs:range :{class} .\n"
    )
    .into_bytes()
}

/// The RDF schema an application's metadata vertex holds (key `[2 << 2]`).
fn stored_schema(state: &crate::hypergraph_state::HypergraphState, domain: &[u8; 32]) -> Vec<u8> {
    let va = crate::hypergraph_state::vertex_adds_discriminator().unwrap();
    let blob = state
        .get(
            domain,
            &crate::hypergraph_state::HYPERGRAPH_METADATA_ADDRESS,
            &va,
        )
        .unwrap()
        .expect("application metadata vertex");
    let outer = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(&blob).unwrap(),
    };
    outer.get(&[2u8 << 2]).expect("rdf schema").to_vec()
}

fn crdt() -> Arc<quil_hypergraph::HypergraphCrdt> {
    Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_hypergraph::testing::MemStore::new()),
        Arc::new(NoopInclusionProver),
    ))
}

/// A hypergraph deploy derives its domain from its configuration alone,
/// so anyone can deploy a deployed hypergraph's configuration again with
/// another schema.
#[test]
fn reproduces_a_redeployed_hypergraph_rewriting_its_schema() {
    let engine = HypergraphExecutionEngine::new_with_state(
        ExecutionMode::Application,
        crdt(),
        Arc::new(crate::testing::NoopHypergraphConfigResolver),
    );
    let owner = FalconSigner::generate();
    let cfg = crate::hypergraph_intrinsic::HypergraphConfiguration {
        read_public_key: vec![7; quil_crypto::SNTRUP761_PUBLIC_KEY_LEN],
        write_public_key: owner.public_key().to_vec(),
        owner_public_key: owner.public_key().to_vec(),
    };
    let domain = crate::hypergraph_intrinsic::hypergraph_deploy_domain(&cfg).unwrap();
    let base = crate::hypergraph_intrinsic::hypergraph_base_domain();
    let deploy = |rdf_schema: Vec<u8>| {
        crate::hypergraph_intrinsic::HypergraphDeploy {
            config: Some(cfg.clone()),
            rdf_schema,
        }
        .to_canonical_bytes()
        .unwrap()
    };
    apply_to(&engine, 10, &base, deploy(schema("Note"))).expect("harness: the deploy applies");
    let state = engine.state.as_ref().unwrap();
    assert_eq!(
        stored_schema(state, &domain),
        schema("Note"),
        "harness: the deploy wrote its schema at the derived domain"
    );

    let replay = apply_to(&engine, 11, &base, deploy(schema("Forged")));
    let after = stored_schema(state, &domain);
    assert!(
        after == schema("Note"),
        "REPLAY-ACCEPTED (hypergraph redeploy): a deploy of the deployed configuration \
         (result {replay:?}) rewrote its schema"
    );
}

/// The same for a compute application, whose domain covers only its
/// read and write keys.
#[test]
fn reproduces_a_redeployed_compute_application_rewriting_its_schema() {
    let stubs = crate::testing::NoopExecutionCrypto::new();
    let engine = ComputeExecutionEngine::new_with_state(
        ExecutionMode::Application,
        crdt(),
        stubs.key_manager,
        stubs.circuit_compiler,
    );
    let owner = FalconSigner::generate();
    let cfg = crate::compute_intrinsic::config::ComputeConfiguration {
        read_public_key: vec![7; quil_crypto::SNTRUP761_PUBLIC_KEY_LEN],
        write_public_key: owner.public_key().to_vec(),
        owner_public_key: owner.public_key().to_vec(),
    };
    let tree =
        crate::compute_intrinsic::materialize::build_compute_configuration_metadata_tree(&cfg)
            .unwrap();
    let mut preimage = crate::domains::COMPUTE.to_vec();
    preimage.extend_from_slice(&crate::hypergraph_state::tree_content_digest(&tree));
    let domain = quil_crypto::poseidon::hash_bytes_to_32(&preimage).unwrap();
    let deploy = |rdf_schema: Vec<u8>| {
        crate::compute_intrinsic::config::ComputeDeploy {
            config: cfg.to_canonical_bytes().unwrap(),
            rdf_schema,
        }
        .to_canonical_bytes()
        .unwrap()
    };
    let base = crate::domains::COMPUTE;
    apply_to(&engine, 10, &base, deploy(schema("Program"))).expect("harness: the deploy applies");
    let state = engine.state.as_ref().unwrap();
    assert_eq!(
        stored_schema(state, &domain),
        schema("Program"),
        "harness: the deploy wrote its schema at the derived domain"
    );

    let replay = apply_to(&engine, 11, &base, deploy(schema("Forged")));
    let after = stored_schema(state, &domain);
    assert!(
        after == schema("Program"),
        "REPLAY-ACCEPTED (compute redeploy): a deploy of the deployed configuration \
         (result {replay:?}) rewrote its schema"
    );
}

/// Before the config replay frame a deploy and an update behave as older
/// builds do, so history replays unchanged: an update signed over its domain
/// alone applies, and a deploy of a deployed configuration rewrites it. From
/// the frame the unbound update is refused, a bound one applies and the
/// deploy is refused.
#[test]
fn before_the_config_replay_frame_deploys_and_updates_apply_as_before() {
    crate::config_replay::set_config_replay_frame_for_thread(Some(100));
    let engine = engine();
    let owner = FalconSigner::generate();
    let original = config(b"zero", &owner);
    let domain = materialize::token_deploy_domain(&original).unwrap();
    let base = token_base_domain();
    apply(&engine, 10, &base, deploy(&original)).expect("harness: the deploy applies");

    let early = apply(
        &engine,
        11,
        &domain,
        unbound_update(&domain, &config(b"one", &owner), &owner),
    );
    let vertex = engine
        .state
        .as_ref()
        .unwrap()
        .get(
            &domain,
            &crate::hypergraph_state::HYPERGRAPH_METADATA_ADDRESS,
            &crate::hypergraph_state::vertex_adds_discriminator().unwrap(),
        )
        .unwrap()
        .unwrap();
    let sequenced = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(&vertex).unwrap(),
    }
    .get(&crate::config_replay::UPDATE_SEQUENCE_KEY)
    .is_some();
    assert!(
        early.is_ok() && stored(&engine, &domain).name == b"one" && !sequenced,
        "ACTIVATION: before the frame an update signed over its domain alone was \
         refused or wrote an update sequence ({early:?})"
    );
    let redeploy = apply(&engine, 12, &base, deploy(&original));
    assert!(
        redeploy.is_ok() && stored(&engine, &domain).name == b"zero",
        "ACTIVATION: before the frame a deploy of the deployed configuration did not \
         apply as before ({redeploy:?})"
    );

    let late = apply(
        &engine,
        100,
        &domain,
        unbound_update(&domain, &config(b"late", &owner), &owner),
    );
    assert!(
        late.is_err(),
        "UNBOUND: from the frame an update signed over its domain alone applied"
    );
    apply(
        &engine,
        101,
        &domain,
        update(&engine, &domain, &config(b"bound", &owner), &owner),
    )
    .expect("harness: from the frame a bound update applies");
    let refused = apply(&engine, 102, &base, deploy(&original));
    assert!(
        refused.is_err() && stored(&engine, &domain).name == b"bound",
        "REPLAY-ACCEPTED: from the frame a deploy of the deployed configuration applied"
    );
    crate::config_replay::set_config_replay_frame_for_thread(None);
}

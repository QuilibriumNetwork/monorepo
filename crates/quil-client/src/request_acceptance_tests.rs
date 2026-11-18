//! Acceptance tests for the requests the client *emits*.
//!
//! For every signed request the client builds, we construct it via the client's
//! real `build_*` code path, then run it through the **node's own** verification
//! function and assert it would be accepted. These pin the parts the client is
//! solely responsible for — canonical byte layout, signing domain/separator, key
//! selection, and proto shape — so a drift in either the client's construction
//! or the node's verify will fail here.
//!
//! Scope: state-independent signature and structural verification for the
//! retained deploy, compute and hypergraph client requests. QCT3 token
//! authorization and execution are covered by the current wallet tests.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sha3::{Digest, Sha3_256};

use quil_crypto::FalconKeyConstructor;
use quil_execution::compute_intrinsic::conversions::{
    code_execute_from_proto, compute_update_from_proto,
};
use quil_execution::compute_intrinsic::intrinsic::verify_code_execute;
// Internal (canonical) hypergraph op types the node verifies against; the engine
// converts the proto ops the client emits into these via `from_proto` before
// calling `verify_op_signature`. We do the same in these tests.
use quil_execution::hypergraph_intrinsic::types as hgtypes;
use quil_execution::hypergraph_intrinsic::{
    hyperedge_extrinsic_commit, verify_op_signature, AuthCheck, HypergraphConfigResolver,
    HypergraphUpdate as CanonicalHypergraphUpdate, OpForAuth,
};
use quil_execution::token_intrinsic::conversions::{
    token_config_from_proto, token_update_from_proto,
};
use quil_keys::FileKeyManager;
use quil_types::crypto::KeyType;
use quil_types::proto::compute::{
    Application, ComputeConfiguration, ExecuteOperation, ExecutionContext,
};
use quil_types::proto::hypergraph::HypergraphConfiguration;
use quil_types::proto::token::{
    FeeBasis, FeeBasisType, TokenConfiguration, TokenMintBehavior, TokenMintStrategy,
};

use crate::commands::compute::build_code_execute;
use crate::commands::deploy::compute_update::build_compute_update;
use crate::commands::deploy::hypergraph_update::build_hypergraph_update;
use crate::commands::deploy::token_update::{build_token_update, updated_config};
use crate::commands::hypergraph::put::build_hyperedge_add;
use crate::commands::hypergraph::remove::{build_hyperedge_remove, build_vertex_remove};
use crate::vertex_write::{build_vertex_add, own_read_key};

// ---- fixtures ------------------------------------------------------------

static COUNTER: AtomicU64 = AtomicU64::new(0);
// 32-byte AES key for the encrypted keystore (deterministic, test-only).
const TEST_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// A fresh `FileKeyManager` in a temp keystore with the standard PQ key set
/// created (`q-prover-key` Falcon, `q-onion-key` sntrup761, Decaf448 view/spend).
fn make_km() -> FileKeyManager {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("quil-client-acc-{}-{}", std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let km = FileKeyManager::new(
        dir.join("keys.yml"),
        TEST_KEY_HEX,
        "q-prover-key".into(),
        Box::new(FalconKeyConstructor),
    )
    .unwrap();
    km.ensure_standard_keys().unwrap();
    km
}

/// The Falcon `q-prover-key` public key — the network write/owner key.
fn prover_pubkey(km: &FileKeyManager) -> Vec<u8> {
    km.get_public_key_bytes_by_id("q-prover-key").unwrap()
}

/// Test resolver: the deployment is known and resolves the domain to the given
/// write + owner keys. Models the "valid precondition" — a deployed domain whose
/// authority is the signer.
struct StaticResolver {
    write: Vec<u8>,
    owner: Vec<u8>,
}
impl HypergraphConfigResolver for StaticResolver {
    fn write_public_key(&self, _domain: &[u8]) -> Option<Vec<u8>> {
        Some(self.write.clone())
    }
    fn owner_public_key(&self, _domain: &[u8]) -> Option<Vec<u8>> {
        Some(self.owner.clone())
    }
}

/// Resolver for an unknown domain (no deployment) — every op must be rejected.
struct UnknownResolver;
impl HypergraphConfigResolver for UnknownResolver {
    fn write_public_key(&self, _domain: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

fn resolver_for(km: &FileKeyManager) -> Arc<dyn HypergraphConfigResolver> {
    let pk = prover_pubkey(km);
    Arc::new(StaticResolver {
        write: pk.clone(),
        owner: pk,
    })
}

const DOMAIN: [u8; 32] = [0xAB; 32];

// ---- hypergraph ops (verify_op_signature) --------------------------------

#[test]
fn vertex_add_is_accepted() {
    let km = make_km();
    let raw = b"nameQuilibrium".to_vec();
    let data_address = Sha3_256::digest(&raw).to_vec();
    let read_pk = own_read_key(&km).unwrap();

    let op = build_vertex_add(&km, &DOMAIN, &data_address, &raw, &read_pk).unwrap();
    let internal = hgtypes::VertexAdd::from_proto(&op);
    let resolver = resolver_for(&km);
    assert_eq!(
        verify_op_signature(&resolver, &OpForAuth::VertexAdd(&internal)).unwrap(),
        AuthCheck::Verified
    );
}

#[test]
fn vertex_remove_is_accepted() {
    let km = make_km();
    let data_address = vec![0x42u8; 32];
    let op = build_vertex_remove(&km, &DOMAIN, &data_address).unwrap();
    let internal = hgtypes::VertexRemove::from_proto(&op);
    let resolver = resolver_for(&km);
    assert_eq!(
        verify_op_signature(&resolver, &OpForAuth::VertexRemove(&internal)).unwrap(),
        AuthCheck::Verified
    );
}

#[test]
fn hyperedge_add_is_accepted() {
    let km = make_km();
    // A hyperedge under domain D has app == D (domain-binding is enforced
    // before the signature check).
    let app: [u8; 32] = DOMAIN;
    let data = [0x22u8; 32];
    let mut atom = [0u8; 64];
    atom[..32].copy_from_slice(&app);
    atom[32..].copy_from_slice(&data);

    let op = build_hyperedge_add(&km, &DOMAIN, &app, &data, &[atom]).unwrap();
    // The node recomputes the extrinsic commitment from the op's value bytes.
    let commit = hyperedge_extrinsic_commit(&op.value).unwrap();
    let internal = hgtypes::HyperedgeAdd::from_proto(&op);
    let resolver = resolver_for(&km);
    assert_eq!(
        verify_op_signature(
            &resolver,
            &OpForAuth::HyperedgeAdd {
                op: &internal,
                commit: &commit
            }
        )
        .unwrap(),
        AuthCheck::Verified
    );
}

#[test]
fn hyperedge_remove_is_accepted() {
    let km = make_km();
    let mut id = [0u8; 64];
    id[..32].copy_from_slice(&DOMAIN); // app == domain
    id[32..].copy_from_slice(&[0x22u8; 32]);

    let op = build_hyperedge_remove(&km, &DOMAIN, &id).unwrap();
    let internal = hgtypes::HyperedgeRemove::from_proto(&op);
    let resolver = resolver_for(&km);
    assert_eq!(
        verify_op_signature(&resolver, &OpForAuth::HyperedgeRemove(&internal)).unwrap(),
        AuthCheck::Verified
    );
}

#[test]
fn hypergraph_op_rejected_under_wrong_write_key() {
    let km = make_km();
    let other = make_km();
    let op = build_vertex_remove(&km, &DOMAIN, &vec![0x42u8; 32]).unwrap();
    let internal = hgtypes::VertexRemove::from_proto(&op);
    // Resolver returns a DIFFERENT domain write key → signature must fail.
    let resolver: Arc<dyn HypergraphConfigResolver> = Arc::new(StaticResolver {
        write: prover_pubkey(&other),
        owner: vec![],
    });
    assert_eq!(
        verify_op_signature(&resolver, &OpForAuth::VertexRemove(&internal)).unwrap(),
        AuthCheck::Invalid
    );
}

#[test]
fn hypergraph_op_rejected_for_unknown_domain() {
    let km = make_km();
    let op = build_vertex_remove(&km, &DOMAIN, &vec![0x42u8; 32]).unwrap();
    let internal = hgtypes::VertexRemove::from_proto(&op);
    let resolver: Arc<dyn HypergraphConfigResolver> = Arc::new(UnknownResolver);
    assert_eq!(
        verify_op_signature(&resolver, &OpForAuth::VertexRemove(&internal)).unwrap(),
        AuthCheck::UnknownDomain
    );
}

// ---- deploy updates (owner-key signature) --------------------------------

/// Mirror the node's compute/token update verify: re-encode the update with the
/// signature field cleared, canonicalize, and validate the Falcon owner sig
/// under `domain ‖ TAG` against the prior owner key.
fn falcon_ok(km: &FileKeyManager, owner: &[u8], msg: &[u8], sig: &[u8], domain_sep: &[u8]) -> bool {
    km.validate_signature(KeyType::Falcon512, owner, msg, sig, domain_sep)
        .unwrap()
}

#[test]
fn compute_update_is_accepted() {
    let km = make_km();
    let owner = prover_pubkey(&km);
    let cfg = ComputeConfiguration {
        read_public_key: own_read_key(&km).unwrap(),
        write_public_key: owner.clone(),
        owner_public_key: owner.clone(),
    };
    let signed = build_compute_update(&km, &DOMAIN, cfg, Vec::new(), None).unwrap();

    let sig = signed
        .public_key_signature_bls48581
        .as_ref()
        .unwrap()
        .signature
        .clone();
    let mut unsigned = signed.clone();
    unsigned.public_key_signature_bls48581 = None;
    let msg = compute_update_from_proto(&unsigned)
        .unwrap()
        .to_canonical_bytes()
        .unwrap();

    let mut sep = DOMAIN.to_vec();
    sep.extend_from_slice(b"COMPUTE_UPDATE");
    assert!(falcon_ok(&km, &owner, &msg, &sig, &sep));

    // Wrong domain separator (e.g. TOKEN_UPDATE) must not verify.
    let mut wrong = DOMAIN.to_vec();
    wrong.extend_from_slice(b"TOKEN_UPDATE");
    assert!(!falcon_ok(&km, &owner, &msg, &sig, &wrong));
}

#[test]
fn token_update_is_accepted() {
    let km = make_km();
    let owner = prover_pubkey(&km);
    let cfg = TokenConfiguration {
        owner_public_key: owner.clone(),
        name: "Test".into(),
        symbol: "TST".into(),
        ..Default::default()
    };
    let signed = build_token_update(&km, &DOMAIN, cfg, None).unwrap();

    let sig = signed
        .public_key_signature_bls48581
        .as_ref()
        .unwrap()
        .signature
        .clone();
    let mut unsigned = signed.clone();
    unsigned.public_key_signature_bls48581 = None;
    let msg = token_update_from_proto(&unsigned)
        .unwrap()
        .to_canonical_bytes()
        .unwrap();

    let mut sep = DOMAIN.to_vec();
    sep.extend_from_slice(b"TOKEN_UPDATE");
    assert!(falcon_ok(&km, &owner, &msg, &sig, &sep));
}

/// A paid-mint token as the chain holds it, with every field set.
fn deployed_paid_mint_token(owner: Vec<u8>) -> TokenConfiguration {
    TokenConfiguration {
        // Mintable, burnable, acceptable.
        behavior: 0b1011,
        mint_strategy: Some(TokenMintStrategy {
            mint_behavior: TokenMintBehavior::MintWithPayment as i32,
            payment_address: vec![0x5a; 32],
            fee_basis: Some(FeeBasis {
                r#type: FeeBasisType::PerUnit as i32,
                baseline: vec![0x03, 0xe8],
            }),
            ..Default::default()
        }),
        units: vec![0x01],
        supply: vec![0x27, 0x10],
        name: "Example".into(),
        symbol: "EXM".into(),
        additional_reference: vec![vec![0x7c; 64]],
        owner_public_key: owner,
    }
}

/// An update that renames a token must leave every other field as the chain
/// holds it: the node replaces the whole configuration with the update's.
#[test]
fn token_update_keeps_unchanged_config_fields() {
    use quil_execution::token_intrinsic::metadata_schema::{
        build_token_configuration_metadata_tree, decode_token_config_from_tree,
    };
    use quil_execution::token_intrinsic::TokenConfiguration as CanonicalTokenConfiguration;

    let km = make_km();
    let owner = prover_pubkey(&km);
    let current = deployed_paid_mint_token(owner.clone());
    let cfg = updated_config(&current, &["name=Renamed".to_string()]).unwrap();
    let signed = build_token_update(&km, &DOMAIN, cfg, None).unwrap();

    // The node's reading: the canonical update, signed by the current owner.
    let sig = signed
        .public_key_signature_bls48581
        .as_ref()
        .unwrap()
        .signature
        .clone();
    let mut unsigned = signed.clone();
    unsigned.public_key_signature_bls48581 = None;
    let update = token_update_from_proto(&unsigned).unwrap();
    let msg = update.to_canonical_bytes().unwrap();
    let mut sep = DOMAIN.to_vec();
    sep.extend_from_slice(b"TOKEN_UPDATE");
    assert!(falcon_ok(&km, &owner, &msg, &sig, &sep));

    // The configuration the node writes, read back as the node reads it.
    let stored = |cfg: &CanonicalTokenConfiguration| {
        let tree = build_token_configuration_metadata_tree(cfg).unwrap();
        decode_token_config_from_tree(&tree).unwrap()
    };
    let got = stored(&CanonicalTokenConfiguration::from_canonical_bytes(&update.config).unwrap());
    let mut renamed = current.clone();
    renamed.name = "Renamed".into();
    let want = stored(&token_config_from_proto(&renamed).unwrap());

    assert_eq!(got.name, b"Renamed".to_vec(), "update lost the new name");
    let unchanged = [
        ("behavior", got.behavior == want.behavior),
        ("mint strategy", got.mint_strategy == want.mint_strategy),
        ("units", got.units == want.units),
        ("supply", got.supply == want.supply),
        ("symbol", got.symbol == want.symbol),
        (
            "additional reference",
            got.additional_reference.concat() == want.additional_reference.concat(),
        ),
        ("owner key", got.owner_public_key == want.owner_public_key),
    ];
    let erased: Vec<&str> = unchanged
        .iter()
        .filter(|(_, same)| !same)
        .map(|(field, _)| *field)
        .collect();
    assert!(
        erased.is_empty(),
        "update erased unchanged fields: {erased:?}"
    );
}

#[test]
fn hypergraph_update_is_accepted() {
    let km = make_km();
    let owner = prover_pubkey(&km);
    let cfg = HypergraphConfiguration {
        read_public_key: own_read_key(&km).unwrap(),
        write_public_key: owner.clone(),
        owner_public_key: owner.clone(),
    };
    let signed = build_hypergraph_update(&km, &DOMAIN, cfg, Vec::new(), None).unwrap();

    let sig = signed
        .public_key_signature_bls48581
        .as_ref()
        .unwrap()
        .signature
        .clone();
    let mut unsigned = signed.clone();
    unsigned.public_key_signature_bls48581 = None;
    let msg = CanonicalHypergraphUpdate::from_proto(&unsigned)
        .unwrap()
        .to_canonical_bytes_without_signature()
        .unwrap();

    // The node's verify_update_signature validates the Falcon owner sig under
    // `domain ‖ "HYPERGRAPH_UPDATE"` against the resolved owner key — the same
    // underlying check as falcon_ok here (with owner = the resolved key).
    let mut sep = DOMAIN.to_vec();
    sep.extend_from_slice(b"HYPERGRAPH_UPDATE");
    assert!(falcon_ok(&km, &owner, &msg, &sig, &sep));
}

// ---- compute execute (proof-of-payment) ----------------------------------

#[test]
fn code_execute_is_accepted() {
    let km = make_km();
    let rendezvous = vec![0x33u8; 32];
    let main_op = ExecuteOperation {
        application: Some(Application {
            address: DOMAIN.to_vec(),
            execution_context: ExecutionContext::Hypergraph as i32,
        }),
        identifier: b"default".to_vec(),
        dependencies: Vec::new(),
    };
    let op = build_code_execute(&km, &DOMAIN, &rendezvous, vec![main_op]).unwrap();
    // The engine converts the proto op to its canonical form before verifying.
    let internal = code_execute_from_proto(&op).unwrap();
    assert!(verify_code_execute(&internal).unwrap());

    // Tampering the rendezvous (what the payment sig covers) must be rejected —
    // verify_code_execute returns Err on a bad payment signature.
    let mut bad = op.clone();
    bad.rendezvous = vec![0x44u8; 32];
    let bad_internal = code_execute_from_proto(&bad).unwrap();
    assert!(verify_code_execute(&bad_internal).is_err());
}

// ---- token mint (authorization signature) --------------------------------

/// From the config replay frame a token update the client signs over the
/// stored configuration applies through the node's own token engine
/// (validate and process, real Falcon verification), and once a later update
/// replaced that configuration the same update is refused: it cannot restore
/// what it set. An update signed over its domain alone, as before the frame,
/// is refused.
#[test]
fn a_client_signed_token_update_applies_only_to_the_configuration_it_replaces() {
    use quil_execution::config_replay::{
        metadata_vertex_binding, set_config_replay_frame_for_thread,
    };
    use quil_execution::engines::{ExecutionMode, TokenExecutionEngine};
    use quil_execution::hypergraph_state::{
        vertex_adds_discriminator, HypergraphState, HYPERGRAPH_METADATA_ADDRESS,
    };
    use quil_execution::message_envelope::CanonicalMessageRequest;
    use quil_execution::token_intrinsic::constants::token_base_domain;
    use quil_execution::token_intrinsic::materialize::token_deploy_domain;
    use quil_execution::token_intrinsic::TokenDeploy;
    use quil_types::crypto::NoopInclusionProver;
    use quil_types::execution::ShardExecutionEngine;

    use crate::commands::deploy::token_update::config_from_metadata_vertex;

    set_config_replay_frame_for_thread(Some(0));
    let km = make_km();
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_hypergraph::testing::MemStore::new()),
        Arc::new(NoopInclusionProver),
    ));
    let engine = TokenExecutionEngine::new_with_state(
        ExecutionMode::Application,
        Arc::new(NoopInclusionProver),
        crdt.clone(),
        Arc::new(quil_crypto::DefaultKeyManager::new()),
        Arc::new(quil_execution::testing::NoopClockStore),
    );
    let apply = |frame: u64, address: &[u8], inner: Vec<u8>| -> quil_types::error::Result<()> {
        let message = CanonicalMessageRequest::wrap(inner)?.to_canonical_bytes()?;
        engine.validate_message(frame, address, &message)?;
        engine
            .process_message(frame, &num_bigint::BigInt::from(0), address, &message)
            .map(|_| ())
    };
    let canonical = |update: &quil_types::proto::token::TokenUpdate| {
        token_update_from_proto(update)
            .unwrap()
            .to_canonical_bytes()
            .unwrap()
    };

    let deployed = TokenConfiguration {
        behavior: 1,
        units: vec![1],
        name: "Client".into(),
        symbol: "CLI".into(),
        owner_public_key: prover_pubkey(&km),
        ..Default::default()
    };
    let deployed = token_config_from_proto(&deployed).unwrap();
    let domain = token_deploy_domain(&deployed).unwrap();
    let deploy = TokenDeploy {
        config: deployed.to_canonical_bytes().unwrap(),
        rdf_schema: Vec::new(),
    };
    apply(
        10,
        &token_base_domain(),
        deploy.to_canonical_bytes().unwrap(),
    )
    .expect("harness: the deploy applies");
    // The token as the client reads it: its configuration and the binding
    // the update signs over.
    let current = || {
        let blob = HypergraphState::new(crdt.clone())
            .get(
                &domain,
                &HYPERGRAPH_METADATA_ADDRESS,
                &vertex_adds_discriminator().unwrap(),
            )
            .unwrap()
            .expect("token metadata vertex");
        (
            config_from_metadata_vertex(&blob).unwrap(),
            metadata_vertex_binding(&blob).unwrap(),
        )
    };
    let rename = |name: &str| {
        let (cfg, prior) = current();
        let cfg = updated_config(&cfg, &[format!("name={name}")]).unwrap();
        build_token_update(&km, &domain, cfg, Some(prior.as_slice())).unwrap()
    };

    let first = rename("One");
    apply(11, &domain, canonical(&first)).unwrap_or_else(|e| {
        panic!(
            "CLIENT: the node refused the client's update signed over the stored \
             configuration: {e}"
        )
    });
    assert_eq!(
        current().0.name,
        "One",
        "harness: the first update took effect"
    );
    let second = rename("Two");
    apply(12, &domain, canonical(&second)).expect("harness: the second update applies");

    let replay = apply(13, &domain, canonical(&first));
    let name = current().0.name;
    assert!(
        name == "Two",
        "REPLAY-ACCEPTED (client update replay): the first update applied again ({replay:?}) \
         and restored name {name}"
    );

    let (cfg, _) = current();
    let cfg = updated_config(&cfg, &["name=Unbound".to_string()]).unwrap();
    let unbound = build_token_update(&km, &domain, cfg, None).unwrap();
    let refused = apply(14, &domain, canonical(&unbound));
    assert!(
        refused.is_err() && current().0.name == "Two",
        "UNBOUND: an update signed over its domain alone applied ({refused:?})"
    );
    set_config_replay_frame_for_thread(None);
}

/// The compute update the client signs over the stored metadata verifies
/// under the separator the node's compute engine uses from the config replay
/// frame, and an unbound one does not; before the frame the reverse.
/// (Compute updates do not apply today, so this checks the separator alone.)
#[test]
fn a_client_signed_compute_update_binds_the_metadata_it_replaces() {
    use quil_execution::config_replay::{stored_binding, update_separator, COMPUTE_UPDATE_TAG};
    use quil_execution::hypergraph_state::HypergraphState;
    use quil_types::execution::{FrameExecutionContext, ShardPath};

    quil_execution::config_replay::set_config_replay_frame_for_thread(Some(100));
    let km = make_km();
    let owner = prover_pubkey(&km);
    let cfg = ComputeConfiguration {
        read_public_key: own_read_key(&km).unwrap(),
        write_public_key: owner.clone(),
        owner_public_key: owner.clone(),
    };
    let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_hypergraph::testing::MemStore::new()),
        Arc::new(quil_types::crypto::NoopInclusionProver),
    )));
    let canonical = quil_execution::compute_intrinsic::conversions::compute_config_from_proto(&cfg);
    let schema = b"@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\
        @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n\
        @prefix qcl: <https://types.quilibrium.com/qcl/> .\n\
        :Note a rdfs:Class .\n:Field a rdfs:Property ;\n  rdfs:domain qcl:Uint ;\n  \
        qcl:size 8 ;\n  qcl:order 0 ;\n  rdfs:range :Note .\n";
    let domain = quil_execution::compute_intrinsic::materialize::materialize_compute_deploy_init(
        &state,
        &canonical,
        schema,
        1,
        &quil_types::crypto::NoopInclusionProver,
    )
    .unwrap();
    let at = |frame_number| FrameExecutionContext {
        frame_number,
        finalized_global_frame: None,
        shard: ShardPath::WHOLE,
        venue: None,
    };
    let signed = |binding: Option<&[u8]>| {
        let signed = build_compute_update(&km, &domain, cfg.clone(), Vec::new(), binding).unwrap();
        let sig = signed
            .public_key_signature_bls48581
            .as_ref()
            .unwrap()
            .signature
            .clone();
        let mut unsigned = signed;
        unsigned.public_key_signature_bls48581 = None;
        let msg = compute_update_from_proto(&unsigned)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        (msg, sig)
    };
    let binding = stored_binding(&state, &domain).unwrap().unwrap();
    let (bound_msg, bound_sig) = signed(Some(&binding));
    let (unbound_msg, unbound_sig) = signed(None);
    let node = |frame| update_separator(&state, &domain, COMPUTE_UPDATE_TAG, at(frame)).unwrap();

    assert!(
        falcon_ok(&km, &owner, &bound_msg, &bound_sig, &node(100))
            && !falcon_ok(&km, &owner, &unbound_msg, &unbound_sig, &node(100)),
        "COMPUTE-BINDING: from the frame the node's separator does not take exactly the \
         bound update"
    );
    assert!(
        falcon_ok(&km, &owner, &unbound_msg, &unbound_sig, &node(99))
            && !falcon_ok(&km, &owner, &bound_msg, &bound_sig, &node(99)),
        "COMPUTE-BINDING: before the frame the node's separator does not take exactly the \
         unbound update"
    );
    quil_execution::config_replay::set_config_replay_frame_for_thread(None);
}

//! Acceptance tests for the requests the client *emits*.
//!
//! For every signed request the client builds, we construct it via the client's
//! real `build_*` code path, then run it through the **node's own** verification
//! function and assert it would be accepted. These pin the parts the client is
//! solely responsible for — canonical byte layout, signing domain/separator, key
//! selection, and proto shape — so a drift in either the client's construction
//! or the node's verify will fail here.
//!
//! Scope: signature + structural verification that is independent of chain
//! state. State preconditions (a deployed domain resolving to the signer's write
//! /owner key, a coin existing in the shadow accumulator, a claimable reward
//! balance) are assumed valid and modelled by the resolver / inputs — they are
//! the network's precondition, not the client's output. The lattice spend paths
//! (transfer/split/merge, escrow create/claim) additionally require a seeded
//! accumulator root and are covered at the money-conservation level in
//! `quil-execution`; here we cover their client-owned authorization signature
//! (mint), which is the state-independent half.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use sha3::{Digest, Sha3_256};

use quil_crypto::FalconKeyConstructor;
use quil_execution::compute_intrinsic::conversions::{code_execute_from_proto, compute_update_from_proto};
use quil_execution::compute_intrinsic::intrinsic::verify_code_execute;
use quil_execution::domains::QUIL_TOKEN;
// Internal (canonical) hypergraph op types the node verifies against; the engine
// converts the proto ops the client emits into these via `from_proto` before
// calling `verify_op_signature`. We do the same in these tests.
use quil_execution::hypergraph_intrinsic::types as hgtypes;
use quil_execution::hypergraph_intrinsic::{
    hyperedge_extrinsic_commit, verify_op_signature, AuthCheck, HypergraphConfigResolver,
    HypergraphUpdate as CanonicalHypergraphUpdate, OpForAuth,
};
use quil_execution::token_intrinsic::conversions::token_update_from_proto;
use quil_execution::token_intrinsic::lattice_ct::{
    mint_auth_message, tx_challenge, verify_mint_auth_signature,
};
use quil_keys::FileKeyManager;
use quil_types::crypto::KeyType;
use quil_types::proto::compute::{
    Application, ComputeConfiguration, ExecuteOperation, ExecutionContext,
};
use quil_types::proto::hypergraph::HypergraphConfiguration;
use quil_types::proto::token::TokenConfiguration;

use crate::commands::compute::build_code_execute;
use crate::commands::deploy::compute_update::build_compute_update;
use crate::commands::deploy::hypergraph_update::build_hypergraph_update;
use crate::commands::deploy::token_update::build_token_update;
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
    let dir = std::env::temp_dir().join(format!(
        "quil-client-acc-{}-{}",
        std::process::id(),
        n
    ));
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
    let signed = build_compute_update(&km, &DOMAIN, cfg, Vec::new()).unwrap();

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
    let signed = build_token_update(&km, &DOMAIN, cfg).unwrap();

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

#[test]
fn hypergraph_update_is_accepted() {
    let km = make_km();
    let owner = prover_pubkey(&km);
    let cfg = HypergraphConfiguration {
        read_public_key: own_read_key(&km).unwrap(),
        write_public_key: owner.clone(),
        owner_public_key: owner.clone(),
    };
    let signed = build_hypergraph_update(&km, &DOMAIN, cfg, Vec::new()).unwrap();

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

#[test]
fn mint_authorization_signature_is_accepted() {
    let km = make_km();
    let owner = prover_pubkey(&km);
    let domain = QUIL_TOKEN.to_vec();
    let value: u128 = 12_345;
    // The mint auth signature binds the outputs via mu = tx_challenge(...); the
    // exact output commitments are the accumulator's business — here we exercise
    // the client-owned authorization contract (same helpers the mint command
    // uses) with a representative commitment.
    let output_commitments = vec![vec![7u8; 32]];
    let mu = tx_challenge(&domain, &output_commitments, value);

    let signer = km.get_signer_by_id("q-prover-key").unwrap();
    let sig = signer
        .sign_with_domain(&mint_auth_message(value, &mu), &domain)
        .unwrap();

    assert!(verify_mint_auth_signature(&owner, &sig, value, &mu, &domain));
    // Claiming a different value than was signed must fail.
    assert!(!verify_mint_auth_signature(&owner, &sig, value + 1, &mu, &domain));
}

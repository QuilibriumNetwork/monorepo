//! Owner-signed updates of hypergraph and token applications must apply only
//! to the state they were signed against: neither a superseded hypergraph
//! update nor a token update whose configuration came back may apply again.

use super::*;
use crate::message_envelope::CanonicalMessageRequest;
use crate::token_intrinsic::{
    constants::token_base_domain, materialize, metadata_schema, TokenConfiguration, TokenDeploy,
    TokenUpdate,
};
use quil_crypto::FalconSigner;
use quil_types::crypto::{NoopInclusionProver, Signer};
use quil_types::execution::ShardExecutionEngine;

fn crdt() -> Arc<quil_hypergraph::HypergraphCrdt> {
    Arc::new(quil_hypergraph::HypergraphCrdt::new(
        Arc::new(quil_hypergraph::testing::MemStore::new()),
        Arc::new(NoopInclusionProver),
    ))
}

/// Apply one request through `engine` (fee multiplier 0).
fn apply(
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

/// The separator an owner signs an update of `domain` under (`tag` names the
/// application kind), as clients sign it from the config replay frame: bound
/// to the metadata vertex `state` holds for it.
fn separator(
    state: &crate::hypergraph_state::HypergraphState,
    domain: &[u8; 32],
    tag: &[u8],
) -> Vec<u8> {
    let binding = crate::config_replay::stored_binding(state, domain)
        .unwrap()
        .expect("metadata vertex");
    crate::config_replay::update_signing_domain(domain, tag, Some(&binding))
}

/// Resolves a hypergraph's write key and schema from committed state, as the
/// production resolver does, and its owner key from `owner`: the production
/// resolver resolves none, so it authorizes no update at all.
struct OwnerResolver {
    inner: crate::hypergraph_intrinsic::CrdtHypergraphConfigResolver,
    owner: Vec<u8>,
}

impl crate::hypergraph_intrinsic::HypergraphConfigResolver for OwnerResolver {
    fn for_execution_context(
        &self,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    ) -> Result<Arc<dyn crate::hypergraph_intrinsic::HypergraphConfigResolver>> {
        Ok(Arc::new(Self {
            inner: crate::hypergraph_intrinsic::CrdtHypergraphConfigResolver::new(crdt),
            owner: self.owner.clone(),
        }))
    }
    fn write_public_key(&self, domain: &[u8]) -> Option<Vec<u8>> {
        self.inner.write_public_key(domain)
    }
    fn owner_public_key(&self, _domain: &[u8]) -> Option<Vec<u8>> {
        Some(self.owner.clone())
    }
    fn prior_rdf_schema(&self, domain: &[u8]) -> Option<Vec<u8>> {
        self.inner.prior_rdf_schema(domain)
    }
}

fn schema() -> Vec<u8> {
    b"@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n\
      @prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n\
      @prefix qcl: <https://types.quilibrium.com/qcl/> .\n\
      :Note a rdfs:Class .\n\
      :Field a rdfs:Property ;\n  rdfs:domain qcl:Uint ;\n  qcl:size 8 ;\n  \
      qcl:order 0 ;\n  rdfs:range :Note .\n"
        .to_vec()
}

fn hypergraph_config(
    owner: &FalconSigner,
    write: &FalconSigner,
) -> crate::hypergraph_intrinsic::HypergraphConfiguration {
    crate::hypergraph_intrinsic::HypergraphConfiguration {
        read_public_key: vec![7; quil_crypto::SNTRUP761_PUBLIC_KEY_LEN],
        write_public_key: write.public_key().to_vec(),
        owner_public_key: owner.public_key().to_vec(),
    }
}

/// A hypergraph update to `cfg` signed by `owner` under `sep`.
fn hypergraph_update(
    cfg: &crate::hypergraph_intrinsic::HypergraphConfiguration,
    owner: &FalconSigner,
    sep: &[u8],
) -> Vec<u8> {
    let mut update = crate::hypergraph_intrinsic::HypergraphUpdate {
        config: Some(cfg.clone()),
        rdf_schema: Vec::new(),
        public_key_signature_bls48581: None,
    };
    let message = update.to_canonical_bytes_without_signature().unwrap();
    update.public_key_signature_bls48581 = Some(crate::hypergraph_intrinsic::AggregateSignature {
        signature: owner.sign_with_domain(&message, sep).unwrap(),
        public_key: None,
        bitmask: Vec::new(),
    });
    update.to_canonical_bytes().unwrap()
}

/// A deployed hypergraph: its engine, state and domain.
type Deployed = (
    HypergraphExecutionEngine,
    Arc<quil_hypergraph::HypergraphCrdt>,
    [u8; 32],
);

/// A hypergraph deployed by `owner` with write key `write`, on an engine
/// whose resolver resolves `resolver_owner` as its owner (none: the
/// production resolver).
fn deployed_hypergraph(
    owner: &FalconSigner,
    write: &FalconSigner,
    resolver_owner: Option<Vec<u8>>,
) -> Deployed {
    let crdt = crdt();
    let resolver: Arc<dyn crate::hypergraph_intrinsic::HypergraphConfigResolver> =
        match resolver_owner {
            Some(owner) => Arc::new(OwnerResolver {
                inner: crate::hypergraph_intrinsic::CrdtHypergraphConfigResolver::new(crdt.clone()),
                owner,
            }),
            None => Arc::new(
                crate::hypergraph_intrinsic::CrdtHypergraphConfigResolver::new(crdt.clone()),
            ),
        };
    let engine = HypergraphExecutionEngine::new_with_state(
        ExecutionMode::Application,
        crdt.clone(),
        resolver,
    )
    .with_key_manager(Arc::new(quil_crypto::DefaultKeyManager::new()));
    let cfg = hypergraph_config(owner, write);
    let domain = crate::hypergraph_intrinsic::hypergraph_deploy_domain(&cfg).unwrap();
    let deploy = crate::hypergraph_intrinsic::HypergraphDeploy {
        config: Some(cfg),
        rdf_schema: schema(),
    }
    .to_canonical_bytes()
    .unwrap();
    apply(
        &engine,
        10,
        &crate::hypergraph_intrinsic::hypergraph_base_domain(),
        deploy,
    )
    .expect("harness: the hypergraph deploy applies");
    (engine, crdt, domain)
}

/// The write key committed state resolves for `domain`.
fn write_key(crdt: &Arc<quil_hypergraph::HypergraphCrdt>, domain: &[u8; 32]) -> Vec<u8> {
    use crate::hypergraph_intrinsic::HypergraphConfigResolver;
    crate::hypergraph_intrinsic::CrdtHypergraphConfigResolver::new(crdt.clone())
        .write_public_key(domain)
        .expect("hypergraph write key")
}

/// Sibling: an owner-signed hypergraph update binds only (domain,
/// update), so the owner's earlier update applied again restores the write
/// key a later one replaced. Latent: the production resolver resolves no
/// owner key, so no hypergraph update applies on a regular node today.
#[test]
fn reproduces_a_replayed_hypergraph_update_restoring_a_superseded_write_key() {
    let owner = FalconSigner::generate();
    let (w0, w1, w2) = (
        FalconSigner::generate(),
        FalconSigner::generate(),
        FalconSigner::generate(),
    );
    let (engine, crdt, domain) =
        deployed_hypergraph(&owner, &w0, Some(owner.public_key().to_vec()));
    let state = engine.state.clone().unwrap();
    let sep = separator(&state, &domain, b"HYPERGRAPH_UPDATE");
    let first = hypergraph_update(&hypergraph_config(&owner, &w1), &owner, &sep);
    apply(&engine, 11, &domain, first.clone()).unwrap_or_else(|e| {
        panic!("HYPERGRAPH-BINDING: the owner's bound update was refused: {e}")
    });
    let sep = separator(&state, &domain, b"HYPERGRAPH_UPDATE");
    let second = hypergraph_update(&hypergraph_config(&owner, &w2), &owner, &sep);
    apply(&engine, 12, &domain, second).expect("harness: the second update applies");
    assert_eq!(
        write_key(&crdt, &domain),
        w2.public_key(),
        "harness: the second update took effect"
    );

    let replay = apply(&engine, 13, &domain, first);
    assert!(
        write_key(&crdt, &domain) == w2.public_key(),
        "REPLAY-ACCEPTED (hypergraph update replay): the owner's superseded update applied \
         again ({replay:?}) and restored the superseded write key"
    );
}

fn token_engine() -> TokenExecutionEngine {
    TokenExecutionEngine::new_with_state(
        ExecutionMode::Application,
        Arc::new(NoopInclusionProver),
        crdt(),
        Arc::new(quil_crypto::DefaultKeyManager::new()),
        Arc::new(crate::testing::NoopClockStore),
    )
}

fn token_config(name: &[u8], owner: &FalconSigner) -> TokenConfiguration {
    TokenConfiguration {
        behavior: 1,
        units: vec![1],
        name: name.to_vec(),
        symbol: b"RTN".to_vec(),
        owner_public_key: owner.public_key().to_vec(),
        ..Default::default()
    }
}

/// A token update to `cfg` signed by `owner` under `sep`.
fn token_update(cfg: &TokenConfiguration, owner: &FalconSigner, sep: &[u8]) -> Vec<u8> {
    let mut update = TokenUpdate {
        config: cfg.to_canonical_bytes().unwrap(),
        rdf_schema: Vec::new(),
        public_key_signature_bls48581: Vec::new(),
    };
    update.public_key_signature_bls48581 = owner
        .sign_with_domain(&update.to_canonical_bytes().unwrap(), sep)
        .unwrap();
    update.to_canonical_bytes().unwrap()
}

/// The token name the chain holds for `domain`.
fn token_name(engine: &TokenExecutionEngine, domain: &[u8; 32]) -> Vec<u8> {
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
    let inner = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(
            outer.get(&materialize::TOKEN_CONFIG_OUTER_KEY).unwrap(),
        )
        .unwrap(),
    };
    metadata_schema::decode_token_config_from_tree(&inner)
        .unwrap()
        .name
}

/// The identical-configuration case: the owner renames a token and
/// renames it back. Its configuration is then exactly the one the first
/// update was signed against, so binding an update to the configuration it
/// replaces alone would let the first update apply again.
#[test]
fn reproduces_a_replayed_token_update_returning_from_an_identical_configuration() {
    let engine = token_engine();
    let owner = FalconSigner::generate();
    let original = token_config(b"zero", &owner);
    let domain = materialize::token_deploy_domain(&original).unwrap();
    apply(
        &engine,
        10,
        &token_base_domain(),
        TokenDeploy {
            config: original.to_canonical_bytes().unwrap(),
            rdf_schema: Vec::new(),
        }
        .to_canonical_bytes()
        .unwrap(),
    )
    .expect("harness: the deploy applies");
    // Each update signed over the state as the previous update left it, so
    // `first` is signed against a configuration an update wrote, as is the
    // state it is replayed onto.
    let state = engine.state.clone().unwrap();
    let rename = |cfg: &TokenConfiguration| {
        token_update(cfg, &owner, &separator(&state, &domain, b"TOKEN_UPDATE"))
    };
    let mut frame = 11;
    let mut apply_next = |update: Vec<u8>| {
        frame += 1;
        apply(&engine, frame, &domain, update)
    };
    apply_next(rename(&token_config(b"one", &owner))).expect("harness: the rename applies");
    apply_next(rename(&original)).expect("harness: the rename back applies");
    let first = rename(&token_config(b"two", &owner));
    apply_next(first.clone()).expect("harness: the second rename applies");
    apply_next(rename(&original)).expect("harness: the second rename back applies");
    assert_eq!(
        token_name(&engine, &domain),
        b"zero",
        "harness: renamed back"
    );

    let replay = apply_next(first);
    let name = token_name(&engine, &domain);
    assert!(
        name == b"zero",
        "REPLAY-ACCEPTED (identical configuration): the owner's first update applied again \
         ({replay:?}) and restored name {:?}",
        String::from_utf8_lossy(&name),
    );
}

/// Hypergraph admission knows no frame, so it accepts an owner's update
/// signed either way (and refuses one the owner did not sign); execution
/// from the config replay frame takes only the bound one.
#[test]
fn hypergraph_admission_takes_either_form_and_execution_only_the_bound_one() {
    let owner = FalconSigner::generate();
    let (w0, w1) = (FalconSigner::generate(), FalconSigner::generate());
    let (engine, crdt, domain) =
        deployed_hypergraph(&owner, &w0, Some(owner.public_key().to_vec()));
    let state = engine.state.clone().unwrap();
    let cfg = hypergraph_config(&owner, &w1);
    let bound = hypergraph_update(
        &cfg,
        &owner,
        &separator(&state, &domain, b"HYPERGRAPH_UPDATE"),
    );
    let unbound = hypergraph_update(
        &cfg,
        &owner,
        &[&domain[..], &b"HYPERGRAPH_UPDATE"[..]].concat(),
    );
    let forged = hypergraph_update(
        &cfg,
        &FalconSigner::generate(),
        &separator(&state, &domain, b"HYPERGRAPH_UPDATE"),
    );
    let admit = |inner: &[u8]| {
        let message = CanonicalMessageRequest::wrap(inner.to_vec())
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        engine.validate_message(11, &domain, &message)
    };
    assert!(
        admit(&bound).is_ok() && admit(&unbound).is_ok() && admit(&forged).is_err(),
        "ADMISSION: admission did not take both of the owner's forms and refuse a forged \
         one (bound {:?}, unbound {:?}, forged {:?})",
        admit(&bound),
        admit(&unbound),
        admit(&forged),
    );

    assert!(
        apply(&engine, 11, &domain, unbound).is_err()
            && write_key(&crdt, &domain) == w0.public_key(),
        "UNBOUND: from the frame an unbound hypergraph update applied"
    );
    apply(&engine, 12, &domain, bound).expect("harness: the bound update applies");
    assert_eq!(
        write_key(&crdt, &domain),
        w1.public_key(),
        "harness: rotated"
    );
}

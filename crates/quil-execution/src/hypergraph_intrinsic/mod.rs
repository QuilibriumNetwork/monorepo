//! Hypergraph intrinsic. Port of
//! `node/execution/intrinsics/hypergraph/`.
//!
//! Contains:
//! - `canonical`: length-prefixed binary serialization (byte-compatible
//!   with Go `protobufs/hypergraph.go` ToCanonicalBytes/FromCanonicalBytes).
//! - `types`: Rust representations of the five hypergraph messages plus
//!   the aggregate-signature envelope.

pub mod auth;
pub mod canonical;
pub mod conversions;
pub mod dispatch;
pub mod hyperedge_ops;
pub mod types;
pub mod vertex_ops;

/// `RAW_HYPERGRAPH_PREFIX` — `b"q_hypergraph"` (Go
/// `hypergraph_intrinsic.go:27`).
pub const RAW_HYPERGRAPH_PREFIX: &[u8] = b"q_hypergraph";

/// `poseidon("q_hypergraph")` → HYPERGRAPH_BASE_DOMAIN (Go
/// `hypergraph_intrinsic.go:31-36`). Computed lazily (Poseidon isn't
/// const-evaluable). Used as the hypergraph intrinsic's type-domain and
/// for engine routing.
pub fn hypergraph_base_domain() -> [u8; 32] {
    quil_crypto::poseidon::hash_bytes_to_32(RAW_HYPERGRAPH_PREFIX)
        .expect("poseidon hash of q_hypergraph")
}

/// Build the hypergraph configuration metadata tree — Go
/// `newHypergraphConfigurationMetadata` (hypergraph_intrinsic.go:242-272):
/// read key at `[0<<2]`, write key at `[1<<2]`, each sized `57`.
pub fn build_hypergraph_configuration_metadata_tree(
    config: &types::HypergraphConfiguration,
) -> quil_types::error::Result<quil_tries::VectorCommitmentTree> {
    use num_bigint::BigInt;
    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.insert(&[0u8 << 2], &config.read_public_key, &[], &BigInt::from(57))?;
    tree.insert(&[1u8 << 2], &config.write_public_key, &[], &BigInt::from(57))?;
    Ok(tree)
}

/// Materialize a **new** HypergraphDeploy — Go `HypergraphIntrinsic.Deploy`
/// deploy branch (hypergraph_intrinsic.go:658-707). Derives the new
/// hypergraph app's domain from `poseidon(RAW_HYPERGRAPH_PREFIX ‖
/// config_commit)` and writes the full metadata vertex via
/// `init_metadata_vertex` (empty consensus + sumcheck, supplied RDF
/// schema, config at `additionalData[13]`, type-domain
/// `HYPERGRAPH_BASE_DOMAIN`). `rdf_schema` is supplied by the deploy
/// message. Returns the derived domain.
pub fn materialize_hypergraph_deploy_init(
    state: &crate::hypergraph_state::HypergraphState,
    config: &types::HypergraphConfiguration,
    rdf_schema: &[u8],
    frame_number: u64,
    inclusion_prover: &(dyn quil_types::crypto::InclusionProver + Sync),
) -> quil_types::error::Result<[u8; 32]> {
    let mut config_tree = build_hypergraph_configuration_metadata_tree(config)?;
    let config_commit = config_tree.commit(inclusion_prover);

    let mut preimage = Vec::with_capacity(RAW_HYPERGRAPH_PREFIX.len() + config_commit.len());
    preimage.extend_from_slice(RAW_HYPERGRAPH_PREFIX);
    preimage.extend_from_slice(&config_commit);
    let domain = quil_crypto::poseidon::hash_bytes_to_32(&preimage)?;

    let rdf = std::str::from_utf8(rdf_schema).map_err(|_| {
        quil_types::error::QuilError::InvalidArgument(
            "hypergraph deploy: rdf schema not valid UTF-8".into(),
        )
    })?;

    let mut consensus = quil_tries::VectorCommitmentTree::new();
    let mut sumcheck = quil_tries::VectorCommitmentTree::new();
    let mut additional: Vec<Option<quil_tries::VectorCommitmentTree>> =
        (0..14).map(|_| None).collect();
    additional[13] = Some(config_tree);

    let type_domain = hypergraph_base_domain();
    state.init_metadata_vertex(
        &domain,
        &mut consensus,
        &mut sumcheck,
        rdf,
        &mut additional,
        &type_domain,
        frame_number,
        inclusion_prover,
    )?;
    Ok(domain)
}

/// Materialize a HypergraphUpdate — Go `HypergraphIntrinsic.Deploy` update
/// branch (hypergraph_intrinsic.go:560-630). Loads the existing metadata
/// vertex at `address`, re-seals the config sub-tree at `[16<<2]` (if a
/// config is supplied), and writes a new RDF schema at `[3<<2]` (if
/// supplied), with the only-adds evolution check against the existing
/// `[2<<2]` schema. Byte-parity with Go (incl. the `[3<<2]` write key).
/// Caller has already verified the owner-key signature.
pub fn materialize_hypergraph_update(
    state: &crate::hypergraph_state::HypergraphState,
    address: &[u8],
    config: Option<&types::HypergraphConfiguration>,
    rdf_schema: &[u8],
    frame_number: u64,
    inclusion_prover: &(dyn quil_types::crypto::InclusionProver + Sync),
) -> quil_types::error::Result<()> {
    use num_bigint::BigInt;
    let metadata_addr = crate::hypergraph_state::HYPERGRAPH_METADATA_ADDRESS;
    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
    let blob = state
        .get(address, &metadata_addr, &va_disc)?
        .filter(|b| !b.is_empty())
        .ok_or_else(|| {
            quil_types::error::QuilError::InvalidArgument(
                "hypergraph update: no existing metadata vertex".into(),
            )
        })?;
    let mut outer = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(&blob).map_err(|e| {
            quil_types::error::QuilError::Internal(format!("hypergraph update: deserialize: {e}"))
        })?,
    };

    let existing_rdf = outer.get(&[2u8 << 2]).map(|b| b.to_vec());

    if let Some(cfg) = config {
        let mut config_tree = build_hypergraph_configuration_metadata_tree(cfg)?;
        crate::hypergraph_state::seal_metadata_state_at_index(
            &mut outer,
            &mut config_tree,
            16,
            inclusion_prover,
        )?;
    }

    if !rdf_schema.is_empty() {
        dispatch::validate_rdf_schema_bytes(rdf_schema)?;
        if let Some(old) = existing_rdf.as_ref().filter(|o| !o.is_empty()) {
            dispatch::validate_rdf_schema_evolution(old, rdf_schema)?;
        }
        outer
            .insert(&[3u8 << 2], rdf_schema, &[], &BigInt::from(rdf_schema.len()))
            .map_err(|e| {
                quil_types::error::QuilError::Internal(format!(
                    "hypergraph update: rdf insert: {e}"
                ))
            })?;
    }

    let _ = outer.commit(inclusion_prover);
    let out_blob = quil_tries::serialize_go_tree(outer.root.as_ref()).map_err(|e| {
        quil_types::error::QuilError::Internal(format!("hypergraph update: serialize: {e}"))
    })?;
    state.set(address, &metadata_addr, &va_disc, frame_number, out_blob)?;
    Ok(())
}

pub use types::{
    HyperedgeAdd, HyperedgeRemove, HypergraphConfiguration, HypergraphDeploy,
    HypergraphUpdate, VertexAdd, VertexRemove,
};

pub use canonical::{
    AggregateSignature, Bls48581G2PublicKey, TYPE_BLS48581_AGGREGATE_SIGNATURE,
    TYPE_BLS48581_G2_PUBLIC_KEY, TYPE_HYPEREDGE_ADD, TYPE_HYPEREDGE_REMOVE,
    TYPE_HYPERGRAPH_CONFIGURATION, TYPE_HYPERGRAPH_DEPLOYMENT, TYPE_HYPERGRAPH_UPDATE,
    TYPE_VERTEX_ADD, TYPE_VERTEX_REMOVE,
};

pub use conversions::{
    aggregate_sig_from_proto, aggregate_sig_to_proto, pack_vertex_add_proof_chunks,
    split_vertex_add_proof_chunks,
};

pub use vertex_ops::{
    encrypted_to_vertex_tree, vertex_add_cost_from_proof_count,
    vertex_add_cost_from_raw_len, vertex_add_domain_separator,
    vertex_add_signing_message, vertex_read_addresses, vertex_remove_cost,
    vertex_remove_domain_separator, vertex_remove_signing_message,
    vertex_write_addresses, MAX_VERTEX_ADD_DISK_SIZE, VERENC_COMPRESSED_BYTES,
    VERENC_PROOF_BYTES, VERENC_PROOF_CHARGE_BYTES, VERTEX_ADD_TAG,
    VERTEX_REMOVE_COST, VERTEX_REMOVE_TAG,
};

pub use dispatch::{
    check_sufficient_fee, decode_and_validate, decode_and_validate_deploy,
    decode_and_validate_update, decode_message, dispatch_cost, is_mutating_op,
    lock_addresses_for_input, peek_message_kind, validate_rdf_schema_evolution,
    DispatchedDeploy, DispatchedDeployOrUpdate, DispatchedMessage, DispatchedUpdate,
    HypergraphLockState, MessageKind,
};

pub use auth::{verify_op_signature, AuthCheck, HypergraphConfigResolver, OpForAuth};

pub use hyperedge_ops::{
    assert_hyperedge_domain_matches, extract_hyperedge_id,
    hyperedge_add_cost_from_atom_count, hyperedge_add_domain_separator,
    hyperedge_add_signing_message, hyperedge_id_app_address,
    hyperedge_id_data_address, hyperedge_read_addresses, hyperedge_remove_cost,
    hyperedge_remove_domain_separator, hyperedge_remove_signing_message,
    hyperedge_write_addresses, HYPEREDGE_ADD_TAG, HYPEREDGE_ATOM_TYPE_BYTE,
    HYPEREDGE_ID_LEN, HYPEREDGE_ID_OFFSET, HYPEREDGE_MIN_VALUE_LEN,
    HYPEREDGE_REMOVE_COST, HYPEREDGE_REMOVE_TAG,
};

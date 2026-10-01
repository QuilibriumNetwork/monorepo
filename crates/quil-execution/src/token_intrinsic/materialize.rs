//! Shared coin field storage, content addresses, spend markers and token metadata.

use num_bigint::BigInt;
use sha2::{Digest, Sha512};
use quil_types::error::{QuilError, Result};

pub const TOKEN_CONFIG_OUTER_KEY: [u8; 1] = [16u8 << 2];

/// Content-hash address for a coin vertex once KZG is retired from the token
/// path (forest cutover). The legacy derivation was
/// `poseidon(KZG_commitment_of_the_vertex_tree)` — a BLS48-581 G1 multiexp
/// purely to produce a stable 32-byte id. The forest replacement hashes the
/// coin's flat field set directly: `poseidon(SHA-512(field_key ‖ value …))`
/// over the tree's leaves in nibble order (the same order the flatten commits
/// them, so the address is a deterministic function of exactly the committed
/// content). This removes the last BLS48-581 dependency from the token
/// materialize path. Existing (pre-cutover) coins keep their opaque
/// historical addresses — this only assigns addresses to newly minted coins.
/// Vertex key holding a coin's accumulator position.
pub const COIN_POSITION_KEY: [u8; 1] = [4u8 << 2];

/// A coin's identity: its content WITHOUT the accumulator position.
///
/// The position cannot be part of the identity, because the identity is what
/// decides the position: a coin's block is derived from its address, and the
/// shard that stores the coin is the one that owns that block. Hashing the
/// position in would make that circular.
///
/// Nothing is weakened by leaving it out. The identity already covers the
/// frame, the one-time owner key, the amount commitment and the memo, each
/// carrying per-coin randomness, so two coins cannot share one. The position
/// is still committed state — it lives in the vertex and every node recomputes
/// it by replaying the same staging, which places it in the block the address
/// selects. (Nothing re-checks that at execution: positions are never taken
/// from a transaction. Wallets check it on scanned coins, because a serving
/// peer could lie about a position.)
pub fn coin_identity_address(tree: &quil_tries::VectorCommitmentTree) -> Result<[u8; 32]> {
    let mut h = Sha512::new();
    for (k, v) in tree.leaves() {
        if k.as_slice() == COIN_POSITION_KEY {
            continue;
        }
        h.update((k.len() as u32).to_be_bytes());
        h.update(&k);
        h.update((v.len() as u32).to_be_bytes());
        h.update(&v);
    }
    let digest = h.finalize();
    quil_crypto::poseidon::hash_bytes_to_32(&digest)
}

pub fn coin_content_address(tree: &quil_tries::VectorCommitmentTree) -> Result<[u8; 32]> {
    let mut h = Sha512::new();
    for (k, v) in tree.leaves() {
        h.update((k.len() as u32).to_be_bytes());
        h.update(&k);
        h.update((v.len() as u32).to_be_bytes());
        h.update(&v);
    }
    let digest = h.finalize();
    quil_crypto::poseidon::hash_bytes_to_32(&digest)
}

/// Create a **lattice** coin vertex tree. Unlike the decaf coin, it stores the
/// PQ fields at their natural (variable) widths: the one-time key `P`, the
/// SIS-compress value node `cv = H_B(C)`, an optional encrypted memo, and the
/// type hash. `C` itself is never stored (the recipient reconstructs it from the
/// memo). Layout: `0x00` FrameNumber, `1<<2` OneTimeKey(P), `2<<2` Commitment(cv),
/// `3<<2` Memo(opt), `[0xFF;32]` type hash.
pub fn create_lattice_coin_vertex_tree(
    frame_number: &[u8],
    one_time_key: &[u8],
    cv: &[u8],
    memo: &[u8],
    coin_type_hash: &[u8; 32],
) -> Result<quil_tries::VectorCommitmentTree> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.insert(&[0x00], frame_number, &[], &BigInt::from(frame_number.len()))
        .map_err(|e| QuilError::Internal(format!("lattice coin tree: {}", e)))?;
    tree.insert(&[1u8 << 2], one_time_key, &[], &BigInt::from(one_time_key.len()))
        .map_err(|e| QuilError::Internal(format!("lattice coin tree: {}", e)))?;
    tree.insert(&[2u8 << 2], cv, &[], &BigInt::from(cv.len()))
        .map_err(|e| QuilError::Internal(format!("lattice coin tree: {}", e)))?;
    if !memo.is_empty() {
        tree.insert(&[3u8 << 2], memo, &[], &BigInt::from(memo.len()))
            .map_err(|e| QuilError::Internal(format!("lattice coin tree: {}", e)))?;
    }
    tree.insert(&[0xFFu8; 32], coin_type_hash, &[], &BigInt::from(32))
        .map_err(|e| QuilError::Internal(format!("lattice coin tree: {}", e)))?;
    Ok(tree)
}

/// Compute the coin type hash for a domain.
/// `poseidon(domain || "coin:Coin")` → 32 bytes.
pub fn coin_type_hash(domain: &[u8]) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(domain.len() + 9);
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(b"coin:Coin");
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

/// Create a spent marker tree for an input's verification key.
/// The marker is a minimal tree with a single `{0x01}` entry at key 0.
pub fn create_spent_marker_tree() -> Result<quil_tries::VectorCommitmentTree> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.insert(&[0x00], &[0x01], &[], &BigInt::from(0))
        .map_err(|e| QuilError::Internal(format!("spent marker: {}", e)))?;
    Ok(tree)
}

/// Apply a TokenDeploy / TokenUpdate by writing a freshly-built
/// `TokenConfigurationMetadata` tree into the metadata vertex's outer
/// tree at `[16 << 2]`.
///
/// Mirrors Go `TokenIntrinsic.Deploy` at `token_intrinsic.go:208-248`:
/// 1. Read existing metadata vertex tree (or start a fresh one for
/// initial deploy).
/// 2. Build the inner `TokenConfigurationMetadata` tree from the
/// `TokenConfiguration`.
/// 3. Commit the inner tree, serialize via the same Go-tree format the
/// consensus layer reads back, insert at outer key `[0x40]` with
/// the inner-commitment as commit metadata.
/// 4. Write the resulting outer tree under
/// `(domain, HYPERGRAPH_METADATA_ADDRESS)` in vertex-adds.
///
/// Returns the address of the metadata vertex that was written.
pub fn materialize_token_deploy(
    state: &crate::hypergraph_state::HypergraphState,
    domain: &[u8],
    config: &super::config::TokenConfiguration,
    frame_number: u64,
    _inclusion_prover: &(dyn quil_types::crypto::InclusionProver + Sync),
) -> Result<[u8; 32]> {
    let metadata_addr = crate::hypergraph_state::HYPERGRAPH_METADATA_ADDRESS;
    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;

    // Load existing outer tree if present (Update path) — start from
    // empty otherwise (initial Deploy path).
    let mut outer = match state.get(domain, &metadata_addr, &va_disc)? {
        Some(blob) if !blob.is_empty() => {
            let root = quil_tries::deserialize_go_tree(&blob).map_err(|e| {
                QuilError::Internal(format!(
                    "token deploy: outer tree deserialize: {e}"
                ))
            })?;
            quil_tries::VectorCommitmentTree { root }
        }
        _ => quil_tries::VectorCommitmentTree::new(),
    };

    // Build the inner config tree. hash_target = SHA-512 content digest (retired
    // from KZG; a vestigial go-tree annotation, not a forest leaf).
    let inner = super::metadata_schema::build_token_configuration_metadata_tree(config)?;
    let inner_commit = crate::hypergraph_state::tree_content_digest(&inner);
    let inner_blob = quil_tries::serialize_go_tree(inner.root.as_ref()).map_err(|e| {
        QuilError::Internal(format!("token deploy: inner tree serialize: {e}"))
    })?;

    let inner_size = BigInt::from(inner_blob.len() as u64);
    outer
        .insert(&TOKEN_CONFIG_OUTER_KEY, &inner_blob, &inner_commit, &inner_size)
        .map_err(|e| QuilError::Internal(format!("token deploy: outer insert: {e}")))?;

    // Node commitments retired to non-KZG (forest-irrelevant); serialize as-is.
    let outer_blob = quil_tries::serialize_go_tree(outer.root.as_ref()).map_err(|e| {
        QuilError::Internal(format!("token deploy: outer serialize: {e}"))
    })?;

    state.set(domain, &metadata_addr, &va_disc, frame_number, outer_blob)?;
    Ok(metadata_addr)
}

/// Materialize a **new** TokenDeploy — Go `TokenIntrinsic.Deploy` deploy
/// branch (`token_intrinsic.go:255-307`, the `domain == TOKEN_BASE_DOMAIN`
/// path). Unlike `materialize_token_deploy` (the update path, which writes
/// the config into an existing metadata vertex at a known address), a
/// deploy DERIVES the new token's domain from its config and builds the
/// full metadata vertex via `init_metadata_vertex`:
/// 1. build the config (`additionalData[13]`) tree,
/// 2. derive `domain = poseidon(TOKEN_PREFIX ‖ config_tree.commit)`,
/// 3. build the RDF schema templated by `(domain, behavior)`,
/// 4. `init_metadata_vertex(domain, empty, empty, rdf, [13]=config,
/// TOKEN_BASE_DOMAIN, ...)` — which records the `0xff*32`
/// type-domain so the manager can route this domain to the token
/// engine.
/// Returns the derived domain.
/// Domain a token deploy derives from its configuration, without writing
/// anything: `poseidon(TOKEN_PREFIX ‖ config content digest)`. The deploying
/// wallet prints this so it can address the token it just created.
pub fn token_deploy_domain(config: &super::config::TokenConfiguration) -> Result<[u8; 32]> {
    let config_tree = super::metadata_schema::build_token_configuration_metadata_tree(config)?;
    let config_commit = crate::hypergraph_state::tree_content_digest(&config_tree);
    let mut preimage = Vec::with_capacity(super::constants::TOKEN_PREFIX.len() + config_commit.len());
    preimage.extend_from_slice(super::constants::TOKEN_PREFIX);
    preimage.extend_from_slice(&config_commit);
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

pub fn materialize_token_deploy_init(
    state: &crate::hypergraph_state::HypergraphState,
    config: &super::config::TokenConfiguration,
    frame_number: u64,
    inclusion_prover: &(dyn quil_types::crypto::InclusionProver + Sync),
) -> Result<[u8; 32]> {
    // 1. Config tree (additionalData[13]).
    let config_tree = super::metadata_schema::build_token_configuration_metadata_tree(config)?;

    // 2. Derive the domain from the config CONTENT digest (retired from the KZG
    //    commit → SHA-512 of the config's flat leaves; PQ-safe, no BLS48-581).
    let config_commit = crate::hypergraph_state::tree_content_digest(&config_tree);
    let mut preimage =
        Vec::with_capacity(super::constants::TOKEN_PREFIX.len() + config_commit.len());
    preimage.extend_from_slice(super::constants::TOKEN_PREFIX);
    preimage.extend_from_slice(&config_commit);
    let domain = quil_crypto::poseidon::hash_bytes_to_32(&preimage)?;

    // 3. RDF schema (templated by domain + behavior).
    let rdf = super::rdf_schema::prepare_rdf_schema_from_config(&domain, config.behavior);

    // 4. Full metadata vertex with the TOKEN_BASE_DOMAIN type-domain.
    let mut consensus = quil_tries::VectorCommitmentTree::new();
    let mut sumcheck = quil_tries::VectorCommitmentTree::new();
    let mut additional: Vec<Option<quil_tries::VectorCommitmentTree>> =
        (0..14).map(|_| None).collect();
    additional[13] = Some(config_tree);

    let token_base = super::constants::token_base_domain();
    state.init_metadata_vertex(
        &domain,
        &mut consensus,
        &mut sumcheck,
        &rdf,
        &mut additional,
        &token_base,
        frame_number,
        inclusion_prover,
    )?;
    Ok(domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::NoopInclusionProver;

    #[test]
    fn token_deploy_metadata_vertex_matches_go_init_layout() {
        use crate::hypergraph_state::{
            vertex_adds_discriminator, HypergraphState, HYPERGRAPH_METADATA_ADDRESS,
        };
        use std::sync::Arc;

        let prover = Arc::new(NoopInclusionProver);
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            prover.clone(),
        ));
        let state = HypergraphState::new(crdt);

        let cfg = super::super::config::TokenConfiguration {
            behavior: (super::super::constants::DIVISIBLE
                | super::super::constants::ACCEPTABLE
                | super::super::constants::EXPIRABLE) as u32,
            owner_public_key: vec![0x01u8; 32],
            ..Default::default()
        };
        let domain =
            materialize_token_deploy_init(&state, &cfg, 1, prover.as_ref()).unwrap();

        let va = vertex_adds_discriminator().unwrap();
        let blob = state
            .get(&domain, &HYPERGRAPH_METADATA_ADDRESS, &va)
            .unwrap()
            .unwrap();
        let outer = quil_tries::VectorCommitmentTree {
            root: quil_tries::deserialize_go_tree(&blob).unwrap(),
        };

        // Type-domain (the routing link).
        assert_eq!(
            outer.get(&[0xFFu8; 32]).unwrap(),
            &super::super::constants::token_base_domain()[..]
        );
        // RDF schema, raw at [2<<2].
        let expected_rdf =
            super::super::rdf_schema::prepare_rdf_schema_from_config(&domain, cfg.behavior);
        assert_eq!(outer.get(&[2u8 << 2]).unwrap(), expected_rdf.as_bytes());
        // Empty consensus + sumcheck sub-trees sealed at [0<<2]/[1<<2].
        assert_eq!(outer.get(&[0u8 << 2]).unwrap(), &[0x00u8][..]);
        assert_eq!(outer.get(&[1u8 << 2]).unwrap(), &[0x00u8][..]);
        // Config sub-tree sealed at [16<<2] (non-empty).
        assert!(outer.get(&[16u8 << 2]).is_some());
        // Derived domain is deterministic (poseidon of prefix‖config_commit).
        let domain2 =
            materialize_token_deploy_init(&state, &cfg, 2, prover.as_ref()).unwrap();
        assert_eq!(domain, domain2);
    }

    #[test]
    fn coin_type_hash_is_deterministic() {
        let h1 = coin_type_hash(&[0xAAu8; 32]).unwrap();
        let h2 = coin_type_hash(&[0xAAu8; 32]).unwrap();
        assert_eq!(h1, h2);
        assert!(h1.iter().any(|&b| b != 0));
    }

    #[test]
    fn coin_type_hash_differs_by_domain() {
        let h1 = coin_type_hash(&[0xAAu8; 32]).unwrap();
        let h2 = coin_type_hash(&[0xBBu8; 32]).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn spent_marker_tree_has_marker() {
        let tree = create_spent_marker_tree().unwrap();
        assert_eq!(tree.get(&[0x00]).unwrap(), &[0x01][..]);
    }
}

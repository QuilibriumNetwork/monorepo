//! Token transaction materialize — creates coin vertices for outputs
//! and marks inputs as spent.

use num_bigint::BigInt;
use quil_types::error::{QuilError, Result};

use crate::token_intrinsic::transaction::RecipientBundle;

/// A transaction output ready for materialization.
pub struct TransactionOutput {
    pub frame_number: Vec<u8>,
    pub commitment: Vec<u8>,
    pub recipient: RecipientBundle,
}

/// Create a coin vertex tree for a single transaction output.
///
/// Coin tree layout (single-byte key encoding, order << 2):
/// - 0x00: FrameNumber (8 bytes)
/// - 0x04: Commitment (56 bytes)
/// - 0x08: OneTimeKey (56 bytes)
/// - 0x0C: VerificationKey (56 bytes)
/// - 0x10: CoinBalance (56 bytes, encrypted)
/// - 0x14: Mask (56 bytes, encrypted)
/// - 0x18: AdditionalReference (64 bytes, optional)
/// - 0x1C: AdditionalReferenceKey (56 bytes, optional)
/// - [0xFF; 32]: Type hash
pub fn create_coin_vertex_tree(
    output: &TransactionOutput,
    coin_type_hash: &[u8; 32],
) -> Result<quil_tries::VectorCommitmentTree> {
    let mut tree = quil_tries::VectorCommitmentTree::new();

    // FrameNumber at index 0
    tree.insert(&[0x00], &output.frame_number, &[], &BigInt::from(8))
        .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;

    // Commitment at index 1
    tree.insert(&[1 << 2], &output.commitment, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;

    // OneTimeKey at index 2
    tree.insert(&[2 << 2], &output.recipient.one_time_key, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;

    // VerificationKey at index 3
    tree.insert(&[3 << 2], &output.recipient.verification_key, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;

    // CoinBalance at index 4
    tree.insert(&[4 << 2], &output.recipient.coin_balance, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;

    // Mask at index 5
    tree.insert(&[5 << 2], &output.recipient.mask, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;

    // Optional additional references (non-divisible tokens)
    if output.recipient.additional_reference.len() == 64
        && output.recipient.additional_reference_key.len() == 56
    {
        tree.insert(&[6 << 2], &output.recipient.additional_reference, &[], &BigInt::from(64))
            .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;
        tree.insert(&[7 << 2], &output.recipient.additional_reference_key, &[], &BigInt::from(56))
            .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;
    }

    // Type hash at [0xFF; 32]
    tree.insert(&[0xFFu8; 32], coin_type_hash, &[], &BigInt::from(32))
        .map_err(|e| QuilError::Internal(format!("coin tree: {}", e)))?;

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

/// Compute the pending transaction type hash for a domain.
/// `poseidon(domain || "pending:PendingTransaction")` → 32 bytes.
pub fn pending_type_hash(domain: &[u8]) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(domain.len() + 27);
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(b"pending:PendingTransaction");
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

/// Build the per-output `pending:PendingTransaction` vertex tree.
///
/// Mirrors Go `buildPendingTransactionTrees` at
/// `token_intrinsic_pending_transaction.go:1085-1297`. Layout:
///
/// | Index | Field                         | Size |
/// |-------|-------------------------------|------|
/// | 0     | FrameNumber                   |   8  |
/// | 1<<2  | Commitment                    |  56  |
/// | 2<<2  | To.OneTimeKey                 |  56  |
/// | 3<<2  | Refund.OneTimeKey             |  56  |
/// | 4<<2  | To.VerificationKey            |  56  |
/// | 5<<2  | Refund.VerificationKey        |  56  |
/// | 6<<2  | To.CoinBalance                |  56  |
/// | 7<<2  | Refund.CoinBalance            |  56  |
/// | 8<<2  | To.Mask                       |  56  |
/// | 9<<2  | Refund.Mask                   |  56  |
/// | 10<<2 | To.AdditionalReference (opt)  |  56  |
/// | 11<<2 | To.AdditionalReferenceKey     |  56  |
/// | 12<<2 | Refund.AdditionalReference    |  56  |
/// | 13<<2 | Refund.AdditionalReferenceKey |  56  |
/// | 14<<2 | Expiration (when Expirable)   |   8  |
/// | 0xFF*32 | type hash (pending:PT)      |  32  |
///
/// The To-side AdditionalReference branch occupies indices 10-13 and
/// pushes Expiration (when Expirable) to index 14. Without
/// AdditionalReference, Expiration sits at index 10.
pub fn create_pending_transaction_tree(
    frame_number: &[u8],
    commitment: &[u8],
    to: &super::transaction::RecipientBundle,
    refund: &super::transaction::RecipientBundle,
    expiration: u64,
    expirable: bool,
    pending_type: &[u8; 32],
) -> Result<quil_tries::VectorCommitmentTree> {
    let mut tree = quil_tries::VectorCommitmentTree::new();

    // Index 0: FrameNumber
    tree.insert(&[0x00], frame_number, &[], &BigInt::from(8))
        .map_err(|e| QuilError::Internal(format!("pending tree: {}", e)))?;

    // Index 1<<2: Commitment
    tree.insert(&[1u8 << 2], commitment, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("pending tree: {}", e)))?;

    // Indices 2..=9: dual-recipient OneTimeKey/VK/CoinBalance/Mask
    tree.insert(&[2u8 << 2], &to.one_time_key, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("pending tree: {}", e)))?;
    tree.insert(&[3u8 << 2], &refund.one_time_key, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("pending tree: {}", e)))?;
    tree.insert(&[4u8 << 2], &to.verification_key, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("pending tree: {}", e)))?;
    tree.insert(&[5u8 << 2], &refund.verification_key, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("pending tree: {}", e)))?;
    tree.insert(&[6u8 << 2], &to.coin_balance, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("pending tree: {}", e)))?;
    tree.insert(&[7u8 << 2], &refund.coin_balance, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("pending tree: {}", e)))?;
    tree.insert(&[8u8 << 2], &to.mask, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("pending tree: {}", e)))?;
    tree.insert(&[9u8 << 2], &refund.mask, &[], &BigInt::from(56))
        .map_err(|e| QuilError::Internal(format!("pending tree: {}", e)))?;

    // Indices 10..=14: AdditionalReference (To-side gates) + Expiration
    if to.additional_reference.len() == 64 {
        tree.insert(&[10u8 << 2], &to.additional_reference, &[], &BigInt::from(56))
            .map_err(|e| QuilError::Internal(format!("pending tree: {}", e)))?;
        tree.insert(&[11u8 << 2], &to.additional_reference_key, &[], &BigInt::from(56))
            .map_err(|e| QuilError::Internal(format!("pending tree: {}", e)))?;
        tree.insert(&[12u8 << 2], &refund.additional_reference, &[], &BigInt::from(56))
            .map_err(|e| QuilError::Internal(format!("pending tree: {}", e)))?;
        tree.insert(&[13u8 << 2], &refund.additional_reference_key, &[], &BigInt::from(56))
            .map_err(|e| QuilError::Internal(format!("pending tree: {}", e)))?;
        if expirable {
            let exp = expiration.to_be_bytes();
            tree.insert(&[14u8 << 2], &exp, &[], &BigInt::from(8))
                .map_err(|e| QuilError::Internal(format!("pending tree: {}", e)))?;
        }
    } else if expirable {
        // No AdditionalReference: Expiration goes to index 10.
        let exp = expiration.to_be_bytes();
        tree.insert(&[10u8 << 2], &exp, &[], &BigInt::from(8))
            .map_err(|e| QuilError::Internal(format!("pending tree: {}", e)))?;
    }

    // Type marker at [0xFF; 32]
    tree.insert(&[0xFFu8; 32], pending_type, &[], &BigInt::from(32))
        .map_err(|e| QuilError::Internal(format!("pending tree: {}", e)))?;

    Ok(tree)
}

/// Compute the spent address from an input's verification key.
/// `poseidon(verification_key)` → 32 bytes.
pub fn spent_address(verification_key: &[u8]) -> Result<[u8; 32]> {
    quil_crypto::poseidon::hash_bytes_to_32(verification_key)
}

/// Outer-tree key for the serialized `TokenConfigurationMetadata` blob.
/// Matches Go `token_intrinsic.go:228` where Deploy/Update writes via
/// `[]byte{16 << 2}` into the metadata vertex tree.
pub const TOKEN_CONFIG_OUTER_KEY: [u8; 1] = [16u8 << 2]; // 0x40

/// Apply a TokenDeploy / TokenUpdate by writing a freshly-built
/// `TokenConfigurationMetadata` tree into the metadata vertex's outer
/// tree at `[16 << 2]`.
///
/// Mirrors Go `TokenIntrinsic.Deploy` at `token_intrinsic.go:208-248`:
/// 1. Read existing metadata vertex tree (or start a fresh one for
///    initial deploy).
/// 2. Build the inner `TokenConfigurationMetadata` tree from the
///    `TokenConfiguration`.
/// 3. Commit the inner tree, serialize via the same Go-tree format the
///    consensus layer reads back, insert at outer key `[0x40]` with
///    the inner-commitment as commit metadata.
/// 4. Write the resulting outer tree under
///    `(domain, HYPERGRAPH_METADATA_ADDRESS)` in vertex-adds.
///
/// Returns the address of the metadata vertex that was written.
pub fn materialize_token_deploy(
    state: &crate::hypergraph_state::HypergraphState,
    domain: &[u8],
    config: &super::config::TokenConfiguration,
    frame_number: u64,
    inclusion_prover: &(dyn quil_types::crypto::InclusionProver + Sync),
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

    // Build the inner config tree.
    let mut inner = super::metadata_schema::build_token_configuration_metadata_tree(config)?;
    let inner_commit = inner.commit(inclusion_prover);
    let inner_blob = quil_tries::serialize_go_tree(inner.root.as_ref()).map_err(|e| {
        QuilError::Internal(format!("token deploy: inner tree serialize: {e}"))
    })?;

    let inner_size = BigInt::from(inner_blob.len() as u64);
    outer
        .insert(&TOKEN_CONFIG_OUTER_KEY, &inner_blob, &inner_commit, &inner_size)
        .map_err(|e| QuilError::Internal(format!("token deploy: outer insert: {e}")))?;

    // Re-commit the outer tree so the materialized blob carries the
    // updated inclusion proofs.
    let _ = outer.commit(inclusion_prover);

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
///   1. build the config (`additionalData[13]`) tree,
///   2. derive `domain = poseidon(TOKEN_PREFIX ‖ config_tree.commit)`,
///   3. build the RDF schema templated by `(domain, behavior)`,
///   4. `init_metadata_vertex(domain, empty, empty, rdf, [13]=config,
///      TOKEN_BASE_DOMAIN, ...)` — which records the `0xff*32`
///      type-domain so the manager can route this domain to the token
///      engine.
/// Returns the derived domain.
pub fn materialize_token_deploy_init(
    state: &crate::hypergraph_state::HypergraphState,
    config: &super::config::TokenConfiguration,
    frame_number: u64,
    inclusion_prover: &(dyn quil_types::crypto::InclusionProver + Sync),
) -> Result<[u8; 32]> {
    // 1. Config tree (additionalData[13]).
    let mut config_tree = super::metadata_schema::build_token_configuration_metadata_tree(config)?;

    // 2. Derive the domain from the config commitment.
    let config_commit = config_tree.commit(inclusion_prover);
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

/// Extract the verification key from a standard transaction input
/// signature. The signature is 336 bytes (6 × 56), and the
/// verification key is at bytes [224..280] (56*4 to 56*5).
pub fn extract_verification_key_from_signature(signature: &[u8]) -> Option<&[u8]> {
    if signature.len() == 336 {
        Some(&signature[56 * 4..56 * 5])
    } else {
        None
    }
}

/// Full materialize output for a token transaction.
pub struct TransactionMaterializeOutput {
    /// (coin_address, coin_tree) pairs — one per output.
    pub coins: Vec<([u8; 32], quil_tries::VectorCommitmentTree)>,
    /// (spent_address, spent_marker_tree) pairs — one per input.
    pub spent_markers: Vec<([u8; 32], quil_tries::VectorCommitmentTree)>,
}

/// Materialize a token transaction: create coin vertices for outputs,
/// spent markers for inputs.
///
/// The caller writes these to the CRDT via HypergraphState.set().
pub fn materialize_transaction(
    domain: &[u8],
    outputs: &[TransactionOutput],
    input_signatures: &[Vec<u8>],
    inclusion_prover: &(dyn quil_types::crypto::InclusionProver + Sync),
) -> Result<TransactionMaterializeOutput> {
    let type_hash = coin_type_hash(domain)?;

    let mut coins = Vec::with_capacity(outputs.len());
    for output in outputs {
        let mut tree = create_coin_vertex_tree(output, &type_hash)?;
        let commit = tree.commit(inclusion_prover);
        let addr = quil_crypto::poseidon::hash_bytes_to_32(&commit)?;
        coins.push((addr, tree));
    }

    let mut spent_markers = Vec::with_capacity(input_signatures.len());
    for sig in input_signatures {
        if let Some(vk) = extract_verification_key_from_signature(sig) {
            let addr = spent_address(vk)?;
            let marker = create_spent_marker_tree()?;
            spent_markers.push((addr, marker));
        }
    }

    Ok(TransactionMaterializeOutput { coins, spent_markers })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::NoopInclusionProver;

    fn sample_output() -> TransactionOutput {
        TransactionOutput {
            frame_number: vec![0, 0, 0, 0, 0, 0, 0, 42],
            commitment: vec![0xAAu8; 56],
            recipient: RecipientBundle {
                one_time_key: vec![0x11u8; 56],
                verification_key: vec![0x22u8; 56],
                coin_balance: vec![0x33u8; 56],
                mask: vec![0x44u8; 56],
                additional_reference: vec![],
                additional_reference_key: vec![],
            },
        }
    }

    /// Byte-parity (structure) verification of the deploy metadata vertex
    /// against Go `hgstate.Init`'s layout: a deployed token's metadata
    /// vertex must carry, at the prover-independent keys, exactly:
    ///   [0<<2]  empty consensus sub-tree  → serialize_go_tree(None) = [0x00]
    ///   [1<<2]  empty sumcheck sub-tree   → [0x00]
    ///   [2<<2]  the templated RDF schema (raw)
    ///   [16<<2] the config sub-tree (sealed, non-empty)
    ///   0xff*32 the type-domain = TOKEN_BASE_DOMAIN
    /// The type-domain assertion is the critical consensus link: it is
    /// exactly what the manager's select_engine reads back to route this
    /// domain to the token engine. (Commitment bytes depend on the
    /// inclusion prover and are exercised separately.)
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

    /// TRUE byte-parity of the KZG prover + quil-tries commit/serialize
    /// against Go. The (key,value) tree below is committed in Go with the
    /// real KZG inclusion prover (bls48581) and serialized via
    /// SerializeNonLazyTree (node test TestPrintKZGCommitVector); the
    /// expected hex is that Go output. This is the missing prover-DEPENDENT
    /// half of deploy-metadata-vertex parity: it proves Rust's
    /// KzgInclusionProver (same libbls48581) + VectorCommitmentTree::commit
    /// + serialize_go_tree produce byte-identical commitments and serialized
    /// trees to Go's tries.Commit + SerializeNonLazyTree. Combined with the
    /// RDF Go-vectors and the Init-layout test, the full metadata vertex is
    /// byte-parity-verified.
    #[test]
    fn kzg_tree_commit_matches_go_vector() {
        use num_bigint::BigInt;

        quil_crypto::init(); // load the KZG SRS (idempotent across calls)
        let prover = quil_crypto::KzgInclusionProver;

        let mut tree = quil_tries::VectorCommitmentTree::new();
        tree.insert(&[0u8 << 2], b"hello world", &[], &BigInt::from(11))
            .unwrap();
        tree.insert(&[1u8 << 2], &[0xABu8; 56], &[], &BigInt::from(56))
            .unwrap();
        tree.insert(&[16u8 << 2], &[0xCDu8; 32], &[], &BigInt::from(32))
            .unwrap();

        let commit = tree.commit(&prover);
        assert_eq!(
            hex::encode(&commit),
            "020f8e94f575785f6ca4260ee36dee3370f226af96a0f5ad2727c6e2335fb01defa026b7d6696d802dd035f276f8c7cbd04987313415fb206882a06e337561dca0ee675a9d370cb2b20a",
            "KZG root commitment must match Go bls48581"
        );

        let ser = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        assert_eq!(
            hex::encode(&ser),
            "020000000001000000000000000100000000000000000b68656c6c6f20776f726c6400000000000000000000000000000040b30d43f7820dea2998631be4af2e0a5665de80dca55b547a4ce637db8add468d3353f46b2f91f31c3d25e1fc664249c7f92c3b6cd03f300c9becd75f44544b2900000000000000010b010000000000000001040000000000000038abababababababababababababababababababababababababababababababababababababababababababababababababababababababab000000000000000000000000000000407941c8dc10a26dad206aabee1f7c73886bf3161c25360cf5eb11adc3b90c5128fe4cd54483412eb2bbd6c3b6d4efa1ca43ece88d200d8d676f2c7c9692c555180000000000000001380000000000000000000000000000010000000000000001400000000000000020cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd00000000000000000000000000000040c8234b7610cb08164ece21a18803b3fb7a5ca6c7dd3659c5de974ae279f87fc1e5d567153f60304e22d6cf84959bdb4172190dc48ea4a3e3b3f92cc32ad458c90000000000000001200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004a020f8e94f575785f6ca4260ee36dee3370f226af96a0f5ad2727c6e2335fb01defa026b7d6696d802dd035f276f8c7cbd04987313415fb206882a06e337561dca0ee675a9d370cb2b20a000000000000000163000000000000000300000001",
            "serialized committed tree must match Go SerializeNonLazyTree"
        );
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
    fn create_coin_vertex_tree_has_all_fields() {
        let output = sample_output();
        let type_hash = coin_type_hash(&[0xAAu8; 32]).unwrap();
        let tree = create_coin_vertex_tree(&output, &type_hash).unwrap();

        assert_eq!(tree.get(&[0x00]).unwrap(), &output.frame_number[..]);
        assert_eq!(tree.get(&[1 << 2]).unwrap(), &output.commitment[..]);
        assert_eq!(tree.get(&[2 << 2]).unwrap(), &output.recipient.one_time_key[..]);
        assert_eq!(tree.get(&[3 << 2]).unwrap(), &output.recipient.verification_key[..]);
        assert_eq!(tree.get(&[4 << 2]).unwrap(), &output.recipient.coin_balance[..]);
        assert_eq!(tree.get(&[5 << 2]).unwrap(), &output.recipient.mask[..]);
        assert_eq!(tree.get(&[0xFFu8; 32]).unwrap(), &type_hash[..]);
    }

    #[test]
    fn create_coin_with_additional_references() {
        let mut output = sample_output();
        output.recipient.additional_reference = vec![0x55u8; 64];
        output.recipient.additional_reference_key = vec![0x66u8; 56];
        let type_hash = coin_type_hash(&[0xAAu8; 32]).unwrap();
        let tree = create_coin_vertex_tree(&output, &type_hash).unwrap();
        assert_eq!(tree.get(&[6 << 2]).unwrap(), &[0x55u8; 64][..]);
        assert_eq!(tree.get(&[7 << 2]).unwrap(), &[0x66u8; 56][..]);
    }

    #[test]
    fn spent_marker_tree_has_marker() {
        let tree = create_spent_marker_tree().unwrap();
        assert_eq!(tree.get(&[0x00]).unwrap(), &[0x01][..]);
    }

    #[test]
    fn extract_vk_from_336_byte_signature() {
        let mut sig = vec![0u8; 336];
        sig[56 * 4..56 * 5].copy_from_slice(&[0xAAu8; 56]);
        let vk = extract_verification_key_from_signature(&sig).unwrap();
        assert_eq!(vk, &[0xAAu8; 56][..]);
    }

    #[test]
    fn extract_vk_from_wrong_size_returns_none() {
        assert!(extract_verification_key_from_signature(&[0u8; 100]).is_none());
    }

    #[test]
    fn materialize_transaction_creates_coins_and_spent() {
        let outputs = vec![sample_output(), sample_output()];
        let sigs = vec![vec![0xBBu8; 336], vec![0xCCu8; 336]];
        let result = materialize_transaction(
            &[0xAAu8; 32], &outputs, &sigs, &NoopInclusionProver,
        ).unwrap();

        assert_eq!(result.coins.len(), 2);
        assert_eq!(result.spent_markers.len(), 2);
        for (addr, _tree) in &result.coins {
            assert_eq!(addr.len(), 32);
            assert!(addr.iter().any(|&b| b != 0));
        }
        for (addr, tree) in &result.spent_markers {
            assert_eq!(addr.len(), 32);
            assert_eq!(tree.get(&[0x00]).unwrap(), &[0x01][..]);
        }
    }

    #[test]
    fn materialize_empty_transaction() {
        let result = materialize_transaction(
            &[0xAAu8; 32], &[], &[], &NoopInclusionProver,
        ).unwrap();
        assert!(result.coins.is_empty());
        assert!(result.spent_markers.is_empty());
    }
}

//! Token configuration metadata schema — statically compiled from
//! `TOKEN_CONFIGURATION_METADATA_SCHEMA` in
//! `node/execution/intrinsics/token/token_configuration.go:44-91`.
//!
//! Fields on `config:TokenConfiguration`:
//!
//! | Order | Field                | Size (bytes) | RDF type   |
//! |-------|----------------------|--------------|------------|
//! | 0     | Behavior             | 2            | Uint       |
//! | 1     | MintStrategy         | 701          | ByteArray  |
//! | 2     | Units                | 32           | ByteArray  |
//! | 3     | Supply               | 32           | ByteArray  |
//! | 4     | Name                 | 64           | String     |
//! | 5     | Symbol               | 8            | String     |
//! | 6     | AdditionalReference  | 64           | ByteArray  |
//! | 7     | OwnerPublicKey       | 585          | ByteArray  |
//!
//! This module exposes a helper `field_key(name) -> Vec<u8>` built on
//! top of the shared `order_to_key` encoder from `global_schema`.

use crate::global_schema::order_to_key;

/// Max `order` across all fields on `config:TokenConfiguration` — drives
/// the key-encoding width. The schema's max order is 7, so all keys are
/// single-byte.
pub const TOKEN_CONFIG_MAX_ORDER: u16 = 7;

/// Field orders on `config:TokenConfiguration` (Go `token_configuration.go:44-91`).
pub mod field {
    pub const BEHAVIOR: u16 = 0;
    pub const MINT_STRATEGY: u16 = 1;
    pub const UNITS: u16 = 2;
    pub const SUPPLY: u16 = 3;
    pub const NAME: u16 = 4;
    pub const SYMBOL: u16 = 5;
    pub const ADDITIONAL_REFERENCE: u16 = 6;
    pub const OWNER_PUBLIC_KEY: u16 = 7;
}

/// Tree-lookup key for a `config:TokenConfiguration` field.
pub fn field_key(order: u16) -> Vec<u8> {
    order_to_key(order, TOKEN_CONFIG_MAX_ORDER)
}

/// Outer key under which the serialized `config:TokenConfiguration`
/// inner tree is stored inside the vertex data tree at
/// `[domain || HYPERGRAPH_METADATA_ADDRESS]`. Matches Go
/// `token_intrinsic.go:228`, which writes via `[]byte{16 << 2}`.
pub const OUTER_CONFIG_KEY: [u8; 1] = [16u8 << 2]; // 0x40

/// Load a token's `config:TokenConfiguration` inner tree from the
/// hypergraph. Mirrors the first half of Go
/// `unpackAndVerifyTokenConfigurationMetadata`:
///
/// 1. Load `[domain || HYPERGRAPH_METADATA_ADDRESS]` vertex data (outer
///    tree serialized blob).
/// 2. Deserialize as a `VectorCommitmentTree`.
/// 3. Read key `[0x40]` → serialized inner tree bytes.
/// 4. Deserialize the inner tree.
///
/// Returns `Ok(None)` when the vertex is missing / the outer key is
/// empty. The caller reads fields via `field_key(order)` on the
/// returned tree.
pub fn load_token_config_tree(
    hypergraph: &quil_hypergraph::HypergraphCrdt,
    domain: &[u8; 32],
) -> quil_types::error::Result<Option<quil_tries::VectorCommitmentTree>> {
    use quil_hypergraph::addressing::Location;
    use quil_types::error::QuilError;

    let loc = Location {
        app_address: *domain,
        data_address: crate::hypergraph_state::HYPERGRAPH_METADATA_ADDRESS,
    };
    if !hypergraph.lookup_vertex(&loc) {
        return Ok(None);
    }
    let outer_bytes = match hypergraph.get_vertex_underlying_tree_bytes(&loc) {
        Some(b) => b,
        None => return Ok(None),
    };
    let outer_root = quil_tries::deserialize_go_tree(&outer_bytes).map_err(|e| {
        QuilError::InvalidArgument(format!(
            "token config: outer tree deserialize failed: {e}"
        ))
    })?;
    let outer_tree = quil_tries::VectorCommitmentTree { root: outer_root };

    let inner_bytes = match outer_tree.get(&OUTER_CONFIG_KEY) {
        Some(b) => b.to_vec(),
        None => return Ok(None),
    };
    let inner_root = quil_tries::deserialize_go_tree(&inner_bytes).map_err(|e| {
        QuilError::InvalidArgument(format!(
            "token config: inner tree deserialize failed: {e}"
        ))
    })?;
    Ok(Some(quil_tries::VectorCommitmentTree { root: inner_root }))
}

/// Decode a full `TokenConfiguration` from the inner tree. Packs the
/// outer-level fields (Behavior, Units, Supply, Name, Symbol,
/// AdditionalReference, OwnerPublicKey) plus the inner MintStrategy
/// (decoded via `config::decode_mint_strategy_packed`) into the
/// canonical-bytes `TokenConfiguration` shape.
///
/// Ports Go `unpackAndVerifyTokenConfigurationMetadata:925-1190`.
pub fn decode_token_config_from_tree(
    tree: &quil_tries::VectorCommitmentTree,
) -> quil_types::error::Result<super::config::TokenConfiguration> {
    use quil_types::error::QuilError;

    let behavior_bytes = tree.get(&field_key(field::BEHAVIOR))
        .ok_or_else(|| QuilError::InvalidArgument(
            "token config: missing Behavior field".into(),
        ))?;
    if behavior_bytes.len() < 2 {
        return Err(QuilError::InvalidArgument(
            "token config: Behavior field < 2 bytes".into(),
        ));
    }
    let behavior = u16::from_be_bytes([behavior_bytes[0], behavior_bytes[1]]) as u32;

    let mint_strategy = tree.get(&field_key(field::MINT_STRATEGY))
        .map(|b| super::config::decode_mint_strategy_packed(b))
        .transpose()?
        .map(|s| s.to_canonical_bytes())
        .transpose()?
        .unwrap_or_default();

    let units = tree.get(&field_key(field::UNITS))
        .map(|b| b.to_vec()).unwrap_or_default();
    let supply = tree.get(&field_key(field::SUPPLY))
        .map(|b| b.to_vec()).unwrap_or_default();
    let name = tree.get(&field_key(field::NAME))
        .map(|b| b.to_vec()).unwrap_or_default();
    let symbol = tree.get(&field_key(field::SYMBOL))
        .map(|b| b.to_vec()).unwrap_or_default();
    let additional_reference: Vec<Vec<u8>> = tree
        .get(&field_key(field::ADDITIONAL_REFERENCE))
        .map(|b| vec![b.to_vec()])
        .unwrap_or_default();
    let owner_public_key = tree.get(&field_key(field::OWNER_PUBLIC_KEY))
        .map(|b| b.to_vec()).unwrap_or_default();

    Ok(super::config::TokenConfiguration {
        behavior,
        mint_strategy,
        units,
        supply,
        name,
        symbol,
        additional_reference,
        owner_public_key,
    })
}

// =====================================================================
// Build path: TokenConfiguration → metadata tree
// =====================================================================

/// Encode a `TokenMintStrategy` (canonical-bytes) into the packed
/// binary format used by `NewTokenConfigurationMetadata` when storing
/// `MintStrategy` into the metadata tree. Inverse of
/// `decode_mint_strategy_packed`. Mirrors Go
/// `token_configuration.go:632-810`.
pub fn encode_mint_strategy_packed(
    strategy: &super::config::TokenMintStrategy,
) -> quil_types::error::Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&(strategy.mint_behavior as u16).to_be_bytes());
    out.extend_from_slice(&(strategy.proof_basis as u16).to_be_bytes());

    // VerkleRoot: optional
    if !strategy.verkle_root.is_empty() {
        out.push(1);
        out.extend_from_slice(&(strategy.verkle_root.len() as u16).to_be_bytes());
        out.extend_from_slice(&strategy.verkle_root);
    } else {
        out.push(0);
    }

    // Authority: optional
    if !strategy.authority.is_empty() {
        let auth = super::config::Authority::from_canonical_bytes(&strategy.authority)?;
        out.push(1);
        out.extend_from_slice(&(auth.key_type as u16).to_be_bytes());
        out.extend_from_slice(&(auth.public_key.len() as u16).to_be_bytes());
        out.extend_from_slice(&auth.public_key);
        out.push(if auth.can_burn { 1 } else { 0 });
    } else {
        out.push(0);
    }

    // PaymentAddress: u16 length-prefixed (no presence flag — 0-length means absent)
    if !strategy.payment_address.is_empty() {
        out.extend_from_slice(&(strategy.payment_address.len() as u16).to_be_bytes());
        out.extend_from_slice(&strategy.payment_address);
    } else {
        out.extend_from_slice(&0u16.to_be_bytes());
    }

    // FeeBasis: optional
    if !strategy.fee_basis.is_empty() {
        let fb = super::config::FeeBasisStruct::from_canonical_bytes(&strategy.fee_basis)?;
        out.push(1);
        out.extend_from_slice(&(fb.fee_type as u16).to_be_bytes());
        out.extend_from_slice(&(fb.baseline.len() as u16).to_be_bytes());
        out.extend_from_slice(&fb.baseline);
    } else {
        out.push(0);
    }

    if out.len() > 701 {
        return Err(quil_types::error::QuilError::InvalidArgument(
            "mint strategy data exceeds maximum size".into(),
        ));
    }

    Ok(out)
}

/// Build the `TokenConfigurationMetadata` inner tree for a config.
///
/// Mirrors Go `NewTokenConfigurationMetadata` at
/// `token_configuration.go:608-923`. Each field is inserted at
/// `field_key(order)` with the schema-declared size as the leaf
/// length.
pub fn build_token_configuration_metadata_tree(
    config: &super::config::TokenConfiguration,
) -> quil_types::error::Result<quil_tries::VectorCommitmentTree> {
    use num_bigint::BigInt;
    use quil_types::error::QuilError;

    let mut tree = quil_tries::VectorCommitmentTree::new();

    // Behavior (order 0): 2-byte BE
    let behavior_bytes = (config.behavior as u16).to_be_bytes();
    tree.insert(
        &field_key(field::BEHAVIOR),
        &behavior_bytes,
        &[],
        &BigInt::from(2),
    )
    .map_err(|e| QuilError::Internal(format!("token config tree: {}", e)))?;

    // MintStrategy (order 1): packed bytes
    if !config.mint_strategy.is_empty() {
        let strategy =
            super::config::TokenMintStrategy::from_canonical_bytes(&config.mint_strategy)?;
        let packed = encode_mint_strategy_packed(&strategy)?;
        tree.insert(
            &field_key(field::MINT_STRATEGY),
            &packed,
            &[],
            &BigInt::from(701),
        )
        .map_err(|e| QuilError::Internal(format!("token config tree: {}", e)))?;
    }

    // Units (order 2): 32-byte big-int padded
    if !config.units.is_empty() {
        let mut units = vec![0u8; 32];
        let u = &config.units;
        let off = 32usize.saturating_sub(u.len());
        units[off..].copy_from_slice(&u[u.len().saturating_sub(32)..]);
        tree.insert(&field_key(field::UNITS), &units, &[], &BigInt::from(32))
            .map_err(|e| QuilError::Internal(format!("token config tree: {}", e)))?;
    }

    // Supply (order 3): 32-byte big-int padded
    if !config.supply.is_empty() {
        let mut supply = vec![0u8; 32];
        let s = &config.supply;
        let off = 32usize.saturating_sub(s.len());
        supply[off..].copy_from_slice(&s[s.len().saturating_sub(32)..]);
        tree.insert(&field_key(field::SUPPLY), &supply, &[], &BigInt::from(32))
            .map_err(|e| QuilError::Internal(format!("token config tree: {}", e)))?;
    }

    // Name (order 4): truncated to 64 bytes
    let mut name = config.name.clone();
    if name.len() > 64 {
        name.truncate(64);
    }
    tree.insert(&field_key(field::NAME), &name, &[], &BigInt::from(64))
        .map_err(|e| QuilError::Internal(format!("token config tree: {}", e)))?;

    // Symbol (order 5): truncated to 8 bytes
    let mut symbol = config.symbol.clone();
    if symbol.len() > 8 {
        symbol.truncate(8);
    }
    tree.insert(&field_key(field::SYMBOL), &symbol, &[], &BigInt::from(8))
        .map_err(|e| QuilError::Internal(format!("token config tree: {}", e)))?;

    // AdditionalReference (order 6): single concatenated 64-byte field
    let addref: Vec<u8> = config
        .additional_reference
        .iter()
        .flat_map(|v| v.iter().copied())
        .collect();
    tree.insert(
        &field_key(field::ADDITIONAL_REFERENCE),
        &addref,
        &[],
        &BigInt::from(64),
    )
    .map_err(|e| QuilError::Internal(format!("token config tree: {}", e)))?;

    // OwnerPublicKey (order 7)
    if !config.owner_public_key.is_empty() {
        tree.insert(
            &field_key(field::OWNER_PUBLIC_KEY),
            &config.owner_public_key,
            &[],
            &BigInt::from(585),
        )
        .map_err(|e| QuilError::Internal(format!("token config tree: {}", e)))?;
    }

    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_keys_are_single_byte_shifted_by_2() {
        // max_order ≤ 63 → single-byte encoding, `order << 2`.
        assert_eq!(field_key(field::BEHAVIOR), vec![0x00]);
        assert_eq!(field_key(field::MINT_STRATEGY), vec![0x04]);
        assert_eq!(field_key(field::UNITS), vec![0x08]);
        assert_eq!(field_key(field::SUPPLY), vec![0x0C]);
        assert_eq!(field_key(field::NAME), vec![0x10]);
        assert_eq!(field_key(field::SYMBOL), vec![0x14]);
        assert_eq!(field_key(field::ADDITIONAL_REFERENCE), vec![0x18]);
        assert_eq!(field_key(field::OWNER_PUBLIC_KEY), vec![0x1C]);
    }

    #[test]
    fn build_metadata_tree_round_trips_basic_fields() {
        use super::super::config::TokenConfiguration;
        let cfg = TokenConfiguration {
            behavior: 0x3F,
            mint_strategy: vec![],
            units: vec![0xFFu8; 32],
            supply: vec![0xAAu8; 32],
            name: b"Quil".to_vec(),
            symbol: b"Q".to_vec(),
            additional_reference: vec![],
            owner_public_key: vec![0xBBu8; 585],
        };
        let tree = build_token_configuration_metadata_tree(&cfg).unwrap();
        // Behavior is 2-byte BE
        assert_eq!(
            tree.get(&field_key(field::BEHAVIOR)).unwrap(),
            &(cfg.behavior as u16).to_be_bytes()[..],
        );
        // Units, Supply: padded 32-byte
        assert_eq!(tree.get(&field_key(field::UNITS)).unwrap().len(), 32);
        assert_eq!(tree.get(&field_key(field::SUPPLY)).unwrap().len(), 32);
        // Name + Symbol stored as-is (truncated otherwise)
        assert_eq!(tree.get(&field_key(field::NAME)).unwrap(), b"Quil");
        assert_eq!(tree.get(&field_key(field::SYMBOL)).unwrap(), b"Q");
        // OwnerPublicKey present
        assert_eq!(
            tree.get(&field_key(field::OWNER_PUBLIC_KEY)).unwrap(),
            &cfg.owner_public_key[..],
        );
    }

    #[test]
    fn encode_decode_mint_strategy_packed_round_trip_minimal() {
        use super::super::config::TokenMintStrategy;
        let m = TokenMintStrategy {
            mint_behavior: 1, proof_basis: 1,
            verkle_root: vec![],
            authority: vec![],
            payment_address: vec![],
            fee_basis: vec![],
        };
        let packed = encode_mint_strategy_packed(&m).unwrap();
        let back = super::super::config::decode_mint_strategy_packed(&packed).unwrap();
        assert_eq!(back, m);
    }
}

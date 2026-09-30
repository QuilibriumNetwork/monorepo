//! Conversions between prost-generated token proto types and the
//! canonical-bytes types in this module.

use quil_types::error::Result;
use quil_types::proto::keys as keys_pb;
use quil_types::proto::token as pb;

use super::config::{Authority, FeeBasisStruct, TokenConfiguration, TokenMintStrategy};
use super::deploy::{TokenDeploy, TokenUpdate};
// =====================================================================
// Authority
// =====================================================================

pub fn authority_from_proto(p: &pb::Authority) -> Authority {
    Authority {
        key_type: p.key_type,
        public_key: p.public_key.clone(),
        can_burn: p.can_burn,
    }
}

pub fn authority_to_proto(a: &Authority) -> pb::Authority {
    pb::Authority {
        key_type: a.key_type,
        public_key: a.public_key.clone(),
        can_burn: a.can_burn,
    }
}

// =====================================================================
// FeeBasisStruct ↔ FeeBasis
// =====================================================================

pub fn fee_basis_from_proto(p: &pb::FeeBasis) -> FeeBasisStruct {
    FeeBasisStruct {
        fee_type: p.r#type as u32,
        baseline: p.baseline.clone(),
    }
}

pub fn fee_basis_to_proto(f: &FeeBasisStruct) -> pb::FeeBasis {
    pb::FeeBasis {
        r#type: f.fee_type as i32,
        baseline: f.baseline.clone(),
    }
}

// =====================================================================
// TokenMintStrategy — nested canonical bytes for authority + fee_basis
// =====================================================================

pub fn mint_strategy_from_proto(p: &pb::TokenMintStrategy) -> Result<TokenMintStrategy> {
    let authority = match &p.authority {
        Some(a) => authority_from_proto(a).to_canonical_bytes()?,
        None => Vec::new(),
    };
    let fee_basis = match &p.fee_basis {
        Some(f) => fee_basis_from_proto(f).to_canonical_bytes()?,
        None => Vec::new(),
    };
    Ok(TokenMintStrategy {
        mint_behavior: mint_behavior_from_proto(p.mint_behavior)?,
        proof_basis: p.proof_basis as u32,
        verkle_root: p.verkle_root.clone(),
        authority,
        payment_address: p.payment_address.clone(),
        fee_basis,
    })
}

/// The wire enum `TokenMintBehavior` is sequential (proof 1, authority 2,
/// signature 3, payment 4); the configuration consensus reads carries the
/// behaviour as BIT FLAGS (`MINT_WITH_PROOF` 1<<0 ... `MINT_WITH_PAYMENT`
/// 1<<3). The two agree only for proof and authority, so these must map, never
/// cast: cast through, a payment token is stored as a signature token
/// (1<<2 == 4) whose authority is unset and which therefore can never mint,
/// and a signature token becomes an unrecognized behaviour.
fn mint_behavior_from_proto(value: i32) -> Result<u32> {
    use super::constants::*;
    Ok(match value {
        0 => NO_MINT_BEHAVIOR,
        1 => MINT_WITH_PROOF,
        2 => MINT_WITH_AUTHORITY,
        3 => MINT_WITH_SIGNATURE,
        4 => MINT_WITH_PAYMENT,
        other => {
            return Err(quil_types::error::QuilError::InvalidArgument(format!(
                "unknown token mint behavior: {other}"
            )))
        }
    } as u32)
}

fn mint_behavior_to_proto(flags: u32) -> Result<i32> {
    use super::constants::*;
    Ok(match flags as u16 {
        NO_MINT_BEHAVIOR => 0,
        MINT_WITH_PROOF => 1,
        MINT_WITH_AUTHORITY => 2,
        MINT_WITH_SIGNATURE => 3,
        MINT_WITH_PAYMENT => 4,
        other => {
            return Err(quil_types::error::QuilError::InvalidArgument(format!(
                "unknown token mint behavior flags: {other}"
            )))
        }
    })
}

pub fn mint_strategy_to_proto(m: &TokenMintStrategy) -> Result<pb::TokenMintStrategy> {
    let authority = if !m.authority.is_empty() {
        Some(authority_to_proto(
            &Authority::from_canonical_bytes(&m.authority)?,
        ))
    } else {
        None
    };
    let fee_basis = if !m.fee_basis.is_empty() {
        Some(fee_basis_to_proto(
            &FeeBasisStruct::from_canonical_bytes(&m.fee_basis)?,
        ))
    } else {
        None
    };
    Ok(pb::TokenMintStrategy {
        mint_behavior: mint_behavior_to_proto(m.mint_behavior)?,
        proof_basis: m.proof_basis as i32,
        verkle_root: m.verkle_root.clone(),
        authority,
        payment_address: m.payment_address.clone(),
        fee_basis,
    })
}

// =====================================================================
// TokenConfiguration
// =====================================================================

pub fn token_config_from_proto(p: &pb::TokenConfiguration) -> Result<TokenConfiguration> {
    let mint_strategy = match &p.mint_strategy {
        Some(ms) => mint_strategy_from_proto(ms)?.to_canonical_bytes()?,
        None => Vec::new(),
    };
    Ok(TokenConfiguration {
        behavior: p.behavior,
        mint_strategy,
        units: p.units.clone(),
        supply: p.supply.clone(),
        name: p.name.as_bytes().to_vec(),
        symbol: p.symbol.as_bytes().to_vec(),
        additional_reference: p.additional_reference.clone(),
        owner_public_key: p.owner_public_key.clone(),
    })
}

pub fn token_config_to_proto(c: &TokenConfiguration) -> Result<pb::TokenConfiguration> {
    let mint_strategy = if !c.mint_strategy.is_empty() {
        let ms = TokenMintStrategy::from_canonical_bytes(&c.mint_strategy)?;
        Some(mint_strategy_to_proto(&ms)?)
    } else {
        None
    };
    Ok(pb::TokenConfiguration {
        behavior: c.behavior,
        mint_strategy,
        units: c.units.clone(),
        supply: c.supply.clone(),
        name: String::from_utf8_lossy(&c.name).into_owned(),
        symbol: String::from_utf8_lossy(&c.symbol).into_owned(),
        additional_reference: c.additional_reference.clone(),
        owner_public_key: c.owner_public_key.clone(),
    })
}

// =====================================================================
// TokenDeploy / TokenUpdate
// =====================================================================

pub fn token_deploy_from_proto(p: &pb::TokenDeploy) -> Result<TokenDeploy> {
    let config = match &p.config {
        Some(c) => token_config_from_proto(c)?.to_canonical_bytes()?,
        None => Vec::new(),
    };
    Ok(TokenDeploy {
        config,
        rdf_schema: p.rdf_schema.clone(),
    })
}

pub fn token_deploy_to_proto(d: &TokenDeploy) -> Result<pb::TokenDeploy> {
    let config = if !d.config.is_empty() {
        Some(token_config_to_proto(
            &TokenConfiguration::from_canonical_bytes(&d.config)?,
        )?)
    } else {
        None
    };
    Ok(pb::TokenDeploy {
        config,
        rdf_schema: d.rdf_schema.clone(),
    })
}

pub fn token_update_from_proto(p: &pb::TokenUpdate) -> Result<TokenUpdate> {
    let config = match &p.config {
        Some(c) => token_config_from_proto(c)?.to_canonical_bytes()?,
        None => Vec::new(),
    };
    // The canonical field carries the RAW Falcon signature bytes (the verify
    // path `engines.rs` passes it straight to `validate_signature`/falcon_verify
    // — no 0x011C aggregate envelope). Use the proto's inner `signature` field,
    // not the wrapped envelope.
    let sig = match &p.public_key_signature_bls48581 {
        Some(s) => s.signature.clone(),
        None => Vec::new(),
    };
    Ok(TokenUpdate {
        config,
        rdf_schema: p.rdf_schema.clone(),
        public_key_signature_bls48581: sig,
    })
}

pub fn token_update_to_proto(u: &TokenUpdate) -> Result<pb::TokenUpdate> {
    let config = if !u.config.is_empty() {
        Some(token_config_to_proto(
            &TokenConfiguration::from_canonical_bytes(&u.config)?,
        )?)
    } else {
        None
    };
    // The canonical field carries the RAW inner signature bytes (see
    // `token_update_from_proto`); re-wrap it into the proto's inner
    // `signature` field only, leaving pubkey/bitmask empty.
    let public_key_signature_bls48581 = if u.public_key_signature_bls48581.is_empty() {
        None
    } else {
        Some(keys_pb::Bls48581AggregateSignature {
            signature: u.public_key_signature_bls48581.clone(),
            public_key: None,
            bitmask: Vec::new(),
        })
    };
    Ok(pb::TokenUpdate {
        config,
        rdf_schema: u.rdf_schema.clone(),
        public_key_signature_bls48581,
    })
}

#[cfg(test)]
mod tests {
    /// The wire enum and the stored bit flags agree only for proof and
    /// authority. A raw cast made every payment token a signature token with
    /// no authority — deployable, and impossible to mint from.
    #[test]
    fn mint_behavior_maps_between_the_wire_enum_and_the_stored_flags() {
        use super::super::constants::*;
        for (wire, flags) in [
            (0i32, NO_MINT_BEHAVIOR),
            (1, MINT_WITH_PROOF),
            (2, MINT_WITH_AUTHORITY),
            (3, MINT_WITH_SIGNATURE),
            (4, MINT_WITH_PAYMENT),
        ] {
            assert_eq!(super::mint_behavior_from_proto(wire).unwrap(), flags as u32, "wire {wire}");
            assert_eq!(super::mint_behavior_to_proto(flags as u32).unwrap(), wire, "flags {flags}");
        }
        // The two that a cast silently confused.
        assert_eq!(super::mint_behavior_from_proto(4).unwrap(), MINT_WITH_PAYMENT as u32);
        assert_ne!(super::mint_behavior_from_proto(4).unwrap(), MINT_WITH_SIGNATURE as u32);
        assert_eq!(super::mint_behavior_from_proto(3).unwrap(), MINT_WITH_SIGNATURE as u32);
        // A behaviour neither side knows is refused, not stored.
        assert!(super::mint_behavior_from_proto(5).is_err());
        assert!(super::mint_behavior_to_proto(1 << 6).is_err());
    }

    use super::*;

    #[test]
    fn authority_round_trip() {
        let pb = pb::Authority { key_type: 2, public_key: vec![0xAAu8; 585], can_burn: true };
        let a = authority_from_proto(&pb);
        let back = authority_to_proto(&a);
        assert_eq!(back, pb);
    }

    #[test]
    fn fee_basis_round_trip() {
        let pb = pb::FeeBasis { r#type: 1, baseline: vec![0xBBu8; 32] };
        let f = fee_basis_from_proto(&pb);
        let back = fee_basis_to_proto(&f);
        assert_eq!(back, pb);
    }

    #[test]
    fn token_config_round_trip() {
        let pb = pb::TokenConfiguration {
            behavior: 0x3F,
            mint_strategy: Some(pb::TokenMintStrategy {
                mint_behavior: 1, proof_basis: 0,
                verkle_root: vec![], authority: None,
                payment_address: vec![], fee_basis: None,
            }),
            units: vec![0x01], supply: vec![0xFF; 32],
            name: "QUIL".into(), symbol: "Q".into(),
            additional_reference: vec![vec![0xAAu8; 64]],
            owner_public_key: vec![0xBBu8; 585],
        };
        let c = token_config_from_proto(&pb).unwrap();
        let back = token_config_to_proto(&c).unwrap();
        assert_eq!(back, pb);
    }

    #[test]
    fn token_config_canonical_round_trip() {
        let pb = pb::TokenConfiguration {
            behavior: 7, mint_strategy: None,
            units: vec![], supply: vec![], name: "T".into(), symbol: "T".into(),
            additional_reference: vec![], owner_public_key: vec![0xCCu8; 585],
        };
        let c = token_config_from_proto(&pb).unwrap();
        let cb = c.to_canonical_bytes().unwrap();
        let c2 = TokenConfiguration::from_canonical_bytes(&cb).unwrap();
        let back = token_config_to_proto(&c2).unwrap();
        assert_eq!(back, pb);
    }

    #[test]
    fn token_deploy_round_trip() {
        let pb = pb::TokenDeploy {
            config: Some(pb::TokenConfiguration {
                behavior: 1, mint_strategy: None, units: vec![], supply: vec![],
                name: "X".into(), symbol: "X".into(),
                additional_reference: vec![], owner_public_key: vec![0xAAu8; 585],
            }),
            rdf_schema: b"schema".to_vec(),
        };
        let d = token_deploy_from_proto(&pb).unwrap();
        let back = token_deploy_to_proto(&d).unwrap();
        assert_eq!(back, pb);
    }

}

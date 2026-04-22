//! Token config types: Authority (0x0500), FeeBasisStruct (0x0501),
//! TokenMintStrategy (0x0502), TokenConfiguration (0x0503).

use quil_types::error::Result;
use super::cursor::*;

pub const TYPE_AUTHORITY: u32 = 0x0500;
pub const TYPE_FEE_BASIS_STRUCT: u32 = 0x0501;
pub const TYPE_TOKEN_MINT_STRATEGY: u32 = 0x0502;
pub const TYPE_TOKEN_CONFIGURATION: u32 = 0x0503;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Authority {
    pub key_type: u32,
    pub public_key: Vec<u8>,
    pub can_burn: bool,
}

impl Authority {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_AUTHORITY);
        put_u32(&mut out, self.key_type);
        put_lp(&mut out, &self.public_key);
        out.push(if self.can_burn { 1 } else { 0 });
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_AUTHORITY, "Authority")?;
        let key_type = read_u32(data, &mut c)?;
        let public_key = read_lp(data, &mut c)?;
        let can_burn = if c < data.len() { data[c] != 0 } else { false };
        Ok(Self { key_type, public_key, can_burn })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FeeBasisStruct {
    pub fee_type: u32,
    pub baseline: Vec<u8>,
}

impl FeeBasisStruct {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_FEE_BASIS_STRUCT);
        put_u32(&mut out, self.fee_type);
        put_lp(&mut out, &self.baseline);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_FEE_BASIS_STRUCT, "FeeBasisStruct")?;
        let fee_type = read_u32(data, &mut c)?;
        let baseline = read_lp(data, &mut c)?;
        Ok(Self { fee_type, baseline })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TokenMintStrategy {
    pub mint_behavior: u32,
    pub proof_basis: u32,
    pub verkle_root: Vec<u8>,
    pub authority: Vec<u8>,    // nested Authority canonical bytes
    pub payment_address: Vec<u8>,
    pub fee_basis: Vec<u8>,    // nested FeeBasisStruct canonical bytes
}

impl TokenMintStrategy {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_TOKEN_MINT_STRATEGY);
        put_u32(&mut out, self.mint_behavior);
        put_u32(&mut out, self.proof_basis);
        put_lp(&mut out, &self.verkle_root);
        put_lp(&mut out, &self.authority);
        put_lp(&mut out, &self.payment_address);
        put_lp(&mut out, &self.fee_basis);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_TOKEN_MINT_STRATEGY, "TokenMintStrategy")?;
        let mint_behavior = read_u32(data, &mut c)?;
        let proof_basis = read_u32(data, &mut c)?;
        let verkle_root = read_lp(data, &mut c)?;
        let authority = read_lp(data, &mut c)?;
        let payment_address = read_lp(data, &mut c)?;
        let fee_basis = read_lp(data, &mut c)?;
        Ok(Self { mint_behavior, proof_basis, verkle_root, authority, payment_address, fee_basis })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TokenConfiguration {
    pub behavior: u32,
    pub mint_strategy: Vec<u8>,       // nested TokenMintStrategy canonical bytes
    pub units: Vec<u8>,
    pub supply: Vec<u8>,
    pub name: Vec<u8>,
    pub symbol: Vec<u8>,
    pub additional_reference: Vec<Vec<u8>>,
    pub owner_public_key: Vec<u8>,
}

impl TokenConfiguration {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_TOKEN_CONFIGURATION);
        put_u32(&mut out, self.behavior);
        put_lp(&mut out, &self.mint_strategy);
        put_lp(&mut out, &self.units);
        put_lp(&mut out, &self.supply);
        put_lp(&mut out, &self.name);
        put_lp(&mut out, &self.symbol);
        write_array(&mut out, &self.additional_reference);
        put_lp(&mut out, &self.owner_public_key);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_TOKEN_CONFIGURATION, "TokenConfiguration")?;
        let behavior = read_u32(data, &mut c)?;
        let mint_strategy = read_lp(data, &mut c)?;
        let units = read_lp(data, &mut c)?;
        let supply = read_lp(data, &mut c)?;
        let name = read_lp(data, &mut c)?;
        let symbol = read_lp(data, &mut c)?;
        let additional_reference = read_array(data, &mut c)?;
        let owner_public_key = read_lp(data, &mut c)?;
        Ok(Self { behavior, mint_strategy, units, supply, name, symbol, additional_reference, owner_public_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_round_trip() {
        let a = Authority { key_type: 2, public_key: vec![0xAAu8; 585], can_burn: true };
        let b = a.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_AUTHORITY.to_be_bytes());
        assert_eq!(Authority::from_canonical_bytes(&b).unwrap(), a);
    }

    #[test]
    fn fee_basis_round_trip() {
        let f = FeeBasisStruct { fee_type: 1, baseline: vec![0xBBu8; 32] };
        let b = f.to_canonical_bytes().unwrap();
        assert_eq!(FeeBasisStruct::from_canonical_bytes(&b).unwrap(), f);
    }

    #[test]
    fn mint_strategy_round_trip() {
        let m = TokenMintStrategy {
            mint_behavior: 3, proof_basis: 1,
            verkle_root: vec![0x11u8; 32],
            authority: Authority { key_type: 2, public_key: vec![0x22u8; 57], can_burn: false }.to_canonical_bytes().unwrap(),
            payment_address: vec![0x33u8; 32],
            fee_basis: FeeBasisStruct { fee_type: 0, baseline: vec![] }.to_canonical_bytes().unwrap(),
        };
        let b = m.to_canonical_bytes().unwrap();
        assert_eq!(TokenMintStrategy::from_canonical_bytes(&b).unwrap(), m);
    }

    #[test]
    fn token_configuration_round_trip() {
        let tc = TokenConfiguration {
            behavior: 0x3F, mint_strategy: vec![],
            units: vec![0x01], supply: vec![0xFF; 32],
            name: b"QUIL".to_vec(), symbol: b"Q".to_vec(),
            additional_reference: vec![vec![0xAAu8; 64]],
            owner_public_key: vec![0xBBu8; 585],
        };
        let b = tc.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_TOKEN_CONFIGURATION.to_be_bytes());
        assert_eq!(TokenConfiguration::from_canonical_bytes(&b).unwrap(), tc);
    }

    #[test]
    fn token_configuration_empty_fields() {
        let tc = TokenConfiguration::default();
        let b = tc.to_canonical_bytes().unwrap();
        assert_eq!(TokenConfiguration::from_canonical_bytes(&b).unwrap(), tc);
    }

    #[test]
    fn type_prefixes_distinct() {
        use std::collections::HashSet;
        let ids: HashSet<u32> = [TYPE_AUTHORITY, TYPE_FEE_BASIS_STRUCT, TYPE_TOKEN_MINT_STRATEGY, TYPE_TOKEN_CONFIGURATION].into_iter().collect();
        assert_eq!(ids.len(), 4);
    }
}

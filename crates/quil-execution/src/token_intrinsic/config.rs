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

/// Decode a `TokenMintStrategy` from the custom packed binary format
/// used by Go `unpackAndVerifyTokenConfigurationMetadata` when reading
/// the `MintStrategy` field out of the RDF multiprover. Layout:
///
/// ```text
/// u16 mint_behavior
/// u16 proof_basis
/// u8  has_verkle_root
///   if has: u16 len, [len bytes]
/// u8  has_authority
///   if has: u16 key_type, u16 pk_len, [pk_len bytes], u8 can_burn
/// u16 payment_addr_len, [payment_addr_len bytes]
/// u8  has_fee_basis
///   if has: u16 fee_type, u16 baseline_len, [baseline_len bytes]
/// ```
///
/// Ports Go `token_configuration.go:980-1113`.
pub fn decode_mint_strategy_packed(data: &[u8]) -> Result<TokenMintStrategy> {
    use quil_types::error::QuilError;

    let mut cursor = 0usize;

    fn read_u8(data: &[u8], c: &mut usize) -> Result<u8> {
        if *c + 1 > data.len() {
            return Err(QuilError::InvalidArgument(
                "mint strategy packed: short read u8".into(),
            ));
        }
        let b = data[*c];
        *c += 1;
        Ok(b)
    }
    fn read_u16_be(data: &[u8], c: &mut usize) -> Result<u16> {
        if *c + 2 > data.len() {
            return Err(QuilError::InvalidArgument(
                "mint strategy packed: short read u16".into(),
            ));
        }
        let v = u16::from_be_bytes([data[*c], data[*c + 1]]);
        *c += 2;
        Ok(v)
    }
    fn read_bytes<'a>(data: &'a [u8], c: &mut usize, n: usize) -> Result<&'a [u8]> {
        if *c + n > data.len() {
            return Err(QuilError::InvalidArgument(format!(
                "mint strategy packed: short read {} bytes", n
            )));
        }
        let b = &data[*c..*c + n];
        *c += n;
        Ok(b)
    }

    let mint_behavior = read_u16_be(data, &mut cursor)? as u32;
    let proof_basis = read_u16_be(data, &mut cursor)? as u32;

    let mut verkle_root = Vec::new();
    if read_u8(data, &mut cursor)? == 1 {
        let n = read_u16_be(data, &mut cursor)? as usize;
        verkle_root = read_bytes(data, &mut cursor, n)?.to_vec();
    }

    let mut authority: Vec<u8> = Vec::new();
    if read_u8(data, &mut cursor)? == 1 {
        let key_type = read_u16_be(data, &mut cursor)? as u32;
        let pk_len = read_u16_be(data, &mut cursor)? as usize;
        let public_key = read_bytes(data, &mut cursor, pk_len)?.to_vec();
        let can_burn = read_u8(data, &mut cursor)? != 0;
        authority = Authority { key_type, public_key, can_burn }
            .to_canonical_bytes()?;
    }

    let pa_len = read_u16_be(data, &mut cursor)? as usize;
    let payment_address = if pa_len > 0 {
        read_bytes(data, &mut cursor, pa_len)?.to_vec()
    } else {
        Vec::new()
    };

    let mut fee_basis: Vec<u8> = Vec::new();
    if cursor < data.len() && read_u8(data, &mut cursor)? == 1 {
        let fee_type = read_u16_be(data, &mut cursor)? as u32;
        let bl_len = read_u16_be(data, &mut cursor)? as usize;
        if bl_len > 32 {
            return Err(QuilError::InvalidArgument(
                "mint strategy packed: baseline > 32 bytes".into(),
            ));
        }
        let baseline = if bl_len > 0 {
            read_bytes(data, &mut cursor, bl_len)?.to_vec()
        } else {
            Vec::new()
        };
        fee_basis = FeeBasisStruct { fee_type, baseline }
            .to_canonical_bytes()?;
    }

    Ok(TokenMintStrategy {
        mint_behavior,
        proof_basis,
        verkle_root,
        authority,
        payment_address,
        fee_basis,
    })
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

    #[test]
    fn decode_packed_minimal_mint_with_proof() {
        // MintBehavior=1 (MintWithProof), ProofBasis=1 (PoMW), no
        // verkle_root, no authority, empty payment_address, no fee_basis.
        let data: Vec<u8> = vec![
            0x00, 0x01, // mint_behavior
            0x00, 0x01, // proof_basis
            0x00,       // has_verkle_root = 0
            0x00,       // has_authority = 0
            0x00, 0x00, // payment_addr_len = 0
            0x00,       // has_fee_basis = 0
        ];
        let strat = decode_mint_strategy_packed(&data).unwrap();
        assert_eq!(strat.mint_behavior, 1);
        assert_eq!(strat.proof_basis, 1);
        assert!(strat.verkle_root.is_empty());
        assert!(strat.authority.is_empty());
        assert!(strat.payment_address.is_empty());
        assert!(strat.fee_basis.is_empty());
    }

    #[test]
    fn decode_packed_authority_with_payment() {
        // MintBehavior=2 (Authority), ProofBasis=0, has_authority=1
        // with Ed448 key, payment_addr=32 zeros, no fee_basis.
        let mut data: Vec<u8> = Vec::new();
        data.extend(&[0x00, 0x02]); // mint_behavior
        data.extend(&[0x00, 0x00]); // proof_basis
        data.push(0x00);             // has_verkle_root
        data.push(0x01);             // has_authority
        data.extend(&[0x00, 0x01]); // key_type = 1 (Ed448 in Go)
        data.extend(&[0x00, 0x39]); // pk_len = 57
        data.extend(std::iter::repeat(0xAAu8).take(57));
        data.push(0x01);             // can_burn
        data.extend(&[0x00, 0x20]); // payment_addr_len = 32
        data.extend(std::iter::repeat(0xBBu8).take(32));
        data.push(0x00);             // has_fee_basis

        let strat = decode_mint_strategy_packed(&data).unwrap();
        assert_eq!(strat.mint_behavior, 2);
        let a = Authority::from_canonical_bytes(&strat.authority).unwrap();
        assert_eq!(a.key_type, 1);
        assert_eq!(a.public_key, vec![0xAAu8; 57]);
        assert!(a.can_burn);
        assert_eq!(strat.payment_address, vec![0xBBu8; 32]);
    }
}

//! TokenDeploy (0x0504) and TokenUpdate (0x0505).

use quil_types::error::Result;
use super::cursor::*;

pub const TYPE_TOKEN_DEPLOY: u32 = 0x0504;
pub const TYPE_TOKEN_UPDATE: u32 = 0x0505;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TokenDeploy {
    pub config: Vec<u8>,      // nested TokenConfiguration canonical bytes
    pub rdf_schema: Vec<u8>,
}

impl TokenDeploy {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_TOKEN_DEPLOY);
        put_lp(&mut out, &self.config);
        put_lp(&mut out, &self.rdf_schema);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_TOKEN_DEPLOY, "TokenDeploy")?;
        let config = read_lp(data, &mut c)?;
        let rdf_schema = read_lp(data, &mut c)?;
        Ok(Self { config, rdf_schema })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TokenUpdate {
    pub config: Vec<u8>,      // nested TokenConfiguration canonical bytes
    pub rdf_schema: Vec<u8>,
    pub public_key_signature_bls48581: Vec<u8>, // nested BLS48581AggregateSignature
}

impl TokenUpdate {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_TOKEN_UPDATE);
        put_lp(&mut out, &self.config);
        put_lp(&mut out, &self.rdf_schema);
        put_lp(&mut out, &self.public_key_signature_bls48581);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_TOKEN_UPDATE, "TokenUpdate")?;
        let config = read_lp(data, &mut c)?;
        let rdf_schema = read_lp(data, &mut c)?;
        let public_key_signature_bls48581 = read_lp(data, &mut c)?;
        Ok(Self { config, rdf_schema, public_key_signature_bls48581 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_deploy_round_trip() {
        let d = TokenDeploy { config: vec![0x11u8; 50], rdf_schema: b"schema".to_vec() };
        let b = d.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_TOKEN_DEPLOY.to_be_bytes());
        assert_eq!(TokenDeploy::from_canonical_bytes(&b).unwrap(), d);
    }

    #[test]
    fn token_update_round_trip() {
        let u = TokenUpdate { config: vec![0x22u8; 30], rdf_schema: vec![], public_key_signature_bls48581: vec![0x33u8; 74] };
        let b = u.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_TOKEN_UPDATE.to_be_bytes());
        assert_eq!(TokenUpdate::from_canonical_bytes(&b).unwrap(), u);
    }

    #[test]
    fn token_deploy_empty() {
        let d = TokenDeploy::default();
        let b = d.to_canonical_bytes().unwrap();
        assert_eq!(TokenDeploy::from_canonical_bytes(&b).unwrap(), d);
    }
}

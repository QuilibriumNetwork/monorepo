//! ComputeConfiguration (0x0600), ComputeDeploy (0x0601),
//! ComputeUpdate (0x0602).

use quil_types::error::Result;
use super::cursor::*;

pub const TYPE_COMPUTE_CONFIGURATION: u32 = 0x0600;
pub const TYPE_COMPUTE_DEPLOY: u32 = 0x0601;
pub const TYPE_COMPUTE_UPDATE: u32 = 0x0602;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComputeConfiguration {
    pub read_public_key: Vec<u8>,
    pub write_public_key: Vec<u8>,
    pub owner_public_key: Vec<u8>,
}

impl ComputeConfiguration {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_COMPUTE_CONFIGURATION);
        put_lp(&mut out, &self.read_public_key);
        put_lp(&mut out, &self.write_public_key);
        put_lp(&mut out, &self.owner_public_key);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_COMPUTE_CONFIGURATION, "ComputeConfiguration")?;
        Ok(Self { read_public_key: read_lp(data, &mut c)?, write_public_key: read_lp(data, &mut c)?, owner_public_key: read_lp(data, &mut c)? })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComputeDeploy {
    pub config: Vec<u8>,      // nested ComputeConfiguration canonical bytes
    pub rdf_schema: Vec<u8>,
}

impl ComputeDeploy {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_COMPUTE_DEPLOY);
        put_lp(&mut out, &self.config);
        put_lp(&mut out, &self.rdf_schema);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_COMPUTE_DEPLOY, "ComputeDeploy")?;
        Ok(Self { config: read_lp(data, &mut c)?, rdf_schema: read_lp(data, &mut c)? })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ComputeUpdate {
    pub config: Vec<u8>,
    pub rdf_schema: Vec<u8>,
    pub public_key_signature_bls48581: Vec<u8>,
}

impl ComputeUpdate {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_COMPUTE_UPDATE);
        put_lp(&mut out, &self.config);
        put_lp(&mut out, &self.rdf_schema);
        put_lp(&mut out, &self.public_key_signature_bls48581);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_COMPUTE_UPDATE, "ComputeUpdate")?;
        Ok(Self { config: read_lp(data, &mut c)?, rdf_schema: read_lp(data, &mut c)?, public_key_signature_bls48581: read_lp(data, &mut c)? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_config_round_trip() {
        let c = ComputeConfiguration { read_public_key: vec![1u8; 57], write_public_key: vec![2u8; 57], owner_public_key: vec![3u8; 585] };
        let b = c.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_COMPUTE_CONFIGURATION.to_be_bytes());
        assert_eq!(ComputeConfiguration::from_canonical_bytes(&b).unwrap(), c);
    }

    #[test]
    fn compute_deploy_round_trip() {
        let d = ComputeDeploy { config: vec![0x11u8; 50], rdf_schema: b"schema".to_vec() };
        let b = d.to_canonical_bytes().unwrap();
        assert_eq!(ComputeDeploy::from_canonical_bytes(&b).unwrap(), d);
    }

    #[test]
    fn compute_update_round_trip() {
        let u = ComputeUpdate { config: vec![0x22u8; 30], rdf_schema: vec![], public_key_signature_bls48581: vec![0x33u8; 74] };
        let b = u.to_canonical_bytes().unwrap();
        assert_eq!(ComputeUpdate::from_canonical_bytes(&b).unwrap(), u);
    }

    #[test]
    fn all_empty() {
        for f in [
            ComputeConfiguration::default().to_canonical_bytes().unwrap(),
            ComputeDeploy::default().to_canonical_bytes().unwrap(),
            ComputeUpdate::default().to_canonical_bytes().unwrap(),
        ] {
            assert!(f.len() >= 4);
        }
    }
}

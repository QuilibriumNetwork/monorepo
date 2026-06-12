//! Proof canonical-bytes: Multiproof (0x0313), Path (0x0314),
//! TraversalSubProof (0x0315), TraversalProof (0x0316).

use quil_types::error::Result;
use crate::canonical_cursor::{
    put_u32, put_u64, put_lp, read_u32, read_u64, read_lp,
    read_array, write_array, expect_tp as expect,
};

pub const TYPE_MULTIPROOF: u32 = 0x0313;
pub const TYPE_PATH: u32 = 0x0314;
pub const TYPE_TRAVERSAL_SUB_PROOF: u32 = 0x0315;
pub const TYPE_TRAVERSAL_PROOF: u32 = 0x0316;

// -- Multiproof --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Multiproof {
    pub multicommitment: Vec<u8>,
    pub proof: Vec<u8>,
}

impl Multiproof {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_MULTIPROOF);
        put_lp(&mut out, &self.multicommitment);
        put_lp(&mut out, &self.proof);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect(read_u32(data, &mut c)?, TYPE_MULTIPROOF, "Multiproof")?;
        Ok(Self { multicommitment: read_lp(data, &mut c)?, proof: read_lp(data, &mut c)? })
    }
}

// -- Path --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Path {
    pub indices: Vec<u64>,
}

impl Path {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PATH);
        put_u32(&mut out, self.indices.len() as u32);
        for &i in &self.indices { put_u64(&mut out, i); }
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect(read_u32(data, &mut c)?, TYPE_PATH, "Path")?;
        let n = read_u32(data, &mut c)? as usize;
        let mut indices = Vec::with_capacity(n);
        for _ in 0..n { indices.push(read_u64(data, &mut c)?); }
        Ok(Self { indices })
    }
}

// -- TraversalSubProof --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TraversalSubProof {
    pub commits: Vec<Vec<u8>>,
    pub ys: Vec<Vec<u8>>,
    pub paths: Vec<Vec<u8>>, // nested Path canonical bytes
}

impl TraversalSubProof {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_TRAVERSAL_SUB_PROOF);
        write_array(&mut out, &self.commits);
        write_array(&mut out, &self.ys);
        write_array(&mut out, &self.paths);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect(read_u32(data, &mut c)?, TYPE_TRAVERSAL_SUB_PROOF, "TraversalSubProof")?;
        Ok(Self { commits: read_array(data, &mut c)?, ys: read_array(data, &mut c)?, paths: read_array(data, &mut c)? })
    }
}

// -- TraversalProof --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TraversalProof {
    pub multiproof: Vec<u8>, // nested Multiproof canonical bytes
    pub sub_proofs: Vec<Vec<u8>>, // nested TraversalSubProof canonical bytes
}

impl TraversalProof {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_TRAVERSAL_PROOF);
        put_lp(&mut out, &self.multiproof);
        write_array(&mut out, &self.sub_proofs);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect(read_u32(data, &mut c)?, TYPE_TRAVERSAL_PROOF, "TraversalProof")?;
        Ok(Self { multiproof: read_lp(data, &mut c)?, sub_proofs: read_array(data, &mut c)? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn multiproof_round_trip() {
        let m = Multiproof { multicommitment: vec![0xAAu8; 64], proof: vec![0xBBu8; 128] };
        let b = m.to_canonical_bytes().unwrap();
        assert_eq!(Multiproof::from_canonical_bytes(&b).unwrap(), m);
    }
    #[test] fn path_round_trip() {
        let p = Path { indices: vec![1, 2, 3, 42, 100] };
        let b = p.to_canonical_bytes().unwrap();
        assert_eq!(Path::from_canonical_bytes(&b).unwrap(), p);
    }
    #[test] fn path_empty() {
        let p = Path::default();
        let b = p.to_canonical_bytes().unwrap();
        assert_eq!(Path::from_canonical_bytes(&b).unwrap(), p);
    }
    #[test] fn traversal_sub_proof_round_trip() {
        let s = TraversalSubProof {
            commits: vec![vec![1u8; 64], vec![2u8; 64]],
            ys: vec![vec![3u8; 64], vec![4u8; 64]],
            paths: vec![Path { indices: vec![0, 1] }.to_canonical_bytes().unwrap()],
        };
        let b = s.to_canonical_bytes().unwrap();
        assert_eq!(TraversalSubProof::from_canonical_bytes(&b).unwrap(), s);
    }
    #[test] fn traversal_proof_round_trip() {
        let t = TraversalProof {
            multiproof: Multiproof { multicommitment: vec![0xAAu8; 64], proof: vec![0xBBu8; 128] }.to_canonical_bytes().unwrap(),
            sub_proofs: vec![TraversalSubProof::default().to_canonical_bytes().unwrap()],
        };
        let b = t.to_canonical_bytes().unwrap();
        assert_eq!(TraversalProof::from_canonical_bytes(&b).unwrap(), t);
    }
    #[test] fn all_empty_defaults() {
        Multiproof::from_canonical_bytes(&Multiproof::default().to_canonical_bytes().unwrap()).unwrap();
        Path::from_canonical_bytes(&Path::default().to_canonical_bytes().unwrap()).unwrap();
        TraversalSubProof::from_canonical_bytes(&TraversalSubProof::default().to_canonical_bytes().unwrap()).unwrap();
        TraversalProof::from_canonical_bytes(&TraversalProof::default().to_canonical_bytes().unwrap()).unwrap();
    }
    #[test] fn type_prefixes_distinct() {
        use std::collections::HashSet;
        let ids: HashSet<u32> = [TYPE_MULTIPROOF, TYPE_PATH, TYPE_TRAVERSAL_SUB_PROOF, TYPE_TRAVERSAL_PROOF].into_iter().collect();
        assert_eq!(ids.len(), 4);
    }
}

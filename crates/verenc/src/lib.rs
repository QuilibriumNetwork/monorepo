pub mod rdkgith;
pub mod utils;
pub mod pke;
pub mod ve;
pub mod seed_tree;

use std::convert::TryFrom;
use std::convert::TryInto;

use ed448_goldilocks_plus::CompressedEdwardsY;
use ed448_goldilocks_plus::EdwardsPoint;
use ed448_goldilocks_plus::Scalar;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

pub use crate::rdkgith::*;
pub use crate::utils::*;
pub use crate::pke::*;
pub use crate::ve::*;
pub use crate::seed_tree::*;

uniffi::include_scaffolding!("lib");

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct VerencCiphertext {
    pub c1: Vec<u8>,
    pub c2: Vec<u8>,
    pub i: u64,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct VerencShare {
    pub s1: Vec<u8>,
    pub s2: Vec<u8>,
    pub i: u64,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct VerencProofAndBlindingKey {
    pub blinding_key: Vec<u8>,
    pub blinding_pubkey: Vec<u8>,
    pub decryption_key: Vec<u8>,
    pub encryption_key: Vec<u8>,
    pub statement: Vec<u8>,
    pub challenge: Vec<u8>,
    pub polycom: Vec<Vec<u8>>,
    pub ctexts: Vec<VerencCiphertext>,
    pub shares_rands: Vec<VerencShare>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct VerencDecrypt {
    pub blinding_pubkey: Vec<u8>,
    pub decryption_key: Vec<u8>,
    pub statement: Vec<u8>,
    pub ciphertexts: CompressedCiphertext,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct VerencProof {
    pub blinding_pubkey: Vec<u8>,
    pub encryption_key: Vec<u8>,
    pub statement: Vec<u8>,
    pub challenge: Vec<u8>,
    pub polycom: Vec<Vec<u8>>,
    pub ctexts: Vec<VerencCiphertext>,
    pub shares_rands: Vec<VerencShare>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct CompressedCiphertext {
    pub ctexts: Vec<VerencCiphertext>,
    pub aux: Vec<Vec<u8>>,
}

pub fn new_verenc_proof(data: Vec<u8>) -> VerencProofAndBlindingKey {
    if data.len() != 56 {
        return VerencProofAndBlindingKey{
            blinding_key: vec![],
            blinding_pubkey: vec![],
            decryption_key: vec![],
            encryption_key: vec![],
            statement: vec![],
            challenge: vec![],
            polycom: vec![],
            ctexts: vec![],
            shares_rands: vec![],
        };
    }

    let blind = Scalar::random(&mut OsRng);
    let params = CurveParams::init(EdwardsPoint::GENERATOR * blind);
    let pke = Elgamal::setup(&params);
    let (N, t, n) = RVE_PARAMS[0];
    let vparams = RDkgithParams{ N, t, n };
    let mut ve = RDkgith::setup(&params, &vparams, pke.clone());

    let dk = ve.kgen();
    let (stm, wit) = ve.igen(&data.try_into().unwrap());
    let pi = ve.prove(&stm, &wit);
    
    return VerencProofAndBlindingKey {
        blinding_key: blind.to_bytes().to_vec(),
        blinding_pubkey: (EdwardsPoint::GENERATOR * blind).compress().to_bytes().to_vec(),
        decryption_key: dk.to_bytes().to_vec(),
        encryption_key: (EdwardsPoint::GENERATOR * dk).compress().to_bytes().to_vec(),
        statement: stm.compress().to_bytes().to_vec(),
        challenge: pi.challenge,
        polycom: pi.polycom.iter().map(|p| p.compress().to_bytes().to_vec()).collect(),
        ctexts: pi.ctexts.iter().map(|c| VerencCiphertext {
          c1: c.0.c1.compress().to_bytes().to_vec(),
          c2: c.0.c2.to_bytes().to_vec(),
          i: c.1 as u64,
        }).collect(),
        shares_rands: pi.shares_rands.iter().map(|s| VerencShare {
          s1: s.0.to_bytes().to_vec(),
          s2: s.1.to_bytes().to_vec(),
          i: s.2 as u64,
        }).collect(),
    };
}

pub fn new_verenc_proof_encrypt_only(data: Vec<u8>, encryption_key_bytes: Vec<u8>) -> VerencProofAndBlindingKey {
    if data.len() != 56 {
        return VerencProofAndBlindingKey{
            blinding_key: vec![],
            blinding_pubkey: vec![],
            decryption_key: vec![],
            encryption_key: vec![],
            statement: vec![],
            challenge: vec![],
            polycom: vec![],
            ctexts: vec![],
            shares_rands: vec![],
        };
    }

    let encryption_key = point_from_bytes(encryption_key_bytes.clone());
    if encryption_key.is_none() {
        return VerencProofAndBlindingKey{
            blinding_key: vec![],
            blinding_pubkey: vec![],
            decryption_key: vec![],
            encryption_key: vec![],
            statement: vec![],
            challenge: vec![],
            polycom: vec![],
            ctexts: vec![],
            shares_rands: vec![],
        };
    }

    let blind = Scalar::random(&mut OsRng);
    let params = CurveParams::init(EdwardsPoint::GENERATOR * blind);
    let pke = Elgamal::setup(&params);
    let (N, t, n) = RVE_PARAMS[0];
    let vparams = RDkgithParams{ N, t, n };
    let mut ve = RDkgith::setup(&params, &vparams, pke.clone());
    
    ve.set_ek(PKEPublicKey{
        ek: encryption_key.unwrap(),
    });
    let (stm, wit) = ve.igen(&data.try_into().unwrap());
    let pi = ve.prove(&stm, &wit);
    
    return VerencProofAndBlindingKey {
        blinding_key: blind.to_bytes().to_vec(),
        blinding_pubkey: (EdwardsPoint::GENERATOR * blind).compress().to_bytes().to_vec(),
        decryption_key: vec![],
        encryption_key: encryption_key_bytes.clone(),
        statement: stm.compress().to_bytes().to_vec(),
        challenge: pi.challenge,
        polycom: pi.polycom.iter().map(|p| p.compress().to_bytes().to_vec()).collect(),
        ctexts: pi.ctexts.iter().map(|c| VerencCiphertext {
          c1: c.0.c1.compress().to_bytes().to_vec(),
          c2: c.0.c2.to_bytes().to_vec(),
          i: c.1 as u64,
        }).collect(),
        shares_rands: pi.shares_rands.iter().map(|s| VerencShare {
          s1: s.0.to_bytes().to_vec(),
          s2: s.1.to_bytes().to_vec(),
          i: s.2 as u64,
        }).collect(),
    };
}

fn point_from_bytes(bytes: Vec<u8>) -> Option<EdwardsPoint> {
    if bytes.len() != 57 {
      return None;
    }

    let key_bytes: Result<[u8; 57], _> = bytes.try_into();
    if key_bytes.is_err() {
      return None;
    }

    let compressed_key = CompressedEdwardsY::try_from(key_bytes.unwrap());
    if compressed_key.is_err() {
      return None;
    }

    let key = compressed_key.unwrap().decompress();
    if key.is_none().into() {
      return None;
    }

    return Some(key.unwrap());
}

pub fn verenc_verify(proof: VerencProof) -> bool {
    let blinding_key = point_from_bytes(proof.blinding_pubkey);
    if blinding_key.is_none() {
        return false;
    }

    let statement = point_from_bytes(proof.statement);
    if statement.is_none() {
        return false;
    }

    let encryption_key = point_from_bytes(proof.encryption_key);
    if encryption_key.is_none() {
        return false;
    }

    let mut polycom: Vec<EdwardsPoint> = Vec::new();
    for p in proof.polycom {
        let com = point_from_bytes(p);
        if com.is_none() {
            return false;
        }

        polycom.push(com.unwrap());
    }

    let mut ctexts: Vec<(PKECipherText, usize)> = Vec::new();
    for c in proof.ctexts {
        let c1 = point_from_bytes(c.c1);
        if c1.is_none() {
            return false;
        }

        if c.c2.len() != 56 {
            return false;
        }

        let c2 = Scalar::from_bytes(&c.c2.try_into().unwrap());
        ctexts.push((PKECipherText{c1: c1.unwrap(), c2: c2}, c.i as usize));
    }

    let mut shares: Vec<(Scalar, Scalar, usize)> = Vec::new();
    for s in proof.shares_rands {
        if s.s1.len() != 56 {
            return false;
        }

        if s.s2.len() != 56 {
            return false;
        }

        let s1 = Scalar::from_bytes(&s.s1.try_into().unwrap());
        let s2 = Scalar::from_bytes(&s.s2.try_into().unwrap());
        shares.push((s1, s2, s.i as usize));
    }

    let params = CurveParams::init(blinding_key.unwrap());
    let pke = Elgamal::setup(&params);
    let (N, t, n) = RVE_PARAMS[0];
    let vparams = RDkgithParams{ N, t, n };
    let mut ve = RDkgith::setup(&params, &vparams, pke.clone());
    ve.set_ek(PKEPublicKey{
        ek: encryption_key.unwrap(),
    });

    return ve.verify(&statement.unwrap(), &RDkgithProof{
        challenge: proof.challenge,
        polycom: polycom,
        ctexts: ctexts,
        shares_rands: shares,
    });
}


pub fn verenc_compress(proof: VerencProof) -> CompressedCiphertext {
    let blinding_key = point_from_bytes(proof.blinding_pubkey);
    if blinding_key.is_none() {
        return CompressedCiphertext{
            ctexts: vec![],
            aux: vec![],
        };
    }

    let statement = point_from_bytes(proof.statement);
    if statement.is_none() {
        return CompressedCiphertext{
            ctexts: vec![],
            aux: vec![],
        };
    }

    let encryption_key = point_from_bytes(proof.encryption_key);
    if encryption_key.is_none() {
        return CompressedCiphertext{
            ctexts: vec![],
            aux: vec![],
        };
    }

    let mut polycom: Vec<EdwardsPoint> = Vec::new();
    for p in proof.polycom {
        let com = point_from_bytes(p);
        if com.is_none() {
            return CompressedCiphertext{
                ctexts: vec![],
                aux: vec![],
            };
        }

        polycom.push(com.unwrap());
    }

    let mut ctexts: Vec<(PKECipherText, usize)> = Vec::new();
    for c in proof.ctexts {
        let c1 = point_from_bytes(c.c1);
        if c1.is_none() {
            return CompressedCiphertext{
                ctexts: vec![],
                aux: vec![],
            };
        }

        if c.c2.len() != 56 {
            return CompressedCiphertext{
                ctexts: vec![],
                aux: vec![],
            };
        }

        let c2 = Scalar::from_bytes(&c.c2.try_into().unwrap());
        ctexts.push((PKECipherText{c1: c1.unwrap(), c2: c2}, c.i as usize));
    }

    let mut shares: Vec<(Scalar, Scalar, usize)> = Vec::new();
    for s in proof.shares_rands {
        if s.s1.len() != 56 {
            return CompressedCiphertext{
                ctexts: vec![],
                aux: vec![],
            };
        }

        if s.s2.len() != 56 {
            return CompressedCiphertext{
                ctexts: vec![],
                aux: vec![],
            };
        }

        let s1 = Scalar::from_bytes(&s.s1.try_into().unwrap());
        let s2 = Scalar::from_bytes(&s.s2.try_into().unwrap());
        shares.push((s1, s2, s.i as usize));
    }

    let params = CurveParams::init(blinding_key.unwrap());
    let pke = Elgamal::setup(&params);
    let (N, t, n) = RVE_PARAMS[0];
    let vparams = RDkgithParams{ N, t, n };
    let mut ve = RDkgith::setup(&params, &vparams, pke.clone());
    ve.set_ek(PKEPublicKey{
        ek: encryption_key.unwrap(),
    });
    let ve_ct = ve.compress(&statement.unwrap(), &RDkgithProof{
        challenge: proof.challenge,
        polycom: polycom,
        ctexts: ctexts,
        shares_rands: shares,
    });
    return CompressedCiphertext{
        ctexts: ve_ct.ctexts.iter().map(|v| VerencCiphertext{
            c1: v.c1.compress().to_bytes().to_vec(),
            c2: v.c2.to_bytes().to_vec(),
            i: 0,
        }).collect(),
        aux: ve_ct.aux.iter().map(|a| a.to_bytes().to_vec()).collect(),
    };
}

pub fn verenc_recover(recovery: VerencDecrypt) -> Vec<u8> {
    let blinding_key = point_from_bytes(recovery.blinding_pubkey);
    if blinding_key.is_none() {
        return vec![];
    }

    let statement = point_from_bytes(recovery.statement);
    if statement.is_none() {
        return vec![];
    }

    if recovery.decryption_key.len() != 56 {
        return vec![];
    }

    let decryption_key = Scalar::from_bytes(&recovery.decryption_key.try_into().unwrap());
    let mut ctexts: Vec<PKECipherText> = Vec::new();
    let mut aux: Vec<Scalar> = Vec::new();
    for c in recovery.ciphertexts.ctexts {
        let c1 = point_from_bytes(c.c1);
        if c1.is_none() {
            return vec![];
        }

        if c.c2.len() != 56 {
            return vec![];
        }

        let c2 = Scalar::from_bytes(&c.c2.try_into().unwrap());
        ctexts.push(PKECipherText{c1: c1.unwrap(), c2: c2});
    }

    for c in recovery.ciphertexts.aux {
        if c.len() != 56 {
            return vec![];
        }

        let a = Scalar::from_bytes(&c.try_into().unwrap());
        aux.push(a);
    }

    let ve_ct = RDkgithCipherText{
        ctexts: ctexts,
        aux: aux,
    };

    let params = CurveParams::init(blinding_key.unwrap());
    let pke = Elgamal::setup(&params);
    let (N, t, n) = RVE_PARAMS[0];
    let vparams = RDkgithParams{ N, t, n };
    let mut ve = RDkgith::setup(&params, &vparams, pke.clone());
    let wit_recover = ve.recover(&statement.unwrap(), &decryption_key, &ve_ct);
    return wit_recover.to_bytes().to_vec();
}

pub fn chunk_data_for_verenc(data: Vec<u8>) -> Vec<Vec<u8>> {
    return encode_to_curve448_scalars(&data);
}

pub fn combine_chunked_data(chunks: Vec<Vec<u8>>) -> Vec<u8> {
    return decode_from_curve448_scalars(&chunks);
}

pub fn verenc_verify_statement(input: Vec<u8>, blinding_pubkey: Vec<u8>, statement: Vec<u8>) -> bool {
  if input.len() != 56 || blinding_pubkey.len() != 57 || statement.len() != 57 {
    return false
  }
  
  let blind = point_from_bytes(blinding_pubkey);
  if blind.is_none() {
    return false;
  }

  let st = blind.unwrap() * Scalar::from_bytes(input.as_slice().try_into().unwrap());
  return st.compress().to_bytes().to_vec() == statement;
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::*;

    #[test]
    fn test_verenc() {
        let data = vec!['h' as u8, 'e' as u8, 'l' as u8, 'l' as u8, 'o' as u8, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0];
        let proof = new_verenc_proof(data.clone());
        let proofdata = proof.clone();
        let pubproof = VerencProof { blinding_pubkey: proof.blinding_pubkey, encryption_key: proof.encryption_key, statement: proof.statement, challenge: proof.challenge, polycom: proof.polycom, ctexts: proof.ctexts, shares_rands: proof.shares_rands };
        assert!(verenc_verify(pubproof.clone()));
        let compressed = verenc_compress(pubproof);
        let result = verenc_recover(VerencDecrypt{
            blinding_pubkey: proofdata.blinding_pubkey,
            decryption_key: proof.decryption_key,
            statement: proofdata.statement,
            ciphertexts: compressed,
        });

        assert!(data == result);
    }

    #[test]
    fn test_chunking() {
        let mut roundcheck: [u8; 1266] = [0u8;1266];
        OsRng::fill_bytes(&mut OsRng, &mut roundcheck);
        let rndch = chunk_data_for_verenc(roundcheck.to_vec());
        assert!(rndch.len() == 24);
        for i in 0..1000 {
            let mut data: [u8; 1265] = [0u8;1265];
            OsRng::fill_bytes(&mut OsRng, &mut data);
            let chunks = chunk_data_for_verenc(data.to_vec());
            assert!(chunks.len() == 23);
            for chunk in chunks.clone() {
              let scalar_chunk = Scalar::from_bytes(&chunk.clone().try_into().unwrap());
              assert!(scalar_chunk.to_bytes().to_vec() == chunk);
              assert!(chunk[55] == 0);
            }

            let result = combine_chunked_data(chunks);
            let mut padded_data = data.to_vec();
            while result.len() > padded_data.len() {
              padded_data.push(0);
            }
            assert!(padded_data == result);
        }
    }

    #[test]
    fn test_full_verenc() {
        let mut data: [u8; 110] = [0u8;110];
        OsRng::fill_bytes(&mut OsRng, &mut data);
        let chunks = chunk_data_for_verenc(data.to_vec());
        for chunk in chunks.clone() {
          let proof = new_verenc_proof(chunk.clone());
          let blind = Scalar::from_bytes(proof.blinding_key.as_slice().try_into().unwrap());
          let st = EdwardsPoint::GENERATOR * blind * Scalar::from_bytes(chunk.as_slice().try_into().unwrap());
          assert!(st.compress().to_bytes().to_vec() == proof.statement);
          let proofdata = proof.clone();
          let pubproof = VerencProof { blinding_pubkey: proof.blinding_pubkey, encryption_key: proof.encryption_key, statement: proof.statement, challenge: proof.challenge, polycom: proof.polycom, ctexts: proof.ctexts, shares_rands: proof.shares_rands };
          assert!(verenc_verify(pubproof.clone()));
          let compressed = verenc_compress(pubproof);
          let result = verenc_recover(VerencDecrypt{
              blinding_pubkey: proofdata.blinding_pubkey,
              decryption_key: proof.decryption_key,
              statement: proofdata.statement,
              ciphertexts: compressed,
          });

          assert!(chunk == result);
        }
        let result = combine_chunked_data(chunks);
        let mut padded_data = data.to_vec();
        while result.len() > padded_data.len() {
          padded_data.push(0);
        }
        assert!(padded_data == result);
    }
}
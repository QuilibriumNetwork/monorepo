use std::convert::TryInto;

use crate::generators::{BulletproofGens, PedersenGens};
use crate::range_proof::RangeProof;
use crate::curve_adapter::{CompressedPoint, Point, Scalar, BASEPOINT_POINT};

use ed448_goldilocks_plus::{CompressedDecaf, DecafPoint};
use merlin::Transcript;
use rand::thread_rng;
use sha3::Digest;

// Struct definitions for UniFFI return types
#[derive(Debug)]
pub struct RangeProofResult {
    pub proof: Vec<u8>,
    pub commitment: Vec<u8>,
    pub blinding: Vec<u8>,
}

// Implementation of the UDL interface for bulletproofs library

pub fn generate_input_commitments(
    values: Vec<Vec<u8>>,
    blinding: Vec<u8>,
) -> Vec<u8> {
    if values.iter().any(|v| v.len() != 56)  || blinding.len() % 56 != 0 {
        println!("invalid scalar size");
        return vec![];
    }
    let values_scalars: Vec<Scalar> = values.iter().map(|v| Scalar::from_bits(v.as_slice().try_into().unwrap())).collect();
    let blinding_scalars: Vec<_> = (0..(blinding.len()/56)).map(|i| Scalar::from_canonical_bytes(blinding[i*56..(i+1)*56].try_into().unwrap())).collect();
    let mut total = Scalar::zero();
    for s in blinding_scalars {
      if s.is_none() {
        return vec![];
      }
        total = total + s.unwrap();
    }
    let mut new_blinds = Vec::new();
    let pc_gens = PedersenGens::default();
    for _ in 0..values.len()-1 {
        let blind = Scalar::random(&mut thread_rng());
        new_blinds.push(blind);
        total = total - blind;
    }
    new_blinds.push(total);
    let commits: Vec<Point> = values_scalars.iter().zip(new_blinds).map(|(v,b)| pc_gens.commit(*v, b)).collect();
    return commits.iter().flat_map(|c| c.compress().as_bytes().to_vec()).collect();
}

/// Generate a range proof for a value
pub fn generate_range_proof(
    values: Vec<Vec<u8>>,
    blinding: Vec<u8>,
    bit_size: u64,
) -> RangeProofResult {
    if values.iter().any(|v| v.len() != 56) || blinding.len() % 56 != 0 {
        println!("invalid scalar size");
        return RangeProofResult{
          proof: vec![],
          commitment: vec![],
          blinding: vec![],
        };
    }

    let existing_blinds: Vec<_> = (0..(blinding.len()/56)).map(|i| Scalar::from_canonical_bytes(blinding[i*56..(i+1)*56].try_into().unwrap())).collect();
    let mut total = Scalar::zero();
    for s in existing_blinds {
      if s.is_none() {
        return RangeProofResult{
          proof: vec![],
          commitment: vec![],
          blinding: vec![],
        };
      }
      total = total + s.unwrap();
    }
    let mut blinding_scalars: Vec<Scalar> = Vec::new();
    for _ in 0..values.len()-1 {
      let blind = Scalar::random(&mut thread_rng());
      blinding_scalars.push(blind);
      total = total - blind;
    }
    blinding_scalars.push(total);
    let blinding_bytes = blinding_scalars.iter().flat_map(|s| s.to_bytes().to_vec()).collect();
    let values_scalars: Vec<Scalar> = values.iter().map(|v| Scalar::from_bits(v.as_slice().try_into().unwrap())).collect();
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(bit_size as usize, values.len());
    
    let mut prover_transcript = Transcript::new(b"range_proof");
    let result = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &values_scalars,
        &blinding_scalars,
        bit_size as usize,
    );

    if result.is_err() {
      println!("{}", result.unwrap_err());
      return RangeProofResult{
        proof: vec![],
        commitment: vec![],
        blinding: vec![],
      };
    }

    let (proof, commitments) = result.unwrap();
    
    let proof_bytes = proof.to_bytes();
    let commitment_bytes = commitments.iter().flat_map(|s| s.to_bytes().to_vec()).collect();
    
    // Pack everything in the result
    RangeProofResult {
        proof: proof_bytes,
        commitment: commitment_bytes,
        blinding: blinding_bytes,
    }
}

/// Verify a range proof against a commitment
pub fn verify_range_proof(
    proof: Vec<u8>,
    commitment: Vec<u8>,
    bit_size: u64,
) -> bool {
    if commitment.len() % 56 != 0 {
        return false;
    }
    
    let compressed: Vec<CompressedPoint> = commitment.chunks(56).map(|c| CompressedPoint::from_slice(&c)).collect();

    let proof = RangeProof::from_bytes(&proof);
    if proof.is_err() {
      return false;
    }
    
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(bit_size as usize, compressed.len());
    
    let mut verifier_transcript = Transcript::new(b"range_proof");
    
    let result = proof.unwrap().verify_multiple(&bp_gens, &pc_gens, &mut verifier_transcript, &compressed, bit_size as usize);
    
    return result.is_ok();
}

pub fn sum_check(
    input_commitments: Vec<Vec<u8>>,
    additional_input_values: Vec<Vec<u8>>,
    output_commitments: Vec<Vec<u8>>,
    additional_output_values: Vec<Vec<u8>>,
) -> bool {
    let mut left= Point::identity();
    for i in input_commitments {
        if i.len() != 56 {
            println!("invalid input size");
            return false
        }

        let p = CompressedPoint::from_slice(i.as_slice()).decompress();
        if p.is_none() {
            println!("invalid input point");
            return false
        }

        left += p.unwrap();
    }

    let mut additional_input= Point::identity();
    for i in additional_input_values {
        if i.len() != 56 {
            println!("invalid additional size");
            return false
        }
        
        additional_input += Scalar::from_bits(i.as_slice().try_into().unwrap()) * Point(DecafPoint::GENERATOR);
    }

    let mut right= Point::identity();
    for i in output_commitments {
        if i.len() != 56 {
            println!("invalid output size");
            return false
        }
        
        let p = CompressedPoint::from_slice(i.as_slice()).decompress();
        if p.is_none() {
            println!("invalid output point");
            return false
        }

        right += p.unwrap();
    }

    let mut additional_output= Point::identity();
    for i in additional_output_values {
        if i.len() != 56 {
            println!("invalid additional size");
            return false
        }
        
        additional_output += Scalar::from_bits(i.as_slice().try_into().unwrap()) * Point(DecafPoint::GENERATOR);
    }

    let total_right = right + additional_output;
    let diff = (left + additional_input) - total_right;

    diff.is_identity().into()
}

pub fn keygen() -> Vec<u8> {
  let scalar = Scalar::random(&mut thread_rng());
  let point = scalar * Point(DecafPoint::GENERATOR);
  [scalar.as_bytes().to_vec(), point.compress().as_bytes().to_vec()].concat()
}

pub fn scalar_mult(
  lhs: Vec<u8>,
  rhs: Vec<u8>,
) -> Vec<u8> {
  if lhs.len() != 56 || rhs.len() != 56 {
    return Vec::new();
  }

  let mult = Scalar::from_bits(lhs.as_slice().try_into().unwrap()) * Scalar::from_bits(rhs.as_slice().try_into().unwrap());
  [mult.as_bytes().to_vec(), (mult * Point(DecafPoint::GENERATOR)).compress().as_bytes().to_vec()].concat()
}

pub fn scalar_mult_point(
  input_scalar: Vec<u8>,
  public_point: Vec<u8>,
) -> Vec<u8> {
  if input_scalar.len() != 56 || public_point.len() != 56 {
    return Vec::new();
  }

  let point = CompressedPoint::from_slice(&public_point).decompress();
  if point.is_none() {
    return Vec::new();
  }

  let mult = Scalar::from_bits(input_scalar.as_slice().try_into().unwrap()) * point.unwrap();
  mult.compress().as_bytes().to_vec()
}

pub fn scalar_inverse(input_scalar: Vec<u8>) -> Vec<u8> {
  if input_scalar.len() != 56 {
    return Vec::new();
  }

  let inv = Scalar::from_bits(input_scalar.as_slice().try_into().unwrap()).invert();

  [inv.as_bytes().to_vec(), (inv * Point(DecafPoint::GENERATOR)).compress().as_bytes().to_vec()].concat()
}

pub fn scalar_mult_hash_to_scalar(
  input_scalar: Vec<u8>,
  public_point: Vec<u8>,
) -> Vec<u8> {
  if input_scalar.len() != 56 || public_point.len() != 56 {
    return Vec::new();
  }

  let point = CompressedPoint::from_slice(&public_point).decompress();
  if point.is_none() {
    return Vec::new();
  }

  let mult = Scalar::from_bits(input_scalar.as_slice().try_into().unwrap()) * point.unwrap();
  let d = Scalar::hash_from_bytes::<sha3::Shake256>(mult.compress().as_bytes());
  [d.as_bytes().to_vec(), (d * Point(DecafPoint::GENERATOR)).compress().as_bytes().to_vec()].concat()
}

pub fn hash_to_scalar(
  input: Vec<u8>,
) -> Vec<u8> {
  let d = Scalar::hash_from_bytes::<sha3::Shake256>(&input);
  [d.as_bytes().to_vec(), (d * Point(DecafPoint::GENERATOR)).compress().as_bytes().to_vec()].concat()
}

pub fn scalar_addition(lhs: Vec<u8>, rhs: Vec<u8>) -> Vec<u8> {
  if lhs.len() != 56 || rhs.len() != 56 {
    return Vec::new();
  }

  (Scalar::from_bits(lhs.as_slice().try_into().unwrap()) + Scalar::from_bits(rhs.as_slice().try_into().unwrap())).as_bytes().to_vec()
}

pub fn scalar_subtraction(lhs: Vec<u8>, rhs: Vec<u8>) -> Vec<u8> {
  if lhs.len() != 56 || rhs.len() != 56 {
    return Vec::new();
  }

  (Scalar::from_bits(lhs.as_slice().try_into().unwrap()) - Scalar::from_bits(rhs.as_slice().try_into().unwrap())).as_bytes().to_vec()
}

pub fn scalar_to_point(scalar: Vec<u8>) -> Vec<u8> {
  if scalar.len() != 56 {
    return Vec::new();
  }

  (Scalar::from_bits(scalar.as_slice().try_into().unwrap()) * Point(DecafPoint::GENERATOR)).compress().as_bytes().to_vec()
}

pub fn alt_generator() -> Vec<u8> {
  PedersenGens::default().B_blinding.compress().as_bytes().to_vec()
}

pub fn point_addition(input_point: Vec<u8>, public_point: Vec<u8>) -> Vec<u8> {
  if input_point.len() != 56 || public_point.len() != 56 {
    return Vec::new();
  }

  let inpoint = CompressedPoint::from_slice(&input_point).decompress();
  if inpoint.is_none() {
    return Vec::new();
  }

  let pubpoint = CompressedPoint::from_slice(&public_point).decompress();
  if pubpoint.is_none() {
    return Vec::new();
  }

  (inpoint.unwrap() + pubpoint.unwrap()).compress().as_bytes().to_vec()
}

pub fn point_subtraction(input_point: Vec<u8>, public_point: Vec<u8>) -> Vec<u8> {
  if input_point.len() != 56 || public_point.len() != 56 {
    return Vec::new();
  }

  let inpoint = CompressedPoint::from_slice(&input_point).decompress();
  if inpoint.is_none() {
    return Vec::new();
  }

  let pubpoint = CompressedPoint::from_slice(&public_point).decompress();
  if pubpoint.is_none() {
    return Vec::new();
  }

  (inpoint.unwrap() - pubpoint.unwrap()).compress().as_bytes().to_vec()
}

fn internal_sign_hidden(
  x: Scalar,
  t: Scalar,
  a: Scalar,
  r: Scalar,
) -> (Scalar, Scalar, Scalar, Scalar, Point, Point) {
  let gens = PedersenGens::default();
  let p = x * gens.B;
  let c_point = a * gens.B + r * gens.B_blinding;

  let mut rng = thread_rng();
  let k1 = Scalar::random(&mut rng);
  let k2 = Scalar::random(&mut rng);
  let k3 = Scalar::random(&mut rng);

  let r1 = k1 * gens.B;
  let r2 = k2 * gens.B + k3 * gens.B_blinding;

  // Fiat–Shamir challenge
  let data = [
    p.compress().as_bytes(),
    t.as_bytes(),
    c_point.compress().as_bytes(),
    r1.compress().as_bytes(),
    r2.compress().as_bytes(),
  ].concat();
  let c = Scalar::hash_from_bytes::<sha3::Shake256>(&data);

  let s1 = k1 - c * x;
  let s2 = k2 - c * a;
  let s3 = k3 - c * r;

  (c, s1, s2, s3, p, c_point)
}

fn internal_verify_hidden(
  challenge: Scalar,
  t: Scalar,
  s1: Scalar,
  s2: Scalar,
  s3: Scalar,
  p_point: CompressedPoint,
  c_point: CompressedPoint,
) -> bool {
  let gens = PedersenGens::default();
  let p_decomp = p_point.decompress();
  let c_decomp = c_point.decompress();
  if p_decomp.is_none() || c_decomp.is_none() {
    return false;
  }
  
  let r1 = s1 * gens.B + (challenge * p_decomp.unwrap());
  let r2 = s2 * gens.B + (s3 * gens.B_blinding) + (challenge * c_decomp.unwrap());

  let data = [
    p_point.as_bytes(),
    t.as_bytes(),
    c_point.as_bytes(),
    r1.compress().as_bytes(),
    r2.compress().as_bytes(),
  ].concat();
  let c_check = Scalar::hash_from_bytes::<sha3::Shake256>(&data);

  challenge == c_check
}

pub fn sign_simple(
  secret: Vec<u8>,
  message: Vec<u8>
) -> Vec<u8> {
  if secret.len() != 56 || message.len() == 0 {
    return Vec::new();
  }

  let secret_scalar = Scalar::from_bits(secret.as_slice().try_into().unwrap());
  
  let mut rng = thread_rng();
  let k = Scalar::random(&mut rng);

  let gens = PedersenGens::default();

  let p = secret_scalar * gens.B;
  let r = k * gens.B;

  let data = [
    message.as_slice(),
    p.compress().as_bytes(),
    r.compress().as_bytes(),
  ].concat();
  let c = Scalar::hash_from_bytes::<sha3::Shake256>(&data);
  let s = k - c * secret_scalar;
  
  [r.compress().as_bytes().to_vec(), s.as_bytes().to_vec()].concat()
}

pub fn verify_simple(
  message: Vec<u8>,
  signature: Vec<u8>,
  point: Vec<u8>,
) -> bool {
  if message.len() == 0 || signature.len() != 112 || point.len() != 56 {
    return false;
  }

  let r = CompressedPoint::from_slice(&signature[..56]);
  let sig = Scalar::from_bits(signature[56..].try_into().unwrap());
  let pt = CompressedPoint::from_slice(point.as_slice());
  let pt_decomp = pt.decompress();
  let r_decomp = r.decompress();
 
  if pt_decomp.is_none() || r_decomp.is_none() {
    return false;
  }

  let data = [
    message.as_slice(),
    pt.as_bytes(),
    r.as_bytes(),
  ].concat(); 

  let gens = PedersenGens::default();
  let c = Scalar::hash_from_bytes::<sha3::Shake256>(&data);
  
  let check = sig * gens.B + c * pt_decomp.unwrap();

  check == r_decomp.unwrap()
}

pub fn sign_hidden(
  x: Vec<u8>,
  t: Vec<u8>,
  a: Vec<u8>,
  r: Vec<u8>,
) -> Vec<u8> {
  if x.len() != 56 || a.len() != 56 || r.len() != 56 {
    return Vec::new();
  }

  let (c, s1, s2, s3, p, c_point) = internal_sign_hidden(
    Scalar::from_bits(x.as_slice().try_into().unwrap()),
    Scalar::from_bits(t.as_slice().try_into().unwrap()),
    Scalar::from_bits(a.as_slice().try_into().unwrap()),
    Scalar::from_bits(r.as_slice().try_into().unwrap()),
  );

  [
    c.as_bytes().to_vec(),
    s1.as_bytes().to_vec(),
    s2.as_bytes().to_vec(),
    s3.as_bytes().to_vec(),
    p.compress().as_bytes().to_vec(),
    c_point.compress().as_bytes().to_vec(),
  ].concat()
}

pub fn verify_hidden(
  c: Vec<u8>,
  t: Vec<u8>,
  s1: Vec<u8>,
  s2: Vec<u8>,
  s3: Vec<u8>,
  p_point: Vec<u8>,
  c_point: Vec<u8>,
) -> bool {
  if c.len() != 56 ||
    t.len() != 56 ||
    s1.len() != 56 ||
    s2.len() != 56 ||
    s3.len() != 56 ||
    p_point.len() != 56 ||
    c_point.len() != 56 {
    return false;
  }

  internal_verify_hidden(
    Scalar::from_bits(c.as_slice().try_into().unwrap()),
    Scalar::from_bits(t.as_slice().try_into().unwrap()),
    Scalar::from_bits(s1.as_slice().try_into().unwrap()),
    Scalar::from_bits(s2.as_slice().try_into().unwrap()),
    Scalar::from_bits(s3.as_slice().try_into().unwrap()),
    CompressedPoint::from_slice(p_point.as_slice()),
    CompressedPoint::from_slice(c_point.as_slice()),
  )
}

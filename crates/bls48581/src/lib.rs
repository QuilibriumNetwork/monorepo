/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#![allow(clippy::many_single_char_names)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::new_without_default)]
pub mod bls48581;
pub mod bls;
pub mod rand;
pub mod arch;
pub mod hmac;
pub mod hash256;
pub mod hash384;
pub mod hash512;
pub mod sha3;

use std::error::Error;
use std::fs;
use bls48581::big;
use bls48581::ecp;
use bls48581::ecp::ECP;
use bls48581::ecp8;
use bls48581::mpin256::SHA512;
use bls48581::rom;
use bls48581::pair8;
use ::rand::rngs;
use ::rand::RngCore;

uniffi::include_scaffolding!("lib");

fn recurse_fft(
    values: &[big::BIG],
    offset: u64,
    stride: u64,
    roots_stride: u64,
    out: &mut [big::BIG],
    fft_width: u64,
    inverse: bool,
) {
  let M = &big::BIG::new_ints(&rom::CURVE_ORDER);
  let roots = if inverse {
    &bls::singleton().ReverseRootsOfUnityBLS48581[&fft_width]
  } else {
    &bls::singleton().RootsOfUnityBLS48581[&fft_width]
  };

  if out.len() == 1 {
    // optimization: we're working in bls48-581, the first roots of unity
    // value is always 1 no matter the fft width, so we can skip the
    // multiplication:
    out[0] = values[offset as usize].clone();
    return;
  }

  let half = (out.len() as u64) >> 1;

  // slide to the left
  recurse_fft(
    values,
    offset,
    stride << 1,
    roots_stride << 1,
    &mut out[..half as usize],
    fft_width,
    inverse,
  );

  // slide to the right
  recurse_fft(
    values,
    offset + stride,
    stride << 1,
    roots_stride << 1,
    &mut out[half as usize..],
    fft_width,
    inverse,
  );

  // cha cha now, y'all
  for i in 0..half {
    let mul = big::BIG::modmul(
      &out[(i + half) as usize],
      &roots[(i * roots_stride) as usize],
      &big::BIG::new_ints(&rom::CURVE_ORDER),
    );
    let mul_add = big::BIG::modadd(
      &out[i as usize],
      &mul,
      &big::BIG::new_ints(&rom::CURVE_ORDER),
    );
    out[(i + half) as usize] = big::BIG::modadd(
      &out[i as usize],
      &big::BIG::modneg(&mul, &big::BIG::new_ints(&rom::CURVE_ORDER)),
      &big::BIG::new_ints(&rom::CURVE_ORDER),
    );
    out[i as usize] = mul_add;
  }
}

pub fn fft(
  values: &[big::BIG],
  fft_width: u64,
  inverse: bool,
) -> Result<Vec<big::BIG>, String> {
  let mut width = values.len() as u64;
  if width > fft_width {
    return Err("invalid width of values".into());
  }

  if width & (width - 1) != 0 {
    width = nearest_power_of_two(width);
  }

  // We make a copy so we can mutate it during the work.
  let mut working_values = vec![big::BIG::new(); width as usize];
  for i in 0..values.len() {
    working_values[i] = values[i].clone();
  }
  for i in values.len()..width as usize {
    working_values[i] = big::BIG::new();
  }

  let mut out = vec![big::BIG::new(); width as usize];
  let stride = fft_width / width;

  if inverse {
    let mut inv_len = big::BIG::new_int(width as isize);
    inv_len.invmodp(&big::BIG::new_ints(&rom::CURVE_ORDER));

    recurse_fft(&working_values, 0, 1, stride, &mut out, fft_width, inverse);
    for i in 0..out.len() {
      out[i] = big::BIG::modmul(&out[i], &inv_len, &big::BIG::new_ints(&rom::CURVE_ORDER));
    }

    Ok(out)
  } else {
    recurse_fft(&working_values, 0, 1, stride, &mut out, fft_width, inverse);
    Ok(out)
  }
}

/// Optimized iterative in-place FFT with cached modulus.
///
/// Same interface as [`fft`] but ~15-25% faster:
/// - Caches `CURVE_ORDER` modulus once (vs 4× per butterfly in `recurse_fft`)
/// - Iterative bit-reversal + butterfly stages (no recursion overhead)
/// - Single buffer (no separate `working_values` + `out`)
///
/// The existing `fft` is preserved unchanged for side-by-side benchmarking.
pub fn fft_fast(
  values: &[big::BIG],
  fft_width: u64,
  inverse: bool,
) -> Result<Vec<big::BIG>, String> {
  let mut width = values.len() as u64;
  if width > fft_width {
    return Err("invalid width of values".into());
  }

  if width & (width - 1) != 0 {
    width = nearest_power_of_two(width);
  }

  let n = width as usize;
  let log_n = {
    let mut l = 0usize;
    let mut tmp = n;
    while tmp > 1 {
      tmp >>= 1;
      l += 1;
    }
    l
  };

  // Cache the modulus once — this is the key optimization.
  let modulus = big::BIG::new_ints(&rom::CURVE_ORDER);

  // Select roots of unity
  let roots = if inverse {
    &bls::singleton().ReverseRootsOfUnityBLS48581[&fft_width]
  } else {
    &bls::singleton().RootsOfUnityBLS48581[&fft_width]
  };
  let stride = (fft_width / width) as usize;

  // Single buffer: copy values then zero-pad
  let mut data = vec![big::BIG::new(); n];
  for i in 0..values.len() {
    data[i] = values[i].clone();
  }

  // Bit-reversal permutation
  for i in 0..n {
    let j = bit_reverse(i, log_n);
    if i < j {
      let tmp = data[i].clone();
      data[i] = data[j].clone();
      data[j] = tmp;
    }
  }

  // Iterative butterfly stages
  let mut len = 2usize;
  while len <= n {
    let half = len / 2;
    let step = n / len;   // root-of-unity stride for this stage

    let mut start = 0;
    while start < n {
      for k in 0..half {
        let twiddle_idx = k * step * stride;
        let u = data[start + k].clone();
        let t = big::BIG::modmul(
          &data[start + k + half],
          &roots[twiddle_idx],
          &modulus,
        );
        data[start + k] = big::BIG::modadd(&u, &t, &modulus);
        data[start + k + half] = big::BIG::modadd(
          &u,
          &big::BIG::modneg(&t, &modulus),
          &modulus,
        );
      }
      start += len;
    }
    len <<= 1;
  }

  // If inverse: multiply each element by 1/n mod M
  if inverse {
    let mut inv_len = big::BIG::new_int(n as isize);
    inv_len.invmodp(&modulus);
    for i in 0..n {
      data[i] = big::BIG::modmul(&data[i], &inv_len, &modulus);
    }
  }

  Ok(data)
}

/// Reverse the bottom `log_n` bits of `x`.
fn bit_reverse(x: usize, log_n: usize) -> usize {
  let mut result = 0usize;
  let mut val = x;
  for _ in 0..log_n {
    result = (result << 1) | (val & 1);
    val >>= 1;
  }
  result
}

fn recurse_fft_g1(
  values: &[ecp::ECP],
  offset: u64,
  stride: u64,
  roots_stride: u64,
  out: &mut [ecp::ECP],
  fft_width: u64,
  inverse: bool,
) {
  let roots = if inverse {
    &bls::singleton().ReverseRootsOfUnityBLS48581[&fft_width]
  } else {
    &bls::singleton().RootsOfUnityBLS48581[&fft_width]
  };

  if out.len() == 1 {
    out[0] = values[offset as usize].clone();
    return;
  }

  let half = (out.len() as u64) >> 1;

  // slide to the left
  recurse_fft_g1(
    values,
    offset,
    stride << 1,
    roots_stride << 1,
    &mut out[..half as usize],
    fft_width,
    inverse,
  );

  // slide to the right
  recurse_fft_g1(
    values,
    offset + stride,
    stride << 1,
    roots_stride << 1,
    &mut out[half as usize..],
    fft_width,
    inverse,
  );

  // cha cha now, y'all
  for i in 0..half {
    let mul = out[(i + half) as usize].clone().mul(
      &roots[(i * roots_stride) as usize].clone(),
    );
    let mut mul_add = out[i as usize].clone();
    mul_add.add(&mul.clone());
    out[(i + half) as usize] = out[i as usize].clone();
    out[(i + half) as usize].sub(&mul);
    out[i as usize] = mul_add;
  }
}

pub fn fft_g1(
  values: &[ecp::ECP],
  fft_width: u64,
  inverse: bool,
) -> Result<Vec<ecp::ECP>, String> {
  let mut width = values.len() as u64;
  if width > fft_width {
    return Err("invalid width of values".into());
  }

  if width & (width - 1) != 0 {
    width = nearest_power_of_two(width);
  }

  let mut working_values = vec![ecp::ECP::new(); width as usize];
  for i in 0..values.len() {
    working_values[i] = values[i].clone();
  }
  for i in values.len()..width as usize {
    working_values[i] = ecp::ECP::generator();
  }

  let mut out = vec![ecp::ECP::new(); width as usize];
  let stride = fft_width / width;

  if inverse {
    let mut inv_len = big::BIG::new_int(width as isize);
    inv_len.invmodp(&big::BIG::new_ints(&rom::CURVE_ORDER));

    recurse_fft_g1(&working_values, 0, 1, stride, &mut out, fft_width, inverse);
    for i in 0..out.len() {
      out[i] = out[i].clone().mul(&inv_len);
    }

    Ok(out)
  } else {
    recurse_fft_g1(&working_values, 0, 1, stride, &mut out, fft_width, inverse);
    Ok(out)
  }
}

fn nearest_power_of_two(number: u64) -> u64 {
  let mut power = 1;
  while number > power {
    power <<= 1;
  }
  power
}

fn bytes_to_polynomial(
  bytes: &[u8],
) -> Vec<big::BIG> {
  let size = bytes.len() / 64;
  let trunc_last = bytes.len() % 64 > 0;

  let mut poly = Vec::with_capacity(size + (if trunc_last { 1 } else { 0 }));

  for i in 0..size {
    let scalar = big::BIG::frombytes(&bytes[i * 64..(i + 1) * 64]);
    poly.push(scalar);
  }

  if trunc_last {
    let scalar = big::BIG::frombytes(&bytes[size * 64..]);
    poly.push(scalar);
  }

  return poly;
}

pub fn point_linear_combination(
  points: &[ecp::ECP],
  scalars: &Vec<big::BIG>,
) -> Result<ecp::ECP, Box<dyn Error>> {
  if points.len() != scalars.len() {
    return Err(format!(
      "length mismatch between arguments, points: {}, scalars: {}",
      points.len(),
      scalars.len(),
    ).into());
  }

  let result = ecp::ECP::muln(points.len(), points, scalars.as_slice());

  Ok(result)
}

pub fn point8_linear_combination(
  points: &[ecp8::ECP8],
  scalars: &Vec<big::BIG>,
) -> Result<ecp8::ECP8, Box<dyn Error>> {
  if points.len() != scalars.len() {
    return Err(format!(
      "length mismatch between arguments, points: {}, scalars: {}",
      points.len(),
      scalars.len(),
    ).into());
  }

  let mut result = points[0].mul(&scalars[0]);
  for i in 1..points.len() {
    result.add(&points[i].mul(&scalars[i]));
  }

  Ok(result)
}

fn verify(
  commitment: &ecp::ECP,
  z: &big::BIG,
  y: &big::BIG,
  proof: &ecp::ECP,
) -> bool {
  let z2 = ecp8::ECP8::generator().mul(z);
  let y1 = ecp::ECP::generator().mul(y);
  let mut xz = bls::singleton().CeremonyBLS48581G2[1].clone();
  xz.sub(&z2);
  let mut cy = commitment.clone();
  cy.sub(&y1);
  cy.neg();

  let mut r = pair8::initmp();

  pair8::another(&mut r, &xz, &proof);
  pair8::another(&mut r, &ecp8::ECP8::generator(), &cy);
  let mut v = pair8::miller(&mut r);
  v = pair8::fexp(&v);
  return v.isunity();
}

pub fn commit_raw(
  data: &[u8],
  poly_size: u64,
) -> Vec<u8> {
  let mut poly = bytes_to_polynomial(data);
  while poly.len() < poly_size as usize {
    poly.push(big::BIG::new());
  }
  match point_linear_combination_fast(
		&bls::singleton().FFTBLS48581[&poly_size],
		&poly,
	) {
    Ok(commit) => {
      let mut b = [0u8; 74];
      commit.tobytes(&mut b, true);
      return b.to_vec();
    }
    Err(_e) => {
      return [].to_vec();
    }
  }
}

pub fn prove_raw(
  data: &[u8],
  index: u64,
  poly_size: u64,
) -> Vec<u8> {
  let mut poly = bytes_to_polynomial(data);
  while poly.len() < poly_size as usize {
    poly.push(big::BIG::new());
  }

  let z = bls::singleton().RootsOfUnityBLS48581[&poly_size][index as usize];

  match fft_fast(
    &poly,
    poly_size,
    true,
  ) {
    Ok(eval_poly) => {
      let mut subz = big::BIG::new_int(0);
      subz = big::BIG::modadd(&subz, &big::BIG::modneg(&z, &big::BIG::new_ints(&rom::CURVE_ORDER)), &big::BIG::new_ints(&rom::CURVE_ORDER));
      let mut subzinv = subz.clone();
      subzinv.invmodp(&big::BIG::new_ints(&rom::CURVE_ORDER));
      let o = big::BIG::new_int(1);
      let mut oinv = o.clone();
      oinv.invmodp(&big::BIG::new_ints(&rom::CURVE_ORDER));
      let divisors: Vec<big::BIG> = vec![
        subz,
        o
      ];
      let invdivisors: Vec<big::BIG> = vec![
        subzinv,
        oinv
      ];
    
      let mut a: Vec<big::BIG> = eval_poly.iter().map(|x| x.clone()).collect();
    
      // Adapted from Feist's amortized proofs:
      let mut a_pos = a.len() - 1;
      let b_pos = divisors.len() - 1;
      let mut diff = a_pos as isize - b_pos as isize;
      let mut out: Vec<big::BIG> = vec![big::BIG::new(); (diff + 1) as usize];
      while diff >= 0 {
        out[diff as usize] = a[a_pos].clone();
        out[diff as usize] = big::BIG::modmul(&out[diff as usize], &invdivisors[b_pos], &big::BIG::new_ints(&rom::CURVE_ORDER));
        for i in (0..=b_pos).rev() {
          let den = &out[diff as usize].clone();
          a[diff as usize + i] = a[diff as usize + i].clone();
          a[diff as usize + i] = big::BIG::modadd(
            &a[diff as usize + i],
            &big::BIG::modneg(
              &big::BIG::modmul(&den, &divisors[i], &big::BIG::new_ints(&rom::CURVE_ORDER)),
              &big::BIG::new_ints(&rom::CURVE_ORDER)
            ),
            &big::BIG::new_ints(&rom::CURVE_ORDER)
          );
        }

        a_pos -= 1;
        diff -= 1;
      }
    
      match point_linear_combination_fast(
        &bls::singleton().CeremonyBLS48581G1[..(poly_size as usize - 1)],
        &out,
      ) {
        Ok(proof) => {
          let mut b = [0u8; 74];
          proof.tobytes(&mut b, true);
          return b.to_vec();
        }
        Err(_e) => {
          return [].to_vec();
        }
      }
    },
    Err(_e) => {
      return [].to_vec();
    }
  }
}

pub fn verify_raw(
  data: &[u8],
  commit: &[u8],
  index: u64,
  proof: &[u8],
  poly_size: u64,
) -> bool {
  let z = bls::singleton().RootsOfUnityBLS48581[&poly_size][index as usize];

  let y = big::BIG::frombytes(data);

  let c = ecp::ECP::frombytes(commit);
  if c.is_infinity() || c.equals(&ecp::ECP::generator()) {
    return false;
  }

  let p = ecp::ECP::frombytes(proof);
  if p.is_infinity() || p.equals(&ecp::ECP::generator()) {
    return false;
  }

  return verify(
    &c,
    &z,
    &y,
    &p,
  );
}

// ── Full-width scalar API ───────────────────────────────────────────────────
//
// The original commit/prove functions use 64-byte-per-scalar serialization
// (BYTES_PER_SCALAR = 64), which truncates the top 9 bytes of BLS48-581
// field elements (MODBYTES = 73).  The functions below use the full MODBYTES
// width, preserving complete field elements.

/// Bytes per scalar in the full-width encoding (= MODBYTES = 73).
pub const FULL_BYTES_PER_SCALAR: usize = big::MODBYTES;

fn bytes_to_polynomial_full(
  bytes: &[u8],
) -> Vec<big::BIG> {
  let size = bytes.len() / FULL_BYTES_PER_SCALAR;
  let trunc_last = bytes.len() % FULL_BYTES_PER_SCALAR > 0;

  let mut poly = Vec::with_capacity(size + (if trunc_last { 1 } else { 0 }));

  for i in 0..size {
    let start = i * FULL_BYTES_PER_SCALAR;
    let scalar = big::BIG::frombytes(&bytes[start..start + FULL_BYTES_PER_SCALAR]);
    poly.push(scalar);
  }

  if trunc_last {
    let scalar = big::BIG::frombytes(&bytes[size * FULL_BYTES_PER_SCALAR..]);
    poly.push(scalar);
  }

  poly
}

/// Commit to a polynomial in evaluation form using full-width (MODBYTES per
/// scalar) encoding.
///
/// Like [`commit_raw`] but reads 73 bytes per scalar instead of 64,
/// preserving the full field element without truncation.
pub fn commit_raw_full(
  data: &[u8],
  poly_size: u64,
) -> Vec<u8> {
  let mut poly = bytes_to_polynomial_full(data);
  while poly.len() < poly_size as usize {
    poly.push(big::BIG::new());
  }
  match point_linear_combination_fast(
    &bls::singleton().FFTBLS48581[&poly_size],
    &poly,
  ) {
    Ok(commit) => {
      let mut b = [0u8; 74];
      commit.tobytes(&mut b, true);
      b.to_vec()
    }
    Err(_) => vec![],
  }
}

/// Create an opening proof at a domain-point index using full-width scalars.
///
/// Like [`prove_raw`] but reads 73 bytes per scalar. Uses the existing
/// [`div_by_linear`] helper and monomial-basis SRS for the quotient commitment.
pub fn prove_raw_full(
  data: &[u8],
  index: u64,
  poly_size: u64,
) -> Vec<u8> {
  let mut poly = bytes_to_polynomial_full(data);
  while poly.len() < poly_size as usize {
    poly.push(big::BIG::new());
  }

  let z = bls::singleton().RootsOfUnityBLS48581[&poly_size][index as usize];

  match fft_fast(&poly, poly_size, true) {
    Ok(coeffs) => {
      let q = div_by_linear(&coeffs, &z);
      match point_linear_combination_fast(
        &bls::singleton().CeremonyBLS48581G1[..q.len()],
        &q,
      ) {
        Ok(proof) => {
          let mut b = [0u8; 74];
          proof.tobytes(&mut b, true);
          b.to_vec()
        }
        Err(_) => vec![],
      }
    }
    Err(_) => vec![],
  }
}

/// Commit to a polynomial given directly as `BIG` scalars in evaluation form.
///
/// Uses the Lagrange-basis SRS (`FFTBLS48581`) to compute
/// `C = Σ scalars[i] · [Lᵢ(τ)]₁`.  No byte serialization — avoids the
/// 64-byte truncation inherent in [`commit_raw`].
pub fn commit_scalars(
  scalars: &[big::BIG],
  poly_size: u64,
) -> Vec<u8> {
  let mut poly = scalars.to_vec();
  while poly.len() < poly_size as usize {
    poly.push(big::BIG::new());
  }
  match point_linear_combination_fast(
    &bls::singleton().FFTBLS48581[&poly_size],
    &poly,
  ) {
    Ok(commit) => {
      let mut b = [0u8; 74];
      commit.tobytes(&mut b, true);
      b.to_vec()
    }
    Err(_) => vec![],
  }
}

/// Commit to a polynomial given as `BIG` scalars in coefficient form.
///
/// Uses the monomial-basis SRS (`CeremonyBLS48581G1`) to compute
/// `C = Σ coeffs[i] · [τⁱ]₁`.  Useful when you already have coefficient-form
/// polynomials (e.g. quotients from synthetic division) and want to skip the
/// FFT that would be needed to convert to evaluation form first.
pub fn commit_scalars_monomial(
  coeffs: &[big::BIG],
) -> Vec<u8> {
  match point_linear_combination_fast(
    &bls::singleton().CeremonyBLS48581G1[..coeffs.len()],
    &coeffs.to_vec(),
  ) {
    Ok(commit) => {
      let mut b = [0u8; 74];
      commit.tobytes(&mut b, true);
      b.to_vec()
    }
    Err(_) => vec![],
  }
}

/// Like [`point_linear_combination`] but uses `ECP::muln_fast` (signed-digit
/// adaptive-window Pippenger with mixed addition).
pub fn point_linear_combination_fast(
  points: &[ecp::ECP],
  scalars: &Vec<big::BIG>,
) -> Result<ecp::ECP, Box<dyn Error>> {
  if points.len() != scalars.len() {
    return Err(format!(
      "length mismatch between arguments, points: {}, scalars: {}",
      points.len(),
      scalars.len(),
    ).into());
  }

  let result = ecp::ECP::muln_fast(points.len(), points, scalars.as_slice());

  Ok(result)
}

/// Like [`commit_scalars_monomial`] but uses the optimized `muln_fast`.
pub fn commit_scalars_monomial_fast(
  coeffs: &[big::BIG],
) -> Vec<u8> {
  match point_linear_combination_fast(
    &bls::singleton().CeremonyBLS48581G1[..coeffs.len()],
    &coeffs.to_vec(),
  ) {
    Ok(commit) => {
      let mut b = [0u8; 74];
      commit.tobytes(&mut b, true);
      b.to_vec()
    }
    Err(_) => vec![],
  }
}

/// Like [`commit_scalars`] but uses the optimized `muln_fast`.
pub fn commit_scalars_fast(
  scalars: &[big::BIG],
  poly_size: u64,
) -> Vec<u8> {
  let mut poly = scalars.to_vec();
  while poly.len() < poly_size as usize {
    poly.push(big::BIG::new());
  }
  match point_linear_combination_fast(
    &bls::singleton().FFTBLS48581[&poly_size],
    &poly,
  ) {
    Ok(commit) => {
      let mut b = [0u8; 74];
      commit.tobytes(&mut b, true);
      b.to_vec()
    }
    Err(_) => vec![],
  }
}

// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Multiproof {
    pub d: Vec<u8>,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct BlsKeygenOutput {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub proof_of_possession_sig: Vec<u8>,
}

#[derive(Debug)]
pub struct BlsAggregateOutput {
    pub aggregate_public_key: Vec<u8>,
    pub aggregate_signature: Vec<u8>,
}

pub fn bls_keygen() -> BlsKeygenOutput {
  init();
  let mut ikm = [0u8;64];
  ::rand::thread_rng().fill_bytes(&mut ikm);
  let mut s = [0u8;73];
  let mut pk = [0u8;585];
  let is_ok = bls48581::bls256::key_pair_generate(&ikm, &mut s, &mut pk);
  if is_ok != bls48581::bls256::BLS_OK {
    return BlsKeygenOutput{
      proof_of_possession_sig: vec![],
      public_key: vec![],
      secret_key: vec![],
    };
  }

  let mut msg = b"BLS48_POP_SK".to_vec();
  msg.extend_from_slice(&pk);

  let mut sig = [0u8; 74];
  let is_sig_ok = bls48581::bls256::core_sign(&mut sig, &msg, &s);
  if is_sig_ok != bls48581::bls256::BLS_OK {
    return BlsKeygenOutput{
      proof_of_possession_sig: vec![],
      public_key: vec![],
      secret_key: vec![],
    };
  }

  BlsKeygenOutput{
    secret_key: s.to_vec(),
    public_key: pk.to_vec(),
    proof_of_possession_sig: sig.to_vec(),
  }
}

pub fn bls_sign(sk: &[u8], msg: &[u8], domain: &[u8]) -> Vec<u8> {
  let mut fullmsg = domain.to_vec();
  fullmsg.extend_from_slice(&msg);

  let mut sig = [0u8; 74];
  let is_sig_ok = bls48581::bls256::core_sign(&mut sig, &fullmsg, &sk);
  if is_sig_ok != bls48581::bls256::BLS_OK {
    return vec![];
  }

  return sig.to_vec();
}

pub fn bls_verify(pk: &[u8], sig: &[u8], msg: &[u8], domain: &[u8]) -> bool {
  let mut fullmsg = domain.to_vec();
  fullmsg.extend_from_slice(&msg);

  let is_sig_ok = bls48581::bls256::core_verify(&sig, &fullmsg, &pk);
  is_sig_ok == bls48581::bls256::BLS_OK
}

pub fn bls_verify_msig_mmsg(pks: &Vec<Vec<u8>>, sig: &[u8], msgs: &Vec<Vec<u8>>, domain: &[u8]) -> bool {
  let mut fullmsgs = Vec::<Vec::<u8>>::new();
  for msg in msgs {
    let mut fullmsg = domain.to_vec();
    fullmsg.extend_from_slice(&msg);
    fullmsgs.push(fullmsg);
  }

  let is_sig_ok = bls48581::bls256::core_msig_verify(&sig, &fullmsgs, &pks);
  is_sig_ok == bls48581::bls256::BLS_OK
}

pub fn bls_aggregate(pks: &Vec<Vec<u8>>, sigs: &Vec<Vec<u8>>) -> BlsAggregateOutput {
  if pks.len() != sigs.len() {
    return BlsAggregateOutput{
      aggregate_public_key: vec![],
      aggregate_signature: vec![],
    };
  }

  let sig_all = sigs.iter().fold(ecp::ECP::new(), |acc, sig| {
    let mut a = ecp::ECP::frombytes(&sig);
    a.add(&acc);
    a
  });
  let pk_all = pks.iter().fold(ecp8::ECP8::new(), |acc, pk| {
    let mut a = ecp8::ECP8::frombytes(&pk);
    a.add(&acc);
    a
  });
  let mut sigbytes = [0u8;74];
  sig_all.tobytes(&mut sigbytes, true);
  let mut pkbytes = [0u8;585];
  pk_all.tobytes(&mut pkbytes, true);

  BlsAggregateOutput{
    aggregate_public_key: pkbytes.to_vec(),
    aggregate_signature: sigbytes.to_vec(),
  }
}

pub fn init() {
  bls::singleton();
}

// ============================================================
// Scalar / G1 helpers used by threshold BLS protocols.
//
// These expose the modular arithmetic + scalar-to-G1 mapping over the
// BLS48-581 scalar field that the existing high-level BLS API doesn't
// surface. Used by `bls48581-wasm` so the qkms-sdk JavaScript sidecar can
// drive t-of-n DKG and signing without re-implementing curve math in JS.
//
// All scalars are 73 big-endian bytes (== `MODBYTES`). G1 points are
// 74-byte compressed (matches the existing `bls_sign` output and `ecp::ECP`
// `tobytes(.., true)` convention).
// ============================================================

const SCALAR_BYTES: usize = big::MODBYTES; // 73
const G1_COMPRESSED_BYTES: usize = 74;
// BLS48-581 uses ECP8 for the public-key group (== "G2" / "G8" in different
// naming conventions). Compressed serialized size matches the buffer
// `bls_keygen` allocates for the public key.
const G8_COMPRESSED_BYTES: usize = 585;

fn parse_scalar(bytes: &[u8]) -> Option<big::BIG> {
  if bytes.len() != SCALAR_BYTES {
    return None;
  }
  let mut s = big::BIG::frombytes(bytes);
  // Defensive: callers may hand us bytes that aren't reduced; the modular
  // ops below all do their own reduction, but normalising here gives us a
  // canonical 73-byte serialisation on the way out.
  s.rmod(&big::BIG::new_ints(&rom::CURVE_ORDER));
  Some(s)
}

fn scalar_to_bytes(s: &big::BIG) -> Vec<u8> {
  let mut s_copy = s.clone();
  s_copy.rmod(&big::BIG::new_ints(&rom::CURVE_ORDER));
  let mut out = vec![0u8; SCALAR_BYTES];
  s_copy.tobytes(&mut out);
  out
}

/// Generate a uniformly random scalar in [0, q), serialized as 73 BE bytes.
pub fn bls_scalar_random() -> Vec<u8> {
  init();
  let mut raw_seed = [0u8; 128];
  ::rand::thread_rng().fill_bytes(&mut raw_seed);
  let mut rng = rand::RAND::new();
  rng.clean();
  rng.seed(raw_seed.len(), &raw_seed);
  let q = big::BIG::new_ints(&rom::CURVE_ORDER);
  let s = big::BIG::randomnum(&q, &mut rng);
  scalar_to_bytes(&s)
}

/// Modular multiplication on the BLS48-581 scalar field: returns `(a * b) mod q`.
pub fn bls_scalar_mul(a: &[u8], b: &[u8]) -> Vec<u8> {
  let aa = match parse_scalar(a) { Some(v) => v, None => return Vec::new() };
  let bb = match parse_scalar(b) { Some(v) => v, None => return Vec::new() };
  let q = big::BIG::new_ints(&rom::CURVE_ORDER);
  let r = big::BIG::modmul(&aa, &bb, &q);
  scalar_to_bytes(&r)
}

/// Modular addition on the BLS48-581 scalar field: returns `(a + b) mod q`.
pub fn bls_scalar_add(a: &[u8], b: &[u8]) -> Vec<u8> {
  let aa = match parse_scalar(a) { Some(v) => v, None => return Vec::new() };
  let bb = match parse_scalar(b) { Some(v) => v, None => return Vec::new() };
  let q = big::BIG::new_ints(&rom::CURVE_ORDER);
  let r = big::BIG::modadd(&aa, &bb, &q);
  scalar_to_bytes(&r)
}

/// Modular subtraction on the BLS48-581 scalar field: returns `(a - b) mod q`.
pub fn bls_scalar_sub(a: &[u8], b: &[u8]) -> Vec<u8> {
  let aa = match parse_scalar(a) { Some(v) => v, None => return Vec::new() };
  let bb = match parse_scalar(b) { Some(v) => v, None => return Vec::new() };
  let q = big::BIG::new_ints(&rom::CURVE_ORDER);
  let neg_b = big::BIG::modneg(&bb, &q);
  let r = big::BIG::modadd(&aa, &neg_b, &q);
  scalar_to_bytes(&r)
}

/// Modular negation: `-a mod q`.
pub fn bls_scalar_neg(a: &[u8]) -> Vec<u8> {
  let aa = match parse_scalar(a) { Some(v) => v, None => return Vec::new() };
  let q = big::BIG::new_ints(&rom::CURVE_ORDER);
  let r = big::BIG::modneg(&aa, &q);
  scalar_to_bytes(&r)
}

/// Modular inverse: `a^{-1} mod q`. Returns empty vec on non-invertible input
/// (a == 0).
pub fn bls_scalar_inv(a: &[u8]) -> Vec<u8> {
  let mut aa = match parse_scalar(a) { Some(v) => v, None => return Vec::new() };
  if aa.iszilch() {
    return Vec::new();
  }
  let q = big::BIG::new_ints(&rom::CURVE_ORDER);
  aa.invmodp(&q);
  scalar_to_bytes(&aa)
}

/// Convert a uint64 to a 73-byte BE scalar — used by clients to lift small
/// integers (party ids) into the scalar field for Lagrange-coefficient
/// arithmetic without having to hard-code MODBYTES on the JS side.
pub fn bls_scalar_from_u64(v: u64) -> Vec<u8> {
  // BIG::new_int takes isize. Constrain to a sane range; party ids are well
  // below 2^31 in practice.
  let s = if v <= isize::MAX as u64 {
    big::BIG::new_int(v as isize)
  } else {
    // Build the BIG by hand from a 73-byte BE buffer.
    let mut buf = vec![0u8; SCALAR_BYTES];
    buf[SCALAR_BYTES - 8] = (v >> 56) as u8;
    buf[SCALAR_BYTES - 7] = (v >> 48) as u8;
    buf[SCALAR_BYTES - 6] = (v >> 40) as u8;
    buf[SCALAR_BYTES - 5] = (v >> 32) as u8;
    buf[SCALAR_BYTES - 4] = (v >> 24) as u8;
    buf[SCALAR_BYTES - 3] = (v >> 16) as u8;
    buf[SCALAR_BYTES - 2] = (v >> 8) as u8;
    buf[SCALAR_BYTES - 1] = v as u8;
    big::BIG::frombytes(&buf)
  };
  scalar_to_bytes(&s)
}

/// Compute the G1 point `g^scalar` (i.e. `scalar * G1.generator()`),
/// returned as 74-byte compressed bytes. Used for Feldman commitments
/// in BLS-N DKG.
pub fn bls_scalar_to_g1(scalar: &[u8]) -> Vec<u8> {
  let s = match parse_scalar(scalar) { Some(v) => v, None => return Vec::new() };
  let g = ECP::generator();
  let p = g.mul(&s);
  let mut out = vec![0u8; G1_COMPRESSED_BYTES];
  p.tobytes(&mut out, true);
  out
}

/// Add two G1 points (compressed input/output, 74 bytes each). Used by
/// BLS-N to aggregate G1 partial signatures.
pub fn bls_g1_add(a: &[u8], b: &[u8]) -> Vec<u8> {
  if a.len() != G1_COMPRESSED_BYTES || b.len() != G1_COMPRESSED_BYTES {
    return Vec::new();
  }
  let mut pa = ECP::frombytes(a);
  let pb = ECP::frombytes(b);
  pa.add(&pb);
  let mut out = vec![0u8; G1_COMPRESSED_BYTES];
  pa.tobytes(&mut out, true);
  out
}

/// Compute the G8 / ECP8 point `g^scalar` (the BLS48-581 public-key group).
/// Returns 585-byte compressed bytes — same wire format the existing
/// `bls_keygen` produces for `public_key` and `bls_verify` accepts.
/// Used for BLS-N DKG Feldman commitments and master verification key.
pub fn bls_scalar_to_g8(scalar: &[u8]) -> Vec<u8> {
  let s = match parse_scalar(scalar) { Some(v) => v, None => return Vec::new() };
  let g = ecp8::ECP8::generator();
  let p = g.mul(&s);
  let mut out = vec![0u8; G8_COMPRESSED_BYTES];
  p.tobytes(&mut out, true);
  out
}

/// Add two G8 / ECP8 points (compressed input/output, 585 bytes each).
/// Used by BLS-N DKG to sum commitment[0] across all parties into the
/// master public key.
pub fn bls_g8_add(a: &[u8], b: &[u8]) -> Vec<u8> {
  if a.len() != G8_COMPRESSED_BYTES || b.len() != G8_COMPRESSED_BYTES {
    return Vec::new();
  }
  let mut pa = ecp8::ECP8::frombytes(a);
  let pb = ecp8::ECP8::frombytes(b);
  pa.add(&pb);
  let mut out = vec![0u8; G8_COMPRESSED_BYTES];
  pa.tobytes(&mut out, true);
  out
}

const BYTES_PER_SCALAR: usize = 64;

/// Very small helper – SHA3‑512 → field element mod r.
fn hash_to_scalar(payload: &[u8]) -> big::BIG {
    let mut h = sha3::SHA3::new(sha3::HASH512);
    h.process_array(payload);
    let mut digest = [0u8;64];
    h.hash(&mut digest);
    // reduce 512‑bit buffer modulo the BLS48‑581 scalar field order
    let mut s = big::BIG::frombytes(&digest[..BYTES_PER_SCALAR]);
    s.rmod(&big::BIG::new_ints(&rom::CURVE_ORDER));
    s
}

/// Synthetic division (in‑place) by (X − x0), returns quotient, assumes
///  `poly(coeff form)[deg ≤ n]`  and     y = poly(x0)   is already known.
fn div_by_linear(poly: &[big::BIG], x0: &big::BIG) -> Vec<big::BIG> {
    let b = big::BIG::modneg(x0, &big::BIG::new_ints(&rom::CURVE_ORDER));
    let a = big::BIG::new_int(1);
    let divisors: Vec<big::BIG> = vec![
      b.clone(),
      a.clone()
    ];
    let mut invb = b.clone();
    invb.invmodp(&big::BIG::new_ints(&rom::CURVE_ORDER));
    let mut inva = a.clone();
    inva.invmodp(&big::BIG::new_ints(&rom::CURVE_ORDER));
    let invdivisors: Vec<big::BIG> = vec![
      invb,
      inva
    ];

    let mut a: Vec<big::BIG> = poly.iter().map(|x| x.clone()).collect();

    // Adapted from Feist's amortized proofs:
    let mut a_pos = a.len() - 1;
    let b_pos = divisors.len() - 1;
    let mut diff = a_pos as isize - b_pos as isize;
    let mut out: Vec<big::BIG> = vec![big::BIG::new(); (diff + 1) as usize];
    while diff >= 0 {
      out[diff as usize] = a[a_pos].clone();
      out[diff as usize] = big::BIG::modmul(&out[diff as usize], &invdivisors[b_pos], &big::BIG::new_ints(&rom::CURVE_ORDER));
      for i in (0..=b_pos).rev() {
        let den = &out[diff as usize].clone();
        a[diff as usize + i] = a[diff as usize + i].clone();
        a[diff as usize + i] = big::BIG::modadd(
          &a[diff as usize + i],
          &big::BIG::modneg(
            &big::BIG::modmul(&den, &divisors[i], &big::BIG::new_ints(&rom::CURVE_ORDER)),
            &big::BIG::new_ints(&rom::CURVE_ORDER)
          ),
          &big::BIG::new_ints(&rom::CURVE_ORDER)
        );
      }
      let mut b = [0u8;73];
      out[diff as usize].tobytes(&mut b);

      a_pos -= 1;
      diff -= 1;
    }
    out
}

#[allow(clippy::too_many_arguments)]
pub fn prove_multiple(
    commitments: &Vec<Vec<u8>>, // Cᵢ
    polys: &Vec<Vec<u8>>,       // fᵢ(x)
    indices: &Vec<u64>,         // zᵢ  = ω_{indices[i]}
    poly_size: u64,
) -> Multiproof {               // (D, π)
    assert_eq!(polys.len(), indices.len());
    let m = polys.len();

    // 0. Pre‑work: commitments Cᵢ and values yᵢ = fᵢ(zᵢ)
    let mut commits: Vec<ecp::ECP> = Vec::with_capacity(m);
    let mut y:      Vec<big::BIG> = Vec::with_capacity(m);
    for (i, (blob, &idx)) in polys.iter().zip(indices).enumerate() {
        commits.push(ecp::ECP::frombytes(&commitments[i]));
        let eval_vec = bytes_to_polynomial(blob);
        y.push( eval_vec[idx as usize].clone() );
    }

    // 1. Fiat–Shamir challenge  ρ
    let mut fs_input = Vec::<u8>::new();
    for (i, c) in commits.iter().enumerate() {
        let mut tmp = [0u8; 74];
        c.tobytes(&mut tmp, true);
        fs_input.extend_from_slice(&tmp);
    }
    for (i, s) in y.iter().enumerate() {
        let mut tmp = [0u8; 73];
        s.tobytes(&mut tmp);
        fs_input.extend_from_slice(&tmp);
    }
    for (i, &idx) in indices.iter().enumerate() { 
        fs_input.extend_from_slice(&idx.to_le_bytes()); 
    }
    let rho = hash_to_scalar(&fs_input);

    // 2. Build  Q(X) = Σ ρᶦ · (fᵢ(X) − yᵢ)/(X − zᵢ)
    // Note – the yᵢ term is removed from the polynomial when performing polynomial division, as it is the remainder.
    let modulus = big::BIG::new_ints(&rom::CURVE_ORDER);
    let mut q_coeffs = vec![vec![big::BIG::new(); poly_size as usize-1]; m];
    let mut h_coeffs = vec![vec![big::BIG::new(); poly_size as usize-1]; m];
    let mut f_evals = Vec::new();
    let mut yrho: Vec<big::BIG> = Vec::with_capacity(m);
    let mut acc_pow = big::BIG::new_int(1);
    for ((index, blob), (&idx, y_i)) in polys.iter().enumerate().zip(indices.iter().zip(y.iter())) {
        let mut f_eval = bytes_to_polynomial(blob);
        while f_eval.len() < poly_size as usize { f_eval.push(big::BIG::new()); }
        let coeffs = fft_fast(&f_eval, poly_size, true).unwrap();    // coeff form
        f_evals.push(coeffs.clone());

        // 2a. divide by (X − zᵢ)
        let f = coeffs.clone();
        let z_i = bls::singleton().RootsOfUnityBLS48581[&poly_size][idx as usize].clone();
        let q_i = div_by_linear(&f, &z_i);
        
        // 2b. scale by ρᶦ  and accumulate into Q
        q_coeffs[index] = q_i;
        for dst in q_coeffs[index].iter_mut() {
          *dst = big::BIG::modmul(&acc_pow, &dst, &modulus);
        }

        yrho.push(big::BIG::modmul(y_i, &acc_pow, &modulus));
        
        // next power of ρ
        acc_pow = big::BIG::modmul(&acc_pow, &rho, &modulus); // ρ←ρ·ρ   (cheap pow‑chain)
    }

    // 3. Commit to  Q (H check added for debugging)
    let mut qx = q_coeffs.iter().fold(
      vec![big::BIG::new(); poly_size as usize],
      |acc, q| acc.iter().zip(q).map(|(a,b)| big::BIG::modadd(a,b,&modulus)).collect(),
    );
    qx.push(big::BIG::new());

    let c_q = &point_linear_combination_fast(
      &bls::singleton().CeremonyBLS48581G1[..(qx.len())],
      &qx,
    ).unwrap();
    
    let mut c_q_bytes = [0u8; 74];
    c_q.tobytes(&mut c_q_bytes, true);

    // 4. Fiat–Shamir point  t
    let t = hash_to_scalar(&c_q_bytes);

    // 5. Compute h(x) =  Σ ρᶦ · (fᵢ(X))/(t − zᵢ)
    let mut acc_pow = big::BIG::new_int(1);
    for ((index, blob), (&idx, y_i)) in polys.iter().enumerate().zip(indices.iter().zip(y.iter())) {
        let mut coeffs = f_evals[index].clone();
        let z_i = bls::singleton().RootsOfUnityBLS48581[&poly_size][idx as usize].clone();
        let mut den = big::BIG::modadd(&t, &big::BIG::modneg(&z_i, &modulus), &modulus);
        den.invmodp(&modulus);
        for (i, dst) in coeffs.iter_mut().enumerate() {
          *dst = big::BIG::modmul(dst, &acc_pow, &modulus);
          *dst = big::BIG::modmul(dst, &den, &modulus);
        }
        h_coeffs[index] = coeffs.clone();
        
        acc_pow = big::BIG::modmul(&acc_pow, &rho, &modulus);
    }
    let hx = h_coeffs.iter().fold(
      vec![big::BIG::new(); poly_size as usize],
      |acc, q| acc.iter().zip(q).map(|(a,b)| big::BIG::modadd(a,b,&modulus)).collect(),
    );
    let c_h = &point_linear_combination_fast(
      &bls::singleton().CeremonyBLS48581G1[..(hx.len())],
      &hx,
    ).unwrap();
    let mut g2x: Vec<big::BIG> = hx.iter().zip(qx).map(|(h, q)| big::BIG::modadd(h, &big::BIG::modneg(&q, &modulus), &modulus)).collect();

    let mut c_h_bytes = [0u8; 74];
    c_h.tobytes(&mut c_h_bytes, true);

    // 6. Evaluate y and produce opening π
    let mut y = big::BIG::new();
    for (idx, coeff) in yrho.iter().enumerate() {
        let root_idx = *indices.get(idx).unwrap() as usize;
        let root = bls::singleton().RootsOfUnityBLS48581[&poly_size][root_idx].clone();
        
        let mut div = big::BIG::modadd(&t, &big::BIG::modneg(&root, &modulus), &modulus);
        
        div.invmodp(&modulus);
        
        let term = big::BIG::modmul(coeff, &div, &modulus);
        
        y = big::BIG::modadd(&y, &term, &modulus);
    }
    
    // (g2 − q_t)/(X − t)
    let g2div = div_by_linear(&g2x, &t);

    let proof = point_linear_combination_fast(
        &bls::singleton().CeremonyBLS48581G1[..g2div.len()],
        &g2div
    ).unwrap();
    let mut proof_bytes = [0u8; 74];
    proof.tobytes(&mut proof_bytes, true);

    let mut q_t_bytes = [0u8; 73];
    y.tobytes(&mut q_t_bytes);

    Multiproof{
      proof: proof_bytes.to_vec(),
      d: c_q_bytes.to_vec(),
    }
}

pub fn verify_multiple(
    commits: &Vec<Vec<u8>>,  // Cᵢ
    y_bytes: &Vec<Vec<u8>>,  // yᵢ
    indices: &Vec<u64>,
    poly_size: u64,
    c_q_bytes: &Vec<u8>,    // D
    proof_bytes: &Vec<u8>,  // π
) -> bool {
    assert_eq!(commits.len(), indices.len());
    assert_eq!(commits.len(), y_bytes.len());
    let m = commits.len();

    // 0. Decode input
    let c_q = ecp::ECP::frombytes(c_q_bytes.as_slice()); // D
    let proof = ecp::ECP::frombytes(proof_bytes); // π

    let mut c_points: Vec<ecp::ECP> = Vec::with_capacity(m); // Cᵢ
    let mut y_scalars: Vec<big::BIG> = Vec::with_capacity(m); // yᵢ
    for (i, (c_bytes, y_b)) in commits.iter().zip(y_bytes).enumerate() {
        c_points.push(ecp::ECP::frombytes(&c_bytes));
        y_scalars.push(big::BIG::frombytes(&y_b));
    }

    // 1. Re‑derive ρ
    let mut fs_input = Vec::<u8>::new();
    for (i, b) in commits.iter().enumerate() {
      fs_input.extend_from_slice(b);
    }
    for (i, b) in y_bytes.iter().enumerate() {
      fs_input.extend_from_slice(&[0u8;9]);
      fs_input.extend_from_slice(b);
    }
    for (i, &idx) in indices.iter().enumerate() { 
      fs_input.extend_from_slice(&idx.to_le_bytes()); 
    }
    
    let rho = hash_to_scalar(&fs_input);
    
    let modulus = big::BIG::new_ints(&rom::CURVE_ORDER);
    let t = hash_to_scalar(c_q_bytes);

    // 2. Compute E and y
    let mut scalars: Vec<big::BIG> = Vec::with_capacity(m + 1);
    let mut acc_pow = big::BIG::new_int(1);
    let mut y = big::BIG::new();
    
    for ((c_i, y_i), &idx) in c_points.iter().zip(y_scalars.iter()).zip(indices) {
        let z_i = bls::singleton().RootsOfUnityBLS48581[&poly_size][idx as usize].clone();
        
        let mut denom = big::BIG::modadd(&t, &big::BIG::modneg(&z_i, &modulus), &modulus);
        
        // 1/(t−zᵢ)
        denom.invmodp(&modulus);
        
        let numerator = big::BIG::modmul(&acc_pow, y_i, &modulus);
        y = big::BIG::modadd(&y, &big::BIG::modmul(&numerator, &denom, &modulus), &modulus);

        let coeff = big::BIG::modmul(&acc_pow, &denom, &modulus);
        scalars.push(coeff);

        // next ρᶦ
        acc_pow = big::BIG::modmul(&acc_pow, &rho, &modulus);
    }

    // commit = E-D
    let mut commit = point_linear_combination_fast(&c_points, &scalars).unwrap();
    let mut e_bytes = [0u8; 74];
    commit.tobytes(&mut e_bytes, true);
    commit.sub(&c_q);

    // 3. Check: single Kate opening  (E-D-[y], G2, q_t, proof)
    verify(&commit, &t, &y, &proof)
}
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use ecp::ECP;

    use super::*;

    #[test]
    fn fft_matches_fft_g1_when_raised() {
      init();
      let mut rand = rand::RAND::new();
      let mut v = vec![big::BIG::new(); 16];
      let mut vp = vec![ECP::new(); 16];
      for i in 0..16 {
        v[i] = big::BIG::random(&mut rand);
        vp[i] = ECP::generator().mul(&v[i]);
      }
      let scalars = fft(v.as_slice(), 16, false).unwrap();
      let points = fft_g1(vp.as_slice(), 16, false).unwrap();
      for (i, s) in scalars.iter().enumerate() {
        let sp = ECP::generator().mul(&s);
        assert!(points[i].equals(&sp));
      }
    }

    #[test]
    fn bls_multi_sign() {
        init();
        let outs: Vec<BlsKeygenOutput> = (0..20).into_iter().map(|_| bls_keygen()).collect();
        let mut sigs = Vec::<Vec<u8>>::new();
        for out in outs.clone() {
          assert!(bls_verify(&out.public_key, &out.proof_of_possession_sig, &out.public_key, b"BLS48_POP_SK"));
          let sig = bls_sign(&out.secret_key, b"test msg", b"test domain");
          sigs.push(sig);
        }
        let blsAggregateOutput = bls_aggregate(
          &outs.iter().map(|out| out.public_key.clone()).collect::<Vec<Vec<u8>>>(),
          &sigs,
        );
        assert!(bls_verify(&blsAggregateOutput.aggregate_public_key, &blsAggregateOutput.aggregate_signature, b"test msg", b"test domain"));
    }

    #[test]
    fn bls_multi_message_sign() {
        init();
        let outs: Vec<BlsKeygenOutput> = (0..20).into_iter().map(|_| bls_keygen()).collect();
        let mut pks = Vec::<Vec::<u8>>::new();
        let mut messages = Vec::<Vec::<u8>>::new();
        let mut sigs = Vec::<Vec::<u8>>::new();
        for (i, out) in outs.clone().iter().enumerate() {
          assert!(bls_verify(&out.public_key.clone(), &out.proof_of_possession_sig, &out.public_key, b"BLS48_POP_SK"));
          let msg = format!("test msg {i}");
          let sig = bls_sign(&out.secret_key, msg.as_bytes(), b"test domain");
          pks.push(out.public_key.clone());
          messages.push(msg.as_bytes().to_vec());
          sigs.push(sig);
        }
        let blsAggregateOutput = bls_aggregate(
          &outs.iter().map(|out| out.public_key.clone()).collect::<Vec<Vec<u8>>>(),
          &sigs,
        );
        assert!(bls_verify_msig_mmsg(&pks, &blsAggregateOutput.aggregate_signature, &messages, b"test domain"));
    }

    #[test]
    fn multiproof_roundtrip() {
        init();                        // sets up the global BLS48‑581 constants
        let poly_size: u64 = 256;      // evaluation domain Ω₆₄
        let m = 256;            // number of openings in this test

        let mut rng = rand::RAND::new();
        rng.clean();
        rng.seed(32, &[0xA5; 32]);

        // test fixtures to be filled
        let mut blobs:     Vec<Vec<u8>> = Vec::with_capacity(m);
        let mut commits:   Vec<Vec<u8>> = Vec::with_capacity(m);
        let mut y_bytes:   Vec<Vec<u8>> = Vec::with_capacity(m);
        let mut indices:   Vec<u64>     = Vec::with_capacity(m);

        for idx in 0..m {
            // pick a unique evaluation point  z_i  (just use 0,1,2,3,4,5,... here)
            let z_index = idx as u64;
            indices.push(z_index);

            // make 64 random field elements (evaluation form)
            let evals: Vec<[u8;64]> = (0..poly_size)
                .map(|_| {
                  let mut b = [0u8; 64];
                  for i in 0..64 {
                    b[i] = rng.getbyte();
                  }
                  b
                })
                .collect();

            // save the value  y_i = f_i(z_i)  for later verification
            let y_i = evals[z_index as usize].clone();
            y_bytes.push(y_i.to_vec());

            // serialise the whole evaluation vector – 256 scalars × 256 each
            let mut blob: Vec<u8> = Vec::with_capacity((poly_size as usize) * 256);
            for s in &evals {
                blob.extend_from_slice(s);
            }
            blobs.push(blob.clone());

            // pre‑compute commitment  C_i
            commits.push(commit_raw(&blob, poly_size));
        }

        let now = Instant::now();
        let commit_refs: Vec<Vec<u8>> = commits;
        let blob_refs:   Vec<Vec<u8>> = blobs;
        let multiproof = prove_multiple(&commit_refs, &blob_refs, &indices, poly_size);
        println!("prove: {:?} elapsed", now.elapsed());
        let y_refs:      Vec<Vec<u8>> = y_bytes;
        let now = Instant::now();

        assert!(
            verify_multiple(
                &commit_refs,
                &y_refs,
                &indices,
                poly_size,
                &multiproof.d,
                &multiproof.proof
            ),
            "multiproof verification failed"
        );
        println!("verification: {:?} elapsed", now.elapsed());
    }

    #[test]
    fn full_width_commit_prove_verify_roundtrip() {
        init();
        let poly_size: u64 = 16;
        let index: u64 = 3;

        let mut rng = rand::RAND::new();
        rng.clean();
        rng.seed(32, &[0xB7; 32]);

        let modulus = big::BIG::new_ints(&rom::CURVE_ORDER);

        // Generate random field-element scalars (evaluation form)
        let mut scalars = Vec::with_capacity(poly_size as usize);
        for _ in 0..poly_size {
            let mut s = big::BIG::random(&mut rng);
            s.rmod(&modulus);
            scalars.push(s);
        }

        // Serialize to full-width bytes (MODBYTES per scalar)
        let mut full_bytes = Vec::with_capacity(poly_size as usize * FULL_BYTES_PER_SCALAR);
        for s in &scalars {
            let mut buf = [0u8; big::MODBYTES];
            s.tobytes(&mut buf);
            full_bytes.extend_from_slice(&buf);
        }

        // 1. commit_raw_full and commit_scalars must agree
        let c1 = commit_raw_full(&full_bytes, poly_size);
        assert!(!c1.is_empty(), "commit_raw_full returned empty");
        let c2 = commit_scalars(&scalars, poly_size);
        assert_eq!(c1, c2, "commit_raw_full and commit_scalars must match");

        // 2. prove_raw_full opening at a domain point
        let proof = prove_raw_full(&full_bytes, index, poly_size);
        assert!(!proof.is_empty(), "prove_raw_full returned empty");

        // 3. Evaluation value is scalars[index] (Lagrange eval form)
        let mut y_bytes = [0u8; big::MODBYTES];
        scalars[index as usize].tobytes(&mut y_bytes);

        // 4. Verify — verify_raw accepts any-length data slice
        assert!(
            verify_raw(&y_bytes, &c1, index, &proof, poly_size),
            "full-width roundtrip verification failed"
        );
    }

    #[test]
    fn commit_monomial_matches_lagrange() {
        init();
        let poly_size: u64 = 16;

        let mut rng = rand::RAND::new();
        rng.clean();
        rng.seed(32, &[0xC3; 32]);

        let modulus = big::BIG::new_ints(&rom::CURVE_ORDER);

        // Random coefficient-form polynomial
        let mut coeffs = Vec::with_capacity(poly_size as usize);
        for _ in 0..poly_size {
            let mut s = big::BIG::random(&mut rng);
            s.rmod(&modulus);
            coeffs.push(s);
        }

        // Commit via monomial SRS (coefficient form)
        let c_mono = commit_scalars_monomial(&coeffs);
        assert!(!c_mono.is_empty());

        // Convert to eval form and commit via Lagrange SRS
        let evals = fft(&coeffs, poly_size, false).unwrap();
        let c_lagr = commit_scalars(&evals, poly_size);

        assert_eq!(c_mono, c_lagr, "monomial and Lagrange commits must match");
    }

    #[test]
    fn fft_fast_matches_fft() {
        init();
        let mut rng = rand::RAND::new();
        rng.clean();
        rng.seed(32, &[0xD1; 32]);

        let modulus = big::BIG::new_ints(&rom::CURVE_ORDER);

        for &size in &[16u64, 32, 64, 128, 256] {
            let mut values = Vec::with_capacity(size as usize);
            for _ in 0..size {
                let mut s = big::BIG::random(&mut rng);
                s.rmod(&modulus);
                values.push(s);
            }

            // Forward FFT
            let out_orig = fft(&values, size, false).unwrap();
            let out_fast = fft_fast(&values, size, false).unwrap();
            assert_eq!(out_orig.len(), out_fast.len(), "size mismatch for n={}", size);
            for i in 0..out_orig.len() {
                assert!(big::BIG::comp(&out_orig[i], &out_fast[i]) == 0,
                    "forward FFT mismatch at index {} for n={}", i, size);
            }

            // Inverse FFT
            let inv_orig = fft(&values, size, true).unwrap();
            let inv_fast = fft_fast(&values, size, true).unwrap();
            for i in 0..inv_orig.len() {
                assert!(big::BIG::comp(&inv_orig[i], &inv_fast[i]) == 0,
                    "inverse FFT mismatch at index {} for n={}", i, size);
            }
        }
    }

    #[test]
    fn fft_fast_roundtrip() {
        init();
        let mut rng = rand::RAND::new();
        rng.clean();
        rng.seed(32, &[0xE2; 32]);

        let modulus = big::BIG::new_ints(&rom::CURVE_ORDER);
        let size = 64u64;

        let mut values = Vec::with_capacity(size as usize);
        for _ in 0..size {
            let mut s = big::BIG::random(&mut rng);
            s.rmod(&modulus);
            values.push(s);
        }

        // fft_fast forward then inverse should recover original
        let evals = fft_fast(&values, size, false).unwrap();
        let recovered = fft_fast(&evals, size, true).unwrap();
        for i in 0..values.len() {
            assert!(big::BIG::comp(&values[i], &recovered[i]) == 0,
                "roundtrip mismatch at index {}", i);
        }
    }

    #[test]
    fn madd_matches_add() {
        init();

        let g = ECP::generator();

        // Create two distinct affine points
        let p1 = g.mul(&big::BIG::new_int(42));
        let mut p1_aff = p1.clone();
        p1_aff.affine();

        let p2 = g.mul(&big::BIG::new_int(77));
        let mut p2_aff = p2.clone();
        p2_aff.affine();

        // add
        let mut r_add = p1_aff.clone();
        r_add.add(&p2_aff);
        r_add.affine();

        // madd
        let mut r_madd = p1_aff.clone();
        r_madd.madd(&p2_aff);
        r_madd.affine();

        let mut b1 = [0u8; 74];
        let mut b2 = [0u8; 74];
        r_add.tobytes(&mut b1, true);
        r_madd.tobytes(&mut b2, true);
        assert_eq!(b1, b2, "madd must match add for two distinct affine points");
    }

    #[test]
    fn muln_fast_matches_muln() {
        init();
        let mut rng = rand::RAND::new();
        rng.clean();
        rng.seed(32, &[0xF3; 32]);

        let modulus = big::BIG::new_ints(&rom::CURVE_ORDER);
        let g = ECP::generator();

        for &n in &[1, 4, 16, 32, 64, 128] {
            // Generate n random points and scalars
            let mut scalars = Vec::with_capacity(n);
            let mut points = Vec::with_capacity(n);
            for _ in 0..n {
                let mut s = big::BIG::random(&mut rng);
                s.rmod(&modulus);
                let p = g.mul(&s);  // random point
                let mut e = big::BIG::random(&mut rng);
                e.rmod(&modulus);
                points.push(p);
                scalars.push(e);
            }

            let result_orig = ECP::muln(n, &points, &scalars);
            let result_fast = ECP::muln_fast(n, &points, &scalars);

            // Compare by converting to affine bytes
            let mut b1 = [0u8; 74];
            let mut b2 = [0u8; 74];
            result_orig.tobytes(&mut b1, true);
            result_fast.tobytes(&mut b2, true);
            assert_eq!(b1, b2, "muln_fast mismatch for n={}", n);
        }
    }

    #[test]
    fn commit_scalars_fast_matches_original() {
        init();
        let poly_size: u64 = 16;

        let mut rng = rand::RAND::new();
        rng.clean();
        rng.seed(32, &[0xA1; 32]);

        let modulus = big::BIG::new_ints(&rom::CURVE_ORDER);

        let mut scalars = Vec::with_capacity(poly_size as usize);
        for _ in 0..poly_size {
            let mut s = big::BIG::random(&mut rng);
            s.rmod(&modulus);
            scalars.push(s);
        }

        let c_orig = commit_scalars(&scalars, poly_size);
        let c_fast = commit_scalars_fast(&scalars, poly_size);
        assert_eq!(c_orig, c_fast, "commit_scalars_fast must match commit_scalars");

        // Also test monomial commitment
        let coeffs = fft(&scalars, poly_size, true).unwrap();
        let cm_orig = commit_scalars_monomial(&coeffs);
        let cm_fast = commit_scalars_monomial_fast(&coeffs);
        assert_eq!(cm_orig, cm_fast, "commit_scalars_monomial_fast must match");
    }
}

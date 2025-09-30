#![allow(clippy::many_single_char_names)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_memcpy)]
#![allow(clippy::new_without_default)]
use num::integer::sqrt;
use rand::{Rng, RngCore};
use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar, EdwardsPoint};
use subtle::{Choice, ConstantTimeEq, ConstantTimeGreater};

uniffi::include_scaffolding!("lib");

fn u64_to_le_bytes(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..std::mem::size_of::<u64>()].copy_from_slice(&value.to_le_bytes());
    bytes
}

type Matrix = Vec<Vec<[u8; 32]>>;
type Vector = Vec<[u8; 32]>;
type SecretSharedMatrix = Vec<Matrix>;
type SecretSharedVector = Vec<Vector>;

pub fn gen_poly_frags(
    secret: &Scalar,
    total: u64,
    threshold: u64,
) -> Vec<[u8; 32]> {
    let mut coeffs = vec![*secret];
    let mut rng = rand::thread_rng();

    for _ in 1..=threshold {
        let mut coeff_bytes = [0u8; 32];
        rng.fill_bytes(&mut coeff_bytes);
        let scalar = Scalar::from_bytes_mod_order(coeff_bytes);
        coeffs.push(scalar);
    }

    let mut frags = Vec::with_capacity(total as usize);

    for i in 1..=total {
        let mut result = coeffs[0];
        let i_bytes = u64_to_le_bytes(i);
        let mut x = Scalar::from_bytes_mod_order(i_bytes);

        for j in 1..threshold {
            let xi = coeffs[j as usize] * x;
            result += xi;
            x *= Scalar::from_bytes_mod_order(i_bytes);
        }

        frags.push(result.to_bytes());
    }

    frags
}

fn shamir_split_matrix(
    matrix: &[Vec<Scalar>],
    total: u64,
    threshold: u64,
) -> SecretSharedMatrix {
    let mut shamir_matrix = vec![vec![vec![[0u8; 32]; matrix[0].len()]; matrix.len()]; total as usize];

    for x in 0..matrix.len() {
        for y in 0..matrix[0].len() {
            let frags = gen_poly_frags(&matrix[x][y], total, threshold);
            for i in 0..total {
                shamir_matrix[i as usize][x as usize][y as usize] = frags[i as usize];
            }
        }
    }

    shamir_matrix
}

fn generate_random_vector_shares(
    length: u64,
    total: u64,
    threshold: u64,
) -> SecretSharedVector {
    let mut result = vec![vec![[0u8; 32]; length as usize]; total as usize];
    let mut rng = rand::thread_rng();

    for j in 0..length {
        let mut bi_bytes = [0u8; 32];
        rng.fill_bytes(&mut bi_bytes);
        let scalar = Scalar::from_bytes_mod_order(bi_bytes);
        let frags = gen_poly_frags(&scalar, total, threshold);
        for i in 0..total {
            result[i as usize][j as usize] = frags[i as usize];
        }
    }

    result
}

pub fn interpolate_polynomial_shares(
    shares: &[Scalar],
    ids: &[u64],
) -> Scalar {
    let mut reconstructed_sum = Scalar::ZERO;

    for j in 0..ids.len() {
        let mut coeff_num = Scalar::ONE;
        let mut coeff_denom = Scalar::ONE;

        for k in 0..ids.len() {
            if j != k {
                let ik_scalar = Scalar::from(ids[k] as u64);
                let ij_scalar = Scalar::from(ids[j] as u64);

                coeff_num *= ik_scalar;
                coeff_denom *= ik_scalar - ij_scalar;
            }
        }

        let coeff = coeff_num * coeff_denom.invert();
        let reconstructed_frag = coeff * shares[(ids[j] - 1) as usize];
        reconstructed_sum += reconstructed_frag;
    }

    reconstructed_sum
}

fn interpolate_polynomial_point_shares(
    shares: &[EdwardsPoint],
    ids: &[u64],
) -> EdwardsPoint {
    let mut reconstructed_sum = EdwardsPoint::mul_base(&Scalar::ZERO);

    for j in 0..ids.len() {
        let mut coeff_num = Scalar::ONE;
        let mut coeff_denom = Scalar::ONE;

        for k in 0..ids.len() {
            if j != k {
                let ik_scalar = Scalar::from(ids[k] as u64);
                let ij_scalar = Scalar::from(ids[j] as u64);

                coeff_num *= ik_scalar;
                coeff_denom *= ik_scalar - ij_scalar;
            }
        }

        let coeff = coeff_num * coeff_denom.invert();
        let reconstructed_frag = shares[(ids[j] - 1) as usize] * coeff;
        reconstructed_sum += reconstructed_frag;
    }

    reconstructed_sum
}

/// Compare two Scalars: returns 1 if a > b, 0 otherwise, in constant time
fn scalar_gt(a: &Scalar, b: &Scalar) -> Choice {
    let a_bytes = a.to_bytes();
    let b_bytes = b.to_bytes();
    let mut result = 0u8;
    let mut all_equal = 1u8;

    for i in (0..32).rev() {
        let byte_gt = ConstantTimeGreater::ct_gt(&a_bytes[i], &b_bytes[i]);
        let byte_eq = ConstantTimeEq::ct_eq(&a_bytes[i], &b_bytes[i]);
        result |= byte_gt.unwrap_u8() & all_equal;
        all_equal &= byte_eq.unwrap_u8();
    }

    Choice::from(result)
}

fn lu_decompose(
    matrix: &[Vec<Scalar>],
) -> (Vec<Vec<Scalar>>, Vec<Vec<Scalar>>) {
    let n = matrix.len();
    let mut p = (0..n).collect::<Vec<_>>();
    let mut new_a = matrix.to_vec();
    let mut pm = vec![vec![Scalar::ZERO; n]; n];

    for i in 0..n {
        let mut imax = i;
        let mut max_a = new_a[i][i];

        for k in i..n {
            if bool::from(scalar_gt(&new_a[k][i], &max_a)) {
                max_a = new_a[k][i];
                imax = k;
            }
        }

        if imax != i {
            p.swap(i, imax);
            new_a.swap(i, imax);
        }

        for j in i + 1..n {
            let m = new_a[i][i];
            new_a[j][i] *= m.invert();

            for k in i + 1..n {
                let n = new_a[j][i];
                let o = new_a[i][k];
                new_a[j][k] -= n * o;
            }
        }
    }

    for i in 0..n {
        for j in 0..n {
            pm[i][j] = if p[i] == j { Scalar::ONE } else { Scalar::ZERO };
        }
    }

    (new_a, pm)
}

fn invert(matrix: &[Vec<Scalar>]) -> Vec<Vec<Scalar>> {
    let n = matrix.len();
    let (a, p) = lu_decompose(matrix);
    let mut ia = vec![vec![Scalar::ZERO; n]; n];

    for j in 0..n {
        for i in 0..n {
            ia[i][j] = p[i][j];

            for k in 0..i {
                let m = ia[k][j];
                ia[i][j] -= a[i][k] * m;
            }
        }

        for i in (0..n).rev() {
            for k in i + 1..n {
                let m = ia[k][j];
                ia[i][j] -= a[i][k] * m;
            }
            ia[i][j] *= a[i][i].invert();
        }
    }

    ia
}

fn interpolate_matrix_shares(
    matrix_shares: &SecretSharedMatrix,
    ids: &[u64],
) -> Vec<Vec<Scalar>> {
    let mut matrix = vec![vec![Scalar::ZERO; matrix_shares[0][0].len()]; matrix_shares[0].len()];

    for x in 0..matrix.len() {
        for y in 0..matrix[0].len() {
            let mut shares = Vec::with_capacity(matrix_shares.len());
            for i in 0..matrix_shares.len() {
                shares.push(Scalar::from_bytes_mod_order(matrix_shares[i][x][y]));
            }
            matrix[x][y] = interpolate_polynomial_shares(&shares, ids);
        }
    }

    matrix
}

fn scalar_mult(a: i64, b: &[Vec<Scalar>]) -> Vec<Vec<Scalar>> {
    let mut prod = vec![vec![Scalar::ZERO; b[0].len()]; b.len()];
    let scalar_a = if a >= 0 {
        Scalar::from(a as u64)
    } else {
        -Scalar::from((-a) as u64)
    };

    for x in 0..b.len() {
        for y in 0..b[0].len() {
            prod[x][y] = scalar_a * b[x][y];
        }
    }

    prod
}

fn add_matrices(a: &Vec<Vec<Scalar>>, b: &Vec<Vec<Scalar>>) -> Vec<Vec<Scalar>> {
    assert_eq!(a.len(), b.len());
    assert_eq!(a[0].len(), b[0].len());
    let mut result = vec![vec![Scalar::ZERO; a[0].len()]; a.len()];
    for i in 0..a.len() {
        for j in 0..a[0].len() {
            result[i][j] = a[i][j] + b[i][j];
        }
    }
    result
}

fn subtract_matrices(a: &Vec<Vec<Scalar>>, b: &Vec<Vec<Scalar>>) -> Vec<Vec<Scalar>> {
    assert_eq!(a.len(), b.len());
    assert_eq!(a[0].len(), b[0].len());
    let mut result = vec![vec![Scalar::ZERO; a[0].len()]; a.len()];
    for i in 0..a.len() {
        for j in 0..a[0].len() {
            result[i][j] = a[i][j] - b[i][j];
        }
    }
    result
}

fn strassen(a: &Vec<Vec<Scalar>>, b: &Vec<Vec<Scalar>>) -> Vec<Vec<Scalar>> {
    let n = a.len();
    
    if n == 1 {
        return vec![vec![a[0][0] * b[0][0]]];
    }
    
    let new_size = n.next_power_of_two();
    let mut a_padded = vec![vec![Scalar::ZERO; new_size]; new_size];
    let mut b_padded = vec![vec![Scalar::ZERO; new_size]; new_size];
    
    for i in 0..n {
        for j in 0..n {
            a_padded[i][j] = a[i][j];
            b_padded[i][j] = b[i][j];
        }
    }
    
    let mid = new_size / 2;
    
    let a11 = &a_padded[..mid].iter().map(|row| row[..mid].to_vec()).collect::<Vec<_>>();
    let a12 = &a_padded[..mid].iter().map(|row| row[mid..].to_vec()).collect::<Vec<_>>();
    let a21 = &a_padded[mid..].iter().map(|row| row[..mid].to_vec()).collect::<Vec<_>>();
    let a22 = &a_padded[mid..].iter().map(|row| row[mid..].to_vec()).collect::<Vec<_>>();
    
    let b11 = &b_padded[..mid].iter().map(|row| row[..mid].to_vec()).collect::<Vec<_>>();
    let b12 = &b_padded[..mid].iter().map(|row| row[mid..].to_vec()).collect::<Vec<_>>();
    let b21 = &b_padded[mid..].iter().map(|row| row[..mid].to_vec()).collect::<Vec<_>>();
    let b22 = &b_padded[mid..].iter().map(|row| row[mid..].to_vec()).collect::<Vec<_>>();
    
    let p1 = strassen(&add_matrices(a11, a22), &add_matrices(b11, b22));
    let p2 = strassen(&add_matrices(a21, a22), b11);
    let p3 = strassen(a11, &subtract_matrices(b12, b22));
    let p4 = strassen(a22, &subtract_matrices(b21, b11));
    let p5 = strassen(&add_matrices(a11, a12), b22);
    let p6 = strassen(&subtract_matrices(a21, a11), &add_matrices(b11, b12));
    let p7 = strassen(&subtract_matrices(a12, a22), &add_matrices(b21, b22));
    
    let c11 = add_matrices(&subtract_matrices(&add_matrices(&p1, &p4), &p5), &p7);
    let c12 = add_matrices(&p3, &p5);
    let c21 = add_matrices(&p2, &p4);
    let c22 = add_matrices(&subtract_matrices(&add_matrices(&p1, &p3), &p2), &p6);
    
    let mut result = vec![vec![Scalar::ZERO; new_size]; new_size];
    for i in 0..mid {
        for j in 0..mid {
            result[i][j] = c11[i][j];
            result[i][j+mid] = c12[i][j];
            result[i+mid][j] = c21[i][j];
            result[i+mid][j+mid] = c22[i][j];
        }
    }
    
    result[..n].iter().map(|row| row[..n].to_vec()).collect()
}

fn coppersmith_winograd(a: &Vec<Vec<Scalar>>, b: &Vec<Vec<Scalar>>) -> Vec<Vec<Scalar>> {
  let n = a.len();
  
  if n == 1 {
      return vec![vec![a[0][0] * b[0][0]]];
  }
  
  let new_size = if n % 2 == 0 { n } else { n + 1 };
  let mut a_padded = vec![vec![Scalar::ZERO; new_size]; new_size];
  let mut b_padded = vec![vec![Scalar::ZERO; new_size]; new_size];
  
  for i in 0..n {
      for j in 0..n {
          a_padded[i][j] = a[i][j];
          b_padded[i][j] = b[i][j];
      }
  }
  
  let mid = new_size / 2;
  
  let a11 = &a_padded[..mid].iter().map(|row| row[..mid].to_vec()).collect::<Vec<_>>();
  let a12 = &a_padded[..mid].iter().map(|row| row[mid..].to_vec()).collect::<Vec<_>>();
  let a21 = &a_padded[mid..].iter().map(|row| row[..mid].to_vec()).collect::<Vec<_>>();
  let a22 = &a_padded[mid..].iter().map(|row| row[mid..].to_vec()).collect::<Vec<_>>();
  
  let b11 = &b_padded[..mid].iter().map(|row| row[..mid].to_vec()).collect::<Vec<_>>();
  let b12 = &b_padded[..mid].iter().map(|row| row[mid..].to_vec()).collect::<Vec<_>>();
  let b21 = &b_padded[mid..].iter().map(|row| row[..mid].to_vec()).collect::<Vec<_>>();
  let b22 = &b_padded[mid..].iter().map(|row| row[mid..].to_vec()).collect::<Vec<_>>();
  
  let s1 = subtract_matrices(a21, a11);
  let s2 = add_matrices(a21, a22);
  let s3 = subtract_matrices(a12, a22);
  let s4 = subtract_matrices(b12, b11);
  let s5 = add_matrices(b11, b22);
  let s6 = subtract_matrices(b22, b21);
  
  let p1 = coppersmith_winograd(a11, b11);
  let p2 = coppersmith_winograd(&s1, &s5);
  let p3 = coppersmith_winograd(&s2, b11);
  let p4 = coppersmith_winograd(a22, &s6);
  let p5 = coppersmith_winograd(a11, &s4);
  let p6 = coppersmith_winograd(&s3, b22);
  let p7 = coppersmith_winograd(&s2, &s6);
  
  let t1 = add_matrices(&p1, &p2);
  let t2 = subtract_matrices(&t1, &p3);
  
  let c11 = add_matrices(&p1, &p5);
  let c12 = add_matrices(&t2, &p6);
  let c21 = add_matrices(&t1, &p4);
  let c22 = add_matrices(&t2, &p7);
  
  let mut result = vec![vec![Scalar::ZERO; new_size]; new_size];
  for i in 0..mid {
      for j in 0..mid {
          result[i][j] = c11[i][j];
          result[i][j+mid] = c12[i][j];
          result[i+mid][j] = c21[i][j];
          result[i+mid][j+mid] = c22[i][j];
      }
  }
  
  result[..n].iter().map(|row| row[..n].to_vec()).collect()
}

fn generate_dot_product(
    a: &Vec<Vec<Scalar>>,
    b: &Vec<Vec<Scalar>>,
) -> Vec<Vec<Scalar>> {
    assert_eq!(a[0].len(), b.len(), "Cannot generate dot product of a and b - mismatched length");

    if a.len() <= 100 {
      let mut ab_matrix = vec![vec![Scalar::ZERO; b[0].len()]; a.len()];

      for x in 0..a.len() {
          for y in 0..b[0].len() {
              for ay in 0..a[0].len() {
                  ab_matrix[x][y] += a[x][ay] * b[ay][y];
              }
          }
      }

      ab_matrix
    } else {
      coppersmith_winograd(a, b)
    }
}

fn generate_random_matrix_and_inverse_shares(
    size: u64,
    total: u64,
    threshold: u64,
) -> [SecretSharedMatrix; 2] {
    let mut output = vec![vec![Scalar::ZERO; size as usize]; size as usize];
    let mut rng = rand::thread_rng();

    for x in 0..size {
        for y in 0..size {
            let mut i_bytes = [0u8; 32];
            rng.fill_bytes(&mut i_bytes);
            output[x as usize][y as usize] = Scalar::from_bytes_mod_order(i_bytes);
        }
    }

    let split_output = shamir_split_matrix(&output, total, threshold);
    let split_inverse = shamir_split_matrix(&invert(&output), total, threshold);

    [split_output, split_inverse]
}

fn generate_random_beaver_triple_matrix_shares(
    size_x: u64,
    size_y: u64,
    total: u64,
    threshold: u64,
) -> (Vec<Vec<Scalar>>, Vec<Vec<Scalar>>, SecretSharedMatrix, SecretSharedMatrix, SecretSharedMatrix) {
    let mut u_matrix = vec![vec![Scalar::ZERO; size_x as usize]; size_y as usize];
    let mut v_matrix = vec![vec![Scalar::ZERO; size_x as usize]; size_x as usize];
    let mut rng = rand::thread_rng();

    for i in 0..size_y {
        for j in 0..size_x {
            let mut uj_bytes = [0u8; 32];
            rng.fill_bytes(&mut uj_bytes);
            u_matrix[i as usize][j as usize] = Scalar::from_bytes_mod_order(uj_bytes);
        }
    }

    for i in 0..size_x {
        for j in 0..size_x {
            let mut vj_bytes = [0u8; 32];
            rng.fill_bytes(&mut vj_bytes);
            v_matrix[i as usize][j as usize] = Scalar::from_bytes_mod_order(vj_bytes);
        }
    }

    let uv_matrix = generate_dot_product(&u_matrix, &v_matrix);

    let u_matrix_shares = shamir_split_matrix(&u_matrix, total, threshold);
    let v_matrix_shares = shamir_split_matrix(&v_matrix, total, threshold);
    let uv_matrix_shares = shamir_split_matrix(&uv_matrix, total, threshold);

    return (u_matrix, v_matrix, u_matrix_shares, v_matrix_shares, uv_matrix_shares);
}

pub fn generate_permutation_matrix(size: u64) -> Vec<Vec<Scalar>> {
    let mut rng = rand::thread_rng();
    let mut matrix = Vec::with_capacity(size as usize);
    let mut elements: Vec<u64> = (0..size).collect();

    for _ in 0..size {
        let pos = rng.gen_range(0..elements.len());
        let vec_pos = elements.remove(pos);

        let mut vector = vec![Scalar::ZERO; size as usize];
        vector[vec_pos as usize] = Scalar::ONE;

        matrix.push(vector);
    }

    matrix
}

fn rpm_collect_r(rs: Vec<Vec<Vec<Scalar>>>, size: u64, depth: u64, players: u64) -> Vec<Vec<Scalar>> {
  let mut r = vec![vec![Scalar::ZERO; size as usize]; depth as usize];
  for j in 0..depth {
      for k in 0..size {
          for i in 0..players {
              r[j as usize][k as usize] += rs[i as usize][j as usize][k as usize];
          }
      }
  }

  r
}

fn rpm_collect_m(ms: Vec<Vec<Vec<Vec<Vec<Scalar>>>>>, size: u64, depth: u64, players: u64) -> Vec<Vec<Vec<Vec<Scalar>>>> {
  let k = sqrt(size);
  let mut m = vec![vec![vec![vec![Scalar::ZERO; k as usize]; k as usize]; k as usize]; depth as usize];
  for j in 0..depth {
      for l in 0..k {
          for i in 0..players {
              if i == 0 {
                  m[j as usize][l as usize] = ms[i as usize][j as usize][l as usize].clone();
              } else {
                  m[j as usize][l as usize] = generate_dot_product(&m[j as usize][l as usize], &ms[i as usize][j as usize][l as usize]);
              }
          }
      }
  }

  m
}

fn rpm_butterfly(r: &Vec<Scalar>) -> Vec<Scalar> {
  let k = sqrt(r.len());
  let mut out = vec![Scalar::ZERO; r.len()];
  for i in 0..r.len() {
    out[(i % k) * k + (i / k)] = r[i];
  }

  out
}

pub struct InitialShares {
    pub ms: Vec<Vec<SecretSharedMatrix>>,
    pub rs: Vec<SecretSharedVector>,
}

// The truly offline portion of RPM Variant 3 (subvariant 2) – generates `dealers^2` shamir splits of `sqrt(size) x sqrt(size)` permutation matrices and `depth` `size`-sized vectors.
// Output matrices are indexed by depth, then sub matrix for the depth, then party (minus 1). Output vectors are indexed by depth, then party (minus 1). 
pub fn rpm_generate_initial_shares(size: u64, depth: u64, dealers: u64, players: u64) -> InitialShares {
    if players < dealers*dealers {
      assert!(false, "players must be at greater than or equal to dealers^2");
    }

    let k = sqrt(size);

    let mut permutation_matrices_shares = Vec::<Vec<Vec<Matrix>>>::with_capacity(depth as usize);
    let mut random_shares = Vec::<Vec<Vector>>::with_capacity(depth as usize);
    for _i in 0..depth {
        let mut share_set = Vec::<Vec<Vec<Vector>>>::with_capacity(k as usize);
        for _j in 0..k {
            let matrix = generate_permutation_matrix(k);
            share_set.push(shamir_split_matrix(&matrix, players, dealers));
        }
        permutation_matrices_shares.push(share_set);
    }

    for _i in 0..depth {
        random_shares.push(generate_random_vector_shares(size, players, dealers));
    }

    InitialShares{
        ms: permutation_matrices_shares,
        rs: random_shares,
    }
}

pub struct CombinedSharesAndMask {
    pub ms: Vec<Vec<Matrix>>,
    pub rs: Vec<Vector>,
    pub mrms: Vec<Vec<Matrix>>,
}

// The second part of the "offline" portion of RPM Variant 3 (subvariant 2). Not truly offline, but the paper designates "offline" as "not actively processing user input". Fixes a
// flaw in Variant 3 with subvariant 2 - Using Variant 2 standalone the mask vector (R) shares are intended to be additively combined, then when online, shares are given to the end
// users directly from the servers, masking their input, and unmasked subtractively at the end with the mask-only product with the permutation matrix. For Variant 3, this is insufficient
// as the first round of depth produces an unmasked output vector with `sqrt(size)` k-anonymity instead of `size` k-anonymity. Arguably, this is still better than no anonymity but the
// claims in the paper are incorrect with standard shamir sharing. When countered with proposing the use of authenticated beaver triples instead, the problem is resolved, but the
// communication and compute complexity go up astronomically, which the paper does not account for in complexity analysis. We instead use a far cheaper and equally secure option of
// creating a mask vector for every subsequent depth, running the butterfly shuffle to get its inverse, applying it to the output vector shares in the same way the user applies the
// original mask vector, before applying the butterfly shuffle to the output vector itself (thus inverting the inverse shuffled mask on the output vector), running the next depth's
// permutation and subtracting the mask vector's dot product with the depth's matrices applied to it. If this is what the paper _meant_ by saying one can use Variant 2 with Variant 3,
// they never explained it (and their example MP-SPDZ "code" for perf testing doesn't have this shape, let alone actually work beyond drilling the equivalent number of operations to
// get performance data).
// WARNING: this function has NO guardrails – it is expected bounds are checked upstream.
pub fn rpm_combine_shares_and_mask(ms: Vec<Vec<Vec<Matrix>>>, rs: Vec<Vec<Vector>>, size: u64, depth: u64, dealers: u64) -> CombinedSharesAndMask {
    let k = sqrt(size);
    let mut mss = vec![vec![vec![vec![vec![Scalar::ZERO; ms[0][0][0][0].len()]; ms[0][0][0].len()]; ms[0][0].len()]; ms[0].len()]; ms.len()];
    let mut rss = vec![vec![vec![Scalar::ZERO; rs[0][0].len()]; rs[0].len()]; rs.len()];
    for i in 0..rs.len() {
        for j in 0..rs[0].len() {
            for k in 0..rs[0][0].len() {
                rss[i][j][k] = Scalar::from_bytes_mod_order(rs[i][j][k]);
            }
        }
    }
    
    for i in 0..ms.len() {
        for j in 0..ms[0].len() {
            for k in 0..ms[0][0].len() {
                for l in 0..ms[0][0][0].len() {
                    for m in 0..ms[0][0][0][0].len() {
                        mss[i][j][k][l][m] = Scalar::from_bytes_mod_order(ms[i][j][k][l][m]);
                    }
                }
            }
        }
    }

    let r = rpm_collect_r(rss, size, depth, dealers);
    let m = rpm_collect_m(mss, size, depth, dealers);
    let mut mrm = vec![vec![vec![vec![Scalar::ZERO; k as usize]; 1]; k as usize]; depth as usize];
    for d in 0..depth {
        let rd = &r[d as usize];
        let opt_butterfly = if d == 0 { &rd } else { &rpm_butterfly(rd) };
        for i in 0..k {
            mrm[d as usize][i as usize] = generate_dot_product(
              &vec![opt_butterfly[(i*k) as usize..((i+1)*k) as usize].to_vec()],
              &m[d as usize][i as usize],
            );
        }
    }

    let mut rb = vec![vec![[0u8; 32]; r[0].len()]; r.len()];
    let mut mb = vec![vec![vec![vec![[0u8; 32]; m[0][0][0].len()]; m[0][0].len()]; m[0].len()]; m.len()];
    let mut mrmb = vec![vec![vec![vec![[0u8; 32]; mrm[0][0][0].len()]; mrm[0][0].len()]; mrm[0].len()]; mrm.len()];
    for i in 0..r.len() {
        for j in 0..r[0].len() {
            rb[i][j] = r[i][j].to_bytes();
        }
    }

    for i in 0..m.len() {
        for j in 0..m[0].len() {
            for k in 0..m[0][0].len() {
                for l in 0..m[0][0][0].len() {
                    mb[i][j][k][l] = m[i][j][k][l].to_bytes();
                }
            }
        }
    }

    for i in 0..mrm.len() {
        for j in 0..mrm[0].len() {
            for k in 0..mrm[0][0].len() {
                for l in 0..mrm[0][0][0].len() {
                    mrmb[i][j][k][l] = mrm[i][j][k][l].to_bytes();
                }
            }
        }
    }
    
    CombinedSharesAndMask{
        ms: mb, 
        rs: rb,
        mrms: mrmb,
    }
}

pub struct SketchProposal {
  pub mp: Vec<Vec<Vec<[u8; 32]>>>,
  pub rp: Vec<[u8; 32]>,
}

// WARNING: this function has NO guardrails – it is expected bounds are checked upstream.
pub fn rpm_sketch_propose(m: Vec<Vec<Matrix>>, r: Vec<Vector>) -> SketchProposal {
    let mut mc = Vec::<Vec<Vec<[u8; 32]>>>::with_capacity(m.len());
    for i in 0..m.len() {
        let mut mps = Vec::<Vec<[u8; 32]>>::with_capacity(m[0].len());
        for j in 0..m[0].len() {
            let mut mp = Vec::<[u8; 32]>::with_capacity(m[0][0].len());
            for k in 0..m[0][0].len() {
                let mut s = Scalar::ZERO;
                for l in 0..m[0][0][0].len() {
                    s += Scalar::from_bytes_mod_order(m[i][j][k][l]);
                    s += Scalar::from_bytes_mod_order(m[i][j][l][k]);
                }
                mp.push(EdwardsPoint::mul_base(&s).compress().to_bytes());
            }
            mps.push(mp);
        }
        mc.push(mps);
    }

    let mut rp = Vec::<[u8; 32]>::with_capacity(r[0].len());
    for i in 0..r.len() {
        let mut s = Scalar::ZERO;
        for j in 0..r[0].len() {
            s += Scalar::from_bytes_mod_order(r[i][j]);
        }
        rp.push(EdwardsPoint::mul_base(&s).compress().to_bytes());
    }

    SketchProposal{
        mp: mc,
        rp: rp,
    }
}

// WARNING: this function has NO guardrails – it is expected bounds are checked upstream.
pub fn rpm_sketch_verify(mcs: Vec<Vec<Vec<Vec<[u8; 32]>>>>, rcs: Vec<Vec<[u8; 32]>>, dealers: u64) -> bool {
    let two = EdwardsPoint::mul_base(&(Scalar::ONE + Scalar::ONE));
    for i in 0..mcs[0].len() {
        for j in 0..mcs[0][0].len() {
            for k in 0..mcs[0][0][0].len() {
                let mut l = Vec::<EdwardsPoint>::with_capacity(mcs.len());
                for p in 0..mcs.len() {
                    match CompressedEdwardsY::from_slice(&mcs[p][i][j][k]) {
                        Ok(y) => {
                            match y.decompress() {
                                Some(p) => {
                                  l.push(p);
                                }
                                None => {
                                  return false;
                                }
                            }
                        }
                        Err(_) => {
                            return false;
                        }
                    }
                }
                for p in 1..=(mcs.len()-((dealers as usize)*(dealers as usize))+1) {
                    let mut pset = Vec::<u64>::with_capacity((dealers*dealers) as usize);
                    for pi in p..(p+((dealers as usize)*(dealers as usize))) {
                        pset.push(pi as u64);
                    }

                    let v = interpolate_polynomial_point_shares(&l, &pset);
                    if v != two {
                        return false;
                    }
                }
            }
        }
    }

    for i in 0..rcs[0].len() {
        let mut l = Vec::<EdwardsPoint>::with_capacity(rcs.len());
        for p in 0..rcs.len() {
            match CompressedEdwardsY::from_slice(&rcs[p][i]) {
                Ok(y) => {
                    match y.decompress() {
                        Some(p) => {
                          l.push(p);
                        }
                        None => {
                          return false;
                        }
                    }
                }
                Err(_) => {
                    return false;
                }
            }
        }

        let mut rs = Vec::<EdwardsPoint>::with_capacity(rcs.len()-dealers as usize+1);
        for p in 1..=(rcs.len()-dealers as usize+1) {
            let mut pset = Vec::<u64>::with_capacity(dealers as usize);
            for pi in p..(p+dealers as usize) {
                pset.push(pi as u64);
            }

            rs.push(interpolate_polynomial_point_shares(&l, &pset));
        }

        for p in 0..rs.len()-1 {
            if rs[p] != rs[p+1] {
                return false;
            }
        }
    }

    return true;
}

// The online fast permutation phase of the matrices. Outputs in a format expected to be broadcasted, collated by party and redirected back into masked_input_shares for the next round.
// WARNING: this function has NO guardrails – it is expected bounds are checked upstream.
pub fn rpm_permute(masked_input_shares: Vec<Vector>, mb: Vec<Vec<Matrix>>, rb: Vec<Vector>, mrmb: Vec<Vec<Matrix>>, depth_index: u64, parties: Vec<u64>) -> Vec<Vector> {
    let mut big_r  = Vec::<Scalar>::with_capacity(rb[0].len());
    for j in 0..masked_input_shares[0].len() {
        let mut r = Vec::<Scalar>::with_capacity(masked_input_shares.len());
        for k in 0..masked_input_shares.len() {
            r.push(Scalar::from_bytes_mod_order(masked_input_shares[k][j]));
        }
        big_r.push(interpolate_polynomial_shares(&r, &parties));
    }

    let mut y = vec![vec![Scalar::ZERO; rb[0].len()]; 1];

    let mut m = vec![vec![vec![vec![Scalar::ZERO; mb[0][0][0].len()]; mb[0][0].len()]; mb[0].len()]; mb.len()];
    let mut r = vec![vec![Scalar::ZERO; rb[0].len()]; rb.len()];
    let mut mrm = vec![vec![vec![vec![Scalar::ZERO; mrmb[0][0][0].len()]; mrmb[0][0].len()]; mrmb[0].len()]; mrmb.len()];

    for i in 0..mb.len() {
        for j in 0..mb[0].len() {
            for k in 0..mb[0][0].len() {
                for l in 0..mb[0][0][0].len() {
                    m[i][j][k][l] = Scalar::from_bytes_mod_order(mb[i][j][k][l]);
                }
            }
        }
    }

    for i in 0..rb.len() {
        for j in 0..rb[0].len() {
            r[i][j] = Scalar::from_bytes_mod_order(rb[i][j]);
        }
    }

    for i in 0..mrmb.len() {
        for j in 0..mrmb[0].len() {
            for k in 0..mrmb[0][0].len() {
                for l in 0..mrmb[0][0][0].len() {
                    mrm[i][j][k][l] = Scalar::from_bytes_mod_order(mrmb[i][j][k][l]);
                }
            }
        }
    }
    
    let k = sqrt(r[0].len());
    for i in 0..k {
        let mut out = generate_dot_product(&vec![big_r[i*k..(i+1)*k].to_vec()], &m[depth_index as usize][i]);
        out = subtract_matrices(&out, &mrm[depth_index as usize][i]);
        if depth_index as usize + 1 != r.len() {
          out = add_matrices(&out, &vec![r[depth_index as usize + 1][i*k..(i+1)*k].to_vec()]);
        }
        
        for j in 0..k {
          y[0][i*k + j] = out[0][j];
        }
    }

    y[0] = rpm_butterfly(&y[0]);

    let mut yb = vec![vec![[0u8; 32]; rb[0].len()]; 1];
    for i in 0..rb[0].len() {
        yb[0][i] = y[0][i].to_bytes();
    }

    yb
}

// Convenience function for collecting the last round's output and interpolating it.
// WARNING: this function has NO guardrails – it is expected bounds are checked upstream.
pub fn rpm_finalize(input: Vec<Vector>, parties: Vec<u64>) -> Vector {
  let mut result  = Vec::<[u8; 32]>::with_capacity(input[0].len());

  for j in 0..input[0].len() {
      let mut r = Vec::<Scalar>::with_capacity(input.len());
      for k in 0..input.len() {
          r.push(Scalar::from_bytes_mod_order(input[k][j]));
      }
      result.push(interpolate_polynomial_shares(&r, &parties).to_bytes());
  }

  result
}

#[inline]
fn vec32_to_arr32(v: &[u8]) -> [u8; 32] {
    // Fast path with clear panic on invalid shapes (UDL should ensure len==32).
    v.try_into().expect("expected 32-byte element")
}

#[inline]
fn arr32_to_vec32(a: [u8; 32]) -> Vec<u8> {
    a.to_vec()
}

// Matrix <-> sequence<sequence<sequence<u8>>>
fn ffi_matrix_to_internal(m: &Vec<Vec<Vec<u8>>>) -> Matrix {
    m.iter()
        .map(|row| row.iter().map(|cell| vec32_to_arr32(cell)).collect())
        .collect()
}
fn internal_matrix_to_ffi(m: Matrix) -> Vec<Vec<Vec<u8>>> {
    m.into_iter()
        .map(|row| row.into_iter().map(arr32_to_vec32).collect())
        .collect()
}

// Vector <-> sequence<sequence<u8>>
fn ffi_vector_to_internal(v: &Vec<Vec<u8>>) -> Vector {
    v.iter().map(|bytes| vec32_to_arr32(bytes)).collect()
}
fn internal_vector_to_ffi(v: Vector) -> Vec<Vec<u8>> {
    v.into_iter().map(arr32_to_vec32).collect()
}

// SecretSharedMatrix <-> sequence<sequence<sequence<sequence<u8>>>>
fn ffi_ssm_to_internal(ssm: &Vec<Vec<Vec<Vec<u8>>>>) -> SecretSharedMatrix {
    ssm.iter().map(ffi_matrix_to_internal).collect()
}
fn internal_ssm_to_ffi(ssm: SecretSharedMatrix) -> Vec<Vec<Vec<Vec<u8>>>> {
    ssm.into_iter().map(internal_matrix_to_ffi).collect()
}

// SecretSharedVector <-> sequence<sequence<sequence<u8>>>
fn ffi_ssv_to_internal(ssv: &Vec<Vec<Vec<u8>>>) -> SecretSharedVector {
    ssv.iter().map(ffi_vector_to_internal).collect()
}
fn internal_ssv_to_ffi(ssv: SecretSharedVector) -> Vec<Vec<Vec<u8>>> {
    ssv.into_iter().map(internal_vector_to_ffi).collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedInitialShares {
    // ms: Vec<Vec<SecretSharedMatrix>> => seq^6
    pub ms: Vec<Vec<Vec<Vec<Vec<Vec<u8>>>>>>,
    // rs: Vec<SecretSharedVector>      => seq^4
    pub rs: Vec<Vec<Vec<Vec<u8>>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedCombinedSharesAndMask {
    // ms: Vec<Vec<Matrix>> => seq^5
    pub ms: Vec<Vec<Vec<Vec<Vec<u8>>>>>,
    // rs: Vec<Vector>      => seq^3
    pub rs: Vec<Vec<Vec<u8>>>,
    // mrms: Vec<Vec<Matrix>> => seq^5
    pub mrms: Vec<Vec<Vec<Vec<Vec<u8>>>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedSketchProposal {
    // mp: Vec<Vec<Vec<[u8;32]>>> => seq^4
    pub mp: Vec<Vec<Vec<Vec<u8>>>>,
    // rp: Vec<[u8;32]>           => seq^2
    pub rp: Vec<Vec<u8>>,
}

impl From<InitialShares> for WrappedInitialShares {
    fn from(x: InitialShares) -> Self {
        let ms = x.ms
            .into_iter()
            .map(|row| row.into_iter().map(internal_ssm_to_ffi).collect())
            .collect();
        let rs = x.rs
            .into_iter()
            .map(internal_ssv_to_ffi)
            .collect();
        WrappedInitialShares { ms, rs }
    }
}

impl From<CombinedSharesAndMask> for WrappedCombinedSharesAndMask {
    fn from(x: CombinedSharesAndMask) -> Self {
        let ms = x.ms
            .into_iter()
            .map(|row| row.into_iter().map(internal_matrix_to_ffi).collect())
            .collect();
        let rs = x.rs
            .into_iter()
            .map(internal_vector_to_ffi)
            .collect();
        let mrms = x.mrms
            .into_iter()
            .map(|row| row.into_iter().map(internal_matrix_to_ffi).collect())
            .collect();
        WrappedCombinedSharesAndMask { ms, rs, mrms }
    }
}

impl From<SketchProposal> for WrappedSketchProposal {
    fn from(x: SketchProposal) -> Self {
        let mp = x.mp
            .into_iter()
            .map(internal_matrix_to_ffi)
            .collect();
        let rp = internal_vector_to_ffi(x.rp);
        WrappedSketchProposal { mp, rp }
    }
}

pub fn wrapped_rpm_generate_initial_shares(
    size: u64, depth: u64, dealers: u64, players: u64
) -> WrappedInitialShares {
    rpm_generate_initial_shares(size, depth, dealers, players).into()
}

pub fn wrapped_rpm_combine_shares_and_mask(
    // ms: Vec<Vec<Vec<Matrix>>> => seq^6
    ms: &Vec<Vec<Vec<Vec<Vec<Vec<u8>>>>>>,
    // rs: Vec<Vec<Vector>>      => seq^4
    rs: &Vec<Vec<Vec<Vec<u8>>>>,
    size: u64, depth: u64, dealers: u64,
) -> WrappedCombinedSharesAndMask {
    // Convert ms
    let ms_int: Vec<Vec<Vec<Matrix>>> = ms.iter()
        .map(|row| {
            row.iter()
               .map(|matset| matset.iter().map(ffi_matrix_to_internal).collect())
               .collect()
        })
        .collect();

    // Convert rs
    let rs_int: Vec<Vec<Vector>> = rs.iter()
        .map(|row| row.iter().map(ffi_vector_to_internal).collect())
        .collect();

    rpm_combine_shares_and_mask(ms_int, rs_int, size, depth, dealers).into()
}

pub fn wrapped_rpm_sketch_propose(
    // m: Vec<Vec<Matrix>> => seq^5
    m: &Vec<Vec<Vec<Vec<Vec<u8>>>>>,
    // r: Vec<Vector>      => seq^3
    r: &Vec<Vec<Vec<u8>>>,
) -> WrappedSketchProposal {
    let m_int: Vec<Vec<Matrix>> =
        m.iter().map(|row| row.iter().map(ffi_matrix_to_internal).collect()).collect();
    let r_int: Vec<Vector> =
        r.iter().map(ffi_vector_to_internal).collect();
    rpm_sketch_propose(m_int, r_int).into()
}

pub fn wrapped_rpm_sketch_verify(
    // mcs: Vec<Vec<Vec<Vec<[u8; 32]>>>> => seq^5
    mcs: &Vec<Vec<Vec<Vec<Vec<u8>>>>>,
    // rcs: Vec<Vec<[u8; 32]>>           => seq^3
    rcs: &Vec<Vec<Vec<u8>>>,
    dealers: u64,
) -> bool {
    let mcs_int: Vec<Vec<Vec<Vec<[u8; 32]>>>> = mcs.iter()
        .map(|a| a.iter()
            .map(|b| b.iter()
                .map(|c| c.iter().map(|bytes| vec32_to_arr32(bytes)).collect())
                .collect())
            .collect())
        .collect();

    let rcs_int: Vec<Vec<[u8; 32]>> = rcs.iter()
        .map(|row| row.iter().map(|bytes| vec32_to_arr32(bytes)).collect())
        .collect();

    rpm_sketch_verify(mcs_int, rcs_int, dealers)
}

pub fn wrapped_rpm_permute(
    // masked_input_shares: Vec<Vector> => seq^3
    masked_input_shares: &Vec<Vec<Vec<u8>>>,
    // mb: Vec<Vec<Matrix>>             => seq^5
    mb: &Vec<Vec<Vec<Vec<Vec<u8>>>>>,
    // rb: Vec<Vector>                  => seq^3
    rb: &Vec<Vec<Vec<u8>>>,
    // mrmb: Vec<Vec<Matrix>>           => seq^5
    mrmb: &Vec<Vec<Vec<Vec<Vec<u8>>>>>,
    depth_index: u64,
    parties: &Vec<u64>,
) -> Vec<Vec<Vec<u8>>> {
    let masked_int: Vec<Vector> = masked_input_shares.iter().map(ffi_vector_to_internal).collect();
    let mb_int: Vec<Vec<Matrix>> = mb.iter().map(|row| row.iter().map(ffi_matrix_to_internal).collect()).collect();
    let rb_int: Vec<Vector> = rb.iter().map(ffi_vector_to_internal).collect();
    let mrmb_int: Vec<Vec<Matrix>> = mrmb.iter().map(|row| row.iter().map(ffi_matrix_to_internal).collect()).collect();

    let out: Vec<Vector> = rpm_permute(masked_int, mb_int, rb_int, mrmb_int, depth_index, parties.clone());
    out.into_iter().map(internal_vector_to_ffi).collect()
}

pub fn wrapped_rpm_finalize(
    // input: Vec<Vector> => seq^3
    input: &Vec<Vec<Vec<u8>>>,
    parties: &Vec<u64>,
) -> Vec<Vec<u8>> { 
    let input_int: Vec<Vector> = input.iter().map(ffi_vector_to_internal).collect();
    let out: Vector = rpm_finalize(input_int, parties.clone());
    internal_vector_to_ffi(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_permutation_matrix() {
        let m = generate_permutation_matrix(100);
        for x in &m {
            let y_sum: u8 = x.iter().map(|y| y.to_bytes()[0]).sum();
            assert_eq!(y_sum, 0x01);
        }

        for x in 0..m.len() {
            let x_sum: u8 = (0..m.len()).map(|y| m[y][x].to_bytes()[0]).sum();
            assert_eq!(x_sum, 0x01);
        }
    }

    fn verify_lagrange(shares: &[Scalar], expected: &Scalar, total: u64, threshold: u64) {
        let mut result: Option<Scalar> = None;

        for i in 1..=(total - threshold + 1) {
            let mut reconstructed_sum = Scalar::ZERO;

            for j in 0..threshold {
                let mut coeff_num = Scalar::ONE;
                let mut coeff_denom = Scalar::ONE;

                for k in 0..threshold {
                    if j != k {
                        let ik_scalar = Scalar::from((i + k) as u64);
                        let ij_scalar = Scalar::from((i + j) as u64);

                        coeff_num *= ik_scalar;
                        coeff_denom *= ik_scalar - ij_scalar;
                    }
                }

                coeff_denom = coeff_denom.invert();
                coeff_num *= coeff_denom;
                let reconstructed_frag = coeff_num * shares[(i + j - 1) as usize];

                reconstructed_sum += reconstructed_frag;
            }

            match result {
                None => {
                    result = Some(reconstructed_sum);
                    assert_eq!(expected.to_bytes(), reconstructed_sum.to_bytes());
                }
                Some(ref r) if *r != reconstructed_sum => {
                    panic!("mismatched reconstruction");
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_generate_shamir_matrix() {
        let m = generate_permutation_matrix(100);
        let sm = shamir_split_matrix(&m, 10, 3);
        for (xi, x) in sm[0].iter().enumerate() {
            for yi in 0..x.len() {
                let y: Vec<Scalar> = (0..10).map(|i| Scalar::from_bytes_mod_order(sm[i][xi][yi])).collect();
                verify_lagrange(&y, &m[xi][yi], 10, 3);
            }
        }
    }

    #[test]
    fn test_butterfly() {
      let mut xs = vec![Scalar::ZERO; 100];

      for j in 0..100 {
          xs[j] = Scalar::from(j as u64);
      }

      let mut testxs = vec![Scalar::ZERO; 100];
      for i in 0..10 {
          for j in 0..10 {
              testxs[i*10 + j] = Scalar::from((j*10+i) as u64);
          }
      }
      let bxs = rpm_butterfly(&xs);
      let inverted = rpm_butterfly(&bxs);

      for j in 0..100 {
          assert_eq!(testxs[j].to_bytes(), bxs[j].to_bytes());
          assert_eq!(inverted[j].to_bytes(), xs[j].to_bytes());
      }
    }

    #[test]
    fn test_rpm() {
        let depth = 15 as usize;
        let players = 9 as usize;
        let dealers = 3 as usize;

        let is1 = rpm_generate_initial_shares(100, depth as u64, dealers as u64, players as u64);
        let is2 = rpm_generate_initial_shares(100, depth as u64, dealers as u64, players as u64);
        let is3 = rpm_generate_initial_shares(100, depth as u64, dealers as u64, players as u64);
        let (m1, r1) = (is1.ms, is1.rs);
        let (m2, r2) = (is2.ms, is2.rs);
        let (m3, r3) = (is3.ms, is3.rs);

        let mut ms = vec![vec![vec![vec![vec![vec![[0u8; 32]; 10]; 10]; 10]; depth]; dealers]; players];
        let mut rs = vec![vec![vec![vec![[0u8; 32]; 100]; depth]; dealers]; players];

        let mut mc = Vec::<Vec<Vec<Vec<Vec<[u8; 32]>>>>>::with_capacity(players);
        let mut rc = Vec::<Vec<Vec<[u8; 32]>>>::with_capacity(players);
        let mut mrmc = Vec::<Vec<Vec<Vec<Vec<[u8; 32]>>>>>::with_capacity(players);
        let mut mccs = Vec::<Vec<Vec<Vec<[u8; 32]>>>>::with_capacity(players);
        let mut rccs = Vec::<Vec<[u8; 32]>>::with_capacity(players);
        for i in 0..players {
            for j in 0..depth {
                for k in 0..10 {
                    ms[i][0][j][k] = m1[j][k][i].clone();
                    ms[i][1][j][k] = m2[j][k][i].clone();
                    ms[i][2][j][k] = m3[j][k][i].clone();
                }

                rs[i][0][j] = r1[j][i].clone();
                rs[i][1][j] = r2[j][i].clone();
                rs[i][2][j] = r3[j][i].clone();
            }
            let cs = rpm_combine_shares_and_mask(ms[i].clone(), rs[i].clone(), 100, depth as u64, dealers as u64);
            let (m, r, mrm) = (cs.ms, cs.rs, cs.mrms);
            let sp = rpm_sketch_propose(m.clone(), r.clone());
            let (mcc, rcc) = (sp.mp, sp.rp);
            mc.push(m);
            rc.push(r);
            mrmc.push(mrm);
            mccs.push(mcc);
            rccs.push(rcc);
        }

        assert!(rpm_sketch_verify(mccs, rccs, dealers as u64));

        let mut xs = vec![vec![[0u8; 32]; 100]; players];

        for i in 0..100 {
            let xsi = gen_poly_frags(&Scalar::from(i as u64), 9, 3);
            for j in 0..9 {
                xs[j][i] = (Scalar::from_bytes_mod_order(xsi[j]) + Scalar::from_bytes_mod_order(rc[j][0][i])).to_bytes();
            }
        }

        for d in 0..depth {
            let mut ys = vec![vec![[0u8; 32]; 100]; 9];
            for i in 0..players {
                let out = rpm_permute(xs.clone(), mc[i].clone(), rc[i].clone(), mrmc[i].clone(), d as u64, vec![1,2,3,4,5,6,7,8,9]);
                ys[i] = out[0].clone();
            }

            xs = ys;
            let mut result  = Vec::<Scalar>::with_capacity(100);
            for j in 0..100 {
                let mut r = Vec::<Scalar>::with_capacity(9);
                for k in 0..9 {
                    r.push(Scalar::from_bytes_mod_order(xs[k][j]));
                }
                result.push(interpolate_polynomial_shares(&r, &vec![1, 2, 3, 4, 5, 6, 7, 8, 9]));
            }

            if d == depth-1 {
                let mut bset = Vec::<u8>::with_capacity(100);
                for (_yi, y) in result.iter().enumerate() {
                    bset.push(y.to_bytes()[0]);
                }
                bset.sort();
                for i in 0u8..100u8 {
                    assert_eq!(bset[i as usize], i)
                }
            }
        }
    }

    // just generates all ones
    fn generate_malicious_permutation_matrix(size: u64) -> Vec<Vec<Scalar>> {
        let mut matrix = Vec::with_capacity(size as usize);
    
        for _ in 0..size {
            let vector = vec![Scalar::ONE; size as usize];
    
            matrix.push(vector);
        }
    
        matrix
    }

    fn rpm_generate_malicious_shares(size: u64, depth: u64, dealers: u64, players: u64) -> (Vec<Vec<SecretSharedMatrix>>, Vec<SecretSharedVector>) {
      if players < dealers*dealers {
        assert!(false, "players must be at greater than or equal to dealers^2");
      }
  
      let k = sqrt(size);
  
      let mut permutation_matrices_shares = Vec::<Vec<Vec<Vec<Vec<[u8; 32]>>>>>::with_capacity(depth as usize);
      let mut random_shares = Vec::<Vec<Vec<[u8; 32]>>>::with_capacity(depth as usize);
      for _i in 0..depth {
          let mut share_set = Vec::<Vec<Vec<Vec<[u8; 32]>>>>::with_capacity(k as usize);
          for _j in 0..k {
              let matrix = generate_malicious_permutation_matrix(k);
              share_set.push(shamir_split_matrix(&matrix, players, dealers));
          }
          permutation_matrices_shares.push(share_set);
      }
  
      for _i in 0..depth {
          random_shares.push(generate_random_vector_shares(size, players, dealers));
      }
  
      (permutation_matrices_shares, random_shares)
    }

    #[test]
    fn malicious_matrix_rpm() {
        let depth = 15 as usize;
        let players = 9 as usize;
        let dealers = 3 as usize;

        let (m1, r1) = rpm_generate_malicious_shares(100, depth as u64, dealers as u64, players as u64);
        let is2 = rpm_generate_initial_shares(100, depth as u64, dealers as u64, players as u64);
        let is3 = rpm_generate_initial_shares(100, depth as u64, dealers as u64, players as u64);
        let (m2, r2) = (is2.ms, is2.rs);
        let (m3, r3) = (is3.ms, is3.rs);

        let mut ms = vec![vec![vec![vec![vec![vec![[0u8; 32]; 10]; 10]; 10]; depth]; dealers]; players];
        let mut rs = vec![vec![vec![vec![[0u8; 32]; 100]; depth]; dealers]; players];

        let mut mccs = Vec::<Vec<Vec<Vec<[u8; 32]>>>>::with_capacity(players);
        let mut rccs = Vec::<Vec<[u8; 32]>>::with_capacity(players);
        for i in 0..players {
            for j in 0..depth {
                for k in 0..10 {
                    ms[i][0][j][k] = m1[j][k][i].clone();
                    ms[i][1][j][k] = m2[j][k][i].clone();
                    ms[i][2][j][k] = m3[j][k][i].clone();
                }

                rs[i][0][j] = r1[j][i].clone();
                rs[i][1][j] = r2[j][i].clone();
                rs[i][2][j] = r3[j][i].clone();
            }
            let cs = rpm_combine_shares_and_mask(ms[i].clone(), rs[i].clone(), 100, depth as u64, dealers as u64);
            let (m, r) = (cs.ms, cs.rs);
            let sp = rpm_sketch_propose(m.clone(), r.clone());
            let (mcc, rcc) = (sp.mp, sp.rp);

            mccs.push(mcc);
            rccs.push(rcc);
        }

        assert!(!rpm_sketch_verify(mccs, rccs, dealers as u64));
    }

    #[test]
    fn malicious_mask_rpm() {
        let depth = 15 as usize;
        let players = 9 as usize;
        let dealers = 3 as usize;

        let is1 = rpm_generate_initial_shares(100, depth as u64, dealers as u64, players as u64);
        let (m1, mut r1) = (is1.ms, is1.rs);
        // set all random secret shares for the first depth for player 7 to zero:
        r1[0][6][0] = Scalar::ZERO.to_bytes();
        r1[0][6][1] = Scalar::ZERO.to_bytes();
        r1[0][6][2] = Scalar::ZERO.to_bytes();
        r1[0][6][3] = Scalar::ZERO.to_bytes();
        r1[0][6][4] = Scalar::ZERO.to_bytes();
        r1[0][6][5] = Scalar::ZERO.to_bytes();
        r1[0][6][6] = Scalar::ZERO.to_bytes();
        r1[0][6][7] = Scalar::ZERO.to_bytes();
        r1[0][6][8] = Scalar::ZERO.to_bytes();
        let is2 = rpm_generate_initial_shares(100, depth as u64, dealers as u64, players as u64);
        let is3 = rpm_generate_initial_shares(100, depth as u64, dealers as u64, players as u64);
        let (m2, r2) = (is2.ms, is2.rs);
        let (m3, r3) = (is3.ms, is3.rs);

        let mut ms = vec![vec![vec![vec![vec![vec![[0u8; 32]; 10]; 10]; 10]; depth]; dealers]; players];
        let mut rs = vec![vec![vec![vec![[0u8; 32]; 100]; depth]; dealers]; players];

        let mut mccs = Vec::<Vec<Vec<Vec<[u8; 32]>>>>::with_capacity(players);
        let mut rccs = Vec::<Vec<[u8; 32]>>::with_capacity(players);
        for i in 0..players {
            for j in 0..depth {
                for k in 0..10 {
                    ms[i][0][j][k] = m1[j][k][i].clone();
                    ms[i][1][j][k] = m2[j][k][i].clone();
                    ms[i][2][j][k] = m3[j][k][i].clone();
                }

                rs[i][0][j] = r1[j][i].clone();
                rs[i][1][j] = r2[j][i].clone();
                rs[i][2][j] = r3[j][i].clone();
            }
            let cs = rpm_combine_shares_and_mask(ms[i].clone(), rs[i].clone(), 100, depth as u64, dealers as u64);
            let (m, r) = (cs.ms, cs.rs);
            let sp = rpm_sketch_propose(m.clone(), r.clone());
            let (mcc, rcc) = (sp.mp, sp.rp);

            mccs.push(mcc);
            rccs.push(rcc);
        }

        assert!(!rpm_sketch_verify(mccs, rccs, dealers as u64));
    }

    #[test]
    fn test_matrix_dot_product() {
        let zero = Scalar::ZERO;
        let one = Scalar::ONE;
        let two = Scalar::from(2u64);
        let three = Scalar::from(3u64);
        let four = Scalar::from(4u64);

        let a_matrix = vec![
            vec![two, two],
            vec![zero, three],
            vec![zero, four],
        ];
        let b_matrix = vec![
            vec![two, one, two],
            vec![three, two, four],
        ];

        let ab_matrix = generate_dot_product(&a_matrix, &b_matrix);
        assert_eq!(ab_matrix[0][0].to_bytes()[0], 0x0a);
        assert_eq!(ab_matrix[0][1].to_bytes()[0], 0x06);
        assert_eq!(ab_matrix[0][2].to_bytes()[0], 0x0c);
        assert_eq!(ab_matrix[1][0].to_bytes()[0], 0x09);
        assert_eq!(ab_matrix[1][1].to_bytes()[0], 0x06);
        assert_eq!(ab_matrix[1][2].to_bytes()[0], 0x0c);
        assert_eq!(ab_matrix[2][0].to_bytes()[0], 0x0c);
        assert_eq!(ab_matrix[2][1].to_bytes()[0], 0x08);
        assert_eq!(ab_matrix[2][2].to_bytes()[0], 0x10);
    }

    #[test]
    fn test_shamir() {
        let f = gen_poly_frags(&Scalar::ONE, 10, 3);
        let g = interpolate_polynomial_shares(&f.into_iter().map(|s| Scalar::from_bytes_mod_order(s)).collect::<Vec<_>>(), &[1, 2, 3]);
        assert_eq!(Scalar::ONE.to_bytes(), g.to_bytes())
    }

    #[test]
    fn test_generate_random_beaver_triple_matrix_shares() {
        let beaver_triple_shares = generate_random_beaver_triple_matrix_shares(100, 1, 10, 3);

        let u_matrix_shares = &beaver_triple_shares.2;
        let v_matrix_shares = &beaver_triple_shares.3;
        let uv_matrix_shares = &beaver_triple_shares.4;

        let u_matrix = interpolate_matrix_shares(u_matrix_shares, &[1, 2, 3]);
        let v_matrix = interpolate_matrix_shares(v_matrix_shares, &[1, 2, 3]);
        let uv_matrix = interpolate_matrix_shares(uv_matrix_shares, &[1, 2, 3]);

        let uv_check = generate_dot_product(&u_matrix, &v_matrix);
        assert_eq!(uv_matrix, uv_check);
    }

    #[test]
    fn test_permutation_matrix() {
        let permutation_matrix1 = generate_permutation_matrix(100);
        let permutation_matrix2 = generate_permutation_matrix(100);
        let permutation_matrix3 = generate_permutation_matrix(100);
        let permutation_matrix4 = generate_permutation_matrix(100);

        let mut permutation_matrix = generate_dot_product(&permutation_matrix1, &permutation_matrix2);
        permutation_matrix = generate_dot_product(&permutation_matrix, &permutation_matrix3);
        permutation_matrix = generate_dot_product(&permutation_matrix, &permutation_matrix4);

        let one = Scalar::ONE;
        for x in 0..100 {
            let sum_x: Scalar = permutation_matrix[x].iter().sum();
            assert_eq!(sum_x, one);
        }

        for y in 0..100 {
            let sum_y: Scalar = (0..100).map(|x| permutation_matrix[x][y]).sum();
            assert_eq!(sum_y, one);
        }
    }
}

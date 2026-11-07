//! Portable reference commitment arithmetic and public key expansion.
//! This is not a hiding commitment by itself: the complete proof construction
//! must supply the required masking, parameter bounds and transcript binding.
use super::{expansion::CounterExpander, transcript::REFERENCE_POLYNOMIAL_BYTES, *};

#[derive(Debug, PartialEq, Eq)]
pub enum CommitmentError {
    Rank,
    Length,
    Allocation,
    NonceExhausted,
    Expansion,
}

/// Coefficient-space equivalent of polxvec_almostuniform. This is deliberately
/// NOT exact uniform sampling: 38-bit packed values are reduced modulo p.
/// Stream nonces advance by 2^32 every 32 polynomials, as in the pinned source.
pub fn reference_almost_uniform(
    seed: &[u8; 32],
    nonce: u64,
    count: usize,
) -> Result<Vec<ProofPolynomial>, CommitmentError> {
    let groups = count.div_ceil(32);
    if groups > 0 {
        let last = u64::try_from(groups - 1).map_err(|_| CommitmentError::NonceExhausted)?;
        nonce
            .checked_add(
                last.checked_mul(1u64 << 32)
                    .ok_or(CommitmentError::NonceExhausted)?,
            )
            .ok_or(CommitmentError::NonceExhausted)?;
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| CommitmentError::Allocation)?;
    while output.len() < count {
        let group = output.len() / 32;
        let take = (count - output.len()).min(32);
        let mut stream = CounterExpander::aes256(seed, nonce + ((group as u64) << 32));
        let length = (take * REFERENCE_POLYNOMIAL_BYTES).div_ceil(512) * 512;
        let mut bytes = Zeroizing::new(vec![0; length]);
        stream
            .squeeze(&mut bytes)
            .map_err(|_| CommitmentError::Expansion)?;
        // Full groups of 8 polynomials consume exactly 19 AES squeeze blocks,
        // so one rounded read is equivalent to the source's inner chunking.
        for packed in
            bytes[..take * REFERENCE_POLYNOMIAL_BYTES].chunks_exact(REFERENCE_POLYNOMIAL_BYTES)
        {
            let mut coefficients = ProofPolynomial::unpack_reference_raw(packed)
                .map_err(|_| CommitmentError::Length)?;
            for coefficient in coefficients.iter_mut() {
                *coefficient %= MODULUS;
            }
            output.push(ProofPolynomial(coefficients));
        }
    }
    Ok(output)
}

fn times_x(value: &ProofPolynomial) -> ProofPolynomial {
    let mut result = Zeroizing::new(vec![0; DEGREE]);
    result[0] = (MODULUS - value.0[DEGREE - 1]) % MODULUS;
    result[1..].copy_from_slice(&value.0[..DEGREE - 1]);
    ProofPolynomial(result)
}

/// Sum block products in R_p[Y]/(Y^d-X), d=next_power_of_two(rank), retaining
/// the first `rank` extension coefficients. Final witness blocks are padded
/// with zeros. This implements the coefficient-space reference operation,
/// without CRT/NTT representation or native variance bookkeeping.
pub fn extension_product_sum(
    key: &[ProofPolynomial],
    witness: &[ProofPolynomial],
    rank: usize,
) -> Result<Vec<ProofPolynomial>, CommitmentError> {
    if rank == 0 || rank > 32 {
        return Err(CommitmentError::Rank);
    }
    let degree = rank.next_power_of_two();
    let padded = witness
        .len()
        .checked_add(degree - 1)
        .ok_or(CommitmentError::Length)?
        / degree
        * degree;
    if key.len() < padded {
        return Err(CommitmentError::Length);
    }
    let mut output: Vec<_> = (0..rank)
        .map(|_| ProofPolynomial(Zeroizing::new(vec![0; DEGREE])))
        .collect();
    for start in (0..witness.len()).step_by(degree) {
        let count = (witness.len() - start).min(degree);
        for i in 0..degree {
            for j in 0..count {
                let index = (i + j) % degree;
                if index >= rank {
                    continue;
                }
                let product = key[start + i].mul(&witness[start + j]);
                let product = if i + j >= degree {
                    times_x(&product)
                } else {
                    product
                };
                output[index] = output[index].add(&product);
            }
        }
    }
    Ok(output)
}

/// Transpose the extension-product rotation matrix against polynomial
/// challenges. The result has one coefficient per witness polynomial, such
/// that sum(result_i*w_i) = sum(challenge_j*extension_product_j).
pub fn aggregate_extension_rows(
    key: &[ProofPolynomial],
    challenges: &[ProofPolynomial],
    witness_count: usize,
) -> Result<Vec<ProofPolynomial>, CommitmentError> {
    let rank = challenges.len();
    if rank == 0 || rank > 32 {
        return Err(CommitmentError::Rank);
    }
    let degree = rank.next_power_of_two();
    let padded = witness_count
        .checked_add(degree - 1)
        .ok_or(CommitmentError::Length)?
        / degree
        * degree;
    if key.len() < padded {
        return Err(CommitmentError::Length);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(witness_count)
        .map_err(|_| CommitmentError::Allocation)?;
    for start in (0..witness_count).step_by(degree) {
        for col in 0..(witness_count - start).min(degree) {
            let mut coefficient = ProofPolynomial(Zeroizing::new(vec![0; DEGREE]));
            for (row, challenge) in challenges.iter().enumerate() {
                let index = (degree + row - col) % degree;
                let product = challenge.mul(&key[start + index]);
                let product = if col > row {
                    times_x(&product)
                } else {
                    product
                };
                coefficient = coefficient.add(&product);
            }
            output.push(coefficient);
        }
    }
    Ok(output)
}

/// Per-instance reproduction of the reference comkey growth schedule. Key
/// material depends on the sequence of expansion requests, not just final size.
/// A production protocol must fix that schedule and its parameter/context binding.
#[derive(Default)]
pub struct ReferenceCommitmentKey {
    polynomials: Vec<ProofPolynomial>,
    next_nonce: u64,
}
impl ReferenceCommitmentKey {
    pub fn ensure(&mut self, count: usize) -> Result<(), CommitmentError> {
        if self.next_nonce != 0 && self.polynomials.len() >= count {
            return Ok(());
        }
        let target = count.checked_add(31).ok_or(CommitmentError::Length)? / 32 * 32;
        let next_nonce = self
            .next_nonce
            .checked_add(1)
            .ok_or(CommitmentError::NonceExhausted)?;
        let additional = target - self.polynomials.len();
        self.polynomials
            .try_reserve_exact(additional)
            .map_err(|_| CommitmentError::Allocation)?;
        let new = reference_almost_uniform(&[0; 32], self.next_nonce, additional)?;
        self.polynomials.extend(new);
        self.next_nonce = next_nonce;
        Ok(())
    }
    pub fn commit(
        &self,
        witness: &[ProofPolynomial],
        rank: usize,
    ) -> Result<Vec<ProofPolynomial>, CommitmentError> {
        extension_product_sum(&self.polynomials, witness, rank)
    }
    pub fn len(&self) -> usize {
        self.polynomials.len()
    }
    pub fn is_empty(&self) -> bool {
        self.polynomials.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_expansion_matches_independent_openssl_lane_reference() {
        use sha2::{Digest, Sha256};
        let seed = std::array::from_fn(|i| i as u8);
        let polynomials = reference_almost_uniform(&seed, 0x0102030405060708, 33).unwrap();
        let mut hash = Sha256::new();
        for coefficient in polynomials.iter().flat_map(|p| p.0.iter()) {
            Digest::update(&mut hash, coefficient.to_le_bytes());
        }
        let digest = hash
            .finalize()
            .iter()
            .map(|v| format!("{v:02x}"))
            .collect::<String>();
        assert_eq!(
            digest,
            "74dee75cef90f739e54568d12aea0ca359dc2fa67f213df15a6aa7119864f5c7"
        );
    }

    #[test]
    fn extension_product_matches_independent_flat_negacyclic_convolution() {
        let rank = 3;
        let degree = 4;
        let key: Vec<_> = (0..8)
            .map(|i| {
                let mut p = vec![0i64; DEGREE];
                for j in 0..4 {
                    p[j] = (i * 7 + j * 11 + 1) as i64;
                }
                ProofPolynomial::from_signed(&p).unwrap()
            })
            .collect();
        let witness: Vec<_> = (0..5)
            .map(|i| {
                let mut p = vec![0i64; DEGREE];
                p[0] = i as i64 - 2;
                p[DEGREE - 1] = 1;
                ProofPolynomial::from_signed(&p).unwrap()
            })
            .collect();
        let output = extension_product_sum(&key, &witness, rank).unwrap();
        let n = DEGREE * degree;
        let mut expected = vec![0i128; n];
        for start in [0, 4] {
            for i in 0..degree {
                for j in 0..(witness.len() - start).min(degree) {
                    for (a, &x) in key[start + i].0.iter().enumerate() {
                        if x == 0 {
                            continue;
                        }
                        for (b, &y) in witness[start + j].0.iter().enumerate() {
                            let index = (a + b) * degree + i + j;
                            expected[index % n] +=
                                if index < n { 1 } else { -1 } * i128::from(x) * i128::from(y);
                        }
                    }
                }
            }
        }
        for i in 0..rank {
            for j in 0..DEGREE {
                assert_eq!(
                    output[i].0[j],
                    expected[j * degree + i].rem_euclid(i128::from(MODULUS)) as u64
                );
            }
        }
        assert!(matches!(
            extension_product_sum(&key[..4], &witness, rank),
            Err(CommitmentError::Length)
        ));
        assert!(matches!(
            extension_product_sum(&key, &witness, 0),
            Err(CommitmentError::Rank)
        ));
    }

    #[test]
    fn reference_key_growth_preserves_prefix_and_exposes_schedule_dependence() {
        let mut grown = ReferenceCommitmentKey::default();
        grown.ensure(1).unwrap();
        assert_eq!(grown.len(), 32);
        let first = grown.polynomials[0].reference_bitpack();
        grown.ensure(32).unwrap();
        assert_eq!(grown.next_nonce, 1);
        grown.ensure(33).unwrap();
        assert_eq!(grown.len(), 64);
        assert_eq!(first, grown.polynomials[0].reference_bitpack());
        let mut single = ReferenceCommitmentKey::default();
        single.ensure(64).unwrap();
        assert_eq!(first, single.polynomials[0].reference_bitpack());
        assert_ne!(*grown.polynomials[32].0, *single.polynomials[32].0);
        assert!(matches!(
            reference_almost_uniform(&[0; 32], u64::MAX, 33),
            Err(CommitmentError::NonceExhausted)
        ));
    }
}

//! Portable arithmetic foundation for a proof-backend reimplementation.
//! Ring degree/modulus match pinned labrados data.h (N=256, LOGQ=38, QOFF=107).
//! This is an integer reference and private-assignment checker, NOT a ZK proof
//! system, wire codec, parameter certificate, or constant-time implementation.
use super::*;
use submission::{RelationSink, SubmissionCounts};
use zeroize::Zeroizing;

pub mod challenge;
pub mod commitment;
pub mod constraints;
pub mod expansion;
pub mod gaussian;
pub mod gaussian_exact;
pub mod gaussian_projection;
pub mod lnp_projection;
pub mod projection;
pub mod rejection;
pub mod transcript;
pub mod uniform;

pub const DEGREE: usize = 256;
pub const MODULUS: u64 = PROOF_MODULUS as u64;

/// Canonical residues in Z_p[X]/(X^256+1). Distinct from the amount ring type.
/// No Debug/serialization implementation: arithmetic values can be private.
pub struct ProofPolynomial(Zeroizing<Vec<u64>>);

impl ProofPolynomial {
    pub fn from_signed(coefficients: &[i64]) -> Option<Self> {
        (coefficients.len() == DEGREE).then(|| {
            Self(Zeroizing::new(
                coefficients
                    .iter()
                    .map(|&v| i128::from(v).rem_euclid(PROOF_MODULUS) as u64)
                    .collect(),
            ))
        })
    }

    pub fn add(&self, rhs: &Self) -> Self {
        Self(Zeroizing::new(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&a, &b)| (a + b) % MODULUS)
                .collect(),
        ))
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        Self(Zeroizing::new(
            self.0
                .iter()
                .zip(rhs.0.iter())
                .map(|(&a, &b)| (a + MODULUS - b) % MODULUS)
                .collect(),
        ))
    }

    /// Schoolbook reference: each accumulator is bounded by 256*(p-1)^2,
    /// below 2^84, so i128 is sufficient even for dense full-width inputs.
    pub fn mul(&self, rhs: &Self) -> Self {
        let mut product = Zeroizing::new(vec![0i128; DEGREE]);
        for (i, &a) in self.0.iter().enumerate() {
            for (j, &b) in rhs.0.iter().enumerate() {
                let k = i + j;
                product[k % DEGREE] +=
                    if k < DEGREE { 1 } else { -1 } * i128::from(a) * i128::from(b);
            }
        }
        Self(Zeroizing::new(
            product
                .iter()
                .map(|v| v.rem_euclid(PROOF_MODULUS) as u64)
                .collect(),
        ))
    }

    /// Involution X -> X^-1: constant fixed, reversed remaining coefficients negated.
    pub fn conjugate(&self) -> Self {
        let mut result = Zeroizing::new(vec![0; DEGREE]);
        result[0] = self.0[0];
        for i in 1..DEGREE {
            result[i] = (MODULUS - self.0[DEGREE - i]) % MODULUS;
        }
        Self(result)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CheckError {
    State,
    Domain,
    Shape,
    Equation,
    Counts,
}

/// Receives private assignments and evaluates every submitted row modulo p.
/// This is the first portable backend layer; it has no proof generation API.
#[derive(Default)]
pub struct PortableWitnessChecker {
    /// Binary and short witnesses in one global index space, as integers.
    binary: Zeroizing<Vec<Vec<i64>>>,
    short_normsq: Vec<u64>,
    expected: Option<SubmissionCounts>,
    rows: [usize; 3],
    finished: bool,
}

impl PortableWitnessChecker {
    fn active(&self) -> Result<SubmissionCounts, CheckError> {
        if self.finished {
            return Err(CheckError::State);
        }
        self.expected.ok_or(CheckError::State)
    }
    fn bit_poly(&self, index: usize) -> Result<&[i64], CheckError> {
        self.binary
            .get(index)
            .map(|p| p.as_slice())
            .ok_or(CheckError::Shape)
    }
}

impl RelationSink for PortableWitnessChecker {
    type Error = CheckError;
    fn begin(
        &mut self,
        modulus: i128,
        degree: usize,
        counts: SubmissionCounts,
        short_normsq: &[u64],
    ) -> Result<(), CheckError> {
        if self.expected.is_some() || self.finished {
            return Err(CheckError::State);
        }
        if modulus != PROOF_MODULUS || degree != DEGREE {
            return Err(CheckError::Shape);
        }
        counts
            .original_binary_polynomials
            .checked_add(counts.auxiliary_binary_polynomials)
            .and_then(|n| n.checked_add(counts.short_polynomials))
            .ok_or(CheckError::Counts)?;
        if short_normsq.len() != counts.short_polynomials {
            return Err(CheckError::Counts);
        }
        self.short_normsq = short_normsq.to_vec();
        self.expected = Some(counts);
        Ok(())
    }
    fn binary(&mut self, index: usize, values: &[u8]) -> Result<(), CheckError> {
        let expected = self.active()?;
        if index != self.binary.len()
            || index >= expected.original_binary_polynomials + expected.auxiliary_binary_polynomials
        {
            return Err(CheckError::Counts);
        }
        if values.len() != DEGREE || values.iter().any(|&v| v > 1) {
            return Err(CheckError::Domain);
        }
        self.binary.push(values.iter().map(|&v| i64::from(v)).collect());
        Ok(())
    }
    fn short(&mut self, index: usize, values: &[i64]) -> Result<(), CheckError> {
        let expected = self.active()?;
        let binary = expected.original_binary_polynomials + expected.auxiliary_binary_polynomials;
        if index != self.binary.len() || index < binary || index >= binary + expected.short_polynomials {
            return Err(CheckError::Counts);
        }
        let normsq = values.iter().try_fold(0u128, |s, &v| s.checked_add((i128::from(v) * i128::from(v)) as u128));
        if values.len() != DEGREE || normsq.is_none_or(|n| n > u128::from(self.short_normsq[index - binary])) {
            return Err(CheckError::Domain);
        }
        self.binary.push(values.to_vec());
        Ok(())
    }
    fn scalar(&mut self, row: ScalarRow<'_>) -> Result<(), CheckError> {
        if self.rows[0] >= self.active()?.scalar_equations {
            return Err(CheckError::Counts);
        }
        let mut result = -i128::from(row.rhs);
        for &(coefficient, polynomial, index) in row.terms {
            let value = self
                .bit_poly(polynomial)?
                .get(index)
                .ok_or(CheckError::Shape)?;
            result =
                (result + i128::from(coefficient) * i128::from(*value)).rem_euclid(PROOF_MODULUS);
        }
        if result.rem_euclid(PROOF_MODULUS) != 0 {
            return Err(CheckError::Equation);
        }
        self.rows[0] += 1;
        Ok(())
    }
    fn linear(&mut self, terms: &[(Vec<i64>, usize)], rhs: &[i64]) -> Result<(), CheckError> {
        if self.rows[1] >= self.active()?.linear_equations {
            return Err(CheckError::Counts);
        }
        if rhs.len() != DEGREE {
            return Err(CheckError::Shape);
        }
        let mut residual = Zeroizing::new(rhs.iter().map(|&v| -i128::from(v)).collect::<Vec<_>>());
        for (coefficients, index) in terms {
            if coefficients.len() != DEGREE {
                return Err(CheckError::Shape);
            }
            let bits = self.bit_poly(*index)?;
            for (i, &a) in coefficients.iter().enumerate() {
                if a == 0 {
                    continue;
                } // Public coefficient only.
                for (j, &b) in bits.iter().enumerate() {
                    let k = i + j;
                    residual[k % DEGREE] +=
                        if k < DEGREE { 1 } else { -1 } * i128::from(a) * i128::from(b);
                }
            }
            for value in residual.iter_mut() {
                *value = value.rem_euclid(PROOF_MODULUS);
            }
        }
        if residual.iter().any(|v| v.rem_euclid(PROOF_MODULUS) != 0) {
            return Err(CheckError::Equation);
        }
        self.rows[1] += 1;
        Ok(())
    }
    fn selection(&mut self, row: SelectionRow) -> Result<(), CheckError> {
        if self.rows[2] >= self.active()?.selection_equations {
            return Err(CheckError::Counts);
        }
        let selector = self.bit_poly(row.selector)?;
        if selector[1..].iter().any(|&v| v != 0) || selector[0] > 1 || row.terms.is_empty() {
            return Err(CheckError::Domain);
        }
        let s = i128::from(selector[0]);
        let mut residual = vec![0i128; DEGREE];
        for &(w, z, o, sel) in &row.terms {
            let (zero, one, selected) = (self.bit_poly(z)?, self.bit_poly(o)?, self.bit_poly(sel)?);
            for i in 0..DEGREE {
                residual[i] += i128::from(w)
                    * (s * (i128::from(one[i]) - i128::from(zero[i])) + i128::from(zero[i]) - i128::from(selected[i]));
            }
        }
        if residual.iter().any(|v| v.rem_euclid(PROOF_MODULUS) != 0) {
            return Err(CheckError::Equation);
        }
        self.rows[2] += 1;
        Ok(())
    }
    fn finish(&mut self, counts: SubmissionCounts) -> Result<(), CheckError> {
        if counts != self.active()?
            || self.binary.len()
                != counts.original_binary_polynomials + counts.auxiliary_binary_polynomials + counts.short_polynomials
            || self.rows
                != [
                    counts.scalar_equations,
                    counts.linear_equations,
                    counts.selection_equations,
                ]
        {
            return Err(CheckError::Counts);
        }
        self.finished = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "native-proof")]
    #[test]
    fn private_aes256_native_streams_match_portable_references() {
        use super::{expansion::CounterExpander, gaussian, uniform, rejection::{self, RejectionKind, RejectionParameters}};
        use quil_lattice_proof_sys::{ffi, NATIVE_STATE};
        let _guard = NATIVE_STATE.lock().unwrap();
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let mut other = key; other[31] ^= 128;
        let nonce = 0x0102030405060708;
        let mut previous_bytes = None;
        for seed in [key, other] {
            let mut actual = [0; 1024];
            assert_eq!(unsafe { ffi::quil_fixture_private_stream(seed.as_ptr(), nonce, 2, actual.as_mut_ptr()) }, 0);
            let mut expected = [0; 1024];
            CounterExpander::aes256(&seed, nonce).squeeze(&mut expected).unwrap();
            assert_eq!(actual, expected);
            if let Some(previous) = previous_bytes { assert_ne!(actual, previous); }
            previous_bytes = Some(actual);
            for count in 1..=8 {
                for mode in [0, 1] {
                    let mut actual = vec![0i64; 256 * count];
                    assert_eq!(unsafe { ffi::quil_fixture_sample_prg(seed.as_ptr(), nonce, count, 0, mode, actual.as_mut_ptr()) }, 0);
                    let expected = if mode == 0 {
                        uniform::uniform_polynomials(&seed, nonce, count).unwrap()
                    } else {
                        uniform::uniform_polynomials_private(&seed, nonce, count).unwrap()
                    };
                    let coefficients: Vec<_> = expected.iter().flat_map(|p| p.0.iter().map(|&x| x as i64)).collect();
                    let mismatch = actual.iter().zip(&coefficients).enumerate()
                        .find(|(_, (actual, expected))| actual != expected);
                    assert!(mismatch.is_none(), "uniform mode={mode} count={count}: first mismatch {mismatch:?}");
                }
            }
            for scale in [0, 4, 12, 20, 26] {
                for mode in [2, 3] {
                    let mut actual = vec![0i64; 256];
                    assert_eq!(unsafe { ffi::quil_fixture_sample_prg(seed.as_ptr(), nonce, 1, scale, mode, actual.as_mut_ptr()) }, 0);
                    let mut stream = CounterExpander::aes256(&seed, nonce);
                    let expected = gaussian::gaussian_i32(&mut stream, 256, scale).unwrap();
                    assert_eq!(actual, expected.iter().map(|&x| i64::from(x)).collect::<Vec<_>>(), "Gaussian mode={mode} scale={scale}");
                }
            }
            for (kind, mode) in [(RejectionKind::Standard, 0), (RejectionKind::SignFiltered, 1), (RejectionKind::Bimodal, 2)] {
                for (zv, vv, variance) in [
                    (-3, 4, 8.0), (0, 4, 8.0), (3, 4, 8.0),
                    (i64::MIN, i64::MAX, 2.0f64.powi(63)),
                    (i64::MAX, i64::MAX, 2.0f64.powi(63)),
                    (i64::MIN, 0, 2.0f64.powi(63)),
                    (i64::MAX, 0, 2.0f64.powi(63)),
                ] {
                    let mut stream = CounterExpander::aes256(&seed, nonce);
                    let params = RejectionParameters::from_binary64(variance, 2.0).unwrap();
                    let expected = rejection::sample_decision(&mut stream, kind, zv, vv, &params).unwrap();
                    assert_eq!(unsafe { ffi::quil_fixture_private_rejection(seed.as_ptr(), nonce, mode, zv, vv, variance, 2.0) }, i32::from(expected));
                }
            }
        }
    }

    use super::*;

    #[test]
    fn full_width_multiplication_matches_independent_integer_vector() {
        use sha2::{Digest, Sha256};
        let a: Vec<_> = (0..DEGREE as u64)
            .map(|i| ((i.pow(3) * 104729 + MODULUS - 1 - i * 19) % MODULUS) as i64)
            .collect();
        let b: Vec<_> = (0..DEGREE as u64)
            .map(|i| (((i + 7).pow(5) * 65537 + i * 37) % MODULUS) as i64)
            .collect();
        let result = ProofPolynomial::from_signed(&a)
            .unwrap()
            .mul(&ProofPolynomial::from_signed(&b).unwrap());
        let mut hash = Sha256::new();
        for &value in result.0.iter() {
            Digest::update(&mut hash, value.to_le_bytes());
        }
        let digest = hash
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            digest,
            "b0321ab2428cff3955ef5fd45ae8dfad0c3bd0e8729de3491e1975a87e918bd0"
        );
    }

    #[test]
    fn proof_ring_negacyclic_and_conjugation_identities() {
        let mut x = vec![0; DEGREE];
        x[1] = 1;
        let x = ProofPolynomial::from_signed(&x).unwrap();
        let mut last = vec![0; DEGREE];
        last[DEGREE - 1] = 1;
        let last = ProofPolynomial::from_signed(&last).unwrap();
        let result = x.mul(&last);
        assert_eq!(result.0[0], MODULUS - 1);
        assert!(result.0[1..].iter().all(|&v| v == 0));
        let a = ProofPolynomial::from_signed(
            &(0..DEGREE)
                .map(|i| i as i64 * 137 - 2000)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(*a.conjugate().conjugate().0, *a.0);
        assert_eq!(
            *a.mul(&x).conjugate().0,
            *a.conjugate().mul(&x.conjugate()).0
        );
        assert_eq!(*a.add(&x).sub(&x).0, *a.0);
    }

    #[test]
    fn portable_checker_rejects_changed_rows_and_nonbinary_witnesses() {
        let counts = SubmissionCounts {
            original_binary_polynomials: 1,
            scalar_equations: 1,
            ..Default::default()
        };
        let mut checker = PortableWitnessChecker::default();
        checker.begin(PROOF_MODULUS, DEGREE, counts, &[]).unwrap();
        assert_eq!(checker.binary(0, &[2; DEGREE]), Err(CheckError::Domain));
        checker.binary(0, &[1; DEGREE]).unwrap();
        assert_eq!(
            checker.scalar(ScalarRow {
                terms: &[(1, 0, 0)],
                rhs: 0
            }),
            Err(CheckError::Equation)
        );
        checker
            .scalar(ScalarRow {
                terms: &[(1, 0, 0)],
                rhs: 1,
            })
            .unwrap();
        checker.finish(counts).unwrap();
        assert_eq!(checker.finish(counts), Err(CheckError::State));
    }
}

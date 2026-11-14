//! Reference second LNP projection masking. A one-use prepared mask connects
//! Gaussian sampling, signed planes, response formation and standard rejection.
//! This is not a complete ZK proof.
use super::{
    expansion::CounterExpander,
    gaussian::{gaussian_i32, GaussianError},
    projection::{signed_projection_bitplanes, ProjectionError},
    rejection::{sample_decision, RejectionError, RejectionKind, RejectionParameters},
    ProofPolynomial, DEGREE, MODULUS,
};
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum GaussianProjectionError {
    Parameter,
    Length,
    InnerProductRange,
    ResponseNorm,
    Gaussian(GaussianError),
    Projection(ProjectionError),
    Rejection(RejectionError),
}

/// Explicit reference parameters. Sigma is binary64 1.55*2^log2_scale and
/// variance is its binary64 square. This pins portable behavior; it does NOT
/// reproduce every extended-precision native parameter value. Repetition and
/// security/distribution bounds must be certified by the enclosing parameter set.
pub struct GaussianProjectionParameters {
    log2_scale: u32,
    rejection: RejectionParameters,
}

impl GaussianProjectionParameters {
    pub fn reference(log2_scale: u32, repetition: f64) -> Result<Self, GaussianProjectionError> {
        // Current Gaussian output and bit-plane representation are signed i32.
        // The reference uses logsdp+6 bits for the sampled mask.
        if log2_scale > 26 {
            return Err(GaussianProjectionError::Parameter);
        }
        let sigma = 1.55f64 * (1u64 << log2_scale) as f64;
        Ok(Self {
            log2_scale,
            rejection: RejectionParameters::from_binary64(sigma * sigma, repetition)
                .map_err(GaussianProjectionError::Rejection)?,
        })
    }

    /// Public verifier-side norm check corresponding to ||z|| <= sqrt(512)*sd.
    /// Canonical ring residues are interpreted in their unique centered range.
    /// Squaring and comparison are exact, with no floating-point square root.
    pub fn check_response_norm(&self, response: &ProofPolynomial) -> bool {
        let squared_norm: u128 = response
            .0
            .iter()
            .map(|&value| {
                let centered = if value > MODULUS / 2 {
                    i128::from(value) - i128::from(MODULUS)
                } else {
                    i128::from(value)
                };
                centered.unsigned_abs() * centered.unsigned_abs()
            })
            .sum();
        self.rejection.contains_squared_norm(squared_norm, 512)
    }
}

/// Prepared before the commitment that precedes the projection challenge.
/// No Clone/Debug/codec. Consuming `respond` prevents accidentally reusing this
/// sampled mask across attempts. The complete commitment order remains external.
pub struct GaussianProjectionMask<'p> {
    parameters: &'p GaussianProjectionParameters,
    values: Zeroizing<Vec<i32>>,
    planes: Zeroizing<Vec<Vec<u8>>>,
}

impl<'p> GaussianProjectionMask<'p> {
    pub fn sample(
        stream: &mut CounterExpander,
        parameters: &'p GaussianProjectionParameters,
    ) -> Result<Self, GaussianProjectionError> {
        let values = gaussian_i32(stream, DEGREE, parameters.log2_scale)
            .map_err(GaussianProjectionError::Gaussian)?;
        let planes = signed_projection_bitplanes(&values, parameters.log2_scale as usize + 6)
            .map_err(GaussianProjectionError::Projection)?;
        Ok(Self {
            parameters,
            values,
            planes,
        })
    }

    /// Private binary assignment to include in the pre-challenge commitment.
    pub fn bitplanes(&self) -> &[Vec<u8>] {
        &self.planes
    }

    /// `None` is standard rejection: restart the entire enclosing attempt with
    /// its saved transcript and fresh masks. Errors abort, including numerical
    /// ambiguity and range failures. Neither case exposes an unaccepted response.
    /// The rejection stream must follow the protocol's separate nonce schedule.
    pub fn respond(
        self,
        projection: &[i32],
        rejection_stream: &mut CounterExpander,
    ) -> Result<Option<AcceptedGaussianProjection>, GaussianProjectionError> {
        if projection.len() != DEGREE {
            return Err(GaussianProjectionError::Length);
        }
        let mut response = Zeroizing::new(vec![0i64; DEGREE]);
        let mut zv = 0i128;
        let mut vv = 0i128;
        for ((out, &y), &v) in response.iter_mut().zip(self.values.iter()).zip(projection) {
            *out = i64::from(y) + i64::from(v);
            zv += i128::from(*out) * i128::from(v);
            vv += i128::from(v) * i128::from(v);
        }
        let zv = i64::try_from(zv).map_err(|_| GaussianProjectionError::InnerProductRange)?;
        let vv = i64::try_from(vv).map_err(|_| GaussianProjectionError::InnerProductRange)?;
        if sample_decision(
            rejection_stream,
            RejectionKind::Standard,
            zv,
            vv,
            &self.parameters.rejection,
        )
        .map_err(GaussianProjectionError::Rejection)?
        {
            return Ok(None);
        }
        let response = ProofPolynomial::from_signed(&response).unwrap();
        if !self.parameters.check_response_norm(&response) {
            return Err(GaussianProjectionError::ResponseNorm);
        }
        Ok(Some(AcceptedGaussianProjection {
            response,
            mask_planes: self.planes,
        }))
    }
}

/// Only the response is a public proof message. Mask planes remain
/// private and must be bound by the final proof. No wire-proof API is provided.
pub struct AcceptedGaussianProjection {
    response: ProofPolynomial,
    mask_planes: Zeroizing<Vec<Vec<u8>>>,
}

impl AcceptedGaussianProjection {
    pub fn response(&self) -> &ProofPolynomial {
        &self.response
    }
    pub fn mask_planes(&self) -> &[Vec<u8>] {
        &self.mask_planes
    }
}

#[cfg(test)]
mod tests {
    use super::super::projection::{aggregate_signed_bitplanes, ReferenceProjection};
    use super::*;

    #[test]
    fn sampled_projection_response_binds_mask_planes_and_matrix_aggregation() {
        let parameters = GaussianProjectionParameters::reference(12, 1.01).unwrap();
        let mask =
            GaussianProjectionMask::sample(&mut CounterExpander::aes128(&[7; 16], 1), &parameters)
                .unwrap();
        let witness: Vec<[i16; DEGREE]> = (0..8)
            .map(|i| std::array::from_fn(|j| ((i + j) % 2) as i16))
            .collect();
        let matrix = ReferenceProjection::from_seed([19; 32], witness.len()).unwrap();
        let projection = matrix.project(&witness).unwrap();
        let mut rejection_stream = CounterExpander::aes128(&[9; 16], 0);
        let accepted = mask
            .respond(&projection, &mut rejection_stream)
            .unwrap()
            .unwrap();
        assert!(parameters.check_response_norm(accepted.response()));
        let alpha = std::array::from_fn(|i| i as i64 * 997 - 65536);
        let rows = matrix.aggregate(&alpha).unwrap();
        let mask_rows = aggregate_signed_bitplanes(&alpha, accepted.mask_planes().len()).unwrap();
        let mut sum = 0i128;
        for (row, values) in rows.iter().zip(&witness) {
            let values: Vec<i64> = values.iter().map(|&v| i64::from(v)).collect();
            sum += i128::from(row.mul(&ProofPolynomial::from_signed(&values).unwrap()).0[0]);
        }
        // Mask rows encode -dot(alpha,y); subtract for Pi*v+y=z.
        for (row, plane) in mask_rows.iter().zip(accepted.mask_planes()) {
            let values: Vec<i64> = plane.iter().map(|&v| i64::from(v)).collect();
            sum -= i128::from(row.mul(&ProofPolynomial::from_signed(&values).unwrap()).0[0]);
        }
        let public = ProofPolynomial::from_signed(&alpha)
            .unwrap()
            .conjugate()
            .mul(accepted.response());
        assert_eq!(sum.rem_euclid(i128::from(MODULUS)), i128::from(public.0[0]));

        use super::super::constraints::{
            EquationDomain, LinearPart, SparseConstraint, WitnessLayout,
        };
        let layout = WitnessLayout::new(&[witness.len(), accepted.mask_planes().len()]).unwrap();
        let mut assignment: Vec<_> = witness
            .iter()
            .map(|values| {
                let coefficients: Vec<i64> = values.iter().map(|&v| i64::from(v)).collect();
                ProofPolynomial::from_signed(&coefficients).unwrap()
            })
            .collect();
        for plane in accepted.mask_planes() {
            let coefficients: Vec<i64> = plane.iter().map(|&v| i64::from(v)).collect();
            assignment.push(ProofPolynomial::from_signed(&coefficients).unwrap());
        }
        let zero = ProofPolynomial::from_signed(&[0; DEGREE]).unwrap();
        let equation = SparseConstraint::new(
            &layout,
            EquationDomain::ConstantCoefficient,
            vec![
                LinearPart {
                    offset: 0,
                    coefficients: rows,
                },
                LinearPart {
                    offset: witness.len(),
                    coefficients: mask_rows.iter().map(|row| zero.sub(row)).collect(),
                },
            ],
            vec![],
            public,
        )
        .unwrap();
        assert!(equation.check(&assignment).unwrap());
        // Changing a private mask coefficient breaks the bound equation.
        let mut one = [0; DEGREE];
        one[0] = 1;
        assignment[witness.len()] =
            assignment[witness.len()].add(&ProofPolynomial::from_signed(&one).unwrap());
        assert!(!equation.check(&assignment).unwrap());
    }

    #[test]
    fn norm_check_uses_centered_residues_and_exact_threshold() {
        let parameters = GaussianProjectionParameters::reference(0, 2.0).unwrap();
        // 512 * binary64(1.55^2) is between 1230 and 1231.
        for (coefficient, expected) in [(35, true), (-35, true), (36, false), (-36, false)] {
            let mut values = [0; DEGREE];
            values[0] = coefficient;
            assert_eq!(
                parameters.check_response_norm(&ProofPolynomial::from_signed(&values).unwrap()),
                expected
            );
        }
        let mut threshold = [0; DEGREE];
        threshold[..3].copy_from_slice(&[35, 2, 1]); // squared norm 1230
        assert!(parameters.check_response_norm(&ProofPolynomial::from_signed(&threshold).unwrap()));
        threshold[3] = 1; // squared norm 1231
        assert!(!parameters.check_response_norm(&ProofPolynomial::from_signed(&threshold).unwrap()));
        assert!(matches!(
            GaussianProjectionParameters::reference(27, 2.0),
            Err(GaussianProjectionError::Parameter)
        ));
        assert!(matches!(
            GaussianProjectionParameters::reference(0, f64::NAN),
            Err(GaussianProjectionError::Rejection(_))
        ));
    }

    #[test]
    fn failures_and_sampling_rejection_are_distinct() {
        let parameters = GaussianProjectionParameters::reference(0, 2.0).unwrap();
        let prepare = || GaussianProjectionMask {
            parameters: &parameters,
            values: Zeroizing::new(vec![0; DEGREE]),
            planes: Zeroizing::new(vec![vec![0; DEGREE]; 6]),
        };
        let mut stream = CounterExpander::aes128(&[3; 16], 0);
        assert!(matches!(
            prepare().respond(&[], &mut stream),
            Err(GaussianProjectionError::Length)
        ));
        assert!(matches!(
            prepare().respond(&[i32::MAX; DEGREE], &mut stream),
            Err(GaussianProjectionError::InnerProductRange)
        ));
        assert!(matches!(
            prepare().respond(&[100; DEGREE], &mut stream),
            Err(GaussianProjectionError::Rejection(
                RejectionError::ExponentRange
            ))
        ));
        // Ordinary rejection is allowed only after an unambiguous decision.
        let mut saw_accept = false;
        let mut saw_reject = false;
        for nonce in 0..16 {
            let result = prepare()
                .respond(&[0; DEGREE], &mut CounterExpander::aes128(&[2; 16], nonce))
                .unwrap();
            saw_accept |= result.is_some();
            saw_reject |= result.is_none();
        }
        assert!(saw_accept && saw_reject);
    }
}

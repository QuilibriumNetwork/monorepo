//! Reference ternary JL projection and its ring-linear aggregation.
//! Matrices are public and regenerated with fixed scratch space. This is not
//! a norm proof: masking, bounds, and proof composition are still required.
use super::{
    expansion::CounterExpander, transcript::ReferenceTranscript, ProofPolynomial, DEGREE, MODULUS,
};
use zeroize::Zeroizing;

const MATRIX_BYTES: usize = DEGREE * DEGREE / 8;

#[derive(Debug, PartialEq, Eq)]
pub enum ProjectionError {
    Length,
    CounterExhausted,
    Overflow,
    Allocation,
    Width,
    Range,
}

/// Public matrix descriptor, not a witness or proof message. The second sign
/// matrix begins after ALL polynomials of the first matrix in the AES stream.
pub struct ReferenceProjection {
    seed: [u8; 32],
    polynomials: usize,
}

impl ReferenceProjection {
    fn check_count(polynomials: usize) -> Result<(), ProjectionError> {
        if (polynomials as u128) * (2 * MATRIX_BYTES / 16) as u128 > 1u128 << 64 {
            return Err(ProjectionError::CounterExhausted);
        }
        Ok(())
    }

    pub fn from_seed(seed: [u8; 32], polynomials: usize) -> Result<Self, ProjectionError> {
        Self::check_count(polynomials)?;
        Ok(Self { seed, polynomials })
    }

    /// Pinned jl_sample_mat seed transition. Validate dimensions before
    /// advancing the transcript. Transaction initialization remains external.
    pub fn from_transcript(
        transcript: &mut ReferenceTranscript,
        polynomials: usize,
    ) -> Result<Self, ProjectionError> {
        Self::check_count(polynomials)?;
        Self::from_seed(transcript.derive_reference_seed(), polynomials)
    }

    fn visit_matrices(
        &self,
        count: usize,
        mut visit: impl FnMut(
            usize,
            &[u8; MATRIX_BYTES],
            &[u8; MATRIX_BYTES],
        ) -> Result<(), ProjectionError>,
    ) -> Result<(), ProjectionError> {
        if count > self.polynomials {
            return Err(ProjectionError::Length);
        }
        let mut first = CounterExpander::aes256(&self.seed, 0);
        let mut second = CounterExpander::aes256(&self.seed, 0);
        second
            .skip_aes_blocks(self.polynomials as u128 * (MATRIX_BYTES / 16) as u128)
            .map_err(|_| ProjectionError::CounterExhausted)?;
        let mut a = [0; MATRIX_BYTES];
        let mut b = [0; MATRIX_BYTES];
        for index in 0..count {
            first
                .squeeze(&mut a)
                .map_err(|_| ProjectionError::CounterExhausted)?;
            second
                .squeeze(&mut b)
                .map_err(|_| ProjectionError::CounterExhausted)?;
            visit(index, &a, &b)?;
        }
        Ok(())
    }

    /// Exact integer projection. i128 accumulators avoid the reference SIMD's
    /// possible intermediate i32 overflow; refuse an out-of-range final result.
    /// Result is private unless the enclosing proof explicitly masks it.
    pub fn project(
        &self,
        witness: &[[i16; DEGREE]],
    ) -> Result<Zeroizing<Vec<i32>>, ProjectionError> {
        if witness.len() != self.polynomials {
            return Err(ProjectionError::Length);
        }
        self.project_prefix(witness)
    }

    /// Project a shorter witness against the shared maximum-width matrix used
    /// by LNP. The second stream offset remains the full descriptor width.
    /// This is different from generating a new matrix at witness.len().
    pub fn project_prefix(
        &self,
        witness: &[[i16; DEGREE]],
    ) -> Result<Zeroizing<Vec<i32>>, ProjectionError> {
        let mut sums = Zeroizing::new(vec![0i128; DEGREE]);
        self.visit_matrices(witness.len(), |index, a, b| {
            for (row, sum) in sums.iter_mut().enumerate() {
                for (col, &value) in witness[index].iter().enumerate() {
                    *sum += i128::from(value) * i128::from(entry(a, b, row, col));
                }
            }
            Ok(())
        })?;
        let mut output = Zeroizing::new(vec![0; DEGREE]);
        for (value, sum) in output.iter_mut().zip(sums.iter()) {
            *value = i32::try_from(*sum).map_err(|_| ProjectionError::Overflow)?;
        }
        Ok(output)
    }

    /// Conjugated matrix transpose times public alpha, modulo p. Consequently
    /// sum constant(aggregate_i * witness_i) = dot(alpha, project(witness)).
    /// Output size is one polynomial per input; matrix scratch stays 16 KiB.
    pub fn aggregate(
        &self,
        alpha: &[i64; DEGREE],
    ) -> Result<Vec<ProofPolynomial>, ProjectionError> {
        self.aggregate_prefix(alpha, self.polynomials)
    }

    /// Aggregate the first `count` columns of polynomials from the shared
    /// matrix, retaining its full-width second-stream offset.
    pub fn aggregate_prefix(
        &self,
        alpha: &[i64; DEGREE],
        count: usize,
    ) -> Result<Vec<ProofPolynomial>, ProjectionError> {
        if count > self.polynomials {
            return Err(ProjectionError::Length);
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(count)
            .map_err(|_| ProjectionError::Allocation)?;
        self.visit_matrices(count, |_, a, b| {
            let mut coefficients = Zeroizing::new(vec![0u64; DEGREE]);
            for (col, coefficient) in coefficients.iter_mut().enumerate() {
                let sum: i128 = alpha
                    .iter()
                    .enumerate()
                    .map(|(row, &value)| i128::from(value) * i128::from(entry(a, b, row, col)))
                    .sum();
                *coefficient = sum.rem_euclid(i128::from(MODULUS)) as u64;
            }
            output.push(ProofPolynomial(coefficients).conjugate());
            Ok(())
        })?;
        Ok(output)
    }
}

/// Pinned 32-row x 16-column bit tile, eight tiles per column strip.
fn entry(a: &[u8; MATRIX_BYTES], b: &[u8; MATRIX_BYTES], row: usize, col: usize) -> i8 {
    let byte = (col / 16) * 512 + (row / 32) * 64 + (col % 8) * 8 + row % 8;
    let bit = (row % 32) / 8 + 4 * ((col % 16) / 8);
    1 - ((a[byte] >> bit) & 1) as i8 - ((b[byte] >> bit) & 1) as i8
}

/// Exact two's-complement planes for private projected values. Width must be
/// selected by verifier parameters, never trusted from a proof. Binary checks
/// and these range constraints still have to be included in the final proof.
pub fn signed_projection_bitplanes(
    projection: &[i32],
    width: usize,
) -> Result<Zeroizing<Vec<Vec<u8>>>, ProjectionError> {
    if !(1..=32).contains(&width) {
        return Err(ProjectionError::Width);
    }
    if projection.len() != DEGREE {
        return Err(ProjectionError::Length);
    }
    let limit = 1i64 << (width - 1);
    if projection
        .iter()
        .any(|&v| i64::from(v) < -limit || i64::from(v) >= limit)
    {
        return Err(ProjectionError::Range);
    }
    let mut planes = Zeroizing::new(vec![vec![0u8; DEGREE]; width]);
    for (bit, plane) in planes.iter_mut().enumerate() {
        for (value, &coefficient) in plane.iter_mut().zip(projection) {
            *value = ((coefficient as u32 >> bit) & 1) as u8;
        }
    }
    Ok(planes)
}

/// Negative conjugate of alpha times each two's-complement weight. This folds
/// the reference jl_aggregate_proj caller's final sign-plane negation into the
/// API, so adding these rows to the matrix aggregation yields constant zero.
pub fn aggregate_signed_bitplanes(
    alpha: &[i64; DEGREE],
    width: usize,
) -> Result<Vec<ProofPolynomial>, ProjectionError> {
    if !(1..=32).contains(&width) {
        return Err(ProjectionError::Width);
    }
    let conjugate = ProofPolynomial::from_signed(alpha).unwrap().conjugate();
    Ok((0..width)
        .map(|bit| {
            let weight = (1i128 << bit) * if bit + 1 == width { -1 } else { 1 };
            ProofPolynomial(Zeroizing::new(
                conjugate
                    .0
                    .iter()
                    .map(|&v| (-weight * i128::from(v)).rem_euclid(i128::from(MODULUS)) as u64)
                    .collect(),
            ))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_matrix_prefix_retains_full_width_stream_offset() {
        let matrix = ReferenceProjection::from_seed([23; 32], 3).unwrap();
        let first: [i16; DEGREE] = std::array::from_fn(|i| i as i16 - 128);
        let prefix = matrix.project_prefix(&[first]).unwrap();
        let padded = matrix.project(&[first, [0; DEGREE], [0; DEGREE]]).unwrap();
        assert_eq!(&*prefix, &*padded);
        let other = ReferenceProjection::from_seed([23; 32], 1)
            .unwrap()
            .project(&[first])
            .unwrap();
        assert_ne!(&*prefix, &*other);
        let alpha = std::array::from_fn(|i| i as i64 - 128);
        let partial = matrix.aggregate_prefix(&alpha, 1).unwrap();
        let full = matrix.aggregate(&alpha).unwrap();
        assert_eq!(partial[0].reference_bitpack(), full[0].reference_bitpack());
        assert_eq!(
            matrix.project_prefix(&[[0; DEGREE]; 4]),
            Err(ProjectionError::Length)
        );
        assert!(matches!(
            matrix.aggregate_prefix(&alpha, 4),
            Err(ProjectionError::Length)
        ));
        assert_eq!(&*matrix.project_prefix(&[]).unwrap(), &vec![0; DEGREE]);
    }

    #[test]
    fn openssl_inverse_tile_vector_matches_projection_and_aggregation() {
        use sha2::{Digest, Sha256};
        let mut transcript = ReferenceTranscript::from_state(std::array::from_fn(|i| i as u8));
        let matrix = ReferenceProjection::from_transcript(&mut transcript, 3).unwrap();
        assert_eq!(
            transcript.state(),
            [
                0x06, 0x6a, 0x36, 0x1d, 0xc6, 0x75, 0xf8, 0x56, 0xce, 0xcd, 0xc0, 0x2b, 0x25, 0x21, 0x8a, 0x10,
                0xce, 0xc0, 0xce, 0xcf, 0x79, 0x85, 0x9e, 0xc0, 0xfe, 0xc3, 0xd4, 0x09, 0xe5, 0x84, 0x7a, 0x92
            ]
        );
        let witness: Vec<[i16; DEGREE]> = (0..3)
            .map(|i| std::array::from_fn(|j| (((i * 997 + j * 73) % 65536) as i32 - 32768) as i16))
            .collect();
        let alpha = std::array::from_fn(|i| {
            if i % 2 == 0 {
                i64::MAX - i as i64
            } else {
                i64::MIN + i as i64
            }
        });
        let projected = matrix.project(&witness).unwrap();
        let mut hash = Sha256::new();
        for v in projected.iter() {
            hash.update(v.to_le_bytes());
        }
        assert_eq!(
            format!("{:x}", hash.finalize()),
            "126446c99091c28596d2c5e9cb2ee29c5f2778b4cb5d604b61b8ddc4c0cd3dd4"
        );
        let aggregated = matrix.aggregate(&alpha).unwrap();
        let mut hash = Sha256::new();
        for polynomial in &aggregated {
            for v in polynomial.0.iter() {
                hash.update(v.to_le_bytes());
            }
        }
        assert_eq!(
            format!("{:x}", hash.finalize()),
            "ef7f814d7a5d5516f7554175d315c998ce7b900005970039cf358b683ae6cb92"
        );
    }

    #[test]
    fn signed_planes_bind_the_projection_with_the_sign_plane_negated() {
        for width in [1, 2, 16, 31, 32] {
            let limit = 1i64 << (width - 1);
            let values: Vec<i32> = (0..DEGREE)
                .map(|i| match i % 4 {
                    0 => -limit as i32,
                    1 => (limit - 1) as i32,
                    2 => -1,
                    _ => 0,
                })
                .collect();
            let planes = signed_projection_bitplanes(&values, width).unwrap();
            for col in 0..DEGREE {
                let reconstructed: i64 = planes
                    .iter()
                    .enumerate()
                    .map(|(bit, plane)| {
                        i64::from(plane[col])
                            * (1i64 << bit)
                            * if bit + 1 == width { -1 } else { 1 }
                    })
                    .sum();
                assert_eq!(reconstructed, i64::from(values[col]));
            }
            let alpha = std::array::from_fn(|i| i64::MIN + i as i64);
            let rows = aggregate_signed_bitplanes(&alpha, width).unwrap();
            let mut sum: i128 = values
                .iter()
                .zip(alpha)
                .map(|(&v, a)| i128::from(v) * i128::from(a))
                .sum();
            for (row, plane) in rows.iter().zip(planes.iter()) {
                let coefficients: Vec<i64> = plane.iter().map(|&v| i64::from(v)).collect();
                sum += i128::from(
                    row.mul(&ProofPolynomial::from_signed(&coefficients).unwrap())
                        .0[0],
                );
            }
            assert_eq!(sum.rem_euclid(i128::from(MODULUS)), 0);
            if width < 32 {
                assert_eq!(
                    signed_projection_bitplanes(&vec![limit as i32; DEGREE], width),
                    Err(ProjectionError::Range)
                );
                assert_eq!(
                    signed_projection_bitplanes(&vec![(-limit - 1) as i32; DEGREE], width),
                    Err(ProjectionError::Range)
                );
            }
        }
        for width in [0, 33, usize::MAX] {
            assert_eq!(
                signed_projection_bitplanes(&vec![0; DEGREE], width),
                Err(ProjectionError::Width)
            );
            assert!(matches!(
                aggregate_signed_bitplanes(&[0; DEGREE], width),
                Err(ProjectionError::Width)
            ));
        }
    }

    #[test]
    fn bit_tiles_cover_every_entry_once() {
        // Independent inverse tile traversal, including both nibbles and all
        // four groups of eight rows. Check every bit, not just random samples.
        let a = [0; MATRIX_BYTES];
        let mut b = [0; MATRIX_BYTES];
        let mut seen = vec![false; DEGREE * DEGREE];
        for strip in 0..16 {
            for tile in 0..8 {
                for lane in 0..8 {
                    for byte_in_lane in 0..8 {
                        let offset = strip * 512 + tile * 64 + lane * 8 + byte_in_lane;
                        for bit in 0..8 {
                            let row = tile * 32 + (bit % 4) * 8 + byte_in_lane;
                            let col = strip * 16 + (bit / 4) * 8 + lane;
                            assert!(!seen[row * DEGREE + col]);
                            seen[row * DEGREE + col] = true;
                            b[offset] = 1 << bit;
                            assert_eq!(entry(&a, &b, row, col), 0);
                            assert_eq!(entry(&b, &b, row, col), -1);
                            b[offset] = 0;
                            assert_eq!(entry(&a, &b, row, col), 1);
                        }
                    }
                }
            }
        }
        assert!(seen.into_iter().all(|v| v));
    }

    #[test]
    fn aggregation_matches_integer_projection_including_negacyclic_wrap() {
        let matrix = ReferenceProjection::from_seed([17; 32], 3).unwrap();
        let witness: Vec<[i16; DEGREE]> = (0..3)
            .map(|i| std::array::from_fn(|j| ((i * 137 + j * 73) % 65536) as i16))
            .collect();
        let alpha = std::array::from_fn(|i| {
            if i % 2 == 0 {
                i64::MAX - i as i64
            } else {
                i64::MIN + i as i64
            }
        });
        let projection = matrix.project(&witness).unwrap();
        let aggregated = matrix.aggregate(&alpha).unwrap();
        let mut left = 0i128;
        for (polynomial, values) in aggregated.iter().zip(&witness) {
            let values: Vec<i64> = values.iter().map(|&v| i64::from(v)).collect();
            left += i128::from(
                polynomial
                    .mul(&ProofPolynomial::from_signed(&values).unwrap())
                    .0[0],
            );
        }
        let right: i128 = alpha
            .iter()
            .zip(projection.iter())
            .map(|(&a, &b)| i128::from(a) * i128::from(b))
            .sum();
        assert_eq!(
            left.rem_euclid(i128::from(MODULUS)),
            right.rem_euclid(i128::from(MODULUS))
        );
    }

    #[test]
    fn dimensions_and_transcript_failure_are_checked() {
        let mut transcript = ReferenceTranscript::from_state([3; 32]);
        assert!(matches!(
            ReferenceProjection::from_transcript(&mut transcript, usize::MAX),
            Err(ProjectionError::CounterExhausted)
        ));
        assert_eq!(transcript.state(), [3; 32]);
        let empty = ReferenceProjection::from_transcript(&mut transcript, 0).unwrap();
        assert_ne!(transcript.state(), [3; 32]);
        assert_eq!(&*empty.project(&[]).unwrap(), &vec![0; DEGREE]);
        assert!(empty.aggregate(&[0; DEGREE]).unwrap().is_empty());
        let matrix = ReferenceProjection::from_seed([0; 32], 1).unwrap();
        assert_eq!(matrix.project(&[]), Err(ProjectionError::Length));
    }
}

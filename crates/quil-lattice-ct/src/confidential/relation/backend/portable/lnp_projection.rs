//! First LNP projection-mask and carry-decomposition components.
//! These are private prover intermediates, not proof messages. Commitments,
//! the complete retry/transcript schedule, and norm parameters remain external.
use super::{
    expansion::{CounterExpander, ExpansionError},
    projection::{signed_projection_bitplanes, ProjectionError},
    DEGREE,
};
use zeroize::Zeroizing;

pub const PROJECTION_GROUPS: usize = 4;
pub const MAX_CARRIES: usize = 32;
// Pinned lnp.c consumes this whole buffer for EACH of four masks, retaining
// only its first 3*N bytes. Preserve the discarded bytes in stream scheduling.
const MASK_SQUEEZE_BYTES: usize = ((3 * DEGREE * PROJECTION_GROUPS + 1) / 512) * 512;

#[derive(Debug, PartialEq, Eq)]
pub enum LnpProjectionError {
    Width,
    Length,
    MaskRange,
    NonTernaryCarry,
    Expansion(ExpansionError),
    Projection(ProjectionError),
}

/// Four independent uniform masks centered modulo 2^k. Widths are public
/// parameters and must be at most 24 because the reference draws three bytes.
/// Generate before committing the masked witness, not after its challenge.
/// On stream failure discard the whole attempt; no partial masks are returned.
pub fn sample_uniform_projection_masks(
    stream: &mut CounterExpander,
    widths: [usize; PROJECTION_GROUPS],
) -> Result<Zeroizing<Vec<Vec<i32>>>, LnpProjectionError> {
    if widths.iter().any(|&width| !(1..=24).contains(&width)) {
        return Err(LnpProjectionError::Width);
    }
    let mut masks = Zeroizing::new(vec![vec![0; DEGREE]; PROJECTION_GROUPS]);
    let mut bytes = Zeroizing::new(vec![0; MASK_SQUEEZE_BYTES]);
    for (output, width) in masks.iter_mut().zip(widths) {
        stream
            .squeeze(&mut bytes)
            .map_err(LnpProjectionError::Expansion)?;
        let modulus = 1i32 << width;
        for (coefficient, encoded) in output.iter_mut().zip(bytes.chunks_exact(3)) {
            let raw = i32::from(encoded[0])
                | (i32::from(encoded[1]) << 8)
                | (i32::from(encoded[2]) << 16);
            let residue = raw & (modulus - 1);
            *coefficient = if residue >= modulus / 2 {
                residue - modulus
            } else {
                residue
            };
        }
    }
    Ok(masks)
}

/// Private assignment to Pi*s + mask = 2^k*(w-t) + low. No Debug, Clone or
/// serialization; low_planes, positive and negative need binary proof rows.
pub struct ProjectionDecomposition {
    low: Zeroizing<Vec<i32>>,
    low_planes: Zeroizing<Vec<Vec<u8>>>,
    positive: Zeroizing<Vec<u8>>,
    negative: Zeroizing<Vec<u8>>,
}

impl ProjectionDecomposition {
    pub fn low(&self) -> &[i32] {
        &self.low
    }
    pub fn low_planes(&self) -> &[Vec<u8>] {
        &self.low_planes
    }
    pub fn positive(&self) -> &[u8] {
        &self.positive
    }
    pub fn negative(&self) -> &[u8] {
        &self.negative
    }
}

/// None means the reference's carry-count rejection: retry the ENTIRE enclosing
/// attempt with its saved transcript and fresh randomness. Errors (including
/// a carry outside {-1,0,1}) abort; they are not sampling rejections.
pub fn decompose_masked_projection(
    projection: &[i32],
    mask: &[i32],
    width: usize,
) -> Result<Option<ProjectionDecomposition>, LnpProjectionError> {
    if !(1..=24).contains(&width) {
        return Err(LnpProjectionError::Width);
    }
    if projection.len() != DEGREE || mask.len() != DEGREE {
        return Err(LnpProjectionError::Length);
    }
    let modulus = 1i64 << width;
    if mask
        .iter()
        .any(|&v| i64::from(v) < -modulus / 2 || i64::from(v) >= modulus / 2)
    {
        return Err(LnpProjectionError::MaskRange);
    }
    let mut low = Zeroizing::new(vec![0i32; DEGREE]);
    let mut positive = Zeroizing::new(vec![0u8; DEGREE]);
    let mut negative = Zeroizing::new(vec![0u8; DEGREE]);
    let mut carries = 0;
    for index in 0..DEGREE {
        // i32 projection plus <=24-bit mask is strictly inside (-p/2,p/2),
        // so the reference's centering modulo p cannot change this sum.
        let coefficient = i64::from(projection[index]) + i64::from(mask[index]);
        let residue = (coefficient + modulus / 2).rem_euclid(modulus) - modulus / 2;
        let carry = (coefficient - residue) / modulus;
        match carry {
            0 => {}
            1 => {
                positive[index] = 1;
                carries += 1;
            }
            -1 => {
                negative[index] = 1;
                carries += 1;
            }
            _ => return Err(LnpProjectionError::NonTernaryCarry),
        }
        low[index] = residue as i32;
    }
    if carries > MAX_CARRIES {
        return Ok(None);
    }
    let low_planes =
        signed_projection_bitplanes(&low, width).map_err(LnpProjectionError::Projection)?;
    Ok(Some(ProjectionDecomposition {
        low,
        low_planes,
        positive,
        negative,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_and_following_stream_match_openssl_fixture() {
        use sha2::{Digest, Sha256};
        let mut stream = CounterExpander::aes128(&std::array::from_fn(|i| i as u8), 7);
        let masks = sample_uniform_projection_masks(&mut stream, [1, 8, 17, 24]).unwrap();
        let mut hash = Sha256::new();
        for mask in masks.iter() {
            for value in mask {
                hash.update(value.to_le_bytes());
            }
        }
        assert_eq!(
            format!("{:x}", hash.finalize()),
            "7169a0dd7d827916999db075c28e38bcb77500e9b62f7a4a4d7475ff4e9c6cd6"
        );
        let mut next = [0; 512];
        stream.squeeze(&mut next).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(next)),
            "66a004187a350bf5b0834e8acb8ab580e5bd59fc6359937af926c51603ee7d94"
        );
    }

    #[test]
    fn four_shared_matrix_groups_recompose_with_sampled_masks() {
        use super::super::projection::ReferenceProjection;
        let widths = [17, 18, 19, 20];
        let masks =
            sample_uniform_projection_masks(&mut CounterExpander::aes128(&[5; 16], 0), widths)
                .unwrap();
        let matrix = ReferenceProjection::from_seed([11; 32], 4).unwrap();
        let witness: Vec<[i16; DEGREE]> = (0..4)
            .map(|i| std::array::from_fn(|j| ((i + j) % 2) as i16))
            .collect();
        for group in 0..PROJECTION_GROUPS {
            let projection = matrix.project_prefix(&witness[..group + 1]).unwrap();
            let decomposition =
                decompose_masked_projection(&projection, &masks[group], widths[group])
                    .unwrap()
                    .unwrap();
            for row in 0..DEGREE {
                let carry = i32::from(decomposition.positive()[row])
                    - i32::from(decomposition.negative()[row]);
                assert_eq!(
                    projection[row] + masks[group][row],
                    (1i32 << widths[group]) * carry + decomposition.low()[row]
                );
            }
        }
    }

    #[test]
    fn carry_threshold_and_signed_boundaries_recompose_exactly() {
        for width in [1, 2, 17, 24] {
            let modulus = 1i32 << width;
            let mask: Vec<i32> = (0..DEGREE)
                .map(|i| {
                    if i % 2 == 0 {
                        -modulus / 2
                    } else {
                        modulus / 2 - 1
                    }
                })
                .collect();
            let mut projected = vec![0; DEGREE];
            for (i, value) in projected.iter_mut().take(MAX_CARRIES).enumerate() {
                *value = if i % 2 == 0 { -1 } else { 1 };
            }
            let result = decompose_masked_projection(&projected, &mask, width)
                .unwrap()
                .unwrap();
            for i in 0..DEGREE {
                let carry = i32::from(result.positive()[i]) - i32::from(result.negative()[i]);
                assert_eq!(projected[i] + mask[i], modulus * carry + result.low()[i]);
                assert_eq!(result.positive()[i] * result.negative()[i], 0);
                let low: i64 = result
                    .low_planes()
                    .iter()
                    .enumerate()
                    .map(|(bit, plane)| {
                        i64::from(plane[i]) * (1i64 << bit) * if bit + 1 == width { -1 } else { 1 }
                    })
                    .sum();
                assert_eq!(low, i64::from(result.low()[i]));
            }
            projected[MAX_CARRIES] = -1;
            assert!(decompose_masked_projection(&projected, &mask, width)
                .unwrap()
                .is_none());
            // Fatal decomposition error remains fatal even after >32 carries.
            projected[DEGREE - 1] = 2 * modulus;
            assert!(matches!(
                decompose_masked_projection(&projected, &mask, width),
                Err(LnpProjectionError::NonTernaryCarry)
            ));
        }
    }

    #[test]
    fn malformed_parameters_abort_before_consuming_mask_randomness() {
        let mut stream = CounterExpander::aes128(&[9; 16], 0);
        assert_eq!(
            sample_uniform_projection_masks(&mut stream, [1, 17, 24, 25]),
            Err(LnpProjectionError::Width)
        );
        let mut expected = [0; 512];
        let mut actual = [0; 512];
        stream.squeeze(&mut actual).unwrap();
        CounterExpander::aes128(&[9; 16], 0)
            .squeeze(&mut expected)
            .unwrap();
        assert_eq!(actual, expected);
        assert!(matches!(
            decompose_masked_projection(&[0; DEGREE], &[2; DEGREE], 2),
            Err(LnpProjectionError::MaskRange)
        ));
        assert!(matches!(
            decompose_masked_projection(&[], &[0; DEGREE], 2),
            Err(LnpProjectionError::Length)
        ));
        assert!(matches!(
            decompose_masked_projection(&[0; DEGREE], &[0; DEGREE], 0),
            Err(LnpProjectionError::Width)
        ));
    }
}

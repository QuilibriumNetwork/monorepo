//! Reference port of pinned polyvec_challenge and scalar poly_fft/poly_opnorm.
//! See NOTICE. Floating-point acceptance matches tested strict C fixtures, not
//! a certified bound on the mathematical operator norm.
use super::*;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

mod roots;
const RATE: usize = 168;
const WEIGHT: usize = 24;
const NORM_LIMIT: f64 = 10.0;

#[derive(Debug, PartialEq, Eq)]
pub enum ChallengeError {
    Allocation,
    Numeric,
}

/// Scalar reference estimate with the pinned binary64 FFT constants. No
/// certificate of rounding error, architecture-independent boundary decisions,
/// or exact norm bounds is implied. Short challenges are public proof values.
pub fn reference_operator_norm(coefficients: &[i16; DEGREE]) -> Result<f64, ChallengeError> {
    let mut values: [(f64, f64); 128] =
        std::array::from_fn(|i| (f64::from(coefficients[i]), f64::from(coefficients[128 + i])));
    let mut root = 1;
    let mut length = 64;
    while length >= 1 {
        for start in (0..128).step_by(2 * length) {
            let (real, imaginary) = roots::ROOTS[root];
            for j in start..start + length {
                let (a, b) = values[j + length];
                let product = (a * real - b * imaginary, a * imaginary + b * real);
                let original = values[j];
                values[j + length] = (original.0 - product.0, original.1 - product.1);
                values[j] = (original.0 + product.0, original.1 + product.1);
            }
            root += 1;
        }
        length >>= 1;
    }
    let mut maximum: f64 = 0.0;
    for (real, imaginary) in values {
        let norm = real.hypot(imaginary);
        if !norm.is_finite() {
            return Err(ChallengeError::Numeric);
        }
        maximum = maximum.max(norm);
    }
    Ok(maximum)
}

fn consume_chunk(
    output: &mut Vec<ProofPolynomial>,
    limit: usize,
    bytes: &[u8],
) -> Result<(), ChallengeError> {
    let mut position = 0;
    let start = output.len();
    while output.len() - start < limit && position + 25 <= bytes.len() {
        let mut signs =
            u32::from_le_bytes([bytes[position], bytes[position + 1], bytes[position + 2], 0]);
        position += 3;
        let mut coefficients = [0i16; DEGREE];
        let mut k = DEGREE - WEIGHT;
        while k < DEGREE && position < bytes.len() {
            let index = usize::from(bytes[position]);
            position += 1;
            if index <= k {
                coefficients[k] = coefficients[index];
                coefficients[index] = 1 - 2 * (signs & 1) as i16;
                signs >>= 1;
                k += 1;
            }
        }
        if k == DEGREE && reference_operator_norm(&coefficients)? <= NORM_LIMIT {
            output.push(ProofPolynomial::from_signed(&coefficients.map(i64::from)).unwrap());
        }
    }
    Ok(())
}

fn sample(
    count: usize,
    mut read: impl FnMut(&mut [u8]),
) -> Result<Vec<ProofPolynomial>, ChallengeError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(count)
        .map_err(|_| ChallengeError::Allocation)?;
    while output.len() < count {
        let remaining = count - output.len();
        let batch = remaining.min(10);
        let blocks = if remaining >= 10 {
            17
        } else {
            (remaining * 17).div_ceil(10)
        };
        let mut bytes = vec![0; blocks * RATE];
        read(&mut bytes);
        consume_chunk(&mut output, batch, &bytes)?;
        // Unused/partial candidates and leftover bytes are intentionally
        // discarded, matching the reference call's block-consumption schedule.
    }
    Ok(output)
}

pub fn short_polynomial_challenges(
    seed: &[u8; 32],
    nonce: u64,
    count: usize,
) -> Result<Vec<ProofPolynomial>, ChallengeError> {
    let mut hash = Shake128::default();
    Update::update(&mut hash, seed);
    Update::update(&mut hash, &nonce.to_le_bytes());
    let mut reader = hash.finalize_xof();
    sample(count, |bytes| reader.read(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_challenges_and_stream_consumption_match_scalar_c() {
        use sha2::{Digest, Sha256};
        let hex = |bytes: &[u8]| bytes.iter().map(|v| format!("{v:02x}")).collect::<String>();
        let seed = std::array::from_fn(|i| i as u8);
        let nonce = 0x0102030405060708u64;
        for (count, consumed_expected, expected, next) in [
            (
                1,
                336,
                "a2b143ebc6a93f09678feb1306fe5fa1a7f7222478ba6a8ebea4b63293595b04",
                "27e596202d895ec4ad0a9a8d65610d01125516d449413b3397172b88ec0cde3c",
            ),
            (
                10,
                2856,
                "225da8cdb9ed6961f64749c10f62e0fdc72eb550f87d3e18ae130fc19bc64b63",
                "d94ca25eb65c9ca87779530d78fde8f0d370965602f5c81ccd2374d43ed86d6f",
            ),
            (
                11,
                3528,
                "33b8f3298f1be5ce86793d94a8ebccc46702eeebdc59003bd9082a1f268c28ce",
                "b22add3599c41cd9078814f8e763d0276144de62998a24e938b9820d0f2747f0",
            ),
        ] {
            let polynomials = short_polynomial_challenges(&seed, nonce, count).unwrap();
            let mut digest = Sha256::new();
            for polynomial in &polynomials {
                assert_eq!(polynomial.0.iter().filter(|&&v| v != 0).count(), WEIGHT);
                let coefficients: [i16; DEGREE] = std::array::from_fn(|i| match polynomial.0[i] {
                    0 => 0,
                    1 => 1,
                    v if v == MODULUS - 1 => -1,
                    _ => panic!("unexpected challenge coefficient"),
                });
                assert!(reference_operator_norm(&coefficients).unwrap() <= NORM_LIMIT);
                for coefficient in coefficients {
                    Digest::update(&mut digest, coefficient.to_le_bytes());
                }
            }
            assert_eq!(hex(&digest.finalize()), expected);
            let mut hash = Shake128::default();
            Update::update(&mut hash, &seed);
            Update::update(&mut hash, &nonce.to_le_bytes());
            let mut reader = hash.finalize_xof();
            let mut consumed = 0;
            sample(count, |bytes| {
                consumed += bytes.len();
                reader.read(bytes);
            })
            .unwrap();
            assert_eq!(consumed, consumed_expected);
            let mut bytes = [0; RATE];
            reader.read(&mut bytes);
            assert_eq!(hex(&Sha256::digest(bytes)), next);
        }
    }
    #[test]
    fn norm_reference_and_incomplete_candidates_are_handled() {
        let mut coefficients = [0; DEGREE];
        coefficients[0] = 10;
        assert_eq!(reference_operator_norm(&coefficients), Ok(10.0));
        coefficients[0] = 11;
        assert_eq!(reference_operator_norm(&coefficients), Ok(11.0));
        let mut output = Vec::new();
        consume_chunk(&mut output, 1, &[255; 336]).unwrap();
        assert!(output.is_empty());
        assert!(sample(0, |_| panic!("zero count consumes nothing"))
            .unwrap()
            .is_empty());
    }
}

//! Portable reference for standard/sign-filtered/bimodal rejection decisions.
//! Outward-rounded integer intervals replace platform-dependent long double.
//! Variable-time BigUint storage is not guaranteed to be erased.
//! This is not a masking layer or a complete ZK security argument.
use super::expansion::{CounterExpander, ExpansionError};
use num_bigint::BigUint;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectionKind {
    Standard,
    SignFiltered,
    Bimodal,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RejectionError {
    Parameter,
    ExponentRange,
    Ambiguous,
    Expansion(ExpansionError),
}

/// Public exact rational parameters derived from finite positive binary64
/// values, without calling platform transcendental functions. These are not
/// proof parameter estimates or an assertion that a chosen M is sufficient.
pub struct RejectionParameters {
    variance: Rational,
    repetition: Rational,
}
struct Rational {
    numerator: BigUint,
    denominator: BigUint,
}
struct Interval {
    lower: BigUint,
    upper: BigUint,
}

fn positive_binary64(value: f64) -> Result<Rational, RejectionError> {
    if !value.is_finite() || value <= 0.0 {
        return Err(RejectionError::Parameter);
    }
    let bits = value.to_bits();
    let exponent = ((bits >> 52) & 2047) as i32;
    let mantissa = (bits & ((1u64 << 52) - 1)) | if exponent == 0 { 0 } else { 1u64 << 52 };
    let shift = if exponent == 0 {
        -1074
    } else {
        exponent - 1023 - 52
    };
    let mut numerator = BigUint::from(mantissa);
    let mut denominator = BigUint::from(1u8);
    if shift >= 0 {
        numerator <<= shift as usize;
    } else {
        denominator <<= -shift as usize;
    }
    Ok(Rational {
        numerator,
        denominator,
    })
}

impl RejectionParameters {
    /// Exact comparison against a public multiple of the stored variance.
    /// Useful for squared response-norm checks without platform sqrt rounding.
    pub(super) fn contains_squared_norm(&self, squared_norm: u128, multiple: u64) -> bool {
        BigUint::from(squared_norm) * &self.variance.denominator
            <= BigUint::from(multiple) * &self.variance.numerator
    }

    /// Exact public values represented as unsigned mantissa * 2^exponent.
    /// Bounded shifts cover the native binary floating formats without
    /// rounding wider Linux long-double parameters down to binary64.
    pub fn from_binary_components(
        variance_mantissa: u128,
        variance_exponent: i32,
        repetition_mantissa: u128,
        repetition_exponent: i32,
    ) -> Result<Self, RejectionError> {
        fn rational(mantissa: u128, exponent: i32) -> Result<Rational, RejectionError> {
            if mantissa == 0 || !(-32768..=32768).contains(&exponent) {
                return Err(RejectionError::Parameter);
            }
            let mut numerator = BigUint::from(mantissa);
            let mut denominator = BigUint::from(1u8);
            if exponent >= 0 { numerator <<= exponent as usize; }
            else { denominator <<= (-exponent) as usize; }
            Ok(Rational { numerator, denominator })
        }
        let variance = rational(variance_mantissa, variance_exponent)?;
        let repetition = rational(repetition_mantissa, repetition_exponent)?;
        if repetition.numerator < repetition.denominator { return Err(RejectionError::Parameter); }
        Ok(Self { variance, repetition })
    }

    /// Square the exact native standard deviation in integer arithmetic.
    /// Native floating-point multiplication must not round the variance first.
    pub fn from_standard_deviation_components(
        mantissa: u128, exponent: i32,
        repetition_mantissa: u128, repetition_exponent: i32,
    ) -> Result<Self, RejectionError> {
        let mut parameters = Self::from_binary_components(mantissa, exponent, repetition_mantissa, repetition_exponent)?;
        parameters.variance.numerator = &parameters.variance.numerator * &parameters.variance.numerator;
        parameters.variance.denominator = &parameters.variance.denominator * &parameters.variance.denominator;
        Ok(parameters)
    }

    pub fn from_binary64(variance: f64, repetition: f64) -> Result<Self, RejectionError> {
        if repetition < 1.0 {
            return Err(RejectionError::Parameter);
        }
        Ok(Self {
            variance: positive_binary64(variance)?,
            repetition: positive_binary64(repetition)?,
        })
    }
}

fn ceil_div(numerator: &BigUint, denominator: &BigUint) -> BigUint {
    (numerator + denominator - BigUint::from(1u8)) / denominator
}

/// Bounds exp(sign * numerator/denominator), in units of 2^-precision.
/// Domain is explicitly limited to |x|<=128 until actual proof parameters
/// establish a larger necessary range. Range errors abort, never accept/reject.
fn exp_interval(
    negative: bool,
    numerator: &BigUint,
    denominator: &BigUint,
    precision: usize,
) -> Result<Interval, RejectionError> {
    let scale = BigUint::from(1u8) << precision;
    if numerator == &BigUint::from(0u8) {
        return Ok(Interval {
            lower: scale.clone(),
            upper: scale,
        });
    }
    if numerator > &(denominator * 128u32) {
        return Err(RejectionError::ExponentRange);
    }
    let mut reduced_denominator = denominator.clone();
    let mut squares = 0;
    while numerator * 2u32 > reduced_denominator {
        reduced_denominator <<= 1;
        squares += 1;
    }
    // y<=1/2. Each positive Taylor term is enclosed by directed rounding.
    // After term n, remaining tail <= 2 * term_(n+1), since all subsequent
    // term ratios are at most 1/2. Rounding errors are retained in the bounds.
    let mut lower = scale.clone();
    let mut upper = scale.clone();
    let mut term_lower = scale.clone();
    let mut term_upper = scale.clone();
    let mut converged = false;
    for n in 1..=precision + 16 {
        let divisor = &reduced_denominator * n;
        term_lower = (&term_lower * numerator) / &divisor;
        term_upper = ceil_div(&(&term_upper * numerator), &divisor);
        lower += &term_lower;
        upper += &term_upper;
        let next_upper = ceil_div(
            &(&term_upper * numerator),
            &(&reduced_denominator * (n + 1)),
        );
        if next_upper <= BigUint::from(1u8) {
            upper += next_upper * 2u32;
            converged = true;
            break;
        }
    }
    if !converged {
        return Err(RejectionError::Ambiguous);
    }
    for _ in 0..squares {
        lower = (&lower * &lower) / &scale;
        upper = ceil_div(&(&upper * &upper), &scale);
    }
    if negative {
        let square = &scale * &scale;
        let inverse_lower = &square / &upper;
        let inverse_upper = ceil_div(&square, &lower);
        lower = inverse_lower;
        upper = inverse_upper;
    }
    Ok(Interval { lower, upper })
}

/// Evaluate the mathematical acceptance rule for an exact 63-bit draw.
/// `Ok(true)` means reject/retry; numerical uncertainty returns an error and
/// MUST abort proof construction, not trigger another sampling attempt.
pub fn decide(
    kind: RejectionKind,
    zv: i64,
    vv: i64,
    draw: u64,
    parameters: &RejectionParameters,
) -> Result<bool, RejectionError> {
    if draw >= 1u64 << 63 {
        return Err(RejectionError::Parameter);
    }
    decide_integer(kind, zv, vv, BigUint::from(draw), 63, parameters)
}

/// Revised exact 256-bit draw, interpreted little endian as u / 2^256.
/// This reference avoids rounding the random draw to a floating-point value.
/// It is not the native prover's decision routine.
pub fn decide_256(
    kind: RejectionKind,
    zv: i64,
    vv: i64,
    draw: &[u8; 32],
    parameters: &RejectionParameters,
) -> Result<bool, RejectionError> {
    decide_integer(kind, zv, vv, BigUint::from_bytes_le(draw), 256, parameters)
}

fn decide_integer(
    kind: RejectionKind,
    zv: i64,
    vv: i64,
    draw: BigUint,
    draw_bits: usize,
    parameters: &RejectionParameters,
) -> Result<bool, RejectionError> {
    if vv < 0 {
        return Err(RejectionError::Parameter);
    }
    if kind == RejectionKind::SignFiltered && zv < 0 {
        return Ok(true);
    }
    let draw_numerator = draw * &parameters.repetition.numerator;
    let draw_denominator = (BigUint::from(1u8) << draw_bits) * &parameters.repetition.denominator;
    for precision in [128usize, 256, 512, 1024] {
        let scale = BigUint::from(1u8) << precision;
        if kind != RejectionKind::Bimodal {
            let exponent = i128::from(vv) - 2 * i128::from(zv);
            let numerator =
                BigUint::from(exponent.unsigned_abs()) * &parameters.variance.denominator;
            let denominator = &parameters.variance.numerator * 2u32;
            let exponential = exp_interval(exponent < 0, &numerator, &denominator, precision)?;
            let left = &draw_numerator * &scale;
            if left <= exponential.lower * &draw_denominator {
                return Ok(false);
            }
            if left > exponential.upper * &draw_denominator {
                return Ok(true);
            }
        } else {
            let variance_twice = &parameters.variance.numerator * 2u32;
            let decay = exp_interval(
                true,
                &(BigUint::from(vv as u64) * &parameters.variance.denominator),
                &variance_twice,
                precision,
            )?;
            let numerator = BigUint::from(zv.unsigned_abs()) * &parameters.variance.denominator;
            let positive =
                exp_interval(false, &numerator, &parameters.variance.numerator, precision)?;
            let negative =
                exp_interval(true, &numerator, &parameters.variance.numerator, precision)?;
            let cosh_lower = (positive.lower + negative.lower) / 2u32;
            let cosh_upper = ceil_div(&(positive.upper + negative.upper), &BigUint::from(2u8));
            let lower = decay.lower * cosh_lower * &draw_numerator;
            let upper = decay.upper * cosh_upper * &draw_numerator;
            let right = &scale * &scale * &draw_denominator;
            if upper <= right {
                return Ok(false);
            }
            if lower > right {
                return Ok(true);
            }
        }
    }
    Err(RejectionError::Ambiguous)
}

/// Preserve the pinned rejection routine's draw consumption: one full AES
/// squeeze block, using the first eight little-endian bytes masked to 63 bits.
/// Sign-filtered negative inner products reject without consuming any bytes.
pub fn sample_decision(
    stream: &mut CounterExpander,
    kind: RejectionKind,
    zv: i64,
    vv: i64,
    parameters: &RejectionParameters,
) -> Result<bool, RejectionError> {
    if vv < 0 {
        return Err(RejectionError::Parameter);
    }
    if kind == RejectionKind::SignFiltered && zv < 0 {
        return Ok(true);
    }
    let mut bytes = Zeroizing::new([0u8; 512]);
    stream
        .squeeze(&mut *bytes)
        .map_err(RejectionError::Expansion)?;
    let draw = u64::from_le_bytes(bytes[..8].try_into().unwrap()) & ((1u64 << 63) - 1);
    decide(kind, zv, vv, draw, parameters)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "native-proof")]
    #[test]
    fn native_parameter_parts_preserve_binary64_and_wider_precision() {
        use quil_lattice_proof_sys::{ffi, NATIVE_STATE};
        let _guard = NATIVE_STATE.lock().unwrap();
        let mut bytes = [0; 16];
        let mut exponent = 0;
        let mut precision = 0;
        for value in [f64::from_bits(1), f64::MIN_POSITIVE, 0.1, 1.55, 8.0, f64::MAX] {
            assert_eq!(unsafe { ffi::quil_fixture_rejection_parts(value, 0, bytes.as_mut_ptr(), &mut exponent, &mut precision) }, 0);
            let exact = RejectionParameters::from_binary_components(u128::from_le_bytes(bytes), exponent, 2, 0).unwrap();
            let reference = positive_binary64(value).unwrap();
            let squared = RejectionParameters::from_standard_deviation_components(u128::from_le_bytes(bytes), exponent, 2, 0).unwrap();
            assert_eq!(&squared.variance.numerator * &reference.denominator * &reference.denominator,
                       &reference.numerator * &reference.numerator * &squared.variance.denominator);
            assert_eq!(&exact.variance.numerator * &reference.denominator,
                       &reference.numerator * &exact.variance.denominator);
        }
        assert_eq!(unsafe { ffi::quil_fixture_rejection_parts(0.0, 1, bytes.as_mut_ptr(), &mut exponent, &mut precision) }, 0);
        assert!((53..=128).contains(&precision));
        assert_eq!(exponent, -127);
        assert_eq!(u128::from_le_bytes(bytes), (1u128 << 127) + (1u128 << (128 - precision)));
        assert_eq!(unsafe { ffi::quil_fixture_rejection_parts(0.0, 2, bytes.as_mut_ptr(), &mut exponent, &mut precision) }, 0);
        assert_eq!(u128::from_le_bytes(bytes), 1u128 << 127);
        assert!(RejectionParameters::from_binary_components(u128::from_le_bytes(bytes), exponent, 2, 0).is_ok());
        for value in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert_eq!(unsafe { ffi::quil_fixture_rejection_parts(value, 0, bytes.as_mut_ptr(), &mut exponent, &mut precision) }, -1);
        }
        for args in [(0, 0, 2, 0), (1, i32::MIN, 2, 0), (1, i32::MAX, 2, 0), (1, 0, 1, -1)] {
            assert!(matches!(RejectionParameters::from_binary_components(args.0, args.1, args.2, args.3), Err(RejectionError::Parameter)));
        }
    }

    #[test]
    fn full_width_draws_resolve_adjacent_acceptance_thresholds() {
        // Python Decimal at 180 digits: floor(2^256 * exp(-1)/2) and
        // floor(2^256 * exp(1/4)/(exp(1)+exp(-1))), little endian.
        for (kind, vv, threshold) in [
            (RejectionKind::Standard, 0, "76ed8352e85c1298993bb65ad5024ced867c2a48c1636f5d8d6fde596cac162f"),
            (RejectionKind::SignFiltered, 0, "76ed8352e85c1298993bb65ad5024ced867c2a48c1636f5d8d6fde596cac162f"),
            (RejectionKind::Bimodal, 4, "1b6ae21e6c98fc77d9bac0394d57350ce2a14f62023dcda4b24ebb2d0bd9826a"),
        ] {
            let params = RejectionParameters::from_binary64(8.0, 2.0).unwrap();
            let mut draw: [u8; 32] = std::array::from_fn(|i|
                u8::from_str_radix(&threshold[2*i..2*i+2], 16).unwrap());
            assert_eq!(decide_256(kind, 8, vv, &draw, &params), Ok(false));
            draw[0] += 1; // These independently computed thresholds do not carry.
            assert_eq!(decide_256(kind, 8, vv, &draw, &params), Ok(true));
        }
        let params = RejectionParameters::from_binary64(8.0, 2.0).unwrap();
        let mut half = [0; 32];
        half[31] = 128;
        assert_eq!(decide_256(RejectionKind::Standard, 0, 0, &half, &params), Ok(false));
        half[0] = 1;
        assert_eq!(decide_256(RejectionKind::Standard, 0, 0, &half, &params), Ok(true));
        assert_eq!(decide_256(RejectionKind::Standard, 0, -1, &half, &params), Err(RejectionError::Parameter));
        assert_eq!(decide_256(RejectionKind::Standard, i64::MAX, 0, &half, &params), Err(RejectionError::ExponentRange));
    }

    #[test]
    fn adjacent_draws_match_independent_decimal_thresholds() {
        for (kind, zv, vv, variance, repetition, draw, expected) in [
            (
                RejectionKind::Standard,
                20i64,
                12i64,
                8.0,
                2.0,
                801390865377409347u64,
                false,
            ),
            (
                RejectionKind::Standard,
                20i64,
                12i64,
                8.0,
                2.0,
                801390865377409348u64,
                false,
            ),
            (
                RejectionKind::Standard,
                20i64,
                12i64,
                8.0,
                2.0,
                801390865377409349u64,
                true,
            ),
            (
                RejectionKind::Standard,
                -3i64,
                2i64,
                64.0,
                1.25,
                7854582740615871674u64,
                false,
            ),
            (
                RejectionKind::Standard,
                -3i64,
                2i64,
                64.0,
                1.25,
                7854582740615871675u64,
                false,
            ),
            (
                RejectionKind::Standard,
                -3i64,
                2i64,
                64.0,
                1.25,
                7854582740615871676u64,
                true,
            ),
            (
                RejectionKind::Standard,
                1i64,
                1i64,
                0.125,
                2.0,
                84465975781740358u64,
                false,
            ),
            (
                RejectionKind::Standard,
                1i64,
                1i64,
                0.125,
                2.0,
                84465975781740359u64,
                false,
            ),
            (
                RejectionKind::Standard,
                1i64,
                1i64,
                0.125,
                2.0,
                84465975781740360u64,
                true,
            ),
            (
                RejectionKind::Standard,
                4611686018427387905i64,
                4611686018427387906i64,
                1.152921504606847e+18,
                1.5,
                832165111336262932u64,
                false,
            ),
            (
                RejectionKind::Standard,
                4611686018427387905i64,
                4611686018427387906i64,
                1.152921504606847e+18,
                1.5,
                832165111336262933u64,
                false,
            ),
            (
                RejectionKind::Standard,
                4611686018427387905i64,
                4611686018427387906i64,
                1.152921504606847e+18,
                1.5,
                832165111336262934u64,
                true,
            ),
            (
                RejectionKind::Bimodal,
                20i64,
                12i64,
                8.0,
                2.0,
                1592054551566709426u64,
                false,
            ),
            (
                RejectionKind::Bimodal,
                20i64,
                12i64,
                8.0,
                2.0,
                1592054551566709427u64,
                false,
            ),
            (
                RejectionKind::Bimodal,
                20i64,
                12i64,
                8.0,
                2.0,
                1592054551566709428u64,
                true,
            ),
            (
                RejectionKind::Bimodal,
                -3i64,
                2i64,
                64.0,
                1.25,
                7486668603546967517u64,
                false,
            ),
            (
                RejectionKind::Bimodal,
                -3i64,
                2i64,
                64.0,
                1.25,
                7486668603546967518u64,
                false,
            ),
            (
                RejectionKind::Bimodal,
                -3i64,
                2i64,
                64.0,
                1.25,
                7486668603546967519u64,
                true,
            ),
            (RejectionKind::Bimodal, 128i64, 0i64, 1.0, 2.0, 0u64, false),
            (RejectionKind::Bimodal, 128i64, 0i64, 1.0, 2.0, 1u64, true),
            (RejectionKind::Standard, 128i64, 0i64, 1.0, 2.0, 0u64, false),
            (RejectionKind::Standard, 128i64, 0i64, 1.0, 2.0, 1u64, true),
        ] {
            let parameters = RejectionParameters::from_binary64(variance, repetition).unwrap();
            assert_eq!(
                decide(kind, zv, vv, draw, &parameters),
                Ok(expected),
                "{kind:?}, zv={zv}, vv={vv}, draw={draw}"
            );
        }
    }

    #[test]
    fn exact_boundary_decisions_preserve_all_63_random_bits() {
        let parameters = RejectionParameters::from_binary64(1.0, 2.0).unwrap();
        for kind in [RejectionKind::Standard, RejectionKind::Bimodal] {
            assert_eq!(decide(kind, 0, 0, (1u64 << 62) - 1, &parameters), Ok(false));
            assert_eq!(decide(kind, 0, 0, 1u64 << 62, &parameters), Ok(false));
            assert_eq!(decide(kind, 0, 0, (1u64 << 62) + 1, &parameters), Ok(true));
        }
        assert!(matches!(
            RejectionParameters::from_binary64(f64::NAN, 2.0),
            Err(RejectionError::Parameter)
        ));
        assert_eq!(
            decide(RejectionKind::Standard, i64::MIN, 0, 1, &parameters),
            Err(RejectionError::ExponentRange)
        );
    }

    #[test]
    fn sign_filtered_rejection_does_not_consume_a_draw() {
        let parameters = RejectionParameters::from_binary64(8.0, 2.0).unwrap();
        let mut stream = CounterExpander::aes128(&[3; 16], 1);
        let mut expected = CounterExpander::aes128(&[3; 16], 1);
        assert_eq!(
            sample_decision(&mut stream, RejectionKind::SignFiltered, -1, 1, &parameters),
            Ok(true)
        );
        let mut a = [0; 512];
        let mut b = [0; 512];
        stream.squeeze(&mut a).unwrap();
        expected.squeeze(&mut b).unwrap();
        assert_eq!(a, b);
        for kind in [RejectionKind::Standard, RejectionKind::Bimodal] {
            let mut stream = CounterExpander::aes128(&[4; 16], 2);
            let mut expected = CounterExpander::aes128(&[4; 16], 2);
            expected.squeeze(&mut b).unwrap();
            let draw = u64::from_le_bytes(b[..8].try_into().unwrap()) & ((1u64 << 63) - 1);
            assert_eq!(
                sample_decision(&mut stream, kind, 0, 0, &parameters),
                decide(kind, 0, 0, draw, &parameters)
            );
            stream.squeeze(&mut a).unwrap();
            expected.squeeze(&mut b).unwrap();
            assert_eq!(a, b);
        }
    }
}

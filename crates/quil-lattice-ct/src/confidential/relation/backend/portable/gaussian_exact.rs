//! Integer implementation of Canonne–Kamath–Steinke, Algorithms 1–3:
//! https://arxiv.org/html/2004.00010#S5
//! The mathematical sampler is exact given uniform bits. Explicit resource
//! limits can abort a call. Variable-time BigUint temporaries are not guaranteed
//! to be erased.
use super::expansion::{CounterExpander, ExpansionError, SQUEEZE_BYTES};
use num_bigint::BigUint;
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum ExactGaussianError {
    Parameter,
    Budget,
    Allocation,
    OutputRange,
    Expansion(ExpansionError),
}

/// Limits cover the entire call, not each retry. Exhaustion is an error and
/// must abort proving; callers must not restart the sampler on that error.
pub struct SamplingBudget {
    pub max_steps: usize,
    pub max_random_bytes: usize,
    pub max_coefficients: usize,
}

struct Sampler<'a> {
    stream: &'a mut CounterExpander,
    buffer: Zeroizing<[u8; SQUEEZE_BYTES]>,
    position: usize,
    steps: usize,
    random_bytes: usize,
}

impl Sampler<'_> {
    fn step(&mut self) -> Result<(), ExactGaussianError> {
        self.steps = self.steps.checked_sub(1).ok_or(ExactGaussianError::Budget)?;
        Ok(())
    }

    fn byte(&mut self) -> Result<u8, ExactGaussianError> {
        if self.position == SQUEEZE_BYTES {
            self.random_bytes = self.random_bytes.checked_sub(SQUEEZE_BYTES)
                .ok_or(ExactGaussianError::Budget)?;
            self.stream.squeeze(&mut *self.buffer).map_err(ExactGaussianError::Expansion)?;
            self.position = 0;
        }
        let byte = self.buffer[self.position];
        self.position += 1;
        Ok(byte)
    }

    fn uniform(&mut self, bound: &BigUint) -> Result<BigUint, ExactGaussianError> {
        if bound == &BigUint::from(0u8) { return Err(ExactGaussianError::Parameter); }
        if bound == &BigUint::from(1u8) { return Ok(BigUint::from(0u8)); }
        let bits = (bound - 1u8).bits() as usize;
        // All bounds in this fixed parameter family are much smaller; this
        // also bounds temporary random storage if an arithmetic input changes.
        if bits > 4096 { return Err(ExactGaussianError::Parameter); }
        let mut bytes = Zeroizing::new(vec![0u8; bits.div_ceil(8)]);
        loop {
            self.step()?;
            for byte in bytes.iter_mut() { *byte = self.byte()?; }
            if bits % 8 != 0 {
                let last = bytes.len() - 1;
                bytes[last] &= (1u8 << (bits % 8)) - 1;
            }
            let value = BigUint::from_bytes_le(&bytes);
            if &value < bound { return Ok(value); }
        }
    }

    // Bernoulli(exp(-numerator/denominator)), for 0 <= numerator <= denominator.
    // The alternating stopping rule avoids approximating exp numerically.
    fn exp_unit(&mut self, numerator: &BigUint, denominator: &BigUint) -> Result<bool, ExactGaussianError> {
        let mut k = 1u64;
        loop {
            self.step()?;
            let bound = denominator * k;
            if self.uniform(&bound)? >= *numerator { return Ok(k % 2 == 1); }
            k = k.checked_add(1).ok_or(ExactGaussianError::Budget)?;
        }
    }

    fn exp(&mut self, numerator: &BigUint, denominator: &BigUint) -> Result<bool, ExactGaussianError> {
        if denominator == &BigUint::from(0u8) { return Err(ExactGaussianError::Parameter); }
        let mut remaining = numerator.clone();
        while &remaining > denominator {
            if !self.exp_unit(&BigUint::from(1u8), &BigUint::from(1u8))? { return Ok(false); }
            remaining -= denominator;
        }
        self.exp_unit(&remaining, denominator)
    }

    fn laplace(&mut self, scale: u64) -> Result<(bool, u64), ExactGaussianError> {
        let scale_big = BigUint::from(scale);
        loop {
            self.step()?;
            let negative = self.uniform(&BigUint::from(2u8))? == BigUint::from(1u8);
            let residue = loop {
                let residue = self.uniform(&scale_big)?;
                if self.exp(&residue, &scale_big)? { break residue; }
            };
            let mut quotient = 0u64;
            while self.exp_unit(&BigUint::from(1u8), &BigUint::from(1u8))? {
                quotient = quotient.checked_add(1).ok_or(ExactGaussianError::Budget)?;
            }
            let residue = residue.to_u64_digits().first().copied().unwrap_or(0);
            let magnitude = quotient.checked_mul(scale).and_then(|x| x.checked_add(residue))
                .ok_or(ExactGaussianError::OutputRange)?;
            if !negative || magnitude != 0 { return Ok((negative, magnitude)); }
        }
    }
}

/// Sample the discrete Gaussian with SD equal to the exact binary64 value
/// `1.55` times `2^log2_scale`, matching the native SD parameter construction.
/// No rounded CDF or floating exponential participates in sampling.
pub fn gaussian_i32(
    stream: &mut CounterExpander,
    count: usize,
    log2_scale: u32,
    budget: SamplingBudget,
) -> Result<Zeroizing<Vec<i32>>, ExactGaussianError> {
    if log2_scale > 26 { return Err(ExactGaussianError::Parameter); }
    if count > budget.max_coefficients { return Err(ExactGaussianError::Budget); }
    let mut output = Zeroizing::new(Vec::new());
    output.try_reserve_exact(count).map_err(|_| ExactGaussianError::Allocation)?;
    // 1.55's binary64 significand is exact; scale <= 26 keeps the exponent negative.
    let significand = (1.55f64.to_bits() & ((1u64 << 52) - 1)) | (1u64 << 52);
    let denominator = 1u64 << (52 - log2_scale);
    let scale = significand / denominator + 1;
    let sd_n = BigUint::from(significand);
    let sd_d = BigUint::from(denominator);
    let variance_n = &sd_n * &sd_n;
    let variance_d = &sd_d * &sd_d;
    let acceptance_d = &variance_n * &variance_d * BigUint::from(scale).pow(2) * 2u8;
    let mut sampler = Sampler {
        stream, buffer: Zeroizing::new([0; SQUEEZE_BYTES]), position: SQUEEZE_BYTES,
        steps: budget.max_steps, random_bytes: budget.max_random_bytes,
    };
    for _ in 0..count {
        loop {
            sampler.step()?;
            let (negative, magnitude) = sampler.laplace(scale)?;
            let term = BigUint::from(magnitude) * &variance_d * scale;
            let difference = if term >= variance_n { term - &variance_n } else { &variance_n - term };
            if sampler.exp(&(&difference * &difference), &acceptance_d)? {
                // Large Laplace proposals must be rejected normally before
                // checking i32 range; truncating proposals would bias outputs.
                let signed = if negative { -i128::from(magnitude) } else { i128::from(magnitude) };
                output.push(i32::try_from(signed).map_err(|_| ExactGaussianError::OutputRange)?);
                break;
            }
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn budget() -> SamplingBudget {
        SamplingBudget { max_steps: 1 << 20, max_random_bytes: 1 << 20, max_coefficients: 32 }
    }

    #[test]
    fn integer_samples_match_independent_python_openssl_vectors() {
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        for (scale, expected) in [
            (0, "cd6b4822e8bfe8d5acba49fa26e670e306a329df6b3a38113f5f2f6d42def879"),
            (4, "b458a4af2e19d89a4e1ea6680802367958e0b32e220355d7fd1ec3a347c603a5"),
            (12, "185e64ccb5b1e6162ac6dc2efaeb3b4b2a7b2b3aa951a309788fd80a5c1d94cb"),
            (20, "fc5236f4a09857c80f351f6ff818ce705c3a2900791fe14b9053d2c41dfe56e3"),
            (26, "c536c51d4e417dea794ed9ead5c59548d1233200955e86e78a0fe2583364ed3a"),
        ] {
            let mut stream = CounterExpander::aes256(&key, 0x0102030405060708);
            let output = gaussian_i32(&mut stream, 32, scale, budget()).unwrap();
            let mut hash = Sha256::new();
            for value in output.iter() { hash.update(value.to_le_bytes()); }
            let actual: String = hash.finalize().iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(actual, expected, "scale={scale}");
        }
    }

    #[test]
    fn resource_exhaustion_is_an_error_and_invalid_input_preserves_the_stream() {
        let mut stream = CounterExpander::aes256(&[4; 32], 1);
        assert_eq!(gaussian_i32(&mut stream, 1, 27, budget()), Err(ExactGaussianError::Parameter));
        assert_eq!(gaussian_i32(&mut stream, 33, 0, budget()), Err(ExactGaussianError::Budget));
        let mut no_steps = budget(); no_steps.max_steps = 0;
        assert_eq!(gaussian_i32(&mut stream, 1, 0, no_steps), Err(ExactGaussianError::Budget));
        let mut no_bytes = budget(); no_bytes.max_random_bytes = 0;
        assert_eq!(gaussian_i32(&mut stream, 1, 0, no_bytes), Err(ExactGaussianError::Budget));
        let mut expected = CounterExpander::aes256(&[4; 32], 1);
        let mut a = [0; SQUEEZE_BYTES]; let mut b = [0; SQUEEZE_BYTES];
        stream.squeeze(&mut a).unwrap(); expected.squeeze(&mut b).unwrap();
        assert_eq!(a, b);
    }
}

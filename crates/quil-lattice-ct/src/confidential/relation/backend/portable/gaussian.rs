//! Portable reference port of pinned labrados gaussian.c (see crate NOTICE).
//! Matches its CDF, binary64 approximation and byte/bit buffering. The upstream
//! approximation has a FIXME about its interval. The sampler is not constant-time.
use super::expansion::{CounterExpander, ExpansionError, SQUEEZE_BYTES};
use zeroize::{Zeroize, Zeroizing};

const CDF: [(u64, u64); 21] = [
    (10894764499197476522, 10804844707381617341),
    (4761708367981796450, 6209732027000382074),
    (1476784279527800432, 14108379346150813303),
    (316388870594767345, 17827298407763885637),
    (46043503515468600, 18385899657892021654),
    (4503729779335039, 3860889375818664979),
    (294122444862326, 13947176349836216550),
    (12769598070895, 14321894682751135119),
    (367552986472, 10286761328368440884),
    (7001273393, 2287787188970898528),
    (88153536, 17843977990435837663),
    (733119, 12174894787802692461),
    (4024, 18067426722645776197),
    (14, 10764017821655913055),
    (0, 643125733022530080),
    (0, 1014291014134832),
    (0, 1055215183460),
    (0, 724109373),
    (0, 327744),
    (0, 98),
    (0, 0),
];

#[derive(Debug, PartialEq, Eq)]
pub enum GaussianError {
    Parameter,
    Length,
    Expansion(ExpansionError),
    Numeric,
    OutputRange,
}
impl From<ExpansionError> for GaussianError {
    fn from(error: ExpansionError) -> Self {
        Self::Expansion(error)
    }
}

struct RandomBuffer {
    bytes: Zeroizing<Vec<u8>>,
    position: usize,
    bits: u64,
    bit_position: usize,
}
impl Drop for RandomBuffer {
    fn drop(&mut self) {
        self.bits.zeroize();
    }
}
impl RandomBuffer {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(vec![0; SQUEEZE_BYTES]),
            position: SQUEEZE_BYTES,
            bits: 0,
            bit_position: 64,
        }
    }
    fn words(
        &mut self,
        stream: &mut CounterExpander,
        count: usize,
    ) -> Result<Zeroizing<Vec<u64>>, GaussianError> {
        let length = count * 8;
        if self.position + length > SQUEEZE_BYTES {
            stream.squeeze(&mut self.bytes)?;
            self.position = 0;
        }
        let words = self.bytes[self.position..self.position + length]
            .chunks_exact(8)
            .map(|v| u64::from_le_bytes(v.try_into().unwrap()))
            .collect();
        self.position += length;
        Ok(Zeroizing::new(words))
    }
    fn bit(&mut self, stream: &mut CounterExpander) -> Result<i32, GaussianError> {
        if self.bit_position >= 64 {
            self.bits = self.words(stream, 1)?[0];
            self.bit_position = 0;
        }
        let bit = (self.bits & 1) as i32;
        self.bits >>= 1;
        self.bit_position += 1;
        Ok(bit)
    }
}

fn exp_small(x: f64) -> f64 {
    let t = x * x;
    let t = x - t
        * (1.66666666666666019037e-1
            + t * (-2.77777777770155933842e-3
                + t * (6.61375632143793436117e-5
                    + t * (-1.65339022054652515390e-6 + t * 4.13813679705723846039e-8))));
    1.0 - ((x * t) / (t - 2.0) - x)
}

fn bernoulli_exp(
    stream: &mut CounterExpander,
    buffer: &mut RandomBuffer,
    mut x: f64,
) -> Result<bool, GaussianError> {
    if !x.is_finite() || x < 0.0 {
        return Err(GaussianError::Numeric);
    }
    let words = buffer.words(stream, 2)?;
    let exponent = x * 1.4426950408889634;
    if exponent >= u64::MAX as f64 {
        return Err(GaussianError::Numeric);
    }
    let exponent = exponent as u64;
    x -= 0.6931471805599453 * exponent as f64;
    let shift = exponent.min(63);
    let low_bits = words[0] ^ ((words[0] >> shift) << shift);
    let threshold = exp_small(-x) * (1u64 << 53) as f64;
    if !threshold.is_finite() || !(0.0..=(1u64 << 53) as f64).contains(&threshold) {
        return Err(GaussianError::Numeric);
    }
    Ok(low_bits == 0 && (words[1] & ((1u64 << 53) - 1)) < threshold as u64)
}

fn gaussian155(
    stream: &mut CounterExpander,
    buffer: &mut RandomBuffer,
    center: f64,
) -> Result<i32, GaussianError> {
    loop {
        let sign = buffer.bit(stream)?;
        let words = buffer.words(stream, 2)?;
        let z = CDF
            .iter()
            .take_while(|&&(hi, lo)| words[0] < hi || (words[0] == hi && words[1] < lo))
            .count() as i32;
        let k = (-sign & (2 * z)) - z + sign;
        let difference = k as f64 - center;
        let x = (difference * difference - ((k - sign) * (k - sign)) as f64)
            * (1.0 / (2.0 * 1.55 * 1.55));
        if bernoulli_exp(stream, buffer, x)? {
            return Ok(k);
        }
    }
}

/// Reference gaussian_i32 call semantics, including its initial extra squeeze
/// block and discarding leftover buffered bits at return. On error discard the
/// stream; no partially sampled output is returned. log2_scale is not itself a
/// certified standard deviation or a proof-parameter selection API.
pub fn gaussian_i32(
    stream: &mut CounterExpander,
    count: usize,
    log2_scale: u32,
) -> Result<Zeroizing<Vec<i32>>, GaussianError> {
    if log2_scale > 31 {
        return Err(GaussianError::Parameter);
    }
    let nbits = count
        .checked_mul(log2_scale as usize)
        .ok_or(GaussianError::Length)?;
    let blocks = nbits
        .div_ceil(SQUEEZE_BYTES * 8)
        .checked_add(1)
        .ok_or(GaussianError::Length)?;
    let length = blocks
        .checked_mul(SQUEEZE_BYTES)
        .ok_or(GaussianError::Length)?;
    let mut initial = Zeroizing::new(vec![0u8; length]);
    stream.squeeze(&mut initial)?;
    let mut buffer = RandomBuffer::new();
    let mask = (1u64 << log2_scale) - 1;
    let inv = 1.0 / (1u64 << log2_scale) as f64;
    let mut result = Zeroizing::new(Vec::new());
    for i in 0..count {
        let offset = i * log2_scale as usize;
        let word = u64::from_le_bytes(initial[offset / 8..offset / 8 + 8].try_into().unwrap());
        let uniform = (word >> (offset & 7)) & mask;
        let k = gaussian155(stream, &mut buffer, uniform as f64 * inv)?;
        let sample = (i64::from(k) << log2_scale) - uniform as i64;
        result.push(i32::try_from(sample).map_err(|_| GaussianError::OutputRange)?);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gaussian_samples_and_stream_position_match_pinned_scalar_c() {
        use sha2::{Digest, Sha256};
        let hex = |bytes: &[u8]| bytes.iter().map(|v| format!("{v:02x}")).collect::<String>();
        for (scale, samples, next) in [
            (
                0,
                "72a7912c4e321e452d1bfd16a0e4b4e0cb4de7f492403954ed7847335e892f5a",
                "4249cb221f87f1e7ae86185eef05826269c920d81f5207e056a626f9c9106dc8",
            ),
            (
                4,
                "34c79510feaad418cf3313660a7c615fbc31bc8660110784b1cffebd3e22cdb8",
                "d6ef51253b82e617c63db03333013e5918cc5c3357d2c58d3318365cd9f481ca",
            ),
            (
                12,
                "75584c25df077a0bd846ba6bd40a7c298365b226e12e015fc752817524457061",
                "839cc384e2b2c25c7f646d7eda8f56f89643c70f81e192c75c31d979a3380b34",
            ),
            (
                20,
                "d2af34a810393378ead0d7740efa3008594957cf459ac04d2dcf377d842bf9f0",
                "d6ef51253b82e617c63db03333013e5918cc5c3357d2c58d3318365cd9f481ca",
            ),
        ] {
            let key = std::array::from_fn(|i| i as u8);
            let mut stream = CounterExpander::aes128(&key, 0x0102030405060708);
            let output = gaussian_i32(&mut stream, 256, scale).unwrap();
            let mut hash = Sha256::new();
            for value in output.iter() {
                hash.update(value.to_le_bytes());
            }
            assert_eq!(
                hex(&hash.finalize()),
                samples,
                "sample mismatch at scale {scale}"
            );
            let mut bytes = [0; 512];
            stream.squeeze(&mut bytes).unwrap();
            assert_eq!(
                hex(&Sha256::digest(bytes)),
                next,
                "stream mismatch at scale {scale}"
            );
        }
    }
    #[test]
    fn invalid_scale_is_rejected_before_consuming_stream() {
        let mut first = CounterExpander::aes128(&[0; 16], 0);
        assert!(matches!(
            gaussian_i32(&mut first, 1, 32),
            Err(GaussianError::Parameter)
        ));
        let mut second = CounterExpander::aes128(&[0; 16], 0);
        let mut a = [0; 512];
        let mut b = [0; 512];
        first.squeeze(&mut a).unwrap();
        second.squeeze(&mut b).unwrap();
        assert_eq!(a, b);
    }
}

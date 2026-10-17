//! Portable LOGQ=38 polzvec_uniform semantics from the pinned implementation.
//! Five little-endian bytes per coefficient, masked to 38 bits. Reject the
//! entire batch if ANY coefficient is >=p. Four-polynomial batches consume
//! 5120 stream bytes; tails round up to the next 512-byte squeeze block.
use super::{
    expansion::{CounterExpander, ExpansionError, SQUEEZE_BYTES},
    *,
};

pub fn uniform_polynomials(
    seed: &[u8; 32],
    nonce: u64,
    count: usize,
) -> Result<Vec<ProofPolynomial>, ExpansionError> {
    let mut stream = CounterExpander::aes256(seed, nonce);
    sample(count, |bytes| stream.squeeze(bytes))
}

/// Reference private-mask stream; public transcript expansion is AES-256 as well.
pub fn uniform_polynomials_private(seed: &[u8; 32], nonce: u64, count: usize) -> Result<Vec<ProofPolynomial>, ExpansionError> {
    let mut stream = CounterExpander::aes256(seed, nonce);
    sample(count, |bytes| stream.squeeze(bytes))
}

fn sample(
    count: usize,
    mut squeeze: impl FnMut(&mut [u8]) -> Result<(), ExpansionError>,
) -> Result<Vec<ProofPolynomial>, ExpansionError> {
    let mut result = Vec::new();
    while result.len() < count {
        let batch = (count - result.len()).min(4);
        let bytes = (batch * DEGREE * 5).div_ceil(SQUEEZE_BYTES) * SQUEEZE_BYTES;
        let mut buffer = Zeroizing::new(vec![0u8; bytes]);
        loop {
            squeeze(&mut buffer)?;
            let mut candidates = Zeroizing::new(vec![0u64; batch * DEGREE]);
            for (value, encoded) in candidates.iter_mut().zip(buffer.chunks_exact(5)) {
                let mut word = [0; 8];
                word[..5].copy_from_slice(encoded);
                *value = u64::from_le_bytes(word) & ((1u64 << 38) - 1);
                word.zeroize();
            }
            if candidates.iter().any(|&value| value >= MODULUS) {
                continue;
            }
            for polynomial in candidates.chunks_exact(DEGREE) {
                result.push(ProofPolynomial(Zeroizing::new(polynomial.to_vec())));
            }
            break;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_full_batch_and_tail_match_openssl_reference() {
        use sha2::{Digest, Sha256};
        let key = std::array::from_fn(|i| i as u8);
        let values = uniform_polynomials(&key, 0x0102030405060708, 5).unwrap();
        let mut hash = Sha256::new();
        for value in values.iter().flat_map(|p| p.0.iter()) {
            Digest::update(&mut hash, value.to_le_bytes());
        }
        let digest = hash
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(
            digest,
            "ee5d78f81e0ad5096d520f9a5a34025730946de521393400b07710afd60bad26"
        );
    }

    #[test]
    fn invalid_coefficient_retries_whole_batch_and_tails_round_up() {
        let mut calls = Vec::new();
        let output = sample(5, |bytes| {
            calls.push(bytes.len());
            bytes.fill(0);
            if calls.len() == 1 {
                bytes[0] = 77; // Must not survive the rejected batch.
                bytes[5..10].copy_from_slice(&MODULUS.to_le_bytes()[..5]);
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, [5120, 5120, 1536]);
        assert_eq!(output.len(), 5);
        assert!(output.iter().all(|p| p.0.iter().all(|&c| c == 0)));
        assert!(sample(0, |_| panic!("empty sample consumes no bytes"))
            .unwrap()
            .is_empty());
    }
}

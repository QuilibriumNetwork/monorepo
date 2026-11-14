//! Portable reproduction of the pinned backend's AES counter layout.
//! AES input = nonce.to_le_bytes() || counter.to_le_bytes(). Counter starts at
//! zero; an upstream squeeze block is 512 bytes (32 AES blocks). This is a
//! deterministic expansion primitive, not an entropy source or complete sampler.
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use zeroize::Zeroize;

pub const SQUEEZE_BYTES: usize = 512;

enum Cipher {
    Aes128(aes::Aes128),
    Aes256(aes::Aes256),
}

/// Secret key schedules are zeroized by the aes crate's enabled zeroize feature.
/// No Clone, Debug or serialization API. Calling select_nonce deliberately
/// resets the stream; callers must follow the proof protocol's nonce schedule.
pub struct CounterExpander {
    cipher: Cipher,
    nonce: u64,
    next: u128,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ExpansionError {
    InvalidLength,
    CounterExhausted,
}

impl Drop for CounterExpander {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.next.zeroize();
    }
}

impl CounterExpander {
    pub fn aes128(key: &[u8; 16], nonce: u64) -> Self {
        Self {
            cipher: Cipher::Aes128(aes::Aes128::new(key.into())),
            nonce,
            next: 0,
        }
    }
    pub fn aes256(key: &[u8; 32], nonce: u64) -> Self {
        Self {
            cipher: Cipher::Aes256(aes::Aes256::new(key.into())),
            nonce,
            next: 0,
        }
    }
    pub fn select_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
        self.next = 0;
    }

    /// Internal public-matrix regeneration only. Does not change the nonce.
    /// Failure leaves the stream position unchanged.
    pub(super) fn skip_aes_blocks(&mut self, blocks: u128) -> Result<(), ExpansionError> {
        let end = self
            .next
            .checked_add(blocks)
            .filter(|&end| end <= 1u128 << 64)
            .ok_or(ExpansionError::CounterExhausted)?;
        self.next = end;
        Ok(())
    }

    /// Errors leave output and state unchanged. Refuse counter wrap instead of
    /// repeating stream bytes. Valid upstream-length calls have identical layout.
    pub fn squeeze(&mut self, output: &mut [u8]) -> Result<(), ExpansionError> {
        if output.len() % SQUEEZE_BYTES != 0 {
            return Err(ExpansionError::InvalidLength);
        }
        let end = self.next + (output.len() / 16) as u128;
        if end > 1u128 << 64 {
            return Err(ExpansionError::CounterExhausted);
        }
        for (offset, block) in output.chunks_exact_mut(16).enumerate() {
            block[..8].copy_from_slice(&self.nonce.to_le_bytes());
            block[8..].copy_from_slice(&((self.next + offset as u128) as u64).to_le_bytes());
            let block = GenericArray::from_mut_slice(block);
            match &self.cipher {
                Cipher::Aes128(cipher) => cipher.encrypt_block(block),
                Cipher::Aes256(cipher) => cipher.encrypt_block(block),
            }
        }
        self.next = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_matrix_skip_matches_consumption_and_checks_overflow() {
        let mut consumed = CounterExpander::aes128(&[42; 16], 0);
        let mut skipped = CounterExpander::aes128(&[42; 16], 0);
        let mut scratch = [0; 8192];
        consumed.squeeze(&mut scratch).unwrap();
        skipped.skip_aes_blocks(8192 / 16).unwrap();
        let mut expected = [0; 512];
        let mut actual = [0; 512];
        consumed.squeeze(&mut expected).unwrap();
        skipped.squeeze(&mut actual).unwrap();
        assert_eq!(actual, expected);
        let before = skipped.next;
        assert_eq!(
            skipped.skip_aes_blocks(u128::MAX),
            Err(ExpansionError::CounterExhausted)
        );
        assert_eq!(skipped.next, before);
        skipped.skip_aes_blocks((1u128 << 64) - before).unwrap();
        assert_eq!(
            skipped.skip_aes_blocks(1),
            Err(ExpansionError::CounterExhausted)
        );
        assert_eq!(skipped.next, 1u128 << 64);
    }

    #[test]
    fn both_key_sizes_match_independent_openssl_vectors() {
        use sha2::{Digest, Sha256};
        let key128 = std::array::from_fn(|i| i as u8);
        let key256 = std::array::from_fn(|i| i as u8);
        for (mut stream, expected) in [
            (
                CounterExpander::aes128(&key128, 0x0102030405060708),
                "ed5f8634f3d0558d22058a59747c9748fb37e153eee29d6d33da7fce42a93664",
            ),
            (
                CounterExpander::aes256(&key256, 0x0102030405060708),
                "af50681021c760155d04ba43d6c865c90bb1dc2e2925634507a34a53b346843e",
            ),
        ] {
            let mut output = [0; 1024];
            stream.squeeze(&mut output).unwrap();
            let digest = Sha256::digest(output)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            assert_eq!(digest, expected);
        }
    }

    #[test]
    fn chunking_nonce_reset_and_counter_exhaustion_are_exact() {
        let mut combined = [0; 1024];
        let mut separate = [0; 1024];
        let mut stream = CounterExpander::aes128(&[7; 16], 0x0102030405060708);
        stream.squeeze(&mut combined).unwrap();
        stream.select_nonce(0x0102030405060708);
        stream.squeeze(&mut separate[..512]).unwrap();
        stream.squeeze(&mut separate[512..]).unwrap();
        assert_eq!(combined, separate);
        let mut malformed = [99; 511];
        let before = stream.next;
        assert_eq!(
            stream.squeeze(&mut malformed),
            Err(ExpansionError::InvalidLength)
        );
        assert_eq!(stream.next, before);
        assert_eq!(malformed, [99; 511]);
        stream.next = (1u128 << 64) - 32;
        stream.squeeze(&mut separate[..512]).unwrap();
        let before = separate;
        assert_eq!(
            stream.squeeze(&mut separate[..512]),
            Err(ExpansionError::CounterExhausted)
        );
        assert_eq!(separate, before);
        stream.select_nonce(11);
        assert_eq!(stream.next, 0);
    }
}

//! Pinned backend polynomial encoding and transcript transitions, not a
//! complete transaction transcript or standalone proof codec. Callers must
//! only absorb public proof messages, never private witnesses.
use super::*;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

pub const REFERENCE_POLYNOMIAL_BYTES: usize = DEGREE * 38 / 8;

#[derive(Debug, PartialEq, Eq)]
pub enum TranscriptError {
    Length,
    Noncanonical,
    Allocation,
}

impl ProofPolynomial {
    /// polz_bitpack layout for canonical residues: each of 32 lanes concatenates
    /// eight 14-bit low limbs, eight 14-bit middle limbs and eight 10-bit high
    /// limbs. Consecutive 16-bit words from the lanes are interleaved on wire.
    /// Encoding one polynomial is not a complete proof or transaction format.
    pub fn reference_bitpack(&self) -> [u8; REFERENCE_POLYNOMIAL_BYTES] {
        let mut output = [0; REFERENCE_POLYNOMIAL_BYTES];
        for lane in 0..32 {
            let mut position = 0;
            for (limb, width) in [14, 14, 10].into_iter().enumerate() {
                for group in 0..8 {
                    let value = self.0[group * 32 + lane] >> (limb * 14);
                    for bit in 0..width {
                        let offset = ((position / 16) * 32 + lane) * 2 + (position % 16) / 8;
                        output[offset] |= (((value >> bit) & 1) as u8) << (position % 8);
                        position += 1;
                    }
                }
            }
        }
        output
    }

    pub fn from_reference_bitpack(input: &[u8]) -> Result<Self, TranscriptError> {
        let coefficients = Self::unpack_reference_raw(input)?;
        if coefficients.iter().any(|&v| v >= MODULUS) {
            return Err(TranscriptError::Noncanonical);
        }
        Ok(Self(coefficients))
    }

    /// Internal only: the reference almost-uniform sampler intentionally draws
    /// all 38-bit strings and reduces them. External decoding remains canonical.
    pub(super) fn unpack_reference_raw(
        input: &[u8],
    ) -> Result<Zeroizing<Vec<u64>>, TranscriptError> {
        if input.len() != REFERENCE_POLYNOMIAL_BYTES {
            return Err(TranscriptError::Length);
        }
        let mut coefficients = Zeroizing::new(vec![0u64; DEGREE]);
        for lane in 0..32 {
            let mut position = 0;
            for (limb, width) in [14, 14, 10].into_iter().enumerate() {
                for group in 0..8 {
                    for bit in 0..width {
                        let offset = ((position / 16) * 32 + lane) * 2 + (position % 16) / 8;
                        let value = (input[offset] >> (position % 8)) & 1;
                        coefficients[group * 32 + lane] |= u64::from(value) << (limb * 14 + bit);
                        position += 1;
                    }
                }
            }
        }
        Ok(coefficients)
    }
}

/// Backend-reference 32-byte public chaining state. Initialization and the
/// complete protocol message schedule are NOT implemented here. In particular,
/// a caller-supplied state is not a substitute for binding a transaction.
pub struct ReferenceTranscript {
    state: [u8; 32],
}

impl ReferenceTranscript {
    /// Pinned sample_chalx_uniform actually calls the almost-uniform sampler.
    /// Keep that distribution distinct from exact-uniform rejection sampling.
    /// Commit the chaining state only after successful expansion.
    pub fn almost_uniform_challenges(
        &mut self,
        count: usize,
    ) -> Result<Vec<ProofPolynomial>, commitment::CommitmentError> {
        let mut pending = Self::from_state(self.state);
        let seed = pending.derive_reference_seed();
        let output = commitment::reference_almost_uniform(&seed, 0, count)?;
        self.state = pending.state;
        Ok(output)
    }

    /// Pinned aggregate schedule: one seed transition and one nonce-zero
    /// challenge-vector call. State is committed only after successful sampling.
    pub fn aggregate_short_challenges(
        &mut self,
        count: usize,
    ) -> Result<Vec<ProofPolynomial>, challenge::ChallengeError> {
        let mut pending = Self::from_state(self.state);
        let seed = pending.derive_reference_seed();
        let output = challenge::short_polynomial_challenges(&seed, 0, count)?;
        self.state = pending.state;
        Ok(output)
    }

    /// Pinned amortization schedule: one seed transition, then one separately
    /// initialized stream per polynomial with nonce 0,1,... . This is distinct
    /// from requesting one vector from a shared stream.
    pub fn amortized_short_challenges(
        &mut self,
        count: usize,
    ) -> Result<Vec<ProofPolynomial>, challenge::ChallengeError> {
        let mut output = Vec::new();
        output
            .try_reserve_exact(count)
            .map_err(|_| challenge::ChallengeError::Allocation)?;
        let mut pending = Self::from_state(self.state);
        let seed = pending.derive_reference_seed();
        for nonce in 0..count {
            output.extend(challenge::short_polynomial_challenges(
                &seed,
                nonce as u64,
                1,
            )?);
        }
        self.state = pending.state;
        Ok(output)
    }
    pub fn from_state(state: [u8; 32]) -> Self {
        Self { state }
    }
    pub fn state(&self) -> [u8; 32] {
        self.state
    }

    /// SHAKE128(old_state || bitpack(public_messages), 32).
    pub fn absorb_public_polynomials(&mut self, messages: &[ProofPolynomial]) {
        let mut hash = Shake128::default();
        Update::update(&mut hash, &self.state);
        for message in messages {
            Update::update(&mut hash, &message.reference_bitpack());
        }
        hash.finalize_xof().read(&mut self.state);
    }

    /// Common pinned seed transition: split SHAKE128(old_state,64) into the
    /// next 32-byte state and a 32-byte sampler seed. Does not select a sampler.
    pub fn derive_reference_seed(&mut self) -> [u8; 32] {
        let mut hash = Shake128::default();
        Update::update(&mut hash, &self.state);
        let mut reader = hash.finalize_xof();
        reader.read(&mut self.state);
        let mut seed = [0; 32];
        reader.read(&mut seed);
        seed
    }

    /// Exact sample_chalz behavior at q=2^38-107: low 32 bits of each little-
    /// endian 64-bit word, NOT uniform 38-bit ring residues. The state occupies
    /// the final 32 XOF bytes after each chunk of at most 100,000 challenges.
    /// Zero challenges leave state unchanged. Distribution must be included in
    /// the proof soundness analysis rather than inferred from upstream comments.
    pub fn scalar_challenges_32(&mut self, count: usize) -> Result<Vec<u32>, TranscriptError> {
        let mut output = Vec::new();
        output
            .try_reserve_exact(count)
            .map_err(|_| TranscriptError::Allocation)?;
        while output.len() < count {
            let chunk = (count - output.len()).min(100_000);
            let mut hash = Shake128::default();
            Update::update(&mut hash, &self.state);
            let mut reader = hash.finalize_xof();
            for _ in 0..chunk {
                let mut bytes = [0; 8];
                reader.read(&mut bytes);
                output.push(u32::from_le_bytes(bytes[..4].try_into().unwrap()));
            }
            reader.read(&mut self.state);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_and_amortized_schedules_advance_once_but_use_distinct_streams() {
        let initial = [17; 32];
        let mut aggregate = ReferenceTranscript::from_state(initial);
        let mut amortized = ReferenceTranscript::from_state(initial);
        let a = aggregate.aggregate_short_challenges(11).unwrap();
        let b = amortized.amortized_short_challenges(11).unwrap();
        assert_eq!(aggregate.state(), amortized.state());
        assert_ne!(aggregate.state(), initial);
        // The two schedules squeeze different buffer sizes and discard
        // leftovers per buffer, so even the first polynomial may differ.
        assert!(a.iter().zip(&b).skip(1).any(|(a, b)| *a.0 != *b.0));
        let mut zero = ReferenceTranscript::from_state(initial);
        assert!(zero.aggregate_short_challenges(0).unwrap().is_empty());
        assert_eq!(zero.state(), aggregate.state());
    }

    #[test]
    fn packing_and_chunked_transcript_match_independent_python_vectors() {
        use sha2::{Digest, Sha256};
        let hex = |bytes: &[u8]| bytes.iter().map(|v| format!("{v:02x}")).collect::<String>();
        let coefficients: Vec<_> = (0..DEGREE as u64)
            .map(|i| ((i.pow(3) * 104729 + MODULUS - 1 - i * 19) % MODULUS) as i64)
            .collect();
        let polynomial = ProofPolynomial::from_signed(&coefficients).unwrap();
        assert_eq!(
            hex(&Sha256::digest(polynomial.reference_bitpack())),
            "461f34231a6872a9538dbff8b9f0449bbc6893cbfd8cc84895c2f44bd9ae7852"
        );
        let mut transcript = ReferenceTranscript::from_state(std::array::from_fn(|i| i as u8));
        transcript.absorb_public_polynomials(&[polynomial]);
        assert_eq!(hex(&transcript.state()), "0c4fdaa9fbbfb24dfd581c7f9e5fa62a2e818eb8aa119f04ec79801747bdf610");
        assert_eq!(
            hex(&transcript.derive_reference_seed()),
            "6d9666ced828cc82aab9cd7190831f02354fb67bf07ca0f1c270c54d34da2080"
        );
        assert_eq!(hex(&transcript.state()), "95d3f9806d6842a236ca6bc40280a55bfc3f934658db95014b8dd8153a55ee1b");
        let challenges = transcript.scalar_challenges_32(100_001).unwrap();
        let mut hash = Sha256::new();
        for challenge in challenges {
            Digest::update(&mut hash, challenge.to_le_bytes());
        }
        assert_eq!(
            hex(&hash.finalize()),
            "295086d29c611e25ec92f92dc5add4431d324355c959d47e67b28db1e24763e3"
        );
        assert_eq!(hex(&transcript.state()), "306b1188d3150df2d0975796a6b5b06bcb38828fd5daf7df174263d3468a3ee9");
    }
    #[test]
    fn canonical_encoding_roundtrip_and_modulus_alias_rejection() {
        let mut coefficients: Vec<_> = (0..DEGREE)
            .map(|i| ((i as u64 * 104729 + 1) % MODULUS) as i64)
            .collect();
        coefficients[0] = MODULUS as i64 - 1;
        let polynomial = ProofPolynomial::from_signed(&coefficients).unwrap();
        let bytes = polynomial.reference_bitpack();
        assert_eq!(
            *ProofPolynomial::from_reference_bitpack(&bytes).unwrap().0,
            *polynomial.0
        );
        assert!(matches!(
            ProofPolynomial::from_reference_bitpack(&bytes[..1215]),
            Err(TranscriptError::Length)
        ));
        let invalid = ProofPolynomial(Zeroizing::new(vec![MODULUS; DEGREE]));
        assert!(matches!(
            ProofPolynomial::from_reference_bitpack(&invalid.reference_bitpack()),
            Err(TranscriptError::Noncanonical)
        ));
        let mut transcript = ReferenceTranscript::from_state([7; 32]);
        assert!(transcript.scalar_challenges_32(0).unwrap().is_empty());
        assert_eq!(transcript.state(), [7; 32]);
    }
}

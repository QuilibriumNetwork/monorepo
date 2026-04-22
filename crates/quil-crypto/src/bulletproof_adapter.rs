//! BulletproofProver implementation wrapping the ed448-bulletproofs
//! crate's `uniffi_bulletproofs` module.

use quil_types::crypto::{BulletproofProver, RangeProofResult};
use quil_types::error::Result;

/// DECAF448-based bulletproof prover.
pub struct Decaf448BulletproofProver;

impl BulletproofProver for Decaf448BulletproofProver {
    fn generate_range_proof(
        &self,
        values: &[Vec<u8>],
        blinding: &[u8],
        bit_size: u64,
    ) -> Result<RangeProofResult> {
        let result = bulletproofs::uniffi_bulletproofs::generate_range_proof(
            values.to_vec(),
            blinding.to_vec(),
            bit_size,
        );
        Ok(RangeProofResult {
            proof: result.proof,
            commitments: result.commitment,
        })
    }

    fn generate_input_commitments(
        &self,
        values: &[Vec<u8>],
        blinding: &[u8],
    ) -> Vec<u8> {
        bulletproofs::uniffi_bulletproofs::generate_input_commitments(
            values.to_vec(),
            blinding.to_vec(),
        )
    }

    fn verify_range_proof(&self, proof: &[u8], commitment: &[u8], bit_size: u64) -> bool {
        bulletproofs::uniffi_bulletproofs::verify_range_proof(
            proof.to_vec(), commitment.to_vec(), bit_size,
        )
    }

    fn sum_check(
        &self,
        inputs: &[Vec<u8>],
        additional_inputs: &[Vec<u8>],
        outputs: &[Vec<u8>],
        additional_outputs: &[Vec<u8>],
    ) -> bool {
        bulletproofs::uniffi_bulletproofs::sum_check(
            inputs.to_vec(), additional_inputs.to_vec(),
            outputs.to_vec(), additional_outputs.to_vec(),
        )
    }

    fn sign_hidden(&self, x: &[u8], t: &[u8], a: &[u8], r: &[u8]) -> Vec<u8> {
        bulletproofs::uniffi_bulletproofs::sign_hidden(
            x.to_vec(), t.to_vec(), a.to_vec(), r.to_vec(),
        )
    }

    fn verify_hidden(
        &self, c: &[u8], t: &[u8], s1: &[u8], s2: &[u8], s3: &[u8],
        point: &[u8], commitment: &[u8],
    ) -> bool {
        bulletproofs::uniffi_bulletproofs::verify_hidden(
            c.to_vec(), t.to_vec(), s1.to_vec(), s2.to_vec(),
            s3.to_vec(), point.to_vec(), commitment.to_vec(),
        )
    }

    fn simple_sign(&self, secret_key: &[u8], message: &[u8]) -> Vec<u8> {
        bulletproofs::uniffi_bulletproofs::sign_simple(
            secret_key.to_vec(), message.to_vec(),
        )
    }

    fn simple_verify(&self, message: &[u8], signature: &[u8], point: &[u8]) -> bool {
        bulletproofs::uniffi_bulletproofs::verify_simple(
            message.to_vec(), signature.to_vec(), point.to_vec(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_sign_verify_round_trip() {
        let prover = Decaf448BulletproofProver;
        let key_bytes = bulletproofs::uniffi_bulletproofs::keygen();
        let secret_key = &key_bytes[..56];
        let public_point = &key_bytes[56..];

        let message = b"test message";
        let signature = prover.simple_sign(secret_key, message);
        assert!(!signature.is_empty());
        assert!(prover.simple_verify(message, &signature, public_point));
    }

    #[test]
    fn simple_verify_rejects_wrong_message() {
        let prover = Decaf448BulletproofProver;
        let key_bytes = bulletproofs::uniffi_bulletproofs::keygen();
        let secret_key = &key_bytes[..56];
        let public_point = &key_bytes[56..];

        let signature = prover.simple_sign(secret_key, b"correct");
        assert!(!prover.simple_verify(b"wrong", &signature, public_point));
    }

    #[test]
    fn range_proof_rejects_garbage() {
        let prover = Decaf448BulletproofProver;
        assert!(!prover.verify_range_proof(&[0u8; 100], &[0u8; 56], 64));
    }
}

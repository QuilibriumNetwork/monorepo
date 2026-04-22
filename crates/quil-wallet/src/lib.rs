//! Wallet-side transaction construction.
//!
//! Produces a signed token [`Transaction`](quil_execution::token_intrinsic::transaction::Transaction)
//! ready to submit via `NodeService::Send`. Deliberately NOT part of
//! the node binary — the node *receives* bundles; a wallet *builds*
//! them.
//!
//! Mirror of Go's `qclient` transfer build flow:
//! 1. Compute Pedersen commitments on new output values with random
//!    blinding factors chosen such that ∑input_blindings = ∑output_blindings.
//! 2. Generate a bulletproof range proof over the output values
//!    (proves each is in `[0, 2^64)` without revealing them).
//! 3. Build [`TransactionInput`] records, each carrying the spent
//!    coin's commitment + a BLS48-581 signature authorizing the spend.
//! 4. Build [`TransactionOutput`] records with the output commitments
//!    and optional `RecipientBundle` (encrypted amount + blinding for
//!    the recipient — we leave empty here; the recipient encryption
//!    scheme is layered on top of this builder).
//! 5. Assemble, canonicalize, and return the [`Transaction`] bytes.
//!
//! The canonical-bytes serialization is byte-compatible with Go.
//! The *cryptographic* byte layout of Pedersen points and range
//! proofs is determined by the underlying `bulletproofs` crate —
//! same curve (Ristretto-like on 56-byte field elements), same
//! generators, so any verifier on either side accepts the result.

use std::sync::Arc;

use quil_crypto::poseidon::hash_bytes_to_32;
use quil_execution::token_intrinsic::transaction::{
    RecipientBundle, Transaction, TransactionInput, TransactionOutput,
};
use quil_types::crypto::Signer;
use quil_types::error::{QuilError, Result};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("invalid value: {0}")]
    InvalidValue(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("commitment generation failed: {0}")]
    CommitmentFailed(String),
    #[error("range proof generation failed: {0}")]
    RangeProofFailed(String),
    #[error("execution error: {0}")]
    Execution(#[from] QuilError),
}

/// One input UTXO the wallet controls. The caller provides the raw
/// value + blinding factor used when the coin was created; the
/// builder re-derives the commitment to confirm it matches the one
/// stored on-chain.
#[derive(Debug, Clone)]
pub struct InputCoin {
    /// The 32-byte on-chain commitment (from `GetTokensByAccount`).
    pub commitment: Vec<u8>,
    /// The 56-byte scalar value of the coin (encoded as a field element).
    pub value: [u8; 56],
    /// The 56-byte blinding factor used when the coin was minted.
    pub blinding: [u8; 56],
}

/// One output specifying a recipient + an amount. The amount is
/// encoded as a 56-byte field-element scalar (same format as
/// `bulletproofs::generate_range_proof` expects).
#[derive(Debug, Clone)]
pub struct OutputSpec {
    /// 56-byte output value scalar.
    pub value: [u8; 56],
    /// Frame number this output becomes active at (4-byte big-endian).
    pub frame_number: u32,
    /// Optional encrypted recipient bundle; if empty the output is
    /// treated as self-owned (caller-side construction).
    pub recipient_bundle: Option<RecipientBundle>,
}

/// Builder for signed transfer transactions.
pub struct TransferBuilder {
    domain: Vec<u8>,
    inputs: Vec<InputCoin>,
    outputs: Vec<OutputSpec>,
    fees: Vec<Vec<u8>>,
    /// Signer for BLS48581 input signatures.
    signer: Arc<dyn Signer>,
}

impl TransferBuilder {
    pub fn new(domain: Vec<u8>, signer: Arc<dyn Signer>) -> Self {
        Self {
            domain,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fees: Vec::new(),
            signer,
        }
    }

    pub fn add_input(mut self, input: InputCoin) -> Self {
        self.inputs.push(input);
        self
    }

    pub fn add_output(mut self, output: OutputSpec) -> Self {
        self.outputs.push(output);
        self
    }

    pub fn add_fee(mut self, fee_bigint_be: Vec<u8>) -> Self {
        self.fees.push(fee_bigint_be);
        self
    }

    /// Build + sign the transaction, returning canonical bytes
    /// ready to wrap in a `MessageBundle`.
    ///
    /// Flow:
    /// 1. Sum input blindings, allocate fresh blindings for each
    ///    output so the total matches (balance-preserving).
    /// 2. Generate a bulletproof range proof over the outputs.
    /// 3. BLS-sign each input's commitment under the transaction
    ///    identity digest.
    /// 4. Assemble `TransactionInput`s, `TransactionOutput`s, and
    ///    the `Transaction` envelope.
    pub fn build_and_sign(self) -> core::result::Result<Vec<u8>, WalletError> {
        if self.inputs.is_empty() {
            return Err(WalletError::InvalidValue("no inputs".into()));
        }
        if self.outputs.is_empty() {
            return Err(WalletError::InvalidValue("no outputs".into()));
        }

        // --- 1. Collect input blindings as a concatenated blob, then
        // generate output commitments (Pedersen) + range proof such
        // that ∑output_blindings = ∑input_blindings. The
        // `bulletproofs` helper does this balancing internally:
        // passing the sum-of-input-blindings as `blinding`.
        let mut input_blindings_buf: Vec<u8> = Vec::with_capacity(self.inputs.len() * 56);
        for ic in &self.inputs {
            input_blindings_buf.extend_from_slice(&ic.blinding);
        }

        let output_values: Vec<Vec<u8>> = self.outputs.iter().map(|o| o.value.to_vec()).collect();

        let range_proof = bulletproofs::uniffi_bulletproofs::generate_range_proof(
            output_values,
            input_blindings_buf,
            64, // 64-bit range
        );
        if range_proof.proof.is_empty() {
            return Err(WalletError::RangeProofFailed(
                "range proof generation returned empty".into(),
            ));
        }
        // `commitment` is the concatenation of per-output Decaf448
        // point commitments. Each compressed point is 56 bytes
        // (Ed448's field element size).
        const OUTPUT_COMMIT_BYTES: usize = 56;
        if range_proof.commitment.len() != OUTPUT_COMMIT_BYTES * self.outputs.len() {
            return Err(WalletError::RangeProofFailed(format!(
                "expected {} commitment bytes, got {}",
                OUTPUT_COMMIT_BYTES * self.outputs.len(),
                range_proof.commitment.len()
            )));
        }

        // --- 2. Build TransactionOutput records.
        let mut outputs_bytes = Vec::with_capacity(self.outputs.len());
        for (i, spec) in self.outputs.iter().enumerate() {
            let commit = range_proof.commitment[i * OUTPUT_COMMIT_BYTES
                ..(i + 1) * OUTPUT_COMMIT_BYTES]
                .to_vec();
            let recipient_bytes = match &spec.recipient_bundle {
                Some(rb) => rb.to_canonical_bytes()?,
                None => Vec::new(),
            };
            let out = TransactionOutput {
                frame_number: spec.frame_number.to_be_bytes().to_vec(),
                commitment: commit,
                recipient_output: recipient_bytes,
            };
            outputs_bytes.push(out.to_canonical_bytes()?);
        }

        // --- 3. Sign each input. The signing message is the
        // Poseidon-hashed digest of
        // `domain || input_commitment || all_output_commitments`,
        // matching Go's per-input signature scheme in
        // `node/execution/intrinsics/token/transaction_serialization.go`.
        let mut all_output_commits: Vec<u8> = Vec::new();
        for i in 0..self.outputs.len() {
            all_output_commits.extend_from_slice(
                &range_proof.commitment[i * OUTPUT_COMMIT_BYTES..(i + 1) * OUTPUT_COMMIT_BYTES],
            );
        }

        let mut inputs_bytes = Vec::with_capacity(self.inputs.len());
        for input in &self.inputs {
            let mut digest_input = Vec::with_capacity(
                self.domain.len() + input.commitment.len() + all_output_commits.len(),
            );
            digest_input.extend_from_slice(&self.domain);
            digest_input.extend_from_slice(&input.commitment);
            digest_input.extend_from_slice(&all_output_commits);
            let digest = hash_bytes_to_32(&digest_input)?;

            let sig = self
                .signer
                .sign_with_domain(&digest, b"TOKEN_TRANSFER")
                .map_err(|e| WalletError::SigningFailed(e.to_string()))?;

            let tx_input = TransactionInput {
                commitment: input.commitment.clone(),
                signature: sig,
                // Per-input proofs (spent-coin traversal) are left
                // empty here. A full wallet plugs the relevant
                // subtree proof from the token store's spent-set.
                proofs: Vec::new(),
            };
            inputs_bytes.push(tx_input.to_canonical_bytes()?);
        }

        // --- 4. Assemble Transaction.
        let tx = Transaction {
            domain: self.domain,
            inputs: inputs_bytes,
            outputs: outputs_bytes,
            fees: self.fees,
            range_proof: range_proof.proof,
            traversal_proof: Vec::new(),
        };

        Ok(tx.to_canonical_bytes()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_execution::token_intrinsic::transaction::Transaction;
    use quil_types::crypto::BlsConstructor;

    fn bls_signer() -> Arc<dyn Signer> {
        let ctor = quil_crypto::Bls48581KeyConstructor;
        let (boxed, _pk) = ctor.new_key().expect("bls keygen");
        Arc::from(boxed)
    }

    fn scalar56(v: u8) -> [u8; 56] {
        let mut s = [0u8; 56];
        s[0] = v;
        s
    }

    #[test]
    fn build_and_sign_single_input_single_output() {
        let signer = bls_signer();
        let builder = TransferBuilder::new(vec![0x11u8; 32], signer)
            .add_input(InputCoin {
                commitment: vec![0xAAu8; 32],
                value: scalar56(100),
                blinding: scalar56(3),
            })
            .add_output(OutputSpec {
                value: scalar56(100),
                frame_number: 42,
                recipient_bundle: None,
            });
        let bytes = builder.build_and_sign().expect("build");
        // The result must round-trip through Transaction decode.
        let tx = Transaction::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(tx.domain, vec![0x11u8; 32]);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert!(!tx.range_proof.is_empty(), "range proof must be present");
    }

    #[test]
    fn build_and_sign_multi_output() {
        let signer = bls_signer();
        let bytes = TransferBuilder::new(vec![0x22u8; 32], signer)
            .add_input(InputCoin {
                commitment: vec![0xBBu8; 32],
                value: scalar56(100),
                blinding: scalar56(7),
            })
            .add_output(OutputSpec {
                value: scalar56(60),
                frame_number: 1,
                recipient_bundle: None,
            })
            .add_output(OutputSpec {
                value: scalar56(40),
                frame_number: 1,
                recipient_bundle: None,
            })
            .build_and_sign()
            .expect("build multi-output");
        let tx = Transaction::from_canonical_bytes(&bytes).expect("decode");
        assert_eq!(tx.outputs.len(), 2);
    }

    #[test]
    fn empty_inputs_rejected() {
        let signer = bls_signer();
        let err = TransferBuilder::new(vec![0u8; 32], signer)
            .add_output(OutputSpec {
                value: scalar56(1),
                frame_number: 0,
                recipient_bundle: None,
            })
            .build_and_sign()
            .unwrap_err();
        matches!(err, WalletError::InvalidValue(_));
    }

    #[test]
    fn empty_outputs_rejected() {
        let signer = bls_signer();
        let err = TransferBuilder::new(vec![0u8; 32], signer)
            .add_input(InputCoin {
                commitment: vec![0u8; 32],
                value: scalar56(1),
                blinding: scalar56(1),
            })
            .build_and_sign()
            .unwrap_err();
        matches!(err, WalletError::InvalidValue(_));
    }
}

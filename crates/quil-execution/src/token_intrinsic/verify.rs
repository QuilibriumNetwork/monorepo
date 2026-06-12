//! Token transaction verification. Ports the crypto-level checks
//! from `token_intrinsic_transaction.go:1471-1601`.
//!
//! What's implemented:
//! - Structural validation (input/output counts, fee bounds)
//! - Bulletproof range proof verification
//! - Bulletproof sum check (inputs == outputs + fees)
//!
//! What's NOT implemented (needs state lookups):
//! - Per-input signature verification (needs traversal proof)
//! - Double-spend check (needs vertex lookup)
//! - Verification key uniqueness check (needs vertex lookup)
//! - Traversal proof verification (needs shard commits)

use num_bigint::BigInt;
use num_traits::One;
use quil_types::crypto::{BulletproofProver, DecafConstructor};
use quil_types::error::{QuilError, Result};

use super::transaction::{RecipientBundle, Transaction, TransactionInput, TransactionOutput};


/// Maximum number of inputs or outputs in a single transaction.
pub const MAX_IO_COUNT: usize = 100;
/// Range proof bit size (128 bits — covers values up to 2^128).
pub const RANGE_PROOF_BIT_SIZE: u64 = 128;

// =====================================================================
// Transaction challenge / transcript construction
// =====================================================================

/// Build the Schnorr-signature challenge transcript bytes that feed
/// into each input's hidden signature verification.
///
/// Mirrors Go's `Transaction.GetChallenge` at
/// `node/execution/intrinsics/token/token_intrinsic_transaction.go:1446-1467`
/// byte-for-byte:
///
/// ```text
/// transcript = Domain
///   || foreach output:
///        Commitment
///     || FrameNumber
///     || RecipientOutput.CoinBalance
///     || RecipientOutput.Mask
///     || RecipientOutput.OneTimeKey
///     || RecipientOutput.VerificationKey
///     || (if len(AdditionalReference) == 64) AdditionalReference || AdditionalReferenceKey
/// ```
///
/// The returned bytes are NOT the challenge itself — they're the input
/// to Decaf448 `hash_to_scalar`. Call `compute_transaction_challenge`
/// for the scalar. This is split out so callers can inspect / log the
/// pre-hash bytes if debugging cross-implementation mismatches.
///
/// Each output's `recipient_output` field is nested canonical bytes of
/// a `RecipientBundle` — we decode it here so the transcript layout
/// matches Go's struct-field order exactly.
pub fn build_transaction_transcript(tx: &Transaction) -> Result<Vec<u8>> {
    let mut transcript = Vec::with_capacity(tx.domain.len() + tx.outputs.len() * 256);
    transcript.extend_from_slice(&tx.domain);

    for (idx, out_bytes) in tx.outputs.iter().enumerate() {
        let out = TransactionOutput::from_canonical_bytes(out_bytes).map_err(|e| {
            QuilError::InvalidArgument(format!(
                "transaction transcript: output {idx} decode: {e}"
            ))
        })?;

        transcript.extend_from_slice(&out.commitment);
        transcript.extend_from_slice(&out.frame_number);

        let recipient = RecipientBundle::from_canonical_bytes(&out.recipient_output).map_err(|e| {
            QuilError::InvalidArgument(format!(
                "transaction transcript: output {idx} recipient decode: {e}"
            ))
        })?;

        // Go layout: CoinBalance || Mask || OneTimeKey || VerificationKey
        // (note this is NOT the same order as RecipientBundle's canonical
        // bytes layout, which is OneTimeKey || VerificationKey || CoinBalance
        // || Mask. Must follow Go's transcript ordering.)
        transcript.extend_from_slice(&recipient.coin_balance);
        transcript.extend_from_slice(&recipient.mask);
        transcript.extend_from_slice(&recipient.one_time_key);
        transcript.extend_from_slice(&recipient.verification_key);

        // AdditionalReference is only appended when it's exactly 64 bytes —
        // matches Go's `len(o.RecipientOutput.AdditionalReference) == 64`
        // guard at :1456. Shorter/absent → both fields skipped.
        if recipient.additional_reference.len() == 64 {
            transcript.extend_from_slice(&recipient.additional_reference);
            transcript.extend_from_slice(&recipient.additional_reference_key);
        }
    }

    Ok(transcript)
}

/// Compute the transaction challenge scalar. Equivalent to Go's
/// `Transaction.GetChallenge() -> Private()` — the Decaf448
/// `hash_to_scalar` of the transcript bytes from
/// `build_transaction_transcript`. The resulting scalar is passed as
/// the `transcript` (confusingly named, but matches Go) argument to
/// `verify_input_hidden_signature`.
pub fn compute_transaction_challenge(
    tx: &Transaction,
    decaf: &dyn DecafConstructor,
) -> Result<Vec<u8>> {
    let transcript = build_transaction_transcript(tx)?;
    decaf.hash_to_scalar(&transcript)
}

// =====================================================================
// Transaction input hidden signature verification
// =====================================================================

/// Verify the hidden Schnorr signature on a single transaction input.
///
/// The 336-byte signature decomposes as 6×56 DECAF448 scalars/points:
/// - `[0..56]`: challenge (c)
/// - `[56..112]`: s1
/// - `[112..168]`: s2
/// - `[168..224]`: s3
/// - `[224..280]`: point (verification key)
/// - `[280..336]`: commitment
///
/// `transcript` is the **scalar** produced by Decaf448 `hash_to_scalar`
/// over the transcript bytes — call `compute_transaction_challenge`
/// to produce it correctly. Historical note: a prior comment here
/// described the transcript as "SHA3 of the domain + input + output
/// commitments", which was wrong in both the hash algorithm and the
/// field layout. Go hashes with Decaf's `HashToScalar` over a specific
/// per-output sequence (see `build_transaction_transcript`).
pub fn verify_input_hidden_signature(
    bp: &dyn BulletproofProver,
    signature: &[u8],
    transcript: &[u8],
) -> Result<bool> {
    if signature.len() != 336 {
        return Err(QuilError::InvalidArgument(format!(
            "input signature: expected 336 bytes, got {}", signature.len()
        )));
    }

    let c = &signature[0..56];
    let s1 = &signature[56..112];
    let s2 = &signature[112..168];
    let s3 = &signature[168..224];
    let point = &signature[224..280];
    let commitment = &signature[280..336];

    Ok(bp.verify_hidden(c, transcript, s1, s2, s3, point, commitment))
}

/// Validate structural properties of a transaction input.
///
/// Checks:
/// - Commitment is 56 bytes
/// - Signature is 336 bytes
/// - Commitment matches the commitment embedded in the signature
///   (bytes [280..336] must equal the commitment field)
pub fn validate_input_structural(
    commitment: &[u8],
    signature: &[u8],
) -> Result<()> {
    if commitment.len() != 56 {
        return Err(QuilError::InvalidArgument(format!(
            "input: commitment is {} bytes (expected 56)", commitment.len()
        )));
    }
    if signature.len() != 336 {
        return Err(QuilError::InvalidArgument(format!(
            "input: signature is {} bytes (expected 336)", signature.len()
        )));
    }
    // Commitment must match the commitment embedded in signature[280..336]
    if commitment != &signature[280..336] {
        return Err(QuilError::InvalidArgument(
            "input: commitment doesn't match signature".into(),
        ));
    }
    Ok(())
}

/// Structural validation of a transaction's input/output counts and
/// fee values.
pub fn validate_transaction_structural(
    input_count: usize,
    output_count: usize,
    fees: &[Vec<u8>],
    behavior: u16,
    traversal_proof_subproof_count: usize,
) -> Result<()> {
    if input_count == 0 || output_count == 0 {
        return Err(QuilError::InvalidArgument(
            "transaction: zero inputs or outputs".into(),
        ));
    }
    if input_count > MAX_IO_COUNT || output_count > MAX_IO_COUNT {
        return Err(QuilError::InvalidArgument(format!(
            "transaction: too many inputs ({}) or outputs ({})",
            input_count, output_count
        )));
    }
    if input_count != traversal_proof_subproof_count {
        return Err(QuilError::InvalidArgument(format!(
            "transaction: input count ({}) != subproof count ({})",
            input_count, traversal_proof_subproof_count
        )));
    }

    // Validate fee values are in [0, 2^128]
    let max_fee = BigInt::one() << 128u32;
    for (i, fee_bytes) in fees.iter().enumerate() {
        let fee = BigInt::from_bytes_be(num_bigint::Sign::Plus, fee_bytes);
        if fee > max_fee || fee < BigInt::from(0) {
            return Err(QuilError::InvalidArgument(format!(
                "transaction: fee {} out of range", i
            )));
        }
    }

    // Non-divisible tokens require matching input/output counts
    if behavior & super::constants::DIVISIBLE == 0 && input_count != output_count {
        return Err(QuilError::InvalidArgument(
            "transaction: non-divisible token has mismatching inputs and outputs".into(),
        ));
    }

    Ok(())
}

/// Verify the bulletproof range proof and sum check for a transaction.
///
/// This is the core crypto verification that doesn't need state lookups:
/// 1. Verify range proof: all output commitments are in [0, 2^128]
/// 2. Verify sum check: input commitments == output commitments + fees
///
/// `input_commitments`: 56-byte DECAF448 point per input
/// `output_commitments`: 56-byte DECAF448 point per output
/// `fees`: big-endian serialized fee values (for QUIL token domain)
/// `range_proof`: the serialized bulletproof
pub fn verify_transaction_crypto(
    bulletproof_prover: &dyn BulletproofProver,
    input_commitments: &[Vec<u8>],
    output_commitments: &[Vec<u8>],
    fees: &[Vec<u8>],
    range_proof: &[u8],
    is_quil_domain: bool,
) -> Result<bool> {
    // Build the concatenated commitment bytes for range proof verification
    let mut commitment_bytes = Vec::with_capacity(output_commitments.len() * 56);
    for c in output_commitments {
        if c.len() != 56 {
            return Err(QuilError::InvalidArgument(format!(
                "transaction: output commitment is {} bytes (expected 56)",
                c.len()
            )));
        }
        commitment_bytes.extend_from_slice(c);
    }

    // 1. Range proof: verify all outputs are in valid range
    if !bulletproof_prover.verify_range_proof(range_proof, &commitment_bytes, RANGE_PROOF_BIT_SIZE) {
        return Ok(false);
    }

    // 2. Sum check: inputs == outputs + fees
    let sumcheck_fees = if is_quil_domain {
        fees.to_vec()
    } else {
        vec![]
    };

    if !bulletproof_prover.sum_check(
        input_commitments,
        &[], // no additional inputs
        output_commitments,
        &sumcheck_fees,
    ) {
        return Ok(false);
    }

    Ok(true)
}

/// Structural validation for a MintTransaction. Same checks but
/// without traversal proof subproof count (mints have no traversal).
pub fn validate_mint_transaction_structural(
    input_count: usize,
    output_count: usize,
    fees: &[Vec<u8>],
    behavior: u16,
) -> Result<()> {
    if input_count == 0 || output_count == 0 {
        return Err(QuilError::InvalidArgument("mint: zero inputs or outputs".into()));
    }
    if input_count > MAX_IO_COUNT || output_count > MAX_IO_COUNT {
        return Err(QuilError::InvalidArgument(format!("mint: too many I/O ({}/{})", input_count, output_count)));
    }
    let max_fee = BigInt::one() << 128u32;
    for (i, fb) in fees.iter().enumerate() {
        let fee = BigInt::from_bytes_be(num_bigint::Sign::Plus, fb);
        if fee > max_fee { return Err(QuilError::InvalidArgument(format!("mint: fee {} out of range", i))); }
    }
    if behavior & super::constants::DIVISIBLE == 0 && input_count != output_count {
        return Err(QuilError::InvalidArgument("mint: non-divisible mismatched I/O".into()));
    }
    Ok(())
}

/// Verify bulletproof crypto for MintTransaction. No fees in sum check.
pub fn verify_mint_transaction_crypto(
    bp: &dyn BulletproofProver,
    input_commitments: &[Vec<u8>],
    output_commitments: &[Vec<u8>],
    range_proof: &[u8],
) -> Result<bool> {
    let mut cb = Vec::with_capacity(output_commitments.len() * 56);
    for c in output_commitments {
        if c.len() != 56 { return Err(QuilError::InvalidArgument("mint: bad commitment size".into())); }
        cb.extend_from_slice(c);
    }
    if !bp.verify_range_proof(range_proof, &cb, RANGE_PROOF_BIT_SIZE) { return Ok(false); }
    if !bp.sum_check(input_commitments, &[], output_commitments, &[]) { return Ok(false); }
    Ok(true)
}
/// Build the transcript bytes for a MintTransaction (see Go
/// `MintTransaction.GetChallenge` at `token_intrinsic_mint_transaction.go:2666-2692`).
///
/// Differs from the standard transcript in that it includes per-input
/// proofs *before* the domain/outputs section and lays out outputs in a
/// slightly different field order (AdditionalReference immediately
/// after FrameNumber).
pub fn build_mint_transaction_transcript(
    domain: &[u8],
    input_proofs: &[Vec<Vec<u8>>],
    outputs: &[super::mint::MintTransactionOutput],
    recipients: &[RecipientBundle],
) -> Result<Vec<u8>> {
    if outputs.len() != recipients.len() {
        return Err(QuilError::InvalidArgument(
            "build_mint_transaction_transcript: output/recipient length mismatch".into(),
        ));
    }
    let mut t = Vec::new();
    for proofs in input_proofs {
        for p in proofs {
            t.extend_from_slice(p);
        }
    }
    t.extend_from_slice(domain);
    for (o, r) in outputs.iter().zip(recipients.iter()) {
        t.extend_from_slice(&o.commitment);
        t.extend_from_slice(&o.frame_number);
        if r.additional_reference.len() == 64 {
            t.extend_from_slice(&r.additional_reference);
            t.extend_from_slice(&r.additional_reference_key);
        }
        t.extend_from_slice(&r.coin_balance);
        t.extend_from_slice(&r.mask);
        t.extend_from_slice(&r.one_time_key);
        t.extend_from_slice(&r.verification_key);
    }
    Ok(t)
}

/// Build the transcript bytes for a PendingTransaction (see Go
/// `PendingTransaction.GetChallenge` at
/// `token_intrinsic_pending_transaction.go:1532-1559`).
///
/// The pending transcript has two recipient bundles (to, refund) per
/// output and an Expiration u64 appended after the commitment.
pub fn build_pending_transaction_transcript(
    domain: &[u8],
    outputs: &[super::pending::PendingTransactionOutput],
    to_recipients: &[RecipientBundle],
    refund_recipients: &[RecipientBundle],
) -> Result<Vec<u8>> {
    if outputs.len() != to_recipients.len() || outputs.len() != refund_recipients.len() {
        return Err(QuilError::InvalidArgument(
            "build_pending_transaction_transcript: output/recipient length mismatch".into(),
        ));
    }
    let mut t = Vec::new();
    t.extend_from_slice(domain);
    for ((o, to), refund) in outputs
        .iter()
        .zip(to_recipients.iter())
        .zip(refund_recipients.iter())
    {
        t.extend_from_slice(&o.commitment);
        t.extend_from_slice(&o.expiration.to_be_bytes());
        t.extend_from_slice(&o.frame_number);
        if to.additional_reference.len() == 64 {
            t.extend_from_slice(&to.additional_reference);
            t.extend_from_slice(&to.additional_reference_key);
        }
        t.extend_from_slice(&to.coin_balance);
        t.extend_from_slice(&to.mask);
        t.extend_from_slice(&to.one_time_key);
        t.extend_from_slice(&to.verification_key);
        if refund.additional_reference.len() == 64 {
            t.extend_from_slice(&refund.additional_reference);
            t.extend_from_slice(&refund.additional_reference_key);
        }
        t.extend_from_slice(&refund.coin_balance);
        t.extend_from_slice(&refund.mask);
        t.extend_from_slice(&refund.one_time_key);
        t.extend_from_slice(&refund.verification_key);
    }
    Ok(t)
}

// =====================================================================
// Non-divisible propagation check
// =====================================================================

/// For a non-divisible token, each output's `AdditionalReference` /
/// `AdditionalReferenceKey` must equal the last 128 bytes of the
/// matching input's last proof (`proofs[-1][:64]` and `[64:128]`).
///
/// Port of `token_intrinsic_transaction.go:1532-1541`:
/// ```go
/// if tx.config.Behavior&Divisible == 0 {
///     if !bytes.Equal(
///         o.RecipientOutput.AdditionalReference,
///         tx.Inputs[i].Proofs[len(tx.Inputs[i].Proofs)-1][:64],
///     ) || !bytes.Equal(
///         o.RecipientOutput.AdditionalReferenceKey,
///         tx.Inputs[i].Proofs[len(tx.Inputs[i].Proofs)-1][64:],
///     ) {
///         return false, errors.Wrap(errors.New("invalid reference"), ...)
///     }
/// }
/// ```
pub fn check_non_divisible_propagation(
    behavior: u16,
    inputs: &[TransactionInput],
    outputs: &[TransactionOutput],
    recipients: &[RecipientBundle],
) -> Result<()> {
    // Only applies to non-divisible tokens
    if behavior & super::constants::DIVISIBLE != 0 {
        return Ok(());
    }
    if inputs.len() != outputs.len() || inputs.len() != recipients.len() {
        return Err(QuilError::InvalidArgument(
            "non-divisible propagation: input/output/recipient length mismatch".into(),
        ));
    }
    for (i, r) in recipients.iter().enumerate() {
        let proofs = &inputs[i].proofs;
        let last = proofs.last().ok_or_else(|| {
            QuilError::InvalidArgument(format!(
                "non-divisible propagation: input {} has no proofs",
                i
            ))
        })?;
        if last.len() < 128 {
            return Err(QuilError::InvalidArgument(format!(
                "non-divisible propagation: input {} last proof too short ({} < 128)",
                i,
                last.len()
            )));
        }
        if r.additional_reference != last[..64]
            || r.additional_reference_key != last[64..128]
        {
            return Err(QuilError::InvalidArgument(format!(
                "non-divisible propagation: output {} reference mismatch",
                i
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_intrinsic::constants::QUIL_BEHAVIOR;
    use quil_types::crypto::RangeProofResult;

    // =================================================================
    // Transcript construction tests
    // =================================================================

    fn mk_recipient(extra: Option<(&[u8; 64], &[u8])>) -> Vec<u8> {
        let mut rb = RecipientBundle {
            one_time_key: vec![0x11u8; 56],
            verification_key: vec![0x22u8; 56],
            coin_balance: vec![0x33u8; 16],
            mask: vec![0x44u8; 56],
            additional_reference: vec![],
            additional_reference_key: vec![],
        };
        if let Some((r, k)) = extra {
            rb.additional_reference = r.to_vec();
            rb.additional_reference_key = k.to_vec();
        }
        rb.to_canonical_bytes().unwrap()
    }

    fn mk_output(recipient_bytes: Vec<u8>) -> Vec<u8> {
        let out = TransactionOutput {
            frame_number: 42u64.to_be_bytes().to_vec(),
            commitment: vec![0x55u8; 56],
            recipient_output: recipient_bytes,
        };
        out.to_canonical_bytes().unwrap()
    }

    #[test]
    fn transcript_layout_matches_go_field_order() {
        // Go's transcript for one output without AdditionalReference:
        //   domain || commitment || frame_number || coin_balance || mask
        //         || one_time_key || verification_key
        let tx = Transaction {
            domain: vec![0xAAu8; 32],
            inputs: vec![],
            outputs: vec![mk_output(mk_recipient(None))],
            fees: vec![],
            range_proof: vec![],
            traversal_proof: vec![],
        };

        let transcript = build_transaction_transcript(&tx).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&[0xAAu8; 32]);           // domain
        expected.extend_from_slice(&[0x55u8; 56]);           // commitment
        expected.extend_from_slice(&42u64.to_be_bytes());    // frame_number
        expected.extend_from_slice(&[0x33u8; 16]);           // coin_balance
        expected.extend_from_slice(&[0x44u8; 56]);           // mask
        expected.extend_from_slice(&[0x11u8; 56]);           // one_time_key
        expected.extend_from_slice(&[0x22u8; 56]);           // verification_key

        assert_eq!(transcript, expected);
    }

    #[test]
    fn transcript_appends_additional_reference_only_at_64_bytes() {
        // Go: `if len(o.RecipientOutput.AdditionalReference) == 64` —
        // 63 or 65 bytes must NOT trigger the append.
        let ref_64 = [0xBBu8; 64];
        let key_bytes = vec![0xCCu8; 48];

        let tx = Transaction {
            domain: vec![],
            inputs: vec![],
            outputs: vec![mk_output(mk_recipient(Some((&ref_64, &key_bytes))))],
            fees: vec![],
            range_proof: vec![],
            traversal_proof: vec![],
        };
        let with_ref = build_transaction_transcript(&tx).unwrap();

        // Same tx with shorter reference — should NOT append.
        let mut rb_short = RecipientBundle {
            one_time_key: vec![0x11u8; 56],
            verification_key: vec![0x22u8; 56],
            coin_balance: vec![0x33u8; 16],
            mask: vec![0x44u8; 56],
            additional_reference: vec![0xBBu8; 63],
            additional_reference_key: vec![0xCCu8; 48],
        };
        let tx_short = Transaction {
            domain: vec![],
            inputs: vec![],
            outputs: vec![mk_output(rb_short.to_canonical_bytes().unwrap())],
            fees: vec![],
            range_proof: vec![],
            traversal_proof: vec![],
        };
        let without_ref = build_transaction_transcript(&tx_short).unwrap();

        assert_eq!(
            with_ref.len(),
            without_ref.len() + 64 + key_bytes.len(),
            "64-byte AdditionalReference appends ref + ref_key; shorter does not"
        );
        // And longer than 64 must also NOT append.
        rb_short.additional_reference = vec![0xBBu8; 65];
        let tx_long = Transaction {
            domain: vec![],
            inputs: vec![],
            outputs: vec![mk_output(rb_short.to_canonical_bytes().unwrap())],
            fees: vec![],
            range_proof: vec![],
            traversal_proof: vec![],
        };
        let long = build_transaction_transcript(&tx_long).unwrap();
        assert_eq!(long.len(), without_ref.len(), "≠64 bytes = skip");
    }

    #[test]
    fn transcript_multiple_outputs_concatenates_in_order() {
        let tx = Transaction {
            domain: vec![0xDD; 8],
            inputs: vec![],
            outputs: vec![
                mk_output(mk_recipient(None)),
                mk_output(mk_recipient(None)),
                mk_output(mk_recipient(None)),
            ],
            fees: vec![],
            range_proof: vec![],
            traversal_proof: vec![],
        };

        let t = build_transaction_transcript(&tx).unwrap();
        // Per-output contribution is fixed size with no AdditionalReference:
        //   56 (commitment) + 8 (frame) + 16 + 56 + 56 + 56 = 248 bytes.
        let per_output = 248;
        assert_eq!(t.len(), 8 /* domain */ + 3 * per_output);
    }


    // Stub prover that always accepts/rejects
    struct AcceptProver;
    impl BulletproofProver for AcceptProver {
        fn generate_range_proof(&self, _: &[Vec<u8>], _: &[u8], _: u64) -> Result<RangeProofResult> { Err(QuilError::Internal("range proof generation not supported".into())) }
        fn generate_input_commitments(&self, _: &[Vec<u8>], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_range_proof(&self, _: &[u8], _: &[u8], _: u64) -> bool { true }
        fn sum_check(&self, _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>]) -> bool { true }
        fn sign_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> bool { true }
        fn simple_sign(&self, _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn simple_verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool { true }
    }

    struct RejectProver;
    impl BulletproofProver for RejectProver {
        fn generate_range_proof(&self, _: &[Vec<u8>], _: &[u8], _: u64) -> Result<RangeProofResult> { Err(QuilError::Internal("range proof generation not supported".into())) }
        fn generate_input_commitments(&self, _: &[Vec<u8>], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_range_proof(&self, _: &[u8], _: &[u8], _: u64) -> bool { false }
        fn sum_check(&self, _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>]) -> bool { false }
        fn sign_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> bool { false }
        fn simple_sign(&self, _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn simple_verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool { false }
    }

    // -- Structural validation --

    #[test]
    fn structural_accepts_valid() {
        assert!(validate_transaction_structural(2, 3, &[], QUIL_BEHAVIOR, 2).is_ok());
    }

    #[test]
    fn structural_rejects_zero_inputs() {
        assert!(validate_transaction_structural(0, 1, &[], QUIL_BEHAVIOR, 0).is_err());
    }

    #[test]
    fn structural_rejects_zero_outputs() {
        assert!(validate_transaction_structural(1, 0, &[], QUIL_BEHAVIOR, 1).is_err());
    }

    #[test]
    fn structural_rejects_too_many_inputs() {
        assert!(validate_transaction_structural(101, 1, &[], QUIL_BEHAVIOR, 101).is_err());
    }

    #[test]
    fn structural_rejects_mismatched_subproof_count() {
        assert!(validate_transaction_structural(2, 2, &[], QUIL_BEHAVIOR, 3).is_err());
    }

    #[test]
    fn structural_rejects_oversized_fee() {
        let huge = vec![0xFFu8; 32]; // way over 2^128
        assert!(validate_transaction_structural(1, 1, &[huge], QUIL_BEHAVIOR, 1).is_err());
    }

    #[test]
    fn structural_non_divisible_rejects_mismatched_io() {
        // behavior=0 means not divisible
        assert!(validate_transaction_structural(2, 3, &[], 0, 2).is_err());
    }

    #[test]
    fn structural_non_divisible_accepts_matched_io() {
        assert!(validate_transaction_structural(2, 2, &[], 0, 2).is_ok());
    }

    // -- Crypto verification --

    #[test]
    fn crypto_accepts_with_accept_prover() {
        let inputs = vec![vec![0xAAu8; 56], vec![0xBBu8; 56]];
        let outputs = vec![vec![0xCCu8; 56]];
        let result = verify_transaction_crypto(
            &AcceptProver, &inputs, &outputs, &[], b"proof", true,
        ).unwrap();
        assert!(result);
    }

    #[test]
    fn crypto_rejects_with_reject_prover() {
        let inputs = vec![vec![0xAAu8; 56]];
        let outputs = vec![vec![0xBBu8; 56]];
        let result = verify_transaction_crypto(
            &RejectProver, &inputs, &outputs, &[], b"proof", true,
        ).unwrap();
        assert!(!result);
    }

    #[test]
    fn crypto_rejects_wrong_commitment_size() {
        let inputs = vec![vec![0xAAu8; 56]];
        let outputs = vec![vec![0xBBu8; 32]]; // wrong size
        assert!(verify_transaction_crypto(
            &AcceptProver, &inputs, &outputs, &[], b"proof", true,
        ).is_err());
    }

    #[test]
    fn crypto_passes_fees_only_for_quil_domain() {
        // This just exercises the code path — actual sum_check behavior
        // depends on the prover.
        let inputs = vec![vec![0xAAu8; 56]];
        let outputs = vec![vec![0xBBu8; 56]];
        let fees = vec![vec![0, 100]]; // 100 in big-endian
        assert!(verify_transaction_crypto(
            &AcceptProver, &inputs, &outputs, &fees, b"proof", true,
        ).unwrap());
        assert!(verify_transaction_crypto(
            &AcceptProver, &inputs, &outputs, &fees, b"proof", false,
        ).unwrap());
    }

    // -- Mint structural validation --

    #[test]
    fn mint_structural_accepts_valid() {
        assert!(validate_mint_transaction_structural(2, 3, &[], QUIL_BEHAVIOR).is_ok());
    }

    #[test]
    fn mint_structural_rejects_zero_inputs() {
        assert!(validate_mint_transaction_structural(0, 1, &[], QUIL_BEHAVIOR).is_err());
    }

    #[test]
    fn mint_structural_rejects_too_many() {
        assert!(validate_mint_transaction_structural(101, 1, &[], QUIL_BEHAVIOR).is_err());
    }

    // -- Input signature verification --

    #[test]
    fn input_structural_accepts_valid() {
        let mut sig = vec![0u8; 336];
        let commitment = vec![0xAAu8; 56];
        sig[280..336].copy_from_slice(&commitment);
        assert!(validate_input_structural(&commitment, &sig).is_ok());
    }

    #[test]
    fn input_structural_rejects_wrong_commitment_size() {
        assert!(validate_input_structural(&[0u8; 32], &[0u8; 336]).is_err());
    }

    #[test]
    fn input_structural_rejects_wrong_sig_size() {
        assert!(validate_input_structural(&[0u8; 56], &[0u8; 100]).is_err());
    }

    #[test]
    fn input_structural_rejects_mismatched_commitment() {
        let commitment = vec![0xAAu8; 56];
        let sig = vec![0xBBu8; 336]; // commitment in sig is 0xBB, not 0xAA
        assert!(validate_input_structural(&commitment, &sig).is_err());
    }

    #[test]
    fn input_hidden_sig_accepts_with_accept_prover() {
        let sig = vec![0xAAu8; 336];
        assert!(verify_input_hidden_signature(&AcceptProver, &sig, b"transcript").unwrap());
    }

    #[test]
    fn input_hidden_sig_rejects_with_reject_prover() {
        let sig = vec![0xAAu8; 336];
        assert!(!verify_input_hidden_signature(&RejectProver, &sig, b"transcript").unwrap());
    }

    #[test]
    fn input_hidden_sig_rejects_wrong_size() {
        assert!(verify_input_hidden_signature(&AcceptProver, &[0u8; 100], b"transcript").is_err());
    }

    // -- PendingTransaction --

    #[test]
    fn pending_structural_accepts_valid() {
        assert!(validate_transaction_structural(2, 3, &[], QUIL_BEHAVIOR, 2).is_ok());
    }

    #[test]
    fn pending_crypto_accepts_with_accept_prover() {
        let inputs = vec![vec![0xAAu8; 56]];
        let outputs = vec![vec![0xBBu8; 56]];
        // PendingTransaction sum check includes fees for QUIL domain
        assert!(verify_transaction_crypto(&AcceptProver, &inputs, &outputs, &[vec![0, 50]], b"proof", true).unwrap());
    }

    // -- Mint crypto verification --

    #[test]
    fn mint_crypto_accepts_with_accept_prover() {
        let inputs = vec![vec![0xAAu8; 56]];
        let outputs = vec![vec![0xBBu8; 56]];
        assert!(verify_mint_transaction_crypto(&AcceptProver, &inputs, &outputs, b"proof").unwrap());
    }

    #[test]
    fn mint_crypto_rejects_with_reject_prover() {
        let inputs = vec![vec![0xAAu8; 56]];
        let outputs = vec![vec![0xBBu8; 56]];
        assert!(!verify_mint_transaction_crypto(&RejectProver, &inputs, &outputs, b"proof").unwrap());
    }
}

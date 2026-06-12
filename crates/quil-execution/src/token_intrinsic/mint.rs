//! Mint transaction types: MintTransactionInput (0x050D),
//! MintTransactionOutput (0x050E), MintTransaction (0x050F).
//!
//! Ports `node/execution/intrinsics/token/token_intrinsic_mint_transaction.go`.
//!
//! All five mint behaviors that the Go node ships are implemented here:
//!
//! Verify (per-input + tx-level wrappers):
//! - `verify_authority` — `MintWithAuthority` (genesis + coinbase),
//!   the canonical 9-check chain (Go `verifyWithMintWithAuthority`).
//! - `verify_with_signature` / `verify_mint_transaction_signature` —
//!   `MintWithSignature`. Same 9 input checks as authority plus the
//!   per-output `output[i].VerificationKey == input[i].proofs[0][32..88]`
//!   constraint (Go `MintTransactionOutput.Verify` line 2061-2070).
//! - `verify_verkle_multiproof_input` /
//!   `verify_mint_transaction_verkle` — `MintWithProof +
//!   VerkleMultiproofWithSignature` (Go
//!   `verifyWithVerkleMultiproofSignature`).
//! - `verify_with_payment_input` / `verify_mint_transaction_payment` —
//!   `MintWithPayment` (free-mint and paid-mint flows; nested
//!   PendingTransaction verification is delegated to a caller-supplied
//!   closure).
//! - `verify_pomw_input` + `verify_mint_transaction_pomw` — the
//!   13-check `MintWithProof + ProofOfMeaningfulWork` chain.
//!
//! Materialize:
//! - `materialize_authority` — shared output writer for Authority,
//!   Signature, Verkle, and Payment variants. Writes each output as a
//!   coin vertex plus a spent marker per input at `poseidon(proofs[0])`.
//! - `materialize_pomw` — the PoMW supply-invariant variant; decrements
//!   the prover reward balance for each input before delegating coin
//!   creation to `materialize_authority`.
//!
//! Wire format: all variants share the same canonical-bytes triple
//! (0x050D / 0x050E / 0x050F). The variant in force is selected by the
//! token's `MintStrategy.MintBehavior` (+ `ProofBasis` for `MintWithProof`)
//! at runtime via `TokenConfigResolver::mint_variant_for_domain`.

use quil_types::crypto::{
    BulletproofProver, DecafConstructor, InclusionProver, KeyManager, KeyType,
};
use quil_types::error::{QuilError, Result};
use super::cursor::*;

pub const TYPE_MINT_TRANSACTION_INPUT: u32 = 0x050D;
pub const TYPE_MINT_TRANSACTION_OUTPUT: u32 = 0x050E;
pub const TYPE_MINT_TRANSACTION: u32 = 0x050F;

// PoMW constants — see Go `token_intrinsic_mint_transaction.go:1693-1811`.
const PROVER_ADDR_LEN: usize = 32;
const BLS48581_G2_PUBKEY_LEN: usize = 585;
const BLS48581_G1_SIG_LEN: usize = 74;
const POMW_PROOF1_MIN_LEN: usize =
    PROVER_ADDR_LEN + BLS48581_G2_PUBKEY_LEN + BLS48581_G1_SIG_LEN;
const DECAF_ELEM_LEN: usize = 56;
const HIDDEN_SIG_LEN: usize = 6 * DECAF_ELEM_LEN;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MintTransactionInput {
    pub value: Vec<u8>,
    pub commitment: Vec<u8>,
    pub signature: Vec<u8>,
    pub proofs: Vec<Vec<u8>>,
    pub additional_reference: Vec<u8>,
    pub additional_reference_key: Vec<u8>,
}

impl MintTransactionInput {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_MINT_TRANSACTION_INPUT);
        put_lp(&mut out, &self.value);
        put_lp(&mut out, &self.commitment);
        put_lp(&mut out, &self.signature);
        write_array(&mut out, &self.proofs);
        put_lp(&mut out, &self.additional_reference);
        put_lp(&mut out, &self.additional_reference_key);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_MINT_TRANSACTION_INPUT, "MintTransactionInput")?;
        Ok(Self {
            value: read_lp(data, &mut c)?,
            commitment: read_lp(data, &mut c)?,
            signature: read_lp(data, &mut c)?,
            proofs: read_array(data, &mut c)?,
            additional_reference: read_lp(data, &mut c)?,
            additional_reference_key: read_lp(data, &mut c)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MintTransactionOutput {
    pub frame_number: Vec<u8>,
    pub commitment: Vec<u8>,
    pub recipient_output: Vec<u8>, // nested RecipientBundle canonical bytes
}

impl MintTransactionOutput {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_MINT_TRANSACTION_OUTPUT);
        put_lp(&mut out, &self.frame_number);
        put_lp(&mut out, &self.commitment);
        put_lp(&mut out, &self.recipient_output);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_MINT_TRANSACTION_OUTPUT, "MintTransactionOutput")?;
        Ok(Self {
            frame_number: read_lp(data, &mut c)?,
            commitment: read_lp(data, &mut c)?,
            recipient_output: read_lp(data, &mut c)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MintTransaction {
    pub domain: Vec<u8>,
    pub inputs: Vec<Vec<u8>>,
    pub outputs: Vec<Vec<u8>>,
    pub fees: Vec<Vec<u8>>,
    pub range_proof: Vec<u8>,
}

impl MintTransaction {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_MINT_TRANSACTION);
        put_lp(&mut out, &self.domain);
        write_array(&mut out, &self.inputs);
        write_array(&mut out, &self.outputs);
        write_array(&mut out, &self.fees);
        put_lp(&mut out, &self.range_proof);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_MINT_TRANSACTION, "MintTransaction")?;
        Ok(Self {
            domain: read_lp(data, &mut c)?,
            inputs: read_array(data, &mut c)?,
            outputs: read_array(data, &mut c)?,
            fees: read_array(data, &mut c)?,
            range_proof: read_lp(data, &mut c)?,
        })
    }

    /// Byte-size cost basis for fee computation. Ports Go
    /// `MintTransaction.GetCost` at
    /// `token_intrinsic_mint_transaction.go:2148-2163`. `behavior` is
    /// the token's `TokenConfiguration.behavior` flags; the non-divisible
    /// constant `110` mirrors Go's legacy non-divisible additional-
    /// reference overhead.
    pub fn get_cost(&self, behavior: u16) -> Result<num_bigint::BigInt> {
        use num_bigint::BigInt;
        let mut size = BigInt::from(self.domain.len() as u64);
        size += BigInt::from(self.range_proof.len() as u64);
        let is_non_divisible = behavior & super::constants::DIVISIBLE == 0;
        for raw in &self.outputs {
            let out = MintTransactionOutput::from_canonical_bytes(raw)?;
            let r = super::transaction::RecipientBundle::from_canonical_bytes(
                &out.recipient_output,
            )?;
            size += BigInt::from(8u64);
            size += BigInt::from(out.commitment.len() as u64);
            size += BigInt::from(r.coin_balance.len() as u64);
            size += BigInt::from(r.mask.len() as u64);
            size += BigInt::from(r.one_time_key.len() as u64);
            size += BigInt::from(r.verification_key.len() as u64);
            if is_non_divisible {
                size += BigInt::from(110u64);
            }
        }
        Ok(size)
    }
}

// =====================================================================
// Verification — MintWithAuthority behavior
// =====================================================================

/// Convert the `key_type` field in a `token_intrinsic::config::Authority`
/// (`u32`) to the `quil_types::crypto::KeyType` enum used by `KeyManager`.
///
/// Mirrors the Go enum in `types/crypto/key_type.go`.
fn key_type_from_u32(kt: u32) -> Result<KeyType> {
    match kt {
        0 => Ok(KeyType::Ed448),
        1 => Ok(KeyType::X448),
        2 => Ok(KeyType::Bls48581G1),
        3 => Ok(KeyType::Bls48581G2),
        4 => Ok(KeyType::Decaf448),
        5 => Ok(KeyType::Secp256k1Sha256),
        6 => Ok(KeyType::Secp256k1Sha3),
        7 => Ok(KeyType::Ed25519),
        _ => Err(QuilError::InvalidArgument(format!(
            "mint: invalid authority key type {}",
            kt
        ))),
    }
}

/// Signature size (in bytes) for each key type, per
/// `token_intrinsic_mint_transaction.go:1471-1489`.
fn signature_size_for_key_type(kt: KeyType) -> Result<usize> {
    match kt {
        KeyType::Ed448 => Ok(114),
        KeyType::Bls48581G1 | KeyType::Bls48581G2 => Ok(74),
        KeyType::Ed25519 => Ok(64),
        KeyType::Secp256k1Sha256 | KeyType::Secp256k1Sha3 => Ok(64),
        _ => Err(QuilError::InvalidArgument(
            "mint authority: unsupported key type for signature".into(),
        )),
    }
}

/// Build the output transcript for a mint transaction and hash it to a
/// DECAF448 scalar. Port of `MintTransaction.GetChallenge` in
/// `token_intrinsic_mint_transaction.go:2666`.
///
/// ```text
/// transcript =
///     concat(input[i].proofs concatenated, for i in inputs)
///     || domain
///     || concat over outputs:
///          output.commitment
///          || output.frame_number
///          || (if output.recipient.additional_reference is 64 bytes:
///                output.recipient.additional_reference
///                || output.recipient.additional_reference_key)
///          || output.recipient.coin_balance
///          || output.recipient.mask
///          || output.recipient.one_time_key
///          || output.recipient.verification_key
///
/// challenge = decaf.hash_to_scalar(transcript).Private()
/// ```
pub fn build_mint_transaction_transcript(
    tx: &MintTransaction,
    decoded_inputs: &[MintTransactionInput],
) -> Result<Vec<u8>> {
    let mut transcript: Vec<u8> = Vec::new();
    for input in decoded_inputs {
        for proof in &input.proofs {
            transcript.extend_from_slice(proof);
        }
    }
    transcript.extend_from_slice(&tx.domain);
    for raw_out in &tx.outputs {
        let out = MintTransactionOutput::from_canonical_bytes(raw_out)?;
        let recipient = super::transaction::RecipientBundle::from_canonical_bytes(
            &out.recipient_output,
        )?;
        transcript.extend_from_slice(&out.commitment);
        transcript.extend_from_slice(&out.frame_number);
        if recipient.additional_reference.len() == 64 {
            transcript.extend_from_slice(&recipient.additional_reference);
            transcript.extend_from_slice(&recipient.additional_reference_key);
        }
        transcript.extend_from_slice(&recipient.coin_balance);
        transcript.extend_from_slice(&recipient.mask);
        transcript.extend_from_slice(&recipient.one_time_key);
        transcript.extend_from_slice(&recipient.verification_key);
    }
    Ok(transcript)
}

/// Compute the DECAF448 challenge scalar for a mint transaction.
/// Returns the 56-byte little-endian private scalar.
pub fn compute_mint_transaction_challenge(
    tx: &MintTransaction,
    decoded_inputs: &[MintTransactionInput],
    decaf: &dyn DecafConstructor,
) -> Result<Vec<u8>> {
    let transcript = build_mint_transaction_transcript(tx, decoded_inputs)?;
    decaf.hash_to_scalar(&transcript)
}

/// Verify a MintTransaction under the `MintWithAuthority` behavior.
///
/// Mirrors `MintTransaction.Verify` and
/// `MintTransactionInput.verifyWithMintWithAuthority` in
/// `token_intrinsic_mint_transaction.go:2696` and `:1459`.
///
/// Performs:
/// 1. Structural validation (I/O counts, fees bounded, non-divisible
///    tokens have matching I/O counts).
/// 2. For each input:
///    a. Commitment length check.
///    b. Non-divisible token checks (unitary value, additional
///       reference fields).
///    c. Single proof present, length `88 + signature_size(key_type)`.
///    d. First 32 bytes of proof equal the claimed `Value`.
///    e. Authority signature verification via `KeyManager`:
///       message=`proof[:88]`, signature=`proof[88:]`, context=`domain`.
///    f. Key image match: `proof[32..88] == signature[56*4..56*5]`.
///    g. Commitment match: `commitment == signature[56*5..56*6]`.
///    h. Hidden bulletproof signature verification against
///       `build_mint_transaction_transcript`.
///    i. Key image uniqueness across inputs (double-spend).
/// 3. For each output:
///    a. Structural output validation (commitment length, bundle
///       lengths, frame number).
///    b. `frame_number_arg > output.frame_number` (big-endian u64).
/// 4. Bulletproof range proof verification over concatenated output
///    commitments.
/// 5. Bulletproof sum check: input commitments sum == output
///    commitments sum (no fees for mints).
///
/// Note: Spent-coin lookups (poseidon(proof) → vertex exists) are the
/// caller's responsibility — this function is pure crypto. The
/// dispatcher calls `spent_check::check_not_spent_by_address` before
/// materialization.
///
/// `authority_key_type`/`authority_public_key` come from the token's
/// `TokenMintStrategy.authority` decoded as `Authority` canonical
/// bytes. `token_behavior` is the `TokenConfiguration.behavior` flags.
#[allow(clippy::too_many_arguments)]
pub fn verify_authority(
    tx: &MintTransaction,
    frame_number: u64,
    authority_key_type: u32,
    authority_public_key: &[u8],
    token_behavior: u16,
    bulletproof_prover: &dyn BulletproofProver,
    decaf: &dyn DecafConstructor,
    key_manager: &dyn KeyManager,
) -> Result<bool> {
    // 1. Structural validation.
    super::verify::validate_mint_transaction_structural(
        tx.inputs.len(),
        tx.outputs.len(),
        &tx.fees,
        token_behavior,
    )?;

    // Decode all inputs up front so we can use them both for the
    // transcript and per-input verification.
    let mut decoded_inputs: Vec<MintTransactionInput> = Vec::with_capacity(tx.inputs.len());
    for raw in &tx.inputs {
        decoded_inputs.push(MintTransactionInput::from_canonical_bytes(raw)?);
    }

    // 2. Compute the shared transcript (also used as `outputTranscript`
    // argument to the input signature verification).
    let transcript = compute_mint_transaction_challenge(tx, &decoded_inputs, decaf)?;

    let key_type = key_type_from_u32(authority_key_type)?;
    let sig_size = signature_size_for_key_type(key_type)?;

    // Per-input verification + double-spend check within the batch.
    let mut seen_key_images: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    let mut input_commitments: Vec<Vec<u8>> = Vec::with_capacity(decoded_inputs.len());
    for input in &decoded_inputs {
        // 2a. Commitment length.
        if input.commitment.len() != 56 {
            return Err(QuilError::InvalidArgument(format!(
                "mint authority: commitment is {} bytes (expected 56)",
                input.commitment.len()
            )));
        }

        // 2b. Non-divisible checks (authority path: both reference
        // fields must be populated).
        if token_behavior & super::constants::DIVISIBLE == 0 {
            // Value must equal 1 (big-endian unsigned).
            let value_is_one = input.value.iter().rev().enumerate().all(|(i, &b)| {
                if i == 0 { b == 1 } else { b == 0 }
            }) && !input.value.is_empty();
            if !value_is_one {
                return Err(QuilError::InvalidArgument(
                    "mint authority: non-divisible token with non-unitary value".into(),
                ));
            }
            if input.additional_reference.len() != 64 {
                return Err(QuilError::InvalidArgument(
                    "mint authority: non-divisible token missing additional_reference".into(),
                ));
            }
            if input.additional_reference_key.len() != 56 {
                return Err(QuilError::InvalidArgument(
                    "mint authority: non-divisible token missing additional_reference_key".into(),
                ));
            }
        }

        // 2c. Proofs structure.
        if input.proofs.len() != 1 {
            return Err(QuilError::InvalidArgument(format!(
                "mint authority: expected 1 proof, got {}",
                input.proofs.len()
            )));
        }
        let proof = &input.proofs[0];
        if proof.len() != 88 + sig_size {
            return Err(QuilError::InvalidArgument(format!(
                "mint authority: proof is {} bytes (expected {})",
                proof.len(),
                88 + sig_size
            )));
        }

        // 2d. Claimed value matches proof.
        // Go compares as big.Int — equivalent to unsigned big-endian
        // byte compare after stripping leading zeros on both sides.
        if !bigint_bytes_equal(&proof[0..32], &input.value) {
            return Err(QuilError::InvalidArgument(
                "mint authority: proof value mismatch".into(),
            ));
        }

        // 2e. Authority signature: sign over proof[:88] with context = domain.
        // `proof[:88]` = value(32) || key_image(56)
        let sig_valid = key_manager.validate_signature(
            key_type,
            authority_public_key,
            &proof[0..88],
            &proof[88..],
            &tx.domain,
        )?;
        if !sig_valid {
            return Ok(false);
        }

        // 2f. Key image match.
        if input.signature.len() != 336 {
            return Err(QuilError::InvalidArgument(format!(
                "mint authority: input signature is {} bytes (expected 336)",
                input.signature.len()
            )));
        }
        if proof[32..88] != input.signature[56 * 4..56 * 5] {
            return Err(QuilError::InvalidArgument(
                "mint authority: key image mismatch".into(),
            ));
        }

        // 2g. Commitment match.
        if input.commitment != input.signature[56 * 5..56 * 6] {
            return Err(QuilError::InvalidArgument(
                "mint authority: commitment mismatch".into(),
            ));
        }

        // 2h. Hidden bulletproof signature.
        let hidden_valid = super::verify::verify_input_hidden_signature(
            bulletproof_prover,
            &input.signature,
            &transcript,
        )?;
        if !hidden_valid {
            return Ok(false);
        }

        // 2i. Key image uniqueness.
        let key_image = input.signature[56 * 4..56 * 5].to_vec();
        if !seen_key_images.insert(key_image) {
            return Err(QuilError::InvalidArgument(
                "mint authority: duplicate key image (double-spend)".into(),
            ));
        }

        input_commitments.push(input.commitment.clone());
    }

    // 3. Per-output validation.
    let mut output_commitments: Vec<Vec<u8>> = Vec::with_capacity(tx.outputs.len());
    for raw_out in &tx.outputs {
        let out = MintTransactionOutput::from_canonical_bytes(raw_out)?;
        let recipient = super::transaction::RecipientBundle::from_canonical_bytes(
            &out.recipient_output,
        )?;

        // Frame number must be an 8-byte big-endian value, strictly
        // less than `frame_number` argument.
        if out.frame_number.len() != 8 {
            return Err(QuilError::InvalidArgument(
                "mint authority: output frame_number must be 8 bytes".into(),
            ));
        }
        let out_frame = u64::from_be_bytes(out.frame_number[..].try_into().unwrap());
        if frame_number <= out_frame {
            return Err(QuilError::InvalidArgument(
                "mint authority: output frame_number >= verify frame_number".into(),
            ));
        }

        // Bundle field sizes.
        if out.commitment.len() != 56
            || recipient.one_time_key.len() != 56
            || recipient.verification_key.len() != 56
            || recipient.coin_balance.len() != 56
            || recipient.mask.len() != 56
        {
            return Err(QuilError::InvalidArgument(
                "mint authority: output field sizes invalid".into(),
            ));
        }

        output_commitments.push(out.commitment);
    }

    // 4. + 5. Range proof + sum check.
    let crypto_ok = super::verify::verify_mint_transaction_crypto(
        bulletproof_prover,
        &input_commitments,
        &output_commitments,
        &tx.range_proof,
    )?;

    Ok(crypto_ok)
}

// =====================================================================
// MintWithSignature — same per-input checks as MintWithAuthority
// =====================================================================
//
// Go `verifyWithMintWithSignature` at `token_intrinsic_mint_transaction
// .go:1350-1457` runs the identical 9 checks as `verifyWithMintWithAuthority`
// just in a slightly different order. `verify_authority` already
// implements the full chain, so the signature variant delegates.

/// Verify a `MintWithSignature` MintTransaction.
///
/// At the per-input level this runs the same 9-check chain as
/// `verify_authority`. In addition, per Go
/// `MintTransactionOutput.Verify` (lines 2060-2071), every output must
/// satisfy `output[i].RecipientOutput.VerificationKey ==
/// input[i].proofs[0][32..88]` — the signature variant binds each
/// minted coin's recipient VK to the key image carried in the proof.
///
/// Callers should still perform the hypergraph spend-check
/// (`poseidon(proof)` vertex not present) out-of-band — see
/// `verify_mint_transaction_signature` which runs both the input
/// chain and the per-output spend check + per-input spend check.
#[allow(clippy::too_many_arguments)]
pub fn verify_with_signature(
    tx: &MintTransaction,
    frame_number: u64,
    authority_key_type: u32,
    authority_public_key: &[u8],
    token_behavior: u16,
    bulletproof_prover: &dyn BulletproofProver,
    decaf: &dyn DecafConstructor,
    key_manager: &dyn KeyManager,
) -> Result<bool> {
    let ok = verify_authority(
        tx,
        frame_number,
        authority_key_type,
        authority_public_key,
        token_behavior,
        bulletproof_prover,
        decaf,
        key_manager,
    )?;
    if !ok {
        return Ok(false);
    }

    // Per-output: VerificationKey must equal proofs[0][32..88] from the
    // matching input. Non-divisible tokens enforce input-count ==
    // output-count via `validate_mint_transaction_structural`; for
    // divisible tokens we still match by index where present.
    if tx.inputs.len() != tx.outputs.len() {
        // Signature mints carry a 1:1 binding between input proofs and
        // output VKs. Go relies on the non-divisible structural check
        // for this; for divisible tokens with mismatched counts there
        // is no way to bind the recipient VK to a specific input, so
        // reject defensively.
        return Err(QuilError::InvalidArgument(format!(
            "mint signature: inputs/outputs length mismatch ({} != {})",
            tx.inputs.len(),
            tx.outputs.len()
        )));
    }
    for (idx, raw_out) in tx.outputs.iter().enumerate() {
        let out = MintTransactionOutput::from_canonical_bytes(raw_out)?;
        let recipient = super::transaction::RecipientBundle::from_canonical_bytes(
            &out.recipient_output,
        )?;
        let input = MintTransactionInput::from_canonical_bytes(&tx.inputs[idx])?;
        if input.proofs.is_empty() || input.proofs[0].len() < 88 {
            return Err(QuilError::InvalidArgument(
                "mint signature: input.proofs[0] too short for VK image".into(),
            ));
        }
        if recipient.verification_key != input.proofs[0][32..88] {
            return Err(QuilError::InvalidArgument(format!(
                "mint signature: output[{}].VerificationKey does not match input[{}].proofs[0][32..88]",
                idx, idx
            )));
        }
    }

    Ok(true)
}

// =====================================================================
// MintWithProof / VerkleMultiproofWithSignature
// =====================================================================

/// Verify a single input under the `MintWithProof +
/// VerkleMultiproofWithSignature` variant. Ports Go
/// `verifyWithVerkleMultiproofSignature` at
/// `token_intrinsic_mint_transaction.go:1568-1675`.
///
/// Proof layout (`input.proofs[0]`):
/// ```text
/// [0 .. n-88)    traversal proof (parsed by `parse_go_traversal_proof`)
/// [n-88 .. n-56) amount — big-endian 32-byte big.Int that must equal
///                input.value
/// [n-56 .. n)    key image — 56 bytes that must equal
///                input.signature[56*4 .. 56*5]
/// ```
///
/// `verkle_root` is the token config's `MintStrategy.VerkleRoot`.
///
/// Spend-check (`poseidon(proofs[0])` vertex not present) is the
/// caller's responsibility, matching the pattern used by the other
/// variants. The in-tx double-spend batch check belongs to the tx-level
/// caller as well.
pub fn verify_verkle_multiproof_input(
    input: &MintTransactionInput,
    output_transcript: &[u8],
    verkle_root: &[u8],
    inclusion_prover: &(dyn InclusionProver + Sync),
    bulletproof_prover: &dyn BulletproofProver,
) -> Result<()> {
    if input.proofs.len() != 1 {
        return Err(QuilError::InvalidArgument(
            "mint verkle: expected 1 proof".into(),
        ));
    }
    let proof = &input.proofs[0];
    if proof.len() < 88 {
        return Err(QuilError::InvalidArgument(format!(
            "mint verkle: proof is {} bytes (< 88 minimum for amount + image)",
            proof.len()
        )));
    }

    let n = proof.len();
    let amount_slice = &proof[n - 88..n - 56];
    let image_slice = &proof[n - 56..];
    let traversal_slice = &proof[..n - 88];

    // Claimed value must match proof amount (big.Int compare).
    if !bigint_bytes_equal(amount_slice, &input.value) {
        return Err(QuilError::InvalidArgument(
            "mint verkle: proof amount does not match input.value".into(),
        ));
    }

    // Parse + verify the traversal proof against the token's
    // configured verkle root.
    let traversal = parse_go_traversal_proof(traversal_slice)?;
    if !crate::traversal_proof::verify_traversal_proof(
        inclusion_prover,
        verkle_root,
        &traversal,
    )? {
        return Err(QuilError::InvalidArgument(
            "mint verkle: traversal proof invalid".into(),
        ));
    }

    // Last y of subproof[0] must equal the last 88 bytes (amount || image).
    let sp0 = traversal.sub_proofs.first().ok_or_else(|| {
        QuilError::InvalidArgument("mint verkle: traversal has no subproof[0]".into())
    })?;
    let last_y = sp0.ys.last().ok_or_else(|| {
        QuilError::InvalidArgument("mint verkle: subproof[0] has no ys".into())
    })?;
    if last_y.as_slice() != &proof[n - 88..] {
        return Err(QuilError::InvalidArgument(
            "mint verkle: traversal proof value does not match amount||image".into(),
        ));
    }

    // Key image + commitment parity with the hidden signature layout.
    if input.signature.len() != 336 {
        return Err(QuilError::InvalidArgument(format!(
            "mint verkle: signature is {} bytes (expected 336)",
            input.signature.len()
        )));
    }
    if image_slice != &input.signature[56 * 4..56 * 5] {
        return Err(QuilError::InvalidArgument(
            "mint verkle: key image mismatch".into(),
        ));
    }
    if input.commitment != input.signature[56 * 5..56 * 6] {
        return Err(QuilError::InvalidArgument(
            "mint verkle: commitment does not match signature commitment".into(),
        ));
    }

    // Hidden Schnorr over the output transcript.
    let hidden_ok = bulletproof_prover.verify_hidden(
        &input.signature[0..56],
        output_transcript,
        &input.signature[56..56 * 2],
        &input.signature[56 * 2..56 * 3],
        &input.signature[56 * 3..56 * 4],
        &input.signature[56 * 4..56 * 5],
        &input.signature[56 * 5..56 * 6],
    );
    if !hidden_ok {
        return Err(QuilError::InvalidArgument(
            "mint verkle: hidden Schnorr signature rejected".into(),
        ));
    }
    Ok(())
}

// =====================================================================
// MintWithPayment
// =====================================================================

/// Config fields `MintWithPayment` needs from the token's
/// `MintStrategy`.
pub struct MintWithPaymentConfig<'a> {
    /// `MintStrategy.FeeBasis.Baseline`. `None` (or baseline = 0) means
    /// "free mint" — the nested PendingTransaction + rate-scaling flow
    /// is skipped.
    pub fee_baseline: Option<&'a num_bigint::BigInt>,
    /// `MintStrategy.PaymentAddress`.
    pub payment_address: &'a [u8],
}

/// Verify a single input under the `MintWithPayment` mint strategy.
/// Ports Go `verifyWithMintWithPayment` at
/// `token_intrinsic_mint_transaction.go:1117-1348`.
///
/// Proof `[0]` layout:
/// ```text
/// <... nested PendingTransaction bytes (free-mint: empty)>
/// [n-224..n-168)  synthetic blind scalar (56)
/// [n-168..n-112)  ephemeral key scalar (56)
/// [n-112..n-56)   paymentAddress preimage part 1 (56)
/// [n-56 .. n)     paymentAddress preimage part 2 (56)
/// ```
///
/// For a free mint (fee baseline absent or zero), `proof[0]` must be
/// exactly 224 bytes (no nested tx). For a paid mint, the nested
/// PendingTransaction is the prefix (`proof[0][..n-224]`), followed
/// by the same 224-byte context tail.
///
/// The nested PendingTransaction verify is delegated to the caller
/// via `verify_nested_pending` (so the caller can inject the hypergraph
/// + crypto providers without re-plumbing them here).
#[allow(clippy::too_many_arguments)]
pub fn verify_with_payment_input<F>(
    input: &MintTransactionInput,
    output_transcript: &[u8],
    input_index: usize,
    config: &MintWithPaymentConfig<'_>,
    decaf: &dyn DecafConstructor,
    bulletproof_prover: &dyn BulletproofProver,
    verify_nested_pending: F,
) -> Result<()>
where
    F: FnOnce(&[u8], usize, &[u8]) -> Result<NestedPendingResult>,
{
    use num_bigint::{BigInt, Sign};

    if input.proofs.len() != 1 {
        return Err(QuilError::InvalidArgument(
            "mint payment: expected 1 proof".into(),
        ));
    }
    let proof = &input.proofs[0];

    // Determine free-mint vs paid-mint.
    let is_free_mint = match config.fee_baseline {
        None => true,
        Some(b) => *b == BigInt::from(0),
    };

    if is_free_mint {
        if proof.len() != 224 {
            return Err(QuilError::InvalidArgument(format!(
                "mint payment: free mint proof is {} bytes (expected 224)",
                proof.len()
            )));
        }
    } else if proof.len() < 224 {
        return Err(QuilError::InvalidArgument(format!(
            "mint payment: paid mint proof is {} bytes (< 224 minimum)",
            proof.len()
        )));
    }

    let n = proof.len();
    let synthetic_blind_scalar = &proof[n - 224..n - 168];
    let ephemeral_scalar_slice = &proof[n - 168..n - 112];
    let vk_preimage_part1 = &proof[n - 112..n - 56];
    let vk_preimage_part2 = &proof[n - 56..];

    // `balance = reversed(input.value.FillBytes(56))` — little-endian
    // form for the decaf scalar adapter.
    let mut balance = vec![0u8; 56];
    let val_bytes = &input.value;
    if val_bytes.len() > 56 {
        return Err(QuilError::InvalidArgument(format!(
            "mint payment: value is {} bytes (> 56)", val_bytes.len()
        )));
    }
    let offset = 56 - val_bytes.len();
    balance[offset..].copy_from_slice(val_bytes);
    balance.reverse();

    let synthetic_blind = decaf.new_from_scalar(synthetic_blind_scalar)?;
    let balance_point = decaf.new_from_scalar(&balance)?;
    let mut raised_blind = synthetic_blind.agree_with(&decaf.alt_generator())?;

    if !is_free_mint {
        let baseline = config.fee_baseline.unwrap();
        // rateLI = reversed(baseline.FillBytes(56))
        let (_, base_bytes_be) = baseline.to_bytes_be();
        let mut rate_le = vec![0u8; 56];
        if base_bytes_be.len() > 56 {
            return Err(QuilError::InvalidArgument(
                "mint payment: fee baseline exceeds 56 bytes".into(),
            ));
        }
        let off = 56 - base_bytes_be.len();
        rate_le[off..].copy_from_slice(&base_bytes_be);
        rate_le.reverse();
        let rate = decaf.new_from_scalar(&rate_le)?;
        let inv_rate_bytes = rate.inverse_scalar()?;
        let inv_rate = decaf.new_from_scalar(&inv_rate_bytes)?;
        raised_blind = inv_rate.agree_with(&raised_blind)?;
    }

    let check = balance_point.add(&raised_blind)?;
    if check != input.commitment {
        return Err(QuilError::InvalidArgument(
            "mint payment: recomputed commitment mismatch".into(),
        ));
    }

    if !is_free_mint {
        // Nested PendingTransaction verify via the callback. The
        // nested tx occupies `proof[.. n-224]` for non-free mints.
        let nested_bytes = &proof[..n - 224];
        let nested = verify_nested_pending(
            nested_bytes,
            input_index,
            config.payment_address,
        )?;

        // Scaled check = rate ⋅ check must equal paymentTx.Outputs[index].Commitment.
        let baseline = config.fee_baseline.unwrap();
        let (_, base_bytes_be) = baseline.to_bytes_be();
        let mut rate_le = vec![0u8; 56];
        let off = 56 - base_bytes_be.len();
        rate_le[off..].copy_from_slice(&base_bytes_be);
        rate_le.reverse();
        let rate = decaf.new_from_scalar(&rate_le)?;
        let scaled_check = rate.agree_with(&check)?;
        if scaled_check != nested.output_commitment {
            return Err(QuilError::InvalidArgument(
                "mint payment: output commitment mismatch after rate scaling".into(),
            ));
        }

        // Verification-key derivation: ephemeral ⋅ vk_preimage_part1
        // hashed → rvk; checkVK = rvk ⊕ vk_preimage_part2 (decaf Add).
        let ephemeral_key = decaf.new_from_scalar(ephemeral_scalar_slice)?;
        let rvk_bytes = ephemeral_key.agree_with_and_hash_to_scalar(vk_preimage_part1)?;
        let rvk = decaf.new_from_scalar(&rvk_bytes)?;
        let check_vk = rvk.add(vk_preimage_part2)?;
        if check_vk != nested.to_verification_key {
            return Err(QuilError::InvalidArgument(
                "mint payment: verification key derivation mismatch".into(),
            ));
        }

        // paymentAddress = poseidon(vk_preimage_part1 || vk_preimage_part2)
        // must equal config.payment_address.
        let mut preimage = Vec::with_capacity(112);
        preimage.extend_from_slice(vk_preimage_part1);
        preimage.extend_from_slice(vk_preimage_part2);
        let payment_addr = quil_crypto::poseidon::hash_bytes_to_32(&preimage)?;
        if payment_addr.as_slice() != config.payment_address {
            return Err(QuilError::InvalidArgument(
                "mint payment: payment address mismatch".into(),
            ));
        }

        // Refund VK == To VK ensures the payment was abandoned (the
        // refund branch collapses onto the same key).
        if nested.refund_verification_key != nested.to_verification_key {
            return Err(QuilError::InvalidArgument(
                "mint payment: payment not abandoned (refund VK != to VK)".into(),
            ));
        }
    }

    // Final commitment-in-signature check + hidden Schnorr.
    if input.signature.len() != 336 {
        return Err(QuilError::InvalidArgument(format!(
            "mint payment: signature is {} bytes (expected 336)",
            input.signature.len()
        )));
    }
    if input.commitment != input.signature[56 * 5..56 * 6] {
        return Err(QuilError::InvalidArgument(
            "mint payment: commitment does not match signature commitment".into(),
        ));
    }
    let hidden_ok = bulletproof_prover.verify_hidden(
        &input.signature[0..56],
        output_transcript,
        &input.signature[56..56 * 2],
        &input.signature[56 * 2..56 * 3],
        &input.signature[56 * 3..56 * 4],
        &input.signature[56 * 4..56 * 5],
        &input.signature[56 * 5..56 * 6],
    );
    if !hidden_ok {
        return Err(QuilError::InvalidArgument(
            "mint payment: hidden Schnorr signature rejected".into(),
        ));
    }
    Ok(())
}

/// Result of the nested PendingTransaction verification requested by
/// `verify_with_payment_input`. Only the three fields needed for the
/// downstream checks are returned.
pub struct NestedPendingResult {
    /// `paymentTx.Outputs[index].Commitment` — checked against the
    /// rate-scaled commitment.
    pub output_commitment: Vec<u8>,
    /// `paymentTx.Outputs[index].ToOutput.VerificationKey` — checked
    /// against the derived `rvk + vk_preimage_part2`.
    pub to_verification_key: Vec<u8>,
    /// `paymentTx.Outputs[index].RefundOutput.VerificationKey` —
    /// checked for equality with `to_verification_key` (abandoned
    /// payment invariant).
    pub refund_verification_key: Vec<u8>,
}

/// Compare two byte slices as unsigned big-endian integers, ignoring
/// leading zeros. Go's `big.Int.Cmp` treats
/// `[0, 0, 5] == [5] == [0, 5]`.
fn bigint_bytes_equal(a: &[u8], b: &[u8]) -> bool {
    fn strip(s: &[u8]) -> &[u8] {
        let mut i = 0;
        while i < s.len() && s[i] == 0 {
            i += 1;
        }
        &s[i..]
    }
    strip(a) == strip(b)
}

// =====================================================================
// Tx-level verify wrappers — Signature / Verkle / Payment
// =====================================================================
//
// These mirror `verify_mint_transaction_pomw` in shape: they compose
// the per-input verifier with the auxiliary cross-tx checks Go's
// `MintTransaction.Verify` performs (per-output spend check, per-input
// spend check, key-image batch double-spend, output frame-number /
// recipient field validation, etc.) so the engine dispatch only has to
// route by variant rather than re-implement those wrappers inline.

/// Per-output spend check — for each output `o`, the vertex at
/// `tx.domain || poseidon(o.RecipientOutput.VerificationKey)` must
/// NOT exist in the hypergraph. Mirrors Go
/// `MintTransaction.Verify` lines 2754-2767.
fn verify_outputs_not_spent(
    tx: &MintTransaction,
    decoded_outputs: &[MintTransactionOutput],
    hypergraph: &Arc<HypergraphCrdt>,
) -> Result<()> {
    if tx.domain.len() < 32 {
        return Err(QuilError::InvalidArgument(format!(
            "mint: tx.domain.len() = {} (< 32)", tx.domain.len()
        )));
    }
    let mut app = [0u8; 32];
    app.copy_from_slice(&tx.domain[..32]);
    for (idx, raw_out) in decoded_outputs.iter().enumerate() {
        let recipient = super::transaction::RecipientBundle::from_canonical_bytes(
            &raw_out.recipient_output,
        )?;
        if recipient.verification_key.is_empty() {
            return Err(QuilError::InvalidArgument(format!(
                "mint: output[{}] missing verification key", idx
            )));
        }
        let spend_addr = quil_crypto::poseidon::hash_bytes_to_32(
            &recipient.verification_key,
        )?;
        let loc = quil_hypergraph::addressing::Location {
            app_address: app,
            data_address: spend_addr,
        };
        if hypergraph.lookup_vertex(&loc) {
            return Err(QuilError::InvalidArgument(format!(
                "mint: output[{}] verification key already used (vertex exists)",
                idx
            )));
        }
    }
    Ok(())
}

/// Per-input spend check + per-batch key-image uniqueness — for each
/// input the vertex at `tx.domain || poseidon(proofs[0])` must NOT
/// exist, and key images (signature[56*4..56*5]) must be unique within
/// the batch. Mirrors the loop at Go `MintTransaction.Verify`
/// lines 2727-2745.
fn verify_inputs_not_spent_and_unique(
    tx: &MintTransaction,
    decoded_inputs: &[MintTransactionInput],
    hypergraph: &Arc<HypergraphCrdt>,
) -> Result<()> {
    let mut app = [0u8; 32];
    app.copy_from_slice(&tx.domain[..32]);
    let mut seen_key_images: std::collections::HashSet<Vec<u8>> =
        std::collections::HashSet::new();
    for (idx, input) in decoded_inputs.iter().enumerate() {
        if input.proofs.is_empty() {
            return Err(QuilError::InvalidArgument(format!(
                "mint: input[{}] has no proofs", idx
            )));
        }
        let spend_addr = quil_crypto::poseidon::hash_bytes_to_32(&input.proofs[0])?;
        let loc = quil_hypergraph::addressing::Location {
            app_address: app,
            data_address: spend_addr,
        };
        if hypergraph.lookup_vertex(&loc) {
            return Err(QuilError::InvalidArgument(format!(
                "mint: input[{}] proof already spent (vertex exists)", idx
            )));
        }
        if input.signature.len() < 56 * 5 {
            return Err(QuilError::InvalidArgument(format!(
                "mint: input[{}] signature shorter than 56*5 bytes", idx
            )));
        }
        let key_image = input.signature[56 * 4..56 * 5].to_vec();
        if !seen_key_images.insert(key_image) {
            return Err(QuilError::InvalidArgument(format!(
                "mint: input[{}] duplicate key image (double-spend)", idx
            )));
        }
    }
    Ok(())
}

/// Build the output transcript shared by Signature, Verkle, and
/// Payment per-input verifies. Wraps the verify-module helper so the
/// tx-level wrappers don't have to redo recipient decoding.
fn build_signature_style_transcript(
    tx: &MintTransaction,
    decoded_inputs: &[MintTransactionInput],
    decoded_outputs: &[MintTransactionOutput],
) -> Result<Vec<u8>> {
    let recipients: Vec<super::transaction::RecipientBundle> = decoded_outputs
        .iter()
        .map(|o| super::transaction::RecipientBundle::from_canonical_bytes(&o.recipient_output))
        .collect::<Result<Vec<_>>>()?;
    let input_proofs: Vec<Vec<Vec<u8>>> =
        decoded_inputs.iter().map(|i| i.proofs.clone()).collect();
    super::verify::build_mint_transaction_transcript(
        &tx.domain, &input_proofs, decoded_outputs, &recipients,
    )
}

/// Decode all inputs + outputs from canonical bytes. Used by the
/// tx-level verify wrappers.
fn decode_inputs_outputs(
    tx: &MintTransaction,
) -> Result<(Vec<MintTransactionInput>, Vec<MintTransactionOutput>)> {
    let mut inputs = Vec::with_capacity(tx.inputs.len());
    for raw in &tx.inputs {
        inputs.push(MintTransactionInput::from_canonical_bytes(raw)?);
    }
    let mut outputs = Vec::with_capacity(tx.outputs.len());
    for raw in &tx.outputs {
        outputs.push(MintTransactionOutput::from_canonical_bytes(raw)?);
    }
    Ok((inputs, outputs))
}

/// Top-level verify for a `MintWithSignature` MintTransaction. Mirrors
/// the input + output loops in Go `MintTransaction.Verify`
/// (`token_intrinsic_mint_transaction.go:2696`) for the Signature
/// variant: structural validation, per-input + per-output spend checks
/// against the hypergraph, key-image batch uniqueness, the per-input
/// 9-check chain, and the per-output `VK == proofs[0][32..88]` binding.
///
/// Returns `Ok(())` if every check passes, `Err` on the first failure.
#[allow(clippy::too_many_arguments)]
pub fn verify_mint_transaction_signature(
    tx: &MintTransaction,
    frame_number: u64,
    authority_key_type: u32,
    authority_public_key: &[u8],
    token_behavior: u16,
    hypergraph: &Arc<HypergraphCrdt>,
    bulletproof_prover: &dyn BulletproofProver,
    decaf: &dyn DecafConstructor,
    key_manager: &dyn KeyManager,
) -> Result<()> {
    let (decoded_inputs, decoded_outputs) = decode_inputs_outputs(tx)?;

    // Output spend check (per-output VK not already a vertex).
    verify_outputs_not_spent(tx, &decoded_outputs, hypergraph)?;
    // Input spend check + batch double-spend.
    verify_inputs_not_spent_and_unique(tx, &decoded_inputs, hypergraph)?;

    let ok = verify_with_signature(
        tx,
        frame_number,
        authority_key_type,
        authority_public_key,
        token_behavior,
        bulletproof_prover,
        decaf,
        key_manager,
    )?;
    if !ok {
        return Err(QuilError::InvalidArgument(
            "mint signature: verify chain rejected".into(),
        ));
    }
    Ok(())
}

/// Top-level verify for `MintWithProof + VerkleMultiproofWithSignature`.
/// Mirrors Go's `MintTransaction.Verify` for the verkle variant:
/// resolves the verkle root, per-input + per-output spend checks,
/// builds the output transcript, runs `verify_verkle_multiproof_input`
/// per input, then runs the bulletproof range/sum check (callers can
/// run that separately via `verify::verify_mint_transaction_crypto` if
/// they prefer to share the call site with PoMW).
#[allow(clippy::too_many_arguments)]
pub fn verify_mint_transaction_verkle(
    tx: &MintTransaction,
    verkle_root: &[u8],
    token_behavior: u16,
    hypergraph: &Arc<HypergraphCrdt>,
    inclusion_prover: &(dyn InclusionProver + Sync),
    bulletproof_prover: &dyn BulletproofProver,
) -> Result<()> {
    super::verify::validate_mint_transaction_structural(
        tx.inputs.len(),
        tx.outputs.len(),
        &tx.fees,
        token_behavior,
    )?;

    let (decoded_inputs, decoded_outputs) = decode_inputs_outputs(tx)?;
    verify_outputs_not_spent(tx, &decoded_outputs, hypergraph)?;
    verify_inputs_not_spent_and_unique(tx, &decoded_inputs, hypergraph)?;

    let transcript = build_signature_style_transcript(tx, &decoded_inputs, &decoded_outputs)?;
    for input in &decoded_inputs {
        verify_verkle_multiproof_input(
            input,
            &transcript,
            verkle_root,
            inclusion_prover,
            bulletproof_prover,
        )?;
    }
    Ok(())
}

/// Top-level verify for `MintWithPayment`. The nested PendingTransaction
/// verification is delegated to a caller-supplied closure — same pattern
/// as `verify_with_payment_input` — so this module doesn't have to
/// import the engine-level `verify_pending_transaction` machinery.
#[allow(clippy::too_many_arguments)]
pub fn verify_mint_transaction_payment<F>(
    tx: &MintTransaction,
    config: &MintWithPaymentConfig<'_>,
    token_behavior: u16,
    hypergraph: &Arc<HypergraphCrdt>,
    decaf: &dyn DecafConstructor,
    bulletproof_prover: &dyn BulletproofProver,
    mut verify_nested_pending: F,
) -> Result<()>
where
    F: FnMut(&[u8], usize, &[u8]) -> Result<NestedPendingResult>,
{
    super::verify::validate_mint_transaction_structural(
        tx.inputs.len(),
        tx.outputs.len(),
        &tx.fees,
        token_behavior,
    )?;

    let (decoded_inputs, decoded_outputs) = decode_inputs_outputs(tx)?;
    verify_outputs_not_spent(tx, &decoded_outputs, hypergraph)?;
    verify_inputs_not_spent_and_unique(tx, &decoded_inputs, hypergraph)?;

    let transcript = build_signature_style_transcript(tx, &decoded_inputs, &decoded_outputs)?;
    for (idx, input) in decoded_inputs.iter().enumerate() {
        verify_with_payment_input(
            input,
            &transcript,
            idx,
            config,
            decaf,
            bulletproof_prover,
            |nested, output_idx, payment_addr| verify_nested_pending(nested, output_idx, payment_addr),
        )?;
    }
    Ok(())
}

// =====================================================================
// Materialization — MintWithAuthority behavior
// =====================================================================

/// Materialize the outputs and spent markers from a verified mint
/// transaction under the `MintWithAuthority` behavior.
///
/// For each output, constructs a coin vertex tree at
/// `domain || poseidon(output.recipient.verification_key)` using the
/// standard coin layout (see `materialize::create_coin_vertex_tree`).
///
/// For each input, writes a spent marker at
/// `domain || poseidon(input.proofs[0])` to prevent replay of the
/// authority signature.
///
/// Mirrors `MintTransaction.Materialize` in
/// `token_intrinsic_mint_transaction.go:2228`, stripped of the
/// PoMW-specific prover-balance update and the additional-references
/// tree rotation that only applies to non-authority non-divisible
/// tokens.
pub fn materialize_authority(
    tx: &MintTransaction,
    inclusion_prover: &(dyn quil_types::crypto::InclusionProver + Sync),
) -> Result<super::materialize::TransactionMaterializeOutput> {
    use super::materialize::{
        coin_type_hash, create_coin_vertex_tree, create_spent_marker_tree,
        TransactionMaterializeOutput, TransactionOutput as MatOutput,
    };

    let mut decoded_outputs: Vec<MatOutput> = Vec::with_capacity(tx.outputs.len());
    for raw_out in &tx.outputs {
        let out = MintTransactionOutput::from_canonical_bytes(raw_out)?;
        let recipient = super::transaction::RecipientBundle::from_canonical_bytes(
            &out.recipient_output,
        )?;
        decoded_outputs.push(MatOutput {
            frame_number: out.frame_number,
            commitment: out.commitment,
            recipient,
        });
    }

    let type_hash = coin_type_hash(&tx.domain)?;

    let mut coins: Vec<([u8; 32], quil_tries::VectorCommitmentTree)> =
        Vec::with_capacity(decoded_outputs.len());
    for output in &decoded_outputs {
        if output.recipient.verification_key.is_empty() {
            return Err(QuilError::InvalidArgument(
                "mint authority materialize: missing verification key".into(),
            ));
        }
        // Per Go Materialize and GetWriteAddresses, the coin vertex
        // address is `poseidon(verification_key)`.
        let addr = quil_crypto::poseidon::hash_bytes_to_32(
            &output.recipient.verification_key,
        )?;
        let mut tree = create_coin_vertex_tree(output, &type_hash)?;
        // Touch the commit so it matches the Go path which calls
        // `coinTree.Commit(inclusionProver, false)` — we don't use the
        // returned root, but the operation ensures internal state is
        // consistent for any downstream readers.
        let _ = tree.commit(inclusion_prover);
        coins.push((addr, tree));
    }

    // Spent markers: one per input, keyed by poseidon(proof).
    let mut spent_markers: Vec<([u8; 32], quil_tries::VectorCommitmentTree)> =
        Vec::with_capacity(tx.inputs.len());
    // Spent marker key is `poseidon(proofs[0])` regardless of mint
    // behavior (Go `token_intrinsic_mint_transaction.go:2559`). Authority
    // mints supply 1 proof, PoMW mints supply 3, but only the first is
    // consulted for the spent-marker key.
    for raw_input in &tx.inputs {
        let input = MintTransactionInput::from_canonical_bytes(raw_input)?;
        if input.proofs.is_empty() {
            return Err(QuilError::InvalidArgument(
                "mint materialize: input has no proofs".into(),
            ));
        }
        let addr = quil_crypto::poseidon::hash_bytes_to_32(&input.proofs[0])?;
        let marker = create_spent_marker_tree()?;
        spent_markers.push((addr, marker));
    }

    Ok(TransactionMaterializeOutput {
        coins,
        spent_markers,
    })
}

/// Materialize a PoMW mint. Decrements the prover reward balance
/// stored at the PoMW "reward vertex" for each input BEFORE creating
/// coin trees. Ports the `MintWithProof + ProofOfMeaningfulWork` branch
/// of Go `MintTransaction.Materialize` at
/// `token_intrinsic_mint_transaction.go:2237-2335`.
///
/// For QUIL (is_quil=true) the reward vertex lives at
/// `(GLOBAL_INTRINSIC, poseidon(QUIL_TOKEN_ADDR || proofs[1][..32]))`.
/// For other domains it lives at `(tx_domain, proofs[1][..32])`.
///
/// The prover balance decrement mirrors Go exactly: each input iterates
/// the full tx input set to compute `totalMinted = Σ input.value`, then
/// subtracts that from the target prover's Balance. If any iteration
/// sees `current < totalMinted` the materialize aborts (Go's "insufficient
/// prover balance").
///
/// Coin tree + spent marker creation is identical to the authority
/// path, so this function delegates to `materialize_authority` for the
/// output `TransactionMaterializeOutput` — the caller then writes coins
/// + spent markers via the standard `write_tx_result` path.
pub fn materialize_pomw(
    tx: &MintTransaction,
    state: &crate::hypergraph_state::HypergraphState,
    frame_number: u64,
    is_quil_domain: bool,
    inclusion_prover: &(dyn quil_types::crypto::InclusionProver + Sync),
) -> Result<super::materialize::TransactionMaterializeOutput> {
    use num_bigint::{BigInt, Sign};

    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;

    // 1. Compute total mint value across all inputs (same for every loop
    //    iteration — we compute once to avoid a redundant inner loop).
    let mut total_minted = BigInt::from(0);
    for raw_input in &tx.inputs {
        let input = MintTransactionInput::from_canonical_bytes(raw_input)?;
        total_minted += BigInt::from_bytes_be(Sign::Plus, &input.value);
    }

    // 2. For each input, decrement its prover's reward balance by
    //    `total_minted`. Mirrors Go's outer `for i := 0; i < len(Inputs); i++`.
    for raw_input in &tx.inputs {
        let input = MintTransactionInput::from_canonical_bytes(raw_input)?;
        if input.proofs.len() < 2 || input.proofs[1].len() < 32 {
            return Err(QuilError::InvalidArgument(
                "pomw materialize: input.proofs[1] must be at least 32 bytes".into(),
            ));
        }
        let prover_address = &input.proofs[1][..32];

        let (reward_domain, reward_addr): (Vec<u8>, [u8; 32]) = if is_quil_domain {
            let addr = crate::global_intrinsic::materialize::reward_address(prover_address)?;
            (crate::domains::GLOBAL.to_vec(), addr)
        } else {
            let mut a = [0u8; 32];
            a.copy_from_slice(prover_address);
            (tx.domain.clone(), a)
        };

        let reward_blob = state
            .get(&reward_domain, &reward_addr, &va_disc)?
            .ok_or_else(|| QuilError::InvalidArgument(
                "pomw materialize: reward vertex not found".into(),
            ))?;
        let mut reward_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&reward_blob);

        let balance_bytes = crate::global_intrinsic::materialize::read_reward_balance(&reward_tree);
        let current = if balance_bytes.is_empty() {
            BigInt::from(0)
        } else {
            BigInt::from_bytes_be(Sign::Plus, &balance_bytes)
        };

        if current < total_minted {
            return Err(QuilError::InvalidArgument(
                "pomw materialize: insufficient prover balance".into(),
            ));
        }
        let new_balance = &current - &total_minted;

        // Go uses `FillBytes(make([]byte, 32))` — fixed 32 big-endian
        // bytes, zero-padded from the left.
        let (_, trimmed) = new_balance.to_bytes_be();
        let mut padded = vec![0u8; 32];
        if !trimmed.is_empty() {
            let start = 32usize.saturating_sub(trimmed.len());
            padded[start..].copy_from_slice(&trimmed);
        }
        crate::global_intrinsic::materialize::set_reward_balance(&mut reward_tree, &padded)?;

        let new_blob = crate::prover_registry::vertex_tree_to_blob(&reward_tree);
        state.set(&reward_domain, &reward_addr, &va_disc, frame_number, new_blob)?;
    }

    // 3. Standard coin + spent marker materialization (identical to
    //    authority path).
    materialize_authority(tx, inclusion_prover)
}

// =====================================================================
// Proof-of-Meaningful-Work verify
// =====================================================================

use sha2::{Digest, Sha512};

use crate::domains::{GLOBAL as GLOBAL_ADDR, QUIL_TOKEN as QUIL_TOKEN_ADDR};
use crate::traversal_proof::{TraversalProof, TraversalSubProof, verify_traversal_proof};

/// Parse a `TraversalProof` from Go's raw wire format. The format is
/// *not* the canonical-bytes form with a type tag — it's the binary
/// layout written by `types/tries/lazy_proof_tree.go::TraversalProof::
/// ToBytes` and read by `FromBytes:1527-1645`:
///
/// ```text
/// u32 multiproof_len
/// [multiproof_len bytes]     (inner: u32 d_len, [d], u32 proof_len, [proof])
/// u32 sub_proofs_count
/// for each subproof:
///   u32 commits_count
///   {u32 commit_len, [commit_len bytes]} × commits_count
///   u32 ys_count
///   {u32 y_len, [y_len bytes]} × ys_count
///   u32 paths_count
///   {u32 path_len, u64 × path_len} × paths_count
/// ```
///
/// The inner multiproof is a pair `(d, proof)` where `d` is the
/// multi-commitment. See `bls48581/bls48581.go::Multiproof::FromBytes`.
pub fn parse_go_traversal_proof(data: &[u8]) -> Result<TraversalProof> {
    let mut c = 0usize;

    // Outer u32 multiproof length
    let mp_len = read_go_u32(data, &mut c)? as usize;
    let mp_bytes = read_go_bytes(data, &mut c, mp_len)?;

    // Inner multiproof: u32 d_len, [d], u32 proof_len, [proof]
    let mut mc = 0usize;
    let d_len = read_go_u32(mp_bytes, &mut mc)? as usize;
    let multicommitment = read_go_bytes(mp_bytes, &mut mc, d_len)?.to_vec();
    let proof_len = read_go_u32(mp_bytes, &mut mc)? as usize;
    let proof = read_go_bytes(mp_bytes, &mut mc, proof_len)?.to_vec();

    // Subproofs
    let sp_count = read_go_u32(data, &mut c)? as usize;
    let mut sub_proofs = Vec::with_capacity(sp_count);

    for _ in 0..sp_count {
        let commits_count = read_go_u32(data, &mut c)? as usize;
        let mut commits = Vec::with_capacity(commits_count);
        for _ in 0..commits_count {
            let l = read_go_u32(data, &mut c)? as usize;
            commits.push(read_go_bytes(data, &mut c, l)?.to_vec());
        }

        let ys_count = read_go_u32(data, &mut c)? as usize;
        let mut ys = Vec::with_capacity(ys_count);
        for _ in 0..ys_count {
            let l = read_go_u32(data, &mut c)? as usize;
            ys.push(read_go_bytes(data, &mut c, l)?.to_vec());
        }

        let paths_count = read_go_u32(data, &mut c)? as usize;
        let mut paths = Vec::with_capacity(paths_count);
        for _ in 0..paths_count {
            let plen = read_go_u32(data, &mut c)? as usize;
            let mut path = Vec::with_capacity(plen);
            for _ in 0..plen {
                path.push(read_go_u64(data, &mut c)?);
            }
            paths.push(path);
        }

        sub_proofs.push(TraversalSubProof { commits, ys, paths });
    }

    // Structural validation: at least one subproof with ys data.
    if sub_proofs.is_empty() {
        return Err(QuilError::InvalidArgument(
            "pomw: traversal proof has no subproofs".into(),
        ));
    }
    if !sub_proofs.iter().any(|sp| !sp.ys.is_empty()) {
        return Err(QuilError::InvalidArgument(
            "pomw: traversal proof has no ys data".into(),
        ));
    }

    Ok(TraversalProof { multicommitment, proof, sub_proofs })
}

fn read_go_u32(data: &[u8], c: &mut usize) -> Result<u32> {
    if *c + 4 > data.len() {
        return Err(QuilError::InvalidArgument(
            "pomw: EOF reading u32".into(),
        ));
    }
    let mut b = [0u8; 4];
    b.copy_from_slice(&data[*c..*c + 4]);
    *c += 4;
    Ok(u32::from_be_bytes(b))
}

fn read_go_u64(data: &[u8], c: &mut usize) -> Result<u64> {
    if *c + 8 > data.len() {
        return Err(QuilError::InvalidArgument(
            "pomw: EOF reading u64".into(),
        ));
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[*c..*c + 8]);
    *c += 8;
    Ok(u64::from_be_bytes(b))
}

fn read_go_bytes<'a>(data: &'a [u8], c: &mut usize, len: usize) -> Result<&'a [u8]> {
    if *c + len > data.len() {
        return Err(QuilError::InvalidArgument(
            "pomw: EOF reading bytes".into(),
        ));
    }
    let out = &data[*c..*c + len];
    *c += len;
    Ok(out)
}

/// Result of computing the expected reward root + derived address for
/// a PoMW verification. Decouples the "which tree to verify against"
/// decision from the verification itself so tests can inject fixtures.
pub struct PomwRewardContext {
    /// The traversal-proof root to verify against. For the QUIL
    /// domain this is the frame's `ProverTreeCommitment`; for any
    /// other token domain it's the `vertex_adds` shard commit.
    pub reward_root: Vec<u8>,
    /// The leaf's on-chain address — bound to the OWNER prover
    /// (the prover whose work produced the reward), not the signer.
    /// For QUIL this is `poseidon(QUIL_TOKEN_ADDRESS ‖ owner_address)`;
    /// for other tokens it's the owner address directly. Spend
    /// authority is enforced by a separate `DelegateAddress` field
    /// check inside `verify_pomw_input`, not by binding the address
    /// to the signer's pubkey.
    pub delegated_address: [u8; 32],
    /// The domain to use when verifying the traversal proof. For
    /// QUIL this is `GLOBAL_INTRINSIC_ADDRESS` (0xFF × 32); for
    /// other tokens it's the tx's own domain.
    pub prover_root_domain: [u8; 32],
}

/// Compute the address + root domain derivations from the tx domain
/// and the OWNER prover address. The on-chain reward vertex's leaf
/// key is bound to the owner (the prover whose work produced the
/// rewards), independent of who is signing the spend — this is what
/// makes delegate-spend work without rewriting the leaf.
///
/// Diverges from the original derivation, which hashed the signer's
/// pubkey here and effectively pinned spend authority to "signer is
/// the prover themselves". Spend authority is now enforced by a
/// separate check on the leaf's `DelegateAddress` field (see
/// `verify_pomw_input` step 11) rather than baked into the leaf
/// address.
pub fn derive_pomw_addressing(
    tx_domain: &[u8],
    owner_prover_address: &[u8],
) -> Result<(/* prover_root_domain */ [u8; 32], /* leaf_owner_address */ [u8; 32])> {
    if tx_domain.len() != 32 {
        return Err(QuilError::InvalidArgument(format!(
            "pomw: tx domain must be 32 bytes, got {}",
            tx_domain.len()
        )));
    }
    if owner_prover_address.len() != PROVER_ADDR_LEN {
        return Err(QuilError::InvalidArgument(format!(
            "pomw: owner prover address must be {} bytes, got {}",
            PROVER_ADDR_LEN,
            owner_prover_address.len()
        )));
    }

    let mut prover_root_domain = [0u8; 32];
    prover_root_domain.copy_from_slice(&tx_domain[..32]);

    if tx_domain == QUIL_TOKEN_ADDR {
        // QUIL special case: reward leaves live under the global
        // intrinsic domain at `poseidon(QUIL_TOKEN_ADDR ‖ owner)`
        // — exactly where `materialize::reward_address` writes them
        // at join time.
        prover_root_domain = GLOBAL_ADDR;
        let mut preimage = Vec::with_capacity(64);
        preimage.extend_from_slice(&QUIL_TOKEN_ADDR);
        preimage.extend_from_slice(owner_prover_address);
        let leaf_owner_address = quil_crypto::poseidon::hash_bytes_to_32(&preimage)?;
        Ok((prover_root_domain, leaf_owner_address))
    } else {
        // Non-QUIL: the leaf-owner address is the owner prover
        // address directly under the token's domain.
        let mut leaf_owner_address = [0u8; 32];
        leaf_owner_address.copy_from_slice(owner_prover_address);
        Ok((prover_root_domain, leaf_owner_address))
    }
}

/// Verify the `verifyProof` multiproof check from Go (mint's
/// `verifyProof:1890-1939`). It constructs expected evaluations from
/// the provided `data` fields and verifies the KZG multiproof at the
/// leaf level of the traversal proof's first subproof.
///
/// `data[i]` is a 32-byte field, `indices[i]` is the leaf slot
/// (0..64), and `keys[i]` (optional) is used as the key prefix if
/// non-empty — otherwise the prefix is `[(indices[i] as u8) << 2]`.
///
/// Returns `Ok(true)` if the multiproof verifies; `Ok(false)` if
/// KZG rejects; `Err` for structural problems.
pub fn verify_multiproof_against_leaves(
    inclusion_prover: &dyn InclusionProver,
    data: &[&[u8]],
    indices: &[usize],
    keys: &[&[u8]],
    multicommitment: &[u8],
    proof: &[u8],
    last_y_of_traversal_subproof_0: &[u8],
) -> Result<bool> {
    if data.len() != indices.len() || data.len() != keys.len() {
        return Err(QuilError::InvalidArgument(
            "pomw: verify_multiproof_against_leaves: data/indices/keys length mismatch".into(),
        ));
    }

    let mut evaluations: Vec<Vec<u8>> = Vec::with_capacity(data.len());
    let mut uindices: Vec<u64> = Vec::with_capacity(data.len());
    let mut commits: Vec<Vec<u8>> = Vec::with_capacity(data.len());

    for i in 0..data.len() {
        let mut h = Sha512::new();
        h.update([0u8]);
        if keys[i].is_empty() {
            // Empty key → use the index << 2 encoding (see Go
            // `verifyProof:1904-1906`).
            if indices[i] > u8::MAX as usize {
                return Err(QuilError::InvalidArgument(format!(
                    "pomw: index {} exceeds u8", indices[i]
                )));
            }
            h.update([(indices[i] as u8) << 2]);
        } else {
            h.update(keys[i]);
        }
        h.update(data[i]);
        evaluations.push(h.finalize().to_vec());
        commits.push(last_y_of_traversal_subproof_0.to_vec());
        uindices.push(indices[i] as u64);
    }

    let commit_refs: Vec<&[u8]> = commits.iter().map(|c| c.as_slice()).collect();
    let eval_refs: Vec<&[u8]> = evaluations.iter().map(|e| e.as_slice()).collect();

    Ok(inclusion_prover.verify_multiple(
        &commit_refs,
        &eval_refs,
        &uindices,
        64,
        multicommitment,
        proof,
    ))
}

/// Verify the address-derivation check:
/// `sha512(0x00 || prover_root_domain || delegated_address || last_y)
///  == last_commit`.
///
/// Mirrors Go lines 1832-1850. Returns `Ok(())` if the derivation
/// matches; `Err(InvalidArgument)` otherwise.
pub fn verify_pomw_address_derivation(
    prover_root_domain: &[u8; 32],
    delegated_address: &[u8; 32],
    last_y: &[u8],
    last_commit: &[u8],
) -> Result<()> {
    let mut h = Sha512::new();
    h.update([0u8]);
    h.update(prover_root_domain);
    h.update(delegated_address);
    h.update(last_y);
    let out = h.finalize();
    if out.as_slice() != last_commit {
        return Err(QuilError::InvalidArgument(
            "pomw: address derivation mismatch (last commit != sha512(...))".into(),
        ));
    }
    Ok(())
}

/// Verify a `MintTransactionInput` against the Proof-of-Meaningful-Work
/// rules. Port of `verifyWithProofOfMeaningfulWork`
/// (`token_intrinsic_mint_transaction.go:1678-1888`).
///
/// ### Inputs
///
/// - `input`:             the mint transaction input being verified
/// - `tx_domain`:         the enclosing transaction's 32-byte domain
/// - `output_transcript`: SHA3 transcript of output commitments,
///                        produced by the caller's
///                        `build_mint_transaction_transcript`
/// - `reward_root`:       the reward-tree root to verify the
///                        traversal proof against. For QUIL: the
///                        cited frame's `ProverTreeCommitment`; for
///                        other tokens: the per-domain vertex_adds
///                        shard commit at the input's frame number.
///                        The caller resolves this because it
///                        requires the clock/hypergraph store.
/// - `inclusion_prover`:  for KZG multiproof verification
/// - `bulletproof_prover`: for the hidden-Schnorr sig check
/// - `key_manager`:       for the BLS48-581 signature check
///
/// ### Returns
///
/// - `Ok(())` if every check passes
/// - `Err` with a tight description of the first failing check
///
/// ### State dependency split
///
/// This function does NOT perform the hypergraph spend-check or the
/// reward-root resolution — those live one level up in
/// `verify_proof_of_meaningful_work_with_root` (spend-check +
/// delegation) and `verify_mint_transaction_pomw` (full resolution
/// from ClockStore for QUIL or `HypergraphCrdt::get_shard_commits`
/// for non-QUIL). Token-engine dispatch calls the tx-level wrapper.
pub fn verify_pomw_input(
    input: &MintTransactionInput,
    tx_domain: &[u8],
    output_transcript: &[u8],
    reward_root: &[u8],
    inclusion_prover: &dyn InclusionProver,
    bulletproof_prover: &dyn BulletproofProver,
    key_manager: &dyn KeyManager,
) -> Result<()> {
    // 1. Structural: exactly 3 proofs.
    if input.proofs.len() != 3 {
        return Err(QuilError::InvalidArgument(format!(
            "pomw: proofs.len() = {} (expected 3)", input.proofs.len()
        )));
    }

    // 2. proofs[1] layout: <prover addr, 32> | <pubkey, 585> | <sig, 74>.
    if input.proofs[1].len() < POMW_PROOF1_MIN_LEN {
        return Err(QuilError::InvalidArgument(format!(
            "pomw: proofs[1].len() = {} (< {})",
            input.proofs[1].len(),
            POMW_PROOF1_MIN_LEN
        )));
    }

    // 3. Hidden signature must be 336 bytes (6 × 56).
    if input.signature.len() != HIDDEN_SIG_LEN {
        return Err(QuilError::InvalidArgument(format!(
            "pomw: signature.len() = {} (expected {})",
            input.signature.len(),
            HIDDEN_SIG_LEN
        )));
    }

    // 4. Commitment must be 56 bytes.
    if input.commitment.len() != DECAF_ELEM_LEN {
        return Err(QuilError::InvalidArgument(format!(
            "pomw: commitment.len() = {} (expected {})",
            input.commitment.len(),
            DECAF_ELEM_LEN
        )));
    }

    // 5. Decode the traversal proof from proofs[0].
    let traversal = parse_go_traversal_proof(&input.proofs[0])?;

    // 6. Extract owner prover address, signer pubkey, and BLS sig.
    // `pubkey` is the SIGNER's pubkey (may be the prover's own or a
    // configured delegate's). `owner_prover_address` is the prover
    // whose reward vertex is being spent — the leaf address derives
    // from this, not from the signer's pubkey.
    let owner_prover_address = &input.proofs[1][..PROVER_ADDR_LEN];
    let pubkey = &input.proofs[1][PROVER_ADDR_LEN..PROVER_ADDR_LEN + BLS48581_G2_PUBKEY_LEN];
    let signature =
        &input.proofs[1][PROVER_ADDR_LEN + BLS48581_G2_PUBKEY_LEN
            ..PROVER_ADDR_LEN + BLS48581_G2_PUBKEY_LEN + BLS48581_G1_SIG_LEN];

    // 7. Compute the addressing derivation. `leaf_owner_address` is
    // the reward vertex's location on chain — bound to the owner,
    // not the signer. Spend authority is verified separately in
    // step 11 below by reading the leaf's `DelegateAddress` field.
    let (prover_root_domain, leaf_owner_address) =
        derive_pomw_addressing(tx_domain, owner_prover_address)?;

    // 8. Verify the traversal proof against `reward_root`.
    if !verify_traversal_proof(inclusion_prover, reward_root, &traversal)? {
        return Err(QuilError::InvalidArgument(
            "pomw: traversal proof failed (reward root mismatch)".into(),
        ));
    }

    // 9. Verify the multiproof — proves the balance/address pair.
    //
    // Go builds the leaves from `[proofs[1][:32] (prover addr), value
    // as 32-byte BE]` with indices `[0, 1]` and `keys = [nil, nil]`.
    let sp0 = traversal.sub_proofs.first().ok_or_else(|| {
        QuilError::InvalidArgument("pomw: no subproof[0] for multiproof".into())
    })?;
    let last_y = sp0.ys.last().ok_or_else(|| {
        QuilError::InvalidArgument("pomw: subproof[0] has no ys".into())
    })?;
    let last_commit = sp0.commits.last().ok_or_else(|| {
        QuilError::InvalidArgument("pomw: subproof[0] has no commits".into())
    })?;

    let value_padded = pad_be_to_32(&input.value)?;
    let addr_bytes = &input.proofs[1][..PROVER_ADDR_LEN];

    // Decode the outer multiproof envelope from proofs[2]: same
    // format as the inner multiproof — `(u32 d_len, [d], u32 p_len,
    // [p])`.
    let mut mc = 0usize;
    let outer_d_len = read_go_u32(&input.proofs[2], &mut mc)? as usize;
    let outer_d = read_go_bytes(&input.proofs[2], &mut mc, outer_d_len)?;
    let outer_p_len = read_go_u32(&input.proofs[2], &mut mc)? as usize;
    let outer_p = read_go_bytes(&input.proofs[2], &mut mc, outer_p_len)?;

    let valid_mp = verify_multiproof_against_leaves(
        inclusion_prover,
        &[addr_bytes, &value_padded[..]],
        &[0, 1],
        &[&[], &[]],
        outer_d,
        outer_p,
        last_y,
    )?;
    if !valid_mp {
        return Err(QuilError::InvalidArgument(
            "pomw: multiproof rejected".into(),
        ));
    }

    // 10. Verify address derivation at the leaf. The recomputed leaf
    // commit uses the OWNER-derived address — proving the
    // `last_y` blob is the reward vertex content for this prover's
    // on-chain leaf.
    verify_pomw_address_derivation(
        &prover_root_domain,
        &leaf_owner_address,
        last_y,
        last_commit,
    )?;

    // 11. Spend authority. Parse the leaf value (`last_y`) as the
    // reward sub-tree, read its `DelegateAddress` field, and verify
    // `poseidon(signer_pubkey) == DelegateAddress`. This is the
    // single rule that covers both self-spend and delegate-spend:
    //
    //   * Self-spend: the owner never configured a delegate. Join-time
    //     materialize wrote `DelegateAddress = prover.address =
    //     poseidon(prover_pubkey)`. The signer is the prover, so
    //     `poseidon(signer_pubkey) == DelegateAddress` holds.
    //
    //   * Delegate-spend: the owner set `delegate_address =
    //     poseidon(delegate_pubkey)` via `ProverJoin.DelegateAddress`
    //     (or rotated to it via `ProverUpdate`). Only a signer whose
    //     pubkey hashes to the configured delegate address can pass
    //     this check.
    //
    // The original derivation (pre-fork) baked spend authority into
    // the leaf address by deriving it from `poseidon(signer_pubkey)`,
    // which made the `DelegateAddress` field informational only. This
    // hard-fork change moves authority out of the address into an
    // explicit check, letting delegate-spend actually work.
    let signer_addr = quil_crypto::poseidon::hash_bytes_to_32(pubkey)?;
    let leaf_subtree = crate::prover_registry::rebuild_vertex_tree_from_blob(last_y);
    let delegate_address_field = crate::global_schema::read_field(
        &leaf_subtree,
        "reward:ProverReward",
        "DelegateAddress",
    )
    .ok_or_else(|| {
        QuilError::InvalidArgument(
            "pomw: reward vertex missing DelegateAddress field".into(),
        )
    })?;
    if delegate_address_field.len() != 32 {
        return Err(QuilError::InvalidArgument(format!(
            "pomw: reward vertex DelegateAddress is {} bytes (expected 32)",
            delegate_address_field.len()
        )));
    }
    if signer_addr.as_slice() != delegate_address_field.as_slice() {
        return Err(QuilError::InvalidArgument(
            "pomw: signer pubkey does not match the reward vertex's DelegateAddress \
             (signer is neither the owner nor the configured delegate)"
                .into(),
        ));
    }

    // 12. BLS48-581 G2 signature over Signature[56*4..56*5] (the key
    // image / point component of the hidden signature), keyed by
    // `pubkey` and signed under tx_domain. Proves the signer holds
    // the private key for the `pubkey` whose hash we just matched
    // against `DelegateAddress`.
    let key_image = &input.signature[4 * DECAF_ELEM_LEN..5 * DECAF_ELEM_LEN];
    let bls_ok = key_manager.validate_signature(
        KeyType::Bls48581G1,
        pubkey,
        key_image,
        signature,
        tx_domain,
    )?;
    if !bls_ok {
        return Err(QuilError::InvalidArgument(
            "pomw: BLS48-581 signature rejected".into(),
        ));
    }

    // 12. The stated commitment must match the commitment encoded
    // in the hidden signature's last 56 bytes.
    let embedded_commitment = &input.signature[5 * DECAF_ELEM_LEN..6 * DECAF_ELEM_LEN];
    if input.commitment != embedded_commitment {
        return Err(QuilError::InvalidArgument(
            "pomw: input commitment does not match signature-embedded commitment".into(),
        ));
    }

    // 13. Hidden-Schnorr signature check over the output transcript.
    let c_s = &input.signature[0..DECAF_ELEM_LEN];
    let s1 = &input.signature[DECAF_ELEM_LEN..2 * DECAF_ELEM_LEN];
    let s2 = &input.signature[2 * DECAF_ELEM_LEN..3 * DECAF_ELEM_LEN];
    let s3 = &input.signature[3 * DECAF_ELEM_LEN..4 * DECAF_ELEM_LEN];

    let hidden_ok = bulletproof_prover.verify_hidden(
        c_s,
        output_transcript,
        s1,
        s2,
        s3,
        key_image,
        embedded_commitment,
    );
    if !hidden_ok {
        return Err(QuilError::InvalidArgument(
            "pomw: hidden-Schnorr signature rejected".into(),
        ));
    }

    Ok(())
}

fn pad_be_to_32(v: &[u8]) -> Result<[u8; 32]> {
    if v.len() > 32 {
        return Err(QuilError::InvalidArgument(format!(
            "pomw: value is {} bytes (> 32, cannot left-pad)", v.len()
        )));
    }
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(v);
    Ok(out)
}

// =====================================================================
// Full PoMW verify wrapper — resolves state dependencies
// =====================================================================

use std::sync::Arc;

use quil_hypergraph::HypergraphCrdt;
use quil_types::store::ClockStore;

/// Top-level PoMW verification for an entire `MintTransaction`. Chains
/// the state lookups that Go `verifyWithProofOfMeaningfulWork` performs
/// inline at `token_intrinsic_mint_transaction.go:1732-1794`:
///
/// 1. Resolve the cited frame number from `outputs[0].frame_number`.
/// 2. Fetch the reward root:
///    - **QUIL**: `ClockStore::get_global_clock_frame(frame).header
///      .prover_tree_commitment`
///    - **non-QUIL**: `HypergraphCrdt::get_shard_commits(frame,
///      tx.domain)[0]` (vertex_adds commit)
/// 3. Build the output transcript via `build_mint_transaction_transcript`.
/// 4. For each input, call `verify_proof_of_meaningful_work_with_root`
///    (spend-check + `verify_pomw_input` — the 13-check chain).
///
/// This function is fail-closed — missing ClockStore (for QUIL) or a
/// missing shard commit (for non-QUIL) returns `Err`.
#[allow(clippy::too_many_arguments)]
pub fn verify_mint_transaction_pomw(
    tx: &MintTransaction,
    hypergraph: &Arc<HypergraphCrdt>,
    clock_store: Option<&dyn ClockStore>,
    inclusion_prover: &dyn InclusionProver,
    bulletproof_prover: &dyn BulletproofProver,
    key_manager: &dyn KeyManager,
) -> Result<()> {
    if tx.outputs.is_empty() {
        return Err(QuilError::InvalidArgument(
            "pomw: tx has no outputs".into(),
        ));
    }
    if tx.domain.len() < 32 {
        return Err(QuilError::InvalidArgument(format!(
            "pomw: tx.domain.len() = {} (< 32)", tx.domain.len()
        )));
    }

    // Decode outputs + inputs once; reused for the transcript and
    // per-input verify.
    let mut decoded_inputs: Vec<MintTransactionInput> =
        Vec::with_capacity(tx.inputs.len());
    for raw in &tx.inputs {
        decoded_inputs.push(MintTransactionInput::from_canonical_bytes(raw)?);
    }
    let mut decoded_outputs: Vec<MintTransactionOutput> =
        Vec::with_capacity(tx.outputs.len());
    for raw in &tx.outputs {
        decoded_outputs.push(MintTransactionOutput::from_canonical_bytes(raw)?);
    }

    if decoded_outputs[0].frame_number.len() != 8 {
        return Err(QuilError::InvalidArgument(
            "pomw: outputs[0].frame_number must be 8 bytes".into(),
        ));
    }
    let mut fnb = [0u8; 8];
    fnb.copy_from_slice(&decoded_outputs[0].frame_number);
    let cited_frame = u64::from_be_bytes(fnb);

    // Reward-root resolution branches by domain.
    let reward_root: Vec<u8> = if tx.domain == QUIL_TOKEN_ADDR {
        let cs = clock_store.ok_or_else(|| QuilError::Internal(
            "pomw: clock store required for QUIL reward root".into(),
        ))?;
        let frame = cs.get_global_clock_frame(cited_frame)?;
        let header = frame.header.ok_or_else(|| QuilError::InvalidArgument(
            "pomw: cited frame has no header".into(),
        ))?;
        if header.prover_tree_commitment.is_empty() {
            return Err(QuilError::InvalidArgument(
                "pomw: cited frame has empty prover_tree_commitment".into(),
            ));
        }
        header.prover_tree_commitment
    } else {
        // Non-QUIL: reward tree root = vertex_adds shard commit at the
        // tx's own domain.
        let commits = hypergraph.get_shard_commits(cited_frame, &tx.domain)?;
        if commits.is_empty() || commits[0].is_empty() {
            return Err(QuilError::InvalidArgument(
                "pomw: non-QUIL shard vertex_adds commit missing".into(),
            ));
        }
        commits.into_iter().next().unwrap()
    };

    // Build output transcript shared across all input verifies.
    let recipients: Vec<super::transaction::RecipientBundle> = decoded_outputs
        .iter()
        .map(|o| super::transaction::RecipientBundle::from_canonical_bytes(&o.recipient_output))
        .collect::<Result<Vec<_>>>()?;
    let input_proofs: Vec<Vec<Vec<u8>>> =
        decoded_inputs.iter().map(|i| i.proofs.clone()).collect();
    let transcript = super::verify::build_mint_transaction_transcript(
        &tx.domain, &input_proofs, &decoded_outputs, &recipients,
    )?;

    for input in &decoded_inputs {
        verify_proof_of_meaningful_work_with_root(
            input,
            &tx.domain,
            &transcript,
            &reward_root,
            hypergraph,
            inclusion_prover,
            bulletproof_prover,
            key_manager,
        )?;
    }

    Ok(())
}

/// Variant of the above that skips reward-root resolution — the
/// caller supplies `reward_root` directly. Still performs the
/// spend-check and then delegates to `verify_pomw_input`.
///
/// This is the entry point the token engine dispatch should prefer
/// once it knows the frame number and has resolved the root via the
/// clock/hypergraph stores.
pub fn verify_proof_of_meaningful_work_with_root(
    input: &MintTransactionInput,
    tx_domain: &[u8],
    output_transcript: &[u8],
    reward_root: &[u8],
    hypergraph: &Arc<HypergraphCrdt>,
    inclusion_prover: &dyn InclusionProver,
    bulletproof_prover: &dyn BulletproofProver,
    key_manager: &dyn KeyManager,
) -> Result<()> {
    if input.proofs.len() != 3 {
        return Err(QuilError::InvalidArgument(format!(
            "pomw: proofs.len() = {} (expected 3)", input.proofs.len()
        )));
    }
    if tx_domain.len() < 32 {
        return Err(QuilError::InvalidArgument(format!(
            "pomw: tx_domain.len() = {} (< 32)", tx_domain.len()
        )));
    }

    let spend_addr = quil_crypto::poseidon::hash_bytes_to_32(&input.proofs[0])?;
    let mut app = [0u8; 32];
    app.copy_from_slice(&tx_domain[..32]);
    let loc = quil_hypergraph::addressing::Location {
        app_address: app,
        data_address: spend_addr,
    };
    if hypergraph.lookup_vertex(&loc) {
        return Err(QuilError::InvalidArgument(
            "pomw: proof already spent".into(),
        ));
    }

    verify_pomw_input(
        input,
        tx_domain,
        output_transcript,
        reward_root,
        inclusion_prover,
        bulletproof_prover,
        key_manager,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::{
        BulletproofProver, DecafAgreement, DecafConstructor, InclusionProver, KeyManager,
        KeyType, Multiproof, RangeProofResult,
    };

    // --- Canonical-bytes round-trip tests (pre-existing) ---

    #[test]
    fn mint_input_round_trip() {
        let i = MintTransactionInput {
            value: vec![0, 100], commitment: vec![0xAAu8; 64],
            signature: vec![0xBBu8; 74], proofs: vec![vec![0xCCu8; 32]],
            additional_reference: vec![0xDDu8; 64], additional_reference_key: vec![0xEEu8; 57],
        };
        let b = i.to_canonical_bytes().unwrap();
        assert_eq!(MintTransactionInput::from_canonical_bytes(&b).unwrap(), i);
    }

    #[test]
    fn mint_output_round_trip() {
        let o = MintTransactionOutput { frame_number: vec![0,0,0,1], commitment: vec![0xAAu8; 64], recipient_output: vec![0xBBu8; 20] };
        let b = o.to_canonical_bytes().unwrap();
        assert_eq!(MintTransactionOutput::from_canonical_bytes(&b).unwrap(), o);
    }

    #[test]
    fn mint_transaction_round_trip() {
        let mt = MintTransaction {
            domain: vec![0x11u8; 32],
            inputs: vec![MintTransactionInput { value: vec![0, 50], commitment: vec![1u8; 64], signature: vec![2u8; 74], proofs: vec![], additional_reference: vec![], additional_reference_key: vec![] }.to_canonical_bytes().unwrap()],
            outputs: vec![MintTransactionOutput { frame_number: vec![0,0,0,1], commitment: vec![3u8; 64], recipient_output: vec![] }.to_canonical_bytes().unwrap()],
            fees: vec![], range_proof: vec![0xFFu8; 128],
        };
        let b = mt.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_MINT_TRANSACTION.to_be_bytes());
        assert_eq!(MintTransaction::from_canonical_bytes(&b).unwrap(), mt);
    }

    #[test]
    fn mint_transaction_empty() {
        let mt = MintTransaction::default();
        let b = mt.to_canonical_bytes().unwrap();
        assert_eq!(MintTransaction::from_canonical_bytes(&b).unwrap(), mt);
    }

    #[test]
    fn all_mint_type_prefixes_distinct() {
        use std::collections::HashSet;
        let ids: HashSet<u32> = [TYPE_MINT_TRANSACTION_INPUT, TYPE_MINT_TRANSACTION_OUTPUT, TYPE_MINT_TRANSACTION].into_iter().collect();
        assert_eq!(ids.len(), 3);
    }

    // --- Test doubles ---

    struct AcceptBulletproofs;
    impl BulletproofProver for AcceptBulletproofs {
        fn generate_range_proof(&self, _: &[Vec<u8>], _: &[u8], _: u64) -> Result<RangeProofResult> { Err(QuilError::Internal("n/a".into())) }
        fn generate_input_commitments(&self, _: &[Vec<u8>], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_range_proof(&self, _: &[u8], _: &[u8], _: u64) -> bool { true }
        fn sum_check(&self, _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>]) -> bool { true }
        fn sign_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> bool { true }
        fn simple_sign(&self, _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn simple_verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool { true }
    }

    // Rejects only the hidden bulletproof, accepts range proof + sum check.
    struct RejectHiddenOnly;
    impl BulletproofProver for RejectHiddenOnly {
        fn generate_range_proof(&self, _: &[Vec<u8>], _: &[u8], _: u64) -> Result<RangeProofResult> { Err(QuilError::Internal("n/a".into())) }
        fn generate_input_commitments(&self, _: &[Vec<u8>], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_range_proof(&self, _: &[u8], _: &[u8], _: u64) -> bool { true }
        fn sum_check(&self, _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>]) -> bool { true }
        fn sign_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> bool { false }
        fn simple_sign(&self, _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn simple_verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool { false }
    }

    struct StubDecaf;
    impl DecafConstructor for StubDecaf {
        fn new_key(&self) -> Result<Box<dyn DecafAgreement>> { Err(QuilError::Internal("n/a".into())) }
        fn from_bytes(&self, _: &[u8]) -> Result<Box<dyn DecafAgreement>> { Err(QuilError::Internal("n/a".into())) }
        fn hash_to_scalar(&self, data: &[u8]) -> Result<Vec<u8>> {
            // Deterministic cheap hash: truncate/pad SHA3-256 to 56 bytes.
            use quil_crypto::poseidon::hash_bytes_to_32;
            let h = hash_bytes_to_32(data)?;
            let mut out = Vec::with_capacity(56);
            out.extend_from_slice(&h);
            out.extend_from_slice(&h[..24]);
            Ok(out)
        }
        fn new_from_scalar(&self, _: &[u8]) -> Result<Box<dyn DecafAgreement>> { Err(QuilError::Internal("n/a".into())) }
        fn alt_generator(&self) -> Vec<u8> { vec![0u8; 56] }
    }

    struct AcceptKm;
    impl KeyManager for AcceptKm {
        fn validate_signature(&self, _: KeyType, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<bool> { Ok(true) }
    }

    struct RejectKm;
    impl KeyManager for RejectKm {
        fn validate_signature(&self, _: KeyType, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<bool> { Ok(false) }
    }

    struct StubInclusion;
    impl InclusionProver for StubInclusion {
        fn commit_raw(&self, data: &[u8], _: u64) -> Result<Vec<u8>> {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new(); data.hash(&mut h);
            let h = h.finish().to_be_bytes();
            let mut out = vec![0u8; 64]; out[..8].copy_from_slice(&h); Ok(out)
        }
        fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> { Ok(vec![]) }
        fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> { Ok(true) }
        fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64) -> Result<Box<dyn Multiproof>> { Err(QuilError::Internal("n/a".into())) }
        fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { true }
    }

    // --- Test fixtures ---

    /// Build a valid authority mint transaction (one input, one
    /// output) with all structural constraints satisfied.
    fn build_valid_authority_mint() -> MintTransaction {
        // Value = 100 (big-endian big.Int encoding = [0x64]).
        // But proof[0..32] compares as big int to value, so we pad to 32.
        let value_be: Vec<u8> = {
            let mut v = vec![0u8; 32]; v[31] = 0x64; v
        };
        // Signature: 336 bytes, verification_key at [224..280], commitment at [280..336].
        let vk = vec![0xAAu8; 56];
        let commitment = vec![0xBBu8; 56];
        let mut signature = vec![0x00u8; 336];
        signature[56 * 4..56 * 5].copy_from_slice(&vk);
        signature[56 * 5..56 * 6].copy_from_slice(&commitment);

        // proof = value(32) || key_image(56) || authority_sig(74 for BLS)
        let mut proof = Vec::with_capacity(88 + 74);
        proof.extend_from_slice(&value_be);
        proof.extend_from_slice(&vk); // key image must equal signature[56*4..56*5]
        proof.extend_from_slice(&vec![0xCCu8; 74]); // BLS signature placeholder
        assert_eq!(proof.len(), 88 + 74);

        // User-visible value stored in MintTransactionInput may drop
        // leading zeros (Go encodes big.Int via FillBytes -> SetBytes).
        let input = MintTransactionInput {
            value: vec![0x64],
            commitment: commitment.clone(),
            signature: signature.clone(),
            proofs: vec![proof],
            additional_reference: vec![],
            additional_reference_key: vec![],
        };

        // Recipient bundle (56-byte fields).
        let recipient = super::super::transaction::RecipientBundle {
            one_time_key: vec![0x11u8; 56],
            verification_key: vec![0x22u8; 56],
            coin_balance: vec![0x33u8; 56],
            mask: vec![0x44u8; 56],
            additional_reference: vec![],
            additional_reference_key: vec![],
        };

        // Output frame number strictly less than verify frame_number (we use 10).
        let out_frame = 1u64.to_be_bytes().to_vec();
        let output = MintTransactionOutput {
            frame_number: out_frame,
            commitment: vec![0x55u8; 56],
            recipient_output: recipient.to_canonical_bytes().unwrap(),
        };

        MintTransaction {
            domain: vec![0x77u8; 32],
            inputs: vec![input.to_canonical_bytes().unwrap()],
            outputs: vec![output.to_canonical_bytes().unwrap()],
            fees: vec![],
            range_proof: vec![0xEEu8; 128],
        }
    }

    // --- Authority verification tests ---

    #[test]
    fn authority_valid_mint_is_accepted() {
        let tx = build_valid_authority_mint();
        let ok = verify_authority(
            &tx,
            10, // frame_number argument
            KeyType::Bls48581G2 as u32,
            &vec![0xDDu8; 97], // authority pubkey (length not enforced by stub)
            super::super::constants::QUIL_BEHAVIOR,
            &AcceptBulletproofs,
            &StubDecaf,
            &AcceptKm,
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn authority_bad_authority_signature_is_rejected() {
        let tx = build_valid_authority_mint();
        // RejectKm returns false → whole verify returns Ok(false).
        let ok = verify_authority(
            &tx, 10,
            KeyType::Bls48581G2 as u32,
            &vec![0xDDu8; 97],
            super::super::constants::QUIL_BEHAVIOR,
            &AcceptBulletproofs,
            &StubDecaf,
            &RejectKm,
        )
        .unwrap();
        assert!(!ok);
    }

    #[test]
    fn authority_bad_hidden_signature_is_rejected() {
        let tx = build_valid_authority_mint();
        let ok = verify_authority(
            &tx, 10,
            KeyType::Bls48581G2 as u32,
            &vec![0xDDu8; 97],
            super::super::constants::QUIL_BEHAVIOR,
            &RejectHiddenOnly,
            &StubDecaf,
            &AcceptKm,
        )
        .unwrap();
        assert!(!ok);
    }

    #[test]
    fn authority_zero_outputs_is_rejected() {
        let mut tx = build_valid_authority_mint();
        tx.outputs.clear();
        let err = verify_authority(
            &tx, 10,
            KeyType::Bls48581G2 as u32,
            &vec![0xDDu8; 97],
            super::super::constants::QUIL_BEHAVIOR,
            &AcceptBulletproofs, &StubDecaf, &AcceptKm,
        );
        assert!(err.is_err());
    }

    #[test]
    fn authority_key_image_mismatch_is_rejected() {
        let tx = build_valid_authority_mint();
        // Mutate the input so that proof[32..88] no longer equals
        // signature[56*4..56*5].
        let mut input = MintTransactionInput::from_canonical_bytes(&tx.inputs[0]).unwrap();
        input.proofs[0][32] ^= 0xFF;
        let mut tx = tx.clone();
        tx.inputs[0] = input.to_canonical_bytes().unwrap();
        let err = verify_authority(
            &tx, 10,
            KeyType::Bls48581G2 as u32,
            &vec![0xDDu8; 97],
            super::super::constants::QUIL_BEHAVIOR,
            &AcceptBulletproofs, &StubDecaf, &AcceptKm,
        );
        assert!(err.is_err());
    }

    #[test]
    fn authority_commitment_mismatch_is_rejected() {
        let tx = build_valid_authority_mint();
        let mut input = MintTransactionInput::from_canonical_bytes(&tx.inputs[0]).unwrap();
        input.commitment[0] ^= 0xFF;
        // Signature still embeds the original commitment at [280..336];
        // mutating `input.commitment` breaks the binding check.
        let mut tx = tx.clone();
        tx.inputs[0] = input.to_canonical_bytes().unwrap();
        let err = verify_authority(
            &tx, 10,
            KeyType::Bls48581G2 as u32,
            &vec![0xDDu8; 97],
            super::super::constants::QUIL_BEHAVIOR,
            &AcceptBulletproofs, &StubDecaf, &AcceptKm,
        );
        assert!(err.is_err());
    }

    #[test]
    fn authority_value_proof_mismatch_is_rejected() {
        let tx = build_valid_authority_mint();
        let mut input = MintTransactionInput::from_canonical_bytes(&tx.inputs[0]).unwrap();
        // Input.Value says 0x64 but proof[0..32] says 0x65.
        input.proofs[0][31] = 0x65;
        let mut tx = tx.clone();
        tx.inputs[0] = input.to_canonical_bytes().unwrap();
        let err = verify_authority(
            &tx, 10,
            KeyType::Bls48581G2 as u32,
            &vec![0xDDu8; 97],
            super::super::constants::QUIL_BEHAVIOR,
            &AcceptBulletproofs, &StubDecaf, &AcceptKm,
        );
        assert!(err.is_err());
    }

    #[test]
    fn authority_output_frame_ge_verify_frame_is_rejected() {
        let tx = build_valid_authority_mint();
        // Output frame = 1, call verify with frame_number = 1 (not >).
        let err = verify_authority(
            &tx, 1,
            KeyType::Bls48581G2 as u32,
            &vec![0xDDu8; 97],
            super::super::constants::QUIL_BEHAVIOR,
            &AcceptBulletproofs, &StubDecaf, &AcceptKm,
        );
        assert!(err.is_err());
    }

    #[test]
    fn authority_unknown_key_type_is_rejected() {
        let tx = build_valid_authority_mint();
        let err = verify_authority(
            &tx, 10,
            99, // invalid
            &vec![0xDDu8; 97],
            super::super::constants::QUIL_BEHAVIOR,
            &AcceptBulletproofs, &StubDecaf, &AcceptKm,
        );
        assert!(err.is_err());
    }

    // --- Non-authority variant smoke tests ---

    #[test]
    fn verify_with_signature_runs_authority_chain_plus_vk_binding() {
        // Signature variant runs the full Authority 9-check chain
        // PLUS the per-output `output[i].VK == input[i].proofs[0][32..88]`
        // constraint. The default fixture has output VK = 0x22 but
        // input proofs[0][32..88] = 0xAA (the key image), so verify
        // must reject.
        let tx = build_valid_authority_mint();
        let err = verify_with_signature(
            &tx, 10, KeyType::Bls48581G1 as u32,
            &vec![0xDDu8; 97],
            super::super::constants::QUIL_BEHAVIOR,
            &AcceptBulletproofs, &StubDecaf, &AcceptKm,
        );
        assert!(err.is_err(), "signature variant must enforce output VK binding");
    }

    #[test]
    fn verify_with_signature_accepts_when_output_vk_matches_proof_image() {
        // Build the same fixture but make output VK = key image (the
        // signature variant's binding constraint).
        let mut tx = build_valid_authority_mint();
        let key_image = vec![0xAAu8; 56]; // matches signature[56*4..56*5] in the fixture
        let mut out = MintTransactionOutput::from_canonical_bytes(&tx.outputs[0]).unwrap();
        let mut recipient = super::super::transaction::RecipientBundle::from_canonical_bytes(
            &out.recipient_output,
        )
        .unwrap();
        recipient.verification_key = key_image.clone();
        out.recipient_output = recipient.to_canonical_bytes().unwrap();
        tx.outputs[0] = out.to_canonical_bytes().unwrap();
        let ok = verify_with_signature(
            &tx, 10, KeyType::Bls48581G1 as u32,
            &vec![0xDDu8; 97],
            super::super::constants::QUIL_BEHAVIOR,
            &AcceptBulletproofs, &StubDecaf, &AcceptKm,
        ).unwrap();
        assert!(ok);
    }

    #[test]
    fn verkle_input_rejects_undersized_proof() {
        let mut input = MintTransactionInput::default();
        input.commitment = vec![0xBBu8; 56];
        input.signature = vec![0u8; 336];
        input.value = vec![1];
        input.proofs = vec![vec![0u8; 50]]; // < 88 bytes
        let err = verify_verkle_multiproof_input(
            &input, &[], &vec![0u8; 64], &StubInclusion, &AcceptBulletproofs,
        );
        assert!(err.is_err(), "expected rejection on undersized proof");
    }

    #[test]
    fn verkle_input_rejects_amount_mismatch() {
        let mut input = MintTransactionInput::default();
        input.commitment = vec![0xBBu8; 56];
        input.signature = vec![0u8; 336];
        input.value = vec![0x64]; // 100
        // Proof: 0 bytes traversal + amount (32) + image (56). Amount = 200.
        let mut proof = vec![0u8; 88];
        proof[31] = 0xC8; // 200
        input.proofs = vec![proof];
        let err = verify_verkle_multiproof_input(
            &input, &[], &vec![0u8; 64], &StubInclusion, &AcceptBulletproofs,
        );
        assert!(err.is_err(), "expected rejection on amount mismatch");
    }

    #[test]
    fn payment_input_free_mint_requires_exactly_224_byte_proof() {
        let mut input = MintTransactionInput::default();
        input.commitment = vec![0xBBu8; 56];
        input.signature = vec![0u8; 336];
        input.value = vec![0x64];
        input.proofs = vec![vec![0u8; 100]];
        let cfg = MintWithPaymentConfig {
            fee_baseline: None,
            payment_address: &[0u8; 32],
        };
        let err = verify_with_payment_input(
            &input, &[], 0, &cfg, &StubDecaf, &AcceptBulletproofs,
            |_nested, _idx, _pa| Err(QuilError::Internal(
                "nested pending should not be called for free mint".into(),
            )),
        );
        assert!(err.is_err(), "expected rejection on free-mint proof length != 224");
    }

    // --- bigint_bytes_equal helper ---

    #[test]
    fn bigint_bytes_equal_handles_leading_zeros() {
        assert!(bigint_bytes_equal(&[0, 0, 0x64], &[0x64]));
        assert!(bigint_bytes_equal(&[], &[0]));
        assert!(!bigint_bytes_equal(&[0x64], &[0x65]));
        assert!(bigint_bytes_equal(&[0; 32], &[]));
    }

    // --- Materialize tests ---

    #[test]
    fn materialize_authority_produces_coin_and_spent_marker() {
        let tx = build_valid_authority_mint();
        let result = materialize_authority(&tx, &StubInclusion).unwrap();
        assert_eq!(result.coins.len(), 1);
        assert_eq!(result.spent_markers.len(), 1);

        let (coin_addr, _coin_tree) = &result.coins[0];
        // Address = poseidon(verification_key) where verification_key = 0x22u8; 56.
        let expected_addr = quil_crypto::poseidon::hash_bytes_to_32(&vec![0x22u8; 56]).unwrap();
        assert_eq!(coin_addr, &expected_addr);

        // Spent marker = poseidon(proof).
        let input = MintTransactionInput::from_canonical_bytes(&tx.inputs[0]).unwrap();
        let expected_spent = quil_crypto::poseidon::hash_bytes_to_32(&input.proofs[0]).unwrap();
        assert_eq!(&result.spent_markers[0].0, &expected_spent);
    }

    #[test]
    fn materialize_authority_missing_vk_is_rejected() {
        let tx = build_valid_authority_mint();
        let mut out = MintTransactionOutput::from_canonical_bytes(&tx.outputs[0]).unwrap();
        let mut recipient = super::super::transaction::RecipientBundle::from_canonical_bytes(
            &out.recipient_output,
        )
        .unwrap();
        recipient.verification_key = vec![];
        out.recipient_output = recipient.to_canonical_bytes().unwrap();
        let mut tx = tx.clone();
        tx.outputs[0] = out.to_canonical_bytes().unwrap();
        assert!(materialize_authority(&tx, &StubInclusion).is_err());
    }

    fn build_valid_pomw_mint(prover_addr: &[u8; 32]) -> MintTransaction {
        // proofs[1] must be at least 32 bytes (prover address) — for
        // materialize we don't need the full 691-byte PoMW layout.
        let proofs_1 = prover_addr.to_vec();
        let proof_0 = vec![0xCCu8; 88];

        let vk = vec![0xAAu8; 56];
        let commitment = vec![0xBBu8; 56];
        let mut signature = vec![0x00u8; 336];
        signature[56 * 4..56 * 5].copy_from_slice(&vk);
        signature[56 * 5..56 * 6].copy_from_slice(&commitment);

        let input = MintTransactionInput {
            value: vec![0x64], // 100
            commitment: commitment.clone(),
            signature,
            proofs: vec![proof_0, proofs_1],
            additional_reference: vec![],
            additional_reference_key: vec![],
        };

        let recipient = super::super::transaction::RecipientBundle {
            one_time_key: vec![0x11u8; 56],
            verification_key: vec![0x22u8; 56],
            coin_balance: vec![0x33u8; 56],
            mask: vec![0x44u8; 56],
            additional_reference: vec![],
            additional_reference_key: vec![],
        };

        let output = MintTransactionOutput {
            frame_number: 1u64.to_be_bytes().to_vec(),
            commitment: vec![0x55u8; 56],
            recipient_output: recipient.to_canonical_bytes().unwrap(),
        };

        MintTransaction {
            domain: crate::domains::QUIL_TOKEN.to_vec(),
            inputs: vec![input.to_canonical_bytes().unwrap()],
            outputs: vec![output.to_canonical_bytes().unwrap()],
            fees: vec![],
            range_proof: vec![0xEEu8; 128],
        }
    }

    fn install_reward_balance(
        state: &crate::hypergraph_state::HypergraphState,
        prover_addr: &[u8; 32],
        balance: u64,
    ) {
        let mut reward_tree = quil_tries::VectorCommitmentTree::new();
        let mut balance_bytes = vec![0u8; 32];
        balance_bytes[24..32].copy_from_slice(&balance.to_be_bytes());
        crate::global_intrinsic::materialize::set_reward_balance(
            &mut reward_tree, &balance_bytes,
        ).unwrap();
        let blob = crate::prover_registry::vertex_tree_to_blob(&reward_tree);

        let reward_addr =
            crate::global_intrinsic::materialize::reward_address(prover_addr).unwrap();
        let va_disc = crate::hypergraph_state::vertex_adds_discriminator().unwrap();
        state.set(&crate::domains::GLOBAL, &reward_addr, &va_disc, 1, blob).unwrap();
    }

    fn stub_state() -> crate::hypergraph_state::HypergraphState {
        use std::sync::Arc;
        use quil_hypergraph::HypergraphCrdt;
        use quil_hypergraph::testing::MemStore;
        use quil_types::crypto::NoopInclusionProver;
        let crdt = HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(NoopInclusionProver),
        );
        crate::hypergraph_state::HypergraphState::new(Arc::new(crdt))
    }

    #[test]
    fn materialize_pomw_decrements_prover_balance() {
        let prover_addr = [0x77u8; 32];
        let tx = build_valid_pomw_mint(&prover_addr);
        let state = stub_state();
        install_reward_balance(&state, &prover_addr, 500);

        let result = materialize_pomw(
            &tx, &state, /*frame*/ 10, /*is_quil*/ true, &StubInclusion,
        ).unwrap();
        assert_eq!(result.coins.len(), 1);
        assert_eq!(result.spent_markers.len(), 1);

        // Re-read the reward vertex and confirm balance = 500 - 100 = 400.
        let reward_addr =
            crate::global_intrinsic::materialize::reward_address(&prover_addr).unwrap();
        let va_disc = crate::hypergraph_state::vertex_adds_discriminator().unwrap();
        let blob = state.get(&crate::domains::GLOBAL, &reward_addr, &va_disc).unwrap().unwrap();
        let reward_tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&blob);
        let balance_bytes =
            crate::global_intrinsic::materialize::read_reward_balance(&reward_tree);
        let balance = num_bigint::BigInt::from_bytes_be(
            num_bigint::Sign::Plus, &balance_bytes,
        );
        assert_eq!(balance, num_bigint::BigInt::from(400));
    }

    #[test]
    fn materialize_pomw_rejects_insufficient_balance() {
        let prover_addr = [0x88u8; 32];
        let tx = build_valid_pomw_mint(&prover_addr);
        let state = stub_state();
        install_reward_balance(&state, &prover_addr, 50); // < 100

        let err = materialize_pomw(
            &tx, &state, 10, true, &StubInclusion,
        );
        assert!(err.is_err(), "expected rejection on insufficient balance");
    }

    #[test]
    fn materialize_pomw_rejects_missing_reward_vertex() {
        let prover_addr = [0x99u8; 32];
        let tx = build_valid_pomw_mint(&prover_addr);
        let state = stub_state();
        // No install_reward_balance — the vertex is absent.

        let err = materialize_pomw(
            &tx, &state, 10, true, &StubInclusion,
        );
        assert!(err.is_err(), "expected rejection when reward vertex missing");
    }

    // --- GetCost tests ---

    #[test]
    fn get_cost_matches_byte_sum_for_authority_mint() {
        let tx = build_valid_authority_mint();
        // Domain(32) + RangeProof(128) + 1 output: 8 + Commitment(56)
        //   + CoinBalance(56) + Mask(56) + OneTimeKey(56) + VerificationKey(56)
        //   + (non-divisible ? 110 : 0).
        // QUIL behavior is Divisible, so no 110 overhead.
        let cost = tx.get_cost(crate::token_intrinsic::constants::QUIL_BEHAVIOR).unwrap();
        let expected = num_bigint::BigInt::from(
            32u64 + 128 + 8 + 56 + 56 + 56 + 56 + 56
        );
        assert_eq!(cost, expected);
    }

    #[test]
    fn get_cost_adds_110_per_output_for_non_divisible() {
        let tx = build_valid_authority_mint();
        let cost = tx.get_cost(0 /* no Divisible flag */).unwrap();
        let divisible_cost = tx.get_cost(crate::token_intrinsic::constants::QUIL_BEHAVIOR).unwrap();
        assert_eq!(cost - divisible_cost, num_bigint::BigInt::from(110u64));
    }
}

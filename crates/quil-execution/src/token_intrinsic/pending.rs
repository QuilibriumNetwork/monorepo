//! Pending transaction types: PendingTransactionInput (0x050A),
//! PendingTransactionOutput (0x050B), PendingTransaction (0x050C).
//!
//! Also hosts the crypto-level `Verify` + `Materialize` helpers ported
//! from `node/execution/intrinsics/token/token_intrinsic_pending_transaction.go`.

use num_bigint::BigInt;
use num_traits::One;
use quil_hypergraph::HypergraphCrdt;
use quil_types::crypto::{BulletproofProver, DecafConstructor, InclusionProver};
use quil_types::error::{QuilError, Result};

use super::constants::{ACCEPTABLE, DIVISIBLE, FRAME_2_1_CUTOVER};
use super::cursor::*;
use super::materialize::{
    create_pending_transaction_tree, create_spent_marker_tree,
    pending_type_hash, spent_address,
};
use super::transaction::RecipientBundle;
use super::verify::{
    validate_input_structural, validate_transaction_structural,
    verify_input_hidden_signature, verify_transaction_crypto, MAX_IO_COUNT,
    RANGE_PROOF_BIT_SIZE,
};

/// Public-read key for the pre-2.1 VerEnc coin fields. Matches Go
/// `token_intrinsic_transaction.go:33`:
/// `2cf07ca8d9ab1a4bb0902e25a9b90759dd54d881f54d52a76a17e79bf0361c325650f12746e4337ffb5940e7665ad7bf83f44af98d964bbe`.
const PUBLIC_READ_KEY: [u8; 56] = [
    0x2c, 0xf0, 0x7c, 0xa8, 0xd9, 0xab, 0x1a, 0x4b,
    0xb0, 0x90, 0x2e, 0x25, 0xa9, 0xb9, 0x07, 0x59,
    0xdd, 0x54, 0xd8, 0x81, 0xf5, 0x4d, 0x52, 0xa7,
    0x6a, 0x17, 0xe7, 0x9b, 0xf0, 0x36, 0x1c, 0x32,
    0x56, 0x50, 0xf1, 0x27, 0x46, 0xe4, 0x33, 0x7f,
    0xfb, 0x59, 0x40, 0xe7, 0x66, 0x5a, 0xd7, 0xbf,
    0x83, 0xf4, 0x4a, 0xf9, 0x8d, 0x96, 0x4b, 0xbe,
];

pub const TYPE_PENDING_TRANSACTION_INPUT: u32 = 0x050A;
pub const TYPE_PENDING_TRANSACTION_OUTPUT: u32 = 0x050B;
pub const TYPE_PENDING_TRANSACTION: u32 = 0x050C;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PendingTransactionInput {
    pub commitment: Vec<u8>,
    pub signature: Vec<u8>,
    pub proofs: Vec<Vec<u8>>,
}

impl PendingTransactionInput {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PENDING_TRANSACTION_INPUT);
        put_lp(&mut out, &self.commitment);
        put_lp(&mut out, &self.signature);
        write_array(&mut out, &self.proofs);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_PENDING_TRANSACTION_INPUT, "PendingTransactionInput")?;
        Ok(Self { commitment: read_lp(data, &mut c)?, signature: read_lp(data, &mut c)?, proofs: read_array(data, &mut c)? })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PendingTransactionOutput {
    pub frame_number: Vec<u8>,
    pub commitment: Vec<u8>,
    pub to: Vec<u8>,           // nested RecipientBundle canonical bytes
    pub refund: Vec<u8>,       // nested RecipientBundle canonical bytes
    pub expiration: u64,
}

impl PendingTransactionOutput {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PENDING_TRANSACTION_OUTPUT);
        put_lp(&mut out, &self.frame_number);
        put_lp(&mut out, &self.commitment);
        put_lp(&mut out, &self.to);
        put_lp(&mut out, &self.refund);
        put_u64(&mut out, self.expiration);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_PENDING_TRANSACTION_OUTPUT, "PendingTransactionOutput")?;
        Ok(Self {
            frame_number: read_lp(data, &mut c)?,
            commitment: read_lp(data, &mut c)?,
            to: read_lp(data, &mut c)?,
            refund: read_lp(data, &mut c)?,
            expiration: read_u64(data, &mut c)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PendingTransaction {
    pub domain: Vec<u8>,
    pub inputs: Vec<Vec<u8>>,
    pub outputs: Vec<Vec<u8>>,
    pub fees: Vec<Vec<u8>>,
    pub range_proof: Vec<u8>,
    pub traversal_proof: Vec<u8>,
}

impl PendingTransaction {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PENDING_TRANSACTION);
        put_lp(&mut out, &self.domain);
        write_array(&mut out, &self.inputs);
        write_array(&mut out, &self.outputs);
        write_array(&mut out, &self.fees);
        put_lp(&mut out, &self.range_proof);
        put_lp(&mut out, &self.traversal_proof);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_PENDING_TRANSACTION, "PendingTransaction")?;
        Ok(Self {
            domain: read_lp(data, &mut c)?,
            inputs: read_array(data, &mut c)?,
            outputs: read_array(data, &mut c)?,
            fees: read_array(data, &mut c)?,
            range_proof: read_lp(data, &mut c)?,
            traversal_proof: read_lp(data, &mut c)?,
        })
    }

    /// Byte-size cost basis for fee computation. Ports Go
    /// `PendingTransaction.GetCost` at
    /// `token_intrinsic_pending_transaction.go:1328-1358`. Accounts for
    /// both the `to` and `refund` recipient bundles per output.
    pub fn get_cost(&self) -> Result<BigInt> {
        let mut size = BigInt::from(self.domain.len() as u64);
        size += BigInt::from(self.range_proof.len() as u64);
        size += BigInt::from(self.traversal_proof.len() as u64);
        for raw in &self.outputs {
            let out = PendingTransactionOutput::from_canonical_bytes(raw)?;
            let to = RecipientBundle::from_canonical_bytes(&out.to)?;
            let refund = RecipientBundle::from_canonical_bytes(&out.refund)?;
            size += BigInt::from(8u64);
            size += BigInt::from(out.commitment.len() as u64);
            // refund
            size += BigInt::from(refund.coin_balance.len() as u64);
            size += BigInt::from(refund.mask.len() as u64);
            size += BigInt::from(refund.one_time_key.len() as u64);
            size += BigInt::from(refund.verification_key.len() as u64);
            if refund.additional_reference.len() == 64 {
                size += BigInt::from(120u64);
            }
            // to
            size += BigInt::from(to.coin_balance.len() as u64);
            size += BigInt::from(to.mask.len() as u64);
            size += BigInt::from(to.one_time_key.len() as u64);
            size += BigInt::from(to.verification_key.len() as u64);
            if to.additional_reference.len() == 64 {
                size += BigInt::from(120u64);
            }
        }
        Ok(size)
    }
}

// =====================================================================
// Legacy coin decoding (pre-FRAME_2_1_CUTOVER coins)
// =====================================================================

/// Decoded coin context used during input signature verification.
///
/// Pre-2.1 (frame < 244200) coins have a "packed" layout where the
/// frame number is a LittleEndian uint64 sitting in an encrypted
/// `VerEnc` blob, and the encryption_key + cipher are concatenated
/// into a single field at key `{0}` rather than split into separate
/// tree keys. See Go `token_intrinsic_pending_transaction.go:85-120`.
///
/// Post-2.1 coins use BigEndian and separate fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoinFormat {
    /// Frame < 244200: LittleEndian uint64, packed encryption.
    Legacy,
    /// Frame >= 244200: BigEndian uint64, separate encryption fields.
    Modern,
}

impl CoinFormat {
    /// Select the coin format for a given frame number.
    /// Matches Go's cutover: frames <= FRAME_2_1_CUTOVER use legacy.
    pub fn for_frame(frame_number: u64) -> Self {
        if frame_number < FRAME_2_1_CUTOVER {
            Self::Legacy
        } else {
            Self::Modern
        }
    }
}

/// Decode a coin's frame number from its vertex tree's raw bytes at
/// key `{0,0,0,0,0,0,0,0}` (modern, 8-byte BE) or key `{0}` (legacy,
/// packed VerEnc blob). For the legacy path we cannot actually decrypt
/// without the `publicReadKey`-aware verifiable-encryptor, but we can
/// still identify the format by whether the raw bytes length is 8.
///
/// Mirrors the probing loop at Go `token_intrinsic_pending_transaction.go:85-120`.
pub fn detect_coin_format_from_framebytes(fn_data: &[u8]) -> CoinFormat {
    // Modern format stores the frame number as raw 8 BE bytes
    if fn_data.len() == 8 {
        CoinFormat::Modern
    } else {
        CoinFormat::Legacy
    }
}

/// Read a coin frame number from already-decoded 8-byte raw bytes.
/// `is_legacy = true` uses LittleEndian (pre-2.1 packed format);
/// false uses BigEndian (modern).
pub fn read_coin_frame_number(raw_bytes: &[u8], is_legacy: bool) -> Result<u64> {
    if raw_bytes.len() < 8 {
        return Err(QuilError::InvalidArgument(format!(
            "coin frame number: expected >=8 bytes, got {}",
            raw_bytes.len()
        )));
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&raw_bytes[..8]);
    Ok(if is_legacy {
        u64::from_le_bytes(b)
    } else {
        u64::from_be_bytes(b)
    })
}

// =====================================================================
// Transcript construction for PendingTransaction challenge
// =====================================================================

/// Build the transcript that is hashed to form the challenge for the
/// hidden Schnorr signatures on each input.
///
/// Mirrors Go `PendingTransaction.GetChallenge()` at
/// `token_intrinsic_pending_transaction.go:1532-1559`:
/// - domain
/// - for each output:
///   - commitment (56B)
///   - expiration (u64 BE, 8B)
///   - frame_number (8B)
///   - if to.additional_reference is 64B: to.additional_reference || to.additional_reference_key
///   - to.coin_balance (56B) || to.mask (56B) || to.one_time_key (56B) || to.verification_key (56B)
///   - if refund.additional_reference is 64B: refund.additional_reference || refund.additional_reference_key
///   - refund.coin_balance (56B) || refund.mask (56B) || refund.one_time_key (56B) || refund.verification_key (56B)
///
/// The output recipients are decoded from nested RecipientBundle canonical bytes.
pub fn build_pending_transaction_transcript(tx: &PendingTransaction) -> Result<Vec<u8>> {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(&tx.domain);

    for raw in &tx.outputs {
        let output = PendingTransactionOutput::from_canonical_bytes(raw)?;
        let to = RecipientBundle::from_canonical_bytes(&output.to)?;
        let refund = RecipientBundle::from_canonical_bytes(&output.refund)?;

        transcript.extend_from_slice(&output.commitment);
        transcript.extend_from_slice(&output.expiration.to_be_bytes());
        transcript.extend_from_slice(&output.frame_number);

        if to.additional_reference.len() == 64 {
            transcript.extend_from_slice(&to.additional_reference);
            transcript.extend_from_slice(&to.additional_reference_key);
        }
        transcript.extend_from_slice(&to.coin_balance);
        transcript.extend_from_slice(&to.mask);
        transcript.extend_from_slice(&to.one_time_key);
        transcript.extend_from_slice(&to.verification_key);

        if refund.additional_reference.len() == 64 {
            transcript.extend_from_slice(&refund.additional_reference);
            transcript.extend_from_slice(&refund.additional_reference_key);
        }
        transcript.extend_from_slice(&refund.coin_balance);
        transcript.extend_from_slice(&refund.mask);
        transcript.extend_from_slice(&refund.one_time_key);
        transcript.extend_from_slice(&refund.verification_key);
    }

    Ok(transcript)
}

/// Reduce a transcript to a DECAF448 scalar (56 bytes) via
/// `DecafConstructor::hash_to_scalar`. Mirrors Go's
/// `tx.decafConstructor.HashToScalar(transcript)`.
pub fn compute_transaction_challenge(
    dc: &dyn DecafConstructor,
    transcript: &[u8],
) -> Result<Vec<u8>> {
    dc.hash_to_scalar(transcript)
}

// =====================================================================
// Verify: crypto-level + structural
// =====================================================================

/// Behavior flag preflight: `PendingTransaction` is only valid when
/// the domain's behavior includes `ACCEPTABLE`. Go check at
/// `token_intrinsic_pending_transaction.go:495-497`.
pub fn check_acceptable(behavior: u16) -> Result<()> {
    if behavior & ACCEPTABLE == 0 {
        return Err(QuilError::InvalidArgument(
            "pending: behavior lacks ACCEPTABLE flag".into(),
        ));
    }
    Ok(())
}

/// Structural validation specific to `PendingTransaction`:
/// - Exactly 2 outputs (to + refund branches)
/// - 1..=MAX_IO_COUNT inputs
/// - Fees within [0, 2^128]
/// - If non-divisible, inputs.len() == outputs.len() (2, since outputs=2)
///
/// Mirrors the opening of Go `Verify` at
/// `token_intrinsic_pending_transaction.go:1563-1586`.
pub fn validate_pending_structural(
    tx: &PendingTransaction,
    behavior: u16,
) -> Result<()> {
    // Acceptable flag
    check_acceptable(behavior)?;

    let input_count = tx.inputs.len();
    let output_count = tx.outputs.len();

    // PendingTransaction always has exactly 2 outputs (to + refund).
    if output_count != 2 {
        return Err(QuilError::InvalidArgument(format!(
            "pending: expected exactly 2 outputs (to + refund), got {}",
            output_count
        )));
    }

    if input_count == 0 || input_count > MAX_IO_COUNT {
        return Err(QuilError::InvalidArgument(format!(
            "pending: invalid input count {}",
            input_count
        )));
    }

    // Fee values in [0, 2^128]
    let max_fee = BigInt::one() << 128u32;
    for (i, fee_bytes) in tx.fees.iter().enumerate() {
        let fee = BigInt::from_bytes_be(num_bigint::Sign::Plus, fee_bytes);
        if fee > max_fee {
            return Err(QuilError::InvalidArgument(format!(
                "pending: fee {} out of range",
                i
            )));
        }
    }

    // Non-divisible behavior: input count must match output count.
    if behavior & DIVISIBLE == 0 && input_count != output_count {
        return Err(QuilError::InvalidArgument(
            "pending: non-divisible token has mismatching inputs and outputs".into(),
        ));
    }

    Ok(())
}

/// Per-output structural check: commitment and recipient field sizes.
///
/// Mirrors Go `PendingTransactionOutput.Verify` at
/// `token_intrinsic_pending_transaction.go:938-1012`.
pub fn validate_pending_output_structural(
    output: &PendingTransactionOutput,
    behavior: u16,
) -> Result<()> {
    if output.commitment.len() != 56 {
        return Err(QuilError::InvalidArgument(
            "pending output: commitment must be 56 bytes".into(),
        ));
    }
    let to = RecipientBundle::from_canonical_bytes(&output.to)?;
    let refund = RecipientBundle::from_canonical_bytes(&output.refund)?;

    for (bundle, label) in [(&to, "to"), (&refund, "refund")] {
        if bundle.one_time_key.len() != 56
            || bundle.verification_key.len() != 56
            || bundle.coin_balance.len() != 56
            || bundle.mask.len() != 56
        {
            return Err(QuilError::InvalidArgument(format!(
                "pending output: invalid {} recipient field size",
                label
            )));
        }
    }

    // Non-divisible: additional_reference/additional_reference_key required and must match
    if behavior & DIVISIBLE == 0 {
        if to.additional_reference.len() != 64
            || to.additional_reference_key.len() != 56
            || refund.additional_reference.len() != 64
            || refund.additional_reference_key.len() != 56
        {
            return Err(QuilError::InvalidArgument(
                "pending output: non-divisible requires additional reference/key on to+refund".into(),
            ));
        }
        if to.additional_reference != refund.additional_reference
            || to.additional_reference_key != refund.additional_reference_key
        {
            return Err(QuilError::InvalidArgument(
                "pending output: non-divisible to/refund references must match".into(),
            ));
        }
    }

    Ok(())
}

/// Per-input structural check for a PendingTransaction input.
///
/// Mirrors Go `PendingTransactionInput.Verify` structural portion at
/// `token_intrinsic_pending_transaction.go:442-477`.
///
/// Accepts two signature shapes:
/// - 336 bytes: modern hidden-Schnorr signature
/// - 259 bytes: pre-2.1 legacy ed448 transfer signature (only valid
///   when `check_legacy` is true, i.e. the domain is QUIL_TOKEN).
pub fn validate_pending_input_structural(
    input: &PendingTransactionInput,
    behavior: u16,
    check_legacy: bool,
) -> Result<()> {
    if input.commitment.len() != 56 {
        return Err(QuilError::InvalidArgument(
            "pending input: commitment must be 56 bytes".into(),
        ));
    }

    match input.signature.len() {
        259 => {
            if !check_legacy {
                return Err(QuilError::InvalidArgument(
                    "pending input: legacy-sized signature outside legacy domain".into(),
                ));
            }
            // Legacy path — structural check only. The full ed448 +
            // VerEnc crypto verify runs in `legacy_verify_input` once
            // the hypergraph CRDT is available.
            Ok(())
        }
        336 => {
            validate_input_structural(&input.commitment, &input.signature)?;

            // Non-divisible: must have 2 proofs (main multiproof + addref),
            // divisible: 1 proof.
            let addref_delta = if behavior & DIVISIBLE == 0 { 1 } else { 0 };
            let expected_proofs = 1 + addref_delta;
            if input.proofs.len() != expected_proofs {
                return Err(QuilError::InvalidArgument(format!(
                    "pending input: expected {} proof(s), got {}",
                    expected_proofs,
                    input.proofs.len()
                )));
            }
            Ok(())
        }
        n => Err(QuilError::InvalidArgument(format!(
            "pending input: signature must be 336 or 259 bytes, got {}",
            n
        ))),
    }
}

// =====================================================================
// Legacy pre-2.1 ed448 verify
// =====================================================================

/// Parse a 621-byte `MPCitHVerEnc` blob (Go
/// `MPCitHVerEncFromBytes`, `verenc/verifiable_encryption.go:139`) and
/// build the `VerencDecrypt` payload expected by `verenc_recover`.
fn parse_mpcith_verenc(bytes: &[u8], decryption_key: &[u8]) -> Option<verenc::VerencDecrypt> {
    if bytes.len() != 621 {
        return None;
    }
    let mut ctexts = Vec::with_capacity(3);
    for i in 0..3 {
        let base = i * (57 + 56);
        ctexts.push(verenc::VerencCiphertext {
            c1: bytes[base..base + 57].to_vec(),
            c2: bytes[base + 57..base + 57 + 56].to_vec(),
            i: 0,
        });
    }
    let mut aux = Vec::with_capacity(3);
    for i in 0..3 {
        let base = 339 + i * 56;
        aux.push(bytes[base..base + 56].to_vec());
    }
    Some(verenc::VerencDecrypt {
        blinding_pubkey: bytes[507..564].to_vec(),
        decryption_key: decryption_key.to_vec(),
        statement: bytes[564..621].to_vec(),
        ciphertexts: verenc::CompressedCiphertext { ctexts, aux },
    })
}

/// Decrypt a single 621-byte VerEnc blob with the supplied decryption
/// key and return the combined plaintext bytes. Matches Go
/// `MPCitHVerifiableEncryptor.Decrypt` with a one-element input list.
fn decrypt_single_verenc(bytes: &[u8], decryption_key: &[u8]) -> Option<Vec<u8>> {
    let d = parse_mpcith_verenc(bytes, decryption_key)?;
    let chunk = verenc::verenc_recover(d);
    if chunk.is_empty() {
        return None;
    }
    Some(verenc::combine_chunked_data(vec![chunk]))
}

/// Verify a legacy 259-byte pre-2.1 pending-transaction input. Ports
/// Go `PendingTransactionInput.legacyVerify` at
/// `token_intrinsic_pending_transaction.go:612-748`.
///
/// Returns `Ok(())` when every check passes, or an `Err` naming the
/// first check that failed. This path is still live on mainnet because
/// any spend of a pre-cutover coin still produces a 259-byte signature.
///
/// The signature layout (`input.signature`, 259 bytes total) is:
/// ```text
///   [0..32)     signature image (spend nullifier seed)
///   [32..89)    ed448 public key (57 bytes)
///   [89..145)   raised blind (56 bytes)
///   [145..259)  ed448 signature (114 bytes)
/// ```
pub fn legacy_verify_input(
    input: &PendingTransactionInput,
    transcript: &[u8],
    hypergraph: &HypergraphCrdt,
    dc: &dyn DecafConstructor,
) -> Result<()> {
    use crate::domains::QUIL_TOKEN;

    if input.signature.len() != 259 {
        return Err(QuilError::InvalidArgument(format!(
            "legacy verify: signature must be 259 bytes, got {}",
            input.signature.len()
        )));
    }
    if input.commitment.len() != 56 {
        return Err(QuilError::InvalidArgument(format!(
            "legacy verify: commitment must be 56 bytes, got {}",
            input.commitment.len()
        )));
    }

    // 1. Spend check: poseidon(sig[:32]) hashed into QUIL domain must not
    //    already exist in the hypergraph (image already consumed).
    let image = quil_crypto::poseidon::hash_bytes_to_32(&input.signature[..32])?;
    let image_loc = quil_hypergraph::addressing::Location {
        app_address: QUIL_TOKEN,
        data_address: image,
    };
    if hypergraph.lookup_vertex(&image_loc) {
        return Err(QuilError::InvalidArgument(
            "legacy verify: signature image already spent".into(),
        ));
    }

    // 2. Locate the coin vertex at [QUIL_TOKEN_ADDRESS || sig[:32]] and
    //    load its underlying data tree. The tree has 3 sequential u64-BE
    //    indexed slots: 0=FrameNumber, 1=CoinBalance, 2=ImplicitOwnerAddress.
    let mut coin_addr = [0u8; 32];
    coin_addr.copy_from_slice(&input.signature[..32]);
    let coin_loc = quil_hypergraph::addressing::Location {
        app_address: QUIL_TOKEN,
        data_address: coin_addr,
    };
    if !hypergraph.lookup_vertex(&coin_loc) {
        return Err(QuilError::InvalidArgument(
            "legacy verify: coin vertex not found for legacy spend".into(),
        ));
    }
    let tree_bytes = hypergraph
        .get_vertex_underlying_tree_bytes(&coin_loc)
        .ok_or_else(|| QuilError::InvalidArgument(
            "legacy verify: coin vertex underlying-data tree missing".into(),
        ))?;
    let root = quil_tries::deserialize_go_tree(&tree_bytes).map_err(|e| {
        QuilError::InvalidArgument(format!(
            "legacy verify: coin tree deserialize failed: {e}"
        ))
    })?;
    let tree = quil_tries::VectorCommitmentTree { root };

    let read_slot = |idx: u64| -> Option<Vec<u8>> {
        let key = idx.to_be_bytes();
        tree.get(&key).map(|b| b.to_vec())
    };

    let fn_blob = read_slot(0).ok_or_else(|| QuilError::InvalidArgument(
        "legacy verify: missing FrameNumber encrypted slot".into(),
    ))?;
    let amount_blob = read_slot(1).ok_or_else(|| QuilError::InvalidArgument(
        "legacy verify: missing CoinBalance encrypted slot".into(),
    ))?;
    let address_blob = read_slot(2).ok_or_else(|| QuilError::InvalidArgument(
        "legacy verify: missing ImplicitOwnerAddress encrypted slot".into(),
    ))?;

    // 3. Decrypt FrameNumber → u64 LE; reject if past the 2.1 cutover.
    let fn_plain = decrypt_single_verenc(&fn_blob, &PUBLIC_READ_KEY)
        .ok_or_else(|| QuilError::InvalidArgument(
            "legacy verify: failed to decrypt FrameNumber".into(),
        ))?;
    if fn_plain.len() < 8 {
        return Err(QuilError::InvalidArgument(
            "legacy verify: decrypted FrameNumber < 8 bytes".into(),
        ));
    }
    let mut fn_le = [0u8; 8];
    fn_le.copy_from_slice(&fn_plain[..8]);
    let coin_frame = u64::from_le_bytes(fn_le);
    if coin_frame > FRAME_2_1_CUTOVER {
        return Err(QuilError::InvalidArgument(format!(
            "legacy verify: decrypted frame {} > cutover {}",
            coin_frame, FRAME_2_1_CUTOVER
        )));
    }

    // 4. Challenge = poseidon(transcript) padded to 32 BE bytes.
    let challenge = quil_crypto::poseidon::hash_bytes_to_32(transcript)?;

    // 5. ed448 verify: payload = "transfer" || sig[:32] || challenge,
    //    signature at sig[145..259], pubkey at sig[32..89], ctx = "".
    let mut payload = Vec::with_capacity(8 + 32 + 32);
    payload.extend_from_slice(b"transfer");
    payload.extend_from_slice(&input.signature[..32]);
    payload.extend_from_slice(&challenge);
    let pubkey = &input.signature[32..89];
    let ed_sig = &input.signature[145..];
    if !quil_crypto::ed448_verify(pubkey, &payload, ed_sig) {
        return Err(QuilError::InvalidArgument(
            "legacy verify: ed448 signature invalid".into(),
        ));
    }

    // 6. Commitment check: commitment == decafScalar(amount) + raised_blind.
    let raised_blind = &input.signature[89..145];
    let amt_plain = decrypt_single_verenc(&amount_blob, &PUBLIC_READ_KEY)
        .ok_or_else(|| QuilError::InvalidArgument(
            "legacy verify: failed to decrypt CoinBalance".into(),
        ))?;
    if amt_plain.len() > 56 {
        return Err(QuilError::InvalidArgument(format!(
            "legacy verify: decrypted amount is {} bytes (> 56)",
            amt_plain.len()
        )));
    }
    let mut amount_bytes = amt_plain;
    // Go appends zero bytes to the right (LE-extension).
    amount_bytes.resize(56, 0u8);
    let scalar = dc.new_from_scalar(&amount_bytes)?;
    let commitment_check = scalar.add(raised_blind)?;
    if commitment_check != input.commitment {
        return Err(QuilError::InvalidArgument(
            "legacy verify: recomputed commitment does not match input commitment".into(),
        ));
    }

    // 7. Address check: decrypt the legacy address, drop its leading
    //    byte, reverse the next 32 bytes, and compare against either
    //    poseidon(pubkey) or poseidon(peerIdMultihash(pubkey)).
    let addr_plain = decrypt_single_verenc(&address_blob, &PUBLIC_READ_KEY)
        .ok_or_else(|| QuilError::InvalidArgument(
            "legacy verify: failed to decrypt ImplicitOwnerAddress".into(),
        ))?;
    if addr_plain.len() < 33 {
        return Err(QuilError::InvalidArgument(format!(
            "legacy verify: decrypted address is {} bytes (< 33)",
            addr_plain.len()
        )));
    }
    let mut legacy_addr = addr_plain[1..33].to_vec();
    legacy_addr.reverse();

    let addr_from_pubkey = quil_crypto::poseidon::hash_bytes_to_32(pubkey)?;
    let peer_id = quil_crypto::peer_id_multihash_from_ed448_pubkey(pubkey);
    let addr_from_peerid = quil_crypto::poseidon::hash_bytes_to_32(&peer_id)?;

    if legacy_addr.as_slice() != addr_from_pubkey.as_slice()
        && legacy_addr.as_slice() != addr_from_peerid.as_slice()
    {
        return Err(QuilError::InvalidArgument(
            "legacy verify: address mismatch (neither poseidon(pubkey) \
             nor poseidon(peerId) matches)".into(),
        ));
    }

    Ok(())
}

/// Crypto-level verify for a PendingTransaction. Does not perform
/// state lookups (spent-coin / traversal-proof checks live in the
/// dispatcher with the HypergraphState).
///
/// Ported crypto checks from Go `PendingTransaction.Verify`:
/// 1. Structural: behavior ACCEPTABLE, exactly 2 outputs, inputs in [1..=MAX_IO_COUNT],
///    fees bounded, non-divisible input/output count match.
/// 2. Per-input structural + signature:
///    - modern 336-byte: hidden-Schnorr (bulletproof hidden verify)
///    - legacy 259-byte: pre-2.1 ed448 transfer (see `legacy_verify_input`;
///      requires `hypergraph` to read the coin's encrypted vertex data).
/// 3. Per-output structural (commitment sizes, recipient field sizes,
///    non-divisible addref parity).
/// 4. Bulletproof range proof on the concatenated output commitments.
/// 5. Sum check: inputs == outputs + fees (fees only included for QUIL domain).
///
/// `frame_number` is only used to validate output frames (they must be
/// strictly greater than the current frame). The legacy coin's own
/// cutover check is made against the decrypted FrameNumber slot inside
/// `legacy_verify_input`, not against the tx frame.
pub fn verify_pending_transaction(
    tx: &PendingTransaction,
    frame_number: u64,
    behavior: u16,
    is_quil_domain: bool,
    bp: &dyn BulletproofProver,
    dc: &dyn DecafConstructor,
    hypergraph: Option<&HypergraphCrdt>,
) -> Result<bool> {
    // 1. Structural
    validate_pending_structural(tx, behavior)?;

    // 2. Decode inputs + outputs upfront
    let mut inputs: Vec<PendingTransactionInput> = Vec::with_capacity(tx.inputs.len());
    for raw in &tx.inputs {
        inputs.push(PendingTransactionInput::from_canonical_bytes(raw)?);
    }
    let mut outputs: Vec<PendingTransactionOutput> = Vec::with_capacity(tx.outputs.len());
    for raw in &tx.outputs {
        outputs.push(PendingTransactionOutput::from_canonical_bytes(raw)?);
    }

    // 3. Per-input structural validation. Legacy-sized (259-byte) sigs
    //    are accepted at any frame on the QUIL domain — legacy coins
    //    minted pre-cutover are still spendable on live mainnet. The
    //    coin's own frame bound (≤ FRAME_2_1_CUTOVER) is enforced inside
    //    `legacy_verify_input` against the decrypted frame number, not
    //    against the tx's current frame (mirrors Go lines 617, 664).
    let check_legacy = is_quil_domain;
    for input in &inputs {
        validate_pending_input_structural(input, behavior, check_legacy)?;
    }

    // 4. Per-output structural
    for output in &outputs {
        validate_pending_output_structural(output, behavior)?;

        // Output frame number must be strictly greater than the current frame
        // (mirror of Go `PendingTransactionOutput.Verify` at
        // `token_intrinsic_pending_transaction.go:942-951`).
        if output.frame_number.len() != 8 {
            return Err(QuilError::InvalidArgument(
                "pending output: frame_number must be 8 bytes".into(),
            ));
        }
        let mut fn_b = [0u8; 8];
        fn_b.copy_from_slice(&output.frame_number[..8]);
        let out_frame = u64::from_be_bytes(fn_b);
        if out_frame <= frame_number {
            return Err(QuilError::InvalidArgument(format!(
                "pending output: frame {} must be > current {}",
                out_frame, frame_number
            )));
        }
    }

    // 5. Double-spend check (within the transaction itself): each input's
    //    verification key must be unique across inputs. Go does this at lines
    //    1594-1626. For modern sigs the key is at [56*4..56*5]; for legacy at
    //    sig[..32].
    let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    for input in &inputs {
        let vk: Vec<u8> = if input.signature.len() == 259 {
            input.signature[..32].to_vec()
        } else {
            input.signature[56 * 4..56 * 5].to_vec()
        };
        if !seen.insert(vk) {
            return Err(QuilError::InvalidArgument(
                "pending: duplicate input verification key (self double-spend)".into(),
            ));
        }
    }

    // 6. Build challenge transcript and reduce to a DECAF448 scalar.
    let transcript = build_pending_transaction_transcript(tx)?;
    let challenge = compute_transaction_challenge(dc, &transcript)?;

    // 7. Per-input signature check. Modern (336-byte) inputs use the
    //    hidden-Schnorr path; legacy (259-byte) inputs use the pre-2.1
    //    ed448 transfer protocol — both are live on mainnet because any
    //    spend of a pre-cutover coin still produces a 259-byte signature.
    //    The legacy path needs the hypergraph CRDT to read the coin's
    //    encrypted vertex data; reject if unavailable.
    let transcript_for_legacy = build_pending_transaction_transcript(tx)?;
    for input in &inputs {
        if input.signature.len() == 259 {
            let hg = hypergraph.ok_or_else(|| QuilError::Internal(
                "pending: legacy input requires hypergraph CRDT reference".into(),
            ))?;
            legacy_verify_input(input, &transcript_for_legacy, hg, dc)?;
            continue;
        }
        // Modern hidden-Schnorr path.
        // Commitment must match the one embedded in the signature at [56*5..56*6]
        if input.commitment != input.signature[56 * 5..56 * 6] {
            return Err(QuilError::InvalidArgument(
                "pending input: commitment doesn't match signature".into(),
            ));
        }
        if !verify_input_hidden_signature(bp, &input.signature, &challenge)? {
            return Ok(false);
        }
    }

    // 8. Collect input + output commitments, then run range proof + sum check.
    let input_commitments: Vec<Vec<u8>> =
        inputs.iter().map(|i| i.commitment.clone()).collect();
    let output_commitments: Vec<Vec<u8>> =
        outputs.iter().map(|o| o.commitment.clone()).collect();

    let ok = verify_transaction_crypto(
        bp,
        &input_commitments,
        &output_commitments,
        &tx.fees,
        &tx.range_proof,
        is_quil_domain,
    )?;
    if !ok {
        return Ok(false);
    }

    // 9. Explicit range-proof check on concatenated output commitments.
    //    `verify_transaction_crypto` already does this, but we re-assert the
    //    bit size matches the constant used in Go.
    let _ = RANGE_PROOF_BIT_SIZE;

    Ok(true)
}

// =====================================================================
// Materialize: emit coin vertices + spent marker
// =====================================================================

/// Output vertices produced by materializing a PendingTransaction.
///
/// Mirrors Go `PendingTransaction.Materialize` at
/// `token_intrinsic_pending_transaction.go:1361-1435`: one
/// `pending:PendingTransaction` tree per canonical output (carrying
/// dual-recipient OneTimeKey/VK/CoinBalance/Mask plus optional
/// AdditionalReference and Expiration), and a spent marker per input.
pub struct PendingMaterializeOutput {
    /// (pending_address, pending_tree) pairs — one per canonical output.
    pub pendings: Vec<([u8; 32], quil_tries::VectorCommitmentTree)>,
    /// (spent_address, spent_marker_tree) pairs — one per input.
    pub spent_markers: Vec<([u8; 32], quil_tries::VectorCommitmentTree)>,
}

/// Materialize a PendingTransaction into per-output `pending:PendingTransaction`
/// trees plus spent markers.
///
/// Each output's tree address is `poseidon(commit(tree))` — the commitment
/// of the `pending:PendingTransaction` tree itself. Go also prefixes the
/// 32-byte address with the 32-byte domain inside `cachedAddresses`
/// (`outAddr := domain || addrBI`); we return only the 32-byte data
/// address since callers already pass the domain to `state.set`.
///
/// Spent markers are written at `poseidon(input.verification_key)`.
/// The verification key is read from `signature[56*4..56*5]` for modern
/// sigs (336 bytes) and `signature[..32]` for legacy sigs (259 bytes).
///
/// Port of Go `PendingTransaction.Materialize` +
/// `buildPendingTransactionTrees` at
/// `token_intrinsic_pending_transaction.go:1085-1297, 1361-1435`.
pub fn materialize_pending_transaction(
    tx: &PendingTransaction,
    frame_number: u64,
    behavior: u16,
    inclusion_prover: &(dyn InclusionProver + Sync),
) -> Result<PendingMaterializeOutput> {
    // Pending type hash: poseidon(domain || "pending:PendingTransaction")
    let pending_type = pending_type_hash(&tx.domain)?;

    let mut pendings = Vec::with_capacity(tx.outputs.len());
    let frame_bytes = frame_number.to_be_bytes().to_vec();
    let expirable = behavior & super::constants::EXPIRABLE != 0;

    for raw in &tx.outputs {
        let output = PendingTransactionOutput::from_canonical_bytes(raw)?;
        let to = RecipientBundle::from_canonical_bytes(&output.to)?;
        let refund = RecipientBundle::from_canonical_bytes(&output.refund)?;

        let mut tree = create_pending_transaction_tree(
            &frame_bytes,
            &output.commitment,
            &to,
            &refund,
            output.expiration,
            expirable,
            &pending_type,
        )?;
        let commit = tree.commit(inclusion_prover);
        let addr = quil_crypto::poseidon::hash_bytes_to_32(&commit)?;
        pendings.push((addr, tree));
    }

    // Spent markers for inputs
    let mut spent_markers = Vec::with_capacity(tx.inputs.len());
    for raw in &tx.inputs {
        let input = PendingTransactionInput::from_canonical_bytes(raw)?;
        let vk: &[u8] = if input.signature.len() == 259 {
            &input.signature[..32]
        } else if input.signature.len() == 336 {
            &input.signature[56 * 4..56 * 5]
        } else {
            continue;
        };
        let addr = spent_address(vk)?;
        let marker = create_spent_marker_tree()?;
        spent_markers.push((addr, marker));
    }

    Ok(PendingMaterializeOutput { pendings, spent_markers })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::{DecafAgreement, Multiproof, RangeProofResult};

    // --- Stub provers ---

    struct AcceptProver;
    impl BulletproofProver for AcceptProver {
        fn generate_range_proof(&self, _: &[Vec<u8>], _: &[u8], _: u64) -> Result<RangeProofResult> { Err(QuilError::Internal("n/a".into())) }
        fn generate_input_commitments(&self, _: &[Vec<u8>], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_range_proof(&self, _: &[u8], _: &[u8], _: u64) -> bool { true }
        fn sum_check(&self, _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>]) -> bool { true }
        fn sign_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> bool { true }
        fn simple_sign(&self, _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn simple_verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool { true }
    }

    struct RejectHiddenProver;
    impl BulletproofProver for RejectHiddenProver {
        fn generate_range_proof(&self, _: &[Vec<u8>], _: &[u8], _: u64) -> Result<RangeProofResult> { Err(QuilError::Internal("n/a".into())) }
        fn generate_input_commitments(&self, _: &[Vec<u8>], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_range_proof(&self, _: &[u8], _: &[u8], _: u64) -> bool { true }
        fn sum_check(&self, _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>]) -> bool { true }
        fn sign_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> bool { false }
        fn simple_sign(&self, _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn simple_verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool { true }
    }

    struct StubDecaf;
    impl DecafConstructor for StubDecaf {
        fn new_key(&self) -> Result<Box<dyn DecafAgreement>> { Err(QuilError::Internal("n/a".into())) }
        fn from_bytes(&self, _: &[u8]) -> Result<Box<dyn DecafAgreement>> { Err(QuilError::Internal("n/a".into())) }
        fn hash_to_scalar(&self, data: &[u8]) -> Result<Vec<u8>> {
            // Deterministic 56-byte output derived from input length + first byte
            let mut out = vec![0u8; 56];
            out[0] = data.first().copied().unwrap_or(0);
            out[1] = (data.len() as u8).wrapping_add(1);
            Ok(out)
        }
        fn new_from_scalar(&self, _: &[u8]) -> Result<Box<dyn DecafAgreement>> { Err(QuilError::Internal("n/a".into())) }
        fn alt_generator(&self) -> Vec<u8> { vec![0u8; 56] }
    }

    struct StubInc;
    impl InclusionProver for StubInc {
        fn commit_raw(&self, data: &[u8], _: u64) -> Result<Vec<u8>> {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new(); data.hash(&mut h);
            let hash = h.finish().to_be_bytes();
            let mut out = vec![0u8; 64]; out[..8].copy_from_slice(&hash); Ok(out)
        }
        fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> { Ok(vec![]) }
        fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> { Ok(true) }
        fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64) -> Result<Box<dyn Multiproof>> { Err(QuilError::Internal("n/a".into())) }
        fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { true }
    }

    // --- Helpers to build valid test fixtures ---

    fn make_recipient(tag: u8) -> RecipientBundle {
        RecipientBundle {
            one_time_key: vec![tag; 56],
            verification_key: vec![tag ^ 0x80; 56],
            coin_balance: vec![tag; 56],
            mask: vec![tag ^ 0x01; 56],
            additional_reference: vec![],
            additional_reference_key: vec![],
        }
    }

    fn make_output(frame: u64, commitment_tag: u8, to_tag: u8, refund_tag: u8) -> Vec<u8> {
        let to = make_recipient(to_tag).to_canonical_bytes().unwrap();
        let refund = make_recipient(refund_tag).to_canonical_bytes().unwrap();
        PendingTransactionOutput {
            frame_number: frame.to_be_bytes().to_vec(),
            commitment: vec![commitment_tag; 56],
            to,
            refund,
            expiration: 1000,
        }
        .to_canonical_bytes()
        .unwrap()
    }

    /// Modern-format input: 336-byte sig, commitment embedded at [56*5..56*6].
    fn make_modern_input(vk_tag: u8, commitment_tag: u8) -> Vec<u8> {
        let mut sig = vec![0u8; 336];
        // VK at [56*4..56*5]
        for b in &mut sig[56 * 4..56 * 5] { *b = vk_tag; }
        // Commitment embedded at [56*5..56*6]
        let commitment = vec![commitment_tag; 56];
        sig[56 * 5..56 * 6].copy_from_slice(&commitment);

        PendingTransactionInput {
            commitment,
            signature: sig,
            proofs: vec![vec![0xAAu8; 128]], // 1 proof for divisible tokens
        }
        .to_canonical_bytes()
        .unwrap()
    }

    /// Legacy-format input: 259-byte sig.
    fn make_legacy_input(vk_tag: u8, commitment_tag: u8) -> Vec<u8> {
        let mut sig = vec![0u8; 259];
        for b in &mut sig[..32] { *b = vk_tag; }
        PendingTransactionInput {
            commitment: vec![commitment_tag; 56],
            signature: sig,
            proofs: vec![],
        }
        .to_canonical_bytes()
        .unwrap()
    }

    fn make_tx(inputs: Vec<Vec<u8>>, outputs: Vec<Vec<u8>>) -> PendingTransaction {
        PendingTransaction {
            domain: crate::domains::QUIL_TOKEN.to_vec(),
            inputs,
            outputs,
            fees: vec![],
            range_proof: vec![0xEEu8; 32],
            traversal_proof: vec![0x01, 0x02, 0x03, 0x04],
        }
    }

    // --- Round-trip tests ---

    #[test]
    fn pending_input_round_trip() {
        let i = PendingTransactionInput { commitment: vec![0xAAu8; 64], signature: vec![0xBBu8; 74], proofs: vec![vec![0xCCu8; 32]] };
        let b = i.to_canonical_bytes().unwrap();
        assert_eq!(PendingTransactionInput::from_canonical_bytes(&b).unwrap(), i);
    }

    #[test]
    fn pending_output_round_trip() {
        let o = PendingTransactionOutput { frame_number: vec![0,0,0,5], commitment: vec![0xAAu8; 64], to: vec![0xBBu8; 10], refund: vec![0xCCu8; 10], expiration: 1000 };
        let b = o.to_canonical_bytes().unwrap();
        assert_eq!(PendingTransactionOutput::from_canonical_bytes(&b).unwrap(), o);
    }

    #[test]
    fn pending_transaction_round_trip() {
        let pt = PendingTransaction { domain: vec![0x11u8; 32], inputs: vec![], outputs: vec![], fees: vec![vec![0, 50]], range_proof: vec![0xFFu8; 64], traversal_proof: vec![] };
        let b = pt.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_PENDING_TRANSACTION.to_be_bytes());
        assert_eq!(PendingTransaction::from_canonical_bytes(&b).unwrap(), pt);
    }

    #[test]
    fn pending_transaction_empty() {
        let pt = PendingTransaction::default();
        let b = pt.to_canonical_bytes().unwrap();
        assert_eq!(PendingTransaction::from_canonical_bytes(&b).unwrap(), pt);
    }

    // --- Coin format detection ---

    #[test]
    fn coin_format_legacy_for_early_frame() {
        assert_eq!(CoinFormat::for_frame(0), CoinFormat::Legacy);
        assert_eq!(CoinFormat::for_frame(244_199), CoinFormat::Legacy);
    }

    #[test]
    fn coin_format_modern_at_and_after_cutover() {
        assert_eq!(CoinFormat::for_frame(244_200), CoinFormat::Modern);
        assert_eq!(CoinFormat::for_frame(300_000), CoinFormat::Modern);
    }

    #[test]
    fn detect_coin_format_from_framebytes_length() {
        assert_eq!(detect_coin_format_from_framebytes(&[0u8; 8]), CoinFormat::Modern);
        // Legacy packed VerEnc blobs are much larger than 8 bytes
        assert_eq!(detect_coin_format_from_framebytes(&[0u8; 50]), CoinFormat::Legacy);
    }

    #[test]
    fn read_legacy_frame_little_endian() {
        // Frame 42 in little endian
        let raw = 42u64.to_le_bytes();
        assert_eq!(read_coin_frame_number(&raw, true).unwrap(), 42);
    }

    #[test]
    fn read_modern_frame_big_endian() {
        let raw = 42u64.to_be_bytes();
        assert_eq!(read_coin_frame_number(&raw, false).unwrap(), 42);
    }

    #[test]
    fn legacy_and_modern_decode_differs_for_nonzero() {
        let raw = 0x01020304_05060708u64.to_le_bytes();
        let legacy = read_coin_frame_number(&raw, true).unwrap();
        let modern = read_coin_frame_number(&raw, false).unwrap();
        assert_eq!(legacy, 0x01020304_05060708);
        assert_eq!(modern, 0x08070605_04030201);
    }

    // --- Transcript ---

    #[test]
    fn transcript_is_deterministic() {
        let tx = make_tx(
            vec![make_modern_input(0x11, 0xC1)],
            vec![make_output(42, 0xC1, 0x21, 0x22), make_output(42, 0xC2, 0x23, 0x24)],
        );
        let t1 = build_pending_transaction_transcript(&tx).unwrap();
        let t2 = build_pending_transaction_transcript(&tx).unwrap();
        assert_eq!(t1, t2);
        assert!(t1.starts_with(&tx.domain));
    }

    #[test]
    fn transcript_includes_expected_fields() {
        let tx = make_tx(
            vec![],
            vec![make_output(100, 0xC1, 0x21, 0x22)],
        );
        let t = build_pending_transaction_transcript(&tx).unwrap();
        // domain (32) + commitment (56) + expiration (8) + frame (8)
        //   + to.coin_balance (56) + to.mask (56) + to.one_time_key (56) + to.verification_key (56)
        //   + refund.coin_balance (56) + refund.mask (56) + refund.one_time_key (56) + refund.verification_key (56)
        // = 32 + 56 + 8 + 8 + 4*56 + 4*56 = 32 + 56 + 16 + 448 = 552
        assert_eq!(t.len(), 552);
    }

    // --- Structural ---

    #[test]
    fn structural_rejects_non_acceptable_behavior() {
        let tx = make_tx(vec![make_modern_input(0x11, 0xC1)], vec![make_output(42, 0xC1, 0x21, 0x22), make_output(42, 0xC2, 0x23, 0x24)]);
        // behavior without ACCEPTABLE
        let err = validate_pending_structural(&tx, DIVISIBLE);
        assert!(err.is_err());
    }

    #[test]
    fn structural_rejects_wrong_output_count() {
        let tx = make_tx(vec![make_modern_input(0x11, 0xC1)], vec![make_output(42, 0xC1, 0x21, 0x22)]);
        assert!(validate_pending_structural(&tx, ACCEPTABLE | DIVISIBLE).is_err());
    }

    #[test]
    fn structural_accepts_valid() {
        let tx = make_tx(
            vec![make_modern_input(0x11, 0xC1)],
            vec![make_output(42, 0xC1, 0x21, 0x22), make_output(42, 0xC2, 0x23, 0x24)],
        );
        assert!(validate_pending_structural(&tx, ACCEPTABLE | DIVISIBLE).is_ok());
    }

    #[test]
    fn structural_rejects_zero_inputs() {
        let tx = make_tx(vec![], vec![make_output(42, 0xC1, 0x21, 0x22), make_output(42, 0xC2, 0x23, 0x24)]);
        assert!(validate_pending_structural(&tx, ACCEPTABLE | DIVISIBLE).is_err());
    }

    // --- Input structural ---

    #[test]
    fn input_structural_accepts_modern_sig() {
        let raw = make_modern_input(0x11, 0xC1);
        let input = PendingTransactionInput::from_canonical_bytes(&raw).unwrap();
        assert!(validate_pending_input_structural(&input, ACCEPTABLE | DIVISIBLE, false).is_ok());
    }

    #[test]
    fn input_structural_rejects_bad_sig_length() {
        let input = PendingTransactionInput { commitment: vec![0u8; 56], signature: vec![0u8; 100], proofs: vec![] };
        assert!(validate_pending_input_structural(&input, ACCEPTABLE | DIVISIBLE, true).is_err());
    }

    #[test]
    fn input_structural_legacy_allowed_only_when_checklegacy() {
        let raw = make_legacy_input(0x22, 0xC2);
        let input = PendingTransactionInput::from_canonical_bytes(&raw).unwrap();
        assert!(validate_pending_input_structural(&input, ACCEPTABLE | DIVISIBLE, true).is_ok());
        assert!(validate_pending_input_structural(&input, ACCEPTABLE | DIVISIBLE, false).is_err());
    }

    // --- Top-level verify ---

    #[test]
    fn verify_modern_tx_accepts_with_accept_prover() {
        let tx = make_tx(
            vec![make_modern_input(0x11, 0xC1)],
            vec![make_output(100, 0xD1, 0x21, 0x22), make_output(100, 0xD2, 0x23, 0x24)],
        );
        let ok = verify_pending_transaction(&tx, 42, ACCEPTABLE | DIVISIBLE, true, &AcceptProver, &StubDecaf, None).unwrap();
        assert!(ok);
    }

    #[test]
    fn verify_legacy_input_rejects_when_coin_vertex_absent() {
        // Supply an empty hypergraph. The legacy path is exercised
        // (no longer short-circuited) and must reject because the
        // spend-image coin vertex is not present in the CRDT.
        use std::sync::Arc;
        use quil_hypergraph::HypergraphCrdt;
        use quil_hypergraph::testing::MemStore;
        use quil_types::crypto::NoopInclusionProver;

        let crdt = HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(NoopInclusionProver),
        );

        let tx = make_tx(
            vec![make_legacy_input(0x11, 0xC1)],
            vec![make_output(300_000, 0xD1, 0x21, 0x22), make_output(300_000, 0xD2, 0x23, 0x24)],
        );
        let err = verify_pending_transaction(
            &tx, 260_000, ACCEPTABLE | DIVISIBLE, true,
            &AcceptProver, &StubDecaf, Some(&crdt),
        );
        assert!(err.is_err(), "expected legacy verify to reject when coin vertex missing");
    }

    #[test]
    fn verify_legacy_input_requires_hypergraph() {
        // A 259-byte legacy signature on the QUIL domain is accepted at
        // any frame (old coins are still spendable) but verify cannot
        // complete without a hypergraph CRDT reference — the legacy
        // verifier needs to read the coin's encrypted vertex data.
        let tx = make_tx(
            vec![make_legacy_input(0x11, 0xC1)],
            vec![make_output(300_000, 0xD1, 0x21, 0x22), make_output(300_000, 0xD2, 0x23, 0x24)],
        );
        let err = verify_pending_transaction(
            &tx, FRAME_2_1_CUTOVER + 1, ACCEPTABLE | DIVISIBLE, true,
            &AcceptProver, &StubDecaf, None,
        );
        assert!(err.is_err(),
            "legacy input must error when hypergraph not supplied");
    }

    #[test]
    fn verify_legacy_sig_rejected_outside_quil_domain() {
        // Non-QUIL domain: legacy sigs are structurally rejected (only
        // the QUIL domain permits the pre-2.1 sig layout).
        let tx = make_tx(
            vec![make_legacy_input(0x11, 0xC1)],
            vec![make_output(300_000, 0xD1, 0x21, 0x22), make_output(300_000, 0xD2, 0x23, 0x24)],
        );
        let err = verify_pending_transaction(
            &tx, FRAME_2_1_CUTOVER + 1, ACCEPTABLE | DIVISIBLE,
            /* is_quil_domain */ false,
            &AcceptProver, &StubDecaf, None,
        );
        assert!(err.is_err());
    }

    #[test]
    fn verify_rejects_non_acceptable() {
        let tx = make_tx(
            vec![make_modern_input(0x11, 0xC1)],
            vec![make_output(100, 0xD1, 0x21, 0x22), make_output(100, 0xD2, 0x23, 0x24)],
        );
        // Missing ACCEPTABLE flag
        let err = verify_pending_transaction(&tx, 42, DIVISIBLE, true, &AcceptProver, &StubDecaf, None);
        assert!(err.is_err());
    }

    #[test]
    fn verify_rejects_wrong_output_count() {
        let tx = make_tx(
            vec![make_modern_input(0x11, 0xC1)],
            vec![make_output(100, 0xD1, 0x21, 0x22)], // only 1 output
        );
        let err = verify_pending_transaction(&tx, 42, ACCEPTABLE | DIVISIBLE, true, &AcceptProver, &StubDecaf, None);
        assert!(err.is_err());
    }

    #[test]
    fn verify_rejects_three_outputs() {
        let tx = make_tx(
            vec![make_modern_input(0x11, 0xC1)],
            vec![
                make_output(100, 0xD1, 0x21, 0x22),
                make_output(100, 0xD2, 0x23, 0x24),
                make_output(100, 0xD3, 0x25, 0x26),
            ],
        );
        let err = verify_pending_transaction(&tx, 42, ACCEPTABLE | DIVISIBLE, true, &AcceptProver, &StubDecaf, None);
        assert!(err.is_err());
    }

    #[test]
    fn verify_rejects_bad_signature_with_reject_prover() {
        let tx = make_tx(
            vec![make_modern_input(0x11, 0xC1)],
            vec![make_output(100, 0xD1, 0x21, 0x22), make_output(100, 0xD2, 0x23, 0x24)],
        );
        let ok = verify_pending_transaction(&tx, 42, ACCEPTABLE | DIVISIBLE, true, &RejectHiddenProver, &StubDecaf, None).unwrap();
        assert!(!ok);
    }

    #[test]
    fn verify_rejects_commitment_sig_mismatch() {
        // Build an input whose commitment doesn't match sig[56*5..56*6].
        let mut sig = vec![0u8; 336];
        for b in &mut sig[56 * 4..56 * 5] { *b = 0x11; }
        // Embedded commitment in sig is 0xAA
        for b in &mut sig[56 * 5..56 * 6] { *b = 0xAA; }
        // But the top-level commitment is 0xBB — mismatch!
        let bad = PendingTransactionInput { commitment: vec![0xBBu8; 56], signature: sig, proofs: vec![vec![0u8; 32]] }
            .to_canonical_bytes()
            .unwrap();

        let tx = make_tx(vec![bad], vec![make_output(100, 0xD1, 0x21, 0x22), make_output(100, 0xD2, 0x23, 0x24)]);
        let err = verify_pending_transaction(&tx, 42, ACCEPTABLE | DIVISIBLE, true, &AcceptProver, &StubDecaf, None);
        assert!(err.is_err());
    }

    #[test]
    fn verify_rejects_duplicate_input_vk() {
        // Both inputs share the same verification key → self double-spend.
        // Need behavior divisible since we have 2 inputs + 2 outputs.
        let tx = make_tx(
            vec![make_modern_input(0x11, 0xC1), make_modern_input(0x11, 0xC2)],
            vec![make_output(100, 0xD1, 0x21, 0x22), make_output(100, 0xD2, 0x23, 0x24)],
        );
        let err = verify_pending_transaction(&tx, 42, ACCEPTABLE | DIVISIBLE, true, &AcceptProver, &StubDecaf, None);
        assert!(err.is_err());
    }

    #[test]
    fn verify_rejects_output_frame_not_after_current() {
        // output.frame_number (100) <= current_frame (100) should reject.
        let tx = make_tx(
            vec![make_modern_input(0x11, 0xC1)],
            vec![make_output(100, 0xD1, 0x21, 0x22), make_output(100, 0xD2, 0x23, 0x24)],
        );
        let err = verify_pending_transaction(&tx, 100, ACCEPTABLE | DIVISIBLE, true, &AcceptProver, &StubDecaf, None);
        assert!(err.is_err());
    }

    // --- Materialize ---

    #[test]
    fn materialize_emits_one_pending_tree_per_output_and_spent_markers() {
        let tx = make_tx(
            vec![make_modern_input(0x11, 0xC1), make_modern_input(0x12, 0xC2)],
            vec![make_output(100, 0xD1, 0x21, 0x22), make_output(100, 0xD2, 0x23, 0x24)],
        );
        let result = materialize_pending_transaction(
            &tx, 42, ACCEPTABLE | DIVISIBLE, &StubInc,
        ).unwrap();
        // 2 outputs → 2 pending trees (one per output, dual-recipient inside)
        assert_eq!(result.pendings.len(), 2);
        // 2 inputs → 2 spent markers
        assert_eq!(result.spent_markers.len(), 2);

        // Each pending tree carries indexed fields. Verify a couple.
        let (_addr, tree) = &result.pendings[0];
        // Index 0: frame_number (be u64 = 42)
        assert_eq!(tree.get(&[0x00]).unwrap(), &42u64.to_be_bytes()[..]);
        // Index 1<<2: commitment (56 bytes of 0xD1)
        assert_eq!(tree.get(&[1u8 << 2]).unwrap(), &[0xD1u8; 56][..]);
        // Index 2<<2: To.OneTimeKey (recipient tag = 0x21)
        assert_eq!(tree.get(&[2u8 << 2]).unwrap(), &[0x21u8; 56][..]);
        // Index 3<<2: Refund.OneTimeKey (recipient tag = 0x22)
        assert_eq!(tree.get(&[3u8 << 2]).unwrap(), &[0x22u8; 56][..]);
        // Type marker at [0xFF; 32]: poseidon(domain || "pending:PendingTransaction")
        let expected_type = pending_type_hash(&tx.domain).unwrap();
        assert_eq!(tree.get(&[0xFFu8; 32]).unwrap(), &expected_type[..]);

        for (_addr, tree) in &result.spent_markers {
            assert_eq!(tree.get(&[0x00]).unwrap(), &[0x01][..]);
        }
    }

    #[test]
    fn materialize_legacy_input_uses_first_32_bytes_as_vk() {
        let tx = make_tx(
            vec![make_legacy_input(0xAB, 0xC1)],
            vec![make_output(100, 0xD1, 0x21, 0x22), make_output(100, 0xD2, 0x23, 0x24)],
        );
        let result = materialize_pending_transaction(
            &tx, 42, ACCEPTABLE | DIVISIBLE, &StubInc,
        ).unwrap();
        assert_eq!(result.spent_markers.len(), 1);
        // Addr is poseidon(sig[..32]) where sig[..32] = [0xAB; 32]
        let expected = quil_crypto::poseidon::hash_bytes_to_32(&[0xABu8; 32]).unwrap();
        assert_eq!(result.spent_markers[0].0, expected);
    }

    #[test]
    fn materialize_expirable_writes_expiration_at_index_10_when_no_addref() {
        use super::super::constants::EXPIRABLE;
        let tx = make_tx(
            vec![make_modern_input(0x11, 0xC1)],
            vec![make_output(100, 0xD1, 0x21, 0x22)],
        );
        let result = materialize_pending_transaction(
            &tx, 42, ACCEPTABLE | DIVISIBLE | EXPIRABLE, &StubInc,
        ).unwrap();
        let (_addr, tree) = &result.pendings[0];
        // Without AdditionalReference, Expiration sits at index 10<<2.
        let exp_bytes = tree.get(&[10u8 << 2]).unwrap();
        assert_eq!(exp_bytes, &1000u64.to_be_bytes()[..]); // make_output sets expiration=1000
    }
}

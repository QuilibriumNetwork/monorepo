//! Pending transaction types: PendingTransactionInput (0x050A),
//! PendingTransactionOutput (0x050B), PendingTransaction (0x050C).
//!
//! Also hosts the crypto-level `Verify` + `Materialize` helpers ported
//! from `node/execution/intrinsics/token/token_intrinsic_pending_transaction.go`.

use num_bigint::BigInt;
use quil_types::error::Result;

use super::cursor::*;
use super::transaction::RecipientBundle;

/// Public-read key for the pre-2.1 VerEnc coin fields. Matches Go
/// `token_intrinsic_transaction.go:33`:
/// `2cf07ca8d9ab1a4bb0902e25a9b90759dd54d881f54d52a76a17e79bf0361c325650f12746e4337ffb5940e7665ad7bf83f44af98d964bbe`.
pub(crate) const PUBLIC_READ_KEY: [u8; 56] = [
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
// Legacy verenc decryption (migration only — decodes pre-2.1 coins into
// transparent entries; NOT a spend path)
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
pub(crate) fn decrypt_single_verenc(bytes: &[u8], decryption_key: &[u8]) -> Option<Vec<u8>> {
    let d = parse_mpcith_verenc(bytes, decryption_key)?;
    let chunk = verenc::verenc_recover(d);
    if chunk.is_empty() {
        return None;
    }
    Some(verenc::combine_chunked_data(vec![chunk]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::{DecafAgreement, Multiproof, RangeProofResult};


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

    // --- Transcript ---

    // --- Structural ---

    // --- Input structural ---

    // --- Top-level verify ---

    // --- Materialize ---
}

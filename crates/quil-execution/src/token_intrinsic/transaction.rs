//! Transaction types: RecipientBundle (0x0506), TransactionInput (0x0507),
//! TransactionOutput (0x0508), Transaction (0x0509).

use quil_types::error::Result;
use super::cursor::*;

pub const TYPE_RECIPIENT_BUNDLE: u32 = 0x0506;
pub const TYPE_TRANSACTION_INPUT: u32 = 0x0507;
pub const TYPE_TRANSACTION_OUTPUT: u32 = 0x0508;
pub const TYPE_TRANSACTION: u32 = 0x0509;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecipientBundle {
    pub one_time_key: Vec<u8>,
    pub verification_key: Vec<u8>,
    pub coin_balance: Vec<u8>,
    pub mask: Vec<u8>,
    pub additional_reference: Vec<u8>,
    pub additional_reference_key: Vec<u8>,
}

impl RecipientBundle {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_RECIPIENT_BUNDLE);
        put_lp(&mut out, &self.one_time_key);
        put_lp(&mut out, &self.verification_key);
        put_lp(&mut out, &self.coin_balance);
        put_lp(&mut out, &self.mask);
        put_lp(&mut out, &self.additional_reference);
        put_lp(&mut out, &self.additional_reference_key);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_RECIPIENT_BUNDLE, "RecipientBundle")?;
        Ok(Self {
            one_time_key: read_lp(data, &mut c)?,
            verification_key: read_lp(data, &mut c)?,
            coin_balance: read_lp(data, &mut c)?,
            mask: read_lp(data, &mut c)?,
            additional_reference: read_lp(data, &mut c)?,
            additional_reference_key: read_lp(data, &mut c)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransactionInput {
    pub commitment: Vec<u8>,
    pub signature: Vec<u8>,
    pub proofs: Vec<Vec<u8>>,
}

impl TransactionInput {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_TRANSACTION_INPUT);
        put_lp(&mut out, &self.commitment);
        put_lp(&mut out, &self.signature);
        write_array(&mut out, &self.proofs);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_TRANSACTION_INPUT, "TransactionInput")?;
        Ok(Self {
            commitment: read_lp(data, &mut c)?,
            signature: read_lp(data, &mut c)?,
            proofs: read_array(data, &mut c)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransactionOutput {
    pub frame_number: Vec<u8>,
    pub commitment: Vec<u8>,
    pub recipient_output: Vec<u8>, // nested RecipientBundle canonical bytes
}

impl TransactionOutput {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_TRANSACTION_OUTPUT);
        put_lp(&mut out, &self.frame_number);
        put_lp(&mut out, &self.commitment);
        put_lp(&mut out, &self.recipient_output);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_TRANSACTION_OUTPUT, "TransactionOutput")?;
        Ok(Self {
            frame_number: read_lp(data, &mut c)?,
            commitment: read_lp(data, &mut c)?,
            recipient_output: read_lp(data, &mut c)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Transaction {
    pub domain: Vec<u8>,
    pub inputs: Vec<Vec<u8>>,   // nested TransactionInput canonical bytes
    pub outputs: Vec<Vec<u8>>,  // nested TransactionOutput canonical bytes
    pub fees: Vec<Vec<u8>>,     // BigInt serialized
    pub range_proof: Vec<u8>,
    pub traversal_proof: Vec<u8>, // nested TraversalProof canonical bytes
}

impl Transaction {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_TRANSACTION);
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
        expect_tp(read_u32(data, &mut c)?, TYPE_TRANSACTION, "Transaction")?;
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
    /// `Transaction.GetCost` at `token_intrinsic_transaction.go:991-1014`.
    pub fn get_cost(&self) -> Result<num_bigint::BigInt> {
        use num_bigint::BigInt;
        let mut size = BigInt::from(self.domain.len() as u64);
        size += BigInt::from(self.range_proof.len() as u64);
        size += BigInt::from(self.traversal_proof.len() as u64);
        for raw in &self.outputs {
            let out = TransactionOutput::from_canonical_bytes(raw)?;
            let r = RecipientBundle::from_canonical_bytes(&out.recipient_output)?;
            size += BigInt::from(8u64); // frame number
            size += BigInt::from(out.commitment.len() as u64);
            size += BigInt::from(r.coin_balance.len() as u64);
            size += BigInt::from(r.mask.len() as u64);
            size += BigInt::from(r.one_time_key.len() as u64);
            size += BigInt::from(r.verification_key.len() as u64);
            if r.additional_reference.len() == 64 {
                size += BigInt::from(120u64);
            }
        }
        Ok(size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_bundle_round_trip() {
        let r = RecipientBundle {
            one_time_key: vec![1u8; 57], verification_key: vec![2u8; 57],
            coin_balance: vec![3u8; 32], mask: vec![4u8; 32],
            additional_reference: vec![5u8; 64], additional_reference_key: vec![6u8; 57],
        };
        let b = r.to_canonical_bytes().unwrap();
        assert_eq!(RecipientBundle::from_canonical_bytes(&b).unwrap(), r);
    }

    #[test]
    fn transaction_input_round_trip() {
        let i = TransactionInput {
            commitment: vec![0xAAu8; 64], signature: vec![0xBBu8; 74],
            proofs: vec![vec![0xCCu8; 32], vec![0xDDu8; 32]],
        };
        let b = i.to_canonical_bytes().unwrap();
        assert_eq!(TransactionInput::from_canonical_bytes(&b).unwrap(), i);
    }

    #[test]
    fn transaction_output_round_trip() {
        let o = TransactionOutput {
            frame_number: vec![0, 0, 0, 42], commitment: vec![0xAAu8; 64],
            recipient_output: RecipientBundle::default().to_canonical_bytes().unwrap(),
        };
        let b = o.to_canonical_bytes().unwrap();
        assert_eq!(TransactionOutput::from_canonical_bytes(&b).unwrap(), o);
    }

    #[test]
    fn transaction_round_trip() {
        let tx = Transaction {
            domain: vec![0x11u8; 32],
            inputs: vec![TransactionInput { commitment: vec![1u8; 64], signature: vec![2u8; 74], proofs: vec![] }.to_canonical_bytes().unwrap()],
            outputs: vec![TransactionOutput { frame_number: vec![0,0,0,1], commitment: vec![3u8; 64], recipient_output: vec![] }.to_canonical_bytes().unwrap()],
            fees: vec![vec![0, 100]], range_proof: vec![0xFFu8; 128],
            traversal_proof: vec![],
        };
        let b = tx.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_TRANSACTION.to_be_bytes());
        assert_eq!(Transaction::from_canonical_bytes(&b).unwrap(), tx);
    }

    #[test]
    fn transaction_empty() {
        let tx = Transaction::default();
        let b = tx.to_canonical_bytes().unwrap();
        assert_eq!(Transaction::from_canonical_bytes(&b).unwrap(), tx);
    }
}

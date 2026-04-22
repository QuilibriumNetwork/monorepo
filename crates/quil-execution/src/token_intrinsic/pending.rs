//! Pending transaction types: PendingTransactionInput (0x050A),
//! PendingTransactionOutput (0x050B), PendingTransaction (0x050C).

use quil_types::error::Result;
use super::cursor::*;

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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

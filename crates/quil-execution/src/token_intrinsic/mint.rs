//! Mint transaction types: MintTransactionInput (0x050D),
//! MintTransactionOutput (0x050E), MintTransaction (0x050F).

use quil_types::error::Result;
use super::cursor::*;

pub const TYPE_MINT_TRANSACTION_INPUT: u32 = 0x050D;
pub const TYPE_MINT_TRANSACTION_OUTPUT: u32 = 0x050E;
pub const TYPE_MINT_TRANSACTION: u32 = 0x050F;

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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

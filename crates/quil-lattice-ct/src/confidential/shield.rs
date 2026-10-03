//! Legacy-coin shield encoding and amount relation. The execution
//! layer must authenticate the legacy owner, source value and unspent state.
use super::{
    relation::{CompiledAmountRelation, PublicAmountRelation},
    transfer::{
        parameter_context, Output, Reader, TransferError, MAX_TRANSACTION_BYTES, MEMO_BYTES,
    },
    AmountCommitment, AmountOpening, CommitmentKey, COMMITMENT_BYTES, MAX_PRIVATE_COINS,
};
use super::relation::membership::IDENTITY_BYTES;

const PREFIX: [u8; 4] = 0x0516u32.to_be_bytes();
const VERSION: &[u8; 8] = b"QCT3SH\0\x02";
const PROOF_MAGIC: &[u8; 8] = b"QPF6\0\0\0\0";
const HEADER_BYTES: usize = 4 + 8 + 32 + 32 + 32 + 57 + 16 + 16 + 2;
const OUTPUT_BYTES: usize = COMMITMENT_BYTES + IDENTITY_BYTES + MEMO_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShieldStatement {
    pub network: [u8; 32],
    pub application: [u8; 32],
    pub transparent_address: [u8; 32],
    pub owner_public_key: [u8; 57],
    pub amount: u128,
    pub fee: u128,
    pub outputs: Vec<Output>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shield {
    pub statement: ShieldStatement,
    pub signature: [u8; 114],
    pub proof: Vec<u8>,
}

impl ShieldStatement {
    /// The legacy owner signs these exact bytes. The amount proof binds the
    /// same bytes, including all recipient owners, commitments and memos.
    /// Signatures and proofs are excluded to avoid circular dependencies.
    pub fn context_bytes(&self) -> Result<Vec<u8>, TransferError> {
        if self.outputs.is_empty() || self.outputs.len() > MAX_PRIVATE_COINS {
            return Err(TransferError::Dimensions);
        }
        if self.fee > self.amount {
            return Err(TransferError::Noncanonical);
        }
        let len = HEADER_BYTES + self.outputs.len() * OUTPUT_BYTES;
        if len + 114 + 4 + 40 >= MAX_TRANSACTION_BYTES {
            return Err(TransferError::Length);
        }
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(&PREFIX);
        bytes.extend_from_slice(VERSION);
        bytes.extend_from_slice(&self.network);
        bytes.extend_from_slice(&self.application);
        bytes.extend_from_slice(&self.transparent_address);
        bytes.extend_from_slice(&self.owner_public_key);
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes.extend_from_slice(&self.fee.to_le_bytes());
        bytes.extend_from_slice(&(self.outputs.len() as u16).to_le_bytes());
        for output in &self.outputs {
            bytes.extend_from_slice(&output.commitment.to_bytes());
            bytes.extend_from_slice(&output.owner);
            bytes.extend_from_slice(&output.memo);
        }
        Ok(bytes)
    }

    pub fn public_relation(
        &self,
        max_outputs: usize,
    ) -> Result<PublicAmountRelation, TransferError> {
        if self.outputs.len() > max_outputs {
            return Err(TransferError::ResourceLimit);
        }
        let context = self.context_bytes()?;
        let key = CommitmentKey::derive(&parameter_context(&self.network, &self.application));
        let commitments: Vec<_> = self.outputs.iter().map(|o| o.commitment.clone()).collect();
        PublicAmountRelation::compile_issuance(&key, &commitments, self.amount, self.fee)
            .map(|r| r.with_transaction_context(&context))
            .map_err(TransferError::Relation)
    }

    pub fn private_relation(
        &self,
        openings: &[(u128, &AmountOpening)],
        max_outputs: usize,
    ) -> Result<CompiledAmountRelation, TransferError> {
        if self.outputs.len() > max_outputs {
            return Err(TransferError::ResourceLimit);
        }
        if openings.len() != self.outputs.len() {
            return Err(TransferError::Dimensions);
        }
        let context = self.context_bytes()?;
        let key = CommitmentKey::derive(&parameter_context(&self.network, &self.application));
        let coins: Vec<_> = openings
            .iter()
            .zip(&self.outputs)
            .map(|(&(amount, opening), output)| (amount, opening, &output.commitment))
            .collect();
        CompiledAmountRelation::compile_issuance(&key, &coins, self.amount, self.fee)
            .map(|r| r.with_transaction_context(&context))
            .map_err(TransferError::Relation)
    }
}

impl Shield {
    pub fn encode(&self) -> Result<Vec<u8>, TransferError> {
        if self.proof.len() < 40 || self.proof.get(..8) != Some(PROOF_MAGIC.as_slice()) {
            return Err(TransferError::Noncanonical);
        }
        let mut bytes = self.statement.context_bytes()?;
        if bytes
            .len()
            .checked_add(114 + 4)
            .and_then(|n| n.checked_add(self.proof.len()))
            .filter(|&n| n < MAX_TRANSACTION_BYTES)
            .is_none()
        {
            return Err(TransferError::Length);
        }
        bytes.extend_from_slice(&self.signature);
        bytes.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.proof);
        Ok(bytes)
    }

    pub fn decode(
        bytes: &[u8],
        network: &[u8; 32],
        application: &[u8; 32],
    ) -> Result<Self, TransferError> {
        if bytes.len() >= MAX_TRANSACTION_BYTES {
            return Err(TransferError::Length);
        }
        let mut r = Reader(bytes);
        if r.take(4)? != PREFIX || r.take(8)? != VERSION {
            return Err(TransferError::Version);
        }
        let encoded_network = r.array()?;
        let encoded_application = r.array()?;
        if &encoded_network != network || &encoded_application != application {
            return Err(TransferError::Context);
        }
        let transparent_address = r.array()?;
        let owner_public_key = r.array()?;
        let amount = u128::from_le_bytes(r.array()?);
        let fee = u128::from_le_bytes(r.array()?);
        let count = u16::from_le_bytes(r.array()?) as usize;
        if count == 0 || count > MAX_PRIVATE_COINS {
            return Err(TransferError::Dimensions);
        }
        if r.0.len() < count * OUTPUT_BYTES + 114 + 4 + 40 {
            return Err(TransferError::Length);
        }
        let mut outputs = Vec::with_capacity(count);
        for _ in 0..count {
            outputs.push(Output {
                commitment: AmountCommitment::from_bytes(r.take(COMMITMENT_BYTES)?)
                    .map_err(|_| TransferError::Noncanonical)?,
                owner: r.array()?,
                memo: r.array()?,
            });
        }
        let signature = r.array()?;
        let len = u32::from_le_bytes(r.array()?) as usize;
        if len < 40 || len != r.0.len() || r.0.get(..8) != Some(PROOF_MAGIC.as_slice()) {
            return Err(TransferError::Length);
        }
        let statement = ShieldStatement {
            network: encoded_network,
            application: encoded_application,
            transparent_address,
            owner_public_key,
            amount,
            fee,
            outputs,
        };
        statement.context_bytes()?;
        Ok(Self {
            statement,
            signature,
            proof: r.0.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shield_codec_binds_source_outputs_and_bounds_the_payload() {
        let network = [1; 32];
        let application = [2; 32];
        let context = parameter_context(&network, &application);
        let key = CommitmentKey::derive(&context);
        let opening = AmountOpening::from_seed(&context, &[3; 32]);
        // Framing/size fixture only; these are not valid native proof bytes.
        let mut proof = vec![0; 149928];
        proof[..8].copy_from_slice(PROOF_MAGIC);
        let shield = Shield {
            statement: ShieldStatement {
                network,
                application,
                transparent_address: [4; 32],
                owner_public_key: [5; 57],
                amount: 11,
                fee: 1,
                outputs: vec![
                    Output {
                        commitment: key.commit(5, &opening),
                        owner: [6; IDENTITY_BYTES],
                        memo: [7; MEMO_BYTES]
                    };
                    2
                ],
            },
            signature: [8; 114],
            proof,
        };
        assert!(shield
            .statement
            .private_relation(&[(5, &opening); 2], 2)
            .unwrap()
            .validate_local_witness());
        assert!(shield.statement.public_relation(1).is_err());
        let bytes = shield.encode().unwrap();
        assert_eq!(bytes.len(), 180507); // Includes signatures, memos and proof framing.
        assert!(bytes.len() < super::super::transfer::TARGET_TRANSACTION_BYTES);
        assert_eq!(
            Shield::decode(&bytes, &network, &application).unwrap(),
            shield
        );
        assert!(Shield::decode(&bytes, &[9; 32], &application).is_err());
        assert!(Shield::decode(&bytes, &network, &[9; 32]).is_err());
        for end in [0, 4, 12, HEADER_BYTES - 1, bytes.len() - 1] {
            assert!(Shield::decode(&bytes[..end], &network, &application).is_err());
        }
        let mut appended = bytes.clone();
        appended.push(0);
        assert!(Shield::decode(&appended, &network, &application).is_err());
        let original = shield.statement.context_bytes().unwrap();
        let mut changed = shield.clone();
        changed.statement.transparent_address[0] ^= 1;
        assert_ne!(changed.statement.context_bytes().unwrap(), original);
        changed = shield.clone();
        changed.statement.outputs[0].memo[0] ^= 1;
        assert_ne!(changed.statement.context_bytes().unwrap(), original);
        changed = shield.clone();
        changed.statement.fee = 12;
        assert!(changed.encode().is_err());
        changed = shield.clone();
        changed.proof.resize(
            MAX_TRANSACTION_BYTES - (bytes.len() - shield.proof.len()),
            0,
        );
        assert!(changed.encode().is_err());
    }
}

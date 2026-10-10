//! Reward-backed mint encoding. Execution must authenticate the cited reward
//! root, signatures and current balances, and record authorization consumption.
use super::{
    relation::{CompiledAmountRelation, PublicAmountRelation},
    transfer::{
        parameter_context, Output, Reader, TransferError, MAX_TRANSACTION_BYTES, MEMO_BYTES,
    },
    AmountCommitment, AmountOpening, CommitmentKey, COMMITMENT_BYTES, MAX_PRIVATE_COINS,
};
use super::relation::membership::IDENTITY_BYTES;
use std::collections::BTreeSet;

pub const FALCON_PUBLIC_BYTES: usize = 897;
pub const FALCON_SIGNATURE_BYTES: usize = 666;
pub const MAX_REWARD_PROOF_BYTES: usize = 32 * 1024;
const PREFIX: [u8; 4] = 0x0513u32.to_be_bytes();
const VERSION: &[u8; 8] = b"QCT3MT\0\x02";
const PROOF_MAGIC: &[u8; 8] = b"QPF6\0\0\0\0";
const HEADER_BYTES: usize = 4 + 8 + 32 + 32 + 8 + 32 + 16 + 2 + 2;
const CLAIM_BYTES: usize = 32 + 16 + FALCON_PUBLIC_BYTES + 4;
const OUTPUT_BYTES: usize = COMMITMENT_BYTES + IDENTITY_BYTES + MEMO_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewardClaim {
    pub owner: [u8; 32],
    pub value: u128,
    pub public_key: [u8; FALCON_PUBLIC_BYTES],
    pub forest_proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintStatement {
    pub network: [u8; 32],
    pub application: [u8; 32],
    pub cited_frame: u64,
    pub reward_root: [u8; 32],
    pub fee: u128,
    pub claims: Vec<RewardClaim>,
    pub outputs: Vec<Output>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mint {
    pub statement: MintStatement,
    pub signatures: Vec<[u8; FALCON_SIGNATURE_BYTES]>,
    pub proof: Vec<u8>,
}

impl MintStatement {
    pub fn total(&self) -> Result<u128, TransferError> {
        if self.claims.is_empty() || self.claims.len() > MAX_PRIVATE_COINS {
            return Err(TransferError::Dimensions);
        }
        let mut owners = BTreeSet::new();
        self.claims.iter().try_fold(0u128, |sum, claim| {
            if claim.value == 0 || !owners.insert(claim.owner) {
                return Err(TransferError::Noncanonical);
            }
            sum.checked_add(claim.value)
                .ok_or(TransferError::Noncanonical)
        })
    }

    /// Every claimant signs these same exact bytes; the native amount proof
    /// binds them too. Signatures/proof bytes are excluded to avoid a cycle.
    pub fn context_bytes(&self) -> Result<Vec<u8>, TransferError> {
        if self.outputs.is_empty() || self.outputs.len() > MAX_PRIVATE_COINS {
            return Err(TransferError::Dimensions);
        }
        if self.fee > self.total()? {
            return Err(TransferError::Noncanonical);
        }
        let mut len = HEADER_BYTES + self.outputs.len() * OUTPUT_BYTES;
        for claim in &self.claims {
            if claim.forest_proof.is_empty() || claim.forest_proof.len() > MAX_REWARD_PROOF_BYTES {
                return Err(TransferError::Length);
            }
            len += CLAIM_BYTES + claim.forest_proof.len();
        }
        if len + self.claims.len() * FALCON_SIGNATURE_BYTES + 4 + 40 >= MAX_TRANSACTION_BYTES {
            return Err(TransferError::Length);
        }
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(&PREFIX);
        bytes.extend_from_slice(VERSION);
        bytes.extend_from_slice(&self.network);
        bytes.extend_from_slice(&self.application);
        bytes.extend_from_slice(&self.cited_frame.to_le_bytes());
        bytes.extend_from_slice(&self.reward_root);
        bytes.extend_from_slice(&self.fee.to_le_bytes());
        bytes.extend_from_slice(&(self.claims.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(self.outputs.len() as u16).to_le_bytes());
        for claim in &self.claims {
            bytes.extend_from_slice(&claim.owner);
            bytes.extend_from_slice(&claim.value.to_le_bytes());
            bytes.extend_from_slice(&claim.public_key);
            bytes.extend_from_slice(&(claim.forest_proof.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&claim.forest_proof);
        }
        for output in &self.outputs {
            bytes.extend_from_slice(&output.commitment.to_bytes());
            bytes.extend_from_slice(&output.owner);
            bytes.extend_from_slice(&output.memo);
        }
        Ok(bytes)
    }

    pub fn public_relation(
        &self,
        max_claims: usize,
        max_outputs: usize,
    ) -> Result<PublicAmountRelation, TransferError> {
        if self.claims.len() > max_claims || self.outputs.len() > max_outputs {
            return Err(TransferError::ResourceLimit);
        }
        let context = self.context_bytes()?;
        let key = CommitmentKey::derive(&parameter_context(&self.network, &self.application));
        let commitments: Vec<_> = self.outputs.iter().map(|o| o.commitment.clone()).collect();
        PublicAmountRelation::compile_issuance(&key, &commitments, self.total()?, self.fee)
            .map(|r| r.with_transaction_context(&context))
            .map_err(TransferError::Relation)
    }

    pub fn private_relation(
        &self,
        openings: &[(u128, &AmountOpening)],
        max_claims: usize,
        max_outputs: usize,
    ) -> Result<CompiledAmountRelation, TransferError> {
        if self.claims.len() > max_claims || self.outputs.len() > max_outputs {
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
            .map(|(&(a, r), o)| (a, r, &o.commitment))
            .collect();
        CompiledAmountRelation::compile_issuance(&key, &coins, self.total()?, self.fee)
            .map(|r| r.with_transaction_context(&context))
            .map_err(TransferError::Relation)
    }
}

impl Mint {
    pub fn encode(&self) -> Result<Vec<u8>, TransferError> {
        if self.signatures.len() != self.statement.claims.len() {
            return Err(TransferError::Dimensions);
        }
        if self.proof.len() < 40 || self.proof.get(..8) != Some(PROOF_MAGIC.as_slice()) {
            return Err(TransferError::Noncanonical);
        }
        let mut bytes = self.statement.context_bytes()?;
        if bytes
            .len()
            .checked_add(self.signatures.len() * FALCON_SIGNATURE_BYTES + 4)
            .and_then(|n| n.checked_add(self.proof.len()))
            .filter(|&n| n < MAX_TRANSACTION_BYTES)
            .is_none()
        {
            return Err(TransferError::Length);
        }
        for signature in &self.signatures {
            bytes.extend_from_slice(signature);
        }
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
        let cited_frame = u64::from_le_bytes(r.array()?);
        let reward_root = r.array()?;
        let fee = u128::from_le_bytes(r.array()?);
        let claim_count = u16::from_le_bytes(r.array()?) as usize;
        let output_count = u16::from_le_bytes(r.array()?) as usize;
        if claim_count == 0
            || output_count == 0
            || claim_count > MAX_PRIVATE_COINS
            || output_count > MAX_PRIVATE_COINS
        {
            return Err(TransferError::Dimensions);
        }
        if r.0.len()
            < claim_count * (CLAIM_BYTES + 1 + FALCON_SIGNATURE_BYTES)
                + output_count * OUTPUT_BYTES
                + 4
                + 40
        {
            return Err(TransferError::Length);
        }
        let mut claims = Vec::with_capacity(claim_count);
        for _ in 0..claim_count {
            let owner = r.array()?;
            let value = u128::from_le_bytes(r.array()?);
            let public_key = r.array()?;
            let len = u32::from_le_bytes(r.array()?) as usize;
            if len == 0 || len > MAX_REWARD_PROOF_BYTES {
                return Err(TransferError::Length);
            }
            claims.push(RewardClaim {
                owner,
                value,
                public_key,
                forest_proof: r.take(len)?.to_vec(),
            });
        }
        let mut outputs = Vec::with_capacity(output_count);
        for _ in 0..output_count {
            outputs.push(Output {
                commitment: AmountCommitment::from_bytes(r.take(COMMITMENT_BYTES)?)
                    .map_err(|_| TransferError::Noncanonical)?,
                owner: r.array()?,
                memo: r.array()?,
            });
        }
        let mut signatures = Vec::with_capacity(claim_count);
        for _ in 0..claim_count {
            signatures.push(r.array()?);
        }
        let len = u32::from_le_bytes(r.array()?) as usize;
        if len < 40 || len != r.0.len() || r.0.get(..8) != Some(PROOF_MAGIC.as_slice()) {
            return Err(TransferError::Length);
        }
        let statement = MintStatement {
            network: encoded_network,
            application: encoded_application,
            cited_frame,
            reward_root,
            fee,
            claims,
            outputs,
        };
        statement.context_bytes()?;
        Ok(Self {
            statement,
            signatures,
            proof: r.0.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::transfer::TARGET_TRANSACTION_BYTES;
    use super::*;

    #[test]
    fn reward_mint_codec_binds_claims_outputs_and_bounds_the_complete_payload() {
        let network = [1; 32];
        let application = [2; 32];
        let context = parameter_context(&network, &application);
        let key = CommitmentKey::derive(&context);
        let openings = [
            AmountOpening::from_seed(&context, &[3; 32]),
            AmountOpening::from_seed(&context, &[4; 32]),
        ];
        let amounts = [u128::MAX - 258, 256];
        let outputs = amounts
            .iter()
            .zip(&openings)
            .map(|(&a, r)| Output {
                commitment: key.commit(a, r),
                owner: [5; IDENTITY_BYTES],
                memo: [6; MEMO_BYTES],
            })
            .collect();
        let statement = MintStatement {
            network,
            application,
            cited_frame: 7,
            reward_root: [8; 32],
            fee: 2,
            claims: [u128::MAX - 257, 257]
                .iter()
                .enumerate()
                .map(|(i, &value)| RewardClaim {
                    owner: [9 + i as u8; 32],
                    value,
                    public_key: [11 + i as u8; FALCON_PUBLIC_BYTES],
                    forest_proof: vec![12; MAX_REWARD_PROOF_BYTES],
                })
                .collect(),
            outputs,
        };
        let private = statement
            .private_relation(
                &[(amounts[0], &openings[0]), (amounts[1], &openings[1])],
                2,
                2,
            )
            .unwrap();
        assert!(private.validate_local_witness());
        assert_eq!(statement.total().unwrap(), u128::MAX);
        // Size/framing fixture only: neither these forest proofs, signatures nor
        // the native proof bytes are valid cryptographic authorizations.
        let mut proof = vec![0; 149_928];
        proof[..8].copy_from_slice(PROOF_MAGIC);
        let tx = Mint {
            statement,
            signatures: vec![[0; FALCON_SIGNATURE_BYTES]; 2],
            proof,
        };
        let bytes = tx.encode().unwrap();
        assert_eq!(bytes.len(), 249_096);
        assert!(bytes.len() < TARGET_TRANSACTION_BYTES);
        assert_eq!(Mint::decode(&bytes, &network, &application).unwrap(), tx);
        assert!(Mint::decode(&bytes, &[99; 32], &application).is_err());
        assert!(Mint::decode(&bytes[..bytes.len() - 1], &network, &application).is_err());
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(Mint::decode(&extra, &network, &application).is_err());
        assert!(tx.statement.public_relation(1, 2).is_err());
        assert!(tx.statement.public_relation(2, 1).is_err());
        let original = tx.statement.context_bytes().unwrap();
        let mut changed = tx.clone();
        changed.statement.cited_frame += 1;
        assert_ne!(changed.statement.context_bytes().unwrap(), original);
        changed = tx.clone();
        changed.statement.reward_root[0] ^= 1;
        assert_ne!(changed.statement.context_bytes().unwrap(), original);
        changed = tx.clone();
        changed.statement.outputs[0].memo[0] ^= 1;
        assert_ne!(changed.statement.context_bytes().unwrap(), original);
        changed = tx.clone();
        changed.statement.claims[0].forest_proof[0] ^= 1;
        assert_ne!(changed.statement.context_bytes().unwrap(), original);
        changed = tx.clone();
        changed.statement.claims[1].owner = changed.statement.claims[0].owner;
        assert!(changed.encode().is_err());
        changed = tx.clone();
        changed.statement.claims[1].value += 1;
        assert!(changed.encode().is_err());
        changed = tx.clone();
        changed.statement.claims[0].forest_proof.push(0);
        assert!(changed.encode().is_err());
        changed = tx.clone();
        changed.signatures.pop();
        assert!(changed.encode().is_err());
        changed = tx.clone();
        changed.proof.resize(MAX_TRANSACTION_BYTES, 0);
        assert!(changed.encode().is_err());
    }
}

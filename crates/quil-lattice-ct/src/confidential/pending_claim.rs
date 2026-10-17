//! Escrow claim/refund statement. Amount proofs do not authorize
//! consumption: execution must compare the source/policy with stored state,
//! check the selected signature and global deadline, and consume the source once.
use super::{
    mint::{FALCON_PUBLIC_BYTES, FALCON_SIGNATURE_BYTES},
    relation::{CompiledAmountRelation, PublicAmountRelation},
    transfer::{parameter_context, Output, Reader, TransferError, MAX_TRANSACTION_BYTES, MEMO_BYTES},
    AmountCommitment, AmountOpening, CommitmentKey, COMMITMENT_BYTES, MAX_PRIVATE_COINS,
};
use super::relation::membership::IDENTITY_BYTES;

const PREFIX: [u8; 4] = 0x0515u32.to_be_bytes();
const VERSION: &[u8; 8] = b"QCT3PC\0\x02";
const OUTPUT_BYTES: usize = COMMITMENT_BYTES + IDENTITY_BYTES + MEMO_BYTES;
const HEADER_BYTES: usize = 4 + 8 + 32 + 32 + 32 + COMMITMENT_BYTES + 2 * FALCON_PUBLIC_BYTES + 8 + 1 + 16 + 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimBranch { Recipient, Refund }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EscrowPolicy {
    pub recipient: [u8; FALCON_PUBLIC_BYTES],
    pub refund: [u8; FALCON_PUBLIC_BYTES],
    /// Compared with an authenticated global-frame reference, never an app height.
    pub refund_after_global_frame: u64,
}

impl EscrowPolicy {
    /// Select authority after the caller supplies an authenticated global frame.
    /// The recipient remains eligible after refund becomes possible. Replay
    /// exclusion and signature verification must still be enforced by execution.
    pub fn key_for_branch(&self, branch: ClaimBranch, global_frame: u64) -> Option<&[u8; FALCON_PUBLIC_BYTES]> {
        match branch {
            ClaimBranch::Recipient => Some(&self.recipient),
            ClaimBranch::Refund if global_frame >= self.refund_after_global_frame => Some(&self.refund),
            ClaimBranch::Refund => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingClaimStatement {
    pub network: [u8; 32],
    pub application: [u8; 32],
    pub escrow_address: [u8; 32],
    pub source: AmountCommitment,
    pub policy: EscrowPolicy,
    pub branch: ClaimBranch,
    pub fee: u128,
    pub outputs: Vec<Output>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingClaim {
    pub statement: PendingClaimStatement,
    pub signature: [u8; FALCON_SIGNATURE_BYTES],
    pub proof: Vec<u8>,
}

impl PendingClaimStatement {
    pub fn context_bytes(&self) -> Result<Vec<u8>, TransferError> {
        // The identified escrow is one input in the shared relation limit.
        if self.outputs.is_empty() || self.outputs.len() >= MAX_PRIVATE_COINS {
            return Err(TransferError::Dimensions);
        }
        let len = HEADER_BYTES + self.outputs.len() * OUTPUT_BYTES;
        if len + FALCON_SIGNATURE_BYTES + 4 + 40 >= MAX_TRANSACTION_BYTES {
            return Err(TransferError::Length);
        }
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(&PREFIX);
        bytes.extend_from_slice(VERSION);
        bytes.extend_from_slice(&self.network);
        bytes.extend_from_slice(&self.application);
        bytes.extend_from_slice(&self.escrow_address);
        bytes.extend_from_slice(&self.source.to_bytes());
        bytes.extend_from_slice(&self.policy.recipient);
        bytes.extend_from_slice(&self.policy.refund);
        bytes.extend_from_slice(&self.policy.refund_after_global_frame.to_le_bytes());
        bytes.push(match self.branch { ClaimBranch::Recipient => 0, ClaimBranch::Refund => 1 });
        bytes.extend_from_slice(&self.fee.to_le_bytes());
        bytes.extend_from_slice(&(self.outputs.len() as u16).to_le_bytes());
        for output in &self.outputs {
            bytes.extend_from_slice(&output.commitment.to_bytes());
            bytes.extend_from_slice(&output.owner);
            bytes.extend_from_slice(&output.memo);
        }
        debug_assert_eq!(bytes.len(), len);
        Ok(bytes)
    }

    pub fn public_relation(&self, max_outputs: usize) -> Result<PublicAmountRelation, TransferError> {
        if self.outputs.len() > max_outputs { return Err(TransferError::ResourceLimit); }
        let bytes = self.context_bytes()?;
        let key = CommitmentKey::derive(&parameter_context(&self.network, &self.application));
        let outputs: Vec<_> = self.outputs.iter().map(|o| o.commitment.clone()).collect();
        PublicAmountRelation::compile_public_spend(&key, std::slice::from_ref(&self.source), &outputs, self.fee)
            .map(|r| r.with_transaction_context(&bytes)).map_err(TransferError::Relation)
    }

    pub fn private_relation(&self, source: (u128, &AmountOpening), outputs: &[(u128, &AmountOpening)], max_outputs: usize)
        -> Result<CompiledAmountRelation, TransferError> {
        if outputs.len() != self.outputs.len() { return Err(TransferError::Dimensions); }
        if outputs.len() > max_outputs { return Err(TransferError::ResourceLimit); }
        let bytes = self.context_bytes()?;
        let key = CommitmentKey::derive(&parameter_context(&self.network, &self.application));
        let outputs: Vec<_> = outputs.iter().zip(&self.outputs).map(|(&(a, r), o)| (a, r, &o.commitment)).collect();
        CompiledAmountRelation::compile_public_spend(&key, &[(source.0, source.1, &self.source)], &outputs, self.fee)
            .map(|r| r.with_transaction_context(&bytes)).map_err(TransferError::Relation)
    }
}

impl PendingClaim {
    pub fn encode(&self) -> Result<Vec<u8>, TransferError> {
        if self.proof.len() < 40 || self.proof.len() >= MAX_TRANSACTION_BYTES || &self.proof[..8] != b"QPF6\0\0\0\0" {
            return Err(TransferError::Length);
        }
        let mut bytes = self.statement.context_bytes()?;
        if bytes.len() + FALCON_SIGNATURE_BYTES + 4 + self.proof.len() >= MAX_TRANSACTION_BYTES {
            return Err(TransferError::Length);
        }
        bytes.extend_from_slice(&self.signature);
        bytes.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.proof);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8], network: &[u8; 32], application: &[u8; 32]) -> Result<Self, TransferError> {
        if bytes.len() >= MAX_TRANSACTION_BYTES { return Err(TransferError::Length); }
        let mut r = Reader(bytes);
        if r.take(4)? != PREFIX || r.take(8)? != VERSION { return Err(TransferError::Version); }
        let encoded_network = r.array()?;
        let encoded_application = r.array()?;
        if &encoded_network != network || &encoded_application != application { return Err(TransferError::Context); }
        let escrow_address = r.array()?;
        let source = AmountCommitment::from_bytes(r.take(COMMITMENT_BYTES)?).map_err(|_| TransferError::Noncanonical)?;
        let policy = EscrowPolicy { recipient: r.array()?, refund: r.array()?, refund_after_global_frame: u64::from_le_bytes(r.array()?) };
        let branch = match r.take(1)?[0] { 0 => ClaimBranch::Recipient, 1 => ClaimBranch::Refund, _ => return Err(TransferError::Noncanonical) };
        let fee = u128::from_le_bytes(r.array()?);
        let count = u16::from_le_bytes(r.array()?) as usize;
        if count == 0 || count >= MAX_PRIVATE_COINS { return Err(TransferError::Dimensions); }
        if r.0.len() < count * OUTPUT_BYTES + FALCON_SIGNATURE_BYTES + 4 + 40 { return Err(TransferError::Length); }
        let mut outputs = Vec::with_capacity(count);
        for _ in 0..count {
            outputs.push(Output {
                commitment: AmountCommitment::from_bytes(r.take(COMMITMENT_BYTES)?).map_err(|_| TransferError::Noncanonical)?,
                owner: r.array()?, memo: r.array()?,
            });
        }
        let signature = r.array()?;
        let proof_len = u32::from_le_bytes(r.array()?) as usize;
        if proof_len < 40 || proof_len != r.0.len() || &r.0[..8] != b"QPF6\0\0\0\0" { return Err(TransferError::Length); }
        Ok(Self { statement: PendingClaimStatement { network: encoded_network, application: encoded_application,
            escrow_address, source, policy, branch, fee, outputs }, signature, proof: r.0.to_vec() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_claim_codec_context_and_refund_boundary() {
        let network = [11; 32];
        let application = [12; 32];
        let context = parameter_context(&network, &application);
        let key = CommitmentKey::derive(&context);
        let input = AmountOpening::from_seed(&context, &[13; 32]);
        let output = AmountOpening::from_seed(&context, &[14; 32]);
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        let tx = PendingClaim {
            statement: PendingClaimStatement {
                network, application, escrow_address: [15; 32], source: key.commit(11, &input),
                policy: EscrowPolicy { recipient: [16; FALCON_PUBLIC_BYTES], refund: [17; FALCON_PUBLIC_BYTES], refund_after_global_frame: 100 },
                branch: ClaimBranch::Recipient, fee: 2,
                outputs: vec![Output { commitment: key.commit(9, &output), owner: [18; IDENTITY_BYTES], memo: [19; MEMO_BYTES] }],
            }, signature: [0; FALCON_SIGNATURE_BYTES], proof,
        };
        let bytes = tx.encode().unwrap();
        assert_eq!(PendingClaim::decode(&bytes, &network, &application).unwrap(), tx);
        assert_eq!(bytes.len(), HEADER_BYTES + OUTPUT_BYTES + FALCON_SIGNATURE_BYTES + 4 + 40);
        assert!(tx.statement.private_relation((11, &input), &[(9, &output)], 1).unwrap().validate_local_witness());
        assert!(tx.statement.public_relation(1).is_ok());
        assert!(tx.statement.public_relation(0).is_err());
        assert!(tx.statement.private_relation((11, &input), &[(8, &output)], 1).is_err());
        for frame in [0, 99, 100, 101, u64::MAX] {
            assert_eq!(tx.statement.policy.key_for_branch(ClaimBranch::Recipient, frame), Some(&tx.statement.policy.recipient));
            assert_eq!(tx.statement.policy.key_for_branch(ClaimBranch::Refund, frame).is_some(), frame >= 100);
        }
        let bound = tx.statement.context_bytes().unwrap();
        let mut changes = Vec::new();
        let mut s = tx.statement.clone(); s.policy.refund_after_global_frame += 1; changes.push(s);
        let mut s = tx.statement.clone(); s.policy.recipient[0] ^= 1; changes.push(s);
        let mut s = tx.statement.clone(); s.policy.refund[0] ^= 1; changes.push(s);
        let mut s = tx.statement.clone(); s.branch = ClaimBranch::Refund; changes.push(s);
        let mut s = tx.statement.clone(); s.escrow_address[0] ^= 1; changes.push(s);
        let mut s = tx.statement.clone(); s.source = key.commit(10, &input); changes.push(s);
        let mut s = tx.statement.clone(); s.outputs[0].memo[0] ^= 1; changes.push(s);
        for s in changes { assert_ne!(s.context_bytes().unwrap(), bound); }
        for end in [0, 3, 4, 11, 12, 75, 107, HEADER_BYTES - 1, HEADER_BYTES,
            HEADER_BYTES + OUTPUT_BYTES - 1, bytes.len() - 1] {
            assert!(PendingClaim::decode(&bytes[..end], &network, &application).is_err());
        }
        assert!(PendingClaim::decode(&bytes, &[20; 32], &application).is_err());
        assert!(PendingClaim::decode(&bytes, &network, &[20; 32]).is_err());
        let mut bad = bytes.clone(); bad[4] ^= 1;
        assert!(PendingClaim::decode(&bad, &network, &application).is_err());
        let mut bad = bytes.clone(); bad[HEADER_BYTES - 19] = 2;
        assert!(PendingClaim::decode(&bad, &network, &application).is_err());
        let mut bad = bytes.clone(); bad[HEADER_BYTES - 2..HEADER_BYTES].fill(255);
        assert!(PendingClaim::decode(&bad, &network, &application).is_err());
        let mut bad = bytes.clone(); bad.push(0);
        assert!(PendingClaim::decode(&bad, &network, &application).is_err());
        assert!(PendingClaim::decode(&vec![0; MAX_TRANSACTION_BYTES], &network, &application).is_err());
    }
}

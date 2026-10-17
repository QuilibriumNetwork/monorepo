//! App-side transport of globally authorized mint outputs.
//! Decoding does not authenticate the global root or consume the authorization.
use super::{
    mint::MAX_REWARD_PROOF_BYTES,
    transfer::{Output, Reader, TransferError, MAX_TRANSACTION_BYTES, MEMO_BYTES},
    AmountCommitment, COMMITMENT_BYTES, MAX_PRIVATE_COINS,
};
use super::relation::membership::IDENTITY_BYTES;

const PREFIX: [u8; 4] = 0x0517u32.to_be_bytes();
const VERSION: &[u8; 8] = b"QCT3MC\0\x02";
const HEADER_BYTES: usize = 4 + 8 + 32 + 32 + 8 + 32 + 32 + 16 + 2 + 4;
const OUTPUT_BYTES: usize = COMMITMENT_BYTES + IDENTITY_BYTES + MEMO_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MintClaim {
    pub network: [u8; 32],
    pub application: [u8; 32],
    pub cited_global_frame: u64,
    pub global_root: [u8; 32],
    pub receipt: [u8; 32],
    /// Fee already authorized with the global reward debit; not another debit.
    pub fee: u128,
    pub outputs: Vec<Output>,
    pub forest_proof: Vec<u8>,
}

impl MintClaim {
    pub fn encode(&self) -> Result<Vec<u8>, TransferError> {
        if self.outputs.is_empty() || self.outputs.len() > MAX_PRIVATE_COINS {
            return Err(TransferError::Dimensions);
        }
        if self.forest_proof.is_empty() || self.forest_proof.len() > MAX_REWARD_PROOF_BYTES {
            return Err(TransferError::Length);
        }
        let len = HEADER_BYTES + self.outputs.len() * OUTPUT_BYTES + self.forest_proof.len();
        if len >= MAX_TRANSACTION_BYTES {
            return Err(TransferError::Length);
        }
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(&PREFIX);
        bytes.extend_from_slice(VERSION);
        bytes.extend_from_slice(&self.network);
        bytes.extend_from_slice(&self.application);
        bytes.extend_from_slice(&self.cited_global_frame.to_le_bytes());
        bytes.extend_from_slice(&self.global_root);
        bytes.extend_from_slice(&self.receipt);
        bytes.extend_from_slice(&self.fee.to_le_bytes());
        bytes.extend_from_slice(&(self.outputs.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(self.forest_proof.len() as u32).to_le_bytes());
        for output in &self.outputs {
            bytes.extend_from_slice(&output.commitment.to_bytes());
            bytes.extend_from_slice(&output.owner);
            bytes.extend_from_slice(&output.memo);
        }
        bytes.extend_from_slice(&self.forest_proof);
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
        let cited_global_frame = u64::from_le_bytes(r.array()?);
        let global_root = r.array()?;
        let receipt = r.array()?;
        let fee = u128::from_le_bytes(r.array()?);
        let count = u16::from_le_bytes(r.array()?) as usize;
        let proof_len = u32::from_le_bytes(r.array()?) as usize;
        if count == 0 || count > MAX_PRIVATE_COINS {
            return Err(TransferError::Dimensions);
        }
        // Check the complete size before allocating outputs or copying the proof.
        if proof_len == 0
            || proof_len > MAX_REWARD_PROOF_BYTES
            || r.0.len() != count * OUTPUT_BYTES + proof_len
        {
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
        Ok(Self {
            network: encoded_network,
            application: encoded_application,
            cited_global_frame,
            global_root,
            receipt,
            fee,
            outputs,
            forest_proof: r.take(proof_len)?.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::{AmountOpening, CommitmentKey};

    fn claim() -> MintClaim {
        let key = CommitmentKey::derive(&[1; 32]);
        let opening = AmountOpening::from_seed(&[1; 32], &[2; 32]);
        MintClaim {
            network: [1; 32],
            application: [3; 32],
            cited_global_frame: 9,
            global_root: [4; 32],
            receipt: [5; 32],
            fee: 2,
            outputs: vec![
                Output {
                    commitment: key.commit(7, &opening),
                    owner: [6; IDENTITY_BYTES],
                    memo: [7; MEMO_BYTES]
                };
                2
            ],
            // Codec fixture only; deliberately not an authenticated forest proof.
            forest_proof: vec![8; MAX_REWARD_PROOF_BYTES],
        }
    }

    #[test]
    fn bounded_claim_roundtrip_and_size() {
        let claim = claim();
        let bytes = claim.encode().unwrap();
        assert_eq!(bytes.len(), 63_200);
        assert_eq!(
            MintClaim::decode(&bytes, &claim.network, &claim.application).unwrap(),
            claim
        );
        // Previously measured 2-claim mint at maximum reward-witness lengths.
        assert!(241_896 + bytes.len() < MAX_TRANSACTION_BYTES);
        assert!(241_896 + bytes.len() > 256 * 1024);
    }

    #[test]
    fn rejects_bad_lengths_context_and_noncanonical_commitments() {
        let claim = claim();
        let bytes = claim.encode().unwrap();
        for len in [0, 4, 12, HEADER_BYTES - 1, HEADER_BYTES, bytes.len() - 1] {
            assert!(MintClaim::decode(&bytes[..len], &claim.network, &claim.application).is_err());
        }
        let mut changed = bytes.clone();
        changed.push(0);
        assert!(MintClaim::decode(&changed, &claim.network, &claim.application).is_err());
        assert!(MintClaim::decode(&bytes, &[9; 32], &claim.application).is_err());
        assert!(MintClaim::decode(&bytes, &claim.network, &[9; 32]).is_err());
        for count in [0u16, 129, u16::MAX] {
            let mut changed = bytes.clone();
            changed[HEADER_BYTES - 6..HEADER_BYTES - 4].copy_from_slice(&count.to_le_bytes());
            assert!(MintClaim::decode(&changed, &claim.network, &claim.application).is_err());
        }
        let mut changed = bytes.clone();
        changed[HEADER_BYTES - 4..HEADER_BYTES].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(MintClaim::decode(&changed, &claim.network, &claim.application).is_err());
        let mut changed = bytes;
        changed[HEADER_BYTES..HEADER_BYTES + COMMITMENT_BYTES].fill(0xff);
        assert!(MintClaim::decode(&changed, &claim.network, &claim.application).is_err());
        let mut claim = claim;
        claim.forest_proof.push(0);
        assert!(claim.encode().is_err());
    }
}

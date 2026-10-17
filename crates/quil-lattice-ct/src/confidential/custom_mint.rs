//! Custom-token (non-QUIL) issuance encoding and amount relation. Execution
//! must load the token's deployed mint policy, authenticate the configured
//! authority (or confirm a permissionless policy) over `context_bytes`, and
//! record one-time consumption of the statement's receipt. The amount relation
//! proves only that the outputs open to exactly the public `amount`; it
//! carries no QUIL fee because custom-token units are not QUIL gas.
use super::{
    relation::{CompiledAmountRelation, PublicAmountRelation},
    transfer::{
        parameter_context, Output, Reader, TransferError, MAX_TRANSACTION_BYTES, MEMO_BYTES,
    },
    AmountCommitment, AmountOpening, CommitmentKey, COMMITMENT_BYTES, MAX_PRIVATE_COINS,
};
use super::relation::membership::IDENTITY_BYTES;

const PREFIX: [u8; 4] = 0x0513u32.to_be_bytes();
/// Distinguishes custom issuance from the reward mint (`QCT3MT`) sharing 0x0513.
pub const VERSION: &[u8; 8] = b"QCT3CM\0\x02";
const PROOF_MAGIC: &[u8; 8] = b"QPF6\0\0\0\0";
/// Falcon-512 public keys are 897 bytes; Ed448 57; Ed25519 32.
pub const MAX_AUTHORITY_KEY_BYTES: usize = 1024;
/// Entitlement proof bytes: one byte of direction plus a 32-byte sibling per
/// level, to a depth of 32 (four billion entitlements).
pub const MAX_ENTITLEMENT_PROOF_BYTES: usize = 33 * 32;
/// Falcon-512 signatures are 666 bytes; Ed448 114; Ed25519 64.
pub const MAX_AUTHORITY_SIGNATURE_BYTES: usize = 1024;
const HEADER_BYTES: usize = 4 + 8 + 32 + 32 + 4 + 2 + 32 + 16 + 2 + 2;
const OUTPUT_BYTES: usize = COMMITMENT_BYTES + IDENTITY_BYTES + MEMO_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomMintStatement {
    pub network: [u8; 32],
    pub application: [u8; 32],
    /// Protocol key-type discriminant of the configured authority. Execution
    /// compares it and the key against the token's deployed mint strategy.
    pub authority_key_type: u32,
    /// Empty for a permissionless (free-payment) policy; then the signature
    /// must also be empty and `authority_key_type` zero.
    pub authority_public_key: Vec<u8>,
    /// Caller-chosen uniqueness. Execution derives the one-time receipt from
    /// the complete context, so two identical statements cannot both mint.
    pub nonce: [u8; 32],
    /// Public issuance total; every output must open to a share of it.
    pub amount: u128,
    pub outputs: Vec<Output>,
    /// Membership proof of this mint's entitlement in the token's configured
    /// entitlement root, for a proof-basis policy; empty for every other
    /// policy. Execution computes the leaf from the statement, so the proof
    /// binds the authority key and the amount.
    pub entitlement_proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomMint {
    pub statement: CustomMintStatement,
    pub signature: Vec<u8>,
    pub proof: Vec<u8>,
}

impl CustomMintStatement {
    pub fn is_permissionless(&self) -> bool {
        self.authority_public_key.is_empty()
    }

    /// The configured authority signs these exact bytes; the amount proof binds
    /// the same bytes. Signature and proof bytes are excluded to avoid a cycle.
    pub fn context_bytes(&self) -> Result<Vec<u8>, TransferError> {
        if self.outputs.is_empty() || self.outputs.len() > MAX_PRIVATE_COINS {
            return Err(TransferError::Dimensions);
        }
        if self.authority_public_key.len() > MAX_AUTHORITY_KEY_BYTES {
            return Err(TransferError::Length);
        }
        if self.amount == 0 || (self.is_permissionless() && self.authority_key_type != 0) {
            return Err(TransferError::Noncanonical);
        }
        if self.entitlement_proof.len() > MAX_ENTITLEMENT_PROOF_BYTES
            || self.entitlement_proof.len() % 33 != 0
            || (!self.entitlement_proof.is_empty() && self.is_permissionless())
        {
            return Err(TransferError::Noncanonical);
        }
        let len = HEADER_BYTES + self.authority_public_key.len() + self.entitlement_proof.len()
            + self.outputs.len() * OUTPUT_BYTES;
        if len + 2 + MAX_AUTHORITY_SIGNATURE_BYTES + 4 + 40 >= MAX_TRANSACTION_BYTES {
            return Err(TransferError::Length);
        }
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(&PREFIX);
        bytes.extend_from_slice(VERSION);
        bytes.extend_from_slice(&self.network);
        bytes.extend_from_slice(&self.application);
        bytes.extend_from_slice(&self.authority_key_type.to_le_bytes());
        bytes.extend_from_slice(&(self.authority_public_key.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&self.authority_public_key);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes.extend_from_slice(&(self.entitlement_proof.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&self.entitlement_proof);
        bytes.extend_from_slice(&(self.outputs.len() as u16).to_le_bytes());
        for output in &self.outputs {
            bytes.extend_from_slice(&output.commitment.to_bytes());
            bytes.extend_from_slice(&output.owner);
            bytes.extend_from_slice(&output.memo);
        }
        Ok(bytes)
    }

    pub fn public_relation(&self, max_outputs: usize) -> Result<PublicAmountRelation, TransferError> {
        if self.outputs.len() > max_outputs {
            return Err(TransferError::ResourceLimit);
        }
        let context = self.context_bytes()?;
        let key = CommitmentKey::derive(&parameter_context(&self.network, &self.application));
        let commitments: Vec<_> = self.outputs.iter().map(|o| o.commitment.clone()).collect();
        PublicAmountRelation::compile_issuance(&key, &commitments, self.amount, 0)
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
        CompiledAmountRelation::compile_issuance(&key, &coins, self.amount, 0)
            .map(|r| r.with_transaction_context(&context))
            .map_err(TransferError::Relation)
    }
}

impl CustomMint {
    pub fn encode(&self) -> Result<Vec<u8>, TransferError> {
        if self.proof.len() < 40 || self.proof.get(..8) != Some(PROOF_MAGIC.as_slice()) {
            return Err(TransferError::Noncanonical);
        }
        if self.signature.len() > MAX_AUTHORITY_SIGNATURE_BYTES
            || (self.statement.is_permissionless() != self.signature.is_empty())
        {
            return Err(TransferError::Noncanonical);
        }
        let mut bytes = self.statement.context_bytes()?;
        if bytes
            .len()
            .checked_add(2 + self.signature.len() + 4)
            .and_then(|n| n.checked_add(self.proof.len()))
            .filter(|&n| n < MAX_TRANSACTION_BYTES)
            .is_none()
        {
            return Err(TransferError::Length);
        }
        bytes.extend_from_slice(&(self.signature.len() as u16).to_le_bytes());
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
        let authority_key_type = u32::from_le_bytes(r.array()?);
        let key_len = u16::from_le_bytes(r.array()?) as usize;
        if key_len > MAX_AUTHORITY_KEY_BYTES {
            return Err(TransferError::Length);
        }
        let authority_public_key = r.take(key_len)?.to_vec();
        let nonce = r.array()?;
        let amount = u128::from_le_bytes(r.array()?);
        let entitlement_len = u16::from_le_bytes(r.array()?) as usize;
        if entitlement_len > MAX_ENTITLEMENT_PROOF_BYTES {
            return Err(TransferError::Length);
        }
        let entitlement_proof = r.take(entitlement_len)?.to_vec();
        let count = u16::from_le_bytes(r.array()?) as usize;
        if count == 0 || count > MAX_PRIVATE_COINS {
            return Err(TransferError::Dimensions);
        }
        if r.0.len() < count * OUTPUT_BYTES + 2 + 4 + 40 {
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
        let signature_len = u16::from_le_bytes(r.array()?) as usize;
        if signature_len > MAX_AUTHORITY_SIGNATURE_BYTES {
            return Err(TransferError::Length);
        }
        let signature = r.take(signature_len)?.to_vec();
        let len = u32::from_le_bytes(r.array()?) as usize;
        if len < 40 || len != r.0.len() || r.0.get(..8) != Some(PROOF_MAGIC.as_slice()) {
            return Err(TransferError::Length);
        }
        let statement = CustomMintStatement {
            network: encoded_network,
            application: encoded_application,
            authority_key_type,
            authority_public_key,
            nonce,
            amount,
            outputs,
            entitlement_proof,
        };
        statement.context_bytes()?;
        if statement.is_permissionless() != signature.is_empty() {
            return Err(TransferError::Noncanonical);
        }
        Ok(Self {
            statement,
            signature,
            proof: r.0.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::transfer::TARGET_TRANSACTION_BYTES;
    use super::*;

    fn fixture(authority: Vec<u8>, key_type: u32) -> (CustomMint, Vec<AmountOpening>, [u128; 2]) {
        let network = [1; 32];
        let application = [2; 32];
        let context = parameter_context(&network, &application);
        let key = CommitmentKey::derive(&context);
        let openings = vec![
            AmountOpening::from_seed(&context, &[3; 32]),
            AmountOpening::from_seed(&context, &[4; 32]),
        ];
        let amounts = [u128::MAX - 256, 256];
        let outputs = amounts
            .iter()
            .zip(&openings)
            .map(|(&a, r)| Output { commitment: key.commit(a, r), owner: [5; IDENTITY_BYTES], memo: [6; MEMO_BYTES] })
            .collect();
        let signature = if authority.is_empty() { Vec::new() } else { vec![7; 666] };
        // Framing/size fixture only: neither the signature nor the proof bytes
        // are valid cryptographic authorizations.
        let mut proof = vec![0; 149_928];
        proof[..8].copy_from_slice(PROOF_MAGIC);
        let tx = CustomMint {
            statement: CustomMintStatement {
                network,
                application,
                authority_key_type: key_type,
                authority_public_key: authority,
                entitlement_proof: Vec::new(),
                nonce: [8; 32],
                amount: u128::MAX,
                outputs,
            },
            signature,
            proof,
        };
        (tx, openings, amounts)
    }

    #[test]
    fn custom_mint_codec_binds_policy_nonce_outputs_and_bounds_the_payload() {
        let (tx, openings, amounts) = fixture(vec![9; 897], 8);
        let private = tx
            .statement
            .private_relation(&[(amounts[0], &openings[0]), (amounts[1], &openings[1])], 2)
            .unwrap();
        assert!(private.validate_local_witness());
        assert!(tx.statement.public_relation(2).is_ok());
        assert!(tx.statement.public_relation(1).is_err());
        let bytes = tx.encode().unwrap();
        assert_eq!(bytes.len(), 4 + 8 + 32 + 32 + 4 + 2 + 897 + 32 + 16 + 2 + 2 + 2 * OUTPUT_BYTES + 2 + 666 + 4 + 149_928);
        // An entitlement proof rides in the statement and binds the context.
        let mut entitled = tx.clone();
        entitled.statement.entitlement_proof = vec![1; 33 * 3];
        assert_ne!(entitled.statement.context_bytes().unwrap(), tx.statement.context_bytes().unwrap());
        let entitled_bytes = entitled.encode().unwrap();
        assert_eq!(entitled_bytes.len(), bytes.len() + 33 * 3);
        assert_eq!(CustomMint::decode(&entitled_bytes, &[1; 32], &[2; 32]).unwrap(), entitled);
        // A proof must be whole levels, bounded, and carried by an authorized
        // statement (a permissionless mint proves nothing).
        for proof in [vec![1; 32], vec![1; MAX_ENTITLEMENT_PROOF_BYTES + 33]] {
            let mut bad = tx.clone();
            bad.statement.entitlement_proof = proof;
            assert!(bad.encode().is_err());
        }
        assert!(bytes.len() < TARGET_TRANSACTION_BYTES);
        assert_eq!(&bytes[4..12], VERSION);
        assert_eq!(CustomMint::decode(&bytes, &[1; 32], &[2; 32]).unwrap(), tx);
        assert!(CustomMint::decode(&bytes, &[99; 32], &[2; 32]).is_err());
        assert!(CustomMint::decode(&bytes, &[1; 32], &[99; 32]).is_err());
        for end in [0, 4, 12, HEADER_BYTES - 1, bytes.len() - 1] {
            assert!(CustomMint::decode(&bytes[..end], &[1; 32], &[2; 32]).is_err());
        }
        let mut appended = bytes.clone();
        appended.push(0);
        assert!(CustomMint::decode(&appended, &[1; 32], &[2; 32]).is_err());
        // The reward-mint decoder must not accept custom issuance and vice versa.
        assert!(super::super::mint::Mint::decode(&bytes, &[1; 32], &[2; 32]).is_err());
        let original = tx.statement.context_bytes().unwrap();
        for field in 0..7 {
            let mut changed = tx.clone();
            match field {
                0 => changed.statement.nonce[0] ^= 1,
                1 => changed.statement.amount -= 1,
                2 => changed.statement.authority_public_key[0] ^= 1,
                3 => changed.statement.authority_key_type += 1,
                4 => changed.statement.outputs[0].memo[0] ^= 1,
                6 => changed.statement.entitlement_proof = vec![2; 33],
                _ => changed.statement.outputs[1].owner[0] ^= 1,
            }
            assert_ne!(changed.statement.context_bytes().unwrap(), original);
        }
        let mut changed = tx.clone();
        changed.statement.amount = 0;
        assert!(changed.encode().is_err());
        changed = tx.clone();
        changed.signature.clear();
        assert!(changed.encode().is_err()); // Configured authority requires a signature.
        changed = tx.clone();
        changed.signature = vec![0; MAX_AUTHORITY_SIGNATURE_BYTES + 1];
        assert!(changed.encode().is_err());
        changed = tx.clone();
        changed.statement.authority_public_key = vec![0; MAX_AUTHORITY_KEY_BYTES + 1];
        assert!(changed.encode().is_err());
        changed = tx.clone();
        changed.proof.resize(MAX_TRANSACTION_BYTES, 0);
        assert!(changed.encode().is_err());
        changed = tx.clone();
        changed.statement.outputs.clear();
        assert!(changed.encode().is_err());
    }

    #[test]
    fn permissionless_custom_mint_has_canonical_empty_authority() {
        let (tx, _, _) = fixture(Vec::new(), 0);
        assert!(tx.statement.is_permissionless());
        let bytes = tx.encode().unwrap();
        assert_eq!(CustomMint::decode(&bytes, &[1; 32], &[2; 32]).unwrap(), tx);
        let mut signed = tx.clone();
        signed.signature = vec![1; 114];
        assert!(signed.encode().is_err());
        let mut typed = tx.clone();
        typed.statement.authority_key_type = 8;
        assert!(typed.encode().is_err());
        // A signature smuggled after an empty authority must fail decoding.
        let mut spliced = bytes.clone();
        let sig_offset = HEADER_BYTES + 2 * OUTPUT_BYTES;
        spliced[sig_offset..sig_offset + 2].copy_from_slice(&1u16.to_le_bytes());
        spliced.insert(sig_offset + 2, 0);
        assert!(CustomMint::decode(&spliced, &[1; 32], &[2; 32]).is_err());
    }
}

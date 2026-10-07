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
/// A batch shield: many legacy coins of one owner (see `BATCH_SHIELD.md`).
const BATCH_VERSION: &[u8; 8] = b"QCT3SH\0\x03";
/// Fixed bytes of a batch statement, sources and outputs excluded.
const BATCH_HEADER_BYTES: usize = 4 + 8 + 32 + 32 + 57 + 2 + 16 + 2;
const SOURCE_BYTES: usize = 32 + 16;
/// Legacy coins one batch shield may consume: the most whose spend entry (32
/// bytes a consumption, beside up to 16 outputs) fits the relay's 4,096-byte
/// entry.
pub const MAX_SHIELD_SOURCES: usize = 96;

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

/// The (first) legacy coin a shield consumes, read from its encoding without
/// decoding the rest. Only the shard whose range holds that coin can verify
/// the shield, so routing sends the operation there.
pub fn source_address(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.get(..4)? != PREFIX {
        return None;
    }
    let version = bytes.get(4..12)?;
    if version == VERSION {
        // prefix ‖ version ‖ network(32) ‖ application(32) ‖ transparent address
        return bytes.get(76..108)?.try_into().ok();
    }
    if version == BATCH_VERSION {
        // prefix ‖ version ‖ network ‖ application ‖ owner key(57) ‖ count(2) ‖ first source
        return bytes.get(135..167)?.try_into().ok();
    }
    None
}

/// One legacy coin a batch shield consumes, with its public amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShieldSource {
    pub address: [u8; 32],
    pub amount: u128,
}

/// Many legacy coins of one owner moved into the confidential accumulator by
/// one signature and one issuance proof over their total. The proof does not
/// grow with the sources: their amounts are public.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchShieldStatement {
    pub network: [u8; 32],
    pub application: [u8; 32],
    pub owner_public_key: [u8; 57],
    /// Strictly ascending by address, 1 to [`MAX_SHIELD_SOURCES`].
    pub sources: Vec<ShieldSource>,
    pub fee: u128,
    pub outputs: Vec<Output>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchShield {
    pub statement: BatchShieldStatement,
    pub signature: [u8; 114],
    pub proof: Vec<u8>,
}

impl BatchShieldStatement {
    /// The sources' total, or an error if it overflows.
    pub fn total(&self) -> Result<u128, TransferError> {
        self.sources.iter().try_fold(0u128, |sum, source| sum.checked_add(source.amount))
            .ok_or(TransferError::Noncanonical)
    }

    /// The legacy owner signs these exact bytes, and the amount proof binds
    /// them: every source, its amount, the fee and every output.
    pub fn context_bytes(&self) -> Result<Vec<u8>, TransferError> {
        if self.outputs.is_empty() || self.outputs.len() > MAX_PRIVATE_COINS
            || self.sources.is_empty() || self.sources.len() > MAX_SHIELD_SOURCES
        {
            return Err(TransferError::Dimensions);
        }
        if !self.sources.windows(2).all(|pair| pair[0].address < pair[1].address) {
            return Err(TransferError::Noncanonical);
        }
        if self.fee > self.total()? {
            return Err(TransferError::Noncanonical);
        }
        let len = BATCH_HEADER_BYTES + self.sources.len() * SOURCE_BYTES + self.outputs.len() * OUTPUT_BYTES;
        if len + 114 + 4 + 40 >= MAX_TRANSACTION_BYTES {
            return Err(TransferError::Length);
        }
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(&PREFIX);
        bytes.extend_from_slice(BATCH_VERSION);
        bytes.extend_from_slice(&self.network);
        bytes.extend_from_slice(&self.application);
        bytes.extend_from_slice(&self.owner_public_key);
        bytes.extend_from_slice(&(self.sources.len() as u16).to_le_bytes());
        for source in &self.sources {
            bytes.extend_from_slice(&source.address);
            bytes.extend_from_slice(&source.amount.to_le_bytes());
        }
        bytes.extend_from_slice(&self.fee.to_le_bytes());
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
        PublicAmountRelation::compile_issuance(&key, &commitments, self.total()?, self.fee)
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
        CompiledAmountRelation::compile_issuance(&key, &coins, self.total()?, self.fee)
            .map(|r| r.with_transaction_context(&context))
            .map_err(TransferError::Relation)
    }
}

impl BatchShield {
    pub fn encode(&self) -> Result<Vec<u8>, TransferError> {
        if self.proof.len() < 40 || self.proof.get(..8) != Some(PROOF_MAGIC.as_slice()) {
            return Err(TransferError::Noncanonical);
        }
        let mut bytes = self.statement.context_bytes()?;
        if bytes.len().checked_add(114 + 4).and_then(|n| n.checked_add(self.proof.len()))
            .filter(|&n| n < MAX_TRANSACTION_BYTES).is_none()
        {
            return Err(TransferError::Length);
        }
        bytes.extend_from_slice(&self.signature);
        bytes.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.proof);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8], network: &[u8; 32], application: &[u8; 32]) -> Result<Self, TransferError> {
        if bytes.len() >= MAX_TRANSACTION_BYTES {
            return Err(TransferError::Length);
        }
        let mut r = Reader(bytes);
        if r.take(4)? != PREFIX || r.take(8)? != BATCH_VERSION {
            return Err(TransferError::Version);
        }
        let encoded_network = r.array()?;
        let encoded_application = r.array()?;
        if &encoded_network != network || &encoded_application != application {
            return Err(TransferError::Context);
        }
        let owner_public_key = r.array()?;
        let count = u16::from_le_bytes(r.array()?) as usize;
        if count == 0 || count > MAX_SHIELD_SOURCES {
            return Err(TransferError::Dimensions);
        }
        let mut sources = Vec::with_capacity(count);
        for _ in 0..count {
            sources.push(ShieldSource { address: r.array()?, amount: u128::from_le_bytes(r.array()?) });
        }
        let fee = u128::from_le_bytes(r.array()?);
        let outputs_count = u16::from_le_bytes(r.array()?) as usize;
        if outputs_count == 0 || outputs_count > MAX_PRIVATE_COINS {
            return Err(TransferError::Dimensions);
        }
        if r.0.len() < outputs_count * OUTPUT_BYTES + 114 + 4 + 40 {
            return Err(TransferError::Length);
        }
        let mut outputs = Vec::with_capacity(outputs_count);
        for _ in 0..outputs_count {
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
        let statement = BatchShieldStatement {
            network: encoded_network,
            application: encoded_application,
            owner_public_key,
            sources,
            fee,
            outputs,
        };
        statement.context_bytes()?;
        Ok(Self { statement, signature, proof: r.0.to_vec() })
    }
}

/// A shield of either encoding: one legacy coin (version 2) or a batch
/// (version 3). The version bytes select the decoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnyShield {
    Single(Shield),
    Batch(BatchShield),
}

impl AnyShield {
    pub fn decode(bytes: &[u8], network: &[u8; 32], application: &[u8; 32]) -> Result<Self, TransferError> {
        match bytes.get(4..12) {
            Some(version) if version == BATCH_VERSION => BatchShield::decode(bytes, network, application).map(Self::Batch),
            _ => Shield::decode(bytes, network, application).map(Self::Single),
        }
    }

    pub fn is_batch(&self) -> bool {
        matches!(self, Self::Batch(_))
    }

    pub fn owner_public_key(&self) -> &[u8; 57] {
        match self {
            Self::Single(s) => &s.statement.owner_public_key,
            Self::Batch(b) => &b.statement.owner_public_key,
        }
    }

    /// Every legacy coin consumed, ascending for a batch.
    pub fn sources(&self) -> Vec<ShieldSource> {
        match self {
            Self::Single(s) => vec![ShieldSource { address: s.statement.transparent_address, amount: s.statement.amount }],
            Self::Batch(b) => b.statement.sources.clone(),
        }
    }

    pub fn fee(&self) -> u128 {
        match self {
            Self::Single(s) => s.statement.fee,
            Self::Batch(b) => b.statement.fee,
        }
    }

    pub fn outputs(&self) -> &[Output] {
        match self {
            Self::Single(s) => &s.statement.outputs,
            Self::Batch(b) => &b.statement.outputs,
        }
    }

    /// The bytes the owner signed.
    pub fn context_bytes(&self) -> Result<Vec<u8>, TransferError> {
        match self {
            Self::Single(s) => s.statement.context_bytes(),
            Self::Batch(b) => b.statement.context_bytes(),
        }
    }

    pub fn public_relation(&self, max_outputs: usize) -> Result<PublicAmountRelation, TransferError> {
        match self {
            Self::Single(s) => s.statement.public_relation(max_outputs),
            Self::Batch(b) => b.statement.public_relation(max_outputs),
        }
    }

    pub fn signature(&self) -> &[u8; 114] {
        match self {
            Self::Single(s) => &s.signature,
            Self::Batch(b) => &b.signature,
        }
    }

    pub fn proof(&self) -> &[u8] {
        match self {
            Self::Single(s) => &s.proof,
            Self::Batch(b) => &b.proof,
        }
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
        // Routing reads the source without decoding the rest.
        assert_eq!(source_address(&bytes), Some(shield.statement.transparent_address));
        assert_eq!(source_address(&bytes[..107]), None);
        let mut other = bytes.clone();
        other[11] = 0x09;
        assert_eq!(source_address(&other), None, "an unknown version");
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

    fn batch(sources: Vec<ShieldSource>, fee: u128) -> BatchShield {
        let (network, application) = ([1; 32], [2; 32]);
        let context = parameter_context(&network, &application);
        let key = CommitmentKey::derive(&context);
        let opening = AmountOpening::from_seed(&context, &[3; 32]);
        let mut proof = vec![0; 64];
        proof[..8].copy_from_slice(PROOF_MAGIC);
        BatchShield {
            statement: BatchShieldStatement {
                network,
                application,
                owner_public_key: [4; 57],
                sources,
                fee,
                outputs: vec![Output { commitment: key.commit(5, &opening), owner: [6; IDENTITY_BYTES], memo: [7; MEMO_BYTES] }],
            },
            signature: [8; 114],
            proof,
        }
    }

    fn sources(n: usize) -> Vec<ShieldSource> {
        (0..n).map(|i| {
            let mut address = [0u8; 32];
            address[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
            ShieldSource { address, amount: 1_000 + i as u128 }
        }).collect()
    }

    #[test]
    fn batch_shield_codec_binds_every_source_and_bounds_them() {
        let shield = batch(sources(MAX_SHIELD_SOURCES), 7);
        assert_eq!(shield.statement.total().unwrap(), (0..96u128).map(|i| 1_000 + i).sum::<u128>());
        let bytes = shield.encode().unwrap();
        assert_eq!(BatchShield::decode(&bytes, &[1; 32], &[2; 32]).unwrap(), shield);
        assert!(BatchShield::decode(&bytes, &[9; 32], &[2; 32]).is_err());
        match AnyShield::decode(&bytes, &[1; 32], &[2; 32]).unwrap() {
            AnyShield::Batch(decoded) => assert_eq!(decoded, shield),
            AnyShield::Single(_) => panic!("version 3 decodes as a batch"),
        }
        let any = AnyShield::Batch(shield.clone());
        assert_eq!(any.sources(), shield.statement.sources);
        assert_eq!((any.fee(), any.outputs().len(), any.proof().len()), (7, 1, 64));
        assert!(Shield::decode(&bytes, &[1; 32], &[2; 32]).is_err(), "a batch is not a single shield");
        // Routing reads the first source.
        assert_eq!(source_address(&bytes), Some(shield.statement.sources[0].address));
        for end in [0, 12, 134, 166, bytes.len() - 1] {
            assert!(BatchShield::decode(&bytes[..end], &[1; 32], &[2; 32]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(BatchShield::decode(&trailing, &[1; 32], &[2; 32]).is_err());

        // Every source and amount is signed and proven over.
        let original = shield.statement.context_bytes().unwrap();
        let mut changed = shield.clone();
        changed.statement.sources[50].amount += 1;
        assert_ne!(changed.statement.context_bytes().unwrap(), original);
        changed = shield.clone();
        changed.statement.sources[95].address[31] ^= 1;
        assert_ne!(changed.statement.context_bytes().unwrap(), original);

        // Bounds: 1 to 96 sources, strictly ascending, a total that fits and
        // covers the fee.
        assert_eq!(batch(sources(MAX_SHIELD_SOURCES + 1), 0).encode(), Err(TransferError::Dimensions));
        assert_eq!(batch(Vec::new(), 0).encode(), Err(TransferError::Dimensions));
        let mut unsorted = sources(3);
        unsorted.swap(0, 1);
        assert_eq!(batch(unsorted, 0).encode(), Err(TransferError::Noncanonical));
        let mut repeated = sources(3);
        repeated[2] = repeated[1];
        assert_eq!(batch(repeated, 0).encode(), Err(TransferError::Noncanonical));
        let mut huge = sources(2);
        huge[0].amount = u128::MAX;
        assert_eq!(batch(huge, 0).encode(), Err(TransferError::Noncanonical), "the total overflows");
        assert_eq!(batch(sources(2), 2_002).encode(), Err(TransferError::Noncanonical), "the fee exceeds the total");
        assert!(batch(sources(2), 2_001).encode().is_ok(), "the fee may take the whole total");
        // A one-source batch is still version 3.
        let one = batch(sources(1), 0).encode().unwrap();
        assert!(matches!(AnyShield::decode(&one, &[1; 32], &[2; 32]).unwrap(), AnyShield::Batch(_)));
    }
}

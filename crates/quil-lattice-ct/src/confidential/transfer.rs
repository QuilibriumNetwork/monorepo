//! Ordinary-transfer encoding. No execution admission is implied.
//! The complete proof-excluding encoding is the proof's transaction context.
//! Memos are fixed-size opaque ciphertexts; delivery, memo suite,
//! root admission and spent-image checks are not performed here.

use super::{
    relation::{
        membership::{InputPath, MembershipKey, MembershipStatement, Node, MAX_DEPTH, NODE_BYTES},
        CompiledAmountRelation, PublicAmountRelation,
    },
    *,
};
use super::relation::membership::IDENTITY_BYTES;
use std::collections::BTreeSet;

pub const MAX_TRANSACTION_BYTES: usize = 1 << 20;
pub const TARGET_TRANSACTION_BYTES: usize = 256 << 10;
pub const MEMO_BYTES: usize = 1115;
const PREFIX: [u8; 4] = 0x0512u32.to_be_bytes();
const VERSION: &[u8; 8] = b"QCT3TX\0\x02";
const PROOF_MAGIC: &[u8; 8] = b"QPF6\0\0\0\0";

#[derive(Debug, PartialEq, Eq)]
pub enum TransferError {
    Length,
    Version,
    Dimensions,
    ResourceLimit,
    DuplicateImage,
    Noncanonical,
    Context,
    Relation(TokenError),
}

/// Caller-selected circuit dimensions, checked before relation construction.
/// These are count limits, not a bound on process memory or native allocations.
/// There is deliberately no default admission policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompileLimits {
    pub max_inputs: usize,
    pub max_outputs: usize,
    pub max_depth: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub commitment: AmountCommitment,
    pub owner: [u8; IDENTITY_BYTES],
    pub memo: [u8; MEMO_BYTES],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferStatement {
    pub network: [u8; 32],
    pub application: [u8; 32],
    pub depth: u8,
    pub root: Node,
    pub images: Vec<[u8; IDENTITY_BYTES]>,
    pub outputs: Vec<Output>,
    pub fee: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub statement: TransferStatement,
    pub proof: Vec<u8>,
}

/// Canonical 32-byte identifier for the node's configured u8 network selector.
/// Big-endian zero extension is injective across all supported selectors.
pub const fn network_identifier(network: u8) -> [u8; 32] {
    let mut id = [0; 32];
    id[31] = network;
    id
}

/// Stable suite parameters for wallet, execution and stored-coin decoding.
pub fn parameter_context(network: &[u8; 32], application: &[u8; 32]) -> [u8; 32] {
    let mut hash = Shake256::default();
    hash.update(b"quil/token/transfer-parameters/v2\0");
    hash.update(network);
    hash.update(application);
    let mut result = [0; 32];
    hash.finalize_xof().read(&mut result);
    result
}

impl TransferStatement {
    fn check_compile_limits(&self, limits: CompileLimits) -> Result<(), TransferError> {
        if self.images.len() > limits.max_inputs
            || self.outputs.len() > limits.max_outputs
            || usize::from(self.depth) > limits.max_depth
        {
            return Err(TransferError::ResourceLimit);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), TransferError> {
        if self.depth == 0
            || usize::from(self.depth) > MAX_DEPTH
            || self.images.is_empty()
            || self.images.len() > MAX_PRIVATE_COINS
            || self.outputs.is_empty()
            || self.outputs.len() > MAX_PRIVATE_COINS
        {
            return Err(TransferError::Dimensions);
        }
        if self.images.iter().collect::<BTreeSet<_>>().len() != self.images.len() {
            return Err(TransferError::DuplicateImage);
        }
        Ok(())
    }

    /// Stable coin parameters per network/application, independent of a spend's
    /// fee, root, memos or recipients. Coins remain usable in later transfers.
    pub fn parameter_context(&self) -> [u8; 32] {
        parameter_context(&self.network, &self.application)
    }

    /// Canonical signed/proved bytes, including the operation and suite marker.
    /// Proof length and proof bytes are excluded to avoid circular dependence.
    pub fn context_bytes(&self) -> Result<Vec<u8>, TransferError> {
        self.validate()?;
        let size = 4
            + 8
            + 64
            + 1
            + 4
            + 16
            + NODE_BYTES
            + self.images.len() * IDENTITY_BYTES
            + self.outputs.len() * (COMMITMENT_BYTES + IDENTITY_BYTES + MEMO_BYTES);
        if size + 4 + 40 >= MAX_TRANSACTION_BYTES {
            return Err(TransferError::Length);
        }
        let mut bytes = Vec::with_capacity(size);
        bytes.extend_from_slice(&PREFIX);
        bytes.extend_from_slice(VERSION);
        bytes.extend_from_slice(&self.network);
        bytes.extend_from_slice(&self.application);
        bytes.push(self.depth);
        bytes.extend_from_slice(&(self.images.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(self.outputs.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&self.fee.to_le_bytes());
        bytes.extend_from_slice(&self.root.to_bytes());
        for image in &self.images {
            bytes.extend_from_slice(image);
        }
        for output in &self.outputs {
            bytes.extend_from_slice(&output.commitment.to_bytes());
            bytes.extend_from_slice(&output.owner);
            bytes.extend_from_slice(&output.memo);
        }
        debug_assert_eq!(bytes.len(), size);
        Ok(bytes)
    }

    /// Reconstruct the proof relation from exactly the decoded public fields.
    /// The caller must also enforce admitted roots and unspent input images.
    pub fn public_relation(
        &self,
        limits: CompileLimits,
    ) -> Result<PublicAmountRelation, TransferError> {
        self.check_compile_limits(limits)?;
        let bytes = self.context_bytes()?;
        let context = self.parameter_context();
        let key = CommitmentKey::derive(&context);
        let membership_key = MembershipKey::derive(&context);
        let images: Result<Vec<_>, _> = self
            .images
            .iter()
            .map(|i| Node::from_identity_bytes(i))
            .collect();
        let images = images.map_err(TransferError::Relation)?;
        let commitments: Vec<_> = self.outputs.iter().map(|o| o.commitment.clone()).collect();
        let statement = MembershipStatement {
            root: &self.root,
            key_images: &images,
            depth: usize::from(self.depth),
        };
        PublicAmountRelation::compile_with_membership(
            &key,
            &membership_key,
            &commitments,
            0,
            self.fee,
            &statement,
        )
        .map(|relation| relation.with_transaction_context(&bytes))
        .map_err(TransferError::Relation)
    }

    /// Compile the wallet's private witness against these finalized public
    /// outputs and memos. Input count, amounts, openings, ownership, root and
    /// images are validated by the shared relation compiler.
    pub fn private_relation(
        &self,
        inputs: &[(u128, &AmountOpening, &AmountCommitment)],
        output_openings: &[(u128, &AmountOpening)],
        paths: &[InputPath<'_>],
        limits: CompileLimits,
    ) -> Result<CompiledAmountRelation, TransferError> {
        self.check_compile_limits(limits)?;
        if inputs.len() != self.images.len()
            || output_openings.len() != self.outputs.len()
            || paths.len() != self.images.len()
        {
            return Err(TransferError::Dimensions);
        }
        let bytes = self.context_bytes()?;
        let context = self.parameter_context();
        let key = CommitmentKey::derive(&context);
        let membership_key = MembershipKey::derive(&context);
        let images: Result<Vec<_>, _> = self
            .images
            .iter()
            .map(|i| Node::from_identity_bytes(i))
            .collect();
        let images = images.map_err(TransferError::Relation)?;
        let outputs: Vec<_> = output_openings
            .iter()
            .zip(&self.outputs)
            .map(|(&(amount, opening), output)| (amount, opening, &output.commitment))
            .collect();
        let statement = MembershipStatement {
            root: &self.root,
            key_images: &images,
            depth: usize::from(self.depth),
        };
        CompiledAmountRelation::compile_with_membership(
            &key,
            &membership_key,
            inputs,
            &outputs,
            0,
            self.fee,
            &statement,
            paths,
        )
        .map(|relation| relation.with_transaction_context(&bytes))
        .map_err(TransferError::Relation)
    }
}

impl Transfer {
    pub fn encode(&self) -> Result<Vec<u8>, TransferError> {
        if self.proof.len() < 40 || self.proof.get(..8) != Some(PROOF_MAGIC.as_slice()) {
            return Err(TransferError::Noncanonical);
        }
        let mut bytes = self.statement.context_bytes()?;
        if bytes
            .len()
            .checked_add(4)
            .and_then(|n| n.checked_add(self.proof.len()))
            .filter(|&n| n < MAX_TRANSACTION_BYTES)
            .is_none()
        {
            return Err(TransferError::Length);
        }
        bytes.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.proof);
        Ok(bytes)
    }

    /// Checks the envelope and canonical public coefficients, not proof validity.
    /// Expected domains come from the node/wallet, never from the transaction.
    pub fn decode(
        bytes: &[u8],
        network: &[u8; 32],
        application: &[u8; 32],
    ) -> Result<Self, TransferError> {
        if bytes.len() >= MAX_TRANSACTION_BYTES {
            return Err(TransferError::Length);
        }
        let mut reader = Reader(bytes);
        if reader.take(4)? != PREFIX || reader.take(8)? != VERSION {
            return Err(TransferError::Version);
        }
        let encoded_network = reader.array()?;
        let encoded_application = reader.array()?;
        if &encoded_network != network || &encoded_application != application {
            return Err(TransferError::Context);
        }
        let depth = reader.array::<1>()?[0];
        let inputs = u16::from_le_bytes(reader.array()?) as usize;
        let outputs = u16::from_le_bytes(reader.array()?) as usize;
        if depth == 0
            || usize::from(depth) > MAX_DEPTH
            || inputs == 0
            || inputs > MAX_PRIVATE_COINS
            || outputs == 0
            || outputs > MAX_PRIVATE_COINS
        {
            return Err(TransferError::Dimensions);
        }
        let fee = u128::from_le_bytes(reader.array()?);
        let root =
            Node::from_bytes(reader.take(NODE_BYTES)?).map_err(|_| TransferError::Noncanonical)?;
        // Count-derived lower bound is checked before allocating the vectors.
        let required = inputs * IDENTITY_BYTES + outputs * (COMMITMENT_BYTES + IDENTITY_BYTES + MEMO_BYTES) + 4 + 40;
        if reader.0.len() < required {
            return Err(TransferError::Length);
        }
        let images = (0..inputs)
            .map(|_| {
                let image: [u8; IDENTITY_BYTES] = reader.array()?;
                // Key images are canonical rank-1 identities; reject early.
                Node::from_identity_bytes(&image).map_err(|_| TransferError::Noncanonical)?;
                Ok(image)
            })
            .collect::<Result<Vec<_>, TransferError>>()?;
        let mut decoded_outputs = Vec::with_capacity(outputs);
        for _ in 0..outputs {
            decoded_outputs.push(Output {
                commitment: AmountCommitment::from_bytes(reader.take(COMMITMENT_BYTES)?)
                    .map_err(|_| TransferError::Noncanonical)?,
                owner: reader.array()?,
                memo: reader.array()?,
            });
        }
        let proof_len = u32::from_le_bytes(reader.array()?) as usize;
        if proof_len < 40
            || proof_len != reader.0.len()
            || reader.0.get(..8) != Some(PROOF_MAGIC.as_slice())
        {
            return Err(TransferError::Length);
        }
        let statement = TransferStatement {
            network: encoded_network,
            application: encoded_application,
            depth,
            root,
            images,
            outputs: decoded_outputs,
            fee,
        };
        statement.validate()?;
        Ok(Self {
            statement,
            proof: reader.0.to_vec(),
        })
    }
}

pub(super) struct Reader<'a>(pub(super) &'a [u8]);
impl<'a> Reader<'a> {
    pub(super) fn take(&mut self, count: usize) -> Result<&'a [u8], TransferError> {
        let result = self.0.get(..count).ok_or(TransferError::Length)?;
        self.0 = &self.0[count..];
        Ok(result)
    }
    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], TransferError> {
        self.take(N)?.try_into().map_err(|_| TransferError::Length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const LIMITS: CompileLimits = CompileLimits {
        max_inputs: 2,
        max_outputs: 2,
        max_depth: 32,
    };

    #[test]
    fn rejects_compile_dimensions_before_witness_or_circuit_construction() {
        let tx = fixture(8);
        for limits in [
            CompileLimits {
                max_inputs: 1,
                ..LIMITS
            },
            CompileLimits {
                max_outputs: 1,
                ..LIMITS
            },
            CompileLimits {
                max_depth: 7,
                ..LIMITS
            },
        ] {
            assert!(matches!(
                tx.statement.public_relation(limits),
                Err(TransferError::ResourceLimit)
            ));
            assert!(matches!(
                tx.statement.private_relation(&[], &[], &[], limits),
                Err(TransferError::ResourceLimit)
            ));
        }
        assert!(tx
            .statement
            .check_compile_limits(CompileLimits {
                max_depth: 8,
                ..LIMITS
            })
            .is_ok());
        assert!(matches!(
            tx.statement.private_relation(&[], &[], &[], LIMITS),
            Err(TransferError::Dimensions)
        ));
    }

    fn fixture(depth: u8) -> Transfer {
        let key = CommitmentKey::derive(&[3; 32]);
        let outputs = (0..2)
            .map(|i| Output {
                commitment: key.commit(
                    10 + u128::from(i),
                    &AmountOpening::from_seed(&[3; 32], &[i + 1; 32]),
                ),
                owner: [i + 1; IDENTITY_BYTES],
                memo: [i + 2; MEMO_BYTES],
            })
            .collect();
        // Framing-only fixture: these bytes are not a valid cryptographic proof.
        let mut proof = vec![0; 170_600];
        proof[..8].copy_from_slice(PROOF_MAGIC);
        Transfer {
            statement: TransferStatement {
                network: [1; 32],
                application: [2; 32],
                depth,
                root: Node::zero(),
                images: vec![[1; IDENTITY_BYTES], [2; IDENTITY_BYTES]],
                outputs,
                fee: 2,
            },
            proof,
        }
    }
    #[test]
    fn retired_native_proof_version_is_rejected() {
        for magic in [b"QPF1\0\0\0\0", b"QPF2\0\0\0\0", b"QPF3\0\0\0\0"] {
            let mut tx=fixture(1);
            tx.proof[..8].copy_from_slice(magic);
            assert!(tx.encode().is_err());
        }
    }
    #[test]
    fn wallet_relation_uses_finalized_transfer_parameters_and_public_amounts() {
        use super::super::relation::membership::{NoteSecrets, RecipientSecret};
        let mut tx = fixture(1);
        let context = tx.statement.parameter_context();
        let key = CommitmentKey::derive(&context);
        let membership_key = MembershipKey::derive(&context);
        let input = NoteSecrets::from_seeds(
            &context,
            &RecipientSecret::from_seed(&context, &[99; 32]),
            &[7; 32],
        );
        let output = NoteSecrets::from_seeds(
            &context,
            &RecipientSecret::from_seed(&context, &[99; 32]),
            &[8; 32],
        );
        let input_commitment = key.commit(7, &input.opening);
        let tree = super::super::coin_tree::CoinTree::build(
            &context,
            &[super::super::coin_tree::CoinRecord {
                address: [1; 32],
                owner: membership_key
                    .owner_key(&input.owner)
                    .identity_bytes()
                    .unwrap(),
                commitment: input_commitment.clone(),
                position: 0,
            }],
            1,
            4,
        )
        .unwrap();
        let auth = tree.auth_path(&[1; 32], 1).unwrap();
        let siblings = auth.siblings;
        let directions = auth.right;
        tx.statement.root = tree.root_at_depth(1).unwrap().root;
        tx.statement.images = vec![membership_key
            .key_image(&input.owner)
            .identity_bytes()
            .unwrap()];
        tx.statement.outputs = vec![Output {
            commitment: key.commit(6, &output.opening),
            owner: membership_key
                .owner_key(&output.owner)
                .identity_bytes()
                .unwrap(),
            memo: [0; MEMO_BYTES],
        }];
        tx.statement.fee = 1;
        let inputs = [(7, &input.opening, &input_commitment)];
        let outputs = [(6, &output.opening)];
        let paths = [InputPath {
            owner: &input.owner,
            siblings: &siblings,
            right: &directions,
        }];
        let private = tx
            .statement
            .private_relation(&inputs, &outputs, &paths, LIMITS)
            .unwrap();
        assert!(private.validate_local_witness());
        assert!(tx.statement.public_relation(LIMITS).is_ok());
        tx.statement.fee = 2;
        assert!(matches!(
            tx.statement
                .private_relation(&inputs, &outputs, &paths, LIMITS),
            Err(TransferError::Relation(TokenError::Unbalanced))
        ));
        tx.statement.fee = 1;
        tx.statement.network[0] ^= 1;
        assert!(tx
            .statement
            .private_relation(&inputs, &outputs, &paths, LIMITS)
            .is_err());
    }
    #[test]
    fn complete_framing_size_and_roundtrip() {
        for depth in [8, 16, 32] {
            let tx = fixture(depth);
            let bytes = tx.encode().unwrap();
            assert_eq!(bytes.len(), 213_123);
            assert!(bytes.len() <= TARGET_TRANSACTION_BYTES);
            assert_eq!(Transfer::decode(&bytes, &[1; 32], &[2; 32]).unwrap(), tx);
            assert_eq!(
                &bytes[..bytes.len() - tx.proof.len() - 4],
                tx.statement.context_bytes().unwrap()
            );
        }
    }
    #[test]
    fn rejects_bad_counts_domains_versions_coefficients_and_framing() {
        let tx = fixture(8);
        let encoded = tx.encode().unwrap();
        let reject = |b: &[u8]| assert!(Transfer::decode(b, &[1; 32], &[2; 32]).is_err());
        for len in [0, 3, 11, 76, 97, 7009, encoded.len() - 1] {
            reject(&encoded[..len]);
        }
        for index in [0, 4, 12, 44] {
            let mut bytes = encoded.clone();
            bytes[index] ^= 1;
            reject(&bytes);
        }
        for depth in [0, 33, 255] {
            let mut bytes = encoded.clone();
            bytes[76] = depth;
            reject(&bytes);
        }
        for offset in [77, 79] {
            for count in [0u16, 129, u16::MAX] {
                let mut bytes = encoded.clone();
                bytes[offset..offset + 2].copy_from_slice(&count.to_le_bytes());
                reject(&bytes);
            }
        }
        // Root and first key image (38-bit proof-ring packing) and first output
        // commitment (36-bit packing): each is a decoded canonical polynomial
        // field, so an out-of-range first coefficient is rejected.
        for offset in [97, 97 + NODE_BYTES] {
            let mut bytes = encoded.clone();
            bytes[offset..offset + 5].copy_from_slice(&crate::rp::P.to_le_bytes()[..5]);
            reject(&bytes);
        }
        let mut bytes = encoded.clone();
        let offset = 97 + NODE_BYTES + 2 * IDENTITY_BYTES;
        bytes[offset..offset + 9].copy_from_slice(&(u128::from(Poly::Q)).to_le_bytes()[..9]);
        reject(&bytes);
        let mut duplicate = tx.clone();
        duplicate.statement.images[1] = duplicate.statement.images[0];
        assert_eq!(duplicate.encode(), Err(TransferError::DuplicateImage));
        let mut bytes = encoded.clone();
        bytes[97 + NODE_BYTES + IDENTITY_BYTES..97 + NODE_BYTES + 2 * IDENTITY_BYTES].copy_from_slice(&[1; IDENTITY_BYTES]);
        reject(&bytes);
        let mut bytes = encoded.clone();
        bytes.push(0);
        reject(&bytes);
        let mut bytes = encoded.clone();
        let length_offset = bytes.len() - tx.proof.len() - 4;
        bytes[length_offset..length_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        reject(&bytes);
    }
    #[test]
    fn strict_total_limit_and_context_cover_all_mutable_fields() {
        let mut tx = fixture(8);
        let context = tx.statement.context_bytes().unwrap();
        let parameters = tx.statement.parameter_context();
        tx.proof
            .resize(MAX_TRANSACTION_BYTES - 1 - context.len() - 4, 0);
        let bytes = tx.encode().unwrap();
        assert_eq!(bytes.len(), MAX_TRANSACTION_BYTES - 1);
        assert!(Transfer::decode(&bytes, &[1; 32], &[2; 32]).is_ok());
        tx.proof.push(0);
        assert_eq!(tx.encode(), Err(TransferError::Length));
        let original = tx.statement;
        let mut variants = vec![original.clone(); 8];
        variants[0].network[0] ^= 1;
        variants[1].application[0] ^= 1;
        variants[2].depth += 1;
        variants[3].fee += 1;
        variants[4].images[0][0] ^= 1;
        variants[5].outputs[0].owner[0] ^= 1;
        variants[6].outputs[0].memo[0] ^= 1;
        variants[7].outputs.swap(0, 1);
        for (i, variant) in variants.iter().enumerate() {
            assert_ne!(variant.context_bytes().unwrap(), context);
            if i >= 2 {
                assert_eq!(variant.parameter_context(), parameters);
            } else {
                assert_ne!(variant.parameter_context(), parameters);
            }
        }
    }
}

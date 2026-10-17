//! Funding envelope for one escrow plus optional change coins.
//! The first funding output is exclusively the escrow commitment/recovery
//! record. Execution must not insert it into the ordinary coin accumulator.
use super::{
    memo::EscrowRecoveryMemo,
    mint::FALCON_PUBLIC_BYTES,
    pending_claim::EscrowPolicy,
    relation::{membership::InputPath, CompiledAmountRelation, PublicAmountRelation},
    transfer::{CompileLimits, Output, Reader, Transfer, TransferError, TransferStatement, MAX_TRANSACTION_BYTES, MEMO_BYTES},
    AmountCommitment, AmountOpening,
};
use super::relation::membership::IDENTITY_BYTES;

const PREFIX: [u8; 4] = 0x0514u32.to_be_bytes();
const VERSION: &[u8; 8] = b"QCT3PE\0\x02";
pub const PENDING_HEADER_BYTES: usize = 4 + 8 + 32 + 32 + 2 * FALCON_PUBLIC_BYTES + 8 + IDENTITY_BYTES + MEMO_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingCreateStatement {
    pub funding: TransferStatement,
    pub policy: EscrowPolicy,
    pub refund_recovery: EscrowRecoveryMemo,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingCreate {
    pub statement: PendingCreateStatement,
    pub proof: Vec<u8>,
}

impl PendingCreateStatement {
    /// The escrow output must become a typed pending record. Only the remaining
    /// outputs are ordinary change coins. Both groups are covered by conservation.
    pub fn split_outputs(&self) -> Result<(&Output, &[Output]), TransferError> {
        self.funding.outputs.split_first().ok_or(TransferError::Dimensions)
    }

    fn header_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PENDING_HEADER_BYTES);
        bytes.extend_from_slice(&PREFIX);
        bytes.extend_from_slice(VERSION);
        bytes.extend_from_slice(&self.funding.network);
        bytes.extend_from_slice(&self.funding.application);
        bytes.extend_from_slice(&self.policy.recipient);
        bytes.extend_from_slice(&self.policy.refund);
        bytes.extend_from_slice(&self.policy.refund_after_global_frame.to_le_bytes());
        bytes.extend_from_slice(&self.refund_recovery.owner);
        bytes.extend_from_slice(&self.refund_recovery.ciphertext);
        debug_assert_eq!(bytes.len(), PENDING_HEADER_BYTES);
        bytes
    }

    /// Canonical proof-excluding context includes all funding fields and both
    /// recovery records. The recipient recovery is in the first funding output.
    pub fn context_bytes(&self) -> Result<Vec<u8>, TransferError> {
        self.split_outputs()?;
        let funding = self.funding.context_bytes()?;
        if PENDING_HEADER_BYTES + funding.len() + 4 + 40 >= MAX_TRANSACTION_BYTES {
            return Err(TransferError::Length);
        }
        let mut bytes = self.header_bytes();
        bytes.extend_from_slice(&funding);
        Ok(bytes)
    }

    pub fn public_relation(&self, limits: CompileLimits) -> Result<PublicAmountRelation, TransferError> {
        let context = self.context_bytes()?;
        self.funding.public_relation(limits).map(|r| r.with_transaction_context(&context))
    }

    pub fn private_relation(
        &self,
        inputs: &[(u128, &AmountOpening, &AmountCommitment)],
        output_openings: &[(u128, &AmountOpening)],
        paths: &[InputPath<'_>],
        limits: CompileLimits,
    ) -> Result<CompiledAmountRelation, TransferError> {
        let context = self.context_bytes()?;
        self.funding.private_relation(inputs, output_openings, paths, limits)
            .map(|r| r.with_transaction_context(&context))
    }
}

impl PendingCreate {
    pub fn encode(&self) -> Result<Vec<u8>, TransferError> {
        if self.proof.len() < 40 || self.proof.len() >= MAX_TRANSACTION_BYTES || &self.proof[..8] != b"QPF6\0\0\0\0" {
            return Err(TransferError::Length);
        }
        let mut bytes = self.statement.context_bytes()?;
        if bytes.len() + 4 + self.proof.len() >= MAX_TRANSACTION_BYTES { return Err(TransferError::Length); }
        bytes.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.proof);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8], network: &[u8; 32], application: &[u8; 32]) -> Result<Self, TransferError> {
        if bytes.len() >= MAX_TRANSACTION_BYTES { return Err(TransferError::Length); }
        let mut r = Reader(bytes);
        if r.take(4)? != PREFIX || r.take(8)? != VERSION { return Err(TransferError::Version); }
        if r.take(32)? != network || r.take(32)? != application { return Err(TransferError::Context); }
        let policy = EscrowPolicy { recipient: r.array()?, refund: r.array()?, refund_after_global_frame: u64::from_le_bytes(r.array()?) };
        let refund_recovery = EscrowRecoveryMemo { owner: r.array()?, ciphertext: r.array()? };
        // Transfer decoding rechecks the inner domains, counts, canonical ring
        // coefficients, proof framing, and absence of trailing bytes.
        let funding = Transfer::decode(r.0, network, application)?;
        Ok(Self { statement: PendingCreateStatement { funding: funding.statement, policy, refund_recovery }, proof: funding.proof })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::{CommitmentKey, relation::membership::{Node, NODE_BYTES}};

    #[cfg(feature = "native-proof")]
    #[test]
    #[ignore = "explicit native proving and payload measurement task"]
    fn native_pending_creation_roundtrip() {
        use crate::confidential::{
            address::RecipientAddress,
            coin_tree::{CoinRecord, CoinTree},
            memo::{create_escrow_recovery, create_output, open_escrow_recovery, open_output},
            relation::{backend::native::{self, NativeBudget}, membership::{MembershipKey, RecipientSecret}},
            transfer::{parameter_context, TARGET_TRANSACTION_BYTES},
        };
        use pqcrypto_ntruprime::sntrup761;
        use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};

        let started = std::time::Instant::now();
        let network = [121; 32];
        let application = [122; 32];
        let context = parameter_context(&network, &application);
        let make_recipient = |seed| {
            let recipient = RecipientSecret::from_seed(&context, &[seed; 32]);
            let (public, secret) = sntrup761::keypair();
            let address = RecipientAddress::new(&context, &recipient, public.as_bytes()).unwrap();
            (recipient, secret, address)
        };
        let (sender, sender_kem, sender_address) = make_recipient(123);
        let (recipient, recipient_kem, recipient_address) = make_recipient(124);
        let (refund, refund_kem, refund_address) = make_recipient(125);
        // Exercise full-width conservation, including a sum above u128::MAX.
        let created_inputs: Vec<_> = [u128::MAX, 257].into_iter()
            .map(|amount| create_output(&context, &sender_address, amount).unwrap()).collect();
        let notes: Vec<_> = created_inputs.iter().map(|created|
            open_output(&context, sender_kem.as_bytes(), &sender, &created.output).unwrap()).collect();
        let coins: Vec<_> = created_inputs.iter().enumerate().map(|(i, created)| CoinRecord {
            address: [i as u8; 32], owner: created.output.owner,
            commitment: created.output.commitment.clone(), position: i as u64,
        }).collect();
        let tree = CoinTree::build(&context, &coins, 1, 16).unwrap();
        let root = tree.root_at_depth(1).unwrap();
        let auth: Vec<_> = coins.iter().map(|coin| tree.auth_path(&coin.address, 1).unwrap()).collect();
        let paths: Vec<_> = notes.iter().zip(&auth).map(|(note, path)| InputPath {
            owner: &note.secrets.owner, siblings: &path.siblings, right: &path.right,
        }).collect();
        let inputs: Vec<_> = notes.iter().zip(&coins).map(|(note, coin)|
            (note.amount, &note.secrets.opening, &coin.commitment)).collect();
        let escrow = create_escrow_recovery(&context, &recipient_address, &refund_address, u128::MAX - 1).unwrap();
        let change = create_output(&context, &sender_address, 256).unwrap();
        let membership = MembershipKey::derive(&context);
        let statement = PendingCreateStatement {
            funding: TransferStatement {
                network, application, depth: root.depth, root: root.root,
                images: notes.iter().map(|note| membership.key_image(&note.secrets.owner).identity_bytes().unwrap()).collect(),
                fee: 2,
                outputs: vec![Output { commitment: escrow.commitment.clone(), owner: escrow.recipient.owner, memo: escrow.recipient.ciphertext }, change.output],
            },
            // Authority bytes are public context in a creation proof. Claim
            // signature/eligibility and stored-policy admission are separate.
            policy: EscrowPolicy { recipient: [126; FALCON_PUBLIC_BYTES], refund: [127; FALCON_PUBLIC_BYTES], refund_after_global_frame: 200 },
            refund_recovery: escrow.refund,
        };
        let limits = CompileLimits { max_inputs: 2, max_outputs: 2, max_depth: 1 };
        let budget = NativeBudget { max_native_bytes: 24 << 30 };
        let relation = statement.private_relation(&inputs,
            &[(u128::MAX - 1, &escrow.opening), (256, &change.opening)], &paths, limits).unwrap();
        eprintln!("native_pending_creation_compiled seconds={:.3}", started.elapsed().as_secs_f64());
        let proof = native::prove(&relation, budget).unwrap();
        drop(relation);
        let tx = PendingCreate { statement, proof };
        let bytes = tx.encode().unwrap();
        assert!(bytes.len() <= TARGET_TRANSACTION_BYTES);
        assert!(bytes.len() < MAX_TRANSACTION_BYTES);
        let decoded = PendingCreate::decode(&bytes, &network, &application).unwrap();
        assert_eq!(decoded, tx);
        assert!(native::verify_owned(decoded.statement.public_relation(limits).unwrap(), &decoded.proof, budget).unwrap());
        // Removing the pending wrapper must not turn escrow funding into an
        // ordinary transfer that would publish the escrow as a spendable coin.
        assert!(!native::verify_owned(decoded.statement.funding.public_relation(limits).unwrap(), &decoded.proof, budget).unwrap());
        let mut changed = decoded.statement.clone();
        changed.policy.refund_after_global_frame += 1;
        assert!(!native::verify_owned(changed.public_relation(limits).unwrap(), &decoded.proof, budget).unwrap());
        let mut changed = decoded.statement.clone();
        changed.refund_recovery.ciphertext[0] ^= 1;
        assert!(!native::verify_owned(changed.public_relation(limits).unwrap(), &decoded.proof, budget).unwrap());
        let mut changed = decoded.statement.clone();
        changed.funding.outputs[0].memo[0] ^= 1;
        assert!(!native::verify_owned(changed.public_relation(limits).unwrap(), &decoded.proof, budget).unwrap());
        let (pending, change) = decoded.statement.split_outputs().unwrap();
        for (secret, kem, recovery) in [
            (&recipient, &recipient_kem, EscrowRecoveryMemo { owner: pending.owner, ciphertext: pending.memo }),
            (&refund, &refund_kem, decoded.statement.refund_recovery.clone()),
        ] {
            let opened = open_escrow_recovery(&context, kem.as_bytes(), secret, &pending.commitment, &recovery).unwrap();
            assert_eq!(opened.amount(), u128::MAX - 1);
            assert_eq!(CommitmentKey::derive(&context).commit(opened.amount(), opened.opening()), pending.commitment);
        }
        assert_eq!(change.len(), 1);
        assert_eq!(open_output(&context, sender_kem.as_bytes(), &sender, &change[0]).unwrap().amount, 256);
        eprintln!("native_pending_creation inputs=2 outputs=2 bytes={} proof_bytes={} header_bytes={} transfer_reinterpretation_rejected=true policy_and_recovery_changes_rejected=true both_parties_recovered=true seconds={:.3}",
            bytes.len(), decoded.proof.len(), PENDING_HEADER_BYTES, started.elapsed().as_secs_f64());
    }

    #[test]
    fn pending_creation_binds_recovery_policy_and_separates_change() {
        let network = [101; 32];
        let application = [102; 32];
        let context = super::super::transfer::parameter_context(&network, &application);
        let key = CommitmentKey::derive(&context);
        let opening = AmountOpening::from_seed(&context, &[103; 32]);
        let mut proof = vec![0; 40]; proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        let mut tx = PendingCreate { statement: PendingCreateStatement {
            funding: TransferStatement { network, application, depth: 1,
                root: Node::from_bytes(&[0; NODE_BYTES]).unwrap(), images: vec![[104; IDENTITY_BYTES]], fee: 2,
                outputs: vec![Output { commitment: key.commit(10, &opening), owner: [105; IDENTITY_BYTES], memo: [106; MEMO_BYTES] },
                    Output { commitment: key.commit(3, &opening), owner: [107; IDENTITY_BYTES], memo: [108; MEMO_BYTES] }],
            },
            policy: EscrowPolicy { recipient: [109; FALCON_PUBLIC_BYTES], refund: [110; FALCON_PUBLIC_BYTES], refund_after_global_frame: 200 },
            refund_recovery: EscrowRecoveryMemo { owner: [111; IDENTITY_BYTES], ciphertext: [112; MEMO_BYTES] },
        }, proof };
        let bytes = tx.encode().unwrap();
        assert_eq!(PendingCreate::decode(&bytes, &network, &application).unwrap(), tx);
        let (escrow, change) = tx.statement.split_outputs().unwrap();
        assert_eq!(escrow, &tx.statement.funding.outputs[0]);
        assert_eq!(change, &tx.statement.funding.outputs[1..]);
        let bound = tx.statement.context_bytes().unwrap();
        let mut variants = Vec::new();
        let mut s = tx.statement.clone(); s.policy.recipient[0] ^= 1; variants.push(s);
        let mut s = tx.statement.clone(); s.policy.refund[0] ^= 1; variants.push(s);
        let mut s = tx.statement.clone(); s.policy.refund_after_global_frame += 1; variants.push(s);
        let mut s = tx.statement.clone(); s.refund_recovery.owner[0] ^= 1; variants.push(s);
        let mut s = tx.statement.clone(); s.refund_recovery.ciphertext[0] ^= 1; variants.push(s);
        let mut s = tx.statement.clone(); s.funding.outputs[0].memo[0] ^= 1; variants.push(s);
        for s in variants { assert_ne!(s.context_bytes().unwrap(), bound); }
        for end in [0, 3, 11, 75, PENDING_HEADER_BYTES - 1, PENDING_HEADER_BYTES, bytes.len() - 1] {
            assert!(PendingCreate::decode(&bytes[..end], &network, &application).is_err());
        }
        let mut bad = bytes.clone(); bad[PENDING_HEADER_BYTES + 12] ^= 1;
        assert!(PendingCreate::decode(&bad, &network, &application).is_err());
        let mut bad = bytes.clone(); bad.push(0);
        assert!(PendingCreate::decode(&bad, &network, &application).is_err());
        assert!(PendingCreate::decode(&bytes, &[113; 32], &application).is_err());
        assert!(PendingCreate::decode(&bytes, &network, &[113; 32]).is_err());
        let context_len = bound.len();
        tx.proof.resize(MAX_TRANSACTION_BYTES - context_len - 5, 0);
        let largest = tx.encode().unwrap();
        assert_eq!(largest.len(), MAX_TRANSACTION_BYTES - 1);
        assert!(PendingCreate::decode(&largest, &network, &application).is_ok());
        tx.proof.push(0);
        assert!(tx.encode().is_err());
        tx.statement.funding.outputs.clear();
        assert!(tx.statement.split_outputs().is_err());
        assert!(tx.statement.context_bytes().is_err());
    }
}

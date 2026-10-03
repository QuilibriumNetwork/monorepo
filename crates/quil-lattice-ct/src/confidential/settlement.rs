//! Cross-domain QUIL settlement: a QUIL spend whose public outflow is the
//! operation's own fee plus a settlement amount made available to exactly one
//! destination application under one consumer context. The amount relation is
//! the transfer relation with outflow `fee + settlement`; the proof transcript
//! binds the settlement header (fee, amount, destination, context) so the
//! funding cannot be reinterpreted as an ordinary transfer or re-targeted.
//! Execution writes a global settlement record; the destination application
//! consumes it once through a membership proof against a cited global root.
use super::{
    address::{RecipientAddress, ADDRESS_BYTES},
    relation::{membership::{InputPath, MembershipKey}, CompiledAmountRelation, PublicAmountRelation},
    transfer::{parameter_context, CompileLimits, Reader, Transfer, TransferError, TransferStatement, MAX_TRANSACTION_BYTES},
    AmountCommitment, AmountOpening, CommitmentKey,
};

pub const PREFIX: [u8; 4] = 0x0518u32.to_be_bytes();
pub const VERSION: &[u8; 8] = b"QCT3ST\0\x02";
/// prefix ‖ version ‖ network ‖ application ‖ fee ‖ settlement ‖ destination ‖ context
pub const SETTLEMENT_HEADER_BYTES: usize = 4 + 8 + 32 + 32 + 16 + 16 + 32 + 32;
/// Longest claimant key a pre-funded settlement may name (Falcon-512 is 897).
pub const MAX_CLAIMANT_KEY_BYTES: usize = 1024;

/// A present payment: payee address ‖ nonce ‖ value (after a one-byte flag).
pub const PAYMENT_BYTES: usize = ADDRESS_BYTES + 32 + 16;
/// A present claimant's fixed part: key type ‖ key length (after a flag byte).
pub const CLAIMANT_HEADER_BYTES: usize = 4 + 2;

/// A payment made by the settlement's first funding output: a QUIL coin owned
/// by `payee` whose amount `value` and note nonce are public, so anyone can
/// check the coin against the payee's address (a token's paid mint price paid
/// to the token's payment address). The payee can spend the coin like any
/// other; spends of payment coins are linkable to each other because their
/// note nonces are public.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payment {
    pub payee: RecipientAddress,
    pub nonce: [u8; 32],
    pub value: u128,
}

/// The key a pre-funded settlement hands the authority to choose the bundle it
/// funds. A payer who does not yet know the bundle names a claimant instead of
/// a context; the consumer's claim then carries this key and a signature over
/// the bundle's context. Execution compares the key type and key against the
/// global record, so only this key can direct the settlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claimant {
    /// Protocol key-type discriminant (Ed448, Ed25519 or Falcon-512).
    pub key_type: u32,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementStatement {
    /// The spend. Its `fee` is the total public outflow `fee + settlement`.
    pub funding: TransferStatement,
    /// This operation's own gas, paid to the global frame's prover.
    pub fee: u128,
    /// Amount available to the destination application's consumer bundle.
    pub settlement: u128,
    /// The only application that may consume the settlement.
    pub destination: [u8; 32],
    /// Consumer-chosen binding: SHA3-256 of the bundle the payment funds, zero
    /// for a pre-funded settlement, which binds a `claimant` instead.
    pub context: [u8; 32],
    /// Pre-funded binding: the key that may later name the funded bundle.
    /// Exactly one of `context` and `claimant` is set.
    pub claimant: Option<Claimant>,
    /// Optional public payment carried by `funding.outputs[0]`.
    pub payment: Option<Payment>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settlement {
    pub statement: SettlementStatement,
    pub proof: Vec<u8>,
}

impl SettlementStatement {
    fn validate(&self) -> Result<(), TransferError> {
        if self.settlement == 0 || self.destination == self.funding.application {
            return Err(TransferError::Dimensions);
        }
        // Exactly one binding: a bundle's context, or the claimant who will
        // name one. A settlement bound to neither would fund any bundle.
        if (self.context == [0; 32]) != self.claimant.is_some() {
            return Err(TransferError::Noncanonical);
        }
        // The key type is a protocol discriminant, and zero is a real one
        // (Ed448); only the key bytes say whether a claimant is present.
        if let Some(claimant) = &self.claimant {
            if claimant.public_key.is_empty() || claimant.public_key.len() > MAX_CLAIMANT_KEY_BYTES {
                return Err(TransferError::Noncanonical);
            }
        }
        if self.fee.checked_add(self.settlement) != Some(self.funding.fee) {
            return Err(TransferError::Noncanonical);
        }
        if let Some(payment) = &self.payment {
            if payment.value == 0 || self.funding.outputs.is_empty() {
                return Err(TransferError::Dimensions);
            }
            if payment.payee.context() != &parameter_context(&self.funding.network, &self.funding.application) {
                return Err(TransferError::Context);
            }
        }
        Ok(())
    }

    /// Check the payment coin: `funding.outputs[0]` commits to exactly
    /// `payment.value` under the opening derived from the public nonce and is
    /// owned by the payee's recipient key under that nonce. The funding proof
    /// separately proves the coin's amount is conserved and in range.
    pub fn check_payment(&self) -> Result<(), TransferError> {
        let Some(payment) = &self.payment else { return Ok(()) };
        self.validate()?;
        let context = parameter_context(&self.funding.network, &self.funding.application);
        let output = &self.funding.outputs[0];
        let opening = AmountOpening::from_seed(&context, &payment.nonce);
        if CommitmentKey::derive(&context).commit(payment.value, &opening) != output.commitment {
            return Err(TransferError::Noncanonical);
        }
        let owner = MembershipKey::derive(&context)
            .output_owner(payment.payee.recipient_key(), &payment.nonce)
            .and_then(|node| node.identity_bytes().ok())
            .ok_or(TransferError::Noncanonical)?;
        if owner != output.owner {
            return Err(TransferError::Noncanonical);
        }
        Ok(())
    }

    fn header_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SETTLEMENT_HEADER_BYTES + 2 + PAYMENT_BYTES + CLAIMANT_HEADER_BYTES + MAX_CLAIMANT_KEY_BYTES);
        bytes.extend_from_slice(&PREFIX);
        bytes.extend_from_slice(VERSION);
        bytes.extend_from_slice(&self.funding.network);
        bytes.extend_from_slice(&self.funding.application);
        bytes.extend_from_slice(&self.fee.to_le_bytes());
        bytes.extend_from_slice(&self.settlement.to_le_bytes());
        bytes.extend_from_slice(&self.destination);
        bytes.extend_from_slice(&self.context);
        match &self.payment {
            None => bytes.push(0),
            Some(payment) => {
                bytes.push(1);
                bytes.extend_from_slice(&payment.payee.encode());
                bytes.extend_from_slice(&payment.nonce);
                bytes.extend_from_slice(&payment.value.to_le_bytes());
            }
        }
        match &self.claimant {
            None => bytes.push(0),
            Some(claimant) => {
                bytes.push(1);
                bytes.extend_from_slice(&claimant.key_type.to_le_bytes());
                bytes.extend_from_slice(&(claimant.public_key.len() as u16).to_le_bytes());
                bytes.extend_from_slice(&claimant.public_key);
            }
        }
        bytes
    }

    /// Canonical proof-excluding bytes: the settlement header, then the full
    /// funding context. This is the identity the global record derives from.
    pub fn context_bytes(&self) -> Result<Vec<u8>, TransferError> {
        self.validate()?;
        let funding = self.funding.context_bytes()?;
        if SETTLEMENT_HEADER_BYTES + 2 + PAYMENT_BYTES + CLAIMANT_HEADER_BYTES + MAX_CLAIMANT_KEY_BYTES
            + funding.len() + 4 + 40 >= MAX_TRANSACTION_BYTES
        {
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
        self.funding
            .private_relation(inputs, output_openings, paths, limits)
            .map(|r| r.with_transaction_context(&context))
    }
}

impl Settlement {
    pub fn encode(&self) -> Result<Vec<u8>, TransferError> {
        if self.proof.len() < 40 || self.proof.len() >= MAX_TRANSACTION_BYTES || &self.proof[..8] != b"QPF6\0\0\0\0" {
            return Err(TransferError::Length);
        }
        let mut bytes = self.statement.context_bytes()?;
        if bytes.len() + 4 + self.proof.len() >= MAX_TRANSACTION_BYTES {
            return Err(TransferError::Length);
        }
        bytes.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.proof);
        Ok(bytes)
    }

    /// Checks the envelope, the funding encoding and the outflow split, not
    /// proof validity. Expected domains come from the node/wallet.
    pub fn decode(bytes: &[u8], network: &[u8; 32], application: &[u8; 32]) -> Result<Self, TransferError> {
        if bytes.len() >= MAX_TRANSACTION_BYTES {
            return Err(TransferError::Length);
        }
        let mut r = Reader(bytes);
        if r.take(4)? != PREFIX || r.take(8)? != VERSION {
            return Err(TransferError::Version);
        }
        if r.take(32)? != network || r.take(32)? != application {
            return Err(TransferError::Context);
        }
        let fee = u128::from_le_bytes(r.array()?);
        let settlement = u128::from_le_bytes(r.array()?);
        let destination = r.array()?;
        let context = r.array()?;
        let payment = match r.take(1)?[0] {
            0 => None,
            1 => {
                let payee = RecipientAddress::decode(r.take(ADDRESS_BYTES)?, &parameter_context(network, application))
                    .map_err(|_| TransferError::Context)?;
                let nonce = r.array()?;
                let value = u128::from_le_bytes(r.array()?);
                Some(Payment { payee, nonce, value })
            }
            _ => return Err(TransferError::Noncanonical),
        };
        let claimant = match r.take(1)?[0] {
            0 => None,
            1 => {
                let key_type = u32::from_le_bytes(r.array()?);
                let length = u16::from_le_bytes(r.take(2)?.try_into().unwrap()) as usize;
                if length > MAX_CLAIMANT_KEY_BYTES {
                    return Err(TransferError::Length);
                }
                Some(Claimant { key_type, public_key: r.take(length)?.to_vec() })
            }
            _ => return Err(TransferError::Noncanonical),
        };
        let funding = Transfer::decode(r.0, network, application)?;
        let statement = SettlementStatement { funding: funding.statement, fee, settlement, destination, context, payment, claimant };
        statement.validate()?;
        Ok(Self { statement, proof: funding.proof })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidential::{
        relation::membership::{Node, IDENTITY_BYTES, NODE_BYTES},
        transfer::{parameter_context, Output, MEMO_BYTES},
        CommitmentKey,
    };

    fn sample() -> Settlement {
        let network = [131; 32];
        let application = [132; 32];
        let context = parameter_context(&network, &application);
        let key = CommitmentKey::derive(&context);
        let opening = AmountOpening::from_seed(&context, &[133; 32]);
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        Settlement {
            statement: SettlementStatement {
                funding: TransferStatement {
                    network, application, depth: 1,
                    root: Node::from_bytes(&[0; NODE_BYTES]).unwrap(),
                    images: vec![[134; IDENTITY_BYTES]],
                    fee: 7 + 1_000,
                    outputs: vec![Output { commitment: key.commit(5, &opening), owner: [135; IDENTITY_BYTES], memo: [136; MEMO_BYTES] }],
                },
                fee: 7,
                settlement: 1_000,
                destination: [137; 32],
                context: [138; 32],
                payment: None,
                claimant: None,
            },
            proof,
        }
    }

    #[test]
    fn settlement_binds_amount_destination_context_and_outflow_split() {
        let tx = sample();
        let (network, application) = (tx.statement.funding.network, tx.statement.funding.application);
        let bytes = tx.encode().unwrap();
        assert_eq!(Settlement::decode(&bytes, &network, &application).unwrap(), tx);
        // The funding alone is not a settlement (different prefix and context).
        let funding_context = tx.statement.funding.context_bytes().unwrap();
        let bound = tx.statement.context_bytes().unwrap();
        assert_ne!(bound, funding_context);
        assert!(bound.ends_with(&funding_context));

        let mut variants = Vec::new();
        let mut s = tx.statement.clone(); s.destination[0] ^= 1; variants.push(s);
        let mut s = tx.statement.clone(); s.context[0] ^= 1; variants.push(s);
        let mut s = tx.statement.clone(); s.fee += 1; s.settlement -= 1; variants.push(s);
        for s in variants {
            assert_ne!(s.context_bytes().unwrap(), bound);
        }
        // The outflow must split exactly into fee and settlement.
        let mut s = tx.statement.clone(); s.settlement += 1;
        assert!(s.context_bytes().is_err());
        let mut s = tx.statement.clone(); s.fee = u128::MAX;
        assert!(s.context_bytes().is_err());
        // A zero settlement or a settlement to the paying application is not
        // a cross-domain payment.
        let mut s = tx.statement.clone(); s.funding.fee = s.fee; s.settlement = 0;
        assert!(s.context_bytes().is_err());
        let mut s = tx.statement.clone(); s.destination = application;
        assert!(s.context_bytes().is_err());

        for end in [0, 3, 11, 75, SETTLEMENT_HEADER_BYTES - 1, SETTLEMENT_HEADER_BYTES, SETTLEMENT_HEADER_BYTES + 1, bytes.len() - 1] {
            assert!(Settlement::decode(&bytes[..end], &network, &application).is_err());
        }
        let mut bad = bytes.clone(); bad.push(0);
        assert!(Settlement::decode(&bad, &network, &application).is_err());
        // Tamper the settlement amount in the header: the split no longer holds.
        let mut bad = bytes.clone(); bad[4 + 8 + 32 + 32 + 16] ^= 1;
        assert!(Settlement::decode(&bad, &network, &application).is_err());
        // An unknown payment or claimant flag is not canonical.
        let mut bad = bytes.clone(); bad[SETTLEMENT_HEADER_BYTES] = 2;
        assert!(Settlement::decode(&bad, &network, &application).is_err());
        let mut bad = bytes.clone(); bad[SETTLEMENT_HEADER_BYTES + 1] = 2;
        assert!(Settlement::decode(&bad, &network, &application).is_err());
        assert!(Settlement::decode(&bytes, &[139; 32], &application).is_err());
        assert!(Settlement::decode(&bytes, &network, &[139; 32]).is_err());
        // A settlement never decodes as a transfer and vice versa.
        assert!(Transfer::decode(&bytes, &network, &application).is_err());
        let transfer = Transfer { statement: tx.statement.funding.clone(), proof: tx.proof.clone() }.encode().unwrap();
        assert!(Settlement::decode(&transfer, &network, &application).is_err());
    }

    #[test]
    fn a_settlement_binds_either_a_bundle_context_or_a_claimant() {
        let tx = sample();
        let (network, application) = (tx.statement.funding.network, tx.statement.funding.application);
        let claimant = Claimant { key_type: 3, public_key: vec![9; 897] };
        let prefunded = SettlementStatement { context: [0; 32], claimant: Some(claimant.clone()), ..tx.statement.clone() };
        let bound = prefunded.context_bytes().unwrap();
        assert_ne!(bound, tx.statement.context_bytes().unwrap());
        let encoded = Settlement { statement: prefunded.clone(), proof: tx.proof.clone() }.encode().unwrap();
        assert_eq!(Settlement::decode(&encoded, &network, &application).unwrap().statement, prefunded);
        // The claimant key and its type are bound into the transcript.
        for changed in [
            Claimant { key_type: 4, ..claimant.clone() },
            Claimant { public_key: vec![10; 897], ..claimant.clone() },
            Claimant { public_key: vec![9; 896], ..claimant.clone() },
        ] {
            let other = SettlementStatement { claimant: Some(changed), ..prefunded.clone() };
            assert_ne!(other.context_bytes().unwrap(), bound);
        }
        // Neither binding, or both, is not a settlement; nor is an empty,
        // untyped or oversized claimant key.
        assert!(SettlementStatement { context: [0; 32], claimant: None, ..tx.statement.clone() }.context_bytes().is_err());
        assert!(SettlementStatement { claimant: Some(claimant.clone()), ..tx.statement.clone() }.context_bytes().is_err());
        for bad in [
            Claimant { public_key: Vec::new(), ..claimant.clone() },
            Claimant { public_key: vec![9; MAX_CLAIMANT_KEY_BYTES + 1], ..claimant.clone() },
        ] {
            assert!(SettlementStatement { claimant: Some(bad), ..prefunded.clone() }.context_bytes().is_err());
        }
    }

    #[test]
    fn payment_coin_must_open_to_the_public_value_for_the_payee() {
        use crate::confidential::{memo::create_output_with_nonce, relation::membership::RecipientSecret};
        let mut tx = sample();
        let (network, application) = (tx.statement.funding.network, tx.statement.funding.application);
        let context = parameter_context(&network, &application);
        use pqcrypto_traits::kem::PublicKey as _;
        let (kem, _) = pqcrypto_ntruprime::sntrup761::keypair();
        let payee = RecipientAddress::new(&context, &RecipientSecret::from_seed(&context, &[140; 32]), kem.as_bytes()).unwrap();
        let other = RecipientAddress::new(&context, &RecipientSecret::from_seed(&context, &[142; 32]), kem.as_bytes()).unwrap();
        let nonce = [143; 32];
        tx.statement.funding.outputs[0] = create_output_with_nonce(&context, &payee, 600, &nonce).unwrap().output;
        tx.statement.payment = Some(Payment { payee: payee.clone(), nonce, value: 600 });
        tx.statement.check_payment().unwrap();
        // The payment round-trips and is bound into the proof transcript.
        let bytes = tx.encode().unwrap();
        assert_eq!(Settlement::decode(&bytes, &network, &application).unwrap(), tx);
        let unpaid = SettlementStatement { payment: None, ..tx.statement.clone() };
        assert_ne!(unpaid.context_bytes().unwrap(), tx.statement.context_bytes().unwrap());
        // Wrong value, wrong payee or wrong nonce do not match the coin.
        for payment in [
            Payment { value: 601, ..tx.statement.payment.clone().unwrap() },
            Payment { payee: other, ..tx.statement.payment.clone().unwrap() },
            Payment { nonce: [144; 32], ..tx.statement.payment.clone().unwrap() },
        ] {
            let statement = SettlementStatement { payment: Some(payment), ..tx.statement.clone() };
            assert!(statement.check_payment().is_err());
        }
        // A payment is independent of the binding: it may pre-fund too.
        let mut prefunded = tx.statement.clone();
        prefunded.context = [0; 32];
        prefunded.claimant = Some(Claimant { key_type: 3, public_key: vec![7; 897] });
        assert!(prefunded.context_bytes().is_ok());
        // A zero-valued payment is not a payment.
        let statement = SettlementStatement { payment: Some(Payment { value: 0, ..tx.statement.payment.clone().unwrap() }), ..tx.statement.clone() };
        assert!(statement.context_bytes().is_err());
    }
}

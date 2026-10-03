//! The spend entry an executing shard relays for each confidential operation.
//!
//! Built structurally from the operation bytes after execution has verified
//! the operation — the same pattern settlement relay entries use — so the
//! engine's result type does not change. Nothing here reads state: everything
//! a consume-once decision needs is derived from the operation and decided by
//! the global commit.
use super::{
    escrow,
    global_commit::{self, EscrowClaim, EscrowCreate, SpendEntry},
    custom_mint, roots, settlement_record, spent, spent_check,
    state::coin_identity,
};
use crate::domains;
use crate::hypergraph_state::HypergraphState;
use crate::token_engine::{
    TYPE_LATTICE_MINT, TYPE_LATTICE_MINT_CLAIM, TYPE_LATTICE_PENDING, TYPE_LATTICE_PENDING_CLAIM, TYPE_LATTICE_SETTLEMENT,
    TYPE_LATTICE_SHIELD, TYPE_LATTICE_TRANSACTION,
};
use quil_lattice_ct::confidential::{
    custom_mint::CustomMint,
    mint_claim::MintClaim,
    pending_claim::{ClaimBranch, PendingClaim},
    pending_create::PendingCreate,
    settlement::Settlement,
    shield::Shield,
    transfer::{parameter_context, Output, Transfer, TransferStatement},
    MAX_PRIVATE_COINS,
};
use quil_types::error::{QuilError, Result};
use std::collections::BTreeSet;

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("spend entry: {message}"))
}

/// Whether an operation of type `tp` on `application` commits through the
/// global frame. Custom-token issuance does; the QUIL reward mint is itself
/// global and authorizes rather than creates coins.
pub fn commits_globally(application: &[u8; 32], tp: u32) -> bool {
    is_relayed(tp) || (tp == TYPE_LATTICE_MINT && application != &domains::QUIL_TOKEN)
}

/// Whether a type prefix is relayed through the global commit on every
/// application.
pub fn is_relayed(tp: u32) -> bool {
    matches!(
        tp,
        TYPE_LATTICE_TRANSACTION
            | TYPE_LATTICE_PENDING
            | TYPE_LATTICE_PENDING_CLAIM
            | TYPE_LATTICE_SHIELD
            | TYPE_LATTICE_MINT_CLAIM
            | TYPE_LATTICE_SETTLEMENT
    )
}

fn output_addresses(context: &[u8; 32], frame: u64, outputs: &[Output]) -> Result<Vec<[u8; 32]>> {
    outputs.iter().map(|output| coin_identity(context, frame, output).map(|(address, _)| address)).collect()
}

fn base(tp: u32, bytes: &[u8], frame: u64, context: [u8; 32]) -> SpendEntry {
    SpendEntry {
        kind: tp,
        tx_id: global_commit::tx_id(bytes),
        source_frame: frame,
        context,
        root_digest: None,
        consumptions: Vec::new(),
        outputs: Vec::new(),
        escrow_create: None,
        escrow_claim: None,
        fee: 0,
        settlement: None,
    }
}

/// The part every spend of existing coins shares: its root and its images.
fn funding(entry: &mut SpendEntry, s: &TransferStatement, outputs: &[Output]) -> Result<()> {
    if s.images.is_empty()
        || s.images.len() > MAX_PRIVATE_COINS
        || s.images.iter().collect::<BTreeSet<_>>().len() != s.images.len()
    {
        return Err(invalid("invalid image set"));
    }
    entry.root_digest = Some(roots::root_digest(&entry.context, s.depth, &s.root));
    entry.consumptions = s
        .images
        .iter()
        .map(|image| spent::marker_address(&s.network, &s.application, image))
        .collect::<Result<_>>()?;
    entry.outputs = output_addresses(&entry.context, entry.source_frame, outputs)?;
    Ok(())
}

/// The outputs a relayed operation creates, in the order its spend entry lists
/// their addresses — what an owning shard delivers once they commit.
pub fn operation_outputs(network: &[u8; 32], application: &[u8; 32], tp: u32, bytes: &[u8]) -> Result<Vec<Output>> {
    let decode = |_| invalid("invalid operation encoding or context");
    Ok(match tp {
        TYPE_LATTICE_TRANSACTION => Transfer::decode(bytes, network, application).map_err(decode)?.statement.outputs,
        TYPE_LATTICE_PENDING => {
            let tx = PendingCreate::decode(bytes, network, application).map_err(decode)?;
            let (_, change) = tx.statement.split_outputs().map_err(|_| invalid("missing escrow output"))?;
            change.to_vec()
        }
        TYPE_LATTICE_PENDING_CLAIM => PendingClaim::decode(bytes, network, application).map_err(decode)?.statement.outputs,
        TYPE_LATTICE_SHIELD => Shield::decode(bytes, network, application).map_err(decode)?.statement.outputs,
        TYPE_LATTICE_MINT_CLAIM => MintClaim::decode(bytes, network, application).map_err(decode)?.outputs,
        TYPE_LATTICE_MINT if application != &domains::QUIL_TOKEN => {
            CustomMint::decode(bytes, network, application).map_err(decode)?.statement.outputs
        }
        TYPE_LATTICE_SETTLEMENT => Settlement::decode(bytes, network, application).map_err(decode)?.statement.funding.outputs,
        _ => return Err(invalid("operation is not relayed through the global commit")),
    })
}

/// [`spend_entry`], for any operation that [`commits_globally`]: a custom
/// mint's consumptions depend on the deployed mint policy, read from `state`.
pub fn commit_entry(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    tp: u32,
    bytes: &[u8],
    frame: u64,
) -> Result<SpendEntry> {
    if !(tp == TYPE_LATTICE_MINT && application != &domains::QUIL_TOKEN) {
        return spend_entry(network, application, tp, bytes, frame);
    }
    let mint = CustomMint::decode(bytes, network, application).map_err(|_| invalid("invalid operation encoding or context"))?;
    let context = parameter_context(network, application);
    let mut entry = base(tp, bytes, frame, context);
    entry.consumptions = custom_mint::commit_consumptions(state, bytes, network, application)?;
    entry.outputs = output_addresses(&context, frame, &mint.statement.outputs)?;
    entry.encode()?;
    Ok(entry)
}

/// The spend entry of one verified confidential operation, executed at
/// `frame` of a shard of `application`.
pub fn spend_entry(network: &[u8; 32], application: &[u8; 32], tp: u32, bytes: &[u8], frame: u64) -> Result<SpendEntry> {
    let context = parameter_context(network, application);
    let mut entry = base(tp, bytes, frame, context);
    let decode = |_| invalid("invalid operation encoding or context");
    match tp {
        TYPE_LATTICE_TRANSACTION => {
            let tx = Transfer::decode(bytes, network, application).map_err(decode)?;
            funding(&mut entry, &tx.statement, &tx.statement.outputs)?;
            entry.fee = tx.statement.fee;
        }
        TYPE_LATTICE_PENDING => {
            let tx = PendingCreate::decode(bytes, network, application).map_err(decode)?;
            let s = &tx.statement;
            let (escrowed, change) = s.split_outputs().map_err(|_| invalid("missing escrow output"))?;
            funding(&mut entry, &s.funding, change)?;
            let (address, _) = escrow::create_escrow(&context, frame, escrowed, &s.policy, &s.refund_recovery)?;
            entry.escrow_create = Some(EscrowCreate {
                address,
                binding: global_commit::escrow_binding(
                    &context,
                    &address,
                    &escrowed.commitment.to_bytes(),
                    &s.policy.recipient,
                    &s.policy.refund,
                    s.policy.refund_after_global_frame,
                ),
                refund_after_global_frame: s.policy.refund_after_global_frame,
            });
            entry.fee = s.funding.fee;
        }
        TYPE_LATTICE_PENDING_CLAIM => {
            let tx = PendingClaim::decode(bytes, network, application).map_err(decode)?;
            let s = &tx.statement;
            entry.outputs = output_addresses(&context, frame, &s.outputs)?;
            entry.escrow_claim = Some(EscrowClaim {
                address: s.escrow_address,
                binding: global_commit::escrow_binding(
                    &context,
                    &s.escrow_address,
                    &s.source.to_bytes(),
                    &s.policy.recipient,
                    &s.policy.refund,
                    s.policy.refund_after_global_frame,
                ),
                refund: s.branch == ClaimBranch::Refund,
            });
            entry.fee = s.fee;
        }
        TYPE_LATTICE_SHIELD => {
            let tx = Shield::decode(bytes, network, application).map_err(decode)?;
            let s = &tx.statement;
            entry.consumptions = vec![spent_check::key_image_spent_address(&s.transparent_address)?];
            entry.outputs = output_addresses(&context, frame, &s.outputs)?;
            entry.fee = s.fee;
        }
        TYPE_LATTICE_MINT_CLAIM => {
            let claim = MintClaim::decode(bytes, network, application).map_err(decode)?;
            entry.consumptions = vec![claim.receipt];
            entry.outputs = output_addresses(&context, frame, &claim.outputs)?;
            entry.fee = claim.fee;
        }
        TYPE_LATTICE_SETTLEMENT => {
            let tx = Settlement::decode(bytes, network, application).map_err(decode)?;
            funding(&mut entry, &tx.statement.funding, &tx.statement.funding.outputs)?;
            // The operation's own gas; the settlement amount is not a fee.
            entry.fee = tx.statement.fee;
            entry.settlement = Some(settlement_record::entry(&tx.statement)?);
        }
        _ => return Err(invalid("operation is not relayed through the global commit")),
    }
    // Enforce the relay's own bounds here, where a malformed entry is the
    // executing shard's error, not the global frame's.
    entry.encode()?;
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_lattice_ct::confidential::{
        relation::membership::{Node, IDENTITY_BYTES, NODE_BYTES},
        transfer::MEMO_BYTES,
        AmountOpening, CommitmentKey,
    };

    fn proof() -> Vec<u8> {
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        proof
    }

    fn output(context: &[u8; 32], seed: u8) -> Output {
        Output {
            owner: [seed; IDENTITY_BYTES],
            commitment: CommitmentKey::derive(context).commit(u128::from(seed), &AmountOpening::from_seed(context, &[seed; 32])),
            memo: [seed; MEMO_BYTES],
        }
    }

    /// A transfer's entry consumes exactly the markers local staging writes,
    /// creates exactly the addresses it stages, and cites its root by digest.
    #[test]
    fn a_transfer_entry_matches_what_the_transfer_spends_and_creates() {
        let (network, application) = ([1u8; 32], [2u8; 32]);
        let context = parameter_context(&network, &application);
        let root = Node::from_bytes(&[3u8; NODE_BYTES]).unwrap();
        let statement = TransferStatement {
            network, application, depth: 32, root: root.clone(),
            images: vec![[4; IDENTITY_BYTES], [5; IDENTITY_BYTES]],
            outputs: vec![output(&context, 6), output(&context, 7)],
            fee: 9,
        };
        let bytes = Transfer { statement: statement.clone(), proof: proof() }.encode().unwrap();
        let entry = spend_entry(&network, &application, TYPE_LATTICE_TRANSACTION, &bytes, 55).unwrap();
        assert_eq!(entry.kind, TYPE_LATTICE_TRANSACTION);
        assert_eq!(entry.tx_id, global_commit::tx_id(&bytes));
        assert_eq!(entry.source_frame, 55);
        assert_eq!(entry.root_digest, Some(roots::root_digest(&context, 32, &root)));
        assert_eq!(entry.consumptions, vec![
            spent::marker_address(&network, &application, &[4; IDENTITY_BYTES]).unwrap(),
            spent::marker_address(&network, &application, &[5; IDENTITY_BYTES]).unwrap(),
        ]);
        assert_eq!(entry.outputs, vec![
            coin_identity(&context, 55, &statement.outputs[0]).unwrap().0,
            coin_identity(&context, 55, &statement.outputs[1]).unwrap().0,
        ]);
        assert_eq!(entry.fee, 9);
        // The same operation executed at another frame creates other addresses
        // but consumes the same markers — so only one of the two can commit.
        let later = spend_entry(&network, &application, TYPE_LATTICE_TRANSACTION, &bytes, 56).unwrap();
        assert_ne!(later.outputs, entry.outputs);
        assert_eq!(later.consumptions, entry.consumptions);
        // A relayed entry is small, and round-trips.
        let encoded = entry.encode().unwrap();
        assert!(encoded.len() < 300, "{} bytes", encoded.len());
        assert_eq!(SpendEntry::decode(&encoded).unwrap(), entry);
        // Non-relayed types are refused.
        assert!(spend_entry(&network, &application, 0x0513, &bytes, 55).is_err());
    }
}

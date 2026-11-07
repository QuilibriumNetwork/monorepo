//! The spend entry an executing shard relays for each confidential operation.
//!
//! Built structurally from the operation bytes after execution has verified
//! the operation — the same pattern settlement relay entries use — so the
//! engine's result type does not change. Nothing here reads state: everything
//! a consume-once decision needs is derived from the operation and decided by
//! the global commit.
use super::{
    custom_mint, escrow,
    global_commit::{self, CommitNeeds, EscrowClaim, EscrowCreate, SpendEntry},
    roots, settlement_record, spent, spent_check,
    state::coin_identity,
};
use crate::domains;
use crate::hypergraph_state::HypergraphState;
use crate::token_engine::{
    TYPE_LATTICE_MINT, TYPE_LATTICE_MINT_CLAIM, TYPE_LATTICE_PENDING, TYPE_LATTICE_PENDING_CLAIM,
    TYPE_LATTICE_SETTLEMENT, TYPE_LATTICE_SHIELD, TYPE_LATTICE_TRANSACTION,
};
use quil_lattice_ct::confidential::{
    coin_tree::is_burned_owner,
    custom_mint::CustomMint,
    mint::Mint,
    mint_claim::MintClaim,
    pending_claim::{ClaimBranch, PendingClaim, PendingClaimStatement},
    pending_create::PendingCreate,
    relation::membership::IDENTITY_BYTES,
    settlement::Settlement,
    shield::AnyShield,
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
    outputs
        .iter()
        .map(|output| coin_identity(context, frame, output).map(|(address, _)| address))
        .collect()
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
    entry.root_digest = Some(funding_root(&entry.context, s));
    entry.consumptions = image_markers(s)?;
    entry.outputs = output_addresses(&entry.context, entry.source_frame, outputs)?;
    Ok(())
}

/// The root a spend of existing coins proves its coins against.
fn funding_root(context: &[u8; 32], s: &TransferStatement) -> [u8; 32] {
    roots::root_digest(context, s.depth, &s.root)
}

/// The escrow a pending claim closes, as the global commit matches it.
fn escrow_claim(context: &[u8; 32], s: &PendingClaimStatement) -> EscrowClaim {
    EscrowClaim {
        address: s.escrow_address,
        binding: global_commit::escrow_binding(
            context,
            &s.escrow_address,
            &s.source.to_bytes(),
            &s.policy.recipient,
            &s.policy.refund,
            s.policy.refund_after_global_frame,
        ),
        refund: s.branch == ClaimBranch::Refund,
    }
}

/// The markers a spend of existing coins consumes: one per key image.
fn image_markers(s: &TransferStatement) -> Result<Vec<[u8; 32]>> {
    s.images
        .iter()
        .map(|image| spent::marker_address(&s.network, &s.application, image))
        .collect()
}

/// The markers a shield consumes: one per legacy source, so a batch commits
/// all of them or none.
fn shield_markers(shield: &AnyShield) -> Result<Vec<[u8; 32]>> {
    shield
        .sources()
        .iter()
        .map(|source| spent_check::key_image_spent_address(&source.address))
        .collect()
}

/// The outputs a relayed operation creates, in the order its spend entry lists
/// their addresses — what an owning shard delivers once they commit.
pub fn operation_outputs(
    network: &[u8; 32],
    application: &[u8; 32],
    tp: u32,
    bytes: &[u8],
) -> Result<Vec<Output>> {
    let decode = |_| invalid("invalid operation encoding or context");
    Ok(match tp {
        TYPE_LATTICE_TRANSACTION => {
            Transfer::decode(bytes, network, application)
                .map_err(decode)?
                .statement
                .outputs
        }
        TYPE_LATTICE_PENDING => {
            let tx = PendingCreate::decode(bytes, network, application).map_err(decode)?;
            let (_, change) = tx
                .statement
                .split_outputs()
                .map_err(|_| invalid("missing escrow output"))?;
            change.to_vec()
        }
        TYPE_LATTICE_PENDING_CLAIM => {
            PendingClaim::decode(bytes, network, application)
                .map_err(decode)?
                .statement
                .outputs
        }
        TYPE_LATTICE_SHIELD => AnyShield::decode(bytes, network, application)
            .map_err(decode)?
            .outputs()
            .to_vec(),
        TYPE_LATTICE_MINT_CLAIM => {
            MintClaim::decode(bytes, network, application)
                .map_err(decode)?
                .outputs
        }
        TYPE_LATTICE_MINT if application != &domains::QUIL_TOKEN => {
            CustomMint::decode(bytes, network, application)
                .map_err(decode)?
                .statement
                .outputs
        }
        TYPE_LATTICE_SETTLEMENT => {
            Settlement::decode(bytes, network, application)
                .map_err(decode)?
                .statement
                .funding
                .outputs
        }
        _ => {
            return Err(invalid(
                "operation is not relayed through the global commit",
            ))
        }
    })
}

/// Every owner operation `tp` names: its coin outputs'
/// ([`operation_outputs`]), a pending create's escrowed output and refund
/// recovery too, and the outputs a QUIL reward mint authorizes.
pub fn operation_owners(
    network: &[u8; 32],
    application: &[u8; 32],
    tp: u32,
    bytes: &[u8],
) -> Result<Vec<[u8; IDENTITY_BYTES]>> {
    let decode = |_| invalid("invalid operation encoding or context");
    let owners = |outputs: &[Output]| -> Vec<[u8; IDENTITY_BYTES]> {
        outputs.iter().map(|output| output.owner).collect()
    };
    Ok(match tp {
        TYPE_LATTICE_PENDING => {
            let tx = PendingCreate::decode(bytes, network, application).map_err(decode)?;
            let mut all = owners(&tx.statement.funding.outputs);
            all.push(tx.statement.refund_recovery.owner);
            all
        }
        TYPE_LATTICE_MINT if application == &domains::QUIL_TOKEN => {
            let mint = Mint::decode(bytes, network, application).map_err(decode)?;
            owners(&mint.statement.outputs)
        }
        _ => owners(&operation_outputs(network, application, tp, bytes)?),
    })
}

fn refuse_noncanonical(owners: &[[u8; IDENTITY_BYTES]]) -> Result<()> {
    if owners.iter().any(is_burned_owner) {
        return Err(invalid("an owner is not a canonical identity"));
    }
    Ok(())
}

/// Refuse an operation naming an owner that is not a canonical identity
/// ([`operation_owners`]); from
/// [`global_commit::canonical_owners_active`].
pub fn check_owners(
    network: &[u8; 32],
    application: &[u8; 32],
    tp: u32,
    bytes: &[u8],
) -> Result<()> {
    refuse_noncanonical(&operation_owners(network, application, tp, bytes)?)
}

/// Whether operation `bytes` (type `tp`) names an owner that is not a
/// canonical identity, the refusal of [`check_owners`], read from its bytes
/// alone; false when they do not decode (execution refuses those for their
/// encoding, not their owners) and for a type that names no owner.
pub fn names_noncanonical_owner(
    network: &[u8; 32],
    application: &[u8; 32],
    tp: u32,
    bytes: &[u8],
) -> bool {
    operation_owners(network, application, tp, bytes)
        .is_ok_and(|owners| owners.iter().any(is_burned_owner))
}

/// Refuse an operation creating a coin whose owner is not a canonical
/// identity: exactly the coins a globally executed application's fold took
/// and failed on, so that venue keeps refusing them (at every frame, with no
/// gate) now that the fold burns such a coin instead.
pub fn check_coin_owners(
    network: &[u8; 32],
    application: &[u8; 32],
    tp: u32,
    bytes: &[u8],
) -> Result<()> {
    let outputs = operation_outputs(network, application, tp, bytes)?;
    let owners: Vec<_> = outputs.iter().map(|output| output.owner).collect();
    refuse_noncanonical(&owners)
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
    let mint = CustomMint::decode(bytes, network, application)
        .map_err(|_| invalid("invalid operation encoding or context"))?;
    let context = parameter_context(network, application);
    let mut entry = base(tp, bytes, frame, context);
    entry.consumptions = custom_mint::commit_consumptions(state, bytes, network, application)?;
    entry.outputs = output_addresses(&context, frame, &mint.statement.outputs)?;
    entry.encode()?;
    Ok(entry)
}

/// The spend entry of one verified confidential operation, executed at
/// `frame` of a shard of `application`.
pub fn spend_entry(
    network: &[u8; 32],
    application: &[u8; 32],
    tp: u32,
    bytes: &[u8],
    frame: u64,
) -> Result<SpendEntry> {
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
            let (escrowed, change) = s
                .split_outputs()
                .map_err(|_| invalid("missing escrow output"))?;
            funding(&mut entry, &s.funding, change)?;
            let (address, _) =
                escrow::create_escrow(&context, frame, escrowed, &s.policy, &s.refund_recovery)?;
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
            entry.escrow_claim = Some(escrow_claim(&context, s));
            entry.fee = s.fee;
        }
        TYPE_LATTICE_SHIELD => {
            // One consumption marker per legacy source: a batch commits all of
            // them or none.
            let tx = AnyShield::decode(bytes, network, application).map_err(decode)?;
            entry.consumptions = shield_markers(&tx)?;
            entry.outputs = output_addresses(&context, frame, tx.outputs())?;
            entry.fee = tx.fee();
        }
        TYPE_LATTICE_MINT_CLAIM => {
            let claim = MintClaim::decode(bytes, network, application).map_err(decode)?;
            entry.consumptions = vec![claim.receipt];
            entry.outputs = output_addresses(&context, frame, &claim.outputs)?;
            entry.fee = claim.fee;
        }
        TYPE_LATTICE_SETTLEMENT => {
            let tx = Settlement::decode(bytes, network, application).map_err(decode)?;
            funding(
                &mut entry,
                &tx.statement.funding,
                &tx.statement.funding.outputs,
            )?;
            // The operation's own gas; the settlement amount is not a fee.
            entry.fee = tx.statement.fee;
            entry.settlement = Some(settlement_record::entry(&tx.statement)?);
        }
        _ => {
            return Err(invalid(
                "operation is not relayed through the global commit",
            ))
        }
    }
    // Enforce the relay's own bounds here, where a malformed entry is the
    // executing shard's error, not the global frame's.
    entry.encode()?;
    Ok(entry)
}

/// The network an operation's bytes name, where every confidential
/// operation carries it (as [`super::wire::fee`] reads it).
pub fn operation_network(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.get(12..44)?.try_into().ok()
}

/// What a relayed operation of `application` needs of GLOBAL state to
/// commit, as its [`spend_entry`] (or, for a custom mint, [`commit_entry`])
/// states it, read from its bytes against the network they name: decoding
/// only, no proof and no state. A custom mint's consumptions here are its
/// receipt alone; its entitlement marker depends on its deployed policy
/// ([`custom_mint::commit_consumptions`]). Spend entries' frame-dependent
/// parts (output and escrow addresses) are not needed and not read. `None`
/// for bytes that do not decode as such an operation.
pub fn commit_needs(application: &[u8; 32], tp: u32, bytes: &[u8]) -> Option<CommitNeeds> {
    let network = operation_network(bytes)?;
    let context = parameter_context(&network, application);
    let mut needs = CommitNeeds {
        context,
        ..Default::default()
    };
    let funded = |needs: &mut CommitNeeds, s: &TransferStatement| -> Option<()> {
        needs.root_digest = Some(funding_root(&needs.context, s));
        needs.consumptions = image_markers(s).ok()?;
        Some(())
    };
    match tp {
        TYPE_LATTICE_TRANSACTION => funded(
            &mut needs,
            &Transfer::decode(bytes, &network, application)
                .ok()?
                .statement,
        )?,
        TYPE_LATTICE_PENDING => funded(
            &mut needs,
            &PendingCreate::decode(bytes, &network, application)
                .ok()?
                .statement
                .funding,
        )?,
        TYPE_LATTICE_SETTLEMENT => funded(
            &mut needs,
            &Settlement::decode(bytes, &network, application)
                .ok()?
                .statement
                .funding,
        )?,
        TYPE_LATTICE_SHIELD => {
            needs.consumptions =
                shield_markers(&AnyShield::decode(bytes, &network, application).ok()?).ok()?
        }
        TYPE_LATTICE_MINT_CLAIM => {
            needs.consumptions = vec![
                MintClaim::decode(bytes, &network, application)
                    .ok()?
                    .receipt,
            ]
        }
        TYPE_LATTICE_PENDING_CLAIM => {
            needs.escrow_claim = Some(escrow_claim(
                &context,
                &PendingClaim::decode(bytes, &network, application)
                    .ok()?
                    .statement,
            ))
        }
        TYPE_LATTICE_MINT if application != &domains::QUIL_TOKEN => {
            needs.consumptions = vec![custom_mint::receipt_address(
                &CustomMint::decode(bytes, &network, application)
                    .ok()?
                    .statement,
            )
            .ok()?]
        }
        _ => return None,
    }
    Some(needs)
}

/// Operations naming owners, one per type that creates or authorizes coins,
/// with the owners a test sets (tests).
#[cfg(test)]
pub(crate) mod owner_fixtures {
    use super::*;
    use quil_lattice_ct::confidential::{
        custom_mint::CustomMintStatement,
        memo::EscrowRecoveryMemo,
        mint::{MintStatement, RewardClaim, FALCON_PUBLIC_BYTES, FALCON_SIGNATURE_BYTES},
        pending_claim::EscrowPolicy,
        pending_create::PendingCreateStatement,
        relation::membership::{Node, NODE_BYTES},
        settlement::SettlementStatement,
        shield::{Shield, ShieldStatement},
        transfer::MEMO_BYTES,
        AmountOpening, CommitmentKey,
    };

    /// The network every fixture names.
    pub(crate) const NETWORK: [u8; 32] = [1; 32];
    /// The custom token the custom mint fixture issues.
    pub(crate) const CUSTOM: [u8; 32] = [8; 32];

    /// Each fixture's (type, application, whether each owner slot is a
    /// coin's): a pending create's escrowed output and refund recovery are
    /// not coins, and a QUIL reward mint only authorizes its outputs.
    pub(crate) fn cases() -> [(u32, [u8; 32], &'static [bool]); 8] {
        let quil = domains::QUIL_TOKEN;
        [
            (TYPE_LATTICE_TRANSACTION, quil, &[true, true]),
            (TYPE_LATTICE_PENDING, quil, &[false, true, false]),
            (TYPE_LATTICE_PENDING_CLAIM, quil, &[true]),
            (TYPE_LATTICE_SHIELD, quil, &[true]),
            (TYPE_LATTICE_MINT_CLAIM, quil, &[true]),
            (TYPE_LATTICE_MINT, CUSTOM, &[true]),
            (TYPE_LATTICE_SETTLEMENT, quil, &[true]),
            (TYPE_LATTICE_MINT, quil, &[false]),
        ]
    }

    /// A coin of `application` owned by `owner`.
    fn coin(application: &[u8; 32], owner: [u8; IDENTITY_BYTES]) -> Output {
        let context = parameter_context(&NETWORK, application);
        Output {
            owner,
            commitment: CommitmentKey::derive(&context)
                .commit(6, &AmountOpening::from_seed(&context, &[6; 32])),
            memo: [6; MEMO_BYTES],
        }
    }

    /// Fixture `case` of [`cases`], its owner slots holding `o`.
    pub(crate) fn encode(case: usize, o: &[[u8; IDENTITY_BYTES]]) -> Vec<u8> {
        let quil = domains::QUIL_TOKEN;
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        let funding = |outputs: Vec<Output>, fee: u128| TransferStatement {
            network: NETWORK,
            application: quil,
            depth: 1,
            root: Node::from_bytes(&[0; NODE_BYTES]).unwrap(),
            images: vec![[5; IDENTITY_BYTES]],
            outputs,
            fee,
        };
        let policy = EscrowPolicy {
            recipient: [7; FALCON_PUBLIC_BYTES],
            refund: [8; FALCON_PUBLIC_BYTES],
            refund_after_global_frame: 100,
        };
        match case {
            0 => Transfer {
                statement: funding(vec![coin(&quil, o[0]), coin(&quil, o[1])], 2),
                proof: proof.clone(),
            }
            .encode(),
            1 => PendingCreate {
                statement: PendingCreateStatement {
                    funding: funding(vec![coin(&quil, o[0]), coin(&quil, o[1])], 2),
                    policy: policy.clone(),
                    refund_recovery: EscrowRecoveryMemo {
                        owner: o[2],
                        ciphertext: [10; MEMO_BYTES],
                    },
                },
                proof: proof.clone(),
            }
            .encode(),
            2 => PendingClaim {
                statement: PendingClaimStatement {
                    network: NETWORK,
                    application: quil,
                    escrow_address: [15; 32],
                    source: coin(&quil, o[0]).commitment,
                    policy: policy.clone(),
                    branch: ClaimBranch::Recipient,
                    fee: 2,
                    outputs: vec![coin(&quil, o[0])],
                },
                signature: [0; FALCON_SIGNATURE_BYTES],
                proof: proof.clone(),
            }
            .encode(),
            3 => Shield {
                statement: ShieldStatement {
                    network: NETWORK,
                    application: quil,
                    transparent_address: [6; 32],
                    owner_public_key: [7; 57],
                    amount: 12,
                    fee: 2,
                    outputs: vec![coin(&quil, o[0])],
                },
                signature: [0; 114],
                proof: proof.clone(),
            }
            .encode(),
            4 => MintClaim {
                network: NETWORK,
                application: quil,
                cited_global_frame: 1,
                global_root: [3; 32],
                receipt: [9; 32],
                fee: 0,
                outputs: vec![coin(&quil, o[0])],
                forest_proof: vec![4; 8],
            }
            .encode(),
            5 => CustomMint {
                statement: CustomMintStatement {
                    network: NETWORK,
                    application: CUSTOM,
                    authority_key_type: 0,
                    authority_public_key: Vec::new(),
                    entitlement_proof: Vec::new(),
                    nonce: [9; 32],
                    amount: 10,
                    outputs: vec![coin(&CUSTOM, o[0])],
                },
                signature: Vec::new(),
                proof: proof.clone(),
            }
            .encode(),
            6 => Settlement {
                statement: SettlementStatement {
                    funding: funding(vec![coin(&quil, o[0])], 7 + 1_000),
                    fee: 7,
                    settlement: 1_000,
                    destination: [137; 32],
                    context: [138; 32],
                    payment: None,
                    claimant: None,
                },
                proof: proof.clone(),
            }
            .encode(),
            _ => Mint {
                statement: MintStatement {
                    network: NETWORK,
                    application: quil,
                    cited_frame: 1,
                    reward_root: [8; 32],
                    fee: 2,
                    claims: vec![RewardClaim {
                        owner: [8; 32],
                        value: 18,
                        public_key: [0; FALCON_PUBLIC_BYTES],
                        forest_proof: vec![1],
                    }],
                    outputs: vec![coin(&quil, o[0])],
                },
                signatures: vec![[0; FALCON_SIGNATURE_BYTES]],
                proof: proof.clone(),
            }
            .encode(),
        }
        .unwrap()
    }
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
            commitment: CommitmentKey::derive(context).commit(
                u128::from(seed),
                &AmountOpening::from_seed(context, &[seed; 32]),
            ),
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
            network,
            application,
            depth: 32,
            root: root.clone(),
            images: vec![[4; IDENTITY_BYTES], [5; IDENTITY_BYTES]],
            outputs: vec![output(&context, 6), output(&context, 7)],
            fee: 9,
        };
        let bytes = Transfer {
            statement: statement.clone(),
            proof: proof(),
        }
        .encode()
        .unwrap();
        let entry =
            spend_entry(&network, &application, TYPE_LATTICE_TRANSACTION, &bytes, 55).unwrap();
        assert_eq!(entry.kind, TYPE_LATTICE_TRANSACTION);
        assert_eq!(entry.tx_id, global_commit::tx_id(&bytes));
        assert_eq!(entry.source_frame, 55);
        assert_eq!(
            entry.root_digest,
            Some(roots::root_digest(&context, 32, &root))
        );
        assert_eq!(
            entry.consumptions,
            vec![
                spent::marker_address(&network, &application, &[4; IDENTITY_BYTES]).unwrap(),
                spent::marker_address(&network, &application, &[5; IDENTITY_BYTES]).unwrap(),
            ]
        );
        assert_eq!(
            entry.outputs,
            vec![
                coin_identity(&context, 55, &statement.outputs[0])
                    .unwrap()
                    .0,
                coin_identity(&context, 55, &statement.outputs[1])
                    .unwrap()
                    .0,
            ]
        );
        assert_eq!(entry.fee, 9);
        // The same operation executed at another frame creates other addresses
        // but consumes the same markers — so only one of the two can commit.
        let later =
            spend_entry(&network, &application, TYPE_LATTICE_TRANSACTION, &bytes, 56).unwrap();
        assert_ne!(later.outputs, entry.outputs);
        assert_eq!(later.consumptions, entry.consumptions);
        // A relayed entry is small, and round-trips.
        let encoded = entry.encode().unwrap();
        assert!(encoded.len() < 300, "{} bytes", encoded.len());
        assert_eq!(SpendEntry::decode(&encoded).unwrap(), entry);
        // Non-relayed types are refused.
        assert!(spend_entry(&network, &application, 0x0513, &bytes, 55).is_err());
    }

    /// Every owner an operation names reaches the canonical owner check,
    /// and the ungated check takes exactly the coins a fold takes. One fixture
    /// per type that creates or authorizes coins, each owner slot made
    /// non-canonical in turn.
    #[test]
    fn every_owner_an_operation_names_reaches_the_canonical_check() {
        use super::owner_fixtures::{cases, encode, NETWORK};
        let network = NETWORK;
        let quil = domains::QUIL_TOKEN;
        for (case, (tp, application, coins)) in cases().iter().enumerate() {
            let good = vec![[3; IDENTITY_BYTES]; coins.len()];
            let bytes = encode(case, &good);
            assert_eq!(
                operation_owners(&network, application, *tp, &bytes).unwrap(),
                good,
                "case {case}"
            );
            check_owners(&network, application, *tp, &bytes).unwrap();
            let named = |bytes: &[u8]| names_noncanonical_owner(&network, application, *tp, bytes);
            assert!(!named(&bytes) && !named(&bytes[1..]), "case {case}");
            let relayed = is_relayed(*tp) || application != &quil;
            if relayed {
                check_coin_owners(&network, application, *tp, &bytes).unwrap();
            }
            for slot in 0..coins.len() {
                let mut owners = good.clone();
                owners[slot] = [0xff; IDENTITY_BYTES];
                let bytes = encode(case, &owners);
                let refused = check_owners(&network, application, *tp, &bytes).unwrap_err();
                assert!(
                    names_noncanonical_owner(&network, application, *tp, &bytes),
                    "READ-AHEAD GAP: case {case} slot {slot}: check_owners refuses an owner the \
                     read-ahead misses"
                );
                assert!(
                    refused.to_string().contains("not a canonical identity"),
                    "case {case} slot {slot}: {refused}"
                );
                if relayed {
                    assert_eq!(
                        check_coin_owners(&network, application, *tp, &bytes).is_err(),
                        coins[slot],
                        "case {case} slot {slot}: the ungated check takes coins only"
                    );
                }
            }
        }
    }

    /// What an operation needs of GLOBAL state, read from its bytes, is what
    /// its spend entry carries (root, consumptions, escrow claim, context),
    /// for a transfer, a shield and a pending claim; nothing is read from the
    /// bytes of another application or type, or bytes that do not decode.
    #[test]
    fn commit_needs_are_the_spend_entrys_read_from_the_bytes() {
        use quil_lattice_ct::confidential::{
            pending_claim::EscrowPolicy,
            shield::{Shield, ShieldStatement},
        };
        let (network, application) = ([1u8; 32], [2u8; 32]);
        let context = parameter_context(&network, &application);
        let transfer = Transfer {
            statement: TransferStatement {
                network,
                application,
                depth: 32,
                root: Node::from_bytes(&[3u8; NODE_BYTES]).unwrap(),
                images: vec![[4; IDENTITY_BYTES], [5; IDENTITY_BYTES]],
                outputs: vec![output(&context, 6)],
                fee: 9,
            },
            proof: proof(),
        }
        .encode()
        .unwrap();
        let shield = Shield {
            statement: ShieldStatement {
                network,
                application,
                transparent_address: [8; 32],
                owner_public_key: [9; 57],
                amount: 12,
                fee: 2,
                outputs: vec![output(&context, 6)],
            },
            signature: [0; 114],
            proof: proof(),
        }
        .encode()
        .unwrap();
        let claim = PendingClaim {
            statement: PendingClaimStatement {
                network,
                application,
                escrow_address: [10; 32],
                source: CommitmentKey::derive(&context)
                    .commit(12, &AmountOpening::from_seed(&context, &[11; 32])),
                policy: EscrowPolicy {
                    recipient: std::array::from_fn(|i| i as u8),
                    refund: std::array::from_fn(|i| !(i as u8)),
                    refund_after_global_frame: 300,
                },
                branch: ClaimBranch::Refund,
                fee: 2,
                outputs: vec![output(&context, 6)],
            },
            signature: std::array::from_fn(|_| 0),
            proof: proof(),
        }
        .encode()
        .unwrap();
        for (tp, bytes) in [
            (TYPE_LATTICE_TRANSACTION, &transfer),
            (TYPE_LATTICE_SHIELD, &shield),
            (TYPE_LATTICE_PENDING_CLAIM, &claim),
        ] {
            let needs = commit_needs(&application, tp, bytes).expect("decodes");
            let entry = spend_entry(&network, &application, tp, bytes, 55).unwrap();
            assert!(
                !needs.consumptions.is_empty() || needs.escrow_claim.is_some(),
                "type {tp:#x} read nothing"
            );
            assert_eq!(
                needs,
                CommitNeeds {
                    context: entry.context,
                    root_digest: entry.root_digest,
                    consumptions: entry.consumptions,
                    escrow_claim: entry.escrow_claim,
                },
                "type {tp:#x}"
            );
            assert!(commit_needs(&[7; 32], tp, bytes).is_none());
            assert!(commit_needs(&application, tp, &bytes[..60]).is_none());
        }
        assert!(commit_needs(&application, TYPE_LATTICE_SHIELD, &transfer).is_none());
        assert!(commit_needs(&application, 0x0513, &transfer).is_none());
    }
}

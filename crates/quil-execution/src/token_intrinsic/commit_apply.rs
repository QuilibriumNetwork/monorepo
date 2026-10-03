//! The commit of an operation whose executing venue is also its commit point:
//! a globally executed application.
//!
//! A split application's operations reach the commit as relayed spend entries
//! and its outputs come back as deliveries. An application the global
//! materializer executes has no shard to relay from or deliver to, so the same
//! three steps happen here in one pass: decide the spend, place what it
//! created, and publish the application's canonical root — the root a later
//! spend's membership proof is checked against, which a split application's
//! shards publish through their headers' accumulator reports.
use super::{
    delivery, global_accumulator, global_commit, shard_accumulator, spend_entries,
    state::{coin_identity, SnapshotLimits},
};
use crate::hypergraph_state::HypergraphState;
use quil_lattice_ct::confidential::transfer::parameter_context;
use quil_types::error::{QuilError, Result};

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("global commit: {message}"))
}

/// Commit one verified operation and apply everything it created. Returns the
/// addresses of the coins it placed, in the entry's output order.
///
/// Verification is the caller's: this decides and writes.
#[allow(clippy::too_many_arguments)]
pub fn commit_and_place(
    state: &HypergraphState,
    frame: u64,
    network: &[u8; 32],
    application: &[u8; 32],
    tp: u32,
    bytes: &[u8],
    limits: SnapshotLimits,
) -> Result<Vec<[u8; 32]>> {
    // Every output, record and root update has to survive the commit's
    // coverage filter together, as it did when shards staged locally.
    state.require_full_domain_coverage(application)?;
    let entry = spend_entries::commit_entry(state, network, application, tp, bytes, frame)?;
    // The venue that executes it is also the one that holds it: the whole
    // application, since a globally executed one is never split.
    let (placements, escrow) = match global_commit::commit_entry(
        state, frame, application, &entry, quil_types::execution::ShardPath::WHOLE)? {
        global_commit::Outcome::Committed { placements, escrow, .. } => (placements, escrow),
        global_commit::Outcome::AlreadyDecided => return Err(invalid("operation already decided")),
        global_commit::Outcome::Rejected(reason) => return Err(invalid(reason)),
    };
    let parameters = parameter_context(network, application);
    let outputs = spend_entries::operation_outputs(network, application, tp, bytes)?;
    if outputs.len() != placements.len() {
        return Err(QuilError::Internal("global commit: placements do not match outputs".into()));
    }
    let mut placed = Vec::with_capacity(placements.len());
    for (output, placement) in outputs.iter().zip(&placements) {
        let (address, tree) = coin_identity(&parameters, frame, output)?;
        if address != placement.address {
            return Err(QuilError::Internal("global commit: placement names another output".into()));
        }
        delivery::place_committed(
            state, frame, network, application, &address, tree,
            placement.block, placement.seq, limits,
        )?;
        placed.push(address);
    }
    // No shard delivers to a globally executed application, so its escrow
    // records are written here, where a delivery would have written them.
    if let Some(placement) = escrow {
        let (address, blob) = delivery::escrow_record(network, application, bytes, frame)?;
        if address != placement.address {
            return Err(QuilError::Internal("global commit: escrow placement names another record".into()));
        }
        delivery::place_committed_escrow(state, frame, application, &address, &blob, placement.block, placement.seq)?;
    }
    publish_canonical_root(state, frame, network, application)?;
    Ok(placed)
}

/// Publish what this venue holds as the application's canonical root, the way
/// a shard's accumulator report does. Without it the application's own history
/// stays empty and the next spend's root is refused as non-canonical.
pub fn publish_canonical_root(
    state: &HypergraphState,
    frame: u64,
    network: &[u8; 32],
    application: &[u8; 32],
) -> Result<()> {
    // The whole application: a globally executed one is never split.
    // The whole application has no narrower block to attest.
    let Some(report) = shard_accumulator::shard_report(state, network, application, &[], false)? else {
        return Ok(());
    };
    global_accumulator::materialize_report(state, frame, application, &report.encode()?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypergraph_state::vertex_adds_discriminator;
    use quil_lattice_ct::confidential::{
        memo::EscrowRecoveryMemo,
        mint_claim::MintClaim,
        pending_claim::EscrowPolicy,
        pending_create::{PendingCreate, PendingCreateStatement},
        relation::membership::IDENTITY_BYTES,
        transfer::{Output, Transfer, TransferStatement, MEMO_BYTES},
        AmountOpening, CommitmentKey,
    };
    use std::sync::Arc;

    const NETWORK: [u8; 32] = [1; 32];
    const APPLICATION: [u8; 32] = [2; 32];

    fn state() -> HypergraphState {
        HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        )))
    }

    fn limits() -> SnapshotLimits {
        SnapshotLimits { max_coins: 64, max_depth: 32, max_nodes: 1 << 12 }
    }

    fn output(seed: u8, amount: u128) -> Output {
        let context = parameter_context(&NETWORK, &APPLICATION);
        Output {
            owner: [seed; IDENTITY_BYTES],
            commitment: CommitmentKey::derive(&context).commit(amount, &AmountOpening::from_seed(&context, &[seed; 32])),
            memo: [seed; MEMO_BYTES],
        }
    }

    fn proof() -> Vec<u8> {
        let mut proof = vec![0; 40];
        proof[..8].copy_from_slice(b"QPF6\0\0\0\0");
        proof
    }

    /// A claim of an authorized reward: the bootstrap that needs no prior root.
    fn mint_claim(receipt: u8, outputs: Vec<Output>) -> Vec<u8> {
        MintClaim {
            network: NETWORK, application: APPLICATION, cited_global_frame: 1, global_root: [3; 32],
            receipt: [receipt; 32], fee: 0, outputs, forest_proof: vec![4; 8],
        }
        .encode()
        .unwrap()
    }

    fn transfer(images: Vec<[u8; IDENTITY_BYTES]>, outputs: Vec<Output>, root: &quil_lattice_ct::confidential::coin_tree::RootRecord) -> Vec<u8> {
        Transfer {
            statement: TransferStatement {
                network: NETWORK, application: APPLICATION, depth: root.depth, root: root.root.clone(),
                images, outputs, fee: 0,
            },
            proof: proof(),
        }
        .encode()
        .unwrap()
    }

    const CLAIM: u32 = crate::token_engine::TYPE_LATTICE_MINT_CLAIM;
    const TRANSFER: u32 = crate::token_engine::TYPE_LATTICE_TRANSACTION;
    const PENDING: u32 = crate::token_engine::TYPE_LATTICE_PENDING;

    /// The whole path a globally executed application takes: coins arrive at
    /// their committed positions, the root that places them becomes canonical,
    /// and the next spend proves against it.
    #[test]
    fn a_global_venue_commits_places_and_publishes_its_own_root() {
        let state = state();
        let disc = vertex_adds_discriminator().unwrap();
        let placed = commit_and_place(&state, 10, &NETWORK, &APPLICATION, CLAIM, &mint_claim(9, vec![output(5, 100)]), limits()).unwrap();
        assert_eq!(placed.len(), 1);
        assert!(state.get(&APPLICATION, &placed[0], &disc).unwrap().is_some());
        // Its position is the one the commit assigned, not an append index.
        let block = super::super::coin_blocks::block_for_address(super::super::coin_blocks::INITIAL_BLOCK_BITS, &placed[0]).unwrap();
        assert_eq!(global_commit::block_sequence(&state, &APPLICATION, block).unwrap(), 1);
        assert_eq!(global_commit::delivery(&state, &APPLICATION, block, 0).unwrap().unwrap().address, placed[0]);

        // The root the placement produced is published as canonical, so a
        // transfer against it is not refused as citing an unknown root.
        let root = super::super::roots::read_current(&state, &NETWORK, &APPLICATION).unwrap().unwrap();
        let spend = transfer(vec![[7; IDENTITY_BYTES]], vec![output(6, 100)], &root);
        let placed = commit_and_place(&state, 11, &NETWORK, &APPLICATION, TRANSFER, &spend, limits()).unwrap();
        assert_eq!(placed.len(), 1);
        assert!(state.get(&APPLICATION, &placed[0], &disc).unwrap().is_some());

        // Spending the same image again is refused by the commit. Its
        // rejection is recorded — a re-carried relay is not judged twice — but
        // nothing it would have created exists, and the root does not move.
        let after = super::super::roots::read_current(&state, &NETWORK, &APPLICATION).unwrap();
        let again = transfer(vec![[7; IDENTITY_BYTES]], vec![output(8, 100)], &root);
        let error = commit_and_place(&state, 12, &NETWORK, &APPLICATION, TRANSFER, &again, limits()).unwrap_err();
        assert!(matches!(error, QuilError::InvalidArgument(_)), "{error}");
        assert!(error.to_string().contains("already consumed"), "{error}");
        let (rejected_address, _) = coin_identity(&parameter_context(&NETWORK, &APPLICATION), 12, &output(8, 100)).unwrap();
        assert!(state.get(&APPLICATION, &rejected_address, &disc).unwrap().is_none());
        assert_eq!(super::super::roots::read_current(&state, &NETWORK, &APPLICATION).unwrap(), after);
        let error = commit_and_place(&state, 13, &NETWORK, &APPLICATION, TRANSFER, &again, limits()).unwrap_err();
        assert!(error.to_string().contains("already decided"), "{error}");

        // A root that was never published is not canonical.
        let mut unknown = root.clone();
        unknown.root = quil_lattice_ct::confidential::relation::membership::Node::from_bytes(
            &[9; quil_lattice_ct::confidential::relation::membership::NODE_BYTES]).unwrap();
        let stale = transfer(vec![[10; IDENTITY_BYTES]], vec![output(11, 100)], &unknown);
        let error = commit_and_place(&state, 14, &NETWORK, &APPLICATION, TRANSFER, &stale, limits()).unwrap_err();
        assert!(error.to_string().contains("canonical history"), "{error}");
    }

    /// An escrow a globally executed application creates is discoverable: its
    /// record is written where a delivery would have put it, and counted.
    #[test]
    fn an_escrow_created_in_the_global_venue_is_written_and_counted() {
        let state = state();
        let disc = vertex_adds_discriminator().unwrap();
        commit_and_place(&state, 10, &NETWORK, &APPLICATION, CLAIM, &mint_claim(9, vec![output(5, 100)]), limits()).unwrap();
        let root = super::super::roots::read_current(&state, &NETWORK, &APPLICATION).unwrap().unwrap();
        let statement = PendingCreateStatement {
            funding: TransferStatement {
                network: NETWORK, application: APPLICATION, depth: root.depth, root: root.root.clone(),
                images: vec![[12; IDENTITY_BYTES]],
                // The escrowed output first, then the change.
                outputs: vec![output(13, 60), output(14, 40)],
                fee: 0,
            },
            policy: EscrowPolicy { recipient: [15; 897], refund: [16; 897], refund_after_global_frame: 200 },
            refund_recovery: EscrowRecoveryMemo { owner: [17; IDENTITY_BYTES], ciphertext: [18; MEMO_BYTES] },
        };
        let bytes = PendingCreate { statement, proof: proof() }.encode().unwrap();
        let placed = commit_and_place(&state, 11, &NETWORK, &APPLICATION, PENDING, &bytes, limits()).unwrap();
        // Only the change is a coin; the escrow is its own record.
        assert_eq!(placed.len(), 1);
        let (address, blob) = delivery::escrow_record(&NETWORK, &APPLICATION, &bytes, 11).unwrap();
        assert_eq!(state.get(&APPLICATION, &address, &disc).unwrap(), Some(blob));
        let block = super::super::coin_blocks::block_for_address(super::super::coin_blocks::INITIAL_BLOCK_BITS, &address).unwrap();
        assert_eq!(delivery::escrow_count(&state, &APPLICATION, block).unwrap(), 1);
        // And the commit holds it open, bound to its policy.
        let (_, refund_after, consumed) = global_commit::escrow(&state, &APPLICATION, &address).unwrap().unwrap();
        assert_eq!((refund_after, consumed), (200, false));
    }

    /// Partial coverage and an exhausted snapshot budget are refused before
    /// anything is written, as they were when shards staged locally.
    #[test]
    fn a_commit_that_cannot_be_applied_writes_nothing() {
        let state = state();
        let bytes = mint_claim(9, vec![output(5, 100)]);
        state.crdt().set_covered_prefix(&quil_tries::get_full_path(&APPLICATION)).unwrap();
        let saved = state.changeset_len();
        assert!(matches!(
            commit_and_place(&state, 10, &NETWORK, &APPLICATION, CLAIM, &bytes, limits()),
            Err(QuilError::ExecutionUnavailable(_))
        ));
        assert_eq!(state.changeset_len(), saved);
        state.crdt().set_covered_prefix(&[]).unwrap();
        assert!(commit_and_place(&state, 10, &NETWORK, &APPLICATION, CLAIM, &bytes,
            SnapshotLimits { max_coins: 0, ..limits() }).is_err());
        assert!(super::super::roots::read_current(&state, &NETWORK, &APPLICATION).unwrap().is_none());
    }
}

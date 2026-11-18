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

/// What [`commit_and_place`] would refuse operation `bytes` (type `tp`) of
/// `application` for at GLOBAL frame `frame`, read from `state` without
/// writing and without verifying its proof: the same error, so the venue
/// can refuse it before the proof work its commit would only waste. `None`
/// when the commit would accept it, or when what it reads cannot be read
/// (the commit then decides as before).
pub fn refused_before_proof(
    state: &HypergraphState,
    frame: u64,
    network: &[u8; 32],
    application: &[u8; 32],
    tp: u32,
    bytes: &[u8],
) -> Option<QuilError> {
    // `commit_and_place` refuses a coin whose owner is not canonical first,
    // at every frame, from the bytes alone.
    if let Err(error) = spend_entries::check_coin_owners(network, application, tp, bytes) {
        return Some(error);
    }
    let entry = spend_entries::commit_entry(state, network, application, tp, bytes, frame).ok()?;
    global_commit::refusal(
        state,
        frame,
        application,
        &entry,
        quil_types::execution::ShardPath::WHOLE,
    )
    .ok()
    .flatten()
    .map(invalid)
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
    // A coin whose owner is not a canonical identity failed this venue's fold
    // and the operation was skipped. The fold now burns such a coin (as a
    // split application's owning shard must), so the refusal is made here,
    // before anything is written: the same outcome on every build.
    spend_entries::check_coin_owners(network, application, tp, bytes)?;
    let entry = spend_entries::commit_entry(state, network, application, tp, bytes, frame)?;
    // The venue that executes it is also the one that holds it: the whole
    // application, since a globally executed one is never split.
    let (placements, escrow) = match global_commit::commit_entry(
        state,
        frame,
        application,
        &entry,
        quil_types::execution::ShardPath::WHOLE,
    )? {
        global_commit::Outcome::Committed {
            placements, escrow, ..
        } => (placements, escrow),
        global_commit::Outcome::AlreadyDecided => return Err(invalid("operation already decided")),
        global_commit::Outcome::Rejected(reason) => return Err(invalid(reason)),
    };
    let parameters = parameter_context(network, application);
    let outputs = spend_entries::operation_outputs(network, application, tp, bytes)?;
    if outputs.len() != placements.len() {
        return Err(QuilError::Internal(
            "global commit: placements do not match outputs".into(),
        ));
    }
    let mut placed = Vec::with_capacity(placements.len());
    for (output, placement) in outputs.iter().zip(&placements) {
        let (address, tree) = coin_identity(&parameters, frame, output)?;
        if address != placement.address {
            return Err(QuilError::Internal(
                "global commit: placement names another output".into(),
            ));
        }
        // A globally executed application is never split: its store holds
        // every block.
        delivery::place_committed(
            state,
            frame,
            network,
            application,
            &address,
            tree,
            placement.block,
            placement.seq,
            &[],
            limits,
        )?;
        placed.push(address);
    }
    // Once per operation, not per frame: the canonical root it publishes below
    // is GLOBAL state, and has to take this operation's coins.
    super::roots::fold_placed(state, frame, network, application, limits)?;
    // No shard delivers to a globally executed application, so its escrow
    // records are written here, where a delivery would have written them.
    if let Some(placement) = escrow {
        let (address, blob) = delivery::escrow_record(network, application, bytes, frame)?;
        if address != placement.address {
            return Err(QuilError::Internal(
                "global commit: escrow placement names another record".into(),
            ));
        }
        delivery::place_committed_escrow(
            state,
            frame,
            application,
            &address,
            &blob,
            placement.block,
            placement.seq,
        )?;
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
    let Some(report) = shard_accumulator::shard_report(state, network, application, &[], false)?
    else {
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
        SnapshotLimits {
            max_coins: 64,
            max_depth: 32,
            max_nodes: 1 << 12,
        }
    }

    fn output(seed: u8, amount: u128) -> Output {
        let context = parameter_context(&NETWORK, &APPLICATION);
        Output {
            owner: [seed; IDENTITY_BYTES],
            commitment: CommitmentKey::derive(&context)
                .commit(amount, &AmountOpening::from_seed(&context, &[seed; 32])),
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
            network: NETWORK,
            application: APPLICATION,
            cited_global_frame: 1,
            global_root: [3; 32],
            receipt: [receipt; 32],
            fee: 0,
            outputs,
            forest_proof: vec![4; 8],
        }
        .encode()
        .unwrap()
    }

    fn transfer(
        images: Vec<[u8; IDENTITY_BYTES]>,
        outputs: Vec<Output>,
        root: &quil_lattice_ct::confidential::coin_tree::RootRecord,
    ) -> Vec<u8> {
        Transfer {
            statement: TransferStatement {
                network: NETWORK,
                application: APPLICATION,
                depth: root.depth,
                root: root.root.clone(),
                images,
                outputs,
                fee: 0,
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
        let placed = commit_and_place(
            &state,
            10,
            &NETWORK,
            &APPLICATION,
            CLAIM,
            &mint_claim(9, vec![output(5, 100)]),
            limits(),
        )
        .unwrap();
        assert_eq!(placed.len(), 1);
        assert!(state
            .get(&APPLICATION, &placed[0], &disc)
            .unwrap()
            .is_some());
        // Its position is the one the commit assigned, not an append index.
        let block = super::super::coin_blocks::block_for_address(
            super::super::coin_blocks::INITIAL_BLOCK_BITS,
            &placed[0],
        )
        .unwrap();
        assert_eq!(
            global_commit::block_sequence(&state, &APPLICATION, block).unwrap(),
            1
        );
        assert_eq!(
            global_commit::delivery(&state, &APPLICATION, block, 0)
                .unwrap()
                .unwrap()
                .address,
            placed[0]
        );

        // The root the placement produced is published as canonical, so a
        // transfer against it is not refused as citing an unknown root.
        let root = super::super::roots::read_current(&state, &NETWORK, &APPLICATION)
            .unwrap()
            .unwrap();
        let spend = transfer(vec![[7; IDENTITY_BYTES]], vec![output(6, 100)], &root);
        let placed = commit_and_place(
            &state,
            11,
            &NETWORK,
            &APPLICATION,
            TRANSFER,
            &spend,
            limits(),
        )
        .unwrap();
        assert_eq!(placed.len(), 1);
        assert!(state
            .get(&APPLICATION, &placed[0], &disc)
            .unwrap()
            .is_some());

        // Spending the same image again is refused by the commit. Its
        // rejection is recorded — a re-carried relay is not judged twice — but
        // nothing it would have created exists, and the root does not move.
        let after = super::super::roots::read_current(&state, &NETWORK, &APPLICATION).unwrap();
        let again = transfer(vec![[7; IDENTITY_BYTES]], vec![output(8, 100)], &root);
        let error = commit_and_place(
            &state,
            12,
            &NETWORK,
            &APPLICATION,
            TRANSFER,
            &again,
            limits(),
        )
        .unwrap_err();
        assert!(matches!(error, QuilError::InvalidArgument(_)), "{error}");
        assert!(error.to_string().contains("already consumed"), "{error}");
        let (rejected_address, _) = coin_identity(
            &parameter_context(&NETWORK, &APPLICATION),
            12,
            &output(8, 100),
        )
        .unwrap();
        assert!(state
            .get(&APPLICATION, &rejected_address, &disc)
            .unwrap()
            .is_none());
        assert_eq!(
            super::super::roots::read_current(&state, &NETWORK, &APPLICATION).unwrap(),
            after
        );
        let error = commit_and_place(
            &state,
            13,
            &NETWORK,
            &APPLICATION,
            TRANSFER,
            &again,
            limits(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("already decided"), "{error}");

        // A root that was never published is not canonical.
        let mut unknown = root.clone();
        unknown.root = quil_lattice_ct::confidential::relation::membership::Node::from_bytes(
            &[9; quil_lattice_ct::confidential::relation::membership::NODE_BYTES],
        )
        .unwrap();
        let stale = transfer(vec![[10; IDENTITY_BYTES]], vec![output(11, 100)], &unknown);
        let error = commit_and_place(
            &state,
            14,
            &NETWORK,
            &APPLICATION,
            TRANSFER,
            &stale,
            limits(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("canonical history"), "{error}");
    }

    /// An escrow a globally executed application creates is discoverable: its
    /// record is written where a delivery would have put it, and counted.
    #[test]
    fn an_escrow_created_in_the_global_venue_is_written_and_counted() {
        let state = state();
        let disc = vertex_adds_discriminator().unwrap();
        commit_and_place(
            &state,
            10,
            &NETWORK,
            &APPLICATION,
            CLAIM,
            &mint_claim(9, vec![output(5, 100)]),
            limits(),
        )
        .unwrap();
        let root = super::super::roots::read_current(&state, &NETWORK, &APPLICATION)
            .unwrap()
            .unwrap();
        let statement = PendingCreateStatement {
            funding: TransferStatement {
                network: NETWORK,
                application: APPLICATION,
                depth: root.depth,
                root: root.root.clone(),
                images: vec![[12; IDENTITY_BYTES]],
                // The escrowed output first, then the change.
                outputs: vec![output(13, 60), output(14, 40)],
                fee: 0,
            },
            policy: EscrowPolicy {
                recipient: [15; 897],
                refund: [16; 897],
                refund_after_global_frame: 200,
            },
            refund_recovery: EscrowRecoveryMemo {
                owner: [17; IDENTITY_BYTES],
                ciphertext: [18; MEMO_BYTES],
            },
        };
        let bytes = PendingCreate {
            statement,
            proof: proof(),
        }
        .encode()
        .unwrap();
        let placed = commit_and_place(
            &state,
            11,
            &NETWORK,
            &APPLICATION,
            PENDING,
            &bytes,
            limits(),
        )
        .unwrap();
        // Only the change is a coin; the escrow is its own record.
        assert_eq!(placed.len(), 1);
        let (address, blob) = delivery::escrow_record(&NETWORK, &APPLICATION, &bytes, 11).unwrap();
        assert_eq!(
            state.get(&APPLICATION, &address, &disc).unwrap(),
            Some(blob)
        );
        let block = super::super::coin_blocks::block_for_address(
            super::super::coin_blocks::INITIAL_BLOCK_BITS,
            &address,
        )
        .unwrap();
        assert_eq!(
            delivery::escrow_count(&state, &APPLICATION, block).unwrap(),
            1
        );
        // And the commit holds it open, bound to its policy.
        let (_, refund_after, consumed) = global_commit::escrow(&state, &APPLICATION, &address)
            .unwrap()
            .unwrap();
        assert_eq!((refund_after, consumed), (200, false));
    }

    /// Partial coverage and an exhausted snapshot budget are refused before
    /// anything is written, as they were when shards staged locally.
    #[test]
    fn a_commit_that_cannot_be_applied_writes_nothing() {
        let state = state();
        let bytes = mint_claim(9, vec![output(5, 100)]);
        state
            .crdt()
            .set_covered_prefix(&quil_tries::get_full_path(&APPLICATION))
            .unwrap();
        let saved = state.changeset_len();
        assert!(matches!(
            commit_and_place(&state, 10, &NETWORK, &APPLICATION, CLAIM, &bytes, limits()),
            Err(QuilError::ExecutionUnavailable(_))
        ));
        assert_eq!(state.changeset_len(), saved);
        state.crdt().set_covered_prefix(&[]).unwrap();
        assert!(commit_and_place(
            &state,
            10,
            &NETWORK,
            &APPLICATION,
            CLAIM,
            &bytes,
            SnapshotLimits {
                max_coins: 0,
                ..limits()
            }
        )
        .is_err());
        assert!(
            super::super::roots::read_current(&state, &NETWORK, &APPLICATION)
                .unwrap()
                .is_none()
        );
    }

    /// An output no fold can take: one owner coefficient is 2^38 - 1 >= P.
    fn noncanonical_output(memo: u8) -> Output {
        Output {
            owner: [0xff; IDENTITY_BYTES],
            ..output(memo, 100)
        }
    }

    /// A split application's GLOBAL view, bootstrapped by a reward claim
    /// committed in the global venue, which publishes the canonical root a
    /// transfer cites. Returns the state, the root and its coin's block.
    fn split_bootstrap() -> (
        HypergraphState,
        quil_lattice_ct::confidential::coin_tree::RootRecord,
        u64,
    ) {
        let global = state();
        let claim = mint_claim(9, vec![output(5, 100)]);
        let placed =
            commit_and_place(&global, 10, &NETWORK, &APPLICATION, CLAIM, &claim, limits()).unwrap();
        let root = super::super::roots::read_current(&global, &NETWORK, &APPLICATION)
            .unwrap()
            .unwrap();
        let width = super::super::coin_blocks::INITIAL_BLOCK_BITS;
        let block = super::super::coin_blocks::block_for_address(width, &placed[0]).unwrap();
        (global, root, block)
    }

    /// Commit a transfer relayed from a split shard, as the global
    /// materializer does. The source shard's checks never read an output
    /// owner, so its verdict is the decode's.
    fn relay(
        global: &HypergraphState,
        bytes: &[u8],
    ) -> std::result::Result<Vec<global_commit::Placement>, String> {
        let entry =
            spend_entries::commit_entry(global, &NETWORK, &APPLICATION, TRANSFER, bytes, 11)
                .map_err(|e| format!("refused at decode: {e}"))?;
        let source = quil_types::execution::ShardPath::from_bits(&[false]);
        let outcome = global_commit::commit_entry(global, 11, &APPLICATION, &entry, source)
            .map_err(|e| format!("GLOBAL commit error: {e}"))?;
        match outcome {
            global_commit::Outcome::Committed { placements, .. } => Ok(placements),
            other => Err(format!("GLOBAL commit outcome: {other:?}")),
        }
    }

    /// Reproducer. A transfer's output owners are never checked canonical
    /// at decode: the source shard verifies and relays it, GLOBAL reserves
    /// its outputs' delivery sequences, and the owner is first parsed when
    /// the owning shard folds the frame's coins. That fold fails, so
    /// `commit_frame_with_app_history` fails for the certified frame on every
    /// replica, the cursor is held and the frame is retried forever: the
    /// shard halts. A fixed node refuses the transfer before GLOBAL reserves
    /// a sequence, or lands and folds every honest coin of the frame.
    #[test]
    fn reproduces_a_noncanonical_owner_wedging_the_owning_shard() {
        use super::super::{coin_blocks, roots};
        use quil_lattice_ct::confidential::relation::membership::Node;
        let parameters = parameter_context(&NETWORK, &APPLICATION);
        let block_of = |output: &Output| {
            let (address, _) = coin_identity(&parameters, 11, output).unwrap();
            coin_blocks::block_for_address(coin_blocks::INITIAL_BLOCK_BITS, &address).unwrap()
        };
        let canonical = |seed: u8| {
            let o = output(seed, 100);
            Node::from_identity_bytes(&o.owner).is_ok().then_some(o)
        };
        let (_, _, bootstrap_block) = split_bootstrap();
        assert!(
            Node::from_identity_bytes(&noncanonical_output(1).owner).is_err(),
            "precondition: the owner is non-canonical"
        );
        let bad = (1..=200u8)
            .map(noncanonical_output)
            .find(|o| block_of(o) != bootstrap_block)
            .unwrap();
        let wedged = block_of(&bad);
        let behind = (20..=200u8)
            .filter_map(canonical)
            .find(|o| block_of(o) == wedged)
            .expect("an honest coin shares the block among 181");
        let elsewhere = (20..=200u8)
            .filter_map(canonical)
            .find(|o| ![wedged, bootstrap_block].contains(&block_of(o)))
            .unwrap();

        // Control: the same transfer with a canonical owner commits, so a
        // refusal below is the owner's.
        let (control, root, _) = split_bootstrap();
        let twin = Output {
            owner: [3; IDENTITY_BYTES],
            ..bad.clone()
        };
        let twin_tx = transfer(vec![[7; IDENTITY_BYTES]], vec![twin], &root);
        relay(&control, &twin_tx).expect("control: a canonical twin commits");

        let (global, root, _) = split_bootstrap();
        let bad_tx = transfer(vec![[7; IDENTITY_BYTES]], vec![bad.clone()], &root);
        let reserved = match relay(&global, &bad_tx) {
            Ok(placements) => placements,
            Err(refused) => {
                eprintln!("refused before GLOBAL reserved a sequence: {refused}");
                return;
            }
        };
        let outputs = vec![behind.clone(), elsewhere.clone()];
        let honest_tx = transfer(vec![[10; IDENTITY_BYTES]], outputs, &root);
        let honest = relay(&global, &honest_tx).expect("an honest transfer commits");
        assert_eq!((reserved[0].block, reserved[0].seq), (wedged, 0));
        assert_eq!((honest[0].block, honest[0].seq), (wedged, 1));
        let deliveries = [
            (&bad, &reserved[0]),
            (&behind, &honest[0]),
            (&elsewhere, &honest[1]),
        ];

        // The owning shard takes the frame's deliveries, one message each,
        // and folds them at the frame's end, as the app materializer does.
        let deliver = |skip_bad: bool| {
            let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
                Arc::new(quil_hypergraph::testing::MemStore::new()),
                Arc::new(quil_types::crypto::NoopInclusionProver),
            ));
            let message = HypergraphState::new(crdt.clone());
            let mut placed = Vec::new();
            for (output, placement) in deliveries.iter().skip(usize::from(skip_bad)) {
                let (address, tree) = coin_identity(&parameters, 11, output).unwrap();
                assert_eq!(address, placement.address);
                let result = delivery::place_committed(
                    &message,
                    20,
                    &NETWORK,
                    &APPLICATION,
                    &address,
                    tree,
                    placement.block,
                    placement.seq,
                    &[],
                    limits(),
                );
                placed.push(result.map_err(|e| e.to_string()));
                message.commit().unwrap();
                message.abort();
            }
            let end = HypergraphState::new(crdt);
            let folded = roots::fold_placed(&end, 20, &NETWORK, &APPLICATION, limits())
                .map_err(|e| e.to_string());
            (end, placed, folded)
        };
        let (end, placed, folded) = deliver(false);
        if let Err(error) = &folded {
            let (_, _, replayed) = deliver(false);
            let (_, without, _) = deliver(true);
            panic!(
                "WEDGED SHARD: GLOBAL reserved block {wedged} seq 0 for a coin whose owner is \
                 non-canonical; the owning shard placed it ({:?}) and the frame's fold fails \
                 ({error}). A fresh replica replaying the frame fails the same way \
                 ({replayed:?}), and without it the block's next honest coin is refused \
                 ({:?}). commit_frame_with_app_history returns this error on every replica, \
                 so the certified frame retries forever and the shard halts",
                placed[0], without[0]
            );
        }
        let disc = vertex_adds_discriminator().unwrap();
        let landed = |output: &Output| {
            let (address, _) = coin_identity(&parameters, 11, output).unwrap();
            end.get(&APPLICATION, &address, &disc).unwrap().is_some()
        };
        assert!(
            landed(&behind) && landed(&elsewhere),
            "PERMANENT REFUSAL: the frame folds but an honest coin of it never lands \
             ({placed:?}); the block's later coins wait behind the refused one"
        );
    }

    /// A globally executed application: the same output, committed and
    /// placed in the global venue, is refused (by its failing fold on the
    /// release base, before anything is written once fixed), and the
    /// engine's per-operation rollback leaves nothing behind. The operation
    /// is skipped (a deterministic error, not an unavailable store) on every
    /// build, so GLOBAL agrees across builds, and the next commit lands.
    #[test]
    fn a_noncanonical_owner_in_the_global_venue_rolls_back_cleanly() {
        use super::super::coin_blocks;
        let parameters = parameter_context(&NETWORK, &APPLICATION);
        let state = state();
        let bad = noncanonical_output(1);
        let (address, _) = coin_identity(&parameters, 10, &bad).unwrap();
        let width = coin_blocks::INITIAL_BLOCK_BITS;
        let block = coin_blocks::block_for_address(width, &address).unwrap();
        let savepoint = state.changeset_len();
        let claim = mint_claim(9, vec![bad]);
        let Err(error) =
            commit_and_place(&state, 10, &NETWORK, &APPLICATION, CLAIM, &claim, limits())
        else {
            panic!(
                "GLOBAL DIVERGENCE: the global venue committed a coin whose owner is \
                 non-canonical; every earlier build fails that operation, so GLOBAL \
                 would disagree across builds"
            );
        };
        assert!(
            !error.is_execution_unavailable(),
            "GLOBAL HALT: the global materializer fails its frame on this error: {error}"
        );
        // What `finish_token_step` does for a failed operation.
        state.rollback_to(savepoint);
        let sequence = global_commit::block_sequence(&state, &APPLICATION, block).unwrap();
        assert_eq!(sequence, 0, "the rollback releases the reserved sequence");
        let record = global_commit::delivery(&state, &APPLICATION, block, 0).unwrap();
        assert!(record.is_none());
        let next = mint_claim(8, vec![output(6, 100)]);
        let placed = commit_and_place(&state, 11, &NETWORK, &APPLICATION, CLAIM, &next, limits())
            .expect("the next commit lands");
        let disc = vertex_adds_discriminator().unwrap();
        assert!(state
            .get(&APPLICATION, &placed[0], &disc)
            .unwrap()
            .is_some());
    }

    /// The global venue refuses a coin whose owner is not canonical before
    /// its proof, with the error its commit refuses it with: the pre-proof
    /// read runs the commit's owner check first. An honest coin stands.
    #[test]
    fn a_noncanonical_coin_owner_is_refused_before_the_proof() {
        let state = state();
        let claim = mint_claim(9, vec![noncanonical_output(1)]);
        let ahead = refused_before_proof(&state, 10, &NETWORK, &APPLICATION, CLAIM, &claim)
            .expect("READ-AHEAD GAP: the commit refuses this coin's owner, the pre-proof read not");
        let commit = commit_and_place(&state, 10, &NETWORK, &APPLICATION, CLAIM, &claim, limits())
            .expect_err("the commit refuses it");
        assert_eq!(ahead.to_string(), commit.to_string());
        let honest = mint_claim(8, vec![output(6, 100)]);
        assert!(refused_before_proof(&state, 10, &NETWORK, &APPLICATION, CLAIM, &honest).is_none());
    }

    /// A node whose store does not cover the whole application refuses a
    /// coin whose owner is not canonical before the proof, at any frame,
    /// with the error every covering node's commit refuses it with: it
    /// records the operation as failed and goes on, as they do, where it
    /// used to verify the proof and then stop the frame at the coverage
    /// check. What needs the coverage still stops it.
    #[test]
    fn a_node_without_full_coverage_refuses_a_noncanonical_owner_as_a_covering_one() {
        let state = state();
        let claim = mint_claim(9, vec![noncanonical_output(1)]);
        let commit = commit_and_place(&state, 10, &NETWORK, &APPLICATION, CLAIM, &claim, limits())
            .expect_err("a covering node's commit refuses it");
        state
            .crdt()
            .set_covered_prefix(&quil_tries::get_full_path(&APPLICATION))
            .unwrap();
        let ahead = refused_before_proof(&state, 10, &NETWORK, &APPLICATION, CLAIM, &claim);
        let plain = mint_claim(8, vec![output(6, 100)]);
        let stops = commit_and_place(&state, 10, &NETWORK, &APPLICATION, CLAIM, &plain, limits());
        state.crdt().set_covered_prefix(&[]).unwrap();
        let ahead = ahead.expect(
            "READ-AHEAD GAP: a node without full coverage verifies the proof of a coin every \
             commit refuses, then stops the frame",
        );
        assert_eq!(
            ahead.to_string(),
            commit.to_string(),
            "a node without full coverage records another outcome"
        );
        assert!(!ahead.is_execution_unavailable());
        assert!(
            matches!(stops, Err(QuilError::ExecutionUnavailable(_))),
            "{stops:?}"
        );
    }

    /// Recovery: a delivery GLOBAL already committed with a non-canonical
    /// owner is burned. The owning shard places it, the frame's fold takes
    /// its position as the empty leaf, the block's next honest coin lands
    /// behind it, a fresh replica replaying the frame (a restarted node or an
    /// archive resuming the shard) publishes the same root, and a rebuild
    /// from the stored coins reproduces it.
    #[test]
    fn a_committed_noncanonical_coin_is_burned_and_its_block_goes_on() {
        use super::super::{coin_blocks, roots};
        let parameters = parameter_context(&NETWORK, &APPLICATION);
        let block_of = |output: &Output| {
            let (address, _) = coin_identity(&parameters, 11, output).unwrap();
            coin_blocks::block_for_address(coin_blocks::INITIAL_BLOCK_BITS, &address).unwrap()
        };
        let (_, _, bootstrap_block) = split_bootstrap();
        let bad = (1..=200u8)
            .map(noncanonical_output)
            .find(|o| block_of(o) != bootstrap_block)
            .unwrap();
        let wedged = block_of(&bad);
        let behind = (20..=200u8)
            .map(|seed| output(seed, 100))
            .find(|o| block_of(o) == wedged)
            .expect("an honest coin shares the block among 181");
        let (global, root, _) = split_bootstrap();
        let bad_tx = transfer(vec![[7; IDENTITY_BYTES]], vec![bad.clone()], &root);
        let reserved =
            relay(&global, &bad_tx).expect("committed, as a build without the gate does");
        let honest_tx = transfer(vec![[10; IDENTITY_BYTES]], vec![behind.clone()], &root);
        let honest = relay(&global, &honest_tx).unwrap();
        assert_eq!((reserved[0].block, reserved[0].seq), (wedged, 0));
        assert_eq!((honest[0].block, honest[0].seq), (wedged, 1));
        let replica = || {
            let state = state();
            for (output, placement) in [(&bad, &reserved[0]), (&behind, &honest[0])] {
                let (address, tree) = coin_identity(&parameters, 11, output).unwrap();
                delivery::place_committed(
                    &state,
                    20,
                    &NETWORK,
                    &APPLICATION,
                    &address,
                    tree,
                    placement.block,
                    placement.seq,
                    &[],
                    limits(),
                )
                .expect("each delivery lands in sequence");
            }
            let folded = roots::fold_placed(&state, 20, &NETWORK, &APPLICATION, limits())
                .expect("the frame's fold takes the burned coin")
                .expect("the frame placed coins");
            (state, folded)
        };
        let (state, folded) = replica();
        assert_eq!(folded.coins, 2);
        assert_eq!(
            roots::block_count(&state, &NETWORK, &APPLICATION, wedged, limits()).unwrap(),
            2
        );
        let disc = vertex_adds_discriminator().unwrap();
        assert!(state
            .get(&APPLICATION, &honest[0].address, &disc)
            .unwrap()
            .is_some());
        let (_, replayed) = replica();
        assert_eq!(replayed, folded, "a replica replaying the frame agrees");
        assert_eq!(
            roots::full_rebuild_root(&state, &NETWORK, &APPLICATION, limits()).unwrap(),
            folded,
            "a rebuild from the stored coins reproduces the folded root"
        );
    }

    /// A globally executed application, now that the fold burns such a
    /// coin: the venue still refuses the operation, before writing anything,
    /// as every earlier build did by failing the fold, so GLOBAL agrees across
    /// builds; the next commit lands.
    #[test]
    fn the_global_venue_refuses_a_noncanonical_coin_before_writing() {
        let state = state();
        let savepoint = state.changeset_len();
        let claim = mint_claim(9, vec![output(5, 100), noncanonical_output(1)]);
        let refused = commit_and_place(&state, 10, &NETWORK, &APPLICATION, CLAIM, &claim, limits())
            .unwrap_err();
        assert!(
            matches!(refused, QuilError::InvalidArgument(_)),
            "{refused}"
        );
        assert!(
            refused.to_string().contains("not a canonical identity"),
            "{refused}"
        );
        assert_eq!(state.changeset_len(), savepoint, "nothing was written");
        let next = mint_claim(8, vec![output(6, 100)]);
        commit_and_place(&state, 11, &NETWORK, &APPLICATION, CLAIM, &next, limits())
            .expect("the next commit lands");
    }
}

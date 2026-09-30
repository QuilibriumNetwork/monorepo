//! Delivery of a globally committed output into the block it was placed in.
//!
//! The owning shard's proposer includes one delivery per committed output, in
//! sequence order. Each carries the full output and a membership proof of its
//! GLOBAL delivery record against a global root the frame's anchor has
//! reached. Materialization checks, deterministically from the certified frame
//! alone, that:
//!
//! * the shard owns the block;
//! * the cited root is the canonical root of a global frame at or before the
//!   frame's anchor;
//! * the record is proven at that root, and names this output: its address is
//!   recomputed from the output and the operation's source frame;
//! * the sequence number is exactly the block's next local index.
//!
//! Then it writes the coin at its committed position and extends the block.
//! A delivery that fails any check is skipped identically by every replica;
//! a later proposer includes it again.
use super::{
    coin_blocks, global_commit, roots, spend_entries,
    state::{coin_identity, place_coin, SnapshotLimits},
};
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
use quil_lattice_ct::confidential::{
    relation::membership::IDENTITY_BYTES,
    transfer::{parameter_context, Output, MEMO_BYTES},
    AmountCommitment, COMMITMENT_BYTES,
};
use quil_types::{
    error::{QuilError, Result},
    execution::FrameExecutionContext,
    store::ClockStore,
};

pub use super::constants::TYPE_COIN_DELIVERY;

pub const DELIVERY_VERSION: &[u8; 8] = b"QCT3DL\0\x01";
/// The same envelope delivering a committed escrow record instead of a coin.
pub const ESCROW_DELIVERY_VERSION: &[u8; 8] = b"QCT3DE\0\x01";
/// Deliveries one frame includes: bounds frame size (each carries a ~15 KB
/// output or ~20 KB escrow, and a proof).
pub const MAX_DELIVERIES_PER_FRAME: usize = 64;
/// Envelope, network, application, cited frame, root, block, seq, source
/// frame, tx id.
const HEADER_BYTES: usize = 4 + 8 + 32 + 32 + 8 + 32 + 8 + 8 + 8 + 32 + 9;
const OUTPUT_BYTES: usize = IDENTITY_BYTES + COMMITMENT_BYTES + MEMO_BYTES;

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("coin delivery: {message}"))
}

/// What a delivery places.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Delivered {
    /// A committed output, at its committed position.
    Coin(Output),
    /// A committed escrow's canonical record blob (`escrow::StoredEscrow`).
    Escrow(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinDelivery {
    pub network: [u8; 32],
    pub application: [u8; 32],
    pub cited_global_frame: u64,
    pub global_root: [u8; 32],
    pub block: u64,
    pub seq: u64,
    pub source_frame: u64,
    pub tx_id: [u8; 32],
    /// The shard that executed the operation — proven with the record, so a
    /// delivery cannot claim its bytes came from somewhere else.
    pub source_shard: quil_types::execution::ShardPath,
    pub delivered: Delivered,
    pub forest_proof: Vec<u8>,
}

impl CoinDelivery {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.forest_proof.len() > super::reward_witness::MAX_REWARD_PROOF_BYTES {
            return Err(invalid("oversized proof"));
        }
        let mut bytes = Vec::with_capacity(HEADER_BYTES + OUTPUT_BYTES + 4 + self.forest_proof.len());
        bytes.extend_from_slice(&TYPE_COIN_DELIVERY.to_be_bytes());
        bytes.extend_from_slice(match self.delivered {
            Delivered::Coin(_) => DELIVERY_VERSION,
            Delivered::Escrow(_) => ESCROW_DELIVERY_VERSION,
        });
        bytes.extend_from_slice(&self.network);
        bytes.extend_from_slice(&self.application);
        bytes.extend_from_slice(&self.cited_global_frame.to_be_bytes());
        bytes.extend_from_slice(&self.global_root);
        bytes.extend_from_slice(&self.block.to_be_bytes());
        bytes.extend_from_slice(&self.seq.to_be_bytes());
        bytes.extend_from_slice(&self.source_frame.to_be_bytes());
        bytes.extend_from_slice(&self.tx_id);
        bytes.extend_from_slice(&self.source_shard.to_bytes());
        match &self.delivered {
            Delivered::Coin(output) => {
                bytes.extend_from_slice(&output.owner);
                bytes.extend_from_slice(&output.commitment.to_bytes());
                bytes.extend_from_slice(&output.memo);
            }
            Delivered::Escrow(blob) => {
                if blob.is_empty() || blob.len() > super::escrow::MAX_ESCROW_BLOB_BYTES {
                    return Err(invalid("escrow record size"));
                }
                bytes.extend_from_slice(&(blob.len() as u32).to_be_bytes());
                bytes.extend_from_slice(blob);
            }
        }
        bytes.extend_from_slice(&(self.forest_proof.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.forest_proof);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8], network: &[u8; 32], application: &[u8; 32]) -> Result<Self> {
        if bytes.len() < HEADER_BYTES || bytes[..4] != TYPE_COIN_DELIVERY.to_be_bytes() {
            return Err(invalid("invalid envelope"));
        }
        let escrow = match &bytes[4..12] {
            v if v == DELIVERY_VERSION => false,
            v if v == ESCROW_DELIVERY_VERSION => true,
            _ => return Err(invalid("invalid envelope")),
        };
        let mut rest = &bytes[12..];
        let mut take = |n: usize| -> Result<&[u8]> {
            if rest.len() < n {
                return Err(invalid("truncated"));
            }
            let (head, tail) = rest.split_at(n);
            rest = tail;
            Ok(head)
        };
        let decoded_network: [u8; 32] = take(32)?.try_into().unwrap();
        let decoded_application: [u8; 32] = take(32)?.try_into().unwrap();
        if &decoded_network != network || &decoded_application != application {
            return Err(invalid("delivery for another network or application"));
        }
        let cited_global_frame = u64::from_be_bytes(take(8)?.try_into().unwrap());
        let global_root: [u8; 32] = take(32)?.try_into().unwrap();
        let block = u64::from_be_bytes(take(8)?.try_into().unwrap());
        let seq = u64::from_be_bytes(take(8)?.try_into().unwrap());
        let source_frame = u64::from_be_bytes(take(8)?.try_into().unwrap());
        let tx_id: [u8; 32] = take(32)?.try_into().unwrap();
        let source_shard = quil_types::execution::ShardPath::from_bytes(take(9)?)
            .ok_or_else(|| invalid("malformed executing shard"))?;
        let delivered = if escrow {
            let len = u32::from_be_bytes(take(4)?.try_into().unwrap()) as usize;
            if len == 0 || len > super::escrow::MAX_ESCROW_BLOB_BYTES {
                return Err(invalid("escrow record size"));
            }
            Delivered::Escrow(take(len)?.to_vec())
        } else {
            let owner: [u8; IDENTITY_BYTES] = take(IDENTITY_BYTES)?.try_into().unwrap();
            let commitment = AmountCommitment::from_bytes(take(COMMITMENT_BYTES)?).map_err(|_| invalid("malformed commitment"))?;
            let memo: [u8; MEMO_BYTES] = take(MEMO_BYTES)?.try_into().unwrap();
            Delivered::Coin(Output { owner, commitment, memo })
        };
        let proof_len = u32::from_be_bytes(take(4)?.try_into().unwrap()) as usize;
        if proof_len > super::reward_witness::MAX_REWARD_PROOF_BYTES {
            return Err(invalid("invalid proof length"));
        }
        let forest_proof = take(proof_len)?.to_vec();
        if !rest.is_empty() {
            return Err(invalid("trailing bytes"));
        }
        Ok(Self {
            network: decoded_network,
            application: decoded_application,
            cited_global_frame,
            global_root,
            block,
            seq,
            source_frame,
            tx_id,
            source_shard,
            delivered,
            forest_proof,
        })
    }
}

/// The fields of a GLOBAL delivery record, exactly as the commit writes them.
fn record_fields(
    kind: &str,
    address: &[u8; 32],
    source_frame: u64,
    tx_id: &[u8; 32],
    source_shard: quil_types::execution::ShardPath,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    Ok(vec![
        (vec![0xff; 32], super::global_accumulator::kind(kind)?.to_vec()),
        (vec![0], address.to_vec()),
        (vec![4], source_frame.to_be_bytes().to_vec()),
        (vec![8], tx_id.to_vec()),
        (vec![12], source_shard.to_bytes().to_vec()),
    ])
}

/// Escrows of `block` this shard has taken delivery of.
pub fn escrow_count(state: &HypergraphState, application: &[u8; 32], block: u64) -> Result<u64> {
    let disc = vertex_adds_discriminator()?;
    match state.get(application, &super::state::block_record_address(super::state::BLOCK_ESCROW_COUNT_TAG, block), &disc)? {
        None => Ok(0),
        Some(bytes) => Ok(u64::from_be_bytes(
            bytes.as_slice().try_into().map_err(|_| QuilError::Store("coin delivery: malformed escrow count".into()))?,
        )),
    }
}

/// Verify one delivery against the certified frame and apply it: a coin at
/// its committed position and the block extended, or an escrow record written.
/// Returns the delivered address.
pub fn verify_and_apply(
    state: &HypergraphState,
    context: FrameExecutionContext,
    clock: &dyn ClockStore,
    network: &[u8; 32],
    application: &[u8; 32],
    bytes: &[u8],
    limits: SnapshotLimits,
) -> Result<[u8; 32]> {
    let delivery = CoinDelivery::decode(bytes, network, application)?;
    let shard = context.shard.bits().ok_or_else(|| invalid("the executing shard is undecodable"))?;
    if !coin_blocks::shard_owns_block(&shard, delivery.block) {
        return Err(invalid("block is not this shard's"));
    }
    let anchor = context
        .finalized_global_frame
        .ok_or_else(|| invalid("delivery requires the frame's global anchor"))?;
    let root = super::mint_authorization::clock_reward_root(clock, delivery.cited_global_frame, anchor)?;
    if root != delivery.global_root {
        return Err(invalid("cited global root mismatch"));
    }
    let parameters = parameter_context(network, application);
    let membership = quil_forest::MembershipProof::from_bytes(&delivery.forest_proof).map_err(|_| invalid("malformed proof"))?;
    let proven = |record: [u8; 32], kind: &str, address: &[u8; 32]| -> Result<()> {
        let mut vertex = crate::domains::GLOBAL.to_vec();
        vertex.extend_from_slice(&record);
        if membership.inputs.len() != 1 || membership.inputs[0].vertex_address != vertex {
            return Err(invalid("proof does not address this delivery"));
        }
        quil_forest::verify_vertex_membership(&root, &membership.inputs[0],
            &record_fields(kind, address, delivery.source_frame, &delivery.tx_id, delivery.source_shard)?)
            .map_err(|_| invalid("delivery record not proven at the cited root"))
    };
    match &delivery.delivered {
        Delivered::Coin(output) => {
            let (address, tree) = coin_identity(&parameters, delivery.source_frame, output)?;
            proven(global_commit::delivery_address(application, delivery.block, delivery.seq)?, global_commit::KIND_DELIVERY, &address)?;
            place_committed(state, context.frame_number, network, application, &address, tree, delivery.block, delivery.seq, limits)?;
            Ok(address)
        }
        Delivered::Escrow(blob) => {
            let tree = quil_tries::VectorCommitmentTree {
                root: quil_tries::deserialize_go_tree(blob).map_err(|_| invalid("malformed escrow record"))?,
            };
            let address = super::materialize::coin_content_address(&tree)?;
            let escrow = super::escrow::decode_escrow_blob(blob, &parameters, &address)?;
            // A block id carries the width it was created at; the record must
            // sit in the block its own address selects AT THAT WIDTH.
            let width = coin_blocks::creation_width(delivery.block);
            if escrow.frame_number != delivery.source_frame
                || !(coin_blocks::INITIAL_BLOCK_BITS..=coin_blocks::MAX_BLOCK_BITS).contains(&width)
                || coin_blocks::block_for_address(width, &address)? != delivery.block
            {
                return Err(invalid("escrow record does not match its delivery"));
            }
            proven(global_commit::escrow_delivery_address(application, delivery.block, delivery.seq)?, global_commit::KIND_ESCROW_DELIVERY, &address)?;
            place_committed_escrow(state, context.frame_number, application, &address, blob, delivery.block, delivery.seq)?;
            Ok(address)
        }
    }
}

/// Write a committed output at its committed position `(block, seq)` and
/// extend the block: the shared last step of a delivery and of a globally
/// executed application's inline commit.
#[allow(clippy::too_many_arguments)]
pub(crate) fn place_committed(
    state: &HypergraphState,
    frame: u64,
    network: &[u8; 32],
    application: &[u8; 32],
    address: &[u8; 32],
    mut tree: quil_tries::VectorCommitmentTree,
    block: u64,
    seq: u64,
    limits: SnapshotLimits,
) -> Result<()> {
    // Exactly the block's next index: deliveries land in commit order.
    let count = roots::block_count(state, network, application, block, limits)?;
    if count != seq {
        return Err(invalid(&format!("out of sequence: block {block} seq {seq}, local count {count}")));
    }
    let disc = vertex_adds_discriminator()?;
    if state.get(application, address, &disc)?.is_some() {
        return Err(invalid("coin already present"));
    }
    // A block id carries the width it was created at. GLOBAL chose it at the
    // committed placement width, which splits raise past the six bits of the
    // application's own width record; no production path writes that record,
    // so bounding by it refused every coin delivered into a wider block (a live
    // width run's reward claims were skipped by every replica). The coin must
    // sit in the block its own address selects at that width.
    if coin_blocks::block_for_address(coin_blocks::creation_width(block), address)? != block {
        return Err(invalid("coin does not sit in its delivered block"));
    }
    let position = coin_blocks::position(coin_blocks::MAX_BLOCK_BITS, block, seq)?;
    place_coin(&mut tree, position)?;
    let savepoint = state.changeset_len();
    let apply = || -> Result<()> {
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref())
            .map_err(|e| QuilError::Internal(format!("coin encoding: {e}")))?;
        state.set(application, address, &disc, frame, blob)?;
        roots::refresh_root(state, network, application, limits)?;
        Ok(())
    };
    if let Err(error) = apply() {
        state.rollback_to(savepoint);
        return Err(error);
    }
    Ok(())
}

/// Write a committed escrow's record at its committed `(block, seq)` and
/// count it: the shared last step of an escrow delivery and of a globally
/// executed application's inline commit.
pub(crate) fn place_committed_escrow(
    state: &HypergraphState,
    frame: u64,
    application: &[u8; 32],
    address: &[u8; 32],
    blob: &[u8],
    block: u64,
    seq: u64,
) -> Result<()> {
    let count = escrow_count(state, application, block)?;
    if count != seq {
        return Err(invalid(&format!("escrow out of sequence: block {block} seq {seq}, local count {count}")));
    }
    let disc = vertex_adds_discriminator()?;
    if state.get(application, address, &disc)?.is_some() {
        return Err(invalid("escrow already present"));
    }
    let savepoint = state.changeset_len();
    let apply = || -> Result<()> {
        state.set(application, address, &disc, frame, blob.to_vec())?;
        state.set(
            application,
            &super::state::block_record_address(super::state::BLOCK_ESCROW_COUNT_TAG, block),
            &disc,
            frame,
            (seq + 1).to_be_bytes().to_vec(),
        )?;
        Ok(())
    };
    if let Err(error) = apply() {
        state.rollback_to(savepoint);
        return Err(error);
    }
    Ok(())
}

/// The canonical record of the escrow a pending create (`0x0514`) makes, and
/// its address.
pub(crate) fn escrow_record(
    network: &[u8; 32],
    application: &[u8; 32],
    operation: &[u8],
    source_frame: u64,
) -> Result<([u8; 32], Vec<u8>)> {
    let tx = quil_lattice_ct::confidential::pending_create::PendingCreate::decode(operation, network, application)
        .map_err(|_| invalid("invalid escrow operation"))?;
    let (escrowed, _) = tx.statement.split_outputs().map_err(|_| invalid("missing escrow output"))?;
    super::escrow::StoredEscrow {
        frame_number: source_frame,
        output: escrowed.clone(),
        policy: tx.statement.policy.clone(),
        refund_recovery: tx.statement.refund_recovery.clone(),
    }
    .encode(&parameter_context(network, application))
}

/// A committed output or escrow this shard has yet to take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingDelivery {
    pub escrow: bool,
    pub block: u64,
    pub seq: u64,
    pub address: [u8; 32],
    pub source_frame: u64,
    pub tx_id: [u8; 32],
    /// Where the operation ran, and so where its bytes are.
    pub source_shard: quil_types::execution::ShardPath,
}

/// Committed outputs and escrows of the blocks `shard` owns that local state
/// has not yet taken, in delivery order, at most `cap`. `global` is a view of
/// GLOBAL state.
pub fn pending_deliveries(
    global: &HypergraphState,
    local: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    shard: &[bool],
    limits: SnapshotLimits,
    cap: usize,
) -> Result<Vec<PendingDelivery>> {
    // Every width the application has placed at, narrowest first. Within one
    // width the shard owns exactly the blocks whose path extends its own, so
    // only those are enumerated (a whole-application holder at the widest
    // setting would otherwise walk 32,768 ids per pull); a width narrower than
    // the shard is skipped, since it owns no whole block there.
    let placed_at = global_commit::placement_width(global, application)?;
    let mut pending = Vec::new();
    for block in coin_blocks::owned_blocks(shard, placed_at) {
        debug_assert!(coin_blocks::shard_owns_block(shard, block));
        for escrow in [false, true] {
            let (committed, mut seq) = if escrow {
                (global_commit::escrow_sequence(global, application, block)?, escrow_count(local, application, block)?)
            } else {
                (global_commit::block_sequence(global, application, block)?, roots::block_count(local, network, application, block, limits)?)
            };
            while seq < committed && pending.len() < cap {
                let record = if escrow {
                    global_commit::escrow_delivery(global, application, block, seq)?
                } else {
                    global_commit::delivery(global, application, block, seq)?
                };
                let Some(record) = record else { break };
                pending.push(PendingDelivery {
                    escrow, block, seq,
                    address: record.address,
                    source_frame: record.source_frame,
                    tx_id: record.tx_id,
                    source_shard: record.source_shard,
                });
                seq += 1;
            }
        }
        if pending.len() >= cap {
            break;
        }
    }
    Ok(pending)
}

/// What a committed operation delivered at `address`, rebuilt from the
/// operation bytes, or `None` if it created nothing there.
pub fn find_delivered(
    network: &[u8; 32],
    application: &[u8; 32],
    tp: u32,
    operation: &[u8],
    pending: &PendingDelivery,
) -> Result<Option<Delivered>> {
    let parameters = parameter_context(network, application);
    if pending.escrow {
        if tp != super::constants::TYPE_LATTICE_PENDING {
            return Ok(None);
        }
        let (address, blob) = escrow_record(network, application, operation, pending.source_frame)?;
        return Ok((address == pending.address).then_some(Delivered::Escrow(blob)));
    }
    for output in spend_entries::operation_outputs(network, application, tp, operation)? {
        if coin_identity(&parameters, pending.source_frame, &output)?.0 == pending.address {
            return Ok(Some(Delivered::Coin(output)));
        }
    }
    Ok(None)
}

/// Build one delivery: its record proven at the newest global root retained at
/// or before `anchor`. `Ok(None)` when no retained root holds the record yet.
#[allow(clippy::too_many_arguments)]
pub fn build_delivery(
    global: &HypergraphState,
    clock: &dyn ClockStore,
    network: &[u8; 32],
    application: &[u8; 32],
    anchor: u64,
    pending: &PendingDelivery,
    delivered: Delivered,
) -> Result<Option<Vec<u8>>> {
    let (root, header) = super::reward_witness::newest_retained_global_root(global, clock, Some(anchor))?;
    let record = if pending.escrow {
        global_commit::escrow_delivery_address(application, pending.block, pending.seq)?
    } else {
        global_commit::delivery_address(application, pending.block, pending.seq)?
    };
    let Some(proof) = global.crdt().global_vertex_membership_at_root(&root, &record)? else {
        return Ok(None);
    };
    let forest_proof = quil_forest::MembershipProof { inputs: vec![proof] }.to_bytes();
    CoinDelivery {
        network: *network,
        application: *application,
        cited_global_frame: header.frame_number,
        global_root: root,
        block: pending.block,
        seq: pending.seq,
        source_frame: pending.source_frame,
        tx_id: pending.tx_id,
        source_shard: pending.source_shard,
        delivered,
        forest_proof,
    }
    .encode()
    .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_lattice_ct::confidential::{AmountOpening, CommitmentKey};

    #[test]
    fn a_delivery_round_trips_and_binds_its_domain() {
        let (network, application) = ([1u8; 32], [2u8; 32]);
        let context = parameter_context(&network, &application);
        let delivery = CoinDelivery {
            network, application, cited_global_frame: 90, global_root: [3; 32],
            block: coin_blocks::block_id(coin_blocks::INITIAL_BLOCK_BITS, 5).unwrap(), seq: 7,
            source_frame: 40, tx_id: [4; 32], source_shard: quil_types::execution::ShardPath::from_bits(&[true, false]),
            delivered: Delivered::Coin(Output {
                owner: [5; IDENTITY_BYTES],
                commitment: CommitmentKey::derive(&context).commit(9, &AmountOpening::from_seed(&context, &[6; 32])),
                memo: [7; MEMO_BYTES],
            }),
            forest_proof: vec![8; 123],
        };
        let bytes = delivery.encode().unwrap();
        assert_eq!(CoinDelivery::decode(&bytes, &network, &application).unwrap(), delivery);
        assert!(CoinDelivery::decode(&bytes, &[9; 32], &application).is_err());
        assert!(CoinDelivery::decode(&bytes, &network, &[9; 32]).is_err());
        assert!(CoinDelivery::decode(&bytes[..bytes.len() - 1], &network, &application).is_err());
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(CoinDelivery::decode(&extended, &network, &application).is_err());
        // An escrow delivery round-trips under its own version.
        let escrow = CoinDelivery { delivered: Delivered::Escrow(vec![9; 500]), ..delivery };
        let bytes = escrow.encode().unwrap();
        assert_eq!(&bytes[4..12], ESCROW_DELIVERY_VERSION);
        assert_eq!(CoinDelivery::decode(&bytes, &network, &application).unwrap(), escrow);
        assert!(CoinDelivery::decode(&bytes[..bytes.len() - 1], &network, &application).is_err());
    }

    /// A live width run: once the application split past six bits, GLOBAL
    /// placed new coins in wider blocks, and every replica of the receiving
    /// shard refused them ("block beyond the accumulator's current width")
    /// because its own width record was never written.
    #[test]
    fn a_coin_delivered_into_a_block_wider_than_six_bits_is_placed() {
        let (network, application) = ([1u8; 32], [2u8; 32]);
        let context = parameter_context(&network, &application);
        let state = HypergraphState::new(std::sync::Arc::new(quil_hypergraph::HypergraphCrdt::new(
            std::sync::Arc::new(quil_hypergraph::testing::MemStore::new()),
            std::sync::Arc::new(quil_types::crypto::NoopInclusionProver),
        )));
        let limits = SnapshotLimits { max_coins: 64, max_depth: 32, max_nodes: 1 << 14 };
        let coin = |seed: u8| {
            let output = Output {
                owner: [seed; IDENTITY_BYTES],
                commitment: CommitmentKey::derive(&context).commit(u128::from(seed), &AmountOpening::from_seed(&context, &[seed; 32])),
                memo: [seed; MEMO_BYTES],
            };
            coin_identity(&context, 5, &output).unwrap()
        };
        let place = |address: &[u8; 32], tree, block, seq| {
            place_committed(&state, 5, &network, &application, address, tree, block, seq, limits)
        };
        assert_eq!(roots::block_width(&state, &application).unwrap(), coin_blocks::INITIAL_BLOCK_BITS);

        let (first, tree) = coin(3);
        let wide = coin_blocks::block_for_address(9, &first).unwrap();
        place(&first, tree, wide, 0).expect("a nine-bit block is accepted");
        assert_eq!(roots::block_count(&state, &network, &application, wide, limits).unwrap(), 1);

        // A six-bit coin lives beside it.
        let (second, tree) = coin(4);
        let narrow = coin_blocks::block_for_address(coin_blocks::INITIAL_BLOCK_BITS, &second).unwrap();
        place(&second, tree, narrow, 0).expect("a six-bit block is accepted");

        // Out of sequence, or in a block its address does not select, is refused.
        let (third, tree) = coin(5);
        let own = coin_blocks::block_for_address(9, &third).unwrap();
        assert!(place(&third, tree, own, 3).is_err(), "out of sequence");
        assert_ne!(own, wide);
        let (_, tree) = coin(5);
        let wrong = place(&third, tree, wide, 1).unwrap_err();
        assert!(wrong.to_string().contains("does not sit in its delivered block"), "{wrong}");
    }

    /// After a split past a block's width, the shard holding the block's
    /// records attests what it received; an output GLOBAL then re-places lands
    /// once, and one that had already landed cannot land again.
    #[test]
    fn a_holder_attests_its_block_and_a_re_placed_output_lands_once() {
        use super::super::shard_accumulator::{self, BlockAttestation, ShardReport};
        let (network, application) = ([1u8; 32], [2u8; 32]);
        let context = parameter_context(&network, &application);
        let state = HypergraphState::new(std::sync::Arc::new(quil_hypergraph::HypergraphCrdt::new(
            std::sync::Arc::new(quil_hypergraph::testing::MemStore::new()),
            std::sync::Arc::new(quil_types::crypto::NoopInclusionProver),
        )));
        let limits = SnapshotLimits { max_coins: 64, max_depth: 32, max_nodes: 1 << 14 };
        let coin = |seed: u8| {
            let output = Output {
                owner: [seed; IDENTITY_BYTES],
                commitment: CommitmentKey::derive(&context).commit(u128::from(seed), &AmountOpening::from_seed(&context, &[seed; 32])),
                memo: [seed; MEMO_BYTES],
            };
            coin_identity(&context, 5, &output).unwrap()
        };
        let (delivered, tree) = coin(3);
        let narrow = coin_blocks::block_for_address(7, &delivered).unwrap();
        place_committed(&state, 5, &network, &application, &delivered, tree, narrow, 0, limits).unwrap();

        let path = coin_blocks::block_path(narrow);
        let holder: Vec<bool> = path.iter().copied().chain([false]).collect();
        let sibling: Vec<bool> = path.iter().copied().chain([true]).collect();
        let report = shard_accumulator::shard_report(&state, &network, &application, &holder, true).unwrap().unwrap();
        assert!(report.attestations.contains(&BlockAttestation { block: narrow, coins: 1, escrows: 0 }));
        assert!(report.attestations.iter().all(|a| a.block == narrow || a.coins == 0), "{:?}", report.attestations);
        let bytes = report.encode().unwrap();
        assert_eq!(&bytes[..8], shard_accumulator::ATTESTING_REPORT_VERSION);
        assert_eq!(ShardReport::decode(&bytes).unwrap(), report);
        let other = shard_accumulator::shard_report(&state, &network, &application, &sibling, true).unwrap();
        assert!(other.is_none_or(|report| report.attestations.iter().all(|a| a.block != narrow)));
        assert!(shard_accumulator::shard_report(&state, &network, &application, &holder, false).unwrap().is_none(),
            "before the re-placement frame nothing is attested");

        // GLOBAL moved everything past the attested count to width eight.
        let (again, tree) = coin(3);
        let refused = place_committed(&state, 9, &network, &application, &again,
            tree, coin_blocks::block_for_address(8, &again).unwrap(), 0, limits).unwrap_err();
        assert!(refused.to_string().contains("coin already present"), "{refused}");
        let (moved, tree) = coin(4);
        let target = coin_blocks::block_for_address(8, &moved).unwrap();
        let seq = roots::block_count(&state, &network, &application, target, limits).unwrap();
        place_committed(&state, 9, &network, &application, &moved, tree, target, seq, limits).unwrap();
    }
}

//! Confidential coin storage boundary. Proof admission is not enabled here.
//! The type marker binds the suite and network/application parameter context.
//! Full commitments and mandatory memos use the existing vertex field layout.

pub use quil_lattice_ct::confidential::transfer::network_identifier;
use quil_lattice_ct::confidential::{
    coin_tree::CoinRecord,
    transfer::{parameter_context, Output, MEMO_BYTES},
    AmountCommitment,
};
use quil_lattice_ct::confidential::sharded_tree::ShardedCoinTree;
use quil_tries::VectorCommitmentTree;
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
use quil_types::error::{QuilError, Result};
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};

use super::materialize::create_lattice_coin_vertex_tree;

#[derive(Debug, PartialEq, Eq)]
pub struct StoredCoin {
    pub frame_number: u64,
    /// Leaf index in the application's coin accumulator, assigned at staging.
    pub position: u64,
    pub output: Output,
}

impl StoredCoin {
    pub fn record(&self, address: [u8; 32]) -> CoinRecord {
        CoinRecord {
            address,
            owner: self.output.owner,
            commitment: self.output.commitment.clone(),
            position: self.position,
        }
    }
}

fn type_hash(context: &[u8; 32]) -> Result<[u8; 32]> {
    // v2: records carry their accumulator position (leaf index).
    let mut bytes = Vec::from(b"quil/coin/QCT3/v4\0".as_slice());
    bytes.extend_from_slice(context);
    quil_crypto::poseidon::hash_bytes_to_32(&bytes)
}

/// Prepare a vertex and its content address for the caller's state transaction.
/// `position` is the coin's leaf index in the application accumulator (see
/// `roots::next_position`); it is part of the committed content.
/// This function neither verifies a proof nor writes or commits state.
pub fn create_coin(
    context: &[u8; 32],
    frame_number: u64,
    output: &Output,
    position: u64,
) -> Result<([u8; 32], VectorCommitmentTree)> {
    let (address, mut tree) = coin_identity(context, frame_number, output)?;
    place_coin(&mut tree, position)?;
    Ok((address, tree))
}

/// A coin's address and its vertex before a position is assigned. Staging
/// needs the address first: the address selects the block, the block's owner
/// is the shard that stores the coin, and only then is a position allocated
/// from that block's own counter.
pub fn coin_identity(
    context: &[u8; 32],
    frame_number: u64,
    output: &Output,
) -> Result<([u8; 32], VectorCommitmentTree)> {
    let tree = create_lattice_coin_vertex_tree(
        &frame_number.to_be_bytes(),
        &output.owner,
        &output.commitment.to_bytes(),
        &output.memo,
        &type_hash(context)?,
    )?;
    let address = super::materialize::coin_identity_address(&tree)?;
    Ok((address, tree))
}

/// Record the accumulator position in a coin vertex. The address is already
/// fixed by [`coin_identity`] and does not change.
pub fn place_coin(tree: &mut VectorCommitmentTree, position: u64) -> Result<()> {
    let position = position.to_be_bytes();
    tree.insert(
        &super::materialize::COIN_POSITION_KEY,
        &position,
        &[],
        &num_bigint::BigInt::from(position.len()),
    )
    .map_err(|e| QuilError::Internal(format!("coin tree: {e}")))
}

/// Ignore other vertex types; reject malformed records bearing our type marker.
/// Callers must obtain `context` from their network/application configuration.
pub fn read_coin(tree: &VectorCommitmentTree, context: &[u8; 32]) -> Result<Option<StoredCoin>> {
    let marker = type_hash(context)?;
    if tree.get(&[0xff; 32]) != Some(marker.as_slice()) {
        return Ok(None);
    }
    let invalid = || QuilError::Internal("coin: malformed stored record".into());
    // Reject extra fields instead of silently omitting committed data when
    // reconstructing a recipient output or its content address.
    if tree.leaves().len() != 6 {
        return Err(invalid());
    }
    let frame = tree.get(&[0]).ok_or_else(invalid)?;
    let owner = tree.get(&[4]).ok_or_else(invalid)?;
    let commitment = tree.get(&[8]).ok_or_else(invalid)?;
    let memo = tree.get(&[12]).ok_or_else(invalid)?;
    let position = tree.get(&[16]).ok_or_else(invalid)?;
    let frame_number = u64::from_be_bytes(frame.try_into().map_err(|_| invalid())?);
    let position = u64::from_be_bytes(position.try_into().map_err(|_| invalid())?);
    let owner: [u8; IDENTITY_BYTES] = owner.try_into().map_err(|_| invalid())?;
    let memo: [u8; MEMO_BYTES] = memo.try_into().map_err(|_| invalid())?;
    let commitment = AmountCommitment::from_bytes(commitment).map_err(|_| invalid())?;
    Ok(Some(StoredCoin {
        frame_number,
        position,
        output: Output {
            owner,
            commitment,
            memo,
        },
    }))
}

/// Separate from the old accumulator root, migration receipt and token metadata.
pub const ROOT_ADDRESS: [u8; 32] = {
    let mut address = [0xff; 32];
    address[31] = 0xfc;
    address
};

/// Persisted append frontier of the coin accumulator (see `roots`).
pub const FRONTIER_ADDRESS: [u8; 32] = {
    let mut address = [0xff; 32];
    address[31] = 0xfb;
    address
};

/// Reserved address family for the per-block accumulator records. Layout:
///
/// ```text
/// [0..2]   the block's bit path, left-aligned (widths ≤ 15 fit), then zeros
/// [2..23]  0xff fill
/// [23]     tag
/// [24..32] block id, big-endian
/// ```
///
/// The path leads so the record lives INSIDE the block's own prefix: the shard
/// that owns a block — the one appending its coins — is the only shard that
/// ever writes its records. The fill and the id (which must agree with the
/// leading bits) keep the family outside any reachable coin address, which is
/// a Poseidon image.
const BLOCK_RECORD_FILL: std::ops::Range<usize> = 2..23;
const BLOCK_RECORD_TAG_AT: usize = 23;
/// Per-block append frontier.
pub const BLOCK_FRONTIER_TAG: u8 = 0xf0;
/// Per-block subtree root, folded into the application root.
pub const BLOCK_ROOT_TAG: u8 = 0xf1;
/// The shard a block is allocated to. Recorded, never derived, so widening the
/// index space cannot reassign a block out from under existing coins.
pub const BLOCK_OWNER_TAG: u8 = 0xf2;
/// How many committed escrows of the block this shard has taken delivery of.
pub const BLOCK_ESCROW_COUNT_TAG: u8 = 0xf3;

/// The flat block summary: sorted `(block, coins, root)` of every non-empty
/// block in one record. Replaced by the stored tree of `summary_tree`, which
/// leaves `summary_tree::MOVED` here; a flat record is read until then.
pub const BLOCK_SUMMARY_ADDRESS: [u8; 32] = {
    let mut address = [0xff; 32];
    address[31] = 0xf9;
    address
};

/// Committed accumulator width (block levels). Growth raises it; every
/// existing position keeps its value.
pub const SHAPE_ADDRESS: [u8; 32] = {
    let mut address = [0xff; 32];
    address[31] = 0xfa;
    address
};

/// Node-local copies of the application-wide accumulator records: the local
/// root history ([`ROOT_ADDRESS`]), the frontier, the width, the flat summary
/// and the summary tree. Keyed
/// `LOCAL_RECORD_PREFIX ‖ application ‖ address` among the execution records:
/// staged with a frame's changeset and committed with it, but outside the
/// application tree, so no shard root, shard size or world size includes them.
///
/// In the tree these records sat at all-ones addresses, inside the all-ones
/// shard's range. An archive executing every shard wrote a copy none of that
/// shard's members held, so the shard could never bootstrap from an archive.
/// Nothing consensus-critical reads them: a spend's root is checked against
/// GLOBAL's canonical history, and a shard's report derives from its block
/// records. Copies written in the tree before are read where they are until
/// overwritten here (the tree never forgets a vertex, so they stay).
pub const LOCAL_RECORD_PREFIX: &[u8] = b"quil/accumulator/local/v1\0";

pub fn local_record_key(application: &[u8; 32], address: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(LOCAL_RECORD_PREFIX.len() + 64);
    key.extend_from_slice(LOCAL_RECORD_PREFIX);
    key.extend_from_slice(application);
    key.extend_from_slice(address);
    key
}

/// The application whose local `address` record `key` is.
pub fn local_record_application(key: &[u8], address: &[u8; 32]) -> Option<[u8; 32]> {
    let rest = key.strip_prefix(LOCAL_RECORD_PREFIX)?;
    (rest.len() == 64 && rest[32..] == address[..]).then(|| rest[..32].try_into().unwrap())
}

/// A local accumulator record, or its legacy copy in the tree.
pub(crate) fn read_local(state: &HypergraphState, application: &[u8; 32], address: &[u8; 32]) -> Result<Option<Vec<u8>>> {
    match state.get_record(&local_record_key(application, address))? {
        Some(value) => Ok(Some(value)),
        None => state.get(application, address, &vertex_adds_discriminator()?),
    }
}

pub(crate) fn write_local(state: &HypergraphState, application: &[u8; 32], address: &[u8; 32], value: Vec<u8>) {
    state.stage_records([quil_types::store::RecordMutation {
        key: local_record_key(application, address),
        value: Some(value),
    }]);
}

/// The block's bit path left-aligned in two bytes: the leading bits of any
/// address inside the block's prefix.
fn block_path_prefix(block: u64) -> [u8; 2] {
    let mut prefix = 0u16;
    for (i, bit) in super::coin_blocks::block_path(block).iter().enumerate().take(16) {
        if *bit {
            prefix |= 1 << (15 - i);
        }
    }
    prefix.to_be_bytes()
}

/// Address of one per-block record, inside the block's own prefix.
pub fn block_record_address(tag: u8, block: u64) -> [u8; 32] {
    let mut address = [0xff; 32];
    address[0..2].copy_from_slice(&block_path_prefix(block));
    address[BLOCK_RECORD_TAG_AT] = tag;
    address[24..32].copy_from_slice(&block.to_be_bytes());
    address
}

/// Whether an address is one of the accumulator's own records rather than a
/// coin. Checked before decoding, so a block record is never read as a coin.
pub fn is_accumulator_record(address: &[u8; 32]) -> bool {
    if address == &ROOT_ADDRESS
        || address == &FRONTIER_ADDRESS
        || address == &SHAPE_ADDRESS
        || address == &BLOCK_SUMMARY_ADDRESS
        || address == &super::constants::LEGACY_ACCUMULATOR_ROOT_ADDRESS
        || address == &super::legacy_migration::MIGRATION_RECEIPT_ADDRESS
        || super::summary_tree::is_node_address(address)
    {
        return true;
    }
    if !address[BLOCK_RECORD_FILL].iter().all(|byte| *byte == 0xff)
        || !matches!(address[BLOCK_RECORD_TAG_AT], BLOCK_FRONTIER_TAG | BLOCK_ROOT_TAG | BLOCK_OWNER_TAG | BLOCK_ESCROW_COUNT_TAG)
    {
        return false;
    }
    // The id must be a real block and the leading bits must be its path, so a
    // record is recognised exactly where `block_record_address` puts it.
    let block = u64::from_be_bytes(address[24..32].try_into().unwrap());
    let width = super::coin_blocks::creation_width(block);
    (super::coin_blocks::INITIAL_BLOCK_BITS..=super::coin_blocks::MAX_BLOCK_BITS).contains(&width)
        && address[0..2] == block_path_prefix(block)
}

/// Retained coin records and cached tree nodes are separately bounded. These
/// counts are not an RSS limit and do not bound store iterator I/O.
#[derive(Clone, Copy)]
pub struct SnapshotLimits {
    pub max_coins: usize,
    pub max_depth: usize,
    pub max_nodes: usize,
}

pub(crate) fn decode_snapshot_coin(
    context: &[u8; 32],
    application: &[u8; 32],
    key: &[u8],
    blob: &[u8],
) -> Result<Option<CoinRecord>> {
    decode_stored_snapshot_coin(context, application, key, blob)
        .map(|coin| coin.map(|coin| coin.record(key[32..].try_into().unwrap())))
}

/// Validate the full stored output, including its content address, for both
/// wallet enumeration and membership-tree reconstruction.
pub(crate) fn decode_stored_snapshot_coin(
    context: &[u8; 32],
    application: &[u8; 32],
    key: &[u8],
    blob: &[u8],
) -> Result<Option<StoredCoin>> {
    if key.len() != 64 || &key[..32] != application {
        return Err(QuilError::Internal(
            "coin snapshot: invalid vertex key".into(),
        ));
    }
    let address: [u8; 32] = key[32..].try_into().unwrap();
    if is_accumulator_record(&address) {
        return Ok(None);
    }
    let tree = VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(blob)
            .map_err(|e| QuilError::Internal(format!("coin snapshot: {e}")))?,
    };
    let Some(coin) = read_coin(&tree, context)? else {
        return Ok(None);
    };
    if super::materialize::coin_identity_address(&tree)? != address {
        return Err(QuilError::Internal(
            "coin snapshot: coin address mismatch".into(),
        ));
    }
    Ok(Some(coin))
}

/// Reconstruct a coin tree from a consistent committed-store snapshot.
/// This does not admit its root. Callers must not hold the non-reentrant forest
/// write guard. Release it before expensive lattice tree construction.
pub fn load_committed_snapshot(
    state: &crate::hypergraph_state::HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    limits: SnapshotLimits,
) -> Result<ShardedCoinTree> {
    if !(1..=32).contains(&limits.max_depth) {
        return Err(QuilError::InvalidArgument(
            "coin snapshot: invalid depth".into(),
        ));
    }
    let context = parameter_context(network, application);
    let mut records = Vec::new();
    let mut error = None;
    {
        let _guard = state.crdt().lock_forest_writes();
        state
            .crdt()
            .for_each_vertex_adds_blob(application, &mut |key, blob| {
                if error.is_some() {
                    return;
                }
                let collect = || -> Result<Option<CoinRecord>> {
                    let record = decode_snapshot_coin(&context, application, &key, &blob)?;
                    if record.is_some() && records.len() >= limits.max_coins {
                        return Err(QuilError::InvalidArgument(
                            "coin snapshot: coin limit exceeded".into(),
                        ));
                    }
                    Ok(record)
                };
                match collect() {
                    Ok(Some(record)) => records.push(record),
                    Ok(None) => {}
                    Err(e) => error = Some(e),
                }
            })?;
    }
    if let Some(error) = error {
        return Err(error);
    }
    // Positions are block-partitioned, not a dense 0..n run, so the snapshot
    // is the sharded tree: the same tree a node holding every coin builds, and
    // the same root the per-block fold produces.
    let width = super::roots::block_width(state, application)?;
    let shape = super::coin_blocks::shape(width)?;
    ShardedCoinTree::build(&context, shape, &records)
        .map_err(|e| QuilError::InvalidArgument(format!("coin snapshot: {e:?}")))
}

#[cfg(test)]
mod block_record_address_tests {
    use super::*;
    use super::super::coin_blocks;

    /// A block's records sit inside the block's own prefix, so the shard that
    /// owns the block is the one that holds them; and only those exact
    /// addresses are recognised as accumulator records.
    #[test]
    fn block_records_live_in_their_own_block_prefix() {
        let width = coin_blocks::INITIAL_BLOCK_BITS;
        for path in [0u64, 1, 0b101101, 63] {
            let block = coin_blocks::block_id(width, path).unwrap();
            for tag in [BLOCK_FRONTIER_TAG, BLOCK_ROOT_TAG, BLOCK_OWNER_TAG, BLOCK_ESCROW_COUNT_TAG] {
                let address = block_record_address(tag, block);
                assert!(is_accumulator_record(&address));
                // The address falls in the block it describes.
                assert_eq!(coin_blocks::block_for_address(width, &address).unwrap(), block);
                // Moved into another block's prefix, it is no longer a record.
                let mut moved = address;
                moved[0] ^= 0x80;
                assert!(!is_accumulator_record(&moved));
                // Nor with a different id, or a broken fill.
                let mut other = address;
                other[31] ^= 1;
                assert!(!is_accumulator_record(&other));
                let mut broken = address;
                broken[10] = 0;
                assert!(!is_accumulator_record(&broken));
            }
        }
        // A wider block (created after growth) is inside its own prefix too.
        let wide = coin_blocks::block_id(width + 3, 0b101010101).unwrap();
        let address = block_record_address(BLOCK_ROOT_TAG, wide);
        assert!(is_accumulator_record(&address));
        assert_eq!(coin_blocks::block_for_address(width + 3, &address).unwrap(), wide);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;
    use quil_lattice_ct::confidential::{AmountOpening, CommitmentKey};

    fn output() -> Output {
        let context = [7; 32];
        Output {
            owner: [9; IDENTITY_BYTES],
            commitment: CommitmentKey::derive(&context)
                .commit(123, &AmountOpening::from_seed(&context, &[8; 32])),
            memo: [10; MEMO_BYTES],
        }
    }

    #[test]
    fn stored_coin_roundtrips_through_vertex_serialization() {
        let output = output();
        let (address, tree) = create_coin(&[7; 32], 42, &output, 3).unwrap();
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        let restored = VectorCommitmentTree {
            root: quil_tries::deserialize_go_tree(&blob).unwrap(),
        };
        assert_eq!(super::super::materialize::coin_identity_address(&restored).unwrap(), address);
        // A coin's address is its identity, not its placement: the same output
        // in the same frame has one address wherever it lands in the
        // accumulator. That is what lets the address choose the block, and
        // therefore the shard that stores and appends it.
        let (elsewhere, other_tree) = create_coin(&[7; 32], 42, &output, 900_001).unwrap();
        assert_eq!(elsewhere, address);
        assert_eq!(read_coin(&other_tree, &[7; 32]).unwrap().unwrap().position, 900_001);
        let coin = read_coin(&restored, &[7; 32]).unwrap().unwrap();
        assert_eq!(coin.frame_number, 42);
        assert_eq!(coin.position, 3);
        assert_eq!(coin.output, output);
        let record = coin.record(address);
        assert_eq!(record.address, address);
        assert_eq!(record.owner, output.owner);
        assert_eq!(record.commitment, output.commitment);
        assert_eq!(record.position, 3);
        // The position is committed state but NOT identity: the same output at
        // another index is the same coin, which is what breaks the circularity
        // between "the address selects the block" and "the block assigns the
        // position". Placement is pinned by deterministic re-materialization
        // (every node stages outputs the same way), not by the address; wallets
        // additionally refuse a scanned coin whose position lies outside the
        // block its address selects.
        assert_eq!(create_coin(&[7; 32], 42, &output, 4).unwrap().0, address);
        // A different coin is still a different address.
        let mut other = output.clone();
        other.memo[0] ^= 1;
        assert_ne!(create_coin(&[7; 32], 42, &other, 3).unwrap().0, address);
        assert_ne!(create_coin(&[7; 32], 43, &output, 3).unwrap().0, address);
        assert!(read_coin(&restored, &[6; 32]).unwrap().is_none());
        let legacy = create_lattice_coin_vertex_tree(
            &42u64.to_be_bytes(),
            &output.owner,
            &output.commitment.to_bytes(),
            &output.memo,
            &super::super::materialize::coin_type_hash(&[7; 32]).unwrap(),
        )
        .unwrap();
        assert!(read_coin(&legacy, &[7; 32]).unwrap().is_none());
    }

    #[test]
    fn stored_coin_rejects_bad_fields() {
        let output = output();
        for (key, bytes) in [
            (0, vec![0; 7]),
            (4, vec![0; 47]),
            (8, vec![0; 1]),
            (12, vec![0; MEMO_BYTES - 1]),
            (16, vec![0]),
            (
                8,
                vec![255; quil_lattice_ct::confidential::COMMITMENT_BYTES],
            ),
        ] {
            let (_, mut tree) = create_coin(&[7; 32], 42, &output, 0).unwrap();
            tree.insert(&[key], &bytes, &[], &BigInt::from(bytes.len()))
                .unwrap();
            assert!(read_coin(&tree, &[7; 32]).is_err(), "field {key}");
        }
        // Extra fields and a missing position are rejected too.
        let (_, mut extra) = create_coin(&[7; 32], 42, &output, 0).unwrap();
        extra.insert(&[20], &[1], &[], &BigInt::from(1)).unwrap();
        assert!(read_coin(&extra, &[7; 32]).is_err());
        let without_position = create_lattice_coin_vertex_tree(
            &42u64.to_be_bytes(),
            &output.owner,
            &output.commitment.to_bytes(),
            &output.memo,
            &type_hash(&[7; 32]).unwrap(),
        )
        .unwrap();
        assert!(read_coin(&without_position, &[7; 32]).is_err());
        let missing_memo = create_lattice_coin_vertex_tree(
            &42u64.to_be_bytes(),
            &output.owner,
            &output.commitment.to_bytes(),
            &[],
            &type_hash(&[7; 32]).unwrap(),
        )
        .unwrap();
        assert!(read_coin(&missing_memo, &[7; 32]).is_err());
    }
    #[test]
    fn committed_snapshot_matches_coin_records_and_enforces_limits() {
        use crate::hypergraph_state::HypergraphState;
        use quil_hypergraph::addressing::{shard_key_for_location, Location};
        use quil_types::{crypto::NoopInclusionProver, store::HypergraphStore};
        use std::sync::Arc;

        let network = [1; 32];
        let application = [2; 32];
        let context = parameter_context(&network, &application);
        let store = Arc::new(quil_hypergraph::testing::MemStore::new());
        let txn = store.new_transaction(false).unwrap();
        let shard = shard_key_for_location(&Location {
            app_address: application,
            data_address: [0; 32],
        });
        let mut records = Vec::new();
        for i in (0..3).rev() {
            let mut output = output();
            output.owner[0] = i;
            let (address, tree) = create_coin(&context, 42, &output, u64::from(i)).unwrap();
            let mut key = application.to_vec();
            key.extend_from_slice(&address);
            let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
            store
                .save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &key, &blob)
                .unwrap();
            records.push(
                StoredCoin {
                    frame_number: 42,
                    position: u64::from(i),
                    output,
                }
                .record(address),
            );
        }
        // Every record the accumulator owns uses a raw codec, so a scan must
        // skip the whole family — including the per-block frontiers and roots,
        // which are the ones a hand-listed set forgets.
        let block = super::super::coin_blocks::block_id(super::super::coin_blocks::INITIAL_BLOCK_BITS, 3).unwrap();
        for address in [
            // (The shape and summary records are left alone: this fixture
            // writes junk, and those two have decode contracts the snapshot
            // reads — a malformed one must FAIL, not be skipped.)
            ROOT_ADDRESS,
            FRONTIER_ADDRESS,
            block_record_address(BLOCK_FRONTIER_TAG, block),
            block_record_address(BLOCK_ROOT_TAG, block),
            block_record_address(BLOCK_OWNER_TAG, block),
            super::super::constants::LEGACY_ACCUMULATOR_ROOT_ADDRESS,
            super::super::legacy_migration::MIGRATION_RECEIPT_ADDRESS,
        ] {
            let mut key = application.to_vec();
            key.extend_from_slice(&address);
            store
                .save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &key, &[1, 2, 3])
                .unwrap();
        }
        let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store.clone(),
            Arc::new(NoopInclusionProver),
        )));
        let limits = SnapshotLimits {
            max_coins: 3,
            max_depth: 3,
            max_nodes: 10,
        };
        // The snapshot is the sharded tree: it must equal a direct build over
        // the same records, and skip every reserved accumulator record rather
        // than mistaking one for a coin.
        let shape = super::super::coin_blocks::shape(
            super::super::coin_blocks::INITIAL_BLOCK_BITS,
        )
        .unwrap();
        let expected = ShardedCoinTree::build(&context, shape, &records).unwrap();
        let actual = load_committed_snapshot(&state, &network, &application, limits).unwrap();
        assert_eq!(actual.coins(), records.len() as u64);
        assert_eq!(actual.root(), expected.root());
        for record in &records {
            let a = actual.auth_path(&record.address).unwrap();
            let b = expected.auth_path(&record.address).unwrap();
            assert_eq!(a.siblings, b.siblings);
            assert_eq!(a.right, b.right);
            // And the path reaches the application root.
            let owner = quil_lattice_ct::confidential::relation::membership::Node::from_identity_bytes(
                &record.owner,
            )
            .unwrap();
            assert_eq!(
                ShardedCoinTree::root_from_path(&context, &owner, &record.commitment, &a).unwrap(),
                actual.root()
            );
        }
        // The sharded tree is sparse — it materializes only occupied paths —
        // so memory is bounded by the coin limit (coins x depth) rather than
        // by a node cap over a dense layer.
        for limits in [
            SnapshotLimits {
                max_coins: 2,
                ..limits
            },
            SnapshotLimits {
                max_depth: 0,
                ..limits
            },
        ] {
            assert!(load_committed_snapshot(&state, &network, &application, limits).is_err());
        }
        // A record under a different content address cannot enter the snapshot.
        let (_, tree) = create_coin(&context, 43, &output(), 3).unwrap();
        let mut key = application.to_vec();
        key.extend_from_slice(&[5; 32]);
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        store
            .save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &key, &blob)
            .unwrap();
        assert!(load_committed_snapshot(
            &state,
            &network,
            &application,
            SnapshotLimits {
                max_coins: 4,
                max_nodes: 16,
                ..limits
            }
        )
        .is_err());
    }
}

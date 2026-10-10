//! The canonical application roots the global materializer keeps from shard
//! reports.
//!
//! Every certified app-shard header may carry its shard's accumulator report.
//! The global materializer records each reported subtree, folds the
//! application's current subtrees into its root, and publishes that root into
//! a bounded root history — the one a spend's root is checked against once
//! commits go through the global frame.
//!
//! Rules, all deterministic from the certified headers alone:
//!
//! * **Ownership.** A report's shard is the header's own filter, whose
//!   committee signed it, so a shard can only report its own subtree.
//! * **Monotonic.** Coins only accumulate. A report with fewer coins than the
//!   recorded subtree is stale and ignored; one with the same count and a
//!   different root is an equivocation and refused.
//! * **Topology.** A report replaces every recorded subtree of the same width
//!   that overlaps it — an ancestor after a split, descendants after a merge —
//!   so the recorded set stays prefix-free. Until every new shard has reported,
//!   the canonical root can lack some coins (never contain a false one); the
//!   header heartbeat bounds how long.
//!
//! GLOBAL records, all vertex trees under the global intrinsic address:
//!
//! * subtree: context, coins, root — one per `(application, width, shard)`;
//! * index: context and the application's current `(width, shard)` entries;
//! * root history: the application's published roots.
use super::{coin_blocks, roots, shard_accumulator::{self, ShardReport}};
use crate::global_schema::GLOBAL_INTRINSIC_ADDRESS;
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
use num_bigint::BigInt;
use quil_lattice_ct::confidential::{
    coin_tree::RootRecord,
    relation::membership::{Node, NODE_BYTES},
};
use quil_types::error::{QuilError, Result};

/// Subtrees one application's index may hold (mainnet QUIL at depth 9 is 512
/// shards in one width layer).
pub const MAX_SUBTREES: usize = 4096;
const ENTRY_BYTES: usize = 1 + 1 + 8;

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("global accumulator: {message}"))
}

pub(crate) fn hash(parts: &[&[u8]]) -> Result<[u8; 32]> {
    quil_crypto::poseidon::hash_bytes_to_32(&parts.concat())
}

/// A shard path as `(len, bits left-aligned in a u64)` — the index encoding.
fn pack_shard(shard: &[bool]) -> Result<(u8, u64)> {
    if shard.len() > 64 {
        return Err(invalid("shard path longer than 64 bits"));
    }
    let bits = shard.iter().enumerate().fold(0u64, |acc, (i, bit)| {
        if *bit { acc | (1u64 << (63 - i)) } else { acc }
    });
    Ok((shard.len() as u8, bits))
}

fn unpack_shard(len: u8, bits: u64) -> Vec<bool> {
    (0..usize::from(len)).map(|i| bits & (1u64 << (63 - i)) != 0).collect()
}

pub fn subtree_address(application: &[u8; 32], width: u8, shard: &[bool]) -> Result<[u8; 32]> {
    let (len, bits) = pack_shard(shard)?;
    hash(&[b"quil/accumulator/subtree/v1\0", application, &[width, len], &bits.to_be_bytes()])
}

pub fn index_address(application: &[u8; 32]) -> Result<[u8; 32]> {
    hash(&[b"quil/accumulator/index/v1\0", application])
}

pub fn root_history_address(application: &[u8; 32]) -> Result<[u8; 32]> {
    hash(&[b"quil/accumulator/root-history/v1\0", application])
}

pub(crate) fn kind(tag: &str) -> Result<[u8; 32]> {
    hash(&[tag.as_bytes()])
}

pub(crate) fn write_record(state: &HypergraphState, frame: u64, address: &[u8; 32], fields: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    for (key, value) in fields {
        tree.insert(key, value, &[], &BigInt::from(value.len()))?;
    }
    let blob = quil_tries::serialize_go_tree(tree.root.as_ref())
        .map_err(|_| QuilError::ExecutionUnavailable("cannot encode accumulator record".into()))?;
    let disc = vertex_adds_discriminator()?;
    if state.get(&GLOBAL_INTRINSIC_ADDRESS, address, &disc)?.as_deref() != Some(blob.as_slice()) {
        state.set(&GLOBAL_INTRINSIC_ADDRESS, address, &disc, frame, blob)?;
    }
    Ok(())
}

/// The kind of the record at `address`, `None` when absent.
pub(crate) fn record_kind(state: &HypergraphState, address: &[u8; 32]) -> Result<Option<[u8; 32]>> {
    let disc = vertex_adds_discriminator()?;
    let Some(blob) = state.get(&GLOBAL_INTRINSIC_ADDRESS, address, &disc)? else { return Ok(None) };
    if blob.is_empty() {
        return Ok(None);
    }
    let tree = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(&blob).map_err(|_| invalid("malformed record"))?,
    };
    tree.get(&[0xff; 32]).map(|kind| kind.try_into().map_err(|_| invalid("malformed record kind"))).transpose()
}

/// Remove the record at `address`.
pub(crate) fn clear_record(state: &HypergraphState, frame: u64, address: &[u8; 32]) -> Result<()> {
    let disc = vertex_adds_discriminator()?;
    if state.get(&GLOBAL_INTRINSIC_ADDRESS, address, &disc)?.is_some_and(|blob| !blob.is_empty()) {
        state.set(&GLOBAL_INTRINSIC_ADDRESS, address, &disc, frame, Vec::new())?;
    }
    Ok(())
}

/// Read a record's fields, checking its kind. `None` when absent.
pub(crate) fn read_record(state: &HypergraphState, address: &[u8; 32], expected_kind: &[u8; 32], keys: &[&[u8]]) -> Result<Option<Vec<Vec<u8>>>> {
    let disc = vertex_adds_discriminator()?;
    let Some(blob) = state.get(&GLOBAL_INTRINSIC_ADDRESS, address, &disc)? else { return Ok(None) };
    if blob.is_empty() {
        return Ok(None);
    }
    let tree = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(&blob).map_err(|_| invalid("malformed record"))?,
    };
    if tree.get(&[0xff; 32]) != Some(expected_kind.as_slice()) {
        return Err(invalid("record of another kind at an accumulator address"));
    }
    keys.iter()
        .map(|key| tree.get(key).map(<[u8]>::to_vec).ok_or_else(|| invalid("record missing a field")))
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

struct Subtree {
    coins: u64,
    root: Node,
}

fn read_subtree(state: &HypergraphState, application: &[u8; 32], width: u8, shard: &[bool]) -> Result<Option<Subtree>> {
    let kind = kind("quil/accumulator/subtree-record/v1\0")?;
    let Some(fields) = read_record(state, &subtree_address(application, width, shard)?, &kind, &[&[4], &[8]])? else {
        return Ok(None);
    };
    let coins = u64::from_be_bytes(fields[0].as_slice().try_into().map_err(|_| invalid("malformed coins"))?);
    if fields[1].len() != NODE_BYTES {
        return Err(invalid("malformed root"));
    }
    let root = Node::from_bytes(&fields[1]).map_err(|_| invalid("malformed root"))?;
    Ok(Some(Subtree { coins, root }))
}

type Index = Vec<(u8, Vec<bool>)>;

/// Every subtree the application's shards have reported: `(width, shard path,
/// coins, root)`. These fold to the canonical root, and a coin's path to it
/// runs through the shard's own subtree and then over these.
pub fn subtrees(state: &HypergraphState, application: &[u8; 32]) -> Result<Vec<(u8, Vec<bool>, u64, Node)>> {
    let Some((_, index)) = read_index(state, application)? else { return Ok(Vec::new()) };
    let mut subtrees = Vec::with_capacity(index.len());
    for (width, shard) in index {
        let Some(subtree) = read_subtree(state, application, width, &shard)? else {
            return Err(invalid("indexed subtree has no record"));
        };
        subtrees.push((width, shard, subtree.coins, subtree.root));
    }
    Ok(subtrees)
}

pub(crate) fn read_index(state: &HypergraphState, application: &[u8; 32]) -> Result<Option<([u8; 32], Index)>> {
    let kind = kind("quil/accumulator/index-record/v1\0")?;
    let Some(fields) = read_record(state, &index_address(application)?, &kind, &[&[0], &[4]])? else {
        return Ok(None);
    };
    let context: [u8; 32] = fields[0].as_slice().try_into().map_err(|_| invalid("malformed context"))?;
    if fields[1].len() % ENTRY_BYTES != 0 || fields[1].len() / ENTRY_BYTES > MAX_SUBTREES {
        return Err(invalid("malformed index"));
    }
    let index = fields[1]
        .chunks_exact(ENTRY_BYTES)
        .map(|entry| (entry[0], unpack_shard(entry[1], u64::from_be_bytes(entry[2..10].try_into().unwrap()))))
        .collect();
    Ok(Some((context, index)))
}

/// The application's canonical current root and its encoded history, if any
/// shard of it has reported.
pub fn read_root_history(state: &HypergraphState, application: &[u8; 32]) -> Result<Option<Vec<u8>>> {
    let kind = kind("quil/accumulator/root-history-record/v1\0")?;
    Ok(read_record(state, &root_history_address(application)?, &kind, &[&[0]])?.map(|mut fields| fields.remove(0)))
}

/// Whether the application's canonical root history retains `root`.
pub fn accepts_root(state: &HypergraphState, application: &[u8; 32], context: &[u8; 32], depth: u8, root: &Node) -> Result<bool> {
    match read_root_history(state, application)? {
        Some(history) => roots::history_retains(&history, context, depth, root),
        None => Ok(false),
    }
}

fn overlaps(a: &[bool], b: &[bool]) -> bool {
    let n = a.len().min(b.len());
    a[..n] == b[..n]
}

/// Structural check of a header's accumulator field: empty, or a canonical
/// report whose layers the header's shard can own.
pub fn verify_report(filter: &[u8], report: &[u8]) -> Result<Option<(ShardReport, [u8; 32], Vec<bool>)>> {
    if report.is_empty() {
        return Ok(None);
    }
    let report = ShardReport::decode(report)?;
    let (application, shard) = quil_forest::decode_shard_filter_or_root(filter, 32)
        .ok_or_else(|| invalid("header filter names no shard"))?;
    let application: [u8; 32] = application.as_slice().try_into().map_err(|_| invalid("malformed application"))?;
    for subtree in &report.subtrees {
        shard_accumulator::subtree_position(subtree.width, &shard)?;
    }
    // A shard attests only a block on its own path narrower than it whose
    // records it holds: the one shard whose counts for that block are final.
    for attestation in &report.attestations {
        if usize::from(coin_blocks::creation_width(attestation.block)) >= shard.len()
            || !super::global_commit::holds_block_records(&shard, attestation.block)
        {
            return Err(invalid("an attestation for a block this shard does not hold"));
        }
    }
    Ok(Some((report, application, shard)))
}

/// Record one certified header's accumulator report. Returns whether the
/// application's canonical root changed.
pub fn materialize_report(state: &HypergraphState, frame: u64, filter: &[u8], report: &[u8]) -> Result<bool> {
    let Some((report, application, shard)) = verify_report(filter, report)? else { return Ok(false) };
    if !report.attestations.is_empty() {
        if frame < super::global_commit::orphan_replacement_frame() {
            return Err(invalid("block attestations before the orphan re-placement frame"));
        }
        for attestation in &report.attestations {
            super::global_commit::apply_orphan_attestation(
                state, frame, &application, attestation.block, attestation.coins, attestation.escrows,
            )?;
        }
    }
    let (context, mut index) = match read_index(state, &application)? {
        Some((context, _)) if context != report.context => {
            return Err(invalid("report context differs from the application's recorded context"));
        }
        Some((context, index)) => (context, index),
        None => (report.context, Vec::new()),
    };

    let subtree_kind = kind("quil/accumulator/subtree-record/v1\0")?;
    // Widths below the placement width receive no further coins: their blocks
    // are frozen. A recorded ancestor's subtree of a frozen width therefore
    // already holds everything a deeper shard could report for it, and it
    // must stay: once the application splits past a width, a block of that
    // width can straddle two children, neither of which can report it, and
    // replacing the ancestor's record dropped that block's coins from the
    // canonical root.
    let placement = super::global_commit::placement_width(state, &application)?;
    let frozen_under_ancestor = |width: u8, index: &[(u8, Vec<bool>)]| {
        width < placement
            && index.iter().any(|(w, entry)| *w == width && entry.len() < shard.len() && shard.starts_with(entry))
    };
    let mut changed = false;
    for subtree in &report.subtrees {
        if frozen_under_ancestor(subtree.width, &index) {
            continue;
        }
        match read_subtree(state, &application, subtree.width, &shard)? {
            Some(existing) if existing.coins > subtree.coins => continue,
            Some(existing) if existing.coins == subtree.coins => {
                if existing.root != subtree.root {
                    return Err(invalid("equivocating report: same coins, different root"));
                }
                // A heartbeat: the subtree is recorded, but after a topology
                // change it may have been dropped from the index; re-admit it.
                if index.iter().any(|(width, entry)| *width == subtree.width && *entry == shard) {
                    continue;
                }
            }
            _ => {}
        }
        index.retain(|(width, entry)| *width != subtree.width || !overlaps(entry, &shard));
        index.push((subtree.width, shard.clone()));
        write_record(state, frame, &subtree_address(&application, subtree.width, &shard)?, &[
            (vec![0xff; 32], subtree_kind.to_vec()),
            (vec![0], context.to_vec()),
            (vec![4], subtree.coins.to_be_bytes().to_vec()),
            (vec![8], subtree.root.to_bytes().to_vec()),
        ])?;
        changed = true;
    }
    if !changed {
        return Ok(false);
    }
    if index.len() > MAX_SUBTREES {
        return Err(invalid("too many subtrees for one application"));
    }
    index.sort_by(|a, b| (a.0, pack_shard(&a.1).ok()).cmp(&(b.0, pack_shard(&b.1).ok())));
    let mut entries = Vec::with_capacity(index.len() * ENTRY_BYTES);
    for (width, entry) in &index {
        let (len, bits) = pack_shard(entry)?;
        entries.push(*width);
        entries.push(len);
        entries.extend_from_slice(&bits.to_be_bytes());
    }
    write_record(state, frame, &index_address(&application)?, &[
        (vec![0xff; 32], kind("quil/accumulator/index-record/v1\0")?.to_vec()),
        (vec![0], context.to_vec()),
        (vec![4], entries),
    ])?;

    let mut subtrees = Vec::with_capacity(index.len());
    let mut coins = 0u64;
    for (width, entry) in &index {
        let subtree = read_subtree(state, &application, *width, entry)?
            .ok_or_else(|| invalid("indexed subtree has no record"))?;
        coins = coins.checked_add(subtree.coins).ok_or_else(|| invalid("coin count overflow"))?;
        subtrees.push((*width, entry.clone(), subtree.root));
    }
    let root = shard_accumulator::fold_application_root(&context, &subtrees)?;
    let current = RootRecord { context, depth: coin_blocks::DEPTH, coins, root };
    let existing = read_root_history(state, &application)?;
    tracing::info!(
        frame,
        application = %hex::encode(&application[..8]),
        coins,
        subtrees = index.len(),
        // The widest layer any shard reports: growth past six bits shows here.
        max_width = index.iter().map(|(width, _)| *width).max().unwrap_or(0),
        root = %hex::encode(&quil_crypto::poseidon::hash_bytes_to_32(&current.root.to_bytes())?[..8]),
        record = %hex::encode(&root_history_address(&application)?[..8]),
        "canonical application root published",
    );
    let history = roots::publish_history(existing.as_deref(), current)?;
    write_record(state, frame, &root_history_address(&application)?, &[
        (vec![0xff; 32], kind("quil/accumulator/root-history-record/v1\0")?.to_vec()),
        (vec![0], history),
    ])?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hypergraph_state::vertex_adds_discriminator;
    use quil_lattice_ct::confidential::{
        relation::membership::IDENTITY_BYTES, transfer::{parameter_context, Output}, AmountOpening, CommitmentKey,
    };
    use std::collections::BTreeMap;

    fn mem_state() -> HypergraphState {
        HypergraphState::new(std::sync::Arc::new(quil_hypergraph::HypergraphCrdt::new(
            std::sync::Arc::new(quil_hypergraph::testing::MemStore::new()),
            std::sync::Arc::new(quil_types::crypto::NoopInclusionProver),
        )))
    }

    fn filter(application: &[u8; 32], shard: &[bool]) -> Vec<u8> {
        if shard.is_empty() { application.to_vec() } else { quil_forest::encode_shard_bit_path(application, shard) }
    }

    /// An application with coins staged through the real accumulator, and the
    /// root it published locally.
    fn application_with_coins(seeds: std::ops::RangeInclusive<u8>) -> (HypergraphState, [u8; 32], [u8; 32], RootRecord) {
        let state = mem_state();
        let (network, application) = ([41u8; 32], [42u8; 32]);
        let context = parameter_context(&network, &application);
        let limits = super::super::state::SnapshotLimits { max_coins: 256, max_depth: 32, max_nodes: 1 << 16 };
        let disc = vertex_adds_discriminator().unwrap();
        let key = CommitmentKey::derive(&context);
        let mut staged = BTreeMap::new();
        for seed in seeds {
            let output = Output {
                owner: [seed; IDENTITY_BYTES],
                commitment: key.commit(u128::from(seed), &AmountOpening::from_seed(&context, &[seed; 32])),
                memo: [seed; 1115],
            };
            let (address, tree) = roots::stage_coin(&state, &network, &application, &context, 1, &output, &mut staged, limits).unwrap();
            state.set(&application, &address, &disc, 1, quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()).unwrap();
        }
        let published = roots::refresh_root(&state, &network, &application, limits).unwrap();
        (state, network, application, published)
    }

    fn report(state: &HypergraphState, network: &[u8; 32], application: &[u8; 32], shard: &[bool]) -> Vec<u8> {
        shard_accumulator::shard_report(state, network, application, shard, false).unwrap()
            .map(|report| report.encode().unwrap())
            .unwrap_or_default()
    }

    /// Reports from every shard of a partition publish exactly the root the
    /// accumulator computes, and that root is then accepted.
    #[test]
    fn shard_reports_publish_the_application_root() {
        let (local, network, application, published) = application_with_coins(1..=20);
        let global = mem_state();
        let shards = [vec![false, false], vec![false, true], vec![true]];
        for shard in &shards {
            let bytes = report(&local, &network, &application, shard);
            if !bytes.is_empty() {
                materialize_report(&global, 10, &filter(&application, shard), &bytes).unwrap();
            }
        }
        let history = read_root_history(&global, &application).unwrap().unwrap();
        assert_eq!(roots::decode_current(&history, &published.context).unwrap(), published);
        assert!(accepts_root(&global, &application, &published.context, published.depth, &published.root).unwrap());
        // Re-sending the same reports (the heartbeat) changes nothing.
        for shard in &shards {
            let bytes = report(&local, &network, &application, shard);
            if !bytes.is_empty() {
                assert!(!materialize_report(&global, 11, &filter(&application, shard), &bytes).unwrap());
            }
        }
    }

    /// Stale reports are ignored, equivocations and context changes refused,
    /// and a shard can only place its report at its own position.
    #[test]
    fn stale_equivocating_and_foreign_reports_do_not_move_the_root() {
        let (early, network, application, _) = application_with_coins(1..=6);
        let (late, _, _, published) = application_with_coins(1..=12);
        let global = mem_state();
        let whole = filter(&application, &[]);
        let late_report = report(&late, &network, &application, &[]);
        assert!(materialize_report(&global, 10, &whole, &late_report).unwrap());
        // An older report (fewer coins) arriving later is ignored.
        assert!(!materialize_report(&global, 11, &whole, &report(&early, &network, &application, &[])).unwrap());
        let current = || roots::decode_current(&read_root_history(&global, &application).unwrap().unwrap(), &published.context).unwrap();
        assert_eq!(current(), published);
        // Same coin count, different root: refused.
        let mut forged = ShardReport::decode(&late_report).unwrap();
        forged.subtrees[0].root = ShardReport::decode(&report(&early, &network, &application, &[])).unwrap().subtrees[0].root.clone();
        assert!(materialize_report(&global, 12, &whole, &forged.encode().unwrap()).is_err());
        // A different network's context for the same application: refused.
        let mut other_network = ShardReport::decode(&late_report).unwrap();
        other_network.context = [0xAA; 32];
        other_network.subtrees[0].coins += 1;
        assert!(materialize_report(&global, 13, &whole, &other_network.encode().unwrap()).is_err());
        assert_eq!(current(), published);
        // A filter naming no shard, or a shard deeper than the width: refused.
        assert!(materialize_report(&global, 14, &[1, 2, 3], &late_report).is_err());
        let too_deep = filter(&application, &[true; 7]);
        assert!(materialize_report(&global, 15, &too_deep, &late_report).is_err());
    }

    /// A split past the initial width: coins staged at width six, the width
    /// raised to seven, more coins staged, and the application then held by a
    /// complete partition whose deepest shards are seven bits. Those shards own
    /// no whole width-six block and report only their width-seven layer; the
    /// canonical root must still account for every coin, old and new.
    #[test]
    fn a_partition_deeper_than_six_bits_accounts_for_every_coin() {
        let state = mem_state();
        let (network, application) = ([41u8; 32], [42u8; 32]);
        let context = parameter_context(&network, &application);
        let limits = super::super::state::SnapshotLimits { max_coins: 256, max_depth: 32, max_nodes: 1 << 16 };
        let disc = vertex_adds_discriminator().unwrap();
        let key = CommitmentKey::derive(&context);
        let mut staged = BTreeMap::new();
        let mut stage = |seed: u8, state: &HypergraphState| {
            let output = Output {
                owner: [seed; IDENTITY_BYTES],
                commitment: key.commit(u128::from(seed), &AmountOpening::from_seed(&context, &[seed; 32])),
                memo: [seed; 1115],
            };
            let (address, tree) = roots::stage_coin(state, &network, &application, &context, 1, &output, &mut staged, limits).unwrap();
            state.set(&application, &address, &disc, 1, quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()).unwrap();
        };
        let global = mem_state();
        for seed in 1..=12u8 {
            stage(seed, &state);
        }
        roots::refresh_root(&state, &network, &application, limits).unwrap();
        // Before the split: the whole application reports its width-six layer.
        materialize_report(&global, 10, &filter(&application, &[]), &report(&state, &network, &application, &[])).unwrap();

        // The split that goes past six bits raises the width first: the
        // application's own block space, and GLOBAL's placement width.
        state.set(&application, &super::super::state::SHAPE_ADDRESS, &disc, 1, vec![7]).unwrap();
        super::super::global_commit::raise_placement_width(&global, 11, &application, 7).unwrap();
        for seed in 13..=24u8 {
            stage(seed, &state);
        }
        let exact = roots::refresh_root(&state, &network, &application, limits).unwrap();
        // The hard case must be present: a width-six block under the seven-bit
        // leaves, which no shard of the new partition owns whole. With this
        // fixture's coins that is block `000100`.
        let b = |bits: &str| bits.chars().map(|c| c == '1').collect::<Vec<bool>>();
        let summary = roots::block_summary(&state, &application).unwrap();
        let frozen = coin_blocks::block_id(6, 0b000100).unwrap();
        assert!(summary.blocks.iter().any(|(block, coins, _)| *block == frozen && *coins > 0),
            "the fixture must hold coins in the width-six block under the seven-bit leaves");

        // A complete partition that descends to seven bits through `000100`.
        let partition: Vec<Vec<bool>> = ["1", "01", "001", "0000", "00011", "000101", "0001000", "0001001"]
            .iter().map(|bits| b(bits)).collect();
        for shard in &partition {
            let bytes = report(&state, &network, &application, shard);
            if !bytes.is_empty() {
                materialize_report(&global, 11, &filter(&application, shard), &bytes).unwrap();
            }
        }
        let published = roots::decode_current(&read_root_history(&global, &application).unwrap().unwrap(), &context).unwrap();
        assert_eq!(published.coins, exact.coins, "every coin, old and new, is accounted for");
        assert_eq!(published.root, exact.root, "the canonical root equals the application's own");
        // The width-six layer is still the whole application's frozen record.
        let (_, index) = read_index(&global, &application).unwrap().unwrap();
        assert!(index.contains(&(6, Vec::new())));
        assert!(index.iter().all(|(width, shard)| *width == 7 || shard.is_empty()));

        // Merge back to the whole application: its report replaces the
        // seven-bit layers and repeats the frozen one; the root is unchanged.
        materialize_report(&global, 12, &filter(&application, &[]), &report(&state, &network, &application, &[])).unwrap();
        let merged = roots::decode_current(&read_root_history(&global, &application).unwrap().unwrap(), &context).unwrap();
        assert_eq!((merged.coins, merged.root), (exact.coins, exact.root));
        let (_, index) = read_index(&global, &application).unwrap().unwrap();
        assert_eq!(index, vec![(6, Vec::new()), (7, Vec::new())]);
    }

    /// A split replaces the parent's subtree with its children's as they
    /// report, and a merge replaces the children with the parent: the recorded
    /// set never overlaps, and once every shard has reported the root is exact.
    #[test]
    fn topology_changes_replace_overlapping_subtrees() {
        let (before, network, application, at_split) = application_with_coins(1..=10);
        let (after, _, _, grown) = application_with_coins(1..=16);
        let global = mem_state();
        let root_now = || roots::decode_current(&read_root_history(&global, &application).unwrap().unwrap(), &at_split.context).unwrap();

        materialize_report(&global, 10, &filter(&application, &[]), &report(&before, &network, &application, &[])).unwrap();
        assert_eq!(root_now(), at_split);
        // Split. Coin addresses are Poseidon (BN254) images, so every address
        // begins `00` and a split at the root would leave one half empty; this
        // is the deep split a size-driven proposer actually makes, with its
        // spine. Shards holding no coins send no report.
        let partition = [vec![true], vec![false, true], vec![false, false, false], vec![false, false, true]];
        let mut reporting = 0;
        for shard in &partition {
            let bytes = report(&after, &network, &application, shard);
            if !bytes.is_empty() {
                reporting += 1;
                materialize_report(&global, 11, &filter(&application, shard), &bytes).unwrap();
            }
        }
        assert!(reporting >= 2, "the fixture must exercise more than one reporting child");
        assert_eq!(root_now(), grown, "the children's reports replace the parent's");
        let (_, index) = read_index(&global, &application).unwrap().unwrap();
        assert_eq!(index.len(), reporting);
        // Merge back: the parent's report replaces both children.
        materialize_report(&global, 12, &filter(&application, &[]), &report(&after, &network, &application, &[])).unwrap();
        let (_, index) = read_index(&global, &application).unwrap().unwrap();
        assert_eq!(index, vec![(coin_blocks::INITIAL_BLOCK_BITS, Vec::new())]);
        assert_eq!(root_now(), grown);
    }
}

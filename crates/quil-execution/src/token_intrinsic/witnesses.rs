//! Wallet witnesses from a committed coin snapshot. Transport wiring
//! remains separate; a returned root must still be checked by spend admission.
use super::{
    roots,
    state::{load_committed_snapshot, SnapshotLimits},
};
use crate::hypergraph_state::HypergraphState;
#[cfg(test)]
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
use quil_lattice_ct::confidential::{
    coin_tree::{AuthPath, RootRecord, ROOT_RECORD_BYTES},
    relation::membership::NODE_BYTES,
    MAX_PRIVATE_COINS,
};
use quil_types::error::{QuilError, Result};
use std::collections::BTreeSet;

pub struct CoinWitness {
    pub address: [u8; 32],
    pub path: Option<AuthPath>,
}
pub struct Witnesses {
    pub root: RootRecord,
    pub coins: Vec<CoinWitness>,
}

/// Bounds the unframed canonical node/direction/address data, not RPC framing,
/// process RSS or the underlying committed-store scan I/O. A transport must
/// separately bound its fully encoded response.
#[derive(Clone, Copy)]
pub struct WitnessLimits {
    pub snapshot: SnapshotLimits,
    pub max_requests: usize,
    pub max_path_data_bytes: usize,
}

/// Witnesses against the application's canonical root: the shard's own path
/// to its subtree, then the fold over what every shard reported. A spend
/// proves against this root, which is the one the global commit accepts — a
/// shard's own root is only part of it.
///
/// `local` is the committed state of whatever part of the application this
/// node holds — one shard's, or every shard's on an archive — `global` a view
/// of GLOBAL, and
/// `local_roots` the roots its witness index can serve paths at, newest first.
/// The path must reach the subtree the reports folded in, so the root it is
/// built at is the one the shard's last report covered — usually not its
/// newest, since a report lags the coins it reports by a frame or two.
/// A shard holding the whole application reports one subtree covering
/// everything, so the fold is empty and this is its local path.
pub fn canonical_witnesses(
    local: &HypergraphState,
    global: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    addresses: &[[u8; 32]],
    local_roots: &[RootRecord],
    index: &super::witness_index::LocalWitnessIndex,
) -> Result<Witnesses> {
    use quil_lattice_ct::confidential::{coin_tree::CoinRecord, sharded_tree};
    let context = quil_lattice_ct::confidential::transfer::parameter_context(network, application);
    let unavailable = |what: &str| QuilError::ExecutionUnavailable(format!("canonical witness: {what}"));
    let reported = super::global_accumulator::subtrees(global, application)?;
    if reported.is_empty() {
        return Err(unavailable("the application has no canonical root yet"));
    }
    let nodes = reported
        .iter()
        .map(|(width, shard, _, root)| {
            let (level, at) = super::shard_accumulator::subtree_position(*width, shard)?;
            Ok((level, at, root.clone()))
        })
        .collect::<Result<Vec<_>>>()?;
    let depth = usize::from(super::coin_blocks::DEPTH);
    let root = sharded_tree::fold_sparse(&context, depth, &nodes)
        .map_err(|e| unavailable(&format!("fold: {e:?}")))?;
    let coins = reported.iter().try_fold(0u64, |total, (_, _, coins, _)| {
        total.checked_add(*coins).ok_or_else(|| unavailable("coin count overflow"))
    })?;
    let canonical = RootRecord { context, depth: super::coin_blocks::DEPTH, coins, root };

    // The subtree a coin sits under is the one whose shard owns its block —
    // a property of the coin, not of whoever serves the witness. An archive
    // holding every shard answers for all of them; a shard answers for its
    // own, which is the only part of the application it has.
    let subtree_of = |position: u64| -> Result<((usize, u64), quil_lattice_ct::confidential::relation::membership::Node)> {
        let (block, _) = super::coin_blocks::locate(position);
        let width = super::coin_blocks::creation_width(block);
        reported
            .iter()
            .find(|(at_width, at, _, _)| *at_width == width && super::coin_blocks::shard_owns_block(at, block))
            .map(|(width, shard, _, root)| Ok::<_, QuilError>((super::shard_accumulator::subtree_position(*width, shard)?, root.clone())))
            .transpose()?
            .ok_or_else(|| unavailable("no shard has reported the subtree this coin is in"))
    };

    // The shard's own root: the same tree below its subtree's level, with
    // every other shard's subtree still zero — which the fold replaces.
    let key = quil_lattice_ct::confidential::relation::membership::MembershipKey::derive(&context);
    let disc = crate::hypergraph_state::vertex_adds_discriminator()?;
    let mut coins = Vec::with_capacity(addresses.len());
    for address in addresses {
        match local.get(application, address, &disc)? {
            None => coins.push((*address, None)),
            Some(blob) => {
                let mut store_key = application.to_vec();
                store_key.extend_from_slice(address);
                match super::state::decode_stored_snapshot_coin(&context, application, &store_key, &blob)? {
                    None => coins.push((*address, None)),
                    Some(coin) => coins.push((*address, Some(coin.record(*address)))),
                }
            }
        }
    }

    // A report lags the coins it reports, so the newest root the index serves
    // is usually not the one the reports folded in. Take the newest root that
    // is: its paths reach the subtree GLOBAL holds, and so the canonical root.
    let mut last = unavailable("this shard has not reported its coins yet; retry");
    for local_root in local_roots {
        if local_root.context != context
            || !roots::accepts_root(local, network, application, local_root.depth, &local_root.root)?
        {
            continue;
        }
        let mut witnesses = Vec::with_capacity(coins.len());
        let mut matches = true;
        for (address, record) in &coins {
            let Some(record) = record else {
                witnesses.push(CoinWitness { address: *address, path: None });
                continue;
            };
            let (mine, reported_subtree) = subtree_of(record.position)?;
            let fold = sharded_tree::fold_sparse_auth_path(&context, depth, &nodes, mine)
                .map_err(|e| unavailable(&format!("fold path: {e:?}")))?;
            let mut path = match index.auth_path(local_root, record) {
                Ok(path) if path.siblings.len() == depth => path,
                // A coin newer than this root, or a root the index no longer
                // serves: try an older one.
                _ => { matches = false; break }
            };
            path.siblings.truncate(mine.0);
            path.right.truncate(mine.0);
            // The path so far must reach exactly the subtree the reports folded
            // in. It does not while a report is behind the coins asked for.
            let owner = quil_lattice_ct::confidential::relation::membership::Node::from_identity_bytes(&record.owner)
                .map_err(|_| unavailable("stored coin owner"))?;
            let mut node = key.leaf(&owner, &record.commitment);
            for (sibling, right) in path.siblings.iter().zip(&path.right) {
                node = if *right { key.parent(sibling, &node) } else { key.parent(&node, sibling) };
            }
            if node != reported_subtree {
                matches = false;
                break;
            }
            path.siblings.extend(fold.siblings);
            path.right.extend(fold.right);
            witnesses.push(CoinWitness { address: *address, path: Some(path) });
        }
        if matches {
            return Ok(Witnesses { root: canonical, coins: witnesses });
        }
        last = unavailable("this shard's report is behind the coins asked for; retry");
    }
    Err(last)
}

pub fn committed_witnesses(
    state: &HypergraphState,
    network: &[u8; 32],
    application: &[u8; 32],
    addresses: &[[u8; 32]],
    limits: WitnessLimits,
) -> Result<Witnesses> {
    if addresses.is_empty()
        || addresses.len() > limits.max_requests
        || addresses.len() > MAX_PRIVATE_COINS
        || addresses.iter().collect::<BTreeSet<_>>().len() != addresses.len()
    {
        return Err(QuilError::InvalidArgument(
            "coin witness: invalid address count or duplicates".into(),
        ));
    }
    // Charge the accumulator's real depth before loading the tree. It is a
    // property of the tree's fixed shape, not of the caller's limits, so
    // charging a caller-supplied depth would under-bill every path served.
    let maximum = usize::from(super::coin_blocks::DEPTH)
        .checked_mul(NODE_BYTES + 1)
        .and_then(|n| n.checked_add(33))
        .and_then(|n| n.checked_mul(addresses.len()))
        .and_then(|n| n.checked_add(ROOT_RECORD_BYTES));
    if maximum.is_none_or(|bytes| bytes > limits.max_path_data_bytes) {
        return Err(QuilError::InvalidArgument(
            "coin witness: path data limit exceeded".into(),
        ));
    }
    let tree = load_committed_snapshot(state, network, application, limits.snapshot)?;
    // The accumulator has one shape, so the snapshot's root is the application
    // root the per-block fold publishes — the same value a wallet's path must
    // reach.
    let root = RootRecord {
        context: quil_lattice_ct::confidential::transfer::parameter_context(network, application),
        depth: tree.shape().depth() as u8,
        coins: roots::summary_coins(state, application)?,
        root: tree.root(),
    };
    // Root changes during construction are harmless if this exact root remains
    // retained. If it has been evicted, fail and let the caller retry a snapshot.
    if !roots::accepts_root(state, network, application, root.depth, &root.root)? {
        return Err(QuilError::NotFound(
            "coin witness: snapshot root is not retained; synchronize and retry".into(),
        ));
    }
    let mut coins = Vec::with_capacity(addresses.len());
    for address in addresses {
        let path = match tree.auth_path(address) {
            Ok(path) => Some(path),
            Err(quil_lattice_ct::confidential::coin_tree::TreeError::MissingCoin) => None,
            Err(e) => {
                return Err(QuilError::Internal(format!(
                    "coin witness path: {e:?}"
                )))
            }
        };
        coins.push(CoinWitness {
            address: *address,
            path,
        });
    }
    Ok(Witnesses { root, coins })
}

/// Point-read witness serving against a retained canonical root. The index
/// is local and untrusted; absence of an indexed node never means no coin.
pub fn indexed_witnesses(
    state: &HypergraphState, network: &[u8; 32], application: &[u8; 32],
    addresses: &[[u8; 32]], root: RootRecord,
    index: &super::witness_index::LocalWitnessIndex,
) -> Result<Witnesses> {
    use crate::hypergraph_state::vertex_adds_discriminator;
    let unavailable = || QuilError::ExecutionUnavailable("coin witness index unavailable or stale; retry after synchronization".into());
    if addresses.is_empty() || addresses.len() > 4 || addresses.len() > MAX_PRIVATE_COINS
        || addresses.iter().collect::<BTreeSet<_>>().len() != addresses.len() {
        return Err(QuilError::InvalidArgument("coin witness: invalid address count or duplicates".into()));
    }
    let context = quil_lattice_ct::confidential::transfer::parameter_context(network, application);
    if root.context != context || !roots::accepts_root(state, network, application, root.depth, &root.root)? {
        return Err(unavailable());
    }
    let disc = vertex_adds_discriminator()?;
    let mut coins = Vec::new();
    for address in addresses {
        let path = match state.get(application, address, &disc)? {
            None => None,
            Some(blob) => {
                if blob.len() > 64 * 1024 { return Err(unavailable()); }
                let mut key = application.to_vec(); key.extend_from_slice(address);
                match super::state::decode_stored_snapshot_coin(&context, application, &key, &blob)? {
                    None => None,
                    // Whether the coin is in the tree at this root is the
                    // index's answer to give: positions are block-partitioned,
                    // so a total count says nothing about one coin's block.
                    Some(coin) => Some(index.auth_path(&root, &coin.record(*address))?),
                }
            }
        };
        coins.push(CoinWitness { address: *address, path });
    }
    if !roots::accepts_root(state, network, application, root.depth, &root.root)? { return Err(unavailable()); }
    Ok(Witnesses { root, coins })
}

#[cfg(test)]
mod tests {
    use super::super::state::create_coin;
    use super::*;
    use crate::hypergraph_state::vertex_adds_discriminator;
    use quil_lattice_ct::confidential::{
        relation::membership::{MembershipKey, Node},
        transfer::{parameter_context, Output},
        AmountOpening, CommitmentKey,
    };
    use quil_types::crypto::NoopInclusionProver;
    use std::sync::Arc;
    /// Two shards of one split application, their coins in one state as an
    /// archive holds them. Each coin proves against the root every shard folds
    /// into, through the subtree ITS OWN block belongs to — coins of different
    /// shards take different subtrees, and the server's own coverage does not
    /// enter into it.
    #[test]
    fn a_canonical_witness_proves_against_the_root_every_shard_folds_into() {
        use quil_lattice_ct::confidential::{coin_tree::CoinRecord, relation::membership::MembershipKey};
        let directory = tempfile::tempdir().unwrap();
        let db: Arc<dyn quil_types::store::KvDb> = Arc::new(quil_store::RocksDb::open(directory.path()).unwrap());
        let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(NoopInclusionProver),
        )));
        let (network, application) = ([1u8; 32], [2u8; 32]);
        let context = parameter_context(&network, &application);
        let limits = SnapshotLimits { max_coins: 8, max_depth: 32, max_nodes: 1 << 12 };
        let disc = vertex_adds_discriminator().unwrap();
        // A coin address is a Poseidon image, which always begins `00`, so a
        // split on the first bits puts every coin in one child. Shards that
        // actually divide the coins differ deeper in: `000` and `001`.
        let left = vec![false, false, false];
        let right = vec![false, false, true];
        let width = super::super::coin_blocks::INITIAL_BLOCK_BITS;
        let mut staged = std::collections::BTreeMap::new();
        let mut records: Vec<CoinRecord> = Vec::new();
        let mut addresses = Vec::new();
        let (mut have_left, mut have_right) = (false, false);
        for seed in 0..64u8 {
            if have_left && have_right {
                break;
            }
            let output = Output {
                owner: [seed | 1; IDENTITY_BYTES],
                commitment: CommitmentKey::derive(&context).commit(5, &AmountOpening::from_seed(&context, &[seed; 32])),
                memo: [0; 1115],
            };
            let (address, tree) = roots::stage_coin(
                &state, &network, &application, &context, 0, &output, &mut staged, limits,
            ).unwrap();
            let block = super::super::coin_blocks::block_for_address(width, &address).unwrap();
            let wanted = match (
                super::super::coin_blocks::shard_owns_block(&left, block),
                super::super::coin_blocks::shard_owns_block(&right, block),
            ) {
                (true, _) if !have_left => { have_left = true; true }
                (_, true) if !have_right => { have_right = true; true }
                _ => false,
            };
            if !wanted {
                // Not a block this test needs: unstage it.
                staged.entry(block).and_modify(|placed| *placed -= 1);
                continue;
            }
            state.set(&application, &address, &disc, 0,
                quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()).unwrap();
            let stored = super::super::state::read_coin(&tree, &context).unwrap().unwrap();
            records.push(CoinRecord {
                address, position: stored.position, owner: output.owner, commitment: output.commitment.clone(),
            });
            addresses.push(address);
        }
        assert!(have_left && have_right, "fixture needs a coin in each shard");
        let local_root = roots::refresh_root(&state, &network, &application, limits).unwrap();
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(1).unwrap();

        // Both shards report what this state holds of them, as their headers do.
        let filter = |shard: &[bool]| quil_forest::encode_shard_bit_path(&application, shard);
        for shard in [&left, &right] {
            let report = super::super::shard_accumulator::shard_report(&state, &network, &application, shard, false)
                .unwrap().expect("each shard holds a coin");
            super::super::global_accumulator::materialize_report(&state, 10, &filter(shard), &report.encode().unwrap()).unwrap();
        }

        let mut index = super::super::witness_index::LocalWitnessIndex::for_root(db.clone(), &local_root, 32).unwrap();
        let empty = roots::refresh_root(&HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()), Arc::new(NoopInclusionProver)))),
            &network, &application, limits).unwrap();
        index.append(&empty, &local_root, &records).unwrap();

        let witnesses = canonical_witnesses(
            &state, &state, &network, &application, &addresses, &[local_root.clone()], &index,
        ).unwrap();
        assert_eq!(witnesses.root.depth, super::super::coin_blocks::DEPTH);
        assert_eq!(witnesses.root.coins, local_root.coins);
        let key = MembershipKey::derive(&context);
        let mut subtrees = std::collections::BTreeSet::new();
        for record in &records {
            let witness = witnesses.coins.iter().find(|w| w.address == record.address).unwrap();
            let path = witness.path.as_ref().expect("the state holds the coin");
            assert_eq!(path.siblings.len(), usize::from(super::super::coin_blocks::DEPTH));
            let (block, _) = super::super::coin_blocks::locate(record.position);
            subtrees.insert(super::super::coin_blocks::shard_owns_block(&left, block));
            let mut node = key.leaf(
                &quil_lattice_ct::confidential::relation::membership::Node::from_identity_bytes(&record.owner).unwrap(),
                &record.commitment,
            );
            for (sibling, right) in path.siblings.iter().zip(&path.right) {
                node = if *right { key.parent(sibling, &node) } else { key.parent(&node, sibling) };
            }
            assert_eq!(node, witnesses.root.root, "coin {}", hex::encode(record.address));
        }
        assert_eq!(subtrees.len(), 2, "the coins came from both shards' subtrees");
    }

    #[test]
    fn witnesses_require_retained_roots_and_reconstruct_stored_coins() {
        let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(NoopInclusionProver),
        )));
        let network = [1; 32];
        let application = [2; 32];
        let context = parameter_context(&network, &application);
        let limits = WitnessLimits {
            snapshot: SnapshotLimits {
                max_coins: 3,
                max_depth: 32,
                max_nodes: 16,
            },
            max_requests: 3,
            max_path_data_bytes: 1 << 20,
        };
        let disc = vertex_adds_discriminator().unwrap();
        let mut addresses = Vec::new();
        let mut outputs = Vec::new();
        let mut staged = std::collections::BTreeMap::new();
        for i in 0..2 {
            let output = Output {
                owner: [i + 1; IDENTITY_BYTES],
                commitment: CommitmentKey::derive(&context)
                    .commit(5, &AmountOpening::from_seed(&context, &[i + 2; 32])),
                memo: [0; 1115],
            };
            let (address, tree) = roots::stage_coin(
                &state, &network, &application, &context, 0, &output, &mut staged, limits.snapshot,
            )
            .unwrap();
            state
                .set(
                    &application,
                    &address,
                    &disc,
                    0,
                    quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
                )
                .unwrap();
            addresses.push(address);
            outputs.push(output);
        }
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(1).unwrap();
        assert!(matches!(
            committed_witnesses(&state, &network, &application, &addresses, limits),
            Err(QuilError::NotFound(_))
        ));
        let root =
            roots::refresh_root(&state, &network, &application, limits.snapshot).unwrap();
        addresses.push([0; 32]);
        let response =
            committed_witnesses(&state, &network, &application, &addresses, limits).unwrap();
        assert_eq!(response.root, root);
        let key = MembershipKey::derive(&context);
        for ((address, witness), output) in addresses.iter().zip(&response.coins).zip(&outputs) {
            assert_eq!(&witness.address, address);
            let path = witness.path.as_ref().unwrap();
            let mut node = key.leaf(
                &Node::from_identity_bytes(&output.owner).unwrap(),
                &output.commitment,
            );
            for (sibling, &right) in path.siblings.iter().zip(&path.right) {
                node = if right {
                    key.parent(sibling, &node)
                } else {
                    key.parent(&node, sibling)
                };
            }
            assert_eq!(node, root.root);
        }
        assert!(response.coins[2].path.is_none());
        for bad in [vec![], vec![addresses[0], addresses[0]]] {
            assert!(committed_witnesses(&state, &network, &application, &bad, limits).is_err());
        }
        assert!(committed_witnesses(
            &state,
            &network,
            &application,
            &addresses,
            WitnessLimits {
                max_requests: 2,
                ..limits
            }
        )
        .is_err());
        assert!(committed_witnesses(
            &state,
            &network,
            &application,
            &addresses,
            WitnessLimits {
                max_path_data_bytes: ROOT_RECORD_BYTES,
                ..limits
            }
        )
        .is_err());
    }
}

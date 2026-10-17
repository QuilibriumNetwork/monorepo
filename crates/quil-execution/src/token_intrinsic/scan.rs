//! Bounded confidential coin and escrow enumeration from a retained database snapshot.
use super::{
    roots,
    state::{decode_stored_snapshot_coin, StoredCoin, ROOT_ADDRESS},
};
use quil_hypergraph::addressing::{shard_key_for_location, Location};
#[cfg(test)]
use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
use quil_lattice_ct::confidential::{coin_tree::RootRecord, transfer::parameter_context};
use quil_types::{
    error::{QuilError, Result},
    store::{SnapshotReadable, VertexPageLimits},
};

pub struct CoinPage {
    pub root: RootRecord,
    pub coins: Vec<([u8; 32], StoredCoin)>,
    /// Last examined vertex, including non-coin records. A page can contain no
    /// coins and still require continuation. Only `has_more == false` ends a scan.
    pub cursor: Option<[u8; 32]>,
    pub has_more: bool,
}

/// Root bound to the retained database generation used for enumeration.
///
/// The CANONICAL application root first. The per-application record read below
/// is a LOCAL root: on a split application every shard writes its own, holding
/// only the coins that shard happens to hold, and the one this lookup reaches
/// is whichever shard covers address zero. An application split BEFORE its
/// first commit has no such record at all — the whole-application inline commit
/// that writes it never runs — so every scan failed with `no root in snapshot`
/// and a wallet could not read a split application at all. The canonical root
/// is what a spend proves against and the
/// global accumulator publishes it for split and whole applications alike.
pub fn snapshot_root(snapshot: &dyn SnapshotReadable, network: &[u8; 32], application: &[u8; 32]) -> Result<RootRecord> {
    let context = parameter_context(network, application);
    if let Some(canonical) = canonical_snapshot_root(snapshot, &context, application)? {
        return Ok(canonical);
    }
    local_snapshot_root(snapshot, network, application)
}

/// Root of the coins actually present in this local snapshot. A witness
/// index rebuilds this tree, then composes paths against the published shard
/// reports. Those reports may lag local delivery and cannot describe the set
/// of leaves being indexed.
pub(super) fn local_snapshot_root(
    snapshot: &dyn SnapshotReadable,
    network: &[u8; 32],
    application: &[u8; 32],
) -> Result<RootRecord> {
    let context = parameter_context(network, application);
    let shard = shard_key_for_location(&Location {
        app_address: *application,
        data_address: [0; 32],
    });
    let mut key = [0; 64];
    key[..32].copy_from_slice(application);
    key[32..].copy_from_slice(&ROOT_ADDRESS);
    // The node-local record, else a legacy copy in the tree.
    let root_bytes = match snapshot.read_record(&super::state::local_record_key(application, &ROOT_ADDRESS)) {
        Ok(Some(bytes)) => Some(bytes),
        _ => snapshot.load_vertex_underlying_raw("vertex", "adds", &shard, &key)?,
    }
    .ok_or_else(|| QuilError::NotFound("coin scan: no root in snapshot".into()))?;
    roots::decode_current(&root_bytes, &context)
}

/// The application's canonical root as the global accumulator published it:
/// every shard's reported subtree folded into one root. `None` when no shard
/// has reported yet, which leaves the caller its local record.
fn canonical_snapshot_root(
    snapshot: &dyn SnapshotReadable,
    context: &[u8; 32],
    application: &[u8; 32],
) -> Result<Option<RootRecord>> {
    let address = super::global_accumulator::root_history_address(application)?;
    let domain = crate::global_schema::GLOBAL_INTRINSIC_ADDRESS;
    let shard = shard_key_for_location(&Location { app_address: domain, data_address: address });
    let mut key = [0; 64];
    key[..32].copy_from_slice(&domain);
    key[32..].copy_from_slice(&address);
    let found = snapshot.load_vertex_underlying_raw("vertex", "adds", &shard, &key)?;
    tracing::debug!(
        application = %hex::encode(&application[..8]),
        record = %hex::encode(&address[..8]),
        shard_l1 = ?shard.l1,
        shard_l2 = %hex::encode(&shard.l2[..8]),
        found = found.is_some(),
        "canonical coin root snapshot lookup",
    );
    let Some(blob) = found else {
        return Ok(None);
    };
    let tree = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(&blob)
            .map_err(|_| QuilError::ExecutionUnavailable("cannot decode the canonical root record".into()))?,
    };
    match tree.get(&[0]) {
        Some(history) => roots::decode_current(history, context).map(Some),
        None => Ok(None),
    }
}

/// Read at most one bounded underlying page. Callers must reuse the same
/// retained snapshot for continuation, and bound snapshot retention. This
/// returns public encrypted outputs, not ownership or spendability decisions.
/// Transport framing and total scan work need separate limits.
pub fn scan_page(
    snapshot: &dyn SnapshotReadable,
    network: &[u8; 32],
    application: &[u8; 32],
    after: Option<&[u8; 32]>,
    limits: VertexPageLimits,
) -> Result<CoinPage> {
    scan_page_with_root(snapshot, network, application, after, limits,
        snapshot_root(snapshot, network, application)?)
}

/// Internal index scan. Wallet pages continue to advertise the canonical root.
pub(super) fn scan_local_page(
    snapshot: &dyn SnapshotReadable,
    network: &[u8; 32],
    application: &[u8; 32],
    after: Option<&[u8; 32]>,
    limits: VertexPageLimits,
) -> Result<CoinPage> {
    scan_page_with_root(snapshot, network, application, after, limits,
        local_snapshot_root(snapshot, network, application)?)
}

fn scan_page_with_root(
    snapshot: &dyn SnapshotReadable,
    network: &[u8; 32],
    application: &[u8; 32],
    after: Option<&[u8; 32]>,
    limits: VertexPageLimits,
    root: RootRecord,
) -> Result<CoinPage> {
    if limits.max_entries == 0 || limits.max_bytes < 64 {
        return Err(QuilError::InvalidArgument(
            "coin scan: invalid page limits".into(),
        ));
    }
    let context = parameter_context(network, application);
    let shard = shard_key_for_location(&Location { app_address: *application, data_address: [0; 32] });
    let mut key = [0; 64]; key[..32].copy_from_slice(application);
    // The accumulator's own records share this keyspace and are never coins.
    // They are passed over unread: the root history (up to 128 root ids) and
    // the block summary (one root per non-empty block) outgrow a page, and
    // would then fail every wallet's scan.
    let page = snapshot.page_vertex_underlying_fixed_skipping(
        "vertex",
        "adds",
        &shard,
        application,
        after,
        limits,
        &super::state::is_accumulator_record,
    )?;
    let mut cursor = after.copied();
    let mut bytes = 0usize;
    let mut coins = Vec::new();
    if page.entries.len() > limits.max_entries || (page.has_more && page.entries.is_empty()) {
        return Err(QuilError::Store(
            "coin scan: invalid backend page".into(),
        ));
    }
    for (address, blob) in page.entries {
        bytes = bytes
            .checked_add(64)
            .and_then(|n| n.checked_add(blob.len()))
            .ok_or_else(|| QuilError::Store("coin scan: page size overflow".into()))?;
        if bytes > limits.max_bytes || cursor.is_some_and(|previous| address <= previous) {
            return Err(QuilError::Store(
                "coin scan: invalid backend page bounds or order".into(),
            ));
        }
        key[32..].copy_from_slice(&address);
        if let Some(coin) = decode_stored_snapshot_coin(&context, application, &key, &blob)? {
            coins.push((address, coin));
        }
        cursor = Some(address);
    }
    Ok(CoinPage {
        root,
        coins,
        cursor,
        has_more: page.has_more,
    })
}

/// Public encrypted escrows from one retained snapshot; no ownership or
/// consumption assertion is made. Empty pages may still require continuation.
pub struct EscrowPage {
    pub escrows: Vec<([u8; 32], Vec<u8>)>,
    pub cursor: Option<[u8; 32]>,
    pub has_more: bool,
}

pub fn scan_escrow_page(
    snapshot: &dyn SnapshotReadable,
    network: &[u8; 32],
    application: &[u8; 32],
    after: Option<&[u8; 32]>,
    limits: VertexPageLimits,
) -> Result<EscrowPage> {
    if limits.max_entries == 0 || limits.max_bytes < 64 {
        return Err(QuilError::InvalidArgument(
            "coin scan: invalid page limits".into(),
        ));
    }
    let context = parameter_context(network, application);
    let shard = shard_key_for_location(&Location {
        app_address: *application,
        data_address: [0; 32],
    });
    // Passed over unread, as in the coin scan.
    let page = snapshot.page_vertex_underlying_fixed_skipping(
        "vertex",
        "adds",
        &shard,
        application,
        after,
        limits,
        &super::state::is_accumulator_record,
    )?;
    let mut cursor = after.copied();
    let mut bytes = 0usize;
    let mut escrows = Vec::new();
    if page.entries.len() > limits.max_entries || (page.has_more && page.entries.is_empty()) {
        return Err(QuilError::Store(
            "coin scan: invalid backend page".into(),
        ));
    }
    for (address, blob) in page.entries {
        bytes = bytes
            .checked_add(64)
            .and_then(|n| n.checked_add(blob.len()))
            .ok_or_else(|| QuilError::Store("coin scan: page size overflow".into()))?;
        if bytes > limits.max_bytes || cursor.is_some_and(|previous| address <= previous) {
            return Err(QuilError::Store(
                "coin scan: invalid backend page bounds or order".into(),
            ));
        }
        // Every record the accumulator owns is skipped by ONE predicate, not a
        // hand-listed set: per-block frontiers and roots are not Go trees, and
        // a list that forgets one fails the whole scan on the first block
        // record it meets (`go_format: unknown node tag`), which reads as a
        // corrupt store and makes escrows unlistable.
        if !super::state::is_accumulator_record(&address) {
            let tree = quil_tries::VectorCommitmentTree {
                // Name the record. One unparseable vertex fails the whole
                // scan, and "unknown node tag" alone says nothing about WHICH
                // address to go and look at.
                root: quil_tries::deserialize_go_tree(&blob).map_err(|e| {
                    QuilError::Store(format!(
                        "escrow scan: vertex {} ({} bytes, first byte {:#04x}): {e}",
                        hex::encode(address),
                        blob.len(),
                        blob.first().copied().unwrap_or(0),
                    ))
                })?,
            };
            if super::escrow::read_escrow(&tree, &context, &address)?.is_some() {
                // Enforce exactly the same bounded, canonical blob accepted by wallets.
                super::escrow::decode_escrow_blob(&blob, &context, &address)?;
                escrows.push((address, blob));
            }
        }
        cursor = Some(address);
    }
    Ok(EscrowPage {
        escrows,
        cursor,
        has_more: page.has_more,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hypergraph_state::{vertex_adds_discriminator, HypergraphState},
        token_intrinsic::state::{create_coin, SnapshotLimits},
    };
    use quil_lattice_ct::confidential::{transfer::Output, AmountOpening, CommitmentKey};
    use quil_types::crypto::NoopInclusionProver;
    use std::sync::Arc;

    #[test]
    fn escrow_scan_retains_snapshot_and_advances_over_metadata_without_coin_root() {
        use super::super::escrow::StoredEscrow;
        use quil_lattice_ct::confidential::{memo::EscrowRecoveryMemo, pending_claim::EscrowPolicy};
        let dir = tempfile::tempdir().unwrap();
        let db = quil_store::RocksDb::open(dir.path()).unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(store.clone(), Arc::new(NoopInclusionProver))));
        let network = [1; 32]; let application = [2; 32];
        let context = parameter_context(&network, &application);
        let limits = VertexPageLimits { max_entries: 1, max_bytes: 240 * 1024 };
        let empty = store.capture_snapshot().unwrap();
        let page = scan_escrow_page(empty.as_ref(), &network, &application, None, limits).unwrap();
        assert!(page.escrows.is_empty() && !page.has_more);
        let escrow = StoredEscrow { frame_number: 73,
            output: Output { owner: [3; IDENTITY_BYTES], memo: [4; 1115], commitment: CommitmentKey::derive(&context).commit(7, &AmountOpening::from_seed(&context, &[5; 32])) },
            policy: EscrowPolicy { recipient: [6; 897], refund: [7; 897], refund_after_global_frame: 100 },
            refund_recovery: EscrowRecoveryMemo { owner: [8; IDENTITY_BYTES], ciphertext: [9; 1115] } };
        let (address, blob) = escrow.encode(&context).unwrap();
        let disc = vertex_adds_discriminator().unwrap();
        state.set(&application, &address, &disc, 0, blob.clone()).unwrap();
        state.set(&application, &super::super::state::FRONTIER_ADDRESS, &disc, 0, vec![1, 2, 3]).unwrap();
        // The accumulator's PER-BLOCK records are not Go trees either. A scan
        // that skips only the application-wide reserved addresses dies on the
        // first one it meets ("go_format: unknown node tag"), which surfaces
        // as a corrupt store and makes every escrow unlistable.
        let block = super::super::coin_blocks::block_id(super::super::coin_blocks::INITIAL_BLOCK_BITS, 5).unwrap();
        for tag in [super::super::state::BLOCK_FRONTIER_TAG, super::super::state::BLOCK_ROOT_TAG] {
            let address = super::super::state::block_record_address(tag, block);
            state.set(&application, &address, &disc, 0, b"QCT3FR\0\x02 not a tree".to_vec()).unwrap();
        }
        // The root history and block summary outgrow a page (a 249,339-byte
        // root history fails every wallet's scan). They, and the summary
        // tree's records, are passed over unread.
        for address in [super::super::state::ROOT_ADDRESS, super::super::state::BLOCK_SUMMARY_ADDRESS,
            super::super::summary_tree::node_address(0, 64), super::super::summary_tree::node_address(16, 0)] {
            state.set(&application, &address, &disc, 0, vec![7; 300 * 1024]).unwrap();
        }
        state.commit().unwrap(); state.abort(); state.crdt().commit(1).unwrap();
        let snapshot = store.capture_snapshot().unwrap();
        let mut after = None; let mut records = Vec::new(); let mut pages = 0;
        loop {
            let page = scan_escrow_page(snapshot.as_ref(), &network, &application, after.as_ref(), limits).unwrap();
            records.extend(page.escrows); pages += 1;
            if !page.has_more { break; }
            assert!(page.cursor > after); after = page.cursor;
        }
        assert_eq!(records, vec![(address, blob.clone())]);
        assert_eq!(pages, 2, "the escrow's page, then one that passes over the accumulator's records");
        // A later malformed committed record cannot alter an existing scan.
        let shard = shard_key_for_location(&Location { app_address: application, data_address: [0; 32] });
        let mut key = application.to_vec(); key.extend_from_slice(&address);
        db.inner().put(quil_store::encoding::hypergraph_vertex_data_v2_key("vertex", "adds", &shard, &key, u64::MAX), b"invalid").unwrap();
        let all = VertexPageLimits { max_entries: 8, ..limits };
        assert_eq!(scan_escrow_page(snapshot.as_ref(), &network, &application, None, all).unwrap().escrows, records);
        assert!(scan_escrow_page(store.capture_snapshot().unwrap().as_ref(), &network, &application, None, all).is_err());
    }

    /// A split application's whole-application root record is a LOCAL root —
    /// on a real split each shard writes its own, over only the coins it holds,
    /// and an application split before its first commit has none at all (the
    /// inline commit that writes one never runs), which failed every wallet
    /// read with `no root in snapshot`. The scan must answer from the CANONICAL
    /// root the global accumulator folds from the shards' reports, even when a
    /// local record is sitting right there.
    #[test]
    fn a_split_application_scans_against_its_canonical_root() {
        use super::super::{coin_blocks, global_accumulator, roots, shard_accumulator};
        use quil_types::store::HypergraphStore;
        use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
        let dir = tempfile::tempdir().unwrap();
        let db = quil_store::RocksDb::open(dir.path()).unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store.clone(), Arc::new(NoopInclusionProver),
        )));
        let (network, application) = ([1u8; 32], [2u8; 32]);
        let context = parameter_context(&network, &application);
        let limits = SnapshotLimits { max_coins: 8, max_depth: 32, max_nodes: 1 << 12 };
        let disc = vertex_adds_discriminator().unwrap();
        let mut staged = std::collections::BTreeMap::new();
        let mut blocks = Vec::new();
        let mut addresses = Vec::new();
        for seed in 0..3u8 {
            let output = Output {
                owner: [seed | 1; IDENTITY_BYTES],
                commitment: CommitmentKey::derive(&context)
                    .commit(7, &AmountOpening::from_seed(&context, &[seed; 32])),
                memo: [0; 1115],
            };
            let (address, tree) =
                roots::stage_coin(&state, &network, &application, &context, 0, &output, &mut staged, limits).unwrap();
            state.set(&application, &address, &disc, 0,
                quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap()).unwrap();
            blocks.push(coin_blocks::block_for_address(coin_blocks::INITIAL_BLOCK_BITS, &address).unwrap());
            addresses.push(address);
        }
        // The LOCAL record covers every staged coin.
        let local_root = roots::refresh_root(&state, &network, &application, limits).unwrap();
        assert_eq!(local_root.coins, 3);
        // One shard reports its subtree; the canonical root folds from that
        // report alone, so it counts fewer coins than the local record.
        let shard: Vec<bool> = (0..8u8)
            .map(|p| (0..3).map(|i| p >> (2 - i) & 1 == 1).collect::<Vec<bool>>())
            .find(|candidate| coin_blocks::shard_owns_block(candidate, blocks[0]))
            .expect("some depth-3 shard owns the first coin's block");
        let report = shard_accumulator::shard_report(&state, &network, &application, &shard, false)
            .unwrap().expect("the shard holds a coin");
        let filter = quil_forest::encode_shard_bit_path(&application, &shard);
        assert!(global_accumulator::materialize_report(&state, 10, &filter, &report.encode().unwrap()).unwrap());
        let canonical = global_accumulator::read_root_history(&state, &application).unwrap()
            .map(|history| roots::decode_current(&history, &context).unwrap())
            .expect("the accumulator published a canonical root");
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(1).unwrap();

        // The coin-scan RPC serves from `capture_tree_snapshot`, so the
        // canonical record must be visible through THAT, not merely through a
        // plain store snapshot.
        let snapshot = store.capture_tree_snapshot().unwrap().expect("tree snapshot");
        let root = snapshot_root(snapshot.as_ref(), &network, &application).unwrap();
        // Compare compactly: a RootRecord's Debug is a full lattice polynomial.
        let digest = |r: &RootRecord| (r.coins, r.depth, r.context,
            quil_crypto::poseidon::hash_bytes_to_32(&r.root.to_bytes()).unwrap());
        assert_eq!(digest(&root), digest(&canonical), "the scan answers from the canonical root");
        assert_ne!(root.coins, local_root.coins, "not the whole-application local record");

        // The index must build the three LOCAL coins even while only one
        // shard has reported. Using the wallet's canonical root here used to
        // fail forever with "incomplete coin coverage" whenever reports lagged.
        use super::super::witness_index::{LocalWitnessIndex, WitnessBootstrap};
        let db = Arc::new(db);
        let mut builder = WitnessBootstrap::new(db.clone(), snapshot, &network, &application).unwrap();
        assert_eq!(digest(builder.root()), digest(&local_root));
        let mut finished = false;
        for _ in 0..128 {
            if builder.step().unwrap() { finished = true; break; }
        }
        assert!(finished, "bounded local bootstrap finishes with lagging reports");
        let ready = LocalWitnessIndex::ready_root(db.as_ref(), &context).unwrap().unwrap();
        assert_eq!(digest(&ready), digest(&local_root));
        let index = LocalWitnessIndex::for_root(db, &local_root, 32).unwrap();
        let witnesses = super::super::witnesses::canonical_witnesses(
            &state, &state, &network, &application, &addresses[..1], &[local_root.clone()], &index,
        ).unwrap();
        assert_eq!(digest(&witnesses.root), digest(&canonical));
        assert!(witnesses.coins[0].path.is_some());
        let unreported = blocks.iter().position(|block| !coin_blocks::shard_owns_block(&shard, *block)).unwrap();
        assert!(super::super::witnesses::canonical_witnesses(
            &state, &state, &network, &application, &[addresses[unreported]], &[local_root], &index,
        ).is_err(), "local indexing cannot authorize an unreported coin");
    }

    #[test]
    fn scan_pages_keep_snapshot_coins_and_advance_past_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let db = quil_store::RocksDb::open(dir.path()).unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store.clone(),
            Arc::new(NoopInclusionProver),
        )));
        let network = [1; 32];
        let application = [2; 32];
        let context = parameter_context(&network, &application);
        let limits = VertexPageLimits {
            max_entries: 1,
            max_bytes: 256 * 1024,
        };
        let empty_snapshot = store.capture_snapshot().unwrap();
        assert!(matches!(
            scan_page(
                empty_snapshot.as_ref(),
                &network,
                &application,
                None,
                limits
            ),
            Err(QuilError::NotFound(_))
        ));
        let disc = vertex_adds_discriminator().unwrap();
        let snapshot_limits = SnapshotLimits {
            max_coins: 2,
            max_depth: 32,
            max_nodes: 1 << 16,
        };
        // Coins are placed the way staging places them — into the block their
        // address selects, at that block's next free index — so the scan is
        // exercised against positions the accumulator actually accepts.
        let mut staged = std::collections::BTreeMap::new();
        let width = roots::block_width(&state, &application).unwrap();
        let mut expected = Vec::new();
        for i in 0..2 {
            let output = Output {
                owner: [i + 3; IDENTITY_BYTES],
                commitment: CommitmentKey::derive(&context).commit(
                    10 + u128::from(i),
                    &AmountOpening::from_seed(&context, &[i + 7; 32]),
                ),
                memo: [i; 1115],
            };
            let (address, tree) = roots::stage_coin(
                &state,
                &network,
                &application,
                &context,
                7,
                &output,
                &mut staged,
                snapshot_limits,
            )
            .unwrap();
            let block =
                crate::token_intrinsic::coin_blocks::block_for_address(width, &address).unwrap();
            let position = crate::token_intrinsic::coin_blocks::position(
                width,
                block,
                staged[&block] - 1,
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
            expected.push((
                address,
                StoredCoin {
                    frame_number: 7,
                    position,
                    output,
                },
            ));
        }
        let receipt = crate::token_intrinsic::legacy_migration::MIGRATION_RECEIPT_ADDRESS;
        state
            .set(&application, &receipt, &disc, 0, vec![1, 2, 3])
            .unwrap();
        expected.sort_by_key(|entry| entry.0);
        let root = roots::refresh_root(&state, &network, &application, snapshot_limits).unwrap();
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(1).unwrap();
        let snapshot = store.capture_snapshot().unwrap();
        // One vertex per page. Accumulator records live inside the prefix of
        // the block they describe, so they interleave with coins by address;
        // the scan passes over them unread and returns exactly the coins, in
        // order. Only the last page, past the records after the last coin,
        // holds none.
        let scan_all = |snapshot: &dyn SnapshotReadable, from: Option<[u8; 32]>| {
            let mut cursor = from;
            let mut coins = Vec::new();
            let mut cursors = Vec::new();
            let mut pages = 0;
            loop {
                let page = scan_page(snapshot, &network, &application, cursor.as_ref(), limits)?;
                assert_eq!(page.root, root);
                if page.coins.is_empty() {
                    assert!(!page.has_more, "a page without a coin is the last");
                }
                coins.extend(page.coins);
                cursors.push(page.cursor);
                cursor = page.cursor;
                pages += 1;
                assert!(pages < 64, "the accumulator's records are bounded");
                if !page.has_more {
                    return Ok::<_, QuilError>((coins, cursors));
                }
            }
        };
        let (coins, cursors) = scan_all(snapshot.as_ref(), None).unwrap();
        assert_eq!(coins, expected);
        assert_eq!(*cursors.last().unwrap(), Some(expected.last().unwrap().0),
            "the scan ends at the last coin; the records past it, up to the migration receipt, are not rows");
        let _ = receipt;

        // Corrupt the later coin's current stored record after the scan has
        // passed the earlier one. The retained reader must still see the
        // original; a fresh reader must reject the malformed coin rather than
        // silently omit it.
        let after_first = cursors[cursors
            .iter()
            .position(|cursor| *cursor == Some(expected[0].0))
            .expect("the scan passed the first coin")];
        let shard = shard_key_for_location(&Location {
            app_address: application,
            data_address: [0; 32],
        });
        let mut key = application.to_vec();
        key.extend_from_slice(&expected[1].0);
        db.inner()
            .put(
                quil_store::encoding::hypergraph_vertex_data_v2_key(
                    "vertex",
                    "adds",
                    &shard,
                    &key,
                    u64::MAX,
                ),
                b"invalid",
            )
            .unwrap();
        let (rest, _) = scan_all(snapshot.as_ref(), after_first).unwrap();
        assert_eq!(rest, expected[1..]);
        let fresh = store.capture_snapshot().unwrap();
        assert!(scan_all(fresh.as_ref(), after_first).is_err());
        assert!(scan_page(snapshot.as_ref(), &[9; 32], &application, None, limits).is_err());
        assert!(scan_page(
            snapshot.as_ref(),
            &network,
            &application,
            None,
            VertexPageLimits {
                max_entries: 0,
                ..limits
            }
        )
        .is_err());
        assert!(scan_page(
            snapshot.as_ref(),
            &network,
            &application,
            None,
            VertexPageLimits {
                max_bytes: 64,
                ..limits
            }
        )
        .is_err());
    }
}

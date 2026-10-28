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
    store::{
        IndexedVertexPage, LargeVertexIndexState, ShardKey, SnapshotReadable, VertexPageLimits,
    },
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
pub fn snapshot_root(
    snapshot: &dyn SnapshotReadable,
    network: &[u8; 32],
    application: &[u8; 32],
) -> Result<RootRecord> {
    snapshot_root_if_any(snapshot, network, application)?.ok_or_else(no_root)
}

/// [`snapshot_root`], or `None` when the application has neither root.
fn snapshot_root_if_any(
    snapshot: &dyn SnapshotReadable,
    network: &[u8; 32],
    application: &[u8; 32],
) -> Result<Option<RootRecord>> {
    let context = parameter_context(network, application);
    if let Some(canonical) = canonical_snapshot_root(snapshot, &context, application)? {
        return Ok(Some(canonical));
    }
    local_snapshot_root_if_any(snapshot, network, application)
}

fn no_root() -> QuilError {
    QuilError::NotFound("coin scan: no root in snapshot".into())
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
    local_snapshot_root_if_any(snapshot, network, application)?.ok_or_else(no_root)
}

fn local_snapshot_root_if_any(
    snapshot: &dyn SnapshotReadable,
    network: &[u8; 32],
    application: &[u8; 32],
) -> Result<Option<RootRecord>> {
    let context = parameter_context(network, application);
    let shard = shard_key_for_location(&Location {
        app_address: *application,
        data_address: [0; 32],
    });
    let mut key = [0; 64];
    key[..32].copy_from_slice(application);
    key[32..].copy_from_slice(&ROOT_ADDRESS);
    // The node-local record, else a legacy copy in the tree.
    let root_bytes =
        match snapshot.read_record(&super::state::local_record_key(application, &ROOT_ADDRESS)) {
            Ok(Some(bytes)) => Some(bytes),
            _ => snapshot.load_vertex_underlying_raw("vertex", "adds", &shard, &key)?,
        };
    root_bytes
        .map(|bytes| roots::decode_current(&bytes, &context))
        .transpose()
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
    let shard = shard_key_for_location(&Location {
        app_address: domain,
        data_address: address,
    });
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
        root: quil_tries::deserialize_go_tree(&blob).map_err(|_| {
            QuilError::ExecutionUnavailable("cannot decode the canonical root record".into())
        })?,
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
    scan_page_with_root(
        snapshot,
        network,
        application,
        after,
        limits,
        snapshot_root(snapshot, network, application)?,
    )
}

/// What a wallet scan finds in one store.
pub enum WalletPage {
    /// A page listed against the application's root.
    Page(CoinPage),
    /// No root and no coin: no confidential coin exists in the application.
    NoRoot,
    /// No root, yet the store holds a coin: its root has not arrived.
    UnrootedCoins,
}

/// The error a scan answers for [`WalletPage::UnrootedCoins`].
pub fn unrooted_coins_error() -> QuilError {
    QuilError::ExecutionUnavailable(
        "coin scan: coins but no root in snapshot yet; retry once the root is published".into(),
    )
}

/// A wallet scan's page. An application with no coin root at all, neither
/// the canonical root GLOBAL folds from shard reports (a shard holding no
/// confidential coin reports nothing) nor a local record (written with the
/// first coin a node commits), is one in which no confidential coin exists
/// yet, such as QUIL before its first shield or mint. Its scan is complete
/// and empty, [`WalletPage::NoRoot`], rather than failed.
///
/// Only a fresh scan gets that answer. A continuation without a root is an
/// error, and a first page that already holds a coin is
/// [`WalletPage::UnrootedCoins`]: a store whose root has not arrived, not an
/// empty application.
pub fn scan_wallet_page(
    snapshot: &dyn SnapshotReadable,
    network: &[u8; 32],
    application: &[u8; 32],
    after: Option<&[u8; 32]>,
    limits: VertexPageLimits,
) -> Result<WalletPage> {
    if let Some(root) = snapshot_root_if_any(snapshot, network, application)? {
        return scan_page_with_root(snapshot, network, application, after, limits, root)
            .map(WalletPage::Page);
    }
    if after.is_some() {
        return Err(no_root());
    }
    let (coins, _, _) = scan_coins(snapshot, network, application, None, limits)?;
    Ok(if coins.is_empty() {
        WalletPage::NoRoot
    } else {
        WalletPage::UnrootedCoins
    })
}

/// Internal index scan. Wallet pages continue to advertise the canonical root.
pub(super) fn scan_local_page(
    snapshot: &dyn SnapshotReadable,
    network: &[u8; 32],
    application: &[u8; 32],
    after: Option<&[u8; 32]>,
    limits: VertexPageLimits,
) -> Result<CoinPage> {
    scan_page_with_root(
        snapshot,
        network,
        application,
        after,
        limits,
        local_snapshot_root(snapshot, network, application)?,
    )
}

fn scan_page_with_root(
    snapshot: &dyn SnapshotReadable,
    network: &[u8; 32],
    application: &[u8; 32],
    after: Option<&[u8; 32]>,
    limits: VertexPageLimits,
    root: RootRecord,
) -> Result<CoinPage> {
    let (coins, cursor, has_more) = scan_coins(snapshot, network, application, after, limits)?;
    Ok(CoinPage {
        root,
        coins,
        cursor,
        has_more,
    })
}

/// One bounded page of coin records: the coins, the last examined address
/// and whether the scan continues.
fn scan_coins(
    snapshot: &dyn SnapshotReadable,
    network: &[u8; 32],
    application: &[u8; 32],
    after: Option<&[u8; 32]>,
    limits: VertexPageLimits,
) -> Result<(Vec<([u8; 32], StoredCoin)>, Option<[u8; 32]>, bool)> {
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
    let mut key = [0; 64];
    key[..32].copy_from_slice(application);
    let started = std::time::Instant::now();
    let page = page_records(snapshot, &shard, application, after, limits)?;
    let mut cursor = after.copied();
    let mut bytes = 0usize;
    let mut coins = Vec::new();
    check_backend_page(&page, after, limits)?;
    let examined = page.examined;
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
    let cursor = page.cursor.max(cursor);
    report_slow_page(
        snapshot,
        application,
        examined,
        coins.len(),
        started.elapsed(),
    );
    Ok((coins, cursor, page.has_more))
}

/// One backend page of the application's records. Through the store's index
/// of its large rows when it keeps one, so the transparent coins that share
/// the keyspace (about 122 million in QUIL) are never read: each page then
/// costs its own records, not the walk to them. The accumulator's own records
/// are passed over unread: the root history (up to 128 root ids) and the block
/// summary (one root per non-empty block) outgrow a page, and would then fail
/// every wallet's scan.
fn page_records(
    snapshot: &dyn SnapshotReadable,
    shard: &ShardKey,
    application: &[u8; 32],
    after: Option<&[u8; 32]>,
    limits: VertexPageLimits,
) -> Result<IndexedVertexPage> {
    let skip = &super::state::is_accumulator_record;
    match snapshot.large_vertex_index_state()? {
        LargeVertexIndexState::Complete => snapshot.page_large_vertices_skipping(
            "vertex",
            "adds",
            shard,
            application,
            after,
            limits,
            skip,
        ),
        LargeVertexIndexState::Building { rows_walked } => Err(index_building_error(rows_walked)),
        LargeVertexIndexState::Unsupported => {
            let page = snapshot.page_vertex_underlying_fixed_skipping(
                "vertex",
                "adds",
                shard,
                application,
                after,
                limits,
                skip,
            )?;
            Ok(IndexedVertexPage {
                // Rows passed over move no cursor here: a page of none
                // continues from where the last one ended.
                cursor: page
                    .entries
                    .last()
                    .map(|(address, _)| *address)
                    .or(after.copied()),
                examined: page.entries.len(),
                entries: page.entries,
                has_more: page.has_more,
            })
        }
    }
}

/// The answer to a scan while the store still walks the rows it held before
/// it indexed its large ones.
fn index_building_error(rows_walked: u64) -> QuilError {
    QuilError::ExecutionUnavailable(format!(
        "coin scan: this node is still indexing its stored records once after an upgrade \
         ({rows_walked} walked so far); coins and escrows can be listed when it finishes, \
         retry in a few minutes"
    ))
}

fn check_backend_page(
    page: &IndexedVertexPage,
    after: Option<&[u8; 32]>,
    limits: VertexPageLimits,
) -> Result<()> {
    let last = page.entries.last().map(|(address, _)| *address);
    if page.entries.len() > limits.max_entries
        || page.cursor < last
        || page.cursor < after.copied()
        || (page.has_more && page.cursor <= after.copied())
    {
        return Err(QuilError::Store("coin scan: invalid backend page".into()));
    }
    Ok(())
}

/// A page slower than this is reported (at most once a minute).
const SLOW_PAGE: std::time::Duration = std::time::Duration::from_secs(1);

/// One line, at most once a minute, for scan pages that run long: a store
/// whose index cannot answer them, or a disk that cannot keep up.
fn report_slow_page(
    snapshot: &dyn SnapshotReadable,
    application: &[u8; 32],
    examined: usize,
    coins: usize,
    elapsed: std::time::Duration,
) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SLOW: AtomicU64 = AtomicU64::new(0);
    static LAST: AtomicU64 = AtomicU64::new(0);
    if elapsed < SLOW_PAGE {
        return;
    }
    let slow = SLOW.fetch_add(1, Ordering::Relaxed) + 1;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let last = LAST.load(Ordering::Relaxed);
    if now < last.saturating_add(60)
        || LAST
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
    SLOW.store(0, Ordering::Relaxed);
    tracing::warn!(
        store = snapshot.store_name().as_deref().unwrap_or("unnamed"),
        application = %hex::encode(application),
        records_examined = examined,
        coins_returned = coins,
        elapsed_ms = elapsed.as_millis() as u64,
        slow_pages_since_last_report = slow,
        "coin scan page slow: this node's store answered a wallet page in over a second; wallets may run out of time or pages"
    );
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
    let page = page_records(snapshot, &shard, application, after, limits)?;
    let mut cursor = after.copied();
    let mut bytes = 0usize;
    let mut escrows = Vec::new();
    check_backend_page(&page, after, limits)?;
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
        cursor: page.cursor.max(cursor),
        has_more: page.has_more,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hypergraph_state::{vertex_adds_discriminator, HypergraphState},
        token_intrinsic::state::SnapshotLimits,
    };
    use quil_lattice_ct::confidential::{transfer::Output, AmountOpening, CommitmentKey};
    use quil_types::crypto::NoopInclusionProver;
    use std::sync::Arc;

    #[test]
    fn escrow_scan_retains_snapshot_and_advances_over_metadata_without_coin_root() {
        use super::super::escrow::StoredEscrow;
        use quil_lattice_ct::confidential::{
            memo::EscrowRecoveryMemo, pending_claim::EscrowPolicy,
        };
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
            max_bytes: 240 * 1024,
        };
        let empty = store.capture_snapshot().unwrap();
        let page = scan_escrow_page(empty.as_ref(), &network, &application, None, limits).unwrap();
        assert!(page.escrows.is_empty() && !page.has_more);
        let escrow = StoredEscrow {
            frame_number: 73,
            output: Output {
                owner: [3; IDENTITY_BYTES],
                memo: [4; 1115],
                commitment: CommitmentKey::derive(&context)
                    .commit(7, &AmountOpening::from_seed(&context, &[5; 32])),
            },
            policy: EscrowPolicy {
                recipient: [6; 897],
                refund: [7; 897],
                refund_after_global_frame: 100,
            },
            refund_recovery: EscrowRecoveryMemo {
                owner: [8; IDENTITY_BYTES],
                ciphertext: [9; 1115],
            },
        };
        let (address, blob) = escrow.encode(&context).unwrap();
        let disc = vertex_adds_discriminator().unwrap();
        state
            .set(&application, &address, &disc, 0, blob.clone())
            .unwrap();
        state
            .set(
                &application,
                &super::super::state::FRONTIER_ADDRESS,
                &disc,
                0,
                vec![1, 2, 3],
            )
            .unwrap();
        // The accumulator's PER-BLOCK records are not Go trees either. A scan
        // that skips only the application-wide reserved addresses dies on the
        // first one it meets ("go_format: unknown node tag"), which surfaces
        // as a corrupt store and makes every escrow unlistable.
        let block =
            super::super::coin_blocks::block_id(super::super::coin_blocks::INITIAL_BLOCK_BITS, 5)
                .unwrap();
        for tag in [
            super::super::state::BLOCK_FRONTIER_TAG,
            super::super::state::BLOCK_ROOT_TAG,
        ] {
            let address = super::super::state::block_record_address(tag, block);
            state
                .set(
                    &application,
                    &address,
                    &disc,
                    0,
                    b"QCT3FR\0\x02 not a tree".to_vec(),
                )
                .unwrap();
        }
        // The root history and block summary outgrow a page (a 249,339-byte
        // root history fails every wallet's scan). They, and the summary
        // tree's records, are passed over unread.
        for address in [
            super::super::state::ROOT_ADDRESS,
            super::super::state::BLOCK_SUMMARY_ADDRESS,
            super::super::summary_tree::node_address(0, 64),
            super::super::summary_tree::node_address(16, 0),
        ] {
            state
                .set(&application, &address, &disc, 0, vec![7; 300 * 1024])
                .unwrap();
        }
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(1).unwrap();
        let snapshot = store.capture_snapshot().unwrap();
        let mut after = None;
        let mut records = Vec::new();
        let mut pages = 0;
        loop {
            let page = scan_escrow_page(
                snapshot.as_ref(),
                &network,
                &application,
                after.as_ref(),
                limits,
            )
            .unwrap();
            records.extend(page.escrows);
            pages += 1;
            if !page.has_more {
                break;
            }
            assert!(page.cursor > after);
            after = page.cursor;
        }
        assert_eq!(records, vec![(address, blob.clone())]);
        assert_eq!(
            pages, 2,
            "the escrow's page, then one that passes over the accumulator's records"
        );
        // A later malformed committed record cannot alter an existing scan.
        let shard = shard_key_for_location(&Location {
            app_address: application,
            data_address: [0; 32],
        });
        let mut key = application.to_vec();
        key.extend_from_slice(&address);
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
        let all = VertexPageLimits {
            max_entries: 8,
            ..limits
        };
        assert_eq!(
            scan_escrow_page(snapshot.as_ref(), &network, &application, None, all)
                .unwrap()
                .escrows,
            records
        );
        assert!(scan_escrow_page(
            store.capture_snapshot().unwrap().as_ref(),
            &network,
            &application,
            None,
            all
        )
        .is_err());
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
        use quil_lattice_ct::confidential::relation::membership::IDENTITY_BYTES;
        use quil_types::store::HypergraphStore;
        let dir = tempfile::tempdir().unwrap();
        let db = quil_store::RocksDb::open(dir.path()).unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store.clone(),
            Arc::new(NoopInclusionProver),
        )));
        let (network, application) = ([1u8; 32], [2u8; 32]);
        let context = parameter_context(&network, &application);
        let limits = SnapshotLimits {
            max_coins: 8,
            max_depth: 32,
            max_nodes: 1 << 12,
        };
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
            let (address, tree) = roots::stage_coin(
                &state,
                &network,
                &application,
                &context,
                0,
                &output,
                &mut staged,
                limits,
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
            blocks.push(
                coin_blocks::block_for_address(coin_blocks::INITIAL_BLOCK_BITS, &address).unwrap(),
            );
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
            .unwrap()
            .expect("the shard holds a coin");
        let filter = quil_forest::encode_shard_bit_path(&application, &shard);
        assert!(global_accumulator::materialize_report(
            &state,
            10,
            &filter,
            &report.encode().unwrap()
        )
        .unwrap());
        let canonical = global_accumulator::read_root_history(&state, &application)
            .unwrap()
            .map(|history| roots::decode_current(&history, &context).unwrap())
            .expect("the accumulator published a canonical root");
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(1).unwrap();

        // The coin-scan RPC serves from `capture_tree_snapshot`, so the
        // canonical record must be visible through THAT, not merely through a
        // plain store snapshot.
        let snapshot = store
            .capture_tree_snapshot()
            .unwrap()
            .expect("tree snapshot");
        let root = snapshot_root(snapshot.as_ref(), &network, &application).unwrap();
        // Compare compactly: a RootRecord's Debug is a full lattice polynomial.
        let digest = |r: &RootRecord| {
            (
                r.coins,
                r.depth,
                r.context,
                quil_crypto::poseidon::hash_bytes_to_32(&r.root.to_bytes()).unwrap(),
            )
        };
        assert_eq!(
            digest(&root),
            digest(&canonical),
            "the scan answers from the canonical root"
        );
        assert_ne!(
            root.coins, local_root.coins,
            "not the whole-application local record"
        );

        // The index must build the three LOCAL coins even while only one
        // shard has reported. Using the wallet's canonical root here used to
        // fail forever with "incomplete coin coverage" whenever reports lagged.
        use super::super::witness_index::{LocalWitnessIndex, WitnessBootstrap};
        let db = Arc::new(db);
        let mut builder =
            WitnessBootstrap::new(db.clone(), snapshot, &network, &application).unwrap();
        assert_eq!(digest(builder.root()), digest(&local_root));
        let mut finished = false;
        for _ in 0..128 {
            if builder.step().unwrap() {
                finished = true;
                break;
            }
        }
        assert!(
            finished,
            "bounded local bootstrap finishes with lagging reports"
        );
        let ready = LocalWitnessIndex::ready_root(db.as_ref(), &context)
            .unwrap()
            .unwrap();
        assert_eq!(digest(&ready), digest(&local_root));
        let index = LocalWitnessIndex::for_root(db, &local_root, 32).unwrap();
        let witnesses = super::super::witnesses::canonical_witnesses(
            &state,
            &state,
            &network,
            &application,
            &addresses[..1],
            &[local_root.clone()],
            &index,
        )
        .unwrap();
        assert_eq!(digest(&witnesses.root), digest(&canonical));
        assert!(witnesses.coins[0].path.is_some());
        let unreported = blocks
            .iter()
            .position(|block| !coin_blocks::shard_owns_block(&shard, *block))
            .unwrap();
        assert!(
            super::super::witnesses::canonical_witnesses(
                &state,
                &state,
                &network,
                &application,
                &[addresses[unreported]],
                &[local_root],
                &index,
            )
            .is_err(),
            "local indexing cannot authorize an unreported coin"
        );
    }

    /// An application in which no confidential coin exists has no root at
    /// all, canonical or local: QUIL on every archive until its first shield
    /// or mint (#698). A wallet's scan of it is complete and empty instead of
    /// failing. A store holding a coin whose root has not arrived, and a
    /// continuation without a root, are not that answer; spends still need
    /// a root.
    #[test]
    fn a_wallet_scan_of_an_application_without_coins_is_empty_not_failed() {
        let (network, application) = ([1u8; 32], [2u8; 32]);
        let context = parameter_context(&network, &application);
        let limits = VertexPageLimits {
            max_entries: 8,
            max_bytes: 240 * 1024,
        };
        let snapshot_limits = SnapshotLimits {
            max_coins: 8,
            max_depth: 32,
            max_nodes: 1 << 12,
        };
        let output = Output {
            owner: [3; IDENTITY_BYTES],
            commitment: CommitmentKey::derive(&context)
                .commit(5, &AmountOpening::from_seed(&context, &[4; 32])),
            memo: [0; 1115],
        };
        // A store with the coin, its root published or not.
        let store_with_coin = |publish: bool| {
            let dir = tempfile::tempdir().unwrap();
            let db = quil_store::RocksDb::open(dir.path()).unwrap();
            let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
            let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
                store.clone(),
                Arc::new(NoopInclusionProver),
            )));
            let mut staged = std::collections::BTreeMap::new();
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
            state
                .set(
                    &application,
                    &address,
                    &vertex_adds_discriminator().unwrap(),
                    0,
                    quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
                )
                .unwrap();
            let root = publish.then(|| {
                roots::refresh_root(&state, &network, &application, snapshot_limits).unwrap()
            });
            state.commit().unwrap();
            state.abort();
            state.crdt().commit(1).unwrap();
            (dir, db, store, address, root)
        };

        let dir = tempfile::tempdir().unwrap();
        let db = quil_store::RocksDb::open(dir.path()).unwrap();
        let empty_store = quil_store::RocksHypergraphStore::new(db.inner());
        let empty = empty_store.capture_snapshot().unwrap();
        assert!(matches!(
            scan_wallet_page(empty.as_ref(), &network, &application, None, limits),
            Ok(WalletPage::NoRoot)
        ));
        assert!(matches!(
            snapshot_root(empty.as_ref(), &network, &application),
            Err(QuilError::NotFound(_))
        ));
        assert!(matches!(
            scan_wallet_page(
                empty.as_ref(),
                &network,
                &application,
                Some(&[1; 32]),
                limits
            ),
            Err(QuilError::NotFound(_))
        ));

        let (_dir, _db, store, _, _) = store_with_coin(false);
        let unrooted = store.capture_snapshot().unwrap();
        assert!(
            matches!(
                scan_wallet_page(unrooted.as_ref(), &network, &application, None, limits),
                Ok(WalletPage::UnrootedCoins)
            ),
            "a coin without a root is not an empty application"
        );

        let (_dir, _db, store, address, root) = store_with_coin(true);
        let rooted = store.capture_snapshot().unwrap();
        let Ok(WalletPage::Page(page)) =
            scan_wallet_page(rooted.as_ref(), &network, &application, None, limits)
        else {
            panic!("the coin's root is published");
        };
        assert_eq!(page.root, root.unwrap());
        assert_eq!(
            page.coins
                .iter()
                .map(|(address, _)| *address)
                .collect::<Vec<_>>(),
            vec![address]
        );
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
            let position =
                crate::token_intrinsic::coin_blocks::position(width, block, staged[&block] - 1)
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

    /// A wallet scan of an application whose keyspace is mostly migrated
    /// transparent coins (QUIL holds about 122 million) must still list its
    /// confidential coins within the client's default budget: 128 pages of
    /// 8 records (`qclient token coins --max-pages`). Paging every record of
    /// the keyspace ran out of pages long before the coins (mainnet,
    /// 2026-10-28: `scan ended or page budget exhausted`).
    #[test]
    fn a_wallet_scan_finds_coins_behind_thousands_of_transparent_coins_within_the_client_budget() {
        use crate::token_intrinsic::legacy_migration::{
            create_transparent_coin_tree, transparent_type_hash, TransparentCoin,
        };
        const TRANSPARENT: usize = 5_000;
        const CLIENT_PAGES: usize = 128;
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
        let disc = vertex_adds_discriminator().unwrap();
        let snapshot_limits = SnapshotLimits {
            max_coins: 2,
            max_depth: 32,
            max_nodes: 1 << 16,
        };
        // The two of 64 confidential coins with the highest addresses, so
        // most transparent coins sort before them.
        let output = |seed: u8| Output {
            owner: [seed; IDENTITY_BYTES],
            commitment: CommitmentKey::derive(&context)
                .commit(5, &AmountOpening::from_seed(&context, &[seed; 32])),
            memo: [seed; 1115],
        };
        let mut seeds: Vec<(u8, [u8; 32])> = (1..=64u8)
            .map(|seed| {
                let (address, _) =
                    crate::token_intrinsic::state::coin_identity(&context, 7, &output(seed))
                        .unwrap();
                (seed, address)
            })
            .collect();
        seeds.sort_by_key(|(_, address)| *address);
        let mut staged = std::collections::BTreeMap::new();
        let mut confidential = Vec::new();
        for (seed, _) in &seeds[seeds.len() - 2..] {
            let (address, tree) = roots::stage_coin(
                &state,
                &network,
                &application,
                &context,
                7,
                &output(*seed),
                &mut staged,
                snapshot_limits,
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
            confidential.push(address);
        }
        confidential.sort();
        roots::refresh_root(&state, &network, &application, snapshot_limits).unwrap();
        // Transparent coins as the migration wrote them, all before the coins.
        let type_hash = transparent_type_hash(&application).unwrap();
        let mut transparent = 0;
        let mut origin = 0u32;
        while transparent < TRANSPARENT {
            origin += 1;
            let mut origin_bytes = [0u8; 32];
            origin_bytes[..4].copy_from_slice(&origin.to_le_bytes());
            let tree = create_transparent_coin_tree(
                &TransparentCoin {
                    owner_address: [0x11; 32],
                    amount: 1_000,
                },
                &type_hash,
                &origin_bytes,
            )
            .unwrap();
            let address = crate::token_intrinsic::materialize::coin_content_address(&tree).unwrap();
            if address >= confidential[0] {
                continue;
            }
            state
                .set(
                    &application,
                    &address,
                    &disc,
                    0,
                    quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
                )
                .unwrap();
            transparent += 1;
        }
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(1).unwrap();
        let snapshot = store.capture_snapshot().unwrap();
        // Driven as the client drives the node: pages of at most 8 records
        // and 240 KiB, continued from each page's cursor, 128 pages at most.
        let limits = VertexPageLimits {
            max_entries: 8,
            max_bytes: 240 * 1024,
        };
        let mut after = None;
        let mut found = Vec::new();
        let mut pages = 0;
        loop {
            assert!(
                pages < CLIENT_PAGES,
                "scan ended or page budget exhausted: {pages} pages listed {} of 2 coins behind {TRANSPARENT} transparent coins",
                found.len()
            );
            let page = match scan_wallet_page(
                snapshot.as_ref(),
                &network,
                &application,
                after.as_ref(),
                limits,
            )
            .unwrap()
            {
                WalletPage::Page(page) => page,
                _ => panic!("the application has a root and coins"),
            };
            pages += 1;
            found.extend(page.coins.into_iter().map(|(address, _)| address));
            if !page.has_more {
                break;
            }
            assert!(page.cursor > after, "each page moves the scan on");
            after = page.cursor;
        }
        assert_eq!(found, confidential);
    }

    /// A store with `transparent` migrated transparent coins and two
    /// confidential coins under a root, committed: its directory, database
    /// and the coins' addresses in order.
    fn wallet_store(
        transparent: u32,
    ) -> (
        tempfile::TempDir,
        quil_store::RocksDb,
        Arc<quil_store::RocksHypergraphStore>,
        Vec<[u8; 32]>,
    ) {
        use crate::token_intrinsic::legacy_migration::{
            create_transparent_coin_tree, transparent_type_hash, TransparentCoin,
        };
        let dir = tempfile::tempdir().unwrap();
        let db = quil_store::RocksDb::open(dir.path()).unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store.clone(),
            Arc::new(NoopInclusionProver),
        )));
        let (network, application) = ([1; 32], [2; 32]);
        let context = parameter_context(&network, &application);
        let disc = vertex_adds_discriminator().unwrap();
        let limits = SnapshotLimits {
            max_coins: 2,
            max_depth: 32,
            max_nodes: 1 << 16,
        };
        let mut staged = std::collections::BTreeMap::new();
        let mut coins = Vec::new();
        for seed in 1..=2u8 {
            let output = Output {
                owner: [seed; IDENTITY_BYTES],
                commitment: CommitmentKey::derive(&context)
                    .commit(5, &AmountOpening::from_seed(&context, &[seed; 32])),
                memo: [seed; 1115],
            };
            let (address, tree) = roots::stage_coin(
                &state,
                &network,
                &application,
                &context,
                7,
                &output,
                &mut staged,
                limits,
            )
            .unwrap();
            let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
            assert!(blob.len() >= quil_store::large_vertex_index::LARGE_VERTEX_MIN_BYTES);
            state.set(&application, &address, &disc, 0, blob).unwrap();
            coins.push(address);
        }
        coins.sort();
        roots::refresh_root(&state, &network, &application, limits).unwrap();
        let type_hash = transparent_type_hash(&application).unwrap();
        for origin in 0..transparent {
            let mut origin_bytes = [0u8; 32];
            origin_bytes[..4].copy_from_slice(&origin.to_le_bytes());
            let tree = create_transparent_coin_tree(
                &TransparentCoin {
                    owner_address: [0x11; 32],
                    amount: 1_000,
                },
                &type_hash,
                &origin_bytes,
            )
            .unwrap();
            let address = crate::token_intrinsic::materialize::coin_content_address(&tree).unwrap();
            let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
            assert!(blob.len() < quil_store::large_vertex_index::LARGE_VERTEX_MIN_BYTES);
            state.set(&application, &address, &disc, 0, blob).unwrap();
        }
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(1).unwrap();
        (dir, db, store, coins)
    }

    fn scan_wallet(snapshot: &dyn SnapshotReadable) -> Result<Vec<[u8; 32]>> {
        let limits = VertexPageLimits {
            max_entries: 8,
            max_bytes: 240 * 1024,
        };
        let mut after = None;
        let mut found = Vec::new();
        for _ in 0..128 {
            let WalletPage::Page(page) =
                scan_wallet_page(snapshot, &[1; 32], &[2; 32], after.as_ref(), limits)?
            else {
                panic!("the application has a root and coins");
            };
            found.extend(page.coins.into_iter().map(|(address, _)| address));
            if !page.has_more {
                return Ok(found);
            }
            after = page.cursor;
        }
        panic!("scan ended or page budget exhausted");
    }

    /// A store upgraded from a binary that kept no index answers wallet scans
    /// unavailable, naming the walk and its progress, until the walk of its
    /// rows ends; the walk resumes after a restart from its saved cursor.
    #[test]
    fn scans_answer_unavailable_until_the_upgrade_walk_ends() {
        let (dir, db, store, coins) = wallet_store(400);
        // As written by a binary without the index.
        let mut batch = rocksdb::WriteBatch::default();
        batch.delete_range([0x37u8].as_slice(), [0x38u8].as_slice());
        db.inner().write(batch).unwrap();
        let refused = scan_wallet(store.capture_snapshot().unwrap().as_ref()).unwrap_err();
        assert!(
            matches!(&refused, QuilError::ExecutionUnavailable(m) if m.contains("still indexing") && m.contains("0 walked")),
            "{refused}"
        );
        let progress = quil_store::large_vertex_index::walk_step(
            &db.inner(),
            100,
            std::time::Duration::from_secs(60),
        )
        .unwrap();
        assert!(!progress.complete);
        let refused = scan_wallet(store.capture_snapshot().unwrap().as_ref()).unwrap_err();
        assert!(refused.to_string().contains("100 walked"), "{refused}");
        drop(store);
        drop(db);
        let db = quil_store::RocksDb::open(dir.path()).unwrap();
        let store = quil_store::RocksHypergraphStore::new(db.inner());
        assert!(scan_wallet(store.capture_snapshot().unwrap().as_ref()).is_err());
        let mut steps = 0;
        while !quil_store::large_vertex_index::walk_step(
            &db.inner(),
            100,
            std::time::Duration::from_secs(60),
        )
        .unwrap()
        .complete
        {
            steps += 1;
            assert!(steps < 100);
        }
        assert_eq!(
            scan_wallet(store.capture_snapshot().unwrap().as_ref()).unwrap(),
            coins
        );
    }

    /// A delivery whose placement fails is rolled back with its index entry:
    /// the committed store indexes the placed coin and not the refused one.
    #[cfg(feature = "native-proof")]
    #[test]
    fn a_rolled_back_placement_leaves_no_index_entry() {
        let dir = tempfile::tempdir().unwrap();
        let db = quil_store::RocksDb::open(dir.path()).unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let state = HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store.clone(),
            Arc::new(NoopInclusionProver),
        )));
        let (network, application) = ([1u8; 32], [2u8; 32]);
        let context = parameter_context(&network, &application);
        // A cap of one coin refuses the second placement after its vertex
        // was staged, which rolls the placement back.
        let limits = SnapshotLimits {
            max_coins: 1,
            max_depth: 32,
            max_nodes: 1 << 14,
        };
        let coin = |seed: u8| {
            let output = Output {
                owner: [seed; IDENTITY_BYTES],
                commitment: CommitmentKey::derive(&context).commit(
                    u128::from(seed),
                    &AmountOpening::from_seed(&context, &[seed; 32]),
                ),
                memo: [seed; 1115],
            };
            crate::token_intrinsic::state::coin_identity(&context, 5, &output).unwrap()
        };
        let place = |seed: u8| {
            let (address, tree) = coin(seed);
            let block =
                crate::token_intrinsic::coin_blocks::block_for_address(7, &address).unwrap();
            let seq = roots::block_count(&state, &network, &application, block, limits).unwrap();
            crate::token_intrinsic::delivery::place_committed(
                &state,
                5,
                &network,
                &application,
                &address,
                tree,
                block,
                seq,
                limits,
            )
            .map(|()| address)
        };
        let placed = place(3).unwrap();
        let before = state.changeset_len();
        assert!(place(4).is_err());
        assert_eq!(
            state.changeset_len(),
            before,
            "the refused placement left nothing staged"
        );
        let refused = coin(4).0;
        state.commit().unwrap();
        state.abort();
        state.crdt().commit(1).unwrap();
        let snapshot = store.capture_snapshot().unwrap();
        let shard = shard_key_for_location(&Location {
            app_address: application,
            data_address: [0; 32],
        });
        let page = snapshot
            .page_large_vertices_skipping(
                "vertex",
                "adds",
                &shard,
                &application,
                None,
                VertexPageLimits {
                    max_entries: 8,
                    max_bytes: 240 * 1024,
                },
                &super::super::state::is_accumulator_record,
            )
            .unwrap();
        let listed: Vec<_> = page.entries.iter().map(|(address, _)| *address).collect();
        assert_eq!(listed, vec![placed]);
        // The index itself, read raw: the live entries of this application.
        let mut prefix = vec![0x37u8, 0x01];
        prefix.extend_from_slice(&application);
        let entries: Vec<[u8; 32]> = db
            .inner()
            .iterator(rocksdb::IteratorMode::From(
                &prefix,
                rocksdb::Direction::Forward,
            ))
            .map(|entry| entry.unwrap().0)
            .take_while(|key| key.starts_with(&prefix))
            .map(|key| key[prefix.len()..].try_into().unwrap())
            .filter(|address| !super::super::state::is_accumulator_record(address))
            .collect();
        assert!(
            entries.contains(&placed) && !entries.contains(&refused),
            "{entries:?}"
        );
    }
}

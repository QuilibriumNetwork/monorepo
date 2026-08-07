//! Legacy verenc → transparent migration.
//!
//! Pre-2.1 coins are stored as verenc (verifiable-encryption) blobs under the
//! hard-coded `PUBLIC_READ_KEY` — i.e. **already publicly readable**, so they
//! carry no privacy. This migration (run once by archive nodes behind a special
//! flag, like the pebble→rocksdb / forest cutovers) decrypts each legacy coin and
//! re-materializes it as a compact **transparent public token entry**
//! (Ed448-owner ‖ amount, ~72 B vs ~621 B). The decrypt is deterministic (same
//! `PUBLIC_READ_KEY` everywhere) so every node produces byte-identical output —
//! consensus-safe.
//!
//! A transparent coin can then be **one-way shielded** into a lattice private
//! coin with its Ed448 owner signature ([`super::lattice_ct::verify_lattice_shield`]).
//! The verenc machinery runs only here, reading old coins — never for new value.

use num_bigint::BigInt;
use quil_tries::VectorCommitmentTree;
use quil_types::error::{QuilError, Result};

use super::pending::{decrypt_single_verenc, PUBLIC_READ_KEY};

/// The decrypted legacy coin: its Ed448-derived owner address and public amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentCoin {
    pub owner_address: [u8; 32],
    pub amount: u128,
}

/// Decrypt a legacy verenc coin vertex tree into `(owner_address, amount)`.
/// Slots (keys `idx.to_be_bytes()`): 1 = CoinBalance (amount), 2 =
/// ImplicitOwnerAddress. `Ok(None)` if the tree isn't a legacy coin (missing
/// slots). Mirrors the decrypt in `pending::legacy_verify_input`.
pub fn decode_legacy_verenc_coin(tree: &VectorCommitmentTree) -> Result<Option<TransparentCoin>> {
    let read_slot = |idx: u64| tree.get(&idx.to_be_bytes()).map(|b| b.to_vec());
    let (amount_blob, address_blob) = match (read_slot(1), read_slot(2)) {
        (Some(a), Some(b)) => (a, b),
        _ => return Ok(None),
    };

    // Amount: the decrypted verenc slot carries a single leading pad byte, so
    // the little-endian u128 value occupies bytes [1..17] — NOT [0..16]. Reading
    // from byte 0 shifts every byte up one position (×256 inflation). Parse
    // [1..17] as the LE u128; reject if any byte past 16 is set.
    let amt = decrypt_single_verenc(&amount_blob, &PUBLIC_READ_KEY)
        .ok_or_else(|| QuilError::InvalidArgument("migrate: decrypt amount failed".into()))?;
    if amt.len() < 17 {
        return Err(QuilError::InvalidArgument("migrate: legacy amount slot too short".into()));
    }
    if amt.iter().skip(17).any(|&b| b != 0) {
        return Err(QuilError::InvalidArgument("migrate: legacy amount exceeds u128".into()));
    }
    let mut a16 = [0u8; 16];
    a16.copy_from_slice(&amt[1..17]);
    let amount = u128::from_le_bytes(a16);

    // Owner address: decrypt, drop the leading byte, reverse the next 32.
    let addr = decrypt_single_verenc(&address_blob, &PUBLIC_READ_KEY)
        .ok_or_else(|| QuilError::InvalidArgument("migrate: decrypt address failed".into()))?;
    if addr.len() < 33 {
        return Err(QuilError::InvalidArgument("migrate: legacy address < 33 bytes".into()));
    }
    let mut owner_address = [0u8; 32];
    owner_address.copy_from_slice(&addr[1..33]);
    owner_address.reverse();

    Ok(Some(TransparentCoin { owner_address, amount }))
}

/// Type hash for a transparent legacy coin vertex: `poseidon(domain ‖
/// "transparent:LegacyCoin")`.
pub fn transparent_type_hash(domain: &[u8]) -> Result<[u8; 32]> {
    let mut p = Vec::with_capacity(domain.len() + 22);
    p.extend_from_slice(domain);
    p.extend_from_slice(b"transparent:LegacyCoin");
    quil_crypto::poseidon::hash_bytes_to_32(&p)
}

/// Build the compact transparent-coin vertex tree: `[0x00]` owner (32 B),
/// `[1<<2]` amount (16 B LE), `[2<<2]` origin (the original verenc coin's
/// 32-byte address), `[0xFF;32]` type hash.
///
/// The `origin` leaf is a per-coin UNIQUENESS element: without it, two legacy
/// coins with the same `(owner, amount)` would hash to the same
/// [`coin_content_address`](super::materialize::coin_content_address) and the
/// second would overwrite the first — silently destroying value. Binding the
/// original address makes every migrated coin's content address distinct and
/// gives a 1:1 link back to the coin it replaced. Consumers still read `owner`
/// (`[0x00]`) and `amount` (`[1<<2]`) by key, so the extra leaf is inert to the
/// spend/shield path.
pub fn create_transparent_coin_tree(
    coin: &TransparentCoin,
    type_hash: &[u8; 32],
    origin: &[u8; 32],
) -> Result<VectorCommitmentTree> {
    let mut tree = VectorCommitmentTree::new();
    let ins = |t: &mut VectorCommitmentTree, k: &[u8], v: &[u8]| {
        t.insert(k, v, &[], &BigInt::from(v.len()))
            .map_err(|e| QuilError::Internal(format!("transparent coin tree: {}", e)))
    };
    ins(&mut tree, &[0x00], &coin.owner_address)?;
    ins(&mut tree, &[1u8 << 2], &coin.amount.to_le_bytes())?;
    ins(&mut tree, &[2u8 << 2], origin)?;
    ins(&mut tree, &[0xFFu8; 32], type_hash)?;
    Ok(tree)
}

/// Migrate one legacy coin: decrypt it and (if it is one) build its transparent
/// vertex, bound to its `origin` (original 32-byte address) for uniqueness.
/// Returns `(transparent_address, amount, transparent_tree)`, or `Ok(None)` for
/// non-legacy vertices. `amount` is surfaced so the bulk pass can prove
/// conservation.
pub fn migrate_legacy_coin(
    domain: &[u8],
    legacy_tree: &VectorCommitmentTree,
    origin: &[u8; 32],
) -> Result<Option<([u8; 32], u128, VectorCommitmentTree)>> {
    let Some(coin) = decode_legacy_verenc_coin(legacy_tree)? else {
        return Ok(None);
    };
    let th = transparent_type_hash(domain)?;
    let tree = create_transparent_coin_tree(&coin, &th, origin)?;
    let addr = super::materialize::coin_content_address(&tree)?;
    Ok(Some((addr, coin.amount, tree)))
}

/// Result of a bulk legacy migration: how many coins were converted and the
/// total value moved (for the conservation check — `Σ transparent == Σ verenc`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LegacyMigrationSummary {
    pub migrated: usize,
    pub total_amount: u128,
}

/// The single store shard holding all of `domain`'s coin vertices — `l2` = the
/// (padded) domain address (`shard_key_for_location`). All coins live under this
/// one keyspace; the forest build later sub-shards them by address.
pub fn coin_domain_shard(domain: &[u8]) -> quil_types::store::ShardKey {
    let mut app = [0u8; 32];
    let n = domain.len().min(32);
    app[..n].copy_from_slice(&domain[..n]);
    quil_hypergraph::addressing::shard_key_for_location(&quil_hypergraph::addressing::Location {
        app_address: app,
        data_address: [0u8; 32],
    })
}

/// Archive-node bulk verenc→transparent migration, STREAMING (bounded memory):
/// scans the coin keyspace in `chunk_size`-row snapshot chunks
/// ([`stream_migrate_vertex_adds`](quil_store::RocksHypergraphStore::stream_migrate_vertex_adds),
/// `rayon` per-coin transform), emitting `VertexWrite`s straight to the KV
/// keyspace — NO `HypergraphState` changeset, NO per-coin KZG recompute — so peak
/// memory is O(chunk) even at 100+ GB coin sets. Each legacy verenc coin becomes
/// a transparent entry at its content address and the verenc original is
/// PHYSICALLY DELETED from the adds phase. Deterministic ⇒ consensus-safe. The
/// forest is rebuilt afterward (`quil_forest_migrate`); the caller records the
/// conservation receipt. Returns the count + total value moved;
/// `progress(scanned, migrated)` fires per chunk.
pub fn migrate_all_legacy_coins(
    store: &quil_store::RocksHypergraphStore,
    domain: &[u8],
    chunk_size: usize,
    progress: &mut (dyn FnMut(usize, usize) + Send),
) -> Result<LegacyMigrationSummary> {
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    let shard = coin_domain_shard(domain);
    let dom: Vec<u8> = domain[..domain.len().min(32)].to_vec();

    // PARALLELISM across the 256 top-address-byte ranges: one snapshot iterator +
    // transform + writer per range, fanned across the rayon pool so ALL cores
    // stay busy. A single serial iterator was the throughput ceiling (the
    // per-coin verenc decode is cheap and thread-safe; the bottleneck was the
    // scan/write pipeline running on one core). Ranges are disjoint by address ⇒
    // each coin is migrated exactly once. The transform is serial WITHIN a range
    // (the range fan-out is the parallelism).
    let scanned = AtomicUsize::new(0);
    let migrated = AtomicUsize::new(0);
    let total = Mutex::new(0u128);
    let progress = Mutex::new(progress);

    (0u8..=255u8).into_par_iter().try_for_each(|top| -> Result<()> {
        // Sub-range key (after the shard prefix): domain(32) ‖ [top address byte].
        let mut sub = Vec::with_capacity(dom.len() + 1);
        sub.extend_from_slice(&dom);
        sub.push(top);

        store.migrate_vertex_adds_subrange(
            &shard,
            &sub,
            chunk_size,
            |chunk: &[(Vec<u8>, Vec<u8>)]| -> Result<(usize, Vec<quil_store::VertexWrite>)> {
                let mut writes = Vec::with_capacity(chunk.len() * 2);
                let mut m = 0usize;
                let mut chunk_amount: u128 = 0;
                for (vk, blob) in chunk {
                    if let Some((amount, ws)) = migrate_one(domain, vk, blob)? {
                        chunk_amount = chunk_amount.checked_add(amount).ok_or_else(|| {
                            QuilError::InvalidArgument(
                                "migrate: total legacy amount overflows u128".into(),
                            )
                        })?;
                        m += 1;
                        writes.extend(ws);
                    }
                }
                // Fold this chunk's counts into the shared totals and report —
                // PER CHUNK (across all ranges), so progress is live rather than
                // only when a whole 760k-coin range finishes.
                let sc = scanned.fetch_add(chunk.len(), Ordering::Relaxed) + chunk.len();
                let mi = migrated.fetch_add(m, Ordering::Relaxed) + m;
                {
                    let mut t = total.lock().unwrap();
                    *t = t.checked_add(chunk_amount).ok_or_else(|| {
                        QuilError::InvalidArgument(
                            "migrate: total legacy amount overflows u128".into(),
                        )
                    })?;
                }
                (*progress.lock().unwrap())(sc, mi);
                Ok((m, writes))
            },
        )?;
        Ok(())
    })?;

    let total_amount = *total.lock().unwrap();
    Ok(LegacyMigrationSummary {
        migrated: migrated.load(Ordering::Relaxed),
        total_amount,
    })
}

/// Transform ONE legacy verenc coin vertex: decode it, emit its transparent
/// entry at the (unique) content address, and PHYSICALLY DELETE the verenc
/// original from the adds phase (treated as if it never existed — the
/// conservation receipt records Σ). Returns `None` for non-legacy vertices and
/// the reserved metadata vertices (shadow-accumulator root, receipt). Mirrors
/// [`rescale_one`]. Pure + deterministic ⇒ safe to fan out across `rayon`.
fn migrate_one(
    domain: &[u8],
    vertex_key: &[u8],
    blob: &[u8],
) -> Result<Option<(u128, [quil_store::VertexWrite; 2])>> {
    use super::shadow_accumulator::ACC_ROOT_ADDRESS;
    if vertex_key.len() < 64 {
        return Ok(None);
    }
    let addr = &vertex_key[32..64];
    if addr == ACC_ROOT_ADDRESS.as_slice() || addr == MIGRATION_RECEIPT_ADDRESS.as_slice() {
        return Ok(None);
    }
    let mut origin = [0u8; 32];
    origin.copy_from_slice(&vertex_key[32..64]);
    let tree = VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(blob)
            .map_err(|e| QuilError::Internal(format!("migrate: deserialize: {e}")))?,
    };
    match migrate_legacy_coin(domain, &tree, &origin)? {
        Some((new_addr, amount, ttree)) => {
            let ser = quil_tries::serialize_go_tree(ttree.root.as_ref())
                .map_err(|e| QuilError::Internal(format!("migrate: serialize: {e}")))?;
            // Put key = domain(32) ‖ new content address(32).
            let mut add_key = Vec::with_capacity(64);
            add_key.extend_from_slice(&vertex_key[..32]);
            add_key.extend_from_slice(&new_addr);
            Ok(Some((
                amount,
                [
                    quil_store::VertexWrite::Put {
                        set: "vertex",
                        phase: "adds",
                        vertex_key: add_key,
                        blob: ser,
                    },
                    quil_store::VertexWrite::Delete {
                        set: "vertex",
                        phase: "adds",
                        vertex_key: vertex_key.to_vec(),
                    },
                ],
            )))
        }
        None => Ok(None),
    }
}

/// Reserved vertex holding the coin-conservation receipt `count(u64 BE) ‖
/// total(u128 BE)`. Because the migration DELETES the verenc originals (they
/// "never existed"), `--verify-db` can't re-sum them post-hoc; instead the
/// migration records `(count, Σ)` here and verify recomputes `Σ transparent`
/// and requires a match. Sits at `…FD`, one below the shadow-accumulator root
/// (`…FE`), out of the hash-derived coin address space.
pub const MIGRATION_RECEIPT_ADDRESS: [u8; 32] = {
    let mut a = [0xFFu8; 32];
    a[31] = 0xFD;
    a
};

/// Read the coin-conservation receipt `(count, total)` written by the
/// migration, if present. `None` on a DB that predates receipt-writing.
pub fn read_migration_receipt(
    state: &crate::hypergraph_state::HypergraphState,
    domain: &[u8],
) -> Result<Option<(u64, u128)>> {
    let disc = crate::hypergraph_state::vertex_adds_discriminator()?;
    match state.get(domain, &MIGRATION_RECEIPT_ADDRESS, &disc)? {
        Some(rec) if rec.len() >= 24 => {
            let count = u64::from_be_bytes(rec[0..8].try_into().unwrap());
            let total = u128::from_be_bytes(rec[8..24].try_into().unwrap());
            Ok(Some((count, total)))
        }
        _ => Ok(None),
    }
}

/// Write the coin-conservation receipt `(count, total)` at
/// [`MIGRATION_RECEIPT_ADDRESS`] so `--verify-db` can reconcile
/// `Σ transparent == Σ verenc` after the verenc originals are deleted.
pub fn write_migration_receipt(
    state: &crate::hypergraph_state::HypergraphState,
    domain: &[u8],
    count: u64,
    total: u128,
) -> Result<()> {
    let mut rec = Vec::with_capacity(24);
    rec.extend_from_slice(&count.to_be_bytes());
    rec.extend_from_slice(&total.to_be_bytes());
    let disc = crate::hypergraph_state::vertex_adds_discriminator()?;
    state.set(domain, &MIGRATION_RECEIPT_ADDRESS, &disc, 0, rec)
}

/// In-place CORRECTIVE pass for a DB migrated by the OLD byte-shifted decode
/// (every transparent coin ×256). Operates on the ALREADY-transparent coins —
/// no verenc re-decrypt, no backup: `÷256` each amount and re-key to its new
/// content address. Streams the vertex-adds keyspace in chunks (`rayon` within a
/// chunk) via [`quil_store::RocksHypergraphStore::stream_migrate_vertex_adds`],
/// emitting `VertexWrite` puts/deletes. Returns the count corrected + the
/// corrected total (for the receipt + conservation check).
pub fn rescale_all_legacy_coins(
    store: &quil_store::RocksHypergraphStore,
    domain: &[u8],
    chunk_size: usize,
    progress: &mut dyn FnMut(usize, usize),
) -> Result<LegacyMigrationSummary> {
    use rayon::prelude::*;
    let mut app = [0u8; 32];
    let n = domain.len().min(32);
    app[..n].copy_from_slice(&domain[..n]);
    let shard = quil_hypergraph::addressing::shard_key_for_location(
        &quil_hypergraph::addressing::Location { app_address: app, data_address: [0u8; 32] },
    );

    let mut total_amount: u128 = 0u128;
    let (_, rescaled) = store.stream_migrate_vertex_adds(
        &shard,
        chunk_size,
        |chunk: &[(Vec<u8>, Vec<u8>)]| -> Result<(usize, Vec<quil_store::VertexWrite>)> {
            let per: Vec<(u128, [quil_store::VertexWrite; 2])> = chunk
                .par_iter()
                .filter_map(|(vertex_key, blob)| rescale_one(domain, vertex_key, blob).transpose())
                .collect::<Result<Vec<_>>>()?;
            let mut writes = Vec::with_capacity(per.len() * 2);
            let mut m = 0usize;
            for (amount, ws) in per {
                total_amount = total_amount.checked_add(amount).ok_or_else(|| {
                    QuilError::InvalidArgument("rescale: total corrected amount overflows u128".into())
                })?;
                m += 1;
                writes.extend(ws);
            }
            Ok((m, writes))
        },
        |scanned, rescaled| progress(scanned, rescaled),
    )?;
    Ok(LegacyMigrationSummary { migrated: rescaled, total_amount })
}

/// Correct a single already-transparent coin: `÷256` its inflated amount and
/// re-key to the new content address. Skips reserved metadata vertices and
/// non-transparent leaves. Bails LOUDLY if the amount's low byte is set (not a
/// clean ×256 shift ⇒ data isn't uniformly inflated) rather than corrupt it.
fn rescale_one(
    domain: &[u8],
    vertex_key: &[u8],
    blob: &[u8],
) -> Result<Option<(u128, [quil_store::VertexWrite; 2])>> {
    use super::shadow_accumulator::ACC_ROOT_ADDRESS;
    if vertex_key.len() < 64 {
        return Ok(None);
    }
    let addr = &vertex_key[32..64];
    // Never touch the reserved metadata vertices (shadow-accumulator root, receipt).
    if addr == ACC_ROOT_ADDRESS.as_slice() || addr == MIGRATION_RECEIPT_ADDRESS.as_slice() {
        return Ok(None);
    }
    let tree = VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(blob)
            .map_err(|e| QuilError::Internal(format!("rescale: deserialize: {e}")))?,
    };
    let th = transparent_type_hash(domain)?;
    // Only transparent legacy coins carry this type leaf.
    match tree.get(&[0xFFu8; 32]) {
        Some(t) if t == th.as_slice() => {}
        _ => return Ok(None),
    }
    let owner = tree
        .get(&[0x00])
        .ok_or_else(|| QuilError::InvalidArgument("rescale: coin missing owner leaf".into()))?;
    let origin_v = tree
        .get(&[2u8 << 2])
        .ok_or_else(|| QuilError::InvalidArgument("rescale: coin missing origin leaf".into()))?;
    let amt_v = tree
        .get(&[1u8 << 2])
        .ok_or_else(|| QuilError::InvalidArgument("rescale: coin missing amount leaf".into()))?;
    if owner.len() != 32 || origin_v.len() != 32 {
        return Err(QuilError::InvalidArgument("rescale: owner/origin not 32 bytes".into()));
    }
    let mut b = [0u8; 16];
    let k = amt_v.len().min(16);
    b[..k].copy_from_slice(&amt_v[..k]);
    let inflated = u128::from_le_bytes(b);
    // A clean one-byte left shift ⇒ the low byte is 0 and ÷256 is exact. If it
    // isn't, the data is NOT uniformly ×256 and we must NOT silently truncate —
    // fail loudly so the operator investigates rather than corrupting balances.
    if inflated & 0xFF != 0 {
        return Err(QuilError::InvalidArgument(format!(
            "rescale: coin amount {inflated} is not a clean ×256 shift (low byte set) — \
             data is not uniformly inflated; aborting"
        )));
    }
    if inflated == 0 {
        return Ok(None); // already zero — nothing to correct, and re-keying would collide
    }
    let true_amount = inflated >> 8;
    let mut owner_address = [0u8; 32];
    owner_address.copy_from_slice(owner);
    let mut origin = [0u8; 32];
    origin.copy_from_slice(origin_v);
    let coin = TransparentCoin { owner_address, amount: true_amount };
    let ctree = create_transparent_coin_tree(&coin, &th, &origin)?;
    let new_addr = super::materialize::coin_content_address(&ctree)?;
    let ser = quil_tries::serialize_go_tree(ctree.root.as_ref())
        .map_err(|e| QuilError::Internal(format!("rescale: serialize: {e}")))?;
    let mut add_key = Vec::with_capacity(64);
    add_key.extend_from_slice(&vertex_key[..32]);
    add_key.extend_from_slice(&new_addr);
    Ok(Some((
        true_amount,
        [
            quil_store::VertexWrite::Put {
                set: "vertex",
                phase: "adds",
                vertex_key: add_key,
                blob: ser,
            },
            quil_store::VertexWrite::Delete {
                set: "vertex",
                phase: "adds",
                vertex_key: vertex_key.to_vec(),
            },
        ],
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transparent_coin_tree_stores_owner_amount_and_origin() {
        let coin = TransparentCoin { owner_address: [0x7Au8; 32], amount: 123456789 };
        let th = transparent_type_hash(&[0x51u8; 32]).unwrap();
        let origin = [0x33u8; 32];
        let tree = create_transparent_coin_tree(&coin, &th, &origin).unwrap();
        assert_eq!(tree.get(&[0x00]).unwrap(), &coin.owner_address[..]);
        assert_eq!(tree.get(&[1u8 << 2]).unwrap(), &coin.amount.to_le_bytes()[..]);
        assert_eq!(tree.get(&[2u8 << 2]).unwrap(), &origin[..]);
        assert_eq!(tree.get(&[0xFFu8; 32]).unwrap(), &th[..]);
    }

    #[test]
    fn identical_owner_amount_coins_get_distinct_addresses_via_origin() {
        // Two legacy coins with the SAME (owner, amount) must not collide: the
        // origin leaf makes their content addresses distinct so neither is lost.
        let coin = TransparentCoin { owner_address: [0x7Au8; 32], amount: 100 };
        let th = transparent_type_hash(&[0x51u8; 32]).unwrap();
        let a = super::super::materialize::coin_content_address(
            &create_transparent_coin_tree(&coin, &th, &[0xA1u8; 32]).unwrap(),
        )
        .unwrap();
        let b = super::super::materialize::coin_content_address(
            &create_transparent_coin_tree(&coin, &th, &[0xB2u8; 32]).unwrap(),
        )
        .unwrap();
        assert_ne!(a, b, "distinct origins ⇒ distinct content addresses");
    }

    #[test]
    fn non_legacy_tree_decodes_to_none() {
        // A tree without the encrypted slots is not a legacy coin.
        let mut tree = VectorCommitmentTree::new();
        tree.insert(&[0x00], b"not-a-coin", &[], &BigInt::from(10)).unwrap();
        assert!(decode_legacy_verenc_coin(&tree).unwrap().is_none());
    }
}

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
//! coin with its Ed448 owner signature through the QCT3 shield adapter.
//! The verenc machinery runs only here, reading old coins — never for new value.

use num_bigint::BigInt;
use quil_tries::VectorCommitmentTree;
use quil_types::error::{QuilError, Result};

/// Public-read key for the pre-2.1 VerEnc coin fields. Matches Go
/// `token_intrinsic_transaction.go:33`:
/// `2cf07ca8d9ab1a4bb0902e25a9b90759dd54d881f54d52a76a17e79bf0361c325650f12746e4337ffb5940e7665ad7bf83f44af98d964bbe`.
pub(crate) const PUBLIC_READ_KEY: [u8; 56] = [
    0x2c, 0xf0, 0x7c, 0xa8, 0xd9, 0xab, 0x1a, 0x4b,
    0xb0, 0x90, 0x2e, 0x25, 0xa9, 0xb9, 0x07, 0x59,
    0xdd, 0x54, 0xd8, 0x81, 0xf5, 0x4d, 0x52, 0xa7,
    0x6a, 0x17, 0xe7, 0x9b, 0xf0, 0x36, 0x1c, 0x32,
    0x56, 0x50, 0xf1, 0x27, 0x46, 0xe4, 0x33, 0x7f,
    0xfb, 0x59, 0x40, 0xe7, 0x66, 0x5a, 0xd7, 0xbf,
    0x83, 0xf4, 0x4a, 0xf9, 0x8d, 0x96, 0x4b, 0xbe,
];


// =====================================================================
// Legacy verenc decryption (migration only — decodes pre-2.1 coins into
// transparent entries; NOT a spend path)
// =====================================================================

/// Parse a 621-byte `MPCitHVerEnc` blob (Go
/// `MPCitHVerEncFromBytes`, `verenc/verifiable_encryption.go:139`) and
/// build the `VerencDecrypt` payload expected by `verenc_recover`.
fn parse_mpcith_verenc(bytes: &[u8], decryption_key: &[u8]) -> Option<verenc::VerencDecrypt> {
    if bytes.len() != 621 {
        return None;
    }
    let mut ctexts = Vec::with_capacity(3);
    for i in 0..3 {
        let base = i * (57 + 56);
        ctexts.push(verenc::VerencCiphertext {
            c1: bytes[base..base + 57].to_vec(),
            c2: bytes[base + 57..base + 57 + 56].to_vec(),
            i: 0,
        });
    }
    let mut aux = Vec::with_capacity(3);
    for i in 0..3 {
        let base = 339 + i * 56;
        aux.push(bytes[base..base + 56].to_vec());
    }
    Some(verenc::VerencDecrypt {
        blinding_pubkey: bytes[507..564].to_vec(),
        decryption_key: decryption_key.to_vec(),
        statement: bytes[564..621].to_vec(),
        ciphertexts: verenc::CompressedCiphertext { ctexts, aux },
    })
}

/// Decrypt a single 621-byte VerEnc blob with the supplied decryption
/// key and return the combined plaintext bytes. Matches Go
/// `MPCitHVerifiableEncryptor.Decrypt` with a one-element input list.
pub(crate) fn decrypt_single_verenc(bytes: &[u8], decryption_key: &[u8]) -> Option<Vec<u8>> {
    let d = parse_mpcith_verenc(bytes, decryption_key)?;
    let chunk = verenc::verenc_recover(d);
    if chunk.is_empty() {
        return None;
    }
    Some(verenc::combine_chunked_data(vec![chunk]))
}



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

/// A transparent legacy coin's `(owner, amount, origin)` from its stored vertex
/// blob, or `None` for any other vertex. The checks are `shield::check_source`'s
/// except the content address, which the caller read the blob under. The type
/// hash is stored verbatim, so other vertices are passed over without parsing.
pub fn read_transparent_coin(blob: &[u8], type_hash: &[u8; 32]) -> Option<([u8; 32], u128, [u8; 32])> {
    memchr::memmem::find(blob, type_hash)?;
    let tree = VectorCommitmentTree { root: quil_tries::deserialize_go_tree(blob).ok()? };
    if tree.leaves().len() != 4 || tree.get(&[0xff; 32]) != Some(type_hash.as_slice()) {
        return None;
    }
    let owner = tree.get(&[0x00])?.try_into().ok()?;
    let amount = u128::from_le_bytes(tree.get(&[1u8 << 2])?.try_into().ok()?);
    let origin = tree.get(&[2u8 << 2])?.try_into().ok()?;
    Some((owner, amount, origin))
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
    // transform + writer per range, fanned across the rayon pool. A single scan
    // is single-CORE-bound (the verenc decode dominates); fanning ranges out
    // engages all cores. rayon caps live iterators at the pool size, so the DB
    // sees ~cores concurrent readers, not 256. Ranges are disjoint by address ⇒
    // each coin is migrated once; other ranges' transparent puts are skipped by
    // `migrate_one`. Transform is serial WITHIN a range (fan-out is the parallelism).
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
                // Fold this chunk's counts into the shared totals and report PER
                // CHUNK (across all ranges), so progress is live rather than only
                // when a whole ~760k-coin range finishes.
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
/// the reserved metadata vertices (shadow-accumulator root, receipt). Pure +
/// deterministic ⇒ safe to fan out across `rayon`.
fn migrate_one(
    domain: &[u8],
    vertex_key: &[u8],
    blob: &[u8],
) -> Result<Option<(u128, [quil_store::VertexWrite; 2])>> {
    use super::constants::LEGACY_ACCUMULATOR_ROOT_ADDRESS as ACC_ROOT_ADDRESS;
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
        Some(rec) if rec.len() == 24 => {
            let count = u64::from_be_bytes(rec[0..8].try_into().unwrap());
            let total = u128::from_be_bytes(rec[8..24].try_into().unwrap());
            Ok(Some((count, total)))
        }
        Some(_) => Err(QuilError::InvalidArgument("malformed migration receipt".into())),
        None => Ok(None),
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

/// Read the coin-conservation receipt `(count, total)` straight from the RAW KV
/// keyspace — the exact place [`migrate_all_legacy_coins`]'s caller writes it
/// ([`quil_store::RocksHypergraphStore::migrate_put_vertex_underlying`]). The
/// OFFLINE `--verify-db` / `--repair-receipt` passes hold a bare store and must
/// read what was physically written, bypassing the versioned
/// [`crate::hypergraph_state::HypergraphState`] view. `None` if no receipt vertex
/// is present (a DB that predates receipt-writing).
pub fn read_migration_receipt_raw(
    store: &quil_store::RocksHypergraphStore,
    domain: &[u8],
) -> Result<Option<(u64, u128)>> {
    let shard = coin_domain_shard(domain);
    let mut vk = domain.to_vec();
    vk.extend_from_slice(&MIGRATION_RECEIPT_ADDRESS);
    match store.load_vertex_underlying("vertex", "adds", &shard, &vk)? {
        Some(rec) if rec.len() == 24 => {
            let count = u64::from_be_bytes(rec[0..8].try_into().unwrap());
            let total = u128::from_be_bytes(rec[8..24].try_into().unwrap());
            Ok(Some((count, total)))
        }
        Some(_) => Err(QuilError::InvalidArgument("malformed migration receipt".into())),
        None => Ok(None),
    }
}

/// Write the coin-conservation receipt directly to the RAW KV keyspace (matching
/// the migration's `migrate_put_vertex_underlying` write). Used by
/// `--repair-receipt` to overwrite a receipt that a RESTARTED migration recorded
/// as only its final run's slice (see [`sum_transparent_coins`]).
pub fn write_migration_receipt_raw(
    store: &quil_store::RocksHypergraphStore,
    domain: &[u8],
    count: u64,
    total: u128,
) -> Result<()> {
    let shard = coin_domain_shard(domain);
    let mut vk = domain.to_vec();
    vk.extend_from_slice(&MIGRATION_RECEIPT_ADDRESS);
    let mut rec = Vec::with_capacity(24);
    rec.extend_from_slice(&count.to_be_bytes());
    rec.extend_from_slice(&total.to_be_bytes());
    store.migrate_put_vertex_underlying("vertex", "adds", &shard, &vk, &rec)
}

/// Sum the migrated TRANSPARENT coin set: `(count, Σ amount)`.
///
/// This is the GROUND TRUTH of what the migration actually left in the DB —
/// independent of the conservation receipt. A migration that was stopped and
/// restarted UNDERCOUNTS in its receipt: it physically deletes each verenc
/// original as it converts it, and every run's counters restart at 0, so coins
/// converted by an earlier (interrupted) run are invisible to the final run's
/// tally. The transparent set, by contrast, accumulates across all runs (puts are
/// never deleted), so scanning it recovers the true totals.
///
/// Skips the reserved metadata vertices (shadow-accumulator root at `…FE`,
/// receipt at `…FD`) by key — they are raw records, not coin trees. Every other
/// vertex under the coin shard is a serialized coin tree and is counted iff its
/// type leaf equals the transparent type hash.
pub fn sum_transparent_coins(
    store: &quil_store::RocksHypergraphStore,
    domain: &[u8],
) -> Result<(u64, u128)> {
    use super::constants::LEGACY_ACCUMULATOR_ROOT_ADDRESS as ACC_ROOT_ADDRESS;
    let th = transparent_type_hash(domain)?;
    let shard = coin_domain_shard(domain);
    let (mut count, mut total) = (0u64, 0u128);
    let mut scan_err: Option<QuilError> = None;
    store.for_each_vertex_underlying("vertex", "adds", &shard, |vk: Vec<u8>, blob: Vec<u8>| {
        if scan_err.is_some() {
            return;
        }
        // Skip the reserved metadata vertices (raw records, not coin trees).
        if vk.len() >= 64 {
            let addr = &vk[32..64];
            if addr == ACC_ROOT_ADDRESS.as_slice() || addr == MIGRATION_RECEIPT_ADDRESS.as_slice() {
                return;
            }
        }
        let root = match quil_tries::deserialize_go_tree(&blob) {
            Ok(r) => r,
            Err(e) => {
                scan_err = Some(QuilError::Internal(format!("transparent coin decode: {e}")));
                return;
            }
        };
        let tree = VectorCommitmentTree { root };
        // Count only transparent coins (type leaf == transparent type hash).
        if tree.get(&[0xFFu8; 32]).map(|t| t == th.as_slice()).unwrap_or(false) {
            let Some(a) = tree.get(&[1u8 << 2]).filter(|a| a.len() == 16) else {
                scan_err = Some(QuilError::InvalidArgument("transparent coin amount must be 16 bytes".into()));
                return;
            };
            let amount = u128::from_le_bytes(a.try_into().unwrap());
            let Some(next_total) = total.checked_add(amount) else {
                scan_err = Some(QuilError::InvalidArgument("transparent coin total overflows u128".into()));
                return;
            };
            let Some(next_count) = count.checked_add(1) else {
                scan_err = Some(QuilError::InvalidArgument("transparent coin count overflows u64".into()));
                return;
            };
            total = next_total;
            count = next_count;
        }
    })?;
    if let Some(e) = scan_err {
        return Err(e);
    }
    Ok((count, total))
}

#[cfg(test)]
mod read_transparent_tests {
    use super::*;

    #[test]
    fn a_transparent_coin_reads_back_and_other_vertices_do_not() {
        let domain = [0x11u8; 32];
        let th = transparent_type_hash(&domain).unwrap();
        let coin = TransparentCoin { owner_address: [7; 32], amount: 123_456_789_012_345, };
        let tree = create_transparent_coin_tree(&coin, &th, &[9; 32]).unwrap();
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        assert_eq!(read_transparent_coin(&blob, &th), Some(([7; 32], 123_456_789_012_345, [9; 32])));
        let other = transparent_type_hash(&[0x22; 32]).unwrap();
        assert_eq!(read_transparent_coin(&blob, &other), None, "another domain's type");
        assert_eq!(read_transparent_coin(&[0; 64], &th), None);
        let mut extra = create_transparent_coin_tree(&coin, &th, &[9; 32]).unwrap();
        extra.insert(&[12], &[1], &[], &BigInt::from(1)).unwrap();
        let extra = quil_tries::serialize_go_tree(extra.root.as_ref()).unwrap();
        assert_eq!(read_transparent_coin(&extra, &th), None, "a fifth field is not a transparent coin");
    }
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

#[cfg(test)]
mod _size_probe {
    use super::*;
    #[test]
    fn print_transparent_coin_size() {
        let coin = TransparentCoin { owner_address: [0xabu8; 32], amount: 123456789u128 };
        let th = [0xffu8; 32];
        let origin = [0xcdu8; 32];
        let tree = create_transparent_coin_tree(&coin, &th, &origin).unwrap();
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        println!("TRANSPARENT_COIN_SERIALIZED_BYTES = {}", blob.len());
    }
}

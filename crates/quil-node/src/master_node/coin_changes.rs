//! Wallet arrival cursors across the stores covering one application.
//!
//! The backend cursor belongs to one durable store generation. The envelope
//! binds its range and issuer; it contains no address the node can dial.

use std::sync::Arc;

use quil_hypergraph::HypergraphCrdt;
use quil_types::{
    error::{QuilError, Result},
    store::{
        CoinChangesPageData, CoinData, MAX_COIN_CHANGE_CURSOR_BYTES,
        MAX_COIN_CHANGE_SOURCES as MAX_SOURCES,
    },
};

const LOCAL: u8 = 1;
const MAX_FILTER_BYTES: usize = 128;
const MAX_BACKEND_CURSOR_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Source {
    filter: Vec<u8>,
    cursor: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct Cursor {
    next: usize,
    sources: Vec<Source>,
}

fn unavailable(message: &str) -> QuilError {
    QuilError::ExecutionUnavailable(message.into())
}

fn encode(
    network: &[u8; 32],
    issuer: &[u8; 32],
    domain: &[u8; 32],
    cursor: &Cursor,
) -> Result<Vec<u8>> {
    if cursor.sources.is_empty()
        || cursor.sources.len() > MAX_SOURCES
        || cursor.next >= cursor.sources.len()
    {
        return Err(unavailable(
            "coin feed source count exceeds its cursor budget",
        ));
    }
    let mut bytes = vec![LOCAL];
    bytes.extend_from_slice(network);
    bytes.extend_from_slice(issuer);
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&(cursor.next as u16).to_be_bytes());
    bytes.extend_from_slice(&(cursor.sources.len() as u16).to_be_bytes());
    for source in &cursor.sources {
        if source.filter.len() > MAX_FILTER_BYTES
            || !source.filter.starts_with(domain)
            || source.cursor.is_empty()
            || source.cursor.len() > MAX_BACKEND_CURSOR_BYTES
        {
            return Err(unavailable(
                "coin feed source has no bounded durable cursor",
            ));
        }
        bytes.extend_from_slice(&(source.filter.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&source.filter);
        bytes.extend_from_slice(&(source.cursor.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&source.cursor);
    }
    if bytes.len() > MAX_COIN_CHANGE_CURSOR_BYTES {
        return Err(unavailable("coin feed cursor exceeds its byte budget"));
    }
    Ok(bytes)
}

fn decode(
    bytes: &[u8],
    network: &[u8; 32],
    issuer: &[u8; 32],
    domain: &[u8; 32],
) -> Option<Cursor> {
    if bytes.len() > MAX_COIN_CHANGE_CURSOR_BYTES
        || bytes.first() != Some(&LOCAL)
        || bytes.get(1..33)? != network
        || bytes.get(33..65)? != issuer
        || bytes.get(65..97)? != domain
    {
        return None;
    }
    let mut rest = bytes.get(97..)?;
    fn number(rest: &mut &[u8]) -> Option<usize> {
        let n = u16::from_be_bytes(rest.get(..2)?.try_into().ok()?);
        *rest = &rest[2..];
        Some(usize::from(n))
    }
    fn field(rest: &mut &[u8], max: usize) -> Option<Vec<u8>> {
        let len = number(rest)?;
        if len == 0 || len > max {
            return None;
        }
        let bytes = rest.get(..len)?.to_vec();
        *rest = &rest[len..];
        Some(bytes)
    }
    let next = number(&mut rest)?;
    let count = number(&mut rest)?;
    if count == 0 || count > MAX_SOURCES || next >= count {
        return None;
    }
    let mut sources: Vec<Source> = Vec::with_capacity(count);
    for _ in 0..count {
        let filter = field(&mut rest, MAX_FILTER_BYTES)?;
        let cursor = field(&mut rest, MAX_BACKEND_CURSOR_BYTES)?;
        if !filter.starts_with(domain)
            || sources
                .last()
                .is_some_and(|previous| previous.filter >= filter)
        {
            return None;
        }
        sources.push(Source { filter, cursor });
    }
    rest.is_empty().then_some(Cursor { next, sources })
}

pub(super) fn bootstrap(
    network: &[u8; 32],
    issuer: &[u8; 32],
    domain: &[u8; 32],
    sources: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<Vec<u8>> {
    // An older provider's snapshot cannot be given a live-store watermark.
    if sources.len() > MAX_SOURCES || sources.iter().any(|(_, cursor)| cursor.is_empty()) {
        return Ok(Vec::new());
    }
    let mut sources: Vec<_> = sources
        .into_iter()
        .map(|(filter, cursor)| Source { filter, cursor })
        .collect();
    sources.sort_by(|a, b| a.filter.cmp(&b.filter));
    encode(network, issuer, domain, &Cursor { next: 0, sources })
}

fn reset(network: [u8; 32]) -> CoinChangesPageData {
    CoinChangesPageData {
        network,
        coins: Vec::new(),
        cursor: Vec::new(),
        has_more: false,
        reset: true,
    }
}

pub(super) fn page(
    network: [u8; 32],
    issuer: &[u8; 32],
    domain: &[u8; 32],
    mut local: Vec<(Vec<u8>, Arc<HypergraphCrdt>)>,
    bytes: &[u8],
    max_coins: usize,
) -> Result<Option<CoinChangesPageData>> {
    let Some(mut cursor) = decode(bytes, &network, issuer, domain) else {
        if local.len() > MAX_SOURCES {
            return Ok(None);
        }
        return Ok(Some(reset(network)));
    };
    local.sort_by(|a, b| a.0.cmp(&b.0));
    if cursor.sources.len() != local.len()
        || cursor
            .sources
            .iter()
            .zip(&local)
            .any(|(source, (filter, _))| &source.filter != filter)
    {
        return Ok(Some(reset(network)));
    }
    let mut databases = Vec::with_capacity(local.len());
    let mut heads = Vec::with_capacity(local.len());
    for ((_, crdt), source) in local.iter().zip(&cursor.sources) {
        let Some(db) = crdt.forest_store() else {
            return Ok(None);
        };
        // Validate every source before returning any output: bootstrap reads
        // refuse incomplete state, whereas an existing feed must reset.
        let Some(head) = quil_store::coin_changes::cursor_head(&db, domain, &source.cursor)? else {
            return Ok(Some(reset(network)));
        };
        databases.push(db);
        heads.push(head);
    }
    // Start after the last served store, rather than repeatedly draining a
    // hot first worker while later workers accumulate unseen outputs.
    let index = (0..local.len())
        .map(|offset| (cursor.next + offset) % local.len())
        .find(|&index| cursor.sources[index].cursor != heads[index]);
    let Some(index) = index else {
        return Ok(Some(CoinChangesPageData {
            network,
            coins: Vec::new(),
            cursor: bytes.to_vec(),
            has_more: false,
            reset: false,
        }));
    };
    let max_coins = max_coins.clamp(8, 64);
    let budget = quil_types::store::scan_page_bytes(max_coins).saturating_sub(bytes.len() + 1024);
    let raw = quil_store::coin_changes::read_page(
        &databases[index],
        domain,
        &cursor.sources[index].cursor,
        max_coins,
        budget,
    )?;
    if raw.reset {
        return Ok(Some(reset(network)));
    }
    let context = quil_lattice_ct::confidential::transfer::parameter_context(&network, domain);
    let (path, _) = super::grpc::shard_range(&local[index].0)
        .ok_or_else(|| unavailable("coin feed source has an invalid shard range"))?;
    let mut coins = Vec::new();
    for record in raw.records {
        let address: [u8; 32] = record.key[32..].try_into().unwrap();
        if !path.covers(&address) {
            continue;
        }
        if let Some(coin) = quil_execution::token_intrinsic::state::decode_stored_snapshot_coin(
            &context,
            domain,
            &record.key,
            &record.blob,
        )? {
            coins.push(CoinData {
                address,
                frame_number: coin.frame_number,
                position: coin.position,
                owner: coin.output.owner.to_vec(),
                commitment: coin.output.commitment.to_bytes().to_vec(),
                memo: coin.output.memo.to_vec(),
            });
        }
    }
    cursor.sources[index].cursor = raw.cursor;
    cursor.next = (index + 1) % local.len();
    // The selected read may have drained arrivals beyond its sampled head.
    let has_more = raw.has_more
        || cursor
            .sources
            .iter()
            .zip(&heads)
            .enumerate()
            .any(|(other, (source, head))| other != index && &source.cursor != head);
    Ok(Some(CoinChangesPageData {
        network,
        coins,
        cursor: encode(&network, issuer, domain, &cursor)?,
        has_more,
        reset: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_is_bound_to_issuer_network_domain_and_every_source() {
        let network = [1; 32];
        let issuer = [2; 32];
        let domain = [3; 32];
        let sources = vec![(domain.to_vec(), vec![8; 57])];
        let bytes = bootstrap(&network, &issuer, &domain, sources).unwrap();
        let cursor = decode(&bytes, &network, &issuer, &domain).unwrap();
        assert_eq!(cursor.sources[0].cursor, vec![8; 57]);
        assert!(decode(&bytes, &[9; 32], &issuer, &domain).is_none());
        assert!(decode(&bytes, &network, &[9; 32], &domain).is_none());
        assert!(decode(&bytes, &network, &issuer, &[9; 32]).is_none());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode(&trailing, &network, &issuer, &domain).is_none());
        for end in 0..bytes.len() {
            assert!(decode(&bytes[..end], &network, &issuer, &domain).is_none());
        }
    }

    #[test]
    fn unsupported_snapshots_and_excess_sources_cannot_advertise_a_watermark() {
        let domain = [3; 32];
        assert!(bootstrap(
            &[1; 32],
            &[2; 32],
            &domain,
            vec![(domain.to_vec(), Vec::new())]
        )
        .unwrap()
        .is_empty());
        assert!(bootstrap(
            &[1; 32],
            &[2; 32],
            &domain,
            vec![(domain.to_vec(), vec![8; 57]); MAX_SOURCES + 1]
        )
        .unwrap()
        .is_empty());
    }

    fn store() -> (quil_store::RocksDb, Arc<HypergraphCrdt>) {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let crdt = Arc::new(HypergraphCrdt::new(
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        (db, crdt)
    }

    fn stored_cursor(db: &quil_store::RocksDb, domain: &[u8; 32]) -> Vec<u8> {
        let snapshot = quil_store::RocksHypergraphSnapshot::from_database(db.inner());
        quil_store::coin_changes::snapshot_cursor(&snapshot, domain).unwrap()
    }

    fn coin(
        db: &quil_store::RocksDb,
        domain: &[u8; 32],
        frame: u64,
        seed: u8,
        high: Option<bool>,
    ) -> [u8; 32] {
        use quil_lattice_ct::confidential::{
            relation::membership::IDENTITY_BYTES,
            transfer::{parameter_context, Output},
            AmountOpening, CommitmentKey,
        };
        let context = parameter_context(&[1; 32], domain);
        for nonce in seed..=u8::MAX {
            let output = Output {
                owner: [nonce; IDENTITY_BYTES],
                commitment: CommitmentKey::derive(&context)
                    .commit(5, &AmountOpening::from_seed(&context, &[nonce; 32])),
                memo: [nonce; 1115],
            };
            let (address, tree) =
                quil_execution::token_intrinsic::state::create_coin(&context, frame, &output, 0)
                    .unwrap();
            // BN254 addresses have two leading zero bits. Partition on the
            // next bit, which can actually vary for real Coin identities.
            if high.is_some_and(|high| (address[0] & 0x20 != 0) != high) {
                continue;
            }
            let shard = quil_hypergraph::addressing::shard_key_for_location(
                &quil_hypergraph::addressing::Location {
                    app_address: *domain,
                    data_address: address,
                },
            );
            let key = [domain.as_slice(), &address].concat();
            let key = quil_store::encoding::hypergraph_vertex_data_v2_key(
                "vertex", "adds", &shard, &key, frame,
            );
            db.inner()
                .put(
                    key,
                    quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
                )
                .unwrap();
            return address;
        }
        panic!("could not make a coin in the requested range");
    }

    #[test]
    fn a_late_old_frame_arrives_after_the_snapshot_without_rewriting_its_origin() {
        let domain = [3; 32];
        let (db, crdt) = store();
        coin(&db, &domain, 100, 1, None);
        let cursor = bootstrap(
            &[1; 32],
            &[2; 32],
            &domain,
            vec![(domain.to_vec(), stored_cursor(&db, &domain))],
        )
        .unwrap();
        let address = coin(&db, &domain, 7, 2, None);
        let result = page(
            [1; 32],
            &[2; 32],
            &domain,
            vec![(domain.to_vec(), crdt.clone())],
            &cursor,
            8,
        )
        .unwrap()
        .unwrap();
        assert!(!result.reset);
        assert_eq!(result.coins.len(), 1);
        assert_eq!(result.coins[0].address, address);
        assert_eq!(result.coins[0].frame_number, 7);
        assert!(!result.has_more);
        let empty = page(
            [1; 32],
            &[2; 32],
            &domain,
            vec![(domain.to_vec(), crdt)],
            &result.cursor,
            8,
        )
        .unwrap()
        .unwrap();
        assert!(empty.coins.is_empty());
        assert!(!empty.has_more);
    }

    #[test]
    fn a_hot_worker_does_not_starve_the_other_source_and_changed_coverage_resets() {
        let domain = [3; 32];
        let (low_db, low_crdt) = store();
        let (high_db, high_crdt) = store();
        let low = quil_forest::encode_shard_bit_path(&domain, &[false, false, false]);
        let high = quil_forest::encode_shard_bit_path(&domain, &[false, false, true]);
        let mut bytes = bootstrap(
            &[1; 32],
            &[2; 32],
            &domain,
            vec![
                (low.clone(), stored_cursor(&low_db, &domain)),
                (high.clone(), stored_cursor(&high_db, &domain)),
            ],
        )
        .unwrap();
        let local = vec![(low.clone(), low_crdt), (high.clone(), high_crdt)];
        let low_address = coin(&low_db, &domain, 90, 1, Some(false));
        let high_address = coin(&high_db, &domain, 9, 1, Some(true));
        let mut seen = Vec::new();
        for seed in 10..12 {
            let result = page([1; 32], &[2; 32], &domain, local.clone(), &bytes, 8)
                .unwrap()
                .unwrap();
            assert!(!result.reset);
            seen.extend(result.coins.iter().map(|coin| coin.address));
            bytes = result.cursor;
            coin(&low_db, &domain, 100 + u64::from(seed), seed, Some(false));
        }
        assert!(seen.contains(&low_address));
        assert!(seen.contains(&high_address));
        let reset = page(
            [1; 32],
            &[2; 32],
            &domain,
            vec![local[0].clone()],
            &bytes,
            8,
        )
        .unwrap()
        .unwrap();
        assert!(reset.reset && reset.coins.is_empty() && reset.cursor.is_empty());
    }

    #[test]
    fn a_reset_worker_invalidates_the_whole_cursor_before_other_coins_are_returned() {
        let domain = [3; 32];
        let (low_db, low_crdt) = store();
        let (high_db, high_crdt) = store();
        let low = quil_forest::encode_shard_bit_path(&domain, &[false, false, false]);
        let high = quil_forest::encode_shard_bit_path(&domain, &[false, false, true]);
        let bytes = bootstrap(
            &[1; 32],
            &[2; 32],
            &domain,
            vec![
                (low.clone(), stored_cursor(&low_db, &domain)),
                (high.clone(), stored_cursor(&high_db, &domain)),
            ],
        )
        .unwrap();
        let mut local = vec![(low.clone(), low_crdt), (high.clone(), high_crdt)];
        local.sort_by(|a, b| a.0.cmp(&b.0));
        let first_is_low = local[0].0 == low;
        let (hot, invalidated) = if first_is_low {
            (&low_db, &high_db)
        } else {
            (&high_db, &low_db)
        };
        coin(hot, &domain, 7, 1, Some(!first_is_low));
        quil_store::coin_changes::reset(&invalidated.inner()).unwrap();
        let result = page([1; 32], &[2; 32], &domain, local, &bytes, 8)
            .unwrap()
            .unwrap();
        assert!(result.reset && result.coins.is_empty() && result.cursor.is_empty());
    }

    #[test]
    fn journal_reserved_addresses_match_the_existing_coin_decoder() {
        use quil_execution::token_intrinsic::{coin_blocks, state, summary_tree};
        let agrees = |address: [u8; 32]| {
            assert_eq!(
                quil_store::coin_changes::is_reserved_coin_record(&address),
                state::is_accumulator_record(&address),
                "address {address:?}",
            )
        };
        for last in 0..=255 {
            let mut address = [0xff; 32];
            address[31] = last;
            agrees(address);
        }
        for level in 0..=summary_tree::LEVELS {
            for index in [0, (1u64 << (summary_tree::LEVELS - level)) - 1] {
                let address = summary_tree::node_address(level, index);
                agrees(address);
                let mut near = address;
                near[25] ^= 1;
                agrees(near);
            }
        }
        for width in coin_blocks::INITIAL_BLOCK_BITS..=coin_blocks::MAX_BLOCK_BITS {
            for path in [0, (1 << width) - 1] {
                let block = coin_blocks::block_id(width, path).unwrap();
                for tag in [
                    state::BLOCK_FRONTIER_TAG,
                    state::BLOCK_ROOT_TAG,
                    state::BLOCK_OWNER_TAG,
                    state::BLOCK_ESCROW_COUNT_TAG,
                ] {
                    let address = state::block_record_address(tag, block);
                    agrees(address);
                    let mut near = address;
                    near[0] ^= 0x80;
                    agrees(near);
                }
            }
        }
    }

    #[test]
    fn oversized_valid_coins_require_reset_even_with_padding_before_the_owner_field() {
        use quil_tries::VectorCommitmentNode;
        let domain = [3; 32];
        let (db, crdt) = store();
        let address = coin(&db, &domain, 7, 1, None);
        let shard = quil_hypergraph::addressing::shard_key_for_location(
            &quil_hypergraph::addressing::Location {
                app_address: domain,
                data_address: address,
            },
        );
        let vertex = [domain.as_slice(), &address].concat();
        let key = quil_store::encoding::hypergraph_vertex_data_v2_key(
            "vertex", "adds", &shard, &vertex, 7,
        );
        let original = db.inner().get(&key).unwrap().unwrap();
        let mut trailing = original.clone();
        trailing.resize(80 * 1024, 0);
        let mut root = quil_tries::deserialize_go_tree(&original).unwrap();
        fn pad_frame_metadata(node: &mut VectorCommitmentNode) -> bool {
            match node {
                VectorCommitmentNode::Leaf(leaf) if leaf.key == [0] => {
                    leaf.commitment.resize(80 * 1024, 0);
                    true
                }
                VectorCommitmentNode::Branch(branch) => branch
                    .children
                    .iter_mut()
                    .flatten()
                    .any(|child| pad_frame_metadata(child)),
                _ => false,
            }
        }
        assert!(pad_frame_metadata(root.as_mut().unwrap()));
        let leading = quil_tries::serialize_go_tree(root.as_ref()).unwrap();
        let context = quil_lattice_ct::confidential::transfer::parameter_context(&[1; 32], &domain);
        for blob in [trailing, leading] {
            assert!(
                quil_execution::token_intrinsic::state::decode_stored_snapshot_coin(
                    &context, &domain, &vertex, &blob,
                )
                .unwrap()
                .is_some(),
                "the existing decoder accepts this unchanged Coin"
            );
            let cursor = bootstrap(
                &[1; 32],
                &[2; 32],
                &domain,
                vec![(domain.to_vec(), stored_cursor(&db, &domain))],
            )
            .unwrap();
            db.inner().put(&key, blob).unwrap();
            let result = page(
                [1; 32],
                &[2; 32],
                &domain,
                vec![(domain.to_vec(), crdt.clone())],
                &cursor,
                8,
            )
            .unwrap()
            .unwrap();
            assert!(result.reset && result.coins.is_empty());
        }
    }
}

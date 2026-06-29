//! Per-shard size + commitment metadata derived from the hypergraph CRDT.

use num_bigint::BigInt;
use num_traits::Zero;

use quil_hypergraph::HypergraphCrdt;
use quil_tries::{get_full_path, NodeMetadata};
use quil_types::store::{ShardInfo, ShardKey};

#[derive(Debug, Clone)]
pub struct AppShardMetadata {
    pub prefix: Vec<u32>,
    /// Big-endian, leading zero bytes stripped.
    pub size: Vec<u8>,
    pub data_shards: u64,
    /// `[vertex_adds, vertex_removes, hyperedge_adds, hyperedge_removes]`,
    /// each 64 bytes; missing nodes contribute a 64-byte zero blob.
    pub commitments: [Vec<u8>; 4],
}

impl AppShardMetadata {
    pub fn size_bigint(&self) -> BigInt {
        BigInt::from_bytes_be(num_bigint::Sign::Plus, &self.size)
    }
}

pub fn build_app_shard_full_prefix(l2: &[u8], prefix: &[u32]) -> Vec<i32> {
    let mut full = get_full_path(l2);
    full.reserve(prefix.len());
    for &p in prefix {
        full.push(p as i32);
    }
    full
}

/// `ShardInfo.shard_key` is 35 bytes: `L1[3] ++ L2[32]`.
pub fn shard_key_from_bytes(shard_key: &[u8]) -> Option<ShardKey> {
    if shard_key.len() != 35 {
        return None;
    }
    let mut l1 = [0u8; 3];
    let mut l2 = [0u8; 32];
    l1.copy_from_slice(&shard_key[..3]);
    l2.copy_from_slice(&shard_key[3..]);
    Some(ShardKey { l1, l2 })
}

/// Returns `None` only for a malformed `shard_key`. Empty/missing nodes
/// contribute a 64-byte zero commitment and 0 size.
pub fn get_app_shard_metadata(
    crdt: &HypergraphCrdt,
    shard: &ShardInfo,
) -> Option<AppShardMetadata> {
    let typed_key = shard_key_from_bytes(&shard.shard_key)?;
    let full_prefix = build_app_shard_full_prefix(&typed_key.l2, &shard.prefix);

    let metas = match crdt.phase_set_metadata_at_path(&typed_key, &full_prefix) {
        Ok(m) => m,
        Err(_) => [None, None, None, None],
    };

    let zero64 = || vec![0u8; 64];
    let unwrap_commitment = |m: &Option<NodeMetadata>| -> Vec<u8> {
        match m {
            Some(meta) if meta.commitment.len() == 64 => meta.commitment.clone(),
            _ => zero64(),
        }
    };

    let commitments: [Vec<u8>; 4] = [
        unwrap_commitment(&metas[0]),
        unwrap_commitment(&metas[1]),
        unwrap_commitment(&metas[2]),
        unwrap_commitment(&metas[3]),
    ];

    // `size` and `data_shards` come from vertex_adds only.
    let (size_bytes, data_shards) = match &metas[0] {
        Some(meta) => {
            let bytes = if meta.size.is_zero() {
                Vec::new()
            } else {
                let (_, b) = meta.size.to_bytes_be();
                b
            };
            (bytes, meta.leaf_count)
        }
        None => (Vec::new(), 0u64),
    };

    Some(AppShardMetadata {
        prefix: shard.prefix.clone(),
        size: size_bytes,
        data_shards,
        commitments,
    })
}

/// Maximum bytes per storage leaf (≤1 GiB — the SDR/KZG sweet spot). A leaf is a
/// maximal sub-shard prefix whose committed subtree size does not exceed this.
pub const LEAF_MAX_BYTES: u64 = 1 << 30;

/// The 6-bit-nibble branching factor of the shard vector-commitment tree.
pub const SHARD_TREE_BRANCH: u32 = 64;

/// Partition a shard subtree into storage leaves: the set of maximal prefixes
/// (under `base`) whose committed subtree size is `≤ leaf_max_bytes`. Pure +
/// deterministic over a `size_of(prefix) -> bytes` oracle (`0` = no data at that
/// prefix), so it's identical on every node given the same committed state.
///
/// Descends only into prefixes that still exceed the cap and have data; a node
/// that exceeds the cap but has no children (an indivisible oversized vertex) is
/// emitted as its own leaf. `max_depth` bounds recursion.
pub fn partition_leaves<F: Fn(&[u32]) -> u64>(
    base: &[u32],
    leaf_max_bytes: u64,
    branch_factor: u32,
    max_depth: usize,
    size_of: &F,
) -> Vec<Vec<u32>> {
    fn rec<F: Fn(&[u32]) -> u64>(
        prefix: Vec<u32>,
        cap: u64,
        bf: u32,
        depth_left: usize,
        size_of: &F,
        out: &mut Vec<Vec<u32>>,
    ) {
        let sz = size_of(&prefix);
        if sz == 0 {
            return; // no data under this prefix
        }
        if sz <= cap || depth_left == 0 {
            out.push(prefix);
            return;
        }
        let mut any_child = false;
        for nib in 0..bf {
            let mut child = prefix.clone();
            child.push(nib);
            if size_of(&child) > 0 {
                any_child = true;
                rec(child, cap, bf, depth_left - 1, size_of, out);
            }
        }
        if !any_child {
            // Oversized but indivisible (no children) — can't split further.
            out.push(prefix);
        }
    }
    let mut out = Vec::new();
    rec(base.to_vec(), leaf_max_bytes, branch_factor, max_depth, size_of, &mut out);
    out
}

/// Encode a shard's storage leaves for a confirm/epoch boundary. For each leaf
/// prefix, fetches the leaf's canonical data (`leaf_data_for(prefix)`),
/// SDR-encodes it into the member's unique replica, and commits it. Returns the
/// [`ConfirmLeafRoots`] payload to fold into the `ProverConfirm` (so the roots
/// are registered + authenticated) plus the per-leaf `(prefix, replica)` bytes
/// for the worker to persist (and later answer per-frame openings from).
///
/// Pure over the `leaf_data_for` oracle so it's testable independent of the
/// CRDT subtree read; the integration supplies the real leaf bytes. Requires
/// `bls48581::init()`.
#[allow(clippy::type_complexity)]
pub fn compute_confirm_leaf_roots<F: Fn(&[u32]) -> Vec<u8>>(
    filter: &[u8],
    member: &[u8],
    epoch: u64,
    leaf_prefixes: &[Vec<u32>],
    block_poly_size: u64,
    params: &quil_crypto::sdr::SdrParams,
    leaf_data_for: &F,
) -> (
    quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots,
    Vec<(Vec<u32>, Vec<u8>)>,
) {
    use quil_execution::global_intrinsic::leaf_id_bytes;
    use quil_execution::global_intrinsic::leaf_root_registration::{
        ConfirmLeafRoots, LeafRootEntry,
    };

    let mut entries = Vec::with_capacity(leaf_prefixes.len());
    let mut replicas = Vec::with_capacity(leaf_prefixes.len());
    for prefix in leaf_prefixes {
        let leaf_id = leaf_id_bytes(filter, prefix);
        let data = leaf_data_for(prefix);
        let (replica, leaf) = quil_crypto::sdr::build_leaf_replica(
            &data, member, &leaf_id, epoch, block_poly_size, params,
        );
        entries.push(LeafRootEntry {
            prefix: prefix.clone(),
            leaf_root: leaf.root.clone(),
            num_blocks: leaf.block_commitments().len() as u64,
        });
        replicas.push((prefix.clone(), replica));
    }
    (ConfirmLeafRoots { filter: filter.to_vec(), entries }, replicas)
}

/// Real `leaf_data_for` oracle: the canonical, member-INDEPENDENT byte string
/// for the storage leaf at `relative_prefix` under shard `filter`. The header
/// (`VERSION(0x01) || filter || relative_prefix`) binds the leaf identity so a
/// replica can't be replayed for a different leaf; the body is the committed
/// 4-phase-set subtree at the absolute path `get_full_path(l2) ++ relative_prefix`
/// (`HypergraphCrdt::serialize_phase_subtrees`). Feeds `compute_confirm_leaf_roots`
/// and the per-frame opening producer — wrap it in a `Fn(&[u32]) -> Vec<u8>` closure
/// at the call site. See memory `porep-leaf-data-canonical-spec`.
///
/// CONSENSUS-CRITICAL: every member covering the leaf must produce identical
/// bytes. Do not change this encoding after storage-epoch activation without a
/// network fork. Reads committed CRDT state — call at a commit boundary.
pub fn leaf_data_for(
    crdt: &HypergraphCrdt,
    filter: &[u8],
    shard_key: &ShardKey,
    relative_prefix: &[u32],
) -> quil_types::error::Result<Vec<u8>> {
    const VERSION: u8 = 0x01;
    let mut out: Vec<u8> = Vec::new();
    out.push(VERSION);
    out.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    out.extend_from_slice(filter);
    out.extend_from_slice(&(relative_prefix.len() as u16).to_be_bytes());
    for &p in relative_prefix {
        out.extend_from_slice(&p.to_be_bytes());
    }
    let full_path = build_app_shard_full_prefix(&shard_key.l2, relative_prefix);
    let body = crdt.serialize_phase_subtrees(shard_key, &full_path)?;
    out.extend_from_slice(&body);
    Ok(out)
}

/// Worker confirm / epoch-boundary hook (PoRep wiring E). For each shard
/// `filter` the prover is confirming, partition its committed subtree into
/// storage leaves, SDR-encode each into the member's UNIQUE replica, register
/// the leaf roots, and persist the replicas to `replica_store` (keyed by
/// `(epoch, leaf_id)`) so the per-frame producer can answer openings. Returns
/// the per-shard [`ConfirmLeafRoots`] to fold into the ProverConfirm via
/// [`crate::provers::actions::build_confirm_bundle_with_leaf_roots`].
///
/// Reads committed CRDT state — call at a commit boundary. Leaf data is fetched
/// fallibly up front (so a store error aborts rather than silently encoding an
/// empty leaf), then encoded through the pure `compute_confirm_leaf_roots`.
pub fn compute_storage_confirm(
    crdt: &HypergraphCrdt,
    replica_store: &quil_store::replica_store::ReplicaStore,
    filters: &[Vec<u8>],
    member: &[u8],
    epoch: u64,
    block_poly_size: u64,
    params: &quil_crypto::sdr::SdrParams,
) -> quil_types::error::Result<
    Vec<quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots>,
> {
    use quil_execution::global_intrinsic::leaf_id_bytes;
    let mut all = Vec::with_capacity(filters.len());
    for filter in filters {
        // 35-byte shard key: L1 (3-byte bloom) ++ L2 (the filter address).
        let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(filter, 256, 3);
        let mut shard_key_bytes = Vec::with_capacity(3 + filter.len());
        shard_key_bytes.extend_from_slice(&l1);
        shard_key_bytes.extend_from_slice(filter);
        let Some(typed) = shard_key_from_bytes(&shard_key_bytes) else {
            continue;
        };

        let prefixes = partition_shard_leaves(crdt, &shard_key_bytes, &[]);
        if prefixes.is_empty() {
            // Empty shard: nothing to attest, register an empty set so the
            // confirm still records (epoch, filter) coverage.
            all.push(
                quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots {
                    filter: filter.clone(),
                    entries: Vec::new(),
                },
            );
            continue;
        }

        // Fetch every leaf's canonical data up front (fallible), then encode
        // through the pure oracle (a map lookup) so errors propagate.
        let mut data_map: std::collections::HashMap<Vec<u32>, Vec<u8>> =
            std::collections::HashMap::with_capacity(prefixes.len());
        for p in &prefixes {
            data_map.insert(p.clone(), leaf_data_for(crdt, filter, &typed, p)?);
        }
        let oracle = |p: &[u32]| -> Vec<u8> { data_map.get(p).cloned().unwrap_or_default() };

        let (groups, replicas) = compute_confirm_leaf_roots(
            filter, member, epoch, &prefixes, block_poly_size, params, &oracle,
        );
        for (prefix, replica) in &replicas {
            let lid = leaf_id_bytes(filter, prefix);
            replica_store.put(epoch, &lid, replica)?;
        }
        all.push(groups);
    }
    Ok(all)
}

/// Per-frame producer (PoRep wiring E, part A): build ONE member's possession
/// openings for a frame, from the replicas it persisted at confirm time. For
/// each covered `(filter, prefixes)` it loads the leaf's replica from
/// `replica_store` at `(epoch, leaf_id)`, derives the `(block, point)` challenge
/// for each of `queries` queries from the beacon `rho_n`, and builds the
/// opening. The aggregator assembles these (plus the other committee members'
/// openings, collected via votes) into the frame's `StorageAttestation` with
/// [`quil_crypto::porep::build_frame_storage_attestation`].
///
/// `rho_n = derive_storage_beacon(global_frame_number, global_output)` of the
/// global frame this app-shard frame is anchored to — so the challenge is
/// unpredictable until that VDF output is revealed. Leaves whose replica is
/// missing (never confirmed / evicted) are skipped. Requires `quil_crypto::init()`.
#[allow(clippy::type_complexity)]
pub fn build_member_frame_openings(
    replica_store: &quil_store::replica_store::ReplicaStore,
    covered: &[(Vec<u8>, Vec<Vec<u32>>)],
    member: &[u8],
    epoch: u64,
    rho_n: &[u8],
    poly_size: u64,
    queries: u32,
) -> quil_types::error::Result<Vec<quil_crypto::porep::StorageOpening>> {
    use quil_execution::global_intrinsic::leaf_id_bytes;
    let mut openings = Vec::new();
    for (filter, prefixes) in covered {
        for prefix in prefixes {
            let lid = leaf_id_bytes(filter, prefix);
            let Some(replica) = replica_store.get(epoch, &lid)? else {
                continue;
            };
            let leaf = quil_crypto::sdr::commit_leaf(&replica, poly_size);
            for q in 0..queries {
                openings.push(quil_crypto::porep::build_storage_opening(
                    &replica, &leaf, &lid, epoch, member, q, rho_n, poly_size,
                ));
            }
        }
    }
    Ok(openings)
}

/// Build the PoRep openings blob a member attaches to its app-shard VOTE: the
/// serialized `StorageAttestation` over this member's openings for every leaf it
/// covers on `filter`, at the per-frame beacon `rho_n`. The vote-aggregator
/// collects these from the rank's votes and assembles the frame attestation
/// (`build_frame_storage_attestation`) when the QC forms. Reads the member's
/// persisted replicas from `replica_store`; returns EMPTY bytes when the member
/// covers no leaves with stored replicas (a not-yet-confirmed member attaches
/// nothing, and the vote serializes byte-identically to the legacy form).
pub fn build_vote_openings(
    crdt: &HypergraphCrdt,
    replica_store: &quil_store::replica_store::ReplicaStore,
    filter: &[u8],
    member: &[u8],
    epoch: u64,
    rho_n: &[u8],
) -> quil_types::error::Result<Vec<u8>> {
    let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(filter, 256, 3);
    let mut shard_key = Vec::with_capacity(3 + filter.len());
    shard_key.extend_from_slice(&l1);
    shard_key.extend_from_slice(filter);
    let prefixes = partition_shard_leaves(crdt, &shard_key, &[]);
    if prefixes.is_empty() {
        return Ok(Vec::new());
    }
    let covered = vec![(filter.to_vec(), prefixes)];
    let openings = build_member_frame_openings(
        replica_store,
        &covered,
        member,
        epoch,
        rho_n,
        quil_types::consensus::STORAGE_BLOCK_POLY_SIZE,
        quil_types::consensus::STORAGE_QUERIES_PER_LEAF,
    )?;
    if openings.is_empty() {
        return Ok(Vec::new());
    }
    let att = quil_types::proto::global::StorageAttestation {
        openings: openings.iter().map(quil_crypto::porep::StorageOpening::to_proto).collect(),
    };
    Ok(prost::Message::encode_to_vec(&att))
}

/// Decode the openings a peer attached to its vote (inverse of
/// [`build_vote_openings`]). Empty / malformed blob → no openings.
pub fn decode_vote_openings(blob: &[u8]) -> Vec<quil_crypto::porep::StorageOpening> {
    if blob.is_empty() {
        return Vec::new();
    }
    match <quil_types::proto::global::StorageAttestation as prost::Message>::decode(blob) {
        Ok(att) => att
            .openings
            .iter()
            .map(quil_crypto::porep::StorageOpening::from_proto)
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Partition a shard's subtree into storage-leaf prefixes using the live CRDT's
/// committed size metadata as the oracle. `shard_key` is the 35-byte
/// `L1 ++ L2`. The returned prefixes are the leaves the member must encode +
/// register this epoch (`leaf_id = leaf_id_bytes(filter, prefix)`).
pub fn partition_shard_leaves(
    crdt: &HypergraphCrdt,
    shard_key: &[u8],
    base_prefix: &[u32],
) -> Vec<Vec<u32>> {
    use num_traits::ToPrimitive;
    let size_of = |prefix: &[u32]| -> u64 {
        let shard = ShardInfo {
            shard_key: shard_key.to_vec(),
            prefix: prefix.to_vec(),
            size: Vec::new(),
            data_shards: 0,
            commitment: Vec::new(),
        };
        match get_app_shard_metadata(crdt, &shard) {
            Some(md) => md.size_bigint().to_u64().unwrap_or(u64::MAX),
            None => 0,
        }
    };
    partition_leaves(base_prefix, LEAF_MAX_BYTES, SHARD_TREE_BRANCH, 32, &size_of)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use quil_hypergraph::Location;
    use quil_hypergraph::testing::{MemStore, StubProver};
    use quil_types::crypto::InclusionProver;
    use quil_types::store::HypergraphStore;

    fn make_crdt() -> Arc<HypergraphCrdt> {
        let store: Arc<dyn HypergraphStore> = Arc::new(MemStore::new());
        let prover: Arc<dyn InclusionProver> = Arc::new(StubProver);
        Arc::new(HypergraphCrdt::new(store, prover))
    }

    #[test]
    fn partition_single_leaf_when_under_cap() {
        // Root fits under the cap → one leaf (the root itself).
        let size_of = |p: &[u32]| if p.is_empty() { 500u64 } else { 0 };
        let leaves = partition_leaves(&[], 1000, 64, 8, &size_of);
        assert_eq!(leaves, vec![Vec::<u32>::new()]);
    }

    #[test]
    fn partition_descends_until_under_cap() {
        use std::collections::HashMap;
        // Root = 3000 (> cap 1000); children 0,1,2 each 1000 (≤ cap).
        let mut m: HashMap<Vec<u32>, u64> = HashMap::new();
        m.insert(vec![], 3000);
        m.insert(vec![0], 1000);
        m.insert(vec![1], 1000);
        m.insert(vec![2], 1000);
        let size_of = |p: &[u32]| *m.get(p).unwrap_or(&0);
        let mut leaves = partition_leaves(&[], 1000, 64, 8, &size_of);
        leaves.sort();
        assert_eq!(leaves, vec![vec![0], vec![1], vec![2]]);
    }

    #[test]
    fn partition_recurses_multiple_levels() {
        use std::collections::HashMap;
        // Root 5000 → child [0]=5000 → [0,0]=2000? still >cap → split again.
        let mut m: HashMap<Vec<u32>, u64> = HashMap::new();
        m.insert(vec![], 5000);
        m.insert(vec![0], 5000);
        m.insert(vec![0, 0], 800); // leaf
        m.insert(vec![0, 1], 900); // leaf
        let size_of = |p: &[u32]| *m.get(p).unwrap_or(&0);
        let mut leaves = partition_leaves(&[], 1000, 64, 8, &size_of);
        leaves.sort();
        assert_eq!(leaves, vec![vec![0, 0], vec![0, 1]]);
    }

    #[test]
    fn partition_emits_indivisible_oversized_node() {
        // A node over the cap with no children can't be split — emit it.
        let size_of = |p: &[u32]| if p.is_empty() { 9999u64 } else { 0 };
        let leaves = partition_leaves(&[], 1000, 64, 8, &size_of);
        assert_eq!(leaves, vec![Vec::<u32>::new()]);
    }

    #[test]
    fn partition_empty_shard_yields_nothing() {
        let size_of = |_p: &[u32]| 0u64;
        let leaves = partition_leaves(&[], 1000, 64, 8, &size_of);
        assert!(leaves.is_empty());
    }

    #[test]
    fn confirm_leaf_roots_produce_verifiable_openings() {
        use std::collections::HashMap;
        use quil_execution::global_intrinsic::leaf_id_bytes;
        quil_crypto::init();
        let poly_size = 16u64;
        let params = quil_crypto::sdr::SdrParams::default();
        let filter = vec![0xABu8; 32];
        let member = vec![0x9Au8; 32];
        let epoch = 4u64;
        let rho_n = [0x5Cu8; 32];
        let bitmask = [0x03u8];
        let frame = 11u64;
        let prefixes = vec![vec![0u32], vec![1u32]];

        // 4 blocks of distinct leaf data per prefix.
        let leaf_data_for = |p: &[u32]| -> Vec<u8> {
            let seed = p[0] as u8;
            let nodes = 4 * poly_size as usize;
            (0..nodes * 32).map(|i| (i as u8).wrapping_add(seed)).collect()
        };

        // E4: worker builds the confirm leaf roots + replicas.
        let (groups, replicas) = compute_confirm_leaf_roots(
            &filter, &member, epoch, &prefixes, poly_size, &params, &leaf_data_for,
        );
        assert_eq!(groups.entries.len(), 2);
        assert_eq!(groups.filter, filter);

        // The registry the verifier would build from those (registered) roots.
        let mut reg: HashMap<(Vec<u8>, Vec<u8>), (Vec<u8>, u64, u64)> = HashMap::new();
        for e in &groups.entries {
            let lid = leaf_id_bytes(&filter, &e.prefix);
            reg.insert((member.clone(), lid), (e.leaf_root.clone(), e.num_blocks, epoch));
        }

        // E5: per-frame openings built from the stored replicas.
        let mut openings = Vec::new();
        for (prefix, replica) in &replicas {
            let lid = leaf_id_bytes(&filter, prefix);
            let leaf = quil_crypto::sdr::commit_leaf(replica, poly_size);
            for q in 0..2u32 {
                openings.push(quil_crypto::porep::build_storage_opening(
                    replica, &leaf, &lid, epoch, &member, q, &rho_n, poly_size,
                ));
            }
        }
        let (att, root) = quil_crypto::porep::build_frame_storage_attestation(
            &openings, frame, &rho_n, &bitmask, poly_size,
        );

        // C: the verifier accepts against the registered roots for this epoch.
        let good = |m: &[u8], l: &[u8]| reg.get(&(m.to_vec(), l.to_vec())).cloned();
        assert!(
            quil_crypto::porep::verify_frame_storage_attestation_registered(
                &root, &att, frame, &rho_n, &bitmask, poly_size, epoch, good,
            ),
            "worker-built confirm roots + replicas must yield verifiable openings"
        );
    }

    #[test]
    fn real_crdt_leaf_data_produces_verifiable_openings() {
        use std::collections::HashMap;
        use quil_execution::global_intrinsic::leaf_id_bytes;
        use quil_hypergraph::Location;
        use quil_hypergraph::addressing::shard_key_for_location;
        quil_crypto::init();

        // A real shard with committed vertices.
        let crdt = make_crdt();
        let app = 0x77u8;
        let filter = vec![app; 32]; // app-shard filter == app_address
        for d in 0u8..3 {
            let loc = Location { app_address: [app; 32], data_address: [d; 32] };
            crdt.add_vertex(&loc, &vec![d.wrapping_add(1); 256]).unwrap();
        }
        crdt.commit(1).unwrap();
        let shard_key = shard_key_for_location(&Location {
            app_address: [app; 32],
            data_address: [0u8; 32],
        });

        let poly_size = 16u64;
        let params = quil_crypto::sdr::SdrParams::default();
        let member = vec![0x9Au8; 32];
        let epoch = 4u64;
        let rho_n = [0x5Cu8; 32];
        let bitmask = [0x01u8];
        let frame = 11u64;
        // One leaf = the whole shard subtree (relative prefix []).
        let prefixes = vec![Vec::<u32>::new()];

        // The REAL oracle reads the committed CRDT subtree.
        let oracle = |p: &[u32]| -> Vec<u8> {
            leaf_data_for(&crdt, &filter, &shard_key, p).expect("leaf_data_for")
        };
        // Deterministic + carries the committed body (not just the header).
        assert_eq!(oracle(&[]), oracle(&[]));
        assert!(
            oracle(&[]).len() > 5 + filter.len(),
            "leaf data must carry header + committed subtree body"
        );

        let (groups, replicas) = compute_confirm_leaf_roots(
            &filter, &member, epoch, &prefixes, poly_size, &params, &oracle,
        );
        assert_eq!(groups.entries.len(), 1);

        let mut reg: HashMap<(Vec<u8>, Vec<u8>), (Vec<u8>, u64, u64)> = HashMap::new();
        for e in &groups.entries {
            let lid = leaf_id_bytes(&filter, &e.prefix);
            reg.insert((member.clone(), lid), (e.leaf_root.clone(), e.num_blocks, epoch));
        }
        let mut openings = Vec::new();
        for (prefix, replica) in &replicas {
            let lid = leaf_id_bytes(&filter, prefix);
            let leaf = quil_crypto::sdr::commit_leaf(replica, poly_size);
            for q in 0..2u32 {
                openings.push(quil_crypto::porep::build_storage_opening(
                    replica, &leaf, &lid, epoch, &member, q, &rho_n, poly_size,
                ));
            }
        }
        let (att, root) = quil_crypto::porep::build_frame_storage_attestation(
            &openings, frame, &rho_n, &bitmask, poly_size,
        );
        let good = |m: &[u8], l: &[u8]| reg.get(&(m.to_vec(), l.to_vec())).cloned();
        assert!(
            quil_crypto::porep::verify_frame_storage_attestation_registered(
                &root, &att, frame, &rho_n, &bitmask, poly_size, epoch, good,
            ),
            "real-CRDT leaf data must yield verifiable storage openings"
        );
    }

    #[test]
    fn compute_storage_confirm_persists_replicas_and_folds_roots() {
        use quil_execution::global_intrinsic::leaf_id_bytes;
        use quil_hypergraph::Location;
        quil_crypto::init();

        let crdt = make_crdt();
        let app = 0x33u8;
        let filter = vec![app; 32];
        for d in 0u8..3 {
            crdt.add_vertex(
                &Location { app_address: [app; 32], data_address: [d; 32] },
                &vec![d.wrapping_add(1); 256],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();

        let replica_store = quil_store::replica_store::ReplicaStore::new(Arc::new(
            quil_store::RocksDb::open_in_memory().unwrap(),
        ));
        let member = vec![0xC1u8; 32];
        let epoch = 7u64;
        let poly_size = 16u64;
        let params = quil_crypto::sdr::SdrParams::default();

        let roots = compute_storage_confirm(
            &crdt,
            &replica_store,
            std::slice::from_ref(&filter),
            &member,
            epoch,
            poly_size,
            &params,
        )
        .expect("compute_storage_confirm");

        assert_eq!(roots.len(), 1, "one shard confirmed");
        assert_eq!(roots[0].filter, filter);
        assert!(
            !roots[0].entries.is_empty(),
            "a shard with committed data must register at least one leaf root"
        );

        // Every registered leaf's replica was persisted under (epoch, leaf_id)
        // and its commitment matches the registered root — the producer can
        // later answer openings from exactly these bytes.
        for e in &roots[0].entries {
            let lid = leaf_id_bytes(&filter, &e.prefix);
            let replica = replica_store
                .get(epoch, &lid)
                .unwrap()
                .expect("replica persisted at (epoch, leaf_id)");
            let leaf = quil_crypto::sdr::commit_leaf(&replica, poly_size);
            assert_eq!(
                leaf.root, e.leaf_root,
                "registered leaf_root must equal the persisted replica's commitment"
            );
            assert_eq!(leaf.block_commitments().len() as u64, e.num_blocks);
        }
    }

    #[test]
    fn member_frame_openings_verify_against_confirm_roots() {
        use std::collections::HashMap;
        use quil_execution::global_intrinsic::leaf_id_bytes;
        use quil_hypergraph::Location;
        quil_crypto::init();

        // Confirm: persist replicas + register roots.
        let crdt = make_crdt();
        let app = 0x44u8;
        let filter = vec![app; 32];
        for d in 0u8..3 {
            crdt.add_vertex(
                &Location { app_address: [app; 32], data_address: [d; 32] },
                &vec![d.wrapping_add(1); 256],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let replica_store = quil_store::replica_store::ReplicaStore::new(Arc::new(
            quil_store::RocksDb::open_in_memory().unwrap(),
        ));
        let member = vec![0xD2u8; 32];
        let epoch = 5u64;
        let poly_size = 16u64;
        let params = quil_crypto::sdr::SdrParams::default();
        let roots = compute_storage_confirm(
            &crdt,
            &replica_store,
            std::slice::from_ref(&filter),
            &member,
            epoch,
            poly_size,
            &params,
        )
        .unwrap();

        let mut reg: HashMap<(Vec<u8>, Vec<u8>), (Vec<u8>, u64, u64)> = HashMap::new();
        let mut prefixes: Vec<Vec<u32>> = Vec::new();
        for e in &roots[0].entries {
            let lid = leaf_id_bytes(&filter, &e.prefix);
            reg.insert((member.clone(), lid), (e.leaf_root.clone(), e.num_blocks, epoch));
            prefixes.push(e.prefix.clone());
        }

        // Producer: build this member's openings for a frame anchored to a
        // global frame (beacon from its VDF output).
        let rho_n = quil_crypto::porep::derive_storage_beacon(42, &vec![0x9u8; 516]);
        let covered = vec![(filter.clone(), prefixes)];
        let openings = build_member_frame_openings(
            &replica_store, &covered, &member, epoch, &rho_n, poly_size, 2,
        )
        .unwrap();
        assert!(!openings.is_empty(), "covered leaves must yield openings");

        // Single-member committee → bitmask [0x01]. The aggregated frame
        // attestation must verify against the confirm-registered roots.
        let frame = 100u64;
        let bitmask = [0x01u8];
        let (att, root) = quil_crypto::porep::build_frame_storage_attestation(
            &openings, frame, &rho_n, &bitmask, poly_size,
        );
        let good = |m: &[u8], l: &[u8]| reg.get(&(m.to_vec(), l.to_vec())).cloned();
        assert!(
            quil_crypto::porep::verify_frame_storage_attestation_registered(
                &root, &att, frame, &rho_n, &bitmask, poly_size, epoch, good,
            ),
            "producer openings from persisted replicas must verify against confirm roots"
        );
    }

    #[test]
    fn vote_openings_roundtrip_and_verify() {
        use std::collections::HashMap;
        use quil_execution::global_intrinsic::leaf_id_bytes;
        use quil_hypergraph::Location;
        quil_crypto::init();

        let crdt = make_crdt();
        let app = 0x88u8;
        let filter = vec![app; 32];
        for d in 0u8..3 {
            crdt.add_vertex(
                &Location { app_address: [app; 32], data_address: [d; 32] },
                &vec![d.wrapping_add(1); 256],
            )
            .unwrap();
        }
        crdt.commit(1).unwrap();
        let replica_store = quil_store::replica_store::ReplicaStore::new(Arc::new(
            quil_store::RocksDb::open_in_memory().unwrap(),
        ));
        let member = vec![0xE3u8; 32];
        let epoch = 6u64;
        let poly_size = quil_types::consensus::STORAGE_BLOCK_POLY_SIZE;
        let params = quil_crypto::sdr::SdrParams::default();

        // Confirm: persist replicas + register roots (production constants).
        let roots = compute_storage_confirm(
            &crdt, &replica_store, std::slice::from_ref(&filter), &member, epoch, poly_size, &params,
        )
        .unwrap();
        let mut reg: HashMap<(Vec<u8>, Vec<u8>), (Vec<u8>, u64, u64)> = HashMap::new();
        for e in &roots[0].entries {
            let lid = leaf_id_bytes(&filter, &e.prefix);
            reg.insert((member.clone(), lid), (e.leaf_root.clone(), e.num_blocks, epoch));
        }

        // Producer builds the vote blob; aggregator decodes it.
        let rho_n = quil_crypto::porep::derive_storage_beacon(42, &vec![0x9u8; 516]);
        let blob = build_vote_openings(&crdt, &replica_store, &filter, &member, epoch, &rho_n).unwrap();
        assert!(!blob.is_empty(), "a covered member must attach openings");
        let openings = decode_vote_openings(&blob);
        assert!(!openings.is_empty());

        // Aggregator assembles the frame attestation (single-member committee).
        let (att, root) = quil_crypto::porep::build_frame_storage_attestation(
            &openings, 100, &rho_n, &[0x01u8], poly_size,
        );
        let good = |m: &[u8], l: &[u8]| reg.get(&(m.to_vec(), l.to_vec())).cloned();
        assert!(
            quil_crypto::porep::verify_frame_storage_attestation_registered(
                &root, &att, 100, &rho_n, &[0x01u8], poly_size, epoch, good,
            ),
            "decoded vote openings must assemble into a verifiable frame attestation"
        );
    }

    #[test]
    fn shard_key_from_bytes_round_trip() {
        let mut buf = vec![0u8; 35];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(1);
        }
        let key = shard_key_from_bytes(&buf).expect("valid 35-byte key");
        assert_eq!(&key.l1[..], &buf[..3]);
        assert_eq!(&key.l2[..], &buf[3..]);
    }

    #[test]
    fn shard_key_from_bytes_rejects_bad_length() {
        assert!(shard_key_from_bytes(&[]).is_none());
        assert!(shard_key_from_bytes(&vec![0u8; 34]).is_none());
        assert!(shard_key_from_bytes(&vec![0u8; 36]).is_none());
    }

    #[test]
    fn build_full_prefix_concats_l2_path_and_shard_prefix() {
        // L2 = [0xAB] => 2 nibbles {42, 48} per `get_full_path` test
        // (lib.rs::full_path_single_byte_ab_has_two_nibbles).
        let l2 = vec![0xABu8];
        let prefix = vec![5u32, 12u32];
        let path = build_app_shard_full_prefix(&l2, &prefix);
        assert_eq!(path, vec![42i32, 48, 5, 12]);
    }

    #[test]
    fn empty_shard_returns_zero_metadata() {
        let crdt = make_crdt();
        let mut shard_key = vec![0u8; 35];
        shard_key[0] = 0x01;
        let shard = ShardInfo {
            shard_key,
            prefix: vec![],
            size: vec![],
            data_shards: 0,
            commitment: vec![],
        };
        let meta = get_app_shard_metadata(&crdt, &shard).expect("valid key");
        assert_eq!(meta.size, Vec::<u8>::new());
        assert_eq!(meta.data_shards, 0);
        for c in &meta.commitments {
            assert_eq!(c, &vec![0u8; 64]);
        }
    }

    #[test]
    fn shard_with_vertex_reports_nonzero_metadata() {
        let crdt = make_crdt();

        let mut app_address = [0xCDu8; 32];
        app_address[0] = 0xAB;
        let location = Location {
            app_address,
            data_address: [0x11u8; 32],
        };
        let payload = b"some-vertex-payload";
        crdt.add_vertex(&location, payload).unwrap();

        let typed = quil_hypergraph::addressing::shard_key_for_location(&location);
        let mut shard_key_bytes = Vec::with_capacity(35);
        shard_key_bytes.extend_from_slice(&typed.l1);
        shard_key_bytes.extend_from_slice(&typed.l2);

        let shard = ShardInfo {
            shard_key: shard_key_bytes,
            prefix: vec![],
            size: vec![],
            data_shards: 0,
            commitment: vec![],
        };

        let meta = get_app_shard_metadata(&crdt, &shard).expect("valid key");
        assert_eq!(meta.commitments.len(), 4);
        for c in &meta.commitments {
            assert_eq!(c.len(), 64, "phase commitment must be 64 bytes");
        }
        assert_eq!(meta.size_bigint(), num_bigint::BigInt::from(payload.len()));
        assert_eq!(meta.data_shards, 1);
    }
}

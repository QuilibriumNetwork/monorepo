//! Stage-3 integration glue for the per-token SIS coin accumulator (the "shadow
//! tree"). This layer connects the pure [`CoinAccumulator`] to committed
//! hypergraph state:
//!
//! - **Build** a token's accumulator from its committed coin vertices, in a
//! canonical order all nodes agree on ([`build_from_coins`]).
//! - **Commit** the `(depth ‖ root)` record to a reserved per-domain vertex so it
//! rides `state_roots[0]` — no frame-header/validator change ([`write_root`]).
//! - **Read** the committed root back for spend verification ([`read_root`]).
//!
//! # Keying — one tree per token domain
//!
//! `ShardKey` derives from `app_address = domain` only, so a domain is exactly
//! one shard: each token gets a single accumulator over *all* its coins (full-set
//! anonymity, no per-shard fragmentation). A global cross-token tree buys nothing
//! (value is per-token and the domain is public), so per-token is the maximum.
//!
//! # Canonical order (consensus-critical)
//!
//! Leaves are inserted in **ascending coin-address order** — the deterministic
//! order every node's committed-state scan yields. Indices are therefore not
//! creation-stable, but that's fine: a wallet rebuilds its coin's index +
//! auth-path against a specific committed root at spend time (the root-history
//! model), and the key image prevents double-spend regardless of which historical
//! root was used.

use quil_tries::{deserialize_go_tree, VectorCommitmentTree};
use quil_types::error::{QuilError, Result};

use super::coin_accumulator::CoinAccumulator;
use super::materialize::coin_type_hash;
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};

/// Coin-vertex field keys — must match the lattice write path
/// `materialize::create_lattice_coin_vertex_tree` (P@[1<<2], cv@[2<<2]).
/// (The retired decaf `create_coin_vertex_tree` used the opposite slots; the
/// accumulator reads the lattice layout, since only lattice coins are spendable
/// through the membership path.)
const COIN_KEY_ONE_TIME_KEY: [u8; 1] = [1u8 << 2]; // P (one-time key)
const COIN_KEY_COMMITMENT: [u8; 1] = [2u8 << 2]; // cv (value commitment)
const COIN_KEY_MEMO: [u8; 1] = [3u8 << 2]; // opaque recipient memo (optional)
const COIN_KEY_TYPE: [u8; 32] = [0xFFu8; 32];

/// Reserved per-domain address holding the committed accumulator root record.
/// `[0xFF;31] ‖ 0xFE` is **out of the Poseidon field**, so it can never collide
/// with a coin address (`poseidon(...)`), a spent marker (`poseidon(vk)`), or the
/// metadata vertex (`[0xFF;32]`).
pub const ACC_ROOT_ADDRESS: [u8; 32] = {
    let mut a = [0xFFu8; 32];
    a[31] = 0xFE;
    a
};

/// Decode a coin vertex blob and, if it is a `coin:Coin` for `domain`, return its
/// `(one_time_key P, commitment cv)` field bytes (each a wire-encoded node).
/// Returns `Ok(None)` for non-coin vertices (metadata, pending, spent markers).
pub fn extract_coin_leaf(blob: &[u8], domain: &[u8]) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let root = match deserialize_go_tree(blob) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    let tree = VectorCommitmentTree { root };
    // Filter on the type marker VALUE — not merely "has a [0xFF;32] leaf" — so
    // metadata/pending/spent vertices are excluded.
    let want_type = coin_type_hash(domain)?;
    match tree.get(&COIN_KEY_TYPE) {
        Some(t) if t == want_type.as_slice() => {}
        _ => return Ok(None),
    }
    let p = tree
        .get(&COIN_KEY_ONE_TIME_KEY)
        .ok_or_else(|| QuilError::Internal("shadow-acc: coin missing one_time_key".into()))?
        .to_vec();
    let cv = tree
        .get(&COIN_KEY_COMMITMENT)
        .ok_or_else(|| QuilError::Internal("shadow-acc: coin missing commitment".into()))?
        .to_vec();
    Ok(Some((p, cv)))
}

/// Build a token's [`CoinAccumulator`] from its coin vertices. `coins` yields
/// `(coin_address, vertex_blob)` for every vertex in the domain's committed
/// vertex-adds set (non-coins are filtered out). Leaves are inserted in ascending
/// address order — the canonical, all-nodes-agree order.
pub fn build_from_coins<I>(domain: &[u8], coins: I) -> Result<CoinAccumulator>
where
    I: IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
{
    // Collect (address, P, cv) for coins only, then sort by address.
    let mut leaves: Vec<([u8; 32], Vec<u8>, Vec<u8>)> = Vec::new();
    for (addr, blob) in coins {
        if addr.as_slice() == ACC_ROOT_ADDRESS || addr.as_slice() == &[0xFFu8; 32] {
            continue;
        }
        if let Some((p, cv)) = extract_coin_leaf(&blob, domain)? {
            let mut a = [0u8; 32];
            let n = addr.len().min(32);
            a[..n].copy_from_slice(&addr[..n]);
            leaves.push((a, p, cv));
        }
    }
    leaves.sort_by(|x, y| x.0.cmp(&y.0));

    let mut acc = CoinAccumulator::new();
    for (_, p, cv) in &leaves {
        acc.insert_coin(p, cv)?;
    }
    Ok(acc)
}

/// Like [`extract_coin_leaf`] but also returns the optional memo blob, for
/// wallet coin enumeration/scanning.
pub fn extract_coin_leaf_full(
    blob: &[u8],
    domain: &[u8],
) -> Result<Option<(Vec<u8>, Vec<u8>, Vec<u8>)>> {
    let root = match deserialize_go_tree(blob) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    let tree = VectorCommitmentTree { root };
    let want_type = coin_type_hash(domain)?;
    match tree.get(&COIN_KEY_TYPE) {
        Some(t) if t == want_type.as_slice() => {}
        _ => return Ok(None),
    }
    let p = tree
        .get(&COIN_KEY_ONE_TIME_KEY)
        .ok_or_else(|| QuilError::Internal("shadow-acc: coin missing one_time_key".into()))?
        .to_vec();
    let cv = tree
        .get(&COIN_KEY_COMMITMENT)
        .ok_or_else(|| QuilError::Internal("shadow-acc: coin missing commitment".into()))?
        .to_vec();
    let memo = tree.get(&COIN_KEY_MEMO).map(|m| m.to_vec()).unwrap_or_default();
    Ok(Some((p, cv, memo)))
}

/// Scan a domain's committed coins in canonical (ascending-address) order,
/// returning `(address, P, cv, memo)` per coin. The all-nodes-agree order the
/// accumulator uses.
pub fn scan_domain_coins(
    state: &HypergraphState,
    domain: &[u8],
) -> Result<Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>> {
    let mut leaves: Vec<([u8; 32], Vec<u8>, Vec<u8>, Vec<u8>)> = Vec::new();
    let mut scan_err: Option<QuilError> = None;
    state.crdt().for_each_vertex_adds_blob(domain, &mut |key, blob| {
        if scan_err.is_some() {
            return;
        }
        let addr = if key.len() >= 64 { &key[32..64] } else { &key[..] };
        if addr == ACC_ROOT_ADDRESS || addr == &[0xFFu8; 32] {
            return;
        }
        match extract_coin_leaf_full(&blob, domain) {
            Ok(Some((p, cv, memo))) => {
                let mut a = [0u8; 32];
                let n = addr.len().min(32);
                a[..n].copy_from_slice(&addr[..n]);
                leaves.push((a, p, cv, memo));
            }
            Ok(None) => {}
            Err(e) => scan_err = Some(e),
        }
    })?;
    if let Some(e) = scan_err {
        return Err(e);
    }
    leaves.sort_by(|x, y| x.0.cmp(&y.0));
    Ok(leaves
        .into_iter()
        .map(|(a, p, cv, memo)| (a.to_vec(), p, cv, memo))
        .collect())
}

/// One materialized escrow (pending) vertex, decoded from its subtree.
pub struct EscrowLeaf {
    pub address: Vec<u8>,
    pub cv: Vec<u8>,
    pub to_key: Vec<u8>,
    pub refund_key: Vec<u8>,
    pub expiration: u64,
    pub memo: Vec<u8>,
}

/// Decode an escrow (pending) vertex blob into its fields, or `None` for a
/// non-escrow vertex. Field layout mirrors `create_lattice_pending_vertex_tree`.
pub fn extract_escrow_leaf(
    blob: &[u8],
    domain: &[u8],
) -> Result<Option<(Vec<u8>, Vec<u8>, Vec<u8>, u64, Vec<u8>)>> {
    let root = deserialize_go_tree(blob)
        .map_err(|e| QuilError::Internal(format!("shadow-acc: escrow blob decode: {e}")))?;
    let tree = VectorCommitmentTree { root };
    let want_type = super::materialize::pending_type_hash(domain)?;
    match tree.get(&[0xFFu8; 32]) {
        Some(t) if t == want_type.as_slice() => {}
        _ => return Ok(None),
    }
    let getf = |k: u8| tree.get(&[k << 2]).map(|v| v.to_vec());
    let cv = getf(1).ok_or_else(|| QuilError::Internal("shadow-acc: escrow missing cv".into()))?;
    let to_key =
        getf(2).ok_or_else(|| QuilError::Internal("shadow-acc: escrow missing to_key".into()))?;
    let refund_key = getf(3)
        .ok_or_else(|| QuilError::Internal("shadow-acc: escrow missing refund_key".into()))?;
    let exp_bytes = getf(4)
        .ok_or_else(|| QuilError::Internal("shadow-acc: escrow missing expiration".into()))?;
    let expiration = u64::from_be_bytes(
        exp_bytes
            .get(..8)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| QuilError::Internal("shadow-acc: escrow bad expiration".into()))?,
    );
    let memo = getf(5).unwrap_or_default();
    Ok(Some((cv, to_key, refund_key, expiration, memo)))
}

/// Scan a domain's committed escrows (pending vertices) in canonical
/// (ascending-address) order. The node-side backing for a pending-escrow list.
pub fn scan_domain_escrows(state: &HypergraphState, domain: &[u8]) -> Result<Vec<EscrowLeaf>> {
    let mut leaves: Vec<EscrowLeaf> = Vec::new();
    let mut scan_err: Option<QuilError> = None;
    state.crdt().for_each_vertex_adds_blob(domain, &mut |key, blob| {
        if scan_err.is_some() {
            return;
        }
        match extract_escrow_leaf(&blob, domain) {
            Ok(Some((cv, to_key, refund_key, expiration, memo))) => {
                let addr = if key.len() >= 64 { &key[32..64] } else { &key[..] };
                let mut a = [0u8; 32];
                let n = addr.len().min(32);
                a[..n].copy_from_slice(&addr[..n]);
                leaves.push(EscrowLeaf {
                    address: a.to_vec(),
                    cv,
                    to_key,
                    refund_key,
                    expiration,
                    memo,
                });
            }
            Ok(None) => {}
            Err(e) => scan_err = Some(e),
        }
    })?;
    if let Some(e) = scan_err {
        return Err(e);
    }
    leaves.sort_by(|x, y| x.address.cmp(&y.address));
    Ok(leaves)
}

/// A membership witness for one coin: its canonical `leaf_index` and
/// `auth_path`, or `found = false` if the one-time key isn't in the set.
pub struct CoinWitness {
    pub one_time_key: Vec<u8>,
    pub found: bool,
    pub leaf_index: u64,
    pub auth_path: Vec<Vec<u8>>,
}

/// Build spend witnesses for the requested one-time keys against the domain's
/// current committed accumulator. Returns `(depth, root, witnesses)` — exactly
/// what a wallet feeds into `build_spend_transaction` (root/depth + per-input
/// `leaf_index`/`auth_path`). The node-side backing for the
/// `GetCoinSpendWitness` RPC.
pub fn coin_spend_witnesses(
    state: &HypergraphState,
    domain: &[u8],
    requested_otks: &[Vec<u8>],
) -> Result<(usize, Vec<u8>, Vec<CoinWitness>)> {
    let leaves = scan_domain_coins(state, domain)?;

    // Build the accumulator from the sorted leaves (index == position).
    let mut acc = CoinAccumulator::new();
    for (_, p, cv, _) in &leaves {
        acc.insert_coin(p, cv)?;
    }
    let (depth, root) = acc.root_with_depth();

    let witnesses = requested_otks
        .iter()
        .map(|otk| match leaves.iter().position(|(_, p, _, _)| p == otk) {
            Some(idx) => CoinWitness {
                one_time_key: otk.clone(),
                found: true,
                leaf_index: idx as u64,
                auth_path: acc.auth_path(idx),
            },
            None => CoinWitness {
                one_time_key: otk.clone(),
                found: false,
                leaf_index: 0,
                auth_path: Vec::new(),
            },
        })
        .collect();

    Ok((depth, root, witnesses))
}

// ── Committed root record: `depth (u32 LE) ‖ root_bytes` ─────────────────────

/// Encode the `(current_depth, root)` record committed at [`ACC_ROOT_ADDRESS`].
pub fn encode_root_record(depth: usize, root_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + root_bytes.len());
    out.extend_from_slice(&(depth as u32).to_le_bytes());
    out.extend_from_slice(root_bytes);
    out
}

/// Decode a `(depth, root_bytes)` record.
pub fn decode_root_record(rec: &[u8]) -> Result<(usize, Vec<u8>)> {
    if rec.len() < 4 {
        return Err(QuilError::InvalidArgument("shadow-acc: truncated root record".into()));
    }
    let depth = u32::from_le_bytes(rec[0..4].try_into().unwrap()) as usize;
    Ok((depth, rec[4..].to_vec()))
}

/// Commit the accumulator's current `(depth ‖ root)` to the reserved per-domain
/// vertex. Rides `state_roots[0]` — tamper-evident, synced, no wire change.
pub fn write_root(state: &HypergraphState, domain: &[u8], acc: &CoinAccumulator) -> Result<()> {
    let (depth, root) = acc.root_with_depth();
    let rec = encode_root_record(depth, &root);
    let disc = vertex_adds_discriminator()?;
    state.set(domain, &ACC_ROOT_ADDRESS, &disc, 0, rec)
}

/// The encoded `(depth ‖ root)` record for an EMPTY coin accumulator. A pre-2.1
/// legacy DB holds NO shielded/lattice coins (shielding is a post-migration op),
/// so its shadow-accumulator root is provably empty — the `--migrate-db` coin
/// pass writes THIS directly instead of a full-set scan. Encapsulates the
/// accumulator internals so the offline pass can persist the root without a
/// `HypergraphState`.
pub fn empty_root_record(domain: &[u8]) -> Result<Vec<u8>> {
    let acc = build_from_coins(domain, std::iter::empty::<(Vec<u8>, Vec<u8>)>())?;
    let (depth, root) = acc.root_with_depth();
    Ok(encode_root_record(depth, &root))
}

/// Read the committed `(depth, root_bytes)` for a token, if present.
pub fn read_root(state: &HypergraphState, domain: &[u8]) -> Result<Option<(usize, Vec<u8>)>> {
    let disc = vertex_adds_discriminator()?;
    match state.get(domain, &ACC_ROOT_ADDRESS, &disc)? {
        Some(rec) => Ok(Some(decode_root_record(&rec)?)),
        None => Ok(None),
    }
}

// ── Live wiring: rebuild from committed state + commit the root per frame ─────

/// Rebuild a token's coin accumulator by scanning its committed vertex-adds
/// coins. The shadow tree is a deterministic function of the coin set, so this
/// reconstructs it exactly — no separate durability needed. Call after a frame's
/// coins are committed. (The reserved root vertex is itself skipped: it is not a
/// `coin:Coin`, so `extract_coin_leaf` filters it out.)
pub fn rebuild_from_state(state: &HypergraphState, domain: &[u8]) -> Result<CoinAccumulator> {
    let mut coins: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    state.crdt().for_each_vertex_adds_blob(domain, &mut |key, blob| {
        // key = domain ‖ address (64 bytes); the coin address is the second half.
        let addr = if key.len() >= 64 { key[32..64].to_vec() } else { key };
        coins.push((addr, blob));
    })?;
    build_from_coins(domain, coins)
}

/// Rebuild the accumulator and commit its `(depth ‖ root)` to the reserved
/// vertex — the per-frame shadow-tree finalize step (rides `state_roots[0]`).
pub fn refresh_root(state: &HypergraphState, domain: &[u8]) -> Result<()> {
    let acc = rebuild_from_state(state, domain)?;
    write_root(state, domain, &acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_intrinsic::materialize::{coin_type_hash, create_lattice_coin_vertex_tree};
    use quil_lattice_ct::arith::SplitMix64;
    use quil_lattice_ct::membership::{prove_membership, verify_membership, MembershipParams};
    use quil_lattice_ct::module::{PolyVec, ETA};
    use quil_lattice_ct::{accumulator::ACC_NODE_RANK, wire};

    // Build a coin vertex blob carrying wire-encoded lattice P and cv (the target
    // coin model), plus its content address.
    fn make_coin(domain: &[u8], p_bytes: &[u8], cv_bytes: &[u8], frame: u64) -> (Vec<u8>, Vec<u8>) {
        // Build via the LATTICE write path (P@[1<<2], cv@[2<<2]) so the coin
        // matches what `extract_coin_leaf` and the prover expect.
        let th = coin_type_hash(domain).unwrap();
        let tree = create_lattice_coin_vertex_tree(
            &frame.to_be_bytes(),
            p_bytes,
            cv_bytes,
            &[],
            &th,
        )
        .unwrap();
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        // Address = a stand-in content address (any 32 bytes; canonical order is
        // by this value).
        let addr = quil_crypto::poseidon::hash_bytes_to_32(&blob).unwrap().to_vec();
        (addr, blob)
    }

    fn rand_node_bytes(seed: u64) -> Vec<u8> {
        let mut prg = SplitMix64::new(seed);
        wire::encode_polyvec(&PolyVec::sample_short(ACC_NODE_RANK, ETA, &mut prg))
    }

    #[test]
    fn extract_filters_non_coins() {
        let domain = b"tokenA";
        let (_, coin_blob) = make_coin(domain, &rand_node_bytes(1), &rand_node_bytes(2), 1);
        assert!(extract_coin_leaf(&coin_blob, domain).unwrap().is_some());
        // Wrong domain ⇒ type hash mismatch ⇒ filtered.
        assert!(extract_coin_leaf(&coin_blob, b"tokenB").unwrap().is_none());
    }

    #[test]
    fn build_is_canonical_and_membership_verifies() {
        let domain = b"QUIL";
        // A real spendable coin: P = A·sk, cv a short node.
        let mut prg = SplitMix64::new(77);
        let mp1 = MembershipParams::production(1); // A_otk depth-independent
        let sk = PolyVec::sample_short(quil_lattice_ct::params::LWE_RANK_LAMBDA, ETA, &mut prg);
        let p = mp1.a_otk.matvec(&sk);
        let cv = PolyVec::sample_short(ACC_NODE_RANK, ETA, &mut prg);
        let (my_addr, my_blob) =
            make_coin(domain, &wire::encode_polyvec(&p), &wire::encode_polyvec(&cv), 5);

        // Plus a handful of decoy coins.
        let mut coins = vec![(my_addr.clone(), my_blob)];
        for i in 0..4u64 {
            coins.push(make_coin(domain, &rand_node_bytes(100 + i), &rand_node_bytes(200 + i), i));
        }
        // Shuffle the input order — build must be order-independent (sorts).
        coins.rotate_left(3);

        let acc = build_from_coins(domain, coins.clone()).unwrap();
        assert_eq!(acc.len(), 5);
        // Rebuild from a different input order ⇒ identical committed root.
        let mut coins2 = coins.clone();
        coins2.rotate_left(2);
        assert_eq!(build_from_coins(domain, coins2).unwrap().root_bytes(), acc.root_bytes());

        // Find my coin's canonical index and prove membership against the root.
        let mut sorted: Vec<[u8; 32]> = coins
            .iter()
            .map(|(a, _)| {
                let mut x = [0u8; 32];
                x.copy_from_slice(&a[..32]);
                x
            })
            .collect();
        sorted.sort();
        let mut my = [0u8; 32];
        my.copy_from_slice(&my_addr[..32]);
        let idx = sorted.iter().position(|a| *a == my).unwrap();

        let d = acc.current_depth();
        let mp = MembershipParams::production(d);
        let root = wire::decode_polyvec(&acc.root_bytes()).unwrap();
        let path: Vec<_> =
            acc.auth_path(idx).iter().map(|b| wire::decode_polyvec(b).unwrap()).collect();
        let proof = prove_membership(&mp, &root, &sk, &cv, idx, &path, b"spend", 9).unwrap();
        assert_eq!(
            verify_membership(&mp, &root, &proof, b"spend"),
            Some(mp.bk.matvec(&sk)),
            "coin scanned from vertices proves membership against the committed root"
        );
    }

    #[test]
    fn rebuild_from_scanned_state_matches_direct_build() {
        use quil_hypergraph::addressing::{shard_key_for_location, Location};
        use quil_types::crypto::NoopInclusionProver;
        use quil_types::store::HypergraphStore;
        use std::sync::Arc;

        let domain = &[0x51u8; 32][..];
        let coins: Vec<_> = (0..4u64)
            .map(|i| make_coin(domain, &rand_node_bytes(i), &rand_node_bytes(10 + i), i))
            .collect();
        let expected = build_from_coins(domain, coins.clone()).unwrap();

        // Populate a MemStore directly with the coins' vertex-adds blobs.
        let store = Arc::new(quil_hypergraph::testing::MemStore::new());
        let txn = store.new_transaction(false).unwrap();
        let mut app = [0u8; 32];
        app.copy_from_slice(domain);
        let shard = shard_key_for_location(&Location { app_address: app, data_address: [0u8; 32] });
        for (addr, blob) in &coins {
            let mut key = domain.to_vec();
            key.extend_from_slice(addr); // 64-byte vertex key = domain ‖ address
            store.save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &key, blob).unwrap();
        }
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store, Arc::new(NoopInclusionProver)));
        let state = HypergraphState::new(crdt);

        let acc = rebuild_from_state(&state, domain).unwrap();
        assert_eq!(acc.len(), 4, "all four coins scanned");
        assert_eq!(
            acc.root_bytes(),
            expected.root_bytes(),
            "root rebuilt from scanned state == direct build (deterministic)"
        );
    }

    #[test]
    fn coin_spend_witnesses_finds_coin_and_matches_accumulator() {
        use quil_hypergraph::addressing::{shard_key_for_location, Location};
        use quil_types::crypto::NoopInclusionProver;
        use quil_types::store::HypergraphStore;
        use std::sync::Arc;

        let domain = &[0x77u8; 32][..];
        // Coin i has P = rand_node_bytes(i); target the 3rd coin's P.
        let coins: Vec<_> = (0..5u64)
            .map(|i| make_coin(domain, &rand_node_bytes(i), &rand_node_bytes(50 + i), i))
            .collect();
        let target_p = rand_node_bytes(2);

        let store = Arc::new(quil_hypergraph::testing::MemStore::new());
        let txn = store.new_transaction(false).unwrap();
        let mut app = [0u8; 32];
        app.copy_from_slice(domain);
        let shard = shard_key_for_location(&Location { app_address: app, data_address: [0u8; 32] });
        for (addr, blob) in &coins {
            let mut key = domain.to_vec();
            key.extend_from_slice(addr);
            store.save_vertex_underlying(txn.as_ref(), "vertex", "adds", &shard, &key, blob).unwrap();
        }
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store, Arc::new(NoopInclusionProver)));
        let state = HypergraphState::new(crdt);

        let (depth, root, ws) =
            coin_spend_witnesses(&state, domain, &[target_p.clone(), b"not-a-coin".to_vec()]).unwrap();
        assert_eq!(ws.len(), 2);
        assert!(ws[0].found, "target coin's P is in the set");
        assert!(!ws[1].found, "a bogus P is not found");

        // (depth, root, auth_path) must match a direct accumulator rebuild.
        let acc = rebuild_from_state(&state, domain).unwrap();
        let (d, r) = acc.root_with_depth();
        assert_eq!((depth, root), (d, r));
        assert_eq!(ws[0].auth_path, acc.auth_path(ws[0].leaf_index as usize));
    }

    #[test]
    fn root_record_round_trips_through_state() {
        use crate::hypergraph_state::HypergraphState;
        use quil_types::crypto::NoopInclusionProver;
        use std::sync::Arc;

        let domain = &[0x51u8; 32][..]; // 32-byte app_address (state.set requires it)
        let coins: Vec<_> =
            (0..3u64).map(|i| make_coin(domain, &rand_node_bytes(i), &rand_node_bytes(10 + i), i)).collect();
        let acc = build_from_coins(domain, coins).unwrap();

        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(NoopInclusionProver),
        ));
        let state = HypergraphState::new(crdt);
        write_root(&state, domain, &acc).unwrap();
        let (depth, root) = read_root(&state, domain).unwrap().expect("root committed");
        assert_eq!(depth, acc.current_depth());
        assert_eq!(root, acc.root_bytes(), "committed root round-trips through state");
    }
}

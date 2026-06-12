//! Genesis loading and initialization — parses the embedded mainnet genesis
//! JSON, seeds the prover registry, and stores the initial frame + QC.

use std::sync::Arc;

use base64::Engine;
use num_bigint::BigInt;
use quil_crypto::poseidon::hash_bytes_to_32;
use quil_execution::global_intrinsic::materialize;
use quil_execution::global_schema::{write_field, write_type, GLOBAL_INTRINSIC_ADDRESS};
use quil_execution::hypergraph_state::{self, HypergraphState};
use quil_execution::prover_registry;
use quil_hypergraph::HypergraphCrdt;
use quil_types::error::{QuilError, Result};
use quil_types::proto::global;
use quil_types::proto::keys;
use quil_types::store::{ClockStore, ShardKey, ShardsStore};
use serde::Deserialize;
use tracing::{debug, info, warn};

/// Embedded mainnet genesis JSON.
const MAINNET_GENESIS_JSON: &[u8] = include_bytes!("../mainnet_genesis.json");

/// Expected frame number for mainnet genesis.
pub const MAINNET_GENESIS_FRAME_NUMBER: u64 = 244200;

/// Beacon seniority value for mainnet genesis.
///
/// This is the output of `compat::GetAggregatedSeniority([beacon_peer_id])`
/// for the beacon prover at genesis. The same seniority is applied to
/// ALL genesis provers (beacon + archive peers).
///
/// Deterministic derivation from the embedded retro JSONs:
///   * First retro (`reward=157208`): `10*6*60*24*92 / (157208/157208)` = 7,948,800
///   * Second retro (feb+mar+apr+may present): `10*6*60*24*(29+31+30+31)` = 10,454,400
///   * Third retro (present): `10*6*60*24*30` = 2,592,000
///   * Fourth retro (present): `10*6*60*24*31` = 2,678,400
///   * Sum: 23,673,600
///
/// `mainnet_244200_seniority.json` may additionally raise this via
/// `max(retro_sum, mainnet_entry)` — the `seniority_compat` module
/// handles both. The constant must match the canonical compat table;
/// `mainnet_beacon_seniority_matches_compat_table` asserts it at build
/// time so any divergence fails loudly instead of silently producing
/// an incompatible genesis prover tree commitment.
pub const MAINNET_BEACON_SENIORITY: u64 = 23_673_600;

/// Parsed genesis data from JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct GenesisData {
    pub frame_number: u64,
    pub timestamp: i64,
    pub difficulty: u32,
    /// Base64-encoded parent selector (32 bytes).
    pub parent_selector: String,
    /// Map of hex key (32 bytes) to base64 value (64 bytes).
    /// Initial shard commitments.
    pub initial_commitments: std::collections::HashMap<String, String>,
    /// Base64-encoded VDF output (516 bytes).
    pub output: String,
    /// Base64-encoded Ed448 public key of the beacon prover.
    pub beacon_ed448_key: String,
    /// Base64-encoded BLS48-581 G2 public key of the beacon prover.
    pub beacon_bls48581_key: String,
    /// Map of peer ID to hex-encoded BLS48-581 public key for archive provers.
    pub archive_peers: std::collections::HashMap<String, String>,
}

/// Load and parse the embedded mainnet genesis JSON.
pub fn get_mainnet_genesis_data() -> Result<GenesisData> {
    serde_json::from_slice(MAINNET_GENESIS_JSON)
        .map_err(|e| QuilError::Internal(format!("failed to parse genesis JSON: {}", e)))
}

/// Build a `GlobalFrame` proto from genesis data (header only, no prover
/// seeding). Use `initialize_genesis_state` for the full initialization.
pub fn build_genesis_frame(genesis: &GenesisData) -> Result<global::GlobalFrame> {
    let b64 = base64::engine::general_purpose::STANDARD;

    let parent_selector = b64.decode(&genesis.parent_selector)
        .map_err(|e| QuilError::Internal(format!("bad genesis parent_selector: {}", e)))?;
    let output = b64.decode(&genesis.output)
        .map_err(|e| QuilError::Internal(format!("bad genesis output: {}", e)))?;

    if output.len() != 516 {
        return Err(QuilError::Internal(format!(
            "genesis output should be 516 bytes, got {}",
            output.len()
        )));
    }
    if parent_selector.len() != 32 {
        return Err(QuilError::Internal(format!(
            "genesis parent_selector should be 32 bytes, got {}",
            parent_selector.len()
        )));
    }

    // Decode beacon BLS key (used as the genesis frame prover)
    let beacon_bls_key = b64.decode(&genesis.beacon_bls48581_key)
        .map_err(|e| QuilError::Internal(format!("bad genesis beacon BLS key: {}", e)))?;

    // Build frame header
    let header = global::GlobalFrameHeader {
        frame_number: genesis.frame_number,
        timestamp: genesis.timestamp,
        difficulty: genesis.difficulty,
        parent_selector: parent_selector.clone(),
        output: output.clone(),
        prover: beacon_bls_key,
        prover_tree_commitment: vec![0u8; 64], // Filled in by initialize_genesis_state
        requests_root: Vec::new(),
        ..Default::default()
    };

    info!(
        frame_number = genesis.frame_number,
        timestamp = genesis.timestamp,
        difficulty = genesis.difficulty,
        output_len = output.len(),
        archive_peers = genesis.archive_peers.len(),
        "parsed mainnet genesis"
    );

    Ok(global::GlobalFrame {
        header: Some(header),
        requests: Vec::new(),
    })
}

/// Return the expected genesis frame number for the given network.
///
/// - Network 0 (mainnet): Returns `MAINNET_GENESIS_FRAME_NUMBER`
/// - Other networks (testnet/devnet): Returns 0
pub fn expected_genesis_frame_number(network: u32) -> u64 {
    match network {
        0 => MAINNET_GENESIS_FRAME_NUMBER,
        _ => 0,
    }
}

/// Load the mainnet genesis frame. Convenience function that combines
/// `get_mainnet_genesis_data()` and `build_genesis_frame()`.
pub fn load_mainnet_genesis() -> Result<global::GlobalFrame> {
    let data = get_mainnet_genesis_data()?;
    build_genesis_frame(&data)
}

/// Get the list of initial archive peer BLS public keys from genesis.
/// Returns pairs of (peer_id, bls_pubkey_bytes).
pub fn genesis_archive_peers() -> Result<Vec<(String, Vec<u8>)>> {
    let data = get_mainnet_genesis_data()?;
    let mut peers = Vec::new();
    for (peer_id, pubkey_hex) in &data.archive_peers {
        let pubkey = hex::decode(pubkey_hex)
            .map_err(|e| QuilError::Internal(format!(
                "bad genesis archive peer key for {}: {}", peer_id, e
            )))?;
        peers.push((peer_id.clone(), pubkey));
    }
    Ok(peers)
}

/// Static QUIC multiaddrs for the genesis archive peers.
///
/// `genesis_archive_peers()` only carries `(peer_id, bls_pubkey)` —
/// the network address is normally learned via PeerInfo gossip after
/// libp2p bootstrap fans out. On a fresh node where the libp2p mesh
/// hasn't converged yet, the archive pool stays empty and the
/// shard-info remote fallback has nowhere to dial.
///
/// These addresses are hardcoded operator-known endpoints for the
/// genesis archives — they should be kept in sync with mainnet
/// operator records. Update when an operator rotates IPs.
pub fn genesis_archive_static_multiaddrs() -> Vec<&'static str> {
    vec![
        "/ip4/192.69.222.130/udp/8336/quic-v1/p2p/QmcKQjpQmLpbDsiif2MuakhHFyxWvqYauPsJDaXnLav7PJ",
        "/ip4/191.96.166.157/udp/8336/quic-v1/p2p/QmestbFp8PddwRk6ysBRrmWZEiHun5aRidHkqFxgeFaWVK",
        "/ip4/146.0.74.72/udp/8336/quic-v1/p2p/QmZKERVN8UkwLp9mPCZw4aaRx9N8Ewnkv7VQh1zyZwBSir",
        "/ip4/147.124.199.194/udp/8336/quic-v1/p2p/QmS3xJKbAmQxDiry9HpXV6bJyRvyd47pbufpZwEmgY1cy6",
        "/ip4/192.154.103.90/udp/8336/quic-v1/p2p/QmcuXdV3mdgwmhUv9kzRnZmjJyBwE7erNWVo8Q2ikrcjzX",
    ]
}

/// Helper: extract `(peer_id_str, ip_str)` from each genesis-archive
/// QUIC multiaddr. Used by `main.rs` to derive the corresponding
/// `host:8340` mTLS endpoints to seed the archive pool.
pub fn genesis_archive_static_ips() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for ma in genesis_archive_static_multiaddrs() {
        let parts: Vec<&str> = ma.trim_start_matches('/').split('/').collect();
        let mut ip: Option<String> = None;
        let mut peer: Option<String> = None;
        let mut i = 0;
        while i < parts.len() {
            match parts[i] {
                "ip4" | "ip6" if i + 1 < parts.len() => {
                    ip = Some(parts[i + 1].to_string());
                    i += 2;
                }
                "p2p" if i + 1 < parts.len() => {
                    peer = Some(parts[i + 1].to_string());
                    i += 2;
                }
                _ => i += 1,
            }
        }
        if let (Some(p), Some(a)) = (peer, ip) {
            out.push((p, a));
        }
    }
    out
}

/// Verify that a frame from the store matches the expected genesis.
/// Returns Ok(true) if the frame matches, Ok(false) if it doesn't,
/// or Err if genesis data can't be loaded.
pub fn verify_genesis_frame(frame: &global::GlobalFrame) -> Result<bool> {
    let genesis = get_mainnet_genesis_data()?;
    let expected = build_genesis_frame(&genesis)?;

    let h = match frame.header.as_ref() {
        Some(h) => h,
        None => return Ok(false),
    };
    let eh = match expected.header.as_ref() {
        Some(eh) => eh,
        None => return Err(QuilError::Internal("genesis frame has no header".into())),
    };

    Ok(h.frame_number == eh.frame_number
        && h.output == eh.output
        && h.parent_selector == eh.parent_selector
        && h.timestamp == eh.timestamp
        && h.difficulty == eh.difficulty)
}

// =========================================================================
// Full genesis initialization
// =========================================================================

/// Initialize the full genesis state for mainnet.
///
/// 1. Checks if the genesis frame already exists in `clock_store`. If yes,
///    returns it along with the latest QC.
/// 2. Parses the embedded mainnet genesis JSON.
/// 3. Seeds initial commitments into the shards store.
/// 4. Establishes genesis provers in the hypergraph CRDT via
///    `HypergraphState` — creating Prover and ProverAllocation vertices
///    with hyperedge connections.
/// 5. Commits the hypergraph and computes `ProverTreeCommitment`.
/// 6. Computes the 256 global commitments from VectorCommitmentTrees.
/// 7. Stores the genesis frame and QC in `clock_store`.
/// 8. Returns the completed frame and QC.
///
/// The caller is responsible for initializing consensus/liveness state
/// (via `ConsensusStore::put_liveness_state`/`put_consensus_state`)
/// after this function returns.
pub fn initialize_genesis_state(
    clock_store: &dyn ClockStore,
    shards_store: &dyn ShardsStore,
    hypergraph: &Arc<HypergraphCrdt>,
    inclusion_prover: &(dyn quil_types::crypto::InclusionProver + Sync),
) -> Result<(global::GlobalFrame, global::QuorumCertificate)> {
    info!("initializing genesis frame for global consensus");

    // 1. Check if genesis already exists
    let genesis_data = get_mainnet_genesis_data()?;
    if let Ok(existing) = clock_store.get_global_clock_frame(genesis_data.frame_number) {
        if existing.header.is_some() {
            info!(
                frame_number = genesis_data.frame_number,
                "genesis frame already exists in clock store"
            );
            // Return existing frame + latest QC
            let qc = clock_store.get_latest_quorum_certificate(&[])
                .unwrap_or_else(|_| make_genesis_qc(&existing));
            return Ok((existing, qc));
        }
    }

    // 2. Build the base genesis frame
    let mut genesis_frame = build_genesis_frame(&genesis_data)?;
    let header = genesis_frame.header.as_mut().unwrap();

    // Initialize 256 global commitments
    header.global_commitments = vec![vec![0u8; 64]; 256];

    // 3. Seed initial commitments into shards store + VectorCommitmentTrees
    let mut commitment_trees: Vec<quil_tries::VectorCommitmentTree> = (0..256)
        .map(|_| quil_tries::VectorCommitmentTree::new())
        .collect();

    let b64 = base64::engine::general_purpose::STANDARD;

    for (hex_key, base64_value) in &genesis_data.initial_commitments {
        let key_bytes = hex::decode(hex_key)
            .map_err(|e| QuilError::Internal(format!(
                "failed to decode commitment key {}: {}", hex_key, e
            )))?;

        let commitment_value = b64.decode(base64_value)
            .map_err(|e| QuilError::Internal(format!(
                "failed to decode commitment value: {}", e
            )))?;

        let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(&key_bytes, 256, 3);

        // shard_key layout in the rocks store is L1[3] || L2[32].
        // Without the L1 prefix, range_app_shards mis-slices 3 bytes
        // of the encoded path as part of the returned shard_key,
        // which empties the TUI "available shards" panel.
        let mut shard_key = Vec::with_capacity(3 + key_bytes.len());
        shard_key.extend_from_slice(&l1);
        shard_key.extend_from_slice(&key_bytes);

        // Store app shard entries (64x64 grid for each bloom index)
        let txn = clock_store.new_transaction(false)?;
        for i in 0..64u32 {
            for j in 0..64u32 {
                shards_store.put_app_shard(
                    txn.as_ref(),
                    &quil_types::store::ShardInfo {
                        shard_key: shard_key.clone(),
                        prefix: vec![i, j],
                        size: Vec::new(),
                        data_shards: 0,
                        commitment: Vec::new(),
                    },
                )?;
            }
        }
        txn.commit()?;

        // Insert into the 3 bloom-selected commitment trees
        for i in 0..3 {
            let idx = l1[i] as usize;
            commitment_trees[idx].insert(
                &key_bytes,
                &commitment_value,
                &[],
                &BigInt::from(commitment_value.len() as u64),
            )?;
            commitment_trees[idx].commit(inclusion_prover);
        }
    }

    // 4. Establish genesis provers in the hypergraph
    let state = HypergraphState::new(hypergraph.clone());
    establish_mainnet_genesis_provers(&state, &genesis_data)?;
    state.commit()?;

    // 5. Commit the hypergraph and extract prover tree commitment
    let roots = hypergraph.commit(0)?;

    // The global intrinsic address shard key has L1=[0,0,0] and
    // L2=GLOBAL_INTRINSIC_ADDRESS
    let global_shard_key = ShardKey {
        l1: [0u8; 3],
        l2: GLOBAL_INTRINSIC_ADDRESS,
    };

    let prover_root = match roots.get(&global_shard_key) {
        Some(shard_roots) if !shard_roots.is_empty() => shard_roots[0].clone(),
        _ => {
            warn!("no prover tree roots after commit, using empty root");
            vec![0u8; 64]
        }
    };

    header.prover_tree_commitment = prover_root;

    // 6. Compute 256 global commitments
    for i in 0..256 {
        header.global_commitments[i] = commitment_trees[i].commit(inclusion_prover);
    }

    // 7. Set empty signature payload — avoids panics on header readers.
    header.public_key_signature_bls48581 = Some(keys::Bls48581AggregateSignature {
        signature: Vec::new(),
        public_key: Some(keys::Bls48581g2PublicKey {
            key_value: Vec::new(),
        }),
        bitmask: Vec::new(),
    });

    // 8. Store in clock store
    let txn = clock_store.new_transaction(false)?;
    clock_store.put_global_clock_frame(&genesis_frame, txn.as_ref())?;

    let genesis_qc = make_genesis_qc(&genesis_frame);
    clock_store.put_quorum_certificate(&genesis_qc, txn.as_ref())?;
    txn.commit()?;

    info!("initialized genesis frame for global consensus");
    Ok((genesis_frame, genesis_qc))
}

/// Build the genesis QuorumCertificate for a genesis frame.
fn make_genesis_qc(frame: &global::GlobalFrame) -> global::QuorumCertificate {
    let header = frame.header.as_ref().unwrap();

    // Selector = poseidon(output) — matches GlobalFrame.Identity()
    let selector = hash_bytes_to_32(&header.output)
        .map(|h| h.to_vec())
        .unwrap_or_else(|_| vec![0u8; 32]);

    global::QuorumCertificate {
        rank: 0,
        filter: Vec::new(),
        frame_number: header.frame_number,
        selector,
        timestamp: 0,
        aggregate_signature: Some(keys::Bls48581AggregateSignature {
            public_key: Some(keys::Bls48581g2PublicKey {
                key_value: vec![0u8; 585],
            }),
            signature: vec![0u8; 74],
            bitmask: vec![0xFFu8; 32],
        }),
    }
}

// =========================================================================
// Prover seeding
// =========================================================================

/// Seed genesis provers into the hypergraph. Creates Prover +
/// ProverAllocation vertices for the beacon prover and each archive
/// peer, all with the same aggregated seniority.
fn establish_mainnet_genesis_provers(
    state: &HypergraphState,
    genesis_data: &GenesisData,
) -> Result<()> {
    let b64 = base64::engine::general_purpose::STANDARD;

    // The aggregated-seniority lookup over the beacon Ed448 peer ID
    // resolves to MAINNET_BEACON_SENIORITY.
    let seniority = MAINNET_BEACON_SENIORITY;

    debug!(
        seniority = seniority,
        "establishing seniority for beacon from aggregated records"
    );

    // Decode beacon BLS key
    let beacon_bls_key = b64.decode(&genesis_data.beacon_bls48581_key)
        .map_err(|e| QuilError::Internal(format!(
            "failed to decode beacon BLS key: {}", e
        )))?;

    // Add beacon prover
    add_genesis_prover(
        state,
        &beacon_bls_key,
        seniority,
        genesis_data.frame_number,
    )?;

    // Add archive peers (all use same seniority as beacon)
    for (peer_id, pubkey_hex) in &genesis_data.archive_peers {
        let pubkey = hex::decode(pubkey_hex)
            .map_err(|e| QuilError::Internal(format!(
                "failed to decode archive peer key for {}: {}", peer_id, e
            )))?;

        add_genesis_prover(
            state,
            &pubkey,
            seniority,
            genesis_data.frame_number,
        )?;
    }

    Ok(())
}

/// Add a single genesis prover to the hypergraph state. Creates:
///
/// - **Prover vertex**: PublicKey, Status=1 (Active), AvailableStorage=0,
///   Seniority, at `poseidon(pubkey)` within `GLOBAL_INTRINSIC_ADDRESS`.
///
/// - **ProverAllocation vertex**: Prover (reference), Status=1 (Active),
///   ConfirmationFilter=nil (global shard), JoinFrameNumber=0,
///   JoinConfirmFrameNumber=0, LastActiveFrameNumber=frameNumber,
///   at `poseidon("PROVER_ALLOCATION" || pubkey || nil)`.
///
/// - **Hyperedge** connecting the prover to its allocation, stored at the
///   prover's data address within the hyperedge adds set.
fn add_genesis_prover(
    state: &HypergraphState,
    pubkey: &[u8],
    seniority: u64,
    frame_number: u64,
) -> Result<()> {
    let va_disc = hypergraph_state::vertex_adds_discriminator()?;
    let ha_disc = hypergraph_state::hyperedge_adds_discriminator()?;
    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];

    // Compute prover address: poseidon(pubkey) -> 32 bytes
    let prover_address = materialize::prover_address_from_pubkey(pubkey)?;

    // --- Build Prover vertex tree ---
    let mut prover_tree = quil_tries::VectorCommitmentTree::new();
    let prover_cls = "prover:Prover";

    // Type hash at [0xFF; 32]
    write_type(&mut prover_tree, prover_cls)?;

    // PublicKey (order 0)
    write_field(&mut prover_tree, prover_cls, "PublicKey", pubkey)?;

    // Status = 1 (Active) — genesis provers start active, not joining
    write_field(&mut prover_tree, prover_cls, "Status", &[materialize::STATUS_ACTIVE])?;

    // AvailableStorage = 0
    write_field(
        &mut prover_tree,
        prover_cls,
        "AvailableStorage",
        &0u64.to_be_bytes(),
    )?;

    // Seniority
    write_field(
        &mut prover_tree,
        prover_cls,
        "Seniority",
        &seniority.to_be_bytes(),
    )?;

    // JoinFrameNumber and KickFrameNumber are intentionally not set on
    // the prover vertex at genesis — only the allocation carries those.

    // Serialize and store prover vertex
    let prover_blob = prover_registry::vertex_tree_to_blob(&prover_tree);
    state.set(domain, &prover_address, &va_disc, frame_number, prover_blob)?;

    // --- Build ProverAllocation vertex tree ---
    let alloc_cls = "allocation:ProverAllocation";

    // Compute allocation address:
    //   poseidon("PROVER_ALLOCATION" || pubkey || filter)
    // For genesis the filter is empty, so the concat is just
    // "PROVER_ALLOCATION" || pubkey.
    let alloc_address = materialize::allocation_address(pubkey, &[])?;

    let mut alloc_tree = quil_tries::VectorCommitmentTree::new();

    // Type hash
    write_type(&mut alloc_tree, alloc_cls)?;

    // Prover reference (order 0) — the prover's 32-byte address
    write_field(&mut alloc_tree, alloc_cls, "Prover", &prover_address)?;

    // Status = 1 (Active)
    write_field(&mut alloc_tree, alloc_cls, "Status", &[materialize::STATUS_ACTIVE])?;

    // ConfirmationFilter = nil (empty, global shard allocation).
    write_field(&mut alloc_tree, alloc_cls, "ConfirmationFilter", &[])?;

    // JoinFrameNumber = 0
    write_field(&mut alloc_tree, alloc_cls, "JoinFrameNumber", &0u64.to_be_bytes())?;

    // JoinConfirmFrameNumber = 0
    write_field(&mut alloc_tree, alloc_cls, "JoinConfirmFrameNumber", &0u64.to_be_bytes())?;

    // LastActiveFrameNumber = frameNumber
    write_field(
        &mut alloc_tree,
        alloc_cls,
        "LastActiveFrameNumber",
        &frame_number.to_be_bytes(),
    )?;

    // Serialize and store allocation vertex
    let alloc_blob = prover_registry::vertex_tree_to_blob(&alloc_tree);
    state.set(domain, &alloc_address, &va_disc, frame_number, alloc_blob)?;

    // --- Build Hyperedge connecting prover to allocation ---
    //
    // Hyperedge lives at (GLOBAL_INTRINSIC_ADDRESS, proverAddress); the
    // allocation atom is added to its extrinsic tree.
    //
    // The extrinsic tree stores each atom at key = atom ID
    // (64 bytes: appAddr || dataAddr) with value = atom bytes
    // (0x00 || appAddr[32] || dataAddr[32] || commitment[64] || size[32] = 161 bytes).

    // Build the extrinsic tree for the hyperedge.
    // Key = allocation atom ID (GLOBAL_INTRINSIC_ADDRESS || alloc_address)
    let mut atom_id = Vec::with_capacity(64);
    atom_id.extend_from_slice(&GLOBAL_INTRINSIC_ADDRESS);
    atom_id.extend_from_slice(&alloc_address);

    // Value = atom.ToBytes() = 0x00 || appAddr[32] || dataAddr[32] || commitment[64] || size[32]
    let alloc_commitment = alloc_tree.commit(&quil_types::crypto::NoopInclusionProver);
    // Get tree size from root node, or default to zero
    let alloc_size = alloc_tree.root.as_ref()
        .map(|node| node.size().clone())
        .unwrap_or_else(|| BigInt::from(0));
    let mut alloc_size_bytes = [0u8; 32];
    let (_, size_bytes) = alloc_size.to_bytes_be();
    let offset = 32usize.saturating_sub(size_bytes.len());
    alloc_size_bytes[offset..].copy_from_slice(&size_bytes[..std::cmp::min(size_bytes.len(), 32)]);

    let mut atom_bytes = Vec::with_capacity(161);
    atom_bytes.push(0x00);
    atom_bytes.extend_from_slice(&GLOBAL_INTRINSIC_ADDRESS);
    atom_bytes.extend_from_slice(&alloc_address);
    atom_bytes.extend_from_slice(&alloc_commitment);
    atom_bytes.extend_from_slice(&alloc_size_bytes);

    // Build the extrinsic VectorCommitmentTree for the hyperedge
    let mut ext_tree = quil_tries::VectorCommitmentTree::new();
    ext_tree.insert(
        &atom_id,
        &atom_bytes,
        &[],
        &BigInt::from(atom_bytes.len() as u64),
    )?;

    // Serialize the extrinsic tree as the hyperedge data
    let hyperedge_blob = prover_registry::vertex_tree_to_blob(&ext_tree);
    state.set(domain, &prover_address, &ha_disc, frame_number, hyperedge_blob)?;

    debug!(
        prover_address = hex::encode(&prover_address),
        alloc_address = hex::encode(&alloc_address),
        seniority = seniority,
        "added genesis prover"
    );

    Ok(())
}

// =========================================================================
// Testnet / devnet genesis
// =========================================================================

/// Default difficulty for testnet/devnet genesis when none is specified.
const DEFAULT_TESTNET_DIFFICULTY: u32 = 10000;

/// Initialize genesis state for a testnet or devnet network.
///
/// Unlike the mainnet path, this creates a fresh genesis at frame 0 with:
/// - Empty parent selector (32 zero bytes)
/// - Current wall-clock timestamp
/// - Empty VDF output (516 zero bytes)
/// - Prover reward vertices in the QUIL token domain
/// - Provers seeded with seniority 1000
///
/// The `genesis_seed` parameter (hex-encoded) supplies one or more 585-byte
/// BLS48-581 public keys. When empty or when `network == 99`,
/// `local_bls_pubkey` is used as the sole prover instead.
pub fn initialize_testnet_genesis_state(
    network: u8,
    genesis_seed: &str,
    local_bls_pubkey: &[u8],
    difficulty: u32,
    clock_store: &dyn ClockStore,
    shards_store: &dyn quil_types::store::ShardsStore,
    hypergraph: &Arc<HypergraphCrdt>,
    inclusion_prover: &(dyn quil_types::crypto::InclusionProver + Sync),
) -> Result<(global::GlobalFrame, global::QuorumCertificate)> {
    info!(network = network, "initializing testnet/devnet genesis frame");

    // 1. Check if genesis already exists at frame 0
    if let Ok(existing) = clock_store.get_global_clock_frame(0) {
        if existing.header.is_some() {
            info!("testnet genesis frame already exists in clock store");
            let qc = clock_store
                .get_latest_quorum_certificate(&[])
                .unwrap_or_else(|_| make_genesis_qc(&existing));
            return Ok((existing, qc));
        }
    }

    // 2. Determine prover keys
    let prover_pubkeys = resolve_testnet_prover_keys(network, genesis_seed, local_bls_pubkey)?;
    if prover_pubkeys.is_empty() {
        return Err(QuilError::Internal(
            "no prover keys available for testnet genesis".into(),
        ));
    }

    // 3. Create reward vertices in the QUIL token domain
    establish_testnet_reward_vertices(&prover_pubkeys, hypergraph)?;

    // 4. Create prover + allocation vertices (seniority=1000, frame=0)
    let state = HypergraphState::new(hypergraph.clone());
    for pubkey in &prover_pubkeys {
        add_genesis_prover(&state, pubkey, 1000, 0)?;
    }

    // Seed the QUIL_TOKEN domain with six placeholder vertices and
    // write six app-shard records keyed by
    // `(QUIL_TOKEN_ADDRESS, path=0..5)`. Without these the testnet has
    // no app shards in `shards_store`, so a non-global prover joining
    // the network has nothing to propose joining —
    // `build_proposal_descriptors` only sees the global filter (which
    // it explicitly filters out).
    let quil_token_domain = quil_execution::domains::QUIL_TOKEN;
    let va_disc = hypergraph_state::vertex_adds_discriminator()?;
    for i in 0u8..6 {
        let mut address = [0u8; 32];
        address[0] = i;
        // 64-byte zero blob is the placeholder payload.
        state.set(&quil_token_domain[..], &address, &va_disc, 0, vec![0u8; 64])?;
    }

    state.commit()?;

    // 5. Commit hypergraph and extract roots
    let roots = hypergraph.commit(0)?;

    // Persist the six QUIL token app-shard records to the shards
    // store. The shards-store entries are what the worker allocator
    // iterates via `range_app_shards` to discover available shards
    // — they're the source of truth for "what shards exist", separate
    // from the prover registry's view of "who is allocated where".
    //
    // `shard_key` layout: a 3-byte bloom filter index (L1) followed
    // by the 32-byte address (L2). The shards-store reader hardcodes
    // a 35-byte shard_key length, so writing a bare 32-byte L2 here
    // causes 3 bytes of the encoded prefix u32 to be folded into the
    // shard_key on readback.
    let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(
        &quil_token_domain[..],
        256,
        3,
    );
    let mut quil_shard_key = Vec::with_capacity(3 + quil_token_domain.len());
    quil_shard_key.extend_from_slice(&l1);
    quil_shard_key.extend_from_slice(&quil_token_domain[..]);
    {
        let txn = clock_store.new_transaction(false)?;
        for path in 0u32..6 {
            shards_store.put_app_shard(
                txn.as_ref(),
                &quil_types::store::ShardInfo {
                    shard_key: quil_shard_key.clone(),
                    prefix: vec![path],
                    size: Vec::new(),
                    data_shards: 0,
                    commitment: Vec::new(),
                },
            )?;
        }
        txn.commit()?;
    }

    // Build 256 commitment trees from all shard roots
    let mut commitment_trees: Vec<quil_tries::VectorCommitmentTree> =
        (0..256).map(|_| quil_tries::VectorCommitmentTree::new()).collect();

    for (shard_key, commits) in &roots {
        if commits.is_empty() {
            continue;
        }
        for i in 0..3 {
            let idx = shard_key.l1[i] as usize;
            if idx < 256 {
                commitment_trees[idx].insert(
                    &shard_key.l2,
                    &commits[0],
                    &[],
                    &BigInt::from(commits[0].len() as u64),
                )?;
                commitment_trees[idx].commit(inclusion_prover);
            }
        }
    }

    // Extract prover tree commitment
    let global_shard_key = ShardKey {
        l1: [0u8; 3],
        l2: GLOBAL_INTRINSIC_ADDRESS,
    };
    let prover_root = match roots.get(&global_shard_key) {
        Some(shard_roots) if !shard_roots.is_empty() => shard_roots[0].clone(),
        _ => {
            warn!("no prover tree roots after testnet commit, using empty root");
            vec![0u8; 64]
        }
    };

    // 6. Build the stub genesis frame
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    let effective_difficulty = if difficulty > 0 {
        difficulty
    } else {
        DEFAULT_TESTNET_DIFFICULTY
    };

    let mut global_commitments: Vec<Vec<u8>> = Vec::with_capacity(256);
    for i in 0..256 {
        global_commitments.push(commitment_trees[i].commit(inclusion_prover));
    }

    let header = global::GlobalFrameHeader {
        frame_number: 0,
        parent_selector: vec![0u8; 32],
        timestamp: now_ms,
        difficulty: effective_difficulty,
        output: vec![0u8; 516],
        prover: Vec::new(),
        prover_tree_commitment: prover_root,
        requests_root: Vec::new(),
        global_commitments,
        public_key_signature_bls48581: Some(keys::Bls48581AggregateSignature {
            signature: Vec::new(),
            public_key: Some(keys::Bls48581g2PublicKey {
                key_value: Vec::new(),
            }),
            bitmask: Vec::new(),
        }),
        ..Default::default()
    };

    let genesis_frame = global::GlobalFrame {
        header: Some(header),
        requests: Vec::new(),
    };

    // 7. Store frame + QC
    let txn = clock_store.new_transaction(false)?;
    clock_store.put_global_clock_frame(&genesis_frame, txn.as_ref())?;
    let genesis_qc = make_genesis_qc(&genesis_frame);
    clock_store.put_quorum_certificate(&genesis_qc, txn.as_ref())?;
    txn.commit()?;

    info!("initialized testnet/devnet genesis frame");
    Ok((genesis_frame, genesis_qc))
}

/// Resolve the set of BLS public keys to use for testnet genesis provers.
///
/// - If `genesis_seed` is non-empty and `network != 99`: hex-decode the seed
///   and split into 585-byte BLS48-581 public keys.
/// - Otherwise: use `local_bls_pubkey` as the single prover.
pub fn resolve_testnet_prover_keys(
    network: u8,
    genesis_seed: &str,
    local_bls_pubkey: &[u8],
) -> Result<Vec<Vec<u8>>> {
    if network != 99 && !genesis_seed.is_empty() {
        let stripped: String = genesis_seed.split_whitespace().collect();
        let seed_bytes = hex::decode(&stripped).map_err(|e| {
            QuilError::Internal(format!("failed to decode genesis seed hex: {}", e))
        })?;
        if seed_bytes.len() % 585 != 0 {
            return Err(QuilError::Internal(format!(
                "invalid genesis seed length {}: must be a multiple of 585 bytes",
                seed_bytes.len()
            )));
        }
        let count = seed_bytes.len() / 585;
        let mut keys = Vec::with_capacity(count);
        for i in 0..count {
            keys.push(seed_bytes[i * 585..(i + 1) * 585].to_vec());
        }
        debug!(count = count, "resolved testnet prover keys from genesis seed");
        Ok(keys)
    } else {
        debug!("using local BLS pubkey as sole testnet prover");
        Ok(vec![local_bls_pubkey.to_vec()])
    }
}

/// Create ProverReward vertices in the QUIL token domain for each prover.
/// Each prover gets:
/// - A reward vertex at `poseidon(QUIL_TOKEN_ADDRESS || prover_address)`
///   within the QUIL_TOKEN domain
/// - DelegateAddress set to the reward address itself
/// - Balance set to 10000 * 8_000_000_000 (10000 QUIL)
fn establish_testnet_reward_vertices(
    prover_pubkeys: &[Vec<u8>],
    hypergraph: &Arc<HypergraphCrdt>,
) -> Result<()> {
    let va_disc = hypergraph_state::vertex_adds_discriminator()?;
    let quil_token_domain = &quil_execution::domains::QUIL_TOKEN[..];

    let state = HypergraphState::new(hypergraph.clone());

    for pubkey in prover_pubkeys {
        let prover_address = materialize::prover_address_from_pubkey(pubkey)?;
        let reward_addr = materialize::reward_address(&prover_address)?;

        // Build ProverReward vertex tree
        let mut reward_tree = quil_tries::VectorCommitmentTree::new();
        let reward_cls = "reward:ProverReward";

        write_type(&mut reward_tree, reward_cls)?;

        // DelegateAddress (order 0) — set to the reward address itself
        write_field(&mut reward_tree, reward_cls, "DelegateAddress", &reward_addr)?;

        // Balance (order 1) — 10000 QUIL = 10000 * 8_000_000_000
        let balance = 10_000u64 * quil_execution::token_intrinsic::constants::QUIL_TOKEN_UNITS;
        let mut balance_bytes = [0u8; 32];
        let balance_be = balance.to_be_bytes();
        balance_bytes[32 - balance_be.len()..].copy_from_slice(&balance_be);
        write_field(&mut reward_tree, reward_cls, "Balance", &balance_bytes)?;

        // Serialize and store reward vertex
        let reward_blob = prover_registry::vertex_tree_to_blob(&reward_tree);
        state.set(
            quil_token_domain,
            &reward_addr,
            &va_disc,
            0,
            reward_blob,
        )?;

        debug!(
            prover_address = hex::encode(&prover_address),
            reward_address = hex::encode(&reward_addr),
            "created testnet reward vertex"
        );
    }

    state.commit()?;
    Ok(())
}

// =========================================================================
// Unified genesis entry point
// =========================================================================

/// Initialize genesis state, dispatching to the appropriate path based on
/// the network identifier.
///
/// - `network == 0` (mainnet): Loads the embedded mainnet genesis JSON and
///   seeds provers from the archive peer list.
/// - Any other value (testnet/devnet): Creates a stub genesis at frame 0
///   with provers derived from `genesis_seed` or `local_bls_pubkey`.
pub fn initialize_genesis(
    network: u8,
    genesis_seed: &str,
    local_bls_pubkey: &[u8],
    difficulty: u32,
    clock_store: &dyn ClockStore,
    shards_store: &dyn ShardsStore,
    hypergraph: &Arc<HypergraphCrdt>,
    inclusion_prover: &(dyn quil_types::crypto::InclusionProver + Sync),
) -> Result<(global::GlobalFrame, global::QuorumCertificate)> {
    if network == 0 {
        initialize_genesis_state(clock_store, shards_store, hypergraph, inclusion_prover)
    } else {
        initialize_testnet_genesis_state(
            network,
            genesis_seed,
            local_bls_pubkey,
            difficulty,
            clock_store,
            shards_store,
            hypergraph,
            inclusion_prover,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mainnet_genesis() {
        let data = get_mainnet_genesis_data().unwrap();
        assert_eq!(data.frame_number, 244200);
        assert_eq!(data.timestamp, 1744726759481);
        assert_eq!(data.difficulty, 160000);
        assert_eq!(data.archive_peers.len(), 5);
        assert_eq!(data.initial_commitments.len(), 1);
    }

    #[test]
    fn build_genesis_frame_from_json() {
        let data = get_mainnet_genesis_data().unwrap();
        let frame = build_genesis_frame(&data).unwrap();
        let h = frame.header.as_ref().unwrap();
        assert_eq!(h.frame_number, 244200);
        assert_eq!(h.timestamp, 1744726759481);
        assert_eq!(h.difficulty, 160000);
        assert_eq!(h.output.len(), 516);
        assert_eq!(h.parent_selector.len(), 32);
        assert!(h.prover.len() > 0);
    }

    #[test]
    fn load_mainnet_genesis_convenience() {
        let frame = load_mainnet_genesis().unwrap();
        assert_eq!(frame.header.as_ref().unwrap().frame_number, 244200);
    }

    #[test]
    fn expected_genesis_frame_number_mainnet() {
        assert_eq!(expected_genesis_frame_number(0), 244200);
    }

    #[test]
    fn expected_genesis_frame_number_testnet() {
        assert_eq!(expected_genesis_frame_number(1), 0);
    }

    #[test]
    fn genesis_archive_peers_returns_five() {
        let peers = genesis_archive_peers().unwrap();
        assert_eq!(peers.len(), 5);
        for (peer_id, pubkey) in &peers {
            assert!(peer_id.starts_with("Qm"), "expected multibase peer ID");
            assert!(pubkey.len() > 100, "BLS pubkey should be > 100 bytes");
        }
    }

    #[test]
    fn verify_genesis_frame_matches() {
        let frame = load_mainnet_genesis().unwrap();
        assert!(verify_genesis_frame(&frame).unwrap());
    }

    #[test]
    fn verify_genesis_frame_wrong_number_fails() {
        let mut frame = load_mainnet_genesis().unwrap();
        frame.header.as_mut().unwrap().frame_number = 999;
        assert!(!verify_genesis_frame(&frame).unwrap());
    }

    // -----------------------------------------------------------------
    // Prover seeding tests (using in-memory CRDT)
    // -----------------------------------------------------------------

    use quil_hypergraph::testing::MemStore;
    use quil_types::crypto::NoopInclusionProver;

    fn test_crdt() -> Arc<HypergraphCrdt> {
        Arc::new(HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(NoopInclusionProver),
        ))
    }

    #[test]
    fn add_genesis_prover_creates_vertices() {
        let crdt = test_crdt();
        let state = HypergraphState::new(crdt.clone());

        let pubkey = vec![0xAAu8; 585]; // dummy BLS key
        add_genesis_prover(&state, &pubkey, 1000, 244200).unwrap();
        state.commit().unwrap();

        // Verify prover vertex exists in CRDT
        let prover_address = materialize::prover_address_from_pubkey(&pubkey).unwrap();
        let loc = quil_hypergraph::addressing::Location {
            app_address: GLOBAL_INTRINSIC_ADDRESS,
            data_address: prover_address,
        };
        assert!(crdt.lookup_vertex(&loc), "prover vertex should exist");

        // Verify allocation vertex exists
        let alloc_address = materialize::allocation_address(&pubkey, &[]).unwrap();
        let alloc_loc = quil_hypergraph::addressing::Location {
            app_address: GLOBAL_INTRINSIC_ADDRESS,
            data_address: alloc_address,
        };
        assert!(crdt.lookup_vertex(&alloc_loc), "allocation vertex should exist");

        // Verify hyperedge exists
        assert!(crdt.lookup_hyperedge(&loc), "hyperedge should exist at prover address");
    }

    #[test]
    fn add_genesis_prover_sets_correct_fields() {
        let crdt = test_crdt();
        let state = HypergraphState::new(crdt.clone());

        let pubkey = vec![0xBBu8; 585];
        let seniority = 5000u64;
        let frame_number = 244200u64;

        add_genesis_prover(&state, &pubkey, seniority, frame_number).unwrap();
        state.commit().unwrap();

        // Read prover vertex data from CRDT
        let prover_address = materialize::prover_address_from_pubkey(&pubkey).unwrap();
        let loc = quil_hypergraph::addressing::Location {
            app_address: GLOBAL_INTRINSIC_ADDRESS,
            data_address: prover_address,
        };
        let prover_data = crdt.get_vertex_data(&loc).expect("prover data should exist");

        let prover_tree = prover_registry::rebuild_vertex_tree_from_blob(&prover_data);
        let cls = "prover:Prover";

        // Verify PublicKey
        assert_eq!(
            quil_execution::global_schema::read_field(&prover_tree, cls, "PublicKey"),
            Some(pubkey.clone()),
        );
        // Verify Status = 1 (Active)
        assert_eq!(
            quil_execution::global_schema::read_field(&prover_tree, cls, "Status"),
            Some(vec![1]),
        );
        // Verify AvailableStorage = 0
        assert_eq!(
            quil_execution::global_schema::read_field(&prover_tree, cls, "AvailableStorage"),
            Some(0u64.to_be_bytes().to_vec()),
        );
        // Verify Seniority
        assert_eq!(
            quil_execution::global_schema::read_field(&prover_tree, cls, "Seniority"),
            Some(seniority.to_be_bytes().to_vec()),
        );
        // Verify type hash
        assert_eq!(
            quil_execution::global_schema::read_type(&prover_tree),
            Some("prover:Prover"),
        );
    }

    #[test]
    fn add_genesis_prover_sets_allocation_fields() {
        let crdt = test_crdt();
        let state = HypergraphState::new(crdt.clone());

        let pubkey = vec![0xCCu8; 585];
        let frame_number = 244200u64;

        add_genesis_prover(&state, &pubkey, 1000, frame_number).unwrap();
        state.commit().unwrap();

        // Read allocation vertex data
        let alloc_address = materialize::allocation_address(&pubkey, &[]).unwrap();
        let alloc_loc = quil_hypergraph::addressing::Location {
            app_address: GLOBAL_INTRINSIC_ADDRESS,
            data_address: alloc_address,
        };
        let alloc_data = crdt.get_vertex_data(&alloc_loc).expect("allocation data should exist");

        let alloc_tree = prover_registry::rebuild_vertex_tree_from_blob(&alloc_data);
        let cls = "allocation:ProverAllocation";

        // Verify type hash
        assert_eq!(
            quil_execution::global_schema::read_type(&alloc_tree),
            Some("allocation:ProverAllocation"),
        );

        // Verify Prover reference
        let prover_address = materialize::prover_address_from_pubkey(&pubkey).unwrap();
        assert_eq!(
            quil_execution::global_schema::read_field(&alloc_tree, cls, "Prover"),
            Some(prover_address.to_vec()),
        );

        // Verify Status = 1 (Active)
        assert_eq!(
            quil_execution::global_schema::read_field(&alloc_tree, cls, "Status"),
            Some(vec![1]),
        );

        // Verify ConfirmationFilter = empty (global shard)
        assert_eq!(
            quil_execution::global_schema::read_field(&alloc_tree, cls, "ConfirmationFilter"),
            Some(vec![]),
        );

        // Verify JoinFrameNumber = 0
        assert_eq!(
            quil_execution::global_schema::read_field(&alloc_tree, cls, "JoinFrameNumber"),
            Some(0u64.to_be_bytes().to_vec()),
        );

        // Verify JoinConfirmFrameNumber = 0
        assert_eq!(
            quil_execution::global_schema::read_field(&alloc_tree, cls, "JoinConfirmFrameNumber"),
            Some(0u64.to_be_bytes().to_vec()),
        );

        // Verify LastActiveFrameNumber = frame_number
        assert_eq!(
            quil_execution::global_schema::read_field(&alloc_tree, cls, "LastActiveFrameNumber"),
            Some(frame_number.to_be_bytes().to_vec()),
        );
    }

    /// Deterministic verification of MAINNET_BEACON_SENIORITY against
    /// the canonical compat table. Computes the beacon peer ID from
    /// the Ed448 key in mainnet_genesis.json and runs it through
    /// `seniority_compat::get_aggregated_seniority`.
    ///
    /// If this assertion ever fails, MAINNET_BEACON_SENIORITY was
    /// wrong and the genesis prover tree commitment would diverge
    /// from the canonical one, making the node unable to join mainnet.
    #[test]
    fn mainnet_beacon_seniority_matches_compat_table() {
        let b64 = base64::engine::general_purpose::STANDARD;
        let genesis = get_mainnet_genesis_data().unwrap();

        // Beacon Ed448 key is a 57-byte public key (not a 114-byte
        // priv+pub pair), so we derive the peer ID directly from it
        // via the same path quil_p2p uses.
        let ed448_pub = b64
            .decode(&genesis.beacon_ed448_key)
            .expect("beacon Ed448 key not valid base64");
        assert_eq!(
            ed448_pub.len(),
            57,
            "beacon_ed448_key is {}B, expected 57B Ed448 pubkey",
            ed448_pub.len()
        );

        let peer_id_bytes = quil_p2p::ed448_identity::peer_id_from_ed448_pubkey(&ed448_pub);
        let peer_id_str = bs58::encode(&peer_id_bytes).into_string();

        let computed =
            quil_execution::seniority_compat::get_aggregated_seniority(&[peer_id_str.clone()]);

        assert_eq!(
            computed, MAINNET_BEACON_SENIORITY,
            "MAINNET_BEACON_SENIORITY ({}) does not match compat table result ({}) \
             for beacon peer {}. Either the constant is wrong or the compat \
             table (crates/quil-execution/src/seniority_compat.rs) is broken. \
             Fix one or the other — genesis frame commitment depends on this value.",
            MAINNET_BEACON_SENIORITY,
            computed,
            peer_id_str
        );
    }

    #[test]
    fn establish_mainnet_genesis_provers_creates_six_provers() {
        let crdt = test_crdt();
        let state = HypergraphState::new(crdt.clone());
        let genesis_data = get_mainnet_genesis_data().unwrap();

        establish_mainnet_genesis_provers(&state, &genesis_data).unwrap();
        state.commit().unwrap();

        // Should have 1 beacon + 5 archive = 6 provers
        // Each prover creates 2 vertices (prover + allocation) + 1 hyperedge
        // = 12 vertices + 6 hyperedges
        //
        // Verify beacon prover exists
        let b64 = base64::engine::general_purpose::STANDARD;
        let beacon_key = b64.decode(&genesis_data.beacon_bls48581_key).unwrap();
        let beacon_addr = materialize::prover_address_from_pubkey(&beacon_key).unwrap();
        let beacon_loc = quil_hypergraph::addressing::Location {
            app_address: GLOBAL_INTRINSIC_ADDRESS,
            data_address: beacon_addr,
        };
        assert!(crdt.lookup_vertex(&beacon_loc), "beacon prover should exist");

        // Verify each archive peer exists
        for (_peer_id, pubkey_hex) in &genesis_data.archive_peers {
            let pubkey = hex::decode(pubkey_hex).unwrap();
            let addr = materialize::prover_address_from_pubkey(&pubkey).unwrap();
            let loc = quil_hypergraph::addressing::Location {
                app_address: GLOBAL_INTRINSIC_ADDRESS,
                data_address: addr,
            };
            assert!(crdt.lookup_vertex(&loc), "archive prover should exist");
        }
    }

    #[test]
    fn make_genesis_qc_fields() {
        let frame = load_mainnet_genesis().unwrap();
        let qc = make_genesis_qc(&frame);

        assert_eq!(qc.rank, 0);
        assert_eq!(qc.filter, Vec::<u8>::new());
        assert_eq!(qc.frame_number, 244200);
        assert_eq!(qc.selector.len(), 32);
        assert_eq!(qc.timestamp, 0);

        let agg = qc.aggregate_signature.as_ref().unwrap();
        assert_eq!(agg.signature.len(), 74);
        assert_eq!(agg.public_key.as_ref().unwrap().key_value.len(), 585);
        assert_eq!(agg.bitmask, vec![0xFFu8; 32]);
    }

    // -----------------------------------------------------------------
    // Testnet genesis tests
    // -----------------------------------------------------------------

    /// Minimal no-op ShardsStore stub for testnet-genesis tests. The
    /// actual put/range behavior is exercised by integration tests
    /// against `RocksShardsStore`; here we just need a writable
    /// destination.
    struct StubShardsStore;
    impl ShardsStore for StubShardsStore {
        fn range_app_shards(&self) -> quil_types::error::Result<Vec<quil_types::store::ShardInfo>> {
            Ok(vec![])
        }
        fn get_app_shards(
            &self,
            _: &[u8],
            _: &[u32],
        ) -> quil_types::error::Result<Vec<quil_types::store::ShardInfo>> {
            Ok(vec![])
        }
        fn put_app_shard(
            &self,
            _: &dyn quil_types::store::Transaction,
            _: &quil_types::store::ShardInfo,
        ) -> quil_types::error::Result<()> {
            Ok(())
        }
        fn delete_app_shard(
            &self,
            _: &dyn quil_types::store::Transaction,
            _: &[u8],
            _: &[u32],
        ) -> quil_types::error::Result<()> {
            Ok(())
        }
    }

    fn stub_shards_store() -> StubShardsStore {
        StubShardsStore
    }

    /// Minimal in-memory ClockStore for testnet genesis tests.
    struct TestClockStore {
        frames: std::sync::Mutex<
            std::collections::HashMap<u64, global::GlobalFrame>,
        >,
        qc: std::sync::Mutex<Option<global::QuorumCertificate>>,
    }

    impl TestClockStore {
        fn new() -> Self {
            Self {
                frames: std::sync::Mutex::new(std::collections::HashMap::new()),
                qc: std::sync::Mutex::new(None),
            }
        }
    }

    /// No-op transaction for TestClockStore.
    struct TestTxn;
    impl quil_types::store::Transaction for TestTxn {
        fn get(&self, _: &[u8]) -> quil_types::error::Result<Option<Vec<u8>>> { Ok(None) }
        fn set(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
        fn commit(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
        fn delete(&self, _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
        fn abort(self: Box<Self>) -> quil_types::error::Result<()> { Ok(()) }
        fn new_iter(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<Box<dyn quil_types::store::Iterator>> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn delete_range(&self, _: &[u8], _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
        fn as_any(&self) -> &dyn std::any::Any { self }
    }

    impl ClockStore for TestClockStore {
        fn new_transaction(&self, _: bool) -> quil_types::error::Result<Box<dyn quil_types::store::Transaction>> {
            Ok(Box::new(TestTxn))
        }
        fn get_latest_global_clock_frame(&self) -> quil_types::error::Result<global::GlobalFrame> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn get_earliest_global_clock_frame(&self) -> quil_types::error::Result<global::GlobalFrame> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn get_global_clock_frame(&self, frame_number: u64) -> quil_types::error::Result<global::GlobalFrame> {
            self.frames.lock().unwrap().get(&frame_number).cloned()
                .ok_or_else(|| QuilError::NotFound("frame not found".into()))
        }
        fn put_global_clock_frame(&self, frame: &global::GlobalFrame, _: &dyn quil_types::store::Transaction) -> quil_types::error::Result<()> {
            if let Some(h) = frame.header.as_ref() {
                self.frames.lock().unwrap().insert(h.frame_number, frame.clone());
            }
            Ok(())
        }
        fn put_global_clock_frame_candidate(&self, _: &global::GlobalFrame, _: &dyn quil_types::store::Transaction) -> quil_types::error::Result<()> { Ok(()) }
        fn get_global_clock_frame_candidate(&self, _: u64, _: &[u8]) -> quil_types::error::Result<global::GlobalFrame> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn delete_global_clock_frame_range(&self, _: u64, _: u64) -> quil_types::error::Result<()> { Ok(()) }
        fn reset_global_clock_frames(&self) -> quil_types::error::Result<()> { Ok(()) }
        fn get_latest_certified_global_state(&self) -> quil_types::error::Result<global::GlobalProposal> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn get_earliest_certified_global_state(&self) -> quil_types::error::Result<global::GlobalProposal> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn get_certified_global_state(&self, _: u64) -> quil_types::error::Result<global::GlobalProposal> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn put_certified_global_state(&self, _: &global::GlobalProposal, _: &dyn quil_types::store::Transaction) -> quil_types::error::Result<()> { Ok(()) }
        fn get_latest_quorum_certificate(&self, _: &[u8]) -> quil_types::error::Result<global::QuorumCertificate> {
            self.qc.lock().unwrap().clone()
                .ok_or_else(|| QuilError::NotFound("no qc".into()))
        }
        fn get_quorum_certificate(&self, _: &[u8], _: u64) -> quil_types::error::Result<global::QuorumCertificate> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn put_quorum_certificate(&self, qc: &global::QuorumCertificate, _: &dyn quil_types::store::Transaction) -> quil_types::error::Result<()> {
            *self.qc.lock().unwrap() = Some(qc.clone());
            Ok(())
        }
        fn get_latest_timeout_certificate(&self, _: &[u8]) -> quil_types::error::Result<global::TimeoutCertificate> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn get_timeout_certificate(&self, _: &[u8], _: u64) -> quil_types::error::Result<global::TimeoutCertificate> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn put_timeout_certificate(&self, _: &global::TimeoutCertificate, _: &dyn quil_types::store::Transaction) -> quil_types::error::Result<()> { Ok(()) }
        fn get_latest_shard_clock_frame(&self, _: &[u8]) -> quil_types::error::Result<global::AppShardFrame> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn get_shard_clock_frame(&self, _: &[u8], _: u64, _: bool) -> quil_types::error::Result<global::AppShardFrame> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn commit_shard_clock_frame(&self, _: &[u8], _: u64, _: &[u8], _: &dyn quil_types::store::Transaction, _: bool) -> quil_types::error::Result<()> { Ok(()) }
        fn stage_shard_clock_frame(&self, _: &[u8], _: &global::AppShardFrame, _: &dyn quil_types::store::Transaction) -> quil_types::error::Result<()> { Ok(()) }
        fn get_staged_shard_clock_frame(&self, _: &[u8], _: u64, _: &[u8], _: bool) -> quil_types::error::Result<global::AppShardFrame> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn set_latest_shard_clock_frame_number(&self, _: &[u8], _: u64) -> quil_types::error::Result<()> { Ok(()) }
        fn delete_shard_clock_frame_range(&self, _: &[u8], _: u64, _: u64) -> quil_types::error::Result<()> { Ok(()) }
        fn reset_shard_clock_frames(&self, _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
        fn get_latest_certified_app_shard_state(&self, _: &[u8]) -> quil_types::error::Result<global::AppShardProposal> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn put_certified_app_shard_state(&self, _: &global::AppShardProposal, _: &dyn quil_types::store::Transaction) -> quil_types::error::Result<()> { Ok(()) }
        fn put_proposal_vote(&self, _: &dyn quil_types::store::Transaction, _: &global::ProposalVote) -> quil_types::error::Result<()> { Ok(()) }
        fn get_proposal_vote(&self, _: &[u8], _: u64, _: &[u8]) -> quil_types::error::Result<global::ProposalVote> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn get_proposal_votes(&self, _: &[u8], _: u64) -> quil_types::error::Result<Vec<global::ProposalVote>> { Ok(vec![]) }
        fn put_timeout_vote(&self, _: &dyn quil_types::store::Transaction, _: &global::TimeoutState) -> quil_types::error::Result<()> { Ok(()) }
        fn get_timeout_vote(&self, _: &[u8], _: u64, _: &[u8]) -> quil_types::error::Result<global::TimeoutState> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn get_timeout_votes(&self, _: &[u8], _: u64) -> quil_types::error::Result<Vec<global::TimeoutState>> { Ok(vec![]) }
        fn get_total_distance(&self, _: &[u8], _: u64, _: &[u8]) -> quil_types::error::Result<num_bigint::BigInt> {
            Err(QuilError::NotFound("stub".into()))
        }
        fn set_total_distance(&self, _: &[u8], _: u64, _: &[u8], _: &num_bigint::BigInt) -> quil_types::error::Result<()> { Ok(()) }
        fn get_peer_seniority_map(&self, _: &[u8]) -> quil_types::error::Result<std::collections::HashMap<String, u64>> {
            Ok(std::collections::HashMap::new())
        }
        fn put_peer_seniority_map(&self, _: &dyn quil_types::store::Transaction, _: &[u8], _: &std::collections::HashMap<String, u64>) -> quil_types::error::Result<()> { Ok(()) }
        fn compact_data(&self, _: &[u8]) -> quil_types::error::Result<()> { Ok(()) }
    }

    #[test]
    fn resolve_testnet_prover_keys_from_seed() {
        // Two 585-byte BLS keys concatenated as hex
        let key_a = vec![0xAAu8; 585];
        let key_b = vec![0xBBu8; 585];
        let mut seed_bytes = key_a.clone();
        seed_bytes.extend_from_slice(&key_b);
        let seed_hex = hex::encode(&seed_bytes);

        let keys = resolve_testnet_prover_keys(1, &seed_hex, &[0xCC; 585]).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], key_a);
        assert_eq!(keys[1], key_b);
    }

    #[test]
    fn resolve_testnet_prover_keys_invalid_length() {
        let bad_seed = hex::encode(vec![0xAA; 100]); // not a multiple of 585
        let result = resolve_testnet_prover_keys(1, &bad_seed, &[0xCC; 585]);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_testnet_prover_keys_empty_seed_uses_local() {
        let local_key = vec![0xDDu8; 585];
        let keys = resolve_testnet_prover_keys(1, "", &local_key).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], local_key);
    }

    #[test]
    fn resolve_testnet_prover_keys_network_99_uses_local() {
        let seed_hex = hex::encode(vec![0xAAu8; 585]);
        let local_key = vec![0xDDu8; 585];
        let keys = resolve_testnet_prover_keys(99, &seed_hex, &local_key).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], local_key);
    }

    #[test]
    fn resolve_testnet_prover_keys_strips_embedded_spaces() {
        // YAML folded scalars (`>` / `>-`) join lines with single spaces.
        let key_a = vec![0xAAu8; 585];
        let key_b = vec![0xBBu8; 585];
        let seed_hex = format!("{} {}", hex::encode(&key_a), hex::encode(&key_b));

        let keys = resolve_testnet_prover_keys(1, &seed_hex, &[0xCC; 585]).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], key_a);
        assert_eq!(keys[1], key_b);
    }

    #[test]
    fn resolve_testnet_prover_keys_strips_mixed_whitespace() {
        // Newlines, tabs, and leading/trailing whitespace must all be tolerated.
        let key_a = vec![0xAAu8; 585];
        let key_b = vec![0xBBu8; 585];
        let seed_hex = format!(
            "  {}\n\t{}\n",
            hex::encode(&key_a),
            hex::encode(&key_b),
        );

        let keys = resolve_testnet_prover_keys(1, &seed_hex, &[0xCC; 585]).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], key_a);
        assert_eq!(keys[1], key_b);
    }

    #[test]
    fn resolve_testnet_prover_keys_invalid_hex_char_still_errors() {
        // Non-whitespace garbage should still produce a decode error,
        // confirming the whitespace strip is not masking other invalid input.
        let valid = hex::encode(vec![0xAAu8; 585]);
        let seed_hex = format!("{} ZZ", valid);
        let result = resolve_testnet_prover_keys(1, &seed_hex, &[0xCC; 585]);
        assert!(result.is_err());
    }

    #[test]
    fn establish_testnet_reward_vertices_creates_rewards() {
        let crdt = test_crdt();
        let pubkey = vec![0xAAu8; 585];
        establish_testnet_reward_vertices(&[pubkey.clone()], &crdt).unwrap();

        // Verify reward vertex exists in QUIL_TOKEN domain
        let prover_address = materialize::prover_address_from_pubkey(&pubkey).unwrap();
        let reward_addr = materialize::reward_address(&prover_address).unwrap();
        let loc = quil_hypergraph::addressing::Location {
            app_address: quil_execution::domains::QUIL_TOKEN,
            data_address: reward_addr,
        };
        assert!(crdt.lookup_vertex(&loc), "reward vertex should exist");

        // Verify reward data
        let reward_data = crdt.get_vertex_data(&loc).expect("reward data should exist");
        let reward_tree = prover_registry::rebuild_vertex_tree_from_blob(&reward_data);
        let cls = "reward:ProverReward";

        // Verify type hash
        assert_eq!(
            quil_execution::global_schema::read_type(&reward_tree),
            Some("reward:ProverReward"),
        );

        // Verify DelegateAddress
        assert_eq!(
            quil_execution::global_schema::read_field(&reward_tree, cls, "DelegateAddress"),
            Some(reward_addr.to_vec()),
        );

        // Verify Balance = 10000 * 8_000_000_000
        let balance_data = quil_execution::global_schema::read_field(&reward_tree, cls, "Balance")
            .expect("Balance should be set");
        assert_eq!(balance_data.len(), 32);
        // Last 8 bytes should contain the value 80_000_000_000_000
        let mut expected_balance = [0u8; 32];
        let val = 10_000u64 * 8_000_000_000u64;
        expected_balance[24..32].copy_from_slice(&val.to_be_bytes());
        assert_eq!(balance_data, expected_balance.to_vec());
    }

    #[test]
    fn initialize_testnet_genesis_single_prover() {
        let crdt = test_crdt();
        let clock_store = TestClockStore::new();
        let pubkey = vec![0xEEu8; 585];

        let shards_store = stub_shards_store();
        let (frame, qc) = initialize_testnet_genesis_state(
            1,    // network
            "",   // empty seed -> use local key
            &pubkey,
            10000, // difficulty
            &clock_store,
            &shards_store,
            &crdt,
            &NoopInclusionProver,
        )
        .unwrap();

        // Verify frame header
        let h = frame.header.as_ref().expect("frame should have header");
        assert_eq!(h.frame_number, 0);
        assert_eq!(h.parent_selector, vec![0u8; 32]);
        assert_eq!(h.output, vec![0u8; 516]);
        assert_eq!(h.difficulty, 10000);
        assert!(h.timestamp > 0, "timestamp should be set to current time");
        assert_eq!(h.global_commitments.len(), 256);
        assert!(h.prover_tree_commitment.len() > 0, "prover tree commitment should be set");

        // Verify QC
        assert_eq!(qc.frame_number, 0);
        assert_eq!(qc.rank, 0);

        // Verify frame is stored and retrievable
        let stored = clock_store.get_global_clock_frame(0).unwrap();
        assert_eq!(
            stored.header.as_ref().unwrap().frame_number,
            0,
        );

        // Verify prover vertex exists in CRDT
        let prover_address = materialize::prover_address_from_pubkey(&pubkey).unwrap();
        let loc = quil_hypergraph::addressing::Location {
            app_address: GLOBAL_INTRINSIC_ADDRESS,
            data_address: prover_address,
        };
        assert!(crdt.lookup_vertex(&loc), "prover vertex should exist");

        // Verify allocation vertex exists
        let alloc_address = materialize::allocation_address(&pubkey, &[]).unwrap();
        let alloc_loc = quil_hypergraph::addressing::Location {
            app_address: GLOBAL_INTRINSIC_ADDRESS,
            data_address: alloc_address,
        };
        assert!(crdt.lookup_vertex(&alloc_loc), "allocation vertex should exist");

        // Verify reward vertex exists in QUIL_TOKEN domain
        let reward_addr = materialize::reward_address(&prover_address).unwrap();
        let reward_loc = quil_hypergraph::addressing::Location {
            app_address: quil_execution::domains::QUIL_TOKEN,
            data_address: reward_addr,
        };
        assert!(crdt.lookup_vertex(&reward_loc), "reward vertex should exist");
    }

    #[test]
    fn initialize_testnet_genesis_idempotent() {
        let crdt = test_crdt();
        let clock_store = TestClockStore::new();
        let pubkey = vec![0xFFu8; 585];

        let shards_store = stub_shards_store();
        // First call
        let (frame1, _qc1) = initialize_testnet_genesis_state(
            1, "", &pubkey, 10000, &clock_store, &shards_store, &crdt, &NoopInclusionProver,
        ).unwrap();

        // Second call should return existing frame
        let (frame2, _qc2) = initialize_testnet_genesis_state(
            1, "", &pubkey, 10000, &clock_store, &shards_store, &crdt, &NoopInclusionProver,
        ).unwrap();

        assert_eq!(
            frame1.header.as_ref().unwrap().frame_number,
            frame2.header.as_ref().unwrap().frame_number,
        );
    }

    #[test]
    fn initialize_genesis_dispatches_to_testnet() {
        let crdt = test_crdt();
        let clock_store = TestClockStore::new();
        let pubkey = vec![0xAAu8; 585];

        // network=1 should go to testnet path
        let shards_store = stub_shards_store();

        let (frame, _qc) = initialize_genesis(
            1, "", &pubkey, 10000, &clock_store, &shards_store, &crdt, &NoopInclusionProver,
        ).unwrap();

        let h = frame.header.as_ref().unwrap();
        assert_eq!(h.frame_number, 0, "testnet genesis should be frame 0");
    }
}

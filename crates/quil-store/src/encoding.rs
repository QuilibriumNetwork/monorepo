/// Key encoding matching Go's Pebble format byte-for-byte.
/// Constants and key builders must produce identical bytes to Go's
/// `node/store/constants.go` + `node/store/clock.go`.
/// All integers are big-endian.

// -----------------------------------------------------------------------
// Store type prefixes (first byte) — from Go's constants.go:4-20
// -----------------------------------------------------------------------

pub const CLOCK_FRAME: u8 = 0x00;
pub const PROVING_KEY: u8 = 0x01;
pub const PROVING_KEY_STAGED: u8 = 0x02;
pub const KEY_BUNDLE: u8 = 0x03;
pub const DATA_PROOF: u8 = 0x04;
pub const DATA_TIME_PROOF: u8 = 0x05;
pub const PEERSTORE: u8 = 0x06;
pub const COIN: u8 = 0x07;
pub const PROOF: u8 = 0x08;
pub const HYPERGRAPH_SHARD: u8 = 0x09;
pub const SHARD: u8 = 0x0A;
pub const INBOX: u8 = 0x0B;
pub const CONSENSUS: u8 = 0x0C;
/// Sub-discriminators under CONSENSUS — match Go's
/// `node/store/constants.go:178-179`. The Rust consensus store
/// historically wrote these at top-level prefixes 0x01/0x02 which
/// collide with PROVING_KEY / PROVING_KEY_STAGED. Moved here so the
/// keyspace is internally consistent and survives a Go store
/// migration without overwriting key-bundle data.
pub const CONSENSUS_STATE: u8 = 0x00;
pub const CONSENSUS_LIVENESS: u8 = 0x01;
pub const MIGRATION: u8 = 0xF0;
pub const WORKER: u8 = 0xFF;

// Worker store sub-prefixes (second byte) — Go parity with
// `node/store/constants.go:172-173`.
pub const WORKER_BY_CORE: u8 = 0x00;
pub const WORKER_BY_FILTER: u8 = 0x01;

// -----------------------------------------------------------------------
// Clock store indexes (second byte) — from Go's constants.go:23-76
// -----------------------------------------------------------------------

pub const CLOCK_GLOBAL_FRAME: u8 = 0x00;
pub const CLOCK_SHARD_FRAME: u8 = 0x01;
pub const CLOCK_SHARD_STAGED: u8 = 0x02;
pub const CLOCK_SHARD_FRAME_FRECENCY: u8 = 0x03;
pub const CLOCK_TOTAL_DISTANCE: u8 = 0x04;
pub const CLOCK_COMPACTION: u8 = 0x05;
pub const CLOCK_PEER_SENIORITY: u8 = 0x06;
pub const CLOCK_APP_CERTIFIED_STATE: u8 = 0x07;
pub const CLOCK_GLOBAL_FRAME_REQUEST: u8 = 0x08;
pub const CLOCK_GLOBAL_CERTIFIED_STATE: u8 = 0x09;
pub const CLOCK_SHARD_CERTIFIED_STATE: u8 = 0x0A;
pub const CLOCK_QUORUM_CERTIFICATE: u8 = 0x0B;
pub const CLOCK_TIMEOUT_CERTIFICATE: u8 = 0x0C;
pub const CLOCK_PROPOSAL_VOTE: u8 = 0x0D;
pub const CLOCK_TIMEOUT_VOTE: u8 = 0x0E;
pub const CLOCK_GLOBAL_FRAME_CANDIDATE: u8 = 0x0F;
/// Per-frame-candidate request bundles. Mirrors Go's
/// `CLOCK_GLOBAL_FRAME_REQUEST_CANDIDATE` (`node/store/constants.go:75`).
pub const CLOCK_GLOBAL_FRAME_REQUEST_CANDIDATE: u8 = 0xF8;

pub const INDEX_EARLIEST: u8 = 0x10;
pub const INDEX_LATEST: u8 = 0x20;
pub const INDEX_PARENT: u8 = 0x30;

// -----------------------------------------------------------------------
// Hypergraph store indexes — from Go's constants.go:98-130
// -----------------------------------------------------------------------

pub const HG_SHARD_COMMIT: u8 = 0x00;
pub const HG_VERTEX_ADDS_TREE_NODE: u8 = 0x02;
pub const HG_VERTEX_REMOVES_TREE_NODE: u8 = 0x12;
pub const HG_HYPEREDGE_ADDS_TREE_NODE: u8 = 0x03;
pub const HG_HYPEREDGE_REMOVES_TREE_NODE: u8 = 0x13;
pub const HG_VERTEX_ADDS_TREE_NODE_BY_PATH: u8 = 0x22;
pub const HG_VERTEX_REMOVES_TREE_NODE_BY_PATH: u8 = 0x32;
pub const HG_VERTEX_ADDS_SHARD_COMMIT: u8 = 0xE0;
pub const HG_VERTEX_REMOVES_SHARD_COMMIT: u8 = 0xE1;
pub const HG_HYPEREDGE_ADDS_SHARD_COMMIT: u8 = 0xE2;
pub const HG_HYPEREDGE_REMOVES_SHARD_COMMIT: u8 = 0xE3;
pub const HG_ALT_SHARD_COMMIT: u8 = 0xE4;
pub const HG_ALT_SHARD_COMMIT_LATEST: u8 = 0xE5;
pub const HG_ALT_SHARD_ADDRESS_INDEX: u8 = 0xE6;
pub const HG_VERTEX_DATA: u8 = 0xF0;
pub const HG_VERTEX_ADDS_CHANGE_RECORD: u8 = 0x42;
pub const HG_VERTEX_REMOVES_CHANGE_RECORD: u8 = 0x52;
pub const HG_HYPEREDGE_ADDS_CHANGE_RECORD: u8 = 0x43;
pub const HG_HYPEREDGE_REMOVES_CHANGE_RECORD: u8 = 0x53;
pub const HG_HYPERGRAPH_COVERED_PREFIX: u8 = 0xFA;
pub const HG_VERTEX_ADDS_TREE_ROOT: u8 = 0xFC;
pub const HG_VERTEX_REMOVES_TREE_ROOT: u8 = 0xFD;
pub const HG_HYPEREDGE_ADDS_TREE_ROOT: u8 = 0xFE;
pub const HG_HYPEREDGE_REMOVES_TREE_ROOT: u8 = 0xFF;

// Rust-only blob prefixes for the lazy tree cache path.
// These don't conflict with Go's hypergraph indexes (which live
// under the HYPERGRAPH_SHARD=0x09 store prefix, not standalone).
pub const HG_TREE_BLOB_PREFIX: u8 = 0x2F;
pub const HG_VERTEX_DATA_PREFIX: u8 = 0x30;

// Per-node lazy tree backend prefixes. Each radix-trie node lives at
// its own RocksDB key, so loading a 700 GB shard's tree doesn't require
// materializing the whole thing into memory. The migration tool reads
// Go's `[0x09, {0x02,0x12,0x03,0x13}, ...]` per-node entries, decodes
// them via `tries.DeserializeLeafNode`/`DeserializeBranchNode`, then
// re-emits each node into the Rust layout below (using
// `quil_tries::serialize_node_solo`). Go's on-disk node bytes are
// never read by Rust — the migration is the only point of contact.
//
// [0x33, set_byte, phase_byte, l1(1), l2(32), node_key]            → solo-node bytes
// [0x34, set_byte, phase_byte, l1(1), l2(32), path_i32_BE × depth] → by-key pointer
//
// `set_byte` and `phase_byte` are the same single-byte encoding as
// the legacy blob layout (see `set_type_byte`/`phase_type_byte`).
//
// The by-path index value is the *full RocksDB by-key key* for that
// node — the lazy walker SeekGE's the by-path index to find the
// deepest covering branch (mirrors Go's `GetNodeByPath`), then issues
// a second `Get` against the returned by-key pointer to fetch the
// node bytes. This is exactly the dual-index scheme Go uses, just
// reshuffled into Rust's keyspace.
pub const HG_TREE_NODE_BY_KEY: u8 = 0x33;
pub const HG_TREE_NODE_BY_PATH: u8 = 0x34;

// -----------------------------------------------------------------------
// Coin store indexes — from Go's constants.go:78-86
// -----------------------------------------------------------------------

pub const COIN_BY_ADDRESS: u8 = 0x00;
pub const COIN_BY_OWNER: u8 = 0x01;
pub const TRANSACTION_BY_ADDRESS: u8 = 0x02;
pub const TRANSACTION_BY_OWNER: u8 = 0x03;
pub const PENDING_TRANSACTION_BY_ADDRESS: u8 = 0x04;
pub const PENDING_TRANSACTION_BY_OWNER: u8 = 0x05;

// -----------------------------------------------------------------------
// Key store indexes — from Go's constants.go:132-152
// -----------------------------------------------------------------------

pub const KEY_DATA: u8 = 0x00;
pub const KEY_IDENTITY: u8 = 0x30;
pub const KEY_PROVING: u8 = 0x31;
pub const KEY_CROSS_SIGNATURE: u8 = 0x40;
pub const KEY_X448_SIGNED_KEY_BY_ID: u8 = 0x50;
pub const KEY_X448_SIGNED_KEY_BY_PARENT: u8 = 0x51;
pub const KEY_X448_SIGNED_KEY_BY_PURPOSE: u8 = 0x52;
pub const KEY_X448_SIGNED_KEY_BY_EXPIRY: u8 = 0x53;
pub const KEY_DECAF448_SIGNED_KEY_BY_ID: u8 = 0x54;
pub const KEY_DECAF448_SIGNED_KEY_BY_PARENT: u8 = 0x55;
pub const KEY_DECAF448_SIGNED_KEY_BY_PURPOSE: u8 = 0x56;
pub const KEY_DECAF448_SIGNED_KEY_BY_EXPIRY: u8 = 0x57;

// -----------------------------------------------------------------------
// Shard store indexes — from Go's constants.go:155-157
// -----------------------------------------------------------------------

pub const APP_SHARD_DATA: u8 = 0x00;

// -----------------------------------------------------------------------
// Dispatch (inbox) store indexes — from Go's constants.go:160-168
// -----------------------------------------------------------------------

pub const INBOX_MESSAGE: u8 = 0x00;
pub const INBOX_MESSAGE_DATA: u8 = 0x01;
pub const INBOX_MESSAGE_BY_ADDR: u8 = 0x02;
pub const INBOX_HUB_BY_ADDR: u8 = 0x10;
pub const INBOX_HUB_ADDS: u8 = 0x11;
pub const INBOX_HUB_DELETES: u8 = 0x12;

// -----------------------------------------------------------------------
// Clock store key builders — matching Go's clock.go exactly
// -----------------------------------------------------------------------

/// [0x00, 0x00, frame_number(8 BE)]
pub fn clock_global_frame_key(frame_number: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(10);
    key.push(CLOCK_FRAME);
    key.push(CLOCK_GLOBAL_FRAME);
    key.extend_from_slice(&frame_number.to_be_bytes());
    key
}

/// [0x00, 0x08, frame_number(8 BE), request_index(2 BE)]
pub fn clock_global_frame_request_key(frame_number: u64, request_index: u16) -> Vec<u8> {
    let mut key = Vec::with_capacity(12);
    key.push(CLOCK_FRAME);
    key.push(CLOCK_GLOBAL_FRAME_REQUEST);
    key.extend_from_slice(&frame_number.to_be_bytes());
    key.extend_from_slice(&request_index.to_be_bytes());
    key
}

/// [0x00, 0x20]
pub fn clock_global_latest_index() -> Vec<u8> {
    vec![CLOCK_FRAME, INDEX_LATEST | CLOCK_GLOBAL_FRAME]
}

/// [0x00, 0x10]
pub fn clock_global_earliest_index() -> Vec<u8> {
    vec![CLOCK_FRAME, INDEX_EARLIEST | CLOCK_GLOBAL_FRAME]
}

/// [0x00, 0x0F, frame_number(8 BE), selector(32 bytes)]
pub fn clock_global_frame_candidate_key(frame_number: u64, selector: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(10 + 32);
    key.push(CLOCK_FRAME);
    key.push(CLOCK_GLOBAL_FRAME_CANDIDATE);
    key.extend_from_slice(&frame_number.to_be_bytes());
    key.extend_from_slice(&right_align(selector, 32));
    key
}

/// [0x00, 0x2F]
pub fn clock_global_frame_candidate_latest_index() -> Vec<u8> {
    vec![CLOCK_FRAME, INDEX_LATEST | CLOCK_GLOBAL_FRAME_CANDIDATE]
}

/// Go's `clockGlobalFrameRequestCandidateKey`:
/// `[0x00, 0xF8, selector, frame_number(8 BE), request_index(2 BE)]`.
/// Note Go appends selector with no width-aligning, so the selector
/// bytes flow into the key as-is.
pub fn clock_global_frame_request_candidate_key(
    selector: &[u8],
    frame_number: u64,
    request_index: u16,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + selector.len() + 8 + 2);
    key.push(CLOCK_FRAME);
    key.push(CLOCK_GLOBAL_FRAME_REQUEST_CANDIDATE);
    key.extend_from_slice(selector);
    key.extend_from_slice(&frame_number.to_be_bytes());
    key.extend_from_slice(&request_index.to_be_bytes());
    key
}

/// [0x00, 0x09, rank(8 BE)]
pub fn clock_global_certified_state_key(rank: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(10);
    key.push(CLOCK_FRAME);
    key.push(CLOCK_GLOBAL_CERTIFIED_STATE);
    key.extend_from_slice(&rank.to_be_bytes());
    key
}

/// [0x00, 0x29]
pub fn clock_global_certified_state_latest_index() -> Vec<u8> {
    vec![CLOCK_FRAME, INDEX_LATEST | CLOCK_GLOBAL_CERTIFIED_STATE]
}

/// [0x00, 0x19]
pub fn clock_global_certified_state_earliest_index() -> Vec<u8> {
    vec![CLOCK_FRAME, INDEX_EARLIEST | CLOCK_GLOBAL_CERTIFIED_STATE]
}

/// Go's clockQuorumCertificateKey: [0x00, 0x0B, rank(8 BE)]
/// NOTE: Go ignores the filter parameter — key does NOT include filter.
pub fn clock_quorum_certificate_key(rank: u64, _filter: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(10);
    key.push(CLOCK_FRAME);
    key.push(CLOCK_QUORUM_CERTIFICATE);
    key.extend_from_slice(&rank.to_be_bytes());
    key
}

/// [0x00, 0x2B, filter...]
pub fn clock_quorum_certificate_latest_index(filter: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + filter.len());
    key.push(CLOCK_FRAME);
    key.push(INDEX_LATEST | CLOCK_QUORUM_CERTIFICATE);
    key.extend_from_slice(filter);
    key
}

/// [0x00, 0x0C, rank(8 BE)]
pub fn clock_timeout_certificate_key(rank: u64, _filter: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(10);
    key.push(CLOCK_FRAME);
    key.push(CLOCK_TIMEOUT_CERTIFICATE);
    key.extend_from_slice(&rank.to_be_bytes());
    key
}

/// [0x00, 0x2C, filter...]
pub fn clock_timeout_certificate_latest_index(filter: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + filter.len());
    key.push(CLOCK_FRAME);
    key.push(INDEX_LATEST | CLOCK_TIMEOUT_CERTIFICATE);
    key.extend_from_slice(filter);
    key
}

/// [0x00, 0x1C, filter...]
pub fn clock_timeout_certificate_earliest_index(filter: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + filter.len());
    key.push(CLOCK_FRAME);
    key.push(INDEX_EARLIEST | CLOCK_TIMEOUT_CERTIFICATE);
    key.extend_from_slice(filter);
    key
}

/// Go's `clockShardParentIndexKey`:
/// `[0x00, 0x31, frame_number(8 BE), filter..., right_align(selector, 32)]`
/// (`CLOCK_SHARD_FRAME_INDEX_PARENT` = `0x30 | CLOCK_SHARD_FRAME` = `0x31`)
pub fn clock_shard_parent_index_key(
    filter: &[u8],
    frame_number: u64,
    selector: &[u8],
) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + 8 + filter.len() + 32);
    k.push(CLOCK_FRAME);
    k.push(INDEX_PARENT | CLOCK_SHARD_FRAME);
    k.extend_from_slice(&frame_number.to_be_bytes());
    k.extend_from_slice(filter);
    k.extend_from_slice(&right_align(selector, 32));
    k
}

/// Go's `clockProverTrieKey`:
/// `[0x00, 0x03, ring(2 BE), frame_number(8 BE), filter...]`
pub fn clock_prover_trie_key(filter: &[u8], ring: u16, frame_number: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + 2 + 8 + filter.len());
    k.push(CLOCK_FRAME);
    k.push(CLOCK_SHARD_FRAME_FRECENCY);
    k.extend_from_slice(&ring.to_be_bytes());
    k.extend_from_slice(&frame_number.to_be_bytes());
    k.extend_from_slice(filter);
    k
}

/// Go's `clockDataTotalDistanceKey`:
/// `[0x00, 0x04, frame_number(8 BE), filter..., right_align(selector, 32)]`
pub fn clock_data_total_distance_key(
    filter: &[u8],
    frame_number: u64,
    selector: &[u8],
) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + 8 + filter.len() + 32);
    k.push(CLOCK_FRAME);
    k.push(CLOCK_TOTAL_DISTANCE);
    k.extend_from_slice(&frame_number.to_be_bytes());
    k.extend_from_slice(filter);
    k.extend_from_slice(&right_align(selector, 32));
    k
}

// -----------------------------------------------------------------------
// Shard frame key builders — matching Go's clock.go argument order
// -----------------------------------------------------------------------

pub fn clock_shard_frame_key(filter: &[u8], frame_number: u64) -> Vec<u8> {
    let mut k = vec![CLOCK_FRAME, CLOCK_SHARD_FRAME];
    k.extend_from_slice(filter);
    k.extend_from_slice(&frame_number.to_be_bytes());
    k
}

pub fn clock_shard_latest_index(filter: &[u8]) -> Vec<u8> {
    let mut k = vec![CLOCK_FRAME, INDEX_LATEST | CLOCK_SHARD_FRAME];
    k.extend_from_slice(filter);
    k
}

pub fn clock_shard_staged_key(selector: &[u8], frame_number: u64) -> Vec<u8> {
    let mut k = vec![CLOCK_FRAME, CLOCK_SHARD_STAGED];
    k.extend_from_slice(selector);
    k.extend_from_slice(&frame_number.to_be_bytes());
    k
}

/// Go: clockProposalVoteKey(rank, filter, identity)
/// Key: [0x00, 0x0D, rank(8 BE), filter..., identity...]
pub fn clock_proposal_vote_key(filter: &[u8], rank: u64, identity: &[u8]) -> Vec<u8> {
    let mut k = vec![CLOCK_FRAME, CLOCK_PROPOSAL_VOTE];
    k.extend_from_slice(&rank.to_be_bytes());
    k.extend_from_slice(filter);
    k.extend_from_slice(identity);
    k
}

pub fn clock_proposal_vote_prefix(filter: &[u8], rank: u64) -> Vec<u8> {
    let mut k = vec![CLOCK_FRAME, CLOCK_PROPOSAL_VOTE];
    k.extend_from_slice(&rank.to_be_bytes());
    k.extend_from_slice(filter);
    k
}

/// Go: clockTimeoutVoteKey(rank, filter, identity)
/// Key: [0x00, 0x0E, rank(8 BE), filter..., identity...]
pub fn clock_timeout_vote_key(filter: &[u8], rank: u64, identity: &[u8]) -> Vec<u8> {
    let mut k = vec![CLOCK_FRAME, CLOCK_TIMEOUT_VOTE];
    k.extend_from_slice(&rank.to_be_bytes());
    k.extend_from_slice(filter);
    k.extend_from_slice(identity);
    k
}

pub fn clock_timeout_vote_prefix(filter: &[u8], rank: u64) -> Vec<u8> {
    let mut k = vec![CLOCK_FRAME, CLOCK_TIMEOUT_VOTE];
    k.extend_from_slice(&rank.to_be_bytes());
    k.extend_from_slice(filter);
    k
}

pub fn clock_total_distance_key(filter: &[u8], frame_number: u64, selector: &[u8]) -> Vec<u8> {
    let mut k = vec![CLOCK_FRAME, CLOCK_TOTAL_DISTANCE];
    k.extend_from_slice(filter);
    k.extend_from_slice(&frame_number.to_be_bytes());
    k.extend_from_slice(selector);
    k
}

pub fn clock_peer_seniority_key(filter: &[u8]) -> Vec<u8> {
    let mut k = vec![CLOCK_FRAME, CLOCK_PEER_SENIORITY];
    k.extend_from_slice(filter);
    k
}

pub fn clock_app_certified_state_key(filter: &[u8], rank: u64) -> Vec<u8> {
    let mut k = vec![CLOCK_FRAME, CLOCK_APP_CERTIFIED_STATE];
    k.extend_from_slice(filter);
    k.extend_from_slice(&rank.to_be_bytes());
    k
}

pub fn clock_app_certified_state_latest_index(filter: &[u8]) -> Vec<u8> {
    let mut k = vec![CLOCK_FRAME, INDEX_LATEST | CLOCK_APP_CERTIFIED_STATE];
    k.extend_from_slice(filter);
    k
}

/// Shard certified state: [0x00, 0x0A, rank(8 BE), filter...]
pub fn clock_shard_certified_state_key(rank: u64, filter: &[u8]) -> Vec<u8> {
    let mut k = vec![CLOCK_FRAME, CLOCK_SHARD_CERTIFIED_STATE];
    k.extend_from_slice(&rank.to_be_bytes());
    k.extend_from_slice(filter);
    k
}

// -----------------------------------------------------------------------
// Hypergraph shard commit key builders — using Go's HYPERGRAPH_SHARD=0x09
// -----------------------------------------------------------------------

/// Shard commit type discriminators matching Go's 0xE0-0xE3.
pub fn shard_commit_type_byte(phase_type: &str, set_type: &str) -> u8 {
    match (set_type, phase_type) {
        ("vertex", "adds") => HG_VERTEX_ADDS_SHARD_COMMIT,
        ("vertex", "removes") => HG_VERTEX_REMOVES_SHARD_COMMIT,
        ("hyperedge", "adds") => HG_HYPEREDGE_ADDS_SHARD_COMMIT,
        ("hyperedge", "removes") => HG_HYPEREDGE_REMOVES_SHARD_COMMIT,
        _ => 0xFF,
    }
}

/// Shard commit key matching Go: [0x09, frame_number(8 BE), commit_type, shard_address...]
pub fn hypergraph_shard_commit_key(
    frame_number: u64,
    phase_type: &str,
    set_type: &str,
    shard_address: &[u8],
) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 8 + 1 + shard_address.len());
    k.push(HYPERGRAPH_SHARD);
    k.extend_from_slice(&frame_number.to_be_bytes());
    k.push(shard_commit_type_byte(phase_type, set_type));
    k.extend_from_slice(shard_address);
    k
}

/// Prefix for all shard commits at a given frame: [0x09, frame_number(8 BE)]
pub fn hypergraph_shard_commit_frame_prefix(frame_number: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 8);
    k.push(HYPERGRAPH_SHARD);
    k.extend_from_slice(&frame_number.to_be_bytes());
    k
}

/// Alt shard commit key: `[0x09, 0xE4, frame_number(8 BE), shard_address...]`.
/// Matches Go's `hypergraphAltShardCommitKey`.
pub fn hypergraph_alt_shard_commit_key(
    frame_number: u64,
    shard_address: &[u8],
) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + 8 + shard_address.len());
    k.push(HYPERGRAPH_SHARD);
    k.push(HG_ALT_SHARD_COMMIT);
    k.extend_from_slice(&frame_number.to_be_bytes());
    k.extend_from_slice(shard_address);
    k
}

/// Latest-frame marker for an alt shard: `[0x09, 0xE5, shard_address...]`.
pub fn hypergraph_alt_shard_commit_latest_key(shard_address: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + shard_address.len());
    k.push(HYPERGRAPH_SHARD);
    k.push(HG_ALT_SHARD_COMMIT_LATEST);
    k.extend_from_slice(shard_address);
    k
}

/// Address existence index for iterating alt shards.
pub fn hypergraph_alt_shard_address_index_key(shard_address: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + shard_address.len());
    k.push(HYPERGRAPH_SHARD);
    k.push(HG_ALT_SHARD_ADDRESS_INDEX);
    k.extend_from_slice(shard_address);
    k
}

/// Prefix for iterating all alt shard address index entries.
pub fn hypergraph_alt_shard_address_prefix() -> Vec<u8> {
    vec![HYPERGRAPH_SHARD, HG_ALT_SHARD_ADDRESS_INDEX]
}

/// Top-level covered-prefix key — Go writes/reads this at
/// `[0x09, 0xFA]` (see `node/store/hypergraph.go:727`).
pub fn hypergraph_covered_prefix_key() -> Vec<u8> {
    vec![HYPERGRAPH_SHARD, HG_HYPERGRAPH_COVERED_PREFIX]
}

/// Mirror of Go's `hypergraphChangeRecordKey`:
/// `[0x09, change_type, l1(3), l2(32), frame_number(8 BE), key...]`.
/// Returns `None` when the `set_type` / `phase_type` pair doesn't map
/// to a known change-record discriminator (Go silently writes a
/// zero-byte; Rust prefers explicit None so callers can guard).
pub fn hypergraph_change_record_key(
    set_type: &str,
    phase_type: &str,
    shard_key: &quil_types::store::ShardKey,
    frame_number: u64,
    key: &[u8],
) -> Option<Vec<u8>> {
    let change_type = change_record_type_byte(set_type, phase_type)?;
    let mut k = Vec::with_capacity(2 + 3 + 32 + 8 + key.len());
    k.push(HYPERGRAPH_SHARD);
    k.push(change_type);
    k.extend_from_slice(&shard_key.l1);
    k.extend_from_slice(&shard_key.l2);
    k.extend_from_slice(&frame_number.to_be_bytes());
    k.extend_from_slice(key);
    Some(k)
}

/// Mirror of Go's per-set/phase change-record discriminator switch
/// (see `node/store/hypergraph.go:612-628`).
pub fn change_record_type_byte(set_type: &str, phase_type: &str) -> Option<u8> {
    match (set_type, phase_type) {
        ("vertex", "adds") => Some(HG_VERTEX_ADDS_CHANGE_RECORD),
        ("vertex", "removes") => Some(HG_VERTEX_REMOVES_CHANGE_RECORD),
        ("hyperedge", "adds") => Some(HG_HYPEREDGE_ADDS_CHANGE_RECORD),
        ("hyperedge", "removes") => Some(HG_HYPEREDGE_REMOVES_CHANGE_RECORD),
        _ => None,
    }
}

/// Prefix used by `reap_old_changesets` to enumerate every tree-root
/// entry under HYPERGRAPH_SHARD. Go iterates
/// `[0x09, VERTEX_ADDS_TREE_ROOT]..[0x0A, 0x00]` (see
/// `node/store/hypergraph.go:1846-1848`).
pub fn hypergraph_tree_roots_iter_bounds() -> (Vec<u8>, Vec<u8>) {
    (
        vec![HYPERGRAPH_SHARD, HG_VERTEX_ADDS_TREE_ROOT],
        vec![HYPERGRAPH_SHARD + 1, 0x00],
    )
}

// -----------------------------------------------------------------------
// Hypergraph tree blob keys (Rust lazy-cache path)
// -----------------------------------------------------------------------

pub fn hypergraph_tree_blob_key(
    set_type: &str,
    phase_type: &str,
    shard_key: &quil_types::store::ShardKey,
) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 1 + 1 + 3 + 32);
    k.push(HG_TREE_BLOB_PREFIX);
    k.push(set_type_byte(set_type));
    k.push(phase_type_byte(phase_type));
    k.extend_from_slice(&shard_key.l1);
    k.extend_from_slice(&shard_key.l2);
    k
}

pub fn hypergraph_vertex_data_prefix(
    set_type: &str,
    phase_type: &str,
    shard_key: &quil_types::store::ShardKey,
) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 1 + 1 + 3 + 32);
    k.push(HG_VERTEX_DATA_PREFIX);
    k.push(set_type_byte(set_type));
    k.push(phase_type_byte(phase_type));
    k.extend_from_slice(&shard_key.l1);
    k.extend_from_slice(&shard_key.l2);
    k
}

pub fn hypergraph_vertex_data_key(
    set_type: &str,
    phase_type: &str,
    shard_key: &quil_types::store::ShardKey,
    vertex_key: &[u8],
) -> Vec<u8> {
    let mut k = hypergraph_vertex_data_prefix(set_type, phase_type, shard_key);
    k.extend_from_slice(vertex_key);
    k
}

// -----------------------------------------------------------------------
// Per-node lazy tree backend key builders.
//
// `node_key` is whatever bytes the in-memory tree uses as the node's
// identity (Go uses sha3 of the path; Rust just hands the same bytes
// through, since the value isn't interpreted by the store).
// `path` is the radix-trie nibble path for this node, as a slice of
// i32 nibbles big-endian-encoded into the key.
// -----------------------------------------------------------------------

pub fn hypergraph_tree_node_by_key_prefix(
    set_type: &str,
    phase_type: &str,
    shard_key: &quil_types::store::ShardKey,
) -> Vec<u8> {
    let mut k = Vec::with_capacity(3 + 1 + 32);
    k.push(HG_TREE_NODE_BY_KEY);
    k.push(set_type_byte(set_type));
    k.push(phase_type_byte(phase_type));
    k.extend_from_slice(&shard_key.l1);
    k.extend_from_slice(&shard_key.l2);
    k
}

pub fn hypergraph_tree_node_by_key(
    set_type: &str,
    phase_type: &str,
    shard_key: &quil_types::store::ShardKey,
    node_key: &[u8],
) -> Vec<u8> {
    let mut k = hypergraph_tree_node_by_key_prefix(set_type, phase_type, shard_key);
    k.extend_from_slice(node_key);
    k
}

pub fn hypergraph_tree_node_by_path_prefix(
    set_type: &str,
    phase_type: &str,
    shard_key: &quil_types::store::ShardKey,
) -> Vec<u8> {
    let mut k = Vec::with_capacity(3 + 1 + 32);
    k.push(HG_TREE_NODE_BY_PATH);
    k.push(set_type_byte(set_type));
    k.push(phase_type_byte(phase_type));
    k.extend_from_slice(&shard_key.l1);
    k.extend_from_slice(&shard_key.l2);
    k
}

/// Path is encoded as one big-endian u64 per nibble. Go writes nibbles
/// in by-path keys as `binary.BigEndian.AppendUint64(key, uint64(p))`
/// at `node/store/hypergraph.go:553` — 8 bytes per nibble. The earlier
/// Rust port used 4 bytes (i32), which made every cross-implementation
/// SeekGE land on the wrong sort position and miss every migrated
/// child entry. Match Go exactly here.
pub fn hypergraph_tree_node_by_path(
    set_type: &str,
    phase_type: &str,
    shard_key: &quil_types::store::ShardKey,
    path: &[i32],
) -> Vec<u8> {
    let mut k = hypergraph_tree_node_by_path_prefix(set_type, phase_type, shard_key);
    for &p in path {
        k.extend_from_slice(&(p as u64).to_be_bytes());
    }
    k
}

// -----------------------------------------------------------------------
// Consensus store key builders. `[CONSENSUS(0x0C), CONSENSUS_STATE(0x00),
// filter]` and `[CONSENSUS(0x0C), CONSENSUS_LIVENESS(0x01), filter]`
// — same layout Go's `node/store/consensus.go` uses, so a node that
// migrated from Go writes back into the same keyspace.
// -----------------------------------------------------------------------

pub fn consensus_state_key(filter: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + filter.len());
    k.push(CONSENSUS);
    k.push(CONSENSUS_STATE);
    k.extend_from_slice(filter);
    k
}

pub fn consensus_liveness_key(filter: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + filter.len());
    k.push(CONSENSUS);
    k.push(CONSENSUS_LIVENESS);
    k.extend_from_slice(filter);
    k
}

// -----------------------------------------------------------------------
// Token store key builders
// -----------------------------------------------------------------------

pub fn coin_key(address: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + address.len());
    key.push(COIN);
    key.push(COIN_BY_ADDRESS);
    key.extend_from_slice(address);
    key
}

pub fn coin_by_owner_key(owner: &[u8], address: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + owner.len() + address.len());
    key.push(COIN);
    key.push(COIN_BY_OWNER);
    key.extend_from_slice(owner);
    key.extend_from_slice(address);
    key
}

pub fn transaction_key(domain: &[u8], address: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + domain.len() + address.len());
    key.push(COIN);
    key.push(TRANSACTION_BY_ADDRESS);
    key.extend_from_slice(domain);
    key.extend_from_slice(address);
    key
}

pub fn transaction_by_owner_key(domain: &[u8], owner: &[u8], address: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + domain.len() + owner.len() + address.len());
    key.push(COIN);
    key.push(TRANSACTION_BY_OWNER);
    key.extend_from_slice(domain);
    key.extend_from_slice(owner);
    key.extend_from_slice(address);
    key
}

pub fn pending_transaction_key(domain: &[u8], address: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + domain.len() + address.len());
    key.push(COIN);
    key.push(PENDING_TRANSACTION_BY_ADDRESS);
    key.extend_from_slice(domain);
    key.extend_from_slice(address);
    key
}

pub fn pending_transaction_by_owner_key(domain: &[u8], owner: &[u8], address: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + domain.len() + owner.len() + address.len());
    key.push(COIN);
    key.push(PENDING_TRANSACTION_BY_OWNER);
    key.extend_from_slice(domain);
    key.extend_from_slice(owner);
    key.extend_from_slice(address);
    key
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn set_type_byte(set_type: &str) -> u8 {
    match set_type {
        "vertex" => 0,
        "hyperedge" => 1,
        _ => 0xFF,
    }
}

fn phase_type_byte(phase_type: &str) -> u8 {
    match phase_type {
        "adds" => 0,
        "removes" => 1,
        _ => 0xFF,
    }
}

fn right_align(data: &[u8], size: usize) -> Vec<u8> {
    let l = data.len();
    if l == size {
        return data.to_vec();
    }
    if l > size {
        return data[l - size..].to_vec();
    }
    let mut result = vec![0u8; size];
    result[size - l..].copy_from_slice(data);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_frame_key_matches_go() {
        let key = clock_global_frame_key(42);
        assert_eq!(key.len(), 10);
        assert_eq!(key[0], CLOCK_FRAME);    // 0x00
        assert_eq!(key[1], CLOCK_GLOBAL_FRAME); // 0x00
        assert_eq!(&key[2..], &42u64.to_be_bytes());
    }

    #[test]
    fn proposal_vote_key_matches_go() {
        // Go: [0x00, 0x0D, rank(8BE), filter..., identity...]
        let key = clock_proposal_vote_key(&[0xAA], 5, &[0xBB]);
        assert_eq!(key[0], 0x00);
        assert_eq!(key[1], 0x0D); // CLOCK_PROPOSAL_VOTE
        assert_eq!(&key[2..10], &5u64.to_be_bytes()); // rank
        assert_eq!(key[10], 0xAA); // filter
        assert_eq!(key[11], 0xBB); // identity
    }

    #[test]
    fn timeout_vote_key_matches_go() {
        let key = clock_timeout_vote_key(&[0xCC], 7, &[0xDD]);
        assert_eq!(key[1], 0x0E); // CLOCK_TIMEOUT_VOTE
        assert_eq!(&key[2..10], &7u64.to_be_bytes());
    }

    #[test]
    fn quorum_certificate_key_ignores_filter_like_go() {
        // Go ignores the filter parameter
        let key1 = clock_quorum_certificate_key(10, &[0xAA, 0xBB]);
        let key2 = clock_quorum_certificate_key(10, &[]);
        assert_eq!(key1, key2); // filter doesn't affect key
        assert_eq!(key1.len(), 10);
        assert_eq!(key1[1], 0x0B);
    }

    #[test]
    fn shard_commit_uses_hypergraph_shard_prefix() {
        let key = hypergraph_shard_commit_key(100, "adds", "vertex", &[0xAA; 4]);
        assert_eq!(key[0], HYPERGRAPH_SHARD); // 0x09, not 0x31
        assert_eq!(&key[1..9], &100u64.to_be_bytes());
        assert_eq!(key[9], HG_VERTEX_ADDS_SHARD_COMMIT); // 0xE0
    }

    #[test]
    fn total_distance_key_matches_go() {
        let key = clock_total_distance_key(&[0x01], 42, &[0x02]);
        assert_eq!(key[1], 0x04); // CLOCK_TOTAL_DISTANCE = 0x04
    }

    #[test]
    fn timeout_certificate_key_matches_go() {
        let key = clock_timeout_certificate_key(99, &[]);
        assert_eq!(key[1], 0x0C); // CLOCK_TIMEOUT_CERTIFICATE
        assert_eq!(key.len(), 10);
    }

    #[test]
    fn latest_index() {
        assert_eq!(clock_global_latest_index(), vec![0x00, 0x20]);
    }

    #[test]
    fn global_frame_request_key() {
        let key = clock_global_frame_request_key(42, 3);
        assert_eq!(key.len(), 12);
        assert_eq!(key[1], 0x08);
    }

    #[test]
    fn right_align_exact() {
        assert_eq!(right_align(&[1, 2, 3], 3), vec![1, 2, 3]);
    }

    #[test]
    fn right_align_pad() {
        assert_eq!(right_align(&[1, 2], 4), vec![0, 0, 1, 2]);
    }

    #[test]
    fn right_align_trim() {
        assert_eq!(right_align(&[1, 2, 3, 4], 2), vec![3, 4]);
    }
}

//! Real-components materialize harness.
//!
//! Wires the production stack with NO network/consensus layer: one real
//! in-memory RocksDB shared by a `RocksHypergraphStore` + `RocksShardsStore`
//! + `RocksClockStore`, a `HypergraphCrdt` backed by that hypergraph store,
//! an `ExecutionEngineManager`, a `SharedProverRegistry`, and a
//! `FrameMaterializer` wired exactly as `allocator_and_lifecycle.rs` wires it
//! (eviction registry + rocks store + shard-size source).
//!
//! This is the seam the unit tests with mock registries miss: the registry
//! refreshes from the FLAT per-vertex keyspace while the materializer mutates
//! the CRDT and persists via `commit_frame`. Every store-vs-CRDT bug this
//! session lived here.

use std::collections::HashMap;
use std::sync::Arc;

use quil_engine::frame_materializer::{FrameMaterializer, GLOBAL_EVICTION_ACTIVATION_FRAME};
use quil_execution::prover_registry::{
    rebuild_vertex_tree_from_blob, vertex_tree_to_blob, SharedProverRegistry,
};
use quil_execution::global_intrinsic::materialize::{
    create_allocation_vertex_tree, create_prover_vertex_tree,
};
use quil_execution::global_schema::{read_field, write_field};
use quil_types::consensus::ProverRegistry;
use quil_types::crypto::{InclusionProver, NoopInclusionProver};
use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader};
use quil_types::store::{ClockStore, ShardKey, ShardsStore};

const STATUS_ACTIVE: u8 = 1;

pub struct MaterializeHarness {
    _rocks: quil_store::RocksDb,
    pub hg_store: Arc<quil_store::RocksHypergraphStore>,
    pub shards_store: Arc<quil_store::RocksShardsStore>,
    pub clock_store: Arc<quil_store::RocksClockStore>,
    pub crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    pub registry: Arc<SharedProverRegistry>,
    pub materializer: FrameMaterializer,
    pub prover_address: Vec<u8>,
}

impl MaterializeHarness {
    pub fn new(archive_mode: bool, inclusion_prover: Arc<dyn InclusionProver>) -> Self {
        let rocks = quil_store::RocksDb::open_in_memory().expect("open in-memory db");
        let db = rocks.inner();
        let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(db.clone()));
        let shards_store = Arc::new(quil_store::RocksShardsStore::new(db.clone()));
        let clock_store = Arc::new(quil_store::RocksClockStore::new(db.clone()));

        // CRDT backed by the REAL hypergraph store — so `commit_frame`
        // persists into the same store the registry refreshes from.
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
            inclusion_prover.clone(),
        ));

        let stubs = quil_execution::testing::NoopExecutionCrypto::new();
        let hg_resolver: Arc<
            dyn quil_execution::hypergraph_intrinsic::HypergraphConfigResolver,
        > = Arc::new(quil_execution::testing::NoopHypergraphConfigResolver);
        let exec_manager = Arc::new(quil_execution::ExecutionEngineManager::new(
            inclusion_prover.clone(),
            stubs.key_manager.clone(),
            crdt.clone(),
            stubs.bulletproof_prover.clone(),
            stubs.decaf_constructor.clone(),
            stubs.circuit_compiler.clone(),
            clock_store.clone() as Arc<dyn ClockStore>,
            hg_resolver,
            true,
        ));

        let registry = Arc::new(SharedProverRegistry::new());
        let prover_address = vec![0x01u8; 32];

        // Deterministic shard-size source from the shards store, exactly as
        // production wires it (filter = L2 ++ prefix-byte).
        let shard_size_source = {
            let ss = shards_store.clone();
            Arc::new(move || {
                let mut out: HashMap<Vec<u8>, u64> = HashMap::new();
                if let Ok(shards) = ss.range_app_shards() {
                    for s in shards {
                        let l2_start = if s.shard_key.len() >= 3 { 3 } else { 0 };
                        let mut filter = s.shard_key[l2_start..].to_vec();
                        for p in &s.prefix {
                            filter.push(*p as u8);
                        }
                        if filter.is_empty() {
                            continue;
                        }
                        let has = s.size.iter().any(|&b| b != 0);
                        out.insert(filter, if has { 1 } else { 0 });
                    }
                }
                out
            }) as Arc<dyn Fn() -> HashMap<Vec<u8>, u64> + Send + Sync>
        };

        let materializer = FrameMaterializer::new(
            exec_manager,
            registry.clone() as Arc<dyn ProverRegistry>,
            clock_store.clone() as Arc<dyn ClockStore>,
            crdt.clone(),
            hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
            Arc::new(quil_engine::rewards::OptRewardIssuance),
            prover_address.clone(),
            archive_mode,
        )
        .with_eviction_registry(registry.clone())
        .with_rocks_hg_store(hg_store.clone())
        .with_shard_size_source(shard_size_source);

        Self {
            _rocks: rocks,
            hg_store,
            shards_store,
            clock_store,
            crdt,
            registry,
            materializer,
            prover_address,
        }
    }

    /// Write a vertex blob straight into the FLAT per-vertex keyspace — the
    /// path hypergraph SYNC uses — WITHOUT touching the CRDT tree. The vertex
    /// is therefore visible to `refresh_from_store` but absent from the
    /// CRDT's in-memory tree: the exact production seam.
    pub fn seed_flat_vertex(&self, addr: &[u8; 32], blob: &[u8]) {
        use quil_types::store::HypergraphStore as _;
        let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
        let mut vk = vec![0xFFu8; 32];
        vk.extend_from_slice(addr);
        let txn = self.hg_store.new_transaction(false).unwrap();
        self.hg_store
            .save_vertex_underlying_txn(txn.as_ref(), "vertex", "adds", &shard, &vk, blob)
            .unwrap();
        txn.commit().unwrap();
    }

    pub fn refresh_registry(&self) {
        self.registry.refresh_from_store(&self.hg_store);
    }
}

/// Build an Active prover vertex blob whose only allocation is Active and
/// long-inactive (last_active = 100) on the given non-global filter.
fn active_inactive_prover(prover_addr: &[u8; 32], filter: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut prover = create_prover_vertex_tree(&vec![0xCDu8; 57], 0).unwrap();
    write_field(&mut prover, "prover:Prover", "Status", &[STATUS_ACTIVE]).unwrap();

    let mut alloc = create_allocation_vertex_tree(prover_addr, filter, 0).unwrap();
    write_field(&mut alloc, "allocation:ProverAllocation", "Status", &[STATUS_ACTIVE]).unwrap();
    write_field(
        &mut alloc,
        "allocation:ProverAllocation",
        "LastActiveFrameNumber",
        &100u64.to_be_bytes(),
    )
    .unwrap();

    (vertex_tree_to_blob(&prover), vertex_tree_to_blob(&alloc))
}

fn frame_at(n: u64) -> GlobalFrame {
    GlobalFrame {
        header: Some(GlobalFrameHeader {
            frame_number: n,
            ..Default::default()
        }),
        requests: Vec::new(),
    }
}

/// End-to-end: an inactive prover present only in the flat keyspace (the
/// sync seam) is kicked when the materializer materializes a frame past the
/// eviction activation — exercising find_eviction_candidates (registry) →
/// evict (flat-store fallback) → commit → refresh, the full wiring that
/// repeatedly broke and that mock-registry tests can't reach.
#[test]
fn materialize_evicts_inactive_prover_present_only_in_flat_store() {
    let h = MaterializeHarness::new(true, Arc::new(NoopInclusionProver));

    let prover_addr = [0x55u8; 32];
    let filter = vec![0x33u8; 64];
    let (prover_blob, alloc_blob) = active_inactive_prover(&prover_addr, &filter);
    // Flat-keyspace only (CRDT tree never sees them) — the sync seam.
    h.seed_flat_vertex(&prover_addr, &prover_blob);
    h.seed_flat_vertex(&[0xA5u8; 32], &alloc_blob);
    h.refresh_registry();

    // Sanity: the registry (from the flat store) sees the candidate.
    let frame = GLOBAL_EVICTION_ACTIVATION_FRAME + 100;
    let halts: HashMap<Vec<u8>, u64> = HashMap::new();
    let pre = h.registry.find_eviction_candidates(frame, 360, &halts);
    assert!(
        pre.iter().any(|a| a == &prover_addr.to_vec()),
        "registry must see the inactive prover as a candidate pre-materialize"
    );

    // Materialize a frame past activation — the materializer's eviction step
    // runs, reads the vertex via the flat-store fallback, kicks it, commits,
    // and refreshes the registry.
    h.materializer.materialize(&frame_at(frame)).expect("materialize");

    // The kicked prover must no longer be an eviction candidate (Status=4 →
    // dropped from the registry on refresh).
    let post = h.registry.find_eviction_candidates(frame, 360, &halts);
    assert!(
        !post.iter().any(|a| a == &prover_addr.to_vec()),
        "after materialize the prover must be kicked and gone from the candidate set \
         (this is the store-vs-CRDT seam that had no end-to-end coverage)"
    );
}

// =====================================================================
// Shard split: real materialize + authorization (real RocksShardsStore)
// =====================================================================

/// Permissive key manager so the test drives the AUTHORIZATION + grid-write
/// paths without real BLS signing (the BLS path is covered by quil-execution
/// verify tests). Only `validate_signature` matters here.
struct AcceptAllKeyManager;
impl quil_types::crypto::KeyManager for AcceptAllKeyManager {
    fn validate_signature(
        &self,
        _key_type: quil_types::crypto::KeyType,
        _public_key: &[u8],
        _message: &[u8],
        _signature: &[u8],
        _domain: &[u8],
    ) -> quil_types::error::Result<bool> {
        Ok(true)
    }
}

/// Build a GlobalIntrinsic wired with a real RocksShardsStore + registry,
/// plus a HypergraphState, returning everything needed to drive
/// `invoke_step` for a ShardSplit.
fn split_fixture() -> (
    quil_execution::global_intrinsic::intrinsic::GlobalIntrinsic,
    quil_execution::hypergraph_state::HypergraphState,
    Arc<quil_store::RocksShardsStore>,
    Arc<quil_execution::prover_registry::SharedProverRegistry>,
    Arc<quil_store::RocksHypergraphStore>,
) {
    use quil_types::store::HypergraphStore as _;

    let rocks = quil_store::RocksDb::open_in_memory().unwrap();
    let db = rocks.inner();
    let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(db.clone()));
    let shards_store = Arc::new(quil_store::RocksShardsStore::new(db.clone()));
    let kvdb: Arc<dyn quil_types::store::KvDb> = Arc::new(rocks);

    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
        Arc::new(NoopInclusionProver),
    ));
    let state = quil_execution::hypergraph_state::HypergraphState::new(crdt);
    let registry = Arc::new(quil_execution::prover_registry::SharedProverRegistry::new());

    let gi = quil_execution::global_intrinsic::intrinsic::GlobalIntrinsic::new_with_stores(
        Arc::new(AcceptAllKeyManager),
        None,
        None,
        Some(shards_store.clone() as Arc<dyn quil_types::store::ShardsStore>),
        Some(kvdb),
    )
    .with_frame_header_deps(
        registry.clone() as Arc<dyn ProverRegistry>,
        Arc::new(quil_engine::rewards::OptRewardIssuance),
    );

    (gi, state, shards_store, registry, hg_store)
}

/// Seed a global prover (empty-filter Active allocation) into the flat
/// keyspace (for the registry / authorization) AND its prover vertex into
/// the HypergraphState (for the BLS pubkey extraction in verify).
fn seed_global_prover(
    state: &quil_execution::hypergraph_state::HypergraphState,
    hg_store: &Arc<quil_store::RocksHypergraphStore>,
    registry: &Arc<quil_execution::prover_registry::SharedProverRegistry>,
    pubkey: &[u8],
    alloc_flat_byte: u8,
    filter: &[u8],
) -> [u8; 32] {
    use quil_types::store::HypergraphStore as _;
    // Prover address is poseidon(pubkey); verify_addressed_bls binds the sig
    // address to it, so we store the prover there and sign with it.
    let prover_addr =
        quil_execution::global_intrinsic::materialize::prover_address_from_pubkey(pubkey).unwrap();

    let mut prover = create_prover_vertex_tree(pubkey, 0).unwrap();
    write_field(&mut prover, "prover:Prover", "Status", &[STATUS_ACTIVE]).unwrap();
    let prover_blob = vertex_tree_to_blob(&prover);

    let mut alloc = create_allocation_vertex_tree(&prover_addr, filter, 0).unwrap();
    write_field(&mut alloc, "allocation:ProverAllocation", "Status", &[STATUS_ACTIVE]).unwrap();
    let alloc_blob = vertex_tree_to_blob(&alloc);

    let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
    let txn = hg_store.new_transaction(false).unwrap();
    let mut vkp = vec![0xFFu8; 32];
    vkp.extend_from_slice(&prover_addr);
    hg_store.save_vertex_underlying_txn(txn.as_ref(), "vertex", "adds", &shard, &vkp, &prover_blob).unwrap();
    let mut vka = vec![0xFFu8; 32];
    vka.extend_from_slice(&[alloc_flat_byte; 32]);
    hg_store.save_vertex_underlying_txn(txn.as_ref(), "vertex", "adds", &shard, &vka, &alloc_blob).unwrap();
    txn.commit().unwrap();
    registry.refresh_from_store(hg_store);

    // Prover vertex into the state changeset so verify's `state.get` finds
    // the pubkey at (GLOBAL, prover_addr).
    let va = quil_execution::hypergraph_state::vertex_adds_discriminator().unwrap();
    state
        .set(&quil_execution::domains::GLOBAL, &prover_addr[..], &va, 1, prover_blob)
        .unwrap();
    prover_addr
}

fn shard_split_bytes(shard_address: &[u8], proposer: &[u8; 32]) -> Vec<u8> {
    use quil_execution::global_intrinsic::prover_ops::ShardSplit;
    use quil_execution::global_intrinsic::addressed_signature::AddressedSignature;
    let c0 = {
        let mut c = shard_address.to_vec();
        c.push(0x00);
        c
    };
    let c1 = {
        let mut c = shard_address.to_vec();
        c.push(0x80);
        c
    };
    ShardSplit {
        shard_address: shard_address.to_vec(),
        proposed_shards: vec![c0, c1],
        frame_number: 1,
        public_key_signature_bls48581: Some(AddressedSignature {
            signature: vec![0u8; 74],
            address: proposer.to_vec(),
        }),
    }
    .to_canonical_bytes()
    .unwrap()
}

fn shard_merge_bytes(parent: &[u8], children: &[Vec<u8>], proposer: &[u8; 32]) -> Vec<u8> {
    use quil_execution::global_intrinsic::prover_ops::ShardMerge;
    use quil_execution::global_intrinsic::addressed_signature::AddressedSignature;
    ShardMerge {
        shard_addresses: children.to_vec(),
        parent_address: parent.to_vec(),
        frame_number: 1,
        public_key_signature_bls48581: Some(AddressedSignature {
            signature: vec![0u8; 74],
            address: proposer.to_vec(),
        }),
    }
    .to_canonical_bytes()
    .unwrap()
}

#[test]
fn shard_split_by_global_prover_registers_enumerable_child_and_rejects_non_global() {
    let quil = quil_execution::domains::QUIL_TOKEN;
    // A depth-1 QUIL shard filter (33 bytes).
    let mut shard_address = quil.to_vec();
    shard_address.push(0x05);

    // --- Global proposer: split is STAGED at proposal time, applied at E+2. ---
    {
        let (gi, state, shards_store, registry, hg_store) = split_fixture();
        // Empty filter ⇒ global prover ⇒ authorized to propose splits.
        let proposer = seed_global_prover(&state, &hg_store, &registry, &vec![0xCDu8; 57], 0x88, &[]);
        let bytes = shard_split_bytes(&shard_address, &proposer);
        // Propose in epoch 0 (frame 1).
        gi.invoke_step(1, &bytes, &state).expect("global proposer split must be accepted");

        let count_children = |store: &dyn quil_types::store::ShardsStore| -> usize {
            store
                .range_app_shards()
                .unwrap()
                .iter()
                .filter(|s| s.shard_key.len() == 35 && s.shard_key[3..35] == quil[..])
                .count()
        };

        // Epoch-aligned: the topology flip is DEFERRED to E+2. The children are
        // not yet enumerable, but a pending change is staged for epoch 2.
        assert_eq!(count_children(shards_store.as_ref()), 0, "split must be staged, not immediate");
        let pending = shards_store.all_pending_shard_changes().unwrap();
        assert_eq!(pending.len(), 1, "one pending split recorded");
        assert_eq!(pending[0].effective_epoch, 2, "frame 1 (epoch 0) → effective epoch 2");
        assert!(pending[0].affects_shard(&shard_address), "pending change targets the parent");

        // Applying within epoch 1 does nothing (E+2 not reached).
        gi.apply_due_shard_changes(720, &state).expect("apply at epoch 1"); // frame 720 = epoch 1
        assert_eq!(count_children(shards_store.as_ref()), 0, "not applied before E+2");

        // Crossing into epoch 2 flips the topology: both children become enumerable.
        gi.apply_due_shard_changes(1440, &state).expect("apply at epoch 2"); // frame 1440 = epoch 2
        let shards = shards_store.range_app_shards().unwrap();
        let children: Vec<_> = shards
            .iter()
            .filter(|s| s.shard_key.len() == 35 && s.shard_key[3..35] == quil[..])
            .collect();
        assert_eq!(
            children.len(),
            2,
            "at E+2 both child sub-shards must be registered under a 35-byte L1||L2 key"
        );
        assert!(children.iter().any(|s| s.prefix == vec![0x05, 0x00]));
        assert!(children.iter().any(|s| s.prefix == vec![0x05, 0x80]));
        // The pending change is consumed once applied (idempotent).
        assert!(shards_store.all_pending_shard_changes().unwrap().is_empty());
        gi.apply_due_shard_changes(1440, &state).expect("re-apply is a no-op");
    }

    // --- Non-global proposer: split is rejected (authorization). ---
    {
        let (gi, state, shards_store, registry, hg_store) = split_fixture();
        // Non-empty filter ⇒ NOT a global prover ⇒ unauthorized. Distinct
        // pubkey so it has a distinct address.
        let proposer = seed_global_prover(&state, &hg_store, &registry, &vec![0xEEu8; 57], 0xAA, &vec![0x33u8; 64]);
        let bytes = shard_split_bytes(&shard_address, &proposer);
        let res = gi.invoke_step(1, &bytes, &state);
        assert!(
            res.is_err(),
            "a non-global proposer must be rejected (proposer_is_active_global)"
        );
        assert!(
            shards_store.range_app_shards().unwrap().is_empty(),
            "rejected split must not write any shard"
        );
    }
}

/// Phase F join-freeze: once a split is staged on shard S, joins targeting S
/// (or its pending children) are rejected until the change settles at E+2.
#[test]
fn pending_split_freezes_joins_to_affected_shard_until_e2() {
    use quil_execution::global_intrinsic::{ProverJoin, SignatureWithPop};

    let quil = quil_execution::domains::QUIL_TOKEN;
    let mut shard_address = quil.to_vec();
    shard_address.push(0x05); // the shard being split

    let (gi, state, shards_store, registry, hg_store) = split_fixture();
    let proposer = seed_global_prover(&state, &hg_store, &registry, &vec![0xCDu8; 57], 0x88, &[]);
    // Stage a split in epoch 0 (frame 1) → effective epoch 2.
    gi.invoke_step(1, &shard_split_bytes(&shard_address, &proposer), &state)
        .expect("split staged");
    assert_eq!(shards_store.all_pending_shard_changes().unwrap().len(), 1);

    // Minimal join op — the freeze gate runs BEFORE signature/VDF verification,
    // so a real pubkey + target filter is all that's needed to exercise it.
    let join_to = |filter: Vec<u8>, frame: u64| -> Vec<u8> {
        ProverJoin {
            filters: vec![filter],
            frame_number: frame,
            public_key_signature_bls48581: Some(SignatureWithPop {
                signature: vec![0u8; 74],
                public_key: Some(vec![0xABu8; 585]),
                pop_signature: vec![0u8; 74],
            }),
            delegate_address: vec![],
            merge_targets: vec![],
            proof: vec![],
        }
        .to_canonical_bytes()
        .unwrap()
    };
    let is_frozen = |res: &quil_types::error::Result<()>| -> bool {
        matches!(res, Err(e) if format!("{e:?}").contains("frozen"))
    };

    // A join to the parent shard is frozen.
    assert!(is_frozen(&gi.invoke_step(2, &join_to(shard_address.clone(), 2), &state)),
        "join to the splitting shard must be frozen");
    // A join to a pending CHILD is frozen too (the child doesn't exist yet).
    let mut child = shard_address.clone();
    child.push(0x00);
    assert!(is_frozen(&gi.invoke_step(2, &join_to(child, 2), &state)),
        "join to a pending child must be frozen");

    // A join to an unrelated shard is NOT frozen (fails later, but not on the freeze).
    let mut other = quil.to_vec();
    other.push(0x09);
    assert!(!is_frozen(&gi.invoke_step(2, &join_to(other, 2), &state)),
        "join to an unrelated shard must not be frozen");

    // Once the split applies at E+2, the freeze lifts.
    gi.apply_due_shard_changes(1440, &state).expect("apply at epoch 2"); // frame 1440 = epoch 2
    assert!(shards_store.all_pending_shard_changes().unwrap().is_empty());
    assert!(!is_frozen(&gi.invoke_step(1441, &join_to(shard_address, 1441), &state)),
        "freeze must lift after the E+2 apply");
}

/// Seed an ACTIVE data-shard prover whose allocation lives at the CANONICAL
/// `allocation_address(pubkey, filter)` — in `hg_store` (so the registry
/// enumerates it) AND in the `state` changeset (so reassignment's `state.get`
/// finds it) — plus its prover→allocation hyperedge. Returns the prover
/// address + canonical allocation address.
fn seed_data_prover(
    state: &quil_execution::hypergraph_state::HypergraphState,
    hg_store: &Arc<quil_store::RocksHypergraphStore>,
    registry: &Arc<quil_execution::prover_registry::SharedProverRegistry>,
    pubkey: &[u8],
    filter: &[u8],
) -> ([u8; 32], [u8; 32]) {
    use quil_execution::global_intrinsic::materialize::{
        allocation_address, build_prover_allocation_hyperedge_blob, create_allocation_vertex_tree,
        prover_address_from_pubkey,
    };
    use quil_types::store::HypergraphStore as _;

    let prover_addr = prover_address_from_pubkey(pubkey).unwrap();
    let alloc_addr = allocation_address(pubkey, filter).unwrap();

    let mut prover = create_prover_vertex_tree(pubkey, 0).unwrap();
    write_field(&mut prover, "prover:Prover", "Status", &[STATUS_ACTIVE]).unwrap();
    let prover_blob = vertex_tree_to_blob(&prover);

    let mut alloc = create_allocation_vertex_tree(&prover_addr, filter, 0).unwrap();
    write_field(&mut alloc, "allocation:ProverAllocation", "Status", &[STATUS_ACTIVE]).unwrap();
    let alloc_blob = vertex_tree_to_blob(&alloc);

    // Into hg_store (registry source), keyed by canonical addresses.
    let shard = ShardKey { l1: [0; 3], l2: [0xFF; 32] };
    let txn = hg_store.new_transaction(false).unwrap();
    let mut vkp = vec![0xFFu8; 32];
    vkp.extend_from_slice(&prover_addr);
    hg_store.save_vertex_underlying_txn(txn.as_ref(), "vertex", "adds", &shard, &vkp, &prover_blob).unwrap();
    let mut vka = vec![0xFFu8; 32];
    vka.extend_from_slice(&alloc_addr);
    hg_store.save_vertex_underlying_txn(txn.as_ref(), "vertex", "adds", &shard, &vka, &alloc_blob).unwrap();
    txn.commit().unwrap();
    registry.refresh_from_store(hg_store);

    // Into the state changeset so `rekey_allocation`'s `state.get` finds it.
    let va = quil_execution::hypergraph_state::vertex_adds_discriminator().unwrap();
    let ha = quil_execution::hypergraph_state::hyperedge_adds_discriminator().unwrap();
    state.set(&quil_execution::domains::GLOBAL, &prover_addr[..], &va, 1, prover_blob).unwrap();
    state.set(&quil_execution::domains::GLOBAL, &alloc_addr[..], &va, 1, alloc_blob).unwrap();
    let he = build_prover_allocation_hyperedge_blob(&prover_addr, &[(alloc_addr, &alloc)]).unwrap();
    state.set(&quil_execution::domains::GLOBAL, &prover_addr[..], &ha, 1, he).unwrap();

    (prover_addr, alloc_addr)
}

/// Phase F deterministic reassignment: when a shard splits, each active prover
/// on the parent is moved to exactly one child (by the address-bucketing rule)
/// at the E+2 boundary — its allocation re-keys to the child address with the
/// ConfirmationFilter rewritten, and the prover's hyperedge follows.
#[test]
fn split_at_e2_reassigns_active_prover_to_deterministic_child() {
    use quil_execution::global_intrinsic::materialize::allocation_address;
    use quil_execution::global_intrinsic::reassignment::assign_child_index;

    let quil = quil_execution::domains::QUIL_TOKEN;
    let mut parent = quil.to_vec();
    parent.push(0x05);

    let (gi, state, _shards_store, registry, hg_store) = split_fixture();
    // Global proposer (empty filter) authorizes the split.
    let proposer = seed_global_prover(&state, &hg_store, &registry, &vec![0xCDu8; 57], 0x88, &[]);
    // An active data-shard prover allocated to the parent shard.
    let (data_addr, parent_alloc_addr) =
        seed_data_prover(&state, &hg_store, &registry, &vec![0x7Au8; 57], &parent);

    // Sanity: the registry sees the data prover on the parent shard.
    assert_eq!(
        registry.get_active_provers(&parent).unwrap().len(),
        1,
        "data prover must be active on the parent shard"
    );

    // Stage the split (epoch 0 → effective epoch 2).
    gi.invoke_step(1, &shard_split_bytes(&parent, &proposer), &state)
        .expect("split staged");

    // Apply at E+2 → reassignment runs.
    gi.apply_due_shard_changes(1440, &state).expect("apply at epoch 2");

    // The prover must land on the child selected by the deterministic rule.
    let children = vec![
        { let mut c = parent.clone(); c.push(0x00); c },
        { let mut c = parent.clone(); c.push(0x80); c },
    ];
    let idx = assign_child_index(&data_addr, children.len());
    let child_filter = &children[idx];
    let child_alloc_addr = allocation_address(&vec![0x7Au8; 57], child_filter).unwrap();

    let va = quil_execution::hypergraph_state::vertex_adds_discriminator().unwrap();
    let ha = quil_execution::hypergraph_state::hyperedge_adds_discriminator().unwrap();

    // (1) The child allocation exists with the rewritten ConfirmationFilter.
    let child_blob = state
        .get(&quil_execution::domains::GLOBAL, &child_alloc_addr[..], &va)
        .unwrap()
        .expect("child allocation must exist after reassignment");
    let child_tree = rebuild_vertex_tree_from_blob(&child_blob);
    assert_eq!(
        read_field(&child_tree, "allocation:ProverAllocation", "ConfirmationFilter").unwrap(),
        *child_filter,
        "reassigned allocation carries the child filter"
    );
    // Status carried verbatim (still Active).
    assert_eq!(
        read_field(&child_tree, "allocation:ProverAllocation", "Status")
            .and_then(|b| b.first().copied()),
        Some(STATUS_ACTIVE),
        "Status carries verbatim across the re-key"
    );

    // (2) The prover's hyperedge now references the child allocation, not parent.
    let he_blob = state
        .get(&quil_execution::domains::GLOBAL, &data_addr[..], &ha)
        .unwrap()
        .expect("hyperedge present");
    let mut he = quil_tries::VectorCommitmentTree::new();
    he.root = quil_tries::deserialize_go_tree(&he_blob).unwrap();
    let atom_key = |addr: &[u8; 32]| {
        let mut k = vec![0xFFu8; 32];
        k.extend_from_slice(addr);
        k
    };
    let keys: Vec<Vec<u8>> = he.leaves().into_iter().map(|(k, _)| k).collect();
    assert!(keys.contains(&atom_key(&child_alloc_addr)), "hyperedge points at child");
    // The 0x80 child (the non-colliding case) fully re-keys: parent atom gone.
    if child_alloc_addr != parent_alloc_addr {
        assert!(!keys.contains(&atom_key(&parent_alloc_addr)), "old parent atom removed");
    }
}

/// Phase F merge reassignment: when children merge back into a parent, every
/// active prover on any child moves to the parent at E+2. Exercises BOTH the
/// re-key path (0x80 child → distinct parent address) and the in-place path
/// (0x00 child → SAME address as parent via poseidon trailing-zero collision).
#[test]
fn merge_at_e2_reassigns_active_provers_to_parent() {
    use quil_execution::global_intrinsic::materialize::allocation_address;

    // Merge materialize requires a 32-byte parent (merge-to-root), so use the
    // bare QUIL address as the parent and its depth-1 children.
    let parent = quil_execution::domains::QUIL_TOKEN.to_vec();
    let child0 = { let mut c = parent.clone(); c.push(0x00); c }; // collides w/ parent addr
    let child1 = { let mut c = parent.clone(); c.push(0x80); c }; // re-keys

    let (gi, state, _shards_store, registry, hg_store) = split_fixture();
    let proposer = seed_global_prover(&state, &hg_store, &registry, &vec![0xCDu8; 57], 0x88, &[]);

    // Prover A active on child1 (re-key case); prover B active on child0 (in-place case).
    let a_pk = vec![0x7Au8; 57];
    let b_pk = vec![0x6Bu8; 57];
    let (a_addr, a_child_alloc) = seed_data_prover(&state, &hg_store, &registry, &a_pk, &child1);
    let (_b_addr, b_child_alloc) = seed_data_prover(&state, &hg_store, &registry, &b_pk, &child0);

    assert_eq!(registry.get_active_provers(&child1).unwrap().len(), 1, "A on child1");
    assert_eq!(registry.get_active_provers(&child0).unwrap().len(), 1, "B on child0");

    // Stage the merge (epoch 0 → effective epoch 2) and apply at E+2.
    gi.invoke_step(1, &shard_merge_bytes(&parent, &[child0.clone(), child1.clone()], &proposer), &state)
        .expect("merge staged");
    assert_eq!(_shards_store.all_pending_shard_changes().unwrap().len(), 1, "one pending merge");
    gi.apply_due_shard_changes(1440, &state).expect("apply merge at epoch 2");

    let va = quil_execution::hypergraph_state::vertex_adds_discriminator().unwrap();
    let assert_on_parent = |pk: &[u8]| {
        let parent_alloc = allocation_address(pk, &parent).unwrap();
        let blob = state
            .get(&quil_execution::domains::GLOBAL, &parent_alloc[..], &va)
            .unwrap()
            .expect("allocation must exist at parent address after merge");
        let tree = rebuild_vertex_tree_from_blob(&blob);
        assert_eq!(
            read_field(&tree, "allocation:ProverAllocation", "ConfirmationFilter").unwrap(),
            parent,
            "ConfirmationFilter rewritten to parent"
        );
    };
    // A: re-key — child1 address differs from parent address.
    assert_ne!(a_child_alloc, allocation_address(&a_pk, &parent).unwrap());
    assert_on_parent(&a_pk);
    // B: in-place — child0 address equals parent address (trailing-zero collision).
    assert_eq!(b_child_alloc, allocation_address(&b_pk, &parent).unwrap());
    assert_on_parent(&b_pk);

    // A's hyperedge now references the parent allocation, not the child1 one.
    let ha = quil_execution::hypergraph_state::hyperedge_adds_discriminator().unwrap();
    let he_blob = state
        .get(&quil_execution::domains::GLOBAL, &a_addr[..], &ha)
        .unwrap()
        .expect("A hyperedge present");
    let mut he = quil_tries::VectorCommitmentTree::new();
    he.root = quil_tries::deserialize_go_tree(&he_blob).unwrap();
    let atom_key = |addr: &[u8; 32]| { let mut k = vec![0xFFu8; 32]; k.extend_from_slice(addr); k };
    let keys: Vec<Vec<u8>> = he.leaves().into_iter().map(|(k, _)| k).collect();
    assert!(keys.contains(&atom_key(&allocation_address(&a_pk, &parent).unwrap())),
        "A hyperedge points at parent allocation");
    assert!(!keys.contains(&atom_key(&a_child_alloc)), "A old child1 atom removed");
}

// ---- Gap coverage (audit 2026-06-28): invoke_join admission guards ----

fn build_join_op(pubkey: &[u8], filter: &[u8], frame: u64) -> Vec<u8> {
    use quil_execution::global_intrinsic::{ProverJoin, SignatureWithPop};
    ProverJoin {
        filters: vec![filter.to_vec()],
        frame_number: frame,
        public_key_signature_bls48581: Some(SignatureWithPop {
            signature: vec![0u8; 74],
            public_key: Some(pubkey.to_vec()),
            pop_signature: vec![0u8; 74],
        }),
        delegate_address: vec![],
        merge_targets: vec![],
        proof: vec![],
    }
    .to_canonical_bytes()
    .unwrap()
}

/// A prover whose vertex carries `KickFrameNumber > 0` cannot rejoin — the
/// kicked-rejoin guard rejects the join before any allocation is written.
#[test]
fn invoke_join_rejects_previously_kicked_prover() {
    use quil_execution::global_intrinsic::materialize::prover_address_from_pubkey;
    let quil = quil_execution::domains::QUIL_TOKEN;
    let (gi, state, _ss, _reg, _hg) = split_fixture();
    let pubkey = vec![0xABu8; 585];
    let prover_addr = prover_address_from_pubkey(&pubkey).unwrap();

    // Seed a KICKED prover vertex at its canonical address.
    let mut prover = create_prover_vertex_tree(&pubkey, 0).unwrap();
    write_field(&mut prover, "prover:Prover", "KickFrameNumber", &500u64.to_be_bytes()).unwrap();
    let va = quil_execution::hypergraph_state::vertex_adds_discriminator().unwrap();
    state
        .set(&quil_execution::domains::GLOBAL, &prover_addr[..], &va, 1, vertex_tree_to_blob(&prover))
        .unwrap();

    let res = gi.invoke_step(2, &build_join_op(&pubkey, &quil.to_vec(), 2), &state);
    assert!(
        matches!(&res, Err(e) if format!("{e:?}").contains("kicked")),
        "expected previously-kicked rejection, got {res:?}"
    );
}

/// A prover with an Active allocation still inside the 720-frame window cannot
/// re-join the same filter; once the window elapses the guard lets it through.
#[test]
fn invoke_join_rejects_rejoin_while_allocation_still_active() {
    use quil_execution::global_intrinsic::materialize::{allocation_address, prover_address_from_pubkey};
    let quil = quil_execution::domains::QUIL_TOKEN;
    let (gi, state, _ss, _reg, _hg) = split_fixture();
    let pubkey = vec![0xACu8; 585];
    let prover_addr = prover_address_from_pubkey(&pubkey).unwrap();
    let filter = quil.to_vec();
    let va = quil_execution::hypergraph_state::vertex_adds_discriminator().unwrap();

    // Prover vertex (not kicked) + an Active allocation joined at frame 10.
    let prover = create_prover_vertex_tree(&pubkey, 0).unwrap();
    state
        .set(&quil_execution::domains::GLOBAL, &prover_addr[..], &va, 1, vertex_tree_to_blob(&prover))
        .unwrap();
    let mut alloc = create_allocation_vertex_tree(&prover_addr, &filter, 10).unwrap();
    write_field(&mut alloc, "allocation:ProverAllocation", "Status", &[STATUS_ACTIVE]).unwrap();
    let alloc_addr = allocation_address(&pubkey, &filter).unwrap();
    state
        .set(&quil_execution::domains::GLOBAL, &alloc_addr[..], &va, 1, vertex_tree_to_blob(&alloc))
        .unwrap();

    // Within the 720-frame window (frame 100 < 10 + 720) → rejected.
    let blocked = gi.invoke_step(100, &build_join_op(&pubkey, &filter, 100), &state);
    assert!(
        matches!(&blocked, Err(e) if format!("{e:?}").contains("still active")),
        "expected still-active rejection, got {blocked:?}"
    );
    // After the window (frame 800 >= 10 + 720) the still-active guard no longer
    // fires (the join may fail later for other reasons, but NOT on this guard).
    let after = gi.invoke_step(800, &build_join_op(&pubkey, &filter, 800), &state);
    assert!(
        !matches!(&after, Err(e) if format!("{e:?}").contains("still active")),
        "still-active guard must not fire past the 720-frame window, got {after:?}"
    );
}

/// A rejoin preserves the prover's existing seniority via `max(existing,
/// computed)`: re-joining with no merge targets (computed seniority 0) must
/// NOT reset an accumulated seniority of 100.
#[test]
fn invoke_join_preserves_existing_seniority_via_max() {
    use quil_execution::global_intrinsic::materialize::prover_address_from_pubkey;
    let quil = quil_execution::domains::QUIL_TOKEN;
    let (gi, state, _ss, _reg, _hg) = split_fixture();
    let pubkey = vec![0xADu8; 585];
    let prover_addr = prover_address_from_pubkey(&pubkey).unwrap();
    let va = quil_execution::hypergraph_state::vertex_adds_discriminator().unwrap();

    // Existing prover with seniority 100 (not kicked, no active allocation).
    let prover = create_prover_vertex_tree(&pubkey, 100).unwrap();
    state
        .set(&quil_execution::domains::GLOBAL, &prover_addr[..], &va, 1, vertex_tree_to_blob(&prover))
        .unwrap();

    let res = gi.invoke_step(2, &build_join_op(&pubkey, &quil.to_vec(), 2), &state);
    assert!(res.is_ok(), "rejoin should succeed: {res:?}");

    // max(existing 100, computed 0) = 100 → seniority preserved, not reset to 0.
    let blob = state
        .get(&quil_execution::domains::GLOBAL, &prover_addr[..], &va)
        .unwrap()
        .unwrap();
    let tree = rebuild_vertex_tree_from_blob(&blob);
    assert_eq!(
        read_field(&tree, "prover:Prover", "Seniority").unwrap(),
        100u64.to_be_bytes().to_vec(),
        "rejoin must preserve seniority via max()"
    );
}

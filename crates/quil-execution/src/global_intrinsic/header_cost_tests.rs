//! Cost of a GLOBAL frame's shard headers at mainnet's scale (2026-10-25: 93
//! headers of 17 participants each, every member opening its leaf twice):
//! the rewards/activity and storage-audit steps of each header, executed
//! three times like a frame's proposal check, vote and publication.

use super::*;
use crate::global_intrinsic::frame_header::FrameHeader;
use crate::global_intrinsic::materialize;
use crate::global_intrinsic::prover_shard_update::{
    materialize_prover_shard_update_with_fees, ShardMetadata,
};
use crate::prover_registry::{rebuild_vertex_tree_from_blob, vertex_tree_to_blob};
use num_bigint::BigInt;
use quil_types::consensus::{
    ProverAllocation, ProverAllocationInfo, ProverInfo, ProverStatus, RewardIssuance,
};
use rayon::prelude::*;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const HEADERS: usize = 93;
const PARTICIPANTS: usize = 17;
/// Blocks of each member's leaf: two path levels above the blocks.
const NUM_BLOCKS: u64 = 256;
const WORLD_SIZE: u64 = 1 << 34;
const SHARD_SIZE: u64 = 1 << 24;

/// The PoMW issuance arithmetic the node installs.
struct PomwIssuance;
impl RewardIssuance for PomwIssuance {
    fn calculate(
        &self,
        difficulty: u64,
        world_state_bytes: u64,
        units: u64,
        provers: &[HashMap<String, ProverAllocation>],
    ) -> Result<Vec<BigInt>> {
        let basis = crate::pricing::pomw_basis(difficulty, world_state_bytes, units);
        let world = BigInt::from(world_state_bytes);
        Ok(provers
            .iter()
            .map(|allocations| {
                allocations
                    .values()
                    .map(|a| {
                        crate::pricing::allocation_ring_reward(
                            &basis, &BigInt::from(a.state_size), &world, a.ring, a.shards,
                        )
                    })
                    .sum::<BigInt>()
            })
            .collect())
    }
}

struct Seat {
    public_key: Vec<u8>,
    address: [u8; 32],
}

fn seat(header: usize, member: usize) -> Seat {
    let mut public_key = vec![0x5Au8; 897];
    public_key[0] = header as u8;
    public_key[1] = member as u8;
    let address = materialize::prover_address_from_pubkey(&public_key).unwrap();
    Seat { public_key, address }
}

fn shard_filter(header: usize) -> Vec<u8> {
    let mut filter = vec![0x3Cu8; 32];
    filter[0] = header as u8;
    filter
}

fn open_state(db: &quil_store::RocksDb) -> HypergraphState {
    let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        store,
        Arc::new(quil_tries::ShaInclusionProver),
    ));
    crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE));
    HypergraphState::new(crdt)
}

fn vertex(state: &HypergraphState, address: &[u8]) -> quil_tries::VectorCommitmentTree {
    let va_disc = vertex_adds_discriminator().unwrap();
    let blob = state.get(&GLOBAL_INTRINSIC_ADDRESS[..], address, &va_disc).unwrap().unwrap();
    rebuild_vertex_tree_from_blob(&blob)
}

fn prover_info(seat: &Seat, filter: &[u8], ring: u8) -> ProverInfo {
    ProverInfo {
        public_key: seat.public_key.clone(),
        address: seat.address.to_vec(),
        status: ProverStatus::Active,
        kick_frame_number: 0,
        allocations: vec![ProverAllocationInfo {
            status: ProverStatus::Active,
            confirmation_filter: filter.to_vec(),
            rejection_filter: Vec::new(),
            join_frame_number: 1,
            leave_frame_number: 0,
            pause_frame_number: 0,
            resume_frame_number: 0,
            kick_frame_number: 0,
            join_confirm_frame_number: 0,
            join_reject_frame_number: 0,
            leave_confirm_frame_number: 0,
            leave_reject_frame_number: 0,
            last_active_frame_number: 0,
            last_signed_frame_number: 0,
            epoch: 0,
            ring,
            vertex_address: materialize::allocation_address(&seat.public_key, filter).unwrap().to_vec(),
        }],
        available_storage: 0,
        seniority: 0,
        delegate_address: Vec::new(),
    }
}

fn ms(total: Duration) -> f64 {
    total.as_secs_f64() * 1e3
}

#[test]
#[ignore = "measurement"]
fn measure_global_frame_header_cost() {
    quil_crypto::init();
    let poly_size = quil_types::consensus::STORAGE_BLOCK_POLY_SIZE;
    let queries = quil_types::consensus::STORAGE_QUERIES_PER_LEAF;
    let prior_frame = 2_000u64;
    let frame = prior_frame + 1;
    let anchor = frame - 1;
    let epoch = quil_types::consensus::epoch_for_frame(anchor);
    // The test clock store holds no frames: the beacon of an empty output.
    let rho_n = quil_crypto::porep::derive_storage_beacon(anchor, &[]);
    let va_disc = vertex_adds_discriminator().unwrap();
    let domain = &GLOBAL_INTRINSIC_ADDRESS[..];

    // One replica leaf stands in for every member's: the audit's cost
    // depends on the leaf's shape, not on its bytes.
    let replica: Vec<u8> = (0..NUM_BLOCKS as usize * poly_size as usize * 32)
        .map(|i| if i % 32 == 31 { (i / 32) as u8 } else { 0 })
        .collect();
    let leaf = quil_crypto::sdr::commit_leaf(&replica, poly_size);
    let seats: Vec<Vec<Seat>> =
        (0..HEADERS).map(|h| (0..PARTICIPANTS).map(|m| seat(h, m)).collect()).collect();

    let directory = tempfile::tempdir().unwrap();
    let db = quil_store::RocksDb::open(directory.path()).unwrap();
    let state = open_state(&db);
    for (h, members) in seats.iter().enumerate() {
        let filter = shard_filter(h);
        for seat in members {
            let join = materialize::materialize_prover_join(&seat.public_key, &[filter.clone()], 1, 1_000).unwrap();
            state.set(domain, &join.prover_address, &va_disc, 1, vertex_tree_to_blob(&join.prover_tree)).unwrap();
            for (address, tree) in &join.allocations {
                state.set(domain, address, &va_disc, 1, vertex_tree_to_blob(tree)).unwrap();
            }
            let registration = materialize::materialize_leaf_root_registration(
                &seat.address,
                &crate::global_intrinsic::LeafRootRegistration {
                    shard_filter: filter.clone(),
                    prefix: Vec::new(),
                    epoch,
                    leaf_root: leaf.root.clone(),
                    num_blocks: NUM_BLOCKS,
                    frame_number: 1,
                    public_key_signature_bls48581: None,
                },
            )
            .unwrap();
            state.set(domain, &registration.address, &va_disc, 1, vertex_tree_to_blob(&registration.tree)).unwrap();
        }
    }
    state.commit().unwrap();
    state.abort();
    state.crdt().commit(1).unwrap();

    let registry: Arc<dyn quil_types::consensus::ProverRegistry> =
        Arc::new(crate::prover_registry::SharedProverRegistry::new());
    let frame_prover: Arc<dyn quil_types::crypto::FrameProver> =
        Arc::new(quil_crypto::WesolowskiFrameProver::new(2048));
    let issuance: Arc<dyn RewardIssuance> = Arc::new(PomwIssuance);
    let participants: Vec<usize> = (0..PARTICIPANTS).collect();
    let shard = || ShardMetadata { state_size: SHARD_SIZE, shard_count: 1 };
    let header = |h: usize, attestation: Vec<u8>| FrameHeader {
        address: shard_filter(h),
        frame_number: 5,
        difficulty: 100_000,
        prover: seats[h][0].address.to_vec(),
        global_frame_number: anchor,
        storage_attestation: attestation,
        ..Default::default()
    };

    // The prior frame: every participant has been rewarded and active, and
    // its ring is recorded, as on a running network.
    for h in 0..HEADERS {
        let provers = seats[h].iter().map(|s| prover_info(s, &shard_filter(h), 0)).collect();
        materialize_prover_shard_update_with_fees(
            &header(h, Vec::new()), prior_frame, &state, &registry, &frame_prover, &issuance,
            WORLD_SIZE, provers, &participants, shard(), 0, None, None,
        )
        .unwrap();
        state.commit().unwrap();
        state.abort();
    }
    state.crdt().commit(prior_frame).unwrap();
    let provers: Vec<Vec<ProverInfo>> = (0..HEADERS)
        .map(|h| {
            let filter = shard_filter(h);
            seats[h]
                .iter()
                .map(|s| {
                    let allocation = vertex(&state, &materialize::allocation_address(&s.public_key, &filter).unwrap());
                    let ring = read_field(&allocation, "allocation:ProverAllocation", "Ring")
                        .and_then(|bytes| bytes.first().copied())
                        .unwrap_or(0);
                    prover_info(s, &filter, ring)
                })
                .collect()
        })
        .collect();
    drop(state);

    let started = Instant::now();
    let ops: Vec<FrameHeader> = (0..HEADERS)
        .into_par_iter()
        .map(|h| {
            let leaf_id = crate::global_intrinsic::leaf_id_bytes(&shard_filter(h), &[]);
            let openings: Vec<quil_types::proto::global::StorageOpening> = seats[h]
                .iter()
                .flat_map(|s| (0..queries).map(move |q| (s, q)))
                .map(|(s, q)| {
                    quil_crypto::porep::build_storage_opening(
                        &replica, &leaf, &leaf_id, epoch, &s.address, q, &rho_n, poly_size,
                    )
                    .to_proto()
                })
                .collect();
            let attestation = quil_types::proto::global::StorageAttestation { openings };
            header(h, prost::Message::encode_to_vec(&attestation))
        })
        .collect();
    eprintln!(
        "{HEADERS} headers x {PARTICIPANTS} participants, {queries} openings each of a {NUM_BLOCKS}-block leaf \
         (built in {:.1} s)",
        started.elapsed().as_secs_f64()
    );

    let gi = GlobalIntrinsic::new(Arc::new(crate::testing::NoopKeyManager))
        .with_clock_store(Arc::new(quil_store::testing::InMemoryClockStore::new()));
    for execution in 1..=3 {
        let state = open_state(&db);
        let (mut rewards, mut audit) = (Duration::ZERO, Duration::ZERO);
        for (h, op) in ops.iter().enumerate() {
            let started = Instant::now();
            materialize_prover_shard_update_with_fees(
                op, frame, &state, &registry, &frame_prover, &issuance,
                WORLD_SIZE, provers[h].clone(), &participants, shard(), 0, None, None,
            )
            .unwrap();
            let credited = Instant::now();
            gi.audit_storage_attestation(frame, op, &[], &state, &va_disc).unwrap();
            audit += credited.elapsed();
            rewards += credited - started;
            state.commit().unwrap();
            state.abort();
        }
        eprintln!(
            "execution {execution}: per header rewards/activity {:.2} ms, storage audit {:.2} ms; \
             per frame {:.0} ms + {:.0} ms",
            ms(rewards) / HEADERS as f64,
            ms(audit) / HEADERS as f64,
            ms(rewards),
            ms(audit),
        );
        // Every opening is honest: the audit evicts nobody.
        for members in &seats {
            for s in members {
                let status = read_field(&vertex(&state, &s.address), "prover:Prover", "Status");
                assert_ne!(status.as_deref(), Some(&[4u8][..]), "an honest member was evicted");
            }
        }
    }
}

//! Offline measurements over an authenticated, downloaded snapshot. Uses the
//! same sector pool, encoders, bindings and proof builders as the worker.
use super::*;
mod parallel;
pub use parallel::{measure_allocation, BenchmarkInput};
use quil_execution::global_intrinsic::{
    persistent_storage as protocol, storage_epoch_proof as epoch_proof,
};
use serde::Serialize;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

#[derive(Clone)]
pub struct BenchmarkOptions {
    pub directory: PathBuf,
    pub member: [u8; 32],
    pub beacon: Vec<u8>,
    pub rounds: usize,
    pub frames: usize,
    pub memory_budget_bytes: u64,
    pub stop: Arc<AtomicBool>,
}
#[derive(Default, Clone, Serialize)]
pub struct RoundMeasurement {
    pub encode_seconds: f64,
    pub binding_seconds: f64,
    pub fresh_proof_seconds: f64,
    pub fresh_verify_seconds: f64,
    pub seal_message_bytes: u64,
    pub frame_openings_seconds: f64,
    pub settlement_prepare_seconds: f64,
    pub settlement_prove_seconds: f64,
    pub settlement_verify_seconds: f64,
    pub settlement_message_bytes: u64,
}
#[derive(Default, Serialize)]
pub struct SnapshotMeasurement {
    pub filter: String,
    pub epoch: u64,
    pub snapshot_frame: u64,
    pub roots: Vec<String>,
    pub canonical_node_payload_bytes: u64,
    pub estimated_settlement_peak_bytes: u64,
    pub sectors: usize,
    pub replica_bytes: u64,
    pub cold_label_seconds: f64,
    pub certificate_witness_seconds: f64,
    pub certificate_prove_seconds: f64,
    pub certificate_verify_seconds: f64,
    pub certificate_message_bytes: u64,
    pub temporary_disk_peak_bytes: u64,
    pub rounds: Vec<RoundMeasurement>,
}
struct Gates(Option<u64>);
impl Gates {
    fn new(epoch: u64) -> Self {
        let old = quil_types::consensus::persistent_storage_epoch_thread_override();
        quil_types::consensus::set_persistent_storage_epoch_for_thread(Some(epoch));
        Self(old)
    }
}
impl Drop for Gates {
    fn drop(&mut self) {
        quil_types::consensus::set_persistent_storage_epoch_for_thread(self.0);
    }
}
fn check(options: &BenchmarkOptions) -> Result<()> {
    if options.stop.load(Ordering::Relaxed) {
        return Err(unavailable(
            "storage benchmark stopped by its resource/time budget".into(),
        ));
    }
    Ok(())
}
fn fits(bytes: u64, options: &BenchmarkOptions, phase: &str) -> Result<()> {
    check(options)?;
    if bytes > options.memory_budget_bytes {
        return Err(unavailable(format!(
            "{phase} needs an estimated {bytes} bytes, exceeding the {} byte storage budget",
            options.memory_budget_bytes
        )));
    }
    Ok(())
}
fn directory_bytes(path: &Path) -> u64 {
    fs::read_dir(path)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| {
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                directory_bytes(&entry.path())
            } else {
                entry.metadata().map_or(0, |m| m.len())
            }
        })
        .sum()
}

/// Fully measure one shard; never extrapolates a sampled sector into a GO.
/// The caller authenticates `snapshot` against a finalized GLOBAL checkpoint.
pub fn measure_snapshot(
    crdt: Arc<HypergraphCrdt>,
    snapshot: quil_types::consensus::StorageSnapshotRoots,
    filter: Vec<u8>,
    options: &BenchmarkOptions,
) -> Result<SnapshotMeasurement> {
    let store = LabelStore::new(options.directory.join("labels"))
        .with_disk_floor(crate::storage_readiness::disk_floor);
    measure_with_store(crdt, snapshot, filter, options, &store, None)
}

fn measure_with_store(
    crdt: Arc<HypergraphCrdt>,
    snapshot: quil_types::consensus::StorageSnapshotRoots,
    filter: Vec<u8>,
    options: &BenchmarkOptions,
    store: &LabelStore,
    coordinator: Option<&parallel::Coordinator>,
) -> Result<SnapshotMeasurement> {
    if !(2..=5).contains(&options.rounds)
        || options.frames == 0
        || options.frames > quil_types::consensus::epoch_length_frames() as usize
    {
        return Err(unavailable(
            "benchmark requires 2..5 rounds and 1..epoch_length frame openings".into(),
        ));
    }
    let _gates = Gates::new(snapshot.epoch);
    let source = quil_execution::global_intrinsic::storage_snapshot::Source {
        filter: filter.clone(),
        snapshot: snapshot.clone(),
    };
    let captured = capture_at(&crdt, &filter, snapshot.epoch, &[source])?;
    let mut measured = SnapshotMeasurement {
        filter: hex::encode(&filter),
        epoch: snapshot.epoch,
        snapshot_frame: snapshot.frame,
        roots: snapshot.roots.iter().map(hex::encode).collect(),
        sectors: captured.prefixes.len(),
        ..Default::default()
    };
    let mut plans = Vec::new();
    for prefix in &captured.prefixes {
        let exact = captured.node_count(prefix)?;
        let n = sector::capacity(exact.saturating_add(exact.div_ceil(4)))
            .ok_or_else(|| unavailable("sector capacity overflow".into()))?;
        measured.canonical_node_payload_bytes = measured
            .canonical_node_payload_bytes
            .saturating_add(exact.saturating_mul(30));
        measured.replica_bytes = measured.replica_bytes.saturating_add(n.saturating_mul(32));
        plans.push((prefix.clone(), exact, n));
    }
    let dummy = epoch_proof::EpochClaim {
        member: options.member,
        seats: vec![epoch_proof::SeatClaim {
            settle_epoch: snapshot.epoch,
            held: plans
                .iter()
                .map(|(prefix, _, n)| epoch_proof::HeldLeaf {
                    leaf_id: quil_execution::global_intrinsic::leaf_id_bytes(&filter, prefix),
                    n: *n,
                    comm_r: [0; 32],
                })
                .collect(),
            frames: (0..options.frames)
                .map(|j| epoch_proof::CommittedFrame {
                    frame_number: j as u64 + 10,
                    rho_n: [1; 32],
                    root: [0; 32],
                })
                .collect(),
            ..Default::default()
        }],
    };
    measured.estimated_settlement_peak_bytes = protocol::estimate_epoch_proving_memory_bytes(
        &dummy.statement(),
        &quil_crypto::sdr::SdrParams::default(),
    )
    .map_err(QuilError::InvalidArgument)?
    .saturating_add(measured.replica_bytes);
    fits(
        measured.estimated_settlement_peak_bytes,
        options,
        "settlement proving",
    )?;
    // The current settlement worker holds all of a seat's replicas. Check it
    // before spending hours constructing capacity that this node cannot settle.
    fits(
        measured.replica_bytes.saturating_add(400 << 20),
        options,
        "settlement preparation",
    )?;
    let indexed: Vec<_> = plans.iter().enumerate().collect();
    let cold = crate::storage_jobs::for_each_parallel(&indexed, |&(index, (prefix, exact, n))| {
        let result = (|| {
            let mut stats = SnapshotMeasurement::default();
            check(options)?;
            eprintln!(
                "storage benchmark {}: cold sector {}/{} ({} MiB)",
                measured.filter,
                index + 1,
                plans.len(),
                n * 32 >> 20
            );
            fits(
                proof::labelling_peak_bytes(*n, &quil_crypto::sdr::SdrParams::default())
                    .saturating_add(400 << 20),
                options,
                "cold certification",
            )?;
            let _memory = crate::storage_jobs::reserve_until(
                proof::labelling_peak_bytes(*n, &quil_crypto::sdr::SdrParams::default())
                    .saturating_add(400 << 20),
                &|| options.stop.load(Ordering::Relaxed),
            )
            .ok_or_else(|| unavailable("benchmark stopped waiting for memory".into()))?;
            let leaf = quil_execution::global_intrinsic::leaf_id_bytes(&filter, prefix);
            let (dir, id, count) = loop {
                check(options)?;
                if let Some(reservation) =
                    try_reserve(store, &options.member, &leaf, snapshot.epoch, *exact)?
                {
                    break reservation;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            };
            if count != *n {
                return Err(unavailable(
                    "cold benchmark found pre-existing capacity; use a fresh directory".into(),
                ));
            }
            let start = Instant::now();
            let mut capacity = initialize(
                &store,
                &options.member,
                snapshot.epoch,
                dir,
                id,
                *n,
                &|| options.stop.load(Ordering::Relaxed),
            )?;
            stats.cold_label_seconds += start.elapsed().as_secs_f64();
            let message = protocol::CapacityMessage {
                member: options.member,
                epoch: snapshot.epoch,
                certificate: capacity.cert,
                signed_at: 0,
                signature: Vec::new(),
                proof: Vec::new(),
            };
            let root = message.root();
            let start = Instant::now();
            let certificate = {
                let kept = store
                    .find(snapshot.epoch, &options.member, &id, |count| count == *n)
                    .ok_or_else(|| unavailable("initial sector layers missing".into()))?;
                let last = fs::read(capacity.dir.join("last")).map_err(io)?;
                let beacon = sector::certificate_beacon(
                    &options.member,
                    &id,
                    snapshot.epoch,
                    *n,
                    &root,
                    &options.beacon,
                );
                let statement = proof::SealStatement {
                    member: &options.member,
                    leaf_id: &id,
                    epoch: snapshot.epoch,
                    n: *n,
                    registered: capacity.cert.registered().unwrap(),
                    beacon: &beacon,
                };
                let plain = proof::prove_seal_with_labels(
                    &last,
                    &statement,
                    &quil_crypto::sdr::SdrParams::default(),
                    sector::CHALLENGES,
                    &kept,
                )
                .map_err(QuilError::InvalidArgument)?;
                stats.certificate_witness_seconds += start.elapsed().as_secs_f64();
                let start = Instant::now();
                let proof = protocol::prove_certificate(
                    &options.member,
                    &id,
                    snapshot.epoch,
                    *n,
                    &root,
                    &options.beacon,
                    &plain,
                )
                .map_err(QuilError::InvalidArgument)?;
                stats.certificate_prove_seconds += start.elapsed().as_secs_f64();
                proof
            };
            let start = Instant::now();
            protocol::verify_certificate(
                &options.member,
                &id,
                snapshot.epoch,
                *n,
                &root,
                &options.beacon,
                &certificate,
            )
            .map_err(QuilError::InvalidArgument)?;
            stats.certificate_verify_seconds += start.elapsed().as_secs_f64();
            let mut envelope = message;
            envelope.proof = certificate;
            let bytes = envelope.envelope().to_canonical_bytes().len() as u64;
            if bytes > quil_types::consensus::STORAGE_SEAL_BYTES_PER_FRAME as u64 {
                return Err(unavailable(
                    "capacity certificate exceeds GLOBAL message budget".into(),
                ));
            }
            stats.certificate_message_bytes += bytes;
            stats.temporary_disk_peak_bytes = stats
                .temporary_disk_peak_bytes
                .max(directory_bytes(&options.directory));
            // This is a local rehearsal acknowledgment following actual AIR verify;
            // no capacity message is submitted to mainnet.
            capacity.certified = true;
            capacity.save()?;
            store.release_certified_sector(snapshot.epoch, &options.member, &id);
            eprintln!(
                "storage benchmark {}: cold sector {}/{} certified",
                measured.filter,
                index + 1,
                plans.len()
            );
            Ok((id, capacity.cert, stats))
        })();
        if let Err(error) = &result {
            if let Some(coordinator) = coordinator {
                coordinator.fail(error);
            } else {
                options.stop.store(true, Ordering::Relaxed);
            }
        }
        result
    })?;
    let mut certificates = std::collections::BTreeMap::new();
    for (id, cert, stats) in cold {
        certificates.insert(id, cert);
        measured.cold_label_seconds += stats.cold_label_seconds;
        measured.certificate_witness_seconds += stats.certificate_witness_seconds;
        measured.certificate_prove_seconds += stats.certificate_prove_seconds;
        measured.certificate_verify_seconds += stats.certificate_verify_seconds;
        measured.certificate_message_bytes += stats.certificate_message_bytes;
        measured.temporary_disk_peak_bytes = measured
            .temporary_disk_peak_bytes
            .max(stats.temporary_disk_peak_bytes);
    }
    if let Some(coordinator) = coordinator {
        coordinator.arrive(0)?;
    }
    for round in 0..options.rounds {
        check(options)?;
        eprintln!(
            "storage benchmark {}: full encode/proof round {}/{}",
            measured.filter,
            round + 1,
            options.rounds
        );
        fs::create_dir_all(
            options
                .directory
                .join("replicas")
                .join(&measured.filter)
                .join(round.to_string()),
        )
        .map_err(io)?;
        let db = Arc::new(quil_store::RocksDb::open(
            &options
                .directory
                .join("replicas")
                .join(&measured.filter)
                .join(round.to_string()),
        )?);
        let replicas = ReplicaStore::new(db.clone());
        let mut timing = RoundMeasurement::default();
        let mut claim = epoch_proof::SeatClaim {
            seal_epoch: snapshot.epoch,
            settle_epoch: snapshot.epoch - 2,
            ..Default::default()
        };
        let mut witness = epoch_proof::SeatWitness {
            certificates: Vec::new(),
            seals: Vec::new(),
            opened: Vec::new(),
        };
        let mut bindings = Vec::new();
        let mut counts = Vec::new();
        let encoded = crate::storage_jobs::for_each_parallel(&plans, |(prefix, _, n)| {
            let result = (|| {
                check(options)?;
                let mut timing = RoundMeasurement::default();
                fits(
                    proof::encoding_with_labels_bytes(*n),
                    options,
                    "snapshot encoding",
                )?;
                let start = Instant::now();
                // A fresh output DB forces the production full-read/encode path on
                // EVERY round even though the authenticated input roots are fixed.
                let (count, _, _) = encode_leaf(
                    &captured,
                    &options.member,
                    prefix,
                    &replicas,
                    Some(&store),
                    &|| options.stop.load(Ordering::Relaxed),
                )?;
                timing.encode_seconds += start.elapsed().as_secs_f64();
                let _memory = crate::storage_jobs::reserve_until(64 << 20, &|| {
                    options.stop.load(Ordering::Relaxed)
                })
                .ok_or_else(|| unavailable("benchmark binding stopped".into()))?;
                let leaf = quil_execution::global_intrinsic::leaf_id_bytes(&filter, prefix);
                let source = Source::new(
                    &store,
                    &replicas,
                    &options.member,
                    snapshot.epoch,
                    leaf.clone(),
                )?;
                let root = sector::Registration::parse(&source.stored.registration_root).unwrap();
                let start = Instant::now();
                let leaf_claim = captured.claim(
                    prefix,
                    &leaf,
                    &options.member,
                    &options.beacon,
                    root.data,
                    count,
                )?;
                let binding = captured.prove_binding_sparse(&leaf_claim, &source)?;
                binding::verify(&leaf_claim, &binding).map_err(QuilError::InvalidArgument)?;
                timing.binding_seconds += start.elapsed().as_secs_f64();
                let start = Instant::now();
                let fresh = sector::prove(
                    &options.member,
                    &leaf,
                    snapshot.epoch,
                    count,
                    &root,
                    &options.beacon,
                    &|t, i| source.open(t, i),
                )
                .map_err(QuilError::InvalidArgument)?;
                timing.fresh_proof_seconds += start.elapsed().as_secs_f64();
                let leaf = epoch_proof::SealedLeaf {
                    leaf_id: leaf,
                    n: count,
                    registered: root.registered(),
                    beacon: options.beacon.clone(),
                    persistent: Some(root),
                };
                Ok((count, binding, fresh, leaf, timing))
            })();
            if let Err(error) = &result {
                if let Some(coordinator) = coordinator {
                    coordinator.fail(error);
                } else {
                    options.stop.store(true, Ordering::Relaxed);
                }
            }
            result
        })?;
        for (count, binding, fresh, leaf, part) in encoded {
            counts.push(count);
            bindings.push(binding);
            witness.seals.push(fresh);
            witness.certificates.push(Vec::new());
            claim.seals.push(leaf);
            timing.encode_seconds += part.encode_seconds;
            timing.binding_seconds += part.binding_seconds;
            timing.fresh_proof_seconds += part.fresh_proof_seconds;
        }
        replicas.put_partition(snapshot.epoch, &filter, &captured.prefixes)?;
        replicas.put_leaf_nodes(snapshot.epoch, &filter, &counts)?;
        let epoch_claim = epoch_proof::EpochClaim {
            member: options.member,
            seats: vec![claim.clone()],
        };
        let prepared = crate::storage_epoch_batch::PreparedSeat {
            member: options.member,
            part: epoch_proof::SeatProof {
                shard_filter: filter.clone(),
                epoch: snapshot.epoch - 2,
                seals: true,
                bindings,
                ..Default::default()
            },
            claim,
            witness,
            solo: false,
        };
        let start = Instant::now();
        let sealed = {
            let bytes = crate::storage_epoch_batch::proving_bytes(std::slice::from_ref(&prepared))?;
            let _memory =
                crate::storage_jobs::reserve_until(bytes, &|| options.stop.load(Ordering::Relaxed))
                    .ok_or_else(|| unavailable("benchmark stopped waiting to prove".into()))?;
            crate::storage_epoch_batch::prove(vec![prepared])?
        };
        timing.fresh_proof_seconds += start.elapsed().as_secs_f64();
        timing.seal_message_bytes = sealed.len() as u64;
        let packet = epoch_proof::StorageEpochProof::from_canonical_bytes(&sealed)?;
        let start = Instant::now();
        protocol::verify(&epoch_claim, &packet.proof, &|id| {
            Ok(certificates.get(id).copied())
        })
        .map_err(QuilError::InvalidArgument)?;
        timing.fresh_verify_seconds = start.elapsed().as_secs_f64();
        if sealed.len() > quil_types::consensus::STORAGE_SEAL_BYTES_PER_FRAME.saturating_sub(4096) {
            return Err(unavailable(
                "snapshot seal exceeds GLOBAL frame budget".into(),
            ));
        }
        if let Some(coordinator) = coordinator {
            coordinator.arrive(1 + round * 3)?;
        }
        let mut slot = quil_types::consensus::StorageSeatSlot {
            epoch: snapshot.epoch,
            leaves: captured.prefixes.clone(),
            registered_at: 1,
            sealed_at: Some(2),
            frames: options.frames as u64,
            accumulator: [0; 32],
            chained: Vec::new(),
            open: true,
        };
        let beacons: Vec<[u8; 32]> = (0..options.frames)
            .map(|j| {
                digest(
                    &[
                        b"quil/readiness/frame/v1".as_slice(),
                        &options.beacon,
                        &(round as u64).to_be_bytes(),
                        &(j as u64).to_be_bytes(),
                    ]
                    .concat(),
                )
            })
            .collect();
        let start = Instant::now();
        let mut committed = Vec::new();
        for (j, beacon) in beacons.iter().enumerate() {
            check(options)?;
            let frame = j as u64 + 10;
            let root = commitment(&replicas, &options.member, &filter, &slot, frame, beacon)?;
            slot.chained.push((frame, frame));
            committed.push((frame, *beacon, root));
        }
        slot.accumulator = quil_execution::global_intrinsic::storage_seat::chain(
            committed.iter().map(|(f, b, r)| (*f, b.as_slice(), r)),
        );
        timing.frame_openings_seconds = start.elapsed().as_secs_f64();
        if let Some(coordinator) = coordinator {
            coordinator.arrive(2 + round * 3)?;
        }
        let start = Instant::now();
        let settled = prepare_member_seat(
            &replicas,
            &options.member,
            &filter,
            snapshot.epoch,
            None,
            Some((&slot, &beacons)),
        )?;
        timing.settlement_prepare_seconds = start.elapsed().as_secs_f64();
        let settlement_claim = epoch_proof::EpochClaim {
            member: options.member,
            seats: vec![settled.claim.clone()],
        };
        let start = Instant::now();
        let message = {
            let bytes = crate::storage_epoch_batch::proving_bytes(std::slice::from_ref(&settled))?;
            let _memory =
                crate::storage_jobs::reserve_until(bytes, &|| options.stop.load(Ordering::Relaxed))
                    .ok_or_else(|| unavailable("benchmark stopped waiting to settle".into()))?;
            crate::storage_epoch_batch::prove(vec![settled])?
        };
        timing.settlement_prove_seconds = start.elapsed().as_secs_f64();
        timing.settlement_message_bytes = message.len() as u64;
        let start = Instant::now();
        let proof = epoch_proof::StorageEpochProof::from_canonical_bytes(&message)?;
        settlement_claim
            .verify(&proof.proof)
            .map_err(QuilError::InvalidArgument)?;
        timing.settlement_verify_seconds = start.elapsed().as_secs_f64();
        if message.len() > quil_types::consensus::STORAGE_SEAL_BYTES_PER_FRAME {
            return Err(unavailable("settlement exceeds GLOBAL frame budget".into()));
        }
        measured.rounds.push(timing);
        if let Some(coordinator) = coordinator {
            coordinator.arrive(3 + round * 3)?;
        }
    }
    Ok(measured)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentic_snapshot_runs_cold_and_two_full_encode_settlement_rounds() {
        quil_crypto::init();
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(Some(1393));
        crate::storage_jobs::set_available_for_test(Some(64 << 30));
        let graph = super::super::super::tests::test_crdt();
        let app = [87; 32];
        graph
            .add_vertex(
                &quil_hypergraph::Location {
                    app_address: app,
                    data_address: [1; 32],
                },
                &[7; 100],
            )
            .unwrap();
        graph.commit(1).unwrap();
        let snapshot = current_source(&graph, &app, 1500).snapshot;
        let dir = tempfile::tempdir().unwrap();
        let options = BenchmarkOptions {
            directory: dir.path().to_owned(),
            member: [99; 32],
            beacon: vec![31; 32],
            rounds: 2,
            frames: 2,
            memory_budget_bytes: 64 << 30,
            stop: Arc::new(AtomicBool::new(false)),
        };
        let store = LabelStore::with_space(
            dir.path().join("labels"),
            crate::storage_labels::ample_space(),
        );
        let before = quil_types::consensus::persistent_storage_epoch_thread_override();
        let measured = measure_with_store(
            graph,
            snapshot.clone(),
            app.to_vec(),
            &options,
            &store,
            None,
        )
        .unwrap();
        assert_eq!(
            quil_types::consensus::persistent_storage_epoch_thread_override(),
            before
        );
        assert_eq!(measured.rounds.len(), 2);
        assert_eq!(measured.sectors, 1);
        assert_eq!(
            measured.roots,
            snapshot.roots.iter().map(hex::encode).collect::<Vec<_>>()
        );
        assert!(measured.certificate_message_bytes > 0);
        assert!(measured.estimated_settlement_peak_bytes > measured.replica_bytes);
        for round in measured.rounds {
            assert!(round.encode_seconds > 0.);
            assert!(round.seal_message_bytes > 0);
            assert!(round.settlement_message_bytes > 0);
        }
        crate::storage_jobs::set_available_for_test(None);
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(None);
    }
}

#[cfg(test)]
mod allocation_tests {
    use super::*;
    fn inputs() -> Vec<BenchmarkInput> {
        (0..3)
            .map(|i| {
                let graph = super::super::super::tests::test_crdt();
                let app = [101 + i; 32];
                graph
                    .add_vertex(
                        &quil_hypergraph::Location {
                            app_address: app,
                            data_address: [1; 32],
                        },
                        &[9; 100],
                    )
                    .unwrap();
                graph.commit(1).unwrap();
                let snapshot = current_source(&graph, &app, 1500).snapshot;
                BenchmarkInput {
                    crdt: graph,
                    snapshot,
                    filter: app.to_vec(),
                    keep: Box::new(()),
                }
            })
            .collect()
    }
    fn options(path: &Path) -> BenchmarkOptions {
        BenchmarkOptions {
            directory: path.to_owned(),
            member: [109; 32],
            beacon: vec![41; 32],
            rounds: 2,
            frames: 2,
            memory_budget_bytes: 64 << 30,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }
    #[test]
    fn more_shards_than_cpus_finish_every_parallel_phase_with_real_proofs() {
        quil_crypto::init();
        quil_types::consensus::set_stable_replica_key_epoch_for_thread(Some(1393));
        crate::storage_jobs::set_job_slots_for_test(2);
        crate::storage_jobs::set_available_for_test(Some(64 << 30));
        let dir = tempfile::tempdir().unwrap();
        let (measured, allocation) = measure_allocation(inputs(), &options(dir.path())).unwrap();
        assert_eq!(measured.len(), 3);
        assert_eq!(allocation.parallel_jobs, 2);
        assert_eq!(allocation.rounds.len(), 2);
        assert!(allocation.cold_wall_seconds > 0.);
        for shard in measured {
            assert_eq!(shard.rounds.len(), 2);
            assert!(shard.certificate_message_bytes > 0);
        }
        for round in allocation.rounds {
            assert!(round.registration_wall_seconds > 0.);
            assert!(round.settlement_wall_seconds > 0.);
        }
        assert_eq!(
            quil_types::consensus::persistent_storage_epoch_thread_override(),
            None
        );
    }
    #[test]
    fn a_failed_parallel_shard_cancels_other_phase_waiters() {
        crate::storage_jobs::set_job_slots_for_test(2);
        let dir = tempfile::tempdir().unwrap();
        let mut opts = options(dir.path());
        opts.memory_budget_bytes = 1;
        assert!(measure_allocation(inputs(), &opts).is_err());
        assert!(opts.stop.load(Ordering::Relaxed));
    }
}

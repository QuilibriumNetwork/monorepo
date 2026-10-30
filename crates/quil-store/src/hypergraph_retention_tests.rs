use super::*;
use quil_hypergraph::{HypergraphCrdt, Location};
use quil_types::store::HypergraphStore;

const APP: [u8; 32] = [9; 32];

struct Fixture {
    _dir: tempfile::TempDir,
    db: quil_forest::CoordinatedDb,
    store: Arc<RocksHypergraphStore>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = quil_forest::CoordinatedDb::new(rocksdb::DB::open_default(dir.path()).unwrap());
        let store = Arc::new(RocksHypergraphStore::new(db.clone()));
        Self {
            _dir: dir,
            db,
            store,
        }
    }

    /// A fresh CRDT over the same database, as after a restart.
    fn crdt(&self) -> Arc<HypergraphCrdt> {
        let crdt = Arc::new(HypergraphCrdt::new(
            self.store.clone(),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            self.db.clone(),
            FOREST_NAMESPACE,
        ));
        crdt.set_unified_tree(true);
        crdt.set_app_shard_prefixes(APP, vec![vec![]]);
        crdt
    }

    fn blob_versions(&self, location: &Location) -> Vec<u64> {
        let shard = quil_hypergraph::shard_key_for_location(location);
        let prefix = crate::encoding::hypergraph_vertex_data_v2_vk_prefix(
            "vertex",
            "adds",
            &shard,
            &location.to_id(),
        );
        self.db
            .iterator(rocksdb::IteratorMode::From(
                &prefix,
                rocksdb::Direction::Forward,
            ))
            .map(|entry| entry.unwrap().0)
            .take_while(|key| key.starts_with(&prefix) && key.len() == prefix.len() + 8)
            .map(|key| u64::from_be_bytes(key[key.len() - 8..].try_into().unwrap()))
            .collect()
    }
}

fn record() -> Location {
    Location {
        app_address: APP,
        data_address: [1; 32],
    }
}

/// Commit `record` = "value {frame}" (and one untouched vertex) at each frame;
/// returns each frame's vertex-adds root.
fn commit_frames(
    crdt: &HypergraphCrdt,
    frames: std::ops::RangeInclusive<u64>,
) -> Vec<(u64, [u8; 32])> {
    let shard = quil_hypergraph::shard_key_for_location(&record());
    frames
        .map(|frame| {
            crdt.add_vertex(&record(), format!("value {frame}").as_bytes())
                .unwrap();
            if frame == 1 {
                crdt.add_vertex(
                    &Location {
                        app_address: APP,
                        data_address: [2; 32],
                    },
                    b"untouched",
                )
                .unwrap();
            }
            let roots = crdt.commit(frame).unwrap();
            (frame, roots[&shard][0].as_slice().try_into().unwrap())
        })
        .collect()
}

#[test]
fn retention_keeps_recent_roots_and_every_newest_value_and_reclaims_the_rest() {
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    let roots = commit_frames(&crdt, 1..=10);
    assert_eq!(fixture.blob_versions(&record()).len(), 10);

    // Keep the last 3 frames: cull at frame 7, whose state stays readable.
    let (trees, nodes) = crdt.prune_retaining(3, usize::MAX).unwrap();
    assert_eq!(trees, 1);
    assert!(nodes > 0, "superseded forest nodes are reclaimed");
    assert_eq!(
        fixture.blob_versions(&record()).len(),
        4,
        "frames 7..=10 remain"
    );
    assert_eq!(
        crdt.get_vertex_data_checked(&record()).unwrap().as_deref(),
        Some(&b"value 10"[..])
    );
    let untouched = Location {
        app_address: APP,
        data_address: [2; 32],
    };
    assert_eq!(
        crdt.get_vertex_data_checked(&untouched).unwrap().as_deref(),
        Some(&b"untouched"[..])
    );
    let forest = quil_forest::Forest::with_namespace(fixture.db.clone(), FOREST_NAMESPACE);
    for (frame, root) in &roots {
        let resolved = crdt.resolve_root(&APP, 0, *root);
        if *frame >= 7 {
            let (version, _) =
                resolved.unwrap_or_else(|| panic!("frame {frame} root must stay resolvable"));
            assert_eq!(
                forest
                    .shard_phase_root(&APP, quil_forest::Phase::VertexAdds, version)
                    .unwrap(),
                Some(*root),
                "frame {frame} tree must stay readable"
            );
        } else {
            assert!(resolved.is_none(), "frame {frame} is past retention");
        }
    }

    // A later pass over the same history finds nothing more to do.
    assert_eq!(crdt.prune_retaining(3, usize::MAX).unwrap().1, 0);
    assert_eq!(fixture.blob_versions(&record()).len(), 4);
}

/// Versions restarted without a wipe (the old version-zero rebuild): the
/// index holds a history that fell back. Nothing is pruned, because stale
/// records of the old history may name node keys the rebuild reused.
#[test]
fn retention_leaves_a_tree_whose_versions_restarted_untouched() {
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    commit_frames(&crdt, 1..=6);
    let txn = fixture.store.new_transaction(false).unwrap();
    for (version, frame) in [(40u64, 1u64), (41, 2), (42, 3)] {
        fixture
            .store
            .put_root_version(
                txn.as_ref(),
                "vertex",
                "adds",
                &APP,
                &[version as u8; 32],
                version,
                frame,
            )
            .unwrap();
    }
    txn.commit().unwrap();
    let before = fixture.blob_versions(&record());
    assert_eq!(crdt.prune_retaining(1, usize::MAX).unwrap(), (0, 0));
    assert_eq!(fixture.blob_versions(&record()), before);
    assert_eq!(
        crdt.get_vertex_data_checked(&record()).unwrap().as_deref(),
        Some(&b"value 6"[..])
    );
}

/// A reset that wipes the tree and its blobs (the prover reset) also drops its
/// index, so the rebuilt tree's history is clean and prunable again.
#[test]
fn a_wiping_reset_drops_its_index_and_the_rebuilt_tree_can_be_pruned() {
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    let old = commit_frames(&crdt, 1..=5);
    crdt.reset_shard_forest_trees(&APP).unwrap();
    fixture
        .store
        .clear_shard_underlying(&quil_hypergraph::shard_key_for_location(&record()))
        .unwrap();
    assert!(old
        .iter()
        .all(|(_, root)| crdt.resolve_root(&APP, 0, *root).is_none()));
    commit_frames(&crdt, 6..=12);
    let (trees, _) = crdt.prune_retaining(3, usize::MAX).unwrap();
    assert_eq!(trees, 1);
    assert_eq!(
        fixture.blob_versions(&record()).len(),
        4,
        "frames 9..=12 remain"
    );
    assert_eq!(
        crdt.get_vertex_data_checked(&record()).unwrap().as_deref(),
        Some(&b"value 12"[..])
    );
}

/// A tree head below the watermark (a store whose versions ran backwards
/// without a new index entry) keeps all its nodes.
#[test]
fn retention_refuses_a_forest_watermark_above_the_tree_head() {
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    commit_frames(&crdt, 1..=6);
    drop(crdt);
    let forest = quil_forest::Forest::with_namespace(fixture.db.clone(), FOREST_NAMESPACE);
    forest
        .write_head_version(&APP, quil_forest::Phase::VertexAdds, 0)
        .unwrap();
    let crdt = fixture.crdt();
    assert_eq!(crdt.prune_retaining(1, usize::MAX).unwrap(), (0, 0));
}

/// Blob deletions are bounded per pass and resume on the next.
#[test]
fn retention_blob_deletions_are_bounded_per_pass() {
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    commit_frames(&crdt, 1..=10);
    crdt.prune_retaining(2, 2).unwrap();
    assert_eq!(fixture.blob_versions(&record()).len(), 8);
    crdt.prune_retaining(2, 100).unwrap();
    assert_eq!(fixture.blob_versions(&record()).len(), 3);
    assert_eq!(
        crdt.get_vertex_data_checked(&record()).unwrap().as_deref(),
        Some(&b"value 10"[..])
    );
}

/// Superseded leaf values go with the retention pass, but every retained
/// root still reads each vertex's value: the record rewritten every frame and
/// the vertex written once, whose only value lies below the watermark.
#[test]
fn retention_drops_superseded_leaf_values_and_retained_roots_still_read_every_leaf() {
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    let roots = commit_frames(&crdt, 1..=10);
    let untouched = Location {
        app_address: APP,
        data_address: [2; 32],
    };
    let keys = || fixture.db.iterator(rocksdb::IteratorMode::Start).count();

    let nodes_only = crdt.prune_retaining_with(3, usize::MAX, None).unwrap();
    assert_eq!(nodes_only.values, 0, "values are kept unless asked for");
    let before = keys();
    let pass = crdt
        .prune_retaining_with(3, usize::MAX, Some(usize::MAX))
        .unwrap();
    assert!(pass.values > 0, "the record's superseded values go");
    assert_eq!(before - keys(), pass.values, "only value keys were deleted");
    assert_eq!(
        crdt.prune_retaining_with(3, usize::MAX, Some(usize::MAX))
            .unwrap()
            .values,
        0
    );

    let forest = quil_forest::Forest::with_namespace(fixture.db.clone(), FOREST_NAMESPACE);
    for (frame, root) in roots.iter().filter(|(frame, _)| *frame >= 7) {
        let (version, _) = crdt.resolve_root(&APP, 0, *root).unwrap();
        assert_eq!(
            forest
                .shard_phase_root(&APP, quil_forest::Phase::VertexAdds, version)
                .unwrap(),
            Some(*root)
        );
        let read = |location: &Location| {
            forest
                .shard_phase_get_with_proof_raw(
                    &APP,
                    quil_forest::Phase::VertexAdds,
                    version,
                    &location.data_address,
                )
                .unwrap()
                .0
        };
        let expected = quil_tries::vertex_leaf_value(format!("value {frame}").as_bytes()).unwrap();
        assert_eq!(
            read(&record()),
            Some(expected),
            "frame {frame}: the record's value at its version"
        );
        assert_eq!(
            read(&untouched),
            Some(quil_tries::vertex_leaf_value(b"untouched").unwrap()),
            "frame {frame}: a value written once, below the watermark, stays readable"
        );
    }
    assert_eq!(
        crdt.get_vertex_data_checked(&record()).unwrap().as_deref(),
        Some(&b"value 10"[..])
    );
}

/// A value pass bounded by its budget deletes at most that many, never a
/// partially scanned key's floor, and a later pass finishes the job.
#[test]
fn retention_value_deletions_are_bounded_per_pass() {
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    commit_frames(&crdt, 1..=10);
    let first = crdt.prune_retaining_with(3, usize::MAX, Some(2)).unwrap();
    assert!(first.values <= 2);
    let rest = crdt
        .prune_retaining_with(3, usize::MAX, Some(usize::MAX))
        .unwrap();
    assert!(rest.values > 0);
    assert_eq!(
        crdt.prune_retaining_with(3, usize::MAX, Some(usize::MAX))
            .unwrap()
            .values,
        0
    );
    assert_eq!(
        crdt.get_vertex_data_checked(&record()).unwrap().as_deref(),
        Some(&b"value 10"[..])
    );
}

/// A measurement, not a check (run with `--run-ignored ignored-only`): one
/// retention pass over a large synthetic blob keyspace, a tree with many
/// rewritten leaves and sibling trees of the same application (a split
/// application's sub-shards, each with a retention window of index entries),
/// while a reader takes the commit lock every 2 ms and a writer commits every
/// 500 ms. Sizes from `QUIL_PRUNE_MEASURE_{LEAVES,FRAMES,VERTICES,VERSIONS,
/// SIBLINGS,ENTRIES}`.
#[test]
#[ignore]
fn measure_a_retention_pass_and_the_longest_commit_lock_wait_beside_it() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    let size = |name: &str, default: u64| {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(default)
    };
    let leaves = size("QUIL_PRUNE_MEASURE_LEAVES", 10_000);
    let frames = size("QUIL_PRUNE_MEASURE_FRAMES", 12);
    let vertices = size("QUIL_PRUNE_MEASURE_VERTICES", 300_000);
    let versions = size("QUIL_PRUNE_MEASURE_VERSIONS", 4);
    let siblings = size("QUIL_PRUNE_MEASURE_SIBLINGS", 0);
    let entries = size("QUIL_PRUNE_MEASURE_ENTRIES", 2_160);
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    let leaf = |i: u64| {
        let mut data_address = [0u8; 32];
        data_address[..8].copy_from_slice(&i.to_be_bytes());
        data_address[31] = 0xA5;
        Location {
            app_address: APP,
            data_address,
        }
    };
    let built = Instant::now();
    for frame in 1..=frames {
        for i in 0..leaves {
            crdt.add_vertex(&leaf(i), format!("leaf {i} frame {frame}").as_bytes())
                .unwrap();
        }
        crdt.commit(frame).unwrap();
    }
    // Blob versions the tree does not reference: most above every
    // watermark (scanned, kept), one vertex in ten with two below it.
    let shard = quil_hypergraph::shard_key_for_location(&record());
    let blob = vec![0xAB; 128];
    let mut written = 0u64;
    for chunk in (0..vertices).collect::<Vec<_>>().chunks(20_000) {
        let txn = fixture.store.new_transaction(false).unwrap();
        for &i in chunk {
            let mut id = [0u8; 64];
            id[..32].copy_from_slice(&APP);
            id[32..40].copy_from_slice(&i.to_be_bytes());
            id[63] = 0x5A;
            let low: &[u64] = if i % 10 == 0 { &[1, 2] } else { &[] };
            for version in low
                .iter()
                .copied()
                .chain((0..versions).map(|v| 1_000_000 + v))
            {
                fixture
                    .store
                    .save_vertex_underlying_versioned(
                        txn.as_ref(),
                        "vertex",
                        "adds",
                        &shard,
                        &id,
                        &blob,
                        version,
                    )
                    .unwrap();
                written += 1;
            }
        }
        txn.commit().unwrap();
    }
    // Sibling trees under the same application, each with a clean history
    // of `entries` versions. All but the first 20 lie in its newest frame, so
    // its index stays a full retention window through the short retention
    // this measurement prunes the record's tree with.
    for sibling in 0..siblings {
        let mut id = APP.to_vec();
        id.extend_from_slice(&[0x00, 0x08, (sibling >> 8) as u8, sibling as u8]);
        let txn = fixture.store.new_transaction(false).unwrap();
        for entry in 1..=entries {
            let mut root = [0u8; 32];
            root[..8].copy_from_slice(&sibling.to_be_bytes());
            root[8..16].copy_from_slice(&entry.to_be_bytes());
            fixture
                .store
                .put_root_version(
                    txn.as_ref(),
                    "vertex",
                    "adds",
                    &id,
                    &root,
                    entry,
                    if entry <= 20 { 1 } else { 1_000 },
                )
                .unwrap();
        }
        txn.commit().unwrap();
    }
    fixture.db.flush().unwrap();
    fixture.db.compact_range(None::<&[u8]>, None::<&[u8]>);
    eprintln!(
        "MEASURE built leaves={leaves} frames={frames} vertices={vertices} blob_versions={written} siblings={siblings} entries={entries} build_s={}",
        built.elapsed().as_secs()
    );

    let pass = |label: &str, first_commit: u64| -> u64 {
        let stop = AtomicBool::new(false);
        let (pass, elapsed, waits, commits) = std::thread::scope(|scope| {
            let reader = scope.spawn(|| {
                let mut waits: Vec<Duration> = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    let asked = Instant::now();
                    crdt.read_execution_record(b"measure").unwrap();
                    waits.push(asked.elapsed());
                    std::thread::sleep(Duration::from_millis(2));
                }
                waits
            });
            let writer = scope.spawn(|| {
                let mut frame = first_commit;
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(500));
                    crdt.add_vertex(&record(), format!("value {frame}").as_bytes())
                        .unwrap();
                    crdt.commit(frame).unwrap();
                    frame += 1;
                }
                frame
            });
            let started = Instant::now();
            let pass = crdt
                .prune_retaining_with(2, 100_000, Some(100_000))
                .unwrap();
            let elapsed = started.elapsed();
            stop.store(true, Ordering::Relaxed);
            let waits = reader.join().unwrap();
            let last = writer.join().unwrap();
            (pass, elapsed, waits, last)
        });
        let longest = waits.iter().max().copied().unwrap_or_default();
        let over_100ms = waits
            .iter()
            .filter(|w| **w > Duration::from_millis(100))
            .count();
        eprintln!(
            "MEASURE {label} pass_ms={} scan_ms={} trees={} nodes={} values={} blobs={} holds={} max_hold_ms={} held_ms={} replans={} max_replan_ms={} commits={} reader_calls={} reader_max_wait_ms={} reader_waits_over_100ms={over_100ms}",
            elapsed.as_millis(),
            pass.scan.as_millis(),
            pass.trees,
            pass.nodes,
            pass.values,
            pass.blobs,
            pass.holds,
            pass.max_hold.as_millis(),
            pass.held.as_millis(),
            pass.replans,
            pass.max_replan.as_millis(),
            commits - first_commit,
            waits.len(),
            longest.as_millis(),
        );
        commits
    };
    let next_frame = pass("first", frames + 1);
    // One more frame of every leaf: the steady state, a full scan that
    // finds little to delete.
    for i in 0..leaves {
        crdt.add_vertex(&leaf(i), format!("leaf {i} frame {next_frame}").as_bytes())
            .unwrap();
    }
    crdt.commit(next_frame).unwrap();
    pass("steady", next_frame + 1);
}

/// The scans of a retention pass hold no lock: a reader asking for the commit
/// lock while a pass scans for seconds gets it at once, and the pass still
/// reclaims what it found, in holds far shorter than its scans.
#[test]
fn a_reader_gets_the_commit_lock_while_a_retention_pass_scans() {
    use quil_hypergraph::RetentionStep;
    use std::time::{Duration, Instant};
    const SCAN: Duration = Duration::from_secs(2);
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    commit_frames(&crdt, 1..=10);
    let (scanning_tx, scanning_rx) = std::sync::mpsc::channel();
    let (pass, waited) = std::thread::scope(|scope| {
        let pruner = scope.spawn(|| {
            crdt.prune_retaining_observed(3, usize::MAX, Some(usize::MAX), &mut |step| {
                // The scans of a large store take seconds from here on.
                if let RetentionStep::Planned { .. } = step {
                    scanning_tx.send(()).unwrap();
                    std::thread::sleep(SCAN);
                }
            })
            .unwrap()
        });
        scanning_rx.recv().unwrap();
        let asked = Instant::now();
        crdt.read_execution_record(b"reader").unwrap();
        let waited = asked.elapsed();
        (pruner.join().unwrap(), waited)
    });
    assert!(
        waited < Duration::from_millis(500),
        "a reader waited {waited:?} for the commit lock while the pass scanned"
    );
    assert_eq!(pass.trees, 1, "{pass:?}");
    assert!(
        pass.blobs > 0 && pass.nodes > 0 && pass.values > 0,
        "{pass:?}"
    );
    assert!(pass.holds >= 1 && pass.max_hold < SCAN, "{pass:?}");
    assert_eq!(
        fixture.blob_versions(&record()).len(),
        4,
        "frames 7..=10 remain"
    );
}

/// A frame committed while a pass scans is above every watermark the scan
/// read, and deletions follow the live index: the late frames, every root
/// the live retention keeps and the newest value all stay readable.
#[test]
fn frames_committed_during_a_retention_pass_stay_readable() {
    use quil_hypergraph::RetentionStep;
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    let mut roots = commit_frames(&crdt, 1..=10);
    let mut late = Vec::new();
    let pass = crdt
        .prune_retaining_observed(3, usize::MAX, Some(usize::MAX), &mut |step| {
            if matches!(step, RetentionStep::Scanned { .. }) {
                late = commit_frames(&crdt, 11..=12);
            }
        })
        .unwrap();
    assert_eq!(late.len(), 2, "the commits ran during the pass");
    assert!(!pass.abandoned, "{pass:?}");
    roots.extend(late);
    // The live retention at the deletions: frames 9..=12.
    assert_eq!(
        fixture.blob_versions(&record()).len(),
        4,
        "frames 9..=12 remain"
    );
    let forest = quil_forest::Forest::with_namespace(fixture.db.clone(), FOREST_NAMESPACE);
    for (frame, root) in roots.iter().filter(|(frame, _)| *frame >= 9) {
        let (version, _) = crdt
            .resolve_root(&APP, 0, *root)
            .unwrap_or_else(|| panic!("frame {frame} root must stay resolvable"));
        assert_eq!(
            forest
                .shard_phase_root(&APP, quil_forest::Phase::VertexAdds, version)
                .unwrap(),
            Some(*root),
            "frame {frame} tree must stay readable"
        );
        assert_eq!(
            forest
                .shard_phase_get_with_proof_raw(
                    &APP,
                    quil_forest::Phase::VertexAdds,
                    version,
                    &record().data_address,
                )
                .unwrap()
                .0,
            Some(quil_tries::vertex_leaf_value(format!("value {frame}").as_bytes()).unwrap()),
            "frame {frame}: the record's value at its version"
        );
    }
    assert_eq!(
        crdt.get_vertex_data_checked(&record()).unwrap().as_deref(),
        Some(&b"value 12"[..])
    );
}

/// A tree wiped and rebuilt while a pass scans restarts its versions, so the
/// versions the scan found below its watermark may now be the rebuilt tree's
/// history. The pass deletes none of it.
#[test]
fn a_tree_rebuilt_during_a_retention_pass_keeps_its_new_history() {
    use quil_hypergraph::RetentionStep;
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    commit_frames(&crdt, 1..=10);
    let mut rebuilt = Vec::new();
    let pass = crdt
        .prune_retaining_observed(3, usize::MAX, Some(usize::MAX), &mut |step| {
            if matches!(step, RetentionStep::Scanned { .. }) {
                crdt.reset_shard_forest_trees(&APP).unwrap();
                fixture
                    .store
                    .clear_shard_underlying(&quil_hypergraph::shard_key_for_location(&record()))
                    .unwrap();
                rebuilt = commit_frames(&crdt, 11..=14);
            }
        })
        .unwrap();
    assert_eq!(rebuilt.len(), 4, "the rebuild ran during the pass");
    // The wipe moved the tree generation: the pass ends at its first hold.
    assert!(pass.abandoned, "{pass:?}");
    assert_eq!(pass.holds, 0, "{pass:?}");
    assert_eq!(
        fixture.blob_versions(&record()).len(),
        4,
        "every version of the rebuilt tree remains"
    );
    let forest = quil_forest::Forest::with_namespace(fixture.db.clone(), FOREST_NAMESPACE);
    for (frame, root) in &rebuilt {
        let (version, _) = crdt
            .resolve_root(&APP, 0, *root)
            .unwrap_or_else(|| panic!("frame {frame} root must stay resolvable"));
        assert_eq!(
            forest
                .shard_phase_root(&APP, quil_forest::Phase::VertexAdds, version)
                .unwrap(),
            Some(*root),
            "frame {frame} tree must stay readable"
        );
    }
    assert_eq!(
        crdt.get_vertex_data_checked(&record()).unwrap().as_deref(),
        Some(&b"value 14"[..])
    );
}

/// A tree that turns unclean between the scan and the first hold (an index
/// entry reusing a version, as a restart without a wipe leaves) moves no tree
/// generation. Only the live replan sees it, and refuses the tree: nothing
/// the scan planned is deleted.
#[test]
fn a_tree_turning_unclean_after_the_scan_keeps_everything() {
    use quil_hypergraph::RetentionStep;
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    commit_frames(&crdt, 1..=10);
    let before = fixture.blob_versions(&record());
    let mut planned = 0;
    let pass = crdt
        .prune_retaining_observed(3, usize::MAX, Some(usize::MAX), &mut |step| {
            if let RetentionStep::Scanned { blob_vertices, .. } = step {
                planned = blob_vertices;
                let txn = fixture.store.new_transaction(false).unwrap();
                fixture
                    .store
                    .put_root_version(txn.as_ref(), "vertex", "adds", &APP, &[0xEE; 32], 5, 11)
                    .unwrap();
                txn.commit().unwrap();
            }
        })
        .unwrap();
    assert!(planned > 0, "the scan found versions to delete");
    assert!(!pass.abandoned, "{pass:?}");
    assert_eq!(
        (pass.blobs, pass.nodes, pass.values, pass.roots),
        (0, 0, 0, 0),
        "{pass:?}"
    );
    assert_eq!(fixture.blob_versions(&record()), before);
}

/// Blob versions are shared by every tree of an application. A sibling tree
/// indexed after the scan, without a watermark of its own (a sub-shard that
/// just began committing), makes the keyspace unprunable, though the tree the
/// scan planned stays prunable: its nodes go, the shared blobs stay.
#[test]
fn a_sibling_tree_indexed_after_the_scan_holds_back_the_shared_blobs() {
    use quil_hypergraph::RetentionStep;
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    commit_frames(&crdt, 1..=10);
    let before = fixture.blob_versions(&record());
    let mut sibling = APP.to_vec();
    sibling.extend_from_slice(&[0x00, 0x08, 0x0e]);
    let pass = crdt
        .prune_retaining_observed(3, usize::MAX, Some(usize::MAX), &mut |step| {
            if matches!(step, RetentionStep::Scanned { .. }) {
                let txn = fixture.store.new_transaction(false).unwrap();
                fixture
                    .store
                    .put_root_version(txn.as_ref(), "vertex", "adds", &sibling, &[0xAB; 32], 1, 10)
                    .unwrap();
                txn.commit().unwrap();
            }
        })
        .unwrap();
    assert_eq!(pass.blobs, 0, "{pass:?}");
    assert_eq!(fixture.blob_versions(&record()), before);
    assert_eq!(pass.trees, 1, "{pass:?}");
    assert!(pass.nodes > 0, "{pass:?}");
}

/// `count` vertices rewritten at each of `frames`.
fn commit_many(crdt: &HypergraphCrdt, frames: std::ops::RangeInclusive<u64>, count: u8) {
    for frame in frames {
        for vertex in 0..count {
            crdt.add_vertex(
                &Location {
                    app_address: APP,
                    data_address: [0x40 + vertex; 32],
                },
                format!("vertex {vertex} frame {frame}").as_bytes(),
            )
            .unwrap();
        }
        crdt.commit(frame).unwrap();
    }
}

/// Holds of one chunk each: every kind of work is cut short by its hold.
fn one_chunk_holds() -> quil_hypergraph::RetentionPacing {
    quil_hypergraph::RetentionPacing {
        hold: std::time::Duration::ZERO,
        pause: std::time::Duration::ZERO,
        chunk: 1,
        node_batch: 1,
    }
}

/// Blob, node and value work cut short by its hold resumes in the next: in
/// holds of one chunk, a pass deletes exactly what one unhurried pass does.
#[test]
fn work_cut_short_by_a_hold_resumes_in_the_next() {
    let run = |pacing: quil_hypergraph::RetentionPacing| {
        let fixture = Fixture::new();
        let crdt = fixture.crdt();
        commit_many(&crdt, 1..=10, 6);
        crdt.prune_retaining_paced(3, usize::MAX, Some(usize::MAX), pacing, &mut |_| {})
            .unwrap()
    };
    let whole = run(quil_hypergraph::RetentionPacing::default());
    let paced = run(one_chunk_holds());
    assert!(
        whole.blobs > 1 && whole.nodes > 1 && whole.values > 1,
        "{whole:?}"
    );
    assert_eq!(
        (
            paced.blobs,
            paced.nodes,
            paced.values,
            paced.roots,
            paced.trees
        ),
        (
            whole.blobs,
            whole.nodes,
            whole.values,
            whole.roots,
            whole.trees
        ),
        "(blobs, nodes, values, roots, trees)"
    );
    assert!(
        paced.holds > whole.nodes + 6,
        "every chunk took its own hold: {paced:?}"
    );
}

/// A replan stays valid until another writer takes the commit lock: readers
/// do not invalidate it, so a pass over many holds replans once; a commit
/// between two holds costs exactly one more.
#[test]
fn a_pass_replans_only_after_another_writer_held_the_commit_lock() {
    use quil_hypergraph::RetentionStep;
    let run = |commit_between: bool| {
        let fixture = Fixture::new();
        let crdt = fixture.crdt();
        commit_many(&crdt, 1..=10, 6);
        let mut held = 0;
        crdt.prune_retaining_paced(
            3,
            usize::MAX,
            Some(usize::MAX),
            one_chunk_holds(),
            &mut |step| {
                if matches!(step, RetentionStep::Held { .. }) {
                    held += 1;
                    crdt.read_execution_record(b"reader").unwrap();
                    if commit_between && held == 2 {
                        commit_many(&crdt, 11..=11, 6);
                    }
                }
            },
        )
        .unwrap()
    };
    let quiet = run(false);
    assert!(quiet.holds > 3, "{quiet:?}");
    assert_eq!(quiet.replans, 1, "{quiet:?}");
    let busy = run(true);
    assert_eq!(busy.replans, 2, "{busy:?}");
}

/// A tree indexed with no known head is refused for its nodes and its values
/// alike, and warned about once in the pass.
#[test]
fn a_tree_without_a_head_is_warned_about_once_a_pass() {
    let fixture = Fixture::new();
    let crdt = fixture.crdt();
    let mut sibling = APP.to_vec();
    sibling.extend_from_slice(&[0x00, 0x08, 0x0e]);
    let forest = quil_forest::Forest::with_namespace(fixture.db.clone(), FOREST_NAMESPACE);
    let txn = fixture.store.new_transaction(false).unwrap();
    for version in 1..=10u64 {
        let root = forest
            .commit_shard_phase_raw(
                &sibling,
                quil_forest::Phase::VertexAdds,
                version,
                vec![(vec![7; 32], format!("value {version}").into_bytes())],
            )
            .unwrap();
        fixture
            .store
            .put_root_version(
                txn.as_ref(),
                "vertex",
                "adds",
                &sibling,
                &root,
                version,
                version,
            )
            .unwrap();
    }
    txn.commit().unwrap();
    let mut value_keys = 0;
    let pass = crdt
        .prune_retaining_observed(3, usize::MAX, Some(usize::MAX), &mut |step| {
            if let quil_hypergraph::RetentionStep::Scanned {
                value_keys: found, ..
            } = step
            {
                value_keys = found;
            }
        })
        .unwrap();
    assert!(value_keys > 0, "both its nodes and its values are visited");
    assert_eq!(pass.refused_trees, 1, "{pass:?}");
    assert_eq!((pass.trees, pass.nodes, pass.values), (0, 0, 0), "{pass:?}");
}

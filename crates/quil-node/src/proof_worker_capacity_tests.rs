//! How many proofs a regular node verifies at once. These tests use only
//! interfaces of the release base, so they show its outcome there.
use super::*;
use quil_engine::admission_verify::{background_threads, AdmissionJob, AdmissionQueue};
use quil_execution::manager::PreverifyCounts;
use std::sync::{Arc, Condvar, Mutex};

const GIB: u64 = 1 << 30;

/// Mainnet, 2026-11-02: a regular node verified one batch shield at a time
/// across all its shards, 5-7 of about 100 s per 600 s, while its shards
/// waited on their own verdicts to apply frames and 25 of 107 shards missed
/// quorum. A 16-CPU node with memory to spare has the machine for three.
#[test]
fn a_regular_nodes_queue_verifies_by_its_cpus() {
    let slots = verifier_slots(
        &ProofWorkerConfig::default(),
        false,
        Some(16),
        Some(64 * GIB),
    );
    let queue = AdmissionQueue::new(16, 1 << 20, true);
    queue.set_threads(background_threads(Some(slots.slots)));
    // Each job waits until three run together, or gives up.
    let meeting = Arc::new((Mutex::new((0usize, 0usize)), Condvar::new()));
    let job: AdmissionJob = {
        let meeting = meeting.clone();
        Arc::new(move || {
            let (state, changed) = &*meeting;
            let mut guard = state.lock().unwrap();
            guard.0 += 1;
            guard.1 = guard.1.max(guard.0);
            changed.notify_all();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
            while guard.1 < 3 && std::time::Instant::now() < deadline {
                guard = changed
                    .wait_timeout(guard, std::time::Duration::from_millis(50))
                    .unwrap()
                    .0;
            }
            guard.0 -= 1;
            PreverifyCounts {
                operations: 1,
                verified: 1,
                ..Default::default()
            }
        })
    };
    for n in 0..3u8 {
        assert!(queue.offer([n; 32], 10, 1, job.clone(), false));
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while (0..3u8).any(|n| queue.pending(&[n; 32])) {
        assert!(std::time::Instant::now() < deadline, "the queue stalled");
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let peak = meeting.0.lock().unwrap().1;
    assert_eq!(
        peak, 3,
        "a regular node on 16 CPUs verified {peak} at once with {} slots, while its shards wait \
         on their verdicts to apply frames",
        slots.slots
    );
}

/// Each bound of a regular node's size holds and yields to the next: CPUs,
/// memory, the floor (never under what it had), the cap. Nothing it chooses
/// can leave it without a verifier: the floor keeps one queue thread and the
/// slot frames use.
#[test]
fn a_regular_nodes_slots_follow_cpus_within_memory_and_the_bounds() {
    let unset = ProofWorkerConfig::default();
    let slots = |cpus, memory| verifier_slots(&unset, false, cpus, memory).slots;
    let plenty = Some(1024 * GIB);
    // CPUs over the default four threads per child.
    assert_eq!(slots(Some(4), plenty), 2);
    assert_eq!(slots(Some(8), plenty), 2);
    assert_eq!(slots(Some(12), plenty), 3);
    assert_eq!(slots(Some(16), plenty), 4);
    assert_eq!(slots(Some(32), plenty), 8);
    // Fewer native threads per child: more of them.
    let two_threads = ProofWorkerConfig {
        native_threads: 2,
        ..unset.clone()
    };
    assert_eq!(
        verifier_slots(&two_threads, false, Some(16), plenty).slots,
        8
    );
    // One per 6 GiB available, exactly at its boundary, and never under two.
    assert_eq!(slots(Some(64), Some(18 * GIB)), 3);
    assert_eq!(slots(Some(64), Some(18 * GIB - 1)), 2);
    assert_eq!(slots(Some(64), Some(GIB)), 2);
    // The floor on a small machine; the cap on a large one.
    assert_eq!(slots(Some(1), plenty), 2);
    assert_eq!(slots(Some(4096), plenty), 16);
    // Unknown CPUs leave the default; unknown memory the CPU bound.
    assert_eq!(slots(None, plenty), 2);
    assert_eq!(slots(Some(16), None), 4);
    // An explicit value wins, below or above the rule.
    for configured in [1, 2, 12] {
        let explicit = ProofWorkerConfig {
            max_concurrent: Some(configured),
            ..unset.clone()
        };
        assert_eq!(
            verifier_slots(&explicit, false, Some(16), plenty).slots,
            configured
        );
    }
}

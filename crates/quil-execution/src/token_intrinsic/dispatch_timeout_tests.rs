//! How long a worker verification may run. These tests read and write the
//! process-wide estimates, so each runs in its own process (nextest) and uses
//! a size class no other test in it measures.
use super::*;
use std::time::Duration;

const FLOOR: Duration = Duration::from_secs(900);
const CEILING: Duration = Duration::from_secs(1800);

#[test]
fn the_deadline_is_a_multiple_of_the_measured_class_between_its_bounds() {
    let timeout =
        |secs: u64, timed_out| verify_timeout(secs * 1_000_000, FLOOR, CEILING, timed_out);
    // 100 s measured: six times is under the floor, so the floor.
    assert_eq!(timeout(100, false), FLOOR);
    // Between the bounds: a multiple of the estimate.
    assert_eq!(timeout(200, false), Duration::from_secs(1200));
    // A slow node's class reaches the configured deadline, never past it.
    assert_eq!(timeout(400, false), CEILING);
    // Not measured yet: the whole deadline, whatever the mean of other classes.
    assert_eq!(verify_timeout(0, FLOOR, CEILING, false), CEILING);
    // After a timeout: the whole deadline, so it can finish and teach the class.
    assert_eq!(timeout(100, true), CEILING);
    // An operator's shorter deadline still bounds it.
    let short = Duration::from_secs(300);
    assert_eq!(verify_timeout(100_000_000, FLOOR, short, false), short);
}

/// A proof worker that verifies after `secs`.
fn slow_worker(directory: &std::path::Path, secs: u64, ceiling: Duration) -> WorkerVerifier {
    let script = directory.join("slow.sh");
    std::fs::write(
        &script,
        format!("#!/bin/sh\ncat > /dev/null\nsleep {secs}\nexit 80\n"),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    WorkerVerifier::new(script, 5, ceiling).unwrap()
}

/// The recovery path of the bound: a verification slower than its class's
/// deadline times out once, gets the whole configured deadline, finishes, and
/// teaches the class, so later ones of its size are given more. A deadline
/// that stayed short would refuse this node's verifications for good, and a
/// member that cannot verify cannot apply the frame.
#[test]
fn a_verification_past_its_deadline_gets_the_whole_one_next_and_teaches_the_class() {
    const BYTES: usize = 300_000;
    let measured = Duration::from_millis(10);
    let floor = Duration::from_millis(200);
    record_duration(BYTES, measured);
    let directory = tempfile::tempdir().unwrap();
    let worker = slow_worker(directory.path(), 2, Duration::from_secs(30));
    let policy = TokenPolicy::for_network(1);
    let mut operation = TYPE_LATTICE_SHIELD.to_be_bytes().to_vec();
    operation.resize(BYTES, 1);
    let attempt = |floor| {
        worker_verdict_above(
            floor,
            &worker,
            &policy.network,
            &domains::QUIL_TOKEN,
            &operation,
            policy.limits,
            policy.native_budget,
        )
    };
    let first = std::time::Instant::now();
    assert!(
        matches!(
            attempt(floor),
            Err(ClientError::Process(WorkerError::Timeout))
        ),
        "a stuck child runs out its class's deadline"
    );
    assert!(
        first.elapsed() < Duration::from_secs(2),
        "the child outlived its deadline: {:?}",
        first.elapsed()
    );
    assert_eq!(
        estimated_verify_secs(BYTES),
        measured.as_secs_f64(),
        "a timeout taught the estimate"
    );
    assert!(
        matches!(attempt(floor), Ok(true)),
        "the retry did not get the whole configured deadline: the operation can never verify"
    );
    assert!(
        estimated_verify_secs(BYTES) > 0.4,
        "the accepted verdict did not teach the class: {:.3} s",
        estimated_verify_secs(BYTES)
    );
    // Remembered no longer: the next operation of this size gets the class's
    // deadline, now a multiple of what it learned.
    let key = verdict_key(
        &policy.network,
        &domains::QUIL_TOKEN,
        &operation,
        policy.limits,
        policy.native_budget,
    );
    assert!(!timed_out_before(&key));
}

#[test]
fn the_timed_out_operations_remembered_stay_bounded() {
    for n in 0..(TIMED_OUT_ENTRIES + 8) as u32 {
        let mut key = [0; 32];
        key[..4].copy_from_slice(&n.to_le_bytes());
        note_timed_out(key, true);
    }
    let set = TIMED_OUT.lock().unwrap();
    let held = set.as_ref().unwrap();
    assert_eq!(held.keys.len(), TIMED_OUT_ENTRIES);
    assert_eq!(held.order.len(), TIMED_OUT_ENTRIES);
}

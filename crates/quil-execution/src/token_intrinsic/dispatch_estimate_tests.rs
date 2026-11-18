//! What teaches the per-size-class verification estimate. These tests use
//! only interfaces of the release base, so they show its outcome there.
//! They read and write the process-wide estimates, so each runs in its own
//! process (nextest) and uses a size class no other test in it measures.
use super::*;

/// A proof worker that reads its request and rejects it at once.
fn rejecting_worker(directory: &std::path::Path) -> WorkerVerifier {
    let script = directory.join("reject.sh");
    std::fs::write(&script, "#!/bin/sh\ncat > /dev/null\nexit 81\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    WorkerVerifier::new(script, 5, std::time::Duration::from_secs(30)).unwrap()
}

fn rejected(worker: &WorkerVerifier, bytes: usize, n: u8) {
    let policy = TokenPolicy::for_network(1);
    let mut operation = TYPE_LATTICE_SHIELD.to_be_bytes().to_vec();
    operation.resize(bytes, n);
    let verdict = worker_verdict(
        worker,
        &policy.network,
        &domains::QUIL_TOKEN,
        &operation,
        policy.limits,
        policy.native_budget,
    );
    assert!(matches!(verdict, Ok(false)), "{verdict:?}");
}

/// A size class measured at 300 s stays above the frame budget however many
/// operations of its size the worker rejects quickly.
#[test]
fn rejected_operations_do_not_lower_a_measured_class_below_the_budget() {
    const BYTES: usize = 200_000;
    record_duration(BYTES, std::time::Duration::from_secs(300));
    assert!(!verification_known_to_fit(BYTES, 6.0));
    let directory = tempfile::tempdir().unwrap();
    let worker = rejecting_worker(directory.path());
    for n in 0..14 {
        rejected(&worker, BYTES, n);
    }
    assert!(
        !verification_known_to_fit(BYTES, 6.0),
        "rejected samples lowered the class estimate below budget: {:.3} s after 14 rejections",
        estimated_verify_secs(BYTES)
    );
}

/// A size class not measured yet is still not known to fit after the worker
/// rejected an operation of its size.
#[test]
fn a_rejected_operation_does_not_make_an_unmeasured_class_fit() {
    const BYTES: usize = 600 << 10;
    assert!(!verification_known_to_fit(BYTES, 24.0));
    let directory = tempfile::tempdir().unwrap();
    rejected(&rejecting_worker(directory.path()), BYTES, 1);
    assert!(
        !verification_known_to_fit(BYTES, 24.0),
        "one rejected sample made an unmeasured class known to fit: {:.3} s",
        estimated_verify_secs(BYTES)
    );
}

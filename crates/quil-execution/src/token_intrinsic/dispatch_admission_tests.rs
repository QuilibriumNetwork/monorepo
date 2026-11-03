//! Bounds of the verdict cache and of what reaches the proof worker. These
//! tests use only interfaces of the release base, so they show its outcome
//! there.
use super::*;

/// A cache full of rejected verdicts keeps the accepted ones: a verdict a
/// proposal or frame still needs took minutes to compute.
#[test]
fn rejected_verdicts_never_evict_an_accepted_one() {
    let accepted = [0xa5; 32];
    record_verdict(accepted, true);
    for n in 0..VERDICT_CACHE_ENTRIES as u32 {
        let mut key = [0x5a; 32];
        key[..4].copy_from_slice(&n.to_le_bytes());
        record_verdict(key, false);
    }
    assert_eq!(
        cached_verdict(&accepted),
        Some(true),
        "an accepted verdict was evicted by {VERDICT_CACHE_ENTRIES} rejected ones"
    );
    // A full side keeps its newest entries and drops only its oldest.
    let mut newest = [0x5a; 32];
    newest[..4].copy_from_slice(&(VERDICT_CACHE_ENTRIES as u32 - 1).to_le_bytes());
    let mut extra = [0x5b; 32];
    extra[..4].copy_from_slice(&7u32.to_le_bytes());
    record_verdict(extra, false);
    assert_eq!(
        cached_verdict(&newest),
        Some(false),
        "a full cache forgot its newest verdicts"
    );
    assert_eq!(cached_verdict(&extra), Some(false));
}

/// An operation dispatch refuses before native work (here: it does not
/// decode) is never sent to the proof worker by a pre-verification.
#[test]
fn an_undecodable_operation_never_reaches_the_proof_worker() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("spawned");
    let script = directory.path().join("worker.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ncat > /dev/null\ntouch {}\nexit 81\n",
            marker.display()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let worker = WorkerVerifier::new(script, 5, std::time::Duration::from_secs(30)).unwrap();
    let policy = TokenPolicy::for_network(1);
    let mut junk = TYPE_LATTICE_TRANSACTION.to_be_bytes().to_vec();
    junk.extend_from_slice(&[0x33; 4096]);
    let outcome = policy.preverify(
        &worker,
        &domains::QUIL_TOKEN,
        &junk,
        TYPE_LATTICE_TRANSACTION,
    );
    assert!(
        !marker.exists(),
        "an undecodable operation was sent to the proof worker (pre-verification: {outcome:?})"
    );
    assert_eq!(outcome, Preverified::NotApplicable);
}

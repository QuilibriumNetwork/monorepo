#![no_main]
//! Global-intrinsic TimeoutCertificate decode — its `latest_ranks` count was
//! hint-capped in the F9 sweep. Reachable via :8340 consensus + message paths.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = quil_execution::global_intrinsic::consensus_types::TimeoutCertificate::from_canonical_bytes(data);
});

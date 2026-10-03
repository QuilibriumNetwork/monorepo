#![no_main]
//! Global-intrinsic ProverJoin decode — its `merge_targets` count was
//! hint-capped (as is the filter count).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = quil_execution::global_intrinsic::prover_join::ProverJoin::from_canonical_bytes(data);
});

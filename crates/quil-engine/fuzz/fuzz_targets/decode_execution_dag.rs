#![no_main]
//! Compute-intrinsic ExecutionDag decode — one of the inner-op decoders whose
//! `operations` count is hint-capped against allocation bombs.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = quil_execution::compute_intrinsic::ops::ExecutionDag::from_canonical_bytes(data);
});

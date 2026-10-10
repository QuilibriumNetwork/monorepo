#![no_main]
//! Bundle-level decode (also reached per-bundle inside decode_global_frame).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = quil_engine::consensus_wire::decode_message_bundle(data);
});

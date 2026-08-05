#![no_main]
//! The gossip GLOBAL_FRAME entry point: decodes an attacker-controlled frame
//! (header incl. commit_count/aux_count/req_count + every bundle) BEFORE any
//! cert/VDF authentication. This is where F9 lived.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = quil_engine::consensus_wire::decode_global_frame(data);
});

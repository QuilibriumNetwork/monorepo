#![no_main]
//! CanonicalMessageRequest envelope decode (per-request, message-submission).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = quil_execution::message_envelope::CanonicalMessageRequest::from_canonical_bytes(data);
});

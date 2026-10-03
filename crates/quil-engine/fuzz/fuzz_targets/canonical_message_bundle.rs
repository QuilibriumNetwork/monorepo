#![no_main]
//! CanonicalMessageBundle envelope decode (message-submission path). Has the
//! `num_requests` allocation guard; fuzz it to keep that guard honest.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = quil_execution::message_envelope::CanonicalMessageBundle::from_canonical_bytes(data);
});

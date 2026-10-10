//! Small helpers: run-ID and bearer-token generation.

use rand::rngs::OsRng;
use rand::RngCore;
use uuid::Uuid;

/// Generates a random UUID-v4 string (e.g. `f47ac10b-58cc-4372-a567-0e02b2c3d479`).
/// Used to uniquely identify a test run and its compose project.
pub fn new_run_id() -> String {
    Uuid::new_v4().to_string()
}

/// Generates a secure random bearer token (32 random bytes, hex-encoded).
pub fn generate_bearer_token() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

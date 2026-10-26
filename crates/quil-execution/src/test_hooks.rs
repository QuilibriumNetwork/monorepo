//! Fault-injection hooks for the devnet smoke test (`scripts/devnet-smoke.sh`).
//!
//! Every hook is a function that does nothing unless the `test-hooks`
//! feature is on, so a default or release build carries no trace of it.
//! With the feature, a hook reads its own `QUIL_TEST_*` environment
//! variable. To add one, put a function here, give it an env variable, call
//! it from the code path under test, and drive it from the smoke script.

/// Delay the first full read of the prover registry from the store by
/// `QUIL_TEST_REGISTRY_LOAD_DELAY_MS` milliseconds, once per process. It
/// stands in for a slow store: on mainnet that read takes 18-29 s, long
/// enough for startup code to look at the registry before it is loaded.
#[cfg(feature = "test-hooks")]
pub fn registry_load_delay() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static DONE: AtomicBool = AtomicBool::new(false);
    let Some(ms) = std::env::var("QUIL_TEST_REGISTRY_LOAD_DELAY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
    else {
        return;
    };
    if DONE.swap(true, Ordering::SeqCst) {
        return;
    }
    tracing::warn!(delay_ms = ms, "TEST HOOK: delaying the first prover registry load");
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

#[cfg(not(feature = "test-hooks"))]
#[inline(always)]
pub fn registry_load_delay() {}

// `insecure-rng` replaces the CSPRNG with a constant-seeded StdRng so
// tests are reproducible. If it ever reaches an optimized/release build
// EVERY key, nonce, and OT seed becomes predictable (seed 42) — a total
// break of the threshold scheme. Fail the build loudly rather than ship
// a deterministic-key binary. Debug/test builds (debug_assertions on)
// may still opt in.
#[cfg(all(feature = "insecure-rng", not(debug_assertions)))]
compile_error!(
    "the `insecure-rng` feature seeds the RNG with a constant and makes all \
     key material predictable; it must never be enabled in a release build. \
     Remove `--features insecure-rng` (or build with debug assertions for tests)."
);

#[cfg(feature = "insecure-rng")]
use rand::rngs::StdRng;
#[cfg(not(feature = "insecure-rng"))]
use rand::rngs::ThreadRng;
#[cfg(feature = "insecure-rng")]
use rand::SeedableRng;

pub const DEFAULT_SEED: u64 = 42;

#[cfg(not(feature = "insecure-rng"))]
pub fn get_rng() -> ThreadRng {
    rand::thread_rng()
}

#[cfg(feature = "insecure-rng")]
pub fn get_rng() -> StdRng {
    rand::rngs::StdRng::seed_from_u64(DEFAULT_SEED)
}

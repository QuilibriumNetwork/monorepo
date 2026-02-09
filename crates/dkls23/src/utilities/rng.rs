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

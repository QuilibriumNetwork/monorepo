//! `-v/--verbose`: whether commands print how they derived a result
//! (frames, sizes, margins, page counts, timings, base units) beside it.
//! `main` sets it once, before any command runs.

use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Record the `-v/--verbose` flag.
pub fn set(verbose: bool) {
    VERBOSE.store(verbose, Ordering::Relaxed);
}

/// Whether `-v/--verbose` was given.
pub fn on() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

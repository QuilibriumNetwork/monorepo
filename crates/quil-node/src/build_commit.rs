//! The source commit this binary was built from, as the build script read
//! it (`build_support/commit.rs`).

/// The full object ID in hex; empty when the build could not read one.
pub(crate) const ID: &str = env!("QUIL_SOURCE_COMMIT");

/// Tracked files differed from [`ID`] when this binary was built.
pub(crate) const DIRTY: bool = !env!("QUIL_SOURCE_DIRTY").is_empty();

/// [`ID`]'s bytes, as the health report carries them.
pub(crate) fn id_bytes() -> Vec<u8> {
    hex::decode(ID).expect("build script emits a hex commit ID")
}

/// `<ID>[+dirty]` for logs, or `unknown`.
pub(crate) fn label() -> &'static str {
    if ID.is_empty() {
        "unknown"
    } else {
        concat!(env!("QUIL_SOURCE_COMMIT"), env!("QUIL_SOURCE_DIRTY"))
    }
}

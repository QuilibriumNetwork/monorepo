pub mod proto;
pub mod protojson;
pub mod crypto;
pub mod store;
pub mod consensus;
pub mod execution;
pub mod p2p;
pub mod lifecycle;
pub mod error;

#[inline]
pub fn append_debug_log(_tag: &str, _msg: &str) {}

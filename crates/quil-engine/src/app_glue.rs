//! App shard consensus glue.
//!
//! The legacy HotStuff consumer/finalizer/follower callbacks and the
//! persistence codec have been removed in favour of the commonware-simplex
//! ("CW") path (see `cw_app_seams.rs`). What remains is the canonical
//! aggregate-signature helper shared by the wire/frame assembly code.

use quil_types::error::Result;

/// Encode a QC's aggregate signature into the canonical
/// `BLS48581AggregateSignature` byte format the wire FrameHeader's
/// `public_key_signature_bls48581` field expects. The pubkey is
/// embedded as `Bls48581G2PublicKey` (4-byte type prefix + 585-byte
/// key). The bitmask identifies committee positions that
/// participated.
pub fn canonical_aggregate_signature(
    signature: &[u8],
    public_key: &[u8],
    bitmask: &[u8],
) -> Result<Vec<u8>> {
    use quil_execution::hypergraph_intrinsic::canonical::{
        AggregateSignature, Bls48581G2PublicKey,
    };
    let pubkey = if public_key.is_empty() {
        None
    } else {
        Some(Bls48581G2PublicKey {
            key_value: public_key.to_vec(),
        })
    };
    let agg = AggregateSignature {
        signature: signature.to_vec(),
        public_key: pubkey,
        bitmask: bitmask.to_vec(),
    };
    agg.to_canonical_bytes()
}

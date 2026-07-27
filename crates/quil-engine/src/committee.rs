//! Identity encoding helpers bridging prover addresses to the consensus
//! layer's [`Identity`](quil_consensus::models::Identity) type.
//!
//! Identity convention: a prover's [`Identity`] is its raw 32-byte
//! address. These helpers make the (trivial) conversion explicit and
//! reversible so call sites read intentionally.

use quil_consensus::models::Identity;
use quil_types::error::Result;

/// Convert a raw prover address into an `Identity` (raw bytes — same value).
pub fn address_to_identity(address: &[u8]) -> Identity {
    address.to_vec()
}

/// Identity bytes are the raw address.
pub fn identity_to_address(id: &Identity) -> Result<Vec<u8>> {
    Ok(id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_to_identity_is_raw_bytes() {
        let id = address_to_identity(&[0xAB, 0xCD, 0xEF]);
        assert_eq!(id, vec![0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn identity_to_address_round_trip() {
        let addr = vec![0xAA; 32];
        let id = address_to_identity(&addr);
        let decoded = identity_to_address(&id).unwrap();
        assert_eq!(decoded, addr);
    }
}

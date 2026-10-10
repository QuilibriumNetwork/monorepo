//! Protocol signature verification shared by the paths that admit a key named
//! in state or in a settlement: custom-token mint authorities, mint
//! entitlements and the claimant of a pre-funded settlement.
//!
//! Post-quantum only. Application-level authority is
//! Falcon-512 (FN-DSA-512) and nothing else: the classical curves (Ed448,
//! Ed25519, secp256k1) and BLS48-581 are refused, as they already are for
//! hypergraph write keys, compute write keys, token owner keys, mint claims
//! and escrow claims. A configuration or statement naming any other key type
//! is rejected rather than verified.
use quil_types::{crypto::KeyType, error::{QuilError, Result}};

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("signature: {message}"))
}

/// Whether `key_type` is an admissible application authority key. Only
/// Falcon-512 is; callers reject a configuration or statement naming another
/// type before doing any work with it.
pub fn is_post_quantum_authority(key_type: u32) -> bool {
    key_type == KeyType::Falcon512 as u32
}

/// Verify an authority signature over `message`, domain-separated by `domain`
/// as the FN-DSA context (the key manager's convention). Only Falcon-512 is
/// accepted; every other key type is an error, not a failed signature.
pub fn verify_authority_signature(
    key_type: u32,
    public_key: &[u8],
    message: &[u8],
    domain: &[u8],
    signature: &[u8],
) -> Result<()> {
    if !is_post_quantum_authority(key_type) {
        return Err(invalid("authority keys must be post-quantum (Falcon-512)"));
    }
    if public_key.len() != quil_crypto::FALCON_PUBLIC_KEY_LEN
        || !quil_crypto::falcon_verify(public_key, signature, message, domain)
    {
        return Err(invalid("invalid authority signature"));
    }
    Ok(())
}


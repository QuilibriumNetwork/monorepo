//! Hypergraph write-authority verification.
//!
//! Each hypergraph deployment binds an Ed448 `WritePublicKey` that
//! authorizes VertexAdd/VertexRemove/HyperedgeAdd/HyperedgeRemove ops
//! into that hypergraph's domain. Without verifying the signature
//! against this key, anyone holding a valid Ed448 key can impersonate
//! the hypergraph's owner.
//!
//! Production callers wire in a [`HypergraphConfigResolver`] that
//! resolves `domain → WritePublicKey` from the deployment config
//! vertex. When no resolver is configured (test / unfinished port),
//! `verify_op_signature` returns `Ok(false)` — callers can treat that
//! as a soft-fail and log, or as a hard reject in production builds.

use std::sync::Arc;

use quil_types::error::{QuilError, Result};

use super::{
    hyperedge_ops::{
        hyperedge_add_domain_separator, hyperedge_add_signing_message,
        hyperedge_remove_domain_separator, hyperedge_remove_signing_message,
        HYPEREDGE_ID_LEN, HYPEREDGE_MIN_VALUE_LEN,
    },
    split_vertex_add_proof_chunks,
    types::{HyperedgeAdd, HyperedgeRemove, VertexAdd, VertexRemove},
    vertex_ops::{
        vertex_add_domain_separator, vertex_add_signing_message,
        vertex_remove_domain_separator, vertex_remove_signing_message,
    },
};

/// Resolves the Ed448 `WritePublicKey` for a hypergraph domain.
///
/// Implementations look up the deployment configuration vertex keyed
/// by domain (the 32-byte hypergraph address) and return its write
/// key. `None` means the deployment isn't known to this node — callers
/// must reject the op (an op against an undeployed hypergraph is
/// always invalid).
pub trait HypergraphConfigResolver: Send + Sync {
    fn write_public_key(&self, domain: &[u8]) -> Option<Vec<u8>>;
}

/// Outcome of [`verify_op_signature`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthCheck {
    /// Signature verified against the resolved write key.
    Verified,
    /// No resolver configured — caller decides whether to allow.
    NoResolver,
    /// Resolver returned no key for this domain — the deployment is
    /// unknown to this node, op must be rejected.
    UnknownDomain,
    /// Signature failed to verify against the resolved write key.
    Invalid,
}

/// Verify the Ed448 signature on a hypergraph op against the
/// hypergraph's `WritePublicKey`. Implements the same signing scheme
/// Go's `FileKeyManager::ValidateSignature` uses for Ed448:
///
/// ```text
/// signed_bytes = (domain || op_tag) || op_message
/// ```
///
/// (`op_tag` is `"VERTEX_ADD"` / `"VERTEX_REMOVE"` / `"HYPEREDGE_ADD"`
/// / `"HYPEREDGE_REMOVE"`. Ed448 verify uses the empty RFC 8032
/// context — the tag is folded into the message instead.)
///
/// `commit` is only needed for HyperedgeAdd; pass `None` for other ops.
pub fn verify_op_signature(
    resolver: Option<&Arc<dyn HypergraphConfigResolver>>,
    op: &OpForAuth<'_>,
) -> Result<AuthCheck> {
    let Some(resolver) = resolver else {
        return Ok(AuthCheck::NoResolver);
    };
    let domain = op.domain();
    let Some(write_key) = resolver.write_public_key(domain) else {
        return Ok(AuthCheck::UnknownDomain);
    };

    let (separator, message, signature) = match op {
        OpForAuth::VertexAdd(v) => {
            let chunks = split_vertex_add_proof_chunks(&v.data)?;
            (
                vertex_add_domain_separator(&v.domain)?,
                vertex_add_signing_message(&v.domain, &v.data_address, &chunks)?,
                &v.signature[..],
            )
        }
        OpForAuth::VertexRemove(v) => (
            vertex_remove_domain_separator(&v.domain)?,
            vertex_remove_signing_message(&v.domain, &v.data_address)?,
            &v.signature[..],
        ),
        OpForAuth::HyperedgeAdd { op: h, commit } => {
            let id = {
                if h.value.len() < HYPEREDGE_MIN_VALUE_LEN {
                    return Err(QuilError::InvalidArgument(
                        "hyperedge add auth: value too short".into(),
                    ));
                }
                let mut id = [0u8; HYPEREDGE_ID_LEN];
                id.copy_from_slice(&h.value[1..1 + HYPEREDGE_ID_LEN]);
                id
            };
            (
                hyperedge_add_domain_separator(&h.domain)?,
                hyperedge_add_signing_message(&id, commit)?,
                &h.signature[..],
            )
        }
        OpForAuth::HyperedgeRemove(h) => {
            if h.value.len() < HYPEREDGE_MIN_VALUE_LEN {
                return Err(QuilError::InvalidArgument(
                    "hyperedge remove auth: value too short".into(),
                ));
            }
            let mut id = [0u8; HYPEREDGE_ID_LEN];
            id.copy_from_slice(&h.value[1..1 + HYPEREDGE_ID_LEN]);
            (
                hyperedge_remove_domain_separator(&h.domain)?,
                hyperedge_remove_signing_message(&id),
                &h.signature[..],
            )
        }
    };

    let mut signed = Vec::with_capacity(separator.len() + message.len());
    signed.extend_from_slice(&separator);
    signed.extend_from_slice(&message);

    if quil_crypto::ed448_verify(&write_key, &signed, signature) {
        Ok(AuthCheck::Verified)
    } else {
        Ok(AuthCheck::Invalid)
    }
}

/// Borrowed view of an op for `verify_op_signature`. HyperedgeAdd
/// requires the caller to pre-compute the extrinsic-tree commitment.
pub enum OpForAuth<'a> {
    VertexAdd(&'a VertexAdd),
    VertexRemove(&'a VertexRemove),
    HyperedgeAdd { op: &'a HyperedgeAdd, commit: &'a [u8] },
    HyperedgeRemove(&'a HyperedgeRemove),
}

impl<'a> OpForAuth<'a> {
    fn domain(&self) -> &[u8] {
        match self {
            OpForAuth::VertexAdd(v) => &v.domain,
            OpForAuth::VertexRemove(v) => &v.domain,
            OpForAuth::HyperedgeAdd { op, .. } => &op.domain,
            OpForAuth::HyperedgeRemove(h) => &h.domain,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed448_rust::PrivateKey;

    struct StaticResolver(Vec<u8>);
    impl HypergraphConfigResolver for StaticResolver {
        fn write_public_key(&self, _domain: &[u8]) -> Option<Vec<u8>> {
            Some(self.0.clone())
        }
    }

    fn sign_with_domain(seed: &[u8; 57], domain: &[u8], tag: &[u8], message: &[u8]) -> Vec<u8> {
        let sk = PrivateKey::from(seed);
        let mut signed = Vec::with_capacity(domain.len() + tag.len() + message.len());
        signed.extend_from_slice(domain);
        signed.extend_from_slice(tag);
        signed.extend_from_slice(message);
        sk.sign(&signed, None).unwrap().to_vec()
    }

    fn pubkey_from_seed(seed: &[u8; 57]) -> Vec<u8> {
        let sk = PrivateKey::from(seed);
        let pk = ed448_rust::PublicKey::from(&sk);
        pk.as_byte().to_vec()
    }

    #[test]
    fn vertex_remove_verifies_against_resolved_key() {
        let seed = [7u8; 57];
        let pubkey = pubkey_from_seed(&seed);
        let domain = vec![0xABu8; 32];
        let data_address = vec![0x42u8; 32];

        let msg = vertex_remove_signing_message(&domain, &data_address).unwrap();
        let sig = sign_with_domain(&seed, &domain, b"VERTEX_REMOVE", &msg);

        let op = VertexRemove {
            domain: domain.clone(),
            data_address: data_address.clone(),
            signature: sig,
        };
        let resolver: Arc<dyn HypergraphConfigResolver> = Arc::new(StaticResolver(pubkey));
        let check = verify_op_signature(Some(&resolver), &OpForAuth::VertexRemove(&op)).unwrap();
        assert_eq!(check, AuthCheck::Verified);
    }

    #[test]
    fn vertex_remove_rejects_wrong_key() {
        let seed = [7u8; 57];
        let other = pubkey_from_seed(&[9u8; 57]);
        let domain = vec![0xABu8; 32];
        let data_address = vec![0x42u8; 32];

        let msg = vertex_remove_signing_message(&domain, &data_address).unwrap();
        let sig = sign_with_domain(&seed, &domain, b"VERTEX_REMOVE", &msg);

        let op = VertexRemove {
            domain,
            data_address,
            signature: sig,
        };
        let resolver: Arc<dyn HypergraphConfigResolver> = Arc::new(StaticResolver(other));
        let check = verify_op_signature(Some(&resolver), &OpForAuth::VertexRemove(&op)).unwrap();
        assert_eq!(check, AuthCheck::Invalid);
    }

    #[test]
    fn missing_resolver_reports_no_resolver() {
        let op = VertexRemove {
            domain: vec![0u8; 32],
            data_address: vec![0u8; 32],
            signature: vec![0u8; 114],
        };
        let check = verify_op_signature(None, &OpForAuth::VertexRemove(&op)).unwrap();
        assert_eq!(check, AuthCheck::NoResolver);
    }

    #[test]
    fn unknown_domain_when_resolver_returns_none() {
        struct NoneResolver;
        impl HypergraphConfigResolver for NoneResolver {
            fn write_public_key(&self, _: &[u8]) -> Option<Vec<u8>> {
                None
            }
        }
        let op = VertexRemove {
            domain: vec![0u8; 32],
            data_address: vec![0u8; 32],
            signature: vec![0u8; 114],
        };
        let resolver: Arc<dyn HypergraphConfigResolver> = Arc::new(NoneResolver);
        let check = verify_op_signature(Some(&resolver), &OpForAuth::VertexRemove(&op)).unwrap();
        assert_eq!(check, AuthCheck::UnknownDomain);
    }
}

//! KeyManager implementation that dispatches signature verification
//! to the appropriate algorithm based on KeyType.

use std::sync::Arc;

use quil_types::crypto::{BlsConstructor, KeyManager, KeyType};
use quil_types::error::{QuilError, Result};

/// Default key manager that dispatches to BLS48-581 and Ed448 verifiers.
pub struct DefaultKeyManager {
    bls_constructor: Arc<dyn BlsConstructor>,
}

impl DefaultKeyManager {
    pub fn new(bls_constructor: Arc<dyn BlsConstructor>) -> Self {
        Self { bls_constructor }
    }
}

impl KeyManager for DefaultKeyManager {
    fn validate_signature(
        &self,
        key_type: KeyType,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        domain: &[u8],
    ) -> Result<bool> {
        match key_type {
            KeyType::Ed448 => {
                // Ed448 public key is 57 bytes, signature is 114 bytes.
                if public_key.len() != 57 {
                    return Err(QuilError::InvalidArgument(format!(
                        "Ed448: invalid public key length {}",
                        public_key.len()
                    )));
                }
                if signature.len() != 114 {
                    return Err(QuilError::InvalidArgument(format!(
                        "Ed448: invalid signature length {}",
                        signature.len()
                    )));
                }

                // Go's `Ed448Key.SignWithDomain` (node/keys/ed448_key.go)
                // signs `concat(domain, message)` under pure Ed448 with
                // an empty RFC 8032 ctx. `ValidateSignature` in
                // node/keys/inmem.go verifies the same way. Mirror that
                // exactly here — passing `domain` as the RFC ctx
                // produces a different signature and would never verify
                // a Go-signed payload.
                let pk = ed448_rust::PublicKey::try_from(public_key)
                    .map_err(|e| QuilError::Internal(format!("Ed448 key decode: {:?}", e)))?;

                let mut digest = Vec::with_capacity(domain.len() + message.len());
                digest.extend_from_slice(domain);
                digest.extend_from_slice(message);
                match pk.verify(&digest, signature, None) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }

            KeyType::Bls48581G1 | KeyType::Bls48581G2 => {
                // BLS48-581 verification: public key is G2 (585 bytes),
                // signature is G1 (74 bytes). Domain is the BLS context.
                Ok(self.bls_constructor.verify_signature_raw(
                    public_key,
                    signature,
                    message,
                    domain,
                ))
            }

            other => Err(QuilError::InvalidArgument(format!(
                "KeyManager: unsupported key type {:?} for signature verification",
                other
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::{BlsAggregateOutput, Signer};

    // Stub BLS constructor for testing
    struct StubBlsConstructor {
        accept: bool,
    }
    impl BlsConstructor for StubBlsConstructor {
        fn new_key(&self) -> Result<(Box<dyn Signer>, Vec<u8>)> { Err(QuilError::Internal("key generation not supported in stub".into())) }
        fn from_bytes(&self, _: &[u8], _: &[u8]) -> Result<Box<dyn Signer>> { Err(QuilError::Internal("key deserialization not supported in stub".into())) }
        fn verify_signature_raw(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> bool { self.accept }
        fn verify_multi_message_signature_raw(&self, _: &[u8], _: &[u8], _: &[&[u8]], _: &[u8]) -> bool { self.accept }
        fn aggregate(&self, _: &[&[u8]], _: &[&[u8]]) -> Result<BlsAggregateOutput> { Err(QuilError::Internal("BLS aggregation not supported in stub".into())) }
    }

    fn km(accept_bls: bool) -> DefaultKeyManager {
        DefaultKeyManager::new(Arc::new(StubBlsConstructor { accept: accept_bls }))
    }

    #[test]
    fn bls_g2_dispatches_to_constructor() {
        let m = km(true);
        assert!(m.validate_signature(
            KeyType::Bls48581G2,
            &[0u8; 585],
            b"msg",
            &[0u8; 74],
            b"domain",
        ).unwrap());
    }

    #[test]
    fn bls_g2_returns_false_when_constructor_rejects() {
        let m = km(false);
        assert!(!m.validate_signature(
            KeyType::Bls48581G2,
            &[0u8; 585],
            b"msg",
            &[0u8; 74],
            b"domain",
        ).unwrap());
    }

    #[test]
    fn bls_g1_also_dispatches_to_constructor() {
        let m = km(true);
        assert!(m.validate_signature(
            KeyType::Bls48581G1,
            &[0u8; 585],
            b"msg",
            &[0u8; 74],
            b"",
        ).unwrap());
    }

    #[test]
    fn ed448_rejects_wrong_key_length() {
        let m = km(false);
        let err = m.validate_signature(
            KeyType::Ed448,
            &[0u8; 56], // should be 57
            b"msg",
            &[0u8; 114],
            b"",
        ).unwrap_err();
        assert!(matches!(err, QuilError::InvalidArgument(_)));
    }

    #[test]
    fn ed448_rejects_wrong_sig_length() {
        let m = km(false);
        let err = m.validate_signature(
            KeyType::Ed448,
            &[0u8; 57],
            b"msg",
            &[0u8; 100], // should be 114
            b"",
        ).unwrap_err();
        assert!(matches!(err, QuilError::InvalidArgument(_)));
    }

    #[test]
    fn ed448_returns_false_for_invalid_signature() {
        let m = km(false);
        // Random bytes won't form a valid Ed448 key — should return
        // an error or false.
        let result = m.validate_signature(
            KeyType::Ed448,
            &[0x01u8; 57],
            b"msg",
            &[0x02u8; 114],
            b"",
        );
        // Either Ok(false) or Err — both acceptable for garbage input.
        match result {
            Ok(false) => {}
            Err(_) => {}
            Ok(true) => panic!("should not validate garbage"),
        }
    }

    #[test]
    fn ed448_sign_with_domain_round_trips_through_validate_signature() {
        // The whole point of this round-trip: Ed448Signer::sign_with_domain
        // must match exactly what DefaultKeyManager::validate_signature
        // verifies. Both follow Go's `Ed448Key.SignWithDomain` /
        // inmem.go ValidateSignature scheme — pure Ed448 over
        // concat(domain, message) with empty RFC ctx.
        let m = km(false);
        let seed = [0x42u8; 57];
        let pk = crate::Ed448Signer::derive_public(&seed).unwrap();
        let signer = crate::Ed448Signer::from_bytes(&seed, &pk).unwrap();

        for domain in [&b""[..], &b"NODE_AUTHENTICATION"[..], &[0xFFu8; 32][..]] {
            let msg = b"hello-from-the-rust-port";
            let sig = signer.sign_with_domain(msg, domain).unwrap();
            let ok = m
                .validate_signature(KeyType::Ed448, &pk, msg, &sig, domain)
                .unwrap();
            assert!(
                ok,
                "validate_signature must accept what sign_with_domain produced (domain.len()={})",
                domain.len()
            );

            // Same signature must NOT verify under a different domain.
            let other_domain = b"DIFFERENT_DOMAIN";
            if domain != other_domain {
                let bad = m
                    .validate_signature(KeyType::Ed448, &pk, msg, &sig, other_domain)
                    .unwrap();
                assert!(!bad, "different-domain verify must fail");
            }
        }
    }

    #[test]
    fn unsupported_key_type_returns_error() {
        let m = km(false);
        assert!(m.validate_signature(
            KeyType::X448,
            &[0u8; 57],
            b"msg",
            &[0u8; 114],
            b"",
        ).is_err());
    }
}

//! KeyManager implementation that dispatches signature verification
//! to the appropriate algorithm based on KeyType.

use std::sync::Arc;

use quil_types::crypto::{KeyManager, KeyType};
use quil_types::error::{QuilError, Result};

/// Default key manager that dispatches signature verification to Ed448 and the
/// post-quantum Falcon (FN-DSA-512) verifiers. BLS48-581 signatures are retired.
#[derive(Default)]
pub struct DefaultKeyManager;

impl DefaultKeyManager {
    pub fn new() -> Self {
        Self
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

            KeyType::Falcon512 => {
                // Post-quantum consensus signatures: public key 897 B,
                // signature 666 B, `domain` → FN-DSA domain-separation context.
                // Used by the ProverJoin PoP + join signature, and by an
                // Ed448→Falcon seniority-merge target (which itself uses the
                // Ed448 arm above — this arm covers a Falcon-keyed merge).
                Ok(crate::falcon_verify(public_key, signature, message, domain))
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
    use quil_types::crypto::Signer;

    fn km(_accept_bls: bool) -> DefaultKeyManager {
        DefaultKeyManager::new()
    }

    #[test]
    fn falcon512_dispatches_to_falcon_verify() {
        // The BLS stub rejects, proving the Falcon path is independent of it.
        let m = km(false);
        let signer = crate::FalconSigner::generate();
        let sig = signer.sign_with_domain(b"consensus", b"global").unwrap();
        assert!(m
            .validate_signature(KeyType::Falcon512, signer.public_key(), b"consensus", &sig, b"global")
            .unwrap());
        // Wrong domain → false (domain separation), no error.
        assert!(!m
            .validate_signature(KeyType::Falcon512, signer.public_key(), b"consensus", &sig, b"other")
            .unwrap());
        // Malformed pubkey → false, no panic.
        assert!(!m
            .validate_signature(KeyType::Falcon512, &[0u8; 10], b"consensus", &sig, b"global")
            .unwrap());
    }

    #[test]
    fn bls_key_types_are_now_rejected() {
        // BLS48-581 signatures are retired; the key manager rejects both G1/G2
        // key types (they fall through to the unsupported-key-type error).
        let m = km(false);
        for kt in [KeyType::Bls48581G1, KeyType::Bls48581G2] {
            assert!(
                m.validate_signature(kt, &[0u8; 585], b"msg", &[0u8; 74], b"domain").is_err(),
                "BLS key type {kt:?} must be rejected (retired)"
            );
        }
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

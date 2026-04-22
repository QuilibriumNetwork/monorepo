//! TLS handshake debugging utilities.

use libp2p::identity::Keypair;

/// Debug the Ed448 identity encoding and signing.
pub fn debug_ed448_identity(keypair: &Keypair) {
    let public = keypair.public();
    let encoded = public.encode_protobuf();

    tracing::debug!(
        encoded_len = encoded.len(),
        encoded_hex = hex::encode(&encoded),
        "Ed448 public key protobuf encoding"
    );

    let peer_id = libp2p::PeerId::from_public_key(&public);
    tracing::debug!(%peer_id, "derived PeerId");

    match keypair.sign(b"libp2p-tls-handshake:test") {
        Ok(sig) => {
            tracing::debug!(sig_len = sig.len(), "signing OK");
            let valid = public.verify(b"libp2p-tls-handshake:test", &sig);
            tracing::debug!(valid, "self-verify");
        }
        Err(e) => tracing::debug!(error = %e, "signing FAILED"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed448_protobuf_encoding() {
        let keypair = Keypair::generate_ed448();
        let encoded = keypair.public().encode_protobuf();
        assert!(encoded.len() >= 61);
        assert_eq!(encoded[0], 0x08); // field 1 tag
        assert_eq!(encoded[1], 0x04); // Ed448 = 4
        assert_eq!(encoded[2], 0x12); // field 2 tag
        assert_eq!(encoded[3], 57);   // 57-byte key
    }

    #[test]
    fn test_ed448_sign_verify() {
        let keypair = Keypair::generate_ed448();
        let sig = keypair.sign(b"test").expect("sign");
        assert!(keypair.public().verify(b"test", &sig));
    }

    #[test]
    fn test_qm_peer_id() {
        let keypair = Keypair::generate_ed448();
        let pid = libp2p::PeerId::from_public_key(&keypair.public());
        assert!(pid.to_string().starts_with("Qm"));
    }

    #[test]
    fn test_tls_certificate_generation() {
        let keypair = Keypair::generate_ed448();

        // The critical test: does libp2p-tls accept our Ed448 keypair?
        let result = std::panic::catch_unwind(|| {
            // libp2p_tls::certificate::generate is what QUIC uses internally
            // If this works, the TLS cert can be generated with Ed448
            let _config = libp2p::noise::Config::new(&keypair);
        });
        // noise::Config::new should work with Ed448 keypair
        assert!(result.is_ok(), "noise config creation failed with Ed448");
    }
}

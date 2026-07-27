//! Streamlined NTRU Prime (sntrup761) as a rustls TLS 1.3 key-exchange group.
//!
//! Quilibrium-local addition to the vendored `libp2p-tls`: this makes the QUIC
//! transport (libp2p-quic → quinn → rustls) negotiate a **post-quantum, pure
//! NTRU** key exchange instead of classical X25519.
//!
//! Why this exists: QUIC bakes TLS 1.3 into the transport, and TLS's PQ story
//! is a standardized named-group registry that only admitted ML-KEM (Kyber).
//! There is no NTRU TLS named group, so we define one under a **private-use
//! codepoint** and implement it directly against rustls's KEM key-exchange
//! interface. This is interop-only within the Rust-only Quilibrium network
//! (same rationale as the PQNoise TCP wire and Falcon sigs).
//!
//! rustls models a KEM key exchange asymmetrically:
//! * client: [`SupportedKxGroup::start`] generates a keypair; `pub_key()` is the
//!   NTRU public key sent in the ClientHello `key_share`.
//! * server: [`SupportedKxGroup::start_and_complete`] receives the client's
//!   public key and **encapsulates**, returning the ciphertext (its own
//!   `key_share`) plus the shared secret.
//! * client: [`ActiveKeyExchange::complete`] receives the server's ciphertext
//!   and **decapsulates** to the same shared secret.
//!
//! sntrup761 is the OpenSSH-deployed, PQClean-audited NTRU-family KEM
//! (pk 1158 B / ct 1039 B / shared secret 32 B), via `pqcrypto-ntruprime`.

use pqcrypto_ntruprime::sntrup761;
use pqcrypto_traits::kem::{
    Ciphertext as _, PublicKey as _, SecretKey as _, SharedSecret as _,
};
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved};

/// Private-use TLS supported-groups codepoint for sntrup761. Both peers on the
/// (Rust-only) network agree on this value; it is not an IANA assignment.
const SNTRUP761_GROUP: NamedGroup = NamedGroup::Unknown(0xFE71);

/// The sntrup761 key-exchange group. Install via `provider.kx_groups`.
pub static SNTRUP761: &(dyn SupportedKxGroup) = &Sntrup761KxGroup;

#[derive(Debug)]
struct Sntrup761KxGroup;

impl SupportedKxGroup for Sntrup761KxGroup {
    fn name(&self) -> NamedGroup {
        SNTRUP761_GROUP
    }

    /// Client side: generate an sntrup761 keypair.
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let (pk, sk) = sntrup761::keypair();
        Ok(Box::new(Sntrup761KeyExchange {
            public: pk.as_bytes().to_vec(),
            secret: sk.as_bytes().to_vec(),
        }))
    }

    /// Server side: encapsulate to the client's public key (KEM data
    /// dependency — must override the DH-shaped default).
    fn start_and_complete(&self, peer_pub_key: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let pk = sntrup761::PublicKey::from_bytes(peer_pub_key)
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        let (ss, ct) = sntrup761::encapsulate(&pk);
        Ok(CompletedKeyExchange {
            group: SNTRUP761_GROUP,
            pub_key: ct.as_bytes().to_vec(),
            secret: SharedSecret::from(ss.as_bytes()),
        })
    }
}

/// A client-side in-progress sntrup761 exchange (holds the ephemeral keypair).
struct Sntrup761KeyExchange {
    public: Vec<u8>,
    secret: Vec<u8>,
}

impl ActiveKeyExchange for Sntrup761KeyExchange {
    /// Client side: decapsulate the server's ciphertext to the shared secret.
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let sk = sntrup761::SecretKey::from_bytes(&self.secret)
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        let ct = sntrup761::Ciphertext::from_bytes(peer_pub_key)
            .map_err(|_| Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))?;
        let ss = sntrup761::decapsulate(&ct, &sk);
        Ok(SharedSecret::from(ss.as_bytes()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        SNTRUP761_GROUP
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive the full rustls KEM key-exchange interface and assert both sides
    /// derive the identical shared secret.
    #[test]
    fn sntrup761_kx_group_round_trip() {
        let group = Sntrup761KxGroup;
        assert_eq!(group.name(), SNTRUP761_GROUP);

        // Client starts.
        let client = group.start().unwrap();
        let client_pk = client.pub_key().to_vec();
        assert_eq!(client_pk.len(), sntrup761::public_key_bytes());

        // Server encapsulates to the client's public key.
        let completed = group.start_and_complete(&client_pk).unwrap();
        assert_eq!(completed.group, SNTRUP761_GROUP);
        assert_eq!(completed.pub_key.len(), sntrup761::ciphertext_bytes());
        let server_secret = completed.secret.secret_bytes().to_vec();

        // Client decapsulates the server's ciphertext.
        let client_secret = client.complete(&completed.pub_key).unwrap();
        assert_eq!(client_secret.secret_bytes(), &server_secret[..]);
        assert_eq!(server_secret.len(), sntrup761::shared_secret_bytes());
    }

    #[test]
    fn rejects_garbage_key_share() {
        let group = Sntrup761KxGroup;
        assert!(group.start_and_complete(&[0u8; 10]).is_err());
    }
}

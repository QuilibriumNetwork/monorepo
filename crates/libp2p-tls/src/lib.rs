// Copyright 2021 Parity Technologies (UK) Ltd.
// Copyright 2022 Protocol Labs.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! TLS configuration based on libp2p TLS specs.
//!
//! See <https://github.com/libp2p/specs/blob/master/tls/tls.md>.

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

pub mod certificate;
pub mod sntrup761_kx;
mod upgrade;
mod verifier;

use std::sync::Arc;

use certificate::AlwaysResolvesCert;
pub use futures_rustls::TlsStream;
use libp2p_identity::{Keypair, PeerId};
pub use upgrade::{Config, UpgradeError};

const P2P_ALPN: [u8; 6] = *b"libp2p";

/// Create a TLS client configuration for libp2p.
pub fn make_client_config(
    keypair: &Keypair,
    remote_peer_id: Option<PeerId>,
) -> Result<rustls::ClientConfig, certificate::GenError> {
    let (certificate, private_key) = certificate::generate(keypair)?;

    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = verifier::CIPHERSUITES.to_vec();
    // Quilibrium: post-quantum, pure-NTRU QUIC key exchange. Offer ONLY
    // sntrup761 (non-hybrid) — the Rust-only network agrees on this group.
    provider.kx_groups = vec![sntrup761_kx::SNTRUP761];

    let cert_resolver = Arc::new(
        AlwaysResolvesCert::new(certificate, &private_key)
            .expect("Client cert key DER is valid; qed"),
    );

    let mut crypto = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("Cipher suites and kx groups are configured; qed")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            verifier::Libp2pCertificateVerifier::with_remote_peer_id(remote_peer_id),
        ))
        .with_client_cert_resolver(cert_resolver);
    crypto.alpn_protocols = vec![P2P_ALPN.to_vec()];

    Ok(crypto)
}

/// Create a TLS server configuration for libp2p.
pub fn make_server_config(
    keypair: &Keypair,
) -> Result<rustls::ServerConfig, certificate::GenError> {
    let (certificate, private_key) = certificate::generate(keypair)?;

    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = verifier::CIPHERSUITES.to_vec();
    // Quilibrium: post-quantum, pure-NTRU QUIC key exchange (see client config).
    provider.kx_groups = vec![sntrup761_kx::SNTRUP761];

    let cert_resolver = Arc::new(
        AlwaysResolvesCert::new(certificate, &private_key)
            .expect("Server cert key DER is valid; qed"),
    );

    let mut crypto = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("Cipher suites and kx groups are configured; qed")
        .with_client_cert_verifier(Arc::new(verifier::Libp2pCertificateVerifier::new()))
        .with_cert_resolver(cert_resolver);
    crypto.alpn_protocols = vec![P2P_ALPN.to_vec()];

    Ok(crypto)
}

#[cfg(test)]
mod pq_quic_tests {
    use super::*;
    use libp2p_identity::Keypair;

    /// A real TLS 1.3 handshake through the forked libp2p configs completes and
    /// negotiates the sntrup761 key-exchange group — i.e. QUIC (which uses this
    /// same rustls key schedule) is now post-quantum. Both peers offer *only*
    /// sntrup761, so completion alone proves NTRU was used; we also assert the
    /// negotiated group explicitly.
    #[test]
    fn tls13_handshake_negotiates_sntrup761() {
        let server_id = Keypair::generate_ed25519();
        let client_id = Keypair::generate_ed25519();
        let server_pid = server_id.public().to_peer_id();

        let client_config =
            make_client_config(&client_id, Some(server_pid)).expect("client config");
        let server_config = make_server_config(&server_id).expect("server config");

        let mut client = rustls::ClientConnection::new(
            Arc::new(client_config),
            "quilibrium".try_into().unwrap(),
        )
        .expect("client conn");
        let mut server =
            rustls::ServerConnection::new(Arc::new(server_config)).expect("server conn");

        for _ in 0..16 {
            let mut flight = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut flight).unwrap();
            }
            if !flight.is_empty() {
                server.read_tls(&mut flight.as_slice()).unwrap();
                server.process_new_packets().expect("server process");
            }

            let mut flight = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut flight).unwrap();
            }
            if !flight.is_empty() {
                client.read_tls(&mut flight.as_slice()).unwrap();
                client.process_new_packets().expect("client process");
            }

            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }

        assert!(!client.is_handshaking(), "client handshake did not complete");
        assert!(!server.is_handshaking(), "server handshake did not complete");

        let group = client
            .negotiated_key_exchange_group()
            .expect("a key-exchange group was negotiated");
        assert_eq!(group.name(), sntrup761_kx::SNTRUP761.name());
    }
}

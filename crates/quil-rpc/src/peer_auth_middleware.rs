//! gRPC peer-identity extractor for inbound requests.
//!
//! Mirrors the *identification* half of Go's channel peer-auth layer:
//! given the client cert's SAN DNS name (`hex(ed448_pub || xsign)`),
//! derive the peer's Ed448 public key + libp2p peer ID, attach them
//! to the request as an [`AuthenticatedPeer`] extension, and let
//! downstream handlers (or service layers) gate on presence.
//!
//! Policy *enforcement* lives in each handler — the handler inspects
//! `req.extensions().get::<AuthenticatedPeer>()` and decides whether
//! the absence / presence of a peer ID plus the configured
//! [`AllowedPeerPolicy`] on a `PeerAuthenticator` admits the request.
//!
//! Tonic 0.12 doesn't expose the gRPC method name in a bare
//! `Request<()>` interceptor (the URI is consumed by the service
//! router before interceptors see it). That's why policy enforcement
//! is pushed to the handler level, where the method is implicit.
//!
//! Full mTLS verification (proving the peer actually owns the Ed448
//! key they claim in the SAN via the `xsign` cross-signature) is
//! performed at the TLS layer by
//! [`crate::quil_tls::XsignClientCertVerifier`], which rustls invokes
//! during the handshake. By the time a request reaches this
//! interceptor the SAN's Ed448 → libp2p PeerID mapping has been
//! cryptographically vouched for; this interceptor only re-decodes
//! it from the cert to attach to the request extension.

use tonic::{Request, Status};
use tracing::debug;

use quil_p2p::PeerId;

/// Request extension set by the TLS acceptor layer carrying the
/// client's DER-encoded X.509 certificate. Absence signals the
/// request arrived over plaintext or with no client cert.
#[derive(Debug, Clone)]
pub struct PeerCertInfo {
    pub cert_der: Vec<u8>,
}

/// Request extension populated by [`peer_auth_interceptor`] once the
/// cert's SAN is decoded. Handlers consult this to gate writes.
#[derive(Debug, Clone)]
pub struct AuthenticatedPeer {
    pub peer_id: PeerId,
    pub ed448_public_key: Vec<u8>,
}

/// Decode the peer's Ed448 public key + libp2p PeerID from an X.509
/// cert's SAN DNS name. Returns `None` on any parse failure.
///
/// Matches the encoding written by
/// [`quil_tls::build_quil_tls_cert`](crate::quil_tls::build_quil_tls_cert):
/// `hex(ed448_pub_57 || xsign_114)`.
pub fn peer_identity_from_cert(cert_der: &[u8]) -> Option<(Vec<u8>, PeerId)> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    let san = cert.subject_alternative_name().ok().flatten()?;
    for name in &san.value.general_names {
        if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
            let Ok(all) = hex::decode(dns) else { continue };
            if all.len() < 57 {
                continue;
            }
            let ed448_pub = all[..57].to_vec();
            let peer_id_bytes =
                quil_p2p::ed448_identity::peer_id_from_ed448_pubkey(&ed448_pub);
            if let Ok(peer_id) = PeerId::from_bytes(&peer_id_bytes) {
                return Some((ed448_pub, peer_id));
            }
        }
    }
    None
}

/// Tonic interceptor: extracts peer identity from either a
/// [`PeerCertInfo`] extension (injected manually, e.g. for tests) or
/// tonic's built-in `TlsConnectInfo` (populated automatically when the
/// server runs behind a `tokio_rustls::TlsStream`). Decodes the
/// first peer cert into an [`AuthenticatedPeer`] and attaches it.
///
/// Always passes the request through — policy enforcement is
/// handler-side. Safe to apply to every service; has no effect on
/// plaintext calls.
pub fn peer_auth_interceptor(mut req: Request<()>) -> Result<Request<()>, Status> {
    if req.extensions().get::<AuthenticatedPeer>().is_some() {
        return Ok(req);
    }

    // Prefer an explicit PeerCertInfo extension (test harness path),
    // else fall through to tonic's TlsConnectInfo which wraps the
    // tokio_rustls session's peer certs.
    let cert_der = req
        .extensions()
        .get::<PeerCertInfo>()
        .map(|info| info.cert_der.clone())
        .or_else(|| {
            req.extensions()
                .get::<tonic::transport::server::TlsConnectInfo<
                    tonic::transport::server::TcpConnectInfo,
                >>()
                .and_then(|info| info.peer_certs())
                .and_then(|certs| certs.first().map(|c| c.as_ref().to_vec()))
        });

    if let Some(der) = cert_der {
        if let Some((pubkey, peer_id)) = peer_identity_from_cert(&der) {
            debug!(%peer_id, "authenticated inbound peer from cert");
            req.extensions_mut().insert(AuthenticatedPeer {
                peer_id,
                ed448_public_key: pubkey,
            });
        }
    }
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_request_passes_without_auth_peer() {
        let req: Request<()> = Request::new(());
        let out = peer_auth_interceptor(req).unwrap();
        assert!(out.extensions().get::<AuthenticatedPeer>().is_none());
    }

    #[test]
    fn empty_cert_bytes_leaves_no_auth_peer() {
        let mut req: Request<()> = Request::new(());
        req.extensions_mut().insert(PeerCertInfo {
            cert_der: Vec::new(),
        });
        let out = peer_auth_interceptor(req).unwrap();
        assert!(out.extensions().get::<AuthenticatedPeer>().is_none());
    }

    #[test]
    fn malformed_cert_bytes_leaves_no_auth_peer() {
        let mut req: Request<()> = Request::new(());
        req.extensions_mut().insert(PeerCertInfo {
            cert_der: vec![0xde, 0xad, 0xbe, 0xef],
        });
        let out = peer_auth_interceptor(req).unwrap();
        assert!(out.extensions().get::<AuthenticatedPeer>().is_none());
    }

    #[test]
    fn real_tls_cert_derives_peer_identity() {
        // Build an actual cert via build_quil_tls_cert, then parse the
        // PEM-encoded cert back into DER and feed through the extractor.
        let seed = [0x42u8; 57];
        let tls = crate::quil_tls::build_quil_tls_cert(&seed).unwrap();
        // tls.cert_pem is PEM — decode to DER.
        let der_blocks: Vec<Vec<u8>> = rustls_pemfile::certs(&mut tls.cert_pem.as_bytes())
            .filter_map(|r| r.ok())
            .map(|c| c.to_vec())
            .collect();
        assert!(!der_blocks.is_empty(), "cert_pem should produce at least one DER block");
        let (pubkey, _peer_id) = peer_identity_from_cert(&der_blocks[0])
            .expect("cert SAN should decode to a valid peer identity");
        assert_eq!(pubkey.len(), 57, "Ed448 public key should be 57 bytes");

        // Now pass through the full interceptor to confirm end-to-end.
        let mut req: Request<()> = Request::new(());
        req.extensions_mut().insert(PeerCertInfo {
            cert_der: der_blocks[0].clone(),
        });
        let out = peer_auth_interceptor(req).unwrap();
        let ap = out.extensions().get::<AuthenticatedPeer>().expect("auth set");
        assert_eq!(ap.ed448_public_key.len(), 57);
    }
}

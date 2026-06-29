//! Quilibrium peer mTLS — generates the Ed25519-on-x509 certificate that
//! Go's `node/p2p/peer_authenticator.go` uses for archive client/server auth.
//!
//! The scheme works around Go's x509 lacking native Ed448 support:
//!
//! 1. Derive an Ed25519 seed deterministically:
//!      `ed25519_seed = SHA256(ed448_seed || "tls-cert-derivation")[..32]`
//! 2. Generate an Ed25519 keypair from that seed.
//! 3. Cross-sign the Ed25519 public key with the Ed448 private key:
//!      `xsign = ed448_priv.sign("tls-cert-derivation" || ed25519_pub)`
//! 4. Self-sign an x509 cert with the Ed25519 key, embedding
//!      `hex(ed448_pub || xsign)` (171 bytes hex => 342 chars) as the
//!    cert's single SAN DNS name.
//!
//! On the receiving side, peers parse the DNS name back into the Ed448 pubkey
//! + signature, verify the cross-sig, and re-derive the libp2p peer ID.

use ed25519_dalek::SigningKey;
use ed448_rust::{PrivateKey as Ed448PrivateKey, PublicKey as Ed448PublicKey};
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, KeyPair, SanType, PKCS_ED25519,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

const TLS_CERT_DERIVATION_CTX: &[u8] = b"tls-cert-derivation";

#[derive(Debug, Error)]
pub enum QuilTlsError {
    #[error("ed448 key error: {0}")]
    Ed448(String),
    #[error("ed25519 pkcs8 encode error: {0}")]
    Ed25519Pkcs8(String),
    #[error("rcgen error: {0}")]
    Rcgen(String),
}

/// PEM-encoded TLS material derived from a Quilibrium Ed448 seed.
pub struct QuilTlsCert {
    /// PEM-encoded x509 certificate.
    pub cert_pem: String,
    /// PEM-encoded PKCS#8 Ed25519 private key.
    pub key_pem: String,
    /// Hex-encoded `ed448_pub || xsign` — the SAN DNS name.
    pub xsign_hex: String,
}

/// Build a Quilibrium TLS certificate for the given Ed448 seed (57 bytes,
/// matching `ed448::SeedSize`).
pub fn build_quil_tls_cert(ed448_seed: &[u8; 57]) -> Result<QuilTlsCert, QuilTlsError> {
    // 1. Derive Ed25519 seed.
    let mut hasher = Sha256::new();
    hasher.update(ed448_seed);
    hasher.update(TLS_CERT_DERIVATION_CTX);
    let digest = hasher.finalize();
    let mut ed25519_seed = [0u8; 32];
    ed25519_seed.copy_from_slice(&digest[..32]);

    // 2. Generate Ed25519 keypair.
    let signing_key = SigningKey::from_bytes(&ed25519_seed);
    let ed25519_pub = signing_key.verifying_key().to_bytes();

    // 3. Cross-sign with Ed448.
    let ed448_priv = Ed448PrivateKey::from(*ed448_seed);
    let ed448_pub = Ed448PublicKey::try_from(&ed448_priv)
        .map_err(|e| QuilTlsError::Ed448(format!("derive pub: {:?}", e)))?;
    let mut to_sign = Vec::with_capacity(TLS_CERT_DERIVATION_CTX.len() + ed25519_pub.len());
    to_sign.extend_from_slice(TLS_CERT_DERIVATION_CTX);
    to_sign.extend_from_slice(&ed25519_pub);
    let xsign = ed448_priv
        .sign(&to_sign, None)
        .map_err(|e| QuilTlsError::Ed448(format!("sign: {:?}", e)))?;

    // 4. Build the SAN string: hex(ed448_pub || xsign)
    let mut san_buf = Vec::with_capacity(57 + 114);
    san_buf.extend_from_slice(&ed448_pub.as_byte());
    san_buf.extend_from_slice(&xsign);
    let xsign_hex = hex::encode(&san_buf);

    // 5. Build the cert with rcgen. rcgen 0.11 uses *ring*, which requires
    // PKCS#8 v2 (with public key included). ed25519-dalek emits v1, so we
    // hand-encode the v2 DER blob ourselves.
    let pkcs8_v2 = ed25519_pkcs8_v2(&ed25519_seed, &ed25519_pub);
    let key_pair = KeyPair::from_der(&pkcs8_v2)
        .map_err(|e| QuilTlsError::Rcgen(format!("KeyPair::from_der: {}", e)))?;
    if key_pair.algorithm() != &PKCS_ED25519 {
        return Err(QuilTlsError::Rcgen(format!(
            "unexpected algorithm: {:?}",
            key_pair.algorithm()
        )));
    }
    // For external consumers we still want a PEM. Wrap the v2 DER ourselves.
    let key_pem = pkcs8_der_to_pem("PRIVATE KEY", &pkcs8_v2);

    let mut params = CertificateParams::default();
    params.alg = &PKCS_ED25519;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::OrganizationName, "QTLS");
    params.subject_alt_names = vec![SanType::DnsName(xsign_hex.clone())];
    params.key_pair = Some(key_pair);

    let cert = Certificate::from_params(params)
        .map_err(|e| QuilTlsError::Rcgen(format!("from_params: {}", e)))?;
    let cert_pem = cert
        .serialize_pem()
        .map_err(|e| QuilTlsError::Rcgen(format!("serialize_pem: {}", e)))?;
    Ok(QuilTlsCert {
        cert_pem,
        key_pem: key_pem.to_string(),
        xsign_hex,
    })
}

/// Encode an Ed25519 PKCS#8 v2 blob (private + public keys) in the exact
/// shape that *ring* — and therefore rcgen 0.11 — expects.
///
/// Structure:
/// ```text
/// SEQUENCE                      (0x30 0x53)
///   INTEGER 1                   (0x02 0x01 0x01)
///   AlgorithmIdentifier         (0x30 0x05 0x06 0x03 0x2b 0x65 0x70)  -- 1.3.101.112
///   OCTET STRING wrapping
///     OCTET STRING(seed[32])    (0x04 0x22 0x04 0x20 || seed)
///   [1] BIT STRING(pubkey[32])  (0xa1 0x23 0x03 0x21 0x00 || pubkey)
/// ```
fn ed25519_pkcs8_v2(seed: &[u8; 32], public_key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(85);
    out.extend_from_slice(&[
        0x30, 0x53, // SEQUENCE, 83 bytes
        0x02, 0x01, 0x01, // INTEGER 1
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, 0x04, 0x20, // OCTET STRING(34) wrapping OCTET STRING(32)
    ]);
    out.extend_from_slice(seed);
    out.extend_from_slice(&[
        0xa1, 0x23, // [1] context-specific, 35 bytes
        0x03, 0x21, 0x00, // BIT STRING(33), zero unused bits
    ]);
    out.extend_from_slice(public_key);
    out
}

/// Wrap a DER blob in a PKCS#8 PEM container with the requested label.
fn pkcs8_der_to_pem(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::new();
    out.push_str(&format!("-----BEGIN {}-----\n", label));
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {}-----\n", label));
    out
}

// =====================================================================
// Server-side TLS: build a `rustls::ServerConfig` from an Ed448 seed,
// with a permissive client cert verifier that accepts any
// syntactically-valid Ed448-derived peer cert. Mirrors the
// `AcceptAnyServerCert` verifier used on the client side.
// =====================================================================

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{ServerConfig, SignatureScheme};

/// Client cert verifier that enforces Quilibrium's xsign cross-signature
/// scheme. Mirrors Go's `peer_authenticator.go` `VerifyPeerCertificate`
/// callback:
///
/// 1. Parse the presented end-entity cert.
/// 2. Extract the cert's Ed25519 public key from its
///    `SubjectPublicKeyInfo`.
/// 3. Pull the single SAN DNS name and decode it as
///    `hex(ed448_pub_57 || xsign_114)`.
/// 4. Verify the Ed448 signature `xsign` over the message
///    `b"tls-cert-derivation" || ed25519_pub` under the SAN's Ed448
///    public key.
///
/// Any failure rejects the handshake. Per-peer authorization
/// (membership in prover/signer registries, whitelist, etc.) is still
/// applied at the gRPC service layer by `PeerAuthenticator`; this
/// verifier only proves the SAN identity is owned by the peer.
///
/// Requires a client cert (mandatory auth) so downstream code can
/// always rely on `TlsConnectInfo::peer_certs()` being populated.
#[derive(Debug)]
pub struct XsignClientCertVerifier {
    /// Signature-verification algorithms from the installed crypto provider,
    /// used to perform the real TLS `CertificateVerify` proof-of-possession
    /// check in `verify_tls1x_signature`.
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl Default for XsignClientCertVerifier {
    /// Build a verifier wired to the ring crypto provider's signature
    /// algorithms (matching the provider installed by
    /// `build_quil_server_tls_config`).
    fn default() -> Self {
        Self {
            supported: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }
}

/// Memoized results of [`XsignClientCertVerifier::verify_xsign`], keyed by
/// SHA-256 of the presented cert DER → the SAN-derived Ed448 pubkey. A peer
/// presents the IDENTICAL cert on every handshake, and the xsign scheme has
/// no expiry, so the (slow, vendored-pure-Rust) Ed448 *verify* — plus the
/// x509 parse — should run once per distinct peer cert, not once per
/// connection. A tampered cert hashes differently → cache miss → full
/// verify → reject, so caching is sound. Bounded; cleared wholesale on
/// overflow (crude but keeps it from growing unbounded as prover identities
/// churn). The verify is deterministic, so a re-fill is cheap correctness-wise.
static XSIGN_VERIFY_CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<[u8; 32], Vec<u8>>>,
> = std::sync::OnceLock::new();
const XSIGN_VERIFY_CACHE_CAP: usize = 8192;

impl XsignClientCertVerifier {
    /// Stand-alone validation routine, exposed for tests. Returns the
    /// SAN-derived Ed448 public key on success.
    pub fn verify_xsign(cert_der: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        use sha2::{Digest, Sha256};
        let cert_hash: [u8; 32] = Sha256::digest(cert_der).into();
        let cache = XSIGN_VERIFY_CACHE
            .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
        if let Some(pk) = cache.lock().unwrap().get(&cert_hash) {
            return Ok(pk.clone());
        }

        let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
            .map_err(|e| rustls::Error::General(format!("parse client cert: {e}")))?;

        // Extract the cert's Ed25519 SubjectPublicKey raw bytes. For
        // Ed25519 (OID 1.3.101.112) the BIT STRING is the 32-byte
        // public key.
        let spki = cert.public_key();
        let ed25519_pub: &[u8] = spki.subject_public_key.data.as_ref();
        if ed25519_pub.len() != 32 {
            return Err(rustls::Error::General(format!(
                "client cert subject pubkey is not 32 bytes (got {})",
                ed25519_pub.len()
            )));
        }

        // Find the SAN; require exactly one DNSName entry to match the
        // Go side's `len(peerCert.DNSNames) != 1` check.
        let san_ext = cert
            .subject_alternative_name()
            .map_err(|e| rustls::Error::General(format!("read SAN: {e}")))?
            .ok_or_else(|| rustls::Error::General("client cert missing SAN".into()))?;

        let mut dns_names = san_ext.value.general_names.iter().filter_map(|n| match n {
            x509_parser::extensions::GeneralName::DNSName(d) => Some(*d),
            _ => None,
        });
        let dns = dns_names
            .next()
            .ok_or_else(|| rustls::Error::General("client cert SAN has no DNSName".into()))?;
        if dns_names.next().is_some() {
            return Err(rustls::Error::General(
                "client cert SAN has multiple DNSNames".into(),
            ));
        }

        let blob = hex::decode(dns)
            .map_err(|e| rustls::Error::General(format!("decode SAN hex: {e}")))?;
        // 57-byte Ed448 pubkey || 114-byte Ed448 signature
        if blob.len() != 57 + 114 {
            return Err(rustls::Error::General(format!(
                "client cert SAN xsign blob has wrong length: {}",
                blob.len()
            )));
        }
        let ed448_pub_bytes: [u8; 57] = blob[..57]
            .try_into()
            .map_err(|_| rustls::Error::General("ed448 pubkey slice".into()))?;
        let xsign = &blob[57..];

        let ed448_pub = ed448_rust::PublicKey::from(ed448_pub_bytes);

        let mut signed = Vec::with_capacity(TLS_CERT_DERIVATION_CTX.len() + ed25519_pub.len());
        signed.extend_from_slice(TLS_CERT_DERIVATION_CTX);
        signed.extend_from_slice(ed25519_pub);

        ed448_pub
            .verify(&signed, xsign, None)
            .map_err(|e| rustls::Error::General(format!("xsign verify failed: {e:?}")))?;

        let pubkey = blob[..57].to_vec();
        {
            let mut c = cache.lock().unwrap();
            if c.len() >= XSIGN_VERIFY_CACHE_CAP {
                c.clear();
            }
            c.insert(cert_hash, pubkey.clone());
        }
        Ok(pubkey)
    }
}

impl ClientCertVerifier for XsignClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Self::verify_xsign(end_entity.as_ref())?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // This callback IS the TLS proof-of-possession check: when a custom
        // verifier is installed there is no separate built-in step. Verify the
        // client's CertificateVerify signature against the cert's Ed25519 key,
        // proving the live peer holds the cert's private half (Go's
        // crypto/tls enforces this unconditionally; xsign alone does not).
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // The Quilibrium cert always uses Ed25519 — narrow the list so
        // rustls negotiates that scheme. (The Go side leaves it open;
        // restricting here is harmless and surfaces mismatches early.)
        vec![SignatureScheme::ED25519]
    }
}

/// Backwards-compatible alias retained for existing callers/tests.
/// New code should use [`XsignClientCertVerifier`].
pub type AcceptAnyClientCert = XsignClientCertVerifier;

/// Build a rustls `ServerConfig` from an Ed448 seed. The server
/// presents the Ed25519-derived Quilibrium cert and requires every
/// client to present one (verified permissively — trust is at the
/// application layer via the peer-auth interceptor).
pub fn build_quil_server_tls_config(
    ed448_seed: &[u8; 57],
) -> Result<Arc<ServerConfig>, QuilTlsError> {
    // SAFETY: install the default rustls crypto provider once; errors
    // just mean another provider is already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tls_cert = build_quil_tls_cert(ed448_seed)?;
    let cert_chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut tls_cert.cert_pem.as_bytes())
            .filter_map(|r| r.ok())
            .collect();
    if cert_chain.is_empty() {
        return Err(QuilTlsError::Rcgen("no cert in pem output".into()));
    }

    let key_der: PrivateKeyDer<'static> = rustls_pemfile::private_key(
        &mut tls_cert.key_pem.as_bytes(),
    )
    .map_err(|e| QuilTlsError::Rcgen(format!("parse key pem: {}", e)))?
    .ok_or_else(|| QuilTlsError::Rcgen("no private key in pem".into()))?;

    let verifier: Arc<dyn ClientCertVerifier> = Arc::new(XsignClientCertVerifier::default());

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key_der)
        .map_err(|e| QuilTlsError::Rcgen(format!("server config: {}", e)))?;

    // ALPN h2 — required for gRPC over HTTP/2.
    config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    // =================================================================
    // XsignClientCertVerifier — accepts good certs, rejects tampered
    // =================================================================

    fn cert_der_from_seed(seed: &[u8; 57]) -> Vec<u8> {
        let tls = build_quil_tls_cert(seed).unwrap();
        let pem = tls.cert_pem.clone();
        let mut reader = pem.as_bytes();
        let cert = rustls_pemfile::certs(&mut reader).next().unwrap().unwrap();
        cert.to_vec()
    }

    #[test]
    fn xsign_verifier_accepts_well_formed_cert() {
        let seed = [0x71u8; 57];
        let der = cert_der_from_seed(&seed);
        let pubkey = XsignClientCertVerifier::verify_xsign(&der)
            .expect("xsign verify must accept a freshly-built cert");
        assert_eq!(pubkey.len(), 57);
    }

    #[test]
    fn xsign_verifier_rejects_random_bytes() {
        let err = XsignClientCertVerifier::verify_xsign(&[0x00, 0x01, 0x02]);
        assert!(err.is_err());
    }

    #[test]
    fn xsign_verifier_rejects_tampered_san() {
        // Take a real cert, flip a bit in the xsign signature half of
        // the SAN, and confirm verification fails.
        let seed = [0x55u8; 57];
        let tls = build_quil_tls_cert(&seed).unwrap();
        // Mutate the SAN string (still valid hex of valid length) by
        // flipping the last hex digit. This corrupts the signature
        // while keeping the encoding parseable.
        let mut san = tls.xsign_hex.clone();
        let last = san.pop().unwrap();
        let flipped = if last == 'f' { '0' } else { 'f' };
        san.push(flipped);
        // Build a new cert with the corrupted SAN. We have to redo
        // the rcgen flow from scratch since the existing helper
        // computes its own SAN.
        let mut hasher = sha2::Sha256::new();
        hasher.update(&seed);
        hasher.update(TLS_CERT_DERIVATION_CTX);
        let digest = hasher.finalize();
        let mut ed25519_seed = [0u8; 32];
        ed25519_seed.copy_from_slice(&digest[..32]);
        let signing = ed25519_dalek::SigningKey::from_bytes(&ed25519_seed);
        let ed25519_pub = signing.verifying_key().to_bytes();
        let pkcs8 = ed25519_pkcs8_v2(&ed25519_seed, &ed25519_pub);
        let key_pair = rcgen::KeyPair::from_der(&pkcs8).unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.alg = &rcgen::PKCS_ED25519;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "QTLS");
        params.subject_alt_names = vec![rcgen::SanType::DnsName(san)];
        params.key_pair = Some(key_pair);
        let cert = rcgen::Certificate::from_params(params).unwrap();
        let pem = cert.serialize_pem().unwrap();
        let der = rustls_pemfile::certs(&mut pem.as_bytes())
            .next()
            .unwrap()
            .unwrap()
            .to_vec();

        let res = XsignClientCertVerifier::verify_xsign(&der);
        assert!(res.is_err(), "tampered SAN must fail xsign verification");
    }

    // =================================================================
    // build_quil_tls_cert — smoke + structure
    // =================================================================

    #[test]
    fn build_cert_from_known_seed() {
        let seed = [0x42u8; 57];
        let tls = build_quil_tls_cert(&seed).expect("build cert");
        assert!(tls.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(tls.key_pem.contains("BEGIN PRIVATE KEY"));
        // xsign is hex(57 + 114) = 342 chars
        assert_eq!(tls.xsign_hex.len(), (57 + 114) * 2);
    }

    #[test]
    fn build_cert_from_zero_seed() {
        let seed = [0u8; 57];
        let tls = build_quil_tls_cert(&seed).expect("build cert");
        assert!(tls.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(tls.cert_pem.contains("END CERTIFICATE"));
        assert!(tls.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(tls.key_pem.contains("END PRIVATE KEY"));
    }

    #[test]
    fn build_cert_xsign_is_valid_hex() {
        let seed = [0x17u8; 57];
        let tls = build_quil_tls_cert(&seed).unwrap();
        // Every character must be a valid hex digit.
        for c in tls.xsign_hex.chars() {
            assert!(
                c.is_ascii_hexdigit(),
                "xsign_hex contains non-hex char: {:?}",
                c
            );
        }
        // Round-trip decodes cleanly.
        let decoded = hex::decode(&tls.xsign_hex).unwrap();
        assert_eq!(decoded.len(), 57 + 114);
    }

    #[test]
    fn build_cert_xsign_starts_with_ed448_pubkey() {
        // The first 57 bytes of the xsign blob are the Ed448 public key
        // derived from the seed. Compute it independently and compare.
        let seed = [0x99u8; 57];
        let tls = build_quil_tls_cert(&seed).unwrap();
        let decoded = hex::decode(&tls.xsign_hex).unwrap();

        let priv_key = Ed448PrivateKey::from(seed);
        let pub_key = Ed448PublicKey::try_from(&priv_key).unwrap();
        assert_eq!(&decoded[..57], pub_key.as_byte());
    }

    #[test]
    fn build_cert_xsign_signature_portion_has_ed448_sig_length() {
        // The last 114 bytes of xsign are the Ed448 signature over
        // `"tls-cert-derivation" || ed25519_pub`. We don't verify the
        // signature directly (that's a property of ed448-rust, not
        // our TLS cert code), but we lock down the length and the
        // split point between pub key and signature.
        let seed = [0x33u8; 57];
        let tls = build_quil_tls_cert(&seed).unwrap();
        let decoded = hex::decode(&tls.xsign_hex).unwrap();
        assert_eq!(decoded.len(), 57 + 114);
        let signature = &decoded[57..];
        assert_eq!(signature.len(), 114);
        // Sanity: the signature must not be all zero (a degenerate
        // ed448 sig would be suspicious).
        assert!(!signature.iter().all(|&b| b == 0));
    }

    #[test]
    fn build_cert_xsign_is_deterministic_for_same_seed() {
        // Extracted as its own property: the xsign_hex output is a
        // deterministic function of the seed alone. This is a stronger
        // claim than `same_seed_produces_same_xsign_but_different_cert`
        // below because it verifies the determinism across multiple
        // invocations, not just two.
        let seed = [0x55u8; 57];
        let results: Vec<String> = (0..5)
            .map(|_| build_quil_tls_cert(&seed).unwrap().xsign_hex)
            .collect();
        // All 5 outputs must be identical.
        for r in &results[1..] {
            assert_eq!(r, &results[0]);
        }
    }

    // =================================================================
    // Deterministic derivation
    // =================================================================

    #[test]
    fn same_seed_produces_same_xsign_but_different_cert() {
        // The `xsign_hex` is deterministic from the seed (SHA-256
        // derivation + Ed25519 key + Ed448 sig). The x509 cert body
        // may include a randomly-generated serial number and
        // timestamps, so cert_pem can differ between calls while
        // xsign_hex stays identical.
        let seed = [0xABu8; 57];
        let a = build_quil_tls_cert(&seed).unwrap();
        let b = build_quil_tls_cert(&seed).unwrap();
        assert_eq!(a.xsign_hex, b.xsign_hex);
        assert_eq!(a.key_pem, b.key_pem);
        // cert_pem structure contains the SAN which contains xsign_hex;
        // both certs should include it.
        assert!(a.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(b.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn different_seeds_produce_different_xsign() {
        let a = build_quil_tls_cert(&[0x01u8; 57]).unwrap();
        let b = build_quil_tls_cert(&[0x02u8; 57]).unwrap();
        assert_ne!(a.xsign_hex, b.xsign_hex);
        assert_ne!(a.key_pem, b.key_pem);
    }

    #[test]
    fn different_seeds_produce_different_ed25519_keys() {
        // If the derivation is correct, two seeds must produce two
        // different Ed25519 private keys. We extract the first 32
        // bytes of the derived seed from each and compare.
        let seed_a = [0x11u8; 57];
        let seed_b = [0x22u8; 57];

        let derive_ed25519_seed = |seed: &[u8; 57]| -> [u8; 32] {
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update(TLS_CERT_DERIVATION_CTX);
            let mut out = [0u8; 32];
            out.copy_from_slice(&hasher.finalize()[..32]);
            out
        };
        let a_seed = derive_ed25519_seed(&seed_a);
        let b_seed = derive_ed25519_seed(&seed_b);
        assert_ne!(a_seed, b_seed);
    }

    // =================================================================
    // PKCS#8 v2 DER encoder
    // =================================================================

    #[test]
    fn ed25519_pkcs8_v2_is_85_bytes() {
        let seed = [0x33u8; 32];
        let pub_key = [0x44u8; 32];
        let encoded = ed25519_pkcs8_v2(&seed, &pub_key);
        assert_eq!(encoded.len(), 85);
    }

    #[test]
    fn ed25519_pkcs8_v2_header_matches_ring_expected_shape() {
        let seed = [0u8; 32];
        let pub_key = [0u8; 32];
        let encoded = ed25519_pkcs8_v2(&seed, &pub_key);
        // Byte-by-byte structural check against the v2 ASN.1 layout
        // documented in the function comment.
        assert_eq!(encoded[0], 0x30); // SEQUENCE
        assert_eq!(encoded[1], 0x53); // length 83
        assert_eq!(&encoded[2..5], &[0x02, 0x01, 0x01]); // INTEGER 1
        assert_eq!(
            &encoded[5..12],
            &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]
        ); // AlgorithmIdentifier (Ed25519 OID 1.3.101.112)
        assert_eq!(&encoded[12..16], &[0x04, 0x22, 0x04, 0x20]); // wrapping OCTET STRING(seed)
    }

    #[test]
    fn ed25519_pkcs8_v2_contains_seed_at_expected_offset() {
        let seed = [0x77u8; 32];
        let pub_key = [0x88u8; 32];
        let encoded = ed25519_pkcs8_v2(&seed, &pub_key);
        // Seed lives at offset 16..48
        assert_eq!(&encoded[16..48], &seed[..]);
    }

    #[test]
    fn ed25519_pkcs8_v2_contains_pubkey_at_expected_offset() {
        let seed = [0x11u8; 32];
        let pub_key = [0x22u8; 32];
        let encoded = ed25519_pkcs8_v2(&seed, &pub_key);
        // After the seed there are 5 header bytes (0xa1, 0x23, 0x03,
        // 0x21, 0x00), then the 32-byte public key at offset 53..85.
        assert_eq!(&encoded[48..53], &[0xa1, 0x23, 0x03, 0x21, 0x00]);
        assert_eq!(&encoded[53..85], &pub_key[..]);
    }

    #[test]
    fn ed25519_pkcs8_v2_encoding_is_deterministic() {
        let seed = [0x99u8; 32];
        let pub_key = [0xAAu8; 32];
        let a = ed25519_pkcs8_v2(&seed, &pub_key);
        let b = ed25519_pkcs8_v2(&seed, &pub_key);
        assert_eq!(a, b);
    }

    // =================================================================
    // PEM wrapping
    // =================================================================

    #[test]
    fn pkcs8_der_to_pem_produces_valid_pem_envelope() {
        let der = vec![0u8; 85];
        let pem = pkcs8_der_to_pem("PRIVATE KEY", &der);
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem.ends_with("-----END PRIVATE KEY-----\n"));
    }

    #[test]
    fn pkcs8_der_to_pem_uses_custom_label() {
        let der = vec![0u8; 32];
        let pem = pkcs8_der_to_pem("CUSTOM LABEL", &der);
        assert!(pem.contains("-----BEGIN CUSTOM LABEL-----"));
        assert!(pem.contains("-----END CUSTOM LABEL-----"));
    }

    #[test]
    fn pkcs8_der_to_pem_wraps_body_at_64_chars() {
        let der = vec![0xFFu8; 256]; // large enough to span multiple lines
        let pem = pkcs8_der_to_pem("TEST", &der);
        // Every non-header line must be <= 64 characters.
        for line in pem.lines() {
            if line.starts_with("-----") {
                continue;
            }
            assert!(
                line.len() <= 64,
                "line exceeds 64 chars: {} ({})",
                line.len(),
                line
            );
        }
    }

    #[test]
    fn pkcs8_der_to_pem_round_trips_through_base64() {
        use base64::Engine;
        let der = (0..85u8).collect::<Vec<u8>>();
        let pem = pkcs8_der_to_pem("PRIVATE KEY", &der);
        // Extract the body between BEGIN and END markers, remove
        // newlines, base64-decode, and verify round-trip.
        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .unwrap();
        assert_eq!(decoded, der);
    }

    // =================================================================
    // QuilTlsError shape sanity
    // =================================================================

    #[test]
    fn tls_error_display_includes_inner_message() {
        let err = QuilTlsError::Ed448("derive failed".into());
        let msg = format!("{}", err);
        assert!(msg.contains("ed448"));
        assert!(msg.contains("derive failed"));

        let err2 = QuilTlsError::Rcgen("build failed".into());
        let msg2 = format!("{}", err2);
        assert!(msg2.contains("rcgen"));
        assert!(msg2.contains("build failed"));
    }

    // =================================================================
    // Proof-of-possession regression test — END-TO-END HANDSHAKE
    //
    // `verify_xsign` proves the presented cert is genuine (the Ed448
    // identity authorized its Ed25519 cert key) but NOT that the live peer
    // holds the cert's private key. That second guarantee is the TLS
    // `CertificateVerify` check, which rustls routes through
    // `verify_tls1x_signature`. `XsignClientCertVerifier` now performs that
    // check (it previously stubbed those callbacks to `Ok(assertion())`,
    // which let a client present a public cert it did not own — signing
    // CertificateVerify with a different key — and still authenticate).
    //
    // This repro covers the acceptor direction (`build_quil_server_tls_config`
    // / `XsignClientCertVerifier`); the client direction is covered in
    // `archive_client.rs`. The test drives a real TLS 1.3 handshake through
    // the actual production construction and asserts the handshake FAILS for a
    // forged (non-possessing) client. It failed before possession was enforced
    // (the handshake succeeded, demonstrating the bypass); it now guards
    // against that regression.
    // =================================================================

    use tokio_rustls::{TlsAcceptor, TlsConnector};

    fn cert_chain_from_seed(seed: &[u8; 57]) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(cert_der_from_seed(seed))]
    }

    /// Load the Ed25519 signing key derived from `seed`. Pairing this with a
    /// *different* seed's cert chain (via `CertifiedKey::new`, which — unlike
    /// `from_der` — does not check the key matches the cert) is the forgery:
    /// present someone else's cert, sign with your own key.
    fn signing_key_from_seed(seed: &[u8; 57]) -> Arc<dyn rustls::sign::SigningKey> {
        let tls = build_quil_tls_cert(seed).unwrap();
        let key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut tls.key_pem.as_bytes())
                .unwrap()
                .unwrap();
        rustls::crypto::ring::sign::any_supported_type(&key).unwrap()
    }

    /// Client resolver presenting `victim`'s cert chain but signing with the
    /// attacker's key — a client that does NOT possess the cert's key.
    #[derive(Debug)]
    struct ForgedClientIdentity(Arc<rustls::sign::CertifiedKey>);
    impl rustls::client::ResolvesClientCert for ForgedClientIdentity {
        fn resolve(
            &self,
            _root_hint_subjects: &[&[u8]],
            _sigschemes: &[SignatureScheme],
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(self.0.clone())
        }
        fn has_certs(&self) -> bool {
            true
        }
    }

    /// Proper client-side server-cert verifier for the test client. This
    /// branch has no client-side xsign verifier, so we implement one inline,
    /// mirroring Go's client `VerifyPeerCertificate`: verify the server's
    /// xsign cross-signature on its cert AND verify the handshake signature
    /// (real proof-of-possession) via rustls' standard webpki path. With a
    /// fully-correct verifier on the client, the handshake completing in the
    /// forged test is unambiguously the *server* accepting a non-possessing
    /// client — not a pushover client rubber-stamping the server.
    #[derive(Debug)]
    struct XsignServerVerifier {
        supported: rustls::crypto::WebPkiSupportedAlgorithms,
    }
    impl XsignServerVerifier {
        fn new() -> Self {
            Self {
                supported: rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms,
            }
        }
    }
    impl rustls::client::danger::ServerCertVerifier for XsignServerVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            // Genuine cert check: the server must present a valid xsign cert.
            XsignClientCertVerifier::verify_xsign(end_entity.as_ref())?;
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            // Real proof-of-possession: the server must hold its cert's key.
            rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.supported.supported_schemes()
        }
    }

    #[tokio::test]
    async fn acceptor_completes_handshake_with_forged_client_signature() {
        // Production server, built exactly as the node does.
        let acceptor = TlsAcceptor::from(build_quil_server_tls_config(&[0x71u8; 57]).unwrap());

        // Attacker: victim's public cert + attacker's own (different) key.
        let forged = Arc::new(rustls::sign::CertifiedKey::new(
            cert_chain_from_seed(&[0x61u8; 57]),
            signing_key_from_seed(&[0x62u8; 57]),
        ));
        let client_cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(XsignServerVerifier::new()))
            .with_client_cert_resolver(Arc::new(ForgedClientIdentity(forged)));
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let (server_res, client_res) = tokio::join!(
            acceptor.accept(server_io),
            connector.connect(server_name, client_io),
        );

        // Setup guard: the attacker's client side must complete. In TLS 1.3
        // the client finishes its flight before the server validates the
        // client cert, so this is Ok before and after the fix — ensuring the
        // handshake actually reached the client-auth stage.
        assert!(
            client_res.is_ok(),
            "handshake did not reach the client-auth stage: {:?}",
            client_res.err(),
        );
        assert!(
            server_res.is_err(),
            "VULNERABILITY: TlsAcceptor (build_quil_server_tls_config) completed the \
             handshake with a client that presented the victim's cert but signed \
             CertificateVerify with a different key — proof-of-possession is not \
             enforced, so the peer identity is spoofable by cert replay",
        );
    }

    /// Positive control: the SAME server must SUCCEED for a legitimate client
    /// that actually possesses its cert's key. Proves the forged test fails
    /// specifically because possession is missing — not because of ALPN, the
    /// duplex transport, or some other setup detail. Passes before and after
    /// the fix (all possession is legitimate).
    #[tokio::test]
    async fn acceptor_completes_handshake_with_legitimate_client() {
        let acceptor = TlsAcceptor::from(build_quil_server_tls_config(&[0x71u8; 57]).unwrap());

        // Legit client: presents its own cert signed with its own key.
        let seed = [0x61u8; 57];
        let tls = build_quil_tls_cert(&seed).unwrap();
        let key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut tls.key_pem.as_bytes())
                .unwrap()
                .unwrap();
        let client_cfg = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(XsignServerVerifier::new()))
            .with_client_auth_cert(cert_chain_from_seed(&seed), key)
            .unwrap();
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let (server_res, client_res) = tokio::join!(
            acceptor.accept(server_io),
            connector.connect(server_name, client_io),
        );

        // Nobody rejects here, so both sides must complete.
        assert!(
            client_res.is_ok(),
            "legitimate handshake must succeed (client side): {:?}",
            client_res.err(),
        );
        assert!(
            server_res.is_ok(),
            "legitimate handshake must succeed (server side): {:?}",
            server_res.err(),
        );
    }
}

//! Serialize + verify simplex FINALIZATION certificates for reward attribution
//! (task #61). A commonware‑simplex‑finalized app‑shard frame carries no BLS
//! aggregate signature in its header — its authenticity is the simplex quorum
//! certificate (`Finalization` = the finalized proposal + a Falcon
//! [`Certificate`](crate::falcon_scheme::Certificate) over it). To credit the
//! shard's work at the GLOBAL level, the archive re‑verifies that certificate
//! against the shard committee (the active provers' Falcon keys) and reads the
//! signer set from the cert's `Signers` bitmap.
//!
//! - [`encode_finalization`] serializes the `Finalization` for the coverage
//!   bundle (called on the finalize path, via the seam finalizer).
//! - [`verify_finalization`] rebuilds the committee verifier, decodes + verifies
//!   the cert, binds it to the frame identity digest, and returns the signing
//!   members' public keys (for reward distribution).

use commonware_codec::{Encode, Read};
use commonware_consensus::simplex::types::Finalization;
use commonware_cryptography::{certificate::Scheme as _, sha256::Digest as Sha256Digest};
use commonware_utils::ordered::{Quorum as _, Set};

use crate::falcon_base::FalconPublicKey;
use crate::falcon_simplex::SimplexFalconScheme;

/// The concrete finalization certificate type for Quilibrium consensus.
pub type AppFinalization = Finalization<SimplexFalconScheme, Sha256Digest>;

/// Discriminator prefixing a CW finalization cert when it rides in a frame
/// header's `public_key_signature_bls48581` field (which legacy frames used for
/// a BLS aggregate). Lets the global reward path tell a CW cert from a BLS agg.
pub const CW_CERT_MAGIC: &[u8] = b"CWCT";

/// Wrap a serialized finalization cert with [`CW_CERT_MAGIC`] for the header sig field.
pub fn wrap_cert_for_header(cert: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(CW_CERT_MAGIC.len() + cert.len());
    v.extend_from_slice(CW_CERT_MAGIC);
    v.extend_from_slice(cert);
    v
}

/// If `sig_field` carries a CW cert (magic prefix), return the raw cert bytes.
pub fn unwrap_cert_from_header(sig_field: &[u8]) -> Option<&[u8]> {
    sig_field.strip_prefix(CW_CERT_MAGIC)
}

/// Serialize a finalization certificate (proposal + Falcon cert) to bytes for
/// carrying in the coverage bundle.
pub fn encode_finalization(f: &AppFinalization) -> Vec<u8> {
    f.encode().to_vec()
}

/// Verify a serialized [`AppFinalization`] against a shard committee.
///
/// - `bytes`: the serialized finalization certificate.
/// - `committee_pubkeys`: the shard's committee members' Falcon public keys
///   (the active provers under the filter; any order — the `Set` sorts).
/// - `namespace`: the consensus domain, `b"appshard" ++ app_address`.
/// - `expected_digest`: `Poseidon(header.output)` — the frame identity the cert
///   must bind to.
///
/// Returns the public keys of the committee members that signed (a quorum, for
/// reward attribution), or `None` if the cert is malformed, below quorum, has a
/// bad signature, or does not bind to `expected_digest`.
pub fn verify_finalization(
    bytes: &[u8],
    committee_pubkeys: &[Vec<u8>],
    namespace: &[u8],
    expected_digest: [u8; 32],
) -> Option<Vec<Vec<u8>>> {
    // Rebuild the committee verifier (same Set every node builds — it sorts).
    let pks: Vec<FalconPublicKey> = committee_pubkeys
        .iter()
        .filter_map(|b| FalconPublicKey::from_bytes(b))
        .collect();
    if pks.is_empty() {
        return None;
    }
    let set: Set<FalconPublicKey> = pks.try_into().ok()?;
    let n = set.len();
    let scheme = SimplexFalconScheme::verifier(namespace, set);

    // Decode the finalization (cfg = committee size, bounds the Signers bitmap).
    let mut cursor: &[u8] = bytes;
    let f = <AppFinalization as Read>::read_cfg(&mut cursor, &n).ok()?;

    // Bind the certificate to the frame identity we are crediting.
    if f.proposal.payload != Sha256Digest(expected_digest) {
        return None;
    }

    // Verify quorum + every Falcon signature over the finalize subject.
    if !scheme.verify_finalization_cert(&f.proposal, &f.certificate) {
        return None;
    }

    // Read the signing members off the cert's `Signers` bitmap.
    let mut signers = Vec::with_capacity(f.certificate.signers.count());
    for idx in f.certificate.signers.iter() {
        if let Some(pk) = scheme.participants().key(idx) {
            signers.push(pk.as_ref().to_vec());
        }
    }
    Some(signers)
}

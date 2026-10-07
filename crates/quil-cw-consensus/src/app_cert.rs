//! Serialize + verify simplex FINALIZATION certificates for reward attribution.
//! A commonware‑simplex‑finalized app‑shard frame carries no BLS
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
use commonware_consensus::simplex::types::{Finalization, Proposal};
use commonware_cryptography::{certificate::Scheme as _, sha256::Digest as Sha256Digest};
use commonware_utils::ordered::{Quorum as _, Set};

use crate::falcon_base::FalconPublicKey;
use crate::falcon_simplex::SimplexFalconScheme;

/// The concrete finalization certificate type for Quilibrium consensus.
pub type AppFinalization = Finalization<SimplexFalconScheme, Sha256Digest>;

/// A verified certificate, retaining the consensus coordinates needed for
/// restart. An application frame number is not a Simplex view.
pub struct VerifiedFinalization {
    pub finalization: AppFinalization,
    pub signers: Vec<Vec<u8>>,
}

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

/// Read only the bounded proposal prefix to select a historical committee.
/// This is an UNAUTHENTICATED lookup hint. The caller must subsequently verify
/// the complete certificate with that committee, namespace, epoch and digest.
pub fn unverified_finalization_epoch(bytes: &[u8]) -> Option<u64> {
    if bytes.len() > crate::handoff::MAX_RECORD_BYTES {
        return None;
    }
    let proposal = Proposal::<Sha256Digest>::read_cfg(&mut &bytes[..], &()).ok()?;
    Some(proposal.round.epoch().get())
}

/// The size of the committee a certificate was signed under and how many of
/// its members signed, read from its `Signers` bitmap. UNAUTHENTICATED, for
/// diagnostics only: decoding against a rebuilt committee is bounded by that
/// committee's size, so a certificate signed under a larger committee fails as
/// [`CertError::Encoding`] without saying how large the signing committee was.
pub fn unverified_signers(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.len() > crate::handoff::MAX_RECORD_BYTES {
        return None;
    }
    let mut cursor = bytes;
    let f = <AppFinalization as Read>::read_cfg(&mut cursor, &crate::handoff::MAX_MEMBERS).ok()?;
    cursor.is_empty().then(|| (f.certificate.signers.len(), f.certificate.signers.count()))
}

/// Which of `candidates` produced the certificate's signatures: each
/// `(signer index in the signing committee, public key)` found. UNAUTHENTICATED,
/// for diagnostics: it names who signed a certificate whose committee cannot be
/// rebuilt, by checking every candidate key against every signature.
pub fn identify_signers(bytes: &[u8], namespace: &[u8], candidates: &[Vec<u8>]) -> Option<Vec<(u32, Vec<u8>)>> {
    use commonware_consensus::simplex::{scheme::Namespace as SimplexNamespace, types::Subject};
    use commonware_cryptography::certificate::{Namespace as _, Subject as _};
    use commonware_cryptography::Verifier as _;
    if bytes.len() > crate::handoff::MAX_RECORD_BYTES {
        return None;
    }
    let mut cursor = bytes;
    let f = <AppFinalization as Read>::read_cfg(&mut cursor, &crate::handoff::MAX_MEMBERS).ok()?;
    if !cursor.is_empty() {
        return None;
    }
    let base = SimplexNamespace::derive(namespace);
    let subject = Subject::Finalize { proposal: &f.proposal };
    let (namespace, message) = (subject.namespace(&base), subject.message());
    let keys: Vec<(FalconPublicKey, &Vec<u8>)> = candidates
        .iter()
        .filter_map(|bytes| FalconPublicKey::from_bytes(bytes).map(|key| (key, bytes)))
        .collect();
    let mut found = Vec::new();
    for (signer, signature) in f.certificate.signers.iter().zip(f.certificate.signatures.iter()) {
        let Some(signature) = signature.get() else { continue };
        if let Some((_, bytes)) = keys.iter().find(|(key, _)| key.verify(namespace, &message, signature)) {
            found.push((signer.get(), (*bytes).clone()));
        }
    }
    Some(found)
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
    verify_finalization_details(bytes, committee_pubkeys, namespace, expected_digest)
        .map(|verified| verified.signers)
}

/// Why a finalization certificate was not accepted. Every variant is a
/// rejection; they differ only in what an operator should look at. "Wrong
/// committee" and "bad signature" are indistinguishable to the verifier (both
/// fail the quorum check) and are reported together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertError {
    /// A committee key is not a Falcon public key, or the set is empty or has
    /// duplicates: the caller reconstructed the committee wrongly.
    Committee,
    /// The bytes do not decode as a certificate for a committee of this size,
    /// or carry trailing data.
    Encoding,
    /// The implicit-genesis view, or a parent at or after its own view.
    Coordinates,
    /// The certificate is for a different frame identity.
    Digest,
    /// Below quorum, signed by other keys, or signed in another namespace.
    Quorum,
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Committee => "malformed committee",
            Self::Encoding => "undecodable certificate",
            Self::Coordinates => "invalid view or parent",
            Self::Digest => "certificate is for another frame",
            Self::Quorum => "no valid quorum under this committee and namespace",
        })
    }
}

/// Verify a certificate and preserve its authenticated epoch, view and parent.
/// Callers installing a restart floor must also require the configured epoch.
pub fn verify_finalization_details(
    bytes: &[u8],
    committee_pubkeys: &[Vec<u8>],
    namespace: &[u8],
    expected_digest: [u8; 32],
) -> Option<VerifiedFinalization> {
    check_finalization(bytes, committee_pubkeys, namespace, expected_digest).ok()
}

/// [`verify_finalization_details`], saying which check refused the certificate.
pub fn check_finalization(
    bytes: &[u8],
    committee_pubkeys: &[Vec<u8>],
    namespace: &[u8],
    expected_digest: [u8; 32],
) -> Result<VerifiedFinalization, CertError> {
    // Rebuild the committee verifier (same Set every node builds — it sorts).
    let pks: Vec<FalconPublicKey> = committee_pubkeys
        .iter()
        .map(|b| FalconPublicKey::from_bytes(b))
        .collect::<Option<_>>()
        .ok_or(CertError::Committee)?;
    if pks.is_empty() {
        return Err(CertError::Committee);
    }
    let set: Set<FalconPublicKey> = pks.try_into().map_err(|_| CertError::Committee)?;
    let n = set.len();
    let scheme = SimplexFalconScheme::verifier(namespace, set);

    // Decode the finalization (cfg = committee size, bounds the Signers bitmap).
    let mut cursor: &[u8] = bytes;
    let f = <AppFinalization as Read>::read_cfg(&mut cursor, &n).map_err(|_| CertError::Encoding)?;
    if !cursor.is_empty() {
        return Err(CertError::Encoding);
    }
    if f.proposal.round.view().is_zero() || f.proposal.parent >= f.proposal.round.view() {
        return Err(CertError::Coordinates);
    }
    // Bind the certificate to the frame identity we are crediting.
    if f.proposal.payload != Sha256Digest(expected_digest) {
        return Err(CertError::Digest);
    }

    // Verify quorum + every Falcon signature over the finalize subject.
    if !scheme.verify_finalization_cert(&f.proposal, &f.certificate) {
        return Err(CertError::Quorum);
    }

    // Read the signing members off the cert's `Signers` bitmap.
    let mut signers = Vec::with_capacity(f.certificate.signers.count());
    for idx in f.certificate.signers.iter() {
        if let Some(pk) = scheme.participants().key(idx) {
            signers.push(pk.as_ref().to_vec());
        }
    }
    Ok(VerifiedFinalization {
        finalization: f,
        signers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::falcon_base::FalconPrivateKey;
    use commonware_consensus::{
        simplex::types::{Proposal, Subject},
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::Signer as _;
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_utils::N3f1;

    /// The certificate parsers over arbitrary bytes: a wrapped header field,
    /// the unverified epoch hint and the full check must return, never panic.
    #[test]
    fn certificate_parsers_survive_arbitrary_bytes() {
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || { x ^= x >> 12; x ^= x << 25; x ^= x >> 27; x.wrapping_mul(0x9e37_79b9_7f4a_7c15) };
        let member = FalconPrivateKey::random(commonware_utils::test_rng()).public_key().as_ref().to_vec();
        for i in 0..5_000u64 {
            let len = (next() % 700) as usize;
            let mut bytes: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if i % 2 == 0 {
                bytes = wrap_cert_for_header(&bytes);
            }
            let outcome = std::panic::catch_unwind(|| {
                let cert = unwrap_cert_from_header(&bytes).unwrap_or(&bytes);
                let _ = unverified_finalization_epoch(cert);
                let _ = check_finalization(cert, std::slice::from_ref(&member), b"appshard", [7; 32]);
                let _ = unverified_signers(cert);
                let _ = identify_signers(cert, b"appshard", std::slice::from_ref(&member));
            });
            assert!(outcome.is_ok(), "certificate parser panicked on {}", hex::encode(&bytes));
        }
    }

    #[test]
    fn verified_restart_certificate_retains_coordinates_and_rejects_ambiguous_inputs() {
        let keys: Vec<_> = (0..4)
            .map(|_| FalconPrivateKey::random(commonware_utils::test_rng()))
            .collect();
        let members: Vec<_> = keys.iter().map(|key| key.public_key()).collect();
        let set: Set<_> = members.clone().try_into().unwrap();
        let namespace = b"appshard/checkpoint-test";
        let schemes: Vec<_> = keys
            .into_iter()
            .map(|key| SimplexFalconScheme::signer(namespace, set.clone(), key).unwrap())
            .collect();
        let proposal = Proposal::new(
            Round::new(Epoch::new(7), View::new(43)),
            View::new(40),
            Sha256Digest([9; 32]),
        );
        let attestations: Vec<_> = schemes[..3]
            .iter()
            .map(|scheme| {
                scheme
                    .sign(Subject::Finalize {
                        proposal: &proposal,
                    })
                    .unwrap()
            })
            .collect();
        let finalization = AppFinalization {
            proposal,
            certificate: schemes[0]
                .assemble::<_, N3f1>(attestations, &Sequential)
                .unwrap(),
        };
        let member_bytes: Vec<Vec<u8>> = members.iter().map(|key| key.as_ref().to_vec()).collect();
        let bytes = encode_finalization(&finalization);
        assert_eq!(unverified_finalization_epoch(&bytes), Some(7));
        assert_eq!(unverified_finalization_epoch(&bytes[..2]), None);
        let prefix = finalization.proposal.encode().to_vec();
        assert_eq!(unverified_finalization_epoch(&prefix), Some(7));
        assert!(verify_finalization_details(&prefix, &member_bytes, namespace, [9; 32]).is_none(),
            "an epoch lookup hint is not a verified certificate");
        let verified =
            verify_finalization_details(&bytes, &member_bytes, namespace, [9; 32]).unwrap();
        assert_eq!(
            verified.finalization.proposal.round,
            finalization.proposal.round
        );
        assert_eq!(verified.finalization.proposal.parent, View::new(40));
        assert_eq!(verified.signers.len(), 3);
        assert_eq!(unverified_signers(&bytes), Some((4, 3)));
        assert_eq!(check_finalization(&bytes, &member_bytes[..3], namespace, [9; 32]).err(),
            Some(CertError::Encoding), "a smaller rebuilt committee cannot decode it");
        assert_eq!(unverified_signers(&prefix), None);
        let mut pool = member_bytes.clone();
        pool.push(FalconPrivateKey::random(commonware_utils::test_rng()).public_key().as_ref().to_vec());
        let named = identify_signers(&bytes, namespace, &pool).unwrap();
        let signed: Vec<u32> = finalization.certificate.signers.iter().map(|signer| signer.get()).collect();
        assert_eq!(named.iter().map(|(index, _)| *index).collect::<Vec<_>>(), signed, "every signer, by its index");
        for (index, key) in &named {
            assert_eq!(key, &set.key(commonware_utils::Participant::new(*index)).unwrap().as_ref().to_vec(), "signer {index}");
        }
        assert!(identify_signers(&bytes, b"other shard", &pool).unwrap().is_empty(), "the namespace binds each signature");
        assert!(
            crate::engine_host::GlobalEngineParams::new("test", 7, Sha256Digest([0; 32]))
                .with_finalized_floor(verified.finalization)
                .is_ok()
        );
        assert!(
            crate::engine_host::GlobalEngineParams::new("test", 8, Sha256Digest([0; 32]))
                .with_finalized_floor(finalization.clone())
                .is_err()
        );
        assert!(
            verify_finalization_details(&bytes, &member_bytes, b"other shard", [9; 32]).is_none()
        );
        assert!(verify_finalization_details(&bytes, &member_bytes, namespace, [8; 32]).is_none());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(
            verify_finalization_details(&trailing, &member_bytes, namespace, [9; 32]).is_none()
        );
        let mut malformed = member_bytes.clone();
        malformed.push(vec![1]);
        assert!(
            verify_finalization_details(&bytes, &malformed, namespace, [9; 32]).is_none(),
            "a malformed committee entry must not be silently removed"
        );
        let mut noncausal = finalization.clone();
        noncausal.proposal.parent = View::new(43);
        let votes: Vec<_> = schemes[..3].iter().map(|scheme| {
            scheme.sign(Subject::Finalize { proposal: &noncausal.proposal }).unwrap()
        }).collect();
        noncausal.certificate = schemes[0].assemble::<_, N3f1>(votes, &Sequential).unwrap();
        assert!(verify_finalization_details(&encode_finalization(&noncausal), &member_bytes, namespace, [9; 32]).is_none(),
            "even a signed quorum cannot name its own view as parent");
        let mut changed = finalization;
        changed.proposal.round = Round::new(Epoch::new(8), View::new(43));
        assert!(verify_finalization_details(
            &encode_finalization(&changed),
            &member_bytes,
            namespace,
            [9; 32]
        )
        .is_none());
    }
}

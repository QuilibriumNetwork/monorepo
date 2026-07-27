//! Falcon-512 `certificate::Scheme` for commonware consensus (equal votes).
//!
//! This is the multi-party layer on top of `falcon_base`: it produces
//! per-participant attestations, verifies them, and assembles / verifies
//! **certificates** (a `Signers` bitmap + one Falcon signature per contributing
//! participant). It is modeled on commonware's own scheme templates:
//!
//! * structure (single key used for both identity and signing, `Set<PublicKey>`)
//! follows **ed25519**'s `Generic<N>`;
//! * verification is **non-batchable** (Falcon has no random-linear-combination
//! batch verify), so the verify bodies follow **secp256r1**'s one-by-one form
//! and `is_batchable()` returns `false`.
//!
//! Equal votes: quorum is the plain count-based `Set::quorum::<M>()` (floor(2N/3)+1
//! for `N3f1`), identical for every participant — no seniority weighting.

use crate::falcon_base::{FalconPrivateKey, FalconPublicKey, FalconSignature};
use bytes::{Buf, BufMut};
use commonware_codec::{
    types::lazy::Lazy, EncodeSize, Error as CodecError, Read, ReadRangeExt, Write,
};
use commonware_cryptography::{
    certificate::{Attestation, Namespace, Scheme, Signers, Subject, Verification},
    Digest, Signer as _, Verifier as _,
};
use commonware_parallel::Strategy;
use commonware_utils::{
    ordered::{Quorum, Set},
    Faults, Participant,
};
use rand_core::CryptoRng;
use std::collections::BTreeSet;

/// Generic Falcon signing scheme (protocol-agnostic core).
#[derive(Clone, Debug)]
pub struct Generic<N: Namespace> {
    participants: Set<FalconPublicKey>,
    signer: Option<(Participant, FalconPrivateKey)>,
    namespace: N,
}

impl<N: Namespace> Generic<N> {
    /// Build a signing instance if `private_key` is in the participant set.
    pub fn signer(
        namespace: &[u8],
        participants: Set<FalconPublicKey>,
        private_key: FalconPrivateKey,
    ) -> Option<Self> {
        let index = participants.index(&private_key.public_key())?;
        Some(Self {
            participants,
            signer: Some((index, private_key)),
            namespace: N::derive(namespace),
        })
    }

    /// Build a verify-only instance.
    pub fn verifier(namespace: &[u8], participants: Set<FalconPublicKey>) -> Self {
        Self {
            participants,
            signer: None,
            namespace: N::derive(namespace),
        }
    }

    pub fn me(&self) -> Option<Participant> {
        self.signer.as_ref().map(|(i, _)| *i)
    }

    pub fn participants(&self) -> &Set<FalconPublicKey> {
        &self.participants
    }

    pub fn sign<'a, S, D>(&self, subject: S::Subject<'a, D>) -> Option<Attestation<S>>
    where
        S: Scheme<Signature = FalconSignature>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
    {
        let (index, private_key) = self.signer.as_ref()?;
        let signature = private_key.sign(subject.namespace(&self.namespace), &subject.message());
        Some(Attestation {
            signer: *index,
            signature: signature.into(),
        })
    }

    pub fn verify_attestation<'a, S, D>(
        &self,
        subject: S::Subject<'a, D>,
        attestation: &Attestation<S>,
    ) -> bool
    where
        S: Scheme<Signature = FalconSignature>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
    {
        let Some(public_key) = self.participants.key(attestation.signer) else {
            return false;
        };
        let Some(signature) = attestation.signature.get() else {
            return false;
        };
        public_key.verify(subject.namespace(&self.namespace), &subject.message(), signature)
    }

    pub fn verify_attestations<'a, S, D, I>(
        &self,
        subject: S::Subject<'a, D>,
        attestations: I,
    ) -> Verification<S>
    where
        S: Scheme<Signature = FalconSignature>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
        I: IntoIterator<Item = Attestation<S>>,
    {
        let namespace = subject.namespace(&self.namespace);
        let message = subject.message();
        let mut invalid = BTreeSet::new();
        let mut verified = Vec::new();
        for attestation in attestations {
            let Some(public_key) = self.participants.key(attestation.signer) else {
                invalid.insert(attestation.signer);
                continue;
            };
            let Some(signature) = attestation.signature.get() else {
                invalid.insert(attestation.signer);
                continue;
            };
            if public_key.verify(namespace, &message, signature) {
                verified.push(attestation);
            } else {
                invalid.insert(attestation.signer);
            }
        }
        Verification::new(verified, invalid.into_iter().collect())
    }

    pub fn assemble<S, I, M>(&self, attestations: I) -> Option<Certificate>
    where
        S: Scheme<Signature = FalconSignature>,
        I: IntoIterator<Item = Attestation<S>>,
        M: Faults,
    {
        let mut entries = Vec::new();
        for Attestation { signer, signature } in attestations {
            if usize::from(signer) >= self.participants.len() {
                return None;
            }
            let signature = signature.get().cloned()?;
            entries.push((signer, signature));
        }
        if entries.len() < self.participants.quorum::<M>() as usize {
            return None;
        }
        entries.sort_by_key(|(signer, _)| *signer);
        let (signer, signatures): (Vec<Participant>, Vec<_>) = entries.into_iter().unzip();
        let signers = Signers::from(self.participants.len(), signer);
        let signatures = signatures.into_iter().map(Lazy::from).collect();
        Some(Certificate { signers, signatures })
    }

    pub fn verify_certificate<'a, S, D, M>(
        &self,
        subject: S::Subject<'a, D>,
        certificate: &Certificate,
    ) -> bool
    where
        S: Scheme<Signature = FalconSignature>,
        S::Subject<'a, D>: Subject<Namespace = N>,
        D: Digest,
        M: Faults,
    {
        if certificate.signers.len() != self.participants.len() {
            return false;
        }
        if certificate.signers.count() != certificate.signatures.len() {
            return false;
        }
        if certificate.signers.count() < self.participants.quorum::<M>() as usize {
            return false;
        }
        let namespace = subject.namespace(&self.namespace);
        let message = subject.message();
        for (signer, signature) in certificate.signers.iter().zip(&certificate.signatures) {
            let Some(public_key) = self.participants.key(signer) else {
                return false;
            };
            let Some(signature) = signature.get() else {
                return false;
            };
            if !public_key.verify(namespace, &message, signature) {
                return false;
            }
        }
        true
    }

    pub const fn is_attributable() -> bool {
        true
    }
    pub const fn is_batchable() -> bool {
        false
    }
    pub const fn certificate_codec_config(&self) -> usize {
        self.participants.len()
    }
    pub const fn certificate_codec_config_unbounded() -> usize {
        u32::MAX as usize
    }
}

/// A Falcon quorum certificate: which participants signed + their signatures.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate {
    pub signers: Signers,
    pub signatures: Vec<Lazy<FalconSignature>>,
}

impl Write for Certificate {
    fn write(&self, writer: &mut impl BufMut) {
        self.signers.write(writer);
        self.signatures.write(writer);
    }
}

impl EncodeSize for Certificate {
    fn encode_size(&self) -> usize {
        self.signers.encode_size() + self.signatures.encode_size()
    }
}

impl Read for Certificate {
    type Cfg = usize;

    fn read_cfg(reader: &mut impl Buf, participants: &usize) -> Result<Self, CodecError> {
        let signers = Signers::read_cfg(reader, participants)?;
        if signers.count() == 0 {
            return Err(CodecError::Invalid(
                "cw_spike::falcon_scheme::Certificate",
                "Certificate contains no signers",
            ));
        }
        let signatures = Vec::<Lazy<FalconSignature>>::read_range(reader, ..=*participants)?;
        if signers.count() != signatures.len() {
            return Err(CodecError::Invalid(
                "cw_spike::falcon_scheme::Certificate",
                "Signers and signatures counts differ",
            ));
        }
        Ok(Self { signers, signatures })
    }
}

// ------------------------------------------------------------------
// Concrete scheme bound to a subject type (what simplex will instantiate).
// A generic `Subject` carries its own namespace; for the spike we use a
// minimal test subject with a `Vec<u8>` namespace.
// ------------------------------------------------------------------

/// Falcon scheme wrapper for a concrete subject `$subject` / namespace `$ns`.
#[derive(Clone, Debug)]
pub struct FalconCertScheme {
    generic: Generic<Vec<u8>>,
}

impl FalconCertScheme {
    pub fn signer(
        namespace: &[u8],
        participants: Set<FalconPublicKey>,
        private_key: FalconPrivateKey,
    ) -> Option<Self> {
        Some(Self {
            generic: Generic::signer(namespace, participants, private_key)?,
        })
    }
    pub fn verifier(namespace: &[u8], participants: Set<FalconPublicKey>) -> Self {
        Self {
            generic: Generic::verifier(namespace, participants),
        }
    }
}

impl commonware_cryptography::certificate::Verifier for FalconCertScheme {
    type Subject<'a, D: Digest> = TestSubject;
    type PublicKey = FalconPublicKey;
    type Certificate = Certificate;

    fn verify_certificate<R, D, M>(
        &self,
        _rng: &mut R,
        subject: Self::Subject<'_, D>,
        certificate: &Self::Certificate,
        _strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest,
        M: Faults,
    {
        self.generic.verify_certificate::<Self, D, M>(subject, certificate)
    }

    fn verify_certificates<'a, R, D, I, M>(
        &self,
        _rng: &mut R,
        certificates: I,
        _strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest,
        I: Iterator<Item = (Self::Subject<'a, D>, &'a Self::Certificate)>,
        M: Faults,
    {
        for (subject, certificate) in certificates {
            if !self.generic.verify_certificate::<Self, D, M>(subject, certificate) {
                return false;
            }
        }
        true
    }

    fn is_batchable() -> bool {
        Generic::<Vec<u8>>::is_batchable()
    }

    fn certificate_codec_config(&self) -> usize {
        self.generic.certificate_codec_config()
    }

    fn certificate_codec_config_unbounded() -> usize {
        Generic::<Vec<u8>>::certificate_codec_config_unbounded()
    }
}

impl Scheme for FalconCertScheme {
    type Signature = FalconSignature;

    fn me(&self) -> Option<Participant> {
        self.generic.me()
    }

    fn participants(&self) -> &Set<Self::PublicKey> {
        self.generic.participants()
    }

    fn sign<D: Digest>(&self, subject: Self::Subject<'_, D>) -> Option<Attestation<Self>> {
        self.generic.sign::<Self, D>(subject)
    }

    fn verify_attestation<R, D>(
        &self,
        _rng: &mut R,
        subject: Self::Subject<'_, D>,
        attestation: &Attestation<Self>,
        _strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRng,
        D: Digest,
    {
        self.generic.verify_attestation::<Self, D>(subject, attestation)
    }

    fn verify_attestations<R, D, I>(
        &self,
        _rng: &mut R,
        subject: Self::Subject<'_, D>,
        attestations: I,
        _strategy: &impl Strategy,
    ) -> Verification<Self>
    where
        R: CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: Send,
    {
        self.generic.verify_attestations::<Self, D, _>(subject, attestations)
    }

    fn assemble<I, M>(&self, attestations: I, _strategy: &impl Strategy) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: Send,
        M: Faults,
    {
        self.generic.assemble::<Self, _, M>(attestations)
    }

    fn is_attributable() -> bool {
        Generic::<Vec<u8>>::is_attributable()
    }
}

/// Minimal subject for the spike round-trip (namespace `Vec<u8>`, opaque message).
#[derive(Clone, Debug)]
pub struct TestSubject {
    pub message: bytes::Bytes,
}

impl Subject for TestSubject {
    type Namespace = Vec<u8>;
    fn namespace<'a>(&self, derived: &'a Self::Namespace) -> &'a [u8] {
        derived.as_ref()
    }
    fn message(&self) -> bytes::Bytes {
        self.message.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::certificate::{Scheme as _, Verifier as _};
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, N3f1, TryCollect};

    const NAMESPACE: &[u8] = b"global";

    fn setup(n: u32) -> Vec<FalconCertScheme> {
        let sks: Vec<_> = (0..n).map(|_| FalconPrivateKey::random(test_rng())).collect();
        let participants: Set<FalconPublicKey> =
            sks.iter().map(|sk| sk.public_key()).try_collect().unwrap();
        sks.into_iter()
            .map(|sk| FalconCertScheme::signer(NAMESPACE, participants.clone(), sk).unwrap())
            .collect()
    }

    fn subject() -> TestSubject {
        TestSubject { message: bytes::Bytes::from_static(b"state_id|rank") }
    }

    #[test]
    fn attributable_and_not_batchable() {
        assert!(FalconCertScheme::is_attributable());
        assert!(!FalconCertScheme::is_batchable());
    }

    #[test]
    fn attestation_roundtrip() {
        let schemes = setup(4);
        let mut rng = test_rng();
        let att = schemes[0].sign::<Sha256Digest>(subject()).unwrap();
        assert!(schemes[0].verify_attestation::<_, Sha256Digest>(
            &mut rng,
            subject(),
            &att,
            &Sequential
        ));
    }

    #[test]
    fn certificate_quorum_roundtrip() {
        let schemes = setup(4); // N=4 → N3f1 quorum = floor(2*4/3)+1 = 3
        let mut rng = test_rng();

        // Collect 3 attestations (a quorum) and assemble.
        let atts: Vec<_> = schemes[..3]
            .iter()
            .map(|s| s.sign::<Sha256Digest>(subject()).unwrap())
            .collect();
        let cert = schemes[0].assemble::<_, N3f1>(atts, &Sequential).unwrap();
        assert!(schemes[0].verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            subject(),
            &cert,
            &Sequential
        ));

        // A tampered message must fail verification.
        let other = TestSubject { message: bytes::Bytes::from_static(b"different") };
        assert!(!schemes[0].verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            other,
            &cert,
            &Sequential
        ));
    }

    #[test]
    fn below_quorum_does_not_assemble() {
        let schemes = setup(4);
        // Only 2 attestations — below the quorum of 3.
        let atts: Vec<_> = schemes[..2]
            .iter()
            .map(|s| s.sign::<Sha256Digest>(subject()).unwrap())
            .collect();
        assert!(schemes[0].assemble::<_, N3f1>(atts, &Sequential).is_none());
    }

    #[test]
    fn certificate_codec_roundtrip() {
        use commonware_codec::Encode;
        let schemes = setup(4);
        let atts: Vec<_> = schemes[..3]
            .iter()
            .map(|s| s.sign::<Sha256Digest>(subject()).unwrap())
            .collect();
        let cert = schemes[0].assemble::<_, N3f1>(atts, &Sequential).unwrap();
        let mut buf = cert.encode();
        let cert2 = Certificate::read_cfg(&mut buf, &4usize).unwrap();
        assert_eq!(cert, cert2);
    }
}

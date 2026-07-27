//! Bind the Falcon `certificate::Scheme` to commonware **simplex**'s subject.
//!
//! `simplex`'s `Engine` is generic over `S: simplex::scheme::Scheme<D>`, which
//! is auto-implemented for any `certificate::Scheme` whose GAT
//! `Subject<'a, D> == simplex::types::Subject<'a, D>` (the notarize/nullify/
//! finalize vote subject, whose `Namespace` is `simplex::scheme::Namespace`).
//!
//! The generic Falcon `Generic<N>` in `falcon_scheme` is already parametric over
//! the namespace, so binding it to simplex is just: `N = simplex::scheme::Namespace`
//! and `Subject<'a, D> = simplex::types::Subject<'a, D>`. If the compile-time
//! assertion at the bottom holds, a simplex `Engine` can be instantiated with
//! Falcon signatures — the decisive integration gate for the migration.

use crate::falcon_base::{FalconPrivateKey, FalconPublicKey, FalconSignature};
use crate::falcon_scheme::{Certificate, Generic};
use commonware_consensus::simplex::{
    scheme::Namespace as SimplexNamespace,
    types::{Proposal, Subject},
};
use commonware_cryptography::{
    certificate::{Attestation, Scheme, Verification, Verifier},
    Digest,
};
use commonware_parallel::Strategy;
use commonware_utils::{ordered::Set, Faults, Participant};
use rand_core::CryptoRng;

/// Falcon scheme bound to simplex's vote subject — instantiable in `simplex::Engine`.
#[derive(Clone, Debug)]
pub struct SimplexFalconScheme {
    generic: Generic<SimplexNamespace>,
}

impl SimplexFalconScheme {
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

    /// Verify a FINALIZATION certificate over `proposal` against this committee.
    /// No rng needed — Falcon verify is deterministic (non‑batchable). Used for
    /// off‑engine cert verification (reward attribution at the global level),
    /// where simplex's `Finalization::verify` rng/strategy plumbing isn't handy.
    /// Checks count == committee size, quorum `floor(2N/3)+1`, and every sig.
    pub fn verify_finalization_cert<D: Digest>(
        &self,
        proposal: &Proposal<D>,
        cert: &Certificate,
    ) -> bool {
        self.generic
            .verify_certificate::<Self, D, commonware_utils::N3f1>(
                Subject::Finalize { proposal },
                cert,
            )
    }
}

impl Verifier for SimplexFalconScheme {
    type Subject<'a, D: Digest> = Subject<'a, D>;
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
        Generic::<SimplexNamespace>::is_batchable()
    }
    fn certificate_codec_config(&self) -> usize {
        self.generic.certificate_codec_config()
    }
    fn certificate_codec_config_unbounded() -> usize {
        Generic::<SimplexNamespace>::certificate_codec_config_unbounded()
    }
}

impl Scheme for SimplexFalconScheme {
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
        Generic::<SimplexNamespace>::is_attributable()
    }
}

/// COMPILE-TIME PROOF: `SimplexFalconScheme` satisfies simplex's `Scheme<D>`
/// marker, so `simplex::Engine` can be instantiated with Falcon signatures.
/// If this function type-checks, the integration gate is passed.
#[allow(dead_code)]
fn _assert_simplex_compatible<D: Digest>()
where
    SimplexFalconScheme: commonware_consensus::simplex::scheme::Scheme<D>,
{
}

#[allow(dead_code)]
fn _instantiate_the_assertion() {
    _assert_simplex_compatible::<commonware_cryptography::sha256::Digest>();
}

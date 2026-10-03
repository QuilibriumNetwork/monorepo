//! Falcon-512 base cryptography types for commonware.
//!
//! These implement commonware's foundational crypto traits
//! (`Signature`, `PublicKey`/`Verifier`, `Signer`/`Random`) over Quilibrium's
//! Falcon-512 (FN-DSA) primitives. The `certificate::Scheme` (built on top of
//! these) lives in `falcon_scheme.rs`.
//!
//! ## Domain-separation reconciliation
//!
//! commonware's whole crypto surface carries domain separation in the
//! **namespace prefix**: `Signer::sign(namespace, msg)` /
//! `Verifier::verify(namespace, msg, sig)` internally form
//! `union_unique(namespace, msg)` (a length-prefixed concatenation) and sign
//! *that* — exactly how ed25519/secp256r1 do it (no signer-level domain).
//!
//! Quilibrium's `falcon_verify(pk, sig, msg, domain)` instead threads the
//! consensus domain (`b"global"` / `b"globaltimeout"`) through FN-DSA's
//! `DomainContext`. To fit commonware's model without changing its callers we
//! push that separation into the **namespace** and pass an **empty**
//! `DomainContext` to fn-dsa. So the consensus domains become the commonware
//! `namespace` argument, and the payload actually signed is
//! `union_unique(namespace, msg)`. This is behaviourally identical to
//! secp256r1's `sign_inner(Some(namespace), msg)`.

use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_math::algebra::Random;
use commonware_utils::{union_unique, Array, Span};
use core::ops::Deref;
use quil_crypto::{
    falcon_verify, FalconSigner, FALCON_PUBLIC_KEY_LEN, FALCON_SIGNATURE_LEN,
};
use quil_types::crypto::Signer as QuilSigner;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

/// Boilerplate: turn a fixed-length `[u8; N]` newtype into a commonware `Array`
/// (the supertrait bundle `Signature`/`PublicKey` require) — mirrors the manual
/// impls on `commonware_utils::sequence::FixedBytes`.
macro_rules! byte_array_newtype {
    ($name:ident, $len:expr) => {
        impl Write for $name {
            fn write(&self, buf: &mut impl BufMut) {
                self.0.write(buf);
            }
        }
        impl Read for $name {
            type Cfg = ();
            fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
                Ok(Self(<[u8; $len]>::read(buf)?))
            }
        }
        impl FixedSize for $name {
            const SIZE: usize = $len;
        }
        impl Span for $name {}
        impl Array for $name {}
        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
        impl Deref for $name {
            type Target = [u8];
            fn deref(&self) -> &[u8] {
                &self.0
            }
        }
        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                for b in &self.0 {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }
    };
}

/// Falcon-512 signature (666 bytes).
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[repr(transparent)]
pub struct FalconSignature([u8; FALCON_SIGNATURE_LEN]);

byte_array_newtype!(FalconSignature, FALCON_SIGNATURE_LEN);
impl commonware_cryptography::Signature for FalconSignature {}

/// Falcon-512 public (verifying) key (897 bytes).
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[repr(transparent)]
pub struct FalconPublicKey([u8; FALCON_PUBLIC_KEY_LEN]);

byte_array_newtype!(FalconPublicKey, FALCON_PUBLIC_KEY_LEN);

impl FalconPublicKey {
    /// Build from raw 897-byte Falcon public-key bytes (e.g. a committee
    /// member's `q-consensus-key` pubkey). Returns `None` on wrong length.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let arr: [u8; FALCON_PUBLIC_KEY_LEN] = bytes.try_into().ok()?;
        Some(Self(arr))
    }
}

impl commonware_cryptography::Verifier for FalconPublicKey {
    type Signature = FalconSignature;

    fn verify(&self, namespace: &[u8], msg: &[u8], sig: &Self::Signature) -> bool {
        // Domain separation via the namespace prefix; empty FN-DSA context.
        let payload = union_unique(namespace, msg);
        falcon_verify(&self.0, &sig.0, &payload, &[])
    }
}

impl commonware_cryptography::PublicKey for FalconPublicKey {}

/// Bounded, insertion-ordered signature cache. Falcon (FN-DSA) signing is
/// NON-DETERMINISTIC — the Gaussian sampler draws fresh randomness, so signing
/// the SAME message twice yields DIFFERENT bytes. commonware-simplex re-signs a
/// vote on every rebroadcast and compares two votes from the same signer by
/// their full attestation (signature) bytes (`Nullify::eq` etc.); a re-signed
/// nullify/notarize/finalize therefore looks like a CONFLICTING vote, trips
/// equivocation detection (`batcher/round.rs` "conflicting nullify") and gets the
/// honest peer BLOCKED. Caching the first signature per signed payload and
/// returning it verbatim on re-sign makes rebroadcasts byte-identical — the
/// behaviour commonware assumes for deterministic BLS/ed25519.
struct SigCache {
    map: HashMap<Vec<u8>, FalconSignature>,
    order: VecDeque<Vec<u8>>,
}

/// Enough for every in-flight view's votes (notarize/nullify/finalize across the
/// handful of concurrently-active rounds) many times over; oldest-evicted.
const SIG_CACHE_CAP: usize = 4096;

impl SigCache {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }
}

/// Falcon-512 private key. Holds the encoded signing key (1281 B) alongside the
/// public key (897 B) so `public_key()` is free.
#[derive(Clone)]
pub struct FalconPrivateKey {
    signing_key: Vec<u8>,
    public_key: [u8; FALCON_PUBLIC_KEY_LEN],
    /// Shared across clones (commonware clones the signer): a re-sign of an
    /// already-signed payload returns the SAME cached signature. See [`SigCache`].
    sig_cache: Arc<Mutex<SigCache>>,
}

impl core::fmt::Debug for FalconPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print the secret signing key.
        f.debug_struct("FalconPrivateKey")
            .field("signing_key", &"<redacted>")
            .field("public_key", &FalconPublicKey(self.public_key))
            .finish()
    }
}

impl FalconPrivateKey {
    /// Wrap existing key bytes (e.g. loaded from the node's key store).
    pub fn from_bytes(signing_key: &[u8], public_key: &[u8]) -> Option<Self> {
        let pk: [u8; FALCON_PUBLIC_KEY_LEN] = public_key.try_into().ok()?;
        Some(Self {
            signing_key: signing_key.to_vec(),
            public_key: pk,
            sig_cache: Arc::new(Mutex::new(SigCache::new())),
        })
    }
}

impl Random for FalconPrivateKey {
    fn random(_rng: impl rand_core::CryptoRng) -> Self {
        // NOTE: FN-DSA keygen needs an `RngCore` from fn-dsa's own rand_core
        // version, which differs from commonware's; rather than bridge two
        // rand_core majors we generate from OS entropy here. The consequence is
        // that `Signer::from_seed` (documented test/example-only) is not
        // deterministic — production keys come from `from_bytes` or fresh OS
        // entropy, both of which are correct.
        let signer = FalconSigner::generate();
        let pk: [u8; FALCON_PUBLIC_KEY_LEN] = signer
            .public_key()
            .try_into()
            .expect("fn-dsa public key is FALCON_PUBLIC_KEY_LEN");
        Self {
            signing_key: signer.private_key().to_vec(),
            public_key: pk,
            sig_cache: Arc::new(Mutex::new(SigCache::new())),
        }
    }
}

impl commonware_cryptography::Signer for FalconPrivateKey {
    type Signature = FalconSignature;
    type PublicKey = FalconPublicKey;

    fn public_key(&self) -> Self::PublicKey {
        FalconPublicKey(self.public_key)
    }

    fn sign(&self, namespace: &[u8], msg: &[u8]) -> Self::Signature {
        // Mirror `Verifier::verify`: separation via namespace, empty context.
        let payload = union_unique(namespace, msg);
        // NEVER produce a second signature for a payload we've already signed —
        // Falcon is non-deterministic, so a fresh signature over the SAME vote
        // reads as an equivocation to commonware and blocks us (see [`SigCache`]).
        // Hold the lock across signing so a concurrent re-sign of the same
        // payload can't race in a distinct signature.
        let mut cache = self.sig_cache.lock().expect("sig cache poisoned");
        if let Some(sig) = cache.map.get(&payload) {
            return sig.clone();
        }
        let signer = FalconSigner::from_bytes(&self.signing_key, &self.public_key);
        let sig = signer
            .sign_with_domain(&payload, &[])
            .expect("falcon signing over a valid key never fails");
        let arr: [u8; FALCON_SIGNATURE_LEN] = sig
            .try_into()
            .expect("fn-dsa signature is FALCON_SIGNATURE_LEN");
        let fsig = FalconSignature(arr);
        cache.map.insert(payload.clone(), fsig.clone());
        cache.order.push_back(payload);
        if cache.order.len() > SIG_CACHE_CAP {
            if let Some(old) = cache.order.pop_front() {
                cache.map.remove(&old);
            }
        }
        fsig
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer, Verifier};
    use commonware_utils::test_rng;

    #[test]
    fn sign_verify_roundtrip_via_commonware_traits() {
        let sk = FalconPrivateKey::random(test_rng());
        let pk = sk.public_key();
        let ns = b"global";
        let msg = b"filter|state_id|rank";

        let sig = sk.sign(ns, msg);
        assert!(pk.verify(ns, msg, &sig));

        // Wrong namespace (domain separation) must fail.
        assert!(!pk.verify(b"globaltimeout", msg, &sig));
        // Wrong message must fail.
        assert!(!pk.verify(ns, b"tampered", &sig));
    }

    #[test]
    fn resigning_same_payload_returns_identical_bytes() {
        // Falcon signing is non-deterministic, so WITHOUT the cache two signs of
        // the same payload differ — which commonware reads as an equivocation
        // ("conflicting nullify") and blocks the peer. The cache must make a
        // re-sign byte-identical (as a deterministic scheme would be).
        let sk = FalconPrivateKey::random(test_rng());
        let ns = b"global";
        let msg = b"view-7-nullify";
        let a = sk.sign(ns, msg);
        let b = sk.sign(ns, msg);
        assert_eq!(a, b, "re-sign of the same payload must return the cached signature");
        // A clone shares the cache (commonware clones the signer).
        let b2 = sk.clone().sign(ns, msg);
        assert_eq!(a, b2, "cache is shared across clones");
        // A DIFFERENT payload still gets its own (valid) signature.
        let c = sk.sign(ns, b"view-8-nullify");
        assert_ne!(a, c);
        assert!(sk.public_key().verify(ns, b"view-8-nullify", &c));
    }

    #[test]
    fn codec_roundtrip() {
        use commonware_codec::{DecodeExt, Encode};
        let sk = FalconPrivateKey::random(test_rng());
        let pk = sk.public_key();
        let sig = sk.sign(b"d", b"m");

        let pk2 = FalconPublicKey::decode(pk.encode()).unwrap();
        let sig2 = FalconSignature::decode(sig.encode()).unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(sig, sig2);
        assert!(pk2.verify(b"d", b"m", &sig2));
    }
}

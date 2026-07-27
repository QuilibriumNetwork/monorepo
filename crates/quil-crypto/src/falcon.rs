//! Falcon / FN-DSA-512 post-quantum signatures for consensus.
//!
//! replaces the BLS48-581 signature primitive on
//! the consensus path (votes, timeouts, quorum-cert shares, frame-header sigs,
//! prover-join PoP) with Falcon. Unlike BLS, Falcon does **not** aggregate — a
//! quorum certificate becomes a list of individual Falcon sigs + a signer
//! bitmask (handled by the consensus adapter in `quil-engine`); this module is
//! just the sign/verify primitive, mirroring the [`Signer`] interface the
//! `Bls48581Signer` implemented so it is a drop-in at that seam.
//!
//! Falcon-512 sizes: signing key 1281 B, public (verifying) key 897 B,
//! signature 666 B. Verify is CPU-fast and constant-time; the floating-point
//! risk is confined to signing. Backed by Pornin's `fn-dsa` crate (the same one
//! used for Falcon peer identities in `libp2p-identity`).

use fn_dsa::{
    signature_size, sign_key_size, vrfy_key_size, DomainContext, KeyPairGenerator,
    KeyPairGeneratorStandard, SigningKey, SigningKeyStandard, VerifyingKey,
    VerifyingKeyStandard, FN_DSA_LOGN_512, HASH_ID_RAW,
};

use quil_types::crypto::{BlsAggregateOutput, BlsConstructor, KeyType, Signer};
use quil_types::error::{QuilError, Result};

/// FN-DSA degree used everywhere: Falcon-512.
const LOGN: u32 = FN_DSA_LOGN_512;

/// Encoded signing-key length (1281 bytes).
pub const FALCON_SIGNING_KEY_LEN: usize = sign_key_size(FN_DSA_LOGN_512);
/// Encoded public (verifying) key length (897 bytes).
pub const FALCON_PUBLIC_KEY_LEN: usize = vrfy_key_size(FN_DSA_LOGN_512);
/// Signature length (666 bytes).
pub const FALCON_SIGNATURE_LEN: usize = signature_size(FN_DSA_LOGN_512);

/// A Falcon-512 signer.
pub struct FalconSigner {
    signing_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl FalconSigner {
    /// Generate a fresh Falcon-512 keypair.
    pub fn generate() -> Self {
        let mut kg = KeyPairGeneratorStandard::default();
        let mut signing_key = vec![0u8; sign_key_size(LOGN)];
        let mut public_key = vec![0u8; vrfy_key_size(LOGN)];
        kg.keygen(LOGN, &mut rand::rngs::OsRng, &mut signing_key, &mut public_key);
        Self {
            signing_key,
            public_key,
        }
    }

    /// Wrap existing key bytes.
    pub fn from_bytes(signing_key: &[u8], public_key: &[u8]) -> Self {
        Self {
            signing_key: signing_key.to_vec(),
            public_key: public_key.to_vec(),
        }
    }
}

impl Signer for FalconSigner {
    fn key_type(&self) -> KeyType {
        KeyType::Falcon512
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn private_key(&self) -> &[u8] {
        &self.signing_key
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.sign_with_domain(message, &[])
    }

    fn sign_with_domain(&self, message: &[u8], domain: &[u8]) -> Result<Vec<u8>> {
        let mut sk = SigningKeyStandard::decode(&self.signing_key)
            .ok_or_else(|| QuilError::Crypto("falcon signing key decode failed".into()))?;
        let mut sig = vec![0u8; signature_size(sk.get_logn())];
        // The consensus `domain` (b"global" / b"globaltimeout" / …) becomes the
        // FN-DSA domain-separation context, so a signature valid under one
        // domain never verifies under another.
        sk.sign(
            &mut rand::rngs::OsRng,
            &DomainContext(domain),
            &HASH_ID_RAW,
            message,
            &mut sig,
        );
        Ok(sig)
    }
}

/// Verify a Falcon-512 signature. Rejects wrong-length inputs up front (defence
/// in depth — `fn-dsa`'s `decode` already returns `None` rather than panicking
/// on malformed bytes, but a peer-supplied pk/sig should never even reach the
/// decoder mis-sized).
pub fn falcon_verify(public_key: &[u8], signature: &[u8], message: &[u8], domain: &[u8]) -> bool {
    if public_key.len() != FALCON_PUBLIC_KEY_LEN || signature.len() != FALCON_SIGNATURE_LEN {
        return false;
    }
    match VerifyingKeyStandard::decode(public_key) {
        Some(vk) => vk.verify(signature, &DomainContext(domain), &HASH_ID_RAW, message),
        None => false,
    }
}

/// Recompute the 897-byte Falcon public key from a 1281-byte signing key.
/// Returns `None` if the signing key doesn't decode.
pub fn falcon_public_from_signing_key(signing_key: &[u8]) -> Option<Vec<u8>> {
    let sk = SigningKeyStandard::decode(signing_key)?;
    let mut vrfy = vec![0u8; vrfy_key_size(sk.get_logn())];
    sk.to_verifying_key(&mut vrfy);
    Some(vrfy)
}

/// Constructor + verification surface for Falcon consensus signatures.
///
/// Implements the SAME `BlsConstructor` trait the BLS path did, so it drops
/// into every injection site (`app_engine.rs`, `*_aggregation.rs`, …) by
/// swapping `Bls48581KeyConstructor` → `FalconKeyConstructor`. Falcon does not
/// aggregate, so the "aggregate" is a **concatenation**:
///
/// * [`aggregate`](FalconKeyConstructor::aggregate): `signature` = the member
/// signatures concatenated in bitmask order (666 B each); `public_key` = the
/// member public keys concatenated (897 B each), in the SAME order.
/// * [`aggregate_public_keys`](FalconKeyConstructor::aggregate_public_keys):
/// the member public keys concatenated. Because the committee reconstructs
/// the exact same ordered concatenation, `bind_aggregate_pubkey_to_committee`'s
/// `reconstructed == transmitted` equality check keeps working unchanged.
/// * QC/TC verification uses
/// [`verify_multi_pubkey_multi_message_raw`](FalconKeyConstructor::verify_multi_pubkey_multi_message_raw):
/// split the concatenated signature into 666-byte components and verify each
/// member's signature against its own message (all equal for a QC, distinct
/// for a TC) — i.e. N independent Falcon verifies instead of one pairing.
pub struct FalconKeyConstructor;

impl BlsConstructor for FalconKeyConstructor {
    fn new_key(&self) -> Result<(Box<dyn Signer>, Vec<u8>)> {
        let signer = FalconSigner::generate();
        let public_key = signer.public_key().to_vec();
        Ok((Box::new(signer), public_key))
    }

    fn from_bytes(&self, private_key: &[u8], public_key: &[u8]) -> Result<Box<dyn Signer>> {
        Ok(Box::new(FalconSigner::from_bytes(private_key, public_key)))
    }

    fn verify_signature_raw(
        &self,
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
        context: &[u8],
    ) -> bool {
        falcon_verify(public_key, signature, message, context)
    }

    fn verify_multi_message_signature_raw(
        &self,
        public_key: &[u8],
        signature: &[u8],
        messages: &[&[u8]],
        context: &[u8],
    ) -> bool {
        // One signer signs a single message, so a lone signer's "aggregate" is
        // just its signature over that one message.
        matches!(messages, [msg] if falcon_verify(public_key, signature, msg, context))
    }

    fn verify_multi_pubkey_multi_message_raw(
        &self,
        public_keys: &[&[u8]],
        signature: &[u8],
        messages: &[&[u8]],
        context: &[u8],
    ) -> bool {
        // One public key and one message per signer; `signature` is the members'
        // signatures concatenated in the same order (666 bytes each).
        let n = public_keys.len();
        if n == 0 || n != messages.len() || signature.len() != n * FALCON_SIGNATURE_LEN {
            return false;
        }
        public_keys.iter().zip(messages.iter()).enumerate().all(|(i, (pk, msg))| {
            let component = &signature[i * FALCON_SIGNATURE_LEN..(i + 1) * FALCON_SIGNATURE_LEN];
            falcon_verify(pk, component, msg, context)
        })
    }

    fn verify_signatures_batch(&self, items: &[(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)]) -> bool {
        // Falcon has no random-linear-combination batch verify; a plain loop is
        // correct and constant-time per item.
        !items.is_empty()
            && items
                .iter()
                .all(|(pk, sig, msg, ctx)| falcon_verify(pk, sig, msg, ctx))
    }

    fn aggregate(&self, public_keys: &[&[u8]], signatures: &[&[u8]]) -> Result<BlsAggregateOutput> {
        if public_keys.iter().any(|k| k.len() != FALCON_PUBLIC_KEY_LEN)
            || signatures.iter().any(|s| s.len() != FALCON_SIGNATURE_LEN)
        {
            return Err(QuilError::Crypto(
                "falcon aggregate: malformed public key or signature length".into(),
            ));
        }
        Ok(BlsAggregateOutput {
            signature: signatures.concat(),
            public_key: public_keys.concat(),
        })
    }

    fn aggregate_public_keys(&self, public_keys: &[&[u8]]) -> Result<Vec<u8>> {
        if public_keys.iter().any(|k| k.len() != FALCON_PUBLIC_KEY_LEN) {
            return Err(QuilError::Crypto(
                "falcon aggregate_public_keys: malformed public key length".into(),
            ));
        }
        Ok(public_keys.concat())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falcon_sizes() {
        assert_eq!(FALCON_SIGNING_KEY_LEN, 1281);
        assert_eq!(FALCON_PUBLIC_KEY_LEN, 897);
        assert_eq!(FALCON_SIGNATURE_LEN, 666);
    }

    #[test]
    fn sign_verify_with_domain() {
        let s = FalconSigner::generate();
        let msg = b"consensus vote payload";
        let sig = s.sign_with_domain(msg, b"global").unwrap();
        assert_eq!(sig.len(), FALCON_SIGNATURE_LEN);
        assert!(falcon_verify(s.public_key(), &sig, msg, b"global"));
        // Wrong domain must not verify (domain separation).
        assert!(!falcon_verify(s.public_key(), &sig, msg, b"globaltimeout"));
        // Wrong message must not verify.
        assert!(!falcon_verify(s.public_key(), &sig, b"tampered", b"global"));
    }

    #[test]
    fn verify_rejects_malformed_lengths_without_panic() {
        let s = FalconSigner::generate();
        let sig = s.sign(b"m").unwrap();
        // short / empty pk and sig → false, never panics.
        assert!(!falcon_verify(&[], &sig, b"m", &[]));
        assert!(!falcon_verify(s.public_key(), &[1, 2, 3], b"m", &[]));
        assert!(!falcon_verify(&vec![0u8; FALCON_PUBLIC_KEY_LEN], &sig, b"m", &[]));
    }

    #[test]
    fn from_bytes_roundtrip() {
        let s = FalconSigner::generate();
        let s2 = FalconSigner::from_bytes(s.private_key(), s.public_key());
        let sig = s2.sign(b"x").unwrap();
        assert!(falcon_verify(s.public_key(), &sig, b"x", &[]));
    }

    // ---- FalconKeyConstructor (the BlsConstructor drop-in) ----

    /// QC pattern: N signers over the SAME vote message. `aggregate` concats;
    /// verification splits and checks each component.
    #[test]
    fn quorum_certificate_concat_and_verify() {
        let c = FalconKeyConstructor;
        let ctx = b"global";
        let (a, pk_a) = c.new_key().unwrap();
        let (b, pk_b) = c.new_key().unwrap();
        let (d, pk_d) = c.new_key().unwrap();
        let msg = b"filter|state_id|rank"; // shared QC vote message
        let sigs: Vec<Vec<u8>> = [&a, &b, &d]
            .iter()
            .map(|s| s.sign_with_domain(msg, ctx).unwrap())
            .collect();

        let agg = c
            .aggregate(
                &[pk_a.as_slice(), pk_b.as_slice(), pk_d.as_slice()],
                &[sigs[0].as_slice(), sigs[1].as_slice(), sigs[2].as_slice()],
            )
            .unwrap();
        assert_eq!(agg.signature.len(), 3 * FALCON_SIGNATURE_LEN);
        assert_eq!(agg.public_key.len(), 3 * FALCON_PUBLIC_KEY_LEN);

        // Verify all three against the shared message (QC path).
        let msgs = [&msg[..], &msg[..], &msg[..]];
        assert!(c.verify_multi_pubkey_multi_message_raw(
            &[pk_a.as_slice(), pk_b.as_slice(), pk_d.as_slice()],
            &agg.signature,
            &msgs,
            ctx,
        ));
        // Wrong context (domain separation) → false.
        assert!(!c.verify_multi_pubkey_multi_message_raw(
            &[pk_a.as_slice(), pk_b.as_slice(), pk_d.as_slice()],
            &agg.signature,
            &msgs,
            b"globaltimeout",
        ));
        // Corrupt one component signature → false, no panic.
        let mut bad = agg.signature.clone();
        bad[0] ^= 0xff;
        assert!(!c.verify_multi_pubkey_multi_message_raw(
            &[pk_a.as_slice(), pk_b.as_slice(), pk_d.as_slice()],
            &bad,
            &msgs,
            ctx,
        ));
    }

    /// TC pattern: signers over DISTINCT messages (differing newest_qc_rank).
    #[test]
    fn timeout_certificate_distinct_messages() {
        let c = FalconKeyConstructor;
        let ctx = b"globaltimeout";
        let (a, pk_a) = c.new_key().unwrap();
        let (b, pk_b) = c.new_key().unwrap();
        let m_a = b"filter|rank|qc_rank_7".to_vec();
        let m_b = b"filter|rank|qc_rank_9".to_vec();
        let sig_a = a.sign_with_domain(&m_a, ctx).unwrap();
        let sig_b = b.sign_with_domain(&m_b, ctx).unwrap();
        let agg = c
            .aggregate(&[pk_a.as_slice(), pk_b.as_slice()], &[sig_a.as_slice(), sig_b.as_slice()])
            .unwrap();
        assert!(c.verify_multi_pubkey_multi_message_raw(
            &[pk_a.as_slice(), pk_b.as_slice()],
            &agg.signature,
            &[m_a.as_slice(), m_b.as_slice()],
            ctx,
        ));
        // Swapped messages → false.
        assert!(!c.verify_multi_pubkey_multi_message_raw(
            &[pk_a.as_slice(), pk_b.as_slice()],
            &agg.signature,
            &[m_b.as_slice(), m_a.as_slice()],
            ctx,
        ));
    }

    /// The committee-bind invariant: `aggregate_public_keys` (committee-side
    /// reconstruction) must equal the pubkey half of `aggregate` (transmitted),
    /// so `bind_aggregate_pubkey_to_committee`'s equality check still holds.
    #[test]
    fn aggregate_public_keys_matches_aggregate_half() {
        let c = FalconKeyConstructor;
        let (a, pk_a) = c.new_key().unwrap();
        let (b, pk_b) = c.new_key().unwrap();
        let sig_a = a.sign_with_domain(b"m", b"d").unwrap();
        let sig_b = b.sign_with_domain(b"m", b"d").unwrap();
        let pk_only = c
            .aggregate_public_keys(&[pk_a.as_slice(), pk_b.as_slice()])
            .unwrap();
        let full = c
            .aggregate(&[pk_a.as_slice(), pk_b.as_slice()], &[sig_a.as_slice(), sig_b.as_slice()])
            .unwrap();
        assert_eq!(pk_only, full.public_key);
        assert_eq!(pk_only.len(), 2 * FALCON_PUBLIC_KEY_LEN);
    }

    #[test]
    fn constructor_rejects_malformed_without_panic() {
        let c = FalconKeyConstructor;
        assert!(!c.verify_signature_raw(&[], &[], b"m", b"d"));
        assert!(c.aggregate(&[&[0u8; 10]], &[&[0u8; 3]]).is_err());
        assert!(c.aggregate_public_keys(&[&[]]).is_err());
        assert!(!c.verify_multi_pubkey_multi_message_raw(&[&[0u8; 897]], &[0u8; 5], &[b"m"], b"d"));
        assert!(!c.verify_signatures_batch(&[]));
    }
}

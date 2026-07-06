use quil_types::crypto::{BlsAggregateOutput, BlsConstructor, KeyType, Signer};
use quil_types::error::Result;

// Canonical fixed-size BLS48-581 compressed encodings. `bls48581`'s point
// deserialization (`ECP::frombytes` / `ECP8::frombytes`) indexes the input
// slice WITHOUT a length guard, so a short/malformed byte string — which can
// only come from a hostile or corrupt source — causes an index-out-of-bounds
// PANIC (remote DoS) before any subgroup/pairing check runs. Every verify
// boundary below rejects wrong-length inputs up front. Do NOT "fix" this by
// making `frombytes` return the point at infinity: infinity passes subgroup
// membership, which would turn a malformed input into a signature FORGERY.
const BLS_G8_PUBKEY_BYTES: usize = 585; // G8 compressed public key
const BLS_G1_SIG_BYTES: usize = 74; // G1 compressed signature

#[inline]
fn bls_pk_sig_lengths_ok(public_key_g2: &[u8], signature_g1: &[u8]) -> bool {
    public_key_g2.len() == BLS_G8_PUBKEY_BYTES && signature_g1.len() == BLS_G1_SIG_BYTES
}

/// BLS48-581 signer wrapping the bls48581 crate.
pub struct Bls48581Signer {
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl Signer for Bls48581Signer {
    fn key_type(&self) -> KeyType {
        KeyType::Bls48581G2
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn private_key(&self) -> &[u8] {
        &self.secret_key
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(bls48581::bls_sign(&self.secret_key, message, &[]))
    }

    fn sign_with_domain(&self, message: &[u8], domain: &[u8]) -> Result<Vec<u8>> {
        Ok(bls48581::bls_sign(&self.secret_key, message, domain))
    }
}

/// Constructor for BLS48-581 keys.
pub struct Bls48581KeyConstructor;

impl BlsConstructor for Bls48581KeyConstructor {
    fn new_key(&self) -> Result<(Box<dyn Signer>, Vec<u8>)> {
        let output = bls48581::bls_keygen();
        let public_key = output.public_key.clone();
        let signer = Bls48581Signer {
            secret_key: output.secret_key,
            public_key: output.public_key,
        };
        Ok((Box::new(signer), public_key))
    }

    fn from_bytes(&self, private_key: &[u8], public_key: &[u8]) -> Result<Box<dyn Signer>> {
        Ok(Box::new(Bls48581Signer {
            secret_key: private_key.to_vec(),
            public_key: public_key.to_vec(),
        }))
    }

    fn verify_signature_raw(
        &self,
        public_key_g2: &[u8],
        signature_g1: &[u8],
        message: &[u8],
        context: &[u8],
    ) -> bool {
        if !bls_pk_sig_lengths_ok(public_key_g2, signature_g1) {
            return false;
        }
        bls48581::bls_verify(public_key_g2, signature_g1, message, context)
    }

    fn verify_multi_message_signature_raw(
        &self,
        public_key_g2: &[u8],
        signature_g1: &[u8],
        messages: &[&[u8]],
        context: &[u8],
    ) -> bool {
        if !bls_pk_sig_lengths_ok(public_key_g2, signature_g1) {
            return false;
        }
        let msgs: Vec<Vec<u8>> = messages.iter().map(|m| m.to_vec()).collect();
        bls48581::bls_verify_msig_mmsg(
            &vec![public_key_g2.to_vec()],
            signature_g1,
            &msgs,
            context,
        )
    }

    fn verify_multi_pubkey_multi_message_raw(
        &self,
        public_keys_g2: &[&[u8]],
        signature_g1: &[u8],
        messages: &[&[u8]],
        context: &[u8],
    ) -> bool {
        // Length guard first — `bls_verify_msig_mmsg` decodes each pk and the
        // sig via the unguarded `frombytes` (OOB-panic on short input). pk and
        // sig can carry attacker bytes (a peer-supplied TC aggregate sig).
        if signature_g1.len() != BLS_G1_SIG_BYTES
            || public_keys_g2.iter().any(|k| k.len() != BLS_G8_PUBKEY_BYTES)
        {
            return false;
        }
        // One pubkey per message — the caller pairs pk_j with m_j.
        if public_keys_g2.len() != messages.len() || messages.is_empty() {
            return false;
        }
        let pks: Vec<Vec<u8>> = public_keys_g2.iter().map(|k| k.to_vec()).collect();
        let msgs: Vec<Vec<u8>> = messages.iter().map(|m| m.to_vec()).collect();
        bls48581::bls_verify_msig_mmsg(&pks, signature_g1, &msgs, context)
    }

    fn verify_signatures_batch(
        &self,
        items: &[(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)],
    ) -> bool {
        // Fresh OS entropy per call: the random batch coefficients must be
        // unpredictable to whoever produced the signatures, else a
        // cancellation forgery is possible.
        use rand::RngCore;
        // Reject any wrong-length point up front: `bls_verify_batch` decodes
        // every (pk, sig) via the unguarded `frombytes` and would panic on a
        // malformed element from a hostile peer.
        for (pk, sig, _msg, _ctx) in items {
            if !bls_pk_sig_lengths_ok(pk, sig) {
                return false;
            }
        }
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        bls48581::bls_verify_batch(items, &seed)
    }

    fn aggregate(
        &self,
        public_keys: &[&[u8]],
        signatures: &[&[u8]],
    ) -> Result<BlsAggregateOutput> {
        // Wrong-length points would OOB-panic in `bls_aggregate`'s `frombytes`.
        // This is a true (pk, sig)-aggregate, so both lists must be canonical
        // (585-byte G8 pubkeys, 74-byte G1 sigs). Callers that only want the
        // aggregate PUBKEY must use `aggregate_public_keys` — do NOT pass
        // pubkeys in the `signatures` slot here.
        if public_keys.iter().any(|k| k.len() != BLS_G8_PUBKEY_BYTES)
            || signatures.iter().any(|s| s.len() != BLS_G1_SIG_BYTES)
        {
            return Err(quil_types::error::QuilError::Crypto(
                "bls aggregate: malformed public key or signature length".into(),
            ));
        }
        let pks: Vec<Vec<u8>> = public_keys.iter().map(|k| k.to_vec()).collect();
        let sigs: Vec<Vec<u8>> = signatures.iter().map(|s| s.to_vec()).collect();
        let output = bls48581::bls_aggregate(&pks, &sigs);
        Ok(BlsAggregateOutput {
            signature: output.aggregate_signature,
            public_key: output.aggregate_public_key,
        })
    }

    fn aggregate_public_keys(&self, public_keys: &[&[u8]]) -> Result<Vec<u8>> {
        // Every G8 public key must be full-length; `ECP8::frombytes` indexes
        // without a length guard (short input OOB-panics).
        if public_keys.iter().any(|k| k.len() != BLS_G8_PUBKEY_BYTES) {
            return Err(quil_types::error::QuilError::Crypto(
                "bls aggregate_public_keys: malformed public key length".into(),
            ));
        }
        let pks: Vec<Vec<u8>> = public_keys.iter().map(|k| k.to_vec()).collect();
        Ok(bls48581::bls_aggregate_pubkeys(&pks))
    }
}

#[cfg(test)]
mod length_guard_tests {
    use super::*;
    use quil_types::crypto::BlsConstructor;

    // Regression: a malformed (short/wrong-length) public key or signature —
    // reachable from any peer via a KeyRegistry cross-signature or a consensus
    // QC — must return `false`, NOT panic. `bls48581`'s `frombytes` indexes
    // without a length guard, so without the boundary check these inputs
    // caused a remote-DoS index-out-of-bounds panic in the P2P receive task.
    #[test]
    fn verify_signature_raw_rejects_malformed_lengths_without_panic() {
        let c = Bls48581KeyConstructor;
        let msg = b"m";
        let ctx = b"KEY_REGISTRY";
        // empty pk (ECP8::frombytes indexes b[0] immediately) + empty sig
        assert!(!c.verify_signature_raw(&[], &[], msg, ctx));
        // short sig against a right-length (garbage) pubkey
        assert!(!c.verify_signature_raw(&vec![0u8; BLS_G8_PUBKEY_BYTES], &[1, 2, 3], msg, ctx));
        // short pubkey against a right-length (garbage) sig
        assert!(!c.verify_signature_raw(&[9u8; 5], &vec![0u8; BLS_G1_SIG_BYTES], msg, ctx));
        // the exact all-zero right-length case (garbage but correctly sized):
        // must still not panic (returns false via the curve check)
        assert!(!c.verify_signature_raw(
            &vec![0u8; BLS_G8_PUBKEY_BYTES],
            &vec![0u8; BLS_G1_SIG_BYTES],
            msg,
            ctx
        ));
    }

    // F2 regression: a multi-signer aggregate where each signer signed a
    // DIFFERENT message must verify via verify_multi_pubkey_multi_message_raw
    // (product-of-pairings over ALL signers), and must NOT verify via the
    // single-aggregate-pubkey path (which only checks messages[0]).
    #[test]
    fn multi_pubkey_multi_message_verifies_distinct_messages() {
        let c = Bls48581KeyConstructor;
        let ctx = b"timeout";
        let (s_a, pk_a) = c.new_key().unwrap();
        let (s_b, pk_b) = c.new_key().unwrap();
        // Distinct per-signer messages (the newest_qc_rank differs).
        let m_a = b"filter|rank|qc_rank_7".to_vec();
        let m_b = b"filter|rank|qc_rank_9".to_vec();
        let sig_a = s_a.sign_with_domain(&m_a, ctx).unwrap();
        let sig_b = s_b.sign_with_domain(&m_b, ctx).unwrap();
        // Aggregate signature = sig_a + sig_b (G1 point sum).
        let agg = c
            .aggregate(&[pk_a.as_slice(), pk_b.as_slice()], &[sig_a.as_slice(), sig_b.as_slice()])
            .unwrap();
        // Correct multi-pubkey/multi-message verify → TRUE.
        assert!(c.verify_multi_pubkey_multi_message_raw(
            &[pk_a.as_slice(), pk_b.as_slice()],
            &agg.signature,
            &[m_a.as_slice(), m_b.as_slice()],
            ctx,
        ));
        // The OLD path (single aggregate pubkey over the same message list)
        // is the F2 bug: it only pairs the aggregate pk with messages[0], so
        // it does NOT verify the mixed-message aggregate → FALSE.
        assert!(!c.verify_multi_message_signature_raw(
            &agg.public_key,
            &agg.signature,
            &[m_a.as_slice(), m_b.as_slice()],
            ctx,
        ));
        // Tamper: swap a message → must fail.
        assert!(!c.verify_multi_pubkey_multi_message_raw(
            &[pk_a.as_slice(), pk_b.as_slice()],
            &agg.signature,
            &[m_b.as_slice(), m_a.as_slice()],
            ctx,
        ));
        // Length mismatch (pks != msgs) and malformed sig → false, no panic.
        assert!(!c.verify_multi_pubkey_multi_message_raw(
            &[pk_a.as_slice()],
            &agg.signature,
            &[m_a.as_slice(), m_b.as_slice()],
            ctx,
        ));
        assert!(!c.verify_multi_pubkey_multi_message_raw(
            &[pk_a.as_slice(), pk_b.as_slice()],
            &[0u8; 5],
            &[m_a.as_slice(), m_b.as_slice()],
            ctx,
        ));
    }

    #[test]
    fn verify_batch_and_aggregate_reject_malformed_lengths() {
        let c = Bls48581KeyConstructor;
        // batch with one malformed item → false, no panic
        let items = vec![(vec![0u8; 10], vec![0u8; 3], b"m".to_vec(), b"d".to_vec())];
        assert!(!c.verify_signatures_batch(&items));
        // aggregate over malformed points → Err, no panic
        let pk = vec![0u8; 10];
        let sig = vec![0u8; 3];
        assert!(c.aggregate(&[pk.as_slice()], &[sig.as_slice()]).is_err());
    }

    // The clean replacement for the FrameHeader "throwaway pubkey in the
    // signature slot" hack: aggregate_public_keys must equal the PUBKEY HALF of
    // a full aggregate(pks, sigs), be 585 bytes, and reject malformed input
    // without panicking.
    #[test]
    fn aggregate_public_keys_matches_aggregate_pubkey_half() {
        let c = Bls48581KeyConstructor;
        let (s_a, pk_a) = c.new_key().unwrap();
        let (s_b, pk_b) = c.new_key().unwrap();
        let sig_a = s_a.sign_with_domain(b"m", b"d").unwrap();
        let sig_b = s_b.sign_with_domain(b"m", b"d").unwrap();
        let pk_only = c
            .aggregate_public_keys(&[pk_a.as_slice(), pk_b.as_slice()])
            .unwrap();
        let full = c
            .aggregate(
                &[pk_a.as_slice(), pk_b.as_slice()],
                &[sig_a.as_slice(), sig_b.as_slice()],
            )
            .unwrap();
        assert_eq!(pk_only, full.public_key, "pubkey-only fold must match aggregate's pubkey half");
        assert_eq!(pk_only.len(), BLS_G8_PUBKEY_BYTES);
        // malformed / short pubkey → Err, no panic
        assert!(c.aggregate_public_keys(&[&[0u8; 10]]).is_err());
        assert!(c.aggregate_public_keys(&[&[]]).is_err());
    }
}

//! BLS-backed consensus verifier. Mirror of
//! `consensus/verification/common.go::verifyAggregatedSignatureOneMessage`
//! and `verifyTCSignatureManyMessages`, wrapped into a concrete
//! implementation of the [`Verifier`] trait.
//!
//! The verifier is the crypto boundary: given a QC or TC trait object,
//! it reconstructs the canonical signed message (via
//! [`make_vote_message`] / [`make_timeout_message`]) and delegates to
//! the underlying [`SignatureAggregator`] for the actual check. This
//! cleanly separates "what bytes should have been signed" (format,
//! owned by `quil-consensus`) from "is this signature valid"
//! (crypto, owned by adapter crates).

use std::sync::Arc;

use quil_consensus::models::{QuorumCertificate, TimeoutCertificate, Unique};
use quil_consensus::signature_aggregator::SignatureAggregator;
use quil_consensus::verification::{make_timeout_message, make_vote_message};
use quil_consensus::verifier::Verifier;
use quil_types::error::{QuilError, Result};

/// Concrete [`Verifier`] backed by a raw
/// [`SignatureAggregator`](quil_consensus::signature_aggregator::SignatureAggregator).
///
/// `ds_tag` is the BLS domain-separation tag applied to every
/// verification call — committees typically use distinct tags per
/// shard / filter so signatures from one cluster can't be replayed
/// into another.
pub struct BlsConsensusVerifier {
    aggregator: Arc<dyn SignatureAggregator>,
    /// Domain separator used for QC verification. Mirrors the
    /// `vote_domain` the voters signed under.
    vote_ds_tag: Vec<u8>,
    /// Domain separator used for TC verification. Mirrors the
    /// `timeout_domain` the timeout votes were signed under.
    timeout_ds_tag: Vec<u8>,
}

impl BlsConsensusVerifier {
    /// Construct a verifier whose vote_domain is used for both QC and
    /// TC checks. Kept for backwards-compat with tests; production
    /// should call [`Self::new_with_timeout_domain`].
    pub fn new(aggregator: Arc<dyn SignatureAggregator>, ds_tag: Vec<u8>) -> Self {
        Self {
            aggregator,
            vote_ds_tag: ds_tag.clone(),
            timeout_ds_tag: ds_tag,
        }
    }

    /// Construct a verifier with distinct domains for QC and TC. QCs
    /// are aggregates of votes (signed with `vote_domain`), TCs are
    /// aggregates of timeout votes (signed with `timeout_domain`).
    /// Using the same tag for both was a latent bug — a TC formed under
    /// the timeout domain would never verify against the vote-domain
    /// `ds_tag`.
    pub fn new_with_timeout_domain(
        aggregator: Arc<dyn SignatureAggregator>,
        vote_domain: Vec<u8>,
        timeout_domain: Vec<u8>,
    ) -> Self {
        Self {
            aggregator,
            vote_ds_tag: vote_domain,
            timeout_ds_tag: timeout_domain,
        }
    }
}

impl<V: Unique> Verifier<V> for BlsConsensusVerifier {
    /// Verifying a standalone vote is the caller's responsibility —
    /// the vote's signer ID is looked up in the committee and then
    /// verified against the canonical vote message. This concrete
    /// implementation doesn't have access to the committee mapping,
    /// so it assumes `vote.source()` carries the state ID (the same
    /// shape as [`make_vote_message`]) and that the signature bytes
    /// in `vote.signature()` were produced by a committee member.
    ///
    /// Returns `Ok(())` when the signature verifies against the
    /// vote's source (treated as state ID) and rank, using the
    /// signer's public key. **However**, because we don't have the
    /// public key here (only the vote), we can't actually verify
    /// at this layer — the caller must plug the public key in via
    /// [`Self::verify_vote_with_key`] or use a
    /// [`WeightedSignatureAggregator`](quil_consensus::signature_aggregator::WeightedSignatureAggregator)
    /// which owns the committee membership.
    fn verify_vote(&self, _vote: &V) -> Result<()> {
        Err(QuilError::Consensus(
            "verify_vote requires per-signer public key — use verify_vote_with_key".into(),
        ))
    }

    /// Verify a QC against its own embedded aggregate signature. The
    /// aggregate public key is taken from the QC's
    /// `aggregated_signature().public_key()`, and the canonical
    /// message is reconstructed from the QC's filter + rank +
    /// identity.
    fn verify_quorum_certificate(&self, qc: &dyn QuorumCertificate) -> Result<()> {
        let msg = make_vote_message(qc.filter(), qc.rank(), qc.identity());
        let agg = qc.aggregated_signature();
        let pk = agg.public_key();
        let sig = agg.signature();
        let bitmask = agg.bitmask();
        if pk.is_empty() {
            return Err(QuilError::InsufficientSignatures(
                "QC has no aggregated public key".into(),
            ));
        }
        let ok = self.aggregator.verify_signature_raw(pk, sig, &msg, &self.vote_ds_tag);
        if !ok {
            // Dump details so an operator can compare what voters signed
            // vs what we're verifying. The two most common asymmetries
            // are (a) `identity` re-derivation diverging between
            // proposer and verifier, and (b) `ds_tag` mismatch.
            tracing::warn!(
                rank = qc.rank(),
                filter_len = qc.filter().len(),
                identity = %hex::encode(qc.identity()),
                msg = %hex::encode(&msg),
                ds_tag = %hex::encode(&self.vote_ds_tag),
                pk_len = pk.len(),
                pk_head = %hex::encode(&pk[..pk.len().min(16)]),
                sig_len = sig.len(),
                sig_head = %hex::encode(&sig[..sig.len().min(16)]),
                bitmask = %hex::encode(bitmask),
                "QC verification failed — dumping inputs",
            );
            return Err(QuilError::InvalidQuorumCertificate(format!(
                "aggregated QC signature failed verification at rank {} (state {})",
                qc.rank(),
                hex::encode(qc.identity())
            )));
        }
        Ok(())
    }

    /// Verify a TC. Each signer contributed a signature over a
    /// different message (`filter || tc.rank || signer.newestQCRank`).
    /// The aggregate signature must verify against the per-signer
    /// reconstructed messages.
    fn verify_timeout_certificate(&self, tc: &dyn TimeoutCertificate) -> Result<()> {
        let latest_ranks = tc.latest_ranks();
        if latest_ranks.is_empty() {
            return Err(QuilError::InsufficientSignatures(
                "TC carries no signer ranks".into(),
            ));
        }
        let agg = tc.aggregated_signature();
        let pk = agg.public_key();
        let sig = agg.signature();
        if pk.is_empty() {
            return Err(QuilError::InsufficientSignatures(
                "TC has no aggregated public key".into(),
            ));
        }

        // Reconstruct one message per signer. The TC aggregate was
        // built over these messages in some stable order — the raw
        // aggregator's `verify_signature_multi_message` is
        // responsible for the set-equality semantics.
        let messages: Vec<Vec<u8>> = latest_ranks
            .iter()
            .map(|r| make_timeout_message(tc.filter(), tc.rank(), *r))
            .collect();
        let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        let pk_refs: Vec<&[u8]> = vec![pk];

        let ok = self.aggregator.verify_signature_multi_message(
            &pk_refs,
            sig,
            &msg_refs,
            &self.timeout_ds_tag,
        );
        if !ok {
            return Err(QuilError::InvalidTimeoutCertificate(format!(
                "aggregated TC signature failed verification at rank {}",
                tc.rank()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls_signature_aggregator::{BlsAggregatedSignature, BlsSignatureAggregator};
    use quil_consensus::models::{AggregatedSignature, Identity};
    use quil_crypto::Bls48581KeyConstructor;
    use quil_types::crypto::{BlsAggregateOutput, BlsConstructor};
    // The `Signer` trait is needed in scope so that dyn-dispatched
    // calls to `sign_with_domain` on `Box<dyn Signer>` resolve
    // correctly below — the compiler reports it as "unused" because
    // no bare `Signer` name is mentioned, but the allow silences the
    // false positive.
    #[allow(unused_imports)]
    use quil_types::crypto::Signer;

    // Minimal concrete QC we can construct on demand.
    #[derive(Debug)]
    struct TestQc {
        rank: u64,
        id: Identity,
        filter: Vec<u8>,
        agg: BlsAggregatedSignature,
    }
    impl QuorumCertificate for TestQc {
        fn filter(&self) -> &[u8] { &self.filter }
        fn rank(&self) -> u64 { self.rank }
        fn frame_number(&self) -> u64 { 0 }
        fn identity(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &self.agg }
        fn equals(&self, o: &dyn QuorumCertificate) -> bool {
            self.rank == o.rank() && self.id == *o.identity()
        }
    }

    // Minimal concrete TC.
    #[derive(Debug)]
    struct TestTc {
        rank: u64,
        latest_ranks: Vec<u64>,
        filter: Vec<u8>,
        latest_qc: TestQc,
        agg: BlsAggregatedSignature,
    }
    impl TimeoutCertificate for TestTc {
        fn filter(&self) -> &[u8] { &self.filter }
        fn rank(&self) -> u64 { self.rank }
        fn latest_ranks(&self) -> &[u64] { &self.latest_ranks }
        fn latest_quorum_cert(&self) -> &dyn QuorumCertificate { &self.latest_qc }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &self.agg }
        fn equals(&self, o: &dyn TimeoutCertificate) -> bool { self.rank == o.rank() }
    }

    fn bls_bundle() -> (
        Arc<BlsSignatureAggregator>,
        Bls48581KeyConstructor,
        Vec<u8>,
    ) {
        let bls = Bls48581KeyConstructor;
        let raw = Arc::new(BlsSignatureAggregator::new(Arc::new(Bls48581KeyConstructor)));
        let ds_tag = b"test-ds-tag".to_vec();
        (raw, bls, ds_tag)
    }

    #[test]
    fn verify_valid_single_signer_qc() {
        let (raw, bls, ds_tag) = bls_bundle();
        let verifier = BlsConsensusVerifier::new(
            raw.clone() as Arc<dyn SignatureAggregator>,
            ds_tag.clone(),
        );

        // Build the canonical QC message the committee would sign.
        let filter = b"shard-global".to_vec();
        let state_id: Identity = "state-5".into();
        let rank = 5u64;
        let msg = make_vote_message(&filter, rank, &state_id);

        // One-signer "aggregate": sign with a single key and take
        // the single (pk, sig) pair as the aggregate.
        let (signer, pk) = bls.new_key().unwrap();
        let sig = signer.sign_with_domain(&msg, &ds_tag).unwrap();
        let agg = BlsAggregatedSignature::new(BlsAggregateOutput {
            signature: sig,
            public_key: pk,
        });
        let qc = TestQc {
            rank,
            id: state_id,
            filter,
            agg,
        };
        type V = crate::bls_verifier::tests::TestVote;
        <BlsConsensusVerifier as Verifier<V>>::verify_quorum_certificate(&verifier, &qc).unwrap();
    }

    #[test]
    fn verify_qc_with_tampered_message_fails() {
        let (raw, bls, ds_tag) = bls_bundle();
        let verifier = BlsConsensusVerifier::new(
            raw.clone() as Arc<dyn SignatureAggregator>,
            ds_tag.clone(),
        );
        // Sign the real message but advertise a different rank on the QC.
        let filter = b"f".to_vec();
        let state_id: Identity = "state-5".into();
        let msg = make_vote_message(&filter, 5, &state_id);
        let (signer, pk) = bls.new_key().unwrap();
        let sig = signer.sign_with_domain(&msg, &ds_tag).unwrap();
        let agg = BlsAggregatedSignature::new(BlsAggregateOutput {
            signature: sig,
            public_key: pk,
        });
        let qc = TestQc {
            rank: 6, // mismatched — verification reconstructs msg from rank=6
            id: state_id,
            filter,
            agg,
        };
        type V = crate::bls_verifier::tests::TestVote;
        let err = <BlsConsensusVerifier as Verifier<V>>::verify_quorum_certificate(&verifier, &qc)
            .unwrap_err();
        assert!(err.is_invalid_quorum_certificate());
    }

    #[test]
    fn verify_qc_with_empty_pk_is_insufficient_signatures() {
        let (raw, _bls, ds_tag) = bls_bundle();
        let verifier = BlsConsensusVerifier::new(
            raw.clone() as Arc<dyn SignatureAggregator>,
            ds_tag,
        );
        let qc = TestQc {
            rank: 0,
            id: "empty".into(),
            filter: vec![],
            agg: BlsAggregatedSignature::new(BlsAggregateOutput {
                signature: vec![0u8; 10],
                public_key: vec![],
            }),
        };
        type V = crate::bls_verifier::tests::TestVote;
        let err = <BlsConsensusVerifier as Verifier<V>>::verify_quorum_certificate(&verifier, &qc)
            .unwrap_err();
        assert!(err.is_insufficient_signatures());
    }

    #[test]
    fn verify_tc_with_valid_single_signer() {
        let (raw, bls, ds_tag) = bls_bundle();
        let verifier = BlsConsensusVerifier::new(
            raw.clone() as Arc<dyn SignatureAggregator>,
            ds_tag.clone(),
        );
        let filter = b"f".to_vec();
        let tc_rank = 10u64;
        let signer_newest_qc_rank = 9u64;
        let msg = make_timeout_message(&filter, tc_rank, signer_newest_qc_rank);
        let (signer, pk) = bls.new_key().unwrap();
        let sig = signer.sign_with_domain(&msg, &ds_tag).unwrap();
        let tc = TestTc {
            rank: tc_rank,
            latest_ranks: vec![signer_newest_qc_rank],
            filter: filter.clone(),
            latest_qc: TestQc {
                rank: signer_newest_qc_rank,
                id: "qc-9".into(),
                filter: filter.clone(),
                agg: BlsAggregatedSignature::new(BlsAggregateOutput {
                    signature: vec![],
                    public_key: vec![],
                }),
            },
            agg: BlsAggregatedSignature::new(BlsAggregateOutput {
                signature: sig,
                public_key: pk,
            }),
        };
        type V = crate::bls_verifier::tests::TestVote;
        <BlsConsensusVerifier as Verifier<V>>::verify_timeout_certificate(&verifier, &tc).unwrap();
    }

    #[test]
    fn verify_tc_with_no_signers_is_insufficient() {
        let (raw, _bls, ds_tag) = bls_bundle();
        let verifier = BlsConsensusVerifier::new(
            raw.clone() as Arc<dyn SignatureAggregator>,
            ds_tag,
        );
        let tc = TestTc {
            rank: 10,
            latest_ranks: vec![],
            filter: vec![],
            latest_qc: TestQc {
                rank: 0,
                id: "".into(),
                filter: vec![],
                agg: BlsAggregatedSignature::new(BlsAggregateOutput {
                    signature: vec![],
                    public_key: vec![],
                }),
            },
            agg: BlsAggregatedSignature::new(BlsAggregateOutput {
                signature: vec![1, 2, 3],
                public_key: vec![1, 2, 3],
            }),
        };
        type V = crate::bls_verifier::tests::TestVote;
        let err = <BlsConsensusVerifier as Verifier<V>>::verify_timeout_certificate(&verifier, &tc)
            .unwrap_err();
        assert!(err.is_insufficient_signatures());
    }

    #[test]
    fn verify_vote_requires_key_lookup() {
        let (raw, _bls, ds_tag) = bls_bundle();
        let verifier = BlsConsensusVerifier::new(
            raw.clone() as Arc<dyn SignatureAggregator>,
            ds_tag,
        );
        let vote = TestVote {
            id: "v1".into(),
            rank: 5,
            payload: vec![],
        };
        let err = <BlsConsensusVerifier as Verifier<TestVote>>::verify_vote(&verifier, &vote)
            .unwrap_err();
        assert!(matches!(err, QuilError::Consensus(_)));
    }

    // Placeholder vote type for the generic `Verifier<V>` bounds.
    #[derive(Debug, Clone)]
    pub(super) struct TestVote {
        id: Identity,
        rank: u64,
        payload: Vec<u8>,
    }
    impl Unique for TestVote {
        fn identity(&self) -> &Identity { &self.id }
        fn rank(&self) -> u64 { self.rank }
        fn source(&self) -> &Identity { &self.id }
        fn timestamp(&self) -> u64 { 0 }
        fn signature(&self) -> &[u8] { &self.payload }
    }
}

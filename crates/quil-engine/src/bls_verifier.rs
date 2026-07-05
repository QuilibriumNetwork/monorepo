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

use quil_consensus::committee::Replicas;
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
    /// Committee this verifier binds certs to. Used two ways: (1) the QC/TC
    /// aggregate-public-key bind in [`Self::bind_aggregate_pubkey_to_committee`]
    /// (reconstruct the aggregate of the bitmask-selected members and require
    /// it to equal the cert's transmitted pubkey), and (2) resolving a single
    /// vote's signer → public key in [`Verifier::verify_vote`]. It is
    /// MANDATORY: a committee-less verifier would silently skip the bind and
    /// leave every QC/TC verify path fail-open to a self-signed forgery, so the
    /// type does not allow one.
    committee: Arc<dyn Replicas>,
    /// Filter the voters signed under, baked into the reconstructed
    /// vote message (`make_vote_message(filter, rank, source)`). The
    /// global chain uses an empty filter; app shards use the shard's
    /// address.
    vote_filter: Vec<u8>,
}

impl BlsConsensusVerifier {
    /// Construct a verifier bound to `committee`.
    ///
    /// QCs are aggregates of votes signed with `vote_domain`; TCs are
    /// aggregates of timeout votes signed with `timeout_domain`. These must be
    /// distinct — using one tag for both is a latent bug, since a TC formed
    /// under the timeout domain would never verify against the vote domain.
    ///
    /// `committee` is MANDATORY: it binds each cert's transmitted aggregate
    /// public key to the bitmask-selected members
    /// ([`Self::bind_aggregate_pubkey_to_committee`]) and resolves signers in
    /// [`Verifier::verify_vote`]. Requiring it at the type level makes the
    /// committee-less fail-open unrepresentable.
    ///
    /// `vote_filter` is the filter the voters signed under — empty for the
    /// global chain, the shard address for app shards — and must match what the
    /// per-rank vote collector uses in [`make_vote_message`]. It affects only
    /// `verify_vote`; the QC/TC paths reconstruct the message from the cert's
    /// own filter.
    pub fn new(
        aggregator: Arc<dyn SignatureAggregator>,
        vote_domain: Vec<u8>,
        timeout_domain: Vec<u8>,
        committee: Arc<dyn Replicas>,
        vote_filter: Vec<u8>,
    ) -> Self {
        Self {
            aggregator,
            vote_ds_tag: vote_domain,
            timeout_ds_tag: timeout_domain,
            committee,
            vote_filter,
        }
    }

    /// Bind a cert's transmitted aggregate public key to the committee:
    /// reconstruct the aggregate of the public keys of the members the
    /// `bitmask` selects at `rank`, and require it to equal `transmitted_pk`.
    ///
    /// Without this, the QC/TC signature is verified against a public key
    /// that travels *inside the cert*, so a peer can sign the canonical
    /// message with a self-generated key, set the bitmask to name real
    /// members (passing the weight check), and present a matching
    /// `(pk, sig)` pair that verifies in isolation — a complete forgery of
    /// consensus authority. This is the inbound-path mirror of the
    /// `bytes.Equal(qc.PubKey, Aggregate(committeePubkeys).PubKey)` check in
    /// Go's `VerifyQuorumCertificate` / `VerifyTimeoutCertificate`
    /// (`consensus_protocol.go`).
    ///
    /// The committee is mandatory, so this bind is unconditional on every
    /// verification path — there is no committee-less verifier to skip it. It
    /// runs on the inbound-proposal gate (`app_engine`), the archive proposal
    /// ingest (`archive_sync`), AND the global/app-shard TIMEOUT aggregators
    /// (`timeout_aggregation`, `app_timeout_aggregation`), whose validator
    /// verifies the QC/TC embedded in a peer's `TimeoutState`.
    /// Bind the transmitted aggregate pubkey to the committee members the
    /// bitmask selects, and return those members' public keys IN BITMASK
    /// (committee-index) ORDER. The TC path needs this order to pair each
    /// signer's pubkey with that signer's per-message (the aggregator sorts
    /// both the bitmask and `latest_ranks` by member index, so they align).
    fn bind_aggregate_pubkey_to_committee(
        &self,
        rank: u64,
        bitmask: &[u8],
        transmitted_pk: &[u8],
        sig: &[u8],
    ) -> Result<Vec<Vec<u8>>> {
        let committee = &self.committee;
        let members = committee.identities_by_rank(rank)?;
        let expected_len = (members.len() + 7) / 8;
        if bitmask.len() < expected_len {
            return Err(QuilError::InsufficientSignatures(format!(
                "bitmask length {} too short for committee size {} at rank {}",
                bitmask.len(),
                members.len(),
                rank
            )));
        }
        // Same index→bit convention as `ConsensusValidator::decode_signers`,
        // so the selected set matches the one the weight check used.
        let mut signer_pks: Vec<Vec<u8>> = Vec::new();
        for (i, m) in members.iter().enumerate() {
            if bitmask[i / 8] & (1 << (i % 8)) != 0 {
                let pk = m.public_key();
                if pk.is_empty() {
                    return Err(QuilError::InsufficientSignatures(format!(
                        "committee member {} at rank {} has no public key to bind",
                        hex::encode(m.identity()),
                        rank
                    )));
                }
                signer_pks.push(pk.to_vec());
            }
        }
        if signer_pks.is_empty() {
            return Err(QuilError::InsufficientSignatures(
                "bitmask selects no committee members".into(),
            ));
        }
        // The aggregate *public key* depends only on the member public
        // keys (G2 point sum, order-independent); the signature argument
        // is irrelevant to it. We pass the transmitted signature once per
        // signer to satisfy the aggregate API's equal-length contract, as
        // Go does.
        let pk_refs: Vec<&[u8]> = signer_pks.iter().map(|p| p.as_slice()).collect();
        let sigs: Vec<&[u8]> = vec![sig; signer_pks.len()];
        let reconstructed = self.aggregator.aggregate(&pk_refs, &sigs)?;
        if reconstructed.public_key() != transmitted_pk {
            return Err(QuilError::InvalidQuorumCertificate(format!(
                "aggregate public key does not match the committee members \
                 selected by the bitmask at rank {} — forged or stale cert",
                rank
            )));
        }
        Ok(signer_pks)
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
    fn verify_vote(&self, vote: &V) -> Result<()> {
        let committee = &self.committee;

        // Resolve the voter's public key from the committee at the
        // vote's rank. An unknown signer surfaces as `InvalidSigner`,
        // which the caller (`ConsensusValidator::validate_vote`) treats
        // as a rejection.
        let voter = committee.identity_by_rank(vote.rank(), vote.identity())?;
        let pk = voter.public_key();
        if pk.is_empty() {
            return Err(QuilError::InvalidVote(format!(
                "voter {} has no public key at rank {}",
                hex::encode(vote.identity()),
                vote.rank()
            )));
        }

        // Reconstruct the canonical vote message the signer produced:
        // `make_vote_message(filter, rank, state_id)` where `state_id`
        // is the proposal identity the vote carries in `source()`.
        let msg = make_vote_message(&self.vote_filter, vote.rank(), vote.source());
        if self
            .aggregator
            .verify_signature_raw(pk, vote.signature(), &msg, &self.vote_ds_tag)
        {
            Ok(())
        } else {
            Err(QuilError::InvalidSignature(format!(
                "vote {} for rank {} failed signature verification",
                hex::encode(vote.identity()),
                vote.rank()
            )))
        }
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
        // Bind the transmitted aggregate pk to the committee BEFORE
        // trusting it for signature verification — otherwise the check
        // below is verifying a self-consistent forgery.
        let _ = self.bind_aggregate_pubkey_to_committee(qc.rank(), bitmask, pk, sig)?;
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
        let bitmask = agg.bitmask();
        if pk.is_empty() {
            return Err(QuilError::InsufficientSignatures(
                "TC has no aggregated public key".into(),
            ));
        }
        // Bind the transmitted aggregate pk to the committee before
        // trusting it (same rationale as the QC path above), and get the
        // selected members' pubkeys in bitmask order.
        let signer_pks = self.bind_aggregate_pubkey_to_committee(tc.rank(), bitmask, pk, sig)?;

        // Reconstruct one message per signer (each signs a DIFFERENT
        // message: `filter||rank||newest_qc_rank_j`). The TC aggregator
        // sorts both the bitmask and `latest_ranks` by committee-member
        // index, so `signer_pks[j]` (bitmask order) pairs with
        // `latest_ranks[j]`.
        let messages: Vec<Vec<u8>> = latest_ranks
            .iter()
            .map(|r| make_timeout_message(tc.filter(), tc.rank(), *r))
            .collect();

        // SECURITY: pass ONE pubkey per message so `core_msig_verify`
        // checks `e(sig,g) == Π_j e(pk_j, H(m_j))` over EVERY signer.
        // Passing the single aggregate pk (as before) made the verifier's
        // `pks.zip(hms)` truncate to `messages[0]`, silently ignoring
        // `messages[1..]` — so honest TCs with mixed `newest_qc_rank`
        // values (the lag condition that produces timeouts) were rejected,
        // wedging recovery rounds. The signer count (bitmask) MUST match
        // the per-signer rank count.
        if signer_pks.len() != messages.len() {
            return Err(QuilError::InvalidTimeoutCertificate(format!(
                "TC signer count {} != per-signer rank count {} at rank {}",
                signer_pks.len(),
                messages.len(),
                tc.rank()
            )));
        }
        let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        let pk_refs: Vec<&[u8]> = signer_pks.iter().map(|p| p.as_slice()).collect();

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
    use crate::bls_signature_aggregator::BlsSignatureAggregator;
    use quil_consensus::models::{AggregatedSignature, Identity};
    use quil_crypto::Bls48581KeyConstructor;
    use quil_types::crypto::BlsConstructor;
    // The `Signer` trait is needed in scope so that dyn-dispatched
    // calls to `sign_with_domain` on `Box<dyn Signer>` resolve
    // correctly below — the compiler reports it as "unused" because
    // no bare `Signer` name is mentioned, but the allow silences the
    // false positive.
    #[allow(unused_imports)]
    use quil_types::crypto::Signer;

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

    // ---- Shared committee-bind test helpers ----
    // `BlsAggregatedSignature` deliberately carries an EMPTY bitmask (owned by
    // the packer, decoded separately), but the mandatory committee bind reads
    // `agg.bitmask()` to select members — so these tests use a bitmask-carrying
    // aggregate + a single-member committee whose member holds the test key.
    use quil_consensus::models::WeightedIdentity;

    #[derive(Debug)]
    struct BmAgg {
        sig: Vec<u8>,
        pk: Vec<u8>,
        bm: Vec<u8>,
    }
    impl AggregatedSignature for BmAgg {
        fn signature(&self) -> &[u8] { &self.sig }
        fn public_key(&self) -> &[u8] { &self.pk }
        fn bitmask(&self) -> &[u8] { &self.bm }
    }
    #[derive(Debug)]
    struct BmQc {
        rank: u64,
        id: Identity,
        filter: Vec<u8>,
        agg: BmAgg,
    }
    impl QuorumCertificate for BmQc {
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
    #[derive(Debug)]
    struct BmTc {
        rank: u64,
        latest_ranks: Vec<u64>,
        filter: Vec<u8>,
        latest_qc: BmQc,
        agg: BmAgg,
    }
    impl TimeoutCertificate for BmTc {
        fn filter(&self) -> &[u8] { &self.filter }
        fn rank(&self) -> u64 { self.rank }
        fn latest_ranks(&self) -> &[u64] { &self.latest_ranks }
        fn latest_quorum_cert(&self) -> &dyn QuorumCertificate { &self.latest_qc }
        fn aggregated_signature(&self) -> &dyn AggregatedSignature { &self.agg }
        fn equals(&self, o: &dyn TimeoutCertificate) -> bool { self.rank == o.rank() }
    }
    #[derive(Debug)]
    struct OneMemberId {
        id: Identity,
        pk: Vec<u8>,
    }
    impl WeightedIdentity for OneMemberId {
        fn public_key(&self) -> &[u8] { &self.pk }
        fn identity(&self) -> &Identity { &self.id }
        fn weight(&self) -> u64 { 1 }
    }
    struct OneMember {
        id: Identity,
        pk: Vec<u8>,
    }
    impl Replicas for OneMember {
        fn leader_for_rank(&self, _r: u64) -> Result<Identity> { Ok(self.id.clone()) }
        fn quorum_threshold_for_rank(&self, _r: u64) -> Result<u64> { Ok(1) }
        fn timeout_threshold_for_rank(&self, _r: u64) -> Result<u64> { Ok(1) }
        fn self_identity(&self) -> &Identity { &self.id }
        fn identities_by_rank(&self, _r: u64) -> Result<Vec<Box<dyn WeightedIdentity>>> {
            Ok(vec![Box::new(OneMemberId { id: self.id.clone(), pk: self.pk.clone() })])
        }
        fn identity_by_rank(&self, _r: u64, pid: &Identity) -> Result<Box<dyn WeightedIdentity>> {
            if pid == &self.id {
                Ok(Box::new(OneMemberId { id: self.id.clone(), pk: self.pk.clone() }))
            } else {
                Err(QuilError::InvalidSigner(hex::encode(pid)))
            }
        }
    }
    fn one_member_committee(id: Identity, pk: Vec<u8>) -> Arc<dyn Replicas> {
        Arc::new(OneMember { id, pk })
    }

    #[test]
    fn verify_qc_with_committee_bind_but_tampered_message_fails() {
        // The bind PASSES (correct committee-reconstructed pubkey) but the
        // signature check fails because the QC advertises a rank whose
        // reconstructed message the signature doesn't cover — distinct from a
        // forged-pubkey rejection at the bind.
        let (raw, bls, ds_tag) = bls_bundle();
        let filter = b"f".to_vec();
        let state_id: Identity = "state-5".into();
        let msg = make_vote_message(&filter, 5, &state_id);
        let (signer, member_pk) = bls.new_key().unwrap();
        let sig = signer.sign_with_domain(&msg, &ds_tag).unwrap();
        let reconstructed_pk = raw
            .aggregate(&[member_pk.as_slice()], &[sig.as_slice()])
            .unwrap()
            .public_key()
            .to_vec();
        let committee = one_member_committee(b"m1".to_vec(), member_pk);
        let verifier = BlsConsensusVerifier::new(
            raw as Arc<dyn SignatureAggregator>,
            ds_tag.clone(),
            ds_tag,
            committee,
            filter.clone(),
        );
        let qc = BmQc {
            rank: 6, // mismatched — verification reconstructs msg from rank=6
            id: state_id,
            filter,
            agg: BmAgg { sig, pk: reconstructed_pk, bm: vec![0b1] },
        };
        type V = crate::bls_verifier::tests::TestVote;
        let err = <BlsConsensusVerifier as Verifier<V>>::verify_quorum_certificate(&verifier, &qc)
            .unwrap_err();
        assert!(err.is_invalid_quorum_certificate());
    }

    #[test]
    fn verify_qc_with_empty_pk_is_insufficient_signatures() {
        // Empty aggregate pubkey → the `pk.is_empty()` guard fires before the
        // committee bind → InsufficientSignatures.
        let (raw, _bls, ds_tag) = bls_bundle();
        let committee = one_member_committee(b"m1".to_vec(), vec![1, 2, 3]);
        let verifier = BlsConsensusVerifier::new(
            raw as Arc<dyn SignatureAggregator>,
            ds_tag.clone(),
            ds_tag,
            committee,
            vec![],
        );
        let qc = BmQc {
            rank: 0,
            id: "empty".into(),
            filter: vec![],
            agg: BmAgg { sig: vec![0u8; 10], pk: vec![], bm: vec![0b1] },
        };
        type V = crate::bls_verifier::tests::TestVote;
        let err = <BlsConsensusVerifier as Verifier<V>>::verify_quorum_certificate(&verifier, &qc)
            .unwrap_err();
        assert!(err.is_insufficient_signatures());
    }

    #[test]
    fn verify_tc_with_valid_single_signer() {
        let (raw, bls, ds_tag) = bls_bundle();
        let filter = b"f".to_vec();
        let tc_rank = 10u64;
        let signer_newest_qc_rank = 9u64;
        let msg = make_timeout_message(&filter, tc_rank, signer_newest_qc_rank);
        let (signer, member_pk) = bls.new_key().unwrap();
        let sig = signer.sign_with_domain(&msg, &ds_tag).unwrap();
        let reconstructed_pk = raw
            .aggregate(&[member_pk.as_slice()], &[sig.as_slice()])
            .unwrap()
            .public_key()
            .to_vec();
        let committee = one_member_committee(b"m1".to_vec(), member_pk);
        let verifier = BlsConsensusVerifier::new(
            raw as Arc<dyn SignatureAggregator>,
            ds_tag.clone(),
            ds_tag,
            committee,
            filter.clone(),
        );
        let tc = BmTc {
            rank: tc_rank,
            latest_ranks: vec![signer_newest_qc_rank],
            filter: filter.clone(),
            latest_qc: BmQc {
                rank: signer_newest_qc_rank,
                id: "qc-9".into(),
                filter: filter.clone(),
                agg: BmAgg { sig: vec![], pk: vec![], bm: vec![] },
            },
            agg: BmAgg { sig, pk: reconstructed_pk, bm: vec![0b1] },
        };
        type V = crate::bls_verifier::tests::TestVote;
        <BlsConsensusVerifier as Verifier<V>>::verify_timeout_certificate(&verifier, &tc).unwrap();
    }

    #[test]
    fn verify_tc_with_no_signers_is_insufficient() {
        // Empty latest_ranks → the `latest_ranks.is_empty()` guard fires before
        // the committee bind → InsufficientSignatures.
        let (raw, _bls, ds_tag) = bls_bundle();
        let committee = one_member_committee(b"m1".to_vec(), vec![1, 2, 3]);
        let verifier = BlsConsensusVerifier::new(
            raw as Arc<dyn SignatureAggregator>,
            ds_tag.clone(),
            ds_tag,
            committee,
            vec![],
        );
        let tc = BmTc {
            rank: 10,
            latest_ranks: vec![],
            filter: vec![],
            latest_qc: BmQc {
                rank: 0,
                id: "".into(),
                filter: vec![],
                agg: BmAgg { sig: vec![], pk: vec![], bm: vec![] },
            },
            agg: BmAgg { sig: vec![1, 2, 3], pk: vec![1, 2, 3], bm: vec![0b1] },
        };
        type V = crate::bls_verifier::tests::TestVote;
        let err = <BlsConsensusVerifier as Verifier<V>>::verify_timeout_certificate(&verifier, &tc)
            .unwrap_err();
        assert!(err.is_insufficient_signatures());
    }

    #[test]
    fn verify_vote_with_committee_verifies_and_rejects() {
        use quil_consensus::committee::Replicas;
        use quil_consensus::models::WeightedIdentity;

        let (raw, bls, ds_tag) = bls_bundle();
        let filter = b"global".to_vec();
        let rank = 7u64;
        // `TestVote::source()` returns its `id`, so we sign the canonical
        // vote message over that same identity (the test exercises the
        // committee pk lookup + message reconstruction + domain check, not
        // the voter/state distinction).
        let voter_id: Identity = b"voter-1".to_vec();
        let msg = make_vote_message(&filter, rank, &voter_id);
        let (signer, pk) = bls.new_key().unwrap();
        let sig = signer.sign_with_domain(&msg, &ds_tag).unwrap();

        // Minimal committee returning the voter's real public key.
        struct C {
            voter: Identity,
            pk: Vec<u8>,
        }
        #[derive(Debug)]
        struct M {
            id: Identity,
            pk: Vec<u8>,
        }
        impl WeightedIdentity for M {
            fn public_key(&self) -> &[u8] { &self.pk }
            fn identity(&self) -> &Identity { &self.id }
            fn weight(&self) -> u64 { 1 }
        }
        impl Replicas for C {
            fn leader_for_rank(&self, _r: u64) -> Result<Identity> { Ok(self.voter.clone()) }
            fn quorum_threshold_for_rank(&self, _r: u64) -> Result<u64> { Ok(1) }
            fn timeout_threshold_for_rank(&self, _r: u64) -> Result<u64> { Ok(1) }
            fn self_identity(&self) -> &Identity { &self.voter }
            fn identities_by_rank(&self, _r: u64) -> Result<Vec<Box<dyn WeightedIdentity>>> {
                Ok(vec![])
            }
            fn identity_by_rank(
                &self,
                _r: u64,
                pid: &Identity,
            ) -> Result<Box<dyn WeightedIdentity>> {
                if pid == &self.voter {
                    Ok(Box::new(M { id: self.voter.clone(), pk: self.pk.clone() }))
                } else {
                    Err(QuilError::InvalidSigner(hex::encode(pid)))
                }
            }
        }

        let committee: Arc<dyn Replicas> = Arc::new(C { voter: voter_id.clone(), pk });
        let verifier = BlsConsensusVerifier::new(
            raw as Arc<dyn SignatureAggregator>,
            ds_tag.clone(),
            ds_tag,
            committee,
            filter,
        );

        // Valid vote verifies.
        let good = TestVote { id: voter_id.clone(), rank, payload: sig.clone() };
        <BlsConsensusVerifier as Verifier<TestVote>>::verify_vote(&verifier, &good).unwrap();

        // Wrong rank → reconstructed message differs → invalid signature.
        let wrong_rank = TestVote { id: voter_id.clone(), rank: rank + 1, payload: sig.clone() };
        let err = <BlsConsensusVerifier as Verifier<TestVote>>::verify_vote(&verifier, &wrong_rank)
            .unwrap_err();
        assert!(err.is_invalid_signature());

        // Unknown signer → InvalidSigner.
        let unknown = TestVote { id: b"stranger".to_vec(), rank, payload: sig };
        let err = <BlsConsensusVerifier as Verifier<TestVote>>::verify_vote(&verifier, &unknown)
            .unwrap_err();
        assert!(err.is_invalid_signer());
    }

    #[test]
    fn verify_qc_binds_aggregate_pubkey_to_committee() {
        use quil_consensus::committee::Replicas;
        use quil_consensus::models::WeightedIdentity;

        let (raw, bls, ds_tag) = bls_bundle();
        let filter = b"shard".to_vec();
        let state_id: Identity = "state-9".into();
        let rank = 9u64;
        let msg = make_vote_message(&filter, rank, &state_id);

        // The committee's one real member signs the canonical message.
        let (member_signer, member_pk) = bls.new_key().unwrap();
        let sig = member_signer.sign_with_domain(&msg, &ds_tag).unwrap();
        // What the binding will reconstruct from the bitmask-selected
        // member pubkeys.
        let reconstructed_pk = raw
            .aggregate(&[member_pk.as_slice()], &[sig.as_slice()])
            .unwrap()
            .public_key()
            .to_vec();

        // QC carrying an explicit bitmask (the test `BlsAggregatedSignature`
        // has none, so use a local agg).
        #[derive(Debug)]
        struct AggBm { sig: Vec<u8>, pk: Vec<u8>, bm: Vec<u8> }
        impl AggregatedSignature for AggBm {
            fn signature(&self) -> &[u8] { &self.sig }
            fn public_key(&self) -> &[u8] { &self.pk }
            fn bitmask(&self) -> &[u8] { &self.bm }
        }
        #[derive(Debug)]
        struct QcBm { rank: u64, id: Identity, filter: Vec<u8>, agg: AggBm }
        impl QuorumCertificate for QcBm {
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

        // 1-member committee returning the member's real pubkey.
        #[derive(Debug)]
        struct M { id: Identity, pk: Vec<u8> }
        impl WeightedIdentity for M {
            fn public_key(&self) -> &[u8] { &self.pk }
            fn identity(&self) -> &Identity { &self.id }
            fn weight(&self) -> u64 { 1 }
        }
        struct C { id: Identity, pk: Vec<u8> }
        impl Replicas for C {
            fn leader_for_rank(&self, _r: u64) -> Result<Identity> { Ok(self.id.clone()) }
            fn quorum_threshold_for_rank(&self, _r: u64) -> Result<u64> { Ok(1) }
            fn timeout_threshold_for_rank(&self, _r: u64) -> Result<u64> { Ok(1) }
            fn self_identity(&self) -> &Identity { &self.id }
            fn identities_by_rank(&self, _r: u64) -> Result<Vec<Box<dyn WeightedIdentity>>> {
                Ok(vec![Box::new(M { id: self.id.clone(), pk: self.pk.clone() })])
            }
            fn identity_by_rank(&self, _r: u64, pid: &Identity) -> Result<Box<dyn WeightedIdentity>> {
                if pid == &self.id {
                    Ok(Box::new(M { id: self.id.clone(), pk: self.pk.clone() }))
                } else {
                    Err(QuilError::InvalidSigner(hex::encode(pid)))
                }
            }
        }
        let committee: Arc<dyn Replicas> =
            Arc::new(C { id: b"m1".to_vec(), pk: member_pk.clone() });
        let verifier = BlsConsensusVerifier::new(
            raw as Arc<dyn SignatureAggregator>,
            ds_tag.clone(),
            ds_tag.clone(),
            committee,
            filter.clone(),
        );
        type V = crate::bls_verifier::tests::TestVote;

        // Honest QC: pk = committee-reconstructed aggregate, bit 0 set.
        let good = QcBm {
            rank,
            id: state_id.clone(),
            filter: filter.clone(),
            agg: AggBm { sig: sig.clone(), pk: reconstructed_pk.clone(), bm: vec![0b1] },
        };
        <BlsConsensusVerifier as Verifier<V>>::verify_quorum_certificate(&verifier, &good).unwrap();

        // FORGED QC: attacker signs the same message with their OWN key and
        // presents (attacker_pk, attacker_sig) under the same bitmask. The
        // signature is self-consistent, but the pk is not bound to the
        // committee → rejected before the (passable) signature check.
        let (attacker_signer, attacker_pk) = bls.new_key().unwrap();
        let attacker_sig = attacker_signer.sign_with_domain(&msg, &ds_tag).unwrap();
        let forged = QcBm {
            rank,
            id: state_id,
            filter,
            agg: AggBm { sig: attacker_sig, pk: attacker_pk, bm: vec![0b1] },
        };
        let err =
            <BlsConsensusVerifier as Verifier<V>>::verify_quorum_certificate(&verifier, &forged)
                .unwrap_err();
        assert!(err.is_invalid_quorum_certificate());
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

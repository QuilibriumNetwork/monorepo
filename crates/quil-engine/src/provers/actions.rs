//! Prover lifecycle action handlers. Builds and signs prover messages
//! (ProverJoin, ProverConfirm, ProverLeave, ProverReject) and wraps
//! them in MessageBundle canonical bytes.
//!
//! These are pure message construction functions — no VDF or network I/O.
//! VDF computation and gRPC submission happen in the node binary.

use quil_types::crypto::Signer;
use quil_types::error::Result;

use quil_execution::global_intrinsic::prover_join::ProverJoin;
use quil_execution::global_intrinsic::seniority_merge::SeniorityMerge;
use quil_execution::global_intrinsic::prover_ops::{ProverConfirm, ProverReject};
use quil_execution::global_intrinsic::prover_filter_ops::ProverLeave;
use quil_execution::global_intrinsic::sig_with_pop::SignatureWithPop;
use quil_execution::global_intrinsic::addressed_signature::AddressedSignature;
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

/// Build a signed ProverJoin wrapped in a MessageBundle.
///
/// Caller must have already computed the VDF proof bytes.
///
/// `merge_targets`: optional seniority merge data. Each merge target must
/// already be signed (signature populated). Pass empty vec for first-time joins.
pub fn build_join_bundle(
    filters: &[Vec<u8>],
    frame_number: u64,
    bls_pubkey: &[u8],
    bls_signer: &dyn Signer,
    prover_address: &[u8],
    proof: &[u8],
    merge_targets: Vec<SeniorityMerge>,
) -> Result<Vec<u8>> {
    // Build unsigned join for signing
    let unsigned = ProverJoin {
        filters: filters.to_vec(),
        frame_number,
        public_key_signature_bls48581: None,
        delegate_address: prover_address.to_vec(),
        merge_targets: merge_targets.clone(),
        proof: proof.to_vec(),
    };
    let join_message = unsigned.to_canonical_bytes()?;

    // Domain: poseidon(GLOBAL_INTRINSIC_ADDRESS || "PROVER_JOIN")
    let mut dp = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
    dp.extend_from_slice(b"PROVER_JOIN");
    let domain = quil_crypto::poseidon::hash_bytes_to_32(&dp)?;

    let sig = bls_signer.sign_with_domain(&join_message, &domain)?;
    let pop = bls_signer.sign_with_domain(bls_pubkey, b"BLS48_POP_SK")?;

    let signed = ProverJoin {
        filters: filters.to_vec(),
        frame_number,
        public_key_signature_bls48581: Some(SignatureWithPop {
            signature: sig,
            public_key: Some(bls_pubkey.to_vec()),
            pop_signature: pop,
        }),
        delegate_address: prover_address.to_vec(),
        merge_targets,
        proof: proof.to_vec(),
    };

    wrap_in_bundle(signed.to_canonical_bytes()?)
}

/// Build a signed ProverConfirm wrapped in a MessageBundle.
pub fn build_confirm_bundle(
    filters: &[Vec<u8>],
    frame_number: u64,
    bls_signer: &dyn Signer,
    prover_address: &[u8],
) -> Result<Vec<u8>> {
    let mut msg = Vec::new();
    for f in filters { msg.extend_from_slice(f); }
    msg.extend_from_slice(&frame_number.to_be_bytes());

    let mut dp = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
    dp.extend_from_slice(b"PROVER_CONFIRM");
    let domain = quil_crypto::poseidon::hash_bytes_to_32(&dp)?;

    let sig = bls_signer.sign_with_domain(&msg, &domain)?;

    let confirm = ProverConfirm {
        filter: vec![0u8; 32], // deprecated field — Go writes "reservedreserved..."
        frame_number,
        public_key_signature_bls48581: Some(AddressedSignature {
            signature: sig,
            address: prover_address.to_vec(),
        }),
        filters: filters.to_vec(),
    };

    wrap_in_bundle(confirm.to_canonical_bytes()?)
}

/// Build a signed ProverReject wrapped in a MessageBundle.
pub fn build_reject_bundle(
    filters: &[Vec<u8>],
    frame_number: u64,
    bls_signer: &dyn Signer,
    prover_address: &[u8],
) -> Result<Vec<u8>> {
    let mut msg = Vec::new();
    for f in filters { msg.extend_from_slice(f); }
    msg.extend_from_slice(&frame_number.to_be_bytes());

    let mut dp = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
    dp.extend_from_slice(b"PROVER_REJECT");
    let domain = quil_crypto::poseidon::hash_bytes_to_32(&dp)?;

    let sig = bls_signer.sign_with_domain(&msg, &domain)?;

    let reject = ProverReject {
        filter: vec![0u8; 32], // deprecated field
        frame_number,
        public_key_signature_bls48581: Some(AddressedSignature {
            signature: sig,
            address: prover_address.to_vec(),
        }),
        filters: filters.to_vec(),
    };

    wrap_in_bundle(reject.to_canonical_bytes()?)
}

/// Build a signed ProverLeave wrapped in a MessageBundle.
pub fn build_leave_bundle(
    filters: &[Vec<u8>],
    frame_number: u64,
    bls_signer: &dyn Signer,
    prover_address: &[u8],
) -> Result<Vec<u8>> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&(filters.len() as u32).to_be_bytes());
    for f in filters {
        msg.extend_from_slice(&(f.len() as u32).to_be_bytes());
        msg.extend_from_slice(f);
    }
    msg.extend_from_slice(&frame_number.to_be_bytes());

    let mut dp = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
    dp.extend_from_slice(b"PROVER_LEAVE");
    let domain = quil_crypto::poseidon::hash_bytes_to_32(&dp)?;

    let sig = bls_signer.sign_with_domain(&msg, &domain)?;

    let leave = ProverLeave {
        filters: filters.to_vec(),
        frame_number,
        public_key_signature_bls48581: Some(AddressedSignature {
            signature: sig,
            address: prover_address.to_vec(),
        }),
    };

    wrap_in_bundle(leave.to_canonical_bytes()?)
}

/// Build seniority merge helpers from the Ed448 peer key.
///
/// When re-joining, the Ed448 peer key signs the new BLS prover public key
/// with domain "PROVER_JOIN_MERGE". This lets the network link the new prover
/// identity to the old peer identity and transfer seniority.
pub fn build_merge_helpers(
    ed448_seed: &[u8; 57],
    bls_pubkey: &[u8],
) -> Result<Vec<SeniorityMerge>> {
    let ed448_privkey = ed448_rust::PrivateKey::from(*ed448_seed);
    let ed448_pubkey = ed448_rust::PublicKey::from(&ed448_privkey);
    let ed448_pubkey_bytes = ed448_pubkey.as_byte().to_vec();

    // Sign: domain || message (Go's Ed448Key.SignWithDomain prepends domain to message)
    // See node/keys/ed448_key.go:79: Sign(rand, concat(domain, message), 0)
    let mut sign_input = Vec::from(b"PROVER_JOIN_MERGE" as &[u8]);
    sign_input.extend_from_slice(bls_pubkey);
    let signature = ed448_privkey
        .sign(&sign_input, None) // empty context (Go uses ed448.Sign with "")
        .map_err(|e| quil_types::error::QuilError::Crypto(format!("Ed448 merge sign: {:?}", e)))?;

    Ok(vec![SeniorityMerge {
        signature: signature.to_vec(),
        key_type: 4, // KeyTypeEd448
        prover_public_key: ed448_pubkey_bytes,
    }])
}

/// Build a signed ShardSplit message bundle.
/// Submitted when a shard has >32 active provers.
pub fn build_shard_split_bundle(
    filter: &[u8],
    frame_number: u64,
    bls_signer: &dyn Signer,
    prover_address: &[u8],
) -> Result<Vec<u8>> {
    // Message: filter || frame_number
    let mut msg = Vec::new();
    msg.extend_from_slice(filter);
    msg.extend_from_slice(&frame_number.to_be_bytes());

    let mut dp = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
    dp.extend_from_slice(b"SHARD_SPLIT");
    let domain = quil_crypto::poseidon::hash_bytes_to_32(&dp)?;
    let sig = bls_signer.sign_with_domain(&msg, &domain)?;

    // Canonical bytes: [type_prefix][filter_len][filter][frame_number][sig_len][address][sig]
    let mut out = Vec::new();
    out.extend_from_slice(&0x031Eu32.to_be_bytes()); // TYPE_SHARD_SPLIT
    out.extend_from_slice(&(filter.len() as u32).to_be_bytes());
    out.extend_from_slice(filter);
    out.extend_from_slice(&frame_number.to_be_bytes());
    out.extend_from_slice(&(prover_address.len() as u32).to_be_bytes());
    out.extend_from_slice(prover_address);
    out.extend_from_slice(&(sig.len() as u32).to_be_bytes());
    out.extend_from_slice(&sig);

    wrap_in_bundle(out)
}

/// Build a signed ShardMerge message bundle.
/// Submitted when adjacent shards both have <6 active provers.
pub fn build_shard_merge_bundle(
    filter_left: &[u8],
    filter_right: &[u8],
    frame_number: u64,
    bls_signer: &dyn Signer,
    prover_address: &[u8],
) -> Result<Vec<u8>> {
    let mut msg = Vec::new();
    msg.extend_from_slice(filter_left);
    msg.extend_from_slice(filter_right);
    msg.extend_from_slice(&frame_number.to_be_bytes());

    let mut dp = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
    dp.extend_from_slice(b"SHARD_MERGE");
    let domain = quil_crypto::poseidon::hash_bytes_to_32(&dp)?;
    let sig = bls_signer.sign_with_domain(&msg, &domain)?;

    let mut out = Vec::new();
    out.extend_from_slice(&0x031Fu32.to_be_bytes()); // TYPE_SHARD_MERGE
    out.extend_from_slice(&(filter_left.len() as u32).to_be_bytes());
    out.extend_from_slice(filter_left);
    out.extend_from_slice(&(filter_right.len() as u32).to_be_bytes());
    out.extend_from_slice(filter_right);
    out.extend_from_slice(&frame_number.to_be_bytes());
    out.extend_from_slice(&(prover_address.len() as u32).to_be_bytes());
    out.extend_from_slice(prover_address);
    out.extend_from_slice(&(sig.len() as u32).to_be_bytes());
    out.extend_from_slice(&sig);

    wrap_in_bundle(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_crypto::Bls48581KeyConstructor;
    use quil_types::crypto::BlsConstructor;

    /// Decode a bundle's single inner request bytes (after stripping the
    /// CanonicalMessageRequest envelope). Asserts there is exactly one
    /// request and returns the inner payload bytes.
    fn decode_single_inner(bundle_bytes: &[u8]) -> Vec<u8> {
        let bundle = CanonicalMessageBundle::from_canonical_bytes(bundle_bytes)
            .expect("bundle decodes");
        assert_eq!(bundle.requests.len(), 1, "exactly one request expected");
        let req = bundle.requests[0].as_ref().expect("request present");
        req.inner_bytes.clone()
    }

    /// Generate a real BLS keypair (signer + public key bytes).
    fn bls_keypair() -> (Box<dyn Signer>, Vec<u8>) {
        Bls48581KeyConstructor.new_key().expect("bls keypair")
    }

    #[test]
    fn join_bundle_round_trips_fields_and_signature() {
        let (signer, pk) = bls_keypair();
        let filters = vec![vec![0x01u8; 32], vec![0x02u8; 32]];
        let frame_number = 12345u64;
        let address = vec![0x07u8; 32];
        let proof = vec![0x09u8; 64];

        let bytes = build_join_bundle(
            &filters,
            frame_number,
            &pk,
            signer.as_ref(),
            &address,
            &proof,
            Vec::new(),
        )
        .expect("build join");

        let inner = decode_single_inner(&bytes);
        let join = ProverJoin::from_canonical_bytes(&inner).expect("join decodes");
        assert_eq!(join.filters, filters);
        assert_eq!(join.frame_number, frame_number);
        assert_eq!(join.delegate_address, address);
        assert_eq!(join.proof, proof);
        assert!(join.merge_targets.is_empty());
        let sig = join
            .public_key_signature_bls48581
            .expect("signature present");
        assert_eq!(sig.public_key.as_deref(), Some(pk.as_slice()));
        assert!(!sig.signature.is_empty());
        assert!(!sig.pop_signature.is_empty());
    }

    #[test]
    fn join_bundle_signature_verifies_under_domain() {
        let (signer, pk) = bls_keypair();
        let filters = vec![vec![0x03u8; 32]];
        let frame_number = 99u64;
        let address = vec![0x07u8; 32];
        let proof = vec![0x09u8; 32];

        let bytes = build_join_bundle(
            &filters, frame_number, &pk, signer.as_ref(), &address, &proof, Vec::new(),
        )
        .unwrap();
        let inner = decode_single_inner(&bytes);
        let join = ProverJoin::from_canonical_bytes(&inner).unwrap();
        let sig = join.public_key_signature_bls48581.unwrap();

        // Reconstruct the signed message and domain, then verify.
        let unsigned = ProverJoin {
            filters: filters.clone(),
            frame_number,
            public_key_signature_bls48581: None,
            delegate_address: address.clone(),
            merge_targets: Vec::new(),
            proof: proof.clone(),
        };
        let join_message = unsigned.to_canonical_bytes().unwrap();
        let mut dp = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
        dp.extend_from_slice(b"PROVER_JOIN");
        let domain = quil_crypto::poseidon::hash_bytes_to_32(&dp).unwrap();

        let bls = Bls48581KeyConstructor;
        assert!(bls.verify_signature_raw(&pk, &sig.signature, &join_message, &domain));
        // POP signature verifies over the pubkey under the POP domain.
        assert!(bls.verify_signature_raw(&pk, &sig.pop_signature, &pk, b"BLS48_POP_SK"));
    }

    #[test]
    fn join_bundle_carries_merge_targets() {
        let (signer, pk) = bls_keypair();
        let merge = SeniorityMerge {
            signature: vec![0xAAu8; 114],
            key_type: 4,
            prover_public_key: vec![0xBBu8; 57],
        };
        let bytes = build_join_bundle(
            &[vec![0x01u8; 32]],
            1,
            &pk,
            signer.as_ref(),
            &[0x07u8; 32],
            &[0x09u8; 8],
            vec![merge.clone()],
        )
        .unwrap();
        let inner = decode_single_inner(&bytes);
        let join = ProverJoin::from_canonical_bytes(&inner).unwrap();
        assert_eq!(join.merge_targets.len(), 1);
        assert_eq!(join.merge_targets[0].key_type, 4);
        assert_eq!(join.merge_targets[0].prover_public_key, vec![0xBBu8; 57]);
    }

    #[test]
    fn confirm_bundle_round_trips_fields() {
        let (signer, _pk) = bls_keypair();
        let filters = vec![vec![0x05u8; 32]];
        let frame_number = 777u64;
        let address = vec![0x42u8; 32];

        let bytes =
            build_confirm_bundle(&filters, frame_number, signer.as_ref(), &address).unwrap();
        let inner = decode_single_inner(&bytes);
        let confirm = ProverConfirm::from_canonical_bytes(&inner).expect("confirm decodes");
        assert_eq!(confirm.filters, filters);
        assert_eq!(confirm.frame_number, frame_number);
        // deprecated `filter` field decodes to a 32-byte placeholder.
        assert_eq!(confirm.filter.len(), 32);
        let sig = confirm.public_key_signature_bls48581.expect("sig present");
        assert_eq!(sig.address, address);
        assert!(!sig.signature.is_empty());
    }

    #[test]
    fn reject_bundle_round_trips_fields() {
        let (signer, _pk) = bls_keypair();
        let filters = vec![vec![0x06u8; 32], vec![0x07u8; 32]];
        let frame_number = 4242u64;
        let address = vec![0x11u8; 32];

        let bytes =
            build_reject_bundle(&filters, frame_number, signer.as_ref(), &address).unwrap();
        let inner = decode_single_inner(&bytes);
        let reject = ProverReject::from_canonical_bytes(&inner).expect("reject decodes");
        assert_eq!(reject.filters, filters);
        assert_eq!(reject.frame_number, frame_number);
        let sig = reject.public_key_signature_bls48581.expect("sig present");
        assert_eq!(sig.address, address);
    }

    #[test]
    fn leave_bundle_round_trips_fields() {
        let (signer, _pk) = bls_keypair();
        let filters = vec![vec![0x08u8; 32]];
        let frame_number = 314u64;
        let address = vec![0x21u8; 32];

        let bytes =
            build_leave_bundle(&filters, frame_number, signer.as_ref(), &address).unwrap();
        let inner = decode_single_inner(&bytes);
        let leave = ProverLeave::from_canonical_bytes(&inner).expect("leave decodes");
        assert_eq!(leave.filters, filters);
        assert_eq!(leave.frame_number, frame_number);
        let sig = leave.public_key_signature_bls48581.expect("sig present");
        assert_eq!(sig.address, address);
    }

    #[test]
    fn confirm_signature_verifies_under_domain() {
        let (signer, pk) = bls_keypair();
        let filters = vec![vec![0x05u8; 32]];
        let frame_number = 777u64;
        let address = vec![0x42u8; 32];

        let bytes =
            build_confirm_bundle(&filters, frame_number, signer.as_ref(), &address).unwrap();
        let inner = decode_single_inner(&bytes);
        let confirm = ProverConfirm::from_canonical_bytes(&inner).unwrap();
        let sig = confirm.public_key_signature_bls48581.unwrap();

        // Recompute the signed message: concat(filters) || frame_number BE.
        let mut msg = Vec::new();
        for f in &filters {
            msg.extend_from_slice(f);
        }
        msg.extend_from_slice(&frame_number.to_be_bytes());
        let mut dp = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
        dp.extend_from_slice(b"PROVER_CONFIRM");
        let domain = quil_crypto::poseidon::hash_bytes_to_32(&dp).unwrap();

        let bls = Bls48581KeyConstructor;
        assert!(bls.verify_signature_raw(&pk, &sig.signature, &msg, &domain));
    }

    #[test]
    fn merge_helpers_signs_bls_pubkey_with_ed448() {
        let seed = [0x42u8; 57];
        let bls_pubkey = vec![0xCDu8; 585];
        let merges = build_merge_helpers(&seed, &bls_pubkey).expect("merge helpers");
        assert_eq!(merges.len(), 1);
        let m = &merges[0];
        assert_eq!(m.key_type, 4);
        assert!(!m.signature.is_empty());

        // The prover_public_key must be the Ed448 public key derived
        // from the seed, and the signature must verify over
        // "PROVER_JOIN_MERGE" || bls_pubkey.
        let priv_key = ed448_rust::PrivateKey::from(seed);
        let pub_key = ed448_rust::PublicKey::from(&priv_key);
        assert_eq!(m.prover_public_key, pub_key.as_byte().to_vec());

        let mut sign_input = Vec::from(b"PROVER_JOIN_MERGE" as &[u8]);
        sign_input.extend_from_slice(&bls_pubkey);
        assert!(pub_key
            .verify(&sign_input, &m.signature, None)
            .is_ok());
    }

    #[test]
    fn shard_split_bundle_has_correct_type_and_fields() {
        let (signer, _pk) = bls_keypair();
        let filter = vec![0x33u8; 32];
        let frame_number = 5000u64;
        let address = vec![0x44u8; 32];

        let bytes =
            build_shard_split_bundle(&filter, frame_number, signer.as_ref(), &address).unwrap();
        let inner = decode_single_inner(&bytes);

        // inner layout: [type 0x031E][filter_len][filter][frame#][addr_len][addr][sig_len][sig]
        assert_eq!(&inner[0..4], &0x031Eu32.to_be_bytes());
        let mut cur = 4usize;
        let flen = u32::from_be_bytes(inner[cur..cur + 4].try_into().unwrap()) as usize;
        cur += 4;
        assert_eq!(&inner[cur..cur + flen], filter.as_slice());
        cur += flen;
        let fnum = u64::from_be_bytes(inner[cur..cur + 8].try_into().unwrap());
        cur += 8;
        assert_eq!(fnum, frame_number);
        let alen = u32::from_be_bytes(inner[cur..cur + 4].try_into().unwrap()) as usize;
        cur += 4;
        assert_eq!(&inner[cur..cur + alen], address.as_slice());
        cur += alen;
        let slen = u32::from_be_bytes(inner[cur..cur + 4].try_into().unwrap()) as usize;
        assert!(slen > 0, "signature must be present");
    }

    #[test]
    fn shard_merge_bundle_has_correct_type_and_both_filters() {
        let (signer, _pk) = bls_keypair();
        let left = vec![0x55u8; 32];
        let right = vec![0x66u8; 32];
        let frame_number = 6000u64;
        let address = vec![0x77u8; 32];

        let bytes = build_shard_merge_bundle(
            &left, &right, frame_number, signer.as_ref(), &address,
        )
        .unwrap();
        let inner = decode_single_inner(&bytes);
        assert_eq!(&inner[0..4], &0x031Fu32.to_be_bytes());

        let mut cur = 4usize;
        let llen = u32::from_be_bytes(inner[cur..cur + 4].try_into().unwrap()) as usize;
        cur += 4;
        assert_eq!(&inner[cur..cur + llen], left.as_slice());
        cur += llen;
        let rlen = u32::from_be_bytes(inner[cur..cur + 4].try_into().unwrap()) as usize;
        cur += 4;
        assert_eq!(&inner[cur..cur + rlen], right.as_slice());
        cur += rlen;
        let fnum = u64::from_be_bytes(inner[cur..cur + 8].try_into().unwrap());
        assert_eq!(fnum, frame_number);
    }

    #[test]
    fn shard_split_and_merge_have_distinct_type_prefixes() {
        let (signer, _pk) = bls_keypair();
        let split = build_shard_split_bundle(&[0x01u8; 32], 1, signer.as_ref(), &[0x02u8; 32])
            .unwrap();
        let merge = build_shard_merge_bundle(
            &[0x01u8; 32], &[0x03u8; 32], 1, signer.as_ref(), &[0x02u8; 32],
        )
        .unwrap();
        let split_inner = decode_single_inner(&split);
        let merge_inner = decode_single_inner(&merge);
        assert_ne!(&split_inner[0..4], &merge_inner[0..4]);
    }

    #[test]
    fn empty_filters_still_produce_decodable_bundle() {
        let (signer, _pk) = bls_keypair();
        let bytes = build_leave_bundle(&[], 0, signer.as_ref(), &[0x01u8; 32]).unwrap();
        let inner = decode_single_inner(&bytes);
        let leave = ProverLeave::from_canonical_bytes(&inner).unwrap();
        assert!(leave.filters.is_empty());
        assert_eq!(leave.frame_number, 0);
    }
}

/// Wrap encoded prover operation bytes in a MessageBundle.
fn wrap_in_bundle(op_bytes: Vec<u8>) -> Result<Vec<u8>> {
    let req = CanonicalMessageRequest::wrap(op_bytes)?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let bundle = CanonicalMessageBundle {
        requests: vec![Some(req)],
        timestamp: now_ms,
    };
    bundle.to_canonical_bytes()
}

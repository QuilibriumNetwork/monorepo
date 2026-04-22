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

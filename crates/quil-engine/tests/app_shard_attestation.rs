//! Round-trip test for app shard FrameHeader attestation.
//!
//! What we're guarding against: every time the producer's signing
//! payload, signing domain, aggregate-pubkey reconciliation, bitmask
//! encoding, or multi-proof packing has drifted from what the
//! archive's `verify_frame_header_attestation` expects, archives
//! reject every frame with `aggregate BLS + multi-proof check
//! failed` (or worse: silent skip at the materializer). Catching
//! that loop in a Rust-only test takes seconds; chasing it across
//! the testnet takes the better part of a day.
//!
//! The test reconstructs the producer side end-to-end with real
//! crypto:
//!   1. Build N active provers in the registry with real BLS keys.
//!   2. Build a canonical app-shard `AppShardState` and its VDF-proved
//!      `FrameHeader` via `WesolowskiFrameProver::prove_frame_header`.
//!   3. Each prover signs `make_vote_message(app_address, rank,
//!      poseidon(output))` under domain `"appshard" || app_address` —
//!      matching `app_engine::start_consensus` + Go's
//!      `consensus_voting_provider.go`.
//!   4. Aggregate the per-signer BLS sigs and (for N>1) compute each
//!      signer's Wesolowski multi-proof. Pack as
//!      `bls_agg(74) || u32_be(N) || N×516 multi-proofs`.
//!   5. Embed the canonical `AggregateSignature` in the FrameHeader's
//!      `public_key_signature_bls48581` field.
//!   6. Call `verify_frame_header_attestation` with the same active
//!      provers list the archive would build. Assert success.
//!
//! The two scenarios cover the codepaths that drift in practice:
//!   - Single-prover (74-byte BLS agg, no multi-proof tail) — the
//!     common testnet shape.
//!   - 3-prover (74 + 3×516 = 1622-byte sig, multi-proof tail
//!     verified). Catches multi-proof packing + per-signer challenge
//!     derivation regressions.

use std::sync::Arc;

use quil_consensus::models::{State, Unique};
use quil_consensus::verification::make_vote_message;
use quil_consensus::voting_provider::VotingProvider;
use quil_crypto::{Bls48581KeyConstructor, WesolowskiFrameProver};
use quil_engine::app_types::{AppShardState, AppShardVote, AppShardVoteFactory};
use quil_engine::voting_provider::{AddressDerivation, BlsVotingProvider};
use quil_execution::global_intrinsic::frame_header::FrameHeader;
use quil_execution::global_intrinsic::prover_shard_update::verify_frame_header_attestation;
use quil_execution::hypergraph_intrinsic::canonical::{
    AggregateSignature, Bls48581G2PublicKey,
};
use quil_types::consensus::{
    ProverAllocationInfo, ProverInfo, ProverStatus,
};
use quil_types::crypto::{BlsConstructor, FrameProver, Signer};

/// Compute the app shard's wire address: `poseidon(filter)`. Mirrors
/// `app_engine::new_with_filter` at `app_engine.rs:530`.
fn app_address_from_filter(filter: &[u8]) -> Vec<u8> {
    quil_crypto::poseidon::hash_bytes_to_32(filter)
        .expect("poseidon hash")
        .to_vec()
}

/// Build a deterministic 32-byte filter for the test.
fn test_filter() -> Vec<u8> {
    let mut f = vec![0u8; 32];
    f[0] = 0x11;
    f[31] = 0xff;
    f
}

/// Spin up `n` BLS keypairs and the matching `ProverInfo` rows that
/// `verify_frame_header_attestation` will iterate via
/// `prover_registry.get_active_provers(filter)`. Addresses are
/// `poseidon(pubkey_g2)` and the resulting list is sorted by address
/// — `RocksProverRegistry`'s `filter_cache` keeps addresses in
/// sorted order, so the archive will see the same ordering; if we
/// hand the verifier any other order the bitmask indexes pick up
/// wrong pubkeys.
fn build_committee(
    bls: &dyn BlsConstructor,
    n: usize,
    filter: &[u8],
) -> Vec<(Box<dyn Signer>, ProverInfo)> {
    let mut signers: Vec<(Box<dyn Signer>, ProverInfo)> = Vec::with_capacity(n);
    for _ in 0..n {
        let (signer, pubkey) = bls.new_key().expect("bls new_key");
        let address = quil_crypto::poseidon::hash_bytes_to_32(&pubkey)
            .expect("poseidon address")
            .to_vec();
        let info = ProverInfo {
            public_key: pubkey,
            address,
            status: ProverStatus::Active,
            kick_frame_number: 0,
            allocations: vec![ProverAllocationInfo {
                status: ProverStatus::Active,
                confirmation_filter: filter.to_vec(),
                rejection_filter: Vec::new(),
                join_frame_number: 0,
                leave_frame_number: 0,
                pause_frame_number: 0,
                resume_frame_number: 0,
                kick_frame_number: 0,
                join_confirm_frame_number: 0,
                join_reject_frame_number: 0,
                leave_confirm_frame_number: 0,
                leave_reject_frame_number: 0,
                last_active_frame_number: 0,
                vertex_address: Vec::new(),
            }],
            available_storage: 0,
            seniority: 1000,
            delegate_address: Vec::new(),
        };
        signers.push((signer, info));
    }
    // Match the registry's `filter_cache` ordering: addresses sorted
    // lexicographically. The verifier loop walks active provers in
    // this exact order and pulls pubkeys by the bitmask bit index.
    signers.sort_by(|a, b| a.1.address.cmp(&b.1.address));
    signers
}

/// Build the bitmask that names all signers at indices `0..n`. Each
/// byte holds 8 bits, bit i = signer at committee index i. Matches
/// `quil_consensus::signature_aggregator::build_bitmask`.
fn bitmask_full(n: usize) -> Vec<u8> {
    let len = (n + 7) / 8;
    let mut bm = vec![0u8; len];
    for i in 0..n {
        bm[i / 8] |= 1u8 << (i % 8);
    }
    bm
}

/// Build a canonical app-shard `FrameHeader` where the committee has
/// `committee_size` active provers but only `signer_count` of them
/// sign. This is the realistic shape — a multi-prover committee
/// where a single leader's self-vote forms a QC (testnet 1-of-N
/// quorum cases). Catches the asymmetry between the attestation
/// verifier (which short-circuits `74-byte sig → ids=None`) and any
/// downstream caller that forgets the short-circuit.
fn build_and_verify_partial(
    committee_size: usize,
    signer_count: usize,
) -> Result<(quil_execution::global_intrinsic::frame_header::FrameHeader, Vec<ProverInfo>), Box<dyn std::error::Error>>
{
    assert!(signer_count >= 1 && signer_count <= committee_size);
    let bls = Bls48581KeyConstructor;
    let frame_prover = WesolowskiFrameProver::new(2048);
    let filter = test_filter();
    let app_address = filter.clone(); // live invariant — Go alias

    let signers = build_committee(&bls, committee_size, &filter);
    let active_provers: Vec<ProverInfo> =
        signers.iter().map(|(_, info)| info.clone()).collect();
    let prover_address = active_provers[0].address.clone();
    let requests_root = vec![0u8; 64];
    let state_roots: Vec<Vec<u8>> = vec![vec![0u8; 74]; 4];
    let difficulty: u32 = 200;
    let timestamp: i64 = 1_700_000_000_000;
    let frame_number: u64 = 1;
    let rank: u64 = 42;
    let fee_multiplier_vote: u64 = 0;

    let proto = frame_prover.prove_frame_header(
        &[], &app_address, &requests_root, &state_roots,
        &prover_address, timestamp, difficulty, fee_multiplier_vote, frame_number,
    )?;

    let identity = quil_crypto::poseidon::hash_bytes_to_32(&proto.output)?.to_vec();
    let vote_payload = make_vote_message(&app_address, rank, &identity);
    let mut domain = b"appshard".to_vec();
    domain.extend_from_slice(&app_address);

    // Only the first `signer_count` provers actually sign.
    let mut sigs: Vec<Vec<u8>> = Vec::with_capacity(signer_count);
    let mut pks: Vec<Vec<u8>> = Vec::with_capacity(signer_count);
    for (signer, info) in signers.iter().take(signer_count) {
        sigs.push(signer.sign_with_domain(&vote_payload, &domain)?);
        pks.push(info.public_key.clone());
    }
    let pk_refs: Vec<&[u8]> = pks.iter().map(|v| v.as_slice()).collect();
    let sig_refs: Vec<&[u8]> = sigs.iter().map(|v| v.as_slice()).collect();
    let agg = bls.aggregate(&pk_refs, &sig_refs)?;
    assert_eq!(agg.signature.len(), 74);

    // Bitmask covers ONLY the first `signer_count` positions, even
    // though `committee_size` may be larger. Each committee member
    // sits at its position in the sorted-address committee, so bits
    // 0..signer_count are set.
    let bitmask = {
        let len = (committee_size + 7) / 8;
        let mut bm = vec![0u8; len];
        for i in 0..signer_count {
            bm[i / 8] |= 1u8 << (i % 8);
        }
        bm
    };

    // For multi-signer with multi-prover committee, pack the
    // multi-proof tail. For single-signer (`signer_count == 1`) we
    // intentionally keep the 74-byte single-aggregate layout — that
    // covers the regression we just hit where the validate path
    // mistakenly demanded a multi-proof tail.
    let packed_sig: Vec<u8> = if signer_count <= 1 {
        agg.signature.clone()
    } else {
        use sha3::{Digest, Sha3_256};
        let challenge: [u8; 32] = Sha3_256::digest(&proto.parent_selector).into();
        let ids: Vec<&[u8]> =
            active_provers.iter().map(|p| p.address.as_slice()).collect();
        let mut proofs: Vec<Vec<u8>> = Vec::with_capacity(signer_count);
        for i in 0..signer_count {
            proofs.push(frame_prover.calculate_multi_proof(
                &challenge,
                difficulty,
                &ids,
                i as u32,
            )?);
        }
        let mut packed = Vec::with_capacity(74 + 4 + 516 * signer_count);
        packed.extend_from_slice(&agg.signature);
        packed.extend_from_slice(&(signer_count as u32).to_be_bytes());
        for p in &proofs {
            packed.extend_from_slice(p);
        }
        packed
    };

    let agg_canonical = AggregateSignature {
        signature: packed_sig,
        public_key: Some(Bls48581G2PublicKey {
            key_value: agg.public_key,
        }),
        bitmask,
    };

    let frame_header = FrameHeader {
        address: app_address,
        frame_number,
        rank,
        timestamp,
        difficulty,
        output: proto.output,
        parent_selector: proto.parent_selector,
        requests_root,
        state_roots,
        prover: prover_address,
        fee_multiplier_vote: fee_multiplier_vote as i64,
        public_key_signature_bls48581: agg_canonical.to_canonical_bytes()?,
    };

    let returned = verify_frame_header_attestation(
        &frame_header,
        &frame_prover,
        &bls,
        &active_provers,
    )?;
    assert_eq!(returned.len(), (committee_size + 7) / 8);
    Ok((frame_header, active_provers))
}

/// Single signer, but the committee has THREE active provers.
/// Reproduces the live testnet case where the local prover is the
/// only one voting on its shard's frames but the committee includes
/// archives that don't actively participate. The QC's aggregate is
/// still a single-signer 74-byte BLS sig (no multi-proof tail
/// needed), and the verifier MUST short-circuit on the 74-byte
/// path. Both `verify_frame_header_attestation` (the attestation
/// path) and the validate-message path in `intrinsic.rs::validate`
/// must apply the same short-circuit; a previous regression
/// unconditionally requested multi-proof verification, fell off the
/// end of the empty tail, and rejected every single-signer frame.
#[test]
fn single_signer_with_three_prover_committee_verifies() {
    build_and_verify_partial(/*committee_size=*/ 3, /*signer_count=*/ 1)
        .expect("single signer on a 3-prover committee must verify (74-byte sig short-circuit)");
}

fn build_and_verify(committee_size: usize) -> Result<(), Box<dyn std::error::Error>> {
    let bls = Bls48581KeyConstructor;
    // 2048-bit Wesolowski VDF, same as mainnet (`main.rs:765`).
    let frame_prover = WesolowskiFrameProver::new(2048);
    let filter = test_filter();
    let app_address = app_address_from_filter(&filter);

    // 1. Build the committee + signers.
    let signers = build_committee(&bls, committee_size, &filter);
    let active_provers: Vec<ProverInfo> =
        signers.iter().map(|(_, info)| info.clone()).collect();

    // 2. Run the VDF for the frame header. Genesis-like parent so the
    //    test stays cheap; we only need a valid output for the
    //    challenge poseidon-input round-trip.
    let prover_address = active_provers[0].address.clone();
    let requests_root = vec![0u8; 64]; // empty-frame root
    let state_roots: Vec<Vec<u8>> = vec![vec![0u8; 74]; 4];
    let difficulty: u32 = 200; // small enough to keep the test fast
    let timestamp: i64 = 1_700_000_000_000;
    let frame_number: u64 = 1;
    let rank: u64 = 42;
    let fee_multiplier_vote: u64 = 0;

    let proto = frame_prover.prove_frame_header(
        &[],                              // previous_frame_output
        &app_address,                     // address — must match verifier
        &requests_root,
        &state_roots,
        &prover_address,
        timestamp,
        difficulty,
        fee_multiplier_vote,
        frame_number,
    )?;

    // 3. Each signer produces a vote. The payload + domain must
    //    byte-exactly match what the verifier reconstructs.
    let identity =
        quil_crypto::poseidon::hash_bytes_to_32(&proto.output)?.to_vec();
    let vote_payload = make_vote_message(&app_address, rank, &identity);
    let mut domain = b"appshard".to_vec();
    domain.extend_from_slice(&app_address);

    let mut per_signer_sigs: Vec<Vec<u8>> = Vec::with_capacity(committee_size);
    let mut per_signer_pks: Vec<Vec<u8>> = Vec::with_capacity(committee_size);
    for (signer, info) in &signers {
        let sig = signer.sign_with_domain(&vote_payload, &domain)?;
        per_signer_sigs.push(sig);
        per_signer_pks.push(info.public_key.clone());
    }

    // 4. Aggregate. For multi-prover the verifier also requires the
    //    Wesolowski multi-proof tail.
    let pk_refs: Vec<&[u8]> = per_signer_pks.iter().map(|v| v.as_slice()).collect();
    let sig_refs: Vec<&[u8]> = per_signer_sigs.iter().map(|v| v.as_slice()).collect();
    let agg = bls.aggregate(&pk_refs, &sig_refs)?;
    assert_eq!(agg.signature.len(), 74, "BLS aggregate signature is 74 bytes");

    let packed_sig: Vec<u8> = if committee_size <= 1 {
        agg.signature.clone()
    } else {
        // Compute each signer's 516-byte multi-proof:
        //   challenge = sha3(parent_selector), index = i in committee,
        //   ids = committee.address[]. Matches the producer in
        //   `app_engine::start_consensus` → `ShardMultiProofPrecomputer`.
        use sha3::{Digest, Sha3_256};
        let challenge: [u8; 32] = Sha3_256::digest(&proto.parent_selector).into();
        let ids: Vec<&[u8]> = active_provers
            .iter()
            .map(|p| p.address.as_slice())
            .collect();
        let mut multi_proofs: Vec<Vec<u8>> = Vec::with_capacity(committee_size);
        for i in 0..committee_size {
            let proof = frame_prover.calculate_multi_proof(
                &challenge,
                difficulty,
                &ids,
                i as u32,
            )?;
            assert_eq!(proof.len(), 516);
            multi_proofs.push(proof);
        }
        let mut packed = Vec::with_capacity(74 + 4 + 516 * committee_size);
        packed.extend_from_slice(&agg.signature);
        packed.extend_from_slice(&(committee_size as u32).to_be_bytes());
        for mp in &multi_proofs {
            packed.extend_from_slice(mp);
        }
        packed
    };

    // 5. Build the canonical `AggregateSignature` blob the FrameHeader
    //    embeds, then embed it. Bitmask covers all committee
    //    positions because every signer in this test signs.
    let bitmask = bitmask_full(committee_size);
    let agg_canonical = AggregateSignature {
        signature: packed_sig,
        public_key: Some(Bls48581G2PublicKey {
            key_value: agg.public_key.clone(),
        }),
        bitmask: bitmask.clone(),
    };
    let agg_canonical_bytes = agg_canonical.to_canonical_bytes()?;

    let frame_header = FrameHeader {
        address: app_address.clone(),
        frame_number,
        rank,
        timestamp,
        difficulty,
        output: proto.output.clone(),
        parent_selector: proto.parent_selector.clone(),
        requests_root,
        state_roots,
        prover: prover_address,
        fee_multiplier_vote: fee_multiplier_vote as i64,
        public_key_signature_bls48581: agg_canonical_bytes,
    };

    // 6. Verify — must succeed. The function's return value is the
    //    raw bitmask, which we cross-check against what we emitted.
    let recovered_bitmask = verify_frame_header_attestation(
        &frame_header,
        &frame_prover,
        &bls,
        &active_provers,
    )?;
    assert_eq!(
        recovered_bitmask, bitmask,
        "verifier-returned bitmask differs from producer's"
    );
    Ok(())
}

#[test]
fn single_prover_frame_header_round_trips() {
    build_and_verify(1).expect("single-prover attestation should verify");
}

/// Multi-prover wire format covers the count + N×516 multi-proof
/// tail. Catches packing-order regressions: per-signer multi-proofs
/// must be emitted in committee-index order (which is sorted
/// address order) so the verifier walks them in lockstep with the
/// bitmask-derived participant ids. Mis-order = "aggregate BLS +
/// multi-proof check failed" on the archive.
///
/// The canonical decoder's length gate was intentionally diverged
/// from Go to accept this `74 + 4 + N×516` layout — Go's gate
/// rejects every multi-prover blob before signature math runs,
/// which is a dormant bug there but a real blocker for us.
#[test]
fn three_prover_frame_header_round_trips() {
    build_and_verify(3).expect("three-prover attestation should verify");
}

/// Catches the regression that prompted this whole test: the
/// producer used to sign `make_vote_message(filter, rank, identity)`
/// (raw 32-byte shard filter) while the verifier reconstructs
/// `make_vote_message(header.address, rank, identity)` where
/// `header.address = app_address = poseidon(filter)`. Even with a
/// single signer the aggregate-pubkey-reconciliation check still
/// passes (it doesn't depend on the message), but the BLS verify of
/// the agg sig over the payload fails. Verifying the inverse — that
/// signing with `filter` and expecting a verify success FAILS —
/// pins the contract so the next refactor can't silently break it.
#[test]
fn signing_with_raw_filter_instead_of_app_address_must_fail_verify() {
    let bls = Bls48581KeyConstructor;
    // 2048-bit Wesolowski VDF, same as mainnet (`main.rs:765`).
    let frame_prover = WesolowskiFrameProver::new(2048);
    let filter = test_filter();
    let app_address = app_address_from_filter(&filter);

    let signers = build_committee(&bls, 1, &filter);
    let active_provers: Vec<ProverInfo> =
        signers.iter().map(|(_, info)| info.clone()).collect();
    let prover_address = active_provers[0].address.clone();
    let requests_root = vec![0u8; 64];
    let state_roots: Vec<Vec<u8>> = vec![vec![0u8; 74]; 4];
    let difficulty: u32 = 200;
    let timestamp: i64 = 1_700_000_000_000;
    let frame_number: u64 = 1;
    let rank: u64 = 42;

    let proto = frame_prover
        .prove_frame_header(
            &[],
            &app_address,
            &requests_root,
            &state_roots,
            &prover_address,
            timestamp,
            difficulty,
            0,
            frame_number,
        )
        .unwrap();

    let identity = quil_crypto::poseidon::hash_bytes_to_32(&proto.output)
        .unwrap()
        .to_vec();
    // BUG SHAPE: use raw filter in payload (what the old code did).
    let bogus_payload = make_vote_message(&filter, rank, &identity);
    // Domain stays correct so we isolate the payload-field bug.
    let mut domain = b"appshard".to_vec();
    domain.extend_from_slice(&app_address);
    let sig = signers[0]
        .0
        .sign_with_domain(&bogus_payload, &domain)
        .unwrap();
    let agg = bls
        .aggregate(&[signers[0].1.public_key.as_slice()], &[sig.as_slice()])
        .unwrap();

    let agg_canonical = AggregateSignature {
        signature: agg.signature,
        public_key: Some(Bls48581G2PublicKey {
            key_value: agg.public_key,
        }),
        bitmask: bitmask_full(1),
    };
    let frame_header = FrameHeader {
        address: app_address,
        frame_number,
        rank,
        timestamp,
        difficulty,
        output: proto.output,
        parent_selector: proto.parent_selector,
        requests_root,
        state_roots,
        prover: prover_address,
        fee_multiplier_vote: 0,
        public_key_signature_bls48581: agg_canonical.to_canonical_bytes().unwrap(),
    };

    let result = verify_frame_header_attestation(
        &frame_header,
        &frame_prover,
        &bls,
        &active_provers,
    );
    assert!(
        result.is_err(),
        "expected verifier to reject sig over raw-filter payload, got {:?}",
        result
    );
}

// =====================================================================
// Production-wiring tests
// =====================================================================
//
// The tests above call `bls.sign_with_domain` + `bls.aggregate`
// directly. They prove the verifier round-trips when the producer
// signs the canonical payload + domain by hand. But the live
// failures we've been chasing aren't in the primitives — they're
// in the wiring between `BlsVotingProvider::sign_vote(state)`,
// `AppShardVoteFactory`, and the post-aggregation FrameHeader
// emission. The tests below drive that real wiring so a future
// regression in any field (sign_filter, vote_domain, identifier
// derivation, voter_address derivation) trips a unit test instead
// of a 15-minute testnet roundtrip.

/// Build a minimal `State<AppShardState>` whose identifier matches
/// the production-time derivation (`compute_output_identity(output) =
/// poseidon(output)` — see `app_types.rs`). The State's `rank` is
/// set independently of any AppShardState rank since the consensus
/// State wraps the AppShardState with its own pacemaker rank.
fn build_state(
    filter: &[u8],
    rank: u64,
    output: &[u8],
    parent_selector: &[u8],
    frame_number: u64,
) -> State<AppShardState> {
    let inner = AppShardState::new(
        filter.to_vec(),
        frame_number,
        rank,
        0,                 // timestamp
        200,               // difficulty
        output.to_vec(),
        parent_selector.to_vec(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        0,
    );
    let identity = <AppShardState as Unique>::identity(&inner).clone();
    State {
        rank,
        identifier: identity.clone(),
        proposer_id: Vec::new(),
        parent_qc_identity: identity,
        parent_qc_rank: rank.saturating_sub(1),
        parent_quorum_certificate: None,
        timestamp: 0,
        state: inner,
    }
}

/// End-to-end through the actual `BlsVotingProvider::sign_vote`
/// path that production uses. Catches:
///   - `sign_filter` field set to the wrong value (this whole
///     producer/verifier saga).
///   - `vote_domain` byte sequence diverging from `"appshard" ||
///     header.address`.
///   - `state.identifier` ≠ `poseidon(state.output)` (the verifier
///     reconstructs identity from `header.output`).
///   - `AppShardVoteFactory` failing to round-trip the signature
///     bytes onto the produced vote.
#[test]
fn bls_voting_provider_sign_vote_round_trips_through_verifier() {
    let bls: Arc<dyn BlsConstructor> = Arc::new(Bls48581KeyConstructor);
    let frame_prover = WesolowskiFrameProver::new(2048);
    let filter = test_filter();
    // Match the live invariant: `app_address = filter` (Go alias).
    let app_address = filter.clone();

    // Single signer at committee position 0.
    let (signer, pubkey) = bls.new_key().expect("bls new_key");
    let prover_address = quil_crypto::poseidon::hash_bytes_to_32(&pubkey)
        .expect("poseidon")
        .to_vec();
    let active_provers = vec![ProverInfo {
        public_key: pubkey.clone(),
        address: prover_address.clone(),
        status: ProverStatus::Active,
        kick_frame_number: 0,
        allocations: vec![ProverAllocationInfo {
            status: ProverStatus::Active,
            confirmation_filter: filter.clone(),
            rejection_filter: Vec::new(),
            join_frame_number: 0,
            leave_frame_number: 0,
            pause_frame_number: 0,
            resume_frame_number: 0,
            kick_frame_number: 0,
            join_confirm_frame_number: 0,
            join_reject_frame_number: 0,
            leave_confirm_frame_number: 0,
            leave_reject_frame_number: 0,
            last_active_frame_number: 0,
            vertex_address: Vec::new(),
        }],
        available_storage: 0,
        seniority: 1000,
        delegate_address: Vec::new(),
    }];

    // Generate a real VDF output so identity = poseidon(output)
    // matches what the verifier reconstructs from `header.output`.
    let proto = frame_prover
        .prove_frame_header(
            &[],
            &app_address,
            &vec![0u8; 64],
            &vec![vec![0u8; 74]; 4],
            &prover_address,
            1_700_000_000_000,
            200,
            0,
            1,
        )
        .expect("prove_frame_header");

    let rank: u64 = 42;
    let state = build_state(&filter, rank, &proto.output, &proto.parent_selector, 1);

    // Mirror the production wiring in `app_engine.rs::start_consensus`:
    //   sign_filter = self.app_address (now == filter),
    //   vote_domain = "appshard" || self.app_address,
    //   derive_address = poseidon(pubkey) → 32 bytes,
    //   factory = AppShardVoteFactory { filter }.
    let mut vote_domain = b"appshard".to_vec();
    vote_domain.extend_from_slice(&app_address);
    let mut timeout_domain = b"appshardtimeout".to_vec();
    timeout_domain.extend_from_slice(&app_address);
    let derive_address: AddressDerivation = Arc::new(|pk: &[u8]| {
        quil_crypto::poseidon::hash_bytes_to_32(pk)
            .unwrap_or_default()
            .to_vec()
    });
    let factory = Arc::new(AppShardVoteFactory {
        filter: filter.clone(),
    });
    let voting_provider: BlsVotingProvider<
        AppShardState,
        AppShardVote,
        AppShardVoteFactory,
    > = BlsVotingProvider::new_with_filter(
        Arc::from(signer),
        vote_domain,
        timeout_domain,
        derive_address,
        factory,
        // Critical: must equal `app_address`, NOT raw `filter` if
        // they differ. With the production fix they're the same.
        app_address.clone(),
    );

    let vote = voting_provider
        .sign_vote(&state)
        .expect("sign_vote must succeed");
    assert_eq!(vote.rank(), rank, "vote.rank reflects state.rank");

    // Aggregate just this single signer's vote. Production uses
    // `WeightedSignatureAggregatorImpl::aggregate` here, but for one
    // signer it reduces to `bls.aggregate([pk], [sig])`.
    let agg = bls
        .aggregate(&[pubkey.as_slice()], &[vote.signature_bytes.as_slice()])
        .expect("bls aggregate");
    assert_eq!(agg.signature.len(), 74);

    let agg_canonical = AggregateSignature {
        signature: agg.signature,
        public_key: Some(Bls48581G2PublicKey {
            key_value: agg.public_key,
        }),
        bitmask: bitmask_full(1),
    };
    let frame_header = FrameHeader {
        address: app_address,
        frame_number: 1,
        rank,
        timestamp: 1_700_000_000_000,
        difficulty: 200,
        output: proto.output,
        parent_selector: proto.parent_selector,
        requests_root: vec![0u8; 64],
        state_roots: vec![vec![0u8; 74]; 4],
        prover: prover_address,
        fee_multiplier_vote: 0,
        public_key_signature_bls48581: agg_canonical
            .to_canonical_bytes()
            .expect("canonical encode"),
    };

    let bitmask = verify_frame_header_attestation(
        &frame_header,
        &frame_prover,
        bls.as_ref(),
        &active_provers,
    )
    .expect("verify_frame_header_attestation must succeed end-to-end");
    assert_eq!(bitmask, vec![0x01u8]);
}

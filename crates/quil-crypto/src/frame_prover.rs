use std::collections::HashSet;
use std::sync::RwLock;

use quil_types::crypto::{BlsConstructor, FrameProver};
use quil_types::error::{QuilError, Result};
use quil_types::proto::global;

/// VDF-based frame prover using the Wesolowski VDF from the vdf crate.
pub struct WesolowskiFrameProver {
    /// VDF integer size in bits (typically 2048).
    pub int_size_bits: u16,
    /// Keys of shard-`FrameHeader` BLS signatures already verified in a
    /// batch this frame. `verify_frame_header_signature` skips the BLS
    /// pairing (keeps the VDF) when the header's key is present. A key is
    /// a hash of the FULL verification tuple (pubkey‖sig‖payload‖domain),
    /// so a present key can only ever short-circuit a signature that was
    /// actually verified valid over those exact inputs — safe for every
    /// caller, not just the materializer. Cleared per frame.
    bls_preverified: RwLock<HashSet<[u8; 32]>>,
}

impl WesolowskiFrameProver {
    pub fn new(int_size_bits: u16) -> Self {
        Self {
            int_size_bits,
            bls_preverified: RwLock::new(HashSet::new()),
        }
    }
}

/// Build the exact BLS verification inputs for a shard `FrameHeader`:
/// `(public_key, signature[..74], payload, domain)`. Mirrors
/// `verify_frame_header_signature` byte-for-byte so the batch path and
/// the per-header path agree. Returns `None` if the header lacks a
/// well-formed signature (the per-header path will reject it).
fn frame_header_bls_inputs(
    header: &global::FrameHeader,
) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let sig = header.public_key_signature_bls48581.as_ref()?;
    let pubkey = sig.public_key.as_ref().map(|k| k.key_value.clone()).unwrap_or_default();
    if pubkey.is_empty() || sig.signature.len() < 74 {
        return None;
    }
    let identity = crate::poseidon::hash_bytes_to_32(&header.output).ok()?;
    // payload = address || identity || rank_be (MakeVoteMessage)
    let mut payload = Vec::with_capacity(header.address.len() + 32 + 8);
    payload.extend_from_slice(&header.address);
    payload.extend_from_slice(&identity);
    payload.extend_from_slice(&header.rank.to_be_bytes());
    // domain = "appshard" || address
    let mut domain = Vec::with_capacity(8 + header.address.len());
    domain.extend_from_slice(b"appshard");
    domain.extend_from_slice(&header.address);
    Some((pubkey, sig.signature[..74].to_vec(), payload, domain))
}

/// Hash the full BLS verification tuple → the preverified-set key.
fn bls_tuple_key(pk: &[u8], sig74: &[u8], payload: &[u8], domain: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update((pk.len() as u32).to_be_bytes());
    h.update(pk);
    h.update(sig74);
    h.update((payload.len() as u32).to_be_bytes());
    h.update(payload);
    h.update(domain);
    h.finalize().into()
}

/// Indices of set bits in a bitmask, ascending. Bit `i` lives at byte `i/8`,
/// position `i%8` — matching `quil_consensus::signature_aggregator::build_bitmask`
/// and `quil_consensus::bitmask::set_bit_indices`. Inlined here so the crypto
/// crate need not depend on quil-consensus.
fn set_bit_indices(bitmask: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    for (byte_idx, &byte) in bitmask.iter().enumerate() {
        for bit in 0..8u32 {
            if byte & (1u8 << bit) != 0 {
                out.push(byte_idx * 8 + bit as usize);
            }
        }
    }
    out
}

impl FrameProver for WesolowskiFrameProver {
    fn prove_frame_header(
        &self,
        previous_frame_output: &[u8],
        address: &[u8],
        requests_root: &[u8],
        state_roots: &[Vec<u8>],
        prover: &[u8],
        timestamp: i64,
        difficulty: u32,
        fee_multiplier_vote: u64,
        frame_number: u64,
        storage_attestation_root: &[u8],
        global_frame_number: u64,
    ) -> Result<global::FrameHeader> {
        use sha3::{Digest, Sha3_256};

        // parent = poseidon(previous_frame_output[:516]); zero on genesis.
        let parent: Vec<u8> = if previous_frame_output.len() >= 516 {
            crate::poseidon::hash_bytes_to_32(&previous_frame_output[..516])
                .map_err(|e| QuilError::Crypto(format!("parent poseidon: {}", e)))?
                .to_vec()
        } else {
            vec![0u8; 32]
        };

        let mut input = Vec::new();
        input.extend_from_slice(address);
        input.extend_from_slice(&frame_number.to_be_bytes());
        input.extend_from_slice(&(timestamp as u64).to_be_bytes());
        input.extend_from_slice(&difficulty.to_be_bytes());
        input.extend_from_slice(&fee_multiplier_vote.to_be_bytes());
        input.extend_from_slice(&parent);
        input.extend_from_slice(requests_root);
        for sr in state_roots {
            input.extend_from_slice(sr);
        }
        input.extend_from_slice(prover);
        // Storage-attestation binding: commit the attestation root and the
        // global beacon anchor so neither can be altered after the VDF is solved.
        input.extend_from_slice(storage_attestation_root);
        input.extend_from_slice(&global_frame_number.to_be_bytes());

        let challenge: [u8; 32] = Sha3_256::digest(&input).into();
        let output = vdf::wesolowski_solve(self.int_size_bits, &challenge, difficulty);

        Ok(global::FrameHeader {
            address: address.to_vec(),
            frame_number,
            rank: 0,
            timestamp,
            difficulty,
            output,
            parent_selector: parent,
            requests_root: requests_root.to_vec(),
            state_roots: state_roots.to_vec(),
            prover: prover.to_vec(),
            fee_multiplier_vote,
            public_key_signature_bls48581: None,
            storage_attestation_root: storage_attestation_root.to_vec(),
            global_frame_number,
            storage_attestation: Vec::new(),
        })
    }

    fn verify_frame_header(&self, header: &global::FrameHeader) -> Result<Vec<u8>> {
        use sha3::{Digest, Sha3_256};

        let mut input = Vec::new();
        input.extend_from_slice(&header.address);
        input.extend_from_slice(&header.frame_number.to_be_bytes());
        input.extend_from_slice(&(header.timestamp as u64).to_be_bytes());
        input.extend_from_slice(&header.difficulty.to_be_bytes());
        input.extend_from_slice(&header.fee_multiplier_vote.to_be_bytes());
        input.extend_from_slice(&header.parent_selector);
        input.extend_from_slice(&header.requests_root);
        for sr in &header.state_roots {
            input.extend_from_slice(sr);
        }
        input.extend_from_slice(&header.prover);
        input.extend_from_slice(&header.storage_attestation_root);
        input.extend_from_slice(&header.global_frame_number.to_be_bytes());

        let challenge: [u8; 32] = Sha3_256::digest(&input).into();

        if vdf::wesolowski_verify(
            self.int_size_bits,
            &challenge,
            header.difficulty,
            &header.output,
        ) {
            Ok(header.output.clone())
        } else {
            Err(QuilError::Crypto("invalid frame header VDF proof".into()))
        }
    }

    fn prove_global_frame_header(
        &self,
        previous_frame: &global::GlobalFrameHeader,
        commitments: &[Vec<u8>],
        prover_root: &[u8],
        request_root: &[u8],
        signer: &dyn quil_types::crypto::Signer,
        timestamp: i64,
        difficulty: u32,
        prover_index: u8,
    ) -> Result<global::GlobalFrameHeader> {
        use sha3::{Digest, Sha3_256};
        if previous_frame.output.len() < 516 {
            return Err(QuilError::InvalidArgument(format!(
                "previous frame output too short: {} (need ≥ 516)",
                previous_frame.output.len()
            )));
        }
        // parent = poseidon(previousFrame.Output[:516]).FillBytes(32)
        let parent = crate::poseidon::hash_bytes_to_32(&previous_frame.output[..516])?;

        let new_frame_number = previous_frame.frame_number + 1;

        let mut input: Vec<u8> = Vec::new();
        input.extend_from_slice(&new_frame_number.to_be_bytes());
        input.extend_from_slice(&(timestamp as u64).to_be_bytes());
        input.extend_from_slice(&difficulty.to_be_bytes());
        input.extend_from_slice(&parent);
        for c in commitments {
            input.extend_from_slice(c);
        }
        input.extend_from_slice(prover_root);
        input.extend_from_slice(request_root);

        let b: [u8; 32] = Sha3_256::digest(&input).into();
        let output = vdf::wesolowski_solve(self.int_size_bits, &b, difficulty);

        let mut sign_payload = Vec::with_capacity(32 + output.len());
        sign_payload.extend_from_slice(&b);
        sign_payload.extend_from_slice(&output);

        let signature_bytes = signer.sign_with_domain(&sign_payload, b"global")?;

        // Build the BLS aggregate signature carrier — only BLS48-581
        // signers populate it; mirror Go's `switch pubkeyType`.
        let bls_sig = match signer.key_type() {
            quil_types::crypto::KeyType::Bls48581G1
            | quil_types::crypto::KeyType::Bls48581G2 => {
                let mut bitmask = vec![0u8; 32];
                let byte_idx = (prover_index / 8) as usize;
                let bit_idx = prover_index % 8;
                if byte_idx < bitmask.len() {
                    bitmask[byte_idx] |= 1u8 << bit_idx;
                }
                Some(quil_types::proto::keys::Bls48581AggregateSignature {
                    bitmask,
                    signature: signature_bytes,
                    public_key: Some(quil_types::proto::keys::Bls48581g2PublicKey {
                        key_value: signer.public_key().to_vec(),
                    }),
                })
            }
            other => {
                return Err(QuilError::Crypto(format!(
                    "unsupported proving key type: {:?}", other
                )));
            }
        };

        let cloned_commitments: Vec<Vec<u8>> = commitments.iter().cloned().collect();

        Ok(global::GlobalFrameHeader {
            frame_number: new_frame_number,
            rank: 0,
            timestamp,
            difficulty,
            output,
            parent_selector: parent.to_vec(),
            global_commitments: cloned_commitments,
            prover_tree_commitment: prover_root.to_vec(),
            requests_root: request_root.to_vec(),
            prover: signer.public_key().to_vec(),
            public_key_signature_bls48581: bls_sig,
        })
    }

    fn verify_global_frame_header(
        &self,
        header: &global::GlobalFrameHeader,
    ) -> Result<Vec<u8>> {
        // Build challenge matching Go's GetGlobalFrameSignaturePayload:
        // SHA3-256(frame_number || timestamp || difficulty || parent_selector
        //          || global_commitments... || prover_tree_commitment || requests_root)
        use sha3::{Digest, Sha3_256};

        if header.parent_selector.len() != 32 {
            return Err(QuilError::Crypto("invalid parent selector length".into()));
        }
        if header.output.len() != 516 {
            return Err(QuilError::Crypto(format!(
                "invalid output length: {} (expected 516)", header.output.len()
            )));
        }

        let mut input = Vec::new();
        input.extend_from_slice(&header.frame_number.to_be_bytes());
        input.extend_from_slice(&(header.timestamp as u64).to_be_bytes());
        input.extend_from_slice(&header.difficulty.to_be_bytes());
        input.extend_from_slice(&header.parent_selector);
        for commitment in &header.global_commitments {
            input.extend_from_slice(commitment);
        }
        input.extend_from_slice(&header.prover_tree_commitment);
        input.extend_from_slice(&header.requests_root);

        let challenge = Sha3_256::digest(&input);

        if vdf::wesolowski_verify(
            self.int_size_bits,
            &challenge,
            header.difficulty,
            &header.output,
        ) {
            Ok(header.output.clone())
        } else {
            Err(QuilError::Crypto(
                "invalid global frame header VDF proof".into(),
            ))
        }
    }

    fn calculate_multi_proof(
        &self,
        challenge: &[u8; 32],
        difficulty: u32,
        ids: &[&[u8]],
        index: u32,
    ) -> Result<Vec<u8>> {
        let ids_vec: Vec<Vec<u8>> = ids.iter().map(|id| id.to_vec()).collect();
        Ok(vdf::wesolowski_solve_multi(
            self.int_size_bits,
            challenge,
            difficulty,
            &ids_vec,
            index,
        ))
    }

    fn verify_multi_proof(
        &self,
        challenge: &[u8; 32],
        difficulty: u32,
        ids: &[&[u8]],
        alleged_solutions: &[&[u8]],
    ) -> Result<bool> {
        let ids_vec: Vec<Vec<u8>> = ids.iter().map(|id| id.to_vec()).collect();
        let solutions_vec: Vec<Vec<u8>> = alleged_solutions.iter().map(|s| s.to_vec()).collect();
        Ok(vdf::wesolowski_verify_multi(
            self.int_size_bits,
            challenge,
            difficulty,
            &ids_vec,
            &solutions_vec,
        ))
    }

    fn verify_frame_header_signature(
        &self,
        header: &global::FrameHeader,
        bls: &dyn quil_types::crypto::BlsConstructor,
        ids: Option<&[&[u8]]>,
    ) -> Result<bool> {
        let sig = match header.public_key_signature_bls48581.as_ref() {
            Some(s) => s,
            None => {
                tracing::warn!("verify_frame_header_signature: missing signature struct");
                return Ok(false);
            }
        };
        let pubkey_bytes = sig.public_key.as_ref()
            .map(|k| k.key_value.as_slice())
            .unwrap_or(&[]);
        if pubkey_bytes.is_empty() || sig.signature.len() < 74 {
            tracing::warn!(
                pubkey_len = pubkey_bytes.len(),
                sig_len = sig.signature.len(),
                "verify_frame_header_signature: pubkey empty or sig < 74 bytes"
            );
            return Ok(false);
        }

        let identity = crate::poseidon::hash_bytes_to_32(&header.output)?;

        // payload = address || identity || rank_be (MakeVoteMessage)
        let mut payload = Vec::with_capacity(header.address.len() + 32 + 8);
        payload.extend_from_slice(&header.address);
        payload.extend_from_slice(&identity);
        payload.extend_from_slice(&header.rank.to_be_bytes());

        let mut domain = Vec::with_capacity(8 + header.address.len());
        domain.extend_from_slice(b"appshard");
        domain.extend_from_slice(&header.address);

        // Skip the (expensive) BLS pairing if this exact signature tuple
        // was already verified valid in a batch this frame; the VDF
        // multiproof below still runs. Falls back to the full pairing
        // verify when not preverified.
        let bls_key = bls_tuple_key(pubkey_bytes, &sig.signature[..74], &payload, &domain);
        let bls_ok = self.bls_preverified.read().unwrap().contains(&bls_key)
            || bls.verify_signature_raw(pubkey_bytes, &sig.signature[..74], &payload, &domain);
        if !bls_ok {
            tracing::warn!(
                header_address_prefix = %hex::encode(&header.address[..header.address.len().min(16)]),
                rank = header.rank,
                output_prefix = %hex::encode(&header.output[..header.output.len().min(8)]),
                identity_prefix = %hex::encode(&identity[..16]),
                pubkey_prefix = %hex::encode(&pubkey_bytes[..pubkey_bytes.len().min(16)]),
                sig_prefix = %hex::encode(&sig.signature[..16]),
                domain = %String::from_utf8_lossy(&domain[..8]),
                payload_len = payload.len(),
                "verify_frame_header_signature: BLS verify of agg sig over vote-message payload FAILED"
            );
            return Ok(false);
        }

        // Multiproof verify is only required for multi-signer aggregates.
        let set_bits: u32 = sig.bitmask.iter().map(|b| b.count_ones()).sum();
        if sig.signature.len() == 74 && set_bits != 1 {
            tracing::warn!(
                set_bits,
                bitmask_hex = %hex::encode(&sig.bitmask),
                "verify_frame_header_signature: 74-byte sig must have exactly 1 set bit"
            );
            return Ok(false);
        }
        if sig.signature.len() == 74 && ids.is_none() {
            return Ok(true);
        }

        let ids = match ids {
            Some(i) => i,
            None => return Ok(true),
        };
        let mp = &sig.signature[74..];
        if mp.len() < 4 {
            tracing::warn!(
                tail_len = mp.len(),
                "verify_frame_header_signature: multi-proof tail < 4 bytes (no count prefix)"
            );
            return Ok(false);
        }
        let mut cursor = 0usize;
        let mp_count =
            u32::from_be_bytes(mp[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        let mut multiproofs: Vec<&[u8]> = Vec::with_capacity(mp_count);
        for _ in 0..mp_count {
            if cursor + 516 > mp.len() {
                tracing::warn!(
                    mp_count,
                    cursor,
                    tail_len = mp.len(),
                    "verify_frame_header_signature: multi-proof tail truncated"
                );
                return Ok(false);
            }
            multiproofs.push(&mp[cursor..cursor + 516]);
            cursor += 516;
        }

        use sha3::{Digest, Sha3_256};
        let challenge_bytes: [u8; 32] = Sha3_256::digest(&header.parent_selector).into();

        // `ids` is the full active committee — the deterministic universe the
        // workers committed the challenge prime `b` to when they precomputed.
        // The PRESENT signer set is whoever the bitmask names; we verify only
        // their proofs against the committee-bound `b`. A BFT committee never
        // requires full attendance, and a prover cannot know who will be
        // present when it precomputes — so `b` must bind to the committee, not
        // the dynamic signer subset. See `vdf::wesolowski_verify_multi_sparse`.
        let committee = ids;
        let present_indices: Vec<usize> = set_bit_indices(&sig.bitmask);
        for &idx in &present_indices {
            if idx >= committee.len() {
                tracing::warn!(
                    idx,
                    committee = committee.len(),
                    "verify_frame_header_signature: bitmask index out of committee range"
                );
                return Ok(false);
            }
        }
        // The aggregator emits one proof per present signer, in ascending
        // committee-index order — so the packed proofs must be 1:1 with the
        // bitmask's set bits.
        if present_indices.len() != multiproofs.len() {
            tracing::warn!(
                present = present_indices.len(),
                proofs = multiproofs.len(),
                "verify_frame_header_signature: present-signer count != packed multiproof count"
            );
            return Ok(false);
        }
        let committee_vec: Vec<Vec<u8>> = committee.iter().map(|s| s.to_vec()).collect();
        let present_vec: Vec<Vec<u8>> =
            present_indices.iter().map(|&i| committee[i].to_vec()).collect();
        let solutions_vec: Vec<Vec<u8>> = multiproofs.iter().map(|s| s.to_vec()).collect();
        let ok = vdf::wesolowski_verify_multi_sparse(
            self.int_size_bits,
            &challenge_bytes,
            header.difficulty,
            &committee_vec,
            &present_vec,
            &solutions_vec,
        );
        if !ok {
            tracing::warn!(
                mp_count,
                committee = committee.len(),
                present = present_indices.len(),
                difficulty = header.difficulty,
                challenge_prefix = %hex::encode(&challenge_bytes[..16]),
                parent_selector_prefix = %hex::encode(
                    &header.parent_selector[..header.parent_selector.len().min(16)]
                ),
                "verify_frame_header_signature: sparse multi-proof verify returned false"
            );
        }
        Ok(ok)
    }

    fn verify_frame_header_signatures_batch(
        &self,
        headers: &[&global::FrameHeader],
        bls: &dyn BlsConstructor,
    ) -> bool {
        // Build the per-header BLS verification tuples. A header without a
        // well-formed signature makes the whole batch fail → fall back to
        // per-header verification (which rejects it precisely).
        let mut items: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> =
            Vec::with_capacity(headers.len());
        for h in headers {
            match frame_header_bls_inputs(h) {
                Some(t) => items.push(t),
                None => return false,
            }
        }
        if items.is_empty() {
            return true;
        }
        // One multi-pairing + one final exponentiation for all N.
        if !bls.verify_signatures_batch(&items) {
            return false;
        }
        // Record each verified tuple so the per-header
        // `verify_frame_header_signature` skips the redundant pairing.
        let mut set = self.bls_preverified.write().unwrap();
        for (pk, sig74, payload, domain) in &items {
            set.insert(bls_tuple_key(pk, sig74, payload, domain));
        }
        true
    }

    fn clear_bls_preverified(&self) {
        self.bls_preverified.write().unwrap().clear();
    }

    fn verify_global_header_signature(
        &self,
        header: &global::GlobalFrameHeader,
        bls: &dyn quil_types::crypto::BlsConstructor,
    ) -> Result<bool> {
        // Mirrors Go `WesolowskiFrameProver.VerifyGlobalHeaderSignature`:
        //   payload = MakeVoteMessage(nil, rank, identity=poseidon(output))
        //   BLS verify against pubkey with context = "global"
        let sig = match header.public_key_signature_bls48581.as_ref() {
            Some(s) => s,
            None => return Ok(false),
        };
        let pubkey_bytes = sig.public_key.as_ref()
            .map(|k| k.key_value.as_slice())
            .unwrap_or(&[]);
        if pubkey_bytes.is_empty() || sig.signature.is_empty() {
            return Ok(false);
        }

        let identity = crate::poseidon::hash_bytes_to_32(&header.output)?;

        // filter = nil for global frames; raw identity bytes (32) +
        // rank big-endian.
        let mut payload = Vec::with_capacity(32 + 8);
        payload.extend_from_slice(&identity);
        payload.extend_from_slice(&header.rank.to_be_bytes());

        Ok(bls.verify_signature_raw(
            pubkey_bytes,
            &sig.signature,
            &payload,
            b"global",
        ))
    }
}

#[cfg(test)]
mod batch_tests {
    use super::*;
    use quil_types::crypto::{BlsConstructor, FrameProver, Signer};

    /// Build a shard `FrameHeader` with a real single-signer BLS aggregate
    /// signature over the exact `(payload, domain)` that
    /// `verify_frame_header_signature` reconstructs.
    fn make_signed_header(
        signer: &dyn Signer,
        pk: &[u8],
        address: Vec<u8>,
        output: Vec<u8>,
        rank: u64,
    ) -> global::FrameHeader {
        let identity = crate::poseidon::hash_bytes_to_32(&output).unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(&address);
        payload.extend_from_slice(&identity);
        payload.extend_from_slice(&rank.to_be_bytes());
        let mut domain = b"appshard".to_vec();
        domain.extend_from_slice(&address);
        let sig = signer.sign_with_domain(&payload, &domain).unwrap();
        assert_eq!(sig.len(), 74, "single-signer aggregate must be 74 bytes");
        global::FrameHeader {
            address,
            output,
            rank,
            public_key_signature_bls48581: Some(quil_types::proto::keys::Bls48581AggregateSignature {
                public_key: Some(quil_types::proto::keys::Bls48581g2PublicKey {
                    key_value: pk.to_vec(),
                }),
                signature: sig,
                bitmask: vec![0x01],
            }),
            ..Default::default()
        }
    }

    #[test]
    fn batch_preverify_skips_and_matches_individual() {
        crate::init();
        let bls = crate::Bls48581KeyConstructor;
        let fp = WesolowskiFrameProver::new(2048);

        let mut headers = Vec::new();
        let mut _signers = Vec::new(); // keep alive
        for i in 0..6u64 {
            let (signer, pk) = BlsConstructor::new_key(&bls).unwrap();
            let addr = vec![i as u8; 32];
            let output = vec![(i + 1) as u8; 516];
            let h = make_signed_header(signer.as_ref(), &pk, addr, output, 100 + i);
            // Ground truth: individual verify passes (74-byte sig, ids None).
            assert!(fp.verify_frame_header_signature(&h, &bls, None).unwrap(), "individual {i}");
            headers.push(h);
            _signers.push(signer);
        }

        // Batch verify all → true, populates the preverified set.
        let refs: Vec<&global::FrameHeader> = headers.iter().collect();
        assert!(fp.verify_frame_header_signatures_batch(&refs, &bls), "batch all-valid");

        // Per-header verify now succeeds via the skip path.
        for h in &headers {
            assert!(fp.verify_frame_header_signature(h, &bls, None).unwrap(), "post-batch skip");
        }

        // Clear → still verifies (real pairing again, no stale skip).
        fp.clear_bls_preverified();
        for h in &headers {
            assert!(fp.verify_frame_header_signature(h, &bls, None).unwrap(), "post-clear re-verify");
        }

        // Tamper one header's address (payload changes) → batch rejects all,
        // and the individual verify of the tampered one also rejects.
        let mut tampered = headers.clone();
        tampered[2].address = vec![0xABu8; 32];
        let trefs: Vec<&global::FrameHeader> = tampered.iter().collect();
        assert!(!fp.verify_frame_header_signatures_batch(&trefs, &bls), "batch rejects tampered set");
        assert!(
            !fp.verify_frame_header_signature(&tampered[2], &bls, None).unwrap(),
            "individual rejects tampered"
        );
    }
}

use quil_types::crypto::FrameProver;
use quil_types::error::{QuilError, Result};
use quil_types::proto::global;

/// VDF-based frame prover using the Wesolowski VDF from the vdf crate.
pub struct WesolowskiFrameProver {
    /// VDF integer size in bits (typically 2048).
    pub int_size_bits: u16,
}

impl WesolowskiFrameProver {
    pub fn new(int_size_bits: u16) -> Self {
        Self { int_size_bits }
    }
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

        if !bls.verify_signature_raw(
            pubkey_bytes,
            &sig.signature[..74],
            &payload,
            &domain,
        ) {
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

        let result = self.verify_multi_proof(
            &challenge_bytes,
            header.difficulty,
            ids,
            &multiproofs,
        );
        if let Ok(false) = result {
            tracing::warn!(
                mp_count,
                ids_count = ids.len(),
                difficulty = header.difficulty,
                challenge_prefix = %hex::encode(&challenge_bytes[..16]),
                parent_selector_prefix = %hex::encode(
                    &header.parent_selector[..header.parent_selector.len().min(16)]
                ),
                "verify_frame_header_signature: multi-proof verify returned false"
            );
        }
        result
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

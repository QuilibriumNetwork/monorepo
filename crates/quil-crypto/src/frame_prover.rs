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
        filter: &[u8],
        frame_number: u64,
        parent_selector: &[u8],
        difficulty: u32,
        prover: &[u8],
    ) -> Result<global::FrameHeader> {
        // Build the challenge from filter || frame_number || parent_selector || prover
        let mut challenge = Vec::new();
        challenge.extend_from_slice(filter);
        challenge.extend_from_slice(&frame_number.to_be_bytes());
        challenge.extend_from_slice(parent_selector);
        challenge.extend_from_slice(prover);

        let output = vdf::wesolowski_solve(self.int_size_bits, &challenge, difficulty);

        Ok(global::FrameHeader {
            address: filter.to_vec(),
            frame_number,
            rank: 0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
            difficulty,
            output,
            parent_selector: parent_selector.to_vec(),
            requests_root: Vec::new(),
            state_roots: Vec::new(),
            prover: prover.to_vec(),
            fee_multiplier_vote: 0,
            public_key_signature_bls48581: None,
        })
    }

    fn verify_frame_header(&self, header: &global::FrameHeader) -> Result<Vec<u8>> {
        let mut challenge = Vec::new();
        challenge.extend_from_slice(&header.address);
        challenge.extend_from_slice(&header.frame_number.to_be_bytes());
        challenge.extend_from_slice(&header.parent_selector);
        challenge.extend_from_slice(&header.prover);

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
        frame_number: u64,
        parent_selector: &[u8],
        difficulty: u32,
        prover: &[u8],
    ) -> Result<global::GlobalFrameHeader> {
        let mut challenge = Vec::new();
        challenge.extend_from_slice(&frame_number.to_be_bytes());
        challenge.extend_from_slice(parent_selector);
        challenge.extend_from_slice(prover);

        let output = vdf::wesolowski_solve(self.int_size_bits, &challenge, difficulty);

        Ok(global::GlobalFrameHeader {
            frame_number,
            rank: 0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
            difficulty,
            output,
            parent_selector: parent_selector.to_vec(),
            global_commitments: Vec::new(),
            prover_tree_commitment: Vec::new(),
            requests_root: Vec::new(),
            prover: prover.to_vec(),
            public_key_signature_bls48581: None,
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
}

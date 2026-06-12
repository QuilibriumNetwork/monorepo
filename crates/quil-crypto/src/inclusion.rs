use quil_types::crypto::{InclusionProver, Multiproof};
use quil_types::error::Result;

/// KZG multiproof wrapping the bls48581 crate's prove_multiple output.
pub struct KzgMultiproof {
    pub d: Vec<u8>,
    pub proof_data: Vec<u8>,
    pub y_values: Vec<Vec<u8>>,
}

impl Multiproof for KzgMultiproof {
    fn commitment(&self) -> &[u8] {
        &self.d
    }

    fn proof(&self) -> &[u8] {
        &self.proof_data
    }

    fn evaluations(&self) -> Vec<Vec<u8>> {
        self.y_values.clone()
    }
}

/// KZG polynomial commitment-based inclusion prover using bls48581.
pub struct KzgInclusionProver;

impl InclusionProver for KzgInclusionProver {
    fn commit_raw(&self, data: &[u8], poly_size: u64) -> Result<Vec<u8>> {
        Ok(bls48581::commit_raw(data, poly_size))
    }

    fn prove_raw(&self, data: &[u8], index: u64, poly_size: u64) -> Result<Vec<u8>> {
        Ok(bls48581::prove_raw(data, index, poly_size))
    }

    fn verify_raw(
        &self,
        data: &[u8],
        commit: &[u8],
        index: u64,
        proof: &[u8],
        poly_size: u64,
    ) -> Result<bool> {
        Ok(bls48581::verify_raw(data, commit, index, proof, poly_size))
    }

    fn prove_multiple(
        &self,
        commitments: &[&[u8]],
        polys: &[&[u8]],
        indices: &[u64],
        poly_size: u64,
    ) -> Result<Box<dyn Multiproof>> {
        let commits_vec: Vec<Vec<u8>> = commitments.iter().map(|c| c.to_vec()).collect();
        let polys_vec: Vec<Vec<u8>> = polys.iter().map(|p| p.to_vec()).collect();
        let indices_vec: Vec<u64> = indices.to_vec();

        let mp = bls48581::prove_multiple(&commits_vec, &polys_vec, &indices_vec, poly_size);
        Ok(Box::new(KzgMultiproof {
            d: mp.d,
            proof_data: mp.proof,
            y_values: Vec::new(), // evaluations extracted separately
        }))
    }

    fn verify_multiple(
        &self,
        commitments: &[&[u8]],
        evaluations: &[&[u8]],
        indices: &[u64],
        poly_size: u64,
        multi_commitment: &[u8],
        proof: &[u8],
    ) -> bool {
        let commits_vec: Vec<Vec<u8>> = commitments.iter().map(|c| c.to_vec()).collect();
        let evals_vec: Vec<Vec<u8>> = evaluations.iter().map(|e| e.to_vec()).collect();
        let indices_vec: Vec<u64> = indices.to_vec();

        bls48581::verify_multiple(
            &commits_vec,
            &evals_vec,
            &indices_vec,
            poly_size,
            &multi_commitment.to_vec(),
            &proof.to_vec(),
        )
    }
}

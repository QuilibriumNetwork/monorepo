//! Traversal proof verification. Port of
//! `types/tries/lazy_proof_tree.go:1281-1409`.
//!
//! A traversal proof demonstrates that specific leaves exist in a
//! vector commitment tree at a given root. It uses:
//! 1. Per-path subproofs (commit chain + y values)
//! 2. A KZG multiproof aggregating all openings

use sha2::{Digest, Sha512};
use quil_types::crypto::InclusionProver;
use quil_types::error::{QuilError, Result};

/// A decoded traversal proof (mirrors Go's `tries.TraversalProof`).
pub struct TraversalProof {
    /// KZG multiproof: (multicommitment, proof).
    pub multicommitment: Vec<u8>,
    pub proof: Vec<u8>,
    /// Per-input subproofs.
    pub sub_proofs: Vec<TraversalSubProof>,
}

/// A single sub-proof within a traversal proof.
pub struct TraversalSubProof {
    /// Commitment chain from root down to leaf.
    pub commits: Vec<Vec<u8>>,
    /// Evaluated values at each level.
    pub ys: Vec<Vec<u8>>,
    /// Path indices at each level (each path is a Vec<u64>).
    pub paths: Vec<Vec<u64>>,
}

/// Verify a traversal proof against a known root commitment.
///
/// Returns `Ok(true)` if all subproofs are structurally valid and
/// the KZG multiproof verifies. Returns `Ok(false)` for invalid
/// proofs and `Err` for structural errors.
pub fn verify_traversal_proof(
    inclusion_prover: &dyn InclusionProver,
    root: &[u8],
    proof: &TraversalProof,
) -> Result<bool> {
    // Structural checks
    if proof.multicommitment.is_empty() || proof.proof.is_empty() {
        return Err(QuilError::InvalidArgument(
            "traversal proof: empty multiproof".into(),
        ));
    }

    for (i, sp) in proof.sub_proofs.iter().enumerate() {
        if sp.commits.is_empty() {
            return Err(QuilError::InvalidArgument(format!(
                "traversal proof: subproof {} has no commits", i
            )));
        }
        if sp.paths.len() != sp.commits.len() - 1 {
            return Err(QuilError::InvalidArgument(format!(
                "traversal proof: subproof {} paths/commits mismatch", i
            )));
        }
        if sp.ys.len() != sp.commits.len() {
            return Err(QuilError::InvalidArgument(format!(
                "traversal proof: subproof {} ys/commits mismatch", i
            )));
        }
    }

    // Root check: each subproof's first commit must equal the root
    for (i, sp) in proof.sub_proofs.iter().enumerate() {
        if sp.commits[0] != root {
            return Err(QuilError::InvalidArgument(format!(
                "traversal proof: subproof {} root mismatch", i
            )));
        }
    }

    // Per-subproof path verification
    let mut all_commits: Vec<Vec<u8>> = Vec::new();
    let mut all_indices: Vec<u64> = Vec::new();
    let mut all_ys: Vec<Vec<u8>> = Vec::new();

    for sp in &proof.sub_proofs {
        if sp.commits.len() <= 1 {
            continue;
        }

        // Collect the last index from each path
        for p in &sp.paths {
            if let Some(&last) = p.last() {
                all_indices.push(last);
            }
        }

        // Collect commits and ys (excluding the last level)
        all_commits.extend_from_slice(&sp.commits[..sp.commits.len() - 1]);
        all_ys.extend_from_slice(&sp.ys[..sp.ys.len() - 1]);

        // Recursive path check
        if !verify_path_chain(&sp.commits, &sp.paths, &sp.ys)? {
            return Ok(false);
        }
    }

    // KZG multiproof verification
    if all_commits.len() > 1 {
        let commit_refs: Vec<&[u8]> = all_commits.iter().map(|c| c.as_slice()).collect();
        let y_refs: Vec<&[u8]> = all_ys.iter().map(|y| y.as_slice()).collect();

        if !inclusion_prover.verify_multiple(
            &commit_refs,
            &y_refs,
            &all_indices,
            64, // poly_size = 64 (64-way branching)
            &proof.multicommitment,
            &proof.proof,
        ) {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Recursively verify the commit → y chain within a subproof.
fn verify_path_chain(
    commits: &[Vec<u8>],
    paths: &[Vec<u64>],
    ys: &[Vec<u8>],
) -> Result<bool> {
    if commits.len() <= 1 {
        return Ok(true);
    }

    // Compute expected y[0] from commits[1]
    let out = if commits.len() > 2 {
        // Hash with branch prefix: SHA-512(0x01 || path_prefix_as_u32_be... || commits[1])
        let mut h = Sha512::new();
        h.update([1u8]);
        if paths.len() > 1 {
            for &p in &paths[1][..paths[1].len() - 1] {
                h.update((p as u32).to_be_bytes());
            }
        }
        h.update(&commits[1]);
        h.finalize().to_vec()
    } else {
        commits[1].clone()
    };

    if out != ys[0] {
        return Ok(false);
    }

    verify_path_chain(&commits[1..], &paths[1..], &ys[1..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::NoopInclusionProver;

    struct RejectAll;
    impl InclusionProver for RejectAll {
        fn commit_raw(&self, _: &[u8], _: u64) -> Result<Vec<u8>> { Ok(vec![]) }
        fn prove_raw(&self, _: &[u8], _: u64, _: u64) -> Result<Vec<u8>> { Ok(vec![]) }
        fn verify_raw(&self, _: &[u8], _: &[u8], _: u64, _: &[u8], _: u64) -> Result<bool> { Ok(true) }
        fn prove_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64) -> Result<Box<dyn quil_types::crypto::Multiproof>> { Err(QuilError::Internal("batch multiproof generation not supported".into())) }
        fn verify_multiple(&self, _: &[&[u8]], _: &[&[u8]], _: &[u64], _: u64, _: &[u8], _: &[u8]) -> bool { false }
    }

    #[test]
    fn rejects_empty_multiproof() {
        let proof = TraversalProof {
            multicommitment: vec![],
            proof: vec![0u8; 64],
            sub_proofs: vec![],
        };
        assert!(verify_traversal_proof(&NoopInclusionProver, &[0u8; 64], &proof).is_err());
    }

    #[test]
    fn rejects_mismatched_subproof_lengths() {
        let proof = TraversalProof {
            multicommitment: vec![0u8; 64],
            proof: vec![0u8; 64],
            sub_proofs: vec![TraversalSubProof {
                commits: vec![vec![0u8; 64], vec![1u8; 64]],
                ys: vec![vec![2u8; 64]], // should be 2 entries
                paths: vec![vec![0]],
            }],
        };
        assert!(verify_traversal_proof(&NoopInclusionProver, &[0u8; 64], &proof).is_err());
    }

    #[test]
    fn rejects_root_mismatch() {
        let root = vec![0xAAu8; 64];
        let proof = TraversalProof {
            multicommitment: vec![0u8; 64],
            proof: vec![0u8; 64],
            sub_proofs: vec![TraversalSubProof {
                commits: vec![vec![0xBBu8; 64]], // doesn't match root
                ys: vec![vec![0u8; 64]],
                paths: vec![],
            }],
        };
        assert!(verify_traversal_proof(&NoopInclusionProver, &root, &proof).is_err());
    }

    #[test]
    fn accepts_single_commit_subproof() {
        let root = vec![0xAAu8; 64];
        let proof = TraversalProof {
            multicommitment: vec![0u8; 64],
            proof: vec![0u8; 64],
            sub_proofs: vec![TraversalSubProof {
                commits: vec![root.clone()],
                ys: vec![vec![0u8; 64]],
                paths: vec![],
            }],
        };
        // Single commit = trivially valid (no KZG check needed)
        assert!(verify_traversal_proof(&NoopInclusionProver, &root, &proof).unwrap());
    }

    #[test]
    fn rejects_with_reject_multiproof_verifier() {
        let root = vec![0xAAu8; 64];
        let mid = root.clone();
        let leaf = root.clone();
        // Need 3+ commits so all_commits > 1 triggers verify_multiple
        let proof = TraversalProof {
            multicommitment: vec![0u8; 64],
            proof: vec![0u8; 64],
            sub_proofs: vec![
                TraversalSubProof {
                    commits: vec![root.clone(), mid.clone(), leaf.clone()],
                    // ys[0] must equal SHA-512(0x01 || path_prefix || mid)
                    // We use the hash result so the path check passes
                    ys: vec![{
                        let mut h = Sha512::new();
                        h.update([1u8]);
                        h.update(&mid);
                        h.finalize().to_vec()
                    }, leaf.clone(), vec![0u8; 64]],
                    paths: vec![vec![0], vec![1]],
                },
            ],
        };
        // Path check passes but KZG multiproof rejects
        assert!(!verify_traversal_proof(&RejectAll, &root, &proof).unwrap());
    }
}

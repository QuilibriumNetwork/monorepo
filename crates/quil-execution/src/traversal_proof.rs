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

/// Parse a `TraversalProof` from Go's raw wire format. The format is
/// *not* the canonical-bytes form with a type tag — it's the binary
/// layout written by `types/tries/lazy_proof_tree.go::TraversalProof::
/// ToBytes` and read by `FromBytes:1527-1645`:
///
/// ```text
/// u32 multiproof_len
/// [multiproof_len bytes] (inner: u32 d_len, [d], u32 proof_len, [proof])
/// u32 sub_proofs_count
/// for each subproof:
/// u32 commits_count
/// {u32 commit_len, [commit_len bytes]} × commits_count
/// u32 ys_count
/// {u32 y_len, [y_len bytes]} × ys_count
/// u32 paths_count
/// {u32 path_len, u64 × path_len} × paths_count
/// ```
///
/// The inner multiproof is a pair `(d, proof)` where `d` is the
/// multi-commitment. See `bls48581/bls48581.go::Multiproof::FromBytes`.
pub fn parse_traversal_proof(data: &[u8]) -> Result<TraversalProof> {
    let mut c = 0usize;

    // Outer u32 multiproof length
    let mp_len = read_go_u32(data, &mut c)? as usize;
    let mp_bytes = read_go_bytes(data, &mut c, mp_len)?;

    // Inner multiproof: u32 d_len, [d], u32 proof_len, [proof]
    let mut mc = 0usize;
    let d_len = read_go_u32(mp_bytes, &mut mc)? as usize;
    let multicommitment = read_go_bytes(mp_bytes, &mut mc, d_len)?.to_vec();
    let proof_len = read_go_u32(mp_bytes, &mut mc)? as usize;
    let proof = read_go_bytes(mp_bytes, &mut mc, proof_len)?.to_vec();

    // Subproofs.
    // Every `Vec::with_capacity` below is pre-sized from an attacker-controlled
    // u32 count. Cap each hint against the remaining bytes (each entry needs at
    // least a 4-byte length prefix, u64 elements 8 bytes) so a bogus count can't
    // drive a multi-GB allocation → OOM/abort before the per-entry read even
    // runs. `.min(..)` is a HINT cap only: the loop still reads and bounds-checks
    // each real entry, so legit proofs are never rejected. (These hand-rolled
    // `read_go_*` parsers never moved to the bounded `canonical_cursor` helpers.)
    let sp_count = read_go_u32(data, &mut c)? as usize;
    let mut sub_proofs = Vec::with_capacity(sp_count.min(data.len().saturating_sub(c) / 4));

    for _ in 0..sp_count {
        let commits_count = read_go_u32(data, &mut c)? as usize;
        let mut commits = Vec::with_capacity(commits_count.min(data.len().saturating_sub(c) / 4));
        for _ in 0..commits_count {
            let l = read_go_u32(data, &mut c)? as usize;
            commits.push(read_go_bytes(data, &mut c, l)?.to_vec());
        }

        let ys_count = read_go_u32(data, &mut c)? as usize;
        let mut ys = Vec::with_capacity(ys_count.min(data.len().saturating_sub(c) / 4));
        for _ in 0..ys_count {
            let l = read_go_u32(data, &mut c)? as usize;
            ys.push(read_go_bytes(data, &mut c, l)?.to_vec());
        }

        let paths_count = read_go_u32(data, &mut c)? as usize;
        let mut paths = Vec::with_capacity(paths_count.min(data.len().saturating_sub(c) / 4));
        for _ in 0..paths_count {
            let plen = read_go_u32(data, &mut c)? as usize;
            let mut path = Vec::with_capacity(plen.min(data.len().saturating_sub(c) / 8));
            for _ in 0..plen {
                path.push(read_go_u64(data, &mut c)?);
            }
            paths.push(path);
        }

        sub_proofs.push(TraversalSubProof { commits, ys, paths });
    }

    // Structural validation: at least one subproof with ys data.
    if sub_proofs.is_empty() {
        return Err(QuilError::InvalidArgument(
            "pomw: traversal proof has no subproofs".into(),
        ));
    }
    if !sub_proofs.iter().any(|sp| !sp.ys.is_empty()) {
        return Err(QuilError::InvalidArgument(
            "pomw: traversal proof has no ys data".into(),
        ));
    }

    Ok(TraversalProof { multicommitment, proof, sub_proofs })
}

pub(crate) fn read_go_u32(data: &[u8], c: &mut usize) -> Result<u32> {
    if *c + 4 > data.len() {
        return Err(QuilError::InvalidArgument(
            "pomw: EOF reading u32".into(),
        ));
    }
    let mut b = [0u8; 4];
    b.copy_from_slice(&data[*c..*c + 4]);
    *c += 4;
    Ok(u32::from_be_bytes(b))
}

fn read_go_u64(data: &[u8], c: &mut usize) -> Result<u64> {
    if *c + 8 > data.len() {
        return Err(QuilError::InvalidArgument(
            "pomw: EOF reading u64".into(),
        ));
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[*c..*c + 8]);
    *c += 8;
    Ok(u64::from_be_bytes(b))
}

pub(crate) fn read_go_bytes<'a>(data: &'a [u8], c: &mut usize, len: usize) -> Result<&'a [u8]> {
    if *c + len > data.len() {
        return Err(QuilError::InvalidArgument(
            "pomw: EOF reading bytes".into(),
        ));
    }
    let out = &data[*c..*c + len];
    *c += len;
    Ok(out)
}

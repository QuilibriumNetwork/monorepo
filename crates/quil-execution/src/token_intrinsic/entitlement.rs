//! Mint entitlements: the Merkle tree a proof-basis custom token commits to in
//! its configuration (replacing the retired KZG/verkle basis; custom tokens
//! never mint by proof of meaningful work).
//!
//! A leaf authorizes one key to mint one exact amount once. The token's
//! configuration carries the tree's root; a mint carries the membership proof
//! of its leaf, signs the statement with the leaf's key, and consumes the leaf
//! through a marker in the token's own tree. Nothing here reads state: the
//! caller checks the root against the deployed configuration and the marker
//! against committed state.
use quil_types::error::{QuilError, Result};
use sha3::{Digest, Sha3_256};

/// Bytes of one proof level: direction byte then the sibling hash.
pub const LEVEL_BYTES: usize = 1 + 32;
/// Deepest tree a proof may walk (four billion entitlements).
pub const MAX_DEPTH: usize = 32;

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("mint entitlement: {message}"))
}

/// The leaf that authorizes `public_key` (of `key_type`) to mint exactly
/// `amount` on `network`.
///
/// The leaf binds the network but not the token: a token's address is derived
/// from its configuration, which carries this tree's root, so a deployer cannot
/// know the address while building the tree. A token deployed with another
/// token's root therefore honours the same entitlements, which is the
/// deployer's own choice, and each token consumes them in its own tree.
pub fn leaf(network: &[u8; 32], key_type: u32, public_key: &[u8], amount: u128) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update(b"quil/token/mint-entitlement/v1\0");
    hash.update(network);
    hash.update(key_type.to_be_bytes());
    hash.update((public_key.len() as u32).to_be_bytes());
    hash.update(public_key);
    hash.update(amount.to_be_bytes());
    hash.finalize().into()
}

/// Interior node. The domain separation differs from the leaf hash, so a proof
/// cannot pass an interior node off as a leaf.
pub fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update(b"quil/token/mint-entitlement/node/v1\0");
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

/// Walk `proof` from `leaf` and require it to reach `root`. Each level is a
/// direction byte (1 = the sibling is on the left) and a 32-byte sibling.
pub fn verify(leaf: &[u8; 32], proof: &[u8], root: &[u8]) -> Result<()> {
    if root.len() != 32 {
        return Err(invalid("configured entitlement root is not 32 bytes"));
    }
    if proof.len() % LEVEL_BYTES != 0 || proof.len() / LEVEL_BYTES > MAX_DEPTH {
        return Err(invalid("malformed proof"));
    }
    let mut current = *leaf;
    for level in proof.chunks_exact(LEVEL_BYTES) {
        let sibling: [u8; 32] = level[1..].try_into().unwrap();
        current = match level[0] {
            0 => node(&current, &sibling),
            1 => node(&sibling, &current),
            _ => return Err(invalid("proof direction is not 0 or 1")),
        };
    }
    if current.as_slice() != root {
        return Err(invalid("entitlement is not in the token's entitlement root"));
    }
    Ok(())
}

/// Address of the marker recording that `leaf` has minted, in the token's own
/// tree. Written with the mint, so an entitlement mints exactly once.
pub fn consumed_marker(application: &[u8; 32], leaf: &[u8; 32]) -> Result<[u8; 32]> {
    let mut bytes = b"quil/token/mint-entitlement/consumed/v1\0".to_vec();
    bytes.extend_from_slice(application);
    bytes.extend_from_slice(leaf);
    quil_crypto::poseidon::hash_bytes_to_32(&bytes)
}

/// Build the tree over `leaves` in the given order and return its root with one
/// proof per leaf. A level with an odd count carries its last node up
/// unchanged. Deployers publish the root in the token configuration and hand
/// each holder its proof.
pub fn build(leaves: &[[u8; 32]]) -> Result<([u8; 32], Vec<Vec<u8>>)> {
    if leaves.is_empty() {
        return Err(invalid("no entitlements"));
    }
    let mut proofs: Vec<Vec<u8>> = vec![Vec::new(); leaves.len()];
    // Index of each original leaf in the current level.
    let mut positions: Vec<usize> = (0..leaves.len()).collect();
    let mut level = leaves.to_vec();
    let mut depth = 0;
    while level.len() > 1 {
        depth += 1;
        if depth > MAX_DEPTH {
            return Err(invalid("too many entitlements"));
        }
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            next.push(if pair.len() == 2 { node(&pair[0], &pair[1]) } else { pair[0] });
        }
        for (leaf, position) in proofs.iter_mut().zip(positions.iter_mut()) {
            let sibling = *position ^ 1;
            if sibling < level.len() {
                leaf.push(u8::from(sibling < *position));
                leaf.extend_from_slice(&level[sibling]);
            }
            *position /= 2;
        }
        level = next;
    }
    Ok((level[0], proofs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(count: u8) -> Vec<[u8; 32]> {
        (0..count).map(|i| leaf(&[1; 32], 3, &[i; 897], 10 + i as u128)).collect()
    }

    #[test]
    fn a_built_proof_verifies_only_for_its_own_leaf_and_root() {
        for count in [1u8, 2, 3, 5, 8] {
            let entitlements = leaves(count);
            let (root, proofs) = build(&entitlements).unwrap();
            for (leaf, proof) in entitlements.iter().zip(&proofs) {
                verify(leaf, proof, &root).unwrap();
                // Another leaf, another root, or a flipped direction fails.
                assert!(verify(&[9; 32], proof, &root).is_err());
                assert!(verify(leaf, proof, &[7; 32]).is_err());
                if !proof.is_empty() {
                    let mut flipped = proof.clone();
                    flipped[0] ^= 1;
                    let mut tampered = proof.clone();
                    tampered[1] ^= 1;
                    assert!(count == 1 || verify(leaf, &flipped, &root).is_err());
                    assert!(verify(leaf, &tampered, &root).is_err());
                }
            }
        }
    }

    #[test]
    fn leaves_bind_the_key_amount_and_token_and_proofs_are_bounded() {
        let base = leaf(&[1; 32], 3, &[4; 897], 10);
        assert_ne!(base, leaf(&[2; 32], 3, &[4; 897], 10));
        assert_ne!(base, leaf(&[1; 32], 4, &[4; 897], 10));
        assert_ne!(base, leaf(&[1; 32], 3, &[5; 897], 10));
        assert_ne!(base, leaf(&[1; 32], 3, &[4; 897], 11));
        // A leaf can never be read as an interior node.
        assert_ne!(base, node(&[4; 32], &[5; 32]));
        assert!(build(&[]).is_err());
        assert!(verify(&base, &[0; LEVEL_BYTES - 1], &[0; 32]).is_err());
        assert!(verify(&base, &vec![0; LEVEL_BYTES * (MAX_DEPTH + 1)], &[0; 32]).is_err());
        assert!(verify(&base, &[2; LEVEL_BYTES], &[0; 32]).is_err());
        assert!(verify(&base, &[], &base).is_ok());
        assert_ne!(consumed_marker(&[1; 32], &base).unwrap(), consumed_marker(&[2; 32], &base).unwrap());
    }
}

//! A raw-key proof checked against the root of a subtree on its key's path
//! (hash storage proofs, decided 2026-10-22). A shard's state roots are its
//! subtree's in the app tree, so a proof for a key in the shard verifies
//! against them with no app root.

use jmt::proof::SparseMerkleProof;
use sha2::Sha256;

/// An empty subtree's root. The forest gives an empty subtree either this or
/// zeros (zeros for a missing nibble child, this for an empty range within a
/// nibble), and a shard header carries what it gives: compare with
/// [`same_root`].
pub const EMPTY_ROOT: [u8; 32] = *b"SPARSE_MERKLE_PLACEHOLDER_HASH__";

/// Whether two subtree roots are the same, either form of an empty one
/// being the same.
pub fn same_root(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let empty = |root: &[u8; 32]| *root == EMPTY_ROOT || *root == [0; 32];
    a == b || (empty(a) && empty(b))
}

/// A raw-key proof as a verifier needs it: the leaf it ends at, `(key, value
/// hash)` — the key itself when present, else the one key in the region it
/// would have taken, `None` when that region is empty — and the sibling
/// hashes from that leaf's depth up to the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompactProof {
    pub leaf: Option<([u8; 32], [u8; 32])>,
    pub siblings: Vec<[u8; 32]>,
}

impl CompactProof {
    /// From a proof of [`crate::Forest::shard_phase_get_with_proof_raw`].
    pub fn of(proof: &SparseMerkleProof<Sha256>) -> Self {
        Self {
            leaf: proof
                .leaf()
                .map(|leaf| (leaf.key_bytes(), leaf.value_hash_bytes())),
            siblings: proof.sibling_hashes(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(67 + 32 * self.siblings.len());
        match &self.leaf {
            Some((key, value_hash)) => {
                out.push(1);
                out.extend_from_slice(key);
                out.extend_from_slice(value_hash);
            }
            None => out.push(0),
        }
        out.extend_from_slice(&(self.siblings.len() as u16).to_be_bytes());
        for sibling in &self.siblings {
            out.extend_from_slice(sibling);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (leaf, rest) = match bytes.split_first()? {
            (0, rest) => (None, rest),
            (1, rest) if rest.len() >= 64 => (
                Some((rest[..32].try_into().ok()?, rest[32..64].try_into().ok()?)),
                &rest[64..],
            ),
            _ => return None,
        };
        let count = u16::from_be_bytes(rest.get(..2)?.try_into().ok()?) as usize;
        let rest = &rest[2..];
        if count > 256 || rest.len() != 32 * count {
            return None;
        }
        let siblings = rest
            .chunks_exact(32)
            .map(|sibling| sibling.try_into().expect("32 bytes"))
            .collect();
        Some(Self { leaf, siblings })
    }
}

/// The hash of a leaf of `key` whose value hashes to `value_hash`.
fn leaf_hash(key: &[u8; 32], value_hash: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = Sha256::new();
    hasher.update(jmt::proof::LEAF_DOMAIN_SEPARATOR);
    hasher.update(key);
    hasher.update(value_hash);
    hasher.finalize().into()
}

/// The root of the subtree of the first `depth` bits of `key`, as `proof`
/// shows it. `None` when the proof is malformed: too long, or a
/// non-inclusion leaf that does not share the proof's depth of bits with
/// `key`.
pub fn subtree_root(proof: &CompactProof, key: &[u8; 32], depth: usize) -> Option<[u8; 32]> {
    let siblings = &proof.siblings;
    if siblings.len() > 256 || depth > 256 {
        return None;
    }
    if let Some((leaf_key, _)) = &proof.leaf {
        if leaf_key != key && common_prefix_bits(leaf_key, key) < siblings.len() {
            return None;
        }
    }
    let at_leaf = proof
        .leaf
        .as_ref()
        .map_or(EMPTY_ROOT, |(leaf_key, value_hash)| {
            leaf_hash(leaf_key, value_hash)
        });
    Some(if depth >= siblings.len() {
        // At or below where the proof ends, the region holds its one leaf
        // if that leaf shares the subtree's bits, else nothing.
        match &proof.leaf {
            Some((leaf_key, _))
                if depth == siblings.len() || common_prefix_bits(leaf_key, key) >= depth =>
            {
                at_leaf
            }
            _ => EMPTY_ROOT,
        }
    } else {
        // Hash up from the leaf's depth to `depth`, a level per sibling,
        // reading the key's bits from the deepest.
        let mut hash = at_leaf;
        for (level, sibling) in siblings.iter().enumerate().take(siblings.len() - depth) {
            let bit_index = siblings.len() - 1 - level;
            let bit = key[bit_index / 8] & (0x80 >> (bit_index % 8)) != 0;
            hash = if bit {
                SparseMerkleProof::<Sha256>::combine(*sibling, hash)
            } else {
                SparseMerkleProof::<Sha256>::combine(hash, *sibling)
            };
        }
        hash
    })
}

fn common_prefix_bits(a: &[u8; 32], b: &[u8; 32]) -> usize {
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        let diff = x ^ y;
        if diff != 0 {
            return i * 8 + diff.leading_zeros() as usize;
        }
    }
    256
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Forest, Phase};

    /// Every proof, for a present key or an absent one, gives the root the
    /// forest computes for every subtree on its path.
    #[test]
    fn a_proof_gives_the_forests_root_of_each_subtree_on_its_path() {
        let forest = Forest::in_memory();
        let app = [0x44u8; 32];
        let keys: Vec<[u8; 32]> = [0x00u8, 0x01, 0x40, 0x41, 0x7F, 0x80, 0xC3, 0xC4, 0xFF]
            .iter()
            .map(|&lead| {
                let mut key = [lead; 32];
                key[0] = lead;
                key[1] = lead.wrapping_mul(7);
                key
            })
            .collect();
        let mut shards = std::collections::BTreeMap::new();
        let leaves: Vec<(Vec<u8>, Vec<u8>)> = keys
            .iter()
            .map(|key| {
                (
                    key.to_vec(),
                    quil_tries::vertex_leaf_value(&[key[0]; 12]).unwrap(),
                )
            })
            .collect();
        shards.insert(Vec::new(), [leaves, Vec::new(), Vec::new(), Vec::new()]);
        forest.commit_app_shards(&app, 1, 0, shards).unwrap();
        let mut probes = keys.clone();
        probes.extend([[0x20u8; 32], [0x9Au8; 32], [0xC3u8; 32]]);
        for probe in &probes {
            let (value, proof) = forest
                .shard_phase_get_with_proof_raw(&app, Phase::VertexAdds, 1, probe)
                .unwrap();
            let proof = CompactProof::of(&proof);
            assert_eq!(
                CompactProof::from_bytes(&proof.to_bytes()),
                Some(proof.clone())
            );
            for depth in 0..=12 {
                let bits: Vec<bool> = (0..depth)
                    .map(|i| probe[i / 8] & (0x80 >> (i % 8)) != 0)
                    .collect();
                let expected = forest
                    .app_subtree_root(&app, Phase::VertexAdds, 1, &bits)
                    .unwrap();
                let root = subtree_root(&proof, probe, depth).unwrap();
                assert!(
                    same_root(&root, &expected),
                    "probe {:02x} depth {depth}: {:?} vs {:?}",
                    probe[0],
                    root,
                    expected
                );
            }
            match (&value, &proof.leaf) {
                (Some(value), Some((key, value_hash))) => {
                    assert_eq!(key, probe);
                    assert_eq!(
                        *value_hash,
                        <Sha256 as sha2::Digest>::digest(value).as_slice()
                    );
                }
                (None, Some((key, _))) => assert_ne!(key, probe),
                (None, None) => {}
                (Some(_), None) => panic!("a present key without its leaf"),
            }
            let mut forged = proof.clone();
            if let Some(sibling) = forged.siblings.first_mut() {
                sibling[0] ^= 1;
                assert!(
                    !same_root(
                        &subtree_root(&forged, probe, 0).unwrap(),
                        &forest
                            .app_subtree_root(&app, Phase::VertexAdds, 1, &[])
                            .unwrap()
                    ),
                    "a changed sibling"
                );
            }
        }
    }
}

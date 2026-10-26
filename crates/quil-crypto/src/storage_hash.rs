//! The hash of the hash storage proofs: Poseidon2 of width 24 over KoalaBear
//! (`p = 2^31 - 2^24 + 1`) with Plonky3's published round constants.
//!
//! Every hash a storage proof's STARK recomputes is this one: the SDR labels,
//! the column digests and the data, column and replica Merkle trees. With
//! Keccak inside the proof, proving one leaf's seal took ~27 s and 23 GB and
//! gave a 1.5 MB proof; Poseidon2 is ~300× cheaper to prove and gives ~5×
//! smaller proofs, for ~7× slower labelling (measured and decided
//! 2026-10-21). Like any hash it is post-quantum up to generic (Grover / BHT)
//! attacks. Values the verifier derives itself (challenges, replica keys,
//! opening indices) stay SHA3.
//!
//! A digest is 8 field elements (248 bits), serialized as 8 little-endian
//! canonical `u32`s. A data node carries 30 bytes: 8 elements of 30 bits.

use std::sync::OnceLock;

use p3_field::integers::QuotientMap;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{default_koalabear_poseidon2_24, KoalaBear, Poseidon2KoalaBear};
use p3_symmetric::Permutation;

pub type F = KoalaBear;
pub const WIDTH: usize = 24;
pub const RATE: usize = 16;
pub const DIGEST_ELEMS: usize = 8;
pub type Digest = [F; DIGEST_ELEMS];
pub const DIGEST_BYTES: usize = 4 * DIGEST_ELEMS;
/// Data bytes one node carries: 8 elements of 30 bits, each below `p`.
pub const DATA_BYTES_PER_NODE: usize = 30;
const ELEMENT_BITS: u32 = 30;

pub const ZERO: Digest = [F::ZERO; DIGEST_ELEMS];

/// What a hash is for. It occupies the first capacity element, so no hash of
/// one kind equals a hash of another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Domain {
    /// An inner Merkle node over its two children.
    Node = 1,
    /// The empty leaf a level's missing right child stands for.
    Empty = 2,
    /// A tree's root bound to its kind and leaf count.
    Root = 3,
    /// An SDR label.
    Label = 4,
    /// One step of a column digest.
    Column = 5,
    /// The openings a frame commits to.
    Openings = 6,
}

pub fn felt(value: u32) -> F {
    F::from_int(value)
}

fn permutation() -> &'static Poseidon2KoalaBear<WIDTH> {
    static PERMUTATION: OnceLock<Poseidon2KoalaBear<WIDTH>> = OnceLock::new();
    PERMUTATION.get_or_init(default_koalabear_poseidon2_24)
}

pub fn permute(state: &mut [F; WIDTH]) {
    permutation().permute_mut(state);
}

/// Two digests into one: the permutation of `left ‖ right ‖ domain`,
/// truncated.
pub fn compress(left: &Digest, right: &Digest, domain: Domain) -> Digest {
    let mut state = [F::ZERO; WIDTH];
    state[..DIGEST_ELEMS].copy_from_slice(left);
    state[DIGEST_ELEMS..RATE].copy_from_slice(right);
    state[RATE] = felt(domain as u32);
    permute(&mut state);
    first_digest(&state)
}

fn first_digest(state: &[F; WIDTH]) -> Digest {
    state[..DIGEST_ELEMS].try_into().expect("8 elements")
}

/// A sponge over a fixed number of elements: the domain and the length sit
/// in the capacity; each block of 16 is added to the rate and permuted; the
/// last block is zero-padded.
pub struct Absorber {
    state: [F; WIDTH],
    position: usize,
    remaining: usize,
    permuted: bool,
}

impl Absorber {
    pub fn new(domain: Domain, length: usize) -> Self {
        let mut state = [F::ZERO; WIDTH];
        state[RATE] = felt(domain as u32);
        state[RATE + 1] = felt(length as u32);
        Self { state, position: 0, remaining: length, permuted: false }
    }

    pub fn absorb(&mut self, value: F) {
        debug_assert!(self.remaining > 0, "more elements than declared");
        self.state[self.position] += value;
        self.position += 1;
        self.remaining -= 1;
        if self.position == RATE {
            permute(&mut self.state);
            self.position = 0;
            self.permuted = true;
        }
    }

    pub fn absorb_digest(&mut self, digest: &Digest) {
        for &value in digest {
            self.absorb(value);
        }
    }

    pub fn finish(mut self) -> Digest {
        debug_assert_eq!(self.remaining, 0, "fewer elements than declared");
        // A partial block, or an empty input, still gets its permutation.
        if self.position > 0 || !self.permuted {
            permute(&mut self.state);
        }
        first_digest(&self.state)
    }
}

pub fn sponge(domain: Domain, input: &[F]) -> Digest {
    let mut absorber = Absorber::new(domain, input.len());
    for &value in input {
        absorber.absorb(value);
    }
    absorber.finish()
}

pub fn add(a: &Digest, b: &Digest) -> Digest {
    std::array::from_fn(|i| a[i] + b[i])
}

pub fn sub(a: &Digest, b: &Digest) -> Digest {
    std::array::from_fn(|i| a[i] - b[i])
}

pub fn to_bytes(digest: &Digest) -> [u8; DIGEST_BYTES] {
    let mut out = [0u8; DIGEST_BYTES];
    for (chunk, value) in out.chunks_exact_mut(4).zip(digest) {
        chunk.copy_from_slice(&value.as_canonical_u32().to_le_bytes());
    }
    out
}

/// The digest `bytes` serialize, `None` unless exactly 32 bytes of canonical
/// elements.
pub fn from_bytes(bytes: &[u8]) -> Option<Digest> {
    if bytes.len() != DIGEST_BYTES {
        return None;
    }
    let mut out = ZERO;
    for (slot, chunk) in out.iter_mut().zip(bytes.chunks_exact(4)) {
        *slot = F::from_canonical_checked(u32::from_le_bytes(chunk.try_into().expect("4 bytes")))?;
    }
    Some(out)
}

/// Digests from consecutive 32-byte serializations; `None` for any partial or
/// non-canonical one.
pub fn digests_from_bytes(bytes: &[u8]) -> Option<Vec<Digest>> {
    if bytes.len() % DIGEST_BYTES != 0 {
        return None;
    }
    bytes.chunks_exact(DIGEST_BYTES).map(from_bytes).collect()
}

pub fn digests_to_bytes(digests: &[Digest]) -> Vec<u8> {
    let mut out = Vec::with_capacity(digests.len() * DIGEST_BYTES);
    for digest in digests {
        out.extend_from_slice(&to_bytes(digest));
    }
    out
}

/// Up to 30 bytes of data as one node: the bytes zero-padded to 30 and read
/// as a little-endian 240-bit number, split into eight 30-bit elements.
pub fn pack_node(bytes: &[u8]) -> Digest {
    debug_assert!(bytes.len() <= DATA_BYTES_PER_NODE);
    let mut padded = [0u8; DATA_BYTES_PER_NODE];
    padded[..bytes.len()].copy_from_slice(bytes);
    let mask = (1u128 << ELEMENT_BITS) - 1;
    let mut out = ZERO;
    for (half, chunk) in padded.chunks_exact(15).enumerate() {
        let mut wide = [0u8; 16];
        wide[..15].copy_from_slice(chunk);
        let bits = u128::from_le_bytes(wide);
        for k in 0..4 {
            out[half * 4 + k] = felt(((bits >> (ELEMENT_BITS as usize * k)) & mask) as u32);
        }
    }
    out
}

/// The 30 bytes [`pack_node`] packed, `None` if an element has more than 30
/// bits.
pub fn unpack_node(node: &Digest) -> Option<[u8; DATA_BYTES_PER_NODE]> {
    let mut out = [0u8; DATA_BYTES_PER_NODE];
    for (half, chunk) in out.chunks_exact_mut(15).enumerate() {
        let mut bits = 0u128;
        for k in 0..4 {
            let value = node[half * 4 + k].as_canonical_u32();
            if value >> ELEMENT_BITS != 0 {
                return None;
            }
            bits |= (value as u128) << (ELEMENT_BITS as usize * k);
        }
        chunk.copy_from_slice(&bits.to_le_bytes()[..15]);
    }
    Some(out)
}

/// A replica key ([`crate::sdr::replica_key`], SHA3) as the label hash's key:
/// its first 30 bytes, packed.
pub fn key_digest(key: &[u8]) -> Digest {
    pack_node(&key[..key.len().min(DATA_BYTES_PER_NODE)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_packs_thirty_bytes_reversibly() {
        for seed in 0u8..8 {
            let bytes: Vec<u8> = (0..30).map(|i| (i as u8).wrapping_mul(97).wrapping_add(seed)).collect();
            let node = pack_node(&bytes);
            assert!(node.iter().all(|v| v.as_canonical_u32() < 1 << 30));
            assert_eq!(unpack_node(&node).unwrap().as_slice(), bytes.as_slice());
        }
        assert_eq!(pack_node(&[]), ZERO);
        assert_eq!(unpack_node(&pack_node(&[0xFF; 7])).unwrap()[..8], [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0]);
    }

    #[test]
    fn only_canonical_digests_deserialize() {
        let digest: Digest = std::array::from_fn(|i| felt(i as u32 * 1_000_003 + 7));
        assert_eq!(from_bytes(&to_bytes(&digest)), Some(digest));
        let mut bad = to_bytes(&digest);
        bad[..4].copy_from_slice(&F::ORDER_U32.to_le_bytes());
        assert_eq!(from_bytes(&bad), None, "p itself is not canonical");
        assert_eq!(from_bytes(&bad[..31]), None);
    }

    #[test]
    fn domains_and_lengths_separate_hashes() {
        let a: Digest = std::array::from_fn(|i| felt(i as u32 + 1));
        let b: Digest = std::array::from_fn(|i| felt(i as u32 + 100));
        assert_ne!(compress(&a, &b, Domain::Node), compress(&a, &b, Domain::Column));
        assert_ne!(compress(&a, &b, Domain::Node), compress(&b, &a, Domain::Node));
        let input: Vec<F> = a.iter().chain(&b).copied().collect();
        assert_ne!(sponge(Domain::Label, &input), sponge(Domain::Label, &input[..15]));
        assert_ne!(sponge(Domain::Label, &input), sponge(Domain::Root, &input));
        let mut padded = input.clone();
        padded.push(F::ZERO);
        assert_ne!(sponge(Domain::Label, &input), sponge(Domain::Label, &padded), "length is bound");
        // The incremental absorber is the one-shot sponge.
        let mut absorber = Absorber::new(Domain::Label, 40);
        for i in 0..40u32 {
            absorber.absorb(felt(i));
        }
        assert_eq!(absorber.finish(), sponge(Domain::Label, &(0..40).map(felt).collect::<Vec<_>>()));
        assert_ne!(sponge(Domain::Empty, &[]), ZERO);
    }
}

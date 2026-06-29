#![allow(non_snake_case)]

use std::convert::TryInto;
use sha2::{Digest, Sha256};
use rand::RngCore;
use rand::rngs::OsRng;

// Implementation of the seed tree optimization
// Port of the LegRoast C implementation to Rust 
// https://github.com/WardBeullens/LegRoast, main branch at cac7406)
// See merkletree.c

// To convert seeds to finite field elements see utils::seed_to_FF

pub const SEED_BYTES : usize = 16;
pub type Seed = [u8; SEED_BYTES];

pub struct SeedTree {
    seeds : Vec<Seed>,   // length must be (2*PARTIES-1)
    depth : usize,      // log_2(N)
    num_leaves: usize   // N
}

/// Wipe every GGM seed on drop. These seeds are the DKG-in-the-head
/// party randomness behind the verifiable-encryption proof; leaking
/// them from freed memory would expose the witness-sharing secrets.
impl Drop for SeedTree {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for s in self.seeds.iter_mut() {
            s.zeroize();
        }
    }
}

impl SeedTree {

    fn expand(salt : &[u8], rep_index : u16, seed_index : u16, seed : &Seed) -> (Seed, Seed) {
        let mut hasher = Sha256::new();
        hasher.update(salt);
        hasher.update(rep_index.to_le_bytes());
        hasher.update(seed_index.to_le_bytes());
        hasher.update(seed);
        let digest = hasher.finalize();

        ( digest[0..SEED_BYTES].try_into().expect("Hash digest too short, needs to be twice the seed length"),
          digest[SEED_BYTES..].try_into().expect("Hash digest too short, needs to be twice the seed length") )
    }

    fn left_child(i : usize) -> usize {
        2*i+1
    }
    fn right_child(i : usize) -> usize {
        2*i+2
    }    
    fn parent(i : usize) -> usize {
        (i-1)/2
    }
    fn sibling(i : usize) -> usize {
        // ((i)%2)? i+1 : i-1 
        if i % 2 == 1 {
            i + 1
        } else {
            i - 1
        }
    }

    pub fn zero_seed() -> Seed {
        [0; SEED_BYTES]
    }

    pub fn random_seed() -> Seed {
        let mut random_vector = [0u8; SEED_BYTES];
        OsRng.fill_bytes(&mut random_vector);
        random_vector
    }    

    pub fn create(root_seed : &Seed, depth : usize, salt : &[u8], rep_index : usize) -> Self {

        let num_leaves = 1 << depth;
        let mut seeds = vec![Self::zero_seed(); 2*num_leaves - 1];
        seeds[0] = root_seed.clone();
        let rep_index = rep_index as u16;

       for i in 0 .. num_leaves - 1 {
            let i_u16 : u16 = i.try_into().unwrap();
            let (left, right) = Self::expand(salt, rep_index, i_u16, &seeds[i]);
            seeds[Self::left_child(i)] = left;
            seeds[Self::right_child(i)] = right;
       }

       SeedTree{seeds, depth, num_leaves}
    }

    // Unopened party index is given in [0, .., N-1]
    pub fn open_seeds(&self, unopened_index : usize) -> Vec<Seed> {
        let mut unopened_index = unopened_index + (1 << self.depth) - 1;
        let mut out = Vec::new();
        let mut to_reveal = 0;
        while to_reveal < self.depth {
            out.push(self.seeds[Self::sibling(unopened_index)]);
            unopened_index = Self::parent(unopened_index);
            to_reveal += 1;
        }

        out
    }

    // Callers  must ensure that revealed.size() == depth
    pub fn reconstruct_tree(depth : usize, salt : &[u8], rep_index : usize, unopened_index : usize, revealed : &Vec<Seed>) -> Self {
        let num_leaves = 1 << depth;
        let mut unopened_index = unopened_index + num_leaves - 1;
        let mut seeds = vec![Self::zero_seed(); 2 * num_leaves - 1];
        let mut next_insert = 0;
        assert!(revealed.len() == depth);
        while next_insert < depth {
            seeds[Self::sibling(unopened_index)] = revealed[next_insert];
            unopened_index = Self::parent(unopened_index);
            next_insert += 1;
        }

        let zero_seed = seeds[0];   // we'll never have the root
        for i in 0 .. num_leaves - 1 {
            if seeds[i] != zero_seed {
                let (left, right) = Self::expand(salt, rep_index as u16, i as u16, &seeds[i]);
                seeds[Self::left_child(i)] = left;
                seeds[Self::right_child(i)] = right;                
            }
        }

        SeedTree { seeds, depth, num_leaves }
    }

    pub fn get_leaf(&self, i : usize) -> Seed {
        assert!(i < self.num_leaves, "get_leaf: leaf index too large"); // Caller bug

        self.seeds[self.num_leaves - 1 + i]
    }

    pub fn print_tree(&self, label : &str) {
        print!("Tree {}:\n", label);
        for i in 0..self.seeds.len() {
            print!("seed {} = {}\n", i, hex::encode_upper(self.seeds[i]));
            if i == self.num_leaves - 2 {
                print!("---- leaves follow ----\n")
            }            
        }
    }

}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;    
    use rand::RngCore;

    fn random_vec(len :usize) -> Vec<u8> {
        let mut random_vector = vec![0u8; len];
        OsRng.fill_bytes(&mut random_vector);
        random_vector
    }



    #[test]
    fn test_seed_tree_create() {
        let N = 8;
        let logN = 3;
        let root_seed = SeedTree::random_seed();
        let salt = random_vec(32);
        let rep_index = 5;

        let tree = SeedTree::create(&root_seed, logN, salt.as_slice(), rep_index);
        assert!(tree.num_leaves == N);
        for i in 0..tree.num_leaves {
            let leaf_seed_i = tree.get_leaf(i);
            assert!(leaf_seed_i != SeedTree::zero_seed());
        }
    }

    #[test]
    fn test_seed_tree_roundtrip() {
        let N = 8;
        let logN = 3;
        let root_seed = SeedTree::random_seed();
        let salt = random_vec(32);
        let rep_index = 5;

        let tree = SeedTree::create(&root_seed, logN, salt.as_slice(), rep_index);
        assert!(tree.num_leaves == N);

        for unopened_party in 0 .. N-1 {
            let opening_data = tree.open_seeds(unopened_party);
            let tree2 = SeedTree::reconstruct_tree(logN, &salt, rep_index, unopened_party, &opening_data);
            assert!(tree2.num_leaves == N);

            for i in 0..N {
                if i != unopened_party {
                    assert!(tree.get_leaf(i) == tree2.get_leaf(i));
                }
                else {
                    assert!(tree2.get_leaf(i) == SeedTree::zero_seed());
                }
            }
        }

    }    

}
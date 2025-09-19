#![allow(non_snake_case)]

use sha2::{Digest, Sha512};
use crate::Seed;
use std::convert::TryInto;

use ed448_goldilocks_plus::EdwardsPoint as GGA;
use ed448_goldilocks_plus::Scalar as FF;


pub type Statement = GGA;
pub type Witness = FF;


#[derive(Clone, Default, PartialEq, Debug)]
pub struct CurveParams {
    pub(crate) G: GGA,
}

impl CurveParams {
    pub fn init(blind: GGA) -> Self {
        let G = blind;
       
        CurveParams {
            G
        }
    }
}

/* Utility functions */
pub fn hash_to_FF(point: &GGA) -> FF {
    let digest = hash_SHA512(&point.compress().to_bytes()[..]);

    FF::from_bytes(&(digest[0..56].try_into().unwrap()))
}

pub fn hash_SHA512(input : &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(input);
    
    hasher.finalize().to_vec()
}

pub fn bytes_to_u32(input : &Vec<u8>) -> Vec<u32> {
    let extra = input.len() % 4;
    let mut output = Vec::<u32>::new();
    for i in (0..input.len()-extra).step_by(4) {
        let next_bytes : [u8 ; 4] = input[i..i+4].try_into().unwrap();
        output.push(u32::from_le_bytes(next_bytes));
    }
    output
}

// Derive a uniformly random field element from a seed, 
// assuming the bitlength of the field is less than 448 bits
// Used to convert seeds to shares.
pub fn seed_to_FF(seed: Seed, salt: &[u8], rep_index : usize, party_index : usize, additional_input : Option<&[u8]>) -> FF {
    let rep_index = rep_index as u16;
    let party_index = party_index as u16;
    let mut hasher = Sha512::new();
    hasher.update(salt);
    hasher.update(seed);
    hasher.update(rep_index.to_le_bytes());
    hasher.update(party_index.to_le_bytes());
    if additional_input.is_some() {
        hasher.update(additional_input.unwrap());
    }
    
    let digest = hasher.finalize();

    FF::from_bytes(&digest[0..56].try_into().unwrap())
}

// A simple bit–reader over a byte slice.
struct BitReader<'a> {
  data: &'a [u8],
  // This counts the total number of bits read so far.
  bit_pos: usize,
}

impl<'a> BitReader<'a> {
  fn new(data: &'a [u8]) -> Self {
      Self { data, bit_pos: 0 }
  }

  // Reads a single bit from the input.
  fn read_bit(&mut self) -> Option<bool> {
      if self.bit_pos >= self.data.len() * 8 {
          return None;
      }
      // In little–endian order within a byte, the bit at position (bit_pos % 8)
      // is extracted. (This is just one valid choice; what matters is consistency.)
      let byte = self.data[self.bit_pos / 8];
      let bit = (byte >> (self.bit_pos % 8)) & 1;
      self.bit_pos += 1;
      Some(bit != 0)
  }

  // Reads `count` bits and returns them as the lower `count` bits of a u64.
  // (Assumes count <= 64.)
  fn read_bits(&mut self, count: usize) -> Option<u64> {
      let mut value = 0u64;
      for i in 0..count {
          // Each bit read is placed in position i (i.e. we’re building a little–endian number).
          let bit = self.read_bit();
          if bit.is_some() && bit.unwrap() {
              value |= 1 << i;
          }
          if i == 0 && bit.is_none() {
            return None
          }
      }
      Some(value)
  }
}

// Encodes an arbitrary byte slice into a vector of Curve448 clamped scalars.
// Each scalar encodes 440 bits of data (i.e. 55 bytes).
//
// The mapping is as follows (little–endian view):
//   - Bytes 0..=54: all 8 bits are free
//   - Byte 55: empty
//
// If the final chunk has fewer than 440 bits, it is padded with zero bits.
pub fn encode_to_curve448_scalars(input: &[u8]) -> Vec<Vec<u8>> {
  let mut reader = BitReader::new(input);
  let mut scalars = Vec::new();

  // Continue until no more bits are available.
  while let Some(_) = reader.read_bits(1) {
      // (We already advanced one bit; move back one step.)
      reader.bit_pos -= 1;

      let mut scalar = vec![0;56];

      for i in 0..55 {
          // If there aren’t enough bits, pad with 0.
          let byte = reader.read_bits(8).unwrap_or(0);
          scalar[i] = byte as u8;
      }

      scalars.push(scalar);
  }

  scalars
}

// Recombines a slice of 56-byte scalars (each containing 440 free bits)
// into the original bit–stream, returned as a Vec<u8>.
//
// The packing was as follows (little–endian bit–order):
//   - Bytes 0..=54: all 8 bits are free (440 bits total)
//   - Byte 55: empty
pub fn decode_from_curve448_scalars(scalars: &Vec<Vec<u8>>) -> Vec<u8> {
  let mut output: Vec<u8> = Vec::new();
  // We'll accumulate bits in `acc` (lowest-order bits are the oldest)
  // and keep track of how many bits we have in `bits_in_acc`.
  let mut acc: u64 = 0;
  let mut bits_in_acc: usize = 0;

  // A helper macro to push bits into our accumulator and flush bytes when possible.
  macro_rules! push_bits {
      ($value:expr, $num_bits:expr) => {{
          // Append the new bits to the accumulator.
          acc |= ($value as u64) << bits_in_acc;
          bits_in_acc += $num_bits;
          // While we have a full byte, flush it.
          while bits_in_acc >= 8 {
              output.push((acc & 0xFF) as u8);
              acc >>= 8;
              bits_in_acc -= 8;
          }
      }};
  }

  for scalar in scalars {
      if scalar.len() != 56 {
          return vec![];
      }

      for &byte in &scalar[0..55] {
          push_bits!(byte, 8);
      }
  }

  output
}

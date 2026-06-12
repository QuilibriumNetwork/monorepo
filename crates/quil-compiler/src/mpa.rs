//! Multi-precision integer arithmetic for constant evaluation.
//! Port of `bedlam/compiler/mpa/mpint.go`.

use std::fmt;

use num_bigint::BigInt;
use num_traits::{One, ToPrimitive, Zero};

use crate::types::Size;

/// Multi-precision integer.
#[derive(Debug, Clone)]
pub struct Int {
    pub bits: Size,
    value: BigInt,
}

impl Int {
    /// Create a new Int with the specified bit size.
    pub fn new(bits: Size) -> Self {
        assert!(bits > 0, "mpa.new: bits are zero");
        Int {
            bits,
            value: BigInt::zero(),
        }
    }

    /// Create a new Int with the given value and optional bit size.
    pub fn from_i64(x: i64, bits: Size) -> Self {
        let bits = if bits == 0 {
            let ux = x as u64;
            let mut b: Size = 1;
            while b < 64 {
                if (u64::MAX << b as u64) & ux == 0 {
                    break;
                }
                b += 1;
            }
            if b > 32 { 64 } else { 32 }
        } else {
            bits
        };
        let mut result = Int {
            bits,
            value: BigInt::from(x),
        };
        result.mask();
        result
    }

    /// Create from a BigInt.
    pub fn from_bigint(x: BigInt, bits: Size) -> Self {
        let bits = if bits == 0 {
            let bl = x.bits() as Size;
            if bl > 32 { 64.max(bl) } else { 32.max(bl) }
        } else {
            bits
        };
        let mut result = Int { bits, value: x };
        result.mask();
        result
    }

    /// Parse from string with given base.
    pub fn parse(s: &str, base: u32) -> Option<Self> {
        let val = if base == 0 {
            // Auto-detect prefix
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                BigInt::parse_bytes(hex.as_bytes(), 16)?
            } else if let Some(bin) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
                BigInt::parse_bytes(bin.as_bytes(), 2)?
            } else if let Some(oct) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
                BigInt::parse_bytes(oct.as_bytes(), 8)?
            } else if s.len() > 1 && s.starts_with('0') {
                BigInt::parse_bytes(s.as_bytes(), 8)?
            } else {
                BigInt::parse_bytes(s.as_bytes(), 10)?
            }
        } else {
            BigInt::parse_bytes(s.as_bytes(), base)?
        };
        Some(Int::from_bigint(val, 0))
    }

    fn is_small(&self) -> bool {
        self.bits <= 64
    }

    fn mask(&mut self) {
        if self.bits > 0 && self.bits <= 64 {
            let mask = if self.bits >= 64 {
                u64::MAX
            } else {
                (1u64 << self.bits as u64) - 1
            };
            // Mask to bits width
            let v = self.value.to_i64().unwrap_or(0) as u64;
            self.value = BigInt::from((v & mask) as i64);
        }
    }

    pub fn type_size(&self) -> i32 {
        self.bits as i32
    }

    pub fn set_type_size(&mut self, size: Size) {
        self.bits = size;
    }

    pub fn bit(&self, i: u32) -> bool {
        self.value.bit(i as u64)
    }

    pub fn bit_len(&self) -> usize {
        self.value.bits() as usize
    }

    pub fn int64(&self) -> i64 {
        if self.is_small() {
            let v = self.value.to_i64().unwrap_or(0);
            // Sign extend based on bits
            if self.bits < 64 {
                let sign_bit = 1i64 << (self.bits - 1);
                if v & sign_bit != 0 {
                    let mask = (1i64 << self.bits) - 1;
                    return v | !mask;
                }
            }
            v
        } else {
            self.value.to_i64().unwrap_or(0)
        }
    }

    pub fn sign(&self) -> i32 {
        if self.is_small() {
            let v = self.int64();
            if v < 0 {
                -1
            } else if v > 0 {
                1
            } else {
                0
            }
        } else {
            match self.value.sign() {
                num_bigint::Sign::Minus => -1,
                num_bigint::Sign::NoSign => 0,
                num_bigint::Sign::Plus => 1,
            }
        }
    }

    pub fn cmp(&self, x: &Int) -> std::cmp::Ordering {
        self.int64().cmp(&x.int64())
    }

    pub fn value(&self) -> &BigInt {
        &self.value
    }

    /// text in given base
    pub fn text(&self, base: u32) -> String {
        match base {
            2 => format!("{:b}", self.value),
            8 => format!("{:o}", self.value),
            10 => self.value.to_string(),
            16 => format!("{:x}", self.value),
            _ => self.value.to_string(),
        }
    }

    // Arithmetic operations

    pub fn add(&self, y: &Int) -> Int {
        let bits = self.bits.max(y.bits);
        Int::from_bigint(&self.value + &y.value, bits)
    }

    pub fn sub(&self, y: &Int) -> Int {
        let bits = self.bits.max(y.bits);
        Int::from_bigint(&self.value - &y.value, bits)
    }

    pub fn mul(&self, y: &Int) -> Int {
        let bits = self.bits.max(y.bits);
        Int::from_bigint(&self.value * &y.value, bits)
    }

    pub fn div(&self, y: &Int) -> Int {
        if y.value.is_zero() {
            return Int::from_i64(-1, self.bits);
        }
        let bits = self.bits.max(y.bits);
        Int::from_bigint(&self.value / &y.value, bits)
    }

    pub fn modulo(&self, y: &Int) -> Int {
        if y.value.is_zero() {
            return self.clone();
        }
        let bits = self.bits.max(y.bits);
        Int::from_bigint(&self.value % &y.value, bits)
    }

    pub fn and(&self, y: &Int) -> Int {
        Int::from_bigint(&self.value & &y.value, self.bits)
    }

    pub fn or(&self, y: &Int) -> Int {
        Int::from_bigint(&self.value | &y.value, self.bits)
    }

    pub fn xor(&self, y: &Int) -> Int {
        Int::from_bigint(&self.value ^ &y.value, self.bits)
    }

    pub fn and_not(&self, y: &Int) -> Int {
        // a &^ b = a & !b
        let not_y = !&y.value;
        Int::from_bigint(&self.value & &not_y, self.bits)
    }

    pub fn lsh(&self, n: u32) -> Int {
        let mut result = Int::from_bigint(&self.value << n as u64, self.bits);
        // Clear bits above type size
        if self.bits > 0 {
            for i in (self.bits as u64)..result.value.bits() {
                result.value = &result.value & !(BigInt::one() << i);
            }
        }
        result
    }

    pub fn rsh(&self, n: u32) -> Int {
        Int::from_bigint(&self.value >> n as u64, self.bits)
    }
}

impl fmt::Display for Int {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl PartialEq for Int {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_arithmetic() {
        let a = Int::from_i64(100, 32);
        let b = Int::from_i64(200, 32);
        assert_eq!(a.add(&b).int64(), 300);
        assert_eq!(b.sub(&a).int64(), 100);
        assert_eq!(a.mul(&b).int64(), 20000);
    }

    #[test]
    fn parse_hex() {
        let v = Int::parse("ff", 16).unwrap();
        assert_eq!(v.int64(), 255);
    }

    #[test]
    fn parse_auto_detect() {
        let v = Int::parse("0xff", 0).unwrap();
        assert_eq!(v.int64(), 255);
        let v = Int::parse("0b1010", 0).unwrap();
        assert_eq!(v.int64(), 10);
    }

    #[test]
    fn bitwise_ops() {
        let a = Int::from_i64(0xFF, 32);
        let b = Int::from_i64(0x0F, 32);
        assert_eq!(a.and(&b).int64(), 0x0F);
        assert_eq!(a.or(&b).int64(), 0xFF);
        assert_eq!(a.xor(&b).int64(), 0xF0);
    }

    #[test]
    fn shift_ops() {
        let a = Int::from_i64(1, 32);
        assert_eq!(a.lsh(4).int64(), 16);
        let b = Int::from_i64(16, 32);
        assert_eq!(b.rsh(4).int64(), 1);
    }
}

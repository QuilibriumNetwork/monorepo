//! Multiplier circuits (array + Karatsuba). Port of `circuits/circ_multiplier.go`.

use super::compiler::{new_adder, new_half_adder, new_full_adder, new_subtractor, Compiler};
use super::gates::Gate;
use crate::circuit::Operation;

/// Default Karatsuba → array crossover threshold.
const DEFAULT_ARRAY_THRESHOLD: usize = 21;

/// Create a multiplier circuit: x * y = z.
pub fn new_multiplier(
    cc: &mut Compiler,
    array_threshold: usize,
    x: &[usize],
    y: &[usize],
    z: &mut [usize],
) -> Result<(), String> {
    let threshold = if array_threshold < 8 {
        DEFAULT_ARRAY_THRESHOLD
    } else {
        array_threshold
    };
    new_karatsuba_multiplier(cc, threshold, x, y, z)
}

/// Array multiplier: x * y = z.
pub fn new_array_multiplier(
    cc: &mut Compiler,
    x: &[usize],
    y: &[usize],
    z: &mut [usize],
) -> Result<(), String> {
    let (x, y) = cc.zero_pad(x, y);
    let x = if x.len() > z.len() {
        &x[..z.len()]
    } else {
        &x
    };
    let y = if y.len() > z.len() {
        &y[..z.len()]
    } else {
        &y
    };

    // One bit multiplication is AND.
    if x.len() == 1 {
        let g = Gate::new(Operation::And, x[0], y[0], z[0]);
        cc.add_gate(g);
        if z.len() > 1 {
            z[1] = cc.zero_wire();
        }
        return Ok(());
    }

    // Construct Y0 sums.
    let mut sums = Vec::new();
    for (i, &xn) in x.iter().enumerate() {
        let s = if i == 0 {
            z[0]
        } else {
            cc.allocator.wire()
        };
        cc.add_gate(Gate::new(Operation::And, xn, y[0], s));
        if i != 0 {
            sums.push(s);
        }
    }

    // Intermediate layers.
    let mut j = 1;
    while j + 1 < y.len() {
        let mut ands = Vec::new();
        for &xn in x.iter() {
            let w = cc.allocator.wire();
            cc.add_gate(Gate::new(Operation::And, xn, y[j], w));
            ands.push(w);
        }

        let mut nsums = Vec::new();
        let mut carry = 0usize; // wire index, will be set below
        for i in 0..ands.len() {
            let cout = cc.allocator.wire();
            let s = if i == 0 {
                z[j]
            } else {
                let w = cc.allocator.wire();
                nsums.push(w);
                w
            };

            if i == 0 {
                new_half_adder(cc, ands[i], sums[i], s, cout);
            } else if i >= sums.len() {
                new_half_adder(cc, ands[i], carry, s, cout);
            } else {
                new_full_adder(cc, ands[i], sums[i], carry, s, cout);
            }
            carry = cout;
        }
        nsums.push(carry);
        sums = nsums;
        j += 1;
    }

    // Final layer.
    let mut carry = 0usize;
    for (i, &xn) in x.iter().enumerate() {
        let and = cc.allocator.wire();
        cc.add_gate(Gate::new(Operation::And, xn, y[j], and));

        let cout = if i + 1 >= x.len() && j + i + 1 < z.len() {
            z[j + i + 1]
        } else {
            cc.allocator.wire()
        };

        if j + i < z.len() {
            if i == 0 {
                new_half_adder(cc, and, sums[i], z[j + i], cout);
            } else if i >= sums.len() {
                new_half_adder(cc, and, carry, z[j + i], cout);
            } else {
                new_full_adder(cc, and, sums[i], carry, z[j + i], cout);
            }
        }
        carry = cout;
    }

    let zw = cc.zero_wire();
    for i in (j + x.len() + 1)..z.len() {
        z[i] = zw;
    }

    Ok(())
}

/// Karatsuba multiplier: a * b = r.
pub fn new_karatsuba_multiplier(
    cc: &mut Compiler,
    limit: usize,
    a: &[usize],
    b: &[usize],
    r: &mut [usize],
) -> Result<(), String> {
    let (a, b) = cc.zero_pad(a, b);
    let a = if a.len() > r.len() {
        &a[..r.len()]
    } else {
        &a
    };
    let b = if b.len() > r.len() {
        &b[..r.len()]
    } else {
        &b
    };

    if a.len() <= limit {
        return new_array_multiplier(cc, a, b, r);
    }

    let mid = a.len() / 2;
    let a_low = &a[..mid];
    let a_high = &a[mid..];
    let b_low = &b[..mid];
    let b_high = &b[mid..];

    // z0 = aLow * bLow
    let z0_len = (a_low.len().max(b_low.len()) * 2).min(r.len());
    let mut z0: Vec<usize> = (0..z0_len).map(|_| cc.allocator.wire()).collect();
    new_karatsuba_multiplier(cc, limit, a_low, b_low, &mut z0)?;

    // aSum = aLow + aHigh
    let a_sum_len = a_low.len().max(a_high.len()) + 1;
    let mut a_sum: Vec<usize> = (0..a_sum_len).map(|_| cc.allocator.wire()).collect();
    new_adder(cc, a_low, a_high, &mut a_sum)?;

    // bSum = bLow + bHigh
    let b_sum_len = b_low.len().max(b_high.len()) + 1;
    let mut b_sum: Vec<usize> = (0..b_sum_len).map(|_| cc.allocator.wire()).collect();
    new_adder(cc, b_low, b_high, &mut b_sum)?;

    // z1 = aSum * bSum
    let z1_len = (a_sum_len.max(b_sum_len) * 2).min(r.len());
    let mut z1: Vec<usize> = (0..z1_len).map(|_| cc.allocator.wire()).collect();
    new_karatsuba_multiplier(cc, limit, &a_sum, &b_sum, &mut z1)?;

    // z2 = aHigh * bHigh
    let z2_len = (a_high.len().max(b_high.len()) * 2).min(r.len());
    let mut z2: Vec<usize> = (0..z2_len).map(|_| cc.allocator.wire()).collect();
    new_karatsuba_multiplier(cc, limit, a_high, b_high, &mut z2)?;

    // sub1 = z1 - z2
    let mut sub1: Vec<usize> = (0..r.len()).map(|_| cc.allocator.wire()).collect();
    new_subtractor(cc, &z1, &z2, &mut sub1)?;

    // sub2 = sub1 - z0
    let mut sub2: Vec<usize> = (0..r.len()).map(|_| cc.allocator.wire()).collect();
    new_subtractor(cc, &sub1, &z0, &mut sub2)?;

    // shift1 = z2 << (mid*2)
    let shift1 = cc.shift_left(&z2, r.len(), mid * 2);

    // shift2 = sub2 << mid
    let shift2 = cc.shift_left(&sub2, r.len(), mid);

    // add1 = shift1 + shift2
    let mut add1: Vec<usize> = (0..r.len()).map(|_| cc.allocator.wire()).collect();
    new_adder(cc, &shift1, &shift2, &mut add1)?;

    // r = add1 + z0
    new_adder(cc, &add1, &z0, r)?;

    Ok(())
}

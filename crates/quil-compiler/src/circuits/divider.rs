//! Division circuits. Port of `circuits/circ_divider.go`.

use super::compiler::{new_mux, new_subtractor, Compiler};

/// Unsigned long division: q = a / b, r = a % b.
pub fn new_udivider_long(
    cc: &mut Compiler,
    a: &[usize],
    b: &[usize],
    q: &mut [usize],
    rret: &mut [usize],
) -> Result<(), String> {
    let (a, b) = cc.zero_pad(a, b);
    let n = a.len();

    let zw = cc.zero_wire();
    let mut r: Vec<usize> = vec![zw; n];

    for i in (0..n).rev() {
        // r <<= 1
        for j in (1..r.len()).rev() {
            r[j] = r[j - 1];
        }
        r[0] = a[i];

        // diff = r - b
        let mut diff: Vec<usize> = (0..r.len() + 1).map(|_| cc.allocator.wire()).collect();
        new_subtractor(cc, &r, &b, &mut diff)?;

        // quotient bit
        if i < q.len() {
            let zero_arr = [cc.zero_wire()];
            let one_arr = [cc.one_wire()];
            let mut q_bit = [q[i]];
            new_mux(
                cc,
                &diff[diff.len() - 1..],
                &zero_arr,
                &one_arr,
                &mut q_bit,
            )?;
            q[i] = q_bit[0];
        }

        // Select r or diff based on overflow bit.
        let mut nr: Vec<usize> = (0..r.len())
            .map(|j| {
                if i == 0 && j < rret.len() {
                    rret[j]
                } else {
                    cc.allocator.wire()
                }
            })
            .collect();

        new_mux(
            cc,
            &diff[diff.len() - 1..],
            &r,
            &diff[..diff.len() - 1],
            &mut nr,
        )?;
        r = nr;
    }
    Ok(())
}

/// Unsigned division (delegates to long division).
pub fn new_udivider(
    cc: &mut Compiler,
    a: &[usize],
    b: &[usize],
    q: &mut [usize],
    r: &mut [usize],
) -> Result<(), String> {
    new_udivider_long(cc, a, b, q, r)
}

/// Signed division: q = a / b, r = a % b.
pub fn new_idivider(
    cc: &mut Compiler,
    a: &[usize],
    b: &[usize],
    q: &mut [usize],
    r: &mut [usize],
) -> Result<(), String> {
    let (a, b) = cc.zero_pad(a, b);
    let n = a.len();

    let zero = [cc.zero_wire()];
    let neg0 = cc.zero_wire();

    // If a is negative, negate it.
    let neg1 = cc.allocator.wire();
    cc.inv(neg0, neg1);

    let mut a1: Vec<usize> = (0..n).map(|_| cc.allocator.wire()).collect();
    new_subtractor(cc, &zero, &a, &mut a1)?;

    let mut neg2_arr = [cc.allocator.wire()];
    new_mux(cc, &a[n - 1..], &[neg1], &[neg0], &mut neg2_arr)?;
    let neg2 = neg2_arr[0];

    let mut a2: Vec<usize> = (0..n).map(|_| cc.allocator.wire()).collect();
    new_mux(cc, &a[n - 1..], &a1, &a, &mut a2)?;

    // If b is negative, negate it.
    let neg3 = cc.allocator.wire();
    cc.inv(neg2, neg3);

    let mut b1: Vec<usize> = (0..n).map(|_| cc.allocator.wire()).collect();
    new_subtractor(cc, &zero, &b, &mut b1)?;

    let mut neg4_arr = [cc.allocator.wire()];
    new_mux(cc, &b[n - 1..], &[neg3], &[neg2], &mut neg4_arr)?;
    let neg4 = neg4_arr[0];

    let mut b2: Vec<usize> = (0..n).map(|_| cc.allocator.wire()).collect();
    new_mux(cc, &b[n - 1..], &b1, &b, &mut b2)?;

    if q.is_empty() {
        // Modulo only.
        return new_udivider(cc, &a2, &b2, q, r);
    }

    // q0 = a2 / b2
    let mut q0: Vec<usize> = (0..q.len()).map(|_| cc.allocator.wire()).collect();
    new_udivider(cc, &a2, &b2, &mut q0, r)?;

    // q1 = -q0
    let mut q1: Vec<usize> = (0..q.len()).map(|_| cc.allocator.wire()).collect();
    new_subtractor(cc, &zero, &q0, &mut q1)?;

    // If neg, use q1, else q0.
    new_mux(cc, &[neg4], &q1, &q0, q)
}

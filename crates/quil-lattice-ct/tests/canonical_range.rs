//! Test-only check for replacing canonical-residue carry chains.
//! This is an exact proof-ring equation, not an application-ring congruence.
//! QPF4 now emits this identity; this independent model supplements submission tests.
use quil_lattice_ct::{confidential::relation::backend::PROOF_MODULUS, rq::Poly};

const BITS: usize = 36;

fn planes(value: u64) -> [u8; BITS] {
    std::array::from_fn(|bit| ((value >> bit) & 1) as u8)
}

fn residual(value: &[u8; BITS], complement: &[u8; BITS]) -> Option<i128> {
    if value.iter().chain(complement).any(|&bit| bit > 1) {
        return None;
    }
    Some(value.iter().zip(complement).enumerate().fold(
        -i128::from(Poly::Q - 1),
        |sum, (bit, (&a, &b))| sum + ((i128::from(a) + i128::from(b)) << bit),
    ))
}

fn accepts(value: &[u8; BITS], complement: &[u8; BITS]) -> bool {
    residual(value, complement).is_some_and(|r| r.rem_euclid(PROOF_MODULUS) == 0)
}

#[test]
fn complete_declared_ranges_cannot_wrap_the_proof_modulus() {
    assert_eq!(Poly::Q, (1u64 << BITS) - 23);
    // Every bit is nonnegative. These are exact extrema over all 72 bits;
    // no correlation or private assignment is needed for this interval bound.
    let minimum = -i128::from(Poly::Q - 1);
    let maximum = 2 * ((1i128 << BITS) - 1) - i128::from(Poly::Q - 1);
    assert!(minimum > -PROOF_MODULUS / 2);
    assert!(maximum < PROOF_MODULUS / 2);
    assert_eq!(residual(&planes(0), &planes(0)), Some(minimum));
    assert_eq!(residual(&[1; BITS], &[1; BITS]), Some(maximum));
    // Thus modular zero means integer zero. The equality x+c=q-1 and c>=0
    // implies x<q; conversely every x<q has the representable complement q-1-x.
}

#[test]
fn canonical_endpoints_and_assignments_satisfy_the_exact_row() {
    let mut values = vec![0, 1, Poly::Q - 2, Poly::Q - 1];
    for bit in 0..BITS {
        values.extend([(1u64 << bit) - 1, 1u64 << bit]);
    }
    let mut state = 0x6a09e667f3bcc909u64;
    for _ in 0..65536 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        values.push(state % Poly::Q);
    }
    for value in values {
        let x = planes(value);
        let c = planes(Poly::Q - 1 - value);
        assert!(accepts(&x, &c));
        for bit in 0..BITS {
            let mut changed = c;
            changed[bit] ^= 1;
            assert!(!accepts(&x, &changed));
        }
    }
}

#[test]
fn all_noncanonical_residues_and_nonbinary_assignments_are_rejected() {
    for value in Poly::Q..(1u64 << BITS) {
        let x = planes(value);
        // This assignment satisfies the wrong, application-ring congruence.
        let c = planes(2 * Poly::Q - 1 - value);
        assert_eq!(residual(&x, &c).unwrap().rem_euclid(i128::from(Poly::Q)), 0);
        assert!(!accepts(&x, &c));
        // Even the smallest complement makes the exact residual positive;
        // together with the global bound, this excludes every complement.
        assert!(residual(&x, &planes(0)).unwrap() > 0);
    }
    let x = planes(0);
    let c = planes(Poly::Q - 1);
    for bit in 0..BITS {
        let mut changed = x;
        changed[bit] = 2;
        assert!(!accepts(&changed, &c));
        let mut changed = c;
        changed[bit] = 2;
        assert!(!accepts(&x, &changed));
    }
}

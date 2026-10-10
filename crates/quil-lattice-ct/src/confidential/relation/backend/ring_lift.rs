//! Integer lifting of linear R_q equations with binary polynomial inputs.
//! Two signed base-2^18 planes replace one congruence when public bounds permit;
//! otherwise five base-256 planes are used. This is a private
//! assignment reference, not a proof backend. The binary_lift module expands
//! ranges into bits; the native adapter must enforce their binary domains.
use super::*;
use zeroize::Zeroizing;

pub mod binary_lift;

const ACTIVE_RADIX_BITS: u32 = 18;

#[derive(Debug, PartialEq, Eq)]
pub enum LiftError {
    InvalidShape,
    ResidualMayWrap,
    InvalidWitness,
}

/// Public coefficients and bounds; no private assignment is retained here.
pub struct RingLiftPlan {
    radix_bits: u32,
    planes: usize,
    terms: Vec<(Poly, usize)>,
    rhs: Poly,
    quotient_bits: u32,
    carry_bits: u32,
    residual_bound: i128,
    direct_residual_bound: Option<i128>,
}

/// Private quotient and intermediate carries. No wire format or Debug API.
pub struct LiftWitness {
    quotient: Zeroizing<Vec<i128>>,
    carries: Zeroizing<Vec<Vec<i128>>>,
}

fn centered(value: u64) -> i128 {
    if value > Poly::Q / 2 {
        i128::from(value) - i128::from(Poly::Q)
    } else {
        i128::from(value)
    }
}

fn digit(value: i128, plane: usize, radix_bits: u32) -> i128 {
    value.signum() * ((value.abs() >> (radix_bits as usize * plane)) & ((1i128 << radix_bits) - 1))
}

fn signed_bits(bound: i128) -> Result<u32, LiftError> {
    (2..64)
        .find(|&bits| bound < (1i128 << (bits - 1)))
        .ok_or(LiftError::ResidualMayWrap)
}

fn in_range(value: i128, bits: u32) -> bool {
    let half = 1i128 << (bits - 1);
    (-half..half).contains(&value)
}

impl CompiledAmountRelation {
    /// Covers stored linear R_q equations (amount commitments and the
    /// transaction-context binding). Membership hashes are native proof-ring
    /// rows (`native_membership_rows`); selections use `selection_backend_rows`.
    pub fn ring_backend_plans(&self) -> impl Iterator<Item = Result<RingLiftPlan, LiftError>> + '_ {
        self.ring
            .iter()
            .map(|row| RingLiftPlan::new(row, self))
    }

    pub fn lift_ring_witness(&self, plan: &RingLiftPlan) -> Result<LiftWitness, LiftError> {
        plan.assign(self)
    }
}

impl RingLiftPlan {
    fn new(row: &RingEquation, relation: &CompiledAmountRelation) -> Result<Self, LiftError> {
        match Self::new_with_radix(row, relation, ACTIVE_RADIX_BITS) {
            Err(LiftError::ResidualMayWrap) => Self::new_with_radix(row, relation, 8),
            result => result,
        }
    }

    // QPF6 selects from public data only; private assignments cannot affect it.
    // Variable bounds (1 for binary handles, the declared coefficient bound for
    // short handles) are public relation structure, not witness values.
    fn new_with_radix(row: &RingEquation, relation: &CompiledAmountRelation, radix_bits: u32) -> Result<Self, LiftError> {
        if ![8, 12, 16, 18].contains(&radix_bits) { return Err(LiftError::InvalidShape); }
        let planes = (64 - Poly::Q.leading_zeros()).div_ceil(radix_bits) as usize;
        let base = 1i128 << radix_bits;
        let valid = |p: &Poly| p.c.len() == Poly::D && p.c.iter().all(|&v| v < Poly::Q);
        if !valid(&row.rhs) || row.terms.iter().any(|(p, i)| relation.variable_bound(*i).is_none() || !valid(p)) {
            return Err(LiftError::InvalidShape);
        }
        let var_bound = |i: &usize| i128::from(relation.variable_bound(*i).unwrap_or(0));
        // For any output coefficient of a negacyclic convolution, each public
        // coefficient occurs exactly once and multiplies one variable
        // coefficient of magnitude at most its bound. Triangle bounds remain
        // valid even if variables repeat or later constraints correlate them.
        let sum = row
            .terms
            .iter()
            .flat_map(|(p, i)| p.c.iter().map(move |&v| centered(v).abs() * var_bound(i)))
            .try_fold(0i128, |s, v| s.checked_add(v))
            .ok_or(LiftError::ResidualMayWrap)?;
        let rhs_bound = row.rhs.c.iter().map(|&v| centered(v).abs()).max().unwrap();
        // A q-congruence whose integer residual is strictly smaller than q
        // already means integer equality. Such rows need no lifting variables.
        let direct_residual_bound = (sum + rhs_bound < i128::from(Poly::Q)
            && sum + rhs_bound < PROOF_MODULUS / 2)
            .then_some(sum + rhs_bound);
        let quotient_bits = signed_bits((sum + rhs_bound) / i128::from(Poly::Q))?;
        let z_bound = 1i128 << (quotient_bits - 1);
        let mut carry_bound = 0;
        let mut plane_bounds = vec![0i128; planes];
        for (plane, bound) in plane_bounds.iter_mut().enumerate() {
            *bound = row
                .terms
                .iter()
                .flat_map(|(p, i)| p.c.iter().map(move |&v| digit(centered(v), plane, radix_bits).abs() * var_bound(i)))
                .sum::<i128>()
                + row
                    .rhs
                    .c
                    .iter()
                    .map(|&v| digit(centered(v), plane, radix_bits).abs())
                    .max()
                    .unwrap()
                + digit(i128::from(Poly::Q), plane, radix_bits) * z_bound;
            carry_bound = (carry_bound + *bound) / base;
        }
        // A uniform carry range follows from B >= max_plane_bound / (base - 1).
        carry_bound = carry_bound.max((plane_bounds.iter().max().unwrap() + base - 2) / (base - 1));
        let carry_bits = signed_bits(carry_bound)?;
        let c_bound = 1i128 << (carry_bits - 1);
        let residual_bound = plane_bounds.iter().max().unwrap() + (base + 1) * c_bound;
        if residual_bound >= PROOF_MODULUS / 2 {
            return Err(LiftError::ResidualMayWrap);
        }
        Ok(Self {
            radix_bits, planes,
            terms: row.terms.clone(),
            rhs: row.rhs.clone(),
            quotient_bits,
            carry_bits,
            residual_bound,
            direct_residual_bound,
        })
    }

    pub fn quotient_bits(&self) -> u32 {
        self.quotient_bits
    }
    pub fn carry_bits(&self) -> u32 {
        self.carry_bits
    }
    pub(super) fn plane_count(&self) -> usize {
        self.planes
    }
    pub fn max_residual_bound(&self) -> i128 {
        self.residual_bound
    }

    pub fn direct_residual_bound(&self) -> Option<i128> {
        self.direct_residual_bound
    }

    /// Public signed digit coefficients for one backend ring equation. Inputs
    /// retain their original binary-variable handles. Add `-q_digit * z`, the
    /// previous carry, and `-base * next_carry`; endpoint carries are zero.
    pub fn plane_terms(
        &self,
        plane: usize,
    ) -> Option<impl Iterator<Item = (Vec<i64>, usize)> + '_> {
        (plane < self.planes).then(|| {
            self.terms.iter().map(move |(p, index)| {
                (
                    p.c.iter()
                        .map(|&v| digit(centered(v), plane, self.radix_bits) as i64)
                        .collect(),
                    *index,
                )
            })
        })
    }

    pub fn plane_rhs(&self, plane: usize) -> Option<Vec<i64>> {
        (plane < self.planes).then(|| {
            self.rhs
                .c
                .iter()
                .map(|&v| digit(centered(v), plane, self.radix_bits) as i64)
                .collect()
        })
    }

    pub fn plane_modulus_digit(&self, plane: usize) -> Option<i64> {
        (plane < self.planes).then(|| digit(i128::from(Poly::Q), plane, self.radix_bits) as i64)
    }

    fn evaluate(
        &self,
        relation: &CompiledAmountRelation,
        plane: Option<usize>,
    ) -> Result<Zeroizing<Vec<i128>>, LiftError> {
        let convert = |v| {
            let x = centered(v);
            plane.map_or(x, |j| digit(x, j, self.radix_bits))
        };
        let mut result =
            Zeroizing::new(self.rhs.c.iter().map(|&v| -convert(v)).collect::<Vec<_>>());
        for (coefficient, index) in &self.terms {
            let input = relation.witness(*index).ok_or(LiftError::InvalidWitness)?;
            let bound = relation.variable_bound(*index).ok_or(LiftError::InvalidWitness)?;
            // Variable coefficients are small non-negative integers (bits or
            // digits), never centered residues.
            if input.c.len() != Poly::D || input.c.iter().any(|&v| v > bound) {
                return Err(LiftError::InvalidWitness);
            }
            for (i, &a) in coefficient.c.iter().enumerate() {
                let a = convert(a);
                if a == 0 {
                    continue;
                }
                for (j, &b) in input.c.iter().enumerate() {
                    let k = i + j;
                    result[k % Poly::D] += if k < Poly::D { a } else { -a } * i128::from(b);
                }
            }
        }
        Ok(result)
    }

    fn assign(&self, relation: &CompiledAmountRelation) -> Result<LiftWitness, LiftError> {
        let mut quotient = self.evaluate(relation, None)?;
        for value in quotient.iter_mut() {
            if *value % i128::from(Poly::Q) != 0 {
                return Err(LiftError::InvalidWitness);
            }
            *value /= i128::from(Poly::Q);
            if !in_range(*value, self.quotient_bits) {
                return Err(LiftError::InvalidWitness);
            }
        }
        let mut carries = Zeroizing::new(Vec::<Vec<i128>>::new());
        for plane in 0..self.planes {
            let residual = self.evaluate(relation, Some(plane))?;
            let mut next = Zeroizing::new(vec![0; Poly::D]);
            for k in 0..Poly::D {
                let value = residual[k] - digit(i128::from(Poly::Q), plane, self.radix_bits) * quotient[k]
                    + if plane == 0 { 0 } else { carries[plane - 1][k] };
                if value % (1i128 << self.radix_bits) != 0 {
                    return Err(LiftError::InvalidWitness);
                }
                next[k] = value / (1i128 << self.radix_bits);
                if !in_range(next[k], self.carry_bits) || (plane == self.planes - 1 && next[k] != 0) {
                    return Err(LiftError::InvalidWitness);
                }
            }
            if plane < self.planes - 1 {
                carries.push(next.to_vec());
            }
        }
        Ok(LiftWitness { quotient, carries })
    }

    /// Cross-check using p, exact signed ranges and zero endpoint carries.
    /// This function has the private assignment and is NOT a network verifier.
    pub fn validate_local_witness(
        &self,
        relation: &CompiledAmountRelation,
        witness: &LiftWitness,
    ) -> bool {
        if witness.quotient.len() != Poly::D
            || witness.carries.len() != self.planes - 1
            || witness
                .quotient
                .iter()
                .any(|&z| !in_range(z, self.quotient_bits))
            || witness
                .carries
                .iter()
                .any(|c| c.len() != Poly::D || c.iter().any(|&v| !in_range(v, self.carry_bits)))
        {
            return false;
        }
        (0..self.planes).all(|plane| {
            let Ok(residual) = self.evaluate(relation, Some(plane)) else {
                return false;
            };
            (0..Poly::D).all(|k| {
                let value = residual[k] - digit(i128::from(Poly::Q), plane, self.radix_bits) * witness.quotient[k]
                    + if plane == 0 {
                        0
                    } else {
                        witness.carries[plane - 1][k]
                    }
                    - if plane == self.planes - 1 {
                        0
                    } else {
                        (1i128 << self.radix_bits) * witness.carries[plane][k]
                    };
                value.rem_euclid(PROOF_MODULUS) == 0
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_amount_rows_lift_with_hidden_and_public_targets() {
        let context = [19; 32];
        let key = CommitmentKey::derive(&context);
        let input = AmountOpening::from_seed(&context, &[21; 32]);
        let output = AmountOpening::from_seed(&context, &[22; 32]);
        let amount = u128::MAX;
        let ci = key.commit(amount, &input);
        let co = key.commit(amount - 1, &output);
        let relation = CompiledAmountRelation::compile(
            &key,
            &[(amount, &input, &ci)],
            &[(amount - 1, &output, &co)],
            0,
            1,
        )
        .unwrap();
        for plan in relation.ring_backend_plans() {
            let plan = plan.unwrap();
            assert!(plan.max_residual_bound() < PROOF_MODULUS / 2);
            let witness = relation.lift_ring_witness(&plan).unwrap();
            assert!(plan.validate_local_witness(&relation, &witness));
            assert!(plan
                .encode_binary_witness(&witness)
                .unwrap()
                .validate_local_witness(&relation));
        }
    }

    #[test]
    fn negacyclic_lifting_checks_quotients_carries_and_domains() {
        let a = Poly {
            c: (0..Poly::D)
                .map(|i| {
                    if i % 2 == 0 {
                        Poly::Q - 1 - i as u64
                    } else {
                        Poly::Q / 2 - i as u64
                    }
                })
                .collect(),
        };
        let b = Poly {
            c: (0..Poly::D).map(|i| u64::from(i % 3 != 0)).collect(),
        };
        let rhs = a.mul(&b);
        let mut relation = CompiledAmountRelation {
            binary: vec![b], short: Vec::new(), short_bound: Vec::new(), exact_ring: Vec::new(), ring: vec![RingEquation {
                terms: vec![(a, 0)],
                rhs,
            }],
            scalar: Vec::new(),
            input_commitment_planes: Vec::new(),
            membership: membership::MembershipConstraints::default(),
        };
        let plan = relation.ring_backend_plans().next().unwrap().unwrap();
        let mut witness = relation.lift_ring_witness(&plan).unwrap();
        assert!(plan.validate_local_witness(&relation, &witness));
        assert!(witness.quotient.iter().any(|&z| z != 0));
        witness.carries[0][0] += 1;
        assert!(!plan.validate_local_witness(&relation, &witness));
        witness.carries[0][0] -= 1;
        witness.quotient[0] += PROOF_MODULUS;
        assert!(!plan.validate_local_witness(&relation, &witness));
        relation.binary[0].c[0] = 2;
        assert!(matches!(
            relation.lift_ring_witness(&plan),
            Err(LiftError::InvalidWitness)
        ));
        relation.ring[0].rhs.c.pop();
        assert!(matches!(
            relation.ring_backend_plans().next().unwrap(),
            Err(LiftError::InvalidShape)
        ));
    }
    #[test]
    #[ignore = "public fixture diagnostic; estimates alternate radix bounds without changing proof equations"]
    fn public_fixture_lift_radix_census() {
        use crate::confidential::transfer::{CompileLimits, Transfer};
        let path = std::env::var("QUIL_LIFT_CENSUS_TRANSACTION").expect("public fixture path");
        let bytes = std::fs::read(path).unwrap();
        // This diagnostic uses the example fixture's explicit expected domains.
        let tx = Transfer::decode(&bytes, &[1; 32], &[2; 32]).unwrap();
        let public = tx.statement.public_relation(CompileLimits {
            max_inputs: 2, max_outputs: 2, max_depth: 32,
        }).unwrap();
        let radices = [8u32, 12, 16, 18];
        let exact = public.relation.exact_ring.len();
        let mut totals = [(exact, 0usize, exact, 0usize, 0i128); 4];
        // Membership hashes are native proof-ring rows and need no lifting;
        // the census covers the lifted amount/context rows.
        for plan in public.relation.ring_backend_plans() {
            let plan = plan.unwrap();
            for (slot, &bits) in radices.iter().enumerate() {
                let (rows, auxiliary, direct, rejected, max_residual) = &mut totals[slot];
                if plan.direct_residual_bound().is_some() {
                    *rows += 1; *direct += 1; continue;
                }
                let base = 1i128 << bits;
                let planes = 36u32.div_ceil(bits) as usize;
                let digit_at = |v: i128, plane: usize| {
                    v.signum() * ((v.abs() >> (bits as usize * plane)) & (base - 1))
                };
                let z_bound = 1i128 << (plan.quotient_bits - 1);
                let mut maximum = 0i128;
                let mut carry = 0i128;
                for plane in 0..planes {
                    let bound = plan.terms.iter().flat_map(|(p, _)| &p.c)
                        .map(|&v| digit_at(centered(v), plane).abs()).sum::<i128>()
                        + plan.rhs.c.iter().map(|&v| digit_at(centered(v), plane).abs()).max().unwrap()
                        + digit_at(i128::from(Poly::Q), plane) * z_bound;
                    maximum = maximum.max(bound);
                    carry = (carry + bound) / base;
                }
                carry = carry.max((maximum + base - 2) / (base - 1));
                let carry_bits = signed_bits(carry).unwrap();
                let residual = maximum + (base + 1) * (1i128 << (carry_bits - 1));
                *max_residual = (*max_residual).max(residual);
                if residual >= PROOF_MODULUS / 2 { *rejected += 1; continue; }
                if bits == plan.radix_bits {
                    assert_eq!(carry_bits, plan.carry_bits);
                    assert_eq!(residual, plan.residual_bound);
                }
                *rows += planes;
                *auxiliary += plan.quotient_bits as usize + (planes - 1) * carry_bits as usize;
            }
        }
        for (bits, (rows, auxiliary, direct, rejected, maximum)) in radices.into_iter().zip(totals) {
            eprintln!("lift_radix_census depth={} radix_bits={bits} accepted_rows={rows} auxiliary_binary_polynomials={auxiliary} direct_rows={direct} rejected_plans={rejected} max_residual_bound={maximum} proof_half_modulus={}", tx.statement.depth, PROOF_MODULUS / 2);
        }
    }

    #[test]
    fn alternate_radices_preserve_assignments_and_emitted_equations() {
        let a = Poly { c: (0..Poly::D).map(|i| match i % 4 {
            0 => Poly::Q - 1 - i as u64,
            1 => Poly::Q / 2 - i as u64,
            2 => 1 << 18,
            _ => 1,
        }).collect() };
        let b = Poly { c: (0..Poly::D).map(|i| u64::from(i % 3 != 0)).collect() };
        let rhs = a.mul(&b);
        let relation = CompiledAmountRelation {
            binary: vec![b], short: Vec::new(), short_bound: Vec::new(), exact_ring: Vec::new(), ring: vec![RingEquation { terms: vec![(a, 0)], rhs }],
            scalar: Vec::new(), input_commitment_planes: Vec::new(),
            membership: membership::MembershipConstraints::default(),
        };
        let reference = RingLiftPlan::new(&relation.ring[0], &relation).unwrap();
        let original = reference.assign(&relation).unwrap();
        for bits in [8, 12, 16, 18] {
            let plan = RingLiftPlan::new_with_radix(&relation.ring[0], &relation, bits).unwrap();
            let mut witness = plan.assign(&relation).unwrap();
            assert_eq!(&*original.quotient, &*witness.quotient);
            assert_eq!(witness.carries.len(), 36u32.div_ceil(bits) as usize - 1);
            assert!(plan.validate_local_witness(&relation, &witness));
            let encoded = plan.encode_binary_witness(&witness).unwrap();
            assert_eq!(encoded.rows().len(), plan.planes);
            assert!(encoded.validate_local_witness(&relation));
            // Independent public p-ring checker rejects an incorrect carry.
            witness.carries[0][0] += 1;
            assert!(!plan.validate_local_witness(&relation, &witness));
            assert!(!plan.encode_binary_witness(&witness).unwrap().validate_local_witness(&relation));
            witness.carries[0][0] -= 1;
            witness.carries[0][0] = 1i128 << (plan.carry_bits - 1);
            assert!(matches!(plan.encode_binary_witness(&witness), Err(LiftError::InvalidWitness)));
        }
    }

    #[test]
    fn alternate_radix_rejects_unsafe_public_bound() {
        let coefficient = Poly { c: vec![Poly::Q / 2; Poly::D] };
        let row = RingEquation { terms: vec![(coefficient, 0); 4096], rhs: Poly::zero() };
        let relation = CompiledAmountRelation {
            binary: vec![Poly::zero()], short: Vec::new(), short_bound: Vec::new(),
            ring: Vec::new(), exact_ring: Vec::new(), scalar: Vec::new(),
            input_commitment_planes: Vec::new(), membership: membership::MembershipConstraints::default(),
        };
        assert!(matches!(RingLiftPlan::new_with_radix(&row, &relation, 18), Err(LiftError::ResidualMayWrap)));
        assert!(RingLiftPlan::new_with_radix(&row, &relation, 8).is_ok());
        let fallback = RingLiftPlan::new(&row, &relation).unwrap();
        assert_eq!(fallback.radix_bits, 8);
        assert_eq!(fallback.plane_count(), 5);
        for bits in [0, 1, 63] {
            assert!(matches!(RingLiftPlan::new_with_radix(&row, &relation, bits), Err(LiftError::InvalidShape)));
        }
    }

}

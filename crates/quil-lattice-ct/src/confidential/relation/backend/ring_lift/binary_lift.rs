//! Binary range encoding and public p-ring rows for the five-plane lift.
//! All auxiliary coefficients are bits, including the two's-complement sign
//! planes. The native proof frontend must enforce those binary domains.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Variable {
    Original(usize),
    Auxiliary(usize),
}

/// Signed public coefficients in Z_p[X]/(X^256+1), not in the original R_q.
#[derive(Debug, PartialEq, Eq)]
pub struct BinaryLiftRow {
    pub terms: Vec<(Vec<i64>, Variable)>,
    pub rhs: Vec<i64>,
}

/// Public equations and binary-domain count, with no auxiliary assignment.
#[derive(Debug, PartialEq, Eq)]
pub struct BinaryLiftStatement {
    rows: Vec<BinaryLiftRow>,
    auxiliary_polynomials: usize,
}

impl BinaryLiftStatement {
    pub fn rows(&self) -> &[BinaryLiftRow] {
        &self.rows
    }
    pub fn auxiliary_polynomials(&self) -> usize {
        self.auxiliary_polynomials
    }
}

/// The auxiliary assignment has no Debug or wire API and is erased on drop.
pub struct BinaryLift {
    statement: BinaryLiftStatement,
    auxiliary: Zeroizing<Vec<Vec<u8>>>,
}

fn weight(bit: u32, width: u32) -> i64 {
    if bit + 1 == width {
        -(1i64 << bit)
    } else {
        1i64 << bit
    }
}

fn encode(values: &[i128], width: u32, output: &mut Vec<Vec<u8>>) -> Result<usize, LiftError> {
    if values.len() != Poly::D || values.iter().any(|&v| !in_range(v, width)) {
        return Err(LiftError::InvalidWitness);
    }
    let start = output.len();
    for bit in 0..width {
        output.push(values.iter().map(|&v| ((v >> bit) & 1) as u8).collect());
    }
    Ok(start)
}

impl RingLiftPlan {
    pub fn encode_relation(
        &self,
        relation: &CompiledAmountRelation,
    ) -> Result<BinaryLift, LiftError> {
        if self.direct_residual_bound.is_some() {
            self.encode_binary_witness(&LiftWitness {
                quotient: Zeroizing::new(Vec::new()),
                carries: Zeroizing::new(Vec::new()),
            })
        } else {
            self.encode_binary_witness(&relation.lift_ring_witness(self)?)
        }
    }
    /// Emit equations and auxiliary binary domains using only public plan data.
    /// This does not evaluate, allocate or require a private witness.
    pub fn public_statement(&self) -> BinaryLiftStatement {
        if self.direct_residual_bound.is_some() {
            return BinaryLiftStatement {
                rows: vec![BinaryLiftRow {
                    terms: self
                        .terms
                        .iter()
                        .map(|(p, i)| {
                            (
                                p.c.iter().map(|&v| centered(v) as i64).collect(),
                                Variable::Original(*i),
                            )
                        })
                        .collect(),
                    rhs: self.rhs.c.iter().map(|&v| centered(v) as i64).collect(),
                }],
                auxiliary_polynomials: 0,
            };
        }
        let z = 0;
        let carries: Vec<_> = (0..self.planes - 1)
            .map(|i| self.quotient_bits as usize + i * self.carry_bits as usize)
            .collect();
        let rows = (0..self.planes)
            .map(|plane| {
                let mut terms: Vec<_> = self
                    .plane_terms(plane)
                    .unwrap()
                    .map(|(p, i)| (p, Variable::Original(i)))
                    .collect();
                let mut append = |start: usize, width: u32, scale: i64| {
                    for bit in 0..width {
                        let mut coefficient = vec![0; Poly::D];
                        coefficient[0] = scale * weight(bit, width);
                        terms.push((coefficient, Variable::Auxiliary(start + bit as usize)));
                    }
                };
                append(
                    z,
                    self.quotient_bits,
                    -self.plane_modulus_digit(plane).unwrap(),
                );
                if plane > 0 {
                    append(carries[plane - 1], self.carry_bits, 1);
                }
                if plane + 1 < self.planes {
                    append(carries[plane], self.carry_bits, -(1i64 << self.radix_bits));
                }
                BinaryLiftRow {
                    terms,
                    rhs: self.plane_rhs(plane).unwrap(),
                }
            })
            .collect();
        BinaryLiftStatement {
            rows,
            auxiliary_polynomials: self.quotient_bits as usize
                + (self.planes - 1) * self.carry_bits as usize,
        }
    }

    /// Attach a checked private assignment to exactly the public equations.
    pub fn encode_binary_witness(&self, witness: &LiftWitness) -> Result<BinaryLift, LiftError> {
        let statement = self.public_statement();
        let mut auxiliary = Zeroizing::new(Vec::new());
        if self.direct_residual_bound.is_none() {
            if witness.carries.len() != self.planes - 1 {
                return Err(LiftError::InvalidWitness);
            }
            encode(&witness.quotient, self.quotient_bits, &mut auxiliary)?;
            for carry in witness.carries.iter() {
                encode(carry, self.carry_bits, &mut auxiliary)?;
            }
        }
        debug_assert_eq!(auxiliary.len(), statement.auxiliary_polynomials());
        Ok(BinaryLift {
            statement,
            auxiliary,
        })
    }
}

impl BinaryLift {
    /// Trusted prover-adapter callback. Coefficients are secrets and must never
    /// enter logs or transaction serialization. Borrowed slices expire on return.
    pub fn visit_private_auxiliary<E>(
        &self,
        mut visit: impl FnMut(usize, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        for (index, coefficients) in self.auxiliary.iter().enumerate() {
            visit(index, coefficients)?;
        }
        Ok(())
    }
    pub fn rows(&self) -> &[BinaryLiftRow] {
        self.statement.rows()
    }
    pub fn auxiliary_polynomials(&self) -> usize {
        self.auxiliary.len()
    }

    /// Independent check of emitted binary equations modulo p. The integer
    /// quotient/carry representation is not used by this checker.
    pub fn validate_local_witness(&self, relation: &CompiledAmountRelation) -> bool {
        if self
            .auxiliary
            .iter()
            .any(|p| p.len() != Poly::D || p.iter().any(|&v| v > 1))
        {
            return false;
        }
        self.statement.rows().iter().all(|row| {
            let mut residual =
                Zeroizing::new(row.rhs.iter().map(|&v| -i128::from(v)).collect::<Vec<_>>());
            for (coefficient, variable) in &row.terms {
                let input: Zeroizing<Vec<u64>> = match *variable {
                    Variable::Original(index) => {
                        let Some(p) = relation.binary.get(index) else {
                            return false;
                        };
                        Zeroizing::new(p.c.clone())
                    }
                    Variable::Auxiliary(index) => {
                        let Some(p) = self.auxiliary.get(index) else {
                            return false;
                        };
                        Zeroizing::new(p.iter().map(|&v| u64::from(v)).collect())
                    }
                };
                if input.len() != Poly::D || input.iter().any(|&v| v > 1) {
                    return false;
                }
                for (i, &a) in coefficient.iter().enumerate() {
                    if a == 0 {
                        continue;
                    }
                    for (j, &b) in input.iter().enumerate() {
                        let k = i + j;
                        residual[k % Poly::D] +=
                            (if k < Poly::D { 1 } else { -1 }) * i128::from(a) * i128::from(b);
                    }
                }
            }
            residual.iter().all(|v| v.rem_euclid(PROOF_MODULUS) == 0)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publicly_bounded_small_rows_need_no_lifting_witness() {
        let relation = CompiledAmountRelation {
            binary: vec![Poly::one()], short: Vec::new(), short_bound: Vec::new(), ring: Vec::new(), exact_ring: Vec::new(),
            scalar: Vec::new(),
            input_commitment_planes: Vec::new(),
            membership: membership::MembershipConstraints::default(),
        };
        let row = RingEquation {
            terms: vec![(Poly::one().scalar_mul(-2), 0)],
            rhs: Poly::one().scalar_mul(-2),
        };
        let plan = RingLiftPlan::new(&row, &relation).unwrap();
        assert_eq!(plan.direct_residual_bound(), Some(4));
        let lifted = relation.lift_ring_witness(&plan).unwrap();
        let binary = plan.encode_binary_witness(&lifted).unwrap();
        assert_eq!(binary.auxiliary_polynomials(), 0);
        assert_eq!(binary.rows().len(), 1);
        assert!(binary.validate_local_witness(&relation));
    }

    #[test]
    fn signed_binary_ranges_cover_endpoints_without_aliases() {
        for width in [2, 14, 23, 24] {
            let half = 1i128 << (width - 1);
            for value in [-half, -1, 0, half - 1] {
                let mut bits = Vec::new();
                encode(&vec![value; Poly::D], width, &mut bits).unwrap();
                let recovered: i128 = bits
                    .iter()
                    .enumerate()
                    .map(|(b, p)| i128::from(p[0]) * i128::from(weight(b as u32, width)))
                    .sum();
                assert_eq!(value, recovered);
            }
            assert!(encode(&vec![half; Poly::D], width, &mut Vec::new()).is_err());
            assert!(encode(&vec![-half - 1; Poly::D], width, &mut Vec::new()).is_err());
        }
    }

    #[test]
    fn emitted_rows_enforce_binary_quotient_and_carry_witnesses() {
        let a = Poly {
            c: vec![Poly::Q / 2; Poly::D],
        };
        let b = Poly {
            c: vec![1; Poly::D],
        };
        let rhs = a.mul(&b);
        let relation = CompiledAmountRelation {
            binary: vec![b], short: Vec::new(), short_bound: Vec::new(), ring: Vec::new(), exact_ring: Vec::new(),
            scalar: Vec::new(),
            input_commitment_planes: Vec::new(),
            membership: membership::MembershipConstraints::default(),
        };
        let plan = RingLiftPlan::new(
            &RingEquation {
                terms: vec![(a, 0)],
                rhs,
            },
            &relation,
        )
        .unwrap();
        let witness = relation.lift_ring_witness(&plan).unwrap();
        let mut encoded = plan.encode_binary_witness(&witness).unwrap();
        assert!(encoded.validate_local_witness(&relation));
        assert_eq!(encoded.rows().len(), plan.plane_count());
        encoded.auxiliary[0][0] ^= 1;
        assert!(!encoded.validate_local_witness(&relation));
        encoded.auxiliary[0][0] ^= 1;
        let carry = plan.quotient_bits as usize;
        encoded.auxiliary[carry][0] ^= 1;
        assert!(!encoded.validate_local_witness(&relation));
        encoded.auxiliary[carry][0] = 2;
        assert!(!encoded.validate_local_witness(&relation));
    }
}

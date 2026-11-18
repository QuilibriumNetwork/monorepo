//! Vanishing-mask equation bundle: f(s)+g-h=0, with ct(g)=ct(h)=0.
//! This converts a constant-coefficient condition to a full ring equation only
//! together with its zero-constant constraints and binary witness domains.
use super::super::{expansion::ExpansionError, uniform::uniform_polynomials, MODULUS};
use super::*;

pub const VANISHING_BITS: usize = 38;

#[derive(Debug, PartialEq, Eq)]
pub enum VanishingError {
    NonvanishingResidual,
    Expansion(ExpansionError),
}

fn signed_planes(polynomial: &ProofPolynomial) -> Zeroizing<Vec<Vec<u8>>> {
    let mut planes = Zeroizing::new(vec![vec![0u8; DEGREE]; VANISHING_BITS]);
    for (index, &value) in polynomial.0.iter().enumerate() {
        let centered = if value > MODULUS / 2 {
            value as i64 - MODULUS as i64
        } else {
            value as i64
        };
        for (bit, plane) in planes.iter_mut().enumerate() {
            plane[index] = ((centered as u64 >> bit) & 1) as u8;
        }
    }
    planes
}

/// Sample and commit this private mask before deriving the aggregate f.
/// No Clone/Debug/serialization; finish consumes the prepared mask once.
pub struct PreparedVanishingMask {
    mask: ProofPolynomial,
    planes: Zeroizing<Vec<Vec<u8>>>,
}

pub struct VanishingWitness {
    mask_planes: Zeroizing<Vec<Vec<u8>>>,
    residual_planes: Zeroizing<Vec<Vec<u8>>>,
}

impl PreparedVanishingMask {
    pub fn sample(seed: &[u8; 32], nonce: u64) -> Result<Self, VanishingError> {
        Ok(Self::sample_many(seed, nonce, 1)?.remove(0))
    }
    /// Sample the protocol's entire mask batch in one uniform-sampler call.
    /// Separate one-mask calls would change its batch rejection/nonce schedule.
    pub fn sample_many(
        seed: &[u8; 32],
        nonce: u64,
        count: usize,
    ) -> Result<Vec<Self>, VanishingError> {
        Ok(uniform_polynomials(seed, nonce, count)
            .map_err(VanishingError::Expansion)?
            .into_iter()
            .map(|mut mask| {
                mask.0[0] = 0;
                let planes = signed_planes(&mask);
                Self { mask, planes }
            })
            .collect())
    }
    pub fn bitplanes(&self) -> &[Vec<u8>] {
        &self.planes
    }
    pub fn finish(self, residual: &ProofPolynomial) -> Result<VanishingWitness, VanishingError> {
        if residual.0[0] != 0 {
            return Err(VanishingError::NonvanishingResidual);
        }
        let masked = residual.add(&self.mask);
        Ok(VanishingWitness {
            mask_planes: self.planes,
            residual_planes: signed_planes(&masked),
        })
    }
}

impl VanishingWitness {
    pub fn mask_planes(&self) -> &[Vec<u8>] {
        &self.mask_planes
    }
    pub fn residual_planes(&self) -> &[Vec<u8>] {
        &self.residual_planes
    }
}

pub struct VanishingConstraint {
    ring: SparseConstraint,
    mask: Range<usize>,
    residual: Range<usize>,
}

fn overlaps(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start < b.end && b.start < a.end && !a.is_empty() && !b.is_empty()
}

impl VanishingConstraint {
    /// The 38-polynomial mask/residual slots must be disjoint and unused by f.
    /// They are reserved in the public layout before aggregation. The returned
    /// bundle must be consumed with all its zero-constant equations and domains.
    pub fn new(
        mut source: SparseConstraint,
        mask_offset: usize,
        residual_offset: usize,
    ) -> Result<Self, ConstraintError> {
        if source.domain != EquationDomain::ConstantCoefficient {
            return Err(ConstraintError::Domain);
        }
        let range = |offset: usize| -> Result<Range<usize>, ConstraintError> {
            let end = offset
                .checked_add(VANISHING_BITS)
                .filter(|&end| end <= source.layout.count)
                .ok_or(ConstraintError::Layout)?;
            Ok(offset..end)
        };
        let mask = range(mask_offset)?;
        let residual = range(residual_offset)?;
        if overlaps(&mask, &residual) {
            return Err(ConstraintError::Layout);
        }
        let reserved = |range: &Range<usize>| overlaps(range, &mask) || overlaps(range, &residual);
        for part in &source.linear {
            if reserved(&(part.offset..part.offset + part.coefficients.len())) {
                return Err(ConstraintError::Layout);
            }
        }
        for term in &source.quadratic {
            if reserved(&source.layout.groups[term.left_group])
                || reserved(&source.layout.groups[term.right_group])
            {
                return Err(ConstraintError::Layout);
            }
        }
        let powers = |sign: i64| {
            (0..VANISHING_BITS)
                .map(|bit| {
                    let mut coefficient = [0; DEGREE];
                    coefficient[0] =
                        sign * (1i64 << bit) * if bit + 1 == VANISHING_BITS { -1 } else { 1 };
                    ProofPolynomial::from_signed(&coefficient).unwrap()
                })
                .collect()
        };
        source.linear.push(LinearPart {
            offset: mask.start,
            coefficients: powers(1),
        });
        source.linear.push(LinearPart {
            offset: residual.start,
            coefficients: powers(-1),
        });
        source.domain = EquationDomain::Ring;
        Ok(Self {
            ring: source,
            mask,
            residual,
        })
    }

    pub fn ring_equation(&self) -> &SparseConstraint {
        &self.ring
    }

    /// Both ranges must be registered as exact binary variables with the prover.
    pub fn binary_ranges(&self) -> [Range<usize>; 2] {
        [self.mask.clone(), self.residual.clone()]
    }

    /// Every mask and residual bit-plane has zero constant coefficient. These
    /// checks must accompany the full-ring equation; dropping them changes it.
    pub fn zero_constant_equations(&self) -> Result<Vec<SparseConstraint>, ConstraintError> {
        let mut output = Vec::new();
        for range in self.binary_ranges() {
            for offset in range {
                let mut one = [0; DEGREE];
                one[0] = 1;
                output.push(SparseConstraint::new(
                    &self.ring.layout,
                    EquationDomain::ConstantCoefficient,
                    vec![LinearPart {
                        offset,
                        coefficients: vec![ProofPolynomial::from_signed(&one).unwrap()],
                    }],
                    vec![],
                    zero(),
                )?);
            }
        }
        Ok(output)
    }

    /// Assignment-level check of the complete bundle, including binary domains.
    pub fn check(&self, witness: &[ProofPolynomial]) -> Result<bool, ConstraintError> {
        if witness.len() != self.ring.layout.count {
            return Err(ConstraintError::Length);
        }
        for range in self.binary_ranges() {
            for polynomial in &witness[range] {
                if polynomial.0[0] != 0 || polynomial.0.iter().any(|&value| value > 1) {
                    return Ok(false);
                }
            }
        }
        self.ring.check(witness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poly(terms: &[(usize, i64)]) -> ProofPolynomial {
        let mut values = [0; DEGREE];
        for &(index, value) in terms {
            values[index] = value;
        }
        ProofPolynomial::from_signed(&values).unwrap()
    }

    fn source(layout: &WitnessLayout) -> SparseConstraint {
        SparseConstraint::new(
            layout,
            EquationDomain::ConstantCoefficient,
            vec![LinearPart {
                offset: 0,
                coefficients: vec![poly(&[(0, 1)])],
            }],
            vec![],
            poly(&[(0, 7)]),
        )
        .unwrap()
    }

    #[test]
    fn mask_batch_preserves_uniform_sampler_grouping() {
        let mut reference = uniform_polynomials(&[37; 32], 9, 5).unwrap();
        let masks = PreparedVanishingMask::sample_many(&[37; 32], 9, 5).unwrap();
        for (expected, mask) in reference.iter_mut().zip(masks) {
            expected.0[0] = 0;
            assert_eq!(expected.reference_bitpack(), mask.mask.reference_bitpack());
            assert!(mask.bitplanes().iter().all(|plane| plane[0] == 0));
        }
        assert!(PreparedVanishingMask::sample_many(&[37; 32], 9, 0)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn sampled_mask_lifts_scalar_equation_with_all_binding_checks() {
        let layout = WitnessLayout::new(&[1, VANISHING_BITS, VANISHING_BITS]).unwrap();
        let mask = PreparedVanishingMask::sample(&[19; 32], 7).unwrap();
        assert!(mask.bitplanes().iter().all(|plane| plane[0] == 0));
        let prepared = mask.finish(&poly(&[(1, 3), (255, -11)])).unwrap();
        let mut witness = vec![poly(&[(0, 7), (1, 3), (255, -11)])];
        for plane in prepared
            .mask_planes()
            .iter()
            .chain(prepared.residual_planes())
        {
            let coefficients: Vec<i64> = plane.iter().map(|&value| i64::from(value)).collect();
            witness.push(ProofPolynomial::from_signed(&coefficients).unwrap());
        }
        let equation = VanishingConstraint::new(source(&layout), 1, 1 + VANISHING_BITS).unwrap();
        assert!(equation.check(&witness).unwrap());
        let zeros = equation.zero_constant_equations().unwrap();
        assert_eq!(zeros.len(), 2 * VANISHING_BITS);
        assert!(zeros.iter().all(|row| row.check(&witness).unwrap()));
        // Equal changes to both constant terms leave the ring equation true,
        // but must fail the required zero-constant part of the bundle.
        witness[1] = witness[1].add(&poly(&[(0, 1)]));
        witness[1 + VANISHING_BITS] = witness[1 + VANISHING_BITS].add(&poly(&[(0, 1)]));
        assert!(equation.ring_equation().check(&witness).unwrap());
        assert!(!equation.check(&witness).unwrap());
        assert!(!zeros[0].check(&witness).unwrap());
    }

    #[test]
    fn signed_planes_recompose_centered_modulus_endpoints() {
        let original = poly(&[
            (1, (MODULUS / 2) as i64),
            (2, -((MODULUS / 2) as i64)),
            (3, -1),
        ]);
        let planes = signed_planes(&original);
        let mut values = [0i64; DEGREE];
        for (bit, plane) in planes.iter().enumerate() {
            let weight = (1i64 << bit) * if bit + 1 == VANISHING_BITS { -1 } else { 1 };
            for (out, &value) in values.iter_mut().zip(plane) {
                *out += i64::from(value) * weight;
            }
        }
        assert_eq!(
            original.reference_bitpack(),
            ProofPolynomial::from_signed(&values)
                .unwrap()
                .reference_bitpack()
        );
        assert!(matches!(
            PreparedVanishingMask::sample(&[1; 32], 0)
                .unwrap()
                .finish(&poly(&[(0, 1)])),
            Err(VanishingError::NonvanishingResidual)
        ));
    }

    #[test]
    fn lifting_rejects_reused_or_overlapping_reserved_slots() {
        let layout = WitnessLayout::new(&[1, VANISHING_BITS, VANISHING_BITS]).unwrap();
        assert!(matches!(
            VanishingConstraint::new(source(&layout), 1, 2),
            Err(ConstraintError::Layout)
        ));
        assert!(matches!(
            VanishingConstraint::new(source(&layout), 0, 1 + VANISHING_BITS),
            Err(ConstraintError::Layout)
        ));
        assert!(matches!(
            VanishingConstraint::new(source(&layout), usize::MAX, 1),
            Err(ConstraintError::Layout)
        ));
        let mut ring = source(&layout);
        ring.domain = EquationDomain::Ring;
        assert!(matches!(
            VanishingConstraint::new(ring, 1, 1 + VANISHING_BITS),
            Err(ConstraintError::Domain)
        ));
    }
}

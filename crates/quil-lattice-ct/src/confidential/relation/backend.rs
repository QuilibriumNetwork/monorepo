//! Checked translation of scalar constraints to the pinned backend's 38-bit ring.
//! This covers Boolean SHAKE gates, scalar selectors and amount conservation.
//! The ring_lift module handles linear R_q and expanded hash equations, with
//! binary auxiliary range encoding. Selection rows retain quadratic handles.
use super::*;

pub mod portable;
pub mod ring_lift;
pub mod submission;
#[cfg(feature = "native-proof")]
pub mod native;

/// Process lifecycle boundary for a trusted, separately executed verifier.
pub mod worker_process;
pub mod worker_request;
pub mod worker_limits;
pub mod worker_client;

/// Public handles for one quadratic selection row over the backend ring:
/// Σ_k w_k · (s·(one_k − zero_k) + zero_k − selected_k) = 0, with s a scalar
/// binary polynomial (its nonconstant coefficients are zero in the scalar
/// relation) and every other handle a binary or short witness. Weights let a
/// whole limb-represented node row be selected by one quadratic row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectionRow {
    pub selector: usize,
    /// (weight, zero, one, selected) per witness triple.
    pub terms: Vec<(i64, usize, usize, usize)>,
}

impl SelectionRow {
    /// Even without the scalar-selector restriction, two binary negacyclic
    /// products plus two binary linear terms have residual magnitude <=514.
    pub const RESIDUAL_BOUND: i128 = 2 * Poly::D as i128 + 2;

    /// Every handle referenced by the row, selector first.
    pub fn handles(&self) -> impl Iterator<Item = usize> + '_ {
        std::iter::once(self.selector)
            .chain(self.terms.iter().flat_map(|&(_, z, o, s)| [z, o, s]))
    }

    /// Private-assignment check, not a proof verifier. A native frontend emits
    /// the quadratic ring row AND retains the scalar-selector constraint.
    pub fn validate_local_witness(&self, relation: &CompiledAmountRelation) -> bool {
        let fetch = |i: usize| -> Option<&Poly> {
            let (p, bound) = (relation.witness(i)?, relation.variable_bound(i)?);
            (p.c.len() == Poly::D && p.c.iter().all(|&v| v <= bound)).then_some(p)
        };
        let Some(selector) = fetch(self.selector) else { return false };
        if selector.c[1..].iter().any(|&v| v != 0) || self.terms.is_empty() {
            return false;
        }
        let s = i128::from(selector.c[0]);
        let mut residual = vec![0i128; Poly::D];
        for &(w, z, o, sel) in &self.terms {
            let (Some(zero), Some(one), Some(selected)) = (fetch(z), fetch(o), fetch(sel)) else { return false };
            for i in 0..Poly::D {
                residual[i] += i128::from(w)
                    * (s * (i128::from(one.c[i]) - i128::from(zero.c[i]))
                        + i128::from(zero.c[i])
                        - i128::from(selected.c[i]));
            }
        }
        residual.into_iter().all(|v| v.rem_euclid(PROOF_MODULUS) == 0)
    }
}

pub const PROOF_MODULUS: i128 = (1i128 << 38) - 107;

#[derive(Debug, PartialEq, Eq)]
pub enum ScalarPlanError {
    InvalidIndex,
    ResidualMayWrap,
}

/// Public circuit data only. Terms address coefficients of binary polynomials.
/// A native adapter must combine repeated indices before populating its vectors.
pub struct ScalarRow<'a> {
    pub terms: &'a [(i64, usize, usize)],
    pub rhs: i64,
}

pub struct ScalarPlan<'a> {
    relation: &'a CompiledAmountRelation,
    max_residual_bound: i128,
}

impl CompiledAmountRelation {
    /// Certify that integer scalar equalities can be checked modulo the backend
    /// prime. The bound depends only on public coefficients and binary domains,
    /// never on the supplied private assignment. Binary constraints remain
    /// mandatory in the proof backend.
    pub fn scalar_backend_plan(&self) -> Result<ScalarPlan<'_>, ScalarPlanError> {
        let mut maximum = 0;
        for row in &self.scalar {
            let mut bound = i128::from(row.rhs).abs();
            for &(coefficient, polynomial, index) in &row.terms {
                if polynomial >= self.binary.len() || index >= Poly::D {
                    return Err(ScalarPlanError::InvalidIndex);
                }
                bound = bound
                    .checked_add(i128::from(coefficient).abs())
                    .ok_or(ScalarPlanError::ResidualMayWrap)?;
            }
            if bound >= PROOF_MODULUS / 2 {
                return Err(ScalarPlanError::ResidualMayWrap);
            }
            maximum = maximum.max(bound);
        }
        Ok(ScalarPlan {
            relation: self,
            max_residual_bound: maximum,
        })
    }
}

impl ScalarPlan<'_> {
    pub fn rows(&self) -> impl Iterator<Item = ScalarRow<'_>> {
        self.relation.scalar.iter().map(|row| ScalarRow {
            terms: &row.terms,
            rhs: row.rhs,
        })
    }

    pub fn max_residual_bound(&self) -> i128 {
        self.max_residual_bound
    }

    /// Private-assignment reference check, not a proof verifier. It deliberately
    /// evaluates modulo the backend prime to cross-check the integer checker.
    pub fn validate_local_witness(&self) -> bool {
        if self
            .relation
            .binary
            .iter()
            .any(|p| p.c.len() != Poly::D || p.c.iter().any(|&v| v > 1))
        {
            return false;
        }
        self.rows().all(|row| {
            let residual = row
                .terms
                .iter()
                .fold(-i128::from(row.rhs), |sum, &(a, p, c)| {
                    sum + i128::from(a) * i128::from(self.relation.binary[p].c[c])
                });
            residual.rem_euclid(PROOF_MODULUS) == 0
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_translation_requires_one_whole_node_choice() {
        let mut relation = CompiledAmountRelation {
            binary: vec![Poly::one(), Poly::zero(), Poly::one(), Poly::one()],
            short: Vec::new(), short_bound: Vec::new(),
            ring: Vec::new(), exact_ring: Vec::new(),
            scalar: Vec::new(),
            input_commitment_planes: Vec::new(),
            membership: membership::MembershipConstraints::default(),
        };
        let row = SelectionRow {
            selector: 0,
            terms: vec![(1, 1, 2, 3)],
        };
        assert!(SelectionRow::RESIDUAL_BOUND < PROOF_MODULUS / 2);
        assert!(row.validate_local_witness(&relation));
        relation.binary[3].c[1] = 1;
        assert!(!row.validate_local_witness(&relation));
        relation.binary[3].c[1] = 0;
        relation.binary[0].c[1] = 1;
        assert!(!row.validate_local_witness(&relation));
        relation.binary[0].c[1] = 0;
        relation.binary[0].c[0] = 2;
        assert!(!row.validate_local_witness(&relation));
    }

    #[test]
    fn scalar_translation_requires_public_bounds_and_binary_inputs() {
        let mut relation = CompiledAmountRelation {
            binary: vec![Poly::one()],
            short: Vec::new(), short_bound: Vec::new(),
            ring: Vec::new(), exact_ring: Vec::new(),
            scalar: vec![ScalarEquation {
                terms: vec![(1, 0, 0)],
                rhs: 1,
            }],
            input_commitment_planes: Vec::new(),
            membership: membership::MembershipConstraints::default(),
        };
        assert!(relation
            .scalar_backend_plan()
            .unwrap()
            .validate_local_witness());
        relation.binary[0].c[0] = 2;
        assert!(!relation
            .scalar_backend_plan()
            .unwrap()
            .validate_local_witness());
        relation.binary[0].c[0] = 1;
        relation.scalar[0].rhs = PROOF_MODULUS as i64 + 1;
        assert!(matches!(
            relation.scalar_backend_plan(),
            Err(ScalarPlanError::ResidualMayWrap)
        ));
        relation.scalar[0].rhs = 1;
        relation.scalar[0].terms[0].2 = 256;
        assert!(matches!(
            relation.scalar_backend_plan(),
            Err(ScalarPlanError::InvalidIndex)
        ));
    }
}

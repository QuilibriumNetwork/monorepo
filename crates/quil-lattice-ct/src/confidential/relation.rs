//! Backend-independent amount constraints over the commitment ring.
//!
//! Input commitments are hidden binary decompositions; output commitments are
//! public constants. This is a prover-side constraint compiler and assignment
//! checker, NOT a ZK proof. Optional membership/ownership constraints are compiled
//! by the `membership` child module.
//! A backend adapter must preserve every binary/linear/scalar constraint and
//! correctly lift equations to its own modulus before this can form a proof.

use super::*;

pub mod backend;
pub mod membership;
mod public_spend;
mod exact_ring;
use exact_ring::ExactRingEquation;

#[derive(PartialEq, Eq)]
struct RingEquation {
    terms: Vec<(Poly, usize)>,
    rhs: Poly,
}

#[derive(PartialEq, Eq)]
struct ScalarEquation {
    // (integer coefficient, binary witness polynomial, coefficient index)
    terms: Vec<(i64, usize, usize)>,
    rhs: i64,
}

/// Private witness storage intentionally has no Debug or serialization API.
/// Constraint coefficients depend only on public parameters/counts/outputs.
/// Handles of approximate-norm ("short") witness polynomials carry this tag;
/// binary handles are plain indices. Resolved to one global index space at
/// submission: [binary originals][lifting auxiliaries][short polynomials].
pub(crate) const SHORT_TAG: usize = 1 << 62;

pub struct CompiledAmountRelation {
    binary: Vec<Poly>,
    /// Short witness polynomials with per-polynomial coefficient bounds
    /// (0 ≤ c ≤ bound). Proven by the backend as l2-norm bounds, not exactly.
    short: Vec<Poly>,
    short_bound: Vec<u64>,
    ring: Vec<RingEquation>,
    exact_ring: Vec<ExactRingEquation>,
    scalar: Vec<ScalarEquation>,
    // Stable handles for adding membership to the same private commitment.
    input_commitment_planes: Vec<[[usize; 36]; BINDING_RANK + 1]>,
    membership: membership::MembershipConstraints,
}

/// A circuit reconstructed from public inputs. It has no private submission or
/// witness-checking API. Construction discards all temporary placeholder values.
pub struct PublicAmountRelation {
    relation: CompiledAmountRelation,
}

impl PublicAmountRelation {
    /// Reconstruct the amount equations for issuing confidential outputs from
    /// an independently authorized public inflow. There are no private input
    /// coins, membership paths or spend images. This does not authorize minting:
    /// the enclosing operation must verify the funding entitlement and bind its
    /// full canonical context with `with_transaction_context`.
    pub fn compile_issuance(
        key: &CommitmentKey,
        outputs: &[AmountCommitment],
        inflow: u128,
        outflow: u128,
    ) -> Result<Self, TokenError> {
        if outputs.is_empty() { return Err(TokenError::Length); }
        if outputs.len() > MAX_PRIVATE_COINS { return Err(TokenError::TooManyCoins); }
        let opening = AmountOpening { r: std::array::from_fn(|_| Poly::zero()) };
        let output_coins: Vec<_> = outputs.iter().map(|c| (0, &opening, c)).collect();
        let mut relation = CompiledAmountRelation::compile_graph(
            key, &[], &output_coins, inflow, outflow, &BalanceTrace { carries: [0; 17] },
        );
        relation.erase_private();
        Ok(Self { relation })
    }

    /// Bind the same canonical, proof-excluding transaction bytes as the prover.
    /// This includes recipient IDs, memos, operation and network/application
    /// context. Encoding and field completeness are the caller's responsibility.
    pub fn with_transaction_context(mut self, canonical_context: &[u8]) -> Self {
        let first = self.relation.binary.len();
        self.relation.bind_transaction_context(canonical_context);
        for polynomial in &mut self.relation.binary[first..] {
            polynomial.c.zeroize();
            polynomial.c.clear();
            polynomial.c.shrink_to_fit();
        }
        self
    }

    pub fn submit<S: backend::submission::StatementSink>(
        &self,
        sink: &mut S,
    ) -> Result<backend::submission::SubmissionCounts, backend::submission::SubmissionError<S::Error>>
    {
        self.relation.submit_public_statement(sink)
    }
}

impl Drop for CompiledAmountRelation {
    fn drop(&mut self) {
        for p in self.binary.iter_mut().chain(&mut self.short) {
            p.c.zeroize();
        }
    }
}

impl CompiledAmountRelation {
    /// Erase private assignments while retaining public structure. Public
    /// relations call this after construction with placeholder witnesses.
    pub(crate) fn erase_private(&mut self) {
        for p in self.binary.iter_mut().chain(&mut self.short) {
            p.c.zeroize();
            p.c.clear();
            p.c.shrink_to_fit();
        }
    }

    /// Allocate a short witness polynomial with an explicit coefficient bound.
    #[allow(dead_code)]
    pub(crate) fn short(&mut self, p: Poly, bound: u64) -> usize {
        assert!(bound >= 1 && bound < (1 << 31));
        assert!(p.c.len() == Poly::D && p.c.iter().all(|&c| c <= bound));
        let index = self.short.len();
        self.short.push(p);
        self.short_bound.push(bound);
        SHORT_TAG | index
    }

    pub(crate) fn short_count(&self) -> usize {
        self.short.len()
    }

    /// Squared l2 bound declared to the backend for each short polynomial.
    pub(crate) fn short_normsq(&self) -> Vec<u64> {
        self.short_bound.iter().map(|&b| (Poly::D as u64) * b * b).collect()
    }

    /// Witness value for a binary or short handle; `None` for unknown handles.
    pub(crate) fn witness(&self, handle: usize) -> Option<&Poly> {
        if handle & SHORT_TAG != 0 { self.short.get(handle ^ SHORT_TAG) } else { self.binary.get(handle) }
    }

    /// Coefficient magnitude bound for a handle (1 for binary variables).
    pub(crate) fn variable_bound(&self, handle: usize) -> Option<u64> {
        if handle & SHORT_TAG != 0 { self.short_bound.get(handle ^ SHORT_TAG).copied() } else { (handle < self.binary.len()).then_some(1) }
    }

    /// Global backend index of a handle given the auxiliary count.
    pub(crate) fn resolve(&self, handle: usize, auxiliary: usize) -> usize {
        if handle & SHORT_TAG != 0 { self.binary.len() + auxiliary + (handle ^ SHORT_TAG) } else { handle }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelationShape {
    pub binary_polynomials: usize,
    pub ring_equations: usize,
    pub scalar_equations: usize,
}

impl CompiledAmountRelation {
    /// Prover counterpart to `PublicAmountRelation::compile_issuance`.
    /// Proves the output openings and exact public-inflow conservation only;
    /// authorization and canonical operation-context binding remain external.
    pub fn compile_issuance(
        key: &CommitmentKey,
        outputs: &[(u128, &AmountOpening, &AmountCommitment)],
        inflow: u128,
        outflow: u128,
    ) -> Result<Self, TokenError> {
        if outputs.is_empty() { return Err(TokenError::Length); }
        Self::compile(key, &[], outputs, inflow, outflow)
    }

    /// Bind canonical transaction bytes excluding the proof itself. Use exactly
    /// the same bytes in `PublicAmountRelation::with_transaction_context`.
    /// The digest becomes public equation data, so the backend statement hash
    /// covers it without treating transaction fields as private witnesses.
    pub fn with_transaction_context(mut self, canonical_context: &[u8]) -> Self {
        self.bind_transaction_context(canonical_context);
        self
    }

    fn bind_transaction_context(&mut self, canonical_context: &[u8]) {
        let mut hash = Shake256::default();
        hash.update(b"quil/token/transaction-context/v2\0");
        hash.update(&(canonical_context.len() as u64).to_le_bytes());
        hash.update(canonical_context);
        let mut digest = [0u8; 64];
        hash.finalize_xof().read(&mut digest);
        for chunk in digest.chunks_exact(32) {
            let bits = Poly {
                c: (0..256)
                    .map(|i| u64::from((chunk[i / 8] >> (i % 8)) & 1))
                    .collect(),
            };
            let index = self.binary(bits.clone());
            self.ring.push(RingEquation {
                terms: vec![(Poly::one(), index)],
                rhs: bits,
            });
        }
    }

    fn binary(&mut self, p: Poly) -> usize {
        let index = self.binary.len();
        self.binary.push(p);
        index
    }

    fn bit_planes(&mut self, p: &Poly) -> [usize; 36] {
        std::array::from_fn(|bit| {
            self.binary(Poly {
                c: p.c.iter().map(|&c| (c >> bit) & 1).collect(),
            })
        })
    }

    /// Prove x+c=q-1 exactly over the proof modulus, with 36-bit x and c.
    /// The public interval check excludes wraparound; no R_q centering is valid.
    fn canonical_residue(&mut self, p: &Poly) -> [usize; 36] {
        let value = self.bit_planes(p);
        let complement = self.bit_planes(&Poly {
            c: p.c.iter().map(|&v| Poly::Q - 1 - v).collect(),
        });
        self.exact_ring.push(ExactRingEquation {
            terms: (0..36).flat_map(|bit| {
                [(1i64 << bit, value[bit]), (1i64 << bit, complement[bit])]
            }).collect(),
            rhs: (Poly::Q - 1) as i64,
        });
        value
    }

    /// One-hot masks constrain each opening coefficient to exactly [-2,2].
    fn opening_masks(&mut self, opening: &AmountOpening) -> [[usize; 5]; OPENING_RANK] {
        self.short_masks(&opening.r)
    }

    fn short_masks<const N: usize>(&mut self, secret: &[Poly; N]) -> [[usize; 5]; N] {
        std::array::from_fn(|i| {
            let indices = std::array::from_fn(|value| {
                let residue = (value as i64 - 2).rem_euclid(Poly::Q as i64) as u64;
                self.binary(Poly {
                    c: secret[i]
                        .c
                        .iter()
                        .map(|&c| u64::from(c == residue))
                        .collect(),
                })
            });
            self.ring.push(RingEquation {
                terms: indices.iter().map(|&index| (Poly::one(), index)).collect(),
                rhs: Poly {
                    c: vec![1; Poly::D],
                },
            });
            indices
        })
    }

    fn coin(
        &mut self,
        key: &CommitmentKey,
        amount: u128,
        opening: &AmountOpening,
        commitment: &AmountCommitment,
        hidden: bool,
    ) -> usize {
        let message = self.binary(amount_message(amount));
        // A sum of binary coefficients is zero iff each is zero; sum <=128<q.
        self.scalar.push(ScalarEquation {
            terms: (128..Poly::D).map(|j| (1, message, j)).collect(),
            rhs: 0,
        });
        let masks = self.opening_masks(opening);
        let mut input_planes = [[0; 36]; BINDING_RANK + 1];
        for row in 0..=BINDING_RANK {
            let mut coefficients: [Poly; OPENING_RANK] = std::array::from_fn(|_| Poly::zero());
            if row < BINDING_RANK {
                coefficients[row] = Poly::one();
                coefficients[BINDING_RANK] = key.u[row].clone();
                coefficients[BINDING_RANK + 1..].clone_from_slice(&key.v[row]);
            } else {
                coefficients[BINDING_RANK] = Poly::one();
                coefficients[BINDING_RANK + 1..].clone_from_slice(&key.w);
            }
            let mut terms = Vec::new();
            for (coefficient, indices) in coefficients.iter().zip(&masks) {
                if coefficient.c.iter().all(|&c| c == 0) {
                    continue;
                }
                for (value, &index) in indices.iter().enumerate() {
                    if value != 2 {
                        terms.push((coefficient.scalar_mul(value as i64 - 2), index));
                    }
                }
            }
            if row == BINDING_RANK {
                terms.push((Poly::one(), message));
            }
            let rhs = if hidden {
                let planes = self.canonical_residue(&commitment.t[row]);
                input_planes[row] = planes;
                for (bit, index) in planes.into_iter().enumerate() {
                    terms.push((Poly::one().scalar_mul(-(1i64 << bit)), index));
                }
                Poly::zero()
            } else {
                commitment.t[row].clone()
            };
            self.ring.push(RingEquation { terms, rhs });
        }
        if hidden {
            self.input_commitment_planes.push(input_planes);
        }
        message
    }

    /// Compile only the amount component of the eventual transaction relation.
    /// Inputs are private; outputs and public aggregates are public. The caller
    /// must later connect these input commitments to membership/ownership using
    /// the SAME witness variables, not unlinked second copies.
    pub fn compile(
        key: &CommitmentKey,
        inputs: &[(u128, &AmountOpening, &AmountCommitment)],
        outputs: &[(u128, &AmountOpening, &AmountCommitment)],
        inflow: u128,
        outflow: u128,
    ) -> Result<Self, TokenError> {
        let trace = check_amount_witness(key, inputs, outputs, inflow, outflow)?;
        Ok(Self::compile_graph(
            key, inputs, outputs, inflow, outflow, &trace,
        ))
    }

    // Shared circuit construction. The prover checks its assignment before
    // entering here; public compilation uses fixed placeholders only.
    fn compile_graph(
        key: &CommitmentKey,
        inputs: &[(u128, &AmountOpening, &AmountCommitment)],
        outputs: &[(u128, &AmountOpening, &AmountCommitment)],
        inflow: u128,
        outflow: u128,
        trace: &BalanceTrace,
    ) -> Self {
        Self::compile_graph_inner(key, inputs, outputs, inflow, outflow, trace, true)
    }

    fn compile_graph_inner(
        key: &CommitmentKey,
        inputs: &[(u128, &AmountOpening, &AmountCommitment)],
        outputs: &[(u128, &AmountOpening, &AmountCommitment)],
        inflow: u128,
        outflow: u128,
        trace: &BalanceTrace,
        hidden_inputs: bool,
    ) -> Self {
        let mut result = Self {
            binary: Vec::new(),
            short: Vec::new(), short_bound: Vec::new(),
            ring: Vec::new(), exact_ring: Vec::new(),
            scalar: Vec::new(),
            input_commitment_planes: Vec::new(),
            membership: membership::MembershipConstraints::default(),
        };
        let input_messages: Vec<_> = inputs
            .iter()
            .map(|&(v, r, c)| result.coin(key, v, r, c, hidden_inputs))
            .collect();
        let output_messages: Vec<_> = outputs
            .iter()
            .map(|&(v, r, c)| result.coin(key, v, r, c, false))
            .collect();
        let mut carries = Poly::zero();
        for j in 1..16 {
            let encoded = (i32::from(trace.carries[j]) + 256) as u16;
            for bit in 0..9 {
                carries.c[(j - 1) * 9 + bit] = u64::from((encoded >> bit) & 1);
            }
        }
        let carry = result.binary(carries);
        result.scalar.push(ScalarEquation {
            terms: (135..Poly::D).map(|j| (1, carry, j)).collect(),
            rhs: 0,
        });
        for limb in 0..16 {
            let mut terms = Vec::new();
            for (&message, sign) in input_messages
                .iter()
                .map(|m| (m, 1))
                .chain(output_messages.iter().map(|m| (m, -1)))
            {
                for bit in 0..8 {
                    terms.push((sign * (1 << bit), message, limb * 8 + bit));
                }
            }
            let mut rhs =
                ((outflow >> (8 * limb)) & 255) as i64 - ((inflow >> (8 * limb)) & 255) as i64;
            if limb > 0 {
                for bit in 0..9 {
                    terms.push((1 << bit, carry, (limb - 1) * 9 + bit));
                }
                rhs += 256; // previous carry is encoded with a +256 offset
            }
            if limb < 15 {
                for bit in 0..9 {
                    terms.push((-256 * (1 << bit), carry, limb * 9 + bit));
                }
                rhs -= 65536; // next carry has the same offset, scaled by -256
            }
            result.scalar.push(ScalarEquation { terms, rhs });
        }
        result
    }

    pub fn shape(&self) -> RelationShape {
        RelationShape {
            binary_polynomials: self.binary.len(),
            ring_equations: self.ring.len() + self.exact_ring.len(),
            scalar_equations: self.scalar.len(),
        }
    }

    /// Reference assignment check; it consumes private data and is not a
    /// network verifier. A passing result is not a proof or a security estimate.
    pub fn validate_local_witness(&self) -> bool {
        if self
            .binary
            .iter()
            .any(|p| p.c.len() != Poly::D || p.c.iter().any(|&c| c > 1))
        {
            return false;
        }
        if !self.exact_ring.iter().all(|row| row.validate(&self.binary)) {
            return false;
        }
        if self.short.iter().zip(&self.short_bound).any(|(p, &b)| p.c.len() != Poly::D || p.c.iter().any(|&c| c > b)) {
            return false;
        }
        for equation in &self.ring {
            let mut sum = Poly::zero();
            for (coefficient, index) in &equation.terms {
                let Some(input) = self.witness(*index) else { return false };
                sum = sum.add(&coefficient.mul_ntt(input));
            }
            if sum != equation.rhs {
                return false;
            }
        }
        self.scalar.iter().all(|equation| {
            equation
                .terms
                .iter()
                .map(|&(a, index, j)| i128::from(a) * i128::from(self.binary[index].c[j]))
                .sum::<i128>()
                == i128::from(equation.rhs)
        }) && self.membership.validate(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "native-proof")]
    #[test]
    #[ignore = "complete native proving; run the lattice issuance Taskfile task"]
    fn native_issuance_amount_relation_roundtrip() {
        use backend::native::{self, NativeBudget};
        let key = CommitmentKey::derive(&[41; 32]);
        let openings: [_; 2] = std::array::from_fn(|i|
            AmountOpening::from_seed(&[41; 32], &[i as u8; 32]));
        let amounts = [u128::MAX - 258, 256];
        let commitments: [_; 2] = std::array::from_fn(|i| key.commit(amounts[i], &openings[i]));
        let coins: [_; 2] = std::array::from_fn(|i| (amounts[i], &openings[i], &commitments[i]));
        let context = b"issuance amount fixture: authorization remains external";
        let private = CompiledAmountRelation::compile_issuance(&key, &coins, u128::MAX, 2)
            .unwrap().with_transaction_context(context);
        let budget = NativeBudget { max_native_bytes: 1024 * 1024 * 1024 };
        let started = std::time::Instant::now();
        let proof = native::prove(&private, budget).unwrap();
        drop(private);
        let public = PublicAmountRelation::compile_issuance(&key, &commitments, u128::MAX, 2)
            .unwrap().with_transaction_context(context);
        assert!(native::verify_owned(public, &proof, budget).unwrap());
        let changed_value = PublicAmountRelation::compile_issuance(
            &key, &commitments, u128::MAX - 1, 2,
        ).unwrap().with_transaction_context(context);
        assert!(!native::verify_owned(changed_value, &proof, budget).unwrap());
        let changed_context = PublicAmountRelation::compile_issuance(
            &key, &commitments, u128::MAX, 2,
        ).unwrap().with_transaction_context(b"different issuance authorization");
        assert!(!native::verify_owned(changed_context, &proof, budget).unwrap());
        // Amount-relation proof only: this is not a complete issuance encoding.
        assert!(proof.len() < 256 * 1024);
        eprintln!("native_issuance_amount_relation outputs=2 changed_value_rejected=true changed_context_rejected=true proof_bytes={} seconds={:.3}",
            proof.len(), started.elapsed().as_secs_f64());
    }

    #[test]
    fn issuance_binds_authorized_public_value_without_private_input_coins() {
        let key = CommitmentKey::derive(&[31; 32]);
        let openings: [_; 2] = std::array::from_fn(|i|
            AmountOpening::from_seed(&[31; 32], &[i as u8; 32]));
        let amounts = [u128::MAX - 258, 256];
        let commitments: [_; 2] = std::array::from_fn(|i| key.commit(amounts[i], &openings[i]));
        let coins: [_; 2] = std::array::from_fn(|i| (amounts[i], &openings[i], &commitments[i]));
        let private = CompiledAmountRelation::compile_issuance(&key, &coins, u128::MAX, 2)
            .unwrap().with_transaction_context(b"publicly authorized issuance fixture");
        let public = PublicAmountRelation::compile_issuance(&key, &commitments, u128::MAX, 2)
            .unwrap().with_transaction_context(b"publicly authorized issuance fixture");
        assert!(private.validate_local_witness());
        assert!(private.input_commitment_planes.is_empty());
        assert!(private.ring == public.relation.ring);
        assert!(private.exact_ring == public.relation.exact_ring);
        assert!(private.scalar == public.relation.scalar);
        assert!(private.membership == public.relation.membership);
        assert_eq!(private.binary.len(), public.relation.binary.len());
        assert!(public.relation.binary.iter().all(|p| p.c.is_empty()));
        assert!(matches!(CompiledAmountRelation::compile_issuance(&key, &coins, u128::MAX, 1),
            Err(TokenError::Unbalanced)));
        assert!(matches!(CompiledAmountRelation::compile_issuance(&key, &[], 0, 0),
            Err(TokenError::Length)));
        assert!(matches!(PublicAmountRelation::compile_issuance(&key, &[], 0, 0),
            Err(TokenError::Length)));
        assert!(matches!(PublicAmountRelation::compile_issuance(
            &key, &vec![commitments[0].clone(); MAX_PRIVATE_COINS + 1], 0, 0),
            Err(TokenError::TooManyCoins)));
        let changed = PublicAmountRelation::compile_issuance(&key, &commitments, u128::MAX, 1)
            .unwrap().with_transaction_context(b"publicly authorized issuance fixture");
        assert!(private.scalar != changed.relation.scalar);
        let changed = PublicAmountRelation::compile_issuance(&key, &commitments, u128::MAX, 2)
            .unwrap().with_transaction_context(b"different issuance authorization");
        assert!(private.ring != changed.relation.ring);
    }

    #[test]
    fn compiled_two_input_two_output_relation() {
        let key = CommitmentKey::derive(&[4; 32]);
        let openings: [_; 4] =
            std::array::from_fn(|i| AmountOpening::from_seed(&[4; 32], &[i as u8; 32]));
        let amounts = [u128::MAX, 257, u128::MAX - 1, 256];
        let commitments: [_; 4] = std::array::from_fn(|i| key.commit(amounts[i], &openings[i]));
        let coins: [_; 4] = std::array::from_fn(|i| (amounts[i], &openings[i], &commitments[i]));
        let mut relation =
            CompiledAmountRelation::compile(&key, &coins[..2], &coins[2..], 0, 2).unwrap();
        assert!(relation.validate_local_witness());
        assert_eq!(relation.input_commitment_planes.len(), 2);
        let alternative_opening = AmountOpening::from_seed(&[4; 32], &[99; 32]);
        let alternative_commitment = key.commit(amounts[0], &alternative_opening);
        let alternative_inputs = [
            (amounts[0], &alternative_opening, &alternative_commitment),
            coins[1],
        ];
        let alternative =
            CompiledAmountRelation::compile(&key, &alternative_inputs, &coins[2..], 0, 2).unwrap();
        assert!(alternative.validate_local_witness());
        // No private commitment coefficients may become public equation data.
        assert!(relation.ring == alternative.ring);
        assert!(relation.exact_ring == alternative.exact_ring);
        assert!(relation.scalar == alternative.scalar);
        assert!(relation.binary != alternative.binary);
        assert_eq!(
            relation.shape(),
            RelationShape {
                binary_polynomials: 1661,
                ring_equations: 126,
                scalar_equations: 21
            }
        );
        relation.binary[0].c[127] ^= 1;
        assert!(!relation.validate_local_witness());
        relation.binary[0].c[127] ^= 1;
        relation.binary[0].c[200] = 1;
        assert!(!relation.validate_local_witness());
    }

    #[test]
    fn canonical_decomposition_rejects_modulus_alias_and_nonbinary_masks() {
        let mut relation = CompiledAmountRelation {
            binary: Vec::new(),
            short: Vec::new(), short_bound: Vec::new(),
            ring: Vec::new(), exact_ring: Vec::new(),
            scalar: Vec::new(),
            input_commitment_planes: Vec::new(),
            membership: membership::MembershipConstraints::default(),
        };
        let planes = relation.canonical_residue(&Poly::zero());
        assert!(relation.validate_local_witness());
        // Alter a amount relation assignment, not the old protocol.
        // q aliases zero in R_q, but cannot pass the integer canonicality constraints.
        for (bit, index) in planes.into_iter().enumerate() {
            relation.binary[index].c[0] = (Poly::Q >> bit) & 1;
        }
        assert!(!relation.validate_local_witness());
        relation.binary[0].c[0] = 2;
        assert!(!relation.validate_local_witness());
    }
}

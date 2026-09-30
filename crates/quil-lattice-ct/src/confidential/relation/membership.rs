//! Membership/ownership constraints sharing the amount witness.
//!
//! The accumulator hash and the note identities live in the proof ring
//! R_p = Z_p[X]/(X^256+1), p = 2^38 − 107, so every hash row is a native
//! proof-ring equation: no integer lifting from the commitment ring R_q. Hash
//! inputs are base-128 limbs (short witness polynomials proven by approximate
//! l2-norm bounds), except the coin-compression hash, which consumes the
//! amount relation's exact binary planes of the commitment. Ownership uses a
//! recipient-only secret plus a fresh per-note nonce; three rank-1
//! lattice-linear equations bind recipient address, owner and key image.
//! There is no proof backend, transaction authorization or network verifier here.

use super::*;
use crate::rp::{PolyP, PreparedP, RowAccumulator, P, PACKED_BYTES as PACKED_P_BYTES};
use std::sync::Arc;

pub const NODE_RANK: usize = 4;
pub const NODE_BYTES: usize = NODE_RANK * PACKED_P_BYTES;
pub const MAX_DEPTH: usize = 32;
/// Identities (recipient key, owner, key image) are three canonical R_p
/// polynomials: module rank 3 gives the identity maps 2^225 quantum core-SVP
/// at the extracted bound (rank 2 sat at 2^129).
pub const IDENTITY_RANK: usize = 3;
pub const IDENTITY_BYTES: usize = IDENTITY_RANK * PACKED_P_BYTES;
/// Uniform polynomials expanded from the recipient secret and the note nonce.
/// Each carries 38·256 bits; the leftover-hash bound needs > 29,184 + 2·128
/// bits per rank-3 identity output (four polynomials = 38,912 bits), and the
/// note vector masks the owner and the key image jointly (> 58,368 + 256 bits;
/// seven polynomials = 68,096 bits).
const RECIPIENT_POLYS: usize = 4;
const NOTE_POLYS: usize = 7;
/// Base-128 limbs per hashed polynomial: 6 × 7 bits cover 38-bit residues.
const LIMBS: usize = 6;
/// Coefficient bound declared for every limb witness. The top limb of a 38-bit
/// residue only holds three bits, but a uniform declaration lets the backend
/// merge consecutive limbs into large approximate-norm parts; the looser
/// bound only widens the extracted-witness norm the SIS argument accounts for.
const LIMB_BOUND: [u64; LIMBS] = [127; LIMBS];
type Planes = [usize; 36];
type Limbs = [usize; LIMBS];
type NodeLimbs = [Limbs; NODE_RANK];
type Matrix = Vec<Vec<PolyP>>;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Node([PolyP; NODE_RANK]);

impl Node {
    pub fn zero() -> Self {
        Self(std::array::from_fn(|_| PolyP::zero()))
    }

    pub fn to_bytes(&self) -> [u8; NODE_BYTES] {
        let mut bytes = [0; NODE_BYTES];
        for (p, dst) in self.0.iter().zip(bytes.chunks_exact_mut(PACKED_P_BYTES)) {
            p.encode(dst);
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TokenError> {
        if bytes.len() != NODE_BYTES {
            return Err(TokenError::Length);
        }
        let mut rows = Vec::with_capacity(NODE_RANK);
        for src in bytes.chunks_exact(PACKED_P_BYTES) {
            rows.push(PolyP::decode(src).ok_or(TokenError::NoncanonicalCoefficient)?);
        }
        Ok(Self(std::array::from_fn(|i| rows[i].clone())))
    }

    /// Embed a rank-1 identity in row 0; all other rows are zero.
    fn from_identity(identity: [PolyP; IDENTITY_RANK]) -> Self {
        let mut node = Self::zero();
        node.0[..IDENTITY_RANK].clone_from_slice(&identity);
        node
    }

    /// Canonical compact encoding for owner IDs/key images only, not roots.
    pub fn identity_bytes(&self) -> Result<[u8; IDENTITY_BYTES], TokenError> {
        if self.0[IDENTITY_RANK..].iter().any(|p| p.c.iter().any(|&c| c != 0)) {
            return Err(TokenError::NoncanonicalCoefficient);
        }
        let mut bytes = [0; IDENTITY_BYTES];
        for (p, dst) in self.0[..IDENTITY_RANK].iter().zip(bytes.chunks_exact_mut(PACKED_P_BYTES)) {
            p.encode(dst);
        }
        Ok(bytes)
    }

    pub fn from_identity_bytes(bytes: &[u8]) -> Result<Self, TokenError> {
        if bytes.len() != IDENTITY_BYTES {
            return Err(TokenError::Length);
        }
        let identity = std::array::from_fn(|i| {
            PolyP::decode(&bytes[i * PACKED_P_BYTES..(i + 1) * PACKED_P_BYTES])
        });
        let identity: [Option<PolyP>; IDENTITY_RANK] = identity;
        if identity.iter().any(|p| p.is_none()) {
            return Err(TokenError::NoncanonicalCoefficient);
        }
        Ok(Self::from_identity(identity.map(|p| p.unwrap())))
    }
}

/// Recipient-only spend secret. Never give its seed to a payment sender or put
/// it in an output memo. A reusable address exposes only `recipient_key`.
pub struct RecipientSecret([u8; 32]);
impl Drop for RecipientSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl RecipientSecret {
    pub fn from_seed(context: &[u8; 32], private_seed: &[u8; 32]) -> Self {
        let mut reader = stream(
            context,
            b"membership/v3/private-recipient",
            Some(private_seed),
        );
        let mut secret = [0; 32];
        reader.read(&mut secret);
        Self(secret)
    }
    /// The note nonce may be sent in the encrypted memo; the recipient secret
    /// remains private. Fresh nonces distinguish coins under a reusable address.
    pub fn note_owner(&self, note_nonce: &[u8; 32]) -> OwnerSecret {
        OwnerSecret {
            recipient: self.0,
            nonce: *note_nonce,
        }
    }
}

/// Prover-only per-note ownership witness, with a recipient-only component.
pub struct OwnerSecret {
    recipient: [u8; 32],
    nonce: [u8; 32],
}
impl Drop for OwnerSecret {
    fn drop(&mut self) {
        self.recipient.zeroize();
        self.nonce.zeroize();
    }
}

pub struct NoteSecrets {
    pub opening: AmountOpening,
    pub owner: OwnerSecret,
}
impl NoteSecrets {
    /// Recover an opening from the memo seed and combine it with the wallet's
    /// independently held recipient secret. The memo seed alone cannot spend.
    pub fn from_seeds(
        context: &[u8; 32],
        recipient: &RecipientSecret,
        note_seed: &[u8; 32],
    ) -> Self {
        Self {
            opening: AmountOpening::from_seed(context, note_seed),
            owner: recipient.note_owner(note_seed),
        }
    }
}

/// Public matrix with its NTT-domain form for hashing.
struct PublicMatrix {
    rows: Matrix,
    prepared: Vec<Vec<PreparedP>>,
}

pub struct MembershipKey {
    context: [u8; 32],
    coin: Arc<PublicMatrix>,
    leaf: Arc<PublicMatrix>,
    branch: Arc<PublicMatrix>,
    /// Rank-1 identity maps over base-128 limbs: address, owner, key image.
    address: Arc<PublicMatrix>,
    owner: Arc<PublicMatrix>,
    image: Arc<PublicMatrix>,
}

fn uniform_poly_p(reader: &mut impl XofReader) -> PolyP {
    let mut p = PolyP::zero();
    for c in &mut p.c {
        loop {
            let mut bytes = [0u8; 8];
            reader.read(&mut bytes[..5]);
            let v = u64::from_le_bytes(bytes) & ((1u64 << 38) - 1);
            if v < P {
                *c = v;
                break;
            }
        }
    }
    p
}

fn matrix(context: &[u8; 32], label: &[u8], rows: usize, columns: usize) -> Arc<PublicMatrix> {
    let mut reader = stream(context, label, None);
    let rows: Matrix = (0..rows)
        .map(|_| (0..columns).map(|_| uniform_poly_p(&mut reader)).collect())
        .collect();
    let prepared = rows.iter().map(|row| row.iter().map(PolyP::prepare).collect()).collect();
    Arc::new(PublicMatrix { rows, prepared })
}

/// Hash over base-128 limbs of the inputs: row = Σ_col A[row][col] · limb_col.
fn hash_vec(matrix: &PublicMatrix, inputs: &[PolyP]) -> Vec<PolyP> {
    let digits: Vec<PolyP> = inputs.iter().flat_map(|p| p.limbs(LIMBS)).collect();
    assert_eq!(digits.len(), matrix.rows[0].len());
    matrix
        .prepared
        .iter()
        .map(|row| {
            let mut acc = RowAccumulator::new();
            for (a, x) in row.iter().zip(&digits) {
                acc.add(a, x);
            }
            acc.finish()
        })
        .collect()
}

fn hash(matrix: &PublicMatrix, inputs: &[PolyP]) -> Node {
    let rows = hash_vec(matrix, inputs);
    assert_eq!(rows.len(), NODE_RANK);
    Node(std::array::from_fn(|row| rows[row].clone()))
}

/// Commitment polynomials (canonical residues below q < 2^36) as integers in
/// the proof ring; their base-128 limbs are the coin hash input.
fn commitment_polys(commitment: &AmountCommitment) -> Vec<PolyP> {
    commitment.t.iter().map(|p| PolyP { c: p.c.clone() }).collect()
}

/// Uniform canonical proof-ring polynomials from a private 32-byte seed. The
/// expansion is the only place the seed is used; the polynomials are the
/// actual witness.
fn expand<const M: usize>(context: &[u8; 32], label: &[u8], seed: &[u8; 32]) -> [PolyP; M] {
    let mut reader = stream(context, label, Some(seed));
    std::array::from_fn(|_| uniform_poly_p(&mut reader))
}

fn expand_recipient(context: &[u8; 32], secret: &[u8; 32]) -> [PolyP; RECIPIENT_POLYS] {
    expand(context, b"identity/v6/recipient", secret)
}

fn expand_note(context: &[u8; 32], nonce: &[u8; 32]) -> [PolyP; NOTE_POLYS] {
    expand(context, b"identity/v6/note", nonce)
}

impl MembershipKey {
    /// Fixed ranks and labels for this suite; not caller matrices.
    pub fn derive(context: &[u8; 32]) -> Self {
        Self {
            context: *context,
            coin: matrix(context, b"membership/v5/coin", NODE_RANK, (BINDING_RANK + 1) * LIMBS),
            leaf: matrix(context, b"membership/v5/leaf", NODE_RANK, 2 * NODE_RANK * LIMBS),
            branch: matrix(context, b"membership/v5/branch", NODE_RANK, 2 * NODE_RANK * LIMBS),
            address: matrix(context, b"identity/v6/address", IDENTITY_RANK, RECIPIENT_POLYS * LIMBS),
            owner: matrix(context, b"identity/v6/owner", IDENTITY_RANK, (IDENTITY_RANK + NOTE_POLYS) * LIMBS),
            image: matrix(context, b"identity/v6/image", IDENTITY_RANK, (RECIPIENT_POLYS + NOTE_POLYS) * LIMBS),
        }
    }

    fn recipient_value(&self, expanded: &[PolyP; RECIPIENT_POLYS]) -> [PolyP; IDENTITY_RANK] {
        let rows = hash_vec(&self.address, expanded);
        std::array::from_fn(|i| rows[i].clone())
    }

    fn owner_value(&self, recipient: &[PolyP; IDENTITY_RANK], note: &[PolyP; NOTE_POLYS]) -> [PolyP; IDENTITY_RANK] {
        let rows = hash_vec(&self.owner, &[recipient.as_slice(), note.as_slice()].concat());
        std::array::from_fn(|i| rows[i].clone())
    }

    fn image_value(&self, expanded: &[PolyP; RECIPIENT_POLYS], note: &[PolyP; NOTE_POLYS]) -> [PolyP; IDENTITY_RANK] {
        let rows = hash_vec(&self.image, &[expanded.as_slice(), note.as_slice()].concat());
        std::array::from_fn(|i| rows[i].clone())
    }

    /// Public reusable recipient key `A_addr · digits(expand(secret))`.
    pub fn recipient_key(&self, secret: &RecipientSecret) -> [u8; IDENTITY_BYTES] {
        Node::from_identity(self.recipient_value(&expand_recipient(&self.context, &secret.0)))
            .identity_bytes()
            .expect("identity rows are canonical")
    }

    /// Sender-side output construction from a public recipient address and
    /// fresh note nonce. No recipient spend secret is available to the sender.
    /// Returns `None` for a non-canonical recipient key.
    pub fn output_owner(&self, recipient_key: &[u8; IDENTITY_BYTES], nonce: &[u8; 32]) -> Option<Node> {
        let recipient = Node::from_identity_bytes(recipient_key).ok()?;
        let recipient: [PolyP; IDENTITY_RANK] = std::array::from_fn(|i| recipient.0[i].clone());
        let note = expand_note(&self.context, nonce);
        Some(Node::from_identity(self.owner_value(&recipient, &note)))
    }

    pub fn owner_key(&self, secret: &OwnerSecret) -> Node {
        let recipient = self.recipient_value(&expand_recipient(&self.context, &secret.recipient));
        let note = expand_note(&self.context, &secret.nonce);
        Node::from_identity(self.owner_value(&recipient, &note))
    }

    pub fn key_image(&self, secret: &OwnerSecret) -> Node {
        let expanded = expand_recipient(&self.context, &secret.recipient);
        let note = expand_note(&self.context, &secret.nonce);
        Node::from_identity(self.image_value(&expanded, &note))
    }

    pub fn leaf(&self, owner: &Node, commitment: &AmountCommitment) -> Node {
        let compressed = hash(&self.coin, &commitment_polys(commitment));
        hash(
            &self.leaf,
            &[owner.0.as_slice(), compressed.0.as_slice()].concat(),
        )
    }

    pub fn parent(&self, left: &Node, right: &Node) -> Node {
        hash(
            &self.branch,
            &[left.0.as_slice(), right.0.as_slice()].concat(),
        )
    }
}

pub struct InputPath<'a> {
    pub owner: &'a OwnerSecret,
    /// Ordered leaf-to-root. `right[i]` means the running node is the right child.
    pub siblings: &'a [Node],
    pub right: &'a [bool],
}

/// Public statement supplied by execution, never derived from an untrusted proof.
pub struct MembershipStatement<'a> {
    pub root: &'a Node,
    pub key_images: &'a [Node],
    pub depth: usize,
}

/// A hash input spanning `LIMBS` matrix columns: either a signed combination
/// of limb witness sets, or the exact binary planes of a commitment
/// polynomial (limb j = Σ_{7j ≤ bit < 7j+7, bit < 36} 2^(bit−7j) · plane_bit).
#[derive(Clone, PartialEq, Eq)]
enum Input {
    Limbs(Vec<(i64, Limbs)>),
    Planes(Planes),
}

#[derive(Clone, PartialEq, Eq)]
enum Target {
    /// Hidden output rows as limb sets: value = Σ_i 128^i · limb_i.
    Hidden(Vec<Limbs>),
    Public(Vec<PolyP>),
}

#[derive(PartialEq, Eq)]
struct HashEquation {
    matrix: Arc<PublicMatrix>,
    inputs: Vec<Input>,
    target: Target,
}

impl PartialEq for PublicMatrix {
    fn eq(&self, other: &Self) -> bool {
        self.rows == other.rows
    }
}
impl Eq for PublicMatrix {}

/// One limb selected by a scalar selector: selected = zero + s·(one − zero),
/// one unit-weight quadratic row per limb. (A single weighted row per node
/// row was measured to inflate the backend's quadratic decomposition and
/// the witness by ~60 %, so per-limb rows are retained.)
#[derive(PartialEq, Eq)]
struct SelectEquation {
    selector: usize,
    zero: usize,
    one: usize,
    selected: usize,
}

/// A native proof-ring row: Σ coefficient_i · witness_i = rhs over Z_p[X]/(X^256+1),
/// with signed public coefficients in (−p/2, p/2).
pub struct NativeRow {
    pub terms: Vec<(Vec<i64>, usize)>,
    pub rhs: Vec<i64>,
}

#[derive(Default, PartialEq, Eq)]
pub(super) struct MembershipConstraints {
    hashes: Vec<HashEquation>,
    selections: Vec<SelectEquation>,
    /// Direct equalities Σ 128^i · limb_i = value (depth-0 root binding).
    equalities: Vec<(Limbs, PolyP)>,
}

fn centered_p(v: u64) -> i64 {
    if v > P / 2 { v as i64 - P as i64 } else { v as i64 }
}

fn scaled_column(column: &PolyP, scale: i64) -> Vec<i64> {
    column
        .c
        .iter()
        .map(|&v| centered_p(((v as i128 * scale as i128).rem_euclid(P as i128)) as u64))
        .collect()
}

fn add_term(terms: &mut std::collections::BTreeMap<usize, Vec<i64>>, handle: usize, coefficients: Vec<i64>) {
    let entry = terms.entry(handle).or_insert_with(|| vec![0; Poly::D]);
    for (e, c) in entry.iter_mut().zip(coefficients) {
        *e = centered_p(((*e as i128 + c as i128).rem_euclid(P as i128)) as u64);
    }
}

fn limb_weight(limb: usize) -> i64 {
    1i64 << (7 * limb)
}

fn witness_p(relation: &CompiledAmountRelation, handle: usize) -> Option<PolyP> {
    relation.witness(handle).map(|p| PolyP { c: p.c.clone() })
}

impl MembershipConstraints {
    /// Expand every hash equality into native proof-ring rows, one per public
    /// matrix row, retaining the original witness handles.
    pub(super) fn native_rows(&self) -> impl Iterator<Item = NativeRow> + '_ {
        let hashes = self.hashes.iter().flat_map(|equation| {
            (0..equation.matrix.rows.len()).map(move |row| {
                let mut terms = std::collections::BTreeMap::<usize, Vec<i64>>::new();
                for (input, expression) in equation.inputs.iter().enumerate() {
                    match expression {
                        Input::Limbs(sets) => {
                            for &(sign, limbs) in sets {
                                for (limb, &handle) in limbs.iter().enumerate() {
                                    let column = &equation.matrix.rows[row][input * LIMBS + limb];
                                    add_term(&mut terms, handle, scaled_column(column, sign));
                                }
                            }
                        }
                        Input::Planes(planes) => {
                            for (position, &handle) in planes.iter().enumerate() {
                                let column = &equation.matrix.rows[row][input * LIMBS + position / 7];
                                add_term(&mut terms, handle, scaled_column(column, 1 << (position % 7)));
                            }
                        }
                    }
                }
                let rhs = match &equation.target {
                    Target::Public(rows) => rows[row].c.iter().map(|&v| centered_p(v)).collect(),
                    Target::Hidden(limbs) => {
                        for (limb, &handle) in limbs[row].iter().enumerate() {
                            let mut coefficient = vec![0i64; Poly::D];
                            coefficient[0] = -limb_weight(limb);
                            add_term(&mut terms, handle, coefficient);
                        }
                        vec![0; Poly::D]
                    }
                };
                NativeRow {
                    terms: terms.into_iter().filter(|(_, c)| c.iter().any(|&v| v != 0)).map(|(i, c)| (c, i)).collect(),
                    rhs,
                }
            })
        });
        let equalities = self.equalities.iter().map(|(limbs, value)| NativeRow {
            terms: limbs
                .iter()
                .enumerate()
                .map(|(limb, &handle)| {
                    let mut coefficient = vec![0i64; Poly::D];
                    coefficient[0] = limb_weight(limb);
                    (coefficient, handle)
                })
                .collect(),
            rhs: value.c.iter().map(|&v| centered_p(v)).collect(),
        });
        hashes.chain(equalities)
    }

    pub(super) fn native_row_count(&self) -> usize {
        self.hashes.iter().map(|h| h.matrix.rows.len()).sum::<usize>() + self.equalities.len()
    }

    fn limb_value(relation: &CompiledAmountRelation, limbs: &Limbs) -> Option<PolyP> {
        let mut value = PolyP::zero();
        for (limb, &handle) in limbs.iter().enumerate() {
            let p = witness_p(relation, handle)?;
            let weight = limb_weight(limb) as u128;
            value = value.add(&PolyP { c: p.c.iter().map(|&v| ((v as u128 * weight) % P as u128) as u64).collect() });
        }
        Some(value)
    }

    fn input_digits(relation: &CompiledAmountRelation, input: &Input) -> Option<Vec<PolyP>> {
        match input {
            Input::Limbs(sets) => (0..LIMBS)
                .map(|limb| {
                    let mut digit = vec![0i128; Poly::D];
                    for &(sign, limbs) in sets {
                        let p = witness_p(relation, limbs[limb])?;
                        for (d, &v) in digit.iter_mut().zip(&p.c) {
                            *d += sign as i128 * v as i128;
                        }
                    }
                    Some(PolyP { c: digit.iter().map(|&v| v.rem_euclid(P as i128) as u64).collect() })
                })
                .collect(),
            Input::Planes(planes) => (0..LIMBS)
                .map(|limb| {
                    let mut digit = vec![0u64; Poly::D];
                    for bit in 0..7 {
                        let position = limb * 7 + bit;
                        if position < 36 {
                            let p = relation.witness(planes[position])?;
                            for (d, &v) in digit.iter_mut().zip(&p.c) {
                                *d += v << bit;
                            }
                        }
                    }
                    Some(PolyP { c: digit })
                })
                .collect(),
        }
    }

    pub(super) fn validate(&self, relation: &CompiledAmountRelation) -> bool {
        for gate in &self.selections {
            // selector is constrained to a constant binary polynomial by the
            // main relation, so it selects one whole node, not per coefficient.
            let Some(selector) = relation.witness(gate.selector) else { return false };
            if selector.c[1..].iter().any(|&v| v != 0) || selector.c[0] > 1 {
                return false;
            }
            let (Some(zero), Some(one), Some(selected)) = (
                relation.witness(gate.zero), relation.witness(gate.one), relation.witness(gate.selected),
            ) else { return false };
            if *(if selector.c[0] == 1 { one } else { zero }) != *selected {
                return false;
            }
        }
        for equation in &self.hashes {
            // Evaluate the LINEAR limb-to-gadget equation directly. Do not first
            // reduce the represented node and then decompose it again.
            let mut digits = Vec::new();
            for input in &equation.inputs {
                let Some(mut d) = Self::input_digits(relation, input) else { return false };
                if d.iter().any(|p| p.c.iter().any(|&v| v >= 256)) { return false; }
                digits.append(&mut d);
            }
            if digits.len() != equation.matrix.rows[0].len() { return false; }
            let value: Vec<PolyP> = equation
                .matrix
                .prepared
                .iter()
                .map(|row| {
                    let mut acc = RowAccumulator::new();
                    for (a, x) in row.iter().zip(&digits) { acc.add(a, x); }
                    acc.finish()
                })
                .collect();
            let target = match &equation.target {
                Target::Public(rows) => Some(rows.clone()),
                Target::Hidden(limbs) => limbs.iter().map(|l| Self::limb_value(relation, l)).collect(),
            };
            if Some(value) != target { return false; }
        }
        for (limbs, value) in &self.equalities {
            if Self::limb_value(relation, limbs).as_ref() != Some(value) { return false; }
        }
        true
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MembershipShape {
    /// Native proof-ring rows across all hash equalities and limb bindings.
    pub hash_ring_equations: usize,
    pub quadratic_selection_equations: usize,
}

impl CompiledAmountRelation {
    pub fn selection_backend_rows(&self) -> impl Iterator<Item = backend::SelectionRow> + '_ {
        self.membership
            .selections
            .iter()
            .map(|gate| backend::SelectionRow {
                selector: gate.selector,
                terms: vec![(1, gate.zero, gate.one, gate.selected)],
            })
    }

    pub(super) fn native_membership_rows(&self) -> impl Iterator<Item = NativeRow> + '_ {
        self.membership.native_rows()
    }

    pub(super) fn native_membership_row_count(&self) -> usize {
        self.membership.native_row_count()
    }

    /// Six short limb witnesses for one proof-ring polynomial.
    fn poly_limbs(&mut self, p: &PolyP) -> Limbs {
        let limbs = p.limbs(LIMBS);
        std::array::from_fn(|i| self.short(Poly { c: limbs[i].c.clone() }, LIMB_BOUND[i]))
    }

    fn node_limbs(&mut self, node: &Node) -> NodeLimbs {
        std::array::from_fn(|row| self.poly_limbs(&node.0[row]))
    }

    pub fn membership_shape(&self) -> MembershipShape {
        MembershipShape {
            hash_ring_equations: self.membership.native_row_count(),
            quadratic_selection_equations: self.membership.selections.len(),
        }
    }

    /// Compile amount+membership+ownership constraints for the same private
    /// inputs. This is still a local witness compiler, not a spend proof.
    pub fn compile_with_membership(
        value_key: &CommitmentKey,
        key: &MembershipKey,
        inputs: &[(u128, &AmountOpening, &AmountCommitment)],
        outputs: &[(u128, &AmountOpening, &AmountCommitment)],
        inflow: u128,
        outflow: u128,
        statement: &MembershipStatement<'_>,
        paths: &[InputPath<'_>],
    ) -> Result<Self, TokenError> {
        Self::compile_membership_graph(
            value_key, key, inputs, outputs, inflow, outflow, statement, paths, true,
        )
    }

    fn compile_membership_graph(
        value_key: &CommitmentKey,
        key: &MembershipKey,
        inputs: &[(u128, &AmountOpening, &AmountCommitment)],
        outputs: &[(u128, &AmountOpening, &AmountCommitment)],
        inflow: u128,
        outflow: u128,
        statement: &MembershipStatement<'_>,
        paths: &[InputPath<'_>],
        check_assignment: bool,
    ) -> Result<Self, TokenError> {
        if inputs.len().saturating_add(outputs.len()) > MAX_PRIVATE_COINS {
            return Err(TokenError::TooManyCoins);
        }
        if statement.depth > MAX_DEPTH
            || paths.len() != inputs.len()
            || statement.key_images.len() != inputs.len()
            || paths
                .iter()
                .any(|p| p.siblings.len() != statement.depth || p.right.len() != statement.depth)
        {
            return Err(TokenError::InvalidMembership);
        }
        for i in 0..statement.key_images.len() {
            if statement.key_images[..i].contains(&statement.key_images[i]) {
                return Err(TokenError::DuplicateKeyImage);
            }
        }
        let mut result = if check_assignment {
            Self::compile(value_key, inputs, outputs, inflow, outflow)?
        } else {
            Self::compile_graph(
                value_key,
                inputs,
                outputs,
                inflow,
                outflow,
                &BalanceTrace { carries: [0; 17] },
            )
        };
        let ablation = ablation();
        if ablation == Ablation::NoMembership {
            // Benchmark-only ablation: hidden inputs without membership or ownership.
            return Ok(result);
        }
        for (input, path) in paths.iter().enumerate() {
            if check_assignment && key.key_image(path.owner) != statement.key_images[input] {
                return Err(TokenError::InvalidMembership);
            }
            let owner = key.owner_key(path.owner);
            let zero = result.short(Poly::zero(), LIMB_BOUND[0]);
            let owner_limbs: NodeLimbs = if ablation == Ablation::NoOwnership {
                // Benchmark-only ablation: the owner node is an unconstrained hidden
                // witness and the public key image is not bound. Never a valid proof.
                result.node_limbs(&owner)
            } else {
                // Rank-1 lattice identities over the shared base-128 gadget:
                //   R = A_addr · digits(X_s), O = A_own · digits(R ‖ X_n),
                //   I = A_img · digits(X_s ‖ X_n)   (I is public, R and O hidden).
                let expanded = expand_recipient(&key.context, &path.owner.recipient);
                let note = expand_note(&key.context, &path.owner.nonce);
                let expanded_limbs: Vec<Limbs> = expanded.iter().map(|p| result.poly_limbs(p)).collect();
                let note_limbs: Vec<Limbs> = note.iter().map(|p| result.poly_limbs(p)).collect();
                let recipient = key.recipient_value(&expanded);
                let recipient_limbs: Vec<Limbs> = recipient.iter().map(|p| result.poly_limbs(p)).collect();
                result.membership.hashes.push(HashEquation {
                    matrix: key.address.clone(),
                    inputs: expanded_limbs.iter().map(|&l| Input::Limbs(vec![(1, l)])).collect(),
                    target: Target::Hidden(recipient_limbs.clone()),
                });
                let owner_value = key.owner_value(&recipient, &note);
                let owner_identity_limbs: Vec<Limbs> = owner_value.iter().map(|p| result.poly_limbs(p)).collect();
                result.membership.hashes.push(HashEquation {
                    matrix: key.owner.clone(),
                    inputs: recipient_limbs
                        .iter()
                        .chain(&note_limbs)
                        .map(|&l| Input::Limbs(vec![(1, l)]))
                        .collect(),
                    target: Target::Hidden(owner_identity_limbs.clone()),
                });
                let image = statement.key_images[input].identity_bytes()?;
                let image = Node::from_identity_bytes(&image)?;
                result.membership.hashes.push(HashEquation {
                    matrix: key.image.clone(),
                    inputs: expanded_limbs
                        .iter()
                        .chain(&note_limbs)
                        .map(|&l| Input::Limbs(vec![(1, l)]))
                        .collect(),
                    target: Target::Public(image.0[..IDENTITY_RANK].to_vec()),
                });
                // Owner node: identity rows, then shared zero limbs.
                std::array::from_fn(|row| {
                    if row < IDENTITY_RANK { owner_identity_limbs[row] } else { [zero; LIMBS] }
                })
            };
            let compressed = hash(&key.coin, &commitment_polys(inputs[input].2));
            let compressed_limbs = result.node_limbs(&compressed);
            result.membership.hashes.push(HashEquation {
                matrix: key.coin.clone(),
                // Use the amount compiler's existing private commitment handles.
                inputs: result.input_commitment_planes[input]
                    .iter()
                    .map(|&planes| Input::Planes(planes))
                    .collect(),
                target: Target::Hidden(compressed_limbs.to_vec()),
            });
            let mut current = key.leaf(&owner, inputs[input].2);
            let mut current_limbs = result.node_limbs(&current);
            result.membership.hashes.push(HashEquation {
                matrix: key.leaf.clone(),
                inputs: owner_limbs
                    .iter()
                    .chain(&compressed_limbs)
                    .map(|&l| Input::Limbs(vec![(1, l)]))
                    .collect(),
                target: Target::Hidden(current_limbs.to_vec()),
            });
            for level in 0..statement.depth {
                let sibling = &path.siblings[level];
                let sibling_limbs = result.node_limbs(sibling);
                let selector = result.binary(if path.right[level] {
                    Poly::one()
                } else {
                    Poly::zero()
                });
                result.scalar.push(ScalarEquation {
                    terms: (1..Poly::D).map(|j| (1, selector, j)).collect(),
                    rhs: 0,
                });
                let left: NodeLimbs = std::array::from_fn(|row| {
                    std::array::from_fn(|limb| {
                        let zero = current_limbs[row][limb];
                        let one = sibling_limbs[row][limb];
                        let chosen = if path.right[level] { one } else { zero };
                        let value = result.witness(chosen).expect("limb handle").clone();
                        let selected = result.short(value, LIMB_BOUND[limb]);
                        result.membership.selections.push(SelectEquation { selector, zero, one, selected });
                        selected
                    })
                });
                let mut hash_inputs: Vec<Input> = left.iter().map(|&l| Input::Limbs(vec![(1, l)])).collect();
                hash_inputs.extend((0..NODE_RANK).map(|row| {
                    Input::Limbs(vec![(1, current_limbs[row]), (1, sibling_limbs[row]), (-1, left[row])])
                }));
                current = if path.right[level] {
                    key.parent(sibling, &current)
                } else {
                    key.parent(&current, sibling)
                };
                let target = if level + 1 == statement.depth {
                    Target::Public(statement.root.0.to_vec())
                } else {
                    current_limbs = result.node_limbs(&current);
                    Target::Hidden(current_limbs.to_vec())
                };
                result.membership.hashes.push(HashEquation {
                    matrix: key.branch.clone(),
                    inputs: hash_inputs,
                    target,
                });
            }
            if check_assignment && current != *statement.root {
                return Err(TokenError::InvalidMembership);
            }
            if statement.depth == 0 {
                // The leaf itself is the public root; bind every component.
                for row in 0..NODE_RANK {
                    result.membership.equalities.push((current_limbs[row], statement.root.0[row].clone()));
                }
            }
        }
        Ok(result)
    }
}

impl PublicAmountRelation {
    /// Reconstruct the amount, ownership and membership equations from public
    /// transaction data. No input commitment, amount, opening, owner secret or
    /// membership path is accepted. Fixed placeholders build variable handles;
    /// they are not checked as assignments and are discarded before returning.
    pub fn compile_with_membership(
        value_key: &CommitmentKey,
        key: &MembershipKey,
        outputs: &[AmountCommitment],
        inflow: u128,
        outflow: u128,
        statement: &MembershipStatement<'_>,
    ) -> Result<Self, TokenError> {
        let inputs = statement.key_images.len();
        if inputs.saturating_add(outputs.len()) > MAX_PRIVATE_COINS {
            return Err(TokenError::TooManyCoins);
        }
        if statement.depth > MAX_DEPTH {
            return Err(TokenError::InvalidMembership);
        }
        let opening = AmountOpening {
            r: std::array::from_fn(|_| Poly::zero()),
        };
        let commitment = value_key.commit(0, &opening);
        let input_coins = vec![(0, &opening, &commitment); inputs];
        let output_coins: Vec<_> = outputs.iter().map(|c| (0, &opening, c)).collect();
        let owner = OwnerSecret {
            recipient: [0; 32],
            nonce: [0; 32],
        };
        let siblings = vec![Node::zero(); statement.depth];
        let directions = vec![false; statement.depth];
        let paths: Vec<_> = (0..inputs)
            .map(|_| InputPath {
                owner: &owner,
                siblings: &siblings,
                right: &directions,
            })
            .collect();
        let mut relation = CompiledAmountRelation::compile_membership_graph(
            value_key,
            key,
            &input_coins,
            &output_coins,
            inflow,
            outflow,
            statement,
            &paths,
            false,
        )?;
        relation.erase_private();
        Ok(Self { relation })
    }
}

/// Benchmark-only relation ablation, selectable solely through the
/// `ablation-bench` cargo feature plus `QUIL_ABLATION`. Production builds
/// cannot enable it; ablated relations are cost measurements, not proofs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ablation {
    None,
    NoOwnership,
    NoMembership,
}

fn ablation() -> Ablation {
    #[cfg(feature = "ablation-bench")]
    {
        match std::env::var("QUIL_ABLATION").as_deref() {
            Ok("no_ownership") => return Ablation::NoOwnership,
            Ok("no_membership") => return Ablation::NoMembership,
            _ => {}
        }
    }
    Ablation::None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent evaluation of a native row: Σ coefficient ⊛ witness − rhs ≡ 0 (mod p).
    fn native_row_holds(relation: &CompiledAmountRelation, row: &NativeRow) -> bool {
        let mut residual: Vec<i128> = row.rhs.iter().map(|&v| -i128::from(v)).collect();
        for (coefficients, handle) in &row.terms {
            let Some(w) = relation.witness(*handle) else { return false };
            for (i, &a) in coefficients.iter().enumerate() {
                if a == 0 { continue; }
                for (j, &b) in w.c.iter().enumerate() {
                    let k = i + j;
                    residual[k % Poly::D] += if k < Poly::D { 1 } else { -1 } * i128::from(a) * i128::from(b);
                }
            }
        }
        residual.iter().all(|v| v.rem_euclid(P as i128) == 0)
    }

    // SHA3-256 of the 2,432-byte canonical identity encodings for context [6;32],
    // recipient seed [9;32], note seed [7;32]. Pinned from an independent Python
    // reimplementation.
    const OWNER_VECTOR_SHA3: &str = "3897684e7a9c5271eb9c99ad54f8b6c6837268a4c211170a82f1b8b9e2fe7d63";
    const IMAGE_VECTOR_SHA3: &str = "3131172893d43644500dc0e969be57bfa7cb6bcb2e67d921783fd8279c2146d0";

    #[test]
    fn recipient_secret_and_note_nonce_bind_compact_identities() {
        let context = [6; 32];
        let seed = [7; 32];
        let key = MembershipKey::derive(&context);
        let value_key = CommitmentKey::derive(&context);
        let sent = NoteSecrets::from_seeds(
            &context,
            &RecipientSecret::from_seed(&context, &[9; 32]),
            &seed,
        );
        let received = NoteSecrets::from_seeds(
            &context,
            &RecipientSecret::from_seed(&context, &[9; 32]),
            &seed,
        );
        assert_eq!(
            value_key.commit(u128::MAX, &sent.opening),
            value_key.commit(u128::MAX, &received.opening)
        );
        assert_eq!(key.owner_key(&sent.owner), key.owner_key(&received.owner));
        let owner = key.owner_key(&sent.owner);
        let image = key.key_image(&sent.owner);
        assert_ne!(owner, image);
        let recipient = RecipientSecret::from_seed(&context, &[9; 32]);
        let public_address = key.recipient_key(&recipient);
        assert_eq!(key.output_owner(&public_address, &seed).unwrap(), owner);
        let wrong_recipient = RecipientSecret::from_seed(&context, &seed);
        assert_ne!(key.owner_key(&wrong_recipient.note_owner(&seed)), owner);
        assert_ne!(key.key_image(&recipient.note_owner(&[8; 32])), image);
        assert_ne!(key.output_owner(&public_address, &[8; 32]).unwrap(), owner);
        // Vectors generated independently by a reference script.
        let digest = |node: &Node| {
            let mut h = <sha3::Sha3_256 as sha3::Digest>::new();
            sha3::Digest::update(&mut h, node.identity_bytes().unwrap());
            sha3::Digest::finalize(h).iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        assert_eq!(digest(&owner), OWNER_VECTOR_SHA3);
        assert_eq!(digest(&image), IMAGE_VECTOR_SHA3);
        for identity in [&owner, &image] {
            let compact = identity.identity_bytes().unwrap();
            assert_eq!(compact.len(), IDENTITY_BYTES);
            assert_eq!(Node::from_identity_bytes(&compact).unwrap(), *identity);
            assert!(Node::from_identity_bytes(&compact[..IDENTITY_BYTES - 1]).is_err());
            let mut too_long = compact.to_vec();
            too_long.push(0);
            assert!(Node::from_identity_bytes(&too_long).is_err());
        }
        let mut malformed = owner.clone();
        malformed.0[NODE_RANK - 1].c[0] = 1;
        assert!(malformed.identity_bytes().is_err());
        malformed = owner.clone();
        malformed.0[0].c[0] = P;
        assert!(Node::from_identity_bytes(&malformed.to_bytes()[..IDENTITY_BYTES]).is_err());
        assert_ne!(
            key.key_image(&sent.owner),
            MembershipKey::derive(&[8; 32]).key_image(&sent.owner)
        );
    }

    #[test]
    fn path_choice_is_witness_data_and_leaf_root_is_bound() {
        let context = [5; 32];
        let value_key = CommitmentKey::derive(&context);
        let key = MembershipKey::derive(&context);
        let secret = RecipientSecret::from_seed(&context, &[8; 32]).note_owner(&[9; 32]);
        let opening = AmountOpening::from_seed(&context, &[9; 32]);
        let commitment = value_key.commit(10, &opening);
        let coin = [(10, &opening, &commitment)];
        let leaf = key.leaf(&key.owner_key(&secret), &commitment);
        let images = [key.key_image(&secret)];
        // Same leaf at both positions gives two honest witnesses for the same
        // public root/image. Public equation coefficients must be identical.
        let root = key.parent(&leaf, &leaf);
        let sibling = [leaf.clone()];
        let statement = MembershipStatement {
            root: &root,
            key_images: &images,
            depth: 1,
        };
        let compile = |right: &[bool]| {
            CompiledAmountRelation::compile_with_membership(
                &value_key,
                &key,
                &coin,
                &coin,
                0,
                0,
                &statement,
                &[InputPath {
                    owner: &secret,
                    siblings: &sibling,
                    right,
                }],
            )
            .unwrap()
        };
        let left = compile(&[false]);
        let right = compile(&[true]);
        assert!(left.validate_local_witness() && right.validate_local_witness());
        assert!(left.ring == right.ring && left.scalar == right.scalar);
        assert!(left.membership == right.membership);
        assert!(left.binary != right.binary);
        // Exercise compression, hidden leaf targets and the public root, with
        // both directions of the correlated child expression. Each matrix has
        // six identically shaped rows; lift the first row of every family.
        for relation in [&left, &right] {
            assert!(relation
                .selection_backend_rows()
                .all(|row| row.validate_local_witness(relation)));
            // Every emitted native proof-ring row must hold over the witness
            // modulo p, independently of the structural validator.
            assert!(relation.native_membership_rows().all(|row| native_row_holds(relation, &row)));
            assert!(relation.native_membership_row_count() > 0);
        }
        let leaf_statement = MembershipStatement {
            root: &leaf,
            key_images: &images,
            depth: 0,
        };
        let mut direct = CompiledAmountRelation::compile_with_membership(
            &value_key,
            &key,
            &coin,
            &coin,
            0,
            0,
            &leaf_statement,
            &[InputPath {
                owner: &secret,
                siblings: &[],
                right: &[],
            }],
        )
        .unwrap();
        assert!(direct.validate_local_witness());
        let public = PublicAmountRelation::compile_with_membership(
            &value_key,
            &key,
            &[coin[0].2.clone()],
            0,
            0,
            &leaf_statement,
        )
        .unwrap();
        assert!(public.relation.ring == direct.ring);
        assert!(public.relation.scalar == direct.scalar);
        assert!(public.relation.membership == direct.membership);
        direct.ring.last_mut().unwrap().rhs.c[0] ^= 1;
        assert!(!direct.validate_local_witness());
        let malformed = MembershipStatement {
            depth: MAX_DEPTH + 1,
            ..leaf_statement
        };
        assert!(matches!(
            PublicAmountRelation::compile_with_membership(&value_key, &key, &[], 0, 0, &malformed,),
            Err(TokenError::InvalidMembership)
        ));
        assert!(CompiledAmountRelation::compile_with_membership(
            &value_key,
            &key,
            &coin,
            &coin,
            0,
            0,
            &malformed,
            &[InputPath {
                owner: &secret,
                siblings: &[],
                right: &[]
            }],
        )
        .is_err());
    }

    #[test]
    fn two_coins_share_root_and_amount_witness() {
        let value_key = CommitmentKey::derive(&[3; 32]);
        let key = MembershipKey::derive(&[3; 32]);
        let owners: [_; 2] = std::array::from_fn(|i| {
            RecipientSecret::from_seed(&[3; 32], &[i as u8; 32]).note_owner(&[i as u8 + 32; 32])
        });
        let openings: [_; 4] =
            std::array::from_fn(|i| AmountOpening::from_seed(&[3; 32], &[i as u8 + 10; 32]));
        let amounts = [257, 8, 254, 9];
        let commitments: [_; 4] =
            std::array::from_fn(|i| value_key.commit(amounts[i], &openings[i]));
        let coins: [_; 4] = std::array::from_fn(|i| (amounts[i], &openings[i], &commitments[i]));
        let leaves: [_; 2] =
            std::array::from_fn(|i| key.leaf(&key.owner_key(&owners[i]), &commitments[i]));
        let parent = key.parent(&leaves[0], &leaves[1]);
        let root = key.parent(&Node::zero(), &parent);
        let images: [_; 2] = std::array::from_fn(|i| key.key_image(&owners[i]));
        for node in [&root, &images[0], &images[1]] {
            let bytes = node.to_bytes();
            assert_eq!(bytes.len(), NODE_BYTES);
            assert_eq!(Node::from_bytes(&bytes).unwrap(), *node);
            assert_eq!(
                Node::from_bytes(&bytes[..bytes.len() - 1]),
                Err(TokenError::Length)
            );
        }
        let mut noncanonical = root.clone();
        noncanonical.0[NODE_RANK - 1].c[255] = P;
        assert_eq!(
            Node::from_bytes(&noncanonical.to_bytes()),
            Err(TokenError::NoncanonicalCoefficient)
        );
        let siblings = [
            [leaves[1].clone(), Node::zero()],
            [leaves[0].clone(), Node::zero()],
        ];
        let directions = [[false, true], [true, true]];
        let paths: [_; 2] = std::array::from_fn(|i| InputPath {
            owner: &owners[i],
            siblings: &siblings[i],
            right: &directions[i],
        });
        let statement = MembershipStatement {
            root: &root,
            key_images: &images,
            depth: 2,
        };
        let mut relation = CompiledAmountRelation::compile_with_membership(
            &value_key,
            &key,
            &coins[..2],
            &coins[2..],
            0,
            2,
            &statement,
            &paths,
        )
        .unwrap();
        assert!(relation.validate_local_witness());
        // Two inputs × two levels × (NODE_RANK rows × 6 limbs) unit-weight selections.
        assert_eq!(
            relation.membership_shape().quadratic_selection_equations,
            2 * 2 * NODE_RANK * 6
        );
        // A changed private input must fail its original amount/leaf linkage.
        let index = relation.input_commitment_planes[0][0][0];
        relation.binary[index].c[0] ^= 1;
        assert!(!relation.validate_local_witness());
        relation.binary[index].c[0] ^= 1;
        // Every polynomial component shares the same scalar path selector.
        let selector = relation.membership.selections[0].selector;
        relation.binary[selector].c[1] = 1;
        assert!(!relation.validate_local_witness());
        relation.binary[selector].c[1] = 0;
        // The public image is a public hash target: a different image must
        // fail the identity equation, not merely the honest-witness builder.
        let mut wrong_image = images.clone();
        wrong_image[0].0[0].c[0] ^= 1;
        let wrong = MembershipStatement { root: &root, key_images: &wrong_image, depth: 2 };
        assert!(CompiledAmountRelation::compile_with_membership(
            &value_key, &key, &coins[..2], &coins[2..], 0, 2, &wrong, &paths,
        ).is_err());
        let bad = MembershipStatement {
            root: &Node::zero(),
            key_images: &images,
            depth: 2,
        };
        assert!(CompiledAmountRelation::compile_with_membership(
            &value_key,
            &key,
            &coins[..2],
            &coins[2..],
            0,
            2,
            &bad,
            &paths,
        )
        .is_err());
        let duplicates = [images[0].clone(), images[0].clone()];
        let duplicate = MembershipStatement {
            root: &root,
            key_images: &duplicates,
            depth: 2,
        };
        assert!(matches!(
            CompiledAmountRelation::compile_with_membership(
                &value_key,
                &key,
                &coins[..2],
                &coins[2..],
                0,
                2,
                &duplicate,
                &paths,
            ),
            Err(TokenError::DuplicateKeyImage)
        ));
    }
}

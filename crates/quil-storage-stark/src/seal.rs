//! A member's epoch STARK: in one proof, the seals of its registrations for
//! the next epoch and the possession openings it committed to this epoch.
//!
//! - **Seals:** everything [`quil_crypto::storage_proof::verify_seal`] checks
//!   for each leaf, proven over the plain seal proofs.
//! - **Openings:** each frame the member proposed committed one root
//!   ([`quil_crypto::storage_proof::openings_root`]) over the replica nodes it
//!   opened at that frame's beacon. The proof shows each value sits at its
//!   beacon-derived index under the registration's `comm_R`, and that the
//!   values hash to exactly the committed root. Committing at proposal time
//!   keeps the response window; proving later moves the openings off GLOBAL.
//!
//! Ten tables, joined by multiset buses (LogUp):
//!
//! | table | rows | proves |
//! |---|---|---|
//! | `Perm` | one Poseidon2 permutation each | the permutation; provides `perm` |
//! | `Pub` | one per (challenge, slot) | the seal indices (periodic, the verifier's) |
//! | `Leaves` | one per leaf | each leaf's key and tree depth (periodic) |
//! | `Column` | 16 per opened column | its labels chain into its column digest |
//! | `Label` | 128 per challenge | each layer's label is the sponge of the member's key, the layer and node, and its graph parents' labels |
//! | `Merkle` | `2^⌈log max depth⌉` per path | each opened value sits at its public index under its tree's root |
//! | `Check` | one per challenge | the replica node is the data node plus the last label |
//! | `Bind` | three per leaf | each root, bound to its tree and leaf count, is the registered commitment |
//! | `OPub` | one per opening | the opening indices (periodic) |
//! | `Frames` | one per absorbed pair | each frame's opened values hash to its committed root |
//!
//! Leaves are the sealed registrations, then the held ones; challenges and
//! openings are numbered across them, and every bus message names its leaf,
//! so leaves sharing node indices stay apart. A seal slot is a (challenge,
//! position) pair: position 0 is the challenged node, 1..=6 its DRG parents
//! (inactive for node 0), 7..=14 its expander parents. Every table reads the
//! node a slot names from `Pub`, whose entries the verifier derives from the
//! beacons and the graph, each read a fixed number of times: no slot can be
//! skipped, repeated or renamed, and a label row's challenge, layer and block
//! follow from its position, so the graph is the real one.

use std::borrow::Cow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_batch_stark::{prove_batch, verify_batch, BatchProof, ProverData, StarkInstance};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use quil_crypto::sdr::SdrParams;
use quil_crypto::storage_hash::{self as hash, Digest, Domain};
use quil_crypto::storage_proof::{self, SealProof, SealStatement};

use crate::config::{config, Config, Val};
use crate::poseidon;

const PERM: &str = "perm";
const PUB: &str = "pub";
const OPEN: &str = "open";
const KEY: &str = "key";
const DEPTH: &str = "depth";
const LABEL: &str = "label";
const LEAF: &str = "leaf";
const ROOT: &str = "root";

const D: usize = hash::DIGEST_ELEMS;
const W: usize = poseidon::WIDTH;
const LAYERS: usize = 11;
const DRG: usize = 6;
const EXPANDER: usize = 8;
/// Slots per challenge: the node, its DRG parents, its expander parents.
const SLOTS: usize = 1 + DRG + EXPANDER;
/// Merkle paths per challenge: data, replica, and one column per slot.
const PATHS: usize = 2 + SLOTS;
const COLUMN_ROWS: usize = 16;
const LABEL_BLOCKS: usize = 8;
const LABEL_ROWS: usize = 16 * LABEL_BLOCKS;
const LABEL_LENGTH: u32 = (2 + DRG + EXPANDER) as u32 * D as u32;
/// Tables never shorter than this.
const MIN_HEIGHT: usize = 4;

/// Reads of each `Pub` entry: a challenged node by every layer's header (11),
/// its column, its data, replica and column paths, and its check row; a DRG
/// parent by every layer (11), its column and its path; an expander parent by
/// layers 1..=10, its column and its path.
const NODE_READS: u32 = LAYERS as u32 + 1 + 3 + 1;
const DRG_READS: u32 = LAYERS as u32 + 1 + 1;
const EXPANDER_READS: u32 = (LAYERS as u32 - 1) + 1 + 1;

#[derive(Clone, Copy)]
#[repr(u32)]
enum Tree {
    Data = 0,
    Column = 1,
    Replica = 2,
}

fn felt(value: u64) -> Val {
    hash::felt(value as u32)
}

fn height(rows: usize) -> usize {
    rows.next_power_of_two().max(MIN_HEIGHT)
}

// ── The statement ────────────────────────────────────────────────────────────

/// A registration whose possession the member proves: its openings open
/// against `comm_r`.
#[derive(Clone, Copy, Debug)]
pub struct Held<'a> {
    pub member: &'a [u8],
    pub leaf_id: &'a [u8],
    pub epoch: u64,
    pub n: u64,
    pub comm_r: [u8; 32],
}

/// A frame the member proposed: the root it committed and the held
/// registrations it opened there (indices into [`EpochStatement::held`]).
#[derive(Clone, Debug)]
pub struct FrameOpenings<'a> {
    pub frame_number: u64,
    pub rho_n: &'a [u8],
    pub root: [u8; 32],
    pub held: Vec<usize>,
}

/// Everything one epoch proof covers.
#[derive(Clone, Debug)]
pub struct EpochStatement<'a> {
    pub seals: Vec<SealStatement<'a>>,
    /// Seal challenges per sealed leaf.
    pub count: usize,
    pub held: Vec<Held<'a>>,
    pub frames: Vec<FrameOpenings<'a>>,
    /// Openings per held registration per frame.
    pub queries: u32,
}

/// One opened replica node: its value and its path in `comm_R`.
#[derive(Clone, Debug)]
pub struct Opened {
    pub value: [u8; 32],
    pub path: Vec<[u8; 32]>,
}

/// What the verifier derives from one leaf of the statement.
#[derive(Clone, Debug)]
struct LeafPublic {
    n: u64,
    depth: usize,
    key: Digest,
    /// The registered commitments, data, column and replica; a held leaf
    /// binds only its replica.
    commitments: [Option<Digest>; 3],
    challenges: Vec<u64>,
    /// Per challenge: the node of every slot, and whether the slot opens.
    slots: Vec<[(u64, bool); SLOTS]>,
    /// Opening paths of a held leaf.
    openings: u64,
}

impl LeafPublic {
    fn sealed(statement: &SealStatement, params: &SdrParams, count: usize) -> Result<Self, String> {
        let n = check_nodes(statement.n)?;
        let registered = &statement.registered;
        let challenges = storage_proof::seal_challenges(statement, count);
        let slots = challenges
            .iter()
            .map(|&j| {
                let (same_layer, layer_below) = storage_proof::parents_of(j, n, params);
                let mut slots = [(0u64, false); SLOTS];
                slots[0] = (j, true);
                for (slot, &p) in slots[1..=DRG].iter_mut().zip(&same_layer) {
                    *slot = (p, true);
                }
                for (slot, &p) in slots[1 + DRG..].iter_mut().zip(&layer_below) {
                    *slot = (p, true);
                }
                slots
            })
            .collect();
        Ok(Self {
            n,
            depth: storage_proof::tree_depth(n),
            key: hash::key_digest(&quil_crypto::sdr::replica_key(
                statement.member,
                statement.leaf_id,
                statement.epoch,
            )),
            commitments: [
                Some(commitment(&registered.comm_d)?),
                Some(commitment(&registered.comm_c)?),
                Some(commitment(&registered.comm_r)?),
            ],
            challenges,
            slots,
            openings: 0,
        })
    }

    fn held(held: &Held, openings: u64) -> Result<Self, String> {
        let n = check_nodes(held.n)?;
        Ok(Self {
            n,
            depth: storage_proof::tree_depth(n),
            key: hash::ZERO,
            commitments: [None, None, Some(commitment(&held.comm_r)?)],
            challenges: Vec::new(),
            slots: Vec::new(),
            openings,
        })
    }

    /// Opened columns of tree C: every slot that opens.
    fn column_paths(&self) -> u64 {
        self.slots
            .iter()
            .flatten()
            .filter(|(_, open)| *open)
            .count() as u64
    }

    /// Paths reaching each tree's root: data, column, replica.
    fn paths(&self) -> [u64; 3] {
        let count = self.challenges.len() as u64;
        [count, self.column_paths(), count + self.openings]
    }
}

fn check_nodes(n: u64) -> Result<u64, String> {
    if n < storage_proof::MIN_NODES as u64 || n >= 1 << 30 {
        return Err(format!("a registration of {n} nodes"));
    }
    Ok(n)
}

fn commitment(node: &[u8; 32]) -> Result<Digest, String> {
    hash::from_bytes(node).ok_or_else(|| "a non-canonical commitment".to_string())
}

/// One opening: its (global) leaf and its node.
#[derive(Clone, Copy, Debug)]
struct OpeningPublic {
    leaf: usize,
    index: u64,
}

/// One row of `Frames`: the pair of digests a frame's sponge absorbs there.
#[derive(Clone, Copy, Debug, Default)]
struct FrameBlock {
    first: bool,
    last: bool,
    /// Opening ids of the two slots when they hold opened values.
    a: Option<usize>,
    b: Option<usize>,
    frame_number: u64,
    count: u64,
    root: Digest,
}

/// What the verifier derives from an epoch statement.
#[derive(Clone, Debug)]
pub struct Public {
    /// The sealed leaves, then the held ones.
    leaves: Vec<LeafPublic>,
    /// Per global challenge: its leaf and its index in that leaf.
    challenge_of: Vec<(usize, usize)>,
    openings: Vec<OpeningPublic>,
    blocks: Vec<FrameBlock>,
    /// SHA3 over the whole statement, as field elements: what the transcript
    /// binds.
    digest: Digest,
}

impl Public {
    pub fn new(statement: &EpochStatement, params: &SdrParams) -> Result<Self, String> {
        if (params.drg_degree, params.expander_degree, params.layers) != (DRG, EXPANDER, LAYERS) {
            return Err(
                "the seal circuit is fixed to DRG degree 6, expander degree 8 and 11 layers".into(),
            );
        }
        if statement.seals.is_empty() && statement.frames.is_empty() {
            return Err("an epoch proof covers at least one seal or frame".into());
        }
        if !statement.seals.is_empty() && statement.count == 0 {
            return Err("seals need challenges".into());
        }
        let mut leaves = statement
            .seals
            .iter()
            .map(|s| LeafPublic::sealed(s, params, statement.count))
            .collect::<Result<Vec<_>, _>>()?;
        let sealed = leaves.len();
        let mut opened = vec![0u64; statement.held.len()];
        for frame in &statement.frames {
            if frame.held.is_empty() {
                return Err(format!("frame {} opens nothing", frame.frame_number));
            }
            for &h in &frame.held {
                *opened.get_mut(h).ok_or_else(|| {
                    format!("frame {} opens held registration {h}", frame.frame_number)
                })? += statement.queries as u64;
            }
        }
        for (held, &count) in statement.held.iter().zip(&opened) {
            leaves.push(LeafPublic::held(held, count)?);
        }
        let challenge_of = leaves
            .iter()
            .enumerate()
            .flat_map(|(l, leaf)| (0..leaf.challenges.len()).map(move |k| (l, k)))
            .collect();

        let mut openings = Vec::new();
        let mut blocks = Vec::new();
        for frame in &statement.frames {
            let first_opening = openings.len();
            for &h in &frame.held {
                let held = &statement.held[h];
                for q in 0..statement.queries {
                    let index = storage_proof::opening_index(
                        frame.rho_n,
                        held.leaf_id,
                        held.epoch,
                        held.member,
                        q,
                        held.n,
                    );
                    openings.push(OpeningPublic {
                        leaf: sealed + h,
                        index,
                    });
                }
            }
            let count = openings.len() - first_opening;
            let root = commitment(&frame.root)?;
            // Digests absorbed: the header, then each value; two per block.
            let digests = 1 + count;
            let rows = digests.div_ceil(2);
            for b in 0..rows {
                let value =
                    |slot: usize| (slot >= 1 && slot <= count).then(|| first_opening + slot - 1);
                blocks.push(FrameBlock {
                    first: b == 0,
                    last: b + 1 == rows,
                    a: value(2 * b),
                    b: value(2 * b + 1),
                    frame_number: frame.frame_number,
                    count: count as u64,
                    root,
                });
            }
        }
        Ok(Self {
            leaves,
            challenge_of,
            openings,
            blocks,
            digest: statement_digest(statement),
        })
    }

    fn challenges(&self) -> usize {
        self.challenge_of.len()
    }

    /// Rows per Merkle path: the deepest tree's levels, rounded up.
    fn path_rows(&self) -> usize {
        self.leaves
            .iter()
            .map(|l| l.depth)
            .max()
            .unwrap_or(1)
            .next_power_of_two()
    }

    /// The leaf of global challenge `g`, its index there, and the leaf.
    fn challenge(&self, g: usize) -> (usize, usize, &LeafPublic) {
        let (l, k) = self.challenge_of[g];
        (l, k, &self.leaves[l])
    }

    fn transcript_values(&self) -> Vec<Val> {
        let mut values = vec![
            felt(self.leaves.len() as u64),
            felt(self.challenges() as u64),
            felt(self.openings.len() as u64),
        ];
        values.extend_from_slice(&self.digest);
        values
    }

    /// Every table's height, in table order.
    fn heights(&self) -> [usize; 10] {
        let g = self.challenges();
        let paths = g * PATHS + self.openings.len();
        [
            height(self.permutations()),
            height(g * SLOTS),
            height(self.leaves.len()),
            height((g * SLOTS).max(1) * COLUMN_ROWS),
            height(g.max(1) * LABEL_ROWS),
            height(paths.max(1) * self.path_rows()),
            height(g),
            height(3 * self.leaves.len()),
            height(self.openings.len()),
            height(self.blocks.len()),
        ]
    }

    /// Permutations the statement needs: every label block, column step,
    /// path level, binding and frame block.
    fn permutations(&self) -> usize {
        let leaves: usize = self
            .leaves
            .iter()
            .map(|leaf| {
                let count = leaf.challenges.len();
                let columns = leaf.column_paths() as usize;
                let paths = 2 * count + columns + leaf.openings as usize;
                count * LAYERS * LABEL_BLOCKS
                    + columns * LAYERS
                    + paths * leaf.depth
                    + leaf.commitments.iter().flatten().count()
            })
            .sum();
        leaves + self.blocks.len()
    }
}

/// SHA3 over the whole statement in order: each seal (member, leaf, beacon,
/// epoch, node count, the three commitments), the challenge count, each held
/// registration (member, leaf, epoch, node count, replica commitment), the
/// query count and each frame (number, beacon, root, held registrations).
fn statement_digest(statement: &EpochStatement) -> Digest {
    use sha3::{Digest as _, Sha3_256};
    let mut h = Sha3_256::new();
    let mut put = |bytes: &[u8]| {
        h.update((bytes.len() as u32).to_be_bytes());
        h.update(bytes);
    };
    put(b"quil/storage-stark/epoch/v1");
    put(&(statement.seals.len() as u64).to_be_bytes());
    for s in &statement.seals {
        put(s.member);
        put(s.leaf_id);
        put(s.beacon);
        put(&s.epoch.to_be_bytes());
        put(&s.n.to_be_bytes());
        put(&s.registered.comm_d);
        put(&s.registered.comm_c);
        put(&s.registered.comm_r);
    }
    put(&(statement.count as u64).to_be_bytes());
    put(&(statement.held.len() as u64).to_be_bytes());
    for held in &statement.held {
        put(held.member);
        put(held.leaf_id);
        put(&held.epoch.to_be_bytes());
        put(&held.n.to_be_bytes());
        put(&held.comm_r);
    }
    put(&statement.queries.to_be_bytes());
    put(&(statement.frames.len() as u64).to_be_bytes());
    for frame in &statement.frames {
        put(&frame.frame_number.to_be_bytes());
        put(frame.rho_n);
        put(&frame.root);
        put(&(frame.held.len() as u64).to_be_bytes());
        for &held in &frame.held {
            put(&(held as u64).to_be_bytes());
        }
    }
    hash::key_digest(&h.finalize())
}

// ── The tables ───────────────────────────────────────────────────────────────

/// One table of the epoch statement. Every table's periodic columns are the
/// verifier's: structure (layers, blocks, levels) and, for `Pub`, `Leaves`,
/// `Bind`, `OPub` and `Frames`, the statement.
#[derive(Clone)]
pub enum SealAir {
    /// The permutation table also carries the statement's digest as public
    /// values, so the transcript binds it.
    Perm {
        public_values: usize,
    },
    Pub {
        periodic: Vec<Vec<Val>>,
    },
    Leaves {
        periodic: Vec<Vec<Val>>,
    },
    Column {
        periodic: Vec<Vec<Val>>,
    },
    Label {
        periodic: Vec<Vec<Val>>,
    },
    Merkle {
        periodic: Vec<Vec<Val>>,
    },
    Check,
    Bind {
        periodic: Vec<Vec<Val>>,
    },
    OPub {
        periodic: Vec<Vec<Val>>,
    },
    Frames {
        periodic: Vec<Vec<Val>>,
    },
}

pub(crate) const PERM_WIDTH: usize = poseidon::NUM_COLS + 1;

/// `Pub`: one committed column (constrained to zero); the rest is periodic.
pub(crate) mod pubc {
    pub const WIDTH: usize = 1;
    pub const P_G: usize = 0;
    pub const P_S: usize = 1;
    pub const P_NODE: usize = 2;
    pub const P_ACTIVE: usize = 3;
    pub const P_LEAF: usize = 4;
    pub const P_READS: usize = 5;
    pub const PERIODIC: usize = 6;
}

/// `Leaves`: one committed column (zero); each leaf's key and depth and how
/// often they are read.
pub(crate) mod lvs {
    pub const WIDTH: usize = 1;
    pub const P_LEAF: usize = 0;
    pub const P_DEPTH: usize = 1;
    pub const P_KEY: usize = 2;
    pub const P_KEY_READS: usize = P_KEY + 8;
    pub const P_DEPTH_READS: usize = P_KEY_READS + 1;
    pub const PERIODIC: usize = P_DEPTH_READS + 1;
}

/// `Column`: slot (g, s), its node, activity and leaf, whether the 16 rows are
/// an instance at all, the chain step and the label's multiplicity.
pub(crate) mod col {
    pub const G: usize = 0;
    pub const S: usize = 1;
    pub const NODE: usize = 2;
    pub const ACTIVE: usize = 3;
    pub const INSTANCE: usize = 4;
    pub const LEAF: usize = 5;
    pub const ACC: usize = 6;
    pub const LABEL: usize = ACC + 8;
    pub const OUT: usize = LABEL + 8;
    pub const MULT: usize = OUT + 24;
    pub const WIDTH: usize = MULT + 1;
    pub const P_LAYER: usize = 0;
    pub const P_FIRST: usize = 1;
    pub const P_LAST: usize = 2;
    pub const P_LIVE: usize = 3;
    pub const P_END: usize = 4;
    pub const PERIODIC: usize = 5;
}

/// `Label`: challenge, its node and leaf, whether it is real, the two slots'
/// nodes and activity, the two absorbed digests, the sponge state in and the
/// permutation's output.
pub(crate) mod lab {
    pub const G: usize = 0;
    pub const J: usize = 1;
    pub const LEAF: usize = 2;
    pub const REAL: usize = 3;
    pub const A_NODE: usize = 4;
    pub const A_ACTIVE: usize = 5;
    pub const B_NODE: usize = 6;
    pub const B_ACTIVE: usize = 7;
    pub const A: usize = 8;
    pub const B: usize = A + 8;
    pub const STATE: usize = B + 8;
    pub const OUT: usize = STATE + 24;
    pub const WIDTH: usize = OUT + 24;
    pub const P_LAYER: usize = 0;
    pub const P_LIVE: usize = 1;
    pub const P_FIRST_BLOCK: usize = 2;
    pub const P_LAST_BLOCK: usize = 3;
    pub const P_DRG: usize = 4;
    pub const P_EXPANDER: usize = 5;
    pub const P_BELOW: usize = 6;
    pub const P_A_SLOT: usize = 7;
    pub const P_LAST_OF_CHALLENGE: usize = 8;
    pub const PERIODIC: usize = 9;
}

/// `Merkle`: the path's id (a challenge, or an opening when `OPEN`), its tree
/// position and slot, whether it is a column path, a path at all, active;
/// its leaf and that leaf's depth; whether this level is live and whether it
/// is the path's last; the gate (path ∧ active); whether it is an opening's
/// path; the index, its bit, the value, the sibling, the output.
pub(crate) mod mrk {
    pub const G: usize = 0;
    pub const T: usize = 1;
    pub const S: usize = 2;
    pub const IS_COLUMN: usize = 3;
    pub const IS_PATH: usize = 4;
    pub const ACTIVE: usize = 5;
    pub const LEAF: usize = 6;
    pub const DEPTH: usize = 7;
    pub const LIVE: usize = 8;
    pub const END: usize = 9;
    pub const GATE: usize = 10;
    pub const OPEN: usize = 11;
    pub const IDX: usize = 12;
    pub const BIT: usize = 13;
    pub const CUR: usize = 14;
    pub const SIB: usize = CUR + 8;
    pub const OUT: usize = SIB + 8;
    pub const WIDTH: usize = OUT + 24;
    pub const P_LEVEL: usize = 0;
    pub const P_FIRST: usize = 1;
    pub const P_END: usize = 2;
    pub const PERIODIC: usize = 3;
}

/// `Check`: challenge, node, leaf, data, last label, replica, whether a row.
pub(crate) mod chk {
    pub const G: usize = 0;
    pub const J: usize = 1;
    pub const LEAF: usize = 2;
    pub const DATA: usize = 3;
    pub const LABEL: usize = DATA + 8;
    pub const REPLICA: usize = LABEL + 8;
    pub const ROW: usize = REPLICA + 8;
    pub const WIDTH: usize = ROW + 1;
}

/// `Bind`: the root and the permutation's output; periodic leaf, tree,
/// liveness, leaf count, path count and the registered commitment.
pub(crate) mod bnd {
    pub const ROOT: usize = 0;
    pub const OUT: usize = ROOT + 8;
    pub const WIDTH: usize = OUT + 24;
    pub const P_LEAF: usize = 0;
    pub const P_TREE: usize = 1;
    pub const P_LIVE: usize = 2;
    pub const P_N: usize = 3;
    pub const P_PATHS: usize = 4;
    pub const P_COMMITMENT: usize = 5;
    pub const PERIODIC: usize = P_COMMITMENT + 8;
}

/// `OPub`: one committed column (zero); each opening's id, leaf and node.
pub(crate) mod opb {
    pub const WIDTH: usize = 1;
    pub const P_O: usize = 0;
    pub const P_LEAF: usize = 1;
    pub const P_IDX: usize = 2;
    pub const P_READS: usize = 3;
    pub const PERIODIC: usize = 4;
}

/// `Frames`: the two digests a block absorbs, the sponge state in and the
/// permutation's output; periodic: liveness, first and last block, whether
/// each slot holds an opened value and which, the frame's number, opening
/// count and committed root.
pub(crate) mod frm {
    pub const A: usize = 0;
    pub const B: usize = A + 8;
    pub const STATE: usize = B + 8;
    pub const OUT: usize = STATE + 24;
    pub const WIDTH: usize = OUT + 24;
    pub const P_LIVE: usize = 0;
    pub const P_FIRST: usize = 1;
    pub const P_LAST: usize = 2;
    pub const P_A_VALUE: usize = 3;
    pub const P_B_VALUE: usize = 4;
    pub const P_A_ID: usize = 5;
    pub const P_B_ID: usize = 6;
    pub const P_FRAME: usize = 7;
    pub const P_COUNT: usize = 8;
    pub const P_ROOT: usize = 9;
    pub const PERIODIC: usize = P_ROOT + 8;
}

impl SealAir {
    fn tables(public: &Public) -> Vec<SealAir> {
        let heights = public.heights();

        let mut pub_p = vec![vec![Val::ZERO; heights[1]]; pubc::PERIODIC];
        for g in 0..public.challenges() {
            let (l, k, leaf) = public.challenge(g);
            for (s, &(node, active)) in leaf.slots[k].iter().enumerate() {
                let row = g * SLOTS + s;
                let reads = match s {
                    0 => NODE_READS,
                    s if s <= DRG => DRG_READS,
                    _ => EXPANDER_READS,
                };
                pub_p[pubc::P_G][row] = felt(g as u64);
                pub_p[pubc::P_S][row] = felt(s as u64);
                pub_p[pubc::P_NODE][row] = felt(node);
                pub_p[pubc::P_ACTIVE][row] = Val::from_bool(active);
                pub_p[pubc::P_LEAF][row] = felt(l as u64);
                pub_p[pubc::P_READS][row] = hash::felt(reads);
            }
        }

        let mut leaves_p = vec![vec![Val::ZERO; heights[2]]; lvs::PERIODIC];
        for (l, leaf) in public.leaves.iter().enumerate() {
            let count = leaf.challenges.len() as u64;
            leaves_p[lvs::P_LEAF][l] = felt(l as u64);
            leaves_p[lvs::P_DEPTH][l] = felt(leaf.depth as u64);
            for i in 0..D {
                leaves_p[lvs::P_KEY + i][l] = leaf.key[i];
            }
            leaves_p[lvs::P_KEY_READS][l] = felt(count * LAYERS as u64);
            leaves_p[lvs::P_DEPTH_READS][l] = felt(count * PATHS as u64 + leaf.openings);
        }

        let mut column_p = vec![vec![Val::ZERO; COLUMN_ROWS]; col::PERIODIC];
        for layer in 0..COLUMN_ROWS {
            column_p[col::P_LAYER][layer] = felt(layer as u64);
            column_p[col::P_FIRST][layer] = Val::from_bool(layer == 0);
            column_p[col::P_LAST][layer] = Val::from_bool(layer == LAYERS - 1);
            column_p[col::P_LIVE][layer] = Val::from_bool(layer < LAYERS);
            column_p[col::P_END][layer] = Val::from_bool(layer == COLUMN_ROWS - 1);
        }

        let mut label_p = vec![vec![Val::ZERO; LABEL_ROWS]; lab::PERIODIC];
        for row in 0..LABEL_ROWS {
            let (layer, block) = (row / LABEL_BLOCKS, row % LABEL_BLOCKS);
            label_p[lab::P_LAYER][row] = felt(layer as u64);
            label_p[lab::P_LIVE][row] = Val::from_bool(layer < LAYERS);
            label_p[lab::P_FIRST_BLOCK][row] = Val::from_bool(block == 0);
            label_p[lab::P_LAST_BLOCK][row] = Val::from_bool(block == LABEL_BLOCKS - 1);
            label_p[lab::P_DRG][row] = Val::from_bool((1..=3).contains(&block));
            label_p[lab::P_EXPANDER][row] = Val::from_bool(block >= 4);
            label_p[lab::P_BELOW][row] = Val::from_bool(layer >= 1);
            // Block b absorbs slots 2b-1 and 2b (blocks 1..=7).
            label_p[lab::P_A_SLOT][row] = felt(if block == 0 { 0 } else { 2 * block as u64 - 1 });
            label_p[lab::P_LAST_OF_CHALLENGE][row] = Val::from_bool(row == LABEL_ROWS - 1);
        }

        let path_rows = public.path_rows();
        let mut merkle_p = vec![vec![Val::ZERO; path_rows]; mrk::PERIODIC];
        for level in 0..path_rows {
            merkle_p[mrk::P_LEVEL][level] = felt(level as u64);
            merkle_p[mrk::P_FIRST][level] = Val::from_bool(level == 0);
            merkle_p[mrk::P_END][level] = Val::from_bool(level == path_rows - 1);
        }

        let mut bind_p = vec![vec![Val::ZERO; heights[7]]; bnd::PERIODIC];
        for (l, leaf) in public.leaves.iter().enumerate() {
            let paths = leaf.paths();
            for tree in 0..3 {
                let row = 3 * l + tree;
                bind_p[bnd::P_LEAF][row] = felt(l as u64);
                bind_p[bnd::P_TREE][row] = felt(tree as u64);
                bind_p[bnd::P_N][row] = felt(leaf.n);
                if let Some(commitment) = leaf.commitments[tree] {
                    bind_p[bnd::P_LIVE][row] = Val::ONE;
                    bind_p[bnd::P_PATHS][row] = felt(paths[tree]);
                    for i in 0..D {
                        bind_p[bnd::P_COMMITMENT + i][row] = commitment[i];
                    }
                }
            }
        }

        let mut opub_p = vec![vec![Val::ZERO; heights[8]]; opb::PERIODIC];
        for (o, opening) in public.openings.iter().enumerate() {
            opub_p[opb::P_O][o] = felt(o as u64);
            opub_p[opb::P_LEAF][o] = felt(opening.leaf as u64);
            opub_p[opb::P_IDX][o] = felt(opening.index);
            opub_p[opb::P_READS][o] = Val::ONE;
        }

        let mut frames_p = vec![vec![Val::ZERO; heights[9]]; frm::PERIODIC];
        for (row, block) in public.blocks.iter().enumerate() {
            frames_p[frm::P_LIVE][row] = Val::ONE;
            frames_p[frm::P_FIRST][row] = Val::from_bool(block.first);
            frames_p[frm::P_LAST][row] = Val::from_bool(block.last);
            frames_p[frm::P_A_VALUE][row] = Val::from_bool(block.a.is_some());
            frames_p[frm::P_B_VALUE][row] = Val::from_bool(block.b.is_some());
            frames_p[frm::P_A_ID][row] = felt(block.a.unwrap_or(0) as u64);
            frames_p[frm::P_B_ID][row] = felt(block.b.unwrap_or(0) as u64);
            frames_p[frm::P_FRAME][row] = felt(block.frame_number);
            frames_p[frm::P_COUNT][row] = felt(block.count);
            for i in 0..D {
                frames_p[frm::P_ROOT + i][row] = block.root[i];
            }
        }

        vec![
            SealAir::Perm {
                public_values: public.transcript_values().len(),
            },
            SealAir::Pub { periodic: pub_p },
            SealAir::Leaves { periodic: leaves_p },
            SealAir::Column { periodic: column_p },
            SealAir::Label { periodic: label_p },
            SealAir::Merkle { periodic: merkle_p },
            SealAir::Check,
            SealAir::Bind { periodic: bind_p },
            SealAir::OPub { periodic: opub_p },
            SealAir::Frames { periodic: frames_p },
        ]
    }

    fn base_width(&self) -> usize {
        match self {
            SealAir::Perm { .. } => PERM_WIDTH,
            SealAir::Pub { .. } => pubc::WIDTH,
            SealAir::Leaves { .. } => lvs::WIDTH,
            SealAir::Column { .. } => col::WIDTH,
            SealAir::Label { .. } => lab::WIDTH,
            SealAir::Merkle { .. } => mrk::WIDTH,
            SealAir::Check => chk::WIDTH,
            SealAir::Bind { .. } => bnd::WIDTH,
            SealAir::OPub { .. } => opb::WIDTH,
            SealAir::Frames { .. } => frm::WIDTH,
        }
    }

    fn periodic(&self) -> Option<&Vec<Vec<Val>>> {
        match self {
            SealAir::Pub { periodic }
            | SealAir::Leaves { periodic }
            | SealAir::Column { periodic }
            | SealAir::Label { periodic }
            | SealAir::Merkle { periodic }
            | SealAir::Bind { periodic }
            | SealAir::OPub { periodic }
            | SealAir::Frames { periodic } => Some(periodic),
            SealAir::Perm { .. } | SealAir::Check => None,
        }
    }

    /// `trace` widened with the copies of this table's periodic columns.
    fn with_periodic_copies(&self, trace: &RowMajorMatrix<Val>) -> RowMajorMatrix<Val> {
        let Some(periodic) = self.periodic() else {
            return trace.clone();
        };
        let base = self.base_width();
        let width = base + periodic.len();
        let mut values = Vec::with_capacity(trace.values.len() / base * width);
        for (row, cells) in trace.values.chunks_exact(base).enumerate() {
            values.extend_from_slice(cells);
            values.extend(periodic.iter().map(|column| column[row % column.len()]));
        }
        RowMajorMatrix::new(values, width)
    }
}

impl BaseAir<Val> for SealAir {
    /// The table's own columns, then a committed copy of each periodic column
    /// (bus messages cannot read periodic columns; the copies are constrained
    /// equal to them).
    fn width(&self) -> usize {
        self.base_width() + self.num_periodic_columns()
    }

    fn num_public_values(&self) -> usize {
        match self {
            SealAir::Perm { public_values } => *public_values,
            _ => 0,
        }
    }

    fn num_periodic_columns(&self) -> usize {
        self.periodic().map_or(0, Vec::len)
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        match self.periodic() {
            Some(periodic) => Cow::Borrowed(periodic.as_slice()),
            None => Cow::Owned(Vec::new()),
        }
    }
}

impl<AB: InteractionBuilder<F = Val>> Air<AB> for SealAir {
    fn eval(&self, builder: &mut AB) {
        match self {
            SealAir::Perm { .. } => eval_perm(builder),
            SealAir::Pub { .. } => eval_pub(builder),
            SealAir::Leaves { .. } => eval_leaves(builder),
            SealAir::Column { .. } => eval_column(builder),
            SealAir::Label { .. } => eval_label(builder),
            SealAir::Merkle { .. } => eval_merkle(builder),
            SealAir::Check => eval_check(builder),
            SealAir::Bind { .. } => eval_bind(builder),
            SealAir::OPub { .. } => eval_opub(builder),
            SealAir::Frames { .. } => eval_frames(builder),
        }
    }
}

/// The copies of the periodic columns, starting at column `base`, each
/// constrained equal to its periodic column. Only LogUp's trace builder
/// evaluates without periodic values; it checks no constraints.
fn periodic_copies<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    local: &[AB::Var],
    base: usize,
    count: usize,
) -> Vec<AB::Expr> {
    let periodic = builder.periodic_values().to_vec();
    if periodic.len() == count {
        for (i, value) in periodic.into_iter().enumerate() {
            builder.assert_eq(local[base + i], value);
        }
    }
    (0..count).map(|i| local[base + i].into()).collect()
}

fn constant<AB: AirBuilder<F = Val>>(value: Val) -> AB::Expr {
    AB::Expr::from(value)
}

/// A permutation input of two digests and a domain in the first capacity
/// element (a Merkle node or a column step).
fn compress_input<AB: AirBuilder<F = Val>>(
    left: Vec<AB::Expr>,
    right: Vec<AB::Expr>,
    domain: Domain,
) -> Vec<AB::Expr> {
    let mut input: Vec<AB::Expr> = left.into_iter().chain(right).collect();
    input.push(constant::<AB>(hash::felt(domain as u32)));
    input.extend((0..W - 2 * D - 1).map(|_| AB::Expr::ZERO));
    input
}

/// A tuple: the leading expressions, then `D` columns from `at`.
fn with_digest<AB: AirBuilder>(head: Vec<AB::Expr>, local: &[AB::Var], at: usize) -> Vec<AB::Expr> {
    head.into_iter()
        .chain((0..D).map(|i| local[at + i].into()))
        .collect()
}

fn eval_perm<AB: InteractionBuilder<F = Val>>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice().to_vec();
    let cols: &poseidon::Cols<AB::Var> = core::borrow::Borrow::borrow(&local[..poseidon::NUM_COLS]);
    let (input, output) = poseidon::eval(builder, cols);
    let fields: Vec<AB::Expr> = input
        .iter()
        .chain(output.iter())
        .map(|&v| v.into())
        .collect();
    builder.push_interaction(
        PERM,
        fields,
        Count::provided(local[poseidon::NUM_COLS].into()),
    );
}

fn eval_pub<AB: InteractionBuilder<F = Val>>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice().to_vec();
    builder.assert_zero(local[0]);
    let p = periodic_copies(builder, &local, pubc::WIDTH, pubc::PERIODIC);
    builder.push_interaction(
        PUB,
        [
            p[pubc::P_G].clone(),
            p[pubc::P_S].clone(),
            p[pubc::P_NODE].clone(),
            p[pubc::P_ACTIVE].clone(),
            p[pubc::P_LEAF].clone(),
        ],
        Count::provided(p[pubc::P_READS].clone()),
    );
}

fn eval_leaves<AB: InteractionBuilder<F = Val>>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice().to_vec();
    builder.assert_zero(local[0]);
    let p = periodic_copies(builder, &local, lvs::WIDTH, lvs::PERIODIC);
    let key: Vec<AB::Expr> = [p[lvs::P_LEAF].clone()]
        .into_iter()
        .chain((0..D).map(|i| p[lvs::P_KEY + i].clone()))
        .collect();
    builder.push_interaction(KEY, key, Count::provided(p[lvs::P_KEY_READS].clone()));
    builder.push_interaction(
        DEPTH,
        [p[lvs::P_LEAF].clone(), p[lvs::P_DEPTH].clone()],
        Count::provided(p[lvs::P_DEPTH_READS].clone()),
    );
}

fn eval_opub<AB: InteractionBuilder<F = Val>>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice().to_vec();
    builder.assert_zero(local[0]);
    let p = periodic_copies(builder, &local, opb::WIDTH, opb::PERIODIC);
    builder.push_interaction(
        OPEN,
        [
            p[opb::P_O].clone(),
            p[opb::P_LEAF].clone(),
            p[opb::P_IDX].clone(),
        ],
        Count::provided(p[opb::P_READS].clone()),
    );
}

fn eval_column<AB: InteractionBuilder<F = Val>>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice().to_vec();
    let next = main.next_slice().to_vec();
    let periodic = periodic_copies(builder, &local, col::WIDTH, col::PERIODIC);
    let p = |i: usize| -> AB::Expr { periodic[i].clone() };
    let v = |i: usize| -> AB::Expr { local[i].into() };
    let nv = |i: usize| -> AB::Expr { next[i].into() };

    for i in [col::ACTIVE, col::INSTANCE] {
        builder.assert_bool(local[i]);
    }
    // The slot, node, activity, instance and leaf hold for all 16 rows.
    let within = builder.is_transition() * (AB::Expr::ONE - p(col::P_END));
    for i in [
        col::G,
        col::S,
        col::NODE,
        col::ACTIVE,
        col::INSTANCE,
        col::LEAF,
    ] {
        builder.when(within.clone()).assert_eq(nv(i), v(i));
    }
    let live = v(col::INSTANCE) * v(col::ACTIVE) * p(col::P_LIVE);
    // The chain starts at zero and carries each step's digest into the next.
    let continues = within * p(col::P_LIVE) * (AB::Expr::ONE - p(col::P_LAST));
    for i in 0..D {
        builder.when(p(col::P_FIRST)).assert_zero(v(col::ACC + i));
        builder
            .when(continues.clone())
            .assert_eq(nv(col::ACC + i), v(col::OUT + i));
    }
    // Only a live instance row provides its label.
    builder.assert_zero(v(col::MULT) * (AB::Expr::ONE - live.clone()));

    let acc: Vec<AB::Expr> = (0..D).map(|i| v(col::ACC + i)).collect();
    let label: Vec<AB::Expr> = (0..D).map(|i| v(col::LABEL + i)).collect();
    let fields: Vec<AB::Expr> = compress_input::<AB>(acc, label, Domain::Column)
        .into_iter()
        .chain((0..W).map(|i| v(col::OUT + i)))
        .collect();
    builder.push_interaction(PERM, fields, Count::bounded(-live, 1));
    builder.push_interaction(
        LABEL,
        with_digest::<AB>(
            vec![v(col::LEAF), v(col::NODE), p(col::P_LAYER)],
            &local,
            col::LABEL,
        ),
        Count::provided(v(col::MULT)),
    );
    builder.push_interaction(
        PUB,
        [
            v(col::G),
            v(col::S),
            v(col::NODE),
            v(col::ACTIVE),
            v(col::LEAF),
        ],
        Count::bounded(-(v(col::INSTANCE) * p(col::P_FIRST)), 1),
    );
    builder.push_interaction(
        LEAF,
        with_digest::<AB>(
            vec![AB::Expr::ZERO, v(col::G), v(col::S) + AB::Expr::TWO],
            &local,
            col::OUT,
        ),
        Count::bounded(v(col::INSTANCE) * v(col::ACTIVE) * p(col::P_LAST), 1),
    );
}

fn eval_label<AB: InteractionBuilder<F = Val>>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice().to_vec();
    let next = main.next_slice().to_vec();
    let periodic = periodic_copies(builder, &local, lab::WIDTH, lab::PERIODIC);
    let p = |i: usize| -> AB::Expr { periodic[i].clone() };
    let v = |i: usize| -> AB::Expr { local[i].into() };
    let nv = |i: usize| -> AB::Expr { next[i].into() };

    for i in [lab::A_ACTIVE, lab::B_ACTIVE, lab::REAL] {
        builder.assert_bool(local[i]);
    }
    // The challenge counter starts at 0 and steps after each challenge's 128
    // rows; its node, leaf and reality hold within the challenge.
    builder.when_first_row().assert_zero(v(lab::G));
    builder
        .when_transition()
        .assert_eq(nv(lab::G), v(lab::G) + p(lab::P_LAST_OF_CHALLENGE));
    let same_challenge = builder.is_transition() * (AB::Expr::ONE - p(lab::P_LAST_OF_CHALLENGE));
    for i in [lab::J, lab::LEAF, lab::REAL] {
        builder.when(same_challenge.clone()).assert_eq(nv(i), v(i));
    }

    // Rows of padding challenges (beyond the last real one) do nothing.
    let live = v(lab::REAL) * p(lab::P_LIVE);
    let first = live.clone() * p(lab::P_FIRST_BLOCK);
    // Block 0: the leaf's key (read below), then [layer, j, 0, …]; the
    // sponge starts from its IV.
    builder
        .when(first.clone())
        .assert_eq(v(lab::B), p(lab::P_LAYER));
    builder
        .when(first.clone())
        .assert_eq(v(lab::B + 1), v(lab::J));
    for i in 2..D {
        builder.when(first.clone()).assert_zero(v(lab::B + i));
    }
    for i in 0..W {
        let iv = match i {
            16 => hash::felt(Domain::Label as u32),
            17 => hash::felt(LABEL_LENGTH),
            _ => Val::ZERO,
        };
        builder
            .when(first.clone())
            .assert_eq(v(lab::STATE + i), constant::<AB>(iv));
    }
    // Later blocks continue the sponge.
    let continues = live.clone() * (AB::Expr::ONE - p(lab::P_LAST_BLOCK));
    for i in 0..W {
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(nv(lab::STATE + i), v(lab::OUT + i));
    }
    // Slots that read nothing are zero: DRG slots of node 0, expander slots on
    // layer 0.
    let drg = live.clone() * p(lab::P_DRG);
    let below = live.clone() * p(lab::P_EXPANDER) * p(lab::P_BELOW);
    let expander_zero = live.clone() * p(lab::P_EXPANDER) * (AB::Expr::ONE - p(lab::P_BELOW));
    for (active, slot) in [(lab::A_ACTIVE, lab::A), (lab::B_ACTIVE, lab::B)] {
        for i in 0..D {
            builder
                .when(drg.clone() * (AB::Expr::ONE - v(active)))
                .assert_zero(v(slot + i));
            builder.when(expander_zero.clone()).assert_zero(v(slot + i));
        }
    }

    // The permutation: state plus the two slots.
    let mut fields: Vec<AB::Expr> = (0..W)
        .map(|i| {
            let absorbed = if i < D {
                v(lab::A + i)
            } else if i < 2 * D {
                v(lab::B + i - D)
            } else {
                AB::Expr::ZERO
            };
            v(lab::STATE + i) + absorbed
        })
        .collect();
    fields.extend((0..W).map(|i| v(lab::OUT + i)));
    builder.push_interaction(PERM, fields, Count::bounded(-live.clone(), 1));

    // Once per layer: the challenged node and the leaf's key.
    builder.push_interaction(
        PUB,
        [
            v(lab::G),
            AB::Expr::ZERO,
            v(lab::J),
            AB::Expr::ONE,
            v(lab::LEAF),
        ],
        Count::bounded(-first.clone(), 1),
    );
    builder.push_interaction(
        KEY,
        with_digest::<AB>(vec![v(lab::LEAF)], &local, lab::A),
        Count::bounded(-first, 1),
    );
    // Each parent slot: its node from `Pub`, its label from its column.
    let reads = drg + below;
    let a_slot = p(lab::P_A_SLOT);
    builder.push_interaction(
        PUB,
        [
            v(lab::G),
            a_slot.clone(),
            v(lab::A_NODE),
            v(lab::A_ACTIVE),
            v(lab::LEAF),
        ],
        Count::bounded(-reads.clone(), 1),
    );
    builder.push_interaction(
        PUB,
        [
            v(lab::G),
            a_slot + AB::Expr::ONE,
            v(lab::B_NODE),
            v(lab::B_ACTIVE),
            v(lab::LEAF),
        ],
        Count::bounded(-reads.clone(), 1),
    );
    let parent_layer = p(lab::P_LAYER) - p(lab::P_EXPANDER);
    for (node, active, slot) in [
        (lab::A_NODE, lab::A_ACTIVE, lab::A),
        (lab::B_NODE, lab::B_ACTIVE, lab::B),
    ] {
        builder.push_interaction(
            LABEL,
            with_digest::<AB>(
                vec![v(lab::LEAF), v(node), parent_layer.clone()],
                &local,
                slot,
            ),
            Count::bounded(-(reads.clone() * v(active)), 1),
        );
    }
    // The last block's output is the node's label on this layer: its column's.
    builder.push_interaction(
        LABEL,
        with_digest::<AB>(
            vec![v(lab::LEAF), v(lab::J), p(lab::P_LAYER)],
            &local,
            lab::OUT,
        ),
        Count::bounded(-(live * p(lab::P_LAST_BLOCK)), 1),
    );
}

fn eval_merkle<AB: InteractionBuilder<F = Val>>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice().to_vec();
    let next = main.next_slice().to_vec();
    let periodic = periodic_copies(builder, &local, mrk::WIDTH, mrk::PERIODIC);
    let p = |i: usize| -> AB::Expr { periodic[i].clone() };
    let v = |i: usize| -> AB::Expr { local[i].into() };
    let nv = |i: usize| -> AB::Expr { next[i].into() };

    for i in [
        mrk::IS_COLUMN,
        mrk::IS_PATH,
        mrk::ACTIVE,
        mrk::BIT,
        mrk::LIVE,
        mrk::OPEN,
    ] {
        builder.assert_bool(local[i]);
    }
    // A data or replica path reads slot 0; a column path's tree position is
    // its slot plus 2; an opening's path is a replica path, always active.
    builder.assert_zero((AB::Expr::ONE - v(mrk::IS_COLUMN)) * v(mrk::S));
    builder.assert_zero(v(mrk::IS_COLUMN) * (v(mrk::T) - v(mrk::S) - AB::Expr::TWO));
    builder
        .assert_zero((AB::Expr::ONE - v(mrk::IS_COLUMN)) * v(mrk::T) * (v(mrk::T) - AB::Expr::ONE));
    builder.assert_zero(v(mrk::OPEN) * v(mrk::IS_COLUMN));
    builder.assert_zero(v(mrk::OPEN) * (v(mrk::T) - AB::Expr::ONE));
    builder.assert_zero(v(mrk::OPEN) * (AB::Expr::ONE - v(mrk::ACTIVE)));
    builder.assert_eq(v(mrk::GATE), v(mrk::IS_PATH) * v(mrk::ACTIVE));

    // The path's identity holds over its block of rows.
    let within = builder.is_transition() * (AB::Expr::ONE - p(mrk::P_END));
    for i in [
        mrk::G,
        mrk::T,
        mrk::S,
        mrk::IS_COLUMN,
        mrk::IS_PATH,
        mrk::ACTIVE,
        mrk::LEAF,
        mrk::DEPTH,
        mrk::OPEN,
    ] {
        builder.when(within.clone()).assert_eq(nv(i), v(i));
    }
    // A path is live from level 0 for exactly its leaf's depth: live starts
    // at 1, never comes back, and its last live level is depth - 1.
    builder
        .when(v(mrk::IS_PATH) * p(mrk::P_FIRST))
        .assert_one(v(mrk::LIVE));
    builder
        .when(within.clone())
        .assert_zero(nv(mrk::LIVE) * (AB::Expr::ONE - v(mrk::LIVE)));
    // At a block's end the next row is another path's; `P_END` cuts it off.
    let ends = v(mrk::LIVE)
        * (p(mrk::P_END) + (AB::Expr::ONE - p(mrk::P_END)) * (AB::Expr::ONE - nv(mrk::LIVE)));
    builder.assert_eq(v(mrk::END), ends);
    builder
        .when(v(mrk::END))
        .assert_eq(p(mrk::P_LEVEL) + AB::Expr::ONE, v(mrk::DEPTH));

    // Each live level halves the index and hands its output up; the last has
    // index 0 above it.
    let chain = within * v(mrk::LIVE) * nv(mrk::LIVE);
    builder
        .when(chain.clone())
        .assert_eq(v(mrk::IDX), nv(mrk::IDX) * AB::Expr::TWO + v(mrk::BIT));
    builder
        .when(v(mrk::END))
        .assert_eq(v(mrk::IDX), v(mrk::BIT));
    for i in 0..D {
        builder
            .when(chain.clone())
            .assert_eq(nv(mrk::CUR + i), v(mrk::OUT + i));
    }

    let bit = v(mrk::BIT);
    let left: Vec<AB::Expr> = (0..D)
        .map(|i| v(mrk::CUR + i) + bit.clone() * (v(mrk::SIB + i) - v(mrk::CUR + i)))
        .collect();
    let right: Vec<AB::Expr> = (0..D)
        .map(|i| v(mrk::SIB + i) + bit.clone() * (v(mrk::CUR + i) - v(mrk::SIB + i)))
        .collect();
    let fields: Vec<AB::Expr> = compress_input::<AB>(left, right, Domain::Node)
        .into_iter()
        .chain((0..W).map(|i| v(mrk::OUT + i)))
        .collect();
    builder.push_interaction(
        PERM,
        fields,
        Count::bounded(-(v(mrk::GATE) * v(mrk::LIVE)), 1),
    );

    // The first level reads the leaf index (from `Pub` for a seal path, from
    // `OPub` for an opening), the leaf's depth, and the value from its
    // producer; the last live level sends the root to `Bind`.
    let starts = v(mrk::IS_PATH) * p(mrk::P_FIRST);
    builder.push_interaction(
        PUB,
        [
            v(mrk::G),
            v(mrk::S),
            v(mrk::IDX),
            v(mrk::ACTIVE),
            v(mrk::LEAF),
        ],
        Count::bounded(-(starts.clone() * (AB::Expr::ONE - v(mrk::OPEN))), 1),
    );
    builder.push_interaction(
        OPEN,
        [v(mrk::G), v(mrk::LEAF), v(mrk::IDX)],
        Count::bounded(-(starts.clone() * v(mrk::OPEN)), 1),
    );
    builder.push_interaction(
        DEPTH,
        [v(mrk::LEAF), v(mrk::DEPTH)],
        Count::bounded(-starts, 1),
    );
    builder.push_interaction(
        LEAF,
        with_digest::<AB>(vec![v(mrk::OPEN), v(mrk::G), v(mrk::T)], &local, mrk::CUR),
        Count::bounded(-(v(mrk::GATE) * p(mrk::P_FIRST)), 1),
    );
    // Trees: data 0, column 1, replica 2 (t = 1 → replica).
    let tree = v(mrk::IS_COLUMN) + (AB::Expr::ONE - v(mrk::IS_COLUMN)) * v(mrk::T) * AB::Expr::TWO;
    builder.push_interaction(
        ROOT,
        with_digest::<AB>(vec![v(mrk::LEAF), tree], &local, mrk::OUT),
        Count::bounded(v(mrk::GATE) * v(mrk::END), 1),
    );
}

fn eval_check<AB: InteractionBuilder<F = Val>>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice().to_vec();
    let v = |i: usize| -> AB::Expr { local[i].into() };
    builder.assert_bool(local[chk::ROW]);
    let row = v(chk::ROW);
    for i in 0..D {
        builder
            .when(row.clone())
            .assert_eq(v(chk::REPLICA + i), v(chk::DATA + i) + v(chk::LABEL + i));
    }
    builder.push_interaction(
        PUB,
        [
            v(chk::G),
            AB::Expr::ZERO,
            v(chk::J),
            AB::Expr::ONE,
            v(chk::LEAF),
        ],
        Count::bounded(-row.clone(), 1),
    );
    builder.push_interaction(
        LABEL,
        with_digest::<AB>(
            vec![
                v(chk::LEAF),
                v(chk::J),
                constant::<AB>(felt(LAYERS as u64 - 1)),
            ],
            &local,
            chk::LABEL,
        ),
        Count::bounded(-row.clone(), 1),
    );
    for (t, at) in [(0u64, chk::DATA), (1, chk::REPLICA)] {
        builder.push_interaction(
            LEAF,
            with_digest::<AB>(
                vec![AB::Expr::ZERO, v(chk::G), constant::<AB>(felt(t))],
                &local,
                at,
            ),
            Count::bounded(row.clone(), 1),
        );
    }
}

fn eval_bind<AB: InteractionBuilder<F = Val>>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice().to_vec();
    let periodic = periodic_copies(builder, &local, bnd::WIDTH, bnd::PERIODIC);
    let p = |i: usize| -> AB::Expr { periodic[i].clone() };
    let v = |i: usize| -> AB::Expr { local[i].into() };
    let live = p(bnd::P_LIVE);
    // The root-binding sponge: [tree, n, 0…] ‖ root, one block.
    let mut fields: Vec<AB::Expr> = Vec::with_capacity(2 * W);
    fields.push(p(bnd::P_TREE));
    fields.push(p(bnd::P_N));
    fields.extend((2..D).map(|_| AB::Expr::ZERO));
    fields.extend((0..D).map(|i| v(bnd::ROOT + i)));
    fields.push(constant::<AB>(hash::felt(Domain::Root as u32)));
    fields.push(constant::<AB>(hash::felt(2 * D as u32)));
    fields.extend((2 * D + 2..W).map(|_| AB::Expr::ZERO));
    fields.extend((0..W).map(|i| v(bnd::OUT + i)));
    builder.push_interaction(PERM, fields, Count::bounded(-live.clone(), 1));
    for i in 0..D {
        builder
            .when(live.clone())
            .assert_eq(v(bnd::OUT + i), p(bnd::P_COMMITMENT + i));
    }
    builder.push_interaction(
        ROOT,
        with_digest::<AB>(vec![p(bnd::P_LEAF), p(bnd::P_TREE)], &local, bnd::ROOT),
        Count::provided(-(live * p(bnd::P_PATHS))),
    );
}

fn eval_frames<AB: InteractionBuilder<F = Val>>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice().to_vec();
    let next = main.next_slice().to_vec();
    let periodic = periodic_copies(builder, &local, frm::WIDTH, frm::PERIODIC);
    let p = |i: usize| -> AB::Expr { periodic[i].clone() };
    let v = |i: usize| -> AB::Expr { local[i].into() };
    let nv = |i: usize| -> AB::Expr { next[i].into() };

    let live = p(frm::P_LIVE);
    let first = live.clone() * p(frm::P_FIRST);
    // Block 0 absorbs the header [frame, count, 0, …] in slot A; the sponge
    // starts from its IV, whose length is 8 × (1 + count).
    builder
        .when(first.clone())
        .assert_eq(v(frm::A), p(frm::P_FRAME));
    builder
        .when(first.clone())
        .assert_eq(v(frm::A + 1), p(frm::P_COUNT));
    for i in 2..D {
        builder.when(first.clone()).assert_zero(v(frm::A + i));
    }
    for i in 0..W {
        let iv = match i {
            16 => constant::<AB>(hash::felt(Domain::Openings as u32)),
            17 => (p(frm::P_COUNT) + AB::Expr::ONE) * constant::<AB>(felt(D as u64)),
            _ => AB::Expr::ZERO,
        };
        builder.when(first.clone()).assert_eq(v(frm::STATE + i), iv);
    }
    // Later blocks continue the frame's sponge; the last yields its root.
    let continues = live.clone() * (AB::Expr::ONE - p(frm::P_LAST));
    for i in 0..W {
        builder
            .when_transition()
            .when(continues.clone())
            .assert_eq(nv(frm::STATE + i), v(frm::OUT + i));
    }
    for i in 0..D {
        builder
            .when(live.clone() * p(frm::P_LAST))
            .assert_eq(v(frm::OUT + i), p(frm::P_ROOT + i));
    }
    // A slot that is neither the header nor an opened value is zero padding.
    let a_pad =
        live.clone() * (AB::Expr::ONE - p(frm::P_FIRST)) * (AB::Expr::ONE - p(frm::P_A_VALUE));
    let b_pad = live.clone() * (AB::Expr::ONE - p(frm::P_B_VALUE));
    for i in 0..D {
        builder.when(a_pad.clone()).assert_zero(v(frm::A + i));
        builder.when(b_pad.clone()).assert_zero(v(frm::B + i));
    }

    let mut fields: Vec<AB::Expr> = (0..W)
        .map(|i| {
            let absorbed = if i < D {
                v(frm::A + i)
            } else if i < 2 * D {
                v(frm::B + i - D)
            } else {
                AB::Expr::ZERO
            };
            v(frm::STATE + i) + absorbed
        })
        .collect();
    fields.extend((0..W).map(|i| v(frm::OUT + i)));
    builder.push_interaction(PERM, fields, Count::bounded(-live.clone(), 1));
    // Each opened value is the leaf its opening's path starts from.
    builder.push_interaction(
        LEAF,
        with_digest::<AB>(
            vec![AB::Expr::ONE, p(frm::P_A_ID), AB::Expr::ONE],
            &local,
            frm::A,
        ),
        Count::bounded(live.clone() * p(frm::P_A_VALUE), 1),
    );
    builder.push_interaction(
        LEAF,
        with_digest::<AB>(
            vec![AB::Expr::ONE, p(frm::P_B_ID), AB::Expr::ONE],
            &local,
            frm::B,
        ),
        Count::bounded(live * p(frm::P_B_VALUE), 1),
    );
}

// ── The witness ──────────────────────────────────────────────────────────────

struct Traces {
    perm: Vec<[Val; W]>,
    column: RowMajorMatrix<Val>,
    label: RowMajorMatrix<Val>,
    merkle: RowMajorMatrix<Val>,
    check: RowMajorMatrix<Val>,
    bind: RowMajorMatrix<Val>,
    frames: RowMajorMatrix<Val>,
}

fn digest(node: &[u8; 32]) -> Result<Digest, String> {
    hash::from_bytes(node).ok_or_else(|| "a non-canonical node in the witness".to_string())
}

/// Every permutation a row queries, so the permutation table can provide
/// each.
struct Perms(Vec<[Val; W]>);

impl Perms {
    fn run(&mut self, input: [Val; W]) -> [Val; W] {
        let mut out = input;
        hash::permute(&mut out);
        self.0.push(input);
        out
    }
}

fn compress_state(left: &Digest, right: &Digest, domain: Domain) -> [Val; W] {
    let mut state = [Val::ZERO; W];
    state[..D].copy_from_slice(left);
    state[D..2 * D].copy_from_slice(right);
    state[2 * D] = hash::felt(domain as u32);
    state
}

/// A slot's opened column: its labels on every layer and its path.
struct SlotColumn {
    labels: Vec<Digest>,
    path: Vec<Digest>,
}

/// One path the Merkle table proves: its row block's identity, its leaf
/// value and siblings.
struct PathWitness {
    id: usize,
    t: usize,
    s: usize,
    open: bool,
    leaf: usize,
    index: u64,
    active: bool,
    value: Digest,
    path: Vec<Digest>,
}

fn build(public: &Public, seals: &[&SealProof], openings: &[Opened]) -> Result<Traces, String> {
    // Sealed leaves come first; they alone register a data commitment.
    let sealed = public
        .leaves
        .iter()
        .filter(|l| l.commitments[0].is_some())
        .count();
    if seals.len() != sealed {
        return Err(format!("{} seal proofs for {sealed} seals", seals.len()));
    }
    if openings.len() != public.openings.len() {
        return Err(format!(
            "{} openings for {} expected",
            openings.len(),
            public.openings.len()
        ));
    }
    let heights = public.heights();
    let total = public.challenges();
    let mut perms = Perms(Vec::with_capacity(public.permutations()));

    // Per global challenge: its opening and its slots' columns.
    let mut seal_openings = Vec::with_capacity(total);
    let mut columns: Vec<[Option<SlotColumn>; SLOTS]> = Vec::with_capacity(total);
    for (l, (leaf, seal)) in public.leaves[..sealed].iter().zip(seals).enumerate() {
        if seal.openings.len() != leaf.challenges.len() {
            return Err(format!(
                "leaf {l}: {} openings for {} challenges",
                seal.openings.len(),
                leaf.challenges.len()
            ));
        }
        for (k, opening) in seal.openings.iter().enumerate() {
            let read = |c: &storage_proof::ColumnOpening| -> Result<SlotColumn, String> {
                Ok(SlotColumn {
                    labels: c.labels.iter().map(digest).collect::<Result<_, _>>()?,
                    path: c.path.iter().map(digest).collect::<Result<_, _>>()?,
                })
            };
            let mut slot_columns: [Option<SlotColumn>; SLOTS] = Default::default();
            slot_columns[0] = Some(read(&opening.column)?);
            let parents: Vec<usize> = if leaf.slots[k][1].1 {
                (1..SLOTS).collect()
            } else {
                (1 + DRG..SLOTS).collect()
            };
            if opening.parents.len() != parents.len() {
                return Err(format!(
                    "leaf {l} challenge {k}: {} parent columns, {} expected",
                    opening.parents.len(),
                    parents.len()
                ));
            }
            for (slot, parent) in parents.into_iter().zip(&opening.parents) {
                slot_columns[slot] = Some(read(parent)?);
            }
            if slot_columns
                .iter()
                .flatten()
                .any(|c| c.labels.len() != LAYERS || c.path.len() != leaf.depth)
            {
                return Err(format!(
                    "leaf {l} challenge {k}: a column of the wrong shape"
                ));
            }
            seal_openings.push(opening);
            columns.push(slot_columns);
        }
    }

    // LABEL demand per (leaf, node, layer): what label rows and check rows read.
    let mut demand: std::collections::HashMap<(usize, u64, usize), u32> =
        std::collections::HashMap::new();
    for g in 0..total {
        let (l, k, leaf) = public.challenge(g);
        let j = leaf.challenges[k];
        for layer in 0..LAYERS {
            for s in 1..SLOTS {
                let (node, open) = leaf.slots[k][s];
                if if s <= DRG { open } else { layer >= 1 } {
                    let at = if s <= DRG { layer } else { layer - 1 };
                    *demand.entry((l, node, at)).or_default() += 1;
                }
            }
            *demand.entry((l, j, layer)).or_default() += 1;
        }
        *demand.entry((l, j, LAYERS - 1)).or_default() += 1;
    }

    // Column table.
    let mut column = RowMajorMatrix::new(vec![Val::ZERO; heights[3] * col::WIDTH], col::WIDTH);
    let mut seal_leaves: Vec<[Option<Digest>; PATHS]> = vec![Default::default(); total];
    for g in 0..total {
        let (l, k, leaf) = public.challenge(g);
        for s in 0..SLOTS {
            let instance = g * SLOTS + s;
            let (node, active) = leaf.slots[k][s];
            let mut acc = hash::ZERO;
            for layer in 0..COLUMN_ROWS {
                let row = &mut column.values[(instance * COLUMN_ROWS + layer) * col::WIDTH..]
                    [..col::WIDTH];
                row[col::G] = felt(g as u64);
                row[col::S] = felt(s as u64);
                row[col::NODE] = felt(node);
                row[col::ACTIVE] = Val::from_bool(active);
                row[col::INSTANCE] = Val::ONE;
                row[col::LEAF] = felt(l as u64);
                if !active || layer >= LAYERS {
                    continue;
                }
                let label = columns[g][s]
                    .as_ref()
                    .expect("an open slot has a column")
                    .labels[layer];
                let out = perms.run(compress_state(&acc, &label, Domain::Column));
                row[col::ACC..col::ACC + D].copy_from_slice(&acc);
                row[col::LABEL..col::LABEL + D].copy_from_slice(&label);
                row[col::OUT..col::OUT + W].copy_from_slice(&out);
                if let Some(m) = demand.remove(&(l, node, layer)) {
                    row[col::MULT] = hash::felt(m);
                }
                acc.copy_from_slice(&out[..D]);
            }
            if active {
                seal_leaves[g][2 + s] = Some(acc);
            }
        }
    }
    if !demand.is_empty() {
        return Err("a label the statement reads has no opened column".into());
    }

    // Label table: real challenges, then padding ones that read nothing.
    let mut label = RowMajorMatrix::new(vec![Val::ZERO; heights[4] * lab::WIDTH], lab::WIDTH);
    let mut last_labels = vec![hash::ZERO; total];
    for g in 0..heights[4] / LABEL_ROWS {
        for r in 0..LABEL_ROWS {
            label.values[(g * LABEL_ROWS + r) * lab::WIDTH + lab::G] = felt(g as u64);
        }
        if g >= total {
            continue;
        }
        let (l, k, leaf) = public.challenge(g);
        let j = leaf.challenges[k];
        for layer in 0..16 {
            let mut state = [Val::ZERO; W];
            state[16] = hash::felt(Domain::Label as u32);
            state[17] = hash::felt(LABEL_LENGTH);
            for block in 0..LABEL_BLOCKS {
                let row = &mut label.values
                    [((g * 16 + layer) * LABEL_BLOCKS + block) * lab::WIDTH..][..lab::WIDTH];
                row[lab::J] = felt(j);
                row[lab::LEAF] = felt(l as u64);
                row[lab::REAL] = Val::ONE;
                if layer >= LAYERS {
                    continue;
                }
                let (a, b): (Digest, Digest);
                if block == 0 {
                    let mut header = hash::ZERO;
                    header[0] = felt(layer as u64);
                    header[1] = felt(j);
                    (a, b) = (leaf.key, header);
                } else {
                    let slot_digest = |s: usize| -> Digest {
                        let (_, open) = leaf.slots[k][s];
                        if !(if s <= DRG { open } else { layer >= 1 }) {
                            return hash::ZERO;
                        }
                        let at = if s <= DRG { layer } else { layer - 1 };
                        columns[g][s]
                            .as_ref()
                            .expect("an open slot has a column")
                            .labels[at]
                    };
                    let (sa, sb) = (2 * block - 1, 2 * block);
                    row[lab::A_NODE] = felt(leaf.slots[k][sa].0);
                    row[lab::A_ACTIVE] = Val::from_bool(leaf.slots[k][sa].1);
                    row[lab::B_NODE] = felt(leaf.slots[k][sb].0);
                    row[lab::B_ACTIVE] = Val::from_bool(leaf.slots[k][sb].1);
                    (a, b) = (slot_digest(sa), slot_digest(sb));
                }
                row[lab::A..lab::A + D].copy_from_slice(&a);
                row[lab::B..lab::B + D].copy_from_slice(&b);
                row[lab::STATE..lab::STATE + W].copy_from_slice(&state);
                let mut input = state;
                for i in 0..D {
                    input[i] += a[i];
                    input[D + i] += b[i];
                }
                state = perms.run(input);
                row[lab::OUT..lab::OUT + W].copy_from_slice(&state);
            }
            if layer == LAYERS - 1 {
                last_labels[g].copy_from_slice(&state[..D]);
            }
        }
    }

    // Check table and the data and replica leaves.
    let mut check = RowMajorMatrix::new(vec![Val::ZERO; heights[6] * chk::WIDTH], chk::WIDTH);
    let mut data_paths = Vec::with_capacity(total);
    for (g, opening) in seal_openings.iter().enumerate() {
        let (l, k, leaf) = public.challenge(g);
        let (data, replica) = (digest(&opening.data)?, digest(&opening.replica)?);
        let row = &mut check.values[g * chk::WIDTH..][..chk::WIDTH];
        row[chk::G] = felt(g as u64);
        row[chk::J] = felt(leaf.challenges[k]);
        row[chk::LEAF] = felt(l as u64);
        row[chk::DATA..chk::DATA + D].copy_from_slice(&data);
        row[chk::LABEL..chk::LABEL + D].copy_from_slice(&last_labels[g]);
        row[chk::REPLICA..chk::REPLICA + D].copy_from_slice(&replica);
        row[chk::ROW] = Val::ONE;
        seal_leaves[g][0] = Some(data);
        seal_leaves[g][1] = Some(replica);
        let path = |nodes: &[[u8; 32]]| -> Result<Vec<Digest>, String> {
            nodes.iter().map(digest).collect()
        };
        data_paths.push((path(&opening.data_path)?, path(&opening.replica_path)?));
    }

    // Frames table: each frame's sponge over its header and opened values.
    let mut frames = RowMajorMatrix::new(vec![Val::ZERO; heights[9] * frm::WIDTH], frm::WIDTH);
    let opened_values: Vec<Digest> = openings
        .iter()
        .map(|o| digest(&o.value))
        .collect::<Result<_, _>>()?;
    let mut state = [Val::ZERO; W];
    for (row_index, block) in public.blocks.iter().enumerate() {
        if block.first {
            state = [Val::ZERO; W];
            state[16] = hash::felt(Domain::Openings as u32);
            state[17] = felt((1 + block.count) * D as u64);
        }
        let a = if block.first {
            let mut header = hash::ZERO;
            header[0] = felt(block.frame_number);
            header[1] = felt(block.count);
            header
        } else {
            block.a.map_or(hash::ZERO, |o| opened_values[o])
        };
        let b = block.b.map_or(hash::ZERO, |o| opened_values[o]);
        let row = &mut frames.values[row_index * frm::WIDTH..][..frm::WIDTH];
        row[frm::A..frm::A + D].copy_from_slice(&a);
        row[frm::B..frm::B + D].copy_from_slice(&b);
        row[frm::STATE..frm::STATE + W].copy_from_slice(&state);
        let mut input = state;
        for i in 0..D {
            input[i] += a[i];
            input[D + i] += b[i];
        }
        state = perms.run(input);
        row[frm::OUT..frm::OUT + W].copy_from_slice(&state);
        if block.last && state[..D] != block.root[..] {
            return Err(format!(
                "frame {}: the opened values do not hash to the committed root",
                block.frame_number
            ));
        }
    }

    // Merkle table: every seal path, then every opening's.
    let mut paths: Vec<PathWitness> = Vec::with_capacity(total * PATHS + openings.len());
    for g in 0..total {
        let (l, k, leaf) = public.challenge(g);
        for t in 0..PATHS {
            let s = t.saturating_sub(2);
            let (index, active) = leaf.slots[k][s];
            let path = match t {
                0 => data_paths[g].0.clone(),
                1 => data_paths[g].1.clone(),
                _ => columns[g][s]
                    .as_ref()
                    .map_or(Vec::new(), |c| c.path.clone()),
            };
            paths.push(PathWitness {
                id: g,
                t,
                s,
                open: false,
                leaf: l,
                index,
                active,
                value: seal_leaves[g][t].unwrap_or(hash::ZERO),
                path,
            });
        }
    }
    for (o, (opening, witness)) in public.openings.iter().zip(openings).enumerate() {
        let path = witness
            .path
            .iter()
            .map(digest)
            .collect::<Result<Vec<_>, _>>()?;
        if path.len() != public.leaves[opening.leaf].depth {
            return Err(format!("opening {o}: a path of the wrong depth"));
        }
        paths.push(PathWitness {
            id: o,
            t: 1,
            s: 0,
            open: true,
            leaf: opening.leaf,
            index: opening.index,
            active: true,
            value: opened_values[o],
            path,
        });
    }
    let path_rows = public.path_rows();
    let mut merkle = RowMajorMatrix::new(vec![Val::ZERO; heights[5] * mrk::WIDTH], mrk::WIDTH);
    let mut roots: Vec<[Option<Digest>; 3]> = vec![[None; 3]; public.leaves.len()];
    for (block, witness) in paths.iter().enumerate() {
        let leaf = &public.leaves[witness.leaf];
        let mut cur = witness.value;
        let mut idx = witness.index;
        for level in 0..path_rows {
            let row = &mut merkle.values[(block * path_rows + level) * mrk::WIDTH..][..mrk::WIDTH];
            let live = level < leaf.depth;
            row[mrk::G] = felt(witness.id as u64);
            row[mrk::T] = felt(witness.t as u64);
            row[mrk::S] = felt(witness.s as u64);
            row[mrk::IS_COLUMN] = Val::from_bool(witness.t >= 2);
            row[mrk::IS_PATH] = Val::ONE;
            row[mrk::ACTIVE] = Val::from_bool(witness.active);
            row[mrk::LEAF] = felt(witness.leaf as u64);
            row[mrk::DEPTH] = felt(leaf.depth as u64);
            row[mrk::LIVE] = Val::from_bool(live);
            row[mrk::END] = Val::from_bool(level + 1 == leaf.depth);
            row[mrk::GATE] = Val::from_bool(witness.active);
            row[mrk::OPEN] = Val::from_bool(witness.open);
            row[mrk::IDX] = felt(idx);
            if !live {
                continue;
            }
            let bit = idx & 1;
            row[mrk::BIT] = felt(bit);
            row[mrk::CUR..mrk::CUR + D].copy_from_slice(&cur);
            idx >>= 1;
            if !witness.active {
                continue;
            }
            let sib = witness.path[level];
            row[mrk::SIB..mrk::SIB + D].copy_from_slice(&sib);
            let (left, right) = if bit == 0 { (cur, sib) } else { (sib, cur) };
            let out = perms.run(compress_state(&left, &right, Domain::Node));
            row[mrk::OUT..mrk::OUT + W].copy_from_slice(&out);
            cur.copy_from_slice(&out[..D]);
        }
        if witness.active {
            let tree = match witness.t {
                0 => Tree::Data,
                1 => Tree::Replica,
                _ => Tree::Column,
            } as usize;
            match roots[witness.leaf][tree] {
                None => roots[witness.leaf][tree] = Some(cur),
                Some(root) if root != cur => {
                    return Err(format!(
                        "leaf {}: a path reaches another root of tree {tree}",
                        witness.leaf
                    ))
                }
                Some(_) => {}
            }
        }
    }

    // Bind table.
    let mut bind = RowMajorMatrix::new(vec![Val::ZERO; heights[7] * bnd::WIDTH], bnd::WIDTH);
    for (l, leaf) in public.leaves.iter().enumerate() {
        for tree in 0..3 {
            if leaf.commitments[tree].is_none() {
                continue;
            }
            let root = roots[l][tree].ok_or("a tree without an opened path")?;
            let mut state = [Val::ZERO; W];
            state[0] = felt(tree as u64);
            state[1] = felt(leaf.n);
            state[D..2 * D].copy_from_slice(&root);
            state[16] = hash::felt(Domain::Root as u32);
            state[17] = hash::felt(2 * D as u32);
            let out = perms.run(state);
            let row = &mut bind.values[(3 * l + tree) * bnd::WIDTH..][..bnd::WIDTH];
            row[bnd::ROOT..bnd::ROOT + D].copy_from_slice(&root);
            row[bnd::OUT..bnd::OUT + W].copy_from_slice(&out);
        }
    }

    Ok(Traces {
        perm: perms.0,
        column,
        label,
        merkle,
        check,
        bind,
        frames,
    })
}

fn perm_trace(inputs: &[[Val; W]], height: usize) -> RowMajorMatrix<Val> {
    use p3_maybe_rayon::prelude::*;
    let mut trace = RowMajorMatrix::new(vec![Val::ZERO; height * PERM_WIDTH], PERM_WIDTH);
    trace
        .values
        .par_chunks_exact_mut(PERM_WIDTH)
        .enumerate()
        .for_each(|(i, row)| {
            let _ = poseidon::fill(row, inputs.get(i).copied().unwrap_or([Val::ZERO; W]));
            row[poseidon::NUM_COLS] = Val::from_bool(i < inputs.len());
        });
    trace
}

// ── Proving and verifying ───────────────────────────────────────────────────

/// A member's epoch proof: its seals (`seals[i]` proving
/// `statement.seals[i]`) and the openings it committed (`openings` in the
/// statement's order: frame, held registration, query).
pub fn prove_epoch(
    statement: &EpochStatement,
    params: &SdrParams,
    seals: &[&SealProof],
    openings: &[Opened],
) -> Result<Vec<u8>, String> {
    prove_with(statement, params, seals, openings, &mut |_, _| {})
}

/// [`prove_epoch`], letting `tamper` edit each table's finished trace (by
/// table index, `Perm` = 0 … `Frames` = 9) first: what a dishonest prover
/// controls.
pub(crate) fn prove_with(
    statement: &EpochStatement,
    params: &SdrParams,
    seals: &[&SealProof],
    openings: &[Opened],
    tamper: &mut dyn FnMut(usize, &mut RowMajorMatrix<Val>),
) -> Result<Vec<u8>, String> {
    let public = Public::new(statement, params)?;
    let traces = build(&public, seals, openings)?;
    let heights = public.heights();
    let perm = perm_trace(&traces.perm, heights[0]);
    let zero =
        |rows: usize, width: usize| RowMajorMatrix::new(vec![Val::ZERO; rows * width], width);
    let pub_trace = zero(heights[1], pubc::WIDTH);
    let leaves_trace = zero(heights[2], lvs::WIDTH);
    let opub_trace = zero(heights[8], opb::WIDTH);
    let airs = SealAir::tables(&public);
    let transcript = public.transcript_values();
    let traces: Vec<RowMajorMatrix<Val>> = [
        &perm,
        &pub_trace,
        &leaves_trace,
        &traces.column,
        &traces.label,
        &traces.merkle,
        &traces.check,
        &traces.bind,
        &opub_trace,
        &traces.frames,
    ]
    .into_iter()
    .zip(&airs)
    .enumerate()
    .map(|(table, (trace, air))| {
        let mut trace = air.with_periodic_copies(trace);
        tamper(table, &mut trace);
        trace
    })
    .collect();
    let config = config();
    let instances: Vec<StarkInstance<'_, Config, SealAir>> = airs
        .iter()
        .zip(&traces)
        .enumerate()
        .map(|(i, (air, trace))| StarkInstance {
            air,
            trace,
            public_values: if i == 0 {
                transcript.clone()
            } else {
                Vec::new()
            },
        })
        .collect();
    let prover_data =
        ProverData::from_instances(&config, &instances).map_err(|e| format!("{e:?}"))?;
    let proof = prove_batch(&config, &instances, &prover_data).map_err(|e| format!("{e:?}"))?;
    postcard::to_allocvec(&proof).map_err(|e| e.to_string())
}

/// Check a member's epoch proof against its statement.
pub fn verify_epoch(
    statement: &EpochStatement,
    params: &SdrParams,
    bytes: &[u8],
) -> Result<(), String> {
    let public = Public::new(statement, params)?;
    let proof: BatchProof<Config> = postcard::from_bytes(bytes).map_err(|e| e.to_string())?;
    let airs = SealAir::tables(&public);
    let degree_bits: Vec<usize> = public
        .heights()
        .iter()
        .map(|h| h.trailing_zeros() as usize)
        .collect();
    let config = config();
    let common = ProverData::from_airs_and_degrees(&config, &airs, &degree_bits)
        .map_err(|e| format!("{e:?}"))?
        .common;
    let mut public_values = vec![Vec::new(); airs.len()];
    public_values[0] = public.transcript_values();
    verify_batch(&config, &airs, &proof, &public_values, &common).map_err(|e| format!("{e:?}"))
}

fn seals_only<'a>(statements: &[SealStatement<'a>], count: usize) -> EpochStatement<'a> {
    EpochStatement {
        seals: statements.to_vec(),
        count,
        held: Vec::new(),
        frames: Vec::new(),
        queries: 0,
    }
}

/// One proof of several seals, no openings.
pub fn prove_many(
    statements: &[SealStatement],
    params: &SdrParams,
    count: usize,
    seals: &[&SealProof],
) -> Result<Vec<u8>, String> {
    prove_epoch(&seals_only(statements, count), params, seals, &[])
}

/// Check [`prove_many`]'s proof.
pub fn verify_many(
    statements: &[SealStatement],
    params: &SdrParams,
    count: usize,
    bytes: &[u8],
) -> Result<(), String> {
    verify_epoch(&seals_only(statements, count), params, bytes)
}

/// A proof of one seal.
pub fn prove(
    statement: &SealStatement,
    params: &SdrParams,
    count: usize,
    seal: &SealProof,
) -> Result<Vec<u8>, String> {
    prove_many(std::slice::from_ref(statement), params, count, &[seal])
}

/// Check [`prove`]'s proof.
pub fn verify(
    statement: &SealStatement,
    params: &SdrParams,
    count: usize,
    bytes: &[u8],
) -> Result<(), String> {
    verify_many(std::slice::from_ref(statement), params, count, bytes)
}

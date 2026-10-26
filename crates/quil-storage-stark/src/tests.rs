use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use quil_crypto::sdr::{self, SdrParams};
use quil_crypto::storage_proof::{self, encode_leaf, prove_seal, Registered, SealProof, SealStatement};

use crate::config::Val;
use crate::seal::{self, EpochStatement, FrameOpenings, Held, Opened};

const EPOCH: u64 = 4;
const QUERIES: u32 = 2;

fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed)).collect()
}

/// One member's encoded leaf.
struct Fixture {
    member: Vec<u8>,
    leaf: Vec<u8>,
    epoch: u64,
    encoded: storage_proof::EncodedLeaf,
}

impl Fixture {
    fn new(bytes: usize) -> Self {
        Self::of(b"leaf-stark", bytes, 3)
    }

    fn of(leaf: &[u8], bytes: usize, seed: u8) -> Self {
        Self::at(leaf, EPOCH, bytes, seed)
    }

    fn at(leaf: &[u8], epoch: u64, bytes: usize, seed: u8) -> Self {
        let member = vec![7u8; 32];
        let encoded = encode_leaf(&data(bytes, seed), &sdr::replica_key(&member, leaf, epoch), &SdrParams::default());
        Self { member, leaf: leaf.to_vec(), epoch, encoded }
    }

    fn statement<'a>(&'a self, beacon: &'a [u8]) -> SealStatement<'a> {
        SealStatement {
            member: &self.member,
            leaf_id: &self.leaf,
            epoch: self.epoch,
            n: self.encoded.n,
            registered: Registered {
                comm_d: self.encoded.comm_d,
                comm_c: self.encoded.comm_c,
                comm_r: self.encoded.comm_r,
            },
            beacon,
        }
    }

    fn seal(&self, statement: &SealStatement, count: usize) -> SealProof {
        prove_seal(&self.encoded.replica, statement, &SdrParams::default(), count).unwrap()
    }

    fn held(&self) -> Held<'_> {
        Held { member: &self.member, leaf_id: &self.leaf, epoch: self.epoch, n: self.encoded.n, comm_r: self.encoded.comm_r }
    }

    /// This member's opening of `query` at beacon `rho`.
    fn open(&self, query: u32, rho: &[u8]) -> Opened {
        let opening = storage_proof::build_opening(
            &self.encoded.replica,
            &self.encoded.replica_cap,
            &self.encoded.registration_root(),
            &self.leaf,
            self.epoch,
            &self.member,
            query,
            rho,
        )
        .unwrap();
        Opened {
            value: opening.value.try_into().unwrap(),
            path: opening.path_commits.into_iter().map(|node| node.try_into().unwrap()).collect(),
        }
    }
}

/// A member's epoch: leaves it seals for the next epoch, registrations it
/// holds, and the frames it proposed (each opening some held registrations).
struct Epoch {
    sealed: Vec<Fixture>,
    held: Vec<Fixture>,
    frames: Vec<(u64, Vec<u8>, Vec<usize>)>,
    count: usize,
}

impl Epoch {
    fn new() -> Self {
        Self {
            sealed: vec![Fixture::of(b"leaf-a", 200 * 30, 1), Fixture::of(b"leaf-b", 70 * 30, 2)],
            held: vec![Fixture::at(b"leaf-a", EPOCH - 1, 150 * 30, 4), Fixture::at(b"leaf-c", EPOCH - 1, 600 * 30, 5)],
            frames: vec![(11, b"rho-11".to_vec(), vec![0]), (12, b"rho-12".to_vec(), vec![0, 1]), (15, b"rho-15".to_vec(), vec![1])],
            count: 8,
        }
    }

    fn openings(&self) -> (Vec<FrameOpenings<'_>>, Vec<Opened>) {
        let mut opened = Vec::new();
        let frames = self
            .frames
            .iter()
            .map(|(number, rho, held)| {
                let values: Vec<Opened> =
                    held.iter().flat_map(|&h| (0..QUERIES).map(move |q| (h, q))).map(|(h, q)| self.held[h].open(q, rho)).collect();
                let root = storage_proof::openings_root(*number, &values.iter().map(|o| o.value).collect::<Vec<_>>()).unwrap();
                opened.extend(values);
                FrameOpenings { frame_number: *number, rho_n: rho, root, held: held.clone() }
            })
            .collect();
        (frames, opened)
    }

    fn statement(&self) -> (EpochStatement<'_>, Vec<SealProof>, Vec<Opened>) {
        let seals: Vec<SealStatement> = self.sealed.iter().map(|f| f.statement(b"beacon")).collect();
        let plain: Vec<SealProof> = self.sealed.iter().zip(&seals).map(|(f, s)| f.seal(s, self.count)).collect();
        let (frames, opened) = self.openings();
        let statement = EpochStatement {
            seals,
            count: self.count,
            held: self.held.iter().map(Fixture::held).collect(),
            frames,
            queries: QUERIES,
        };
        (statement, plain, opened)
    }
}

#[test]
fn an_honest_seal_proves_and_verifies() {
    let fixture = Fixture::new(300 * 30 + 7);
    let params = SdrParams::default();
    let statement = fixture.statement(b"beacon");
    let plain = fixture.seal(&statement, 16);
    let started = std::time::Instant::now();
    let proof = seal::prove(&statement, &params, 16, &plain).unwrap();
    let proving = started.elapsed();
    let started = std::time::Instant::now();
    assert_eq!(seal::verify(&statement, &params, 16, &proof), Ok(()));
    eprintln!("16 challenges, n = {}: prove {proving:?}, verify {:?}, {} bytes (plain seal {} bytes)",
        fixture.encoded.n, started.elapsed(), proof.len(), plain.to_bytes().len());
    // Another beacon is another statement.
    assert!(seal::verify(&fixture.statement(b"other beacon"), &params, 16, &proof).is_err());
    // A flipped byte does not verify.
    let mut tampered = proof.clone();
    let at = tampered.len() / 2;
    tampered[at] ^= 1;
    assert!(seal::verify(&statement, &params, 16, &tampered).is_err());
}

/// Three leaves of different depths in one proof: it verifies for exactly
/// those statements, in that order.
#[test]
fn one_proof_covers_several_leaves() {
    let params = SdrParams::default();
    let fixtures = [Fixture::of(b"leaf-a", 300 * 30, 1), Fixture::of(b"leaf-b", 40 * 30, 2), Fixture::of(b"leaf-c", 1100 * 30, 3)];
    let beacons: [&[u8]; 3] = [b"beacon-a", b"beacon-b", b"beacon-c"];
    let statements: Vec<SealStatement> = fixtures.iter().zip(beacons).map(|(f, b)| f.statement(b)).collect();
    let seals: Vec<SealProof> = fixtures.iter().zip(&statements).map(|(f, s)| f.seal(s, 8)).collect();
    let refs: Vec<&SealProof> = seals.iter().collect();
    let proof = seal::prove_many(&statements, &params, 8, &refs).unwrap();
    assert_eq!(seal::verify_many(&statements, &params, 8, &proof), Ok(()));
    let reordered = vec![statements[1], statements[0], statements[2]];
    assert!(seal::verify_many(&reordered, &params, 8, &proof).is_err(), "another order");
    assert!(seal::verify_many(&statements[..2], &params, 8, &proof).is_err(), "a leaf left out");
    let mut altered = statements.clone();
    altered[2].beacon = b"beacon-x";
    assert!(seal::verify_many(&altered, &params, 8, &proof).is_err(), "another beacon for one leaf");
    // Proving a statement with another leaf's seal fails before any proof.
    let swapped: Vec<&SealProof> = vec![&seals[1], &seals[0], &seals[2]];
    assert!(seal::prove_many(&statements, &params, 8, &swapped).is_err());
}

/// Seals and the openings of three committed frames in one proof.
#[test]
fn one_proof_covers_an_epochs_seals_and_openings() {
    let params = SdrParams::default();
    let epoch = Epoch::new();
    let (statement, plain, opened) = epoch.statement();
    let refs: Vec<&SealProof> = plain.iter().collect();
    let proof = seal::prove_epoch(&statement, &params, &refs, &opened).unwrap();
    assert_eq!(seal::verify_epoch(&statement, &params, &proof), Ok(()));

    let mut other_root = statement.clone();
    other_root.frames[1].root = statement.frames[0].root;
    assert!(seal::verify_epoch(&other_root, &params, &proof).is_err(), "another committed root");
    let mut fewer = statement.clone();
    fewer.frames.pop();
    assert!(seal::verify_epoch(&fewer, &params, &proof).is_err(), "a frame left out");
    let mut other_held = statement.clone();
    other_held.frames[0].held = vec![1];
    assert!(seal::verify_epoch(&other_held, &params, &proof).is_err(), "another registration opened");

    // A committed root the values do not hash to cannot be proven.
    let mut wrong = statement.clone();
    wrong.frames[2].root = statement.frames[0].root;
    assert!(seal::prove_epoch(&wrong, &params, &refs, &opened).is_err());
    // Nor can a value other than the replica's.
    let mut forged = opened.clone();
    forged[0].value = forged[1].value;
    assert!(seal::prove_epoch(&statement, &params, &refs, &forged).is_err());
}

/// A member that seals nothing this epoch still proves its openings.
#[test]
fn an_epoch_of_openings_alone_proves() {
    let params = SdrParams::default();
    let epoch = Epoch::new();
    let (mut statement, _, opened) = epoch.statement();
    statement.seals.clear();
    let proof = seal::prove_epoch(&statement, &params, &[], &opened).unwrap();
    assert_eq!(seal::verify_epoch(&statement, &params, &proof), Ok(()));
}

/// A dishonest prover edits the traces before proving. However the prover
/// reacts (a debug build checks its own constraints and panics; a release
/// build emits a proof), no proof it produces may verify.
fn rejected(table: usize, tamper: impl Fn(&mut RowMajorMatrix<Val>) + std::panic::RefUnwindSafe) {
    let params = SdrParams::default();
    let epoch = Epoch::new();
    let (statement, plain, opened) = epoch.statement();
    let refs: Vec<&SealProof> = plain.iter().collect();
    let outcome = std::panic::catch_unwind(|| {
        seal::prove_with(&statement, &params, &refs, &opened, &mut |t, trace| {
            if t == table {
                tamper(trace)
            }
        })
    });
    match outcome {
        Ok(Ok(proof)) => {
            let verdict = seal::verify_epoch(&statement, &params, &proof);
            eprintln!("tamper table {table}: proof made, verifier says {verdict:?}");
            assert!(verdict.is_err(), "a tampered table {table} verified");
        }
        Ok(Err(error)) => eprintln!("tamper table {table}: prover refused: {error}"),
        Err(_) => eprintln!("tamper table {table}: prover panicked (debug constraint check)"),
    }
}

fn cell(trace: &mut RowMajorMatrix<Val>, row: usize, col: usize) -> &mut Val {
    let width = trace.width;
    &mut trace.values[row * width + col]
}

fn bump(value: &mut Val) {
    *value += Val::ONE;
}

const PERM: usize = 0;
const PUB: usize = 1;
const LEAVES: usize = 2;
const COLUMN: usize = 3;
const LABEL: usize = 4;
const MERKLE: usize = 5;
const CHECK: usize = 6;
const OPUB: usize = 8;
const FRAMES: usize = 9;

#[test]
fn a_parent_label_other_than_its_columns_is_rejected() {
    // Challenge 0, layer 2, block 1: the first DRG parent's label.
    rejected(LABEL, |t| bump(cell(t, 2 * 8 + 1, seal::lab::A)));
}

#[test]
fn a_parent_other_than_the_graphs_is_rejected() {
    rejected(LABEL, |t| bump(cell(t, 3 * 8 + 4, seal::lab::A_NODE)));
}

#[test]
fn a_skipped_parent_is_rejected() {
    // Pretend an expander parent is absent: inactive, zero slot.
    rejected(LABEL, |t| {
        let row = 5 * 8 + 5;
        *cell(t, row, seal::lab::A_ACTIVE) = Val::ZERO;
        for i in 0..8 {
            *cell(t, row, seal::lab::A + i) = Val::ZERO;
        }
    });
}

#[test]
fn a_label_under_another_leafs_key_is_rejected() {
    // Every row of challenge 0 claims leaf 1 (whose key differs).
    rejected(LABEL, |t| {
        for row in 0..128 {
            *cell(t, row, seal::lab::LEAF) = Val::ONE;
        }
    });
}

#[test]
fn a_column_label_other_than_committed_is_rejected() {
    rejected(COLUMN, |t| bump(cell(t, 3, seal::col::LABEL)));
}

#[test]
fn a_replica_node_other_than_data_plus_label_is_rejected() {
    rejected(CHECK, |t| bump(cell(t, 0, seal::chk::REPLICA)));
}

#[test]
fn a_sibling_off_the_registered_tree_is_rejected() {
    rejected(MERKLE, |t| bump(cell(t, 1, seal::mrk::SIB)));
}

#[test]
fn a_path_of_another_depth_is_rejected() {
    // Path 0 claims to end one level early.
    rejected(MERKLE, |t| {
        for row in 0..16 {
            *cell(t, row, seal::mrk::DEPTH) -= Val::ONE;
        }
    });
}

#[test]
fn a_public_index_copy_other_than_the_verifiers_is_rejected() {
    // The committed copy of `Pub`'s node column, entry 1.
    rejected(PUB, |t| bump(cell(t, 1, seal::pubc::WIDTH + seal::pubc::P_NODE)));
}

#[test]
fn a_leaf_key_copy_other_than_the_verifiers_is_rejected() {
    rejected(LEAVES, |t| bump(cell(t, 0, seal::lvs::WIDTH + seal::lvs::P_KEY)));
}

#[test]
fn a_permutation_used_twice_but_provided_once_is_rejected() {
    rejected(PERM, |t| *cell(t, 0, seal::PERM_WIDTH - 1) = Val::ZERO);
}

#[test]
fn an_opened_value_other_than_committed_is_rejected() {
    // Frame block 0's slot B: the first frame's first opened value.
    rejected(FRAMES, |t| bump(cell(t, 0, seal::frm::B)));
}

#[test]
fn an_opening_index_copy_other_than_the_verifiers_is_rejected() {
    rejected(OPUB, |t| bump(cell(t, 0, seal::opb::WIDTH + seal::opb::P_IDX)));
}

#[test]
fn an_opening_path_off_the_replica_tree_is_rejected() {
    // The first opening's path is the block after every seal path.
    rejected(MERKLE, |t| {
        let width = t.width;
        let rows = t.values.len() / width;
        let row = (0..rows).find(|&r| t.values[r * width + seal::mrk::OPEN] == Val::ONE).expect("an opening path");
        bump(cell(t, row, seal::mrk::SIB));
    });
}

/// Prove and verify 64-challenge seals over leaves of `QUIL_SEAL_NODES`
/// (comma-separated node counts), each alone and then all in one proof, and
/// report the costs:
/// `cargo test --release -p quil-storage-stark seal_costs -- --ignored --nocapture`.
#[test]
#[ignore]
fn seal_costs() {
    let sizes = std::env::var("QUIL_SEAL_NODES").unwrap_or_else(|_| "4096,65536".into());
    let params = SdrParams::default();
    let mut fixtures = Vec::new();
    for (i, nodes) in sizes.split(',').map(|s| s.trim().parse::<usize>().unwrap()).enumerate() {
        let started = std::time::Instant::now();
        let fixture = Fixture::of(format!("leaf-{i}").as_bytes(), nodes * 30, i as u8);
        let encoding = started.elapsed();
        let statement = fixture.statement(b"beacon");
        let started = std::time::Instant::now();
        let plain = fixture.seal(&statement, 64);
        let plain_proving = started.elapsed();
        let started = std::time::Instant::now();
        let proof = seal::prove(&statement, &params, 64, &plain).unwrap();
        let proving = started.elapsed();
        let started = std::time::Instant::now();
        seal::verify(&statement, &params, 64, &proof).unwrap();
        eprintln!(
            "n = {nodes} (depth {}): encode {:.1}s, plain seal {:.1}s / {} KB, STARK prove {:.2}s, verify {:.1}ms, {} KB",
            storage_proof::tree_depth(nodes as u64),
            encoding.as_secs_f64(),
            plain_proving.as_secs_f64(),
            plain.to_bytes().len() / 1024,
            proving.as_secs_f64(),
            started.elapsed().as_secs_f64() * 1e3,
            proof.len() / 1024
        );
        fixtures.push((fixture, plain));
    }
    let copies: usize = std::env::var("QUIL_SEAL_COPIES").ok().and_then(|c| c.parse().ok()).unwrap_or(1);
    let statements: Vec<SealStatement> =
        (0..copies).flat_map(|_| fixtures.iter().map(|(f, _)| f.statement(b"beacon"))).collect();
    let seals: Vec<&SealProof> = (0..copies).flat_map(|_| fixtures.iter().map(|(_, s)| s)).collect();
    let started = std::time::Instant::now();
    let proof = seal::prove_many(&statements, &params, 64, &seals).unwrap();
    let proving = started.elapsed();
    let started = std::time::Instant::now();
    seal::verify_many(&statements, &params, 64, &proof).unwrap();
    let plain: usize = seals.iter().map(|s| s.to_bytes().len()).sum();
    eprintln!(
        "all {} leaves in one proof: prove {:.2}s, verify {:.1}ms, {} KB (plain seals {} KB)",
        statements.len(),
        proving.as_secs_f64(),
        started.elapsed().as_secs_f64() * 1e3,
        proof.len() / 1024,
        plain / 1024
    );
}

/// The cost of proving an epoch's openings: `QUIL_OPEN_FRAMES` frames, each
/// opening every one of `QUIL_OPEN_LEAVES` held registrations of
/// `QUIL_OPEN_NODES` nodes.
#[test]
#[ignore]
fn opening_costs() {
    let env = |name: &str, default: usize| std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default);
    let (frames, leaves, nodes) = (env("QUIL_OPEN_FRAMES", 45), env("QUIL_OPEN_LEAVES", 4), env("QUIL_OPEN_NODES", 65536));
    let params = SdrParams::default();
    let held: Vec<Fixture> = (0..leaves).map(|l| Fixture::at(format!("held-{l}").as_bytes(), EPOCH, nodes * 30, l as u8)).collect();
    let epoch = Epoch {
        sealed: Vec::new(),
        held,
        frames: (0..frames).map(|f| (f as u64 + 1, format!("rho-{f}").into_bytes(), (0..leaves).collect())).collect(),
        count: 0,
    };
    let (statement, _, opened) = epoch.statement();
    let started = std::time::Instant::now();
    let proof = seal::prove_epoch(&statement, &params, &[], &opened).unwrap();
    let proving = started.elapsed();
    let started = std::time::Instant::now();
    seal::verify_epoch(&statement, &params, &proof).unwrap();
    eprintln!(
        "{frames} frames × {leaves} leaves × {QUERIES} openings ({} total, depth {}): prove {:.2}s, verify {:.1}ms, {} KB",
        opened.len(),
        storage_proof::tree_depth(nodes as u64),
        proving.as_secs_f64(),
        started.elapsed().as_secs_f64() * 1e3,
        proof.len() / 1024
    );
}

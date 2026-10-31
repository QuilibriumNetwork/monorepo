use super::*;
use crate::storage_hash as hash;

const LEAF: &[u8] = b"leaf-A";
const EPOCH: u64 = 9;

fn member(seed: u8) -> Vec<u8> {
    vec![seed; 32]
}

fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn params() -> SdrParams {
    SdrParams::default()
}

/// `n` canonical serialized nodes (any `n`: trees take any leaf count).
fn nodes(n: usize, seed: u8) -> Vec<u8> {
    let mut nodes = data_nodes(&data(n * hash::DATA_BYTES_PER_NODE, seed));
    nodes.truncate(n * NODE_BYTES);
    nodes
}

fn node_at(nodes: &[u8], v: u64) -> Node {
    let at = v as usize * NODE_BYTES;
    nodes[at..at + NODE_BYTES].try_into().expect("32 bytes")
}

fn statement<'a>(member: &'a [u8], encoded: &EncodedLeaf, beacon: &'a [u8]) -> SealStatement<'a> {
    SealStatement {
        member,
        leaf_id: LEAF,
        epoch: EPOCH,
        n: encoded.n,
        registered: Registered {
            comm_d: encoded.comm_d,
            comm_c: encoded.comm_c,
            comm_r: encoded.comm_r,
        },
        beacon,
    }
}

fn encode(member: &[u8], data: &[u8]) -> EncodedLeaf {
    encode_leaf(data, &sdr::replica_key(member, LEAF, EPOCH), &params())
}

#[test]
fn every_leaf_opens_against_the_commitment_and_nothing_else_does() {
    for n in [1u64, 2, 3, 5, 8, 33, 1000] {
        let nodes = nodes(n as usize, n as u8);
        let tree = MerkleTree::from_nodes(&nodes).unwrap();
        let commitment = tree.commitment(Tree::Replica);
        for index in 0..n {
            let value = node_at(&nodes, index);
            let path = tree.path(index);
            assert!(
                verify_path(Tree::Replica, n, &commitment, index, &value, &path),
                "n={n} index={index}"
            );
            let mut wrong = value;
            wrong[0] ^= 1;
            assert!(!verify_path(
                Tree::Replica,
                n,
                &commitment,
                index,
                &wrong,
                &path
            ));
            assert!(
                !verify_path(Tree::Data, n, &commitment, index, &value, &path),
                "another tree's commitment"
            );
            assert!(
                !verify_path(Tree::Replica, n + 1, &commitment, index, &value, &path),
                "another leaf count"
            );
        }
        assert!(
            !verify_path(
                Tree::Replica,
                n,
                &commitment,
                n,
                &[0; 32],
                &tree.path(n - 1)
            ),
            "a padding position"
        );
    }
    let mut non_canonical = nodes(4, 1);
    non_canonical[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(
        MerkleTree::from_nodes(&non_canonical).is_none(),
        "nodes must be canonical field elements"
    );
    assert!(MerkleTree::from_nodes(&[]).is_none());
}

#[test]
fn a_cap_gives_the_same_paths_as_the_whole_tree() {
    for n in [1u64, 7, 1024, 1025, 3000, 4096] {
        let nodes = nodes(n as usize, 3);
        let tree = MerkleTree::from_nodes(&nodes).unwrap();
        for height in [0usize, 3, CAP_HEIGHT, 20] {
            let cap = tree.cap(height);
            assert_eq!(
                cap.commitment(Tree::Replica),
                tree.commitment(Tree::Replica)
            );
            for index in [0, n / 3, n / 2, n - 1] {
                assert_eq!(
                    cap.path(&nodes, index),
                    Some(tree.path(index)),
                    "n={n} height={height} index={index}"
                );
                // The same path from only the leaves below the cap.
                let below = cap.subtree(index).unwrap();
                let subtree =
                    &nodes[below.start as usize * NODE_BYTES..below.end as usize * NODE_BYTES];
                assert!(below.end - below.start <= 1 << cap.height);
                assert_eq!(cap.subtree_path(subtree, index), Some(tree.path(index)));
                assert_eq!(cap.subtree_path(&subtree[NODE_BYTES..], index), None);
            }
            assert_eq!(cap.subtree(n), None);
            assert_eq!(MerkleCap::from_bytes(&cap.to_bytes()), Some(cap.clone()));
            let mut other = nodes.clone();
            other[0] ^= 1;
            assert_eq!(cap.path(&other, 0), None, "leaves that are not the tree's");
        }
    }
    let cap = MerkleTree::from_nodes(&nodes(3000, 3))
        .unwrap()
        .cap(CAP_HEIGHT);
    let mut bytes = cap.to_bytes();
    bytes[20] ^= 1;
    assert_eq!(
        MerkleCap::from_bytes(&bytes),
        None,
        "levels that do not hash up"
    );
    assert_eq!(
        MerkleCap::from_bytes(&cap.to_bytes()[..100]),
        None,
        "truncated"
    );
}

#[test]
fn the_replica_is_the_data_plus_the_members_last_labels() {
    let m = member(1);
    for len in [30usize, 640, 4096] {
        let raw = data(len, 7);
        let encoded = encode(&m, &raw);
        let layers = all_layers(encoded.n as usize, &sdr::replica_key(&m, LEAF, EPOCH));
        let replica = hash::digests_from_bytes(&encoded.replica).unwrap();
        let recovered: Vec<u8> = replica
            .iter()
            .zip(layers.last().unwrap())
            .flat_map(|(r, l)| hash::unpack_node(&hash::sub(r, l)).unwrap())
            .collect();
        assert_eq!(&recovered[..len], raw.as_slice());
        assert!(recovered[len..].iter().all(|&b| b == 0), "zero padding");
        assert_eq!(
            MerkleTree::from_nodes(&data_nodes(&raw))
                .unwrap()
                .commitment(Tree::Data),
            encoded.comm_d
        );
    }
    // Data that is not whole nodes, or too little, is zero-padded to at least
    // two nodes.
    assert_eq!(encode(&m, &data(70, 1)).n, 3);
    assert_eq!(encode(&m, &data(20, 1)).n, 2);
    assert_eq!(encode(&m, &[]).n, 2);
    assert_ne!(
        encode(&m, &data(640, 7)).replica,
        encode(&member(2), &data(640, 7)).replica,
        "member-unique"
    );
}

#[test]
fn an_honest_seal_verifies() {
    let m = member(1);
    let encoded = encode(&m, &data(300 * NODE_BYTES + 5, 2));
    let stmt = statement(&m, &encoded, b"beacon-1");
    let proof = prove_seal(&encoded.replica, &stmt, &params(), 16).unwrap();
    assert_eq!(verify_seal(&stmt, &proof, &params(), 16), Ok(()));
    let bytes = proof.to_bytes();
    assert_eq!(
        SealProof::from_bytes(&bytes, encoded.n, params().layers, 16),
        Some(proof.clone())
    );
    assert_eq!(
        SealProof::from_bytes(&bytes[..bytes.len() - 1], encoded.n, params().layers, 16),
        None
    );
    assert_eq!(
        SealProof::from_bytes(
            &[bytes.as_slice(), &[0]].concat(),
            encoded.n,
            params().layers,
            16
        ),
        None
    );
    assert_eq!(
        SealProof::from_bytes(&bytes, encoded.n, params().layers, 15),
        None,
        "more openings than allowed"
    );
    assert!(
        verify_seal(&stmt, &proof, &params(), 17).is_err(),
        "too few openings"
    );
}

#[test]
fn a_seal_answers_only_its_own_beacon() {
    let m = member(1);
    let encoded = encode(&m, &data(200 * NODE_BYTES, 2));
    let proof = prove_seal(
        &encoded.replica,
        &statement(&m, &encoded, b"beacon-1"),
        &params(),
        16,
    )
    .unwrap();
    assert!(verify_seal(&statement(&m, &encoded, b"beacon-2"), &proof, &params(), 16).is_err());
}

/// Copycat: B registers A's commitments as its own. B cannot prove them, A's
/// proof answers other challenges, and even answering B's own challenges from
/// A's replica and A's (public) labelling fails: the labels are recomputed
/// with B's key.
#[test]
fn another_members_replica_cannot_be_sealed() {
    let (a, b) = (member(1), member(2));
    let raw = data(200 * NODE_BYTES, 2);
    let encoded = encode(&a, &raw);
    let as_b = statement(&b, &encoded, b"beacon");
    assert!(prove_seal(&encoded.replica, &as_b, &params(), 16).is_err());
    let a_proof = prove_seal(
        &encoded.replica,
        &statement(&a, &encoded, b"beacon"),
        &params(),
        16,
    )
    .unwrap();
    assert!(verify_seal(&as_b, &a_proof, &params(), 16).is_err());

    let n = encoded.n;
    let layers = all_layers(n as usize, &sdr::replica_key(&a, LEAF, EPOCH));
    let column_labels = |v: u64| -> Vec<Node> {
        layers
            .iter()
            .map(|layer| hash::to_bytes(&layer[v as usize]))
            .collect()
    };
    let columns: Vec<u8> = (0..n)
        .flat_map(|v| column_digest(&column_labels(v)).unwrap())
        .collect();
    let column_tree = MerkleTree::from_nodes(&columns).unwrap();
    let padded = data_nodes(&raw);
    let (data_tree, replica_tree) = (
        MerkleTree::from_nodes(&padded).unwrap(),
        MerkleTree::from_nodes(&encoded.replica).unwrap(),
    );
    let column = |v: u64| ColumnOpening {
        labels: column_labels(v),
        path: column_tree.path(v),
    };
    let copied = SealProof {
        openings: seal_challenges(&as_b, 16)
            .into_iter()
            .map(|j| {
                let (same_layer, layer_below) = parents_of(j, n, &params());
                SealOpening {
                    data: node_at(&padded, j),
                    data_path: data_tree.path(j),
                    replica: node_at(&encoded.replica, j),
                    replica_path: replica_tree.path(j),
                    column: column(j),
                    parents: same_layer
                        .iter()
                        .chain(&layer_below)
                        .map(|&p| column(p))
                        .collect(),
                }
            })
            .collect(),
    };
    let err = verify_seal(&as_b, &copied, &params(), 16).unwrap_err();
    assert!(err.contains("label is not this member's"), "{err}");
}

/// Sybil: one identity's replica registered under a second identity, both
/// committing to the same data. The second identity's labels differ in every
/// node, so its seal fails.
#[test]
fn one_replica_cannot_serve_two_identities() {
    let (a, b) = (member(1), member(2));
    let raw = data(200 * NODE_BYTES, 4);
    let ea = encode(&a, &raw);
    let eb = encode(&b, &raw);
    assert_eq!(ea.comm_d, eb.comm_d, "the same data");
    assert_ne!(ea.comm_r, eb.comm_r, "but different replicas");
    let shared = SealStatement {
        registered: Registered {
            comm_r: ea.comm_r,
            ..Registered {
                comm_d: eb.comm_d,
                comm_c: eb.comm_c,
                comm_r: eb.comm_r,
            }
        },
        ..statement(&b, &eb, b"beacon")
    };
    assert!(prove_seal(&ea.replica, &shared, &params(), 16).is_err());
}

/// Every layer's labels of a leaf of `n` nodes, for building forgeries.
fn all_layers(n: usize, key: &[u8]) -> Vec<Vec<hash::Digest>> {
    let mut layers = Vec::new();
    label_layers(n, &hash::key_digest(key), &params(), &mut |_, layer| {
        layers.push(layer.to_vec())
    });
    layers
}

/// Junk: a replica of cheap bytes registered beside the honest data and column
/// commitments. The cheater answers every challenge with honest data, honest
/// labels and honest parent columns, and its junk replica nodes: the replica
/// is still not the data under its labels.
#[test]
fn a_junk_replica_fails_its_seal() {
    let m = member(1);
    let raw = data(200 * NODE_BYTES, 5);
    let honest = encode(&m, &raw);
    let n = honest.n;
    let junk = vec![0u8; honest.replica.len()];
    let junk_tree = MerkleTree::from_nodes(&junk).unwrap();
    let stmt = SealStatement {
        registered: Registered {
            comm_r: junk_tree.commitment(Tree::Replica),
            ..statement(&m, &honest, b"beacon").registered
        },
        ..statement(&m, &honest, b"beacon")
    };
    let layers = all_layers(n as usize, &sdr::replica_key(&m, LEAF, EPOCH));
    let column_labels = |v: u64| -> Vec<Node> {
        layers
            .iter()
            .map(|layer| hash::to_bytes(&layer[v as usize]))
            .collect()
    };
    let columns: Vec<u8> = (0..n)
        .flat_map(|v| column_digest(&column_labels(v)).unwrap())
        .collect();
    let column_tree = MerkleTree::from_nodes(&columns).unwrap();
    assert_eq!(column_tree.commitment(Tree::Column), honest.comm_c);
    let padded = data_nodes(&raw);
    let data_tree = MerkleTree::from_nodes(&padded).unwrap();
    let column = |v: u64| ColumnOpening {
        labels: column_labels(v),
        path: column_tree.path(v),
    };
    let forged = SealProof {
        openings: seal_challenges(&stmt, 16)
            .into_iter()
            .map(|j| {
                let (same_layer, layer_below) = parents_of(j, n, &params());
                SealOpening {
                    data: node_at(&padded, j),
                    data_path: data_tree.path(j),
                    replica: node_at(&junk, j),
                    replica_path: junk_tree.path(j),
                    column: column(j),
                    parents: same_layer
                        .iter()
                        .chain(&layer_below)
                        .map(|&p| column(p))
                        .collect(),
                }
            })
            .collect(),
    };
    let err = verify_seal(&stmt, &forged, &params(), 16).unwrap_err();
    assert!(err.contains("not its data"), "{err}");
    assert!(
        prove_seal(&junk, &stmt, &params(), 16).is_err(),
        "nor can the prover seal it"
    );
}

/// Wrong data: the replica encodes data other than the registered data.
#[test]
fn a_replica_of_other_data_fails_its_seal() {
    let m = member(1);
    let real = encode(&m, &data(200 * NODE_BYTES, 6));
    let other = encode(&m, &data(200 * NODE_BYTES, 7));
    let stmt = SealStatement {
        registered: Registered {
            comm_d: real.comm_d,
            ..statement(&m, &other, b"beacon").registered
        },
        ..statement(&m, &other, b"beacon")
    };
    assert!(prove_seal(&other.replica, &stmt, &params(), 16).is_err());
}

#[test]
fn a_tampered_parent_column_fails() {
    let m = member(1);
    let encoded = encode(&m, &data(200 * NODE_BYTES, 8));
    let stmt = statement(&m, &encoded, b"beacon");
    let mut proof = prove_seal(&encoded.replica, &stmt, &params(), 4).unwrap();
    proof.openings[1].parents[2].labels[3][0] ^= 1;
    assert!(verify_seal(&stmt, &proof, &params(), 4).is_err());
}

#[test]
fn an_opening_verifies_only_for_its_member_frame_and_epoch() {
    let (a, b) = (member(1), member(2));
    let encoded = encode(&a, &data(3000 * NODE_BYTES, 9));
    let root = encoded.registration_root();
    let open = |member: &[u8], query, rho: &[u8]| {
        build_opening(
            &encoded.replica,
            &encoded.replica_cap,
            &root,
            LEAF,
            EPOCH,
            member,
            query,
            rho,
        )
        .unwrap()
    };
    let opening = open(&a, 0, b"rho-1");
    assert!(verify_opening(&opening, b"rho-1"));
    assert!(
        !verify_opening(&opening, b"rho-2"),
        "replayed in a later frame"
    );
    let as_b = crate::porep::StorageOpening {
        member_id: b.clone(),
        ..opening.clone()
    };
    assert!(!verify_opening(&as_b, b"rho-1"), "another member's opening");
    let other_epoch = crate::porep::StorageOpening {
        epoch: EPOCH + 1,
        ..opening.clone()
    };
    assert!(
        !verify_opening(&other_epoch, b"rho-1"),
        "replayed in another epoch"
    );
    if opening_index(b"rho-1", LEAF, EPOCH, &a, 1, encoded.n)
        != opening_index(b"rho-1", LEAF, EPOCH, &a, 0, encoded.n)
    {
        let other_query = crate::porep::StorageOpening {
            query: 1,
            ..opening.clone()
        };
        assert!(
            !verify_opening(&other_query, b"rho-1"),
            "reused for another query"
        );
    }
    let mut wrong = opening.clone();
    wrong.value[0] ^= 1;
    assert!(!verify_opening(&wrong, b"rho-1"));
    let kzg_fields = crate::porep::StorageOpening {
        proof: vec![1],
        ..opening.clone()
    };
    assert!(
        !verify_opening(&kzg_fields, b"rho-1"),
        "only the hash fields may be set"
    );
}

#[test]
fn an_openings_root_binds_the_frame_and_every_value_in_order() {
    let values: Vec<Node> = (0..3).map(|i| node_at(&nodes(3, 9), i)).collect();
    let root = openings_root(7, &values).unwrap();
    assert_ne!(openings_root(8, &values).unwrap(), root, "another frame");
    assert_ne!(
        openings_root(7, &values[..2]).unwrap(),
        root,
        "a value left out"
    );
    let reversed: Vec<Node> = values.iter().rev().copied().collect();
    assert_ne!(openings_root(7, &reversed).unwrap(), root, "another order");
    let mut other = values.clone();
    other[1][0] ^= 1;
    assert_ne!(openings_root(7, &other), Some(root));
    assert!(openings_root(7, &[[0xFF; 32]]).is_none(), "non-canonical");
}

#[test]
fn the_attestation_root_binds_the_opening_set_in_any_order() {
    let a = member(1);
    let encoded = encode(&a, &data(500 * NODE_BYTES, 1));
    let root = encoded.registration_root();
    let openings: Vec<_> = (0..3)
        .map(|q| {
            build_opening(
                &encoded.replica,
                &encoded.replica_cap,
                &root,
                LEAF,
                EPOCH,
                &a,
                q,
                b"rho",
            )
            .unwrap()
        })
        .collect();
    let reversed: Vec<_> = openings.iter().rev().cloned().collect();
    let r = attestation_root(&openings, 5, b"rho", b"\x01");
    assert_eq!(r.len(), 32);
    assert_eq!(attestation_root(&reversed, 5, b"rho", b"\x01"), r);
    assert_ne!(attestation_root(&openings[..2], 5, b"rho", b"\x01"), r);
    assert_ne!(attestation_root(&openings, 6, b"rho", b"\x01"), r);
    assert_ne!(attestation_root(&openings, 5, b"rho", b"\x03"), r);
    assert!(attestation_root(&[], 5, b"rho", b"\x01").is_empty());
}

/// The shared `porep` entry points take the hash path from the activation
/// epoch, and only for openings of an epoch at or after it.
#[test]
fn porep_verifies_hash_openings_from_the_activation_epoch() {
    let a = member(1);
    let encoded = encode(&a, &data(500 * NODE_BYTES, 1));
    let root = encoded.registration_root();
    let openings: Vec<_> = (0..2)
        .map(|q| {
            build_opening(
                &encoded.replica,
                &encoded.replica_cap,
                &root,
                LEAF,
                EPOCH,
                &a,
                q,
                b"rho",
            )
            .unwrap()
        })
        .collect();
    let verify = |att_root: &[u8]| {
        crate::porep::verify_frame_storage_attestation(att_root, &openings, 5, b"rho", b"\x01", 64)
    };
    quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(EPOCH));
    let att_root =
        crate::porep::compute_storage_attestation_root(&openings, 5, b"rho", b"\x01", 64);
    assert_eq!(att_root, attestation_root(&openings, 5, b"rho", b"\x01"));
    assert!(verify(&att_root));
    assert!(!verify(&[0u8; 32]), "another opening set's root");
    quil_types::consensus::set_hash_storage_proof_epoch_for_thread(Some(EPOCH + 1));
    assert!(
        !verify(&att_root),
        "before activation the openings are read as KZG"
    );
    quil_types::consensus::set_hash_storage_proof_epoch_for_thread(None);
}

/// BLS48-581 is not post-quantum. Its last live use is the KZG storage proofs
/// (`porep`, `sdr`, `inclusion`), kept to verify epochs before
/// `hash_storage_proof_epoch`. Any other code that calls the library directly
/// fails here: the July KZG→JMT migration traced callers of the tree's
/// interfaces and missed these direct ones (2026-10-20).
#[test]
fn bls48581_stays_confined_to_the_kzg_storage_proofs() {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crates directory");
    let allowed = [
        "bls48581/",
        "bls48581-wasm/",
        "quil-crypto/src/inclusion.rs",
        "quil-crypto/src/porep.rs",
        "quil-crypto/src/sdr.rs",
        "quil-crypto/src/lib.rs",
    ];
    let needle = ["bls48581", "::"].concat(); // not spelled out, or this file would match
    let mut offenders = Vec::new();
    let mut pending = vec![crates.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)
            .expect("readable source tree")
            .flatten()
        {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if path.is_dir() {
                if name != "target" && !name.starts_with('.') {
                    pending.push(path);
                }
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let relative = path
                .strip_prefix(crates)
                .expect("under crates")
                .to_string_lossy()
                .replace('\\', "/");
            if allowed.iter().any(|prefix| relative.starts_with(prefix)) {
                continue;
            }
            let Ok(source) = std::fs::read_to_string(&path) else {
                continue;
            };
            for (number, line) in source.lines().enumerate() {
                if !line.trim_start().starts_with("//") && line.contains(&needle) {
                    offenders.push(format!("{relative}:{}", number + 1));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "direct bls48581 calls outside the KZG storage proofs: {offenders:?}"
    );
}

/// Labels kept in memory, as a member keeps them on disk.
struct Kept {
    layers: Vec<Vec<hash::Digest>>,
    columns: Vec<hash::Digest>,
}

impl Kept {
    fn label(n: u64, key: &[u8]) -> (Self, Node) {
        let mut layers = Vec::new();
        let (_, columns) = label_leaf(n, key, &params(), &mut |_, layer| {
            layers.push(layer.to_vec())
        });
        let comm_c = MerkleTree::from_digests(columns.clone()).commitment(Tree::Column);
        (Self { layers, columns }, comm_c)
    }
}

impl LabelSource for Kept {
    fn label(&self, layer: usize, v: u64) -> Option<Node> {
        Some(hash::to_bytes(self.layers.get(layer)?.get(v as usize)?))
    }
    fn columns(&self) -> Option<Vec<hash::Digest>> {
        Some(self.columns.clone())
    }
    fn last_layer(&self) -> Option<Vec<hash::Digest>> {
        self.layers.last().cloned()
    }
}

/// Labels do not depend on the data, so a leaf labelled ahead at a padded
/// count and given its data later is the leaf encoded whole at that count.
#[test]
fn a_leaf_from_labels_kept_ahead_is_the_leaf_encoded_whole() {
    let m = member(4);
    let key = sdr::replica_key(&m, LEAF, EPOCH);
    let leaf = data(3_000, 7);
    let exact = data_node_count(leaf.len() as u64);
    let n = precompute_nodes(exact);
    assert!(padded_nodes_allowed(exact, n));
    let mut streamed = Vec::new();
    let whole = encode_leaf_at(&leaf, &key, &params(), n, &mut |layer, labels| {
        streamed.push((layer, labels.len()))
    });
    assert_eq!(whole.n, n);
    assert_eq!(
        streamed,
        (0..params().layers)
            .map(|l| (l, n as usize))
            .collect::<Vec<_>>()
    );
    let (kept, comm_c) = Kept::label(n, &key);
    let ahead = encode_with_labels(&leaf, n, kept.layers.last().unwrap(), comm_c).unwrap();
    assert_eq!(ahead.replica, whole.replica);
    assert_eq!(
        (ahead.comm_d, ahead.comm_c, ahead.comm_r),
        (whole.comm_d, whole.comm_c, whole.comm_r)
    );
    assert_eq!(ahead.replica_cap, whole.replica_cap);
    assert!(
        encode_with_labels(&data(200_000, 7), n, kept.layers.last().unwrap(), comm_c).is_err(),
        "data larger than the labels"
    );
}

/// A seal opened from kept labels is the relabelled seal, verifies at a
/// padded count, and refuses labels that are not the registration's.
#[test]
fn a_seal_from_kept_labels_is_the_relabelled_seal() {
    let m = member(5);
    let key = sdr::replica_key(&m, LEAF, EPOCH);
    let leaf = data(2_000, 9);
    let n = precompute_nodes(data_node_count(leaf.len() as u64));
    let (kept, comm_c) = Kept::label(n, &key);
    let encoded = encode_with_labels(&leaf, n, kept.layers.last().unwrap(), comm_c).unwrap();
    let beacon = [3u8; 32];
    let statement = statement(&m, &encoded, &beacon);
    let relabelled = prove_seal(&encoded.replica, &statement, &params(), 16).unwrap();
    let opened =
        prove_seal_with_labels(&encoded.replica, &statement, &params(), 16, &kept).unwrap();
    assert_eq!(opened, relabelled);
    verify_seal(&statement, &opened, &params(), 16).unwrap();

    let mut wrong = Kept {
        layers: kept.layers.clone(),
        columns: kept.columns.clone(),
    };
    let challenged = seal_challenges(&statement, 1)[0] as usize;
    wrong.layers[3][challenged] = hash::add(&wrong.layers[3][challenged], &[hash::felt(1); 8]);
    assert!(
        prove_seal_with_labels(&encoded.replica, &statement, &params(), 16, &wrong).is_err(),
        "a label that is not its column's"
    );
    let (other, _) = Kept::label(n, &sdr::replica_key(&member(6), LEAF, EPOCH));
    assert!(
        prove_seal_with_labels(&encoded.replica, &statement, &params(), 16, &other).is_err(),
        "another member's labels"
    );
}

/// A count labelled ahead stays registrable while the data changes by a few
/// percent, and a registration never pads past an eighth and the floor.
#[test]
fn a_count_labelled_ahead_stays_registrable_while_the_data_changes_a_little() {
    for exact in [2u64, 100, 4_096, 1_000_000, 35_791_394] {
        let n = precompute_nodes(exact);
        let grown = exact + exact / 16;
        let shrunk = exact - exact / 20;
        assert!(padded_nodes_allowed(grown, n), "grown {exact}");
        assert!(padded_nodes_allowed(shrunk.max(1), n), "shrunk {exact}");
        assert!(!padded_nodes_allowed(n + 1, n), "data past the labels");
    }
    assert!(padded_nodes_allowed(10, 10));
    assert!(!padded_nodes_allowed(10, 9));
    assert!(padded_nodes_allowed(800, 800 + 100 + PAD_FLOOR_NODES));
    assert!(!padded_nodes_allowed(800, 800 + 101 + PAD_FLOOR_NODES));
}

/// Labelling given up when told to stop hands on no further layer and
/// returns nothing; one never told to stop is [`label_leaf`]'s.
#[test]
fn labelling_stops_when_told_and_is_unchanged_otherwise() {
    use std::cell::Cell;
    let n = STOP_CHECK_NODES as u64 + 7;
    let key = b"stop-key";
    let whole = label_leaf(n, key, &params(), &mut |_, _| {});
    assert_eq!(
        label_leaf_until(n, key, &params(), &mut |_, _| {}, &|| false),
        Some(whole)
    );
    // Stopped within the second layer: one layer handed on, then none.
    let looks = Cell::new(0usize);
    let checks_per_layer = (n as usize).div_ceil(STOP_CHECK_NODES);
    let mut layers = Vec::new();
    let stopped = label_leaf_until(
        n,
        key,
        &params(),
        &mut |index, _| layers.push(index),
        &|| {
            looks.set(looks.get() + 1);
            looks.get() > checks_per_layer + 1
        },
    );
    assert_eq!(stopped, None);
    assert_eq!(layers, vec![0], "no layer after the stop");
    assert_eq!(
        looks.get(),
        checks_per_layer + 2,
        "it stops at the first look that says so"
    );
}

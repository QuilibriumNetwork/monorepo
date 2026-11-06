//! Persistent identity-bound label sectors. Initial certification uses the
//! existing 11-layer PoRep over zero data (R = L). Epoch updates open D, L and
//! R at fresh, registration-bound challenges and check R = D + L. Lower layers
//! cease to be needed after their final-layer root has been certified.
use crate::{storage_hash as hash, storage_proof as proof};
use proof::{ColumnOpening, MerkleCap, Node, SealOpening, SealProof, Tree};
use sha3::{Digest as _, Sha3_256};

pub const ROOT_BYTES: usize = 164;
pub const MAX_SECTOR_NODES: u64 = 1 << 26;
pub const CHALLENGES: usize = 64;
pub use quil_types::consensus::StorageSealProfile as Profile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registration {
    pub profile: Profile,
    pub data: Node,
    pub labels: Node,
    pub replica: Node,
    pub sector: [u8; 32],
    pub columns: Node,
}
impl Registration {
    pub fn to_bytes(&self) -> Vec<u8> {
        [
            self.data.as_slice(),
            &self.labels,
            &self.replica,
            self.profile.tag(),
            &self.sector,
            &self.columns,
        ]
        .concat()
    }
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ROOT_BYTES {
            return None;
        }
        let profile = Profile::from_tag(&bytes[96..100])?;
        let node = |at| {
            let n: Node = bytes.get(at..at + 32)?.try_into().ok()?;
            let _ = hash::from_bytes(&n)?;
            Some(n)
        };
        Some(Self {
            profile,
            data: node(0)?,
            labels: node(32)?,
            replica: node(64)?,
            sector: bytes[100..132].try_into().ok()?,
            columns: node(132)?,
        })
    }
    pub fn registered(&self) -> proof::Registered {
        proof::Registered {
            comm_d: self.data,
            comm_c: self.labels,
            comm_r: self.replica,
        }
    }
    pub fn certificate(&self, n: u64) -> Certificate {
        Certificate {
            profile: self.profile,
            sector: self.sector,
            n,
            columns: self.columns,
            labels: self.labels,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Certificate {
    pub profile: Profile,
    pub sector: [u8; 32],
    pub n: u64,
    pub columns: Node,
    pub labels: Node,
}
impl Certificate {
    pub const BYTES: usize = 104;
    pub const PROFILED_BYTES: usize = 108;
    pub fn params(&self) -> crate::sdr::SdrParams {
        crate::sdr::SdrParams::for_profile(self.profile)
    }
    pub fn valid(&self) -> bool {
        self.n >= 2
            && self.n <= MAX_SECTOR_NODES
            && self.n.is_power_of_two()
            && hash::from_bytes(&self.columns).is_some()
            && hash::from_bytes(&self.labels).is_some()
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        let base = [
            self.sector.as_slice(),
            &self.n.to_be_bytes(),
            &self.columns,
            &self.labels,
        ]
        .concat();
        if self.profile == Profile::Eleven {
            base
        } else {
            [self.profile.tag().as_slice(), &base].concat()
        }
    }
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let (profile, bytes) = match bytes.len() {
            Self::BYTES => (Profile::Eleven, bytes),
            Self::PROFILED_BYTES => {
                let profile = Profile::from_tag(&bytes[..4])?;
                if profile == Profile::Eleven {
                    return None;
                }
                (profile, &bytes[4..])
            }
            _ => return None,
        };
        let cert = Self {
            profile,
            sector: bytes[..32].try_into().ok()?,
            n: u64::from_be_bytes(bytes[32..40].try_into().ok()?),
            columns: bytes[40..72].try_into().ok()?,
            labels: bytes[72..104].try_into().ok()?,
        };
        cert.valid().then_some(cert)
    }
    pub fn registered(&self) -> Option<proof::Registered> {
        self.valid().then_some(proof::Registered {
            comm_d: proof::zero_commitment(Tree::Data, self.n)?,
            comm_c: self.columns,
            comm_r: self.labels,
        })
    }
}

pub fn capacity(exact: u64) -> Option<u64> {
    exact
        .max(2)
        .checked_next_power_of_two()
        .filter(|n| *n <= MAX_SECTOR_NODES)
}
pub fn padded_nodes_allowed(exact: u64, n: u64) -> bool {
    exact <= n && n >= 2 && n <= MAX_SECTOR_NODES && n.is_power_of_two()
}

fn context(
    member: &[u8],
    leaf: &[u8],
    epoch: u64,
    n: u64,
    root: &Registration,
    beacon: &[u8],
) -> Node {
    let mut h = Sha3_256::new();
    h.update(b"quil/persistent-storage/epoch/v1");
    for bytes in [member, leaf, beacon] {
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
    }
    h.update(epoch.to_be_bytes());
    h.update(n.to_be_bytes());
    h.update(root.to_bytes());
    h.finalize().into()
}

/// The zero-data certificate is challenged only after its complete roots were
/// registered. Binding the entire registration also prevents proof transplants.
pub fn certificate_beacon(
    member: &[u8],
    leaf: &[u8],
    epoch: u64,
    n: u64,
    root: &Registration,
    beacon: &[u8],
) -> Node {
    context(member, leaf, epoch, n, root, beacon)
}

pub fn challenges(
    member: &[u8],
    leaf: &[u8],
    epoch: u64,
    n: u64,
    root: &Registration,
    beacon: &[u8],
) -> Option<Vec<u64>> {
    if !root.certificate(n).valid() {
        return None;
    }
    let context = context(member, leaf, epoch, n, root, beacon);
    Some(
        (0..CHALLENGES)
            .map(|i| {
                let mut h = Sha3_256::new();
                h.update(b"quil/persistent-storage/open/v1");
                h.update(context);
                h.update((i as u32).to_be_bytes());
                let digest = h.finalize();
                u64::from_be_bytes(digest[..8].try_into().unwrap()) % n
            })
            .collect(),
    )
}

/// Native sparse proof: a single final-label opening replaces each complete
/// label column and its fourteen parents. Proof size is strictly bounded by
/// 64 * (3 nodes + 3 Merkle paths), independently of stored record count.
pub fn prove(
    member: &[u8],
    leaf: &[u8],
    epoch: u64,
    n: u64,
    root: &Registration,
    beacon: &[u8],
    open: &dyn Fn(Tree, u64) -> Option<(Node, Vec<Node>)>,
) -> Result<SealProof, String> {
    let indices =
        challenges(member, leaf, epoch, n, root, beacon).ok_or("invalid sector capacity")?;
    let mut openings = Vec::with_capacity(CHALLENGES);
    for index in indices {
        let (data, data_path) = open(Tree::Data, index).ok_or("data opening unavailable")?;
        let (replica, replica_path) =
            open(Tree::Replica, index).ok_or("replica opening unavailable")?;
        // A certified final layer is committed as a replica, not a column hash.
        let (label, path) = open(Tree::Column, index).ok_or("label opening unavailable")?;
        openings.push(SealOpening {
            data,
            data_path,
            replica,
            replica_path,
            column: ColumnOpening {
                labels: vec![label],
                path,
            },
            parents: Vec::new(),
        });
    }
    let proof = SealProof { openings };
    verify(member, leaf, epoch, n, root, beacon, &proof)?;
    Ok(proof)
}

/// The caller must first authenticate root.certificate(n) against GLOBAL's
/// certified-sector record. This function alone certifies no labels.
pub fn verify(
    member: &[u8],
    leaf: &[u8],
    epoch: u64,
    n: u64,
    root: &Registration,
    beacon: &[u8],
    proof: &SealProof,
) -> Result<(), String> {
    let indices =
        challenges(member, leaf, epoch, n, root, beacon).ok_or("invalid sector capacity")?;
    if proof.openings.len() != CHALLENGES {
        return Err("persistent proof challenge count".into());
    }
    for (index, opening) in indices.into_iter().zip(&proof.openings) {
        if opening.column.labels.len() != 1 || !opening.parents.is_empty() {
            return Err("persistent proof shape".into());
        }
        let label = &opening.column.labels[0];
        for (tree, commitment, node, path) in [
            (Tree::Data, &root.data, &opening.data, &opening.data_path),
            (
                Tree::Replica,
                &root.replica,
                &opening.replica,
                &opening.replica_path,
            ),
            (Tree::Replica, &root.labels, label, &opening.column.path),
        ] {
            if !proof::verify_path(tree, n, commitment, index, node, path) {
                return Err("persistent proof Merkle opening".into());
            }
        }
        let data = hash::from_bytes(&opening.data).ok_or("noncanonical data node")?;
        let label = hash::from_bytes(label).ok_or("noncanonical label node")?;
        if hash::to_bytes(&hash::add(&data, &label)) != opening.replica {
            return Err("replica is not data plus certified label".into());
        }
    }
    Ok(())
}

pub fn open(cap: &MerkleCap, nodes: &[u8], index: u64) -> Option<(Node, Vec<Node>)> {
    let node = nodes
        .get(index as usize * 32..index as usize * 32 + 32)?
        .try_into()
        .ok()?;
    Some((node, cap.path(nodes, index)?))
}

/// Lossless dictionary encoding of the fresh Merkle openings. Shared upper
/// paths and zero-padding subtrees are sent once; verification still checks
/// the exact same 64 D/L/R openings. No cryptographic assumption is added.
pub fn encode_proof(proof: &SealProof, n: u64) -> Result<Vec<u8>, String> {
    use std::collections::BTreeMap;
    if !padded_nodes_allowed(n, n) || proof.openings.len() != CHALLENGES {
        return Err("persistent proof capacity or count".into());
    }
    let depth = proof::tree_depth(n);
    let mut dictionary = Vec::<Node>::new();
    let mut ids = BTreeMap::<Node, u16>::new();
    let mut indices = Vec::new();
    for opening in &proof.openings {
        if opening.column.labels.len() != 1
            || !opening.parents.is_empty()
            || [
                opening.data_path.len(),
                opening.replica_path.len(),
                opening.column.path.len(),
            ] != [depth; 3]
        {
            return Err("persistent proof shape".into());
        }
        for (node, path) in [
            (&opening.data, &opening.data_path),
            (&opening.replica, &opening.replica_path),
            (&opening.column.labels[0], &opening.column.path),
        ] {
            for node in std::iter::once(node).chain(path) {
                let id = if let Some(id) = ids.get(node) {
                    *id
                } else {
                    let _ = hash::from_bytes(node).ok_or("noncanonical proof dictionary node")?;
                    let id = u16::try_from(dictionary.len())
                        .map_err(|_| "proof dictionary too large")?;
                    dictionary.push(*node);
                    ids.insert(*node, id);
                    id
                };
                indices.extend_from_slice(&id.to_be_bytes());
            }
        }
    }
    let mut out = b"PSP1".to_vec();
    out.extend_from_slice(&(dictionary.len() as u16).to_be_bytes());
    for node in dictionary {
        out.extend_from_slice(&node);
    }
    out.extend_from_slice(&indices);
    Ok(out)
}

pub fn decode_proof(bytes: &[u8], n: u64) -> Option<SealProof> {
    if !padded_nodes_allowed(n, n) || bytes.get(..4)? != b"PSP1" {
        return None;
    }
    let depth = proof::tree_depth(n);
    let words = CHALLENGES * 3 * (depth + 1);
    let count = u16::from_be_bytes(bytes.get(4..6)?.try_into().ok()?) as usize;
    if count == 0 || count > words || bytes.len() != 6 + 32 * count + 2 * words {
        return None;
    }
    let dictionary = bytes[6..6 + 32 * count]
        .chunks_exact(32)
        .map(|b| b.try_into().ok())
        .collect::<Option<Vec<Node>>>()?;
    let mut indices = bytes[6 + 32 * count..].chunks_exact(2);
    let mut node = || {
        let id = u16::from_be_bytes(indices.next()?.try_into().ok()?) as usize;
        dictionary.get(id).copied()
    };
    let mut openings = Vec::with_capacity(CHALLENGES);
    for _ in 0..CHALLENGES {
        let data = node()?;
        let data_path = (0..depth).map(|_| node()).collect::<Option<Vec<_>>>()?;
        let replica = node()?;
        let replica_path = (0..depth).map(|_| node()).collect::<Option<Vec<_>>>()?;
        let label = node()?;
        let path = (0..depth).map(|_| node()).collect::<Option<Vec<_>>>()?;
        openings.push(SealOpening {
            data,
            data_path,
            replica,
            replica_path,
            column: ColumnOpening {
                labels: vec![label],
                path,
            },
            parents: Vec::new(),
        });
    }
    let proof = SealProof { openings };
    // Unique dictionary entries, first-use order and no unused entries make
    // the wire representation canonical and bound all decoder allocations.
    (encode_proof(&proof, n).ok()?.as_slice() == bytes).then_some(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capacities_and_versioned_roots_are_strict() {
        for exact in [0, 1, 2, 3, 31, 32, 33, MAX_SECTOR_NODES] {
            let n = capacity(exact).unwrap();
            assert!(padded_nodes_allowed(exact, n));
            assert!(n.is_power_of_two());
            assert!(n >= exact);
        }
        assert_eq!(capacity(MAX_SECTOR_NODES + 1), None);
        assert_eq!(capacity(u64::MAX), None);
        for n in [0, 1, 3, MAX_SECTOR_NODES + 1, u64::MAX] {
            assert!(!padded_nodes_allowed(1, n));
        }
        let root = Registration {
            profile: Profile::Eleven,
            data: [0; 32],
            labels: [0; 32],
            replica: [0; 32],
            sector: [255; 32],
            columns: [0; 32],
        };
        assert_eq!(Registration::parse(&root.to_bytes()), Some(root));
        let mut bytes = root.to_bytes();
        bytes.push(0);
        assert!(Registration::parse(&bytes).is_none());
        let mut bytes = root.to_bytes();
        bytes[96] ^= 1;
        assert!(Registration::parse(&bytes).is_none());
        let mut bytes = root.to_bytes();
        bytes[..32].fill(255);
        assert!(Registration::parse(&bytes).is_none());
        let cert = root.certificate(32);
        assert_eq!(Certificate::parse(&cert.to_bytes()), Some(cert));
    }

    #[test]
    fn fresh_openings_bind_data_identity_epoch_sector_and_beacon() {
        let n = 128;
        let member = [3; 32];
        let id = [7; 32];
        let leaf = b"logical leaf";
        let epoch = 1500;
        let beacon = [9; 32];
        let (last, columns) = proof::label_leaf(
            n,
            &crate::sdr::stable_replica_key(&member, &id),
            &crate::sdr::SdrParams::default(),
            &mut |_, _| {},
        );
        let labels = MerkleCap::from_digests(&last, 3);
        let label_bytes = hash::digests_to_bytes(&last);
        let columns = MerkleCap::from_digests(&columns, 3).commitment(Tree::Column);
        let mut previous = None;
        for data in [
            b"first value".as_slice(),
            b"different useful data".as_slice(),
        ] {
            let encoded =
                proof::encode_with_labels(data, n, &last, labels.commitment(Tree::Replica))
                    .unwrap();
            let mut data_bytes = proof::data_nodes(data);
            data_bytes.resize(n as usize * 32, 0);
            let root = Registration {
                profile: Profile::Eleven,
                data: encoded.comm_d,
                labels: labels.commitment(Tree::Replica),
                replica: encoded.comm_r,
                sector: id,
                columns,
            };
            let plain = prove(
                &member,
                leaf,
                epoch,
                n,
                &root,
                &beacon,
                &|tree, index| match tree {
                    Tree::Data => open(&encoded.data_cap, &data_bytes, index),
                    Tree::Column => open(&labels, &label_bytes, index),
                    Tree::Replica => open(&encoded.replica_cap, &encoded.replica, index),
                },
            )
            .unwrap();
            assert_eq!(
                verify(&member, leaf, epoch, n, &root, &beacon, &plain),
                Ok(())
            );
            assert_eq!(
                SealProof::from_bytes(&plain.to_bytes(), n, 1, CHALLENGES),
                Some(plain.clone())
            );
            let compact = encode_proof(&plain, n).unwrap();
            assert!(compact.len() < plain.to_bytes().len());
            assert_eq!(decode_proof(&compact, n), Some(plain.clone()));
            let mut truncated = compact.clone();
            truncated.pop();
            assert!(decode_proof(&truncated, n).is_none());
            let mut trailing = compact.clone();
            trailing.push(0);
            assert!(decode_proof(&trailing, n).is_none());
            let mut invalid = compact.clone();
            invalid[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
            assert!(decode_proof(&invalid, n).is_none());
            let count = u16::from_be_bytes(compact[4..6].try_into().unwrap()) as usize;
            let mut noncanonical = b"PSP1".to_vec();
            noncanonical.extend_from_slice(&((count + 1) as u16).to_be_bytes());
            noncanonical.extend_from_slice(&compact[6..6 + 32 * count]);
            noncanonical.extend_from_slice(&compact[6..38]);
            noncanonical.extend_from_slice(&compact[6 + 32 * count..]);
            assert!(
                decode_proof(&noncanonical, n).is_none(),
                "duplicate unused dictionary entry"
            );
            let mut invalid = compact.clone();
            invalid[6 + 32 * count..8 + 32 * count].copy_from_slice(&u16::MAX.to_be_bytes());
            assert!(decode_proof(&invalid, n).is_none());

            for (m, l, e, b) in [
                ([4; 32], leaf.as_slice(), epoch, beacon),
                (member, b"another".as_slice(), epoch, beacon),
                (member, leaf.as_slice(), epoch + 1, beacon),
                (member, leaf.as_slice(), epoch, [8; 32]),
            ] {
                assert!(verify(&m, l, e, n, &root, &b, &plain).is_err());
            }
            let mut changed = root;
            changed.sector[0] ^= 1;
            assert!(verify(&member, leaf, epoch, n, &changed, &beacon, &plain).is_err());
            let mut changed = root;
            changed.columns[0] ^= 1;
            assert!(verify(&member, leaf, epoch, n, &changed, &beacon, &plain).is_err());
            let mut bad = plain.clone();
            bad.openings[0].replica[0] ^= 1;
            assert!(verify(&member, leaf, epoch, n, &root, &beacon, &bad).is_err());
            let mut bad = plain.clone();
            bad.openings[0].column.labels.push([0; 32]);
            assert!(verify(&member, leaf, epoch, n, &root, &beacon, &bad).is_err());
            let mut bad = plain.clone();
            bad.openings.pop();
            assert!(verify(&member, leaf, epoch, n, &root, &beacon, &bad).is_err());
            let mut bad = plain.clone();
            bad.openings[0].data_path.push([0; 32]);
            assert!(verify(&member, leaf, epoch, n, &root, &beacon, &bad).is_err());
            if let Some(old) = previous {
                assert!(verify(&member, leaf, epoch, n, &root, &beacon, &old).is_err());
            }
            previous = Some(plain);
        }
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    #[test]
    fn profile_encodings_are_canonical_and_legacy_bytes_remain_unchanged() {
        let base = Certificate {
            profile: Profile::Eleven,
            sector: [7; 32],
            n: 32,
            columns: [0; 32],
            labels: [0; 32],
        };
        let old = [&[7u8; 32][..], &32u64.to_be_bytes(), &[0u8; 64]].concat();
        assert_eq!(base.to_bytes(), old);
        for profile in [Profile::Eleven, Profile::Two, Profile::Three] {
            let cert = Certificate { profile, ..base };
            assert_eq!(Certificate::parse(&cert.to_bytes()), Some(cert));
            let root = Registration {
                profile,
                data: [0; 32],
                labels: cert.labels,
                replica: [0; 32],
                sector: cert.sector,
                columns: cert.columns,
            };
            assert_eq!(Registration::parse(&root.to_bytes()), Some(root));
            assert_eq!(root.certificate(32), cert);
            assert_eq!(&root.to_bytes()[96..100], profile.tag());
        }
        let noncanonical = [Profile::Eleven.tag().as_slice(), &old].concat();
        assert!(Certificate::parse(&noncanonical).is_none());
        let unknown = [b"PS09".as_slice(), &old].concat();
        assert!(Certificate::parse(&unknown).is_none());
        let three = Certificate {
            profile: Profile::Three,
            ..base
        };
        assert_ne!(base, three);
    }
}

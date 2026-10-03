//! Authenticated historical registrations for storage-bearing app frames.
//! The live registry has only three epoch slots. Old frames need the record
//! bound to their own GLOBAL anchor, without replacing the live GLOBAL tree.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use quil_execution::{
    global_intrinsic::{leaf_id_bytes, materialize},
    global_schema,
};
use quil_types::error::{QuilError, Result};

pub const MAX_GLOBAL_VERTEX_PROOF_BYTES: usize = 32 * 1024;
pub type GlobalVertexProofSource = Arc<
    dyn Fn([u8; 32], [u8; 32]) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>>> + Send>>
        + Send
        + Sync,
>;
pub type Registration = (Vec<u8>, u64, u64);
type CacheKey = ([u8; 32], [u8; 32], u64);

pub fn verify_global_vertex_proof(
    root: &[u8; 32],
    address: &[u8; 32],
    bytes: &[u8],
) -> Result<quil_forest::VertexMembershipProof> {
    if bytes.len() > MAX_GLOBAL_VERTEX_PROOF_BYTES || bytes.get(..4) != Some(&[1, 0, 0, 0]) {
        return Err(QuilError::InvalidArgument(
            "historical GLOBAL proof dimensions".into(),
        ));
    }
    let mut proof = quil_forest::MembershipProof::from_bytes(bytes)
        .map_err(|_| QuilError::InvalidArgument("historical GLOBAL proof encoding".into()))?;
    let item = proof
        .inputs
        .pop()
        .ok_or_else(|| QuilError::InvalidArgument("empty historical proof".into()))?;
    let expected: Vec<_> = [0xff; 32]
        .into_iter()
        .chain(address.iter().copied())
        .collect();
    if item.vertex_address != expected || item.shard_aggregation.is_some() {
        return Err(QuilError::InvalidArgument(
            "historical GLOBAL proof address".into(),
        ));
    }
    quil_forest::verify_vertex_membership(root, &item, &[])
        .map_err(|_| QuilError::InvalidArgument("historical GLOBAL proof root or blob".into()))?;
    Ok(item)
}

/// Small, volatile cache of authenticated registrations, keyed by the exact
/// GLOBAL root, record address and epoch. It cannot authorize another anchor.
/// Pruned history still requires a peer retaining that root; this cache is not
/// a durable historical-retention policy.
pub struct StorageHistory {
    records: Mutex<lru::LruCache<CacheKey, Option<Registration>>>,
}

impl Default for StorageHistory {
    fn default() -> Self {
        Self {
            records: Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(1024).unwrap(),
            )),
        }
    }
}

impl StorageHistory {
    pub fn get(
        &self,
        root: [u8; 32],
        address: [u8; 32],
        epoch: u64,
    ) -> Option<Option<Registration>> {
        self.records
            .lock()
            .ok()?
            .get(&(root, address, epoch))
            .cloned()
    }

    pub fn insert(
        &self,
        root: [u8; 32],
        member: &[u8],
        leaf: &[u8],
        epoch: u64,
        bytes: &[u8],
    ) -> Result<Option<Registration>> {
        let address = materialize::leaf_root_address(member, leaf)?;
        let proof = verify_global_vertex_proof(&root, &address, bytes)?;
        let tree = quil_tries::VectorCommitmentTree {
            root: quil_tries::deserialize_go_tree(&proof.vertex_blob)?,
        };
        let cls = "leafroot:LeafRootRegistration";
        let read = |name| global_schema::read_field(&tree, cls, name);
        let valid_type = tree
            .root
            .as_ref()
            .and_then(|r| r.find_leaf_value(&[0xff; 32]))
            == Some(global_schema::compute_type_hash(cls).to_vec());
        let prefix = read("Prefix")
            .ok_or_else(|| QuilError::InvalidArgument("historical leaf prefix missing".into()))?;
        let filter = read("ShardFilter")
            .ok_or_else(|| QuilError::InvalidArgument("historical leaf filter missing".into()))?;
        if !valid_type
            || member.len() != 32
            || read("Member").as_deref() != Some(member)
            || prefix.len() % 4 != 0
            || leaf_id_bytes(&filter, &materialize::unpack_prefix(&prefix)) != leaf
        {
            return Err(QuilError::InvalidArgument(
                "historical storage registration identity".into(),
            ));
        }
        let value = materialize::leaf_root_registration_for_epoch(&tree, epoch)
            .map(|(root, blocks)| (root, blocks, epoch));
        self.records
            .lock()
            .map_err(|_| QuilError::ExecutionUnavailable("storage history cache poisoned".into()))?
            .put((root, address, epoch), value.clone());
        Ok(value)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use quil_hypergraph::{addressing::Location, HypergraphCrdt};
    use quil_tries::VectorCommitmentTree;

    pub struct Archive {
        pub db: quil_store::RocksDb,
        pub crdt: Arc<HypergraphCrdt>,
        pub address: [u8; 32],
    }
    impl Archive {
        pub fn new(member: &[u8; 32], leaf: &[u8]) -> Self {
            let db = quil_store::RocksDb::open_in_memory().unwrap();
            let crdt = Self::open_crdt(&db);
            Self {
                db,
                crdt,
                address: materialize::leaf_root_address(member, leaf).unwrap(),
            }
        }
        pub fn open_crdt(db: &quil_store::RocksDb) -> Arc<HypergraphCrdt> {
            let crdt = Arc::new(HypergraphCrdt::new(
                Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
                Arc::new(quil_types::crypto::NoopInclusionProver),
            ));
            crdt.set_forest(quil_forest::Forest::with_namespace(
                db.inner(),
                quil_store::FOREST_NAMESPACE,
            ));
            crdt
        }
        pub fn commit(&self, tree: &VectorCommitmentTree, frame: u64) -> [u8; 32] {
            self.crdt
                .add_vertex(
                    &Location {
                        app_address: [0xff; 32],
                        data_address: self.address,
                    },
                    &quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap(),
                )
                .unwrap();
            self.crdt
                .commit_with_global_cursor(
                    frame,
                    &quil_store::encoding::global_materialized_cursor_key(),
                )
                .unwrap();
            self.crdt.current_forest_phase_root(&[0xff; 32], 0).unwrap()
        }
        pub fn proof(&self, root: [u8; 32]) -> Vec<u8> {
            quil_forest::MembershipProof {
                inputs: vec![self
                    .crdt
                    .global_vertex_membership_at_root(&root, &self.address)
                    .unwrap()
                    .unwrap()],
            }
            .to_bytes()
        }
    }

    #[test]
    fn retained_registration_survives_three_epoch_rotation_and_reopen() {
        let member = [7; 32];
        let filter = [8; 32];
        let leaf = leaf_id_bytes(&filter, &[]);
        let archive = Archive::new(&member, &leaf);
        let mut tree =
            materialize::create_leaf_root_vertex_tree(&member, &filter, &[], 3, &[11; 74], 2, 10)
                .unwrap();
        let original = archive.commit(&tree, 10);
        for epoch in 4..=7 {
            tree = materialize::upsert_leaf_root_registration(
                Some(&tree),
                &member,
                &filter,
                &[],
                epoch,
                &[epoch as u8; 74],
                3,
                epoch + 10,
            )
            .unwrap();
            archive.commit(&tree, epoch + 10);
        }
        assert!(materialize::leaf_root_registration_for_epoch(&tree, 3).is_none());
        let reopened = Archive::open_crdt(&archive.db);
        let proof = reopened
            .global_vertex_membership_at_root(&original, &archive.address)
            .unwrap()
            .unwrap();
        let bytes = quil_forest::MembershipProof {
            inputs: vec![proof],
        }
        .to_bytes();
        let history = StorageHistory::default();
        assert_eq!(
            history.insert(original, &member, &leaf, 3, &bytes).unwrap(),
            Some((vec![11; 74], 2, 3))
        );
        assert_eq!(
            history.insert(original, &member, &leaf, 7, &bytes).unwrap(),
            None
        );
        assert!(history.get([0; 32], archive.address, 3).is_none());
        assert!(history.insert([0; 32], &member, &leaf, 3, &bytes).is_err());
        assert!(history
            .insert(original, &[9; 32], &leaf, 3, &bytes)
            .is_err());
        assert!(history
            .insert(original, &member, &[9; 32], 3, &bytes)
            .is_err());
        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(history
            .insert(original, &member, &leaf, 3, &corrupt)
            .is_err());
        assert!(verify_global_vertex_proof(
            &original,
            &archive.address,
            &vec![0; MAX_GLOBAL_VERTEX_PROOF_BYTES + 1]
        )
        .is_err());
        reopened.prune_to_frame(100).unwrap();
        assert!(reopened
            .global_vertex_membership_at_root(&original, &archive.address)
            .is_err());
    }

    #[test]
    fn membership_at_the_right_address_does_not_substitute_record_identity() {
        let member = [7; 32];
        let filter = [8; 32];
        let leaf = leaf_id_bytes(&filter, &[]);
        let archive = Archive::new(&member, &leaf);
        let original =
            materialize::create_leaf_root_vertex_tree(&member, &filter, &[], 3, &[11; 74], 2, 10)
                .unwrap();
        for (index, field, value) in [
            (1, "Member", vec![9; 32]),
            (2, "ShardFilter", vec![9; 32]),
            (3, "Prefix", vec![0, 0, 0]),
        ] {
            let mut tree = VectorCommitmentTree {
                root: quil_tries::deserialize_go_tree(
                    &quil_tries::serialize_go_tree(original.root.as_ref()).unwrap(),
                )
                .unwrap(),
            };
            global_schema::write_field(&mut tree, "leafroot:LeafRootRegistration", field, &value)
                .unwrap();
            let root = archive.commit(&tree, index);
            let bytes = archive.proof(root);
            assert!(verify_global_vertex_proof(&root, &archive.address, &bytes).is_ok());
            assert!(
                StorageHistory::default()
                    .insert(root, &member, &leaf, 3, &bytes)
                    .is_err(),
                "{field}"
            );
        }
        let mut tree = original;
        global_schema::write_type(&mut tree, "reward:ProverReward").unwrap();
        let root = archive.commit(&tree, 4);
        assert!(StorageHistory::default()
            .insert(root, &member, &leaf, 3, &archive.proof(root))
            .is_err());
    }
}

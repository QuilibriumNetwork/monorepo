//! Bounded reads from the already committed canonical snapshot. Neither the
//! record array nor its values are enumerated after the challenge arrives.
use super::*;
use quil_crypto::storage_proof::{MerkleCap, MerkleTree};
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
    ops::Range,
};

/// Open a node under the registered data root. All returned nodes are checked
/// before their bytes are used as a header, record, or binary-search key.
pub trait BindingSource {
    fn open(&self, index: u64) -> Result<Opening, String>;
}

/// An LRU of at most 64 decoded Merkle subtrees (at most 4 MiB with the
/// production cap height). Reads can come from a snapshot file or R - L.
pub struct SparseData<'a> {
    cap: &'a MerkleCap,
    read: &'a dyn Fn(Range<u64>) -> Result<Vec<u8>, String>,
    cached: RefCell<VecDeque<(u64, MerkleTree)>>,
}

impl<'a> SparseData<'a> {
    pub fn new(
        cap: &'a MerkleCap,
        read: &'a dyn Fn(Range<u64>) -> Result<Vec<u8>, String>,
    ) -> Self {
        Self {
            cap,
            read,
            cached: RefCell::new(VecDeque::new()),
        }
    }
}

impl BindingSource for SparseData<'_> {
    fn open(&self, index: u64) -> Result<Opening, String> {
        if self.cap.height > quil_crypto::storage_proof::CAP_HEIGHT {
            return Err("snapshot cap subtree exceeds sparse memory bound".into());
        }
        let range = self
            .cap
            .subtree(index)
            .ok_or("binding index outside snapshot")?;
        let mut cached = self.cached.borrow_mut();
        let tree = if let Some(at) = cached.iter().position(|(start, _)| *start == range.start) {
            cached.remove(at).unwrap().1
        } else {
            MerkleTree::from_nodes(&(self.read)(range.clone())?)
                .ok_or("noncanonical snapshot subtree")?
        };
        let path = self
            .cap
            .path_from_subtree(&tree, index)
            .ok_or("snapshot subtree differs from data cap")?;
        let node = tree
            .node(index - range.start)
            .ok_or("snapshot subtree is short")?;
        cached.push_front((range.start, tree));
        cached.truncate(64);
        Ok(Opening { node, path })
    }
}

/// The same wire proof as `prove_with_cap`, using only sampled values and
/// O(BINDING_SAMPLES * log(records)) authenticated index reads. The value and
/// state-proof callbacks must read the versions named by `claim.sources`.
pub fn prove_sparse(
    claim: &LeafClaim,
    source: &dyn BindingSource,
    proof_of: &dyn Fn(u8, &[u8; 32]) -> Result<CompactProof, String>,
    value_of: &dyn Fn(u8, &[u8; 32]) -> Result<Vec<u8>, String>,
) -> Result<LeafBinding, String> {
    let cache = RefCell::new(BTreeMap::<u64, Opening>::new());
    let open = |index: u64| -> Result<Opening, String> {
        if let Some(opening) = cache.borrow().get(&index) {
            return Ok(opening.clone());
        }
        let opening = source.open(index)?;
        claim
            .open(&opening, index)
            .ok_or("binding source does not open against registration")?;
        cache.borrow_mut().insert(index, opening.clone());
        Ok(opening)
    };
    let header = header_nodes(claim.filter, claim.prefix);
    let header_openings = (0..header).map(&open).collect::<Result<Vec<_>, _>>()?;
    let bytes: Vec<u8> = header_openings
        .iter()
        .flat_map(|opening| {
            storage_hash::unpack_node(&storage_hash::from_bytes(&opening.node).unwrap()).unwrap()
        })
        .collect();
    let count = u32::from_be_bytes(
        bytes
            .get(1..5)
            .ok_or("short snapshot header")?
            .try_into()
            .unwrap(),
    );
    if bytes != header_bytes(claim.filter, claim.prefix, count) {
        return fail("snapshot header names another leaf");
    }
    let count = u64::from(count);
    let values_start = header
        .checked_add(RECORD_NODES * count)
        .ok_or("snapshot index overflow")?;
    if values_start > claim.n {
        return fail("snapshot index exceeds registration");
    }
    let records = |j: u64| -> Result<Vec<Opening>, String> {
        if j >= count {
            return fail("record outside snapshot index");
        }
        (0..RECORD_NODES)
            .map(|k| open(header + RECORD_NODES * j + k))
            .collect()
    };
    let decode = |nodes: &[Opening]| -> Result<Record, String> {
        let bytes: Vec<u8> = nodes
            .iter()
            .flat_map(|opening| {
                storage_hash::unpack_node(&storage_hash::from_bytes(&opening.node).unwrap())
                    .unwrap()
            })
            .collect();
        Record::decode(&bytes).ok_or("malformed snapshot index record".into())
    };
    let last = if count > 0 {
        records(count - 1)?
    } else {
        Vec::new()
    };
    let exact = match count {
        0 => node_count(header, 0, 0),
        _ => {
            let last = decode(&last)?;
            node_count(
                header,
                count,
                last.offset
                    .checked_add(last.len as u64)
                    .ok_or("snapshot offset overflow")?,
            )
        }
    };
    if !claim.allows_nodes(exact) {
        return fail("snapshot index count differs from registration");
    }
    // As `prove_with_cap`: from the padding bound, record 0 and the first
    // padding node are opened too.
    let bound = quil_types::consensus::storage_padding_bound_at(claim.epoch);
    let mut proved = LeafBinding {
        header: header_openings,
        last,
        first: if bound && count > 1 {
            records(0)?
        } else {
            Vec::new()
        },
        padding: if bound && exact < claim.n {
            Some(open(exact)?)
        } else {
            None
        },
        ..Default::default()
    };
    let value_limit = if quil_types::consensus::persistent_storage_at(claim.epoch) {
        quil_types::consensus::STORAGE_SEAL_BYTES_PER_FRAME
    } else {
        32 << 20
    };
    let mut value_bytes = 0usize;
    if count > 0 {
        for sample in 0..BINDING_SAMPLES {
            let j = claim.record_index(sample, count);
            let mut nodes = records(j)?;
            let record = decode(&nodes)?;
            if j + 1 < count {
                nodes.extend(records(j + 1)?);
            }
            // Refuse an unpublishable proof before loading large blobs. This
            // also bounds memory when one record is sampled repeatedly.
            value_bytes = value_bytes
                .checked_add(record.len as usize)
                .ok_or("binding value bytes overflow")?;
            if record.len as usize > MAX_VALUE || value_bytes > value_limit {
                return fail("sampled values exceed storage proof budget");
            }
            let value = value_of(record.phase, &record.address)?;
            if value.len() != record.len as usize {
                return fail("snapshot value length differs from index");
            }
            let value_node = if record.len == 0 {
                None
            } else {
                let byte = record
                    .offset
                    .checked_add(claim.value_byte(sample, record.len))
                    .ok_or("value offset overflow")?;
                Some(open(
                    values_start
                        .checked_add(byte / DATA_BYTES_PER_NODE as u64)
                        .ok_or("value index overflow")?,
                )?)
            };
            proved.records.push(RecordCheck {
                records: nodes,
                proof: proof_of(record.phase, &record.address)?,
                value,
                value_node,
            });
        }
    }
    for sample in 0..BINDING_SAMPLES {
        let (phase, point) = claim.coverage_point(sample);
        let proof = proof_of(phase, &point)?;
        let record = if let Some(key) = proof
            .leaf
            .map(|(key, _)| key)
            .filter(|key| under(key, &claim.bits))
        {
            let (mut lo, mut hi) = (0, count);
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                let at = decode(&records(mid)?)?.key();
                if at < (phase, key) {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            let nodes = records(lo)?;
            if decode(&nodes)?.key() != (phase, key) {
                return fail("a state key is absent from the snapshot index");
            }
            Some((lo, nodes))
        } else {
            None
        };
        proved.coverage.push(CoverageCheck { proof, record });
    }
    Ok(proved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_crypto::storage_proof::{MerkleCap, Tree, CAP_HEIGHT};
    use std::{cell::Cell, time::Instant};

    // This exercises authenticated DATA-index I/O. State proof verification is
    // covered with real retained forests in the engine tests; these synthetic
    // coverage keys deliberately exercise every binary-search level.
    fn indexed_workload(count: u32) {
        let filter = [7; 32];
        let prefix = [];
        let header = header_bytes(&filter, &prefix, count);
        let header_count = header_nodes(&filter, &prefix);
        let n = node_count(header_count, count as u64, 0);
        let address = |j: u64| {
            let mut key = [0; 32];
            key[..8].copy_from_slice(&j.to_be_bytes());
            key
        };
        let read = |range: Range<u64>| -> Result<Vec<u8>, String> {
            let mut out = Vec::with_capacity((range.end - range.start) as usize * 32);
            for index in range {
                let packed = if index < header_count {
                    let at = index as usize * DATA_BYTES_PER_NODE;
                    storage_hash::pack_node(&header[at..at + DATA_BYTES_PER_NODE])
                } else {
                    let j = (index - header_count) / RECORD_NODES;
                    let record = Record {
                        phase: 0,
                        address: address(j),
                        offset: 0,
                        len: 0,
                    }
                    .encode();
                    let at = ((index - header_count) % RECORD_NODES) as usize * DATA_BYTES_PER_NODE;
                    storage_hash::pack_node(&record[at..at + DATA_BYTES_PER_NODE])
                };
                out.extend_from_slice(&storage_hash::to_bytes(&packed));
            }
            Ok(out)
        };
        let prep = Instant::now();
        let cap = MerkleCap::from_reader(n, CAP_HEIGHT, |r| {
            storage_hash::digests_from_bytes(&read(r).ok()?)
        })
        .unwrap();
        let preparation = prep.elapsed();
        let claim = LeafClaim {
            filter: &filter,
            prefix: &prefix,
            leaf_id: b"indexed load",
            member: &[3; 32],
            epoch: 9,
            beacon: b"beacon",
            bits: Vec::new(),
            sources: Vec::new(),
            comm_d: cap.commitment(Tree::Data),
            n,
        };
        let (reads, bytes, values) = (Cell::new(0u64), Cell::new(0u64), Cell::new(0u64));
        let counted = |range: Range<u64>| {
            reads.set(reads.get() + 1);
            bytes.set(bytes.get() + (range.end - range.start) * 32);
            read(range)
        };
        let source = SparseData::new(&cap, &counted);
        let state_proof = |phase: u8, point: &[u8; 32]| -> Result<CompactProof, String> {
            let j = u64::from_be_bytes(point[..8].try_into().unwrap()) % count as u64;
            Ok(CompactProof {
                leaf: (phase == 0).then_some((address(j), [0; 32])),
                siblings: Vec::new(),
            })
        };
        let started = Instant::now();
        let proved = prove_sparse(&claim, &source, &state_proof, &|_, _| {
            values.set(values.get() + 1);
            Ok(Vec::new())
        })
        .unwrap();
        assert_eq!(values.get(), BINDING_SAMPLES as u64);
        assert_eq!(proved.records.len(), BINDING_SAMPLES);
        let depth = 64 - (count as u64).leading_zeros() as u64;
        let bound = header_count
            + RECORD_NODES
                * (1 + 2 * BINDING_SAMPLES as u64 + BINDING_SAMPLES as u64 * (depth + 1));
        assert!(
            reads.get() <= bound,
            "read {} subtrees > {bound}",
            reads.get()
        );
        assert!(bytes.get() <= bound * (1 << CAP_HEIGHT) * 32);
        assert!(source.cached.borrow().len() <= 64);
        eprintln!("records={count} cap_preparation={preparation:?} proof_prepare={:?} subtree_reads={} bytes_read={} proof_bytes={}",started.elapsed(),reads.get(),bytes.get(),proved.to_bytes().len());
        // Never accept a stale/corrupt subtree through the trusted cap.
        let wrong = |r: Range<u64>| {
            let mut bytes = read(r)?;
            bytes[0] ^= 1;
            Ok(bytes)
        };
        assert!(prove_sparse(
            &claim,
            &SparseData::new(&cap, &wrong),
            &state_proof,
            &|_, _| Ok(Vec::new())
        )
        .is_err());
    }
    #[test]
    fn sparse_index_reads_grow_logarithmically() {
        indexed_workload(10_003);
    }
    #[test]
    #[ignore = "mainnet-sized streaming DATA index; run explicitly on scale hosts"]
    fn mainnet_million_record_index() {
        for count in [1_258_607, 5_033_438] {
            indexed_workload(count);
        }
    }
    #[test]
    fn repeated_large_values_are_refused_before_unbounded_blob_reads() {
        use quil_crypto::storage_proof::{data_nodes, MerkleTree};
        quil_types::consensus::set_persistent_storage_epoch_for_thread(Some(1500));
        let filter = [7; 32];
        let entry = Entry {
            phase: 0,
            address: [8; 32],
            value: vec![3; 1 << 20],
        };
        let mut nodes = data_nodes(&leaf_data(&filter, &[], &[entry.clone()]));
        let n = quil_crypto::persistent_storage::capacity((nodes.len() / 32) as u64).unwrap();
        nodes.resize(n as usize * 32, 0);
        let tree = MerkleTree::from_nodes(&nodes).unwrap();
        let cap = tree.cap(CAP_HEIGHT);
        let claim = LeafClaim {
            filter: &filter,
            prefix: &[],
            leaf_id: b"budget",
            member: &[3; 32],
            epoch: 1500,
            beacon: b"beacon",
            bits: Vec::new(),
            sources: Vec::new(),
            comm_d: cap.commitment(Tree::Data),
            n,
        };
        let read = |r: Range<u64>| Ok(nodes[r.start as usize * 32..r.end as usize * 32].to_vec());
        let source = SparseData::new(&cap, &read);
        let loaded = Cell::new(0);
        let result = prove_sparse(
            &claim,
            &source,
            &|_, _| {
                Ok(CompactProof {
                    leaf: None,
                    siblings: Vec::new(),
                })
            },
            &|_, _| {
                loaded.set(loaded.get() + 1);
                Ok(entry.value.clone())
            },
        );
        assert!(result.unwrap_err().contains("budget"));
        assert_eq!(loaded.get(), 4);
        quil_types::consensus::set_persistent_storage_epoch_for_thread(None);
    }
}

//! Binding a registered leaf's data to the certified state it is read from
//! (hash storage proofs, decided 2026-10-22).
//!
//! A registration commits `comm_D` to a leaf's data, and a seal proves the
//! replica encodes whatever data `comm_D` commits to. What makes that data the
//! shard's is this binding, checked by GLOBAL when it seals the registration
//! from the snapshot roots it recorded (`storage_snapshot`) and nothing else.
//!
//! A leaf's data ([`leaf_data`]) is its header, an index of its entries — one
//! record per vertex or hyperedge added under the leaf's bits, sorted by phase
//! then address, each naming where its value lies — then the values. The
//! state roots authenticate each address's `vertex_commitment(value) ‖ len`
//! but no sums, so an entry's place cannot be proven from them; the index
//! carries the places and the binding samples it, from the seal's beacon:
//!
//! - a record check opens a random record and the next, proves its address
//!   holds that value under the source's root, and opens a random node of the
//!   value against the data: records sorted, places contiguous, values real;
//! - a coverage check proves what a random address under the leaf's bits
//!   finds in the tree, and a key it finds must be indexed: nothing left out.
//!
//! Each check catches a leaf whose records or coverage are wrong in a share ε
//! of its entries with probability ε, by entry rather than by byte (sizes are
//! not authenticated), every epoch it is sealed.

use quil_crypto::storage_proof::{verify_path, Node, Tree, MIN_NODES};
use quil_crypto::storage_hash::{self, DATA_BYTES_PER_NODE};
use quil_forest::subtree_proof::{same_root, subtree_root, CompactProof};
use sha3::{Digest as _, Sha3_256};

/// The leaf-data encoding of hash-proof epochs.
pub const LEAF_DATA_VERSION: u8 = 0x03;

/// The phases a leaf holds: vertex and hyperedge adds. A removal carries no
/// data; the removed value stays in its adds tree.
pub const BOUND_PHASES: [u8; 2] = [0, 2];

/// Record checks and coverage checks per sealed leaf.
pub const BINDING_SAMPLES: usize = 16;

const RECORD_BYTES: usize = 1 + 32 + 8 + 4;
const RECORD_NODES: u64 = 2;
const DST_BINDING: &[u8] = b"quil/storage-binding/v1";

/// One entry of a leaf: an added vertex or hyperedge and its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub phase: u8,
    pub address: [u8; 32],
    pub value: Vec<u8>,
}

/// An index record: an entry's phase, address, and its value's place among
/// the values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub phase: u8,
    pub address: [u8; 32],
    pub offset: u64,
    pub len: u32,
}

impl Record {
    fn encode(&self) -> [u8; RECORD_NODES as usize * DATA_BYTES_PER_NODE] {
        let mut out = [0u8; RECORD_NODES as usize * DATA_BYTES_PER_NODE];
        out[0] = self.phase;
        out[1..33].copy_from_slice(&self.address);
        out[33..41].copy_from_slice(&self.offset.to_be_bytes());
        out[41..45].copy_from_slice(&self.len.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != RECORD_NODES as usize * DATA_BYTES_PER_NODE || bytes[RECORD_BYTES..].iter().any(|&b| b != 0) {
            return None;
        }
        Some(Self {
            phase: bytes[0],
            address: bytes[1..33].try_into().ok()?,
            offset: u64::from_be_bytes(bytes[33..41].try_into().ok()?),
            len: u32::from_be_bytes(bytes[41..45].try_into().ok()?),
        })
    }

    fn key(&self) -> (u8, [u8; 32]) {
        (self.phase, self.address)
    }
}

fn header_bytes(filter: &[u8], prefix: &[u32], entries: u32) -> Vec<u8> {
    let mut out = vec![LEAF_DATA_VERSION];
    out.extend_from_slice(&entries.to_be_bytes());
    out.extend_from_slice(&(filter.len() as u16).to_be_bytes());
    out.extend_from_slice(filter);
    out.extend_from_slice(&(prefix.len() as u16).to_be_bytes());
    for part in prefix {
        out.extend_from_slice(&part.to_be_bytes());
    }
    let padded = out.len().div_ceil(DATA_BYTES_PER_NODE) * DATA_BYTES_PER_NODE;
    out.resize(padded, 0);
    out
}

/// Data nodes a leaf's header takes.
pub fn header_nodes(filter: &[u8], prefix: &[u32]) -> u64 {
    (header_bytes(filter, prefix, 0).len() / DATA_BYTES_PER_NODE) as u64
}

/// A leaf's data: header, index, values. `entries` sorted by phase, address.
pub fn leaf_data(filter: &[u8], prefix: &[u32], entries: &[Entry]) -> Vec<u8> {
    let mut out = header_bytes(filter, prefix, entries.len() as u32);
    let mut offset = 0u64;
    for entry in entries {
        let record = Record { phase: entry.phase, address: entry.address, offset, len: entry.value.len() as u32 };
        out.extend_from_slice(&record.encode());
        offset += entry.value.len() as u64;
    }
    for entry in entries {
        out.extend_from_slice(&entry.value);
    }
    out
}

/// The data nodes of a leaf of `header` nodes and `entries` whose values
/// total `values` bytes.
pub fn node_count(header: u64, entries: u64, values: u64) -> u64 {
    (header + RECORD_NODES * entries + values.div_ceil(DATA_BYTES_PER_NODE as u64)).max(MIN_NODES as u64)
}

/// The leaf a binding is for, and where its data is read from.
pub struct LeafClaim<'a> {
    pub filter: &'a [u8],
    pub prefix: &'a [u32],
    pub leaf_id: &'a [u8],
    pub member: &'a [u8],
    pub epoch: u64,
    /// The seal's beacon.
    pub beacon: &'a [u8],
    /// The leaf's bits in its app tree: the shard's, then the prefix's.
    pub bits: Vec<bool>,
    /// Each snapshot source: its bits and its four phase roots.
    pub sources: Vec<(Vec<bool>, [[u8; 32]; 4])>,
    /// The registration: data commitment and node count.
    pub comm_d: Node,
    pub n: u64,
}

impl LeafClaim<'_> {
    fn challenge(&self, kind: u8, index: u64) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(DST_BINDING);
        h.update([kind]);
        h.update(index.to_be_bytes());
        h.update((self.beacon.len() as u32).to_be_bytes());
        h.update(self.beacon);
        h.update((self.leaf_id.len() as u32).to_be_bytes());
        h.update(self.leaf_id);
        h.update((self.member.len() as u32).to_be_bytes());
        h.update(self.member);
        h.update(self.epoch.to_be_bytes());
        h.finalize().into()
    }

    /// The record a record check opens, of `entries`.
    pub fn record_index(&self, sample: usize, entries: u64) -> u64 {
        u64::from_be_bytes(self.challenge(0, sample as u64)[..8].try_into().expect("8 bytes")) % entries.max(1)
    }

    /// The byte of the record's value a record check opens, of `len`.
    pub fn value_byte(&self, sample: usize, len: u32) -> u64 {
        u64::from_be_bytes(self.challenge(1, sample as u64)[..8].try_into().expect("8 bytes")) % (len.max(1) as u64)
    }

    /// The address and phase a coverage check proves: random, under the
    /// leaf's bits.
    pub fn coverage_point(&self, sample: usize) -> (u8, [u8; 32]) {
        let mut point = self.challenge(2, sample as u64);
        for (i, &bit) in self.bits.iter().enumerate().take(256) {
            let mask = 0x80u8 >> (i % 8);
            if bit {
                point[i / 8] |= mask;
            } else {
                point[i / 8] &= !mask;
            }
        }
        let phase = BOUND_PHASES[(self.challenge(3, sample as u64)[0] % BOUND_PHASES.len() as u8) as usize];
        (phase, point)
    }

    /// The source whose subtree holds `address`.
    fn source_of(&self, address: &[u8; 32]) -> Option<&(Vec<bool>, [[u8; 32]; 4])> {
        self.sources.iter().find(|(bits, _)| under(address, bits))
    }

    fn open(&self, opening: &Opening, index: u64) -> Option<[u8; DATA_BYTES_PER_NODE]> {
        if !verify_path(Tree::Data, self.n, &self.comm_d, index, &opening.node, &opening.path) {
            return None;
        }
        storage_hash::unpack_node(&storage_hash::from_bytes(&opening.node)?)
    }
}

/// Whether `address` starts with `bits`.
pub fn under(address: &[u8; 32], bits: &[bool]) -> bool {
    bits.len() <= 256 && bits.iter().enumerate().all(|(i, &bit)| (address[i / 8] & (0x80 >> (i % 8)) != 0) == bit)
}

/// Whether leaves at these bits below a shard's tile it: none is under
/// another, and together they cover it.
pub fn tiles(leaves: &[Vec<bool>]) -> bool {
    use num_bigint::BigUint;
    let mut sorted = leaves.to_vec();
    sorted.sort();
    if sorted.is_empty() || sorted.iter().any(|leaf| leaf.len() > 256) || sorted.windows(2).any(|pair| pair[1].starts_with(&pair[0])) {
        return false;
    }
    let total: BigUint = sorted.iter().map(|leaf| BigUint::from(1u8) << (256 - leaf.len())).sum();
    total == BigUint::from(1u8) << 256usize
}

/// A data node and its path in the leaf's data tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    pub node: Node,
    pub path: Vec<Node>,
}

/// A record check: records `j` and `j + 1` (one when `j` is the last), the
/// proof of record `j`'s address in its phase, its value, and the opened
/// node of the value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordCheck {
    pub records: Vec<Opening>,
    pub proof: CompactProof,
    pub value: Vec<u8>,
    pub value_node: Option<Opening>,
}

/// A coverage check: the proof of the point in its phase, and, when it finds
/// a key under the leaf's bits, that key's record and its index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageCheck {
    pub proof: CompactProof,
    pub record: Option<(u64, Vec<Opening>)>,
}

/// A sealed leaf's binding.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LeafBinding {
    /// The header's nodes.
    pub header: Vec<Opening>,
    /// The last record's nodes, which fix where the values end.
    pub last: Vec<Opening>,
    pub records: Vec<RecordCheck>,
    pub coverage: Vec<CoverageCheck>,
}

/// Why a binding does not hold.
fn fail<T>(what: &str) -> Result<T, String> {
    Err(format!("storage binding: {what}"))
}

/// Check `binding` of the leaf `claim` describes.
pub fn verify(claim: &LeafClaim, binding: &LeafBinding) -> Result<(), String> {
    let header_count = header_nodes(claim.filter, claim.prefix);
    if binding.header.len() as u64 != header_count {
        return fail("header nodes");
    }
    let mut header = Vec::with_capacity(header_count as usize * DATA_BYTES_PER_NODE);
    for (index, opening) in binding.header.iter().enumerate() {
        header.extend_from_slice(&claim.open(opening, index as u64).ok_or("storage binding: a header node does not open")?);
    }
    let entries = u32::from_be_bytes(header.get(1..5).ok_or("storage binding: short header")?.try_into().expect("4 bytes"));
    if header != header_bytes(claim.filter, claim.prefix, entries) {
        return fail("the header names another leaf");
    }
    let entries = entries as u64;
    let open_record = |openings: &[Opening], index: u64| -> Result<Record, String> {
        let first = header_count + RECORD_NODES * index;
        let mut bytes = Vec::with_capacity(RECORD_NODES as usize * DATA_BYTES_PER_NODE);
        for (k, opening) in openings.iter().enumerate() {
            bytes.extend_from_slice(&claim.open(opening, first + k as u64).ok_or("storage binding: a record node does not open")?);
        }
        let record = Record::decode(&bytes).ok_or("storage binding: a malformed record")?;
        if !BOUND_PHASES.contains(&record.phase) || !under(&record.address, &claim.bits) {
            return fail("a record outside the leaf");
        }
        Ok(record)
    };
    let values_start = header_count + RECORD_NODES * entries;
    if entries == 0 {
        if !binding.last.is_empty() || !binding.records.is_empty() || claim.n != node_count(header_count, 0, 0) {
            return fail("an empty leaf's size");
        }
    } else {
        if binding.last.len() as u64 != RECORD_NODES {
            return fail("the last record");
        }
        let last = open_record(&binding.last, entries - 1)?;
        if claim.n != node_count(header_count, entries, last.offset + last.len as u64) {
            return fail("the node count is not the index's");
        }
        if binding.records.len() != BINDING_SAMPLES {
            return fail("record checks");
        }
        for (sample, check) in binding.records.iter().enumerate() {
            let j = claim.record_index(sample, entries);
            let pair = if j + 1 < entries { 2 * RECORD_NODES } else { RECORD_NODES } as usize;
            if check.records.len() != pair {
                return fail("record check nodes");
            }
            let record = open_record(&check.records[..RECORD_NODES as usize], j)?;
            if j + 1 < entries {
                let next = open_record(&check.records[RECORD_NODES as usize..], j + 1)?;
                if next.key() <= record.key() || next.offset != record.offset + record.len as u64 {
                    return fail("records out of order or not contiguous");
                }
            }
            let (source_bits, roots) = claim.source_of(&record.address).ok_or("storage binding: a record no source holds")?;
            let root = subtree_root(&check.proof, &record.address, source_bits.len()).ok_or("storage binding: a malformed proof")?;
            let value_hash: [u8; 32] = {
                use sha2::Digest as _;
                let leaf_value = quil_tries::vertex_leaf_value(&check.value).map_err(|e| format!("storage binding: {e}"))?;
                sha2::Sha256::digest(&leaf_value).into()
            };
            if !same_root(&root, &roots[record.phase as usize])
                || check.proof.leaf != Some((record.address, value_hash))
                || check.value.len() != record.len as usize
            {
                return fail("a record the state does not hold");
            }
            match (&check.value_node, record.len) {
                (None, 0) => {}
                (Some(opening), len) if len > 0 => {
                    let byte = record.offset + claim.value_byte(sample, len);
                    let node = values_start + byte / DATA_BYTES_PER_NODE as u64;
                    let bytes = claim.open(opening, node).ok_or("storage binding: a value node does not open")?;
                    let node_start = (node - values_start) * DATA_BYTES_PER_NODE as u64;
                    for (k, &b) in bytes.iter().enumerate() {
                        let at = node_start + k as u64;
                        if at >= record.offset && at < record.offset + len as u64 && b != check.value[(at - record.offset) as usize] {
                            return fail("a value the data does not hold");
                        }
                    }
                }
                _ => return fail("a value node"),
            }
        }
    }
    if binding.coverage.len() != BINDING_SAMPLES {
        return fail("coverage checks");
    }
    for (sample, check) in binding.coverage.iter().enumerate() {
        let (phase, point) = claim.coverage_point(sample);
        let (source_bits, roots) = claim.source_of(&point).ok_or("storage binding: a point no source holds")?;
        let root = subtree_root(&check.proof, &point, source_bits.len()).ok_or("storage binding: a malformed proof")?;
        if !same_root(&root, &roots[phase as usize]) {
            return fail("a coverage proof the state does not hold");
        }
        let found = check.proof.leaf.map(|(key, _)| key).filter(|key| under(key, &claim.bits));
        match (found, &check.record) {
            (None, None) => {}
            (Some(key), Some((index, openings))) => {
                if *index >= entries || openings.len() as u64 != RECORD_NODES {
                    return fail("a coverage record");
                }
                let record = open_record(openings, *index)?;
                if record.key() != (phase, key) {
                    return fail("a key the index leaves out");
                }
            }
            _ => return fail("a coverage check"),
        }
    }
    Ok(())
}

/// Prove the binding of the leaf `claim` describes, whose data is
/// `entries` ([`leaf_data`]); `proof_of` proves an address in a phase from
/// the source holding it. Fails when `claim` registers other data.
pub fn prove(
    claim: &LeafClaim,
    entries: &[Entry],
    proof_of: &dyn Fn(u8, &[u8; 32]) -> Result<CompactProof, String>,
) -> Result<LeafBinding, String> {
    use quil_crypto::storage_proof::{data_nodes, MerkleTree, NODE_BYTES};
    let data = leaf_data(claim.filter, claim.prefix, entries);
    let nodes = data_nodes(&data);
    let tree = MerkleTree::from_nodes(&nodes).ok_or("storage binding: no data tree")?;
    if tree.commitment(Tree::Data) != claim.comm_d || tree.n() != claim.n {
        return fail("the registration is not this snapshot's data");
    }
    let open = |index: u64| Opening {
        node: nodes[index as usize * NODE_BYTES..][..NODE_BYTES].try_into().expect("a node"),
        path: tree.path(index),
    };
    let header = header_nodes(claim.filter, claim.prefix);
    let count = entries.len() as u64;
    let record_nodes = |j: u64| (0..RECORD_NODES).map(|k| open(header + RECORD_NODES * j + k)).collect::<Vec<_>>();
    let mut offsets = Vec::with_capacity(entries.len());
    let mut offset = 0u64;
    for entry in entries {
        offsets.push(offset);
        offset += entry.value.len() as u64;
    }
    let values_start = header + RECORD_NODES * count;
    let mut proved = LeafBinding {
        header: (0..header).map(open).collect(),
        last: if count > 0 { record_nodes(count - 1) } else { Vec::new() },
        ..Default::default()
    };
    if count > 0 {
        for sample in 0..BINDING_SAMPLES {
            let j = claim.record_index(sample, count);
            let entry = &entries[j as usize];
            let mut records = record_nodes(j);
            if j + 1 < count {
                records.extend(record_nodes(j + 1));
            }
            let len = entry.value.len() as u32;
            let value_node = (len > 0).then(|| {
                let byte = offsets[j as usize] + claim.value_byte(sample, len);
                open(values_start + byte / DATA_BYTES_PER_NODE as u64)
            });
            proved.records.push(RecordCheck {
                records,
                proof: proof_of(entry.phase, &entry.address)?,
                value: entry.value.clone(),
                value_node,
            });
        }
    }
    for sample in 0..BINDING_SAMPLES {
        let (phase, point) = claim.coverage_point(sample);
        let proof = proof_of(phase, &point)?;
        let record = match proof.leaf.map(|(key, _)| key).filter(|key| under(key, &claim.bits)) {
            Some(key) => {
                let j = entries.binary_search_by(|entry| (entry.phase, entry.address).cmp(&(phase, key)))
                    .map_err(|_| "storage binding: a key the snapshot does not index".to_string())?;
                Some((j as u64, record_nodes(j as u64)))
            }
            None => None,
        };
        proved.coverage.push(CoverageCheck { proof, record });
    }
    Ok(proved)
}

// ---- encoding ---------------------------------------------------------------

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn put_openings(out: &mut Vec<u8>, openings: &[Opening]) {
    out.extend_from_slice(&(openings.len() as u16).to_be_bytes());
    for opening in openings {
        out.extend_from_slice(&opening.node);
        out.push(opening.path.len() as u8);
        for node in &opening.path {
            out.extend_from_slice(node);
        }
    }
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let bytes = self.data.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(bytes)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<usize> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?) as usize)
    }
    fn u32(&mut self) -> Option<usize> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?) as usize)
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    fn node(&mut self) -> Option<Node> {
        self.take(32)?.try_into().ok()
    }
    fn bytes(&mut self, max: usize) -> Option<Vec<u8>> {
        let len = self.u32()?;
        (len <= max).then_some(())?;
        Some(self.take(len)?.to_vec())
    }
    fn openings(&mut self) -> Option<Vec<Opening>> {
        let count = self.u16()?;
        if count > 64 {
            return None;
        }
        (0..count)
            .map(|_| {
                let node = self.node()?;
                let depth = self.u8()? as usize;
                Some(Opening { node, path: (0..depth).map(|_| self.node()).collect::<Option<_>>()? })
            })
            .collect()
    }
    fn proof(&mut self) -> Option<CompactProof> {
        CompactProof::from_bytes(&self.bytes(67 + 32 * 256)?)
    }
}

/// The largest value a record check carries.
const MAX_VALUE: usize = 16 << 20;

impl LeafBinding {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_openings(&mut out, &self.header);
        put_openings(&mut out, &self.last);
        out.extend_from_slice(&(self.records.len() as u16).to_be_bytes());
        for check in &self.records {
            put_openings(&mut out, &check.records);
            put_bytes(&mut out, &check.proof.to_bytes());
            put_bytes(&mut out, &check.value);
            put_openings(&mut out, check.value_node.as_slice());
        }
        out.extend_from_slice(&(self.coverage.len() as u16).to_be_bytes());
        for check in &self.coverage {
            put_bytes(&mut out, &check.proof.to_bytes());
            match &check.record {
                Some((index, openings)) => {
                    out.push(1);
                    out.extend_from_slice(&index.to_be_bytes());
                    put_openings(&mut out, openings);
                }
                None => out.push(0),
            }
        }
        out
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        let mut r = Reader { data, at: 0 };
        let header = r.openings()?;
        let last = r.openings()?;
        let record_count = r.u16()?;
        if record_count > BINDING_SAMPLES {
            return None;
        }
        let mut records = Vec::with_capacity(record_count);
        for _ in 0..record_count {
            let nodes = r.openings()?;
            let proof = r.proof()?;
            let value = r.bytes(MAX_VALUE)?;
            let value_node = r.openings()?;
            if value_node.len() > 1 {
                return None;
            }
            records.push(RecordCheck { records: nodes, proof, value, value_node: value_node.into_iter().next() });
        }
        let coverage_count = r.u16()?;
        if coverage_count > BINDING_SAMPLES {
            return None;
        }
        let mut coverage = Vec::with_capacity(coverage_count);
        for _ in 0..coverage_count {
            let proof = r.proof()?;
            let record = match r.u8()? {
                0 => None,
                1 => Some((r.u64()?, r.openings()?)),
                _ => return None,
            };
            coverage.push(CoverageCheck { proof, record });
        }
        (r.at == data.len()).then_some(Self { header, last, records, coverage })
    }
}

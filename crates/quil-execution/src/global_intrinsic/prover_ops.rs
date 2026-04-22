//! Remaining global prover ops canonical-bytes:
//! ProverConfirm, ProverReject, ProverKick, ProverUpdate,
//! ProverSeniorityMerge, ShardSplit, ShardMerge.

use quil_types::error::{QuilError, Result};
use crate::canonical_cursor::{put_u32, put_u64, read_u32, read_u64, read_bytes};
use super::addressed_signature::AddressedSignature;
use super::seniority_merge::SeniorityMerge;
fn read_opt_addr_sig(buf: &[u8], c: &mut usize) -> Result<Option<AddressedSignature>> {
    let l = read_u32(buf, c)? as usize;
    if l > 118 { return Err(QuilError::InvalidArgument(format!("sig too long: {}", l))); }
    if l == 0 { return Ok(None); }
    let b = read_bytes(buf, c, l)?;
    Ok(Some(AddressedSignature::from_canonical_bytes(&b)?))
}
fn write_opt_addr_sig(out: &mut Vec<u8>, sig: Option<&AddressedSignature>) -> Result<()> {
    match sig { Some(s) => { let b = s.to_canonical_bytes()?; put_u32(out, b.len() as u32); out.extend_from_slice(&b); } None => put_u32(out, 0), }
    Ok(())
}
fn read_filters(buf: &[u8], c: &mut usize) -> Result<Vec<Vec<u8>>> {
    let n = read_u32(buf, c)?;
    if n > 100 { return Err(QuilError::InvalidArgument(format!("too many filters: {}", n))); }
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n { let l = read_u32(buf, c)?; if l > 64 { return Err(QuilError::InvalidArgument(format!("filter too long: {}", l))); } out.push(read_bytes(buf, c, l as usize)?); }
    Ok(out)
}
fn write_filters(out: &mut Vec<u8>, filters: &[Vec<u8>]) {
    put_u32(out, filters.len() as u32);
    for f in filters { put_u32(out, f.len() as u32); out.extend_from_slice(f); }
}

// =====================================================================
// ProverConfirm (0x0305)
// =====================================================================
pub const TYPE_PROVER_CONFIRM: u32 = 0x0305;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProverConfirm {
    pub filter: Vec<u8>,
    pub frame_number: u64,
    pub public_key_signature_bls48581: Option<AddressedSignature>,
    pub filters: Vec<Vec<u8>>,
}

impl ProverConfirm {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PROVER_CONFIRM);
        // Go writes a deprecated filter field: always u32(32) + "reserved" × 4.
        // See protobufs/global.go ProverConfirm.ToCanonicalBytes().
        put_u32(&mut out, 32);
        out.extend_from_slice(b"reservedreservedreservedreserved");
        put_u64(&mut out, self.frame_number);
        write_opt_addr_sig(&mut out, self.public_key_signature_bls48581.as_ref())?;
        write_filters(&mut out, &self.filters);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_PROVER_CONFIRM { return Err(QuilError::InvalidArgument(format!("ProverConfirm: bad type 0x{:08x}", tp))); }
        // Read and discard the deprecated filter field (32 bytes of "reserved")
        let fl = read_u32(data, &mut c)?; if fl > 64 { return Err(QuilError::InvalidArgument("ProverConfirm: filter too long".into())); }
        let filter = read_bytes(data, &mut c, fl as usize)?;
        let frame_number = read_u64(data, &mut c)?;
        let sig = read_opt_addr_sig(data, &mut c)?;
        let filters = read_filters(data, &mut c)?;
        Ok(Self { filter, frame_number, public_key_signature_bls48581: sig, filters })
    }
}

// =====================================================================
// ProverReject (0x0306)
// =====================================================================
pub const TYPE_PROVER_REJECT: u32 = 0x0306;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProverReject {
    pub filter: Vec<u8>,
    pub frame_number: u64,
    pub public_key_signature_bls48581: Option<AddressedSignature>,
    pub filters: Vec<Vec<u8>>,
}

impl ProverReject {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PROVER_REJECT);
        // Go writes deprecated filter: always u32(32) + "reserved" × 4
        put_u32(&mut out, 32);
        out.extend_from_slice(b"reservedreservedreservedreserved");
        put_u64(&mut out, self.frame_number);
        write_opt_addr_sig(&mut out, self.public_key_signature_bls48581.as_ref())?;
        write_filters(&mut out, &self.filters);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_PROVER_REJECT { return Err(QuilError::InvalidArgument(format!("ProverReject: bad type 0x{:08x}", tp))); }
        let fl = read_u32(data, &mut c)?; if fl > 64 { return Err(QuilError::InvalidArgument("ProverReject: filter too long".into())); }
        let filter = read_bytes(data, &mut c, fl as usize)?;
        let frame_number = read_u64(data, &mut c)?;
        let sig = read_opt_addr_sig(data, &mut c)?;
        let filters = read_filters(data, &mut c)?;
        Ok(Self { filter, frame_number, public_key_signature_bls48581: sig, filters })
    }
}

// =====================================================================
// ProverKick (0x0307)
// =====================================================================
pub const TYPE_PROVER_KICK: u32 = 0x0307;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProverKick {
    pub frame_number: u64,
    pub kicked_prover_public_key: Vec<u8>,
    pub conflicting_frame_1: Vec<u8>,
    pub conflicting_frame_2: Vec<u8>,
    pub commitment: Vec<u8>,
    pub proof: Vec<u8>,
    pub traversal_proof: Vec<u8>,
}

impl ProverKick {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PROVER_KICK);
        put_u64(&mut out, self.frame_number);
        put_u32(&mut out, self.kicked_prover_public_key.len() as u32); out.extend_from_slice(&self.kicked_prover_public_key);
        put_u32(&mut out, self.conflicting_frame_1.len() as u32); out.extend_from_slice(&self.conflicting_frame_1);
        put_u32(&mut out, self.conflicting_frame_2.len() as u32); out.extend_from_slice(&self.conflicting_frame_2);
        put_u32(&mut out, self.commitment.len() as u32); out.extend_from_slice(&self.commitment);
        put_u32(&mut out, self.proof.len() as u32); out.extend_from_slice(&self.proof);
        put_u32(&mut out, self.traversal_proof.len() as u32); out.extend_from_slice(&self.traversal_proof);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_PROVER_KICK { return Err(QuilError::InvalidArgument(format!("ProverKick: bad type 0x{:08x}", tp))); }
        let frame_number = read_u64(data, &mut c)?;
        let kl = read_u32(data, &mut c)?; if kl > 585 { return Err(QuilError::InvalidArgument("ProverKick: key too long".into())); }
        let kicked = read_bytes(data, &mut c, kl as usize)?;
        let cf1l = read_u32(data, &mut c)?; if cf1l > 34825 { return Err(QuilError::InvalidArgument("ProverKick: cf1 too long".into())); }
        let cf1 = read_bytes(data, &mut c, cf1l as usize)?;
        let cf2l = read_u32(data, &mut c)?; if cf2l > 34825 { return Err(QuilError::InvalidArgument("ProverKick: cf2 too long".into())); }
        let cf2 = read_bytes(data, &mut c, cf2l as usize)?;
        let cl = read_u32(data, &mut c)?; if cl > 74 { return Err(QuilError::InvalidArgument("ProverKick: commit too long".into())); }
        let commitment = read_bytes(data, &mut c, cl as usize)?;
        let pl = read_u32(data, &mut c)?; if pl > 160 { return Err(QuilError::InvalidArgument("ProverKick: proof too long".into())); }
        let proof = read_bytes(data, &mut c, pl as usize)?;
        let tl = read_u32(data, &mut c)?; if tl > 4000 { return Err(QuilError::InvalidArgument("ProverKick: traversal too long".into())); }
        let traversal_proof = read_bytes(data, &mut c, tl as usize)?;
        Ok(Self { frame_number, kicked_prover_public_key: kicked, conflicting_frame_1: cf1, conflicting_frame_2: cf2, commitment, proof, traversal_proof })
    }
}

// =====================================================================
// ProverUpdate (0x0308)
// =====================================================================
pub const TYPE_PROVER_UPDATE: u32 = 0x0308;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProverUpdate {
    pub delegate_address: Vec<u8>,
    pub public_key_signature_bls48581: Option<AddressedSignature>,
}

impl ProverUpdate {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PROVER_UPDATE);
        put_u32(&mut out, self.delegate_address.len() as u32); out.extend_from_slice(&self.delegate_address);
        write_opt_addr_sig(&mut out, self.public_key_signature_bls48581.as_ref())?;
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_PROVER_UPDATE { return Err(QuilError::InvalidArgument(format!("ProverUpdate: bad type 0x{:08x}", tp))); }
        let dl = read_u32(data, &mut c)?; if dl > 32 { return Err(QuilError::InvalidArgument("ProverUpdate: addr too long".into())); }
        let delegate_address = read_bytes(data, &mut c, dl as usize)?;
        let sig = read_opt_addr_sig(data, &mut c)?;
        Ok(Self { delegate_address, public_key_signature_bls48581: sig })
    }
}

// =====================================================================
// ProverSeniorityMerge (0x031A)
// =====================================================================
pub const TYPE_PROVER_SENIORITY_MERGE: u32 = 0x031A;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProverSeniorityMerge {
    pub frame_number: u64,
    pub public_key_signature_bls48581: Option<AddressedSignature>,
    pub merge_targets: Vec<SeniorityMerge>,
}

impl ProverSeniorityMerge {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PROVER_SENIORITY_MERGE);
        put_u64(&mut out, self.frame_number);
        write_opt_addr_sig(&mut out, self.public_key_signature_bls48581.as_ref())?;
        put_u32(&mut out, self.merge_targets.len() as u32);
        for mt in &self.merge_targets {
            let mb = mt.to_canonical_bytes()?;
            put_u32(&mut out, mb.len() as u32); out.extend_from_slice(&mb);
        }
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_PROVER_SENIORITY_MERGE { return Err(QuilError::InvalidArgument(format!("ProverSeniorityMerge: bad type 0x{:08x}", tp))); }
        let frame_number = read_u64(data, &mut c)?;
        let sig = read_opt_addr_sig(data, &mut c)?;
        let n = read_u32(data, &mut c)?;
        if n > 100 { return Err(QuilError::InvalidArgument("ProverSeniorityMerge: too many targets".into())); }
        let mut merge_targets = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let l = read_u32(data, &mut c)?; if l > 1000 { return Err(QuilError::InvalidArgument("ProverSeniorityMerge: target too long".into())); }
            let b = read_bytes(data, &mut c, l as usize)?;
            merge_targets.push(SeniorityMerge::from_canonical_bytes(&b)?);
        }
        Ok(Self { frame_number, public_key_signature_bls48581: sig, merge_targets })
    }
}

// =====================================================================
// ShardSplit (0x031E)
// =====================================================================
pub const TYPE_SHARD_SPLIT: u32 = 0x031E;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShardSplit {
    pub shard_address: Vec<u8>,
    pub proposed_shards: Vec<Vec<u8>>,
    pub frame_number: u64,
    pub public_key_signature_bls48581: Option<AddressedSignature>,
}

impl ShardSplit {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_SHARD_SPLIT);
        put_u32(&mut out, self.shard_address.len() as u32); out.extend_from_slice(&self.shard_address);
        put_u32(&mut out, self.proposed_shards.len() as u32);
        for s in &self.proposed_shards { put_u32(&mut out, s.len() as u32); out.extend_from_slice(s); }
        put_u64(&mut out, self.frame_number);
        write_opt_addr_sig(&mut out, self.public_key_signature_bls48581.as_ref())?;
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_SHARD_SPLIT { return Err(QuilError::InvalidArgument(format!("ShardSplit: bad type 0x{:08x}", tp))); }
        let sal = read_u32(data, &mut c)?; if sal > 64 { return Err(QuilError::InvalidArgument("ShardSplit: shard_address too long".into())); }
        let shard_address = read_bytes(data, &mut c, sal as usize)?;
        let pn = read_u32(data, &mut c)?; if pn > 8 { return Err(QuilError::InvalidArgument("ShardSplit: too many proposed".into())); }
        let mut proposed_shards = Vec::with_capacity(pn as usize);
        for _ in 0..pn { let l = read_u32(data, &mut c)?; if l > 66 { return Err(QuilError::InvalidArgument("ShardSplit: proposed too long".into())); } proposed_shards.push(read_bytes(data, &mut c, l as usize)?); }
        let frame_number = read_u64(data, &mut c)?;
        let sig = read_opt_addr_sig(data, &mut c)?;
        Ok(Self { shard_address, proposed_shards, frame_number, public_key_signature_bls48581: sig })
    }
}

// =====================================================================
// ShardMerge (0x031F)
// =====================================================================
pub const TYPE_SHARD_MERGE: u32 = 0x031F;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShardMerge {
    pub shard_addresses: Vec<Vec<u8>>,
    pub parent_address: Vec<u8>,
    pub frame_number: u64,
    pub public_key_signature_bls48581: Option<AddressedSignature>,
}

impl ShardMerge {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_SHARD_MERGE);
        put_u32(&mut out, self.shard_addresses.len() as u32);
        for s in &self.shard_addresses { put_u32(&mut out, s.len() as u32); out.extend_from_slice(s); }
        put_u32(&mut out, self.parent_address.len() as u32); out.extend_from_slice(&self.parent_address);
        put_u64(&mut out, self.frame_number);
        write_opt_addr_sig(&mut out, self.public_key_signature_bls48581.as_ref())?;
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_SHARD_MERGE { return Err(QuilError::InvalidArgument(format!("ShardMerge: bad type 0x{:08x}", tp))); }
        let n = read_u32(data, &mut c)?; if n > 8 { return Err(QuilError::InvalidArgument("ShardMerge: too many shards".into())); }
        let mut shard_addresses = Vec::with_capacity(n as usize);
        for _ in 0..n { let l = read_u32(data, &mut c)?; if l > 64 { return Err(QuilError::InvalidArgument("ShardMerge: shard too long".into())); } shard_addresses.push(read_bytes(data, &mut c, l as usize)?); }
        let pal = read_u32(data, &mut c)?; if pal > 64 { return Err(QuilError::InvalidArgument("ShardMerge: parent too long".into())); }
        let parent_address = read_bytes(data, &mut c, pal as usize)?;
        let frame_number = read_u64(data, &mut c)?;
        let sig = read_opt_addr_sig(data, &mut c)?;
        Ok(Self { shard_addresses, parent_address, frame_number, public_key_signature_bls48581: sig })
    }
}

// =====================================================================
// Tests
// =====================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn addr_sig() -> AddressedSignature {
        AddressedSignature { signature: vec![0xAAu8; 74], address: vec![0xBBu8; 32] }
    }

    fn merge_target() -> SeniorityMerge {
        SeniorityMerge { signature: vec![0x11u8; 74], key_type: 2, prover_public_key: vec![0x22u8; 57] }
    }

    // -- ProverConfirm --
    #[test]
    fn confirm_round_trip() {
        let c = ProverConfirm { filter: vec![], frame_number: 42, public_key_signature_bls48581: Some(addr_sig()), filters: vec![vec![1u8; 8], vec![2u8; 16]] };
        let b = c.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_PROVER_CONFIRM.to_be_bytes());
        let decoded = ProverConfirm::from_canonical_bytes(&b).unwrap();
        // The deprecated filter field is always written as "reserved" × 4
        assert_eq!(decoded.filter, b"reservedreservedreservedreserved".to_vec());
        assert_eq!(decoded.frame_number, 42);
        assert_eq!(decoded.filters, vec![vec![1u8; 8], vec![2u8; 16]]);
    }
    #[test]
    fn confirm_minimal() {
        let c = ProverConfirm::default();
        let b = c.to_canonical_bytes().unwrap();
        let decoded = ProverConfirm::from_canonical_bytes(&b).unwrap();
        assert_eq!(decoded.filter, b"reservedreservedreservedreserved".to_vec());
        assert_eq!(decoded.frame_number, 0);
        assert!(decoded.filters.is_empty());
    }

    // -- ProverReject --
    #[test]
    fn reject_round_trip() {
        let r = ProverReject { filter: vec![], frame_number: 7, public_key_signature_bls48581: Some(addr_sig()), filters: vec![vec![3u8; 32]] };
        let b = r.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_PROVER_REJECT.to_be_bytes());
        let decoded = ProverReject::from_canonical_bytes(&b).unwrap();
        assert_eq!(decoded.filter, b"reservedreservedreservedreserved".to_vec());
        assert_eq!(decoded.frame_number, 7);
        assert_eq!(decoded.filters, vec![vec![3u8; 32]]);
    }

    // -- ProverKick --
    #[test]
    fn kick_round_trip() {
        let k = ProverKick { frame_number: 100, kicked_prover_public_key: vec![0xCCu8; 585], conflicting_frame_1: vec![1u8; 100], conflicting_frame_2: vec![2u8; 100], commitment: vec![3u8; 74], proof: vec![4u8; 64], traversal_proof: vec![5u8; 200] };
        let b = k.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_PROVER_KICK.to_be_bytes());
        assert_eq!(ProverKick::from_canonical_bytes(&b).unwrap(), k);
    }
    #[test]
    fn kick_minimal() {
        let k = ProverKick::default();
        let b = k.to_canonical_bytes().unwrap();
        assert_eq!(ProverKick::from_canonical_bytes(&b).unwrap(), k);
    }

    // -- ProverUpdate --
    #[test]
    fn update_round_trip() {
        let u = ProverUpdate { delegate_address: vec![0xDDu8; 32], public_key_signature_bls48581: Some(addr_sig()) };
        let b = u.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_PROVER_UPDATE.to_be_bytes());
        assert_eq!(ProverUpdate::from_canonical_bytes(&b).unwrap(), u);
    }
    #[test]
    fn update_minimal() {
        let u = ProverUpdate::default();
        let b = u.to_canonical_bytes().unwrap();
        assert_eq!(ProverUpdate::from_canonical_bytes(&b).unwrap(), u);
    }

    // -- ProverSeniorityMerge --
    #[test]
    fn seniority_merge_round_trip() {
        let s = ProverSeniorityMerge { frame_number: 999, public_key_signature_bls48581: Some(addr_sig()), merge_targets: vec![merge_target(), merge_target()] };
        let b = s.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_PROVER_SENIORITY_MERGE.to_be_bytes());
        assert_eq!(ProverSeniorityMerge::from_canonical_bytes(&b).unwrap(), s);
    }

    // -- ShardSplit --
    #[test]
    fn shard_split_round_trip() {
        let s = ShardSplit { shard_address: vec![0xAAu8; 32], proposed_shards: vec![vec![1u8; 33], vec![2u8; 33]], frame_number: 50, public_key_signature_bls48581: Some(addr_sig()) };
        let b = s.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_SHARD_SPLIT.to_be_bytes());
        assert_eq!(ShardSplit::from_canonical_bytes(&b).unwrap(), s);
    }

    // -- ShardMerge --
    #[test]
    fn shard_merge_round_trip() {
        let m = ShardMerge { shard_addresses: vec![vec![1u8; 32], vec![2u8; 32]], parent_address: vec![3u8; 32], frame_number: 60, public_key_signature_bls48581: Some(addr_sig()) };
        let b = m.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_SHARD_MERGE.to_be_bytes());
        assert_eq!(ShardMerge::from_canonical_bytes(&b).unwrap(), m);
    }

    // -- Cross-type --
    #[test]
    fn type_prefixes_all_distinct() {
        use std::collections::HashSet;
        let ids: HashSet<u32> = [TYPE_PROVER_CONFIRM, TYPE_PROVER_REJECT, TYPE_PROVER_KICK, TYPE_PROVER_UPDATE, TYPE_PROVER_SENIORITY_MERGE, TYPE_SHARD_SPLIT, TYPE_SHARD_MERGE].into_iter().collect();
        assert_eq!(ids.len(), 7);
    }
}

//! Remaining global prover ops canonical-bytes:
//! ProverConfirm, ProverReject, ProverKick, ProverUpdate,
//! ProverSeniorityMerge, ShardSplit, ShardMerge.

use super::addressed_signature::AddressedSignature;
use super::seniority_merge::SeniorityMerge;
use crate::canonical_cursor::{put_u32, put_u64, read_bytes, read_u32, read_u64};
use quil_types::error::{QuilError, Result};
fn read_opt_addr_sig(buf: &[u8], c: &mut usize) -> Result<Option<AddressedSignature>> {
    let l = read_u32(buf, c)? as usize;
    // Falcon-512 addressed-sig envelope: 710 (single) / 1226 (aggregate-1).
    // See `MAX_ADDRESSED_SIG_LEN`.
    if l > super::addressed_signature::MAX_ADDRESSED_SIG_LEN {
        return Err(QuilError::InvalidArgument(format!("sig too long: {}", l)));
    }
    if l == 0 {
        return Ok(None);
    }
    let b = read_bytes(buf, c, l)?;
    Ok(Some(AddressedSignature::from_canonical_bytes(&b)?))
}
fn write_opt_addr_sig(out: &mut Vec<u8>, sig: Option<&AddressedSignature>) -> Result<()> {
    match sig {
        Some(s) => {
            let b = s.to_canonical_bytes()?;
            put_u32(out, b.len() as u32);
            out.extend_from_slice(&b);
        }
        None => put_u32(out, 0),
    }
    Ok(())
}
/// The most filters one prover op carries: every node refuses to decode a
/// join, leave, confirm or reject naming more, so a sender splits a longer
/// list into several ops. Consensus-affecting: every node must agree on
/// what decodes.
pub const MAX_FILTERS_PER_OP: usize = 100;
/// The longest filter a prover op carries; a longer one does not decode.
pub const MAX_FILTER_LEN: usize = 64;

/// Whether `filters` fit one prover op: the decoders' filter count and
/// filter length limits, as an error naming the one exceeded.
pub fn check_filters(filters: &[Vec<u8>]) -> Result<()> {
    if filters.len() > MAX_FILTERS_PER_OP {
        return Err(QuilError::InvalidArgument(format!(
            "too many filters: {} (at most {} per op)",
            filters.len(),
            MAX_FILTERS_PER_OP
        )));
    }
    if let Some(filter) = filters.iter().find(|f| f.len() > MAX_FILTER_LEN) {
        return Err(QuilError::InvalidArgument(format!(
            "filter too long: {} bytes (at most {})",
            filter.len(),
            MAX_FILTER_LEN
        )));
    }
    Ok(())
}

fn read_filters(buf: &[u8], c: &mut usize) -> Result<Vec<Vec<u8>>> {
    let n = read_u32(buf, c)?;
    if n > MAX_FILTERS_PER_OP as u32 {
        return Err(QuilError::InvalidArgument(format!(
            "too many filters: {}",
            n
        )));
    }
    let mut out = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let l = read_u32(buf, c)?;
        if l > MAX_FILTER_LEN as u32 {
            return Err(QuilError::InvalidArgument(format!(
                "filter too long: {}",
                l
            )));
        }
        out.push(read_bytes(buf, c, l as usize)?);
    }
    Ok(out)
}
fn write_filters(out: &mut Vec<u8>, filters: &[Vec<u8>]) {
    put_u32(out, filters.len() as u32);
    for f in filters {
        put_u32(out, f.len() as u32);
        out.extend_from_slice(f);
    }
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
    /// Per-shard storage leaf roots registered as part of this confirm (folded
    /// in: a confirm is the prover's per-epoch re-registration). Appended after
    /// the legacy fields and bound into the signing message; an empty set
    /// serializes + signs byte-identically to the pre-storage-attestation
    /// format. See [`super::leaf_root_registration::ConfirmLeafRoots`].
    pub leaf_roots: Vec<super::leaf_root_registration::ConfirmLeafRoots>,
    /// The sender's release, appended after the leaf roots (an empty set
    /// is then written as an explicit zero group count). Decoded, signed and
    /// recorded only for a confirm signed from the release frame
    /// ([`super::prover_release`]); `None` serializes byte-identically to the
    /// legacy format, and a decoder that predates it ignores the bytes.
    pub release: Option<super::prover_release::Release>,
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
        super::leaf_root_registration::append_confirm_leaf_roots(&mut out, &self.leaf_roots);
        if let Some(release) = self.release.as_ref() {
            if self.leaf_roots.is_empty() {
                put_u32(&mut out, 0);
            }
            out.extend_from_slice(&release.to_bytes());
        }
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_PROVER_CONFIRM {
            return Err(QuilError::InvalidArgument(format!(
                "ProverConfirm: bad type 0x{:08x}",
                tp
            )));
        }
        // Read and discard the deprecated filter field (32 bytes of "reserved")
        let fl = read_u32(data, &mut c)?;
        if fl > 64 {
            return Err(QuilError::InvalidArgument(
                "ProverConfirm: filter too long".into(),
            ));
        }
        let filter = read_bytes(data, &mut c, fl as usize)?;
        let frame_number = read_u64(data, &mut c)?;
        let sig = read_opt_addr_sig(data, &mut c)?;
        let filters = read_filters(data, &mut c)?;
        let leaf_roots = super::leaf_root_registration::read_confirm_leaf_roots(data, &mut c)?;
        // Like a decoder that predates it, never refuse a confirm for its
        // tail: a short tail carries no release, and bytes after it are
        // ignored. Before the release frame the tail is ignored entirely, so a
        // confirm re-encodes as an older build re-encodes it.
        let release = (frame_number >= super::prover_release::confirm_release_frame())
            .then(|| data.get(c..))
            .flatten()
            .and_then(|tail| tail.get(..super::prover_release::Release::ENCODED_LEN))
            .and_then(super::prover_release::Release::from_bytes);
        Ok(Self {
            filter,
            frame_number,
            public_key_signature_bls48581: sig,
            filters,
            leaf_roots,
            release,
        })
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
        if tp != TYPE_PROVER_REJECT {
            return Err(QuilError::InvalidArgument(format!(
                "ProverReject: bad type 0x{:08x}",
                tp
            )));
        }
        let fl = read_u32(data, &mut c)?;
        if fl > 64 {
            return Err(QuilError::InvalidArgument(
                "ProverReject: filter too long".into(),
            ));
        }
        let filter = read_bytes(data, &mut c, fl as usize)?;
        let frame_number = read_u64(data, &mut c)?;
        let sig = read_opt_addr_sig(data, &mut c)?;
        let filters = read_filters(data, &mut c)?;
        Ok(Self {
            filter,
            frame_number,
            public_key_signature_bls48581: sig,
            filters,
        })
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
        put_u32(&mut out, self.kicked_prover_public_key.len() as u32);
        out.extend_from_slice(&self.kicked_prover_public_key);
        put_u32(&mut out, self.conflicting_frame_1.len() as u32);
        out.extend_from_slice(&self.conflicting_frame_1);
        put_u32(&mut out, self.conflicting_frame_2.len() as u32);
        out.extend_from_slice(&self.conflicting_frame_2);
        put_u32(&mut out, self.commitment.len() as u32);
        out.extend_from_slice(&self.commitment);
        put_u32(&mut out, self.proof.len() as u32);
        out.extend_from_slice(&self.proof);
        put_u32(&mut out, self.traversal_proof.len() as u32);
        out.extend_from_slice(&self.traversal_proof);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_PROVER_KICK {
            return Err(QuilError::InvalidArgument(format!(
                "ProverKick: bad type 0x{:08x}",
                tp
            )));
        }
        let frame_number = read_u64(data, &mut c)?;
        let kl = read_u32(data, &mut c)?;
        if kl > 897 {
            return Err(QuilError::InvalidArgument(
                "ProverKick: key too long".into(),
            ));
        }
        let kicked = read_bytes(data, &mut c, kl as usize)?;
        let cf1l = read_u32(data, &mut c)?;
        if cf1l > 34825 {
            return Err(QuilError::InvalidArgument(
                "ProverKick: cf1 too long".into(),
            ));
        }
        let cf1 = read_bytes(data, &mut c, cf1l as usize)?;
        let cf2l = read_u32(data, &mut c)?;
        if cf2l > 34825 {
            return Err(QuilError::InvalidArgument(
                "ProverKick: cf2 too long".into(),
            ));
        }
        let cf2 = read_bytes(data, &mut c, cf2l as usize)?;
        let cl = read_u32(data, &mut c)?;
        if cl > 74 {
            return Err(QuilError::InvalidArgument(
                "ProverKick: commit too long".into(),
            ));
        }
        let commitment = read_bytes(data, &mut c, cl as usize)?;
        let pl = read_u32(data, &mut c)?;
        if pl > 160 {
            return Err(QuilError::InvalidArgument(
                "ProverKick: proof too long".into(),
            ));
        }
        let proof = read_bytes(data, &mut c, pl as usize)?;
        let tl = read_u32(data, &mut c)?;
        if tl > 4000 {
            return Err(QuilError::InvalidArgument(
                "ProverKick: traversal too long".into(),
            ));
        }
        let traversal_proof = read_bytes(data, &mut c, tl as usize)?;
        Ok(Self {
            frame_number,
            kicked_prover_public_key: kicked,
            conflicting_frame_1: cf1,
            conflicting_frame_2: cf2,
            commitment,
            proof,
            traversal_proof,
        })
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
    /// The GLOBAL frame the update was signed at, appended after the
    /// signature and bound into it
    /// ([`super::prover_verify::prover_update_signing_message`]). Carried only
    /// from the prover operation replay guard epoch ([`Self::signed_frame`]);
    /// zero serializes byte-identically to the legacy format, and a decoder
    /// that predates it ignores the bytes.
    pub frame_number: u64,
}

impl ProverUpdate {
    /// The signed frame an update carries for `frame`: `frame` from the
    /// prover operation replay guard epoch, else zero, so that before the
    /// epoch an update re-encodes as a build without the field encodes it.
    pub fn signed_frame(frame: u64) -> u64 {
        if quil_types::consensus::prover_op_replay_guard_active(frame) {
            frame
        } else {
            0
        }
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_PROVER_UPDATE);
        put_u32(&mut out, self.delegate_address.len() as u32);
        out.extend_from_slice(&self.delegate_address);
        write_opt_addr_sig(&mut out, self.public_key_signature_bls48581.as_ref())?;
        if self.frame_number != 0 {
            put_u64(&mut out, self.frame_number);
        }
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_PROVER_UPDATE {
            return Err(QuilError::InvalidArgument(format!(
                "ProverUpdate: bad type 0x{:08x}",
                tp
            )));
        }
        let dl = read_u32(data, &mut c)?;
        if dl > 32 {
            return Err(QuilError::InvalidArgument(
                "ProverUpdate: addr too long".into(),
            ));
        }
        let delegate_address = read_bytes(data, &mut c, dl as usize)?;
        let sig = read_opt_addr_sig(data, &mut c)?;
        // Like a decoder that predates it, never refuse an update for its
        // tail: a short tail carries no frame, and bytes after it are ignored.
        let frame_number = if data.len().saturating_sub(c) >= 8 {
            Self::signed_frame(read_u64(data, &mut c)?)
        } else {
            0
        };
        Ok(Self {
            delegate_address,
            public_key_signature_bls48581: sig,
            frame_number,
        })
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
            put_u32(&mut out, mb.len() as u32);
            out.extend_from_slice(&mb);
        }
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_PROVER_SENIORITY_MERGE {
            return Err(QuilError::InvalidArgument(format!(
                "ProverSeniorityMerge: bad type 0x{:08x}",
                tp
            )));
        }
        let frame_number = read_u64(data, &mut c)?;
        let sig = read_opt_addr_sig(data, &mut c)?;
        let n = read_u32(data, &mut c)?;
        if n > 100 {
            return Err(QuilError::InvalidArgument(
                "ProverSeniorityMerge: too many targets".into(),
            ));
        }
        let mut merge_targets = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let l = read_u32(data, &mut c)?;
            if l > 1000 {
                return Err(QuilError::InvalidArgument(
                    "ProverSeniorityMerge: target too long".into(),
                ));
            }
            let b = read_bytes(data, &mut c, l as usize)?;
            merge_targets.push(SeniorityMerge::from_canonical_bytes(&b)?);
        }
        Ok(Self {
            frame_number,
            public_key_signature_bls48581: sig,
            merge_targets,
        })
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
        put_u32(&mut out, self.shard_address.len() as u32);
        out.extend_from_slice(&self.shard_address);
        put_u32(&mut out, self.proposed_shards.len() as u32);
        for s in &self.proposed_shards {
            put_u32(&mut out, s.len() as u32);
            out.extend_from_slice(s);
        }
        put_u64(&mut out, self.frame_number);
        write_opt_addr_sig(&mut out, self.public_key_signature_bls48581.as_ref())?;
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_SHARD_SPLIT {
            return Err(QuilError::InvalidArgument(format!(
                "ShardSplit: bad type 0x{:08x}",
                tp
            )));
        }
        let sal = read_u32(data, &mut c)?;
        if sal > 64 {
            return Err(QuilError::InvalidArgument(
                "ShardSplit: shard_address too long".into(),
            ));
        }
        let shard_address = read_bytes(data, &mut c, sal as usize)?;
        let pn = read_u32(data, &mut c)?;
        if pn > 8 {
            return Err(QuilError::InvalidArgument(
                "ShardSplit: too many proposed".into(),
            ));
        }
        let mut proposed_shards = Vec::with_capacity(pn as usize);
        for _ in 0..pn {
            let l = read_u32(data, &mut c)?;
            if l > 66 {
                return Err(QuilError::InvalidArgument(
                    "ShardSplit: proposed too long".into(),
                ));
            }
            proposed_shards.push(read_bytes(data, &mut c, l as usize)?);
        }
        let frame_number = read_u64(data, &mut c)?;
        let sig = read_opt_addr_sig(data, &mut c)?;
        Ok(Self {
            shard_address,
            proposed_shards,
            frame_number,
            public_key_signature_bls48581: sig,
        })
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
        for s in &self.shard_addresses {
            put_u32(&mut out, s.len() as u32);
            out.extend_from_slice(s);
        }
        put_u32(&mut out, self.parent_address.len() as u32);
        out.extend_from_slice(&self.parent_address);
        put_u64(&mut out, self.frame_number);
        write_opt_addr_sig(&mut out, self.public_key_signature_bls48581.as_ref())?;
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_SHARD_MERGE {
            return Err(QuilError::InvalidArgument(format!(
                "ShardMerge: bad type 0x{:08x}",
                tp
            )));
        }
        let n = read_u32(data, &mut c)?;
        if n > 8 {
            return Err(QuilError::InvalidArgument(
                "ShardMerge: too many shards".into(),
            ));
        }
        let mut shard_addresses = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let l = read_u32(data, &mut c)?;
            if l > 64 {
                return Err(QuilError::InvalidArgument(
                    "ShardMerge: shard too long".into(),
                ));
            }
            shard_addresses.push(read_bytes(data, &mut c, l as usize)?);
        }
        let pal = read_u32(data, &mut c)?;
        if pal > 64 {
            return Err(QuilError::InvalidArgument(
                "ShardMerge: parent too long".into(),
            ));
        }
        let parent_address = read_bytes(data, &mut c, pal as usize)?;
        let frame_number = read_u64(data, &mut c)?;
        let sig = read_opt_addr_sig(data, &mut c)?;
        Ok(Self {
            shard_addresses,
            parent_address,
            frame_number,
            public_key_signature_bls48581: sig,
        })
    }
}

// =====================================================================
// Tests
// =====================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn addr_sig() -> AddressedSignature {
        AddressedSignature {
            signature: vec![0xAAu8; 666],
            address: vec![0xBBu8; 32],
        }
    }

    fn merge_target() -> SeniorityMerge {
        SeniorityMerge {
            signature: vec![0x11u8; 74],
            key_type: 2,
            prover_public_key: vec![0x22u8; 57],
        }
    }

    /// `check_filters` admits exactly the filter lists every filter op
    /// decodes: senders split by these limits, so they must not drift apart.
    #[test]
    fn every_filter_op_decodes_exactly_what_check_filters_admits() {
        use super::super::{prover_filter_ops::ProverLeave, prover_join::ProverJoin};
        let decodes = |filters: Vec<Vec<u8>>| -> [bool; 4] {
            [
                ProverConfirm::from_canonical_bytes(
                    &ProverConfirm {
                        filters: filters.clone(),
                        ..Default::default()
                    }
                    .to_canonical_bytes()
                    .unwrap(),
                )
                .is_ok(),
                ProverReject::from_canonical_bytes(
                    &ProverReject {
                        filters: filters.clone(),
                        ..Default::default()
                    }
                    .to_canonical_bytes()
                    .unwrap(),
                )
                .is_ok(),
                ProverLeave::from_canonical_bytes(
                    &ProverLeave {
                        filters: filters.clone(),
                        ..Default::default()
                    }
                    .to_canonical_bytes()
                    .unwrap(),
                )
                .is_ok(),
                ProverJoin::from_canonical_bytes(
                    &ProverJoin {
                        filters,
                        ..Default::default()
                    }
                    .to_canonical_bytes()
                    .unwrap(),
                )
                .is_ok(),
            ]
        };
        let at_limit = vec![vec![7u8; MAX_FILTER_LEN]; MAX_FILTERS_PER_OP];
        assert!(check_filters(&at_limit).is_ok());
        assert_eq!(decodes(at_limit), [true; 4]);
        let too_many = vec![vec![7u8; 32]; MAX_FILTERS_PER_OP + 1];
        assert!(check_filters(&too_many).is_err());
        assert_eq!(decodes(too_many), [false; 4]);
        let too_long = vec![vec![7u8; MAX_FILTER_LEN + 1]];
        assert!(check_filters(&too_long).is_err());
        assert_eq!(decodes(too_long), [false; 4]);
    }

    // -- ProverConfirm --
    #[test]
    fn confirm_round_trip() {
        let c = ProverConfirm {
            filter: vec![],
            frame_number: 42,
            public_key_signature_bls48581: Some(addr_sig()),
            filters: vec![vec![1u8; 8], vec![2u8; 16]],
            leaf_roots: Vec::new(),
            release: None,
        };
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
        assert!(decoded.leaf_roots.is_empty());
    }

    #[test]
    fn confirm_empty_leaf_roots_is_byte_identical_to_legacy() {
        use super::super::leaf_root_registration::ConfirmLeafRoots;
        // A confirm with no leaf roots must serialize EXACTLY as before the
        // storage-attestation fold (append nothing) — so existing signatures
        // and on-wire bytes are unchanged.
        let mut c = ProverConfirm {
            filter: vec![],
            frame_number: 42,
            public_key_signature_bls48581: Some(addr_sig()),
            filters: vec![vec![1u8; 8], vec![2u8; 16]],
            leaf_roots: Vec::new(),
            release: None,
        };
        let legacy = c.to_canonical_bytes().unwrap();
        c.leaf_roots = Vec::<ConfirmLeafRoots>::new();
        assert_eq!(c.to_canonical_bytes().unwrap(), legacy);
    }

    #[test]
    fn confirm_with_leaf_roots_round_trips() {
        use super::super::leaf_root_registration::{ConfirmLeafRoots, LeafRootEntry};
        let groups = vec![ConfirmLeafRoots {
            filter: vec![0xAB; 32],
            entries: vec![
                LeafRootEntry {
                    prefix: vec![42, 7],
                    leaf_root: vec![0x11; 74],
                    num_blocks: 1234,
                },
                LeafRootEntry {
                    prefix: vec![],
                    leaf_root: vec![0x22; 74],
                    num_blocks: 1,
                },
            ],
        }];
        let c = ProverConfirm {
            filter: vec![],
            frame_number: 9,
            public_key_signature_bls48581: Some(addr_sig()),
            filters: vec![vec![0xAB; 32]],
            leaf_roots: groups.clone(),
            release: None,
        };
        let b = c.to_canonical_bytes().unwrap();
        let decoded = ProverConfirm::from_canonical_bytes(&b).unwrap();
        assert_eq!(decoded.leaf_roots, groups);
        // The leaf roots extend the bytes beyond the legacy tail.
        let legacy = ProverConfirm {
            leaf_roots: Vec::new(),
            ..c.clone()
        };
        assert!(b.len() > legacy.to_canonical_bytes().unwrap().len());
    }

    /// The confirm encoding of the base release, written out field by field.
    fn legacy_confirm_bytes(c: &ProverConfirm) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x0305u32.to_be_bytes());
        out.extend_from_slice(&32u32.to_be_bytes());
        out.extend_from_slice(b"reservedreservedreservedreserved");
        out.extend_from_slice(&c.frame_number.to_be_bytes());
        match c.public_key_signature_bls48581.as_ref() {
            Some(sig) => {
                let b = sig.to_canonical_bytes().unwrap();
                out.extend_from_slice(&(b.len() as u32).to_be_bytes());
                out.extend_from_slice(&b);
            }
            None => out.extend_from_slice(&0u32.to_be_bytes()),
        }
        out.extend_from_slice(&(c.filters.len() as u32).to_be_bytes());
        for f in &c.filters {
            out.extend_from_slice(&(f.len() as u32).to_be_bytes());
            out.extend_from_slice(f);
        }
        super::super::leaf_root_registration::append_confirm_leaf_roots(&mut out, &c.leaf_roots);
        out
    }

    /// The base release's decoder: the legacy fields, then leaf roots if
    /// bytes remain; anything after them is ignored.
    fn legacy_decode(
        data: &[u8],
    ) -> (
        u64,
        Option<AddressedSignature>,
        Vec<Vec<u8>>,
        Vec<super::super::leaf_root_registration::ConfirmLeafRoots>,
    ) {
        let mut c = 0;
        assert_eq!(read_u32(data, &mut c).unwrap(), TYPE_PROVER_CONFIRM);
        let fl = read_u32(data, &mut c).unwrap();
        read_bytes(data, &mut c, fl as usize).unwrap();
        let frame_number = read_u64(data, &mut c).unwrap();
        let sig = read_opt_addr_sig(data, &mut c).unwrap();
        let filters = read_filters(data, &mut c).unwrap();
        let leaf_roots =
            super::super::leaf_root_registration::read_confirm_leaf_roots(data, &mut c).unwrap();
        (frame_number, sig, filters, leaf_roots)
    }

    fn release() -> super::super::prover_release::Release {
        super::super::prover_release::Release {
            version: [2, 1, 0],
            patch: 25,
            subpatch: 92,
        }
    }

    #[test]
    fn confirm_without_release_is_byte_identical_to_legacy() {
        use super::super::leaf_root_registration::{ConfirmLeafRoots, LeafRootEntry};
        let roots = vec![ConfirmLeafRoots {
            filter: vec![0xAB; 32],
            entries: vec![LeafRootEntry {
                prefix: vec![3],
                leaf_root: vec![0x11; 74],
                num_blocks: 5,
            }],
        }];
        for leaf_roots in [Vec::new(), roots] {
            let c = ProverConfirm {
                filter: vec![],
                frame_number: 42,
                public_key_signature_bls48581: Some(addr_sig()),
                filters: vec![vec![1u8; 8], vec![2u8; 16]],
                leaf_roots,
                release: None,
            };
            let bytes = c.to_canonical_bytes().unwrap();
            assert_eq!(bytes, legacy_confirm_bytes(&c));
            assert_eq!(
                ProverConfirm::from_canonical_bytes(&bytes).unwrap().release,
                None
            );
        }
    }

    #[test]
    fn confirm_with_release_round_trips_and_a_legacy_decoder_ignores_it() {
        use super::super::leaf_root_registration::{ConfirmLeafRoots, LeafRootEntry};
        super::super::prover_release::set_confirm_release_frame_for_thread(Some(42));
        let roots = vec![ConfirmLeafRoots {
            filter: vec![0xAB; 32],
            entries: vec![LeafRootEntry {
                prefix: vec![3],
                leaf_root: vec![0x11; 74],
                num_blocks: 5,
            }],
        }];
        for leaf_roots in [Vec::new(), roots] {
            let c = ProverConfirm {
                filter: vec![],
                frame_number: 42,
                public_key_signature_bls48581: Some(addr_sig()),
                filters: vec![vec![1u8; 8]],
                leaf_roots: leaf_roots.clone(),
                release: Some(release()),
            };
            let bytes = c.to_canonical_bytes().unwrap();
            let legacy = legacy_confirm_bytes(&c);
            // The legacy bytes, an explicit empty leaf-root set, the release.
            let mut expected = legacy.clone();
            if leaf_roots.is_empty() {
                expected.extend_from_slice(&0u32.to_be_bytes());
            }
            expected.extend_from_slice(&[2, 1, 0, 25, 0, 92]);
            assert_eq!(bytes, expected);
            let decoded = ProverConfirm::from_canonical_bytes(&bytes).unwrap();
            assert_eq!(decoded.release, Some(release()));
            assert_eq!(decoded.leaf_roots, leaf_roots);
            let (frame, sig, filters, roots) = legacy_decode(&bytes);
            assert_eq!(
                (frame, sig, filters, roots),
                (42, Some(addr_sig()), vec![vec![1u8; 8]], leaf_roots)
            );
        }
        super::super::prover_release::set_confirm_release_frame_for_thread(None);
    }

    #[test]
    fn before_the_release_frame_a_confirm_re_encodes_as_a_legacy_decoder_reads_it() {
        use super::super::leaf_root_registration::{ConfirmLeafRoots, LeafRootEntry};
        let roots = vec![ConfirmLeafRoots {
            filter: vec![0xAB; 32],
            entries: vec![LeafRootEntry {
                prefix: vec![3],
                leaf_root: vec![0x11; 74],
                num_blocks: 5,
            }],
        }];
        for frame in [None, Some(43)] {
            super::super::prover_release::set_confirm_release_frame_for_thread(frame);
            for leaf_roots in [Vec::new(), roots.clone()] {
                let early = ProverConfirm {
                    filter: vec![],
                    frame_number: 42,
                    public_key_signature_bls48581: Some(addr_sig()),
                    filters: vec![vec![1u8; 8]],
                    leaf_roots,
                    release: Some(release()),
                };
                let legacy = legacy_confirm_bytes(&early);
                let decoded =
                    ProverConfirm::from_canonical_bytes(&early.to_canonical_bytes().unwrap())
                        .unwrap();
                assert_eq!(decoded.release, None, "release frame {frame:?}");
                assert_eq!(
                    decoded.to_canonical_bytes().unwrap(),
                    legacy,
                    "release frame {frame:?}"
                );
            }
        }
        super::super::prover_release::set_confirm_release_frame_for_thread(None);
    }

    #[test]
    fn a_confirm_tail_without_a_whole_release_decodes_without_one() {
        super::super::prover_release::set_confirm_release_frame_for_thread(Some(0));
        let c = ProverConfirm {
            filters: vec![vec![1u8; 8]],
            ..Default::default()
        };
        let mut bytes = c.to_canonical_bytes().unwrap();
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&[2, 1, 0]);
        let decoded = ProverConfirm::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded.release, None);
        bytes.extend_from_slice(&[25, 0, 92, 0xEE]);
        let decoded = ProverConfirm::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(decoded.release, Some(release()));
        super::super::prover_release::set_confirm_release_frame_for_thread(None);
    }

    // -- ProverReject --
    #[test]
    fn reject_round_trip() {
        let r = ProverReject {
            filter: vec![],
            frame_number: 7,
            public_key_signature_bls48581: Some(addr_sig()),
            filters: vec![vec![3u8; 32]],
        };
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
        let k = ProverKick {
            frame_number: 100,
            kicked_prover_public_key: vec![0xCCu8; 585],
            conflicting_frame_1: vec![1u8; 100],
            conflicting_frame_2: vec![2u8; 100],
            commitment: vec![3u8; 74],
            proof: vec![4u8; 64],
            traversal_proof: vec![5u8; 200],
        };
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
        let u = ProverUpdate {
            delegate_address: vec![0xDDu8; 32],
            public_key_signature_bls48581: Some(addr_sig()),
            frame_number: 0,
        };
        let b = u.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_PROVER_UPDATE.to_be_bytes());
        assert_eq!(ProverUpdate::from_canonical_bytes(&b).unwrap(), u);
    }

    /// From the replay guard epoch an update carries its signed frame after
    /// the legacy bytes; before it the frame is read as absent, so the update
    /// re-encodes exactly as a build without the field re-encodes it.
    #[test]
    fn an_update_carries_its_frame_only_from_the_replay_guard_epoch() {
        let legacy = ProverUpdate {
            delegate_address: vec![0xDDu8; 32],
            public_key_signature_bls48581: Some(addr_sig()),
            frame_number: 0,
        };
        let legacy_bytes = legacy.to_canonical_bytes().unwrap();
        let epoch = quil_types::consensus::epoch_length_frames();
        quil_types::consensus::set_prover_op_replay_guard_epoch_for_thread(Some(2));
        let fresh = ProverUpdate {
            frame_number: 2 * epoch + 5,
            ..legacy.clone()
        };
        let bytes = fresh.to_canonical_bytes().unwrap();
        assert_eq!(&bytes[..legacy_bytes.len()], &legacy_bytes[..]);
        assert_eq!(&bytes[legacy_bytes.len()..], &(2 * epoch + 5).to_be_bytes());
        assert_eq!(ProverUpdate::from_canonical_bytes(&bytes).unwrap(), fresh);

        let early = ProverUpdate {
            frame_number: 2 * epoch - 1,
            ..legacy.clone()
        };
        let decoded =
            ProverUpdate::from_canonical_bytes(&early.to_canonical_bytes().unwrap()).unwrap();
        assert_eq!(decoded, legacy, "a frame before the epoch is not carried");
        assert_eq!(decoded.to_canonical_bytes().unwrap(), legacy_bytes);
        quil_types::consensus::set_prover_op_replay_guard_epoch_for_thread(None);
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
        let s = ProverSeniorityMerge {
            frame_number: 999,
            public_key_signature_bls48581: Some(addr_sig()),
            merge_targets: vec![merge_target(), merge_target()],
        };
        let b = s.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_PROVER_SENIORITY_MERGE.to_be_bytes());
        assert_eq!(ProverSeniorityMerge::from_canonical_bytes(&b).unwrap(), s);
    }

    // -- ShardSplit --
    #[test]
    fn shard_split_round_trip() {
        let s = ShardSplit {
            shard_address: vec![0xAAu8; 32],
            proposed_shards: vec![vec![1u8; 33], vec![2u8; 33]],
            frame_number: 50,
            public_key_signature_bls48581: Some(addr_sig()),
        };
        let b = s.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_SHARD_SPLIT.to_be_bytes());
        assert_eq!(ShardSplit::from_canonical_bytes(&b).unwrap(), s);
    }

    // -- ShardMerge --
    #[test]
    fn shard_merge_round_trip() {
        let m = ShardMerge {
            shard_addresses: vec![vec![1u8; 32], vec![2u8; 32]],
            parent_address: vec![3u8; 32],
            frame_number: 60,
            public_key_signature_bls48581: Some(addr_sig()),
        };
        let b = m.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_SHARD_MERGE.to_be_bytes());
        assert_eq!(ShardMerge::from_canonical_bytes(&b).unwrap(), m);
    }

    // -- Cross-type --
    #[test]
    fn type_prefixes_all_distinct() {
        use std::collections::HashSet;
        let ids: HashSet<u32> = [
            TYPE_PROVER_CONFIRM,
            TYPE_PROVER_REJECT,
            TYPE_PROVER_KICK,
            TYPE_PROVER_UPDATE,
            TYPE_PROVER_SENIORITY_MERGE,
            TYPE_SHARD_SPLIT,
            TYPE_SHARD_MERGE,
        ]
        .into_iter()
        .collect();
        assert_eq!(ids.len(), 7);
    }
}

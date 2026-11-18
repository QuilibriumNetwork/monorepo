//! Persistent sector certificates and versioned epoch envelopes. All authority
//! comes from committed GLOBAL state. Cached certificates never skip fresh
//! possession or the ordinary certified-snapshot binding checks.
use super::storage_epoch_proof::{EpochClaim, SeatWitness};
use crate::{
    global_schema::{read_field, write_field, write_type, GLOBAL_INTRINSIC_ADDRESS},
    hypergraph_state::HypergraphState,
};
use quil_crypto::persistent_storage as sector;
use quil_types::error::{QuilError, Result};
use sha3::{Digest as _, Sha3_256};
use std::collections::{BTreeMap, BTreeSet};

pub use quil_storage_stark::persistent::{
    prove as prove_certificate, verify as verify_certificate,
};

const CLASS: &str = "storage:PersistentSector";
const MAGIC: &[u8; 4] = b"PSE1";
const MAX_BYTES: usize = super::storage_epoch_proof::MAX_PROOF_LEN as usize;
mod capacity;
pub use capacity::{
    capacity_domain, capacity_message, check_capacity, pending_certificate, CapacityMessage,
    PendingCertificate,
};

#[derive(Debug, Clone)]
pub struct StateRecord {
    address: [u8; 32],
    member: [u8; 32],
    sector: [u8; 32],
    certificate: Vec<u8>,
    usage: Vec<u8>,
}

fn address(domain: &[u8], member: &[u8; 32], id: &[u8; 32], epoch: Option<u64>) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(domain);
    h.update(member);
    h.update(id);
    if let Some(epoch) = epoch {
        h.update((epoch % 4).to_be_bytes());
    }
    h.finalize().into()
}
pub(super) fn certificate_address(member: &[u8; 32], id: &[u8; 32]) -> [u8; 32] {
    address(b"quil/sector-certificate/v1", member, id, None)
}
fn usage_address(member: &[u8; 32], id: &[u8; 32], epoch: u64) -> [u8; 32] {
    address(b"quil/sector-usage/v1", member, id, Some(epoch))
}

fn sector_count_address(member: &[u8; 32]) -> [u8; 32] {
    address(b"quil/sector-count/v1", member, &[0; 32], None)
}

/// The record of how many sectors `member` has certified: one per member, read
/// back from state since a member's certificates cannot be enumerated.
pub fn sector_count_record(member: &[u8; 32], held: u64) -> StateRecord {
    StateRecord {
        address: sector_count_address(member),
        member: *member,
        sector: [0; 32],
        certificate: Vec::new(),
        usage: held.to_be_bytes().to_vec(),
    }
}

/// A member's certified sectors, and the seats that decide how many it may
/// hold. Certificates are permanent and reusable, so `held` never falls: a
/// member over its cap keeps every sector and only certifies no new one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SectorRoom {
    pub held: u64,
    pub seats: u64,
}
impl SectorRoom {
    pub fn cap(&self) -> u64 {
        quil_types::consensus::max_certified_sectors(self.seats)
    }
    pub fn full(&self) -> bool {
        self.held >= self.cap()
    }
    /// The count record once `fresh` more sectors are certified, if they fit.
    fn admit(&self, member: &[u8; 32], fresh: u64) -> std::result::Result<StateRecord, String> {
        let held = self.held.saturating_add(fresh);
        if held > self.cap() {
            return Err(format!(
                "member holds {} certified sectors, {} more would exceed the {} of {} seats",
                self.held,
                fresh,
                self.cap(),
                self.seats
            ));
        }
        Ok(sector_count_record(member, held))
    }
}
/// Read through `vertex` and the member's hyperedge. A seat is an allocation
/// its member holds or asked for: joining, active, paused or leaving.
fn sector_room(
    member: &[u8; 32],
    vertex: impl Fn(&[u8; 32]) -> Result<Option<Vec<u8>>>,
    hyperedge: Option<Vec<u8>>,
) -> Result<SectorRoom> {
    use super::materialize as m;
    let held = vertex(&sector_count_address(member))?
        .map(|blob| {
            let tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&blob);
            read_field(&tree, CLASS, "Usage")
                .filter(|_| {
                    crate::global_schema::read_type(&tree) == Some(CLASS)
                        && read_field(&tree, CLASS, "Member").as_deref() == Some(member.as_slice())
                })
                .and_then(|usage| <[u8; 8]>::try_from(usage.as_slice()).ok())
                .map(u64::from_be_bytes)
                .ok_or_else(|| QuilError::InvalidArgument("invalid sector count record".into()))
        })
        .transpose()?
        .unwrap_or(0);
    let mut seats = 0;
    for address in m::hyperedge_allocation_addresses(&hyperedge.unwrap_or_default())? {
        let Some(blob) = vertex(&address)?.filter(|blob| !blob.is_empty()) else {
            continue;
        };
        let tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&blob);
        let status = read_field(&tree, "allocation:ProverAllocation", "Status")
            .and_then(|status| status.first().copied());
        if status.is_some_and(|status| {
            [
                m::STATUS_JOINING,
                m::STATUS_ACTIVE,
                m::STATUS_PAUSED,
                m::STATUS_LEAVING,
            ]
            .contains(&status)
        }) {
            seats += 1;
        }
    }
    Ok(SectorRoom { held, seats })
}
pub fn sector_room_in(state: &HypergraphState, member: &[u8; 32]) -> Result<SectorRoom> {
    let adds = crate::hypergraph_state::vertex_adds_discriminator()?;
    let links = crate::hypergraph_state::hyperedge_adds_discriminator()?;
    sector_room(
        member,
        |address| state.get(&GLOBAL_INTRINSIC_ADDRESS, address, &adds),
        state.get(&GLOBAL_INTRINSIC_ADDRESS, member, &links)?,
    )
}

fn read(
    state: &HypergraphState,
    address: &[u8; 32],
    member: &[u8; 32],
    sector: &[u8; 32],
) -> Result<Option<quil_tries::VectorCommitmentTree>> {
    let Some(blob) = state.get(
        &GLOBAL_INTRINSIC_ADDRESS,
        address,
        &crate::hypergraph_state::vertex_adds_discriminator()?,
    )?
    else {
        return Ok(None);
    };
    let tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&blob);
    if crate::global_schema::read_type(&tree) != Some(CLASS)
        || read_field(&tree, CLASS, "Member").as_deref() != Some(member.as_slice())
        || read_field(&tree, CLASS, "Sector").as_deref() != Some(sector.as_slice())
    {
        return Err(QuilError::InvalidArgument(
            "persistent sector record identity".into(),
        ));
    }
    Ok(Some(tree))
}
pub fn certificate(
    state: &HypergraphState,
    member: &[u8; 32],
    id: &[u8; 32],
) -> Result<Option<sector::Certificate>> {
    read(state, &certificate_address(member, id), member, id)?
        .map(|tree| {
            read_field(&tree, CLASS, "Certificate")
                .and_then(|bytes| sector::Certificate::parse(&bytes))
                .ok_or_else(|| {
                    QuilError::InvalidArgument("invalid committed sector certificate".into())
                })
        })
        .transpose()
}
pub fn apply(state: &HypergraphState, frame: u64, records: &[StateRecord]) -> Result<()> {
    for record in records {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        write_type(&mut tree, CLASS)?;
        for (name, bytes) in [
            ("Member", record.member.as_slice()),
            ("Sector", &record.sector),
            ("Certificate", record.certificate.as_slice()),
            ("Usage", record.usage.as_slice()),
        ] {
            write_field(&mut tree, CLASS, name, bytes)?;
        }
        state.set(
            &GLOBAL_INTRINSIC_ADDRESS,
            &record.address,
            &crate::hypergraph_state::vertex_adds_discriminator()?,
            frame,
            crate::prover_registry::vertex_tree_to_blob(&tree),
        )?;
    }
    Ok(())
}

fn legacy(claim: &EpochClaim) -> EpochClaim {
    let mut out = claim.clone();
    for seat in &mut out.seats {
        seat.seals.retain(|leaf| leaf.persistent.is_none());
    }
    out
}
fn needs_legacy(claim: &EpochClaim) -> bool {
    claim
        .seats
        .iter()
        .any(|s| !s.seals.is_empty() || !s.held.is_empty() || !s.frames.is_empty())
}
fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
fn take<'a>(bytes: &mut &'a [u8], n: usize) -> std::result::Result<&'a [u8], String> {
    let value = bytes.get(..n).ok_or("truncated persistent epoch proof")?;
    *bytes = &bytes[n..];
    Ok(value)
}
fn read_lp<'a>(bytes: &mut &'a [u8]) -> std::result::Result<&'a [u8], String> {
    let n = u32::from_be_bytes(take(bytes, 4)?.try_into().unwrap()) as usize;
    if n > MAX_BYTES {
        return Err("persistent proof component is too large".into());
    }
    take(bytes, n)
}

pub fn prove(
    claim: &EpochClaim,
    witnesses: &[SeatWitness],
) -> std::result::Result<Vec<u8>, String> {
    if witnesses.len() != claim.seats.len() {
        return Err("persistent epoch witness count".into());
    }
    let count = claim
        .seats
        .iter()
        .flat_map(|s| &s.seals)
        .filter(|l| l.persistent.is_some())
        .count();
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&(count as u32).to_be_bytes());
    let mut old = Vec::new();
    for (seat, witness) in claim.seats.iter().zip(witnesses) {
        if witness.seals.len() != seat.seals.len() {
            return Err("persistent leaf witness count".into());
        }
        let mut old_witness = SeatWitness {
            certificates: Vec::new(),
            seals: Vec::new(),
            opened: witness.opened.clone(),
        };
        for (i, (leaf, proof)) in seat.seals.iter().zip(&witness.seals).enumerate() {
            if let Some(root) = leaf.persistent {
                if !quil_types::consensus::persistent_storage_at(seat.seal_epoch) {
                    return Err("persistent storage is inactive".into());
                }
                if leaf.registered != root.registered() {
                    return Err("persistent registration mismatch".into());
                }
                sector::verify(
                    &claim.member,
                    &leaf.leaf_id,
                    seat.seal_epoch,
                    leaf.n,
                    &root,
                    &leaf.beacon,
                    proof,
                )?;
                lp(
                    &mut out,
                    witness.certificates.get(i).map_or(&[], Vec::as_slice),
                );
                lp(&mut out, &sector::encode_proof(proof, leaf.n)?);
            } else {
                old_witness.seals.push(proof.clone());
            }
        }
        old.push(old_witness);
    }
    let claim = legacy(claim);
    let proof = if needs_legacy(&claim) {
        super::storage_epoch_proof::prove(&claim, &old)?
    } else {
        Vec::new()
    };
    lp(&mut out, &proof);
    if out.len() > MAX_BYTES {
        return Err("persistent epoch proof exceeds frame budget; use smaller chunks".into());
    }
    Ok(out)
}

/// Verify native epoch updates and only those initial STARK certificates not
/// already in trusted state. The result contains newly certified roots.
pub fn verify(
    claim: &EpochClaim,
    bytes: &[u8],
    lookup: &dyn Fn(&[u8; 32]) -> std::result::Result<Option<sector::Certificate>, String>,
) -> std::result::Result<Vec<sector::Certificate>, String> {
    if bytes.len() > MAX_BYTES {
        return Err("persistent epoch proof too large".into());
    }
    let mut bytes = bytes;
    if take(&mut bytes, 4)? != MAGIC {
        return Err("persistent epoch proof version".into());
    }
    let count = u32::from_be_bytes(take(&mut bytes, 4)?.try_into().unwrap()) as usize;
    let expected = claim
        .seats
        .iter()
        .flat_map(|s| &s.seals)
        .filter(|l| l.persistent.is_some())
        .count();
    if count != expected || count == 0 {
        return Err("persistent seal count".into());
    }
    let mut checked = BTreeMap::new();
    let mut fresh = Vec::new();
    for seat in &claim.seats {
        for leaf in &seat.seals {
            let Some(root) = leaf.persistent else {
                continue;
            };
            if !quil_types::consensus::persistent_storage_at(seat.seal_epoch) {
                return Err("persistent storage is inactive".into());
            }
            if root.registered() != leaf.registered {
                return Err("persistent registration mismatch".into());
            }
            let proof = read_lp(&mut bytes)?;
            let certificate = root.certificate(leaf.n);
            if !certificate.valid() {
                return Err("invalid sector capacity".into());
            }
            let known = checked.get(&root.sector).copied().or(lookup(&root.sector)?);
            if let Some(known) = known {
                if known != certificate {
                    return Err("sector certificate was changed".into());
                }
            } else {
                if root.profile != sector::Profile::Eleven
                    && root.profile != quil_types::consensus::storage_seal_profile(seat.seal_epoch)
                {
                    return Err("sector proof profile is not activated for this epoch".into());
                }
                if proof.is_empty() {
                    return Err("uncertified labels".into());
                }
                quil_storage_stark::persistent::verify(
                    &claim.member,
                    &leaf.leaf_id,
                    seat.seal_epoch,
                    leaf.n,
                    &root,
                    &leaf.beacon,
                    proof,
                )?;
                fresh.push(certificate);
            }
            checked.insert(root.sector, certificate);
            let proof = sector::decode_proof(read_lp(&mut bytes)?, leaf.n)
                .ok_or("malformed persistent openings")?;
            sector::verify(
                &claim.member,
                &leaf.leaf_id,
                seat.seal_epoch,
                leaf.n,
                &root,
                &leaf.beacon,
                &proof,
            )?;
        }
    }
    let old = read_lp(&mut bytes)?;
    if !bytes.is_empty() {
        return Err("trailing persistent proof bytes".into());
    }
    let claim = legacy(claim);
    if needs_legacy(&claim) {
        claim.verify(old)?;
    } else if !old.is_empty() {
        return Err("unexpected settlement proof".into());
    }
    Ok(fresh)
}

/// A physical sector can back only one logical leaf per member per epoch,
/// including when leaves are proved in separate batches or different shards.
pub fn check(
    state: &HypergraphState,
    claim: &EpochClaim,
    bytes: &[u8],
) -> std::result::Result<Vec<StateRecord>, String> {
    let certs = verify(claim, bytes, &|id| {
        certificate(state, &claim.member, id).map_err(|e| e.to_string())
    })?;
    let floor = quil_types::consensus::min_sector_nodes();
    if certs.iter().any(|cert| cert.n < floor) {
        return Err(format!("sector is below the {floor}-node floor"));
    }
    let count = if certs.is_empty() {
        None
    } else {
        let room = sector_room_in(state, &claim.member).map_err(|e| e.to_string())?;
        Some(room.admit(&claim.member, certs.len() as u64)?)
    };
    let mut records: Vec<_> = certs
        .into_iter()
        .map(|cert| StateRecord {
            address: certificate_address(&claim.member, &cert.sector),
            member: claim.member,
            sector: cert.sector,
            certificate: cert.to_bytes(),
            usage: Vec::new(),
        })
        .collect();
    records.extend(count);
    let mut seen = BTreeSet::new();
    for seat in &claim.seats {
        for leaf in &seat.seals {
            let Some(root) = leaf.persistent else {
                continue;
            };
            if !seen.insert((seat.seal_epoch, root.sector)) {
                return Err("sector counted twice in one epoch".into());
            }
            let address = usage_address(&claim.member, &root.sector, seat.seal_epoch);
            if let Some(tree) =
                read(state, &address, &claim.member, &root.sector).map_err(|e| e.to_string())?
            {
                let used =
                    read_field(&tree, CLASS, "Usage").ok_or("invalid sector ownership record")?;
                let epoch = u64::from_be_bytes(
                    used.get(..8)
                        .ok_or("short sector ownership record")?
                        .try_into()
                        .unwrap(),
                );
                if epoch >= seat.seal_epoch {
                    return Err("sector is already allocated for this epoch".into());
                }
            }
            let usage = [
                seat.seal_epoch.to_be_bytes().as_slice(),
                leaf.leaf_id.as_slice(),
            ]
            .concat();
            records.push(StateRecord {
                address,
                member: claim.member,
                sector: root.sector,
                certificate: Vec::new(),
                usage,
            });
        }
    }
    Ok(records)
}

/// Read a typed record at a committed DB sequence, excluding staged execution.
fn committed_blob(
    snapshot: &dyn quil_types::store::SnapshotReadable,
    address: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    committed_underlying(snapshot, "vertex", address)
}
fn committed_underlying(
    snapshot: &dyn quil_types::store::SnapshotReadable,
    set: &str,
    address: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    if !snapshot.has_snapshot_vertex_reads() {
        return Err(QuilError::ExecutionUnavailable(
            "GLOBAL snapshot vertex reads unsupported".into(),
        ));
    }
    let location = quil_hypergraph::addressing::Location {
        app_address: GLOBAL_INTRINSIC_ADDRESS,
        data_address: *address,
    };
    snapshot.load_vertex_underlying_raw(
        set,
        "adds",
        &quil_hypergraph::addressing::shard_key_for_location(&location),
        &location.to_id(),
    )
}
pub fn committed_certificate(
    snapshot: &dyn quil_types::store::SnapshotReadable,
    member: &[u8; 32],
    id: &[u8; 32],
) -> Result<Option<sector::Certificate>> {
    committed_blob(snapshot, &certificate_address(member, id))?
        .map(|blob| {
            let tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&blob);
            let cert = read_field(&tree, CLASS, "Certificate")
                .and_then(|b| sector::Certificate::parse(&b));
            cert.filter(|c| {
                crate::global_schema::read_type(&tree) == Some(CLASS)
                    && c.sector == *id
                    && read_field(&tree, CLASS, "Sector").as_deref() == Some(id.as_slice())
                    && read_field(&tree, CLASS, "Member").as_deref() == Some(member.as_slice())
            })
            .ok_or_else(|| QuilError::InvalidArgument("invalid committed sector identity".into()))
        })
        .transpose()
}
pub fn committed_sector_room(
    snapshot: &dyn quil_types::store::SnapshotReadable,
    member: &[u8; 32],
) -> Result<SectorRoom> {
    sector_room(
        member,
        |address| committed_blob(snapshot, address),
        committed_underlying(snapshot, "hyperedge", member)?,
    )
}
pub fn committed_pending(
    snapshot: &dyn quil_types::store::SnapshotReadable,
    member: &[u8; 32],
    cert: &sector::Certificate,
    epoch: u64,
) -> Result<Option<PendingCertificate>> {
    capacity::decode_pending(
        committed_blob(snapshot, &capacity::pending_address(member, cert, epoch))?,
        member,
    )
}

#[cfg(test)]
mod tests;

pub use quil_storage_stark::seal::estimate_proving_memory_bytes as estimate_epoch_proving_memory_bytes;

//! Capacity certification is separate from useful-data registration. It never
//! creates a seat, pays a reward, or makes an unsealed participant eligible.
//! Signed precommits use a bounded ring of 16 slots per member per epoch.
//! Certificates stay, so a member's total is capped by its seats and each
//! certified sector is at least [`quil_types::consensus::min_sector_nodes`].
use super::super::storage_epoch_proof::{SeatProof, StorageEpochProof};
use super::*;

#[derive(Clone, Debug)]
pub struct PendingCertificate {
    pub certificate: sector::Certificate,
    pub epoch: u64,
    pub committed_at: u64,
}
#[derive(Clone, Debug)]
pub struct CapacityMessage {
    pub member: [u8; 32],
    pub epoch: u64,
    pub certificate: sector::Certificate,
    pub signed_at: u64,
    pub signature: Vec<u8>,
    pub proof: Vec<u8>,
}
fn filter() -> Vec<u8> {
    Sha3_256::digest(b"quil/persistent-sector-capacity/v1").to_vec()
}
pub fn capacity_message(proof: &StorageEpochProof) -> bool {
    proof.seats.len() == 1 && proof.seats[0].shard_filter == filter()
}
pub fn capacity_domain() -> Result<[u8; 32]> {
    super::super::verify::intrinsic_domain(b"PERSISTENT_SECTOR_PRECOMMIT")
}
pub(super) fn pending_address(
    member: &[u8; 32],
    cert: &sector::Certificate,
    epoch: u64,
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"quil/sector-precommit/v1");
    h.update(member);
    h.update([cert.sector[0] % 16]);
    h.update((epoch % 4).to_be_bytes());
    h.finalize().into()
}
impl CapacityMessage {
    pub fn signing_message(&self) -> Vec<u8> {
        [
            b"quil/sector-precommit/v1".as_slice(),
            &self.member,
            &self.epoch.to_be_bytes(),
            &self.signed_at.to_be_bytes(),
            &self.certificate.to_bytes(),
        ]
        .concat()
    }
    pub fn envelope(&self) -> StorageEpochProof {
        let profiled = self.certificate.profile != sector::Profile::Eleven;
        let mut bytes = match (profiled, self.proof.is_empty()) {
            (false, true) => b"PSC1".to_vec(),
            (false, false) => b"PSC2".to_vec(),
            (true, true) => b"PSC3".to_vec(),
            (true, false) => b"PSC4".to_vec(),
        };
        bytes.extend_from_slice(&self.signed_at.to_be_bytes());
        bytes.extend_from_slice(&self.certificate.to_bytes());
        lp(
            &mut bytes,
            if self.proof.is_empty() {
                &self.signature
            } else {
                &self.proof
            },
        );
        StorageEpochProof {
            member: self.member,
            seats: vec![SeatProof {
                shard_filter: filter(),
                epoch: self.epoch.saturating_sub(2),
                seals: true,
                ..Default::default()
            }],
            proof: bytes,
        }
    }
    /// Read a capacity message from its envelope ([`Self::envelope`]).
    pub fn decode(outer: &StorageEpochProof) -> std::result::Result<Self, String> {
        if !capacity_message(outer) {
            return Err("not a capacity certificate".into());
        }
        let part = &outer.seats[0];
        if !part.seals || part.settles || !part.frames.is_empty() || !part.bindings.is_empty() {
            return Err("capacity envelope shape".into());
        }
        let mut bytes = outer.proof.as_slice();
        let magic = take(&mut bytes, 4)?;
        if ![b"PSC1".as_slice(), b"PSC2", b"PSC3", b"PSC4"].contains(&magic) {
            return Err("capacity proof version".into());
        }
        let signed_at = u64::from_be_bytes(take(&mut bytes, 8)?.try_into().unwrap());
        let profiled = magic == b"PSC3" || magic == b"PSC4";
        let precommit = magic == b"PSC1" || magic == b"PSC3";
        let length = if profiled {
            sector::Certificate::PROFILED_BYTES
        } else {
            sector::Certificate::BYTES
        };
        let certificate = sector::Certificate::parse(take(&mut bytes, length)?)
            .ok_or("invalid capacity certificate")?;
        if profiled == (certificate.profile == sector::Profile::Eleven) {
            return Err("capacity suite encoding".into());
        }
        let payload = read_lp(&mut bytes)?.to_vec();
        if payload.is_empty() {
            return Err("empty capacity payload".into());
        }
        if !bytes.is_empty() {
            return Err("trailing capacity bytes".into());
        }
        let epoch = part.seal_epoch();
        Ok(Self {
            member: outer.member,
            epoch,
            certificate,
            signed_at,
            signature: if precommit {
                payload.clone()
            } else {
                Vec::new()
            },
            proof: if !precommit { payload } else { Vec::new() },
        })
    }
    /// The initial certificate proves zero data under a fixed sector identity.
    pub fn root(&self) -> sector::Registration {
        sector::Registration {
            profile: self.certificate.profile,
            data: quil_crypto::storage_proof::zero_commitment(
                quil_crypto::storage_proof::Tree::Data,
                self.certificate.n,
            )
            .unwrap(),
            labels: self.certificate.labels,
            replica: self.certificate.labels,
            sector: self.certificate.sector,
            columns: self.certificate.columns,
        }
    }
}

pub fn pending_certificate(
    state: &HypergraphState,
    member: &[u8; 32],
    cert: &sector::Certificate,
    epoch: u64,
) -> Result<Option<PendingCertificate>> {
    let address = pending_address(member, cert, epoch);
    decode_pending(
        state.get(
            &GLOBAL_INTRINSIC_ADDRESS,
            &address,
            &crate::hypergraph_state::vertex_adds_discriminator()?,
        )?,
        member,
    )
}
pub(super) fn decode_pending(
    blob: Option<Vec<u8>>,
    member: &[u8; 32],
) -> Result<Option<PendingCertificate>> {
    let Some(blob) = blob else {
        return Ok(None);
    };
    let tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&blob);
    let certificate = read_field(&tree, CLASS, "Certificate")
        .and_then(|b| sector::Certificate::parse(&b))
        .ok_or_else(|| QuilError::InvalidArgument("bad pending sector certificate".into()))?;
    let usage = read_field(&tree, CLASS, "Usage")
        .ok_or_else(|| QuilError::InvalidArgument("bad pending sector usage".into()))?;
    if crate::global_schema::read_type(&tree) != Some(CLASS)
        || read_field(&tree, CLASS, "Member").as_deref() != Some(member.as_slice())
        || usage.len() != 16
        || read_field(&tree, CLASS, "Sector").as_deref() != Some(certificate.sector.as_slice())
    {
        return Err(QuilError::InvalidArgument(
            "bad pending sector identity".into(),
        ));
    }
    Ok(Some(PendingCertificate {
        certificate,
        epoch: u64::from_be_bytes(usage[..8].try_into().unwrap()),
        committed_at: u64::from_be_bytes(usage[8..].try_into().unwrap()),
    }))
}

pub fn check_capacity(
    frame: u64,
    outer: &StorageEpochProof,
    state: &HypergraphState,
    keys: &dyn quil_types::crypto::KeyManager,
    output: &dyn Fn(u64) -> Result<Vec<u8>>,
) -> Result<Vec<StateRecord>> {
    let invalid = |e: String| QuilError::InvalidArgument(format!("capacity certificate: {e}"));
    let message = CapacityMessage::decode(outer).map_err(invalid)?;
    if !quil_types::consensus::persistent_storage_at(message.epoch) {
        return Err(invalid("persistent storage is inactive".into()));
    }
    if let Some(known) = certificate(state, &message.member, &message.certificate.sector)? {
        return if known == message.certificate {
            Ok(Vec::new())
        } else {
            Err(invalid("sector certificate changed".into()))
        };
    }
    if message.certificate.profile != sector::Profile::Eleven
        && message.certificate.profile != quil_types::consensus::storage_seal_profile(message.epoch)
    {
        return Err(invalid(
            "sector proof profile is not activated for this epoch".into(),
        ));
    }
    let floor = quil_types::consensus::min_sector_nodes();
    if message.certificate.n < floor {
        return Err(invalid(format!(
            "{} nodes is below the {floor}-node floor",
            message.certificate.n
        )));
    }
    let pending = pending_certificate(state, &message.member, &message.certificate, message.epoch)?;
    if message.proof.is_empty() {
        let current = quil_types::consensus::epoch_for_frame(frame);
        if !quil_types::consensus::capacity_precommit_window(current, message.epoch) {
            return Err(invalid("precommit outside warmup window".into()));
        }
        if message.signed_at > frame
            || frame - message.signed_at > 10
            || message.signature.len() > 2048
        {
            return Err(invalid("precommit freshness or signature length".into()));
        }
        let va = crate::hypergraph_state::vertex_adds_discriminator()?;
        let blob = state
            .get(&GLOBAL_INTRINSIC_ADDRESS, &message.member, &va)?
            .ok_or_else(|| invalid("unregistered member".into()))?;
        let tree = crate::prover_registry::rebuild_vertex_tree_from_blob(&blob);
        if !super::super::verify::verify_addressed_bls(
            &message.member,
            &message.signature,
            &tree,
            &message.signing_message(),
            &capacity_domain()?,
            keys,
            "sector precommit",
        )? {
            return Err(invalid("precommit signature".into()));
        }
        sector_room_in(state, &message.member)?
            .admit(&message.member, 1)
            .map_err(invalid)?;
        if let Some(pending) = pending {
            if pending.epoch == message.epoch && pending.certificate == message.certificate {
                return Ok(Vec::new());
            }
            if pending.epoch >= current.saturating_sub(2)
                && certificate(state, &message.member, &pending.certificate.sector)?.is_none()
            {
                return Err(invalid("precommit slot is still occupied".into()));
            }
        }
        return Ok(vec![StateRecord {
            address: pending_address(&message.member, &message.certificate, message.epoch),
            member: message.member,
            sector: message.certificate.sector,
            certificate: message.certificate.to_bytes(),
            usage: [message.epoch.to_be_bytes().as_slice(), &frame.to_be_bytes()].concat(),
        }]);
    }
    let pending = pending
        .filter(|p| p.epoch == message.epoch && p.certificate == message.certificate)
        .ok_or_else(|| invalid("no matching precommit".into()))?;
    let beacon_frame = pending
        .committed_at
        .checked_add(1)
        .ok_or_else(|| invalid("precommit frame overflow".into()))?;
    if frame <= beacon_frame {
        return Err(invalid("certificate beacon is not yet known".into()));
    }
    if quil_types::consensus::epoch_for_frame(frame) > message.epoch.saturating_add(2) {
        return Err(invalid("precommit expired".into()));
    }
    let count = sector_room_in(state, &message.member)?
        .admit(&message.member, 1)
        .map_err(invalid)?;
    let beacon = quil_crypto::porep::derive_storage_beacon(beacon_frame, &output(beacon_frame)?);
    quil_storage_stark::persistent::verify(
        &message.member,
        &message.certificate.sector,
        message.epoch,
        message.certificate.n,
        &message.root(),
        &beacon,
        &message.proof,
    )
    .map_err(invalid)?;
    Ok(vec![
        StateRecord {
            address: certificate_address(&message.member, &message.certificate.sector),
            member: message.member,
            sector: message.certificate.sector,
            certificate: message.certificate.to_bytes(),
            usage: Vec::new(),
        },
        count,
    ])
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    #[test]
    fn capacity_envelopes_bind_profiles_without_changing_legacy_formats() {
        for profile in [
            sector::Profile::Eleven,
            sector::Profile::Two,
            sector::Profile::Three,
        ] {
            for has_proof in [false, true] {
                let message = CapacityMessage {
                    member: [8; 32],
                    epoch: 1500,
                    certificate: sector::Certificate {
                        profile,
                        n: 32,
                        sector: [5; 32],
                        columns: [0; 32],
                        labels: [0; 32],
                    },
                    signed_at: 77,
                    signature: vec![3; 8],
                    proof: if has_proof { vec![4; 8] } else { vec![] },
                };
                let envelope = message.envelope();
                let decoded = CapacityMessage::decode(&envelope).unwrap();
                assert_eq!(decoded.certificate, message.certificate);
                assert_eq!(decoded.root().profile, profile);
                let expected: &[u8] = match (profile == sector::Profile::Eleven, has_proof) {
                    (true, false) => b"PSC1",
                    (true, true) => b"PSC2",
                    (false, false) => b"PSC3",
                    (false, true) => b"PSC4",
                };
                assert_eq!(&envelope.proof[..4], expected);
                let mut corrupt = envelope.clone();
                corrupt.proof[..4].copy_from_slice(if has_proof { b"PSC2" } else { b"PSC1" });
                if profile != sector::Profile::Eleven {
                    assert!(CapacityMessage::decode(&corrupt).is_err());
                }
            }
        }
    }
}

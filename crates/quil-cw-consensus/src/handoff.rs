//! Authenticated committee sessions and terminal Simplex checkpoints.
//!
//! A seal is a consensus payload in the OLD session. A quorum certificate for
//! an out-of-band statement about a local head is not a substitute. The app
//! automaton must check the selected parent and materialized roots before voting,
//! and refuse descendants of a seal. Global execution authorizes the successor
//! only after every source session in its transition has supplied such a seal.

use commonware_cryptography::{sha256::Sha256, Hasher as _};
use quil_types::error::{QuilError, Result};

use crate::app_cert::{verify_finalization_details, VerifiedFinalization};
use crate::falcon_base::FalconPublicKey;

pub mod automaton;

pub const MAX_MEMBERS: usize = 4096;
pub const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_FILTER_BYTES: usize = 66;
const SESSION_MAGIC: &[u8] = b"QHSS\x01";
const SEAL_MAGIC: &[u8] = b"QHSL\x01";

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("committee handoff: {message}"))
}

/// A globally authorized, immutable session. Its ID binds all configuration,
/// including the checkpoint that is implicitly finalized at Simplex view zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub chain_id: [u8; 32],
    pub filter: Vec<u8>,
    pub generation: u64,
    pub genesis: [u8; 32],
    pub base_frame: u64,
    pub authorization: [u8; 32],
    /// Strictly ascending Falcon public keys, without duplicates.
    pub members: Vec<Vec<u8>>,
}

impl Session {
    pub fn validate(&self) -> Result<()> {
        if !(32..=MAX_FILTER_BYTES).contains(&self.filter.len()) {
            return Err(invalid("invalid full shard filter length"));
        }
        if self.members.is_empty()
            || self.members.len() > MAX_MEMBERS
            || self.members.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .members
                .iter()
                .any(|key| FalconPublicKey::from_bytes(key).is_none())
        {
            return Err(invalid(
                "members must be bounded, unique, sorted Falcon keys",
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = SESSION_MAGIC.to_vec();
        out.extend_from_slice(&self.chain_id);
        put_bytes(&mut out, &self.filter)?;
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.genesis);
        out.extend_from_slice(&self.base_frame.to_be_bytes());
        out.extend_from_slice(&self.authorization);
        out.extend_from_slice(&(self.members.len() as u32).to_be_bytes());
        for key in &self.members {
            put_bytes(&mut out, key)?;
        }
        if out.len() > MAX_RECORD_BYTES {
            return Err(invalid("session exceeds size limit"));
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(bytes)?;
        c.magic(SESSION_MAGIC)?;
        let chain_id = c.array()?;
        let filter = c.bytes(MAX_FILTER_BYTES)?;
        let generation = c.u64()?;
        let genesis = c.array()?;
        let base_frame = c.u64()?;
        let authorization = c.array()?;
        let n = c.count(MAX_MEMBERS, 4 + quil_crypto::FALCON_PUBLIC_KEY_LEN)?;
        let mut members = Vec::with_capacity(n);
        for _ in 0..n {
            members.push(c.bytes(quil_crypto::FALCON_PUBLIC_KEY_LEN)?);
        }
        c.finish()?;
        let session = Self {
            chain_id,
            filter,
            generation,
            genesis,
            base_frame,
            authorization,
            members,
        };
        session.validate()?;
        Ok(session)
    }

    pub fn id(&self) -> Result<[u8; 32]> {
        Ok(Sha256::hash(&self.encode()?).0)
    }

    /// Generation zero retains the deployed namespace ONLY for an explicitly
    /// registered legacy source. It must not be used for a successor session.
    /// Legacy journal reconciliation remains the migration caller's obligation.
    pub fn namespace(&self) -> Result<Vec<u8>> {
        self.validate()?;
        if self.generation == 0 {
            let mut namespace = b"appshard".to_vec();
            namespace.extend_from_slice(&self.filter);
            return Ok(namespace);
        }
        let mut namespace = b"quil/app/simplex/session/v1/".to_vec();
        namespace.extend_from_slice(&self.id()?);
        Ok(namespace)
    }
}

/// State AFTER materializing the last data frame. Header pre-state roots alone
/// do not establish this checkpoint. Outgoing history must be durably available
/// and authenticated by `history_root` before a successor is allowed to vote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub frame: u64,
    pub view: u64,
    pub digest: [u8; 32],
    pub state_roots: [[u8; 32]; 4],
    pub history_root: [u8; 32],
}

impl Checkpoint {
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.frame.to_be_bytes());
        out.extend_from_slice(&self.view.to_be_bytes());
        out.extend_from_slice(&self.digest);
        for root in self.state_roots {
            out.extend_from_slice(&root);
        }
        out.extend_from_slice(&self.history_root);
    }

    pub fn read(c: &mut Cursor<'_>) -> Result<Self> {
        Ok(Self {
            frame: c.u64()?,
            view: c.u64()?,
            digest: c.array()?,
            state_roots: [c.array()?, c.array()?, c.array()?, c.array()?],
            history_root: c.array()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seal {
    pub request: [u8; 32],
    pub session: [u8; 32],
    pub view: u64,
    pub checkpoint: Checkpoint,
}

impl Seal {
    /// Identify the reserved payload family before strict decoding. Unsupported
    /// versions and malformed seals must not fall through to data-frame parsing.
    pub fn is_encoding(bytes: &[u8]) -> bool {
        bytes.starts_with(&SEAL_MAGIC[..4])
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = SEAL_MAGIC.to_vec();
        out.extend_from_slice(&self.request);
        out.extend_from_slice(&self.session);
        out.extend_from_slice(&self.view.to_be_bytes());
        self.checkpoint.write(&mut out);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(bytes)?;
        c.magic(SEAL_MAGIC)?;
        let seal = Self {
            request: c.array()?,
            session: c.array()?,
            view: c.u64()?,
            checkpoint: Checkpoint::read(&mut c)?,
        };
        c.finish()?;
        Ok(seal)
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::hash(&self.encode()).0
    }

    pub fn validate(&self, session: &Session, request: &[u8; 32]) -> Result<()> {
        if self.session != session.id()? || &self.request != request {
            return Err(invalid("seal belongs to another request or session"));
        }
        if self.view <= self.checkpoint.view || self.checkpoint.frame < session.base_frame {
            return Err(invalid("seal regresses its checkpoint"));
        }
        if self.checkpoint.frame == session.base_frame {
            if self.checkpoint.view != 0 || self.checkpoint.digest != session.genesis {
                return Err(invalid("seal changes the authorized genesis"));
            }
        } else if self.checkpoint.view == 0 {
            return Err(invalid(
                "a materialized data frame must have a nonzero view",
            ));
        }
        Ok(())
    }
}

pub fn verify_seal(
    session: &Session,
    request: &[u8; 32],
    seal: &Seal,
    certificate: &[u8],
) -> Option<VerifiedFinalization> {
    if certificate.len() > MAX_RECORD_BYTES {
        return None;
    }
    seal.validate(session, request).ok()?;
    let verified = verify_finalization_details(
        certificate,
        &session.members,
        &session.namespace().ok()?,
        seal.digest(),
    )?;
    let proposal = &verified.finalization.proposal;
    if proposal.round.epoch().get() != session.generation
        || proposal.round.view().get() != seal.view
        || proposal.parent.get() != seal.checkpoint.view
    {
        return None;
    }
    Some(verified)
}

/// Small bounded codec shared with the global authorization record. Counts are
/// checked against both protocol limits and available input before allocating.
pub fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len = u32::try_from(bytes.len()).map_err(|_| invalid("field exceeds size limit"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

pub struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Cursor<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("record exceeds size limit"));
        }
        Ok(Self { bytes, offset: 0 })
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or_else(|| invalid("length overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invalid("truncated record"))?;
        self.offset = end;
        Ok(value)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    pub fn count(&mut self, max: usize, min_bytes: usize) -> Result<usize> {
        let n = self.u32()? as usize;
        if n > max || n > self.bytes.len().saturating_sub(self.offset) / min_bytes.max(1) {
            return Err(invalid("invalid collection length"));
        }
        Ok(n)
    }
    pub fn bytes(&mut self, max: usize) -> Result<Vec<u8>> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(invalid("field exceeds size limit"));
        }
        Ok(self.take(n)?.to_vec())
    }
    pub fn magic(&mut self, expected: &[u8]) -> Result<()> {
        if self.take(expected.len())? != expected {
            return Err(invalid("unknown record version"));
        }
        Ok(())
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    /// Whether every byte has been read.
    pub fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
    pub fn finish(self) -> Result<()> {
        if self.offset != self.bytes.len() {
            return Err(invalid("trailing record bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        app_cert::encode_finalization, falcon_base::FalconPrivateKey,
        falcon_simplex::SimplexFalconScheme,
    };
    use commonware_consensus::{
        simplex::types::{Finalization, Proposal, Subject},
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{certificate::Scheme as _, sha256::Digest, Signer as _};
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_utils::{ordered::Set, N3f1};

    fn keys() -> Vec<FalconPrivateKey> {
        (0..4)
            .map(|_| FalconPrivateKey::random(commonware_utils::test_rng()))
            .collect()
    }

    fn session(keys: &[FalconPrivateKey]) -> Session {
        let mut members: Vec<_> = keys
            .iter()
            .map(|k| k.public_key().as_ref().to_vec())
            .collect();
        members.sort();
        Session {
            chain_id: [1; 32],
            filter: vec![2; 32],
            generation: 7,
            genesis: [3; 32],
            base_frame: 10,
            authorization: [4; 32],
            members,
        }
    }

    fn certify(
        keys: &[FalconPrivateKey],
        session: &Session,
        seal: &Seal,
        epoch: u64,
        view: u64,
        parent: u64,
    ) -> Vec<u8> {
        let members: Set<_> = keys
            .iter()
            .map(|key| key.public_key())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let schemes: Vec<_> = keys
            .iter()
            .cloned()
            .map(|key| {
                SimplexFalconScheme::signer(&session.namespace().unwrap(), members.clone(), key)
                    .unwrap()
            })
            .collect();
        let proposal = Proposal::new(
            Round::new(Epoch::new(epoch), View::new(view)),
            View::new(parent),
            Digest(seal.digest()),
        );
        let votes: Vec<_> = schemes[..3]
            .iter()
            .map(|s| {
                s.sign(Subject::Finalize {
                    proposal: &proposal,
                })
                .unwrap()
            })
            .collect();
        encode_finalization(&Finalization {
            proposal,
            certificate: schemes[0].assemble::<_, N3f1>(votes, &Sequential).unwrap(),
        })
    }

    #[test]
    fn closing_certificate_binds_request_checkpoint_and_simplex_coordinates() {
        let keys = keys();
        let session = session(&keys);
        let request = [5; 32];
        let seal = Seal {
            request,
            session: session.id().unwrap(),
            view: 44,
            checkpoint: Checkpoint {
                frame: 19,
                view: 40,
                digest: [6; 32],
                state_roots: [[7; 32]; 4],
                history_root: [8; 32],
            },
        };
        let certificate = certify(&keys, &session, &seal, 7, 44, 40);
        assert!(verify_seal(&session, &request, &seal, &certificate).is_some());
        for (epoch, view, parent) in [(8, 44, 40), (7, 45, 40), (7, 44, 39)] {
            assert!(verify_seal(
                &session,
                &request,
                &seal,
                &certify(&keys, &session, &seal, epoch, view, parent)
            )
            .is_none());
        }
        for field in 0..7 {
            let mut changed = seal.clone();
            match field {
                0 => changed.request[0] ^= 1,
                1 => changed.session[0] ^= 1,
                2 => changed.checkpoint.digest[0] ^= 1,
                3 => changed.checkpoint.state_roots[2][0] ^= 1,
                4 => changed.checkpoint.history_root[0] ^= 1,
                5 => changed.checkpoint.frame += 1,
                _ => changed.checkpoint.view += 1,
            }
            assert!(verify_seal(&session, &request, &changed, &certificate).is_none());
        }
        let mut trailing = certificate.clone();
        trailing.push(0);
        assert!(verify_seal(&session, &request, &seal, &trailing).is_none());
        assert!(verify_seal(
            &session,
            &request,
            &seal,
            &certificate[..certificate.len() - 1]
        )
        .is_none());
    }

    #[test]
    fn returning_members_do_not_reuse_a_session_namespace() {
        let keys = keys();
        let first = session(&keys);
        let mut returning = first.clone();
        returning.generation += 2;
        assert_ne!(first.namespace().unwrap(), returning.namespace().unwrap());
        for field in 0..5 {
            let mut changed = first.clone();
            match field {
                0 => changed.chain_id[0] ^= 1,
                1 => changed.filter.push(1),
                2 => changed.genesis[0] ^= 1,
                3 => changed.authorization[0] ^= 1,
                _ => changed.base_frame += 1,
            }
            assert_ne!(first.namespace().unwrap(), changed.namespace().unwrap());
        }
        let mut invalid = first.clone();
        invalid.members.swap(0, 1);
        assert!(invalid.encode().is_err());
        invalid = first.clone();
        invalid.members[1] = invalid.members[0].clone();
        assert!(invalid.encode().is_err());
    }

    #[test]
    fn strict_bounded_codecs_and_genesis_parent() {
        let keys = keys();
        let session = session(&keys);
        let bytes = session.encode().unwrap();
        assert_eq!(Session::decode(&bytes).unwrap(), session);
        for n in 0..bytes.len() {
            assert!(Session::decode(&bytes[..n]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(Session::decode(&extra).is_err());
        assert!(Cursor::new(&vec![0; MAX_RECORD_BYTES + 1]).is_err());
        let mut seal = Seal {
            request: [5; 32],
            session: session.id().unwrap(),
            view: 1,
            checkpoint: Checkpoint {
                frame: session.base_frame,
                view: 0,
                digest: session.genesis,
                state_roots: [[0; 32]; 4],
                history_root: [8; 32],
            },
        };
        assert!(seal.validate(&session, &[5; 32]).is_ok());
        let bytes = seal.encode();
        assert_eq!(Seal::decode(&bytes).unwrap(), seal);
        for n in 0..bytes.len() {
            assert!(Seal::decode(&bytes[..n]).is_err());
        }
        seal.checkpoint.digest[0] ^= 1;
        assert!(seal.validate(&session, &[5; 32]).is_err());
        seal.checkpoint.digest = session.genesis;
        seal.checkpoint.frame += 1;
        assert!(seal.validate(&session, &[5; 32]).is_err());
    }
}

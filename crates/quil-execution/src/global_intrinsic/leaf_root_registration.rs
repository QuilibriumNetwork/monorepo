//! `LeafRootRegistration` canonical-bytes envelope.
//!
//! A committee member registers the KZG `leaf_root` it is storing for one
//! `(shard, prefix)` leaf in one replication `epoch`. The per-frame storage
//! attestation later proves possession against this registered root, so the
//! verifier cross-checks `opening.leaf_root == registry.get(member, leaf_id,
//! epoch)` — without registration a cheater could open a self-chosen junk leaf.
//!
//! The leaf is identified by its parent shard `shard_filter` (the
//! `confirmation_filter` = `ShardKey.l2`) plus the sub-shard `prefix` (the
//! 6-bit-nibble path extension that names the logical shard within the shard's
//! vector-commitment tree). The registration is keyed on
//! `(member, leaf_id = canonical(shard_filter ‖ prefix), epoch)`.
//!
//! Wire format (type 0x0320):
//!
//! ```text
//! [u32 BE type_prefix = 0x0320]
//! [u32 BE shard_filter_len] [shard_filter_len bytes]
//! [u32 BE prefix_count]
//!   for each prefix nibble: [u32 BE value]
//! [u64 BE epoch]
//! [u32 BE leaf_root_len] [leaf_root_len bytes]
//! [u64 BE num_blocks]
//! [u64 BE frame_number]
//! [u32 BE sig_len] [sig_len bytes BLS48581SignatureWithProofOfPossession]
//! ```

use quil_types::error::{QuilError, Result};
use crate::canonical_cursor::{put_u32, put_u64, read_u32, read_u64, read_bytes};
use super::sig_with_pop::SignatureWithPop;

pub const TYPE_LEAF_ROOT_REGISTRATION: u32 = 0x0320;

const MAX_SHARD_FILTER_LEN: u32 = 64;
/// A leaf prefix is a nibble path; a 1 GiB leaf at 6-bit branching is at most a
/// few levels deep, but bound generously.
const MAX_PREFIX_LEN: u32 = 256;
const MAX_LEAF_ROOT_LEN: u32 = 128;
const MAX_SIG_LEN: u32 = 753;

/// A member's storage registration for one leaf in one epoch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LeafRootRegistration {
    /// The parent shard's confirmation filter (`ShardKey.l2`).
    pub shard_filter: Vec<u8>,
    /// The leaf's sub-shard prefix path (6-bit nibbles) within the shard tree.
    pub prefix: Vec<u32>,
    /// The replication epoch (SDR re-encode generation).
    pub epoch: u64,
    /// The KZG root of the leaf's vector-commitment tree being registered.
    pub leaf_root: Vec<u8>,
    /// The leaf's block count (sets the challenge block index + path depth).
    pub num_blocks: u64,
    /// The frame at which this registration is submitted.
    pub frame_number: u64,
    /// The registering member's BLS48-581 signature (+ proof of possession).
    pub public_key_signature_bls48581: Option<SignatureWithPop>,
}

impl LeafRootRegistration {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_LEAF_ROOT_REGISTRATION);

        put_u32(&mut out, self.shard_filter.len() as u32);
        out.extend_from_slice(&self.shard_filter);

        put_u32(&mut out, self.prefix.len() as u32);
        for p in &self.prefix {
            put_u32(&mut out, *p);
        }

        put_u64(&mut out, self.epoch);

        put_u32(&mut out, self.leaf_root.len() as u32);
        out.extend_from_slice(&self.leaf_root);

        put_u64(&mut out, self.num_blocks);
        put_u64(&mut out, self.frame_number);

        match &self.public_key_signature_bls48581 {
            Some(sig) => {
                let sb = sig.to_canonical_bytes()?;
                put_u32(&mut out, sb.len() as u32);
                out.extend_from_slice(&sb);
            }
            None => put_u32(&mut out, 0),
        }

        Ok(out)
    }

    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0usize;

        let tp = read_u32(data, &mut c)?;
        if tp != TYPE_LEAF_ROOT_REGISTRATION {
            return Err(QuilError::InvalidArgument(format!(
                "LeafRootRegistration: invalid type prefix 0x{:08x}", tp
            )));
        }

        let sfl = read_u32(data, &mut c)?;
        if sfl > MAX_SHARD_FILTER_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "LeafRootRegistration: invalid shard_filter length {}", sfl
            )));
        }
        let shard_filter = read_bytes(data, &mut c, sfl as usize)?;

        let pc = read_u32(data, &mut c)?;
        if pc > MAX_PREFIX_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "LeafRootRegistration: invalid prefix length {}", pc
            )));
        }
        let mut prefix = Vec::with_capacity(pc as usize);
        for _ in 0..pc {
            prefix.push(read_u32(data, &mut c)?);
        }

        let epoch = read_u64(data, &mut c)?;

        let lrl = read_u32(data, &mut c)?;
        if lrl > MAX_LEAF_ROOT_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "LeafRootRegistration: invalid leaf_root length {}", lrl
            )));
        }
        let leaf_root = read_bytes(data, &mut c, lrl as usize)?;

        let num_blocks = read_u64(data, &mut c)?;
        let frame_number = read_u64(data, &mut c)?;

        let sl = read_u32(data, &mut c)?;
        if sl > MAX_SIG_LEN {
            return Err(QuilError::InvalidArgument(format!(
                "LeafRootRegistration: invalid signature length {}", sl
            )));
        }
        let public_key_signature_bls48581 = if sl > 0 {
            let sb = read_bytes(data, &mut c, sl as usize)?;
            Some(SignatureWithPop::from_canonical_bytes(&sb)?)
        } else {
            None
        };

        Ok(Self {
            shard_filter,
            prefix,
            epoch,
            leaf_root,
            num_blocks,
            frame_number,
            public_key_signature_bls48581,
        })
    }

    /// The canonical leaf identifier `shard_filter ‖ prefix` (each nibble as a
    /// u32 BE), used as the per-leaf component of the registration address.
    /// Deterministic and collision-free across shards/prefixes.
    pub fn leaf_id(&self) -> Vec<u8> {
        leaf_id_bytes(&self.shard_filter, &self.prefix)
    }
}

/// One leaf's storage root within a shard being confirmed. The shard filter is
/// carried by the enclosing [`ConfirmLeafRoots`]; the member is the confirm's
/// signer. Folded into `ProverConfirm` so a prover re-registers its leaf roots
/// as part of each epoch's re-confirm.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LeafRootEntry {
    pub prefix: Vec<u32>,
    pub leaf_root: Vec<u8>,
    pub num_blocks: u64,
}

/// All leaf roots a prover registers for one shard (filter) at confirm time.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfirmLeafRoots {
    pub filter: Vec<u8>,
    pub entries: Vec<LeafRootEntry>,
}

/// Append the canonical encoding of a confirm's leaf-root set to `out`.
/// Deterministic and length-prefixed; used both in `ProverConfirm`'s canonical
/// bytes and in its signing message. **An empty set appends nothing**, so a
/// confirm carrying no leaf roots signs and serializes byte-identically to the
/// pre-storage-attestation format (back-compat).
pub fn append_confirm_leaf_roots(out: &mut Vec<u8>, groups: &[ConfirmLeafRoots]) {
    if groups.is_empty() {
        return;
    }
    out.extend_from_slice(&(groups.len() as u32).to_be_bytes());
    for g in groups {
        out.extend_from_slice(&(g.filter.len() as u32).to_be_bytes());
        out.extend_from_slice(&g.filter);
        out.extend_from_slice(&(g.entries.len() as u32).to_be_bytes());
        for e in &g.entries {
            out.extend_from_slice(&(e.prefix.len() as u32).to_be_bytes());
            for p in &e.prefix {
                out.extend_from_slice(&p.to_be_bytes());
            }
            out.extend_from_slice(&(e.leaf_root.len() as u32).to_be_bytes());
            out.extend_from_slice(&e.leaf_root);
            out.extend_from_slice(&e.num_blocks.to_be_bytes());
        }
    }
}

/// Read a confirm's leaf-root set written by [`append_confirm_leaf_roots`].
/// Absence (cursor at end) yields an empty set (back-compat).
pub fn read_confirm_leaf_roots(
    data: &[u8],
    cursor: &mut usize,
) -> Result<Vec<ConfirmLeafRoots>> {
    if *cursor >= data.len() {
        return Ok(Vec::new());
    }
    let n = read_u32(data, cursor)?;
    if n > MAX_PREFIX_LEN {
        return Err(QuilError::InvalidArgument(format!(
            "ConfirmLeafRoots: too many groups {}", n
        )));
    }
    let mut groups = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let fl = read_u32(data, cursor)?;
        if fl > MAX_SHARD_FILTER_LEN {
            return Err(QuilError::InvalidArgument("ConfirmLeafRoots: filter too long".into()));
        }
        let filter = read_bytes(data, cursor, fl as usize)?;
        let ec = read_u32(data, cursor)?;
        if ec > MAX_PREFIX_LEN {
            return Err(QuilError::InvalidArgument("ConfirmLeafRoots: too many entries".into()));
        }
        let mut entries = Vec::with_capacity(ec as usize);
        for _ in 0..ec {
            let pc = read_u32(data, cursor)?;
            if pc > MAX_PREFIX_LEN {
                return Err(QuilError::InvalidArgument("ConfirmLeafRoots: prefix too long".into()));
            }
            let mut prefix = Vec::with_capacity(pc as usize);
            for _ in 0..pc {
                prefix.push(read_u32(data, cursor)?);
            }
            let lrl = read_u32(data, cursor)?;
            if lrl > MAX_LEAF_ROOT_LEN {
                return Err(QuilError::InvalidArgument("ConfirmLeafRoots: leaf_root too long".into()));
            }
            let leaf_root = read_bytes(data, cursor, lrl as usize)?;
            let num_blocks = read_u64(data, cursor)?;
            entries.push(LeafRootEntry { prefix, leaf_root, num_blocks });
        }
        groups.push(ConfirmLeafRoots { filter, entries });
    }
    Ok(groups)
}

/// Build the canonical leaf id from a shard filter and sub-shard prefix:
/// `shard_filter ‖ 0xFF ‖ prefix[0..] (u32 BE each)`. The `0xFF` separator keeps
/// `(filter=ab, prefix=[c])` distinct from `(filter=a, prefix=[bc-ambiguity])`.
pub fn leaf_id_bytes(shard_filter: &[u8], prefix: &[u32]) -> Vec<u8> {
    let mut id = Vec::with_capacity(shard_filter.len() + 1 + prefix.len() * 4);
    id.extend_from_slice(shard_filter);
    id.push(0xFF);
    for p in prefix {
        id.extend_from_slice(&p.to_be_bytes());
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(sig: bool) -> LeafRootRegistration {
        LeafRootRegistration {
            shard_filter: vec![0xAB; 32],
            prefix: vec![42, 7, 255],
            epoch: 19,
            leaf_root: vec![0x11; 74],
            num_blocks: 1234,
            frame_number: 900_000,
            public_key_signature_bls48581: if sig {
                Some(SignatureWithPop {
                    signature: vec![0x22; 74],
                    public_key: Some(vec![0x33; 585]),
                    pop_signature: vec![0x44; 74],
                })
            } else {
                None
            },
        }
    }

    #[test]
    fn round_trips_with_signature() {
        let r = sample(true);
        let b = r.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_LEAF_ROOT_REGISTRATION.to_be_bytes());
        assert_eq!(LeafRootRegistration::from_canonical_bytes(&b).unwrap(), r);
    }

    #[test]
    fn round_trips_without_signature() {
        let r = sample(false);
        let b = r.to_canonical_bytes().unwrap();
        assert_eq!(LeafRootRegistration::from_canonical_bytes(&b).unwrap(), r);
    }

    #[test]
    fn empty_round_trips() {
        let r = LeafRootRegistration::default();
        let b = r.to_canonical_bytes().unwrap();
        assert_eq!(LeafRootRegistration::from_canonical_bytes(&b).unwrap(), r);
    }

    #[test]
    fn leaf_id_is_distinct_per_shard_and_prefix() {
        let a = leaf_id_bytes(&[0xAA, 0xBB], &[1, 2]);
        let b = leaf_id_bytes(&[0xAA], &[0xBB00_0001, 2]);
        // Without the separator these could collide; assert they don't.
        assert_ne!(a, b);
        assert_eq!(leaf_id_bytes(&[0xAA, 0xBB], &[1, 2]), a);
        assert_ne!(leaf_id_bytes(&[0xAA, 0xBB], &[1, 3]), a);
    }

    #[test]
    fn bad_type_prefix_rejected() {
        let mut b = sample(false).to_canonical_bytes().unwrap();
        b[0] = 0xFF;
        assert!(LeafRootRegistration::from_canonical_bytes(&b).is_err());
    }
}

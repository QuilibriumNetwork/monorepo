//! Commitment to the outgoing records of a closing application session.
//!
//! Read from the same committed snapshot as the materialized cursor and state
//! roots. Missing records are unavailable, including empty frames: assuming an
//! absent fee, settlement, spend or report record is empty would lose outflows
//! on restart/handoff. The caller separately authenticates the selected data
//! parent and verifies that any inherited source history has been recovered.

use quil_cw_consensus::handoff::Session;
use quil_store::encoding;
use quil_types::{
    error::{QuilError, Result},
    store::SnapshotReadable,
};
use sha2::{Digest as _, Sha256};

use crate::token_intrinsic::{accumulator_header, settlement_record, spend_relay};

fn unavailable(message: &str) -> QuilError {
    QuilError::ExecutionUnavailable(format!("handoff outgoing history: {message}"))
}

fn required(snapshot: &dyn SnapshotReadable, key: &[u8], what: &str, frame: u64) -> Result<Vec<u8>> {
    snapshot
        .read_record(key)?
        .ok_or_else(|| unavailable(&format!("required committed record absent ({what}, frame {frame})")))
}

fn field(hash: &mut Sha256, bytes: &[u8]) -> Result<()> {
    let length =
        u32::try_from(bytes.len()).map_err(|_| unavailable("record exceeds encoding limit"))?;
    hash.update(length.to_be_bytes());
    hash.update(bytes);
    Ok(())
}

/// One frame's outgoing records, the inputs of its link in the chain.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FrameOutgoing {
    pub frame: u64,
    /// 16-byte big-endian fee total.
    pub fees: Vec<u8>,
    pub settlements: Vec<u8>,
    pub spends: Vec<u8>,
    /// Report digest, empty for none.
    pub digest: Vec<u8>,
    /// Report bytes under `digest`, empty for none.
    pub report: Vec<u8>,
}

impl FrameOutgoing {
    /// The records as stored under `filter`, the shape the chain reads.
    pub fn records(&self, filter: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut records = vec![
            (encoding::clock_shard_frame_fee_total_key(filter, self.frame), self.fees.clone()),
            (encoding::clock_shard_frame_settlements_key(filter, self.frame), self.settlements.clone()),
            (encoding::clock_shard_frame_spends_key(filter, self.frame), self.spends.clone()),
            (encoding::clock_shard_frame_accumulator_key(filter, self.frame), self.digest.clone()),
        ];
        if !self.digest.is_empty() {
            records.push((encoding::clock_shard_accumulator_report_key(filter, &self.digest), self.report.clone()));
        }
        records
    }
}

/// Extend the chain value `root` by one frame's records, validating each.
pub fn link(root: [u8; 32], outgoing: &FrameOutgoing) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"quil/app/handoff/history/frame/v1");
    hash.update(root);
    hash.update(outgoing.frame.to_be_bytes());
    if outgoing.fees.len() != 16 {
        return Err(unavailable("malformed fee total"));
    }
    field(&mut hash, &outgoing.fees)?;
    settlement_record::decode_entries(&outgoing.settlements)
        .map_err(|_| unavailable("malformed settlements"))?;
    field(&mut hash, &outgoing.settlements)?;
    spend_relay::decode_frame_entries(&outgoing.spends).map_err(|_| unavailable("malformed spends"))?;
    field(&mut hash, &outgoing.spends)?;
    if !outgoing.digest.is_empty() && outgoing.digest.len() != 32 {
        return Err(unavailable("malformed accumulator digest"));
    }
    field(&mut hash, &outgoing.digest)?;
    if accumulator_header::report_digest(&outgoing.report) != outgoing.digest {
        return Err(unavailable("accumulator report does not match its digest"));
    }
    field(&mut hash, &outgoing.report)?;
    Ok(hash.finalize().into())
}

/// The chain value before any frame of `session`.
pub fn start(session: &Session) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"quil/app/handoff/history/start/v1");
    hash.update(session.id()?);
    Ok(hash.finalize().into())
}

/// Hash this session's complete outgoing history through its materialized tip.
/// The initial value binds the session ID, which also commits to the predecessor
/// seals via its global authorization. This does not substitute for recovering
/// those predecessors' records before successor readiness is published.
///
/// This cold path is linear in session length and holds at most one frame's
/// records; [`extend`] continues a chain value the caller already computed.
pub fn root(snapshot: &dyn SnapshotReadable, session: &Session, through: u64) -> Result<[u8; 32]> {
    if through < session.base_frame {
        return Err(unavailable("tip precedes session genesis"));
    }
    extend(snapshot, session, session.base_frame, start(session)?, through)
}

/// Continue the chain from `root`, its value through frame `from`, to `through`.
/// Finalized frames are immutable, so a value computed from an earlier committed
/// snapshot of the same session stays valid; the caller must not mix sessions.
pub fn extend(
    snapshot: &dyn SnapshotReadable,
    session: &Session,
    from: u64,
    mut root: [u8; 32],
    through: u64,
) -> Result<[u8; 32]> {
    if from < session.base_frame || through < from {
        return Err(unavailable("tip precedes the known chain value"));
    }
    let cursor = required(
        snapshot,
        &encoding::consensus_materialized_cursor_key(&session.filter),
        "materialized cursor", through,
    )?;
    let cursor: [u8; 8] = cursor
        .try_into()
        .map_err(|_| unavailable("malformed materialized cursor"))?;
    if u64::from_be_bytes(cursor) != through {
        return Err(unavailable("tip differs from the committed cursor"));
    }
    let mut frame = from;
    while frame < through {
        frame += 1;
        let fees = required(
            snapshot,
            &encoding::clock_shard_frame_fee_total_key(&session.filter, frame),
            "fee total", frame,
        )?;
        let settlements = required(
            snapshot,
            &encoding::clock_shard_frame_settlements_key(&session.filter, frame),
            "settlements", frame,
        )?;
        let spends = required(
            snapshot,
            &encoding::clock_shard_frame_spends_key(&session.filter, frame),
            "spends", frame,
        )?;
        let digest = required(
            snapshot,
            &encoding::clock_shard_frame_accumulator_key(&session.filter, frame),
            "accumulator digest", frame,
        )?;
        let report = if digest.is_empty() {
            Vec::new()
        } else {
            required(
                snapshot,
                &encoding::clock_shard_accumulator_report_key(&session.filter, &digest),
                "accumulator report", frame,
            )?
        };
        root = link(root, &FrameOutgoing { frame, fees, settlements, spends, digest, report })?;
    }
    Ok(root)
}

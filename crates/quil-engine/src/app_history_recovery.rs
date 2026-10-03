//! Bounded, resumable recovery of a session's outgoing history before voting.
//! Headers are authenticated before their relay fields are used. Omitted
//! accumulator fields are resolved only by an exact state match or the
//! nonempty carry-window implication; ambiguity remains unavailable.

use prost::Message;
use quil_cw_consensus::handoff::Session;
use quil_execution::{
    token_intrinsic::{
        accumulator_header::{self, CARRY_WINDOW_FRAMES, HEARTBEAT_FRAMES},
        settlement_record, shard_accumulator, spend_relay,
    },
    ExecutionEngineManager,
};
use quil_store::encoding;
use quil_types::{
    error::{QuilError, Result},
    proto::global::FrameHeader,
    store::{ClockStore, SnapshotReadable},
};
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{app_engine::DeliveryFrameSource, frame_validator::BlsAppFrameValidator};

const MAX_FRAMES: usize = 8;
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROGRESS_BYTES: usize = 2 * 1024 * 1024;
const MAX_REPORT_STATES: usize = 8;
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;
type Roots = [[u8; 32]; 4];

fn unavailable(message: impl Into<String>) -> QuilError {
    QuilError::ExecutionUnavailable(format!("app history recovery: {}", message.into()))
}

#[derive(Serialize, Deserialize)]
struct Progress {
    version: u8,
    session: [u8; 32],
    done: u64,
    target: u64,
    next: u64,
    carry: u64,
    last_report: Vec<u8>,
    reports: Vec<(Roots, Vec<u8>)>,
    /// `(m, report)`: every frame above `m` still to be walked, down to but
    /// excluding `m`, has `report` (see [`earlier_report`]).
    #[serde(default)]
    implied: Option<(u64, Vec<u8>)>,
}

impl Progress {
    fn remember(&mut self, roots: Roots, report: Vec<u8>) -> Result<()> {
        if !report.is_empty() {
            shard_accumulator::ShardReport::decode(&report)?;
        }
        if let Some((_, existing)) = self.reports.iter().find(|(known, _)| *known == roots) {
            if *existing != report {
                return Err(unavailable(
                    "authenticated reports disagree over identical state",
                ));
            }
            return Ok(());
        }
        self.reports.insert(0, (roots, report));
        self.reports.truncate(MAX_REPORT_STATES);
        Ok(())
    }

    fn report(&self, roots: &Roots) -> Option<Vec<u8>> {
        self.reports
            .iter()
            .find(|(known, _)| known == roots)
            .map(|(_, report)| report.clone())
    }

    fn resolve(&self, header: &FrameHeader) -> Result<Option<Vec<u8>>> {
        let roots = header_roots(header)?;
        let report = if !header.accumulator.is_empty()
            || header.frame_number % HEARTBEAT_FRAMES == 0
        {
            Some(header.accumulator.clone())
        } else {
            self.report(&roots).or_else(|| {
                (self.carry > 0 && !self.last_report.is_empty()).then(|| self.last_report.clone())
            })
        };
        if let Some(report) = report.as_ref() {
            if !report.is_empty() {
                shard_accumulator::ShardReport::decode(report)?;
            }
            if (self.carry > 0 && *report != self.last_report)
                || self.report(&roots).is_some_and(|known| known != *report)
            {
                return Err(unavailable("certified accumulator constraints disagree"));
            }
        }
        Ok(report)
    }

    fn validate(&self, session: &Session, cursor: u64) -> Result<()> {
        if self.version != 1
            || self.session != session.id()?
            || self.done < session.base_frame
            || self.done > self.next
            || self.next > self.target
            || self.target > cursor
            || self.carry > CARRY_WINDOW_FRAMES
            || self.reports.len() > MAX_REPORT_STATES
            || self.last_report.len() > shard_accumulator::MAX_REPORT_BYTES
            || self.implied.as_ref().is_some_and(|(low, report)| {
                *low < self.done || *low >= self.next || report.len() > shard_accumulator::MAX_REPORT_BYTES
            })
        {
            return Err(unavailable("invalid recovery progress"));
        }
        if let Some((_, report)) = self.implied.as_ref().filter(|(_, report)| !report.is_empty()) {
            shard_accumulator::ShardReport::decode(report)?;
        }
        for (_, report) in &self.reports {
            if !report.is_empty() {
                shard_accumulator::ShardReport::decode(report)?;
            }
        }
        if !self.last_report.is_empty() {
            shard_accumulator::ShardReport::decode(&self.last_report)?;
        }
        if (self.carry > 0 && self.last_report.is_empty())
            || self
                .reports
                .iter()
                .map(|(roots, _)| roots)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.reports.len()
        {
            return Err(unavailable("inconsistent recovery progress"));
        }
        Ok(())
    }
}

fn header_roots(header: &FrameHeader) -> Result<Roots> {
    if header.state_roots.len() != 4 {
        return Err(unavailable("invalid header roots"));
    }
    let mut roots = [[0; 32]; 4];
    for (out, bytes) in roots.iter_mut().zip(&header.state_roots) {
        *out = bytes
            .as_slice()
            .try_into()
            .map_err(|_| unavailable("non-forest header roots"))?;
    }
    Ok(roots)
}

struct Headers<'a> {
    filter: &'a [u8],
    clock: &'a dyn ClockStore,
    validator: &'a BlsAppFrameValidator,
    source: Option<&'a DeliveryFrameSource>,
}

#[async_trait::async_trait]
trait VerifiedHeaders: Sync {
    async fn get(&self, number: u64) -> Result<FrameHeader>;
}

#[async_trait::async_trait]
impl VerifiedHeaders for Headers<'_> {
    async fn get(&self, number: u64) -> Result<FrameHeader> {
        tokio::time::timeout(Duration::from_secs(3), async {
            let frame = match self.clock.get_shard_clock_frame(self.filter, number, false) {
                Ok(frame) => frame,
                Err(QuilError::NotFound(_)) => {
                    let source = self
                        .source
                        .ok_or_else(|| unavailable("no historical frame source"))?;
                    source(self.filter.to_vec(), number).await.ok_or_else(|| {
                        unavailable(format!("historical frame {number} unavailable"))
                    })?
                }
                Err(error) => return Err(error),
            };
            if frame.encoded_len() > MAX_FRAME_BYTES
                || frame
                    .header
                    .as_ref()
                    .is_none_or(|h| h.address != self.filter || h.frame_number != number)
            {
                return Err(unavailable("wrong or oversized historical frame"));
            }
            self.validator.prepare_storage_history(&frame).await?;
            if !crate::app_engine::validate_app_frame_panic_safe(self.validator, &frame, false)? {
                return Err(QuilError::InvalidSignature(
                    "historical frame rejected".into(),
                ));
            }
            // Recovery consumes authenticated headers only. Unchecked request
            // bodies are never installed into the canonical frame store.
            Ok(frame.header.expect("checked above"))
        })
        .await
        .map_err(|_| unavailable("historical frame validation timed out"))?
    }
}

fn required(snapshot: &dyn SnapshotReadable, key: &[u8]) -> Result<Vec<u8>> {
    snapshot
        .read_record(key)?
        .ok_or_else(|| unavailable("materialized tip has incomplete outgoing records"))
}

fn outflows(header: &FrameHeader, frame: u64) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if header.frame_number
        != frame
            .checked_add(1)
            .ok_or_else(|| unavailable("frame overflow"))?
        || (!header.fee_total.is_empty() && header.fee_total.len() != 16)
    {
        return Err(unavailable("invalid previous-frame relay"));
    }
    let settlements = settlement_record::decode_relay(header.frame_number, &header.settlements)?
        .into_iter()
        .find(|(n, _)| *n == frame)
        .map(|(_, entries)| entries)
        .unwrap_or_default();
    let spends = spend_relay::decode_relay(header.frame_number, &header.spends)?
        .into_iter()
        .find(|(n, _)| *n == frame)
        .map(|(_, entries)| entries)
        .unwrap_or_default();
    Ok((
        quil_execution::global_intrinsic::frame_header::fee_total_to_bytes(
            quil_execution::global_intrinsic::frame_header::fee_total_from_bytes(&header.fee_total),
        ),
        settlement_record::encode_entries(&settlements)?,
        spend_relay::encode_frame_entries(&spends)?,
    ))
}

/// The member executed certified frame `frame` itself: its outgoing records for
/// that frame were committed with its verified state and cursor. When the
/// session's history is audited through `frame - 1`, the audited prefix extends
/// to `frame`, so a restart audits only frames the member did not execute.
/// Without this, every restart re-audited everything since the last restart at
/// eight frames per retry (four minutes for 240 frames on a localnet, hours for
/// a shard that ran a day), with the whole committee out of consensus.
///
/// Any other state (a sync jump, an audit in progress, a concurrent write)
/// leaves the prefix unchanged, and the next recovery audits the difference.
pub fn extend_audited(manager: &ExecutionEngineManager, session: &Session, frame: u64) -> Result<bool> {
    if frame <= session.base_frame {
        return Ok(false);
    }
    let shard = manager.crdt();
    let snapshot = shard.capture_committed_shard(&session.filter)?;
    let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
    if snapshot.records.read_record(&cursor_key)?.as_deref() != Some(frame.to_be_bytes().as_slice()) {
        return Ok(false);
    }
    let progress_key = encoding::app_history_recovery_key(&session.filter, &session.id()?);
    let mut progress: Progress = match snapshot.records.read_record(&progress_key)? {
        Some(bytes) if bytes.len() <= MAX_PROGRESS_BYTES => {
            serde_json::from_slice(&bytes).map_err(|_| unavailable("malformed recovery progress"))?
        }
        Some(_) => return Err(unavailable("oversized recovery progress")),
        None => Progress {
            version: 1,
            session: session.id()?,
            done: session.base_frame,
            target: session.base_frame,
            next: session.base_frame,
            carry: 0,
            last_report: Vec::new(),
            reports: Vec::new(),
            implied: None,
        },
    };
    progress.validate(session, frame)?;
    if progress.done + 1 != frame || progress.next != progress.done || progress.target != progress.done {
        return Ok(false);
    }
    for key in [
        encoding::clock_shard_frame_fee_total_key(&session.filter, frame),
        encoding::clock_shard_frame_settlements_key(&session.filter, frame),
        encoding::clock_shard_frame_spends_key(&session.filter, frame),
        encoding::clock_shard_frame_accumulator_key(&session.filter, frame),
    ] {
        if snapshot.records.read_record(&key)?.is_none() {
            return Ok(false);
        }
    }
    progress.done = frame;
    progress.target = frame;
    progress.next = frame;
    let encoded = serde_json::to_vec(&progress).map_err(|e| unavailable(e.to_string()))?;
    shard.checkpoint_shard_records(&session.filter, &snapshot.roots, &cursor_key, frame, &[(progress_key, encoded)])?;
    Ok(true)
}

/// Header `n + 1` omitted frame `n`'s report off the heartbeat, and neither an
/// authenticated state nor the carry window resolves it. An omitted report is
/// empty or unchanged from the previous frame. Coin blocks are append-only and
/// a session's range is fixed, so a shard's report never becomes empty within
/// a session: an empty report `n` means report `n - 1` was empty too. Either
/// way report `n` equals report `n - 1`, so the nearest earlier frame whose
/// report is determined decides it: a carried report, an omission on a
/// heartbeat (empty), a known state, or this session's audited record at
/// `done`. A heartbeat header always decides, which bounds the search.
///
/// Returns that frame and its report; `None` when the search reaches the
/// session base undecided.
async fn earlier_report(
    headers: &dyn VerifiedHeaders,
    progress: &Progress,
    records: &dyn SnapshotReadable,
    session: &Session,
    n: u64,
) -> Result<Option<(u64, Vec<u8>)>> {
    let mut m = n;
    while m > progress.done {
        m -= 1;
        if m == progress.done && progress.done > session.base_frame {
            return recorded_report(records, &session.filter, m).map(|report| Some((m, report)));
        }
        let header = headers.get(m + 1).await?;
        if !header.accumulator.is_empty() || (m + 1) % HEARTBEAT_FRAMES == 0 {
            if !header.accumulator.is_empty() {
                shard_accumulator::ShardReport::decode(&header.accumulator)?;
            }
            return Ok(Some((m, header.accumulator)));
        }
        if let Some(report) = progress.report(&header_roots(&header)?) {
            return Ok(Some((m, report)));
        }
    }
    Ok(None)
}

/// The audited report of a frame this session already recovered.
fn recorded_report(records: &dyn SnapshotReadable, filter: &[u8], frame: u64) -> Result<Vec<u8>> {
    let digest = records
        .read_record(&encoding::clock_shard_frame_accumulator_key(filter, frame))?
        .ok_or_else(|| unavailable(format!("audited frame {frame} has no accumulator record")))?;
    if digest.is_empty() {
        return Ok(Vec::new());
    }
    let report = records
        .read_record(&encoding::clock_shard_accumulator_report_key(filter, &digest))?
        .ok_or_else(|| unavailable(format!("audited frame {frame} lacks its report")))?;
    if accumulator_header::report_digest(&report) != digest {
        return Err(unavailable(format!("audited frame {frame} report does not match its digest")));
    }
    Ok(report)
}

/// One bounded batch; false means the caller must remain out of consensus and
/// retry. Completed records and the next recovery position share one write.
pub async fn recover(
    session: &Session,
    manager: Arc<ExecutionEngineManager>,
    clock: Arc<dyn ClockStore>,
    validator: Arc<BlsAppFrameValidator>,
    source: Option<&DeliveryFrameSource>,
    expected_cursor: u64,
) -> Result<bool> {
    let headers = Headers {
        filter: &session.filter,
        clock: clock.as_ref(),
        validator: validator.as_ref(),
        source,
    };
    recover_with_headers(session, manager, &headers, expected_cursor).await
}

async fn recover_with_headers(
    session: &Session,
    manager: Arc<ExecutionEngineManager>,
    headers: &dyn VerifiedHeaders,
    expected_cursor: u64,
) -> Result<bool> {
    if expected_cursor < session.base_frame {
        return Err(unavailable("cursor precedes the session base"));
    }
    if expected_cursor == session.base_frame {
        return Ok(true);
    }
    let shard = manager.crdt();
    let snapshot = shard.capture_committed_shard(&session.filter)?;
    let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
    if snapshot.records.read_record(&cursor_key)?.as_deref()
        != Some(expected_cursor.to_be_bytes().as_slice())
    {
        return Err(unavailable("engine cursor differs from committed state"));
    }
    let progress_key = encoding::app_history_recovery_key(&session.filter, &session.id()?);
    let stored = snapshot.records.read_record(&progress_key)?;
    let mut progress: Progress = match stored {
        Some(bytes) => {
            if bytes.len() > MAX_PROGRESS_BYTES {
                return Err(unavailable("oversized recovery progress"));
            }
            serde_json::from_slice(&bytes)
                .map_err(|_| unavailable("malformed recovery progress"))?
        }
        None => Progress {
            version: 1,
            session: session.id()?,
            done: session.base_frame,
            target: session.base_frame,
            next: session.base_frame,
            carry: 0,
            last_report: Vec::new(),
            reports: Vec::new(),
            implied: None,
        },
    };
    progress.validate(session, expected_cursor)?;
    if progress.done == expected_cursor {
        return Ok(true);
    }
    if progress.next == progress.done {
        // The durable cursor denotes locally executed post-state. Authenticate
        // its certified frame before deriving the report from this snapshot.
        let anchor = headers.get(expected_cursor).await?.global_frame_number;
        let manager = manager.clone();
        let records = snapshot.records.clone();
        let filter = session.filter.clone();
        let report = tokio::task::spawn_blocking(move || {
            manager.snapshot_accumulator_report(records.as_ref(), &filter, anchor)
        })
        .await
        .map_err(|e| unavailable(format!("snapshot report task: {e}")))??;
        progress.target = expected_cursor;
        progress.next = expected_cursor;
        progress.carry = 0;
        progress.last_report = report.clone();
        progress.reports.clear();
        progress.implied = None;
        progress.remember(snapshot.roots, report)?;
    }
    let start = Instant::now();
    let mut records = Vec::new();
    let mut processed = 0;
    let mut blocked = None;
    while progress.next > progress.done
        && processed < MAX_FRAMES
        && start.elapsed() < Duration::from_secs(3)
    {
        let n = progress.next;
        let recovered = async {
            if n == progress.target {
                let fees = required(
                    snapshot.records.as_ref(),
                    &encoding::clock_shard_frame_fee_total_key(&session.filter, n),
                )?;
                let settlements = required(
                    snapshot.records.as_ref(),
                    &encoding::clock_shard_frame_settlements_key(&session.filter, n),
                )?;
                let spends = required(
                    snapshot.records.as_ref(),
                    &encoding::clock_shard_frame_spends_key(&session.filter, n),
                )?;
                if fees.len() != 16 {
                    return Err(unavailable("malformed tip fee total"));
                }
                settlement_record::decode_entries(&settlements)?;
                spend_relay::decode_frame_entries(&spends)?;
                return Ok((
                    fees,
                    settlements,
                    spends,
                    progress.last_report.clone(),
                    None,
                ));
            }
            let header = headers.get(n + 1).await?;
            let roots = header_roots(&header)?;
            let mut report = progress.resolve(&header)?;
            if report.is_none() {
                // A preceding heartbeat may authenticate the same unchanged
                // state even when this member's first saved frame is later.
                // A heartbeat at or below the session base belongs to another
                // shard's history (this filter has no frame there).
                let heartbeat = header.frame_number / HEARTBEAT_FRAMES * HEARTBEAT_FRAMES;
                if heartbeat > session.base_frame && heartbeat < header.frame_number {
                    let anchor = headers.get(heartbeat).await?;
                    progress.remember(header_roots(&anchor)?, anchor.accumulator)?;
                    report = progress.resolve(&header)?;
                }
            }
            let implied = progress
                .implied
                .as_ref()
                .filter(|(low, _)| n > *low)
                .map(|(_, report)| report.clone());
            if report.is_none() {
                report = implied.clone();
            }
            if report.is_none() {
                if let Some((low, earlier)) = earlier_report(
                    headers,
                    &progress,
                    snapshot.records.as_ref(),
                    session,
                    n,
                )
                .await?
                {
                    progress.implied = Some((low, earlier.clone()));
                    report = Some(earlier);
                }
            } else if implied.is_some() && report != implied {
                return Err(unavailable("certified accumulator constraints disagree"));
            }
            let report = report.ok_or_else(|| {
                unavailable(format!("no authenticated accumulator report for frame {n}"))
            })?;
            progress.remember(roots, report.clone())?;
            let (fees, settlements, spends) = outflows(&header, n)?;
            Ok((
                fees,
                settlements,
                spends,
                report,
                Some(header.accumulator.is_empty()),
            ))
        }
        .await;
        let (fees, settlements, spends, report, omitted) = match recovered {
            Ok(value) => value,
            Err(error) => {
                blocked = Some(error);
                break;
            }
        };
        let digest = accumulator_header::report_digest(&report);
        records.extend([
            (
                encoding::clock_shard_frame_fee_total_key(&session.filter, n),
                fees,
            ),
            (
                encoding::clock_shard_frame_settlements_key(&session.filter, n),
                settlements,
            ),
            (
                encoding::clock_shard_frame_spends_key(&session.filter, n),
                spends,
            ),
            (
                encoding::clock_shard_frame_accumulator_key(&session.filter, n),
                digest.clone(),
            ),
        ]);
        if !digest.is_empty() {
            records.push((
                encoding::clock_shard_accumulator_report_key(&session.filter, &digest),
                report.clone(),
            ));
        }
        progress.carry = if omitted == Some(true) && !report.is_empty() {
            CARRY_WINDOW_FRAMES
        } else {
            progress.carry.saturating_sub(1)
        };
        progress.last_report = report;
        progress.next -= 1;
        if progress.implied.as_ref().is_some_and(|(low, _)| *low >= progress.next) {
            progress.implied = None;
        }
        processed += 1;
    }
    if processed == 0 {
        return Err(blocked.unwrap_or_else(|| unavailable("no recovery progress")));
    }
    if progress.next == progress.done {
        progress.done = progress.target;
        progress.next = progress.target;
        progress.reports.clear();
        progress.last_report.clear();
        progress.carry = 0;
        progress.implied = None;
    }
    let encoded = serde_json::to_vec(&progress).map_err(|e| unavailable(e.to_string()))?;
    if encoded.len() > MAX_PROGRESS_BYTES {
        return Err(unavailable("recovery progress exceeds byte limit"));
    }
    records.push((progress_key, encoded));
    if records
        .iter()
        .map(|(k, v)| k.len() + v.len())
        .sum::<usize>()
        > MAX_BATCH_BYTES
    {
        return Err(unavailable("recovery batch exceeds byte limit"));
    }
    shard.checkpoint_shard_records(
        &session.filter,
        &snapshot.roots,
        &cursor_key,
        expected_cursor,
        &records,
    )?;
    tracing::info!(
        filter = hex::encode(&session.filter),
        processed,
        target = progress.target,
        next = progress.next,
        done = progress.done,
        "recovered authenticated outgoing history batch"
    );
    if let Some(error) = blocked {
        tracing::warn!(filter = hex::encode(&session.filter), %error, "outgoing history recovery remains incomplete");
    }
    Ok(progress.done == expected_cursor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::Signer as _;
    use std::{collections::BTreeMap, path::Path, sync::Mutex};

    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "quil-history-recovery-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn session() -> Session {
        Session {
            chain_id: [1; 32],
            filter: quil_forest::encode_shard_bit_path(&[2; 32], &[false; 6]),
            generation: 2,
            genesis: [3; 32],
            base_frame: 77,
            authorization: [4; 32],
            members: vec![quil_crypto::FalconSigner::generate().public_key().to_vec()],
        }
    }

    fn progress(session: &Session) -> Progress {
        Progress {
            version: 1,
            session: session.id().unwrap(),
            done: 77,
            target: 95,
            next: 94,
            carry: 0,
            last_report: vec![],
            reports: vec![],
            implied: None,
        }
    }

    fn header(session: &Session, number: u64, roots: Roots) -> FrameHeader {
        FrameHeader {
            address: session.filter.clone(),
            frame_number: number,
            state_roots: roots.iter().map(|root| root.to_vec()).collect(),
            fee_total: quil_execution::global_intrinsic::frame_header::fee_total_field(fee(
                number - 1
            )),
            spends: spend_relay::encode_relay(&[(number - 1, vec![vec![number as u8 - 1; 3]])])
                .unwrap(),
            ..Default::default()
        }
    }

    fn fee(frame: u64) -> u128 {
        if frame % 2 == 0 {
            0
        } else {
            u128::from(frame)
        }
    }

    #[test]
    fn header_fee_encoding_is_normalized_without_inventing_missing_tip_records() {
        let session = session();
        let mut h = header(&session, 95, [[0; 32]; 4]);
        assert!(
            h.fee_total.is_empty(),
            "wire zero is omitted by the production frame encoder"
        );
        assert_eq!(outflows(&h, 94).unwrap().0, 0u128.to_be_bytes());
        h.fee_total = 42u128.to_be_bytes().to_vec();
        assert_eq!(outflows(&h, 94).unwrap().0, 42u128.to_be_bytes());
        h.fee_total = vec![1];
        assert!(outflows(&h, 94).is_err());
        h.fee_total.clear();
        assert!(outflows(&h, 93).is_err());
    }

    // A structurally valid nonempty report with a zero subtree root. These
    // unit cases test constraints, not certification of its contents.
    fn report(context: u8) -> Vec<u8> {
        let layer_bytes = shard_accumulator::LAYER_BYTES;
        let mut bytes = b"QCT3AR\0\x01".to_vec();
        bytes.extend_from_slice(&[context; 32]);
        bytes.push(1);
        bytes.push(6);
        bytes.extend_from_slice(&1u64.to_be_bytes());
        bytes.resize(41 + layer_bytes, 0);
        shard_accumulator::ShardReport::decode(&bytes).unwrap();
        bytes
    }

    #[test]
    fn omission_is_resolved_only_by_an_authenticated_state_or_nonempty_carry() {
        let session = session();
        let mut p = progress(&session);
        let roots = [[1; 32]; 4];
        let mut h = header(&session, 93, roots);
        let a = report(1);
        let b = report(2);
        p.remember([[2; 32]; 4], a.clone()).unwrap();
        p.last_report = a.clone();
        assert!(
            p.resolve(&h).unwrap().is_none(),
            "a newer report alone proves nothing"
        );
        p.remember(roots, a.clone()).unwrap();
        assert_eq!(p.resolve(&h).unwrap(), Some(a.clone()));
        p.reports.clear();
        p.carry = 1;
        assert_eq!(p.resolve(&h).unwrap(), Some(a.clone()));
        h.accumulator = b.clone();
        assert!(
            p.resolve(&h).is_err(),
            "a carried report must satisfy the certified omission window"
        );
        p.carry = 0;
        assert_eq!(p.resolve(&h).unwrap(), Some(b));
        h.accumulator.clear();
        h.frame_number = 96;
        assert_eq!(
            p.resolve(&h).unwrap(),
            Some(vec![]),
            "a mandatory empty heartbeat establishes absence"
        );
        p.remember(roots, a.clone()).unwrap();
        assert!(
            p.resolve(&h).is_err(),
            "the same state cannot have empty and nonempty reports"
        );
        assert!(p.remember(roots, vec![]).is_err());
        p.reports.clear();
        p.carry = 1;
        assert!(p.resolve(&h).is_err());
        p.carry = 0;
        h.frame_number = 93;
        h.accumulator = b"not a report".to_vec();
        assert!(p.resolve(&h).is_err());
    }

    #[test]
    fn progress_rejects_wrong_sessions_ranges_and_inconsistent_constraints() {
        let session = session();
        let mut p = progress(&session);
        p.validate(&session, 95).unwrap();
        p.session[0] ^= 1;
        assert!(p.validate(&session, 95).is_err());
        p.session = session.id().unwrap();
        p.next = 76;
        assert!(p.validate(&session, 95).is_err());
        p.next = 94;
        assert!(p.validate(&session, 94).is_err());
        p.carry = 1;
        assert!(p.validate(&session, 95).is_err());
        p.last_report = report(1);
        p.validate(&session, 95).unwrap();
        p.reports = vec![([[1; 32]; 4], vec![]), ([[1; 32]; 4], vec![])];
        assert!(p.validate(&session, 95).is_err());
    }

    fn open(
        path: &Path,
    ) -> (
        quil_store::RocksDb,
        Arc<quil_store::RocksHypergraphStore>,
        Arc<ExecutionEngineManager>,
    ) {
        let db = quil_store::RocksDb::open(path).unwrap();
        let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let prover = Arc::new(quil_types::crypto::NoopInclusionProver);
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            store.clone(),
            prover.clone(),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        crdt.set_unified_tree(true);
        let stubs = quil_execution::testing::NoopExecutionCrypto::new();
        let manager = Arc::new(ExecutionEngineManager::new(
            prover,
            stubs.key_manager,
            crdt,
            stubs.circuit_compiler,
            Arc::new(quil_store::RocksClockStore::new(db.inner())),
            Arc::new(quil_execution::testing::NoopHypergraphConfigResolver),
            false,
        ));
        (db, store, manager)
    }

    fn tip(session: &Session, n: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
        vec![
            (
                encoding::clock_shard_frame_fee_total_key(&session.filter, n),
                fee(n).to_be_bytes().to_vec(),
            ),
            (
                encoding::clock_shard_frame_settlements_key(&session.filter, n),
                settlement_record::encode_entries(&[]).unwrap(),
            ),
            (
                encoding::clock_shard_frame_spends_key(&session.filter, n),
                spend_relay::encode_frame_entries(&[vec![n as u8; 3]]).unwrap(),
            ),
            (
                encoding::clock_shard_frame_accumulator_key(&session.filter, n),
                vec![9; 32],
            ),
        ]
    }

    // Bypass only header authentication for storage/fault tests. The separate
    // production-source test below uses the real validator and rejects unsigned
    // frames before even a progress marker is written.
    struct VerifiedFixture {
        frames: BTreeMap<u64, FrameHeader>,
        fail_at: Mutex<Option<u64>>,
        reads: Mutex<Vec<u64>>,
    }
    #[async_trait::async_trait]
    impl VerifiedHeaders for VerifiedFixture {
        async fn get(&self, number: u64) -> Result<FrameHeader> {
            self.reads.lock().unwrap().push(number);
            if *self.fail_at.lock().unwrap() == Some(number) {
                return Err(unavailable("test source unavailable"));
            }
            self.frames
                .get(&number)
                .cloned()
                .ok_or_else(|| unavailable("test source missing frame"))
        }
    }

    #[tokio::test]
    async fn bounded_recovery_resumes_after_reopen_fetch_failure_and_failed_commit() {
        let directory = Directory::new();
        let session = session();
        let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
        let progress_key =
            encoding::app_history_recovery_key(&session.filter, &session.id().unwrap());
        let headers = VerifiedFixture {
            frames: (78..=96)
                .map(|n| (n, header(&session, n, [[0; 32]; 4])))
                .collect(),
            fail_at: Mutex::new(None),
            reads: Mutex::new(vec![]),
        };
        {
            let (_db, _store, manager) = open(&directory.0);
            let mut records = tip(&session, 95);
            records.push((
                encoding::clock_shard_frame_accumulator_key(&session.filter, 82),
                vec![8; 32],
            ));
            manager
                .crdt()
                .commit_with_frame_cursor_and_records(95, &cursor_key, &records)
                .unwrap();
            assert!(
                !recover_with_headers(&session, manager.clone(), &headers, 95)
                    .await
                    .unwrap()
            );
            let snapshot = manager
                .crdt()
                .capture_committed_shard(&session.filter)
                .unwrap();
            let p: Progress = serde_json::from_slice(
                &snapshot
                    .records
                    .read_record(&progress_key)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!((p.done, p.target, p.next), (77, 95, 87));
            assert!(snapshot
                .records
                .read_record(&encoding::clock_shard_frame_fee_total_key(
                    &session.filter,
                    87
                ))
                .unwrap()
                .is_none());
            assert_eq!(snapshot.roots, [[0; 32]; 4]);
        }
        {
            let (db, store, manager) = open(&directory.0);
            *headers.fail_at.lock().unwrap() = Some(85);
            assert!(
                !recover_with_headers(&session, manager.clone(), &headers, 95)
                    .await
                    .unwrap()
            );
            let partial = manager
                .crdt()
                .capture_committed_shard(&session.filter)
                .unwrap();
            let saved = partial.records.read_record(&progress_key).unwrap().unwrap();
            let p: Progress = serde_json::from_slice(&saved).unwrap();
            assert_eq!(p.next, 84);
            *headers.fail_at.lock().unwrap() = None;
            store.fail_commit_for_test(true);
            assert!(
                recover_with_headers(&session, manager.clone(), &headers, 95)
                    .await
                    .is_err()
            );
            let failed = manager
                .crdt()
                .capture_committed_shard(&session.filter)
                .unwrap();
            assert_eq!(
                failed.records.read_record(&progress_key).unwrap(),
                Some(saved)
            );
            assert!(failed
                .records
                .read_record(&encoding::clock_shard_frame_fee_total_key(
                    &session.filter,
                    84
                ))
                .unwrap()
                .is_none());
            store.fail_commit_for_test(false);
            assert!(
                recover_with_headers(&session, manager.clone(), &headers, 95)
                    .await
                    .unwrap()
            );
            let complete = manager
                .crdt()
                .capture_committed_shard(&session.filter)
                .unwrap();
            for n in 78..=95 {
                for (key, value) in tip(&session, n).into_iter().take(3) {
                    assert_eq!(
                        complete.records.read_record(&key).unwrap(),
                        Some(value),
                        "frame {n}"
                    );
                }
                assert_eq!(
                    complete
                        .records
                        .read_record(&encoding::clock_shard_frame_accumulator_key(
                            &session.filter,
                            n
                        ))
                        .unwrap(),
                    Some(vec![])
                );
            }
            assert_eq!(complete.roots, [[0; 32]; 4]);
            assert_eq!(
                complete.records.read_record(&cursor_key).unwrap(),
                Some(95u64.to_be_bytes().to_vec())
            );
            quil_execution::global_intrinsic::handoff::history::root(
                complete.records.as_ref(),
                &session,
                95,
            )
            .unwrap();
            assert!(quil_store::RocksClockStore::new(db.inner()).get_latest_shard_clock_frame(&session.filter).is_err(),
                "history repair never installs synthetic header bodies or advances the canonical head");
        }
        let (_db, _store, manager) = open(&directory.0);
        headers.reads.lock().unwrap().clear();
        assert!(
            recover_with_headers(&session, manager.clone(), &headers, 95)
                .await
                .unwrap()
        );
        assert!(
            headers.reads.lock().unwrap().is_empty(),
            "a completed prefix survives restart"
        );
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(96, &cursor_key, &tip(&session, 96))
            .unwrap();
        assert!(
            recover_with_headers(&session, manager.clone(), &headers, 96)
                .await
                .unwrap()
        );
        assert_eq!(
            *headers.reads.lock().unwrap(),
            vec![96],
            "only the new tail needs auditing"
        );
    }

    #[tokio::test]
    async fn nonempty_omission_constraints_and_report_blobs_survive_batch_boundaries() {
        let directory = Directory::new();
        let session = session();
        let (_, _, manager) = open(&directory.0);
        let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(95, &cursor_key, &tip(&session, 95))
            .unwrap();
        let carried = report(1);
        let headers = VerifiedFixture {
            frames: (78..=95)
                .map(|n| {
                    let roots = if n > 92 {
                        [[0; 32]; 4]
                    } else if n >= 91 {
                        [[1; 32]; 4]
                    } else {
                        [[n as u8; 32]; 4]
                    };
                    let mut h = header(&session, n, roots);
                    if n == 92 {
                        h.accumulator = carried.clone();
                    }
                    (n, h)
                })
                .collect(),
            fail_at: Mutex::new(None),
            reads: Mutex::new(vec![]),
        };
        assert!(
            !recover_with_headers(&session, manager.clone(), &headers, 95)
                .await
                .unwrap()
        );
        assert!(
            !recover_with_headers(&session, manager.clone(), &headers, 95)
                .await
                .unwrap()
        );
        assert!(
            recover_with_headers(&session, manager.clone(), &headers, 95)
                .await
                .unwrap()
        );
        let snapshot = manager
            .crdt()
            .capture_committed_shard(&session.filter)
            .unwrap();
        let digest = accumulator_header::report_digest(&carried);
        for n in 78..=95 {
            let expected = if n <= 91 { digest.clone() } else { vec![] };
            assert_eq!(
                snapshot
                    .records
                    .read_record(&encoding::clock_shard_frame_accumulator_key(
                        &session.filter,
                        n
                    ))
                    .unwrap(),
                Some(expected)
            );
        }
        assert_eq!(
            snapshot
                .records
                .read_record(&encoding::clock_shard_accumulator_report_key(
                    &session.filter,
                    &digest
                ))
                .unwrap(),
            Some(carried)
        );
    }

    // A shard stays out of consensus when header 303 omits frame 302's report
    // right after header 304 carried a changed one: neither the carry window
    // nor a known state decides it. An
    // omitted report equals the previous frame's (coin blocks only grow), so
    // the nearest earlier carried report decides it.
    #[tokio::test]
    async fn an_omission_below_a_changed_report_takes_the_earlier_report() {
        let directory = Directory::new();
        let session = session();
        let (_, _, manager) = open(&directory.0);
        let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(95, &cursor_key, &tip(&session, 95))
            .unwrap();
        let (a, b) = (report(1), report(2));
        let frames: BTreeMap<u64, FrameHeader> = (78..=95)
            .map(|n| {
                let roots = if n == 95 { [[0; 32]; 4] } else { [[n as u8; 32]; 4] };
                let mut h = header(&session, n, roots);
                match n {
                    94 => h.accumulator = b.clone(),
                    92 => h.accumulator = a.clone(),
                    _ => {}
                }
                (n, h)
            })
            .collect();
        let headers = VerifiedFixture {
            frames,
            fail_at: Mutex::new(None),
            reads: Mutex::new(vec![]),
        };
        let mut complete = false;
        for _ in 0..4 {
            complete = recover_with_headers(&session, manager.clone(), &headers, 95)
                .await
                .unwrap();
            if complete {
                break;
            }
        }
        assert!(complete);
        assert!(
            headers.reads.lock().unwrap().iter().all(|n| *n > session.base_frame),
            "no header before the session base is fetched"
        );
        let snapshot = manager
            .crdt()
            .capture_committed_shard(&session.filter)
            .unwrap();
        let digest = |r: &Vec<u8>| accumulator_header::report_digest(r);
        for n in 78..=94 {
            let expected = match n {
                94 => vec![],
                93 => digest(&b),
                _ => digest(&a),
            };
            assert_eq!(
                snapshot
                    .records
                    .read_record(&encoding::clock_shard_frame_accumulator_key(
                        &session.filter,
                        n
                    ))
                    .unwrap(),
                Some(expected),
                "frame {n}"
            );
        }
    }

    #[tokio::test]
    async fn executed_frames_extend_the_audited_prefix_but_a_jump_does_not() {
        let directory = Directory::new();
        let session = session();
        let (_, _, manager) = open(&directory.0);
        let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
        let headers = VerifiedFixture {
            frames: (78..=82).map(|n| (n, header(&session, n, [[0; 32]; 4]))).collect(),
            fail_at: Mutex::new(None),
            reads: Mutex::new(vec![]),
        };
        for n in 78..=79 {
            manager
                .crdt()
                .commit_with_frame_cursor_and_records(n, &cursor_key, &tip(&session, n))
                .unwrap();
            assert!(extend_audited(&manager, &session, n).unwrap(), "frame {n}");
        }
        assert!(!extend_audited(&manager, &session, 79).unwrap(), "already audited");
        assert!(recover_with_headers(&session, manager.clone(), &headers, 79).await.unwrap());
        assert!(headers.reads.lock().unwrap().is_empty(), "executed frames need no audit");

        // A frame the member did not execute (a sync jump) is not extended over.
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(81, &cursor_key, &tip(&session, 81))
            .unwrap();
        assert!(!extend_audited(&manager, &session, 81).unwrap());
        let mut complete = false;
        for _ in 0..3 {
            complete = recover_with_headers(&session, manager.clone(), &headers, 81).await.unwrap();
            if complete {
                break;
            }
        }
        assert!(complete);
        assert_eq!(*headers.reads.lock().unwrap(), vec![81, 81], "only the jumped frames are audited");
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(82, &cursor_key, &tip(&session, 82))
            .unwrap();
        assert!(extend_audited(&manager, &session, 82).unwrap());
    }

    #[tokio::test]
    async fn unknown_state_and_missing_tip_records_remain_unavailable() {
        let directory = Directory::new();
        let session = session();
        let (_db, _store, manager) = open(&directory.0);
        let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
        manager
            .crdt()
            .checkpoint_frame_cursor(95, &cursor_key)
            .unwrap();
        let headers = VerifiedFixture {
            frames: [
                (95, header(&session, 95, [[1; 32]; 4])),
                (64, header(&session, 64, [[2; 32]; 4])),
            ]
            .into_iter()
            .collect(),
            fail_at: Mutex::new(None),
            reads: Mutex::new(vec![]),
        };
        assert!(
            recover_with_headers(&session, manager.clone(), &headers, 76)
                .await
                .is_err()
        );
        assert!(
            recover_with_headers(&session, manager.clone(), &headers, 95)
                .await
                .is_err()
        );
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(95, &cursor_key, &tip(&session, 95))
            .unwrap();
        assert!(
            !recover_with_headers(&session, manager.clone(), &headers, 95)
                .await
                .unwrap()
        );
        assert!(
            recover_with_headers(&session, manager.clone(), &headers, 95)
                .await
                .is_err()
        );
        let snapshot = manager
            .crdt()
            .capture_committed_shard(&session.filter)
            .unwrap();
        assert!(snapshot
            .records
            .read_record(&encoding::clock_shard_frame_fee_total_key(
                &session.filter,
                94
            ))
            .unwrap()
            .is_none());
        let key = encoding::app_history_recovery_key(&session.filter, &session.id().unwrap());
        let p: Progress =
            serde_json::from_slice(&snapshot.records.read_record(&key).unwrap().unwrap()).unwrap();
        assert_eq!((p.done, p.next), (77, 94));
    }

    #[tokio::test]
    async fn production_source_rejects_unsigned_or_substituted_frames_without_writes() {
        use quil_types::proto::global::AppShardFrame;
        let directory = Directory::new();
        let session = session();
        let (db, _store, manager) = open(&directory.0);
        let clock: Arc<dyn ClockStore> = Arc::new(quil_store::RocksClockStore::new(db.inner()));
        let validator = Arc::new(BlsAppFrameValidator::new(
            Arc::new(crate::test_support::TestProverRegistry::new()),
            Arc::new(quil_crypto::FalconKeyConstructor),
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
        ));
        let cursor_key = encoding::consensus_materialized_cursor_key(&session.filter);
        manager
            .crdt()
            .commit_with_frame_cursor_and_records(95, &cursor_key, &tip(&session, 95))
            .unwrap();
        let mut unsigned = header(&session, 95, [[0; 32]; 4]);
        unsigned.output = quil_crypto::porep::deterministic_app_frame_output(
            &unsigned.parent_selector,
            &unsigned.requests_root,
            &unsigned.state_roots,
            &quil_crypto::porep::derive_storage_beacon(0, &[]),
            unsigned.frame_number,
            unsigned.rank,
            &unsigned.prover,
            unsigned.difficulty,
            unsigned.fee_multiplier_vote,
            unsigned.timestamp,
            &unsigned.storage_attestation_root,
            fee(94),
            &unsigned.settlements,
            &unsigned.accumulator,
            &unsigned.spends,
        );
        for variant in 0..4 {
            let mut h = unsigned.clone();
            match variant {
                1 => h.frame_number += 1,
                2 => h.address[0] ^= 1,
                3 => h.output[0] ^= 1,
                _ => {}
            }
            let frame = AppShardFrame {
                header: Some(h),
                requests: vec![],
                storage_attestation: None,
            };
            let source: DeliveryFrameSource = Arc::new(move |_, _| {
                let frame = frame.clone();
                Box::pin(async move { Some(frame) })
            });
            let error = recover(
                &session,
                manager.clone(),
                clock.clone(),
                validator.clone(),
                Some(&source),
                95,
            )
            .await
            .unwrap_err();
            if variant == 0 {
                assert!(
                    error.to_string().contains("missing BLS signature"),
                    "{error}"
                );
            }
            let snapshot = manager
                .crdt()
                .capture_committed_shard(&session.filter)
                .unwrap();
            assert!(snapshot
                .records
                .read_record(&encoding::app_history_recovery_key(
                    &session.filter,
                    &session.id().unwrap()
                ))
                .unwrap()
                .is_none());
            assert_eq!(
                snapshot
                    .records
                    .read_record(&encoding::clock_shard_frame_accumulator_key(
                        &session.filter,
                        95
                    ))
                    .unwrap(),
                Some(vec![9; 32])
            );
        }
    }
}

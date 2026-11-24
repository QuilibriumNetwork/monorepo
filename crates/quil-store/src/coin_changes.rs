//! Durable arrival order for wallet discovery.
//!
//! Events join the source rows' final RocksDB batch and contain public vertex
//! blobs. Authoritative Coin decoding stays in quil-node.

use std::collections::BTreeMap;
use std::sync::Arc;

use quil_forest::{CoordinatedDb, LocalBatchProjection, LocalProjectionBatch, LocalProjectionRead};
use quil_types::error::{QuilError, Result};
use quil_types::store::SnapshotReadable;

pub const NAMESPACE: &[u8] = b"quil/local/coin-changes/v1/";
const META: &[u8] = b"quil/local/coin-changes/v1/meta";
const INVALID: &[u8] = b"quil/local/coin-changes/v1/invalid";
pub(crate) const RESET_REQUEST: &[u8] = b"quil/local/coin-changes/v1/reset-request";
pub(crate) const INSTALLING: &[u8] = b"quil/local/coin-changes/v1/installing";
const INSTALL_OVERFLOW: &[u8] = b"quil/local/coin-changes/v1/install-overflow";
const INSTALL_REQUESTS: &[u8] = b"quil/local/coin-changes/v1/install-requests/";
const INSTALL_SCOPES: &[u8] = b"quil/local/coin-changes/v1/install-scopes/";
const MAX_INSTALL_SCOPES: u64 = 128;
const EVENTS: &[u8] = b"quil/local/coin-changes/v1/events/";
const EVENTS_END: &[u8] = b"quil/local/coin-changes/v1/events0";
const MAX_LOG_BYTES: usize = 64 << 20;
const MAX_RECORD_BYTES: usize = 64 << 10;
const MAX_EXAMINED: usize = 1024;
const MAX_RECLAIMED: usize = 1024;

#[derive(Debug)]
pub struct RawCoinChange {
    pub key: [u8; 64],
    pub blob: Vec<u8>,
}

#[derive(Debug)]
pub struct RawCoinChangesPage {
    pub records: Vec<RawCoinChange>,
    pub cursor: Vec<u8>,
    pub has_more: bool,
    pub reset: bool,
}

impl RawCoinChangesPage {
    fn reset() -> Self {
        Self {
            records: Vec::new(),
            cursor: Vec::new(),
            has_more: false,
            reset: true,
        }
    }
}

/// Store generation and the retained event interval `(floor, tail]`.
struct Meta {
    epoch: [u8; 16],
    tail: u64,
    floor: u64,
    bytes: u64,
}

impl Meta {
    fn fresh() -> std::result::Result<Self, String> {
        let mut epoch = [0; 16];
        getrandom::getrandom(&mut epoch).map_err(|e| format!("coin journal epoch: {e}"))?;
        Ok(Self {
            epoch,
            tail: 0,
            floor: 0,
            bytes: 0,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = b"QCCMETA1".to_vec();
        bytes.extend_from_slice(&self.epoch);
        bytes.extend_from_slice(&self.tail.to_be_bytes());
        bytes.extend_from_slice(&self.floor.to_be_bytes());
        bytes.extend_from_slice(&self.bytes.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 48 || &bytes[..8] != b"QCCMETA1" {
            return None;
        }
        let meta = Self {
            epoch: bytes[8..24].try_into().ok()?,
            tail: u64::from_be_bytes(bytes[24..32].try_into().ok()?),
            floor: u64::from_be_bytes(bytes[32..40].try_into().ok()?),
            bytes: u64::from_be_bytes(bytes[40..48].try_into().ok()?),
        };
        (meta.floor <= meta.tail && meta.bytes <= MAX_LOG_BYTES as u64).then_some(meta)
    }

    fn cursor(&self, domain: &[u8; 32], sequence: u64) -> Vec<u8> {
        let mut bytes = b"QCC1".to_vec();
        bytes.extend_from_slice(domain);
        bytes.extend_from_slice(&self.epoch);
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes
    }
}

fn error(cause: impl std::fmt::Display) -> QuilError {
    QuilError::Store(format!("coin changes: {cause}"))
}

fn event_key(sequence: u64) -> Vec<u8> {
    [EVENTS, &sequence.to_be_bytes()].concat()
}

fn event_bytes(blob_len: usize) -> usize {
    EVENTS.len() + 8 + 64 + blob_len
}

/// Enable once, before any wallet snapshot is captured. Old stores bootstrap
/// their existing rows by snapshot; only subsequent arrivals enter the log.
pub(crate) fn enable(db: &CoordinatedDb) -> Result<()> {
    db.register_local_projection(Arc::new(CoinProjection))
        .map_err(error)?;
    let meta = db.get(META).map_err(error)?;
    if meta.as_deref().and_then(Meta::decode).is_none() || db.get(INVALID).map_err(error)?.is_some()
    {
        reset(db)?;
    }
    Ok(())
}

/// A semantic state replacement invalidates all cursors of this local store.
pub fn reset(db: &CoordinatedDb) -> Result<()> {
    if db.has_local_projection(NAMESPACE).map_err(error)? {
        db.put(RESET_REQUEST, b"1").map_err(error)?;
    }
    Ok(())
}

pub fn begin_install(db: &CoordinatedDb, scope: &[u8]) -> Result<()> {
    set_installing(db, scope, true)
}

pub fn finish_install(db: &CoordinatedDb, scope: &[u8]) -> Result<()> {
    set_installing(db, scope, false)
}

fn set_installing(db: &CoordinatedDb, scope: &[u8], installing: bool) -> Result<()> {
    if !db.has_local_projection(NAMESPACE).map_err(error)? {
        return Ok(());
    }
    let (key, value) = installation_request(scope, installing)?;
    db.put(key, value).map_err(error)
}

pub(crate) fn installation_request(scope: &[u8], installing: bool) -> Result<(Vec<u8>, [u8; 1])> {
    if scope.is_empty() || scope.len() > 256 {
        return Err(QuilError::InvalidArgument(
            "coin changes: invalid installation scope".into(),
        ));
    }
    Ok(([INSTALL_REQUESTS, scope].concat(), [u8::from(installing)]))
}

/// The reader must retain one snapshot for every point read. Pending requests
/// matter because a failed projection commits the request without its marker;
/// overlay branches also expose the request before publication projects it.
pub(crate) fn is_installing(
    scope: &[u8],
    mut read: impl FnMut(&[u8]) -> Result<Option<Vec<u8>>>,
) -> Result<bool> {
    let (request_key, _) = installation_request(scope, true)?;
    let marker = read(&[INSTALL_SCOPES, scope].concat())?;
    let request = read(&request_key)?;
    if marker.as_deref() == Some(b"1") || request.as_deref() == Some(&[1]) {
        return Ok(true);
    }
    if marker.is_some() || request.as_deref().is_some_and(|value| value != [0]) {
        return Err(error("malformed installation scope state"));
    }
    if read(INVALID)?.is_some() || read(INSTALL_OVERFLOW)?.is_some() {
        return Err(QuilError::ExecutionUnavailable(
            "coin changes: installation recovery state is uncertain".into(),
        ));
    }
    if let Some(bytes) = read(INSTALLING)? {
        let count = u64::from_be_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| error("malformed installation count"))?,
        );
        if count == 0 || count > MAX_INSTALL_SCOPES {
            return Err(error("invalid installation count"));
        }
    }
    Ok(false)
}

/// Read the watermark from the very same retained snapshot as ListCoins.
/// Never replace a missing snapshot watermark with the current live tail.
pub fn snapshot_cursor(snapshot: &dyn SnapshotReadable, domain: &[u8; 32]) -> Result<Vec<u8>> {
    if snapshot.read_record(INSTALLING)?.is_some()
        || snapshot.read_record(INSTALL_OVERFLOW)?.is_some()
        || snapshot.read_record(INVALID)?.is_some()
    {
        return Err(QuilError::ExecutionUnavailable(
            "coin changes: state installation or journal recovery is incomplete".into(),
        ));
    }
    match snapshot.read_record(META)? {
        None => Ok(Vec::new()),
        Some(bytes) => {
            let meta = Meta::decode(&bytes).ok_or_else(|| error("malformed snapshot metadata"))?;
            Ok(meta.cursor(domain, meta.tail))
        }
    }
}

// Read flags and metadata from one snapshot; a mixed view could accept a
// generation whose history has already been replaced.
fn readable_meta(snapshot: &rocksdb::Snapshot<'_>) -> Result<Option<Meta>> {
    for key in [INVALID, INSTALLING, INSTALL_OVERFLOW] {
        if snapshot.get(key).map_err(error)?.is_some() {
            return Ok(None);
        }
    }
    let bytes = snapshot.get(META).map_err(error)?;
    Ok(bytes.as_deref().and_then(Meta::decode))
}

/// Read a source's tail without scanning events. Lost history or unfinished
/// maintenance returns None, requiring the caller to reset the whole cursor.
pub fn cursor_head(
    db: &CoordinatedDb,
    domain: &[u8; 32],
    cursor: &[u8],
) -> Result<Option<Vec<u8>>> {
    if !db.has_local_projection(NAMESPACE).map_err(error)? {
        return Err(QuilError::ExecutionUnavailable(
            "coin changes: store has no writable journal".into(),
        ));
    }
    if cursor.is_empty() {
        return Ok(None);
    }
    if cursor.len() != 60 || &cursor[..4] != b"QCC1" || &cursor[4..36] != domain {
        return Err(QuilError::InvalidArgument(
            "coin changes: malformed or foreign domain cursor".into(),
        ));
    }
    let snapshot = db.snapshot();
    let Some(meta) = readable_meta(&snapshot)? else {
        return Ok(None);
    };
    let sequence = u64::from_be_bytes(cursor[52..60].try_into().unwrap());
    Ok(
        (cursor[36..52] == meta.epoch && sequence >= meta.floor && sequence <= meta.tail)
            .then(|| meta.cursor(domain, meta.tail)),
    )
}

/// Scan the store-wide sequence, advancing past other domains and non-Coin
/// candidates too. Work is bounded by both record count and bytes examined.
pub fn read_page(
    db: &CoordinatedDb,
    domain: &[u8; 32],
    cursor: &[u8],
    max_entries: usize,
    max_bytes: usize,
) -> Result<RawCoinChangesPage> {
    if !db.has_local_projection(NAMESPACE).map_err(error)? {
        return Err(QuilError::ExecutionUnavailable(
            "coin changes: store has no writable journal".into(),
        ));
    }
    if max_entries == 0 || max_bytes < 64 {
        return Err(QuilError::InvalidArgument(
            "coin changes: invalid page limits".into(),
        ));
    }
    if cursor.is_empty() {
        return Ok(RawCoinChangesPage::reset());
    }
    if cursor.len() != 60 || &cursor[..4] != b"QCC1" || &cursor[4..36] != domain {
        return Err(QuilError::InvalidArgument(
            "coin changes: malformed or foreign domain cursor".into(),
        ));
    }
    let snapshot = db.snapshot();
    let Some(meta) = readable_meta(&snapshot)? else {
        return Ok(RawCoinChangesPage::reset());
    };
    let mut sequence = u64::from_be_bytes(cursor[52..60].try_into().unwrap());
    if cursor[36..52] != meta.epoch || sequence < meta.floor || sequence > meta.tail {
        return Ok(RawCoinChangesPage::reset());
    }
    let max_entries = max_entries.min(quil_types::store::MAX_SCAN_PAGE_ENTRIES);
    let max_bytes = max_bytes.min(quil_types::store::scan_page_bytes(
        quil_types::store::MAX_SCAN_PAGE_ENTRIES,
    ));
    let mut records = Vec::new();
    let mut examined_bytes = 0usize;
    let mut options = rocksdb::ReadOptions::default();
    options.set_iterate_upper_bound(EVENTS_END.to_vec());
    options.fill_cache(false);
    let mut iterator = snapshot.raw_iterator_opt(options);
    if sequence < meta.tail {
        iterator.seek(event_key(sequence + 1));
    }
    for _ in 0..MAX_EXAMINED {
        if sequence == meta.tail || records.len() == max_entries {
            break;
        }
        iterator.status().map_err(error)?;
        let expected = event_key(sequence + 1);
        if iterator.key() != Some(expected.as_slice()) {
            return Ok(RawCoinChangesPage::reset());
        }
        let Some(value) = iterator.value() else {
            return Ok(RawCoinChangesPage::reset());
        };
        if value.len() < 64 + crate::large_vertex_index::LARGE_VERTEX_MIN_BYTES
            || value.len() > 64 + MAX_RECORD_BYTES
        {
            return Ok(RawCoinChangesPage::reset());
        }
        let size = expected.len() + value.len();
        if examined_bytes.saturating_add(size) > max_bytes {
            if examined_bytes == 0 {
                return Err(error("record exceeds page byte budget"));
            }
            break;
        }
        examined_bytes += size;
        if &value[..32] == domain {
            records.push(RawCoinChange {
                key: value[..64].try_into().unwrap(),
                blob: value[64..].to_vec(),
            });
        }
        sequence += 1;
        iterator.next();
    }
    iterator.status().map_err(error)?;
    Ok(RawCoinChangesPage {
        records,
        cursor: meta.cursor(domain, sequence),
        has_more: sequence < meta.tail,
        reset: false,
    })
}

struct CoinProjection;

struct Candidate<'a> {
    key: [u8; 64],
    blob: &'a [u8],
    order: u32,
}

impl LocalBatchProjection for CoinProjection {
    fn namespace(&self) -> &'static [u8] {
        NAMESPACE
    }

    fn project(
        &self,
        view: &LocalProjectionRead<'_>,
        batch: &[u8],
        output: &mut LocalProjectionBatch,
    ) -> std::result::Result<(), String> {
        let mut candidates = BTreeMap::<Vec<u8>, Candidate<'_>>::new();
        let mut reset = false;
        let mut overflow = false;
        let mut bytes = 0usize;
        let mut order = 0u32;
        let mut install_requests = BTreeMap::<Vec<u8>, bool>::new();
        let mut install_overrun = false;
        let invalid = view.get(INVALID).map_err(|e| e.to_string())?.is_some();
        if invalid {
            // Failed projections leave requests durable without scope/count
            // updates. Replay them before clearing INVALID so another scope's
            // finish cannot release an unfinished installation.
            reset = true;
            match view
                .prefix_entries(INSTALL_REQUESTS, MAX_INSTALL_SCOPES as usize, 64 << 10)
                .map_err(|e| e.to_string())?
            {
                Some(entries) => {
                    for (key, value) in entries {
                        let scope = &key[INSTALL_REQUESTS.len()..];
                        if scope.is_empty()
                            || scope.len() > 256
                            || !matches!(value.as_slice(), [0] | [1])
                        {
                            install_overrun = true;
                        } else {
                            install_requests.insert(scope.to_vec(), value == [1]);
                        }
                    }
                }
                None => install_overrun = true,
            }
        }
        let parsed = visit_batch(batch, |mutation| {
            order = order.saturating_add(1);
            match mutation {
                BatchMutation::Put(key, value) => {
                    if key == RESET_REQUEST {
                        reset = true;
                    }
                    if let Some(scope) = key.strip_prefix(INSTALL_REQUESTS) {
                        if scope.is_empty()
                            || scope.len() > 256
                            || !matches!(value, [0] | [1])
                            || (install_requests.len() >= MAX_INSTALL_SCOPES as usize
                                && !install_requests.contains_key(scope))
                        {
                            overflow = true;
                            install_overrun = true;
                        } else {
                            install_requests.insert(scope.to_vec(), value == [1]);
                        }
                    }
                    if overflow {
                        return;
                    }
                    if let Some(key64) = crate::large_vertex_index::row_vertex_key(key) {
                        if let Some(previous) = candidates.remove(key) {
                            bytes -= event_bytes(previous.blob.len());
                        }
                        if is_reserved_coin_record(key64[32..].try_into().unwrap()) {
                            return;
                        }
                        if value.len() < crate::large_vertex_index::LARGE_VERTEX_MIN_BYTES {
                            return;
                        }
                        if value.len() > MAX_RECORD_BYTES {
                            if !may_contain_coin_owner(value) {
                                return;
                            }
                            overflow = true;
                            return;
                        }
                        if is_proven_non_coin(value) {
                            return;
                        }
                        bytes = bytes.saturating_add(event_bytes(value.len()));
                        if bytes > MAX_LOG_BYTES {
                            overflow = true;
                            candidates.clear();
                            return;
                        }
                        candidates.insert(
                            key.to_vec(),
                            Candidate {
                                key: key64.try_into().unwrap(),
                                blob: value,
                                order,
                            },
                        );
                    }
                }
                BatchMutation::Delete(key) => {
                    if let Some(previous) = candidates.remove(key) {
                        bytes -= event_bytes(previous.blob.len());
                    }
                }
                BatchMutation::DeleteRange(lower, upper) => {
                    if range_touches_rows(lower, upper) {
                        reset = true;
                    }
                    candidates.retain(|key, candidate| {
                        let keep = key.as_slice() < lower || key.as_slice() >= upper;
                        if !keep {
                            bytes -= event_bytes(candidate.blob.len());
                        }
                        keep
                    });
                }
            }
        });
        if !parsed {
            // The unparsed suffix may contain a maintenance request. Keep
            // the original request and durable invalid marker so recovery
            // replays it; a mere epoch rotation could lose that active scope.
            return Err("unlistable coin journal input".into());
        }
        if candidates.is_empty() && install_requests.is_empty() && !reset && !overflow {
            return Ok(());
        }
        if install_overrun {
            output.put(INSTALL_OVERFLOW, b"1")?;
        }
        let installed_count = view.get(INSTALLING).map_err(|e| e.to_string())?;
        let had_installed_count = installed_count.is_some();
        let mut installing = match installed_count {
            None => 0,
            Some(bytes) => u64::from_be_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| "coin journal installation count".to_string())?,
            ),
        };
        let previous_installing = installing;
        for (scope, active) in install_requests {
            let marker = [INSTALL_SCOPES, &scope].concat();
            let existed = view.get(&marker).map_err(|e| e.to_string())?.is_some();
            // A duplicate begin/finish changes no state. In particular a
            // caller finishing an unstarted scope must keep valid cursors.
            reset |= active != existed;
            if active && !existed {
                if installing >= MAX_INSTALL_SCOPES {
                    // A bounded fail-closed latch: an untracked unfinished
                    // replacement can never be cleared by another scope.
                    output.put(INSTALL_OVERFLOW, b"1")?;
                } else {
                    installing += 1;
                    output.put(&marker, b"1")?;
                }
            } else if !active && existed {
                installing = installing
                    .checked_sub(1)
                    .ok_or_else(|| "coin journal installation count underflow".to_string())?;
                output.delete(&marker)?;
            }
            output.delete([INSTALL_REQUESTS, &scope].concat())?;
        }
        if installing != previous_installing || (installing == 0 && had_installed_count) {
            if installing == 0 {
                output.delete(INSTALLING)?;
            } else {
                output.put(INSTALLING, installing.to_be_bytes())?;
            }
        }
        let stored = view.get(META).map_err(|e| e.to_string())?;
        let mut meta = stored.as_deref().and_then(Meta::decode);
        let rotate = reset || overflow || meta.is_none();
        if rotate {
            meta = Some(Meta::fresh()?);
            output.delete_range(EVENTS, EVENTS_END)?;
            output.delete(INVALID)?;
            output.delete(RESET_REQUEST)?;
        }
        let mut meta = meta.unwrap();
        // While an external replacement is unfinished no bootstrap is valid;
        // finishing rotates once more and starts at the complete snapshot.
        if overflow || installing > 0 {
            candidates.clear();
            bytes = 0;
        }
        let mut reclaimed = 0;
        while meta.bytes.saturating_add(bytes as u64) > MAX_LOG_BYTES as u64 {
            if reclaimed == MAX_RECLAIMED || meta.floor == meta.tail {
                meta = Meta::fresh()?;
                output.delete_range(EVENTS, EVENTS_END)?;
                break;
            }
            let key = event_key(meta.floor + 1);
            let old = view
                .get(&key)
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "coin journal retention gap".to_string())?;
            meta.bytes = meta
                .bytes
                .checked_sub((key.len() + old.len()) as u64)
                .ok_or_else(|| "coin journal byte accounting".to_string())?;
            meta.floor += 1;
            output.delete(key)?;
            reclaimed += 1;
        }
        let mut candidates: Vec<_> = candidates.into_values().collect();
        candidates.sort_unstable_by_key(|candidate| candidate.order);
        if meta.tail.checked_add(candidates.len() as u64).is_none() {
            meta = Meta::fresh()?;
            output.delete_range(EVENTS, EVENTS_END)?;
        }
        for candidate in candidates {
            meta.tail += 1;
            let mut value = Vec::with_capacity(64 + candidate.blob.len());
            value.extend_from_slice(&candidate.key);
            value.extend_from_slice(candidate.blob);
            let key = event_key(meta.tail);
            meta.bytes += (key.len() + value.len()) as u64;
            output.put_owned(key, value)?;
        }
        let encoded = meta.encode();
        if stored.as_deref() != Some(encoded.as_slice()) {
            output.put(META, encoded)?;
        }
        Ok(())
    }
}

fn range_touches_rows(lower: &[u8], upper: &[u8]) -> bool {
    [[0x30, 0, 0], [0x31, 0, 0]].iter().any(|prefix| {
        lower < upper
            && upper > prefix.as_slice()
            && (lower < prefix.as_slice() || lower.starts_with(prefix))
    })
}

fn may_contain_coin_owner(blob: &[u8]) -> bool {
    // Go leaves encode owner key 4 and 3648 owner bytes with this header.
    // Scan the whole blob: cached metadata may precede the owner and padding
    // may follow it. Absence rules out a valid Coin in the oversized-row path.
    const HEADER: [u8; 18] = [1, 0, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0, 14, 64];
    blob.windows(HEADER.len()).any(|bytes| bytes == HEADER)
}

fn is_proven_non_coin(blob: &[u8]) -> bool {
    if may_contain_coin_owner(blob) {
        return false;
    }
    // Preserve decoder errors and marked but malformed Coins. Only a parsed
    // tree without a possible 32-byte Coin type marker is safe to discard.
    let Ok(root) = quil_tries::deserialize_go_tree(blob) else {
        return false;
    };
    quil_tries::VectorCommitmentTree { root }
        .get(&[0xff; 32])
        .is_none_or(|marker| marker.len() != 32)
}

/// Mirrors token_intrinsic::state; integration tests enforce parity.
/// Reserved root histories must not rotate the journal. Other oversized
/// rows remain uncertain because the decoder accepts trailing padding.
pub fn is_reserved_coin_record(address: &[u8; 32]) -> bool {
    if address[..31].iter().all(|byte| *byte == 0xff) && matches!(address[31], 0xf9..=0xfe) {
        return true;
    }
    let level = address[24];
    let index = u16::from_be_bytes([address[30], address[31]]);
    if address[..23].iter().all(|byte| *byte == 0xff)
        && address[23] == 0xf4
        && level <= 16
        && address[25..30].iter().all(|byte| *byte == 0xff)
        && u64::from(index) < 1u64 << (16 - level)
    {
        return true;
    }
    if !address[2..23].iter().all(|byte| *byte == 0xff) || !matches!(address[23], 0xf0..=0xf3) {
        return false;
    }
    let block = u64::from_be_bytes(address[24..32].try_into().unwrap());
    let width = 63 - block.leading_zeros().min(63);
    if !(6..=15).contains(&width) {
        return false;
    }
    let path = (block & ((1u64 << width) - 1)) << (16 - width);
    address[..2] == (path as u16).to_be_bytes()
}

enum BatchMutation<'a> {
    Put(&'a [u8], &'a [u8]),
    Delete(&'a [u8]),
    DeleteRange(&'a [u8], &'a [u8]),
}

// WriteBatch's twelve-byte header is followed by tagged, length-prefixed
// records. Unsupported column families/merges cannot silently skip outputs.
fn visit_batch<'a>(bytes: &'a [u8], mut visit: impl FnMut(BatchMutation<'a>)) -> bool {
    fn varint(rest: &mut &[u8]) -> Option<usize> {
        let mut value = 0u32;
        for shift in (0..35).step_by(7) {
            let (&byte, tail) = rest.split_first()?;
            *rest = tail;
            value |= u32::from(byte & 0x7f).checked_shl(shift)?;
            if byte & 0x80 == 0 {
                return usize::try_from(value).ok();
            }
        }
        None
    }
    fn slice<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
        let len = varint(rest)?;
        if rest.len() < len {
            return None;
        }
        let (head, tail) = rest.split_at(len);
        *rest = tail;
        Some(head)
    }
    let mut parse = || -> Option<()> {
        let count = u32::from_le_bytes(bytes.get(8..12)?.try_into().ok()?);
        let mut rest = bytes.get(12..)?;
        let mut records = 0u32;
        while let Some((&tag, tail)) = rest.split_first() {
            rest = tail;
            match tag {
                0x0 | 0x7 => visit(BatchMutation::Delete(slice(&mut rest)?)),
                0x1 => visit(BatchMutation::Put(slice(&mut rest)?, slice(&mut rest)?)),
                0xF => visit(BatchMutation::DeleteRange(
                    slice(&mut rest)?,
                    slice(&mut rest)?,
                )),
                0x3 => {
                    slice(&mut rest)?;
                    continue;
                }
                _ => return None,
            }
            records = records.checked_add(1)?;
        }
        (records == count).then_some(())
    };
    parse().is_some()
}

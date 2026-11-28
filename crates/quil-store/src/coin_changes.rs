//! Durable arrival order for wallet discovery.
//!
//! Events and source rows commit in the same RocksDB batch.
//! Stored blobs are public; quil-node decodes Coins.

use std::collections::BTreeMap;
use std::sync::Arc;

use quil_forest::{CoordinatedDb, LocalBatchProjection, LocalProjectionBatch, LocalProjectionRead};
use quil_types::error::{QuilError, Result};
use quil_types::store::SnapshotReadable;

pub const NAMESPACE: &[u8] = b"quil/local/coin-changes/v1/";
const META: &[u8] = b"quil/local/coin-changes/v1/meta";
const INVALID: &[u8] = b"quil/local/coin-changes/v1/invalid";
pub(crate) const DISABLED: &[u8] = b"quil/local/coin-changes/v1/disabled";
pub(crate) const INSTALL_TARGETS: &[u8] = b"quil/local/coin-changes/v1/install-targets/";
/// Canonical import readiness is independent of the optional Coin journal.
pub const SNAPSHOT_INSTALL_STATE: &[u8] = b"quil/local/canonical-snapshot/installing/v1";
pub(crate) const RESET_REQUEST: &[u8] = b"quil/local/coin-changes/v1/reset-request";
pub(crate) const INSTALLING: &[u8] = b"quil/local/coin-changes/v1/installing";
pub(crate) const INSTALL_OVERFLOW: &[u8] = b"quil/local/coin-changes/v1/install-overflow";
const INSTALL_REQUESTS: &[u8] = b"quil/local/coin-changes/v1/install-requests/";
const INSTALL_SCOPES: &[u8] = b"quil/local/coin-changes/v1/install-scopes/";
const MAX_INSTALL_SCOPES: u64 = 128;
const MAX_RECOVERY_BYTES: usize = 64 << 10;
const EVENTS: &[u8] = b"quil/local/coin-changes/v1/events/";
const EVENTS_END: &[u8] = b"quil/local/coin-changes/v1/events0";
const MAX_LOG_BYTES: usize = 64 << 20;
const MAX_RECORD_BYTES: usize = 64 << 10;
const MAX_EXAMINED: usize = 1024;
const MAX_RECLAIMED: usize = 64;
const MAX_BATCH_EVENT_BYTES: usize = 512 << 10;
const MAX_BATCH_EVENTS: usize = 128;

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

/// Configure the journal before exposing the store. A clean restart keeps
/// the existing cursor epoch.
pub(crate) fn configure(db: &CoordinatedDb, enabled: bool) -> Result<()> {
    if db.get(SNAPSHOT_INSTALL_STATE).map_err(error)?.is_none() {
        let snapshot_request = [INSTALL_REQUESTS, b"snapshot-install"].concat();
        let snapshot_scope = [INSTALL_SCOPES, b"snapshot-install"].concat();
        let request = db.get(&snapshot_request).map_err(error)?;
        let scope = db.get(&snapshot_scope).map_err(error)?;
        let legacy_import = legacy_snapshot_import_pending(request.as_deref(), scope.as_deref());
        if legacy_import {
            db.put(SNAPSHOT_INSTALL_STATE, b"1").map_err(error)?;
        }
    }
    let canonical_import_pending = db
        .get(SNAPSHOT_INSTALL_STATE)
        .map_err(error)?
        .as_deref()
        .is_some_and(|value| !completed_snapshot_import(value));
    let stored = db.get(META).map_err(error)?;
    if !enabled {
        if stored.is_some() && db.get(DISABLED).map_err(error)?.is_none() {
            db.put(DISABLED, b"1").map_err(error)?;
        }
        return Ok(());
    }

    let scopes = recovery_page(db, INSTALL_SCOPES, MAX_RECOVERY_BYTES)?;
    let scopes = scopes.complete.then_some(scopes.entries);
    let requests = recovery_page(db, INSTALL_REQUESTS, MAX_RECOVERY_BYTES)?;
    let requests_complete = requests.complete;
    let requests_empty = requests.entries.is_empty();
    let remaining = MAX_RECOVERY_BYTES.saturating_sub(requests.bytes);
    let installing = db.get(INSTALLING).map_err(error)?;
    let invalid = db.get(INVALID).map_err(error)?.is_some();
    let was_disabled = db.get(DISABLED).map_err(error)?.is_some();
    let overflow = db.get(INSTALL_OVERFLOW).map_err(error)?;
    if overflow.as_deref() == Some(b"1") {
        tracing::warn!("Coin journal has untracked legacy maintenance; keeping incremental discovery unavailable until canonical recovery is verified");
    }
    let fresh = stored.as_deref().and_then(Meta::decode).is_none();
    let mut batch = rocksdb::WriteBatch::default();
    let mut repair = rocksdb::WriteBatch::default();
    let uncertain = scopes.is_none() || !requests_complete;
    let mut untracked = scopes.is_none();
    if let Some(scopes) = &scopes {
        let count = scopes.len() as u64;
        let encoded = count.to_be_bytes();
        let expected = (count > 0).then_some(encoded.as_slice());
        if installing.as_deref() != expected {
            if count == 0 {
                repair.delete(INSTALLING);
                if installing.is_some() && requests_complete && requests_empty {
                    untracked = true;
                }
            } else {
                repair.put(INSTALLING, encoded);
            }
        }
        for (key, value) in scopes {
            let scope = &key[INSTALL_SCOPES.len()..];
            if value.as_slice() != b"1" {
                untracked = true;
            }
            let request = [INSTALL_REQUESTS, scope].concat();
            // Verify each scope once, through its pending request when present.
            if !canonical_import_pending
                && requests
                    .entries
                    .binary_search_by(|(key, _)| key.cmp(&request))
                    .is_err()
                && completed_installation(db, scope)?
            {
                batch.put(request, [0]);
            }
        }
    }
    for (key, value) in requests.entries {
        let scope = &key[INSTALL_REQUESTS.len()..];
        if scope.is_empty() || scope.len() > 256 || !matches!(value.as_slice(), [0] | [1]) {
            untracked = true;
            continue;
        }
        if value == [0] || (!canonical_import_pending && completed_installation(db, scope)?) {
            batch.put(key, [0]);
        } else {
            batch.put(key, value);
        }
    }
    if uncertain || untracked {
        let value = if !untracked && recoverable_overflow(overflow.as_deref()) {
            tracing::info!("Coin journal has deferred requests; verifying bounded recovery pages");
            b"2".as_slice()
        } else {
            tracing::warn!("Coin journal recovery cannot verify all maintenance identities; incremental discovery remains unavailable");
            b"1".as_slice()
        };
        if overflow.as_deref() != Some(value) {
            repair.put(INSTALL_OVERFLOW, value);
        }
    }
    if repair.len() > 0 {
        db.write(repair).map_err(error)?;
    }
    db.register_local_projection(Arc::new(CoinProjection))
        .map_err(error)?;
    if fresh
        || invalid
        || was_disabled
        || installing.is_some()
        || overflow.is_some()
        || batch.len() > 0
    {
        batch.delete(DISABLED);
        batch.put(RESET_REQUEST, b"1");
        db.write(batch).map_err(error)?;
    }
    if !canonical_import_pending
        && !requests_complete
        && !untracked
        && recoverable_overflow(overflow.as_deref())
    {
        recover_deferred_requests(db, remaining)?;
    }
    Ok(())
}

fn recoverable_overflow(value: Option<&[u8]>) -> bool {
    value.is_none_or(|value| value == b"2")
}

/// Recheck maintenance against canonical rows only after a pending snapshot
/// has finished replaying. The first configure pass cannot verify these rows.
pub(crate) fn recover_after_snapshot(db: &CoordinatedDb) -> Result<()> {
    let scopes = recovery_page(db, INSTALL_SCOPES, MAX_RECOVERY_BYTES)?;
    let requests = recovery_page(db, INSTALL_REQUESTS, MAX_RECOVERY_BYTES)?;
    let requests_complete = requests.complete;
    let remaining = MAX_RECOVERY_BYTES.saturating_sub(requests.bytes);
    let mut batch = rocksdb::WriteBatch::default();
    for (key, value) in scopes.entries {
        if value != b"1" {
            continue;
        }
        let scope = &key[INSTALL_SCOPES.len()..];
        let request = [INSTALL_REQUESTS, scope].concat();
        if requests
            .entries
            .binary_search_by(|(key, _)| key.cmp(&request))
            .is_err()
            && completed_installation(db, scope)?
        {
            batch.put(request, [0]);
        }
    }
    for (key, value) in requests.entries {
        let scope = &key[INSTALL_REQUESTS.len()..];
        if !scope.is_empty()
            && scope.len() <= 256
            && matches!(value.as_slice(), [0] | [1])
            && (value == [0] || completed_installation(db, scope)?)
        {
            batch.put(key, [0]);
        }
    }
    if batch.len() > 0 {
        db.write(batch).map_err(error)?;
    }
    if !requests_complete && db.get(INSTALL_OVERFLOW).map_err(error)?.as_deref() == Some(b"2") {
        recover_deferred_requests(db, remaining)?;
    }
    Ok(())
}

struct RecoveryPage {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    complete: bool,
    bytes: usize,
}

fn recovery_page(db: &CoordinatedDb, prefix: &[u8], max_bytes: usize) -> Result<RecoveryPage> {
    let mut options = rocksdb::ReadOptions::default();
    options.fill_cache(false);
    let mut iterator = db.raw_iterator_opt(options);
    iterator.seek(prefix);
    let mut entries = Vec::new();
    let mut bytes = 0usize;
    while let Some((key, value)) = iterator.key().zip(iterator.value()) {
        if !key.starts_with(prefix) {
            break;
        }
        bytes = bytes.saturating_add(key.len()).saturating_add(value.len());
        if entries.len() == MAX_INSTALL_SCOPES as usize || bytes > max_bytes {
            iterator.status().map_err(error)?;
            return Ok(RecoveryPage {
                entries,
                complete: false,
                bytes,
            });
        }
        entries.push((key.to_vec(), value.to_vec()));
        iterator.next();
    }
    iterator.status().map_err(error)?;
    Ok(RecoveryPage {
        entries,
        complete: true,
        bytes,
    })
}

// The byte budget covers request enumeration here. Projection validation
// and forest point reads have separate bounds.
fn recover_deferred_requests(db: &CoordinatedDb, mut remaining: usize) -> Result<()> {
    while remaining > 0 {
        let page = recovery_page(db, INSTALL_REQUESTS, remaining)?;
        remaining = remaining.saturating_sub(page.bytes);
        let mut batch = rocksdb::WriteBatch::default();
        let mut finished = Vec::new();
        for (key, value) in page.entries {
            let scope = &key[INSTALL_REQUESTS.len()..];
            if !scope.is_empty()
                && scope.len() <= 256
                && matches!(value.as_slice(), [0] | [1])
                && (value == [0] || completed_installation(db, scope)?)
            {
                batch.put(&key, [0]);
                finished.push(key);
            }
        }
        if finished.is_empty() {
            if !page.complete {
                tracing::warn!("Coin journal deferred recovery has no completed request in its bounded page; keeping its fence");
            }
            return Ok(());
        }
        db.write(batch).map_err(error)?;
        // The write may commit despite projection failure; request removal proves progress.
        let mut progressed = false;
        for key in finished {
            if db.get(key).map_err(error)?.is_none() {
                progressed = true;
                break;
            }
        }
        if !progressed {
            tracing::warn!(
                "Coin journal deferred recovery could not consume a request; keeping its fence"
            );
            return Ok(());
        }
        if page.complete {
            return Ok(());
        }
    }
    tracing::warn!("Coin journal deferred recovery exhausted its startup metadata budget; remaining requests are retained for the next open");
    Ok(())
}

pub(crate) fn rewind_target(scope: &[u8], roots: &[[u8; 32]; 4]) -> (Vec<u8>, Vec<u8>) {
    (
        [INSTALL_TARGETS, scope].concat(),
        roots.iter().flatten().copied().collect(),
    )
}

pub(crate) fn completed_snapshot_import(value: &[u8]) -> bool {
    value == b"0"
}

fn legacy_snapshot_import_pending(request: Option<&[u8]>, scope: Option<&[u8]>) -> bool {
    request == Some(&[1]) || (request != Some(&[0]) && scope == Some(b"1"))
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

/// Pending requests can survive projection failures before their markers exist.
/// Read flags and requests from one snapshot, including in overlays.
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

/// Return the watermark from the snapshot used by ListCoins.
/// A missing watermark leaves incremental discovery unavailable.
pub fn snapshot_cursor(snapshot: &dyn SnapshotReadable, domain: &[u8; 32]) -> Result<Vec<u8>> {
    let import_state = snapshot.read_record(SNAPSHOT_INSTALL_STATE)?;
    let completed = import_state
        .as_deref()
        .is_some_and(completed_snapshot_import);
    let legacy_import = if completed {
        false
    } else {
        let request = snapshot.read_record(&[INSTALL_REQUESTS, b"snapshot-install"].concat())?;
        let scope = snapshot.read_record(&[INSTALL_SCOPES, b"snapshot-install"].concat())?;
        legacy_snapshot_import_pending(request.as_deref(), scope.as_deref())
    };
    if import_state
        .as_deref()
        .is_some_and(|value| !completed_snapshot_import(value))
        || legacy_import
    {
        return Err(QuilError::ExecutionUnavailable(
            "Coin scan snapshot contains an incomplete snapshot import".into(),
        ));
    }
    if snapshot.read_record(DISABLED)?.is_some()
        || snapshot.read_record(INSTALLING)?.is_some()
        || snapshot.read_record(INSTALL_OVERFLOW)?.is_some()
        || snapshot.read_record(INVALID)?.is_some()
    {
        return Ok(Vec::new());
    }
    match snapshot.read_record(META)? {
        None => Ok(Vec::new()),
        Some(bytes) => {
            Ok(Meta::decode(&bytes).map_or_else(Vec::new, |meta| meta.cursor(domain, meta.tail)))
        }
    }
}

// Flags and epoch must come from one snapshot.
fn readable_meta(snapshot: &rocksdb::Snapshot<'_>) -> Result<Option<Meta>> {
    if snapshot
        .get(SNAPSHOT_INSTALL_STATE)
        .map_err(error)?
        .as_deref()
        .is_some_and(|value| !completed_snapshot_import(value))
    {
        return Ok(None);
    }
    for key in [DISABLED, INVALID, INSTALLING, INSTALL_OVERFLOW] {
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
        return Ok(None);
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
        return Ok(RawCoinChangesPage::reset());
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
        let mut work_limit = false;
        let mut bytes = 0usize;
        let mut order = 0u32;
        let mut install_requests = BTreeMap::<Vec<u8>, bool>::new();
        let mut install_overrun = false;
        let mut unknown_installation = false;
        let mut pending_left = false;
        let stored_overflow = view.get(INSTALL_OVERFLOW).map_err(|e| e.to_string())?;
        let tracked_overflow = stored_overflow.as_deref() == Some(b"2");
        let invalid = view.get(INVALID).map_err(|e| e.to_string())?.is_some();
        if invalid || tracked_overflow {
            // Failed projections leave requests without scope/count updates.
            // Replay them before clearing INVALID.
            reset = invalid;
            match view
                .prefix_entries(
                    INSTALL_REQUESTS,
                    MAX_INSTALL_SCOPES as usize,
                    MAX_RECOVERY_BYTES,
                )
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
                            unknown_installation = true;
                        } else {
                            install_requests.insert(scope.to_vec(), value == [1]);
                        }
                    }
                }
                None => {
                    install_overrun = true;
                    pending_left = true;
                }
            }
        }
        let parsed = visit_batch(batch, |mutation| {
            order = order.saturating_add(1);
            match mutation {
                BatchMutation::Put(key, value) => {
                    if key == RESET_REQUEST {
                        reset = true;
                    }
                    if key == INSTALL_OVERFLOW && value == b"1" {
                        // A private branch may have dropped untrackable hints.
                        // Its new fence must survive completion of older scopes.
                        unknown_installation = true;
                        install_overrun = true;
                        overflow = true;
                    }
                    if let Some(scope) = key.strip_prefix(INSTALL_REQUESTS) {
                        if scope.is_empty() || scope.len() > 256 || !matches!(value, [0] | [1]) {
                            overflow = true;
                            install_overrun = true;
                            unknown_installation = true;
                        } else if install_requests.len() >= MAX_INSTALL_SCOPES as usize
                            && !install_requests.contains_key(scope)
                        {
                            // Leave deferred requests durable for a later pass.
                            overflow = true;
                            install_overrun = true;
                            pending_left = true;
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
                        if bytes > MAX_BATCH_EVENT_BYTES || candidates.len() >= MAX_BATCH_EVENTS {
                            work_limit = true;
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
                        candidates.retain(|key, candidate| {
                            let keep = key.as_slice() < lower || key.as_slice() >= upper;
                            if !keep {
                                bytes -= event_bytes(candidate.blob.len());
                            }
                            keep
                        });
                    }
                }
            }
        });
        if work_limit {
            return Err("coin journal per-write event limit".into());
        }
        if !parsed {
            // The unread suffix may contain a begin request. Retain the input
            // and invalidate the journal so recovery can replay it.
            return Err("unlistable coin journal input".into());
        }
        if candidates.is_empty()
            && install_requests.is_empty()
            && !reset
            && !overflow
            && !tracked_overflow
        {
            return Ok(());
        }
        let overflow_value =
            if unknown_installation || !recoverable_overflow(stored_overflow.as_deref()) {
                b"1".as_slice()
            } else {
                b"2".as_slice()
            };
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
            // A duplicate begin or finish does not change this scope.
            if active && !existed {
                if installing >= MAX_INSTALL_SCOPES {
                    // Keep the request while all tracked scope slots are occupied.
                    install_overrun = true;
                    pending_left = true;
                    continue;
                } else {
                    reset = true;
                    installing += 1;
                    output.put(&marker, b"1")?;
                }
            } else if !active && existed {
                reset = true;
                installing = installing
                    .checked_sub(1)
                    .ok_or_else(|| "coin journal installation count underflow".to_string())?;
                output.delete(&marker)?;
            }
            let target = [INSTALL_TARGETS, &scope].concat();
            if !active
                && view
                    .get(&target)
                    .map_err(|error| error.to_string())?
                    .is_some()
            {
                output.delete(target)?;
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
        if install_overrun && stored_overflow.as_deref() != Some(overflow_value) {
            output.put(INSTALL_OVERFLOW, overflow_value)?;
        }
        if (tracked_overflow || (install_overrun && overflow_value == b"2"))
            && !unknown_installation
            && !pending_left
            && installing == 0
        {
            output.delete(INSTALL_OVERFLOW)?;
            reset = true;
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
        // These arrivals are covered by the snapshot after the epoch reset.
        if overflow || installing > 0 || previous_installing > 0 || stored_overflow.is_some() {
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

fn completed_installation(db: &CoordinatedDb, scope: &[u8]) -> Result<bool> {
    if scope == b"snapshot-install" {
        return Ok(db
            .get(SNAPSHOT_INSTALL_STATE)
            .map_err(error)?
            .as_deref()
            .is_some_and(completed_snapshot_import));
    }
    let forest = quil_forest::Forest::with_namespace(db.clone(), crate::FOREST_NAMESPACE);
    let root_versions_absent = |app: &[u8; 32], phase_idx: usize| -> Result<bool> {
        let (set, kind) = [
            ("vertex", "adds"),
            ("vertex", "removes"),
            ("hyperedge", "adds"),
            ("hyperedge", "removes"),
        ][phase_idx];
        let mut prefix = crate::encoding::hypergraph_root_version_key(set, kind, app, &[0; 32]);
        prefix.truncate(prefix.len() - 32);
        let mut options = rocksdb::ReadOptions::default();
        options.fill_cache(false);
        let mut iterator = db.raw_iterator_opt(options);
        iterator.seek(&prefix);
        iterator.status().map_err(error)?;
        Ok(!iterator.key().is_some_and(|key| key.starts_with(&prefix)))
    };
    let empty_phase = |app: &[u8; 32], phase_idx: usize| -> Result<bool> {
        Ok(forest
            .shard_phase_is_physically_empty(app, quil_forest::PHASES[phase_idx])
            .map_err(error)?
            && root_versions_absent(app, phase_idx)?)
    };

    if let Some(descriptor) = scope.strip_prefix(b"wipe/") {
        if descriptor.len() != 33 || descriptor[32] >= 4 {
            return Ok(false);
        }
        let app: &[u8; 32] = descriptor[..32].try_into().unwrap();
        return empty_phase(app, usize::from(descriptor[32]));
    }
    if let Some(descriptor) = scope.strip_prefix(b"reset/") {
        let Ok(app) = <&[u8; 32]>::try_from(descriptor) else {
            return Ok(false);
        };
        for phase_idx in 0..4 {
            if !empty_phase(app, phase_idx)? {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    if let Some(filter) = scope.strip_prefix(b"rewind/") {
        if !(32..=128).contains(&filter.len()) {
            return Ok(false);
        }
        let Some((app, bits)) = quil_forest::decode_shard_filter_or_root(filter, 32) else {
            return Ok(false);
        };
        let Some(targets) = db.get([INSTALL_TARGETS, scope].concat()).map_err(error)? else {
            return Ok(false);
        };
        if targets.len() != 128 {
            return Ok(false);
        }
        let app: &[u8; 32] = app.as_slice().try_into().unwrap();
        for (phase_idx, phase) in quil_forest::PHASES.into_iter().enumerate() {
            let expected: [u8; 32] = targets[phase_idx * 32..(phase_idx + 1) * 32]
                .try_into()
                .unwrap();
            let empty = quil_forest::subtree_proof::same_root(&expected, &[0; 32]);
            match forest.read_head_version(app, phase).map_err(error)? {
                Some(head) => {
                    if forest
                        .shard_phase_root(app, phase, head)
                        .map_err(error)?
                        .is_none()
                    {
                        return Ok(false);
                    }
                    let actual = forest
                        .app_subtree_root(app, phase, head, &bits)
                        .map_err(error)?;
                    if !quil_forest::subtree_proof::same_root(&actual, &expected) {
                        return Ok(false);
                    }
                }
                None => {
                    if !empty
                        || !forest
                            .shard_phase_is_physically_empty(app, phase)
                            .map_err(error)?
                    {
                        return Ok(false);
                    }
                }
            }
            // A whole-app zero target resets this phase and clears its index.
            if bits.is_empty() && expected == [0; 32] && !empty_phase(app, phase_idx)? {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    Ok(false)
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
    // Keep malformed encodings for the node's Coin decoder. Exclude only
    // parsed trees with no possible 32-byte Coin type marker.
    let Ok(root) = quil_tries::deserialize_go_tree(blob) else {
        return false;
    };
    quil_tries::VectorCommitmentTree { root }
        .get(&[0xff; 32])
        .is_none_or(|marker| marker.len() != 32)
}

/// Reserved token metadata and root-history addresses, matching token_intrinsic::state.
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

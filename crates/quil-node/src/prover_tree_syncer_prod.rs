//! Production [`ProverTreeSyncer`] impl — efficient forest Merkle-diff sync.
//!
//! A behind worker catches its shard/phase trees up to a peer archive by
//! walking the peer's JMT top-down and pulling only the nodes whose hash
//! differs from its own ([`quil_forest::diff_leaves`], via a gRPC-backed
//! [`RemoteTreeReader`]). The diff is self-authenticating against the trusted
//! header root, and the pulled leaves are applied into the live CRDT's forest at
//! a COORDINATED version (so they never collide with `commit_inner`).
//!
//! Replaces the legacy KZG `ensure_prover_tree_incremental` /
//! `ensure_shard_tree_fresh` node-by-node walk (which rebuilt a
//! `VectorCommitmentTree`); that path is retired with the forest cutover.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::{info, warn};

use quil_engine::prover_tree_syncer::ProverTreeSyncer;
use quil_rpc::ArchiveClient;
use quil_types::error::{QuilError, Result};

/// Syncs authenticated trees from an archive, with optional master discovery.
pub struct ProdProverTreeSyncer {
    /// Master's directory endpoint for a separate worker, or an explicitly
    /// configured source when archive discovery is disabled.
    pub master_stream_addr: String,
    /// Worker's HypergraphStore (the forest shares its RocksDB).
    /// Supplied by the caller for lifetime/ownership parity with the master
    /// syncer; the sync paths below go through `crdt`'s own forest handle.
    #[allow(dead_code)]
    pub hg_store: Arc<quil_store::RocksHypergraphStore>,
    /// Falcon q-prover-key signing key (1281B) — the `:8340` network identity
    /// used for the PQNoise handshake to the master.
    pub falcon_signing_key: Vec<u8>,
    /// The live CRDT — sync applies into ITS forest at coordinated versions.
    pub crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    /// When set, resolve a live ARCHIVE endpoint per sync attempt (round-robin,
    /// failure-blacklisting) instead of the fixed `master_stream_addr`. Used by
    /// thread-mode workers doing the step-4 app-shard catch-up: they dial an
    /// archive directly (the master only serves the global tree, not app-shard
    /// leaves), and the pool tolerates an empty-at-build / dead-archive state.
    pub archive_pool: Option<Arc<quil_rpc::ArchiveEndpointPool>>,
    /// Separate workers discover the master's verified archive endpoints.
    /// They then read application trees directly from those archives.
    pub discover_archives_from_master: bool,
}

use crate::forest_sync::{is_empty_phase_root, phase_anchor};

/// How long an archive that failed a shard read or a GLOBAL prover-tree
/// sync is passed over while another is known. Process-wide: the master and
/// every worker of this node read the same archives.
const SOURCE_AVOID: std::time::Duration = std::time::Duration::from_secs(120);
static SOURCE_FAILURES: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
> = std::sync::LazyLock::new(Default::default);

pub(crate) fn source_failed(addr: &str) {
    SOURCE_FAILURES
        .lock()
        .unwrap()
        .insert(addr.to_string(), std::time::Instant::now());
}

fn recently_failed(addr: &str) -> bool {
    let mut failures = SOURCE_FAILURES.lock().unwrap();
    failures.retain(|_, at| at.elapsed() < SOURCE_AVOID);
    failures.contains_key(addr)
}

/// The order a pass that pulls the GLOBAL prover tree tries `archives` in:
/// from a random one, so regular nodes passing together at an epoch boundary
/// spread over the archives instead of all asking the first configured one,
/// and with those that failed recently last.
pub(crate) fn archive_pull_order(archives: Vec<String>) -> Vec<String> {
    let start = quil_engine::prover_tree_syncer::random_index(archives.len());
    archive_pull_order_from(archives, start)
}

fn archive_pull_order_from(mut archives: Vec<String>, start: usize) -> Vec<String> {
    if !archives.is_empty() {
        let len = archives.len();
        archives.rotate_left(start % len);
    }
    let (fresh, failed): (Vec<_>, Vec<_>) = archives
        .into_iter()
        .partition(|addr| !recently_failed(addr));
    fresh.into_iter().chain(failed).collect()
}

/// How long an unused archive connection for shard frame reads is kept.
const FRAME_CLIENT_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

/// A shard frame read connection's key: the dialing thread and the archive.
/// Each in-process worker keeps its own connections, so one worker's reads
/// never queue behind another's; their I/O runs on the shared archive I/O
/// runtime (`quil_rpc::archive_client`), where a blocked worker thread
/// cannot stall it.
pub(crate) type FrameClientKey = (std::thread::ThreadId, String);

struct FrameClient<C> {
    id: u64,
    signing_key: Vec<u8>,
    client: C,
    used: std::time::Instant,
}

/// Archive read connections, one per key and identity, for shard frames
/// and historical proofs: a replay batch reads frame by frame, and each
/// new connection costs the archive a PQNoise handshake.
pub(crate) struct FrameClients<C> {
    next_id: u64,
    entries: std::collections::HashMap<FrameClientKey, FrameClient<C>>,
}

impl<C: Clone> FrameClients<C> {
    pub(crate) fn new() -> Self {
        Self {
            next_id: 0,
            entries: Default::default(),
        }
    }

    /// The connection for `key` under `signing_key`, if used within the idle
    /// window. Every idle connection is dropped first.
    pub(crate) fn get(
        &mut self,
        key: &FrameClientKey,
        signing_key: &[u8],
        now: std::time::Instant,
    ) -> Option<C> {
        self.entries
            .retain(|_, cached| now.saturating_duration_since(cached.used) < FRAME_CLIENT_IDLE);
        let cached = self
            .entries
            .get_mut(key)
            .filter(|cached| cached.signing_key == signing_key)?;
        cached.used = now;
        Some(cached.client.clone())
    }

    /// Keep `client` for `key`; its id names it to [`Self::reap`].
    pub(crate) fn insert(
        &mut self,
        key: FrameClientKey,
        signing_key: &[u8],
        client: C,
        now: std::time::Instant,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.entries.insert(
            key,
            FrameClient {
                id,
                signing_key: signing_key.to_vec(),
                client,
                used: now,
            },
        );
        id
    }

    pub(crate) fn evict(&mut self, key: &FrameClientKey) {
        self.entries.remove(key);
    }

    /// Drop connection `id` of `key` once idle. True when nothing is left
    /// to reap: it was dropped now, or earlier, or replaced.
    fn reap(&mut self, key: &FrameClientKey, id: u64, now: std::time::Instant) -> bool {
        let Some(cached) = self.entries.get(key).filter(|cached| cached.id == id) else {
            return true;
        };
        if now.saturating_duration_since(cached.used) < FRAME_CLIENT_IDLE {
            return false;
        }
        self.entries.remove(key);
        true
    }
}

pub(crate) static FRAME_CLIENTS: std::sync::LazyLock<
    std::sync::Mutex<FrameClients<ArchiveClient>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(FrameClients::new()));

fn frame_clients() -> std::sync::MutexGuard<'static, FrameClients<ArchiveClient>> {
    FRAME_CLIENTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Close connection `id` of `key` in `clients` once it has been idle, so an
/// idle channel does not keep pinging the archive.
pub(crate) async fn reap_frame_client<C: Clone>(
    clients: &'static std::sync::Mutex<FrameClients<C>>,
    key: FrameClientKey,
    id: u64,
) {
    loop {
        tokio::time::sleep(FRAME_CLIENT_IDLE).await;
        if clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reap(&key, id, std::time::Instant::now())
        {
            return;
        }
    }
}

/// Whether a failed read leaves its connection unusable. A busy or
/// refusing archive answered over a working connection: keep it.
pub(crate) fn read_breaks_connection(error: &quil_rpc::ArchiveClientError) -> bool {
    use tonic::Code;
    match error {
        quil_rpc::ArchiveClientError::Rpc(status) => matches!(
            status.code(),
            Code::Unavailable | Code::Unknown | Code::Cancelled | Code::DeadlineExceeded
        ),
        _ => true,
    }
}

/// A shard frame read in flight. Dropped before it finishes (a caller's
/// timeout), the read counts as failed and its connection is closed.
struct FrameRead<'a> {
    key: &'a FrameClientKey,
    finished: bool,
}

impl Drop for FrameRead<'_> {
    fn drop(&mut self) {
        if !self.finished {
            frame_clients().evict(self.key);
            source_failed(&self.key.1);
        }
    }
}

/// How long a search of GLOBAL frames for a carried shard header
/// ([`ProverTreeSyncer::carried_shard_headers`]) answers again for that
/// frame when it found copies or, having read and checked everything, none;
/// the back-off after every copy failed to replay
/// ([`ProverTreeSyncer::reject_carried_shard_headers`]) or was refused, and
/// after a search left frames unread or copies unchecked, each doubling up
/// to [`CARRIED_BACKOFF_MAX`]. Warnings about one frame come at most once
/// per [`CARRIED_SEARCH_RETRY`]. Process-wide, keyed by shard and frame, as
/// every worker of this node reads the same archives (tests share it too,
/// each under its own shard); at most [`CARRIED_SEARCHES`] frames of at most
/// [`CARRIED_COPIES`] copies each.
const CARRIED_SEARCH_RETRY: std::time::Duration = std::time::Duration::from_secs(600);
const CARRIED_REJECT_RETRY: std::time::Duration = std::time::Duration::from_secs(120);
const CARRIED_FAIL_RETRY: std::time::Duration = std::time::Duration::from_secs(30);
const CARRIED_BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(3600);
const CARRIED_SEARCHES: usize = 64;
/// How long a GLOBAL frame read for good is passed over
/// ([`ReadMark`]), and the archives whose reads are kept per frame.
const CARRIED_READ_EXPIRY: std::time::Duration = std::time::Duration::from_secs(3600);
const CARRIED_ARCHIVES: usize = 8;
const CARRIED_COPIES: usize = 4;
/// Copies a rebuilt frame failed with ([`ProverTreeSyncer::reject_carried_copy`])
/// and copies refused when checked, remembered per frame across searches,
/// the oldest forgotten first; a refused copy a search still read is kept
/// before any it did not, so a later search reads past every copy refused.
/// A copy refused for its output or structure stays refused; one refused
/// only for its certificate, or an attestation refused (this node's view may
/// lack the session, committee or registrations they need), is tried again,
/// as a rejected one is, once the search's back-off has passed.
const CARRIED_REJECTED: usize = 64;
const CARRIED_REFUSED: usize = 4096;
/// Copies offered for checking per search, named copies first, and at most
/// this many named copies gathered; copies of legacy certificates (whose
/// check may rebuild a historical committee) other than named ones, at most
/// [`CARRIED_LEGACY_CHECKS`] of them. The rest wait for the next search.
const CARRIED_VERIFIES: usize = 64;
const CARRIED_LEGACY_CHECKS: usize = 4;
/// The distinct anchors whose committee the legacy copies a search checks,
/// named or not, may send the node to GLOBAL history for.
const CARRIED_LEGACY_ANCHORS: usize = 2;
/// Distinct copies a search gathers before checking any: named ones first.
const CARRIED_GATHERED: usize = 512;
/// Attested forms of one copy checked per search: forged attestation bytes
/// cannot hide the genuine one behind them.
const CARRIED_ATTESTED_FORMS: usize = 3;
/// One search's time budget: reads stop at [`CARRIED_READ_BUDGET`], each
/// read within [`CARRIED_READ_TIMEOUT`], checks at [`CARRIED_CHECK_BUDGET`].
const CARRIED_SEARCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const CARRIED_READ_BUDGET: std::time::Duration = std::time::Duration::from_secs(40);
const CARRIED_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const CARRIED_CHECK_BUDGET: std::time::Duration = std::time::Duration::from_secs(55);
/// The longest one check may take: a check waiting on a historical
/// committee past it is unavailable, and the copy is checked again later.
const CARRIED_CHECK_SLICE: std::time::Duration = std::time::Duration::from_secs(10);

use quil_engine::prover_tree_syncer::{
    carried_copy_digest, carried_copy_is_legacy, carried_copy_key, normalize_carried_header,
    plausible_carried_copy, plausibly_anchored, rank_carried_copy, CarriedHeaders, CarriedVerifier,
    CopyId, CopyVerdict, CARRIED_HEADER_SPAN, CARRIED_HEADER_WINDOW,
};

/// A digest of one attested form of a copy, its attestation bytes included
/// (unlike [`carried_copy_digest`]): a refused form leaves the others.
fn attested_form_digest(header: &quil_types::proto::global::FrameHeader) -> CopyId {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"quil/app/carried-copy-form/v1");
    hasher.update(carried_copy_digest(header));
    hasher.update(&header.storage_attestation);
    hasher.finalize().into()
}

/// What a search for one shard frame's carried header found: the copies
/// kept, best first, and the digests ([`carried_copy_digest`]) of those
/// whose check passed.
#[derive(Clone, Debug, PartialEq)]
enum CarriedState {
    Found {
        copies: Vec<(u64, quil_types::proto::global::FrameHeader)>,
        certified: Vec<CopyId>,
    },
    /// Copies kept, none certified (their checks could not end), while
    /// frames went unread or copies unchecked: handed to replay, and the
    /// rest read on after the short back-off of a search cut short.
    Partial {
        copies: Vec<(u64, quil_types::proto::global::FrameHeader)>,
    },
    /// Everything read and checked, no copy carried.
    Missed,
    /// Everything read and checked, every copy carried refused.
    Refused,
    /// Every copy found failed to replay.
    Rejected,
    /// Frames left unread or copies unchecked, nothing found.
    Failed,
    /// Not searched: only what was rejected is remembered.
    Unsearched,
}

/// A search for one shard frame's carried header: when it was reached, what
/// it found and under which named parent; the copies rejected, refused, and
/// refused for now (for their certificate or attestation), how many it
/// refused and passed over; the GLOBAL frames each archive was read for
/// ([`ReadMark`]); how often in a row every copy failed to replay, every
/// copy was refused and searches made no progress; and when the frame was
/// last warned about.
struct CarriedSearch {
    at: std::time::Instant,
    state: CarriedState,
    named: Option<[u8; 32]>,
    rejected: std::collections::VecDeque<CopyId>,
    refused: std::collections::VecDeque<CopyId>,
    retried: std::collections::VecDeque<CopyId>,
    /// Per copy refused for now: since when, and how often in a row it was
    /// ([`Self::resume`] tries each again on its own back-off).
    retry: std::collections::HashMap<CopyId, (std::time::Instant, u32)>,
    /// Of the copies rejected, those no search had certified: kept passed
    /// over across back-offs until a search can check copies again.
    unchecked_rejected: std::collections::HashSet<CopyId>,
    refused_now: usize,
    passed_over: usize,
    read: std::collections::HashMap<String, std::collections::BTreeMap<u64, ReadMark>>,
    /// The certified copies the last search that found any kept.
    found: Vec<CopyId>,
    exhausted: u32,
    refused_streak: u32,
    failed: u32,
    warned: Option<std::time::Instant>,
}

/// A GLOBAL frame an archive was read for: when, and whether for good (it
/// carried no copy GLOBAL could have taken, or only copies refused for
/// their output or structure) or until the copies refused for now, or
/// rejected, are tried again. A mark for good expires after
/// [`CARRIED_READ_EXPIRY`], as an archive may have answered without the
/// frame's requests; marks are kept per archive, so one archive's answer
/// never keeps another from reading the frame.
#[derive(Clone, Copy, Debug, PartialEq)]
struct ReadMark {
    at: std::time::Instant,
    for_good: bool,
}

/// `base` doubled for each of `times` past the first, up to [`CARRIED_BACKOFF_MAX`].
fn backoff(base: std::time::Duration, times: u32) -> std::time::Duration {
    base.saturating_mul(1 << times.saturating_sub(1).min(16))
        .min(CARRIED_BACKOFF_MAX)
}

impl CarriedSearch {
    fn new(at: std::time::Instant) -> Self {
        Self {
            at,
            state: CarriedState::Unsearched,
            named: None,
            rejected: Default::default(),
            refused: Default::default(),
            retried: Default::default(),
            retry: Default::default(),
            unchecked_rejected: Default::default(),
            refused_now: 0,
            passed_over: 0,
            read: Default::default(),
            found: Vec::new(),
            exhausted: 0,
            refused_streak: 0,
            failed: 0,
            warned: None,
        }
    }

    /// Whether it still answers a search instead of the archive.
    fn current(&self) -> bool {
        self.fresh(self.at.elapsed())
    }

    /// Whether it still answers a search `age` after it was reached.
    fn fresh(&self, age: std::time::Duration) -> bool {
        match self.state {
            CarriedState::Found { .. } | CarriedState::Missed => age < CARRIED_SEARCH_RETRY,
            CarriedState::Rejected | CarriedState::Refused => age < self.reject_backoff(),
            CarriedState::Failed | CarriedState::Partial { .. } => age < self.fail_backoff(),
            CarriedState::Unsearched => false,
        }
    }

    /// The back-off after every copy found failed to replay, or every copy
    /// carried was refused, doubling each time in a row that happens again.
    fn reject_backoff(&self) -> std::time::Duration {
        match self.state {
            CarriedState::Refused => backoff(CARRIED_REJECT_RETRY, self.refused_streak),
            _ => backoff(CARRIED_REJECT_RETRY, self.exhausted),
        }
    }

    /// The back-off after a search left frames unread or copies unchecked,
    /// doubling each time in a row one makes no progress.
    fn fail_backoff(&self) -> std::time::Duration {
        backoff(CARRIED_FAIL_RETRY, self.failed)
    }

    /// Whether copy `id`, refused for now, is due to be checked again: its
    /// back-off, doubling each time in a row it is refused for now, has
    /// passed since it was.
    fn retry_due(&self, id: &CopyId) -> bool {
        self.retry
            .get(id)
            .is_none_or(|(at, times)| at.elapsed() >= backoff(CARRIED_REJECT_RETRY, *times))
    }

    /// Prepare a search again. Once the back-off after every copy failed to
    /// replay or was refused has passed, the copies rejected are tried
    /// again, but for those no search certified, while no search could
    /// check copies; each copy refused for now is tried again once its own
    /// back-off has passed ([`Self::retry_due`]), whatever the searches
    /// since reached, as its failure may have been this node's (a
    /// committee, session record, registration or GLOBAL frame it lacked
    /// then). The back-offs doubling each time keep forged copies cheap.
    /// Copies refused for their output or structure stay refused. The GLOBAL
    /// frames carrying the copies tried again are read again.
    fn resume(&mut self) {
        if !self.current()
            && matches!(self.state, CarriedState::Rejected | CarriedState::Refused)
            && !self.rejected.is_empty()
        {
            let unchecked = std::mem::take(&mut self.unchecked_rejected);
            self.rejected.retain(|id| unchecked.contains(id));
            self.unchecked_rejected = unchecked;
            self.forget_reads_until_retried();
        }
        let due: Vec<CopyId> = self
            .retried
            .iter()
            .filter(|id| self.retry_due(id))
            .copied()
            .collect();
        if !due.is_empty() {
            self.retried.retain(|id| !due.contains(id));
            self.forget_reads_until_retried();
        }
    }

    /// Forget the GLOBAL frames read until copies were tried again.
    fn forget_reads_until_retried(&mut self) {
        for marks in self.read.values_mut() {
            marks.retain(|_, mark| mark.for_good);
        }
    }

    /// The GLOBAL frames archive `addr` was read for that a search passes
    /// over: those marked until copies are tried again, and those marked for
    /// good within [`CARRIED_READ_EXPIRY`].
    fn read_by(&self, addr: &str) -> std::collections::BTreeSet<u64> {
        self.read
            .get(addr)
            .map(|marks| {
                marks
                    .iter()
                    .filter(|(_, mark)| !mark.for_good || mark.at.elapsed() < CARRIED_READ_EXPIRY)
                    .map(|(&global, _)| global)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Mark the GLOBAL frames `read` (with whether for good) as read from
    /// archive `addr` now, dropping expired marks, at most
    /// [`CARRIED_HEADER_SPAN`] per archive and [`CARRIED_ARCHIVES`]
    /// archives, the one read least recently dropped first.
    fn mark_read(&mut self, addr: &str, read: &[(u64, bool)]) {
        let now = std::time::Instant::now();
        for marks in self.read.values_mut() {
            marks.retain(|_, mark| !mark.for_good || mark.at.elapsed() < CARRIED_READ_EXPIRY);
        }
        if !read.is_empty() {
            let marks = self.read.entry(addr.to_string()).or_default();
            for &(global, for_good) in read {
                if marks.len() < CARRIED_HEADER_SPAN as usize || marks.contains_key(&global) {
                    marks.insert(global, ReadMark { at: now, for_good });
                }
            }
        }
        self.read.retain(|_, marks| !marks.is_empty());
        while self.read.len() > CARRIED_ARCHIVES {
            let oldest = self
                .read
                .iter()
                .min_by_key(|(_, marks)| marks.values().map(|mark| mark.at).max())
                .map(|(addr, _)| addr.clone());
            let Some(oldest) = oldest else { break };
            self.read.remove(&oldest);
        }
    }

    /// Whether it answers a search told `named`: copies found or none not
    /// once the parent the frame after it names is known and this search was
    /// not told that one; a back-off whatever it is told.
    fn answers(&self, named: Option<[u8; 32]>) -> bool {
        self.current()
            && (matches!(
                self.state,
                CarriedState::Rejected | CarriedState::Refused | CarriedState::Failed
            ) || named.is_none()
                || self.named == named)
    }

    /// Whether it remembers copies to pass over or frames read.
    fn remembers(&self) -> bool {
        !self.rejected.is_empty()
            || !self.refused.is_empty()
            || !self.retried.is_empty()
            || !self.read.is_empty()
            || !self.retry.is_empty()
    }

    /// Whether a warning about its frame is due, which it then records.
    fn warn_due(&mut self) -> bool {
        let due = self
            .warned
            .is_none_or(|at| at.elapsed() >= CARRIED_SEARCH_RETRY);
        if due {
            self.warned = Some(std::time::Instant::now());
        }
        due
    }
}

/// Remember `id` in `list` of at most `cap`, the oldest forgotten first.
/// Whether it was new.
fn remember(list: &mut std::collections::VecDeque<CopyId>, id: CopyId, cap: usize) -> bool {
    if list.contains(&id) {
        return false;
    }
    if list.len() >= cap {
        list.pop_front();
    }
    list.push_back(id);
    true
}

/// `list` with the ids a search still read ahead of being forgotten, then
/// `new`, within `cap`.
fn remember_all(
    list: &mut std::collections::VecDeque<CopyId>,
    still_carried: &std::collections::HashSet<CopyId>,
    new: &[CopyId],
    cap: usize,
) {
    let (carried, gone): (Vec<CopyId>, Vec<CopyId>) =
        list.iter().partition(|id| still_carried.contains(*id));
    *list = gone.into_iter().chain(carried).collect();
    for &id in new {
        remember(list, id, cap);
    }
    while list.len() > cap {
        list.pop_front();
    }
}

static CARRIED_SEARCHED: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<(Vec<u8>, u64), CarriedSearch>>,
> = std::sync::LazyLock::new(Default::default);

fn carried_searched(
) -> std::sync::MutexGuard<'static, std::collections::HashMap<(Vec<u8>, u64), CarriedSearch>> {
    CARRIED_SEARCHED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What a search learnt: what it reached, the copies it refused (for now
/// apart), those it passed over as refused before (still carried), how many
/// it refused and passed over, the archive it read and the GLOBAL frames it
/// read from it ([`ReadMark`]), and whether it read or checked anything new.
#[derive(Default)]
struct SearchOutcome<'a> {
    state: Option<CarriedState>,
    named: Option<[u8; 32]>,
    refused: &'a [CopyId],
    retried: &'a [CopyId],
    still_carried: Option<&'a std::collections::HashSet<CopyId>>,
    refused_now: usize,
    passed_over: usize,
    addr: &'a str,
    read: &'a [(u64, bool)],
    progress: bool,
    /// Whether it could check copies (the engine gave it its check).
    verified: bool,
}

/// Record a search of `key` that reached `outcome` now, keeping what was
/// remembered before and the last warning, within [`CARRIED_SEARCHES`]
/// frames: one that no longer answers and remembers nothing goes first,
/// then the oldest of those that remember nothing, then the oldest. A search
/// that finds copies ends a run of searches that refused every copy, and
/// one that finds a certified copy the last one did not ends a run of
/// copies failing to replay: their back-offs start over.
fn keep_carried_search(key: (Vec<u8>, u64), outcome: SearchOutcome<'_>) {
    let mut searches = carried_searched();
    searches.retain(|_, kept| kept.current() || kept.remembers());
    if searches.len() >= CARRIED_SEARCHES && !searches.contains_key(&key) {
        if let Some(evicted) = searches
            .iter()
            .min_by_key(|(_, kept)| (kept.remembers(), kept.at))
            .map(|(key, _)| key.clone())
        {
            searches.remove(&evicted);
        }
    }
    let now = std::time::Instant::now();
    let entry = searches
        .entry(key)
        .or_insert_with(|| CarriedSearch::new(now));
    let state = outcome.state.unwrap_or(CarriedState::Unsearched);
    entry.failed = match (&state, outcome.progress) {
        (CarriedState::Failed | CarriedState::Partial { .. }, false) => {
            entry.failed.saturating_add(1)
        }
        (CarriedState::Failed | CarriedState::Partial { .. }, true) => 1,
        _ => 0,
    };
    // A search that could check copies may try again those it did not.
    if outcome.verified {
        entry.unchecked_rejected.clear();
    }
    match &state {
        CarriedState::Refused => entry.refused_streak = entry.refused_streak.saturating_add(1),
        CarriedState::Found { certified, .. } => {
            entry.refused_streak = 0;
            if certified.iter().any(|copy| !entry.found.contains(copy)) {
                entry.exhausted = 0;
            }
            if !certified.is_empty() {
                entry.found = certified.clone();
                // Copies refused for now since start their back-offs over.
                let retried = &entry.retried;
                entry.retry.retain(|id, _| retried.contains(id));
            }
        }
        _ => {}
    }
    entry.at = now;
    entry.state = state;
    entry.named = outcome.named;
    entry.refused_now = outcome.refused_now;
    entry.passed_over = outcome.passed_over;
    let still_carried = outcome.still_carried.cloned().unwrap_or_default();
    remember_all(
        &mut entry.refused,
        &still_carried,
        outcome.refused,
        CARRIED_REFUSED,
    );
    // A copy refused for now again, after it was tried again, waits twice
    // as long; one still waiting keeps its time.
    for id in outcome.retried {
        if !entry.retried.contains(id) {
            let times = entry.retry.get(id).map_or(0, |(_, times)| *times);
            entry.retry.insert(*id, (now, times.saturating_add(1)));
        }
    }
    remember_all(
        &mut entry.retried,
        &still_carried,
        outcome.retried,
        CARRIED_REFUSED,
    );
    if entry.retry.len() > CARRIED_REFUSED {
        let retried = &entry.retried;
        entry.retry.retain(|id, _| retried.contains(id));
    }
    entry.mark_read(outcome.addr, outcome.read);
}

/// One copy a search keeps: the GLOBAL frame carrying it, the copy, its key
/// and whether its check passed.
struct KeptCopy {
    global: u64,
    header: quil_types::proto::global::FrameHeader,
    key: CopyId,
    certified: bool,
}

/// A copy offered for checking: the GLOBAL frame carrying it, its key, the
/// copy, and whether it is another attested form of a copy gathered.
type OfferedCopy = (u64, CopyId, quil_types::proto::global::FrameHeader, bool);

/// The copies of one shard frame's header read from GLOBAL frames: only
/// plausible ones ([`plausible_carried_copy`]) anchored where GLOBAL could
/// take them ([`plausibly_anchored`]; others are dropped, free to filter
/// again), normalised ([`normalize_carried_header`]), one per key
/// ([`carried_copy_key`]) with up to [`CARRIED_ATTESTED_FORMS`] attested
/// forms, none refused or rejected before (`skip`). They are gathered
/// ([`Self::offer`]), a named copy with an attestation checked as soon as
/// it is gathered, then checked ([`Self::check`]) named copies first,
/// across every frame read; at most [`CARRIED_COPIES`] are kept, the best
/// ([`rank_carried_copy`]), ties in the order read. A copy is kept with its
/// attestation only when that attestation passed the check in full, else
/// with that field cleared.
struct CarriedCopies {
    filter: Vec<u8>,
    frame_number: u64,
    named: Option<[u8; 32]>,
    skip: std::collections::HashSet<CopyId>,
    /// Of `skip`, the copies refused for now or rejected: tried again later.
    for_now: std::collections::HashSet<CopyId>,
    /// Copies refused for now before, due again: checked after the others.
    rechecked: std::collections::HashSet<CopyId>,
    /// The copies each GLOBAL frame read carried, by key, plausible ones
    /// GLOBAL could have taken.
    by_frame: std::collections::BTreeMap<u64, Vec<CopyId>>,
    pending: Vec<OfferedCopy>,
    /// The anchors of the legacy copies checked ([`CARRIED_LEGACY_ANCHORS`]).
    legacy_anchors: std::collections::HashSet<u64>,
    /// The longest one check may take ([`CARRIED_CHECK_SLICE`]).
    slice: std::time::Duration,
    kept: Vec<KeptCopy>,
    seen: std::collections::HashSet<CopyId>,
    forms: std::collections::HashMap<CopyId, Vec<CopyId>>,
    named_gathered: usize,
    refused: Vec<CopyId>,
    retried: Vec<CopyId>,
    still_carried: std::collections::HashSet<CopyId>,
    verifies: usize,
    legacy_checks: usize,
    unverified: usize,
    passed_over: usize,
    implausible: usize,
}

impl CarriedCopies {
    fn new(
        filter: &[u8],
        frame_number: u64,
        named: Option<[u8; 32]>,
        skip: std::collections::HashSet<CopyId>,
    ) -> Self {
        Self {
            filter: filter.to_vec(),
            frame_number,
            named,
            skip,
            for_now: Default::default(),
            rechecked: Default::default(),
            by_frame: Default::default(),
            pending: Vec::new(),
            legacy_anchors: Default::default(),
            slice: CARRIED_CHECK_SLICE,
            kept: Vec::new(),
            seen: Default::default(),
            forms: Default::default(),
            named_gathered: 0,
            refused: Vec::new(),
            retried: Vec::new(),
            still_carried: Default::default(),
            verifies: 0,
            legacy_checks: 0,
            unverified: 0,
            passed_over: 0,
            implausible: 0,
        }
    }

    fn is_named(&self, header: &quil_types::proto::global::FrameHeader) -> bool {
        !rank_carried_copy(header, self.named.as_ref(), false).1
    }

    /// Of the copies `skip` passes over, those refused for now or rejected
    /// (`for_now`): a GLOBAL frame carrying one is read again once they are
    /// tried again ([`Self::frame_read`]).
    fn with_for_now(mut self, for_now: std::collections::HashSet<CopyId>) -> Self {
        self.for_now = for_now;
        self
    }

    /// Of the copies not skipped, those refused for now before and due again
    /// ([`CarriedSearch::retry_due`]): checked after copies never checked.
    fn with_rechecked(mut self, rechecked: std::collections::HashSet<CopyId>) -> Self {
        self.rechecked = rechecked;
        self
    }

    /// Gather the copies GLOBAL frame `global` carries: each key once, and
    /// its first [`CARRIED_ATTESTED_FORMS`] attested forms besides. An
    /// attested form refused before is passed over.
    fn offer(&mut self, global: u64, carried: Vec<quil_types::proto::global::FrameHeader>) {
        self.by_frame.entry(global).or_default();
        for mut header in carried {
            if !plausible_carried_copy(&header, &self.filter, self.frame_number) {
                continue;
            }
            if !plausibly_anchored(header.global_frame_number, global) {
                self.implausible += 1;
                continue;
            }
            normalize_carried_header(&mut header);
            let key = carried_copy_key(&header);
            self.by_frame.entry(global).or_default().push(key);
            if self.skip.contains(&key) {
                self.passed_over += 1;
                self.still_carried.insert(key);
                continue;
            }
            if !header.storage_attestation.is_empty() {
                // This attested form refused before, or the attested copy a
                // rebuilt frame failed to replay with
                // ([`ProverTreeSyncer::reject_carried_copy`]).
                let form = attested_form_digest(&header);
                let passed = [form, carried_copy_digest(&header)]
                    .into_iter()
                    .find(|id| self.skip.contains(id));
                if let Some(passed) = passed {
                    self.passed_over += 1;
                    self.still_carried.insert(passed);
                    header.storage_attestation.clear();
                } else {
                    let forms = self.forms.entry(key).or_default();
                    if forms.contains(&form) {
                        continue;
                    }
                    if forms.len() >= CARRIED_ATTESTED_FORMS {
                        header.storage_attestation.clear();
                    } else {
                        forms.push(form);
                    }
                }
            }
            let named = self.is_named(&header);
            if self.seen.insert(key) {
                let room = match named {
                    true => self.named_gathered < CARRIED_VERIFIES,
                    false => self.pending.len() < CARRIED_GATHERED,
                };
                if room {
                    self.named_gathered += usize::from(named);
                    self.pending.push((global, key, header, false));
                } else {
                    self.unverified += 1;
                }
            } else if !header.storage_attestation.is_empty() {
                self.pending.push((global, key, header, true));
            }
        }
    }

    /// How GLOBAL frame `global`, once read and its copies checked, stands
    /// ([`ReadMark`]): `Some(true)`, read for good, when it carries no copy
    /// GLOBAL could have taken, or only copies refused for their output or
    /// structure; `Some(false)`, read until copies are tried again, when it
    /// carries only those and copies refused for now or rejected; `None`,
    /// read again, when it carries a copy kept or not checked. So planted
    /// copies refused cannot hold later searches to the frames carrying
    /// them.
    fn frame_read(&self, global: u64) -> Option<bool> {
        let mut for_good = true;
        for key in self.by_frame.get(&global)? {
            if self.refused.contains(key)
                || (self.skip.contains(key) && !self.for_now.contains(key))
            {
                continue;
            }
            if self.retried.contains(key) || self.for_now.contains(key) {
                for_good = false;
                continue;
            }
            return None;
        }
        Some(for_good)
    }

    /// Check the copies gathered with `verify` (none: kept unchecked), those
    /// `chosen`, named first and each key before its other attested forms,
    /// within [`CARRIED_VERIFIES`], [`CARRIED_LEGACY_CHECKS`] and
    /// `deadline`, until [`Self::done`]; the rest wait for the next search.
    async fn check_where(
        &mut self,
        verify: Option<&CarriedVerifier>,
        deadline: tokio::time::Instant,
        chosen: impl Fn(&Self, &OfferedCopy) -> bool,
    ) {
        let (mut take, keep): (Vec<OfferedCopy>, Vec<OfferedCopy>) =
            std::mem::take(&mut self.pending)
                .into_iter()
                .partition(|copy| chosen(self, copy));
        self.pending = keep;
        let named = self.named;
        // Named copies first; of each, copies never checked before those
        // refused for now and due again, so forgeries delay the genuine copy
        // by one pass over them at most; then ones whose check needs no
        // historical committee (a session certificate) before legacy ones,
        // which may send the node to GLOBAL history.
        let rechecked = std::mem::take(&mut self.rechecked);
        take.sort_by_key(|(_, key, header, form)| {
            (
                rank_carried_copy(header, named.as_ref(), false).1,
                rechecked.contains(key),
                carried_copy_is_legacy(header),
                *form,
            )
        });
        self.rechecked = rechecked;
        let mut take = take.into_iter();
        while let Some(copy) = take.next() {
            let is_named = self.is_named(&copy.2);
            if copy.3
                && !self.kept.iter().any(|kept| {
                    kept.key == copy.1
                        && kept.certified
                        && kept.header.storage_attestation.is_empty()
                })
            {
                continue;
            }
            // No check to run (the engine silent): only copies the frame
            // after it names go to replay unchecked; the others wait for a
            // search that can check them, as forgeries of them are free.
            let Some(verify) = verify else {
                match is_named {
                    true => self.settle(vec![(copy, CopyVerdict::Unavailable)], false),
                    false => self.unverified += 1,
                }
                continue;
            };
            // A certified named copy with its attestation kept: no other is
            // better; a certified named one without: no other copy is.
            if self.done()
                || (!is_named
                    && self
                        .kept
                        .iter()
                        .any(|kept| kept.certified && self.is_named(&kept.header)))
            {
                break;
            }
            let legacy = !is_named && carried_copy_is_legacy(&copy.2);
            // A legacy copy's check may rebuild the committee of its anchor:
            // named ones too, within a few anchors per search.
            let anchor = copy.2.global_frame_number;
            let new_anchor =
                carried_copy_is_legacy(&copy.2) && !self.legacy_anchors.contains(&anchor);
            if self.verifies >= CARRIED_VERIFIES
                || (legacy && self.legacy_checks >= CARRIED_LEGACY_CHECKS)
                || (new_anchor && self.legacy_anchors.len() >= CARRIED_LEGACY_ANCHORS)
            {
                self.unverified += 1;
                continue;
            }
            if new_anchor {
                self.legacy_anchors.insert(anchor);
            }
            // Each check within its slice of the search's time: one copy
            // whose check waits on GLOBAL history cannot use it all.
            let slice = deadline.min(tokio::time::Instant::now() + self.slice);
            let Some(verdict) = check_within(verify, &copy.2, slice).await else {
                self.unverified += 1 + take.len();
                break;
            };
            self.verifies += 1;
            self.legacy_checks += usize::from(legacy);
            self.settle(vec![(copy, verdict)], true);
        }
    }

    /// [`Self::check_where`] of every copy gathered.
    async fn check(&mut self, verify: Option<&CarriedVerifier>, deadline: tokio::time::Instant) {
        self.check_where(verify, deadline, |_, _| true).await
    }

    /// [`Self::check_where`] of the named copies with an attestation: once
    /// one passes, reading on finds nothing better.
    async fn check_named_attested(
        &mut self,
        verify: Option<&CarriedVerifier>,
        deadline: tokio::time::Instant,
    ) {
        if verify.is_none() {
            return;
        }
        self.check_where(verify, deadline, |copies, (_, _, header, _)| {
            copies.is_named(header) && !header.storage_attestation.is_empty()
        })
        .await
    }

    /// Keep the copies checked, by verdict ([`CopyVerdict`]): a refused copy
    /// or attested form is remembered and dropped (one refused for its
    /// certificate or attestation, to be tried again); a copy whose attestation
    /// did not pass in full is kept with that field cleared; one that could
    /// not be checked is kept below the certified, its attestation cleared,
    /// and, when its check ran (`ran`), remembered for now as well, so
    /// the next searches reach other copies before it is checked again.
    fn settle(&mut self, checked: Vec<(OfferedCopy, CopyVerdict)>, ran: bool) {
        let named = self.named;
        for ((global, key, mut header, other_form), verdict) in checked {
            let form = attested_form_digest(&header);
            if other_form {
                match verdict {
                    CopyVerdict::Certified => {
                        if let Some(kept) = self.kept.iter_mut().find(|kept| kept.key == key) {
                            (kept.global, kept.header) = (global, header);
                        }
                    }
                    CopyVerdict::AttestationRefused => self.retried.push(form),
                    _ => {}
                }
                continue;
            }
            let certified = match verdict {
                CopyVerdict::Refused => {
                    self.refused.push(key);
                    continue;
                }
                CopyVerdict::CertificateRefused => {
                    self.retried.push(key);
                    continue;
                }
                CopyVerdict::Certified => true,
                CopyVerdict::AttestationRefused => {
                    self.retried.push(form);
                    header.storage_attestation.clear();
                    true
                }
                CopyVerdict::AttestationUnavailable => {
                    header.storage_attestation.clear();
                    true
                }
                CopyVerdict::Unavailable => {
                    if ran {
                        self.retried.push(key);
                    }
                    header.storage_attestation.clear();
                    false
                }
            };
            self.kept.push(KeptCopy {
                global,
                header,
                key,
                certified,
            });
        }
        self.kept
            .sort_by_key(|kept| rank_carried_copy(&kept.header, named.as_ref(), kept.certified));
        self.kept.truncate(CARRIED_COPIES);
    }

    /// Whether a certified copy whose output the frame after it names, with
    /// the attestation, is kept: the best a search can find.
    fn done(&self) -> bool {
        self.kept.iter().any(|kept| {
            rank_carried_copy(&kept.header, self.named.as_ref(), kept.certified)
                == (false, false, false)
        })
    }

    /// [`Self::offer`], the early check of a named attested copy, then
    /// [`Self::check`] within a minute; whether the search is [`Self::done`].
    #[cfg(test)]
    async fn take(
        &mut self,
        global: u64,
        carried: Vec<quil_types::proto::global::FrameHeader>,
        verify: Option<&CarriedVerifier>,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        self.offer(global, carried);
        self.check_named_attested(verify, deadline).await;
        self.check(verify, deadline).await;
        self.done()
    }

    /// The copies kept, best first, and the digests of the certified ones.
    fn best(
        &self,
    ) -> (
        Vec<(u64, quil_types::proto::global::FrameHeader)>,
        Vec<CopyId>,
    ) {
        let copies = self
            .kept
            .iter()
            .map(|kept| (kept.global, kept.header.clone()))
            .collect();
        let certified = self
            .kept
            .iter()
            .filter(|kept| kept.certified)
            .map(|kept| carried_copy_digest(&kept.header))
            .collect();
        (copies, certified)
    }
}

/// `copy` checked by `verify` within what is left until `deadline`: `None`
/// once it has passed, and unavailable when the check runs past it (a
/// committee it prepares is still rebuilt, in its own task, for the next
/// search).
async fn check_within(
    verify: &CarriedVerifier,
    copy: &quil_types::proto::global::FrameHeader,
    deadline: tokio::time::Instant,
) -> Option<CopyVerdict> {
    let left = deadline
        .checked_duration_since(tokio::time::Instant::now())
        .filter(|left| !left.is_zero())?;
    Some(
        tokio::time::timeout(left, verify(copy.clone()))
            .await
            .unwrap_or(CopyVerdict::Unavailable),
    )
}

/// The GLOBAL frames of `globals` a search reads, in their order: those at
/// or below the archive's GLOBAL head `head` (the others carry nothing yet)
/// that no search through this archive passes over (`read_before`,
/// [`ReadMark`]); a search
/// reads the first [`CARRIED_HEADER_WINDOW`] of them, the next one on.
fn unread_globals(
    globals: &[u64],
    read_before: &std::collections::BTreeSet<u64>,
    head: u64,
) -> Vec<u64> {
    globals
        .iter()
        .copied()
        .filter(|global| *global <= head && !read_before.contains(global))
        .collect()
}

/// Whether a search was cut short: it failed or timed out, left frames
/// unread or unanswered, or copies unchecked.
fn search_incomplete(failed: bool, unread: usize, unanswered: u64, unverified: usize) -> bool {
    failed || unread > 0 || unanswered > 0 || unverified > 0
}

/// What a search reached: the copies it kept (only uncertified ones while
/// it was cut short: partly, [`CarriedState::Partial`]), else, cut short, a
/// failure ([`search_incomplete`]), else every copy refused (`refused` when
/// checked or passed over as refused before), else none carried.
fn search_state(
    best: &[(u64, quil_types::proto::global::FrameHeader)],
    certified: &[CopyId],
    incomplete: bool,
    refused: usize,
) -> CarriedState {
    match (best.is_empty(), incomplete, refused) {
        (false, true, _) if certified.is_empty() => CarriedState::Partial {
            copies: best.to_vec(),
        },
        (false, _, _) => CarriedState::Found {
            copies: best.to_vec(),
            certified: certified.to_vec(),
        },
        (true, true, _) => CarriedState::Failed,
        (true, false, 0) => CarriedState::Missed,
        (true, false, _) => CarriedState::Refused,
    }
}

/// `globals` as ranges ("9140..=9171, 9182"), for the log.
fn ranges(globals: &[u64]) -> String {
    let mut sorted = globals.to_vec();
    sorted.sort_unstable();
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for global in sorted {
        match ranges.last_mut() {
            Some((_, end)) if *end + 1 == global => *end = global,
            _ => ranges.push((global, global)),
        }
    }
    ranges
        .iter()
        .map(|&(start, end)| match start == end {
            true => start.to_string(),
            false => format!("{start}..={end}"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Every header of `filter`'s frame `frame_number` among `global`'s requests.
fn carried_headers(
    global: &quil_types::proto::global::GlobalFrame,
    filter: &[u8],
    frame_number: u64,
) -> Vec<quil_types::proto::global::FrameHeader> {
    use quil_types::proto::global::message_request::Request;
    global
        .requests
        .iter()
        .flat_map(|bundle| bundle.requests.iter())
        .filter_map(|request| match request.request.as_ref() {
            Some(Request::Shard(header))
                if header.address == filter && header.frame_number == frame_number =>
            {
                Some(header.clone())
            }
            _ => None,
        })
        .collect()
}

impl ProdProverTreeSyncer {
    /// Predecessor outgoing history from this syncer's archive, as the engine
    /// source for a cluster worker (whose archives are discovered through its
    /// master). Unverified: the engine checks it against the sealed root.
    pub fn outgoing_history_source(
        self: &Arc<Self>,
    ) -> quil_engine::app_handoff::OutgoingHistorySource {
        let syncer = self.clone();
        Arc::new(move |filter, from, through| {
            let syncer = syncer.clone();
            Box::pin(async move {
                // Resolving discovers the master's archives on first use.
                let addr = syncer.resolve_addr().await?;
                let endpoints = match syncer.archive_pool.as_ref() {
                    Some(pool) => pool.get_all().await,
                    None => vec![addr],
                };
                crate::storage_history::outgoing_history_from_endpoints(
                    &endpoints,
                    &syncer.falcon_signing_key,
                    filter,
                    from,
                    through,
                )
                .await
            })
        })
    }

    /// Resolve a verified archive. Separate workers must discover one through
    /// their master first: the regular master's tree is not an app-state source.
    async fn resolve_addr(&self) -> Result<String> {
        let addr = self.pick_addr().await?;
        quil_engine::worker_execution::recovery_source(&addr);
        Ok(addr)
    }

    /// The next archive in rotation, passing over one that failed a shard
    /// read recently while another is known.
    async fn pick_addr(&self) -> Result<String> {
        if let Some(pool) = self.archive_pool.as_ref() {
            let mut failed = None;
            for _ in 0..pool.len().await.max(1) {
                let Some(ep) = pool.next().await else { break };
                if !recently_failed(&ep) {
                    return Ok(ep);
                }
                failed.get_or_insert(ep);
            }
            if let Some(ep) = failed {
                return Ok(ep);
            }
            if self.discover_archives_from_master {
                let endpoints = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    let mut client = ArchiveClient::connect_own_master(
                        &self.master_stream_addr,
                        &self.falcon_signing_key,
                    )
                    .await?;
                    client.get_archive_endpoints().await
                })
                .await
                .map_err(|_| QuilError::ExecutionUnavailable("archive discovery timed out".into()))?
                .map_err(|e| QuilError::ExecutionUnavailable(format!("archive discovery: {e}")))?;
                for endpoint in endpoints {
                    pool.add(endpoint).await;
                }
                if let Some(ep) = pool.next().await {
                    return Ok(ep);
                }
            }
            // The GLOBAL poller passes over every archive whose frame poll
            // failed in the last minute; a shard read can still succeed
            // there. Prefer one no shard read failed at recently.
            let mut failed = None;
            for _ in 0..pool.len().await.max(1) {
                let Some(ep) = pool.any_known().await else {
                    break;
                };
                if !recently_failed(&ep) {
                    return Ok(ep);
                }
                failed.get_or_insert(ep);
            }
            if let Some(ep) = failed {
                return Ok(ep);
            }
            if self.discover_archives_from_master {
                return Err(QuilError::ExecutionUnavailable(
                    "master has not discovered an archive yet".into(),
                ));
            }
        }
        // An empty address is no source: dialing it only fails as an invalid URI.
        if self.master_stream_addr.is_empty() {
            return Err(QuilError::ExecutionUnavailable(
                "no archive known yet".into(),
            ));
        }
        Ok(self.master_stream_addr.clone())
    }

    /// Resolve each committed phase at its retained version, then install its
    /// authenticated leaves and data. The peer may have advanced since the
    /// header was finalized; live-head equality is not required.
    async fn sync_single_shard(
        &self,
        addr: &str,
        shard_id: Vec<u8>,
        expected_roots: &[Vec<u8>],
    ) -> Result<bool> {
        let expected =
            std::array::from_fn(|phase| expected_roots.get(phase).map_or(&[][..], Vec::as_slice));
        Ok(crate::forest_sync::sync_shard_phases_verified(
            addr,
            &self.falcon_signing_key,
            self.crdt.clone(),
            &shard_id,
            expected,
        )
        .await?
        .is_some())
    }

    /// Sync a SPLIT app (QUIL: 64 sub-shards). `expected_roots` is the header's
    /// `state_roots`: index `p` is the AGGREGATE root of phase `p`
    /// across the sub-shards. For EVERY phase we verify the fetched sub-shard set
    /// aggregates to `expected_roots[p]` — one binding that authenticates all 64
    /// sub-shard roots at once — BEFORE diffing + applying. Absent sub-shards
    /// contribute the zero root, so the aggregate matches `commit_inner`. Any
    /// phase whose aggregate or post-apply root diverges aborts the sync.
    /// Previously only phase 0 was bound; phases 1–3 could be served divergent.
    async fn sync_split_shard(
        &self,
        addr: &str,
        app: [u8; 32],
        expected_roots: &[Vec<u8>],
    ) -> Result<bool> {
        let mut client = ArchiveClient::connect_mtls(addr, &self.falcon_signing_key)
            .await
            .map_err(|e| QuilError::Internal(format!("archive connect: {e}")))?;
        let handle = tokio::runtime::Handle::current();
        let sub_shards = self.crdt.app_sub_shards(&app);
        for phase in 0u32..4 {
            let expected = expected_roots
                .get(phase as usize)
                .cloned()
                .unwrap_or_default();
            phase_anchor(&expected)?;
            if is_empty_phase_root(&expected) {
                for (id, _) in &sub_shards {
                    if !is_empty_phase_root(
                        &self.crdt.current_forest_phase_root(id, phase as usize)?,
                    ) {
                        warn!(phase, shard = %hex::encode(id), "committed empty split phase still has local data");
                        return Ok(false);
                    }
                }
                continue;
            }
            // Fetch every sub-shard's head for this phase.
            let mut heads: Vec<(Vec<u8>, Vec<bool>, Option<(u64, [u8; 32])>)> =
                Vec::with_capacity(sub_shards.len());
            for (shard_id, bits) in &sub_shards {
                let h = quil_rpc::forest_sync_reader::forest_head(&client, shard_id.clone(), phase)
                    .await
                    .map_err(|e| QuilError::Internal(format!("get_forest_head: {e}")))?;
                let h32 = h
                    .map(|(v, r)| {
                        let root = phase_anchor(&r)?.ok_or_else(|| {
                            QuilError::InvalidArgument("peer forest head has no root".into())
                        })?;
                        Ok::<_, QuilError>((v, root))
                    })
                    .transpose()?;
                if h32.is_none()
                    && !is_empty_phase_root(
                        &self
                            .crdt
                            .current_forest_phase_root(shard_id, phase as usize)?,
                    )
                {
                    warn!(phase, shard = %hex::encode(shard_id), "absent split phase still has local data");
                    return Ok(false);
                }
                heads.push((shard_id.clone(), bits.clone(), h32));
            }
            // Anchor: the aggregate of all sub-shard roots for THIS
            // phase must equal the header-committed aggregate, authenticating
            // every sub-shard root before we pull it. Empty ⇒ trust (bootstrap).
            if !expected.is_empty() {
                let sub_roots: Vec<(Vec<bool>, [u8; 32])> = heads
                    .iter()
                    .map(|(_, bits, h)| (bits.clone(), h.map(|(_, r)| r).unwrap_or([0u8; 32])))
                    .collect();
                if !self.crdt.app_root_matches(&sub_roots, &expected) {
                    warn!(phase, app = %hex::encode(app), "QUIL sub-shard roots do not aggregate to the header root — not syncing");
                    return Ok(false);
                }
            }
            // Diff + apply each present sub-shard (identical ones transfer nothing).
            for (shard_id, _, head) in &heads {
                let Some((v_s, root_s)) = *head else { continue };
                let got = crate::forest_sync::sync_one_phase(
                    &mut client,
                    &handle,
                    &self.crdt,
                    shard_id,
                    phase,
                    v_s,
                    Some(root_s),
                )
                .await?;
                if got != root_s {
                    warn!(phase, shard = %hex::encode(shard_id), "QUIL sub-shard post-sync root mismatch — not syncing");
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Pull the covered subtree against the commitment in a unified shard
    /// header. The archive can hold other shards at unrelated heights; its
    /// whole-app root is neither the header commitment nor a required anchor.
    async fn sync_shard_subtree(
        &self,
        addr: &str,
        filter: &[u8],
        expected_roots: &[Vec<u8>],
    ) -> Result<bool> {
        let bits = self.crdt.canonical_bits_for_filter(filter).ok_or_else(|| {
            QuilError::InvalidArgument("invalid shard filter for subtree sync".into())
        })?;
        let app = &filter[..32];
        let mut client = ArchiveClient::connect_mtls(addr, &self.falcon_signing_key)
            .await
            .map_err(|e| QuilError::Internal(format!("archive connect: {e}")))?;
        let handle = tokio::runtime::Handle::current();
        for phase in 0u32..4 {
            let pinned = phase_anchor(
                expected_roots
                    .get(phase as usize)
                    .map_or(&[][..], Vec::as_slice),
            )?;
            if pinned
                .as_ref()
                .is_some_and(|root| is_empty_phase_root(root))
            {
                let (set, phase_name) = crate::forest_sync::phase_strs(phase);
                let local = self
                    .crdt
                    .sub_shard_commitment_for_filter(set, phase_name, filter);
                if !is_empty_phase_root(&local) {
                    warn!(phase, filter = %hex::encode(filter), "committed empty shard phase has stale or unreadable local state");
                    return Ok(false);
                }
                continue;
            }
            let source_version = if let Some(root) = pinned {
                match quil_rpc::forest_sync_reader::resolve_forest_root(
                    &client,
                    filter.to_vec(),
                    phase,
                    root.to_vec(),
                )
                .await
                {
                    Ok(Some((version, _))) => version,
                    Ok(None) => {
                        warn!(phase, peer = %addr, filter = %hex::encode(filter),
                            root = %hex::encode(root), "peer does not retain the committed shard subtree");
                        return Ok(false);
                    }
                    Err(e) => {
                        return Err(QuilError::Internal(format!("resolve shard subtree: {e}")))
                    }
                }
            } else {
                // No header exists for a brand-new child shard. Bootstrap must
                // actually pull its inherited subtree; no anchor is not empty state.
                match quil_rpc::forest_sync_reader::forest_head(&client, app.to_vec(), phase)
                    .await
                    .map_err(|e| QuilError::Internal(format!("get_forest_head: {e}")))?
                {
                    Some((version, _)) => version,
                    None => {
                        let (set, phase_name) = crate::forest_sync::phase_strs(phase);
                        let local = self
                            .crdt
                            .sub_shard_commitment_for_filter(set, phase_name, filter);
                        if !is_empty_phase_root(&local) {
                            return Ok(false);
                        }
                        continue;
                    }
                }
            };
            let got = crate::forest_sync::sync_subtree_one_phase(
                &mut client,
                &handle,
                &self.crdt,
                app,
                filter,
                phase,
                source_version,
                bits.clone(),
                pinned,
            )
            .await?;
            if pinned.is_some_and(|expected| got != expected) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// True when every phase's LOCAL root already equals the header anchor's
    /// — the node is caught up and a sync would pull nothing, so the whole cycle
    /// (gRPC connect + per-phase head round-trips + diff) can be skipped. Requires
    /// a FULL 4-phase anchor with no empty entry; a bootstrap / partial anchor
    /// returns false so the sync proceeds and trusts the peer. `compute_shard_root`
    /// is a plain forest read and aggregates sub-shards, so this works for both a
    /// single-shard app and a QUIL split.
    fn caught_up_to_anchor(&self, filter: &[u8], expected_roots: &[Vec<u8>]) -> bool {
        if expected_roots.len() != 4 || expected_roots.iter().any(|r| r.len() != 32) {
            return false;
        }
        let Some(sk) = crate::forest_sync::app_shard_key(filter) else {
            return false;
        };
        let scopes = if self.crdt.unified_tree() {
            let Some(bits) = self.crdt.canonical_bits_for_filter(filter) else {
                return false;
            };
            vec![(sk.l2.to_vec(), bits)]
        } else {
            self.crdt
                .app_sub_shards(&sk.l2)
                .into_iter()
                .map(|(id, _)| (id, Vec::new()))
                .collect()
        };
        for phase in 0u32..4 {
            let (s, p) = crate::forest_sync::phase_strs(phase);
            let local = if self.crdt.unified_tree() {
                self.crdt.sub_shard_commitment_for_filter(s, p, filter)
            } else {
                self.crdt.compute_shard_root(s, p, &sk)
            };
            if local.is_empty() {
                // Unreadable/malformed state is not an authenticated empty tree.
                return false;
            }
            if local.as_slice() != expected_roots[phase as usize].as_slice() {
                return false;
            }
            if !is_empty_phase_root(&local)
                && scopes.iter().any(|(id, bits)| {
                    !self
                        .crdt
                        .sync_data_ready(id, phase as usize, bits)
                        .unwrap_or(false)
                })
            {
                // Old sync code could reach this root before its data arrived.
                // Repair/audit it once before enabling the root-only shortcut.
                return false;
            }
        }
        true
    }
}

#[async_trait]
impl ProverTreeSyncer for ProdProverTreeSyncer {
    async fn sync_prover_tree(&self, expected_roots: &[Vec<u8>]) -> Result<bool> {
        // The global prover shard is a single-shard app: L2 = [0xff; 32]. The
        // global header commits ALL FOUR prover-shard phase roots (a flag-day
        // change): `expected_roots` = [prover_tree_commitment (phase 0),
        // prover_tree_aux_roots (phases 1,2,3)], so every phase is authenticated.
        // Skip the whole sync when already caught up to the committed anchor
        // — the periodic cadence would otherwise re-diff the entire prover tree
        // every tick on a node that keeps it current via its own materializer.
        if self.caught_up_to_anchor(&[0xffu8; 32], expected_roots) {
            return Ok(true);
        }
        let addr = self.resolve_addr().await?;
        info!(archive = %addr, "syncing global prover tree from archive (forest diff)");
        let synced = self
            .sync_single_shard(&addr, vec![0xffu8; 32], expected_roots)
            .await;
        // As for a shard tree: the next attempt starts at another archive.
        if !matches!(synced, Ok(true))
            && !synced
                .as_ref()
                .is_err_and(quil_engine::worker_execution::turn_spent)
        {
            source_failed(&addr);
        }
        synced
    }

    async fn sync_shard_tree(&self, filter: &[u8], expected_roots: &[Vec<u8>]) -> Result<bool> {
        // Skip when already caught up (works for single-shard and QUIL split).
        if self.caught_up_to_anchor(filter, expected_roots) {
            return Ok(true);
        }
        let addr = self.resolve_addr().await?;
        let synced = self
            .sync_shard_tree_from(&addr, filter, expected_roots)
            .await;
        // A turn handed back at its hold limit is no failure of the archive.
        if !matches!(synced, Ok(true))
            && !synced
                .as_ref()
                .is_err_and(quil_engine::worker_execution::turn_spent)
        {
            // The next attempt starts at another archive when one is known;
            // what this one installed stays.
            source_failed(&addr);
        }
        synced
    }

    async fn get_app_shard_frame(
        &self,
        filter: &[u8],
        frame_number: u64,
    ) -> Result<Option<quil_types::proto::global::AppShardFrame>> {
        let addr = self.resolve_addr().await?;
        let key = (std::thread::current().id(), addr);
        let mut read = FrameRead {
            key: &key,
            finished: false,
        };
        let fetched = async {
            let cached =
                frame_clients().get(&key, &self.falcon_signing_key, std::time::Instant::now());
            let mut client = match cached {
                Some(client) => client,
                None => {
                    let client = ArchiveClient::connect_mtls(&key.1, &self.falcon_signing_key)
                        .await
                        .map_err(|e| {
                            (QuilError::Internal(format!("archive connect: {e}")), true)
                        })?;
                    let id = frame_clients().insert(
                        key.clone(),
                        &self.falcon_signing_key,
                        client.clone(),
                        std::time::Instant::now(),
                    );
                    tokio::spawn(reap_frame_client(&FRAME_CLIENTS, key.clone(), id));
                    client
                }
            };
            client
                .get_app_shard_frame(filter.to_vec(), frame_number)
                .await
                .map_err(|e| {
                    (
                        QuilError::Internal(format!("get app-shard frame: {e}")),
                        read_breaks_connection(&e),
                    )
                })
        }
        .await;
        read.finished = true;
        fetched.map_err(|(error, broken)| {
            if broken {
                frame_clients().evict(&key);
            }
            source_failed(&key.1);
            error
        })
    }

    /// Reads the GLOBAL frames `globals` from one archive, whole, in order,
    /// skipping those earlier searches read from it whose copies were all
    /// refused or passed over, or that carried none ([`ReadMark`]), at most
    /// [`CARRIED_HEADER_WINDOW`] per search, each within
    /// [`CARRIED_READ_TIMEOUT`] and all within [`CARRIED_READ_BUDGET`]; a
    /// named copy with an attestation is checked as soon as it is gathered,
    /// and reading stops once one passes in full. Then checks the copies
    /// gathered by `verify`, named ones first, within
    /// [`CARRIED_CHECK_BUDGET`] ([`CarriedCopies`]). Frames above the
    /// archive's GLOBAL head carry nothing yet and are not read. A read that
    /// breaks the connection or times out fails the archive as a source and
    /// ends the reading; what was read is still checked. A search that ends
    /// with nothing found and frames unread or unanswered, or copies
    /// unchecked, is incomplete: it backs off, and the next one reads on
    /// where it stopped. Each search logs the frames it read, its bytes,
    /// checks and time; a repeated one is answered from
    /// [`CARRIED_SEARCHED`], unless `named` is known only now.
    async fn carried_shard_headers(
        &self,
        filter: &[u8],
        frame_number: u64,
        globals: &[u64],
        named: Option<[u8; 32]>,
        verify: Option<&CarriedVerifier>,
    ) -> Result<CarriedHeaders> {
        use prost::Message;
        if let Some(answer) = self.cached_carried_shard_headers(filter, frame_number, named) {
            return answer;
        }
        let key = (filter.to_vec(), frame_number);
        let (skip, for_now, rechecked, rejected) = {
            let searches = carried_searched();
            let kept = searches.get(&key);
            let rejected: Vec<CopyId> = kept
                .map(|search| search.rejected.iter().copied().collect())
                .unwrap_or_default();
            let for_now: std::collections::HashSet<CopyId> = kept
                .map(|search| {
                    search
                        .retried
                        .iter()
                        .chain(&search.rejected)
                        .copied()
                        .collect()
                })
                .unwrap_or_default();
            let skip = kept
                .map(|search| {
                    search
                        .refused
                        .iter()
                        .copied()
                        .collect::<std::collections::HashSet<CopyId>>()
                })
                .unwrap_or_default()
                .union(&for_now)
                .copied()
                .collect();
            let rechecked: std::collections::HashSet<CopyId> = kept
                .map(|search| {
                    search
                        .retry
                        .keys()
                        .filter(|id| !search.retried.contains(id))
                        .copied()
                        .collect()
                })
                .unwrap_or_default();
            (skip, for_now, rechecked, rejected)
        };
        let addr = self.resolve_addr().await?;
        let read_before = carried_searched()
            .get(&key)
            .map(|search| search.read_by(&addr))
            .unwrap_or_default();
        let started = std::time::Instant::now();
        let (read_until, check_until) = (
            started + CARRIED_READ_BUDGET,
            tokio::time::Instant::now() + CARRIED_CHECK_BUDGET,
        );
        let (mut bytes, mut unanswered, mut head, mut unread) = (0usize, 0u64, None, 0usize);
        let mut read_globals = Vec::new();
        let mut copies = CarriedCopies::new(filter, frame_number, named, skip)
            .with_for_now(for_now)
            .with_rechecked(rechecked);
        // A read that failed: the error, and whether it fails the archive.
        let mut read_failure: Option<(QuilError, bool)> = None;
        let search = async {
            let reads = async {
                let mut client = ArchiveClient::connect_mtls(&addr, &self.falcon_signing_key)
                    .await
                    .map_err(|e| (QuilError::Internal(format!("archive connect: {e}")), true))?;
                let top = client
                    .get_global_head(u64::MAX)
                    .await
                    .map_err(|e| {
                        (
                            QuilError::Internal(format!("get GLOBAL head: {e}")),
                            read_breaks_connection(&e),
                        )
                    })?
                    .header
                    .map_or(0, |header| header.frame_number);
                head = Some(top);
                let readable = unread_globals(globals, &read_before, top);
                for (index, &global) in readable.iter().enumerate() {
                    let left = read_until
                        .checked_duration_since(std::time::Instant::now())
                        .unwrap_or_default();
                    if left.is_zero() || index as u64 >= CARRIED_HEADER_WINDOW {
                        unread = readable.len() - index;
                        break;
                    }
                    let frame = match tokio::time::timeout(
                        left.min(CARRIED_READ_TIMEOUT),
                        client.get_global_frame(global),
                    )
                    .await
                    {
                        Ok(Ok(frame)) => frame,
                        Ok(Err(e)) if read_breaks_connection(&e) => {
                            unread = readable.len() - index;
                            return Err((
                                QuilError::Internal(format!("get GLOBAL frame {global}: {e}")),
                                true,
                            ));
                        }
                        Ok(Err(_)) => {
                            unanswered += 1;
                            continue;
                        }
                        // The read budget ran out mid-read: the archive is not at fault.
                        Err(_) if left <= CARRIED_READ_TIMEOUT => {
                            unread = readable.len() - index;
                            break;
                        }
                        Err(_) => {
                            unread = readable.len() - index;
                            return Err((
                                QuilError::ExecutionUnavailable(format!(
                                    "reading GLOBAL frame {global} timed out after {}s",
                                    CARRIED_READ_TIMEOUT.as_secs()
                                )),
                                true,
                            ));
                        }
                    };
                    read_globals.push(global);
                    bytes += frame.encoded_len();
                    copies.offer(global, carried_headers(&frame, filter, frame_number));
                    copies.check_named_attested(verify, check_until).await;
                    if copies.done() {
                        unread = readable.len() - index - 1;
                        break;
                    }
                }
                Ok(())
            };
            if let Err(failure) = reads.await {
                read_failure = Some(failure);
            }
            copies.check(verify, check_until).await;
        };
        let timed_out = tokio::time::timeout(CARRIED_SEARCH_TIMEOUT, search)
            .await
            .is_err();
        if let Some((_, true)) = read_failure {
            source_failed(&addr);
        }
        let (filter_hex, elapsed_ms) = (hex::encode(filter), started.elapsed().as_millis() as u64);
        let (from, through) = (globals.iter().min().copied(), globals.iter().max().copied());
        let (refused, retried, unverified, passed_over) = (
            copies.refused.len(),
            copies.retried.len(),
            copies.unverified,
            copies.passed_over,
        );
        let refused_now = refused + retried;
        let (best, certified) = copies.best();
        let failure = read_failure
            .as_ref()
            .map(|(error, _)| error.to_string())
            .or_else(|| {
                timed_out.then(|| format!("timed out after {}s", CARRIED_SEARCH_TIMEOUT.as_secs()))
            });
        let read_ranges = ranges(&read_globals);
        info!(%addr, filter = %filter_hex, frame = frame_number, ?from, ?through, ?head, global_frames_read = read_globals.len(),
            read = %read_ranges.as_str(), read_before = read_before.len(), unread, unanswered, bytes, elapsed_ms,
            copies = best.len(), certified = certified.len(), refused, refused_for_now = retried, unverified, passed_over,
            implausible = copies.implausible, named = named.is_some(), ?failure,
            carried_by = ?best.iter().map(|(global, _)| *global).collect::<Vec<_>>(),
            attested = best.iter().any(|(_, header)| !header.storage_attestation.is_empty()),
            "searched GLOBAL frames for the header of a shard frame no archive serves");
        // Nothing found while frames went unread or unanswered, or copies
        // unchecked: back off, keeping what was read and refused, and read on
        // next time rather than calling it missing.
        // Copies kept unchecked (no check to run) make no find: they go to
        // replay while the next search, after a short back-off, checks.
        let incomplete = search_incomplete(failure.is_some(), unread, unanswered, unverified)
            || (verify.is_none() && !best.is_empty());
        let state = search_state(&best, &certified, incomplete, refused_now + passed_over);
        let failed = state == CarriedState::Failed;
        // The frames read whose copies were all refused or passed over are
        // passed over by the next searches through this archive.
        let read: Vec<(u64, bool)> = read_globals
            .iter()
            .filter_map(|&global| copies.frame_read(global).map(|for_good| (global, for_good)))
            .collect();
        let progress = !read.is_empty() || copies.verifies > 0;
        let (refused_ids, retried_ids) = (copies.refused.clone(), copies.retried.clone());
        let partial = matches!(state, CarriedState::Partial { .. });
        keep_carried_search(
            key.clone(),
            SearchOutcome {
                state: Some(state),
                named,
                refused: &refused_ids,
                retried: &retried_ids,
                still_carried: Some(&copies.still_carried),
                refused_now,
                passed_over,
                addr: &addr,
                read: &read,
                progress,
                verified: verify.is_some(),
            },
        );
        // The info line says only certified=0: say once in a while that the
        // copies handed to replay are unchecked while others wait.
        if partial
            && carried_searched()
                .get_mut(&key)
                .is_some_and(|search| search.warn_due())
        {
            warn!(filter = %hex::encode(filter), frame = frame_number, copies = best.len(), unverified, unread, unanswered,
                refused_for_now = retried,
                "a search of GLOBAL frames for the header of a shard frame no archive serves kept only copies whose \
                 check could not end, while frames went unread or copies unchecked; replay tries the copies kept, \
                 and the rest are read and checked after a short back-off; this node waits on a GLOBAL frame or \
                 historical committee it lacks, or forged copies are being passed over");
        }
        match (failed, read_failure) {
            (true, Some((error, _))) => Err(error),
            (true, None) => Err(QuilError::ExecutionUnavailable(format!(
                "no copy of its header was found in GLOBAL frames {} so far ({unread} unread, {unanswered} unanswered, \
                 {unverified} copies unchecked); they are read on next time",
                match read_ranges.is_empty() { true => "none".to_string(), false => read_ranges } ))),
            _ => Ok(CarriedHeaders { copies: best, certified, rejected, refused: refused_now, passed_over }),
        }
    }

    fn cached_carried_shard_headers(
        &self,
        filter: &[u8],
        frame_number: u64,
        named: Option<[u8; 32]>,
    ) -> Option<Result<CarriedHeaders>> {
        let key = (filter.to_vec(), frame_number);
        let mut searches = carried_searched();
        let search = searches.get_mut(&key)?;
        search.resume();
        if !search.answers(named) {
            return None;
        }
        let rejected: Vec<CopyId> = search.rejected.iter().copied().collect();
        let retry =
            |interval: std::time::Duration| interval.saturating_sub(search.at.elapsed()).as_secs();
        let (refused, passed_over) = (search.refused_now, search.passed_over);
        Some(match &search.state {
            CarriedState::Found { copies, certified } => {
                Ok(CarriedHeaders { copies: copies.clone(), certified: certified.clone(), rejected, refused, passed_over })
            }
            CarriedState::Partial { copies } => {
                Ok(CarriedHeaders { copies: copies.clone(), certified: Vec::new(), rejected, refused, passed_over })
            }
            CarriedState::Missed => Ok(CarriedHeaders { rejected, ..Default::default() }),
            CarriedState::Rejected => Err(QuilError::ExecutionUnavailable(format!(
                "every copy of its carried header failed to replay; GLOBAL frames are read again in {}s",
                retry(search.reject_backoff())
            ))),
            CarriedState::Refused => Err(QuilError::ExecutionUnavailable(format!(
                "every copy of its carried header was refused ({refused} when checked, {passed_over} passed over); \
                 GLOBAL frames are read again in {}s",
                retry(search.reject_backoff())
            ))),
            CarriedState::Failed => Err(QuilError::ExecutionUnavailable(format!(
                "the last search of GLOBAL frames for its header was cut short with nothing found; the rest are \
                 read, and GLOBAL frames carrying copies read again, in {}s",
                retry(search.fail_backoff())
            ))),
            CarriedState::Unsearched => return None,
        })
    }

    fn reject_carried_copy(&self, filter: &[u8], frame_number: u64, copy: CopyId) {
        let key = (filter.to_vec(), frame_number);
        if !carried_searched().contains_key(&key) {
            // Its search was dropped meanwhile: the rejection is kept anyway.
            keep_carried_search(key.clone(), SearchOutcome::default());
        }
        let (rejected, warn) = {
            let mut searches = carried_searched();
            let Some(search) = searches.get_mut(&key) else {
                return;
            };
            if !remember(&mut search.rejected, copy, CARRIED_REJECTED) {
                return;
            }
            let certified = matches!(&search.state, CarriedState::Found { certified, .. } if certified.contains(&copy));
            if !certified {
                search.unchecked_rejected.insert(copy);
            }
            (search.rejected.len(), search.warn_due())
        };
        if warn {
            warn!(filter = %hex::encode(filter), frame = frame_number, rejected,
                "a shard frame rebuilt from a copy of the header GLOBAL carried failed to replay (its reason is \
                 logged with the replay); the next copy is tried, and further copies are not warned about for \
                 ten minutes");
        }
    }

    fn reject_carried_shard_headers(&self, filter: &[u8], frame_number: u64) {
        let (rejected, retry, warn) = {
            let mut searches = carried_searched();
            let Some(search) = searches.get_mut(&(filter.to_vec(), frame_number)) else {
                return;
            };
            search.at = std::time::Instant::now();
            search.state = CarriedState::Rejected;
            search.exhausted = search.exhausted.saturating_add(1);
            (
                search.rejected.len(),
                search.reject_backoff(),
                search.warn_due(),
            )
        };
        if warn {
            warn!(filter = %hex::encode(filter), frame = frame_number, rejected, retry_secs = retry.as_secs(),
                "every copy of the header GLOBAL carried for a shard frame failed to replay (the reasons are logged \
                 with the replays); the GLOBAL frames are read again, and those copies tried again, after the \
                 back-off, which doubles each time they all fail");
        }
    }
}

/// A storage snapshot source synced into a database of its own, removed when
/// the capture reading it is done. Fields drop in order: the store's handles
/// before its directory.
struct ScratchSnapshot {
    _crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    _db: Arc<quil_store::RocksDb>,
    _dir: ScratchDir,
}

struct ScratchDir(std::path::PathBuf);

/// Where storage snapshot sources are synced for the store at `db_path`: a
/// sibling of it, never inside a database's own directory.
/// Where a node keeps the hash storage proof labels it computes ahead
/// (`quil_engine::storage_labels`): one directory beside its workers' stores
/// (`db_path` is one of them), whichever worker installs it and across
/// restarts, so labels a node keeps are always found and evicted.
pub fn storage_labels_dir(db_path: &std::path::Path) -> std::path::PathBuf {
    db_path.parent().unwrap_or(db_path).join("storage-labels")
}

pub fn snapshot_scratch_dir(db_path: &std::path::Path) -> std::path::PathBuf {
    let name = db_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "store".into());
    db_path.with_file_name(format!("{name}-storage-snapshots"))
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            warn!(dir = %self.0.display(), %error, "could not remove a storage snapshot scratch store");
        }
    }
}

impl ProdProverTreeSyncer {
    /// Hash storage proofs: this node's way to read a storage snapshot source
    /// it does not hold (`quil_engine::storage_snapshot::install_remote`) —
    /// a joiner's, a split or merge child's, a state-jumper's. The source's
    /// subtree is synced pinned to its certified roots, from an archive that
    /// retains them, into a scratch store under `scratch`.
    pub fn storage_snapshot_remote(
        self: &Arc<Self>,
        scratch: std::path::PathBuf,
        runtime: tokio::runtime::Handle,
    ) -> Arc<quil_engine::storage_snapshot::RemoteSnapshot> {
        // Stores left by a process that stopped mid-capture.
        let _ = std::fs::remove_dir_all(&scratch);
        let syncer = self.clone();
        Arc::new(
            move |filter: &[u8], app: &[u8; 32], bits: &[bool], roots: &[[u8; 32]; 4]| {
                runtime.block_on(syncer.sync_snapshot_source(&scratch, filter, app, bits, roots))
            },
        )
    }

    async fn sync_snapshot_source(
        &self,
        scratch: &std::path::Path,
        filter: &[u8],
        app: &[u8; 32],
        bits: &[bool],
        roots: &[[u8; 32]; 4],
    ) -> Result<quil_engine::storage_snapshot::Synced> {
        let first = self.resolve_addr().await?;
        let mut endpoints = vec![first.clone()];
        if let Some(pool) = self.archive_pool.as_ref() {
            endpoints.extend(
                pool.get_all()
                    .await
                    .into_iter()
                    .filter(|endpoint| *endpoint != first),
            );
        }
        let mut failure =
            QuilError::ExecutionUnavailable("no archive retains the storage snapshot".into());
        for addr in endpoints {
            match self
                .sync_snapshot_source_from(&addr, scratch, filter, app, bits, roots)
                .await
            {
                Ok(synced) => return Ok(synced),
                Err(error) => {
                    warn!(peer = %addr, filter = %hex::encode(filter), %error, "storage snapshot source not synced from this archive");
                    failure = error;
                }
            }
        }
        Err(failure)
    }

    async fn sync_snapshot_source_from(
        &self,
        addr: &str,
        scratch: &std::path::Path,
        filter: &[u8],
        app: &[u8; 32],
        bits: &[bool],
        roots: &[[u8; 32]; 4],
    ) -> Result<quil_engine::storage_snapshot::Synced> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = scratch.join(format!(
            "{}-{}-{}",
            hex::encode(&filter[..filter.len().min(40)]),
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&dir)
            .map_err(|e| QuilError::Internal(format!("scratch store {}: {e}", dir.display())))?;
        let guard = ScratchDir(dir.clone());
        let db = Arc::new(quil_store::RocksDb::open(&dir)?);
        let crdt = crate::master_node::worker_manager::build_thread_worker_hypergraph(
            &db,
            Arc::new(quil_tries::ShaInclusionProver),
            false,
        );
        crdt.set_unified_tree(true);
        let mut client = ArchiveClient::connect_mtls(addr, &self.falcon_signing_key)
            .await
            .map_err(|e| QuilError::ExecutionUnavailable(format!("archive connect: {e}")))?;
        let handle = tokio::runtime::Handle::current();
        for (phase, root) in roots.iter().enumerate() {
            if is_empty_phase_root(root) {
                continue;
            }
            let phase = phase as u32;
            let version = match quil_rpc::forest_sync_reader::resolve_forest_root(
                &client,
                filter.to_vec(),
                phase,
                root.to_vec(),
            )
            .await
            {
                Ok(Some((version, _))) => version,
                Ok(None) => {
                    return Err(QuilError::ExecutionUnavailable(format!(
                        "{addr} does not retain phase {phase} of the storage snapshot of {}",
                        hex::encode(filter)
                    )))
                }
                Err(e) => {
                    return Err(QuilError::ExecutionUnavailable(format!(
                        "resolve storage snapshot root: {e}"
                    )))
                }
            };
            let got = crate::forest_sync::sync_subtree_one_phase(
                &mut client,
                &handle,
                &crdt,
                app,
                filter,
                phase,
                version,
                bits.to_vec(),
                Some(*root),
            )
            .await?;
            if got != *root {
                return Err(QuilError::InvalidArgument(format!(
                    "synced phase {phase} of {} to {} instead of its snapshot root",
                    hex::encode(filter),
                    hex::encode(got)
                )));
            }
        }
        Ok(quil_engine::storage_snapshot::Synced {
            crdt: crdt.clone(),
            keep: Box::new(ScratchSnapshot {
                _crdt: crdt,
                _db: db,
                _dir: guard,
            }),
        })
    }

    async fn sync_shard_tree_from(
        &self,
        addr: &str,
        filter: &[u8],
        expected_roots: &[Vec<u8>],
    ) -> Result<bool> {
        let n = filter.len().min(32);
        let mut l2 = [0u8; 32];
        l2[..n].copy_from_slice(&filter[..n]);
        // UNIFIED mode: EVERY app is ONE L3 tree keyed by `l2`, and its four phase
        // roots ARE the header `state_roots`. A shard prover covering a specific
        // prefix (`filter = app ‖ prefix`) pulls ONLY its subtree — authenticated
        // against the header subtree root — so it never stores
        // the whole app. A whole-app sync (no prefix, e.g. an archive) diffs the
        // one tree directly.
        if self.crdt.unified_tree() {
            let prefix_bytes: Vec<u8> = if filter.len() > 32 {
                filter[32..].to_vec()
            } else {
                Vec::new()
            };
            if prefix_bytes.is_empty() {
                info!(%addr, filter = %hex::encode(filter), "syncing app tree (unified, whole tree)");
                return self
                    .sync_single_shard(addr, l2.to_vec(), expected_roots)
                    .await;
            }
            info!(%addr, filter = %hex::encode(filter), "syncing shard subtree (unified, range diff — only this prefix)");
            return self.sync_shard_subtree(addr, filter, expected_roots).await;
        }
        // QUIL splits 64-way: its state lives in sub-shard trees (app‖prefix),
        // verified as a set via the aggregation binding (all 4 phases).
        if l2 == quil_execution::domains::QUIL_TOKEN {
            info!(%addr, "syncing QUIL app (forest diff, 64 sub-shards)");
            return self.sync_split_shard(addr, l2, expected_roots).await;
        }
        info!(%addr, filter = %hex::encode(filter), "syncing app-shard tree (forest diff, single-shard)");
        self.sync_single_shard(addr, l2.to_vec(), expected_roots)
            .await
    }
}

#[cfg(test)]
mod archive_routing_tests {
    use super::*;

    #[tokio::test]
    async fn worker_tree_recovery_uses_archives_and_never_falls_back_to_master_state() {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg_store.clone(),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(
            std::time::Duration::ZERO,
        ));
        let mut syncer = ProdProverTreeSyncer {
            master_stream_addr: String::new(),
            hg_store,
            crdt,
            falcon_signing_key: vec![],
            archive_pool: Some(pool.clone()),
            discover_archives_from_master: true,
        };
        // Discovery failure is retryable; an empty archive pool must not turn
        // into a read of the regular master's incomplete application forest.
        assert!(syncer.resolve_addr().await.is_err());
        pool.add("127.0.0.1:8340".into()).await;
        pool.add("127.0.0.1:8350".into()).await;
        assert_eq!(syncer.resolve_addr().await.unwrap(), "127.0.0.1:8340");
        assert_eq!(syncer.resolve_addr().await.unwrap(), "127.0.0.1:8350");
        // Explicit fixed-source tools retain their existing source selection.
        syncer.archive_pool = None;
        syncer.discover_archives_from_master = false;
        syncer.master_stream_addr = "127.0.0.1:8340".into();
        assert_eq!(syncer.resolve_addr().await.unwrap(), "127.0.0.1:8340");
    }

    #[tokio::test]
    async fn a_source_that_failed_is_passed_over_while_another_is_known() {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg_store.clone(),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(
            std::time::Duration::ZERO,
        ));
        let syncer = ProdProverTreeSyncer {
            master_stream_addr: String::new(),
            hg_store,
            crdt,
            falcon_signing_key: vec![],
            archive_pool: Some(pool.clone()),
            discover_archives_from_master: false,
        };
        let (slow, other) = ("192.0.2.1:8340", "192.0.2.2:8340");
        pool.add(slow.into()).await;
        pool.add(other.into()).await;
        source_failed(slow);
        for _ in 0..3 {
            assert_eq!(syncer.resolve_addr().await.unwrap(), other);
        }
        // With every known archive failing, recovery still tries one.
        source_failed(other);
        assert!([slow, other].contains(&syncer.resolve_addr().await.unwrap().as_str()));
    }

    /// An in-process worker shares its master's pool: with every archive
    /// passed over by the GLOBAL poller it still reads one, and with none
    /// known it reports that instead of dialing an empty address.
    #[tokio::test]
    async fn an_empty_or_blacklisted_pool_never_resolves_an_empty_address() {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg_store.clone(),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(
            std::time::Duration::from_secs(60),
        ));
        let mut syncer = ProdProverTreeSyncer {
            master_stream_addr: String::new(),
            hg_store,
            crdt,
            falcon_signing_key: vec![],
            archive_pool: Some(pool.clone()),
            discover_archives_from_master: false,
        };
        let error = syncer.resolve_addr().await.unwrap_err();
        assert!(
            error.to_string().contains("no archive known yet"),
            "{error}"
        );
        let (known, own) = ("192.0.2.9:8340", "192.0.2.10:8340");
        pool.add(known.into()).await;
        pool.add(own.into()).await;
        pool.mark_own(own).await;
        // A failed frame poll passes the archive over for the TTL.
        pool.blacklist_for_tests(known).await;
        assert_eq!(pool.next().await, None);
        for _ in 0..2 {
            assert_eq!(syncer.resolve_addr().await.unwrap(), known);
        }
        syncer.archive_pool = None;
        assert!(
            syncer.resolve_addr().await.is_err(),
            "no pool and no fixed source"
        );
        assert!(syncer
            .get_app_shard_frame(&[1; 32], 0)
            .await
            .unwrap_err()
            .to_string()
            .contains("no archive known"));
    }

    /// Past the poller's blacklist, a source a shard read failed at recently
    /// is passed over while another is known.
    #[tokio::test]
    async fn the_blacklist_fallback_prefers_a_source_no_read_failed_at() {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg_store.clone(),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(
            std::time::Duration::from_secs(60),
        ));
        let syncer = ProdProverTreeSyncer {
            master_stream_addr: String::new(),
            hg_store,
            crdt,
            falcon_signing_key: vec![],
            archive_pool: Some(pool.clone()),
            discover_archives_from_master: false,
        };
        let (failing, other) = ("192.0.2.21:8340", "192.0.2.22:8340");
        for ep in [failing, other] {
            pool.add(ep.into()).await;
            pool.blacklist_for_tests(ep).await;
        }
        source_failed(failing);
        for _ in 0..3 {
            assert_eq!(syncer.resolve_addr().await.unwrap(), other);
        }
    }

    /// A read cancelled by its caller's timeout counts as failed: the next
    /// read starts at another archive and dials afresh.
    #[tokio::test]
    async fn a_cancelled_frame_read_counts_as_failed() {
        // Accepts the connection and never answers the handshake.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let silent = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg_store.clone(),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        let syncer = ProdProverTreeSyncer {
            master_stream_addr: addr.clone(),
            hg_store,
            crdt,
            falcon_signing_key: quil_p2p::generate_falcon_signing_key(),
            archive_pool: None,
            discover_archives_from_master: false,
        };
        let read = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            syncer.get_app_shard_frame(&[1; 32], 0),
        );
        assert!(read.await.is_err(), "the silent archive must not answer");
        assert!(recently_failed(&addr));
        silent.abort();
    }

    /// A failed GLOBAL prover-tree sync passes its archive over, as a failed
    /// shard read does, so the next attempt asks another archive.
    #[tokio::test]
    async fn a_failed_global_prover_tree_sync_passes_its_archive_over() {
        // Nothing listens on a port just released: the dial is refused.
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();
        let other = "192.0.2.31:8340";
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg_store.clone(),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(
            std::time::Duration::ZERO,
        ));
        pool.add(dead.clone()).await;
        pool.add(other.into()).await;
        let syncer = ProdProverTreeSyncer {
            master_stream_addr: String::new(),
            hg_store,
            crdt,
            falcon_signing_key: quil_p2p::generate_falcon_signing_key(),
            archive_pool: Some(pool),
            discover_archives_from_master: false,
        };
        assert!(
            syncer.sync_prover_tree(&[]).await.is_err(),
            "the refused archive must fail the sync"
        );
        assert!(recently_failed(&dead));
        for _ in 0..3 {
            assert_eq!(syncer.resolve_addr().await.unwrap(), other);
        }
    }

    /// Passes over the archives for the GLOBAL prover tree start at a random
    /// archive, not all at the first configured one.
    #[test]
    fn prover_tree_pulls_start_at_a_random_archive() {
        let archives: Vec<String> = (41..45)
            .map(|host| format!("192.0.2.{host}:8340"))
            .collect();
        let firsts: std::collections::HashSet<String> = (0..64)
            .map(|_| archive_pull_order(archives.clone()).remove(0))
            .collect();
        assert!(firsts.len() > 1, "every pass started at {firsts:?}");
        let mut order = archive_pull_order(archives.clone());
        order.sort();
        assert_eq!(order, archives, "a pass tries every archive once");
    }

    /// A pass for the GLOBAL prover tree tries the archives that failed
    /// recently last, in rotation order otherwise.
    #[test]
    fn prover_tree_pulls_try_recently_failed_archives_last() {
        let archives: Vec<String> = (51..55)
            .map(|host| format!("192.0.2.{host}:8340"))
            .collect();
        source_failed(&archives[2]);
        assert_eq!(
            archive_pull_order_from(archives.clone(), 1),
            [&archives[1], &archives[3], &archives[0], &archives[2]].map(String::clone)
        );
        source_failed(&archives[3]);
        assert_eq!(
            archive_pull_order_from(archives.clone(), 3),
            [&archives[0], &archives[1], &archives[3], &archives[2]].map(String::clone)
        );
    }

    /// Idle connections are dropped on any lookup; a connection belongs to
    /// one identity, and its reaper stops once it is gone or replaced.
    #[test]
    fn frame_connections_expire_and_belong_to_their_identity() {
        let start = std::time::Instant::now();
        let key = |addr: &str| (std::thread::current().id(), addr.to_string());
        let mut clients = FrameClients::new();
        let a = clients.insert(key("a:1"), b"k", 1u8, start);
        clients.insert(
            key("b:1"),
            b"k",
            2u8,
            start + std::time::Duration::from_secs(50),
        );
        assert_eq!(
            clients.get(&key("a:1"), b"other", start),
            None,
            "another identity"
        );
        assert!(!clients.reap(&key("a:1"), a, start + std::time::Duration::from_secs(30)));
        assert_eq!(
            clients.get(&key("b:1"), b"k", start + FRAME_CLIENT_IDLE),
            Some(2)
        );
        assert!(
            clients.entries.get(&key("a:1")).is_none(),
            "an idle connection goes on any lookup"
        );
        assert!(
            clients.reap(&key("a:1"), a, start + FRAME_CLIENT_IDLE),
            "nothing left to reap"
        );
        let b = clients.insert(key("b:1"), b"k", 3u8, start + FRAME_CLIENT_IDLE);
        assert!(
            clients.reap(&key("b:1"), b - 1, start),
            "a replaced connection is not reaped"
        );
        assert!(clients.reap(&key("b:1"), b, start + FRAME_CLIENT_IDLE * 2));
        assert!(clients.entries.is_empty());
    }

    #[test]
    fn a_shard_frames_header_is_found_among_a_global_frames_requests() {
        use quil_types::proto::global::{
            message_request::Request, FrameHeader, GlobalFrame, MessageBundle, MessageRequest,
        };
        let shard = |address: u8, frame_number: u64| MessageRequest {
            request: Some(Request::Shard(FrameHeader {
                address: vec![address; 35],
                frame_number,
                ..Default::default()
            })),
            ..Default::default()
        };
        let global = GlobalFrame {
            header: None,
            requests: vec![
                MessageBundle {
                    requests: vec![MessageRequest::default(), shard(1, 7)],
                    ..Default::default()
                },
                MessageBundle {
                    requests: vec![shard(2, 6), shard(2, 7), shard(2, 7)],
                    ..Default::default()
                },
            ],
        };
        let found = carried_headers(&global, &[2; 35], 7);
        assert_eq!(
            found
                .iter()
                .map(|header| (header.address.clone(), header.frame_number))
                .collect::<Vec<_>>(),
            [(vec![2; 35], 7), (vec![2; 35], 7)],
            "every member's copy"
        );
        assert_eq!(carried_headers(&global, &[1; 35], 7).len(), 1);
        assert!(carried_headers(&global, &[2; 35], 8).is_empty());
        assert!(carried_headers(&global, &[3; 35], 7).is_empty());
    }

    /// A copy identity numbered `n`, for tests.
    fn id(n: u64) -> CopyId {
        let mut id = [0; 32];
        id[..8].copy_from_slice(&n.to_be_bytes());
        id
    }

    /// [`keep_carried_search`] of a search told no named parent that refused
    /// `refused`.
    fn keep(key: (Vec<u8>, u64), state: CarriedState, refused: &[CopyId]) {
        keep_carried_search(
            key,
            SearchOutcome {
                state: Some(state),
                refused,
                ..Default::default()
            },
        );
    }

    /// A syncer whose carried-header searches are answered from the cache.
    fn cache_only_syncer() -> ProdProverTreeSyncer {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let hg_store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            hg_store.clone(),
            Arc::new(quil_types::crypto::NoopInclusionProver),
        ));
        ProdProverTreeSyncer {
            master_stream_addr: String::new(),
            hg_store,
            crdt,
            falcon_signing_key: vec![],
            archive_pool: None,
            discover_archives_from_master: false,
        }
    }

    /// A plausible copy of `filter`'s frame 7 header with `output` bytes and
    /// attestation field `attestation`.
    fn carried_copy(
        filter: &[u8],
        output: u8,
        attestation: &[u8],
    ) -> quil_types::proto::global::FrameHeader {
        quil_types::proto::global::FrameHeader {
            address: filter.to_vec(),
            frame_number: 7,
            output: vec![output; 32],
            requests_root: vec![0; 32],
            public_key_signature_bls48581: Some(
                quil_types::proto::keys::Bls48581AggregateSignature {
                    signature: vec![1],
                    ..Default::default()
                },
            ),
            storage_attestation: attestation.to_vec(),
            global_frame_number: 5,
            ..Default::default()
        }
    }

    /// A search answers for its frame for the retry interval, copies found
    /// or none, but not once the parent the frame after it names is known
    /// and it was not told it; once every copy has failed to replay, or the
    /// search failed with nothing found, the GLOBAL frames are read again
    /// after a back-off, whatever it is told. Rejected copies are kept
    /// across searches, the oldest forgotten first, and one frame is warned
    /// about once per interval. The cache holds at most [`CARRIED_SEARCHES`]
    /// frames, dropping the oldest of those that remember no copies first.
    #[test]
    fn carried_searches_remember_rejected_copies_and_warn_once_per_interval() {
        let search = |state, named| CarriedSearch {
            state,
            named,
            ..CarriedSearch::new(std::time::Instant::now())
        };
        let found = search(
            CarriedState::Found {
                copies: Vec::new(),
                certified: Vec::new(),
            },
            None,
        );
        assert!(found.current() && found.answers(None));
        assert!(
            !found.answers(Some([1; 32])),
            "told the named parent only now"
        );
        assert!(search(CarriedState::Missed, Some([1; 32])).answers(Some([1; 32])));
        assert!(
            !search(CarriedState::Missed, Some([1; 32])).answers(Some([2; 32])),
            "told another named parent"
        );
        assert!(
            search(CarriedState::Rejected, None).answers(Some([1; 32])),
            "the back-off holds"
        );
        assert!(search(CarriedState::Failed, None).answers(Some([1; 32])));
        assert!(found.fresh(CARRIED_SEARCH_RETRY - std::time::Duration::from_secs(1)));
        assert!(!found.fresh(CARRIED_SEARCH_RETRY));
        assert!(!search(CarriedState::Missed, None).fresh(CARRIED_SEARCH_RETRY));
        let mut rejected = search(CarriedState::Rejected, None);
        rejected.exhausted = 1;
        assert!(rejected.current() && !rejected.fresh(CARRIED_REJECT_RETRY));
        rejected.exhausted = 3;
        assert_eq!(
            rejected.reject_backoff(),
            CARRIED_REJECT_RETRY * 4,
            "doubling each time every copy fails"
        );
        rejected.exhausted = 30;
        assert_eq!(rejected.reject_backoff(), CARRIED_BACKOFF_MAX);
        assert!(
            !search(CarriedState::Unsearched, None).current(),
            "only remembers"
        );
        assert!(!search(CarriedState::Failed, None).fresh(CARRIED_FAIL_RETRY));
        let mut list = std::collections::VecDeque::new();
        for n in 1..=4 {
            assert!(remember(&mut list, id(n), 3));
        }
        assert!(!remember(&mut list, id(3), 3));
        assert_eq!(list, [id(2), id(3), id(4)], "the oldest forgotten first");

        let filter = vec![0x3c; 33];
        let copy = |output| carried_copy(&filter, output, &[]);
        let copies = vec![(7, copy(1)), (8, copy(2))];
        let found = |copies| CarriedState::Found {
            copies,
            certified: Vec::new(),
        };
        keep((filter.clone(), 1), found(copies.clone()), &[]);
        let syncer = cache_only_syncer();
        let (first, second) = (carried_copy_digest(&copy(1)), carried_copy_digest(&copy(2)));
        let kept = |number| {
            carried_searched()
                .get(&(filter.clone(), number))
                .map(|search| {
                    (
                        search.state.clone(),
                        search.rejected.iter().copied().collect::<Vec<_>>(),
                        search.warned.is_some(),
                    )
                })
        };
        syncer.reject_carried_copy(&filter, 1, first);
        syncer.reject_carried_copy(&filter, 1, first);
        assert_eq!(kept(1), Some((found(copies.clone()), vec![first], true)));
        syncer.reject_carried_copy(&filter, 1, second);
        syncer.reject_carried_shard_headers(&filter, 1);
        assert_eq!(
            kept(1),
            Some((CarriedState::Rejected, vec![first, second], true))
        );
        assert!(
            !carried_searched()
                .get_mut(&(filter.clone(), 1))
                .unwrap()
                .warn_due(),
            "once per interval"
        );
        keep((filter.clone(), 1), found(vec![(9, copy(3))]), &[]);
        assert_eq!(
            kept(1),
            Some((found(vec![(9, copy(3))]), vec![first, second], true)),
            "a search again keeps what was rejected"
        );
        keep((filter.clone(), 3), found(copies), &[]);
        for n in 0..=CARRIED_REJECTED as u64 {
            syncer.reject_carried_copy(&filter, 3, id(n));
        }
        let (_, rejected, _) = kept(3).unwrap();
        assert_eq!(
            rejected,
            (1..=CARRIED_REJECTED as u64).map(id).collect::<Vec<_>>(),
            "a full list forgets its oldest"
        );
        syncer.reject_carried_copy(&filter, 2, first);
        assert_eq!(
            kept(2),
            Some((CarriedState::Unsearched, vec![first], true)),
            "a rejection outlives its search"
        );
        for number in 10..10 + CARRIED_SEARCHES as u64 {
            keep((filter.clone(), number), CarriedState::Missed, &[]);
        }
        let searches = carried_searched();
        assert_eq!(searches.len(), CARRIED_SEARCHES);
        assert!(
            [1, 2, 3]
                .iter()
                .all(|number| searches.contains_key(&(filter.clone(), *number))),
            "frames that remember copies are kept"
        );
        assert!(
            (10..13).all(|number| !searches.contains_key(&(filter.clone(), number))),
            "the oldest that remember none went first"
        );
        assert!(searches.contains_key(&(filter, 9 + CARRIED_SEARCHES as u64)));
    }

    /// Once the back-off after every copy failed has passed, the copies
    /// rejected, and those refused for their certificate, are tried again: a
    /// failure may have been this node's (a committee, registration or
    /// GLOBAL frame it lacked then). Within the back-off they stay so, and
    /// copies refused for their output stay refused.
    #[test]
    fn rejected_copies_are_tried_again_after_the_back_off() {
        let search = |at| CarriedSearch {
            state: CarriedState::Rejected,
            rejected: [id(1), id(2)].into(),
            refused: [id(3)].into(),
            retried: [id(4)].into(),
            retry: [(id(4), (at, 1))].into(),
            exhausted: 1,
            ..CarriedSearch::new(at)
        };
        let mut backing_off = search(std::time::Instant::now());
        backing_off.resume();
        assert_eq!(
            (backing_off.rejected.clone(), backing_off.retried.clone()),
            ([id(1), id(2)].into(), [id(4)].into())
        );
        let Some(past) = std::time::Instant::now()
            .checked_sub(CARRIED_REJECT_RETRY + std::time::Duration::from_secs(1))
        else {
            return;
        };
        let mut expired = search(past);
        assert!(!expired.current());
        expired.resume();
        assert!(
            expired.rejected.is_empty() && expired.retried.is_empty(),
            "tried again"
        );
        assert_eq!(
            expired.refused,
            [id(3)],
            "copies refused when checked stay refused"
        );
    }

    /// A genuine copy whose certificate this node could not reproduce once
    /// (a session or committee record it lacked) is accepted by a later
    /// search: every copy refused completes the search as refused, which
    /// backs off, doubling each time, and the copies refused for their
    /// certificate are checked again after it. A copy refused for its
    /// output stays refused. The first search that refuses every copy says
    /// so, rather than that no copy was carried.
    #[tokio::test]
    async fn a_genuine_copy_refused_once_is_accepted_later() {
        let filter = vec![0x44; 33];
        let (genuine, forged) = (
            carried_copy(&filter, 0x47, &[]),
            carried_copy(&filter, 0x46, &[]),
        );
        let lacking: CarriedVerifier =
            Arc::new(|header: quil_types::proto::global::FrameHeader| {
                Box::pin(async move {
                    match header.output == vec![0x47; 32] {
                        true => CopyVerdict::CertificateRefused,
                        false => CopyVerdict::Refused,
                    }
                })
            });
        let key = (filter.clone(), 7);
        let search = |verify: CarriedVerifier| {
            let (genuine, forged, key) = (genuine.clone(), forged.clone(), key.clone());
            async move {
                let skip = carried_searched()
                    .get_mut(&key)
                    .map(|search| {
                        search.resume();
                        search
                            .refused
                            .iter()
                            .chain(&search.retried)
                            .copied()
                            .collect()
                    })
                    .unwrap_or_default();
                let mut copies = CarriedCopies::new(&key.0, 7, None, skip);
                copies.take(10, vec![forged, genuine], Some(&verify)).await;
                let (best, certified) = copies.best();
                let refused = copies.refused.len() + copies.retried.len() + copies.passed_over;
                let state = search_state(&best, &certified, false, refused);
                keep_carried_search(
                    key.clone(),
                    SearchOutcome {
                        state: Some(state.clone()),
                        refused: &copies.refused,
                        retried: &copies.retried,
                        still_carried: Some(&copies.still_carried),
                        refused_now: refused,
                        ..Default::default()
                    },
                );
                state
            }
        };
        assert_eq!(
            search(lacking.clone()).await,
            CarriedState::Refused,
            "every copy refused, none missing"
        );
        assert_eq!(
            carried_searched()[&key].retried,
            [carried_copy_key(&genuine)]
        );
        assert_eq!(
            carried_searched()[&key].reject_backoff(),
            CARRIED_REJECT_RETRY
        );
        let Some(past) = std::time::Instant::now()
            .checked_sub(CARRIED_BACKOFF_MAX + std::time::Duration::from_secs(1))
        else {
            return;
        };
        let expire = || {
            let mut searches = carried_searched();
            let search = searches.get_mut(&key).unwrap();
            search.at = past;
            for (at, _) in search.retry.values_mut() {
                *at = past;
            }
        };
        expire();
        assert_eq!(search(lacking).await, CarriedState::Refused);
        assert_eq!(
            carried_searched()[&key].reject_backoff(),
            CARRIED_REJECT_RETRY * 2,
            "doubling"
        );
        expire();
        let state = search(checked_as_genuine()).await;
        assert_eq!(
            state,
            CarriedState::Found {
                copies: vec![(10, genuine.clone())],
                certified: vec![carried_copy_digest(&genuine)]
            }
        );
        assert_eq!(
            carried_searched()[&key].refused,
            [carried_copy_key(&forged)],
            "the forged output stays refused"
        );
    }

    /// A search reads the GLOBAL frames no search through its archive read
    /// before without a copy, a window at a time, so over successive
    /// searches a header carried in the middle of a long pause is reached,
    /// each frame read once; frames above the archive's GLOBAL head wait. A
    /// search with a read unanswered is cut short, not a miss. Another
    /// archive reads the frames again, as does the same one once its marks
    /// expire: an archive answering without a frame's requests hides no
    /// copy for good.
    #[test]
    fn successive_searches_read_on_where_the_last_stopped() {
        use quil_engine::prover_tree_syncer::carried_header_globals;
        let filter = vec![0x45; 33];
        let key = (filter.clone(), 7);
        let globals = carried_header_globals(9139, Some(9139 + 300));
        let carrier = 9300;
        let mut read = Vec::new();
        for _ in 0..8 {
            let read_before = carried_searched()
                .get(&key)
                .map(|search| search.read_by("a"))
                .unwrap_or_default();
            let window: Vec<u64> = unread_globals(&globals, &read_before, 9400)
                .into_iter()
                .take(CARRIED_HEADER_WINDOW as usize)
                .collect();
            read.extend(&window);
            if window.contains(&carrier) {
                break;
            }
            let marks: Vec<(u64, bool)> = window.iter().map(|&global| (global, true)).collect();
            keep_carried_search(
                key.clone(),
                SearchOutcome {
                    state: Some(CarriedState::Failed),
                    addr: "a",
                    read: &marks,
                    progress: true,
                    ..Default::default()
                },
            );
        }
        assert!(
            read.contains(&carrier),
            "reached within {} searches",
            read.len() as u64 / CARRIED_HEADER_WINDOW + 1
        );
        let distinct: std::collections::HashSet<u64> = read.iter().copied().collect();
        assert_eq!(distinct.len(), read.len(), "each frame read once");
        assert_eq!(
            carried_searched()[&key].failed,
            1,
            "a search that read on made progress"
        );
        assert!(
            carried_searched()[&key].read_by("b").is_empty(),
            "another archive reads them again"
        );
        let Some(past) = std::time::Instant::now().checked_sub(CARRIED_READ_EXPIRY) else {
            return;
        };
        for mark in carried_searched()
            .get_mut(&key)
            .unwrap()
            .read
            .get_mut("a")
            .unwrap()
            .values_mut()
        {
            mark.at = past;
        }
        assert!(
            carried_searched()[&key].read_by("a").is_empty(),
            "read again once expired"
        );
        assert!(
            unread_globals(&[9139, 9500], &Default::default(), 9400) == [9139],
            "above the head: not yet"
        );
        assert!(search_incomplete(false, 0, 1, 0), "a read unanswered");
        assert!(!search_incomplete(false, 0, 0, 0));
        assert_eq!(search_state(&[], &[], true, 0), CarriedState::Failed);
        assert_eq!(search_state(&[], &[], false, 0), CarriedState::Missed);
    }

    /// A GLOBAL frame whose copies were all refused or passed over counts
    /// as read, so copies planted in the first frames a search reads cannot
    /// hold every later search to them: one refused for its output or
    /// structure, for good; one refused for now, or rejected, until those
    /// copies are tried again, when the frames carrying them are read again.
    /// A frame carrying a copy kept or left unchecked is read again.
    #[tokio::test]
    async fn frames_carrying_only_refused_copies_count_as_read() {
        let filter = [0x46; 33];
        let copy = |output: u8| carried_copy(&filter, output, &[]);
        let verify: CarriedVerifier = Arc::new(|header: quil_types::proto::global::FrameHeader| {
            Box::pin(async move {
                match header.output[0] {
                    0x47 => CopyVerdict::Certified,
                    0x48 => CopyVerdict::CertificateRefused,
                    _ => CopyVerdict::Refused,
                }
            })
        });
        let (rejected, passed) = (carried_copy_key(&copy(0x49)), carried_copy_key(&copy(0x4a)));
        let mut copies = CarriedCopies::new(&filter, 7, None, [rejected, passed].into())
            .with_for_now([rejected].into());
        copies.offer(10, vec![copy(1), copy(2)]);
        copies.offer(11, vec![copy(0x48), copy(3)]);
        copies.offer(12, vec![copy(0x49)]);
        copies.offer(13, vec![copy(0x4a)]);
        copies.offer(14, Vec::new());
        copies.offer(15, vec![copy(0x47)]);
        copies
            .check(
                Some(&verify),
                tokio::time::Instant::now() + std::time::Duration::from_secs(60),
            )
            .await;
        let read: Vec<_> = (10..=15).map(|global| copies.frame_read(global)).collect();
        assert_eq!(
            read,
            [
                Some(true),
                Some(false),
                Some(false),
                Some(true),
                Some(true),
                None
            ]
        );

        let key = (filter.to_vec(), 7);
        keep_carried_search(
            key.clone(),
            SearchOutcome {
                state: Some(CarriedState::Failed),
                retried: &copies.retried,
                addr: "a",
                read: &[(10, true), (11, false), (12, false), (13, true), (14, true)],
                ..Default::default()
            },
        );
        assert_eq!(
            carried_searched()[&key].read_by("a"),
            [10, 11, 12, 13, 14].into()
        );
        let Some(past) = std::time::Instant::now().checked_sub(CARRIED_BACKOFF_MAX) else {
            return;
        };
        for (at, _) in carried_searched().get_mut(&key).unwrap().retry.values_mut() {
            *at = past;
        }
        carried_searched().get_mut(&key).unwrap().resume();
        assert_eq!(
            carried_searched()[&key].read_by("a"),
            [10, 13, 14].into(),
            "the frames carrying copies tried again are read again"
        );
    }

    /// Each copy refused for now is checked again once its own back-off has
    /// passed, whatever the searches since reached: searches cut short (a
    /// read unanswered, copies unchecked) do not keep it refused, and copies
    /// refused later do not hold it back. The back-off doubles each time the
    /// copy is refused for now again, and a certified copy found starts the
    /// count over.
    #[test]
    fn copies_refused_for_now_are_tried_again_after_incomplete_searches() {
        let filter = vec![0x47; 33];
        let key = (filter.clone(), 7);
        let failed = |retried: &[CopyId]| {
            keep_carried_search(
                key.clone(),
                SearchOutcome {
                    state: Some(CarriedState::Failed),
                    retried,
                    ..Default::default()
                },
            )
        };
        let Some(past) = std::time::Instant::now().checked_sub(CARRIED_BACKOFF_MAX) else {
            return;
        };
        let expire = |copy: CopyId| {
            let mut searches = carried_searched();
            let search = searches.get_mut(&key).unwrap();
            search.at = past;
            search.retry.get_mut(&copy).unwrap().0 = past;
            search.resume();
            search.retried.iter().copied().collect::<Vec<_>>()
        };
        failed(&[id(5)]);
        failed(&[]);
        assert!(
            expire(id(5)).is_empty(),
            "tried again after a search cut short"
        );
        failed(&[id(5)]);
        assert_eq!(
            carried_searched()[&key].retry[&id(5)].1,
            2,
            "its back-off doubles"
        );
        failed(&[id(6)]);
        assert_eq!(expire(id(6)), [id(5)], "each on its own back-off");
        let copy = carried_copy_digest(&carried_copy(&filter, 0x47, &[]));
        keep(
            (filter.clone(), 7),
            CarriedState::Found {
                copies: Vec::new(),
                certified: vec![copy],
            },
            &[],
        );
        failed(&[id(6)]);
        assert_eq!(
            carried_searched()[&key].retry[&id(6)].1,
            1,
            "the count starts over"
        );
    }

    /// A run of searches that refused every copy ends when one finds copies,
    /// and a run of copies failing to replay when a search finds a certified
    /// copy the last one did not: each back-off starts over, rather than
    /// staying at its longest across unrelated failures.
    #[test]
    fn back_offs_start_over_once_a_search_finds_something_new() {
        let filter = vec![0x48; 33];
        let key = (filter.clone(), 7);
        let found = |certified: Vec<u64>| CarriedState::Found {
            copies: Vec::new(),
            certified: certified.into_iter().map(id).collect(),
        };
        keep(key.clone(), CarriedState::Refused, &[]);
        keep(key.clone(), CarriedState::Refused, &[]);
        assert_eq!(
            carried_searched()[&key].reject_backoff(),
            CARRIED_REJECT_RETRY * 2
        );
        keep(key.clone(), found(vec![1]), &[]);
        assert_eq!(carried_searched()[&key].refused_streak, 0);
        let syncer = cache_only_syncer();
        syncer.reject_carried_shard_headers(&filter, 7);
        syncer.reject_carried_shard_headers(&filter, 7);
        keep(key.clone(), found(vec![1]), &[]);
        assert_eq!(
            carried_searched()[&key].exhausted,
            2,
            "the same copy found again"
        );
        keep(key.clone(), found(vec![2]), &[]);
        assert_eq!(
            carried_searched()[&key].exhausted,
            0,
            "a copy not found before"
        );
    }

    /// A check that waits on GLOBAL history (a historical committee that
    /// does not come) takes at most its slice of a search's time, and a copy
    /// whose check could not end is remembered for now: forged copies whose
    /// certificates send the node there, gathered ahead of the genuine one,
    /// keep it from its check for a search or two at most. A search that
    /// kept only such copies, others unchecked, hands them to replay but is
    /// not taken for a find: the next search reads on after the short
    /// back-off of a search cut short, not after a found search's interval.
    #[tokio::test(start_paused = true)]
    async fn a_slow_check_cannot_keep_the_genuine_copy_unchecked() {
        // Virtual time: a search's budget and each check's slice are tokio
        // instants, so exactly six forged checks (6 x 50 ms) fit in one search
        // whatever the machine load, and the genuine copy is reached in the second.
        let filter = [0x49; 33];
        let signed = |signature: Vec<u8>| quil_types::proto::global::FrameHeader {
            public_key_signature_bls48581: Some(
                quil_types::proto::keys::Bls48581AggregateSignature {
                    signature,
                    ..Default::default()
                },
            ),
            ..carried_copy(&filter, 0x47, &[])
        };
        let genuine = signed(vec![1]);
        let named = quil_crypto::poseidon::hash_bytes_to_32(&genuine.output).unwrap();
        let verify: CarriedVerifier = Arc::new(|header: quil_types::proto::global::FrameHeader| {
            Box::pin(async move {
                if header.public_key_signature_bls48581.unwrap().signature != vec![1] {
                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                }
                CopyVerdict::Certified
            })
        });
        let forged: Vec<_> = (0..8u8).map(|index| signed(vec![2, index])).collect();
        let key = (filter.to_vec(), 7);
        let mut reached = None;
        for search in 1..=4 {
            if let Some(kept) = carried_searched().get_mut(&key) {
                // A minute later: past a search cut short's back-off, within
                // a found search's interval.
                kept.at = kept
                    .at
                    .checked_sub(std::time::Duration::from_secs(60))
                    .unwrap_or(kept.at);
                if kept.answers(Some(named)) {
                    continue;
                }
            }
            let skip: std::collections::HashSet<CopyId> = carried_searched()
                .get(&key)
                .map(|kept| kept.refused.iter().chain(&kept.retried).copied().collect())
                .unwrap_or_default();
            let mut copies = CarriedCopies::new(&filter, 7, Some(named), skip);
            copies.slice = std::time::Duration::from_millis(50);
            copies.offer(10, forged.clone());
            copies.offer(11, vec![genuine.clone()]);
            copies
                .check(
                    Some(&verify),
                    tokio::time::Instant::now() + std::time::Duration::from_millis(300),
                )
                .await;
            let (best, certified) = copies.best();
            let state = search_state(
                &best,
                &certified,
                search_incomplete(false, 0, 0, copies.unverified),
                0,
            );
            if search == 1 {
                assert!(matches!(state, CarriedState::Partial { .. }), "{state:?}");
            }
            keep_carried_search(
                key.clone(),
                SearchOutcome {
                    state: Some(state),
                    named: Some(named),
                    refused: &copies.refused,
                    retried: &copies.retried,
                    still_carried: Some(&copies.still_carried),
                    progress: true,
                    verified: true,
                    ..Default::default()
                },
            );
            if certified.contains(&carried_copy_digest(&genuine)) {
                reached = Some(search);
                break;
            }
        }
        assert!(
            reached.is_some_and(|search| search <= 2),
            "reached in search {reached:?}"
        );
    }

    /// With no check to run (the engine silent), copies are kept unchecked
    /// in the order read. Those that then fail to replay stay passed over
    /// after the back-off that follows every copy failing, until a search
    /// can check copies: four forgeries of the named output read first
    /// cannot keep the genuine copy, read after them, from replay.
    #[tokio::test]
    async fn unchecked_copies_that_failed_to_replay_stay_passed_over() {
        let filter = vec![0x4b; 33];
        let signed = |signature: Vec<u8>| quil_types::proto::global::FrameHeader {
            public_key_signature_bls48581: Some(
                quil_types::proto::keys::Bls48581AggregateSignature {
                    signature,
                    ..Default::default()
                },
            ),
            ..carried_copy(&filter, 0x47, &[])
        };
        let genuine = signed(vec![1]);
        let named = quil_crypto::poseidon::hash_bytes_to_32(&genuine.output).unwrap();
        let forged: Vec<_> = (0..CARRIED_COPIES as u8)
            .map(|index| signed(vec![2, index]))
            .collect();
        let key = (filter.clone(), 7);
        let syncer = cache_only_syncer();
        let Some(past) = std::time::Instant::now().checked_sub(CARRIED_BACKOFF_MAX) else {
            return;
        };
        let mut kept_by = Vec::new();
        for _ in 0..2 {
            let skip: std::collections::HashSet<CopyId> = carried_searched()
                .get_mut(&key)
                .map(|search| {
                    search.at = past;
                    search.resume();
                    search
                        .refused
                        .iter()
                        .chain(&search.retried)
                        .chain(&search.rejected)
                        .copied()
                        .collect()
                })
                .unwrap_or_default();
            let mut copies = CarriedCopies::new(&filter, 7, Some(named), skip);
            copies.offer(10, forged.clone());
            copies.offer(11, vec![genuine.clone()]);
            copies
                .check(
                    None,
                    tokio::time::Instant::now() + std::time::Duration::from_secs(60),
                )
                .await;
            let (best, certified) = copies.best();
            keep_carried_search(
                key.clone(),
                SearchOutcome {
                    state: Some(search_state(&best, &certified, false, 0)),
                    named: Some(named),
                    ..Default::default()
                },
            );
            for (_, header) in &best {
                syncer.reject_carried_copy(&filter, 7, carried_copy_digest(header));
            }
            syncer.reject_carried_shard_headers(&filter, 7);
            kept_by.push(
                best.into_iter()
                    .map(|(_, header)| header)
                    .collect::<Vec<_>>(),
            );
        }
        assert_eq!(kept_by[0], forged);
        assert_eq!(kept_by[1], [genuine]);
    }

    /// A rebuilt frame that failed to replay names the attested copy it was
    /// rebuilt from ([`ProverTreeSyncer::reject_carried_copy`]): a later
    /// search passes that attested copy over, and takes the copy without its
    /// attestation, rather than checking and keeping it again.
    #[tokio::test]
    async fn a_rejected_attested_copy_is_passed_over_when_gathered() {
        let filter = [0x4a; 33];
        let attested = carried_copy(&filter, 0x47, &[1, 2, 3]);
        let rejected = carried_copy_digest(&attested);
        let mut copies =
            CarriedCopies::new(&filter, 7, None, [rejected].into()).with_for_now([rejected].into());
        copies
            .take(10, vec![attested.clone()], Some(&checked_as_genuine()))
            .await;
        assert_eq!(copies.passed_over, 1);
        assert_eq!(copies.best().0, [(10, carried_copy(&filter, 0x47, &[]))]);
    }

    /// With no check to run (the engine silent), no copy the frame after it
    /// does not name goes to replay unchecked, as forgeries of those are
    /// free and replay can reject only so many: a search keeping none waits
    /// for one that can check them, and one keeping named copies unchecked
    /// is no find, read on after a short back-off.
    #[tokio::test]
    async fn with_no_check_only_named_copies_go_to_replay_unchecked() {
        let filter = [0x4c; 33];
        let copy = |output: u8| carried_copy(&filter, output, &[]);
        let forgeries: Vec<_> = (0..70u8).map(copy).chain([copy(0x47)]).collect();
        let mut copies = CarriedCopies::new(&filter, 7, None, Default::default());
        copies.take(10, forgeries.clone(), None).await;
        let (best, certified) = copies.best();
        assert!(best.is_empty());
        assert_eq!(copies.unverified, forgeries.len());
        let incomplete = search_incomplete(false, 0, 0, copies.unverified);
        assert_eq!(
            search_state(&best, &certified, incomplete, 0),
            CarriedState::Failed
        );
        let named = quil_crypto::poseidon::hash_bytes_to_32(&[0x47; 32]).unwrap();
        let mut copies = CarriedCopies::new(&filter, 7, Some(named), Default::default());
        copies.take(10, forgeries, None).await;
        assert_eq!(copies.best().0, [(10, copy(0x47))]);
    }

    /// Copies never checked are checked before copies refused for now
    /// before and due again, so planted copies refused for their
    /// certificate, back each time their back-off passes, delay a copy read
    /// after them by one pass at most.
    #[tokio::test]
    async fn copies_never_checked_go_before_those_due_again() {
        let filter = [0x4d; 33];
        let signed = |signature: Vec<u8>| quil_types::proto::global::FrameHeader {
            public_key_signature_bls48581: Some(
                quil_types::proto::keys::Bls48581AggregateSignature {
                    signature,
                    ..Default::default()
                },
            ),
            ..carried_copy(&filter, 0x47, &[])
        };
        let (again, fresh) = (signed(vec![2]), signed(vec![1]));
        let named = quil_crypto::poseidon::hash_bytes_to_32(&[0x47; 32]).unwrap();
        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = order.clone();
        let verify: CarriedVerifier =
            Arc::new(move |header: quil_types::proto::global::FrameHeader| {
                seen.lock()
                    .unwrap()
                    .push(header.public_key_signature_bls48581.unwrap().signature);
                Box::pin(async { CopyVerdict::CertificateRefused })
            });
        let mut copies = CarriedCopies::new(&filter, 7, Some(named), Default::default())
            .with_rechecked([carried_copy_key(&again)].into());
        copies.take(10, vec![again, fresh], Some(&verify)).await;
        assert_eq!(*order.lock().unwrap(), [vec![1], vec![2]]);
    }

    /// Forgeries of the named output whose certificates this node refuses,
    /// as production does, only for now (their output being sound) cannot
    /// starve the genuine copy either: those refused are passed over until
    /// their back-off passes, and the next search reaches the genuine one.
    #[tokio::test]
    async fn forgeries_refused_for_now_cannot_starve_the_genuine_named_one() {
        let filter = [0x4e; 33];
        let signed = |signature: Vec<u8>| quil_types::proto::global::FrameHeader {
            public_key_signature_bls48581: Some(
                quil_types::proto::keys::Bls48581AggregateSignature {
                    signature,
                    ..Default::default()
                },
            ),
            ..carried_copy(&filter, 0x47, &[])
        };
        let genuine = signed(vec![1]);
        let named = quil_crypto::poseidon::hash_bytes_to_32(&genuine.output).unwrap();
        let verify: CarriedVerifier = Arc::new(|header: quil_types::proto::global::FrameHeader| {
            Box::pin(async move {
                match header.public_key_signature_bls48581.unwrap().signature == vec![1] {
                    true => CopyVerdict::Certified,
                    false => CopyVerdict::CertificateRefused,
                }
            })
        });
        let forgeries: Vec<_> = (0..100u8).map(|index| signed(vec![2, index])).collect();
        let key = (filter.to_vec(), 7);
        let mut reached = None;
        for search in 1..=3 {
            let (skip, rechecked) = carried_searched()
                .get_mut(&key)
                .map(|kept| {
                    kept.resume();
                    let skip: std::collections::HashSet<CopyId> =
                        kept.refused.iter().chain(&kept.retried).copied().collect();
                    let rechecked: std::collections::HashSet<CopyId> = kept
                        .retry
                        .keys()
                        .filter(|id| !kept.retried.contains(id))
                        .copied()
                        .collect();
                    (skip, rechecked)
                })
                .unwrap_or_default();
            let mut copies =
                CarriedCopies::new(&filter, 7, Some(named), skip).with_rechecked(rechecked);
            copies.offer(10, forgeries.clone());
            copies.offer(11, vec![genuine.clone()]);
            copies
                .check(
                    Some(&verify),
                    tokio::time::Instant::now() + std::time::Duration::from_secs(60),
                )
                .await;
            let (best, certified) = copies.best();
            keep_carried_search(
                key.clone(),
                SearchOutcome {
                    state: Some(search_state(
                        &best,
                        &certified,
                        search_incomplete(false, 0, 0, copies.unverified),
                        0,
                    )),
                    named: Some(named),
                    retried: &copies.retried,
                    still_carried: Some(&copies.still_carried),
                    progress: true,
                    verified: true,
                    ..Default::default()
                },
            );
            if certified.contains(&carried_copy_digest(&genuine)) {
                reached = Some(search);
                break;
            }
        }
        assert_eq!(reached, Some(2));
    }

    /// A copy anchored where GLOBAL could not have taken it (at or above
    /// the GLOBAL frame carrying it, or further below it than GLOBAL's
    /// lockstep window) is dropped without a check, so it uses up none and
    /// cannot stall replay as a wait, with or without a check to run; it is
    /// not remembered as refused, as filtering it again costs nothing. GLOBAL
    /// checks nothing else of a header's anchor: a genuine copy anchored
    /// below the frame's predecessor is taken.
    #[tokio::test]
    async fn a_copy_anchored_where_global_could_not_take_it_is_dropped_unchecked() {
        let filter = [0x41; 33];
        let anchored = |output: u8, anchor: u64| quil_types::proto::global::FrameHeader {
            global_frame_number: anchor,
            ..carried_copy(&filter, output, &[])
        };
        let verify = checked_as_genuine();
        let named = quil_crypto::poseidon::hash_bytes_to_32(&[0x47; 32]).unwrap();
        for verify in [Some(&verify), None] {
            let mut copies = CarriedCopies::new(&filter, 7, Some(named), Default::default());
            copies
                .take(10, vec![anchored(2, 10), anchored(3, 12)], verify)
                .await;
            copies.take(30, vec![anchored(4, 5)], verify).await;
            assert_eq!(copies.verifies, 0, "none checked");
            assert_eq!((copies.refused.len(), copies.implausible), (0, 3));
            copies.take(31, vec![anchored(0x47, 18)], verify).await;
            assert_eq!(copies.best().0, [(31, anchored(0x47, 18))]);
        }
        // Anchored at GLOBAL frame 1, below any predecessor in these tests.
        let mut copies = CarriedCopies::new(&filter, 7, None, Default::default());
        copies
            .take(10, vec![anchored(0x47, 1)], Some(&verify))
            .await;
        assert_eq!(
            copies.best().0,
            [(10, anchored(0x47, 1))],
            "anchored below its predecessor, still taken"
        );
    }

    /// Copies are gathered from every GLOBAL frame read before any is
    /// checked, the named ones checked first: forged copies read before the
    /// genuine one cannot use up a search's checks. Forgeries of the named
    /// output itself (other certificates) take a search's checks, and the
    /// next search passes over those refused, kept ahead of older refusals
    /// while it still reads them, until the genuine copy is reached. Copies
    /// that differ only in the unbound bitmask and public key of a
    /// commonware certificate are one copy, kept without those bytes.
    #[tokio::test]
    async fn forged_copies_cannot_starve_the_genuine_named_one() {
        let filter = [0x43; 33];
        let signed = |output: u8, signature: Vec<u8>| quil_types::proto::global::FrameHeader {
            public_key_signature_bls48581: Some(
                quil_types::proto::keys::Bls48581AggregateSignature {
                    signature,
                    ..Default::default()
                },
            ),
            ..carried_copy(&filter, output, &[])
        };
        let genuine = signed(0x47, vec![1]);
        let named = quil_crypto::poseidon::hash_bytes_to_32(&genuine.output).unwrap();
        let verify: CarriedVerifier = Arc::new(|header: quil_types::proto::global::FrameHeader| {
            Box::pin(async move {
                match (
                    header.output == vec![0x47; 32],
                    header.public_key_signature_bls48581.unwrap().signature == vec![1],
                ) {
                    (true, true) => CopyVerdict::Certified,
                    _ => CopyVerdict::Refused,
                }
            })
        });
        let deadline = || tokio::time::Instant::now() + std::time::Duration::from_secs(60);

        let mut copies = CarriedCopies::new(&filter, 7, Some(named), Default::default());
        for global in 10..15u8 {
            copies.offer(
                global as u64,
                (0..70u8)
                    .map(|index| signed(index, vec![global, index]))
                    .collect(),
            );
        }
        copies.offer(15, vec![genuine.clone()]);
        copies.check(Some(&verify), deadline()).await;
        assert_eq!(
            copies.best(),
            (
                vec![(15, genuine.clone())],
                vec![carried_copy_digest(&genuine)]
            )
        );
        assert_eq!(copies.verifies, 1, "the named copy first");

        let forgeries: Vec<_> = (0..100u8)
            .map(|index| signed(0x47, vec![2, index]))
            .collect();
        let mut copies = CarriedCopies::new(&filter, 7, Some(named), Default::default());
        copies.offer(10, forgeries.clone());
        copies.offer(11, vec![genuine.clone()]);
        assert_eq!(
            (copies.pending.len(), copies.unverified),
            (CARRIED_VERIFIES, 100 - CARRIED_VERIFIES + 1),
            "named copies gathered no more than a search checks"
        );
        copies.check(Some(&verify), deadline()).await;
        assert!(copies.best().0.is_empty());
        let key = (filter.to_vec(), 7);
        keep_carried_search(
            key.clone(),
            SearchOutcome {
                state: Some(CarriedState::Failed),
                named: Some(named),
                refused: &copies.refused,
                still_carried: Some(&copies.still_carried),
                passed_over: copies.passed_over,
                ..Default::default()
            },
        );
        let skip: std::collections::HashSet<CopyId> =
            carried_searched()[&key].refused.iter().copied().collect();
        let mut again = CarriedCopies::new(&filter, 7, Some(named), skip);
        again.offer(10, forgeries);
        again.offer(11, vec![genuine.clone()]);
        again.check(Some(&verify), deadline()).await;
        assert_eq!(again.passed_over, CARRIED_VERIFIES);
        assert_eq!(again.best().0, [(11, genuine.clone())]);

        // Refusals the search still read outlive older ones.
        let (oldest, newest) = (id(u64::MAX - 1), id(u64::MAX));
        keep_carried_search(
            key.clone(),
            SearchOutcome {
                state: Some(CarriedState::Failed),
                named: Some(named),
                refused: &(0..CARRIED_REFUSED as u64).map(id).collect::<Vec<_>>(),
                ..Default::default()
            },
        );
        keep_carried_search(
            key.clone(),
            SearchOutcome {
                state: Some(CarriedState::Failed),
                named: Some(named),
                refused: &[oldest],
                ..Default::default()
            },
        );
        keep_carried_search(
            key.clone(),
            SearchOutcome {
                state: Some(CarriedState::Failed),
                named: Some(named),
                refused: &[newest],
                still_carried: Some(&[id(2)].into()),
                passed_over: 1,
                ..Default::default()
            },
        );
        {
            let searches = carried_searched();
            let search = &searches[&key];
            assert!(
                search.refused.contains(&id(2))
                    && search.refused.contains(&newest)
                    && search.refused.contains(&oldest)
            );
            assert!(
                !search.refused.contains(&id(0)) && !search.refused.contains(&id(1)),
                "the oldest no longer read go first"
            );
            assert_eq!(
                search.failed, 4,
                "the failure back-off doubles while searches make no progress"
            );
            assert_eq!(search.fail_backoff(), CARRIED_FAIL_RETRY * 8);
        }

        let magic = |extra: &[u8]| {
            let mut signature = quil_cw_consensus::app_cert::CW_CERT_MAGIC.to_vec();
            signature.extend_from_slice(extra);
            signature
        };
        let commonware = |bitmask: Vec<u8>, public_key: Option<Vec<u8>>| {
            quil_types::proto::global::FrameHeader {
                public_key_signature_bls48581: Some(
                    quil_types::proto::keys::Bls48581AggregateSignature {
                        signature: magic(&[7]),
                        bitmask,
                        public_key: public_key.map(|key_value| {
                            quil_types::proto::keys::Bls48581g2PublicKey { key_value }
                        }),
                    },
                ),
                ..carried_copy(&filter, 0x48, &[])
            }
        };
        let named = quil_crypto::poseidon::hash_bytes_to_32(&[0x48; 32]).unwrap();
        let mut copies = CarriedCopies::new(&filter, 7, Some(named), Default::default());
        copies
            .take(
                10,
                vec![
                    commonware(vec![9; 4], Some(vec![9; 8])),
                    commonware(Vec::new(), None),
                ],
                None,
            )
            .await;
        assert_eq!(
            copies.best().0,
            [(10, commonware(Vec::new(), None))],
            "one copy, without the unbound bytes"
        );
    }

    /// A check is bounded by what is left of the search's time: none starts
    /// once that has passed, and one running past it is unavailable, so the
    /// search ends without failing its archive as a source.
    #[tokio::test]
    async fn a_check_past_the_time_left_is_unavailable() {
        let copy = carried_copy(&[0x42; 33], 0x47, &[]);
        let verify = checked_as_genuine();
        let slow: CarriedVerifier = Arc::new(|_: quil_types::proto::global::FrameHeader| {
            Box::pin(async {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                CopyVerdict::Certified
            })
        });
        let soon = tokio::time::Instant::now() + std::time::Duration::from_millis(200);
        assert_eq!(
            check_within(&verify, &copy, soon).await,
            Some(CopyVerdict::Certified)
        );
        assert_eq!(
            check_within(
                &slow,
                &copy,
                tokio::time::Instant::now() + std::time::Duration::from_millis(50)
            )
            .await,
            Some(CopyVerdict::Unavailable)
        );
        assert_eq!(
            check_within(&verify, &copy, tokio::time::Instant::now()).await,
            None,
            "out of time"
        );
    }

    /// A search that fails with nothing found keeps the copies refused
    /// before and backs off: the next attempt, even told the named parent
    /// only now, does not read the GLOBAL frames again at once.
    #[tokio::test]
    async fn a_failed_search_keeps_what_it_refused_and_backs_off() {
        let filter = vec![0x3e; 33];
        keep((filter.clone(), 7), CarriedState::Missed, &[id(42)]);
        let mut syncer = cache_only_syncer();
        syncer.master_stream_addr = "127.0.0.1:1".into();
        let named = Some([7; 32]);
        let failed = syncer
            .carried_shard_headers(&filter, 7, &[9], named, None)
            .await
            .unwrap_err();
        assert!(failed.to_string().contains("archive connect"), "{failed}");
        let (state, refused) = carried_searched()
            .get(&(filter.clone(), 7))
            .map(|search| {
                (
                    search.state.clone(),
                    search.refused.iter().copied().collect::<Vec<_>>(),
                )
            })
            .unwrap();
        assert_eq!((state, refused), (CarriedState::Failed, vec![id(42)]));
        let backing_off = syncer
            .carried_shard_headers(&filter, 7, &[9], named, None)
            .await
            .unwrap_err();
        assert!(
            backing_off.to_string().contains("cut short"),
            "{backing_off}"
        );
    }

    /// The certified copy as replay would check it, here by its output and
    /// attestation: the genuine output (0x47) with the attestation [1, 2, 3].
    fn checked_as_genuine() -> CarriedVerifier {
        Arc::new(|header: quil_types::proto::global::FrameHeader| {
            Box::pin(async move {
                match (
                    header.output == vec![0x47; 32],
                    header.storage_attestation.as_slice(),
                ) {
                    (false, _) => CopyVerdict::Refused,
                    (true, []) | (true, [1, 2, 3]) => CopyVerdict::Certified,
                    (true, _) => CopyVerdict::AttestationRefused,
                }
            })
        })
    }

    /// GLOBAL keeps a header whose execution failed, so anyone who gets a
    /// bundle into GLOBAL can plant copies of a frame's header. Each copy is
    /// checked before it is kept: a forged copy read first ends no search,
    /// whether the frame after it names a parent or is missing too, and
    /// copies of the genuine output varying only their attestation bytes
    /// are one copy, its attestation checked once. Unchecked, four
    /// forgeries read first still cannot crowd out the named copy.
    /// Implausible copies are not kept, more forgeries than one search
    /// checks are passed over by the next, as are copies rejected before.
    #[tokio::test]
    async fn a_forged_copy_carried_first_cannot_crowd_out_the_named_one() {
        let filter = [0x3c; 33];
        let copy = |output: u8, attestation: &[u8]| carried_copy(&filter, output, attestation);
        let genuine = copy(0x47, &[1, 2, 3]);
        let named = quil_crypto::poseidon::hash_bytes_to_32(&genuine.output).unwrap();
        let verify = checked_as_genuine();
        let fresh = |named| CarriedCopies::new(&filter, 7, named, Default::default());

        for named in [Some(named), None] {
            let mut copies = fresh(named);
            assert!(
                !copies.take(10, vec![copy(0x46, &[9])], Some(&verify)).await,
                "a forged attested copy ends no search"
            );
            assert_eq!(
                copies.take(11, vec![genuine.clone()], Some(&verify)).await,
                named.is_some(),
                "only the certified named copy with the attestation ends it"
            );
            assert_eq!(
                copies.best(),
                (
                    vec![(11, genuine.clone())],
                    vec![carried_copy_digest(&genuine)]
                )
            );
            assert_eq!(copies.refused, [carried_copy_key(&copy(0x46, &[9]))]);
        }

        let mut copies = fresh(Some(named));
        assert!(
            !copies.take(10, vec![copy(0x47, &[])], Some(&verify)).await,
            "certified and named, without the attestation"
        );
        let variants: Vec<_> = (0..100u8)
            .map(|byte| copy(0x47, &[1, 2, 3, byte]))
            .chain([genuine.clone()])
            .collect();
        assert!(
            !copies.take(11, variants, Some(&verify)).await,
            "a few attested forms are checked, and they fail"
        );
        assert_eq!(
            copies.verifies,
            1 + CARRIED_ATTESTED_FORMS,
            "one copy, a bounded number of its attested forms"
        );
        assert_eq!(
            copies.best().0,
            [(10, copy(0x47, &[]))],
            "kept with that field cleared"
        );
        let mut copies = fresh(Some(named));
        assert!(
            copies
                .take(10, vec![copy(0x47, &[9]), genuine.clone()], Some(&verify))
                .await,
            "a forged attested form read first does not hide the genuine one"
        );
        assert_eq!(copies.best().0, [(10, genuine.clone())]);

        // Unchecked (no check to run), forgeries read first cannot crowd out
        // the named copy: only named copies go to replay unchecked.
        let mut copies = fresh(Some(named));
        for output in 1..=4 {
            assert!(
                !copies
                    .take(10 + output as u64, vec![copy(output, &[])], None)
                    .await
            );
        }
        assert!(!copies.take(15, vec![copy(0x47, &[])], None).await);
        let (best, certified) = copies.best();
        assert_eq!(best, [(15, copy(0x47, &[]))]);
        assert_eq!(copies.unverified, 4, "the others wait for a check");
        assert!(certified.is_empty());

        let mut unsigned = copy(1, &[]);
        unsigned.public_key_signature_bls48581 = None;
        let mut with_requests = copy(2, &[]);
        with_requests.requests_root = vec![7; 32];
        let mut another = copy(3, &[]);
        another.frame_number = 8;
        let mut copies = fresh(None);
        assert!(
            !copies
                .take(10, vec![unsigned, with_requests, another], None)
                .await
        );
        assert!(copies.best().0.is_empty());

        let forgeries: Vec<_> = (100..200u8).map(|output| copy(output, &[])).collect();
        let mut copies = fresh(None);
        copies.take(10, forgeries.clone(), Some(&verify)).await;
        copies.take(11, vec![genuine.clone()], Some(&verify)).await;
        assert!(
            copies.best().0.is_empty(),
            "the genuine copy waits beyond this search's checks"
        );
        assert_eq!(copies.unverified, forgeries.len() - CARRIED_VERIFIES + 1);
        let refused: std::collections::HashSet<CopyId> = copies.refused.iter().copied().collect();
        assert_eq!(refused.len(), CARRIED_VERIFIES);
        let mut again = CarriedCopies::new(&filter, 7, None, refused);
        again.take(10, forgeries, Some(&verify)).await;
        again.take(11, vec![genuine.clone()], Some(&verify)).await;
        assert_eq!(again.passed_over, CARRIED_VERIFIES);
        assert_eq!(again.best().0, [(11, genuine.clone())]);

        let forged = copy(0x46, &[]);
        let mut copies =
            CarriedCopies::new(&filter, 7, Some(named), [carried_copy_key(&forged)].into());
        copies.take(10, vec![forged], None).await;
        copies.take(11, vec![genuine.clone()], None).await;
        assert_eq!(copies.passed_over, 1);
        assert_eq!(
            copies.best().0,
            [(11, copy(0x47, &[]))],
            "unchecked, kept with its attestation cleared"
        );
    }

    /// A copy is kept with its attestation only when that attestation passed
    /// the check in full: a forged attestation on the genuine copy, read
    /// first or after it, leaves the copy kept with that field cleared, and
    /// the attested form is remembered as refused; a copy that could not be
    /// checked is kept cleared too. A forged attestation never reaches
    /// replay, which could store it without its possession proof.
    #[tokio::test]
    async fn only_an_attestation_checked_in_full_is_kept() {
        let filter = [0x3f; 33];
        let copy = |attestation: &[u8]| carried_copy(&filter, 0x47, attestation);
        let verify = checked_as_genuine();
        let named = quil_crypto::poseidon::hash_bytes_to_32(&[0x47; 32]).unwrap();
        for read in [vec![copy(&[9])], vec![copy(&[]), copy(&[9])]] {
            let mut copies = CarriedCopies::new(&filter, 7, Some(named), Default::default());
            for (global, header) in read.into_iter().enumerate() {
                copies
                    .take(10 + global as u64, vec![header], Some(&verify))
                    .await;
            }
            assert_eq!(
                copies.best(),
                (vec![(10, copy(&[]))], vec![carried_copy_digest(&copy(&[]))])
            );
            assert_eq!(copies.retried, [attested_form_digest(&copy(&[9]))]);
        }
        let mut copies = CarriedCopies::new(&filter, 7, Some(named), Default::default());
        copies.take(10, vec![copy(&[1, 2, 3])], None).await;
        assert_eq!(
            copies.best(),
            (vec![(10, copy(&[]))], Vec::new()),
            "unchecked: cleared"
        );
        let mut copies = CarriedCopies::new(
            &filter,
            7,
            Some(named),
            [attested_form_digest(&copy(&[9]))].into(),
        );
        assert!(!copies.take(10, vec![copy(&[9])], Some(&verify)).await);
        assert_eq!(
            copies.best().0,
            [(10, copy(&[]))],
            "an attestation refused before is passed over"
        );
        assert_eq!(copies.passed_over, 1);
        assert!(
            copies.take(11, vec![copy(&[1, 2, 3])], Some(&verify)).await,
            "another attested form is checked"
        );
        assert_eq!(copies.best().0, [(11, copy(&[1, 2, 3]))]);

        // Gathered, a named copy with an attestation is checked at once: a
        // search stops reading only once one passes in full.
        let mut copies = CarriedCopies::new(&filter, 7, Some(named), Default::default());
        let soon = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
        copies.offer(10, vec![copy(&[9])]);
        copies.check_named_attested(Some(&verify), soon).await;
        assert!(!copies.done(), "a forged attestation: reading goes on");
        copies.offer(11, vec![copy(&[1, 2, 3])]);
        copies.check_named_attested(Some(&verify), soon).await;
        assert!(copies.done());
    }

    /// A copy whose attestation fails is rejected, and the next answer,
    /// from the cache as in production, still reaches that copy with its
    /// attestation field cleared; once that fails too, every copy has, and
    /// the GLOBAL frames are read again only after the retry interval.
    #[tokio::test]
    async fn a_rejected_attested_copy_still_yields_its_cleared_form() {
        use quil_engine::prover_tree_syncer::{next_carried_copy, NoCarriedCopy};
        let filter = vec![0x3d; 33];
        let attested = carried_copy(&filter, 0x47, &[1, 2, 3]);
        let cleared = carried_copy(&filter, 0x47, &[]);
        keep(
            (filter.clone(), 7),
            CarriedState::Found {
                copies: vec![(9, attested.clone())],
                certified: vec![carried_copy_digest(&attested)],
            },
            &[],
        );
        let syncer = cache_only_syncer();
        let next = || async {
            next_carried_copy(
                &syncer
                    .carried_shard_headers(&filter, 7, &[9], None, None)
                    .await
                    .unwrap(),
                &filter,
                7,
                None,
            )
        };
        let (_, first, id) = next().await.unwrap();
        assert_eq!(
            (first, id),
            (attested.clone(), carried_copy_digest(&attested))
        );
        syncer.reject_carried_copy(&filter, 7, id);
        let (_, then, id) = next().await.unwrap();
        assert_eq!((then, id), (cleared.clone(), carried_copy_digest(&cleared)));
        syncer.reject_carried_copy(&filter, 7, id);
        assert_eq!(next().await, Err(NoCarriedCopy::Exhausted));
        syncer.reject_carried_shard_headers(&filter, 7);
        assert!(
            syncer
                .carried_shard_headers(&filter, 7, &[9], None, None)
                .await
                .is_err(),
            "read again only after the retry interval"
        );
    }

    #[test]
    fn only_a_broken_connection_is_closed_after_a_failed_read() {
        use quil_rpc::ArchiveClientError::Rpc;
        for status in [
            tonic::Status::unavailable(""),
            tonic::Status::unknown(""),
            tonic::Status::cancelled(""),
            tonic::Status::deadline_exceeded(""),
        ] {
            assert!(read_breaks_connection(&Rpc(status)));
        }
        for status in [
            tonic::Status::resource_exhausted("busy"),
            tonic::Status::not_found(""),
            tonic::Status::permission_denied(""),
        ] {
            assert!(!read_breaks_connection(&Rpc(status)));
        }
        assert!(read_breaks_connection(
            &quil_rpc::ArchiveClientError::InvalidEndpoint("".into())
        ));
    }
}

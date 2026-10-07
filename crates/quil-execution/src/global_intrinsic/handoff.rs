//! Global authorization for committee changes, splits and merges.
//!
//! Records live in the authenticated GLOBAL hypergraph, not a local journal or
//! shard-store side table. Scheduling is an internal global-execution operation:
//! network messages may supply closing certificates, but cannot choose successor
//! members, checkpoints or generations. Runtime scheduling and source sealing
//! must be installed before this protocol can replace legacy committee rebuilds.

use crate::global_schema::GLOBAL_INTRINSIC_ADDRESS;
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
use num_bigint::BigInt;
use quil_cw_consensus::handoff::{
    put_bytes, verify_seal, Checkpoint, Cursor, Seal, Session, MAX_FILTER_BYTES, MAX_MEMBERS,
    MAX_RECORD_BYTES,
};
use quil_types::error::{QuilError, Result};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;

pub const TYPE_COMMITTEE_HANDOFF: u32 = 0x0321;
pub const MAX_TRANSITION_SHARDS: usize = 512;

/// Second leaf of every authorization vertex. The records share the global
/// prover shard with prover and allocation vertices (which carry a type-hash
/// leaf instead), so whole-shard maintenance can tell them apart.
const RECORD_MARKER: &[u8] = b"quil/global/app-handoff/record/v1";

/// Whether a raw vertex blob from the global prover shard is one of this
/// module's authorization records. A whole-shard wipe/rebuild (the flag-day
/// prover-tree reset) must carry these across: losing them would strand every
/// managed application between an unverifiable history and no successor.
pub fn is_record_blob(blob: &[u8]) -> bool {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    let Ok(root) = quil_tries::deserialize_go_tree(blob) else {
        return false;
    };
    tree.root = root;
    tree.get(&[1]).is_some_and(|marker| marker == RECORD_MARKER)
}

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("global committee handoff: {message}"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DesiredCommittee {
    pub filter: Vec<u8>,
    pub members: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub committee: DesiredCommittee,
    pub generation: u64,
    /// The last session of this exact filter, even if the filter was retired.
    pub previous: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub frame: u64,
    pub sources: Vec<Session>,
    /// Source-side shard ranges on which no committee ever formed. They have no
    /// consensus history to seal; they only complete the covered range. A deep
    /// split registers such shards (the co-path "spine") beside its two leaves.
    pub vacant: Vec<Vec<u8>>,
    /// A target with no members is likewise authorized as a range only: no
    /// session is created for it, and it receives an ordinary first session
    /// once provers become eligible there.
    pub targets: Vec<Target>,
}

impl Request {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        if self.sources.is_empty()
            || self.targets.is_empty()
            || self.sources.len() > MAX_TRANSITION_SHARDS
            || self.targets.len() > MAX_TRANSITION_SHARDS
        {
            return Err(invalid("invalid source/target count"));
        }
        let mut out = b"QHRQ\x01".to_vec();
        out.extend_from_slice(&self.frame.to_be_bytes());
        out.extend_from_slice(&(self.sources.len() as u32).to_be_bytes());
        for source in &self.sources {
            put_bytes(&mut out, &source.encode()?)?;
            if out.len() > MAX_RECORD_BYTES {
                return Err(invalid("request exceeds size limit"));
            }
        }
        out.extend_from_slice(&(self.targets.len() as u32).to_be_bytes());
        for target in &self.targets {
            put_bytes(&mut out, &target.committee.filter)?;
            out.extend_from_slice(&target.generation.to_be_bytes());
            out.push(u8::from(target.previous.is_some()));
            if let Some(id) = target.previous {
                out.extend_from_slice(&id);
            }
            out.extend_from_slice(&(target.committee.members.len() as u32).to_be_bytes());
            for key in &target.committee.members {
                put_bytes(&mut out, key)?;
            }
            if out.len() > MAX_RECORD_BYTES {
                return Err(invalid("request exceeds size limit"));
            }
        }
        out.extend_from_slice(&(self.vacant.len() as u32).to_be_bytes());
        for filter in &self.vacant {
            put_bytes(&mut out, filter)?;
        }
        if out.len() > MAX_RECORD_BYTES {
            return Err(invalid("request exceeds size limit"));
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(bytes)?;
        c.magic(b"QHRQ\x01")?;
        let frame = c.u64()?;
        let n = c.count(MAX_TRANSITION_SHARDS, 4)?;
        let mut sources = Vec::with_capacity(n);
        for _ in 0..n {
            sources.push(Session::decode(&c.bytes(MAX_RECORD_BYTES)?)?);
        }
        let n = c.count(MAX_TRANSITION_SHARDS, 17)?;
        let mut targets = Vec::with_capacity(n);
        for _ in 0..n {
            let filter = c.bytes(MAX_FILTER_BYTES)?;
            let generation = c.u64()?;
            let previous = match c.array::<1>()?[0] {
                0 => None,
                1 => Some(c.array()?),
                _ => return Err(invalid("invalid previous-session flag")),
            };
            let n = c.count(MAX_MEMBERS, 4 + quil_crypto::FALCON_PUBLIC_KEY_LEN)?;
            let mut members = Vec::with_capacity(n);
            for _ in 0..n {
                members.push(c.bytes(quil_crypto::FALCON_PUBLIC_KEY_LEN)?);
            }
            targets.push(Target {
                committee: DesiredCommittee { filter, members },
                generation,
                previous,
            });
        }
        let n = c.count(MAX_TRANSITION_SHARDS, 4 + 32)?;
        let mut vacant = Vec::with_capacity(n);
        for _ in 0..n {
            vacant.push(c.bytes(MAX_FILTER_BYTES)?);
        }
        c.finish()?;
        let request = Self {
            frame,
            sources,
            vacant,
            targets,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<()> {
        if self.frame == 0
            || self.sources.is_empty()
            || self.targets.is_empty()
            || self.sources.len() > MAX_TRANSITION_SHARDS
            || self.targets.len() > MAX_TRANSITION_SHARDS
            || self.vacant.len() > MAX_TRANSITION_SHARDS
            || self.vacant.windows(2).any(|p| p[0] >= p[1])
            || self.targets.iter().all(|t| t.committee.members.is_empty())
            || self.sources.windows(2).any(|p| p[0].filter >= p[1].filter)
            || self
                .targets
                .windows(2)
                .any(|p| p[0].committee.filter >= p[1].committee.filter)
        {
            return Err(invalid("noncanonical transition"));
        }
        let chain = self.sources[0].chain_id;
        for source in &self.sources {
            source.validate()?;
            if source.chain_id != chain {
                return Err(invalid("sources belong to different chains"));
            }
        }
        for target in &self.targets {
            if target.generation == 0 {
                return Err(invalid("successor generation cannot be zero"));
            }
            if target.committee.members.is_empty() {
                if !(32..=MAX_FILTER_BYTES).contains(&target.committee.filter.len()) {
                    return Err(invalid("invalid vacant target filter"));
                }
                continue;
            }
            Session {
                chain_id: chain,
                filter: target.committee.filter.clone(),
                generation: target.generation,
                genesis: [0; 32],
                base_frame: 0,
                authorization: [0; 32],
                members: target.committee.members.clone(),
            }
            .validate()?;
        }
        let old: Vec<_> = self.sources.iter().map(|s| s.filter.clone())
            .chain(self.vacant.iter().cloned()).collect();
        let new: Vec<_> = self
            .targets
            .iter()
            .map(|s| s.committee.filter.clone())
            .collect();
        if partition(&old)? != partition(&new)? {
            return Err(invalid("transition changes its covered address range"));
        }
        Ok(())
    }

    pub fn id(&self) -> Result<[u8; 32]> {
        self.validate()?;
        Ok(Sha256::digest(self.encode()?).into())
    }
}

/// Reduce adjacent siblings to their parent to compare prefix-free partitions
/// by the ranges they cover, rather than their number of shards or encoding.
fn partition(filters: &[Vec<u8>]) -> Result<([u8; 32], BTreeSet<Vec<bool>>)> {
    let app: [u8; 32] = filters
        .first()
        .and_then(|f| f.get(..32))
        .ok_or_else(|| invalid("empty partition"))?
        .try_into()
        .unwrap();
    let mut paths = BTreeSet::new();
    for filter in filters {
        if filter.get(..32) != Some(app.as_slice()) {
            return Err(invalid("transition spans applications"));
        }
        if filter.len() == 33 && filter[32] >= 64 {
            return Err(invalid("legacy shard index exceeds the 64-way grid"));
        }
        let (_, path) = quil_forest::decode_shard_filter_or_root(filter, 32)
            .ok_or_else(|| invalid("invalid shard filter"))?;
        if path.len() > 256 || !paths.insert(path) {
            return Err(invalid("duplicate shard range"));
        }
    }
    let ordered: Vec<_> = paths.iter().collect();
    if ordered.windows(2).any(|pair| pair[1].starts_with(pair[0])) {
        return Err(invalid("overlapping shard ranges"));
    }
    loop {
        let pair = paths.iter().find_map(|path| {
            if path.last() != Some(&false) {
                return None;
            }
            let mut sibling = path.clone();
            *sibling.last_mut().unwrap() = true;
            paths.contains(&sibling).then(|| (path.clone(), sibling))
        });
        let Some((mut left, right)) = pair else {
            break;
        };
        paths.remove(&left);
        paths.remove(&right);
        left.pop();
        paths.insert(left);
    }
    Ok((app, paths))
}

/// The only network operation: supply an old-session Simplex finalization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateSubmission {
    pub seal: Seal,
    pub certificate: Vec<u8>,
}
impl CertificateSubmission {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = TYPE_COMMITTEE_HANDOFF.to_be_bytes().to_vec();
        put_bytes(&mut out, &self.seal.encode())?;
        put_bytes(&mut out, &self.certificate)?;
        if out.len() > MAX_RECORD_BYTES {
            return Err(invalid("certificate submission exceeds size limit"));
        }
        Ok(out)
    }
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(bytes)?;
        c.magic(&TYPE_COMMITTEE_HANDOFF.to_be_bytes())?;
        let seal = Seal::decode(&c.bytes(MAX_RECORD_BYTES)?)?;
        let certificate = c.bytes(MAX_RECORD_BYTES)?;
        c.finish()?;
        Ok(Self { seal, certificate })
    }
}

/// Headers a seal submission may carry: its source's app frames from the one
/// after GLOBAL's executed tip through the sealed checkpoint.
pub const MAX_DRAIN_HEADERS: usize = 8;

/// A closing certificate and the drain headers GLOBAL needs to accept it.
///
/// A seal is accepted only once GLOBAL has executed its source through the
/// sealed checkpoint. A running session's frames are carried by later ones
/// when a header misses its lockstep window, but a sealed session produces no
/// later frame: if its last headers miss their window GLOBAL never executes
/// them, the seal is refused until the fence (#699). The seal therefore brings
/// them: canonical app frame headers (`frame_header::FrameHeader` bytes) of the
/// source, consecutive, from GLOBAL's executed tip + 1 through the checkpoint.
/// GLOBAL executes them outside the window, without storage audit or rewards,
/// from [`seal_drain_frame`].
///
/// Encoding: a [`CertificateSubmission`], then, when there are drain headers,
/// `count(u8) ‖ count × bytes`. Without them the bytes are exactly a
/// [`CertificateSubmission`]'s, which is what GLOBAL records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealSubmission {
    pub submission: CertificateSubmission,
    pub drain: Vec<Vec<u8>>,
}

impl SealSubmission {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = self.submission.to_canonical_bytes()?;
        if !self.drain.is_empty() {
            if self.drain.len() > MAX_DRAIN_HEADERS {
                return Err(invalid("too many drain headers"));
            }
            out.push(self.drain.len() as u8);
            for header in &self.drain {
                put_bytes(&mut out, header)?;
            }
        }
        if out.len() > MAX_RECORD_BYTES {
            return Err(invalid("certificate submission exceeds size limit"));
        }
        Ok(out)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(bytes)?;
        c.magic(&TYPE_COMMITTEE_HANDOFF.to_be_bytes())?;
        let seal = Seal::decode(&c.bytes(MAX_RECORD_BYTES)?)?;
        let certificate = c.bytes(MAX_RECORD_BYTES)?;
        let mut drain = Vec::new();
        if !c.is_finished() {
            let count = usize::from(c.u8()?);
            if count == 0 || count > MAX_DRAIN_HEADERS {
                return Err(invalid("drain header count out of range"));
            }
            for _ in 0..count {
                drain.push(c.bytes(MAX_RECORD_BYTES)?);
            }
        }
        c.finish()?;
        Ok(Self { submission: CertificateSubmission { seal, certificate }, drain })
    }
}

/// From this GLOBAL frame a seal submission may carry drain headers
/// ([`SealSubmission`]); before it one that does is refused, as an older
/// build would. Consensus-affecting for GLOBAL. Fixed on mainnet;
/// `QUIL_SEAL_DRAIN_FRAME` elsewhere, never by default.
pub const MAINNET_SEAL_DRAIN_FRAME: u64 = 865_440;

static SEAL_DRAIN_FRAME: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

thread_local! {
    static SEAL_DRAIN_OVERRIDE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

fn seal_drain_frame_for(network: u8, setting: Option<&str>) -> u64 {
    if network == 0 {
        return MAINNET_SEAL_DRAIN_FRAME;
    }
    setting.and_then(|value| value.parse().ok()).unwrap_or(u64::MAX)
}

/// Fix this process's seal drain frame from its network, and return it.
/// Called at startup before any frame is processed; the first call decides.
pub fn init_seal_drain_frame(network: u8) -> u64 {
    *SEAL_DRAIN_FRAME.get_or_init(|| seal_drain_frame_for(network, std::env::var("QUIL_SEAL_DRAIN_FRAME").ok().as_deref()))
}

pub fn seal_drain_frame() -> u64 {
    if let Some(frame) = SEAL_DRAIN_OVERRIDE.with(|cell| cell.get()) {
        return frame;
    }
    *SEAL_DRAIN_FRAME.get_or_init(|| {
        std::env::var("QUIL_SEAL_DRAIN_FRAME").ok().and_then(|value| value.parse().ok()).unwrap_or(u64::MAX)
    })
}

/// Set the seal drain frame for the calling thread only (tests).
pub fn set_seal_drain_frame_for_thread(frame: Option<u64>) {
    SEAL_DRAIN_OVERRIDE.with(|cell| cell.set(frame));
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Active,
    Sealing([u8; 32]),
    Closed([u8; 32]),
}

mod record_sealed {
    pub trait Sealed {}
}

/// Read-only record access, implemented only by serialized execution state and
/// a committed snapshot. App consensus must use `CommittedView`, since an
/// execution view also contains changes from unfinished global frames.
pub trait Records: record_sealed::Sealed {
    #[doc(hidden)]
    fn handoff_vertex(&self, address: &[u8; 32]) -> Result<Option<Vec<u8>>>;
}

impl record_sealed::Sealed for HypergraphState {}
impl Records for HypergraphState {
    fn handoff_vertex(&self, address: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        self.get(
            &GLOBAL_INTRINSIC_ADDRESS,
            address,
            &vertex_adds_discriminator()?,
        )
    }
}

/// A short-lived view of one durably materialized/synchronized global state.
/// The cursor and all authorization records come from the SAME DB snapshot.
/// Capturing this view does not validate an external sync's certificate or
/// make an application's source data/history ready; those are separate gates.
pub struct CommittedView {
    snapshot: Arc<dyn quil_types::store::SnapshotReadable>,
    frame: u64,
}

impl CommittedView {
    pub fn capture(crdt: &Arc<quil_hypergraph::HypergraphCrdt>) -> Result<Self> {
        HypergraphState::new(crdt.clone())
            .require_full_domain_coverage(&GLOBAL_INTRINSIC_ADDRESS)?;
        let snapshot = crdt.capture_committed_snapshot()?;
        let bytes = snapshot
            .read_record(&quil_store::encoding::global_materialized_cursor_key())?
            .ok_or_else(|| {
                QuilError::ExecutionUnavailable(
                    "global handoff snapshot has no materialized cursor".into(),
                )
            })?;
        let frame = u64::from_be_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| QuilError::Store("corrupt global handoff snapshot cursor".into()))?,
        );
        Ok(Self { snapshot, frame })
    }

    pub fn frame(&self) -> u64 {
        self.frame
    }
}

impl record_sealed::Sealed for CommittedView {}
impl Records for CommittedView {
    fn handoff_vertex(&self, address: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let location = quil_hypergraph::Location {
            app_address: GLOBAL_INTRINSIC_ADDRESS,
            data_address: *address,
        };
        let shard = quil_hypergraph::addressing::shard_key_for_location(&location);
        let id = location.to_id();
        if self
            .snapshot
            .load_vertex_underlying_raw("vertex", "removes", &shard, &id)?
            .is_some()
        {
            return Ok(None);
        }
        Ok(self
            .snapshot
            .load_vertex_underlying_raw("vertex", "adds", &shard, &id)?
            .filter(|b| !b.is_empty()))
    }
}

fn address(kind: &[u8], key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"quil/global/app-handoff/v1/");
    h.update((kind.len() as u32).to_be_bytes());
    h.update(kind);
    h.update((key.len() as u32).to_be_bytes());
    h.update(key);
    h.finalize().into()
}

fn read(state: &impl Records, kind: &[u8], key: &[u8]) -> Result<Option<Vec<u8>>> {
    let Some(blob) = state.handoff_vertex(&address(kind, key))? else {
        return Ok(None);
    };
    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.root = quil_tries::deserialize_go_tree(&blob)
        .map_err(|e| QuilError::Store(format!("corrupt handoff vertex: {e}")))?;
    tree.get(&[0])
        .map(|v| Some(v.to_vec()))
        .ok_or_else(|| QuilError::Store("handoff vertex missing record".into()))
}

fn write(state: &HypergraphState, frame: u64, kind: &[u8], key: &[u8], value: &[u8]) -> Result<()> {
    if value.len() > MAX_RECORD_BYTES {
        return Err(invalid("stored record exceeds size limit"));
    }
    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.insert(&[0], value, &[], &BigInt::from(value.len()))
        .map_err(|e| QuilError::Store(format!("handoff vertex: {e}")))?;
    tree.insert(&[1], RECORD_MARKER, &[], &BigInt::from(RECORD_MARKER.len()))
        .map_err(|e| QuilError::Store(format!("handoff vertex: {e}")))?;
    let blob = quil_tries::serialize_go_tree(tree.root.as_ref())
        .map_err(|e| QuilError::Store(format!("handoff vertex: {e}")))?;
    state.set(
        &GLOBAL_INTRINSIC_ADDRESS,
        &address(kind, key),
        &vertex_adds_discriminator()?,
        frame,
        blob,
    )
}

pub fn session(state: &impl Records, id: &[u8; 32]) -> Result<Option<Session>> {
    read(state, b"session", id)?
        .map(|bytes| {
            let value = Session::decode(&bytes)?;
            if &value.id()? != id {
                return Err(QuilError::Store("handoff session ID mismatch".into()));
            }
            Ok(value)
        })
        .transpose()
}

pub fn head(state: &impl Records, filter: &[u8]) -> Result<Option<Session>> {
    let Some(bytes) = read(state, b"head", filter)? else {
        return Ok(None);
    };
    let id = bytes
        .try_into()
        .map_err(|_| QuilError::Store("corrupt handoff head".into()))?;
    let value = session(state, &id)?
        .ok_or_else(|| QuilError::Store("handoff head has no session".into()))?;
    if value.filter != filter {
        return Err(QuilError::Store("handoff head filter mismatch".into()));
    }
    Ok(Some(value))
}

fn generation_key(filter: &[u8], generation: u64) -> Result<Vec<u8>> {
    let mut key = Vec::new();
    put_bytes(&mut key, filter)?;
    key.extend_from_slice(&generation.to_be_bytes());
    Ok(key)
}

/// Historical certificate lookup. The complete filter is part of the key;
/// advancing the head never overwrites an earlier generation's authorization.
pub fn session_at_generation(
    state: &impl Records,
    filter: &[u8],
    generation: u64,
) -> Result<Option<Session>> {
    let Some(bytes) = read(state, b"generation", &generation_key(filter, generation)?)? else {
        return Ok(None);
    };
    let id = bytes.try_into().map_err(|_| QuilError::Store("corrupt handoff generation index".into()))?;
    let value = session(state, &id)?
        .ok_or_else(|| QuilError::Store("handoff generation has no session".into()))?;
    if value.filter != filter || value.generation != generation {
        return Err(QuilError::Store("handoff generation index mismatch".into()));
    }
    Ok(Some(value))
}

fn create_session(state: &HypergraphState, frame: u64, value: &Session) -> Result<[u8; 32]> {
    let id = value.id()?;
    let key = generation_key(&value.filter, value.generation)?;
    if read(state, b"generation", &key)?.is_some() || session(state, &id)?.is_some() {
        return Err(invalid("session generation already authorized"));
    }
    write(state, frame, b"session", &id, &value.encode()?)?;
    write(state, frame, b"generation", &key, &id)?;
    write(state, frame, b"head", &value.filter, &id)?;
    // Once an application enters the protocol, an unregistered child/alias
    // cannot regain legacy authorization by choosing a different full filter.
    write(state, frame, b"managed-app", &value.filter[..32], &[1])?;
    Ok(id)
}

pub fn manages_application(state: &impl Records, filter: &[u8]) -> Result<bool> {
    let app = filter.get(..32).ok_or_else(|| invalid("filter lacks application address"))?;
    match read(state, b"managed-app", app)?.as_deref() {
        None => Ok(false),
        Some([1]) => Ok(true),
        Some(_) => Err(QuilError::Store("corrupt handoff application marker".into())),
    }
}

pub fn status(state: &impl Records, id: &[u8; 32]) -> Result<Status> {
    let bytes = read(state, b"status", id)?
        .ok_or_else(|| QuilError::Store("session status absent".into()))?;
    match bytes.as_slice() {
        [0] => Ok(Status::Active),
        [kind @ (1 | 2), rest @ ..] if rest.len() == 32 => {
            let request = rest.try_into().unwrap();
            Ok(if *kind == 1 {
                Status::Sealing(request)
            } else {
                Status::Closed(request)
            })
        }
        _ => Err(QuilError::Store("corrupt session status".into())),
    }
}

fn set_status(
    state: &HypergraphState,
    frame: u64,
    id: &[u8; 32],
    kind: u8,
    request: Option<&[u8; 32]>,
) -> Result<()> {
    let mut bytes = vec![kind];
    if let Some(id) = request {
        bytes.extend_from_slice(id);
    }
    write(state, frame, b"status", id, &bytes)
}

fn atomic<T>(state: &HypergraphState, f: impl FnOnce() -> Result<T>) -> Result<T> {
    state.require_full_domain_coverage(&GLOBAL_INTRINSIC_ADDRESS)?;
    let checkpoint = state.changeset_len();
    let result = f();
    if result.is_err() {
        state.rollback_to(checkpoint);
    }
    result
}

/// Trusted network initialization or audited legacy migration only. This is
/// deliberately not exposed as a network operation. Generation zero denotes
/// an existing legacy source; every successor receives a positive generation.
pub fn initialize(state: &HypergraphState, frame: u64, initial: &Session) -> Result<()> {
    atomic(state, || {
        initial.validate()?;
        legacy::refuse_unaudited_generation_zero(initial)?;
        partition(&[initial.filter.clone()])?;
        if initial.generation > 1 || head(state, &initial.filter)?.is_some() {
            return Err(invalid(
                "session already initialized or initial generation invalid",
            ));
        }
        let id = create_session(state, frame, initial)?;
        // An explicit empty origin identifies trusted initialization. Missing
        // origin records must not silently downgrade a successor to genesis.
        write(state, frame, b"origin", &id, &[])?;
        set_status(state, frame, &id, 0, None)?;
        record_member_rings(state, frame, &id, initial, &[], false)
    })
}

/// Called by deterministic global membership/topology scheduling, never with
/// an untrusted wire member list. It reserves sources while they close in their
/// existing consensus sessions. Committing this request does NOT activate targets.
pub fn schedule(
    state: &HypergraphState,
    frame: u64,
    sources: Vec<Vec<u8>>,
    targets: Vec<DesiredCommittee>,
) -> Result<Request> {
    schedule_with_vacant(state, frame, sources, Vec::new(), targets)
}

/// [`schedule`] for a topology change whose source side includes shard ranges
/// on which no committee ever formed (`vacant`). The caller vouches that each
/// has no session; a range with one must be a source.
pub fn schedule_with_vacant(
    state: &HypergraphState,
    frame: u64,
    mut sources: Vec<Vec<u8>>,
    mut vacant: Vec<Vec<u8>>,
    mut targets: Vec<DesiredCommittee>,
) -> Result<Request> {
    atomic(state, || {
        vacant.sort();
        for filter in &vacant {
            if head(state, filter)?.is_some() {
                return Err(invalid("a range with a session cannot be declared vacant"));
            }
        }
        if sources.is_empty()
            || sources.len() > MAX_TRANSITION_SHARDS
            || targets.len() > MAX_TRANSITION_SHARDS
        {
            return Err(invalid("invalid transition size"));
        }
        sources.sort();
        targets.sort_by(|a, b| a.filter.cmp(&b.filter));
        let mut source_sessions = Vec::new();
        let mut budget = 0usize;
        for filter in &sources {
            let source = head(state, filter)?.ok_or_else(|| invalid("source session absent"))?;
            if status(state, &source.id()?)? != Status::Active {
                return Err(invalid("source session is already closing or closed"));
            }
            budget += source.encode()?.len();
            if budget > MAX_RECORD_BYTES {
                return Err(invalid("request exceeds size limit"));
            }
            source_sessions.push(source);
        }
        let mut next = Vec::new();
        for committee in targets {
            let previous = head(state, &committee.filter)?;
            if let Some(previous) = &previous {
                if previous.chain_id != source_sessions[0].chain_id {
                    return Err(invalid("target belongs to another chain"));
                }
                if !sources.contains(&committee.filter)
                    && !matches!(status(state, &previous.id()?)?, Status::Closed(_))
                {
                    return Err(invalid("target already has a live session"));
                }
            }
            let generation = previous
                .as_ref()
                .map_or(Some(1), |p| p.generation.checked_add(1))
                .ok_or_else(|| invalid("generation exhausted"))?;
            next.push(Target {
                committee,
                generation,
                previous: previous.as_ref().map(Session::id).transpose()?,
            });
        }
        let request = Request {
            frame,
            sources: source_sessions,
            vacant,
            targets: next,
        };
        let id = request.id()?;
        if read(state, b"request", &id)?.is_some() {
            return Err(invalid("request already exists"));
        }
        write(state, frame, b"request", &id, &request.encode()?)?;
        for source in &request.sources {
            set_status(state, frame, &source.id()?, 1, Some(&id))?;
        }
        Ok(request)
    })
}

pub fn request(state: &impl Records, id: &[u8; 32]) -> Result<Option<Request>> {
    read(state, b"request", id)?
        .map(|bytes| {
            let request = Request::decode(&bytes)?;
            if &request.id()? != id {
                return Err(QuilError::Store("handoff request ID mismatch".into()));
            }
            Ok(request)
        })
        .transpose()
}

fn seal_key(request: &[u8; 32], session: &[u8; 32]) -> Vec<u8> {
    [request.as_slice(), session.as_slice()].concat()
}

pub fn closed_checkpoint(state: &impl Records, id: &[u8; 32]) -> Result<Option<Checkpoint>> {
    let Status::Closed(request) = status(state, id)? else {
        return Ok(None);
    };
    Ok(Some(
        terminal(state, &request, id)?
            .ok_or_else(|| QuilError::Store("closed session has no seal or fence".into()))?
            .checkpoint,
    ))
}

/// A submitted source seal (or a GLOBAL fence) is terminal even while other
/// sources are still closing. Historical data validation must respect that
/// partial transition.
fn submitted_checkpoint(state: &impl Records, id: &[u8; 32]) -> Result<Option<Checkpoint>> {
    let (request, closed) = match status(state, id)? {
        Status::Active => return Ok(None),
        Status::Sealing(request) => (request, false),
        Status::Closed(request) => (request, true),
    };
    match terminal(state, &request, id)? {
        Some(end) => Ok(Some(end.checkpoint)),
        None if closed => Err(QuilError::Store("closed session has no seal or fence".into())),
        None => Ok(None),
    }
}

/// How a closing source ended: its committee's quorum-certified seal, or the
/// checkpoint GLOBAL fenced it at when it never sealed ([`schedule::fence_stalled_sources`]).
struct Terminal {
    checkpoint: Checkpoint,
    /// The value the successor authorization commits to.
    digest: [u8; 32],
    fenced: bool,
}

/// Domain-separated identity of a fence, distinct from any seal digest.
fn fence_digest(request: &[u8; 32], session: &[u8; 32], checkpoint: &Checkpoint) -> [u8; 32] {
    let mut bytes = Vec::new();
    checkpoint.write(&mut bytes);
    let mut h = Sha256::new();
    h.update(b"quil/app/handoff/fence/v1");
    h.update(request);
    h.update(session);
    h.update(&bytes);
    h.finalize().into()
}

fn terminal(state: &impl Records, request: &[u8; 32], id: &[u8; 32]) -> Result<Option<Terminal>> {
    let key = seal_key(request, id);
    if let Some(bytes) = read(state, b"seal", &key)? {
        let seal = CertificateSubmission::from_canonical_bytes(&bytes)?.seal;
        if seal.session != *id || seal.request != *request {
            return Err(QuilError::Store("submitted-session seal mismatch".into()));
        }
        return Ok(Some(Terminal { digest: seal.digest(), checkpoint: seal.checkpoint, fenced: false }));
    }
    let Some(bytes) = read(state, b"fence", &key)? else {
        return Ok(None);
    };
    let mut cursor = Cursor::new(&bytes)?;
    let checkpoint = Checkpoint::read(&mut cursor)?;
    cursor.finish()?;
    Ok(Some(Terminal { digest: fence_digest(request, id, &checkpoint), checkpoint, fenced: true }))
}

/// Whether GLOBAL fenced this closing session instead of receiving its seal.
/// A fenced checkpoint carries no certified outgoing-history root.
pub fn is_fenced(state: &impl Records, id: &[u8; 32]) -> Result<bool> {
    let request = match status(state, id)? {
        Status::Active => return Ok(false),
        Status::Sealing(request) | Status::Closed(request) => request,
    };
    Ok(terminal(state, &request, id)?.is_some_and(|end| end.fenced))
}

pub fn verify_submission(
    state: &impl Records,
    frame: u64,
    submission: &CertificateSubmission,
) -> Result<Request> {
    verify_submission_at(state, frame, submission, session_tip(state, &submission.seal.session)?)
}

/// [`verify_submission`] against `executed`, the source's executed tip once
/// the submission's drain headers would be executed (the recorded tip when it
/// carries none): validation checks a drain without writing it.
pub fn verify_submission_at(
    state: &impl Records,
    frame: u64,
    submission: &CertificateSubmission,
    executed: Option<Checkpoint>,
) -> Result<Request> {
    let request = request(state, &submission.seal.request)?
        .ok_or_else(|| invalid("closing certificate has no authorized request"))?;
    if frame <= request.frame {
        return Err(invalid(
            "closing request must precede certificate inclusion",
        ));
    }
    let source = request
        .sources
        .iter()
        .find(|s| s.id().ok() == Some(submission.seal.session))
        .ok_or_else(|| invalid("certificate is not from a requested source"))?;
    if !matches!(status(state, &submission.seal.session)?, Status::Sealing(r) | Status::Closed(r) if r == submission.seal.request)
    {
        return Err(invalid("source is not closing for this request"));
    }
    // A fence is terminal: the successor was, or will be, authorized from it.
    if read(state, b"fence", &seal_key(&submission.seal.request, &submission.seal.session))?.is_some() {
        return Err(invalid("source was fenced after its closing timeout"));
    }
    verify_seal(
        source,
        &submission.seal.request,
        &submission.seal,
        &submission.certificate,
    )
    .ok_or_else(|| invalid("invalid source finalization certificate"))?;
    // A source's last outflows ride only its drain headers, and nothing relays
    // them once it is retired. Accept its seal only after GLOBAL has executed
    // its data frames through the sealed checkpoint; the committee resubmits.
    // A source asked to close before it produced a frame seals at its base,
    // the authorized genesis (`verify_seal` checks it): it has no frames and
    // nothing to drain. On a live width run a membership change right after
    // authorization closed such sessions, their seals were refused for want of
    // a tip, and the shard stalled four epochs until the fence, twice.
    // The checkpoint must also BE the executed tip: GLOBAL never executes past
    // a session's terminal frame, so a seal below the tip, or at it with
    // another digest, would authorize a successor that drops or forks frames
    // GLOBAL already executed. Such a seal is refused for good; the fence
    // closes the session at its tip.
    let checkpoint = &submission.seal.checkpoint;
    let drained = match executed {
        Some(tip) if tip.frame > checkpoint.frame => {
            return Err(invalid("sealed checkpoint is below the source's executed frames"));
        }
        Some(tip) if tip.frame == checkpoint.frame && tip.digest != checkpoint.digest => {
            return Err(invalid("sealed checkpoint differs from the source's executed frame"));
        }
        Some(tip) => tip.frame == checkpoint.frame,
        None => checkpoint.frame == source.base_frame,
    };
    if !drained {
        return Err(invalid("source frames through the sealed checkpoint are not yet executed"));
    }
    if let Some(previous) = read(
        state,
        b"seal",
        &seal_key(&submission.seal.request, &submission.seal.session),
    )? {
        if CertificateSubmission::from_canonical_bytes(&previous)?.seal != submission.seal {
            return Err(invalid(
                "source already supplied a different closing checkpoint",
            ));
        }
    }
    Ok(request)
}

/// Returns true only when all requested old committees have closed and the
/// successor authorization has been staged. It becomes usable after global
/// frame commit/sync, and is never a certificate under the NEW committee.
pub fn apply_submission(
    state: &HypergraphState,
    frame: u64,
    submission: &CertificateSubmission,
) -> Result<bool> {
    atomic(state, || {
        let request = verify_submission(state, frame, submission)?;
        let request_id = request.id()?;
        if read(state, b"activated", &request_id)?.is_some() {
            return Ok(false);
        }
        let key = seal_key(&request_id, &submission.seal.session);
        if read(state, b"seal", &key)?.is_none() {
            write(
                state,
                frame,
                b"seal",
                &key,
                &submission.to_canonical_bytes()?,
            )?;
        }
        activate(state, frame, &request)
    })
}

/// Authorize the successors once every source has ended, by its seal or by a
/// GLOBAL fence. False while a source is still closing, or once activated.
fn activate(state: &HypergraphState, frame: u64, request: &Request) -> Result<bool> {
    {
        let request_id = request.id()?;
        if read(state, b"activated", &request_id)?.is_some() {
            return Ok(false);
        }
        let mut ends = Vec::new();
        for source in &request.sources {
            let Some(end) = terminal(state, &request_id, &source.id()?)? else {
                return Ok(false);
            };
            ends.push(end);
        }
        for target in &request.targets {
            let current = head(state, &target.committee.filter)?;
            if current.as_ref().map(Session::id).transpose()? != target.previous
                || current
                    .as_ref()
                    .map_or(Some(1), |s| s.generation.checked_add(1))
                    != Some(target.generation)
            {
                return Err(invalid("target changed after the request was authorized"));
            }
        }
        let mut h = Sha256::new();
        h.update(b"quil/app/handoff/authorization/v1");
        h.update(request_id);
        for end in &ends {
            h.update(end.digest);
        }
        let authorization: [u8; 32] = h.finalize().into();
        for source in &request.sources {
            set_status(state, frame, &source.id()?, 2, Some(&request_id))?;
        }
        for target in request.targets.iter().filter(|t| !t.committee.members.is_empty()) {
            let base_frame = match target.previous {
                Some(previous) => {
                    closed_checkpoint(state, &previous)?
                        .ok_or_else(|| invalid("previous target session has not closed"))?
                        .frame
                }
                None => 0,
            };
            let mut h = Sha256::new();
            h.update(b"quil/app/handoff/genesis/v1");
            h.update(authorization);
            h.update(target.generation.to_be_bytes());
            h.update(&target.committee.filter);
            let output: [u8; 32] = h.finalize().into();
            let next = Session {
                chain_id: request.sources[0].chain_id,
                filter: target.committee.filter.clone(),
                generation: target.generation,
                genesis: quil_crypto::poseidon::hash_bytes_to_32(&output)?,
                base_frame,
                authorization,
                members: target.committee.members.clone(),
            };
            let id = create_session(state, frame, &next)?;
            // The authorization names the complete source partition; the new
            // worker must authenticate state/history from those sealed sources.
            write(state, frame, b"origin", &id, &request_id)?;
            write(state, frame, b"genesis-output", &id, &output)?;
            set_status(state, frame, &id, 0, None)?;
            // A membership successor keeps its cohorts; a shard a split or
            // merge creates ranks its members by seniority alone.
            let sources: Vec<Vec<u8>> = request.sources.iter().map(|s| s.filter.clone()).collect();
            let one_cohort = !sources.iter().all(|filter| *filter == next.filter);
            record_member_rings(state, frame, &id, &next, &sources, one_cohort)?;
        }
        write(state, frame, b"activated", &request_id, &authorization)?;
        Ok(true)
    }
}

/// Authenticated source checkpoints for a successor's bootstrap. Returning
/// records is not a local materialization/readiness verdict.
pub fn origins(state: &impl Records, id: &[u8; 32]) -> Result<Vec<(Session, Checkpoint)>> {
    session(state, id)?.ok_or_else(|| invalid("bootstrap session absent"))?;
    let bytes = read(state, b"origin", id)?
        .ok_or_else(|| QuilError::Store("session origin absent".into()))?;
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let request_id = bytes
        .try_into()
        .map_err(|_| QuilError::Store("corrupt session origin".into()))?;
    let request = request(state, &request_id)?
        .ok_or_else(|| QuilError::Store("session origin request absent".into()))?;
    request
        .sources
        .into_iter()
        .map(|source| {
            let checkpoint = closed_checkpoint(state, &source.id()?)?
                .ok_or_else(|| QuilError::Store("session origin is not closed".into()))?;
            Ok((source, checkpoint))
        })
        .collect()
}

/// The highest data frame of `id` that GLOBAL has executed: its coordinates
/// and state roots from the certified header. The history root is not in a
/// header and is left zero.
pub fn session_tip(state: &impl Records, id: &[u8; 32]) -> Result<Option<Checkpoint>> {
    read(state, b"tip", id)?
        .map(|bytes| {
            let mut cursor = Cursor::new(&bytes)?;
            let tip = Checkpoint::read(&mut cursor)?;
            cursor.finish()?;
            Ok(tip)
        })
        .transpose()
}

/// Advance [`session_tip`] to `tip` if it is higher.
pub fn record_session_tip(state: &HypergraphState, frame: u64, id: &[u8; 32], tip: &Checkpoint) -> Result<()> {
    if session_tip(state, id)?.is_some_and(|current| current.frame >= tip.frame) {
        return Ok(());
    }
    let mut bytes = Vec::new();
    tip.write(&mut bytes);
    write(state, frame, b"tip", id, &bytes)
}

/// The reward ring of each of a session's members, in member order, fixed at
/// the session's first rewarded frame. Every frame the session certified is
/// rewarded with these rings, whatever the members' allocations became after
/// a succession, split or merge.
pub fn session_rings(state: &impl Records, id: &[u8; 32]) -> Result<Option<Vec<u8>>> {
    read(state, b"rings", id)
}

/// Record [`session_rings`] once. A recorded snapshot is never replaced.
pub fn record_session_rings(state: &HypergraphState, frame: u64, id: &[u8; 32], rings: &[u8]) -> Result<()> {
    let members = session(state, id)?.ok_or_else(|| invalid("ring snapshot for an absent session"))?.members.len();
    if rings.len() != members {
        return Err(invalid("ring snapshot does not cover the session's members"));
    }
    if read(state, b"rings", id)?.is_some() {
        return Err(invalid("session rings already recorded"));
    }
    write(state, frame, b"rings", id, rings)
}

/// Whether `submission` can no longer change anything: its request already
/// activated, its source's seal is recorded, or the source was fenced.
/// Proposers leave such copies out (every member of a closing committee
/// submits, and resubmits until its own view shows the seal recorded).
pub fn submission_settled(state: &impl Records, submission: &CertificateSubmission) -> Result<bool> {
    let key = seal_key(&submission.seal.request, &submission.seal.session);
    Ok(read(state, b"activated", &submission.seal.request)?.is_some()
        || read(state, b"seal", &key)?.is_some()
        || read(state, b"fence", &key)?.is_some())
}

/// Whether the committee-handoff flag day ([`LegacyHistory::Discard`]) has
/// run: ring keys recorded, gridless applications given a root shard and
/// off-grid allocations moved onto the grid.
///
/// [`LegacyHistory::Discard`]: quil_types::consensus::LegacyHistory::Discard
pub fn flag_day_applied(state: &impl Records) -> Result<bool> {
    Ok(read(state, b"flag-day", b"legacy-discarded")?.is_some())
}

/// Record that the flag day ran at `frame`.
pub fn record_flag_day(state: &HypergraphState, frame: u64) -> Result<()> {
    write(state, frame, b"flag-day", b"legacy-discarded", &frame.to_be_bytes())
}

/// A member's prover address and ring key, read from its allocation on the
/// session's filter or, before a split or merge moves it, on one of the
/// sources'. A member without an allocation ranks last.
fn member_ring_key(
    state: &HypergraphState,
    member: &[u8],
    filters: &[&[u8]],
) -> Result<(Vec<u8>, super::prover_rings::RingKey)> {
    use crate::global_schema::read_field;
    let va_disc = vertex_adds_discriminator()?;
    for filter in filters {
        let address = super::materialize::allocation_address(member, filter)?;
        let Some(blob) = state.get(&GLOBAL_INTRINSIC_ADDRESS[..], &address, &va_disc)? else { continue };
        if blob.is_empty() {
            continue;
        }
        let allocation = crate::prover_registry::rebuild_vertex_tree_from_blob(&blob);
        let Some(prover) = read_field(&allocation, "allocation:ProverAllocation", "Prover") else { continue };
        if let Some(key) = super::prover_rings::read_key(&allocation) {
            return Ok((prover, key));
        }
        let u64_of = |tree: &quil_tries::VectorCommitmentTree, class: &str, field: &str| {
            read_field(tree, class, field)
                .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
                .map_or(0, u64::from_be_bytes)
        };
        let seniority = state
            .get(&GLOBAL_INTRINSIC_ADDRESS[..], &prover, &va_disc)?
            .map(|blob| crate::prover_registry::rebuild_vertex_tree_from_blob(&blob))
            .map_or(0, |tree| u64_of(&tree, "prover:Prover", "Seniority"));
        let confirmed = u64_of(&allocation, "allocation:ProverAllocation", "JoinConfirmFrameNumber");
        return Ok((prover, super::prover_rings::preexisting(confirmed, seniority)));
    }
    Ok((member.to_vec(), super::prover_rings::RingKey { cohort: u64::MAX, seniority: 0 }))
}

/// Under the seniority ring rule, a new session's rings are fixed when it is
/// created (`prover_rings`), from its members' allocations on its filter or on
/// `sources`' filters. A session a split or merge creates (`one_cohort`)
/// ranks its members by seniority alone. Each member's allocation also records
/// its ring, so a split's reassignment carries it to the child.
fn record_member_rings(
    state: &HypergraphState,
    frame: u64,
    id: &[u8; 32],
    created: &Session,
    sources: &[Vec<u8>],
    one_cohort: bool,
) -> Result<()> {
    if !super::prover_rings::governs(frame) {
        return Ok(());
    }
    let mut filters: Vec<&[u8]> = vec![created.filter.as_slice()];
    filters.extend(sources.iter().map(Vec::as_slice).filter(|f| *f != created.filter.as_slice()));
    let keyed = created
        .members
        .iter()
        .map(|member| member_ring_key(state, member, &filters))
        .collect::<Result<Vec<_>>>()?;
    let ranked: Vec<(&[u8], super::prover_rings::RingKey)> =
        keyed.iter().map(|(address, key)| (address.as_slice(), *key)).collect();
    let rings = super::prover_rings::assign(&ranked, one_cohort);
    record_session_rings(state, frame, id, &rings)?;
    let va_disc = vertex_adds_discriminator()?;
    for (member, ring) in created.members.iter().zip(&rings) {
        for filter in &filters {
            let address = super::materialize::allocation_address(member, filter)?;
            let Some(blob) = state.get(&GLOBAL_INTRINSIC_ADDRESS[..], &address, &va_disc)? else { continue };
            if blob.is_empty() {
                continue;
            }
            let mut allocation = crate::prover_registry::rebuild_vertex_tree_from_blob(&blob);
            if crate::global_schema::read_field(&allocation, "allocation:ProverAllocation", "Ring").as_deref()
                != Some(&[*ring][..])
            {
                crate::global_schema::write_field(&mut allocation, "allocation:ProverAllocation", "Ring", &[*ring])?;
                state.set(
                    &GLOBAL_INTRINSIC_ADDRESS[..], &address, &va_disc, frame,
                    crate::prover_registry::vertex_tree_to_blob(&allocation),
                )?;
            }
            break;
        }
    }
    Ok(())
}

#[path = "handoff_history.rs"]
pub mod history;

#[path = "handoff_frames.rs"]
pub mod frames;

#[path = "handoff_schedule.rs"]
pub mod schedule;

#[path = "handoff_legacy.rs"]
pub mod legacy;

#[cfg(test)]
#[path = "handoff_tests.rs"]
mod tests;

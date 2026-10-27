//! End-to-end submission pipeline for prover lifecycle actions.
//!
//! The lifecycle evaluator produces abstract `LifecycleAction`s; this
//! module turns them into signed canonical-bytes messages wrapped in a
//! `MessageBundle` and submits them via a pluggable
//! [`ProverMessageTransport`] (gRPC fan-out + BlossomSub in production,
//! a single in-memory broadcast in tests).
//!
//! Mirrors Go's `publishProverMessage` at
//! `node/consensus/global/global_consensus_engine.go:154-159`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use tracing::{debug, info, warn};

use quil_execution::global_intrinsic::{
    addressed_signature::AddressedSignature,
    leaf_root_registration::{check_confirm_leaf_roots, MAX_CONFIRM_LEAF_ROOT_GROUPS},
    prover_filter_ops::ProverLeave,
    prover_filter_ops::TYPE_PROVER_LEAVE,
    prover_join::ProverJoin,
    prover_join::TYPE_PROVER_JOIN,
    prover_ops::{
        check_filters, ProverConfirm, ProverReject, ProverSeniorityMerge, ShardMerge, ShardSplit,
        MAX_FILTERS_PER_OP, MAX_FILTER_LEN, TYPE_PROVER_CONFIRM, TYPE_PROVER_REJECT,
        TYPE_PROVER_SENIORITY_MERGE, TYPE_SHARD_MERGE, TYPE_SHARD_SPLIT,
    },
    sig_with_pop::SignatureWithPop,
};
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
use quil_types::crypto::{FrameProver, Signer};
use quil_types::error::{QuilError, Result};

use crate::current_frame::CurrentFrame;
use crate::message_collector::{MessageCollector, SubmitOutcome};
use crate::prover_message_transport::ProverMessageTransport;
use crate::provers::lifecycle::{LifecycleAction, ProverLifecycle};
use crate::submission_attempts::OpKind;
use crate::worker::WorkerManager;

/// End-to-end submission pipeline for prover lifecycle actions.
///
/// Owns no transport details — the caller injects an
/// [`Arc<dyn ProverMessageTransport>`] that knows how to ship a
/// `CanonicalMessageBundle` on `GLOBAL_PROVER` (production: gRPC
/// fan-out + BlossomSub; tests: in-memory network).
pub struct ProverPipeline {
    pub lifecycle: Arc<ProverLifecycle>,
    pub worker_manager: Arc<dyn WorkerManager>,
    pub frame_prover: Arc<dyn FrameProver>,
    pub key_manager: Arc<dyn quil_keys::KeyManager + Send + Sync>,
    pub bls_pubkey: Vec<u8>,
    pub prover_address: [u8; 32],
    /// Ed448 seeds loaded from `config.engine.multisig_prover_enrollment_paths`
    /// plus the local peer's own Ed448 seed, used to build merge
    /// helpers for `ProverSeniorityMerge`. Each seed signs the local
    /// BLS prover pubkey with the `PROVER_SENIORITY_MERGE` domain so
    /// on-chain materialization can attribute historical seniority
    /// from the old peer keys.
    pub multisig_ed448_seeds: Vec<[u8; 57]>,
    /// Optional delegate address for ProverJoin emissions. Mirrors Go's
    /// `config.Engine.DelegateAddress` at
    /// `node/consensus/global/worker_allocator.go:1483-1490` —
    /// hex-decoded when set, empty `Vec::new()` when unset. Empty is
    /// the default and is functionally equivalent to "delegate ==
    /// prover_address" inside the materializer (the join handler
    /// substitutes `prover_address` when `len(DelegateAddress) != 32`),
    /// but the canonical-bytes wire form differs — preserve byte-level
    /// parity with default Go nodes by leaving this empty unless the
    /// operator explicitly configured a delegate.
    pub delegate_address: Vec<u8>,
    /// Transport used to ship outbound `MessageBundle` bytes on
    /// `GLOBAL_PROVER` and to fetch the latest frame header for VDF
    /// challenge derivation in [`Self::submit_join`].
    pub transport: Arc<dyn ProverMessageTransport>,
    /// Live hypergraph CRDT — read by the storage-attestation confirm hook
    /// (`submit_confirm`) to partition each confirmed shard's committed
    /// subtree into PoRep leaves. Required for data-shard confirmations.
    pub hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
    /// Replica store the confirm hook persists per-leaf SDR replicas into
    /// (keyed by `(epoch, leaf_id)`), so the per-frame producer can later
    /// answer openings. Required for data-shard confirmations.
    pub replica_store: Option<quil_store::replica_store::ReplicaStore>,
    /// Per-shard storage: the hypergraph and replica store of the worker that
    /// holds and attests a shard, when it is not the node's own (a thread
    /// worker opens its own database). Confirmation must encode the same data
    /// into the same replica store the attesting worker proves from, or the
    /// registered leaf roots diverge from its attestations once the shard's
    /// data changes and every storage frame is rejected.
    pub storage_for_filter: Option<
        std::sync::Arc<
            dyn Fn(
                    &[u8],
                ) -> Option<(
                    std::sync::Arc<quil_hypergraph::HypergraphCrdt>,
                    quil_store::replica_store::ReplicaStore,
                )> + Send
                + Sync,
        >,
    >,
    /// Leaf roots prepared by the standalone (cluster-mode) worker serving a
    /// filter, from its own store: `Ok(None)` when no such worker serves it.
    /// Called from a blocking task, with the time the worker may take.
    /// Without it the master encoded from its own store, which lacks the
    /// shard's data, and the worker's attestations were rejected for leaves
    /// it could never prove.
    pub remote_storage_confirm: Option<RemoteStorageConfirm>,
    /// Splits and merges this node has recorded but not applied. A confirm in
    /// the epoch before one applies also registers the shards it creates from
    /// the confirmed ones (see `pre_registration_targets`).
    pub pending_shard_changes: Option<
        std::sync::Arc<dyn Fn() -> Vec<quil_types::store::PendingShardChange> + Send + Sync>,
    >,
    /// A shard's storage snapshot for an epoch, once GLOBAL has recorded it
    /// (hash storage proofs; the prover registry's). A confirm's registrations
    /// are read from each shard's snapshot sources.
    pub storage_snapshot: Option<
        std::sync::Arc<
            dyn Fn(&[u8], u64) -> Option<quil_types::consensus::StorageSnapshotRoots> + Send + Sync,
        >,
    >,
    /// Local global-message collector, for LOOPBACK of ops this node generates
    /// for ITSELF (ShardSplit/ShardMerge from the coverage orchestrator, which
    /// runs on the frame producer). A producer must include its own generated op
    /// in the frame it builds; the network publish only reaches OTHER nodes, so
    /// on a single-archive network (no other archive to accept, gossipsub won't
    /// self-loopback) the op would otherwise never land. Loop it into the same
    /// collector the gRPC/gossip ingest feeds. `None` disables loopback (tests).
    pub local_message_collector: Option<Arc<MessageCollector>>,
    /// Current-frame tracker, used to tag looped-back ops with the CONSENSUS RANK
    /// (`effective_rank()`) exactly as the gRPC ingest does (grpc.rs:400) so the
    /// leader's `collect_for_rank` picks them up. `None` disables loopback.
    pub current_frame: Option<Arc<CurrentFrame>>,
}

pub type RemoteStorageConfirm = std::sync::Arc<
    dyn Fn(
            &[u8],
            &[Vec<u8>],
            u64,
            std::time::Duration,
            &[SnapshotSources],
        ) -> Result<
            Option<Vec<quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots>>,
        > + Send
        + Sync,
>;

/// The storage snapshot sources of one shard a confirm registers.
pub type SnapshotSources = (
    Vec<u8>,
    Vec<quil_execution::global_intrinsic::storage_snapshot::Source>,
);

/// A filter-carrying op other than a join or confirm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterOp {
    Leave,
    Reject,
}

impl FilterOp {
    fn name(self) -> &'static str {
        match self {
            Self::Leave => "leave",
            Self::Reject => "reject",
        }
    }
}

/// Hard ceiling on lifecycle submissions that do NOT perform VDF
/// compute (confirms, rejects, leaves, seniority merge). Each of
/// these is sign + canonicalize + publish; the only legitimately
/// slow piece is the gRPC fan-out, which has its own per-archive
/// timeout in the transport. 30s is well above the worst case but
/// bounds the spawned task so a transport bug, runtime starvation,
/// or stuck publish can't silently wedge a dispatch forever.
const NON_VDF_SUBMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// What a confirm encodes, per confirmed filter: the filter, from its own
/// storage, then the shards a split or merge applying at `epoch` creates from
/// it (see `pre_registration_targets`). A merge target two confirmed sources
/// share is encoded once, from the first.
fn confirm_encoding_plan(
    filters: &[Vec<u8>],
    changes: &[quil_types::store::PendingShardChange],
    epoch: u64,
) -> Vec<(Vec<u8>, Vec<Vec<u8>>)> {
    let mut claimed: Vec<Vec<u8>> = filters.to_vec();
    filters
        .iter()
        .map(|filter| {
            let targets: Vec<Vec<u8>> = if filter.is_empty() {
                Vec::new()
            } else {
                quil_execution::global_intrinsic::leaf_root_registration::pre_registration_targets(
                    changes,
                    std::slice::from_ref(filter),
                    epoch,
                )
                .into_iter()
                .filter(|target| !claimed.contains(target))
                .collect()
            };
            claimed.extend(targets.iter().cloned());
            (filter.clone(), targets)
        })
        .collect()
}

type LeafRoots = Vec<quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots>;

/// One filter's confirm preparation: its leaf roots, or why the standalone
/// worker that serves it did not prepare them, with its error.
enum Prepared {
    Roots(LeafRoots),
    Unanswered(LeftOutCause, QuilError),
}

/// Why a confirm leaves a seat out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LeftOutCause {
    /// Its worker failed: unreachable, refused, or another error.
    Failed,
    /// Its worker was asked and had not answered by the round's deadline.
    Late,
    /// The round's deadline passed before its worker was asked.
    Unasked,
    /// Its worker's answer omitted or repeated a shard it was asked for.
    Incomplete,
    /// It pre-registers a shard a left-out seat was to encode.
    MergeTarget,
    /// Its filter or leaf roots exceed what every node decodes in a confirm.
    OverLimit,
    /// Its committed allocation no longer accepts the confirm (`confirm_refusal`).
    Refused,
    /// Its thread worker is stopped while the node reopens the worker's
    /// store (`stopped_store_filters`); the master's stores lack the shard.
    StoreStopped,
}

impl LeftOutCause {
    fn name(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::Late => "late",
            Self::Unasked => "unasked",
            Self::Incomplete => "incomplete",
            Self::MergeTarget => "merge target",
            Self::OverLimit => "over decode limit",
            Self::Refused => "refused",
            Self::StoreStopped => "worker store stopped",
        }
    }
}

/// A seat a confirm leaves out, with why; retried on the next cycle, or in
/// the next epoch when it is over the decode limits.
struct LeftOutSeat {
    filter: Vec<u8>,
    /// Shards this seat was to pre-register for the confirm.
    targets: Vec<Vec<u8>>,
    cause: LeftOutCause,
    error: QuilError,
}

/// What a confirm submits: the filters whose storage was prepared and their
/// leaf roots, in the order requested, and the seats it leaves out.
struct PreparedConfirm {
    filters: Vec<Vec<u8>>,
    roots: LeafRoots,
    /// How many of `roots`, in order, each of `filters` registers: its
    /// shard's and those it pre-registers.
    seat_groups: Vec<usize>,
    left_out: Vec<LeftOutSeat>,
}

impl PreparedConfirm {
    /// Settle the left-out seats' reservations: a seat its worker did not
    /// prepare is released, so the next cycle retries it; a seat over the
    /// decode limits is fenced from `frame` until the epoch ends, as
    /// preparing it again (a full storage encode) within the epoch would only
    /// leave it out again; the next epoch's renewal retries it. A refused
    /// seat is fenced for the retry fence. The submitted seats stay reserved
    /// until published.
    fn settle_left_out(
        &self,
        attempt: &mut crate::submission_attempts::SubmissionAttempt,
        frame: u64,
    ) {
        let filters = |settled: fn(LeftOutCause) -> bool| {
            self.left_out
                .iter()
                .filter(|seat| settled(seat.cause))
                .map(|seat| seat.filter.clone())
                .collect::<Vec<_>>()
        };
        attempt.fence_for_epoch(&filters(|cause| cause == LeftOutCause::OverLimit), frame);
        attempt.fence(&filters(|cause| cause == LeftOutCause::Refused), frame);
        attempt.release(&filters(|cause| {
            !matches!(cause, LeftOutCause::OverLimit | LeftOutCause::Refused)
        }));
    }
}

/// The filters of thread workers whose own stores stopped writing, latched
/// or held stopped for their reopening (`worker_execution::store_stopped`).
/// Neither such a store, which refuses the confirm's replica writes, nor the
/// master's stores, which lack the shard, can prepare the seat, and an error
/// preparing one seat would abort the confirm of every seat.
fn stopped_store_filters(
    workers: &[crate::worker::WorkerInfo],
) -> std::collections::HashSet<Vec<u8>> {
    workers
        .iter()
        .filter(|w| !w.filter.is_empty())
        .filter(|w| crate::worker_execution::store_stopped(w.core_id))
        .map(|w| w.filter.clone())
        .collect()
}

/// A seat among `stopped` is left out of the confirm and retried next cycle.
fn stopped_seat(stopped: &std::collections::HashSet<Vec<u8>>, filter: &[u8]) -> Option<Prepared> {
    stopped.contains(filter).then(|| {
        Prepared::Unanswered(
            LeftOutCause::StoreStopped,
            QuilError::ExecutionUnavailable(
                "its thread worker is stopped while its store is reopened".into(),
            ),
        )
    })
}

/// A seat whose preparation failed because its thread worker's store stopped
/// writing during the encode (its own replica writes can push the disk
/// below the floor) is left out like a stopped seat; any other error stays
/// an error, aborting the confirm.
fn stopped_mid_encode(
    workers: &[crate::worker::WorkerInfo],
    filter: &[u8],
    error: QuilError,
) -> Result<Prepared> {
    if workers
        .iter()
        .any(|w| w.filter == filter && crate::worker_execution::store_stopped(w.core_id))
    {
        Ok(Prepared::Unanswered(LeftOutCause::StoreStopped, error))
    } else {
        Err(error)
    }
}

/// Why no node would decode a confirm carrying this seat, if none would: its
/// filter or its leaf-root groups exceed the decoders' limits. Such a seat is
/// left out, so the seats sharing its message still go out.
fn seat_over_limit(filter: &[u8], roots: &LeafRoots) -> Option<QuilError> {
    check_filters(&[filter.to_vec()])
        .and_then(|()| check_confirm_leaf_roots(roots))
        .err()
}

/// Prepare a confirm of `filters` along `confirm_encoding_plan`. A seat whose
/// standalone worker does not answer is left out, so the seats whose workers
/// answer are confirmed instead of all failing together; it is retried on the
/// next cycle. A seat that was to encode a shard a left-out seat had claimed
/// (a shared merge target) is left out with it, so every submitted seat
/// registers the shards a change creates from it, as a full confirm does.
/// A seat whose filter or leaf roots exceed what every node decodes is left
/// out too (`seat_over_limit`), so it does not take its message-mates down,
/// as is one `refused` finds GLOBAL would no longer accept a confirm for,
/// once every seat is prepared. When no seat is left and none is over those
/// limits or refused, the first worker error aborts the confirm, as does any
/// other preparation error.
fn prepare_confirm<F, R>(
    filters: &[Vec<u8>],
    changes: &[quil_types::store::PendingShardChange],
    epoch: u64,
    mut prepare: F,
    mut refused: R,
) -> Result<PreparedConfirm>
where
    F: FnMut(&[u8], &[Vec<u8>]) -> Result<Prepared>,
    R: FnMut(&[u8]) -> Option<QuilError>,
{
    let mut prepared: Vec<(Vec<u8>, Vec<Vec<u8>>, LeafRoots)> = Vec::with_capacity(filters.len());
    let mut left_out: Vec<LeftOutSeat> = Vec::new();
    for (filter, targets) in confirm_encoding_plan(filters, changes, epoch) {
        match prepare(&filter, &targets)? {
            Prepared::Roots(roots) => match seat_over_limit(&filter, &roots) {
                None => prepared.push((filter, targets, roots)),
                Some(error) => left_out.push(LeftOutSeat {
                    filter,
                    targets,
                    cause: LeftOutCause::OverLimit,
                    error,
                }),
            },
            Prepared::Unanswered(cause, error) => left_out.push(LeftOutSeat {
                filter,
                targets,
                cause,
                error,
            }),
        }
    }
    // A seat whose allocation changed while it was prepared (a leave of it
    // landed) would sink every seat of its message.
    let mut index = 0;
    while index < prepared.len() {
        match refused(&prepared[index].0) {
            Some(error) => {
                let (filter, targets, _) = prepared.remove(index);
                left_out.push(LeftOutSeat {
                    filter,
                    targets,
                    cause: LeftOutCause::Refused,
                    error,
                });
            }
            None => index += 1,
        }
    }
    // A shard claimed by a left-out seat is encoded by no submitted seat.
    loop {
        let orphaned: Vec<&Vec<u8>> = left_out
            .iter()
            .flat_map(|seat| seat.targets.iter())
            .collect();
        let Some(position) = prepared.iter().position(|(filter, targets, _)| {
            quil_execution::global_intrinsic::leaf_root_registration::pre_registration_targets(
                changes,
                std::slice::from_ref(filter),
                epoch,
            )
            .iter()
            .any(|target| orphaned.contains(&target) && !targets.contains(target))
        }) else {
            break;
        };
        let (filter, targets, _) = prepared.remove(position);
        left_out.push(LeftOutSeat {
            filter,
            targets,
            cause: LeftOutCause::MergeTarget,
            error: QuilError::ExecutionUnavailable(
                "a shard it pre-registers was to be encoded by a left-out seat".into(),
            ),
        });
    }
    // A seat over the decode limits or refused is settled rather than
    // failed, so it is not prepared again every frame.
    if prepared.is_empty()
        && !left_out.is_empty()
        && left_out
            .iter()
            .all(|seat| !matches!(seat.cause, LeftOutCause::OverLimit | LeftOutCause::Refused))
    {
        return Err(left_out.remove(0).error);
    }
    let mut confirm = PreparedConfirm {
        filters: Vec::with_capacity(prepared.len()),
        roots: Vec::new(),
        seat_groups: Vec::with_capacity(prepared.len()),
        left_out,
    };
    for (filter, _, roots) in prepared {
        confirm.filters.push(filter);
        confirm.seat_groups.push(roots.len());
        confirm.roots.extend(roots);
    }
    Ok(confirm)
}

/// Split a confirm into messages every node decodes: each names at most
/// `MAX_FILTERS_PER_OP` filters and registers at most
/// `MAX_CONFIRM_LEAF_ROOT_GROUPS` leaf-root groups. A seat's groups stay in
/// the message that names it, as GLOBAL honours a group only for a shard the
/// same confirm names or one a change creates from it. Each message is
/// signed, submitted and retried on its own.
fn confirm_messages(
    filters: Vec<Vec<u8>>,
    roots: LeafRoots,
    seat_groups: &[usize],
) -> Vec<(Vec<Vec<u8>>, LeafRoots)> {
    let mut messages: Vec<(Vec<Vec<u8>>, LeafRoots)> = Vec::new();
    let mut roots = roots.into_iter();
    for (index, filter) in filters.into_iter().enumerate() {
        let seat: LeafRoots = roots
            .by_ref()
            .take(seat_groups.get(index).copied().unwrap_or(0))
            .collect();
        let fits = messages.last().is_some_and(|(filters, roots)| {
            filters.len() < MAX_FILTERS_PER_OP
                && roots.len() + seat.len() <= MAX_CONFIRM_LEAF_ROOT_GROUPS
        });
        if !fits {
            messages.push((Vec::new(), Vec::new()));
        }
        if let Some((filters, roots)) = messages.last_mut() {
            filters.push(filter);
            roots.extend(seat);
        }
    }
    // Groups no seat accounts for stay with the last message, as before.
    if let Some((_, last)) = messages.last_mut() {
        last.extend(roots);
    }
    messages
}

/// Split the filters of a join, leave or reject into lists one op carries.
fn filter_chunks(filters: &[Vec<u8>]) -> Vec<Vec<Vec<u8>>> {
    filters
        .chunks(MAX_FILTERS_PER_OP)
        .map(<[Vec<u8>]>::to_vec)
        .collect()
}

/// One line when a prover operation is split into several messages.
fn report_split(op: &'static str, filters: usize, messages: usize, frame_number: u64) {
    if messages > 1 {
        info!(
            op,
            frame = frame_number,
            epoch = quil_types::consensus::epoch_for_frame(frame_number),
            filters,
            chunks = messages,
            max_filters = MAX_FILTERS_PER_OP,
            "prover operation split into several messages: each carries at most the filters every node \
             decodes, and is submitted and retried on its own"
        );
    }
}

/// Decode a prover op as every node does, so this node never publishes one
/// they all refuse: a prover with 105 seats renewed 103 in one confirm, over
/// the filter limit, saw each publication succeed and retried it every few
/// frames while all 103 seats lapsed.
fn decode_prover_op(inner: &[u8]) -> Result<()> {
    let Some(prefix) = inner
        .get(..4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    else {
        return Err(QuilError::InvalidArgument(
            "prover op shorter than its type prefix".into(),
        ));
    };
    match prefix {
        TYPE_PROVER_JOIN => ProverJoin::from_canonical_bytes(inner).map(drop),
        TYPE_PROVER_CONFIRM => ProverConfirm::from_canonical_bytes(inner).map(drop),
        TYPE_PROVER_REJECT => ProverReject::from_canonical_bytes(inner).map(drop),
        TYPE_PROVER_LEAVE => ProverLeave::from_canonical_bytes(inner).map(drop),
        TYPE_PROVER_SENIORITY_MERGE => ProverSeniorityMerge::from_canonical_bytes(inner).map(drop),
        TYPE_SHARD_SPLIT => ShardSplit::from_canonical_bytes(inner).map(drop),
        TYPE_SHARD_MERGE => ShardMerge::from_canonical_bytes(inner).map(drop),
        _ => Ok(()),
    }
}

/// How the error of a prover op `refuse_undecodable` refused starts.
const UNDECODABLE: &str = "prover operation does not decode";

/// When a refused op of kind `op` (as `own_prover_ops::describe` names it)
/// is built again: the sender of a join, confirm, leave or reject fences its
/// filters for the retry fence; a seniority merge waits out its cooldown; a
/// shard split or merge is proposed again when its shard is next eligible.
fn refusal_retry(op: &str) -> &'static str {
    match op {
        "join" | "confirm" | "leave" | "reject" => "its filters are retried after the retry fence",
        "seniority_merge" => "proposed again after the seniority merge cooldown",
        "shard_split" | "shard_merge" => "proposed again when the shard is next eligible",
        _ => "built again when its sender next proposes it",
    }
}

/// Refuse to publish a prover op no node decodes; `refusal_retry` says when
/// it is built again. The warning is given at most once per op kind per
/// epoch.
fn refuse_undecodable(inner: &[u8], frame_number: u64) -> Result<()> {
    let Err(error) = decode_prover_op(inner) else {
        return Ok(());
    };
    let (op, filters) = crate::own_prover_ops::describe(inner);
    let epoch = quil_types::consensus::epoch_for_frame(frame_number);
    if refusal_reports().due(&op, epoch) {
        warn!(
            op,
            frame = frame_number,
            epoch,
            filters = filters.len(),
            longest_filter = filters.iter().map(Vec::len).max().unwrap_or(0),
            max_filters = MAX_FILTERS_PER_OP,
            max_filter_len = MAX_FILTER_LEN,
            max_leaf_root_groups = MAX_CONFIRM_LEAF_ROOT_GROUPS,
            %error,
            retry = refusal_retry(op),
            scope = "this node",
            action = "report this line as a defect: the node built an op over the limits every node decodes",
            "prover operation not published: no node can decode it, so no frame would include it (reported once \
             per op kind per epoch)"
        );
    }
    Err(QuilError::InvalidArgument(format!(
        "{UNDECODABLE}: {op}: {error}"
    )))
}

/// Whether `error` is `refuse_undecodable`'s: the op's filters are then
/// fenced, not retried on the next cycle.
fn is_undecodable(error: &QuilError) -> bool {
    matches!(error, QuilError::InvalidArgument(message) if message.starts_with(UNDECODABLE))
}

/// Keys already reported in an epoch: an anomaly that recurs while it lasts
/// is warned at most once per epoch per key.
struct EpochReports<K>(Mutex<HashMap<K, u64>>);

impl<K> Default for EpochReports<K> {
    fn default() -> Self {
        Self(Mutex::new(HashMap::new()))
    }
}

impl<K: Clone + Eq + std::hash::Hash> EpochReports<K> {
    /// Whether `key` is due a report in `epoch`; records the report.
    fn due(&self, key: &K, epoch: u64) -> bool {
        let Ok(mut reported) = self.0.lock() else {
            return false;
        };
        if reported.get(key).is_some_and(|last| *last >= epoch) {
            return false;
        }
        reported.retain(|_, last| last.saturating_add(1) >= epoch);
        reported.insert(key.clone(), epoch);
        true
    }
}

/// Op kinds whose refusal by `refuse_undecodable` was reported, by epoch.
fn refusal_reports() -> &'static EpochReports<&'static str> {
    static REPORTS: OnceLock<EpochReports<&'static str>> = OnceLock::new();
    REPORTS.get_or_init(EpochReports::default)
}

/// Seats left out of an op over the decode limits that were reported, by op
/// kind and epoch.
fn over_limit_reports() -> &'static EpochReports<(&'static str, Vec<u8>)> {
    static REPORTS: OnceLock<EpochReports<(&'static str, Vec<u8>)>> = OnceLock::new();
    REPORTS.get_or_init(EpochReports::default)
}

/// Warn of the seats an op leaves out because no node would decode a message
/// carrying them, each at most once per epoch: they are fenced until the
/// epoch ends and retried in the next, and the op goes ahead for the others.
fn report_over_limit(op: &'static str, frame_number: u64, seats: &[(Vec<u8>, String)]) {
    const LISTED: usize = 4;
    let epoch = quil_types::consensus::epoch_for_frame(frame_number);
    let due: Vec<&(Vec<u8>, String)> = seats
        .iter()
        .filter(|(filter, _)| over_limit_reports().due(&(op, filter.clone()), epoch))
        .collect();
    if due.is_empty() {
        return;
    }
    let mut reasons: Vec<&str> = due.iter().map(|(_, reason)| reason.as_str()).collect();
    reasons.sort_unstable();
    reasons.dedup();
    warn!(
        op,
        frame = frame_number,
        epoch,
        seats = due.len(),
        filters = %due.iter().take(LISTED).map(|(filter, _)| hex::encode(filter)).collect::<Vec<_>>().join(","),
        more_filters = due.len().saturating_sub(LISTED),
        reasons = %reasons.iter().take(3).copied().collect::<Vec<_>>().join("; "),
        scope = "this node",
        action = "report this line as a defect: the node prepared a seat over the limits every node decodes",
        "prover operation leaves out seats no node would decode in it; sending the others, retrying these in \
         the next epoch (each reported once per epoch)"
    );
}

/// Keep the filters `keep` admits, with their worker ids when the ids pair
/// one-to-one with the filters.
fn retain_paired(
    filters: &mut Vec<Vec<u8>>,
    worker_ids: Option<&mut Vec<u32>>,
    mut keep: impl FnMut(&[u8]) -> bool,
) {
    let kept: Vec<bool> = filters
        .iter()
        .map(|filter| keep(filter.as_slice()))
        .collect();
    if let Some(ids) = worker_ids.filter(|ids| ids.len() == kept.len()) {
        let mut index = 0;
        ids.retain(|_| {
            index += 1;
            kept[index - 1]
        });
    }
    let mut index = 0;
    filters.retain(|_| {
        index += 1;
        kept[index - 1]
    });
}

/// Split a join's filters into the lists one op carries, each with the
/// worker ids paired with its filters; ids that do not pair one-to-one with
/// the filters (none, for an admin join) go with every chunk.
pub fn join_chunks(filters: &[Vec<u8>], worker_ids: &[u32]) -> Vec<(Vec<Vec<u8>>, Vec<u32>)> {
    let paired = worker_ids.len() == filters.len();
    filters
        .chunks(MAX_FILTERS_PER_OP)
        .enumerate()
        .map(|(index, chunk)| {
            let workers = if paired {
                worker_ids[index * MAX_FILTERS_PER_OP..][..chunk.len()].to_vec()
            } else {
                worker_ids.to_vec()
            };
            (chunk.to_vec(), workers)
        })
        .collect()
}

/// Wrap a prover op in a single-request `MessageBundle` for the transport,
/// refusing one no node decodes.
fn prover_bundle(inner_bytes: Vec<u8>, frame_number: u64) -> Result<Vec<u8>> {
    refuse_undecodable(&inner_bytes, frame_number)?;
    let req = CanonicalMessageRequest::wrap(inner_bytes)?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let bundle = CanonicalMessageBundle {
        requests: vec![Some(req)],
        timestamp: now_ms,
    };
    bundle.to_canonical_bytes()
}

/// Standalone workers asked at once for their seats' leaf roots.
const REMOTE_PREPARATIONS: usize = 8;

/// How long one standalone worker may take to encode its seat's replicas and
/// answer: encoding a large shard is slow.
const REMOTE_PREPARATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// The share of an epoch one confirm's round of standalone-worker
/// preparations may take. A seat's renewal is due from its epoch's first
/// frame and lapses at the next boundary. Without a deadline each worker that
/// never answers held the round for its whole timeout, eight at a time, while
/// the round kept an encoder permit: 40 such workers held it for 50 minutes
/// of a two-hour mainnet epoch (720 frames of `IDEAL_FRAME_TIME`). A sixth of
/// an epoch, 20 minutes on mainnet, still gives a worker asked in the round's
/// first half its full timeout, and leaves five more rounds in the epoch for
/// the seats a round leaves out.
const REMOTE_ROUND_EPOCH_SHARE: u64 = 6;

/// When a round of standalone-worker preparations starting now must end.
fn remote_round_deadline() -> std::time::Instant {
    let epoch_ms = quil_types::consensus::epoch_length_frames()
        .saturating_mul(crate::difficulty::IDEAL_FRAME_TIME as u64);
    std::time::Instant::now()
        + std::time::Duration::from_millis(epoch_ms / REMOTE_ROUND_EPOCH_SHARE)
}

/// A standalone worker's answer for a seat: its leaf roots, `None` when no
/// standalone worker runs the seat, or why it gave none.
type RemoteAnswer = std::result::Result<Option<LeafRoots>, (LeftOutCause, QuilError)>;

/// Ask the standalone workers for their seats' leaf roots, `parallel` at a
/// time, keyed by filter, until `deadline`. Each answer may take up to the
/// worker's timeout, and a worker that does not answer must not hold up those
/// that do. Each worker encodes only its own shard, so the queries are
/// independent. A worker is given at most the time left before `deadline`:
/// one that has not answered by then is late, and a seat whose turn comes
/// after the deadline is not asked, so the round ends by it.
fn query_remote_workers<F>(
    requests: &[(Vec<u8>, Vec<Vec<u8>>)],
    parallel: usize,
    deadline: std::time::Instant,
    query: F,
) -> HashMap<Vec<u8>, RemoteAnswer>
where
    F: Fn(&[u8], &[Vec<u8>], std::time::Duration) -> Result<Option<LeafRoots>> + Sync,
{
    if requests.is_empty() {
        return HashMap::new();
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let answers = Mutex::new(HashMap::with_capacity(requests.len()));
    let threads = parallel.max(1).min(requests.len());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some((filter, targets)) = requests.get(index) else {
                    break;
                };
                let timeout = deadline
                    .saturating_duration_since(std::time::Instant::now())
                    .min(REMOTE_PREPARATION_TIMEOUT);
                let answer = if timeout.is_zero() {
                    Err((
                        LeftOutCause::Unasked,
                        QuilError::ExecutionUnavailable(
                            "not asked before the confirm round's deadline".into(),
                        ),
                    ))
                } else {
                    let asked = std::time::Instant::now();
                    query(filter, targets, timeout).map_err(|error| {
                        let cause = if asked.elapsed() >= timeout {
                            LeftOutCause::Late
                        } else {
                            LeftOutCause::Failed
                        };
                        (cause, error)
                    })
                };
                answers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(filter.clone(), answer);
            });
        }
    });
    answers.into_inner().unwrap_or_else(|e| e.into_inner())
}

/// Seats whose standalone workers were asked and had not answered by their
/// round's deadline. The next round asks them after the others, so workers
/// that never answer cannot fill every slot of each round while the seats
/// planned after them go unasked. Holds only this node's own seats.
#[derive(Default)]
struct LateSeats(Mutex<std::collections::HashSet<Vec<u8>>>);

impl LateSeats {
    /// Order `requests` with the late seats last, otherwise as planned.
    fn ask_last(&self, requests: &mut [(Vec<u8>, Vec<Vec<u8>>)]) {
        let late = self.0.lock().unwrap_or_else(|e| e.into_inner());
        requests.sort_by_key(|(filter, _)| late.contains(filter));
    }

    /// Record the round's `answers`: a seat asked and late is late, one that
    /// answered or failed in time is not; an unasked seat keeps its place.
    fn record(&self, answers: &HashMap<Vec<u8>, RemoteAnswer>) {
        let mut late = self.0.lock().unwrap_or_else(|e| e.into_inner());
        for (filter, answer) in answers {
            match answer {
                Err((LeftOutCause::Late, _)) => {
                    late.insert(filter.clone());
                }
                Err((LeftOutCause::Unasked, _)) => {}
                _ => {
                    late.remove(filter);
                }
            }
        }
    }
}

fn late_seats() -> &'static LateSeats {
    static LATE: OnceLock<LateSeats> = OnceLock::new();
    LATE.get_or_init(LateSeats::default)
}

/// Whether `roots` hold exactly one group for `filter` and one for each of
/// `targets`, and none for another shard: the worker encoded every shard the
/// seat registers, so the confirm registers the shards a pending change
/// creates from it.
fn answers_every_requested_shard(filter: &[u8], targets: &[Vec<u8>], roots: &LeafRoots) -> bool {
    roots.len() == 1 + targets.len()
        && std::iter::once(filter)
            .chain(targets.iter().map(Vec::as_slice))
            .all(|shard| roots.iter().filter(|group| group.filter == shard).count() == 1)
}

/// A standalone worker's answer as the preparation of the seat `filter`,
/// asked to encode `targets` too: its leaf roots when they cover every shard
/// asked for, or why the seat is left out; `None` when no standalone worker
/// runs the seat, which the master then encodes from its own store.
fn remote_answer(filter: &[u8], targets: &[Vec<u8>], answer: RemoteAnswer) -> Option<Prepared> {
    match answer {
        Ok(Some(roots)) if answers_every_requested_shard(filter, targets, &roots) => Some(Prepared::Roots(roots)),
        Ok(Some(roots)) => Some(Prepared::Unanswered(
            LeftOutCause::Incomplete,
            QuilError::ExecutionUnavailable(format!(
                "worker answered {} leaf-root groups, not one for its shard and each of its {} targets",
                roots.len(),
                targets.len(),
            )),
        )),
        Ok(None) => None,
        Err((cause, error)) => Some(Prepared::Unanswered(cause, error)),
    }
}

/// How many left-out seats each cause accounts for, e.g. `failed 2, late 1`.
fn left_out_causes<'a>(left_out: impl IntoIterator<Item = &'a LeftOutSeat>) -> String {
    let mut counts: std::collections::BTreeMap<LeftOutCause, usize> = Default::default();
    for seat in left_out {
        *counts.entry(seat.cause).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(cause, count)| format!("{} {count}", cause.name()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The distinct errors of left-out seats with their counts, most frequent
/// first, at most three.
fn left_out_errors<'a>(left_out: impl IntoIterator<Item = &'a LeftOutSeat>) -> String {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for seat in left_out {
        let error = seat.error.to_string();
        match counts.iter_mut().find(|(seen, _)| *seen == error) {
            Some((_, count)) => *count += 1,
            None => counts.push((error, 1)),
        }
    }
    counts.sort_by(|a, b| b.1.cmp(&a.1));
    let more = counts.len().saturating_sub(3);
    let mut summary: Vec<String> = counts
        .into_iter()
        .take(3)
        .map(|(error, count)| format!("{error} ({count})"))
        .collect();
    if more > 0 {
        summary.push(format!("{more} more"));
    }
    summary.join("; ")
}

/// A seniority-merge target GLOBAL already consumed: a join or seniority
/// merge stamped its spent marker, and GLOBAL refuses every later seniority
/// merge naming it, whoever submits it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConsumedMergeTarget {
    /// The target's Ed448 public key.
    pubkey: Vec<u8>,
    /// The merge that consumed it: `join merge` or `seniority merge`.
    marker: &'static str,
    /// The prover the marker credits, when it names one.
    credited: Option<Vec<u8>>,
}

/// Read a vertex (a spent marker, an allocation) from the node's committed
/// GLOBAL state.
fn global_vertex(
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    address: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    let va_disc = quil_execution::hypergraph_state::vertex_adds_discriminator()?;
    quil_execution::hypergraph_state::HypergraphState::new(crdt.clone()).get(
        &quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS[..],
        address,
        &va_disc,
    )
}

/// Seats left out of a confirm as refused that were reported, by epoch.
fn refused_seat_reports() -> &'static EpochReports<Vec<u8>> {
    static REPORTS: OnceLock<EpochReports<Vec<u8>>> = OnceLock::new();
    REPORTS.get_or_init(EpochReports::default)
}

/// Why every node would refuse a confirm naming `filter` at `frame_number`,
/// if it would: `validate_confirm_timing` on the committed allocation of the
/// prover `pubkey`, as GLOBAL checks each filter of a confirm, where one
/// refused filter sinks the whole message. The allocation can change while
/// the confirm is prepared (a leave of the seat lands). The rule reads only
/// the frame's epoch, which inclusion shares (`validate_confirm_epoch`).
/// Nothing for an absent or unreadable allocation, which GLOBAL skips too.
/// Reported at info once per seat per epoch.
fn confirm_refusal(
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    pubkey: &[u8],
    filter: &[u8],
    frame_number: u64,
) -> Option<QuilError> {
    let address =
        quil_execution::global_intrinsic::materialize::allocation_address(pubkey, filter).ok()?;
    let blob = global_vertex(crdt, &address)
        .ok()
        .flatten()
        .filter(|blob| !blob.is_empty())?;
    let tree = quil_execution::prover_registry::rebuild_vertex_tree_from_blob(&blob);
    let error =
        quil_execution::global_intrinsic::verify::validate_confirm_timing(frame_number, &tree)
            .err()?;
    let epoch = quil_types::consensus::epoch_for_frame(frame_number);
    if refused_seat_reports().due(&filter.to_vec(), epoch) {
        let status = quil_execution::global_schema::read_field(
            &tree,
            "allocation:ProverAllocation",
            "Status",
        )
        .and_then(|status| status.first().copied())
        .map(quil_execution::prover_registry::map_allocation_status);
        info!(frame = frame_number, epoch, filter = hex::encode(filter), status = ?status, %error, scope = "local",
            "confirmation leaves out a seat whose committed allocation no longer accepts it (a leave of it landed, \
             or it is already confirmed); submitting the others (reported once per seat per epoch)");
    }
    Some(error)
}

/// Build the `ProverSeniorityMerge` of `seeds` at `frame_number`, leaving out
/// the targets whose join- or seniority-merge spent marker `lookup` finds:
/// GLOBAL refuses those forever (`verify_prover_seniority_merge_spent_markers`).
/// Each target signs the prover key on its own, so the others still form a
/// valid merge; `None` when no target is left.
fn seniority_merge<F>(
    frame_number: u64,
    seeds: &[[u8; 57]],
    bls_pubkey: &[u8],
    prover_address: &[u8; 32],
    bls_signer: &dyn Signer,
    mut lookup: F,
) -> Result<(Option<ProverSeniorityMerge>, Vec<ConsumedMergeTarget>)>
where
    F: FnMut(&[u8; 32]) -> Result<Option<Vec<u8>>>,
{
    use quil_execution::global_intrinsic::materialize::{
        spent_join_merge_address, spent_seniority_merge_address,
    };
    let merge_domain_tag: &[u8] = b"PROVER_SENIORITY_MERGE";

    // Build one SeniorityMerge record per helper seed GLOBAL can still credit.
    let mut merge_targets: Vec<quil_execution::global_intrinsic::SeniorityMerge> =
        Vec::with_capacity(seeds.len());
    let mut consumed = Vec::new();
    'seeds: for seed in seeds {
        let helper_pubkey = quil_p2p::ed448_identity::derive_public_key(seed);
        for (marker, spent) in [
            ("join merge", spent_join_merge_address(&helper_pubkey)?),
            (
                "seniority merge",
                spent_seniority_merge_address(&helper_pubkey)?,
            ),
        ] {
            if let Some(blob) = lookup(&spent)? {
                let tree = quil_execution::prover_registry::rebuild_vertex_tree_from_blob(&blob);
                let credited = quil_execution::global_schema::read_field(
                    &tree,
                    "merge:SpentMerge",
                    "ProverAddress",
                )
                .filter(|address| address.len() == 32);
                consumed.push(ConsumedMergeTarget {
                    pubkey: helper_pubkey,
                    marker,
                    credited,
                });
                continue 'seeds;
            }
        }
        let helper_signer = quil_crypto::Ed448Signer::from_bytes(seed, &helper_pubkey)?;
        let helper_sig = <quil_crypto::Ed448Signer as Signer>::sign_with_domain(
            &helper_signer,
            bls_pubkey,
            merge_domain_tag,
        )?;

        merge_targets.push(quil_execution::global_intrinsic::SeniorityMerge {
            signature: helper_sig,
            key_type: quil_types::crypto::KeyType::Ed448 as u32,
            prover_public_key: helper_pubkey,
        });
    }
    if merge_targets.is_empty() {
        return Ok((None, consumed));
    }

    // BLS-sign `frame_be || helper_pubkeys_concat` under the
    // PROVER_SENIORITY_MERGE domain.
    let mut message: Vec<u8> = Vec::with_capacity(8 + merge_targets.len() * 57);
    message.extend_from_slice(&frame_number.to_be_bytes());
    for mt in &merge_targets {
        message.extend_from_slice(&mt.prover_public_key);
    }
    let domain = ProverPipeline::domain(merge_domain_tag)?;
    let bls_sig = bls_signer.sign_with_domain(&message, &domain)?;

    let merge = ProverSeniorityMerge {
        frame_number,
        public_key_signature_bls48581: Some(AddressedSignature {
            signature: bls_sig,
            address: prover_address.to_vec(),
        }),
        merge_targets,
    };
    Ok((Some(merge), consumed))
}

/// Build the seniority succession of `seeds` from the prover at
/// `predecessor` at `frame_number`: each seed consents to moving what it
/// brought that prover to this one (`prover key || predecessor || frame`
/// under `PROVER_SENIORITY_SUCCESSION`), and the prover signs the targets as
/// it signs a merge.
fn seniority_succession(
    frame_number: u64,
    seeds: &[[u8; 57]],
    bls_pubkey: &[u8],
    prover_address: &[u8; 32],
    bls_signer: &dyn Signer,
    predecessor: &[u8; 32],
) -> Result<ProverSeniorityMerge> {
    use quil_execution::global_intrinsic::seniority_succession::{
        succession_consent_message, SUCCESSION_DOMAIN,
    };
    let consent = succession_consent_message(bls_pubkey, predecessor, frame_number);
    let mut merge_targets = Vec::with_capacity(seeds.len());
    for seed in seeds {
        let pubkey = quil_p2p::ed448_identity::derive_public_key(seed);
        let signer = quil_crypto::Ed448Signer::from_bytes(seed, &pubkey)?;
        merge_targets.push(quil_execution::global_intrinsic::SeniorityMerge {
            signature: <quil_crypto::Ed448Signer as Signer>::sign_with_domain(
                &signer,
                &consent,
                SUCCESSION_DOMAIN,
            )?,
            key_type: quil_types::crypto::KeyType::Ed448 as u32,
            prover_public_key: pubkey,
        });
    }
    let mut message: Vec<u8> = Vec::with_capacity(8 + merge_targets.len() * 57);
    message.extend_from_slice(&frame_number.to_be_bytes());
    for target in &merge_targets {
        message.extend_from_slice(&target.prover_public_key);
    }
    let domain = ProverPipeline::domain(b"PROVER_SENIORITY_MERGE")?;
    Ok(ProverSeniorityMerge {
        frame_number,
        public_key_signature_bls48581: Some(AddressedSignature {
            signature: bls_signer.sign_with_domain(&message, &domain)?,
            address: prover_address.to_vec(),
        }),
        merge_targets,
    })
}

/// What this node last submitted under the seniority succession rules (each
/// op's kind, keys and predecessor): the same plan one cooldown later means
/// GLOBAL did not apply it, and the node holds proposals for the epoch.
fn last_seniority_submission() -> &'static Mutex<Vec<Vec<u8>>> {
    static LAST: OnceLock<Mutex<Vec<Vec<u8>>>> = OnceLock::new();
    LAST.get_or_init(|| Mutex::new(Vec::new()))
}

/// Whether the prover at `address` holds no allocation that would keep a
/// succession from it at `frame_number` (the rule GLOBAL applies) in
/// committed GLOBAL state; false when that cannot be read.
fn prover_idle(
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    address: &[u8],
    frame_number: u64,
) -> bool {
    let Ok(address) = <[u8; 32]>::try_from(address) else {
        return false;
    };
    let state = quil_execution::hypergraph_state::HypergraphState::new(crdt.clone());
    match quil_execution::global_intrinsic::seniority_succession::PredecessorState::read(
        &state, &address,
    ) {
        Ok(Some(prover)) => prover
            .allocations
            .iter()
            .all(|allocation| prover.allocation_blocks(allocation, frame_number).is_none()),
        _ => false,
    }
}

/// The last 6 characters of an identifier, as logs name peers and provers.
fn tail(id: &str) -> &str {
    &id[id.len().saturating_sub(6)..]
}

/// The operator's action when a target's seniority sits with another prover
/// that holds no live allocation.
const SUCCESSION_ACTION: &str = "that prover holds no live allocation: run `qclient node prover merge --dry-run <config dir>` \
     in the node directory to see whether a seniority succession can move its seniority to this prover, \
     and what blocks it";

/// Whom a consumed target's seniority went to, and what the operator can do
/// about it: nothing when it went to this prover. `credited_idle`: the
/// prover it went to holds no live allocation.
fn consumed_target_credit(
    target: &ConsumedMergeTarget,
    own: &[u8; 32],
    credited_idle: bool,
) -> (String, Option<&'static str>) {
    match &target.credited {
        Some(address) if address.as_slice() == own => ("this prover".into(), None),
        Some(address) if credited_idle => (
            format!("prover …{}", tail(&hex::encode(address))),
            Some(SUCCESSION_ACTION),
        ),
        Some(address) => (
            format!("prover …{}", tail(&hex::encode(address))),
            Some("its seniority counts for that prover; restore that prover's key to recover it"),
        ),
        None => (
            "no recorded prover".into(),
            Some("none: GLOBAL credits each target once"),
        ),
    }
}

/// Consumed merge targets this node reported, with the epoch of the report:
/// a target found consumed is reported at once and again at most once per
/// epoch while the lifecycle keeps proposing merges. Holds only this node's
/// own targets.
type ConsumedTargetReports = EpochReports<ConsumedMergeTarget>;

fn consumed_target_reports() -> &'static ConsumedTargetReports {
    static REPORTS: OnceLock<ConsumedTargetReports> = OnceLock::new();
    REPORTS.get_or_init(ConsumedTargetReports::default)
}

impl ProverPipeline {
    fn dispatch_confirmation(
        self: &Arc<Self>,
        mut filters: Vec<Vec<u8>>,
        frame_number: u64,
        needs_storage: bool,
        prune_replicas: bool,
    ) {
        // A seat whose message failed is retried without resending the seats
        // already published (see `reserve_filters`). A confirm of leaves is
        // part of leaving: a renewal's fence must not hold it off.
        let kind = if needs_storage {
            OpKind::Confirm
        } else {
            OpKind::Leave
        };
        let Some(attempt) = self.reserve_filters("confirm", kind, &mut filters, None, frame_number)
        else {
            return;
        };
        tracing::info!(
            frame = frame_number,
            filters = filters.len(),
            needs_storage,
            prune_replicas,
            "dispatching prover confirmation"
        );
        let me = self.clone();
        tokio::spawn(async move {
            // Limit expensive preparation independently from network timeouts.
            // Keep the reservation inside the blocking task: cancelling its
            // waiter cannot start a second encoder while the first still runs.
            let (filters, roots, seat_groups, mut attempt) = if needs_storage {
                static ENCODERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
                let Ok(permit) = ENCODERS.acquire().await else {
                    return;
                };
                let encoder = me.clone();
                let encoded_filters = filters.clone();
                let prepared = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    if prune_replicas {
                        let current_epoch = quil_types::consensus::epoch_for_frame(frame_number);
                        prune_confirmation_replicas(
                            encoder.replica_store.as_ref(),
                            encoder.storage_for_filter.as_deref(),
                            &encoded_filters,
                            current_epoch,
                        );
                    }
                    let confirm =
                        encoder.storage_confirm_leaf_roots(&encoded_filters, frame_number);
                    (confirm, attempt)
                })
                .await;
                match prepared {
                    Ok((Ok(prepared), mut attempt)) => {
                        if !prepared.left_out.is_empty() {
                            prepared.settle_left_out(&mut attempt, me.frame_now(frame_number));
                            me.report_left_out_seats(frame_number, &prepared);
                        }
                        (
                            prepared.filters,
                            prepared.roots,
                            prepared.seat_groups,
                            attempt,
                        )
                    }
                    Ok((Err(e), _attempt)) => {
                        warn!(frame = frame_number, %e, "confirmation preparation failed; retrying on next cycle");
                        return;
                    }
                    Err(e) => {
                        warn!(frame = frame_number, %e, "confirmation preparation task failed");
                        return;
                    }
                }
            } else {
                let mut attempt = attempt;
                let refused: Vec<Vec<u8>> = me.hypergraph.as_ref().map_or_else(Vec::new, |crdt| {
                    filters
                        .iter()
                        .filter(|filter| {
                            confirm_refusal(crdt, &me.bls_pubkey, filter, frame_number).is_some()
                        })
                        .cloned()
                        .collect()
                });
                attempt.fence(&refused, me.frame_now(frame_number));
                let filters: Vec<Vec<u8>> = filters
                    .into_iter()
                    .filter(|filter| !refused.contains(filter))
                    .collect();
                let seat_groups = vec![0; filters.len()];
                (filters, Vec::new(), seat_groups, attempt)
            };
            // Every node refuses a confirm over the filter or leaf-root group
            // limits, so a longer one is split; a failed message leaves its
            // seats to the next cycle and the others still go out. A message
            // the guard refuses keeps its seats fenced instead: rebuilding it
            // on the next cycle would only be refused again.
            let total = filters.len();
            let messages = confirm_messages(filters, roots, &seat_groups);
            let chunks = messages.len();
            report_split("confirm", total, chunks, frame_number);
            for (chunk, (filters, roots)) in messages.into_iter().enumerate() {
                let count = filters.len();
                match tokio::time::timeout(
                    NON_VDF_SUBMIT_TIMEOUT,
                    me.submit_confirm(filters.clone(), frame_number, roots),
                )
                .await
                {
                    Ok(Ok(())) => attempt.published_subset(&filters, me.frame_now(frame_number)),
                    Ok(Err(e)) if is_undecodable(&e) => {
                        attempt.fence(&filters, me.frame_now(frame_number))
                    }
                    Ok(Err(e)) => warn!(frame = frame_number, chunk, chunks, filters = count, %e,
                        "confirmation submission failed; retrying these filters on next cycle"),
                    Err(_) => {
                        warn!(frame = frame_number, chunk, chunks, filters = count,
                        "confirmation submission timed out; retrying these filters on next cycle")
                    }
                }
            }
        });
    }

    /// Warn, once per confirm, of the seats it leaves out because their
    /// workers did not prepare their storage, or not by the round's deadline:
    /// the confirm goes ahead for the others, and these are retried on the
    /// next cycle. Seats over the decode limits are reported apart (see
    /// `report_over_limit`).
    fn report_left_out_seats(&self, frame_number: u64, prepared: &PreparedConfirm) {
        const LISTED: usize = 16;
        // Refused seats are reported as they are found (`confirm_refusal`).
        let (over_limit, unprepared): (Vec<&LeftOutSeat>, Vec<&LeftOutSeat>) = prepared
            .left_out
            .iter()
            .filter(|seat| seat.cause != LeftOutCause::Refused)
            .partition(|seat| seat.cause == LeftOutCause::OverLimit);
        if !over_limit.is_empty() {
            let seats: Vec<(Vec<u8>, String)> = over_limit
                .iter()
                .map(|seat| (seat.filter.clone(), seat.error.to_string()))
                .collect();
            report_over_limit("confirm", frame_number, &seats);
        }
        if unprepared.is_empty() {
            return;
        }
        let workers = self.worker_manager.range_workers().unwrap_or_default();
        let mut core_ids: Vec<u32> = unprepared
            .iter()
            .filter_map(|seat| {
                workers
                    .iter()
                    .find(|w| w.filter == seat.filter)
                    .map(|w| w.core_id)
            })
            .collect();
        core_ids.sort_unstable();
        core_ids.dedup();
        let listed = core_ids
            .iter()
            .take(LISTED)
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        warn!(
            frame = frame_number,
            epoch = quil_types::consensus::epoch_for_frame(frame_number),
            left_out = unprepared.len(),
            requested = prepared.left_out.len() + prepared.filters.len(),
            submitted = prepared.filters.len(),
            causes = %left_out_causes(unprepared.iter().copied()),
            core_ids = %listed,
            more_core_ids = core_ids.len().saturating_sub(LISTED),
            errors = %left_out_errors(unprepared.iter().copied()),
            scope = "local workers",
            action = "check that these workers run, the master can reach them and they answer within the round",
            "confirmation leaves out seats whose workers did not prepare their storage in time; \
             submitting the others, retrying these on next cycle"
        );
    }

    /// Dispatch a lifecycle action. Non-blocking: spawns a tokio task
    /// to handle the (slow) VDF + sign + submit work so the caller's
    /// frame-processing loop continues.
    pub fn dispatch(self: &Arc<Self>, mut action: LifecycleAction) {
        // Confirmations acquire the same reservation inside their preparation
        // helper, where ownership also follows blocking encoders. Other shard
        // operations reserve before spawning so another evaluation cannot race.
        let reserved = match &mut action {
            LifecycleAction::ProposeJoin {
                filters,
                worker_ids,
                frame_number,
            } => Some(self.reserve_filters(
                "join",
                OpKind::Join,
                filters,
                Some(worker_ids),
                *frame_number,
            )),
            LifecycleAction::RejectJoins {
                filters,
                frame_number,
            }
            | LifecycleAction::RejectLeaves {
                filters,
                frame_number,
            } => Some(self.reserve_filters("reject", OpKind::Reject, filters, None, *frame_number)),
            LifecycleAction::ProposeLeave {
                filters,
                frame_number,
            } => Some(self.reserve_filters("leave", OpKind::Leave, filters, None, *frame_number)),
            _ => None,
        };
        let mut reservation = match reserved {
            Some(None) => return,
            Some(attempt) => attempt,
            None => None,
        };
        match action {
            LifecycleAction::Noop => {}
            LifecycleAction::ProposeJoin {
                filters,
                worker_ids,
                frame_number,
            } => {
                let me = self.clone();
                // Guard against overlapping VDF computations — set before
                // spawn so the next evaluate() sees it immediately.
                me.lifecycle.set_proof_in_progress(true);
                // Hard ceiling on the whole submit. VDF compute is
                // `spawn_blocking` and can run 10-20s on a slow box;
                // archive RPC has its own per-call timeout; BlossomSub
                // publish is fast. 90s is well above the legitimate
                // worst case but bounded — if anything in this path
                // ever hangs (transport bug, runtime starvation, etc.)
                // `proof_in_progress` clears so the lifecycle can
                // try again on the next frame instead of being
                // permanently stuck.
                const SUBMIT_JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);
                // Chunk the filters so no single ProverJoin exceeds the
                // decoder's `MAX_FILTERS` (100) ceiling — a >100-shard node
                // would otherwise emit one over-cap message every node drops
                // at decode. Each chunk is an independent, valid join (one
                // prover key, a subset of shards) that GLOBAL processes
                // additively, and marks only its own workers pending. As for
                // confirms, leaves and rejects, a chunk that fails or times
                // out leaves its filters to the next cycle while the others
                // still go out; `proof_in_progress` is held for at most one
                // timeout per chunk. Today there are ~49 shards ⇒ a single
                // chunk, byte-identical to the pre-chunking behaviour.
                tokio::spawn(async move {
                    let chunks = join_chunks(&filters, &worker_ids);
                    let chunk_count = chunks.len();
                    report_split("join", filters.len(), chunk_count, frame_number);
                    let mut attempt = reservation.take().expect("join reservation acquired");
                    for (idx, (chunk, chunk_workers)) in chunks.into_iter().enumerate() {
                        match tokio::time::timeout(
                            SUBMIT_JOIN_TIMEOUT,
                            me.submit_join(chunk.clone(), &chunk_workers, frame_number),
                        )
                        .await
                        {
                            Ok(Ok(())) => {
                                attempt.published_subset(&chunk, me.frame_now(frame_number))
                            }
                            Ok(Err(e)) if is_undecodable(&e) => {
                                attempt.fence(&chunk, me.frame_now(frame_number))
                            }
                            Ok(Err(e)) => {
                                warn!(frame = frame_number, chunk = idx, chunk_count, %e,
                                    "ProposeJoin submission failed; retrying these filters on next cycle");
                            }
                            Err(_) => {
                                warn!(
                                    frame = frame_number,
                                    chunk = idx,
                                    chunk_count,
                                    timeout_s = SUBMIT_JOIN_TIMEOUT.as_secs(),
                                    "ProposeJoin submission timed out; retrying these filters on next cycle",
                                );
                            }
                        }
                    }
                    me.lifecycle.set_proof_in_progress(false);
                });
            }
            LifecycleAction::ConfirmJoins {
                filters,
                frame_number,
            } => {
                self.dispatch_confirmation(filters, frame_number, true, false);
            }
            LifecycleAction::RejectJoins {
                filters,
                frame_number,
            } => {
                let attempt = reservation.take().expect("shard reservation acquired");
                self.spawn_filter_op(
                    FilterOp::Reject,
                    "RejectJoins",
                    filters,
                    frame_number,
                    attempt,
                );
            }
            LifecycleAction::ProposeLeave {
                filters,
                frame_number,
            } => {
                let attempt = reservation.take().expect("shard reservation acquired");
                self.spawn_filter_op(
                    FilterOp::Leave,
                    "ProposeLeave",
                    filters,
                    frame_number,
                    attempt,
                );
            }
            LifecycleAction::ConfirmLeaves {
                filters,
                frame_number,
            } => {
                self.dispatch_confirmation(filters, frame_number, false, false);
            }
            LifecycleAction::ReconfirmEpoch {
                filters,
                frame_number,
            } => {
                self.dispatch_confirmation(filters, frame_number, true, true);
            }
            LifecycleAction::RejectLeaves {
                filters,
                frame_number,
            } => {
                let attempt = reservation.take().expect("shard reservation acquired");
                self.spawn_filter_op(
                    FilterOp::Reject,
                    "RejectLeaves",
                    filters,
                    frame_number,
                    attempt,
                );
            }
            LifecycleAction::ProposeSeniorityMerge { frame_number } => {
                let me = self.clone();
                // TODO
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        NON_VDF_SUBMIT_TIMEOUT,
                        me.submit_seniority_merge(frame_number),
                    )
                    .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            warn!(frame = frame_number, %e, "ProposeSeniorityMerge submission failed");
                        }
                        Err(_) => {
                            warn!(
                                frame = frame_number,
                                timeout_s = NON_VDF_SUBMIT_TIMEOUT.as_secs(),
                                "ProposeSeniorityMerge submission timed out",
                            );
                        }
                    }
                });
            }
        }
    }

    /// Submit a leave or reject, split into ops every node decodes. Each is
    /// published on its own: one that fails leaves its filters to the next
    /// cycle while those already published stay fenced, as do those of one
    /// the guard refuses.
    fn spawn_filter_op(
        self: &Arc<Self>,
        op: FilterOp,
        label: &'static str,
        filters: Vec<Vec<u8>>,
        frame_number: u64,
        mut attempt: crate::submission_attempts::SubmissionAttempt,
    ) {
        let me = self.clone();
        tokio::spawn(async move {
            let chunks = filter_chunks(&filters);
            let chunk_count = chunks.len();
            report_split(op.name(), filters.len(), chunk_count, frame_number);
            for (chunk, filters) in chunks.into_iter().enumerate() {
                let submit = async {
                    match op {
                        FilterOp::Leave => me.submit_leave(filters.clone(), frame_number).await,
                        FilterOp::Reject => me.submit_reject(filters.clone(), frame_number).await,
                    }
                };
                match tokio::time::timeout(NON_VDF_SUBMIT_TIMEOUT, submit).await {
                    Ok(Ok(())) => attempt.published_subset(&filters, me.frame_now(frame_number)),
                    Ok(Err(e)) if is_undecodable(&e) => {
                        attempt.fence(&filters, me.frame_now(frame_number))
                    }
                    Ok(Err(e)) => {
                        warn!(frame = frame_number, chunk, chunk_count, %e,
                            "{label} submission failed; retrying these filters on next cycle");
                    }
                    Err(_) => {
                        warn!(
                            frame = frame_number,
                            chunk,
                            chunk_count,
                            timeout_s = NON_VDF_SUBMIT_TIMEOUT.as_secs(),
                            "{label} submission timed out; retrying these filters on next cycle",
                        );
                    }
                }
            }
        });
    }

    /// The frame a publication or fence is recorded at: the node's latest
    /// frame, else the action's.
    fn frame_now(&self, frame_number: u64) -> u64 {
        self.current_frame
            .as_ref()
            .map_or(frame_number, |frame| frame.effective())
    }

    /// Reserve a shard operation's filters for one attempt. A filter a
    /// running or recently published attempt owns stays with it and is
    /// dropped here, with its paired worker id: after one message of a split
    /// operation fails, the next cycle sends that message's filters, not the
    /// published ones again. A filter longer than every node decodes is
    /// fenced and reported instead of sent, so its message-mates still go
    /// out; it stays fenced from ops of its `kind` until the epoch ends.
    /// `None` when nothing is left to send.
    fn reserve_filters(
        &self,
        op: &'static str,
        kind: OpKind,
        filters: &mut Vec<Vec<u8>>,
        mut worker_ids: Option<&mut Vec<u32>>,
        frame_number: u64,
    ) -> Option<crate::submission_attempts::SubmissionAttempt> {
        let requested = filters.len();
        let attempts = &self.lifecycle.submission_attempts;
        retain_paired(filters, worker_ids.as_deref_mut(), |filter| {
            !attempts.owned(filter, frame_number, kind)
        });
        let Some(mut attempt) = attempts.begin(filters, frame_number, kind) else {
            info!(
                op,
                frame = frame_number,
                filters = requested,
                "shard submission deferred: another operation owns its filters"
            );
            return None;
        };
        let over_long: Vec<Vec<u8>> = filters
            .iter()
            .filter(|filter| filter.len() > MAX_FILTER_LEN)
            .cloned()
            .collect();
        if !over_long.is_empty() {
            retain_paired(filters, worker_ids, |filter| filter.len() <= MAX_FILTER_LEN);
            attempt.fence_for_epoch(&over_long, self.frame_now(frame_number));
            let seats: Vec<(Vec<u8>, String)> = over_long
                .into_iter()
                .map(|filter| {
                    let reason = format!(
                        "filter of {} bytes (at most {MAX_FILTER_LEN})",
                        filter.len()
                    );
                    (filter, reason)
                })
                .collect();
            report_over_limit(op, frame_number, &seats);
            if filters.is_empty() {
                return None;
            }
        }
        Some(attempt)
    }

    fn domain(label: &[u8]) -> Result<[u8; 32]> {
        let mut dp = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
        dp.extend_from_slice(label);
        quil_crypto::poseidon::hash_bytes_to_32(&dp)
    }

    fn bls_signer(&self) -> Result<Box<dyn Signer>> {
        self.key_manager
            .get_signer(quil_types::crypto::KeyType::Falcon512)
            .map_err(|e| QuilError::Internal(format!("no BLS signer: {e}")))
    }

    /// Submit a `ProverJoin` for the given filters. Normally driven
    /// by the lifecycle's `ProposeJoin` action; exposed pub so admin
    /// tooling (`NodeService::request_join`) can force an immediate
    /// submission bypassing the cooldown / readiness gate.
    ///
    /// `worker_ids` is the list of workers that will be pinned to
    /// each filter on success. Pass empty slice for admin submissions
    /// where worker assignment happens after registry confirmation.
    pub async fn submit_join(
        &self,
        filters: Vec<Vec<u8>>,
        worker_ids: &[u32],
        lifecycle_frame: u64,
    ) -> Result<()> {
        info!(
            filter_count = filters.len(),
            lifecycle_frame, "building ProverJoin"
        );

        let header = self.transport.latest_global_frame_header().await?;
        let frame_number = header.frame_number;

        // VDF proof-of-sequential-work is no longer required to join.
        // The `proof` field is retained in the wire format (empty here)
        // purely so historical joins still decode; new joins carry none.
        let all_proofs: Vec<u8> = Vec::new();

        // Seniority merge targets: our own + enrolled Ed448 seeds. The join op
        // itself only carries the BLS prover key, so the ONLY way the join can
        // factor in our libp2p peer-id(s)' premainnet seniority is to attach
        // them as merge targets — each Ed448 seed signs our BLS pubkey under
        // the `PROVER_JOIN_MERGE` domain (the same domain `verify_prover_join`
        // checks and `invoke_join` derives peer-ids from). Without this the
        // prover joins at seniority 0 regardless of what its peer-id earned,
        // and only a later `ProverSeniorityMerge` could raise it. A seed whose
        // peer-id has no premainnet seniority contributes 0 — harmless. This is
        // the same seed set used for `submit_seniority_merge` (own key first,
        // then `multisig_prover_enrollment_paths`).
        let merge_targets: Vec<quil_execution::global_intrinsic::SeniorityMerge> = {
            let mut mts = Vec::with_capacity(self.multisig_ed448_seeds.len());
            for seed in &self.multisig_ed448_seeds {
                let helper_pubkey = quil_p2p::ed448_identity::derive_public_key(seed);
                let helper_signer = quil_crypto::Ed448Signer::from_bytes(seed, &helper_pubkey)?;
                let helper_sig = <quil_crypto::Ed448Signer as Signer>::sign_with_domain(
                    &helper_signer,
                    &self.bls_pubkey,
                    b"PROVER_JOIN_MERGE",
                )?;
                mts.push(quil_execution::global_intrinsic::SeniorityMerge {
                    signature: helper_sig,
                    key_type: quil_types::crypto::KeyType::Ed448 as u32,
                    prover_public_key: helper_pubkey,
                });
            }
            mts
        };

        // Build + sign. Go signs the full ProverJoin canonical bytes
        // with signature=nil, then fills in the signature:
        // see global_prover_join.go:1074-1079.
        let signer = self.bls_signer()?;
        let unsigned = ProverJoin {
            filters: filters.clone(),
            frame_number,
            public_key_signature_bls48581: None,
            delegate_address: self.delegate_address.clone(),
            merge_targets: merge_targets.clone(),
            proof: all_proofs.clone(),
        };
        let join_message = unsigned.to_canonical_bytes()?;
        let join_domain = Self::domain(b"PROVER_JOIN")?;
        let signature = signer.sign_with_domain(&join_message, &join_domain)?;
        // Proof of possession: sign own pubkey with it, using BLS48_POP_SK domain.
        let pop_signature = signer.sign_with_domain(&self.bls_pubkey, b"BLS48_POP_SK")?;

        let signed = ProverJoin {
            filters: filters.clone(),
            frame_number,
            public_key_signature_bls48581: Some(SignatureWithPop {
                signature,
                public_key: Some(self.bls_pubkey.clone()),
                pop_signature,
            }),
            delegate_address: self.delegate_address.clone(),
            merge_targets,
            proof: all_proofs,
        };
        let bytes = signed.to_canonical_bytes()?;

        info!(
            frame = frame_number,
            filter_count = filters.len(),
            bytes_len = bytes.len(),
            "submitting ProverJoin"
        );
        crate::metrics::inc_prover_joins_submitted();

        self.publish_prover_message(bytes, frame_number).await?;

        // Publish succeeded — NOW burn the 4-frame cooldown. Setting
        // this earlier (in lifecycle's evaluate) would waste join
        // opportunities whenever an archive is unreachable or a VDF
        // self-verify fails: the next eligible frame would be gated
        // by a cooldown from a join that never actually reached the
        // network. Matches Go's post-success set at
        // `worker_allocator.go:224`.
        self.lifecycle.record_join_attempt(lifecycle_frame);

        // Persist the pending frame on each worker so reconcile can tell
        // "proposal in flight" from "orphaned". Uses `lifecycle_frame`
        // (not `frame_number`) — the timestamp matches the cooldown
        // timer on WorkerAllocator.
        for &core_id in worker_ids {
            let _ = self
                .worker_manager
                .set_pending_filter_frame(core_id, lifecycle_frame);
        }

        Ok(())
    }

    async fn submit_confirm(
        &self,
        filters: Vec<Vec<u8>>,
        frame_number: u64,
        leaf_roots: Vec<quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots>,
    ) -> Result<()> {
        // Storage-attestation confirm hook (PoRep): at/after activation,
        // partition each confirmed shard, SDR-encode + persist this prover's
        // per-leaf replicas, and fold the registered leaf roots into the
        // confirm. The signature covers `confirm_signing_message`, which
        // appends the leaf-root set — byte-identical to the legacy
        // concat(filters)||frame message when the set is empty (pre-activation
        // / deps absent), so default Go-parity is preserved.
        // From the confirm release frame the confirm reports and signs this
        // build's release, which GLOBAL records on each confirmed allocation.
        let release =
            quil_execution::global_intrinsic::prover_release::release_for_confirm(frame_number);
        let msg = quil_execution::global_intrinsic::prover_verify::confirm_signing_message(
            &filters,
            frame_number,
            &leaf_roots,
            release.as_ref(),
        );

        let signer = self.bls_signer()?;
        let domain = Self::domain(b"PROVER_CONFIRM")?;
        let signature = signer.sign_with_domain(&msg, &domain)?;

        let confirm = ProverConfirm {
            filter: vec![],
            frame_number,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature,
                address: self.prover_address.to_vec(),
            }),
            filters: filters.clone(),
            leaf_roots,
            release,
        };
        let bytes = confirm.to_canonical_bytes()?;

        info!(frame = frame_number, filter_count = filters.len(), leaf_roots = confirm.leaf_roots.len(),
            leaf_entries = confirm.leaf_roots.iter().map(|g| g.entries.len()).sum::<usize>(),
            release = %confirm.release.map_or_else(|| "none".to_string(), |release| release.to_string()),
            "submitting ProverConfirm");
        crate::metrics::inc_prover_confirms_submitted();
        // A hash-proof registration is sealed once this node's view shows it
        // recorded, which may trail GLOBAL by a registry pull; ask for an
        // early one.
        if quil_types::consensus::hash_storage_proofs_at(
            quil_types::consensus::epoch_for_frame(frame_number) + 1,
        ) && confirm
            .leaf_roots
            .iter()
            .any(|group| !group.entries.is_empty())
        {
            crate::global_view_refresh::shared().request(
                crate::global_view_refresh::Reason::StorageRecordAwaited,
                frame_number + 2,
                std::time::Instant::now(),
            );
        }
        self.publish_prover_message(bytes, frame_number).await
    }

    /// Each of `filters`' storage snapshot sources for `epoch` that GLOBAL has
    /// recorded (hash storage proofs; `storage_snapshot::sources`).
    fn snapshot_sources(
        &self,
        filters: &[Vec<u8>],
        changes: &[quil_types::store::PendingShardChange],
        epoch: u64,
    ) -> Vec<SnapshotSources> {
        let Some(lookup) = self.storage_snapshot.as_ref() else {
            return Vec::new();
        };
        if !quil_types::consensus::hash_storage_proofs_at(epoch) {
            return Vec::new();
        }
        filters
            .iter()
            .filter_map(|filter| {
                quil_execution::global_intrinsic::storage_snapshot::sources(
                    filter,
                    epoch,
                    changes,
                    |shard| lookup(shard, epoch),
                )
                .map(|sources| (filter.clone(), sources))
            })
            .collect()
    }

    /// Partition committed shard data into PoRep leaves, encode and persist the
    /// next epoch's replicas, and return their roots. Preparation errors abort
    /// submission so the lifecycle can retry, except a standalone worker's: its
    /// seat is left out of this confirm (see `prepare_confirm`). Standalone
    /// workers are asked concurrently, within a round deadline, and their
    /// answers must cover every shard asked for. Global confirms need no
    /// replicas.
    fn storage_confirm_leaf_roots(
        &self,
        filters: &[Vec<u8>],
        frame_number: u64,
    ) -> Result<PreparedConfirm> {
        let (Some(crdt), Some(replica_store)) =
            (self.hypergraph.as_ref(), self.replica_store.as_ref())
        else {
            if filters.iter().all(Vec::is_empty) {
                return Ok(PreparedConfirm {
                    filters: filters.to_vec(),
                    roots: Vec::new(),
                    seat_groups: vec![0; filters.len()],
                    left_out: Vec::new(),
                });
            }
            return Err(QuilError::Internal(
                "storage confirmation requires hypergraph and replica store".into(),
            ));
        };
        // Epoch-aligned: a confirm in epoch E encodes + registers leaf roots for
        // the NEXT epoch E+1 (the `next` slot). The prover encodes ahead so that
        // when it becomes active next epoch it is already proving against an
        // on-chain registration. The per-frame proving path
        // (`storage_vote_openings`) reads replica@CURRENT-epoch, which this same
        // store wrote one epoch earlier — so encode-ahead lines up exactly.
        let epoch = quil_types::consensus::epoch_for_frame(frame_number) + 1;
        // Shards a split or merge applying next epoch creates from a confirmed
        // shard are registered too, encoded from that shard's storage: its
        // holder is on one of them once the change applies.
        let changes = match self.pending_shard_changes.as_ref() {
            Some(pending) if frame_number >= quil_execution::global_intrinsic::leaf_root_registration::pre_registration_frame() => pending(),
            _ => Vec::new(),
        };
        // A shard whose thread worker is stopped to reopen its store is left
        // out: neither the worker nor the master's stores can prepare it.
        let workers = self.worker_manager.range_workers().unwrap_or_default();
        let stopped = stopped_store_filters(&workers);
        // The thread worker holding each shard, if any. A shard none holds is
        // prepared by the standalone worker running it, else by the master.
        let local: HashMap<_, _> = filters
            .iter()
            .filter(|filter| !filter.is_empty())
            .map(|filter| {
                (
                    filter.clone(),
                    self.storage_for_filter
                        .as_ref()
                        .and_then(|resolve| resolve(filter)),
                )
            })
            .collect();
        // Each seat's shards with the snapshot sources they register.
        let sources = |filter: &[u8], targets: &[Vec<u8>]| {
            let encoded: Vec<Vec<u8>> = std::iter::once(filter.to_vec())
                .chain(targets.iter().cloned())
                .collect();
            let snapshots = self.snapshot_sources(&encoded, &changes, epoch);
            // GLOBAL records the seat's snapshot a frame or two after its
            // frame; a regular node sees it at its next registry pull, which
            // may come after the renewal's grace. Ask for an early one,
            // reaching the frame before this one: a pull reaches the state
            // before the head, so asking for this frame would stay out of
            // reach while the renewal asks again every frame.
            if self.storage_snapshot.is_some()
                && quil_types::consensus::hash_storage_proofs_at(epoch)
                && frame_number >= quil_types::consensus::storage_snapshot_frame(epoch)
                && !snapshots
                    .iter()
                    .any(|(shard, _)| shard.as_slice() == filter)
            {
                crate::global_view_refresh::shared().request(
                    crate::global_view_refresh::Reason::StorageRecordAwaited,
                    frame_number.saturating_sub(1),
                    std::time::Instant::now(),
                );
            }
            (encoded, snapshots)
        };
        let mut answers = match self.remote_storage_confirm.as_ref() {
            Some(remote) => {
                let mut requests: Vec<(Vec<u8>, Vec<Vec<u8>>)> =
                    confirm_encoding_plan(filters, &changes, epoch)
                        .into_iter()
                        .filter(|(filter, _)| {
                            matches!(local.get(filter), Some(None)) && !stopped.contains(filter)
                        })
                        .collect();
                late_seats().ask_last(&mut requests);
                let answers = query_remote_workers(
                    &requests,
                    REMOTE_PREPARATIONS,
                    remote_round_deadline(),
                    |filter, targets, timeout| {
                        let (_, snapshots) = sources(filter, targets);
                        remote(filter, targets, frame_number, timeout, &snapshots)
                    },
                );
                late_seats().record(&answers);
                answers
            }
            None => HashMap::new(),
        };
        // Ask for the snapshot of every seat this node encodes before
        // preparing any: the confirm stops at the first seat not encoded yet,
        // and the seats encode side by side (`crate::storage_jobs`).
        if quil_types::consensus::hash_storage_proofs_at(epoch) {
            for (filter, targets) in confirm_encoding_plan(filters, &changes, epoch) {
                if stopped.contains(&filter) || answers.contains_key(&filter) {
                    continue;
                }
                let worker = local.get(&filter).cloned().flatten();
                let (filter_crdt, filter_replicas) = match worker.as_ref() {
                    Some((worker_crdt, worker_replicas)) => (worker_crdt, worker_replicas),
                    None => (crdt, replica_store),
                };
                let (encoded, snapshots) = sources(&filter, &targets);
                if let Err(error) = crate::app_shard_metadata::request_storage_snapshots(
                    filter_crdt,
                    filter_replicas,
                    &encoded,
                    &self.prover_address,
                    epoch,
                    &snapshots,
                ) {
                    warn!(epoch, filter = %hex::encode(&filter), %error,
                        "storage snapshot not requested; the seat asks again when prepared");
                }
            }
        }
        prepare_confirm(
            filters,
            &changes,
            epoch,
            |filter, targets| {
                if let Some(left_out) = stopped_seat(&stopped, filter) {
                    return Ok(left_out);
                }
                if let Some(prepared) = answers
                    .remove(filter)
                    .and_then(|answer| remote_answer(filter, targets, answer))
                {
                    return Ok(prepared);
                }
                let worker = local.get(filter).cloned().flatten();
                let (filter_crdt, filter_replicas) = match worker.as_ref() {
                    Some((worker_crdt, worker_replicas)) => (worker_crdt, worker_replicas),
                    None => (crdt, replica_store),
                };
                let (encoded, snapshots) = sources(filter, targets);
                match crate::app_shard_metadata::compute_storage_confirm(
                    filter_crdt,
                    filter_replicas,
                    &encoded,
                    &self.prover_address,
                    epoch,
                    quil_types::consensus::STORAGE_BLOCK_POLY_SIZE,
                    &quil_crypto::sdr::SdrParams::default(),
                    frame_number,
                    &snapshots,
                ) {
                    Ok(roots) => Ok(Prepared::Roots(roots)),
                    Err(error) if worker.is_some() => stopped_mid_encode(&workers, filter, error),
                    Err(error) => Err(error),
                }
            },
            |filter| confirm_refusal(crdt, &self.bls_pubkey, filter, frame_number),
        )
    }

    async fn submit_reject(&self, filters: Vec<Vec<u8>>, frame_number: u64) -> Result<()> {
        // Go: sign(concat(filters) || u64(frame_number), PROVER_REJECT_domain).
        // See global_prover_reject.go:260-295.
        let mut msg = Vec::new();
        for f in &filters {
            msg.extend_from_slice(f);
        }
        msg.extend_from_slice(&frame_number.to_be_bytes());

        let signer = self.bls_signer()?;
        let domain = Self::domain(b"PROVER_REJECT")?;
        let signature = signer.sign_with_domain(&msg, &domain)?;

        let reject = ProverReject {
            filter: vec![],
            frame_number,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature,
                address: self.prover_address.to_vec(),
            }),
            filters: filters.clone(),
        };
        let bytes = reject.to_canonical_bytes()?;

        info!(
            frame = frame_number,
            filter_count = filters.len(),
            "submitting ProverReject"
        );
        crate::metrics::inc_prover_rejects_submitted();
        self.publish_prover_message(bytes, frame_number).await
    }

    /// Submit a `ShardSplit` proposal for the given shard → child set.
    /// Go signs `u64_be(frame) || shard_address` under the
    /// `SHARD_SPLIT` domain. See `global_shard_split.go:205-230`.
    pub async fn submit_shard_split(
        &self,
        shard_address: Vec<u8>,
        proposed_shards: Vec<Vec<u8>>,
        frame_number: u64,
    ) -> Result<()> {
        let mut msg = Vec::with_capacity(8 + shard_address.len());
        msg.extend_from_slice(&frame_number.to_be_bytes());
        msg.extend_from_slice(&shard_address);

        let signer = self.bls_signer()?;
        let domain = Self::domain(b"SHARD_SPLIT")?;
        let signature = signer.sign_with_domain(&msg, &domain)?;

        let split = ShardSplit {
            shard_address: shard_address.clone(),
            proposed_shards,
            frame_number,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature,
                address: self.prover_address.to_vec(),
            }),
        };
        let bytes = split.to_canonical_bytes()?;
        debug!(
            frame = frame_number,
            shard = hex::encode(&shard_address),
            "submitting ShardSplit"
        );
        crate::metrics::inc_shard_splits_submitted();
        self.publish_prover_message_local_first(bytes, frame_number)
            .await
    }

    /// Submit a `ShardMerge` proposal for the given shard list →
    /// parent. Go signs `u64_be(frame) || parent_address` under the
    /// `SHARD_MERGE` domain. See `global_shard_merge.go:203-230`.
    pub async fn submit_shard_merge(
        &self,
        shard_addresses: Vec<Vec<u8>>,
        parent_address: Vec<u8>,
        frame_number: u64,
    ) -> Result<()> {
        let mut msg = Vec::with_capacity(8 + parent_address.len());
        msg.extend_from_slice(&frame_number.to_be_bytes());
        msg.extend_from_slice(&parent_address);

        let signer = self.bls_signer()?;
        let domain = Self::domain(b"SHARD_MERGE")?;
        let signature = signer.sign_with_domain(&msg, &domain)?;

        let merge = ShardMerge {
            shard_addresses,
            parent_address: parent_address.clone(),
            frame_number,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature,
                address: self.prover_address.to_vec(),
            }),
        };
        let bytes = merge.to_canonical_bytes()?;
        debug!(
            frame = frame_number,
            parent = hex::encode(&parent_address),
            "submitting ShardMerge"
        );
        crate::metrics::inc_shard_merges_submitted();
        self.publish_prover_message_local_first(bytes, frame_number)
            .await
    }

    /// Submit a `ProverSeniorityMerge` to raise on-chain seniority.
    /// Mirrors Go's `submitSeniorityMerge` at `worker_allocator.go:1725-1783`
    /// and `ProverSeniorityMerge.Prove` at `global_prover_seniority_merge.go:270-349`.
    async fn submit_seniority_merge(&self, frame_number: u64) -> Result<()> {
        if self.multisig_ed448_seeds.is_empty() {
            return Err(QuilError::Internal(
                "seniority merge: no multisig Ed448 seeds loaded".into(),
            ));
        }

        let bls_signer = self.bls_signer()?;
        // From the seniority succession epoch the node submits what
        // `plan_submissions` finds, the same plan the qclient dry run shows.
        if quil_types::consensus::seniority_succession_active(frame_number) {
            let Some(crdt) = self.hypergraph.clone() else {
                // Without GLOBAL state the node cannot tell what GLOBAL would
                // apply (or whether its prover has a record): send nothing.
                self.lifecycle.hold_seniority_merge(frame_number);
                return Ok(());
            };
            {
                let planned = self.succession_rule_ops(frame_number, &crdt, bls_signer.as_ref());
                drop(bls_signer);
                let (ops, signature) = match planned {
                    Ok(planned) => planned,
                    Err(error) => {
                        // Look again next epoch rather than every cooldown.
                        self.lifecycle.hold_seniority_merge(frame_number);
                        return Err(error);
                    }
                };
                // Nothing GLOBAL would apply, or the same ops as last time:
                // GLOBAL did not apply them, so look again next epoch.
                let repeated = {
                    let mut last = last_seniority_submission()
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    let repeated = ops.is_empty() || *last == signature;
                    *last = if repeated { Vec::new() } else { signature };
                    repeated
                };
                if repeated {
                    self.lifecycle.hold_seniority_merge(frame_number);
                    return Ok(());
                }
                for op in ops {
                    self.publish_prover_message(op.to_canonical_bytes()?, frame_number)
                        .await?;
                }
                return Ok(());
            }
        }
        let (merge, consumed) = seniority_merge(
            frame_number,
            &self.multisig_ed448_seeds,
            &self.bls_pubkey,
            &self.prover_address,
            bls_signer.as_ref(),
            |address| {
                self.hypergraph
                    .as_ref()
                    .map_or(Ok(None), |crdt| global_vertex(crdt, address))
            },
        )?;
        self.report_consumed_merge_targets(&consumed, frame_number);
        let Some(merge) = merge else {
            // GLOBAL would refuse it: no target is left to credit.
            self.lifecycle.hold_seniority_merge(frame_number);
            return Ok(());
        };
        let bytes = merge.to_canonical_bytes()?;

        info!(
            frame = frame_number,
            helpers = merge.merge_targets.len(),
            consumed = consumed.len(),
            "submitting ProverSeniorityMerge"
        );
        if self.hypergraph.is_none() {
            // Without GLOBAL state this node cannot tell whether the merge
            // applied: submit it once per epoch.
            self.lifecycle.hold_seniority_merge(frame_number);
        }
        self.publish_prover_message(bytes, frame_number).await
    }

    /// The merge and successions this node's keys can make now under the
    /// seniority succession rules, signed: a merge when it adds seniority,
    /// a succession for each predecessor GLOBAL would let succeed now that
    /// raises this prover's seniority. Reports the keys that count for
    /// another prover or fit nothing.
    fn succession_rule_ops(
        &self,
        frame_number: u64,
        crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
        bls_signer: &dyn Signer,
    ) -> Result<(Vec<ProverSeniorityMerge>, Vec<Vec<u8>>)> {
        use quil_execution::global_intrinsic::seniority_succession::{
            plan_submissions, retro_parts, TargetStanding,
        };
        let state = quil_execution::hypergraph_state::HypergraphState::new(crdt.clone());
        let keys: Vec<Vec<u8>> = self
            .multisig_ed448_seeds
            .iter()
            .map(quil_p2p::ed448_identity::derive_public_key)
            .collect();
        let plan = plan_submissions(
            &state,
            frame_number,
            &self.prover_address,
            &keys,
            &retro_parts,
        )?;
        let consumed: Vec<ConsumedMergeTarget> = plan
            .keys
            .iter()
            .zip(&keys)
            .filter_map(|((markers, standing), key)| {
                let marker = if markers.join.is_some() {
                    "join merge"
                } else {
                    "seniority merge"
                };
                let credited = match standing {
                    TargetStanding::Fresh => return None,
                    TargetStanding::Own => Some(self.prover_address.to_vec()),
                    TargetStanding::Other(prover) => Some(prover.to_vec()),
                    TargetStanding::Unusable(_) => None,
                };
                Some(ConsumedMergeTarget {
                    pubkey: key.clone(),
                    marker,
                    credited,
                })
            })
            .collect();
        self.report_consumed_merge_targets(&consumed, frame_number);
        let seeds_of = |indexes: &[usize]| -> Vec<[u8; 57]> {
            indexes
                .iter()
                .map(|&index| self.multisig_ed448_seeds[index])
                .collect()
        };
        let mut ops = Vec::new();
        let mut signature: Vec<Vec<u8>> = Vec::new();
        if let Some(merge) = &plan.merge {
            signature.push(
                merge
                    .keys
                    .iter()
                    .map(|&index| index as u8)
                    .chain([b'm'])
                    .collect(),
            );
            let seeds = seeds_of(&merge.keys);
            let (op, _) = seniority_merge(
                frame_number,
                &seeds,
                &self.bls_pubkey,
                &self.prover_address,
                bls_signer,
                |_| Ok(None),
            )?;
            if let Some(op) = op {
                info!(
                    frame = frame_number,
                    peer_keys = seeds.len(),
                    increment = merge.increment,
                    "submitting ProverSeniorityMerge"
                );
                ops.push(op);
            }
        }
        for candidate in plan
            .successions
            .iter()
            .filter(|candidate| candidate.submits())
        {
            let seeds = seeds_of(&candidate.keys);
            signature.push(
                candidate
                    .predecessor
                    .iter()
                    .copied()
                    .chain(candidate.keys.iter().map(|&index| index as u8))
                    .chain([b's'])
                    .collect(),
            );
            info!(
                frame = frame_number,
                predecessor = %format!("…{}", tail(&hex::encode(candidate.predecessor))),
                predecessor_seniority = candidate.preview.predecessor_seniority(),
                seniority = candidate.preview.successor_seniority,
                new_seniority = candidate.preview.new_seniority,
                moved_accrual = candidate.preview.amounts.accrual,
                peer_keys = candidate.moving,
                scope = "local",
                "submitting seniority succession: this node's peer keys move the seniority of the idle prover \
                 they count for to this prover"
            );
            ops.push(seniority_succession(
                frame_number,
                &seeds,
                &self.bls_pubkey,
                &self.prover_address,
                bls_signer,
                &candidate.predecessor,
            )?);
        }
        Ok((ops, signature))
    }

    /// Report each consumed merge target once, and at most once per epoch
    /// while it stays out of the merges this node proposes: a warning when
    /// its seniority went elsewhere, a note when it went to this prover.
    fn report_consumed_merge_targets(&self, consumed: &[ConsumedMergeTarget], frame_number: u64) {
        let epoch = quil_types::consensus::epoch_for_frame(frame_number);
        for target in consumed
            .iter()
            .filter(|target| consumed_target_reports().due(target, epoch))
        {
            let peer =
                bs58::encode(quil_p2p::peer_id_from_ed448_pubkey(&target.pubkey)).into_string();
            let target_peer = format!("…{}", tail(&peer));
            let credited_idle = target.credited.as_ref().is_some_and(|credited| {
                credited.as_slice() != &self.prover_address[..]
                    && self
                        .hypergraph
                        .as_ref()
                        .is_some_and(|crdt| prover_idle(crdt, credited, frame_number))
            });
            match consumed_target_credit(target, &self.prover_address, credited_idle) {
                (credited_to, None) => info!(
                    frame = frame_number,
                    epoch,
                    target_peer = %target_peer,
                    marker = target.marker,
                    credited_to = %credited_to,
                    "seniority merge target already credited to this prover; \
                     left out of its seniority merges"
                ),
                (credited_to, Some(action)) => warn!(
                    frame = frame_number,
                    epoch,
                    target_peer = %target_peer,
                    marker = target.marker,
                    credited_to = %credited_to,
                    scope = "committed GLOBAL state",
                    action,
                    "seniority merge target already consumed: GLOBAL refuses to merge it again, \
                     so this node leaves it out of its seniority merges"
                ),
            }
        }
    }

    async fn submit_leave(&self, filters: Vec<Vec<u8>>, frame_number: u64) -> Result<()> {
        // Go's leave message format differs — length-prefixed:
        //   u32(num_filters) || for each: u32(len) || filter || u64(frame).
        // See global_prover_leave.go:230-245.
        let mut msg = Vec::new();
        msg.extend_from_slice(&(filters.len() as u32).to_be_bytes());
        for f in &filters {
            msg.extend_from_slice(&(f.len() as u32).to_be_bytes());
            msg.extend_from_slice(f);
        }
        msg.extend_from_slice(&frame_number.to_be_bytes());

        let signer = self.bls_signer()?;
        let domain = Self::domain(b"PROVER_LEAVE")?;
        let signature = signer.sign_with_domain(&msg, &domain)?;

        let leave = ProverLeave {
            filters: filters.clone(),
            frame_number,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature,
                address: self.prover_address.to_vec(),
            }),
        };
        let bytes = leave.to_canonical_bytes()?;

        info!(
            frame = frame_number,
            filter_count = filters.len(),
            "submitting ProverLeave"
        );
        crate::metrics::inc_prover_leaves_submitted();
        self.publish_prover_message(bytes, frame_number).await
    }

    /// Wrap `inner_bytes`, an op built at `frame_number`, in a
    /// `MessageBundle` (see `prover_bundle`) and hand off to the configured
    /// transport. The transport is responsible for the gRPC fan-out + pubsub
    /// publish (production) or in-memory broadcast (tests).
    async fn publish_prover_message(&self, inner_bytes: Vec<u8>, frame_number: u64) -> Result<()> {
        let tracked = inner_bytes.clone();
        let bundle_bytes = prover_bundle(inner_bytes, frame_number)?;
        self.transport.publish_prover_bundle(bundle_bytes).await?;
        let frame = self
            .current_frame
            .as_ref()
            .map_or(0, |frame| frame.effective());
        crate::own_prover_ops::tracker().submitted(&tracked, frame);
        Ok(())
    }

    /// Loop a self-generated op into the LOCAL mempool (the same collector the
    /// gRPC/gossip ingest feeds), tagged with the current consensus rank exactly
    /// like the gRPC ingest (grpc.rs:400). Returns true if the op is now in the
    /// local mempool (freshly Accepted, or already present as a Duplicate).
    fn loopback_to_local_mempool(&self, bundle_bytes: &[u8]) -> bool {
        match (&self.local_message_collector, &self.current_frame) {
            (Some(mc), Some(cf)) => matches!(
                mc.add_message_outcome(cf.effective_rank(), bundle_bytes.to_vec()),
                SubmitOutcome::Accepted | SubmitOutcome::Duplicate
            ),
            _ => false,
        }
    }

    /// Publish a self-generated op LOCAL-FIRST: add it to this node's own mempool
    /// (so a frame PRODUCER includes its own op) AND best-effort publish to remote
    /// paths. Succeeds if EITHER path delivered — so a single-archive producer
    /// (where the remote publish has no acceptor and gossipsub won't self-loop)
    /// still submits its op instead of failing with "no archive accepted". Used
    /// for ShardSplit/ShardMerge, which the coverage orchestrator generates on
    /// the frame producer itself.
    async fn publish_prover_message_local_first(
        &self,
        inner_bytes: Vec<u8>,
        frame_number: u64,
    ) -> Result<()> {
        let bundle_bytes = prover_bundle(inner_bytes, frame_number)?;
        let looped = self.loopback_to_local_mempool(&bundle_bytes);
        let published = self.transport.publish_prover_bundle(bundle_bytes).await;
        if looped || published.is_ok() {
            if looped {
                debug!("prover op looped back into local mempool (producer self-inclusion)");
            }
            Ok(())
        } else {
            published
        }
    }
}

/// Retire obsolete replicas before encoding the next epoch so its writes do
/// not overlap a fourth epoch. Clean the stores confirmations actually use. Preserve
/// the previous epoch too: early in an epoch, frames can still anchor their
/// storage beacon before its boundary. Publication is not registration proof.
fn prune_confirmation_replicas(
    master: Option<&quil_store::replica_store::ReplicaStore>,
    worker: Option<
        &(dyn Fn(
            &[u8],
        ) -> Option<(
            Arc<quil_hypergraph::HypergraphCrdt>,
            quil_store::replica_store::ReplicaStore,
        )> + Send
              + Sync),
    >,
    filters: &[Vec<u8>],
    current_epoch: u64,
) {
    let keep_from = crate::app_shard_metadata::replica_keep_from(current_epoch);
    let workers = filters.iter().filter_map(|filter| {
        worker
            .and_then(|resolve| resolve(filter))
            .map(|(_, replicas)| replicas)
    });
    for (store_index, store) in master.cloned().into_iter().chain(workers).enumerate() {
        if let Err(error) = store.evict_below_epoch(keep_from) {
            warn!(store_index, keep_from_epoch = keep_from, %error, "replica cleanup failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::confirm_encoding_plan;
    use crate::submission_attempts::OpKind;
    use quil_types::store::{PendingShardChange, ShardChangeKind};

    #[test]
    fn confirmation_prunes_worker_stores_and_keeps_boundary_replicas() {
        use quil_store::replica_store::ReplicaStore;
        use std::sync::Arc;
        let make = || ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        let master = make();
        let worker_a = make();
        let worker_b = make();
        let unrelated = make();
        for store in [&master, &worker_a, &worker_b, &unrelated] {
            for epoch in 5..=8 {
                store.put(epoch, b"leaf", &[epoch as u8]).unwrap();
            }
        }
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        let resolve = |filter: &[u8]| match filter {
            [1] => Some((crdt.clone(), worker_a.clone())),
            [2] => Some((crdt.clone(), worker_b.clone())),
            _ => None,
        };
        super::prune_confirmation_replicas(
            Some(&master),
            Some(&resolve),
            &[vec![1], vec![2], vec![99]],
            7,
        );
        for store in [&master, &worker_a, &worker_b] {
            assert!(
                store.get(5, b"leaf").unwrap().is_none(),
                "old epochs must be pruned in each encoded store"
            );
            for epoch in 6..=8 {
                assert_eq!(
                    store.get(epoch, b"leaf").unwrap(),
                    Some(vec![epoch as u8]),
                    "previous/current/next replicas stay readable"
                );
            }
        }
        assert_eq!(
            unrelated.get(5, b"leaf").unwrap(),
            Some(vec![5]),
            "unselected stores are untouched"
        );
        // A low epoch cannot underflow the retention boundary.
        super::prune_confirmation_replicas(None, Some(&resolve), &[vec![1]], 0);
        assert_eq!(worker_a.get(6, b"leaf").unwrap(), Some(vec![6]));
    }

    #[test]
    fn a_failed_master_cleanup_does_not_skip_worker_cleanup() {
        use quil_store::replica_store::ReplicaStore;
        use std::sync::Arc;
        let primary = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let writable = ReplicaStore::new(primary.clone());
        writable.put(5, b"leaf", b"old").unwrap();
        let readonly = ReplicaStore::new(Arc::new(
            quil_store::RocksDb::open_for_read_only_live(primary.inner().path()).unwrap(),
        ));
        assert_eq!(readonly.get(5, b"leaf").unwrap(), Some(b"old".to_vec()));
        let worker = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        worker.put(5, b"leaf", b"old").unwrap();
        worker.put(7, b"leaf", b"current").unwrap();
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        let resolve = |_: &[u8]| Some((crdt.clone(), worker.clone()));
        super::prune_confirmation_replicas(Some(&readonly), Some(&resolve), &[vec![1]], 7);
        assert_eq!(readonly.get(5, b"leaf").unwrap(), Some(b"old".to_vec()));
        assert!(worker.get(5, b"leaf").unwrap().is_none());
        assert_eq!(worker.get(7, b"leaf").unwrap(), Some(b"current".to_vec()));
    }

    fn change(kind: ShardChangeKind, parent: u8, children: &[u8]) -> PendingShardChange {
        PendingShardChange {
            kind,
            parent: vec![parent],
            children: children.iter().map(|c| vec![*c]).collect(),
            effective_epoch: 8,
            proposed_frame: 0,
        }
    }

    fn roots_of(
        filter: &[u8],
    ) -> quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots {
        quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots {
            filter: filter.to_vec(),
            entries: Vec::new(),
        }
    }

    fn unanswered() -> quil_types::error::QuilError {
        quil_types::error::QuilError::ExecutionUnavailable(
            "worker storage confirm: tcp connect error".into(),
        )
    }

    fn left_out_filters(prepared: &super::PreparedConfirm) -> Vec<Vec<u8>> {
        prepared
            .left_out
            .iter()
            .map(|seat| seat.filter.clone())
            .collect()
    }

    #[test]
    fn a_confirm_skips_a_filter_whose_worker_does_not_answer() {
        use std::sync::Arc;
        let attempts = Arc::new(crate::submission_attempts::SubmissionAttempts::default());
        let filters = vec![vec![1], vec![2]];
        let mut attempt = attempts.begin(&filters, FRAME, OpKind::Confirm).unwrap();
        let prepared = super::prepare_confirm(
            &filters,
            &[],
            2,
            |filter, _| {
                Ok(match filter {
                    [2] => super::Prepared::Unanswered(super::LeftOutCause::Failed, unanswered()),
                    _ => super::Prepared::Roots(vec![roots_of(filter)]),
                })
            },
            |_| None,
        )
        .expect("the seat whose worker answers is confirmed");
        assert_eq!(
            prepared.filters,
            vec![vec![1]],
            "the confirm names only the prepared seat"
        );
        assert_eq!(prepared.roots, vec![roots_of(&[1])]);
        assert_eq!(left_out_filters(&prepared), vec![vec![2]]);
        assert_eq!(
            super::left_out_errors(&prepared.left_out),
            "execution unavailable: worker storage confirm: tcp connect error (1)"
        );
        prepared.settle_left_out(&mut attempt, FRAME);
        assert!(
            attempts.begin(&[vec![2]], FRAME, OpKind::Confirm).is_some(),
            "the left-out seat is free for the next cycle"
        );
        assert!(
            attempts.begin(&[vec![1]], FRAME, OpKind::Confirm).is_none(),
            "the submitted seat stays reserved"
        );
        attempt.published(FRAME);
        assert!(
            attempts
                .begin(&[vec![1]], FRAME + 1, OpKind::Confirm)
                .is_none(),
            "only the submitted seat is fenced as published"
        );
        assert!(attempts
            .begin(&[vec![2]], FRAME + 1, OpKind::Confirm)
            .is_some());
    }

    /// A seat whose thread worker is held stopped for its store is left out
    /// and retried next cycle, never prepared from the master's stores.
    #[test]
    fn a_seat_whose_worker_store_is_stopped_is_left_out() {
        use std::sync::Arc;
        let worker = |core_id: u32, filter: Vec<u8>| crate::worker::WorkerInfo {
            core_id,
            filter,
            available_storage: 0,
            total_storage: 0,
            manually_managed: false,
            pending_filter_frame: 0,
            allocated: true,
        };
        let workers = [
            worker(9_501, vec![1]),
            worker(9_502, vec![2]),
            worker(9_503, Vec::new()),
            worker(9_504, vec![3]),
        ];
        assert!(super::stopped_store_filters(&workers).is_empty());
        quil_forest::storage_health::hold_store(quil_forest::StoreRole::Worker(9_502));
        quil_forest::storage_health::hold_store(quil_forest::StoreRole::Worker(9_503));
        // A worker whose store failed a write and is not stopped yet, or whose
        // restarts ran out: its store refuses the confirm's replica writes.
        let latched = quil_store::RocksDb::open_in_memory().unwrap();
        assert!(latched
            .inner()
            .register_store(quil_forest::StoreRole::Worker(9_504)));
        latched
            .inner()
            .refuse_writes("IO error: Input/output error");
        let stopped = super::stopped_store_filters(&workers);
        quil_forest::storage_health::release_store(quil_forest::StoreRole::Worker(9_502));
        quil_forest::storage_health::release_store(quil_forest::StoreRole::Worker(9_503));
        assert_eq!(stopped, std::collections::HashSet::from([vec![2], vec![3]]));
        let attempts = Arc::new(crate::submission_attempts::SubmissionAttempts::default());
        let filters = vec![vec![1], vec![2], vec![3]];
        let mut attempt = attempts.begin(&filters, FRAME, OpKind::Confirm).unwrap();
        let prepared = super::prepare_confirm(
            &filters,
            &[],
            2,
            |filter, _| {
                if let Some(left_out) = super::stopped_seat(&stopped, filter) {
                    return Ok(left_out);
                }
                // Preparing a seat over a stopped store fails, which would abort
                // every seat's confirm.
                match filter {
                    [2] | [3] => Err(quil_types::error::QuilError::Store(
                        "store refuses writes".into(),
                    )),
                    _ => Ok(super::Prepared::Roots(vec![roots_of(filter)])),
                }
            },
            |_| None,
        )
        .expect("one worker's stopped store does not abort the other seats' confirm");
        assert_eq!(
            (prepared.filters.clone(), left_out_filters(&prepared)),
            (vec![vec![1]], vec![vec![2], vec![3]])
        );
        assert_eq!(
            prepared.left_out[0].cause,
            super::LeftOutCause::StoreStopped
        );
        prepared.settle_left_out(&mut attempt, FRAME);
        assert!(
            attempts.begin(&[vec![2]], FRAME, OpKind::Confirm).is_some(),
            "retried on the next cycle"
        );

        // A store that stops during the encode: its seat is left out; an
        // error of a seat whose store still writes aborts as before.
        let failed = || quil_types::error::QuilError::Store("store refuses writes".into());
        assert!(matches!(
            super::stopped_mid_encode(&workers, &[3], failed()),
            Ok(super::Prepared::Unanswered(
                super::LeftOutCause::StoreStopped,
                _
            ))
        ));
        assert!(super::stopped_mid_encode(&workers, &[1], failed()).is_err());
    }

    #[test]
    fn a_confirm_whose_workers_all_fail_is_not_submitted() {
        use std::sync::Arc;
        let attempts = Arc::new(crate::submission_attempts::SubmissionAttempts::default());
        let filters = vec![vec![1], vec![2]];
        let attempt = attempts.begin(&filters, FRAME, OpKind::Confirm).unwrap();
        let result = super::prepare_confirm(
            &filters,
            &[],
            2,
            |_, _| {
                Ok(super::Prepared::Unanswered(
                    super::LeftOutCause::Failed,
                    unanswered(),
                ))
            },
            |_| None,
        );
        let error = result.err().expect("nothing to submit");
        assert_eq!(
            error.to_string(),
            unanswered().to_string(),
            "fails as before, with the first worker error"
        );
        drop(attempt);
        assert!(
            attempts.begin(&filters, FRAME, OpKind::Confirm).is_some(),
            "every seat is retried on the next cycle"
        );
    }

    #[test]
    fn a_worker_that_does_not_answer_does_not_hold_up_the_others() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{mpsc, Mutex};
        let (answered, answer_seen) = mpsc::channel::<()>();
        let (answered, answer_seen) = (Mutex::new(answered), Mutex::new(answer_seen));
        let overlapped = AtomicBool::new(false);
        // The silent worker's seat comes first, as it may in plan order.
        let requests = vec![(vec![2], Vec::new()), (vec![1], Vec::new())];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let mut answers =
            super::query_remote_workers(&requests, 8, deadline, |filter, _, _| match filter {
                // Stands in for a worker that times out: it gives up once the
                // other has answered, or after five seconds if asked after it.
                [2] => {
                    let seen = answer_seen
                        .lock()
                        .unwrap()
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .is_ok();
                    overlapped.store(seen, Ordering::SeqCst);
                    Err(unanswered())
                }
                _ => {
                    let _ = answered.lock().unwrap().send(());
                    Ok(Some(vec![roots_of(filter)]))
                }
            });
        assert!(
            overlapped.load(Ordering::SeqCst),
            "the answering worker is asked while the other is waited for"
        );
        let prepared = super::prepare_confirm(
            &[vec![2], vec![1]],
            &[],
            2,
            |filter, targets| {
                Ok(answers
                    .remove(filter)
                    .and_then(|answer| super::remote_answer(filter, targets, answer))
                    .expect("every seat was asked"))
            },
            |_| None,
        )
        .expect("the answering worker's seat is confirmed");
        assert_eq!(prepared.filters, vec![vec![1]]);
        assert_eq!(prepared.roots, vec![roots_of(&[1])]);
        assert_eq!(left_out_filters(&prepared), vec![vec![2]]);
    }

    /// A round ends at its deadline: a worker that has not answered by then
    /// is late, the seats after it are not asked, and both are left out
    /// rather than encoded by the master. The next round asks the late seat
    /// after the others, so the seats behind it answer.
    #[test]
    fn a_round_ends_at_its_deadline_and_asks_late_seats_last_next() {
        use super::LeftOutCause;
        let late = super::LateSeats::default();
        let asked = std::sync::Mutex::new(Vec::new());
        // [2] stands in for a worker that never answers: it holds its call
        // for the whole time it is given.
        let query = |filter: &[u8], _: &[Vec<u8>], timeout: std::time::Duration| {
            asked.lock().unwrap().push(filter.to_vec());
            if filter == [2] {
                std::thread::sleep(timeout);
                return Err(quil_types::error::QuilError::ExecutionUnavailable(
                    "worker storage confirm timed out".into(),
                ));
            }
            Ok(Some(vec![roots_of(filter)]))
        };
        let round = |answers: &std::collections::HashMap<Vec<u8>, super::RemoteAnswer>,
                     filter: u8| {
            match answers
                .get(&vec![filter])
                .expect("every seat has an answer")
            {
                Ok(Some(_)) => None,
                Ok(None) => panic!("no seat runs on the master"),
                Err((cause, _)) => Some(*cause),
            }
        };
        let plan = || {
            vec![
                (vec![2], Vec::new()),
                (vec![1], Vec::new()),
                (vec![3], Vec::new()),
            ]
        };

        let mut requests = plan();
        late.ask_last(&mut requests);
        let started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_millis(300);
        let mut answers = super::query_remote_workers(&requests, 1, deadline, query);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "the round ends by its deadline"
        );
        assert_eq!(*asked.lock().unwrap(), vec![vec![2]]);
        assert_eq!(
            [2, 1, 3].map(|filter| round(&answers, filter)),
            [
                Some(LeftOutCause::Late),
                Some(LeftOutCause::Unasked),
                Some(LeftOutCause::Unasked)
            ]
        );
        late.record(&answers);
        let unasked = answers.remove(&vec![1]).unwrap();
        assert!(
            matches!(
                super::remote_answer(&[1], &[], unasked),
                Some(super::Prepared::Unanswered(LeftOutCause::Unasked, _))
            ),
            "an unasked seat is left out, not encoded by the master"
        );

        let mut requests = plan();
        late.ask_last(&mut requests);
        assert_eq!(
            requests
                .iter()
                .map(|(filter, _)| filter[0])
                .collect::<Vec<_>>(),
            vec![1, 3, 2],
            "the late seat is asked last"
        );
        asked.lock().unwrap().clear();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(300);
        let answers = super::query_remote_workers(&requests, 1, deadline, query);
        assert_eq!(
            [1, 3, 2].map(|filter| round(&answers, filter)),
            [None, None, Some(LeftOutCause::Late)]
        );
        late.record(&answers);

        let mut answered = std::collections::HashMap::new();
        answered.insert(vec![2], Ok(Some(vec![roots_of(&[2])])));
        late.record(&answered);
        let mut requests = plan();
        late.ask_last(&mut requests);
        assert_eq!(
            requests
                .iter()
                .map(|(filter, _)| filter[0])
                .collect::<Vec<_>>(),
            vec![2, 1, 3],
            "a seat that answers is late no more"
        );
    }

    /// A worker's answer must hold one group for its shard and one for each
    /// shard it was asked to pre-register: one that omits or repeats a group
    /// leaves its seat out, and with it the seat that shares its merge target.
    #[test]
    fn a_worker_answer_missing_or_repeating_a_requested_shard_leaves_its_seat_out() {
        let changes = vec![change(ShardChangeKind::Merge, 2, &[20, 21])];
        let filters = [vec![20], vec![21], vec![5]];
        let plan = confirm_encoding_plan(&filters, &changes, 8);
        assert_eq!(
            plan[0],
            (vec![20], vec![vec![2]]),
            "20 encodes the merge target"
        );
        for (groups, submitted, left_out) in [
            (
                vec![vec![20], vec![2]],
                vec![vec![20], vec![21], vec![5]],
                Vec::new(),
            ),
            (vec![vec![20]], vec![vec![5]], vec![vec![20], vec![21]]),
            (
                vec![vec![20], vec![2], vec![2]],
                vec![vec![5]],
                vec![vec![20], vec![21]],
            ),
            (
                vec![vec![20], vec![20], vec![2]],
                vec![vec![5]],
                vec![vec![20], vec![21]],
            ),
        ] {
            let mut answers: std::collections::HashMap<Vec<u8>, super::RemoteAnswer> = plan
                .iter()
                .map(|(filter, targets)| {
                    let answered: Vec<Vec<u8>> = if filter == &vec![20] {
                        groups.clone()
                    } else {
                        std::iter::once(filter).chain(targets).cloned().collect()
                    };
                    (
                        filter.clone(),
                        Ok(Some(answered.iter().map(|group| roots_of(group)).collect())),
                    )
                })
                .collect();
            let prepared = super::prepare_confirm(
                &filters,
                &changes,
                8,
                |filter, targets| {
                    Ok(answers
                        .remove(filter)
                        .and_then(|answer| super::remote_answer(filter, targets, answer))
                        .expect("every seat was asked"))
                },
                |_| None,
            )
            .unwrap();
            assert_eq!(
                prepared.filters, submitted,
                "worker of 20 answered {groups:?}"
            );
            assert_eq!(
                left_out_filters(&prepared),
                left_out,
                "worker of 20 answered {groups:?}"
            );
            if !left_out.is_empty() {
                assert_eq!(
                    super::left_out_causes(&prepared.left_out),
                    "incomplete 1, merge target 1"
                );
            }
        }
    }

    #[test]
    fn a_seat_sharing_a_merge_target_with_a_left_out_seat_is_left_out_too() {
        let changes = vec![change(ShardChangeKind::Merge, 2, &[20, 21])];
        let prepared = super::prepare_confirm(
            &[vec![20], vec![21], vec![5]],
            &changes,
            8,
            |filter, targets| {
                Ok(match filter {
                    [20] => super::Prepared::Unanswered(super::LeftOutCause::Failed, unanswered()),
                    _ => super::Prepared::Roots(
                        std::iter::once(filter)
                            .chain(targets.iter().map(Vec::as_slice))
                            .map(roots_of)
                            .collect(),
                    ),
                })
            },
            |_| None,
        )
        .unwrap();
        assert_eq!(
            prepared.filters,
            vec![vec![5]],
            "21 would confirm without registering the merge target 20 claimed"
        );
        assert_eq!(prepared.roots, vec![roots_of(&[5])]);
        assert_eq!(left_out_filters(&prepared), vec![vec![20], vec![21]]);
    }

    #[test]
    fn a_local_preparation_error_still_aborts_the_confirm() {
        let result = super::prepare_confirm(
            &[vec![1], vec![2]],
            &[],
            2,
            |filter, _| match filter {
                [1] => Err(quil_types::error::QuilError::Internal("store".into())),
                _ => Ok(super::Prepared::Roots(vec![roots_of(filter)])),
            },
            |_| None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn a_confirm_encodes_the_shards_a_change_creates_from_each_filter_once() {
        let changes = vec![
            change(ShardChangeKind::Split, 1, &[10, 11]),
            change(ShardChangeKind::Merge, 2, &[20, 21]),
        ];
        assert_eq!(
            confirm_encoding_plan(&[vec![1], vec![20], vec![21], vec![]], &changes, 8),
            vec![
                (vec![1], vec![vec![10], vec![11]]),
                (vec![20], vec![vec![2]]),
                (vec![21], vec![]),
                (vec![], vec![]),
            ],
            "each split child from the parent's storage; a shared merge target once",
        );
        assert_eq!(
            confirm_encoding_plan(&[vec![1]], &changes, 9),
            vec![(vec![1], vec![])],
            "only a change applying next epoch"
        );
    }

    /// A filter `n` distinct over a few hundred seats.
    fn seat(n: usize) -> Vec<u8> {
        let mut filter = vec![0xC0; 32];
        filter[..2].copy_from_slice(&(n as u16).to_be_bytes());
        filter
    }

    /// A shard change applying at epoch 8, between any filters.
    fn change_of(
        kind: ShardChangeKind,
        parent: Vec<u8>,
        children: Vec<Vec<u8>>,
    ) -> PendingShardChange {
        PendingShardChange {
            kind,
            parent,
            children,
            effective_epoch: 8,
            proposed_frame: 0,
        }
    }

    /// Prepare a confirm at epoch 8 as the master does: each seat registers
    /// its shard and those `changes` create from it; a seat `bare` admits
    /// registers none, as a leave confirm does.
    fn prepared_with(
        filters: &[Vec<u8>],
        changes: &[PendingShardChange],
        bare: impl Fn(&[u8]) -> bool,
    ) -> super::PreparedConfirm {
        super::prepare_confirm(
            filters,
            changes,
            8,
            |filter, targets| {
                Ok(super::Prepared::Roots(if bare(filter) {
                    Vec::new()
                } else {
                    std::iter::once(filter)
                        .chain(targets.iter().map(Vec::as_slice))
                        .map(roots_of)
                        .collect()
                }))
            },
            |_| None,
        )
        .unwrap()
    }

    /// Split a prepared confirm and check every message is one each node
    /// decodes, that GLOBAL honours each of its groups (for a shard the
    /// message names, or one a change creates from those shards), and that
    /// together they confirm every seat once, in order.
    fn split_and_decode(
        prepared: super::PreparedConfirm,
        changes: &[PendingShardChange],
    ) -> Vec<(Vec<Vec<u8>>, super::LeafRoots)> {
        use quil_execution::global_intrinsic::{
            addressed_signature::AddressedSignature,
            leaf_root_registration::{pre_registration_targets, MAX_CONFIRM_LEAF_ROOT_GROUPS},
            prover_ops::{ProverConfirm, MAX_FILTERS_PER_OP},
        };
        let (filters, roots) = (prepared.filters.clone(), prepared.roots.clone());
        let messages =
            super::confirm_messages(prepared.filters, prepared.roots, &prepared.seat_groups);
        for (message_filters, message_roots) in &messages {
            assert!(
                message_filters.len() <= MAX_FILTERS_PER_OP,
                "{} filters",
                message_filters.len()
            );
            assert!(
                message_roots.len() <= MAX_CONFIRM_LEAF_ROOT_GROUPS,
                "{} groups",
                message_roots.len()
            );
            let created = pre_registration_targets(changes, message_filters, 8);
            for group in message_roots {
                assert!(
                    message_filters.contains(&group.filter) || created.contains(&group.filter),
                    "GLOBAL honours the group of {} in the message that carries it",
                    hex::encode(&group.filter)
                );
            }
            let confirm = ProverConfirm {
                frame_number: 721,
                public_key_signature_bls48581: Some(AddressedSignature {
                    signature: vec![1; 666],
                    address: vec![2; 32],
                }),
                filters: message_filters.clone(),
                leaf_roots: message_roots.clone(),
                ..Default::default()
            };
            let decoded =
                ProverConfirm::from_canonical_bytes(&confirm.to_canonical_bytes().unwrap())
                    .expect("every message decodes");
            assert_eq!(
                (&decoded.filters, &decoded.leaf_roots),
                (message_filters, message_roots)
            );
        }
        assert_eq!(
            messages
                .iter()
                .flat_map(|(f, _)| f.clone())
                .collect::<Vec<_>>(),
            filters
        );
        assert_eq!(
            messages
                .iter()
                .flat_map(|(_, r)| r.clone())
                .collect::<Vec<_>>(),
            roots
        );
        messages
    }

    fn sizes(messages: &[(Vec<Vec<u8>>, super::LeafRoots)]) -> Vec<usize> {
        messages.iter().map(|(filters, _)| filters.len()).collect()
    }

    /// A renewal of more seats than one confirm decodes (a prover with 105
    /// seats renewed 103 at once, and every node refused it) is split into
    /// messages each node decodes.
    #[test]
    fn a_long_confirm_is_split_into_messages_every_node_decodes() {
        for (seats, expected) in [
            (103, vec![100, 3]),
            (250, vec![100, 100, 50]),
            (100, vec![100]),
            (1, vec![1]),
        ] {
            let filters: Vec<Vec<u8>> = (0..seats).map(seat).collect();
            let messages = split_and_decode(prepared_with(&filters, &[], |_| false), &[]);
            assert_eq!(sizes(&messages), expected, "{seats} seats");
        }
    }

    /// Seats that pre-register the shards their split creates register
    /// several groups each: a message also stays within the group limit, and
    /// each seat's children stay in its message.
    #[test]
    fn a_confirm_split_keeps_each_seat_with_the_shards_its_split_creates() {
        let split = |filter: &Vec<u8>| {
            let children = (0..8u8)
                .map(|c| [filter.as_slice(), &[c]].concat())
                .collect();
            change_of(ShardChangeKind::Split, filter.clone(), children)
        };
        // 100 seats of 9 groups: 900 groups, over the limit of 256.
        let filters: Vec<Vec<u8>> = (0..100).map(seat).collect();
        let changes: Vec<PendingShardChange> = filters.iter().map(split).collect();
        let messages = split_and_decode(prepared_with(&filters, &changes, |_| false), &changes);
        assert_eq!(sizes(&messages), vec![28, 28, 28, 16]);
        // Mixed: every tenth seat splits; a seat without storage (a leave
        // confirm) registers none.
        let filters: Vec<Vec<u8>> = (0..250).map(seat).collect();
        let changes: Vec<PendingShardChange> = filters.iter().step_by(10).map(split).collect();
        let bare = |filter: &[u8]| {
            let n = u16::from_be_bytes([filter[0], filter[1]]);
            n % 7 == 0 && n % 10 != 0
        };
        split_and_decode(prepared_with(&filters, &changes, bare), &changes);
    }

    /// A merge target two confirmed seats share is registered once, by the
    /// first source; its filter is no prefix of either. The split keeps it in
    /// the message naming that source, where GLOBAL honours it.
    #[test]
    fn a_confirm_split_keeps_a_merge_target_with_the_source_that_registers_it() {
        let target = |k: usize| {
            let mut filter = vec![0xD0; 32];
            filter[..2].copy_from_slice(&(k as u16).to_be_bytes());
            filter
        };
        // 240 seats; each pair merges into its own target.
        let filters: Vec<Vec<u8>> = (0..240).map(seat).collect();
        let changes: Vec<PendingShardChange> = (0..120)
            .map(|k| {
                change_of(
                    ShardChangeKind::Merge,
                    target(k),
                    vec![filters[2 * k].clone(), filters[2 * k + 1].clone()],
                )
            })
            .collect();
        let prepared = prepared_with(&filters, &changes, |_| false);
        assert_eq!(prepared.roots.len(), 360, "each target once");
        let messages = split_and_decode(prepared, &changes);
        assert_eq!(sizes(&messages), vec![100, 100, 40]);
        let first_targets: Vec<Vec<u8>> = messages[1]
            .1
            .iter()
            .map(|group| group.filter.clone())
            .filter(|f| f[2] == 0xD0)
            .collect();
        assert_eq!(
            first_targets,
            (50..100).map(target).collect::<Vec<_>>(),
            "with their sources' message"
        );
    }

    /// Preparation records how many groups each submitted seat registers,
    /// which keeps the groups aligned when a confirm is split.
    #[test]
    fn a_prepared_confirm_counts_each_seats_groups() {
        let changes = vec![change(ShardChangeKind::Split, 1, &[10, 11])];
        let prepared = super::prepare_confirm(
            &[vec![1], vec![2], vec![3]],
            &changes,
            8,
            |filter, targets| {
                if filter == &[3u8][..] {
                    return Ok(super::Prepared::Unanswered(
                        super::LeftOutCause::Failed,
                        unanswered(),
                    ));
                }
                Ok(super::Prepared::Roots(
                    std::iter::once(filter)
                        .chain(targets.iter().map(Vec::as_slice))
                        .map(roots_of)
                        .collect(),
                ))
            },
            |_| None,
        )
        .unwrap();
        assert_eq!(prepared.filters, vec![vec![1], vec![2]]);
        assert_eq!(
            prepared.seat_groups,
            vec![3, 1],
            "the split parent registers its two children too"
        );
        assert_eq!(prepared.roots.len(), 4);
    }

    /// A seat whose leaf roots exceed what every node decodes is left out
    /// with its own cause, so the seats that would share its message still go
    /// out, and fenced until the epoch ends rather than released, so it is
    /// not prepared again within the epoch; a seat its worker did not prepare
    /// is retried at once.
    #[test]
    fn a_seat_over_a_decode_limit_is_left_out_and_fenced() {
        use quil_execution::global_intrinsic::leaf_root_registration::{
            ConfirmLeafRoots, LeafRootEntry,
        };
        use std::sync::Arc;
        let too_many_entries = ConfirmLeafRoots {
            filter: seat(5),
            entries: vec![LeafRootEntry::default(); 257],
        };
        let prepare =
            |filter: &[u8], _: &[Vec<u8>]| -> quil_types::error::Result<super::Prepared> {
                Ok(match u16::from_be_bytes([filter[0], filter[1]]) {
                    5 => super::Prepared::Roots(vec![too_many_entries.clone()]),
                    7 => super::Prepared::Roots(vec![roots_of(filter); 257]),
                    9 => super::Prepared::Unanswered(super::LeftOutCause::Failed, unanswered()),
                    _ => super::Prepared::Roots(vec![roots_of(filter)]),
                })
            };
        let filters: Vec<Vec<u8>> = (0..103).map(seat).collect();
        let attempts = Arc::new(crate::submission_attempts::SubmissionAttempts::default());
        let mut attempt = attempts.begin(&filters, FRAME, OpKind::Confirm).unwrap();
        let prepared = super::prepare_confirm(&filters, &[], 8, prepare, |_| None).unwrap();
        assert_eq!(left_out_filters(&prepared), vec![seat(5), seat(7), seat(9)]);
        assert_eq!(
            super::left_out_causes(&prepared.left_out),
            "failed 1, over decode limit 2"
        );
        let errors = super::left_out_errors(&prepared.left_out);
        assert!(
            errors.contains("257 entries (at most 256)") && errors.contains("257 leaf-root groups"),
            "{errors}"
        );
        prepared.settle_left_out(&mut attempt, FRAME);
        assert!(
            attempts
                .begin(&[seat(9)], FRAME + 1, OpKind::Confirm)
                .is_some(),
            "a worker failure is retried on the next cycle"
        );
        let messages = split_and_decode(prepared, &[]);
        assert_eq!(sizes(&messages), vec![100], "the others fill one message");
        drop(attempt); // Nothing was published.
        assert!(
            !attempts.owned(&seat(0), FRAME + 1, OpKind::Confirm),
            "an unpublished seat is retried on the next cycle"
        );
        let next_epoch = FRAME + quil_types::consensus::epoch_length_frames();
        for over in [seat(5), seat(7)] {
            assert!(
                attempts.owned(&over, FRAME + 30, OpKind::Confirm),
                "not prepared again after the retry fence"
            );
            assert!(
                attempts.owned(&over, next_epoch - 1, OpKind::Confirm),
                "nor until the epoch ends"
            );
            assert!(
                !attempts.owned(&over, next_epoch, OpKind::Confirm),
                "retried in the next epoch"
            );
            assert!(
                !attempts.owned(&over, FRAME + 30, OpKind::Leave),
                "the fence does not hold off a leave"
            );
        }
        let left = attempts.begin(&[seat(5)], FRAME + 30, OpKind::Leave);
        assert!(
            left.is_some(),
            "a seat over the decode limits can still be left"
        );
        drop(left);
        for over in [seat(5), seat(7)] {
            assert!(
                attempts.owned(&over, FRAME + 31, OpKind::Confirm),
                "an unpublished leave leaves the renewal fenced"
            );
        }
        // With every seat over a limit the confirm is settled, not failed.
        let prepared = super::prepare_confirm(&[seat(5)], &[], 8, prepare, |_| None)
            .expect("settled, not failed");
        assert!(prepared.filters.is_empty());
        assert!(
            super::confirm_messages(prepared.filters, prepared.roots, &prepared.seat_groups)
                .is_empty()
        );
    }

    /// Committed GLOBAL state holding this prover's allocation of each
    /// filter: joined at frame 10, confirmed in epoch 1 (so registered for
    /// epoch 2), and left at the given frame.
    fn global_with_allocations(
        seats: &[(Vec<u8>, Option<u64>)],
    ) -> std::sync::Arc<quil_hypergraph::HypergraphCrdt> {
        use quil_execution::global_intrinsic::materialize;
        use quil_execution::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
        use std::sync::Arc;
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
            Arc::new(quil_hypergraph::testing::StubProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        let state = HypergraphState::new(crdt.clone());
        let va_disc = vertex_adds_discriminator().unwrap();
        for (filter, left) in seats {
            let (address, mut tree) =
                materialize::materialize_prover_join(BLS_KEY, std::slice::from_ref(filter), 10, 0)
                    .unwrap()
                    .allocations
                    .remove(0);
            materialize::materialize_prover_confirm(&mut tree, 730, None).unwrap();
            if let Some(frame) = left {
                materialize::materialize_prover_leave(&mut tree, *frame).unwrap();
            }
            let blob = quil_execution::prover_registry::vertex_tree_to_blob(&tree);
            state
                .set(
                    &quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS[..],
                    &address,
                    &va_disc,
                    1,
                    blob,
                )
                .unwrap();
        }
        state.commit().unwrap();
        state.abort();
        crdt.commit_with_global_cursor(1, &quil_store::encoding::global_materialized_cursor_key())
            .unwrap();
        crdt
    }

    /// A seat whose leave landed while its renewal was prepared is left out
    /// of the confirm and the others still go out: every node refuses a
    /// confirm naming a seat Leaving since this epoch, and with it every seat
    /// of the message (2026-10-22). It is fenced, not prepared again at once,
    /// and with every seat refused nothing is submitted.
    #[test]
    fn a_seat_turned_leaving_while_prepared_is_left_out_of_its_confirm() {
        const RENEWAL: u64 = 1460; // Epoch 2: renews the seats for epoch 3.
        let (kept, left) = (seat(1), seat(2));
        let global = global_with_allocations(&[(kept.clone(), None), (left.clone(), Some(1450))]);
        let refused = |filter: &[u8]| super::confirm_refusal(&global, BLS_KEY, filter, RENEWAL);
        assert!(
            refused(&kept).is_none(),
            "a seat registered for this epoch renews"
        );
        assert!(
            refused(&seat(3)).is_none(),
            "an absent allocation is left to GLOBAL"
        );
        let prepare =
            |filter: &[u8], _: &[Vec<u8>]| -> quil_types::error::Result<super::Prepared> {
                Ok(super::Prepared::Roots(vec![roots_of(filter)]))
            };
        let attempts =
            std::sync::Arc::new(crate::submission_attempts::SubmissionAttempts::default());
        let filters = vec![kept.clone(), left.clone()];
        let mut attempt = attempts.begin(&filters, RENEWAL, OpKind::Confirm).unwrap();
        let prepared = super::prepare_confirm(&filters, &[], 3, prepare, refused).unwrap();
        assert_eq!(
            prepared.filters,
            vec![kept.clone()],
            "the Leaving seat is left out"
        );
        assert_eq!(super::left_out_causes(&prepared.left_out), "refused 1");
        prepared.settle_left_out(&mut attempt, RENEWAL);
        let messages =
            super::confirm_messages(prepared.filters, prepared.roots, &prepared.seat_groups);
        assert_eq!(
            messages,
            vec![(vec![kept.clone()], vec![roots_of(&kept)])],
            "the other seat still goes out"
        );
        drop(attempt);
        assert!(
            attempts.owned(&left, RENEWAL + 29, OpKind::Confirm),
            "fenced, not prepared again at once"
        );
        assert!(!attempts.owned(&left, RENEWAL + 30, OpKind::Confirm));
        let prepared = super::prepare_confirm(&[left.clone()], &[], 3, prepare, refused)
            .expect("settled, not failed");
        assert!(
            super::confirm_messages(prepared.filters, prepared.roots, &prepared.seat_groups)
                .is_empty()
        );
    }

    /// The guard every publication passes: an op over a decode limit (here a
    /// leaf-root group of 257 entries) is not bundled for the transport, and
    /// its error marks it refused, so its sender fences its filters.
    #[test]
    fn a_bundle_of_an_op_no_node_decodes_is_refused() {
        use quil_execution::global_intrinsic::leaf_root_registration::{
            ConfirmLeafRoots, LeafRootEntry,
        };
        use quil_execution::global_intrinsic::{ProverConfirm, ProverLeave};
        let confirm = |entries: usize| {
            ProverConfirm {
                frame_number: FRAME,
                filters: vec![seat(1)],
                leaf_roots: vec![ConfirmLeafRoots {
                    filter: seat(1),
                    entries: vec![LeafRootEntry::default(); entries],
                }],
                ..Default::default()
            }
            .to_canonical_bytes()
            .unwrap()
        };
        assert!(super::prover_bundle(confirm(256), FRAME).is_ok());
        let refused = super::prover_bundle(confirm(257), FRAME).unwrap_err();
        assert!(super::is_undecodable(&refused), "{refused}");
        let leave = ProverLeave {
            filters: vec![vec![1; 65]],
            ..Default::default()
        }
        .to_canonical_bytes()
        .unwrap();
        assert!(super::is_undecodable(
            &super::prover_bundle(leave, FRAME).unwrap_err()
        ));
        assert!(!super::is_undecodable(
            &quil_types::error::QuilError::Internal("no archive accepted".into())
        ));
    }

    /// The guard refuses an op over the decoders' limits and lets one at
    /// the limits through; joins, leaves and rejects split by the same limit.
    #[test]
    fn an_op_no_node_decodes_is_not_published() {
        use quil_execution::global_intrinsic::{prover_ops::MAX_FILTERS_PER_OP, ProverLeave};
        let leave = |filters: Vec<Vec<u8>>| {
            ProverLeave {
                filters,
                ..Default::default()
            }
            .to_canonical_bytes()
            .unwrap()
        };
        assert!(super::refuse_undecodable(
            &leave((0..MAX_FILTERS_PER_OP).map(seat).collect()),
            FRAME
        )
        .is_ok());
        assert!(super::refuse_undecodable(
            &leave((0..=MAX_FILTERS_PER_OP).map(seat).collect()),
            FRAME
        )
        .is_err());
        assert!(
            super::refuse_undecodable(&leave(vec![vec![1; 65]]), FRAME).is_err(),
            "a filter over 64 bytes"
        );
        let confirm = quil_execution::global_intrinsic::ProverConfirm {
            filters: (0..103).map(seat).collect(),
            ..Default::default()
        };
        assert!(super::refuse_undecodable(&confirm.to_canonical_bytes().unwrap(), FRAME).is_err());
        let filters: Vec<Vec<u8>> = (0..250).map(seat).collect();
        assert_eq!(
            super::filter_chunks(&filters)
                .iter()
                .map(Vec::len)
                .collect::<Vec<_>>(),
            vec![100, 100, 50],
            "a leave or reject is split the same way"
        );
        let workers: Vec<u32> = (0..250).collect();
        let joins = super::join_chunks(&filters, &workers);
        assert_eq!(
            joins.iter().map(|(_, ids)| ids.clone()).collect::<Vec<_>>(),
            vec![
                (0..100).collect::<Vec<u32>>(),
                (100..200).collect(),
                (200..250).collect()
            ],
            "each join marks only its own workers pending"
        );
        assert_eq!(
            joins.iter().map(|(f, _)| f.clone()).collect::<Vec<_>>(),
            super::filter_chunks(&filters)
        );
        assert!(
            super::join_chunks(&filters, &[])
                .iter()
                .all(|(_, ids)| ids.is_empty()),
            "an admin join names none"
        );
    }

    /// The refusal warning says when each kind is built again: only the ops
    /// that name filters have a retry fence.
    #[test]
    fn a_refusal_names_when_each_kind_is_built_again() {
        for op in ["join", "confirm", "leave", "reject"] {
            assert_eq!(
                super::refusal_retry(op),
                "its filters are retried after the retry fence",
                "{op}"
            );
        }
        assert_eq!(
            super::refusal_retry("seniority_merge"),
            "proposed again after the seniority merge cooldown"
        );
        for op in ["shard_split", "shard_merge"] {
            assert_eq!(
                super::refusal_retry(op),
                "proposed again when the shard is next eligible",
                "{op}"
            );
        }
    }

    /// An anomaly that recurs every cycle is reported once per epoch per key.
    #[test]
    fn an_epoch_report_is_due_once_per_epoch() {
        let reports = super::EpochReports::<&'static str>::default();
        assert!(reports.due(&"confirm", 5));
        assert!(!reports.due(&"confirm", 5));
        assert!(reports.due(&"leave", 5), "per key");
        assert!(reports.due(&"confirm", 6));
    }

    const FRAME: u64 = 720;
    const BLS_KEY: &[u8] = b"prover key";
    const OWN: [u8; 32] = [7; 32];
    const OTHER: [u8; 32] = [8; 32];
    const SEEDS: [[u8; 57]; 2] = [[1; 57], [2; 57]];

    fn pubkey(seed: &[u8; 57]) -> Vec<u8> {
        quil_p2p::ed448_identity::derive_public_key(seed)
    }

    /// Stands in for the prover's BLS signer; Ed448 signs deterministically.
    fn prover_signer() -> quil_crypto::Ed448Signer {
        quil_crypto::Ed448Signer::from_bytes(&[9; 57], &pubkey(&[9; 57])).unwrap()
    }

    /// Committed GLOBAL state holding a spent marker at each address, as the
    /// merge that consumed the target stamps it for the prover it credits.
    fn global_with_markers(
        markers: &[([u8; 32], [u8; 32])],
    ) -> std::sync::Arc<quil_hypergraph::HypergraphCrdt> {
        use quil_execution::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
        use std::sync::Arc;
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
            Arc::new(quil_hypergraph::testing::StubProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(
            db.inner(),
            quil_store::FOREST_NAMESPACE,
        ));
        let state = HypergraphState::new(crdt.clone());
        let va_disc = vertex_adds_discriminator().unwrap();
        for (address, credited) in markers {
            let marker =
                quil_execution::global_intrinsic::materialize::create_spent_merge_tree(credited)
                    .unwrap();
            let blob = quil_execution::prover_registry::vertex_tree_to_blob(&marker);
            state
                .set(
                    &quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS[..],
                    address,
                    &va_disc,
                    1,
                    blob,
                )
                .unwrap();
        }
        state.commit().unwrap();
        state.abort();
        crdt.commit_with_global_cursor(1, &quil_store::encoding::global_materialized_cursor_key())
            .unwrap();
        crdt
    }

    fn merge_with(
        global: &std::sync::Arc<quil_hypergraph::HypergraphCrdt>,
        seeds: &[[u8; 57]],
    ) -> (
        Option<super::ProverSeniorityMerge>,
        Vec<super::ConsumedMergeTarget>,
    ) {
        super::seniority_merge(FRAME, seeds, BLS_KEY, &OWN, &prover_signer(), |address| {
            super::global_vertex(global, address)
        })
        .unwrap()
    }

    /// The merge of `seeds` as built before consumed targets were left out.
    fn merge_of(seeds: &[[u8; 57]]) -> super::ProverSeniorityMerge {
        use quil_types::crypto::Signer;
        let merge_targets: Vec<quil_execution::global_intrinsic::SeniorityMerge> = seeds
            .iter()
            .map(|seed| quil_execution::global_intrinsic::SeniorityMerge {
                signature: quil_crypto::Ed448Signer::from_bytes(seed, &pubkey(seed))
                    .unwrap()
                    .sign_with_domain(BLS_KEY, b"PROVER_SENIORITY_MERGE")
                    .unwrap(),
                key_type: quil_types::crypto::KeyType::Ed448 as u32,
                prover_public_key: pubkey(seed),
            })
            .collect();
        let mut message = FRAME.to_be_bytes().to_vec();
        for target in &merge_targets {
            message.extend_from_slice(&target.prover_public_key);
        }
        let domain = super::ProverPipeline::domain(b"PROVER_SENIORITY_MERGE").unwrap();
        super::ProverSeniorityMerge {
            frame_number: FRAME,
            public_key_signature_bls48581: Some(super::AddressedSignature {
                signature: prover_signer().sign_with_domain(&message, &domain).unwrap(),
                address: OWN.to_vec(),
            }),
            merge_targets,
        }
    }

    fn consumed_by(
        seed: &[u8; 57],
        marker: &'static str,
        credited: [u8; 32],
    ) -> super::ConsumedMergeTarget {
        super::ConsumedMergeTarget {
            pubkey: pubkey(seed),
            marker,
            credited: Some(credited.to_vec()),
        }
    }

    #[test]
    fn a_merge_of_unconsumed_targets_is_unchanged() {
        let (merge, consumed) = merge_with(&global_with_markers(&[]), &SEEDS);
        assert_eq!(merge, Some(merge_of(&SEEDS)));
        assert!(consumed.is_empty());
    }

    #[test]
    fn a_target_another_prover_consumed_is_not_merged_and_names_that_prover() {
        let spent = quil_execution::global_intrinsic::materialize::spent_join_merge_address(
            &pubkey(&SEEDS[0]),
        )
        .unwrap();
        let (merge, consumed) = merge_with(&global_with_markers(&[(spent, OTHER)]), &SEEDS[..1]);
        assert_eq!(
            merge, None,
            "GLOBAL refuses a merge naming a consumed target"
        );
        assert_eq!(consumed, vec![consumed_by(&SEEDS[0], "join merge", OTHER)]);
        let (credited_to, action) = super::consumed_target_credit(&consumed[0], &OWN, false);
        assert_eq!(credited_to, "prover …080808");
        assert!(
            action.is_some_and(|action| action.contains("restore that prover's key")),
            "{action:?}"
        );
        // Held by a prover with no live allocation: the operator can check a
        // seniority succession.
        let (_, action) = super::consumed_target_credit(&consumed[0], &OWN, true);
        assert!(
            action.is_some_and(|action| action.contains("qclient node prover merge --dry-run")),
            "{action:?}"
        );
    }

    #[test]
    fn a_target_this_prover_consumed_is_not_merged_again() {
        let spent = quil_execution::global_intrinsic::materialize::spent_seniority_merge_address(
            &pubkey(&SEEDS[0]),
        )
        .unwrap();
        let (merge, consumed) = merge_with(&global_with_markers(&[(spent, OWN)]), &SEEDS[..1]);
        assert_eq!(merge, None);
        assert_eq!(
            consumed,
            vec![consumed_by(&SEEDS[0], "seniority merge", OWN)]
        );
        let (credited_to, action) = super::consumed_target_credit(&consumed[0], &OWN, true);
        assert_eq!(credited_to, "this prover");
        assert_eq!(action, None, "nothing for the operator to do");
    }

    #[test]
    fn a_merge_keeps_only_the_unconsumed_targets() {
        let spent = quil_execution::global_intrinsic::materialize::spent_seniority_merge_address(
            &pubkey(&SEEDS[0]),
        )
        .unwrap();
        let (merge, consumed) = merge_with(&global_with_markers(&[(spent, OTHER)]), &SEEDS);
        assert_eq!(
            merge,
            Some(merge_of(&SEEDS[1..])),
            "the prover signs the remaining target alone"
        );
        assert_eq!(
            consumed,
            vec![consumed_by(&SEEDS[0], "seniority merge", OTHER)]
        );
    }

    #[test]
    fn a_succession_consents_to_moving_the_named_provers_seniority() {
        use quil_types::crypto::Signer;
        let succession = super::seniority_succession(
            FRAME,
            &SEEDS[..1],
            BLS_KEY,
            &OWN,
            &prover_signer(),
            &OTHER,
        )
        .unwrap();
        let consent =
            quil_execution::global_intrinsic::seniority_succession::succession_consent_message(
                BLS_KEY, &OTHER, FRAME,
            );
        let consented = quil_crypto::Ed448Signer::from_bytes(&SEEDS[0], &pubkey(&SEEDS[0]))
            .unwrap()
            .sign_with_domain(&consent, b"PROVER_SENIORITY_SUCCESSION")
            .unwrap();
        assert_eq!(succession.merge_targets[0].signature, consented);
        assert_eq!(
            succession.merge_targets[0].prover_public_key,
            pubkey(&SEEDS[0])
        );
        let merge = merge_of(&SEEDS[..1]);
        assert_ne!(
            succession.merge_targets[0].signature, merge.merge_targets[0].signature,
            "not a merge consent"
        );
        assert_eq!(
            succession.public_key_signature_bls48581, merge.public_key_signature_bls48581,
            "the prover signs the targets as for a merge"
        );
    }

    #[test]
    fn a_consumed_target_is_reported_once_per_epoch() {
        let reports = super::ConsumedTargetReports::default();
        let target = consumed_by(&SEEDS[0], "join merge", OTHER);
        assert!(reports.due(&target, 5), "reported when found");
        assert!(!reports.due(&target, 5), "not again within the epoch");
        assert!(reports.due(&target, 6), "repeated the next epoch");
        assert!(
            reports.due(&consumed_by(&SEEDS[0], "join merge", OWN), 6),
            "a changed marker is reported at once"
        );
    }
}

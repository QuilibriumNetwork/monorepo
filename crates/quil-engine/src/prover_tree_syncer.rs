//! Trait for syncing the global prover tree from archives.
//!
//! Workers need to sync the prover tree to resolve leader rotation,
//! verify FrameHeaders, and attribute shard work. In Go this is
//! `AppConsensusEngine.performBlockingGlobalHypersync` which calls
//! `HyperSyncSelf` against the master/archive. The Rust port can't
//! call `quil-rpc` from `quil-engine` (circular dep), so the trait
//! lives here and the implementation lives in `quil-node`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use quil_types::error::Result;
use quil_types::proto::global::AppShardFrame;

/// Syncs the global prover tree (vertex-adds set for the global
/// intrinsic address) from an archive. Returns `true` if the
/// locally-recomputed root matches `expected_root` after sync.
///
/// Implementations should:
/// 1. Connect to an archive endpoint (mTLS)
/// 2. Pull the prover tree via `ensure_prover_tree_incremental`
/// with `expected_root` pinned
/// 3. Return whether the final root matches
#[async_trait]
pub trait ProverTreeSyncer: Send + Sync {
    /// Sync the global prover tree, pinning EACH phase to `expected_roots[phase]`
    /// — `[prover_tree_commitment (phase 0), prover_tree_aux_roots (1,2,3)]` from
    /// the global header (all four phases anchored). Empty slice ⇒
    /// trust the peer (bootstrap). Returns `Ok(true)` if post-sync roots match,
    /// `Ok(false)` if the sync completed but roots still diverge, `Err` on failure.
    async fn sync_prover_tree(&self, expected_roots: &[Vec<u8>]) -> Result<bool>;

    /// Sync a specific app-shard's subtrees from an archive, pinning EACH of
    /// the four phases to `expected_roots[phase]` — the finalized header's
    /// `state_roots` (all four phases anchored, not just vertex-adds).
    /// Used to catch a shard's CRDT up after a frame gap / restart / late-join.
    /// `filter` is the shard filter; the impl derives the `ShardKey`.
    /// An empty entry (or empty slice) trusts the peer for that phase
    /// (bootstrap). Default is a no-op (`Ok(false)`) for syncers without shard
    /// sync.
    async fn sync_shard_tree(&self, _filter: &[u8], _expected_roots: &[Vec<u8>]) -> Result<bool> {
        Ok(false)
    }

    /// Fetch an app-shard frame from an archive. `frame_number == 0` requests
    /// the latest frame and is used to seed an empty worker's clock lineage.
    async fn get_app_shard_frame(
        &self,
        _filter: &[u8],
        _frame_number: u64,
    ) -> Result<Option<AppShardFrame>> {
        Ok(None)
    }

    /// The headers of `filter`'s frame `frame_number` that the GLOBAL frames
    /// `globals` carry, read in the order given, each with the number of the
    /// GLOBAL frame carrying it: the certified headers members submitted for
    /// the frame's work, a bounded set of distinct plausible copies
    /// ([`plausible_carried_copy`]), one per copy apart from its attestation
    /// field ([`carried_copy_digest`]), best first ([`rank_carried_copy`]).
    /// `named`: the parent the frame after it names. `verify`, when given,
    /// checks each copy's certificate before it is kept
    /// ([`verify_carried_copy`]); a copy it refuses is dropped. With the
    /// copies certified and those a frame rebuilt from failed to replay
    /// ([`Self::reject_carried_copy`]), which the caller passes over.
    /// Default empty for syncers that read no GLOBAL frames.
    async fn carried_shard_headers(
        &self,
        _filter: &[u8],
        _frame_number: u64,
        _globals: &[u64],
        _named: Option<[u8; 32]>,
        _verify: Option<&CarriedVerifier>,
    ) -> Result<CarriedHeaders> {
        Ok(CarriedHeaders::default())
    }

    /// The answer [`Self::carried_shard_headers`] gives from what it
    /// remembers of an earlier search, without reading GLOBAL frames;
    /// `None` when it would read them. Asked first, so a rebuild answered
    /// from memory never waits on the engine for its check.
    fn cached_carried_shard_headers(
        &self,
        _filter: &[u8],
        _frame_number: u64,
        _named: Option<[u8; 32]>,
    ) -> Option<Result<CarriedHeaders>> {
        None
    }

    /// The frame rebuilt from the copy of `filter`'s frame `frame_number`
    /// header with digest `copy` failed to replay: the next copy is tried.
    fn reject_carried_copy(&self, _filter: &[u8], _frame_number: u64, _copy: CopyId) {}

    /// Every copy [`Self::carried_shard_headers`] found for `filter`'s frame
    /// `frame_number` failed to replay: drop them, so a later search reads
    /// the GLOBAL frames again.
    fn reject_carried_shard_headers(&self, _filter: &[u8], _frame_number: u64) {}
}

/// The copies of a shard frame's header GLOBAL frames carry
/// ([`ProverTreeSyncer::carried_shard_headers`]): the digests
/// ([`carried_copy_digest`]) of those whose check passed
/// ([`verify_carried_copy`]), and of those a frame rebuilt from failed to
/// replay.
/// `refused`: copies the search refused when it checked them;
/// `passed_over`: copies it passed over as refused or rejected before. A
/// search that found nothing while frames of its range went unread or
/// copies unchecked answers with an error instead, a wait.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CarriedHeaders {
    pub copies: Vec<(u64, quil_types::proto::global::FrameHeader)>,
    pub certified: Vec<CopyId>,
    pub rejected: Vec<CopyId>,
    pub refused: usize,
    pub passed_over: usize,
}

/// What checking a carried copy found ([`verify_carried_copy`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyVerdict {
    /// Its certificate and deterministic output verify, and its storage
    /// attestation, when it holds one, in full: possession included.
    Certified,
    /// Its certificate and output verify, its attestation does not: the copy
    /// with that field cleared is the frame's.
    AttestationRefused,
    /// Its certificate and output verify, its attestation cannot be checked
    /// now (registrations unavailable): only the cleared copy is kept.
    AttestationUnavailable,
    /// Its output or structure does not verify: the copy is no frame's.
    Refused,
    /// Its output and structure verify, its certificate does not, here and
    /// now: the committee or session records it needs may be missing from
    /// this node's view, so the copy is passed over only for a while.
    CertificateRefused,
    /// They cannot be checked now (a GLOBAL frame or committee unavailable).
    Unavailable,
}

/// Checks a carried copy as replay would ([`verify_carried_copy`]).
pub type CarriedVerifier = std::sync::Arc<
    dyn Fn(
            quil_types::proto::global::FrameHeader,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = CopyVerdict> + Send>>
        + Send
        + Sync,
>;

/// The frame `header` rebuilds, checked as archive replay checks a
/// certified frame. Its structure and deterministic output first, without
/// its certificate, so a copy whose output does not follow from its header
/// is refused before any historical committee is prepared for it. The
/// output is computed from public inputs, the anchor among them: it pins a
/// named copy (whose output the frame after it names) to the genuine
/// anchor, while an unnamed copy can carry a matching output for any
/// anchor, which the search's per-anchor limit bounds.
/// Then, after the same preparation as replay (the historical committee of
/// a legacy certificate and, for a copy holding an attestation, the
/// storage registrations it names), its certificate
/// ([`crate::frame_validator::BlsAppFrameValidator::validate_certified_without_storage`]),
/// which binds the output, and the attestation, in full. A certificate
/// this node does not reproduce is a wait while a committee that could
/// decide it could not be had (the preparation, not the copy, may be at
/// fault), and else refused only for a while
/// ([`CopyVerdict::CertificateRefused`]).
pub async fn verify_carried_copy(
    validator: std::sync::Arc<crate::frame_validator::BlsAppFrameValidator>,
    header: quil_types::proto::global::FrameHeader,
) -> CopyVerdict {
    let attested = !header.storage_attestation.is_empty();
    let cleared_header = quil_types::proto::global::FrameHeader {
        storage_attestation: Vec::new(),
        ..header.clone()
    };
    let (cleared, _) = crate::app_handoff::frame_from_carried_header(&cleared_header);
    let (full, missing) = crate::app_handoff::frame_from_carried_header(&header);
    let decoded = attested && missing.is_none();
    // Without the GLOBAL anchor the output check below is itself a wait.
    let _ = validator.prepare_global_anchor(&cleared).await;
    let structure = {
        let (validator, mut bare) = (validator.clone(), cleared.clone());
        if let Some(header) = bare.header.as_mut() {
            header.public_key_signature_bls48581 = None;
        }
        tokio::task::spawn_blocking(move || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                validator.validate_linked_without_storage(&bare)
            }))
        })
        .await
    };
    if let Some(verdict) = structure_verdict(structure.unwrap_or_else(|_| {
        Ok(Err(quil_types::error::QuilError::Internal(
            "carried copy check ended early".into(),
        )))
    })) {
        return verdict;
    }
    // In its own task: a search that runs out of time leaves it to finish,
    // and the committee it rebuilds serves the next search.
    let committee = {
        let (validator, cleared) = (validator.clone(), cleared.clone());
        tokio::spawn(async move { validator.prepare_historical_committee(&cleared).await })
            .await
            .unwrap_or_else(|error| {
                Err(quil_types::error::QuilError::Internal(format!(
                    "committee preparation: {error}"
                )))
            })
    };
    let history = match decoded {
        true => Some(validator.prepare_storage_history(&full).await),
        false => None,
    };
    let could_cure = cleared
        .header
        .as_ref()
        .is_some_and(|header| validator.legacy_committee_applies(header));
    let checked = tokio::task::spawn_blocking(move || {
        let check = |run: &dyn Fn() -> Result<bool>| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)).unwrap_or_else(|_| {
                Err(quil_types::error::QuilError::Internal(
                    "carried copy check panicked".into(),
                ))
            })
        };
        let certified = check(&|| validator.validate_certified_without_storage(&cleared));
        let possession = match (&certified, decoded) {
            (Ok(true), true) => Some(check(&|| {
                quil_types::consensus::AppFrameValidator::validate(&*validator, &full)
            })),
            _ => None,
        };
        (certified, possession)
    })
    .await;
    let Ok((certified, possession)) = checked else {
        return CopyVerdict::Unavailable;
    };
    match certified {
        Ok(true) => {}
        Err(error) if !refuses_frame(&error) => return CopyVerdict::Unavailable,
        // Refused for its certificate alone, its structure and output sound.
        // A committee that could not be had is a wait only when one could
        // decide this certificate; else this node's view (a session or
        // committee it lacks) may be at fault, not the copy.
        _ if committee.is_err() && could_cure => return CopyVerdict::Unavailable,
        _ => return CopyVerdict::CertificateRefused,
    }
    if !attested {
        return CopyVerdict::Certified;
    }
    match possession {
        Some(Ok(true)) => CopyVerdict::Certified,
        _ if history.as_ref().is_some_and(|prepared| prepared.is_err()) => {
            CopyVerdict::AttestationUnavailable
        }
        Some(Err(error)) if !refuses_frame(&error) => CopyVerdict::AttestationUnavailable,
        _ => CopyVerdict::AttestationRefused,
    }
}

/// What the check of a copy's structure and output (`result`, a panic
/// caught) says of it: `None` when it passes. Only a refusal of the copy
/// refuses it; a panic, the check ending early, or an error of this node's
/// (a GLOBAL frame it lacks, its own clock) is a wait.
fn structure_verdict(result: std::thread::Result<Result<bool>>) -> Option<CopyVerdict> {
    match result {
        Ok(Ok(true)) => None,
        Ok(Ok(false)) => Some(CopyVerdict::Refused),
        Ok(Err(error)) if refuses_frame(&error) => Some(CopyVerdict::Refused),
        _ => Some(CopyVerdict::Unavailable),
    }
}

/// Where archive replay gets its [`CarriedVerifier`]: asked of the
/// recovery target by the first rebuild that needs it, and again by later
/// ones while it gives none, so a replay with every frame served never waits
/// on the engine for it.
#[derive(Default)]
pub(crate) struct CarriedVerifierSource<'a> {
    target: Option<&'a dyn ShardRecoveryTarget>,
    verifier: tokio::sync::OnceCell<CarriedVerifier>,
}

impl<'a> CarriedVerifierSource<'a> {
    pub(crate) fn of(target: &'a dyn ShardRecoveryTarget) -> Self {
        Self {
            target: Some(target),
            verifier: Default::default(),
        }
    }

    /// The verifier, asked for again by a later rebuild while the target
    /// has not answered one.
    async fn get(&self) -> Option<&CarriedVerifier> {
        self.verifier
            .get_or_try_init(|| async {
                match self.target {
                    Some(target) => target.carried_copy_verifier().await.ok_or(()),
                    None => Err(()),
                }
            })
            .await
            .ok()
    }
}

/// Whether `header` can be `filter`'s frame `frame_number`, rebuilt from it:
/// that frame's, with a certificate, committing to no requests. A cheap
/// check before any copy is kept.
pub fn plausible_carried_copy(
    header: &quil_types::proto::global::FrameHeader,
    filter: &[u8],
    frame_number: u64,
) -> bool {
    header.address == filter
        && header.frame_number == frame_number
        && header
            .public_key_signature_bls48581
            .as_ref()
            .is_some_and(|signature| !signature.signature.is_empty())
        && crate::frame_validator::commits_no_requests(&header.requests_root)
}

/// Whether a copy anchored to GLOBAL frame `anchor` can be carried by GLOBAL
/// frame `carried_by`: GLOBAL takes a shard header only while its anchor
/// lies within [`STORAGE_ANCHOR_LOCKSTEP_WINDOW`](quil_execution::global_intrinsic::frame_header::STORAGE_ANCHOR_LOCKSTEP_WINDOW)
/// below the carrying frame. A copy anchored elsewhere is no copy GLOBAL
/// executed. Nothing GLOBAL checks keeps a frame's anchor from lying below
/// its predecessor's; that anchor only places the search.
pub fn plausibly_anchored(anchor: u64, carried_by: u64) -> bool {
    let lockstep = quil_execution::global_intrinsic::frame_header::STORAGE_ANCHOR_LOCKSTEP_WINDOW;
    anchor < carried_by && carried_by - anchor <= 1 + lockstep
}

/// `header` with the fields of a commonware certificate's signature that
/// neither the certificate nor the output binds cleared: its bitmask and
/// public key. A planted copy with other bytes there is the same copy, and
/// those bytes are not stored (`app_handoff::frame_from_carried_header`
/// gives the key back the empty value members store). Its fee total in the
/// canonical form members store (empty for zero, 16 bytes otherwise): the
/// output binds its value, which any other length reads as zero, so a copy
/// with other bytes there is the same copy too.
pub fn normalize_carried_header(header: &mut quil_types::proto::global::FrameHeader) {
    use quil_execution::global_intrinsic::frame_header::{fee_total_field, fee_total_from_bytes};
    header.fee_total = fee_total_field(fee_total_from_bytes(&header.fee_total));
    if let Some(signature) = header
        .public_key_signature_bls48581
        .as_mut()
        .filter(|signature| {
            quil_cw_consensus::app_cert::unwrap_cert_from_header(&signature.signature).is_some()
        })
    {
        signature.bitmask.clear();
        signature.public_key = None;
    }
}

/// Whether `header`'s certificate is a legacy one (generation zero), whose
/// check may rebuild a historical committee from GLOBAL history.
pub fn carried_copy_is_legacy(header: &quil_types::proto::global::FrameHeader) -> bool {
    header
        .public_key_signature_bls48581
        .as_ref()
        .and_then(|signature| {
            quil_cw_consensus::app_cert::unwrap_cert_from_header(&signature.signature)
        })
        .and_then(quil_cw_consensus::app_cert::unverified_finalization_epoch)
        == Some(0)
}

/// The order carried copies are tried in, lowest first: a copy whose
/// certificate verified, then one whose output `named` (the parent the frame
/// after it names) is the digest of, then one with the committee's storage
/// attestation. GLOBAL keeps a header whose execution failed, so anyone who
/// gets a bundle into GLOBAL can plant a copy, and no certificate binds the
/// attestation field.
pub fn rank_carried_copy(
    header: &quil_types::proto::global::FrameHeader,
    named: Option<&[u8; 32]>,
    certified: bool,
) -> (bool, bool, bool) {
    let is_named = named.is_some_and(|named| {
        quil_crypto::poseidon::hash_bytes_to_32(&header.output).is_ok_and(|digest| digest == *named)
    });
    (!certified, !is_named, header.storage_attestation.is_empty())
}

/// The identity of a copy of a carried header ([`carried_copy_digest`]).
pub type CopyId = [u8; 32];

/// A digest of one copy of a carried header, apart from its storage
/// attestation bytes and the unbound signature fields
/// ([`normalize_carried_header`]): whether it holds an attestation counts,
/// its bytes do not, so copies that vary only there are one copy, and the
/// same copy with that field cleared another. SHA-256, so no copy can be
/// ground to share another's identity and have the refusal of one pass
/// over the other.
pub fn carried_copy_digest(header: &quil_types::proto::global::FrameHeader) -> CopyId {
    use sha2::Digest;
    let mut cleared = quil_types::proto::global::FrameHeader {
        storage_attestation: Vec::new(),
        ..header.clone()
    };
    normalize_carried_header(&mut cleared);
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"quil/app/carried-copy/v1");
    hasher.update([u8::from(!header.storage_attestation.is_empty())]);
    hasher.update(prost::Message::encode_to_vec(&cleared));
    hasher.finalize().into()
}

/// The digest of `header` with its attestation field cleared: the copy
/// apart from its attestation ([`carried_copy_digest`]).
pub fn carried_copy_key(header: &quil_types::proto::global::FrameHeader) -> CopyId {
    carried_copy_digest(&quil_types::proto::global::FrameHeader {
        storage_attestation: Vec::new(),
        ..header.clone()
    })
}

/// Why no carried copy is left to rebuild a frame from ([`next_carried_copy`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NoCarriedCopy {
    /// None carried; the reason a copy carried was refused, if one was.
    NoneCarried(Option<String>),
    /// Every copy carried failed to replay, its attestation cleared too.
    Exhausted,
}

/// The copy of `filter`'s frame `number` header to rebuild it from next, with
/// the GLOBAL frame carrying it and its digest: the best ranked
/// ([`rank_carried_copy`]) not rejected, then each attested copy with that
/// field cleared, validated on its certificate and output alone. A rejected
/// copy stays in `carried` so its cleared form is still reached.
pub fn next_carried_copy(
    carried: &CarriedHeaders,
    filter: &[u8],
    number: u64,
    named: Option<&[u8; 32]>,
) -> std::result::Result<(u64, quil_types::proto::global::FrameHeader, CopyId), NoCarriedCopy> {
    use quil_types::proto::global::FrameHeader;
    let mut refused = None;
    let mut usable: Vec<(u64, FrameHeader)> = Vec::new();
    for (global, header) in &carried.copies {
        let why = if header.address != filter || header.frame_number != number {
            "carries another frame's header in its place"
        } else if header
            .public_key_signature_bls48581
            .as_ref()
            .is_none_or(|signature| signature.signature.is_empty())
        {
            "carries its header without a certificate"
        } else if !crate::frame_validator::commits_no_requests(&header.requests_root) {
            "carries its header, which commits requests only its body holds"
        } else if !plausibly_anchored(header.global_frame_number, *global) {
            "carries its header anchored where GLOBAL could not have taken it"
        } else {
            let mut header = header.clone();
            normalize_carried_header(&mut header);
            usable.push((*global, header));
            continue;
        };
        refused.get_or_insert(format!("GLOBAL frame {global} {why}"));
    }
    if usable.is_empty() {
        return Err(match carried.rejected.is_empty() {
            true => NoCarriedCopy::NoneCarried(refused),
            false => NoCarriedCopy::Exhausted,
        });
    }
    usable.sort_by_key(|(_, header)| {
        rank_carried_copy(
            header,
            named,
            carried.certified.contains(&carried_copy_digest(header)),
        )
    });
    let cleared: Vec<(u64, FrameHeader)> = usable
        .iter()
        .filter(|(_, header)| !header.storage_attestation.is_empty())
        .map(|(global, header)| {
            (
                *global,
                FrameHeader {
                    storage_attestation: Vec::new(),
                    ..header.clone()
                },
            )
        })
        .collect();
    let mut tried = std::collections::HashSet::new();
    usable
        .into_iter()
        .chain(cleared)
        .map(|(global, header)| {
            let copy = carried_copy_digest(&header);
            (global, header, copy)
        })
        .find(|(_, _, copy)| tried.insert(*copy) && !carried.rejected.contains(copy))
        .ok_or(NoCarriedCopy::Exhausted)
}

/// A random delay of at most `max`. Every node receives a GLOBAL frame, and
/// passes an epoch boundary, within moments of the others, and they all sync
/// the prover tree from the same few archives: a delay drawn for each sync
/// spreads those syncs out instead of starting them together.
pub fn sync_jitter(max: std::time::Duration) -> std::time::Duration {
    use rand::Rng;
    let nanos = u64::try_from(max.as_nanos()).unwrap_or(u64::MAX);
    std::time::Duration::from_nanos(rand::thread_rng().gen_range(0..=nanos))
}

/// A random index below `len` (0 when `len` is 0): the archive a pass over
/// all of them starts at, so nodes that pass together start at different
/// archives.
pub fn random_index(len: usize) -> usize {
    use rand::Rng;
    if len == 0 {
        0
    } else {
        rand::thread_rng().gen_range(0..len)
    }
}

pub(crate) enum ShardSyncResult {
    Anchored {
        anchor: AppShardFrame,
        predecessor: Option<AppShardFrame>,
    },
    /// `pinned`: the origins' sealed state, verified against their roots;
    /// otherwise the archive's current subtree, unauthenticated.
    Inherited { pinned: bool },
    /// Why nothing usable was installed.
    NotReady(&'static str),
}

/// How often [`ShardRecoveryTarget::stopped`] looks whether a target that
/// cannot signal its stop still runs.
const STOP_POLL: std::time::Duration = std::time::Duration::from_secs(10);

/// Why a recovery attempted nothing: its worker's engine stopped while it
/// waited for a turn ([`recover_in_turns`]).
pub(crate) const ENGINE_STOPPED_WHILE_QUEUED: &str =
    "the worker's shard engine stopped while its recovery waited for a turn";

/// Why a recovery attempted nothing: this node gives up the worker's seat
/// (`WorkerAllocator::gives_up`), so nothing needs its shard state.
pub(crate) const SEAT_GIVEN_UP: &str = "this node gives up the worker's seat";

/// Why a recovery attempted nothing: its attempts keep stopping at a shard
/// frame no archive serves, and the next one waits
/// ([`crate::worker_execution::ArchiveGapPacing`]).
pub(crate) const ARCHIVE_GAP_HELD: &str =
    "the recovery's attempts stop at a shard frame no archive serves; the next one is backed off";

/// The owning actor authenticates and installs a checkpoint. A recovery task
/// keeps this exact target through completion, even if a worker is reassigned.
#[async_trait]
pub(crate) trait ShardRecoveryTarget: Send + Sync {
    fn materialized(&self) -> u64;
    /// Consecutive descendants ending at a certified frame authenticate a
    /// frame with no certificate of its own. The actor verifies the whole chain.
    /// Replay and validation that read committed GLOBAL state while a GLOBAL
    /// state sync installs its chunks refuse with its wait
    /// ([`quil_execution::global_intrinsic::handoff::GLOBAL_SYNC_IN_PROGRESS`]),
    /// which recovery waits out ([`waiting_out_global_sync`]).
    async fn replay(&self, frame: AppShardFrame, descendants: Vec<AppShardFrame>) -> Result<u64>;
    async fn validate(
        &self,
        anchor: AppShardFrame,
        predecessor: Option<AppShardFrame>,
    ) -> Result<bool>;
    async fn install(
        &self,
        anchor: AppShardFrame,
        predecessor: Option<AppShardFrame>,
    ) -> Result<()>;
    fn inherited(&self);
    /// The worker's core, named in recovery's log lines; `None` when unknown.
    fn core_id(&self) -> Option<u32> {
        None
    }
    /// `(source filter, sealed roots)` of the certified state a shard with no
    /// frame of its own syncs against (`app_handoff::origin_anchors`).
    async fn origin_anchors(&self) -> Result<Vec<(Vec<u8>, [[u8; 32]; 4])>> {
        Ok(Vec::new())
    }
    /// The base-state roots a refused archive tip attests: the certified
    /// first frame of a session GLOBAL ended at the current session's base.
    async fn discarded_base_roots(&self, _frame: AppShardFrame) -> Result<Option<Vec<Vec<u8>>>> {
        Ok(None)
    }
    /// The frame GLOBAL has executed the shard's current session through
    /// (`app_handoff::committed_tip`): replay targets at least this, and an
    /// archive below it is behind, not a sign the worker is up to date.
    async fn committed_tip(&self) -> Option<u64> {
        None
    }
    /// The GLOBAL frame the worker's materialized frame `frame` is anchored
    /// to, read from its own store; `None` when unknown.
    async fn materialized_anchor(&self, _frame: u64) -> Option<u64> {
        None
    }
    /// Checks each copy of a frame's header GLOBAL carried, as replay would
    /// ([`verify_carried_copy`]), before a search keeps it. `None` (no
    /// engine, or it did not answer): a search keeps copies unchecked, named
    /// ones first, and replay checks them; the next rebuild asks again.
    async fn carried_copy_verifier(&self) -> Option<CarriedVerifier> {
        None
    }
    /// Whether this shard owes a re-anchor (`app_handoff::ReanchorMarker`),
    /// its head past its session's fence on frames the fence discarded, and
    /// whether this sync makes the attempt.
    async fn reanchor_fence(&self) -> ReanchorAttempt {
        ReanchorAttempt::NotOwed
    }
    /// An attempt of the owed re-anchor installed nothing, for `reason`.
    fn reanchor_failed(&self, _reason: String) {}
    /// An attempt of the owed re-anchor handed its turn back at the hold
    /// limit, its installed leaves kept: the next sync makes the attempt.
    fn reanchor_yielded(&self) {}
    /// Whether the worker's engine still runs, so its recovery goes on.
    fn running(&self) -> bool {
        true
    }
    /// Resolves once the worker's engine has stopped ([`Self::running`]
    /// false), looked at every [`STOP_POLL`]: a recovery still waiting for
    /// its turn then withdraws ([`recover_in_turns`]).
    async fn stopped(&self) {
        while self.running() {
            tokio::time::sleep(STOP_POLL).await;
        }
    }
    /// The worker's committed cursor is at its same-filter predecessor's
    /// sealed checkpoint with other state there
    /// (`app_handoff::sealed_state_mismatch`).
    async fn sealed_state_mismatch(&self) -> Option<crate::app_handoff::SealedStateMismatch> {
        None
    }
    /// A sync installed the predecessor's sealed state at the checkpoint
    /// `frame`, where the worker's cursor is.
    fn sealed_state_installed(&self, _frame: u64) {}
}

#[async_trait]
impl ShardRecoveryTarget for crate::app_engine::AppEngineHandle {
    fn materialized(&self) -> u64 {
        self.materialized_frame()
    }
    fn core_id(&self) -> Option<u32> {
        Some(self.core_id)
    }
    async fn replay(&self, frame: AppShardFrame, descendants: Vec<AppShardFrame>) -> Result<u64> {
        self.replay_archive_frame(frame, descendants).await
    }
    async fn validate(
        &self,
        anchor: AppShardFrame,
        predecessor: Option<AppShardFrame>,
    ) -> Result<bool> {
        self.validate_sync_anchor(anchor, predecessor).await
    }
    async fn install(
        &self,
        anchor: AppShardFrame,
        predecessor: Option<AppShardFrame>,
    ) -> Result<()> {
        self.complete_archive_sync(anchor, predecessor).await
    }
    fn inherited(&self) {
        self.send(crate::app_engine::AppEngineMessage::ShardSyncCompleted { synced_to_frame: 0 });
    }
    async fn origin_anchors(&self) -> Result<Vec<(Vec<u8>, [[u8; 32]; 4])>> {
        crate::app_engine::AppEngineHandle::origin_anchors(self).await
    }
    async fn discarded_base_roots(&self, frame: AppShardFrame) -> Result<Option<Vec<Vec<u8>>>> {
        crate::app_engine::AppEngineHandle::discarded_base_roots(self, frame).await
    }
    async fn committed_tip(&self) -> Option<u64> {
        crate::app_engine::AppEngineHandle::committed_tip(self).await
    }
    async fn materialized_anchor(&self, frame: u64) -> Option<u64> {
        crate::app_engine::AppEngineHandle::materialized_anchor(self, frame).await
    }
    async fn carried_copy_verifier(&self) -> Option<CarriedVerifier> {
        crate::app_engine::AppEngineHandle::carried_copy_verifier(self).await
    }
    async fn reanchor_fence(&self) -> ReanchorAttempt {
        crate::app_engine::AppEngineHandle::reanchor_fence(self).await
    }
    fn reanchor_failed(&self, reason: String) {
        self.send(crate::app_engine::AppEngineMessage::ReanchorFailed { reason });
    }
    fn reanchor_yielded(&self) {
        self.execution_record().reanchor_yielded();
    }
    fn running(&self) -> bool {
        self.is_running()
    }
    async fn stopped(&self) {
        crate::app_engine::AppEngineHandle::stopped(self).await
    }
    async fn sealed_state_mismatch(&self) -> Option<crate::app_handoff::SealedStateMismatch> {
        crate::app_engine::AppEngineHandle::sealed_state_mismatch(self).await
    }
    fn sealed_state_installed(&self, frame: u64) {
        self.send(crate::app_engine::AppEngineMessage::ShardSyncCompleted {
            synced_to_frame: frame,
        });
    }
}

/// What a shard sync starting now does about a re-anchor at the fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReanchorAttempt {
    /// None is owed: the sync runs as usual.
    NotOwed,
    /// This sync makes the owed attempt, at the fence it names.
    Take(u64),
    /// One is owed and another sync has its attempt: this one does nothing,
    /// since the shard's own lineage is discarded and nothing else may write
    /// its trees.
    Elsewhere,
}

/// One turn's replay: the frames it materialized, the batches they took,
/// and its time spent on archive requests and on the engine's replay.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplayTurn {
    pub frames: u64,
    pub batches: u32,
    pub fetch_ms: u64,
    pub replay_ms: u64,
    /// The turn ended below its replay target.
    pub behind: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ShardRecoveryProgress {
    /// `archive_tip`: the highest tip an archive reported (`None`: none had a
    /// frame of the shard). `committed_tip`: GLOBAL's executed frame of the
    /// session. Materialized below the committed tip is not up to date.
    Replayed {
        materialized: u64,
        archive_tip: Option<u64>,
        committed_tip: Option<u64>,
        turn: ReplayTurn,
    },
    Anchored {
        frame: u64,
    },
    Inherited {
        pinned: bool,
    },
    /// The predecessor's sealed state replaced other state at its
    /// checkpoint `frame`, where the worker's cursor is.
    SealedStateInstalled {
        frame: u64,
    },
    NotReady(&'static str),
    /// Nothing was attempted, for a reason that is no failure of the
    /// recovery (a re-anchor at the fence has its own attempt, or the
    /// worker's engine stopped while it waited for a turn): no counter,
    /// streak or archive state changes.
    Deferred(&'static str),
    /// The tree install handed its turn back at the hold limit
    /// ([`crate::recovery_turns::MAX_TURN_HOLD`]) after installing leaves,
    /// which stay: the recovery queues again and resumes from them.
    Yielded,
}

impl std::fmt::Display for ShardRecoveryProgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tip = |tip: &Option<u64>| tip.map_or_else(|| "none".to_string(), |tip| tip.to_string());
        match self {
            Self::Replayed {
                materialized,
                archive_tip,
                committed_tip,
                ..
            } => write!(
                f,
                "replayed to frame {materialized} (archive tip {}, committed tip {})",
                tip(archive_tip),
                tip(committed_tip)
            ),
            Self::Anchored { frame } => {
                write!(f, "installed the archive checkpoint at frame {frame}")
            }
            Self::Inherited { pinned: true } => f.write_str("inherited the origins' sealed state"),
            Self::Inherited { pinned: false } => {
                f.write_str("inherited the covered archive subtree, unpinned")
            }
            Self::SealedStateInstalled { frame } => write!(
                f,
                "installed the predecessor's sealed state at frame {frame}"
            ),
            Self::NotReady(reason) | Self::Deferred(reason) => f.write_str(reason),
            Self::Yielded => f.write_str(crate::worker_execution::RECOVERY_TURN_SPENT),
        }
    }
}

/// How often a recovery waiting out a GLOBAL state sync install asks again
/// ([`waiting_out_global_sync`]).
const GLOBAL_SYNC_POLL: std::time::Duration = std::time::Duration::from_secs(2);

/// How long one recovery attempt waits in total, its turn held, for GLOBAL
/// state sync installs ([`waiting_out_global_sync`]). A regular node's
/// master installs the GLOBAL prover tree from an archive every few
/// minutes, in chunks over seconds to minutes, and committed GLOBAL state is
/// withheld until the last chunk is in. On a node whose installs took 250 to
/// 580 s of every 8 to 10 minutes, replays refused by them failed their
/// attempts and handed their turns back, and 30 of 73 successor sessions
/// stayed blocked below their predecessor's seal (2026-10-26). Past the
/// budget the refusal fails the attempt, as before, and the next one waits
/// again.
const GLOBAL_SYNC_WAIT_BUDGET: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// One recovery attempt's waits for GLOBAL state sync installs, within
/// [`GLOBAL_SYNC_WAIT_BUDGET`].
#[derive(Default)]
struct GlobalSyncWait {
    /// Milliseconds the attempt's waited-out requests took.
    waited_ms: AtomicU64,
    /// The attempt warned that its budget ran out.
    exhausted: AtomicBool,
}

/// `attempt`, an engine request of `duty` for frame `frame` that reads
/// committed GLOBAL state, with a GLOBAL state sync install waited out:
/// while it refuses with
/// [`quil_execution::global_intrinsic::handoff::GLOBAL_SYNC_IN_PROGRESS`],
/// it is asked again every [`GLOBAL_SYNC_POLL`], while the engine runs and
/// within what is left of `wait`'s budget. Once that is spent, the refusal
/// is returned, as it was before any wait. A wait is logged when it starts
/// and when it ends, not per request.
async fn waiting_out_global_sync<T, F, Fut>(
    wait: &GlobalSyncWait,
    target: &dyn ShardRecoveryTarget,
    filter: &[u8],
    frame: u64,
    duty: &'static str,
    mut attempt: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    use quil_execution::global_intrinsic::handoff::global_sync_in_progress;
    let started = tokio::time::Instant::now();
    let mut waiting = false;
    loop {
        let result = attempt().await;
        let waited = started.elapsed();
        let refused = matches!(&result, Err(error) if global_sync_in_progress(error));
        let spent =
            std::time::Duration::from_millis(wait.waited_ms.load(Ordering::Relaxed)) + waited;
        if refused && target.running() && spent + GLOBAL_SYNC_POLL <= GLOBAL_SYNC_WAIT_BUDGET {
            if !waiting {
                waiting = true;
                tracing::info!(core_id = target.core_id(), filter = %hex::encode(filter), frame,
                    duty, poll_secs = GLOBAL_SYNC_POLL.as_secs(),
                    budget_secs = GLOBAL_SYNC_WAIT_BUDGET.as_secs(),
                    "archive recovery waits for this node's GLOBAL state sync to finish \
                    installing, which withholds committed GLOBAL state; an expected wait");
            }
            tokio::time::sleep(GLOBAL_SYNC_POLL).await;
            continue;
        }
        wait.waited_ms
            .fetch_add(waited.as_millis() as u64, Ordering::Relaxed);
        if refused {
            if target.running() && !wait.exhausted.swap(true, Ordering::Relaxed) {
                tracing::warn!(core_id = target.core_id(), filter = %hex::encode(filter), frame,
                    duty, waited_secs = spent.as_secs(),
                    budget_secs = GLOBAL_SYNC_WAIT_BUDGET.as_secs(), scope = "this node",
                    action = "this node's master installs the GLOBAL prover tree from an archive; \
                    check how long its installs take; the next attempt waits again; report it \
                    with this line if it persists",
                    "archive recovery stopped waiting for this node's GLOBAL state sync to \
                    finish installing; the attempt fails and is retried");
            }
        } else if waiting {
            tracing::info!(core_id = target.core_id(), filter = %hex::encode(filter), frame, duty,
                waited_secs = waited.as_secs(), succeeded = result.is_ok(),
                "archive recovery resumed after this node's GLOBAL state sync finished installing");
        }
        return result;
    }
}

/// Common recovery path for thread and separate-process workers. A saved
/// lineage replays certified bodies; an empty worker fetches and authenticates
/// the archive checkpoint before tree writes, then waits for actor installation.
///
/// `keep_turn`: the successor-blocked and lagging-voter flags of a worker
/// holding a recovery turn (none without one). A turn replays one batch, and
/// while one of them stays set further batches up to the replay target,
/// within the turn budget ([`crate::recovery_turns::holds_turn`]). `turn`:
/// the turn held, released before the engine installs an anchor, which reads
/// no archive tree; a tree install past the hold limit hands it back
/// (`ShardRecoveryProgress::Yielded`).
pub(crate) async fn recover_shard_from_latest(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    local: Option<AppShardFrame>,
    target: &dyn ShardRecoveryTarget,
    keep_turn: &[&AtomicBool],
    turn: Option<crate::recovery_turns::Turn<'_>>,
) -> Result<ShardRecoveryProgress> {
    use crate::worker_execution::recovery_phase;
    // No archive extends a head the fence discarded: the local lineage is
    // not replayed, and the shard is anchored again.
    match target.reanchor_fence().await {
        ReanchorAttempt::Take(fence) => {
            crate::worker_execution::recovery_kind(crate::recovery_turns::RecoveryKind::Reanchor);
            let result =
                yielded(reanchor_shard_at_fence(syncer, filter, fence, target, turn).await);
            match &result {
                Ok(ShardRecoveryProgress::NotReady(reason)) => {
                    target.reanchor_failed((*reason).to_string())
                }
                Ok(ShardRecoveryProgress::Yielded) => target.reanchor_yielded(),
                Err(error) => target.reanchor_failed(error.to_string()),
                Ok(_) => {}
            }
            return result;
        }
        ReanchorAttempt::Elsewhere => {
            return Ok(ShardRecoveryProgress::Deferred(REANCHOR_ELSEWHERE))
        }
        ReanchorAttempt::NotOwed => {}
    }
    // A worker at its predecessor's sealed checkpoint holding other state
    // there has no frame to replay: its replay reported success while the
    // successor's start refused the state, every 10 s for good (…091f80 at
    // frame 4693, 2026-10-23).
    if let Some(mismatch) = target.sealed_state_mismatch().await {
        return yielded(install_sealed_state(syncer, filter, mismatch, target).await);
    }
    let sync_wait = &GlobalSyncWait::default();
    if let Some(local) = local {
        recovery_phase("replaying_frames");
        let committed_tip = target.committed_tip().await;
        let (started, from, replay_us) =
            (Instant::now(), target.materialized(), &AtomicU64::new(0));
        let (mut materialized, mut batches) = (from, 0);
        // A batch short of its target replayed all its frames: each frame
        // advances the replay or fails it.
        let verify = CarriedVerifierSource::of(target);
        // The anchor of the frame the last batch ended on, which `local`
        // no longer is: at first, that of the frame materialized, from the
        // worker's own store, as an earlier recovery may have rebuilt it from
        // its carried header, which no archive serves.
        let mut known = match local.header.as_ref().map(|header| header.frame_number) == Some(from)
        {
            true => None,
            false => target
                .materialized_anchor(from)
                .await
                .map(|anchor| (from, anchor)),
        };
        let replay = loop {
            let (replay, last) = replay_shard_from(
                syncer,
                filter,
                local.clone(),
                materialized,
                known,
                committed_tip,
                &verify,
                |frame, child| async move {
                    let at = Instant::now();
                    let number = frame
                        .header
                        .as_ref()
                        .map_or(0, |header| header.frame_number);
                    let advanced = waiting_out_global_sync(
                        sync_wait,
                        target,
                        filter,
                        number,
                        "archive replay",
                        move || target.replay(frame.clone(), child.clone()),
                    )
                    .await;
                    replay_us.fetch_add(at.elapsed().as_micros() as u64, Ordering::Relaxed);
                    advanced
                },
            )
            .await?;
            known = last;
            batches += 1;
            if replay.materialized >= replay.target
                || !crate::recovery_turns::holds_turn(keep_turn, started.elapsed())
            {
                break replay;
            }
            materialized = replay.materialized;
        };
        let replay_ms = replay_us.load(Ordering::Relaxed) / 1000;
        let turn = ReplayTurn {
            frames: replay.materialized.saturating_sub(from),
            batches,
            fetch_ms: (started.elapsed().as_millis() as u64).saturating_sub(replay_ms),
            replay_ms,
            behind: replay.materialized < replay.target,
        };
        return Ok(ShardRecoveryProgress::Replayed {
            materialized: replay.materialized,
            archive_tip: replay.archive_tip,
            committed_tip,
            turn,
        });
    }
    let anchors = target.origin_anchors().await.unwrap_or_else(|error| {
        tracing::warn!(filter = %hex::encode(filter), %error, "origin anchors unavailable; bootstrap unpinned");
        Vec::new()
    });
    let committed_tip = target.committed_tip().await;
    recovery_phase("fetching_checkpoint");
    let synced = sync_shard_from_latest_attested(
        syncer,
        filter,
        None,
        &anchors,
        committed_tip,
        |anchor: AppShardFrame, predecessor: Option<AppShardFrame>| {
            let number = anchor
                .header
                .as_ref()
                .map_or(0, |header| header.frame_number);
            waiting_out_global_sync(
                sync_wait,
                target,
                filter,
                number,
                "archive sync anchor validation",
                move || target.validate(anchor.clone(), predecessor.clone()),
            )
        },
        |frame| target.discarded_base_roots(frame),
    )
    .await;
    match synced {
        Err(error) if crate::worker_execution::turn_spent(&error) => {
            Ok(ShardRecoveryProgress::Yielded)
        }
        Err(error) => Err(error),
        Ok(ShardSyncResult::Anchored {
            anchor,
            predecessor,
        }) => {
            let frame = anchor
                .header
                .as_ref()
                .map_or(0, |header| header.frame_number);
            recovery_phase("installing_checkpoint");
            // The trees are in; the engine's installation reads none from an
            // archive, and its own in-flight guard keeps another install out.
            drop(turn);
            target.install(anchor, predecessor).await?;
            Ok(ShardRecoveryProgress::Anchored { frame })
        }
        Ok(ShardSyncResult::Inherited { pinned }) => {
            target.inherited();
            Ok(ShardRecoveryProgress::Inherited { pinned })
        }
        Ok(ShardSyncResult::NotReady(reason)) => Ok(ShardRecoveryProgress::NotReady(reason)),
    }
}

/// Why an install of a predecessor's sealed state over other local state
/// failed ([`install_sealed_state`]).
pub(crate) const SEALED_STATE_UNAVAILABLE: &str =
    "the archive does not hold the predecessor's sealed state, or its roots differ";
pub(crate) const SEALED_STATE_NOT_INSTALLED: &str =
    "a shard sync pinned to the predecessor's sealed roots left other committed roots on this worker";

/// Install a same-filter predecessor's sealed state over the other state
/// this worker holds at its checkpoint (`mismatch`): its trees are synced
/// pinned to the sealed roots, which the sync verifies, and the actor is
/// told once its committed roots are the sealed ones. The cursor stays at
/// the checkpoint, and the successor's start compares the state again.
async fn install_sealed_state(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    mismatch: crate::app_handoff::SealedStateMismatch,
    target: &dyn ShardRecoveryTarget,
) -> Result<ShardRecoveryProgress> {
    use crate::app_handoff::SealedStateMismatch;
    crate::worker_execution::recovery_phase("installing_leaves");
    let pinned: Vec<Vec<u8>> = mismatch
        .sealed_roots
        .iter()
        .map(|root| root.to_vec())
        .collect();
    if !syncer.sync_shard_tree(filter, &pinned).await? {
        return Ok(ShardRecoveryProgress::NotReady(SEALED_STATE_UNAVAILABLE));
    }
    if target.sealed_state_mismatch().await.is_some() {
        return Ok(ShardRecoveryProgress::NotReady(SEALED_STATE_NOT_INSTALLED));
    }
    target.sealed_state_installed(mismatch.frame);
    tracing::info!(filter = %hex::encode(filter), generation = mismatch.generation, frame = mismatch.frame,
        replaced_roots = %SealedStateMismatch::prefixes(&mismatch.local_roots),
        sealed_roots = %SealedStateMismatch::prefixes(&mismatch.sealed_roots), scope = "this worker",
        "installed the predecessor's sealed state from an archive over other local state at its checkpoint");
    Ok(ShardRecoveryProgress::SealedStateInstalled {
        frame: mismatch.frame,
    })
}

/// A tree sync that handed its turn back ([`crate::worker_execution::turn_spent`])
/// as the outcome it is.
fn yielded(result: Result<ShardRecoveryProgress>) -> Result<ShardRecoveryProgress> {
    match result {
        Err(error) if crate::worker_execution::turn_spent(&error) => {
            Ok(ShardRecoveryProgress::Yielded)
        }
        other => other,
    }
}

/// Recover `filter` for the worker on `core` whose record is `execution`,
/// through `turns`, one attempt per turn: an attempt that handed its turn
/// back at the hold limit ([`ShardRecoveryProgress::Yielded`]) queues again
/// in its first arrival's place, taking at most every other turn while
/// others wait (`recovery_turns::TurnQueue::next`), and resumes from the
/// leaves it installed. A replay whose turn ended behind its target keeps
/// that place for the worker's next recovery of the shard
/// (`SharedWorkerExecution::keep_replay_ticket`), unless its successor is
/// blocked, which goes first regardless: requeued last instead, a voting
/// member 40 to 90 frames behind on an operator's node waited up to 5 hours
/// for each 32-frame batch. `lineage` reads the worker's latest frame of the
/// shard before each attempt. Returns the last attempt's outcome.
///
/// A claim still queued when the worker's engine stops is withdrawn
/// ([`ENGINE_STOPPED_WHILE_QUEUED`]): it leaves the queue. Left queued, a
/// worker whose allocation had moved to other cores waited about 20,000 s
/// on an operator's node, then failed within seconds of its turn ("shard
/// engine stopped before sync validation"). Its place stays for the core's
/// next claim of the shard for up to an epoch, as does that of a recovery
/// whose engine stops after it handed its turn back
/// (`recovery_turns::RecoveryTurns::keep_place`): an engine that restarts
/// on its seat (at its activation, around a GLOBAL sync, at an operator's
/// action) queues again there, not behind every claim that arrived
/// meanwhile. On an operator's node the engine of the one seat it kept
/// restarted seven times in 81 minutes while its recovery waited, and five
/// claims lost their places after waiting 20 to 2,671 s.
///
/// A recovery for a seat this node gives up reads no archive
/// ([`SEAT_GIVEN_UP`]): it asks `given_up` before each attempt and again
/// once its turn is granted, which it then hands on unused.
///
/// A recovery whose attempts keep stopping at a shard frame no archive
/// serves waits out its back-off before it queues for a turn
/// ([`ARCHIVE_GAP_HELD`], [`archive_gap_held`]); its place is kept.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn recover_in_turns(
    turns: &crate::recovery_turns::RecoveryTurns,
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    core: u32,
    target: &dyn ShardRecoveryTarget,
    execution: &crate::worker_execution::SharedWorkerExecution,
    mut lineage: impl FnMut() -> Result<Option<AppShardFrame>>,
    given_up: impl Fn() -> bool,
) -> Result<ShardRecoveryProgress> {
    use crate::recovery_turns::{Claim, RecoveryKind};
    let mut ticket = execution.take_replay_ticket(filter);
    loop {
        if given_up() {
            // Withholding may end (the seat renews): the place stays.
            if let Some(ticket) = ticket {
                execution.keep_replay_ticket(filter, ticket);
            }
            return Ok(ShardRecoveryProgress::Deferred(SEAT_GIVEN_UP));
        }
        if archive_gap_held(execution, filter, target).await {
            if let Some(ticket) = ticket {
                execution.keep_replay_ticket(filter, ticket);
            }
            tracing::debug!(core, filter = %hex::encode(filter), reason = ARCHIVE_GAP_HELD,
                "archive recovery held back");
            return Ok(ShardRecoveryProgress::Deferred(ARCHIVE_GAP_HELD));
        }
        let local = lineage().inspect_err(|error| {
            tracing::warn!(core, filter = %hex::encode(filter), %error,
            "cannot determine local shard lineage for sync")
        })?;
        let attempt = async {
            crate::worker_execution::recovery_phase("waiting_for_permit");
            let kind = if local.is_some() {
                RecoveryKind::Replay
            } else {
                RecoveryKind::Install
            };
            let claim = Claim {
                core,
                filter: filter.to_vec(),
                kind,
                execution: execution.clone(),
                ticket,
            };
            let queued = tokio::time::Instant::now();
            // Dropped unanswered, the claim leaves the queue; granted in the
            // meantime, its turn passes on (`recovery_turns::Queued`).
            let turn = tokio::select! {
                biased;
                () = target.stopped() => {
                    tracing::info!(core, filter = %hex::encode(filter), kind = kind.as_str(),
                        waited_secs = queued.elapsed().as_secs(), scope = "this worker",
                        "archive recovery turn request withdrawn: the shard engine stopped while it waited; the \
                        shard runs elsewhere or is no longer allocated here, and the waiters behind it move up, \
                        or its engine restarts and queues again in this place");
                    return Ok(ShardRecoveryProgress::Deferred(ENGINE_STOPPED_WHILE_QUEUED));
                }
                turn = turns.acquire(claim) => turn,
            };
            let place = *ticket.get_or_insert(turn.ticket());
            if given_up() {
                execution.keep_replay_ticket(filter, place);
                return Ok(ShardRecoveryProgress::Deferred(SEAT_GIVEN_UP));
            }
            let (blocked, lagging) = (
                execution.successor_blocked_flag(),
                execution.lagging_voter_flag(),
            );
            recover_shard_from_latest(
                syncer,
                filter,
                local,
                target,
                &[&*blocked, &*lagging],
                Some(turn),
            )
            .await
        };
        let result = execution.recovering(filter, attempt).await;
        if let (Ok(ShardRecoveryProgress::Replayed { turn, .. }), Some(ticket)) = (&result, ticket)
        {
            if turn.behind && !execution.successor_blocked_flag().load(Ordering::Relaxed) {
                execution.keep_replay_ticket(filter, ticket);
            }
        }
        if !matches!(result, Ok(ShardRecoveryProgress::Yielded)) {
            return result;
        }
        if !target.running() {
            if let Some(ticket) = ticket {
                turns.keep_place(core, filter, ticket);
            }
            return result;
        }
    }
}

/// Whether the recovery of `filter` for `target`, the worker whose record
/// is `execution`, waits rather than attempts now: its attempts keep
/// stopping at a shard frame no archive serves
/// ([`crate::worker_execution::ArchiveGapPacing`]). Asked before a recovery
/// queues for a turn, so a held one reads no archive and leaves the node's
/// turns to others. GLOBAL's committed tip is read only while a hold runs.
pub(crate) async fn archive_gap_held(
    execution: &crate::worker_execution::SharedWorkerExecution,
    filter: &[u8],
    target: &dyn ShardRecoveryTarget,
) -> bool {
    if !execution.archive_gap_holding(filter) {
        return false;
    }
    let committed = target.committed_tip().await;
    execution.archive_gap_hold(
        filter,
        target.materialized(),
        committed,
        tokio::time::Instant::now(),
    )
}

/// Why a re-anchor at the session fence installed nothing.
pub(crate) const REANCHOR_NO_TIP: &str =
    "GLOBAL's committed frame of the session is not known here";
pub(crate) const REANCHOR_UNAVAILABLE: &str =
    "the archive does not hold the frame GLOBAL committed or the state before it";
pub(crate) const REANCHOR_REFUSED: &str =
    "the archive's copy of the frame GLOBAL committed was refused at validation";
/// A sync that is not the owed re-anchor's attempt (`ReanchorAttempt::Elsewhere`).
pub(crate) const REANCHOR_ELSEWHERE: &str =
    "a re-anchor at the session fence is owed and has its own attempt";
/// Marks the failure of a re-anchor step that runs on this node.
pub(crate) const REANCHOR_ON_THIS_NODE: &str = "on this node";

fn on_this_node(
    step: &'static str,
) -> impl Fn(quil_types::error::QuilError) -> quil_types::error::QuilError {
    move |error| {
        quil_types::error::QuilError::ExecutionUnavailable(format!(
            "re-anchor {step} {REANCHOR_ON_THIS_NODE}: {error}"
        ))
    }
}

/// Re-anchor a shard whose head lies past its session's fence on frames the
/// fence discarded, which this node cannot rewind (`app_handoff::fence_rewind`).
/// The anchor is the frame GLOBAL committed for the session
/// (`app_handoff::committed_tip`): the fence, the successor's base, while
/// the successor has executed nothing, its executed tip after. It is
/// authenticated as a bootstrap's is, and the shard's trees are synced
/// pinned to its roots; the actor then rebases the shard's frames and cursor
/// below it and replays it. Nothing is inherited unpinned: without an
/// archive that serves the anchor and its state, the shard waits.
async fn reanchor_shard_at_fence(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    fence: u64,
    target: &dyn ShardRecoveryTarget,
    turn: Option<crate::recovery_turns::Turn<'_>>,
) -> Result<ShardRecoveryProgress> {
    use crate::worker_execution::recovery_phase;
    recovery_phase("fetching_checkpoint");
    let Some(committed) = target
        .committed_tip()
        .await
        .filter(|&tip| tip > 0 && tip >= fence)
    else {
        return Ok(ShardRecoveryProgress::NotReady(REANCHOR_NO_TIP));
    };
    let sync_wait = &GlobalSyncWait::default();
    let mut validate = |anchor: AppShardFrame, predecessor: Option<AppShardFrame>| {
        let number = anchor
            .header
            .as_ref()
            .map_or(0, |header| header.frame_number);
        let validated = waiting_out_global_sync(
            sync_wait,
            target,
            filter,
            number,
            "shard re-anchor validation",
            move || target.validate(anchor.clone(), predecessor.clone()),
        );
        async move { validated.await.map_err(on_this_node("validation")) }
    };
    let Some(frame) = syncer.get_app_shard_frame(filter, committed).await? else {
        return Ok(ShardRecoveryProgress::NotReady(REANCHOR_UNAVAILABLE));
    };
    let Some((anchor, predecessor)) =
        authenticated_anchor(syncer, filter, frame, Some(committed), &mut validate).await?
    else {
        return Ok(ShardRecoveryProgress::NotReady(REANCHOR_REFUSED));
    };
    let roots = anchor
        .header
        .as_ref()
        .map(|header| header.state_roots.clone())
        .unwrap_or_default();
    recovery_phase("installing_leaves");
    if !syncer.sync_shard_tree(filter, &roots).await? {
        return Ok(ShardRecoveryProgress::NotReady(REANCHOR_UNAVAILABLE));
    }
    recovery_phase("installing_checkpoint");
    drop(turn);
    target
        .install(anchor, predecessor)
        .await
        .map_err(on_this_node("installation"))?;
    Ok(ShardRecoveryProgress::Anchored { frame: committed })
}

/// Archives asked for a shard's tip when the first answer is behind GLOBAL's
/// committed session tip, and attempts per frame: each request goes to the
/// next archive in the pool.
const TIP_PROBES: usize = 3;
const FRAME_ATTEMPTS: usize = 3;

/// The largest frame archive replay takes.
const MAX_REPLAY_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// How long a replay batch goes on rebuilding frames from their carried
/// headers (each a search of GLOBAL frames, up to a minute and a half with
/// the engine's answer) before it ends with what it materialized: well
/// within a recovery turn's hold limit
/// ([`crate::recovery_turns::MAX_TURN_HOLD`]).
const REBUILT_BATCH_BUDGET: std::time::Duration = std::time::Duration::from_secs(180);

/// GLOBAL frames read at most per search for the header of a shard frame no
/// archive serves. Members submit a finalized frame's header within a few
/// GLOBAL frames (seven to nine for the frames no archive served on
/// 2026-10-23).
pub const CARRIED_HEADER_WINDOW: u64 = 64;
/// GLOBAL frames searched at most for one frame's header, over successive
/// searches, each reading frames the ones before it read without a copy.
pub const CARRIED_HEADER_SPAN: u64 = 4096;

/// The GLOBAL frames that can carry the header of a shard frame, in the
/// order to read them, from the GLOBAL frames its predecessor and its
/// successor (when known) are anchored to. GLOBAL frame `g` takes a shard
/// header only while that header's anchor is within
/// [`STORAGE_ANCHOR_LOCKSTEP_WINDOW`](quil_execution::global_intrinsic::frame_header::STORAGE_ANCHOR_LOCKSTEP_WINDOW)
/// below `g` ([`plausibly_anchored`]); members anchor a frame no earlier
/// than its predecessor and no later than its successor, which no GLOBAL
/// check enforces, so these anchors only place the search. A range longer
/// than [`CARRIED_HEADER_WINDOW`] is read in this order over successive
/// searches: its top half-window from the top down, for a shard that paused
/// before the frame, its bottom half-window, for one that paused after it,
/// then the rest from the bottom up, at most [`CARRIED_HEADER_SPAN`] in all.
pub fn carried_header_globals(predecessor: u64, successor: Option<u64>) -> Vec<u64> {
    let lockstep = quil_execution::global_intrinsic::frame_header::STORAGE_ANCHOR_LOCKSTEP_WINDOW;
    let from = predecessor.saturating_add(1);
    let through = match successor {
        Some(successor) => successor.max(predecessor).saturating_add(1 + lockstep),
        None => from.saturating_add(CARRIED_HEADER_WINDOW - 1),
    };
    if through - from < CARRIED_HEADER_WINDOW {
        return (from..=through).collect();
    }
    let half = CARRIED_HEADER_WINDOW / 2;
    let middle =
        (from + half..=through - half).take((CARRIED_HEADER_SPAN - CARRIED_HEADER_WINDOW) as usize);
    (through - half + 1..=through)
        .rev()
        .chain(from..from + half)
        .chain(middle)
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ShardReplay {
    pub materialized: u64,
    /// The highest tip an archive reported; `None` when none had a frame.
    pub archive_tip: Option<u64>,
    pub target: u64,
}

/// How the error of a replay stopped at a shard frame no archive serves
/// begins, for the frame itself and for a certified descendant the frame
/// before it needs ([`missing_frame`], read back by [`archive_gap`]).
const MISSING_SHARD_FRAME: &str = "archive replay is missing shard frame ";
const MISSING_DESCENDANT_FRAME: &str = "archive replay is missing descendant frame ";

/// A shard frame that no archive serves and that could not be rebuilt from
/// a header GLOBAL carried, at which a replay stopped, with the highest
/// archive tip that replay found and the committed tip of the session it
/// read (0: unknown).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ArchiveGap {
    pub frame: u64,
    pub archive_tip: Option<u64>,
    pub committed: u64,
}

/// The error of a replay stopped at `gap` for `why`; `descendant`: the
/// frame is a certified descendant the frame before it needs.
fn missing_frame(gap: ArchiveGap, descendant: bool, why: String) -> quil_types::error::QuilError {
    let ArchiveGap {
        frame,
        archive_tip,
        committed,
    } = gap;
    let prefix = match descendant {
        true => MISSING_DESCENDANT_FRAME,
        false => MISSING_SHARD_FRAME,
    };
    quil_types::error::QuilError::ExecutionUnavailable(format!(
        "{prefix}{frame} (archive tip {archive_tip:?}, committed {committed}): {why}"
    ))
}

/// The shard frame no archive serves at which a recovery attempt failing
/// with `error` stopped ([`missing_frame`]); `None` for any other failure.
pub(crate) fn archive_gap(error: &str) -> Option<ArchiveGap> {
    let rest = [MISSING_SHARD_FRAME, MISSING_DESCENDANT_FRAME]
        .iter()
        .find_map(|prefix| error.find(prefix).map(|at| &error[at + prefix.len()..]))?;
    let (frame, rest) = rest.split_once(" (archive tip ")?;
    let (archive_tip, rest) = rest.split_once(", committed ")?;
    let (committed, _) = rest.split_once("):")?;
    let archive_tip = match archive_tip {
        "None" => None,
        tip => Some(tip.strip_prefix("Some(")?.strip_suffix(')')?.parse().ok()?),
    };
    Some(ArchiveGap {
        frame: frame.parse().ok()?,
        archive_tip,
        committed: committed.parse().ok()?,
    })
}

/// A frame of `filter` from the first of `attempts` archive requests that has
/// it. `Ok(None)` when every archive answered without it.
async fn fetch_shard_frame(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    number: u64,
    attempts: usize,
) -> Result<Option<AppShardFrame>> {
    let mut failure = None;
    let mut answered = false;
    for _ in 0..attempts.max(1) {
        match syncer.get_app_shard_frame(filter, number).await {
            Ok(Some(frame)) => return Ok(Some(frame)),
            Ok(None) => answered = true,
            Err(error) => failure = Some(error),
        }
    }
    match failure {
        Some(error) if !answered => Err(error),
        _ => Ok(None),
    }
}

/// Frame `number` of `filter`, which no archive serves, rebuilt from the
/// certified header a GLOBAL frame carries, when that header commits to no
/// requests ([`crate::app_handoff::frame_from_carried_header`]), with the
/// digest of the copy used. The frame's certificate binds its output and the
/// output binds its requests root and storage attestation root, so the
/// header and the committee's storage attestation it carries are the body;
/// the engine validates the frame as any certified one, possession included.
/// A header carried without the attestation still rebuilds the frame, which
/// is then validated on its certificate and output alone
/// ([`crate::frame_validator::empty_without_attestation`]). Archives that
/// executed such a frame from that header never stored a body to serve, and
/// replay stopped there for good (shard …0c1db0 frame 14372, carried by
/// GLOBAL 924341, 2026-10-23).
///
/// `anchor`: the GLOBAL frame the frame before it is anchored to; `None`
/// reads that frame from an archive. The frame after it, read too, bounds
/// the search ([`carried_header_globals`]). Of the copies carried, one whose
/// output that frame names comes first, then one with the attestation, then
/// the attested copies with their attestation field cleared: no certificate
/// binds that field, and GLOBAL's audit of a wrong one does not refuse the
/// frame, so a copy whose attestation fails is followed by one without it.
/// A copy whose frame failed to replay is passed over; once every copy has,
/// the GLOBAL frames are searched again later. `Err` says why nothing was
/// rebuilt.
async fn rebuild_from_carried_header(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    number: u64,
    anchor: Option<u64>,
    ceiling: Option<u64>,
    verify: &CarriedVerifierSource<'_>,
) -> std::result::Result<(AppShardFrame, CopyId), String> {
    let neighbour = |offset: i64| async move {
        let neighbour = number.checked_add_signed(offset)?;
        fetch_shard_frame(syncer, filter, neighbour, FRAME_ATTEMPTS)
            .await
            .ok()
            .flatten()
            .and_then(|frame| frame.header)
            .filter(|header| header.address == filter && header.frame_number == neighbour)
    };
    let anchor = match anchor {
        Some(anchor) => Some(anchor),
        None => neighbour(-1).await.map(|header| header.global_frame_number),
    };
    let Some(from) = anchor.filter(|&anchor| anchor > 0) else {
        return Err("the GLOBAL frame its predecessor is anchored to is unknown".into());
    };
    let successor = neighbour(1).await;
    // Without the frame after it, the tip the archive serves bounds the search.
    let bound = successor
        .as_ref()
        .map(|header| header.global_frame_number)
        .or(ceiling);
    let globals = carried_header_globals(from, bound);
    let (low, high) = (
        globals.iter().min().copied().unwrap_or(from),
        globals.iter().max().copied().unwrap_or(from),
    );
    // A range cut at CARRIED_HEADER_SPAN says how much of it is searched.
    let span = match (high - low + 1) as usize > globals.len() {
        true => format!("{low}..={high} ({} of them searched)", globals.len()),
        false => format!("{low}..={high}"),
    };
    let named =
        successor.and_then(|header| <[u8; 32]>::try_from(header.parent_selector.as_slice()).ok());
    let carried = match syncer.cached_carried_shard_headers(filter, number, named) {
        Some(answer) => answer,
        None => {
            syncer
                .carried_shard_headers(filter, number, &globals, named, verify.get().await)
                .await
        }
    }
    .map_err(|error| {
        format!("the GLOBAL frames {span} that may carry its header are unavailable: {error}")
    })?;
    let (global, header, copy) = match next_carried_copy(&carried, filter, number, named.as_ref()) {
        Ok(next) => next,
        Err(NoCarriedCopy::NoneCarried(refused)) => {
            return Err(refused.unwrap_or_else(|| match carried.refused + carried.passed_over {
                0 => format!("no GLOBAL frame {span} carries its header"),
                _ => format!("GLOBAL frames {span} carry only copies of its header refused ({} when checked, {} \
                     passed over as refused before)", carried.refused, carried.passed_over),
            }));
        }
        Err(NoCarriedCopy::Exhausted) => {
            syncer.reject_carried_shard_headers(filter, number);
            return Err(format!(
                "every header GLOBAL frames {span} carry for it failed to replay; they are read again after the \
                 retry interval"
            ));
        }
    };
    let certified = carried.certified.contains(&carried_copy_digest(&header));
    let (frame, missing) = crate::app_handoff::frame_from_carried_header(&header);
    if first_rebuild(filter, number, copy) {
        match &missing {
            None => {
                tracing::info!(filter = %hex::encode(filter), frame = number, global_frame = global,
                attested = frame.storage_attestation.is_some(), certified, passed_over = carried.rejected.len(),
                "archive replay rebuilt an empty shard frame from the certified header GLOBAL carried, \
                 with its committee's storage attestation: no archive serves its body")
            }
            Some(reason) => {
                tracing::warn!(filter = %hex::encode(filter), frame = number, global_frame = global,
                %reason, certified, passed_over = carried.rejected.len(),
                "archive replay rebuilt an empty shard frame from the certified header GLOBAL carried, \
                 without its storage attestation: no archive serves its body, and this worker validates \
                 it on its certificate and output alone")
            }
        }
    }
    Ok((frame, copy))
}

/// Whether `error` refuses a replayed frame (its certificate, output,
/// possession proof or link), rather than a wait on something unavailable.
/// The validator reports a GLOBAL frame this node lacks (the anchor its
/// output or attestation is checked against) as a `Crypto` error, and a
/// frame timestamp ahead of this node's clock as an `InvalidArgument` one,
/// which its other callers treat as refusals; for archive replay and the
/// copies it rebuilds from, they are waits.
pub(crate) fn refuses_frame(error: &quil_types::error::QuilError) -> bool {
    use quil_types::error::QuilError;
    match error {
        QuilError::Crypto(reason) => {
            !(reason.contains("unavailable")
                && (reason.contains("anchored global frame")
                    || reason.contains("storage attestation: global frame")))
        }
        // Measured against this node's clock, not the frame's history.
        QuilError::InvalidArgument(reason) => !reason.contains("too far in the future"),
        QuilError::InvalidSignature(_) => true,
        _ => false,
    }
}

/// Whether `error` names frame `number` as replay does
/// ("archive replay frame 5577: …", `app_engine::refusal_of`): a refusal of
/// one frame in a replay batch says nothing of the others.
fn names_frame(error: &quil_types::error::QuilError, number: u64) -> bool {
    error
        .to_string()
        .contains(&format!("archive replay frame {number}:"))
}

/// Whether the rebuild of `filter`'s frame `number` from copy `copy` is new
/// to this process, which logs it once: the last 64 rebuilds are remembered.
fn first_rebuild(filter: &[u8], number: u64, copy: CopyId) -> bool {
    static REBUILT: std::sync::Mutex<std::collections::VecDeque<(Vec<u8>, u64, CopyId)>> =
        std::sync::Mutex::new(std::collections::VecDeque::new());
    let mut rebuilt = REBUILT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if rebuilt
        .iter()
        .any(|(shard, frame, used)| shard == filter && *frame == number && *used == copy)
    {
        return false;
    }
    if rebuilt.len() >= 64 {
        rebuilt.pop_front();
    }
    rebuilt.push_back((filter.to_vec(), number, copy));
    true
}

/// [`replay_shard_from`] knowing no anchor but `local`'s.
#[cfg(test)]
pub(crate) async fn replay_shard_from_latest<F, Fut>(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    local: AppShardFrame,
    materialized: u64,
    committed: Option<u64>,
    verify: &CarriedVerifierSource<'_>,
    replay: F,
) -> Result<ShardReplay>
where
    F: FnMut(AppShardFrame, Vec<AppShardFrame>) -> Fut,
    Fut: std::future::Future<Output = Result<u64>>,
{
    replay_shard_from(
        syncer,
        filter,
        local,
        materialized,
        None,
        committed,
        verify,
        replay,
    )
    .await
    .map(|(replay, _)| replay)
}

/// Repair a materialized worker by replaying a bounded number of certified
/// frames through its owning engine. Tree-only fast-forward loses fee, spend,
/// settlement and accumulator history and can race normal materialization.
///
/// The target is the highest archive tip, and at least `committed` (GLOBAL's
/// executed frame of the session): an archive can answer with an old tip, or
/// none, while it or another holds the frames, so one archive's answer alone
/// never ends recovery below what GLOBAL has executed. Every frame is still
/// authenticated by `replay`.
///
/// `known`: the GLOBAL frame a frame replayed earlier is anchored to (frame,
/// anchor); the answer carries that of the frame it materialized last, when
/// known. A batch after one that ended on a frame rebuilt from its carried
/// header, which no archive serves, still finds the GLOBAL frames after
/// that frame's anchor.
pub(crate) async fn replay_shard_from<F, Fut>(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    local: AppShardFrame,
    mut materialized: u64,
    known: Option<(u64, u64)>,
    committed: Option<u64>,
    verify: &CarriedVerifierSource<'_>,
    mut replay: F,
) -> Result<(ShardReplay, Option<(u64, u64)>)>
where
    F: FnMut(AppShardFrame, Vec<AppShardFrame>) -> Fut,
    Fut: std::future::Future<Output = Result<u64>>,
{
    use prost::Message;
    use quil_types::error::QuilError;
    let batch_started = tokio::time::Instant::now();
    let height = |frame: &AppShardFrame| frame.header.as_ref().map_or(0, |h| h.frame_number);
    let committed = committed.unwrap_or(0);
    let mut remote: Option<AppShardFrame> = None;
    let mut failure = None;
    for probe in 0..TIP_PROBES {
        // The local head satisfying GLOBAL is not evidence that this archive
        // is current. Keep the bounded rotation going until a peer reaches
        // both the known local lineage and the committed checkpoint.
        if probe > 0
            && remote
                .as_ref()
                .is_some_and(|frame| height(frame) >= height(&local).max(committed))
        {
            break;
        }
        match syncer.get_app_shard_frame(filter, 0).await {
            Ok(Some(frame)) if frame.header.as_ref().is_some_and(|h| h.address == filter) => {
                if remote
                    .as_ref()
                    .is_none_or(|best| height(&frame) > height(best))
                {
                    remote = Some(frame);
                }
            }
            Ok(Some(_)) if probe == 0 && committed == 0 => {
                return Err(QuilError::InvalidArgument(
                    "wrong-shard archive replay tip".into(),
                ));
            }
            Ok(_) => {}
            Err(error) => failure = Some(error),
        }
    }
    if remote.is_none() {
        if let Some(error) = failure.filter(|_| committed <= height(&local)) {
            return Err(error);
        }
    }
    // The GLOBAL frame the frame at `materialized` is anchored to, when known
    // here: a frame no archive serves is sought among the GLOBAL frames after it.
    let anchor_of = |frame: &AppShardFrame| {
        frame
            .header
            .as_ref()
            .map(|header| header.global_frame_number)
    };
    let mut anchor = match height(&local) == materialized {
        true => anchor_of(&local),
        false => known
            .filter(|&(frame, _)| frame == materialized)
            .map(|(_, anchor)| anchor),
    };
    let archive_tip = remote.as_ref().map(height);
    let tip = match remote {
        Some(remote) if height(&remote) >= height(&local) => remote,
        _ => local,
    };
    if tip.header.as_ref().is_none_or(|h| h.address != filter) {
        return Err(QuilError::InvalidArgument(
            "wrong-shard archive replay tip".into(),
        ));
    }
    let tip_height = height(&tip);
    // The GLOBAL frame the archive's tip is anchored to, which bounds the
    // search for a frame below the tip: a frame above it (GLOBAL committed
    // beyond the archive) has no such bound.
    let ceiling = anchor_of(&tip).filter(|&anchor| anchor > 0);
    let target = tip_height.max(committed);
    if archive_tip.unwrap_or(0) < committed && materialized < committed {
        tracing::info!(filter = %hex::encode(filter), materialized, ?archive_tip, committed_tip = committed,
            "archive shard tip is behind GLOBAL's committed session tip; replaying by frame number");
    }
    for _ in 0..32 {
        if materialized >= target {
            break;
        }
        let next = materialized + 1;
        // Frames of this batch rebuilt from carried headers, and the copies used.
        let mut rebuilt = Vec::new();
        let frame = if next == tip_height {
            tip.clone()
        } else {
            match fetch_shard_frame(syncer, filter, next, FRAME_ATTEMPTS).await? {
                Some(frame) => frame,
                None => {
                    let ceiling = ceiling.filter(|_| next < tip_height);
                    let gap = ArchiveGap {
                        frame: next,
                        archive_tip,
                        committed,
                    };
                    let (frame, copy) =
                        rebuild_from_carried_header(syncer, filter, next, anchor, ceiling, verify)
                            .await
                            .map_err(|why| missing_frame(gap, false, why))?;
                    rebuilt.push((next, copy));
                    frame
                }
            }
        };
        // A frame rebuilt from a carried copy that is itself invalid or
        // oversized never reaches replay: its copy is passed over here.
        let reject_rebuilt = |rebuilt: &[(u64, CopyId)], number: u64| {
            for &(rebuilt_number, copy) in rebuilt {
                if rebuilt_number == number {
                    syncer.reject_carried_copy(filter, number, copy);
                }
            }
        };
        if frame
            .header
            .as_ref()
            .is_none_or(|h| h.address != filter || h.frame_number != next)
            || frame.encoded_len() > MAX_REPLAY_FRAME_BYTES
        {
            reject_rebuilt(&rebuilt, next);
            return Err(QuilError::InvalidArgument(
                "invalid or oversized archive replay frame".into(),
            ));
        }
        let certified = |frame: &AppShardFrame| {
            frame
                .header
                .as_ref()
                .and_then(|header| header.public_key_signature_bls48581.as_ref())
                .is_some_and(|signature| !signature.signature.is_empty())
        };
        let mut descendants = Vec::new();
        let mut bytes = frame.encoded_len();
        // GLOBAL's committed tip has no certified frame after it within the
        // target when a seal made it final (a sealed session's last frame):
        // `replay` authenticates it alone, by the digest GLOBAL committed.
        let sealed_tip = next == committed && next == target;
        if !certified(&frame) && !sealed_tip {
            for offset in 1..=crate::frame_validator::MAX_REPLAY_DESCENDANTS {
                let number = next
                    .checked_add(offset as u64)
                    .filter(|number| *number <= target)
                    .ok_or_else(|| {
                        QuilError::ExecutionUnavailable(
                            "archive replay has no certified descendant within its target".into(),
                        )
                    })?;
                let child = if number == tip_height {
                    tip.clone()
                } else {
                    match fetch_shard_frame(syncer, filter, number, FRAME_ATTEMPTS).await? {
                        Some(child) => child,
                        None => {
                            let below = anchor_of(descendants.last().unwrap_or(&frame));
                            let ceiling = ceiling.filter(|_| number < tip_height);
                            let (child, copy) = rebuild_from_carried_header(
                                syncer, filter, number, below, ceiling, verify,
                            )
                            .await
                            .map_err(|why| {
                                let gap = ArchiveGap {
                                    frame: number,
                                    archive_tip,
                                    committed,
                                };
                                missing_frame(gap, true, why)
                            })?;
                            rebuilt.push((number, copy));
                            child
                        }
                    }
                };
                bytes = bytes.saturating_add(child.encoded_len());
                let invalid = child
                    .header
                    .as_ref()
                    .is_none_or(|h| h.address != filter || h.frame_number != number)
                    || child.encoded_len() > MAX_REPLAY_FRAME_BYTES;
                if invalid || bytes > crate::frame_validator::MAX_REPLAY_CHAIN_BYTES {
                    if invalid {
                        reject_rebuilt(&rebuilt, number);
                    }
                    return Err(QuilError::InvalidArgument(
                        "invalid or oversized archive replay chain".into(),
                    ));
                }
                let terminal = certified(&child);
                descendants.push(child);
                if terminal {
                    break;
                }
            }
            if !descendants.last().is_some_and(certified) {
                return Err(QuilError::ExecutionUnavailable(
                    "archive replay certified descendant limit reached".into(),
                ));
            }
        }
        let last = descendants.last().unwrap_or(&frame);
        let (last_number, last_anchor) = (height(last), anchor_of(last));
        let alone = descendants.is_empty();
        let replayed =
            replay(frame, descendants)
                .await
                .and_then(|advanced| match advanced < next {
                    true => Err(QuilError::ExecutionUnavailable(
                        "archive replay did not materialize its frame".into(),
                    )),
                    false => Ok(advanced),
                });
        let advanced = match replayed {
            Ok(advanced) => advanced,
            Err(error) => {
                // Only a refusal rejects a copy: GLOBAL or registrations
                // unavailable, or an archive read failing, says nothing of it.
                // A batch of several frames rejects the copy of the frame the
                // refusal names; a refusal naming none rejects only a frame
                // replayed alone.
                if refuses_frame(&error) {
                    for &(number, copy) in &rebuilt {
                        if (alone && number == next) || names_frame(&error, number) {
                            syncer.reject_carried_copy(filter, number, copy);
                        }
                    }
                }
                return Err(error);
            }
        };
        anchor = if advanced == last_number {
            last_anchor
        } else {
            None
        };
        materialized = advanced;
        // Each frame rebuilt from a carried header costs a search of GLOBAL
        // frames: past the budget the batch ends with what it materialized,
        // so a run of such frames hands the recovery turn back in time; the
        // next batch goes on from this frame's anchor.
        if !rebuilt.is_empty() && batch_started.elapsed() >= REBUILT_BATCH_BUDGET {
            tracing::info!(filter = %hex::encode(filter), materialized, target, elapsed_secs = batch_started.elapsed().as_secs(),
                "archive replay batch ends early after rebuilding frames from their carried headers; the next recovery turn goes on");
            break;
        }
    }
    Ok((
        ShardReplay {
            materialized,
            archive_tip,
            target,
        },
        anchor.map(|anchor| (materialized, anchor)),
    ))
}

/// The base state of a session based at frame 0 of which GLOBAL executed no
/// frame, when the archive's latest frame (`refused`) failed validation: it
/// belongs to a session GLOBAL ended without executing it, and the archive's
/// current subtree may include its writes. Sync only state something
/// certifies: the origins' sealed roots, else the pre-state roots `refused`
/// attests as the certified first frame of a session ended at this base
/// (`attest_base`). Otherwise refuse; never inherit the subtree unpinned. A
/// shard whose sessions all ended at frame 0 kept every member unstaged and
/// its committee nullifying every view (…a1a80, generation 13, 2026-10-22).
async fn sync_unexecuted_base<A, AFut>(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    origin_anchors: &[(Vec<u8>, [[u8; 32]; 4])],
    refused: AppShardFrame,
    attest_base: &mut A,
) -> Result<ShardSyncResult>
where
    A: FnMut(AppShardFrame) -> AFut,
    AFut: std::future::Future<Output = Result<Option<Vec<Vec<u8>>>>>,
{
    use crate::worker_execution::recovery_phase;
    let number = refused
        .header
        .as_ref()
        .map_or(0, |header| header.frame_number);
    if !origin_anchors.is_empty() {
        recovery_phase("installing_leaves");
        for (source, roots) in origin_anchors {
            let pinned: Vec<Vec<u8>> = roots.iter().map(|root| root.to_vec()).collect();
            if !syncer.sync_shard_tree(source, &pinned).await? {
                return Ok(ShardSyncResult::NotReady(
                    "the archive does not hold the session's certified base state, or its roots differ",
                ));
            }
        }
        tracing::info!(filter = %hex::encode(filter), refused_frame = number, origins = origin_anchors.len(),
            "archive's latest shard frame refused; bootstrapped from the origins' sealed state at the session base");
        return Ok(ShardSyncResult::Inherited { pinned: true });
    }
    let Some(roots) = attest_base(refused).await? else {
        return Ok(ShardSyncResult::NotReady(
            "the archive checkpoint failed validation, and nothing certifies the session's base state",
        ));
    };
    recovery_phase("installing_leaves");
    if !syncer.sync_shard_tree(filter, &roots).await? {
        return Ok(ShardSyncResult::NotReady(
            "the archive does not hold the session's attested base state, or its roots differ",
        ));
    }
    tracing::info!(filter = %hex::encode(filter), refused_frame = number,
        "archive's latest shard frame refused; bootstrapped from the base state its certified first frame attests");
    Ok(ShardSyncResult::Inherited { pinned: true })
}

/// An anchor and its predecessor, both accepted by `validate`; `None` when
/// refused. A malformed or wrong-shard anchor, or one that is not frame
/// `expected`, is an error.
async fn authenticated_anchor<F, Fut>(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    anchor: AppShardFrame,
    expected: Option<u64>,
    validate: &mut F,
) -> Result<Option<(AppShardFrame, Option<AppShardFrame>)>>
where
    F: FnMut(AppShardFrame, Option<AppShardFrame>) -> Fut,
    Fut: std::future::Future<Output = Result<bool>>,
{
    use quil_types::error::QuilError;
    let header = anchor
        .header
        .as_ref()
        .ok_or_else(|| QuilError::InvalidArgument("archive anchor has no header".into()))?;
    if header.address != filter
        || header.frame_number == 0
        || expected.is_some_and(|number| header.frame_number != number)
        || header.state_roots.len() != 4
        || header.state_roots.iter().any(|root| root.len() != 32)
    {
        return Err(QuilError::InvalidArgument(
            "malformed or wrong-shard archive anchor".into(),
        ));
    }
    let predecessor = if header.frame_number > 1 {
        syncer
            .get_app_shard_frame(filter, header.frame_number - 1)
            .await?
    } else {
        None
    };
    Ok(validate(anchor.clone(), predecessor.clone())
        .await?
        .then_some((anchor, predecessor)))
}

/// [`sync_shard_from_latest_attested`] for a session whose base needs no
/// attestation.
#[cfg(test)]
pub(crate) async fn sync_shard_from_latest<F, Fut>(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    local: Option<AppShardFrame>,
    origin_anchors: &[(Vec<u8>, [[u8; 32]; 4])],
    committed: Option<u64>,
    validate: F,
) -> Result<ShardSyncResult>
where
    F: FnMut(AppShardFrame, Option<AppShardFrame>) -> Fut,
    Fut: std::future::Future<Output = Result<bool>>,
{
    sync_shard_from_latest_attested(
        syncer,
        filter,
        local,
        origin_anchors,
        committed,
        validate,
        |_| async { Ok(None) },
    )
    .await
}

/// A stale worker must discover the archive tip even when it has a local
/// clock head. Authenticate the selected chain before installing any leaves.
/// The validator runs on the engine that owns the worker's committee view.
///
/// `committed`: the frame GLOBAL has executed the shard's current session
/// through, or its base (`app_handoff::committed_tip`). When the archive's
/// latest frame is refused, the anchor falls back to that frame, and
/// `attest_base` gives the base-state
/// roots a refused archive tip attests (see [`sync_unexecuted_base`]).
pub(crate) async fn sync_shard_from_latest_attested<F, Fut, A, AFut>(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    local: Option<AppShardFrame>,
    origin_anchors: &[(Vec<u8>, [[u8; 32]; 4])],
    committed: Option<u64>,
    mut validate: F,
    mut attest_base: A,
) -> Result<ShardSyncResult>
where
    F: FnMut(AppShardFrame, Option<AppShardFrame>) -> Fut,
    Fut: std::future::Future<Output = Result<bool>>,
    A: FnMut(AppShardFrame) -> AFut,
    AFut: std::future::Future<Output = Result<Option<Vec<Vec<u8>>>>>,
{
    use crate::worker_execution::recovery_phase;
    let remote = syncer.get_app_shard_frame(filter, 0).await?;
    let height = |frame: &AppShardFrame| frame.header.as_ref().map_or(0, |h| h.frame_number);
    let anchor = match (local, remote) {
        (Some(local), Some(remote)) if height(&local) > height(&remote) => Some(local),
        (_, Some(remote)) => Some(remote),
        (local, None) => local,
    };
    let Some(anchor) = anchor else {
        // A new child without a certified frame of its own holds its origins'
        // state. Sync each origin's range pinned to its sealed roots, which the
        // sync verifies; the origins partition the child's range. Without
        // certified origins, or when no archive still resolves them (retention),
        // inherit the covered archive subtree unpinned, as before.
        recovery_phase("installing_leaves");
        if !origin_anchors.is_empty() {
            let mut pinned = true;
            for (source, roots) in origin_anchors {
                let pinned_roots: Vec<Vec<u8>> = roots.iter().map(|root| root.to_vec()).collect();
                let failure = match syncer.sync_shard_tree(source, &pinned_roots).await {
                    Ok(true) => continue,
                    Ok(false) => {
                        "the archive does not hold it or the synced roots differ".to_string()
                    }
                    Err(error) if crate::worker_execution::turn_spent(&error) => return Err(error),
                    Err(error) => error.to_string(),
                };
                tracing::warn!(filter = %hex::encode(filter), source = %hex::encode(source),
                    sealed_roots = ?roots.iter().map(hex::encode).collect::<Vec<_>>(), %failure,
                    "origin's sealed state could not be synced");
                pinned = false;
                break;
            }
            if pinned {
                tracing::info!(filter = %hex::encode(filter), origins = origin_anchors.len(),
                    "shard bootstrapped from its origins' sealed state");
                return Ok(ShardSyncResult::Inherited { pinned: true });
            }
            // A same-filter origin's sealed roots are what this shard's
            // successor requires at startup (`successor_state_matches`): an
            // unpinned copy is refused there unless it equals them, and the
            // worker installed it, reported success and was refused again
            // every few seconds. Wait for an archive that holds the state.
            if origin_anchors
                .iter()
                .any(|(source, _)| source.as_slice() == filter)
            {
                tracing::warn!(filter = %hex::encode(filter),
                    "the predecessor's sealed state is not available from the archive; not inheriting unpinned state its successor would refuse");
                return Ok(ShardSyncResult::NotReady(
                    "the predecessor's sealed state is not available from the archive",
                ));
            }
            tracing::warn!(filter = %hex::encode(filter),
                "origins' sealed state is not available from the archive; inheriting the covered subtree unpinned");
        } else {
            tracing::info!(filter = %hex::encode(filter),
                "no certified origin state for this shard; inheriting the covered subtree unpinned");
        }
        return Ok(if syncer.sync_shard_tree(filter, &[]).await? {
            ShardSyncResult::Inherited { pinned: false }
        } else {
            ShardSyncResult::NotReady("the archive could not supply the covered subtree")
        });
    };
    let latest = height(&anchor);
    let refused = (committed == Some(0)).then(|| anchor.clone());
    let (anchor, predecessor) = match authenticated_anchor(
        syncer,
        filter,
        anchor,
        None,
        &mut validate,
    )
    .await?
    {
        Some(pair) => pair,
        // The latest frame an archive holds can lie above the checkpoint GLOBAL
        // fenced the shard's last session at: frames its closing committee
        // finalized that GLOBAL never executed. Validation refuses every frame
        // past a terminal checkpoint, and archives serve them as the latest
        // until a successor produces past them. A member holding none of the
        // shard's data never bootstrapped, so never started, and a successor
        // that needed such members for quorum never produced (2026-10-13). The
        // frame GLOBAL committed is the successor's base and authenticated.
        None => {
            // GLOBAL executed no frame of a session based at frame 0, which
            // has no frame to anchor at.
            if let Some(refused) = refused {
                return sync_unexecuted_base(
                    syncer,
                    filter,
                    origin_anchors,
                    refused,
                    &mut attest_base,
                )
                .await;
            }
            let Some(committed) = committed.filter(|&number| number > 0 && number < latest) else {
                return Ok(ShardSyncResult::NotReady(
                    "the archive checkpoint failed validation",
                ));
            };
            let fallback = match syncer.get_app_shard_frame(filter, committed).await? {
                Some(frame) => {
                    authenticated_anchor(syncer, filter, frame, Some(committed), &mut validate)
                        .await?
                }
                None => None,
            };
            let Some(pair) = fallback else {
                return Ok(ShardSyncResult::NotReady(
                    "the archive checkpoint failed validation",
                ));
            };
            tracing::info!(filter = %hex::encode(filter), latest, committed,
                "archive's latest shard frame refused; bootstrapping from the frame GLOBAL committed");
            pair
        }
    };
    let expected_roots = anchor
        .header
        .as_ref()
        .map(|header| header.state_roots.clone())
        .unwrap_or_default();
    recovery_phase("installing_leaves");
    Ok(if syncer.sync_shard_tree(filter, &expected_roots).await? {
        ShardSyncResult::Anchored {
            anchor,
            predecessor,
        }
    } else {
        ShardSyncResult::NotReady(
            "the archive does not hold the checkpoint's state, or its roots differ",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct Target {
        calls: Arc<Mutex<Vec<String>>>,
        cursor: std::sync::atomic::AtomicU64,
        valid: bool,
        install_ok: bool,
        /// The successor-blocked flag, cleared once frame `unblock_at` replays.
        blocked: AtomicBool,
        unblock_at: u64,
    }
    #[async_trait]
    impl ShardRecoveryTarget for Target {
        fn materialized(&self) -> u64 {
            self.cursor.load(std::sync::atomic::Ordering::SeqCst)
        }
        async fn replay(
            &self,
            frame: AppShardFrame,
            _descendants: Vec<AppShardFrame>,
        ) -> Result<u64> {
            let number = frame.header.unwrap().frame_number;
            assert_eq!(number, self.materialized() + 1);
            self.calls.lock().unwrap().push(format!("replay {number}"));
            self.cursor
                .store(number, std::sync::atomic::Ordering::SeqCst);
            if number == self.unblock_at {
                self.blocked
                    .store(false, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(number)
        }
        async fn validate(
            &self,
            anchor: AppShardFrame,
            predecessor: Option<AppShardFrame>,
        ) -> Result<bool> {
            let number = anchor.header.unwrap().frame_number;
            assert_eq!(
                predecessor.unwrap().header.unwrap().frame_number,
                number - 1
            );
            self.calls
                .lock()
                .unwrap()
                .push(format!("validate {number}"));
            Ok(self.valid)
        }
        async fn install(&self, anchor: AppShardFrame, _: Option<AppShardFrame>) -> Result<()> {
            let number = anchor.header.unwrap().frame_number;
            self.calls.lock().unwrap().push(format!("install {number}"));
            if !self.install_ok {
                return Err(quil_types::error::QuilError::ExecutionUnavailable(
                    "actor rejected checkpoint".into(),
                ));
            }
            self.cursor
                .store(number, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        fn inherited(&self) {
            panic!("a certified archive tip must never use unanchored inheritance")
        }
    }

    #[tokio::test]
    async fn headless_worker_recovers_from_archive_and_waits_for_authenticated_installation() {
        for (valid, install_ok) in [(true, true), (false, true), (true, false)] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let archive = Archive {
                latest: Some(frame(500)),
                calls: calls.clone(),
            };
            let target = Target {
                calls: calls.clone(),
                cursor: 0.into(),
                valid,
                install_ok,
                blocked: false.into(),
                unblock_at: 0,
            };
            let result =
                recover_shard_from_latest(&archive, &[5; 32], None, &target, &[], None).await;
            let mut expected = vec!["fetch 0", "fetch 499", "validate 500"];
            if valid {
                expected.extend(["sync 244", "install 500"]);
            }
            assert_eq!(*calls.lock().unwrap(), expected);
            if !valid {
                assert_eq!(
                    result.unwrap(),
                    ShardRecoveryProgress::NotReady("the archive checkpoint failed validation")
                );
            } else if !install_ok {
                assert!(result.is_err());
            } else {
                assert_eq!(
                    result.unwrap(),
                    ShardRecoveryProgress::Anchored { frame: 500 }
                );
            }
            assert_eq!(
                target.materialized(),
                if valid && install_ok { 500 } else { 0 }
            );
        }
    }

    #[tokio::test]
    async fn existing_worker_lineage_replays_instead_of_replacing_its_tree() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(500)),
            calls: calls.clone(),
        };
        let target = Target {
            calls: calls.clone(),
            cursor: 129.into(),
            valid: false,
            install_ok: false,
            blocked: false.into(),
            unblock_at: 0,
        };
        let result =
            recover_shard_from_latest(&archive, &[5; 32], Some(frame(130)), &target, &[], None)
                .await
                .unwrap();
        let ShardRecoveryProgress::Replayed {
            materialized,
            archive_tip,
            committed_tip,
            turn,
        } = result
        else {
            panic!("expected a replay")
        };
        assert_eq!(
            (
                materialized,
                archive_tip,
                committed_tip,
                turn.frames,
                turn.batches
            ),
            (161, Some(500), None, 32, 1)
        );
        let calls = calls.lock().unwrap();
        assert_eq!(
            calls.iter().filter(|s| s.starts_with("replay ")).count(),
            32
        );
        assert!(!calls
            .iter()
            .any(|s| s.starts_with("sync ") || s.starts_with("install ")));
    }

    /// A blocked successor keeps its turn: it replays batch after batch up to
    /// its target, while any other recovery replays one batch per turn.
    #[tokio::test]
    async fn a_blocked_successor_replays_to_its_target_in_one_turn() {
        for (blocked, expected, batches) in
            [(Some(true), 200, 3), (Some(false), 161, 1), (None, 161, 1)]
        {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let archive = Archive {
                latest: Some(frame(200)),
                calls: calls.clone(),
            };
            let target = Target {
                calls: calls.clone(),
                cursor: 129.into(),
                valid: false,
                install_ok: false,
                blocked: blocked.unwrap_or(false).into(),
                unblock_at: 0,
            };
            let result = recover_shard_from_latest(
                &archive,
                &[5; 32],
                Some(frame(130)),
                &target,
                blocked.map(|_| &target.blocked).as_slice(),
                None,
            )
            .await
            .unwrap();
            let ShardRecoveryProgress::Replayed {
                materialized,
                archive_tip,
                turn,
                ..
            } = result
            else {
                panic!("expected a replay")
            };
            assert_eq!(
                (materialized, archive_tip, turn.frames, turn.batches),
                (expected, Some(200), expected - 129, batches),
                "{blocked:?}"
            );
            let calls = calls.lock().unwrap();
            let replayed: Vec<_> = calls
                .iter()
                .filter(|call| call.starts_with("replay "))
                .cloned()
                .collect();
            assert_eq!(
                replayed,
                (130..=expected)
                    .map(|n| format!("replay {n}"))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                calls.iter().filter(|call| *call == "fetch 0").count(),
                batches as usize,
                "one tip probe per batch"
            );
        }
    }

    /// The turn ends with the batch in which the successor stopped being
    /// blocked.
    #[tokio::test]
    async fn a_successor_no_longer_blocked_hands_its_turn_back_after_the_batch() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(600)),
            calls: calls.clone(),
        };
        let target = Target {
            calls: calls.clone(),
            cursor: 129.into(),
            valid: false,
            install_ok: false,
            blocked: true.into(),
            unblock_at: 170,
        };
        let result = recover_shard_from_latest(
            &archive,
            &[5; 32],
            Some(frame(130)),
            &target,
            &[&target.blocked],
            None,
        )
        .await
        .unwrap();
        let ShardRecoveryProgress::Replayed {
            materialized, turn, ..
        } = result
        else {
            panic!("expected a replay")
        };
        assert_eq!((materialized, turn.frames, turn.batches), (193, 64, 2));
    }

    /// A failed batch ends a blocked successor's turn with the failure; the
    /// frames replayed before it stay materialized.
    #[tokio::test]
    async fn a_blocked_successors_turn_ends_at_a_failed_batch() {
        let archive = ChainArchive {
            missing: Some(170),
            wrong_shard: false,
            unsigned_end: 0,
        };
        let target = Target {
            calls: Arc::new(Mutex::new(Vec::new())),
            cursor: 130.into(),
            valid: false,
            install_ok: false,
            blocked: true.into(),
            unblock_at: 0,
        };
        let error = recover_shard_from_latest(
            &archive,
            &[5; 32],
            Some(frame(130)),
            &target,
            &[&target.blocked],
            None,
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("missing shard frame 170"),
            "{error}"
        );
        assert_eq!(target.materialized(), 169);
    }

    /// A voting member trailing its committee keeps its turn for batch after
    /// batch while it trails, and hands it back after the batch in which it
    /// caught up; another replay takes one batch per turn.
    #[tokio::test]
    async fn a_lagging_voter_replays_batches_in_one_turn_while_it_trails() {
        use crate::recovery_turns::RecoveryTurns;
        /// Clears the lagging-voter flag once frame `caught_up_at` replays,
        /// as the engine does once the member reaches its committed tip.
        struct CatchingUp {
            inner: Target,
            lagging: Arc<AtomicBool>,
            caught_up_at: u64,
        }
        #[async_trait]
        impl ShardRecoveryTarget for CatchingUp {
            fn materialized(&self) -> u64 {
                self.inner.materialized()
            }
            async fn replay(
                &self,
                frame: AppShardFrame,
                descendants: Vec<AppShardFrame>,
            ) -> Result<u64> {
                let number = self.inner.replay(frame, descendants).await?;
                if number == self.caught_up_at {
                    self.lagging.store(false, Ordering::SeqCst);
                }
                Ok(number)
            }
            async fn validate(
                &self,
                anchor: AppShardFrame,
                predecessor: Option<AppShardFrame>,
            ) -> Result<bool> {
                self.inner.validate(anchor, predecessor).await
            }
            async fn install(
                &self,
                anchor: AppShardFrame,
                predecessor: Option<AppShardFrame>,
            ) -> Result<()> {
                self.inner.install(anchor, predecessor).await
            }
            fn inherited(&self) {
                self.inner.inherited()
            }
        }
        for (lagging, expected, batches) in [(true, 193, 2), (false, 161, 1)] {
            let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(1)));
            let calls = Arc::new(Mutex::new(Vec::new()));
            let archive = Archive {
                latest: Some(frame(600)),
                calls: calls.clone(),
            };
            let execution = crate::worker_execution::SharedWorkerExecution::default();
            execution.set_lagging_voter(lagging);
            let target = CatchingUp {
                inner: Target {
                    calls,
                    cursor: 129.into(),
                    valid: false,
                    install_ok: false,
                    blocked: false.into(),
                    unblock_at: 0,
                },
                lagging: execution.lagging_voter_flag(),
                caught_up_at: 170,
            };
            let result = recover_in_turns(
                turns,
                &archive,
                &[5; 32],
                1,
                &target,
                &execution,
                || Ok(Some(frame(130))),
                || false,
            )
            .await
            .unwrap();
            let ShardRecoveryProgress::Replayed {
                materialized, turn, ..
            } = result
            else {
                panic!("expected a replay")
            };
            assert_eq!(
                (materialized, turn.frames, turn.batches, turn.behind),
                (expected, expected - 129, batches, true),
                "lagging {lagging}"
            );
        }
    }

    /// A replay whose turn ends behind its target queues again in its first
    /// place, before a replay that queued after its first arrival, rather
    /// than behind it; a replay that reaches its target keeps no place.
    #[tokio::test]
    async fn a_replay_that_ends_behind_keeps_its_place() {
        use crate::recovery_turns::{Claim, RecoveryKind, RecoveryTurns};
        let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(1)));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(600)),
            calls: calls.clone(),
        };
        let target = Target {
            calls: calls.clone(),
            cursor: 129.into(),
            valid: false,
            install_ok: false,
            blocked: false.into(),
            unblock_at: 0,
        };
        let execution = crate::worker_execution::SharedWorkerExecution::default();
        let lineage = || Ok(Some(frame(130)));
        let first = recover_in_turns(
            turns,
            &archive,
            &[5; 32],
            1,
            &target,
            &execution,
            lineage,
            || false,
        )
        .await
        .unwrap();
        assert!(
            matches!(
                first,
                ShardRecoveryProgress::Replayed {
                    materialized: 161,
                    ..
                }
            ),
            "{first:?}"
        );
        // Another worker holds the turn, a replay queues behind it, and then
        // the first worker's next recovery.
        let claim = |core: u32, kind| Claim {
            core,
            filter: vec![core as u8; 32],
            kind,
            execution: Default::default(),
            ticket: None,
        };
        let held = turns.acquire(claim(9, RecoveryKind::Install)).await;
        let other = {
            let calls = calls.clone();
            tokio::spawn(async move {
                let _turn = turns.acquire(claim(2, RecoveryKind::Replay)).await;
                calls.lock().unwrap().push("other granted".to_string());
            })
        };
        tokio::task::yield_now().await;
        calls.lock().unwrap().clear();
        let (again, ()) = tokio::join!(
            recover_in_turns(
                turns,
                &archive,
                &[5; 32],
                1,
                &target,
                &execution,
                lineage,
                || false
            ),
            async {
                for _ in 0..3 {
                    tokio::task::yield_now().await;
                }
                drop(held);
            },
        );
        other.await.unwrap();
        assert!(matches!(
            again.unwrap(),
            ShardRecoveryProgress::Replayed {
                materialized: 193,
                ..
            }
        ));
        let calls = calls.lock().unwrap().clone();
        assert_eq!(
            calls.first().map(String::as_str),
            Some("fetch 0"),
            "{calls:?}"
        );
        assert_eq!(
            calls.last().map(String::as_str),
            Some("other granted"),
            "{calls:?}"
        );
        assert!(
            execution.take_replay_ticket(&[5; 32]).is_some(),
            "still behind, it keeps its place"
        );
        // A replay that reaches its target keeps none.
        let archive = Archive {
            latest: Some(frame(200)),
            calls: Arc::default(),
        };
        let done = recover_in_turns(
            turns,
            &archive,
            &[5; 32],
            1,
            &target,
            &execution,
            || Ok(Some(frame(193))),
            || false,
        )
        .await
        .unwrap();
        assert!(
            matches!(
                done,
                ShardRecoveryProgress::Replayed {
                    materialized: 200,
                    ..
                }
            ),
            "{done:?}"
        );
        assert_eq!(execution.take_replay_ticket(&[5; 32]), None);
    }

    /// A recovery waiting for its turn withdraws once its worker's engine
    /// stops, rather than taking the turn to fail: an operator's node had
    /// two workers wait about 20,000 s for shards whose engines had stopped,
    /// then fail within seconds of their turns. It leaves the queue, reads
    /// no archive, takes no turn and keeps no place in its engine's record.
    #[tokio::test(start_paused = true)]
    async fn a_queued_recovery_withdraws_when_its_engine_stops() {
        use crate::recovery_turns::{Claim, RecoveryKind, RecoveryTurns};
        use std::time::Duration;
        struct Stopping {
            inner: Target,
            running: AtomicBool,
        }
        #[async_trait]
        impl ShardRecoveryTarget for Stopping {
            fn materialized(&self) -> u64 {
                self.inner.materialized()
            }
            async fn replay(
                &self,
                frame: AppShardFrame,
                descendants: Vec<AppShardFrame>,
            ) -> Result<u64> {
                self.inner.replay(frame, descendants).await
            }
            async fn validate(
                &self,
                anchor: AppShardFrame,
                predecessor: Option<AppShardFrame>,
            ) -> Result<bool> {
                self.inner.validate(anchor, predecessor).await
            }
            async fn install(
                &self,
                anchor: AppShardFrame,
                predecessor: Option<AppShardFrame>,
            ) -> Result<()> {
                self.inner.install(anchor, predecessor).await
            }
            fn inherited(&self) {
                self.inner.inherited()
            }
            fn running(&self) -> bool {
                self.running.load(Ordering::SeqCst)
            }
        }
        let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(1)));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(600)),
            calls: calls.clone(),
        };
        let target = Stopping {
            inner: Target {
                calls: calls.clone(),
                cursor: 129.into(),
                valid: false,
                install_ok: false,
                blocked: false.into(),
                unblock_at: 0,
            },
            running: true.into(),
        };
        let execution = crate::worker_execution::SharedWorkerExecution::default();
        execution.keep_replay_ticket(&[5; 32], 0);
        let claim = |core: u32| Claim {
            core,
            filter: vec![core as u8; 32],
            kind: RecoveryKind::Install,
            execution: Default::default(),
            ticket: None,
        };
        let held = turns.acquire(claim(9)).await;
        let (result, ()) = tokio::join!(
            tokio::time::timeout(
                Duration::from_secs(3600),
                recover_in_turns(
                    turns,
                    &archive,
                    &[5; 32],
                    1,
                    &target,
                    &execution,
                    || Ok(Some(frame(130))),
                    || false
                )
            ),
            async {
                tokio::time::sleep(Duration::from_secs(600)).await;
                assert_eq!(turns.waiting(), 1, "queued behind the held turn");
                target.running.store(false, Ordering::SeqCst);
            },
        );
        let result = result
            .expect("withdrawn, not left waiting for the turn")
            .unwrap();
        assert_eq!(
            result,
            ShardRecoveryProgress::Deferred(ENGINE_STOPPED_WHILE_QUEUED)
        );
        assert_eq!(turns.waiting(), 0, "its claim left the queue");
        assert!(calls.lock().unwrap().is_empty(), "no archive read");
        assert!(execution.turn().since.is_none(), "no turn taken");
        assert_eq!(
            execution.take_replay_ticket(&[5; 32]),
            None,
            "no place kept"
        );
        // The next waiter takes the released turn.
        let next = tokio::spawn(async move { drop(turns.acquire(claim(2)).await) });
        tokio::task::yield_now().await;
        drop(held);
        tokio::time::timeout(Duration::from_secs(5), next)
            .await
            .expect("the turn passed on")
            .unwrap();
    }

    /// An engine that restarts on its core and shard while its recovery
    /// waits for a turn (at its activation, around a GLOBAL sync, at an
    /// operator's action) queues again in the place its withdrawn claim
    /// held, before a claim that arrived meanwhile: on an operator's node
    /// the engine of the one seat it kept restarted seven times while its
    /// recovery waited, and five claims, withdrawn after 20 to 2,671 s,
    /// each queued again behind every other.
    #[tokio::test(start_paused = true)]
    async fn reproduces_a_restarted_engine_losing_its_recovery_place() {
        use crate::recovery_turns::{Claim, RecoveryKind, RecoveryTurns};
        use crate::worker_execution::SharedWorkerExecution;
        use std::time::Duration;
        struct Engine {
            inner: Target,
            running: AtomicBool,
        }
        #[async_trait]
        impl ShardRecoveryTarget for Engine {
            fn materialized(&self) -> u64 {
                self.inner.materialized()
            }
            async fn replay(
                &self,
                frame: AppShardFrame,
                descendants: Vec<AppShardFrame>,
            ) -> Result<u64> {
                self.inner.replay(frame, descendants).await
            }
            async fn validate(
                &self,
                anchor: AppShardFrame,
                predecessor: Option<AppShardFrame>,
            ) -> Result<bool> {
                self.inner.validate(anchor, predecessor).await
            }
            async fn install(
                &self,
                anchor: AppShardFrame,
                predecessor: Option<AppShardFrame>,
            ) -> Result<()> {
                self.inner.install(anchor, predecessor).await
            }
            fn inherited(&self) {
                self.inner.inherited()
            }
            fn running(&self) -> bool {
                self.running.load(Ordering::SeqCst)
            }
        }
        let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(1)));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(600)),
            calls: calls.clone(),
        };
        let engine = || Engine {
            inner: Target {
                calls: calls.clone(),
                cursor: 129.into(),
                valid: false,
                install_ok: false,
                blocked: false.into(),
                unblock_at: 0,
            },
            running: true.into(),
        };
        let (stopping, restarted) = (engine(), engine());
        let (first_record, second_record) = (
            SharedWorkerExecution::default(),
            SharedWorkerExecution::default(),
        );
        let lineage = || Ok(Some(frame(130)));
        let claim = |core: u32| Claim {
            core,
            filter: vec![core as u8; 32],
            kind: RecoveryKind::Replay,
            execution: Default::default(),
            ticket: None,
        };
        let held = turns.acquire(claim(9)).await;
        // The worker on core 1 queues for its shard, another worker's replay
        // behind it; then core 1's engine stops.
        let (withdrawn, other) = tokio::join!(
            recover_in_turns(
                turns,
                &archive,
                &[5; 32],
                1,
                &stopping,
                &first_record,
                lineage,
                || false
            ),
            async {
                tokio::task::yield_now().await;
                let (calls, next) = (calls.clone(), claim(2));
                let other = tokio::spawn(async move {
                    let _turn = turns.acquire(next).await;
                    calls.lock().unwrap().push("other granted".to_string());
                });
                tokio::time::sleep(Duration::from_secs(60)).await;
                assert_eq!(turns.waiting(), 2, "both queued behind the held turn");
                stopping.running.store(false, Ordering::SeqCst);
                other
            },
        );
        assert_eq!(
            withdrawn.unwrap(),
            ShardRecoveryProgress::Deferred(ENGINE_STOPPED_WHILE_QUEUED)
        );
        assert_eq!(turns.waiting(), 1, "its claim left the queue");
        // Its engine restarts on the core and shard, with a new record, and
        // its recovery queues again; then the held turn ends.
        let (again, ()) = tokio::join!(
            recover_in_turns(
                turns,
                &archive,
                &[5; 32],
                1,
                &restarted,
                &second_record,
                lineage,
                || false
            ),
            async {
                for _ in 0..3 {
                    tokio::task::yield_now().await;
                }
                assert_eq!(turns.waiting(), 2, "queued again");
                drop(held);
            },
        );
        other.await.unwrap();
        assert!(
            matches!(again, Ok(ShardRecoveryProgress::Replayed { .. })),
            "{again:?}"
        );
        let calls = calls.lock().unwrap().clone();
        assert_eq!(
            calls.first().map(String::as_str),
            Some("fetch 0"),
            "the restarted engine's recovery takes the next turn: {calls:?}"
        );
        assert_eq!(
            calls.last().map(String::as_str),
            Some("other granted"),
            "{calls:?}"
        );
    }

    /// A recovery for a seat this node gives up reads no archive: it asks
    /// before it queues, and again once its turn is granted, which it then
    /// hands on unused (an operator's node installed 1.26M leaves per shard
    /// of seats its planner left).
    #[tokio::test]
    async fn a_recovery_for_a_given_up_seat_reads_no_archive() {
        use crate::recovery_turns::{Claim, RecoveryKind, RecoveryTurns};
        use std::time::Duration;
        let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(1)));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(600)),
            calls: calls.clone(),
        };
        let target = Target {
            calls: calls.clone(),
            cursor: 129.into(),
            valid: false,
            install_ok: false,
            blocked: false.into(),
            unblock_at: 0,
        };
        let execution = crate::worker_execution::SharedWorkerExecution::default();
        let lineage = || Ok(Some(frame(130)));
        execution.keep_replay_ticket(&[5; 32], 7);
        let result = recover_in_turns(
            turns,
            &archive,
            &[5; 32],
            1,
            &target,
            &execution,
            lineage,
            || true,
        )
        .await
        .unwrap();
        assert_eq!(result, ShardRecoveryProgress::Deferred(SEAT_GIVEN_UP));
        assert_eq!(turns.waiting(), 0, "it never queued");
        assert_eq!(
            execution.take_replay_ticket(&[5; 32]),
            Some(7),
            "its place is kept for when it resumes"
        );
        // Given up while it waited for its turn.
        let claim = |core: u32| Claim {
            core,
            filter: vec![core as u8; 32],
            kind: RecoveryKind::Install,
            execution: Default::default(),
            ticket: None,
        };
        let held = turns.acquire(claim(9)).await;
        let given_up = AtomicBool::new(false);
        let (result, ()) = tokio::join!(
            recover_in_turns(
                turns,
                &archive,
                &[5; 32],
                1,
                &target,
                &execution,
                lineage,
                || given_up.load(Ordering::SeqCst)
            ),
            async {
                for _ in 0..3 {
                    tokio::task::yield_now().await;
                }
                assert_eq!(turns.waiting(), 1, "queued behind the held turn");
                given_up.store(true, Ordering::SeqCst);
                drop(held);
            },
        );
        assert_eq!(
            result.unwrap(),
            ShardRecoveryProgress::Deferred(SEAT_GIVEN_UP)
        );
        assert!(calls.lock().unwrap().is_empty(), "no archive read");
        assert!(
            execution.take_replay_ticket(&[5; 32]).is_some(),
            "the granted place is kept"
        );
        drop(
            tokio::time::timeout(Duration::from_secs(5), turns.acquire(claim(2)))
                .await
                .expect("the turn passed on"),
        );
    }

    /// An engine handle's stop resolves once its engine is cancelled or
    /// its message receiver is gone, and not while it runs.
    #[tokio::test]
    async fn an_engine_handle_resolves_its_stop() {
        use std::time::Duration;
        let (handle, receiver) = crate::app_engine::AppEngineHandle::for_test(vec![5; 32]);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                ShardRecoveryTarget::stopped(&handle)
            )
            .await
            .is_err(),
            "a running engine has not stopped"
        );
        drop(receiver);
        tokio::time::timeout(
            Duration::from_secs(5),
            ShardRecoveryTarget::stopped(&handle),
        )
        .await
        .expect("its receiver went with the engine");
        let (handle, _receiver) = crate::app_engine::AppEngineHandle::for_test(vec![5; 32]);
        handle.stop();
        tokio::time::timeout(
            Duration::from_secs(5),
            ShardRecoveryTarget::stopped(&handle),
        )
        .await
        .expect("cancelled");
    }

    struct Archive {
        latest: Option<AppShardFrame>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    /// A certified frame (its certificate is not checked here).
    fn frame(number: u64) -> AppShardFrame {
        AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                address: vec![5; 32],
                frame_number: number,
                state_roots: vec![vec![number as u8; 32]; 4],
                public_key_signature_bls48581: Some(
                    quil_types::proto::keys::Bls48581AggregateSignature {
                        signature: vec![1],
                        ..Default::default()
                    },
                ),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[async_trait]
    impl ProverTreeSyncer for Archive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
        async fn get_app_shard_frame(
            &self,
            _: &[u8],
            number: u64,
        ) -> Result<Option<AppShardFrame>> {
            self.calls.lock().unwrap().push(format!("fetch {number}"));
            Ok(if number == 0 {
                self.latest.clone()
            } else {
                Some(frame(number))
            })
        }
        async fn sync_shard_tree(&self, _: &[u8], roots: &[Vec<u8>]) -> Result<bool> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("sync {}", roots[0][0]));
            Ok(true)
        }
    }

    #[tokio::test]
    async fn stale_local_head_uses_newer_certified_archive_anchor_before_any_tree_write() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(600)),
            calls: calls.clone(),
        };
        let validate_calls = calls.clone();
        let result = sync_shard_from_latest(
            &archive,
            &[5; 32],
            Some(frame(130)),
            &[],
            None,
            move |anchor, predecessor| {
                assert_eq!(anchor.header.unwrap().frame_number, 600);
                assert_eq!(predecessor.unwrap().header.unwrap().frame_number, 599);
                validate_calls.lock().unwrap().push("validate 600".into());
                async { Ok(true) }
            },
        )
        .await
        .unwrap();
        assert!(matches!(result, ShardSyncResult::Anchored { .. }));
        assert_eq!(
            *calls.lock().unwrap(),
            ["fetch 0", "fetch 599", "validate 600", "sync 88"]
        );
    }

    #[tokio::test]
    async fn archive_replay_fills_a_stale_workers_gap_in_bounded_batches_without_tree_sync() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(600)),
            calls: calls.clone(),
        };
        let replayed = Arc::new(Mutex::new(Vec::new()));
        let seen = replayed.clone();
        let result = replay_shard_from_latest(
            &archive,
            &[5; 32],
            frame(130),
            129,
            None,
            &CarriedVerifierSource::default(),
            move |frame, _child| {
                let height = frame.header.unwrap().frame_number;
                seen.lock().unwrap().push(height);
                async move { Ok(height) }
            },
        )
        .await
        .unwrap();
        assert_eq!(
            result,
            ShardReplay {
                materialized: 161,
                archive_tip: Some(600),
                target: 600
            }
        );
        assert_eq!(*replayed.lock().unwrap(), (130..=161).collect::<Vec<_>>());
        assert_eq!(calls.lock().unwrap().len(), 33);
        assert!(calls
            .lock()
            .unwrap()
            .iter()
            .all(|call| call.starts_with("fetch ")));
    }

    /// Serves certified frames up to a tip of 134, except frame 132, which
    /// has no certificate of its own.
    struct BareArchive;

    #[async_trait]
    impl ProverTreeSyncer for BareArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
        async fn get_app_shard_frame(
            &self,
            _: &[u8],
            number: u64,
        ) -> Result<Option<AppShardFrame>> {
            let mut served = frame(if number == 0 { 134 } else { number });
            if number == 132 {
                served
                    .header
                    .as_mut()
                    .unwrap()
                    .public_key_signature_bls48581 = None;
            }
            Ok(Some(served))
        }
        async fn sync_shard_tree(&self, _: &[u8], _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
    }

    /// A frame with no certificate of its own is replayed together with the
    /// certified frame after it, which finalized it.
    #[tokio::test]
    async fn archive_replay_hands_an_uncertified_frame_its_certified_child() {
        let replayed = Arc::new(Mutex::new(Vec::new()));
        let seen = replayed.clone();
        let result = replay_shard_from_latest(
            &BareArchive,
            &[5; 32],
            frame(130),
            130,
            None,
            &CarriedVerifierSource::default(),
            move |frame, child| {
                let height = frame.header.unwrap().frame_number;
                seen.lock().unwrap().push((
                    height,
                    child
                        .into_iter()
                        .map(|child| child.header.unwrap().frame_number)
                        .collect::<Vec<_>>(),
                ));
                async move { Ok(height) }
            },
        )
        .await
        .unwrap();
        assert_eq!(
            result,
            ShardReplay {
                materialized: 134,
                archive_tip: Some(134),
                target: 134
            }
        );
        assert_eq!(
            *replayed.lock().unwrap(),
            vec![
                (131, vec![]),
                (132, vec![133]),
                (133, vec![]),
                (134, vec![])
            ]
        );
    }

    struct ChainArchive {
        missing: Option<u64>,
        wrong_shard: bool,
        unsigned_end: u64,
    }

    #[async_trait]
    impl ProverTreeSyncer for ChainArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
        async fn get_app_shard_frame(
            &self,
            _: &[u8],
            number: u64,
        ) -> Result<Option<AppShardFrame>> {
            if self.missing == Some(number) {
                return Ok(None);
            }
            let mut served = frame(if number == 0 { 200 } else { number });
            if (131..=self.unsigned_end).contains(&number) {
                served
                    .header
                    .as_mut()
                    .unwrap()
                    .public_key_signature_bls48581 = None;
            }
            if self.wrong_shard && number == 132 {
                served.header.as_mut().unwrap().address = vec![9; 32];
            }
            Ok(Some(served))
        }
        async fn sync_shard_tree(&self, _: &[u8], _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn archive_replay_fetches_past_consecutive_unsigned_headers() {
        let archive = ChainArchive {
            missing: None,
            wrong_shard: false,
            unsigned_end: 132,
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = calls.clone();
        let result = replay_shard_from_latest(
            &archive,
            &[5; 32],
            frame(130),
            130,
            None,
            &CarriedVerifierSource::default(),
            move |frame, descendants| {
                let height = frame.header.unwrap().frame_number;
                seen.lock().unwrap().push((
                    height,
                    descendants
                        .iter()
                        .map(|child| child.header.as_ref().unwrap().frame_number)
                        .collect::<Vec<_>>(),
                ));
                async move { Ok(height) }
            },
        )
        .await
        .unwrap();
        assert_eq!(result.materialized, 162);
        let calls = calls.lock().unwrap();
        assert_eq!(calls[0], (131, vec![132, 133]));
        assert_eq!(calls[1], (132, vec![133]));
        assert_eq!(calls[2], (133, vec![]));
    }

    #[tokio::test]
    async fn archive_replay_never_sends_an_unbounded_missing_or_wrong_shard_chain_to_the_actor() {
        for archive in [
            ChainArchive {
                missing: None,
                wrong_shard: false,
                unsigned_end: 200,
            },
            ChainArchive {
                missing: Some(132),
                wrong_shard: false,
                unsigned_end: 132,
            },
            ChainArchive {
                missing: None,
                wrong_shard: true,
                unsigned_end: 132,
            },
        ] {
            assert!(replay_shard_from_latest(
                &archive,
                &[5; 32],
                frame(130),
                130,
                None,
                &CarriedVerifierSource::default(),
                |_, _| async { panic!("incomplete chain must not reach replay") }
            )
            .await
            .is_err());
        }
    }

    #[tokio::test]
    async fn archive_replay_stops_on_engine_rejection_and_never_skips_the_gap() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(600)),
            calls: calls.clone(),
        };
        assert!(replay_shard_from_latest(
            &archive,
            &[5; 32],
            frame(130),
            129,
            None,
            &CarriedVerifierSource::default(),
            |_, _| async {
                Err(quil_types::error::QuilError::InvalidSignature(
                    "rejected certificate".into(),
                ))
            }
        )
        .await
        .is_err());
        assert_eq!(*calls.lock().unwrap(), ["fetch 0", "fetch 130"]);
    }

    /// [`ChainArchive`] missing frame `missing`, whose frames are anchored to
    /// GLOBAL frame 9000 plus their number, and `pause` more from `missing`
    /// on; GLOBAL frames carry `carried` as the missing frame's headers, and
    /// the frame after it names `names` as its parent when set. `searches`:
    /// each GLOBAL search, as the frame sought and the GLOBAL frames read;
    /// `rejected_copies`: the copies rejected; `rejected`: the frames all of
    /// whose copies were. `tip`: the frame it reports as its tip (200 unset);
    /// `refused`, `passed_over`: the copies each search says it refused, and
    /// passed over as refused before.
    struct CarryingArchive {
        chain: ChainArchive,
        missing: u64,
        pause: u64,
        names: Option<Vec<u8>>,
        carried: Vec<(u64, quil_types::proto::global::FrameHeader)>,
        searches: Mutex<Vec<(u64, Vec<u64>)>>,
        rejected_copies: Mutex<Vec<CopyId>>,
        rejected: Mutex<Vec<u64>>,
        asked_named: Mutex<Vec<Option<[u8; 32]>>>,
        also_missing: Option<u64>,
        tip: Option<u64>,
        refused: usize,
        passed_over: usize,
        /// Whether searches are answered from memory.
        cached: bool,
        /// How long each search takes.
        delay: Option<std::time::Duration>,
    }

    impl CarryingArchive {
        fn new(missing: u64, carried: Vec<(u64, quil_types::proto::global::FrameHeader)>) -> Self {
            Self {
                chain: ChainArchive {
                    missing: Some(missing),
                    wrong_shard: false,
                    unsigned_end: 0,
                },
                missing,
                pause: 0,
                names: None,
                carried,
                searches: Mutex::new(Vec::new()),
                rejected_copies: Mutex::new(Vec::new()),
                rejected: Mutex::new(Vec::new()),
                asked_named: Mutex::new(Vec::new()),
                also_missing: None,
                tip: None,
                refused: 0,
                passed_over: 0,
                cached: false,
                delay: None,
            }
        }
    }

    /// [`frame`] anchored to GLOBAL frame 9000 plus its number.
    fn anchored(mut frame: AppShardFrame) -> AppShardFrame {
        let header = frame.header.as_mut().unwrap();
        header.global_frame_number = 9000 + header.frame_number;
        frame
    }

    /// Frame `number`'s header as members submit it to GLOBAL: certified,
    /// committing to no requests.
    fn carried_header(number: u64) -> quil_types::proto::global::FrameHeader {
        let mut header = anchored(frame(number)).header.unwrap();
        header.requests_root = vec![0; 32];
        header
    }

    #[async_trait]
    impl ProverTreeSyncer for CarryingArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
        async fn get_app_shard_frame(
            &self,
            filter: &[u8],
            number: u64,
        ) -> Result<Option<AppShardFrame>> {
            let number = match (number, self.tip) {
                (0, Some(tip)) => tip,
                _ => number,
            };
            if self.also_missing == Some(number) {
                return Ok(None);
            }
            Ok(self
                .chain
                .get_app_shard_frame(filter, number)
                .await?
                .map(anchored)
                .map(|mut frame| {
                    let header = frame.header.as_mut().unwrap();
                    if number >= self.missing {
                        header.global_frame_number += self.pause;
                    }
                    if number == self.missing + 1 {
                        header.parent_selector = self.names.clone().unwrap_or_default();
                    }
                    frame
                }))
        }
        async fn sync_shard_tree(&self, _: &[u8], _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
        async fn carried_shard_headers(
            &self,
            _: &[u8],
            number: u64,
            globals: &[u64],
            named: Option<[u8; 32]>,
            _: Option<&CarriedVerifier>,
        ) -> Result<CarriedHeaders> {
            if let Some(delay) = self.delay {
                tokio::time::sleep(delay).await;
            }
            self.searches
                .lock()
                .unwrap()
                .push((number, globals.to_vec()));
            self.asked_named.lock().unwrap().push(named);
            Ok(CarriedHeaders {
                copies: self.carried.clone(),
                certified: Vec::new(),
                rejected: self.rejected_copies.lock().unwrap().clone(),
                refused: self.refused,
                passed_over: self.passed_over,
            })
        }
        fn cached_carried_shard_headers(
            &self,
            _: &[u8],
            _: u64,
            _: Option<[u8; 32]>,
        ) -> Option<Result<CarriedHeaders>> {
            self.cached.then(|| {
                Ok(CarriedHeaders {
                    copies: self.carried.clone(),
                    ..Default::default()
                })
            })
        }
        fn reject_carried_copy(&self, _: &[u8], _: u64, copy: CopyId) {
            self.rejected_copies.lock().unwrap().push(copy);
        }
        fn reject_carried_shard_headers(&self, _: &[u8], number: u64) {
            self.rejected.lock().unwrap().push(number);
        }
    }

    /// Replay from `local` at `materialized` to the 32-frame batch's end,
    /// with the frames replayed; the replay of a frame `refuse` names fails.
    async fn replay_carrying(
        archive: &CarryingArchive,
        local: u64,
        materialized: u64,
        refuse: fn(&AppShardFrame) -> bool,
    ) -> (Result<ShardReplay>, Vec<AppShardFrame>) {
        let replayed = Arc::new(Mutex::new(Vec::new()));
        let seen = replayed.clone();
        let result = replay_shard_from_latest(
            archive,
            &[5; 32],
            anchored(frame(local)),
            materialized,
            None,
            &CarriedVerifierSource::default(),
            move |frame, descendants| {
                assert!(descendants.is_empty());
                let height = frame.header.as_ref().unwrap().frame_number;
                let refused = refuse(&frame);
                seen.lock().unwrap().push(frame);
                async move {
                    match refused {
                        true => Err(quil_types::error::QuilError::InvalidArgument(
                            "refused".into(),
                        )),
                        false => Ok(height),
                    }
                }
            },
        )
        .await;
        let replayed = replayed.lock().unwrap().clone();
        (result, replayed)
    }

    /// The number of `frame`.
    fn number_of(frame: &AppShardFrame) -> u64 {
        frame.header.as_ref().unwrap().frame_number
    }

    /// No archive serves an empty frame its archives executed from the
    /// certified header GLOBAL carried (…0c1db0 frame 14372, carried by
    /// GLOBAL 924341, 2026-10-23): replay rebuilds it from that header,
    /// sought in the GLOBAL frames that can carry it, from the one after its
    /// predecessor's anchor through GLOBAL's lockstep window above its
    /// successor's, and goes on past it.
    #[tokio::test]
    async fn archive_replay_rebuilds_an_empty_frame_no_archive_serves_from_its_carried_header() {
        // The predecessor's anchor is the local head's, or read from an archive.
        for (local, missing) in [(130, 140), (130, 131), (135, 131)] {
            let archive =
                CarryingArchive::new(missing, vec![(9000 + missing + 6, carried_header(missing))]);
            let (result, replayed) = replay_carrying(&archive, local, 130, |_| false).await;
            assert_eq!(result.unwrap().materialized, 162);
            let from = 9000 + missing;
            assert_eq!(
                *archive.searches.lock().unwrap(),
                [(missing, (from..=from + 14).collect::<Vec<_>>())]
            );
            assert_eq!(
                replayed
                    .iter()
                    .map(|frame| frame.header.as_ref().unwrap().frame_number)
                    .collect::<Vec<_>>(),
                (131..=162).collect::<Vec<_>>()
            );
            let rebuilt = AppShardFrame {
                header: Some(carried_header(missing)),
                requests: vec![],
                storage_attestation: None,
            };
            assert_eq!(replayed[(missing - 131) as usize], rebuilt);
            assert!(archive.rejected.lock().unwrap().is_empty());
        }
    }

    /// GLOBAL takes a frame's header only within its lockstep window above
    /// the frame's own anchor, which lies between its neighbours' anchors.
    /// When a shard paused longer than the search window around the frame,
    /// the top of that range is read first, from the top down, then its
    /// bottom: a search from the predecessor's anchor up never reached the
    /// header of a frame proposed after the pause. Then its middle, over
    /// later searches, so a header carried there is reached too, within
    /// [`CARRIED_HEADER_SPAN`] frames in all.
    #[tokio::test]
    async fn archive_replay_reads_the_global_frames_that_can_carry_a_header_after_a_pause() {
        assert_eq!(
            carried_header_globals(9139, Some(9141)),
            (9140..=9154).collect::<Vec<_>>()
        );
        assert_eq!(
            carried_header_globals(9139, None),
            (9140..=9203).collect::<Vec<_>>()
        );
        let paused = carried_header_globals(9139, Some(9241));
        assert_eq!(
            paused,
            (9223..=9254)
                .rev()
                .chain(9140..=9171)
                .chain(9172..=9222)
                .collect::<Vec<_>>()
        );
        let long = carried_header_globals(9139, Some(9139 + 100_000));
        assert_eq!(long.len() as u64, CARRIED_HEADER_SPAN);
        assert_eq!(
            long[CARRIED_HEADER_WINDOW as usize],
            9140 + CARRIED_HEADER_WINDOW / 2,
            "the middle from the bottom up"
        );

        let mut header = carried_header(140);
        header.global_frame_number += 100;
        let mut archive = CarryingArchive::new(140, vec![(9247, header.clone())]);
        archive.pause = 100;
        let (result, replayed) = replay_carrying(&archive, 130, 130, |_| false).await;
        assert_eq!(result.unwrap().materialized, 162);
        assert_eq!(*archive.searches.lock().unwrap(), [(140, paused)]);
        assert_eq!(replayed[9].header, Some(header));
    }

    /// Several members submit a frame's header. Replay takes the copy whose
    /// output the frame after it names, then one holding the committee's
    /// storage attestation, which the rebuilt frame then carries as its body
    /// does; the header's own attestation field is left empty, as stored.
    #[tokio::test]
    async fn archive_replay_prefers_the_carried_header_its_successor_names_then_one_with_the_attestation(
    ) {
        use prost::Message;
        let attestation = quil_types::proto::global::StorageAttestation {
            openings: vec![Default::default()],
        };
        let copy = |output: u8, attested: bool| {
            let mut header = carried_header(140);
            header.output = vec![output; 32];
            if attested {
                header.storage_attestation = attestation.encode_to_vec();
            }
            header
        };
        let carried = vec![
            (9141, copy(1, false)),
            (9142, copy(2, true)),
            (9143, copy(3, false)),
        ];
        for (names, chosen) in [(None, 2), (Some(3), 3), (Some(2), 2)] {
            let mut archive = CarryingArchive::new(140, carried.clone());
            archive.names = names.map(|output| {
                quil_crypto::poseidon::hash_bytes_to_32(&[output; 32])
                    .unwrap()
                    .to_vec()
            });
            let (result, replayed) = replay_carrying(&archive, 130, 130, |_| false).await;
            assert_eq!(result.unwrap().materialized, 162);
            assert_eq!(replayed[9].header, Some(copy(chosen, false)));
            assert_eq!(
                replayed[9].storage_attestation.is_some(),
                chosen == 2,
                "chose {chosen}"
            );
        }
    }

    /// No certificate binds a carried header's storage attestation field,
    /// and GLOBAL's audit of a wrong one does not refuse the frame. A frame
    /// rebuilt from a copy that fails to replay has that copy rejected, and
    /// the next attempt takes another member's copy, else the attested copy
    /// with its attestation cleared, which replays on its certificate and
    /// output. Once every copy has failed, the GLOBAL frames are searched
    /// again later. A failure of a frame served whole rejects nothing.
    #[tokio::test]
    async fn a_carried_copy_whose_frame_fails_to_replay_is_passed_over_for_the_next() {
        use prost::Message;
        let junk = quil_types::proto::global::StorageAttestation {
            openings: vec![Default::default()],
        }
        .encode_to_vec();
        let attested = quil_types::proto::global::FrameHeader {
            storage_attestation: junk,
            ..carried_header(140)
        };
        let attested_fails: fn(&AppShardFrame) -> bool =
            |frame| frame.storage_attestation.is_some();
        let bare = AppShardFrame {
            header: Some(carried_header(140)),
            requests: vec![],
            storage_attestation: None,
        };
        for carried in [
            vec![(9146, attested.clone()), (9147, carried_header(140))],
            vec![(9146, attested.clone())],
        ] {
            let archive = CarryingArchive::new(140, carried);
            let (result, replayed) = replay_carrying(&archive, 130, 130, attested_fails).await;
            assert!(result.is_err());
            assert!(
                replayed[9].storage_attestation.is_some(),
                "the attested copy first"
            );
            assert_eq!(
                *archive.rejected_copies.lock().unwrap(),
                [carried_copy_digest(&attested)]
            );
            let (result, replayed) = replay_carrying(&archive, 139, 139, attested_fails).await;
            assert_eq!(result.unwrap().materialized, 171);
            assert_eq!(replayed[0], bare);
            assert!(archive.rejected.lock().unwrap().is_empty());
        }

        let archive = CarryingArchive::new(140, vec![(9146, carried_header(140))]);
        let (result, replayed) =
            replay_carrying(&archive, 130, 130, |frame| number_of(frame) == 140).await;
        assert!(result.is_err());
        assert_eq!(replayed.len(), 10);
        assert_eq!(
            *archive.rejected_copies.lock().unwrap(),
            [carried_copy_digest(&carried_header(140))]
        );
        let (result, _) = replay_carrying(&archive, 139, 139, |_| false).await;
        let error = result.unwrap_err().to_string();
        assert!(
            error.ends_with(
                "every header GLOBAL frames 9140..=9154 carry for it failed to replay; \
            they are read again after the retry interval"
            ),
            "{error}"
        );
        assert_eq!(*archive.rejected.lock().unwrap(), [140]);

        let archive = CarryingArchive::new(140, vec![(9146, carried_header(140))]);
        let (result, _) =
            replay_carrying(&archive, 130, 130, |frame| number_of(frame) == 139).await;
        assert!(result.is_err());
        assert!(archive.rejected_copies.lock().unwrap().is_empty());
    }

    /// GLOBAL keeps a header whose execution failed, so anyone who gets a
    /// bundle into GLOBAL can plant a copy of a frame's header, with any
    /// output and attestation. A forged copy carried before the genuine one
    /// is not taken: the copy whose output the frame after it names comes
    /// first, and the search is told that name.
    #[tokio::test]
    async fn a_forged_copy_carried_before_the_genuine_one_is_not_taken() {
        use prost::Message;
        let junk = quil_types::proto::global::StorageAttestation {
            openings: vec![Default::default()],
        }
        .encode_to_vec();
        let forged = quil_types::proto::global::FrameHeader {
            output: vec![0x46; 32],
            storage_attestation: junk,
            ..carried_header(140)
        };
        let genuine = quil_types::proto::global::FrameHeader {
            output: vec![0x47; 32],
            ..carried_header(140)
        };
        let named = quil_crypto::poseidon::hash_bytes_to_32(&genuine.output).unwrap();
        let mut archive = CarryingArchive::new(140, vec![(9141, forged), (9146, genuine.clone())]);
        archive.names = Some(named.to_vec());
        let forged_fails: fn(&AppShardFrame) -> bool =
            |frame| frame.header.as_ref().unwrap().output == vec![0x46; 32];
        let (result, replayed) = replay_carrying(&archive, 130, 130, forged_fails).await;
        assert_eq!(result.unwrap().materialized, 162);
        assert_eq!(replayed[9].header, Some(genuine));
        assert!(archive.rejected_copies.lock().unwrap().is_empty());
        assert_eq!(*archive.asked_named.lock().unwrap(), [Some(named)]);
    }

    /// A rebuilt frame whose replay waits on something unavailable (GLOBAL
    /// frames, registrations, an archive read) has its copy kept: only a
    /// refusal of the frame passes it over.
    #[tokio::test]
    async fn a_rebuilt_frame_whose_replay_waits_keeps_its_copy() {
        let archive = CarryingArchive::new(140, vec![(9146, carried_header(140))]);
        let result = replay_shard_from_latest(
            &archive,
            &[5; 32],
            anchored(frame(130)),
            130,
            None,
            &CarriedVerifierSource::default(),
            |frame, _| {
                let height = number_of(&frame);
                async move {
                    match height {
                        140 => Err(quil_types::error::QuilError::ExecutionUnavailable(
                            "anchor unavailable".into(),
                        )),
                        _ => Ok(height),
                    }
                }
            },
        )
        .await;
        assert!(result.is_err());
        assert!(archive.rejected_copies.lock().unwrap().is_empty());
    }

    /// A refusal in a replay batch rejects the copy of the frame it names:
    /// "frame 140" names 140, not 14 or 1400.
    #[test]
    fn a_refusal_names_the_frame_it_refuses() {
        use quil_types::error::QuilError;
        let refusal = QuilError::InvalidArgument(
            "archive replay frame 140: anchor does not link to predecessor".into(),
        );
        assert!(names_frame(&refusal, 140));
        assert!(!names_frame(&refusal, 14));
        assert!(!names_frame(&refusal, 1400));
        assert!(!names_frame(
            &QuilError::InvalidSignature("app shard frame BLS signature rejected".into()),
            140
        ));
        let another = QuilError::InvalidArgument(
            "archive replay frame 139: does not link to frame 140: parent".into(),
        );
        assert!(
            !names_frame(&another, 140),
            "only the frame replay names first"
        );
        assert!(names_frame(&another, 139));
    }

    /// A frame rebuilt from a carried copy as the certified frame ending a
    /// run of frames without certificates of their own is not replayed
    /// alone: its copy is passed over when the refusal names it, as the
    /// engine now names the frame it refuses (`app_engine::refusal_of`),
    /// and kept when the refusal names another frame of the batch.
    #[tokio::test]
    async fn a_refusal_of_a_rebuilt_terminal_frame_rejects_its_copy() {
        use quil_types::error::QuilError;
        let named = crate::app_engine::refusal_of(
            140,
            QuilError::Crypto("app shard frame storage attestation rejected".into()),
        );
        assert_eq!(
            named.to_string(),
            QuilError::Crypto(
                "archive replay frame 140: app shard frame storage attestation rejected".into()
            )
            .to_string()
        );
        let wait = crate::app_engine::refusal_of(
            140,
            QuilError::ExecutionUnavailable("anchor unavailable".into()),
        );
        assert!(
            matches!(wait, QuilError::ExecutionUnavailable(reason) if reason == "anchor unavailable")
        );
        for (refused, rejected) in [(140, true), (135, false)] {
            let mut archive = CarryingArchive::new(140, vec![(9146, carried_header(140))]);
            archive.chain.unsigned_end = 139;
            let batches = Arc::new(Mutex::new(Vec::new()));
            let seen = batches.clone();
            let result = replay_shard_from_latest(
                &archive,
                &[5; 32],
                anchored(frame(130)),
                130,
                None,
                &CarriedVerifierSource::default(),
                move |frame, descendants| {
                    seen.lock().unwrap().push((
                        number_of(&frame),
                        descendants.iter().map(number_of).collect::<Vec<_>>(),
                    ));
                    async move {
                        Err::<u64, _>(crate::app_engine::refusal_of(
                            refused,
                            QuilError::Crypto("storage attestation rejected".into()),
                        ))
                    }
                },
            )
            .await;
            assert!(result.is_err());
            assert_eq!(
                *batches.lock().unwrap(),
                [(131, (132..=140).collect::<Vec<_>>())],
                "one batch, the rebuilt frame last"
            );
            let expected: Vec<CopyId> = if rejected {
                vec![carried_copy_digest(&carried_header(140))]
            } else {
                Vec::new()
            };
            assert_eq!(
                *archive.rejected_copies.lock().unwrap(),
                expected,
                "refusal of frame {refused}"
            );
        }
    }

    /// A recovery target answering how carried copies are checked, or not.
    struct AskedTarget(std::sync::atomic::AtomicUsize, bool);

    #[async_trait]
    impl ShardRecoveryTarget for AskedTarget {
        fn materialized(&self) -> u64 {
            unreachable!()
        }
        async fn replay(&self, _: AppShardFrame, _: Vec<AppShardFrame>) -> Result<u64> {
            unreachable!()
        }
        async fn validate(&self, _: AppShardFrame, _: Option<AppShardFrame>) -> Result<bool> {
            unreachable!()
        }
        async fn install(&self, _: AppShardFrame, _: Option<AppShardFrame>) -> Result<()> {
            unreachable!()
        }
        fn inherited(&self) {
            unreachable!()
        }
        async fn carried_copy_verifier(&self) -> Option<CarriedVerifier> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let unchecked: CarriedVerifier =
                Arc::new(|_: quil_types::proto::global::FrameHeader| {
                    Box::pin(async { CopyVerdict::Unavailable })
                });
            self.1.then_some(unchecked)
        }
    }

    /// The engine is asked how to check carried copies only by the first
    /// frame rebuilt from one, once per recovery: a replay with every frame
    /// served never waits on it. An engine that gives no answer is asked
    /// again by the next rebuild.
    #[tokio::test]
    async fn the_copy_check_is_asked_for_only_by_a_rebuild() {
        let replay = |frame: AppShardFrame, _: Vec<AppShardFrame>| async move {
            Ok::<u64, quil_types::error::QuilError>(number_of(&frame))
        };
        for (answers, asks) in [(true, 1), (false, 2)] {
            let asked = AskedTarget(std::sync::atomic::AtomicUsize::new(0), answers);
            let source = CarriedVerifierSource::of(&asked);
            let served = ChainArchive {
                missing: None,
                wrong_shard: false,
                unsigned_end: 0,
            };
            assert_eq!(
                replay_shard_from_latest(&served, &[5; 32], frame(130), 130, None, &source, replay)
                    .await
                    .unwrap()
                    .materialized,
                162
            );
            assert_eq!(asked.0.load(std::sync::atomic::Ordering::SeqCst), 0);
            let archive = CarryingArchive::new(140, vec![(9146, carried_header(140))]);
            for _ in 0..2 {
                replay_shard_from_latest(
                    &archive,
                    &[5; 32],
                    anchored(frame(130)),
                    130,
                    None,
                    &source,
                    replay,
                )
                .await
                .unwrap();
            }
            assert_eq!(
                asked.0.load(std::sync::atomic::Ordering::SeqCst),
                asks,
                "answers: {answers}"
            );
        }
    }

    /// A batch that rebuilds frames from their carried headers, each a
    /// search of GLOBAL frames, ends with what it materialized once its
    /// budget has passed, rather than holding the recovery turn through a
    /// long run of such frames; the next batch goes on from there.
    #[tokio::test(start_paused = true)]
    async fn a_batch_of_rebuilt_frames_ends_within_its_budget() {
        let mut archive = CarryingArchive::new(
            140,
            vec![(9146, carried_header(140)), (9147, carried_header(141))],
        );
        archive.also_missing = Some(141);
        archive.delay = Some(REBUILT_BATCH_BUDGET / 2 + std::time::Duration::from_secs(10));
        let (result, _) = replay_carrying(&archive, 130, 130, |_| false).await;
        assert_eq!(
            result.unwrap().materialized,
            141,
            "the batch ends after the frame that passed its budget"
        );
    }

    /// A recovery whose worker's head is not its materialized frame (the
    /// head a worker's lineage reports may lag) still knows that frame's
    /// anchor, from the worker's own store: a frame rebuilt from its carried
    /// header by an earlier recovery, which no archive serves, does not
    /// leave the next one asking archives for it.
    #[tokio::test]
    async fn a_recovery_knows_the_anchor_of_the_frame_materialized_before() {
        struct Anchored {
            cursor: std::sync::atomic::AtomicU64,
            anchors: Mutex<std::collections::HashMap<u64, u64>>,
        }
        #[async_trait]
        impl ShardRecoveryTarget for Anchored {
            fn materialized(&self) -> u64 {
                self.cursor.load(std::sync::atomic::Ordering::SeqCst)
            }
            async fn replay(&self, frame: AppShardFrame, _: Vec<AppShardFrame>) -> Result<u64> {
                let header = frame.header.unwrap();
                self.anchors
                    .lock()
                    .unwrap()
                    .insert(header.frame_number, header.global_frame_number);
                self.cursor
                    .store(header.frame_number, std::sync::atomic::Ordering::SeqCst);
                Ok(header.frame_number)
            }
            async fn validate(&self, _: AppShardFrame, _: Option<AppShardFrame>) -> Result<bool> {
                unreachable!()
            }
            async fn install(&self, _: AppShardFrame, _: Option<AppShardFrame>) -> Result<()> {
                unreachable!()
            }
            fn inherited(&self) {
                unreachable!()
            }
            async fn materialized_anchor(&self, frame: u64) -> Option<u64> {
                self.anchors.lock().unwrap().get(&frame).copied()
            }
        }
        let mut archive = CarryingArchive::new(
            162,
            vec![(9170, carried_header(162)), (9171, carried_header(163))],
        );
        archive.also_missing = Some(163);
        let target = Anchored {
            cursor: std::sync::atomic::AtomicU64::new(130),
            anchors: Mutex::new(Default::default()),
        };
        for expected in [162, 194] {
            let progress = recover_shard_from_latest(
                &archive,
                &[5; 32],
                Some(anchored(frame(130))),
                &target,
                Default::default(),
                None,
            )
            .await
            .unwrap();
            assert!(
                matches!(progress, ShardRecoveryProgress::Replayed { materialized, .. } if materialized == expected),
                "{progress:?}"
            );
        }
    }

    /// The check of a copy's structure and output refuses it only on a
    /// refusal: a panic, the check ending early, or this node's clock behind
    /// the frame's timestamp is a wait, not a refusal kept for the process's
    /// life.
    #[test]
    fn only_a_refusal_of_its_structure_refuses_a_copy() {
        use quil_types::error::QuilError;
        assert_eq!(structure_verdict(Ok(Ok(true))), None);
        assert_eq!(structure_verdict(Ok(Ok(false))), Some(CopyVerdict::Refused));
        assert_eq!(
            structure_verdict(Ok(Err(QuilError::InvalidArgument(
                "output mismatch".into()
            )))),
            Some(CopyVerdict::Refused)
        );
        assert_eq!(
            structure_verdict(Err(Box::new("validation panicked"))),
            Some(CopyVerdict::Unavailable)
        );
        assert_eq!(
            structure_verdict(Ok(Err(QuilError::Internal(
                "carried copy check ended early".into()
            )))),
            Some(CopyVerdict::Unavailable)
        );
        let ahead = QuilError::InvalidArgument(
            "storage frame: timestamp 9 too far in the future (now 1, >7200000ms)".into(),
        );
        assert!(!refuses_frame(&ahead));
        assert_eq!(
            structure_verdict(Ok(Err(ahead))),
            Some(CopyVerdict::Unavailable)
        );
    }

    /// A search answered from memory never waits on the engine for its
    /// check: only one that reads GLOBAL frames asks for it.
    #[tokio::test]
    async fn a_search_answered_from_memory_asks_the_engine_nothing() {
        let replay = |frame: AppShardFrame, _: Vec<AppShardFrame>| async move {
            Ok::<u64, quil_types::error::QuilError>(number_of(&frame))
        };
        let asked = AskedTarget(std::sync::atomic::AtomicUsize::new(0), false);
        let source = CarriedVerifierSource::of(&asked);
        let mut archive = CarryingArchive::new(140, vec![(9146, carried_header(140))]);
        archive.cached = true;
        replay_shard_from_latest(
            &archive,
            &[5; 32],
            anchored(frame(130)),
            130,
            None,
            &source,
            replay,
        )
        .await
        .unwrap();
        assert_eq!(asked.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(archive.searches.lock().unwrap().is_empty());
    }

    /// A frame rebuilt from a carried copy too large to replay never reaches
    /// replay, and its copy is passed over, not tried again for ever.
    #[tokio::test]
    async fn a_copy_rebuilding_an_oversized_frame_is_passed_over() {
        let mut huge = carried_header(140);
        huge.settlements = vec![0; MAX_REPLAY_FRAME_BYTES + 1];
        let archive = CarryingArchive::new(140, vec![(9146, huge.clone())]);
        let (result, _) = replay_carrying(&archive, 130, 130, |_| false).await;
        assert!(result.unwrap_err().to_string().contains("oversized"));
        assert_eq!(
            *archive.rejected_copies.lock().unwrap(),
            [carried_copy_digest(&huge)]
        );
    }

    /// Copies whose fee total differs only in how its value is written are
    /// one copy: the output binds the value alone, which any length but 16
    /// bytes reads as zero, and the copy kept holds the form members store.
    #[test]
    fn copies_differing_only_in_how_their_fee_total_is_written_are_one() {
        let forms = [Vec::new(), vec![0; 3], vec![0; 16], vec![7; 15]];
        let digests: std::collections::HashSet<CopyId> = forms
            .iter()
            .map(|fee_total| {
                carried_copy_digest(&quil_types::proto::global::FrameHeader {
                    fee_total: fee_total.clone(),
                    ..carried_header(140)
                })
            })
            .collect();
        assert_eq!(digests.len(), 1);
        let mut header = quil_types::proto::global::FrameHeader {
            fee_total: vec![0; 3],
            ..carried_header(140)
        };
        normalize_carried_header(&mut header);
        assert!(header.fee_total.is_empty());
        let mut paid = quil_types::proto::global::FrameHeader {
            fee_total: 5u128.to_be_bytes().to_vec(),
            ..carried_header(140)
        };
        normalize_carried_header(&mut paid);
        assert_eq!(paid.fee_total, 5u128.to_be_bytes().to_vec());
    }

    /// GLOBAL checks a header's anchor only against the frame carrying it,
    /// so a genuine frame may be anchored below its predecessor: its copy is
    /// taken. With the frame after it missing too, the search is bounded by
    /// the GLOBAL frame the archive's tip is anchored to. Copies of it all
    /// refused before are said to be.
    #[tokio::test]
    async fn the_search_takes_a_frame_anchored_below_its_predecessor_and_is_bounded_by_the_tip() {
        let low = quil_types::proto::global::FrameHeader {
            global_frame_number: 9135,
            ..carried_header(140)
        };
        let archive = CarryingArchive::new(140, vec![(9140, low.clone())]);
        let (result, replayed) = replay_carrying(&archive, 130, 130, |_| false).await;
        assert_eq!(result.unwrap().materialized, 162);
        assert_eq!(replayed[9].header, Some(low));

        let mut archive = CarryingArchive::new(140, vec![(9146, carried_header(140))]);
        archive.also_missing = Some(141);
        let _ = replay_carrying(&archive, 130, 130, |_| false).await;
        let tip = 9200
            + 1
            + quil_execution::global_intrinsic::frame_header::STORAGE_ANCHOR_LOCKSTEP_WINDOW;
        assert_eq!(
            archive.searches.lock().unwrap()[0],
            (
                140,
                (tip - 31..=tip)
                    .rev()
                    .chain(9140..9172)
                    .chain(9172..=tip - 32)
                    .collect::<Vec<_>>()
            )
        );

        for (refused, passed_over) in [(0, 3), (2, 0)] {
            let mut archive = CarryingArchive::new(140, Vec::new());
            (archive.refused, archive.passed_over) = (refused, passed_over);
            let error = replay_carrying(&archive, 130, 130, |_| false)
                .await
                .0
                .unwrap_err()
                .to_string();
            assert!(
                error.ends_with(&format!(
                    "GLOBAL frames 9140..=9154 carry only copies of its header refused \
                ({refused} when checked, {passed_over} passed over as refused before)"
                )),
                "{error}"
            );
        }
    }

    /// Two frames no archive serves, the first ending a 32-frame batch:
    /// the next batch, from a head it no longer knows the anchor of, is told
    /// that of the frame the last batch rebuilt, so its search for the second
    /// starts after it rather than failing once.
    #[tokio::test]
    async fn a_batch_after_a_rebuilt_frame_knows_its_anchor() {
        let mut archive = CarryingArchive::new(
            162,
            vec![(9170, carried_header(162)), (9171, carried_header(163))],
        );
        archive.also_missing = Some(163);
        let replay = |frame: AppShardFrame, _| async move {
            Ok(frame.header.as_ref().unwrap().frame_number)
        };
        let verify = CarriedVerifierSource::default();
        let (first, known) = replay_shard_from(
            &archive,
            &[5; 32],
            anchored(frame(130)),
            130,
            None,
            None,
            &verify,
            replay,
        )
        .await
        .unwrap();
        assert_eq!((first.materialized, known), (162, Some((162, 9162))));
        let (second, _) = replay_shard_from(
            &archive,
            &[5; 32],
            anchored(frame(130)),
            162,
            known,
            None,
            &verify,
            replay,
        )
        .await
        .unwrap();
        assert_eq!(second.materialized, 194);
    }

    /// GLOBAL's committed tip can lie beyond every archive's tip: a frame
    /// above the archive's tip is sought without the bound of the GLOBAL
    /// frame that tip is anchored to, which lies below the frame's own
    /// anchor, so its carried header is reached even when the frame after
    /// it is missing too.
    #[tokio::test]
    async fn a_frame_above_the_archive_tip_is_sought_unbounded_by_that_tip() {
        let mut archive = CarryingArchive::new(
            140,
            vec![(9146, carried_header(140)), (9147, carried_header(141))],
        );
        (archive.also_missing, archive.tip) = (Some(141), Some(135));
        let result = replay_shard_from_latest(
            &archive,
            &[5; 32],
            anchored(frame(130)),
            130,
            Some(150),
            &CarriedVerifierSource::default(),
            |frame, _| {
                let height = frame.header.as_ref().unwrap().frame_number;
                async move { Ok(height) }
            },
        )
        .await;
        assert_eq!(result.unwrap().materialized, 150);
        assert_eq!(
            archive.searches.lock().unwrap()[0],
            (140, (9140..=9203).collect::<Vec<_>>())
        );
    }

    /// Only a certified header of the missing frame that commits to no
    /// requests replaces its body: otherwise replay stops below it and says
    /// why.
    #[tokio::test]
    async fn archive_replay_keeps_waiting_for_a_body_no_carried_header_replaces() {
        let mut with_requests = carried_header(140);
        with_requests.requests_root = vec![7; 32];
        let mut uncertified = carried_header(140);
        uncertified.public_key_signature_bls48581 = None;
        let mut other_shard = carried_header(140);
        other_shard.address = vec![9; 32];
        for (carried, why) in [
            (Some(with_requests), "GLOBAL frame 9146 carries its header, which commits requests only its body holds"),
            (Some(uncertified), "GLOBAL frame 9146 carries its header without a certificate"),
            (Some(other_shard), "GLOBAL frame 9146 carries another frame's header in its place"),
            (Some(carried_header(141)), "GLOBAL frame 9146 carries another frame's header in its place"),
            (Some(quil_types::proto::global::FrameHeader { global_frame_number: 9100, ..carried_header(140) }),
                "GLOBAL frame 9146 carries its header anchored where GLOBAL could not have taken it"),
            (None, "no GLOBAL frame 9140..=9154 carries its header"),
        ] {
            let archive = CarryingArchive::new(140, carried.map(|header| (9146, header)).into_iter().collect());
            let (result, replayed) = replay_carrying(&archive, 130, 130, |_| false).await;
            let error = result.unwrap_err().to_string();
            assert!(error.contains("archive replay is missing shard frame 140 (archive tip Some(200), committed 0): "), "{error}");
            assert!(error.ends_with(why), "{error}");
            assert_eq!(replayed.len(), 9, "replayed up to the frame below it");
        }
    }

    #[tokio::test]
    async fn rejected_archive_chain_never_installs_its_tree() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(600)),
            calls: calls.clone(),
        };
        let result = sync_shard_from_latest(
            &archive,
            &[5; 32],
            Some(frame(130)),
            &[],
            None,
            |_, _| async { Ok(false) },
        )
        .await
        .unwrap();
        assert!(matches!(result, ShardSyncResult::NotReady(_)));
        assert_eq!(*calls.lock().unwrap(), ["fetch 0", "fetch 599"]);
    }

    /// GLOBAL fenced the shard's last session at 505; its committee had
    /// finalized 506 and 507, which archives still serve as the latest and
    /// validation refuses (past the terminal checkpoint). A member without the
    /// shard's data bootstraps from the frame GLOBAL committed instead.
    #[tokio::test]
    async fn a_refused_archive_tip_falls_back_to_the_committed_frame() {
        let validate = |anchor: AppShardFrame, predecessor: Option<AppShardFrame>| {
            let number = anchor.header.unwrap().frame_number;
            assert_eq!(
                predecessor.unwrap().header.unwrap().frame_number,
                number - 1
            );
            async move { Ok(number <= 505) }
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(507)),
            calls: calls.clone(),
        };
        let result = sync_shard_from_latest(&archive, &[5; 32], None, &[], Some(505), validate)
            .await
            .unwrap();
        let ShardSyncResult::Anchored { anchor, .. } = result else {
            panic!("expected the committed frame as the anchor")
        };
        assert_eq!(anchor.header.unwrap().frame_number, 505);
        assert_eq!(
            *calls.lock().unwrap(),
            ["fetch 0", "fetch 506", "fetch 505", "fetch 504", "sync 249"]
        );

        // Without a committed frame below it the refusal stands.
        for committed in [None, Some(0), Some(507)] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let archive = Archive {
                latest: Some(frame(507)),
                calls: calls.clone(),
            };
            let result = sync_shard_from_latest(&archive, &[5; 32], None, &[], committed, validate)
                .await
                .unwrap();
            assert!(matches!(result, ShardSyncResult::NotReady(_)));
            assert_eq!(*calls.lock().unwrap(), ["fetch 0", "fetch 506"]);
        }
    }

    /// A session based at 0 of which GLOBAL executed nothing; the archive's
    /// latest frame (1) is refused. Certified origins pin the base state;
    /// otherwise the refused frame's attested pre-state roots do; with
    /// neither the sync refuses and never takes the archive's subtree
    /// unpinned (the mock panics on an unpinned sync).
    #[tokio::test]
    async fn a_refused_tip_over_an_unexecuted_base_syncs_only_certified_state() {
        let refuse = |_: AppShardFrame, _: Option<AppShardFrame>| async { Ok(false) };

        let anchors = vec![(vec![1; 32], [[0x51; 32]; 4])];
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(1)),
            calls: calls.clone(),
        };
        let result = sync_shard_from_latest(&archive, &[5; 32], None, &anchors, Some(0), refuse)
            .await
            .unwrap();
        assert!(matches!(
            result,
            ShardSyncResult::Inherited { pinned: true }
        ));
        assert_eq!(
            *calls.lock().unwrap(),
            ["fetch 0", "sync 81"],
            "pinned to the origin's sealed roots"
        );

        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(1)),
            calls: calls.clone(),
        };
        let attested = |refused: AppShardFrame| async move {
            assert_eq!(refused.header.unwrap().frame_number, 1);
            Ok(Some(vec![vec![0x22; 32]; 4]))
        };
        let result = sync_shard_from_latest_attested(
            &archive,
            &[5; 32],
            None,
            &[],
            Some(0),
            refuse,
            attested,
        )
        .await
        .unwrap();
        assert!(matches!(
            result,
            ShardSyncResult::Inherited { pinned: true }
        ));
        assert_eq!(
            *calls.lock().unwrap(),
            ["fetch 0", "sync 34"],
            "pinned to the attested pre-state"
        );

        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(1)),
            calls: calls.clone(),
        };
        let result = sync_shard_from_latest_attested(
            &archive,
            &[5; 32],
            None,
            &[],
            Some(0),
            refuse,
            |_| async { Ok(None) },
        )
        .await
        .unwrap();
        assert!(
            matches!(result, ShardSyncResult::NotReady(reason) if reason.contains("nothing certifies"))
        );
        assert_eq!(*calls.lock().unwrap(), ["fetch 0"], "no unpinned sync");

        // A committed frame above 0 keeps its own fallback; nothing is attested.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(507)),
            calls: calls.clone(),
        };
        let never = |_: AppShardFrame| async { panic!("attested only over an unexecuted base 0") };
        let result = sync_shard_from_latest_attested(
            &archive,
            &[5; 32],
            None,
            &[],
            Some(507),
            refuse,
            never,
        )
        .await
        .unwrap();
        assert!(matches!(result, ShardSyncResult::NotReady(_)));
    }

    /// Serves frame 1 as its latest; every pinned tree sync fails (the
    /// archive does not retain that state); an unpinned one panics.
    struct UnretainedArchive {
        calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl ProverTreeSyncer for UnretainedArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
        async fn get_app_shard_frame(
            &self,
            _: &[u8],
            number: u64,
        ) -> Result<Option<AppShardFrame>> {
            self.calls.lock().unwrap().push(format!("fetch {number}"));
            Ok(Some(frame(1)))
        }
        async fn sync_shard_tree(&self, _: &[u8], roots: &[Vec<u8>]) -> Result<bool> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("sync {}", roots[0][0]));
            Ok(false)
        }
    }

    /// Over an unexecuted base 0, an archive that cannot serve the certified
    /// base state leaves the sync not ready; it never falls back to the
    /// archive's current subtree.
    #[tokio::test]
    async fn an_unretained_base_state_is_never_replaced_by_unpinned_state() {
        let refuse = |_: AppShardFrame, _: Option<AppShardFrame>| async { Ok(false) };
        let anchors = vec![(vec![1; 32], [[0x51; 32]; 4])];
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = UnretainedArchive {
            calls: calls.clone(),
        };
        let result = sync_shard_from_latest(&archive, &[5; 32], None, &anchors, Some(0), refuse)
            .await
            .unwrap();
        assert!(
            matches!(result, ShardSyncResult::NotReady(reason) if reason.contains("certified base state"))
        );
        assert_eq!(
            *calls.lock().unwrap(),
            ["fetch 0", "sync 81"],
            "pinned only"
        );

        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = UnretainedArchive {
            calls: calls.clone(),
        };
        let result = sync_shard_from_latest_attested(
            &archive,
            &[5; 32],
            None,
            &[],
            Some(0),
            refuse,
            |_| async { Ok(Some(vec![vec![0x22; 32]; 4])) },
        )
        .await
        .unwrap();
        assert!(
            matches!(result, ShardSyncResult::NotReady(reason) if reason.contains("attested base state"))
        );
        assert_eq!(
            *calls.lock().unwrap(),
            ["fetch 0", "sync 34"],
            "pinned only"
        );
    }

    /// Holds no frame of the shard; records each tree sync as
    /// `(filter's first byte, pinned root's first byte or None)` and refuses
    /// the pinned sync of `refuse`.
    struct FramelessArchive {
        calls: Arc<Mutex<Vec<(u8, Option<u8>)>>>,
        refuse: Option<Vec<u8>>,
    }

    #[async_trait]
    impl ProverTreeSyncer for FramelessArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
        async fn get_app_shard_frame(&self, _: &[u8], _: u64) -> Result<Option<AppShardFrame>> {
            Ok(None)
        }
        async fn sync_shard_tree(&self, filter: &[u8], roots: &[Vec<u8>]) -> Result<bool> {
            self.calls
                .lock()
                .unwrap()
                .push((filter[0], roots.first().map(|root| root[0])));
            Ok(roots.is_empty() || self.refuse.as_deref() != Some(filter))
        }
    }

    /// A shard with no frame of its own syncs each origin's range pinned to
    /// its sealed roots, and inherits the covered subtree unpinned only when
    /// it has no certified origin or the archive cannot serve one.
    #[tokio::test]
    async fn a_frameless_shard_syncs_its_origins_pinned_to_their_sealed_roots() {
        let child = vec![5; 32];
        let (left, right) = (vec![1; 32], vec![2; 32]);
        let anchors = vec![
            (left.clone(), [[0x51; 32]; 4]),
            (right.clone(), [[0x61; 32]; 4]),
        ];
        let never =
            |_: AppShardFrame, _: Option<AppShardFrame>| async { panic!("no frame to validate") };

        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = FramelessArchive {
            calls: calls.clone(),
            refuse: None,
        };
        let result = sync_shard_from_latest(&archive, &child, None, &anchors, None, never)
            .await
            .unwrap();
        assert!(matches!(
            result,
            ShardSyncResult::Inherited { pinned: true }
        ));
        assert_eq!(
            *calls.lock().unwrap(),
            [(1, Some(0x51)), (2, Some(0x61))],
            "pinned, never unpinned"
        );

        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = FramelessArchive {
            calls: calls.clone(),
            refuse: Some(right),
        };
        let result = sync_shard_from_latest(&archive, &child, None, &anchors, None, never)
            .await
            .unwrap();
        assert!(matches!(
            result,
            ShardSyncResult::Inherited { pinned: false }
        ));
        assert_eq!(
            *calls.lock().unwrap(),
            [(1, Some(0x51)), (2, Some(0x61)), (5, None)],
            "falls back when an origin is unavailable"
        );

        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = FramelessArchive {
            calls: calls.clone(),
            refuse: None,
        };
        let result = sync_shard_from_latest(&archive, &child, None, &[], None, never)
            .await
            .unwrap();
        assert!(matches!(
            result,
            ShardSyncResult::Inherited { pinned: false }
        ));
        assert_eq!(
            *calls.lock().unwrap(),
            [(5, None)],
            "no certified origin: unpinned"
        );
    }

    /// A successor of a same-filter predecessor must start from exactly the
    /// predecessor's sealed state (`successor_state_matches`). When no archive
    /// serves it, an unpinned copy would be installed, reported as success and
    /// refused at startup, over and over: recovery waits instead.
    #[tokio::test]
    async fn an_unavailable_same_filter_seal_is_never_replaced_by_unpinned_state() {
        let filter = vec![5; 32];
        let anchors = vec![(filter.clone(), [[0x71; 32]; 4])];
        let never =
            |_: AppShardFrame, _: Option<AppShardFrame>| async { panic!("no frame to validate") };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = FramelessArchive {
            calls: calls.clone(),
            refuse: Some(filter.clone()),
        };
        let result = sync_shard_from_latest(&archive, &filter, None, &anchors, None, never)
            .await
            .unwrap();
        assert!(matches!(result, ShardSyncResult::NotReady(_)));
        assert_eq!(*calls.lock().unwrap(), [(5, Some(0x71))], "pinned only");
    }

    /// Serves frames through 140, reports `tip` as its latest (`None`: no
    /// latest frame indexed) and records each request.
    struct BehindArchive {
        tip: Option<u64>,
        calls: Arc<Mutex<Vec<u64>>>,
    }

    #[async_trait]
    impl ProverTreeSyncer for BehindArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
        async fn get_app_shard_frame(
            &self,
            _: &[u8],
            number: u64,
        ) -> Result<Option<AppShardFrame>> {
            self.calls.lock().unwrap().push(number);
            Ok(match number {
                0 => self.tip.map(frame),
                n if n <= 140 => Some(frame(n)),
                _ => None,
            })
        }
        async fn sync_shard_tree(&self, _: &[u8], _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
    }

    /// An archive whose latest is at or below the worker's head, or that has
    /// none, is not proof the worker is current: GLOBAL's committed session
    /// tip is the target, the tip is probed on further archives, and frames
    /// are requested by number. Past what any archive holds it stops with the
    /// missing frame named, never reporting the worker up to date.
    #[tokio::test]
    async fn replay_targets_the_committed_tip_when_archives_report_an_old_one() {
        for tip in [Some(130), None] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let archive = BehindArchive {
                tip,
                calls: calls.clone(),
            };
            let result = replay_shard_from_latest(
                &archive,
                &[5; 32],
                frame(130),
                130,
                Some(137),
                &CarriedVerifierSource::default(),
                |frame, _| async move { Ok(frame.header.unwrap().frame_number) },
            )
            .await
            .unwrap();
            assert_eq!(
                result,
                ShardReplay {
                    materialized: 137,
                    archive_tip: tip,
                    target: 137
                }
            );
            assert_eq!(
                calls.lock().unwrap()[..TIP_PROBES],
                [0; TIP_PROBES],
                "the tip is asked of more archives"
            );
        }
        let archive = BehindArchive {
            tip: Some(130),
            calls: Arc::new(Mutex::new(Vec::new())),
        };
        let missing = replay_shard_from_latest(
            &archive,
            &[5; 32],
            frame(130),
            130,
            Some(150),
            &CarriedVerifierSource::default(),
            |frame, _| async move { Ok(frame.header.unwrap().frame_number) },
        )
        .await
        .unwrap_err();
        assert!(
            missing.to_string().contains("missing shard frame 141"),
            "{missing}"
        );
    }

    /// An archive serving frames through 130, and frame 131 without a
    /// certificate (a sealed session's last frame), reporting `tip` as latest.
    struct SealedTipArchive {
        tip: u64,
    }

    #[async_trait]
    impl ProverTreeSyncer for SealedTipArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
        async fn get_app_shard_frame(
            &self,
            _: &[u8],
            number: u64,
        ) -> Result<Option<AppShardFrame>> {
            let number = if number == 0 { self.tip } else { number };
            Ok((number <= 131).then(|| {
                let mut served = frame(number);
                if number == 131 {
                    served
                        .header
                        .as_mut()
                        .unwrap()
                        .public_key_signature_bls48581 = None;
                }
                served
            }))
        }
        async fn sync_shard_tree(&self, _: &[u8], _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
    }

    /// GLOBAL's committed tip, made final by a seal, has no certified frame
    /// after it: it is handed to `replay` alone, which authenticates it by
    /// the digest GLOBAL committed. Replay used to stop at it for want of a
    /// certified descendant, whether the archive's tip was the frame below
    /// it or the frame itself (…091f80, frame 4693, 2026-10-20). Any other
    /// frame without a certificate still needs a certified descendant.
    #[tokio::test]
    async fn replay_hands_the_committed_sealed_tip_alone() {
        for tip in [130, 131] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let seen = calls.clone();
            let result = replay_shard_from_latest(
                &SealedTipArchive { tip },
                &[5; 32],
                frame(130),
                130,
                Some(131),
                &CarriedVerifierSource::default(),
                move |frame, descendants| {
                    let height = frame.header.unwrap().frame_number;
                    seen.lock().unwrap().push((height, descendants.len()));
                    async move { Ok(height) }
                },
            )
            .await
            .unwrap();
            assert_eq!(
                result,
                ShardReplay {
                    materialized: 131,
                    archive_tip: Some(tip),
                    target: 131
                }
            );
            assert_eq!(*calls.lock().unwrap(), vec![(131, 0)]);
        }
        for committed in [Some(130), None, Some(132)] {
            let error = replay_shard_from_latest(
                &SealedTipArchive { tip: 131 },
                &[5; 32],
                frame(130),
                130,
                committed,
                &CarriedVerifierSource::default(),
                |_, _| async { panic!("an unauthenticated frame must not reach replay") },
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains("descendant"), "{error}");
        }
    }

    /// Rotate across peer responses even when the local head already covers
    /// GLOBAL. A stale/absent first response must not hide a newer peer head.
    struct RotatingArchive {
        tips: Mutex<std::collections::VecDeque<Option<u64>>>,
        calls: Arc<Mutex<Vec<u64>>>,
    }

    #[async_trait]
    impl ProverTreeSyncer for RotatingArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
        async fn get_app_shard_frame(
            &self,
            _: &[u8],
            number: u64,
        ) -> Result<Option<AppShardFrame>> {
            self.calls.lock().unwrap().push(number);
            Ok(if number == 0 {
                self.tips.lock().unwrap().pop_front().flatten().map(frame)
            } else {
                Some(frame(number))
            })
        }
        async fn sync_shard_tree(&self, _: &[u8], _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn replay_probes_past_stale_peer_when_local_head_covers_global() {
        for first in [Some(83), None] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let archive = RotatingArchive {
                tips: Mutex::new([first, Some(134)].into()),
                calls: calls.clone(),
            };
            let replayed = Arc::new(Mutex::new(Vec::new()));
            let installed = replayed.clone();
            let result = replay_shard_from_latest(
                &archive,
                &[5; 32],
                frame(130),
                130,
                Some(127),
                &CarriedVerifierSource::default(),
                move |frame, _| {
                    let height = frame.header.unwrap().frame_number;
                    installed.lock().unwrap().push(height);
                    async move { Ok(height) }
                },
            )
            .await
            .unwrap();
            assert_eq!(
                result,
                ShardReplay {
                    materialized: 134,
                    archive_tip: Some(134),
                    target: 134
                }
            );
            assert_eq!(*replayed.lock().unwrap(), [131, 132, 133, 134]);
            assert_eq!(*calls.lock().unwrap(), [0, 0, 131, 132, 133]);
        }
    }

    #[tokio::test]
    async fn replay_tip_rotation_is_bounded_and_stops_at_a_current_peer() {
        for (tips, expected_calls, expected_tip) in [
            (vec![Some(83); TIP_PROBES + 1], TIP_PROBES, 83),
            (vec![Some(130), Some(134)], 1, 130),
        ] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let archive = RotatingArchive {
                tips: Mutex::new(tips.into()),
                calls: calls.clone(),
            };
            let result = replay_shard_from_latest(
                &archive,
                &[5; 32],
                frame(130),
                130,
                Some(127),
                &CarriedVerifierSource::default(),
                |_, _| async { panic!("already materialized through the known target") },
            )
            .await
            .unwrap();
            assert_eq!(
                result,
                ShardReplay {
                    materialized: 130,
                    archive_tip: Some(expected_tip),
                    target: 130
                }
            );
            assert_eq!(*calls.lock().unwrap(), vec![0; expected_calls]);
        }
    }

    /// A worker that owes a re-anchor at `fence`, with GLOBAL's committed
    /// frame `committed`; validates frames through `valid_through`.
    struct Reanchoring {
        calls: Arc<Mutex<Vec<String>>>,
        fence: Option<u64>,
        committed: Option<u64>,
        valid_through: u64,
        install_fails: bool,
        elsewhere: bool,
        failures: Mutex<Vec<String>>,
    }

    impl Reanchoring {
        fn new(
            calls: &Arc<Mutex<Vec<String>>>,
            fence: Option<u64>,
            committed: Option<u64>,
        ) -> Self {
            Self {
                calls: calls.clone(),
                fence,
                committed,
                valid_through: 505,
                install_fails: false,
                elsewhere: false,
                failures: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ShardRecoveryTarget for Reanchoring {
        fn materialized(&self) -> u64 {
            507
        }
        async fn replay(&self, frame: AppShardFrame, _: Vec<AppShardFrame>) -> Result<u64> {
            let number = frame.header.unwrap().frame_number;
            self.calls.lock().unwrap().push(format!("replay {number}"));
            Ok(number)
        }
        async fn validate(
            &self,
            anchor: AppShardFrame,
            predecessor: Option<AppShardFrame>,
        ) -> Result<bool> {
            let number = anchor.header.unwrap().frame_number;
            assert_eq!(
                predecessor.unwrap().header.unwrap().frame_number,
                number - 1
            );
            self.calls
                .lock()
                .unwrap()
                .push(format!("validate {number}"));
            Ok(number <= self.valid_through)
        }
        async fn install(&self, anchor: AppShardFrame, _: Option<AppShardFrame>) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("install {}", anchor.header.unwrap().frame_number));
            if self.install_fails {
                return Err(quil_types::error::QuilError::ExecutionUnavailable(
                    "shard engine rejected sync completion".into(),
                ));
            }
            Ok(())
        }
        fn inherited(&self) {
            panic!("a re-anchor never inherits unpinned state")
        }
        async fn committed_tip(&self) -> Option<u64> {
            self.committed
        }
        async fn reanchor_fence(&self) -> ReanchorAttempt {
            match self.fence {
                Some(_) if self.elsewhere => ReanchorAttempt::Elsewhere,
                Some(fence) => ReanchorAttempt::Take(fence),
                None => ReanchorAttempt::NotOwed,
            }
        }
        fn reanchor_failed(&self, reason: String) {
            self.failures.lock().unwrap().push(reason);
        }
    }

    /// GLOBAL fenced the shard's last session at 505; this worker installed
    /// the archive's 507, a frame the fence discarded. It owes a re-anchor:
    /// its lineage is not replayed, and it anchors at the frame GLOBAL
    /// committed (the fence), authenticated, with its trees pinned to that
    /// frame's roots, before the actor installs it. Without a re-anchor the
    /// same worker replays its lineage, as before.
    #[tokio::test]
    async fn a_head_past_the_fence_is_reanchored_at_the_committed_frame_not_replayed() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(507)),
            calls: calls.clone(),
        };
        let target = Reanchoring::new(&calls, Some(505), Some(505));
        let result =
            recover_shard_from_latest(&archive, &[5; 32], Some(frame(507)), &target, &[], None)
                .await
                .unwrap();
        assert_eq!(result, ShardRecoveryProgress::Anchored { frame: 505 });
        assert_eq!(
            *calls.lock().unwrap(),
            [
                "fetch 505",
                "fetch 504",
                "validate 505",
                "sync 249",
                "install 505"
            ]
        );
        assert!(target.failures.lock().unwrap().is_empty());

        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(507)),
            calls: calls.clone(),
        };
        let target = Reanchoring::new(&calls, None, Some(505));
        let result =
            recover_shard_from_latest(&archive, &[5; 32], Some(frame(507)), &target, &[], None)
                .await
                .unwrap();
        assert!(
            matches!(result, ShardRecoveryProgress::Replayed { .. }),
            "{result:?}"
        );
        assert!(
            calls
                .lock()
                .unwrap()
                .iter()
                .all(|call| call.starts_with("fetch 0")),
            "{:?}",
            calls.lock().unwrap()
        );
    }

    /// A re-anchor owed after a persistent replay mismatch records the
    /// cursor as its fence, below the frame GLOBAL committed: it anchors at
    /// that frame, with the trees pinned to its roots, not at the fence.
    #[tokio::test]
    async fn a_reanchor_below_the_committed_frame_anchors_at_it() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(507)),
            calls: calls.clone(),
        };
        let target = Reanchoring::new(&calls, Some(500), Some(505));
        let result =
            recover_shard_from_latest(&archive, &[5; 32], Some(frame(500)), &target, &[], None)
                .await
                .unwrap();
        assert_eq!(result, ShardRecoveryProgress::Anchored { frame: 505 });
        assert_eq!(
            *calls.lock().unwrap(),
            [
                "fetch 505",
                "fetch 504",
                "validate 505",
                "sync 249",
                "install 505"
            ]
        );
    }

    /// Serves certified frames, but its tree sync never reaches their roots.
    struct StatelessArchive {
        calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl ProverTreeSyncer for StatelessArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
        async fn get_app_shard_frame(
            &self,
            _: &[u8],
            number: u64,
        ) -> Result<Option<AppShardFrame>> {
            self.calls.lock().unwrap().push(format!("fetch {number}"));
            Ok(Some(frame(number)))
        }
        async fn sync_shard_tree(&self, _: &[u8], roots: &[Vec<u8>]) -> Result<bool> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("sync {}", roots.first().map_or(0, |root| root[0])));
            Ok(false)
        }
    }

    /// A re-anchor that no archive can serve, or whose frame fails
    /// validation, installs nothing, never syncs unpinned (the shard holds
    /// data, and its successor refuses anything but the committed state),
    /// and tells the actor why.
    #[tokio::test]
    async fn a_reanchor_waits_for_an_archive_rather_than_inherit_unpinned_state() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let frameless = FramelessArchive {
            calls: Arc::new(Mutex::new(Vec::new())),
            refuse: None,
        };
        let target = Reanchoring::new(&calls, Some(505), Some(505));
        let result =
            recover_shard_from_latest(&frameless, &[5; 32], Some(frame(507)), &target, &[], None)
                .await
                .unwrap();
        assert_eq!(
            result,
            ShardRecoveryProgress::NotReady(REANCHOR_UNAVAILABLE)
        );
        assert!(
            frameless.calls.lock().unwrap().is_empty(),
            "no tree sync at all"
        );
        assert_eq!(*target.failures.lock().unwrap(), [REANCHOR_UNAVAILABLE]);

        let calls = Arc::new(Mutex::new(Vec::new()));
        let stateless = StatelessArchive {
            calls: calls.clone(),
        };
        let target = Reanchoring::new(&calls, Some(505), Some(505));
        let result =
            recover_shard_from_latest(&stateless, &[5; 32], Some(frame(507)), &target, &[], None)
                .await
                .unwrap();
        assert_eq!(
            result,
            ShardRecoveryProgress::NotReady(REANCHOR_UNAVAILABLE)
        );
        assert_eq!(
            *calls.lock().unwrap(),
            ["fetch 505", "fetch 504", "validate 505", "sync 249"],
            "never installed"
        );
        assert_eq!(*target.failures.lock().unwrap(), [REANCHOR_UNAVAILABLE]);

        let calls = Arc::new(Mutex::new(Vec::new()));
        let stateless = StatelessArchive {
            calls: calls.clone(),
        };
        let mut target = Reanchoring::new(&calls, Some(505), Some(505));
        target.valid_through = 504;
        let result =
            recover_shard_from_latest(&stateless, &[5; 32], Some(frame(507)), &target, &[], None)
                .await
                .unwrap();
        assert_eq!(result, ShardRecoveryProgress::NotReady(REANCHOR_REFUSED));
        assert_eq!(
            *calls.lock().unwrap(),
            ["fetch 505", "fetch 504", "validate 505"],
            "no tree write"
        );
        assert_eq!(*target.failures.lock().unwrap(), [REANCHOR_REFUSED]);

        let calls = Arc::new(Mutex::new(Vec::new()));
        let stateless = StatelessArchive {
            calls: calls.clone(),
        };
        let target = Reanchoring::new(&calls, Some(505), None);
        let result =
            recover_shard_from_latest(&stateless, &[5; 32], Some(frame(507)), &target, &[], None)
                .await
                .unwrap();
        assert_eq!(result, ShardRecoveryProgress::NotReady(REANCHOR_NO_TIP));
        assert!(
            calls.lock().unwrap().is_empty(),
            "nothing asked of an archive"
        );
        assert_eq!(*target.failures.lock().unwrap(), [REANCHOR_NO_TIP]);

        // A step on this node that fails says so, for the warning's scope.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(507)),
            calls: calls.clone(),
        };
        let mut target = Reanchoring::new(&calls, Some(505), Some(505));
        target.install_fails = true;
        assert!(recover_shard_from_latest(
            &archive,
            &[5; 32],
            Some(frame(507)),
            &target,
            &[],
            None
        )
        .await
        .is_err());
        let failures = target.failures.lock().unwrap();
        assert!(
            failures.len() == 1 && failures[0].contains("re-anchor installation on this node: "),
            "{failures:?}"
        );
        drop(failures);

        // A sync that is not the attempt's touches nothing, lineage or not,
        // and is no failure of the re-anchor.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(507)),
            calls: calls.clone(),
        };
        let mut target = Reanchoring::new(&calls, Some(505), Some(505));
        target.elsewhere = true;
        for local in [Some(frame(507)), None] {
            let result = recover_shard_from_latest(&archive, &[5; 32], local, &target, &[], None)
                .await
                .unwrap();
            assert_eq!(result, ShardRecoveryProgress::Deferred(REANCHOR_ELSEWHERE));
        }
        assert!(
            calls.lock().unwrap().is_empty(),
            "{:?}",
            calls.lock().unwrap()
        );
        assert!(target.failures.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_peer_tip_does_not_turn_an_existing_worker_into_unanchored_bootstrap() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: None,
            calls: calls.clone(),
        };
        let result = sync_shard_from_latest(
            &archive,
            &[5; 32],
            Some(frame(130)),
            &[],
            None,
            |anchor, predecessor| async move {
                assert_eq!(anchor.header.unwrap().frame_number, 130);
                assert_eq!(predecessor.unwrap().header.unwrap().frame_number, 129);
                Ok(false)
            },
        )
        .await
        .unwrap();
        assert!(matches!(result, ShardSyncResult::NotReady(_)));
        assert_eq!(*calls.lock().unwrap(), ["fetch 0", "fetch 129"]);

        // A malformed source must be refused even if the supplied validator
        // would accept; no forest call can be made without four exact roots.
        let mut malformed = frame(600);
        malformed.header.as_mut().unwrap().state_roots[0].pop();
        let archive = Archive {
            latest: Some(malformed),
            calls: calls.clone(),
        };
        assert!(
            sync_shard_from_latest(&archive, &[5; 32], None, &[], None, |_, _| async {
                panic!("malformed anchor reached validator")
            })
            .await
            .is_err()
        );
        assert_eq!(calls.lock().unwrap().last().unwrap(), "fetch 0");
    }

    /// Serves frame 500 as a checkpoint whose tree takes `chunks` chunks of
    /// `chunk` each to install, kept across attempts as the store keeps
    /// them. Like `forest_sync`, a sync whose recovery spent its turn hands
    /// it back between chunks.
    struct ChunkedArchive {
        chunks: u64,
        chunk: std::time::Duration,
        installed: Arc<AtomicU64>,
        /// When each sync started, and the chunks it installed.
        syncs: Arc<Mutex<Vec<(tokio::time::Instant, u64)>>>,
    }

    #[async_trait]
    impl ProverTreeSyncer for ChunkedArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
        async fn get_app_shard_frame(
            &self,
            _: &[u8],
            number: u64,
        ) -> Result<Option<AppShardFrame>> {
            Ok(Some(frame(if number == 0 { 500 } else { number })))
        }
        async fn sync_shard_tree(&self, _: &[u8], _: &[Vec<u8>]) -> Result<bool> {
            let started = tokio::time::Instant::now();
            let mut chunks = 0;
            let result = loop {
                let installed = self.installed.load(Ordering::SeqCst);
                if installed == self.chunks {
                    break Ok(true);
                }
                if crate::worker_execution::recovery_turn_spent() {
                    break Err(crate::worker_execution::turn_spent_error());
                }
                tokio::time::sleep(self.chunk).await;
                self.installed.store(installed + 1, Ordering::SeqCst);
                chunks += 1;
                crate::worker_execution::recovery_installed(1_024);
                crate::worker_execution::recovery_leaves(
                    0,
                    (installed + 1) * 1_024,
                    self.chunks * 1_024,
                );
            };
            self.syncs.lock().unwrap().push((started, chunks));
            result
        }
    }

    /// A checkpoint install three hold limits long hands its turn back at
    /// the limit, so a worker queued behind it is granted within the limit
    /// and one chunk; it queues again and resumes from the chunks it
    /// installed, none installed twice, until the engine installs its
    /// anchor (an operator's node: two installs of 157,076 and
    /// 23,348 leaves held both turns for hours while 89 to 143 waited).
    #[tokio::test(start_paused = true)]
    async fn a_long_install_hands_its_turn_back_and_resumes_from_its_installed_leaves() {
        use crate::recovery_turns::RecoveryTurns;
        let (limit, chunk) = (
            std::time::Duration::from_secs(600),
            std::time::Duration::from_secs(120),
        );
        assert_eq!(crate::recovery_turns::MAX_TURN_HOLD, limit);
        let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(1)));
        let start = tokio::time::Instant::now();
        let run = |core: u32, chunks: u64| {
            let syncs = Arc::new(Mutex::new(Vec::new()));
            let archive = ChunkedArchive {
                chunks,
                chunk,
                installed: Arc::default(),
                syncs: syncs.clone(),
            };
            let task = tokio::spawn(async move {
                let calls = Arc::new(Mutex::new(Vec::new()));
                let target = Target {
                    calls: calls.clone(),
                    cursor: 0.into(),
                    valid: true,
                    install_ok: true,
                    blocked: false.into(),
                    unblock_at: 0,
                };
                let execution = crate::worker_execution::SharedWorkerExecution::default();
                let result = recover_in_turns(
                    turns,
                    &archive,
                    &[5; 32],
                    core,
                    &target,
                    &execution,
                    || Ok(None),
                    || false,
                )
                .await;
                let installed = archive.installed.load(Ordering::SeqCst);
                let calls = calls.lock().unwrap().clone();
                (
                    result,
                    calls,
                    installed,
                    execution.snapshot().recovery.unwrap(),
                )
            });
            (task, syncs)
        };
        let long_chunks = 3 * limit.as_secs() / chunk.as_secs();
        let (long, long_syncs) = run(1, long_chunks);
        tokio::task::yield_now().await;
        let (short, short_syncs) = run(2, 1);
        let (result, calls, installed, record) = long.await.unwrap();
        assert_eq!(
            result.unwrap(),
            ShardRecoveryProgress::Anchored { frame: 500 }
        );
        assert_eq!(installed, long_chunks);
        let syncs = long_syncs.lock().unwrap().clone();
        assert_eq!(
            syncs.iter().map(|(_, chunks)| *chunks).collect::<Vec<_>>(),
            [5, 5, 5],
            "each turn resumes where the last stopped; no chunk is installed twice"
        );
        assert_eq!(
            calls.iter().filter(|call| *call == "install 500").count(),
            1
        );
        assert_eq!((record.attempts, record.consecutive_failures), (3, 0));
        assert!(
            record.last_outcome.contains("frame 500"),
            "{}",
            record.last_outcome
        );
        let (short_result, ..) = short.await.unwrap();
        assert_eq!(
            short_result.unwrap(),
            ShardRecoveryProgress::Anchored { frame: 500 }
        );
        let granted = short_syncs.lock().unwrap()[0]
            .0
            .saturating_duration_since(start);
        assert!(
            granted <= limit + chunk,
            "the waiter was granted after {granted:?}"
        );
    }

    /// Two long installs and six short ones share two turns: each long
    /// install, handing its turn back at the limit, is granted another
    /// within two short installs' turns, and every short install starts
    /// before the long installs are done.
    #[tokio::test(start_paused = true)]
    async fn long_installs_and_the_waiters_behind_them_all_progress() {
        use crate::recovery_turns::RecoveryTurns;
        let (limit, chunk) = (
            std::time::Duration::from_secs(600),
            std::time::Duration::from_secs(120),
        );
        let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(2)));
        let start = tokio::time::Instant::now();
        let mut workers = Vec::new();
        for (core, chunks) in [
            (1, 15),
            (2, 15),
            (3, 1),
            (4, 1),
            (5, 1),
            (6, 1),
            (7, 1),
            (8, 1),
        ] {
            let syncs = Arc::new(Mutex::new(Vec::new()));
            let archive = ChunkedArchive {
                chunks,
                chunk,
                installed: Arc::default(),
                syncs: syncs.clone(),
            };
            let task = tokio::spawn(async move {
                let target = Target {
                    calls: Arc::default(),
                    cursor: 0.into(),
                    valid: true,
                    install_ok: true,
                    blocked: false.into(),
                    unblock_at: 0,
                };
                let execution = crate::worker_execution::SharedWorkerExecution::default();
                recover_in_turns(
                    turns,
                    &archive,
                    &[5; 32],
                    core,
                    &target,
                    &execution,
                    || Ok(None),
                    || false,
                )
                .await
            });
            tokio::task::yield_now().await;
            workers.push((chunks, task, syncs));
        }
        let mut finished = Vec::new();
        let mut short_starts = Vec::new();
        for (chunks, task, syncs) in workers {
            assert_eq!(
                task.await.unwrap().unwrap(),
                ShardRecoveryProgress::Anchored { frame: 500 }
            );
            let syncs: Vec<_> = syncs
                .lock()
                .unwrap()
                .iter()
                .map(|(at, installed)| (at.saturating_duration_since(start), *installed))
                .collect();
            if chunks == 1 {
                short_starts.push(syncs[0].0);
                continue;
            }
            assert_eq!(
                syncs
                    .iter()
                    .map(|(_, installed)| *installed)
                    .collect::<Vec<_>>(),
                [5, 5, 5],
                "{syncs:?}"
            );
            for pair in syncs.windows(2) {
                let handed_back = pair[0].0 + limit;
                assert!(
                    pair[1].0 <= handed_back + chunk * 2,
                    "a long install waited too long for its next turn: {syncs:?}"
                );
            }
            let (last, installed) = *syncs.last().unwrap();
            finished.push(last + chunk * installed as u32);
        }
        let done = finished.into_iter().max().unwrap();
        assert!(
            short_starts.iter().all(|&at| at < done),
            "short installs started {short_starts:?}, long ones done {done:?}"
        );
    }

    /// A worker at its predecessor's sealed checkpoint frame 4693 whose
    /// committed GLOBAL tip is that frame; `mismatches` answers its sealed
    /// state checks in turn: other state there, or the sealed state.
    struct AtSealedCheckpoint {
        calls: Arc<Mutex<Vec<String>>>,
        mismatches: Mutex<std::collections::VecDeque<bool>>,
    }

    impl AtSealedCheckpoint {
        fn new(calls: &Arc<Mutex<Vec<String>>>, mismatches: &[bool]) -> Self {
            Self {
                calls: calls.clone(),
                mismatches: Mutex::new(mismatches.iter().copied().collect()),
            }
        }
    }

    #[async_trait]
    impl ShardRecoveryTarget for AtSealedCheckpoint {
        fn materialized(&self) -> u64 {
            4693
        }
        async fn replay(&self, frame: AppShardFrame, _: Vec<AppShardFrame>) -> Result<u64> {
            let number = frame.header.unwrap().frame_number;
            self.calls.lock().unwrap().push(format!("replay {number}"));
            Ok(number)
        }
        async fn validate(&self, _: AppShardFrame, _: Option<AppShardFrame>) -> Result<bool> {
            unreachable!("a worker with a lineage is not anchored")
        }
        async fn install(&self, _: AppShardFrame, _: Option<AppShardFrame>) -> Result<()> {
            unreachable!("a worker with a lineage is not anchored")
        }
        fn inherited(&self) {
            panic!("the sealed state is installed pinned")
        }
        async fn committed_tip(&self) -> Option<u64> {
            Some(4693)
        }
        async fn sealed_state_mismatch(&self) -> Option<crate::app_handoff::SealedStateMismatch> {
            self.calls.lock().unwrap().push("check".into());
            self.mismatches
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(false)
                .then(|| crate::app_handoff::SealedStateMismatch {
                    generation: 12,
                    frame: 4693,
                    local_roots: [[0x11; 32], [0; 32], [0; 32], [0; 32]],
                    sealed_roots: [[0xa6; 32], [0; 32], [0; 32], [0; 32]],
                })
        }
        fn sealed_state_installed(&self, frame: u64) {
            self.calls
                .lock()
                .unwrap()
                .push(format!("installed {frame}"));
        }
    }

    /// Recover a worker at its predecessor's sealed checkpoint frame 4693
    /// from the archive `archive` makes, `mismatches` answering its sealed
    /// state checks; the outcome, and the worker's and archive's calls.
    async fn recover_at_sealed_checkpoint(
        archive: impl FnOnce(Arc<Mutex<Vec<String>>>) -> Box<dyn ProverTreeSyncer>,
        mismatches: &[bool],
    ) -> (ShardRecoveryProgress, Vec<String>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = archive(calls.clone());
        let target = AtSealedCheckpoint::new(&calls, mismatches);
        let result = recover_shard_from_latest(
            archive.as_ref(),
            &[5; 32],
            Some(frame(4693)),
            &target,
            &[],
            None,
        )
        .await;
        let calls = calls.lock().unwrap().clone();
        (result.unwrap(), calls)
    }

    /// A worker at its predecessor's sealed checkpoint holding other state
    /// there has no frame to replay: recovery reported "replayed to frame
    /// 4693" while the successor's start refused the state, every 10 s for
    /// good (…091f80, 2026-10-23). It syncs the shard pinned to the sealed
    /// roots and tells the actor once its state is the sealed one. An
    /// archive that cannot supply that state, or a sync that leaves other
    /// roots, fails the attempt; a worker holding the sealed state replays.
    #[tokio::test]
    async fn a_worker_at_its_sealed_checkpoint_with_other_state_installs_the_sealed_state() {
        let archive = |calls| -> Box<dyn ProverTreeSyncer> {
            Box::new(Archive {
                latest: Some(frame(4693)),
                calls,
            })
        };
        let (result, calls) = recover_at_sealed_checkpoint(archive, &[true, false]).await;
        assert_eq!(
            result,
            ShardRecoveryProgress::SealedStateInstalled { frame: 4693 }
        );
        assert_eq!(calls, ["check", "sync 166", "check", "installed 4693"]);
        assert_eq!(
            result.to_string(),
            "installed the predecessor's sealed state at frame 4693"
        );

        let (result, calls) =
            recover_at_sealed_checkpoint(|calls| Box::new(StatelessArchive { calls }), &[true])
                .await;
        assert_eq!(
            result,
            ShardRecoveryProgress::NotReady(SEALED_STATE_UNAVAILABLE)
        );
        assert_eq!(calls, ["check", "sync 166"]);
        assert_eq!(
            crate::worker_execution::failure_class(SEALED_STATE_UNAVAILABLE),
            "archive_state"
        );

        let (result, calls) = recover_at_sealed_checkpoint(archive, &[true, true]).await;
        assert_eq!(
            result,
            ShardRecoveryProgress::NotReady(SEALED_STATE_NOT_INSTALLED)
        );
        assert_eq!(calls, ["check", "sync 166", "check"]);

        let (result, calls) = recover_at_sealed_checkpoint(archive, &[false]).await;
        let ShardRecoveryProgress::Replayed {
            materialized, turn, ..
        } = result
        else {
            panic!("expected a replay: {result:?}")
        };
        assert_eq!((materialized, turn.frames), (4693, 0));
        assert_eq!(calls, ["check", "fetch 0"]);
    }

    /// Never answers an installation: an engine busy or wedged.
    struct Wedged(Target);

    #[async_trait]
    impl ShardRecoveryTarget for Wedged {
        fn materialized(&self) -> u64 {
            self.0.materialized()
        }
        async fn replay(
            &self,
            frame: AppShardFrame,
            descendants: Vec<AppShardFrame>,
        ) -> Result<u64> {
            self.0.replay(frame, descendants).await
        }
        async fn validate(
            &self,
            anchor: AppShardFrame,
            predecessor: Option<AppShardFrame>,
        ) -> Result<bool> {
            self.0.validate(anchor, predecessor).await
        }
        async fn install(&self, _: AppShardFrame, _: Option<AppShardFrame>) -> Result<()> {
            std::future::pending().await
        }
        fn inherited(&self) {
            panic!("a certified archive tip must never use unanchored inheritance")
        }
    }

    /// The engine installs an anchor after the turn is released: one that
    /// never answers keeps no other worker from its turn.
    #[tokio::test(start_paused = true)]
    async fn an_installation_that_never_answers_holds_no_turn() {
        use crate::recovery_turns::{Claim, RecoveryKind, RecoveryTurns};
        let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(1)));
        let claim = |core| Claim {
            core,
            filter: vec![5; 32],
            kind: RecoveryKind::Install,
            execution: Default::default(),
            ticket: None,
        };
        let turn = turns.acquire(claim(1)).await;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = calls.clone();
        let installing = tokio::spawn(async move {
            let archive = Archive {
                latest: Some(frame(500)),
                calls: seen.clone(),
            };
            let target = Wedged(Target {
                calls: seen,
                cursor: 0.into(),
                valid: true,
                install_ok: true,
                blocked: false.into(),
                unblock_at: 0,
            });
            recover_shard_from_latest(&archive, &[5; 32], None, &target, &[], Some(turn)).await
        });
        let next =
            tokio::time::timeout(std::time::Duration::from_secs(60), turns.acquire(claim(2))).await;
        assert!(
            next.is_ok(),
            "the turn was released before the engine's installation"
        );
        assert_eq!(
            calls.lock().unwrap().last().map(String::as_str),
            Some("sync 244")
        );
        assert!(!installing.is_finished());
        installing.abort();
    }

    /// A re-anchor whose tree sync handed its turn back is neither failed
    /// nor done: its attempt goes to the next sync.
    #[tokio::test]
    async fn a_reanchor_that_hands_its_turn_back_is_not_a_failure() {
        struct Spent;
        #[async_trait]
        impl ProverTreeSyncer for Spent {
            async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> {
                unreachable!()
            }
            async fn get_app_shard_frame(
                &self,
                _: &[u8],
                number: u64,
            ) -> Result<Option<AppShardFrame>> {
                Ok(Some(frame(number)))
            }
            async fn sync_shard_tree(&self, _: &[u8], _: &[Vec<u8>]) -> Result<bool> {
                Err(crate::worker_execution::turn_spent_error())
            }
        }
        let calls = Arc::new(Mutex::new(Vec::new()));
        let target = Reanchoring::new(&calls, Some(505), Some(505));
        let result =
            recover_shard_from_latest(&Spent, &[5; 32], Some(frame(507)), &target, &[], None).await;
        assert_eq!(result.unwrap(), ShardRecoveryProgress::Yielded);
        assert!(target.failures.lock().unwrap().is_empty());
        assert!(!calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call.starts_with("install")));
    }

    /// Refuses its first `refusals` replays with a GLOBAL state sync's wait,
    /// as an engine does while its master installs the GLOBAL prover tree,
    /// then replays as `Target` does.
    struct SyncInstalling {
        inner: Target,
        refusals: std::sync::atomic::AtomicUsize,
        refused: std::sync::atomic::AtomicUsize,
    }

    impl SyncInstalling {
        fn new(inner: Target, refusals: usize) -> Self {
            Self {
                inner,
                refusals: refusals.into(),
                refused: 0.into(),
            }
        }
    }

    #[async_trait]
    impl ShardRecoveryTarget for SyncInstalling {
        fn materialized(&self) -> u64 {
            self.inner.materialized()
        }
        async fn replay(
            &self,
            frame: AppShardFrame,
            descendants: Vec<AppShardFrame>,
        ) -> Result<u64> {
            use std::sync::atomic::Ordering::SeqCst;
            if self.refusals.load(SeqCst) > 0 {
                self.refusals.fetch_sub(1, SeqCst);
                self.refused.fetch_add(1, SeqCst);
                return Err(quil_types::error::QuilError::ExecutionUnavailable(
                    quil_execution::global_intrinsic::handoff::GLOBAL_SYNC_IN_PROGRESS.into(),
                ));
            }
            self.inner.replay(frame, descendants).await
        }
        async fn validate(
            &self,
            anchor: AppShardFrame,
            predecessor: Option<AppShardFrame>,
        ) -> Result<bool> {
            self.inner.validate(anchor, predecessor).await
        }
        async fn install(
            &self,
            anchor: AppShardFrame,
            predecessor: Option<AppShardFrame>,
        ) -> Result<()> {
            self.inner.install(anchor, predecessor).await
        }
        fn inherited(&self) {
            panic!("a certified archive tip must never use unanchored inheritance")
        }
    }

    fn replaying_target(calls: &Arc<Mutex<Vec<String>>>) -> Target {
        Target {
            calls: calls.clone(),
            cursor: 129.into(),
            valid: false,
            install_ok: false,
            blocked: false.into(),
            unblock_at: 0,
        }
    }

    /// A replay refused while this node's master installs a GLOBAL state sync
    /// waits the install out within its attempt and goes on once it is in:
    /// the attempt replays its batch and counts no failure. It failed the
    /// attempt, its worker handed its recovery turn back and queued behind
    /// every other, and on a node whose installs took 250 to 580 s of every 8
    /// to 10 minutes 30 of 73 successor sessions stayed blocked below their
    /// predecessor's seal (2026-10-26).
    #[tokio::test(start_paused = true)]
    async fn a_replay_waits_out_a_global_sync_install_and_counts_no_failure() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(500)),
            calls: calls.clone(),
        };
        let target = SyncInstalling::new(replaying_target(&calls), 5);
        let worker = crate::worker_execution::SharedWorkerExecution::default();
        let started = tokio::time::Instant::now();
        let result = worker
            .recovering(
                &[5; 32],
                recover_shard_from_latest(&archive, &[5; 32], Some(frame(130)), &target, &[], None),
            )
            .await
            .unwrap();
        let ShardRecoveryProgress::Replayed {
            materialized, turn, ..
        } = result
        else {
            panic!("expected a replay: {result:?}")
        };
        assert_eq!((materialized, turn.frames), (161, 32));
        assert_eq!(target.refused.load(std::sync::atomic::Ordering::SeqCst), 5);
        let waited = started.elapsed();
        assert!(
            waited >= 5 * GLOBAL_SYNC_POLL && waited < GLOBAL_SYNC_WAIT_BUDGET,
            "{waited:?}"
        );
        let recovery = worker.snapshot().recovery.unwrap();
        assert_eq!(
            (recovery.consecutive_failures, recovery.last_error_unix_ms),
            (0, 0)
        );
        assert!(
            recovery.failures_by_class.is_empty(),
            "{:?}",
            recovery.failures_by_class
        );
    }

    /// An install that does not finish within the attempt's budget fails the
    /// attempt with its wait, as before, once the budget is spent: the turn
    /// is held no longer than [`GLOBAL_SYNC_WAIT_BUDGET`].
    #[tokio::test(start_paused = true)]
    async fn a_global_sync_install_past_the_budget_fails_the_attempt() {
        use quil_execution::global_intrinsic::handoff::global_sync_in_progress;
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive {
            latest: Some(frame(500)),
            calls: calls.clone(),
        };
        let target = SyncInstalling::new(replaying_target(&calls), usize::MAX);
        let worker = crate::worker_execution::SharedWorkerExecution::default();
        let started = tokio::time::Instant::now();
        let error = worker
            .recovering(
                &[5; 32],
                recover_shard_from_latest(&archive, &[5; 32], Some(frame(130)), &target, &[], None),
            )
            .await
            .unwrap_err();
        assert!(global_sync_in_progress(&error), "{error}");
        let waited = started.elapsed();
        assert!(
            waited >= GLOBAL_SYNC_WAIT_BUDGET - GLOBAL_SYNC_POLL
                && waited <= GLOBAL_SYNC_WAIT_BUDGET + GLOBAL_SYNC_POLL,
            "{waited:?}"
        );
        assert!(
            target.refused.load(std::sync::atomic::Ordering::SeqCst)
                > (GLOBAL_SYNC_WAIT_BUDGET.as_secs() / GLOBAL_SYNC_POLL.as_secs()) as usize
        );
        assert_eq!(target.materialized(), 129);
        let recovery = worker.snapshot().recovery.unwrap();
        assert_eq!(recovery.consecutive_failures, 1);
    }

    /// An archive serving the shard's frames through `tip` except
    /// `missing`, each anchored to the GLOBAL frame 1000 above its number,
    /// whose GLOBAL frames carry no header of the missing one: a frame no
    /// archive served below a predecessor's seal (2026-10-27). Counts its
    /// frame reads.
    struct GapArchive {
        tip: AtomicU64,
        missing: u64,
        reads: AtomicU64,
    }

    fn gap_frame(number: u64) -> AppShardFrame {
        let mut frame = frame(number);
        frame.header.as_mut().unwrap().global_frame_number = 1000 + number;
        frame
    }

    #[async_trait]
    impl ProverTreeSyncer for GapArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> {
            unreachable!()
        }
        async fn get_app_shard_frame(
            &self,
            _: &[u8],
            number: u64,
        ) -> Result<Option<AppShardFrame>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let number = match number {
                0 => self.tip.load(Ordering::SeqCst),
                number => number,
            };
            Ok((number != self.missing).then(|| gap_frame(number)))
        }
    }

    /// A worker materialized through `cursor` whose session GLOBAL has
    /// executed through `committed`.
    struct GapTarget {
        cursor: AtomicU64,
        committed: AtomicU64,
    }

    #[async_trait]
    impl ShardRecoveryTarget for GapTarget {
        fn materialized(&self) -> u64 {
            self.cursor.load(Ordering::SeqCst)
        }
        async fn replay(&self, frame: AppShardFrame, _: Vec<AppShardFrame>) -> Result<u64> {
            let number = frame.header.unwrap().frame_number;
            self.cursor.store(number, Ordering::SeqCst);
            Ok(number)
        }
        async fn validate(&self, _: AppShardFrame, _: Option<AppShardFrame>) -> Result<bool> {
            unreachable!("a worker with a lineage replays")
        }
        async fn install(&self, _: AppShardFrame, _: Option<AppShardFrame>) -> Result<()> {
            unreachable!("a worker with a lineage replays")
        }
        fn inherited(&self) {
            unreachable!("a worker with a lineage replays")
        }
        async fn committed_tip(&self) -> Option<u64> {
            Some(self.committed.load(Ordering::SeqCst))
        }
    }

    /// Recovery of the worker's shard, requested as its engine requests it
    /// while its successor session cannot start: at every start retry, 10 s
    /// apart, for `secs`, each once the one before it has ended.
    async fn request_recovery_every_10s(
        turns: &crate::recovery_turns::RecoveryTurns,
        archive: &GapArchive,
        target: &GapTarget,
        execution: &crate::worker_execution::SharedWorkerExecution,
        secs: u64,
    ) {
        let until = tokio::time::Instant::now() + std::time::Duration::from_secs(secs);
        while tokio::time::Instant::now() < until {
            let _ = recover_in_turns(
                turns,
                archive,
                &[5; 32],
                1,
                target,
                execution,
                || Ok(Some(gap_frame(target.materialized()))),
                || false,
            )
            .await;
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    }

    /// A recovery whose attempts stop at a shard frame no archive serves,
    /// requested at each 10 s start retry of its engine, backs off rather
    /// than reading the archives and taking a recovery turn every time: at
    /// most 6 attempts in 5 minutes, where it made one per request (30).
    #[tokio::test(start_paused = true)]
    async fn a_recovery_stopped_at_a_frame_no_archive_serves_backs_off() {
        use crate::recovery_turns::RecoveryTurns;
        let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(1)));
        let archive = GapArchive {
            tip: 200.into(),
            missing: 170,
            reads: 0.into(),
        };
        let target = GapTarget {
            cursor: 169.into(),
            committed: 200.into(),
        };
        let execution = crate::worker_execution::SharedWorkerExecution::default();
        request_recovery_every_10s(turns, &archive, &target, &execution, 300).await;
        let recovery = execution.snapshot().recovery.unwrap();
        assert!(
            recovery.last_error.contains(
                "archive replay is missing shard frame 170 (archive tip Some(200), committed 200): \
                 no GLOBAL frame "
            ),
            "{}",
            recovery.last_error
        );
        assert_eq!(target.materialized(), 169);
        let reads = archive.reads.load(Ordering::SeqCst);
        assert!(
            recovery.attempts <= 6,
            "futile recovery not backed off: {} attempts and {reads} archive frame reads in 300 s, \
             every one stopped at frame 170, which no archive serves",
            recovery.attempts
        );
    }

    /// The back-off of a recovery stopped at a frame no archive serves ends
    /// at once when GLOBAL's committed tip of the session moves, and when an
    /// attempt finds a higher archive tip: the request after it attempts
    /// again rather than waiting twice as long.
    #[tokio::test(start_paused = true)]
    async fn an_archive_gap_backoff_ends_when_the_committed_or_an_archive_tip_moves() {
        use crate::recovery_turns::RecoveryTurns;
        let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(1)));
        let archive = GapArchive {
            tip: 200.into(),
            missing: 170,
            reads: 0.into(),
        };
        let target = GapTarget {
            cursor: 169.into(),
            committed: 200.into(),
        };
        let execution = crate::worker_execution::SharedWorkerExecution::default();
        let attempts = || execution.snapshot().recovery.map_or(0, |r| r.attempts);
        // Attempts at 0, 10, 40, 100 and 220 s; held until 460 s.
        request_recovery_every_10s(turns, &archive, &target, &execution, 300).await;
        assert_eq!(attempts(), 5);
        assert!(execution.archive_gap_holding(&[5; 32]));
        // GLOBAL executed another frame of the session: the request at 300 s
        // attempts at once, a new streak's first failure, retried at 310 s,
        // which backs off until 340 s.
        target.committed.store(201, Ordering::SeqCst);
        request_recovery_every_10s(turns, &archive, &target, &execution, 20).await;
        assert_eq!(attempts(), 7);
        request_recovery_every_10s(turns, &archive, &target, &execution, 20).await;
        assert_eq!(attempts(), 7, "held at 320 and 330 s");
        // An archive's tip moved while it was held: the attempt at 340 s
        // finds it and starts a new streak, retried at 350 s; without the
        // new tip, 350 s would wait for 400 s.
        archive.tip.store(210, Ordering::SeqCst);
        request_recovery_every_10s(turns, &archive, &target, &execution, 20).await;
        assert_eq!(attempts(), 9);
        let recovery = execution.snapshot().recovery.unwrap();
        assert!(
            recovery
                .last_error
                .contains("missing shard frame 170 (archive tip Some(210), committed 201)"),
            "{}",
            recovery.last_error
        );
        assert!(execution.archive_gap_holding(&[5; 32]));
    }

    /// The frame, archive tip and committed tip of a replay stopped at a
    /// frame no archive serves read back from its error, as it reaches the
    /// worker's record, and only from that error.
    #[test]
    fn an_archive_gap_reads_back_from_its_error() {
        let gap = ArchiveGap {
            frame: 20784,
            archive_tip: Some(20982),
            committed: 20982,
        };
        let why = "no GLOBAL frame 940838..=941050 carries its header";
        for descendant in [false, true] {
            let error = missing_frame(gap, descendant, why.into()).to_string();
            assert_eq!(archive_gap(&error), Some(gap), "{error}");
            assert_eq!(
                crate::worker_execution::failure_class(&error),
                "archive_state"
            );
        }
        assert_eq!(
            archive_gap(
                "execution unavailable: archive replay is missing shard frame 20784 (archive tip \
                 Some(20982), committed 20982): no GLOBAL frame 940838..=941050 carries its header"
            ),
            Some(gap)
        );
        let unknown = ArchiveGap {
            archive_tip: None,
            committed: 0,
            ..gap
        };
        let nested = "a frame (archive tip Some(1), committed 2): elsewhere";
        assert_eq!(
            archive_gap(&missing_frame(unknown, false, nested.into()).to_string()),
            Some(unknown)
        );
        for other in [
            "execution unavailable: archive replay has no certified descendant within its target",
            "execution unavailable: archive replay is missing shard frame 8",
            SEALED_STATE_UNAVAILABLE,
            REANCHOR_UNAVAILABLE,
        ] {
            assert_eq!(archive_gap(other), None, "{other}");
        }
    }
}

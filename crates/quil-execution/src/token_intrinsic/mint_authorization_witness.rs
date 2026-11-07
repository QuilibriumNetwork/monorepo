//! Historical receipt lookup. The caller verifies authorization fields; this
//! endpoint cannot attest whether the app has already consumed the receipt.
use crate::hypergraph_state::HypergraphState;
use quil_types::{
    error::{QuilError, Result},
    proto::node::MintAuthorizationState,
    store::{ClockStore, MintAuthorizationStatusData, MintAuthorizationWitnessData},
};
use std::sync::atomic::{AtomicU64, Ordering};

/// Claim attempts that find no receipt log one line per this many seconds: a
/// client retrying in a loop must not fill the node's log.
const CLAIM_WAIT_LOG_EVERY_SECS: u64 = 60;

/// Rate limit of the claim-wait line.
#[derive(Default)]
struct ClaimWaitLog {
    /// When the last line was logged, in seconds after the process's start,
    /// plus one (0: never).
    last: AtomicU64,
    suppressed: AtomicU64,
}

impl ClaimWaitLog {
    /// `Some(lines suppressed since the last one)` when a line is due at `now`.
    fn admit(&self, now: u64) -> Option<u64> {
        let last = self.last.load(Ordering::Relaxed);
        let due =
            last == 0 || now.saturating_add(1).saturating_sub(last) >= CLAIM_WAIT_LOG_EVERY_SECS;
        if due
            && self
                .last
                .compare_exchange(
                    last,
                    now.saturating_add(1),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            return Some(self.suppressed.swap(0, Ordering::Relaxed));
        }
        self.suppressed.fetch_add(1, Ordering::Relaxed);
        None
    }
}

static CLAIM_WAIT_LOG: ClaimWaitLog = ClaimWaitLog {
    last: AtomicU64::new(0),
    suppressed: AtomicU64::new(0),
};

fn seconds_since_start() -> u64 {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_secs()
}

/// The newest global frame a claim through this node may cite, and whether it
/// comes from a QUIL shard's anchor. The claim executes in an app-shard frame
/// and is rejected if it cites a global frame after that frame's anchor.
/// Anchors only grow, so citing at or before the shard's latest certified
/// anchor is always admissible. Without a shard view, fall back to a lag behind
/// the global head.
fn claim_cap(clock: &dyn ClockStore, shard_anchor: Option<u64>) -> Result<(u64, bool)> {
    Ok(match shard_anchor {
        Some(anchor) => (anchor, true),
        None => (
            clock
                .get_latest_global_clock_frame()?
                .header
                .map(|h| h.frame_number)
                .unwrap_or(0)
                .saturating_sub(super::constants::MINT_CLAIM_CITATION_LAG),
            false,
        ),
    })
}

fn cap_source(from_shard_anchor: bool) -> &'static str {
    if from_shard_anchor {
        "slowest QUIL worker anchor"
    } else {
        "head minus citation lag"
    }
}

/// The witness at the newest retained root at or below `cap`, with that root's
/// frame.
fn witness_at_cap(
    state: &HypergraphState,
    clock: &dyn ClockStore,
    receipt: &[u8; 32],
    cap: u64,
) -> Result<(u64, MintAuthorizationWitnessData)> {
    let unavailable = |message: &str| {
        QuilError::ExecutionUnavailable(format!("mint authorization witness: {message}"))
    };
    // Same citation rule as the reward witness: the newest global frame whose
    // root this node retains (a syncing node rarely holds the latest root).
    let (root, header) =
        super::reward_witness::newest_retained_global_root(state, clock, Some(cap))
            .map_err(|e| unavailable(&e.to_string()))?;
    let Some(proof) = state
        .crdt()
        .global_vertex_membership_at_root(&root, receipt)?
    else {
        return Ok((header.frame_number, MintAuthorizationWitnessData::default()));
    };
    let limit = super::reward_witness::MAX_REWARD_PROOF_BYTES;
    if proof.vertex_blob.len() > limit {
        return Err(unavailable("receipt record exceeds witness limit"));
    }
    let proof = quil_forest::MembershipProof {
        inputs: vec![proof],
    }
    .to_bytes();
    if proof.len() > limit {
        return Err(unavailable("membership proof exceeds witness limit"));
    }
    Ok((
        header.frame_number,
        MintAuthorizationWitnessData {
            found: true,
            forest_proof: proof,
            cited_frame: header.frame_number,
            global_root: root.to_vec(),
        },
    ))
}

pub fn witness(
    state: &HypergraphState,
    clock: &dyn ClockStore,
    receipt: &[u8; 32],
    // The QUIL shard's latest certified global anchor, when this node runs
    // or reaches a QUIL shard engine. Later frames anchor at or after it.
    shard_anchor: Option<u64>,
) -> Result<MintAuthorizationWitnessData> {
    witness_logged(state, clock, receipt, shard_anchor, &CLAIM_WAIT_LOG)
}

fn witness_logged(
    state: &HypergraphState,
    clock: &dyn ClockStore,
    receipt: &[u8; 32],
    shard_anchor: Option<u64>,
    log: &ClaimWaitLog,
) -> Result<MintAuthorizationWitnessData> {
    let (cap, from_anchor) = claim_cap(clock, shard_anchor)?;
    let result = witness_at_cap(state, clock, receipt, cap);
    let searched = match &result {
        Ok((_, witness)) if witness.found => None,
        Ok((frame, _)) => Some(Some(*frame)),
        Err(error) if error.is_execution_unavailable() => Some(None),
        Err(_) => None,
    };
    if let Some(searched) = searched {
        if let Some(suppressed) = log.admit(seconds_since_start()) {
            let reason = if searched.is_some() {
                "receipt is not in the newest retained global root at or below the cap"
            } else {
                "this node retains no global root at or below the cap"
            };
            tracing::info!(
                receipt = %hex::encode(receipt),
                searched_frame = searched.unwrap_or(0),
                cap,
                cap_source = cap_source(from_anchor),
                suppressed,
                reason,
                ends_when = "the authorization is included and a retained root at or below \
                             the cap holds it; GetMintAuthorizationStatus tells which is missing",
                "mint claim: no citable authorization yet"
            );
        }
    }
    result.map(|(_, witness)| witness)
}

/// Why a claim through this node can or cannot be made now, for the
/// `GetMintAuthorizationStatus` RPC only. Bounded: one read per frame of the
/// lookback (headers only) plus a binary search over the retained roots in it,
/// each probe holding the commit lock for two point reads. Writes nothing.
pub fn status(
    state: &HypergraphState,
    clock: &dyn ClockStore,
    receipt: &[u8; 32],
    shard_anchor: Option<u64>,
) -> Result<MintAuthorizationStatusData> {
    let head = clock
        .get_latest_global_clock_frame()?
        .header
        .map(|h| h.frame_number)
        .unwrap_or(0);
    let (cap, from_anchor) = claim_cap(clock, shard_anchor)?;
    let mut out = MintAuthorizationStatusData {
        claim_cap: cap.min(head),
        cap_from_shard_anchor: from_anchor,
        head_frame: head,
        ..Default::default()
    };
    let at_cap = retained(witness_at_cap(state, clock, receipt, cap))?;
    if let Some((frame, _)) = &at_cap {
        out.cited_frame = *frame;
    }
    // The newest root known to hold the receipt, starting the inclusion search.
    let holding = match at_cap {
        Some((frame, witness)) if witness.found => {
            out.state = MintAuthorizationState::Claimable;
            Some(frame)
        }
        at_cap => {
            match retained(super::reward_witness::newest_retained_global_root(
                state, clock, None,
            ))? {
                None => {
                    out.state = MintAuthorizationState::NoRetainedRoot;
                    None
                }
                Some((root, header)) => {
                    out.searched_frame = header.frame_number;
                    if retained(state.crdt().global_vertex_present_at_root(&root, receipt))?
                        .unwrap_or(false)
                    {
                        out.state = if at_cap.is_some() {
                            MintAuthorizationState::AwaitingCitableRoot
                        } else {
                            MintAuthorizationState::NoCitableRoot
                        };
                        Some(header.frame_number)
                    } else {
                        out.state = MintAuthorizationState::NotIncluded;
                        None
                    }
                }
            }
        }
    };
    if let Some(holding) = holding {
        out.found = true;
        if out.searched_frame == 0 {
            out.searched_frame = holding;
        }
        let (first, earliest) = first_root_holding(state, clock, receipt, holding);
        out.first_root_frame = first;
        // A header carries its parent's root: first in the root of frame F
        // means executed at frame F-1 or earlier.
        out.inclusion_frame = first.saturating_sub(1);
        out.inclusion_frame_earliest = earliest;
    }
    out.reason = reason(&out);
    Ok(out)
}

/// `Ok(None)` when the history asked for is not retained here.
fn retained<T>(result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.is_execution_unavailable() => Ok(None),
        Err(error) => Err(error),
    }
}

/// The first retained root in the lookback below `holding` that holds the
/// receipt, and the earliest frame its inclusion may be (the newest retained
/// root lacking it; 0 when none does).
fn first_root_holding(
    state: &HypergraphState,
    clock: &dyn ClockStore,
    receipt: &[u8; 32],
    holding: u64,
) -> (u64, u64) {
    let start = holding.saturating_sub(super::reward_witness::REWARD_WITNESS_LOOKBACK_FRAMES);
    let mut roots: Vec<(u64, [u8; 32])> = (start..holding)
        .filter_map(|frame| {
            let header = clock.get_global_clock_frame_header(frame).ok()?;
            let root = super::reward_witness::retained_header_root(state, &header).ok()??;
            Some((frame, root))
        })
        .collect();
    // `holding` is known to hold the receipt: the search never probes its root.
    roots.push((holding, [0; 32]));
    let frames: Vec<u64> = roots.iter().map(|(frame, _)| *frame).collect();
    first_holding(&frames, |frame| {
        let index = frames.binary_search(&frame).ok()?;
        state
            .crdt()
            .global_vertex_present_at_root(&roots[index].1, receipt)
            .ok()
    })
}

/// Over ascending `frames` whose last holds the receipt: the first frame
/// holding it and the last frame seen lacking it (0 if none). A receipt, once
/// written, stays, so a binary search takes at most log2(frames) probes.
/// `holds` answers `None` for a root pruned meanwhile, which is treated as
/// lacking it without being evidence of absence.
fn first_holding(frames: &[u64], mut holds: impl FnMut(u64) -> Option<bool>) -> (u64, u64) {
    let (mut low, mut high, mut lacking) = (0, frames.len() - 1, 0);
    while low < high {
        let middle = low + (high - low) / 2;
        match holds(frames[middle]) {
            Some(true) => high = middle,
            Some(false) => {
                lacking = frames[middle];
                low = middle + 1;
            }
            None => low = middle + 1,
        }
    }
    (frames[high], lacking)
}

fn reason(status: &MintAuthorizationStatusData) -> String {
    let included = if status.inclusion_frame_earliest == status.inclusion_frame {
        format!("included at GLOBAL frame {}", status.inclusion_frame)
    } else if status.inclusion_frame_earliest == 0 {
        format!(
            "included at or before GLOBAL frame {}",
            status.inclusion_frame
        )
    } else {
        format!(
            "included between GLOBAL frames {} and {}",
            status.inclusion_frame_earliest, status.inclusion_frame
        )
    };
    let cap = format!(
        "claim cap {} ({}; head {})",
        status.claim_cap,
        cap_source(status.cap_from_shard_anchor),
        status.head_frame
    );
    match status.state {
        MintAuthorizationState::Unspecified => String::new(),
        MintAuthorizationState::Claimable => format!(
            "{included}; a claim can cite GLOBAL frame {}; {cap}. This node cannot tell whether \
             it was already claimed",
            status.cited_frame
        ),
        MintAuthorizationState::AwaitingCitableRoot => format!(
            "{included}; a claim must cite frame {} or later, but the newest retained root at or \
             below the {cap} is frame {}. Ends when a retained root at or below the cap holds it",
            status.first_root_frame, status.cited_frame
        ),
        MintAuthorizationState::NotIncluded => format!(
            "not in the root of GLOBAL frame {}, the newest retained: not yet included, or \
             rejected at execution ({cap}). Ends with inclusion; if GLOBAL has moved well past \
             the submission, check its frames' outcomes and whether the reward was debited, and \
             mint again if not",
            status.searched_frame
        ),
        MintAuthorizationState::NoCitableRoot => format!(
            "{included}, but this node retains no global root at or below the {cap}. Ends when \
             its QUIL workers' anchors reach a retained root"
        ),
        MintAuthorizationState::NoRetainedRoot => format!(
            "this node retains no recent global root ({cap}): it is syncing or has pruned them. \
             Ends when it retains a root; another node can answer meanwhile"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{domains, hypergraph_state::vertex_adds_discriminator};
    use quil_types::{
        crypto::NoopInclusionProver,
        proto::global::{GlobalFrame, GlobalFrameHeader},
        store::ShardKey,
    };
    use std::sync::{Arc, Mutex};

    const RECEIPT: [u8; 32] = [7; 32];
    const INCLUDED_AT: u64 = 12;

    struct Chain {
        _directory: tempfile::TempDir,
        state: HypergraphState,
        clock: Arc<quil_store::testing::InMemoryClockStore>,
    }

    /// Frames 10..=14 execute, one vertex each, the receipt at `INCLUDED_AT`.
    /// As on mainnet, frame F+1's header carries the root after frame F, so
    /// headers 11..=15 name retained roots and 15 is the head.
    fn chain() -> Chain {
        let directory = tempfile::tempdir().unwrap();
        let db = quil_store::RocksDb::open(directory.path()).unwrap();
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
            Arc::new(NoopInclusionProver),
        ));
        crdt.set_forest(quil_forest::Forest::new(db.inner()));
        let state = HypergraphState::new(crdt.clone());
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let disc = vertex_adds_discriminator().unwrap();
        for frame in 10..=14u64 {
            let address = if frame == INCLUDED_AT {
                RECEIPT
            } else {
                [frame as u8; 32]
            };
            let mut tree = quil_tries::VectorCommitmentTree::new();
            tree.insert(&[0], &[frame as u8], &[], &num_bigint::BigInt::from(1))
                .unwrap();
            let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
            state
                .set(&domains::GLOBAL, &address, &disc, frame, blob)
                .unwrap();
            state.commit().unwrap();
            crdt.commit(frame).unwrap();
            let root = crdt.compute_shard_root(
                "vertex",
                "adds",
                &ShardKey {
                    l1: [0; 3],
                    l2: domains::GLOBAL,
                },
            );
            clock.seed_frame(GlobalFrame {
                header: Some(GlobalFrameHeader {
                    frame_number: frame + 1,
                    prover_tree_commitment: root,
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
        Chain {
            _directory: directory,
            state,
            clock,
        }
    }

    fn status_of(
        chain: &Chain,
        receipt: &[u8; 32],
        anchor: Option<u64>,
    ) -> MintAuthorizationStatusData {
        status(&chain.state, chain.clock.as_ref(), receipt, anchor).unwrap()
    }

    #[test]
    fn claimable_once_a_root_at_or_below_the_cap_holds_the_receipt() {
        let chain = chain();
        // The first root holding it is frame 13's, so 13 is the lowest cap
        // that can claim it.
        for (anchor, cited) in [(13, 13), (14, 14), (99, 15)] {
            let status = status_of(&chain, &RECEIPT, Some(anchor));
            assert_eq!(status.state, MintAuthorizationState::Claimable, "{anchor}");
            assert!(status.found);
            assert_eq!(status.cited_frame, cited);
            assert_eq!(status.first_root_frame, 13);
            assert_eq!(status.inclusion_frame, INCLUDED_AT);
            assert_eq!(status.inclusion_frame_earliest, INCLUDED_AT);
            assert_eq!(status.claim_cap, anchor.min(15));
            assert!(status.cap_from_shard_anchor);
            assert!(status.reason.contains("included at GLOBAL frame 12"));
            // Its verdict is the claim path's own.
            assert!(
                witness(&chain.state, chain.clock.as_ref(), &RECEIPT, Some(anchor))
                    .unwrap()
                    .found
            );
        }
    }

    #[test]
    fn included_above_the_cap_waits_for_a_citable_root_and_says_so() {
        let chain = chain();
        let status = status_of(&chain, &RECEIPT, Some(12));
        assert_eq!(status.state, MintAuthorizationState::AwaitingCitableRoot);
        assert!(status.found);
        assert_eq!(status.cited_frame, 12);
        assert_eq!(status.searched_frame, 15);
        assert_eq!(status.first_root_frame, 13);
        assert_eq!(status.inclusion_frame, INCLUDED_AT);
        assert_eq!(status.claim_cap, 12);
        assert!(status.reason.contains("must cite frame 13 or later"));
        assert!(status.reason.contains("slowest QUIL worker anchor"));
        assert!(
            !witness(&chain.state, chain.clock.as_ref(), &RECEIPT, Some(12))
                .unwrap()
                .found
        );
    }

    #[test]
    fn without_a_shard_view_the_cap_is_the_head_minus_the_lag() {
        let chain = chain();
        // Head 15 less the lag of 8: below every retained root.
        let status = status_of(&chain, &RECEIPT, None);
        assert_eq!(status.claim_cap, 7);
        assert!(!status.cap_from_shard_anchor);
        assert_eq!(status.state, MintAuthorizationState::NoCitableRoot);
        assert_eq!(status.cited_frame, 0);
        assert_eq!(status.first_root_frame, 13);
        assert!(status.reason.contains("head minus citation lag"));
    }

    #[test]
    fn an_absent_receipt_is_not_included_and_names_the_root_searched() {
        let chain = chain();
        let status = status_of(&chain, &[9; 32], Some(14));
        assert_eq!(status.state, MintAuthorizationState::NotIncluded);
        assert!(!status.found);
        assert_eq!(status.searched_frame, 15);
        assert_eq!(status.cited_frame, 14);
        assert_eq!(status.inclusion_frame, 0);
        assert!(status.reason.contains("not yet included, or rejected"));
    }

    #[test]
    fn no_retained_root_is_reported_not_an_error() {
        let chain = chain();
        chain.clock.seed_frame(GlobalFrame {
            header: Some(GlobalFrameHeader {
                frame_number: 2000,
                prover_tree_commitment: vec![1; 32],
                ..Default::default()
            }),
            ..Default::default()
        });
        // Frame 2000's root is unknown and the others are outside the lookback.
        let status = status_of(&chain, &RECEIPT, None);
        assert_eq!(status.state, MintAuthorizationState::NoRetainedRoot);
        assert!(!status.found);
        assert_eq!(status.head_frame, 2000);
        assert_eq!(status.claim_cap, 1992);
    }

    #[test]
    fn sparse_retained_roots_report_the_inclusion_as_a_range() {
        let chain = chain();
        // Header 12 names an unknown root: retained roots are now 11, 13, ...
        chain.clock.seed_frame(GlobalFrame {
            header: Some(GlobalFrameHeader {
                frame_number: 12,
                prover_tree_commitment: vec![1; 32],
                ..Default::default()
            }),
            ..Default::default()
        });
        // Header 13 too: the search can only bound the inclusion to 11..=13.
        chain.clock.seed_frame(GlobalFrame {
            header: Some(GlobalFrameHeader {
                frame_number: 13,
                prover_tree_commitment: vec![1; 32],
                ..Default::default()
            }),
            ..Default::default()
        });
        let status = status_of(&chain, &RECEIPT, Some(14));
        assert_eq!(status.first_root_frame, 14);
        assert_eq!(status.inclusion_frame, 13);
        assert_eq!(status.inclusion_frame_earliest, 11);
        assert!(status.reason.contains("between GLOBAL frames 11 and 13"));
    }

    #[test]
    fn the_inclusion_search_is_logarithmic_and_keeps_only_evidence_of_absence() {
        let frames: Vec<u64> = (1000..=2440).collect();
        for first in [1000, 1001, 1720, 2439, 2440] {
            let mut probes = 0;
            let (found, lacking) = first_holding(&frames, |frame| {
                probes += 1;
                Some(frame >= first)
            });
            assert_eq!(found, first);
            assert_eq!(lacking, if first == 1000 { 0 } else { first - 1 });
            assert!(probes <= 11, "{probes} probes");
        }
        // A probe that cannot answer is no evidence of absence.
        let (found, lacking) = first_holding(&[1, 2, 3], |_| None);
        assert_eq!((found, lacking), (3, 0));
    }

    /// Counts the events a thread emits, keeping their rendered fields.
    #[derive(Default, Clone)]
    struct Capture(Arc<Mutex<Vec<String>>>);

    struct Render<'a>(&'a mut String);
    impl tracing::field::Visit for Render<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write;
            let _ = write!(self.0, "{}={value:?} ", field.name());
        }
    }

    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            // Only this module's lines: the stores log on their own.
            if !event
                .metadata()
                .target()
                .ends_with("mint_authorization_witness")
            {
                return;
            }
            let mut line = format!("{} ", event.metadata().level());
            event.record(&mut Render(&mut line));
            self.0.lock().unwrap().push(line);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    #[test]
    fn a_missed_claim_logs_one_bounded_line_with_cap_and_reason() {
        let chain = chain();
        let capture = Capture::default();
        let log = ClaimWaitLog::default();
        tracing::subscriber::with_default(capture.clone(), || {
            // A hit logs nothing.
            assert!(
                witness_logged(&chain.state, chain.clock.as_ref(), &RECEIPT, Some(14), &log)
                    .unwrap()
                    .found
            );
            assert!(capture.0.lock().unwrap().is_empty());
            // A miss logs once however often it repeats.
            for _ in 0..3 {
                assert!(
                    !witness_logged(&chain.state, chain.clock.as_ref(), &RECEIPT, Some(12), &log)
                        .unwrap()
                        .found
                );
            }
        });
        let lines = capture.0.lock().unwrap().clone();
        assert_eq!(lines.len(), 1, "{lines:?}");
        let line = &lines[0];
        assert!(line.starts_with("INFO "), "{line}");
        for field in [
            "no citable authorization yet",
            "searched_frame=12",
            "cap=12",
            "slowest QUIL worker anchor",
            "not in the newest retained global root",
            "ends_when=",
            "suppressed=0",
            &hex::encode(RECEIPT),
        ] {
            assert!(line.contains(field), "{field} missing from {line}");
        }
        assert_eq!(log.suppressed.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_claim_with_no_root_at_the_cap_logs_that_and_still_fails() {
        let chain = chain();
        let capture = Capture::default();
        let log = ClaimWaitLog::default();
        tracing::subscriber::with_default(capture.clone(), || {
            assert!(
                witness_logged(&chain.state, chain.clock.as_ref(), &RECEIPT, Some(2), &log)
                    .unwrap_err()
                    .is_execution_unavailable()
            );
        });
        let lines = capture.0.lock().unwrap().clone();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("retains no global root"), "{}", lines[0]);
    }

    #[test]
    fn the_wait_line_repeats_only_after_its_interval_and_counts_the_rest() {
        let log = ClaimWaitLog::default();
        assert_eq!(log.admit(0), Some(0));
        assert_eq!(log.admit(CLAIM_WAIT_LOG_EVERY_SECS - 1), None);
        assert_eq!(log.admit(CLAIM_WAIT_LOG_EVERY_SECS - 1), None);
        assert_eq!(log.admit(CLAIM_WAIT_LOG_EVERY_SECS), Some(2));
        assert_eq!(log.admit(CLAIM_WAIT_LOG_EVERY_SECS + 1), None);
    }
}

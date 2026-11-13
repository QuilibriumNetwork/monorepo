//! Bounds on what a received application shard frame carries (request
//! bundles, their requests and storage openings) and takes to decode, on
//! the requests of a message bundle submitted to a shard and on the
//! bundles and requests of a GLOBAL frame received over gossip, counted
//! from the encoding before it is decoded.
//!
//! [`check_frame`] walks a frame's protobuf encoding without allocating
//! and refuses one carrying more than [`MAX_APP_FRAME_ITEMS`] bundles and
//! requests or [`MAX_APP_FRAME_OPENINGS`] storage openings, or whose
//! decode would take more than [`MAX_APP_FRAME_DECODED`] bytes;
//! [`check_bundle`] refuses a submitted bundle that could not fit a frame.
//!
//! A leader proposes at most [`MAX_APP_FRAME_ITEMS`] bundles and requests
//! and defers the rest ([`FrameItemBudget`]); members refuse a proposal
//! past either bound, as followers and archives refuse the frame.

use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use quil_cw_consensus::handoff::MAX_MEMBERS;
use quil_types::consensus::STORAGE_QUERIES_PER_LEAF;
use quil_types::decode_cost::{CostRefusal, DecodeCost};
use quil_types::proto::global::AppShardFrame;
use tracing::warn;

/// Request bundles and requests one application shard frame may carry,
/// counted together. A frame's size does not bound them: a request of a
/// type no converter reads is carried as an empty request, two bytes of a
/// frame's encoding (`consensus_wire`). A leader defers what does not fit
/// ([`FrameItemBudget`]). The engine's other bounds on them:
/// the mirror checks frames of at most 1,024 bundles
/// (`MIRROR_MAX_REQUESTS`, quil-node), a GLOBAL frame followed over gossip
/// carries at most 65,536 bundles and 65,536 requests
/// ([`MAX_GOSSIP_GLOBAL_BUNDLES`], [`MAX_GOSSIP_GLOBAL_REQUESTS`]), and a shard's
/// collector holds at most 65,536 messages a rank (`message_collector`).
/// This is 16 times the mirror's and a quarter of GLOBAL's.
pub const MAX_APP_FRAME_ITEMS: usize = 16_384;

/// Storage openings one application shard frame may carry: 8,192, the
/// [`STORAGE_QUERIES_PER_LEAF`] (2) a member opens a leaf with for each of
/// a committee session's [`MAX_MEMBERS`] (4,096). A leader attaches its
/// own openings (`app_engine`'s proposal), one for each leaf it registered
/// on the shard and each query, and a storage seat's epoch lists at most
/// 4,096 leaves (`MAX_LEAVES`, quil-execution `storage_seat`), so that
/// count too is at most 8,192.
pub const MAX_APP_FRAME_OPENINGS: usize = MAX_MEMBERS * STORAGE_QUERIES_PER_LEAF as usize;

/// The heap one application shard frame's decode may take: 64 MiB, four
/// times the 16 MiB a message carries over the transport. Every repeated
/// field counts, nested ones included: an element of one takes a slot of
/// its struct's size however few bytes encode it (two for an empty one),
/// and a `Vec` holds at least four slots. A frame at
/// [`MAX_APP_FRAME_ITEMS`] and [`MAX_APP_FRAME_OPENINGS`] of the requests
/// and openings nodes write, filling the transport's 16 MiB, is within it.
pub const MAX_APP_FRAME_DECODED: u64 = 64 << 20;

/// What decoding an application shard frame takes ([`check_frame`]).
static APP_FRAME_COST: LazyLock<DecodeCost> = LazyLock::new(|| {
    DecodeCost::of("quilibrium.node.global.pb.AppShardFrame")
        .expect("the embedded descriptors hold the application shard frame")
});

/// What a frame or bundle carries, counted from its encoding.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FrameItems {
    pub bundles: usize,
    pub requests: usize,
    /// Storage openings: a frame's only.
    pub openings: usize,
}

impl FrameItems {
    /// Bundles and requests: what [`MAX_APP_FRAME_ITEMS`] bounds.
    pub fn total(&self) -> usize {
        self.bundles.saturating_add(self.requests)
    }
}

/// Why a frame or bundle is refused before it is decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameRefusal {
    /// Not well-formed, as far as the walk reads it.
    Malformed,
    /// More bundles and requests than [`MAX_APP_FRAME_ITEMS`], or more
    /// storage openings than [`MAX_APP_FRAME_OPENINGS`].
    TooMany(FrameItems),
    /// A decode taking more than [`MAX_APP_FRAME_DECODED`]: at least
    /// `decoded` bytes.
    TooLarge { items: FrameItems, decoded: u64 },
}

impl FrameRefusal {
    /// What the walk counted before it refused.
    fn counted(&self) -> FrameItems {
        match self {
            Self::Malformed => FrameItems::default(),
            Self::TooMany(items) | Self::TooLarge { items, .. } => *items,
        }
    }
}

impl std::fmt::Display for FrameRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "malformed encoding"),
            Self::TooMany(items) => write!(
                f,
                "{} bundles and requests and {} storage openings, past the \
                 {MAX_APP_FRAME_ITEMS} and {MAX_APP_FRAME_OPENINGS} a frame carries",
                items.total(),
                items.openings
            ),
            Self::TooLarge { decoded, .. } => write!(
                f,
                "a decode of at least {decoded} bytes, past the \
                 {MAX_APP_FRAME_DECODED} a frame may take"
            ),
        }
    }
}

/// Counts the bundles, requests and storage openings the application
/// shard frame `data` carries and the heap its decode takes, without
/// allocating, and refuses it past [`MAX_APP_FRAME_ITEMS`],
/// [`MAX_APP_FRAME_OPENINGS`] or [`MAX_APP_FRAME_DECODED`], or malformed.
/// Every occurrence of a field is counted, as the decoder merges them.
pub fn check_frame(data: &[u8]) -> Result<FrameItems, FrameRefusal> {
    let mut items = FrameItems::default();
    let mut frame = WireReader::new(data);
    while !frame.is_empty() {
        match frame.varint32()? {
            // `requests` (2): a bundle, whose `requests` (1) are counted.
            18 => {
                items.bundles += 1;
                let mut bundle = WireReader::new(frame.len_delimited()?);
                while !bundle.is_empty() {
                    match bundle.varint32()? {
                        10 => {
                            items.requests += 1;
                            bundle.len_delimited()?;
                        }
                        tag => bundle.skip(tag)?,
                    }
                }
            }
            // `storage_attestation` (3): its `openings` (1) are counted.
            26 => {
                let mut attestation = WireReader::new(frame.len_delimited()?);
                while !attestation.is_empty() {
                    match attestation.varint32()? {
                        10 => {
                            items.openings += 1;
                            attestation.len_delimited()?;
                        }
                        tag => attestation.skip(tag)?,
                    }
                }
            }
            tag => frame.skip(tag)?,
        }
    }
    if items.total() > MAX_APP_FRAME_ITEMS || items.openings > MAX_APP_FRAME_OPENINGS {
        return Err(FrameRefusal::TooMany(items));
    }
    match APP_FRAME_COST.bytes(data, MAX_APP_FRAME_DECODED) {
        Ok(_) => Ok(items),
        Err(CostRefusal::Malformed) => Err(FrameRefusal::Malformed),
        Err(CostRefusal::Over(decoded)) => Err(FrameRefusal::TooLarge { items, decoded }),
    }
}

/// Whether the application shard frame `data` from `source` is within the
/// bound ([`check_frame`]); a refusal is logged with `peer`, the connected
/// peer it came from where the caller knows it.
pub fn admit_frame(source: &'static str, peer: Option<&[u8]>, data: &[u8]) -> bool {
    match check_frame(data) {
        Ok(_) => true,
        Err(refusal) => {
            note_refused(&FRAMES_REFUSED, source, peer, data.len(), &refusal);
            false
        }
    }
}

/// Decodes the application shard frame `data` from `source` once
/// [`admit_frame`] admits it.
pub fn decode_frame(source: &'static str, data: &[u8]) -> Option<AppShardFrame> {
    if !admit_frame(source, None, data) {
        return None;
    }
    <AppShardFrame as prost::Message>::decode(data).ok()
}

/// Counts the requests of the canonical message bundle `data`, without
/// allocating, and refuses one that could not fit a frame (with its own
/// item, over [`MAX_APP_FRAME_ITEMS`]) or that ends before its requests
/// do. The type and timestamp are left to its decoder. A zero-length
/// request counts as any other: it is how a request of a type no
/// converter reads is re-encoded (`consensus_wire`), and nodes decode
/// that form again.
pub fn check_bundle(data: &[u8]) -> Result<usize, FrameRefusal> {
    let mut at = 4;
    let declared = read_u32(data, &mut at).ok_or(FrameRefusal::Malformed)? as usize;
    if declared.saturating_add(1) > MAX_APP_FRAME_ITEMS {
        return Err(FrameRefusal::TooMany(FrameItems {
            bundles: 1,
            requests: declared,
            openings: 0,
        }));
    }
    for _ in 0..declared {
        let len = read_u32(data, &mut at).ok_or(FrameRefusal::Malformed)? as usize;
        at = at
            .checked_add(len)
            .filter(|&next| next <= data.len())
            .ok_or(FrameRefusal::Malformed)?;
    }
    Ok(declared)
}

/// [`check_bundle`] for a bundle submitted to a shard; a refusal is
/// logged.
pub fn admit_bundle(data: &[u8]) -> Result<usize, FrameRefusal> {
    check_bundle(data).inspect_err(|refusal| {
        note_refused(
            &BUNDLES_REFUSED,
            "shard submission",
            None,
            data.len(),
            refusal,
        );
    })
}

/// Request bundles a GLOBAL frame followed over gossip may carry. A frame
/// that carries more is not followed over gossip; the archive poller
/// fetches it from a trusted source, which has no such bound.
pub const MAX_GOSSIP_GLOBAL_BUNDLES: usize = 65_536;

/// Requests, over all its bundles, a GLOBAL frame followed over gossip may
/// carry. A frame's size does not bound them: a zero-length request is
/// four bytes of the frame's encoding and decodes into a whole
/// `MessageRequest` (`consensus_wire`).
pub const MAX_GOSSIP_GLOBAL_REQUESTS: usize = 65_536;

/// Counts the bundles and requests of the canonical GLOBAL frame `data`,
/// without allocating, and refuses one past [`MAX_GOSSIP_GLOBAL_BUNDLES`]
/// or [`MAX_GOSSIP_GLOBAL_REQUESTS`], or one whose header or bundles end
/// past its data. Each bundle's declared request count is what its
/// decoder builds at most; the requests themselves, the type, header and
/// timestamps are left to the decoder (`consensus_wire::decode_global_frame`).
pub fn check_global_frame(data: &[u8]) -> Result<FrameItems, FrameRefusal> {
    let mut at = 4;
    let header = read_u32(data, &mut at).ok_or(FrameRefusal::Malformed)? as usize;
    at = skip(data, at, header)?;
    let mut items = FrameItems {
        bundles: read_u32(data, &mut at).ok_or(FrameRefusal::Malformed)? as usize,
        ..FrameItems::default()
    };
    if items.bundles > MAX_GOSSIP_GLOBAL_BUNDLES {
        return Err(FrameRefusal::TooMany(items));
    }
    for _ in 0..items.bundles {
        let len = read_u32(data, &mut at).ok_or(FrameRefusal::Malformed)? as usize;
        let end = skip(data, at, len)?;
        let bundle = &data[at..end];
        at = end;
        let mut within = 4;
        let requests = read_u32(bundle, &mut within).ok_or(FrameRefusal::Malformed)? as usize;
        items.requests = items.requests.saturating_add(requests);
        if items.requests > MAX_GOSSIP_GLOBAL_REQUESTS {
            return Err(FrameRefusal::TooMany(items));
        }
    }
    Ok(items)
}

/// [`check_global_frame`] for a GLOBAL frame received over gossip from
/// `source`; a frame past the bound is logged. A malformed one is left to
/// its decoder's refusal.
pub fn admit_global_frame(source: &'static str, data: &[u8]) -> Result<FrameItems, FrameRefusal> {
    let checked = check_global_frame(data);
    if let Err(FrameRefusal::TooMany(counted)) = checked {
        #[cfg(test)]
        REFUSED_HERE.with(|count| count.set(count.get() + 1));
        if let Some(refused) = GLOBAL_FRAMES_REFUSED.due(Instant::now()) {
            warn!(
                source,
                bytes = data.len(),
                bundles = counted.bundles,
                requests = counted.requests,
                bundles_limit = MAX_GOSSIP_GLOBAL_BUNDLES,
                requests_limit = MAX_GOSSIP_GLOBAL_REQUESTS,
                refused_since_last_line = refused,
                check = "none for a genuine frame: the archive poller fetches it; \
                         else the frame's publisher",
                "GLOBAL frame past the gossip bound refused before decoding"
            );
        }
    }
    checked
}

/// The offset `len` bytes past `at` in `data`, if they are there.
fn skip(data: &[u8], at: usize, len: usize) -> Result<usize, FrameRefusal> {
    at.checked_add(len)
        .filter(|&next| next <= data.len())
        .ok_or(FrameRefusal::Malformed)
}

/// A proposal's running count of bundles and requests, which keeps it
/// within its limit, at most [`MAX_APP_FRAME_ITEMS`].
#[derive(Debug)]
pub struct FrameItemBudget {
    items: usize,
    limit: usize,
}

impl Default for FrameItemBudget {
    fn default() -> Self {
        Self::within(MAX_APP_FRAME_ITEMS)
    }
}

impl FrameItemBudget {
    /// A budget of `limit` bundles and requests, at most
    /// [`MAX_APP_FRAME_ITEMS`].
    pub fn within(limit: usize) -> Self {
        Self {
            items: 0,
            limit: limit.min(MAX_APP_FRAME_ITEMS),
        }
    }

    /// Takes room for a bundle of `requests`, if the frame has it.
    pub fn take(&mut self, requests: usize) -> bool {
        let next = self.items.saturating_add(1).saturating_add(requests);
        if next > self.limit {
            #[cfg(test)]
            DEFERRED_HERE.with(|count| count.set(count.get() + 1));
            return false;
        }
        self.items = next;
        true
    }

    /// Which of bundles of `requests` requests each, in order, the frame
    /// takes: each while it has room for it.
    pub fn fit(&mut self, requests: impl IntoIterator<Item = usize>) -> Vec<bool> {
        requests
            .into_iter()
            .map(|requests| self.take(requests))
            .collect()
    }
}

/// How often refusals of one kind are logged again.
const REFUSAL_REPEAT: Duration = Duration::from_secs(600);

/// When refusals of one kind were last logged, and how many since.
struct RefusalLine(Mutex<(Option<Instant>, u64)>);

impl RefusalLine {
    const fn new() -> Self {
        Self(Mutex::new((None, 0)))
    }

    /// Counts a refusal at `now`: the refusals to report when a line is
    /// due (this one included), else `None`.
    fn due(&self, now: Instant) -> Option<u64> {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.1 += 1;
        if state
            .0
            .is_some_and(|last| now.duration_since(last) < REFUSAL_REPEAT)
        {
            return None;
        }
        state.0 = Some(now);
        Some(std::mem::take(&mut state.1))
    }
}

static FRAMES_REFUSED: RefusalLine = RefusalLine::new();
static BUNDLES_REFUSED: RefusalLine = RefusalLine::new();
static GLOBAL_FRAMES_REFUSED: RefusalLine = RefusalLine::new();

#[cfg(test)]
thread_local! {
    /// Refusals on this thread, which the call sites' tests read.
    static REFUSED_HERE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Bundles a [`FrameItemBudget`] had no room for on this thread.
    static DEFERRED_HERE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Refusals [`admit_frame`] and [`admit_bundle`] made on this thread.
#[cfg(test)]
pub(crate) fn refused_here() -> usize {
    REFUSED_HERE.with(std::cell::Cell::get)
}

/// Bundles a [`FrameItemBudget`] had no room for on this thread.
#[cfg(test)]
pub(crate) fn deferred_here() -> usize {
    DEFERRED_HERE.with(std::cell::Cell::get)
}

/// Bundles of `items` bundles and requests in all, for frames at and past
/// the limit.
#[cfg(test)]
pub(crate) fn bundles_of(items: usize) -> Vec<quil_types::proto::global::MessageBundle> {
    use quil_types::proto::global::{MessageBundle, MessageRequest};
    vec![
        MessageBundle {
            requests: vec![MessageRequest::default(); items.saturating_sub(2)],
            timestamp: 5,
        },
        MessageBundle::default(),
    ]
}

/// Logs a refusal: the first, then at most one line per
/// [`REFUSAL_REPEAT`] with the count since.
fn note_refused(
    line: &RefusalLine,
    source: &'static str,
    peer: Option<&[u8]>,
    bytes: usize,
    refusal: &FrameRefusal,
) {
    #[cfg(test)]
    REFUSED_HERE.with(|count| count.set(count.get() + 1));
    let Some(refused) = line.due(Instant::now()) else {
        return;
    };
    let counted = refusal.counted();
    let peer = peer.map_or_else(
        || "not known here".to_owned(),
        |peer| bs58::encode(peer).into_string(),
    );
    warn!(
        source,
        peer,
        bytes,
        bundles = counted.bundles,
        requests = counted.requests,
        openings = counted.openings,
        limit = MAX_APP_FRAME_ITEMS,
        openings_limit = MAX_APP_FRAME_OPENINGS,
        decoded_limit = MAX_APP_FRAME_DECODED,
        refused_since_last_line = refused,
        reason = %refusal,
        check = "the peer's build and what it publishes on the shard's topics; \
                 no genuine frame or bundle is refused",
        "application shard message refused before decoding"
    );
}

/// The big-endian `u32` at `*at`, advancing past it.
fn read_u32(data: &[u8], at: &mut usize) -> Option<u32> {
    let bytes = data.get(*at..at.checked_add(4)?)?;
    *at += 4;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// The longest varint protobuf encodes.
const MAX_VARINT_LEN: usize = 10;

/// A strict reader of protobuf wire format, which never allocates.
struct WireReader<'a> {
    bytes: &'a [u8],
}

impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn varint(&mut self) -> Result<u64, FrameRefusal> {
        let bytes = self.bytes;
        let mut value: u64 = 0;
        for (i, byte) in bytes.iter().take(MAX_VARINT_LEN).enumerate() {
            value |= u64::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                self.bytes = &bytes[i + 1..];
                return Ok(value);
            }
        }
        Err(FrameRefusal::Malformed)
    }

    /// A tag or a length; one past 32 bits is refused, as the decoder
    /// refuses such a tag and no length that large fits a message.
    fn varint32(&mut self) -> Result<u32, FrameRefusal> {
        u32::try_from(self.varint()?).map_err(|_| FrameRefusal::Malformed)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], FrameRefusal> {
        let bytes = self.bytes;
        if len > bytes.len() {
            return Err(FrameRefusal::Malformed);
        }
        let (taken, rest) = bytes.split_at(len);
        self.bytes = rest;
        Ok(taken)
    }

    /// The contents of a length-delimited field.
    fn len_delimited(&mut self) -> Result<&'a [u8], FrameRefusal> {
        let len = self.varint32()? as usize;
        self.take(len)
    }

    /// Skips the value of a field with `tag`, by its wire type. Groups,
    /// which no encoder of these messages writes, are refused.
    fn skip(&mut self, tag: u32) -> Result<(), FrameRefusal> {
        match tag & 0x7 {
            0 => {
                self.varint()?;
            }
            1 => {
                self.take(8)?;
            }
            2 => {
                self.len_delimited()?;
            }
            5 => {
                self.take(4)?;
            }
            _ => return Err(FrameRefusal::Malformed),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_alloc::peak_by;
    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
    use quil_types::proto::application::{Path, TraversalProof, TraversalSubProof};
    use quil_types::proto::compute::{
        CodeDeployment, CodeExecute, CodeFinalize, ExecuteOperation, ExecutionResult,
        StateTransition,
    };
    use quil_types::proto::global::message_request::Request;
    use quil_types::proto::global::{
        ConfirmLeafRoots, FrameHeader, LeafRootEntry, MessageBundle, MessageRequest, ProverConfirm,
        ProverJoin, ProverKick, ProverSeniorityMerge, SeniorityMerge, ShardSplit,
        StorageAttestation, StorageOpening,
    };

    /// An encoded frame with a header, a storage attestation and `bundles`.
    fn frame_of(bundles: Vec<MessageBundle>) -> Vec<u8> {
        prost::Message::encode_to_vec(&AppShardFrame {
            header: Some(FrameHeader {
                address: vec![7; 32],
                frame_number: 9,
                state_roots: vec![vec![1; 32]; 4],
                ..Default::default()
            }),
            requests: bundles,
            storage_attestation: Some(StorageAttestation {
                openings: vec![StorageOpening {
                    path_commits: vec![vec![2; 74]; 3],
                    ..Default::default()
                }],
            }),
        })
    }

    /// A bundle of `requests` requests, the first carrying bytes.
    fn bundle(requests: usize) -> MessageBundle {
        let mut bundle = MessageBundle {
            requests: vec![MessageRequest::default(); requests],
            timestamp: 5,
        };
        if let Some(first) = bundle.requests.first_mut() {
            first.request = Some(
                quil_types::proto::global::message_request::Request::CommitteeHandoff(vec![3; 40]),
            );
        }
        bundle
    }

    /// An encoded frame carrying `openings` empty storage openings.
    fn frame_with_openings(openings: usize) -> Vec<u8> {
        prost::Message::encode_to_vec(&AppShardFrame {
            header: Some(FrameHeader {
                frame_number: 9,
                ..Default::default()
            }),
            requests: Vec::new(),
            storage_attestation: Some(StorageAttestation {
                openings: vec![StorageOpening::default(); openings],
            }),
        })
    }

    fn canonical(requests: Vec<Option<CanonicalMessageRequest>>) -> Vec<u8> {
        CanonicalMessageBundle {
            requests,
            timestamp: 1,
        }
        .to_canonical_bytes()
        .unwrap()
    }

    fn operation(n: u32) -> Option<CanonicalMessageRequest> {
        let mut inner = 0x0512u32.to_be_bytes().to_vec();
        inner.extend_from_slice(&n.to_be_bytes());
        Some(CanonicalMessageRequest::wrap(inner).unwrap())
    }

    /// The walk counts every bundle and request the decoder builds, other
    /// fields skipped.
    #[test]
    fn counts_the_bundles_and_requests_of_a_frame() {
        let data = frame_of(vec![bundle(3), bundle(0), bundle(2)]);
        assert_eq!(
            check_frame(&data),
            Ok(FrameItems {
                bundles: 3,
                requests: 5,
                openings: 1,
            })
        );
        let decoded = <AppShardFrame as prost::Message>::decode(data.as_slice()).unwrap();
        let requests: usize = decoded.requests.iter().map(|b| b.requests.len()).sum();
        assert_eq!((decoded.requests.len(), requests), (3, 5));
        let openings = decoded.storage_attestation.map(|a| a.openings.len());
        assert_eq!(openings, Some(1));
        assert_eq!(
            check_frame(&frame_of(Vec::new())),
            Ok(FrameItems {
                openings: 1,
                ..Default::default()
            })
        );
        assert_eq!(check_frame(&[]), Ok(FrameItems::default()));
    }

    /// A frame of exactly [`MAX_APP_FRAME_ITEMS`] is admitted and decodes.
    #[test]
    fn admits_a_frame_at_the_limit() {
        let at = frame_of(bundles_of(MAX_APP_FRAME_ITEMS));
        assert_eq!(
            check_frame(&at).map(|items| items.total()),
            Ok(MAX_APP_FRAME_ITEMS)
        );
        let before = refused_here();
        assert!(decode_frame("test", &at).is_some());
        assert_eq!(refused_here(), before);
    }

    /// One item past the limit, across bundles, is refused, and so is one
    /// bundle past it.
    #[test]
    fn refuses_a_frame_one_item_over_the_limit() {
        let over = frame_of(vec![bundle(MAX_APP_FRAME_ITEMS - 2), bundle(1)]);
        assert_eq!(
            check_frame(&over),
            Err(FrameRefusal::TooMany(FrameItems {
                bundles: 2,
                requests: MAX_APP_FRAME_ITEMS - 1,
                openings: 1,
            })),
            "FRAME-BOUND: a frame one item past the bound was admitted"
        );
        let before = refused_here();
        assert!(decode_frame("test", &over).is_none());
        assert_eq!(refused_here(), before + 1);
        let bundles = frame_of(vec![bundle(0); MAX_APP_FRAME_ITEMS + 1]);
        assert!(matches!(
            check_frame(&bundles),
            Err(FrameRefusal::TooMany(_))
        ));
    }

    /// Storage openings are counted in every occurrence of the attestation,
    /// as the decoder merges them; a frame at [`MAX_APP_FRAME_OPENINGS`]
    /// is admitted and decodes.
    #[test]
    fn counts_the_storage_openings_of_a_frame() {
        let at = frame_with_openings(MAX_APP_FRAME_OPENINGS);
        assert_eq!(
            check_frame(&at).map(|items| items.openings),
            Ok(MAX_APP_FRAME_OPENINGS)
        );
        let before = refused_here();
        let decoded = decode_frame("test", &at).and_then(|f| f.storage_attestation);
        assert_eq!(
            decoded.map(|a| a.openings.len()),
            Some(MAX_APP_FRAME_OPENINGS)
        );
        assert_eq!(refused_here(), before);
        // Two occurrences of the attestation, one opening each.
        let mut twice = frame_with_openings(1);
        let attestation = prost::Message::encode_to_vec(&StorageAttestation {
            openings: vec![StorageOpening::default()],
        });
        twice.push(0x1a);
        twice.push(u8::try_from(attestation.len()).unwrap());
        twice.extend_from_slice(&attestation);
        assert_eq!(check_frame(&twice).map(|items| items.openings), Ok(2));
        let decoded = <AppShardFrame as prost::Message>::decode(twice.as_slice()).unwrap();
        assert_eq!(decoded.storage_attestation.unwrap().openings.len(), 2);
    }

    /// One storage opening past the bound is refused unread.
    #[test]
    fn refuses_a_frame_one_opening_over_the_limit() {
        let over = frame_with_openings(MAX_APP_FRAME_OPENINGS + 1);
        assert_eq!(
            check_frame(&over),
            Err(FrameRefusal::TooMany(FrameItems {
                openings: MAX_APP_FRAME_OPENINGS + 1,
                ..Default::default()
            })),
            "OPENINGS-BOUND: a frame one opening past the bound was admitted"
        );
        let before = refused_here();
        assert!(decode_frame("test", &over).is_none());
        assert_eq!(refused_here(), before + 1);
    }

    /// An encoding the walk cannot read is refused, never a panic: every
    /// truncation of a frame inside a field, a group, a tag past 32 bits,
    /// a length past the end, an endless varint.
    #[test]
    fn refuses_malformed_frames_without_panic() {
        let data = frame_of(vec![bundle(2), bundle(1)]);
        for end in 0..data.len() {
            let cut = &data[..end];
            // A cut between fields is a shorter frame; the rest are refused.
            if let Ok(items) = check_frame(cut) {
                assert!(items.total() <= 5);
                assert!(<AppShardFrame as prost::Message>::decode(cut).is_ok());
            }
        }
        assert_eq!(
            check_frame(&data[..data.len() - 1]),
            Err(FrameRefusal::Malformed)
        );
        for bad in [
            &[0x0b][..],
            &[0x80, 0x80, 0x80, 0x80, 0x80, 0x01, 0x00],
            &[0x12, 0x05, 0x0a],
            &[0x12, 0xff, 0xff, 0xff, 0xff, 0x0f],
            &[0xff; 11],
            &[0x1a, 0x02, 0x0a, 0x05],
            &[0x1a, 0x01, 0x0b],
        ] {
            assert_eq!(check_frame(bad), Err(FrameRefusal::Malformed), "{bad:?}");
        }
    }

    /// A submitted bundle is counted, zero-length requests included; one
    /// that could not fit a frame or that ends early is refused, without
    /// panic.
    #[test]
    fn checks_submitted_bundles_and_counts_empty_requests() {
        assert_eq!(
            check_bundle(&canonical(vec![operation(1), operation(2)])),
            Ok(2)
        );
        assert_eq!(check_bundle(&canonical(Vec::new())), Ok(0));
        let zero = "ZERO-LENGTH: a bundle with a zero-length request was refused";
        assert_eq!(check_bundle(&canonical(vec![None])), Ok(1), "{zero}");
        assert_eq!(
            check_bundle(&canonical(vec![operation(1), None])),
            Ok(2),
            "{zero}"
        );
        let at: Vec<_> = (0..MAX_APP_FRAME_ITEMS as u32 - 1).map(operation).collect();
        assert_eq!(check_bundle(&canonical(at)), Ok(MAX_APP_FRAME_ITEMS - 1));
        let over: Vec<_> = (0..MAX_APP_FRAME_ITEMS as u32).map(operation).collect();
        assert!(matches!(
            check_bundle(&canonical(over)),
            Err(FrameRefusal::TooMany(_))
        ));
        // A count past the bound is refused unread.
        let mut declared = canonical(Vec::new());
        declared[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            check_bundle(&declared),
            Err(FrameRefusal::TooMany(_))
        ));
        // Every cut before the timestamp.
        let data = canonical(vec![operation(1), operation(2)]);
        for end in 0..data.len() - 8 {
            assert_eq!(
                check_bundle(&data[..end]),
                Err(FrameRefusal::Malformed),
                "{end}"
            );
        }
    }

    /// A proposal's budget takes bundles while the frame has room, and a
    /// later bundle that fits after one that does not.
    #[test]
    fn budget_keeps_a_proposal_within_the_limit() {
        let mut budget = FrameItemBudget::default();
        assert!(budget.take(MAX_APP_FRAME_ITEMS - 3));
        assert!(!budget.take(2));
        assert!(budget.take(1));
        assert!(!budget.take(0));
        let before = deferred_here();
        let half = MAX_APP_FRAME_ITEMS / 2;
        assert_eq!(
            FrameItemBudget::default().fit([half, half, 0]),
            [true, false, true]
        );
        assert_eq!(deferred_here(), before + 1);
        assert_eq!(
            FrameItemBudget::within(10).fit([4, 4, 3]),
            [true, true, false]
        );
        let past = FrameItemBudget::within(MAX_APP_FRAME_ITEMS + 1).fit([MAX_APP_FRAME_ITEMS]);
        assert_eq!(past, [false], "a limit is at most the frame's");
    }

    /// Refusals are logged at the first, then once per interval with the
    /// count since.
    #[test]
    fn refusal_lines_are_bounded() {
        let line = RefusalLine::new();
        let start = Instant::now();
        assert_eq!(line.due(start), Some(1));
        assert_eq!(line.due(start + Duration::from_secs(1)), None);
        assert_eq!(line.due(start + Duration::from_secs(599)), None);
        assert_eq!(line.due(start + REFUSAL_REPEAT), Some(3));
        assert_eq!(line.due(start + REFUSAL_REPEAT), None);
    }

    /// A canonical GLOBAL frame carrying `bundles`, with a default header.
    fn global_frame(bundles: &[Vec<u8>]) -> Vec<u8> {
        use quil_execution::global_intrinsic::frame_header::GlobalFrameHeader;
        let header = GlobalFrameHeader::default().to_canonical_bytes().unwrap();
        let mut frame = crate::consensus_wire::GLOBAL_FRAME_TYPE
            .to_be_bytes()
            .to_vec();
        frame.extend_from_slice(&(header.len() as u32).to_be_bytes());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&(bundles.len() as u32).to_be_bytes());
        for bundle in bundles {
            frame.extend_from_slice(&(bundle.len() as u32).to_be_bytes());
            frame.extend_from_slice(bundle);
        }
        frame
    }

    /// The walk counts every bundle and request the GLOBAL frame decoder
    /// builds, zero-length requests included, and refuses a frame cut
    /// short.
    #[test]
    fn counts_the_bundles_and_requests_of_a_global_frame() {
        let data = global_frame(&[
            canonical(vec![operation(1), None, operation(2)]),
            canonical(Vec::new()),
            canonical(vec![None]),
        ]);
        let counted = FrameItems {
            bundles: 3,
            requests: 4,
            openings: 0,
        };
        assert_eq!(
            check_global_frame(&data),
            Ok(counted),
            "GLOBAL-COUNT: the walk miscounted a GLOBAL frame"
        );
        let decoded = crate::consensus_wire::decode_global_frame(&data).unwrap();
        let requests: usize = decoded.requests.iter().map(|b| b.requests.len()).sum();
        assert_eq!((decoded.requests.len(), requests), (3, 4));
        for end in 0..data.len() {
            assert_eq!(
                check_global_frame(&data[..end]),
                Err(FrameRefusal::Malformed),
                "{end}"
            );
        }
    }

    /// A GLOBAL frame past the gossip bound, in requests over its bundles
    /// or in bundles, is refused unread and logged; one at either bound
    /// is admitted and decodes.
    #[test]
    fn global_frames_past_the_gossip_bound_are_refused_unread() {
        let requests = |n: usize| canonical(vec![None; n]);
        let before = refused_here();
        let at = global_frame(&[requests(MAX_GOSSIP_GLOBAL_REQUESTS)]);
        assert_eq!(
            admit_global_frame("test", &at).map(|items| items.requests),
            Ok(MAX_GOSSIP_GLOBAL_REQUESTS),
            "GLOBAL-AT-BOUND: a frame at the request bound was refused"
        );
        let decoded = crate::consensus_wire::decode_global_frame(&at).unwrap();
        assert_eq!(
            decoded.requests[0].requests.len(),
            MAX_GOSSIP_GLOBAL_REQUESTS
        );
        let over = global_frame(&[requests(MAX_GOSSIP_GLOBAL_REQUESTS), requests(1)]);
        assert_eq!(
            admit_global_frame("test", &over),
            Err(FrameRefusal::TooMany(FrameItems {
                bundles: 2,
                requests: MAX_GOSSIP_GLOBAL_REQUESTS + 1,
                openings: 0,
            })),
            "GLOBAL-REQUESTS: a frame past the request bound was admitted"
        );
        let empty = requests(0);
        let empties = vec![empty; MAX_GOSSIP_GLOBAL_BUNDLES + 1];
        let past = global_frame(&empties);
        assert!(
            matches!(
                admit_global_frame("test", &past),
                Err(FrameRefusal::TooMany(FrameItems { bundles, .. }))
                    if bundles == MAX_GOSSIP_GLOBAL_BUNDLES + 1
            ),
            "GLOBAL-BUNDLES: a frame past the bundle bound was admitted"
        );
        let at_bundles = global_frame(&empties[1..]);
        assert_eq!(
            admit_global_frame("test", &at_bundles).map(|items| items.bundles),
            Ok(MAX_GOSSIP_GLOBAL_BUNDLES),
            "GLOBAL-AT-BOUND: a frame at the bundle bound was refused"
        );
        assert_eq!(
            admit_global_frame("test", &at[..at.len() - 1]),
            Err(FrameRefusal::Malformed)
        );
        assert_eq!(
            refused_here(),
            before + 2,
            "a malformed frame is not logged"
        );
    }

    /// A frame carrying `request` as its only request.
    fn frame_with(request: Request) -> AppShardFrame {
        AppShardFrame {
            requests: vec![MessageBundle {
                requests: vec![MessageRequest {
                    request: Some(request),
                    timestamp: 0,
                }],
                timestamp: 5,
            }],
            ..Default::default()
        }
    }

    /// A confirmation carrying `leaf_roots`.
    fn confirm(leaf_roots: Vec<ConfirmLeafRoots>) -> Request {
        Request::Confirm(ProverConfirm {
            leaf_roots,
            ..Default::default()
        })
    }

    /// A kick whose traversal proof carries `sub_proofs`.
    fn kick(sub_proofs: Vec<TraversalSubProof>) -> Request {
        Request::Kick(ProverKick {
            traversal_proof: Some(TraversalProof {
                sub_proofs,
                ..Default::default()
            }),
            ..Default::default()
        })
    }

    /// Frames each filling one repeated field, nested ones above all, with
    /// `n` of its cheapest elements (empty ones), within the item and
    /// opening bounds; by field.
    fn nested_shapes(n: usize) -> Vec<(&'static str, AppShardFrame)> {
        let entry = |prefix: Vec<u32>| LeafRootEntry {
            prefix,
            ..Default::default()
        };
        let roots = |entries: Vec<LeafRootEntry>| ConfirmLeafRoots {
            entries,
            ..Default::default()
        };
        let paths = |paths: Vec<Path>| TraversalSubProof {
            paths,
            ..Default::default()
        };
        vec![
            (
                "header.state_roots",
                AppShardFrame {
                    header: Some(FrameHeader {
                        state_roots: vec![Vec::new(); n],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ),
            (
                "openings.path_commits",
                AppShardFrame {
                    storage_attestation: Some(StorageAttestation {
                        openings: vec![StorageOpening {
                            path_commits: vec![Vec::new(); n],
                            ..Default::default()
                        }],
                    }),
                    ..Default::default()
                },
            ),
            (
                "bundle.requests",
                AppShardFrame {
                    requests: vec![MessageBundle {
                        requests: vec![MessageRequest::default(); n.min(MAX_APP_FRAME_ITEMS - 1)],
                        timestamp: 5,
                    }],
                    ..Default::default()
                },
            ),
            (
                "join.filters",
                frame_with(Request::Join(ProverJoin {
                    filters: vec![Vec::new(); n],
                    ..Default::default()
                })),
            ),
            (
                "join.merge_targets",
                frame_with(Request::Join(ProverJoin {
                    merge_targets: vec![SeniorityMerge::default(); n],
                    ..Default::default()
                })),
            ),
            (
                "seniority.merge_targets",
                frame_with(Request::SeniorityMerge(ProverSeniorityMerge {
                    merge_targets: vec![SeniorityMerge::default(); n],
                    ..Default::default()
                })),
            ),
            (
                "confirm.leaf_roots",
                frame_with(confirm(vec![ConfirmLeafRoots::default(); n])),
            ),
            (
                "leaf_roots.entries",
                frame_with(confirm(vec![roots(vec![LeafRootEntry::default(); n])])),
            ),
            (
                "leaf_roots(1_entry)",
                frame_with(confirm(vec![roots(vec![LeafRootEntry::default()]); n])),
            ),
            (
                "entries.prefix",
                frame_with(confirm(vec![roots(vec![entry(vec![0; n])])])),
            ),
            (
                "entries(1_prefix)",
                frame_with(confirm(vec![roots(vec![entry(vec![0]); n])])),
            ),
            (
                "kick.sub_proofs",
                frame_with(kick(vec![TraversalSubProof::default(); n])),
            ),
            (
                "sub_proofs.paths",
                frame_with(kick(vec![paths(vec![Path::default(); n])])),
            ),
            (
                "paths.indices",
                frame_with(kick(vec![paths(vec![Path {
                    indices: vec![0; n],
                }])])),
            ),
            (
                "execute.operations",
                frame_with(Request::CodeExecute(CodeExecute {
                    execute_operations: vec![ExecuteOperation::default(); n],
                    ..Default::default()
                })),
            ),
            (
                "finalize.results",
                frame_with(Request::CodeFinalize(CodeFinalize {
                    results: vec![ExecutionResult::default(); n],
                    ..Default::default()
                })),
            ),
            (
                "finalize.state_changes",
                frame_with(Request::CodeFinalize(CodeFinalize {
                    state_changes: vec![StateTransition::default(); n],
                    ..Default::default()
                })),
            ),
            (
                "deploy.input_types",
                frame_with(Request::CodeDeploy(CodeDeployment {
                    input_types: vec![String::new(); n],
                    ..Default::default()
                })),
            ),
            (
                "split.proposed_shards",
                frame_with(Request::ShardSplit(ShardSplit {
                    proposed_shards: vec![Vec::new(); n],
                    ..Default::default()
                })),
            ),
        ]
    }

    /// The heap decoding `data` takes at its most, on this thread.
    fn decode_heap(data: &[u8]) -> u64 {
        let (decoded, heap) = peak_by(|| <AppShardFrame as prost::Message>::decode(data).map(drop));
        assert!(decoded.is_ok());
        u64::try_from(heap).unwrap()
    }

    /// What each nested repeated field decodes to per byte of the frame,
    /// filled with 65,536 empty elements and with one more (where its
    /// `Vec` doubles). A figure for the record; it bounds nothing.
    #[test]
    fn measures_what_nested_fields_decode_to() {
        let mut ratios: Vec<(&str, Vec<f64>)> = Vec::new();
        for (round, n) in [1 << 16, (1 << 16) + 1].into_iter().enumerate() {
            for (at, (field, frame)) in nested_shapes(n).into_iter().enumerate() {
                let data = prost::Message::encode_to_vec(&frame);
                drop(frame);
                let heap = decode_heap(&data);
                println!(
                    "DECODE-DETAIL field={field} elements={n} wire={} heap={heap}",
                    data.len()
                );
                if round == 0 {
                    ratios.push((field, Vec::new()));
                }
                ratios[at].1.push(heap as f64 / data.len() as f64);
            }
        }
        // At most eight lines of 300 characters reach the record.
        println!("DECODE-AMPLIFICATION heap per frame byte, 65,536 / 65,537 elements:");
        let mut line = String::new();
        for (field, ratio) in &ratios {
            line.push_str(&format!(" {field}={:.1}/{:.1}", ratio[0], ratio[1]));
            if line.len() > 220 {
                println!("DECODE-AMPLIFICATION{line}");
                line.clear();
            }
        }
        if !line.is_empty() {
            println!("DECODE-AMPLIFICATION{line}");
        }
        let (field, worst) = ratios
            .iter()
            .map(|(field, ratio)| (*field, ratio[0].max(ratio[1])))
            .fold(
                ("", 0.0),
                |worst, next| if next.1 > worst.1 { next } else { worst },
            );
        println!(
            "DECODE-AMPLIFICATION worst {field}: {worst:.1} bytes a frame byte, \
             a 16 MiB frame decoding to {:.0} MiB",
            worst * 16.0
        );
    }

    /// A frame within the item and opening bounds whose one request
    /// carries 524,288 leaf roots of one empty entry each: four bytes of
    /// the frame an element, which decode to a 48-byte slot and a `Vec` of
    /// four 56-byte entries. Refused before it is decoded.
    #[test]
    fn a_frame_decoding_far_past_its_bytes_is_refused_unread() {
        let frame = frame_with(confirm(vec![
            ConfirmLeafRoots {
                entries: vec![LeafRootEntry::default()],
                ..Default::default()
            };
            1 << 19
        ]));
        let data = prost::Message::encode_to_vec(&frame);
        drop(frame);
        let heap = decode_heap(&data);
        assert!(heap > 64 << 20, "{} bytes decoded to {heap}", data.len());
        // The walk's own state is set up before the measurement.
        let _ = check_frame(&[]);
        let before = refused_here();
        let (admitted, held) = peak_by(|| decode_frame("test", &data).is_some());
        assert!(
            !admitted,
            "NESTED-BOUND: a frame of {} bytes decoding to {heap} was admitted",
            data.len()
        );
        assert_eq!(refused_here(), before + 1);
        assert!(
            held < 1 << 20,
            "NESTED-BOUND: refusing it held {held} bytes"
        );
    }

    /// The heap the walk counts for each nested field's frame is at least
    /// what its decode takes, and not far past it: at a `Vec`'s first
    /// element, its fourth and fifth, and past a doubling.
    #[test]
    fn the_counted_heap_bounds_what_each_nested_field_decodes_to() {
        for n in [1, 4, 5, 1_000, 4_097] {
            for (field, frame) in nested_shapes(n) {
                let data = prost::Message::encode_to_vec(&frame);
                let counted = APP_FRAME_COST.bytes(&data, u64::MAX).unwrap();
                let heap = decode_heap(&data);
                assert!(
                    heap <= counted,
                    "COST-BOUND: {field}, {n} elements, decoded to {heap} bytes, counted {counted}"
                );
                assert!(
                    counted <= 3 * heap + (64 << 10),
                    "COST-TIGHT: {field}, {n} elements, counted {counted} bytes for {heap}"
                );
            }
        }
    }

    /// A frame of the requests and openings nodes write, at
    /// [`MAX_APP_FRAME_ITEMS`] and [`MAX_APP_FRAME_OPENINGS`], filled to
    /// the transport's 16 MiB with a storage proof: admitted, and decoded.
    #[test]
    fn admits_an_honest_frame_at_every_bound() {
        let signature = || {
            Some(quil_types::proto::keys::Bls48581AddressedSignature {
                signature: vec![1; 74],
                address: vec![2; 32],
            })
        };
        let confirmation = MessageRequest {
            request: Some(Request::Confirm(ProverConfirm {
                frame_number: 9,
                public_key_signature_bls48581: signature(),
                filters: vec![vec![3; 35]],
                leaf_roots: vec![ConfirmLeafRoots {
                    filter: vec![3; 35],
                    entries: vec![
                        LeafRootEntry {
                            prefix: vec![1, 2, 3],
                            leaf_root: vec![4; 74],
                            num_blocks: 64,
                        };
                        2
                    ],
                }],
                ..Default::default()
            })),
            timestamp: 1,
        };
        let opening = StorageOpening {
            shard_id: vec![5; 35],
            epoch: 3,
            member_id: vec![6; 32],
            query: 1,
            leaf_root: vec![4; 74],
            num_blocks: 64,
            path_commits: vec![vec![7; 74]; 3],
            path_proofs: vec![vec![8; 74]; 3],
            commitment: vec![9; 74],
            value: vec![10; 32],
            proof: vec![11; 74],
        };
        let mut requests = vec![confirmation; MAX_APP_FRAME_ITEMS - 2];
        requests.push(MessageRequest {
            request: Some(Request::StorageEpochProof(Vec::new())),
            timestamp: 1,
        });
        let mut frame = AppShardFrame {
            header: Some(FrameHeader {
                address: vec![7; 32],
                frame_number: 9,
                output: vec![12; 516],
                state_roots: vec![vec![1; 74]; 4],
                prover: vec![13; 32],
                ..Default::default()
            }),
            requests: vec![MessageBundle {
                requests,
                timestamp: 5,
            }],
            storage_attestation: Some(StorageAttestation {
                openings: vec![opening; MAX_APP_FRAME_OPENINGS],
            }),
        };
        // The proof fills the frame to 64 KiB under the transport's 16 MiB.
        let room = (16 << 20) - (64 << 10) - prost::Message::encoded_len(&frame) - 8;
        if let Some(Request::StorageEpochProof(proof)) =
            &mut frame.requests[0].requests[MAX_APP_FRAME_ITEMS - 2].request
        {
            *proof = vec![14; room];
        }
        let data = prost::Message::encode_to_vec(&frame);
        drop(frame);
        assert!(data.len() <= 16 << 20, "{}", data.len());
        assert!(data.len() > (16 << 20) - (128 << 10), "{}", data.len());
        let _ = check_frame(&[]);
        let walked = Instant::now();
        let items = check_frame(&data);
        let walked = walked.elapsed();
        assert_eq!(
            items.map(|items| (items.total(), items.openings)),
            Ok((MAX_APP_FRAME_ITEMS, MAX_APP_FRAME_OPENINGS)),
            "HONEST-REFUSED: a frame of {} bytes at every bound",
            data.len()
        );
        let counted = APP_FRAME_COST.bytes(&data, u64::MAX).unwrap();
        let decoded = Instant::now();
        let heap = decode_heap(&data);
        let decoded = decoded.elapsed();
        // Times of a test build beside other tests: their ratio, roughly.
        println!(
            "HONEST-FRAME wire={} counted={counted} heap={heap} limit={MAX_APP_FRAME_DECODED} \
             walk_ms={} decode_ms={}",
            data.len(),
            walked.as_millis(),
            decoded.as_millis()
        );
        assert!(
            heap <= counted,
            "COST-BOUND: decoded to {heap}, counted {counted}"
        );
        let before = refused_here();
        assert!(decode_frame("test", &data).is_some());
        assert_eq!(refused_here(), before);
    }

    /// A frame of the most leaf roots of one empty entry each the bound
    /// admits is admitted and decodes; one root more is refused unread,
    /// with what was counted.
    #[test]
    fn refuses_a_frame_one_root_past_the_decoded_bound() {
        let frame = |roots: usize| {
            prost::Message::encode_to_vec(&frame_with(confirm(vec![
                ConfirmLeafRoots {
                    entries: vec![LeafRootEntry::default()],
                    ..Default::default()
                };
                roots
            ])))
        };
        let mut low = 1;
        let mut high = 1 << 19;
        // The most roots a frame admitted carries.
        while high - low > 1 {
            let mid = (low + high) / 2;
            if check_frame(&frame(mid)).is_ok() {
                low = mid;
            } else {
                high = mid;
            }
        }
        let at = APP_FRAME_COST.bytes(&frame(low), u64::MAX).unwrap();
        assert!(at <= MAX_APP_FRAME_DECODED);
        let past = frame(high);
        let counted = APP_FRAME_COST.bytes(&past, u64::MAX).unwrap();
        assert!(counted > MAX_APP_FRAME_DECODED);
        match check_frame(&past) {
            Err(FrameRefusal::TooLarge { items, decoded }) => {
                assert_eq!((items.bundles, items.requests), (1, 1));
                assert!(decoded > MAX_APP_FRAME_DECODED && decoded <= counted);
            }
            other => panic!("DECODED-BOUND: {other:?}"),
        }
        let before = refused_here();
        assert!(decode_frame("test", &past).is_none());
        assert_eq!(refused_here(), before + 1);
        assert!(decode_frame("test", &frame(low)).is_some());
        assert_eq!(refused_here(), before + 1);
    }
}

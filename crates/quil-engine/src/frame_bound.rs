//! Bounds on what a received application shard frame carries (request
//! bundles, their requests and storage openings) and on the requests of a
//! message bundle submitted to a shard, counted from the encoding before
//! it is decoded.
//!
//! [`check_frame`] walks a frame's protobuf encoding without allocating
//! and refuses one carrying more than [`MAX_APP_FRAME_ITEMS`] bundles and
//! requests or [`MAX_APP_FRAME_OPENINGS`] storage openings;
//! [`check_bundle`] refuses a submitted bundle that could not fit a frame.
//!
//! A leader proposes at most [`MAX_APP_FRAME_ITEMS`] bundles and requests
//! and defers the rest ([`FrameItemBudget`]); members refuse a proposal
//! past either bound, as followers and archives refuse the frame.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use quil_cw_consensus::handoff::MAX_MEMBERS;
use quil_types::consensus::STORAGE_QUERIES_PER_LEAF;
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
/// (`MAX_GOSSIP_GLOBAL_BUNDLES`, `_REQUESTS`, quil-node), and a shard's
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
}

impl FrameRefusal {
    /// What the walk counted before it refused.
    fn counted(&self) -> FrameItems {
        match self {
            Self::Malformed => FrameItems::default(),
            Self::TooMany(items) => *items,
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
        }
    }
}

/// Counts the bundles, requests and storage openings the application
/// shard frame `data` carries, without allocating, and refuses it past
/// [`MAX_APP_FRAME_ITEMS`] or [`MAX_APP_FRAME_OPENINGS`], or malformed.
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
    Ok(items)
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
    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
    use quil_types::proto::global::{
        FrameHeader, MessageBundle, MessageRequest, StorageAttestation, StorageOpening,
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
}

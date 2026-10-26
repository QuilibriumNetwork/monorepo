//! Admission of the GLOBAL consensus messages peers deliver over
//! `SubmitGlobalConsensus`.
//!
//! Each message is refused when it is larger than the largest message of its
//! kind an honest member sends. An admitted message waits for the message
//! loop in one of two queues, each with a budget of messages and bytes: one
//! for committee members, and a smaller one shared by every other caller. A
//! queued message holds its share of its budget until the loop takes it, so
//! what waits is bounded whatever the number of caller identities, and
//! callers outside the committee cannot take the room members need. The
//! node's own messages keep the loopback queue, which peers no longer fill.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use quil_engine::bitmasks;
use quil_p2p::node::ReceivedMessage;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tracing::{info, warn};

/// Largest vote, certificate or resolver message. A certificate carries one
/// 666-byte Falcon signature per signer and under 100 bytes more, so this
/// holds one of a committee of over 1,500 members; a vote or a resolver
/// request is under 1 KiB, and a resolver response is one certificate.
pub(crate) const MAX_CONTROL_MESSAGE_BYTES: usize = 1 << 20;

/// Largest block: the largest GLOBAL frame a member proposes or accepts.
pub(crate) const MAX_BLOCK_MESSAGE_BYTES: usize =
    quil_engine::frame_materializer::MAX_GLOBAL_FRAME_BYTES;

/// Messages committee members' deliveries may hold queued at once, as many as
/// the queue they shared with the node's own messages held.
const MEMBER_MESSAGES: usize = 4096;

/// Bytes committee members' deliveries may hold queued at once: sixteen
/// blocks of the largest size, where members send about one block a view.
const MEMBER_BYTES: usize = 256 << 20;

/// Messages all other callers' deliveries may hold queued at once. Members
/// send on the commonware channels, which carry nothing from other callers.
const OTHER_MESSAGES: usize = 64;

/// Bytes all other callers' deliveries may hold queued at once: two blocks
/// of the largest size.
const OTHER_BYTES: usize = 32 << 20;

/// Deliveries one caller identity may make per second.
const MAX_MESSAGES_PER_SEC_PER_PEER: u32 = 256;

/// Caller identities whose rate is tracked before the tracking starts over.
const RATE_PEERS: usize = 4096;

/// Minimum interval between two refusal summaries.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Why a delivery was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// Not a GLOBAL consensus bitmask.
    Topic,
    /// Larger than any honest message of its kind.
    TooLarge,
    /// Over the caller's rate.
    RateLimited,
    /// The committee members' budget is spent.
    MemberBudget,
    /// The other callers' budget is spent.
    OtherBudget,
    /// The message loop has stopped.
    Closed,
}

const REFUSALS: usize = 6;

impl Refusal {
    const ALL: [Refusal; REFUSALS] = [
        Refusal::Topic,
        Refusal::TooLarge,
        Refusal::RateLimited,
        Refusal::MemberBudget,
        Refusal::OtherBudget,
        Refusal::Closed,
    ];

    fn name(self) -> &'static str {
        match self {
            Refusal::Topic => "topic",
            Refusal::TooLarge => "too_large",
            Refusal::RateLimited => "rate_limited",
            Refusal::MemberBudget => "member_budget",
            Refusal::OtherBudget => "other_budget",
            Refusal::Closed => "closed",
        }
    }

    /// The reason given to the caller.
    fn reason(self) -> &'static str {
        match self {
            Refusal::Topic => "unexpected consensus bitmask",
            Refusal::TooLarge => "consensus message too large",
            Refusal::RateLimited => "global consensus delivery rate limited",
            Refusal::MemberBudget | Refusal::OtherBudget => "consensus receive queue full",
            Refusal::Closed => "consensus receive queue closed",
        }
    }
}

/// The largest message a bitmask carries, or `None` when it is not one of
/// the GLOBAL consensus bitmasks.
fn message_limit(bitmask: &[u8]) -> Option<usize> {
    match bitmasks::global_cw_channel_of(bitmask) {
        Some(3) => Some(MAX_BLOCK_MESSAGE_BYTES),
        Some(_) => Some(MAX_CONTROL_MESSAGE_BYTES),
        None if bitmask == bitmasks::GLOBAL_FRAME => Some(MAX_BLOCK_MESSAGE_BYTES),
        None if bitmask == bitmasks::GLOBAL_CONSENSUS => Some(MAX_CONTROL_MESSAGE_BYTES),
        None => None,
    }
}

/// A queued delivery's share of its budget, released when the message loop
/// takes the delivery.
struct Admission {
    _message: OwnedSemaphorePermit,
    _bytes: OwnedSemaphorePermit,
}

/// A peer's delivery waiting for the message loop.
pub(crate) struct RemoteConsensus {
    message: ReceivedMessage,
    _admission: Admission,
}

impl RemoteConsensus {
    /// The message, releasing its share of the budget.
    pub(crate) fn into_message(self) -> ReceivedMessage {
        self.message
    }
}

/// The message loop's ends of the two queues.
pub(crate) struct RemoteConsensusQueues {
    pub(crate) members: mpsc::Receiver<RemoteConsensus>,
    pub(crate) others: mpsc::Receiver<RemoteConsensus>,
}

struct Lane {
    tx: mpsc::Sender<RemoteConsensus>,
    messages: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
}

impl Lane {
    fn new(messages: usize, bytes: usize) -> (Self, mpsc::Receiver<RemoteConsensus>) {
        let (tx, rx) = mpsc::channel(messages);
        let lane = Self {
            tx,
            messages: Arc::new(Semaphore::new(messages)),
            bytes: Arc::new(Semaphore::new(bytes)),
        };
        (lane, rx)
    }

    fn reserve(&self, len: usize) -> Option<Admission> {
        let message = self.messages.clone().try_acquire_owned().ok()?;
        let len = u32::try_from(len).ok()?;
        let bytes = self.bytes.clone().try_acquire_many_owned(len).ok()?;
        Some(Admission {
            _message: message,
            _bytes: bytes,
        })
    }
}

/// Deliveries per caller identity in the current second.
struct PeerRates {
    started: Instant,
    seen: HashMap<Vec<u8>, (u64, u32)>,
}

impl PeerRates {
    fn allow(&mut self, from: &[u8], now: Instant) -> bool {
        let second = now.saturating_duration_since(self.started).as_secs();
        if self.seen.len() > RATE_PEERS {
            self.seen.clear();
        }
        let entry = self.seen.entry(from.to_vec()).or_insert((second, 0));
        if entry.0 == second {
            entry.1 = entry.1.saturating_add(1);
        } else {
            *entry = (second, 1);
        }
        entry.1 <= MAX_MESSAGES_PER_SEC_PER_PEER
    }
}

/// Refusals since the last summary.
#[derive(Default)]
struct RefusalLog {
    counts: [u64; REFUSALS],
    /// Of those, refusals of committee members' deliveries.
    members: u64,
    latest_peer: Vec<u8>,
    last_summary: Option<Instant>,
}

struct RefusalSummary {
    counts: [u64; REFUSALS],
    members: u64,
    latest_peer: Vec<u8>,
    since_previous: Option<Duration>,
}

impl RefusalLog {
    fn record(
        &mut self,
        refusal: Refusal,
        from: &[u8],
        member: bool,
        now: Instant,
    ) -> Option<RefusalSummary> {
        self.counts[refusal as usize] += 1;
        if member {
            self.members += 1;
        }
        self.latest_peer = from.to_vec();
        let since_previous = self
            .last_summary
            .map(|last| now.saturating_duration_since(last));
        if since_previous.is_some_and(|elapsed| elapsed < REFUSAL_LOG_INTERVAL) {
            return None;
        }
        self.last_summary = Some(now);
        Some(RefusalSummary {
            counts: std::mem::take(&mut self.counts),
            members: std::mem::take(&mut self.members),
            latest_peer: std::mem::take(&mut self.latest_peer),
            since_previous,
        })
    }
}

fn log_refusals(summary: &RefusalSummary) {
    let counts = Refusal::ALL
        .iter()
        .map(|refusal| format!("{}={}", refusal.name(), summary.counts[*refusal as usize]))
        .collect::<Vec<_>>()
        .join(" ");
    let window = match summary.since_previous {
        Some(elapsed) => format!("the last {}s", elapsed.as_secs()),
        None => "startup".to_string(),
    };
    let peer = bs58::encode(&summary.latest_peer).into_string();
    if summary.members > 0 {
        warn!(
            members = summary.members,
            latest_peer = %peer,
            "global consensus intake: refused deliveries since {window}: {counts}; some came \
             from committee members, whose votes or blocks are lost: a member_budget refusal \
             means this node's message loop is not keeping up, a too_large or rate_limited \
             one a member sending more than consensus does; report this line"
        );
    } else {
        info!(
            latest_peer = %peer,
            "global consensus intake: refused deliveries since {window}: {counts}; none came \
             from committee members: callers outside the committee exceeded the delivery \
             limits"
        );
    }
}

/// Whether a caller is a committee member: one of the committee's configured
/// peer ids (the genesis archives on mainnet), known before consensus
/// activates, or a member the activated router resolves.
pub(crate) fn committee_members(
    committee_peer_ids: &[String],
    router: Arc<std::sync::OnceLock<Arc<crate::cw_consensus_bridge::CwInboundRouter>>>,
) -> Arc<dyn Fn(&[u8]) -> bool + Send + Sync> {
    let committee: std::collections::HashSet<Vec<u8>> = committee_peer_ids
        .iter()
        .filter_map(|peer_id| bs58::decode(peer_id).into_vec().ok())
        .collect();
    Arc::new(move |from: &[u8]| {
        committee.contains(from) || router.get().is_some_and(|router| router.is_member(from))
    })
}

/// Admits peers' `SubmitGlobalConsensus` deliveries (see the module docs).
pub(crate) struct ConsensusIntake {
    is_member: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    members: Lane,
    others: Lane,
    rates: Mutex<PeerRates>,
    refusals: Mutex<RefusalLog>,
}

impl ConsensusIntake {
    /// `is_member` tells a committee member's identity from another caller's.
    pub(crate) fn new(
        is_member: Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    ) -> (Self, RemoteConsensusQueues) {
        let (members, members_rx) = Lane::new(MEMBER_MESSAGES, MEMBER_BYTES);
        let (others, others_rx) = Lane::new(OTHER_MESSAGES, OTHER_BYTES);
        let intake = Self {
            is_member,
            members,
            others,
            rates: Mutex::new(PeerRates {
                started: Instant::now(),
                seen: HashMap::new(),
            }),
            refusals: Mutex::new(RefusalLog::default()),
        };
        let queues = RemoteConsensusQueues {
            members: members_rx,
            others: others_rx,
        };
        (intake, queues)
    }

    /// Queue `data`, delivered on `bitmask` by the caller `from`, for the
    /// message loop, or say why not.
    pub(crate) fn admit(
        &self,
        from: Vec<u8>,
        bitmask: Vec<u8>,
        data: Vec<u8>,
    ) -> Result<(), String> {
        let topic = bitmask.clone();
        self.try_admit(from, bitmask, data, Instant::now())
            .map_err(|refusal| match refusal {
                Refusal::Topic => format!("unexpected consensus bitmask 0x{}", hex::encode(&topic)),
                _ => refusal.reason().to_string(),
            })
    }

    fn try_admit(
        &self,
        from: Vec<u8>,
        bitmask: Vec<u8>,
        data: Vec<u8>,
        now: Instant,
    ) -> Result<(), Refusal> {
        let member = (self.is_member)(&from);
        let allowed = self
            .rates
            .lock()
            .map(|mut rates| rates.allow(&from, now))
            .unwrap_or(true);
        if !allowed {
            return Err(self.refuse(Refusal::RateLimited, &from, member, now));
        }
        let Some(limit) = message_limit(&bitmask) else {
            return Err(self.refuse(Refusal::Topic, &from, member, now));
        };
        if data.len() > limit {
            return Err(self.refuse(Refusal::TooLarge, &from, member, now));
        }
        let (lane, busy) = if member {
            (&self.members, Refusal::MemberBudget)
        } else {
            (&self.others, Refusal::OtherBudget)
        };
        let Some(admission) = lane.reserve(data.len()) else {
            return Err(self.refuse(busy, &from, member, now));
        };
        let delivery = RemoteConsensus {
            message: ReceivedMessage {
                bitmask,
                data,
                from,
                direct: false,
            },
            _admission: admission,
        };
        match lane.tx.try_send(delivery) {
            Ok(()) => Ok(()),
            Err(error) => {
                // The budget bounds the queue, so it is full only if the
                // loop has stopped taking from it.
                let (refusal, rejected) = match error {
                    mpsc::error::TrySendError::Full(rejected) => (busy, rejected),
                    mpsc::error::TrySendError::Closed(rejected) => (Refusal::Closed, rejected),
                };
                Err(self.refuse(refusal, &rejected.message.from, member, now))
            }
        }
    }

    fn refuse(&self, refusal: Refusal, from: &[u8], member: bool, now: Instant) -> Refusal {
        let summary = self
            .refusals
            .lock()
            .ok()
            .and_then(|mut log| log.record(refusal, from, member, now));
        if let Some(summary) = summary {
            log_refusals(&summary);
        }
        refusal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VOTE: &[u8] = bitmasks::GLOBAL_CW_VOTE;
    const BLOCK: &[u8] = bitmasks::GLOBAL_CW_BLOCK;

    fn intake() -> (ConsensusIntake, RemoteConsensusQueues) {
        ConsensusIntake::new(Arc::new(|from: &[u8]| from.starts_with(b"member")))
    }

    fn deliver(
        intake: &ConsensusIntake,
        from: &str,
        bitmask: &[u8],
        len: usize,
    ) -> Result<(), Refusal> {
        intake.try_admit(
            from.as_bytes().to_vec(),
            bitmask.to_vec(),
            vec![0; len],
            Instant::now(),
        )
    }

    fn queued(queue: &mut mpsc::Receiver<RemoteConsensus>) -> Vec<ReceivedMessage> {
        std::iter::from_fn(|| queue.try_recv().ok())
            .map(RemoteConsensus::into_message)
            .collect()
    }

    /// Members' votes and blocks of the largest honest size, and other
    /// callers' legacy frames, are queued in their own lanes.
    #[test]
    fn honest_deliveries_are_queued() {
        let (intake, mut queues) = intake();
        assert_eq!(deliver(&intake, "member-a", VOTE, 900), Ok(()));
        assert_eq!(
            deliver(&intake, "member-a", BLOCK, MAX_BLOCK_MESSAGE_BYTES),
            Ok(())
        );
        assert_eq!(
            deliver(&intake, "member-b", bitmasks::GLOBAL_CW_CERT, 24 << 10),
            Ok(())
        );
        assert_eq!(
            deliver(&intake, "archive", bitmasks::GLOBAL_FRAME, 1 << 20),
            Ok(())
        );
        let members = queued(&mut queues.members);
        let sizes: Vec<usize> = members.iter().map(|m| m.data.len()).collect();
        assert_eq!(sizes, vec![900, MAX_BLOCK_MESSAGE_BYTES, 24 << 10]);
        assert_eq!(members[0].from, b"member-a".to_vec());
        assert_eq!(members[1].bitmask, BLOCK.to_vec());
        let others = queued(&mut queues.others);
        assert_eq!(others.len(), 1);
        assert_eq!(others[0].bitmask, bitmasks::GLOBAL_FRAME.to_vec());
    }

    /// A message larger than its kind allows, or on another bitmask, is
    /// refused and not queued.
    #[test]
    fn oversize_deliveries_are_refused() {
        let (intake, mut queues) = intake();
        let too_large = Err(Refusal::TooLarge);
        assert_eq!(
            deliver(&intake, "member-a", VOTE, MAX_CONTROL_MESSAGE_BYTES + 1),
            too_large
        );
        assert_eq!(
            deliver(&intake, "member-a", BLOCK, MAX_BLOCK_MESSAGE_BYTES + 1),
            too_large
        );
        assert_eq!(
            deliver(&intake, "anyone", bitmasks::GLOBAL_CONSENSUS, 2 << 20),
            too_large
        );
        assert_eq!(
            deliver(&intake, "anyone", bitmasks::GLOBAL_PROVER, 10),
            Err(Refusal::Topic)
        );
        assert!(queued(&mut queues.members).is_empty());
        assert!(queued(&mut queues.others).is_empty());
        assert_eq!(
            intake.admit(b"anyone".to_vec(), vec![0xab], Vec::new()),
            Err("unexpected consensus bitmask 0xab".to_string())
        );
    }

    /// Callers outside the committee share one budget, whatever their number
    /// of identities; spending it leaves the members' budget untouched, and
    /// the loop taking a delivery returns its share.
    #[test]
    fn other_callers_share_a_budget_members_do_not_depend_on() {
        let (intake, mut queues) = intake();
        for n in 0..OTHER_MESSAGES {
            assert_eq!(deliver(&intake, &format!("other-{n}"), VOTE, 100), Ok(()));
        }
        assert_eq!(
            deliver(&intake, "other-fresh", VOTE, 100),
            Err(Refusal::OtherBudget)
        );
        assert_eq!(deliver(&intake, "member-a", VOTE, 100), Ok(()));
        assert_eq!(queued(&mut queues.others).len(), OTHER_MESSAGES);
        // Bytes: two blocks of the largest size fill the other callers' budget.
        let block = MAX_BLOCK_MESSAGE_BYTES;
        assert_eq!(deliver(&intake, "other-1", BLOCK, block), Ok(()));
        assert_eq!(deliver(&intake, "other-2", BLOCK, block), Ok(()));
        assert_eq!(
            deliver(&intake, "other-3", BLOCK, block),
            Err(Refusal::OtherBudget)
        );
        assert_eq!(deliver(&intake, "member-b", BLOCK, block), Ok(()));
        drop(queues.others.try_recv().unwrap());
        assert_eq!(deliver(&intake, "other-3", BLOCK, block), Ok(()));
        assert_eq!(queued(&mut queues.members).len(), 2);
    }

    /// Members' deliveries are bounded too, by a larger budget.
    #[test]
    fn members_budget_is_bounded() {
        let (intake, mut queues) = intake();
        for n in 0..MEMBER_MESSAGES {
            let from = format!("member-{}", n % 32);
            assert_eq!(deliver(&intake, &from, VOTE, 10), Ok(()));
        }
        assert_eq!(
            deliver(&intake, "member-x", VOTE, 10),
            Err(Refusal::MemberBudget)
        );
        assert_eq!(deliver(&intake, "other", VOTE, 10), Ok(()));
        assert_eq!(queued(&mut queues.members).len(), MEMBER_MESSAGES);
        assert_eq!(deliver(&intake, "member-x", VOTE, 10), Ok(()));
    }

    /// Before consensus activates, the configured committee's peer ids are
    /// members already; other callers are not.
    #[test]
    fn configured_members_are_members_before_activation() {
        let member = bs58::encode(b"member-id").into_string();
        let is_member = committee_members(&[member, "not base58 0OIl".into()], Default::default());
        assert!(is_member(&b"member-id"[..]));
        assert!(!is_member(&b"stranger"[..]));
        let (intake, mut queues) = ConsensusIntake::new(is_member);
        let deliver = |from: &[u8]| {
            intake.try_admit(from.to_vec(), VOTE.to_vec(), vec![0; 10], Instant::now())
        };
        assert_eq!(deliver(&b"member-id"[..]), Ok(()));
        assert_eq!(deliver(&b"stranger"[..]), Ok(()));
        assert_eq!(queued(&mut queues.members).len(), 1);
        assert_eq!(queued(&mut queues.others).len(), 1);
    }

    /// One identity still makes at most 256 deliveries a second.
    #[test]
    fn one_identity_is_rate_limited() {
        let (intake, _queues) = intake();
        let now = Instant::now();
        let send = || intake.try_admit(b"other".to_vec(), VOTE.to_vec(), vec![0; 10], now);
        for _ in 0..MAX_MESSAGES_PER_SEC_PER_PEER {
            let _ = send();
        }
        assert_eq!(send(), Err(Refusal::RateLimited));
    }
}

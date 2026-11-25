// Copyright 2020 Sigma Prime Pty Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::collections::{HashMap, HashSet, VecDeque};

use libp2p_identity::PeerId;
use web_time::Instant;

use crate::{peer_score::RejectReason, MessageId, ValidationError};

/// Tracks recently sent `IWANT` messages and checks if peers respond to them.
#[derive(Default)]
pub(crate) struct GossipPromises {
    /// Stores for each tracked message id and peer the instant when this promise expires.
    ///
    /// If the peer didn't respond until then we consider the promise as broken and penalize the
    /// peer.
    promises: HashMap<MessageId, HashMap<PeerId, Instant>>,
    /// QUILIBRIUM: for each message asked for or announced and not yet delivered, the peers
    /// that announced it and were not asked, and the peers asked. Until the message is
    /// delivered or rejected, each kept mesh announcer that still serves it is asked no later
    /// than its latest start ([`Announcer::latest_start`]), whether or not another promise is
    /// open, and with no promise open one kept announcer is asked at the next heartbeat
    /// ([`GossipPromises::due_announcers`]).
    announcers: HashMap<MessageId, Announced>,
}

/// QUILIBRIUM: a peer that announced a message (IHAVE) and has not been asked for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Announcer {
    pub(crate) peer: PeerId,
    /// Until when it serves an IWANT for the message from its cache, counted from its first
    /// IHAVE; a repeat IHAVE never moves it.
    pub(crate) serve_until: Instant,
    /// The latest instant to ask it: `serve_until` less its promise time and one heartbeat.
    /// A mesh announcer is asked at the last heartbeat at or before then; one over its IWANT
    /// budget there goes out at the next heartbeat, still within `serve_until` less its
    /// promise time. An announcer outside the mesh is asked only once no promise is open.
    pub(crate) latest_start: Instant,
    /// Whether it announced from our mesh: its message is likely large, and an ask waits
    /// `lazy_followup_time`.
    pub(crate) lazy: bool,
}

/// QUILIBRIUM: who announced one message and who was asked for it.
#[derive(Debug, Default)]
struct Announced {
    /// Announcers not yet asked, in the order of their first IHAVE (latest last), at most
    /// [`MAX_FALLBACK_ANNOUNCERS`].
    waiting: VecDeque<Announcer>,
    /// Peers asked for the message: none is kept or asked again for it while the record lasts.
    /// The record ends once no promise is open and no announcer is kept; a withholder that
    /// announces again after that is asked again, as a first announcer.
    asked: HashSet<PeerId>,
}

/// QUILIBRIUM: the kept announcers of one message to ask at a heartbeat.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DueAnnouncers {
    /// Mesh announcers whose latest start comes before the next heartbeat: each is asked now,
    /// whether or not a promise for the message is open.
    pub(crate) deadline: Vec<Announcer>,
    /// With no promise open, the others, mesh or not, latest first IHAVE first: the caller
    /// asks the first it can when no deadline ask went out.
    pub(crate) serial: Vec<Announcer>,
}

/// QUILIBRIUM: the most announcers kept unasked per message. A mesh announcer evicts the
/// latest kept from outside the mesh; otherwise, also when all kept are mesh peers, a new
/// announcer is not kept: the kept ones announced first, so their latest starts come first.
/// A mesh holds at most `mesh_n_high` (12) peers, and each kept one costs a peer id until the
/// message arrives, it is asked, or its cache window ends.
pub(crate) const MAX_FALLBACK_ANNOUNCERS: usize = 8;

impl GossipPromises {
    /// Returns true if the message id exists in the promises.
    pub(crate) fn contains(&self, message: &MessageId) -> bool {
        self.promises.contains_key(message)
    }

    /// QUILIBRIUM: whether `message` has an open promise or a record of its announcers, so
    /// keeping one more announcer of it adds no message to the records.
    pub(crate) fn tracks(&self, message: &MessageId) -> bool {
        self.promises.contains_key(message) || self.announcers.contains_key(message)
    }

    /// QUILIBRIUM: whether we sent `peer` an IWANT for `message` that it has not answered.
    pub(crate) fn promised_by(&self, message: &MessageId, peer: &PeerId) -> bool {
        self.promises
            .get(message)
            .is_some_and(|peers| peers.contains_key(peer))
    }

    /// Get the peers we sent IWANT the input message id.
    pub(crate) fn peers_for_message(&self, message_id: &MessageId) -> Vec<PeerId> {
        self.promises
            .get(message_id)
            .map(|peers| peers.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Track a promise to deliver a message from a list of [`MessageId`]s we are requesting.
    pub(crate) fn add_promise(&mut self, peer: PeerId, messages: &[MessageId], expires: Instant) {
        for message_id in messages {
            // If a promise for this message id and peer already exists we don't update the expiry!
            self.promises
                .entry(message_id.clone())
                .or_default()
                .entry(peer)
                .or_insert(expires);
        }
    }

    /// QUILIBRIUM: [`GossipPromises::add_promise`] for an IWANT sent to `peer`, which is then
    /// no longer kept as an announcer of `messages` and is never kept or asked again for them.
    pub(crate) fn ask(&mut self, peer: PeerId, messages: &[MessageId], expires: Instant) {
        self.add_promise(peer, messages, expires);
        for message_id in messages {
            let announced = self.announcers.entry(message_id.clone()).or_default();
            announced.waiting.retain(|kept| kept.peer != peer);
            announced.asked.insert(peer);
        }
    }

    /// QUILIBRIUM: whether `peer` was asked for `message` since it was first asked for or
    /// announced.
    pub(crate) fn was_asked(&self, message: &MessageId, peer: &PeerId) -> bool {
        self.announcers
            .get(message)
            .is_some_and(|announced| announced.asked.contains(peer))
    }

    /// QUILIBRIUM: keep `announcer` of `message` to ask by its latest start (a mesh peer), or
    /// once no promise for it is open. A repeat IHAVE changes nothing: the first set its place and
    /// serve-until. At [`MAX_FALLBACK_ANNOUNCERS`] a mesh announcer evicts the latest kept
    /// from outside the mesh, and is otherwise not kept. Returns whether it is kept: not when
    /// it was asked for the message already or the cap refused it.
    pub(crate) fn keep_announcer(&mut self, message: &MessageId, announcer: Announcer) -> bool {
        if self.promised_by(message, &announcer.peer) {
            return false;
        }
        let announced = self.announcers.entry(message.clone()).or_default();
        if announced.asked.contains(&announcer.peer) {
            return false;
        }
        if announced
            .waiting
            .iter()
            .any(|kept| kept.peer == announcer.peer)
        {
            return true;
        }
        if announced.waiting.len() >= MAX_FALLBACK_ANNOUNCERS {
            let outside_mesh = announcer
                .lazy
                .then(|| announced.waiting.iter().rposition(|kept| !kept.lazy))
                .flatten();
            let Some(at) = outside_mesh else {
                return false;
            };
            announced.waiting.remove(at);
        }
        announced.waiting.push_back(announcer);
        true
    }

    /// QUILIBRIUM: drop `peer` as a kept announcer of `message` (it left or fell below the
    /// gossip threshold).
    pub(crate) fn forget_announcer(&mut self, message: &MessageId, peer: &PeerId) {
        if let Some(announced) = self.announcers.get_mut(message) {
            announced.waiting.retain(|kept| kept.peer != *peer);
        }
    }

    /// QUILIBRIUM: drops kept announcers whose serve-until passed before `now` (the second
    /// value counts them) and the records of messages with neither an open promise nor a kept
    /// announcer; returns, for each message with announcers to ask at the heartbeat at `now`,
    /// the mesh announcers whose latest start comes before the next one, `heartbeat` later,
    /// and with no promise open the others ([`DueAnnouncers`]). An announcer outside the mesh
    /// is never asked while a promise is open: each ask that is answered is a full copy, and
    /// its latest start comes about a second after its heartbeat gossip, often while the first
    /// copy is still on its way. The caller asks them
    /// ([`GossipPromises::ask`]); the rest stay kept.
    pub(crate) fn due_announcers(
        &mut self,
        now: Instant,
        heartbeat: std::time::Duration,
    ) -> (Vec<(MessageId, DueAnnouncers)>, usize) {
        let next = now.checked_add(heartbeat).unwrap_or(now);
        let mut stale = 0;
        let mut due = Vec::new();
        let promises = &self.promises;
        self.announcers.retain(|message, announced| {
            let before = announced.waiting.len();
            announced.waiting.retain(|kept| kept.serve_until >= now);
            stale += before - announced.waiting.len();
            let open = promises.contains_key(message);
            if !open && announced.waiting.is_empty() {
                return false;
            }
            let (deadline, rest): (Vec<Announcer>, Vec<Announcer>) = announced
                .waiting
                .iter()
                .rev()
                .copied()
                .partition(|kept| kept.lazy && kept.latest_start < next);
            let serial = if open { Vec::new() } else { rest };
            if !deadline.is_empty() || !serial.is_empty() {
                due.push((message.clone(), DueAnnouncers { deadline, serial }));
            }
            true
        });
        (due, stale)
    }

    pub(crate) fn message_delivered(&mut self, message_id: &MessageId) {
        // Someone delivered a message, we can stop tracking all promises for it.
        self.promises.remove(message_id);
        self.announcers.remove(message_id);
    }

    pub(crate) fn reject_message(&mut self, message_id: &MessageId, reason: &RejectReason) {
        // QUILIBRIUM: nobody is asked again for a rejected message.
        self.announcers.remove(message_id);
        // A message got rejected, so we can stop tracking promises and let the score penalty apply
        // from invalid message delivery.
        // We do take exception and apply promise penalty regardless in the following cases, where
        // the peer delivered an obviously invalid message.
        match reason {
            RejectReason::ValidationError(ValidationError::InvalidSignature) => (),
            RejectReason::SelfOrigin => (),
            _ => {
                self.promises.remove(message_id);
            }
        };
    }

    /// Returns the number of broken promises for each peer who didn't follow up on an IWANT
    /// request.
    /// This should be called not too often relative to the expire times, since it iterates over
    /// the whole stored data.
    pub(crate) fn get_broken_promises(&mut self) -> HashMap<PeerId, usize> {
        let now = Instant::now();
        let mut result = HashMap::new();
        self.promises.retain(|msg, peers| {
            peers.retain(|peer_id, expires| {
                if *expires < now {
                    let count = result.entry(*peer_id).or_insert(0);
                    *count += 1;
                    tracing::debug!(
                        peer=%peer_id,
                        message=%msg,
                        "[Penalty] The peer broke the promise to deliver message in time!"
                    );
                    false
                } else {
                    true
                }
            });
            !peers.is_empty()
        });
        result
    }

    /// Moves every promise's expiry and every kept announcer's IHAVE and serve-until `by`
    /// into the past, as if that much time had passed.
    #[cfg(test)]
    pub(crate) fn backdate(&mut self, by: std::time::Duration) {
        let back = |at: &mut Instant| {
            *at = at
                .checked_sub(by)
                .expect("the clock is past the test's offsets");
        };
        self.promises
            .values_mut()
            .flat_map(|peers| peers.values_mut())
            .for_each(back);
        for kept in self
            .announcers
            .values_mut()
            .flat_map(|announced| announced.waiting.iter_mut())
        {
            back(&mut kept.serve_until);
            back(&mut kept.latest_start);
        }
    }

    /// The kept announcers of `message`, latest first IHAVE first.
    #[cfg(test)]
    pub(crate) fn kept_announcers(&self, message: &MessageId) -> Vec<PeerId> {
        self.announcers
            .get(message)
            .map(|announced| {
                announced
                    .waiting
                    .iter()
                    .rev()
                    .map(|kept| kept.peer)
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn id(n: u8) -> MessageId {
        MessageId::new(&[n])
    }

    /// A mesh announcer serving for `serves_for`, to ask by half of it.
    fn announcer(peer: PeerId, serves_for: Duration) -> Announcer {
        let now = Instant::now();
        Announcer {
            peer,
            serve_until: now + serves_for,
            latest_start: now + serves_for / 2,
            lazy: true,
        }
    }

    /// An announcer outside the mesh serving for `serves_for`, to ask by half of it.
    fn gossip_announcer(peer: PeerId, serves_for: Duration) -> Announcer {
        Announcer {
            lazy: false,
            ..announcer(peer, serves_for)
        }
    }

    fn peers(kept: &[Announcer]) -> Vec<PeerId> {
        kept.iter().map(|kept| kept.peer).collect()
    }

    /// Each due message with the peers due by deadline and the serial ones.
    fn due_peers(due: &[(MessageId, DueAnnouncers)]) -> Vec<(MessageId, Vec<PeerId>, Vec<PeerId>)> {
        due.iter()
            .map(|(id, due)| (id.clone(), peers(&due.deadline), peers(&due.serial)))
            .collect()
    }

    /// QUILIBRIUM: an announcer is kept with or without an open promise, once per peer, never
    /// a peer asked for the message, in the order of its first IHAVE; a repeat IHAVE changes
    /// neither its place nor its serve-until. At [`MAX_FALLBACK_ANNOUNCERS`] a new announcer
    /// is not kept when all kept are mesh peers.
    #[test]
    fn keeps_announcers_by_first_ihave_up_to_the_cap() {
        let mut promises = GossipPromises::default();
        let window = Duration::from_secs(60);
        let asked = PeerId::random();
        let unpromised = PeerId::random();
        assert!(
            promises.keep_announcer(&id(2), announcer(unpromised, window)),
            "kept with no promise open"
        );
        promises.ask(asked, &[id(1)], Instant::now() + window);
        assert!(promises.was_asked(&id(1), &asked));
        assert!(
            !promises.keep_announcer(&id(1), announcer(asked, window)),
            "the asked peer is not kept"
        );
        let later: Vec<PeerId> = (0..=MAX_FALLBACK_ANNOUNCERS)
            .map(|_| PeerId::random())
            .collect();
        for peer in &later[..MAX_FALLBACK_ANNOUNCERS] {
            assert!(promises.keep_announcer(&id(1), announcer(*peer, window)));
        }
        assert!(
            !promises.keep_announcer(&id(1), announcer(later[MAX_FALLBACK_ANNOUNCERS], window)),
            "all kept are mesh peers: the newcomer is not kept"
        );
        let first_order: Vec<PeerId> = later[..MAX_FALLBACK_ANNOUNCERS]
            .iter()
            .rev()
            .copied()
            .collect();
        assert_eq!(promises.kept_announcers(&id(1)), first_order);

        let repeat = later[1];
        let before = promises.announcers[&id(1)].waiting[1];
        assert!(promises.keep_announcer(&id(1), announcer(repeat, window * 2)));
        assert_eq!(
            promises.kept_announcers(&id(1)),
            first_order,
            "a repeat IHAVE keeps its peer's place"
        );
        assert_eq!(
            promises.announcers[&id(1)].waiting[1],
            before,
            "a repeat IHAVE keeps the first serve-until and latest start"
        );

        promises.ask(later[2], &[id(1)], Instant::now() + window);
        assert!(
            !promises.kept_announcers(&id(1)).contains(&later[2])
                && !promises.keep_announcer(&id(1), announcer(later[2], window)),
            "an asked announcer leaves the kept ones and is not kept again"
        );
        promises.backdate(window * 2);
        assert_eq!(
            promises.get_broken_promises().get(&later[2]),
            Some(&1),
            "premise: its promise broke"
        );
        assert!(
            !promises.keep_announcer(&id(1), announcer(later[2], window)),
            "nor once its promise broke: a peer is asked for a message once"
        );
        assert!(promises.was_asked(&id(1), &later[2]));
    }

    /// QUILIBRIUM: at [`MAX_FALLBACK_ANNOUNCERS`] a mesh announcer evicts the latest kept from
    /// outside the mesh, never a mesh one; an announcer from outside the mesh evicts nobody.
    #[test]
    fn a_mesh_announcer_evicts_one_from_outside_the_mesh_at_the_cap() {
        let mut promises = GossipPromises::default();
        let window = Duration::from_secs(60);
        let kept: Vec<(PeerId, bool)> = (0..MAX_FALLBACK_ANNOUNCERS)
            .map(|n| (PeerId::random(), n % 2 == 0))
            .collect();
        for (peer, mesh) in &kept {
            let kept = if *mesh {
                announcer(*peer, window)
            } else {
                gossip_announcer(*peer, window)
            };
            assert!(promises.keep_announcer(&id(1), kept));
        }
        assert!(
            !promises.keep_announcer(&id(1), gossip_announcer(PeerId::random(), window)),
            "one from outside the mesh evicts nobody"
        );
        let mut expected: Vec<PeerId> = kept.iter().map(|(peer, _)| *peer).collect();
        let outside: Vec<PeerId> = kept
            .iter()
            .filter(|(_, mesh)| !mesh)
            .map(|(peer, _)| *peer)
            .collect();
        for evicted in outside.iter().rev() {
            let newcomer = PeerId::random();
            assert!(promises.keep_announcer(&id(1), announcer(newcomer, window)));
            expected.retain(|peer| peer != evicted);
            expected.push(newcomer);
            let mut latest_first = expected.clone();
            latest_first.reverse();
            assert_eq!(
                promises.kept_announcers(&id(1)),
                latest_first,
                "a mesh announcer evicts the latest kept from outside the mesh"
            );
        }
        assert!(
            !promises.keep_announcer(&id(1), announcer(PeerId::random(), window)),
            "with only mesh peers kept, a mesh newcomer is not kept"
        );
    }

    /// QUILIBRIUM: a kept mesh announcer whose latest start comes before the next heartbeat is
    /// due by deadline, with or without an open promise; the others, also one outside the mesh
    /// past its latest start, are due only while no promise is open, latest first IHAVE
    /// first; those past their serve-until are dropped and counted; delivery and rejection
    /// drop the record.
    #[test]
    fn hands_out_kept_announcers_by_deadline_and_while_no_promise_is_open() {
        let mut promises = GossipPromises::default();
        let window = Duration::from_secs(60);
        let heartbeat = Duration::from_secs(1);
        let (first, second, third) = (PeerId::random(), PeerId::random(), PeerId::random());
        promises.ask(first, &[id(1)], Instant::now() + Duration::from_secs(1));
        promises.keep_announcer(&id(1), announcer(second, window));
        promises.keep_announcer(&id(1), announcer(third, window));
        promises.keep_announcer(&id(2), announcer(second, window));
        promises.keep_announcer(&id(3), announcer(second, Duration::ZERO));
        promises.backdate(Duration::from_millis(1));
        let (due, stale) = promises.due_announcers(Instant::now(), heartbeat);
        assert_eq!(
            (due_peers(&due), stale),
            (vec![(id(2), vec![], vec![second])], 1),
            "only the unpromised message is due; the announcer past its serve-until is dropped"
        );
        assert!(!promises.tracks(&id(3)), "an empty record is dropped");

        promises.backdate(Duration::from_secs(2));
        assert_eq!(
            promises.get_broken_promises(),
            HashMap::from([(first, 1)]),
            "premise: the first promise broke"
        );
        let (due, _) = promises.due_announcers(Instant::now(), heartbeat);
        assert!(
            due_peers(&due).contains(&(id(1), vec![], vec![third, second])),
            "once the promise broke, latest first IHAVE first: {:?}",
            due_peers(&due)
        );

        // A promise is open until 12 s on; `near`'s latest start is 10 s on, `far`'s 30 s, and
        // `gossip`'s, outside the mesh, 10 s.
        let (near, far, gossip) = (PeerId::random(), PeerId::random(), PeerId::random());
        promises.ask(first, &[id(4)], Instant::now() + Duration::from_secs(12));
        promises.keep_announcer(&id(4), announcer(near, Duration::from_secs(20)));
        promises.keep_announcer(&id(4), announcer(far, window));
        promises.keep_announcer(&id(4), gossip_announcer(gossip, Duration::from_secs(20)));
        let is_due = |promises: &mut GossipPromises| {
            promises
                .due_announcers(Instant::now(), heartbeat)
                .0
                .into_iter()
                .find(|(message, _)| *message == id(4))
                .map(|(_, due)| (peers(&due.deadline), peers(&due.serial)))
        };
        promises.backdate(Duration::from_millis(8_900));
        assert_eq!(
            is_due(&mut promises),
            None,
            "the next heartbeat still comes before the latest start"
        );
        promises.backdate(Duration::from_millis(200));
        assert_eq!(
            is_due(&mut promises),
            Some((vec![near], vec![])),
            "the next heartbeat would come after it: the mesh announcer is asked now, with the \
             promise open, the one outside the mesh is not"
        );
        promises.ask(near, &[id(4)], Instant::now() + Duration::from_secs(1));
        promises.backdate(Duration::from_secs(1));
        assert_eq!(
            is_due(&mut promises),
            None,
            "outside the mesh, past its latest start: still kept, not asked while a promise is open"
        );
        assert_eq!(promises.kept_announcers(&id(4)), vec![gossip, far]);
        promises.backdate(Duration::from_millis(2_100));
        assert_eq!(
            promises.get_broken_promises(),
            HashMap::from([(first, 1), (near, 1)]),
            "premise: both promises broke"
        );
        assert_eq!(
            is_due(&mut promises),
            Some((vec![], vec![gossip, far])),
            "with no promise open, it is asked first: latest first IHAVE first"
        );

        promises.message_delivered(&id(1));
        promises.reject_message(&id(2), &RejectReason::ValidationFailed);
        assert!(!promises.tracks(&id(1)) && !promises.tracks(&id(2)));
        promises.message_delivered(&id(4));
        assert!(promises
            .due_announcers(Instant::now(), heartbeat)
            .0
            .is_empty());
    }
}
